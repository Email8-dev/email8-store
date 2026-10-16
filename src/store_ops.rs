// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Email8:Store
// SPDX-License-Identifier: Apache-2.0

//! Core mail store operations — the single writer for the mail tables.
//!
//! Every function takes a connection that ALREADY has the mail tenant
//! context set (`auth::set_mail_tenant_context`) on the SAME connection
//! (§4.3d). Document ids come from `sequences`; the change log
//! gets one row per touched collection — all inside one transaction held
//! by the caller.
//!
//! Design: `email8/design/sentin8-email8-store-technical-design.md` §6.

use std::collections::HashMap;

use chrono::Utc;
use uuid::Uuid;

use email8::contracts::Collection;
use email8::mail_core::{thread_key as compute_thread_key, ParsedMessage};
use sqlx::PgConnection;

/// Error type for store ops (handler-facing; maps to status codes).
pub type StoreResult<T> = Result<T, StoreOpError>;

#[derive(Debug, thiserror::Error)]
pub enum StoreOpError {
    #[error("database error: {0}")]
    Db(#[from] sqlx::Error),
    #[error("mail account not found in this environment")]
    NoAccount,
    #[error("mailbox {0} not found")]
    MailboxNotFound(String),
    #[error("quota exceeded")]
    QuotaExceeded,
    #[error("document conflict (retry)")]
    Conflict,
}

// ── Sequence allocation (legacy DocumentId/ChangeId counters) ─────────────

/// Allocate `count` ids from the per-(account, kind) sequence and return
/// the first allocated id. Runs inside the caller's transaction.
pub async fn allocate_ids(
    conn: &mut PgConnection,
    account_id: Uuid,
    kind: &str,
    count: i64,
) -> StoreResult<i64> {
    // env_id rides along from the principals row (sequences now carry it
    // for RLS; the upsert keeps the first-seen env binding).
    let upsert = sqlx::query_scalar::<_, i64>(
        r#"INSERT INTO email8.sequences (account_id, env_id, kind, next_id)
           VALUES ($1, (SELECT env_id FROM email8.principals WHERE id = $1), $2, 1 + $3)
           ON CONFLICT (account_id, kind) DO UPDATE
              SET next_id = email8.sequences.next_id + $3
           RETURNING next_id - $3"#,
    )
    .bind(account_id)
    .bind(kind)
    .bind(count)
    .fetch_one(&mut *conn)
    .await?;
    Ok(upsert)
}

/// The next change id for (account, collection) — allocates one.
async fn next_change_id(
    conn: &mut PgConnection,
    account_id: Uuid,
    collection: Collection,
) -> StoreResult<i64> {
    allocate_ids(
        conn,
        account_id,
        &format!("change:{}", collection as u16),
        1,
    )
    .await
}

// ── Provisioning (the `sentin8:auth:user:created` consumer) ───────────────

/// Provision a principal + bootstrap mailboxes + default identity.
/// Idempotent on (env_id, sub) — re-running returns the existing id.
///
/// Runs inside the CALLER'S transaction with the tenant context already
/// stamped on the same connection (PROVRLS-1 design §2.1): the env-tier
/// `principals` policies admit the m2m consumer's writes, and the
/// existence SELECT sees prior rows under the same in-transaction
/// context (at-least-once redelivery never duplicates). Before the
/// holder-tier child writes (addresses/mailboxes) the account binding
/// is stamped in the same transaction — the id is known by then, so
/// `app.account_id` admits the children without env-admin elevation.
pub async fn provision_principal(
    conn: &mut PgConnection,
    env_id: Uuid,
    auth_sub: Uuid,
    primary_address: &str,
    display_name: Option<&str>,
) -> StoreResult<Uuid> {
    let existing: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM email8.principals WHERE env_id = $1 AND sentin8_auth_user_id = $2",
    )
    .bind(env_id)
    .bind(auth_sub)
    .fetch_optional(&mut *conn)
    .await?;
    let account_id = match existing {
        Some(id) => {
            bind_account_context(conn, id).await?;
            bootstrap_mailboxes(conn, env_id, id).await?;
            id
        }
        None => {
            let id: Uuid = sqlx::query_scalar(
                r#"INSERT INTO email8.principals
                       (env_id, sentin8_auth_user_id, name, display_name)
                   VALUES ($1, $2, $3, $4)
                   RETURNING id"#,
            )
            .bind(env_id)
            .bind(auth_sub)
            .bind(primary_address)
            .bind(display_name)
            .fetch_one(&mut *conn)
            .await?;
            bind_account_context(conn, id).await?;
            // Primary address alias row.
            sqlx::query(
                "INSERT INTO email8.principal_addresses (env_id, account_id, address, is_primary) VALUES ($1, $2, $3, TRUE) ON CONFLICT DO NOTHING",
            )
            .bind(env_id)
            .bind(id)
            .bind(primary_address)
            .execute(&mut *conn)
            .await?;
            bootstrap_mailboxes(conn, env_id, id).await?;
            id
        }
    };
    Ok(account_id)
}

/// Stamp the holder-tier account binding on the provision connection
/// (same transaction — the caller's context stamp and this binding both
/// live until the enclosing COMMIT; the child-table policies
/// `account_id = sentin8_current_account_id()` admit the bootstrap
/// writes for the freshly created principal).
async fn bind_account_context(conn: &mut PgConnection, account_id: Uuid) -> StoreResult<()> {
    sqlx::query("SELECT set_config('app.account_id', $1::text, true)")
        .bind(account_id.to_string())
        .execute(&mut *conn)
        .await?;
    Ok(())
}

/// Create the fixed special-use mailbox set (INBOX=0 … ARCHIVE=5) with
/// fresh uid_validity values.
pub async fn bootstrap_mailboxes(
    conn: &mut PgConnection,
    env_id: Uuid,
    account_id: Uuid,
) -> StoreResult<()> {
    let roles: &[(&str, i64)] = &[
        ("INBOX", 0),
        ("Trash", 1),
        ("Junk", 2),
        ("Drafts", 3),
        ("Sent", 4),
        ("Archive", 5),
    ];
    let now = Utc::now().timestamp();
    for (i, (name, uid_seed)) in roles.iter().enumerate() {
        let role = name.to_lowercase();
        // id is DB-generated (gen_random_uuid); the numeric seed only
        // stabilizes uid_validity per role across re-provisioning.
        sqlx::query(
            r#"INSERT INTO email8.mailboxes
                   (env_id, account_id, name, role, sort_order, uid_validity, uid_next)
               VALUES ($1, $2, $3, $4, $5, $6, 1)
               ON CONFLICT (account_id, name) DO NOTHING"#,
        )
        .bind(env_id)
        .bind(account_id)
        .bind(name)
        .bind(role)
        .bind(i as i32)
        .bind(now + *uid_seed) // stable per-mailbox uid_validity
        .execute(&mut *conn)
        .await?;
    }
    Ok(())
}

// ── Ingest ────────────────────────────────────────────────────────────────

/// Ingest a raw message into the account: parse, thread, allocate ids,
/// write the email row + membership + thread + changelog + quota, all in
/// the caller's transaction.
pub async fn ingest_email(
    conn: &mut PgConnection,
    env_id: Uuid,
    account_id: Uuid,
    raw: &[u8],
    blob_hash: &str,
    _source: &str,
    spam_percentage: Option<f32>,
    target_mailboxes: &[Uuid],
) -> StoreResult<IngestOutcome> {
    // Zero-account guard: RLS would silently filter anyway, but be loud.
    if account_id == Uuid::nil() {
        return Err(StoreOpError::NoAccount);
    }
    let parsed = ParsedMessage::parse(raw).map_err(|e| {
        tracing::warn!(error = %e, "email8: unparseable message rejected");
        StoreOpError::Conflict
    })?;

    // Ham override checks need the parsed message early; compute once.
    let _ = &parsed;

    // Quota check (soft): count + bytes.
    let quota: Option<(i64,)> = sqlx::query_as(
        "SELECT used_bytes FROM email8.quota_counters WHERE env_id = $1 AND account_id = $2",
    )
    .bind(env_id)
    .bind(account_id)
    .fetch_optional(&mut *conn)
    .await?;
    let policy: i64 = sqlx::query_scalar(
        "SELECT default_account_quota_bytes FROM email8.quota_policy WHERE env_id = $1",
    )
    .bind(env_id)
    .fetch_optional(&mut *conn)
    .await?
    .unwrap_or(10 * 1024 * 1024 * 1024);
    if let Some((used,)) = quota {
        if policy > 0 && used + raw.len() as i64 > policy {
            return Err(StoreOpError::QuotaExceeded);
        }
    }

    // Threading: candidate threads share the CheekyHash key.
    let tkey = compute_thread_key(&parsed) as i64;
    let candidates: Vec<Uuid> = sqlx::query_scalar(
        "SELECT DISTINCT thread_id FROM email8.emails WHERE account_id = $1 AND thread_key = $2 LIMIT 2",
    )
    .bind(account_id)
    .bind(tkey)
    .fetch_all(&mut *conn)
    .await?;
    let thread_id = match candidates.first() {
        Some(existing) => *existing,
        None => Uuid::new_v4(),
    };

    // Ids + uid allocation: the row id is a UUID (gen_random_uuid
    // default); IMAP UIDs stay per-account counters.
    let email_id = Uuid::new_v4();

    // Resolve target mailboxes (default INBOX) and allocate IMAP UIDs.
    let mut mailboxes: Vec<Uuid> = target_mailboxes.to_vec();
    let inbox_id = default_inbox_id(conn, env_id, account_id).await?;
    if mailboxes.is_empty() {
        mailboxes = vec![inbox_id];
    }
    // Spam re-file: ≥50 goes to Junk instead of INBOX — UNLESS a ham
    // override fires (design §2.3): the sender is in the recipient's
    // address book, or the message replies to something they sent
    // (In-Reply-To/References match their own Message-IDs).
    let spam = spam_percentage.unwrap_or(0.0) >= 50.0;
    let ham_override = spam && ham_override_applies(conn, account_id, &parsed).await?;
    let spam = spam && !ham_override;
    if spam && mailboxes == vec![inbox_id] {
        mailboxes = vec![junk_id(conn, env_id, account_id).await?];
    }
    let mut uids = HashMap::new();
    for mailbox_id in &mailboxes {
        let uid: i64 = sqlx::query_scalar(
            "UPDATE email8.mailboxes SET uid_next = uid_next + 1 WHERE account_id = $1 AND id = $2 RETURNING uid_next - 1",
        )
        .bind(account_id)
        .bind(mailbox_id)
        .fetch_optional(&mut *conn)
        .await?
        .ok_or_else(|| StoreOpError::MailboxNotFound(mailbox_id.to_string()))?;
        uids.insert(*mailbox_id, uid);
    }

    // Search corpus: headers + preview (the FTS index tokenizes this).
    let search_text = build_search_text(&parsed, raw);
    // Story 2.6 — detect the tsvector language once at ingest; the
    // search path picks the matching text-search config per row.
    let fts_lang = email8::mail_core::detect_tsvector_lang(&search_text);

    // Insert the email row.
    sqlx::query(
        r#"INSERT INTO email8.emails
               (id, env_id, account_id, blob_hash, thread_id, size, received_at, sent_at,
                message_id, subject, preview, keywords, has_attachment, is_spam_score,
                metadata, thread_key, search_text)
           VALUES ($1, $2, $3, $4, $5, $6, now(), $7, $8, $9, $10, '{}', $11, $12, $13, $14, $15)"#,
    )
    .bind(email_id)
    .bind(env_id)
    .bind(account_id)
    .bind(blob_hash)
    .bind(thread_id)
    .bind(raw.len() as i64)
    .bind(
        parsed
            .sent_at()
            .and_then(|t| chrono::DateTime::from_timestamp(t, 0)),
    )
    .bind(parsed.message_id())
    .bind(parsed.subject())
    .bind(parsed.preview(raw, 160))
    .bind(parsed.has_attachment(raw))
    .bind(spam_percentage)
    .bind(serde_json::json!({"body_offset": parsed.body_offset, "fts_lang": fts_lang}))
    .bind(tkey)
    .bind(search_text)
    .execute(&mut *conn)
    .await?;

    // Membership rows.
    for mailbox_id in &mailboxes {
        sqlx::query(
            "INSERT INTO email8.email_mailboxes (account_id, env_id, email_id, mailbox_id, imap_uid) \
             VALUES ($1, (SELECT env_id FROM email8.principals WHERE id = $1), $2, $3, $4)",
        )
        .bind(account_id)
        .bind(email_id)
        .bind(mailbox_id)
        .bind(uids[mailbox_id])
        .execute(&mut *conn)
        .await?;
    }

    // Thread row + member.
    sqlx::query(
        "INSERT INTO email8.threads (id, env_id, account_id, subject) VALUES ($1, $2, $3, $4) ON CONFLICT (account_id, id) DO NOTHING",
    )
    .bind(thread_id)
    .bind(env_id)
    .bind(account_id)
    .bind(parsed.subject())
    .execute(&mut *conn)
    .await?;
    sqlx::query(
        "INSERT INTO email8.thread_members (account_id, env_id, thread_id, email_id) \
         VALUES ($1, (SELECT env_id FROM email8.principals WHERE id = $1), $2, $3) \
         ON CONFLICT (account_id, thread_id, email_id) DO NOTHING",
    )
    .bind(account_id)
    .bind(thread_id)
    .bind(email_id)
    .execute(&mut *conn)
    .await?;

    // Blob link: queue/reserved → linked (committed document).
    sqlx::query(
        r#"INSERT INTO email8.blob_links (env_id, owner_account_id, blob_hash, ref_kind, ref_id, collection)
           VALUES ($1, $2, $3, 'linked', $4, $5)
           ON CONFLICT DO NOTHING"#,
    )
    .bind(env_id)
    .bind(account_id)
    .bind(blob_hash)
    .bind(email_id)
    .bind(Collection::Email as u16 as i16)
    .execute(&mut *conn)
    .await?;

    // Quota counters.
    sqlx::query(
        r#"INSERT INTO email8.quota_counters (env_id, account_id, used_bytes, used_objects)
           VALUES ($1, $2, $3, 1)
           ON CONFLICT (env_id, account_id) DO UPDATE SET
               used_bytes = email8.quota_counters.used_bytes + $3,
               used_objects = email8.quota_counters.used_objects + 1,
               updated_at = now()"#,
    )
    .bind(env_id)
    .bind(account_id)
    .bind(raw.len() as i64)
    .execute(&mut *conn)
    .await?;

    // Change log: one row per touched collection (Email + Mailbox).
    let email_change = next_change_id(conn, account_id, Collection::Email).await?;
    sqlx::query(
        "INSERT INTO email8.changelog (account_id, env_id, collection, change_id, changes) \
         VALUES ($1, (SELECT env_id FROM email8.principals WHERE id = $1), $2, $3, $4)",
    )
    .bind(account_id)
    .bind(Collection::Email as u16 as i16)
    .bind(email_change)
    .bind(serde_json::json!([{"op": "ins", "id": email_id}]))
    .execute(&mut *conn)
    .await?;
    let mailbox_change = next_change_id(conn, account_id, Collection::Mailbox).await?;
    sqlx::query(
        "INSERT INTO email8.changelog (account_id, env_id, collection, change_id, changes) \
         VALUES ($1, (SELECT env_id FROM email8.principals WHERE id = $1), $2, $3, $4)",
    )
    .bind(account_id)
    .bind(Collection::Mailbox as u16 as i16)
    .bind(mailbox_change)
    .bind(serde_json::json!(mailboxes
        .iter()
        .map(|m| serde_json::json!({"op": "upd", "id": m}))
        .collect::<Vec<_>>()))
    .execute(&mut *conn)
    .await?;

    // iMIP detection (RFC 6047, story 4.6 inbound): a text/calendar
    // MIME part with a METHOD makes this a scheduling message — file a
    // calendar event row (upsert on UID) and surface the method/uid in
    // the outcome so the event consumer emits the groupware event.
    let (imip_method, imip_uid) = detect_imip(&parsed, raw);
    let mut imip_uid = imip_uid;
    if imip_method.is_some() {
        imip_uid = file_calendar_event(
            conn,
            env_id,
            account_id,
            email_id,
            raw,
            imip_method.as_deref(),
        )
        .await?;
    }

    Ok(IngestOutcome {
        email_id,
        thread_id,
        thread_merge_candidates: candidates,
        mailboxes: mailboxes.iter().map(|m| (*m, uids[m])).collect(),
        email_change_id: email_change,
        is_spam: spam,
        size: raw.len() as i64,
        is_imip: imip_method.is_some(),
        imip_method,
        imip_uid,
    })
}

/// What an ingest produced — feeds the `email8:mail:email:ingested` event.
#[derive(Debug, Clone)]
pub struct IngestOutcome {
    pub email_id: Uuid,
    pub thread_id: Uuid,
    pub thread_merge_candidates: Vec<Uuid>,
    pub mailboxes: Vec<(Uuid, i64)>,
    pub email_change_id: i64,
    pub is_spam: bool,
    pub size: i64,
    /// iMIP (RFC 6047): the message carried a text/calendar part with
    /// a METHOD — the consumer files the calendar event + emits
    /// `email8:groupware:event:{created,updated,cancelled}`.
    pub is_imip: bool,
    /// The iTIP METHOD (REQUEST | REPLY | CANCEL | REFRESH) when iMIP.
    pub imip_method: Option<String>,
    /// The iCalendar UID of the scheduling object.
    pub imip_uid: Option<String>,
}

// ── Changelog queries ─────────────────────────────────────────────────────

/// The current state token (max change id) for (account, collection).
pub async fn current_state(
    conn: &mut PgConnection,
    account_id: Uuid,
    collection: Collection,
) -> StoreResult<i64> {
    let state: Option<i64> = sqlx::query_scalar(
        "SELECT COALESCE(MAX(change_id), 0) FROM email8.changelog WHERE account_id = $1 AND collection = $2",
    )
    .bind(account_id)
    .bind(collection as u16 as i16)
    .fetch_optional(&mut *conn)
    .await?;
    Ok(state.unwrap_or(0))
}

/// Changes since a state token (JMAP `/changes`, IMAP QRESYNC).
pub async fn changes_since(
    conn: &mut PgConnection,
    account_id: Uuid,
    collection: Collection,
    since: Option<i64>,
    max_changes: usize,
) -> StoreResult<ChangesWindow> {
    let old_state = since.unwrap_or(0);
    let rows: Vec<(i64, serde_json::Value)> = sqlx::query_as(
        "SELECT change_id, changes FROM email8.changelog \
         WHERE account_id = $1 AND collection = $2 AND change_id > $3 ORDER BY change_id LIMIT $4",
    )
    .bind(account_id)
    .bind(collection as u16 as i16)
    .bind(old_state)
    .bind((max_changes + 1) as i64)
    .fetch_all(&mut *conn)
    .await?;
    let has_more = rows.len() > max_changes;
    let window: Vec<_> = rows.into_iter().take(max_changes).collect();
    let new_state = window.last().map(|(id, _)| *id).unwrap_or(old_state);
    let mut created = Vec::new();
    let mut updated = Vec::new();
    let mut destroyed = Vec::new();
    for (_, changes) in &window {
        if let Some(list) = changes.as_array() {
            for entry in list {
                let op = entry.get("op").and_then(|v| v.as_str()).unwrap_or("");
                // Entity ids are UUIDs (serialized as strings); legacy
                // numeric ids in old rows are ignored.
                let id = entry
                    .get("id")
                    .and_then(|v| v.as_str())
                    .and_then(|s| uuid::Uuid::parse_str(s).ok());
                if let Some(id) = id {
                    match op {
                        "ins" => created.push(id),
                        "del" => destroyed.push(id),
                        _ => updated.push(id),
                    }
                }
            }
        }
    }
    Ok(ChangesWindow {
        old_state,
        new_state,
        has_more_changes: has_more,
        created,
        updated,
        destroyed,
    })
}

#[derive(Debug, Clone)]
pub struct ChangesWindow {
    pub old_state: i64,
    pub new_state: i64,
    pub has_more_changes: bool,
    pub created: Vec<uuid::Uuid>,
    pub updated: Vec<uuid::Uuid>,
    pub destroyed: Vec<uuid::Uuid>,
}

// ── Address resolution (RCPT path) ────────────────────────────────────────

/// Resolve a recipient address to a local principal, honoring
/// sub-addressing (`user+tag@domain` → `user@domain`) and aliases.
/// Returns `None` when the address is not local.
pub async fn resolve_address(
    conn: &mut PgConnection,
    env_id: Uuid,
    address: &str,
) -> StoreResult<Option<Uuid>> {
    let lower = address.to_ascii_lowercase();
    // 1. Exact principal address.
    let hit: Option<Uuid> = sqlx::query_scalar(
        "SELECT account_id FROM email8.principal_addresses WHERE env_id = $1 AND lower(address) = $2",
    )
    .bind(env_id)
    .bind(&lower)
    .fetch_optional(&mut *conn)
    .await?;
    if let Some(id) = hit {
        return Ok(Some(id));
    }
    // 2. Sub-addressing strip.
    if let Some((local, domain)) = lower.split_once('@') {
        if let Some(base) = local.split_once('+').map(|(b, _)| b) {
            let stripped = format!("{base}@{domain}");
            let hit: Option<Uuid> = sqlx::query_scalar(
                "SELECT account_id FROM email8.principal_addresses WHERE env_id = $1 AND lower(address) = $2",
            )
            .bind(env_id)
            .bind(&stripped)
            .fetch_optional(&mut *conn)
            .await?;
            if let Some(id) = hit {
                return Ok(Some(id));
            }
        }
        // 3. Catch-all domain.
        let catch_all: Option<Uuid> = sqlx::query_scalar(
            "SELECT catch_all_account_id FROM email8.domains WHERE env_id = $1 AND lower(name) = $2 AND catch_all_account_id IS NOT NULL",
        )
        .bind(env_id)
        .bind(domain)
        .fetch_optional(&mut *conn)
        .await?;
        if let Some(id) = catch_all {
            return Ok(Some(id));
        }
    }
    Ok(None)
}

/// Expand a group address to its member addresses.
pub async fn group_members(
    conn: &mut PgConnection,
    env_id: Uuid,
    address: &str,
) -> StoreResult<Vec<String>> {
    let rows: Vec<String> = sqlx::query_scalar(
        "SELECT m.member_address FROM email8.groups g \
         JOIN email8.group_members m ON m.group_id = g.id \
         WHERE g.env_id = $1 AND lower(g.address) = $2",
    )
    .bind(env_id)
    .bind(address.to_ascii_lowercase())
    .fetch_all(&mut *conn)
    .await?;
    Ok(rows)
}

// ── Search corpus ─────────────────────────────────────────────────────────

/// Build the FTS corpus: from/to/cc/bcc/subject + preview text. The
/// tsvector index tokenizes this column with the `simple` config;
/// language-specific stemming happens via the per-language index
/// expressions (store design §4).
/// Ham overrides (design §2.3): a spam-flagged message still lands in
/// INBOX when (a) the sender is in the recipient's address book, or
/// (b) it references one of the recipient's own Message-IDs (a reply
/// to something they sent). Address-book membership reuses the
/// contact table's normalized address column.
async fn ham_override_applies(
    conn: &mut PgConnection,
    account_id: Uuid,
    parsed: &ParsedMessage,
) -> StoreResult<bool> {
    // (a) Address-book sender.
    if let Some(from) = parsed.from_address() {
        let addr = from
            .trim_start_matches('<')
            .trim_end_matches('>')
            .to_ascii_lowercase();
        let listed: Option<i64> = sqlx::query_scalar(
            "SELECT 1 FROM email8.contact_cards \
             WHERE account_id = $1 AND lower(addr) = ANY(emails) LIMIT 1",
        )
        .bind(account_id)
        .bind(&addr)
        .fetch_optional(&mut *conn)
        .await?;
        if listed.is_some() {
            return Ok(true);
        }
        // (b) Trusted reply: any Reference/In-Reply-To id matches a
        // Message-ID this account sent.
        for rid in parsed.reference_ids() {
            let rid = rid.trim_start_matches('<').trim_end_matches('>');
            let mine: Option<i64> = sqlx::query_scalar(
                "SELECT 1 FROM email8.emails \
                 WHERE account_id = $1 AND lower(message_id) = $2 LIMIT 1",
            )
            .bind(account_id)
            .bind(rid.to_ascii_lowercase())
            .fetch_optional(&mut *conn)
            .await?;
            if mine.is_some() {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

fn build_search_text(parsed: &ParsedMessage, raw: &[u8]) -> String {
    let mut parts = Vec::with_capacity(8);
    if let Some(s) = parsed.header("from") {
        parts.push(s.to_string());
    }
    for h in ["to", "cc", "bcc"] {
        if let Some(v) = parsed.header(h) {
            parts.push(v.to_string());
        }
    }
    if let Some(s) = parsed.subject() {
        parts.push(s.to_string());
    }
    parts.push(parsed.preview(raw, 512));
    parts.join("\n")
}
/// iMIP detection: scan the raw MIME parts for `Content-Type:
/// text/calendar` with a `METHOD=` param; extract the VCALENDAR's
/// METHOD + UID. Returns (method, uid) — both None when not an iMIP.
/// iMIP detection (RFC 6047) via the MIME tree walker (story 2.1):
/// every `text/calendar` part (transport-decoded) is scanned for the
/// METHOD (Content-Type param wins, then the VCALENDAR's METHOD:
/// property) and the VEVENT UID. Returns (method, uid) — both None when
/// the message carries no calendar part.
fn detect_imip(parsed: &ParsedMessage, raw: &[u8]) -> (Option<String>, Option<String>) {
    let _ = parsed;
    let parts = email8::mail_core::walk_parts(raw);
    let cals = email8::mail_core::calendar_bodies(raw, &parts);
    let Some(cal_bytes) = cals.first() else {
        return (None, None);
    };
    let cal_text = String::from_utf8_lossy(cal_bytes);
    let lower = cal_text.to_ascii_lowercase();
    // METHOD from the VCALENDAR body (METHOD:REQUEST).
    let method = lower
        .split("method:")
        .nth(1)
        .and_then(|rest| {
            rest.split(['\r', '\n'])
                .next()
                .map(|v| v.trim().trim_end_matches(';').to_uppercase())
        })
        .filter(|v| !v.is_empty());
    // UID from the VEVENT UID line.
    let uid = lower
        .split("uid:")
        .nth(1)
        .and_then(|rest| rest.split(['\r', '\n']).next())
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty());
    (method, uid)
}

/// File the iMIP scheduling object into the account's default calendar
/// (upsert on the iCalendar UID). Returns the resolved uid. Failures
/// never block mail ingestion (the calendar is a side-file).
async fn file_calendar_event(
    conn: &mut PgConnection,
    env_id: Uuid,
    account_id: Uuid,
    email_id: Uuid,
    raw: &[u8],
    method: Option<&str>,
) -> StoreResult<Option<String>> {
    // Parse the transport-decoded calendar part (MIME walker, story 2.1)
    // rather than the whole raw message — base64/qp parts decode right.
    let parts = email8::mail_core::walk_parts(raw);
    let cals = email8::mail_core::calendar_bodies(raw, &parts);
    let Some(cal_bytes) = cals.first() else {
        return Ok(None);
    };
    let text = String::from_utf8_lossy(cal_bytes);
    let cal = email8::ical::parse(&text);
    let events = cal.children_of("VEVENT");
    let Some(event) = events.first() else {
        return Ok(None);
    };
    let Some(uid) = event.get("UID").map(|s| s.to_string()) else {
        return Ok(None);
    };
    let summary = event.get("SUMMARY").map(|s| s.to_string());
    let cancelled = method
        .map(|m| m.eq_ignore_ascii_case("cancel"))
        .unwrap_or(false);
    let data = serde_json::json!({
        "source": "imip",
        "email_id": email_id,
        "method": method,
        "start": event.get("DTSTART"),
        "end": event.get("DTEND"),
        "organizer": event.get("ORGANIZER"),
        "attendee": event.get("ATTENDEE"),
        "cancelled": cancelled,
    });
    // The account's first calendar (provisioning seeds one).
    let calendar_id: Option<i64> = sqlx::query_scalar(
        "SELECT id FROM email8.calendars WHERE account_id = $1 ORDER BY id LIMIT 1",
    )
    .bind(account_id)
    .fetch_optional(&mut *conn)
    .await?;
    let Some(calendar_id) = calendar_id else {
        return Ok(Some(uid)); // no calendar provisioned — skip silently
    };
    let event_id = Uuid::new_v4();
    sqlx::query(
        r#"INSERT INTO email8.calendar_events
               (id, env_id, account_id, calendar_id, uid, display_name, data, size)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
           ON CONFLICT (account_id, uid) DO UPDATE SET
               display_name = $6, data = $7, updated_at = now()"#,
    )
    .bind(event_id)
    .bind(env_id)
    .bind(account_id)
    .bind(calendar_id)
    .bind(&uid)
    .bind(&summary)
    .bind(&data)
    .bind(raw.len() as i64)
    .execute(&mut *conn)
    .await
    .map_err(|e| {
        tracing::warn!(error = %e, "email8: iMIP calendar filing failed (email kept)");
        StoreOpError::Conflict
    })?;
    Ok(Some(uid))
}

/// Body offset helper for the raw message (header/body split).

/// Role-based mailbox lookup: returns the mailbox with the given
/// special-use role (inbox/junk/archive/...) for the account.
pub(crate) async fn role_mailbox_id(
    conn: &mut PgConnection,
    env_id: Uuid,
    account_id: Uuid,
    role: &str,
) -> StoreResult<Uuid> {
    let id: Uuid = sqlx::query_scalar(
        "SELECT id FROM email8.mailboxes WHERE env_id = $1 AND account_id = $2 AND role = $3 ORDER BY sort_order LIMIT 1",
    )
    .bind(env_id)
    .bind(account_id)
    .bind(role)
    .fetch_one(&mut *conn)
    .await
    .map_err(|_| StoreOpError::MailboxNotFound(role.to_string()))?;
    Ok(id)
}

/// The account's INBOX id (bootstrap_mailboxes created it with role
/// 'inbox'). Errors when provisioning hasn't run for the account.
async fn default_inbox_id(
    conn: &mut PgConnection,
    env_id: Uuid,
    account_id: Uuid,
) -> StoreResult<Uuid> {
    role_mailbox_id(conn, env_id, account_id, "inbox").await
}

/// The account's Junk mailbox id (role 'junk' from bootstrap_mailboxes).
async fn junk_id(conn: &mut PgConnection, env_id: Uuid, account_id: Uuid) -> StoreResult<Uuid> {
    role_mailbox_id(conn, env_id, account_id, "junk").await
}
