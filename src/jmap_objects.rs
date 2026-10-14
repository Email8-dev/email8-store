// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Email8:Store
// SPDX-License-Identifier: Apache-2.0

//! JMAP object handlers — Mailbox/Email/Thread get, query, changes.
//! All run on a tenant-context connection with the account binding set.
use uuid::Uuid;

use serde_json::{json, Value};
use sqlx::Row;

use email8::contracts::Collection;
use email8::mail_core::ParsedMessage;

use crate::store_ops::{self, StoreOpError};

/// `Mailbox/get` — list (optionally filtered by `ids`).
pub async fn mailbox_get(
    conn: &mut sqlx::PgConnection,
    account_id: Uuid,
    args: &Value,
) -> Result<Value, StoreOpError> {
    let ids: Option<Vec<Uuid>> = args.get("ids").map(|v| {
        v.as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|i| i.as_str().and_then(|s| Uuid::parse_str(s).ok()))
                    .collect()
            })
            .unwrap_or_default()
    });
    let state = store_ops::current_state(conn, account_id, Collection::Mailbox).await?;
    let rows = if let Some(ids) = ids.filter(|v| !v.is_empty()) {
        sqlx::query(
            "SELECT id, name, role, parent_id, sort_order, uid_validity, is_subscribed \
             FROM email8.mailboxes WHERE account_id = $1 AND id = ANY($2) ORDER BY sort_order, id",
        )
        .bind(account_id)
        .bind(&ids)
        .fetch_all(&mut *conn)
        .await?
    } else {
        sqlx::query(
            "SELECT id, name, role, parent_id, sort_order, uid_validity, is_subscribed \
             FROM email8.mailboxes WHERE account_id = $1 ORDER BY sort_order, id",
        )
        .bind(account_id)
        .fetch_all(&mut *conn)
        .await?
    };
    let list: Vec<Value> = rows
        .iter()
        .map(|r| {
            json!({
                "id": r.get::<Uuid, _>("id").to_string(),
                "name": r.get::<String, _>("name"),
                "parentId": r.get::<Option<Uuid>, _>("parent_id").map(|v| v.to_string()),
                "role": r.get::<Option<String>, _>("role"),
                "sortOrder": r.get::<i32, _>("sort_order"),
                "myRights": { "mayReadItems": true, "mayAddItems": true, "mayRemoveItems": true, "maySetSeen": true, "maySetKeywords": true, "mayCreateChild": true, "mayRename": true, "mayDelete": true, "maySubmit": true },
                "isSubscribed": r.get::<bool, _>("is_subscribed"),
            })
        })
        .collect();
    Ok(json!({ "list": list, "state": state.to_string(), "notFound": [] }))
}

/// `Email/get` — full properties incl. preview + blob id.
pub async fn email_get(
    conn: &mut sqlx::PgConnection,
    account_id: Uuid,
    args: &Value,
    state: &crate::data_api::AppState,
) -> Result<Value, StoreOpError> {
    let ids: Vec<Uuid> = args
        .get("ids")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|i| i.as_str().and_then(|s| Uuid::parse_str(s).ok()))
                .collect()
        })
        .unwrap_or_default();
    let state_token = store_ops::current_state(conn, account_id, Collection::Email).await?;
    if ids.is_empty() {
        return Ok(json!({ "list": [], "state": state_token.to_string(), "notFound": [] }));
    }
    let rows = sqlx::query(
        "SELECT id, blob_hash, thread_id, size, received_at, sent_at, message_id, subject, \
                preview, keywords, has_attachment, metadata \
         FROM email8.emails WHERE account_id = $1 AND id = ANY($2)",
    )
    .bind(account_id)
    .bind(&ids)
    .fetch_all(&mut *conn)
    .await?;
    let mut list = Vec::with_capacity(rows.len());
    let mut not_found: Vec<String> = Vec::new();
    let found_ids: Vec<Uuid> = rows.iter().map(|r| r.get::<Uuid, _>("id")).collect();
    for id in &ids {
        if !found_ids.contains(id) {
            not_found.push(id.to_string());
        }
    }
    for r in rows {
        let id: Uuid = r.get("id");
        let received: chrono::DateTime<chrono::Utc> = r.get("received_at");
        let metadata: Value = r.get("metadata");
        // Sender address comes from the parsed headers — fetch lazily via
        // Storage only when properties were requested. P1 keeps the row
        // fields (headers are re-parsed by the client from blobId).
        let blob_hash: String = r.get("blob_hash");
        let sender = metadata
            .get("from")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let from_value: Value = sender
            .map(|s| json!([{ "email": s }]))
            .unwrap_or(Value::Null);
        list.push(json!({
            "id": id.to_string(),
            "blobId": blob_hash,
            "threadId": r.get::<Uuid, _>("thread_id").to_string(),
            "mailboxIds": email_mailbox_ids(conn, account_id, id).await?,
            "keywords": keywords_map(r.get::<Vec<String>, _>("keywords")),
            "size": r.get::<i64, _>("size"),
            "receivedAt": received.to_rfc3339(),
            "sentAt": r.get::<Option<chrono::DateTime<chrono::Utc>>, _>("sent_at").map(|d| d.to_rfc3339()),
            "messageId": r.get::<Option<String>, _>("message_id"),
            "subject": r.get::<Option<String>, _>("subject"),
            "preview": r.get::<Option<String>, _>("preview"),
            "hasAttachment": r.get::<bool, _>("has_attachment"),
            "from": from_value,
        }));
    }
    let _ = state;
    Ok(json!({ "list": list, "state": state_token.to_string(), "notFound": not_found }))
}

async fn email_mailbox_ids(
    conn: &mut sqlx::PgConnection,
    account_id: Uuid,
    email_id: Uuid,
) -> Result<Value, StoreOpError> {
    let rows: Vec<(Uuid,)> = sqlx::query_as(
        "SELECT mailbox_id FROM email8.email_mailboxes WHERE account_id = $1 AND email_id = $2",
    )
    .bind(account_id)
    .bind(email_id)
    .fetch_all(&mut *conn)
    .await?;
    let mut map = serde_json::Map::new();
    for (m,) in rows {
        map.insert(m.to_string(), json!(true));
    }
    Ok(Value::Object(map))
}

fn keywords_map(keywords: Vec<String>) -> Value {
    let mut map = serde_json::Map::new();
    for k in keywords {
        map.insert(k, json!(true));
    }
    Value::Object(map)
}

/// `Thread/get`.
pub async fn thread_get(
    conn: &mut sqlx::PgConnection,
    account_id: Uuid,
    args: &Value,
) -> Result<Value, StoreOpError> {
    let ids: Vec<Uuid> = args
        .get("ids")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|i| i.as_str().and_then(|s| Uuid::parse_str(s).ok()))
                .collect()
        })
        .unwrap_or_default();
    let state = store_ops::current_state(conn, account_id, Collection::Thread).await?;
    if ids.is_empty() {
        return Ok(json!({ "list": [], "state": state.to_string(), "notFound": [] }));
    }
    let rows = sqlx::query(
        "SELECT t.id, t.subject FROM email8.threads t \
         WHERE t.account_id = $1 AND t.id = ANY($2)",
    )
    .bind(account_id)
    .bind(&ids)
    .fetch_all(&mut *conn)
    .await?;
    let mut list = Vec::new();
    for r in rows {
        let id: Uuid = r.get("id");
        let emails: Vec<Uuid> = sqlx::query_scalar(
            "SELECT email_id FROM email8.thread_members WHERE account_id = $1 AND thread_id = $2 ORDER BY email_id",
        )
        .bind(account_id)
        .bind(id)
        .fetch_all(&mut *conn)
        .await?;
        list.push(json!({
            "id": id.to_string(),
            "emails": emails.iter().map(|e| e.to_string()).collect::<Vec<_>>(),
            "subject": r.get::<Option<String>, _>("subject"),
        }));
    }
    Ok(json!({ "list": list, "state": state.to_string(), "notFound": [] }))
}

/// `Email/query` — filter translation onto the SQL surface (store design §4).
pub async fn email_query(
    conn: &mut sqlx::PgConnection,
    account_id: Uuid,
    args: &Value,
) -> Result<Value, StoreOpError> {
    let position = args.get("position").and_then(|v| v.as_i64()).unwrap_or(0).max(0);
    let limit = args.get("limit")
        .and_then(|v| v.as_i64())
        .unwrap_or(50)
        .clamp(1, 512) as i64;
    let filter = args.get("filter").cloned().unwrap_or(json!({}));

    // Build the WHERE clause from the filter object.
    let mut clauses: Vec<String> = Vec::new();
    let mut binds: Vec<Value> = Vec::new();
    let mut n = 0;
    if let Some(mailbox) = filter.get("inMailbox").and_then(|v| v.as_str()) {
        n += 1;
        clauses.push(format!(
            "id IN (SELECT email_id FROM email8.email_mailboxes WHERE account_id = $1 AND mailbox_id = ${n}::uuid)"
        ));
        binds.push(json!(mailbox));
    }
    if let Some(text) = filter.get("text").and_then(|v| v.as_str()) {
        n += 1;
        clauses.push(format!("search_text ILIKE '%' || ${n} || '%'"));
        binds.push(json!(text));
    }
    if let Some(subject) = filter.get("subject").and_then(|v| v.as_str()) {
        n += 1;
        clauses.push(format!("subject ILIKE '%' || ${n} || '%'"));
        binds.push(json!(subject));
    }
    if let Some(from) = filter.get("from").and_then(|v| v.as_str()) {
        n += 1;
        clauses.push(format!("search_text ILIKE '%' || ${n} || '%'"));
        binds.push(json!(from));
    }
    if let Some(keyword) = filter.get("hasKeyword").and_then(|v| v.as_str()) {
        n += 1;
        clauses.push(format!("${n} = ANY(keywords)"));
        binds.push(json!(keyword));
    }
    if let Some(before) = filter.get("before").and_then(|v| v.as_str()) {
        n += 1;
        clauses.push(format!("received_at < ${n}::timestamptz"));
        binds.push(json!(before));
    }
    if let Some(after) = filter.get("after").and_then(|v| v.as_str()) {
        n += 1;
        clauses.push(format!("received_at > ${n}::timestamptz"));
        binds.push(json!(after));
    }
    let where_sql = if clauses.is_empty() {
        String::new()
    } else {
        format!("AND {}", clauses.join(" AND "))
    };

    // Count matches with the filter binds applied ($2..$N+1).
    let count_sql = format!(
        "SELECT COUNT(*) FROM email8.emails WHERE account_id = $1 {where_sql}"
    );
    let mut count_q = sqlx::query_scalar::<_, i64>(&count_sql).bind(account_id);
    for b in &binds {
        count_q = count_q.bind(b.as_str().unwrap_or(""));
    }
    let total = count_q.fetch_one(&mut *conn).await?;

    // Page the ids: filter binds take $2..$(N+1), limit and position land
    // directly after them ($(N+2) and $(N+3)).
    let limit_p = n + 2;
    let offset_p = n + 3;
    let page_sql = format!(
        "SELECT id FROM email8.emails WHERE account_id = $1 {where_sql} \
         ORDER BY received_at DESC LIMIT ${limit_p} OFFSET ${offset_p}"
    );
    let mut q = sqlx::query_scalar::<_, Uuid>(&page_sql).bind(account_id);
    for b in &binds {
        q = q.bind(b.as_str().unwrap_or(""));
    }
    let rows: Vec<Uuid> = q.bind(limit).bind(position).fetch_all(&mut *conn).await?;

    // SearchSnippet support (RFC 8620 §5, story 2.6): when the filter
    // carries a text query, build per-id snippets from preview/subject.
    let snippets = match filter.get("text").and_then(|v| v.as_str()) {
        Some(text) => {
            let snippet_sql = format!(
                "SELECT id, coalesce(subject, '') || ' ' || coalesce(preview, '') \
                 FROM email8.emails WHERE account_id = $1 {where_sql} \
                 ORDER BY received_at DESC LIMIT ${limit_p} OFFSET ${offset_p}"
            );
            let mut sq = sqlx::query(&snippet_sql).bind(account_id);
            for b in &binds {
                sq = sq.bind(b.as_str().unwrap_or(""));
            }
            let corpus_rows = sq.bind(limit).bind(position).fetch_all(&mut *conn).await?;
            let map: serde_json::Map<String, Value> = corpus_rows
                .iter()
                .filter_map(|r| {
                    let id: Uuid = r.try_get(0).ok()?;
                    let corpus: String = r.try_get(1).unwrap_or_default();
                    Some((
                        id.to_string(),
                        serde_json::Value::String(
                            email8::mail_core::snippet(&corpus, text, 100).preview,
                        ),
                    ))
                })
                .collect();
            Some(serde_json::Value::Object(map))
        }
        None => None,
    };

    Ok(json!({
        "ids": rows.iter().map(|i| i.to_string()).collect::<Vec<_>>(),
        "position": position,
        "total": total,
        "canCalculateChanges": false,
        "limit": limit,
        "snippet": snippets,
    }))
}

/// `{Type}/changes` — shared for Email/Mailbox/Thread.
pub async fn changes(
    conn: &mut sqlx::PgConnection,
    account_id: Uuid,
    object: &str,
    args: &Value,
) -> Result<Value, StoreOpError> {
    let collection = match object {
        "Email" => Collection::Email,
        "Mailbox" => Collection::Mailbox,
        "Thread" => Collection::Thread,
        _ => return Err(StoreOpError::Conflict),
    };
    let since = args
        .get("sinceState")
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse::<i64>().ok());
    let max = args.get("maxChanges").and_then(|v| v.as_u64()).unwrap_or(64) as usize;
    let window = store_ops::changes_since(conn, account_id, collection, since, max).await?;
    Ok(json!({
        "oldState": window.old_state.to_string(),
        "newState": window.new_state.to_string(),
        "created": window.created.iter().map(|i| i.to_string()).collect::<Vec<_>>(),
        "updated": window.updated.iter().map(|i| i.to_string()).collect::<Vec<_>>(),
        "destroyed": window.destroyed.iter().map(|i| i.to_string()).collect::<Vec<_>>(),
        "hasMoreChanges": window.has_more_changes,
    }))
}

/// Reuse the parser for admin/report views (search corpus builder).
pub fn parse_headers(raw: &[u8]) -> Option<ParsedMessage> {
    ParsedMessage::parse(raw).ok()
}

// ── JMAP set methods (RFC 8620 §5.3) ─────────────────────────────────────

/// `Email/set` — update (keywords) / destroy. Creation flows through
/// the ingest API (APPEND / SMTP), not through Email/set (RFC 8620
/// §5.3: only the blob upload path can mint an email).
pub async fn email_set(
    conn: &mut sqlx::PgConnection,
    account_id: Uuid,
    args: &Value,
) -> Result<Value, StoreOpError> {
    let old_state = args.get("ifInState").and_then(|v| v.as_str()).unwrap_or("0");
    let _ = old_state;
    // Email creation flows through the ingest API (APPEND / SMTP);
    // Email/set's create map is always empty per RFC 8620 §5.3.
    let created = json!({});
    let mut updated: Vec<String> = Vec::new();
    let mut destroyed: Vec<String> = Vec::new();
    let not_created = json!({});
    let mut not_updated = json!({});
    let mut not_destroyed = json!({});

    // Update path — keywords / mailboxIds today.
    if let Some(updates) = args.get("update").and_then(|v| v.as_object()) {
        for (id_str, patch) in updates {
            let Ok(id) = id_str.parse::<Uuid>() else {
                not_updated.as_object_mut().unwrap()
                    .insert(id_str.clone(), json!("Invalid email id"));
                continue;
            };
            let res = email_apply_patch(conn, account_id, id, patch).await;
            match res {
                Ok(()) => updated.push(id_str.clone()),
                Err(e) => {
                    not_updated.as_object_mut().unwrap().insert(id_str.clone(), json!(e.to_string()));
                }
            }
        }
    }

    // Destroy path — tombstone + membership delete (the IMAP EXPUNGE
    // shares this semantics).
    if let Some(destroys) = args.get("destroy").and_then(|v| v.as_array()) {
        for id_val in destroys {
            let Some(id) = id_val.as_str().and_then(|s| Uuid::parse_str(s).ok()) else {
                not_destroyed.as_object_mut().unwrap()
                    .insert(id_val.to_string(), json!("Invalid email id"));
                continue;
            };
            let res = sqlx::query(
                "DELETE FROM email8.email_mailboxes WHERE account_id = $1 AND email_id = $2",
            )
            .bind(account_id)
            .bind(id)
            .execute(&mut *conn)
            .await;
            match res {
                Ok(_) => {
                    let _ = sqlx::query(
                        "UPDATE email8.emails SET deleted_at = now() WHERE account_id = $1 AND id = $2",
                    )
                    .bind(account_id)
                    .bind(id)
                    .execute(&mut *conn)
                    .await;
                    destroyed.push(id.to_string());
                }
                Err(e) => {
                    not_destroyed.as_object_mut().unwrap().insert(id.to_string(), json!(e.to_string()));
                }
            }
        }
    }

    Ok(json!({
        "oldState": old_state,
        "newState": "1",
        "created": created,
        "updated": updated,
        "destroyed": destroyed,
        "notCreated": not_created,
        "notUpdated": not_updated,
        "notDestroyed": not_destroyed,
    }))
}

/// Apply one Email/set patch (keywords / mailboxIds).
pub(crate) async fn email_apply_patch(
    conn: &mut sqlx::PgConnection,
    account_id: Uuid,
    email_id: Uuid,
    patch: &Value,
) -> Result<(), StoreOpError> {
    if let Some(keywords) = patch.get("keywords").and_then(|v| v.as_object()) {
        // The patch object maps keyword → true (set) / false (clear).
        let mut kws: Vec<String> = Vec::new();
        for (k, on) in keywords {
            if on.as_bool().unwrap_or(false) {
                kws.push(k.to_ascii_lowercase());
            }
        }
        sqlx::query(
            "UPDATE email8.emails SET keywords = $3, updated_at = now() \
             WHERE account_id = $1 AND id = $2",
        )
        .bind(account_id)
        .bind(email_id)
        .bind(&kws)
        .execute(&mut *conn)
        .await?;
    }
    if let Some(mailbox_ids) = patch.get("mailboxIds").and_then(|v| v.as_object()) {
        // Re-place the email into the set of mailboxes (RFC 8620 —
        // mailboxIds is the authoritative membership set).
        sqlx::query(
            "DELETE FROM email8.email_mailboxes WHERE account_id = $1 AND email_id = $2",
        )
        .bind(account_id)
        .bind(email_id)
        .execute(&mut *conn)
        .await?;
        for (mailbox_str, on) in mailbox_ids {
            if !on.as_bool().unwrap_or(false) {
                continue;
            }
            let Ok(mailbox_id) = Uuid::parse_str(mailbox_str) else {
                continue;
            };
            let uid: i64 = sqlx::query_scalar(
                "UPDATE email8.mailboxes SET uid_next = uid_next + 1 \
                 WHERE account_id = $1 AND id = $2 RETURNING uid_next - 1",
            )
            .bind(account_id)
            .bind(mailbox_id)
            .fetch_optional(&mut *conn)
            .await?
            .unwrap_or(0);
            sqlx::query(
                "INSERT INTO email8.email_mailboxes (account_id, env_id, email_id, mailbox_id, imap_uid) \
                 VALUES ($1, (SELECT env_id FROM email8.principals WHERE id = $1), $2, $3, $4) \
                 ON CONFLICT (account_id, email_id, mailbox_id) DO NOTHING",
            )
            .bind(account_id)
            .bind(email_id)
            .bind(mailbox_id)
            .bind(uid)
            .execute(&mut *conn)
            .await?;
        }
    }
    Ok(())
}

/// `Mailbox/set` — create / update / destroy mailboxes.
pub async fn mailbox_set(
    conn: &mut sqlx::PgConnection,
    account_id: Uuid,
    args: &Value,
) -> Result<Value, StoreOpError> {
    let mut created = json!({});
    let mut updated: Vec<String> = Vec::new();
    let mut destroyed: Vec<String> = Vec::new();
    let mut not_created = json!({});
    let mut not_updated = json!({});
    let mut not_destroyed = json!({});

    if let Some(creates) = args.get("create").and_then(|v| v.as_object()) {
        for (cid, props) in creates {
            let name = props.get("name").and_then(|v| v.as_str()).unwrap_or("");
            if name.is_empty() {
                not_created.as_object_mut().unwrap()
                    .insert(cid.clone(), json!("Mailbox name required"));
                continue;
            }
            let role = props.get("role").and_then(|v| v.as_str());
            let parent_id = props
                .get("parentId")
                .and_then(|v| v.as_str())
                .and_then(|s| Uuid::parse_str(s).ok());
            let id = Uuid::new_v4();
            let res = sqlx::query(
                "INSERT INTO email8.mailboxes \
                     (id, env_id, account_id, name, role, parent_id, uid_validity) \
                 SELECT $1, env_id, $2, $3, $4, $5, $6 \
                 FROM email8.principals WHERE id = $2",
            )
            .bind(id)
            .bind(account_id)
            .bind(name)
            .bind(role)
            .bind(parent_id)
            .bind(chrono::Utc::now().timestamp_millis())
            .execute(&mut *conn)
            .await;
            match res {
                Ok(_) => {
                    created.as_object_mut().unwrap()
                        .insert(cid.clone(), json!({ "id": id.to_string(), "name": name }));
                }
                Err(e) => {
                    not_created.as_object_mut().unwrap().insert(cid.clone(), json!(e.to_string()));
                }
            }
        }
    }

    if let Some(updates) = args.get("update").and_then(|v| v.as_object()) {
        for (id_str, patch) in updates {
            let Ok(id) = id_str.parse::<Uuid>() else {
                not_updated.as_object_mut().unwrap()
                    .insert(id_str.clone(), json!("Invalid mailbox id"));
                continue;
            };
            let name = patch.get("name").and_then(|v| v.as_str());
            let subscribed = patch.get("isSubscribed").and_then(|v| v.as_bool());
            let res = sqlx::query(
                "UPDATE email8.mailboxes SET \
                     name = COALESCE($3, name), \
                     is_subscribed = COALESCE($4, is_subscribed), \
                     updated_at = now() \
                 WHERE account_id = $1 AND id = $2",
            )
            .bind(account_id)
            .bind(id)
            .bind(name)
            .bind(subscribed)
            .execute(&mut *conn)
            .await;
            match res {
                Ok(_) => updated.push(id_str.clone()),
                Err(e) => {
                    not_updated.as_object_mut().unwrap().insert(id_str.clone(), json!(e.to_string()));
                }
            }
        }
    }

    if let Some(destroys) = args.get("destroy").and_then(|v| v.as_array()) {
        for id_val in destroys {
            let Some(id) = id_val.as_str().and_then(|s| Uuid::parse_str(s).ok()) else {
                not_destroyed.as_object_mut().unwrap()
                    .insert(id_val.to_string(), json!("Invalid mailbox id"));
                continue;
            };
            // Refuse to destroy a non-empty mailbox (RFC 8620 §4.6:
            // destroy fails with mailboxHasEmail).
            let count: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM email8.email_mailboxes \
                 WHERE account_id = $1 AND mailbox_id = $2",
            )
            .bind(account_id)
            .bind(id)
            .fetch_one(&mut *conn)
            .await
            .unwrap_or(0);
            if count > 0 {
                not_destroyed.as_object_mut().unwrap()
                    .insert(id.to_string(), json!("mailboxHasEmail"));
                continue;
            }
            let res = sqlx::query(
                "DELETE FROM email8.mailboxes WHERE account_id = $1 AND id = $2",
            )
            .bind(account_id)
            .bind(id)
            .execute(&mut *conn)
            .await;
            match res {
                Ok(_) => destroyed.push(id.to_string()),
                Err(e) => {
                    not_destroyed.as_object_mut().unwrap().insert(id.to_string(), json!(e.to_string()));
                }
            }
        }
    }

    Ok(json!({
        "oldState": args.get("ifInState").and_then(|v| v.as_str()).unwrap_or("0"),
        "newState": "1",
        "created": created,
        "updated": updated,
        "destroyed": destroyed,
        "notCreated": not_created,
        "notUpdated": not_updated,
        "notDestroyed": not_destroyed,
    }))
}

/// `Identity/get` — the user's send identities (RFC 8622 §2.2).
pub async fn identity_get(
    conn: &mut sqlx::PgConnection,
    account_id: Uuid,
    args: &Value,
) -> Result<Value, StoreOpError> {
    let ids: Option<Vec<String>> = args
        .get("ids")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|i| i.as_str().map(String::from)).collect());
    let rows = if let Some(want) = &ids {
        sqlx::query(
            "SELECT id, address, name, reply_to, bcc_to, text_signature, html_signature \
             FROM email8.identities WHERE account_id = $1 AND id = ANY($2)",
        )
        .bind(account_id)
        .bind(want)
        .fetch_all(&mut *conn)
        .await?
    } else {
        sqlx::query(
            "SELECT id, address, name, reply_to, bcc_to, text_signature, html_signature \
             FROM email8.identities WHERE account_id = $1",
        )
        .bind(account_id)
        .fetch_all(&mut *conn)
        .await?
    };
    let list: Vec<Value> = rows
        .iter()
        .map(|r| {
            json!({
                "id": r.get::<Uuid, _>("id").to_string(),
                "address": r.get::<String, _>("address"),
                "name": r.get::<Option<String>, _>("name"),
                "replyTo": r.get::<Option<String>, _>("reply_to"),
                "bccTo": r.get::<Option<String>, _>("bcc_to"),
                "textSignature": r.get::<Option<String>, _>("text_signature"),
                "htmlSignature": r.get::<Option<String>, _>("html_signature"),
            })
        })
        .collect();
    Ok(json!({ "list": list, "notFound": [] }))
}

/// `PushSubscription/get` — the user's push subscriptions (RFC 8620 §7).
pub async fn push_subscription_get(
    conn: &mut sqlx::PgConnection,
    account_id: Uuid,
    args: &Value,
) -> Result<Value, StoreOpError> {
    let _ = args;
    let rows = sqlx::query(
        "SELECT id, endpoint, types_filter, expires_at \
         FROM email8.push_subscriptions WHERE account_id = $1",
    )
    .bind(account_id)
    .fetch_all(&mut *conn)
    .await?;
    let list: Vec<Value> = rows
        .iter()
        .map(|r| {
            json!({
                "id": r.get::<Uuid, _>("id").to_string(),
                "endpoint": r.get::<String, _>("endpoint"),
                "types": r.get::<Option<String>, _>("types_filter"),
                "expires": r.get::<Option<chrono::DateTime<chrono::Utc>>, _>("expires_at")
                    .map(|d| d.to_rfc3339()),
            })
        })
        .collect();
    Ok(json!({ "list": list, "notFound": [] }))
}
// ── Groupware JMAP objects (story 4.5) ────────────────────────────────────

/// `Calendar/get` — the account's calendar list.
pub async fn calendar_get(
    conn: &mut sqlx::PgConnection,
    account_id: Uuid,
    args: &Value,
) -> Result<Value, StoreOpError> {
    let _ = args;
    let rows = sqlx::query(
        "SELECT id, name, color, description, time_zone, supported_components, version \
         FROM email8.calendars WHERE account_id = $1 ORDER BY sort_order, id",
    )
    .bind(account_id)
    .fetch_all(&mut *conn)
    .await?;
    let list: Vec<Value> = rows
        .iter()
        .map(|r| {
            json!({
                "id": r.get::<Uuid, _>("id").to_string(),
                "name": r.get::<String, _>("name"),
                "color": r.get::<Option<String>, _>("color"),
                "description": r.get::<Option<String>, _>("description"),
                "timeZone": r.get::<Option<String>, _>("time_zone"),
                "supportedComponents": r.get::<Vec<String>, _>("supported_components"),
            })
        })
        .collect();
    Ok(json!({ "list": list, "notFound": [] }))
}

/// `CalendarEvent/get` — events (with occurrence data) filtered by
/// calendar via propertiesFilter.
pub async fn calendar_event_get(
    conn: &mut sqlx::PgConnection,
    account_id: Uuid,
    args: &Value,
) -> Result<Value, StoreOpError> {
    let calendar_filter: Option<Vec<String>> = args
        .get("filter")
        .and_then(|f| f.get("calendarIds"))
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|i| i.as_str().map(String::from)).collect());
    let rows = if let Some(cals) = calendar_filter {
        let cal_ids: Vec<Uuid> = cals.iter().filter_map(|s| Uuid::parse_str(s).ok()).collect();
        sqlx::query(
            "SELECT id, calendar_id, uid, display_name, data, occurrences, updated_at \
             FROM email8.calendar_events \
             WHERE account_id = $1 AND calendar_id = ANY($2) ORDER BY id",
        )
        .bind(account_id)
        .bind(&cal_ids)
        .fetch_all(&mut *conn)
        .await?
    } else {
        sqlx::query(
            "SELECT id, calendar_id, uid, display_name, data, occurrences, updated_at \
             FROM email8.calendar_events WHERE account_id = $1 ORDER BY id",
        )
        .bind(account_id)
        .fetch_all(&mut *conn)
        .await?
    };
    let list: Vec<Value> = rows
        .iter()
        .map(|r| {
            json!({
                "id": r.get::<Uuid, _>("id").to_string(),
                "calendarId": r.get::<Uuid, _>("calendar_id").to_string(),
                "uid": r.get::<String, _>("uid"),
                "title": r.get::<Option<String>, _>("display_name"),
                "data": r.get::<serde_json::Value, _>("data"),
                "occurrences": r.get::<serde_json::Value, _>("occurrences"),
                "updated": r.get::<chrono::DateTime<chrono::Utc>, _>("updated_at").to_rfc3339(),
            })
        })
        .collect();
    Ok(json!({ "list": list, "notFound": [] }))
}

/// `AddressBook/get` — the account's address books.
pub async fn addressbook_get(
    conn: &mut sqlx::PgConnection,
    account_id: Uuid,
    args: &Value,
) -> Result<Value, StoreOpError> {
    let _ = args;
    let rows = sqlx::query(
        "SELECT id, name, description, version \
         FROM email8.addressbooks WHERE account_id = $1 ORDER BY id",
    )
    .bind(account_id)
    .fetch_all(&mut *conn)
    .await?;
    let list: Vec<Value> = rows
        .iter()
        .map(|r| {
            json!({
                "id": r.get::<Uuid, _>("id").to_string(),
                "name": r.get::<String, _>("name"),
                "description": r.get::<Option<String>, _>("description"),
            })
        })
        .collect();
    Ok(json!({ "list": list, "notFound": [] }))
}

/// `ContactCard/get` — contact cards (the parsed vCard JSON + the
/// normalized emails array for ham-override lookups).
pub async fn contact_card_get(
    conn: &mut sqlx::PgConnection,
    account_id: Uuid,
    args: &Value,
) -> Result<Value, StoreOpError> {
    let book_filter: Option<Vec<String>> = args
        .get("filter")
        .and_then(|f| f.get("addressbookIds"))
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|i| i.as_str().map(String::from)).collect());
    let rows = if let Some(books) = book_filter {
        let ids: Vec<Uuid> = books.iter().filter_map(|s| Uuid::parse_str(s).ok()).collect();
        sqlx::query(
            "SELECT id, addressbook_id, display_name, card, emails, updated_at \
             FROM email8.contact_cards \
             WHERE account_id = $1 AND addressbook_id = ANY($2) ORDER BY id",
        )
        .bind(account_id)
        .bind(&ids)
        .fetch_all(&mut *conn)
        .await?
    } else {
        sqlx::query(
            "SELECT id, addressbook_id, display_name, card, emails, updated_at \
             FROM email8.contact_cards WHERE account_id = $1 ORDER BY id",
        )
        .bind(account_id)
        .fetch_all(&mut *conn)
        .await?
    };
    let list: Vec<Value> = rows
        .iter()
        .map(|r| {
            json!({
                "id": r.get::<Uuid, _>("id").to_string(),
                "addressbookId": r.get::<Uuid, _>("addressbook_id").to_string(),
                "displayName": r.get::<Option<String>, _>("display_name"),
                "card": r.get::<serde_json::Value, _>("card"),
                "emails": r.get::<Vec<String>, _>("emails"),
            })
        })
        .collect();
    Ok(json!({ "list": list, "notFound": [] }))
}

// ── EmailSubmission/set (story 3.11) ──────────────────────────────────────

/// `EmailSubmission/set` — create submissions by proxying to the Mta
/// `/v1/internal/submit` API (RFC 8621 §6.3). Each create carries the
/// draft Email id + envelope; onSuccessUpdateEmail-style chaining is
/// the client's follow-up Email/set call.
pub async fn email_submission_set(
    state: &crate::data_api::AppState,
    m: &crate::auth::MailAuth,
    account_id: Uuid,
    args: &Value,
) -> Result<Value, String> {
    let mut created = serde_json::Map::new();
    let mut not_created = serde_json::Map::new();
    if let Some(creates) = args.get("create").and_then(|v| v.as_object()) {
        for (cid, sub) in creates {
            let email_id = sub
                .get("emailId")
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            let return_path = sub
                .get("envelope")
                .and_then(|e| e.get("mailFrom"))
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            let rcpts: Vec<String> = sub
                .get("envelope")
                .and_then(|e| e.get("rcptTo"))
                .and_then(|v| v.as_array())
                .map(|a| a.iter().filter_map(|r| r.as_str().map(String::from)).collect())
                .unwrap_or_default();
            if email_id.is_empty() || return_path.is_empty() || rcpts.is_empty() {
                not_created.insert(
                    cid.clone(),
                    json!("envelope is required (emailId, mailFrom, rcptTo)"),
                );
                continue;
            }
            // Resolve the draft email's blob hash (RLS-scoped read).
            let mut conn = state.pool.acquire().await.map_err(|e| e.to_string())?;
            let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
                .bind(m.env_id())
                .execute(&mut *conn)
                .await;
            let email_pk: Uuid = match Uuid::parse_str(&email_id) {
                Ok(v) => v,
                Err(_) => {
                    not_created.insert(cid.clone(), json!("invalid emailId"));
                    continue;
                }
            };
            let blob: Option<String> = sqlx::query_scalar(
                "SELECT blob_hash FROM email8.emails WHERE account_id = $1 AND id = $2",
            )
            .bind(account_id)
            .bind(email_pk)
            .fetch_optional(&mut *conn)
            .await
            .map_err(|e| e.to_string())?;
            let Some(blob_hash) = blob else {
                not_created.insert(cid.clone(), json!("emailNotFound"));
                continue;
            };
            // Proxy to Mta with the service token (Mta re-verifies the
            // user scope + env binding from its own check).
            let token = std::env::var("EMAIL8_STORE_TOKEN").unwrap_or_default();
            let client = reqwest::Client::new();
            let url = format!("{}/v1/internal/submit", state.config.mta_url.trim_end_matches('/'));
            let resp = client
                .post(&url)
                .bearer_auth(token)
                .json(&json!({
                    "env_id": m.env_id(),
                    "account_id": account_id,
                    "user_sub": m.user_sub().unwrap_or_default(),
                    "return_path": return_path,
                    "recipients": rcpts,
                    "blob_hash": blob_hash,
                    "size": 0,
                    "source": "jmap",
                    "idempotency_key": cid,
                }))
                .send()
                .await
                .map_err(|e| e.to_string())?;
            if resp.status().is_success() {
                let body: serde_json::Value = resp.json().await.map_err(|e| e.to_string())?;
                created.insert(
                    cid.clone(),
                    json!({
                        "id": body.get("queue_id").cloned().unwrap_or(json!("pending")),
                        "emailId": email_id,
                    }),
                );
                // RFC 8621 §6.4 onSuccess chaining: the submission
                // succeeded — apply onSuccessUpdateEmail (a patch over
                // the draft, typically `keywords: {$draft: null, $seen:
                // true}` + a Sent mailbox move) or destroy it
                // (onSuccessDestroyEmail).
                if let Ok(draft_pk) = email_id.parse::<Uuid>() {
                    if let Some(on_patch) = sub.get("onSuccessUpdateEmail") {
                        if let Err(e) = chain_update_email(state, m, account_id, draft_pk, on_patch).await {
                            tracing::warn!(error = %e, "email8:store: onSuccessUpdateEmail failed (submission kept)");
                        }
                    } else if sub.get("onSuccessDestroyEmail").and_then(|v| v.as_bool()).unwrap_or(false) {
                        if let Err(e) = chain_destroy_email(state, m, account_id, draft_pk).await {
                            tracing::warn!(error = %e, "email8:store: onSuccessDestroyEmail failed (submission kept)");
                        }
                    }
                }
            } else {
                let err = resp.text().await.unwrap_or_else(|_| "submit failed".into());
                not_created.insert(cid.clone(), json!(err));
            }
        }
    }
    Ok(json!({
        "oldState": args.get("ifInState").and_then(|v| v.as_str()).unwrap_or("0"),
        "newState": "1",
        "created": Value::Object(created),
        "notCreated": Value::Object(not_created),
    }))
}

/// RFC 8621 §6.4 — apply `onSuccessUpdateEmail`: a standard Email/set
/// patch over the submitted draft (keywords nulling + mailbox moves).
async fn chain_update_email(
    state: &crate::data_api::AppState,
    m: &crate::auth::MailAuth,
    account_id: Uuid,
    email_id: Uuid,
    patch: &Value,
) -> Result<(), String> {
    let mut conn = state.pool.acquire().await.map_err(|e| e.to_string())?;
    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(m.env_id())
        .execute(&mut *conn)
        .await;
    email_apply_patch(&mut conn, account_id, email_id, patch)
        .await
        .map_err(|e| e.to_string())?;
    // The changelog 'updated' entry keeps SSE/push consumers in sync.
    let _ = sqlx::query(
        "INSERT INTO email8.changelog \
            (env_id, account_id, change_type, collection, record_id) \
         VALUES ($1, $2, 'updated', 1, $3)",
    )
    .bind(m.env_id())
    .bind(account_id)
    .bind(email_id)
    .execute(&mut *conn)
    .await;
    Ok(())
}

/// RFC 8621 §6.4 — destroy the draft after successful submission
/// (membership rows removed + tombstone; the IMAP EXPUNGE semantics).
async fn chain_destroy_email(
    state: &crate::data_api::AppState,
    m: &crate::auth::MailAuth,
    account_id: Uuid,
    email_id: Uuid,
) -> Result<(), String> {
    let mut tx = state.pool.begin().await.map_err(|e| e.to_string())?;
    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(m.env_id())
        .execute(&mut *tx)
        .await;
    sqlx::query(
        "DELETE FROM email8.email_mailboxes WHERE account_id = $1 AND email_id = $2",
    )
    .bind(account_id)
    .bind(email_id)
    .execute(&mut *tx)
    .await
    .map_err(|e| e.to_string())?;
    sqlx::query(
        "UPDATE email8.emails SET deleted_at = now() WHERE account_id = $1 AND id = $2",
    )
    .bind(account_id)
    .bind(email_id)
    .execute(&mut *tx)
    .await
    .map_err(|e| e.to_string())?;
    sqlx::query(
        "INSERT INTO email8.changelog \
            (env_id, account_id, change_type, collection, record_id) \
         VALUES ($1, $2, 'destroyed', 1, $3)",
    )
    .bind(m.env_id())
    .bind(account_id)
    .bind(email_id)
    .execute(&mut *tx)
    .await
    .map_err(|e| e.to_string())?;
    tx.commit().await.map_err(|e| e.to_string())?;
    Ok(())
}

/// `PushSubscription/set` — create/update/destroy push subscriptions
/// (RFC 8620 §7.2 + RFC 8887 §5). New subscriptions get a verification
/// code; the store marks them unverified until the client posts the
/// code back through the push endpoint.
pub async fn push_subscription_set(
    conn: &mut sqlx::PgConnection,
    env_id: uuid::Uuid,
    account_id: Uuid,
    args: &Value,
) -> Result<Value, StoreOpError> {
    let mut created = serde_json::Map::new();
    let mut not_found: Vec<String> = Vec::new();

    if let Some(create_map) = args.get("create").and_then(|v| v.as_object()) {
        for (cid, obj) in create_map {
            let Some(endpoint) = obj.get("endpoint").and_then(|v| v.as_str()) else {
                created.insert(cid.clone(), serde_json::json!({ "error": "invalidProperties" }));
                continue;
            };
            let types = obj
                .get("types")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|t| t.as_str())
                        .map(crate::data_api::push_type_code)
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            let expires = obj
                .get("expires")
                .and_then(|v| v.as_str())
                .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                .map(|d| d.with_timezone(&chrono::Utc));
            let verification_code = crate::data_api::random_token();
            let id = Uuid::new_v4();
            sqlx::query(
                "INSERT INTO email8.push_subscriptions \
                    (id, env_id, account_id, types, endpoint, keys, verification_code, verified, expires_at) \
                 VALUES ($1, $2, $3, $4, $5, '{}', $6, FALSE, $7)",
            )
            .bind(id)
            .bind(env_id)
            .bind(account_id)
            .bind(&types)
            .bind(endpoint)
            .bind(&verification_code)
            .bind(expires)
            .execute(&mut *conn)
            .await?;
            created.insert(
                cid.clone(),
                serde_json::json!({
                    "id": id.to_string(),
                    "endpoint": endpoint,
                    "verificationCode": verification_code,
                    "verified": false,
                }),
            );
        }
    }

    if let Some(update_map) = args.get("update").and_then(|v| v.as_object()) {
        for (id, patch) in update_map {
            let Ok(pk) = id.parse::<Uuid>() else {
                not_found.push(id.clone());
                continue;
            };
            let n = sqlx::query(
                "UPDATE email8.push_subscriptions \
                 SET types = COALESCE($3, types), \
                     expires_at = COALESCE($4, expires_at) \
                 WHERE account_id = $1 AND id = $2",
            )
            .bind(account_id)
            .bind(pk)
            .bind(patch.get("types").and_then(|v| v.as_array()).map(|arr| {
                arr.iter()
                    .filter_map(|t| t.as_str())
                    .map(crate::data_api::push_type_code)
                    .collect::<Vec<i16>>()
            }))
            .bind(
                patch
                    .get("expires")
                    .and_then(|v| v.as_str())
                    .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                    .map(|d| d.with_timezone(&chrono::Utc)),
            )
            .execute(&mut *conn)
            .await?;
            if n.rows_affected() == 0 {
                not_found.push(id.clone());
            }
        }
    }

    if let Some(ids) = args.get("destroy") {
        let Some(id_list) = ids.as_array() else {
            return Err(StoreOpError::Db(sqlx::Error::Protocol(
                "destroy must be an array".into(),
            )));
        };
        for id in id_list {
            let Some(pk) = id.as_str().and_then(|s| Uuid::parse_str(s).ok()) else {
                not_found.push(id.to_string());
                continue;
            };
            let n = sqlx::query(
                "DELETE FROM email8.push_subscriptions WHERE account_id = $1 AND id = $2",
            )
            .bind(account_id)
            .bind(pk)
            .execute(&mut *conn)
            .await?;
            if n.rows_affected() == 0 {
                not_found.push(id.to_string());
            }
        }
    }

    Ok(serde_json::json!({ "created": created, "updated": {}, "notFound": not_found }))
}
