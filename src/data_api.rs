// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Email8:Store
// SPDX-License-Identifier: Apache-2.0

//! Internal data API — the typed service-to-service surface Mta, Access
//! and Apps call (M2M-authenticated). Also carries the user context of
//! the *originating* caller via headers when proxied (master design §4.8).

use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use uuid::Uuid;

use email8::contracts::{
    BlobQuotaVerdict, ChangesSinceRequest, ChangesSinceResponse, CreateMailboxRequest,
    IngestMessage, IngestedEmail, MailboxDto, ResolveAddressRequest, ResolvedAddress,
    SubmitRequest, SubmitResponse,
};
use sqlx::Row;

use crate::{auth, config::StoreConfig, store_ops};

/// Service state: the service config + the shell `ServiceCore`
/// (pool + Sentin8:Policy engine + shared admin surface — Phase 28 §3.6).
/// The engine inside `core.admin` is the SAME instance the step-5 gate
/// evaluates, so admin writes and request-time decisions agree.
/// (`ServiceCore` is not `Clone`; `Arc` gives the cheap axum-state clone.)
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<StoreConfig>,
    pub pool: sqlx::PgPool,
    pub core: std::sync::Arc<sentin8::shell::ServiceCore>,
    /// The boot-loaded workload registry map — the authorization
    /// record for cert-presenting internal callers (auth DESIGN
    /// §4.3f; group DESIGN.md §3.1).
    pub workload_registry: sentin8::auth::workload_registry::WorkloadMap,
}

/// `POST /v1/internal/resolve` — RCPT resolution (sub-addressing, aliases,
/// catch-all, group expansion).
#[utoipa::path(
    post,
    path = "/v1/internal/resolve",
    request_body = serde_json::Value,
    responses(
        (status = 200, description = "Resolved address", body = serde_json::Value),
    ),
    security(),
    tag = "store",
)]
pub async fn resolve_address(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<ResolveAddressRequest>,
) -> Result<Json<ResolvedAddress>, (StatusCode, String)> {
    let _a = auth::require_mail_auth(
        &state.config,
        &state.workload_registry,
        &state.core.admin.policy,
        &headers,
        "email8:mail:read",
    )
    .await?;
    let mut tx = state.pool.begin().await.map_err(err_db)?;
    auth::set_mail_tenant_context(&mut tx, &_a, req.env_id, Uuid::nil()).await;
    let lower = req.address.to_ascii_lowercase();

    // Group expansion first.
    let members = store_ops::group_members(&mut tx, req.env_id, &lower)
        .await
        .map_err(err_op)?;
    if !members.is_empty() {
        tx.commit().await.map_err(err_db)?;
        return Ok(Json(ResolvedAddress::Group {
            group_id: Uuid::nil(),
            members,
        }));
    }
    match store_ops::resolve_address(&mut tx, req.env_id, &req.address)
        .await
        .map_err(err_op)?
    {
        Some(account_id) => {
            tx.commit().await.map_err(err_db)?;
            Ok(Json(ResolvedAddress::Account {
                account_id,
                name: req.address.clone(),
                address: req.address,
            }))
        }
        None => {
            tx.commit().await.map_err(err_db)?;
            Ok(Json(ResolvedAddress::External {
                address: req.address,
            }))
        }
    }
}

/// `POST /v1/internal/ingest` — local delivery filing.
#[utoipa::path(
    post,
    path = "/v1/internal/ingest",
    request_body = serde_json::Value,
    responses(
        (status = 200, description = "Ingested", body = serde_json::Value),
    ),
    security(),
    tag = "store",
)]
pub async fn ingest(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<IngestMessage>,
) -> Result<Json<IngestedEmail>, (StatusCode, String)> {
    let _a = auth::require_mail_auth(
        &state.config,
        &state.workload_registry,
        &state.core.admin.policy,
        &headers,
        "email8:mail:write",
    )
    .await?;
    // Fetch the raw bytes from Storage before opening the transaction.
    let raw = fetch_blob(&state, &req.blob_hash).await?;
    let mut tx = state.pool.begin().await.map_err(err_db)?;
    auth::set_mail_tenant_context(&mut tx, &_a, req.env_id, req.account_id).await;

    let outcome = store_ops::ingest_email(
        &mut tx,
        req.env_id,
        req.account_id,
        &raw,
        &req.blob_hash,
        &req.source,
        req.spam_percentage,
        &req.mailboxes,
    )
    .await
    .map_err(map_op)?;

    // Outbox event: email8:mail:email:ingested (inbox-first, same tx window).
    // `user_id` (the principal's Sentin8:Auth sub) rides the payload so
    // the BFF /subscribe per-user filter (platform story 0.5) can fan the
    // event to the owning session only.
    let user_id: Option<Uuid> =
        sqlx::query_scalar("SELECT sentin8_auth_user_id FROM email8.principals WHERE id = $1")
            .bind(req.account_id)
            .fetch_optional(&state.pool)
            .await
            .ok()
            .flatten();
    emit_event(
        &state.pool,
        req.env_id,
        "email8:mail:email:ingested",
        serde_json::json!({
            "env_id": req.env_id,
            "account_id": req.account_id,
            "user_id": user_id,
            "email_id": outcome.email_id,
            "thread_id": outcome.thread_id,
            "mailboxes": outcome.mailboxes.iter().map(|(m, _)| m).collect::<Vec<_>>(),
            "imap_uids": outcome.mailboxes.iter().map(|(_, u)| u).collect::<Vec<_>>(),
            "change_id": outcome.email_change_id,
            "size": outcome.size,
            "is_spam": outcome.is_spam,
        }),
    )
    .await;
    // Story 4.6 — an iMIP (RFC 6047 text/calendar) ingest is also a
    // groupware domain event: the calendar row was filed, so fan out the
    // event-driven notification for apps (webmail, mobile) and triggers.
    if outcome.is_imip {
        let operation = match outcome.imip_method.as_deref() {
            Some(m) if m.eq_ignore_ascii_case("cancel") => "cancelled",
            Some(m) if m.eq_ignore_ascii_case("reply") => "updated",
            _ => "created",
        };
        emit_event(
            &state.pool,
            req.env_id,
            &format!("email8:groupware:event:{operation}"),
            serde_json::json!({
                "env_id": req.env_id,
                "account_id": req.account_id,
                "user_id": user_id,
                "email_id": outcome.email_id,
                "uid": outcome.imip_uid,
                "method": outcome.imip_method,
            }),
        )
        .await;
    }
    // Deferred merge when the thread key hit multiple threads.
    if outcome.thread_merge_candidates.len() > 1 {
        emit_event(
            &state.pool,
            req.env_id,
            "email8:mail:thread:merge",
            serde_json::json!({
                "env_id": req.env_id,
                "account_id": req.account_id,
                "surviving_thread_id": outcome.thread_id,
                "merged_thread_ids": outcome.thread_merge_candidates,
                "email_id": outcome.email_id,
            }),
        )
        .await;
    }

    tx.commit().await.map_err(err_db)?;
    Ok(Json(IngestedEmail {
        email_id: outcome.email_id,
        account_id: req.account_id,
        thread_id: outcome.thread_id,
        mailboxes: outcome
            .mailboxes
            .iter()
            .map(|(m, u)| email8::contracts::MailboxUid {
                mailbox_id: *m,
                imap_uid: *u,
            })
            .collect(),
        change_id: outcome.email_change_id,
        size: outcome.size,
    }))
}

/// `GET /v1/internal/mailboxes?env_id=&account_id=` — list an account's
/// mailboxes (Access services bootstrap their session cache from this).
#[derive(Debug, serde::Deserialize)]
pub struct ListMailboxesQuery {
    pub env_id: Uuid,
    pub account_id: Uuid,
}

#[utoipa::path(
    get,
    path = "/v1/internal/mailboxes",
    responses(
        (status = 200, description = "Mailboxes", body = serde_json::Value),
    ),
    security(),
    tag = "store",
)]
pub async fn list_mailboxes(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<ListMailboxesQuery>,
) -> Result<Json<Vec<MailboxDto>>, (StatusCode, String)> {
    let _a = auth::require_mail_auth(
        &state.config,
        &state.workload_registry,
        &state.core.admin.policy,
        &headers,
        "email8:mail:read",
    )
    .await?;
    let mut tx = state.pool.begin().await.map_err(err_db)?;
    auth::set_mail_tenant_context(&mut tx, &_a, q.env_id, q.account_id).await;
    let rows = sqlx::query(
        "SELECT id, account_id, name, role, parent_id, sort_order, uid_validity, uid_next, is_subscribed \
         FROM email8.mailboxes WHERE env_id = $1 AND account_id = $2 ORDER BY sort_order, id",
    )
    .bind(q.env_id)
    .bind(q.account_id)
    .fetch_all(&mut *tx)
    .await
    .map_err(err_db)?;
    tx.commit().await.map_err(err_db)?;
    Ok(Json(
        rows.iter()
            .map(|r| MailboxDto {
                id: r.get("id"),
                account_id: r.get("account_id"),
                name: r.get("name"),
                role: r.get("role"),
                parent_id: r.get("parent_id"),
                sort_order: r.get("sort_order"),
                uid_validity: r.get("uid_validity"),
                uid_next: r.get("uid_next"),
                is_subscribed: r.get("is_subscribed"),
            })
            .collect(),
    ))
}

/// `POST /v1/internal/mailboxes` — create a mailbox.
#[utoipa::path(
    post,
    path = "/v1/internal/mailboxes",
    request_body = serde_json::Value,
    responses(
        (status = 200, description = "Mailbox created", body = serde_json::Value),
    ),
    security(),
    tag = "store",
)]
pub async fn create_mailbox(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CreateMailboxRequest>,
) -> Result<Json<MailboxDto>, (StatusCode, String)> {
    let _a = auth::require_mail_auth(
        &state.config,
        &state.workload_registry,
        &state.core.admin.policy,
        &headers,
        "email8:mail:write",
    )
    .await?;
    let mut tx = state.pool.begin().await.map_err(err_db)?;
    auth::set_mail_tenant_context(&mut tx, &_a, req.env_id, req.account_id).await;
    // Entity ids are DB-generated UUIDs; the sequences table only backs
    // change-id counters now.
    let id = uuid::Uuid::new_v4();
    let row = sqlx::query(
        r#"INSERT INTO email8.mailboxes
               (id, env_id, account_id, name, role, parent_id, sort_order, uid_validity)
           VALUES ($1, $2, $3, $4, $5, $6, 100, $7)
           RETURNING id, account_id, name, role, parent_id, sort_order, uid_validity, uid_next, is_subscribed"#,
    )
    .bind(id)
    .bind(req.env_id)
    .bind(req.account_id)
    .bind(&req.name)
    .bind(&req.role)
    .bind(req.parent_id)
    .bind(chrono::Utc::now().timestamp_millis())
    .fetch_one(&mut *tx)
    .await
    .map_err(err_db)?;
    tx.commit().await.map_err(err_db)?;
    Ok(Json(MailboxDto {
        id: row.get("id"),
        account_id: row.get("account_id"),
        name: row.get("name"),
        role: row.get("role"),
        parent_id: row.get("parent_id"),
        sort_order: row.get("sort_order"),
        uid_validity: row.get("uid_validity"),
        uid_next: row.get("uid_next"),
        is_subscribed: row.get("is_subscribed"),
    }))
}

/// `POST /v1/internal/changes` — changelog window (JMAP/IMAP sync).
#[utoipa::path(
    post,
    path = "/v1/internal/changes",
    request_body = serde_json::Value,
    responses(
        (status = 200, description = "State changes", body = serde_json::Value),
    ),
    security(),
    tag = "store",
)]
pub async fn changes_since(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<ChangesSinceRequest>,
) -> Result<Json<ChangesSinceResponse>, (StatusCode, String)> {
    let _a = auth::require_mail_auth(
        &state.config,
        &state.workload_registry,
        &state.core.admin.policy,
        &headers,
        "email8:mail:read",
    )
    .await?;
    let collection = email8::contracts::Collection::from_u16(req.collection)
        .ok_or((StatusCode::BAD_REQUEST, "unknown collection".into()))?;
    let mut tx = state.pool.begin().await.map_err(err_db)?;
    auth::set_mail_tenant_context(&mut tx, &_a, req.env_id, req.account_id).await;
    let window = store_ops::changes_since(
        &mut tx,
        req.account_id,
        collection,
        req.since_change_id,
        req.max_changes.unwrap_or(64),
    )
    .await
    .map_err(map_op)?;
    tx.commit().await.map_err(err_db)?;
    Ok(Json(ChangesSinceResponse {
        old_state: window.old_state,
        new_state: window.new_state,
        has_more_changes: window.has_more_changes,
        created: window.created,
        updated: window.updated,
        destroyed: window.destroyed,
    }))
}

/// `POST /v1/internal/submit` — enqueue a submission into the Mta queue.
/// Store proxies to Mta (it owns the queue); the response is Mta's.
#[utoipa::path(
    post,
    path = "/v1/internal/submit",
    request_body = serde_json::Value,
    responses(
        (status = 200, description = "Submitted", body = serde_json::Value),
    ),
    security(),
    tag = "store",
)]
pub async fn submit(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<SubmitRequest>,
) -> Result<Json<SubmitResponse>, (StatusCode, String)> {
    let _a = auth::require_mail_auth(
        &state.config,
        &state.workload_registry,
        &state.core.admin.policy,
        &headers,
        "email8:submission:send",
    )
    .await?;
    // Verify the user's identity binding: return_path must be one of the
    // caller's addresses (master design §4.4 — enforced again at Mta).
    let mut tx = state.pool.begin().await.map_err(err_db)?;
    auth::set_mail_tenant_context(&mut tx, &_a, req.env_id, req.account_id).await;
    let known: Option<i64> = sqlx::query_scalar(
        "SELECT 1 FROM email8.principal_addresses WHERE env_id = $1 AND account_id = $2 AND lower(address) = lower($3)",
    )
    .bind(req.env_id)
    .bind(req.account_id)
    .bind(&req.return_path)
    .fetch_optional(&mut *tx)
    .await
    .map_err(err_db)?;
    if known.is_none() && !req.return_path.is_empty() {
        return Err((
            StatusCode::FORBIDDEN,
            "return_path is not one of the caller's addresses".into(),
        ));
    }

    // Proxy to Mta with the caller's token attached (delegated user send).
    let client = reqwest::Client::new();
    let token = auth_header(&headers);
    let url = format!(
        "{}/v1/internal/submit",
        state.config.mta_url.trim_end_matches('/')
    );
    let resp = client
        .post(&url)
        .header("Authorization", token)
        .json(&req)
        .send()
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))?;
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err((status, body));
    }
    let verdict: SubmitResponse = resp
        .json()
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))?;
    tx.commit().await.map_err(err_db)?;
    Ok(Json(verdict))
}

/// `POST /v1/internal/blob-quota` — upload quota gate.
#[utoipa::path(
    post,
    path = "/v1/internal/blob-quota",
    request_body = serde_json::Value,
    responses(
        (status = 200, description = "Quota verdict", body = serde_json::Value),
    ),
    security(),
    tag = "store",
)]
pub async fn blob_quota(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<email8::contracts::BlobQuotaCheck>,
) -> Result<Json<BlobQuotaVerdict>, (StatusCode, String)> {
    let _a = auth::require_mail_auth(
        &state.config,
        &state.workload_registry,
        &state.core.admin.policy,
        &headers,
        "email8:mail:read",
    )
    .await?;
    let mut tx = state.pool.begin().await.map_err(err_db)?;
    auth::set_mail_tenant_context(&mut tx, &_a, req.env_id, req.account_id).await;
    let used: i64 = sqlx::query_scalar(
        "SELECT COALESCE(used_bytes, 0) FROM email8.quota_counters WHERE env_id = $1 AND account_id = $2",
    )
    .bind(req.env_id)
    .bind(req.account_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(err_db)?
    .unwrap_or(0);
    let policy: i64 = sqlx::query_scalar(
        "SELECT default_account_quota_bytes FROM email8.quota_policy WHERE env_id = $1",
    )
    .bind(req.env_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(err_db)?
    .unwrap_or(10 * 1024 * 1024 * 1024);
    tx.commit().await.map_err(err_db)?;
    Ok(Json(BlobQuotaVerdict {
        allowed: policy == 0 || used + req.size <= policy,
        used_bytes: used,
        quota_bytes: if policy == 0 { None } else { Some(policy) },
    }))
}

/// `GET /v1/internal/email/{email_id}` — fetch one email's metadata (Access
/// FETCH path) with mailbox membership.
#[derive(Debug, serde::Deserialize)]
pub struct EmailPath {
    pub env_id: Uuid,
    pub account_id: Uuid,
    pub email_id: Uuid,
}

#[utoipa::path(
    get,
    path = "/v1/internal/email/{env_id}/{account_id}/{email_id}",
    params(
        ("env_id" = String, Path, description = "Env id"),
        ("account_id" = String, Path, description = "Account id"),
        ("email_id" = String, Path, description = "Email id"),
    ),
    responses(
        (status = 200, description = "The email", body = serde_json::Value),
        (status = 404, description = "Unknown email"),
    ),
    security(),
    tag = "store",
)]
pub async fn get_email(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((env_id, account_id, email_id)): Path<(Uuid, Uuid, Uuid)>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let _a = auth::require_mail_auth(
        &state.config,
        &state.workload_registry,
        &state.core.admin.policy,
        &headers,
        "email8:mail:read",
    )
    .await?;
    let mut tx = state.pool.begin().await.map_err(err_db)?;
    auth::set_mail_tenant_context(&mut tx, &_a, env_id, account_id).await;
    let row = sqlx::query(
        "SELECT id, blob_hash, thread_id, size, received_at, sent_at, message_id, subject, \
                preview, keywords, has_attachment, metadata \
         FROM email8.emails WHERE env_id = $1 AND account_id = $2 AND id = $3",
    )
    .bind(env_id)
    .bind(account_id)
    .bind(email_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(err_db)?
    .ok_or((StatusCode::NOT_FOUND, "email not found".into()))?;
    let memberships: Vec<(Uuid, i64)> = sqlx::query_as(
        "SELECT mailbox_id, imap_uid FROM email8.email_mailboxes WHERE account_id = $1 AND email_id = $2",
    )
    .bind(account_id)
    .bind(email_id)
    .fetch_all(&mut *tx)
    .await
    .map_err(err_db)?;
    let mailboxes: serde_json::Value = memberships
        .iter()
        .map(|(m, u)| serde_json::json!({"mailbox_id": m, "imap_uid": u}))
        .collect::<Vec<_>>()
        .into();
    tx.commit().await.map_err(err_db)?;
    Ok(Json(serde_json::json!({
        "id": row.get::<Uuid, _>("id"),
        "blob_hash": row.get::<String, _>("blob_hash"),
        "thread_id": row.get::<Uuid, _>("thread_id"),
        "size": row.get::<i64, _>("size"),
        "received_at": row.get::<chrono::DateTime<chrono::Utc>, _>("received_at"),
        "sent_at": row.get::<Option<chrono::DateTime<chrono::Utc>>, _>("sent_at"),
        "message_id": row.get::<Option<String>, _>("message_id"),
        "subject": row.get::<Option<String>, _>("subject"),
        "preview": row.get::<Option<String>, _>("preview"),
        "keywords": row.get::<Vec<String>, _>("keywords"),
        "has_attachment": row.get::<bool, _>("has_attachment"),
        "metadata": row.get::<serde_json::Value, _>("metadata"),
        "mailboxes": mailboxes,
    })))
}

// ── helpers ────────────────────────────────────────────────────────────────

/// `GET /v1/internal/mailbox/emails?env_id=&account_id=&mailbox_id=` —
/// a mailbox's messages (id, uid, size, flags) for POP3/IMAP projections.
#[derive(Debug, serde::Deserialize)]
pub struct MailboxEmailsQuery {
    pub env_id: Uuid,
    pub account_id: Uuid,
    pub mailbox_id: Uuid,
}

#[utoipa::path(
    get,
    path = "/v1/internal/mailbox/emails",
    responses(
        (status = 200, description = "Emails in the mailbox", body = serde_json::Value),
    ),
    security(),
    tag = "store",
)]
pub async fn list_mailbox_emails(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<MailboxEmailsQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let _a = auth::require_mail_auth(
        &state.config,
        &state.workload_registry,
        &state.core.admin.policy,
        &headers,
        "email8:mail:read",
    )
    .await?;
    let mut tx = state.pool.begin().await.map_err(err_db)?;
    auth::set_mail_tenant_context(&mut tx, &_a, q.env_id, q.account_id).await;
    let rows = sqlx::query(
        "SELECT e.id, m.imap_uid, e.size, e.keywords, e.subject, e.received_at \
         FROM email8.email_mailboxes m \
         JOIN email8.emails e ON e.id = m.email_id AND e.account_id = m.account_id \
         WHERE m.account_id = $1 AND m.mailbox_id = $2 \
         ORDER BY m.imap_uid",
    )
    .bind(q.account_id)
    .bind(q.mailbox_id)
    .fetch_all(&mut *tx)
    .await
    .map_err(err_db)?;
    let items: Vec<serde_json::Value> = rows
        .iter()
        .map(|r| {
            serde_json::json!({
                "id": r.get::<Uuid, _>("id"),
                "uid": r.get::<i64, _>("imap_uid"),
                "size": r.get::<i64, _>("size"),
                "keywords": r.get::<Vec<String>, _>("keywords"),
                "subject": r.get::<Option<String>, _>("subject"),
                "received_at": r.get::<chrono::DateTime<chrono::Utc>, _>("received_at"),
            })
        })
        .collect();
    tx.commit().await.map_err(err_db)?;
    Ok(Json(serde_json::json!({ "items": items })))
}

/// `POST /v1/internal/emails/destroy` — batch expunge (POP3 QUIT, IMAP
/// EXPUNGE). Only removes the membership row (message moves to no
/// mailbox → eligible for GC; the POP3/IMAP destroy is a membership
/// delete + `destroyed` changelog entries).
#[derive(Debug, serde::Deserialize)]
pub struct DestroyEmailsRequest {
    pub env_id: Uuid,
    pub account_id: Uuid,
    pub mailbox_id: Uuid,
    pub email_ids: Vec<Uuid>,
}

#[utoipa::path(
    post,
    path = "/v1/internal/emails/destroy",
    request_body = serde_json::Value,
    responses(
        (status = 200, description = "Destroyed", body = serde_json::Value),
    ),
    security(),
    tag = "store",
)]
pub async fn destroy_emails(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<DestroyEmailsRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let _a = auth::require_mail_auth(
        &state.config,
        &state.workload_registry,
        &state.core.admin.policy,
        &headers,
        "email8:mail:write",
    )
    .await?;
    let mut tx = state.pool.begin().await.map_err(err_db)?;
    auth::set_mail_tenant_context(&mut tx, &_a, req.env_id, req.account_id).await;
    for id in &req.email_ids {
        sqlx::query(
            "DELETE FROM email8.email_mailboxes \
             WHERE account_id = $1 AND mailbox_id = $2 AND email_id = $3",
        )
        .bind(req.account_id)
        .bind(req.mailbox_id)
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(err_db)?;
        // Changelog `destroyed` entry per collection row.
        sqlx::query(
            "INSERT INTO email8.changelog \
                (env_id, account_id, change_type, collection, record_id, mailbox_id) \
             VALUES ($1, $2, 'destroyed', 1, $3, $4)",
        )
        .bind(req.env_id)
        .bind(req.account_id)
        .bind(id)
        .bind(req.mailbox_id)
        .execute(&mut *tx)
        .await
        .map_err(err_db)?;
    }
    tx.commit().await.map_err(err_db)?;
    Ok(Json(
        serde_json::json!({ "destroyed": req.email_ids.len() }),
    ))
}

/// `POST /v1/internal/email/store` — store the raw blob for an APPEND
/// (IMAP/POP3 upload path): bytes → Storage, blob-hash returned.
#[utoipa::path(
    post,
    path = "/v1/internal/email/store",
    request_body = serde_json::Value,
    responses(
        (status = 200, description = "Blob stored", body = serde_json::Value),
    ),
    security(),
    tag = "store",
)]
pub async fn store_raw_blob(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let _a = auth::require_mail_auth(
        &state.config,
        &state.workload_registry,
        &state.core.admin.policy,
        &headers,
        "email8:mail:write",
    )
    .await?;
    let hash = blake3_hash(&body);
    let storage = crate::storage_auth::storage_client(
        &state.pool,
        &state.config.sentin8_storage_url,
        &["storage:env:read"],
    )
    .await
    .map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))?;
    storage
        .put_if_absent(
            "",
            "",
            &format!("email8/blobs/{hash}"),
            "application/octet-stream",
            body.to_vec(),
        )
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))?;
    Ok(Json(serde_json::json!({
        "blob_hash": hash,
        "size": body.len(),
    })))
}

fn blake3_hash(data: &[u8]) -> String {
    blake3::hash(data).to_hex().to_string()
}

/// `POST /v1/internal/email/keywords` — flag set/clear (IMAP STORE).
#[derive(Debug, serde::Deserialize)]
pub struct KeywordsRequest {
    pub env_id: Uuid,
    pub account_id: Uuid,
    pub email_id: Uuid,
    /// true = set/replace, false = remove.
    pub set: bool,
    pub keywords: Vec<String>,
}

#[utoipa::path(
    post,
    path = "/v1/internal/email/keywords",
    request_body = serde_json::Value,
    responses(
        (status = 200, description = "Keywords set"),
    ),
    security(),
    tag = "store",
)]
pub async fn set_email_keywords(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<KeywordsRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let _a = auth::require_mail_auth(
        &state.config,
        &state.workload_registry,
        &state.core.admin.policy,
        &headers,
        "email8:mail:write",
    )
    .await?;
    let mut tx = state.pool.begin().await.map_err(err_db)?;
    auth::set_mail_tenant_context(&mut tx, &_a, req.env_id, req.account_id).await;
    // Normalize: lowercase, strip backslashes.
    let norm: Vec<String> = req
        .keywords
        .iter()
        .map(|k| k.trim_start_matches('\\').to_ascii_lowercase())
        .collect();
    if req.set {
        sqlx::query(
            "UPDATE email8.emails SET keywords = $3 \
             WHERE env_id = $1 AND account_id = $2 AND id = $4",
        )
        .bind(req.env_id)
        .bind(req.account_id)
        .bind(&norm)
        .bind(req.email_id)
        .execute(&mut *tx)
        .await
        .map_err(err_db)?;
    } else {
        sqlx::query(
            "UPDATE email8.emails \
                SET keywords = ARRAY(SELECT unnest(keywords) EXCEPT SELECT unnest($3::text[])) \
             WHERE env_id = $1 AND account_id = $2 AND id = $4",
        )
        .bind(req.env_id)
        .bind(req.account_id)
        .bind(&norm)
        .bind(req.email_id)
        .execute(&mut *tx)
        .await
        .map_err(err_db)?;
    }
    // Changelog updated entry.
    sqlx::query(
        "INSERT INTO email8.changelog \
            (env_id, account_id, change_type, collection, record_id) \
         VALUES ($1, $2, 'updated', 1, $3)",
    )
    .bind(req.env_id)
    .bind(req.account_id)
    .bind(req.email_id)
    .execute(&mut *tx)
    .await
    .map_err(err_db)?;
    // Junk-move training signal (story 5.4): setting/unsetting the
    // $junk keyword enqueues an FTRL sample (the Mta worker drains it).
    if norm.iter().any(|k| k == "$junk") {
        sqlx::query(
            "INSERT INTO email8.spam_training (env_id, account_id, email_id, label) \
             VALUES ($1, $2, $3, $4)",
        )
        .bind(req.env_id)
        .bind(req.account_id)
        .bind(req.email_id)
        .bind(req.set) // set $junk → spam sample; unset → ham sample
        .execute(&mut *tx)
        .await
        .map_err(err_db)?;
    }
    tx.commit().await.map_err(err_db)?;
    Ok(Json(serde_json::json!({ "updated": true })))
}

/// `POST /v1/internal/emails/copy` — membership add (IMAP COPY/MOVE).
#[derive(Debug, serde::Deserialize)]
pub struct CopyEmailsRequest {
    pub env_id: Uuid,
    pub account_id: Uuid,
    pub dest_mailbox_id: Uuid,
    pub email_ids: Vec<Uuid>,
}

#[utoipa::path(
    post,
    path = "/v1/internal/emails/copy",
    request_body = serde_json::Value,
    responses(
        (status = 200, description = "Copied", body = serde_json::Value),
    ),
    security(),
    tag = "store",
)]
pub async fn copy_emails(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CopyEmailsRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let _a = auth::require_mail_auth(
        &state.config,
        &state.workload_registry,
        &state.core.admin.policy,
        &headers,
        "email8:mail:write",
    )
    .await?;
    let mut tx = state.pool.begin().await.map_err(err_db)?;
    auth::set_mail_tenant_context(&mut tx, &_a, req.env_id, req.account_id).await;
    for id in &req.email_ids {
        // Allocate the destination uid.
        let uid: i64 = sqlx::query_scalar(
            "UPDATE email8.mailboxes SET uid_next = uid_next + 1 \
             WHERE account_id = $1 AND id = $2 RETURNING uid_next - 1",
        )
        .bind(req.account_id)
        .bind(req.dest_mailbox_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(err_db)?;
        sqlx::query(
            "INSERT INTO email8.email_mailboxes (account_id, env_id, email_id, mailbox_id, imap_uid) \
             VALUES ($1, $5, $2, $3, $4) ON CONFLICT DO NOTHING",
        )
        .bind(req.account_id)
        .bind(id)
        .bind(req.dest_mailbox_id)
        .bind(uid)
        .bind(req.env_id)
        .execute(&mut *tx)
        .await
        .map_err(err_db)?;
    }
    tx.commit().await.map_err(err_db)?;
    Ok(Json(serde_json::json!({ "copied": req.email_ids.len() })))
}

/// `POST /v1/internal/ingest/append` — IMAP APPEND / POP3-compatible
/// upload: raw bytes → blob → email row + membership in one call.
#[derive(Debug, serde::Deserialize)]
pub struct AppendRequest {
    pub env_id: Uuid,
    pub account_id: Uuid,
    pub mailbox_id: Uuid,
    pub raw_b64: String,
}

#[utoipa::path(
    post,
    path = "/v1/internal/ingest/append",
    request_body = serde_json::Value,
    responses(
        (status = 200, description = "Appended", body = serde_json::Value),
    ),
    security(),
    tag = "store",
)]
pub async fn ingest_append(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<AppendRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let _a = auth::require_mail_auth(
        &state.config,
        &state.workload_registry,
        &state.core.admin.policy,
        &headers,
        "email8:mail:write",
    )
    .await?;
    use base64::Engine;
    let raw = base64::engine::general_purpose::STANDARD
        .decode(&req.raw_b64)
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    let hash = blake3_hash(&raw);
    // Blob → Storage.
    let storage = crate::storage_auth::storage_client(
        &state.pool,
        &state.config.sentin8_storage_url,
        &["storage:env:write"],
    )
    .await
    .map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))?;
    storage
        .put_if_absent(
            "",
            "",
            &format!("email8/blobs/{hash}"),
            "application/octet-stream",
            raw.clone(),
        )
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))?;
    // Ingest into the target mailbox.
    let mut tx = state.pool.begin().await.map_err(err_db)?;
    auth::set_mail_tenant_context(&mut tx, &_a, req.env_id, req.account_id).await;
    let outcome = store_ops::ingest_email(
        &mut tx,
        req.env_id,
        req.account_id,
        &raw,
        &hash,
        "imap",
        None,
        &[req.mailbox_id],
    )
    .await
    .map_err(err_op)?;
    tx.commit().await.map_err(err_db)?;
    Ok(Json(serde_json::json!({
        "email_id": outcome.email_id,
        "imap_uid": outcome.mailboxes.first().map(|(_, uid)| *uid),
    })))
}

// ── Sieve scripts (RFC 5804 backing store) ───────────────────────────────

#[derive(Debug, serde::Deserialize)]
pub struct SieveBase {
    pub env_id: Uuid,
    pub account_id: Uuid,
    #[serde(default)]
    pub name: Option<String>,
}

/// `POST /v1/internal/sieve/list` — the account's scripts + active flag.
#[utoipa::path(
    post,
    path = "/v1/internal/sieve/list",
    request_body = serde_json::Value,
    responses(
        (status = 200, description = "Scripts", body = serde_json::Value),
    ),
    security(),
    tag = "store",
)]
pub async fn sieve_list(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<SieveBase>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let _a = auth::require_mail_auth(
        &state.config,
        &state.workload_registry,
        &state.core.admin.policy,
        &headers,
        "email8:sieve:manage",
    )
    .await?;
    let mut tx = state.pool.begin().await.map_err(err_db)?;
    auth::set_mail_tenant_context(&mut tx, &_a, req.env_id, req.account_id).await;
    let rows = sqlx::query(
        "SELECT s.id, s.name, s.is_active, s.size, s.updated_at \
         FROM email8.sieve_scripts s \
         WHERE s.account_id = $1 ORDER BY s.name",
    )
    .bind(req.account_id)
    .fetch_all(&mut *tx)
    .await
    .map_err(err_db)?;
    let items: Vec<serde_json::Value> = rows
        .iter()
        .map(|r| {
            serde_json::json!({
                "id": r.get::<Uuid, _>("id"),
                "name": r.get::<String, _>("name"),
                "is_active": r.get::<bool, _>("is_active"),
                "size": r.get::<i64, _>("size"),
            })
        })
        .collect();
    tx.commit().await.map_err(err_db)?;
    Ok(Json(serde_json::json!({ "items": items })))
}

#[derive(Debug, serde::Deserialize)]
pub struct SieveGet {
    pub env_id: Uuid,
    pub account_id: Uuid,
    pub name: String,
}

/// `POST /v1/internal/sieve/get` — one script's source (from Storage).
#[utoipa::path(
    post,
    path = "/v1/internal/sieve/get",
    request_body = serde_json::Value,
    responses(
        (status = 200, description = "Script", body = serde_json::Value),
    ),
    security(),
    tag = "store",
)]
pub async fn sieve_get(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<SieveGet>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let _a = auth::require_mail_auth(
        &state.config,
        &state.workload_registry,
        &state.core.admin.policy,
        &headers,
        "email8:sieve:manage",
    )
    .await?;
    let mut tx = state.pool.begin().await.map_err(err_db)?;
    auth::set_mail_tenant_context(&mut tx, &_a, req.env_id, req.account_id).await;
    let row: Option<(String,)> = sqlx::query_as(
        "SELECT blob_hash FROM email8.sieve_scripts WHERE account_id = $1 AND name = $2",
    )
    .bind(req.account_id)
    .bind(&req.name)
    .fetch_optional(&mut *tx)
    .await
    .map_err(err_db)?;
    let Some((blob_hash,)) = row else {
        tx.commit().await.map_err(err_db)?;
        return Ok(Json(serde_json::json!({})));
    };
    let storage = crate::storage_auth::storage_client(
        &state.pool,
        &state.config.sentin8_storage_url,
        &["storage:env:write"],
    )
    .await
    .map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))?;
    let bytes = storage
        .get("", "", &format!("email8/sieve/{blob_hash}"))
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))?;
    tx.commit().await.map_err(err_db)?;
    Ok(Json(serde_json::json!({
        "source": String::from_utf8_lossy(&bytes),
    })))
}

#[derive(Debug, serde::Deserialize)]
pub struct SievePut {
    pub env_id: Uuid,
    pub account_id: Uuid,
    pub name: String,
    pub source: String,
}

/// `POST /v1/internal/sieve/put` — store a compiled script (blob →
/// Storage, row upsert).
#[utoipa::path(
    post,
    path = "/v1/internal/sieve/put",
    request_body = serde_json::Value,
    responses(
        (status = 200, description = "Stored"),
    ),
    security(),
    tag = "store",
)]
pub async fn sieve_put(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<SievePut>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let _a = auth::require_mail_auth(
        &state.config,
        &state.workload_registry,
        &state.core.admin.policy,
        &headers,
        "email8:sieve:manage",
    )
    .await?;
    let hash = blake3_hash(req.source.as_bytes());
    let storage = crate::storage_auth::storage_client(
        &state.pool,
        &state.config.sentin8_storage_url,
        &["storage:env:write"],
    )
    .await
    .map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))?;
    storage
        .put(
            "",
            "",
            &format!("email8/sieve/{hash}"),
            "application/sieve",
            req.source.as_bytes().to_vec(),
        )
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))?;
    let mut tx = state.pool.begin().await.map_err(err_db)?;
    auth::set_mail_tenant_context(&mut tx, &_a, req.env_id, req.account_id).await;
    // Allocate the script id only when inserting a new row (the upsert
    // path reuses the existing id via ON CONFLICT). Entity ids are
    // DB-generated UUIDs; sequences only back change-id counters now.
    let id = uuid::Uuid::new_v4();
    let result = sqlx::query(
        "INSERT INTO email8.sieve_scripts \
            (env_id, account_id, id, name, blob_hash, size, is_active) \
         VALUES ($1, $2, $6, $3, $4, $5, false) \
         ON CONFLICT (account_id, lower(name)) DO UPDATE \
            SET blob_hash = EXCLUDED.blob_hash, size = EXCLUDED.size",
    )
    .bind(req.env_id)
    .bind(req.account_id)
    .bind(&req.name)
    .bind(&hash)
    .bind(req.source.len() as i64)
    .bind(id)
    .execute(&mut *tx)
    .await
    .map_err(err_db)?;
    let _ = result;
    Ok(Json(serde_json::json!({ "stored": true })))
}

#[derive(Debug, serde::Deserialize)]
pub struct SieveActive {
    pub env_id: Uuid,
    pub account_id: Uuid,
    /// None → deactivate; Some(name) → activate that script.
    pub name: Option<String>,
}

/// `POST /v1/internal/sieve/setactive` — flip the active script (only one
/// may be active; the row flips + the account pointer updates).
#[utoipa::path(
    post,
    path = "/v1/internal/sieve/setactive",
    request_body = serde_json::Value,
    responses(
        (status = 200, description = "Activated"),
    ),
    security(),
    tag = "store",
)]
pub async fn sieve_set_active(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<SieveActive>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let _a = auth::require_mail_auth(
        &state.config,
        &state.workload_registry,
        &state.core.admin.policy,
        &headers,
        "email8:sieve:manage",
    )
    .await?;
    let mut tx = state.pool.begin().await.map_err(err_db)?;
    auth::set_mail_tenant_context(&mut tx, &_a, req.env_id, req.account_id).await;
    sqlx::query("UPDATE email8.sieve_scripts SET is_active = false WHERE account_id = $1")
        .bind(req.account_id)
        .execute(&mut *tx)
        .await
        .map_err(err_db)?;
    match &req.name {
        Some(name) => {
            sqlx::query(
                "UPDATE email8.sieve_scripts \
                    SET is_active = true \
                 WHERE account_id = $1 AND name = $2",
            )
            .bind(req.account_id)
            .bind(name)
            .execute(&mut *tx)
            .await
            .map_err(err_db)?;
            if let Some(id) = sqlx::query_scalar::<_, Uuid>(
                "SELECT id FROM email8.sieve_scripts WHERE account_id = $1 AND name = $2",
            )
            .bind(req.account_id)
            .bind(name)
            .fetch_optional(&mut *tx)
            .await
            .map_err(err_db)?
            {
                sqlx::query("UPDATE email8.principals SET active_script_id = $2 WHERE id = $1")
                    .bind(req.account_id)
                    .bind(id)
                    .execute(&mut *tx)
                    .await
                    .map_err(err_db)?;
            }
        }
        None => {
            sqlx::query("UPDATE email8.principals SET active_script_id = NULL WHERE id = $1")
                .bind(req.account_id)
                .execute(&mut *tx)
                .await
                .map_err(err_db)?;
        }
    }
    tx.commit().await.map_err(err_db)?;
    Ok(Json(serde_json::json!({ "active": req.name })))
}

#[derive(Debug, serde::Deserialize)]
pub struct SieveDelete {
    pub env_id: Uuid,
    pub account_id: Uuid,
    pub name: String,
}

/// `POST /v1/internal/sieve/delete` — remove a script row.
#[utoipa::path(
    post,
    path = "/v1/internal/sieve/delete",
    request_body = serde_json::Value,
    responses(
        (status = 200, description = "Deleted"),
    ),
    security(),
    tag = "store",
)]
pub async fn sieve_delete(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<SieveDelete>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let _a = auth::require_mail_auth(
        &state.config,
        &state.workload_registry,
        &state.core.admin.policy,
        &headers,
        "email8:sieve:manage",
    )
    .await?;
    let mut tx = state.pool.begin().await.map_err(err_db)?;
    auth::set_mail_tenant_context(&mut tx, &_a, req.env_id, req.account_id).await;
    let result =
        sqlx::query("DELETE FROM email8.sieve_scripts WHERE account_id = $1 AND name = $2")
            .bind(req.account_id)
            .bind(&req.name)
            .execute(&mut *tx)
            .await
            .map_err(err_db)?;
    tx.commit().await.map_err(err_db)?;
    Ok(Json(
        serde_json::json!({ "deleted": result.rows_affected() > 0 }),
    ))
}

#[derive(Debug, serde::Deserialize)]
pub struct SieveRename {
    pub env_id: Uuid,
    pub account_id: Uuid,
    pub from: String,
    pub to: String,
}

/// `POST /v1/internal/sieve/rename` — rename a script.
#[utoipa::path(
    post,
    path = "/v1/internal/sieve/rename",
    request_body = serde_json::Value,
    responses(
        (status = 200, description = "Renamed"),
    ),
    security(),
    tag = "store",
)]
pub async fn sieve_rename(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<SieveRename>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let _a = auth::require_mail_auth(
        &state.config,
        &state.workload_registry,
        &state.core.admin.policy,
        &headers,
        "email8:sieve:manage",
    )
    .await?;
    let mut tx = state.pool.begin().await.map_err(err_db)?;
    auth::set_mail_tenant_context(&mut tx, &_a, req.env_id, req.account_id).await;
    let result = sqlx::query(
        "UPDATE email8.sieve_scripts SET name = $3 \
         WHERE account_id = $1 AND name = $2",
    )
    .bind(req.account_id)
    .bind(&req.from)
    .bind(&req.to)
    .execute(&mut *tx)
    .await
    .map_err(err_db)?;
    if result.rows_affected() == 0 {
        return Err((StatusCode::NOT_FOUND, "no such script".into()));
    }
    Ok(Json(serde_json::json!({ "renamed": true })))
}

fn err_db(e: sqlx::Error) -> (StatusCode, String) {
    tracing::error!(error = %e, "email8:store: database error");
    (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
}

fn err_op(e: store_ops::StoreOpError) -> (StatusCode, String) {
    map_op(e)
}

fn map_op(e: store_ops::StoreOpError) -> (StatusCode, String) {
    match e {
        store_ops::StoreOpError::Db(db) => err_db(db),
        store_ops::StoreOpError::NoAccount => (StatusCode::NOT_FOUND, e.to_string()),
        store_ops::StoreOpError::MailboxNotFound(_) => (StatusCode::NOT_FOUND, e.to_string()),
        store_ops::StoreOpError::QuotaExceeded => (StatusCode::INSUFFICIENT_STORAGE, e.to_string()),
        store_ops::StoreOpError::Conflict => (StatusCode::CONFLICT, e.to_string()),
    }
}

fn auth_header(headers: &HeaderMap) -> String {
    headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_default()
}

/// Fetch a message blob from Sentin8:Storage (M2M-authenticated).
async fn fetch_blob(state: &AppState, blob_hash: &str) -> Result<Vec<u8>, (StatusCode, String)> {
    let client = crate::storage_auth::storage_client(
        &state.pool,
        &state.config.sentin8_storage_url,
        &["storage:env:read"],
    )
    .await
    .map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))?;
    client
        .get("", "", &format!("email8/blobs/{blob_hash}"))
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))
}

/// Append an event to the local `email8.outbox` (OUTBOX-EMAIL8,
/// architecture-principles §6.7 — the DBX producer path). The row is
/// relayed to Bus `POST /v1/produce` post-commit by the shell's 8b task
/// (idempotency_key = row id; consumers dedupe). The shared-schema note:
/// email8 keeps every table in `email8` — the helper's unqualified
/// `outbox` resolves through the service role's search_path.
async fn emit_event(
    pool: &sqlx::PgPool,
    env_id: Uuid,
    event_type: &str,
    payload: serde_json::Value,
) {
    if let Err(e) =
        sentin8::bus::outbox::insert_outbox_row_pool(pool, env_id, "email8", event_type, &payload)
            .await
    {
        tracing::warn!(error = %e, %event_type, "email8:store: outbox insert failed");
    }
}
// ── ACL grants + effective rights (story 2.7) ─────────────────────────────

/// `POST /v1/internal/acl/grant` — grant rights on one document.
#[derive(Debug, serde::Deserialize)]
pub struct AclGrantRequest {
    pub env_id: Uuid,
    pub account_id: Uuid,
    pub collection: i16,
    pub document_id: Uuid,
    pub grantee_account_id: Uuid,
    /// Bitwise rights (email8::contracts::Acl bits).
    pub rights: i32,
}

#[utoipa::path(
    post,
    path = "/v1/internal/acl/grant",
    request_body = serde_json::Value,
    responses(
        (status = 200, description = "Granted"),
    ),
    security(),
    tag = "store",
)]
pub async fn acl_grant(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<AclGrantRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let _a = auth::require_mail_auth(
        &state.config,
        &state.workload_registry,
        &state.core.admin.policy,
        &headers,
        "email8:mail:write",
    )
    .await?;
    let mut tx = state.pool.begin().await.map_err(err_db)?;
    auth::set_mail_tenant_context(&mut tx, &_a, req.env_id, req.account_id).await;
    sqlx::query(
        r#"INSERT INTO email8.acl_grants
               (env_id, account_id, collection, document_id, grantee_account_id, rights)
           VALUES ($1, $2, $3, $4, $5, $6)
           ON CONFLICT (account_id, collection, document_id, grantee_account_id)
           DO UPDATE SET rights = $6"#,
    )
    .bind(req.env_id)
    .bind(req.account_id)
    .bind(req.collection)
    .bind(req.document_id)
    .bind(req.grantee_account_id)
    .bind(req.rights)
    .execute(&mut *tx)
    .await
    .map_err(err_db)?;
    tx.commit().await.map_err(err_db)?;
    // ShareNotification rides the bus (inbox-first): the grantee's
    // client refreshes its shared-with-me view.
    emit_event(
        &state.pool,
        req.env_id,
        "email8:mail:share:granted",
        serde_json::json!({
            "grantee_account_id": req.grantee_account_id,
            "collection": req.collection,
            "document_id": req.document_id,
            "rights": req.rights,
        }),
    )
    .await;
    Ok(Json(serde_json::json!({ "granted": true })))
}

/// `POST /v1/internal/acl/revoke` — remove a grant.
#[derive(Debug, serde::Deserialize)]
pub struct AclRevokeRequest {
    pub env_id: Uuid,
    pub account_id: Uuid,
    pub collection: i16,
    pub document_id: Uuid,
    pub grantee_account_id: Uuid,
}

#[utoipa::path(
    post,
    path = "/v1/internal/acl/revoke",
    request_body = serde_json::Value,
    responses(
        (status = 200, description = "Revoked"),
    ),
    security(),
    tag = "store",
)]
pub async fn acl_revoke(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<AclRevokeRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let _a = auth::require_mail_auth(
        &state.config,
        &state.workload_registry,
        &state.core.admin.policy,
        &headers,
        "email8:mail:write",
    )
    .await?;
    let mut tx = state.pool.begin().await.map_err(err_db)?;
    auth::set_mail_tenant_context(&mut tx, &_a, req.env_id, req.account_id).await;
    let deleted = sqlx::query(
        "DELETE FROM email8.acl_grants \
         WHERE account_id = $1 AND collection = $2 AND document_id = $3 AND grantee_account_id = $4",
    )
    .bind(req.account_id)
    .bind(req.collection)
    .bind(req.document_id)
    .bind(req.grantee_account_id)
    .execute(&mut *tx)
    .await
    .map_err(err_db)?;
    let revoked = deleted.rows_affected() > 0;
    tx.commit().await.map_err(err_db)?;
    emit_event(
        &state.pool,
        req.env_id,
        "email8:mail:share:revoked",
        serde_json::json!({
            "grantee_account_id": req.grantee_account_id,
            "collection": req.collection,
            "document_id": req.document_id,
        }),
    )
    .await;
    Ok(Json(serde_json::json!({ "revoked": revoked })))
}

/// `GET /v1/internal/acl/rights?env_id&grantee_account_id&collection&document_id`
/// — effective rights for a grantee on one document (the union of
/// direct grants; owners implicitly hold everything).
#[derive(Debug, serde::Deserialize)]
pub struct AclRightsQuery {
    pub env_id: Uuid,
    pub account_id: Uuid,
    pub collection: i16,
    pub document_id: Uuid,
    /// The grantee to compute rights for (defaults to the owner).
    pub grantee_account_id: Option<Uuid>,
}

#[utoipa::path(
    get,
    path = "/v1/internal/acl/rights",
    responses(
        (status = 200, description = "Effective rights", body = serde_json::Value),
    ),
    security(),
    tag = "store",
)]
pub async fn acl_effective_rights(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<AclRightsQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let _a = auth::require_mail_auth(
        &state.config,
        &state.workload_registry,
        &state.core.admin.policy,
        &headers,
        "email8:mail:read",
    )
    .await?;
    let mut tx = state.pool.begin().await.map_err(err_db)?;
    auth::set_mail_tenant_context(&mut tx, &_a, q.env_id, q.account_id).await;
    let grantee = q.grantee_account_id.unwrap_or(q.account_id);
    // The owner holds every right; a grantee holds the union of grants.
    let rights: Option<i32> = sqlx::query_scalar(
        "SELECT BIT_OR(rights)::int FROM email8.acl_grants \
         WHERE account_id = $1 AND collection = $2 AND document_id = $3 AND grantee_account_id = $4",
    )
    .bind(q.account_id)
    .bind(q.collection)
    .bind(q.document_id)
    .bind(grantee)
    .fetch_optional(&mut *tx)
    .await
    .map_err(err_db)?;
    let effective = if grantee == q.account_id {
        i32::MAX // owner
    } else {
        rights.unwrap_or(0)
    };
    tx.commit().await.map_err(err_db)?;
    Ok(Json(serde_json::json!({
        "rights": effective,
        "is_owner": grantee == q.account_id,
    })))
}

/// Map a JMAP push type string ("Email", "Mailbox", "Calendar", …) to
/// the changelog collection code stored in `push_subscriptions.types`.
pub fn push_type_code(name: &str) -> i16 {
    match name {
        "Email" => 0,
        "Mailbox" => 1,
        "Thread" => 2,
        "Identity" => 3,
        "Calendar" => 4,
        "CalendarEvent" => 5,
        "AddressBook" => 6,
        "ContactCard" => 7,
        _ => 99,
    }
}

/// A random URL-safe token (push verification codes, DAV lock tokens…).
pub fn random_token() -> String {
    use rand::Rng;
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = rand::thread_rng();
    (0..24)
        .map(|_| ALPHABET[rng.gen_range(0..ALPHABET.len())] as char)
        .collect()
}
