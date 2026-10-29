// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Email8:Store
// SPDX-License-Identifier: Apache-2.0

//! JMAP API surface - `POST /jmap` (RFC 8620 request processing) plus the
//! session resource, blob download/upload, and the EventSource stream.
//!
//! Design: `email8/design/sentin8-email8-store-technical-design.md` §7.
use uuid::Uuid;

use axum::{
    body::Body,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};

use email8::jmap_proto as jmap;
use serde_json::json;

use crate::{auth, data_api::AppState};

/// `GET /jmap/session` - the RFC 8620 session resource.
// ── JMAP protocol DTOs (RFC 8620 dynamic surface) ────────────────

/// The JMAP `session` document (RFC 8620 §2): capability objects are
/// extension-defined, so the document is dynamic - documented as a
/// transparent wrapper (wire-true, schema non-empty).
#[derive(Debug, serde::Serialize, utoipa::ToSchema)]
#[serde(transparent)]
pub struct JmapSessionDocument(
    /// The session document (capability-keyed dynamic JSON).
    pub serde_json::Value,
);

/// The JMAP request/response batch (RFC 8620 §3.6): method calls are
/// extension-defined - same transparent-wrapper treatment.
#[derive(Debug, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
#[serde(transparent)]
pub struct JmapBatch(
    /// The `using`/`methodCalls` request (or `methodResponses` reply).
    pub serde_json::Value,
);

/// Blob-upload result (RFC 9404 §4; the jmap-proto helper shape).
#[derive(Debug, serde::Serialize, utoipa::ToSchema)]
pub struct JmapUploadResult {
    /// The uploading account.
    #[serde(rename = "accountId")]
    pub account_id: String,
    /// The blob id (content hash).
    #[serde(rename = "blobId")]
    pub blob_id: String,
    /// Type declared at upload.
    #[serde(rename = "type")]
    pub content_type: String,
    /// Size in bytes.
    pub size: i64,
}

#[utoipa::path(
    get,
    path = "/jmap/session",
    responses(
        (status = 200, description = "JMAP session (capabilities + endpoint URLs)", body = JmapSessionDocument),
        (status = 401, description = "Not authenticated"),
    ),
    security(),
    tag = "store",
)]
pub async fn session(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, (StatusCode, String)> {
    let m = auth::require_mail_auth(
        &state.config,
        &state.workload_registry,
        &state.core.admin.policy,
        &headers,
        "email8:mail:read",
    )
    .await?;
    let account_id = if m.account_id != Uuid::nil() {
        m.account_id
    } else {
        // context + binding SELECT share ONE transaction -
        // the transaction-local context evaporates on autocommit.
        let mut tx = state.pool.begin().await.map_err(err_db)?;
        auth::set_mail_tenant_context(&mut tx, &m, m.env_id(), Uuid::nil()).await;
        let bound = auth::bind_account(&mut tx, &m).await?;
        tx.commit().await.map_err(err_db)?;
        bound
    };
    let account_str = account_id.to_string();
    let caps = json!({
        jmap::urn::CORE: {},
        jmap::urn::MAIL: {},
        jmap::urn::SUBMISSION: {},
        jmap::urn::VACATION_RESPONSE: {},
        jmap::urn::SIEVE: {},
        jmap::urn::BLOB: {},
        jmap::urn::QUOTA: {},
    });
    let body = json!({
        "capabilities": caps,
        "accounts": {
            account_str.clone(): {
                "name": m.auth.sub(),
                "isPersonal": true,
                "isReadOnly": false,
                "accountCapabilities": caps,
            }
        },
        "primaryAccounts": { jmap::urn::MAIL: account_str.clone(), jmap::urn::SUBMISSION: account_str },
        "username": m.auth.sub(),
        "apiUrl": "/jmap",
        "downloadUrl": "/jmap/download/{accountId}/{blobId}/{name}",
        "uploadUrl": "/jmap/upload/{accountId}/",
        "eventSourceUrl": "/jmap/eventsource?types=Mailbox,Email&closeafter=state",
        "state": format!("e8-{}", chrono::Utc::now().timestamp()),
    });
    Ok(Json(body).into_response())
}

/// `POST /jmap` - the method-call batch.
#[utoipa::path(
    post,
    path = "/jmap",
    request_body = JmapBatch,
    responses(
        (status = 200, description = "JMAP request/response batch (RFC 8620 §3.6)", body = JmapBatch),
        (status = 401, description = "Not authenticated"),
    ),
    security(),
    tag = "store",
)]
pub async fn api(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<Response, (StatusCode, String)> {
    let m = auth::require_mail_auth(
        &state.config,
        &state.workload_registry,
        &state.core.admin.policy,
        &headers,
        "email8:mail:read",
    )
    .await?;
    let req = jmap::parse(&body).map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

    // Resolve the account binding once for the whole batch.
    // explicit transaction - the context is transaction-local.
    let mut tx = state.pool.begin().await.map_err(err_db)?;
    auth::set_mail_tenant_context(&mut tx, &m, m.env_id(), m.account_id).await;
    let account_id = auth::bind_account(&mut tx, &m).await?;
    tx.commit().await.map_err(err_db)?;

    let mut resp = jmap::JmapResponse::new();
    let responses: Vec<(String, serde_json::Value, String)> = Vec::new();
    let _ = responses;

    for (name, _full, args, call_id) in req.method_calls {
        let Some((object, verb)) = jmap::MethodCall::split(&name) else {
            resp.push_error("unknownMethod", call_id.clone());
            continue;
        };
        // Capability check (RFC 8620 §3.3).
        match jmap::capability_for_method(&object) {
            Some(cap) if req.using.iter().any(|u| u == cap) => {}
            _ => {
                resp.push_error(
                    jmap::RequestError::UnknownCapability(name.clone()).to_string(),
                    call_id.clone(),
                );
                continue;
            }
        }
        let mut args = args;
        if jmap::resolve_references(&mut args, &[]).is_err() {
            resp.push_error("unresolvableReference", call_id.clone());
            continue;
        }
        let result = dispatch(&state, &m, account_id, &object, &verb, args).await;
        match result {
            Ok(value) => resp.push(name.clone(), value, call_id.clone()),
            Err(description) => resp.push_error(description, call_id.clone()),
        }
    }

    Ok(Json(resp.to_json()).into_response())
}

/// Method dispatch - P1 surface: Core/echo, Mailbox/Email get+changes+set
/// basics, Blob upload/download, Vacation/Vacancy get stubs.
async fn dispatch(
    state: &AppState,
    m: &auth::MailAuth,
    account_id: Uuid,
    object: &str,
    verb: &str,
    args: serde_json::Value,
) -> Result<serde_json::Value, String> {
    // the context stamp is transaction-local - begin the
    // transaction FIRST, stamp inside it, and let the object handler run
    // on the same connection for the whole batch method.
    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|e| e.to_string())
        .map_err(err_string)?;
    auth::set_mail_tenant_context(&mut tx, m, m.env_id(), account_id).await;

    match (object, verb) {
        ("Core", "echo") => {
            let _ = tx.commit().await;
            Ok(jmap::echo(args))
        }
        ("Mailbox", "get") => {
            let v = crate::jmap_objects::mailbox_get(&mut tx, account_id, &args)
                .await
                .map_err(err_string);
            let _ = tx.commit().await;
            v
        }
        ("Email", "get") => {
            let v = crate::jmap_objects::email_get(&mut tx, account_id, &args, state)
                .await
                .map_err(err_string);
            let _ = tx.commit().await;
            v
        }
        ("Email", "changes") | ("Mailbox", "changes") | ("Thread", "changes") => {
            let v = crate::jmap_objects::changes(&mut tx, account_id, object, &args)
                .await
                .map_err(err_string);
            let _ = tx.commit().await;
            v
        }
        ("Thread", "get") => {
            let v = crate::jmap_objects::thread_get(&mut tx, account_id, &args)
                .await
                .map_err(err_string);
            let _ = tx.commit().await;
            v
        }
        ("Email", "query") => {
            let v = crate::jmap_objects::email_query(&mut tx, account_id, &args)
                .await
                .map_err(err_string);
            let _ = tx.commit().await;
            v
        }
        ("Email", "set") => {
            let v = crate::jmap_objects::email_set(&mut tx, account_id, &args)
                .await
                .map_err(err_string);
            let _ = tx.commit().await;
            v
        }
        ("Mailbox", "set") => {
            let v = crate::jmap_objects::mailbox_set(&mut tx, account_id, &args)
                .await
                .map_err(err_string);
            let _ = tx.commit().await;
            v
        }
        ("Identity", "get") => {
            let v = crate::jmap_objects::identity_get(&mut tx, account_id, &args)
                .await
                .map_err(err_string);
            let _ = tx.commit().await;
            v
        }
        ("Calendar", "get") => {
            let v = crate::jmap_objects::calendar_get(&mut tx, account_id, &args)
                .await
                .map_err(err_string);
            let _ = tx.commit().await;
            v
        }
        ("CalendarEvent", "get") => {
            let v = crate::jmap_objects::calendar_event_get(&mut tx, account_id, &args)
                .await
                .map_err(err_string);
            let _ = tx.commit().await;
            v
        }
        ("AddressBook", "get") => {
            let v = crate::jmap_objects::addressbook_get(&mut tx, account_id, &args)
                .await
                .map_err(err_string);
            let _ = tx.commit().await;
            v
        }
        ("ContactCard", "get") => {
            let v = crate::jmap_objects::contact_card_get(&mut tx, account_id, &args)
                .await
                .map_err(err_string);
            let _ = tx.commit().await;
            v
        }
        ("PushSubscription", "get") => {
            let v = crate::jmap_objects::push_subscription_get(&mut tx, account_id, &args)
                .await
                .map_err(err_string);
            let _ = tx.commit().await;
            v
        }
        ("PushSubscription", "set") => {
            let v =
                crate::jmap_objects::push_subscription_set(&mut tx, m.env_id(), account_id, &args)
                    .await
                    .map_err(err_string);
            let _ = tx.commit().await;
            v
        }
        ("EmailSubmission", "set") => {
            let v = crate::jmap_objects::email_submission_set(state, m, account_id, &args).await;
            let _ = tx.commit().await;
            v
        }
        ("VacationResponse", "get") => {
            let _ = tx.commit().await;
            Ok(json!({"list": [], "state": "0", "notFound": []}))
        }
        _ => {
            let _ = tx.commit().await;
            Err("unknownMethod".to_string())
        }
    }
}

fn err_db(e: sqlx::Error) -> (StatusCode, String) {
    tracing::error!(error = %e, "email8:store: database error");
    (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
}

fn err_string<E: std::fmt::Display>(e: E) -> String {
    tracing::error!(error = %e, "email8:store: database error");
    e.to_string()
}

/// `GET /jmap/ws` - RFC 8887 JMAP over WebSocket. After the upgrade the
/// server accepts JMAP `Request` frames as text messages and replies with
/// `Response` frames; unsolicited `StateChange` pushes are emitted when
/// the changelog advances. Auth is via the `access_token` query param
/// (browsers cannot set headers on the upgrade request).
#[utoipa::path(
    get,
    path = "/jmap/ws",
    responses(
        (status = 101, description = "WebSocket upgrade (JMAP over WS)"),
    ),
    security(),
    tag = "store",
)]
pub async fn jmap_ws(
    ws: axum::extract::ws::WebSocketUpgrade,
    Query(q): Query<WsQuery>,
    State(state): State<AppState>,
) -> Response {
    // Rebuild an Authorization header from the query token so the shared
    // `require_mail_auth` path applies unchanged.
    let mut headers = HeaderMap::new();
    if let Ok(val) = axum::http::HeaderValue::from_str(&format!("Bearer {}", q.access_token)) {
        headers.insert(axum::http::header::AUTHORIZATION, val);
    }
    let m = match auth::require_mail_auth(
        &state.config,
        &state.workload_registry,
        &state.core.admin.policy,
        &headers,
        "email8:mail:read",
    )
    .await
    {
        Ok(m) => m,
        Err((code, msg)) => return (code, msg).into_response(),
    };
    ws.on_upgrade(move |socket| jmap_ws_session(socket, state, m))
}

#[derive(serde::Deserialize)]
pub struct WsQuery {
    access_token: String,
}

/// One RFC 8887 WS session: request/response loop + 30 s StateChange poll.
async fn jmap_ws_session(
    socket: axum::extract::ws::WebSocket,
    state: AppState,
    m: crate::auth::MailAuth,
) {
    use axum::extract::ws::Message;
    use futures_util::{SinkExt, StreamExt};
    let (mut ws_tx, mut ws_rx) = socket.split();
    loop {
        tokio::select! {
            frame = ws_rx.next() => {
                let Some(Ok(Message::Text(text))) = frame else { break };
                let Ok(req) = jmap::parse(text.as_bytes()) else {
                    let _ = ws_tx
                        .send(Message::Text("{\"methodErrors\":[\"invalidJSON\"]}".into()))
                        .await;
                    continue;
                };
                let resp = handle_ws_batch(&state, &m, req).await;
                if ws_tx.send(Message::Text(resp.into())).await.is_err() {
                    break;
                }
            }
            _ = tokio::time::sleep(std::time::Duration::from_secs(30)) => {
                // StateChange push (RFC 8887 §3.3) - poll the changelog
                // head and emit only when it advanced.
                let Some(push) = ws_state_change(&state, &m).await else { continue };
                if ws_tx
                    .send(Message::Text(
                        serde_json::to_string(&push).unwrap_or_default().into(),
                    ))
                    .await
                    .is_err()
                {
                    break;
                }
            }
        }
    }
}

/// Run one JMAP request batch over the WS (same dispatch as POST /jmap).
async fn handle_ws_batch(
    state: &AppState,
    m: &crate::auth::MailAuth,
    req: jmap::JmapRequest,
) -> String {
    let mut resp = jmap::JmapResponse::new();
    // explicit transaction - the context is transaction-local.
    let Ok(mut tx) = state.pool.begin().await else {
        resp.push_error("serverFail", "ws".to_string());
        return resp.to_json().to_string();
    };
    let _ = auth::set_mail_tenant_context(&mut tx, m, m.env_id(), m.account_id).await;
    let Ok(account_id) = auth::bind_account(&mut tx, m).await else {
        resp.push_error("accountNotFound", "ws".to_string());
        return resp.to_json().to_string();
    };
    // The per-method dispatch opens its own transaction (context stamp +
    // object handler on one connection); this binding tx is done.
    drop(tx);
    for (name, _full, mut args, call_id) in req.method_calls {
        let Some((object, verb)) = jmap::MethodCall::split(&name) else {
            resp.push_error("unknownMethod", call_id.clone());
            continue;
        };
        match jmap::capability_for_method(&object) {
            Some(cap) if req.using.iter().any(|u| u == cap) => {}
            _ => {
                resp.push_error(
                    jmap::RequestError::UnknownCapability(name.clone()).to_string(),
                    call_id.clone(),
                );
                continue;
            }
        }
        let _ = jmap::resolve_references(&mut args, &[]);
        match dispatch(state, m, account_id, &object, &verb, args).await {
            Ok(value) => resp.push(name.clone(), value, call_id.clone()),
            Err(description) => resp.push_error(description, call_id.clone()),
        }
    }
    resp.to_json().to_string()
}

/// Poll the account's changelog head and build a StateChange envelope -
/// `None` when there is no change since the last emission (tracked by
/// the caller's changelog MAX snapshot diff inside `current_state`).
async fn ws_state_change(state: &AppState, m: &auth::MailAuth) -> Option<serde_json::Value> {
    // explicit transaction - context + query share one tx.
    let mut tx = state.pool.begin().await.ok()?;
    auth::set_mail_tenant_context(&mut tx, m, m.env_id(), m.account_id).await;
    let account_id = auth::bind_account(&mut tx, m).await.ok()?;
    let state_now = crate::push_stream::current_state(&mut tx, account_id).await;
    tx.commit().await.ok()?;
    state_now
}

/// `GET /jmap/download/{account_id}/{blob_hash}/{name}` - blob download.
#[utoipa::path(
    get,
    path = "/jmap/download/{account_id}/{blob_id}/{name}",
    params(
        ("account_id" = String, Path, description = "JMAP account id"),
        ("blob_id" = String, Path, description = "Blob id"),
        ("name" = String, Path, description = "Download filename"),
    ),
    responses(
        (status = 200, description = "The raw blob bytes"),
    ),
    security(),
    tag = "store",
)]
pub async fn download(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((_account_id, blob_hash, name)): Path<(Uuid, String, String)>,
) -> Result<Response, (StatusCode, String)> {
    let m = auth::require_mail_auth(
        &state.config,
        &state.workload_registry,
        &state.core.admin.policy,
        &headers,
        "email8:mail:read",
    )
    .await?;
    let _ = m;
    let client = crate::storage_auth::storage_client(
        &state.pool,
        &state.config.sentin8_storage_url,
        &["storage:env:read"],
    )
    .await
    .map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))?;
    let data = client
        .get("", "", &format!("email8/blobs/{blob_hash}"))
        .await
        .map_err(|e| (StatusCode::NOT_FOUND, e.to_string()))?;
    Ok(Response::builder()
        .header("Content-Type", "application/octet-stream")
        .header(
            "Content-Disposition",
            format!("attachment; filename=\"{name}\""),
        )
        .body(Body::from(data))
        .unwrap())
}

/// `POST /jmap/upload/{account_id}` - blob upload (RFC 9404).
#[utoipa::path(
    post,
    path = "/jmap/upload/{account_id}",
    params(("account_id" = String, Path, description = "JMAP account id")),
    request_body = [u8],
    responses(
        (status = 201, description = "Blob created", body = JmapUploadResult),
    ),
    security(),
    tag = "store",
)]
pub async fn upload(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(account_id): Path<Uuid>,
    body: axum::body::Bytes,
) -> Result<Response, (StatusCode, String)> {
    let m = auth::require_mail_auth(
        &state.config,
        &state.workload_registry,
        &state.core.admin.policy,
        &headers,
        "email8:mail:write",
    )
    .await?;
    if account_id == Uuid::nil() {
        return Err((StatusCode::NOT_FOUND, "account not found".into()));
    }
    // Quota gate.
    let verdict = crate::data_api::blob_quota(
        State(state.clone()),
        headers,
        axum::Json(email8::contracts::BlobQuotaCheck {
            env_id: m.env_id(),
            account_id,
            size: body.len() as i64,
        }),
    )
    .await?
    .0;
    if !verdict.allowed {
        return Err((
            StatusCode::INSUFFICIENT_STORAGE,
            "blob quota exceeded".into(),
        ));
    }

    // Content-addressed upload: hash → Storage put → reserved link row.
    let hash = blake3::hash(&body).to_hex().to_string();
    let client = crate::storage_auth::storage_client(
        &state.pool,
        &state.config.sentin8_storage_url,
        &["storage:env:read"],
    )
    .await
    .map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))?;
    client
        .put(
            "",
            "",
            &format!("email8/blobs/{hash}"),
            "application/octet-stream",
            body.to_vec(),
        )
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))?;
    // explicit transaction - the context stamp is
    // transaction-local; the blob_links insert shares the tx.
    let mut tx = state.pool.begin().await.map_err(err_db)?;
    auth::set_mail_tenant_context(&mut tx, &m, m.env_id(), account_id).await;
    sqlx::query(
        "INSERT INTO email8.blob_links (env_id, owner_account_id, blob_hash, ref_kind, expires_at) \
         VALUES ($1, $2, $3, 'reserved', now() + interval '1 day') ON CONFLICT DO NOTHING",
    )
    .bind(m.env_id())
    .bind(account_id)
    .bind(&hash)
    .execute(&mut *tx)
    .await
    .map_err(err_db)?;
    tx.commit().await.map_err(err_db)?;

    Ok(Json(jmap::upload_result(
        &account_id.to_string(),
        &hash,
        "application/octet-stream",
        body.len() as i64,
    ))
    .into_response())
}

/// `GET /jmap/eventsource` - SSE state-change stream (RFC 8620 §7.1).
#[derive(Debug, serde::Deserialize)]
pub struct EventSourceQuery {
    #[serde(default)]
    pub types: Option<String>,
    #[serde(default)]
    pub closeafter: Option<String>,
    #[serde(default)]
    pub ping: Option<u32>,
}

#[utoipa::path(
    get,
    path = "/jmap/eventsource",
    responses(
        (status = 200, description = "JMAP EventSource SSE stream (push notifications)", content_type = "text/event-stream", body = String),
    ),
    security(),
    tag = "store",
)]
pub async fn event_source(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<EventSourceQuery>,
) -> Result<Response, (StatusCode, String)> {
    let m = auth::require_mail_auth(
        &state.config,
        &state.workload_registry,
        &state.core.admin.policy,
        &headers,
        "email8:mail:read",
    )
    .await?;
    let _ = q;
    let stream =
        crate::push_stream::state_stream(state.pool.clone(), m.env_id(), m.auth.sub().to_string());
    Ok(Response::builder()
        .header("Content-Type", "text/event-stream")
        .header("Cache-Control", "no-cache")
        .body(Body::from_stream(stream))
        .unwrap())
}
