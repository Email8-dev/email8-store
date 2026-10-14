// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Email8:Store
// SPDX-License-Identifier: Apache-2.0

//! JMAP API surface — `POST /jmap` (RFC 8620 request processing) plus the
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

/// `GET /jmap/session` — the RFC 8620 session resource.
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
        let mut conn = state.pool.acquire().await.map_err(err_db)?;
        auth::set_mail_tenant_context(&mut conn, m.env_id(), Uuid::nil()).await;
        auth::bind_account(&mut conn, &m).await?
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

/// `POST /jmap` — the method-call batch.
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
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    auth::set_mail_tenant_context(&mut conn, m.env_id(), m.account_id).await;
    let account_id = auth::bind_account(&mut conn, &m).await?;

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

/// Method dispatch — P1 surface: Core/echo, Mailbox/Email get+changes+set
/// basics, Blob upload/download, Vacation/Vacancy get stubs.
async fn dispatch(
    state: &AppState,
    m: &auth::MailAuth,
    account_id: Uuid,
    object: &str,
    verb: &str,
    args: serde_json::Value,
) -> Result<serde_json::Value, String> {
    let mut conn = state
        .pool
        .acquire()
        .await
        .map_err(|e| e.to_string())
        .map_err(err_string)?;
    auth::set_mail_tenant_context(&mut conn, m.env_id(), account_id).await;

    match (object, verb) {
        ("Core", "echo") => Ok(jmap::echo(args)),
        ("Mailbox", "get") => crate::jmap_objects::mailbox_get(&mut conn, account_id, &args)
            .await
            .map_err(err_string),
        ("Email", "get") => crate::jmap_objects::email_get(&mut conn, account_id, &args, state)
            .await
            .map_err(err_string),
        ("Email", "changes") | ("Mailbox", "changes") | ("Thread", "changes") => {
            crate::jmap_objects::changes(&mut conn, account_id, object, &args)
                .await
                .map_err(err_string)
        }
        ("Thread", "get") => crate::jmap_objects::thread_get(&mut conn, account_id, &args)
            .await
            .map_err(err_string),
        ("Email", "query") => crate::jmap_objects::email_query(&mut conn, account_id, &args)
            .await
            .map_err(err_string),
        ("Email", "set") => crate::jmap_objects::email_set(&mut conn, account_id, &args)
            .await
            .map_err(err_string),
        ("Mailbox", "set") => crate::jmap_objects::mailbox_set(&mut conn, account_id, &args)
            .await
            .map_err(err_string),
        ("Identity", "get") => crate::jmap_objects::identity_get(&mut conn, account_id, &args)
            .await
            .map_err(err_string),
        ("Calendar", "get") => crate::jmap_objects::calendar_get(&mut conn, account_id, &args)
            .await
            .map_err(err_string),
        ("CalendarEvent", "get") => {
            crate::jmap_objects::calendar_event_get(&mut conn, account_id, &args)
                .await
                .map_err(err_string)
        }
        ("AddressBook", "get") => {
            crate::jmap_objects::addressbook_get(&mut conn, account_id, &args)
                .await
                .map_err(err_string)
        }
        ("ContactCard", "get") => {
            crate::jmap_objects::contact_card_get(&mut conn, account_id, &args)
                .await
                .map_err(err_string)
        }
        ("PushSubscription", "get") => {
            crate::jmap_objects::push_subscription_get(&mut conn, account_id, &args)
                .await
                .map_err(err_string)
        }
        ("PushSubscription", "set") => {
            crate::jmap_objects::push_subscription_set(&mut conn, m.env_id(), account_id, &args)
                .await
                .map_err(err_string)
        }
        ("EmailSubmission", "set") => {
            crate::jmap_objects::email_submission_set(state, m, account_id, &args).await
        }
        ("VacationResponse", "get") => Ok(json!({"list": [], "state": "0", "notFound": []})),
        _ => Err("unknownMethod".to_string()),
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

/// `GET /jmap/ws` — RFC 8887 JMAP over WebSocket. After the upgrade the
/// server accepts JMAP `Request` frames as text messages and replies with
/// `Response` frames; unsolicited `StateChange` pushes are emitted when
/// the changelog advances. Auth is via the `access_token` query param
/// (browsers cannot set headers on the upgrade request).
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
                // StateChange push (RFC 8887 §3.3) — poll the changelog
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
    let Ok(mut conn) = state.pool.acquire().await else {
        resp.push_error("serverFail", "ws".to_string());
        return resp.to_json().to_string();
    };
    let _ = auth::set_mail_tenant_context(&mut conn, m.env_id(), m.account_id).await;
    let Ok(account_id) = auth::bind_account(&mut conn, m).await else {
        resp.push_error("accountNotFound", "ws".to_string());
        return resp.to_json().to_string();
    };
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

/// Poll the account's changelog head and build a StateChange envelope —
/// `None` when there is no change since the last emission (tracked by
/// the caller's changelog MAX snapshot diff inside `current_state`).
async fn ws_state_change(state: &AppState, m: &crate::auth::MailAuth) -> Option<serde_json::Value> {
    let mut conn = state.pool.acquire().await.ok()?;
    auth::set_mail_tenant_context(&mut conn, m.env_id(), m.account_id).await;
    let account_id = auth::bind_account(&mut conn, m).await.ok()?;
    crate::push_stream::current_state(&mut conn, account_id).await
}

/// `GET /jmap/download/{account_id}/{blob_hash}/{name}` — blob download.
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

/// `POST /jmap/upload/{account_id}` — blob upload (RFC 9404).
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
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    auth::set_mail_tenant_context(&mut conn, m.env_id(), account_id).await;
    sqlx::query(
        "INSERT INTO email8.blob_links (env_id, owner_account_id, blob_hash, ref_kind, expires_at) \
         VALUES ($1, $2, $3, 'reserved', now() + interval '1 day') ON CONFLICT DO NOTHING",
    )
    .bind(m.env_id())
    .bind(account_id)
    .bind(&hash)
    .execute(&mut *conn)
    .await
    .map_err(err_db)?;

    Ok(Json(jmap::upload_result(
        &account_id.to_string(),
        &hash,
        "application/octet-stream",
        body.len() as i64,
    ))
    .into_response())
}

/// `GET /jmap/eventsource` — SSE state-change stream (RFC 8620 §7.1).
#[derive(Debug, serde::Deserialize)]
pub struct EventSourceQuery {
    #[serde(default)]
    pub types: Option<String>,
    #[serde(default)]
    pub closeafter: Option<String>,
    #[serde(default)]
    pub ping: Option<u32>,
}

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
