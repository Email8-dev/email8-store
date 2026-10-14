// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Email8:Store
// SPDX-License-Identifier: Apache-2.0

//! Admin data endpoints (RFW data sources) — `POST /v1/admin/{page}`.
//!
//! Every admin handler enforces the §5.1 hardening: `target_env_id`
//! REQUIRED (no fallback to the token's env), RLS context set on the same
//! connection, explicit `WHERE env_id` clauses.

use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use uuid::Uuid;

use crate::auth;

#[derive(Debug, serde::Deserialize)]
pub struct AdminQuery {
    /// REQUIRED — the env being administered (§5.1 hardening).
    pub target_env_id: Option<Uuid>,
    #[serde(default)]
    pub account_id: Option<Uuid>,
}

/// `POST /v1/admin/{page}` — data for the admin viewer pages.
#[utoipa::path(
    post,
    path = "/v1/admin/{page}",
    params(
        ("page" = String, Path, description = "Admin page id: users|overview|domains|groups|quotas"),
        ("target_env_id" = Option<Uuid>, Query, description = "REQUIRED target env"),
        ("account_id" = Option<Uuid>, Query, description = "Optional account scope"),
    ),
    responses(
        (status = 200, description = "Page data", body = serde_json::Value),
        (status = 400, description = "Missing target_env_id"),
        (status = 403, description = "Missing email8 admin scope"),
        (status = 404, description = "Unknown page"),
    ),
    tag = "email8-store",
)]
pub async fn admin_data(
    State(state): State<StateHack>,
    headers: HeaderMap,
    Path(page): Path<String>,
    Query(q): Query<AdminQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let env_id = q
        .target_env_id
        .ok_or((StatusCode::BAD_REQUEST, "missing target_env_id".into()))?;
    let _a = auth::require_mail_auth(
        &state.config,
        &state.workload_registry,
        &state.core.admin.policy,
        &headers,
        "email8:admin:users",
    )
    .await?;

    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    auth::set_mail_tenant_context(&mut conn, env_id, q.account_id.unwrap_or(Uuid::nil())).await;

    match page.as_str() {
        "users" | "overview" => {
            let principals: Vec<(Uuid, String, Option<String>, chrono::DateTime<chrono::Utc>)> =
                sqlx::query_as(
                    "SELECT id, name, display_name, created_at FROM email8.principals \
                     WHERE env_id = $1 ORDER BY created_at DESC LIMIT 200",
                )
                .bind(env_id)
                .fetch_all(&mut *conn)
                .await
                .map_err(err_db)?;
            let quotas: Vec<(Uuid, i64, i64)> = sqlx::query_as(
                "SELECT account_id, used_bytes, used_objects FROM email8.quota_counters WHERE env_id = $1",
            )
            .bind(env_id)
            .fetch_all(&mut *conn)
            .await
            .map_err(err_db)?;
            let rows: Vec<serde_json::Value> = principals
                .into_iter()
                .map(|(id, name, display, created)| {
                    let used = quotas
                        .iter()
                        .find(|(acc, _, _)| *acc == id)
                        .map(|(_, b, _)| *b)
                        .unwrap_or(0);
                    serde_json::json!({
                        "id": id, "name": name, "display_name": display,
                        "used_bytes": used, "created_at": created.to_rfc3339(),
                    })
                })
                .collect();
            Ok(Json(serde_json::json!({ "items": rows })))
        }
        "domains" => {
            let domains: Vec<(Uuid, String, bool, Option<String>)> = sqlx::query_as(
                "SELECT id, name, is_enabled, catch_all_account_id::text \
                 FROM email8.domains WHERE env_id = $1 ORDER BY name",
            )
            .bind(env_id)
            .fetch_all(&mut *conn)
            .await
            .map_err(err_db)?;
            Ok(Json(serde_json::json!({
                "items": domains.into_iter().map(|(id, name, enabled, catch_all)| serde_json::json!({
                    "id": id, "name": name, "is_enabled": enabled, "catch_all": catch_all,
                })).collect::<Vec<_>>(),
            })))
        }
        "groups" => {
            let groups: Vec<(Uuid, String, Option<String>)> = sqlx::query_as(
                "SELECT id, address, description FROM email8.groups WHERE env_id = $1 ORDER BY address",
            )
            .bind(env_id)
            .fetch_all(&mut *conn)
            .await
            .map_err(err_db)?;
            Ok(Json(serde_json::json!({
                "items": groups.into_iter().map(|(id, address, description)| serde_json::json!({
                    "id": id, "address": address, "description": description,
                })).collect::<Vec<_>>(),
            })))
        }
        "quotas" => {
            let policy: Option<i64> = sqlx::query_scalar(
                "SELECT default_account_quota_bytes FROM email8.quota_policy WHERE env_id = $1",
            )
            .bind(env_id)
            .fetch_optional(&mut *conn)
            .await
            .map_err(err_db)?;
            Ok(Json(serde_json::json!({
                "default_account_quota_bytes": policy.unwrap_or(10_737_418_240),
            })))
        }
        other => Err((
            StatusCode::NOT_FOUND,
            format!("Unknown admin data page: {other}"),
        )),
    }
}

/// Alias so the router (typed on `AppState`) accepts the handler.
type StateHack = crate::data_api::AppState;

fn err_db(e: sqlx::Error) -> (StatusCode, String) {
    tracing::error!(error = %e, "email8:store: admin database error");
    (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
}
