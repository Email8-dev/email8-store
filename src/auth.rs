// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Email8:Store
// SPDX-License-Identifier: Apache-2.0

//! Auth token verification + mail-account resolution for Email8:Store.
//!
//! Verifies the Sentin8:Auth bearer token, resolves the tenant context
//! (`env_id`), and binds the caller's Sentin8:Auth user `sub` to the
//! `principals` row — the "has mail in this env" mapping
//! (integration design §4). The resolved `MailAuth` is what handlers
//! thread into RLS context setters (`app.account_id`).

use axum::http::{HeaderMap, StatusCode};
use uuid::Uuid;

use sentin8::auth::client::AuthContext;
use sqlx::PgConnection;

use crate::config::StoreConfig;

/// The authenticated mail context: the platform AuthContext plus the
/// resolved Email8 principal id for the caller's user.
#[derive(Debug, Clone)]
pub struct MailAuth {
    pub auth: AuthContext,
    /// `principals.id` for (env_id, auth sub). 0 = none (the user
    /// has no mailbox in this env yet).
    pub account_id: Uuid,
}

impl MailAuth {
    pub fn env_id(&self) -> Uuid {
        self.auth.env_id()
    }

    /// The Sentin8:Auth user id (token `sub`) parsed as a UUID.
    pub fn user_sub(&self) -> Option<Uuid> {
        Uuid::parse_str(self.auth.sub()).ok()
    }
}

/// Verify the bearer token and make the step-5 Sentin8:Policy decision
/// for the primary action. The scope list is gone — the Shield scope-mirror
/// set seeded by `vertical enroll` (registration.rs) IS the authorization
/// (policy design §4.3: step 5 is THE decision; no post-verify JWT scope
/// check remains). The mail-account binding is deferred to [`bind_account`]
/// — it needs a tenant-context connection (the principals table is
/// RLS-protected).
///
/// CERTIFICATE-FIRST (CERTFREE-4V, auth DESIGN §4.3f): when the TLS
/// handshake presented an enrolled platform-workload certificate (the
/// internal email8 callers — access/mta), the resolved identity is the
/// authentication and the scope check runs against the registry map row;
/// otherwise the request falls through to the bearer path (user/delegated
/// JWT flows unchanged).
pub async fn require_mail_auth(
    config: &StoreConfig,
    workload_registry: &sentin8::auth::workload_registry::WorkloadMap,
    engine: &sentin8::shield::PolicyEngine,
    headers: &HeaderMap,
    action: &str,
) -> Result<MailAuth, (StatusCode, String)> {
    if let Some(auth) = require_workload_auth(workload_registry, engine, headers, action).await? {
        return Ok(auth);
    }
    let auth =
        sentin8::auth::client::verify_bearer_token(&config.sentin8_auth_client, headers).await?;
    sentin8::shell::policy::require(
        engine,
        &auth,
        headers,
        sentin8::shield::EvalTarget::new(action),
    )
    .await?;
    if Uuid::parse_str(auth.sub()).is_err() {
        return Err((
            StatusCode::UNAUTHORIZED,
            "token subject is not a user id".into(),
        ));
    }
    Ok(MailAuth {
        auth,
        account_id: Uuid::nil(),
    })
}

/// The certificate path of [`require_mail_auth`]: resolve the presented
/// workload certificate against the boot-loaded registry map (the
/// authorization record — scopes + enabled), run the same step-5 policy
/// decision, and build the mail context WITHOUT a user binding (the
/// internal callers carry the account ids in their request bodies —
/// `bind_account` is a user-flow concept).
///
/// # Errors
/// Returns the rejection (status + message) for an unenrolled/disabled
/// workload or a failed policy decision; `Ok(None)` when no client
/// certificate was presented (the caller falls through to bearer).
async fn require_workload_auth(
    workload_registry: &sentin8::auth::workload_registry::WorkloadMap,
    engine: &sentin8::shield::PolicyEngine,
    headers: &HeaderMap,
    action: &str,
) -> Result<Option<MailAuth>, (StatusCode, String)> {
    let Some(identity) =
        sentin8::auth::client::resolve_workload_identity(workload_registry, headers).await?
    else {
        return Ok(None); // no client certificate presented → bearer path
    };
    let auth = sentin8::auth::client::AuthContext::from_workload(
        identity,
        sentin8::middleware::context::TLSContext::from_headers(headers).env_id,
    );
    sentin8::shell::policy::require(
        engine,
        &auth,
        headers,
        sentin8::shield::EvalTarget::new(action),
    )
    .await?;
    Ok(Some(MailAuth {
        auth,
        account_id: Uuid::nil(),
    }))
}

/// Complete the account binding on a connection that already has the
/// standard tenant context set. Returns the (possibly zero) principal id.
pub async fn bind_account(
    conn: &mut PgConnection,
    mail: &MailAuth,
) -> Result<Uuid, (StatusCode, String)> {
    let sub = mail.user_sub().ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            "token subject is not a user id".into(),
        )
    })?;
    let row: Option<(Uuid,)> = sqlx::query_as(
        "SELECT id FROM email8.principals WHERE env_id = $1 AND sentin8_auth_user_id = $2",
    )
    .bind(mail.env_id())
    .bind(sub)
    .fetch_optional(conn)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(row.map(|r| r.0).unwrap_or(Uuid::nil()))
}

/// Set the extended tenant context including the mail account binding.
///
/// Runs `SELECT sentin8_set_tenant_context($1)` (transaction-local) and
/// then binds `app.account_id` for the holder-scoped RLS policies. MUST
/// be awaited on the same connection as the data query (§4.3d).
pub async fn set_mail_tenant_context(conn: &mut PgConnection, env_id: Uuid, account_id: Uuid) {
    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(env_id)
        .execute(&mut *conn)
        .await;
    let _ = sqlx::query("SELECT set_config('app.account_id', $1::text, true)")
        .bind(account_id.to_string())
        .execute(&mut *conn)
        .await;
}
