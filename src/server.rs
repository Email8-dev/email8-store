// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Email8:Store
// SPDX-License-Identifier: Apache-2.0

//! Axum server setup for Email8:Store.

use std::sync::Arc;

use axum::routing::{get, post};

use crate::config::StoreConfig;
use crate::data_api::{self, AppState};

pub async fn build_state(core: sentin8::shell::ServiceCore) -> anyhow::Result<AppState> {
    let config = StoreConfig::from_env();
    let core = std::sync::Arc::new(core);
    let mut state = AppState {
        config: Arc::new(config),
        pool: core.pool.clone(),
        core,
        workload_registry: sentin8::auth::workload_registry::WorkloadMap::boot_load_empty(
            "email8:store",
        ),
    };

    // Sentin8:Policy (Phase 28, §4.2b — shell-owned boot): the shell's
    // boot step 8 already booted the engine (refuse-to-start, shared deps,
    // hot-reload consumer, stat emitter). Services only consume it. The
    // engine published into `core.admin` is the SAME instance the step-5
    // gate evaluates.

    // Cert-presenting Bus client (CERTFREE-4V): the `email8:store`
    // workload certificate IS the identity — no DCR, no token (auth
    // DESIGN §4.3f). Fail-soft: an unreachable Acme at first boot
    // disables the consumer this boot; the next boot retries.
    let issuer = std::env::var("SENTIN8_AUTH_ISSUER")
        .unwrap_or_else(|_| sentin8::config::Sentin8Config::from_env().sentin8_auth_issuer());
    let bus_client = sentin8::bus::client::BusClient::for_workload(
        &state.config.sentin8_bus_url,
        &issuer,
        "email8:store",
    )
    .await;

    // Provisioning consumer: reacts to `sentin8:auth:user:created` events
    // and bootstraps principals + mailboxes (integration design §4).
    if let Ok(bc) = &bus_client {
        crate::event_consumer::spawn(state.core.pool.clone(), bc.clone());
    } else {
        tracing::warn!(error = ?bus_client.err(), "email8:store: bus certificate not ready — provisioning consumer disabled this boot");
    }

    // Cert-identity authorization record for the internal data API
    // (auth DESIGN §4.3f): boot-load the workload registry map the
    // cert-first gate resolves against. Fail-open-with-warning on an
    // unreachable Valkey at boot — the bearer path (user/delegated)
    // serves while certificate-workload calls fail-closed until the
    // next boot (the map is normally published by enroll BEFORE
    // services start). The load presents THIS service's certificate
    // identity over the Valkey TLS plane (group DESIGN.md §3.1).
    let workload_registry = match sentin8::auth::workload_registry::WorkloadMap::boot_load(
        "email8:store",
    )
    .await
    {
        Ok(map) => map,
        Err(e) => {
            tracing::warn!(error = %e, "email8:store: workload registry map unavailable at boot — certificate-workload calls fail-closed until next boot");
            sentin8::auth::workload_registry::WorkloadMap::boot_load_empty("email8:store")
        }
    };
    state.workload_registry = workload_registry;

    Ok(state)
}

pub fn routes(router: axum::Router<AppState>) -> axum::Router<AppState> {
    router
        .route("/v1/health", get(health))
        // JMAP public surface
        .route("/jmap", post(crate::jmap::api))
        .route("/jmap/session", get(crate::jmap::session))
        .route(
            "/jmap/download/{account_id}/{blob_id}/{name}",
            get(crate::jmap::download),
        )
        .route("/jmap/upload/{account_id}", post(crate::jmap::upload))
        .route("/jmap/eventsource", get(crate::jmap::event_source))
        .route("/jmap/ws", get(crate::jmap::jmap_ws))
        // Internal data API (M2M between vertical services)
        .route("/v1/internal/resolve", post(data_api::resolve_address))
        .route("/v1/internal/ingest", post(data_api::ingest))
        .route(
            "/v1/internal/mailboxes",
            post(data_api::create_mailbox).get(data_api::list_mailboxes),
        )
        .route(
            "/v1/internal/mailbox/emails",
            get(data_api::list_mailbox_emails),
        )
        .route("/v1/internal/changes", post(data_api::changes_since))
        .route("/v1/internal/submit", post(data_api::submit))
        .route("/v1/internal/blob-quota", post(data_api::blob_quota))
        .route(
            "/v1/internal/emails/destroy",
            post(data_api::destroy_emails),
        )
        .route("/v1/internal/email/store", post(data_api::store_raw_blob))
        .route(
            "/v1/internal/email/keywords",
            post(data_api::set_email_keywords),
        )
        .route("/v1/internal/emails/copy", post(data_api::copy_emails))
        .route("/v1/internal/ingest/append", post(data_api::ingest_append))
        .route("/v1/internal/acl/grant", post(data_api::acl_grant))
        .route("/v1/internal/acl/revoke", post(data_api::acl_revoke))
        .route(
            "/v1/internal/acl/rights",
            get(data_api::acl_effective_rights),
        )
        .route(
            "/v1/internal/email/{env_id}/{account_id}/{email_id}",
            get(data_api::get_email),
        )
        // Sieve script CRUD (RFC 5804 backing store).
        .route("/v1/internal/sieve/list", post(data_api::sieve_list))
        .route("/v1/internal/sieve/get", post(data_api::sieve_get))
        .route("/v1/internal/sieve/put", post(data_api::sieve_put))
        .route(
            "/v1/internal/sieve/setactive",
            post(data_api::sieve_set_active),
        )
        .route("/v1/internal/sieve/delete", post(data_api::sieve_delete))
        .route("/v1/internal/sieve/rename", post(data_api::sieve_rename))
        // Admin API + RFW pages
        .route(
            "/v1/admin/{*page}",
            post(crate::admin_data::admin_data).get(crate::admin_ui::get_admin_ui),
        )
        // ── Sentin8:Policy admin API (Phase 28 §3.6 — shared
        // implementation; handlers generic over this state via
        // HasPolicyAdmin).
        .route(
            "/v1/admin/policy-sets",
            get(sentin8::shield::admin::list_policy_sets::<AppState>),
        )
        .route(
            "/v1/admin/policy-sets/{name}",
            get(sentin8::shield::admin::get_policy_set::<AppState>)
                .put(sentin8::shield::admin::put_policy_set::<AppState>)
                .delete(sentin8::shield::admin::delete_policy_set::<AppState>),
        )
        .route(
            "/v1/admin/policy-sets/{name}/test",
            post(sentin8::shield::admin::test_policy_set::<AppState>),
        )
        .route(
            "/v1/admin/policy-sets/enforce",
            post(sentin8::shield::admin::admin_enforce_policy_set::<AppState>),
        )
        .route(
            "/v1/admin/policy-sets/shadow",
            post(sentin8::shield::admin::admin_shadow_policy_set::<AppState>),
        )
        .route(
            "/v1/admin/policy-sets/disable",
            post(sentin8::shield::admin::admin_disable_policy_set::<AppState>),
        )
        .route(
            "/v1/admin/relations",
            get(sentin8::shield::admin::list_relations::<AppState>)
                .put(sentin8::shield::admin::put_relation::<AppState>)
                .delete(sentin8::shield::admin::delete_relation::<AppState>),
        )
        .route(
            "/v1/admin/relations/check",
            get(sentin8::shield::admin::check_relation::<AppState>),
        )
        .route(
            "/v1/admin/attributes",
            get(sentin8::shield::admin::list_attributes::<AppState>)
                .put(sentin8::shield::admin::put_attribute::<AppState>)
                .delete(sentin8::shield::admin::delete_attribute::<AppState>),
        )
}

#[utoipa::path(
    get,
    path = "/v1/health",
    responses(
        (status = 200, description = "Liveness (version, build)"),
    ),
    security(),
    tag = "store",
)]
pub async fn health() -> impl axum::response::IntoResponse {
    axum::Json(serde_json::json!({
        "status": "ok",
        "service": "email8:store",
        "version": sentin8::build_info::id(),
            "build": sentin8::build_info::build_hash(),
    }))
}
/// Shared policy-admin surface accessor (Phase 28 §3.6): the boot
/// loaded the engine into `core.admin`; the shared handlers extract it
/// via `HasPolicyAdmin` so the admin surface and the request path
/// evaluate the SAME cache.
impl sentin8::shield::admin::HasPolicyAdmin for AppState {
    fn policy_admin(&self) -> &sentin8::shield::admin::SharedAdminState {
        &self.core.admin
    }
}
