// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Email8:Store
// SPDX-License-Identifier: Apache-2.0

//! Service self-registration data for Email8:Store.
//!
//! Output via `--print-registration` flag. See
//! `sentin8/design/sentin8-service-self-registration-design.md`.

use sentin8::registration::{
    AdminScope, AdminUi, AdminUiPage, ErrorCode, M2mGrant, PgRole, Registration, SqlMigration,
    PolicySetDecl, RelationDecl,
};
#[cfg(not(test))]
use utoipa::OpenApi;


/// The Shield text of the declared scope-mirror set — public so the
/// policy wiring tests (POLICY-7) assert against the REAL seed.
pub const SCOPE_MIRROR_POLICIES: &str = "permit(principal, action == Action::\"email8:mail:read\", resource) when { principal.scopes.contains(\"email8:mail:read\") };
permit(principal, action == Action::\"email8:mail:read\", resource) when { principal.scopes.contains(\"email8:mail:write\") };
permit(principal, action == Action::\"email8:mail:read\", resource) when { principal.scopes.contains(\"email8:admin:users\") };
permit(principal, action == Action::\"email8:mail:read\", resource) when { principal.scopes.contains(\"email8:admin:domains\") };
permit(principal, action == Action::\"email8:mail:read\", resource) when { principal.scopes.contains(\"email8:admin:groups\") };
permit(principal, action == Action::\"email8:mail:read\", resource) when { principal.scopes.contains(\"email8:admin:quotas\") };
permit(principal, action == Action::\"email8:mail:read\", resource) when { principal.scopes.contains(\"email8:admin:queue\") };
permit(principal, action == Action::\"email8:mail:read\", resource) when { principal.scopes.contains(\"email8:admin:reports\") };
permit(principal, action == Action::\"email8:mail:read\", resource) when { principal.scopes.contains(\"email8:admin:spam\") };
permit(principal, action == Action::\"email8:mail:read\", resource) when { principal.scopes.contains(\"sentin8:sys:admin\") };
permit(principal, action == Action::\"email8:mail:read\", resource) when { principal.scopes.contains(\"sentin8:sys:org:admin\") };
permit(principal, action == Action::\"email8:mail:read\", resource) when { principal.scopes.contains(\"sentin8:sys:env:admin\") };
permit(principal, action == Action::\"email8:mail:write\", resource) when { principal.scopes.contains(\"email8:mail:write\") };
permit(principal, action == Action::\"email8:mail:write\", resource) when { principal.scopes.contains(\"email8:mail:receive\") };
permit(principal, action == Action::\"email8:mail:write\", resource) when { principal.scopes.contains(\"email8:admin:users\") };
permit(principal, action == Action::\"email8:mail:write\", resource) when { principal.scopes.contains(\"email8:admin:domains\") };
permit(principal, action == Action::\"email8:mail:write\", resource) when { principal.scopes.contains(\"email8:admin:groups\") };
permit(principal, action == Action::\"email8:mail:write\", resource) when { principal.scopes.contains(\"email8:admin:quotas\") };
permit(principal, action == Action::\"email8:mail:write\", resource) when { principal.scopes.contains(\"email8:admin:queue\") };
permit(principal, action == Action::\"email8:mail:write\", resource) when { principal.scopes.contains(\"email8:admin:reports\") };
permit(principal, action == Action::\"email8:mail:write\", resource) when { principal.scopes.contains(\"email8:admin:spam\") };
permit(principal, action == Action::\"email8:mail:write\", resource) when { principal.scopes.contains(\"sentin8:sys:admin\") };
permit(principal, action == Action::\"email8:mail:write\", resource) when { principal.scopes.contains(\"sentin8:sys:org:admin\") };
permit(principal, action == Action::\"email8:mail:write\", resource) when { principal.scopes.contains(\"sentin8:sys:env:admin\") };
permit(principal, action == Action::\"email8:sieve:manage\", resource) when { principal.scopes.contains(\"email8:sieve:manage\") };
permit(principal, action == Action::\"email8:sieve:manage\", resource) when { principal.scopes.contains(\"email8:admin:scripts\") };
permit(principal, action == Action::\"email8:sieve:manage\", resource) when { principal.scopes.contains(\"sentin8:sys:admin\") };
permit(principal, action == Action::\"email8:sieve:manage\", resource) when { principal.scopes.contains(\"sentin8:sys:org:admin\") };
permit(principal, action == Action::\"email8:sieve:manage\", resource) when { principal.scopes.contains(\"sentin8:sys:env:admin\") };
permit(principal, action == Action::\"email8:submission:send\", resource) when { principal.scopes.contains(\"email8:submission:send\") };
permit(principal, action == Action::\"email8:submission:send\", resource) when { principal.scopes.contains(\"email8:mail:receive\") };
permit(principal, action == Action::\"email8:submission:send\", resource) when { principal.scopes.contains(\"sentin8:sys:admin\") };
permit(principal, action == Action::\"email8:submission:send\", resource) when { principal.scopes.contains(\"sentin8:sys:org:admin\") };
permit(principal, action == Action::\"email8:submission:send\", resource) when { principal.scopes.contains(\"sentin8:sys:env:admin\") };";

/// Default declarative policy set (Sentin8:Policy design §3.2/§3.4,
/// seeded by `vertical enroll` as `origin='platform'`, `mode='enforced'`):
/// action-granular scope permits over the LIVE effective scope set — the
/// exact mirror of the gates this service's handlers evaluate in step 5
/// (policy design §4.3). Enforced (decision 2026-09-07): step 5 is the
/// only gate; shadow is the emergency one-UPDATE rollback lever only.
const POLICIES: &[PolicySetDecl] = &[PolicySetDecl {
    policy_set_name: "scope-mirror",
    description: "Action-granular scope permits for email8:store over the LIVE effective scope set (policy design §3.1d). Enforced (decision 2026-09-07) — step 5 is the only gate.",
    // Shield text lives in SCOPE_MIRROR_POLICIES (single source).
    policies: SCOPE_MIRROR_POLICIES,
    schema: None,
    mode: "enforced",
    default_enabled: true,
}];

/// Default ReBAC relation tuples (design §3.1c) — none declared by this
/// service today; env admins author their own graph (delegate /
/// shared-mailbox edges) via the relations admin API.
const RELATIONS: &[RelationDecl] = &[];

/// M2M workload declarations (CERTFREE-4V): the `email8:store` workload
/// row drives `vertical enroll`'s Valkey ACL-user provisioning (the CN
/// `m2m-email8:store` maps to the ACL user of the same name — group
/// DESIGN.md §3.1) and carries the scopes the internal data-API
/// cert gate checks for the access/mta callers, plus the bus scopes
/// for the provisioning consumer.
const M2M_GRANTS: &[M2mGrant] = &[M2mGrant {
    workload: "email8:store",
    scopes: &[
        "email8:mail:read",
        "email8:mail:write",
        "email8:mail:receive",
        "sentin8:bus:consume",
    ],
}, M2mGrant {
    // Shield hot-reload consumer (BUSPOLICY-1 — see email8-access).
    workload: "email8:store-policy",
    scopes: &["sentin8:bus:consume", "sentin8:stat:measure"],
}];

const PG_ROLES: &[PgRole] = &[PgRole {
    scope: "email8:mail:read,email8:mail:write,email8:groupware:read,email8:groupware:write",
    role: "email8_store_service",
    bypass_rls: false,
    database: "email8",
    cross_schema_grants: &[],
}];

const ADMIN_SCOPES: &[AdminScope] = &[
    AdminScope::Typed { role: "email8:admin", scope: "email8:admin:users" },
    AdminScope::Typed { role: "email8:admin", scope: "email8:admin:domains" },
    AdminScope::Typed { role: "email8:admin", scope: "email8:admin:groups" },
    AdminScope::Typed { role: "email8:admin", scope: "email8:admin:quotas" },
    AdminScope::Typed { role: "email8:admin", scope: "email8:admin:scripts" },
    // User-facing scopes (granted to mail users by default roles).
    AdminScope::Typed { role: "email8:user", scope: "email8:mail:read" },
    AdminScope::Typed { role: "email8:user", scope: "email8:mail:write" },
    AdminScope::Typed { role: "email8:user", scope: "email8:mail:receive" },
    AdminScope::Typed { role: "email8:user", scope: "email8:submission:send" },
    AdminScope::Typed { role: "email8:user", scope: "email8:sieve:manage" },
    AdminScope::Typed { role: "email8:user", scope: "email8:calendar:write" },
    AdminScope::Typed { role: "email8:user", scope: "email8:contacts:write" },
    AdminScope::Typed { role: "email8:user", scope: "email8:files:write" },
    AdminScope::Typed { role: "email8:user", scope: "email8:push:manage" },
    // Policy-admin surface (policy design §3.6; principles §6.0b per-service scope).
    AdminScope::Typed { role: "email8:store:admin", scope: "email8:store:policy:read" },
    AdminScope::Typed { role: "email8:store:admin", scope: "email8:store:policy:write" },
];

const ERROR_CODES: &[ErrorCode] = &[
    ErrorCode { enum_name: "Email8MailboxNotFound", error_code: "email8_mailbox_not_found", status_code: 404 },
    ErrorCode { enum_name: "Email8EmailNotFound", error_code: "email8_email_not_found", status_code: 404 },
    ErrorCode { enum_name: "Email8QuotaExceeded", error_code: "email8_quota_exceeded", status_code: 402 },
    ErrorCode { enum_name: "Email8BlobQuotaExceeded", error_code: "email8_blob_quota_exceeded", status_code: 402 },
    ErrorCode { enum_name: "Email8RcptNotFound", error_code: "email8_rcpt_not_found", status_code: 404 },
    ErrorCode { enum_name: "Email8RelayDenied", error_code: "email8_relay_denied", status_code: 403 },
    ErrorCode { enum_name: "Email8SenderAddressRejected", error_code: "email8_sender_address_rejected", status_code: 403 },
    ErrorCode { enum_name: "Email8Greylisted", error_code: "email8_greylisted", status_code: 429 },
    ErrorCode { enum_name: "Email8ThreadNotFound", error_code: "email8_thread_not_found", status_code: 404 },
    ErrorCode { enum_name: "Email8IdentityNotFound", error_code: "email8_identity_not_found", status_code: 404 },
    ErrorCode { enum_name: "Email8DomainNotFound", error_code: "email8_domain_not_found", status_code: 404 },
    ErrorCode { enum_name: "Email8DuplicateDocument", error_code: "email8_duplicate_document", status_code: 400 },
];

const ADMIN_UI_PAGES: &[AdminUiPage] = &[
    AdminUiPage { route: "overview", label: "Overview", ui_endpoint: "/v1/admin/ui/overview", data_endpoint: "/v1/admin/overview", icon: "0xe1b1" },
    AdminUiPage { route: "users", label: "Mail Users", ui_endpoint: "/v1/admin/ui/users", data_endpoint: "/v1/admin/users", icon: "0xe7fd" },
    AdminUiPage { route: "domains", label: "Domains", ui_endpoint: "/v1/admin/ui/domains", data_endpoint: "/v1/admin/domains", icon: "0xe157" },
    AdminUiPage { route: "groups", label: "Mailing Lists", ui_endpoint: "/v1/admin/ui/groups", data_endpoint: "/v1/admin/groups", icon: "0xe8af" },
    AdminUiPage { route: "quotas", label: "Quotas", ui_endpoint: "/v1/admin/ui/quotas", data_endpoint: "/v1/admin/quotas", icon: "0xe263" },
];

const SQL_1_INIT: &str = include_str!("../sql/init.sql");

fn openapi_spec() -> serde_json::Value {

    // Portable stub when #[path]-included from tests (POLICY-7): the real
    // derive lives in the crate's openapi module, which tests don't link.
    #[cfg(not(test))]
    { return serde_json::to_value(crate::openapi::StoreOpenApi::openapi()).unwrap_or(serde_json::Value::Null); }
    #[cfg(test)]
    return serde_json::Value::Null;
}

/// Print the registration JSON to stdout.
pub fn print(section: Option<String>) -> anyhow::Result<()> {
    let reg = Registration {
        service_type: "email8:store",
        subdomain: "email8-store",
        health_path: "/v1/health",
        admin_scopes: ADMIN_SCOPES,
        error_codes: ERROR_CODES,
        consent_providers: &[],
        consent_flows: &[],
        admin_ui: Some(AdminUi {
            label: "Email",
            icon: "0xe158",
            service_flag: "email8",
            pages: ADMIN_UI_PAGES,
        }),
        sql_migrations: vec![SqlMigration { version: 1, name: "init", sql: SQL_1_INIT }],
        audit_findings: None,
        service_actions: None,
        m2m_grants: Some(M2M_GRANTS),
        pg_roles: PG_ROLES,
        openapi_url: "/openapi.json",
        openapi: openapi_spec,
        policies: POLICIES,
        relations: RELATIONS,
        event_triggers: &[],
        schedules: &[],
    };
    sentin8::registration::print_registration(section, &reg, openapi_spec)
}