// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Email8:Store
// SPDX-License-Identifier: Apache-2.0

//! OpenAPI spec for Email8:Store - the internal data API surface (the JMAP
//! endpoint is a protocol surface, not OpenAPI-described).

use utoipa::OpenApi;

/// OpenAPI spec for the Email8:Store data + admin API.
#[derive(OpenApi)]
#[openapi(
    paths(
        sentin8::shell::policy_check_relation,
        sentin8::shell::policy_delete_attribute,
        sentin8::shell::policy_delete_relation,
        sentin8::shell::policy_delete_set,
        sentin8::shell::policy_get_set,
        sentin8::shell::policy_list_attributes,
        sentin8::shell::policy_list_relations,
        sentin8::shell::policy_list_sets,
        sentin8::shell::policy_mode_disable,
        sentin8::shell::policy_mode_enforce,
        sentin8::shell::policy_mode_shadow,
        sentin8::shell::policy_put_attribute,
        sentin8::shell::policy_put_relation,
        sentin8::shell::policy_put_set,
        sentin8::shell::policy_test_set,
        crate::admin_data::admin_data,
        crate::data_api::resolve_address,
        crate::data_api::ingest,
        crate::data_api::list_mailboxes,
        crate::data_api::create_mailbox,
        crate::data_api::changes_since,
        crate::data_api::submit,
        crate::data_api::blob_quota,
        crate::data_api::get_email,
        crate::data_api::list_mailbox_emails,
        crate::data_api::destroy_emails,
        crate::data_api::store_raw_blob,
        crate::data_api::set_email_keywords,
        crate::data_api::copy_emails,
        crate::data_api::ingest_append,
        crate::data_api::sieve_list,
        crate::data_api::sieve_get,
        crate::data_api::sieve_put,
        crate::data_api::sieve_set_active,
        crate::data_api::sieve_delete,
        crate::data_api::sieve_rename,
        crate::data_api::acl_grant,
        crate::data_api::acl_revoke,
        crate::data_api::acl_effective_rights,
        crate::jmap::session,
        crate::jmap::api,
        crate::jmap::upload,
        crate::jmap::download,
        crate::jmap::event_source,
        crate::jmap::jmap_ws,
        crate::admin_ui::get_admin_ui,
        crate::server::health,
    ),
    components(schemas(
        email8::contracts::IngestMessage,
        email8::contracts::IngestedEmail,
        email8::contracts::ResolveAddressRequest,
        email8::contracts::ResolvedAddress,
        email8::contracts::CreateMailboxRequest,
        email8::contracts::MailboxDto,
        email8::contracts::ChangesSinceRequest,
        email8::contracts::ChangesSinceResponse,
        email8::contracts::SubmitRequest,
        email8::contracts::SubmitResponse,
        email8::contracts::BlobQuotaCheck,
        email8::contracts::BlobQuotaVerdict,
    )),
    security(),
    tags(
        (name = "policy", description = "Shield policy administration (shared surface)"),
        (name = "email8-store", description = "Sentin8 Email8:Store - mail data core + JMAP API"),
    ),
)]pub struct StoreOpenApi;
