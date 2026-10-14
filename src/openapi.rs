// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Email8:Store
// SPDX-License-Identifier: Apache-2.0

//! OpenAPI spec for Email8:Store — the internal data API surface (the JMAP
//! endpoint is a protocol surface, not OpenAPI-described).

use utoipa::OpenApi;

/// OpenAPI spec for the Email8:Store data + admin API.
#[derive(OpenApi)]
#[openapi(
    paths(
        crate::admin_data::admin_data,
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
        (name = "email8-store", description = "Sentin8 Email8:Store — mail data core + JMAP API"),
    ),
)]
pub struct StoreOpenApi;