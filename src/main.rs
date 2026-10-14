// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Email8:Store
// SPDX-License-Identifier: Apache-2.0

//! Sentin8 Email8:Store — mail/collaboration data core + JMAP API.
//!
//! See `email8/design/sentin8-email8-store-technical-design.md`.
//!
//! Boot runs on the platform `sentin8-shell` crate: registration flag, PQ
//! provider, config, capped pool, PG18 check, state binding, OpenAPI
//! merge, middleware stack and PQ-TLS listener are owned by the shell.
//! This binary supplies only its registration data, state and routes.

#[allow(dead_code)]
mod admin_data;
#[allow(dead_code)]
mod admin_ui;
#[allow(dead_code)]
mod auth;
#[allow(dead_code)]
mod config;
#[allow(dead_code)]
mod data_api;
#[allow(dead_code)]
mod event_consumer;
#[allow(dead_code)]
mod jmap;
#[allow(dead_code)]
mod jmap_objects;
mod openapi;
#[allow(dead_code)]
mod push_stream;
mod registration;
#[allow(dead_code)]
mod server;
#[allow(dead_code)]
mod storage_auth;
mod store_ops;

use utoipa::OpenApi;

/// mimalloc global allocator (design §6 D13) — all store-side workers
/// (JMAP push fan-out, event consumer) share this binary's allocator.
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    sentin8::shell::serve(
        sentin8::shell::Sentin8Shell::new("email8:store", "EMAIL8_STORE")
            .with_registration(registration::print)
            .with_state(server::build_state)
            .with_own_health()
            .with_router(|router, _state| server::routes(router))
            .with_openapi(openapi::StoreOpenApi::openapi()),
    )
    .await
}
