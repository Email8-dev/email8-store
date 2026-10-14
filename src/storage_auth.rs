// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Email8:Store
// SPDX-License-Identifier: Apache-2.0

//! Storage client factory (design `sentin8-email8-technical-design.md`
//! "Service-to-service" row).
//!
//! Email8 services call Sentin8:Storage for message blobs. The client is
//! **certificate-presenting** (CERTFREE-4V): every call presents the
//! store's own Acme-issued workload certificate (`CN=m2m-email8:store`)
//! in the TLS handshake — Storage's TLS layer authenticates it and the
//! registry map authorizes the scopes. No M2M token exists on this path.

/// Build a certificate-presenting Storage client (the store's own
/// `email8:store` workload identity).
///
/// # Errors
/// Returns the certificate-ensure or transport-build failure.
pub async fn storage_client(
    _pool: &sqlx::PgPool,
    storage_url: &str,
    scopes: &[&str],
) -> anyhow::Result<sentin8_storage_sdk::client::StorageClient> {
    let _ = scopes; // the registry map carries the granted scopes (enroll)
    let issuer = std::env::var("SENTIN8_AUTH_ISSUER")
        .unwrap_or_else(|_| sentin8::config::Sentin8Config::from_env().sentin8_auth_issuer());
    let ca_cert_path = sentin8::auth::m2m::platform_ca_path();
    let cert =
        sentin8::auth::m2m::ensure_workload_certificate(&issuer, "email8:store", &ca_cert_path)
            .await?;
    sentin8_storage_sdk::client::StorageClient::with_workload_identity(
        storage_url,
        &cert.ca_cert_path,
        &cert.cert_path,
        &cert.key_path,
    )
    .map_err(|e| anyhow::anyhow!("email8:store: Storage mTLS transport: {e}"))
}
