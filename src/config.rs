// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Email8:Store
// SPDX-License-Identifier: Apache-2.0

//! Email8:Store configuration.

use sentin8::auth::client::{Client as AuthClient, ClientOptions};

#[derive(Debug, Clone)]
pub struct StoreConfig {
    pub port: u16,
    pub database_url: String,
    pub sentin8_bus_url: String,
    pub sentin8_storage_url: String,
    pub mta_url: String,
    pub sentin8_auth_client: AuthClient,
}

impl StoreConfig {
    pub fn from_env() -> Self {
        let cfg = sentin8::config::Sentin8Config::from_env();
        Self {
            port: env_u16("EMAIL8_STORE_PORT", 0),
            database_url: env_string("EMAIL8_STORE_DATABASE_URL")
                .or_else(|| env_string("DATABASE_URL"))
                .unwrap_or_else(|| {
                    sentin8::config::Sentin8Config::default_database_url().to_string()
                }),
            sentin8_bus_url: env_string("SENTIN8_BUS_URL").unwrap_or_else(|| cfg.sentin8_bus_url()),
            sentin8_storage_url: env_string("SENTIN8_STORAGE_URL")
                .unwrap_or_else(|| format!("https://{}", cfg.platform_domain("storage"))),
            mta_url: env_string("EMAIL8_MTA_URL")
                .unwrap_or_else(|| format!("https://{}", cfg.platform_domain("email8-mta"))),
            sentin8_auth_client: AuthClient::new(ClientOptions {
                base_url: env_string("SENTIN8_AUTH_ISSUER")
                    .unwrap_or_else(|| cfg.sentin8_auth_issuer()),
                ..Default::default()
            }),
        }
    }
}

impl Default for StoreConfig {
    fn default() -> Self {
        Self::from_env()
    }
}

fn env_string(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|s| !s.is_empty())
}

fn env_u16(key: &str, default: u16) -> u16 {
    std::env::var(key)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(default)
}
