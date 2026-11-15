// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Email8:Store
// SPDX-License-Identifier: Apache-2.0

//! Sentin8:Bus consumer - reacts to `sentin8:auth:user:created` events
//! and provisions Email8 principals + bootstrap mailboxes (the
//! event-driven env-init pattern; integration design §4).
//!
//! BUSENV-1 (the env-declaration contract): auth publishes
//! `sentin8:auth:user:created` to the SIGN-UP ENV's stream
//! (`bus:{env_id}:{family}`) - the SYSTEM-env stream only carries
//! system-env users (platform operator sign-ups). A consumer using the
//! legacy SYSTEM form (`sse_consume(family, group)`) NEVER sees
//! tenant-env sign-ups. This provisioner keeps ONE declared-env
//! consumer per known tenant env (the `email8.domains` registry -
//! re-discovered every reconnect so fresh tenants join without a
//! restart).

use std::collections::BTreeSet;
use std::time::Duration;

use futures_util::StreamExt;
use sqlx::PgPool;
use uuid::Uuid;

const CONSUMER_GROUP: &str = "email8:store:provisioner";
/// Stream family Sentin8:Auth emits to (auth/src/events.rs) - the
/// provisioner must subscribe here to see `sentin8:auth:user:created`.
const EVENT_STREAM_FAMILY: &str = "auth";
const RECONNECT_DELAY: Duration = Duration::from_secs(2);

/// Spawn the Bus consumer background task (the per-env fan-out lives in
/// `run` - each known tenant env gets its own declared-env consumer).
pub fn spawn(
    pool: PgPool,
    bus_client: sentin8::bus::client::BusClient,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        run(pool, bus_client).await;
    })
}

/// The tenant envs worth provisioning for - one consumer per env. The
/// `email8.domains` catalog is the mail-plane's own env registry
/// (env-scoped, NO-RLS on purpose: the pre-tenant discovery surface).
async fn discover_envs(pool: &PgPool) -> BTreeSet<Uuid> {
    sqlx::query_scalar("SELECT DISTINCT env_id FROM email8.domains WHERE is_enabled")
        .fetch_all(pool)
        .await
        .unwrap_or_default()
        .into_iter()
        .collect()
}

async fn run(pool: PgPool, bus_client: sentin8::bus::client::BusClient) {
    tracing::info!("email8:store: provisioning consumer started (group={CONSUMER_GROUP}, family={EVENT_STREAM_FAMILY}, per-env declared streams)");
    // The re-discovery cadence: the SSE consumers are long-lived, so a
    // fresh tenant (new mail domain) would NEVER join mid-stream - the
    // discovery set is re-polled and new envs attach without tearing
    // down the existing consumers. 2s: a freshly-registered tenant's
    // sign-up flow must not race a long discovery window.
    const DISCOVER_TICK: Duration = Duration::from_secs(2);
    let mut current: BTreeSet<Uuid> = BTreeSet::new();
    // Persistent task set: consumers stay attached across discovery
    // ticks (an abort would drop a healthy stream).
    let mut tasks: tokio::task::JoinSet<()> = tokio::task::JoinSet::new();
    loop {
        let envs = discover_envs(&pool).await;
        if envs.is_empty() {
            tracing::info!("email8:store: no mail domains registered - no tenant streams to consume");
            tokio::time::sleep(RECONNECT_DELAY).await;
            continue;
        }
        // Spawn consumers for NEWLY discovered envs; existing consumers
        // keep running in the same JoinSet.
        for env_id in envs.difference(&current).copied().collect::<Vec<_>>() {
            tracing::info!(%env_id, "email8:store: attaching provisioning consumer for env");
            tasks.spawn(env_consumer(
                pool.clone(),
                bus_client.clone(),
                env_id,
            ));
        }
        current = envs;
        // A discovery tick OR any consumer exit wakes the loop; the
        // JoinSet is NOT aborted here (a tick must not kill healthy
        // streams) - only a finished/exited task is reaped.
        tokio::select! {
            _ = tokio::time::sleep(DISCOVER_TICK) => {}
            Some(_) = tasks.join_next() => {
                tracing::info!("email8:store: a provisioning stream ended - it will re-attach on the next discovery tick");
            }
        }
    }
}

/// One declared-env SSE consumer: `sse_consume_env` resolves the
/// `bus:{env_id}:{family}` stream key, and the ack/nack carry the SAME
/// env declaration (an undeclared ack writes the SYSTEM-env group -
/// BUSENV-1: the entry would pend forever).
async fn env_consumer(
    pool: PgPool,
    bus_client: sentin8::bus::client::BusClient,
    env_id: Uuid,
) {
    match bus_client
        .sse_consume_env(EVENT_STREAM_FAMILY, CONSUMER_GROUP, Some(env_id))
        .await
    {
        Ok(resp) => {
            tracing::info!(%env_id, "email8:store: bus SSE connected to stream family '{EVENT_STREAM_FAMILY}'");
            sse_loop(&pool, &bus_client, resp, env_id).await;
            tracing::info!(%env_id, "email8:store: bus SSE disconnected");
        }
        Err(e) => {
            tracing::warn!(error = %e, %env_id, "email8:store: bus consume failed");
        }
    }
}

async fn sse_loop(
    pool: &PgPool,
    bus_client: &sentin8::bus::client::BusClient,
    resp: reqwest::Response,
    env_id: Uuid,
) {
    let mut stream = resp.bytes_stream();
    let mut buffer = String::new();

    while let Some(chunk_result) = stream.next().await {
        let chunk = match chunk_result {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(error = %e, "email8:store: bus SSE stream error");
                return;
            }
        };
        buffer.push_str(&String::from_utf8_lossy(&chunk));

        while let Some(blank_pos) = buffer.find("\n\n") {
            let event_str = buffer[..blank_pos].to_string();
            buffer.drain(..blank_pos + 2);

            // The Bus SSE payload is the serialized `ConsumeMessage`
            // (bus/src/sse.rs): id/message_id, env_id, event_type, data
            // fields. Parse the JSON directly - axum's SSE frames carry
            // only `id:`/`data:` (no `event:` line).
            let msg: serde_json::Value = match serde_json::from_str(
                event_str
                    .lines()
                    .find_map(|l| l.strip_prefix("data:"))
                    .unwrap_or_default()
                    .trim(),
            ) {
                Ok(v) => v,
                Err(_) => continue,
            };
            let event_type = match msg.get("event_type").and_then(|v| v.as_str()) {
                Some(t) => t.to_string(),
                None => continue,
            };
            // env_id + message_id live on the ConsumeMessage (stream
            // fields), not inside the event payload - auth's
            // `sentin8:auth:user:created` payload only carries
            // {email, user_id}.
            let msg_env_id = msg
                .get("env_id")
                .and_then(|v| v.as_str())
                .and_then(|s| uuid::Uuid::parse_str(s).ok());
            let message_id = msg
                .get("message_id")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            let data = match msg.get("payload") {
                Some(p) if !p.is_null() => p.to_string(),
                _ => continue,
            };
            if event_type.is_empty() || data.is_empty() {
                continue;
            }

            if let Err(e) = handle_event(pool, &event_type, &data, msg_env_id.or(Some(env_id))).await {
                tracing::warn!(error = %e, %event_type, "email8:store: event handling failed");
                // NACK for redelivery. NOTE: the SDK's nack has no env
                // variant (BUSENV-1 covered consume/ack) - the plain form
                // is the platform surface; a wrongly-env'd nack leaves
                // the entry to the XAUTOCLAIM sweep (60s redelivery),
                // so the at-least-once guarantee holds either way.
                let _ = bus_client
                    .nack(EVENT_STREAM_FAMILY, CONSUMER_GROUP, &message_id, Some(30))
                    .await;
            } else if !message_id.is_empty() {
                // ACK on success with the SAME env declaration the
                // consumer holds (BUSENV-1): an undeclared ack XACKs the
                // SYSTEM-env stream key and the real entry pends forever
                // (the XAUTOCLAIM sweep redelivers every 60s).
                let _ = bus_client
                    .ack_env(EVENT_STREAM_FAMILY, CONSUMER_GROUP, &message_id, Some(env_id))
                    .await;
            }
        }
    }
}

/// Dispatch one bus event. Provisioning keys off
/// `sentin8:auth:user:created`. `env_id` comes from the ConsumeMessage
/// (the stream the event was published to), not the payload.
async fn handle_event(
    pool: &PgPool,
    event_type: &str,
    data: &str,
    env_id: Option<uuid::Uuid>,
) -> anyhow::Result<()> {
    if event_type != "sentin8:auth:user:created" {
        return Ok(());
    }
    let payload: serde_json::Value = serde_json::from_str(data).unwrap_or_default();
    let Some(env_id) = env_id else {
        return Ok(());
    };
    let Some(auth_sub) = payload
        .get("user_id")
        .or_else(|| payload.get("sub"))
        .and_then(|v| v.as_str())
        .and_then(|s| uuid::Uuid::parse_str(s).ok())
    else {
        return Ok(());
    };
    let email = payload
        .get("email")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    let display = payload
        .get("display_name")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    if email.is_empty() {
        return Ok(()); // no address - nothing to provision for mail
    }

    // the tenant context is transaction-local
    // (`set_config(..., true)`) - on an autocommit connection it
    // evaporates before the next statement and RLS rejects the insert
    // (design §1.1 defect 2). Stamp + provision share ONE explicit
    // transaction on ONE connection (§4.3d). `p_subject_id` is TEXT -
    // bind the sub as its string form.
    let mut tx = pool.begin().await?;
    let _ = sqlx::query(
        // The CURRENT contract (public_helpers.sql): the 8th param is
        // `p_sentin8_auth_user_id` UUID - the former `$2` text form
        // resolved to no overload (E2E-CTX-1).
        "SELECT sentin8_set_tenant_context($1, $2::text, 'm2m', NULL, false, false, false, $2)",
    )
    .bind(env_id)
    .bind(auth_sub)
    .execute(&mut *tx)
    .await;
    crate::store_ops::provision_principal(&mut tx, env_id, auth_sub, &email, display.as_deref())
        .await
        .map_err(|e| anyhow::anyhow!("provision failed: {e}"))?;
    tx.commit().await?;
    tracing::info!(%env_id, user = %email, "email8:store: principal provisioned");
    Ok(())
}
