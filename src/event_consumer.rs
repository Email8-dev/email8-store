// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Email8:Store
// SPDX-License-Identifier: Apache-2.0

//! Sentin8:Bus consumer — reacts to `sentin8:auth:user:created` events
//! and provisions Email8 principals + bootstrap mailboxes (the
//! event-driven env-init pattern; integration design §4).

use std::time::Duration;

use futures_util::StreamExt;
use sqlx::PgPool;

const CONSUMER_GROUP: &str = "email8:store:provisioner";
/// Stream family Sentin8:Auth emits to (auth/src/events.rs) — the
/// provisioner must subscribe here to see `sentin8:auth:user:created`.
const EVENT_STREAM_FAMILY: &str = "auth";
const RECONNECT_DELAY: Duration = Duration::from_secs(2);

/// Spawn the Bus consumer background task.
pub fn spawn(
    pool: PgPool,
    bus_client: sentin8::bus::client::BusClient,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        run(pool, bus_client).await;
    })
}

async fn run(pool: PgPool, bus_client: sentin8::bus::client::BusClient) {
    tracing::info!("email8:store: provisioning consumer started (group={CONSUMER_GROUP}, family={EVENT_STREAM_FAMILY})");
    loop {
        match bus_client
            .sse_consume(EVENT_STREAM_FAMILY, CONSUMER_GROUP)
            .await
        {
            Ok(resp) => {
                tracing::info!(
                    "email8:store: bus SSE connected to stream family '{EVENT_STREAM_FAMILY}'"
                );
                sse_loop(&pool, &bus_client, resp).await;
                tracing::info!("email8:store: bus SSE disconnected — reconnecting");
            }
            Err(e) => {
                tracing::warn!(error = %e, "email8:store: bus consume failed — reconnecting");
            }
        }
        tokio::time::sleep(RECONNECT_DELAY).await;
    }
}

async fn sse_loop(
    pool: &PgPool,
    bus_client: &sentin8::bus::client::BusClient,
    resp: reqwest::Response,
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
            // fields. Parse the JSON directly — axum's SSE frames carry
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
            // fields), not inside the event payload — auth's
            // `sentin8:auth:user:created` payload only carries
            // {email, user_id}.
            let env_id = msg
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

            if let Err(e) = handle_event(pool, bus_client, env_id, &event_type, &data).await {
                tracing::warn!(error = %e, %event_type, "email8:store: event handling failed");
                // NACK so the event is retried by another consumer.
                let _ = bus_client
                    .nack(EVENT_STREAM_FAMILY, CONSUMER_GROUP, &message_id, Some(30))
                    .await;
            } else if !message_id.is_empty() {
                // ACK on success — without it the entry stays in the
                // group's PEL forever, and because every XAUTOCLAIM claim
                // resets the entry's idle clock it would never be
                // re-delivered (or eventually dropped) after the first
                // reclaim cycle.
                let _ = bus_client
                    .ack(EVENT_STREAM_FAMILY, CONSUMER_GROUP, &message_id)
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
    _bus_client: &sentin8::bus::client::BusClient,
    env_id: Option<uuid::Uuid>,
    event_type: &str,
    data: &str,
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
        return Ok(()); // no address — nothing to provision for mail
    }

    let mut conn = pool.acquire().await?;
    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(env_id)
        .execute(&mut *conn)
        .await;
    crate::store_ops::provision_principal(&mut conn, env_id, auth_sub, &email, display.as_deref())
        .await
        .map_err(|e| anyhow::anyhow!("provision failed: {e}"))?;
    tracing::info!(%env_id, user = %email, "email8:store: principal provisioned");
    Ok(())
}
