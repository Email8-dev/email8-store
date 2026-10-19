// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Email8:Store
// SPDX-License-Identifier: Apache-2.0

//! SSE push stream - the `email8:push:state:changed` bus consumer that
//! feeds `GET /jmap/eventsource` subscribers.
//!
//! P1 polls the changelog head per subscriber (cheap: one indexed MAX per
//! account); Epic 4.8 upgrades this to the bus consumer group.
use uuid::Uuid;

use std::time::Duration;

use futures_util::Stream;
use tokio::sync::mpsc;

/// The changelog-head query shared by the SSE stream and the RFC 8887
/// WebSocket StateChange push.
const SQL_HEAD_STATE: &str = "SELECT \
    COALESCE((SELECT MAX(change_id) FROM email8.changelog WHERE account_id = $1 AND collection = 0), 0), \
    COALESCE((SELECT MAX(change_id) FROM email8.changelog WHERE account_id = $1 AND collection = 1), 0)";

/// The current `{Type: changeId}` state map for an account (JMAP RFC
/// 8620 §7.1) - the payload both the SSE `event: state` and the RFC
/// 8887 WebSocket `StateChange` push consume.
pub async fn current_state(
    conn: &mut sqlx::PgConnection,
    account_id: Uuid,
) -> Option<serde_json::Value> {
    let (email_state, mailbox_state) = sqlx::query_as::<_, (i64, i64)>(SQL_HEAD_STATE)
        .bind(account_id)
        .fetch_optional(&mut *conn)
        .await
        .ok()
        .flatten()?;
    Some(serde_json::json!({
        "@type": "StateChange",
        "changed": { account_id.to_string(): {
            "Email": email_state.to_string(),
            "Mailbox": mailbox_state.to_string(),
        }}
    }))
}

/// Produce the SSE body stream for a subscriber. Emits `state` events with
/// the current `{Type: changeId}` map on change, plus `ping` keepalives.
pub fn state_stream(
    pool: sqlx::PgPool,
    env_id: uuid::Uuid,
    sub: String,
) -> impl Stream<Item = Result<Vec<u8>, std::io::Error>> + Send + 'static {
    let (tx, rx) = mpsc::channel::<Result<Vec<u8>, std::io::Error>>(16);
    tokio::spawn(async move {
        let mut last_state: Option<String> = None;
        loop {
            // Resolve the account binding for this subscriber (re-resolve
            // cheaply each tick - the row is indexed and this paces at
            // 1 Hz).
            let Ok(mut conn) = pool.acquire().await else {
                tokio::time::sleep(Duration::from_secs(2)).await;
                continue;
            };
            let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
                .bind(env_id)
                .execute(&mut *conn)
                .await;
            let account: Option<i64> = sqlx::query_scalar(
                "SELECT id FROM email8.principals WHERE env_id = $1 AND sentin8_auth_user_id = $2",
            )
            .bind(env_id)
            .bind(uuid::Uuid::parse_str(&sub).unwrap_or_default())
            .fetch_optional(&mut *conn)
            .await
            .ok()
            .flatten();
            let Some(account_id) = account else {
                let _ = tx.send(Ok(b"event: ping\ndata: {}\n\n".to_vec())).await;
                tokio::time::sleep(Duration::from_secs(30)).await;
                continue;
            };
            let row: Option<(i64, i64)> = sqlx::query_as(
                "SELECT \
                    COALESCE((SELECT MAX(change_id) FROM email8.changelog WHERE account_id = $1 AND collection = 0), 0), \
                    COALESCE((SELECT MAX(change_id) FROM email8.changelog WHERE account_id = $1 AND collection = 1), 0)",
            )
            .bind(account_id)
            .fetch_optional(&mut *conn)
            .await
            .ok()
            .flatten();
            if let Some((email_state, mailbox_state)) = row {
                let state = format!("Email:{email_state},Mailbox:{mailbox_state}");
                if last_state.as_deref() != Some(state.as_str()) {
                    last_state = Some(state.clone());
                    let payload = format!(
                        "event: state\ndata: {{\"changed\": {{\"{account_id}\": {{\"Email\": \"{email_state}\", \"Mailbox\": \"{mailbox_state}\"}}}}}}\n\n"
                    );
                    if tx.send(Ok(payload.into_bytes())).await.is_err() {
                        break; // subscriber went away
                    }
                }
            }
            // Keepalive ping every ~30 s between checks.
            let _ = tx.send(Ok(b"event: ping\ndata: {}\n\n".to_vec())).await;
            tokio::time::sleep(Duration::from_secs(30)).await;
        }
    });
    // Wrap the mpsc receiver in a `futures_util` stream via a poll adapter.
    futures_util::stream::unfold(rx, |mut rx| async move {
        rx.recv().await.map(|item| (item, rx))
    })
}
