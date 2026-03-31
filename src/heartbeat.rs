use log::{error, info};
use std::time::Duration;
use tokio::sync::watch;

const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(120);

/// Run the periodic heartbeat loop.
///
/// Sends one heartbeat immediately, then every `HEARTBEAT_INTERVAL` seconds.
/// Exits cleanly when `shutdown` receives `true`.
pub async fn run(
    proxy_hostname: String,
    token: String,
    monitored_domains: Vec<String>,
    mut shutdown: watch::Receiver<bool>,
) {
    // Send the first heartbeat right away.
    if let Err(e) =
        crate::https_client::send_heartbeat(&proxy_hostname, &token, &monitored_domains).await
    {
        error!("Initial heartbeat failed: {e}");
    }

    let mut interval = tokio::time::interval(HEARTBEAT_INTERVAL);
    // The first tick fires immediately; we already sent above, so consume it.
    interval.tick().await;

    loop {
        tokio::select! {
            _ = interval.tick() => {
                if let Err(e) = crate::https_client::send_heartbeat(
                    &proxy_hostname,
                    &token,
                    &monitored_domains,
                )
                .await
                {
                    error!("Heartbeat failed: {e}");
                } else {
                    info!("Heartbeat OK");
                }
            }
            result = shutdown.changed() => {
                if result.is_err() || *shutdown.borrow() {
                    info!("Heartbeat worker stopping");
                    break;
                }
            }
        }
    }
}
