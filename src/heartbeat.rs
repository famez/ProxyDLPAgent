use log::{error, info};
use std::time::Duration;
use tokio::sync::watch;

const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(120);

/// Run the periodic heartbeat loop.
///
/// Sends one heartbeat immediately, then every `HEARTBEAT_INTERVAL` seconds.
/// The server response contains the current monitored domain list; the PAC file
/// is (re)installed whenever that list changes.
/// Exits cleanly when `shutdown` receives `true`.
pub async fn run(
    proxy_hostname: String,
    token: String,
    mut shutdown: watch::Receiver<bool>,
) {
    // Start with an empty list; the server will supply the authoritative domain
    // list in every heartbeat response, including the very first one.
    let mut current_domains: Vec<String> = Vec::new();

    // Send the first heartbeat right away.
    match crate::https_client::send_heartbeat(&proxy_hostname, &token, &current_domains).await {
        Ok(domains) => {
            refresh_pac_if_changed(&mut current_domains, domains, &proxy_hostname);
        }
        Err(e) => error!("Initial heartbeat failed: {e}"),
    }

    let mut interval = tokio::time::interval(HEARTBEAT_INTERVAL);
    // The first tick fires immediately; we already sent above, so consume it.
    interval.tick().await;

    loop {
        tokio::select! {
            _ = interval.tick() => {
                match crate::https_client::send_heartbeat(
                    &proxy_hostname,
                    &token,
                    &current_domains,
                )
                .await
                {
                    Ok(domains) => {
                        refresh_pac_if_changed(&mut current_domains, domains, &proxy_hostname);
                        info!("Heartbeat OK");
                    }
                    Err(e) => error!("Heartbeat failed: {e}"),
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

/// Update the PAC file when the server returns a different domain list.
fn refresh_pac_if_changed(
    current: &mut Vec<String>,
    new_domains: Vec<String>,
    proxy_hostname: &str,
) {
    if new_domains == *current {
        return;
    }
    *current = new_domains;
    match crate::proxy_config::install_pac_file(
        current,
        proxy_hostname,
        crate::proxy_config::PROXY_PORT,
    ) {
        Ok(()) => info!("PAC file refreshed ({} domain(s))", current.len()),
        Err(e) => error!("Failed to refresh PAC file: {e}"),
    }
}
