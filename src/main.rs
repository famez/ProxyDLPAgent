mod config;
mod heartbeat;
mod https_client;
mod proxy_config;

use anyhow::Result;
use log::{error, info, warn};
use simplelog::{Config as LogConfig, LevelFilter, WriteLogger};
use std::{ffi::OsString, fs::File, time::Duration};
use tokio::sync::watch;

// ─── Windows Service plumbing ─────────────────────────────────────────────────

#[cfg(windows)]
use windows_service::{
    define_windows_service,
    service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    },
    service_control_handler::{self, ServiceControlHandlerResult},
    service_dispatcher,
};

#[cfg(windows)]
define_windows_service!(ffi_service_main, service_main_handler);

/// Entry called by the Windows Service Control Manager.
#[cfg(windows)]
fn service_main_handler(arguments: Vec<OsString>) {
    if let Err(e) = run_as_windows_service(arguments) {
        error!("Service fatal error: {e}");
    }
}

#[cfg(windows)]
fn run_as_windows_service(_arguments: Vec<OsString>) -> Result<()> {
    // Channel used by the SCM control handler to request a stop.
    let (stop_tx, stop_rx) = std::sync::mpsc::channel::<()>();

    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            ServiceControl::Stop | ServiceControl::Shutdown => {
                let _ = stop_tx.send(());
                ServiceControlHandlerResult::NoError
            }
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    let status_handle =
        service_control_handler::register("ProxyDLPAgent", event_handler)?;

    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;

    // Build a tokio runtime and run the agent inside it.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    rt.block_on(async move {
        // Run the agent and wait for an SCM stop signal concurrently.
        tokio::select! {
            result = run_agent(shutdown_rx) => {
                if let Err(e) = result {
                    error!("Agent exited with error: {e}");
                }
            }
            _ = tokio::task::spawn_blocking(move || { stop_rx.recv().ok(); }) => {
                info!("SCM stop requested");
                let _ = shutdown_tx.send(true);
            }
        }
    });

    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;

    Ok(())
}

// ─── Entry point ─────────────────────────────────────────────────────────────

fn main() -> Result<()> {
    init_logging();

    // Handle the `/deregister` command-line flag.
    let args: Vec<String> = std::env::args().collect();
    if args.len() > 1 && args[1].eq_ignore_ascii_case("/deregister") {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        return rt.block_on(deregister_and_exit());
    }

    // Try to start as a Windows Service; falls back to interactive if not invoked by SCM.
    #[cfg(windows)]
    if service_dispatcher::start("ProxyDLPAgent", ffi_service_main).is_ok() {
        return Ok(());
    }

    // Interactive / debug mode.
    info!("Running in interactive mode");
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    rt.block_on(async move {
        tokio::select! {
            result = run_agent(shutdown_rx) => {
                if let Err(e) = result {
                    error!("Agent error: {e}");
                }
            }
            _ = tokio::signal::ctrl_c() => {
                info!("Ctrl+C received, shutting down");
                let _ = shutdown_tx.send(true);
            }
        }
    });

    Ok(())
}

// ─── Core agent logic ─────────────────────────────────────────────────────────

/// Main agent lifecycle: register, fetch domains, install PAC, run heartbeat.
async fn run_agent(shutdown_rx: watch::Receiver<bool>) -> Result<()> {
    // Remove stale logs on each start.
    let _ = std::fs::remove_file(r"C:\trace.log");

    info!("ProxyDLP Agent v1.2.0 starting");

    // ── Load persisted configuration ────────────────────────────────────────
    let already_registered = config::load_from_registry();

    let proxy_hostname = config::get_proxy_hostname().ok_or_else(|| {
        anyhow::anyhow!(
            "ProxyHostname not found in registry. \
             Please set HKLM\\SOFTWARE\\ProxyDlp\\ProxyHostname before starting the agent."
        )
    })?;

    // ── Wait until the proxy is reachable ───────────────────────────────────
    wait_for_proxy_ready(&proxy_hostname).await;

    // ── Register if this is a fresh install ─────────────────────────────────
    if !already_registered {
        info!("No stored credentials – registering with server");
        match https_client::register_agent(&proxy_hostname).await {
            Ok((guid, token)) => {
                config::set_guid(&guid);
                config::set_token(&token);
                config::save_to_registry()?;
            }
            Err(e) => {
                return Err(anyhow::anyhow!("Registration failed: {e}"));
            }
        }
    }

    let token = config::get_token()
        .ok_or_else(|| anyhow::anyhow!("No auth token available"))?;

    // ── Fetch monitored domains and install PAC file ─────────────────────────
    let domains = https_client::get_monitored_domains(&proxy_hostname, &token).await?;

    proxy_config::install_pac_file(&domains, &proxy_hostname, proxy_config::PROXY_PORT)?;

    // ── Start heartbeat task ─────────────────────────────────────────────────
    let hb_rx = shutdown_rx.clone();
    let hb_handle = tokio::spawn(heartbeat::run(
        proxy_hostname.clone(),
        token.clone(),
        domains.clone(),
        hb_rx,
    ));

    // ── Wait for shutdown signal ─────────────────────────────────────────────
    let mut rx = shutdown_rx;
    let _ = rx.changed().await;

    hb_handle.abort();

    // Clean up: remove PAC file so traffic returns to direct connections.
    if let Err(e) = proxy_config::remove_pac_file() {
        warn!("Failed to remove PAC file on shutdown: {e}");
    }

    info!("Agent stopped");
    Ok(())
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Poll the proxy health-check endpoint every 2 seconds until it responds OK.
async fn wait_for_proxy_ready(proxy_hostname: &str) {
    info!("Waiting for proxy at {proxy_hostname} to become healthy…");
    loop {
        if https_client::check_proxy_healthy(proxy_hostname).await {
            info!("Proxy is healthy");
            return;
        }
        warn!("Proxy not reachable yet, retrying in 2 s");
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

/// Load credentials and call the deregister endpoint, then exit.
async fn deregister_and_exit() -> Result<()> {
    info!("Deregistering agent…");
    if config::load_from_registry() {
        let hostname = config::get_proxy_hostname().unwrap_or_default();
        let guid = config::get_guid().unwrap_or_default();
        let token = config::get_token().unwrap_or_default();

        if let Err(e) = https_client::deregister_agent(&hostname, &guid, &token).await {
            error!("Deregistration error: {e}");
        }
    } else {
        warn!("No stored credentials – nothing to deregister");
    }

    // Remove PAC file if present.
    let _ = proxy_config::remove_pac_file();
    Ok(())
}

/// Initialise file-based logging (mirrors the original C `tracelog.h` behaviour).
fn init_logging() {
    let log_path = r"C:\trace.log";
    match File::create(log_path) {
        Ok(file) => {
            let _ = WriteLogger::init(LevelFilter::Info, LogConfig::default(), file);
        }
        Err(_) => {
            // If we cannot open the log file (e.g., during tests), fall back silently.
            let _ = simplelog::SimpleLogger::init(LevelFilter::Info, LogConfig::default());
        }
    }
}
