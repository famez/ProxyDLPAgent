use anyhow::{anyhow, Result};
use log::{info, warn};
use serde::{Deserialize, Serialize};
use std::time::Duration;

const AGENT_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Path to the custom CA certificate used to verify the DLP proxy's TLS cert.
const CA_CERT_PATH: &str = r"C:\Program Files\ProxyDLPAgent\mitmCA.pem";

// API endpoints
const REGISTER_ENDPOINT: &str = "register";
const DEREGISTER_ENDPOINT: &str = "deregister";
const HEARTBEAT_ENDPOINT: &str = "heartbeat";
const MON_URLS_ENDPOINT: &str = "monitored_domains";
const HEALTHCHECK_ENDPOINT: &str = "healthcheck";

// ─── JSON types ──────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct RegisterResponse {
    guid: String,
    token: String,
}

#[derive(Deserialize)]
struct MonitoredDomainsResponse {
    domains: Vec<String>,
}

#[derive(Serialize)]
struct HeartbeatPayload {
    guid: String,
    computer_name: String,
    os_version: String,
    user: String,
    ip_addresses: String,
    agent_version: &'static str,
    monitored_domains: Vec<String>,
}

// ─── HTTP client ─────────────────────────────────────────────────────────────

/// Build a `reqwest::Client` that trusts the custom CA cert if it exists.
fn build_client() -> Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .use_rustls_tls();

    if let Ok(cert_bytes) = std::fs::read(CA_CERT_PATH) {
        match reqwest::Certificate::from_pem(&cert_bytes) {
            Ok(cert) => {
                builder = builder.add_root_certificate(cert);
            }
            Err(e) => warn!("Failed to load CA cert from {CA_CERT_PATH}: {e}"),
        }
    }

    Ok(builder.build()?)
}

fn base_url(proxy_hostname: &str) -> String {
    format!("https://{proxy_hostname}:4443")
}

// ─── Public API ──────────────────────────────────────────────────────────────

/// Register the agent with the DLP server; returns (guid, token).
pub async fn register_agent(proxy_hostname: &str) -> Result<(String, String)> {
    let client = build_client()?;
    let url = format!("{}/{REGISTER_ENDPOINT}", base_url(proxy_hostname));

    let resp = client.get(&url).send().await?;
    if !resp.status().is_success() {
        return Err(anyhow!("Registration failed: HTTP {}", resp.status()));
    }

    let body: RegisterResponse = resp.json().await?;
    info!("Registered successfully, GUID = {}", body.guid);
    Ok((body.guid, body.token))
}

/// Deregister this agent instance from the DLP server.
pub async fn deregister_agent(proxy_hostname: &str, guid: &str, token: &str) -> Result<()> {
    let client = build_client()?;
    let url = format!(
        "{}/{DEREGISTER_ENDPOINT}?guid={guid}",
        base_url(proxy_hostname)
    );

    let resp = client
        .get(&url)
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await?;

    if !resp.status().is_success() {
        return Err(anyhow!("Deregistration failed: HTTP {}", resp.status()));
    }
    info!("Deregistered successfully");
    Ok(())
}

/// Fetch the list of domains the agent should route through the proxy.
pub async fn get_monitored_domains(proxy_hostname: &str, token: &str) -> Result<Vec<String>> {
    let client = build_client()?;
    let guid = crate::config::get_guid().unwrap_or_default();
    let url = format!("{}/{MON_URLS_ENDPOINT}?guid={guid}", base_url(proxy_hostname));

    let resp = client
        .get(&url)
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await?;

    if !resp.status().is_success() {
        return Err(anyhow!(
            "Failed to fetch monitored domains: HTTP {}",
            resp.status()
        ));
    }

    let body: MonitoredDomainsResponse = resp.json().await?;
    info!("Received {} domain(s) to monitor", body.domains.len());
    Ok(body.domains)
}

/// Return `true` if the proxy's health-check endpoint responds with HTTP 200.
pub async fn check_proxy_healthy(proxy_hostname: &str) -> bool {
    let Ok(client) = build_client() else {
        return false;
    };
    let url = format!("{}/{HEALTHCHECK_ENDPOINT}", base_url(proxy_hostname));
    matches!(
        client.get(&url).send().await,
        Ok(r) if r.status().is_success()
    )
}

/// Send a heartbeat with system telemetry to the DLP server.
pub async fn send_heartbeat(
    proxy_hostname: &str,
    token: &str,
    monitored_domains: &[String],
) -> Result<()> {
    let client = build_client()?;
    let url = format!("{}/{HEARTBEAT_ENDPOINT}", base_url(proxy_hostname));

    let guid = crate::config::get_guid().unwrap_or_default();

    let payload = HeartbeatPayload {
        guid,
        computer_name: sys_info::computer_name(),
        os_version: sys_info::os_version(),
        user: sys_info::logged_in_users(),
        ip_addresses: sys_info::ip_addresses(),
        agent_version: AGENT_VERSION,
        monitored_domains: monitored_domains.to_vec(),
    };

    let resp = client
        .post(&url)
        .header("Authorization", format!("Bearer {token}"))
        .json(&payload)
        .send()
        .await?;

    if !resp.status().is_success() {
        return Err(anyhow!("Heartbeat rejected: HTTP {}", resp.status()));
    }
    info!("Heartbeat sent (domains: {})", monitored_domains.len());
    Ok(())
}

// ─── System info helpers ──────────────────────────────────────────────────────

mod sys_info {

    pub fn computer_name() -> String {
        std::env::var("COMPUTERNAME").unwrap_or_else(|_| "unknown".to_string())
    }

    #[cfg(windows)]
    pub fn os_version() -> String {
        use winreg::{enums::*, RegKey};
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        if let Ok(key) =
            hklm.open_subkey(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion")
        {
            let major: u32 = key.get_value("CurrentMajorVersionNumber").unwrap_or(0);
            let minor: u32 = key.get_value("CurrentMinorVersionNumber").unwrap_or(0);
            let build: String = key.get_value("CurrentBuildNumber").unwrap_or_default();
            return format!("Windows {major}.{minor}.{build}");
        }
        "Windows (unknown)".to_string()
    }

    #[cfg(not(windows))]
    pub fn os_version() -> String {
        "unknown".to_string()
    }

    /// Get logged-in users via `query user` (works in both interactive and service contexts).
    pub fn logged_in_users() -> String {
        let Ok(output) = std::process::Command::new("query")
            .arg("user")
            .output()
        else {
            return String::new();
        };

        let text = String::from_utf8_lossy(&output.stdout);
        let mut users: Vec<String> = Vec::new();

        // Skip the header line; each data line starts with a username (possibly '>' for active).
        for line in text.lines().skip(1) {
            let username = line
                .split_whitespace()
                .next()
                .unwrap_or("")
                .trim_start_matches('>')
                .to_string();

            if !username.is_empty() && !users.contains(&username) {
                users.push(username);
            }
        }

        users.join(", ")
    }

    /// Enumerate IPv4 addresses for all non-loopback adapters.
    #[cfg(windows)]
    pub fn ip_addresses() -> String {
        use std::ffi::CStr;
        use windows::Win32::NetworkManagement::IpHelper::{GetAdaptersInfo, IP_ADAPTER_INFO};

        let mut buf_size: u32 = std::mem::size_of::<IP_ADAPTER_INFO>() as u32 * 16;
        let mut buf: Vec<u8> = vec![0u8; buf_size as usize];
        let mut ips: Vec<String> = Vec::new();

        unsafe {
            // First call to get required buffer size.
            let ret = GetAdaptersInfo(Some(buf.as_mut_ptr() as *mut IP_ADAPTER_INFO), &mut buf_size);

            // ERROR_BUFFER_OVERFLOW (111) means our buffer was too small.
            if ret == 111 {
                buf = vec![0u8; buf_size as usize];
                if GetAdaptersInfo(
                    Some(buf.as_mut_ptr() as *mut IP_ADAPTER_INFO),
                    &mut buf_size,
                ) != 0
                {
                    return String::new();
                }
            } else if ret != 0 {
                return String::new();
            }

            let mut adapter_ptr = buf.as_ptr() as *const IP_ADAPTER_INFO;
            while !adapter_ptr.is_null() {
                let adapter = &*adapter_ptr;
                // IpAddressList.IpAddress.String is [u8; 16] containing a null-terminated ASCII IP.
                let ip_bytes: &[u8] = &adapter.IpAddressList.IpAddress.String;
                if let Ok(cstr) = CStr::from_bytes_until_nul(ip_bytes) {
                    let ip = cstr.to_string_lossy();
                    if ip != "0.0.0.0" && !ip.is_empty() {
                        ips.push(ip.into_owned());
                    }
                }
                adapter_ptr = adapter.Next;
            }
        }

        ips.join(", ")
    }

    #[cfg(not(windows))]
    pub fn ip_addresses() -> String {
        String::new()
    }
}
