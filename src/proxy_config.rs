/// proxy_config.rs
///
/// Replaces the WinDivert-based DNS spoofing approach with a PAC (Proxy Auto-Config)
/// file that tells the OS which URLs should be routed through the DLP proxy.
///
/// Flow:
///   1. Receive list of monitored domains from the server.
///   2. Generate a PAC file that routes those domains to the proxy.
///   3. Write the PAC file to disk.
///   4. Configure the Windows proxy settings (HKCU + HKLM policy) to use the PAC file.
///   5. Notify WinInet so running browsers pick up the change immediately.
use anyhow::Result;
use log::{error, info};
use std::{fs, path::Path};

#[cfg(windows)]
use winreg::{enums::*, RegKey};

// ─── Constants ──────────────────────────────────────────────────────────────

/// Port on which the DLP proxy listens for HTTP/HTTPS CONNECT traffic.
pub const PROXY_PORT: u16 = 8080;

/// Local path where the generated PAC file is written.
pub const PAC_FILE_PATH: &str = r"C:\ProgramData\ProxyDLPAgent\proxy.pac";

/// `file:///` URL used in the registry AutoConfigURL value.
pub const PAC_FILE_URL: &str = "file:///C:/ProgramData/ProxyDLPAgent/proxy.pac";

// ─── PAC file generation ─────────────────────────────────────────────────────

/// Build the JavaScript content of a PAC file that forwards `domains` to the
/// proxy at `proxy_host:proxy_port` and lets everything else through directly.
///
/// Example output for domains = ["example.com", "corp.internal"]:
/// ```javascript
/// function FindProxyForURL(url, host) {
///     if (dnsDomainIs(host, ".example.com") || host == "example.com") return "PROXY proxy.host:8080";
///     if (dnsDomainIs(host, ".corp.internal") || host == "corp.internal") return "PROXY proxy.host:8080";
///     return "DIRECT";
/// }
/// ```
pub fn generate_pac_content(domains: &[String], proxy_host: &str, proxy_port: u16) -> String {
    let proxy_directive = format!("PROXY {proxy_host}:{proxy_port}");

    if domains.is_empty() {
        // No monitored domains: route everything through proxy (safe default for DLP).
        return format!(
            "function FindProxyForURL(url, host) {{\n    return \"{proxy_directive}\";\n}}\n"
        );
    }

    let rules: String = domains
        .iter()
        .map(|d| {
            format!(
                "    if (dnsDomainIs(host, \".{d}\") || host == \"{d}\") return \"{proxy_directive}\";"
            )
        })
        .collect::<Vec<_>>()
        .join("\n");

    format!("function FindProxyForURL(url, host) {{\n{rules}\n    return \"DIRECT\";\n}}\n")
}

// ─── Public API ──────────────────────────────────────────────────────────────

/// Write the PAC file for the given domain list and activate it as the system proxy.
pub fn install_pac_file(domains: &[String], proxy_host: &str, proxy_port: u16) -> Result<()> {
    let content = generate_pac_content(domains, proxy_host, proxy_port);

    // Ensure the directory exists.
    if let Some(parent) = Path::new(PAC_FILE_PATH).parent() {
        fs::create_dir_all(parent)?;
    }

    fs::write(PAC_FILE_PATH, &content)?;
    info!("PAC file written to {PAC_FILE_PATH} ({} domain(s))", domains.len());

    set_system_proxy_pac(PAC_FILE_URL)?;
    Ok(())
}

/// Remove the PAC file and clear proxy settings (called on deregistration / service stop).
pub fn remove_pac_file() -> Result<()> {
    if Path::new(PAC_FILE_PATH).exists() {
        fs::remove_file(PAC_FILE_PATH)?;
        info!("PAC file removed");
    }
    clear_system_proxy()?;
    Ok(())
}

// ─── Windows registry + WinInet helpers ──────────────────────────────────────

/// Set `AutoConfigURL` in the registry and notify WinInet.
///
/// Writes to:
///   • HKCU  – takes effect for the current interactive user session.
///   • HKLM  policy path – enforces the setting for all users (requires admin;
///            the agent runs as LocalSystem so this always succeeds).
#[cfg(windows)]
fn set_system_proxy_pac(pac_url: &str) -> Result<()> {
    const INET_SETTINGS: &str =
        r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";
    const POLICY_PATH: &str =
        r"SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings";

    // Per-user (current session / interactive login).
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    if let Ok((key, _)) = hkcu.create_subkey(INET_SETTINGS) {
        key.set_value("AutoConfigURL", &pac_url.to_string())?;
        // Make sure manual proxy is disabled so AutoConfigURL takes precedence.
        key.set_value("ProxyEnable", &0u32)?;
    }

    // System-wide policy (all users, overrides HKCU settings).
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    if let Ok((policy_key, _)) = hklm.create_subkey(POLICY_PATH) {
        let _ = policy_key.set_value("AutoConfigUrl", &pac_url.to_string());
        // ProxySettingsPerUser = 0 means machine-level proxy; = 1 means per-user.
        let _ = policy_key.set_value("ProxySettingsPerUser", &0u32);
    }

    notify_wininet_proxy_change();
    info!("System proxy set to PAC: {pac_url}");
    Ok(())
}

#[cfg(not(windows))]
fn set_system_proxy_pac(_pac_url: &str) -> Result<()> {
    Ok(())
}

/// Clear AutoConfigURL and disable proxy.
#[cfg(windows)]
fn clear_system_proxy() -> Result<()> {
    const INET_SETTINGS: &str =
        r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";
    const POLICY_PATH: &str =
        r"SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings";

    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    if let Ok((key, _)) = hkcu.create_subkey(INET_SETTINGS) {
        let _ = key.delete_value("AutoConfigURL");
        let _ = key.set_value("ProxyEnable", &0u32);
    }

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    if let Ok((policy_key, _)) = hklm.create_subkey(POLICY_PATH) {
        let _ = policy_key.delete_value("AutoConfigUrl");
    }

    notify_wininet_proxy_change();
    info!("System proxy settings cleared");
    Ok(())
}

#[cfg(not(windows))]
fn clear_system_proxy() -> Result<()> {
    Ok(())
}

/// Call `InternetSetOptionW` with SETTINGS_CHANGED + REFRESH so that
/// currently-running IE/Edge/WinInet applications reload the proxy config
/// without needing a restart.
#[cfg(windows)]
fn notify_wininet_proxy_change() {
    use windows::Win32::Networking::WinInet::{
        InternetSetOptionW, INTERNET_OPTION_REFRESH, INTERNET_OPTION_SETTINGS_CHANGED,
    };

    // HINTERNET = NULL means "apply globally" (not to a specific session).
    unsafe {
        let _ = InternetSetOptionW(
            None,
            INTERNET_OPTION_SETTINGS_CHANGED,
            None,
            0,
        );
        let _ = InternetSetOptionW(
            None,
            INTERNET_OPTION_REFRESH,
            None,
            0,
        );
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pac_with_domains() {
        let domains = vec!["example.com".to_string(), "corp.internal".to_string()];
        let pac = generate_pac_content(&domains, "proxy.host", 8080);
        assert!(pac.contains("dnsDomainIs(host, \".example.com\")"));
        assert!(pac.contains("dnsDomainIs(host, \".corp.internal\")"));
        assert!(pac.contains("return \"DIRECT\""));
        assert!(pac.contains("PROXY proxy.host:8080"));
    }

    #[test]
    fn pac_empty_domains_routes_all() {
        let pac = generate_pac_content(&[], "proxy.host", 8080);
        assert!(pac.contains("return \"PROXY proxy.host:8080\""));
        assert!(!pac.contains("DIRECT"));
    }
}
