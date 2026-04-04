/// proxy_config.rs
///
/// Redirects monitored domains to the DLP proxy by writing entries directly
/// into the system hosts file (`C:\Windows\System32\drivers\etc\hosts`).
///
/// The agent-managed block is delimited by well-known comment markers so that
/// the rest of the hosts file is left untouched and the block can be cleanly
/// removed on shutdown / deregistration.
///
///   # BEGIN ProxyDLPAgent
///   192.168.1.100 example.com
///   192.168.1.100 corp.internal
///   # END ProxyDLPAgent
use anyhow::Result;
use log::{debug, info, warn};
use std::{fs, net::ToSocketAddrs};

#[cfg(windows)]
use winreg::{enums::*, RegKey};

// ─── Constants ──────────────────────────────────────────────────────────────

/// Absolute path to the Windows hosts file.
const HOSTS_FILE_PATH: &str = r"C:\Windows\System32\drivers\etc\hosts";

/// Marker that opens the agent-managed block in the hosts file.
const MARKER_BEGIN: &str = "# BEGIN ProxyDLPAgent";

/// Marker that closes the agent-managed block in the hosts file.
const MARKER_END: &str = "# END ProxyDLPAgent";

// ─── Public API ──────────────────────────────────────────────────────────────

/// Write monitored-domain entries into the hosts file and clear any leftover
/// PAC/proxy registry settings from a previous installation strategy.
///
/// `proxy_host` may be either a hostname or an IP address literal.
/// If a hostname is given it is resolved once at call time.
pub fn install_hosts(domains: &[String], proxy_host: &str) -> Result<()> {
    let proxy_ip = resolve_ip(proxy_host)?;
    info!("Proxy IP resolved: {proxy_ip}");

    let existing = fs::read_to_string(HOSTS_FILE_PATH).unwrap_or_default();
    let base = remove_agent_block(&existing);

    let new_content = if domains.is_empty() {
        info!("No monitored domains — hosts file agent block cleared");
        base
    } else {
        let entries: String = domains
            .iter()
            .map(|d| format!("{proxy_ip} {d}\n"))
            .collect();
        debug!("Hosts entries to write:\n{entries}");
        format!("{base}\n{MARKER_BEGIN}\n{entries}{MARKER_END}\n")
    };

    fs::write(HOSTS_FILE_PATH, &new_content)
        .map_err(|e| anyhow::anyhow!("Failed to write hosts file: {e}"))?;

    info!(
        "Hosts file updated at {HOSTS_FILE_PATH} ({} domain(s))",
        domains.len()
    );

    // Clear any PAC / named-proxy / Firefox-GPO settings that a previous
    // version of this agent may have written.
    clear_proxy_settings();

    Ok(())
}

/// Remove the agent-managed block from the hosts file (called on deregistration
/// / service stop).
pub fn remove_hosts() -> Result<()> {
    let existing = match fs::read_to_string(HOSTS_FILE_PATH) {
        Ok(c) => c,
        Err(e) => {
            warn!("Could not read hosts file: {e}");
            return Ok(());
        }
    };

    let cleaned = remove_agent_block(&existing);
    fs::write(HOSTS_FILE_PATH, &cleaned)
        .map_err(|e| anyhow::anyhow!("Failed to write hosts file on cleanup: {e}"))?;

    info!("Hosts file agent block removed");
    Ok(())
}

// ─── Hosts-file helpers ───────────────────────────────────────────────────────

/// Return `content` with the `MARKER_BEGIN` … `MARKER_END` block (inclusive)
/// stripped out.  Lines outside the block are preserved verbatim.
fn remove_agent_block(content: &str) -> String {
    let mut lines: Vec<&str> = Vec::new();
    let mut inside = false;

    for line in content.lines() {
        if line.trim() == MARKER_BEGIN {
            inside = true;
            continue;
        }
        if line.trim() == MARKER_END {
            inside = false;
            continue;
        }
        if !inside {
            lines.push(line);
        }
    }

    // Trim trailing blank lines, then restore a single newline at the end.
    let joined = lines.join("\n");
    let trimmed = joined.trim_end();
    if trimmed.is_empty() {
        String::new()
    } else {
        format!("{trimmed}\n")
    }
}

/// Resolve `host` to its first IPv4/IPv6 address string.
/// If `host` is already an IP literal it is returned as-is without a lookup.
fn resolve_ip(host: &str) -> Result<String> {
    if host.parse::<std::net::IpAddr>().is_ok() {
        return Ok(host.to_string());
    }

    let addr = format!("{host}:80");
    let mut addrs = addr
        .to_socket_addrs()
        .map_err(|e| anyhow::anyhow!("DNS lookup failed for '{host}': {e}"))?;

    addrs
        .next()
        .map(|a| a.ip().to_string())
        .ok_or_else(|| anyhow::anyhow!("No address found for '{host}'"))
}

// ─── Clear legacy proxy registry settings ────────────────────────────────────

/// Clear WinInet AutoConfigURL, WinHTTP named proxy, and Firefox GPO keys that
/// a previous PAC-based installation may have written.
fn clear_proxy_settings() {
    clear_wininet_proxy();
    clear_winhttp_proxy();
    clear_firefox_proxy_gpo();
}

#[cfg(windows)]
fn clear_wininet_proxy() {
    use windows::Win32::Networking::WinInet::{
        InternetSetOptionW, INTERNET_OPTION_REFRESH, INTERNET_OPTION_SETTINGS_CHANGED,
    };

    const INET_SETTINGS: &str =
        r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";

    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    if let Ok(key) = hkcu.open_subkey_with_flags(INET_SETTINGS, KEY_WRITE) {
        let _ = key.delete_value("AutoConfigURL");
        let _ = key.set_value("ProxyEnable", &0u32);
        debug!("HKCU Internet Settings proxy cleared");
    }

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let policy_path =
        r"SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings";
    if let Ok(key) = hklm.open_subkey_with_flags(policy_path, KEY_WRITE) {
        let _ = key.delete_value("AutoConfigUrl");
        debug!("HKLM Internet Settings policy cleared");
    }

    unsafe {
        let _ = InternetSetOptionW(None, INTERNET_OPTION_SETTINGS_CHANGED, None, 0);
        let _ = InternetSetOptionW(None, INTERNET_OPTION_REFRESH, None, 0);
    }

    info!("WinInet proxy settings cleared");
}

#[cfg(not(windows))]
fn clear_wininet_proxy() {}

#[cfg(windows)]
fn clear_winhttp_proxy() {
    use windows::core::PWSTR;
    use windows::Win32::Networking::WinHttp::{
        WinHttpSetDefaultProxyConfiguration, WINHTTP_ACCESS_TYPE_NO_PROXY, WINHTTP_PROXY_INFO,
    };

    let mut proxy_info = WINHTTP_PROXY_INFO {
        dwAccessType: WINHTTP_ACCESS_TYPE_NO_PROXY,
        lpszProxy: PWSTR(std::ptr::null_mut()),
        lpszProxyBypass: PWSTR(std::ptr::null_mut()),
    };

    unsafe {
        match WinHttpSetDefaultProxyConfiguration(&mut proxy_info) {
            Ok(_) => info!("WinHTTP proxy cleared"),
            Err(e) => warn!("WinHTTP clear failed: {e}"),
        }
    }
}

#[cfg(not(windows))]
fn clear_winhttp_proxy() {}

#[cfg(windows)]
fn clear_firefox_proxy_gpo() {
    const FIREFOX_PROXY_KEY: &str = r"SOFTWARE\Policies\Mozilla\Firefox\Proxy";

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    match hklm.open_subkey_with_flags(FIREFOX_PROXY_KEY, KEY_WRITE) {
        Ok(key) => {
            let _ = key.delete_value("Mode");
            let _ = key.delete_value("Locked");
            let _ = key.delete_value("UseHTTPProxyForAllProtocols");
            info!("Firefox proxy GPO cleared");
        }
        Err(_) => debug!("Firefox GPO key not present, nothing to clear"),
    }
}

#[cfg(not(windows))]
fn clear_firefox_proxy_gpo() {}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remove_block_strips_agent_section() {
        let input = "127.0.0.1 localhost\n\
                     # BEGIN ProxyDLPAgent\n\
                     1.2.3.4 example.com\n\
                     # END ProxyDLPAgent\n\
                     # some other comment\n";
        let result = remove_agent_block(input);
        assert!(!result.contains("example.com"));
        assert!(!result.contains(MARKER_BEGIN));
        assert!(!result.contains(MARKER_END));
        assert!(result.contains("127.0.0.1 localhost"));
        assert!(result.contains("# some other comment"));
    }

    #[test]
    fn remove_block_noop_when_no_markers() {
        let input = "127.0.0.1 localhost\n::1 localhost\n";
        let result = remove_agent_block(input);
        assert_eq!(result, input);
    }

    #[test]
    fn resolve_ip_passthrough_for_literals() {
        assert_eq!(resolve_ip("192.168.1.1").unwrap(), "192.168.1.1");
        assert_eq!(resolve_ip("::1").unwrap(), "::1");
    }
}
