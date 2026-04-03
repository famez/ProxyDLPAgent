/// proxy_config.rs
///
/// Configures the OS proxy via three complementary mechanisms:
///   1. PAC file served over HTTP from localhost (fixes file:/// restrictions in modern Windows).
///   2. WinHTTP named proxy (covers .NET apps, PowerShell, Windows services).
///   3. Firefox GPO registry policy (forces Firefox to use the system proxy).
///
/// Flow:
///   1. Receive list of monitored domains from the server.
///   2. Generate a PAC file and write it to disk.
///   3. Spawn a local HTTP server that serves the PAC file.
///   4. Configure WinInet (HKCU + HKLM policy) to use the PAC via http://127.0.0.1.
///   5. Configure WinHTTP to use a named proxy (direct to proxy host:port).
///   6. Configure Firefox via HKLM registry GPO to use system proxy settings.
///   7. Notify WinInet so running browsers pick up the change immediately.
use anyhow::Result;
use log::{debug, error, info, warn};
use std::{fs, path::Path};
use tokio::sync::watch;

#[cfg(windows)]
use winreg::{enums::*, RegKey};

// ─── Constants ──────────────────────────────────────────────────────────────

/// Port on which the DLP proxy listens for HTTP/HTTPS CONNECT traffic.
pub const PROXY_PORT: u16 = 8080;

/// Port on which the local PAC HTTP server listens.
pub const PAC_HTTP_PORT: u16 = 8087;

/// Local path where the generated PAC file is written.
pub const PAC_FILE_PATH: &str = r"C:\ProgramData\ProxyDLPAgent\proxy.pac";

/// HTTP URL served by the local PAC server — used in all registry entries.
pub const PAC_FILE_URL: &str = "http://127.0.0.1:8087/proxy.pac";

// ─── PAC file generation ─────────────────────────────────────────────────────

/// Build the JavaScript content of a PAC file that forwards `domains` to the
/// proxy at `proxy_host:proxy_port` and lets everything else through directly.
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

/// Write the PAC file for the given domain list and activate all proxy mechanisms.
pub fn install_pac_file(domains: &[String], proxy_host: &str, proxy_port: u16) -> Result<()> {
    let content = generate_pac_content(domains, proxy_host, proxy_port);
    debug!("Generated PAC content ({} bytes):\n{content}", content.len());

    // Ensure the directory exists.
    if let Some(parent) = Path::new(PAC_FILE_PATH).parent() {
        match fs::create_dir_all(parent) {
            Ok(_) => debug!("PAC directory ensured: {}", parent.display()),
            Err(e) => warn!("Failed to create PAC directory {}: {e}", parent.display()),
        }
    }

    match fs::write(PAC_FILE_PATH, &content) {
        Ok(_) => info!("PAC file written to {PAC_FILE_PATH} ({} domain(s))", domains.len()),
        Err(e) => return Err(anyhow::anyhow!("Failed to write PAC file: {e}")),
    }

    // 1. WinInet: HKCU + HKLM policy pointing at local PAC HTTP server.
    debug!("Configuring WinInet proxy (PAC URL: {PAC_FILE_URL})");
    set_system_proxy_pac(PAC_FILE_URL)?;

    // 2. WinHTTP: named proxy (covers .NET / PowerShell / Windows services).
    debug!("Configuring WinHTTP named proxy ({proxy_host}:{proxy_port})");
    set_winhttp_named_proxy(proxy_host, proxy_port);

    // 3. Firefox GPO: force system proxy via HKLM registry policy.
    debug!("Configuring Firefox proxy GPO");
    set_firefox_proxy_gpo();

    info!("install_pac_file completed — WinInet + WinHTTP + Firefox configured");
    Ok(())
}

/// Remove the PAC file and clear all proxy settings (called on deregistration / service stop).
pub fn remove_pac_file() -> Result<()> {
    if Path::new(PAC_FILE_PATH).exists() {
        fs::remove_file(PAC_FILE_PATH)?;
        info!("PAC file removed");
    }
    clear_system_proxy()?;
    clear_winhttp_proxy();
    clear_firefox_proxy_gpo();
    Ok(())
}

// ─── Local PAC HTTP server ────────────────────────────────────────────────────

/// Async task: serve the PAC file over HTTP on 127.0.0.1:PAC_HTTP_PORT.
/// Runs until `shutdown_rx` signals true.
pub async fn run_pac_http_server(mut shutdown_rx: watch::Receiver<bool>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    let bind_addr = format!("127.0.0.1:{PAC_HTTP_PORT}");
    let listener = match TcpListener::bind(&bind_addr).await {
        Ok(l) => {
            info!("PAC HTTP server listening on {bind_addr}");
            l
        }
        Err(e) => {
            error!("Failed to bind PAC HTTP server on {bind_addr}: {e}");
            return;
        }
    };

    loop {
        tokio::select! {
            result = listener.accept() => {
                match result {
                    Ok((mut stream, addr)) => {
                        debug!("PAC HTTP: connection from {addr}");
                        tokio::spawn(async move {
                            let mut buf = [0u8; 2048];
                            let n = match stream.read(&mut buf).await {
                                Ok(n) if n > 0 => n,
                                Ok(_) => return,
                                Err(e) => { warn!("PAC HTTP read error from {addr}: {e}"); return; }
                            };

                            let req = String::from_utf8_lossy(&buf[..n]);
                            let first_line = req.lines().next().unwrap_or("");
                            debug!("PAC HTTP request from {addr}: {first_line}");

                            let (status, body, content_type) = match fs::read_to_string(PAC_FILE_PATH) {
                                Ok(content) => ("200 OK", content, "application/x-ns-proxy-autoconfig"),
                                Err(e) => {
                                    warn!("PAC HTTP: could not read PAC file: {e}");
                                    ("404 Not Found", "PAC file not available".to_string(), "text/plain")
                                }
                            };

                            let response = format!(
                                "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                                body.len()
                            );

                            if let Err(e) = stream.write_all(response.as_bytes()).await {
                                warn!("PAC HTTP write error to {addr}: {e}");
                            } else {
                                debug!("PAC HTTP: served {status} to {addr}");
                            }
                        });
                    }
                    Err(e) => warn!("PAC HTTP accept error: {e}"),
                }
            }
            _ = shutdown_rx.changed() => {
                info!("PAC HTTP server shutting down");
                break;
            }
        }
    }
}

// ─── WinInet registry + notification ─────────────────────────────────────────

#[cfg(windows)]
fn set_system_proxy_pac(pac_url: &str) -> Result<()> {
    apply_proxy_to_all_profiles(pac_url, true);
    notify_wininet_proxy_change();
    info!("WinInet proxy set to PAC: {pac_url}");
    Ok(())
}

#[cfg(not(windows))]
fn set_system_proxy_pac(_pac_url: &str) -> Result<()> {
    Ok(())
}

#[cfg(windows)]
fn clear_system_proxy() -> Result<()> {
    apply_proxy_to_all_profiles("", false);
    notify_wininet_proxy_change();
    info!("WinInet proxy settings cleared");
    Ok(())
}

#[cfg(not(windows))]
fn clear_system_proxy() -> Result<()> {
    Ok(())
}

/// Apply or clear `AutoConfigURL` for every user profile on the machine.
///
/// Enumerates `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList`
/// to obtain all user SIDs (including users not currently logged in).
/// For each SID:
///   - If the hive is already loaded in `HKEY_USERS` (user is logged in), write directly.
///   - Otherwise, temporarily load `NTUSER.DAT` via `RegLoadKeyW`, write, then unload.
///
/// `set` = true  → write `AutoConfigURL = pac_url` and `ProxyEnable = 0`.
/// `set` = false → delete `AutoConfigURL` and set `ProxyEnable = 0`.
#[cfg(windows)]
fn apply_proxy_to_all_profiles(pac_url: &str, set: bool) {
    use std::collections::HashSet;
    use std::os::windows::ffi::OsStrExt;
    use windows::core::PCWSTR;
    use windows::Win32::System::Registry::{RegLoadKeyW, RegUnLoadKeyW, HKEY_USERS};

    const INET_SETTINGS: &str =
        r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";
    const PROFILE_LIST: &str =
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList";
    // SIDs of built-in system/service accounts — never touch these.
    const SKIP_SIDS: &[&str] = &[".DEFAULT", "S-1-5-18", "S-1-5-19", "S-1-5-20"];

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let profile_list = match hklm.open_subkey(PROFILE_LIST) {
        Ok(k) => k,
        Err(e) => { warn!("ProfileList open failed: {e}"); return; }
    };

    let hku = RegKey::predef(HKEY_USERS);

    // Collect currently-loaded hives so we know which ones need RegLoadKeyW.
    let loaded: HashSet<String> = hku.enum_keys().filter_map(|r| r.ok()).collect();

    for sid in profile_list.enum_keys().filter_map(|r| r.ok()) {
        if SKIP_SIDS.contains(&sid.as_str()) || sid.ends_with("_Classes") {
            debug!("Skipping profile SID: {sid}");
            continue;
        }

        let already_loaded = loaded.contains(&sid);

        // For users not currently logged in, load their NTUSER.DAT temporarily.
        if !already_loaded {
            let profile_key = match profile_list.open_subkey(&sid) {
                Ok(k) => k,
                Err(e) => { warn!("Cannot open ProfileList\\{sid}: {e}"); continue; }
            };
            // ProfileImagePath may contain REG_EXPAND_SZ — winreg expands it automatically.
            let profile_path: String = match profile_key.get_value("ProfileImagePath") {
                Ok(p) => p,
                Err(e) => { warn!("No ProfileImagePath for {sid}: {e}"); continue; }
            };
            let ntuser_dat = format!(r"{profile_path}\NTUSER.DAT");

            let subkey_wide: Vec<u16> = std::ffi::OsStr::new(&sid)
                .encode_wide().chain(std::iter::once(0)).collect();
            let file_wide: Vec<u16> = std::ffi::OsStr::new(&ntuser_dat)
                .encode_wide().chain(std::iter::once(0)).collect();

            let load_ok = unsafe {
                RegLoadKeyW(
                    HKEY_USERS,
                    PCWSTR(subkey_wide.as_ptr()),
                    PCWSTR(file_wide.as_ptr()),
                ).is_ok()
            };

            if !load_ok {
                warn!("RegLoadKeyW failed for {sid} ({ntuser_dat})");
                continue;
            }
            debug!("Loaded hive for {sid} from {ntuser_dat}");
        }

        // Write or clear proxy settings.
        let inet_path = format!(r"{sid}\{INET_SETTINGS}");
        match hku.create_subkey(&inet_path) {
            Ok((key, _)) => {
                if set {
                    match key.set_value("AutoConfigURL", &pac_url.to_string()) {
                        Ok(_) => debug!("HKU\\{sid} AutoConfigURL written"),
                        Err(e) => warn!("HKU\\{sid} AutoConfigURL write failed: {e}"),
                    }
                    match key.set_value("ProxyEnable", &0u32) {
                        Ok(_) => debug!("HKU\\{sid} ProxyEnable set to 0"),
                        Err(e) => warn!("HKU\\{sid} ProxyEnable write failed: {e}"),
                    }
                } else {
                    let _ = key.delete_value("AutoConfigURL");
                    let _ = key.set_value("ProxyEnable", &0u32);
                    debug!("HKU\\{sid} proxy settings cleared");
                }
            }
            Err(e) => warn!("HKU\\{sid}\\Internet Settings open failed: {e}"),
        }

        // Unload hives we loaded temporarily.
        if !already_loaded {
            let subkey_wide: Vec<u16> = std::ffi::OsStr::new(&sid)
                .encode_wide().chain(std::iter::once(0)).collect();
            unsafe {
                let _ = RegUnLoadKeyW(HKEY_USERS, PCWSTR(subkey_wide.as_ptr()));
            }
            debug!("Unloaded hive for {sid}");
        }
    }
}

#[cfg(windows)]
fn notify_wininet_proxy_change() {
    use windows::Win32::Networking::WinInet::{
        InternetSetOptionW, INTERNET_OPTION_REFRESH, INTERNET_OPTION_SETTINGS_CHANGED,
    };

    unsafe {
        let ok1 = InternetSetOptionW(None, INTERNET_OPTION_SETTINGS_CHANGED, None, 0);
        debug!("InternetSetOptionW(SETTINGS_CHANGED): {ok1:?}");
        let ok2 = InternetSetOptionW(None, INTERNET_OPTION_REFRESH, None, 0);
        debug!("InternetSetOptionW(REFRESH): {ok2:?}");
    }
}

// ─── WinHTTP proxy ───────────────────────────────────────────────────────────

/// Set the WinHTTP default proxy to a named proxy (`proxy_host:proxy_port`).
/// This covers apps that use WinHTTP directly: .NET HttpClient, PowerShell
/// Invoke-WebRequest, Windows Update, etc.
#[cfg(windows)]
fn set_winhttp_named_proxy(proxy_host: &str, proxy_port: u16) {
    use std::os::windows::ffi::OsStrExt;
    use windows::core::PWSTR;
    use windows::Win32::Networking::WinHttp::{
        WinHttpSetDefaultProxyConfiguration, WINHTTP_ACCESS_TYPE_NAMED_PROXY, WINHTTP_PROXY_INFO,
    };

    let proxy_str = format!("{proxy_host}:{proxy_port}");
    let bypass_str = "<local>";

    // Encode as null-terminated wide strings.
    let mut proxy_wide: Vec<u16> = std::ffi::OsStr::new(&proxy_str)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let mut bypass_wide: Vec<u16> = std::ffi::OsStr::new(bypass_str)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let mut proxy_info = WINHTTP_PROXY_INFO {
        dwAccessType: WINHTTP_ACCESS_TYPE_NAMED_PROXY,
        lpszProxy: PWSTR(proxy_wide.as_mut_ptr()),
        lpszProxyBypass: PWSTR(bypass_wide.as_mut_ptr()),
    };

    unsafe {
        match WinHttpSetDefaultProxyConfiguration(&mut proxy_info) {
            Ok(_) => info!("WinHTTP default proxy set to {proxy_str} (bypass: {bypass_str})"),
            Err(e) => warn!("WinHttpSetDefaultProxyConfiguration failed: {e}"),
        }
    }
}

#[cfg(not(windows))]
fn set_winhttp_named_proxy(_proxy_host: &str, _proxy_port: u16) {}

/// Reset the WinHTTP default proxy to "no proxy".
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

// ─── Firefox GPO ─────────────────────────────────────────────────────────────

/// Write Firefox proxy policy to HKLM so Firefox uses the OS proxy settings.
///
/// Registry path: HKLM\SOFTWARE\Policies\Mozilla\Firefox\Proxy
///   Mode                        = "system"  → use OS proxy
///   Locked                      = 1         → user cannot change it
///   UseHTTPProxyForAllProtocols = 1         → HTTP proxy also handles HTTPS
#[cfg(windows)]
fn set_firefox_proxy_gpo() {
    const FIREFOX_PROXY_KEY: &str = r"SOFTWARE\Policies\Mozilla\Firefox\Proxy";

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    match hklm.create_subkey(FIREFOX_PROXY_KEY) {
        Ok((key, disp)) => {
            debug!("HKLM\\{FIREFOX_PROXY_KEY} opened ({disp:?})");
            match key.set_value("Mode", &"system".to_string()) {
                Ok(_) => debug!("Firefox Proxy.Mode = system"),
                Err(e) => warn!("Firefox Proxy.Mode write failed: {e}"),
            }
            match key.set_value("Locked", &1u32) {
                Ok(_) => debug!("Firefox Proxy.Locked = 1"),
                Err(e) => warn!("Firefox Proxy.Locked write failed: {e}"),
            }
            match key.set_value("UseHTTPProxyForAllProtocols", &1u32) {
                Ok(_) => debug!("Firefox Proxy.UseHTTPProxyForAllProtocols = 1"),
                Err(e) => warn!("Firefox Proxy.UseHTTPProxyForAllProtocols write failed: {e}"),
            }
            info!("Firefox proxy GPO configured (mode=system, locked=true)");
        }
        Err(e) => warn!("Failed to open HKLM\\{FIREFOX_PROXY_KEY}: {e}"),
    }
}

#[cfg(not(windows))]
fn set_firefox_proxy_gpo() {}

/// Remove Firefox proxy policy keys set by this agent.
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
        Err(e) => debug!("Firefox GPO key not found, nothing to clear: {e}"),
    }
}

#[cfg(not(windows))]
fn clear_firefox_proxy_gpo() {}

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
