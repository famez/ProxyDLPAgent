use anyhow::Result;
use std::sync::{LazyLock, Mutex};

#[cfg(windows)]
use winreg::{enums::*, RegKey};

const REG_PATH: &str = r"SOFTWARE\ProxyDlp";

#[derive(Default, Clone)]
pub struct Config {
    pub guid: Option<String>,
    pub token: Option<String>,
    pub proxy_hostname: Option<String>,
    pub proxy_ip: Option<String>,
}

static CONFIG: LazyLock<Mutex<Config>> = LazyLock::new(|| Mutex::new(Config::default()));

pub fn get_guid() -> Option<String> {
    CONFIG.lock().unwrap().guid.clone()
}

pub fn get_token() -> Option<String> {
    CONFIG.lock().unwrap().token.clone()
}

pub fn get_proxy_hostname() -> Option<String> {
    CONFIG.lock().unwrap().proxy_hostname.clone()
}

pub fn get_proxy_ip() -> Option<String> {
    CONFIG.lock().unwrap().proxy_ip.clone()
}

pub fn set_guid(guid: &str) {
    CONFIG.lock().unwrap().guid = Some(guid.to_string());
}

pub fn set_token(token: &str) {
    CONFIG.lock().unwrap().token = Some(token.to_string());
}

pub fn set_proxy_hostname(hostname: &str) {
    CONFIG.lock().unwrap().proxy_hostname = Some(hostname.to_string());
}

pub fn set_proxy_ip(ip: &str) {
    CONFIG.lock().unwrap().proxy_ip = Some(ip.to_string());
}

/// Load configuration from the Windows registry.
/// Returns true if all required values (guid, token, hostname) were loaded.
#[cfg(windows)]
pub fn load_from_registry() -> bool {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let key = match hklm.open_subkey(REG_PATH) {
        Ok(k) => k,
        Err(_) => return false,
    };

    let mut cfg = CONFIG.lock().unwrap();

    let hostname: Result<String, _> = key.get_value("ProxyHostname");
    let guid: Result<String, _> = key.get_value("guid");
    let token: Result<String, _> = key.get_value("token");

    if let Ok(v) = hostname {
        cfg.proxy_hostname = Some(v);
    }
    if let Ok(v) = guid {
        cfg.guid = Some(v);
    }
    if let Ok(v) = token {
        cfg.token = Some(v);
    }

    cfg.proxy_hostname.is_some() && cfg.guid.is_some() && cfg.token.is_some()
}

#[cfg(not(windows))]
pub fn load_from_registry() -> bool {
    false
}

/// Persist GUID and token to the Windows registry.
#[cfg(windows)]
pub fn save_to_registry() -> Result<()> {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let (key, _) = hklm.create_subkey(REG_PATH)?;

    let cfg = CONFIG.lock().unwrap();
    if let Some(ref guid) = cfg.guid {
        key.set_value("guid", guid)?;
    }
    if let Some(ref token) = cfg.token {
        key.set_value("token", token)?;
    }
    Ok(())
}

#[cfg(not(windows))]
pub fn save_to_registry() -> Result<()> {
    Ok(())
}
