# CLAUDE.md — ProxyDLP Agent

## Project overview

Windows DLP (Data Loss Prevention) agent written in Rust. It registers with a ProxyDLP Server, fetches a list of monitored domains, and configures the local OS proxy via a generated PAC file so that matching traffic is routed through the DLP proxy for inspection.

Companion server: https://github.com/famez/ProxyDLP

---

## Build

```bash
# Cross-compile from Linux to Windows (primary workflow)
cargo build --release --target x86_64-pc-windows-gnu

# Native Windows build
cargo build --release

# Debug build (faster, no optimisations)
cargo build --target x86_64-pc-windows-gnu
```

Output: `target/x86_64-pc-windows-gnu/release/proxydlp.exe`

---

## Architecture decisions

### PAC file instead of WinDivert
The previous version intercepted DNS packets at the kernel level using the WinDivert driver. This has been replaced with a PAC (Proxy Auto-Config) file approach:

- No kernel driver required.
- The agent generates `C:\ProgramData\ProxyDLPAgent\proxy.pac` with routing rules for monitored domains.
- Windows proxy settings are written to `HKCU\...\Internet Settings\AutoConfigURL` and `HKLM\SOFTWARE\Policies\...\AutoConfigUrl`.
- `InternetSetOptionW` is called to notify running browsers immediately.

**Do not reintroduce WinDivert or any kernel-level packet interception.**

### Single-threaded tokio runtime
The agent is purely I/O-bound. The runtime is built with `Builder::new_current_thread().enable_all()`. Do not switch back to `rt-multi-thread`.

### Pure-Rust TLS
`reqwest` uses `rustls-tls` (no OpenSSL dependency). This simplifies cross-compilation. Do not add `native-tls` or OpenSSL.

---

## Module map

| File | Responsibility |
|---|---|
| `src/main.rs` | Entry point, Windows Service integration, tokio runtime, shutdown handling |
| `src/config.rs` | Read/write `HKLM\SOFTWARE\ProxyDlp` registry key (guid, token, ProxyHostname) |
| `src/https_client.rs` | All HTTPS communication with the server + system info helpers |
| `src/heartbeat.rs` | Tokio task: sends heartbeat every 120 s, stops on shutdown signal |
| `src/proxy_config.rs` | PAC file generation, registry proxy config, WinInet notification |

---

## Key constants

| Constant | Value | Location |
|---|---|---|
| Server API port | `4443` | `https_client.rs` |
| Proxy traffic port (PAC) | `8080` | `proxy_config.rs::PROXY_PORT` |
| Heartbeat interval | `120 s` | `heartbeat.rs` |
| CA cert path | `C:\Program Files\ProxyDLPAgent\mitmCA.pem` | `https_client.rs` |
| PAC file path | `C:\ProgramData\ProxyDLPAgent\proxy.pac` | `proxy_config.rs` |
| Log file | `C:\trace.log` | `main.rs` |
| Registry key | `HKLM\SOFTWARE\ProxyDlp` | `config.rs` |

---

## Commit conventions

Use **Conventional Commits**:

```
feat:       new feature
fix:        bug fix
perf:       performance improvement
refactor:   code change with no behaviour change
chore:      maintenance (deps, tooling, cleanup)
docs:       documentation only
test:       tests only
```

Scope is optional but encouraged: `fix(config):`, `chore(legacy):`, `perf(tokio):`, etc.

---

## Windows-specific notes

- Registry writes to `HKLM` require administrator privileges (the agent runs as LocalSystem when installed as a service).
- `GetAdaptersInfo` returns a plain `u32` (Win32 error code), not a Rust `Result`. Check with `!= 0`.
- `InternetSetOptionW` takes `Option<HINTERNET>` as `None` for global (session-independent) options.
- The `windows` crate version is pinned to `0.52` for compatibility with `windows-service = "0.7"`.
