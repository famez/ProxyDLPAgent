# CLAUDE.md — ProxyDLP Agent

## Project overview

Windows DLP (Data Loss Prevention) agent written in Rust. It registers with a ProxyDLP Server, fetches a list of monitored domains, and configures the local OS proxy via a generated PAC file so that matching traffic is routed through the DLP proxy for inspection.

Companion server: https://github.com/famez/ProxyDLP

---

## Companion server (ProxyDLP)

Source: https://github.com/famez/ProxyDLP

### Overview

Node.js (Express) + MongoDB application with two personas:

- **Web console** (ports 80/443 → 8443): dashboard for viewing intercepted traffic, managing detection rules, monitored domains, users, and statistics.
- **Agent API** (port 4443): REST API consumed exclusively by this agent. The `/api/agent/` prefix returns 403 on port 8443 — agents must always use port **4443**.

A `mitmproxy`-based service intercepts HTTPS traffic on port **8080**, decrypts it with a self-signed CA, inspects it against configured rules, and logs events to MongoDB.

### Agent API endpoints

Base URL: `https://<PROXY_HOSTNAME>:4443`

| Method | Path | Auth | Notes |
|--------|------|------|-------|
| `GET` | `/healthcheck` | No | Returns `"OK"` |
| `GET` | `/register` | No | Returns `{ guid, token }` |
| `GET` | `/monitored_domains` | Yes | query: `?guid=` — returns `{ domains: string[] }` |
| `POST` | `/heartbeat` | Yes | body: `{ guid, computer_name, os_version, user, ip_addresses, agent_version, monitored_domains }` |
| `GET` | `/deregister` | Yes | query: `?guid=` |

### Authentication

All authenticated endpoints require:
- `Authorization: Bearer <raw_token>` header
- `guid` as query param (GET) or JSON body field (POST)

The server looks up the agent by `guid` in the `agents` MongoDB collection and verifies the token with `bcrypt.compare` (12 salt rounds). There is no JWT or expiry — the token is valid until deregistration.

### Token lifecycle

1. Agent calls `GET /register` → server generates a 96-char hex token (`crypto.randomBytes(48)`), stores it hashed (bcrypt), returns `{ guid, token }` plaintext.
2. Agent persists `guid` and `token` in `HKLM\SOFTWARE\ProxyDlp`.
3. All subsequent requests use `Authorization: Bearer <token>` + `guid`.
4. No rotation mechanism — token lives until `GET /deregister` is called.

### Monitored domains

`GET /monitored_domains` reads the `sites` MongoDB collection, flattens the `urls` arrays of all site documents, strips paths (keeps only the domain part), deduplicates, and returns the list. This list is what the agent uses to generate the PAC file.

### Deployment

```bash
./generate_secrets.sh <proxy-hostname>
docker-compose up
```

`generate_secrets.sh` creates `.env` with secrets, generates the mitmproxy CA (4096-bit RSA), and signs the nginx TLS cert with it. The CA public cert (`mitmCA.pem`) must be installed on the agent machine at `C:\Program Files\ProxyDLPAgent\mitmCA.pem` so that rustls can verify the server's TLS certificate.

### Key services

| Service | Role | Port |
|---------|------|------|
| `nginx-server` | TLS termination + reverse proxy | 80, 443, 4443 |
| `web-console` | Node.js app | internal :3000 |
| `mongo` | MongoDB (`ProxyDLP` database) | internal |
| `proxy` | mitmproxy replicas (2–10) | internal :8080 |
| `haproxy` | Load-balances proxy replicas | 8080 |

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
| Log file | `C:\ProgramData\ProxyDLPAgent\trace.log` | `main.rs` |
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
