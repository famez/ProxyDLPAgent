# ProxyDLP Agent

**Status:** ✅ Stable (client / agent)

The **ProxyDLP Agent** is the Windows client component of the [ProxyDLP project](https://github.com/famez/ProxyDLP). It communicates with the ProxyDLP Server to receive the list of domains to monitor and configures the local OS proxy settings accordingly, routing traffic for those domains through the DLP proxy for inspection and policy enforcement.

---

## 🔗 Related project

* **ProxyDLP Server** — [https://github.com/famez/ProxyDLP](https://github.com/famez/ProxyDLP) (server-side component). The server receives heartbeats from agents, manages monitored domain lists, and enforces DLP policies.

---

## 🏗 Architecture

Instead of intercepting network packets at the kernel level, the agent uses a **PAC (Proxy Auto-Config) file** to redirect monitored domains through the proxy:

1. On startup the agent registers with the ProxyDLP Server and fetches the list of domains to monitor.
2. It generates a PAC file (`C:\ProgramData\ProxyDLPAgent\proxy.pac`) containing routing rules for those domains.
3. It configures the Windows proxy settings (registry + policy) to point to the PAC file.
4. Browsers and WinINET-aware applications automatically route matching domains through the proxy.
5. A background heartbeat is sent to the server every 2 minutes with system telemetry.

On shutdown (or `/deregister`) the PAC file is removed and proxy settings are restored.

```
ProxyDLP Agent
    │
    ├─ HTTPS (port 4443) ──► ProxyDLP Server
    │     ├─ /register
    │     ├─ /monitored_domains
    │     ├─ /heartbeat  (every 120 s)
    │     └─ /deregister
    │
    └─ PAC file ──► OS proxy config (HKCU + HKLM policy)
          └─ Browser/WinINET ──► DLP Proxy (port 8080)
```

---

## 📦 Dependencies

All dependencies are managed by **Cargo** — no precompiled libraries or drivers required.

| Crate | Purpose |
|---|---|
| `reqwest` + `rustls` | Async HTTPS client (pure-Rust TLS, no OpenSSL) |
| `tokio` | Async runtime |
| `serde` / `serde_json` | JSON serialization |
| `winreg` | Windows registry access |
| `windows-service` | Windows Service integration |
| `windows` | Win32 API (WinInet, IpHelper) |
| `simplelog` | File-based logging |
| `anyhow` | Error handling |

---

## 🛠 Build

### Prerequisites

```bash
# Add the Windows cross-compilation target
rustup target add x86_64-pc-windows-gnu

# Install the MinGW cross-compiler (Ubuntu/Debian)
sudo apt install gcc-mingw-w64-x86-64
```

### Compile

```bash
# Release build (optimised, symbols stripped)
cargo build --release --target x86_64-pc-windows-gnu

# Output
target/x86_64-pc-windows-gnu/release/proxydlp.exe
```

> If compiling natively on Windows, run `cargo build --release` without the `--target` flag.

---

## ⚙️ Configuration

Before the first run, set the proxy hostname in the Windows registry:

```
HKEY_LOCAL_MACHINE\SOFTWARE\ProxyDlp\ProxyHostname  (REG_SZ)
```

On the first run the agent registers with the server and persists the resulting `guid` and `token` under the same key automatically.

The CA certificate used to verify the server's TLS connection must be present at:
```
C:\Program Files\ProxyDLPAgent\mitmCA.pem
```

---

## 🚀 Usage

Open an elevated (Administrator) command prompt and run:

```powershell
# Normal run (or install as a Windows Service)
.\proxydlp.exe

# Deregister this agent and remove proxy settings
.\proxydlp.exe /deregister
```

The agent can also be installed and managed as a **Windows Service** via `sc.exe` or any service manager.

---

## ⚠️ Notes

* **Administrator privileges** are required to write to `HKLM` registry keys and to `C:\ProgramData\ProxyDLPAgent\`.
* Proxy settings are applied system-wide via the `HKLM\SOFTWARE\Policies\...` key, which takes precedence over per-user settings.
* Logs are written to `C:\trace.log`.

---

## 🧭 Contributing

Bug reports, issues, and pull requests are welcome. Please open issues or PRs in this repository and in the upstream server repository if the issue relates to server/client interaction.

---

## 📄 License

See the `LICENSE` file in this repository for licensing information.
