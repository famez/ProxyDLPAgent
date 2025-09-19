# ProxyDLP Agent

**Status:** ✅ Stable (client / agent)

The **ProxyDLP Agent** is the Windows client component of the [ProxyDLP project](https://github.com/famez/ProxyDLP). The agent captures and forwards network traffic for analysis and policy enforcement by the ProxyDLP Server (see linked project). This repository contains the agent source, bundled helper libraries, and WinDivert artifacts required to run on Windows.

---

## 🔗 Related project

* **ProxyDLP Server** — [https://github.com/famez/ProxyDLP](https://github.com/famez/ProxyDLP) (server-side component). The server receives and processes traffic from this agent and enforces DLP policies.

---

## 📦 Dependencies

The agent depends on the following libraries (specific versions used/tested):

* **WinDivert** (driver + DLL) — *2.2.2* (WinDivert DLL/driver are included in this repo)
* **cURL** — *8.15.0*
* **cJSON** — *v1.7.18* (bundled directly in the source)
* **WinSock2** (Windows networking)
* **MinGW / GCC** — required to compile the project on Windows or for cross-compilation

> The required WinDivert DLL and driver files are present in this repository. Ensure you run the agent with administrator privileges so WinDivert can function correctly.

---

## 🛠 Build (recommended)

**Prerequisites**

* `make` (the included `Makefile` drives the build)
* A working C compiler (GCC or MinGW/MSYS2 for Windows builds)
* If cross-compiling from Linux to Windows: `mingw-w64` toolchain (e.g. `x86_64-w64-mingw32-gcc`)

**Build steps (recommended)**

From the repository root:

```bash
cd src/
make
```

The `Makefile` in `src/` will compile and link the agent for you (producing the Windows executable — e.g., `proxydlp.exe`). Use `make clean` if you want to remove build artifacts before rebuilding.

---

## 🚀 Usage

1. Start the **ProxyDLP Server** (see [https://github.com/famez/ProxyDLP](https://github.com/famez/ProxyDLP) for server setup and configuration).
2. On the client Windows machine, open an elevated (Administrator) command prompt or PowerShell.
3. Run the agent executable (example):

```powershell
# from the directory containing proxydlp.exe
.\proxydlp.exe
```

The agent will intercept traffic via WinDivert and communicate with the server for analysis and policy enforcement.

---

## ⚠️ Notes

* **Administrator privileges** are required to use WinDivert and install/load its driver.
* If the WinDivert driver needs to be installed or loaded, Windows may prompt for elevation or a reboot in some environments.
* The agent includes `cJSON` source directly; cURL and WinDivert binaries are expected to be present as shown in the repository.

---

## 🧭 Contributing

Bug reports, issues, and pull requests are welcome. Please open issues or PRs in this repository and in the upstream server repository if the issue relates to server/client interaction.

---

## 📄 License

See the `LICENSE` file in this repository for licensing information.
