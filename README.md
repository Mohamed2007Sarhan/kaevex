# Kaevex Security Platform v1.0 [SOC Enterprise]

[![Platform](https://img.shields.io/badge/Platform-Windows%2010%20%2F%2011%20%2F%20Server-0078D6?logo=windows&logoColor=white)](https://github.com/kaevex/fire)
[![Architecture](https://img.shields.io/badge/Architecture-x86__64%20Native%20Win32-blue.svg)](https://github.com/kaevex/fire)
[![Language](https://img.shields.io/badge/Language-Pure%20C11%20%2F%20Win32%20API-brightgreen.svg)](https://github.com/kaevex/fire)
[![Dependencies](https://img.shields.io/badge/Dependencies-Zero%20External%20Runtimes-success.svg)](https://github.com/kaevex/fire)
[![Version](https://img.shields.io/badge/Release-v1.0.0--PROD-red.svg)](https://github.com/kaevex/fire)

**Kaevex Security Platform v1.0** is an experimental native Win32/C security application. It is not yet a validated enterprise SOC or release-ready endpoint protection product.

> **Release status:** Review builds have been compiled, but full end-to-end GUI and machine-level validation has not been completed. Modules are a mixture of working local workflows and unavailable integrations; the interface must not be interpreted as proof of protection. Read the feature limitations below and the linked setup guides before use.

Kaevex's native Windows components do not require Python, JVM, or .NET runtimes. SmartSandbox requires a separate Sandboxie-Plus installation; other engines use Windows APIs including CryptoAPI/BCrypt, IP Helper, WFP, AppContainer, VSS, and WinHTTP.

---

## Implemented workflows and current limits

- **Patch & CVE:** inventories installed applications, fetches recent NVD advisories, and can request targeted `winget` upgrades for configured local catalog matches. NVD results are not product/version matched and cannot trigger Auto-Fix. This is not a complete vulnerability scanner; see [CVE coverage and remediation limits](docs/CVE_INTELLIGENCE.md).
- **SmartSandbox:** starts an existing EXE in an installed Sandboxie-Plus box and fails closed when its configured checks fail. MSI is unsupported. Per-process file, network, and API telemetry is unavailable; this is not a VM boundary. See [SmartSandbox setup and limits](docs/SMARTSANDBOX.md).
- **RansomShield:** filesystem monitoring and honeypot deployment are manual actions. VSS snapshot creation can be requested, but snapshot restoration is not implemented. No protection starts merely because the GUI opens.
- **Defense Engines:** workflows are invoked on demand. This build has no per-engine service-health controller, so the UI does not claim that all engines are online.
- **Full Team:** dispatches text-only role prompts to a configured AI provider. Agents do not run scans, inspect files, or apply fixes; all test findings must come from separate tool output.
- **Host and network views:** display locally observable counters where available. Geolocation attack feeds and several external detection integrations are not connected.

---

## Platform Architecture

```
                                  +-------------------------------------------------------------+
                                  |            KAEVEX SECURITY PLATFORM v1.0 (GUI / CLI)        |
                                  +-------------------------------------------------------------+
                                                                 |
               +-----------------------+-------------------------+-----------------------+
               |                       |                         |                       |
     [ DEFENSE ENGINES ]        [ AI OPERATIONS ]         [ THREAT & SANDBOX ]    [ NETWORK & OS ]
     - PacketEngine (Suricata)  - Full Team AI (Groq)     - SmartSandbox (AppCtr) - Adaptive Firewall (WFP)
     - PacketAnalysis (Zeek)    - AI SOC Copilot (Kimi)   - RansomShield & VSS    - NetGuard Traffic & Ports
     - HostSecurity (Wazuh)     - On-Device SOC Fallback  - PacketGuard AV        - DNS Sinkhole Engine
     - CrowdSec ThreatGuard     - Automated Remediation   - Anti-Cheat Intel      - SOC Cluster Mesh (9009)
               |                       |                         |                       |
               +-----------------------+-------------------------+-----------------------+
                                                                 |
                                  +-------------------------------------------------------------+
                                  |     WINDOWS NT KERNEL & WIN32 APIS (Pure Native / 0-Deps)    |
                                  |     CryptoAPI | WFP | IP Helper | VSS | Sandboxie-Plus | DWM |
                                  +-------------------------------------------------------------+
```

---

## Directory Structure

```
c:\Users\Moham\Desktop\keavex\fire\
│
├── dist\                           # Compiled production binaries & assets
│   ├── Kaevex-GUI.exe              # Primary high-performance SOC GUI application
│   ├── kaevex-cli.exe              # Standalone interactive CLI & management shell
│   ├── kaevex-engine.exe           # Headless background defense engine service
│   ├── kaevex-tray.exe             # Native Windows system tray daemon
│   └── data\
│       ├── cve_catalog.json        # 2024-2026 CVE vulnerability database
│       └── kaevex_cve_catalog.json
│
├── src\                            # Complete native C source code
│   ├── gui\
│   │   └── kaevex-gui.c            # Master Win32 GDI/DWM SOC GUI (15 tabs)
│   ├── engines\                    # Modular defense sub-engine headers
│   │   ├── fw_engine.h             # Adaptive Firewall & Netsh controller
│   │   ├── net_engine.h            # NetGuard traffic, port binding & DNS sinkhole
│   │   ├── ransom_engine.h         # RansomShield, canary honeypots & VSS
│   │   ├── sbx_engine.h            # SmartSandbox Sandboxie-Plus integration
│   │   ├── soc_engine.h            # Inter-server discovery & cryptographic mesh
│   │   ├── threat_engine.h         # Gaming detection, FPS boost & forensics
│   │   ├── upd_engine.h            # Autonomous CVE agent & software inventory
│   │   └── data_engine.h           # Data leak inspection & memory hygiene
│   ├── cli\
│   │   └── kaevex-cli.c            # Standalone terminal defense console
│   ├── tray\
│   │   └── kaevex-tray.c           # System tray background controller
│   └── kaevex-engine.c             # Standalone console engine entry point
│
├── kaevex\                         # Deep Packet Inspection & Network IDS subsystem
│   ├── src\                        # Core DPI packet filtering sources
│   ├── rules\                      # Suricata / Snort signature definitions
│   ├── etc\                        # Suricata YAML configuration templates
│   ├── ebpf\                       # eBPF kernel packet bypass scripts
│   ├── host-security\              # Wazuh host compliance integration
│   ├── threat-guard\               # CrowdSec reputation feeds
│   └── packet-analysis\            # Zeek protocol parsers
│
├── web-dashboard\                  # Modern React / TypeScript / Vite Web UI
│   ├── src\                        # Frontend components & Tailwind styles
│   ├── mock-backend.js             # Local development REST mock server
│   └── package.json                # Frontend build configuration
│
├── scripts\                        # Administrative automation & build tools
│   ├── build.bat                   # Full automated build script
│   ├── Kaevex-Admin.bat            # UAC-elevated launcher
│   ├── Kaevex-Start.bat            # Quick launcher
│   └── Kaevex-Dashboard.bat        # Web dashboard launcher
│
├── docs\                           # Detailed technical documentation
│   ├── ARCHITECTURE.md             # In-depth subsystem architectural breakdown
│   ├── FULL_TEAM.md                # Guide to the 5-team Groq AI operations center
│   ├── CVE_INTELLIGENCE.md         # Vulnerability watcher & auto-remediation guide
│   └── CHANGELOG.md                # Release notes and version history
│
├── logs\                           # Forensic audit logs & incident reports
│   └── forensics.log               # Append-only tamper-evident audit trail
│
├── config\                         # Configuration templates and baselines
├── assets\                         # Icons, UI mockups, and visual assets
├── build.bat                       # Root build shortcut
├── Kaevex-Admin.bat                # Root elevated runner
├── Kaevex-Start.bat                # Root quick runner
└── README.md                       # Master platform documentation
```

---

## 15 Interactive GUI Operations Tabs

| Tab | Name | Operational Capabilities |
|:---:|:---|:---|
| 01 | **Support Dashboard** | Real-time dual-line bandwidth charts (inbound/outbound), packet drop metrics, health status, and live incident alert feed. |
| 02 | **Defense Engines** | Individual state toggle and real-time CPU/memory load monitoring for all 8 active defense engines. |
| 03 | **NetGuard Traffic** | TCP/UDP socket enumeration, active connection map, port listener scanner, 1-click port blocker, and DNS sinkholing (`0.0.0.0`). |
| 04 | **WebGuard WAF** | 18-category real-time payload inspector defending against SQLi, XSS, RCE, Path Traversal, SSRF, and command injection. |
| 05 | **Antivirus Core** | Real-time CryptoAPI SHA-256 and MD5 hashing, heuristic PE header analyzer, file reputation checking, and hourly automated scanning. |
| 06 | **RansomShield** | Autonomous honeypot canary deployment (`KaevexDecoy_*.docx`), file-modification tripwire, and VSS Shadow Copy snapshots. |
| 07 | **SmartSandbox** | Sandboxie-Plus persistent EXE boxes, WFP network deny rule, reduced admin rights, and desktop shortcuts. MSI is disabled in hardened mode; Sandboxie-Plus must be installed separately. |
| 08 | **Adaptive Firewall** | Windows Defender Firewall integration, 1-click Emergency Lockdown, automated baseline rules, and custom port filters. |
| 09 | **Patch & CVE Agent** | OS build identification, installed software inventory, continuous Registry change watcher, 1-click AI Fix, and Sandboxing. |
| 10 | **Gaming & Threat** | Anti-cheat compatibility monitor (Vanguard/BattlEye/EAC), game process detector (CS2, Valorant, GTA V), and FPS priority booster. |
| 11 | **SOC Cluster Mesh** | LAN `/24` subnet host scanner, cryptographic key pairing (`KAEVEX-*-MESH`), node latency ping, and distributed status sharing. |
| 12 | **AI SOC Analyst** | Conversational cybersecurity assistant powered by NVIDIA Kimi-K3 cloud inference with automated 2s fallback to local SOC rules. |
| 13 | **Forensics Audit** | Append-only, tamper-evident forensic log viewer with instant search, timestamping, and export functionality. |
| 14 | **Settings & Acc** | REST API port configuration, Windows autostart registry toggle, Discord/SIEM webhook dispatcher, and profile management. |
| 15 | **Full Team** | Multi-agent AI operations center (Red, Blue, Purple, Yellow, Green teams) powered by Groq `llama-3.3-70b-versatile`. |

---

## Building from Source

### Prerequisites
- **Operating System**: Windows 10, Windows 11, or Windows Server 2016+ (64-bit).
- **Compiler**: MinGW-W64 GCC (v11.0 or newer recommended). A standalone GCC distribution is supported out-of-the-box via `C:\GCC`.
- **Libraries**: Native Windows SDK libraries linked automatically (`comctl32`, `ws2_32`, `iphlpapi`, `shell32`, `ole32`, `crypt32`, `psapi`, `dwmapi`, `uxtheme`, `winhttp`, `shlwapi`, `ntdll`, `advapi32`, `user32`, `gdi32`).

### Quick Build
Simply double-click [`build.bat`](file:///c:/Users/Moham/Desktop/keavex/fire/build.bat) in the project root, or execute via terminal:

```cmd
cd /d "c:\Users\Moham\Desktop\keavex\fire"
build.bat
```

The script compiles:
1. `dist\Kaevex-GUI.exe` (Win32 Standalone GUI application)
2. `dist\kaevex-cli.exe` (Command-line defense shell)
3. Synchronizes outputs to `release\` for seamless distribution.

---

## Running Kaevex

### GUI Dashboard (Recommended)
Run with elevated privileges to allow firewall rule enforcement, AppContainer creation, and VSS shadow copy management:
- Right-click [`Kaevex-Admin.bat`](file:///c:/Users/Moham/Desktop/keavex/fire/Kaevex-Admin.bat) and select **Run as Administrator**, or double-click [`Kaevex-Start.bat`](file:///c:/Users/Moham/Desktop/keavex/fire/Kaevex-Start.bat).

### Command-Line Interface (CLI)
Open a command prompt in `dist\` or use the root shortcut:

```cmd
dist\kaevex-cli.exe status       # Display health status of all 9 defense components
dist\kaevex-cli.exe scan C:\Path # Run real-time CryptoAPI SHA-256/MD5 malware scan
dist\kaevex-cli.exe waf "<test>" # Test payload against all 18 WAF attack categories
dist\kaevex-cli.exe firewall     # View active firewall rules and baseline status
dist\kaevex-cli.exe interactive  # Launch interactive real-time SOC command console
```

---

## License & Intellectual Property

Copyright (c) 2025-2026 **Kaevex Cyber Systems**. All Rights Reserved.  
Engineered for mission-critical enterprise resilience, private cloud infrastructure, and hardened endpoint defense.
