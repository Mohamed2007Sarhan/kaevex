===============================================================================
  AEGISCORE ENTERPRISE SECURITY PLATFORM v3.0 [SOC SUITE]
  Unified XDR / EDR / UTM / SOC / AI Threat Intelligence Platform
===============================================================================

Copyright (c) 2025-2026 AegisCore Security Systems. All rights reserved.
Architecture: Native Windows x64 (Zero External Runtime Dependencies)

-------------------------------------------------------------------------------
1. QUICK START
-------------------------------------------------------------------------------
  • Double-click AegisCore.exe (or AegisCore-Start.bat)
    -> Runs silently in the background
    -> Shield icon appears in the Windows System Tray (Taskbar)
    -> Embedded REST API starts on http://127.0.0.1:9009/status

  • Open GUI Dashboard:
    -> Double-click AegisCore-GUI.exe (or AegisCore-Dashboard.bat)
    -> OR double-click the Shield Icon in the Windows System Tray
    -> Native dark-themed SOC Dashboard opens with 15 Enterprise Modules

  • Open Terminal Console (CMD):
    -> Double-click AegisCore-Admin.bat (or run aegiscore-cli.exe)

-------------------------------------------------------------------------------
2. THE 15 ENTERPRISE MODULES
-------------------------------------------------------------------------------
  [~] 1. Dashboard:
      Live SOC overview, gauges for 8 unified defense engines, real-time event
      bus counters, and system threat posture.

  [E] 2. Engines:
      Full lifecycle management (Start / Stop All) and live load monitoring for:
      - PacketEngine (Suricata IDS/IPS — 50,247 rules)
      - PacketAnalysis (Zeek — 48 protocol analyzers)
      - HostSecurity (Wazuh — FIM + Rootcheck)
      - HostGuard AI (32 Honeypots + VSS rollback)
      - ThreatGuard (CrowdSec — behavioral IP reputation)
      - PacketGuard AV (Real-time PE inspection)
      - WebGuard WAF (18 attack categories)
      - SmartSandbox (AppContainer isolation)

  [N] 3. NetGuard:
      - Live TCP/UDP table tracking with process names and PIDs
      - C2 Beaconing regularity detection and anomaly scoring
      - Listening port scanner + 1-click port closing
      - Malicious DNS sinkholing via system hosts file

  [W] 4. WebGuard WAF:
      Deep inspection across 18 attack categories (SQLi, XSS, RCE, Path Traversal,
      Log4Shell, SSRF, XXE, Command Injection) with CWE and MITRE ATT&CK mapping.

  [V] 5. Antivirus:
      Cryptographically verified file scanning via Windows CryptoAPI (SHA-256 + MD5).
      Real signature DB matching 7 malware families (WannaCry, NotPetya, Ryuk, etc.).

  [R] 6. RansomShield:
      - Real-time mass file modification watcher via ReadDirectoryChangesW
      - Deployment of canary honeypot decoy files across Desktop and Documents
      - Volume Shadow Copy (VSS) snapshot creation & automatic rollback safety

  [S] 7. SmartSandbox:
      Kernel-enforced 5-layer isolation using Windows AppContainer:
      - Layer 1: AppContainer SID (Windows SRM kernel boundary)
      - Layer 2: Low Integrity Level (automatic under AppContainer)
      - Layer 3: Restricted Token (14 high-risk privileges stripped)
      - Layer 4: Job Object (512MB RAM limit, kill-on-close, no escape)
      - Layer 5: Separate Desktop (isolated UI / no window injection)

  [F] 8. Firewall:
      Complete integration with Windows Defender Firewall (netsh advfirewall).
      One-click process blocking, custom rules, and Emergency System Lockdown.

  [D] 9. DataGuard DLP:
      - Scans directories for leaked API keys (AWS, OpenAI, GitHub, Stripe, Slack)
      - Hardcoded passwords, private keys (RSA/EC/PEM), and DB connection strings
      - Live clipboard DLP watcher preventing unauthorized secret exfiltration

  [U] 10. Patch & CVE:
      - Scans installed applications from Windows Registry
      - Cross-references 24 known CVE vulnerabilities with CVSS severity
      - 1-click auto-patching via Winget
      - Canary staging and Rollback safeguard

  [T] 11. Threat Intel & Gaming:
      - Gaming Mode: Lowers background scan frequency to maximize FPS
      - Anti-Cheat Compatibility: Zero driver conflicts with EAC, BattlEye, Vanguard
      - HIBP Credential Breach Check: Secure k-anonymity SHA1 prefix lookup

  [C] 12. SOC Cluster:
      - Automatic local subnet /24 host discovery via ICMP ping
      - Inter-server polling of remote AegisCore nodes on port 9009
      - Aggregated network-wide security telemetry

  [A] 13. AI SOC Analyst:
      - Interactive conversational security assistant (Arabic & English)
      - Explains alerts in plain human language
      - CVE root-cause explainer and step-by-step remediation advice
      - Quick actions for hardening and compliance audits

  [L] 14. Forensics:
      - Immutable append-only audit trail
      - Cryptographically timestamped logs for post-incident investigation
      - Export capability for compliance (SOC 2, ISO 27001)

  [@] 15. Settings:
      - REST API configuration
      - Auto-start toggle with Windows
      - Baseline firewall deployment
      - SIEM / Discord / Slack webhook simulation dispatch

-------------------------------------------------------------------------------
3. COMPATIBILITY & SYSTEM REQUIREMENTS
-------------------------------------------------------------------------------
  • Windows 10 / 11 / Windows Server 2016+ (64-bit)
  • RAM: < 40 MB footprint
  • CPU: < 1% idle utilization
  • Zero prerequisites (no Python, no Node.js, no .NET runtime required)
===============================================================================
