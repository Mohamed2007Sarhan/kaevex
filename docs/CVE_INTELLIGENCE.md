# Autonomous CVE Intelligence & Real-Time Patch Agent

## Overview

Kaevex integrates an **Autonomous CVE Agent** (`upd_engine.h`) designed to deliver continuous vulnerability posture awareness for both the Windows Operating System and all installed third-party software.

---

## Capabilities

### 1. Operating System Build Audit
- Reads live Windows registry values (`CurrentBuild`, `UBR`, `DisplayVersion`, `ProductName`).
- Detects missing hotfixes and active OS-level zero-days (e.g., CVE-2024-38077 RDL RCE, CVE-2024-30078 Wi-Fi Driver RCE, CVE-2024-21307 Hyper-V DoS).
- Provides one-click automated mitigations (disabling vulnerable service endpoints, enforcing core isolation, or triggering Windows Update).

### 2. Live Software Inventory & 2024-2026 Catalog Matching
- Enumerates installed 32-bit and 64-bit software from:
  - `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`
  - `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`
- Parses semantic version numbers using `upd_ver_cmp`.
- Cross-references each installed application against the local dynamic database (`dist\data\cve_catalog.json`) containing recent high-severity CVEs for Git, Python, WinRAR, 7-Zip, Microsoft Office, Node.js, and Google Chrome.

### 3. Continuous Registry Watcher
- Background telemetry thread checks registry write timestamps every 30 seconds.
- When an application installation or update is detected, the agent immediately triggers an autonomous re-scan to re-evaluate system exposure without requiring user intervention.

### 4. AI-Powered CVE Remediation & Sandboxing
- **AI Fix CVEs (`IDU_AIFIX`)**: Dispatches the selected vulnerable item to the AI SOC Analyst, generating immediate patch instructions, configuration workarounds, and custom firewall block rules.
- **Sandbox & Update (`IDU_SANDBOX`)**: Immediately isolates the vulnerable application inside an AppContainer sandbox while simultaneously launching Windows Update or Winget to apply the vendor's patch safely.
