# Kaevex System Architecture & Engineering Specifications (v1.0)

## Architectural Principles

Kaevex is engineered with a strict **Zero-Runtime-Dependency** design philosophy:
1. **100% Native Win32 / C11**: No Electron, no WebViews, no .NET CLR, no JVM, and no Python runtimes required.
2. **Deterministic Memory Footprint**: Less than 35 MB of RAM under full enterprise load.
3. **Lock-Free Zero-Copy Ring Buffers**: Real-time packet and event telemetry streams without dynamic allocation bottlenecks.
4. **Kernel-Level Enforcement**: Native integration with Windows AppContainer isolation, Windows Filtering Platform (WFP), CryptoAPI/CNG, and Volume Shadow Copy (VSS).

---

## The 8 Core Defense Engines

```
+-------------------------------------------------------------------------------+
|                        KAEVEX UNIFIED DEFENSE CORE                            |
+-------------------------------------------------------------------------------+
  |
  +--> 1. PacketEngine (Suricata Core)
  |      DPI multi-threaded network inspection, 50,000+ protocol rules.
  |
  +--> 2. PacketAnalysis (Zeek Core)
  |      48 protocol parsers, JA3/JA4 TLS fingerprinting, anomaly extraction.
  |
  +--> 3. HostSecurity (Wazuh Core)
  |      File Integrity Monitoring (FIM), SCA compliance, rootcheck routines.
  |
  +--> 4. HostGuard & RansomShield
  |      Canary honeypot file tripwires, mass-encryption detection, automated VSS.
  |
  +--> 5. ThreatGuard (CrowdSec Core)
  |      Behavioral leaky-bucket IP reputation, dynamic blocking, C2 sinkhole.
  |
  +--> 6. PacketGuard AV
  |      CryptoAPI SHA-256/MD5 hashing, PE header heuristic parsing, hourly scans.
  |
  +--> 7. WebGuard WAF
  |      18 attack categories (SQLi, XSS, RCE, Path Traversal, SSRF, Deserialization).
  |
  +--> 8. SmartSandbox
         AppContainer isolation, low-integrity tokens, restricted desktop sessions.
```

---

## Subsystem Details

### 1. PacketGuard AV (`av_scan_file`)
- Utilizes `CryptAcquireContext`, `CryptCreateHash(CALG_SHA_256)`, and `CryptCreateHash(CALG_MD5)`.
- Hashes 64 KB streamed chunks deterministically with zero memory allocation.
- Hourly background worker automatically audits `C:\Windows\System32`, `C:\Program Files`, and `C:\Program Files (x86)`.

### 2. SmartSandbox (`sbx_engine.h`)
- Leverages `CreateAppContainerProfile` to configure a sandboxed execution boundary.
- Applies `SID_AND_ATTRIBUTES` capabilities restricting access to network sockets, local file writing, and device interfaces.
- Assigns target processes to a dedicated Windows Job Object with memory caps and process creation flags disabled (`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`).

### 3. RansomShield (`ransom_engine.h`)
- Automatically plants honeypot documents (`KaevexDecoy_*.docx`) in monitored directory trees.
- Background worker continuously checks file integrity and size changes using `FindFirstChangeNotificationW`.
- If tampering or rapid file extension alteration is detected, the engine halts the attacking PID and executes `vssadmin create shadow /for=C:` to secure system recovery points.

### 4. Adaptive Firewall (`fw_engine.h`)
- Interfaces directly with `INetFwPolicy2` COM interfaces and `netsh advfirewall`.
- Enforces baseline dropped-packet telemetry and provides emergency one-click network isolation.

### 5. Multi-Server SOC Cluster Mesh (`soc_engine.h`)
- Scans the local `/24` subnet using fast non-blocking WinSock connections on TCP port 9009.
- Performs cryptographic handshake validation using cluster pairing tokens (`KAEVEX-*-MESH`).
- Computes latency ping telemetry and exchanges active threat intelligence across all nodes.
