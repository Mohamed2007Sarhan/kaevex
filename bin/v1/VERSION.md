# AegisCore v1 Release Notes

**Version:** 1.0.0-v1-test  
**Release Date:** 2025  
**Build Type:** Test / Pre-Production  
**Copyright:** 2025 AegisCore Security Systems. All rights reserved.

---

## v1 Test Build — Contents

```
bin/v1/
  AegisCore-v1-Start.bat   <- MAIN LAUNCHER (double-click to start)
  mock-backend.js          <- API simulation server (port 9009)
  serve-dashboard.js       <- Production static file server (port 3000)
  dashboard/               <- Built React frontend (production bundle)
    index.html
    assets/
      index.js             <- Main app bundle (154 KB)
      react.js             <- React runtime (138 KB)
      icons.js             <- Lucide icon set (23 KB)
      index.css            <- Stylesheet (10 KB)
  logs/                    <- Runtime logs written here
  VERSION                  <- This file
```

---

## How to Run (v1 Test)

**Fastest way:**
```
Double-click: AegisCore-v1-Start.bat
```

The launcher will:
1. Detect if real fire-engine backend is running on port 9009
2. If YES → connect to real backend
3. If NO  → start mock-backend.js (simulates all 8 engines)
4. Start serve-dashboard.js (serves built frontend)
5. Open browser to http://localhost:3000

---

## Mock Backend Behavior

When the real C backend is not compiled/running, `mock-backend.js` provides:

| Endpoint Group | Description |
|---|---|
| `/api/v1/status` | Platform info, engine status, uptime |
| `/api/v1/stats` | All engine counters (live, updated every 3s) |
| `/api/v1/alerts` | Ring buffer — new alert every 8 seconds |
| `/api/v1/blocks` | Banned IPs (ban/unban fully functional) |
| `/api/v1/incidents` | Attack incidents — new one every 30 seconds |
| `/api/v1/sessions` | Attack sessions derived from incidents |
| `/api/v1/ioc` | IOC database (add IOC fully functional) |
| `/api/v1/av/*` | AV engine stats + processes |
| `/api/v1/waf/*` | WAF stats, rules, captures, profile switching |
| `/api/v1/sandbox/*` | Sandbox instances + proxy logs |
| `/api/v1/hostguard/*` | HostGuard stats, threads, CVEs, updates, honeypots |
| `/api/v1/integration/stats` | Cross-engine wiring counters |

---

## Tested Pages (v1)

All 21 pages functional with live data:

| Page | Data Source |
|---|---|
| Dashboard | status + stats + alerts |
| Intrusion | alerts ring buffer |
| Host Security | hostguard threads + stats |
| Request Analysis | WAF captures + rules |
| Sandbox | sandbox list + proxy logs |
| Incidents | incidents + sessions |
| Threat Intel | IOC database + blocked IPs |
| Vulnerabilities | CVE report + components |
| Monitoring | all engine stats |
| Analytics | aggregated stats |
| Network | sessions + bus events |
| Update Center | update report |
| Assets | software components |
| Reports | exported JSON report |
| Notifications | alert feed |
| Automation | local rules (no backend needed) |
| AI Agent | visible, backend coming in v2 |
| Settings | WAF profile + AV + system config |
| Search | search across all live data |
| Audit Logs | local operator action log |
| Organizations | placeholder (v2) |

---

## Known v1 Limitations

- Real fire-engine C backend NOT compiled (Windows build system required)
- Mock backend resets on restart (no persistence)
- AI Agent backend not implemented (shows "Coming Soon")
- Organizations page placeholder only
- No authentication (v2 feature)
- No HTTPS (v2 feature)

---

## Next Step: v2

- Compile the real fire-engine backend (Linux target with cmake/autotools)
- Connect real Suricata packet capture engine
- Add authentication layer (JWT)
- Add HTTPS/TLS for the dashboard
- Package as Windows Service
