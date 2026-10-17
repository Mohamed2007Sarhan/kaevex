/*===========================================================================
 * Kaevex AI Team - team_checks.h
 * REAL host security checks (registry / services / sockets / Kaevex engines).
 * Each AI role receives the evidence for its own domain and can only propose
 * fixes by check ID. Fixes are a closed list implemented here, and each one is
 * verified by re-running the check afterwards.
 *===========================================================================*/
#pragma once
#ifndef TEAM_CHECKS_H
#define TEAM_CHECKS_H

enum { TC_PASS = 0, TC_FAIL = 1, TC_UNKNOWN = 2, TC_INFO = 3 };
typedef struct { char id[16]; char title[72]; int status; char evidence[200]; char fix[110]; int fixable; unsigned teams; } TcCheck;
#define TC_MAX 24
/* team bit masks: RED=1 BLUE=2 PURPLE=4 YELLOW=8 GREEN=16 */
#define TCT_RED 1
#define TCT_BLUE 2
#define TCT_PURPLE 4
#define TCT_YELLOW 8
#define TCT_GREEN 16

static BOOL tc_reg_dword(HKEY root, const char *key, const char *val, DWORD *out) {
    HKEY h; if (RegOpenKeyExA(root, key, 0, KEY_READ | KEY_WOW64_64KEY, &h) != ERROR_SUCCESS) return FALSE;
    DWORD sz = sizeof *out, t = 0; LONG rc = RegQueryValueExA(h, val, NULL, &t, (BYTE *)out, &sz); RegCloseKey(h);
    return rc == ERROR_SUCCESS && t == REG_DWORD;
}
static BOOL tc_reg_set(const char *key, const char *val, DWORD v) {
    HKEY h; if (RegCreateKeyExA(HKEY_LOCAL_MACHINE, key, 0, NULL, 0, KEY_SET_VALUE | KEY_WOW64_64KEY, NULL, &h, NULL) != ERROR_SUCCESS) return FALSE;
    LONG rc = RegSetValueExA(h, val, 0, REG_DWORD, (BYTE *)&v, sizeof v); RegCloseKey(h); return rc == ERROR_SUCCESS;
}
/* 1 running, 0 stopped, -1 unknown/not installed, plus start type (2 auto, 3 manual, 4 disabled) */
static int tc_service(const char *name, int *startType) {
    SC_HANDLE m = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT); if (!m) return -1;
    SC_HANDLE s = OpenServiceA(m, name, SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG); int r = -1;
    if (s) { SERVICE_STATUS st; if (QueryServiceStatus(s, &st)) r = st.dwCurrentState == SERVICE_RUNNING ? 1 : 0;
        if (startType) { BYTE buf[1024]; DWORD need; QUERY_SERVICE_CONFIGA *cfg = (QUERY_SERVICE_CONFIGA *)buf; if (QueryServiceConfigA(s, cfg, sizeof buf, &need)) *startType = (int)cfg->dwStartType; }
        CloseServiceHandle(s); }
    CloseServiceHandle(m); return r;
}

static void tc_set(TcCheck *c, const char *id, const char *title, int status, unsigned teams, const char *fix, int fixable, const char *fmt, ...) {
    memset(c, 0, sizeof *c); snprintf(c->id, sizeof c->id, "%s", id); snprintf(c->title, sizeof c->title, "%s", title); c->status = status; c->teams = teams; c->fixable = fixable;
    snprintf(c->fix, sizeof c->fix, "%s", fix ? fix : ""); va_list ap; va_start(ap, fmt); vsnprintf(c->evidence, sizeof c->evidence, fmt, ap); va_end(ap);
}

static int tc_run_all(TcCheck *o, int max) {
    int n = 0; DWORD v; (void)max;
    #define ADD(...) do { if (n < max) tc_set(&o[n++], __VA_ARGS__); } while (0)
    int fw = fwp_profiles_on();
    ADD("FW_ON", "Windows Firewall enabled on all profiles", fw == 7 ? TC_PASS : TC_FAIL, TCT_BLUE | TCT_GREEN | TCT_RED, "Turn the firewall on for all profiles", 1, "profiles on mask=%d (7 = domain+private+public)", fw);
    int st = 0; int def = tc_service("WinDefend", &st); DWORD dis = 0; BOOL pol = tc_reg_dword(HKEY_LOCAL_MACHINE, "SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection", "DisableRealtimeMonitoring", &dis);
    ADD("DEFENDER", "Microsoft Defender service running, real-time protection not disabled", (def == 1 && !(pol && dis)) ? TC_PASS : (def == -1 ? TC_UNKNOWN : TC_FAIL), TCT_BLUE | TCT_GREEN, "Re-enable Defender / check for a third-party AV", 0, "WinDefend service %s%s", def == 1 ? "running" : def == 0 ? "STOPPED" : "not found (third-party AV?)", (pol && dis) ? "; policy DISABLES real-time monitoring" : "");
    v = 0; BOOL luaHave = tc_reg_dword(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", "EnableLUA", &v);
    ADD("UAC", "User Account Control enabled", luaHave ? (v == 1 ? TC_PASS : TC_FAIL) : TC_UNKNOWN, TCT_GREEN | TCT_BLUE, "Enable UAC (reboot needed)", 1, luaHave ? "EnableLUA=%lu" : "EnableLUA not readable", (unsigned long)v);
    BOOL haveSmb = tc_reg_dword(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters", "SMB1", &v);
    ADD("SMB1", "SMBv1 server disabled", haveSmb ? (v == 0 ? TC_PASS : TC_FAIL) : TC_UNKNOWN, TCT_RED | TCT_GREEN, "Disable SMBv1 (EternalBlue-class exposure)", 1, haveSmb ? "SMB1=%lu" : "SMB1 value not set (default depends on Windows build/features)", (unsigned long)v);
    DWORD deny = 1, nla = 0; BOOL rdp = tc_reg_dword(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\Terminal Server", "fDenyTSConnections", &deny); BOOL hasNla = tc_reg_dword(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp", "UserAuthentication", &nla);
    ADD("RDP_NLA", "Remote Desktop off, or protected by Network Level Authentication", !rdp ? TC_UNKNOWN : (deny ? TC_PASS : (hasNla && nla ? TC_PASS : TC_FAIL)), TCT_RED | TCT_GREEN, "Require NLA for Remote Desktop", 1, "RDP %s, NLA %s", rdp ? (deny ? "disabled" : "ENABLED") : "unknown", hasNla ? (nla ? "required" : "NOT required") : "unknown");
    BOOL wd = tc_reg_dword(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest", "UseLogonCredential", &v);
    ADD("WDIGEST", "WDigest does not keep clear-text credentials in memory", (wd && v == 1) ? TC_FAIL : TC_PASS, TCT_RED | TCT_GREEN, "Set UseLogonCredential=0", 1, wd ? "UseLogonCredential=%lu" : "not set (modern default: off)", (unsigned long)v);
    BOOL llm = tc_reg_dword(HKEY_LOCAL_MACHINE, "SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient", "EnableMulticast", &v);
    ADD("LLMNR", "LLMNR name poisoning disabled", (llm && v == 0) ? TC_PASS : TC_FAIL, TCT_RED | TCT_BLUE, "Disable LLMNR via policy", 1, llm ? "EnableMulticast=%lu" : "policy not set (LLMNR active by default)", (unsigned long)v);
    BOOL ar = tc_reg_dword(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer", "NoDriveTypeAutoRun", &v);
    ADD("AUTORUN", "AutoRun disabled for all drive types", (ar && v == 255) ? TC_PASS : TC_FAIL, TCT_RED | TCT_GREEN, "Set NoDriveTypeAutoRun=255", 1, ar ? "NoDriveTypeAutoRun=%lu" : "policy not set", (unsigned long)v);
    BOOL ppl = tc_reg_dword(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\Lsa", "RunAsPPL", &v);
    ADD("LSA_PPL", "LSA runs as a protected process (credential theft hardening)", (ppl && v >= 1) ? TC_PASS : TC_FAIL, TCT_RED | TCT_GREEN, "Enable RunAsPPL (needs reboot; can be UEFI-locked) - manual", 0, ppl ? "RunAsPPL=%lu" : "RunAsPPL not set", (unsigned long)v);
    BOOL sb = tc_reg_dword(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State", "UEFISecureBootEnabled", &v);
    ADD("SECBOOT", "Secure Boot enabled", sb ? (v == 1 ? TC_PASS : TC_FAIL) : TC_UNKNOWN, TCT_GREEN | TCT_BLUE, "Enable Secure Boot in UEFI - manual", 0, sb ? "UEFISecureBootEnabled=%lu" : "not available (legacy BIOS or no access)", (unsigned long)v);
    int wst = 0; int wu = tc_service("wuauserv", &wst);
    ADD("WUPDATE", "Windows Update service not disabled", (wu >= 0 && wst != 4) ? TC_PASS : (wu < 0 ? TC_UNKNOWN : TC_FAIL), TCT_GREEN | TCT_YELLOW, "Set the Windows Update service back to manual/automatic", 0, "wuauserv start type %d", wst);
    BOOL lg = tc_reg_dword(HKEY_LOCAL_MACHINE, FWP_POLICY_KEY "\\StandardProfile\\Logging", "LogDroppedPackets", &v);
    ADD("FW_LOG", "Firewall logs dropped connections (needed for forensics)", (lg && v == 1) ? TC_PASS : TC_FAIL, TCT_BLUE | TCT_PURPLE, "Enable firewall logging", 1, lg ? "LogDroppedPackets=%lu" : "not enabled", (unsigned long)v);

    /* exposed listeners from the live socket table */
    static FwpLive live[FWP_MAX_LIVE]; int nl = fwp_live_snapshot(live, FWP_MAX_LIVE, FALSE);
    static const int risky[] = { 21, 23, 69, 135, 139, 445, 1433, 3306, 3389, 5900, 5985, 5986 }; char ex[200] = ""; int nex = 0;
    for (int i = 0; i < nl; i++) { FwpLive *L = &live[i]; if (!L->inbound || L->proto != FWP_TCP || strncmp(L->localIp, "127.", 4) == 0 || strcmp(L->localIp, "::1") == 0) continue;
        for (unsigned k = 0; k < sizeof risky / sizeof *risky; k++) if (L->localPort == risky[k]) { if (strlen(ex) < 150) snprintf(ex + strlen(ex), sizeof ex - strlen(ex), "%s:%d ", L->proc, L->localPort); nex++; break; } }
    ADD("EXPOSED", "No risky services listening on the network", nex ? TC_FAIL : TC_PASS, TCT_RED | TCT_BLUE, "Close or firewall the listed ports", 0, nex ? "%d risky listener(s): %s" : "none of the common risky ports is listening on a non-loopback address", nex, ex);
    int susp = 0; if (g_netCSInit) EnterCriticalSection(&g_netCS); for (int i = 0; i < g_netConnCnt; i++) if (g_netConns[i].suspicious) susp++; if (g_netCSInit) LeaveCriticalSection(&g_netCS);
    ADD("NET_SUSP", "No connections flagged suspicious by NetGuard", susp ? TC_FAIL : TC_PASS, TCT_BLUE | TCT_PURPLE, "Investigate flagged connections in NetGuard", 0, "%d of %d connections flagged", susp, g_netConnCnt);
    LedgerVerdict lv; threat_ledger_verify(&lv);
    ADD("LEDGER", "Forensics log integrity (HMAC chain)", lv.state == LEDGER_OK ? TC_PASS : (lv.state == LEDGER_NOCHAIN ? TC_INFO : TC_FAIL), TCT_BLUE | TCT_PURPLE | TCT_GREEN, "Investigate: log was modified or truncated", 0, "%s", lv.why);
    ADD("TAMPER", "Kaevex firewall tamper protection running", fwp_watch_running() ? TC_PASS : TC_FAIL, TCT_PURPLE | TCT_BLUE, "Start tamper protection in Firewall Pro > Protection", 0, "tamper watch %s", fwp_watch_running() ? "running" : "not running");
    { int kevN = 0, hi = 0, un = 0; for (int i = 0; i < g_cviFindN; i++) { if (g_cviFind[i].conf >= CVI_MED) { hi++; if (g_cviCves[g_cviFind[i].cve].kev) kevN++; if (g_cviFind[i].status != CVS_FIXED) un++; } }
      ADD("CVE_KEV", "No unpatched software with actively exploited CVEs (CISA KEV)", g_cviKevN == 0 ? TC_UNKNOWN : (kevN && un ? TC_FAIL : TC_PASS), TCT_YELLOW | TCT_GREEN | TCT_RED, "Open CVE Intelligence and fix / contain", 0, g_cviKevN == 0 ? "CVE scan not run yet" : "%d matched finding(s), %d actively exploited, %d unresolved", hi, kevN, un); }
    #undef ADD
    return n;
}

static const char *tc_status_name(int s) { return s == TC_PASS ? "PASS" : s == TC_FAIL ? "FAIL" : s == TC_INFO ? "INFO" : "UNKNOWN"; }

/* Evidence block for one role (0 RED .. 4 GREEN): only checks relevant to its domain. */
static void tc_team_report(int team, char *out, size_t n) {
    static TcCheck c[TC_MAX]; int nc = tc_run_all(c, TC_MAX); unsigned bit = 1u << team; size_t w = 0; int pass = 0, fail = 0;
    w += (size_t)snprintf(out + w, n - w, "REAL CHECK RESULTS for your role (collected just now on this PC):\n");
    for (int i = 0; i < nc && w + 260 < n; i++) {
        if (!(c[i].teams & bit)) continue;
        if (c[i].status == TC_PASS) pass++; else if (c[i].status == TC_FAIL) fail++;
        int fx = (c[i].status == TC_FAIL && c[i].fixable);
        w += (size_t)snprintf(out + w, n - w, "- [%s] %s: %s%s%s%s\n", c[i].id, tc_status_name(c[i].status), c[i].evidence, fx ? " (fixable by Kaevex: /fix " : "", fx ? c[i].id : "", fx ? ")" : "");
    }
    snprintf(out + w, n - w, "Summary: %d passed, %d failed. You may recommend '/fix <ID>' only for items marked fixable; never invent other commands.\n", pass, fail);
}

/* Whitelisted fixes. Returns TRUE only if the re-run check passes afterwards. */
static BOOL tc_fix(const char *id, char *msg, size_t mn) {
    if (!fwp_is_admin()) { snprintf(msg, mn, "Administrator rights are required."); return FALSE; }
    BOOL did = FALSE;
    if (_stricmp(id, "FW_ON") == 0) did = fwp_netsh("advfirewall set allprofiles state on", NULL, 0, 15000) == 0;
    else if (_stricmp(id, "FW_LOG") == 0) did = fwp_enable_logging();
    else if (_stricmp(id, "WDIGEST") == 0) did = tc_reg_set("SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest", "UseLogonCredential", 0);
    else if (_stricmp(id, "LLMNR") == 0) did = tc_reg_set("SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient", "EnableMulticast", 0);
    else if (_stricmp(id, "AUTORUN") == 0) did = tc_reg_set("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer", "NoDriveTypeAutoRun", 255);
    else if (_stricmp(id, "SMB1") == 0) did = tc_reg_set("SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters", "SMB1", 0);
    else if (_stricmp(id, "RDP_NLA") == 0) did = tc_reg_set("SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp", "UserAuthentication", 1);
    else if (_stricmp(id, "UAC") == 0) did = tc_reg_set("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", "EnableLUA", 1);
    else { snprintf(msg, mn, "'%.20s' is not a fixable check (allowed: FW_ON FW_LOG WDIGEST LLMNR AUTORUN SMB1 RDP_NLA UAC).", id); return FALSE; }
    if (!did) { snprintf(msg, mn, "%s: the change could not be written.", id); return FALSE; }
    static TcCheck c[TC_MAX]; int nc = tc_run_all(c, TC_MAX);
    for (int i = 0; i < nc; i++) if (_stricmp(c[i].id, id) == 0) {
        if (c[i].status == TC_PASS) { snprintf(msg, mn, "%s FIXED (verified): %s", id, c[i].evidence); return TRUE; }
        snprintf(msg, mn, "%s was changed but the check still fails: %s%s", id, c[i].evidence, (!_stricmp(id, "UAC") || !_stricmp(id, "SMB1")) ? " (a reboot/service restart may be required)" : ""); return FALSE; }
    snprintf(msg, mn, "%s: applied, but the check could not be re-run.", id); return FALSE;
}

#endif /* TEAM_CHECKS_H */
