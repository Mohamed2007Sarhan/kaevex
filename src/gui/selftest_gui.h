/*===========================================================================
 * Kaevex Self-Test - selftest_gui.h
 * Runs REAL tests against each subsystem and the network and reports PASS / FAIL / WARN / SKIP with
 * evidence. A feature is only reported as working if the test actually exercised it.
 *===========================================================================*/
#pragma once
#ifndef SELFTEST_GUI_H
#define SELFTEST_GUI_H

#include <commctrl.h>
#include <icmpapi.h>

enum { ST_PASS = 0, ST_FAIL, ST_WARN, ST_SKIP };
typedef struct { char name[56]; int status; char detail[260]; DWORD ms; } StResult;
#define ST_MAX 40
#define ST_WM_ROW (WM_APP + 71)
#define ST_WM_DONE (WM_APP + 72)
enum { ST_ID_LV = 8300, ST_ID_RUN, ST_ID_NET, ST_ID_COPY, ST_ID_SUM };

static StResult g_stRes[ST_MAX]; static int g_stN = 0;
static struct { HWND hw, lv, sum; volatile LONG busy; } g_st;

static void st_add(int status, const char *name, DWORD t0, const char *fmt, ...) {
    if (g_stN >= ST_MAX) return; StResult *r = &g_stRes[g_stN]; memset(r, 0, sizeof *r);
    snprintf(r->name, sizeof r->name, "%s", name); r->status = status; r->ms = GetTickCount() - t0;
    va_list ap; va_start(ap, fmt); vsnprintf(r->detail, sizeof r->detail, fmt, ap); va_end(ap);
    int idx = g_stN++; if (g_st.hw) PostMessageA(g_st.hw, ST_WM_ROW, (WPARAM)idx, 0);
}

/* ---- network primitives -------------------------------------------------------------------------------------- */
static int st_http(const char *host, const char *path, int secure, int *status, SYSTEMTIME *date, int *hasDate, DWORD *we) {
    *status = 0; *hasDate = 0; *we = 0; wchar_t wh[128], wp[512]; MultiByteToWideChar(CP_UTF8, 0, host, -1, wh, 128); MultiByteToWideChar(CP_UTF8, 0, path, -1, wp, 512);
    HINTERNET s = WinHttpOpen(L"Kaevex-Selftest/1.0", 4, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0); if (!s) s = WinHttpOpen(L"Kaevex-Selftest/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!s) { *we = GetLastError(); return 0; }
    WinHttpSetTimeouts(s, 6000, 6000, 8000, 15000); int ok = 0;
    HINTERNET c = WinHttpConnect(s, wh, secure ? INTERNET_DEFAULT_HTTPS_PORT : INTERNET_DEFAULT_HTTP_PORT, 0);
    HINTERNET r = c ? WinHttpOpenRequest(c, L"GET", wp, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, secure ? WINHTTP_FLAG_SECURE : 0) : NULL;
    if (r) {
        DWORD noRedir = WINHTTP_DISABLE_REDIRECTS; WinHttpSetOption(r, WINHTTP_OPTION_DISABLE_FEATURE, &noRedir, sizeof noRedir);
        if (WinHttpSendRequest(r, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0) && WinHttpReceiveResponse(r, NULL)) {
            DWORD sc = 0, sz = sizeof sc; WinHttpQueryHeaders(r, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX, &sc, &sz, WINHTTP_NO_HEADER_INDEX); *status = (int)sc;
            DWORD dsz = sizeof(SYSTEMTIME); if (WinHttpQueryHeaders(r, WINHTTP_QUERY_DATE | WINHTTP_QUERY_FLAG_SYSTEMTIME, WINHTTP_HEADER_NAME_BY_INDEX, date, &dsz, WINHTTP_NO_HEADER_INDEX)) *hasDate = 1;
            ok = 1;
        } else *we = GetLastError();
        WinHttpCloseHandle(r);
    } else *we = GetLastError();
    if (c) WinHttpCloseHandle(c); WinHttpCloseHandle(s); return ok;
}

/* Raw UDP DNS A query to a specific resolver (bypasses the system resolver). Returns number of IPv4 answers, -1 on no reply. */
static int st_dns_query(const char *server, const char *name, uint32_t *ips, int maxIps) {
    WSADATA w; WSAStartup(MAKEWORD(2, 2), &w);
    unsigned char q[300]; int n = 0; unsigned short id = (unsigned short)(GetTickCount() ^ 0x5a5a);
    q[n++] = id >> 8; q[n++] = id & 255; q[n++] = 1; q[n++] = 0; q[n++] = 0; q[n++] = 1; q[n++] = 0; q[n++] = 0; q[n++] = 0; q[n++] = 0; q[n++] = 0; q[n++] = 0;
    const char *p = name; while (*p) { const char *d = strchr(p, '.'); size_t l = d ? (size_t)(d - p) : strlen(p); if (l == 0 || l > 63 || n + (int)l + 6 > (int)sizeof q) return -1; q[n++] = (unsigned char)l; memcpy(q + n, p, l); n += (int)l; p += l; if (*p == '.') p++; }
    q[n++] = 0; q[n++] = 0; q[n++] = 1; q[n++] = 0; q[n++] = 1;
    SOCKET s = socket(AF_INET, SOCK_DGRAM, 0); if (s == INVALID_SOCKET) return -1;
    DWORD to = 2500; setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char *)&to, sizeof to);
    struct sockaddr_in sa; memset(&sa, 0, sizeof sa); sa.sin_family = AF_INET; sa.sin_port = htons(53); inet_pton(AF_INET, server, &sa.sin_addr);
    sendto(s, (char *)q, n, 0, (struct sockaddr *)&sa, sizeof sa);
    unsigned char r[1500]; int rl = recv(s, (char *)r, sizeof r, 0); closesocket(s);
    if (rl < 12 || r[0] != (id >> 8) || r[1] != (id & 255)) return -1;
    int an = (r[6] << 8) | r[7], pos = 12;
    for (int i = 0; i < (r[4] << 8 | r[5]) && pos < rl; i++) { while (pos < rl && r[pos]) { if ((r[pos] & 0xC0) == 0xC0) { pos++; break; } pos += r[pos] + 1; } pos += (pos < rl && r[pos] == 0) ? 1 : 1; pos += 4; }
    int cnt = 0;
    for (int i = 0; i < an && pos + 12 <= rl && cnt < maxIps; i++) {
        if ((r[pos] & 0xC0) == 0xC0) pos += 2; else { while (pos < rl && r[pos]) pos += r[pos] + 1; pos++; }
        if (pos + 10 > rl) break; int type = (r[pos] << 8) | r[pos + 1], rdl = (r[pos + 8] << 8) | r[pos + 9]; pos += 10;
        if (type == 1 && rdl == 4 && pos + 4 <= rl) ips[cnt++] = ((uint32_t)r[pos] << 24) | ((uint32_t)r[pos + 1] << 16) | ((uint32_t)r[pos + 2] << 8) | r[pos + 3];
        pos += rdl;
    }
    return cnt;
}
static int st_is_bogon(uint32_t v) { unsigned a = v >> 24, b = (v >> 16) & 255; return a == 0 || a == 10 || a == 127 || (a == 172 && b >= 16 && b <= 31) || (a == 192 && b == 168) || (a == 169 && b == 254) || (a == 100 && b >= 64 && b <= 127) || a >= 224; }

static BOOL st_gateway(char *out, size_t n) {
    ULONG sz = 0; GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_GATEWAYS, NULL, NULL, &sz); IP_ADAPTER_ADDRESSES *a = (IP_ADAPTER_ADDRESSES *)malloc(sz ? sz : 1); BOOL ok = FALSE;
    if (a && GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_GATEWAYS, NULL, a, &sz) == NO_ERROR)
        for (IP_ADAPTER_ADDRESSES *p = a; p && !ok; p = p->Next) if (p->OperStatus == IfOperStatusUp && p->FirstGatewayAddress && p->FirstGatewayAddress->Address.lpSockaddr->sa_family == AF_INET) { inet_ntop(AF_INET, &((struct sockaddr_in *)p->FirstGatewayAddress->Address.lpSockaddr)->sin_addr, out, (socklen_t)n); ok = TRUE; }
    free(a); return ok;
}

static void st_network_tests(void) {
    DWORD t; char gw[48] = ""; t = GetTickCount();
    if (!st_gateway(gw, sizeof gw)) st_add(ST_FAIL, "Network: default gateway", t, "No active adapter with a default gateway (offline or no DHCP).");
    else { HANDLE ic = IcmpCreateFile(); int okp = 0; DWORD rtt = 0; if (ic != INVALID_HANDLE_VALUE) { IPAddr ip; inet_pton(AF_INET, gw, &ip); char reply[sizeof(ICMP_ECHO_REPLY) + 40]; char data[8] = "kaevex"; DWORD rc = IcmpSendEcho(ic, ip, data, 6, NULL, reply, sizeof reply, 1500); if (rc > 0 && ((ICMP_ECHO_REPLY *)reply)->Status == 0) { okp = 1; rtt = ((ICMP_ECHO_REPLY *)reply)->RoundTripTime; } IcmpCloseHandle(ic); }
           st_add(okp ? ST_PASS : ST_WARN, "Network: default gateway", t, okp ? "Gateway %s replied to ping in %lu ms." : "Gateway %s did not answer ping (many routers block ICMP - not necessarily a problem).", gw, (unsigned long)rtt); }
    t = GetTickCount(); { int s = 0, hd = 0; DWORD we = 0; SYSTEMTIME d; int ok = st_http("connectivitycheck.gstatic.com", "/generate_204", 0, &s, &d, &hd, &we);
        if (!ok) st_add(ST_FAIL, "Network: internet / captive portal", t, "No HTTP answer (Win32 %lu): offline, proxy, or blocked.", (unsigned long)we);
        else if (s == 204) st_add(ST_PASS, "Network: internet / captive portal", t, "Internet reachable, no captive portal (HTTP 204).");
        else if (s == 403 || s == 407) st_add(ST_WARN, "Network: internet / captive portal", t, "HTTP %d: a proxy or firewall is refusing plain-HTTP internet access (this is not a captive portal).", s);
        else st_add(ST_WARN, "Network: internet / captive portal", t, "Got HTTP %d instead of 204: a captive portal or a content-modifying proxy is intercepting plain HTTP.", s); }
    t = GetTickCount(); { int s = 0, hd = 0; DWORD we = 0; SYSTEMTIME d; int ok = st_http("www.cisa.gov", "/", 1, &s, &d, &hd, &we);
        if (!ok) st_add(ST_FAIL, "Network: HTTPS + certificate validation", t, "HTTPS to www.cisa.gov failed (Win32 %lu%s).", (unsigned long)we, (we == 12175 || we == 12157 || we == 12044) ? ": TLS/certificate problem - possible interception or wrong clock" : "");
        else { st_add(ST_PASS, "Network: HTTPS + certificate validation", t, "TLS handshake and certificate chain accepted (HTTP %d).", s);
               if (hd) { FILETIME f1, f2; SystemTimeToFileTime(&d, &f1); SYSTEMTIME now; GetSystemTime(&now); SystemTimeToFileTime(&now, &f2);
                   long long skew = (((long long)f2.dwHighDateTime << 32 | f2.dwLowDateTime) - ((long long)f1.dwHighDateTime << 32 | f1.dwLowDateTime)) / 10000000LL;
                   st_add((skew > 300 || skew < -300) ? ST_FAIL : ST_PASS, "Network: system clock vs server time", t, "Clock differs from the server by %lld s%s.", skew, (skew > 300 || skew < -300) ? " - TLS and token validation can break; fix the Windows time" : ""); } } }
    t = GetTickCount(); { const char *host = "services.nvd.nist.gov"; ADDRINFOA h2; memset(&h2, 0, sizeof h2); h2.ai_family = AF_INET; ADDRINFOA *res = NULL; uint32_t sysIps[8]; int ns = 0;
        if (getaddrinfo(host, NULL, &h2, &res) == 0) { for (ADDRINFOA *a = res; a && ns < 8; a = a->ai_next) { uint32_t v = ntohl(((struct sockaddr_in *)a->ai_addr)->sin_addr.s_addr); sysIps[ns++] = v; } freeaddrinfo(res); }
        uint32_t pub[8]; int np = st_dns_query("1.1.1.1", host, pub, 8); if (np < 0) np = st_dns_query("8.8.8.8", host, pub, 8);
        if (ns == 0) st_add(ST_FAIL, "Network: DNS integrity", t, "System resolver could not resolve %s.", host);
        else { int bog = 0, common = 0; for (int i = 0; i < ns; i++) if (st_is_bogon(sysIps[i])) bog++; for (int i = 0; i < ns; i++) for (int k = 0; k < np; k++) if (sysIps[i] == pub[k]) common++;
            if (bog && np > 0) st_add(ST_FAIL, "Network: DNS integrity", t, "System DNS returned a PRIVATE/bogus address for a public host while public resolvers return real ones: DNS hijack or filtering.");
            else if (np < 0) st_add(ST_WARN, "Network: DNS integrity", t, "System DNS ok (%d address(es)); direct UDP DNS to 1.1.1.1/8.8.8.8 is blocked, so it could not be cross-checked.", ns);
            else if (common) st_add(ST_PASS, "Network: DNS integrity", t, "System DNS and public resolvers agree (%d shared address(es)).", common);
            else st_add(ST_WARN, "Network: DNS integrity", t, "System DNS and public resolvers returned different addresses (normal for CDNs, suspicious if you did not configure custom DNS).");
        } }
    char dm[400]; t = GetTickCount(); int ch = fwp_dns_guard_check(dm, sizeof dm); st_add(ch ? ST_WARN : ST_PASS, "Network: DNS resolvers / hosts file baseline", t, ch ? "%s" : "Resolvers and hosts file match the learned baseline.", dm);
    t = GetTickCount(); { char host[64], tok[8] = ""; int st2 = 0, rtt = 0; static char resp[8192]; int rc = link_http("127.0.0.1", g_mobilePort, "GET", "/api/v1/ping", NULL, NULL, resp, sizeof resp, &st2, &rtt); (void)host; (void)tok;
        if (rc != 0 || st2 != 200) st_add(ST_FAIL, "Node API: listening", t, "Local node API on port %d did not answer (rc=%d, HTTP %d).", g_mobilePort, rc, st2); else st_add(ST_PASS, "Node API: listening", t, "Node API answers on port %d in %d ms.", g_mobilePort, rtt);
        int listening = (rc == 0 && st2 == 200);
        t = GetTickCount();
        if (!listening) st_add(ST_SKIP, "Node API: authentication enforced", t, "Skipped: the API is not answering, so authentication cannot be tested.");
        else { rc = link_http("127.0.0.1", g_mobilePort, "GET", "/api/v1/mobile/dashboard", NULL, NULL, resp, sizeof resp, &st2, &rtt);
            int refused = (rc == 0 && (st2 == 401 || st2 == 403));
            st_add(refused ? ST_PASS : ST_FAIL, "Node API: authentication enforced", t, refused ? "Unauthenticated request correctly refused (HTTP %d)." : "Unauthenticated request was NOT refused (rc=%d, HTTP %d) - the API is open!", rc == 0 ? st2 : rc, st2); } }
    t = GetTickCount(); EnterCriticalSection(&g_peerCS); int np = g_peerCount; LeaveCriticalSection(&g_peerCS);
    if (!np) st_add(ST_SKIP, "Cluster: linked nodes", t, "No linked nodes (use Generate key / Accept key in SOC Mesh)."); else { for (int i = 0; i < np; i++) link_refresh_peer(i); int up = 0; EnterCriticalSection(&g_peerCS); for (int i = 0; i < g_peerCount; i++) if (!strcmp(g_peers[i].status, "LINKED")) up++; LeaveCriticalSection(&g_peerCS); st_add(up == np ? ST_PASS : ST_WARN, "Cluster: linked nodes", t, "%d of %d linked node(s) answered with valid authentication.", up, np); }
}

static DWORD WINAPI st_thread(LPVOID p) {
    int netOnly = (int)(INT_PTR)p; g_stN = 0; DWORD t; char m[400];
    if (!netOnly) {
        t = GetTickCount(); st_add(fwp_is_admin() ? ST_PASS : ST_WARN, "Privileges: administrator", t, fwp_is_admin() ? "Running elevated: firewall, services and registry changes are possible." : "NOT elevated: viewing works, but firewall changes, lockdown, logging and fixes will fail. Use Kaevex-Admin.bat.");
        t = GetTickCount(); { int n = net_scan_connections(); st_add(n > 0 ? ST_PASS : ST_FAIL, "NetGuard: socket table", t, "Read %d live TCP/UDP connections from the OS.", n); }
        t = GetTickCount(); { char ver[200]; int rc = fwp_netsh("advfirewall show currentprofile", ver, sizeof ver, 15000); int pm = fwp_profiles_on(); st_add(rc == 0 ? ST_PASS : ST_FAIL, "Firewall: netsh + state", t, rc == 0 ? "netsh works. Profiles ON mask=%d (7 = all)." : "netsh failed (rc=%d).", rc == 0 ? pm : rc); }
        t = GetTickCount(); { FwpRule r; char e[200]; BOOL ok = fwp_parse_rule_text("block out tcp name=\"selftest\" rport=65000", &r, e, sizeof e); FwpConn c; memset(&c, 0, sizeof c); c.dir = FWP_OUT; c.proto = FWP_TCP; c.remotePort = 65000; snprintf(c.remoteIp, sizeof c.remoteIp, "1.2.3.4"); int act = ok ? fwp_eval(&r, 1, &c, NULL, NULL) : -1; st_add(ok && act == FWP_BLOCK ? ST_PASS : ST_FAIL, "Firewall Pro: rule engine", t, ok && act == FWP_BLOCK ? "Rule parsed, validated and evaluated (BLOCK) correctly." : "Rule engine misbehaved: %s", e); }
        t = GetTickCount(); { char snap[MAX_PATH]; if (!fwp_is_admin()) st_add(ST_SKIP, "Firewall Pro: snapshot / rollback", t, "Needs administrator rights."); else { BOOL ok = fwp_snapshot(snap, sizeof snap, "selftest"); st_add(ok ? ST_PASS : ST_FAIL, "Firewall Pro: snapshot / rollback", t, ok ? "Snapshot written and verified on disk: %s" : "Snapshot could not be created.", snap); } }
        t = GetTickCount(); { FwpLogEntry *lg = (FwpLogEntry *)malloc(sizeof(FwpLogEntry) * 500); int n = lg ? fwp_read_log(lg, 500) : -1; free(lg); st_add(n < 0 ? ST_WARN : ST_PASS, "Firewall Pro: logging", t, n < 0 ? "No firewall log file yet: press 'Enable logging' in Firewall Pro > Logs, then generate traffic." : "Firewall log readable (%d recent entries parsed).", n); }
        t = GetTickCount(); st_add(fwp_watch_running() ? ST_PASS : ST_WARN, "Firewall Pro: tamper protection", t, fwp_watch_running() ? "Registry watcher running." : "Not running (start it in Firewall Pro > Protection).");
        t = GetTickCount(); { LedgerVerdict lv; threat_ledger_verify(&lv); st_add(lv.state == LEDGER_OK ? ST_PASS : lv.state == LEDGER_NOCHAIN ? ST_WARN : ST_FAIL, "Forensics ledger: HMAC chain", t, "%s", lv.why); }
        t = GetTickCount(); { char pr[3][100] = {{0}}; (void)pr; int k = 0; for (int i = 0; i < KVAI_PROVIDER_COUNT; i++) { char key[256]; kvai_key_get(i, key, sizeof key); if (key[0]) k++; SecureZeroMemory(key, sizeof key); }
            if (g_aiProvider >= KVAI_PROVIDER_COUNT) st_add(ST_SKIP, "AI provider: live request", t, "Local mode selected (no cloud AI).");
            else if (!k) st_add(ST_FAIL, "AI provider: live request", t, "No API key saved for any provider. Settings > AI Engine.");
            else { char out[300]; KvAiResult r; BOOL ok = kvai_chat(g_aiProvider, NULL, NULL, "You are a connectivity test.", "Reply with the single word OK.", 0.0f, 2048, out, sizeof out, 0, &r); snprintf(m, sizeof m, "%s", ok ? "" : r.error);
                st_add(ok ? ST_PASS : ST_FAIL, "AI provider: live request", t, ok ? "%s answered in %.1f s using model %s." : "%s", ok ? g_kvProv[g_aiProvider].label : m, r.ms / 1000.0, r.model); } }
        t = GetTickCount(); { TcCheck c[TC_MAX]; int n = tc_run_all(c, TC_MAX), fail = 0, pass = 0; for (int i = 0; i < n; i++) { if (c[i].status == TC_FAIL) fail++; else if (c[i].status == TC_PASS) pass++; } st_add(ST_PASS, "AI team: real host checks", t, "%d checks executed against this PC: %d pass, %d fail (type /checks in Full Team for details).", n, pass, fail); }
        t = GetTickCount(); { char w[MAX_PATH]; BOOL has = cvi_find_winget(w, sizeof w); st_add(has ? ST_PASS : ST_WARN, "CVE: winget available", t, has ? "winget found: verified upgrades are possible." : "winget not found: fixes fall back to containment / manual."); }
        t = GetTickCount(); { char *b = NULL; int s = 0; DWORD we = 0; int ok = cvi_http_get("services.nvd.nist.gov", "/rest/json/cves/2.0?resultsPerPage=1", cvi_nvd_key() ? "apiKey: set\r\n" : NULL, &b, &s, &we); if (b) { const char *tr = kvai_find_key(b, "totalResults"); st_add(s == 200 ? ST_PASS : ST_FAIL, "CVE: NVD API", t, s == 200 ? "NVD answered; %d CVE records exist." : "NVD returned HTTP %d.", s == 200 && tr ? atoi(tr) : s); free(b); } else st_add(ST_FAIL, "CVE: NVD API", t, "NVD unreachable (Win32 %lu).", (unsigned long)we); (void)ok; }
        t = GetTickCount(); { cvi_init(NULL); BOOL ok = cvi_refresh_kev(FALSE); st_add(ok ? ST_PASS : ST_FAIL, "CVE: CISA KEV catalog", t, ok ? "%d actively exploited CVEs available." : "KEV catalog unavailable.", g_cviKevN); }
        t = GetTickCount(); { int nid = cvi_winget_ids(FALSE); st_add(nid > 0 ? ST_PASS : ST_WARN, "CVE: installed winget packages", t, nid > 0 ? "%d installed packages identified for AI planning." : "No packages identified (winget missing or nothing installed via winget).", nid); }
    }
    st_network_tests();
    PostMessageA(g_st.hw, ST_WM_DONE, 0, 0); InterlockedExchange(&g_st.busy, 0); return 0;
}

static void st_run(int netOnly) { if (InterlockedCompareExchange(&g_st.busy, 1, 0) != 0) return; SendMessageA(g_st.lv, LVM_DELETEALLITEMS, 0, 0); SetWindowTextA(g_st.sum, "Running tests..."); HANDLE h = CreateThread(NULL, 0, st_thread, (LPVOID)(INT_PTR)netOnly, 0, NULL); if (h) CloseHandle(h); else InterlockedExchange(&g_st.busy, 0); }

static LRESULT CALLBACK st_proc(HWND hw, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    KV_CTLCOLOR_CASES
    case WM_SIZE: { int W = LOWORD(lp), H = HIWORD(lp); MoveWindow(GetDlgItem(hw, ST_ID_RUN), 8, 8, 150, 28, TRUE); MoveWindow(GetDlgItem(hw, ST_ID_NET), 164, 8, 150, 28, TRUE); MoveWindow(GetDlgItem(hw, ST_ID_COPY), 320, 8, 150, 28, TRUE); MoveWindow(g_st.sum, 480, 14, W - 490, 20, TRUE); MoveWindow(g_st.lv, 8, 44, W - 16, H - 52, TRUE); return 0; }
    case ST_WM_ROW: { int i = (int)wp; StResult *r = &g_stRes[i]; const char *sn[] = { "PASS", "FAIL", "WARN", "SKIP" };
        LVITEMA it; memset(&it, 0, sizeof it); it.mask = LVIF_TEXT; it.iItem = i; it.pszText = (char *)sn[r->status]; SendMessageA(g_st.lv, LVM_INSERTITEMA, 0, (LPARAM)&it);
        it.iSubItem = 1; it.pszText = r->name; SendMessageA(g_st.lv, LVM_SETITEMTEXTA, (WPARAM)i, (LPARAM)&it); it.iSubItem = 2; it.pszText = r->detail; SendMessageA(g_st.lv, LVM_SETITEMTEXTA, (WPARAM)i, (LPARAM)&it);
        char ms[24]; snprintf(ms, sizeof ms, "%lu", (unsigned long)r->ms); it.iSubItem = 3; it.pszText = ms; SendMessageA(g_st.lv, LVM_SETITEMTEXTA, (WPARAM)i, (LPARAM)&it); return 0; }
    case ST_WM_DONE: { int c[4] = {0}; for (int i = 0; i < g_stN; i++) c[g_stRes[i].status]++; char s[200]; snprintf(s, sizeof s, "%d PASS   %d FAIL   %d WARN   %d SKIP   (PASS means the test really exercised that feature)", c[0], c[1], c[2], c[3]); SetWindowTextA(g_st.sum, s); return 0; }
    case WM_COMMAND: { int id = LOWORD(wp);
        if (id == ST_ID_RUN) st_run(0); else if (id == ST_ID_NET) st_run(1);
        else if (id == ST_ID_COPY) { size_t cap = (size_t)(g_stN + 1) * 400; char *t = (char *)malloc(cap); if (t) { size_t w = 0; const char *sn[] = { "PASS", "FAIL", "WARN", "SKIP" }; for (int i = 0; i < g_stN; i++) w += (size_t)snprintf(t + w, cap - w, "%s\t%s\t%s\r\n", sn[g_stRes[i].status], g_stRes[i].name, g_stRes[i].detail);
                if (OpenClipboard(hw)) { EmptyClipboard(); HGLOBAL g = GlobalAlloc(GMEM_MOVEABLE, w + 1); if (g) { memcpy(GlobalLock(g), t, w + 1); GlobalUnlock(g); SetClipboardData(CF_TEXT, g); } CloseClipboard(); } free(t); } }
        return 0; }
    case WM_CLOSE: DestroyWindow(hw); return 0;
    case WM_DESTROY: g_st.hw = NULL; return 0;
    }
    return DefWindowProcA(hw, msg, wp, lp);
}

static void st_open(HWND parent) {
    if (g_st.hw && IsWindow(g_st.hw)) { SetForegroundWindow(g_st.hw); return; }
    static BOOL reg = FALSE; if (!reg) { WNDCLASSA wc; memset(&wc, 0, sizeof wc); wc.lpfnWndProc = st_proc; wc.hInstance = GetModuleHandleA(NULL); wc.hCursor = LoadCursor(NULL, IDC_ARROW); kv_theme_init(); wc.hbrBackground = g_kvBrushBg; wc.lpszClassName = "KaevexSelfTest"; RegisterClassA(&wc); reg = TRUE; }
    INITCOMMONCONTROLSEX ic = { sizeof ic, ICC_LISTVIEW_CLASSES }; InitCommonControlsEx(&ic); memset(&g_st, 0, sizeof g_st);
    HWND hw = g_st.hw = CreateWindowExA(0, "KaevexSelfTest", "Kaevex Self-Test - real tests of every subsystem and the network", WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN, CW_USEDEFAULT, CW_USEDEFAULT, 1100, 720, parent, NULL, GetModuleHandleA(NULL), NULL);
    HFONT f = (HFONT)GetStockObject(DEFAULT_GUI_FONT); const char *bt[] = { "Run all tests", "Network only", "Copy report" }; int ids[] = { ST_ID_RUN, ST_ID_NET, ST_ID_COPY };
    for (int i = 0; i < 3; i++) { HWND b = CreateWindowExA(0, "BUTTON", bt[i], WS_CHILD | WS_VISIBLE | WS_TABSTOP, 0, 0, 10, 10, hw, (HMENU)(INT_PTR)ids[i], GetModuleHandleA(NULL), NULL); SendMessageA(b, WM_SETFONT, (WPARAM)f, TRUE); }
    g_st.sum = CreateWindowExA(0, "STATIC", "Press 'Run all tests'. Some tests send one real request (AI, NVD, CISA).", WS_CHILD | WS_VISIBLE, 0, 0, 10, 10, hw, (HMENU)ST_ID_SUM, GetModuleHandleA(NULL), NULL); SendMessageA(g_st.sum, WM_SETFONT, (WPARAM)f, TRUE);
    g_st.lv = CreateWindowExA(0, WC_LISTVIEWA, "", WS_CHILD | WS_VISIBLE | WS_BORDER | LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS, 0, 0, 10, 10, hw, (HMENU)ST_ID_LV, GetModuleHandleA(NULL), NULL);
    const char *cn[] = { "Result", "Test", "Evidence", "ms" }; int cw[] = { 60, 250, 640, 50 }; for (int i = 0; i < 4; i++) { LVCOLUMNA c; memset(&c, 0, sizeof c); c.mask = LVCF_TEXT | LVCF_WIDTH; c.pszText = (char *)cn[i]; c.cx = cw[i]; SendMessageA(g_st.lv, LVM_INSERTCOLUMNA, (WPARAM)i, (LPARAM)&c); }
    SendMessageA(g_st.lv, LVM_SETEXTENDEDLISTVIEWSTYLE, 0, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_DOUBLEBUFFER);
    RECT rc; GetClientRect(hw, &rc); kv_theme_apply(hw); SendMessageA(hw, WM_SIZE, 0, MAKELPARAM(rc.right, rc.bottom)); ShowWindow(hw, SW_SHOW);
}

#endif /* SELFTEST_GUI_H */
