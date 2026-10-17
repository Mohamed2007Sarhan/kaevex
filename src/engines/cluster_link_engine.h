/*===========================================================================
 * Kaevex Security Platform - cluster_link_engine.h
 * REAL linking between Kaevex nodes (desktop <-> desktop / peer).
 *
 *   node A: "Generate key"  -> KAEVEX-LINK-V2://<LAN ip>:<port>/<PIN>
 *   node B: paste key       -> POST /api/v1/auth/pair (PIN) -> bearer token
 *                              GET  /api/v1/ping       -> measured latency
 *                              GET  /api/v1/mobile/dashboard -> real status
 *   A is told to link back to B's address (taken from the TCP connection,
 *   never from attacker-controlled text), so both nodes see each other.
 *
 * Every number shown comes from a real request; failures are reported as such.
 * NOTE: the node API is plain HTTP on the LAN (no TLS yet) - keep it on trusted
 * networks. The server only accepts private-range clients (see mobile engine).
 *===========================================================================*/
#pragma once
#ifndef CLUSTER_LINK_ENGINE_H
#define CLUSTER_LINK_ENGINE_H

#define MAX_LINKED 8
typedef struct {
    char ip[64]; char code[128]; char name[64]; int pingMs; BOOL active;   /* names kept for the GUI */
    int  port;
    char token[72];
    char status[24];            /* LINKED / OFFLINE / AUTH LOST */
    char lastErr[160];
    int  threats, conns, locked;
    DWORD lastOkTick;
    int  fails;
} LinkPeer;

static LinkPeer         g_peers[MAX_LINKED];
static int              g_peerCount = 0;
static CRITICAL_SECTION g_peerCS;
static volatile LONG    g_peerInit = 0, g_peerMonRun = 0;

static void link_init(void) {
    if (InterlockedCompareExchange(&g_peerInit, 1, 0) == 0) { InitializeCriticalSection(&g_peerCS); InterlockedExchange(&g_peerInit, 2); }
    while (g_peerInit != 2) Sleep(1);
}

/* ---- Plain HTTP client with real timing ------------------------------------------------ */
static int link_http(const char *host, int port, const char *method, const char *path, const char *token,
                     const char *body, char *resp, size_t respN, int *status, int *rttMs) {
    *status = 0; if (rttMs) *rttMs = -1; if (resp && respN) resp[0] = 0;
    WSADATA w; WSAStartup(MAKEWORD(2, 2), &w);
    char ps[12]; snprintf(ps, sizeof ps, "%d", port);
    struct addrinfo hints; memset(&hints, 0, sizeof hints); hints.ai_family = AF_INET; hints.ai_socktype = SOCK_STREAM;
    struct addrinfo *ai = NULL;
    if (getaddrinfo(host, ps, &hints, &ai) != 0 || !ai) return -1;
    DWORD t0 = GetTickCount();
    SOCKET s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (s == INVALID_SOCKET) { freeaddrinfo(ai); return -1; }
    u_long nb = 1; ioctlsocket(s, FIONBIO, &nb);
    connect(s, ai->ai_addr, (int)ai->ai_addrlen); freeaddrinfo(ai);
    fd_set wf, ef; FD_ZERO(&wf); FD_ZERO(&ef); FD_SET(s, &wf); FD_SET(s, &ef);
    struct timeval tv = { 3, 0 };
    if (select(0, NULL, &wf, &ef, &tv) <= 0 || !FD_ISSET(s, &wf)) { closesocket(s); return -2; }   /* -2 = cannot connect */
    nb = 0; ioctlsocket(s, FIONBIO, &nb);
    DWORD to = 6000; setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char *)&to, sizeof to); setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (char *)&to, sizeof to);
    size_t bl = body ? strlen(body) : 0;
    char *req = (char *)malloc(bl + 700); if (!req) { closesocket(s); return -1; }
    int n = snprintf(req, bl + 700, "%s %s HTTP/1.1\r\nHost: %s:%d\r\nConnection: close\r\nAccept: application/json\r\n%s%s%sContent-Type: application/json\r\nContent-Length: %u\r\n\r\n%s",
                     method, path, host, port, token && token[0] ? "Authorization: Bearer " : "", token ? token : "", token && token[0] ? "\r\n" : "", (unsigned)bl, body ? body : "");
    int sent = send(s, req, n, 0); free(req);
    if (sent != n) { closesocket(s); return -1; }
    size_t total = 0; int rc;
    while (total + 1 < respN && (rc = recv(s, resp + total, (int)(respN - total - 1), 0)) > 0) total += (size_t)rc;
    closesocket(s);
    resp[total] = 0;
    if (rttMs) *rttMs = (int)(GetTickCount() - t0);
    char *b; if (!link_parse_http(resp, status, &b)) return -3;
    memmove(resp, b, strlen(b) + 1);               /* resp now holds just the body */
    return 0;
}

static BOOL link_json_str(const char *json, const char *key, char *out, size_t n) {
    const char *v = kvai_find_key(json, key); out[0] = 0;
    return v && *v == '"' && kvai_read_str(v, out, n) >= 0;
}
static int link_json_int(const char *json, const char *key, int dflt) {
    const char *v = kvai_find_key(json, key); if (!v) return dflt;
    if (strncmp(v, "true", 4) == 0) return 1; if (strncmp(v, "false", 5) == 0) return 0;
    return atoi(v);
}

/* ---- Local address & key ------------------------------------------------------------------ */
static BOOL link_local_ip(char *out, size_t n) {
    WSADATA w; WSAStartup(MAKEWORD(2, 2), &w);
    SOCKET s = socket(AF_INET, SOCK_DGRAM, 0); if (s == INVALID_SOCKET) return FALSE;
    struct sockaddr_in to; memset(&to, 0, sizeof to); to.sin_family = AF_INET; to.sin_port = htons(53); inet_pton(AF_INET, "192.0.2.1", &to.sin_addr);   /* TEST-NET: nothing is sent, just route selection */
    BOOL ok = FALSE;
    if (connect(s, (struct sockaddr *)&to, sizeof to) == 0) {
        struct sockaddr_in me; int ml = sizeof me;
        if (getsockname(s, (struct sockaddr *)&me, &ml) == 0) { inet_ntop(AF_INET, &me.sin_addr, out, (socklen_t)n); ok = strcmp(out, "0.0.0.0") != 0; }
    }
    closesocket(s); return ok;
}

static BOOL link_generate_code(char *out, size_t n, char *err, size_t errN) {
    if (!g_mobileRunning) { snprintf(err, errN, "The node API is not running (port %d). Start Kaevex as administrator and retry.", g_mobilePort); return FALSE; }
    char ip[64];
    if (!link_local_ip(ip, sizeof ip)) { snprintf(err, errN, "No network connection - cannot determine this machine's LAN address."); return FALSE; }
    if (!link_build_code(ip, g_mobilePort, g_pairingPin, out, n)) { snprintf(err, errN, "Could not build the link key."); return FALSE; }
    return TRUE;
}

/* ---- Connect ---------------------------------------------------------------------------------- */
static int link_find_peer(const char *host, int port) {
    for (int i = 0; i < g_peerCount; i++) if (g_peers[i].port == port && strcmp(g_peers[i].ip, host) == 0) return i;
    return -1;
}

static void link_apply_dashboard(LinkPeer *p, const char *dash) {
    char hn[64]; if (link_json_str(dash, "hostname", hn, sizeof hn) && hn[0]) snprintf(p->name, sizeof p->name, "%s", hn);
    p->threats = link_json_int(dash, "total_threats", p->threats);
    p->conns   = link_json_int(dash, "active_connections", p->conns);
    p->locked  = link_json_int(dash, "firewall_locked", 0);
}

static BOOL link_connect_raw(const char *host, int port, const char *pin, int noBack, char *msg, size_t msgN) {
    link_init();
    static char resp[65536];                                       /* serialized by g_peerCS below */
    char comp[64] = "KAEVEX"; DWORD cl = sizeof comp; GetComputerNameA(comp, &cl);
    int st = 0, rtt = 0;
    EnterCriticalSection(&g_peerCS);
    int rc = link_http(host, port, "GET", "/api/v1/ping", NULL, NULL, resp, sizeof resp, &st, &rtt);
    if (rc == -2) { snprintf(msg, msgN, "Cannot reach %s:%d - check the address, that Kaevex is running there, and that its firewall allows TCP %d.", host, port, port); goto fail; }
    if (rc != 0)  { snprintf(msg, msgN, "No valid HTTP answer from %s:%d.", host, port); goto fail; }
    if (st != 200 || !strstr(resp, "Kaevex")) { snprintf(msg, msgN, "%s:%d answered but is not a Kaevex node (HTTP %d).", host, port, st); goto fail; }
    int pingMs = rtt;

    char body[400]; char ourIp[64];
    int canBack = !noBack && g_mobileRunning && link_local_ip(ourIp, sizeof ourIp);
    if (canBack) snprintf(body, sizeof body, "{\"pin\":\"%s\",\"device_id\":\"kaevex-node-%s\",\"device_name\":\"Kaevex node %s\",\"back_port\":%d,\"back_pin\":\"%s\"}", pin, comp, comp, g_mobilePort, g_pairingPin);
    else         snprintf(body, sizeof body, "{\"pin\":\"%s\",\"device_id\":\"kaevex-node-%s\",\"device_name\":\"Kaevex node %s\"}", pin, comp, comp);
    rc = link_http(host, port, "POST", "/api/v1/auth/pair", NULL, body, resp, sizeof resp, &st, &rtt);
    SecureZeroMemory(body, sizeof body);
    if (rc != 0) { snprintf(msg, msgN, "Pairing request to %s:%d failed (network).", host, port); goto fail; }
    if (st == 429) { snprintf(msg, msgN, "%s:%d temporarily blocked this machine after failed attempts. Wait 10 minutes.", host, port); goto fail; }
    if (st == 401) { snprintf(msg, msgN, "Wrong or expired PIN. Generate a fresh key on the other node."); goto fail; }
    char tok[72] = "";
    if (st != 200 || !link_json_str(resp, "token", tok, sizeof tok) || !tok[0]) { snprintf(msg, msgN, "Pairing refused (HTTP %d).", st); goto fail; }

    char dash[16384]; static char dresp[65536];
    rc = link_http(host, port, "GET", "/api/v1/mobile/dashboard", tok, NULL, dresp, sizeof dresp, &st, &rtt);
    int idx = link_find_peer(host, port);
    if (idx < 0) {
        if (g_peerCount >= MAX_LINKED) { snprintf(msg, msgN, "Maximum of %d linked nodes reached. Unlink one first.", MAX_LINKED); goto fail; }
        idx = g_peerCount++;
    }
    LinkPeer *p = &g_peers[idx]; memset(p, 0, sizeof *p);
    snprintf(p->ip, sizeof p->ip, "%s", host); p->port = port; snprintf(p->token, sizeof p->token, "%s", tok);
    snprintf(p->name, sizeof p->name, "%s", host); snprintf(p->code, sizeof p->code, "%s:%d", host, port);
    p->pingMs = pingMs; p->active = TRUE; snprintf(p->status, sizeof p->status, "LINKED"); p->lastOkTick = GetTickCount();
    if (rc == 0 && st == 200) link_apply_dashboard(p, dresp);
    snprintf(msg, msgN, "Linked to %s (%s:%d) - measured latency %d ms%s.", p->name, host, port, pingMs, canBack ? "; the remote node was asked to link back" : "");
    LeaveCriticalSection(&g_peerCS);
    (void)dash;
    return TRUE;
fail:
    LeaveCriticalSection(&g_peerCS);
    return FALSE;
}

/* Called by the API when a node paired with us and sent back_port/back_pin: link back to the connecting IP. */
typedef struct { char host[64]; int port; char pin[8]; } LinkBackArgs;
static DWORD WINAPI link_back_thread(LPVOID p) {
    LinkBackArgs *a = (LinkBackArgs *)p; char msg[300];
    Sleep(300);
    EnterCriticalSection(&g_peerCS); int known = link_find_peer(a->host, a->port) >= 0; LeaveCriticalSection(&g_peerCS);
    if (!known) { BOOL ok = link_connect_raw(a->host, a->port, a->pin, 1, msg, sizeof msg); if (g_pMobileAddAlert) g_pMobileAddAlert("Cluster", ok ? "INFO" : "WARNING", msg); }
    free(a); return 0;
}
static void link_spawn_backlink(const char *clientIp, int port, const char *pin) {
    link_init();
    if (!link_is_private_ip(clientIp) || port < 1 || port > 65535 || strlen(pin) != 6) return;
    LinkBackArgs *a = (LinkBackArgs *)calloc(1, sizeof *a); if (!a) return;
    snprintf(a->host, sizeof a->host, "%s", clientIp); a->port = port; snprintf(a->pin, sizeof a->pin, "%s", pin);
    HANDLE t = CreateThread(NULL, 0, link_back_thread, a, 0, NULL); if (t) CloseHandle(t); else free(a);
}

/* ---- Health monitor ---------------------------------------------------------------------------------- */
static void link_refresh_peer(int i) {
    static char resp[65536]; int st, rtt; char host[64], tok[72]; int port;
    EnterCriticalSection(&g_peerCS);
    if (i < 0 || i >= g_peerCount) { LeaveCriticalSection(&g_peerCS); return; }
    snprintf(host, sizeof host, "%s", g_peers[i].ip); snprintf(tok, sizeof tok, "%s", g_peers[i].token); port = g_peers[i].port;
    LeaveCriticalSection(&g_peerCS);
    int rc = link_http(host, port, "GET", "/api/v1/mobile/dashboard", tok, NULL, resp, sizeof resp, &st, &rtt);
    EnterCriticalSection(&g_peerCS);
    if (i < g_peerCount && strcmp(g_peers[i].ip, host) == 0 && g_peers[i].port == port) {
        LinkPeer *p = &g_peers[i];
        if (rc == 0 && st == 200) { p->fails = 0; p->pingMs = rtt; p->lastOkTick = GetTickCount(); snprintf(p->status, sizeof p->status, "LINKED"); p->lastErr[0] = 0; link_apply_dashboard(p, resp); }
        else if (rc == 0 && st == 401) { snprintf(p->status, sizeof p->status, "AUTH LOST"); snprintf(p->lastErr, sizeof p->lastErr, "Remote rejected the token (it restarted?). Re-link with a new key."); p->pingMs = -1; }
        else { if (++p->fails >= 2) { snprintf(p->status, sizeof p->status, "OFFLINE"); p->pingMs = -1; } snprintf(p->lastErr, sizeof p->lastErr, rc == -2 ? "Cannot connect" : "No valid answer"); }
    }
    LeaveCriticalSection(&g_peerCS);
}

static DWORD WINAPI link_monitor_thread(LPVOID p) {
    (void)p;
    while (g_peerMonRun) {
        for (int i = 0; i < MAX_LINKED && g_peerMonRun; i++) { EnterCriticalSection(&g_peerCS); int have = i < g_peerCount; LeaveCriticalSection(&g_peerCS); if (have) link_refresh_peer(i); }
        for (int k = 0; k < 100 && g_peerMonRun; k++) Sleep(100);
    }
    return 0;
}
static void link_start_monitor(void) {
    link_init();
    if (InterlockedCompareExchange(&g_peerMonRun, 1, 0) != 0) return;
    HANDLE t = CreateThread(NULL, 0, link_monitor_thread, NULL, 0, NULL); if (t) CloseHandle(t); else InterlockedExchange(&g_peerMonRun, 0);
}

static void link_unlink(int i) {
    link_init(); EnterCriticalSection(&g_peerCS);
    if (i >= 0 && i < g_peerCount) { SecureZeroMemory(g_peers[i].token, sizeof g_peers[i].token); for (int k = i; k < g_peerCount - 1; k++) g_peers[k] = g_peers[k + 1]; g_peerCount--; memset(&g_peers[g_peerCount], 0, sizeof(LinkPeer)); }
    LeaveCriticalSection(&g_peerCS);
}

/* ---- Remote actions ------------------------------------------------------------------------------------ */
/* Sends one authenticated call to a peer. Returns HTTP status (0 = network failure). resp receives the body. */
static int link_call(int i, const char *method, const char *path, const char *body, char *resp, size_t respN) {
    char host[64], tok[72]; int port, st = 0, rtt;
    EnterCriticalSection(&g_peerCS);
    if (i < 0 || i >= g_peerCount) { LeaveCriticalSection(&g_peerCS); return 0; }
    snprintf(host, sizeof host, "%s", g_peers[i].ip); snprintf(tok, sizeof tok, "%s", g_peers[i].token); port = g_peers[i].port;
    LeaveCriticalSection(&g_peerCS);
    if (link_http(host, port, method, path, tok, body, resp, respN, &st, &rtt) != 0) return 0;
    return st;
}

/* action: "lockdown" | "unlock" | "scan". Applies to every linked peer; returns how many confirmed (HTTP 200).
 * detail receives one line per peer with the real outcome. */
static int link_broadcast(const char *action, char *detail, size_t dn) {
    int ok = 0; size_t w = 0; detail[0] = 0;
    static char resp[8192];
    link_init();
    for (int i = 0; i < MAX_LINKED; i++) {
        char name[64];
        EnterCriticalSection(&g_peerCS); int have = i < g_peerCount; if (have) snprintf(name, sizeof name, "%s", g_peers[i].name); LeaveCriticalSection(&g_peerCS);
        if (!have) break;
        int st;
        if (strcmp(action, "lockdown") == 0)    st = link_call(i, "POST", "/api/v1/firewall/lockdown", "{\"enable\":1,\"origin\":\"peer\"}", resp, sizeof resp);
        else if (strcmp(action, "unlock") == 0) st = link_call(i, "POST", "/api/v1/firewall/lockdown", "{\"enable\":0,\"origin\":\"peer\"}", resp, sizeof resp);
        else if (strcmp(action, "scan") == 0)   st = link_call(i, "POST", "/api/v1/threats/scan", "{}", resp, sizeof resp);
        else return 0;
        int good = (st == 200 && strstr(resp, "\"status\":\"success\"") != NULL);
        if (good) ok++;
        if (w < dn) w += (size_t)snprintf(detail + w, dn - w, "%s: %s\n", name, good ? "confirmed" : (st ? "refused/failed (HTTP see node)" : "unreachable"));
    }
    return ok;
}

/* Pulls the peer's most recent alerts into the local feed (deduplicated). Returns number of NEW alerts ingested. */
static int link_pull_alerts(int i, void (*add)(const char *, const char *, const char *)) {
    static char resp[65536]; static unsigned seen[512]; static int seenN = 0;
    if (link_call(i, "GET", "/api/v1/mobile/dashboard", NULL, resp, sizeof resp) != 200) return -1;
    char node[64]; EnterCriticalSection(&g_peerCS); snprintf(node, sizeof node, "%s", i < g_peerCount ? g_peers[i].name : "?"); LeaveCriticalSection(&g_peerCS);
    const char *arr = kvai_find_key(resp, "recent_alerts"); if (!arr || *arr != '[') return 0;
    int fresh = 0; const char *p = arr;
    for (int guard = 0; guard < 64; guard++) {
        const char *m = kvai_find_key(p, "msg"); if (!m || *m != '"') break;
        char msg[260], sev[16] = "INFO", src[48] = "";
        kvai_read_str(m, msg, sizeof msg);
        const char *sv = kvai_find_key(p, "sev"); if (sv && sv < m && *sv == '"') kvai_read_str(sv, sev, sizeof sev);
        const char *sr = kvai_find_key(p, "src"); if (sr && sr < m && *sr == '"') kvai_read_str(sr, src, sizeof src);
        unsigned h = fwp_hash(node) ^ (fwp_hash(msg) * 31u); int dup = 0;
        for (int k = 0; k < seenN; k++) if (seen[k] == h) { dup = 1; break; }
        if (!dup) { seen[seenN++ % 512] = h; char line[360]; snprintf(line, sizeof line, "[%s] %s", node, msg); if (add) add(src[0] ? src : "Cluster", sev, line); fresh++; }
        const char *e = kvai_skip_str(m); if (!e) break; p = e;
    }
    return fresh;
}

/* Pushes the local firewall policy to a peer (optionally applying it there). Returns HTTP status, 0 = unreachable. */
static int link_push_policy(int i, int apply) {
    char *pol = fwp_policy_export_text(); if (!pol) return 0;
    char *esc = kvai_escape_alloc(pol); free(pol); if (!esc) return 0;
    size_t cap = strlen(esc) + 64; char *body = (char *)malloc(cap); if (!body) { free(esc); return 0; }
    snprintf(body, cap, "{\"apply\":%d,\"policy\":\"%s\"}", apply ? 1 : 0, esc); free(esc);
    static char resp[4096]; int st = link_call(i, "POST", "/api/v1/firewall/policy", body, resp, sizeof resp);
    free(body); return st;
}

/* JSON list of peers for GET /api/v1/cluster/nodes */
static int link_nodes_json(char *out, size_t n) {
    int w = snprintf(out, n, "{\"status\":\"success\",\"servers\":[");
    EnterCriticalSection(&g_peerCS);
    for (int i = 0; i < g_peerCount && (size_t)w < n - 400; i++) {
        LinkPeer *p = &g_peers[i]; char en[130], ei[130];
        char *e1 = kvai_escape_alloc(p->name), *e2 = kvai_escape_alloc(p->ip);
        snprintf(en, sizeof en, "%s", e1 ? e1 : ""); snprintf(ei, sizeof ei, "%s", e2 ? e2 : ""); free(e1); free(e2);
        w += snprintf(out + w, n - (size_t)w, "%s{\"id\":%d,\"name\":\"%s\",\"ip\":\"%s\",\"port\":%d,\"status\":\"%s\",\"ping_ms\":%d,\"threats\":%d,\"connections\":%d,\"is_locked\":%s}",
                      i ? "," : "", i + 1, en, ei, p->port, p->status, p->pingMs, p->threats, p->conns, p->locked ? "true" : "false");
    }
    w += snprintf(out + w, n - (size_t)w, "],\"cluster_count\":%d}", g_peerCount + 1);
    LeaveCriticalSection(&g_peerCS);
    return w;
}

#endif /* CLUSTER_LINK_ENGINE_H */
