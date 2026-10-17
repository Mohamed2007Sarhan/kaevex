/*===========================================================================
 * Kaevex WAF reverse proxy - waf_proxy.h  (portable: Windows winsock / POSIX)
 *
 *   client ──► [Kaevex WAF :listen] ──► upstream app (host:port)
 *
 * Every request is fully read, inspected by waf_core.h (path, query, headers, body incl. chunked and multipart)
 * and either forwarded or answered with 403. The client's X-Forwarded-For is replaced with the real peer address.
 * HTTP/1.x only, one request per connection (Connection: close). TLS is not terminated: put the proxy behind your
 * TLS terminator (or in front of a plain-HTTP app) - it protects what passes through it, not other ports.
 *===========================================================================*/
#pragma once
#ifndef WAF_PROXY_H
#define WAF_PROXY_H

#include "waf_core.h"
#include <time.h>
#ifdef _WIN32
  #include <winsock2.h>
  #include <ws2tcpip.h>
  typedef SOCKET kv_sock;
  #define KV_BAD INVALID_SOCKET
  #define kv_close closesocket
  #define KV_MUTEX CRITICAL_SECTION
  #define kv_mutex_init(m) InitializeCriticalSection(m)
  #define kv_lock(m) EnterCriticalSection(m)
  #define kv_unlock(m) LeaveCriticalSection(m)
  typedef DWORD (WINAPI *kv_thread_fn)(LPVOID);
  #define KV_THREAD_RET DWORD WINAPI
  static int kv_spawn(kv_thread_fn f, void *a) { HANDLE h = CreateThread(NULL, 0, f, a, 0, NULL); if (!h) return 0; CloseHandle(h); return 1; }
  static void kv_set_timeout(kv_sock s, int ms) { DWORD t = (DWORD)ms; setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&t, sizeof t); setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char *)&t, sizeof t); }
  #define KV_ATOMIC_INC(p) InterlockedIncrement((volatile LONG *)(p))
#else
  #include <sys/socket.h>
  #include <netinet/in.h>
  #include <arpa/inet.h>
  #include <netdb.h>
  #include <unistd.h>
  #include <pthread.h>
  #include <signal.h>
  typedef int kv_sock;
  #define KV_BAD (-1)
  #define kv_close close
  #define KV_MUTEX pthread_mutex_t
  #define kv_mutex_init(m) pthread_mutex_init(m, NULL)
  #define kv_lock(m) pthread_mutex_lock(m)
  #define kv_unlock(m) pthread_mutex_unlock(m)
  typedef void *(*kv_thread_fn)(void *);
  #define KV_THREAD_RET void *
  static int kv_spawn(kv_thread_fn f, void *a) { pthread_t t; if (pthread_create(&t, NULL, f, a)) return 0; pthread_detach(t); return 1; }
  static void kv_set_timeout(kv_sock s, int ms) { struct timeval tv = { ms / 1000, (ms % 1000) * 1000 }; setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv); setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv); }
  #define KV_ATOMIC_INC(p) __sync_add_and_fetch((p), 1)
#endif

#define WAFP_MAX_BODY   (16u * 1024 * 1024)
#define WAFP_MAX_HEAD   (64u * 1024)
#define WAFP_MAX_CONN   256
#define WAFP_EVENTS     256

typedef struct { char listenHost[48]; int listenPort; char upHost[128]; int upPort; int paranoia; int detectOnly; } WafProxyCfg;
typedef struct { time_t t; char ip[48]; char method[12]; char uri[200]; char rule[12]; char cat[28]; int score; int blocked; } WafEvent;

static WafProxyCfg g_wafpCfg;
static volatile int g_wafpRun = 0;
static kv_sock g_wafpSock = KV_BAD;
static unsigned long g_wafpTotal = 0, g_wafpBlocked = 0, g_wafpAllowed = 0, g_wafpUpErr = 0, g_wafpActive = 0;
static WafEvent g_wafpEv[WAFP_EVENTS]; static int g_wafpEvN = 0; static KV_MUTEX g_wafpMu; static int g_wafpMuInit = 0;
typedef void (*WafpAlertFn)(const char *sev, const char *msg);
static WafpAlertFn g_wafpAlert = NULL;

static void wafp_event(const char *ip, const char *m, const char *uri, const WafVerdict *v, int blocked) {
    kv_lock(&g_wafpMu); WafEvent *e = &g_wafpEv[g_wafpEvN % WAFP_EVENTS]; g_wafpEvN++;
    e->t = time(NULL); snprintf(e->ip, sizeof e->ip, "%s", ip); snprintf(e->method, sizeof e->method, "%s", m); snprintf(e->uri, sizeof e->uri, "%.199s", uri);
    snprintf(e->rule, sizeof e->rule, "%s", v->nhits ? v->hits[0].rule : ""); snprintf(e->cat, sizeof e->cat, "%s", v->top); e->score = v->score; e->blocked = blocked; kv_unlock(&g_wafpMu);
}
static int waf_proxy_events(WafEvent *out, int max) {   /* newest first */
    kv_lock(&g_wafpMu); int n = g_wafpEvN < WAFP_EVENTS ? g_wafpEvN : WAFP_EVENTS; if (n > max) n = max;
    for (int i = 0; i < n; i++) out[i] = g_wafpEv[(g_wafpEvN - 1 - i) % WAFP_EVENTS]; kv_unlock(&g_wafpMu); return n;
}

static int wafp_send_all(kv_sock s, const char *b, size_t n) { size_t w = 0; while (w < n) { int k = (int)send(s, b + w, (int)(n - w > 65536 ? 65536 : n - w), 0); if (k <= 0) return 0; w += (size_t)k; } return 1; }

static int wafp_more(kv_sock s, char **b, size_t *len, size_t *cap) {
    if (*len >= *cap) { if (*cap >= WAFP_MAX_HEAD + WAFP_MAX_BODY + 64) return 0; size_t nc = *cap * 2; char *nb = (char *)realloc(*b, nc + 1); if (!nb) return 0; *b = nb; *cap = nc; }
    int k = (int)recv(s, *b + *len, (int)(*cap - *len), 0); if (k <= 0) return 0; *len += (size_t)k; (*b)[*len] = 0; return 1;
}
static int wafp_need(kv_sock s, char **b, size_t *len, size_t *cap, size_t need) { while (*len < need) if (!wafp_more(s, b, len, cap)) return 0; return 1; }

/* Reads one complete request. raw (malloc) = exact bytes received; *body points at the inspected body (inside raw, or a
 * separate malloc when the request was chunked and had to be decoded for inspection). */
static int wafp_read_request(kv_sock s, char **raw, size_t *rawLen, size_t *headLen, size_t *bodyOff, char **body, size_t *bodyLen, int *err) {
    size_t cap = 16384, len = 0; char *b = (char *)malloc(cap + 1); if (!b) return 0; *err = 0; size_t hend = 0; b[0] = 0;
    while (!hend) {
        if (!wafp_more(s, &b, &len, &cap)) { free(b); return 0; }
        char *e = strstr(b, "\r\n\r\n"); if (e) hend = (size_t)(e - b) + 4; else if (len > WAFP_MAX_HEAD) { *err = 431; free(b); return 0; }
    }
    char *lc = (char *)malloc(hend + 1); if (!lc) { free(b); return 0; } memcpy(lc, b, hend); lc[hend] = 0; for (char *c = lc; *c; c++) *c = (char)tolower((unsigned char)*c);
    int chunked = 0; { char *te = strstr(lc, "\ntransfer-encoding:"); if (te) { char *eol = strchr(te + 1, '\n'); if (eol) { *eol = 0; chunked = strstr(te, "chunked") != NULL; } } }
    long cl = -1; { const char *cp = strstr(lc, "\ncontent-length:"); if (cp) cl = atol(cp + 16); } free(lc);
    *body = NULL; *bodyLen = 0;
    if (chunked) {
        size_t pos = hend, decLen = 0; char *decoded = (char *)malloc(1); if (!decoded) { free(b); return 0; }
        for (;;) {
            char *nl = NULL; for (;;) { if (pos < len) nl = (char *)memchr(b + pos, '\n', len - pos); if (nl) break; if (!wafp_more(s, &b, &len, &cap)) { free(b); free(decoded); return 0; } }
            size_t csz = (size_t)strtoul(b + pos, NULL, 16); pos = (size_t)(nl - b) + 1;
            if (csz == 0) {                                   /* trailers until an empty line */
                for (;;) { char *l2 = NULL; for (;;) { if (pos < len) l2 = (char *)memchr(b + pos, '\n', len - pos); if (l2) break; if (!wafp_more(s, &b, &len, &cap)) { free(b); free(decoded); return 0; } }
                    size_t ll = (size_t)(l2 - (b + pos)); int empty = (ll == 0 || (ll == 1 && b[pos] == '\r')); pos = (size_t)(l2 - b) + 1; if (empty) break; }
                break; }
            if (decLen + csz > WAFP_MAX_BODY) { *err = 413; free(b); free(decoded); return 0; }
            if (!wafp_need(s, &b, &len, &cap, pos + csz + 2)) { free(b); free(decoded); return 0; }
            char *nd = (char *)realloc(decoded, decLen + csz + 1); if (!nd) { free(b); free(decoded); return 0; } decoded = nd; memcpy(decoded + decLen, b + pos, csz); decLen += csz; pos += csz + 2;
        }
        *body = decoded; *bodyLen = decLen; len = pos;
    } else {
        size_t need = cl > 0 ? (size_t)cl : 0; if (need > WAFP_MAX_BODY) { *err = 413; free(b); return 0; }
        if (!wafp_need(s, &b, &len, &cap, hend + need)) { free(b); return 0; }
        *body = b + hend; *bodyLen = need; len = hend + need;
    }
    *raw = b; *rawLen = len; *headLen = hend; *bodyOff = hend; return 1;
}

static void wafp_block_page(kv_sock s, const WafVerdict *v, unsigned long id, const char *ip) {
    char body[900]; int bl = snprintf(body, sizeof body, "<!doctype html><html><head><title>403 Blocked</title></head><body style=\"font-family:sans-serif;background:#0b1220;color:#e5ecf9;text-align:center;padding-top:12vh\"><h1>Request blocked</h1><p>Kaevex WAF stopped this request (%s, score %d).</p><p style=\"color:#8aa0c0\">Reference: KVX-%lu &middot; %s</p></body></html>", v->top[0] ? v->top : "policy", v->score, id, ip);
    char head[300]; int hl = snprintf(head, sizeof head, "HTTP/1.1 403 Forbidden\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: %d\r\nConnection: close\r\nX-Kaevex-WAF: blocked\r\nCache-Control: no-store\r\n\r\n", bl);
    wafp_send_all(s, head, (size_t)hl); wafp_send_all(s, body, (size_t)bl);
}

typedef struct { kv_sock s; char ip[48]; } WafpConn;

static KV_THREAD_RET wafp_conn_thread(void *arg) {
    WafpConn *c = (WafpConn *)arg; kv_sock cs = c->s; char ip[48]; snprintf(ip, sizeof ip, "%s", c->ip); free(c);
    kv_set_timeout(cs, 15000); KV_ATOMIC_INC(&g_wafpActive);
    char *raw = NULL, *body = NULL; size_t rawLen = 0, headLen = 0, bodyOff = 0, bodyLen = 0; int err = 0;
    if (!wafp_read_request(cs, &raw, &rawLen, &headLen, &bodyOff, &body, &bodyLen, &err)) {
        if (err) { const char *m = err == 413 ? "413 Payload Too Large" : "431 Request Header Fields Too Large"; char r[200]; int l = snprintf(r, sizeof r, "HTTP/1.1 %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", m); wafp_send_all(cs, r, (size_t)l); }
        kv_close(cs); goto done;
    }
    {
        char *rl_end = strstr(raw, "\r\n"); char method[12] = "", uri[8200] = "", ver[12] = "";
        if (!rl_end || sscanf(raw, "%11s %8199s %11s", method, uri, ver) < 2) { const char *r = "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"; wafp_send_all(cs, r, strlen(r)); goto closeall; }
        size_t hl = headLen > (size_t)(rl_end - raw) + 2 ? headLen - ((size_t)(rl_end - raw) + 2) : 0; char *hdrs = (char *)malloc(hl + 1); if (!hdrs) goto closeall; memcpy(hdrs, rl_end + 2, hl); hdrs[hl] = 0;
        { char *o = hdrs; for (char *i = hdrs; *i; i++) if (*i != '\r') *o++ = *i; *o = 0; }
        WafRequest rq = { method, uri, hdrs, (const unsigned char *)body, bodyLen }; WafVerdict v; waf_inspect(&rq, g_wafpCfg.paranoia, &v);
        KV_ATOMIC_INC(&g_wafpTotal); int block = v.blocked && !g_wafpCfg.detectOnly;
        if (v.nhits) wafp_event(ip, method, uri, &v, block);
        if (block) {
            unsigned long id = KV_ATOMIC_INC(&g_wafpBlocked); wafp_block_page(cs, &v, id, ip);
            if (g_wafpAlert) { char m[300]; snprintf(m, sizeof m, "WAF blocked %s %.80s from %s: %s [%s] score %d", method, uri, ip, v.top, v.hits[0].rule, v.score); g_wafpAlert(v.score >= 90 ? "CRITICAL" : "WARNING", m); }
            free(hdrs); goto closeall;
        }
        KV_ATOMIC_INC(&g_wafpAllowed); if (v.blocked && g_wafpAlert) { char m[260]; snprintf(m, sizeof m, "WAF (detect-only) would block %s %.80s from %s: %s", method, uri, ip, v.top); g_wafpAlert("WARNING", m); }
        /* forward */
        struct addrinfo hint, *res = NULL; memset(&hint, 0, sizeof hint); hint.ai_socktype = SOCK_STREAM; char ps[12]; snprintf(ps, sizeof ps, "%d", g_wafpCfg.upPort); kv_sock us = KV_BAD;
        if (getaddrinfo(g_wafpCfg.upHost, ps, &hint, &res) == 0) { for (struct addrinfo *a = res; a; a = a->ai_next) { us = socket(a->ai_family, a->ai_socktype, a->ai_protocol); if (us == KV_BAD) continue; kv_set_timeout(us, 30000); if (connect(us, a->ai_addr, (int)a->ai_addrlen) == 0) break; kv_close(us); us = KV_BAD; } freeaddrinfo(res); }
        if (us == KV_BAD) { KV_ATOMIC_INC(&g_wafpUpErr); const char *r = "HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\nContent-Length: 28\r\nConnection: close\r\n\r\nKaevex WAF: upstream is down"; wafp_send_all(cs, r, strlen(r)); free(hdrs); goto closeall; }
        /* rebuild the head: drop hop-by-hop + client X-Forwarded-For, add ours */
        size_t cap2 = hl + 512 + strlen(method) + strlen(uri) + 32; char *out = (char *)malloc(cap2); size_t w = 0; w += (size_t)snprintf(out + w, cap2 - w, "%s %s %s\r\n", method, uri, ver[0] ? ver : "HTTP/1.1");
        for (char *p = hdrs; *p;) { char *e = strchr(p, '\n'); size_t l = e ? (size_t)(e - p) : strlen(p); char *line = p; if (l) { int skip = 0; static const char *drop[] = { "connection:", "proxy-connection:", "keep-alive:", "x-forwarded-for:", "x-real-ip:", "upgrade:", NULL }; for (int i = 0; drop[i]; i++) if (!waf_strncasecmp(line, drop[i], strlen(drop[i]))) skip = 1; if (!skip && w + l + 4 < cap2) { memcpy(out + w, line, l); w += l; out[w++] = '\r'; out[w++] = '\n'; } } p = e ? e + 1 : p + l; if (!e) break; }
        w += (size_t)snprintf(out + w, cap2 - w, "X-Forwarded-For: %s\r\nX-Kaevex-WAF: passed\r\nConnection: close\r\n\r\n", ip);
        int ok = wafp_send_all(us, out, w); free(out); free(hdrs);
        if (ok && !(body >= raw && body <= raw + rawLen)) { /* chunked: forward the original bytes after the head */ ok = wafp_send_all(us, raw + headLen, rawLen - headLen); }
        else if (ok && bodyLen) ok = wafp_send_all(us, body, bodyLen);
        if (ok) { char buf[16384]; for (;;) { int k = (int)recv(us, buf, sizeof buf, 0); if (k <= 0) break; if (!wafp_send_all(cs, buf, (size_t)k)) break; } }
        kv_close(us);
    }
closeall:
    if (body && !(body >= raw && body <= raw + rawLen)) free(body);
    free(raw); kv_close(cs);
done:
#ifdef _WIN32
    InterlockedDecrement((volatile LONG *)&g_wafpActive);
    return 0;
#else
    __sync_sub_and_fetch(&g_wafpActive, 1);
    return NULL;
#endif
}

static KV_THREAD_RET wafp_accept_thread(void *arg) {
    (void)arg;
    while (g_wafpRun) {
        struct sockaddr_storage ss; socklen_t sl = sizeof ss; kv_sock cs = accept(g_wafpSock, (struct sockaddr *)&ss, &sl);
        if (cs == KV_BAD) { if (!g_wafpRun) break; continue; }
        if (g_wafpActive >= WAFP_MAX_CONN) { const char *r = "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"; wafp_send_all(cs, r, strlen(r)); kv_close(cs); continue; }
        WafpConn *c = (WafpConn *)malloc(sizeof *c); if (!c) { kv_close(cs); continue; } c->s = cs; c->ip[0] = 0;
        if (ss.ss_family == AF_INET) inet_ntop(AF_INET, &((struct sockaddr_in *)&ss)->sin_addr, c->ip, sizeof c->ip); else if (ss.ss_family == AF_INET6) inet_ntop(AF_INET6, &((struct sockaddr_in6 *)&ss)->sin6_addr, c->ip, sizeof c->ip);
        if (!kv_spawn(wafp_conn_thread, c)) { kv_close(cs); free(c); }
    }
#ifdef _WIN32
    return 0;
#else
    return NULL;
#endif
}

static int waf_proxy_start(const WafProxyCfg *cfg, WafpAlertFn alertFn, char *err, size_t en) {
    if (g_wafpRun) { snprintf(err, en, "already running"); return 0; }
    if (!g_wafpMuInit) { kv_mutex_init(&g_wafpMu); g_wafpMuInit = 1; }
#ifdef _WIN32
    WSADATA w; WSAStartup(MAKEWORD(2, 2), &w);
#else
    signal(SIGPIPE, SIG_IGN);
#endif
    g_wafpCfg = *cfg; g_wafpAlert = alertFn; g_wafpTotal = g_wafpBlocked = g_wafpAllowed = g_wafpUpErr = 0;
    struct addrinfo hint, *res = NULL; memset(&hint, 0, sizeof hint); hint.ai_family = AF_INET; hint.ai_socktype = SOCK_STREAM; hint.ai_flags = AI_PASSIVE; char ps[12]; snprintf(ps, sizeof ps, "%d", cfg->listenPort);
    if (getaddrinfo(cfg->listenHost[0] ? cfg->listenHost : "127.0.0.1", ps, &hint, &res) != 0 || !res) { snprintf(err, en, "cannot resolve listen address"); return 0; }
    kv_sock s = socket(res->ai_family, res->ai_socktype, res->ai_protocol); if (s == KV_BAD) { freeaddrinfo(res); snprintf(err, en, "socket() failed"); return 0; }
    int one = 1; setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const char *)&one, sizeof one);
    if (bind(s, res->ai_addr, (int)res->ai_addrlen) != 0 || listen(s, 128) != 0) { freeaddrinfo(res); kv_close(s); snprintf(err, en, "cannot listen on %s:%d (port in use or no permission)", cfg->listenHost, cfg->listenPort); return 0; }
    freeaddrinfo(res); g_wafpSock = s; g_wafpRun = 1;
    if (!kv_spawn(wafp_accept_thread, NULL)) { g_wafpRun = 0; kv_close(s); snprintf(err, en, "cannot start thread"); return 0; }
    err[0] = 0; return 1;
}
static void waf_proxy_stop(void) { if (!g_wafpRun) return; g_wafpRun = 0; kv_close(g_wafpSock); g_wafpSock = KV_BAD; }

#endif /* WAF_PROXY_H */
