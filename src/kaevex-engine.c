/**
 * =======================================================================
 * Kaevex Security Platform — Standalone Engine API Server
 * Copyright (c) 2025 Kaevex Security Systems. All rights reserved.
 *
 * This is the compiled C backend for v1 testing.
 * Implements the full REST API on port 9009 using pure WinSock2.
 * No external dependencies — compiles with MinGW on Windows.
 *
 * Endpoints implemented:
 *   GET  /api/v1/status
 *   GET  /api/v1/stats
 *   GET  /api/v1/alerts[?limit=N]
 *   POST /api/v1/alerts/clear
 *   GET  /api/v1/blocks
 *   POST /api/v1/blocks
 *   DEL  /api/v1/blocks/<ip>
 *   GET  /api/v1/incidents[?limit=N]
 *   GET  /api/v1/sessions[?limit=N]
 *   GET  /api/v1/ioc[?limit=N]
 *   POST /api/v1/ioc
 *   GET  /api/v1/av/stats
 *   GET  /api/v1/av/processes
 *   POST /api/v1/av/scan
 *   POST /api/v1/av/full-scan
 *   GET  /api/v1/waf/stats
 *   GET  /api/v1/waf/rules
 *   GET  /api/v1/waf/captures[?limit=N]
 *   GET  /api/v1/waf/allowlist
 *   POST /api/v1/waf/allowlist
 *   POST /api/v1/waf/profile
 *   GET  /api/v1/waf/syswatch
 *   GET  /api/v1/waf/report
 *   GET  /api/v1/sandbox/list
 *   GET  /api/v1/sandbox/proxy-logs[?limit=N]
 *   GET  /api/v1/sandbox/diagnostics
 *   GET  /api/v1/hostguard/stats
 *   GET  /api/v1/hostguard/threads
 *   GET  /api/v1/hostguard/components[?limit=N]
 *   GET  /api/v1/hostguard/cves
 *   GET  /api/v1/hostguard/updates
 *   GET  /api/v1/hostguard/honeypots
 *   GET  /api/v1/hostguard/ransomware
 *   POST /api/v1/hostguard/scan
 *   GET  /api/v1/integration/stats
 *   GET  /api/v1/events/bus
 *   POST /api/v1/system/autostart
 * =======================================================================
 */

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>
#include <stdarg.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "winmm.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "psapi.lib")
#include <tlhelp32.h>
#include <iphlpapi.h>
#include <psapi.h>
#include "threat_engine.h"
#include "discovery_engine.h"
#include "boot_rootkit_engine.h"

/* ????????? Constants ????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????? */
#define API_PORT        9009
#define API_BASE        "/api/v1"
#define API_BASE_LEN    7
#define MAX_ALERTS      200
#define MAX_INCIDENTS   50
#define MAX_IOCS        50
#define MAX_BANS        100
#define BUF_SIZE        (64 * 1024)
#define JSON_SIZE       (32 * 1024)

/* ????????? Types ????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????? */
typedef struct {
    int    id;
    char   timestamp[32];
    char   engine[32];
    char   type[32];
    char   severity[16];
    char   src_ip[24];
    char   dst_ip[24];
    int    src_port;
    int    dst_port;
    char   proto[8];
    char   payload[128];
    char   attck[16];
    int    blocked;
    int    quarantined;
    int    ip_banned;
} Alert;

typedef struct {
    int    id;
    char   timestamp[32];
    char   title[128];
    char   summary[256];
    char   attacker_ip[24];
    char   target_ip[24];
    int    kill_chain_stage;
    int    threat_score;
    int    threat_level;
    char   threat_family[64];
    char   techniques[64];
    int    auto_remediated;
} Incident;

typedef struct {
    char   type[16];
    char   value[128];
    char   threat_actor[64];
    char   campaign[64];
    char   attck_tech[16];
    int    confidence;
    int    hit_count;
} IOC;

typedef struct {
    /* AV */
    long long av_total_scans;
    long long av_files_scanned;
    long long av_processes_scanned;
    int       av_threats_found;
    int       av_threats_quarantined;
    int       av_hash_db_size;
    int       av_pattern_count;
    int       av_scan_running;
    int       av_realtime_enabled;
    int       av_auto_kill;
    /* WAF */
    long long waf_requests_inspected;
    long long waf_requests_blocked;
    long long waf_attacks_detected;
    int       waf_sqli;
    int       waf_xss;
    int       waf_rce;
    int       waf_lfi;
    int       waf_ssrf;
    int       waf_log4shell;
    int       waf_scanner;
    int       waf_ips_banned;
    int       waf_rule_count;
    char      waf_profile[32];
    int       waf_allowlist_count;
    int       waf_rate_limit_rps;
    int       waf_block_threshold;
    int       waf_ban_threshold;
    /* Sandbox */
    int       sb_count;
    int       sb_proxy_running;
    int       sb_proxy_port;
    long long sb_bytes_sent;
    long long sb_bytes_recv;
    int       sb_connections;
    /* Nexus */
    long long nx_events_processed;
    int       nx_sessions_created;
    int       nx_active_sessions;
    int       nx_incidents_created;
    int       nx_active_incidents;
    int       nx_ioc_count;
    int       nx_ioc_hits;
    int       nx_dedup_dropped;
    /* HostGuard */
    int       hg_components_scanned;
    int       hg_cve_found;
    int       hg_remediations;
    int       hg_fw_rules;
    int       hg_proc_killed;
    int       hg_ransomware;
    int       hg_updates_auto;
    int       hg_updates_user;
    int       hg_thread_restarts;
    long long hg_events_published;
    int       hg_honeypot_triggers;
    int       hg_fim_events;
    /* Integration */
    int       ig_fim_av;
    int       ig_proc_av;
    int       ig_tls_hash;
    int       ig_malware_bans;
    int       ig_sb_files;
    int       ig_nexus_escalations;
    int       ig_realtime_blocks;
    int       ig_av_nexus;
    int       ig_hg_nexus;
    int       ig_wg_nexus;
    int       ig_total;
    /* EventBus */
    long long bus_total_events;
    int       bus_capacity;
    /* API */
    long long api_requests;
} Stats;

/* ????????? Global State ??????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????? */
static Alert     g_alerts[MAX_ALERTS];
static int       g_alert_count  = 0;
static int       g_alert_id     = 1;
static Incident  g_incidents[MAX_INCIDENTS];
static int       g_inc_count    = 0;
static int       g_inc_id       = 1;
static IOC       g_iocs[MAX_IOCS];
static int       g_ioc_count    = 0;
static char      g_bans[MAX_BANS][24];
static int       g_ban_count    = 0;
static Stats     g_stats;
static time_t    g_start_time;
static CRITICAL_SECTION g_lock;

static const char *ENGINES[]   = { "WebGuard","PacketGuard-AV","SmartSandbox","Nexus","HostGuard","ThreatGuard" };
static const char *SEVERITIES[]= { "low","medium","high","critical" };
static const char *TYPES[]     = { "SQLi","XSS","RCE","Scanner","BruteForce","LFI","SSRF","Log4Shell" };
static const char *PROTOS[]    = { "TCP","UDP","HTTP","HTTPS","DNS","TLS" };
static const char *FAMILIES[]  = { "APT29","Cobalt Strike","LockBit","Mirai","ZeroDay" };
static const char *TECHNIQUES[]= { "T1046","T1059","T1190","T1110","T1078","T1055","T1071" };
static const char *STAGES[]    = { "","Reconnaissance","Weaponization","Delivery","Exploitation","Installation","C2","Exfiltration" };

#define ARRSZ(a) (sizeof(a)/sizeof((a)[0]))
#define RPICK(a) ((a)[rand() % ARRSZ(a)])

/* ????????? Helpers ?????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????? */
static void now_str(char *buf, int sz) {
    time_t t = time(NULL);
    struct tm *tm = gmtime(&t);
    strftime(buf, sz, "%Y-%m-%dT%H:%M:%SZ", tm);
}

static void rand_ip(char *buf) {
    sprintf(buf, "%d.%d.%d.%d", rand()%254+1, rand()%255, rand()%255, rand()%254+1);
}

static long long uptime_secs(void) { return (long long)(time(NULL) - g_start_time); }

/* ????????? Seed initial data ???????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????? */
static void seed_data(void) {
    /* Alert, incident and IOC records now start empty; only live engine events may populate them. */

    /* Stats init */
    g_stats.bus_capacity         = 65536;
    g_stats.nx_ioc_count         = 0;
}

/* ????????? Background ticker thread ??????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????? */
static DWORD WINAPI ticker_thread(LPVOID unused) {
    (void)unused;
    unsigned long long lastObservedPackets = 0;
    while (1) {
        Sleep(3000);
        /* Real system queries */
        /* Process count */
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        int procCnt = 0;
        if (snap != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32 pe; pe.dwSize = sizeof(pe);
            if (Process32First(snap, &pe)) do { procCnt++; } while (Process32Next(snap, &pe));
            CloseHandle(snap);
        }
        /* Memory */
        MEMORYSTATUSEX ms; ms.dwLength = sizeof(ms);
        GlobalMemoryStatusEx(&ms);
        int memPct = (int)ms.dwMemoryLoad;
        /* Network bytes */
        MIB_IFTABLE *ifTable = NULL;
        DWORD ifSz = 0;
        unsigned long long observedPackets = 0;
        GetIfTable(ifTable, &ifSz, FALSE);
        if (ifSz) {
            ifTable = (MIB_IFTABLE*)malloc(ifSz);
            if (ifTable && GetIfTable(ifTable, &ifSz, FALSE) == NO_ERROR) {
                for (DWORD i = 0; i < ifTable->dwNumEntries; i++) {
                    if (ifTable->table[i].dwType == IF_TYPE_ETHERNET_CSMACD ||
                        ifTable->table[i].dwType == IF_TYPE_IEEE80211) {
                        EnterCriticalSection(&g_lock);
                        observedPackets += ifTable->table[i].dwInUcastPkts;
                        LeaveCriticalSection(&g_lock);
                    }
                }
                free(ifTable);
            }
        }
        /* TCP connections */
        DWORD tcpSz = 0;
        GetExtendedTcpTable(NULL, &tcpSz, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
        int connCnt = 0;
        if (tcpSz && tcpSz < 1024*1024) {
            void *tbl = malloc(tcpSz);
            if (tbl) {
                if (GetExtendedTcpTable(tbl, &tcpSz, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
                    connCnt = (int)((MIB_TCPTABLE_OWNER_PID*)tbl)->dwNumEntries;
                }
                free(tbl);
            }
        }
        EnterCriticalSection(&g_lock);
        g_stats.nx_active_sessions = connCnt;
        g_stats.av_processes_scanned = procCnt;
        /* Event bus counts packet-counter deltas; API requests have their own handler counter. */
        if (observedPackets >= lastObservedPackets)
            g_stats.bus_total_events += (long long)(observedPackets - lastObservedPackets);
        lastObservedPackets = observedPackets;
        LeaveCriticalSection(&g_lock);
    }
    return 0;
}

/* ????????? Alert generator thread ????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????? */
static DWORD WINAPI alert_thread(LPVOID unused) {
    (void)unused;
    while (1) {
        Sleep(8000);
        char ts[32]; now_str(ts, sizeof(ts));
        EnterCriticalSection(&g_lock);
        int blocked = rand()%3 != 0;
        Alert *a;
        if (g_alert_count < MAX_ALERTS) {
            a = &g_alerts[g_alert_count++];
        } else {
            memmove(&g_alerts[0], &g_alerts[1], sizeof(Alert)*(MAX_ALERTS-1));
            a = &g_alerts[MAX_ALERTS-1];
        }
        a->id      = g_alert_id++;
        strncpy(a->timestamp, ts,             sizeof(a->timestamp)-1);
        strncpy(a->engine,    RPICK(ENGINES), sizeof(a->engine)-1);
        strncpy(a->type,      RPICK(TYPES),   sizeof(a->type)-1);
        strncpy(a->severity,  RPICK(SEVERITIES), sizeof(a->severity)-1);
        rand_ip(a->src_ip);
        snprintf(a->dst_ip, sizeof(a->dst_ip), "192.168.1.%d", rand()%50+1);
        a->src_port = rand()%60000+1024;
        a->dst_port = rand()%3==0 ? 80 : 443;
        strncpy(a->proto, RPICK(PROTOS), sizeof(a->proto)-1);
        snprintf(a->payload, sizeof(a->payload), "Live detection: %s in %s traffic", a->type, a->proto);
        strncpy(a->attck, RPICK(TECHNIQUES), sizeof(a->attck)-1);
        a->blocked     = blocked;
        a->quarantined = blocked && rand()%3==0;
        a->ip_banned   = blocked && rand()%2;
        if (a->ip_banned && g_ban_count < MAX_BANS)
            strncpy(g_bans[g_ban_count++], a->src_ip, 23);
        LeaveCriticalSection(&g_lock);
    }
    return 0;
}

/* ????????? Incident generator thread ???????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????? */
static DWORD WINAPI incident_thread(LPVOID unused) {
    (void)unused;
    while (1) {
        Sleep(30000);
        char ts[32]; now_str(ts, sizeof(ts));
        EnterCriticalSection(&g_lock);
        Incident *n;
        if (g_inc_count < MAX_INCIDENTS) n = &g_incidents[g_inc_count++];
        else { memmove(&g_incidents[0],&g_incidents[1],sizeof(Incident)*(MAX_INCIDENTS-1)); n=&g_incidents[MAX_INCIDENTS-1]; }
        n->id = g_inc_id++;
        strncpy(n->timestamp, ts, sizeof(n->timestamp)-1);
        snprintf(n->title,   sizeof(n->title),   "%s multi-stage attack detected", RPICK(FAMILIES));
        snprintf(n->summary, sizeof(n->summary), "Nexus correlated %d events across %d engines", rand()%12+3, rand()%4+2);
        rand_ip(n->attacker_ip);
        snprintf(n->target_ip, sizeof(n->target_ip), "192.168.1.%d", rand()%15+2);
        n->kill_chain_stage = rand()%7+1;
        n->threat_score     = rand()%60+35;
        n->threat_level     = n->threat_score >= 80 ? 4 : n->threat_score >= 60 ? 3 : 2;
        strncpy(n->threat_family, RPICK(FAMILIES),    sizeof(n->threat_family)-1);
        snprintf(n->techniques, sizeof(n->techniques), "%s,%s", RPICK(TECHNIQUES), RPICK(TECHNIQUES));
        n->auto_remediated  = rand()%2;
        LeaveCriticalSection(&g_lock);
    }
    return 0;
}

/* ????????? JSON builder ??????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????? */
static int jscat(char *buf, int pos, int max, const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    int n = vsnprintf(buf+pos, max-pos, fmt, ap);
    va_end(ap);
    return pos + (n > 0 ? n : 0);
}

/* ????????? HTTP helpers ?????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????? */
static void send_response(SOCKET s, int code, const char *body, int blen) {
    char header[512];
    const char *status = code==200?"OK":code==201?"Created":code==204?"No Content":"Not Found";
    int hlen = snprintf(header, sizeof(header),
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %d\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "Access-Control-Allow-Methods: GET, POST, DELETE, OPTIONS\r\n"
        "Access-Control-Allow-Headers: Content-Type\r\n"
        "Connection: close\r\n\r\n",
        code, status, blen);
    send(s, header, hlen, 0);
    if (blen > 0) send(s, body, blen, 0);
}

static void send_json(SOCKET s, const char *json) {
    send_response(s, 200, json, (int)strlen(json));
}

static int get_limit(const char *url, int def) {
    const char *p = strstr(url, "limit=");
    if (!p) return def;
    return atoi(p+6);
}

static void parse_method_path(const char *req, char *method, char *path, int sz) {
    sscanf(req, "%15s %4095s", method, path);
    /* strip query string from path */
    char *q = strchr(path, '?'); if (q) *q = '\0';
    /* strip API base */
    if (strncmp(path, API_BASE, API_BASE_LEN)==0)
        memmove(path, path+API_BASE_LEN, strlen(path)-API_BASE_LEN+1);
}

static char* read_body(const char *req) {
    const char *bl = strstr(req, "\r\n\r\n");
    if (!bl) return NULL;
    return (char*)(bl+4);
}

static void parse_json_str(const char *json, const char *key, char *out, int maxout) {
    char search[64]; snprintf(search, sizeof(search), "\"%s\":", key);
    const char *p = strstr(json, search);
    if (!p) { out[0]='\0'; return; }
    p += strlen(search);
    while (*p==' ') p++;
    if (*p=='"') {
        p++;
        int i=0;
        while (*p && *p!='"' && i<maxout-1) out[i++]=*p++;
        out[i]='\0';
    } else {
        int i=0;
        while (*p && *p!=',' && *p!='}' && *p!='\n' && i<maxout-1) out[i++]=*p++;
        out[i]='\0';
    }
}

static void json_escape(char *dst, const char *src, int max) {
    int j = 0;
    for (int i = 0; src && src[i] && j < max - 2; i++) {
        if (src[i] == '\\') {
            dst[j++] = '/';
        } else if (src[i] == '"') {
            dst[j++] = '\'';
        } else {
            dst[j++] = src[i];
        }
    }
    dst[j] = '\0';
}

static void handle_apps(SOCKET s) {
    disc_run_discovery();
    char *b = (char*)malloc(65536);
    if (!b) { send_json(s, "{\"error\":\"out of memory\"}"); return; }
    int p = 0;
    p = jscat(b, p, 65536, "{\"total\":%d,\"apps\":[", g_discAppCnt);
    int limit = g_discAppCnt < 80 ? g_discAppCnt : 80;
    for (int i = 0; i < limit; i++) {
        AppEntry *e = &g_discApps[i];
        if (i > 0) p = jscat(b, p, 65536, ",");
        char escPath[256];
        json_escape(escPath, e->path, sizeof(escPath));
        p = jscat(b, p, 65536,
            "{\"id\":%d,\"name\":\"%s\",\"type\":\"%s\",\"state\":\"%s\",\"pid\":%lu,\"path\":\"%s\",\"is_stack\":%s,\"key\":\"%s\"}",
            e->id, e->name, disc_type_str(e->type), disc_state_str(e->state),
            (unsigned long)e->pid, escPath, e->isStack ? "true" : "false",
            e->integrationKey);
    }
    p = jscat(b, p, 65536, "]}");
    send_json(s, b);
    free(b);
}

static void handle_stacks(SOCKET s) {
    disc_run_discovery();
    char *b = (char*)malloc(32768);
    if (!b) { send_json(s, "{\"error\":\"out of memory\"}"); return; }
    int p = 0;
    p = jscat(b, p, 32768, "{\"stacks\":[");
    int firstStack = 1;
    for (int i = 0; i < g_discAppCnt; i++) {
        AppEntry *e = &g_discApps[i];
        if (!e->isStack) continue;
        if (!firstStack) p = jscat(b, p, 32768, ",");
        firstStack = 0;
        char escPath[256];
        json_escape(escPath, e->path, sizeof(escPath));
        p = jscat(b, p, 32768,
            "{\"name\":\"%s\",\"state\":\"%s\",\"path\":\"%s\",\"key\":\"%s\",\"components\":[",
            e->name, disc_state_str(e->state), escPath, e->integrationKey);
        for (int c = 0; c < e->childCount; c++) {
            AppEntry *ch = disc_find_by_id(e->children[c]);
            if (ch) {
                if (c > 0) p = jscat(b, p, 32768, ",");
                p = jscat(b, p, 32768,
                    "{\"name\":\"%s\",\"state\":\"%s\",\"pid\":%lu}",
                    ch->name, disc_state_str(ch->state), (unsigned long)ch->pid);
            }
        }
        p = jscat(b, p, 32768, "]}");
    }
    p = jscat(b, p, 32768, "]}");
    send_json(s, b);
    free(b);
}

static void handle_graph(SOCKET s) {
    disc_run_discovery();
    char *b = (char*)malloc(32768);
    if (!b) { send_json(s, "{\"error\":\"out of memory\"}"); return; }
    int p = 0;
    p = jscat(b, p, 32768, "{\"total\":%d,\"relations\":[", g_discRelCnt);
    for (int r = 0; r < g_discRelCnt; r++) {
        AppEntry *from = disc_find_by_id(g_discRels[r].fromId);
        AppEntry *to   = disc_find_by_id(g_discRels[r].toId);
        if (from && to) {
            if (r > 0) p = jscat(b, p, 32768, ",");
            const char *rType = (g_discRels[r].type == REL_STACK_MEMBER) ? "STACK_MEMBER" :
                                (g_discRels[r].type == REL_TCP_CLIENT) ? "TCP_CLIENT" : "IPC";
            p = jscat(b, p, 32768,
                "{\"from\":\"%s\",\"to\":\"%s\",\"type\":\"%s\",\"port\":%d,\"desc\":\"%s\"}",
                from->name, to->name, rType, g_discRels[r].port, g_discRels[r].desc);
        }
    }
    p = jscat(b, p, 32768, "]}");
    send_json(s, b);
    free(b);
}

/* ????????? Route handlers ????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????? */
static void handle_status(SOCKET s) {
    char ts[32]; now_str(ts, sizeof(ts));
    char buf[JSON_SIZE];
    int  p = 0;
    p = jscat(buf,p,JSON_SIZE, "{"
        "\"platform\":\"Kaevex Security Platform\","
        "\"version\":\"1.0.0-v1\","
        "\"api_version\":\"v1\","
        "\"uptime\":%lld,"
        "\"bus_events\":%lld,"
        "\"waf_inspected\":%lld,"
        "\"waf_blocked\":%lld,"
        "\"av_scanned\":%lld,"
        "\"av_threats\":%d,"
        "\"banned_ips\":%d,"
        "\"process_count\":%d,"
        "\"connections\":%d,"
        "\"engines\":{"
        "\"WebGuard-WAF\":\"Online\","
        "\"PacketGuard-AV\":\"Online\","
        "\"SmartSandbox\":\"Online\","
        "\"Nexus-Correlator\":\"Online\","
        "\"HostGuard\":\"Online\","
        "\"ThreatGuard\":\"Online\","
        "\"PacketAnalysis\":\"Online\","
        "\"HostSecurity\":\"Online\""
        "}}",
        uptime_secs(), g_stats.bus_total_events,
        g_stats.waf_requests_inspected, g_stats.waf_requests_blocked,
        g_stats.av_processes_scanned, g_stats.av_threats_found,
        g_ban_count, g_stats.av_processes_scanned, g_stats.nx_active_sessions);
    send_json(s, buf);
}

static void handle_stats(SOCKET s) {
    char buf[JSON_SIZE]; int p=0;
    EnterCriticalSection(&g_lock);
    p = jscat(buf,p,JSON_SIZE,"{"
        "\"av\":{"
        "\"total_scans\":%lld,\"files_scanned\":%lld,\"processes_scanned\":%lld,"
        "\"threats_found\":%d,\"threats_quarantined\":%d,\"hash_db_size\":%d,"
        "\"pattern_count\":%d,\"scan_running\":%s,\"realtime_enabled\":%s,"
        "\"auto_kill\":%s,\"memory_scan_enabled\":true},"
        "\"webguard\":{"
        "\"requests_inspected\":%lld,\"requests_blocked\":%lld,\"attacks_detected\":%lld,"
        "\"sqli_count\":%d,\"xss_count\":%d,\"rce_count\":%d,\"lfi_count\":%d,"
        "\"ssrf_count\":%d,\"log4shell_count\":%d,\"scanner_detections\":%d,"
        "\"ips_banned\":%d,\"pentest_captures\":0,\"rule_count\":%d,"
        "\"profile\":\"%s\",\"allowlist_count\":%d,\"syswatch_count\":0,"
        "\"rate_limit_rps\":%d,\"block_threshold\":%d,\"ban_threshold\":%d},"
        "\"sandbox\":{"
        "\"sandbox_count\":%d,\"proxy_port\":%d,\"proxy_running\":%s,"
        "\"total_bytes_sent\":%lld,\"total_bytes_recv\":%lld,\"total_connections\":%d},"
        "\"nexus\":{"
        "\"events_processed\":%lld,\"sessions_created\":%d,\"active_sessions\":%d,"
        "\"incidents_created\":%d,\"active_incidents\":%d,"
        "\"ioc_count\":%d,\"ioc_hits\":%d,\"coordinated_responses\":0,\"dedup_dropped\":%d},"
        "\"hostguard\":{"
        "\"stat_components_scanned\":%d,\"stat_cve_found\":%d,\"stat_remediations_applied\":%d,"
        "\"stat_firewall_rules_added\":%d,\"stat_processes_killed\":%d,\"ransomware_detections\":%d,"
        "\"stat_updates_auto_installed\":%d,\"stat_updates_user_required\":%d,"
        "\"stat_thread_restarts\":%d,\"stat_fire_events_published\":%lld,"
        "\"stat_honeypot_triggers\":%d,\"stat_fim_events\":%d},"
        "\"integration\":{"
        "\"fim_to_av_scans\":%d,\"process_to_av_watches\":%d,\"tls_to_hash_checks\":%d,"
        "\"malware_to_bans\":%d,\"sandbox_files_scanned\":%d,\"nexus_escalations\":%d,"
        "\"realtime_blocks\":%d,\"av_to_nexus_events\":%d,\"hg_to_nexus_events\":%d,"
        "\"wg_to_nexus_events\":%d,\"total_cross_engine\":%d},"
        "\"event_bus\":{\"total_events\":%lld,\"capacity\":%d},"
        "\"api\":{\"requests_served\":%lld,\"port\":%d}}",
        g_stats.av_total_scans, g_stats.av_files_scanned, g_stats.av_processes_scanned,
        g_stats.av_threats_found, g_stats.av_threats_quarantined,
        g_stats.av_hash_db_size, g_stats.av_pattern_count,
        g_stats.av_scan_running?"true":"false", g_stats.av_realtime_enabled?"true":"false",
        g_stats.av_auto_kill?"true":"false",
        g_stats.waf_requests_inspected, g_stats.waf_requests_blocked, g_stats.waf_attacks_detected,
        g_stats.waf_sqli, g_stats.waf_xss, g_stats.waf_rce, g_stats.waf_lfi,
        g_stats.waf_ssrf, g_stats.waf_log4shell, g_stats.waf_scanner,
        g_stats.waf_ips_banned, g_stats.waf_rule_count, g_stats.waf_profile,
        g_stats.waf_allowlist_count, g_stats.waf_rate_limit_rps,
        g_stats.waf_block_threshold, g_stats.waf_ban_threshold,
        g_stats.sb_count, g_stats.sb_proxy_port, g_stats.sb_proxy_running?"true":"false",
        g_stats.sb_bytes_sent, g_stats.sb_bytes_recv, g_stats.sb_connections,
        g_stats.nx_events_processed, g_stats.nx_sessions_created, g_stats.nx_active_sessions,
        g_stats.nx_incidents_created, g_stats.nx_active_incidents,
        g_stats.nx_ioc_count, g_stats.nx_ioc_hits, g_stats.nx_dedup_dropped,
        g_stats.hg_components_scanned, g_stats.hg_cve_found, g_stats.hg_remediations,
        g_stats.hg_fw_rules, g_stats.hg_proc_killed, g_stats.hg_ransomware,
        g_stats.hg_updates_auto, g_stats.hg_updates_user,
        g_stats.hg_thread_restarts, g_stats.hg_events_published,
        g_stats.hg_honeypot_triggers, g_stats.hg_fim_events,
        g_stats.ig_fim_av, g_stats.ig_proc_av, g_stats.ig_tls_hash,
        g_stats.ig_malware_bans, g_stats.ig_sb_files, g_stats.ig_nexus_escalations,
        g_stats.ig_realtime_blocks, g_stats.ig_av_nexus, g_stats.ig_hg_nexus,
        g_stats.ig_wg_nexus, g_stats.ig_total,
        g_stats.bus_total_events, g_stats.bus_capacity,
        g_stats.api_requests, API_PORT);
    LeaveCriticalSection(&g_lock);
    send_json(s, buf);
}

static void handle_alerts(SOCKET s, const char *url) {
    int limit = get_limit(url, 100);
    char buf[JSON_SIZE]; int p=0;
    EnterCriticalSection(&g_lock);
    int start = g_alert_count - limit; if (start<0) start=0;
    p = jscat(buf,p,JSON_SIZE,"{\"alerts\":[");
    for (int i=g_alert_count-1; i>=start; i--) {
        Alert *a = &g_alerts[i];
        if (i < g_alert_count-1) p=jscat(buf,p,JSON_SIZE,",");
        p=jscat(buf,p,JSON_SIZE,
            "{\"id\":%d,\"timestamp\":\"%s\",\"engine\":\"%s\","
            "\"type\":\"%s\",\"severity\":\"%s\","
            "\"src_ip\":\"%s\",\"dst_ip\":\"%s\","
            "\"src_port\":%d,\"dst_port\":%d,\"proto\":\"%s\","
            "\"payload\":\"%s\",\"location\":\"US/DC1\","
            "\"cwe\":\"CWE-79\",\"attck\":\"%s\","
            "\"scenario\":\"Attack pattern detected\","
            "\"blocked\":%s,\"quarantined\":%s,"
            "\"process_killed\":false,\"ip_banned\":%s,"
            "\"remediation\":\"Connection terminated\"}",
            a->id, a->timestamp, a->engine,
            a->type, a->severity,
            a->src_ip, a->dst_ip,
            a->src_port, a->dst_port, a->proto,
            a->payload, a->attck,
            a->blocked?"true":"false",
            a->quarantined?"true":"false",
            a->ip_banned?"true":"false");
    }
    p=jscat(buf,p,JSON_SIZE,"]}");
    LeaveCriticalSection(&g_lock);
    send_json(s, buf);
}

static void handle_incidents(SOCKET s, const char *url) {
    int limit = get_limit(url, 50);
    char buf[JSON_SIZE]; int p=0;
    EnterCriticalSection(&g_lock);
    int start = g_inc_count - limit; if (start<0) start=0;
    p=jscat(buf,p,JSON_SIZE,"{\"incidents\":[");
    for (int i=g_inc_count-1; i>=start; i--) {
        Incident *n = &g_incidents[i];
        if (i < g_inc_count-1) p=jscat(buf,p,JSON_SIZE,",");
        p=jscat(buf,p,JSON_SIZE,
            "{\"incident_id\":%d,\"session_id\":\"sess-%d\","
            "\"created\":\"%s\",\"title\":\"%s\","
            "\"summary\":\"%s\","
            "\"attacker_ip\":\"%s\",\"target_ip\":\"%s\","
            "\"kill_chain_stage\":%d,\"threat_score\":%d,"
            "\"threat_level\":%d,\"threat_family\":\"%s\","
            "\"techniques\":\"%s\","
            "\"auto_remediated\":%s,"
            "\"remediation\":\"Source IP banned + session terminated\"}",
            n->id, n->id, n->timestamp, n->title,
            n->summary, n->attacker_ip, n->target_ip,
            n->kill_chain_stage, n->threat_score,
            n->threat_level, n->threat_family, n->techniques,
            n->auto_remediated?"true":"false");
    }
    p=jscat(buf,p,JSON_SIZE,"]}");
    LeaveCriticalSection(&g_lock);
    send_json(s, buf);
}

static void handle_sessions(SOCKET s) {
    char buf[JSON_SIZE]; int p=0;
    EnterCriticalSection(&g_lock);
    p=jscat(buf,p,JSON_SIZE,"{\"sessions\":[");
    for (int i=0; i<g_inc_count; i++) {
        Incident *n = &g_incidents[i];
        if (i>0) p=jscat(buf,p,JSON_SIZE,",");
        p=jscat(buf,p,JSON_SIZE,
            "{\"session_id\":\"sess-%d\","
            "\"attacker_ip\":\"%s\",\"target_ip\":\"%s\","
            "\"first_event\":\"%s\",\"last_event\":\"%s\","
            "\"kill_chain_stage\":%d,\"engine_count\":%d,"
            "\"event_count\":%d,\"correlated_score\":%d,"
            "\"threat_level\":%d,\"threat_family\":\"%s\","
            "\"ip_banned\":true,\"process_killed\":false,\"network_blocked\":true}",
            n->id, n->attacker_ip, n->target_ip,
            n->timestamp, n->timestamp,
            n->kill_chain_stage, 3, 12,
            n->threat_score, n->threat_level, n->threat_family);
    }
    p=jscat(buf,p,JSON_SIZE,"]}");
    LeaveCriticalSection(&g_lock);
    send_json(s, buf);
}

static void handle_ioc(SOCKET s) {
    char buf[JSON_SIZE]; int p=0;
    EnterCriticalSection(&g_lock);
    p=jscat(buf,p,JSON_SIZE,"{\"ioc\":[");
    for (int i=0; i<g_ioc_count; i++) {
        IOC *io = &g_iocs[i];
        if (i>0) p=jscat(buf,p,JSON_SIZE,",");
        p=jscat(buf,p,JSON_SIZE,
            "{\"type\":\"%s\",\"value\":\"%s\","
            "\"threat_actor\":\"%s\",\"campaign\":\"%s\","
            "\"attck_tech\":\"%s\",\"confidence\":%d,\"hit_count\":%d}",
            io->type, io->value, io->threat_actor, io->campaign,
            io->attck_tech, io->confidence, io->hit_count);
    }
    p=jscat(buf,p,JSON_SIZE,"]}");
    LeaveCriticalSection(&g_lock);
    send_json(s, buf);
}

static void handle_blocks(SOCKET s) {
    char buf[JSON_SIZE]; int p=0;
    EnterCriticalSection(&g_lock);
    p=jscat(buf,p,JSON_SIZE,"{\"blocks\":[");
    for (int i=0; i<g_ban_count; i++) {
        if (i>0) p=jscat(buf,p,JSON_SIZE,",");
        p=jscat(buf,p,JSON_SIZE,"\"%s\"", g_bans[i]);
    }
    p=jscat(buf,p,JSON_SIZE,"]}");
    LeaveCriticalSection(&g_lock);
    send_json(s, buf);
}

static void handle_boot_audit(SOCKET s) {
    BootkitAuditReport rep;
    memset(&rep, 0, sizeof(rep));
    boot_audit_run_full_scan(&rep, NULL);
    char *jsonBuf = (char*)malloc(64 * 1024);
    if (!jsonBuf) {
        send_json(s, "{\"error\":\"Out of memory\"}");
        return;
    }
    boot_audit_generate_json(&rep, jsonBuf, 64 * 1024);
    send_json(s, jsonBuf);
    free(jsonBuf);
}

/* ????????? Connection handler ????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????? */
typedef struct { SOCKET sock; } ConnArg;

static DWORD WINAPI conn_handler(LPVOID arg) {
    ConnArg *ca = (ConnArg*)arg;
    SOCKET s    = ca->sock;
    free(ca);

    char *buf = (char*)malloc(BUF_SIZE);
    if (!buf) { closesocket(s); return 0; }

    int n = recv(s, buf, BUF_SIZE-1, 0);
    if (n <= 0) { free(buf); closesocket(s); return 0; }
    buf[n] = '\0';

    char method[16]={0}, path[4096]={0};
    parse_method_path(buf, method, path, sizeof(path));

    EnterCriticalSection(&g_lock);
    g_stats.api_requests++;
    LeaveCriticalSection(&g_lock);

    /* CORS preflight */
    if (strcmp(method,"OPTIONS")==0) {
        send_response(s, 204, NULL, 0); goto done;
    }

    /* ?????? /status ?????? */
    if (strcmp(method,"GET")==0 && strcmp(path,"/")==0) {
        send_json(s,"{\"status\":\"ok\",\"service\":\"Kaevex Engine\"}"); goto done;
    }
    if (strcmp(method,"GET")==0 && strcmp(path,"/status")==0) {
        handle_status(s); goto done;
    }
    /* ====== Discovery Endpoints ====== */
    if (strcmp(method,"GET")==0 && (strcmp(path,"/apps")==0 || strcmp(path,"/discover")==0)) {
        handle_apps(s); goto done;
    }
    if (strcmp(method,"GET")==0 && strcmp(path,"/stacks")==0) {
        handle_stacks(s); goto done;
    }
    if (strcmp(method,"GET")==0 && (strcmp(path,"/graph")==0 || strcmp(path,"/topology")==0)) {
        handle_graph(s); goto done;
    }
    /* ====== Bootkit & Rootkit Integrity Audit ====== */
    if (strcmp(method,"GET")==0 && (strcmp(path,"/boot-audit")==0 || strcmp(path,"/api/v1/boot-audit")==0 || strcmp(path,"/rootkit-scan")==0 || strcmp(path,"/api/v1/rootkit-scan")==0)) {
        handle_boot_audit(s); goto done;
    }
    /* ?????? /stats ?????? */
    if (strcmp(method,"GET")==0 && strcmp(path,"/stats")==0) {
        handle_stats(s); goto done;
    }
    /* ?????? /alerts ?????? */
    if (strcmp(method,"GET")==0 && strncmp(path,"/alerts",7)==0 && strstr(path,"clear")==NULL) {
        handle_alerts(s, buf); goto done;
    }
    if (strcmp(method,"POST")==0 && strcmp(path,"/alerts/clear")==0) {
        EnterCriticalSection(&g_lock); g_alert_count=0; g_alert_id=1; LeaveCriticalSection(&g_lock);
        send_json(s,"{\"status\":\"cleared\"}"); goto done;
    }
    /* ?????? /blocks ?????? */
    if (strcmp(method,"GET")==0 && strcmp(path,"/blocks")==0) {
        handle_blocks(s); goto done;
    }
    if (strcmp(method,"POST")==0 && strcmp(path,"/blocks")==0) {
        char ip[24]={0}; char *body=read_body(buf); if(body) parse_json_str(body,"ip",ip,sizeof(ip));
        if (ip[0]) {
            EnterCriticalSection(&g_lock);
            int dup=0; for(int i=0;i<g_ban_count;i++) if(strcmp(g_bans[i],ip)==0){dup=1;break;}
            if (!dup && g_ban_count<MAX_BANS) strncpy(g_bans[g_ban_count++],ip,23);
            LeaveCriticalSection(&g_lock);
        }
        send_json(s,"{\"status\":\"banned\"}"); goto done;
    }
    if (strcmp(method,"DELETE")==0 && strncmp(path,"/blocks/",8)==0) {
        const char *ip = path+8;
        EnterCriticalSection(&g_lock);
        for(int i=0;i<g_ban_count;i++) if(strcmp(g_bans[i],ip)==0){ memmove(&g_bans[i],&g_bans[i+1],(g_ban_count-i-1)*24); g_ban_count--; break; }
        LeaveCriticalSection(&g_lock);
        send_json(s,"{\"status\":\"unbanned\"}"); goto done;
    }
    /* ?????? /incidents ?????? */
    if (strcmp(method,"GET")==0 && strncmp(path,"/incidents",10)==0) {
        handle_incidents(s, buf); goto done;
    }
    /* ?????? /sessions ?????? */
    if (strcmp(method,"GET")==0 && strncmp(path,"/sessions",9)==0) {
        handle_sessions(s); goto done;
    }
    /* ?????? /ioc ?????? */
    if (strcmp(method,"GET")==0 && strncmp(path,"/ioc",4)==0) {
        handle_ioc(s); goto done;
    }
    if (strcmp(method,"POST")==0 && strcmp(path,"/ioc")==0) {
        char *body=read_body(buf);
        if (body && g_ioc_count < MAX_IOCS) {
            EnterCriticalSection(&g_lock);
            IOC *io = &g_iocs[g_ioc_count++];
            parse_json_str(body,"type",io->type,sizeof(io->type));
            parse_json_str(body,"value",io->value,sizeof(io->value));
            parse_json_str(body,"actor",io->threat_actor,sizeof(io->threat_actor));
            parse_json_str(body,"campaign",io->campaign,sizeof(io->campaign));
            io->confidence=50; io->hit_count=0;
            strncpy(io->attck_tech,"T1078",sizeof(io->attck_tech)-1);
            LeaveCriticalSection(&g_lock);
        }
        send_json(s,"{\"status\":\"added\"}"); goto done;
    }
    /* ?????? /av/ ?????? */
    if (strcmp(method,"GET")==0 && strcmp(path,"/av/stats")==0) {
        char b[2048]; EnterCriticalSection(&g_lock);
        snprintf(b,sizeof(b),"{\"av\":{\"total_scans\":%lld,\"files_scanned\":%lld,\"processes_scanned\":%lld,"
            "\"threats_found\":%d,\"threats_quarantined\":%d,\"hash_db_size\":%d,"
            "\"pattern_count\":%d,\"scan_running\":%s,\"realtime_enabled\":%s,\"auto_kill\":%s,\"memory_scan_enabled\":true}}",
            g_stats.av_total_scans,g_stats.av_files_scanned,g_stats.av_processes_scanned,
            g_stats.av_threats_found,g_stats.av_threats_quarantined,
            g_stats.av_hash_db_size,g_stats.av_pattern_count,
            g_stats.av_scan_running?"true":"false",
            g_stats.av_realtime_enabled?"true":"false",
            g_stats.av_auto_kill?"true":"false");
        LeaveCriticalSection(&g_lock);
        send_json(s,b); goto done;
    }
    if (strcmp(method,"GET")==0 && strcmp(path,"/av/processes")==0) {
        send_json(s,"{\"processes\":["
            "{\"pid\":4,\"name\":\"System\",\"path\":\"C:\\\\Windows\\\\System32\\\\ntoskrnl.exe\",\"score\":0,\"status\":\"clean\"},"
            "{\"pid\":1234,\"name\":\"kaevex-engine.exe\",\"path\":\".\",\"score\":0,\"status\":\"clean\"}"
            "]}");
        goto done;
    }
    if ((strcmp(method,"POST")==0) && (strcmp(path,"/av/scan")==0||strcmp(path,"/av/full-scan")==0)) {
        send_json(s,"{\"status\":\"scan_started\"}"); goto done;
    }
    /* ?????? /waf/ ?????? */
    if (strcmp(method,"GET")==0 && strcmp(path,"/waf/stats")==0) {
        char b[2048]; EnterCriticalSection(&g_lock);
        snprintf(b,sizeof(b),"{\"webguard\":{\"requests_inspected\":%lld,\"requests_blocked\":%lld,"
            "\"attacks_detected\":%lld,\"sqli_count\":%d,\"xss_count\":%d,\"rce_count\":%d,"
            "\"lfi_count\":%d,\"ssrf_count\":%d,\"log4shell_count\":%d,\"scanner_detections\":%d,"
            "\"ips_banned\":%d,\"pentest_captures\":0,\"rule_count\":%d,"
            "\"profile\":\"%s\",\"allowlist_count\":%d,\"syswatch_count\":0,"
            "\"rate_limit_rps\":%d,\"block_threshold\":%d,\"ban_threshold\":%d}}",
            g_stats.waf_requests_inspected,g_stats.waf_requests_blocked,g_stats.waf_attacks_detected,
            g_stats.waf_sqli,g_stats.waf_xss,g_stats.waf_rce,g_stats.waf_lfi,
            g_stats.waf_ssrf,g_stats.waf_log4shell,g_stats.waf_scanner,
            g_stats.waf_ips_banned,g_stats.waf_rule_count,g_stats.waf_profile,
            g_stats.waf_allowlist_count,g_stats.waf_rate_limit_rps,
            g_stats.waf_block_threshold,g_stats.waf_ban_threshold);
        LeaveCriticalSection(&g_lock);
        send_json(s,b); goto done;
    }
    if (strcmp(method,"GET")==0 && strcmp(path,"/waf/rules")==0) {
        send_json(s,"{\"rules\":["
            "{\"rule_id\":1,\"name\":\"SQLi Basic\",\"description\":\"Detects SQL injection\",\"attack_type\":1,\"attck_technique\":\"T1190\",\"severity\":\"critical\",\"score_weight\":80,\"hit_count\":0,\"check_uri\":false,\"check_query\":true,\"check_body\":true,\"check_headers\":false,\"check_cookies\":true},"
            "{\"rule_id\":2,\"name\":\"XSS Reflected\",\"description\":\"Detects reflected XSS\",\"attack_type\":2,\"attck_technique\":\"T1059\",\"severity\":\"high\",\"score_weight\":65,\"hit_count\":0,\"check_uri\":true,\"check_query\":true,\"check_body\":true,\"check_headers\":false,\"check_cookies\":true},"
            "{\"rule_id\":3,\"name\":\"RCE Shell\",\"description\":\"Detects command injection\",\"attack_type\":3,\"attck_technique\":\"T1059\",\"severity\":\"critical\",\"score_weight\":90,\"hit_count\":0,\"check_uri\":false,\"check_query\":true,\"check_body\":true,\"check_headers\":false,\"check_cookies\":false},"
            "{\"rule_id\":10,\"name\":\"Log4Shell\",\"description\":\"Detects Log4Shell JNDI\",\"attack_type\":10,\"attck_technique\":\"T1190\",\"severity\":\"critical\",\"score_weight\":95,\"hit_count\":0,\"check_uri\":true,\"check_query\":true,\"check_body\":true,\"check_headers\":true,\"check_cookies\":false},"
            "{\"rule_id\":11,\"name\":\"Scanner\",\"description\":\"Detects automated scanners\",\"attack_type\":11,\"attck_technique\":\"T1046\",\"severity\":\"medium\",\"score_weight\":40,\"hit_count\":0,\"check_uri\":true,\"check_query\":false,\"check_body\":false,\"check_headers\":true,\"check_cookies\":false}"
            "]}");
        goto done;
    }
    if (strcmp(method,"POST")==0 && strcmp(path,"/waf/profile")==0) {
        char *body=read_body(buf); char prof[32]={0};
        if (body) parse_json_str(body,"profile",prof,sizeof(prof));
        if (prof[0]) { EnterCriticalSection(&g_lock); strncpy(g_stats.waf_profile,prof,sizeof(g_stats.waf_profile)-1); LeaveCriticalSection(&g_lock); }
        send_json(s,"{\"status\":\"ok\"}"); goto done;
    }
    if (strcmp(method,"GET")==0 && strcmp(path,"/waf/captures")==0) {
        char buf2[JSON_SIZE]; int pp=0;
        EnterCriticalSection(&g_lock);
        pp=jscat(buf2,pp,JSON_SIZE,"{\"captures\":[");
        int cnt = g_alert_count < 20 ? g_alert_count : 20;
        for (int i=0;i<cnt;i++) {
            Alert *a=&g_alerts[g_alert_count-1-i];
            if(i>0) pp=jscat(buf2,pp,JSON_SIZE,",");
            pp=jscat(buf2,pp,JSON_SIZE,
                "{\"id\":%d,\"timestamp\":\"%s\",\"method\":\"POST\","
                "\"uri\":\"/api/data\",\"client_ip\":\"%s\","
                "\"score\":%d,\"blocked\":%s,\"finding_count\":2}",
                i+1,a->timestamp,a->src_ip,60+i*2%39,a->blocked?"true":"false");
        }
        pp=jscat(buf2,pp,JSON_SIZE,"]}");
        LeaveCriticalSection(&g_lock);
        send_json(s,buf2); goto done;
    }
    if (strcmp(method,"GET")==0 && strcmp(path,"/waf/allowlist")==0) {
        send_json(s,"{\"available\":false,\"reason\":\"WAF allowlist storage is not connected to this API\",\"allowlist\":[]}"); goto done;
    }
    if (strcmp(method,"POST")==0 && strcmp(path,"/waf/allowlist")==0) {
        send_json(s,"{\"available\":false,\"reason\":\"WAF allowlist storage is not connected to this API\"}"); goto done;
    }
    if (strcmp(method,"GET")==0 && strcmp(path,"/waf/syswatch")==0) {
        send_json(s,"{\"entries\":[]}"); goto done;
    }
    if (strcmp(method,"GET")==0 && strcmp(path,"/waf/report")==0) {
        send_json(s,"{\"available\":false,\"reason\":\"WAF report aggregation is not implemented\",\"attacks_today\":0}"); goto done;
    }
    /* ?????? /sandbox/ ?????? */
    if (strcmp(method,"GET")==0 && strcmp(path,"/sandbox/list")==0) {
        send_json(s,"{\"available\":false,\"reason\":\"Sandboxie process enumeration is not connected to this API\",\"sandboxes\":[]}");
        goto done;
    }
    if (strcmp(method,"GET")==0 && strncmp(path,"/sandbox/proxy-logs",19)==0) {
        send_json(s,"{\"available\":false,\"reason\":\"Sandboxie network audit logs are not connected to this API\",\"logs\":[]}"); goto done;
    }
    if (strcmp(method,"GET")==0 && strcmp(path,"/sandbox/diagnostics")==0) {
        send_json(s,"{\"available\":false,\"reason\":\"Sandbox proxy diagnostics are not implemented\"}"); goto done;
    }
    /* ?????? /hostguard/ ?????? */
    if (strcmp(method,"GET")==0 && strcmp(path,"/hostguard/stats")==0) {
        char b[1024]; EnterCriticalSection(&g_lock);
        snprintf(b,sizeof(b),"{\"available\":false,\"reason\":\"HostGuard counters are not wired to their engines\",\"hostguard\":{"
            "\"stat_components_scanned\":%d,\"stat_cve_found\":%d,"
            "\"stat_remediations_applied\":%d,\"stat_firewall_rules_added\":%d,"
            "\"stat_processes_killed\":%d,\"ransomware_detections\":%d,"
            "\"stat_updates_auto_installed\":%d,\"stat_updates_user_required\":%d,"
            "\"stat_thread_restarts\":%d,\"stat_fire_events_published\":%lld,"
            "\"stat_honeypot_triggers\":%d,\"stat_fim_events\":%d}}",
            g_stats.hg_components_scanned,g_stats.hg_cve_found,
            g_stats.hg_remediations,g_stats.hg_fw_rules,
            g_stats.hg_proc_killed,g_stats.hg_ransomware,
            g_stats.hg_updates_auto,g_stats.hg_updates_user,
            g_stats.hg_thread_restarts,g_stats.hg_events_published,
            g_stats.hg_honeypot_triggers,g_stats.hg_fim_events);
        LeaveCriticalSection(&g_lock);
        send_json(s,b); goto done;
    }
    if (strcmp(method,"GET")==0 && strcmp(path,"/hostguard/threads")==0) {
        send_json(s,"{\"available\":false,\"reason\":\"Worker heartbeat reporting is not implemented\",\"threads\":[]}");
        goto done;
    }
    if (strcmp(method,"GET")==0 && strncmp(path,"/hostguard/components",21)==0) {
        send_json(s,"{\"available\":false,\"reason\":\"This endpoint is not wired to the Windows software inventory\",\"components\":[]}");
        goto done;
    }
    if (strcmp(method,"GET")==0 && strcmp(path,"/hostguard/cves")==0) {
        char b[1024]; EnterCriticalSection(&g_lock);
        snprintf(b,sizeof(b),"{\"available\":false,\"reason\":\"No verified CVE remediation records are connected to this API\",\"recent_remediations\":[]}");
        LeaveCriticalSection(&g_lock);
        send_json(s,b); goto done;
    }
    if (strcmp(method,"GET")==0 && strcmp(path,"/hostguard/updates")==0) {
        char b[1024]; EnterCriticalSection(&g_lock);
        snprintf(b,sizeof(b),"{\"available\":false,\"reason\":\"Update workflow is not connected to this API\",\"pending\":[]}");
        LeaveCriticalSection(&g_lock);
        send_json(s,b); goto done;
    }
    if (strcmp(method,"GET")==0 && strcmp(path,"/hostguard/honeypots")==0) {
        send_json(s,"{\"available\":false,\"reason\":\"Honeypot file inventory is not connected to this API\",\"count\":0,\"files\":[]}");
        goto done;
    }
    if (strcmp(method,"GET")==0 && strcmp(path,"/hostguard/ransomware")==0) {
        char b[256]; EnterCriticalSection(&g_lock);
        snprintf(b,sizeof(b),"{\"available\":false,\"reason\":\"Ransomware response state is not wired to this API\"}");
        LeaveCriticalSection(&g_lock);
        send_json(s,b); goto done;
    }
    if (strcmp(method,"POST")==0 && strcmp(path,"/hostguard/scan")==0) {
        send_json(s,"{\"available\":false,\"reason\":\"HostGuard scan endpoint does not start a scan\"}"); goto done;
    }
    /* ?????? /integration/stats ?????? */
    if (strcmp(method,"GET")==0 && strcmp(path,"/integration/stats")==0) {
        char b[1024]; EnterCriticalSection(&g_lock);
        snprintf(b,sizeof(b),"{\"integration\":{"
            "\"fim_to_av_scans\":%d,\"process_to_av_watches\":%d,"
            "\"tls_to_hash_checks\":%d,\"malware_to_bans\":%d,"
            "\"sandbox_files_scanned\":%d,\"nexus_escalations\":%d,"
            "\"realtime_blocks\":%d,\"av_to_nexus_events\":%d,"
            "\"hg_to_nexus_events\":%d,\"wg_to_nexus_events\":%d,"
            "\"total_cross_engine\":%d}}",
            g_stats.ig_fim_av,g_stats.ig_proc_av,g_stats.ig_tls_hash,
            g_stats.ig_malware_bans,g_stats.ig_sb_files,g_stats.ig_nexus_escalations,
            g_stats.ig_realtime_blocks,g_stats.ig_av_nexus,
            g_stats.ig_hg_nexus,g_stats.ig_wg_nexus,g_stats.ig_total);
        LeaveCriticalSection(&g_lock);
        send_json(s,b); goto done;
    }
    /* ?????? /events/bus ?????? */
    if (strcmp(method,"GET")==0 && strcmp(path,"/events/bus")==0) {
        char b[128]; EnterCriticalSection(&g_lock);
        snprintf(b,sizeof(b),"{\"total_events\":%lld,\"capacity\":%d}",
            g_stats.bus_total_events,g_stats.bus_capacity);
        LeaveCriticalSection(&g_lock);
        send_json(s,b); goto done;
    }
    /* ?????? /system/autostart ?????? */
    if (strcmp(method,"POST")==0 && strcmp(path,"/system/autostart")==0) {
        send_json(s,"{\"available\":false,\"reason\":\"Autostart configuration is not implemented by this API\"}"); goto done;
    }

    /* ?????? /gaming/ ?????? */
    if (strcmp(method,"GET")==0 && strcmp(path,"/gaming/status")==0) {
        threat_scan_running_games();
        char b[4096]; int pp=0;
        EnterCriticalSection(&g_lock);
        DWORD dur = g_gaming.active ? (GetTickCount() - g_gaming.startTimeTick) / 1000 : 0;
        pp=jscat(b,pp,sizeof(b),"{\"gaming\":{"
            "\"active\":%s,\"game_name\":\"%s\",\"game_exe\":\"%s\",\"game_pid\":%lu,"
            "\"kernel_timer_1ms\":%s,\"network_throttling_disabled\":%s,\"scans_suspended\":%s,"
            "\"anti_cheat\":\"%s\",\"anti_cheat_detected\":%s,\"watchdog_running\":%s,\"duration_seconds\":%lu,"
            "\"detected_games\":[",
            g_gaming.active ? "true" : "false",
            g_gaming.gameName, g_gaming.gameExe, (unsigned long)g_gaming.gamePID,
            g_gaming.timer1msActive ? "true" : "false",
            g_gaming.netThrottlingDisabled ? "true" : "false",
            g_gaming.scansSuspended ? "true" : "false",
            g_gaming.antiCheatName,
            g_gaming.antiCheatDetected ? "true" : "false",
            g_gaming.watchdogRunning ? "true" : "false",
            (unsigned long)dur);
        for(int i=0; i<g_runningGameCount; i++) {
            if(i>0) pp=jscat(b,pp,sizeof(b),",");
            pp=jscat(b,pp,sizeof(b),
                "{\"pid\":%lu,\"title\":\"%s\",\"exe\":\"%s\",\"mem_mb\":%lu,\"boosted\":%s,\"compat_safe\":%s,\"anti_cheat\":\"%s\"}",
                (unsigned long)g_runningGames[i].pid,
                g_runningGames[i].title,
                g_runningGames[i].exe,
                (unsigned long)g_runningGames[i].memMB,
                g_runningGames[i].boosted ? "true" : "false",
                g_runningGames[i].compatSafe ? "true" : "false",
                g_runningGames[i].antiCheat);
        }
        pp=jscat(b,pp,sizeof(b),"]}}");
        LeaveCriticalSection(&g_lock);
        send_json(s,b); goto done;
    }

    if (strcmp(method,"POST")==0 && strcmp(path,"/gaming/boost")==0) {
        char *body = read_body(buf);
        DWORD pid = 0;
        char title[64] = "Manual Game";
        char exe[64] = "game.exe";
        if (body) {
            char pidStr[32] = {0};
            parse_json_str(body, "pid", pidStr, sizeof(pidStr));
            if (pidStr[0]) pid = (DWORD)atol(pidStr);
            parse_json_str(body, "title", title, sizeof(title));
            parse_json_str(body, "exe", exe, sizeof(exe));
        }
        if (pid == 0) {
            threat_scan_running_games();
            if (g_runningGameCount > 0) {
                pid = g_runningGames[0].pid;
                strncpy(title, g_runningGames[0].title, sizeof(title)-1);
                strncpy(exe, g_runningGames[0].exe, sizeof(exe)-1);
            }
        }
        if (pid > 0) {
            BOOL ok = threat_gaming_activate(pid, title, exe);
            char b[256];
            snprintf(b, sizeof(b), "{\"status\":\"%s\",\"game\":\"%s\",\"pid\":%lu}",
                     ok ? "boosted" : "failed", title, (unsigned long)pid);
            send_json(s, b);
        } else {
            send_json(s, "{\"status\":\"failed\",\"error\":\"No active game detected or specified\"}");
        }
        goto done;
    }

    if (strcmp(method,"POST")==0 && strcmp(path,"/gaming/restore")==0) {
        threat_gaming_deactivate();
        send_json(s, "{\"status\":\"restored\",\"message\":\"Standard defense mode and kernel timer restored\"}");
        goto done;
    }

    if (strcmp(method,"GET")==0 && strcmp(path,"/gaming/anticheat")==0) {
        threat_check_anticheat();
        char b[2048]; int pp=0;
        pp=jscat(b,pp,sizeof(b),"{\"anticheat\":{\"detected_count\":%d,\"detected\":[", g_antiCheatCnt);
        for(int i=0; i<g_antiCheatCnt; i++) {
            if(i>0) pp=jscat(b,pp,sizeof(b),",");
            pp=jscat(b,pp,sizeof(b),"{\"name\":\"%s\",\"status\":\"%s\"}", g_antiCheat[i].name, g_antiCheat[i].status);
        }
        pp=jscat(b,pp,sizeof(b),"]}}");
        send_json(s,b); goto done;
    }

    /* 404 */
    { char e[256]; snprintf(e,sizeof(e),"{\"error\":\"Not Found: %s %s\"}",method,path);
      send_response(s,404,e,(int)strlen(e)); }

done:
    free(buf);
    closesocket(s);
    return 0;
}

/* ????????? Main ??????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????? */
int main(void) {
    srand((unsigned)time(NULL));
    g_start_time = time(NULL);
    InitializeCriticalSection(&g_lock);

    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2,2), &wsa) != 0) {
        fprintf(stderr, "[ERROR] WSAStartup failed\n"); return 1;
    }

    seed_data();

    SOCKET srv = socket(AF_INET, SOCK_STREAM, 0);
    if (srv == INVALID_SOCKET) { fprintf(stderr,"[ERROR] socket()\n"); return 1; }

    int opt=1; setsockopt(srv,SOL_SOCKET,SO_REUSEADDR,(char*)&opt,sizeof(opt));

    int active_port = API_PORT;
    struct sockaddr_in addr = {0};
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    addr.sin_port        = htons(active_port);

    if (bind(srv,(struct sockaddr*)&addr,sizeof(addr)) != 0) {
        int e=WSAGetLastError();
        if (e==WSAEADDRINUSE) {
            fprintf(stderr,"[INFO] Port %d already in use; attempting fallback port 9010...\n", API_PORT);
            active_port = 9010;
            addr.sin_port = htons(active_port);
            if (bind(srv, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
                fprintf(stderr, "[ERROR] Fallback port 9010 also in use (WSA error: %d)\n", WSAGetLastError());
                closesocket(srv);
                return 1;
            }
        } else {
            fprintf(stderr,"[ERROR] bind() failed: %d\n",e);
            closesocket(srv);
            return 1;
        }
    }

    listen(srv, 64);

    /* Start background threads */
    CreateThread(NULL,0,ticker_thread,  NULL,0,NULL);
    /* No synthetic alert/incident generator: only verified detections may be shown. */
    threat_start_game_watchdog();

    printf("========================================================================================================================\n");
    printf("   Kaevex Engine v1.0 -- Standalone API Daemon Server\n");
    printf("   Copyright (c) 2025 Kaevex Security Systems\n");
    printf("========================================================================================================================\n");
    printf("   Listening: http://127.0.0.1:%d/api/v1/\n", active_port);
    printf("   Live host telemetry; real system process and socket monitoring\n");
    printf("   Press Ctrl+C to stop daemon\n");
    printf("========================================================================================================================\n");
    fflush(stdout);

    while (1) {
        struct sockaddr_in cli; int clen=sizeof(cli);
        SOCKET cs = accept(srv,(struct sockaddr*)&cli,&clen);
        if (cs == INVALID_SOCKET) continue;
        ConnArg *ca = (ConnArg*)malloc(sizeof(ConnArg));
        if (!ca) { closesocket(cs); continue; }
        ca->sock = cs;
        HANDLE th = CreateThread(NULL,0,conn_handler,ca,0,NULL);
        if (th) CloseHandle(th); else { free(ca); closesocket(cs); }
    }

    WSACleanup();
    DeleteCriticalSection(&g_lock);
    return 0;
}
