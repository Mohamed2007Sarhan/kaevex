/**
 * =======================================================================
 * Kaevex Security Platform ??? Standalone Engine API Server
 * Copyright (c) 2025 Kaevex Security Systems. All rights reserved.
 *
 * This is the compiled C backend for v1 testing.
 * Implements the full REST API on port 9009 using pure WinSock2.
 * No external dependencies ??? compiles with MinGW on Windows.
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
    char ts[32];
    now_str(ts, sizeof(ts));
    /* 5 seed alerts */
    for (int i = 0; i < 5; i++) {
        Alert *a       = &g_alerts[g_alert_count++];
        a->id          = g_alert_id++;
        strncpy(a->timestamp, ts,             sizeof(a->timestamp)-1);
        strncpy(a->engine,    RPICK(ENGINES), sizeof(a->engine)-1);
        strncpy(a->type,      RPICK(TYPES),   sizeof(a->type)-1);
        strncpy(a->severity,  RPICK(SEVERITIES), sizeof(a->severity)-1);
        rand_ip(a->src_ip);
        snprintf(a->dst_ip, sizeof(a->dst_ip), "192.168.1.%d", rand()%50+1);
        a->src_port    = rand()%60000+1024;
        a->dst_port    = 443;
        strncpy(a->proto, RPICK(PROTOS), sizeof(a->proto)-1);
        snprintf(a->payload, sizeof(a->payload), "Detected %s pattern (seed alert %d)", a->type, i+1);
        strncpy(a->attck, RPICK(TECHNIQUES), sizeof(a->attck)-1);
        a->blocked     = rand()%2;
        a->ip_banned   = a->blocked && rand()%2;
    }
    /* 3 seed incidents */
    for (int i = 0; i < 3; i++) {
        Incident *n    = &g_incidents[g_inc_count++];
        n->id          = g_inc_id++;
        strncpy(n->timestamp, ts, sizeof(n->timestamp)-1);
        snprintf(n->title, sizeof(n->title), "%s multi-stage attack", RPICK(FAMILIES));
        snprintf(n->summary, sizeof(n->summary), "Correlated %d events from %d engines", rand()%10+3, rand()%4+2);
        rand_ip(n->attacker_ip);
        snprintf(n->target_ip, sizeof(n->target_ip), "192.168.1.%d", rand()%15+2);
        n->kill_chain_stage = rand()%6+1;
        n->threat_score     = rand()%50+40;
        n->threat_level     = n->threat_score >= 80 ? 4 : 3;
        strncpy(n->threat_family, RPICK(FAMILIES),    sizeof(n->threat_family)-1);
        snprintf(n->techniques, sizeof(n->techniques), "%s,%s", RPICK(TECHNIQUES), RPICK(TECHNIQUES));
        n->auto_remediated  = 1;
    }
    /* 3 seed IOCs */
    char ip[24]; rand_ip(ip);
    strncpy(g_iocs[0].type, "IP",  16); strncpy(g_iocs[0].value, ip, 128);
    strncpy(g_iocs[0].threat_actor,"APT29",64); strncpy(g_iocs[0].campaign,"SolarWinds-2",64);
    strncpy(g_iocs[0].attck_tech,"T1078",16); g_iocs[0].confidence=95; g_iocs[0].hit_count=5;
    strncpy(g_iocs[1].type,"Domain",16); strncpy(g_iocs[1].value,"malicious-c2.net",128);
    strncpy(g_iocs[1].threat_actor,"LockBit",64); strncpy(g_iocs[1].campaign,"Ransomware-Q4",64);
    strncpy(g_iocs[1].attck_tech,"T1071",16); g_iocs[1].confidence=88; g_iocs[1].hit_count=2;
    strncpy(g_iocs[2].type,"Hash",16); strncpy(g_iocs[2].value,"a1b2c3d4e5f6deadbeef1234567890abcdef1234",128);
    strncpy(g_iocs[2].threat_actor,"Unknown",64); strncpy(g_iocs[2].campaign,"Generic-Dropper",64);
    strncpy(g_iocs[2].attck_tech,"T1055",16); g_iocs[2].confidence=72; g_iocs[2].hit_count=0;
    g_ioc_count = 3;

    /* Stats init */
    g_stats.av_hash_db_size      = 42381;
    g_stats.av_pattern_count     = 8743;
    g_stats.av_realtime_enabled  = 1;
    g_stats.av_auto_kill         = 1;
    g_stats.waf_rule_count       = 248;
    strncpy(g_stats.waf_profile, "Aggressive", sizeof(g_stats.waf_profile)-1);
    g_stats.waf_allowlist_count  = 3;
    g_stats.waf_rate_limit_rps   = 1000;
    g_stats.waf_block_threshold  = 60;
    g_stats.waf_ban_threshold    = 80;
    g_stats.sb_count             = 2;
    g_stats.sb_proxy_running     = 1;
    g_stats.sb_proxy_port        = 8080;
    g_stats.hg_components_scanned= rand()%600+200;
    g_stats.hg_cve_found         = rand()%10;
    g_stats.hg_updates_auto      = rand()%8;
    g_stats.hg_updates_user      = rand()%4;
    g_stats.ig_fim_av            = rand()%50;
    g_stats.ig_proc_av           = rand()%100;
    g_stats.ig_tls_hash          = rand()%200;
    g_stats.ig_malware_bans      = rand()%10;
    g_stats.ig_realtime_blocks   = rand()%20;
    g_stats.ig_total             = rand()%200;
    g_stats.bus_total_events     = rand()%9000+1000;
    g_stats.bus_capacity         = 65536;
    g_stats.nx_ioc_count         = g_ioc_count;
}

/* ????????? Background ticker thread ??????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????? */
static DWORD WINAPI ticker_thread(LPVOID unused) {
    (void)unused;
    while (1) {
        Sleep(3000);
        EnterCriticalSection(&g_lock);
        g_stats.av_files_scanned        += rand()%4;
        g_stats.av_processes_scanned    += rand()%3;
        g_stats.av_total_scans          += 1;
        g_stats.waf_requests_inspected  += rand()%6;
        if (rand()%5==0) { g_stats.waf_requests_blocked++; g_stats.waf_attacks_detected++; }
        if (rand()%10==0){ g_stats.waf_sqli++; g_stats.waf_attacks_detected++; }
        if (rand()%12==0)  g_stats.waf_xss++;
        g_stats.sb_bytes_sent           += rand()%10240;
        g_stats.sb_bytes_recv           += rand()%5120;
        g_stats.sb_connections          += rand()%2;
        g_stats.nx_events_processed     += rand()%4;
        g_stats.nx_incidents_created     = g_inc_count;
        g_stats.nx_active_incidents      = 0;
        for (int i=0; i<g_inc_count; i++) if (!g_incidents[i].auto_remediated) g_stats.nx_active_incidents++;
        g_stats.nx_ioc_count             = g_ioc_count;
        g_stats.waf_ips_banned           = g_ban_count;
        g_stats.bus_total_events        += rand()%10;
        g_stats.ig_total                += rand()%3;
        g_stats.hg_events_published     += rand()%5;
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

/* ????????? Route handlers ????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????? */
static void handle_status(SOCKET s) {
    char ts[32]; now_str(ts, sizeof(ts));
    char buf[JSON_SIZE];
    int  p = 0;
    p = jscat(buf,p,JSON_SIZE, "{"
        "\"platform\":\"Kaevex Security Platform\","
        "\"version\":\"1.0.0-v1\","
        "\"api_version\":\"v1\","
        "\"uptime_seconds\":%lld,"
        "\"total_bus_events\":%lld,"
        "\"api_requests\":%lld,"
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
        uptime_secs(), g_stats.bus_total_events, g_stats.api_requests);
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
        send_json(s,"{\"allowlist\":[\"127.0.0.1\",\"::1\",\"192.168.1.1\"]}"); goto done;
    }
    if (strcmp(method,"POST")==0 && strcmp(path,"/waf/allowlist")==0) {
        send_json(s,"{\"status\":\"added\"}"); goto done;
    }
    if (strcmp(method,"GET")==0 && strcmp(path,"/waf/syswatch")==0) {
        send_json(s,"{\"entries\":[]}"); goto done;
    }
    if (strcmp(method,"GET")==0 && strcmp(path,"/waf/report")==0) {
        send_json(s,"{\"attacks_today\":12,\"top_type\":\"SQLi\",\"top_ip\":\"203.0.113.1\"}"); goto done;
    }
    /* ?????? /sandbox/ ?????? */
    if (strcmp(method,"GET")==0 && strcmp(path,"/sandbox/list")==0) {
        send_json(s,"{\"sandboxes\":["
            "{\"name\":\"Sandbox-Alpha\",\"state\":\"running\",\"pid\":4321,"
            "\"exe\":\"C:\\\\Windows\\\\System32\\\\cmd.exe\","
            "\"start_time\":\"2025-01-01T00:00:00Z\","
            "\"firewall_active\":true,\"low_integrity\":true,"
            "\"bytes_sent\":51200,\"bytes_recv\":102400,\"connections\":3},"
            "{\"name\":\"Sandbox-Beta\",\"state\":\"running\",\"pid\":5678,"
            "\"exe\":\"C:\\\\Windows\\\\System32\\\\notepad.exe\","
            "\"start_time\":\"2025-01-01T00:00:00Z\","
            "\"firewall_active\":true,\"low_integrity\":true,"
            "\"bytes_sent\":20480,\"bytes_recv\":40960,\"connections\":1}"
            "]}");
        goto done;
    }
    if (strcmp(method,"GET")==0 && strncmp(path,"/sandbox/proxy-logs",19)==0) {
        char b2[JSON_SIZE]; int pp=0;
        EnterCriticalSection(&g_lock);
        pp=jscat(b2,pp,JSON_SIZE,"{\"logs\":[");
        int cnt=g_alert_count<10?g_alert_count:10;
        for(int i=0;i<cnt;i++){
            Alert*a=&g_alerts[i];
            if(i>0) pp=jscat(b2,pp,JSON_SIZE,",");
            pp=jscat(b2,pp,JSON_SIZE,
                "{\"timestamp\":\"%s\",\"method\":\"CONNECT\","
                "\"host\":\"cdn.trusted.com\",\"port\":443,"
                "\"sandbox\":\"Sandbox-Alpha\",\"was_blocked\":%s}",
                a->timestamp,a->blocked?"true":"false");
        }
        pp=jscat(b2,pp,JSON_SIZE,"]}");
        LeaveCriticalSection(&g_lock);
        send_json(s,b2); goto done;
    }
    if (strcmp(method,"GET")==0 && strcmp(path,"/sandbox/diagnostics")==0) {
        send_json(s,"{\"status\":\"ok\",\"proxy_reachable\":true}"); goto done;
    }
    /* ?????? /hostguard/ ?????? */
    if (strcmp(method,"GET")==0 && strcmp(path,"/hostguard/stats")==0) {
        char b[1024]; EnterCriticalSection(&g_lock);
        snprintf(b,sizeof(b),"{\"hostguard\":{"
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
        send_json(s,"{\"threads\":["
            "{\"id\":1,\"name\":\"HostGuard-Scanner\",\"alive\":true,\"last_heartbeat_age_s\":2,\"restart_count\":0},"
            "{\"id\":2,\"name\":\"CVE-Checker\",\"alive\":true,\"last_heartbeat_age_s\":3,\"restart_count\":0},"
            "{\"id\":3,\"name\":\"UpdateManager\",\"alive\":true,\"last_heartbeat_age_s\":1,\"restart_count\":0},"
            "{\"id\":4,\"name\":\"Honeypot-Monitor\",\"alive\":true,\"last_heartbeat_age_s\":5,\"restart_count\":0},"
            "{\"id\":5,\"name\":\"RansomwareShield\",\"alive\":true,\"last_heartbeat_age_s\":2,\"restart_count\":0},"
            "{\"id\":6,\"name\":\"FIM-Watcher\",\"alive\":true,\"last_heartbeat_age_s\":4,\"restart_count\":0},"
            "{\"id\":7,\"name\":\"Heartbeat-Monitor\",\"alive\":true,\"last_heartbeat_age_s\":1,\"restart_count\":0}"
            "]}");
        goto done;
    }
    if (strcmp(method,"GET")==0 && strncmp(path,"/hostguard/components",21)==0) {
        send_json(s,"{\"components\":["
            "{\"db_id\":1,\"name\":\"OpenSSL\",\"version\":\"3.0.2\",\"type\":\"Library\",\"os_info\":\"Windows 11\",\"first_seen\":\"2025-01-01T00:00:00Z\",\"last_seen\":\"2025-01-01T00:00:00Z\",\"needs_cve_check\":true,\"needs_update_check\":true},"
            "{\"db_id\":2,\"name\":\"Node.js\",\"version\":\"20.19.0\",\"type\":\"Runtime\",\"os_info\":\"Windows 11\",\"first_seen\":\"2025-01-01T00:00:00Z\",\"last_seen\":\"2025-01-01T00:00:00Z\",\"needs_cve_check\":false,\"needs_update_check\":false},"
            "{\"db_id\":3,\"name\":\"Microsoft Edge\",\"version\":\"121.0.0\",\"type\":\"Browser\",\"os_info\":\"Windows 11\",\"first_seen\":\"2025-01-01T00:00:00Z\",\"last_seen\":\"2025-01-01T00:00:00Z\",\"needs_cve_check\":false,\"needs_update_check\":true},"
            "{\"db_id\":4,\"name\":\"Python 3\",\"version\":\"3.11.2\",\"type\":\"Runtime\",\"os_info\":\"Windows 11\",\"first_seen\":\"2025-01-01T00:00:00Z\",\"last_seen\":\"2025-01-01T00:00:00Z\",\"needs_cve_check\":true,\"needs_update_check\":false},"
            "{\"db_id\":5,\"name\":\"curl\",\"version\":\"8.1.2\",\"type\":\"Tool\",\"os_info\":\"Windows 11\",\"first_seen\":\"2025-01-01T00:00:00Z\",\"last_seen\":\"2025-01-01T00:00:00Z\",\"needs_cve_check\":false,\"needs_update_check\":false}"
            "]}");
        goto done;
    }
    if (strcmp(method,"GET")==0 && strcmp(path,"/hostguard/cves")==0) {
        char b[1024]; EnterCriticalSection(&g_lock);
        snprintf(b,sizeof(b),
            "{\"total_cve_found\":%d,\"total_checks_done\":%d,"
            "\"remediations_applied\":%d,\"recent_remediations\":[%s]}",
            g_stats.hg_cve_found, g_stats.hg_components_scanned,
            g_stats.hg_remediations,
            g_stats.hg_cve_found>0 ?
            "{\"db_id\":1,\"component\":\"OpenSSL\",\"risk_level\":\"high\","
            "\"cve_list\":\"CVE-2023-0215\",\"status\":\"remediated\","
            "\"executed_at\":\"2025-01-01T00:00:00Z\"}" : "");
        LeaveCriticalSection(&g_lock);
        send_json(s,b); goto done;
    }
    if (strcmp(method,"GET")==0 && strcmp(path,"/hostguard/updates")==0) {
        char b[1024]; EnterCriticalSection(&g_lock);
        snprintf(b,sizeof(b),"{\"auto_installed\":%d,\"user_required\":%d,\"pending\":[%s]}",
            g_stats.hg_updates_auto, g_stats.hg_updates_user,
            g_stats.hg_updates_user>0 ?
            "{\"component\":\"OpenSSL\",\"type\":\"security\","
            "\"current_version\":\"3.0.2\",\"latest_version\":\"3.2.1\","
            "\"update_safe\":true,\"status\":\"pending_approval\"}" : "");
        LeaveCriticalSection(&g_lock);
        send_json(s,b); goto done;
    }
    if (strcmp(method,"GET")==0 && strcmp(path,"/hostguard/honeypots")==0) {
        send_json(s,"{\"count\":3,\"ransomware_lockdown\":false,\"files\":["
            "{\"path\":\"C:\\\\Decoy\\\\salary.xlsx\",\"size\":24576,\"active\":true,"
            "\"created\":\"2025-01-01T00:00:00Z\",\"sha256\":\"deadbeefcafe0102030405060708090a0b0c0d0e0f\"},"
            "{\"path\":\"C:\\\\Decoy\\\\passwords.txt\",\"size\":512,\"active\":true,"
            "\"created\":\"2025-01-01T00:00:00Z\",\"sha256\":\"0102030405060708090a0b0c0d0e0f101112131415\"}"
            "]}");
        goto done;
    }
    if (strcmp(method,"GET")==0 && strcmp(path,"/hostguard/ransomware")==0) {
        char b[256]; EnterCriticalSection(&g_lock);
        snprintf(b,sizeof(b),"{\"total_detections\":%d,\"processes_killed\":%d,\"currently_locked_down\":false,\"honeypot_count\":3}",
            g_stats.hg_ransomware,g_stats.hg_proc_killed);
        LeaveCriticalSection(&g_lock);
        send_json(s,b); goto done;
    }
    if (strcmp(method,"POST")==0 && strcmp(path,"/hostguard/scan")==0) {
        send_json(s,"{\"status\":\"scan_initiated\"}"); goto done;
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
        send_json(s,"{\"status\":\"ok\"}"); goto done;
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

    struct sockaddr_in addr = {0};
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    addr.sin_port        = htons(API_PORT);

    if (bind(srv,(struct sockaddr*)&addr,sizeof(addr)) != 0) {
        int e=WSAGetLastError();
        if (e==WSAEADDRINUSE)
            fprintf(stderr,"[INFO] Port %d already in use (real backend may be running)\n",API_PORT);
        else
            fprintf(stderr,"[ERROR] bind() failed: %d\n",e);
        return 0;
    }

    listen(srv, 64);

    /* Start background threads */
    CreateThread(NULL,0,ticker_thread,  NULL,0,NULL);
    CreateThread(NULL,0,alert_thread,   NULL,0,NULL);
    CreateThread(NULL,0,incident_thread,NULL,0,NULL);

    printf("????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????\n");
    printf("???  Kaevex Engine v1.0 ??? API Server              ???\n");
    printf("???  Copyright (c) 2025 Kaevex Security Systems   ???\n");
    printf("????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????\n");
    printf("???  Listening: http://127.0.0.1:%d/api/v1/        ???\n", API_PORT);
    printf("???  8 engine endpoints simulated                     ???\n");
    printf("???  New alert every 8s | Incident every 30s          ???\n");
    printf("???  Press Ctrl+C to stop                             ???\n");
    printf("????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????\n");
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
