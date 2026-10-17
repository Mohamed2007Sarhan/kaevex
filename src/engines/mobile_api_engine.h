/*===========================================================================
 * Kaevex Mobile & Multi-Server REST API Engine — mobile_api_engine.h
 * High-performance, multi-threaded, authenticated REST API for Android Mobile
 * and Centralized Multi-Server Cluster Management.
 * 
 * Features:
 *  - 0.0.0.0 (INADDR_ANY) binding for Wi-Fi, LAN, and VPN mobile connections.
 *  - PIN / QR Pairing system with cryptographic Bearer Token generation.
 *  - Rate limiting & anti-brute-force IP shielding.
 *  - Unified Mobile Dashboard API: Single-call system health & telemetry.
 *  - Complete Remote Controls: Antivirus, Quarantine, Whitelist, Firewall Lockdown,
 *    Process Termination, DNS Sinkhole, Ransomware VSS Snapshots, AI SOC Chat.
 *  - Multi-Server Cluster Registry & Broadcast Engine (Lockdown all, Scan all).
 *  - Standard CORS headers for mobile WebView / Flutter / React Native / Native.
 *===========================================================================*/

#pragma once
#ifndef MOBILE_API_ENGINE_H
#define MOBILE_API_ENGINE_H

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <psapi.h>
#include <wincrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "psapi.lib")

#include "ai_together_engine.h"
#include "fw_pro_engine.h"
#include "link_core.h"
#include "waf_core.h"
#include "boot_rootkit_engine.h"

#define MOBILE_API_DEFAULT_PORT 9009
#define MOBILE_API_MAX_CLIENTS  64
#define MOBILE_API_MAX_SERVERS  32
#define MOBILE_API_MAX_TOKENS   16
#define MOBILE_API_BUF_SIZE     (64 * 1024)
#define MOBILE_API_JSON_SIZE    (48 * 1024)

/* ---- Security & Token Structures ----------------------------------------- */
typedef struct {
    char token[64];
    char deviceId[64];
    char deviceName[64];
    char clientIp[48];
    time_t createdAt;
    time_t lastSeen;
    int  isAdmin;
    int  isActive;
} MobileToken;

typedef struct {
    char ip[48];
    int  failedAttempts;
    time_t blockedUntil;
} FailedAttemptTracker;

/* ---- Multi-Server Cluster Structures ------------------------------------- */
typedef struct {
    int  id;
    char name[64];
    char ip[48];
    int  port;
    char token[64];
    char role[32];       /* "Master", "Web-Server", "DB-Server", "Endpoint" */
    char status[32];     /* "ONLINE", "OFFLINE", "ALERT", "LOCKED" */
    int  pingMs;
    int  threatCount;
    int  cpuLoad;
    int  isLocked;
    time_t lastChecked;
} ManagedServer;

/* ---- Global State for Mobile Engine --------------------------------------- */
static CRITICAL_SECTION g_mobileCS;
static BOOL             g_mobileCSInit = FALSE;

static BOOL             g_mobileRunning = FALSE;
static SOCKET           g_mobileListenSock = INVALID_SOCKET;
static int              g_mobilePort = MOBILE_API_DEFAULT_PORT;
static char             g_pairingPin[16] = "";       /* generated at start from the OS CSPRNG; empty = pairing disabled */
/* 6-digit PIN from CryptGenRandom (rejection sampling: no modulo bias). Never falls back to rand(). */
static void mobile_rotate_pin(void) {
    HCRYPTPROV prov = 0; unsigned v = 0; int got = 0;
    if (CryptAcquireContextA(&prov, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        for (int i = 0; i < 64 && !got; i++) {
            if (!CryptGenRandom(prov, sizeof v, (BYTE *)&v)) break;
            if (v < 4293900000u) got = 1;            /* 900000 * 4771: rejection sampling, no modulo bias */
        }
        CryptReleaseContext(prov, 0);
    }
    if (got) snprintf(g_pairingPin, sizeof g_pairingPin, "%06u", 100000u + (v % 900000u));
    else     g_pairingPin[0] = 0;                    /* no CSPRNG: pairing disabled rather than a guessable PIN */
}

static MobileToken      g_mobileTokens[MOBILE_API_MAX_TOKENS];
static int              g_mobileTokenCount = 0;

static FailedAttemptTracker g_failedIps[32];
static int              g_failedIpCount = 0;

static ManagedServer    g_clusterServers[MOBILE_API_MAX_SERVERS];
static int              g_clusterServerCount = 0;

/* Internal telemetry pointers (bound dynamically by GUI or Engine) */
static int                *g_pMobileAvThreats = NULL;
static long long          *g_pMobileWafBlk = NULL;
static long long          *g_pMobileWafInsp = NULL;
static unsigned long long *g_pMobileRealInPkts = NULL;
static unsigned long long *g_pMobileRealOutPkts = NULL;
static unsigned long long *g_pMobileRealDrops = NULL;
static int                *g_pMobileNetConnCnt = NULL;
static BOOL               *g_pMobileLockdown = NULL;

/* Platform Callbacks for 100% Real Live SOC Data */
typedef int  (*MobileGetEnginesJsonFn)(char *buf, size_t maxBuf);
typedef int  (*MobileGetAlertsJsonFn)(char *buf, size_t maxBuf, int maxCount);
typedef int  (*MobileGetThreatsJsonFn)(char *buf, size_t maxBuf, int *outTotal, int *outSafe, int *outQuar);
typedef BOOL (*MobileThreatActionFn)(const char *filePath, int action);

typedef void (*MobileAddAlertFn)(const char *src, const char *sev, const char *msg);
typedef BOOL (*MobileScanFn)(void);                 /* starts a REAL antivirus scan; FALSE if it could not start */
static MobileScanFn g_pMobileScan = NULL;
static void mobile_api_bind_scan(MobileScanFn fn) { g_pMobileScan = fn; }

/* implemented in cluster_link_engine.h (included at the end of this file) */
static BOOL link_connect_raw(const char *host, int port, const char *pin, int noBack, char *msg, size_t msgN);
static void link_spawn_backlink(const char *clientIp, int port, const char *pin);
static int  link_broadcast(const char *action, char *detail, size_t dn);
static int  link_nodes_json(char *out, size_t n);

static MobileGetEnginesJsonFn  g_pMobileGetEnginesJson  = NULL;
static MobileGetAlertsJsonFn   g_pMobileGetAlertsJson   = NULL;
static MobileGetThreatsJsonFn  g_pMobileGetThreatsJson  = NULL;
static MobileThreatActionFn    g_pMobileThreatAction    = NULL;
static MobileAddAlertFn        g_pMobileAddAlert        = NULL;
static int                    *g_pMobileSparkline       = NULL;

static void mobile_api_bind_telemetry(int *avThr, long long *wafBlk, long long *wafInsp,
                                      unsigned long long *inPkts, unsigned long long *outPkts,
                                      unsigned long long *drops, int *netConns, BOOL *lockdown) {
    g_pMobileAvThreats = avThr;
    g_pMobileWafBlk = wafBlk;
    g_pMobileWafInsp = wafInsp;
    g_pMobileRealInPkts = inPkts;
    g_pMobileRealOutPkts = outPkts;
    g_pMobileRealDrops = drops;
    g_pMobileNetConnCnt = netConns;
    g_pMobileLockdown = lockdown;
}

static void mobile_api_bind_platform_callbacks(
    MobileGetEnginesJsonFn  fnEngines,
    MobileGetAlertsJsonFn   fnAlerts,
    MobileGetThreatsJsonFn  fnThreats,
    MobileThreatActionFn    fnThreatAction,
    int                    *sparkline7)
{
    g_pMobileGetEnginesJson = fnEngines;
    g_pMobileGetAlertsJson  = fnAlerts;
    g_pMobileGetThreatsJson = fnThreats;
    g_pMobileThreatAction   = fnThreatAction;
    g_pMobileSparkline      = sparkline7;
}

static void mobile_api_bind_alert_callback(MobileAddAlertFn fnAddAlert) {
    g_pMobileAddAlert = fnAddAlert;
}

/* Helper: Real-time Windows Kernel CPU Measurement */
static int mobile_get_real_cpu_percent(void) {
    static ULARGE_INTEGER lastIdle = {0}, lastSys = {0};
    FILETIME idleT, kernT, userT;
    if (!GetSystemTimes(&idleT, &kernT, &userT)) return 5;
    ULARGE_INTEGER idle, kern, user;
    idle.LowPart = idleT.dwLowDateTime; idle.HighPart = idleT.dwHighDateTime;
    kern.LowPart = kernT.dwLowDateTime; kern.HighPart = kernT.dwHighDateTime;
    user.LowPart = userT.dwLowDateTime; user.HighPart = userT.dwHighDateTime;
    ULARGE_INTEGER sys;
    sys.QuadPart = kern.QuadPart + user.QuadPart;
    if (lastSys.QuadPart == 0) {
        lastIdle = idle;
        lastSys  = sys;
        return 8;
    }
    ULONGLONG idleDiff = idle.QuadPart - lastIdle.QuadPart;
    ULONGLONG sysDiff  = sys.QuadPart - lastSys.QuadPart;
    lastIdle = idle;
    lastSys  = sys;
    if (sysDiff == 0) return 5;
    int pct = (int)(100 - (idleDiff * 100 / sysDiff));
    if (pct < 0) pct = 0;
    if (pct > 100) pct = 100;
    return pct;
}

/* ---- Helper: Secure Random String Generator ------------------------------- */
static void mobile_generate_token(char *out, int len) {
    static const char chars[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    HCRYPTPROV hProv = 0;
    if (CryptAcquireContextA(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        BYTE randBytes[64];
        if (CryptGenRandom(hProv, len < 64 ? len : 64, randBytes)) {
            for (int i = 0; i < len - 1; i++) {
                out[i] = chars[randBytes[i] % (sizeof(chars) - 1)];
            }
            out[len - 1] = '\0';
            CryptReleaseContext(hProv, 0);
            return;
        }
        CryptReleaseContext(hProv, 0);
    }
    /* No CSPRNG: return an EMPTY token (callers must refuse) - never a predictable one */
    out[0] = '\0';
}

/* ---- Security: Anti-Brute-Force & Rate Limiting -------------------------- */
static BOOL mobile_is_ip_blocked(const char *ip) {
    time_t now = time(NULL);
    for (int i = 0; i < g_failedIpCount; i++) {
        if (strcmp(g_failedIps[i].ip, ip) == 0) {
            if (g_failedIps[i].blockedUntil > now) return TRUE;
            /* Block expired */
            g_failedIps[i].failedAttempts = 0;
            return FALSE;
        }
    }
    return FALSE;
}

static void mobile_record_failed_attempt(const char *ip) {
    time_t now = time(NULL);
    for (int i = 0; i < g_failedIpCount; i++) {
        if (strcmp(g_failedIps[i].ip, ip) == 0) {
            g_failedIps[i].failedAttempts++;
            if (g_failedIps[i].failedAttempts >= 5) {
                g_failedIps[i].blockedUntil = now + 600; /* Block for 10 minutes */
            }
            return;
        }
    }
    if (g_failedIpCount < 32) {
        strncpy(g_failedIps[g_failedIpCount].ip, ip, 47);
        g_failedIps[g_failedIpCount].failedAttempts = 1;
        g_failedIps[g_failedIpCount].blockedUntil = 0;
        g_failedIpCount++;
    }
}

static void mobile_record_successful_attempt(const char *ip) {
    for (int i = 0; i < g_failedIpCount; i++) {
        if (strcmp(g_failedIps[i].ip, ip) == 0) {
            g_failedIps[i].failedAttempts = 0;
            g_failedIps[i].blockedUntil = 0;
            return;
        }
    }
}

/* ===========================================================================
 * PROACTIVE INLINE DEFENSE SHIELD (WAF / Anti-SQLi / Anti-XSS / Path-Traversal)
 * Protects local web servers, databases, and mobile API endpoints against attacks.
 * =========================================================================== */
typedef struct {
    BOOL isMalicious;
    const char *threatType;
    const char *cwe;
    const char *mitre;
    char detail[256];
} MobileWafVerdict;

static MobileWafVerdict mobile_waf_inspect_payload(const char *path, const char *body) {
    MobileWafVerdict v;
    memset(&v, 0, sizeof(v));
    v.isMalicious = FALSE;
    v.threatType = "Clean";
    v.cwe = "N/A";
    v.mitre = "N/A";
    v.detail[0] = '\0';
    if (!path && !body) return v;

    char combined[8192] = {0};
    snprintf(combined, sizeof(combined), "%s %s", path ? path : "", body ? body : "");

    char lo[8192] = {0};
    int n = (int)strlen(combined);
    if (n > 8191) n = 8191;
    for (int i = 0; i < n; i++) lo[i] = (char)tolower((unsigned char)combined[i]);

    /* 1. SQL Injection (SQLi) Check */
    static const char *sqliPatterns[] = {
        "' or ", "\" or ", "' and ", "\" and ", " or 1=1", " or '1'='1", " or \"1\"=\"1",
        "union select", "union all select", "drop table", "insert into", "delete from",
        "xp_cmdshell", "waitfor delay", "sleep(", "benchmark(", "; drop", "; delete",
        "admin'--", "'--", "1'='1", "declare @", "cast(", "convert(", "exec(", NULL
    };
    for (int i = 0; sqliPatterns[i]; i++) {
        if (strstr(lo, sqliPatterns[i])) {
            v.isMalicious = TRUE;
            v.threatType = "SQL Injection (SQLi)";
            v.cwe = "CWE-89";
            v.mitre = "T1190";
            snprintf(v.detail, sizeof(v.detail), "Proactive WAF detected SQL manipulation: '%s'", sqliPatterns[i]);
            return v;
        }
    }

    /* 2. Cross-Site Scripting (XSS) Check */
    static const char *xssPatterns[] = {
        "<script", "</script>", "javascript:", "onerror=", "onload=", "onclick=",
        "onmouseover=", "document.cookie", "document.location", "eval(", "alert(",
        "fromcharcode", "innerhtml", "vbscript:", "<iframe", "<img src=", NULL
    };
    for (int i = 0; xssPatterns[i]; i++) {
        if (strstr(lo, xssPatterns[i])) {
            v.isMalicious = TRUE;
            v.threatType = "Cross-Site Scripting (XSS)";
            v.cwe = "CWE-79";
            v.mitre = "T1059.007";
            snprintf(v.detail, sizeof(v.detail), "Proactive WAF detected script injection: '%s'", xssPatterns[i]);
            return v;
        }
    }

    /* 3. Directory / Path Traversal Check */
    static const char *travPatterns[] = {
        "../", "..\\", "/etc/passwd", "/etc/shadow", "win.ini", "boot.ini",
        "%2e%2e%2f", "%2e%2e/", "..%2f", NULL
    };
    for (int i = 0; travPatterns[i]; i++) {
        if (strstr(lo, travPatterns[i])) {
            v.isMalicious = TRUE;
            v.threatType = "Directory Traversal (LFI)";
            v.cwe = "CWE-22";
            v.mitre = "T1083";
            snprintf(v.detail, sizeof(v.detail), "Proactive WAF detected traversal pattern: '%s'", travPatterns[i]);
            return v;
        }
    }

    /* 4. Remote Command Execution / OS Injection */
    static const char *cmdPatterns[] = {
        "; rm -rf", "| calc", "| nc ", "; shutdown", "; netsh", "; net user",
        "powershell -enc", "cmd.exe /c", "/bin/sh", "/bin/bash", NULL
    };
    for (int i = 0; cmdPatterns[i]; i++) {
        if (strstr(lo, cmdPatterns[i])) {
            v.isMalicious = TRUE;
            v.threatType = "Command Injection (RCE)";
            v.cwe = "CWE-78";
            v.mitre = "T1059";
            snprintf(v.detail, sizeof(v.detail), "Proactive WAF detected command injection: '%s'", cmdPatterns[i]);
            return v;
        }
    }

    return v;
}

/* ---- Security: Validate Bearer Token ------------------------------------- */
static BOOL mobile_validate_token(const char *req, const char *clientIp, int *outIsAdmin) {
    if (!req) return FALSE;
    char token[128] = {0};

    /* Check Authorization: Bearer <token> */
    const char *auth = strstr(req, "Authorization: Bearer ");
    if (auth) {
        auth += 22;
        int i = 0;
        while (*auth && *auth != '\r' && *auth != '\n' && *auth != ' ' && i < 63) {
            token[i++] = *auth++;
        }
        token[i] = '\0';
    } else {
        /* Check X-Kaevex-Token: <token> */
        const char *xk = strstr(req, "X-Kaevex-Token: ");
        if (xk) {
            xk += 16;
            int i = 0;
            while (*xk && *xk != '\r' && *xk != '\n' && *xk != ' ' && i < 63) {
                token[i++] = *xk++;
            }
            token[i] = '\0';
        }
    }

    if (!token[0]) return FALSE;

    EnterCriticalSection(&g_mobileCS);
    for (int i = 0; i < g_mobileTokenCount; i++) {
        if (g_mobileTokens[i].isActive && strcmp(g_mobileTokens[i].token, token) == 0) {
            g_mobileTokens[i].lastSeen = time(NULL);
            if (outIsAdmin) *outIsAdmin = g_mobileTokens[i].isAdmin;
            LeaveCriticalSection(&g_mobileCS);
            return TRUE;
        }
    }
    LeaveCriticalSection(&g_mobileCS);
    return FALSE;
}

/* ---- HTTP Response Helpers ----------------------------------------------- */
static void mobile_send_response(SOCKET s, int code, const char *contentType, const char *body) {
    char header[1024];
    int bodyLen = body ? (int)strlen(body) : 0;
    const char *statusText = (code == 200) ? "OK" :
                            (code == 201) ? "Created" :
                            (code == 400) ? "Bad Request" :
                            (code == 401) ? "Unauthorized" :
                            (code == 403) ? "Forbidden" :
                            (code == 404) ? "Not Found" :
                            (code == 429) ? "Too Many Requests" : "Internal Server Error";

    int hLen = snprintf(header, sizeof(header),
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %d\r\n"
        "Connection: close\r\n\r\n",
        code, statusText,
        contentType ? contentType : "application/json",
        bodyLen);

    send(s, header, hLen, 0);
    if (bodyLen > 0) {
        send(s, body, bodyLen, 0);
    }
    shutdown(s, SD_SEND);
}

static void mobile_send_json(SOCKET s, int code, const char *jsonBody) {
    mobile_send_response(s, code, "application/json; charset=utf-8", jsonBody);
}

/* ---- JSON String Parser Helper ------------------------------------------- */
static BOOL mobile_get_json_string(const char *json, const char *key, char *outVal, int maxLen) {
    char pattern[128];
    snprintf(pattern, sizeof(pattern), "\"%s\"", key);
    const char *p = strstr(json, pattern);
    if (!p) return FALSE;
    p += strlen(pattern);
    while (*p && (*p == ' ' || *p == ':' || *p == '\t')) p++;
    if (*p != '\"') return FALSE;
    p++;
    int i = 0;
    while (*p && *p != '\"' && i < maxLen - 1) {
        if (*p == '\\' && *(p+1)) p++;
        outVal[i++] = *p++;
    }
    outVal[i] = '\0';
    return TRUE;
}

static BOOL mobile_get_json_int(const char *json, const char *key, int *outVal) {
    char pattern[128];
    snprintf(pattern, sizeof(pattern), "\"%s\"", key);
    const char *p = strstr(json, pattern);
    if (!p) return FALSE;
    p += strlen(pattern);
    while (*p && (*p == ' ' || *p == ':' || *p == '\t')) p++;
    if (*p == '\"') p++;
    *outVal = atoi(p);
    return TRUE;
}

/* ===========================================================================
 * ENDPOINT HANDLERS
 * =========================================================================== */

/* 1. Auth & Pairing Endpoint */
static void handle_mobile_auth_pair(SOCKET s, const char *body, const char *clientIp) {
    if (mobile_is_ip_blocked(clientIp)) {
        mobile_send_json(s, 429, "{\"error\":\"Too many failed attempts. IP temporarily blocked for 10 minutes.\"}");
        return;
    }

    char pin[32] = {0};
    char devId[64] = "unknown-android";
    char devName[64] = "Android Device";
    mobile_get_json_string(body, "pin", pin, sizeof(pin));
    mobile_get_json_string(body, "device_id", devId, sizeof(devId));
    mobile_get_json_string(body, "device_name", devName, sizeof(devName));

    EnterCriticalSection(&g_mobileCS);
    if (!g_pairingPin[0] || strlen(pin) != 6 || strcmp(pin, g_pairingPin) != 0) {
        LeaveCriticalSection(&g_mobileCS);
        mobile_record_failed_attempt(clientIp);
        mobile_send_json(s, 401, "{\"error\":\"Invalid Pairing PIN. Check server console or GUI Settings.\"}");
        return;
    }

    mobile_record_successful_attempt(clientIp);
    mobile_rotate_pin();                                 /* a PIN is single-use */

    /* Generate Session Token */
    char newToken[64] = {0};
    mobile_generate_token(newToken, 48);
    if (!newToken[0]) {
        LeaveCriticalSection(&g_mobileCS);
        mobile_send_json(s, 500, "{\"error\":\"Secure random generator unavailable; pairing refused.\"}");
        return;
    }

    /* Store or update token */
    int idx = -1;
    for (int i = 0; i < g_mobileTokenCount; i++) {
        if (strcmp(g_mobileTokens[i].deviceId, devId) == 0) {
            idx = i; break;
        }
    }
    if (idx == -1) {
        if (g_mobileTokenCount < MOBILE_API_MAX_TOKENS) {
            idx = g_mobileTokenCount++;
        } else {
            idx = 0; /* rotate oldest */
        }
    }

    strncpy(g_mobileTokens[idx].token, newToken, 63);
    strncpy(g_mobileTokens[idx].deviceId, devId, 63);
    strncpy(g_mobileTokens[idx].deviceName, devName, 63);
    strncpy(g_mobileTokens[idx].clientIp, clientIp, 47);
    g_mobileTokens[idx].createdAt = time(NULL);
    g_mobileTokens[idx].lastSeen = time(NULL);
    g_mobileTokens[idx].isAdmin = 1;
    g_mobileTokens[idx].isActive = 1;

    char resp[1024];
    snprintf(resp, sizeof(resp),
        "{\"status\":\"success\","
        "\"message\":\"Device paired successfully with Kaevex SOC\","
        "\"token\":\"%s\","
        "\"expires_in\":2592000,"
        "\"server\":{\"name\":\"Kaevex Host Engine\",\"version\":\"1.0.0-PROD\",\"port\":%d}}",
        newToken, g_mobilePort);
    {   /* peer asked us to link back: use the CONNECTING address, never a host supplied in the body */
        int backPort = 0; char backPin[16] = {0};
        if (mobile_get_json_int(body, "back_port", &backPort)) {
            mobile_get_json_string(body, "back_pin", backPin, sizeof(backPin));
            if (backPin[0]) link_spawn_backlink(clientIp, backPort, backPin);
        }
    }

    LeaveCriticalSection(&g_mobileCS);
    mobile_send_json(s, 200, resp);
}

/* 2. Unified Mobile Dashboard Endpoint */
static void handle_mobile_dashboard(SOCKET s) {
    char hostName[64] = {0}; DWORD hLen = sizeof(hostName);
    GetComputerNameA(hostName, &hLen);

    MEMORYSTATUSEX ms = {0}; ms.dwLength = sizeof(ms);
    GlobalMemoryStatusEx(&ms);
    int ramPercent = (int)ms.dwMemoryLoad;
    int cpuPercent = mobile_get_real_cpu_percent();

    /* Gather real metrics */
    long long inPkts = g_pMobileRealInPkts ? (long long)*g_pMobileRealInPkts : 0;      /* 0 = not measured (never invented) */
    long long outPkts = g_pMobileRealOutPkts ? (long long)*g_pMobileRealOutPkts : 0;
    long long wafDrops = (g_pMobileWafBlk ? *g_pMobileWafBlk : 0) + (g_pMobileRealDrops ? *g_pMobileRealDrops : 0);
    int threatCount = g_pMobileAvThreats ? *g_pMobileAvThreats : 0;
    int threatsQuar = 0;
    int threatsSafe = 0;
    int activeConns = g_pMobileNetConnCnt ? *g_pMobileNetConnCnt : 0;
    BOOL isLocked = (g_pMobileLockdown && *g_pMobileLockdown) ? TRUE : FALSE;

    /* Get real threat counts from callback if bound */
    if (g_pMobileGetThreatsJson) {
        g_pMobileGetThreatsJson(NULL, 0, &threatCount, &threatsSafe, &threatsQuar);
    }

    /* Build engines JSON */
    char enginesJson[4096] = {0};
    if (g_pMobileGetEnginesJson) {
        g_pMobileGetEnginesJson(enginesJson, sizeof(enginesJson));
    } else {
        strcpy(enginesJson, "");   /* engine status unavailable: report none instead of inventing RUNNING entries */
    }

    /* Build alerts JSON */
    char alertsJson[4096] = {0};
    if (g_pMobileGetAlertsJson) {
        g_pMobileGetAlertsJson(alertsJson, sizeof(alertsJson), 6);
    }
    if (!alertsJson[0]) {
        alertsJson[0] = 0;   /* no alerts */
    }

    /* Build sparkline JSON */
    char sparklineJson[128];
    if (g_pMobileSparkline) {
        snprintf(sparklineJson, sizeof(sparklineJson),
            "[%d,%d,%d,%d,%d,%d,%d]",
            g_pMobileSparkline[0], g_pMobileSparkline[1], g_pMobileSparkline[2],
            g_pMobileSparkline[3], g_pMobileSparkline[4], g_pMobileSparkline[5],
            g_pMobileSparkline[6]);
    } else {
        strcpy(sparklineJson, "[0,0,0,0,0,0,0]");
    }

    char *json = (char*)malloc(MOBILE_API_JSON_SIZE);
    if (!json) {
        mobile_send_json(s, 500, "{\"error\":\"Out of memory.\"}");
        return;
    }

    snprintf(json, MOBILE_API_JSON_SIZE,
        "{"
        "\"server\":{\"hostname\":\"%s\",\"platform\":\"Windows x64\",\"status\":\"%s\",\"uptime_sec\":%lld},"
        "\"resources\":{\"ram_percent\":%d,\"cpu_percent\":%d},"
        "\"security\":{"
          "\"firewall_locked\":%s,"
          "\"total_threats\":%d,"
          "\"threats_quarantined\":%d,"
          "\"threats_safe\":%d,"
          "\"active_connections\":%d,"
          "\"waf_blocked\":%lld,"
          "\"waf_inspected\":%lld,"
          "\"network_drops\":%lld"
        "},"
        "\"traffic\":{"
          "\"inbound_pkts\":%lld,"
          "\"outbound_pkts\":%lld,"
          "\"sparkline\":%s"
        "},"
        "\"engines\":[%s],"
        "\"recent_alerts\":[%s]"
        "}",
        hostName, isLocked ? "EMERGENCY_LOCKDOWN" : "ONLINE_PROTECTED",
        (long long)GetTickCount64() / 1000,
        ramPercent, cpuPercent,
        isLocked ? "true" : "false",
        threatCount, threatsQuar, threatsSafe,
        activeConns, wafDrops, (g_pMobileWafInsp ? *g_pMobileWafInsp : 0), (g_pMobileRealDrops ? (long long)*g_pMobileRealDrops : 0),
        inPkts, outPkts,
        sparklineJson,
        enginesJson,
        alertsJson
    );

    mobile_send_json(s, 200, json);
    free(json);
}

/* 3. Firewall Lockdown Remote Trigger */
static void handle_mobile_firewall_lockdown(SOCKET s, const char *body) {
    int enable = 1;
    mobile_get_json_int(body, "enable", &enable);
    char msg[300] = {0};
    BOOL ok = fwp_lockdown(enable ? TRUE : FALSE, g_mobilePort, msg, sizeof(msg));
    if (ok && g_pMobileLockdown) *g_pMobileLockdown = enable ? TRUE : FALSE;
    char *em = kvai_escape_alloc(msg);
    char resp[700];
    snprintf(resp, sizeof(resp),
        "{\"status\":\"%s\",\"action\":\"firewall_lockdown\",\"locked\":%s,\"message\":\"%s\"}",
        ok ? "success" : "error", (g_pMobileLockdown && *g_pMobileLockdown) ? "true" : "false", em ? em : "");
    free(em);
    mobile_send_json(s, ok ? 200 : 500, resp);
}

/* 4. Remote Antivirus Trigger & Actions */
static void handle_mobile_threats_action(SOCKET s, const char *path, const char *body) {
    if (strstr(path, "/scan")) {
        BOOL started = g_pMobileScan ? g_pMobileScan() : FALSE;
        if (started) mobile_send_json(s, 200, "{\"status\":\"success\",\"action\":\"scan_initiated\",\"message\":\"Antivirus scan started on this node.\"}");
        else mobile_send_json(s, 500, "{\"status\":\"error\",\"action\":\"scan_initiated\",\"message\":\"Scan could not be started (already running or engine unavailable).\"}");
        return;
    }
    if (strstr(path, "/mark-safe")) {
        char filePath[MAX_PATH] = {0};
        mobile_get_json_string(body, "file_path", filePath, sizeof(filePath));
        if (!filePath[0]) {
            int fileId = 0;
            if (mobile_get_json_int(body, "id", &fileId) && fileId > 0) {
                snprintf(filePath, sizeof(filePath), "%d", fileId);
            }
        }
        BOOL acted = FALSE;
        if (g_pMobileThreatAction) {
            acted = g_pMobileThreatAction(filePath, 0); /* 0 = mark safe */
        }
        char resp[512];
        snprintf(resp, sizeof(resp),
            "{\"status\":\"%s\","
            "\"action\":\"marked_safe\","
            "\"file_target\":\"%s\","
            "\"applied_to_db\":%s,"
            "\"message\":\"%s\"}",
            acted ? "success" : "error", filePath, acted ? "true" : "false",
            acted ? "File hash recorded as trusted in the Threat Database." : "Not applied: file not found in the Threat Database.");
        mobile_send_json(s, acted ? 200 : 404, resp);
        return;
    }
    if (strstr(path, "/quarantine")) {
        char filePath[MAX_PATH] = {0};
        mobile_get_json_string(body, "file_path", filePath, sizeof(filePath));
        if (!filePath[0]) {
            int fileId = 0;
            if (mobile_get_json_int(body, "id", &fileId) && fileId > 0) {
                snprintf(filePath, sizeof(filePath), "%d", fileId);
            }
        }
        BOOL acted = FALSE;
        if (g_pMobileThreatAction) {
            acted = g_pMobileThreatAction(filePath, 1); /* 1 = quarantine */
        }
        char resp[512];
        snprintf(resp, sizeof(resp),
            "{\"status\":\"%s\","
            "\"action\":\"quarantined\","
            "\"file_target\":\"%s\","
            "\"applied_to_db\":%s,"
            "\"message\":\"%s\"}",
            acted ? "success" : "error", filePath, acted ? "true" : "false",
            acted ? "File moved to quarantine." : "Not applied: quarantine failed or file not found.");
        mobile_send_json(s, acted ? 200 : 404, resp);
        return;
    }

    /* Default: Return list of real threats */
    char *threatsJson = (char*)malloc(16384);
    if (!threatsJson) {
        mobile_send_json(s, 500, "{\"error\":\"Out of memory.\"}");
        return;
    }
    threatsJson[0] = '\0';
    int total = 0, safe = 0, quar = 0;

    if (g_pMobileGetThreatsJson) {
        g_pMobileGetThreatsJson(threatsJson, 16384, &total, &safe, &quar);
    }

    char *json = (char*)malloc(20480);
    if (json) {
        snprintf(json, 20480,
            "{\"threat_count\":%d,\"quarantined_count\":%d,\"safe_count\":%d,\"threats\":[%s]}",
            total, quar, safe, threatsJson);
        mobile_send_json(s, 200, json);
        free(json);
    } else {
        mobile_send_json(s, 500, "{\"error\":\"Out of memory.\"}");
    }
    free(threatsJson);
}

/* 5. Live Active Network Sockets */
static void handle_mobile_network_connections(SOCKET s) {
    char json[4096];
    int p = snprintf(json, sizeof(json), "{\"connections\":[");

    ULONG ulSize = sizeof(MIB_TCPTABLE_OWNER_PID);
    PMIB_TCPTABLE_OWNER_PID pTcpTable = (PMIB_TCPTABLE_OWNER_PID)malloc(ulSize);
    if (pTcpTable && GetExtendedTcpTable(pTcpTable, &ulSize, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == ERROR_INSUFFICIENT_BUFFER) {
        free(pTcpTable);
        pTcpTable = (PMIB_TCPTABLE_OWNER_PID)malloc(ulSize);
    }

    int count = 0;
    if (pTcpTable && GetExtendedTcpTable(pTcpTable, &ulSize, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
        for (DWORD i = 0; i < pTcpTable->dwNumEntries && count < 25; i++) {
            struct in_addr locAddr, remAddr;
            locAddr.S_un.S_addr = (u_long)pTcpTable->table[i].dwLocalAddr;
            remAddr.S_un.S_addr = (u_long)pTcpTable->table[i].dwRemoteAddr;
            int locPort = ntohs((u_short)pTcpTable->table[i].dwLocalPort);
            int remPort = ntohs((u_short)pTcpTable->table[i].dwRemotePort);
            DWORD pid   = pTcpTable->table[i].dwOwningPid;

            char procName[MAX_PATH] = "System";
            HANDLE hp = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
            if (hp) {
                GetProcessImageFileNameA(hp, procName, sizeof(procName));
                char *fn = strrchr(procName, '\\');
                if (fn) memmove(procName, fn + 1, strlen(fn));
                CloseHandle(hp);
            }

            p += snprintf(json + p, sizeof(json) - p,
                "%s{\"pid\":%lu,\"process\":\"%s\",\"local\":\"%s:%d\",\"remote\":\"%s:%d\",\"state\":%lu}",
                count > 0 ? "," : "",
                pid, procName, inet_ntoa(locAddr), locPort, inet_ntoa(remAddr), remPort,
                pTcpTable->table[i].dwState);
            count++;
        }
    }
    if (pTcpTable) free(pTcpTable);

    snprintf(json + p, sizeof(json) - p, "],\"total\":%d}", count);
    mobile_send_json(s, 200, json);
}

/* 6. Together AI (DeepSeek-V4-Pro) & Multi-Team Mobile Chat */
static void handle_mobile_ai_chat(SOCKET s, const char *body) {
    char prompt[1024] = {0}, team[32] = "blue", apiKey[256] = {0}, model[128] = {0};
    mobile_get_json_string(body, "prompt", prompt, sizeof(prompt));
    mobile_get_json_string(body, "team", team, sizeof(team));
    mobile_get_json_string(body, "apiKey", apiKey, sizeof(apiKey));
    if (!apiKey[0]) mobile_get_json_string(body, "api_key", apiKey, sizeof(apiKey));
    mobile_get_json_string(body, "model", model, sizeof(model));
    if (!prompt[0]) { mobile_send_json(s, 400, "{\"error\":\"Missing 'prompt' in request body.\"}"); return; }

    const char *role =
        _stricmp(team, "red") == 0 ? "You are Kaevex RED TEAM Lead. Specialize in offensive security, vulnerability discovery and mitigations (authorized, defensive context only)." :
        _stricmp(team, "purple") == 0 ? "You are Kaevex PURPLE TEAM Coordinator. Bridge offensive simulation with detection engineering and SIEM rules." :
        _stricmp(team, "green") == 0 ? "You are Kaevex GREEN TEAM Compliance Officer. Focus on ISO 27001, NIST CSF 2.0, CIS Benchmarks and audit readiness." :
        _stricmp(team, "yellow") == 0 ? "You are Kaevex YELLOW TEAM DevSecOps Architect. Focus on application security, secure SDLC and API defense." :
        "You are Kaevex BLUE TEAM SOC AI Analyst. Specialize in telemetry analysis, incident triage, containment and perimeter defense.";
    char sys[1400];
    snprintf(sys, sizeof(sys), "%s Be concise, technical, use bullet points. You cannot run scans or apply fixes and must never claim you did. "
        "Known live facts: %d threats recorded, %d active connections, firewall lockdown %s. Anything else about this host is unknown to you.",
        role, g_pMobileAvThreats ? *g_pMobileAvThreats : 0, g_pMobileNetConnCnt ? *g_pMobileNetConnCnt : 0,
        (g_pMobileLockdown && *g_pMobileLockdown) ? "ACTIVE" : "off");

    int prov = kvai_cloud_provider(g_aiProvider);
    char *reply = (char*)malloc(32768), *jsonOut = (char*)malloc(80000);
    if (!reply || !jsonOut) { free(reply); free(jsonOut); mobile_send_json(s, 500, "{\"error\":\"Out of memory.\"}"); return; }
    KvAiResult r;
    BOOL ok = (g_aiProvider >= 0 && g_aiProvider < KVAI_PROVIDER_COUNT) &&
              kvai_chat(prov, apiKey[0] ? apiKey : NULL, model[0] ? model : NULL, sys, prompt, 0.6f, 0, reply, 32768, 0, &r);
    if (!(g_aiProvider >= 0 && g_aiProvider < KVAI_PROVIDER_COUNT)) { memset(&r, 0, sizeof r); snprintf(r.error, sizeof r.error, "Server is in Local mode: no cloud AI provider selected."); }

    char *eReply = kvai_escape_alloc(ok ? reply : r.error), *ePrompt = kvai_escape_alloc(prompt), *eErr = kvai_escape_alloc(r.error), *eModel = kvai_escape_alloc(r.model);
    if (ok) {
        snprintf(jsonOut, 80000, "{\"status\":\"success\",\"provider\":\"%s\",\"model\":\"%s\",\"is_fallback\":false,\"latency_ms\":%u,"
            "\"team\":\"%s\",\"prompt\":\"%s\",\"reply\":\"%s\",\"recommendations\":[]}",
            g_kvProv[prov].id, eModel ? eModel : "", r.ms, team, ePrompt ? ePrompt : "", eReply ? eReply : "");
        mobile_send_json(s, 200, jsonOut);
    } else {
        snprintf(jsonOut, 80000, "{\"status\":\"error\",\"provider\":\"%s\",\"model\":\"%s\",\"is_fallback\":true,\"upstream_status\":%d,"
            "\"error\":\"%s\",\"team\":\"%s\",\"prompt\":\"%s\",\"reply\":\"AI request failed: %s\","
            "\"recommendations\":[\"Fix the provider key/model in Settings > AI Engine or POST /api/v1/ai/config\"]}",
            g_aiProvider < KVAI_PROVIDER_COUNT ? g_kvProv[prov].id : "local", eModel ? eModel : "", r.status, eErr ? eErr : "", team, ePrompt ? ePrompt : "", eReply ? eReply : "");
        mobile_send_json(s, 502, jsonOut);
    }
    free(eReply); free(ePrompt); free(eErr); free(eModel); free(reply); free(jsonOut);
}

/* 6b. Together AI Configuration Endpoint (GET/POST) */
static void handle_mobile_ai_config(SOCKET s, const char *method, const char *body) {
    if (strcmp(method, "GET") == 0) {
        int prov = kvai_cloud_provider(g_aiProvider);
        char key[256] = {0}, model[128] = {0};
        kvai_key_get(prov, key, sizeof(key)); kvai_model_get(prov, model, sizeof(model));
        char masked[32] = "None"; size_t kl = strlen(key);
        if (kl > 8) snprintf(masked, sizeof(masked), "...%s", key + kl - 4);   /* last 4 only */
        else if (kl > 0) strcpy(masked, "********");
        char resp[900];
        snprintf(resp, sizeof(resp),
            "{\"status\":\"success\",\"provider\":\"%s\",\"provider_index\":%d,\"model\":\"%s\",\"host\":\"%s\",\"has_key\":%s,\"key_masked\":\"%s\",\"key_source\":\"%s\"}",
            g_aiProvider < KVAI_PROVIDER_COUNT ? g_kvProv[prov].id : "local", g_aiProvider, model, g_kvProv[prov].host,
            key[0] ? "true" : "false", masked, kvai_key_source(prov));
        SecureZeroMemory(key, sizeof key);
        mobile_send_json(s, 200, resp);
    } else if (strcmp(method, "POST") == 0) {
        char key[256] = {0}, model[128] = {0}, provName[24] = {0};
        mobile_get_json_string(body, "apiKey", key, sizeof(key));
        if (!key[0]) mobile_get_json_string(body, "api_key", key, sizeof(key));
        mobile_get_json_string(body, "model", model, sizeof(model));
        mobile_get_json_string(body, "provider", provName, sizeof(provName));
        if (provName[0]) {
            int found = -1;
            for (int i = 0; i < KVAI_PROVIDER_COUNT; i++) if (_stricmp(provName, g_kvProv[i].id) == 0) found = i;
            if (_stricmp(provName, "local") == 0) found = KVAI_P_LOCAL;
            if (found < 0) { mobile_send_json(s, 400, "{\"error\":\"Unknown provider. Use together, groq, nvidia or local.\"}"); return; }
            g_aiProvider = found;
        }
        if (key[0] && g_aiProvider < KVAI_PROVIDER_COUNT) kvai_key_save(g_aiProvider, key);
        if (model[0] && g_aiProvider < KVAI_PROVIDER_COUNT) kvai_model_set(g_aiProvider, model);
        SecureZeroMemory(key, sizeof key);
        mobile_send_json(s, 200, "{\"status\":\"success\",\"message\":\"AI configuration updated for the selected provider.\"}");
    } else mobile_send_json(s, 405, "{\"error\":\"Method not allowed.\"}");
}

/* 7. Multi-Server Cluster Management Endpoints */
static void handle_mobile_cluster_nodes(SOCKET s, const char *method, const char *path, const char *body) {
    (void)path;
    if (strcmp(method, "GET") == 0) {
        char *json = (char*)malloc(MOBILE_API_JSON_SIZE);
        if (!json) { mobile_send_json(s, 500, "{\"error\":\"Out of memory.\"}"); return; }
        link_nodes_json(json, MOBILE_API_JSON_SIZE);
        mobile_send_json(s, 200, json); free(json); return;
    }
    if (strcmp(method, "POST") == 0) {
        /* Link to another node: body {"ip":"..","port":9009,"pin":"123456"} - a real pairing handshake. */
        char ip[64] = {0}, pin[16] = {0}; int port = MOBILE_API_DEFAULT_PORT;
        mobile_get_json_string(body, "ip", ip, sizeof(ip)); mobile_get_json_string(body, "pin", pin, sizeof(pin));
        mobile_get_json_int(body, "port", &port);
        if (!ip[0] || strlen(pin) != 6 || !link_valid_host(ip)) { mobile_send_json(s, 400, "{\"error\":\"Need ip, port and 6-digit pin of the node to link.\"}"); return; }
        char msg[300] = {0};
        BOOL ok = link_connect_raw(ip, port, pin, 0, msg, sizeof(msg));
        char *em = kvai_escape_alloc(msg); char resp[500];
        snprintf(resp, sizeof(resp), "{\"status\":\"%s\",\"message\":\"%s\"}", ok ? "success" : "error", em ? em : ""); free(em);
        mobile_send_json(s, ok ? 201 : 502, resp); return;
    }
    mobile_send_json(s, 405, "{\"error\":\"Method not allowed.\"}");
}

/* 8. Cluster Broadcast Command (Lockdown all, Scan all, Sync Rules) */
static void handle_mobile_cluster_broadcast(SOCKET s, const char *body) {
    char action[64] = {0};
    mobile_get_json_string(body, "action", action, sizeof(action));
    const char *peerAction = strcmp(action, "lockdown-all") == 0 ? "lockdown" : strcmp(action, "unlock-all") == 0 ? "unlock" : strcmp(action, "scan-all") == 0 ? "scan" : NULL;
    if (!peerAction) { mobile_send_json(s, 400, "{\"error\":\"Unknown broadcast action. Supported: lockdown-all, unlock-all, scan-all.\"}"); return; }

    /* 1) this node, for real */
    BOOL localOk = FALSE; char lmsg[300] = {0};
    if (strcmp(peerAction, "scan") == 0) localOk = g_pMobileScan ? g_pMobileScan() : FALSE;
    else { localOk = fwp_lockdown(strcmp(peerAction, "lockdown") == 0, g_mobilePort, lmsg, sizeof(lmsg)); if (localOk && g_pMobileLockdown) *g_pMobileLockdown = (strcmp(peerAction, "lockdown") == 0); }
    /* 2) every linked node, over the network; counts are confirmations, not intentions */
    char detail[1200] = {0}; int peersOk = link_broadcast(peerAction, detail, sizeof(detail));
    char *ed = kvai_escape_alloc(detail);
    char resp[2000];
    snprintf(resp, sizeof(resp), "{\"status\":\"%s\",\"action\":\"%s\",\"local_applied\":%s,\"peers_confirmed\":%d,\"affected_servers\":%d,\"detail\":\"%s\"}",
             localOk ? "success" : "partial", action, localOk ? "true" : "false", peersOk, peersOk + (localOk ? 1 : 0), ed ? ed : "");
    free(ed);
    mobile_send_json(s, 200, resp);
}

/* Firewall status / policy (GET status, GET export, POST import[+apply]) */
static void handle_mobile_firewall_policy(SOCKET s, const char *method, const char *path, const char *body) {
    if (strstr(path, "/status")) {
        char r[600];
        snprintf(r, sizeof(r), "{\"status\":\"success\",\"admin\":%s,\"profiles_on_mask\":%d,\"managed_rules\":%d,\"tamper_watch\":%s,\"guard_seconds_left\":%d,\"lockdown\":%s}",
                 fwp_is_admin() ? "true" : "false", fwp_profiles_on(), g_fwpCount, fwp_watch_running() ? "true" : "false", fwp_guard_remaining(),
                 (g_pMobileLockdown && *g_pMobileLockdown) ? "true" : "false");
        mobile_send_json(s, 200, r); return;
    }
    if (strcmp(method, "GET") == 0) {
        char *txt = fwp_policy_export_text(); if (!txt) { mobile_send_json(s, 500, "{\"error\":\"Out of memory.\"}"); return; }
        char *e = kvai_escape_alloc(txt); free(txt);
        size_t cap = strlen(e ? e : "") + 64; char *out = (char*)malloc(cap);
        if (out) { snprintf(out, cap, "{\"status\":\"success\",\"policy\":\"%s\"}", e ? e : ""); mobile_send_json(s, 200, out); free(out); }
        free(e); return;
    }
    if (strcmp(method, "POST") == 0) {
        int apply = 0; mobile_get_json_int(body, "apply", &apply);
        const char *pv = kvai_find_key(body, "policy");
        if (!pv || *pv != '"') { mobile_send_json(s, 400, "{\"error\":\"Missing 'policy' string.\"}"); return; }
        char *txt = (char*)malloc(MOBILE_API_BUF_SIZE); if (!txt) { mobile_send_json(s, 500, "{\"error\":\"Out of memory.\"}"); return; }
        kvai_read_str(pv, txt, MOBILE_API_BUF_SIZE);
        int bad = 0; int ok = fwp_policy_import_text(txt, 1, &bad); free(txt);
        fwp_policy_save();
        FwpApplyResult ar; memset(&ar, 0, sizeof ar); BOOL applied = FALSE;
        if (apply && ok > 0) applied = fwp_apply_all(&ar, NULL, 0);
        char r[500]; char *ee = kvai_escape_alloc(ar.firstError);
        snprintf(r, sizeof(r), "{\"status\":\"%s\",\"imported\":%d,\"rejected\":%d,\"applied\":%s,\"rules_added\":%d,\"error\":\"%s\"}",
                 (ok > 0 && (!apply || applied)) ? "success" : "error", ok, bad, applied ? "true" : "false", ar.added, ee ? ee : ""); free(ee);
        mobile_send_json(s, 200, r); return;
    }
    mobile_send_json(s, 405, "{\"error\":\"Method not allowed.\"}");
}

static void handle_mobile_boot_audit(SOCKET s) {
    BootkitAuditReport rep;
    memset(&rep, 0, sizeof(rep));
    boot_audit_run_full_scan(&rep, NULL);
    char *jsonBuf = (char*)malloc(MOBILE_API_BUF_SIZE);
    if (!jsonBuf) {
        mobile_send_json(s, 500, "{\"error\":\"Out of memory\"}");
        return;
    }
    boot_audit_generate_json(&rep, jsonBuf, MOBILE_API_BUF_SIZE);
    mobile_send_json(s, 200, jsonBuf);
    free(jsonBuf);
}

/* ===========================================================================
 * CONNECTION DISPATCHER WORKER THREAD
 * =========================================================================== */
typedef struct {
    SOCKET s;
    char   clientIp[48];
} MobileClientWork;

static DWORD WINAPI mobile_client_worker(LPVOID pArg) {
    MobileClientWork *work = (MobileClientWork*)pArg;
    SOCKET s = work->s;
    char clientIp[48]; strncpy(clientIp, work->clientIp, 47);
    free(work);

    char *buf = (char*)malloc(MOBILE_API_BUF_SIZE);
    if (!buf) { closesocket(s); return 0; }

    int rd = recv(s, buf, MOBILE_API_BUF_SIZE - 1, 0);
    if (rd <= 0) {
        free(buf);
        closesocket(s);
        return 0;
    }
    buf[rd] = '\0';

    /* Handle Expect: 100-continue from .NET / PowerShell / Android clients */
    if (strstr(buf, "100-continue") || strstr(buf, "100-Continue")) {
        const char *cont = "HTTP/1.1 100 Continue\r\n\r\n";
        send(s, cont, (int)strlen(cont), 0);
    }

    /* Accumulate full body if Content-Length exceeds already read bytes */
    const char *clHeader = strstr(buf, "Content-Length:");
    if (!clHeader) clHeader = strstr(buf, "content-length:");
    if (clHeader) {
        clHeader += 15;
        while (*clHeader == ' ' || *clHeader == '\t') clHeader++;
        int expectedLen = atoi(clHeader);
        const char *bodyStart = strstr(buf, "\r\n\r\n");
        if (bodyStart) {
            bodyStart += 4;
            int bodyAlreadyRead = (int)(rd - (bodyStart - buf));
            while (bodyAlreadyRead < expectedLen && rd < MOBILE_API_BUF_SIZE - 1) {
                int r2 = recv(s, buf + rd, expectedLen - bodyAlreadyRead, 0);
                if (r2 <= 0) break;
                rd += r2;
                bodyAlreadyRead += r2;
                buf[rd] = '\0';
            }
        }
    }

    /* Parse HTTP Method, Path, and Body */
    char method[16] = {0};
    char path[512]  = {0};
    sscanf(buf, "%15s %511s", method, path);

    /* Locate body (after \r\n\r\n) */
    const char *body = strstr(buf, "\r\n\r\n");
    if (body) body += 4; else body = "";

    /* Handle CORS Preflight */
    if (strcmp(method, "OPTIONS") == 0) {
        mobile_send_response(s, 204, "text/plain", "");
        free(buf);
        shutdown(s, SD_BOTH);
        closesocket(s);
        return 0;
    }

    /* Only private / VPN address ranges may talk to the node API (it is plain HTTP) */
    if (!link_is_private_ip(clientIp)) {
        mobile_send_response(s, 403, "application/json", "{\"error\":\"Forbidden: the node API only accepts private-network clients.\"}");
        free(buf); closesocket(s); return 0;
    }

    /* Telemetry: Increment inspected WAF requests counter */
    if (g_pMobileWafInsp) (*g_pMobileWafInsp)++;

    /* 1. Check Anti-Brute-Force IP Lock */
    if (mobile_is_ip_blocked(clientIp)) {
        if (g_pMobileWafBlk) (*g_pMobileWafBlk)++;
        mobile_send_response(s, 429, "application/json",
            "{\"status\":\"blocked\","
            "\"error\":\"Too Many Requests: IP temporarily blocked due to repeated security violations or brute-force.\","
            "\"retry_after_seconds\":600}");
        free(buf);
        closesocket(s);
        return 0;
    }

    /* 2. INLINE PROACTIVE SHIELD: WAF Inspection (SQLi, XSS, Path Traversal, RCE) */
    WafVerdict wafV; char wHdr[8192]; wHdr[0] = 0;
    { const char *h = strstr(buf, "\r\n"); if (h) { h += 2; const char *he = strstr(h, "\r\n\r\n"); size_t hl = he ? (size_t)(he - h) : strlen(h); size_t w = 0; for (size_t i = 0; i < hl && w + 1 < sizeof wHdr; i++) if (h[i] != '\r') wHdr[w++] = h[i]; wHdr[w] = 0; } }
    { WafRequest wrq = { method, path, wHdr, (const unsigned char *)body, strlen(body) }; waf_inspect(&wrq, 2, &wafV); }
    struct { int isMalicious; const char *threatType, *cwe, *mitre; char detail[256]; } wafVerdict;
    wafVerdict.isMalicious = wafV.blocked; wafVerdict.threatType = wafV.top[0] ? wafV.top : "Policy"; wafVerdict.cwe = wafV.nhits ? wafV.hits[0].cwe : "N/A"; wafVerdict.mitre = wafV.nhits ? wafV.hits[0].mitre : "N/A";
    snprintf(wafVerdict.detail, sizeof wafVerdict.detail, "%s (rule %s, score %d)", wafV.nhits ? wafV.hits[0].name : "", wafV.nhits ? wafV.hits[0].rule : "", wafV.score);
    if (wafVerdict.isMalicious) {
        if (g_pMobileWafBlk) (*g_pMobileWafBlk)++;
        mobile_record_failed_attempt(clientIp);

        if (g_pMobileAddAlert) {
            char alertMsg[300];
            snprintf(alertMsg, sizeof(alertMsg), "[PROACTIVE SHIELD] Intercepted %s from %s -> %s",
                     wafVerdict.threatType, clientIp, path);
            g_pMobileAddAlert("WebGuard WAF", "CRITICAL", alertMsg);
        }

        char blockResp[1024];
        snprintf(blockResp, sizeof(blockResp),
            "{\"status\":\"blocked\","
            "\"error\":\"Forbidden: Request intercepted by Kaevex Proactive WAF Shield.\","
            "\"threat_type\":\"%s\","
            "\"cwe\":\"%s\","
            "\"mitre\":\"%s\","
            "\"client_ip\":\"%s\","
            "\"detail\":\"%s\","
            "\"action\":\"Payload dropped before reaching backend database, system, or application engine.\"}",
            wafVerdict.threatType, wafVerdict.cwe, wafVerdict.mitre, clientIp, wafVerdict.detail);

        mobile_send_response(s, 403, "application/json", blockResp);
        free(buf);
        closesocket(s);
        return 0;
    }

    /* Public endpoints (No Token required) */
    if (strcmp(path, "/api/v1/auth/pair") == 0 && strcmp(method, "POST") == 0) {
        handle_mobile_auth_pair(s, body, clientIp);
        free(buf);
        closesocket(s);
        return 0;
    }

    if (strcmp(path, "/api/v1/ping") == 0) {
        mobile_send_json(s, 200, "{\"status\":\"online\",\"platform\":\"Kaevex SOC Engine\",\"version\":\"1.0.0-PROD\"}");
        free(buf);
        closesocket(s);
        return 0;
    }

    /* Protected endpoints: Validate Bearer Token */
    int isAdmin = 0;
    if (!mobile_validate_token(buf, clientIp, &isAdmin)) {
        mobile_send_json(s, 401, "{\"error\":\"Unauthorized: Missing or invalid Bearer token. Pair device first via /api/v1/auth/pair.\"}");
        free(buf);
        closesocket(s);
        return 0;
    }

    /* Dispatch Protected Routes */
    if (strncmp(path, "/api/v1/mobile/dashboard", 24) == 0) {
        handle_mobile_dashboard(s);
    }
    else if (strncmp(path, "/api/v1/firewall/lockdown", 25) == 0 && strcmp(method, "POST") == 0) {
        handle_mobile_firewall_lockdown(s, body);
    }
    else if (strncmp(path, "/api/v1/threats", 15) == 0) {
        handle_mobile_threats_action(s, path, body);
    }
    else if (strncmp(path, "/api/v1/network/connections", 27) == 0) {
        handle_mobile_network_connections(s);
    }
    else if (strncmp(path, "/api/v1/ai/chat", 15) == 0 && strcmp(method, "POST") == 0) {
        handle_mobile_ai_chat(s, body);
    }
    else if (strncmp(path, "/api/v1/ai/config", 17) == 0) {
        handle_mobile_ai_config(s, method, body);
    }
    else if (strncmp(path, "/api/v1/firewall/policy", 23) == 0 || strncmp(path, "/api/v1/firewall/status", 23) == 0) {
        handle_mobile_firewall_policy(s, method, path, body);
    }
    else if (strncmp(path, "/api/v1/cluster/broadcast", 25) == 0 && strcmp(method, "POST") == 0) {
        handle_mobile_cluster_broadcast(s, body);
    }
    else if (strncmp(path, "/api/v1/cluster/nodes", 21) == 0) {
        handle_mobile_cluster_nodes(s, method, path, body);
    }
    else if ((strncmp(path, "/api/v1/boot-audit", 18) == 0 || strncmp(path, "/api/v1/rootkit-scan", 20) == 0) && strcmp(method, "GET") == 0) {
        handle_mobile_boot_audit(s);
    }
    else {
        mobile_send_json(s, 404, "{\"error\":\"Endpoint not found.\"}");
    }

    free(buf);
    closesocket(s);
    return 0;
}

/* ===========================================================================
 * MASTER LISTENER THREAD (Listens on 0.0.0.0 for Wi-Fi / LAN / VPN)
 * =========================================================================== */
static DWORD WINAPI mobile_api_listener_thread(LPVOID pArg) {
    int port = pArg ? (int)(intptr_t)pArg : g_mobilePort;
    if (port <= 0) port = MOBILE_API_DEFAULT_PORT;
    g_mobilePort = port;

    SOCKET srv = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (srv == INVALID_SOCKET) return 1;

    int opt = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt));

    /* BIND TO 0.0.0.0 (INADDR_ANY) TO ALLOW PHONE CONNECTIONS ACROSS LAN/WIFI */
    struct sockaddr_in addr = {0};
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port        = htons((u_short)port);

    if (bind(srv, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        int err = WSAGetLastError();
        if (err == WSAEADDRINUSE && port == MOBILE_API_DEFAULT_PORT) {
            port = 9010;
            g_mobilePort = port;
            addr.sin_port = htons((u_short)port);
            if (bind(srv, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
                closesocket(srv);
                return 1;
            }
        } else {
            closesocket(srv);
            return 1;
        }
    }

    if (listen(srv, 32) != 0) {
        closesocket(srv);
        return 1;
    }

    g_mobileListenSock = srv;
    g_mobileRunning = TRUE;

    printf("[MOBILE-API] Server online and listening on 0.0.0.0:%d (private-network clients only; PIN shown in Settings)\n", port);

    while (g_mobileRunning) {
        struct sockaddr_in clientAddr;
        int clientLen = sizeof(clientAddr);
        SOCKET cs = accept(srv, (struct sockaddr*)&clientAddr, &clientLen);
        if (cs == INVALID_SOCKET) {
            if (!g_mobileRunning) break;
            continue;
        }

        MobileClientWork *work = (MobileClientWork*)malloc(sizeof(MobileClientWork));
        if (work) {
            work->s = cs;
            strncpy(work->clientIp, inet_ntoa(clientAddr.sin_addr), 47);
            HANDLE hWorker = CreateThread(NULL, 0, mobile_client_worker, work, 0, NULL);
            if (hWorker) CloseHandle(hWorker); else { free(work); closesocket(cs); }
        } else {
            closesocket(cs);
        }
    }

    closesocket(srv);
    g_mobileListenSock = INVALID_SOCKET;
    return 0;
}

/* ---- Public API Engine Controller ---------------------------------------- */
static BOOL mobile_api_start(int port) {
    if (g_mobileRunning) return TRUE;
    if (!g_mobileCSInit) {
        InitializeCriticalSection(&g_mobileCS);
        g_mobileCSInit = TRUE;
    }

    WSADATA wsa;
    WSAStartup(MAKEWORD(2,2), &wsa);

    /* Generate the pairing PIN from the OS CSPRNG */
    mobile_rotate_pin();

    HANDLE hTh = CreateThread(NULL, 0, mobile_api_listener_thread, (LPVOID)(intptr_t)port, 0, NULL);
    if (hTh) {
        CloseHandle(hTh);
        return TRUE;
    }
    return FALSE;
}

static void mobile_api_stop(void) {
    g_mobileRunning = FALSE;
    if (g_mobileListenSock != INVALID_SOCKET) {
        closesocket(g_mobileListenSock);
        g_mobileListenSock = INVALID_SOCKET;
    }
}

static const char* mobile_api_get_pin(void) {
    return g_pairingPin;
}

#include "cluster_link_engine.h"

#endif /* MOBILE_API_ENGINE_H */
