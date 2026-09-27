/*===========================================================================
 * Kaevex Updater + Autonomous CVE Agent - upd_engine.h
 * Windows software inventory, local CVE catalog matching, targeted package updates,
 * Real-Time Progress Callbacks, and Continuous Background Vulnerability Watcher
 *===========================================================================*/
#pragma once
#ifndef UPD_ENGINE_H
#define UPD_ENGINE_H

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shellapi.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include "fw_engine.h"
#include "nvd_feed.h"

#define UPD_MAX_APPS    512
#define UPD_MAX_OS_CVES 32

/* --- Installed app record ------------------------------------------------- */
typedef struct {
    char name[256];
    char version[64];
    char publisher[128];
    char installDate[16];
    char uninstallStr[MAX_PATH];
    char executablePath[MAX_PATH];
    /* CVE match */
    int  cveCount;
    char cveId[4][24];       /* Up to 4 CVEs per app */
    int  cvssScore[4];       /* 0-100 */
    char cveFixed[4][64];    /* Fixed-in version */
    /* Update status */
    int  hasUpdate;
    char newVersion[64];
    char wingetId[128];
} InstalledApp;

static InstalledApp g_apps[UPD_MAX_APPS];
static int          g_appCount = 0;

/* --- OS Build & Vulnerability Information --------------------------------- */
typedef struct {
    char productName[128];
    char displayVersion[32];
    char currentBuild[32];
    char ubr[32];
    int  buildNumber;
    int  ubrNumber;
    /* OS CVEs */
    int  cveCount;
    char cveId[UPD_MAX_OS_CVES][24];
    int  cvssScore[UPD_MAX_OS_CVES];
    char cveDesc[UPD_MAX_OS_CVES][128];
    char mitigation[UPD_MAX_OS_CVES][128];
    BOOL mitigated[UPD_MAX_OS_CVES];
} OsInfo;

static OsInfo g_osInfo = {0};

/* --- Dynamic Vulnerability Intelligence Engine (JSON & Live Feed) --------- */
typedef struct {
    char appMatch[64];
    char vulnVerMax[32];
    char cveId[24];
    int  cvss;
    char fixedVer[32];
    char wingetId[128];
} CveEntry;

typedef struct {
    int  minBuild;
    int  maxBuild;
    char cveId[24];
    int  cvss;
    char desc[128];
    char mitigation[128];
} OsCveEntry;

#define UPD_MAX_DYNAMIC_CVES 1024
static CveEntry   g_cveDB[UPD_MAX_DYNAMIC_CVES];
static int        g_cveDBCnt = 0;
static OsCveEntry g_osCveDB[UPD_MAX_OS_CVES];
static int        g_osCveDBCnt = 0;
static BOOL       g_catalogLoaded = FALSE;

/* =========================================================================
 * Built-in CVE data is intentionally empty until records can be validated against authoritative advisories.
 * ========================================================================= */
typedef struct { const char *app; const char *verMax; const char *cveId; int cvss; const char *fixedVer; const char *wingetId; } StaticCve;
typedef struct { int minBuild; int maxBuild; const char *cveId; int cvss; const char *desc; const char *mitigation; } StaticOsCve;

static const StaticCve UPD_STATIC_CVE_DB[] = {
    {NULL,NULL,NULL,0,NULL,NULL}
};

static const StaticOsCve UPD_STATIC_OS_CVE_DB[] = {
    {0,0,NULL,0,NULL,NULL}
};

static void upd_load_builtin_cves(void) {
    /* Load static app CVE database */
    for (int i = 0; UPD_STATIC_CVE_DB[i].app != NULL && g_cveDBCnt < UPD_MAX_DYNAMIC_CVES; i++) {
        const StaticCve *s = &UPD_STATIC_CVE_DB[i];
        CveEntry *e = &g_cveDB[g_cveDBCnt];
        ZeroMemory(e, sizeof(*e));
        strncpy(e->appMatch,  s->app,     sizeof(e->appMatch)-1);
        strncpy(e->vulnVerMax,s->verMax,  sizeof(e->vulnVerMax)-1);
        strncpy(e->cveId,     s->cveId,   sizeof(e->cveId)-1);
        e->cvss = s->cvss;
        if (s->fixedVer) strncpy(e->fixedVer,  s->fixedVer,  sizeof(e->fixedVer)-1);
        if (s->wingetId) strncpy(e->wingetId,  s->wingetId,  sizeof(e->wingetId)-1);
        g_cveDBCnt++;
    }
    /* Load static OS CVE database */
    for (int i = 0; UPD_STATIC_OS_CVE_DB[i].cveId != NULL && g_osCveDBCnt < UPD_MAX_OS_CVES; i++) {
        const StaticOsCve *s = &UPD_STATIC_OS_CVE_DB[i];
        OsCveEntry *e = &g_osCveDB[g_osCveDBCnt];
        ZeroMemory(e, sizeof(*e));
        e->minBuild = s->minBuild;
        e->maxBuild = s->maxBuild;
        strncpy(e->cveId,       s->cveId,       sizeof(e->cveId)-1);
        e->cvss = s->cvss;
        if (s->desc)       strncpy(e->desc,       s->desc,       sizeof(e->desc)-1);
        if (s->mitigation) strncpy(e->mitigation, s->mitigation, sizeof(e->mitigation)-1);
        g_osCveDBCnt++;
    }
}

static void upd_load_catalog(void) {
    if (g_catalogLoaded) return;
    g_cveDBCnt = 0;
    g_osCveDBCnt = 0;

    /* Load the local built-in fallback first. */
    upd_load_builtin_cves();

    /* Then try to augment from JSON catalog file */
    FILE *f = fopen("dist\\data\\cve_catalog.json", "rb");
    if (!f) f = fopen("dist\\kaevex_cve_catalog.json", "rb");
    if (!f) f = fopen("kaevex_cve_catalog.json", "rb");
    if (!f) { g_catalogLoaded = TRUE; return; } /* use builtin only */

    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz <= 0 || sz > 1024 * 1024) { fclose(f); g_catalogLoaded = TRUE; return; }

    char *buf = (char*)malloc(sz + 1);
    if (!buf) { fclose(f); g_catalogLoaded = TRUE; return; }
    fread(buf, 1, sz, f);
    buf[sz] = '\0';
    fclose(f);

    char *osSec = strstr(buf, "\"os_cves\"");
    char *appSec = strstr(buf, "\"app_cves\"");

    if (osSec) {
        char *p = osSec;
        char *endP = appSec ? appSec : (buf + sz);
        while (p < endP && g_osCveDBCnt < UPD_MAX_OS_CVES) {
            char *obj = strchr(p, '{');
            if (!obj || obj >= endP) break;
            char *objEnd = strchr(obj, '}');
            if (!objEnd || objEnd >= endP) break;

            OsCveEntry *e = &g_osCveDB[g_osCveDBCnt];
            ZeroMemory(e, sizeof(*e));

            char *kMin = strstr(obj, "\"minBuild\"");
            if (kMin && kMin < objEnd) e->minBuild = atoi(kMin + 10 + strspn(kMin + 10, " :\""));
            char *kMax = strstr(obj, "\"maxBuild\"");
            if (kMax && kMax < objEnd) e->maxBuild = atoi(kMax + 10 + strspn(kMax + 10, " :\""));
            char *kCvss = strstr(obj, "\"cvss\"");
            if (kCvss && kCvss < objEnd) e->cvss = atoi(kCvss + 6 + strspn(kCvss + 6, " :\""));
            char *kId = strstr(obj, "\"cveId\"");
            if (kId && kId < objEnd) {
                char *v = strchr(kId + 7, '\"');
                if (v && v < objEnd) sscanf(v + 1, "%23[^\"]", e->cveId);
            }
            char *kDesc = strstr(obj, "\"desc\"");
            if (kDesc && kDesc < objEnd) {
                char *v = strchr(kDesc + 6, '\"');
                if (v && v < objEnd) sscanf(v + 1, "%127[^\"]", e->desc);
            }
            char *kMit = strstr(obj, "\"mitigation\"");
            if (kMit && kMit < objEnd) {
                char *v = strchr(kMit + 12, '\"');
                if (v && v < objEnd) sscanf(v + 1, "%127[^\"]", e->mitigation);
            }

            if (e->cveId[0]) g_osCveDBCnt++;
            p = objEnd + 1;
        }
    }

    if (appSec) {
        char *p = appSec;
        while (g_cveDBCnt < UPD_MAX_DYNAMIC_CVES) {
            char *obj = strchr(p, '{');
            if (!obj) break;
            char *objEnd = strchr(obj, '}');
            if (!objEnd) break;

            CveEntry *e = &g_cveDB[g_cveDBCnt];
            ZeroMemory(e, sizeof(*e));

            char *kMatch = strstr(obj, "\"appMatch\"");
            if (kMatch && kMatch < objEnd) {
                char *v = strchr(kMatch + 10, '\"');
                if (v && v < objEnd) sscanf(v + 1, "%63[^\"]", e->appMatch);
            }
            char *kMax = strstr(obj, "\"vulnVerMax\"");
            if (kMax && kMax < objEnd) {
                char *v = strchr(kMax + 12, '\"');
                if (v && v < objEnd) sscanf(v + 1, "%31[^\"]", e->vulnVerMax);
            }
            char *kId = strstr(obj, "\"cveId\"");
            if (kId && kId < objEnd) {
                char *v = strchr(kId + 7, '\"');
                if (v && v < objEnd) sscanf(v + 1, "%23[^\"]", e->cveId);
            }
            char *kCvss = strstr(obj, "\"cvss\"");
            if (kCvss && kCvss < objEnd) e->cvss = atoi(kCvss + 6 + strspn(kCvss + 6, " :\""));
            char *kFix = strstr(obj, "\"fixedVer\"");
            if (kFix && kFix < objEnd) {
                char *v = strchr(kFix + 10, '\"');
                if (v && v < objEnd) sscanf(v + 1, "%31[^\"]", e->fixedVer);
            }
            char *kWinget = strstr(obj, "\"wingetId\"");
            if (kWinget && kWinget < objEnd) {
                char *v = strchr(kWinget + 10, '\"');
                if (v && v < objEnd) sscanf(v + 1, "%127[^\"]", e->wingetId);
            }

            if (e->cveId[0]) g_cveDBCnt++;
            p = objEnd + 1;
        }
    }

    free(buf);
    g_catalogLoaded = TRUE;
}

/* Force reload of catalog (e.g. after file update) */
static void upd_reload_catalog(void) {
    g_catalogLoaded = FALSE;
    upd_load_catalog();
}

/* --- Version String Comparison ------------------------------------------- */
static int upd_ver_cmp(const char *a, const char *b) {
    int am[4]={0}, bm[4]={0};
    sscanf(a,"%d.%d.%d.%d",&am[0],&am[1],&am[2],&am[3]);
    sscanf(b,"%d.%d.%d.%d",&bm[0],&bm[1],&bm[2],&bm[3]);
    for(int i=0;i<4;i++){
        if(am[i]<bm[i]) return -1;
        if(am[i]>bm[i]) return  1;
    }
    return 0;
}

/* --- Query Windows OS Information & OS-level CVEs ------------------------ */
static void upd_scan_os_info(void) {
    ZeroMemory(&g_osInfo, sizeof(g_osInfo));
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        DWORD sz;
        sz = sizeof(g_osInfo.productName); RegQueryValueExA(hKey, "ProductName", NULL, NULL, (BYTE*)g_osInfo.productName, &sz);
        sz = sizeof(g_osInfo.displayVersion); RegQueryValueExA(hKey, "DisplayVersion", NULL, NULL, (BYTE*)g_osInfo.displayVersion, &sz);
        if (!g_osInfo.displayVersion[0]) {
            sz = sizeof(g_osInfo.displayVersion); RegQueryValueExA(hKey, "ReleaseId", NULL, NULL, (BYTE*)g_osInfo.displayVersion, &sz);
        }
        sz = sizeof(g_osInfo.currentBuild); RegQueryValueExA(hKey, "CurrentBuildNumber", NULL, NULL, (BYTE*)g_osInfo.currentBuild, &sz);
        if (!g_osInfo.currentBuild[0]) {
            sz = sizeof(g_osInfo.currentBuild); RegQueryValueExA(hKey, "CurrentBuild", NULL, NULL, (BYTE*)g_osInfo.currentBuild, &sz);
        }
        DWORD ubrVal = 0; sz = sizeof(ubrVal);
        if (RegQueryValueExA(hKey, "UBR", NULL, NULL, (BYTE*)&ubrVal, &sz) == ERROR_SUCCESS) {
            g_osInfo.ubrNumber = (int)ubrVal;
            snprintf(g_osInfo.ubr, sizeof(g_osInfo.ubr), ".%lu", ubrVal);
        }
        RegCloseKey(hKey);
    }
    if (!g_osInfo.productName[0]) strcpy(g_osInfo.productName, "Microsoft Windows");
    g_osInfo.buildNumber = atoi(g_osInfo.currentBuild);
    upd_load_catalog();

    /* Cross-reference OS build against dynamic OS CVE database */
    g_osInfo.cveCount = 0;
    for (int i = 0; i < g_osCveDBCnt && g_osInfo.cveCount < UPD_MAX_OS_CVES; i++) {
        if (g_osInfo.buildNumber >= g_osCveDB[i].minBuild && g_osInfo.buildNumber <= g_osCveDB[i].maxBuild) {
            int idx = g_osInfo.cveCount++;
            strncpy(g_osInfo.cveId[idx], g_osCveDB[i].cveId, 23);
            g_osInfo.cvssScore[idx] = g_osCveDB[i].cvss;
            strncpy(g_osInfo.cveDesc[idx], g_osCveDB[i].desc, 127);
            strncpy(g_osInfo.mitigation[idx], g_osCveDB[i].mitigation, 127);
            g_osInfo.mitigated[idx] = FALSE;
        }
    }
}

/* --- Read installed software from Registry -------------------------------- */
static int upd_scan_installed(void) {
    g_appCount = 0;
    upd_scan_os_info();

    static const struct { HKEY root; const char *path; } keys[] = {
        {HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall"},
        {HKEY_LOCAL_MACHINE, "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall"},
        {HKEY_CURRENT_USER,  "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall"},
        {0, NULL}
    };

    for(int k = 0; keys[k].path && g_appCount < UPD_MAX_APPS; k++) {
        HKEY hKey;
        if(RegOpenKeyExA(keys[k].root, keys[k].path, 0, KEY_READ, &hKey) != ERROR_SUCCESS)
            continue;

        char subName[256]; DWORD subLen = sizeof(subName), i = 0;
        while(g_appCount < UPD_MAX_APPS &&
              RegEnumKeyExA(hKey, i++, subName, &subLen, NULL,NULL,NULL,NULL) == ERROR_SUCCESS) {
            subLen = sizeof(subName);
            HKEY hSub;
            if(RegOpenKeyExA(hKey, subName, 0, KEY_READ, &hSub) != ERROR_SUCCESS) continue;

            InstalledApp *app = &g_apps[g_appCount];
            ZeroMemory(app, sizeof(*app));
            DWORD sz;

            sz = sizeof(app->name);
            RegQueryValueExA(hSub,"DisplayName",NULL,NULL,(BYTE*)app->name,&sz);
            sz = sizeof(app->version);
            RegQueryValueExA(hSub,"DisplayVersion",NULL,NULL,(BYTE*)app->version,&sz);
            sz = sizeof(app->publisher);
            RegQueryValueExA(hSub,"Publisher",NULL,NULL,(BYTE*)app->publisher,&sz);
            sz = sizeof(app->installDate);
            RegQueryValueExA(hSub,"InstallDate",NULL,NULL,(BYTE*)app->installDate,&sz);
            sz = sizeof(app->uninstallStr);
            RegQueryValueExA(hSub,"UninstallString",NULL,NULL,(BYTE*)app->uninstallStr,&sz);
            sz = sizeof(app->executablePath);
            RegQueryValueExA(hSub,"DisplayIcon",NULL,NULL,(BYTE*)app->executablePath,&sz);
            if (app->executablePath[0] == '"') {
                char *q = strchr(app->executablePath + 1, '"');
                if (q) *q = '\0';
                memmove(app->executablePath, app->executablePath + 1, strlen(app->executablePath));
            } else {
                char *comma = strchr(app->executablePath, ',');
                if (comma) *comma = '\0';
            }
            const char *iconExt = strrchr(app->executablePath, '.');
            if (!iconExt || _stricmp(iconExt, ".exe") != 0 ||
                GetFileAttributesA(app->executablePath) == INVALID_FILE_ATTRIBUTES)
                app->executablePath[0] = '\0';

            RegCloseKey(hSub);
            if(strlen(app->name) > 0) g_appCount++;
        }
        RegCloseKey(hKey);
    }
    return g_appCount;
}

/* --- Check CVEs against installed apps ------------------------------------ */
static int upd_check_cves(void) {
    upd_load_catalog();
    int totalFound = 0;
    for(int a = 0; a < g_appCount; a++) {
        g_apps[a].cveCount = 0;
        char nameLo[256], matchLo[128];
        int ni = 0;
        while(g_apps[a].name[ni] && ni < 255) {
            nameLo[ni] = (char)tolower((unsigned char)g_apps[a].name[ni]); ni++;
        }
        nameLo[ni] = '\0';

        for(int c = 0; c < g_cveDBCnt && g_apps[a].cveCount < 4; c++) {
            int mi = 0;
            while(g_cveDB[c].appMatch[mi] && mi < 127) {
                matchLo[mi] = (char)tolower((unsigned char)g_cveDB[c].appMatch[mi]); mi++;
            }
            matchLo[mi] = '\0';
            if(!strstr(nameLo, matchLo)) continue;

            /* An unknown version is unknown; it is not evidence of a vulnerability. */
            if(g_apps[a].version[0] && g_cveDB[c].vulnVerMax[0] &&
               upd_ver_cmp(g_apps[a].version, g_cveDB[c].vulnVerMax) <= 0) {
                int idx = g_apps[a].cveCount++;
                strncpy(g_apps[a].cveId[idx],    g_cveDB[c].cveId,    23);
                g_apps[a].cvssScore[idx] = g_cveDB[c].cvss;
                strncpy(g_apps[a].cveFixed[idx], g_cveDB[c].fixedVer, 63);
                if(g_cveDB[c].wingetId[0])
                    strncpy(g_apps[a].wingetId, g_cveDB[c].wingetId, 127);
                totalFound++;
            }
        }
    }
    return totalFound;
}

/* OS build findings require vendor/KB verification; no blind registry fixes are available. */
/* --- Apply update for one app via winget (WAITS for completion) ----------- */
static BOOL upd_apply_update(const char *wingetId) {
    if(!wingetId || !*wingetId) return FALSE;
    for (const unsigned char *p = (const unsigned char*)wingetId; *p; ++p)
        if (!(isalnum(*p) || *p == '.' || *p == '-' || *p == '_')) return FALSE;

    /* Check if winget is available */
    char params[768];
    snprintf(params, sizeof(params),
             "/c winget upgrade --id \"%s\" --silent --accept-package-agreements --accept-source-agreements --include-unknown -h 2>&1",
             wingetId);
    SHELLEXECUTEINFOA sei;
    ZeroMemory(&sei, sizeof(sei));
    sei.cbSize       = sizeof(sei);
    sei.lpVerb       = "runas";
    sei.lpFile       = "cmd.exe";
    sei.lpParameters = params;
    sei.fMask        = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NO_CONSOLE;
    sei.nShow        = SW_HIDE;
    if(!ShellExecuteExA(&sei)) return FALSE;
    DWORD exitCode = 1;
    DWORD waitResult = WaitForSingleObject(sei.hProcess, 90000);
    if(waitResult == WAIT_OBJECT_0) GetExitCodeProcess(sei.hProcess, &exitCode);
    else if(waitResult == WAIT_TIMEOUT) TerminateProcess(sei.hProcess, 1);
    CloseHandle(sei.hProcess);
    /* winget exit codes: 0=success, -1978335189=already installed latest, others=error */
    return (waitResult == WAIT_OBJECT_0 && exitCode == 0);
}

/* =========================================================================
 * REAL-TIME AUTO-FIX INFRASTRUCTURE
 * Uses callbacks to report progress line-by-line to the UI
 * ========================================================================= */
typedef void (*UpdProgressCb)(const char *line, int isError);

static UpdProgressCb g_updProgressCb = NULL;

static void upd_progress(const char *line, int isError) {
    if (g_updProgressCb) g_updProgressCb(line, isError);
}

/* --- Threaded auto-fix context ------------------------------------------- */
typedef struct {
    HWND hwndList;   /* listbox to post progress to */
    HWND hwndParent; /* parent window to notify when done */
    int  result;     /* total fixed */
} UpdFixContext;

static DWORD WINAPI upd_fixall_thread(LPVOID lpParam) {
    UpdFixContext *ctx = (UpdFixContext*)lpParam;
    HWND hList = ctx->hwndList;

    #define UPOST(msg) SendMessageA(hList, LB_INSERTSTRING, 0, (LPARAM)(msg))

    UPOST("  ============================================================");
    UPOST("  [KAEVEX AUTONOMOUS CVE REMEDIATION ENGINE v3.0]");
    UPOST("  ============================================================");

    /* Step 1: Refresh app inventory */
    UPOST("  [*] Phase 1: Refreshing installed software inventory...");
    int appCnt = upd_scan_installed();
    int cveCnt = upd_check_cves();

    char buf[400];
    snprintf(buf, sizeof(buf), "  [+] Inventory: %d applications audited, %d CVEs detected", appCnt, cveCnt);
    UPOST(buf);

    /* Step 2: Apply winget upgrades per vulnerable app */
    UPOST("  [*] Phase 2: Applying targeted software patches via winget...");
    int appsPatched = 0;
    int appsSkipped = 0;
    int appsFailed  = 0;
    int appsContained = 0;

    for (int i = 0; i < g_appCount; i++) {
        if (g_apps[i].cveCount > 0 && g_apps[i].wingetId[0]) {
            snprintf(buf, sizeof(buf), "  [>] Patching: %-38s [%s | CVSS %d]",
                     g_apps[i].name, g_apps[i].cveId[0], g_apps[i].cvssScore[0]);
            UPOST(buf);

            BOOL ok = upd_apply_update(g_apps[i].wingetId);
            if (ok) {
                snprintf(buf, sizeof(buf), "  [UPDATE OK] %-34s -> installer succeeded; rescan is needed to verify the CVE", g_apps[i].name);
                appsPatched++;
            } else {
                if(g_apps[i].executablePath[0] && fw_block_program(g_apps[i].executablePath)) {
                    snprintf(buf, sizeof(buf), "  [CONTAINED] %-32s -> all network traffic blocked by Windows Firewall; connectivity may stop", g_apps[i].name);
                    appsContained++;
                } else {
                    snprintf(buf, sizeof(buf), "  [WARN]  %-38s -> Upgrade and verified firewall containment failed", g_apps[i].name);
                    appsFailed++;
                }
            }
            UPOST(buf);
        } else if (g_apps[i].cveCount > 0) {
            if(g_apps[i].executablePath[0] && fw_block_program(g_apps[i].executablePath)) {
                snprintf(buf, sizeof(buf), "  [CONTAINED] %-32s -> no trusted package updater; all network traffic blocked", g_apps[i].name);
                UPOST(buf); appsContained++;
            } else {
                snprintf(buf, sizeof(buf), "  [SKIP] %-38s -> no verified update path or firewall containment for %s", g_apps[i].name, g_apps[i].cveId[0]);
                UPOST(buf); appsSkipped++;
            }
        }
    }

    /* Build ranges do not establish installed patch state; do not change OS policy on that evidence. */
    UPOST("  [*] OS build matches are advisory only. Verify installed KBs and vendor guidance; no OS policy was changed.");
    int osMitigated = 0;
    for (int i = 0; i < g_osInfo.cveCount; i++) {
        snprintf(buf, sizeof(buf), "  [REVIEW] %s -> %s", g_osInfo.cveId[i], g_osInfo.mitigation[i]);
        UPOST(buf);
    }

    /* Summary */
    int totalFixed = appsPatched + osMitigated;
    UPOST("  ============================================================");
    snprintf(buf, sizeof(buf), "  [DONE] Update commands successful (not CVE-verified): %d  |  Network-contained: %d  |  OS policy changes: %d (none automated)  |  Skipped: %d  |  Failed: %d",
             appsPatched, appsContained, osMitigated, appsSkipped, appsFailed);
    UPOST(buf);
    snprintf(buf, sizeof(buf), "  [DONE] OS build-range findings for manual review: %d (not counted as fixed)", g_osInfo.cveCount);
    UPOST(buf);
    UPOST("  ============================================================");

    ctx->result = totalFixed;

    /* Re-scan to refresh the UI */
    Sleep(1000);
    if (ctx->hwndParent)
        PostMessageA(ctx->hwndParent, WM_COMMAND, MAKEWPARAM(241, 0), 0); /* IDU_SCAN=241 */

    free(ctx);
    #undef UPOST
    return 0;
}

/* Launch auto-fix in background thread */
static void upd_auto_fix_all_async(HWND hList, HWND hParent) {
    UpdFixContext *ctx = (UpdFixContext*)malloc(sizeof(UpdFixContext));
    if (!ctx) return;
    ctx->hwndList   = hList;
    ctx->hwndParent = hParent;
    ctx->result     = 0;
    HANDLE hThread = CreateThread(NULL, 0, upd_fixall_thread, ctx, 0, NULL);
    if (hThread) CloseHandle(hThread);
    else free(ctx);
}

/* Synchronous version (kept for compatibility) */
static int upd_auto_fix_all(char *summaryOut, int maxLen) {
    int appsPatched = 0;
    int osMitigated = 0;

    for (int i = 0; i < g_appCount; i++) {
        if (g_apps[i].cveCount > 0 && g_apps[i].wingetId[0]) {
            if (upd_apply_update(g_apps[i].wingetId)) {
                appsPatched++;
            }
        }
    }

    if (summaryOut) {
        snprintf(summaryOut, maxLen,
                 "Update commands successful: %d; OS CVE build matches requiring manual patch verification: %d",
                 appsPatched, g_osInfo.cveCount);
    }
    return (appsPatched + osMitigated);
}

/* --- Continuous Background CVE Watcher ----------------------------------- */
static BOOL   g_cveWatcherActive = FALSE;
static HANDLE g_cveWatcherThread = NULL;
typedef void (*CveAlertCallback)(const char *eng, const char *sev, const char *msg);
static CveAlertCallback g_cveAlertCb = NULL;

static DWORD upd_cve_fingerprint(void) {
    DWORD h = 2166136261u;
    for (int i=0;i<g_appCount;i++) for (int c=0;c<g_apps[i].cveCount;c++) {
        const unsigned char *p=(const unsigned char*)g_apps[i].cveId[c];
        while(*p){h^=*p++;h*=16777619u;}
    }
    for (int i=0;i<g_osInfo.cveCount;i++) {
        const unsigned char *p=(const unsigned char*)g_osInfo.cveId[i];
        while(*p){h^=*p++;h*=16777619u;}
    }
    return h;
}

static DWORD WINAPI upd_watcher_proc(LPVOID lpParam) {
    (void)lpParam;
    int prevAppCount = g_appCount;
    int prevCves = -1;
    DWORD prevFingerprint = 0;
    while (g_cveWatcherActive) {
        Sleep(30000); /* Check every 30 seconds */
        if (!g_cveWatcherActive) break;

        int currentApps = upd_scan_installed();
        int cves = upd_check_cves();
        DWORD fingerprint = upd_cve_fingerprint();
        if ((currentApps != prevAppCount || cves != prevCves || fingerprint != prevFingerprint) && g_cveAlertCb) {
            char alertMsg[256];
            snprintf(alertMsg, sizeof(alertMsg),
                     "Local advisory catalog: %d installed apps, %d potential CVE version matches. Verify with the vendor; no fix was applied.",
                     currentApps, cves);
            g_cveAlertCb("CVE Watcher", cves > 0 ? "WARNING" : "INFO", alertMsg);
            prevAppCount = currentApps;
            prevCves = cves;
            prevFingerprint = fingerprint;
        }
    }
    return 0;
}

static void upd_start_cve_watcher(CveAlertCallback cb) {
    if (g_cveWatcherActive) return;
    g_cveAlertCb = cb;
    g_cveWatcherActive = TRUE;
    g_cveWatcherThread = CreateThread(NULL, 0, upd_watcher_proc, NULL, 0, NULL);
}

static void upd_stop_cve_watcher(void) {
    if (!g_cveWatcherActive) return;
    g_cveWatcherActive = FALSE;
    if (g_cveWatcherThread) {
        WaitForSingleObject(g_cveWatcherThread, 2000);
        CloseHandle(g_cveWatcherThread);
        g_cveWatcherThread = NULL;
    }
}

#endif /* UPD_ENGINE_H */
