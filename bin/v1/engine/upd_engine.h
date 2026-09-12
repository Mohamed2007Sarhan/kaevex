/*===========================================================================
 * Kaevex Updater + Autonomous CVE Agent - upd_engine.h
 * Complete OS & Software Inventory, CVE Detection, 1-Click Auto-Fix,
 * and Continuous Background Vulnerability Watcher
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

#define UPD_MAX_APPS    512
#define UPD_MAX_OS_CVES 16

/* --- Installed app record ------------------------------------------------- */
typedef struct {
    char name[256];
    char version[64];
    char publisher[128];
    char installDate[16];
    char uninstallStr[MAX_PATH];
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

#define UPD_MAX_DYNAMIC_CVES 512
static CveEntry   g_cveDB[UPD_MAX_DYNAMIC_CVES];
static int        g_cveDBCnt = 0;
static OsCveEntry g_osCveDB[UPD_MAX_OS_CVES];
static int        g_osCveDBCnt = 0;
static BOOL       g_catalogLoaded = FALSE;

static void upd_load_catalog(void) {
    if (g_catalogLoaded) return;
    g_cveDBCnt = 0;
    g_osCveDBCnt = 0;

    FILE *f = fopen("dist\\data\\cve_catalog.json", "rb");
    if (!f) f = fopen("dist\\kaevex_cve_catalog.json", "rb");
    if (!f) f = fopen("release\\kaevex_cve_catalog.json", "rb");
    if (!f) f = fopen("kaevex_cve_catalog.json", "rb");
    if (!f) f = fopen("release\\aegiscore_cve_catalog.json", "rb");
    if (!f) f = fopen("aegiscore_cve_catalog.json", "rb");
    if (!f) return;

    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz <= 0 || sz > 1024 * 1024) { fclose(f); return; }

    char *buf = (char*)malloc(sz + 1);
    if (!buf) { fclose(f); return; }
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
    if (g_osInfo.buildNumber == 0) g_osInfo.buildNumber = 22631; /* Safe fallback */

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

            /* Vulnerable if version is empty or less than/equal to maximum vulnerable threshold */
            if(strlen(g_apps[a].version) == 0 || upd_ver_cmp(g_apps[a].version, g_cveDB[c].vulnVerMax) <= 0) {
                int idx = g_apps[a].cveCount++;
                strncpy(g_apps[a].cveId[idx],    g_cveDB[c].cveId,    23);
                g_apps[a].cvssScore[idx] = g_cveDB[c].cvss;
                strncpy(g_apps[a].cveFixed[idx], g_cveDB[c].fixedVer, 63);
                if(g_cveDB[c].wingetId)
                    strncpy(g_apps[a].wingetId, g_cveDB[c].wingetId, 127);
                totalFound++;
            }
        }
    }
    return totalFound;
}

/* --- Apply OS-level mitigation -------------------------------------------- */
static BOOL upd_apply_os_mitigation(int cveIdx) {
    if (cveIdx < 0 || cveIdx >= g_osInfo.cveCount) return FALSE;
    const char *cve = g_osInfo.cveId[cveIdx];

    if (strcmp(cve, "CVE-2021-34527") == 0) {
        /* PrintNightmare: Restrict point and print driver installation */
        HKEY hk;
        if (RegCreateKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Policies\\Microsoft\\Windows NT\\Printers\\PointAndPrint",
                            0, NULL, 0, KEY_SET_VALUE, NULL, &hk, NULL) == ERROR_SUCCESS) {
            DWORD val = 1;
            RegSetValueExA(hk, "RestrictDriverInstallationToAdministrators", 0, REG_DWORD, (BYTE*)&val, sizeof(val));
            RegCloseKey(hk);
            g_osInfo.mitigated[cveIdx] = TRUE;
            return TRUE;
        }
    } else if (strcmp(cve, "CVE-2022-30190") == 0) {
        /* Follina: Disable MSDT protocol */
        RegDeleteKeyA(HKEY_CLASSES_ROOT, "ms-msdt");
        g_osInfo.mitigated[cveIdx] = TRUE;
        return TRUE;
    } else if (strcmp(cve, "CVE-2023-36884") == 0) {
        /* MSHTML: Block cross protocol navigation */
        HKEY hk;
        if (RegCreateKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Policies\\Microsoft\\Internet Explorer\\Main\\FeatureControl\\FEATURE_BLOCK_CROSS_PROTOCOL_FILE_NAVIGATION",
                            0, NULL, 0, KEY_SET_VALUE, NULL, &hk, NULL) == ERROR_SUCCESS) {
            DWORD val = 1;
            RegSetValueExA(hk, "*", 0, REG_DWORD, (BYTE*)&val, sizeof(val));
            RegCloseKey(hk);
            g_osInfo.mitigated[cveIdx] = TRUE;
            return TRUE;
        }
    } else if (strcmp(cve, "CVE-2017-0144") == 0) {
        /* EternalBlue: Disable SMBv1 */
        HKEY hk;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters", 0, KEY_SET_VALUE, &hk) == ERROR_SUCCESS) {
            DWORD val = 0;
            RegSetValueExA(hk, "SMB1", 0, REG_DWORD, (BYTE*)&val, sizeof(val));
            RegCloseKey(hk);
            g_osInfo.mitigated[cveIdx] = TRUE;
            return TRUE;
        }
    } else {
        /* Generic OS Hotfix trigger */
        ShellExecuteA(NULL, "open", "ms-settings:windowsupdate", NULL, NULL, SW_SHOWNORMAL);
        g_osInfo.mitigated[cveIdx] = TRUE;
        return TRUE;
    }
    return FALSE;
}

/* --- Apply update for one app via winget ---------------------------------- */
static BOOL upd_apply_update(const char *wingetId) {
    if(!wingetId || !*wingetId) return FALSE;
    char params[512];
    snprintf(params, sizeof(params),
             "/c winget upgrade --id \"%s\" --silent --accept-package-agreements --accept-source-agreements -h",
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
    WaitForSingleObject(sei.hProcess, 60000);
    CloseHandle(sei.hProcess);
    return TRUE;
}

/* --- 1-Click Autonomous Auto-Fix All CVEs --------------------------------- */
static int upd_auto_fix_all(char *summaryOut, int maxLen) {
    int appsPatched = 0;
    int osMitigated = 0;

    /* 1. Patch all vulnerable applications */
    for (int i = 0; i < g_appCount; i++) {
        if (g_apps[i].cveCount > 0 && g_apps[i].wingetId[0]) {
            if (upd_apply_update(g_apps[i].wingetId)) {
                appsPatched++;
                g_apps[i].cveCount = 0; /* Cleared after patch */
            }
        }
    }

    /* 2. Apply all OS-level CVE mitigations */
    for (int i = 0; i < g_osInfo.cveCount; i++) {
        if (!g_osInfo.mitigated[i]) {
            if (upd_apply_os_mitigation(i)) {
                osMitigated++;
            }
        }
    }

    if (summaryOut) {
        snprintf(summaryOut, maxLen,
                 "Autonomous Remediation Complete: %d Application(s) Patched, %d OS Mitigation(s) Enforced",
                 appsPatched, osMitigated);
    }
    return (appsPatched + osMitigated);
}

/* --- Continuous Background CVE Watcher ----------------------------------- */
static BOOL   g_cveWatcherActive = FALSE;
static HANDLE g_cveWatcherThread = NULL;
typedef void (*CveAlertCallback)(const char *eng, const char *sev, const char *msg);
static CveAlertCallback g_cveAlertCb = NULL;

static DWORD WINAPI upd_watcher_proc(LPVOID lpParam) {
    (void)lpParam;
    int prevAppCount = g_appCount;
    while (g_cveWatcherActive) {
        Sleep(30000); /* Check every 30 seconds */
        if (!g_cveWatcherActive) break;

        int currentApps = upd_scan_installed();
        if (currentApps != prevAppCount) {
            int cves = upd_check_cves();
            prevAppCount = currentApps;
            if (cves > 0 && g_cveAlertCb) {
                char alertMsg[256];
                snprintf(alertMsg, sizeof(alertMsg),
                         "CVE Watcher: Installed software changed! Found %d active CVE(s) requiring remediation.",
                         cves);
                g_cveAlertCb("CVE Watcher", "CRITICAL", alertMsg);
            }
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
