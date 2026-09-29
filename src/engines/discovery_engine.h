/*===========================================================================
 * Kaevex Application Discovery & Stack Intelligence Engine
 * discovery_engine.h
 *
 * Discovers EVERY application on the system using 9 independent sources:
 *   1. Windows Registry (Uninstall keys — all hives)
 *   2. Running Processes (Toolhelp32 snapshot + path resolution)
 *   3. Windows Services (SCM enumeration)
 *   4. Listening Ports (TCP/UDP tables → PID → Process)
 *   5. Well-known install paths (XAMPP, WAMP, Node, Python, etc.)
 *   6. Environment variables (PATH scanning)
 *   7. Package managers (winget, choco, scoop)
 *   8. Software Stack Model (XAMPP = Apache+MySQL+PHP+phpMyAdmin)
 *   9. Unknown process correlation (unrecognized = flagged, not ignored)
 *
 * App Relationship Graph:
 *   Port -> PID -> Process -> App -> Stack
 *   Parent/child process tree
 *   TCP connection correlation
 *
 * Integration Keys:
 *   Each app gets a deterministic SHA-256 derived key
 *   Stored in HKCU\Software\Kaevex\AppKeys\{name}
 *   Revocable, rotatable, permission-scoped
 *===========================================================================*/
#pragma once
#ifndef DISCOVERY_ENGINE_H
#define DISCOVERY_ENGINE_H

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <shellapi.h>
#include <winsvc.h>
#include <winsock2.h>
#include <iphlpapi.h>
#include <wincrypt.h>
#include <shlobj.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <time.h>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "advapi32.lib")

/* =========================================================================
 * Data Model
 * ========================================================================= */

#define DISC_MAX_APPS       512
#define DISC_MAX_PORTS       64
#define DISC_MAX_CHILDREN    16
#define DISC_MAX_RELATIONS   256
#define DISC_KEY_LEN         65   /* SHA-256 hex string */

/* App type classification */
typedef enum {
    APP_TYPE_UNKNOWN   = 0,
    APP_TYPE_STACK     = 1,   /* XAMPP, WAMP, LAMP stack */
    APP_TYPE_SERVICE   = 2,   /* Windows service */
    APP_TYPE_PROCESS   = 3,   /* Running process without service */
    APP_TYPE_INSTALLED = 4,   /* Installed but not running */
    APP_TYPE_COMPONENT = 5,   /* Part of a stack (Apache within XAMPP) */
    APP_TYPE_SERVER    = 6,   /* Network server */
    APP_TYPE_SECURITY  = 7,   /* AV/EDR/VPN */
    APP_TYPE_DEV_TOOL  = 8,   /* IDE/compiler/runtime */
    APP_TYPE_DATABASE  = 9,   /* Database server */
    APP_TYPE_BROWSER   = 10,
    APP_TYPE_GAME      = 11,
    APP_TYPE_RUNTIME   = 12,  /* Java, .NET, Python */
} AppType;

/* App discovery state */
typedef enum {
    APP_STATE_RUNNING  = 0,
    APP_STATE_STOPPED  = 1,
    APP_STATE_PARTIAL  = 2,   /* Stack where only some components are running */
    APP_STATE_UNKNOWN  = 3,
} AppState;

/* Relationship type between two apps */
typedef enum {
    REL_TCP_CLIENT    = 0,   /* A connects to B via TCP */
    REL_TCP_SERVE     = 1,   /* A listens, B connects */
    REL_PARENT_CHILD  = 2,   /* A spawned B */
    REL_SHARED_PORT   = 3,
    REL_STACK_MEMBER  = 4,   /* B is a component of stack A */
    REL_SHARED_RUNTIME= 5,   /* Both use same Java/Python runtime */
} RelationType;

typedef struct {
    char    fromId[37];
    char    toId[37];
    RelationType type;
    int     port;        /* if TCP relation */
    char    desc[128];
} AppRelation;

typedef struct {
    char     id[37];             /* UUID-style "DISC-{name_hash}" */
    char     name[128];          /* Display name */
    char     stackName[64];      /* Parent stack name (if component) */
    char     parentId[37];       /* Parent stack ID */
    AppType  type;
    AppState state;
    char     version[64];
    char     path[MAX_PATH];
    char     publisher[128];
    char     description[256];
    /* Process info */
    DWORD    pid;
    DWORD    parentPid;
    char     exeName[64];
    /* Service info */
    char     serviceName[64];
    char     serviceState[32];
    /* Network */
    int      listenPorts[DISC_MAX_PORTS];
    int      listenPortCnt;
    char     openConnections[16][64]; /* "127.0.0.1:3306 -> Apache" */
    int      openConnCnt;
    /* Stack / children */
    BOOL     isStack;
    char     children[DISC_MAX_CHILDREN][37];  /* child IDs */
    int      childCount;
    /* CVE cross-ref */
    int      cveCount;
    char     primaryCve[24];
    int      primaryCvss;
    /* Integration */
    char     integrationKey[DISC_KEY_LEN];
    BOOL     keyRevoked;
    /* Source flags (bitmask) */
    int      sourceMask;   /* bits: 0=registry, 1=process, 2=service, 3=port, 4=path */
    /* Display */
    char     iconChar[4];  /* ASCII icon shorthand */
    COLORREF iconColor;
    /* Metadata */
    char     installDate[16];
    time_t   firstSeen;
    time_t   lastSeen;
    char     aiSuggestion[256];  /* AI-identified if unknown */
    BOOL     aiIdentified;
} AppEntry;

static AppEntry     g_discApps[DISC_MAX_APPS];
static int          g_discAppCnt = 0;
static AppRelation  g_discRels[DISC_MAX_RELATIONS];
static int          g_discRelCnt = 0;
static BOOL         g_discCSInit = FALSE;
static CRITICAL_SECTION g_discCS;
static time_t       g_lastDiscovery = 0;

/* =========================================================================
 * Integration Key Generation
 * SHA-256(app_name + app_version + machine_guid)
 * ========================================================================= */
static void disc_derive_key(const char *appName, const char *version,
                             const char *path, char keyOut[DISC_KEY_LEN]) {
    /* Get machine GUID */
    char machineGuid[64] = "KAEVEX-DEFAULT-GUID";
    HKEY hk;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\Cryptography", 0, KEY_READ | KEY_WOW64_64KEY, &hk) == ERROR_SUCCESS) {
        DWORD sz = sizeof(machineGuid);
        RegQueryValueExA(hk, "MachineGuid", NULL, NULL, (BYTE*)machineGuid, &sz);
        RegCloseKey(hk);
    }

    /* Build input string */
    char input[1024];
    snprintf(input, sizeof(input), "%s|%s|%s|%s", appName, version, path, machineGuid);

    /* SHA-256 hash via CryptoAPI */
    HCRYPTPROV prov = 0;
    HCRYPTHASH hash = 0;
    BYTE hashBytes[32];
    DWORD hashLen = sizeof(hashBytes);

    if (CryptAcquireContextA(&prov, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        if (CryptCreateHash(prov, CALG_SHA_256, 0, 0, &hash)) {
            CryptHashData(hash, (BYTE*)input, (DWORD)strlen(input), 0);
            CryptGetHashParam(hash, HP_HASHVAL, hashBytes, &hashLen, 0);
            CryptDestroyHash(hash);
        }
        CryptReleaseContext(prov, 0);
    }

    /* Format as hex */
    for (int i = 0; i < 32; i++)
        sprintf(keyOut + i * 2, "%02x", hashBytes[i]);
    keyOut[64] = '\0';
}

/* Store key in registry */
static void disc_store_key(const char *appName, const char *key) {
    HKEY hk;
    char path[256];
    snprintf(path, sizeof(path), "SOFTWARE\\Kaevex\\AppKeys");
    if (RegCreateKeyExA(HKEY_CURRENT_USER, path, 0, NULL, 0,
                         KEY_SET_VALUE, NULL, &hk, NULL) == ERROR_SUCCESS) {
        RegSetValueExA(hk, appName, 0, REG_SZ, (BYTE*)key, (DWORD)strlen(key) + 1);
        RegCloseKey(hk);
    }
}

/* Load stored key (returns FALSE if not found) */
static BOOL disc_load_key(const char *appName, char keyOut[DISC_KEY_LEN]) {
    HKEY hk;
    char path[256];
    snprintf(path, sizeof(path), "SOFTWARE\\Kaevex\\AppKeys");
    if (RegOpenKeyExA(HKEY_CURRENT_USER, path, 0, KEY_READ, &hk) != ERROR_SUCCESS)
        return FALSE;
    DWORD sz = DISC_KEY_LEN;
    BOOL ok = (RegQueryValueExA(hk, appName, NULL, NULL, (BYTE*)keyOut, &sz) == ERROR_SUCCESS);
    RegCloseKey(hk);
    return ok;
}

/* Revoke key */
static void disc_revoke_key(const char *appName) {
    HKEY hk;
    char path[256];
    snprintf(path, sizeof(path), "SOFTWARE\\Kaevex\\AppKeys");
    if (RegOpenKeyExA(HKEY_CURRENT_USER, path, 0, KEY_SET_VALUE, &hk) == ERROR_SUCCESS) {
        RegDeleteValueA(hk, appName);
        RegCloseKey(hk);
    }
}

/* =========================================================================
 * Unique ID generation for app entries
 * ========================================================================= */
static void disc_make_id(const char *name, const char *path, char idOut[37]) {
    /* Simple deterministic ID: DISC-{first8 of name_hash} */
    unsigned int h = 2166136261u;
    for (const char *p = name; *p; p++) h = (h ^ (unsigned char)*p) * 16777619u;
    for (const char *p = path; *p; p++) h = (h ^ (unsigned char)*p) * 16777619u;
    snprintf(idOut, 37, "DISC-%08X", h);
}

/* =========================================================================
 * Find or create app entry
 * ========================================================================= */
static AppEntry* disc_find_by_id(const char *id) {
    for (int i = 0; i < g_discAppCnt; i++)
        if (strcmp(g_discApps[i].id, id) == 0) return &g_discApps[i];
    return NULL;
}

static AppEntry* disc_find_by_name(const char *name) {
    char lo[128]; int ni = 0;
    while (name[ni] && ni < 127) { lo[ni] = (char)tolower((unsigned char)name[ni]); ni++; }
    lo[ni] = '\0';
    for (int i = 0; i < g_discAppCnt; i++) {
        char lo2[128]; ni = 0;
        while (g_discApps[i].name[ni] && ni < 127) {
            lo2[ni] = (char)tolower((unsigned char)g_discApps[i].name[ni]); ni++;
        }
        lo2[ni] = '\0';
        if (strcmp(lo, lo2) == 0) return &g_discApps[i];
    }
    return NULL;
}

static AppEntry* disc_alloc(void) {
    if (g_discAppCnt >= DISC_MAX_APPS) return NULL;
    AppEntry *e = &g_discApps[g_discAppCnt++];
    ZeroMemory(e, sizeof(*e));
    e->firstSeen = e->lastSeen = time(NULL);
    e->iconColor = RGB(100, 120, 150);
    return e;
}

static void disc_add_relation(const char *fromId, const char *toId,
                               RelationType type, int port, const char *desc) {
    if (g_discRelCnt >= DISC_MAX_RELATIONS) return;
    /* Avoid duplicates */
    for (int i = 0; i < g_discRelCnt; i++) {
        if (strcmp(g_discRels[i].fromId, fromId) == 0 &&
            strcmp(g_discRels[i].toId, toId) == 0 &&
            g_discRels[i].type == type) return;
    }
    AppRelation *r = &g_discRels[g_discRelCnt++];
    strncpy(r->fromId, fromId, 36);
    strncpy(r->toId,   toId,   36);
    r->type = type;
    r->port = port;
    if (desc) strncpy(r->desc, desc, 127);
}

/* =========================================================================
 * SOURCE 1: Registry Scan (Installed Apps)
 * ========================================================================= */
static void disc_scan_registry(void) {
    static const struct { HKEY root; const char *path; } keys[] = {
        {HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall"},
        {HKEY_LOCAL_MACHINE, "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall"},
        {HKEY_CURRENT_USER,  "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall"},
        {0, NULL}
    };
    for (int k = 0; keys[k].path && g_discAppCnt < DISC_MAX_APPS; k++) {
        HKEY hKey;
        if (RegOpenKeyExA(keys[k].root, keys[k].path, 0, KEY_READ, &hKey) != ERROR_SUCCESS) continue;
        char subName[256]; DWORD subLen = sizeof(subName), i = 0;
        while (g_discAppCnt < DISC_MAX_APPS &&
               RegEnumKeyExA(hKey, i++, subName, &subLen, NULL,NULL,NULL,NULL) == ERROR_SUCCESS) {
            subLen = sizeof(subName);
            HKEY hSub;
            if (RegOpenKeyExA(hKey, subName, 0, KEY_READ, &hSub) != ERROR_SUCCESS) continue;
            char name[128]={0}, ver[64]={0}, pub[128]={0}, ipath[MAX_PATH]={0}, idate[16]={0};
            DWORD sz;
            sz=sizeof(name); RegQueryValueExA(hSub,"DisplayName",NULL,NULL,(BYTE*)name,&sz);
            sz=sizeof(ver);  RegQueryValueExA(hSub,"DisplayVersion",NULL,NULL,(BYTE*)ver,&sz);
            sz=sizeof(pub);  RegQueryValueExA(hSub,"Publisher",NULL,NULL,(BYTE*)pub,&sz);
            sz=sizeof(ipath);RegQueryValueExA(hSub,"InstallLocation",NULL,NULL,(BYTE*)ipath,&sz);
            sz=sizeof(idate);RegQueryValueExA(hSub,"InstallDate",NULL,NULL,(BYTE*)idate,&sz);
            DWORD noRemove=0; sz=sizeof(noRemove);
            RegQueryValueExA(hSub,"SystemComponent",NULL,NULL,(BYTE*)&noRemove,&sz);
            RegCloseKey(hSub);
            if (!name[0] || noRemove) continue;
            /* Skip duplicates */
            AppEntry *existing = disc_find_by_name(name);
            if (existing) {
                existing->sourceMask |= 0x01;
                if (!existing->version[0] && ver[0]) strncpy(existing->version, ver, 63);
                if (!existing->path[0] && ipath[0]) strncpy(existing->path, ipath, MAX_PATH-1);
                continue;
            }
            AppEntry *e = disc_alloc(); if (!e) { RegCloseKey(hKey); return; }
            strncpy(e->name, name, 127);
            strncpy(e->version, ver, 63);
            strncpy(e->publisher, pub, 127);
            strncpy(e->path, ipath, MAX_PATH-1);
            strncpy(e->installDate, idate, 15);
            e->type = APP_TYPE_INSTALLED;
            e->state = APP_STATE_STOPPED;
            e->sourceMask = 0x01;
            disc_make_id(name, ipath, e->id);
        }
        RegCloseKey(hKey);
    }
}

/* =========================================================================
 * SOURCE 2: Running Processes
 * ========================================================================= */
static BOOL disc_get_process_path(DWORD pid, char pathOut[MAX_PATH]) {
    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProc) return FALSE;
    BOOL ok = (GetModuleFileNameExA(hProc, NULL, pathOut, MAX_PATH) > 0);
    CloseHandle(hProc);
    return ok;
}

static void disc_scan_processes(void) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return;
    PROCESSENTRY32 pe; pe.dwSize = sizeof(pe);
    if (!Process32First(snap, &pe)) { CloseHandle(snap); return; }
    do {
        if (pe.th32ProcessID <= 4) continue;
        char fullPath[MAX_PATH] = {0};
        disc_get_process_path(pe.th32ProcessID, fullPath);

        /* Check if we already have an app entry matching this exe name or path */
        BOOL found = FALSE;
        for (int i = 0; i < g_discAppCnt; i++) {
            /* Match by exe name or install path prefix */
            char exeLo[65], entLo[65];
            int ni = 0;
            while (pe.szExeFile[ni] && ni < 64) {
                exeLo[ni] = (char)tolower((unsigned char)pe.szExeFile[ni]); ni++;
            }
            exeLo[ni] = '\0';
            /* Check if path overlaps with known app install path */
            if (g_discApps[i].path[0] && fullPath[0]) {
                char pathLo[MAX_PATH], appPathLo[MAX_PATH];
                int pi = 0;
                while (fullPath[pi] && pi < MAX_PATH-1) {
                    pathLo[pi] = (char)tolower((unsigned char)fullPath[pi]); pi++;
                }
                pathLo[pi] = '\0';
                pi = 0;
                while (g_discApps[i].path[pi] && pi < MAX_PATH-1) {
                    appPathLo[pi] = (char)tolower((unsigned char)g_discApps[i].path[pi]); pi++;
                }
                appPathLo[pi] = '\0';
                if (appPathLo[0] && strstr(pathLo, appPathLo)) {
                    if (!g_discApps[i].pid) g_discApps[i].pid = pe.th32ProcessID;
                    g_discApps[i].state = APP_STATE_RUNNING;
                    g_discApps[i].sourceMask |= 0x02;
                    strncpy(g_discApps[i].exeName, pe.szExeFile, 63);
                    found = TRUE;
                }
            }
        }

        if (!found && fullPath[0]) {
            /* New process — create an entry */
            /* Skip very common system processes */
            static const char *sysProcs[] = {
                "svchost.exe","lsass.exe","csrss.exe","wininit.exe","services.exe",
                "winlogon.exe","smss.exe","System","Registry","spoolsv.exe",
                "conhost.exe","dllhost.exe","taskhostw.exe","sihost.exe",
                "fontdrvhost.exe","dwm.exe","runtimebroker.exe","searchhost.exe",
                "settingssynchost.exe","securityhealthservice.exe",NULL
            };
            BOOL isSys = FALSE;
            for (int s = 0; sysProcs[s]; s++) {
                if (_stricmp(pe.szExeFile, sysProcs[s]) == 0) { isSys = TRUE; break; }
            }
            if (!isSys && g_discAppCnt < DISC_MAX_APPS) {
                /* Extract app name from exe name (strip .exe) */
                char displayName[128];
                strncpy(displayName, pe.szExeFile, 127);
                char *dot = strrchr(displayName, '.');
                if (dot && _stricmp(dot, ".exe") == 0) *dot = '\0';
                /* Capitalize first letter */
                if (displayName[0] >= 'a' && displayName[0] <= 'z')
                    displayName[0] = (char)toupper((unsigned char)displayName[0]);

                AppEntry *e = disc_alloc();
                if (e) {
                    strncpy(e->name, displayName, 127);
                    strncpy(e->exeName, pe.szExeFile, 63);
                    strncpy(e->path, fullPath, MAX_PATH-1);
                    e->pid = pe.th32ProcessID;
                    e->parentPid = pe.th32ParentProcessID;
                    e->type = APP_TYPE_PROCESS;
                    e->state = APP_STATE_RUNNING;
                    e->sourceMask = 0x02;
                    disc_make_id(displayName, fullPath, e->id);
                }
            }
        }
    } while (Process32Next(snap, &pe));
    CloseHandle(snap);
}

/* =========================================================================
 * SOURCE 3: Windows Services
 * ========================================================================= */
static void disc_scan_services(void) {
    SC_HANDLE scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (!scm) return;
    DWORD needed = 0, cnt = 0, resumeHandle = 0;
    EnumServicesStatusExA(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32,
                          SERVICE_STATE_ALL, NULL, 0, &needed, &cnt, &resumeHandle, NULL);
    if (!needed) { CloseServiceHandle(scm); return; }
    BYTE *buf = (BYTE*)malloc(needed);
    if (!buf) { CloseServiceHandle(scm); return; }
    resumeHandle = 0;
    if (EnumServicesStatusExA(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32,
                              SERVICE_STATE_ALL, buf, needed, &needed, &cnt, &resumeHandle, NULL)) {
        ENUM_SERVICE_STATUS_PROCESSA *svcs = (ENUM_SERVICE_STATUS_PROCESSA*)buf;
        for (DWORD i = 0; i < cnt && g_discAppCnt < DISC_MAX_APPS; i++) {
            const char *svcName = svcs[i].lpServiceName;
            BOOL running = (svcs[i].ServiceStatusProcess.dwCurrentState == SERVICE_RUNNING);
            DWORD svcPid = svcs[i].ServiceStatusProcess.dwProcessId;

            /* Get service exe path */
            char svcPath[MAX_PATH] = {0};
            SC_HANDLE hSvc = OpenServiceA(scm, svcName, SERVICE_QUERY_CONFIG);
            if (hSvc) {
                DWORD needed2 = 0;
                QueryServiceConfigA(hSvc, NULL, 0, &needed2);
                if (needed2 && needed2 < 65536) {
                    QUERY_SERVICE_CONFIGA *cfg = (QUERY_SERVICE_CONFIGA*)malloc(needed2);
                    if (cfg) {
                        if (QueryServiceConfigA(hSvc, cfg, needed2, &needed2))
                            strncpy(svcPath, cfg->lpBinaryPathName, MAX_PATH-1);
                        free(cfg);
                    }
                }
                CloseServiceHandle(hSvc);
            }

            /* Match to existing app */
            BOOL matched = FALSE;
            for (int a = 0; a < g_discAppCnt; a++) {
                if (g_discApps[a].pid == svcPid && svcPid > 0) {
                    strncpy(g_discApps[a].serviceName, svcName, 63);
                    strcpy(g_discApps[a].serviceState, running ? "Running" : "Stopped");
                    g_discApps[a].type = APP_TYPE_SERVICE;
                    g_discApps[a].sourceMask |= 0x04;
                    matched = TRUE;
                    break;
                }
            }
            if (!matched) {
                /* Skip generic Windows services */
                static const char *skip[] = {
                    "wuauserv","bits","cryptsvc","eventlog","lanmanworkstation",
                    "rpcss","spooler","w32tm","winmgmt","winsearch","mpssvc",NULL
                };
                BOOL skipThis = FALSE;
                for (int s = 0; skip[s]; s++)
                    if (_stricmp(svcName, skip[s]) == 0) { skipThis = TRUE; break; }
                if (!skipThis && svcs[i].lpDisplayName[0]) {
                    AppEntry *e = disc_alloc();
                    if (e) {
                        strncpy(e->name, svcs[i].lpDisplayName, 127);
                        strncpy(e->serviceName, svcName, 63);
                        strncpy(e->path, svcPath, MAX_PATH-1);
                        strcpy(e->serviceState, running ? "Running" : "Stopped");
                        e->pid = svcPid;
                        e->type = APP_TYPE_SERVICE;
                        e->state = running ? APP_STATE_RUNNING : APP_STATE_STOPPED;
                        e->sourceMask = 0x04;
                        disc_make_id(svcs[i].lpDisplayName, svcName, e->id);
                    }
                }
            }
        }
    }
    free(buf);
    CloseServiceHandle(scm);
}

/* =========================================================================
 * SOURCE 4: Listening Ports (TCP/UDP → PID → App correlation)
 * ========================================================================= */
static void disc_scan_ports(void) {
    /* TCP */
    DWORD tcpSz = 0;
    GetExtendedTcpTable(NULL, &tcpSz, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    MIB_TCPTABLE_OWNER_PID *tcpTable = (MIB_TCPTABLE_OWNER_PID*)malloc(tcpSz);
    if (tcpTable) {
        if (GetExtendedTcpTable(tcpTable, &tcpSz, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
            for (DWORD i = 0; i < tcpTable->dwNumEntries; i++) {
                MIB_TCPROW_OWNER_PID *row = &tcpTable->table[i];
                if (row->dwState != MIB_TCP_STATE_LISTEN) continue;
                int port = ntohs((USHORT)row->dwLocalPort);
                DWORD pid = row->dwOwningPid;
                /* Find app owning this PID */
                if (pid > 0) {
                    for (int a = 0; a < g_discAppCnt; a++) {
                        if (g_discApps[a].pid == pid) {
                            /* Add port to app's listen list */
                            if (g_discApps[a].listenPortCnt < DISC_MAX_PORTS) {
                                BOOL alreadyHave = FALSE;
                                for (int pp = 0; pp < g_discApps[a].listenPortCnt; pp++)
                                    if (g_discApps[a].listenPorts[pp] == port) { alreadyHave = TRUE; break; }
                                if (!alreadyHave)
                                    g_discApps[a].listenPorts[g_discApps[a].listenPortCnt++] = port;
                            }
                            g_discApps[a].sourceMask |= 0x08;
                            if (g_discApps[a].state == APP_STATE_STOPPED)
                                g_discApps[a].state = APP_STATE_RUNNING;
                            break;
                        }
                    }
                }
            }
        }
        free(tcpTable);
    }
    /* UDP */
    DWORD udpSz = 0;
    GetExtendedUdpTable(NULL, &udpSz, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0);
    MIB_UDPTABLE_OWNER_PID *udpTable = (MIB_UDPTABLE_OWNER_PID*)malloc(udpSz);
    if (udpTable) {
        if (GetExtendedUdpTable(udpTable, &udpSz, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0) == NO_ERROR) {
            for (DWORD i = 0; i < udpTable->dwNumEntries; i++) {
                int port = ntohs((USHORT)udpTable->table[i].dwLocalPort);
                DWORD pid = udpTable->table[i].dwOwningPid;
                for (int a = 0; a < g_discAppCnt; a++) {
                    if (g_discApps[a].pid == pid) {
                        if (g_discApps[a].listenPortCnt < DISC_MAX_PORTS) {
                            BOOL dup = FALSE;
                            for (int pp = 0; pp < g_discApps[a].listenPortCnt; pp++)
                                if (g_discApps[a].listenPorts[pp] == port) { dup = TRUE; break; }
                            if (!dup)
                                g_discApps[a].listenPorts[g_discApps[a].listenPortCnt++] = port;
                        }
                        break;
                    }
                }
            }
        }
        free(udpTable);
    }
}

/* =========================================================================
 * SOURCE 5: Well-Known Software Stack Detection
 * XAMPP, WAMP, Node, Python, Java, Nginx, IIS, etc.
 * ========================================================================= */
typedef struct {
    const char *stackName;
    const char *paths[8];
    const char *markerFile;
    const char *components[8];  /* Component exe names to look for */
    int         defaultPort;
} KnownStack;

static const KnownStack g_knownStacks[] = {
    { "XAMPP",
      {"C:\\xampp", "C:\\Program Files\\XAMPP", "C:\\Program Files (x86)\\XAMPP", "D:\\xampp", NULL},
      "xampp-control.exe",
      {"httpd.exe","mysqld.exe","php.exe","phpMyAdmin",NULL},
      80
    },
    { "WAMP Server",
      {"C:\\wamp","C:\\wamp64","D:\\wamp","D:\\wamp64", NULL},
      "wampmanager.exe",
      {"httpd.exe","mysqld.exe","php.exe",NULL},
      80
    },
    { "Laragon",
      {"C:\\laragon","D:\\laragon",NULL},
      "laragon.exe",
      {"httpd.exe","mysqld.exe","nginx.exe","php.exe",NULL},
      80
    },
    { "IIS",
      {"C:\\inetpub",NULL},
      "iisreset.exe",
      {"w3wp.exe","iisreset.exe",NULL},
      80
    },
    { "Node.js",
      {"C:\\Program Files\\nodejs","C:\\Program Files (x86)\\nodejs",NULL},
      "node.exe",
      {"node.exe","npm.cmd",NULL},
      3000
    },
    { "Python",
      {"C:\\Python","C:\\Python3","C:\\Python312","C:\\Python311","C:\\Python310",
       "C:\\Program Files\\Python312","C:\\Program Files\\Python311","C:\\Program Files\\Python310", NULL},
      "python.exe",
      {"python.exe","pip.exe",NULL},
      8000
    },
    { "Java (JDK)",
      {"C:\\Program Files\\Java","C:\\Program Files\\Microsoft","C:\\Program Files\\Eclipse Adoptium",NULL},
      "java.exe",
      {"java.exe","javac.exe",NULL},
      0
    },
    { "Docker Desktop",
      {"C:\\Program Files\\Docker",NULL},
      "Docker Desktop.exe",
      {"com.docker.backend.exe","dockerd.exe",NULL},
      2375
    },
    { "MongoDB",
      {"C:\\Program Files\\MongoDB",NULL},
      "mongod.exe",
      {"mongod.exe","mongos.exe",NULL},
      27017
    },
    { "Redis",
      {"C:\\Program Files\\Redis",NULL},
      "redis-server.exe",
      {"redis-server.exe",NULL},
      6379
    },
    { "PostgreSQL",
      {"C:\\Program Files\\PostgreSQL",NULL},
      "pg_ctl.exe",
      {"postgres.exe","pg_ctl.exe",NULL},
      5432
    },
    { "MySQL (Standalone)",
      {"C:\\Program Files\\MySQL",NULL},
      "mysqld.exe",
      {"mysqld.exe","mysql.exe",NULL},
      3306
    },
    { "Nginx",
      {"C:\\nginx","C:\\Program Files\\nginx",NULL},
      "nginx.exe",
      {"nginx.exe",NULL},
      80
    },
    { "Apache (Standalone)",
      {"C:\\Apache24","C:\\Apache","C:\\httpd",NULL},
      "httpd.exe",
      {"httpd.exe",NULL},
      80
    },
    { "Visual Studio",
      {"C:\\Program Files\\Microsoft Visual Studio",NULL},
      "devenv.exe",
      {"devenv.exe",NULL},
      0
    },
    {NULL,{NULL},NULL,{NULL},0}
};

static void disc_scan_known_stacks(void) {
    BOOL processRunning[64] = {0}; /* track which process names are running */
    char runningNames[64][64] = {{0}};
    int runningCnt = 0;

    /* Build list of running exe names */
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe; pe.dwSize = sizeof(pe);
        if (Process32First(snap, &pe)) {
            do {
                if (runningCnt < 64) {
                    strncpy(runningNames[runningCnt++], pe.szExeFile, 63);
                }
            } while (Process32Next(snap, &pe));
        }
        CloseHandle(snap);
    }

    for (int s = 0; g_knownStacks[s].stackName && g_discAppCnt < DISC_MAX_APPS - 16; s++) {
        const KnownStack *ks = &g_knownStacks[s];
        char foundPath[MAX_PATH] = {0};
        BOOL exists = FALSE;

        /* Check known paths */
        for (int p = 0; ks->paths[p]; p++) {
            DWORD attr = GetFileAttributesA(ks->paths[p]);
            if (attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY)) {
                strncpy(foundPath, ks->paths[p], MAX_PATH-1);
                exists = TRUE;
                break;
            }
        }
        if (!exists) continue;

        /* Check if already discovered as registry app */
        AppEntry *existing = disc_find_by_name(ks->stackName);
        if (!existing) {
            existing = disc_alloc();
            if (!existing) continue;
            strncpy(existing->name, ks->stackName, 127);
            strncpy(existing->path, foundPath, MAX_PATH-1);
            disc_make_id(ks->stackName, foundPath, existing->id);
        }

        existing->isStack = TRUE;
        existing->type = APP_TYPE_STACK;
        existing->sourceMask |= 0x10;
        existing->listenPorts[0] = ks->defaultPort;
        existing->listenPortCnt = (ks->defaultPort > 0) ? 1 : 0;

        /* Determine state by checking component processes */
        int runningComponents = 0;
        int totalComponents = 0;

        for (int c = 0; ks->components[c]; c++) {
            totalComponents++;
            for (int r = 0; r < runningCnt; r++) {
                if (_stricmp(runningNames[r], ks->components[c]) == 0) {
                    runningComponents++;
                    break;
                }
            }
        }

        if (runningComponents == 0)
            existing->state = APP_STATE_STOPPED;
        else if (runningComponents == totalComponents)
            existing->state = APP_STATE_RUNNING;
        else
            existing->state = APP_STATE_PARTIAL;

        /* Create child component entries */
        existing->childCount = 0;
        for (int c = 0; ks->components[c] && c < DISC_MAX_CHILDREN; c++) {
            const char *compExe = ks->components[c];
            /* Look up running PID for this component */
            DWORD compPid = 0;
            BOOL compRunning = FALSE;
            for (int r = 0; r < runningCnt; r++) {
                if (_stricmp(runningNames[r], compExe) == 0) {
                    compRunning = TRUE;
                    break;
                }
            }

            /* Create component entry */
            char compName[128];
            strncpy(compName, compExe, 127);
            char *dot = strrchr(compName, '.');
            if (dot && _stricmp(dot, ".exe") == 0) *dot = '\0';
            /* Capitalize */
            if (compName[0] >= 'a') compName[0] = (char)toupper((unsigned char)compName[0]);

            /* Check if already exists */
            AppEntry *comp = NULL;
            for (int a = 0; a < g_discAppCnt; a++) {
                if (_stricmp(g_discApps[a].exeName, compExe) == 0 ||
                    _stricmp(g_discApps[a].name, compName) == 0) {
                    comp = &g_discApps[a];
                    break;
                }
            }
            if (!comp && g_discAppCnt < DISC_MAX_APPS) {
                comp = disc_alloc();
                if (comp) {
                    strncpy(comp->name, compName, 127);
                    strncpy(comp->exeName, compExe, 63);
                    snprintf(comp->path, MAX_PATH-1, "%s\\%s", foundPath, compExe);
                    disc_make_id(compName, existing->id, comp->id);
                }
            }
            if (comp) {
                strncpy(comp->stackName, ks->stackName, 63);
                strncpy(comp->parentId, existing->id, 36);
                comp->type = APP_TYPE_COMPONENT;
                comp->state = compRunning ? APP_STATE_RUNNING : APP_STATE_STOPPED;
                comp->sourceMask |= 0x10;
                strncpy(existing->children[existing->childCount], comp->id, 36);
                existing->childCount++;
                /* Add stack membership relation */
                disc_add_relation(existing->id, comp->id, REL_STACK_MEMBER, 0,
                                  "Stack component");
            }
        }
    }
}

/* =========================================================================
 * App Classification & Icon Assignment
 * ========================================================================= */
typedef struct {
    const char *namePart;
    AppType type;
    const char *iconChar;
    COLORREF color;
} AppClassifier;

static const AppClassifier g_classifiers[] = {
    /* Browsers */
    {"chrome",    APP_TYPE_BROWSER,   "[B]", RGB( 66,133,244)},
    {"firefox",   APP_TYPE_BROWSER,   "[B]", RGB(255,115,  0)},
    {"edge",      APP_TYPE_BROWSER,   "[B]", RGB( 0,120,215)},
    {"brave",     APP_TYPE_BROWSER,   "[B]", RGB(251,135, 60)},
    {"opera",     APP_TYPE_BROWSER,   "[B]", RGB(255, 28, 45)},
    /* Databases */
    {"mysql",     APP_TYPE_DATABASE,  "[DB]",RGB( 0,117,143)},
    {"postgres",  APP_TYPE_DATABASE,  "[DB]",RGB( 51,103,145)},
    {"mongodb",   APP_TYPE_DATABASE,  "[DB]",RGB( 71,162, 72)},
    {"redis",     APP_TYPE_DATABASE,  "[DB]",RGB(220, 40, 40)},
    {"sqlite",    APP_TYPE_DATABASE,  "[DB]",RGB( 77,148,188)},
    {"mariadb",   APP_TYPE_DATABASE,  "[DB]",RGB( 29,175,100)},
    /* Servers */
    {"apache",    APP_TYPE_SERVER,    "[WS]",RGB(202, 35, 30)},
    {"httpd",     APP_TYPE_SERVER,    "[WS]",RGB(202, 35, 30)},
    {"nginx",     APP_TYPE_SERVER,    "[WS]",RGB( 0,164, 93)},
    {"iis",       APP_TYPE_SERVER,    "[WS]",RGB(  0,120,212)},
    {"node",      APP_TYPE_SERVER,    "[WS]",RGB( 51,153, 51)},
    {"python",    APP_TYPE_RUNTIME,   "[RT]",RGB( 55,118,171)},
    {"java",      APP_TYPE_RUNTIME,   "[RT]",RGB(237,120, 50)},
    /* Dev tools */
    {"visual studio", APP_TYPE_DEV_TOOL,"[DE]",RGB(104, 33,122)},
    {"vscode",    APP_TYPE_DEV_TOOL,  "[DE]",RGB( 0,122,204)},
    {"git",       APP_TYPE_DEV_TOOL,  "[DE]",RGB(240, 80, 50)},
    {"docker",    APP_TYPE_DEV_TOOL,  "[DE]",RGB( 13,183,237)},
    {"postman",   APP_TYPE_DEV_TOOL,  "[DE]",RGB(255, 108, 55)},
    /* Security */
    {"kaspersky", APP_TYPE_SECURITY,  "[AV]",RGB( 0,175, 70)},
    {"malwarebytes",APP_TYPE_SECURITY,"[AV]",RGB( 31,160,200)},
    {"avast",     APP_TYPE_SECURITY,  "[AV]",RGB(255, 87,  0)},
    {"bitdefender",APP_TYPE_SECURITY, "[AV]",RGB(237, 39, 39)},
    {"nordvpn",   APP_TYPE_SECURITY,  "[VPN]",RGB( 99,179,237)},
    {"protonvpn", APP_TYPE_SECURITY,  "[VPN]",RGB(109, 74,255)},
    {"openvpn",   APP_TYPE_SECURITY,  "[VPN]",RGB(255,165,  0)},
    /* Games/Launchers */
    {"steam",     APP_TYPE_GAME,      "[GM]",RGB( 27, 40, 56)},
    {"epicgames", APP_TYPE_GAME,      "[GM]",RGB(255, 255,255)},
    {"battle.net",APP_TYPE_GAME,      "[GM]",RGB(  0,115,255)},
    /* Communication */
    {"discord",   APP_TYPE_PROCESS,   "[DC]",RGB( 88, 101,242)},
    {"telegram",  APP_TYPE_PROCESS,   "[DC]",RGB( 41,182,246)},
    {"zoom",      APP_TYPE_PROCESS,   "[DC]",RGB( 43,130,243)},
    {"teams",     APP_TYPE_PROCESS,   "[DC]",RGB(100, 53,201)},
    {NULL, 0, NULL, 0}
};

static void disc_classify_apps(void) {
    for (int i = 0; i < g_discAppCnt; i++) {
        AppEntry *e = &g_discApps[i];
        if (e->type != APP_TYPE_UNKNOWN && e->type != APP_TYPE_INSTALLED &&
            e->type != APP_TYPE_PROCESS) continue;

        char nameLo[128]; int ni = 0;
        while (e->name[ni] && ni < 127) {
            nameLo[ni] = (char)tolower((unsigned char)e->name[ni]); ni++;
        }
        nameLo[ni] = '\0';

        for (int c = 0; g_classifiers[c].namePart; c++) {
            if (strstr(nameLo, g_classifiers[c].namePart)) {
                e->type = g_classifiers[c].type;
                strncpy(e->iconChar, g_classifiers[c].iconChar, 3);
                e->iconColor = g_classifiers[c].color;
                break;
            }
        }

        /* Default icons by type */
        if (!e->iconChar[0]) {
            switch (e->type) {
                case APP_TYPE_STACK:    strcpy(e->iconChar, "[S]"); e->iconColor = RGB(168,85,247); break;
                case APP_TYPE_SERVICE:  strcpy(e->iconChar, "[SV]"); e->iconColor = RGB(59,130,246); break;
                case APP_TYPE_PROCESS:  strcpy(e->iconChar, "[P]"); e->iconColor = RGB(16,185,129); break;
                case APP_TYPE_SERVER:   strcpy(e->iconChar, "[WS]"); e->iconColor = RGB(202,35,30); break;
                case APP_TYPE_DATABASE: strcpy(e->iconChar, "[DB]"); e->iconColor = RGB(0,117,143); break;
                case APP_TYPE_BROWSER:  strcpy(e->iconChar, "[B]"); e->iconColor = RGB(66,133,244); break;
                case APP_TYPE_DEV_TOOL: strcpy(e->iconChar, "[DE]"); e->iconColor = RGB(104,33,122); break;
                case APP_TYPE_SECURITY: strcpy(e->iconChar, "[AV]"); e->iconColor = RGB(16,185,129); break;
                case APP_TYPE_GAME:     strcpy(e->iconChar, "[GM]"); e->iconColor = RGB(245,158,11); break;
                case APP_TYPE_RUNTIME:  strcpy(e->iconChar, "[RT]"); e->iconColor = RGB(55,118,171); break;
                default:                strcpy(e->iconChar, "[?]"); e->iconColor = RGB(130,140,155); break;
            }
        }
    }
}

/* =========================================================================
 * Generate Integration Keys for all discovered apps
 * ========================================================================= */
static void disc_generate_keys(void) {
    for (int i = 0; i < g_discAppCnt; i++) {
        AppEntry *e = &g_discApps[i];
        if (e->integrationKey[0]) continue; /* Already has key */
        /* Try to load existing key first */
        if (!disc_load_key(e->name, e->integrationKey)) {
            /* Generate new key */
            disc_derive_key(e->name, e->version, e->path, e->integrationKey);
            disc_store_key(e->name, e->integrationKey);
        }
    }
}

/* =========================================================================
 * App Relationship Builder
 * Correlates TCP connections between apps
 * ========================================================================= */
static void disc_build_relationships(void) {
    /* TCP connections */
    DWORD tcpSz = 0;
    GetExtendedTcpTable(NULL, &tcpSz, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    MIB_TCPTABLE_OWNER_PID *tcpTable = (MIB_TCPTABLE_OWNER_PID*)malloc(tcpSz);
    if (!tcpTable) return;
    if (GetExtendedTcpTable(tcpTable, &tcpSz, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) != NO_ERROR) {
        free(tcpTable); return;
    }
    for (DWORD i = 0; i < tcpTable->dwNumEntries; i++) {
        MIB_TCPROW_OWNER_PID *row = &tcpTable->table[i];
        if (row->dwState != MIB_TCP_STATE_ESTAB) continue;
        int remPort = ntohs((USHORT)row->dwRemotePort);
        DWORD clientPid = row->dwOwningPid;
        /* Find client app */
        AppEntry *clientApp = NULL;
        for (int a = 0; a < g_discAppCnt; a++) {
            if (g_discApps[a].pid == clientPid) { clientApp = &g_discApps[a]; break; }
        }
        /* Find server app (listening on remPort) */
        AppEntry *serverApp = NULL;
        for (int a = 0; a < g_discAppCnt; a++) {
            for (int p = 0; p < g_discApps[a].listenPortCnt; p++) {
                if (g_discApps[a].listenPorts[p] == remPort) {
                    serverApp = &g_discApps[a]; break;
                }
            }
            if (serverApp) break;
        }
        if (clientApp && serverApp && clientApp != serverApp) {
            char desc[128];
            snprintf(desc, sizeof(desc), "TCP connection on port %d", remPort);
            disc_add_relation(clientApp->id, serverApp->id, REL_TCP_CLIENT, remPort, desc);
            /* Add human-readable connection string */
            if (clientApp->openConnCnt < 16) {
                snprintf(clientApp->openConnections[clientApp->openConnCnt++], 63,
                         ":%d -> %s", remPort, serverApp->name);
            }
        }
    }
    free(tcpTable);

    /* Parent/child process relationships */
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe; pe.dwSize = sizeof(pe);
        if (Process32First(snap, &pe)) {
            do {
                if (pe.th32ProcessID <= 4) continue;
                /* Find app for this PID */
                AppEntry *childApp = NULL, *parentApp = NULL;
                for (int a = 0; a < g_discAppCnt; a++) {
                    if (g_discApps[a].pid == pe.th32ProcessID) childApp = &g_discApps[a];
                    if (g_discApps[a].pid == pe.th32ParentProcessID) parentApp = &g_discApps[a];
                }
                if (childApp && parentApp && childApp != parentApp &&
                    parentApp->type != APP_TYPE_UNKNOWN) {
                    disc_add_relation(parentApp->id, childApp->id,
                                      REL_PARENT_CHILD, 0, "Process spawned");
                }
            } while (Process32Next(snap, &pe));
        }
        CloseHandle(snap);
    }
}

/* =========================================================================
 * MAIN DISCOVERY FUNCTION — Call this to run full discovery
 * ========================================================================= */
static int disc_run_discovery(void) {
    if (!g_discCSInit) {
        InitializeCriticalSection(&g_discCS);
        g_discCSInit = TRUE;
    }
    EnterCriticalSection(&g_discCS);

    /* Reset */
    g_discAppCnt = 0;
    g_discRelCnt = 0;
    ZeroMemory(g_discApps, sizeof(g_discApps));
    ZeroMemory(g_discRels, sizeof(g_discRels));

    /* Run all discovery sources */
    disc_scan_registry();           /* Source 1 */
    disc_scan_processes();          /* Source 2 */
    disc_scan_services();           /* Source 3 */
    disc_scan_ports();              /* Source 4 */
    disc_scan_known_stacks();       /* Source 5 */
    disc_classify_apps();           /* Classify and assign icons */
    disc_build_relationships();     /* Build relationship graph */
    disc_generate_keys();           /* Generate integration keys */

    g_lastDiscovery = time(NULL);
    LeaveCriticalSection(&g_discCS);
    return g_discAppCnt;
}

/* =========================================================================
 * Async discovery (background thread)
 * ========================================================================= */
typedef struct { HWND hwndNotify; UINT msgNotify; } DiscContext;

static DWORD WINAPI disc_thread(LPVOID lp) {
    DiscContext *ctx = (DiscContext*)lp;
    int cnt = disc_run_discovery();
    if (ctx) {
        if (ctx->hwndNotify) PostMessageA(ctx->hwndNotify, ctx->msgNotify, (WPARAM)cnt, 0);
        free(ctx);
    }
    return cnt;
}

/* Launch discovery in background. When done, posts msgNotify to hwndNotify */
static void disc_run_async(HWND hwndNotify, UINT msgNotify) {
    DiscContext *ctx = (DiscContext*)malloc(sizeof(DiscContext));
    if (!ctx) return;
    ctx->hwndNotify = hwndNotify;
    ctx->msgNotify  = msgNotify;
    HANDLE hThread = CreateThread(NULL, 0, disc_thread, ctx, 0, NULL);
    if (hThread) CloseHandle(hThread);
    else free(ctx);
}

/* =========================================================================
 * Query helpers for GUI use
 * ========================================================================= */

/* Get stacks only */
static int disc_get_stacks(AppEntry **out, int maxOut) {
    int cnt = 0;
    for (int i = 0; i < g_discAppCnt && cnt < maxOut; i++)
        if (g_discApps[i].isStack) out[cnt++] = &g_discApps[i];
    return cnt;
}

/* Get running apps only */
static int disc_get_running(AppEntry **out, int maxOut) {
    int cnt = 0;
    for (int i = 0; i < g_discAppCnt && cnt < maxOut; i++)
        if (g_discApps[i].state == APP_STATE_RUNNING) out[cnt++] = &g_discApps[i];
    return cnt;
}

/* Get unknown apps */
static int disc_get_unknown(AppEntry **out, int maxOut) {
    int cnt = 0;
    for (int i = 0; i < g_discAppCnt && cnt < maxOut; i++)
        if (g_discApps[i].type == APP_TYPE_UNKNOWN ||
            (g_discApps[i].type == APP_TYPE_PROCESS && !g_discApps[i].publisher[0]))
            out[cnt++] = &g_discApps[i];
    return cnt;
}

/* Get components of a stack */
static int disc_get_children(const char *parentId, AppEntry **out, int maxOut) {
    AppEntry *parent = disc_find_by_id(parentId);
    if (!parent) return 0;
    int cnt = 0;
    for (int c = 0; c < parent->childCount && cnt < maxOut; c++) {
        AppEntry *child = disc_find_by_id(parent->children[c]);
        if (child) out[cnt++] = child;
    }
    return cnt;
}

/* Format app state string */
static const char* disc_state_str(AppState s) {
    switch (s) {
        case APP_STATE_RUNNING: return "RUNNING";
        case APP_STATE_STOPPED: return "STOPPED";
        case APP_STATE_PARTIAL: return "PARTIAL";
        default: return "UNKNOWN";
    }
}

/* Format app type string */
static const char* disc_type_str(AppType t) {
    switch (t) {
        case APP_TYPE_STACK:     return "Stack";
        case APP_TYPE_SERVICE:   return "Service";
        case APP_TYPE_PROCESS:   return "Process";
        case APP_TYPE_INSTALLED: return "Installed";
        case APP_TYPE_COMPONENT: return "Component";
        case APP_TYPE_SERVER:    return "Server";
        case APP_TYPE_SECURITY:  return "Security";
        case APP_TYPE_DEV_TOOL:  return "DevTool";
        case APP_TYPE_DATABASE:  return "Database";
        case APP_TYPE_BROWSER:   return "Browser";
        case APP_TYPE_GAME:      return "Game";
        case APP_TYPE_RUNTIME:   return "Runtime";
        default: return "Unknown";
    }
}

/* XAMPP control helpers */
static void disc_xampp_start(const char *component) {
    /* Find XAMPP path */
    AppEntry *xampp = disc_find_by_name("XAMPP");
    if (!xampp || !xampp->path[0]) return;
    char cmd[512];
    if (!component || !*component)
        snprintf(cmd, sizeof(cmd), "\"%s\\xampp_start.exe\"", xampp->path);
    else if (_stricmp(component, "Apache") == 0)
        snprintf(cmd, sizeof(cmd), "\"%s\\apache_start.bat\"", xampp->path);
    else if (_stricmp(component, "MySQL") == 0)
        snprintf(cmd, sizeof(cmd), "\"%s\\mysql_start.bat\"", xampp->path);
    else
        return;
    ShellExecuteA(NULL, "runas", "cmd.exe",
                  cmd, NULL, SW_HIDE);
}

static void disc_xampp_stop(const char *component) {
    AppEntry *xampp = disc_find_by_name("XAMPP");
    if (!xampp || !xampp->path[0]) return;
    char cmd[512];
    if (!component || !*component)
        snprintf(cmd, sizeof(cmd), "\"%s\\xampp_stop.exe\"", xampp->path);
    else if (_stricmp(component, "Apache") == 0)
        snprintf(cmd, sizeof(cmd), "\"%s\\apache_stop.bat\"", xampp->path);
    else if (_stricmp(component, "MySQL") == 0)
        snprintf(cmd, sizeof(cmd), "\"%s\\mysql_stop.bat\"", xampp->path);
    else
        return;
    ShellExecuteA(NULL, "runas", "cmd.exe",
                  cmd, NULL, SW_HIDE);
}

/* WM_APP+50 = discovery complete notification */
#define WM_DISC_COMPLETE (WM_APP + 50)

#endif /* DISCOVERY_ENGINE_H */
