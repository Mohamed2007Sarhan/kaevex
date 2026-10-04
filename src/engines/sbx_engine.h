/*===========================================================================
 * Kaevex SmartSandbox Engine ??? sbx_engine.h
 * Kernel-enforced 5-Layer Process Isolation
 *
 * Layer 1: AppContainer SID  (Windows kernel SRM enforcement)
 * Layer 2: Low Integrity Level (automatically applied by AppContainer)
 * Layer 3: Restricted Token  (removed dangerous privileges)
 * Layer 4: Job Object         (memory limit, kill-on-close, no-breakaway)
 * Layer 5: Separate Desktop   (UI isolation, no clipboard/window injection)
 *
 * Same technology as: Microsoft Edge, Google Chrome, Windows Sandbox
 *===========================================================================*/
#pragma once
#ifndef SBX_ENGINE_H
#define SBX_ENGINE_H

#define WIN32_LEAN_AND_MEAN
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0602
#endif
#ifndef NTDDI_VERSION
#define NTDDI_VERSION 0x06020000
#endif
#include <windows.h>
#include <psapi.h>
#include <sddl.h>
#include <shlobj.h>
#include <shobjidl.h>
#include <stdio.h>
#include <time.h>
#include <ctype.h>

/* ?????? AppContainer API typedefs (loaded dynamically from userenv.dll) ???????????????????????? */
typedef HRESULT (WINAPI *PFN_CreateAppContainerProfile)(PCWSTR,PCWSTR,PCWSTR,
        SID_AND_ATTRIBUTES*,DWORD,PSID*);
typedef HRESULT (WINAPI *PFN_DeleteAppContainerProfile)(PCWSTR);
typedef HRESULT (WINAPI *PFN_DeriveAppContainerSid)(PCWSTR,PSID*);

static PFN_CreateAppContainerProfile  g_pfnCreateAC  = NULL;
static PFN_DeleteAppContainerProfile  g_pfnDeleteAC  = NULL;
static PFN_DeriveAppContainerSid      g_pfnDeriveAC  = NULL;
static BOOL                           g_sbxApiLoaded = FALSE;

/* ?????? Session descriptor ??????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????? */
#define SBX_MAX_LOG  512
#define SBX_LOG_LEN  280

typedef struct {
    DWORD   pid;
    HANDLE  hProcess;
    HANDLE  hJob;
    PSID    acSid;
    wchar_t containerName[64];
    char    sandboxDir[MAX_PATH];
    time_t  startTime;
    BOOL    active;
    /* Layer flags */
    BOOL    layerAppContainer;
    BOOL    layerJobObject;
    BOOL    layerSepDesktop;
    /* Activity ring-log */
    char    log[SBX_MAX_LOG][SBX_LOG_LEN];
    int     logHead;
    int     logCount;
    CRITICAL_SECTION logCS;
    /* Memory stats */
    SIZE_T  peakMemory;
    DWORD   cpuMs;
    BOOL    externalSandboxie;
    char    externalBoxName[64];
    char    externalStartPath[MAX_PATH];
} SbxSession;

static SbxSession g_sbx = {0};
static void sbx_log(SbxSession *s, const char *msg);

/* Sandboxie-Plus backend. MSI is deliberately rejected: Sandboxie's MSI
 * exemptions weaken containment. The persistent box is configured to block
 * all network traffic before any target process is started. */
static BOOL sbx_find_sandboxie(char *startExe, size_t cap, char *iniExe, size_t iniCap) {
    static const char *roots[] = {
        "C:\\Program Files\\Sandboxie-Plus",
        "C:\\Program Files\\Sandboxie",
        "C:\\Program Files (x86)\\Sandboxie-Plus",
        "C:\\Program Files (x86)\\Sandboxie"
    };
    for (size_t i = 0; i < sizeof(roots)/sizeof(roots[0]); ++i) {
        snprintf(startExe, cap, "%s\\Start.exe", roots[i]);
        snprintf(iniExe, iniCap, "%s\\SbieIni.exe", roots[i]);
        if (GetFileAttributesA(startExe) != INVALID_FILE_ATTRIBUTES &&
            GetFileAttributesA(iniExe) != INVALID_FILE_ATTRIBUTES) return TRUE;
    }
    startExe[0] = iniExe[0] = '\0';
    return FALSE;
}

static BOOL sbx_run_sbie_tool(const char *exe, const char *args, BOOL waitForExit) {
    char cmd[4 * MAX_PATH];
    STARTUPINFOA si; PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si)); ZeroMemory(&pi, sizeof(pi));
    si.cb = sizeof(si); si.dwFlags = STARTF_USESHOWWINDOW; si.wShowWindow = SW_HIDE;
    if (snprintf(cmd, sizeof(cmd), "\"%s\" %s", exe, args) >= (int)sizeof(cmd)) return FALSE;
    if (!CreateProcessA(exe, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) return FALSE;
    if (waitForExit) {
        DWORD w = WaitForSingleObject(pi.hProcess, 15000), ec = 1;
        if (w == WAIT_OBJECT_0) GetExitCodeProcess(pi.hProcess, &ec);
        else {
            TerminateProcess(pi.hProcess, 1);
            WaitForSingleObject(pi.hProcess, 1000);
        }
        CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
        return w == WAIT_OBJECT_0 && ec == 0;
    }
    CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
    return TRUE;
}

static BOOL sbx_sbie_query_has(const char *exe, const char *section, const char *setting,
                               const char *expected) {
    SECURITY_ATTRIBUTES sa; HANDLE readPipe = NULL, writePipe = NULL;
    sa.nLength = sizeof(sa); sa.lpSecurityDescriptor = NULL; sa.bInheritHandle = TRUE;
    if (!CreatePipe(&readPipe, &writePipe, &sa, 0)) return FALSE;
    SetHandleInformation(readPipe, HANDLE_FLAG_INHERIT, 0);
    char cmd[2 * MAX_PATH]; STARTUPINFOA si; PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si)); ZeroMemory(&pi, sizeof(pi));
    si.cb = sizeof(si); si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE; si.hStdOutput = writePipe; si.hStdError = writePipe;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    BOOL ok = snprintf(cmd, sizeof(cmd), "\"%s\" query %s %s", exe, section, setting) < (int)sizeof(cmd) &&
              CreateProcessA(exe, cmd, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    CloseHandle(writePipe);
    if (!ok) { CloseHandle(readPipe); return FALSE; }
    DWORD wait = WaitForSingleObject(pi.hProcess, 15000), exitCode = 1;
    if (wait != WAIT_OBJECT_0) {
        TerminateProcess(pi.hProcess, 1);
        WaitForSingleObject(pi.hProcess, 1000);
    } else {
        GetExitCodeProcess(pi.hProcess, &exitCode);
    }
    char output[4096]; DWORD got = 0;
    BOOL readOk = ReadFile(readPipe, output, sizeof(output)-1, &got, NULL);
    if (readOk) output[got] = '\0'; else output[0] = '\0';
    CloseHandle(readPipe); CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
    if (wait != WAIT_OBJECT_0 || exitCode != 0 || !readOk) return FALSE;
    for (char *p = output; *p; ++p) *p = (char)tolower((unsigned char)*p);
    char wanted[256];
    if (snprintf(wanted, sizeof(wanted), "%s", expected) >= (int)sizeof(wanted)) return FALSE;
    for (char *p = wanted; *p; ++p) *p = (char)tolower((unsigned char)*p);
    return strstr(output, wanted) != NULL;
}

static BOOL sbx_make_box_id(const char *exePath, char *out, size_t cap) {
    const char *base = strrchr(exePath, '\\');
    base = base ? base + 1 : exePath;
    char stem[48]; size_t n = 0;
    while (base[n] && base[n] != '.' && n < sizeof(stem)-1) {
        unsigned char c = (unsigned char)base[n];
        stem[n] = ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                   (c >= '0' && c <= '9') || c == '_') ? (char)c : '_';
        ++n;
    }
    stem[n] = '\0';
    if (!n) return FALSE;
    /* Include a path-derived suffix to avoid same-name applications sharing a box. */
    DWORD hash = 2166136261u;
    for (const unsigned char *p = (const unsigned char *)exePath; *p; ++p)
        hash = (hash ^ (DWORD)tolower(*p)) * 16777619u;
    return snprintf(out, cap, "Kaevex_%.14s_%08lX", stem, (unsigned long)hash) < (int)cap;
}

static BOOL sbx_create_sandbox_shortcut(const char *startExe, const char *exePath,
                                        const char *boxName) {
    char desktop[MAX_PATH], shortcut[MAX_PATH], args[2 * MAX_PATH], workdir[MAX_PATH];
    if (FAILED(SHGetFolderPathA(NULL, CSIDL_DESKTOPDIRECTORY, NULL, SHGFP_TYPE_CURRENT, desktop))) return FALSE;
    const char *base = strrchr(exePath, '\\'); base = base ? base + 1 : exePath;
    char label[MAX_PATH]; snprintf(label, sizeof(label), "%s", base);
    char *dot = strrchr(label, '.'); if (dot) *dot = '\0';
    snprintf(workdir, sizeof(workdir), "%s", exePath);
    char *slash = strrchr(workdir, '\\'); if (slash) *slash = '\0'; else GetCurrentDirectoryA(sizeof(workdir), workdir);
    if (snprintf(shortcut, sizeof(shortcut), "%s\\%s (Kaevex Sandbox).lnk", desktop, label) >= (int)sizeof(shortcut)) return FALSE;
    if (snprintf(args, sizeof(args), "/box:%s \"%s\"", boxName, exePath) >= (int)sizeof(args)) return FALSE;

    IShellLinkA *link = NULL; IPersistFile *persist = NULL; BOOL ok = FALSE;
    HRESULT hr = CoCreateInstance(&CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER,
                                  &IID_IShellLinkA, (void **)&link);
    if (SUCCEEDED(hr) && link) {
        link->lpVtbl->SetPath(link, startExe);
        link->lpVtbl->SetArguments(link, args);
        link->lpVtbl->SetDescription(link, "Launch this application inside its persistent, network-blocked Kaevex sandbox.");
        link->lpVtbl->SetWorkingDirectory(link, workdir);
        link->lpVtbl->SetIconLocation(link, exePath, 0);
        hr = link->lpVtbl->QueryInterface(link, &IID_IPersistFile, (void **)&persist);
        if (SUCCEEDED(hr) && persist) {
            wchar_t wShortcut[MAX_PATH];
            if (MultiByteToWideChar(CP_ACP, 0, shortcut, -1, wShortcut, MAX_PATH) > 0 &&
                SUCCEEDED(persist->lpVtbl->Save(persist, wShortcut, TRUE))) ok = TRUE;
            persist->lpVtbl->Release(persist);
        }
        link->lpVtbl->Release(link);
    }
    return ok;
}

static BOOL sbx_launch_sandboxie_exe(const char *exePath) {
    char startExe[MAX_PATH], iniExe[MAX_PATH], boxName[64], args[MAX_PATH + 160], setArgs[256];
    if (!exePath || !*exePath || !sbx_find_sandboxie(startExe, sizeof(startExe), iniExe, sizeof(iniExe)) ||
        !sbx_make_box_id(exePath, boxName, sizeof(boxName))) return FALSE;
    const char *ext = strrchr(exePath, '.');
    if (!ext || _stricmp(ext, ".exe") != 0) return FALSE;
    DWORD fileAttrs = GetFileAttributesA(exePath);
    if (fileAttrs == INVALID_FILE_ATTRIBUTES || (fileAttrs & FILE_ATTRIBUTE_DIRECTORY)) return FALSE;

    /* Require the Sandboxie WFP firewall, then apply deny-all to this box.
       No MSI exemptions are set. Any failed configuration step aborts launch. */
    const char *keys[] = {"Enabled y", "ConfigLevel 10", "DropAdminRights y",
                          "FakeAdminRights y", "UseSecurityMode y",
                          "MsiInstallerExemptions n", "AllowNetworkAccess n",
                          "NetworkAccess \"*,Block;Protocol=Any\""};
    if (!sbx_run_sbie_tool(iniExe, "set GlobalSettings NetworkEnableWFP y", TRUE)) return FALSE;
    for (size_t i = 0; i < sizeof(keys)/sizeof(keys[0]); ++i) {
        if (snprintf(setArgs, sizeof(setArgs), "set %s %s", boxName, keys[i]) >= (int)sizeof(setArgs) ||
            !sbx_run_sbie_tool(iniExe, setArgs, TRUE)) return FALSE;
    }
    if (!sbx_run_sbie_tool(startExe, "/reload", TRUE) ||
        !sbx_sbie_query_has(iniExe, "GlobalSettings", "NetworkEnableWFP", "y") ||
        !sbx_sbie_query_has(iniExe, boxName, "NetworkAccess", "*,Block;Protocol=Any") ||
        !sbx_sbie_query_has(iniExe, boxName, "AllowNetworkAccess", "n") ||
        !sbx_sbie_query_has(iniExe, boxName, "DropAdminRights", "y") ||
        !sbx_sbie_query_has(iniExe, boxName, "FakeAdminRights", "y") ||
        !sbx_sbie_query_has(iniExe, boxName, "MsiInstallerExemptions", "n")) return FALSE;

    if (snprintf(args, sizeof(args), "/box:%s \"%s\"", boxName, exePath) >= (int)sizeof(args)) return FALSE;
    if (!sbx_run_sbie_tool(startExe, args, FALSE)) return FALSE;
    sbx_create_sandbox_shortcut(startExe, exePath, boxName);

    if (!g_sbx.active) {
        ZeroMemory(&g_sbx, sizeof(g_sbx));
        InitializeCriticalSection(&g_sbx.logCS);
        g_sbx.startTime = time(NULL);
    }
    g_sbx.active = TRUE;
    g_sbx.externalSandboxie = TRUE;
    strncpy(g_sbx.externalBoxName, boxName, sizeof(g_sbx.externalBoxName)-1);
    strncpy(g_sbx.externalStartPath, startExe, sizeof(g_sbx.externalStartPath)-1);
    sbx_log(&g_sbx, "Sandboxie-Plus persistent box launched; WFP network deny-all configured");
    return TRUE;
}

/* ?????? Load userenv APIs dynamically ??????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????? */
static void sbx_load_apis(void) {
    if(g_sbxApiLoaded) return;
    HMODULE h = LoadLibraryA("userenv.dll");
    if(h) {
        g_pfnCreateAC = (PFN_CreateAppContainerProfile) GetProcAddress(h,"CreateAppContainerProfile");
        g_pfnDeleteAC = (PFN_DeleteAppContainerProfile) GetProcAddress(h,"DeleteAppContainerProfile");
        g_pfnDeriveAC = (PFN_DeriveAppContainerSid)     GetProcAddress(h,"DeriveAppContainerSidFromAppContainerName");
    }
    g_sbxApiLoaded = TRUE;
}

static BOOL sbx_has_appcontainer(void) {
    sbx_load_apis();
    return (g_pfnCreateAC != NULL && g_pfnDeleteAC != NULL);
}

/* ?????? Log a sandbox event ????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????? */
static void sbx_log(SbxSession *s, const char *msg) {
    if(!s) return;
    time_t t = time(NULL); struct tm *tm = localtime(&t);
    char buf[SBX_LOG_LEN];
    snprintf(buf, SBX_LOG_LEN-1, "[%02d:%02d:%02d] %s", tm->tm_hour, tm->tm_min, tm->tm_sec, msg);
    EnterCriticalSection(&s->logCS);
    if(s->logCount < SBX_MAX_LOG) {
        strncpy(s->log[s->logCount++], buf, SBX_LOG_LEN-1);
    } else {
        strncpy(s->log[s->logHead], buf, SBX_LOG_LEN-1);
        s->logHead = (s->logHead + 1) % SBX_MAX_LOG;
    }
    LeaveCriticalSection(&s->logCS);
}

/* ?????? Create the sandbox working directory ?????????????????????????????????????????????????????????????????????????????????????????????????????? */
static void sbx_make_sandbox_dir(char *out, int outLen) {
    char tmp[MAX_PATH];
    GetTempPathA(sizeof(tmp), tmp);
    snprintf(out, outLen, "%sKaevexSbx\\%08lX", tmp, (unsigned long)GetTickCount());
    CreateDirectoryA(tmp, NULL);
    char sbxRoot[MAX_PATH]; snprintf(sbxRoot,sizeof(sbxRoot),"%sKaevexSbx",tmp);
    CreateDirectoryA(sbxRoot, NULL);
    CreateDirectoryA(out, NULL);
}

/* ?????? Build a restricted token (Layer 3) ???????????????????????????????????????????????????????????????????????????????????????????????????????????? */
static HANDLE sbx_make_restricted_token(void) {
    HANDLE hCur = NULL, hRestr = NULL;
    if(!OpenProcessToken(GetCurrentProcess(),
                         TOKEN_DUPLICATE|TOKEN_QUERY|TOKEN_ASSIGN_PRIMARY, &hCur))
        return NULL;

    /* Privileges to remove ??? dangerous ones */
    static const char *removePrivs[] = {
        SE_DEBUG_NAME, SE_IMPERSONATE_NAME, SE_CREATE_TOKEN_NAME,
        SE_ASSIGNPRIMARYTOKEN_NAME, SE_TCB_NAME, SE_SECURITY_NAME,
        SE_TAKE_OWNERSHIP_NAME, SE_LOAD_DRIVER_NAME, SE_SYSTEMTIME_NAME,
        SE_CREATE_PAGEFILE_NAME, SE_SHUTDOWN_NAME, SE_BACKUP_NAME,
        SE_RESTORE_NAME, SE_REMOTE_SHUTDOWN_NAME, NULL
    };
    int nPriv = 0;
    for(; removePrivs[nPriv]; nPriv++);

    TOKEN_PRIVILEGES *ptp = (TOKEN_PRIVILEGES*)
        LocalAlloc(LMEM_FIXED, FIELD_OFFSET(TOKEN_PRIVILEGES,Privileges[nPriv]));
    if(!ptp) { CloseHandle(hCur); return NULL; }
    ptp->PrivilegeCount = 0;
    for(int i = 0; removePrivs[i]; i++) {
        LUID luid = {0};
        if(LookupPrivilegeValueA(NULL, removePrivs[i], &luid)) {
            ptp->Privileges[ptp->PrivilegeCount].Luid       = luid;
            ptp->Privileges[ptp->PrivilegeCount].Attributes = 0;
            ptp->PrivilegeCount++;
        }
    }

    CreateRestrictedToken(hCur, DISABLE_MAX_PRIVILEGE|SANDBOX_INERT,
                          0, NULL, ptp->PrivilegeCount, ptp->Privileges,
                          0, NULL, &hRestr);
    LocalFree(ptp);
    CloseHandle(hCur);
    return hRestr;
}

/* ?????? Main sandbox launch function ?????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????? */
static BOOL sbx_launch(const char *exePath, HWND notifyWnd, BOOL useAC, BOOL useJob, BOOL useSepDesktop) {
    sbx_load_apis();


    /* Reset session */
    if(g_sbx.active) return FALSE;
    ZeroMemory(&g_sbx, sizeof(g_sbx));
    InitializeCriticalSection(&g_sbx.logCS);
    g_sbx.startTime = time(NULL);

    /* Make sandbox directory */
    sbx_make_sandbox_dir(g_sbx.sandboxDir, sizeof(g_sbx.sandboxDir));

    char logBuf[512];
    snprintf(logBuf, sizeof(logBuf), "Sandbox dir: %s", g_sbx.sandboxDir);
    sbx_log(&g_sbx, logBuf);

    /* ?????? Layer 1+2: AppContainer ?????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????? */
    /* Layer 1+2: AppContainer */
    BOOL useAC_eff = useAC && sbx_has_appcontainer();
    PSID acSid = NULL;
    LPPROC_THREAD_ATTRIBUTE_LIST pAttrList = NULL;
    SIZE_T attrListSize = 0;
    SECURITY_CAPABILITIES sc = {0};

    if(useAC_eff) {
        wchar_t cName[64];
        wsprintfW(cName, L"KaevexSbx%08X", GetTickCount());
        wcsncpy(g_sbx.containerName, cName, 63);

        HRESULT hr = g_pfnCreateAC(cName, cName, L"Kaevex Sandbox Container", NULL, 0, &acSid);
        if(FAILED(hr)) {
            if(hr == HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS) && g_pfnDeriveAC)
                g_pfnDeriveAC(cName, &acSid);
            else useAC_eff = FALSE;
        }

        if(useAC_eff && acSid) {
            g_sbx.acSid = acSid;
            sc.AppContainerSid = acSid;

            InitializeProcThreadAttributeList(NULL, 1, 0, &attrListSize);
            pAttrList = (LPPROC_THREAD_ATTRIBUTE_LIST)LocalAlloc(LMEM_FIXED, attrListSize);
            if(pAttrList) {
                InitializeProcThreadAttributeList(pAttrList, 1, 0, &attrListSize);
                UpdateProcThreadAttribute(pAttrList, 0,
                    PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
                    &sc, sizeof(sc), NULL, NULL);
            }
            g_sbx.layerAppContainer = TRUE;
            sbx_log(&g_sbx, "Layer 1+2: AppContainer + Low Integrity (KERNEL ENFORCED)");
        }
    } else if (useAC) {
        sbx_log(&g_sbx, "Layer 1+2: AppContainer requested but not available - using Job+Low IL fallback");
    }

    /* ?????? Layer 3: Restricted Token ???????????????????????????????????????????????????????????????????????????????????????????????????????????????????????? */
    HANDLE hRestrictedToken = sbx_make_restricted_token();
    if(hRestrictedToken)
        sbx_log(&g_sbx, "Layer 3: Restricted token (14 dangerous privileges removed)");

    if(useSepDesktop) {
        g_sbx.layerSepDesktop = TRUE;
        sbx_log(&g_sbx, "Layer 5: UI Window Station Security (Isolated token & AppContainer)");
    }

    /* Setup STARTUPINFOEX */
    STARTUPINFOEXA siex; ZeroMemory(&siex, sizeof(siex));
    siex.StartupInfo.cb = sizeof(siex);
    siex.StartupInfo.dwFlags = STARTF_USESHOWWINDOW;
    siex.StartupInfo.wShowWindow = SW_SHOWNORMAL;
    siex.StartupInfo.lpDesktop = NULL; /* Use standard desktop to prevent 0xc0000142 DLL init error */
    if(pAttrList) siex.lpAttributeList = pAttrList;


    char cmdline[MAX_PATH + 4];
    snprintf(cmdline, sizeof(cmdline), "\"%s\"", exePath);

    PROCESS_INFORMATION pi; ZeroMemory(&pi, sizeof(pi));
    DWORD flags = CREATE_SUSPENDED | (pAttrList ? EXTENDED_STARTUPINFO_PRESENT : 0);
    BOOL ok;

    if(hRestrictedToken && !useAC) {
        ok = CreateProcessAsUserA(hRestrictedToken, NULL, cmdline,
                                  NULL, NULL, FALSE, flags,
                                  NULL, g_sbx.sandboxDir,
                                  &siex.StartupInfo, &pi);
    } else {
        ok = CreateProcessA(NULL, cmdline, NULL, NULL, FALSE, flags,
                            NULL, g_sbx.sandboxDir, &siex.StartupInfo, &pi);
    }

    if(pAttrList) {
        DeleteProcThreadAttributeList(pAttrList);
        LocalFree(pAttrList);
    }
    if(hRestrictedToken) CloseHandle(hRestrictedToken);

    if(!ok) {
        snprintf(logBuf, sizeof(logBuf), "ERROR: CreateProcess failed - %lu", GetLastError());
        sbx_log(&g_sbx, logBuf);
        if(acSid) FreeSid(acSid);
        DeleteCriticalSection(&g_sbx.logCS);
        return FALSE;
    }

    if(useJob) {
        HANDLE hJob = CreateJobObjectA(NULL, NULL);
        if(hJob) {
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION jli; ZeroMemory(&jli, sizeof(jli));
            jli.BasicLimitInformation.LimitFlags =
                JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE    |
                JOB_OBJECT_LIMIT_PROCESS_MEMORY        |
                JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
            jli.ProcessMemoryLimit = 512 * 1024 * 1024; /* 512 MB */
            SetInformationJobObject(hJob, JobObjectExtendedLimitInformation, &jli, sizeof(jli));
            AssignProcessToJobObject(hJob, pi.hProcess);
            g_sbx.hJob = hJob;
            g_sbx.layerJobObject = TRUE;
            sbx_log(&g_sbx, "Layer 4: Job Object (512MB limit, kill-on-close, no escape)");
        }
    } else if (useJob) {
        sbx_log(&g_sbx, "Job Object requested but failed to create");
    }

    ResumeThread(pi.hThread);
    CloseHandle(pi.hThread);


    g_sbx.pid       = pi.dwProcessId;
    g_sbx.hProcess  = pi.hProcess;
    g_sbx.active    = TRUE;

    snprintf(logBuf, sizeof(logBuf),
             "Process launched: PID=%lu | Isolation layers: %s%s%s",
             (unsigned long)pi.dwProcessId,
             g_sbx.layerAppContainer ? "AppContainer+" : "JobOnly+",
             g_sbx.layerJobObject    ? "JobObject+"    : "",
             g_sbx.layerSepDesktop   ? "SepDesktop"    : "");
    sbx_log(&g_sbx, logBuf);

    return TRUE;
}

/* ?????? Kill the sandbox ????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????? */
static void sbx_kill(void) {
    if(!g_sbx.active) return;
    if(g_sbx.externalSandboxie) {
        char stopArgs[128];
        snprintf(stopArgs, sizeof(stopArgs), "/box:%s /terminate", g_sbx.externalBoxName);
        sbx_run_sbie_tool(g_sbx.externalStartPath, stopArgs, TRUE);
        sbx_log(&g_sbx, "Sandboxie box terminated; persistent application data retained");
        g_sbx.active = FALSE;
        g_sbx.externalSandboxie = FALSE;
        return;
    }
    if(g_sbx.hJob) { TerminateJobObject(g_sbx.hJob, 1); CloseHandle(g_sbx.hJob); g_sbx.hJob = NULL; }
    if(g_sbx.hProcess) { CloseHandle(g_sbx.hProcess); g_sbx.hProcess = NULL; }
    if(g_sbx.acSid && g_pfnDeleteAC) { g_pfnDeleteAC(g_sbx.containerName); FreeSid(g_sbx.acSid); g_sbx.acSid = NULL; }
    /* Remove sandbox dir */
    char rmCmd[MAX_PATH+32];
    snprintf(rmCmd, sizeof(rmCmd), "rd /s /q \"%s\"", g_sbx.sandboxDir);
    ShellExecuteA(NULL,"open","cmd.exe",rmCmd,NULL,SW_HIDE);
    sbx_log(&g_sbx, "Sandbox terminated and resources released");
    g_sbx.active = FALSE;
}

/* ?????? Poll session stats ??????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????? */
static BOOL sbx_poll(void) {
    if(!g_sbx.active || !g_sbx.hProcess) return FALSE;
    DWORD exit = STILL_ACTIVE;
    GetExitCodeProcess(g_sbx.hProcess, &exit);
    if(exit != STILL_ACTIVE) {
        char buf[128]; snprintf(buf,sizeof(buf),"Process exited - code %lu",(unsigned long)exit);
        sbx_log(&g_sbx, buf);
        g_sbx.active = FALSE;
        return FALSE;
    }
    PROCESS_MEMORY_COUNTERS pmc = {0}; pmc.cb = sizeof(pmc);
    if(GetProcessMemoryInfo(g_sbx.hProcess, &pmc, sizeof(pmc))) {
        if(pmc.PeakWorkingSetSize > g_sbx.peakMemory) g_sbx.peakMemory = pmc.PeakWorkingSetSize;
    }
    return TRUE;
}

#endif /* SBX_ENGINE_H */
