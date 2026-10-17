/*===========================================================================
 * Kaevex Real-Time Protection - realtime_engine.h
 *
 *  FILE WATCHER      ReadDirectoryChangesW over Downloads, Desktop, Documents, Temp and removable
 *                    drives. New/changed executables and scripts are scanned with av_scan_file().
 *  BEHAVIOR MONITOR  Polls the process list (2 s) and flags: Office/PDF/browser parents spawning
 *                    script engines, LOLBin download patterns (certutil/bitsadmin/mshta/regsvr32),
 *                    encoded/hidden PowerShell, and UNSIGNED programs started from user-writable
 *                    folders. Command lines are read with NtQueryInformationProcess.
 *
 * These are heuristics: they raise alerts, they never kill or delete anything on their own.
 * The toggles in Threat Protection start/stop these threads, nothing else.
 * Requires (defined earlier in kaevex-gui.c): av_scan_file, AvResult, threatdb_add, add_alert.
 *===========================================================================*/
#pragma once
#ifndef REALTIME_ENGINE_H
#define REALTIME_ENGINE_H

static volatile LONG g_rtFileRun = 0, g_rtBehRun = 0;
static HANDLE g_rtFileStop = NULL, g_rtBehStop = NULL;
/* counters g_rtFilesScanned/g_rtFileThreats/g_rtProcChecked/g_rtBehAlerts and g_rtHeuristics are declared in kaevex-gui.c
   (g_rtHeuristics FALSE = only known-bad hash matches raise a file alert) */

static int rt_ext_watched(const char *path) {
    static const char *ext[] = { ".exe", ".dll", ".scr", ".com", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jse", ".wsf", ".hta", ".jar", ".msi", ".lnk", ".sys", NULL };
    const char *d = strrchr(path, '.'); if (!d) return 0;
    for (int i = 0; ext[i]; i++) if (_stricmp(d, ext[i]) == 0) return 1;
    return 0;
}

/* ---- File watcher ---------------------------------------------------------------------------------------- */
#define RT_MAXDIRS 10
typedef struct { char path[MAX_PATH]; HANDLE h; OVERLAPPED ov; BYTE buf[32768]; HANDLE ev; } RtDir;

static void rt_scan_one(const char *path) {
    /* wait until the writer is finished */
    for (int i = 0; i < 10; i++) { HANDLE h = CreateFileA(path, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL); if (h != INVALID_HANDLE_VALUE) { CloseHandle(h); break; } Sleep(400); }
    AvResult r;
    if (!av_scan_file(path, &r)) return;
    InterlockedIncrement(&g_rtFilesScanned);
    int bad = r.threat || (g_rtHeuristics && r.score >= 70);
    if (bad) {
        InterlockedIncrement(&g_rtFileThreats);
        char m[420]; snprintf(m, sizeof m, "Real-time scan: %s - %s (score %d) %.200s", r.threat ? "THREAT" : "suspicious", r.tname[0] ? r.tname : "heuristic", r.score, path);
        add_alert("Real-Time", r.threat ? "CRITICAL" : "WARNING", m);
        threatdb_add(path, r.tname[0] ? r.tname : "Heuristic.Suspicious", "RealTime", r.sha256, r.score);
    }
}

static DWORD WINAPI rt_file_thread(LPVOID p) {
    (void)p;
    RtDir d[RT_MAXDIRS]; int n = 0; memset(d, 0, sizeof d);
    char prof[MAX_PATH] = "", tmp[MAX_PATH] = "";
    const int csidl[] = { CSIDL_DESKTOPDIRECTORY, CSIDL_PERSONAL };
    for (int i = 0; i < 2 && n < RT_MAXDIRS; i++) if (SUCCEEDED(SHGetFolderPathA(NULL, csidl[i], NULL, 0, d[n].path))) n++;
    if (GetEnvironmentVariableA("USERPROFILE", prof, sizeof prof) && n < RT_MAXDIRS) { snprintf(d[n].path, MAX_PATH, "%s\\Downloads", prof); n++; }
    if (GetTempPathA(sizeof tmp, tmp) && n < RT_MAXDIRS) { snprintf(d[n].path, MAX_PATH, "%s", tmp); size_t l = strlen(d[n].path); if (l > 3 && d[n].path[l - 1] == '\\') d[n].path[l - 1] = 0; n++; }
    DWORD drives = GetLogicalDrives();
    for (int i = 2; i < 26 && n < RT_MAXDIRS; i++) if (drives & (1u << i)) { char root[4] = { (char)('A' + i), ':', '\\', 0 }; if (GetDriveTypeA(root) == DRIVE_REMOVABLE) { snprintf(d[n].path, MAX_PATH, "%s", root); n++; } }
    HANDLE waits[RT_MAXDIRS + 1]; int nw = 0;
    for (int i = 0; i < n; i++) {
        d[i].h = CreateFileA(d[i].path, FILE_LIST_DIRECTORY, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED, NULL);
        if (d[i].h == INVALID_HANDLE_VALUE) { d[i].h = NULL; continue; }
        d[i].ev = CreateEventA(NULL, TRUE, FALSE, NULL); d[i].ov.hEvent = d[i].ev;
        ReadDirectoryChangesW(d[i].h, d[i].buf, sizeof d[i].buf, TRUE, FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_LAST_WRITE | FILE_NOTIFY_CHANGE_CREATION, NULL, &d[i].ov, NULL);
        waits[nw++] = d[i].ev;
    }
    waits[nw++] = g_rtFileStop;
    char last[MAX_PATH] = ""; DWORD lastTick = 0;
    char msg[260]; snprintf(msg, sizeof msg, "Real-time file protection ON: watching %d location(s) (Downloads, Desktop, Documents, Temp, removable drives).", nw - 1); add_alert("Real-Time", "INFO", msg);
    while (g_rtFileRun) {
        DWORD w = WaitForMultipleObjects((DWORD)nw, waits, FALSE, 1000);
        if (w == WAIT_TIMEOUT) continue;
        if (w >= WAIT_OBJECT_0 + (DWORD)nw - 1) break;
        int idx = -1, k = 0; for (int i = 0; i < n; i++) if (d[i].h) { if ((DWORD)k == w - WAIT_OBJECT_0) { idx = i; break; } k++; }
        if (idx < 0) continue;
        DWORD got = 0; GetOverlappedResult(d[idx].h, &d[idx].ov, &got, FALSE); ResetEvent(d[idx].ev);
        if (got) {
            FILE_NOTIFY_INFORMATION *fn = (FILE_NOTIFY_INFORMATION *)d[idx].buf;
            for (;;) {
                if (fn->Action == FILE_ACTION_ADDED || fn->Action == FILE_ACTION_MODIFIED || fn->Action == FILE_ACTION_RENAMED_NEW_NAME) {
                    char rel[MAX_PATH]; int l = WideCharToMultiByte(CP_ACP, 0, fn->FileName, (int)(fn->FileNameLength / 2), rel, MAX_PATH - 1, NULL, NULL); rel[l > 0 ? l : 0] = 0;
                    char full[MAX_PATH * 2]; snprintf(full, sizeof full, "%s\\%s", d[idx].path, rel);
                    DWORD now = GetTickCount();
                    if (rt_ext_watched(full) && !(strcmp(full, last) == 0 && now - lastTick < 3000) && strstr(full, "kaevex") == NULL) { snprintf(last, sizeof last, "%s", full); lastTick = now; rt_scan_one(full); }
                }
                if (!fn->NextEntryOffset) break; fn = (FILE_NOTIFY_INFORMATION *)((BYTE *)fn + fn->NextEntryOffset);
            }
        }
        if (g_rtFileRun) ReadDirectoryChangesW(d[idx].h, d[idx].buf, sizeof d[idx].buf, TRUE, FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_LAST_WRITE | FILE_NOTIFY_CHANGE_CREATION, NULL, &d[idx].ov, NULL);
    }
    for (int i = 0; i < n; i++) { if (d[i].h) { CancelIo(d[i].h); CloseHandle(d[i].h); } if (d[i].ev) CloseHandle(d[i].ev); }
    return 0;
}

/* ---- Behavior monitor --------------------------------------------------------------------------------------- */
typedef LONG (NTAPI *RtNtQip)(HANDLE, ULONG, PVOID, ULONG, PULONG);
static BOOL rt_cmdline(DWORD pid, char *out, size_t n) {
    out[0] = 0; static RtNtQip fn = NULL; if (!fn) fn = (RtNtQip)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess"); if (!fn) return FALSE;
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid); if (!h) return FALSE;
    BYTE buf[4096]; ULONG need = 0; LONG st = fn(h, 60 /*ProcessCommandLineInformation*/, buf, sizeof buf, &need); CloseHandle(h);
    if (st < 0) return FALSE;
    typedef struct { USHORT Len, Max; PWSTR Buf; } US; US *u = (US *)buf; if (!u->Buf || !u->Len) return FALSE;
    WideCharToMultiByte(CP_ACP, 0, u->Buf, u->Len / 2, out, (int)n - 1, NULL, NULL); out[n - 1] = 0; size_t l = strlen(out); (void)l; return TRUE;
}
static int rt_ieq(const char *a, const char *b) { return _stricmp(a, b) == 0; }
static int rt_in(const char *name, const char **list) { for (int i = 0; list[i]; i++) if (rt_ieq(name, list[i])) return 1; return 0; }
static int rt_has(const char *hay, const char *needle) { char *a = _strdup(hay), *b = _strdup(needle); if (!a || !b) { free(a); free(b); return 0; } for (char *c = a; *c; c++) *c = (char)tolower((unsigned char)*c); for (char *c = b; *c; c++) *c = (char)tolower((unsigned char)*c); int r = strstr(a, b) != NULL; free(a); free(b); return r; }

static void rt_alert_once(const char *sev, const char *key, const char *msg) {
    static char seen[64][96]; static int sn = 0; for (int i = 0; i < 64; i++) if (strcmp(seen[i], key) == 0) return;
    snprintf(seen[sn++ % 64], 96, "%s", key); InterlockedIncrement(&g_rtBehAlerts); add_alert("Behavior", sev, msg);
}

static void rt_inspect(const FwpProc *pr, const FwpProc *all, int nAll) {
    static const char *officeParents[] = { "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "acrord32.exe", "acrobat.exe", "foxitreader.exe", "onenote.exe", NULL };
    static const char *scriptKids[] = { "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", "regsvr32.exe", "rundll32.exe", "bitsadmin.exe", "certutil.exe", "msbuild.exe", NULL };
    char parent[64] = ""; for (int i = 0; i < nAll; i++) if (all[i].pid == pr->ppid) { snprintf(parent, sizeof parent, "%s", all[i].name); break; }
    char cmd[1024]; rt_cmdline(pr->pid, cmd, sizeof cmd); char key[96], m[520];
    InterlockedIncrement(&g_rtProcChecked);
    if (parent[0] && rt_in(parent, officeParents) && rt_in(pr->name, scriptKids)) {
        snprintf(key, sizeof key, "office:%s>%s", parent, pr->name); snprintf(m, sizeof m, "%s started %s (pid %lu) - typical of a malicious document. Command: %.240s", parent, pr->name, (unsigned long)pr->pid, cmd); rt_alert_once("CRITICAL", key, m);
    }
    if (cmd[0]) {
        if (rt_in(pr->name, (const char *[]){ "powershell.exe", "pwsh.exe", NULL }) && (rt_has(cmd, " -enc") || rt_has(cmd, "-encodedcommand") || rt_has(cmd, "downloadstring") || rt_has(cmd, "invoke-expression") || rt_has(cmd, " iex ") || (rt_has(cmd, "-w hidden") && rt_has(cmd, "-nop")))) {
            snprintf(key, sizeof key, "ps:%lu", (unsigned long)pr->pid); snprintf(m, sizeof m, "Suspicious PowerShell (pid %lu, parent %s): %.300s", (unsigned long)pr->pid, parent[0] ? parent : "?", cmd); rt_alert_once("WARNING", key, m); }
        if ((rt_ieq(pr->name, "certutil.exe") && (rt_has(cmd, "-urlcache") || rt_has(cmd, "-decode"))) || (rt_ieq(pr->name, "bitsadmin.exe") && rt_has(cmd, "/transfer")) ||
            (rt_ieq(pr->name, "mshta.exe") && (rt_has(cmd, "http") || rt_has(cmd, "javascript:"))) || (rt_ieq(pr->name, "regsvr32.exe") && rt_has(cmd, "/i:http")) || (rt_ieq(pr->name, "rundll32.exe") && rt_has(cmd, "javascript:"))) {
            snprintf(key, sizeof key, "lol:%lu", (unsigned long)pr->pid); snprintf(m, sizeof m, "Living-off-the-land download/execute pattern: %s (pid %lu): %.300s", pr->name, (unsigned long)pr->pid, cmd); rt_alert_once("CRITICAL", key, m); }
    }
    char path[MAX_PATH]; if (fwp_proc_path(pr->pid, path, sizeof path)) {
        int userDir = rt_has(path, "\\appdata\\local\\temp\\") || rt_has(path, "\\downloads\\") || rt_has(path, "\\appdata\\roaming\\") || rt_has(path, "\\users\\public\\") || rt_has(path, "\\windows\\temp\\");
        if (userDir) {
            wchar_t wp[MAX_PATH]; MultiByteToWideChar(CP_ACP, 0, path, -1, wp, MAX_PATH); char subj[96];
            if (boot_verify_file_signature(wp, subj, sizeof subj) != 1) { snprintf(key, sizeof key, "unsigned:%s", path); snprintf(m, sizeof m, "Unsigned program running from a user-writable folder: %.300s (pid %lu, parent %s)", path, (unsigned long)pr->pid, parent[0] ? parent : "?"); rt_alert_once("WARNING", key, m); }
        }
    }
}

static DWORD WINAPI rt_beh_thread(LPVOID p) {
    (void)p; static FwpProc prev[1024]; static FwpProc cur[1024]; int np = fwp_processes(prev, 1024); (void)np;
    int nPrev = np; add_alert("Real-Time", "INFO", "Behavior monitoring ON: watching new processes (parent/child, command line, unsigned launches).");
    while (g_rtBehRun) {
        if (WaitForSingleObject(g_rtBehStop, 2000) == WAIT_OBJECT_0) break;
        int n = fwp_processes(cur, 1024);
        for (int i = 0; i < n; i++) { int known = 0; for (int k = 0; k < nPrev; k++) if (prev[k].pid == cur[i].pid && strcmp(prev[k].name, cur[i].name) == 0) { known = 1; break; } if (!known) rt_inspect(&cur[i], cur, n); }
        memcpy(prev, cur, sizeof(FwpProc) * (size_t)n); nPrev = n;
    }
    return 0;
}

static void rt_set_file(BOOL on) {
    if (on && InterlockedCompareExchange(&g_rtFileRun, 1, 0) == 0) { g_rtFileStop = CreateEventA(NULL, TRUE, FALSE, NULL); HANDLE t = CreateThread(NULL, 0, rt_file_thread, NULL, 0, NULL); if (t) CloseHandle(t); else InterlockedExchange(&g_rtFileRun, 0); }
    else if (!on && g_rtFileRun) { InterlockedExchange(&g_rtFileRun, 0); if (g_rtFileStop) SetEvent(g_rtFileStop); add_alert("Real-Time", "WARNING", "Real-time file protection turned OFF."); }
}
static void rt_set_behavior(BOOL on) {
    if (on && InterlockedCompareExchange(&g_rtBehRun, 1, 0) == 0) { g_rtBehStop = CreateEventA(NULL, TRUE, FALSE, NULL); HANDLE t = CreateThread(NULL, 0, rt_beh_thread, NULL, 0, NULL); if (t) CloseHandle(t); else InterlockedExchange(&g_rtBehRun, 0); }
    else if (!on && g_rtBehRun) { InterlockedExchange(&g_rtBehRun, 0); if (g_rtBehStop) SetEvent(g_rtBehStop); add_alert("Real-Time", "WARNING", "Behavior monitoring turned OFF."); }
}

#endif /* REALTIME_ENGINE_H */
