/*===========================================================================
 * Kaevex Firewall Pro - fw_pro_engine.h  (Windows layer on top of fw_pro_core.h)
 *
 * Everything here talks to the real Windows Firewall / OS. Nothing is
 * simulated: when a value cannot be obtained it is reported as unavailable.
 * Locale-independent: results are read from the registry and exit codes, never
 * from translated netsh text (the old code broke on non-English Windows).
 *===========================================================================*/
#pragma once
#ifndef FW_PRO_ENGINE_H
#define FW_PRO_ENGINE_H

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <tcpestats.h>
#include <tlhelp32.h>
#include <wincrypt.h>
#include <shlobj.h>
#include <lmcons.h>
#include <stdarg.h>
#include "fw_pro_core.h"

typedef void (*FwpAlertFn)(const char *sev, const char *msg);

/* ---- State ---------------------------------------------------------------- */
static FwpRule          g_fwpRules[FWP_MAX_RULES];
static int              g_fwpCount = 0;
static CRITICAL_SECTION g_fwpCS;
static volatile LONG    g_fwpInit = 0;
static FwpAlertFn       g_fwpAlert = NULL;
static volatile LONG    g_fwpApplying = 0;       /* ignore tamper events caused by ourselves */
static volatile DWORD   g_fwpQuietUntil = 0;
static char             g_fwpDir[MAX_PATH] = "";
static char             g_fwpLastMsg[512] = "";

static void fwp_alert(const char *sev, const char *fmt, ...) {
    char m[400]; va_list ap; va_start(ap, fmt); vsnprintf(m, sizeof m, fmt, ap); va_end(ap);
    if (g_fwpAlert) g_fwpAlert(sev, m);
}

static BOOL fwp_is_admin(void) {
    BOOL r = FALSE; HANDLE t;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &t)) {
        TOKEN_ELEVATION e; DWORD sz;
        if (GetTokenInformation(t, TokenElevation, &e, sizeof e, &sz)) r = e.TokenIsElevated;
        CloseHandle(t);
    }
    return r;
}

static void fwp_init(FwpAlertFn alertFn) {
    if (InterlockedCompareExchange(&g_fwpInit, 1, 0) == 0) {
        InitializeCriticalSection(&g_fwpCS);
        char appdata[MAX_PATH] = "";
        if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, 0, appdata)))
            snprintf(g_fwpDir, sizeof g_fwpDir, "%s\\Kaevex", appdata);
        else snprintf(g_fwpDir, sizeof g_fwpDir, ".");
        CreateDirectoryA(g_fwpDir, NULL);
        char sub[MAX_PATH]; snprintf(sub, sizeof sub, "%s\\fw-snapshots", g_fwpDir); CreateDirectoryA(sub, NULL);
        InterlockedExchange(&g_fwpInit, 2);
    }
    while (g_fwpInit != 2) Sleep(1);
    if (alertFn) g_fwpAlert = alertFn;
}

/* ---- netsh runner (no cmd.exe, absolute path) ---------------------------------- */
/* Returns the netsh exit code, or -1 if it could not be started / timed out. */
static int fwp_netsh(const char *args, char *out, size_t outLen, DWORD timeoutMs) {
    char sysdir[MAX_PATH]; GetSystemDirectoryA(sysdir, sizeof sysdir);
    char cmd[2600];
    if (snprintf(cmd, sizeof cmd, "\"%s\\netsh.exe\" %s", sysdir, args) >= (int)sizeof cmd) return -1;
    HANDLE rd = NULL, wr = NULL; SECURITY_ATTRIBUTES sa = { sizeof sa, NULL, TRUE };
    if (!CreatePipe(&rd, &wr, &sa, 0)) return -1;
    SetHandleInformation(rd, HANDLE_FLAG_INHERIT, 0);
    STARTUPINFOA si; memset(&si, 0, sizeof si); si.cb = sizeof si;
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW; si.wShowWindow = SW_HIDE;
    si.hStdOutput = wr; si.hStdError = wr; si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    PROCESS_INFORMATION pi; memset(&pi, 0, sizeof pi);
    if (!CreateProcessA(NULL, cmd, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        CloseHandle(rd); CloseHandle(wr); return -1;
    }
    CloseHandle(wr);
    size_t total = 0; char tmp[1024]; DWORD got;
    while (ReadFile(rd, tmp, sizeof tmp, &got, NULL) && got) {
        if (out && total + got < outLen) { memcpy(out + total, tmp, got); total += got; }
    }
    if (out && outLen) out[total < outLen ? total : outLen - 1] = 0;
    CloseHandle(rd);
    DWORD w = WaitForSingleObject(pi.hProcess, timeoutMs);
    DWORD code = (DWORD)-1;
    if (w == WAIT_OBJECT_0) GetExitCodeProcess(pi.hProcess, &code); else TerminateProcess(pi.hProcess, 1);
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
    return (w == WAIT_OBJECT_0) ? (int)code : -1;
}

/* ---- Locale-independent firewall state ---------------------------------------------- */
#define FWP_POLICY_KEY "SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy"
/* bit0 domain, bit1 private, bit2 public = profile ON */
static int fwp_profiles_on(void) {
    static const char *names[3] = { "DomainProfile", "StandardProfile", "PublicProfile" };
    int mask = 0;
    for (int i = 0; i < 3; i++) {
        char k[256]; snprintf(k, sizeof k, "%s\\%s", FWP_POLICY_KEY, names[i]);
        HKEY h; DWORD v = 0, sz = sizeof v;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, k, 0, KEY_READ, &h) == ERROR_SUCCESS) {
            if (RegQueryValueExA(h, "EnableFirewall", NULL, NULL, (BYTE *)&v, &sz) == ERROR_SUCCESS && v) mask |= 1 << i;
            RegCloseKey(h);
        }
    }
    return mask;
}

/* Reads the default inbound/outbound action of every profile. Returns 1 if all three agree, writing 1=block/0=allow. */
static int fwp_default_actions(int *inb, int *outb) {
    static const char *names[3] = { "DomainProfile", "StandardProfile", "PublicProfile" };
    int in = -1, out = -1, ok = 1;
    for (int i = 0; i < 3; i++) {
        char k[256]; snprintf(k, sizeof k, "%s\\%s", FWP_POLICY_KEY, names[i]);
        HKEY h; DWORD vi = 0, vo = 0, sz = sizeof vi; int gi = 0, go = 0;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, k, 0, KEY_READ, &h) == ERROR_SUCCESS) {
            sz = sizeof vi; gi = RegQueryValueExA(h, "DefaultInboundAction", NULL, NULL, (BYTE *)&vi, &sz) == ERROR_SUCCESS;
            sz = sizeof vo; go = RegQueryValueExA(h, "DefaultOutboundAction", NULL, NULL, (BYTE *)&vo, &sz) == ERROR_SUCCESS;
            RegCloseKey(h);
        }
        if (!gi) vi = 1; if (!go) vo = 0;             /* Windows defaults when the value is absent: inbound block, outbound allow */
        if (in < 0) in = (int)vi; else if (in != (int)vi) ok = 0;
        if (out < 0) out = (int)vo; else if (out != (int)vo) ok = 0;
    }
    if (inb) *inb = in; if (outb) *outb = out;
    return ok;
}

/* ---- Registry view of installed rules (language independent) -------------------------- */
typedef struct { char name[128]; unsigned hash; int active; } FwpRegRule;

static int fwp_registry_rules(const char *prefix, FwpRegRule *out, int maxOut) {
    HKEY h; int n = 0;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, FWP_POLICY_KEY "\\FirewallRules", 0, KEY_READ, &h) != ERROR_SUCCESS) return 0;
    DWORD vals = 0, maxName = 0, maxData = 0;
    RegQueryInfoKeyA(h, NULL, NULL, NULL, NULL, NULL, NULL, &vals, &maxName, &maxData, NULL, NULL);
    char *vn = (char *)malloc(maxName + 4), *vd = (char *)malloc(maxData + 4);
    if (vn && vd) for (DWORD i = 0; i < vals && n < maxOut; i++) {
        DWORD nl = maxName + 2, dl = maxData + 2, type = 0;
        if (RegEnumValueA(h, i, vn, &nl, NULL, &type, (BYTE *)vd, &dl) != ERROR_SUCCESS || type != REG_SZ) continue;
        vd[dl < maxData + 3 ? dl : maxData + 3] = 0;
        const char *nm = strstr(vd, "|Name=");
        if (!nm) continue;
        nm += 6;
        const char *end = strchr(nm, '|'); size_t len = end ? (size_t)(end - nm) : strlen(nm);
        if (len >= sizeof out[n].name) continue;
        if (prefix && strncmp(nm, prefix, strlen(prefix)) != 0) continue;
        memcpy(out[n].name, nm, len); out[n].name[len] = 0;
        out[n].hash = fwp_hash(vd);
        out[n].active = strstr(vd, "|Active=TRUE|") != NULL;
        n++;
    }
    free(vn); free(vd); RegCloseKey(h);
    return n;
}

/* ---- Policy persistence (TSV, one rule per line) -------------------------------------------- */
#define FWP_FILE_HDR "KAEVEX-FW-POLICY\tv1"

static void fwp_rule_to_line(const FwpRule *r, char *l, size_t n) {
    snprintf(l, n, "%s\t%s\t%d\t%d\t%d\t%d\t%s\t%s\t%s\t%s\t%s\t%d\t%d\t%d\t%d\t%d\t%d\t%s",
             r->name, r->group, r->priority, r->action, r->dir, r->proto, r->program, r->localPorts, r->remotePorts,
             r->remoteAddrs, r->domain, r->ifaceMask, r->profileMask, r->schedDays, r->schedStart, r->schedEnd,
             r->enabled, r->progHash);
}

/* Parses one tab separated line; returns 1 if the rule is syntactically valid AND passes validation. */
static int fwp_line_to_rule(const char *line, FwpRule *r) {
    char buf[1600]; strncpy(buf, line, sizeof buf - 1); buf[sizeof buf - 1] = 0;
    char *f[18]; int nf = 0; char *p = buf;
    while (nf < 18) { f[nf++] = p; char *t = strchr(p, '\t'); if (!t) break; *t = 0; p = t + 1; }
    char *nl = strpbrk(f[nf - 1], "\r\n"); if (nl) *nl = 0;
    if (nf != 18) return 0;
    memset(r, 0, sizeof *r);
    snprintf(r->name, sizeof r->name, "%s", f[0]);   snprintf(r->group, sizeof r->group, "%s", f[1]);
    r->priority = atoi(f[2]); r->action = atoi(f[3]); r->dir = atoi(f[4]); r->proto = atoi(f[5]);
    snprintf(r->program, sizeof r->program, "%s", f[6]);
    snprintf(r->localPorts, sizeof r->localPorts, "%s", f[7]); snprintf(r->remotePorts, sizeof r->remotePorts, "%s", f[8]);
    snprintf(r->remoteAddrs, sizeof r->remoteAddrs, "%s", f[9]); snprintf(r->domain, sizeof r->domain, "%s", f[10]);
    r->ifaceMask = atoi(f[11]); r->profileMask = atoi(f[12]); r->schedDays = atoi(f[13]);
    r->schedStart = atoi(f[14]); r->schedEnd = atoi(f[15]); r->enabled = atoi(f[16]);
    snprintf(r->progHash, sizeof r->progHash, "%s", f[17]);
    return fwp_validate(r) == NULL;
}

static void fwp_policy_path(char *out, size_t n) { snprintf(out, n, "%s\\fw_policy.tsv", g_fwpDir); }

static BOOL fwp_policy_save(void) {
    char path[MAX_PATH], tmp[MAX_PATH]; fwp_policy_path(path, sizeof path); snprintf(tmp, sizeof tmp, "%s.tmp", path);
    FILE *f = fopen(tmp, "wb"); if (!f) return FALSE;
    fprintf(f, "%s\n", FWP_FILE_HDR);
    EnterCriticalSection(&g_fwpCS);
    for (int i = 0; i < g_fwpCount; i++) { char l[1600]; fwp_rule_to_line(&g_fwpRules[i], l, sizeof l); fprintf(f, "%s\n", l); }
    LeaveCriticalSection(&g_fwpCS);
    fclose(f);
    return MoveFileExA(tmp, path, MOVEFILE_REPLACE_EXISTING);
}

/* text -> rules. replace=1 clears the current policy first. Returns imported count; *rejected = invalid lines. */
static int fwp_policy_import_text(const char *text, int replace, int *rejected) {
    int ok = 0, bad = 0; char line[1700];
    EnterCriticalSection(&g_fwpCS);
    if (replace) g_fwpCount = 0;
    const char *p = text;
    while (*p) {
        const char *e = strchr(p, '\n'); size_t n = e ? (size_t)(e - p) : strlen(p);
        if (n >= sizeof line) n = sizeof line - 1;
        memcpy(line, p, n); line[n] = 0;
        p = e ? e + 1 : p + strlen(p);
        if (!line[0] || strncmp(line, "KAEVEX-FW-POLICY", 16) == 0) continue;
        FwpRule r;
        if (fwp_line_to_rule(line, &r) && g_fwpCount < FWP_MAX_RULES) {
            int dup = -1; for (int i = 0; i < g_fwpCount; i++) if (strcmp(g_fwpRules[i].name, r.name) == 0) dup = i;
            if (dup >= 0) g_fwpRules[dup] = r; else g_fwpRules[g_fwpCount++] = r;
            ok++;
        } else bad++;
    }
    LeaveCriticalSection(&g_fwpCS);
    if (rejected) *rejected = bad;
    return ok;
}

static BOOL fwp_policy_load(void) {
    char path[MAX_PATH]; fwp_policy_path(path, sizeof path);
    FILE *f = fopen(path, "rb"); if (!f) return FALSE;
    fseek(f, 0, SEEK_END); long sz = ftell(f); fseek(f, 0, SEEK_SET);
    if (sz <= 0 || sz > 4 * 1024 * 1024) { fclose(f); return FALSE; }
    char *t = (char *)malloc((size_t)sz + 1); if (!t) { fclose(f); return FALSE; }
    size_t rd = fread(t, 1, (size_t)sz, f); t[rd] = 0; fclose(f);
    int bad = 0; fwp_policy_import_text(t, 1, &bad); free(t);
    return TRUE;
}

/* Serialized policy (for export / pushing to cluster peers). Caller frees. */
static char *fwp_policy_export_text(void) {
    size_t cap = 4096 + (size_t)g_fwpCount * 1700; char *o = (char *)malloc(cap); if (!o) return NULL;
    size_t w = (size_t)snprintf(o, cap, "%s\n", FWP_FILE_HDR);
    EnterCriticalSection(&g_fwpCS);
    for (int i = 0; i < g_fwpCount; i++) { char l[1600]; fwp_rule_to_line(&g_fwpRules[i], l, sizeof l); w += (size_t)snprintf(o + w, cap - w, "%s\n", l); }
    LeaveCriticalSection(&g_fwpCS);
    return o;
}

/* ---- SHA-256 of a file (program-change guard) -------------------------------------------------- */
static BOOL fwp_sha256_file(const char *path, char hex[65]) {
    hex[0] = 0;
    HANDLE f = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE) return FALSE;
    HCRYPTPROV pv = 0; HCRYPTHASH hh = 0; BOOL ok = FALSE;
    if (CryptAcquireContextA(&pv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT) && CryptCreateHash(pv, CALG_SHA_256, 0, 0, &hh)) {
        BYTE buf[65536]; DWORD rd; ok = TRUE;
        while (ReadFile(f, buf, sizeof buf, &rd, NULL) && rd) if (!CryptHashData(hh, buf, rd, 0)) { ok = FALSE; break; }
        BYTE d[32]; DWORD dl = 32;
        if (ok && CryptGetHashParam(hh, HP_HASHVAL, d, &dl, 0)) for (int i = 0; i < 32; i++) sprintf(hex + i * 2, "%02x", d[i]); else ok = FALSE;
    }
    if (hh) CryptDestroyHash(hh); if (pv) CryptReleaseContext(pv, 0); CloseHandle(f);
    return ok;
}

/* ---- Domain resolution --------------------------------------------------------------------------- */
/* Resolves domain to a comma list of IPv4/IPv6 addresses (max ~20). */
static BOOL fwp_resolve_domain(const char *domain, char *out, size_t n) {
    out[0] = 0;
    ADDRINFOA hints; memset(&hints, 0, sizeof hints); hints.ai_socktype = SOCK_STREAM;
    ADDRINFOA *res = NULL;
    if (getaddrinfo(domain, NULL, &hints, &res) != 0 || !res) return FALSE;
    size_t w = 0; int cnt = 0;
    for (ADDRINFOA *a = res; a && cnt < 20; a = a->ai_next) {
        char ip[64] = "";
        if (a->ai_family == AF_INET) inet_ntop(AF_INET, &((struct sockaddr_in *)a->ai_addr)->sin_addr, ip, sizeof ip);
        else if (a->ai_family == AF_INET6) inet_ntop(AF_INET6, &((struct sockaddr_in6 *)a->ai_addr)->sin6_addr, ip, sizeof ip);
        else continue;
        if (!fwp_valid_addrs(ip) || strstr(out, ip)) continue;
        int k = snprintf(out + w, n - w, "%s%s", w ? "," : "", ip);
        if (k < 0 || w + (size_t)k >= n) break;
        w += (size_t)k; cnt++;
    }
    freeaddrinfo(res);
    return w > 0;
}

/* ---- Snapshots / rollback ---------------------------------------------------------------------------- */
static BOOL fwp_snapshot(char *outPath, size_t n, const char *tag) {
    SYSTEMTIME t; GetLocalTime(&t);
    char safeTag[32] = ""; for (int i = 0; tag && tag[i] && i < 24; i++) safeTag[i] = isalnum((unsigned char)tag[i]) ? tag[i] : '_';
    char path[MAX_PATH];
    snprintf(path, sizeof path, "%s\\fw-snapshots\\%04d%02d%02d-%02d%02d%02d-%s.wfw", g_fwpDir, t.wYear, t.wMonth, t.wDay, t.wHour, t.wMinute, t.wSecond, safeTag[0] ? safeTag : "manual");
    char args[600]; snprintf(args, sizeof args, "advfirewall export \"%s\"", path);
    int rc = fwp_netsh(args, NULL, 0, 20000);
    if (rc != 0) return FALSE;
    if (GetFileAttributesA(path) == INVALID_FILE_ATTRIBUTES) return FALSE;     /* verify, do not trust the exit code */
    if (outPath) snprintf(outPath, n, "%s", path);
    /* keep newest 20 */
    char pat[MAX_PATH]; snprintf(pat, sizeof pat, "%s\\fw-snapshots\\*.wfw", g_fwpDir);
    char names[64][MAX_PATH]; int cnt = 0; WIN32_FIND_DATAA fd; HANDLE h = FindFirstFileA(pat, &fd);
    if (h != INVALID_HANDLE_VALUE) { do { if (cnt < 64) snprintf(names[cnt++], MAX_PATH, "%s", fd.cFileName); } while (FindNextFileA(h, &fd)); FindClose(h); }
    for (int i = 0; i < cnt; i++) for (int j = i + 1; j < cnt; j++) if (strcmp(names[i], names[j]) < 0) { char tmp[MAX_PATH]; strcpy(tmp, names[i]); strcpy(names[i], names[j]); strcpy(names[j], tmp); }
    for (int i = 20; i < cnt; i++) { char d[MAX_PATH]; snprintf(d, sizeof d, "%s\\fw-snapshots\\%s", g_fwpDir, names[i]); DeleteFileA(d); }
    return TRUE;
}

static int fwp_list_snapshots(char (*names)[MAX_PATH], int maxN) {
    char pat[MAX_PATH]; snprintf(pat, sizeof pat, "%s\\fw-snapshots\\*.wfw", g_fwpDir);
    int cnt = 0; WIN32_FIND_DATAA fd; HANDLE h = FindFirstFileA(pat, &fd);
    if (h != INVALID_HANDLE_VALUE) { do { if (cnt < maxN) snprintf(names[cnt++], MAX_PATH, "%s", fd.cFileName); } while (FindNextFileA(h, &fd)); FindClose(h); }
    for (int i = 0; i < cnt; i++) for (int j = i + 1; j < cnt; j++) if (strcmp(names[i], names[j]) < 0) { char tmp[MAX_PATH]; strcpy(tmp, names[i]); strcpy(names[i], names[j]); strcpy(names[j], tmp); }
    return cnt;
}

static BOOL fwp_restore_snapshot(const char *fileName) {
    for (const char *c = fileName; *c; c++) if (*c == '\\' || *c == '/' || *c == '"' || *c == ':') return FALSE;
    char args[700]; snprintf(args, sizeof args, "advfirewall import \"%s\\fw-snapshots\\%s\"", g_fwpDir, fileName);
    InterlockedExchange(&g_fwpApplying, 1);
    int rc = fwp_netsh(args, NULL, 0, 30000);
    g_fwpQuietUntil = GetTickCount() + 4000; InterlockedExchange(&g_fwpApplying, 0);
    return rc == 0;
}

/* ---- Guarded changes: auto-rollback unless confirmed ---------------------------------------------------- */
static HANDLE          g_fwpGuardEvt = NULL;
static volatile LONG   g_fwpGuardActive = 0;
static volatile DWORD  g_fwpGuardDeadline = 0;
static char            g_fwpGuardSnap[MAX_PATH];

static DWORD WINAPI fwp_guard_thread(LPVOID p) {
    (void)p;
    DWORD w = WaitForSingleObject(g_fwpGuardEvt, g_fwpGuardDeadline - GetTickCount());
    if (w == WAIT_TIMEOUT) {
        const char *fn = strrchr(g_fwpGuardSnap, '\\'); fn = fn ? fn + 1 : g_fwpGuardSnap;
        BOOL ok = fwp_restore_snapshot(fn);
        fwp_alert(ok ? "WARNING" : "CRITICAL", ok ? "Firewall change was not confirmed in time - automatically rolled back." : "Auto-rollback FAILED - restore a snapshot manually.");
    }
    InterlockedExchange(&g_fwpGuardActive, 0);
    return 0;
}

static BOOL fwp_guard_begin(const char *snapPath, int seconds) {
    if (InterlockedCompareExchange(&g_fwpGuardActive, 1, 0) != 0) return FALSE;
    if (!g_fwpGuardEvt) g_fwpGuardEvt = CreateEventA(NULL, TRUE, FALSE, NULL);
    ResetEvent(g_fwpGuardEvt);
    snprintf(g_fwpGuardSnap, sizeof g_fwpGuardSnap, "%s", snapPath);
    g_fwpGuardDeadline = GetTickCount() + (DWORD)seconds * 1000;
    HANDLE t = CreateThread(NULL, 0, fwp_guard_thread, NULL, 0, NULL);
    if (!t) { InterlockedExchange(&g_fwpGuardActive, 0); return FALSE; }
    CloseHandle(t);
    return TRUE;
}
static void fwp_guard_confirm(void) { if (g_fwpGuardActive && g_fwpGuardEvt) SetEvent(g_fwpGuardEvt); }
static int  fwp_guard_remaining(void) { if (!g_fwpGuardActive) return 0; int r = (int)((long)g_fwpGuardDeadline - (long)GetTickCount()) / 1000; return r > 0 ? r : 0; }

/* ---- Apply policy to Windows Firewall --------------------------------------------------------------------- */
static void fwp_delete_by_name(const char *name) {
    char a[400]; if (!fwp_safe_name(name) && strncmp(name, "Kaevex-FW-", 10) != 0) return;
    for (const char *c = name; *c; c++) if (*c == '"' || *c == '&' || *c == '|') return;
    snprintf(a, sizeof a, "advfirewall firewall delete rule name=\"%s\"", name);
    fwp_netsh(a, NULL, 0, 15000);
}

typedef struct { int added, failed, deleted, skippedOff; char firstError[200]; } FwpApplyResult;

static void fwp_apply_one(const FwpRule *r, FwpApplyResult *res) {
    char addrs[300] = "";
    if (r->domain[0]) {
        if (!fwp_resolve_domain(r->domain, addrs, sizeof addrs)) {
            res->failed++; if (!res->firstError[0]) snprintf(res->firstError, sizeof res->firstError, "%s: cannot resolve %s", r->name, r->domain);
            return;
        }
    }
    FwpRule copy = *r;
    time_t now = time(NULL); struct tm tmv; localtime_s(&tmv, &now);
    if (!fwp_sched_active(&copy, &tmv)) copy.enabled = 0;        /* outside its schedule: installed but disabled */
    for (int d = FWP_IN; d <= FWP_OUT; d++) {
        if (r->dir != FWP_BOTH && r->dir != d) continue;
        char args[1900];
        if (!fwp_build_add(&copy, d, addrs, args, sizeof args)) { res->failed++; if (!res->firstError[0]) snprintf(res->firstError, sizeof res->firstError, "%s: rejected by validation", r->name); continue; }
        if (fwp_netsh(args, NULL, 0, 20000) == 0) res->added++;
        else { res->failed++; if (!res->firstError[0]) snprintf(res->firstError, sizeof res->firstError, "%s: netsh failed (need Administrator?)", r->name); }
    }
}

/* Removes every Kaevex-FW-* rule that is currently installed (found via registry). */
static int fwp_remove_all_managed(void) {
    static FwpRegRule rr[FWP_MAX_RULES * 2];
    int n = fwp_registry_rules("Kaevex-FW-", rr, FWP_MAX_RULES * 2), d = 0;
    for (int i = 0; i < n; i++) { fwp_delete_by_name(rr[i].name); d++; }
    return d;
}

/* Full apply: snapshot -> remove old managed rules -> add current policy. Returns TRUE if nothing failed. */
static BOOL fwp_apply_all(FwpApplyResult *res, char *snapOut, size_t snapN) {
    FwpApplyResult local; if (!res) res = &local; memset(res, 0, sizeof *res);
    if (!fwp_is_admin()) { snprintf(res->firstError, sizeof res->firstError, "Administrator rights are required to change firewall rules."); res->failed = 1; return FALSE; }
    char snap[MAX_PATH] = "";
    if (!fwp_snapshot(snap, sizeof snap, "before-apply")) { snprintf(res->firstError, sizeof res->firstError, "Could not create a safety snapshot - aborted, nothing changed."); res->failed = 1; return FALSE; }
    if (snapOut) snprintf(snapOut, snapN, "%s", snap);
    InterlockedExchange(&g_fwpApplying, 1);
    res->deleted = fwp_remove_all_managed();
    EnterCriticalSection(&g_fwpCS);
    FwpRule *copy = (FwpRule *)malloc(sizeof(FwpRule) * (size_t)(g_fwpCount ? g_fwpCount : 1)); int n = g_fwpCount;
    if (copy) memcpy(copy, g_fwpRules, sizeof(FwpRule) * (size_t)n);
    LeaveCriticalSection(&g_fwpCS);
    for (int i = 0; copy && i < n; i++) { if (!copy[i].enabled) { res->skippedOff++; } fwp_apply_one(&copy[i], res); }
    free(copy);
    {   /* verification: netsh said "ok" - confirm the rules really exist in the firewall store */
        static FwpRegRule chk[FWP_MAX_RULES * 2];
        int present = fwp_registry_rules("Kaevex-FW-", chk, FWP_MAX_RULES * 2);
        if (present < res->added) {
            res->failed += res->added - present;
            snprintf(res->firstError, sizeof res->firstError, "netsh reported success but only %d of %d rules exist in the firewall store (not applied).", present, res->added);
            res->added = present;
        }
    }
    g_fwpQuietUntil = GetTickCount() + 4000; InterlockedExchange(&g_fwpApplying, 0);
    return res->failed == 0;
}

/* ---- Real emergency lockdown ---------------------------------------------------------------------------------- */
/* Blocks all inbound and outbound traffic, keeping ONE inbound hole for the Kaevex API port from the local subnet
 * so the host can still be unlocked remotely (replies to allowed inbound sessions are permitted by the stateful firewall). */
static BOOL fwp_lockdown(BOOL on, int apiPort, char *msg, size_t msgN) {
    if (!fwp_is_admin()) { snprintf(msg, msgN, "Administrator rights required."); return FALSE; }
    InterlockedExchange(&g_fwpApplying, 1);
    BOOL ok = TRUE;
    if (on) {
        char snap[MAX_PATH]; fwp_snapshot(snap, sizeof snap, "before-lockdown");
        char a[400];
        fwp_delete_by_name("Kaevex-Lockdown-API");
        snprintf(a, sizeof a, "advfirewall firewall add rule name=\"Kaevex-Lockdown-API\" dir=in action=allow enable=yes protocol=tcp localport=%d remoteip=LocalSubnet profile=any", apiPort);
        ok = fwp_netsh(a, NULL, 0, 15000) == 0;
        ok = ok && fwp_netsh("advfirewall set allprofiles state on", NULL, 0, 15000) == 0;
        ok = ok && fwp_netsh("advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound", NULL, 0, 15000) == 0;
        int di = 0, dout = 0; int agree = fwp_default_actions(&di, &dout);
        if (ok && !(agree && di == 1 && dout == 1)) ok = FALSE;      /* verified in the registry, not just the exit code */
        snprintf(msg, msgN, ok ? "LOCKDOWN ACTIVE (verified): all inbound/outbound blocked; only the Kaevex API port from the local subnet is open." : "Lockdown NOT confirmed: the firewall's default policy is still not 'block in + block out'. Check administrator rights / Group Policy.");
    } else {
        ok = fwp_netsh("advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound", NULL, 0, 15000) == 0;
        fwp_delete_by_name("Kaevex-Lockdown-API");
        int di = 0, dout = 0; int agree = fwp_default_actions(&di, &dout);
        if (ok && !(agree && dout == 0)) ok = FALSE;
        snprintf(msg, msgN, ok ? "Lockdown lifted (verified): default policy restored (inbound blocked, outbound allowed)." : "Could not confirm the default policy was restored - check the firewall settings manually.");
    }
    g_fwpQuietUntil = GetTickCount() + 4000; InterlockedExchange(&g_fwpApplying, 0);
    return ok;
}

/* ---- Logging (pfirewall.log) --------------------------------------------------------------------------------------- */
static BOOL fwp_enable_logging(void) {
    if (!fwp_is_admin()) return FALSE;
    return fwp_netsh("advfirewall set allprofiles logging allowedconnections enable", NULL, 0, 15000) == 0 &&
           fwp_netsh("advfirewall set allprofiles logging droppedconnections enable", NULL, 0, 15000) == 0 &&
           fwp_netsh("advfirewall set allprofiles logging maxfilesize 16384", NULL, 0, 15000) == 0;
}

static void fwp_log_path(char *out, size_t n) {
    char sys[MAX_PATH]; GetSystemDirectoryA(sys, sizeof sys);
    snprintf(out, n, "%s\\LogFiles\\Firewall\\pfirewall.log", sys);
}

/* Reads the last ~2 MB of the log, newest entries last. Returns number of parsed entries (<= maxN). */
static int fwp_read_log(FwpLogEntry *out, int maxN) {
    char path[MAX_PATH]; fwp_log_path(path, sizeof path);
    HANDLE f = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, 0, NULL);
    if (f == INVALID_HANDLE_VALUE) return -1;                       /* -1 = log not available */
    LARGE_INTEGER sz; GetFileSizeEx(f, &sz);
    const LONGLONG window = 2 * 1024 * 1024; LONGLONG off = sz.QuadPart > window ? sz.QuadPart - window : 0;
    LARGE_INTEGER li; li.QuadPart = off; SetFilePointerEx(f, li, NULL, FILE_BEGIN);
    DWORD want = (DWORD)(sz.QuadPart - off), rd = 0;
    char *buf = (char *)malloc(want + 1); if (!buf) { CloseHandle(f); return 0; }
    ReadFile(f, buf, want, &rd, NULL); buf[rd] = 0; CloseHandle(f);
    int n = 0; char *p = buf; if (off) { char *nl = strchr(p, '\n'); if (nl) p = nl + 1; }
    FwpLogEntry *ring = out;
    while (*p) {
        char *e = strchr(p, '\n'); if (e) *e = 0;
        FwpLogEntry ent;
        if (fwp_parse_log_line(p, &ent)) {
            if (n < maxN) ring[n++] = ent; else { memmove(ring, ring + 1, sizeof(FwpLogEntry) * (size_t)(maxN - 1)); ring[maxN - 1] = ent; }
        }
        if (!e) break; p = e + 1;
    }
    free(buf);
    return n;
}

/* ---- Processes: names, parents, tree ----------------------------------------------------------------------------------- */
typedef struct { unsigned pid, ppid; char name[64]; } FwpProc;
static int fwp_processes(FwpProc *out, int maxN) {
    HANDLE s = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0); if (s == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32 pe; pe.dwSize = sizeof pe; int n = 0;
    if (Process32First(s, &pe)) do {
        if (n >= maxN) break;
        out[n].pid = pe.th32ProcessID; out[n].ppid = pe.th32ParentProcessID;
        snprintf(out[n].name, sizeof out[n].name, "%s", pe.szExeFile); n++;
    } while (Process32Next(s, &pe));
    CloseHandle(s);
    return n;
}

static BOOL fwp_proc_path(unsigned pid, char *out, size_t n) {
    out[0] = 0;
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid); if (!h) return FALSE;
    DWORD sz = (DWORD)n; BOOL ok = QueryFullProcessImageNameA(h, 0, out, &sz); CloseHandle(h);
    return ok;
}

static BOOL fwp_proc_user(unsigned pid, char *out, size_t n) {
    out[0] = 0;
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid); if (!h) return FALSE;
    HANDLE tok = NULL; BOOL ok = FALSE;
    if (OpenProcessToken(h, TOKEN_QUERY, &tok)) {
        BYTE buf[256]; DWORD rl = 0;
        if (GetTokenInformation(tok, TokenUser, buf, sizeof buf, &rl)) {
            char nm[128], dom[128]; DWORD nl = sizeof nm, dl = sizeof dom; SID_NAME_USE use;
            if (LookupAccountSidA(NULL, ((TOKEN_USER *)buf)->User.Sid, nm, &nl, dom, &dl, &use)) { snprintf(out, n, "%s\\%s", dom, nm); ok = TRUE; }
        }
        CloseHandle(tok);
    }
    CloseHandle(h); return ok;
}

/* ---- Reverse DNS cache (background resolution, UI never blocks) --------------------------------------------------------------- */
#define FWP_DNS_CACHE 512
typedef struct { char ip[48]; char host[128]; int state; /*0 empty,1 pending,2 done,3 failed*/ } FwpDnsEnt;
static FwpDnsEnt        g_fwpDns[FWP_DNS_CACHE];
static CRITICAL_SECTION g_fwpDnsCS;
static volatile LONG    g_fwpDnsInit = 0, g_fwpDnsThread = 0;

static DWORD WINAPI fwp_dns_worker(LPVOID p) {
    (void)p;
    for (int idle = 0; idle < 40;) {
        char ip[48] = ""; int idx = -1;
        EnterCriticalSection(&g_fwpDnsCS);
        for (int i = 0; i < FWP_DNS_CACHE; i++) if (g_fwpDns[i].state == 1) { idx = i; strcpy(ip, g_fwpDns[i].ip); break; }
        LeaveCriticalSection(&g_fwpDnsCS);
        if (idx < 0) { Sleep(250); idle++; continue; }
        idle = 0;
        char host[128] = ""; struct sockaddr_storage ss; memset(&ss, 0, sizeof ss); int sl = 0;
        struct sockaddr_in *a4 = (struct sockaddr_in *)&ss; struct sockaddr_in6 *a6 = (struct sockaddr_in6 *)&ss;
        if (inet_pton(AF_INET, ip, &a4->sin_addr) == 1) { a4->sin_family = AF_INET; sl = sizeof *a4; }
        else if (inet_pton(AF_INET6, ip, &a6->sin6_addr) == 1) { a6->sin6_family = AF_INET6; sl = sizeof *a6; }
        int ok = sl && getnameinfo((struct sockaddr *)&ss, sl, host, sizeof host, NULL, 0, NI_NAMEREQD) == 0;
        EnterCriticalSection(&g_fwpDnsCS);
        if (strcmp(g_fwpDns[idx].ip, ip) == 0) { g_fwpDns[idx].state = ok ? 2 : 3; if (ok) snprintf(g_fwpDns[idx].host, sizeof g_fwpDns[idx].host, "%s", host); }
        LeaveCriticalSection(&g_fwpDnsCS);
    }
    InterlockedExchange(&g_fwpDnsThread, 0);
    return 0;
}

/* Returns cached host name or "" (and queues a lookup). */
static const char *fwp_dns_lookup(const char *ip, char *buf, size_t n) {
    if (InterlockedCompareExchange(&g_fwpDnsInit, 1, 0) == 0) InitializeCriticalSection(&g_fwpDnsCS);
    buf[0] = 0;
    if (!ip || !ip[0] || strcmp(ip, "0.0.0.0") == 0 || strcmp(ip, "::") == 0) return buf;
    EnterCriticalSection(&g_fwpDnsCS);
    int slot = -1, freeSlot = -1;
    for (int i = 0; i < FWP_DNS_CACHE; i++) {
        if (g_fwpDns[i].state && strcmp(g_fwpDns[i].ip, ip) == 0) { slot = i; break; }
        if (!g_fwpDns[i].state && freeSlot < 0) freeSlot = i;
    }
    if (slot >= 0) { if (g_fwpDns[slot].state == 2) snprintf(buf, n, "%s", g_fwpDns[slot].host); }
    else {
        if (freeSlot < 0) freeSlot = (int)(fwp_hash(ip) % FWP_DNS_CACHE);
        snprintf(g_fwpDns[freeSlot].ip, sizeof g_fwpDns[freeSlot].ip, "%s", ip); g_fwpDns[freeSlot].host[0] = 0; g_fwpDns[freeSlot].state = 1;
        if (InterlockedCompareExchange(&g_fwpDnsThread, 1, 0) == 0) { HANDLE t = CreateThread(NULL, 0, fwp_dns_worker, NULL, 0, NULL); if (t) CloseHandle(t); else InterlockedExchange(&g_fwpDnsThread, 0); }
    }
    LeaveCriticalSection(&g_fwpDnsCS);
    return buf;
}

/* ---- Live connections with attribution -------------------------------------------------------------------------------------------- */
typedef struct {
    unsigned pid, ppid;
    char proc[64], path[MAX_PATH], user[96];
    int  proto;                 /* FWP_TCP / FWP_UDP */
    int  v6;
    char localIp[48], remoteIp[48];
    int  localPort, remotePort;
    char state[16];
    char host[128];             /* reverse DNS if known */
    char rule[96];              /* matching Kaevex rule or "(default)" */
    int  action;                /* what the Kaevex policy says */
    int  inbound;
    long long bytesIn, bytesOut;/* -1 = unavailable (needs admin; counted since monitoring began) */
} FwpLive;

#define FWP_MAX_LIVE 2048
static const char *fwp_tcp_state(DWORD s) {
    static const char *n[] = { "", "CLOSED", "LISTEN", "SYN_SENT", "SYN_RCVD", "ESTAB", "FIN_WAIT1", "FIN_WAIT2", "CLOSE_WAIT", "CLOSING", "LAST_ACK", "TIME_WAIT", "DELETE_TCB" };
    return s < 13 ? n[s] : "?";
}

static void fwp_estats(PMIB_TCPROW row, long long *in, long long *out) {
    *in = *out = -1;
    TCP_ESTATS_DATA_RW_v0 rw; rw.EnableCollection = TRUE;
    SetPerTcpConnectionEStats(row, TcpConnectionEstatsData, (PUCHAR)&rw, 0, sizeof rw, 0);   /* idempotent */
    TCP_ESTATS_DATA_ROD_v0 rod; memset(&rod, 0, sizeof rod);
    if (GetPerTcpConnectionEStats(row, TcpConnectionEstatsData, NULL, 0, 0, NULL, 0, 0, (PUCHAR)&rod, 0, sizeof rod) == NO_ERROR) {
        *in = (long long)rod.DataBytesIn; *out = (long long)rod.DataBytesOut;
    }
}

static int fwp_live_snapshot(FwpLive *out, int maxN, BOOL wantBytes) {
    int n = 0;
    FwpProc procs[1024]; int np = fwp_processes(procs, 1024);
    time_t now = time(NULL); struct tm tmv; localtime_s(&tmv, &now);
    FwpRule *pol = (FwpRule *)malloc(sizeof(FwpRule) * FWP_MAX_RULES); int nr = 0;
    if (pol) { EnterCriticalSection(&g_fwpCS); nr = g_fwpCount; memcpy(pol, g_fwpRules, sizeof(FwpRule) * (size_t)nr); LeaveCriticalSection(&g_fwpCS); }

    /* listening (pid,port) pairs decide direction */
    struct { unsigned pid; int port; } listen[512]; int nl = 0;
    DWORD sz = 0; GetExtendedTcpTable(NULL, &sz, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    MIB_TCPTABLE_OWNER_PID *t4 = (MIB_TCPTABLE_OWNER_PID *)malloc(sz ? sz : 1);
    if (t4 && GetExtendedTcpTable(t4, &sz, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR)
        for (DWORD i = 0; i < t4->dwNumEntries && nl < 512; i++) if (t4->table[i].dwState == MIB_TCP_STATE_LISTEN) { listen[nl].pid = t4->table[i].dwOwningPid; listen[nl].port = ntohs((USHORT)t4->table[i].dwLocalPort); nl++; }
    #define FILL_COMMON(L, pidv) do { \
        L->pid = (pidv); L->ppid = 0; strcpy(L->proc, "?"); \
        for (int k_ = 0; k_ < np; k_++) if (procs[k_].pid == (pidv)) { L->ppid = procs[k_].ppid; snprintf(L->proc, sizeof L->proc, "%s", procs[k_].name); break; } \
        if ((pidv) == 0) strcpy(L->proc, "System Idle"); else if ((pidv) == 4) strcpy(L->proc, "System"); \
        fwp_proc_path((pidv), L->path, sizeof L->path); fwp_proc_user((pidv), L->user, sizeof L->user); } while (0)

    if (t4 && n < maxN) for (DWORD i = 0; i < t4->dwNumEntries && n < maxN; i++) {
        MIB_TCPROW_OWNER_PID *r = &t4->table[i]; FwpLive *L = &out[n]; memset(L, 0, sizeof *L);
        FILL_COMMON(L, r->dwOwningPid);
        L->proto = FWP_TCP; inet_ntop(AF_INET, &r->dwLocalAddr, L->localIp, sizeof L->localIp); inet_ntop(AF_INET, &r->dwRemoteAddr, L->remoteIp, sizeof L->remoteIp);
        L->localPort = ntohs((USHORT)r->dwLocalPort); L->remotePort = ntohs((USHORT)r->dwRemotePort);
        snprintf(L->state, sizeof L->state, "%s", fwp_tcp_state(r->dwState));
        int isl = 0; for (int q = 0; q < nl; q++) if (listen[q].pid == r->dwOwningPid && listen[q].port == L->localPort) isl = 1;
        L->inbound = (r->dwState == MIB_TCP_STATE_LISTEN) || isl;
        L->bytesIn = L->bytesOut = -1;
        if (wantBytes && r->dwState == MIB_TCP_STATE_ESTAB) { MIB_TCPROW row; row.dwState = r->dwState; row.dwLocalAddr = r->dwLocalAddr; row.dwLocalPort = r->dwLocalPort; row.dwRemoteAddr = r->dwRemoteAddr; row.dwRemotePort = r->dwRemotePort; fwp_estats(&row, &L->bytesIn, &L->bytesOut); }
        n++;
    }
    sz = 0; GetExtendedTcpTable(NULL, &sz, FALSE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0);
    MIB_TCP6TABLE_OWNER_PID *t6 = (MIB_TCP6TABLE_OWNER_PID *)malloc(sz ? sz : 1);
    if (t6 && GetExtendedTcpTable(t6, &sz, FALSE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR)
        for (DWORD i = 0; i < t6->dwNumEntries && n < maxN; i++) {
            MIB_TCP6ROW_OWNER_PID *r = &t6->table[i]; FwpLive *L = &out[n]; memset(L, 0, sizeof *L);
            FILL_COMMON(L, r->dwOwningPid);
            L->proto = FWP_TCP; L->v6 = 1; inet_ntop(AF_INET6, r->ucLocalAddr, L->localIp, sizeof L->localIp); inet_ntop(AF_INET6, r->ucRemoteAddr, L->remoteIp, sizeof L->remoteIp);
            L->localPort = ntohs((USHORT)r->dwLocalPort); L->remotePort = ntohs((USHORT)r->dwRemotePort);
            snprintf(L->state, sizeof L->state, "%s", fwp_tcp_state(r->dwState));
            L->inbound = r->dwState == MIB_TCP_STATE_LISTEN; L->bytesIn = L->bytesOut = -1; n++;
        }
    sz = 0; GetExtendedUdpTable(NULL, &sz, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0);
    MIB_UDPTABLE_OWNER_PID *u4 = (MIB_UDPTABLE_OWNER_PID *)malloc(sz ? sz : 1);
    if (u4 && GetExtendedUdpTable(u4, &sz, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0) == NO_ERROR)
        for (DWORD i = 0; i < u4->dwNumEntries && n < maxN; i++) {
            MIB_UDPROW_OWNER_PID *r = &u4->table[i]; FwpLive *L = &out[n]; memset(L, 0, sizeof *L);
            FILL_COMMON(L, r->dwOwningPid);
            L->proto = FWP_UDP; inet_ntop(AF_INET, &r->dwLocalAddr, L->localIp, sizeof L->localIp); strcpy(L->remoteIp, "*");
            L->localPort = ntohs((USHORT)r->dwLocalPort); strcpy(L->state, "UDP"); L->inbound = 1; L->bytesIn = L->bytesOut = -1; n++;
        }
    free(t4); free(t6); free(u4);

    for (int i = 0; i < n; i++) {
        FwpLive *L = &out[i];
        if (strcmp(L->remoteIp, "*") != 0 && strcmp(L->remoteIp, "0.0.0.0") != 0 && strcmp(L->remoteIp, "::") != 0) fwp_dns_lookup(L->remoteIp, L->host, sizeof L->host);
        FwpConn c; memset(&c, 0, sizeof c); c.dir = L->inbound ? FWP_IN : FWP_OUT; c.proto = L->proto;
        c.localPort = L->localPort; c.remotePort = L->remotePort; snprintf(c.remoteIp, sizeof c.remoteIp, "%s", L->remoteIp); snprintf(c.program, sizeof c.program, "%s", L->path);
        int m = -1; L->action = pol ? fwp_eval(pol, nr, &c, &tmv, &m) : FWP_ALLOW;
        snprintf(L->rule, sizeof L->rule, "%s", (m >= 0 && pol) ? pol[m].name : "(default)");
    }
    free(pol);
    return n;
}

/* ---- Process-tree rules ------------------------------------------------------------------------------------------------------------- */
/* Adds BLOCK rules (both directions) for the executable of rootPid and of every descendant. Returns rules added to the policy. */
static int fwp_block_tree(unsigned rootPid, const char *label, char *msg, size_t msgN) {
    FwpProc procs[1024]; int np = fwp_processes(procs, 1024);
    unsigned pid[1024], ppid[1024]; for (int i = 0; i < np; i++) { pid[i] = procs[i].pid; ppid[i] = procs[i].ppid; }
    unsigned sub[256]; int ns = fwp_descendants(pid, ppid, np, rootPid, sub, 256);
    char seen[64][MAX_PATH]; int nseen = 0, added = 0;
    for (int i = 0; i < ns; i++) {
        char path[MAX_PATH]; if (!fwp_proc_path(sub[i], path, sizeof path) || !fwp_valid_program(path)) continue;
        int dup = 0; for (int k = 0; k < nseen; k++) if (_stricmp(seen[k], path) == 0) dup = 1;
        if (dup || nseen >= 64) continue; strcpy(seen[nseen++], path);
        FwpRule r; memset(&r, 0, sizeof r);
        const char *base = strrchr(path, '\\'); base = base ? base + 1 : path;
        char nm[96]; snprintf(nm, sizeof nm, "Tree %.30s %.40s", (label && fwp_safe_name(label)) ? label : "block", base);
        for (char *c = nm; *c; c++) if (!(isalnum((unsigned char)*c) || *c == ' ' || *c == '-' || *c == '.' || *c == '_')) *c = '_';
        snprintf(r.name, sizeof r.name, "%s", nm); snprintf(r.group, sizeof r.group, "Process tree");
        r.priority = 10; r.action = FWP_BLOCK; r.dir = FWP_BOTH; r.proto = FWP_ANY; r.enabled = 1; snprintf(r.program, sizeof r.program, "%s", path);
        fwp_sha256_file(path, r.progHash);
        if (fwp_validate(&r)) continue;
        EnterCriticalSection(&g_fwpCS);
        int idx = -1; for (int k = 0; k < g_fwpCount; k++) if (strcmp(g_fwpRules[k].name, r.name) == 0) idx = k;
        if (idx >= 0) g_fwpRules[idx] = r; else if (g_fwpCount < FWP_MAX_RULES) g_fwpRules[g_fwpCount++] = r; else { LeaveCriticalSection(&g_fwpCS); break; }
        LeaveCriticalSection(&g_fwpCS);
        added++;
    }
    snprintf(msg, msgN, "%d process(es) in the tree, %d distinct executable(s) added as block rules (press Apply to enforce).", ns, added);
    return added;
}

/* ---- Program-change guard ------------------------------------------------------------------------------------------------------------- */
/* Disables any ALLOW rule whose program file hash no longer matches. Returns number of rules disabled. */
static int fwp_hash_guard(void) {
    int disabled = 0;
    EnterCriticalSection(&g_fwpCS);
    for (int i = 0; i < g_fwpCount; i++) {
        FwpRule *r = &g_fwpRules[i];
        if (!r->enabled || !r->progHash[0] || !r->program[0] || r->action != FWP_ALLOW) continue;
        char h[65]; BOOL got = fwp_sha256_file(r->program, h);
        if (got && _stricmp(h, r->progHash) != 0) {
            r->enabled = 0; disabled++;
            fwp_alert("CRITICAL", "Program changed since it was allowed: %s - allow rule '%s' disabled.", r->program, r->name);
        }
    }
    LeaveCriticalSection(&g_fwpCS);
    if (disabled) fwp_policy_save();
    return disabled;
}

/* ---- DNS guard ---------------------------------------------------------------------------------------------------------------------------- */
static int fwp_system_dns(char (*out)[48], int maxN) {
    ULONG sz = 0; GetAdaptersAddresses(AF_INET, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST, NULL, NULL, &sz);
    IP_ADAPTER_ADDRESSES *a = (IP_ADAPTER_ADDRESSES *)malloc(sz ? sz : 1); int n = 0;
    if (a && GetAdaptersAddresses(AF_INET, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST, NULL, a, &sz) == NO_ERROR)
        for (IP_ADAPTER_ADDRESSES *p = a; p; p = p->Next) {
            if (p->OperStatus != IfOperStatusUp || p->IfType == IF_TYPE_SOFTWARE_LOOPBACK) continue;
            for (IP_ADAPTER_DNS_SERVER_ADDRESS *d = p->FirstDnsServerAddress; d && n < maxN; d = d->Next) {
                if (d->Address.lpSockaddr->sa_family != AF_INET) continue;
                char ip[48]; inet_ntop(AF_INET, &((struct sockaddr_in *)d->Address.lpSockaddr)->sin_addr, ip, sizeof ip);
                int dup = 0; for (int k = 0; k < n; k++) if (strcmp(out[k], ip) == 0) dup = 1;
                if (!dup) snprintf(out[n++], 48, "%s", ip);
            }
        }
    free(a); return n;
}

static unsigned fwp_file_hash(const char *path) {
    HANDLE f = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (f == INVALID_HANDLE_VALUE) return 0;
    unsigned h = 2166136261u; BYTE b[8192]; DWORD rd;
    while (ReadFile(f, b, sizeof b, &rd, NULL) && rd) for (DWORD i = 0; i < rd; i++) h = (h ^ b[i]) * 16777619u;
    CloseHandle(f); return h ? h : 1;
}

/* Compares resolvers and the hosts file against the stored baseline (registry HKCU\Software\Kaevex). First call learns. */
static int fwp_dns_guard_check(char *msg, size_t msgN) {
    char dns[16][48]; int n = fwp_system_dns(dns, 16);
    char joined[800] = ""; for (int i = 0; i < n; i++) { strcat(joined, dns[i]); strcat(joined, ";"); }
    char sys[MAX_PATH], hosts[MAX_PATH]; GetSystemDirectoryA(sys, sizeof sys); snprintf(hosts, sizeof hosts, "%s\\drivers\\etc\\hosts", sys);
    unsigned hh = fwp_hash(joined), fh = fwp_file_hash(hosts);
    HKEY k; DWORD d1 = 0, d2 = 0, sz = sizeof d1; int changed = 0; msg[0] = 0;
    if (RegCreateKeyExA(HKEY_CURRENT_USER, "Software\\Kaevex", 0, NULL, 0, KEY_ALL_ACCESS, NULL, &k, NULL) != ERROR_SUCCESS) return 0;
    if (RegQueryValueExA(k, "DnsBaseline", NULL, NULL, (BYTE *)&d1, &sz) != ERROR_SUCCESS) { RegSetValueExA(k, "DnsBaseline", 0, REG_DWORD, (BYTE *)&hh, 4); d1 = hh; }
    sz = sizeof d2;
    if (RegQueryValueExA(k, "HostsBaseline", NULL, NULL, (BYTE *)&d2, &sz) != ERROR_SUCCESS) { RegSetValueExA(k, "HostsBaseline", 0, REG_DWORD, (BYTE *)&fh, 4); d2 = fh; }
    if (d1 != hh) { changed |= 1; snprintf(msg + strlen(msg), msgN - strlen(msg), "DNS resolvers changed (now: %s). ", joined); }
    if (d2 != fh) { changed |= 2; snprintf(msg + strlen(msg), msgN - strlen(msg), "hosts file was modified. "); }
    RegCloseKey(k); return changed;
}
static void fwp_dns_guard_accept(void) {
    char dns[16][48]; int n = fwp_system_dns(dns, 16); char joined[800] = ""; for (int i = 0; i < n; i++) { strcat(joined, dns[i]); strcat(joined, ";"); }
    char sys[MAX_PATH], hosts[MAX_PATH]; GetSystemDirectoryA(sys, sizeof sys); snprintf(hosts, sizeof hosts, "%s\\drivers\\etc\\hosts", sys);
    DWORD hh = fwp_hash(joined), fh = fwp_file_hash(hosts); HKEY k;
    if (RegCreateKeyExA(HKEY_CURRENT_USER, "Software\\Kaevex", 0, NULL, 0, KEY_ALL_ACCESS, NULL, &k, NULL) == ERROR_SUCCESS) {
        RegSetValueExA(k, "DnsBaseline", 0, REG_DWORD, (BYTE *)&hh, 4); RegSetValueExA(k, "HostsBaseline", 0, REG_DWORD, (BYTE *)&fh, 4); RegCloseKey(k);
    }
}

/* Adds a policy rule pair that blocks plain/TLS DNS to every resolver except the approved list (default: current system DNS). */
static BOOL fwp_add_dns_restrict(const char *approvedCsv, char *msg, size_t msgN) {
    char approved[300] = "";
    if (approvedCsv && *approvedCsv) snprintf(approved, sizeof approved, "%s", approvedCsv);
    else { char d[16][48]; int n = fwp_system_dns(d, 16); for (int i = 0; i < n; i++) { if (i) strcat(approved, ","); strcat(approved, d[i]); } }
    if (!approved[0] || !fwp_valid_addrs(approved)) { snprintf(msg, msgN, "No valid approved DNS resolver (give IPv4 addresses)."); return FALSE; }
    char comp[400]; if (!fwp_ipv4_complement(approved, comp, sizeof comp) || strlen(comp) >= sizeof((FwpRule *)0)->remoteAddrs) { snprintf(msg, msgN, "Resolver list too complex."); return FALSE; }
    const char *protos[2] = { "tcp", "udp" };
    for (int i = 0; i < 2; i++) {
        FwpRule r; memset(&r, 0, sizeof r); snprintf(r.name, sizeof r.name, "DNS restrict %s", protos[i]); snprintf(r.group, sizeof r.group, "DNS guard");
        r.priority = 20; r.action = FWP_BLOCK; r.dir = FWP_OUT; r.proto = i ? FWP_UDP : FWP_TCP; r.enabled = 1;
        snprintf(r.remotePorts, sizeof r.remotePorts, "53,853"); snprintf(r.remoteAddrs, sizeof r.remoteAddrs, "%s", comp);
        EnterCriticalSection(&g_fwpCS);
        int idx = -1; for (int k = 0; k < g_fwpCount; k++) if (strcmp(g_fwpRules[k].name, r.name) == 0) idx = k;
        if (idx >= 0) g_fwpRules[idx] = r; else if (g_fwpCount < FWP_MAX_RULES) g_fwpRules[g_fwpCount++] = r;
        LeaveCriticalSection(&g_fwpCS);
    }
    snprintf(msg, msgN, "DNS to any resolver except [%s] will be blocked (press Apply). Note: DoH over port 443 is not covered.", approved);
    return TRUE;
}

/* ---- Tamper protection ---------------------------------------------------------------------------------------------------------------------- */
static volatile LONG g_fwpWatchRun = 0;
static HANDLE g_fwpWatchThread = NULL;
static FwpRegRule g_fwpExpected[FWP_MAX_RULES * 2];
static int g_fwpExpectedN = 0;

static void fwp_capture_expected(void) { g_fwpExpectedN = fwp_registry_rules("Kaevex-FW-", g_fwpExpected, FWP_MAX_RULES * 2); }

/* Verifies firewall ON + each managed rule present and unmodified; re-applies the policy if anything was tampered with. */
static int fwp_tamper_check_and_repair(void) {
    int problems = 0; char what[300] = "";
    if (fwp_profiles_on() != 7) { problems++; snprintf(what + strlen(what), sizeof what - strlen(what), "firewall profile turned off; "); fwp_netsh("advfirewall set allprofiles state on", NULL, 0, 15000); }
    static FwpRegRule now[FWP_MAX_RULES * 2]; int n = fwp_registry_rules("Kaevex-FW-", now, FWP_MAX_RULES * 2);
    int bad = 0;
    for (int i = 0; i < g_fwpExpectedN; i++) {
        int found = -1; for (int k = 0; k < n; k++) if (strcmp(now[k].name, g_fwpExpected[i].name) == 0) { found = k; break; }
        if (found < 0 || now[found].hash != g_fwpExpected[i].hash) { bad++; snprintf(what + strlen(what), sizeof what - strlen(what), "%s %s; ", g_fwpExpected[i].name, found < 0 ? "deleted" : "modified"); if (strlen(what) > 200) break; }
    }
    if (bad) { problems += bad; FwpApplyResult r; fwp_apply_all(&r, NULL, 0); fwp_capture_expected(); }
    if (problems) fwp_alert("CRITICAL", "Firewall tampering detected and repaired: %s", what);
    return problems;
}

static DWORD WINAPI fwp_watch_thread(LPVOID p) {
    (void)p;
    HKEY k; if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, FWP_POLICY_KEY, 0, KEY_NOTIFY | KEY_READ, &k) != ERROR_SUCCESS) { InterlockedExchange(&g_fwpWatchRun, 0); return 1; }
    HANDLE ev = CreateEventA(NULL, FALSE, FALSE, NULL);
    while (g_fwpWatchRun) {
        if (RegNotifyChangeKeyValue(k, TRUE, REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET, ev, TRUE) != ERROR_SUCCESS) break;
        DWORD w = WaitForSingleObject(ev, 1500);
        if (!g_fwpWatchRun) break;
        if (w != WAIT_OBJECT_0) continue;
        Sleep(1500);                                                   /* debounce bursts of registry writes */
        if (g_fwpApplying || GetTickCount() < g_fwpQuietUntil) continue;   /* our own change */
        fwp_tamper_check_and_repair();
    }
    CloseHandle(ev); RegCloseKey(k);
    return 0;
}

static BOOL fwp_watch_start(void) {
    if (!fwp_is_admin() || InterlockedCompareExchange(&g_fwpWatchRun, 1, 0) != 0) return FALSE;
    fwp_capture_expected();
    g_fwpWatchThread = CreateThread(NULL, 0, fwp_watch_thread, NULL, 0, NULL);
    if (!g_fwpWatchThread) { InterlockedExchange(&g_fwpWatchRun, 0); return FALSE; }
    return TRUE;
}
static void fwp_watch_stop(void) { InterlockedExchange(&g_fwpWatchRun, 0); }
static BOOL fwp_watch_running(void) { return g_fwpWatchRun != 0; }

/* ---- Adaptive baseline driver --------------------------------------------------------------------------------------------------------------------- */
static FwpBaseline *g_fwpBl = NULL;
static unsigned g_fwpBlAlerts = 0;

static void fwp_baseline_path(char *o, size_t n) { snprintf(o, n, "%s\\fw_baseline.tsv", g_fwpDir); }

static void fwp_baseline_init(void) {
    if (g_fwpBl) return;
    g_fwpBl = (FwpBaseline *)calloc(1, sizeof(FwpBaseline)); if (!g_fwpBl) return;
    g_fwpBl->learnSeconds = 15 * 60; g_fwpBl->minObs = 25;
    char p[MAX_PATH]; fwp_baseline_path(p, sizeof p); FILE *f = fopen(p, "rb");
    if (f) {
        char line[300]; if (fgets(line, sizeof line, f)) g_fwpBl->started = (time_t)atoll(line);
        while (fgets(line, sizeof line, f)) {
            char *t1 = strchr(line, '\t'); if (!t1) continue; *t1 = 0;
            unsigned h = fwp_hash(line) % FWP_BL_SIZE;
            for (int pr = 0; pr < FWP_BL_SIZE; pr++) { FwpBlEntry *e = &g_fwpBl->e[(h + (unsigned)pr) % FWP_BL_SIZE]; if (!e->key[0]) { snprintf(e->key, sizeof e->key, "%s", line); e->count = (unsigned)atoi(t1 + 1); e->first = e->last = g_fwpBl->started; g_fwpBl->used++; g_fwpBl->observations += e->count; break; } }
        }
        fclose(f);
    }
}

static void fwp_baseline_save(void) {
    if (!g_fwpBl) return; char p[MAX_PATH]; fwp_baseline_path(p, sizeof p); FILE *f = fopen(p, "wb"); if (!f) return;
    fprintf(f, "%lld\n", (long long)g_fwpBl->started);
    for (int i = 0; i < FWP_BL_SIZE; i++) if (g_fwpBl->e[i].key[0]) fprintf(f, "%s\t%u\n", g_fwpBl->e[i].key, g_fwpBl->e[i].count);
    fclose(f);
}

/* Call every few seconds. Learns outbound destinations per application and alerts on NEW ones once the baseline is mature. */
static int fwp_baseline_tick(void) {
    fwp_baseline_init(); if (!g_fwpBl) return 0;
    static FwpLive live[FWP_MAX_LIVE]; int n = fwp_live_snapshot(live, FWP_MAX_LIVE, FALSE), alerts = 0; time_t now = time(NULL);
    for (int i = 0; i < n; i++) {
        FwpLive *L = &live[i];
        if (L->proto != FWP_TCP || L->inbound || strcmp(L->state, "ESTAB") != 0 || !L->path[0]) continue;
        if (strncmp(L->remoteIp, "127.", 4) == 0 || strcmp(L->remoteIp, "::1") == 0) continue;
        const char *exe = strrchr(L->path, '\\'); exe = exe ? exe + 1 : L->path;
        if (fwp_baseline_observe(g_fwpBl, exe, L->remoteIp, L->remotePort, now)) {
            alerts++; g_fwpBlAlerts++;
            fwp_alert("WARNING", "Adaptive firewall: %s (pid %u) connected to a destination never seen before: %s:%d%s%s",
                      exe, L->pid, L->remoteIp, L->remotePort, L->host[0] ? " / " : "", L->host);
        }
    }
    return alerts;
}

#endif /* FW_PRO_ENGINE_H */
