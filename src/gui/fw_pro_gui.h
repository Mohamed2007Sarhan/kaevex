/*===========================================================================
 * Kaevex Firewall Pro - fw_pro_gui.h
 * Native window (tab control + ListView/TreeView). Every list is filled from
 * fw_pro_engine.h (real OS data). Slow operations (netsh, DNS, log parsing)
 * run on worker threads and report back through the activity pane.
 *===========================================================================*/
#pragma once
#ifndef FW_PRO_GUI_H
#define FW_PRO_GUI_H

#include <commctrl.h>
#include <commdlg.h>

#define FWG_WM_LOG      (WM_APP + 41)     /* lParam = malloc'd text */
#define FWG_WM_REFRESH  (WM_APP + 42)     /* wParam = page */

enum { FWG_P_RULES, FWG_P_LIVE, FWG_P_TREE, FWG_P_LOGS, FWG_P_PROT, FWG_P_SBX, FWG_P_COUNT };
enum {
    FWG_ID_TAB = 7000, FWG_ID_LOG,
    FWG_ID_RULES_LV, FWG_ID_RULE_EDIT, FWG_ID_ADD, FWG_ID_DEL, FWG_ID_TOGGLE, FWG_ID_APPLY, FWG_ID_SIM, FWG_ID_CONFLICT, FWG_ID_HELP, FWG_ID_CONFIRM,
    FWG_ID_LIVE_LV, FWG_ID_LIVE_REFRESH, FWG_ID_LIVE_BLOCKAPP, FWG_ID_LIVE_BLOCKTREE, FWG_ID_LIVE_SBX,
    FWG_ID_TREE, FWG_ID_TREE_REFRESH, FWG_ID_TREE_BLOCK,
    FWG_ID_LOGS_LV, FWG_ID_LOGS_FILTER, FWG_ID_LOGS_RELOAD, FWG_ID_LOGS_ENABLE, FWG_ID_LOGS_SUM,
    FWG_ID_WATCH, FWG_ID_DNSCHK, FWG_ID_DNSACC, FWG_ID_DNSRES, FWG_ID_HASH, FWG_ID_BASE, FWG_ID_LOCK, FWG_ID_UNLOCK,
    FWG_ID_SNAP, FWG_ID_RESTORE, FWG_ID_SNAPLIST, FWG_ID_EXPORT, FWG_ID_IMPORT, FWG_ID_PUSH, FWG_ID_PROT_INFO,
    FWG_ID_SB_PROG, FWG_ID_SB_HOSTS, FWG_ID_SB_PORTS, FWG_ID_SB_NET, FWG_ID_SB_LAN, FWG_ID_SB_CREATE, FWG_ID_SB_BROWSE, FWG_ID_SB_INFO
};

typedef struct {
    HWND hw, tab, log, status;
    HWND pg[FWG_P_COUNT][24]; int pgN[FWG_P_COUNT];
    HWND rulesLv, ruleEdit, liveLv, tree, logsLv, logsFilter, logsSum, snapList, protInfo;
    HWND sbProg, sbHosts, sbPorts, sbNet, sbLan, sbInfo;
    int page; BOOL busy;
} FwgState;
static FwgState g_fwg;
static FwpLive *g_fwgLive = NULL; static int g_fwgLiveN = 0;
static FwpLogEntry *g_fwgLog = NULL;

static void fwg_say(const char *fmt, ...) {
    char m[1500]; va_list ap; va_start(ap, fmt); vsnprintf(m, sizeof m, fmt, ap); va_end(ap);
    if (g_fwg.hw && IsWindow(g_fwg.hw)) PostMessageA(g_fwg.hw, FWG_WM_LOG, 0, (LPARAM)_strdup(m));
}

static HWND fwg_ctl(int page, const char *cls, const char *txt, DWORD style, int id) {
    HWND h = CreateWindowExA(0, cls, txt, WS_CHILD | style, 0, 0, 10, 10, g_fwg.hw, (HMENU)(INT_PTR)id, GetModuleHandleA(NULL), NULL);
    SendMessageA(h, WM_SETFONT, (WPARAM)GetStockObject(DEFAULT_GUI_FONT), TRUE);
    if (page >= 0 && g_fwg.pgN[page] < 24) g_fwg.pg[page][g_fwg.pgN[page]++] = h;
    return h;
}
static HWND fwg_btn(int page, const char *t, int id) { return fwg_ctl(page, "BUTTON", t, BS_PUSHBUTTON | WS_TABSTOP, id); }

static void fwg_cols(HWND lv, const char **names, const int *w, int n) {
    for (int i = 0; i < n; i++) { LVCOLUMNA c; memset(&c, 0, sizeof c); c.mask = LVCF_TEXT | LVCF_WIDTH; c.pszText = (char *)names[i]; c.cx = w[i]; SendMessageA(lv, LVM_INSERTCOLUMNA, (WPARAM)i, (LPARAM)&c); }
    SendMessageA(lv, LVM_SETEXTENDEDLISTVIEWSTYLE, 0, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_DOUBLEBUFFER);
}
static void fwg_lv_add(HWND lv, int row, int col, const char *t) {
    if (col == 0) { LVITEMA it; memset(&it, 0, sizeof it); it.mask = LVIF_TEXT | LVIF_PARAM; it.iItem = row; it.pszText = (char *)t; it.lParam = row; SendMessageA(lv, LVM_INSERTITEMA, 0, (LPARAM)&it); }
    else { LVITEMA it; memset(&it, 0, sizeof it); it.iSubItem = col; it.pszText = (char *)t; SendMessageA(lv, LVM_SETITEMTEXTA, (WPARAM)row, (LPARAM)&it); }
}

/* ---- Rules page ------------------------------------------------------------------------- */
static void fwg_fill_rules(void) {
    SendMessageA(g_fwg.rulesLv, WM_SETREDRAW, FALSE, 0); SendMessageA(g_fwg.rulesLv, LVM_DELETEALLITEMS, 0, 0);
    EnterCriticalSection(&g_fwpCS);
    for (int i = 0; i < g_fwpCount; i++) {
        FwpRule *r = &g_fwpRules[i]; char b[32], d[520];
        snprintf(b, sizeof b, "%d", r->priority); fwg_lv_add(g_fwg.rulesLv, i, 0, b);
        fwg_lv_add(g_fwg.rulesLv, i, 1, r->name); fwg_lv_add(g_fwg.rulesLv, i, 2, r->group);
        fwp_describe(r, d, sizeof d); fwg_lv_add(g_fwg.rulesLv, i, 3, d);
        fwg_lv_add(g_fwg.rulesLv, i, 4, r->progHash[0] ? "hash-pinned" : "");
    }
    LeaveCriticalSection(&g_fwpCS);
    SendMessageA(g_fwg.rulesLv, WM_SETREDRAW, TRUE, 0);
}

static int fwg_sel(HWND lv) { return (int)SendMessageA(lv, LVM_GETNEXTITEM, (WPARAM)-1, LVNI_SELECTED); }

static void fwg_add_rule_text(const char *text) {
    FwpRule r; char err[200];
    if (!fwp_parse_rule_text(text, &r, err, sizeof err)) { fwg_say("Rule rejected: %s", err); return; }
    if (r.program[0] && GetFileAttributesA(r.program) != INVALID_FILE_ATTRIBUTES) fwp_sha256_file(r.program, r.progHash);
    EnterCriticalSection(&g_fwpCS);
    int idx = -1; for (int i = 0; i < g_fwpCount; i++) if (strcmp(g_fwpRules[i].name, r.name) == 0) idx = i;
    if (idx >= 0) g_fwpRules[idx] = r; else if (g_fwpCount < FWP_MAX_RULES) g_fwpRules[g_fwpCount++] = r; else { LeaveCriticalSection(&g_fwpCS); fwg_say("Policy full (%d rules).", FWP_MAX_RULES); return; }
    LeaveCriticalSection(&g_fwpCS);
    fwp_policy_save(); fwg_fill_rules();
    fwg_say("Rule '%s' %s in the Kaevex policy. Press 'Apply' to enforce it in Windows Firewall.", r.name, idx >= 0 ? "updated" : "added");
}

static DWORD WINAPI fwg_apply_thread(LPVOID p) {
    (void)p; FwpApplyResult ar; char snap[MAX_PATH] = "";
    fwp_policy_save();
    BOOL ok = fwp_apply_all(&ar, snap, sizeof snap);
    if (ok) {
        BOOL g = snap[0] && fwp_guard_begin(snap, 60);
        fwg_say("Applied: %d rule(s) installed, %d old removed.%s", ar.added, ar.deleted,
                g ? " SAFETY NET: press 'Confirm change' within 60 s or Windows Firewall rolls back automatically." : "");
        fwp_watch_stop(); fwp_watch_start();          /* re-learn expected state after a legitimate change */
    } else fwg_say("Apply FAILED: %s (%d failed). Nothing was left half-applied if the snapshot step failed; see snapshots to restore.", ar.firstError, ar.failed);
    g_fwg.busy = FALSE; return 0;
}

static void fwg_simulate(const char *text) {
    char t2[600]; snprintf(t2, sizeof t2, "allow name=sim %s", text); FwpRule r; char err[200];
    if (!fwp_parse_rule_text(t2, &r, err, sizeof err)) { fwg_say("Simulation input: %s. Example: out tcp app=\"C:\\x.exe\" raddr=1.2.3.4 rport=443", err); return; }
    FwpConn c; memset(&c, 0, sizeof c); c.dir = r.dir == FWP_IN ? FWP_IN : FWP_OUT; c.proto = r.proto == FWP_ANY ? FWP_TCP : r.proto;
    snprintf(c.program, sizeof c.program, "%s", r.program); snprintf(c.remoteIp, sizeof c.remoteIp, "%s", r.remoteAddrs[0] ? r.remoteAddrs : "0.0.0.0");
    c.remotePort = atoi(r.remotePorts); c.localPort = atoi(r.localPorts);
    time_t now = time(NULL); struct tm tmv; localtime_s(&tmv, &now); int m = -1;
    EnterCriticalSection(&g_fwpCS); int act = fwp_eval(g_fwpRules, g_fwpCount, &c, &tmv, &m); char nm[96] = "(default policy)"; if (m >= 0) snprintf(nm, sizeof nm, "%s", g_fwpRules[m].name); LeaveCriticalSection(&g_fwpCS);
    fwg_say("Simulation: %s %s %s:%d -> %s by rule: %s", c.dir == FWP_IN ? "inbound" : "outbound", c.program[0] ? c.program : "(any app)", c.remoteIp, c.remotePort, act == FWP_BLOCK ? "BLOCK" : "ALLOW", nm);
}

/* ---- Live connections -------------------------------------------------------------------- */
static DWORD WINAPI fwg_live_thread(LPVOID p) {
    (void)p; if (!g_fwgLive) g_fwgLive = (FwpLive *)malloc(sizeof(FwpLive) * FWP_MAX_LIVE);
    if (g_fwgLive) g_fwgLiveN = fwp_live_snapshot(g_fwgLive, FWP_MAX_LIVE, TRUE);
    if (g_fwg.hw) PostMessageA(g_fwg.hw, FWG_WM_REFRESH, FWG_P_LIVE, 0);
    return 0;
}
static void fwg_fill_live(void) {
    HWND lv = g_fwg.liveLv; SendMessageA(lv, WM_SETREDRAW, FALSE, 0); SendMessageA(lv, LVM_DELETEALLITEMS, 0, 0);
    for (int i = 0; i < g_fwgLiveN && g_fwgLive; i++) {
        FwpLive *L = &g_fwgLive[i]; char b[96];
        fwg_lv_add(lv, i, 0, L->proc); snprintf(b, sizeof b, "%u", L->pid); fwg_lv_add(lv, i, 1, b); snprintf(b, sizeof b, "%u", L->ppid); fwg_lv_add(lv, i, 2, b);
        fwg_lv_add(lv, i, 3, L->user); fwg_lv_add(lv, i, 4, L->proto == FWP_TCP ? (L->v6 ? "TCP6" : "TCP") : "UDP");
        snprintf(b, sizeof b, "%s:%d", L->localIp, L->localPort); fwg_lv_add(lv, i, 5, b);
        snprintf(b, sizeof b, "%s:%d", L->remoteIp, L->remotePort); fwg_lv_add(lv, i, 6, strcmp(L->remoteIp, "*") ? b : "*");
        fwg_lv_add(lv, i, 7, L->host); fwg_lv_add(lv, i, 8, L->state); fwg_lv_add(lv, i, 9, L->rule); fwg_lv_add(lv, i, 10, L->action == FWP_BLOCK ? "BLOCK" : "allow");
        if (L->bytesIn >= 0) snprintf(b, sizeof b, "%lld / %lld", L->bytesIn, L->bytesOut); else strcpy(b, "n/a");
        fwg_lv_add(lv, i, 11, b);
    }
    SendMessageA(lv, WM_SETREDRAW, TRUE, 0);
    char s[160]; snprintf(s, sizeof s, "Live connections: %d (bytes counted since monitoring began; n/a when not measurable)", g_fwgLiveN); SetWindowTextA(g_fwg.status, s);
}

/* ---- Process tree ------------------------------------------------------------------------- */
static void fwg_tree_add(HTREEITEM parent, const FwpProc *pr, int n, unsigned pid, int depth, const int *conn, char *visited) {
    for (int i = 0; i < n && depth < 24; i++) {
        if (pr[i].pid != pid) continue;
        if (visited[i]) return; visited[i] = 1;
        char t[160]; snprintf(t, sizeof t, "%s  (pid %u)%s", pr[i].name, pr[i].pid, conn[i] ? "  - connections: " : ""); if (conn[i]) snprintf(t + strlen(t), sizeof t - strlen(t), "%d", conn[i]);
        TVINSERTSTRUCTA ins; memset(&ins, 0, sizeof ins); ins.hParent = parent; ins.hInsertAfter = TVI_LAST; ins.item.mask = TVIF_TEXT | TVIF_PARAM; ins.item.pszText = t; ins.item.lParam = (LPARAM)pr[i].pid;
        HTREEITEM h = (HTREEITEM)SendMessageA(g_fwg.tree, TVM_INSERTITEMA, 0, (LPARAM)&ins);
        for (int k = 0; k < n; k++) if (pr[k].ppid == pid && pr[k].pid != pid) fwg_tree_add(h, pr, n, pr[k].pid, depth + 1, conn, visited);
        SendMessageA(g_fwg.tree, TVM_EXPAND, TVE_EXPAND, (LPARAM)h);
        return;
    }
}
static void fwg_fill_tree(void) {
    FwpProc *pr = (FwpProc *)malloc(sizeof(FwpProc) * 1024); int *conn = (int *)calloc(1024, sizeof(int)); char *vis = (char *)calloc(1024, 1);
    if (!pr || !conn || !vis) { free(pr); free(conn); free(vis); return; }
    int n = fwp_processes(pr, 1024);
    for (int i = 0; i < n; i++) for (int k = 0; k < g_fwgLiveN && g_fwgLive; k++) if (g_fwgLive[k].pid == pr[i].pid) conn[i]++;
    SendMessageA(g_fwg.tree, WM_SETREDRAW, FALSE, 0); SendMessageA(g_fwg.tree, TVM_DELETEITEM, 0, (LPARAM)TVI_ROOT);
    for (int i = 0; i < n; i++) {
        int hasParent = 0; for (int k = 0; k < n; k++) if (pr[k].pid == pr[i].ppid && pr[k].pid != pr[i].pid) hasParent = 1;
        if (!hasParent) fwg_tree_add(TVI_ROOT, pr, n, pr[i].pid, 0, conn, vis);
    }
    SendMessageA(g_fwg.tree, WM_SETREDRAW, TRUE, 0);
    free(pr); free(conn); free(vis);
}

/* ---- Logs ---------------------------------------------------------------------------------- */
static DWORD WINAPI fwg_logs_thread(LPVOID p) {
    (void)p; if (!g_fwgLog) g_fwgLog = (FwpLogEntry *)malloc(sizeof(FwpLogEntry) * 6000);
    int n = g_fwgLog ? fwp_read_log(g_fwgLog, 6000) : 0;
    PostMessageA(g_fwg.hw, FWG_WM_REFRESH, FWG_P_LOGS, (LPARAM)n);
    return 0;
}
static void fwg_fill_logs(int n) {
    HWND lv = g_fwg.logsLv; SendMessageA(lv, WM_SETREDRAW, FALSE, 0); SendMessageA(lv, LVM_DELETEALLITEMS, 0, 0);
    if (n < 0) { SetWindowTextA(g_fwg.logsSum, "Firewall log not found. Press 'Enable logging' (administrator), generate some traffic, then Reload."); SendMessageA(lv, WM_SETREDRAW, TRUE, 0); return; }
    char filter[96]; GetWindowTextA(g_fwg.logsFilter, filter, sizeof filter);
    FwpProc *pr = (FwpProc *)malloc(sizeof(FwpProc) * 1024); int np = pr ? fwp_processes(pr, 1024) : 0;
    int shown = 0, allow = 0, drop = 0; unsigned dropPid[64] = {0}; int dropCnt[64] = {0}, dn = 0;
    for (int i = n - 1; i >= 0 && shown < 1500; i--) {
        FwpLogEntry *e = &g_fwgLog[i]; char nm[64] = ""; for (int k = 0; k < np; k++) if (pr[k].pid == e->pid && e->pid) { snprintf(nm, sizeof nm, "%s", pr[k].name); break; }
        if (_stricmp(e->action, "DROP") == 0) { drop++; if (e->pid) { int f = -1; for (int k = 0; k < dn; k++) if (dropPid[k] == e->pid) f = k; if (f < 0 && dn < 64) { f = dn++; dropPid[f] = e->pid; } if (f >= 0) dropCnt[f]++; } } else if (_stricmp(e->action, "ALLOW") == 0) allow++;
        if (!fwp_log_matches(e, filter, nm)) continue;
        char b[48]; snprintf(b, sizeof b, "%s %s", e->date, e->time); fwg_lv_add(lv, shown, 0, b);
        fwg_lv_add(lv, shown, 1, e->action); fwg_lv_add(lv, shown, 2, e->proto); fwg_lv_add(lv, shown, 3, e->src); fwg_lv_add(lv, shown, 4, e->dst);
        snprintf(b, sizeof b, "%d", e->sport); fwg_lv_add(lv, shown, 5, b); snprintf(b, sizeof b, "%d", e->dport); fwg_lv_add(lv, shown, 6, b);
        fwg_lv_add(lv, shown, 7, e->path); fwg_lv_add(lv, shown, 8, nm[0] ? nm : (e->pid ? "(exited)" : "n/a")); snprintf(b, sizeof b, "%u", e->pid); fwg_lv_add(lv, shown, 9, b);
        shown++;
    }
    int best = -1; for (int k = 0; k < dn; k++) if (best < 0 || dropCnt[k] > dropCnt[best]) best = k;
    char top[96] = "n/a"; if (best >= 0) { snprintf(top, sizeof top, "pid %u (%d drops)", dropPid[best], dropCnt[best]); for (int k = 0; k < np; k++) if (pr[k].pid == dropPid[best]) snprintf(top, sizeof top, "%s (%d drops)", pr[k].name, dropCnt[best]); }
    char s[300]; snprintf(s, sizeof s, "Loaded %d log entries: %d allowed, %d dropped. Most dropped: %s. Showing %d (newest first).", n, allow, drop, top, shown);
    SetWindowTextA(g_fwg.logsSum, s); free(pr);
    SendMessageA(lv, WM_SETREDRAW, TRUE, 0);
}

/* ---- Protection actions (all on worker threads) -------------------------------------------- */
enum { FWJ_DNSCHK = 1, FWJ_DNSRES, FWJ_HASH, FWJ_BASE, FWJ_LOCK, FWJ_UNLOCK, FWJ_SNAP, FWJ_RESTORE, FWJ_ENABLELOG, FWJ_PUSH, FWJ_LOGSREL };
typedef struct { int job; char arg[MAX_PATH]; } FwgJob;
static DWORD WINAPI fwg_job_thread(LPVOID p) {
    FwgJob *j = (FwgJob *)p; char m[700] = "";
    switch (j->job) {
    case FWJ_DNSCHK: { int c = fwp_dns_guard_check(m, sizeof m); fwg_say(c ? "DNS GUARD: %s Use 'Accept DNS baseline' if this change was yours." : "DNS guard: resolvers and hosts file match the learned baseline.", m); break; }
    case FWJ_DNSRES: { BOOL ok = fwp_add_dns_restrict(NULL, m, sizeof m); fwg_say("%s%s", ok ? "" : "DNS restrict: ", m); if (ok) PostMessageA(g_fwg.hw, FWG_WM_REFRESH, FWG_P_RULES, 0); break; }
    case FWJ_HASH: { int d = fwp_hash_guard(); fwg_say("Program-change guard: %d allow rule(s) disabled because the program file changed.", d); PostMessageA(g_fwg.hw, FWG_WM_REFRESH, FWG_P_RULES, 0); break; }
    case FWJ_BASE: { fwp_baseline_init(); if (g_fwpBl) { time_t el = time(NULL) - g_fwpBl->started; fwg_say("Adaptive baseline: %d destinations learned from %u observations over %lld min; alerts raised: %u. Learning window %lld min, then new destinations alert.", g_fwpBl->used, g_fwpBl->observations, (long long)(g_fwpBl->started ? el / 60 : 0), g_fwpBlAlerts, (long long)(g_fwpBl->learnSeconds / 60)); } break; }
    case FWJ_LOCK: case FWJ_UNLOCK: { BOOL ok = fwp_lockdown(j->job == FWJ_LOCK, g_mobilePort, m, sizeof m); if (ok && g_pMobileLockdown) *g_pMobileLockdown = (j->job == FWJ_LOCK); fwg_say("%s", m); break; }
    case FWJ_SNAP: { char path[MAX_PATH]; BOOL ok = fwp_snapshot(path, sizeof path, "manual"); fwg_say(ok ? "Snapshot saved: %s" : "Snapshot failed (administrator rights needed).", path); PostMessageA(g_fwg.hw, FWG_WM_REFRESH, FWG_P_PROT, 0); break; }
    case FWJ_RESTORE: { BOOL ok = j->arg[0] && fwp_restore_snapshot(j->arg); fwg_say(ok ? "Restored Windows Firewall from %s" : "Restore failed.", j->arg); break; }
    case FWJ_ENABLELOG: { BOOL ok = fwp_enable_logging(); fwg_say(ok ? "Firewall logging enabled for allowed and dropped connections (16 MB log)." : "Could not enable logging (administrator rights needed)."); break; }
    case FWJ_PUSH: { int ok = 0, n = g_peerCount; for (int i = 0; i < n; i++) if (link_push_policy(i, 0) == 200) ok++; fwg_say(n ? "Policy pushed to %d of %d linked node(s) (imported, not applied there until they Apply)." : "No linked nodes to push to.", ok, n); break; }
    }
    free(j); return 0;
}
static void fwg_job(int job, const char *arg) {
    FwgJob *j = (FwgJob *)calloc(1, sizeof *j); if (!j) return; j->job = job; if (arg) snprintf(j->arg, sizeof j->arg, "%s", arg);
    HANDLE h = CreateThread(NULL, 0, fwg_job_thread, j, 0, NULL); if (h) CloseHandle(h); else free(j);
}

static void fwg_fill_snaps(void) {
    static char names[64][MAX_PATH]; int n = fwp_list_snapshots(names, 64);
    SendMessageA(g_fwg.snapList, LB_RESETCONTENT, 0, 0); for (int i = 0; i < n; i++) SendMessageA(g_fwg.snapList, LB_ADDSTRING, 0, (LPARAM)names[i]);
}

/* ---- Layout / paging ------------------------------------------------------------------------- */
static void fwg_show_page(int pg) {
    g_fwg.page = pg;
    for (int p = 0; p < FWG_P_COUNT; p++) for (int i = 0; i < g_fwg.pgN[p]; i++) ShowWindow(g_fwg.pg[p][i], p == pg ? SW_SHOW : SW_HIDE);
    if (pg == FWG_P_RULES) fwg_fill_rules();
    if (pg == FWG_P_LIVE) { HANDLE h = CreateThread(NULL, 0, fwg_live_thread, NULL, 0, NULL); if (h) CloseHandle(h); }
    if (pg == FWG_P_TREE) { if (!g_fwgLiveN) { HANDLE h = CreateThread(NULL, 0, fwg_live_thread, NULL, 0, NULL); if (h) CloseHandle(h); } fwg_fill_tree(); }
    if (pg == FWG_P_LOGS) { HANDLE h = CreateThread(NULL, 0, fwg_logs_thread, NULL, 0, NULL); if (h) CloseHandle(h); }
    if (pg == FWG_P_PROT) fwg_fill_snaps();
}

static void fwg_layout(int W, int H) {
    const int logH = 118, tabH = 30, M = 8; int top = tabH + 4, bot = H - logH - M, cw = W - 2 * M, ch = bot - top - 4;
    MoveWindow(g_fwg.tab, M, 4, cw, tabH, TRUE);
    MoveWindow(g_fwg.log, M, H - logH, cw, logH - M, TRUE);
    MoveWindow(g_fwg.status, M, bot - 2, cw, 18, TRUE);
    /* rules */
    MoveWindow(g_fwg.rulesLv, M, top + 34, cw, ch - 74, TRUE);
    MoveWindow(g_fwg.ruleEdit, M, top, cw - 4, 26, TRUE);
    int bx = M, by = top + ch - 32, bw = 112;
    int ids[] = { FWG_ID_ADD, FWG_ID_DEL, FWG_ID_TOGGLE, FWG_ID_APPLY, FWG_ID_CONFIRM, FWG_ID_SIM, FWG_ID_CONFLICT, FWG_ID_HELP };
    for (int i = 0; i < 8; i++) { MoveWindow(GetDlgItem(g_fwg.hw, ids[i]), bx, by, bw, 28, TRUE); bx += bw + 6; }
    /* live */
    MoveWindow(g_fwg.liveLv, M, top, cw, ch - 38, TRUE);
    int lids[] = { FWG_ID_LIVE_REFRESH, FWG_ID_LIVE_BLOCKAPP, FWG_ID_LIVE_BLOCKTREE, FWG_ID_LIVE_SBX }; bx = M;
    for (int i = 0; i < 4; i++) { MoveWindow(GetDlgItem(g_fwg.hw, lids[i]), bx, top + ch - 32, 170, 28, TRUE); bx += 176; }
    /* tree */
    MoveWindow(g_fwg.tree, M, top, cw, ch - 38, TRUE);
    MoveWindow(GetDlgItem(g_fwg.hw, FWG_ID_TREE_REFRESH), M, top + ch - 32, 150, 28, TRUE);
    MoveWindow(GetDlgItem(g_fwg.hw, FWG_ID_TREE_BLOCK), M + 156, top + ch - 32, 260, 28, TRUE);
    /* logs */
    MoveWindow(g_fwg.logsFilter, M, top, 360, 26, TRUE);
    MoveWindow(GetDlgItem(g_fwg.hw, FWG_ID_LOGS_RELOAD), M + 368, top, 100, 26, TRUE);
    MoveWindow(GetDlgItem(g_fwg.hw, FWG_ID_LOGS_ENABLE), M + 474, top, 150, 26, TRUE);
    MoveWindow(g_fwg.logsSum, M, top + 30, cw, 20, TRUE);
    MoveWindow(g_fwg.logsLv, M, top + 54, cw, ch - 54, TRUE);
    /* protection */
    int pids[] = { FWG_ID_WATCH, FWG_ID_DNSCHK, FWG_ID_DNSACC, FWG_ID_DNSRES, FWG_ID_HASH, FWG_ID_BASE, FWG_ID_LOCK, FWG_ID_UNLOCK, FWG_ID_SNAP, FWG_ID_RESTORE, FWG_ID_EXPORT, FWG_ID_IMPORT, FWG_ID_PUSH };
    for (int i = 0; i < 13; i++) MoveWindow(GetDlgItem(g_fwg.hw, pids[i]), M + (i % 4) * 250, top + (i / 4) * 34, 244, 28, TRUE);
    MoveWindow(g_fwg.snapList, M, top + 4 * 34 + 4, 500, ch - 4 * 34 - 8, TRUE);
    MoveWindow(g_fwg.protInfo, M + 510, top + 4 * 34 + 4, cw - 510, ch - 4 * 34 - 8, TRUE);
    /* sandbox */
    MoveWindow(g_fwg.sbInfo, M, top, cw, 70, TRUE);
    MoveWindow(g_fwg.sbProg, M, top + 78, cw - 110, 26, TRUE); MoveWindow(GetDlgItem(g_fwg.hw, FWG_ID_SB_BROWSE), M + cw - 104, top + 78, 100, 26, TRUE);
    MoveWindow(g_fwg.sbHosts, M, top + 112, cw, 26, TRUE); MoveWindow(g_fwg.sbPorts, M, top + 146, cw, 26, TRUE);
    MoveWindow(g_fwg.sbNet, M, top + 182, 260, 24, TRUE); MoveWindow(g_fwg.sbLan, M + 270, top + 182, 260, 24, TRUE);
    MoveWindow(GetDlgItem(g_fwg.hw, FWG_ID_SB_CREATE), M, top + 214, 260, 30, TRUE);
}

static void fwg_cmd_sandbox(void) {
    FwpSandbox sb; memset(&sb, 0, sizeof sb);
    GetWindowTextA(g_fwg.sbProg, sb.program, sizeof sb.program); GetWindowTextA(g_fwg.sbHosts, sb.allowHosts, sizeof sb.allowHosts); GetWindowTextA(g_fwg.sbPorts, sb.allowPorts, sizeof sb.allowPorts);
    sb.allowInternet = SendMessageA(g_fwg.sbNet, BM_GETCHECK, 0, 0) == BST_CHECKED; sb.allowLan = SendMessageA(g_fwg.sbLan, BM_GETCHECK, 0, 0) == BST_CHECKED;
    if (!fwp_valid_program(sb.program) || !sb.program[0]) { fwg_say("Sandbox: program must be a full path ending in .exe."); return; }
    if (!fwp_valid_addrs(sb.allowHosts) || !fwp_valid_ports(sb.allowPorts)) { fwg_say("Sandbox: allowed hosts/ports are invalid."); return; }
    const char *base = strrchr(sb.program, '\\'); base = base ? base + 1 : sb.program; char nm[64]; snprintf(nm, sizeof nm, "SBX %.40s", base);
    for (char *c = nm; *c; c++) if (!(isalnum((unsigned char)*c) || *c == ' ' || *c == '-' || *c == '_')) *c = '_';
    FwpRule out[8]; int n = fwp_sandbox_compile(&sb, nm, out, 8);
    if (n < 0) { fwg_say("Sandbox: allow-list too long to express as firewall rules - shorten it."); return; }
    if (n == 0) { fwg_say("Sandbox: with Internet+LAN allowed and no host/port limits there is nothing to block."); return; }
    char hash[65] = ""; fwp_sha256_file(sb.program, hash);
    EnterCriticalSection(&g_fwpCS);
    for (int i = 0; i < n && g_fwpCount < FWP_MAX_RULES; i++) { snprintf(out[i].progHash, sizeof out[i].progHash, "%s", hash); int idx = -1; for (int k = 0; k < g_fwpCount; k++) if (strcmp(g_fwpRules[k].name, out[i].name) == 0) idx = k; if (idx >= 0) g_fwpRules[idx] = out[i]; else g_fwpRules[g_fwpCount++] = out[i]; }
    LeaveCriticalSection(&g_fwpCS);
    fwp_policy_save(); fwg_fill_rules();
    fwg_say("Sandbox for %s compiled into %d block rule(s) in the policy. Press Apply (Rules tab) to enforce.", base, n);
}

static void fwg_block_selected_live(int tree) {
    int s = fwg_sel(g_fwg.liveLv); if (s < 0 || s >= g_fwgLiveN || !g_fwgLive) { fwg_say("Select a connection first."); return; }
    FwpLive *L = &g_fwgLive[s]; char m[300];
    if (tree) { fwp_block_tree(L->pid, L->proc, m, sizeof m); fwg_say("%s", m); fwp_policy_save(); fwg_fill_rules(); return; }
    if (!L->path[0] || !fwp_valid_program(L->path)) { fwg_say("This process path is not available/valid (protected process)."); return; }
    char rule[600]; snprintf(rule, sizeof rule, "block both any app=\"%s\" prio=10 group=\"Live block\" name=\"Live block %.40s\"", L->path, L->proc);
    for (char *c = rule + strlen("block both any app=\""); *c; c++) { }
    fwg_add_rule_text(rule);
}

static LRESULT CALLBACK fwg_proc(HWND hw, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    KV_CTLCOLOR_CASES
    case WM_SIZE: fwg_layout(LOWORD(lp), HIWORD(lp)); return 0;
    case WM_NOTIFY: {
        NMHDR *nh = (NMHDR *)lp;
        if (nh->idFrom == FWG_ID_TAB && nh->code == TCN_SELCHANGE) fwg_show_page((int)SendMessageA(g_fwg.tab, TCM_GETCURSEL, 0, 0));
        if (nh->idFrom == FWG_ID_RULES_LV && nh->code == LVN_ITEMCHANGED) {
            int s = fwg_sel(g_fwg.rulesLv); if (s >= 0 && s < g_fwpCount) { char d[600]; EnterCriticalSection(&g_fwpCS); FwpRule r = g_fwpRules[s]; LeaveCriticalSection(&g_fwpCS); snprintf(d, sizeof d, "block|allow %s", ""); (void)d;
                char t[900]; snprintf(t, sizeof t, "%s %s %s name=\"%s\" prio=%d%s%s%s%s%s%s%s%s%s", r.action ? "block" : "allow", r.dir == FWP_IN ? "in" : r.dir == FWP_OUT ? "out" : "both", r.proto == FWP_TCP ? "tcp" : r.proto == FWP_UDP ? "udp" : r.proto == FWP_ICMP4 ? "icmp4" : r.proto == FWP_ICMP6 ? "icmp6" : "any", r.name, r.priority,
                    r.program[0] ? " app=\"" : "", r.program, r.program[0] ? "\"" : "", r.remotePorts[0] ? " rport=" : "", r.remotePorts, r.remoteAddrs[0] ? " raddr=" : "", r.remoteAddrs, r.group[0] ? " group=" : "", r.group);
                SetWindowTextA(g_fwg.ruleEdit, t); }
        }
        return 0; }
    case WM_COMMAND: {
        int id = LOWORD(wp);
        if (id == FWG_ID_ADD) { char t[900]; GetWindowTextA(g_fwg.ruleEdit, t, sizeof t); fwg_add_rule_text(t); }
        else if (id == FWG_ID_DEL) { int s = fwg_sel(g_fwg.rulesLv); if (s >= 0) { EnterCriticalSection(&g_fwpCS); if (s < g_fwpCount) { for (int k = s; k < g_fwpCount - 1; k++) g_fwpRules[k] = g_fwpRules[k + 1]; g_fwpCount--; } LeaveCriticalSection(&g_fwpCS); fwp_policy_save(); fwg_fill_rules(); fwg_say("Rule removed from the policy (press Apply to remove it from Windows Firewall)."); } }
        else if (id == FWG_ID_TOGGLE) { int s = fwg_sel(g_fwg.rulesLv); if (s >= 0 && s < g_fwpCount) { EnterCriticalSection(&g_fwpCS); g_fwpRules[s].enabled = !g_fwpRules[s].enabled; LeaveCriticalSection(&g_fwpCS); fwp_policy_save(); fwg_fill_rules(); } }
        else if (id == FWG_ID_APPLY) { if (g_fwg.busy) fwg_say("Another operation is running."); else { g_fwg.busy = TRUE; HANDLE h = CreateThread(NULL, 0, fwg_apply_thread, NULL, 0, NULL); if (h) CloseHandle(h); else g_fwg.busy = FALSE; fwg_say("Applying policy (snapshot first)..."); } }
        else if (id == FWG_ID_CONFIRM) { if (fwp_guard_remaining() > 0) { fwp_guard_confirm(); fwg_say("Change confirmed - rollback cancelled."); } else fwg_say("Nothing to confirm."); }
        else if (id == FWG_ID_SIM) { char t[600]; GetWindowTextA(g_fwg.ruleEdit, t, sizeof t); fwg_simulate(t); }
        else if (id == FWG_ID_CONFLICT) { int pr[32][2]; EnterCriticalSection(&g_fwpCS); int n = fwp_find_conflicts(g_fwpRules, g_fwpCount, pr, 32); char m[900] = ""; for (int i = 0; i < n && i < 6; i++) snprintf(m + strlen(m), sizeof m - strlen(m), "'%s' (prio %d) vs '%s' (prio %d); ", g_fwpRules[pr[i][0]].name, g_fwpRules[pr[i][0]].priority, g_fwpRules[pr[i][1]].name, g_fwpRules[pr[i][1]].priority); LeaveCriticalSection(&g_fwpCS);
            fwg_say(n ? "%d priority conflict(s): Windows Firewall lets BLOCK beat ALLOW regardless of priority, so these allow rules will NOT override: %s" : "No allow-over-block priority conflicts.", n, m); }
        else if (id == FWG_ID_HELP) fwg_say("Rule syntax: allow|block  in|out|both  tcp|udp|icmp4|icmp6|any  name=\"X\" [app=\"C:\\p.exe\"] [lport=] [rport=80,443] [raddr=1.2.3.4/24,LocalSubnet] [domain=example.com] [prio=10] [group=G] [iface=lan,wifi] [profile=private] [days=mon,tue] [time=22:00-06:00] [off]");
        else if (id == FWG_ID_LIVE_REFRESH) { HANDLE h = CreateThread(NULL, 0, fwg_live_thread, NULL, 0, NULL); if (h) CloseHandle(h); }
        else if (id == FWG_ID_LIVE_BLOCKAPP) fwg_block_selected_live(0);
        else if (id == FWG_ID_LIVE_BLOCKTREE) fwg_block_selected_live(1);
        else if (id == FWG_ID_LIVE_SBX) { int s = fwg_sel(g_fwg.liveLv); if (s >= 0 && s < g_fwgLiveN) { SetWindowTextA(g_fwg.sbProg, g_fwgLive[s].path); SendMessageA(g_fwg.tab, TCM_SETCURSEL, FWG_P_SBX, 0); fwg_show_page(FWG_P_SBX); } else fwg_say("Select a connection first."); }
        else if (id == FWG_ID_TREE_REFRESH) { HANDLE h = CreateThread(NULL, 0, fwg_live_thread, NULL, 0, NULL); if (h) CloseHandle(h); fwg_fill_tree(); }
        else if (id == FWG_ID_TREE_BLOCK) { HTREEITEM sel = (HTREEITEM)SendMessageA(g_fwg.tree, TVM_GETNEXTITEM, TVGN_CARET, 0); if (!sel) fwg_say("Select a process in the tree."); else { TVITEMA it; memset(&it, 0, sizeof it); it.mask = TVIF_PARAM; it.hItem = sel; SendMessageA(g_fwg.tree, TVM_GETITEMA, 0, (LPARAM)&it); char m[300]; fwp_block_tree((unsigned)it.lParam, "tree", m, sizeof m); fwp_policy_save(); fwg_say("%s", m); } }
        else if (id == FWG_ID_LOGS_RELOAD || (id == FWG_ID_LOGS_FILTER && HIWORD(wp) == EN_CHANGE && g_fwgLog)) { if (id == FWG_ID_LOGS_RELOAD) { HANDLE h = CreateThread(NULL, 0, fwg_logs_thread, NULL, 0, NULL); if (h) CloseHandle(h); } else PostMessageA(hw, FWG_WM_REFRESH, FWG_P_LOGS, (LPARAM)-2); }
        else if (id == FWG_ID_LOGS_ENABLE) fwg_job(FWJ_ENABLELOG, NULL);
        else if (id == FWG_ID_WATCH) { if (fwp_watch_running()) { fwp_watch_stop(); fwg_say("Tamper protection stopped."); } else fwg_say(fwp_watch_start() ? "Tamper protection ON: firewall state and Kaevex rules are watched via registry notifications and repaired if altered." : "Could not start tamper protection (administrator rights needed)."); }
        else if (id == FWG_ID_DNSCHK) fwg_job(FWJ_DNSCHK, NULL);
        else if (id == FWG_ID_DNSACC) { fwp_dns_guard_accept(); fwg_say("Current DNS resolvers and hosts file accepted as the new baseline."); }
        else if (id == FWG_ID_DNSRES) fwg_job(FWJ_DNSRES, NULL);
        else if (id == FWG_ID_HASH) fwg_job(FWJ_HASH, NULL);
        else if (id == FWG_ID_BASE) fwg_job(FWJ_BASE, NULL);
        else if (id == FWG_ID_LOCK) { if (MessageBoxA(hw, "Block ALL inbound and outbound traffic on this PC?\n\nOnly the Kaevex API port from the local subnet stays open so you can unlock remotely.", "Emergency lockdown", MB_YESNO | MB_ICONWARNING) == IDYES) fwg_job(FWJ_LOCK, NULL); }
        else if (id == FWG_ID_UNLOCK) fwg_job(FWJ_UNLOCK, NULL);
        else if (id == FWG_ID_SNAP) fwg_job(FWJ_SNAP, NULL);
        else if (id == FWG_ID_RESTORE) { int s = (int)SendMessageA(g_fwg.snapList, LB_GETCURSEL, 0, 0); if (s < 0) fwg_say("Select a snapshot in the list first."); else { char n[MAX_PATH]; SendMessageA(g_fwg.snapList, LB_GETTEXT, (WPARAM)s, (LPARAM)n); if (MessageBoxA(hw, "Replace the CURRENT Windows Firewall configuration with this snapshot?", "Restore snapshot", MB_YESNO | MB_ICONQUESTION) == IDYES) fwg_job(FWJ_RESTORE, n); } }
        else if (id == FWG_ID_EXPORT) { char *t = fwp_policy_export_text(); if (t) { char path[MAX_PATH]; snprintf(path, sizeof path, "%s\\fw_policy_export.tsv", g_fwpDir); FILE *f = fopen(path, "wb"); if (f) { fputs(t, f); fclose(f); fwg_say("Policy exported to %s", path); } free(t); } }
        else if (id == FWG_ID_IMPORT) { char path[MAX_PATH]; snprintf(path, sizeof path, "%s\\fw_policy_export.tsv", g_fwpDir); FILE *f = fopen(path, "rb"); if (!f) fwg_say("Place a policy file at %s first.", path); else { fseek(f, 0, SEEK_END); long sz = ftell(f); fseek(f, 0, SEEK_SET); char *t = (sz > 0 && sz < 4000000) ? (char *)malloc((size_t)sz + 1) : NULL; if (t) { size_t rd = fread(t, 1, (size_t)sz, f); t[rd] = 0; int bad = 0; int ok = fwp_policy_import_text(t, 0, &bad); free(t); fwp_policy_save(); fwg_fill_rules(); fwg_say("Imported %d rule(s), rejected %d invalid line(s).", ok, bad); } fclose(f); } }
        else if (id == FWG_ID_PUSH) fwg_job(FWJ_PUSH, NULL);
        else if (id == FWG_ID_SB_BROWSE) { char f[MAX_PATH] = ""; OPENFILENAMEA o; memset(&o, 0, sizeof o); o.lStructSize = sizeof o; o.hwndOwner = hw; o.lpstrFilter = "Programs\0*.exe\0"; o.lpstrFile = f; o.nMaxFile = MAX_PATH; o.Flags = OFN_FILEMUSTEXIST; if (GetOpenFileNameA(&o)) SetWindowTextA(g_fwg.sbProg, f); }
        else if (id == FWG_ID_SB_CREATE) fwg_cmd_sandbox();
        return 0; }
    case FWG_WM_LOG: { char *t = (char *)lp; if (t) { SYSTEMTIME st; GetLocalTime(&st); char line[1700]; snprintf(line, sizeof line, "[%02d:%02d:%02d] %s\r\n", st.wHour, st.wMinute, st.wSecond, t); int len = GetWindowTextLengthA(g_fwg.log); SendMessageA(g_fwg.log, EM_SETSEL, (WPARAM)len, (LPARAM)len); SendMessageA(g_fwg.log, EM_REPLACESEL, FALSE, (LPARAM)line); free(t); } return 0; }
    case FWG_WM_REFRESH:
        if (wp == FWG_P_LIVE && g_fwg.page == FWG_P_LIVE) fwg_fill_live();
        else if (wp == FWG_P_LIVE && g_fwg.page == FWG_P_TREE) fwg_fill_tree();
        else if (wp == FWG_P_LOGS && g_fwg.page == FWG_P_LOGS) { int n = (int)lp; if (n == -2) { int c = 0; for (int i = 0; i < 6000 && g_fwgLog && g_fwgLog[i].date[0]; i++) c++; n = c; } fwg_fill_logs(n); }
        else if (wp == FWG_P_RULES) fwg_fill_rules();
        else if (wp == FWG_P_PROT) fwg_fill_snaps();
        return 0;
    case WM_TIMER:
        if (g_fwg.page == FWG_P_LIVE) { HANDLE h = CreateThread(NULL, 0, fwg_live_thread, NULL, 0, NULL); if (h) CloseHandle(h); }
        { char s[120]; int r = fwp_guard_remaining(); if (r > 0) { snprintf(s, sizeof s, "Pending change: confirm within %d s or it is rolled back", r); SetWindowTextA(g_fwg.status, s); } }
        return 0;
    case WM_CLOSE: KillTimer(hw, 1); DestroyWindow(hw); return 0;
    case WM_DESTROY: g_fwg.hw = NULL; return 0;
    }
    return DefWindowProcA(hw, msg, wp, lp);
}

static void fwg_open(HWND parent) {
    if (g_fwg.hw && IsWindow(g_fwg.hw)) { SetForegroundWindow(g_fwg.hw); return; }
    static BOOL reg = FALSE;
    if (!reg) { WNDCLASSA wc; memset(&wc, 0, sizeof wc); wc.lpfnWndProc = fwg_proc; wc.hInstance = GetModuleHandleA(NULL); wc.hCursor = LoadCursor(NULL, IDC_ARROW); kv_theme_init(); wc.hbrBackground = g_kvBrushBg; wc.lpszClassName = "KaevexFwPro"; RegisterClassA(&wc); reg = TRUE; }
    INITCOMMONCONTROLSEX ic = { sizeof ic, ICC_TAB_CLASSES | ICC_LISTVIEW_CLASSES | ICC_TREEVIEW_CLASSES }; InitCommonControlsEx(&ic);
    memset(&g_fwg, 0, sizeof g_fwg);
    g_fwg.hw = CreateWindowExA(0, "KaevexFwPro", "Kaevex Firewall Pro", WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN, CW_USEDEFAULT, CW_USEDEFAULT, 1180, 780, parent, NULL, GetModuleHandleA(NULL), NULL);
    HWND hw = g_fwg.hw;
    g_fwg.tab = CreateWindowExA(0, WC_TABCONTROLA, "", WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS, 0, 0, 10, 10, hw, (HMENU)FWG_ID_TAB, GetModuleHandleA(NULL), NULL);
    SendMessageA(g_fwg.tab, WM_SETFONT, (WPARAM)GetStockObject(DEFAULT_GUI_FONT), TRUE);
    const char *tabs[] = { "Rules & Policy", "Live connections", "Process tree", "Logs", "Protection", "App sandbox" };
    for (int i = 0; i < FWG_P_COUNT; i++) { TCITEMA ti; memset(&ti, 0, sizeof ti); ti.mask = TCIF_TEXT; ti.pszText = (char *)tabs[i]; SendMessageA(g_fwg.tab, TCM_INSERTITEMA, (WPARAM)i, (LPARAM)&ti); }
    g_fwg.log = fwg_ctl(-1, "EDIT", "", WS_VISIBLE | WS_VSCROLL | WS_BORDER | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL, FWG_ID_LOG);
    g_fwg.status = fwg_ctl(-1, "STATIC", "", WS_VISIBLE, 0);
    DWORD LV = WS_BORDER | LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS | WS_TABSTOP;
    g_fwg.rulesLv = fwg_ctl(FWG_P_RULES, WC_LISTVIEWA, "", LV, FWG_ID_RULES_LV);
    { const char *c[] = { "Prio", "Name", "Group", "Rule", "Guard" }; int w[] = { 50, 220, 110, 640, 90 }; fwg_cols(g_fwg.rulesLv, c, w, 5); }
    g_fwg.ruleEdit = fwg_ctl(FWG_P_RULES, "EDIT", "block out tcp name=\"Block example\" rport=23", WS_BORDER | ES_AUTOHSCROLL | WS_TABSTOP, FWG_ID_RULE_EDIT);
    fwg_btn(FWG_P_RULES, "Add / update rule", FWG_ID_ADD); fwg_btn(FWG_P_RULES, "Delete rule", FWG_ID_DEL); fwg_btn(FWG_P_RULES, "Enable / disable", FWG_ID_TOGGLE);
    fwg_btn(FWG_P_RULES, "Apply to Windows", FWG_ID_APPLY); fwg_btn(FWG_P_RULES, "Confirm change", FWG_ID_CONFIRM); fwg_btn(FWG_P_RULES, "Simulate (text box)", FWG_ID_SIM);
    fwg_btn(FWG_P_RULES, "Check conflicts", FWG_ID_CONFLICT); fwg_btn(FWG_P_RULES, "Syntax help", FWG_ID_HELP);
    g_fwg.liveLv = fwg_ctl(FWG_P_LIVE, WC_LISTVIEWA, "", LV, FWG_ID_LIVE_LV);
    { const char *c[] = { "Process", "PID", "Parent", "User", "Proto", "Local", "Remote", "Host (rDNS)", "State", "Kaevex rule", "Verdict", "Bytes in / out" }; int w[] = { 130, 55, 55, 150, 50, 140, 150, 170, 80, 150, 60, 130 }; fwg_cols(g_fwg.liveLv, c, w, 12); }
    fwg_btn(FWG_P_LIVE, "Refresh now", FWG_ID_LIVE_REFRESH); fwg_btn(FWG_P_LIVE, "Block this app", FWG_ID_LIVE_BLOCKAPP); fwg_btn(FWG_P_LIVE, "Block process tree", FWG_ID_LIVE_BLOCKTREE); fwg_btn(FWG_P_LIVE, "Sandbox this app...", FWG_ID_LIVE_SBX);
    g_fwg.tree = fwg_ctl(FWG_P_TREE, WC_TREEVIEWA, "", WS_BORDER | TVS_HASLINES | TVS_HASBUTTONS | TVS_LINESATROOT | TVS_SHOWSELALWAYS, FWG_ID_TREE);
    fwg_btn(FWG_P_TREE, "Refresh tree", FWG_ID_TREE_REFRESH); fwg_btn(FWG_P_TREE, "Block selected process + children", FWG_ID_TREE_BLOCK);
    g_fwg.logsFilter = fwg_ctl(FWG_P_LOGS, "EDIT", "", WS_BORDER | ES_AUTOHSCROLL | WS_TABSTOP, FWG_ID_LOGS_FILTER);
    SendMessageA(g_fwg.logsFilter, EM_SETCUEBANNER, TRUE, (LPARAM)L"Search: process, IP, port, DROP/ALLOW...");
    fwg_btn(FWG_P_LOGS, "Reload", FWG_ID_LOGS_RELOAD); fwg_btn(FWG_P_LOGS, "Enable logging", FWG_ID_LOGS_ENABLE);
    g_fwg.logsSum = fwg_ctl(FWG_P_LOGS, "STATIC", "", 0, FWG_ID_LOGS_SUM);
    g_fwg.logsLv = fwg_ctl(FWG_P_LOGS, WC_LISTVIEWA, "", LV, FWG_ID_LOGS_LV);
    { const char *c[] = { "Time", "Action", "Proto", "Source", "Destination", "SPort", "DPort", "Dir", "Process", "PID" }; int w[] = { 140, 60, 50, 130, 130, 55, 55, 55, 150, 60 }; fwg_cols(g_fwg.logsLv, c, w, 10); }
    fwg_btn(FWG_P_PROT, "Tamper protection ON/OFF", FWG_ID_WATCH); fwg_btn(FWG_P_PROT, "DNS / hosts check", FWG_ID_DNSCHK); fwg_btn(FWG_P_PROT, "Accept DNS baseline", FWG_ID_DNSACC); fwg_btn(FWG_P_PROT, "Restrict DNS to current resolvers", FWG_ID_DNSRES);
    fwg_btn(FWG_P_PROT, "Program-change guard now", FWG_ID_HASH); fwg_btn(FWG_P_PROT, "Adaptive baseline status", FWG_ID_BASE); fwg_btn(FWG_P_PROT, "EMERGENCY LOCKDOWN", FWG_ID_LOCK); fwg_btn(FWG_P_PROT, "Lift lockdown", FWG_ID_UNLOCK);
    fwg_btn(FWG_P_PROT, "Snapshot now", FWG_ID_SNAP); fwg_btn(FWG_P_PROT, "Restore selected snapshot", FWG_ID_RESTORE); fwg_btn(FWG_P_PROT, "Export policy file", FWG_ID_EXPORT); fwg_btn(FWG_P_PROT, "Import policy file", FWG_ID_IMPORT); fwg_btn(FWG_P_PROT, "Push policy to linked nodes", FWG_ID_PUSH);
    g_fwg.snapList = fwg_ctl(FWG_P_PROT, "LISTBOX", "", WS_BORDER | WS_VSCROLL | LBS_NOTIFY, FWG_ID_SNAPLIST);
    g_fwg.protInfo = fwg_ctl(FWG_P_PROT, "STATIC", "Snapshots (left) are taken automatically before every Apply / lockdown and restorable with one click.\r\n\r\nTamper protection watches the firewall policy in the registry and repairs deleted/modified Kaevex rules or a disabled firewall.\r\n\r\nThe adaptive baseline (runs in the background while Kaevex is open) learns each app's usual destinations for 15 minutes, then alerts on new ones.", 0, FWG_ID_PROT_INFO);
    g_fwg.sbInfo = fwg_ctl(FWG_P_SBX, "STATIC", "Per-app network sandbox: pick a program and what it may reach. It is compiled into Windows Firewall block rules (IPv4 allow-lists; IPv6 hosts are not restricted by the host allow-list). Leave hosts/ports empty for no limit.", 0, FWG_ID_SB_INFO);
    g_fwg.sbProg = fwg_ctl(FWG_P_SBX, "EDIT", "", WS_BORDER | ES_AUTOHSCROLL | WS_TABSTOP, FWG_ID_SB_PROG); SendMessageA(g_fwg.sbProg, EM_SETCUEBANNER, TRUE, (LPARAM)L"Full path to program (.exe)");
    fwg_btn(FWG_P_SBX, "Browse...", FWG_ID_SB_BROWSE);
    g_fwg.sbHosts = fwg_ctl(FWG_P_SBX, "EDIT", "", WS_BORDER | ES_AUTOHSCROLL | WS_TABSTOP, FWG_ID_SB_HOSTS); SendMessageA(g_fwg.sbHosts, EM_SETCUEBANNER, TRUE, (LPARAM)L"Allowed remote hosts, e.g. 203.0.113.0/24,198.51.100.7 (empty = any)");
    g_fwg.sbPorts = fwg_ctl(FWG_P_SBX, "EDIT", "", WS_BORDER | ES_AUTOHSCROLL | WS_TABSTOP, FWG_ID_SB_PORTS); SendMessageA(g_fwg.sbPorts, EM_SETCUEBANNER, TRUE, (LPARAM)L"Allowed remote ports, e.g. 80,443 (empty = any)");
    g_fwg.sbNet = fwg_ctl(FWG_P_SBX, "BUTTON", "Allow Internet", BS_AUTOCHECKBOX | WS_TABSTOP, FWG_ID_SB_NET); SendMessageA(g_fwg.sbNet, BM_SETCHECK, BST_CHECKED, 0);
    g_fwg.sbLan = fwg_ctl(FWG_P_SBX, "BUTTON", "Allow local network (LAN)", BS_AUTOCHECKBOX | WS_TABSTOP, FWG_ID_SB_LAN);
    fwg_btn(FWG_P_SBX, "Compile sandbox into policy", FWG_ID_SB_CREATE);
    RECT rc; GetClientRect(hw, &rc); fwg_layout(rc.right, rc.bottom);
    kv_theme_apply(hw); ShowWindow(hw, SW_SHOW); fwg_show_page(0); SetTimer(hw, 1, 3000, NULL);
    fwg_say(fwp_is_admin() ? "Administrator rights: yes - changes can be applied." : "NOT running as administrator: viewing works, but applying rules / lockdown / logging will fail. Start with Kaevex-Admin.bat.");
    fwg_say("Policy loaded: %d rule(s). Nothing changes in Windows Firewall until you press 'Apply'.", g_fwpCount);
}

#endif /* FW_PRO_GUI_H */
