/*===========================================================================
 * Kaevex CVE Intelligence - cve_intel_gui.h
 * Scan (CISA KEV + NVD) -> match -> AI plan -> apply -> verify. Every row is a real finding;
 * its status only becomes "FIXED (verified)" after the installed version was re-read.
 *===========================================================================*/
#pragma once
#ifndef CVE_INTEL_GUI_H
#define CVE_INTEL_GUI_H

#include <commctrl.h>
#include <shellapi.h>

#define CVG_WM_LOG     (WM_APP + 61)
#define CVG_WM_REFRESH (WM_APP + 62)
enum { CVG_LV = 8100, CVG_DETAIL, CVG_LOG, CVG_SCAN, CVG_DEEP, CVG_STOP, CVG_PLAN, CVG_PLANALL, CVG_APPLY, CVG_FIXALL, CVG_VERIFY, CVG_CONFIRM, CVG_OPEN, CVG_STATUS };
enum { CVJ_SCAN = 1, CVJ_DEEP, CVJ_PLAN, CVJ_PLANALL, CVJ_APPLY, CVJ_FIXALL, CVJ_VERIFY };

typedef struct { HWND hw, lv, detail, log, status; } CvgState;
static CvgState g_cvg;
typedef struct { int job, sel; } CvgJob;

static void cvg_say(const char *m) { if (g_cvg.hw && IsWindow(g_cvg.hw)) PostMessageA(g_cvg.hw, CVG_WM_LOG, 0, (LPARAM)_strdup(m)); }

static void cvg_lv_set(int row, int col, const char *t) {
    if (col == 0) { LVITEMA it; memset(&it, 0, sizeof it); it.mask = LVIF_TEXT; it.iItem = row; it.pszText = (char *)t; SendMessageA(g_cvg.lv, LVM_INSERTITEMA, 0, (LPARAM)&it); }
    else { LVITEMA it; memset(&it, 0, sizeof it); it.iSubItem = col; it.pszText = (char *)t; SendMessageA(g_cvg.lv, LVM_SETITEMTEXTA, (WPARAM)row, (LPARAM)&it); }
}

static void cvg_fill(void) {
    int sel = (int)SendMessageA(g_cvg.lv, LVM_GETNEXTITEM, (WPARAM)-1, LVNI_SELECTED);
    SendMessageA(g_cvg.lv, WM_SETREDRAW, FALSE, 0); SendMessageA(g_cvg.lv, LVM_DELETEALLITEMS, 0, 0);
    for (int i = 0; i < g_cviFindN; i++) {
        CviFinding *f = &g_cviFind[i]; CviCve *c = &g_cviCves[f->cve]; char b[48];
        cvg_lv_set(i, 0, c->kev ? (c->ransomware ? "KEV+RANSOM" : "KEV") : "");
        cvg_lv_set(i, 1, c->severity); snprintf(b, sizeof b, "%.1f", c->score10 / 10.0); cvg_lv_set(i, 2, b);
        cvg_lv_set(i, 3, c->id); cvg_lv_set(i, 4, f->appName); cvg_lv_set(i, 5, f->appVer); cvg_lv_set(i, 6, f->fixed[0] ? f->fixed : "unknown");
        cvg_lv_set(i, 7, cvi_conf_name(f->conf)); cvg_lv_set(i, 8, cvi_status_name(f->status));
        snprintf(b, sizeof b, "%s", f->planned ? cvi_action_name(f->plan.action) : "-"); cvg_lv_set(i, 9, b);
    }
    if (sel >= 0 && sel < g_cviFindN) { LVITEMA it; memset(&it, 0, sizeof it); it.stateMask = LVIS_SELECTED | LVIS_FOCUSED; it.state = LVIS_SELECTED | LVIS_FOCUSED; SendMessageA(g_cvg.lv, LVM_SETITEMSTATE, (WPARAM)sel, (LPARAM)&it); }
    SendMessageA(g_cvg.lv, WM_SETREDRAW, TRUE, 0);
    SetWindowTextA(g_cvg.status, g_cviStatusLine);
}

static void cvg_detail(int i) {
    if (i < 0 || i >= g_cviFindN) { SetWindowTextA(g_cvg.detail, ""); return; }
    CviFinding *f = &g_cviFind[i]; CviCve *c = &g_cviCves[f->cve]; char t[4200]; size_t w = 0;
    #define A(...) do { if (w < sizeof t) { int k_ = snprintf(t + w, sizeof t - w, __VA_ARGS__); if (k_ > 0) w += (size_t)k_; } } while (0)
    A("%s  |  CVSS %.1f %s  |  published %s\r\n", c->id, c->score10 / 10.0, c->severity, c->published);
    A("Application: %s %s  (match confidence %s%s)\r\n", f->appName, f->appVer, cvi_conf_name(f->conf), f->allVer ? ", NVD lists ALL versions as affected" : "");
    for (int k = 0; k < g_cviKevN; k++) if (strcmp(g_cviKev[k].cve, c->id) == 0) { A("ACTIVELY EXPLOITED (CISA KEV, added %s)%s. Required action: %s\r\n", g_cviKev[k].added, g_cviKev[k].ransomware ? ", used in ransomware campaigns" : "", g_cviKev[k].action); break; }
    A("Fixed in: %s\r\n\r\n%s\r\n\r\nAffected ranges in NVD:\r\n", f->fixed[0] ? f->fixed : "unknown (no 'fixed' version published)", c->summary);
    for (int k = 0; k < c->nr && k < 6; k++) { CviRange *r = &c->r[k]; A("  %s:%s  %s%s%s%s%s%s%s%s%s\r\n", r->vendor, r->product, r->exact[0] ? "= " : "", r->exact, r->startInc[0] ? ">= " : "", r->startInc, r->startExc[0] ? "> " : "", r->startExc, r->endInc[0] ? " <= " : "", r->endInc, r->endExc[0] ? " (< fixed)" : ""); }
    if (f->planned) { A("\r\nPlan (%s): %s %s\r\n  %s\r\n", f->plan.fromAi ? "from AI, validated" : "rule-based", cvi_action_name(f->plan.action), f->plan.wingetId, f->plan.reason);
        for (int k = 0; k < f->plan.nsteps; k++) A("  - %s\r\n", f->plan.steps[k]); }
    if (f->note[0]) A("\r\nNote: %s\r\n", f->note);
    #undef A
    SetWindowTextA(g_cvg.detail, t);
}

static DWORD WINAPI cvg_job_thread(LPVOID p) {
    CvgJob *j = (CvgJob *)p; char m[700];
    switch (j->job) {
    case CVJ_SCAN: cvi_scan(FALSE, FALSE); break;
    case CVJ_DEEP: cvi_scan(TRUE, TRUE); break;
    case CVJ_PLAN: if (InterlockedCompareExchange(&g_cviBusy, 1, 0) == 0) { g_cviStop = 0; cvi_plan(j->sel, m, sizeof m); cvg_say(m); InterlockedExchange(&g_cviBusy, 0); } break;
    case CVJ_PLANALL: if (InterlockedCompareExchange(&g_cviBusy, 1, 0) == 0) { g_cviStop = 0; int n = 0; for (int i = 0; i < g_cviFindN && !g_cviStop; i++) if (g_cviFind[i].conf >= CVI_MED && !g_cviFind[i].planned) { cvi_plan(i, m, sizeof m); cvg_say(m); n++; PostMessageA(g_cvg.hw, CVG_WM_REFRESH, 0, 0); } snprintf(m, sizeof m, "Planned %d finding(s).", n); cvg_say(m); InterlockedExchange(&g_cviBusy, 0); } break;
    case CVJ_APPLY: if (InterlockedCompareExchange(&g_cviBusy, 1, 0) == 0) { g_cviStop = 0; cvi_apply(j->sel, m, sizeof m); cvg_say(m); InterlockedExchange(&g_cviBusy, 0); } break;
    case CVJ_FIXALL: if (InterlockedCompareExchange(&g_cviBusy, 1, 0) == 0) { g_cviStop = 0; int ok = 0, tried = 0;
            for (int i = 0; i < g_cviFindN && !g_cviStop; i++) { CviFinding *f = &g_cviFind[i]; if (f->conf < CVI_MED || f->status == CVS_FIXED) continue;
                if (!f->planned) cvi_plan(i, m, sizeof m);
                if (f->plan.action != CVI_ACT_UPGRADE) continue;                 /* containment is never automatic */
                tried++; if (cvi_apply(i, m, sizeof m)) ok++; cvg_say(m); PostMessageA(g_cvg.hw, CVG_WM_REFRESH, 0, 0); }
            snprintf(m, sizeof m, "Fix-all finished: %d of %d upgrade(s) verified as fixed.", ok, tried); cvg_say(m); InterlockedExchange(&g_cviBusy, 0); } break;
    case CVJ_VERIFY: if (InterlockedCompareExchange(&g_cviBusy, 1, 0) == 0) { int n = cvi_reverify_all(); snprintf(m, sizeof m, "Re-verification: %d finding(s) are now outside their affected range.", n); cvg_say(m); InterlockedExchange(&g_cviBusy, 0); } break;
    }
    if (g_cvg.hw) PostMessageA(g_cvg.hw, CVG_WM_REFRESH, 0, 0);
    free(j); return 0;
}
static void cvg_job(int job, int sel) {
    if (g_cviBusy) { cvg_say("Another CVE operation is still running (press Stop to cancel)."); return; }
    CvgJob *j = (CvgJob *)calloc(1, sizeof *j); if (!j) return; j->job = job; j->sel = sel;
    HANDLE h = CreateThread(NULL, 0, cvg_job_thread, j, 0, NULL); if (h) CloseHandle(h); else free(j);
}

static void cvg_layout(int W, int H) {
    const int M = 8, bh = 28, logH = 110, detH = 190; int bx = M;
    int ids[] = { CVG_SCAN, CVG_DEEP, CVG_STOP, CVG_PLAN, CVG_PLANALL, CVG_APPLY, CVG_FIXALL, CVG_VERIFY, CVG_CONFIRM, CVG_OPEN };
    for (int i = 0; i < 10; i++) { MoveWindow(GetDlgItem(g_cvg.hw, ids[i]), bx, M, 118, bh, TRUE); bx += 122; }
    MoveWindow(g_cvg.status, M, M + bh + 4, W - 2 * M, 18, TRUE);
    int top = M + bh + 26, lvH = H - top - detH - logH - 3 * M;
    MoveWindow(g_cvg.lv, M, top, W - 2 * M, lvH, TRUE);
    MoveWindow(g_cvg.detail, M, top + lvH + M, W - 2 * M, detH, TRUE);
    MoveWindow(g_cvg.log, M, top + lvH + detH + 2 * M, W - 2 * M, logH, TRUE);
}

static LRESULT CALLBACK cvg_proc(HWND hw, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    KV_CTLCOLOR_CASES
    case WM_SIZE: cvg_layout(LOWORD(lp), HIWORD(lp)); return 0;
    case WM_NOTIFY: { NMHDR *nh = (NMHDR *)lp; if (nh->idFrom == CVG_LV && nh->code == LVN_ITEMCHANGED) cvg_detail((int)SendMessageA(g_cvg.lv, LVM_GETNEXTITEM, (WPARAM)-1, LVNI_SELECTED)); return 0; }
    case WM_COMMAND: {
        int id = LOWORD(wp), sel = (int)SendMessageA(g_cvg.lv, LVM_GETNEXTITEM, (WPARAM)-1, LVNI_SELECTED);
        if (id == CVG_SCAN) cvg_job(CVJ_SCAN, 0);
        else if (id == CVG_DEEP) { if (MessageBoxA(hw, "Deep scan also searches NVD by product name for your most important applications.\nWithout an NVD_API_KEY NVD allows ~5 requests per 30 s, so this can take several minutes. Continue?", "Deep scan", MB_YESNO | MB_ICONQUESTION) == IDYES) cvg_job(CVJ_DEEP, 0); }
        else if (id == CVG_STOP) { g_cviStop = 1; cvg_say("Stop requested..."); }
        else if (id == CVG_PLAN) { if (sel < 0) cvg_say("Select a finding first."); else cvg_job(CVJ_PLAN, sel); }
        else if (id == CVG_PLANALL) cvg_job(CVJ_PLANALL, 0);
        else if (id == CVG_APPLY) {
            if (sel < 0) { cvg_say("Select a finding first."); return 0; }
            CviFinding *f = &g_cviFind[sel]; char q[900];
            if (!f->planned) { cvg_say("Press 'Plan with AI' for this finding first."); return 0; }
            if (f->plan.action == CVI_ACT_UPGRADE) snprintf(q, sizeof q, "Run:\n  winget upgrade --id %s --exact --silent\n\nfor %s %s (%s).\nThe result is verified by re-reading the installed version.", f->plan.wingetId, f->appName, f->appVer, g_cviCves[f->cve].id);
            else if (f->plan.action == CVI_ACT_CONTAIN) snprintf(q, sizeof q, "BLOCK all network access (in and out) for:\n  %s\n\nThis does NOT patch %s. It can break the application's network features. A 90 s confirm-or-rollback safety net is armed.", f->exe, g_cviCves[f->cve].id);
            else { cvg_say("This plan needs a person - see the steps in the details pane."); return 0; }
            if (MessageBoxA(hw, q, "Apply fix", MB_YESNO | MB_ICONWARNING) == IDYES) cvg_job(CVJ_APPLY, sel);
        }
        else if (id == CVG_FIXALL) { if (MessageBoxA(hw, "Apply every validated winget upgrade for MEDIUM/HIGH-confidence findings?\n\nEach upgrade is verified afterwards. Network containment is never applied automatically.", "Fix all", MB_YESNO | MB_ICONWARNING) == IDYES) cvg_job(CVJ_FIXALL, 0); }
        else if (id == CVG_VERIFY) cvg_job(CVJ_VERIFY, 0);
        else if (id == CVG_CONFIRM) { if (fwp_guard_remaining() > 0) { fwp_guard_confirm(); cvg_say("Firewall change confirmed - rollback cancelled."); } else cvg_say("No firewall change is waiting for confirmation."); }
        else if (id == CVG_OPEN) { if (sel >= 0) { char url[100]; snprintf(url, sizeof url, "https://nvd.nist.gov/vuln/detail/%s", g_cviCves[g_cviFind[sel].cve].id); ShellExecuteA(hw, "open", url, NULL, NULL, SW_SHOWNORMAL); } }
        return 0; }
    case CVG_WM_LOG: { char *t = (char *)lp; if (t) { SYSTEMTIME st; GetLocalTime(&st); char line[900]; snprintf(line, sizeof line, "[%02d:%02d:%02d] %s\r\n", st.wHour, st.wMinute, st.wSecond, t); int len = GetWindowTextLengthA(g_cvg.log); SendMessageA(g_cvg.log, EM_SETSEL, (WPARAM)len, (LPARAM)len); SendMessageA(g_cvg.log, EM_REPLACESEL, FALSE, (LPARAM)line); free(t); } return 0; }
    case CVG_WM_REFRESH: cvg_fill(); cvg_detail((int)SendMessageA(g_cvg.lv, LVM_GETNEXTITEM, (WPARAM)-1, LVNI_SELECTED)); return 0;
    case WM_TIMER: if (g_cviBusy) cvg_fill(); return 0;
    case WM_CLOSE: KillTimer(hw, 1); DestroyWindow(hw); return 0;
    case WM_DESTROY: g_cvg.hw = NULL; return 0;
    }
    return DefWindowProcA(hw, msg, wp, lp);
}

static void cvg_open(HWND parent) {
    if (g_cvg.hw && IsWindow(g_cvg.hw)) { SetForegroundWindow(g_cvg.hw); return; }
    static BOOL reg = FALSE;
    if (!reg) { WNDCLASSA wc; memset(&wc, 0, sizeof wc); wc.lpfnWndProc = cvg_proc; wc.hInstance = GetModuleHandleA(NULL); wc.hCursor = LoadCursor(NULL, IDC_ARROW); kv_theme_init(); wc.hbrBackground = g_kvBrushBg; wc.lpszClassName = "KaevexCveIntel"; RegisterClassA(&wc); reg = TRUE; }
    INITCOMMONCONTROLSEX ic = { sizeof ic, ICC_LISTVIEW_CLASSES }; InitCommonControlsEx(&ic);
    cvi_init(cvg_say); cvi_cache_load(); if (g_cviKevN) cvi_evaluate();
    memset(&g_cvg, 0, sizeof g_cvg);
    HWND hw = g_cvg.hw = CreateWindowExA(0, "KaevexCveIntel", "Kaevex CVE Intelligence - CISA KEV + NVD, AI-planned, verified fixes", WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN, CW_USEDEFAULT, CW_USEDEFAULT, 1280, 800, parent, NULL, GetModuleHandleA(NULL), NULL);
    HFONT font = (HFONT)GetStockObject(DEFAULT_GUI_FONT);
    const char *bt[] = { "Scan (KEV)", "Deep scan", "Stop", "Plan with AI", "Plan all", "Apply fix...", "Fix all (AI)", "Re-verify", "Confirm fw change", "Open in NVD" }; int ids[] = { CVG_SCAN, CVG_DEEP, CVG_STOP, CVG_PLAN, CVG_PLANALL, CVG_APPLY, CVG_FIXALL, CVG_VERIFY, CVG_CONFIRM, CVG_OPEN };
    for (int i = 0; i < 10; i++) { HWND b = CreateWindowExA(0, "BUTTON", bt[i], WS_CHILD | WS_VISIBLE | WS_TABSTOP, 0, 0, 10, 10, hw, (HMENU)(INT_PTR)ids[i], GetModuleHandleA(NULL), NULL); SendMessageA(b, WM_SETFONT, (WPARAM)font, TRUE); }
    g_cvg.status = CreateWindowExA(0, "STATIC", g_cviStatusLine, WS_CHILD | WS_VISIBLE, 0, 0, 10, 10, hw, (HMENU)CVG_STATUS, GetModuleHandleA(NULL), NULL); SendMessageA(g_cvg.status, WM_SETFONT, (WPARAM)font, TRUE);
    g_cvg.lv = CreateWindowExA(0, WC_LISTVIEWA, "", WS_CHILD | WS_VISIBLE | WS_BORDER | LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS | WS_TABSTOP, 0, 0, 10, 10, hw, (HMENU)CVG_LV, GetModuleHandleA(NULL), NULL);
    const char *cn[] = { "KEV", "Severity", "CVSS", "CVE", "Application", "Installed", "Fixed in", "Match", "Status", "AI plan" }; int cw[] = { 80, 70, 50, 120, 250, 100, 100, 70, 150, 130 };
    for (int i = 0; i < 10; i++) { LVCOLUMNA c; memset(&c, 0, sizeof c); c.mask = LVCF_TEXT | LVCF_WIDTH; c.pszText = (char *)cn[i]; c.cx = cw[i]; SendMessageA(g_cvg.lv, LVM_INSERTCOLUMNA, (WPARAM)i, (LPARAM)&c); }
    SendMessageA(g_cvg.lv, LVM_SETEXTENDEDLISTVIEWSTYLE, 0, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_DOUBLEBUFFER);
    g_cvg.detail = CreateWindowExA(0, "EDIT", "", WS_CHILD | WS_VISIBLE | WS_BORDER | WS_VSCROLL | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL, 0, 0, 10, 10, hw, (HMENU)CVG_DETAIL, GetModuleHandleA(NULL), NULL);
    g_cvg.log = CreateWindowExA(0, "EDIT", "", WS_CHILD | WS_VISIBLE | WS_BORDER | WS_VSCROLL | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL, 0, 0, 10, 10, hw, (HMENU)CVG_LOG, GetModuleHandleA(NULL), NULL);
    SendMessageA(g_cvg.detail, WM_SETFONT, (WPARAM)font, TRUE); SendMessageA(g_cvg.log, WM_SETFONT, (WPARAM)font, TRUE);
    RECT rc; GetClientRect(hw, &rc); cvg_layout(rc.right, rc.bottom);
    kv_theme_apply(hw); ShowWindow(hw, SW_SHOW); SetTimer(hw, 1, 1500, NULL); cvg_fill();
    char m[400]; snprintf(m, sizeof m, "Cache: %d CVE records, %d KEV entries. %s. Press 'Scan (KEV)': actively exploited CVEs that match your installed software are fetched from NVD and verified against your exact versions.", g_cviCveN, g_cviKevN, cvi_nvd_key() ? "NVD_API_KEY found" : "No NVD_API_KEY (slower, rate-limited)");
    cvg_say(m);
}

#endif /* CVE_INTEL_GUI_H */
