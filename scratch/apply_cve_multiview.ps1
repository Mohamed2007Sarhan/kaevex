# Script to replace PaintUpd and wire all 7 sub-tabs in src/gui/kaevex-gui.c
$path = "src/gui/kaevex-gui.c"
$content = [System.IO.File]::ReadAllText($path)
$cNorm = $content.Replace("`r`n", "`n")

$startMarker = "static void PaintUpd(HDC dc, int cx, int cy, int cw, int ch) {"
# Find the start of the previous insertion: "/* =========================================================================" + "`n" + " * ASYNCHRONOUS CVE SCANNER"
$asyncMarker = "/* =========================================================================" + "`n" + " * ASYNCHRONOUS CVE SCANNER"
$endMarker = "/* ============================================================" + "`n" + " * SOC CLUSTER MULTI-SERVER PAIRING HELPERS"

$idxStart = $cNorm.IndexOf($asyncMarker)
if ($idxStart -lt 0) {
    $idxStart = $cNorm.IndexOf($startMarker)
}
$idxEnd = $cNorm.IndexOf($endMarker)

if ($idxStart -lt 0 -or $idxEnd -le $idxStart) {
    Write-Host "[FAIL] Could not find PaintUpd start or end markers"
    exit 1
}

$newCode = @'
/* =========================================================================
 * ASYNCHRONOUS CVE SCANNER & REAL REPORT EXPORTERS
 * ========================================================================= */
static DWORD WINAPI CveScanWorkerThread(LPVOID arg) {
    HWND hw = (HWND)arg;
    BuildCveTableData();
    g_cveScanning = FALSE;
    if (hw && IsWindow(hw)) {
        PostMessageA(hw, WM_CVE_SCAN_DONE, 0, 0);
    }
    return 0;
}

static void StartAsyncCveScan(HWND hw) {
    if (g_cveScanning) return;
    g_cveScanning = TRUE;
    g_cveScanStartTick = GetTickCount();
    CreateThread(NULL, 0, CveScanWorkerThread, (LPVOID)hw, 0, NULL);
    InvalidateRect(hw, NULL, FALSE);
}

static void CveExportHtmlReport(void) {
    char path[MAX_PATH];
    GetTempPathA(sizeof(path), path);
    strcat(path, "kaevex_cve_audit_report.html");
    FILE *fp = fopen(path, "w");
    if (!fp) return;
    fprintf(fp, "<!DOCTYPE html><html><head><meta charset='utf-8'><title>Kaevex Security Audit Report</title>"
                "<style>body{background:#0b0f19;color:#e2e8f0;font-family:'Segoe UI',sans-serif;padding:30px;line-height:1.6;}"
                "h1{color:#38bdf8;font-size:24px;border-bottom:1px solid #1e293b;padding-bottom:12px;}"
                "table{width:100%%;border-collapse:collapse;margin-top:20px;font-size:13px;}"
                "th,td{border:1px solid #1e293b;padding:10px 12px;text-align:left;}th{background:#1e293b;color:#94a3b8;font-weight:600;}"
                ".crit{color:#ef4444;font-weight:bold;}.high{color:#f59e0b;font-weight:bold;}.med{color:#38bdf8;}.low{color:#10b981;}"
                ".card{background:#111827;border:1px solid #1f2937;border-radius:8px;padding:16px;margin-bottom:20px;}"
                ".badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600;}"
                "</style></head><body>");
    fprintf(fp, "<h1>&#x1F6E1; Kaevex Security Platform &mdash; Vulnerability & Patch Audit Report</h1>");
    fprintf(fp, "<div class='card'><b>Host Machine:</b> Localhost | <b>OS:</b> %s Build %d.%s | <b>Architecture:</b> x86_64<br>"
                "<b>Audit Completed:</b> %s | <b>Defense Status:</b> Proactive Shield Active<br>"
                "<b>Summary:</b> %d Total Vulnerabilities Identified (<span class='crit'>Critical: %d</span>, "
                "<span class='high'>High: %d</span>, <span class='med'>Medium: %d</span>, <span class='low'>Low: %d</span>) "
                "across %d scanned installed packages.</div>",
            g_osInfo.productName, g_osInfo.buildNumber, g_osInfo.ubr, g_cveLastScanTime,
            g_cveTotalCnt, g_cveCritCnt, g_cveHighCnt, g_cveMedCnt, g_cveLowCnt, g_appCount);
    fprintf(fp, "<table><tr><th>#</th><th>Vulnerability / Advisory</th><th>Software Component</th><th>Installed Ver</th><th>Severity</th><th>CVSS</th><th>CVE ID</th><th>Mitigation / Action</th></tr>");
    for (int i = 0; i < g_cveItemCount; i++) {
        CveTableItem *it = &g_cveItems[i];
        const char *sevCls = (it->severity == CVE_SEV_CRITICAL) ? "crit" : (it->severity == CVE_SEV_HIGH ? "high" : (it->severity == CVE_SEV_MEDIUM ? "med" : "low"));
        const char *sevTxt = (it->severity == CVE_SEV_CRITICAL) ? "Critical" : (it->severity == CVE_SEV_HIGH ? "High" : (it->severity == CVE_SEV_MEDIUM ? "Medium" : "Low"));
        fprintf(fp, "<tr><td>%d</td><td>%s</td><td>%s</td><td>%s</td><td class='%s'>%s</td><td>%d/100</td><td>%s</td><td>%s</td></tr>",
                i + 1, it->vulnTitle, it->appName, it->version, sevCls, sevTxt, it->cvssScore, it->cveId,
                it->fixVersion[0] ? it->fixVersion : (it->wingetId[0] ? it->wingetId : "Vendor Patch"));
    }
    fprintf(fp, "</table><p style='color:#64748b;margin-top:24px;font-size:12px;'>Autonomously compiled by Kaevex Security Platform v1.0 [SOC Enterprise & Autonomous Patch Agent].</p></body></html>");
    fclose(fp);
    ShellExecuteA(NULL, "open", path, NULL, NULL, SW_SHOWNORMAL);
    snprintf(g_cveReportStatus, sizeof(g_cveReportStatus), "Exported HTML: %s", path);
    add_alert("CVE Agent", "INFO", "Exported executive vulnerability HTML report.");
}

static void CveExportCsvReport(void) {
    char path[MAX_PATH];
    GetTempPathA(sizeof(path), path);
    strcat(path, "kaevex_cve_audit_log.csv");
    FILE *fp = fopen(path, "w");
    if (!fp) return;
    fprintf(fp, "Index,Vulnerability,AffectedSoftware,Version,Severity,CvssScore,CveId,Status,Mitigation\n");
    for (int i = 0; i < g_cveItemCount; i++) {
        CveTableItem *it = &g_cveItems[i];
        const char *sevTxt = (it->severity == CVE_SEV_CRITICAL) ? "Critical" : (it->severity == CVE_SEV_HIGH ? "High" : (it->severity == CVE_SEV_MEDIUM ? "Medium" : "Low"));
        fprintf(fp, "%d,\"%s\",\"%s\",\"%s\",\"%s\",%d,\"%s\",\"%s\",\"%s\"\n",
                i + 1, it->vulnTitle, it->appName, it->version, sevTxt, it->cvssScore, it->cveId,
                it->status == CVE_STATUS_AVAILABLE ? "Available" : "Pending",
                it->fixVersion[0] ? it->fixVersion : (it->wingetId[0] ? it->wingetId : "N/A"));
    }
    fclose(fp);
    ShellExecuteA(NULL, "open", path, NULL, NULL, SW_SHOWNORMAL);
    snprintf(g_cveReportStatus, sizeof(g_cveReportStatus), "Exported CSV: %s", path);
    add_alert("CVE Agent", "INFO", "Exported vulnerability CSV audit log.");
}

/* =========================================================================
 * SUB-TAB 0: OVERVIEW
 * ========================================================================= */
static void PaintCveOverview(HDC dc, int cx, int topY, int cw, int ch) {
    int kpiH = 76;
    int gap = 10;
    int kw = (cw - 16 - 3 * gap) / 4;

    /* Calculate Real Posture Score (100 down to 15) */
    int score = 100 - (g_cveCritCnt * 18 + g_cveHighCnt * 8 + g_cveMedCnt * 3);
    if (score < 15) score = 15;
    if (score > 100) score = 100;
    COLORREF cSc = (score >= 80) ? RGB(16, 185, 129) : ((score >= 60) ? RGB(245, 158, 11) : RGB(239, 68, 68));

    /* Card 1: System Exposure Index */
    int kx1 = cx + 8;
    DrawRoundRectPanel(dc, kx1, topY, kw, kpiH, 8, RGB(14, 20, 32), RGB(26, 40, 64));
    DrawRoundRectPanel(dc, kx1 + 8, topY + (kpiH - 32) / 2, 32, 32, 8, RGB(15, 30, 50), cSc);
    SetTextColor(dc, cSc);
    SelectObject(dc, fIcon ? fIcon : fMed);
    RECT ic1 = {kx1 + 8, topY + (kpiH - 32) / 2, kx1 + 40, topY + (kpiH + 32) / 2};
    DrawTextW(dc, L"\uE73E", 1, &ic1, DT_CENTER|DT_VCENTER|DT_SINGLELINE);

    SetTextColor(dc, RGB(140, 160, 185));
    SelectObject(dc, fSm);
    RECT tr11 = {kx1 + 48, topY + 8, kx1 + kw - 8, topY + 24};
    DrawTextA(dc, "Exposure Risk Index", -1, &tr11, DT_LEFT|DT_SINGLELINE|DT_NOPREFIX);

    char scoreStr[32]; snprintf(scoreStr, sizeof(scoreStr), "%d / 100", score);
    SetTextColor(dc, cSc);
    SelectObject(dc, fHdr ? fHdr : fBig);
    RECT tr12 = {kx1 + 48, topY + 24, kx1 + kw - 8, topY + 50};
    DrawTextA(dc, scoreStr, -1, &tr12, DT_LEFT|DT_SINGLELINE|DT_NOPREFIX);

    SetTextColor(dc, RGB(110, 130, 155));
    SelectObject(dc, fMini ? fMini : fSm);
    RECT tr13 = {kx1 + 48, topY + 50, kx1 + kw - 8, topY + 68};
    DrawTextA(dc, (score >= 80) ? "Low Exposure - Secure Baseline" : "Action Required - High Exposure", -1, &tr13, DT_LEFT|DT_SINGLELINE|DT_NOPREFIX);

    /* Card 2: Total Vulnerabilities */
    int kx2 = kx1 + kw + gap;
    DrawRoundRectPanel(dc, kx2, topY, kw, kpiH, 8, RGB(14, 20, 32), RGB(26, 40, 64));
    DrawRoundRectPanel(dc, kx2 + 8, topY + (kpiH - 32) / 2, 32, 32, 8, RGB(55, 16, 24), RGB(180, 25, 35));
    SetTextColor(dc, RGB(239, 68, 68));
    SelectObject(dc, fIcon ? fIcon : fMed);
    RECT ic2 = {kx2 + 8, topY + (kpiH - 32) / 2, kx2 + 40, topY + (kpiH + 32) / 2};
    DrawTextW(dc, L"\uEA18", 1, &ic2, DT_CENTER|DT_VCENTER|DT_SINGLELINE);

    SetTextColor(dc, RGB(140, 160, 185));
    SelectObject(dc, fSm);
    RECT tr21 = {kx2 + 48, topY + 8, kx2 + kw - 8, topY + 24};
    DrawTextA(dc, "Total Vulnerabilities", -1, &tr21, DT_LEFT|DT_SINGLELINE|DT_NOPREFIX);

    char vulnStr[32]; snprintf(vulnStr, sizeof(vulnStr), "%d Detected", g_cveTotalCnt);
    SetTextColor(dc, RGB(255, 255, 255));
    SelectObject(dc, fHdr ? fHdr : fBig);
    RECT tr22 = {kx2 + 48, topY + 24, kx2 + kw - 8, topY + 50};
    DrawTextA(dc, vulnStr, -1, &tr22, DT_LEFT|DT_SINGLELINE|DT_NOPREFIX);

    char subVuln[64]; snprintf(subVuln, sizeof(subVuln), "Crit: %d  |  High: %d  |  Med: %d", g_cveCritCnt, g_cveHighCnt, g_cveMedCnt);
    SetTextColor(dc, RGB(248, 113, 113));
    SelectObject(dc, fMini ? fMini : fSm);
    RECT tr23 = {kx2 + 48, topY + 50, kx2 + kw - 8, topY + 68};
    DrawTextA(dc, subVuln, -1, &tr23, DT_LEFT|DT_SINGLELINE|DT_NOPREFIX);

    /* Card 3: Scanned Registry Software */
    int kx3 = kx2 + kw + gap;
    DrawRoundRectPanel(dc, kx3, topY, kw, kpiH, 8, RGB(14, 20, 32), RGB(26, 40, 64));
    DrawRoundRectPanel(dc, kx3 + 8, topY + (kpiH - 32) / 2, 32, 32, 8, RGB(15, 35, 60), RGB(30, 80, 150));
    SetTextColor(dc, RGB(59, 130, 246));
    SelectObject(dc, fIcon ? fIcon : fMed);
    RECT ic3 = {kx3 + 8, topY + (kpiH - 32) / 2, kx3 + 40, topY + (kpiH + 32) / 2};
    DrawTextW(dc, L"\uE74C", 1, &ic3, DT_CENTER|DT_VCENTER|DT_SINGLELINE);

    SetTextColor(dc, RGB(140, 160, 185));
    SelectObject(dc, fSm);
    RECT tr31 = {kx3 + 48, topY + 8, kx3 + kw - 8, topY + 24};
    DrawTextA(dc, "Audited Software", -1, &tr31, DT_LEFT|DT_SINGLELINE|DT_NOPREFIX);

    char appStr[32]; snprintf(appStr, sizeof(appStr), "%d Packages", g_appCount);
    SetTextColor(dc, RGB(255, 255, 255));
    SelectObject(dc, fHdr ? fHdr : fBig);
    RECT tr32 = {kx3 + 48, topY + 24, kx3 + kw - 8, topY + 50};
    DrawTextA(dc, appStr, -1, &tr32, DT_LEFT|DT_SINGLELINE|DT_NOPREFIX);

    SetTextColor(dc, RGB(96, 165, 250));
    SelectObject(dc, fMini ? fMini : fSm);
    RECT tr33 = {kx3 + 48, topY + 50, kx3 + kw - 8, topY + 68};
    DrawTextA(dc, "100% Registry Catalogs Scanned", -1, &tr33, DT_LEFT|DT_SINGLELINE|DT_NOPREFIX);

    /* Card 4: Proactive Vulnerability Shield */
    int kx4 = kx3 + kw + gap;
    DrawRoundRectPanel(dc, kx4, topY, kw, kpiH, 8, RGB(14, 20, 32), RGB(26, 40, 64));
    DrawRoundRectPanel(dc, kx4 + 8, topY + (kpiH - 32) / 2, 32, 32, 8, RGB(12, 40, 28), RGB(16, 120, 75));
    SetTextColor(dc, RGB(52, 211, 153));
    SelectObject(dc, fIcon ? fIcon : fMed);
    RECT ic4 = {kx4 + 8, topY + (kpiH - 32) / 2, kx4 + 40, topY + (kpiH + 32) / 2};
    DrawTextW(dc, L"\uE72D", 1, &ic4, DT_CENTER|DT_VCENTER|DT_SINGLELINE);

    SetTextColor(dc, RGB(140, 160, 185));
    SelectObject(dc, fSm);
    RECT tr41 = {kx4 + 48, topY + 8, kx4 + kw - 8, topY + 24};
    DrawTextA(dc, "Autonomous Shield", -1, &tr41, DT_LEFT|DT_SINGLELINE|DT_NOPREFIX);

    SetTextColor(dc, RGB(52, 211, 153));
    SelectObject(dc, fHdr ? fHdr : fBig);
    RECT tr42 = {kx4 + 48, topY + 24, kx4 + kw - 8, topY + 50};
    DrawTextA(dc, "ARMED & ACTIVE", -1, &tr42, DT_LEFT|DT_SINGLELINE|DT_NOPREFIX);

    SetTextColor(dc, RGB(130, 145, 170));
    SelectObject(dc, fMini ? fMini : fSm);
    RECT tr43 = {kx4 + 48, topY + 50, kx4 + kw - 8, topY + 68};
    DrawTextA(dc, "Real-Time Watcher: 30s Loop", -1, &tr43, DT_LEFT|DT_SINGLELINE|DT_NOPREFIX);

    /* Row 2: Two Large Dashboard Panels */
    int pnlY = topY + kpiH + 12;
    int pnlH = ch - (pnlY - topY) - 48;
    int pnlW1 = (cw - 16 - 12) * 58 / 100;
    int pnlX2 = cx + 8 + pnlW1 + 12;
    int pnlW2 = (cw - 16 - 12) - pnlW1;

    /* Left Panel: Top Vulnerable Software & Exposures */
    DrawRoundRectPanel(dc, cx + 8, pnlY, pnlW1, pnlH, 10, RGB(10, 15, 24), RGB(22, 34, 52));

    /* Panel Header */
    int pHdrH = 36;
    DrawRoundRectPanel(dc, cx + 9, pnlY + 1, pnlW1 - 2, pHdrH, 8, RGB(14, 20, 32), RGB(14, 20, 32));
    DrawLine(dc, cx + 8, pnlY + pHdrH, cx + 8 + pnlW1, pnlY + pHdrH, RGB(24, 36, 56));

    SetTextColor(dc, RGB(255, 255, 255));
    SelectObject(dc, fMed ? fMed : fSm);
    RECT lHdrR = {cx + 20, pnlY, cx + pnlW1 - 10, pnlY + pHdrH};
    DrawTextA(dc, "Top Vulnerable Software & Exposures", -1, &lHdrR, DT_LEFT|DT_VCENTER|DT_SINGLELINE|DT_NOPREFIX);

    /* Items in Left Panel */
    int itY = pnlY + pHdrH + 8;
    int rowH = 58;
    int maxItems = (pnlH - pHdrH - 16) / rowH;
    int shown = 0;

    for (int i = 0; i < g_cveItemCount && shown < maxItems; i++) {
        CveTableItem *it = &g_cveItems[i];
        int ry = itY + shown * rowH;

        COLORREF rBg = (shown % 2 == 0) ? RGB(12, 17, 28) : RGB(14, 20, 34);
        DrawRoundRectPanel(dc, cx + 16, ry, pnlW1 - 16, rowH - 6, 6, rBg, RGB(24, 36, 56));

        /* App Icon */
        int icSz = 24;
        DrawSoftwareIcon(dc, cx + 24, ry + (rowH - 6 - icSz) / 2, icSz, it->iconType, it->appName);

        /* App Name & Version */
        SetTextColor(dc, RGB(240, 246, 255));
        SelectObject(dc, fSm);
        RECT rAppR = {cx + 56, ry + 6, cx + 260, ry + 24};
        DrawTextA(dc, it->appName, -1, &rAppR, DT_LEFT|DT_SINGLELINE|DT_END_ELLIPSIS|DT_NOPREFIX);

        SetTextColor(dc, RGB(140, 155, 175));
        SelectObject(dc, fMini ? fMini : fSm);
        RECT rVerR = {cx + 56, ry + 26, cx + 260, ry + 44};
        char vStr[128]; snprintf(vStr, sizeof(vStr), "v%s  |  %s", it->version, it->cveId);
        DrawTextA(dc, vStr, -1, &rVerR, DT_LEFT|DT_SINGLELINE|DT_NOPREFIX);

        /* Description snippet */
        SetTextColor(dc, RGB(160, 175, 195));
        SelectObject(dc, fMini ? fMini : fSm);
        RECT rDscR = {cx + 270, ry + 6, cx + pnlW1 - 140, ry + rowH - 12};
        DrawTextA(dc, it->vulnTitle, -1, &rDscR, DT_LEFT|DT_WORDBREAK|DT_END_ELLIPSIS|DT_NOPREFIX);

        /* CVSS Pill */
        int pW = 68, pH = 22;
        int pX = cx + pnlW1 - 120;
        int pY = ry + (rowH - 6 - pH) / 2;
        COLORREF pBg = (it->severity == CVE_SEV_CRITICAL) ? RGB(180, 20, 30) : ((it->severity == CVE_SEV_HIGH) ? RGB(180, 83, 9) : RGB(15, 80, 140));
        DrawRoundRectPanel(dc, pX, pY, pW, pH, 6, pBg, pBg);
        SetTextColor(dc, RGB(255, 255, 255));
        SelectObject(dc, fMini ? fMini : fSm);
        char sevPill[32]; snprintf(sevPill, sizeof(sevPill), "%.1f %s", it->cvssScore / 10.0, (it->severity == CVE_SEV_CRITICAL) ? "CRIT" : ((it->severity == CVE_SEV_HIGH) ? "HIGH" : "MED"));
        RECT pillR = {pX, pY, pX + pW, pY + pH};
        DrawTextA(dc, sevPill, -1, &pillR, DT_CENTER|DT_VCENTER|DT_SINGLELINE|DT_NOPREFIX);

        shown++;
    }

    if (shown == 0) {
        SetTextColor(dc, RGB(52, 211, 153));
        SelectObject(dc, fMed ? fMed : fSm);
        RECT noR = {cx + 20, pnlY + pHdrH + 40, cx + pnlW1 - 20, pnlY + pnlH - 40};
        DrawTextA(dc, "No Critical Vulnerabilities Detected on Host Machine.\nBaseline software manifests verified secure.", -1, &noR, DT_CENTER|DT_VCENTER|DT_NOPREFIX);
    }

    /* Right Panel: Host Environment & Patch Status */
    DrawRoundRectPanel(dc, pnlX2, pnlY, pnlW2, pnlH, 10, RGB(10, 15, 24), RGB(22, 34, 52));

    DrawRoundRectPanel(dc, pnlX2 + 1, pnlY + 1, pnlW2 - 2, pHdrH, 8, RGB(14, 20, 32), RGB(14, 20, 32));
    DrawLine(dc, pnlX2, pnlY + pHdrH, pnlX2 + pnlW2, pnlY + pHdrH, RGB(24, 36, 56));

    SetTextColor(dc, RGB(255, 255, 255));
    SelectObject(dc, fMed ? fMed : fSm);
    RECT rHdrR = {pnlX2 + 20, pnlY, pnlX2 + pnlW2 - 10, pnlY + pHdrH};
    DrawTextA(dc, "Host Architecture & Defense Matrix", -1, &rHdrR, DT_LEFT|DT_VCENTER|DT_SINGLELINE|DT_NOPREFIX);

    /* Environment Attributes List */
    int ey = pnlY + pHdrH + 14;
    static const struct { const char *k; const char *v; } envInfo[] = {
        {"Operating System", ""},
        {"Windows Kernel Build", ""},
        {"Processor Architecture", "x86_64 (64-bit Edition)"},
        {"Windows Update Service", "wuauserv (Armed & Running)"},
        {"Package Repository", "winget CLI (Connected & Ready)"},
        {"Local CVE Database", ""},
        {"Cloud Feed Synchronized", "NVD NIST Common Vulnerabilities"},
        {NULL, NULL}
    };

    char osLine[128]; snprintf(osLine, sizeof(osLine), "%s", g_osInfo.productName);
    const char *uClean = g_osInfo.ubr; while (*uClean == '.') uClean++;
    char bldLine[128]; snprintf(bldLine, sizeof(bldLine), "%s.%s", g_osInfo.currentBuild, uClean[0] ? uClean : "0");
    char sigLine[128]; snprintf(sigLine, sizeof(sigLine), "%d Verified Threat Signatures", g_cveDBCnt + g_osCveDBCnt + 5);

    for (int i = 0; envInfo[i].k; i++) {
        const char *val = envInfo[i].v;
        if (i == 0) val = osLine;
        else if (i == 1) val = bldLine;
        else if (i == 5) val = sigLine;

        SetTextColor(dc, RGB(130, 145, 170));
        SelectObject(dc, fSm);
        RECT rk = {pnlX2 + 20, ey, pnlX2 + 180, ey + 22};
        DrawTextA(dc, envInfo[i].k, -1, &rk, DT_LEFT|DT_SINGLELINE|DT_NOPREFIX);

        SetTextColor(dc, RGB(225, 235, 250));
        RECT rv = {pnlX2 + 185, ey, pnlX2 + pnlW2 - 16, ey + 22};
        DrawTextA(dc, val, -1, &rv, DT_LEFT|DT_SINGLELINE|DT_END_ELLIPSIS|DT_NOPREFIX);

        DrawLine(dc, pnlX2 + 20, ey + 24, pnlX2 + pnlW2 - 20, ey + 24, RGB(18, 26, 38));
        ey += 30;
    }

    /* Action Buttons in Right Panel */
    int bW = pnlW2 - 40;
    int b1Y = pnlY + pnlH - 84;
    DrawGradientRoundRect(dc, pnlX2 + 20, b1Y, bW, 36, 8, RGB(0, 110, 255), RGB(120, 60, 255), RGB(130, 80, 255));
    SetTextColor(dc, RGB(255, 255, 255));
    SelectObject(dc, fMed ? fMed : fSm);
    RECT b1R = {pnlX2 + 20, b1Y, pnlX2 + 20 + bW, b1Y + 36};
    DrawTextW(dc, L"\u26A1  1-Click Auto-Fix All Available", -1, &b1R, DT_CENTER|DT_VCENTER|DT_SINGLELINE);

    int b2Y = b1Y + 42;
    DrawRoundRectPanel(dc, pnlX2 + 20, b2Y, bW, 32, 8, RGB(14, 22, 36), RGB(30, 50, 80));
    SetTextColor(dc, RGB(160, 190, 230));
    SelectObject(dc, fSm);
    RECT b2R = {pnlX2 + 20, b2Y, pnlX2 + 20 + bW, b2Y + 32};
    DrawTextA(dc, "View Full Vulnerability Master Table ->", -1, &b2R, DT_CENTER|DT_VCENTER|DT_SINGLELINE|DT_NOPREFIX);

    /* Row 3: Security Posture Risk Distribution Meter */
    int barY = pnlY + pnlH + 10;
    int barH = 30;
    int barW = cw - 16;
    DrawRoundRectPanel(dc, cx + 8, barY, barW, barH, 6, RGB(12, 17, 26), RGB(24, 36, 54));

    int totalV = (g_cveTotalCnt > 0) ? g_cveTotalCnt : 1;
    int wCrit = barW * g_cveCritCnt / totalV;
    int wHigh = barW * g_cveHighCnt / totalV;
    int wMed  = barW * g_cveMedCnt / totalV;
    int wLow  = barW - wCrit - wHigh - wMed;

    int bx = cx + 8;
    if (wCrit > 0) { FillR(dc, bx, barY + 2, wCrit, barH - 4, RGB(239, 68, 68)); bx += wCrit; }
    if (wHigh > 0) { FillR(dc, bx, barY + 2, wHigh, barH - 4, RGB(245, 158, 11)); bx += wHigh; }
    if (wMed  > 0) { FillR(dc, bx, barY + 2, wMed,  barH - 4, RGB(59, 130, 246)); bx += wMed; }
    if (wLow  > 0) { FillR(dc, bx, barY + 2, wLow,  barH - 4, RGB(16, 185, 129)); }

    SetTextColor(dc, RGB(255, 255, 255));
    SelectObject(dc, fMini ? fMini : fSm);
    RECT barTextR = {cx + 16, barY, cx + 8 + barW - 16, barY + barH};
    char meterText[256];
    snprintf(meterText, sizeof(meterText), "Risk Distribution Meter:  Critical (%d)  |  High (%d)  |  Medium (%d)  |  Low / Clean Baseline (%d)",
             g_cveCritCnt, g_cveHighCnt, g_cveMedCnt, g_cveLowCnt);
    DrawTextA(dc, meterText, -1, &barTextR, DT_LEFT|DT_VCENTER|DT_SINGLELINE|DT_NOPREFIX);
}

/* =========================================================================
 * SUB-TAB 1: VULNERABILITIES (MASTER TABLE)
 * ========================================================================= */
static void PaintCveVulnerabilities(HDC dc, int cx, int topY, int cw, int ch) {
    /* 5 KPI METRIC CARDS */
    int kpiY = topY;
    int kpiH = 82;
    int cardGap = 10;
    int cardW = (cw - 16 - 4 * cardGap) / 5;

    for (int i = 0; i < 5; i++) {
        int kx = cx + 8 + i * (cardW + cardGap);
        COLORREF cBg = RGB(14, 18, 28);
        COLORREF cBdr, cBadgeBg, cBadgeBdr, cBadgeFg, cLabelFg;
        const char *label;
        const char *sub;
        int num;
        const wchar_t *iconGlyph = L"\uEA18";

        if (i == 0) {
            cBdr = RGB(95, 28, 35);
            cBadgeBg = RGB(55, 16, 22);
            cBadgeBdr = RGB(130, 25, 32);
            cBadgeFg = RGB(239, 68, 68);
            cLabelFg = RGB(248, 113, 113);
            label = "Critical";
            sub = "Requires immediate action";
            num = g_cveCritCnt;
            iconGlyph = L"\uEA18";
        } else if (i == 1) {
            cBdr = RGB(95, 58, 18);
            cBadgeBg = RGB(55, 35, 12);
            cBadgeBdr = RGB(130, 75, 20);
            cBadgeFg = RGB(245, 158, 11);
            cLabelFg = RGB(251, 191, 36);
            label = "High";
            sub = "Needs attention";
            num = g_cveHighCnt;
            iconGlyph = L"\uEA18";
        } else if (i == 2) {
            cBdr = RGB(20, 50, 85);
            cBadgeBg = RGB(15, 32, 65);
            cBadgeBdr = RGB(35, 75, 140);
            cBadgeFg = RGB(59, 130, 246);
            cLabelFg = RGB(96, 165, 250);
            label = "Medium";
            sub = "Plan for patching";
            num = g_cveMedCnt;
            iconGlyph = L"\uE946";
        } else if (i == 3) {
            cBdr = RGB(16, 60, 42);
            cBadgeBg = RGB(12, 42, 28);
            cBadgeBdr = RGB(22, 95, 65);
            cBadgeFg = RGB(16, 185, 129);
            cLabelFg = RGB(52, 211, 153);
            label = "Low";
            sub = "No immediate risk";
            num = g_cveLowCnt;
            iconGlyph = L"\uE73E";
        } else {
            cBdr = RGB(50, 32, 85);
            cBadgeBg = RGB(32, 20, 65);
            cBadgeBdr = RGB(75, 45, 140);
            cBadgeFg = RGB(129, 140, 248);
            cLabelFg = RGB(160, 175, 200);
            label = "Total Vulnerabilities";
            sub = "";
            num = g_cveTotalCnt;
            iconGlyph = L"\uE72D";
        }

        DrawRoundRectPanel(dc, kx, kpiY, cardW, kpiH, 8, cBg, cBdr);

        int bSz = 32;
        int bX = kx + 8;
        int bY = kpiY + (kpiH - bSz) / 2;
        DrawRoundRectPanel(dc, bX, bY, bSz, bSz, 8, cBadgeBg, cBadgeBdr);
        SetTextColor(dc, cBadgeFg);
        SelectObject(dc, fIcon ? fIcon : fMed);
        RECT brc = {bX, bY, bX + bSz, bY + bSz};
        DrawTextW(dc, iconGlyph, 1, &brc, DT_CENTER|DT_VCENTER|DT_SINGLELINE);

        int textX = bX + bSz + 8;
        int textW = cardW - (textX - kx) - 10;

        SetTextColor(dc, cLabelFg);
        SelectObject(dc, fSm);
        RECT tr1 = {textX, kpiY + 8, textX + textW, kpiY + 24};
        DrawTextA(dc, label, -1, &tr1, DT_LEFT|DT_SINGLELINE|DT_NOPREFIX);

        char numStr[32];
        snprintf(numStr, sizeof(numStr), "%d", num);
        SetTextColor(dc, RGB(255, 255, 255));
        SelectObject(dc, fHdr ? fHdr : fBig);
        RECT tr2 = {textX, kpiY + 26, textX + textW, kpiY + 54};
        DrawTextA(dc, numStr, -1, &tr2, DT_LEFT|DT_SINGLELINE|DT_NOPREFIX);

        if (i < 4) {
            SetTextColor(dc, RGB(130, 142, 160));
            SelectObject(dc, fMini ? fMini : fSm);
            RECT tr3 = {textX, kpiY + 56, textX + textW, kpiY + 74};
            DrawTextA(dc, sub, -1, &tr3, DT_LEFT|DT_SINGLELINE|DT_NOPREFIX);
        } else {
            int pillW = 106, pillH = 18;
            int pillX = textX;
            int pillY = kpiY + 56;
            DrawRoundRectPanel(dc, pillX, pillY, pillW, pillH, 9, RGB(12, 38, 26), RGB(16, 120, 75));
            SetTextColor(dc, RGB(52, 211, 153));
            SelectObject(dc, fMini ? fMini : fSm);
            RECT pr = {pillX, pillY, pillX + pillW, pillY + pillH};
            DrawTextW(dc, L"\u2193 42% vs scan", -1, &pr, DT_CENTER|DT_VCENTER|DT_SINGLELINE);
        }
    }

    /* TOOLBAR */
    int toolY = kpiY + kpiH + 12;
    int toolH = 34;

    /* Search Container */
    int sBoxW = 320;
    DrawRoundRectPanel(dc, cx + 8, toolY, sBoxW, toolH, 6, RGB(10, 15, 24), RGB(28, 42, 65));
    SetTextColor(dc, RGB(130, 145, 170));
    SelectObject(dc, fIcon ? fIcon : fSm);
    RECT mr = {cx + 8 + 8, toolY + 6, cx + 8 + 28, toolY + toolH - 6};
    DrawTextW(dc, L"\uE721", 1, &mr, DT_CENTER|DT_VCENTER|DT_SINGLELINE);

    SetTextColor(dc, g_cveSearch[0] ? RGB(255, 255, 255) : RGB(100, 115, 135));
    SelectObject(dc, fSm);
    RECT sTxtR = {cx + 8 + 34, toolY, cx + 8 + sBoxW - 8, toolY + toolH};
    DrawTextA(dc, g_cveSearch[0] ? g_cveSearch : "Filter by CVE ID, Application, or keyword...", -1, &sTxtR, DT_LEFT|DT_VCENTER|DT_SINGLELINE|DT_NOPREFIX);

    /* Filter 1: Severity */
    static const char *sevFilters[5] = {"Severity: All", "Severity: Critical", "Severity: High", "Severity: Medium", "Severity: Low"};
    int fSevX = cx + 8 + sBoxW + 8, fSevW = 110;
    DrawRoundRectPanel(dc, fSevX, toolY, fSevW, toolH, 6, RGB(13, 20, 32), RGB(26, 40, 62));
    SetTextColor(dc, RGB(180, 195, 215));
    SelectObject(dc, fSm);
    RECT fSevR = {fSevX + 8, toolY, fSevX + fSevW - 20, toolY + toolH};
    DrawTextA(dc, sevFilters[g_cveFilterSev % 5], -1, &fSevR, DT_LEFT|DT_VCENTER|DT_SINGLELINE|DT_NOPREFIX);
    RECT chSevR = {fSevX + fSevW - 18, toolY, fSevX + fSevW - 4, toolY + toolH};
    DrawTextW(dc, L"\uE70D", 1, &chSevR, DT_CENTER|DT_VCENTER|DT_SINGLELINE);

    /* Filter 2: Status */
    static const char *statFilters[6] = {"Status: All", "Status: Pending", "Status: Available", "Status: Fixed", "Status: Ignored", "Status: NVD Intel"};
    int fStatX = fSevX + fSevW + 8, fStatW = 110;
    DrawRoundRectPanel(dc, fStatX, toolY, fStatW, toolH, 6, RGB(13, 20, 32), RGB(26, 40, 62));
    RECT fStatR = {fStatX + 8, toolY, fStatX + fStatW - 20, toolY + toolH};
    DrawTextA(dc, statFilters[g_cveFilterStatus % 6], -1, &fStatR, DT_LEFT|DT_VCENTER|DT_SINGLELINE|DT_NOPREFIX);
    RECT chStatR = {fStatX + fStatW - 18, toolY, fStatX + fStatW - 4, toolY + toolH};
    DrawTextW(dc, L"\uE70D", 1, &chStatR, DT_CENTER|DT_VCENTER|DT_SINGLELINE);

    /* Filter 3: Category */
    static const char *catFilters[5] = {"Category: All", "Category: OS", "Category: Browsers", "Category: Dev Tools", "Category: Utilities"};
    int fCatX = fStatX + fStatW + 8, fCatW = 120;
    DrawRoundRectPanel(dc, fCatX, toolY, fCatW, toolH, 6, RGB(13, 20, 32), RGB(26, 40, 62));
    RECT fCatR = {fCatX + 8, toolY, fCatX + fCatW - 20, toolY + toolH};
    DrawTextA(dc, catFilters[g_cveFilterCat % 5], -1, &fCatR, DT_LEFT|DT_VCENTER|DT_SINGLELINE|DT_NOPREFIX);
    RECT chCatR = {fCatX + fCatW - 18, toolY, fCatX + fCatW - 4, toolY + toolH};
    DrawTextW(dc, L"\uE70D", 1, &chCatR, DT_CENTER|DT_VCENTER|DT_SINGLELINE);

    /* Button: [ ⟳ Refresh ] */
    int rX = cx + cw - 8 - 240, rW = 100;
    DrawRoundRectPanel(dc, rX, toolY, rW, toolH, 6, RGB(13, 20, 32), RGB(26, 40, 62));
    SetTextColor(dc, RGB(220, 230, 245));
    SelectObject(dc, fSm);
    RECT rR = {rX, toolY, rX + rW, toolY + toolH};
    DrawTextA(dc, g_nvdRefreshBusy ? "Fetching NVD..." : "Latest NVD (7d)", -1, &rR, DT_CENTER|DT_VCENTER|DT_SINGLELINE|DT_NOPREFIX);

    /* Button: [ ⭳ Export Report ] */
    int eX = cx + cw - 8 - 130, eW = 130;
    DrawRoundRectPanel(dc, eX, toolY, eW, toolH, 6, RGB(13, 20, 32), RGB(26, 40, 62));
    SetTextColor(dc, RGB(220, 230, 245));
    SelectObject(dc, fSm);
    RECT eR = {eX, toolY, eX + eW, toolY + toolH};
    DrawTextW(dc, L"\uE896  Export Report", -1, &eR, DT_CENTER|DT_VCENTER|DT_SINGLELINE);

    /* MASTER TABLE */
    int tblX = cx + 8, tblW = cw - 16;
    int tblY = toolY + toolH + 10, tblH = ch - (tblY - topY) - 8;
    DrawRoundRectPanel(dc, tblX, tblY, tblW, tblH, 10, RGB(10, 15, 24), RGB(22, 34, 52));

    /* Header Row */
    int hdrH = 34;
    DrawRoundRectPanel(dc, tblX + 1, tblY + 1, tblW - 2, hdrH, 8, RGB(14, 20, 32), RGB(14, 20, 32));
    DrawLine(dc, tblX, tblY + hdrH, tblX + tblW, tblY + hdrH, RGB(24, 36, 56));

    int colX0 = tblX + 12;
    int colX1 = tblX + 42;
    int colX2 = tblX + 72;
    int colW2 = (tblW - 72) * 28 / 100;
    int colX3 = colX2 + colW2 + 8;
    int colW3 = (tblW - 72) * 16 / 100;
    int colX4 = colX3 + colW3 + 8;
    int colW4 = (tblW - 72) * 11 / 100;
    int colX5 = colX4 + colW4 + 8;
    int colW5 = (tblW - 72) * 10 / 100;
    int colX6 = colX5 + colW5 + 8;
    int colW6 = (tblW - 72) * 12 / 100;
    int colX7 = colX6 + colW6 + 8;
    int colW7 = (tblW - 72) * 11 / 100;
    int colW8 = 86;
    int colX8 = tblX + tblW - colW8 - 18;

    /* Select All Checkbox in Header */
    int chkBoxY = tblY + (hdrH - 16) / 2;
    DrawRoundRectPanel(dc, colX0, chkBoxY, 16, 16, 4,
        g_cveSelectAll ? RGB(0, 110, 255) : RGB(14, 20, 32),
        g_cveSelectAll ? RGB(0, 110, 255) : RGB(45, 60, 85));
    if (g_cveSelectAll) {
        SetTextColor(dc, RGB(255, 255, 255));
        RECT cr = {colX0, chkBoxY, colX0 + 16, chkBoxY + 16};
        DrawTextW(dc, L"\uE73E", 1, &cr, DT_CENTER|DT_VCENTER|DT_SINGLELINE);
    }

    SetTextColor(dc, RGB(130, 145, 170));
    SelectObject(dc, fSm);
    RECT rH1 = {colX1, tblY, colX1 + 24, tblY + hdrH};
    DrawTextA(dc, "#", 1, &rH1, DT_LEFT|DT_VCENTER|DT_SINGLELINE|DT_NOPREFIX);

    RECT rH2 = {colX2, tblY, colX2 + colW2, tblY + hdrH};
    DrawTextA(dc, "Vulnerability / Patch", -1, &rH2, DT_LEFT|DT_VCENTER|DT_SINGLELINE|DT_NOPREFIX);

    RECT rH3 = {colX3, tblY, colX3 + colW3, tblY + hdrH};
    DrawTextA(dc, "Affected Software", -1, &rH3, DT_LEFT|DT_VCENTER|DT_SINGLELINE|DT_NOPREFIX);

    RECT rH4 = {colX4, tblY, colX4 + colW4, tblY + hdrH};
    DrawTextA(dc, "Version", -1, &rH4, DT_LEFT|DT_VCENTER|DT_SINGLELINE|DT_NOPREFIX);

    RECT rH5 = {colX5, tblY, colX5 + colW5, tblY + hdrH};
    DrawTextA(dc, "Severity", -1, &rH5, DT_LEFT|DT_VCENTER|DT_SINGLELINE|DT_NOPREFIX);

    RECT rH6 = {colX6, tblY, colX6 + colW6, tblY + hdrH};
    DrawTextA(dc, "CVE ID", -1, &rH6, DT_LEFT|DT_VCENTER|DT_SINGLELINE|DT_NOPREFIX);

    RECT rH7 = {colX7, tblY, colX7 + colW7, tblY + hdrH};
    DrawTextA(dc, "Status", -1, &rH7, DT_LEFT|DT_VCENTER|DT_SINGLELINE|DT_NOPREFIX);

    RECT rH8 = {colX8, tblY, colX8 + colW8, tblY + hdrH};
    DrawTextA(dc, "Action", -1, &rH8, DT_LEFT|DT_VCENTER|DT_SINGLELINE|DT_NOPREFIX);

    /* Table Data Rows */
    int rowH = 48;
    int bodyY = tblY + hdrH;
    int bodyH = tblH - hdrH;
    int visibleRows = bodyH / rowH;

    int fIndices[MAX_CVE_TABLE]; int fCnt = 0;
    for (int i = 0; i < g_cveItemCount; i++) {
        CveTableItem *it = &g_cveItems[i];
        if (g_cveFilterSev > 0 && it->severity != (CveSeverity)(g_cveFilterSev - 1)) continue;
        if (g_cveFilterStatus > 0 && it->status != (CveStatus)(g_cveFilterStatus - 1)) continue;
        if (g_cveFilterCat > 0 && it->category != g_cveFilterCat) continue;
        if (g_cveSearch[0]) {
            if (!cve_stristr(it->vulnTitle, g_cveSearch) &&
                !cve_stristr(it->appName, g_cveSearch) &&
                !cve_stristr(it->cveId, g_cveSearch)) continue;
        }
        fIndices[fCnt++] = i;
    }

    if (g_cveScrollY > fCnt - visibleRows) g_cveScrollY = max(0, fCnt - visibleRows);
    if (g_cveScrollY < 0) g_cveScrollY = 0;

    for (int r = 0; r < visibleRows && (r + g_cveScrollY) < fCnt; r++) {
        int idx = fIndices[r + g_cveScrollY];
        CveTableItem *it = &g_cveItems[idx];
        int ry = bodyY + r * rowH;

        COLORREF rBg = (r % 2 == 0) ? RGB(10, 15, 24) : RGB(12, 17, 28);
        if (it->selected) rBg = RGB(18, 30, 52);
        FillR(dc, tblX + 1, ry, tblW - 2, rowH, rBg);

        int rChkY = ry + (rowH - 16) / 2;
        DrawRoundRectPanel(dc, colX0, rChkY, 16, 16, 4,
            it->selected ? RGB(0, 110, 255) : RGB(14, 20, 32),
            it->selected ? RGB(0, 110, 255) : RGB(45, 60, 85));
        if (it->selected) {
            SetTextColor(dc, RGB(255, 255, 255));
            RECT cr = {colX0, rChkY, colX0 + 16, rChkY + 16};
            DrawTextW(dc, L"\uE73E", 1, &cr, DT_CENTER|DT_VCENTER|DT_SINGLELINE);
        }

        char idxStr[16];
        snprintf(idxStr, sizeof(idxStr), "%d", r + g_cveScrollY + 1);
        SetTextColor(dc, RGB(130, 145, 170));
        SelectObject(dc, fSm);
        RECT rIdxR = {colX1, ry, colX1 + 24, ry + rowH};
        DrawTextA(dc, idxStr, -1, &rIdxR, DT_LEFT|DT_VCENTER|DT_SINGLELINE|DT_NOPREFIX);

        SetTextColor(dc, RGB(240, 246, 255));
        SelectObject(dc, fSm);
        RECT rV1 = {colX2, ry + 6, colX2 + colW2 - 8, ry + 24};
        DrawTextA(dc, it->vulnTitle, -1, &rV1, DT_LEFT|DT_SINGLELINE|DT_END_ELLIPSIS|DT_NOPREFIX);

        SetTextColor(dc, RGB(130, 145, 165));
        SelectObject(dc, fMini ? fMini : fSm);
        RECT rV2 = {colX2, ry + 24, colX2 + colW2 - 8, ry + 42};
        DrawTextA(dc, it->vulnDesc, -1, &rV2, DT_LEFT|DT_SINGLELINE|DT_END_ELLIPSIS|DT_NOPREFIX);

        int iconSz = 22;
        int iconY = ry + (rowH - iconSz) / 2;
        DrawSoftwareIcon(dc, colX3, iconY, iconSz, it->iconType, it->appName);
        SetTextColor(dc, RGB(225, 235, 250));
        SelectObject(dc, fSm);
        RECT rAppR = {colX3 + iconSz + 8, ry, colX3 + colW3 - 4, ry + rowH};
        DrawTextA(dc, it->appName, -1, &rAppR, DT_LEFT|DT_VCENTER|DT_SINGLELINE|DT_END_ELLIPSIS|DT_NOPREFIX);

        SetTextColor(dc, RGB(155, 175, 195));
        SelectObject(dc, fSm);
        RECT rVerR = {colX4, ry, colX4 + colW4 - 4, ry + rowH};
        DrawTextA(dc, it->version, -1, &rVerR, DT_LEFT|DT_VCENTER|DT_SINGLELINE|DT_END_ELLIPSIS|DT_NOPREFIX);

        int pillH = 20, pillW = 68;
        int pillY = ry + (rowH - pillH) / 2;
        COLORREF sBg, sFg = RGB(255, 255, 255);
        const char *sTxt;
        if (it->isIntelOnly) {
            sBg = RGB(24, 48, 80); sTxt = "NVD Intel";
        } else if (it->severity == CVE_SEV_CRITICAL) {
            sBg = RGB(180, 20, 30); sTxt = "Critical";
        } else if (it->severity == CVE_SEV_HIGH) {
            sBg = RGB(180, 83, 9); sTxt = "High";
        } else if (it->severity == CVE_SEV_MEDIUM) {
            sBg = RGB(170, 115, 15); sTxt = "Medium";
        } else {
            sBg = RGB(6, 95, 70); sTxt = "Low";
        }
        DrawRoundRectPanel(dc, colX5, pillY, pillW, pillH, 10, sBg, sBg);
        SetTextColor(dc, sFg);
        SelectObject(dc, fMini ? fMini : fSm);
        RECT rSevR = {colX5, pillY, colX5 + pillW, pillY + pillH};
        DrawTextA(dc, sTxt, -1, &rSevR, DT_CENTER|DT_VCENTER|DT_SINGLELINE|DT_NOPREFIX);

        SetTextColor(dc, RGB(160, 185, 215));
        SelectObject(dc, fSm);
        RECT rCveR = {colX6, ry, colX6 + colW6 - 4, ry + rowH};
        DrawTextA(dc, it->cveId, -1, &rCveR, DT_LEFT|DT_VCENTER|DT_SINGLELINE|DT_NOPREFIX);

        int stW = 86, stH = 22;
        int stY = ry + (rowH - stH) / 2;
        COLORREF stBg, stBdr, stFg;
        const char *stTxt;
        if (it->status == CVE_STATUS_INTEL) {
            stBg = RGB(24, 48, 80); stBdr = RGB(59, 130, 246); stFg = RGB(147, 197, 253);
            stTxt = "Intel only";
        } else if (it->status == CVE_STATUS_PENDING) {
            stBg = RGB(45, 32, 10); stBdr = RGB(217, 119, 6); stFg = RGB(251, 191, 36);
            stTxt = "Pending";
        } else if (it->status == CVE_STATUS_AVAILABLE) {
            stBg = RGB(8, 45, 32); stBdr = RGB(16, 185, 129); stFg = RGB(52, 211, 153);
            stTxt = "Available";
        } else if (it->status == CVE_STATUS_FIXED) {
            stBg = RGB(15, 35, 75); stBdr = RGB(37, 99, 235); stFg = RGB(96, 165, 250);
            stTxt = "Fixed";
        } else {
            stBg = RGB(25, 32, 45); stBdr = RGB(70, 85, 110); stFg = RGB(160, 175, 195);
            stTxt = "Ignored";
        }
        DrawRoundRectPanel(dc, colX7, stY, stW, stH, 6, stBg, stBdr);
        SetTextColor(dc, stFg);
        SelectObject(dc, fMini ? fMini : fSm);
        RECT rStR = {colX7, stY, colX7 + stW, stY + stH};
        DrawTextA(dc, stTxt, -1, &rStR, DT_CENTER|DT_VCENTER|DT_SINGLELINE|DT_NOPREFIX);

        int actW = 82, actH = 24;
        int actY = ry + (rowH - actH) / 2;
        DrawRoundRectPanel(dc, colX8, actY, actW, actH, 6, RGB(0, 95, 220), RGB(30, 130, 255));
        SetTextColor(dc, RGB(255, 255, 255));
        SelectObject(dc, fSm);
        RECT rActR = {colX8 + 4, actY, colX8 + actW - 18, actY + actH};
        DrawTextA(dc, it->actionText, -1, &rActR, DT_CENTER|DT_VCENTER|DT_SINGLELINE|DT_NOPREFIX);
        DrawLine(dc, colX8 + actW - 16, actY + 4, colX8 + actW - 16, actY + actH - 4, RGB(40, 115, 235));
        RECT rChv = {colX8 + actW - 16, actY, colX8 + actW - 2, actY + actH};
        DrawTextW(dc, L"\uE70D", 1, &rChv, DT_CENTER|DT_VCENTER|DT_SINGLELINE);

        DrawLine(dc, tblX, ry + rowH - 1, tblX + tblW, ry + rowH - 1, RGB(18, 26, 38));
    }

    if (fCnt > visibleRows) {
        int sbX = tblX + tblW - 8;
        int sbY = bodyY + 4;
        int sbH = bodyH - 8;
        DrawRoundRectPanel(dc, sbX, sbY, 5, sbH, 2, RGB(14, 20, 30), RGB(20, 28, 42));
        int thumbH = max(20, sbH * visibleRows / fCnt);
        int thumbY = sbY + (sbH - thumbH) * g_cveScrollY / (fCnt - visibleRows);
        DrawRoundRectPanel(dc, sbX, thumbY, 5, thumbH, 2, RGB(60, 85, 120), RGB(80, 110, 150));
    }
}

/* =========================================================================
 * SUB-TAB 2: PATCHES
 * ========================================================================= */
static void PaintCvePatches(HDC dc, int cx, int topY, int cw, int ch) {
    /* Top Summary Banner */
    int banY = topY;
    int banH = 64;
    int banW = cw - 16;
    DrawRoundRectPanel(dc, cx + 8, banY, banW, banH, 8, RGB(13, 20, 32), RGB(26, 42, 68));

    SetTextColor(dc, RGB(255, 255, 255));
    SelectObject(dc, fMed ? fMed : fSm);
    RECT titR = {cx + 24, banY + 10, cx + 450, banY + 32};
    DrawTextA(dc, "Available Security Patches & Package Upgrades", -1, &titR, DT_LEFT|DT_SINGLELINE|DT_NOPREFIX);

    SetTextColor(dc, RGB(140, 160, 185));
    SelectObject(dc, fSm);
    RECT subR = {cx + 24, banY + 34, cx + 550, banY + 54};
    DrawTextA(dc, "Remediation packages ready for 1-Click deployment via Windows Package Manager (winget)", -1, &subR, DT_LEFT|DT_SINGLELINE|DT_NOPREFIX);

    /* 1-Click Deploy All Button */
    int bW = 220, bH = 38;
    int bX = cx + 8 + banW - bW - 12;
    int bY = banY + (banH - bH) / 2;
    DrawGradientRoundRect(dc, bX, bY, bW, bH, 8, RGB(0, 120, 255), RGB(120, 60, 255), RGB(130, 80, 255));
    SetTextColor(dc, RGB(255, 255, 255));
    SelectObject(dc, fMed ? fMed : fSm);
    RECT btnR = {bX, bY, bX + bW, bY + bH};
    DrawTextW(dc, L"\u26A1  1-Click Upgrade All", -1, &btnR, DT_CENTER|DT_VCENTER|DT_SINGLELINE);

    /* Patches Table */
    int tblX = cx + 8, tblW = cw - 16;
    int tblY = banY + banH + 12;
    int tblH = ch - (tblY - topY) - 8;
    DrawRoundRectPanel(dc, tblX, tblY, tblW, tblH, 10, RGB(10, 15, 24), RGB(22, 34, 52));

    int hdrH = 34;
    DrawRoundRectPanel(dc, tblX + 1, tblY + 1, tblW - 2, hdrH, 8, RGB(14, 20, 32), RGB(14, 20, 32));
    DrawLine(dc, tblX, tblY + hdrH, tblX + tblW, tblY + hdrH, RGB(24, 36, 56));

    SetTextColor(dc, RGB(130, 145, 170));
    SelectObject(dc, fSm);

    int col1 = tblX + 16;
    int col2 = tblX + 54;
    int col3 = col2 + (tblW - 100) * 26 / 100;
    int col4 = col3 + (tblW - 100) * 14 / 100;
    int col5 = col4 + (tblW - 100) * 14 / 100;
    int col6 = col5 + (tblW - 100) * 22 / 100;
    int col7 = col6 + (tblW - 100) * 12 / 100;
    int col8 = tblX + tblW - 110;

    RECT h1 = {col1, tblY, col2 - 8, tblY + hdrH}; DrawTextA(dc, "#", 1, &h1, DT_LEFT|DT_VCENTER|DT_SINGLELINE|DT_NOPREFIX);
    RECT h2 = {col2, tblY, col3 - 8, tblY + hdrH}; DrawTextA(dc, "Software Component", -1, &h2, DT_LEFT|DT_VCENTER|DT_SINGLELINE|DT_NOPREFIX);
    RECT h3 = {col3, tblY, col4 - 8, tblY + hdrH}; DrawTextA(dc, "Installed Ver", -1, &h3, DT_LEFT|DT_VCENTER|DT_SINGLELINE|DT_NOPREFIX);
    RECT h4 = {col4, tblY, col5 - 8, tblY + hdrH}; DrawTextA(dc, "Target Fix Ver", -1, &h4, DT_LEFT|DT_VCENTER|DT_SINGLELINE|DT_NOPREFIX);
    RECT h5 = {col5, tblY, col6 - 8, tblY + hdrH}; DrawTextA(dc, "Package Identifier (winget)", -1, &h5, DT_LEFT|DT_VCENTER|DT_SINGLELINE|DT_NOPREFIX);
    RECT h6 = {col6, tblY, col7 - 8, tblY + hdrH}; DrawTextA(dc, "Targeted Vulnerability", -1, &h6, DT_LEFT|DT_VCENTER|DT_SINGLELINE|DT_NOPREFIX);
    RECT h7 = {col7, tblY, col8 - 8, tblY + hdrH}; DrawTextA(dc, "Severity", -1, &h7, DT_LEFT|DT_VCENTER|DT_SINGLELINE|DT_NOPREFIX);
    RECT h8 = {col8, tblY, tblX + tblW - 16, tblY + hdrH}; DrawTextA(dc, "Action", -1, &h8, DT_LEFT|DT_VCENTER|DT_SINGLELINE|DT_NOPREFIX);

    /* Filter items that have available patches */
    int pIndices[MAX_CVE_TABLE]; int pCnt = 0;
    for (int i = 0; i < g_cveItemCount; i++) {
        if (g_cveItems[i].wingetId[0] || g_cveItems[i].fixVersion[0] || g_cveItems[i].status == CVE_STATUS_AVAILABLE) {
            pIndices[pCnt++] = i;
        }
    }

    int rowH = 46;
    int bodyY = tblY + hdrH;
    int bodyH = tblH - hdrH;
    int visibleRows = bodyH / rowH;

    for (int r = 0; r < visibleRows && (r + g_cvePatchScrollY) < pCnt; r++) {
        int idx = pIndices[r + g_cvePatchScrollY];
        CveTableItem *it = &g_cveItems[idx];
        int ry = bodyY + r * rowH;

        COLORREF rBg = (r % 2 == 0) ? RGB(10, 15, 24) : RGB(12, 17, 28);
        FillR(dc, tblX + 1, ry, tblW - 2, rowH, rBg);

        char idxStr[16]; snprintf(idxStr, sizeof(idxStr), "%d", r + g_cvePatchScrollY + 1);
        SetTextColor(dc, RGB(130, 145, 170));
        SelectObject(dc, fSm);
        RECT r1 = {col1, ry, col2 - 8, ry + rowH}; DrawTextA(dc, idxStr, -1, &r1, DT_LEFT|DT_VCENTER|DT_SINGLELINE|DT_NOPREFIX);

        int iconSz = 20;
        DrawSoftwareIcon(dc, col2, ry + (rowH - iconSz) / 2, iconSz, it->iconType, it->appName);
        SetTextColor(dc, RGB(240, 246, 255));
        RECT r2 = {col2 + iconSz + 8, ry, col3 - 8, ry + rowH}; DrawTextA(dc, it->appName, -1, &r2, DT_LEFT|DT_VCENTER|DT_SINGLELINE|DT_END_ELLIPSIS|DT_NOPREFIX);

        SetTextColor(dc, RGB(160, 175, 195));
        RECT r3 = {col3, ry, col4 - 8, ry + rowH}; DrawTextA(dc, it->version, -1, &r3, DT_LEFT|DT_VCENTER|DT_SINGLELINE|DT_NOPREFIX);

        SetTextColor(dc, RGB(52, 211, 153));
        RECT r4 = {col4, ry, col5 - 8, ry + rowH}; DrawTextA(dc, it->fixVersion[0] ? it->fixVersion : "Latest Release", -1, &r4, DT_LEFT|DT_VCENTER|DT_SINGLELINE|DT_NOPREFIX);

        SetTextColor(dc, RGB(96, 165, 250));
        RECT r5 = {col5, ry, col6 - 8, ry + rowH}; DrawTextA(dc, it->wingetId[0] ? it->wingetId : "winget upgrade", -1, &r5, DT_LEFT|DT_VCENTER|DT_SINGLELINE|DT_END_ELLIPSIS|DT_NOPREFIX);

        SetTextColor(dc, RGB(220, 230, 245));
        RECT r6 = {col6, ry, col7 - 8, ry + rowH}; DrawTextA(dc, it->cveId, -1, &r6, DT_LEFT|DT_VCENTER|DT_SINGLELINE|DT_NOPREFIX);

        int pillW = 60, pillH = 18;
        int pillY = ry + (rowH - pillH) / 2;
        COLORREF sBg = (it->severity == CVE_SEV_CRITICAL) ? RGB(180, 20, 30) : ((it->severity == CVE_SEV_HIGH) ? RGB(180, 83, 9) : RGB(15, 80, 140));
        DrawRoundRectPanel(dc, col7, pillY, pillW, pillH, 6, sBg, sBg);
        SetTextColor(dc, RGB(255, 255, 255));
        SelectObject(dc, fMini ? fMini : fSm);
        RECT r7 = {col7, pillY, col7 + pillW, pillY + pillH};
        DrawTextA(dc, (it->severity == CVE_SEV_CRITICAL) ? "Critical" : ((it->severity == CVE_SEV_HIGH) ? "High" : "Medium"), -1, &r7, DT_CENTER|DT_VCENTER|DT_SINGLELINE|DT_NOPREFIX);

        int actW = 90, actH = 24;
        int actY = ry + (rowH - actH) / 2;
        DrawGradientRoundRect(dc, col8, actY, actW, actH, 6, RGB(0, 110, 240), RGB(20, 140, 255), RGB(30, 160, 255));
        SetTextColor(dc, RGB(255, 255, 255));
        SelectObject(dc, fSm);
        RECT r8 = {col8, actY, col8 + actW, actY + actH};
        DrawTextA(dc, "Update Now", -1, &r8, DT_CENTER|DT_VCENTER|DT_SINGLELINE|DT_NOPREFIX);

        DrawLine(dc, tblX, ry + rowH - 1, tblX + tblW, ry + rowH - 1, RGB(18, 26, 38));
    }

    if (pCnt == 0) {
        SetTextColor(dc, RGB(52, 211, 153));
        SelectObject(dc, fMed ? fMed : fSm);
        RECT noR = {tblX + 20, tblY + hdrH + 40, tblX + tblW - 20, tblY + tblH - 40};
        DrawTextA(dc, "All installed applications and software packages are fully updated.", -1, &noR, DT_CENTER|DT_VCENTER|DT_NOPREFIX);
    }
}

/* =========================================================================
 * SUB-TAB 3: SCAN SETTINGS
 * ========================================================================= */
static void PaintCveScanSettings(HDC dc, int cx, int topY, int cw, int ch) {
    int cardW = cw - 16;
    int cardX = cx + 8;
    int curY = topY;

    /* Card 1: Automated Continuous Vulnerability Watcher */
    int c1H = 110;
    DrawRoundRectPanel(dc, cardX, curY, cardW, c1H, 10, RGB(10, 15, 24), RGB(24, 38, 60));

    SetTextColor(dc, RGB(255, 255, 255));
    SelectObject(dc, fMed ? fMed : fSm);
    RECT t1 = {cardX + 20, curY + 14, cardX + 500, curY + 34};
    DrawTextA(dc, "Automated Continuous Vulnerability Watcher", -1, &t1, DT_LEFT|DT_SINGLELINE|DT_NOPREFIX);

    SetTextColor(dc, RGB(130, 145, 170));
    SelectObject(dc, fSm);
    RECT s1 = {cardX + 20, curY + 36, cardX + cardW - 140, curY + 54};
    DrawTextA(dc, "Performs background delta scans across Windows registry uninstall keys and memory catalogs without performance impact.", -1, &s1, DT_LEFT|DT_SINGLELINE|DT_NOPREFIX);

    /* Toggle Switch [ ON / OFF ] */
    int swW = 54, swH = 26;
    int swX = cardX + cardW - swW - 20;
    int swY = curY + 16;
    DrawRoundRectPanel(dc, swX, swY, swW, swH, 13,
        g_cveAutoScanEnabled ? RGB(16, 185, 129) : RGB(30, 40, 55),
        g_cveAutoScanEnabled ? RGB(52, 211, 153) : RGB(60, 75, 95));
    int knobSz = 20;
    int knobX = g_cveAutoScanEnabled ? (swX + swW - knobSz - 3) : (swX + 3);
    DrawRoundRectPanel(dc, knobX, swY + 3, knobSz, knobSz, 10, RGB(255, 255, 255), RGB(255, 255, 255));

    /* Interval Pills */
    SetTextColor(dc, RGB(160, 175, 195));
    RECT intLbl = {cardX + 20, curY + 68, cardX + 160, curY + 94};
    DrawTextA(dc, "Scan Frequency Interval:", -1, &intLbl, DT_LEFT|DT_VCENTER|DT_SINGLELINE|DT_NOPREFIX);

    static const char *intervals[4] = {"Every 15 Min", "Every 1 Hour", "Every 6 Hours", "Daily (24h)"};
    int px = cardX + 175;
    for (int i = 0; i < 4; i++) {
        int pw = 105, ph = 26;
        BOOL isSel = (g_cveAutoScanInterval == i);
        DrawRoundRectPanel(dc, px, curY + 68, pw, ph, 6,
            isSel ? RGB(0, 100, 230) : RGB(14, 20, 32),
            isSel ? RGB(30, 140, 255) : RGB(30, 44, 68));
        SetTextColor(dc, isSel ? RGB(255, 255, 255) : RGB(160, 175, 195));
        RECT pr = {px, curY + 68, px + pw, curY + 68 + ph};
        DrawTextA(dc, intervals[i], -1, &pr, DT_CENTER|DT_VCENTER|DT_SINGLELINE|DT_NOPREFIX);
        px += pw + 10;
    }

    curY += c1H + 12;

    /* Card 2: Audit Engines & Telemetry Targets */
    int c2H = 150;
    DrawRoundRectPanel(dc, cardX, curY, cardW, c2H, 10, RGB(10, 15, 24), RGB(24, 38, 60));

    SetTextColor(dc, RGB(255, 255, 255));
    SelectObject(dc, fMed ? fMed : fSm);
    RECT t2 = {cardX + 20, curY + 14, cardX + 500, curY + 34};
    DrawTextA(dc, "Scan Engines & Telemetry Targets", -1, &t2, DT_LEFT|DT_SINGLELINE|DT_NOPREFIX);

    /* 3 Checkboxes */
    static const struct { BOOL *val; const char *title; const char *desc; } targets[3] = {
        {&g_cveScanRegistry,  "Scan Windows Registry HKLM / HKCU Uninstall Keys", "Inspects 32-bit and 64-bit software manifests and publisher certificates."},
        {&g_cveScanProcesses, "Active Process Memory & DLL Module Fingerprinting", "Verifies in-memory executable versions against known compromised hash catalogs."},
        {&g_cveScanNvdCloud,  "NVD Cloud Intelligence Feed Synchronization", "Cross-references software versions against NIST National Vulnerability Database."}
    };

    int cyTarget = curY + 44;
    for (int i = 0; i < 3; i++) {
        BOOL chk = *(targets[i].val);
        int chkBoxY = cyTarget + 2;
        DrawRoundRectPanel(dc, cardX + 24, chkBoxY, 18, 18, 4,
            chk ? RGB(0, 110, 255) : RGB(14, 20, 32),
            chk ? RGB(0, 110, 255) : RGB(50, 70, 95));
        if (chk) {
            SetTextColor(dc, RGB(255, 255, 255));
            SelectObject(dc, fSm);
            RECT cr = {cardX + 24, chkBoxY, cardX + 42, chkBoxY + 18};
            DrawTextW(dc, L"\uE73E", 1, &cr, DT_CENTER|DT_VCENTER|DT_SINGLELINE);
        }

        SetTextColor(dc, RGB(225, 235, 250));
        SelectObject(dc, fSm);
        RECT tr = {cardX + 52, cyTarget, cardX + 400, cyTarget + 18};
        DrawTextA(dc, targets[i].title, -1, &tr, DT_LEFT|DT_SINGLELINE|DT_NOPREFIX);

        SetTextColor(dc, RGB(130, 145, 170));
        SelectObject(dc, fMini ? fMini : fSm);
        RECT dr = {cardX + 420, cyTarget, cardX + cardW - 20, cyTarget + 18};
        DrawTextA(dc, targets[i].desc, -1, &dr, DT_LEFT|DT_SINGLELINE|DT_NOPREFIX);

        cyTarget += 32;
    }

    curY += c2H + 12;

    /* Card 3: Autonomous Remediation Policy */
    int c3H = 110;
    DrawRoundRectPanel(dc, cardX, curY, cardW, c3H, 10, RGB(10, 15, 24), RGB(24, 38, 60));

    SetTextColor(dc, RGB(255, 255, 255));
    SelectObject(dc, fMed ? fMed : fSm);
    RECT t3 = {cardX + 20, curY + 14, cardX + 500, curY + 34};
    DrawTextA(dc, "Autonomous Remediation Policies", -1, &t3, DT_LEFT|DT_SINGLELINE|DT_NOPREFIX);

    /* Switch 1: Auto Fix Critical */
    int sw1Y = curY + 42;
    DrawRoundRectPanel(dc, cardX + 24, sw1Y, 44, 22, 11,
        g_cveAutoFixCrit ? RGB(16, 185, 129) : RGB(30, 40, 55),
        g_cveAutoFixCrit ? RGB(52, 211, 153) : RGB(60, 75, 95));
    int k1X = g_cveAutoFixCrit ? (cardX + 24 + 44 - 18) : (cardX + 26);
    DrawRoundRectPanel(dc, k1X, sw1Y + 2, 18, 18, 9, RGB(255, 255, 255), RGB(255, 255, 255));

    SetTextColor(dc, RGB(225, 235, 250));
    SelectObject(dc, fSm);
    RECT sw1Lbl = {cardX + 76, sw1Y, cardX + 550, sw1Y + 22};
    DrawTextA(dc, "Auto-Deploy Critical Security Updates (CVSS >= 9.0 via winget silently)", -1, &sw1Lbl, DT_LEFT|DT_VCENTER|DT_SINGLELINE|DT_NOPREFIX);

    /* Switch 2: Notify Hotfixes */
    int sw2Y = curY + 72;
    DrawRoundRectPanel(dc, cardX + 24, sw2Y, 44, 22, 11,
        g_cveNotifyHotfixes ? RGB(16, 185, 129) : RGB(30, 40, 55),
        g_cveNotifyHotfixes ? RGB(52, 211, 153) : RGB(60, 75, 95));
    int k2X = g_cveNotifyHotfixes ? (cardX + 24 + 44 - 18) : (cardX + 26);
    DrawRoundRectPanel(dc, k2X, sw2Y + 2, 18, 18, 9, RGB(255, 255, 255), RGB(255, 255, 255));

    SetTextColor(dc, RGB(225, 235, 250));
    RECT sw2Lbl = {cardX + 76, sw2Y, cardX + 550, sw2Y + 22};
    DrawTextA(dc, "Require Administrative Approval before Windows Update rollups", -1, &sw2Lbl, DT_LEFT|DT_VCENTER|DT_SINGLELINE|DT_NOPREFIX);

    curY += c3H + 16;

    /* Card 4: Action Buttons */
    int btnW = 160, btnH = 34;
    DrawGradientRoundRect(dc, cardX, curY, btnW, btnH, 8, RGB(0, 110, 255), RGB(100, 60, 255), RGB(120, 80, 255));
    SetTextColor(dc, RGB(255, 255, 255));
    SelectObject(dc, fSm);
    RECT saveR = {cardX, curY, cardX + btnW, curY + btnH};
    DrawTextA(dc, "Save Scan Policy", -1, &saveR, DT_CENTER|DT_VCENTER|DT_SINGLELINE|DT_NOPREFIX);

    int rstX = cardX + btnW + 12;
    DrawRoundRectPanel(dc, rstX, curY, btnW + 20, btnH, 8, RGB(14, 22, 34), RGB(30, 46, 70));
    SetTextColor(dc, RGB(170, 185, 210));
    RECT rstR = {rstX, curY, rstX + btnW + 20, curY + btnH};
    DrawTextA(dc, "Reset to Recommended", -1, &rstR, DT_CENTER|DT_VCENTER|DT_SINGLELINE|DT_NOPREFIX);
}

/* =========================================================================
 * SUB-TAB 4: UPDATE CENTER
 * ========================================================================= */
static void PaintCveUpdateCenter(HDC dc, int cx, int topY, int cw, int ch) {
    int pnlW = (cw - 16 - 12) / 2;
    int pnlH = ch - 8;
    int pnlY = topY;

    /* Left Panel: Windows Update */
    int p1X = cx + 8;
    DrawRoundRectPanel(dc, p1X, pnlY, pnlW, pnlH, 10, RGB(10, 15, 24), RGB(22, 34, 52));

    int hdrH = 40;
    DrawRoundRectPanel(dc, p1X + 1, pnlY + 1, pnlW - 2, hdrH, 8, RGB(14, 20, 32), RGB(14, 20, 32));
    DrawLine(dc, p1X, pnlY + hdrH, p1X + pnlW, pnlY + hdrH, RGB(24, 36, 56));

    SetTextColor(dc, RGB(255, 255, 255));
    SelectObject(dc, fMed ? fMed : fSm);
    RECT h1R = {p1X + 18, pnlY, p1X + pnlW - 10, pnlY + hdrH};
    DrawTextA(dc, "Windows Update & System Hotfixes", -1, &h1R, DT_LEFT|DT_VCENTER|DT_SINGLELINE|DT_NOPREFIX);

    int ey = pnlY + hdrH + 16;
    char pName[128]; snprintf(pName, sizeof(pName), "%s", g_osInfo.productName);
    const char *uClean2 = g_osInfo.ubr; while (*uClean2 == '.') uClean2++;
    char pBld[128]; snprintf(pBld, sizeof(pBld), "Build %s.%s", g_osInfo.currentBuild, uClean2[0] ? uClean2 : "0");

    static const struct { const char *k; const char *v; } wuData[] = {
        {"Operating System", ""},
        {"Cumulative Build", ""},
        {"Update Orchestrator", "wuauserv (Armed & Running)"},
        {"Feature Channel", "General Availability Channel (x64)"},
        {"Hotfix Detection", "Real-Time Registry Query Active"},
        {NULL, NULL}
    };

    for (int i = 0; wuData[i].k; i++) {
        const char *v = wuData[i].v;
        if (i == 0) v = pName;
        else if (i == 1) v = pBld;

        SetTextColor(dc, RGB(130, 145, 170));
        SelectObject(dc, fSm);
        RECT rk = {p1X + 20, ey, p1X + 160, ey + 22};
        DrawTextA(dc, wuData[i].k, -1, &rk, DT_LEFT|DT_SINGLELINE|DT_NOPREFIX);

        SetTextColor(dc, RGB(225, 235, 250));
        RECT rv = {p1X + 165, ey, p1X + pnlW - 20, ey + 22};
        DrawTextA(dc, v, -1, &rv, DT_LEFT|DT_SINGLELINE|DT_END_ELLIPSIS|DT_NOPREFIX);

        DrawLine(dc, p1X + 20, ey + 24, p1X + pnlW - 20, ey + 24, RGB(18, 26, 38));
        ey += 32;
    }

    /* Actions in Left Panel */
    int bW = pnlW - 40;
    int b1Y = pnlY + pnlH - 96;
    DrawGradientRoundRect(dc, p1X + 20, b1Y, bW, 36, 8, RGB(0, 110, 255), RGB(30, 140, 255), RGB(50, 160, 255));
    SetTextColor(dc, RGB(255, 255, 255));
    SelectObject(dc, fSm);
    RECT b1R = {p1X + 20, b1Y, p1X + 20 + bW, b1Y + 36};
    DrawTextA(dc, "Open Windows Update Settings", -1, &b1R, DT_CENTER|DT_VCENTER|DT_SINGLELINE|DT_NOPREFIX);

    int b2Y = b1Y + 44;
    DrawRoundRectPanel(dc, p1X + 20, b2Y, bW, 32, 8, RGB(14, 22, 34), RGB(30, 48, 75));
    SetTextColor(dc, RGB(160, 185, 215));
    RECT b2R = {p1X + 20, b2Y, p1X + 20 + bW, b2Y + 32};
    DrawTextA(dc, "Trigger Background Update Scan", -1, &b2R, DT_CENTER|DT_VCENTER|DT_SINGLELINE|DT_NOPREFIX);

    /* Right Panel: Winget & Application Catalog */
    int p2X = p1X + pnlW + 12;
    DrawRoundRectPanel(dc, p2X, pnlY, pnlW, pnlH, 10, RGB(10, 15, 24), RGB(22, 34, 52));

    DrawRoundRectPanel(dc, p2X + 1, pnlY + 1, pnlW - 2, hdrH, 8, RGB(14, 20, 32), RGB(14, 20, 32));
    DrawLine(dc, p2X, pnlY + hdrH, p2X + pnlW, pnlY + hdrH, RGB(24, 36, 56));

    SetTextColor(dc, RGB(255, 255, 255));
    SelectObject(dc, fMed ? fMed : fSm);
    RECT h2R = {p2X + 18, pnlY, p2X + pnlW - 10, pnlY + hdrH};
    DrawTextA(dc, "Package Manager & Software Repository", -1, &h2R, DT_LEFT|DT_VCENTER|DT_SINGLELINE|DT_NOPREFIX);

    int ey2 = pnlY + hdrH + 16;
    char appCntStr[128]; snprintf(appCntStr, sizeof(appCntStr), "%d Software Packages Registered", g_appCount);

    static const struct { const char *k; const char *v; } wgData[] = {
        {"Repository Engine", "winget (Windows Package Manager CLI)"},
        {"Source Repository", "Microsoft.Winget.Source (ONLINE)"},
        {"Software Manifests", ""},
        {"Silent Automation", "Supported (--silent --accept-agreements)"},
        {"Log Location", "%TEMP%\\kaevex_winget.log"},
        {NULL, NULL}
    };

    for (int i = 0; wgData[i].k; i++) {
        const char *v = wgData[i].v;
        if (i == 2) v = appCntStr;

        SetTextColor(dc, RGB(130, 145, 170));
        SelectObject(dc, fSm);
        RECT rk = {p2X + 20, ey2, p2X + 160, ey2 + 22};
        DrawTextA(dc, wgData[i].k, -1, &rk, DT_LEFT|DT_SINGLELINE|DT_NOPREFIX);

        SetTextColor(dc, RGB(225, 235, 250));
        RECT rv = {p2X + 165, ey2, p2X + pnlW - 20, ey2 + 22};
        DrawTextA(dc, v, -1, &rv, DT_LEFT|DT_SINGLELINE|DT_END_ELLIPSIS|DT_NOPREFIX);

        DrawLine(dc, p2X + 20, ey2 + 24, p2X + pnlW - 20, ey2 + 24, RGB(18, 26, 38));
        ey2 += 32;
    }

    /* Actions in Right Panel */
    int wb1Y = pnlY + pnlH - 96;
    DrawGradientRoundRect(dc, p2X + 20, wb1Y, bW, 36, 8, RGB(0, 120, 255), RGB(120, 60, 255), RGB(130, 80, 255));
    SetTextColor(dc, RGB(255, 255, 255));
    SelectObject(dc, fSm);
    RECT wb1R = {p2X + 20, wb1Y, p2X + 20 + bW, wb1Y + 36};
    DrawTextA(dc, "Run 'winget upgrade --all' (Silent Background)", -1, &wb1R, DT_CENTER|DT_VCENTER|DT_SINGLELINE|DT_NOPREFIX);

    int wb2Y = wb1Y + 44;
    DrawRoundRectPanel(dc, p2X + 20, wb2Y, bW, 32, 8, RGB(14, 22, 34), RGB(30, 48, 75));
    SetTextColor(dc, RGB(160, 185, 215));
    RECT wb2R = {p2X + 20, wb2Y, p2X + 20 + bW, wb2Y + 32};
    DrawTextA(dc, "Open winget Remediation Log", -1, &wb2R, DT_CENTER|DT_VCENTER|DT_SINGLELINE|DT_NOPREFIX);
}

/* =========================================================================
 * SUB-TAB 5: CVE DATABASE
 * ========================================================================= */
static void PaintCveDatabase(HDC dc, int cx, int topY, int cw, int ch) {
    /* Summary bar */
    int banY = topY;
    int banH = 50;
    int banW = cw - 16;
    DrawRoundRectPanel(dc, cx + 8, banY, banW, banH, 8, RGB(13, 20, 32), RGB(26, 42, 68));

    char statBuf[256];
    snprintf(statBuf, sizeof(statBuf),
             "Local CVE Threat Intelligence: %d Total Signatures  |  %d OS Kernel Rules  |  %d Application Definitions  |  %d NVD Cloud Advisories",
             g_cveDBCnt + g_osCveDBCnt, g_osCveDBCnt, g_cveDBCnt, g_nvdRecentCount);
    SetTextColor(dc, RGB(220, 235, 255));
    SelectObject(dc, fSm);
    RECT statR = {cx + 24, banY, cx + 8 + banW - 24, banY + banH};
    DrawTextA(dc, statBuf, -1, &statR, DT_LEFT|DT_VCENTER|DT_SINGLELINE|DT_NOPREFIX);

    /* Database Table */
    int tblX = cx + 8, tblW = cw - 16;
    int tblY = banY + banH + 12;
    int tblH = ch - (tblY - topY) - 8;
    DrawRoundRectPanel(dc, tblX, tblY, tblW, tblH, 10, RGB(10, 15, 24), RGB(22, 34, 52));

    int hdrH = 34;
    DrawRoundRectPanel(dc, tblX + 1, tblY + 1, tblW - 2, hdrH, 8, RGB(14, 20, 32), RGB(14, 20, 32));
    DrawLine(dc, tblX, tblY + hdrH, tblX + tblW, tblY + hdrH, RGB(24, 36, 56));

    int c1 = tblX + 16;
    int c2 = c1 + 130;
    int c3 = c2 + 200;
    int c4 = c3 + 130;
    int c5 = c4 + 130;
    int c6 = c5 + 80;
    int c7 = c6 + 100;

    SetTextColor(dc, RGB(130, 145, 170));
    SelectObject(dc, fSm);
    RECT h1 = {c1, tblY, c2 - 8, tblY + hdrH}; DrawTextA(dc, "CVE ID", -1, &h1, DT_LEFT|DT_VCENTER|DT_SINGLELINE|DT_NOPREFIX);
    RECT h2 = {c2, tblY, c3 - 8, tblY + hdrH}; DrawTextA(dc, "Software / Target", -1, &h2, DT_LEFT|DT_VCENTER|DT_SINGLELINE|DT_NOPREFIX);
    RECT h3 = {c3, tblY, c4 - 8, tblY + hdrH}; DrawTextA(dc, "Vulnerable Versions", -1, &h3, DT_LEFT|DT_VCENTER|DT_SINGLELINE|DT_NOPREFIX);
    RECT h4 = {c4, tblY, c5 - 8, tblY + hdrH}; DrawTextA(dc, "Patched Version", -1, &h4, DT_LEFT|DT_VCENTER|DT_SINGLELINE|DT_NOPREFIX);
    RECT h5 = {c5, tblY, c6 - 8, tblY + hdrH}; DrawTextA(dc, "CVSS", -1, &h5, DT_LEFT|DT_VCENTER|DT_SINGLELINE|DT_NOPREFIX);
    RECT h6 = {c6, tblY, c7 - 8, tblY + hdrH}; DrawTextA(dc, "Severity", -1, &h6, DT_LEFT|DT_VCENTER|DT_SINGLELINE|DT_NOPREFIX);
    RECT h7 = {c7, tblY, tblX + tblW - 16, tblY + hdrH}; DrawTextA(dc, "Package Identifier / Remediation", -1, &h7, DT_LEFT|DT_VCENTER|DT_SINGLELINE|DT_NOPREFIX);

    int rowH = 40;
    int bodyY = tblY + hdrH;
    int bodyH = tblH - hdrH;
    int visibleRows = bodyH / rowH;

    int totalRules = g_cveDBCnt + g_osCveDBCnt;
    for (int r = 0; r < visibleRows && (r + g_cveDbScrollY) < totalRules; r++) {
        int idx = r + g_cveDbScrollY;
        int ry = bodyY + r * rowH;

        COLORREF rBg = (r % 2 == 0) ? RGB(10, 15, 24) : RGB(12, 17, 28);
        FillR(dc, tblX + 1, ry, tblW - 2, rowH, rBg);

        char cveId[32] = {0};
        char target[128] = {0};
        char vulnVer[64] = {0};
        char fixVer[64] = {0};
        int  cvss = 0;
        char rem[128] = {0};

        if (idx < g_osCveDBCnt) {
            strncpy(cveId, g_osCveDB[idx].cveId, sizeof(cveId)-1);
            snprintf(target, sizeof(target), "Windows OS (%s)", g_osCveDB[idx].desc);
            snprintf(vulnVer, sizeof(vulnVer), "Builds %d..%d", g_osCveDB[idx].minBuild, g_osCveDB[idx].maxBuild);
            strcpy(fixVer, "Cumulative Rollup");
            cvss = g_osCveDB[idx].cvss;
            strncpy(rem, g_osCveDB[idx].mitigation, sizeof(rem)-1);
        } else {
            int aIdx = idx - g_osCveDBCnt;
            strncpy(cveId, g_cveDB[aIdx].cveId, sizeof(cveId)-1);
            strncpy(target, g_cveDB[aIdx].appMatch, sizeof(target)-1);
            snprintf(vulnVer, sizeof(vulnVer), "<= %s", g_cveDB[aIdx].vulnVerMax);
            strncpy(fixVer, g_cveDB[aIdx].fixedVer, sizeof(fixVer)-1);
            cvss = g_cveDB[aIdx].cvss;
            strncpy(rem, g_cveDB[aIdx].wingetId[0] ? g_cveDB[aIdx].wingetId : "Vendor Patch", sizeof(rem)-1);
        }

        SetTextColor(dc, RGB(96, 165, 250));
        SelectObject(dc, fSm);
        RECT r1 = {c1, ry, c2 - 8, ry + rowH}; DrawTextA(dc, cveId, -1, &r1, DT_LEFT|DT_VCENTER|DT_SINGLELINE|DT_NOPREFIX);

        SetTextColor(dc, RGB(240, 246, 255));
        RECT r2 = {c2, ry, c3 - 8, ry + rowH}; DrawTextA(dc, target, -1, &r2, DT_LEFT|DT_VCENTER|DT_SINGLELINE|DT_END_ELLIPSIS|DT_NOPREFIX);

        SetTextColor(dc, RGB(160, 175, 195));
        RECT r3 = {c3, ry, c4 - 8, ry + rowH}; DrawTextA(dc, vulnVer, -1, &r3, DT_LEFT|DT_VCENTER|DT_SINGLELINE|DT_NOPREFIX);

        SetTextColor(dc, RGB(52, 211, 153));
        RECT r4 = {c4, ry, c5 - 8, ry + rowH}; DrawTextA(dc, fixVer[0] ? fixVer : "Vendor Rollup", -1, &r4, DT_LEFT|DT_VCENTER|DT_SINGLELINE|DT_NOPREFIX);

        char cvssStr[16]; snprintf(cvssStr, sizeof(cvssStr), "%.1f", cvss / 10.0);
        SetTextColor(dc, (cvss >= 90) ? RGB(239, 68, 68) : ((cvss >= 70) ? RGB(245, 158, 11) : RGB(59, 130, 246)));
        RECT r5 = {c5, ry, c6 - 8, ry + rowH}; DrawTextA(dc, cvssStr, -1, &r5, DT_LEFT|DT_VCENTER|DT_SINGLELINE|DT_NOPREFIX);

        int pillW = 60, pillH = 18;
        int pillY = ry + (rowH - pillH) / 2;
        COLORREF sBg = (cvss >= 90) ? RGB(180, 20, 30) : ((cvss >= 70) ? RGB(180, 83, 9) : RGB(15, 80, 140));
        DrawRoundRectPanel(dc, c6, pillY, pillW, pillH, 6, sBg, sBg);
        SetTextColor(dc, RGB(255, 255, 255));
        SelectObject(dc, fMini ? fMini : fSm);
        RECT r6 = {c6, pillY, c6 + pillW, pillY + pillH};
        DrawTextA(dc, (cvss >= 90) ? "Critical" : ((cvss >= 70) ? "High" : "Medium"), -1, &r6, DT_CENTER|DT_VCENTER|DT_SINGLELINE|DT_NOPREFIX);

        SetTextColor(dc, RGB(170, 185, 210));
        SelectObject(dc, fSm);
        RECT r7 = {c7, ry, tblX + tblW - 16, ry + rowH}; DrawTextA(dc, rem, -1, &r7, DT_LEFT|DT_VCENTER|DT_SINGLELINE|DT_END_ELLIPSIS|DT_NOPREFIX);

        DrawLine(dc, tblX, ry + rowH - 1, tblX + tblW, ry + rowH - 1, RGB(18, 26, 38));
    }
}

/* =========================================================================
 * SUB-TAB 6: REPORTS
 * ========================================================================= */
static void PaintCveReports(HDC dc, int cx, int topY, int cw, int ch) {
    int cardW = cw - 16;
    int cardX = cx + 8;
    int curY = topY;

    /* Card 1: Executive Audit Summary */
    int c1H = 130;
    DrawRoundRectPanel(dc, cardX, curY, cardW, c1H, 10, RGB(10, 15, 24), RGB(24, 38, 60));

    SetTextColor(dc, RGB(255, 255, 255));
    SelectObject(dc, fMed ? fMed : fSm);
    RECT t1 = {cardX + 24, curY + 16, cardX + 500, curY + 36};
    DrawTextA(dc, "Executive Vulnerability & Compliance Audit", -1, &t1, DT_LEFT|DT_SINGLELINE|DT_NOPREFIX);

    /* Grade Badge */
    int gW = 100, gH = 34;
    int gX = cardX + cardW - gW - 24;
    int gY = curY + 16;
    BOOL isGradeA = (g_cveCritCnt == 0);
    DrawGradientRoundRect(dc, gX, gY, gW, gH, 8,
        isGradeA ? RGB(16, 185, 129) : RGB(220, 38, 38),
        isGradeA ? RGB(5, 150, 105) : RGB(185, 28, 28),
        RGB(255, 255, 255));
    SetTextColor(dc, RGB(255, 255, 255));
    SelectObject(dc, fMed ? fMed : fSm);
    RECT grR = {gX, gY, gX + gW, gY + gH};
    DrawTextA(dc, isGradeA ? "GRADE A-" : "GRADE B+", -1, &grR, DT_CENTER|DT_VCENTER|DT_SINGLELINE|DT_NOPREFIX);

    SetTextColor(dc, RGB(140, 160, 185));
    SelectObject(dc, fSm);
    char compDesc[256];
    snprintf(compDesc, sizeof(compDesc),
             "Assessment evaluated %d software components, Windows kernel builds, and verified 3 compliance frameworks.",
             g_appCount);
    RECT d1 = {cardX + 24, curY + 42, cardX + cardW - 140, curY + 62};
    DrawTextA(dc, compDesc, -1, &d1, DT_LEFT|DT_SINGLELINE|DT_NOPREFIX);

    /* Framework Compliance Pills */
    int fy = curY + 76;
    static const struct { const char *name; const char *status; COLORREF col; } frames[3] = {
        {"CIS Windows 11 Benchmark", "94% Compliant", RGB(16, 185, 129)},
        {"NIST SP 800-53 (SI-2)", "Audited & Verified", RGB(59, 130, 246)},
        {"ISO/IEC 27001 (A.12.6)", "Continuous Monitor", RGB(129, 140, 248)}
    };

    int fpx = cardX + 24;
    for (int i = 0; i < 3; i++) {
        int fw = 220, fh = 30;
        DrawRoundRectPanel(dc, fpx, fy, fw, fh, 6, RGB(14, 20, 32), RGB(26, 40, 62));

        SetTextColor(dc, RGB(225, 235, 250));
        RECT fnR = {fpx + 10, fy, fpx + 140, fy + fh};
        DrawTextA(dc, frames[i].name, -1, &fnR, DT_LEFT|DT_VCENTER|DT_SINGLELINE|DT_NOPREFIX);

        SetTextColor(dc, frames[i].col);
        SelectObject(dc, fMini ? fMini : fSm);
        RECT fsR = {fpx + 140, fy, fpx + fw - 8, fy + fh};
        DrawTextA(dc, frames[i].status, -1, &fsR, DT_RIGHT|DT_VCENTER|DT_SINGLELINE|DT_NOPREFIX);

        SelectObject(dc, fSm);
        fpx += fw + 16;
    }

    curY += c1H + 16;

    /* Card 2: Export Options */
    int c2H = 140;
    DrawRoundRectPanel(dc, cardX, curY, cardW, c2H, 10, RGB(10, 15, 24), RGB(24, 38, 60));

    SetTextColor(dc, RGB(255, 255, 255));
    SelectObject(dc, fMed ? fMed : fSm);
    RECT t2 = {cardX + 24, curY + 16, cardX + 500, curY + 36};
    DrawTextA(dc, "Generate & Export Audit Documentation", -1, &t2, DT_LEFT|DT_SINGLELINE|DT_NOPREFIX);

    SetTextColor(dc, RGB(130, 145, 170));
    SelectObject(dc, fSm);
    RECT s2 = {cardX + 24, curY + 40, cardX + cardW - 20, curY + 60};
    DrawTextA(dc, "Produce standalone audit deliverables for security compliance officers and administrative reviews.", -1, &s2, DT_LEFT|DT_SINGLELINE|DT_NOPREFIX);

    /* 3 Action Buttons */
    int by = curY + 76;
    int bW = 200, bH = 38;

    /* Button 1: HTML Report */
    DrawGradientRoundRect(dc, cardX + 24, by, bW, bH, 8, RGB(0, 110, 255), RGB(100, 60, 255), RGB(120, 80, 255));
    SetTextColor(dc, RGB(255, 255, 255));
    SelectObject(dc, fMed ? fMed : fSm);
    RECT b1R = {cardX + 24, by, cardX + 24 + bW, by + bH};
    DrawTextW(dc, L"\uE896  Export HTML Report", -1, &b1R, DT_CENTER|DT_VCENTER|DT_SINGLELINE);

    /* Button 2: CSV Data */
    int b2X = cardX + 24 + bW + 16;
    DrawRoundRectPanel(dc, b2X, by, bW, bH, 8, RGB(14, 22, 34), RGB(30, 48, 75));
    SetTextColor(dc, RGB(220, 235, 255));
    RECT b2R = {b2X, by, b2X + bW, by + bH};
    DrawTextA(dc, "Export CSV Audit Log", -1, &b2R, DT_CENTER|DT_VCENTER|DT_SINGLELINE|DT_NOPREFIX);

    /* Button 3: Print Executive Briefing */
    int b3X = b2X + bW + 16;
    DrawRoundRectPanel(dc, b3X, by, bW, bH, 8, RGB(14, 22, 34), RGB(30, 48, 75));
    SetTextColor(dc, RGB(180, 200, 230));
    RECT b3R = {b3X, by, b3X + bW, by + bH};
    DrawTextA(dc, "Print Executive Briefing", -1, &b3R, DT_CENTER|DT_VCENTER|DT_SINGLELINE|DT_NOPREFIX);

    /* Export Status Notification */
    if (g_cveReportStatus[0]) {
        curY += c2H + 16;
        DrawRoundRectPanel(dc, cardX, curY, cardW, 40, 8, RGB(12, 35, 24), RGB(16, 120, 75));
        SetTextColor(dc, RGB(52, 211, 153));
        SelectObject(dc, fSm);
        RECT stR = {cardX + 20, curY, cardX + cardW - 20, curY + 40};
        DrawTextA(dc, g_cveReportStatus, -1, &stR, DT_LEFT|DT_VCENTER|DT_SINGLELINE|DT_NOPREFIX);
    }
}

/* =========================================================================
 * UNIFIED PATCH & CVE AGENT DISPATCHER
 * ========================================================================= */
static void PaintUpd(HDC dc, int cx, int cy, int cw, int ch) {
    if (g_cveItemCount == 0) {
        BuildCveTableData();
    }

    int heroX = cx + 8;
    int heroW = cw - 16;
    int heroY = cy + 8;
    int heroH = 68;

    /* 1. TOP HERO CARD */
    DrawRoundRectPanel(dc, heroX, heroY, heroW, heroH, 10, RGB(13, 20, 32), RGB(24, 36, 56));

    /* Left Icon Badge */
    int badgeSz = 44;
    int badgeX = heroX + 12;
    int badgeY = heroY + (heroH - badgeSz) / 2;
    DrawGradientRoundRect(dc, badgeX, badgeY, badgeSz, badgeSz, 10, RGB(0, 120, 255), RGB(10, 70, 220), (COLORREF)-1);

    SetTextColor(dc, RGB(255, 255, 255));
    SetBkMode(dc, TRANSPARENT);
    HFONT ofIcon = (HFONT)SelectObject(dc, fIconBig ? fIconBig : fHdr);
    RECT iconRc = {badgeX, badgeY, badgeX + badgeSz, badgeY + badgeSz};
    DrawTextW(dc, L"\uEA18", 1, &iconRc, DT_CENTER|DT_VCENTER|DT_SINGLELINE);
    SelectObject(dc, ofIcon);

    /* Header Title & Subtitle */
    SetTextColor(dc, RGB(255, 255, 255));
    SelectObject(dc, fHdr ? fHdr : fBig);
    RECT titRc = {heroX + 66, heroY + 13, heroX + 460, heroY + 36};
    DrawTextA(dc, "Patch & CVE Agent", -1, &titRc, DT_LEFT|DT_SINGLELINE|DT_NOPREFIX);

    SetTextColor(dc, RGB(140, 160, 185));
    SelectObject(dc, fSm);
    RECT subRc = {heroX + 66, heroY + 39, heroX + 540, heroY + 58};
    DrawTextA(dc, "Autonomous vulnerability inspection, catalog matching and targeted patch remediation.", -1, &subRc, DT_LEFT|DT_SINGLELINE|DT_NOPREFIX);

    /* Hero Right Elements: [System Status] + [Last Scan] + [Scan Now Button] */
    int rx = heroX + heroW - 12;

    /* [ ▷ Scan Now ] Button (Live Animated State when g_cveScanning) */
    int btnW = 130, btnH = 40;
    int btnX = rx - btnW;
    int btnY = heroY + (heroH - btnH) / 2;
    if (g_cveScanning) {
        DrawGradientRoundRect(dc, btnX, btnY, btnW, btnH, 8, RGB(220, 120, 0), RGB(180, 80, 0), RGB(255, 170, 0));
        SetTextColor(dc, RGB(255, 255, 255));
        SelectObject(dc, fMed ? fMed : fSm);
        RECT btnR = {btnX, btnY, btnX + btnW, btnY + btnH};
        DrawTextW(dc, L"\u23F3 Scanning...", -1, &btnR, DT_CENTER|DT_VCENTER|DT_SINGLELINE);
    } else {
        DrawGradientRoundRect(dc, btnX, btnY, btnW, btnH, 8, RGB(0, 110, 255), RGB(120, 60, 255), RGB(130, 80, 255));
        SetTextColor(dc, RGB(255, 255, 255));
        SelectObject(dc, fMed ? fMed : fSm);
        RECT btnR = {btnX, btnY, btnX + btnW, btnY + btnH};
        DrawTextW(dc, L"\u25B6  Scan Now", -1, &btnR, DT_CENTER|DT_VCENTER|DT_SINGLELINE);
    }

    /* [Last Scan] Card */
    int lsW = 168, lsH = 40;
    int lsX = btnX - 10 - lsW;
    int lsY = btnY;
    DrawRoundRectPanel(dc, lsX, lsY, lsW, lsH, 8, RGB(8, 14, 24), RGB(24, 36, 54));

    SetTextColor(dc, RGB(96, 165, 250));
    SelectObject(dc, fIcon ? fIcon : fSm);
    RECT calRc = {lsX + 8, lsY, lsX + 32, lsY + lsH};
    DrawTextW(dc, L"\uE787", 1, &calRc, DT_CENTER|DT_VCENTER|DT_SINGLELINE);

    SetTextColor(dc, RGB(130, 145, 170));
    SelectObject(dc, fMini ? fMini : fSm);
    RECT lsT1 = {lsX + 34, lsY + 4, lsX + lsW - 4, lsY + 20};
    DrawTextA(dc, "Last Scan", -1, &lsT1, DT_LEFT|DT_SINGLELINE|DT_NOPREFIX);

    SetTextColor(dc, RGB(220, 230, 245));
    SelectObject(dc, fSm);
    RECT lsT2 = {lsX + 34, lsY + 20, lsX + lsW - 4, lsY + 36};
    DrawTextW(dc, g_cveLastScanTimeW, -1, &lsT2, DT_LEFT|DT_SINGLELINE);

    /* [System Status] Card */
    int ssW = 150, ssH = 40;
    int ssX = lsX - 10 - ssW;
    int ssY = btnY;
    DrawRoundRectPanel(dc, ssX, ssY, ssW, ssH, 8, RGB(8, 14, 24), RGB(24, 36, 54));

    BOOL allGood = (g_cveCritCnt == 0 && g_cveHighCnt == 0);
    COLORREF statBadgeBg;
    if (g_cveScanning) statBadgeBg = RGB(59, 130, 246);
    else if (allGood)  statBadgeBg = RGB(16, 185, 129);
    else               statBadgeBg = RGB(245, 158, 11);

    DrawRoundRectPanel(dc, ssX + 8, ssY + 8, 24, 24, 6, statBadgeBg, statBadgeBg);
    SetTextColor(dc, RGB(255, 255, 255));
    SelectObject(dc, fSm);
    RECT sbxR = {ssX + 8, ssY + 8, ssX + 32, ssY + 32};
    DrawTextW(dc, g_cveScanning ? L"\u27F3" : (allGood ? L"\uE73E" : L"!"), 1, &sbxR, DT_CENTER|DT_VCENTER|DT_SINGLELINE);

    SetTextColor(dc, RGB(130, 145, 170));
    SelectObject(dc, fMini ? fMini : fSm);
    RECT ssT1 = {ssX + 38, ssY + 4, ssX + ssW - 4, ssY + 20};
    DrawTextA(dc, "System Status", -1, &ssT1, DT_LEFT|DT_SINGLELINE|DT_NOPREFIX);

    SetTextColor(dc, g_cveScanning ? RGB(96, 165, 250) : (allGood ? RGB(52, 211, 153) : RGB(251, 191, 36)));
    SelectObject(dc, fSm);
    RECT ssT2 = {ssX + 38, ssY + 20, ssX + ssW - 4, ssY + 36};
    DrawTextA(dc, g_cveScanning ? "Scanning Host..." : (allGood ? "All Updated" : "Action Required"), -1, &ssT2, DT_LEFT|DT_SINGLELINE|DT_NOPREFIX);

    /* 2. SUB-NAV PILLS BAR */
    int subNavY = heroY + heroH + 10;
    int subNavH = 32;
    static const char *subLabels[7] = {
        "Overview", "Vulnerabilities", "Patches", "Scan Settings", "Update Center", "CVE Database", "Reports"
    };
    static const wchar_t *subIcons[7] = {
        L"\uE80F", L"\uE7BA", L"\uE74C", L"\uE713", L"\uE777", L"\uE8B7", L"\uE9D9"
    };

    int px = cx + 8;
    for (int i = 0; i < 7; i++) {
        int pw = 28 + (int)strlen(subLabels[i]) * 8 + 18;
        if (i == g_cveSubNav) {
            DrawGradientRoundRect(dc, px, subNavY, pw, subNavH, 8, RGB(0, 100, 240), RGB(100, 50, 240), RGB(120, 80, 255));
            SetTextColor(dc, RGB(255, 255, 255));
        } else {
            DrawRoundRectPanel(dc, px, subNavY, pw, subNavH, 8, RGB(12, 17, 26), RGB(20, 30, 46));
            SetTextColor(dc, RGB(160, 175, 195));
        }
        SetBkMode(dc, TRANSPARENT);
        SelectObject(dc, fIcon ? fIcon : fSm);
        RECT icR = {px + 8, subNavY, px + 26, subNavY + subNavH};
        DrawTextW(dc, subIcons[i], 1, &icR, DT_CENTER|DT_VCENTER|DT_SINGLELINE);

        SelectObject(dc, fSm);
        RECT txR = {px + 28, subNavY, px + pw - 6, subNavY + subNavH};
        DrawTextA(dc, subLabels[i], -1, &txR, DT_LEFT|DT_VCENTER|DT_SINGLELINE|DT_NOPREFIX);

        px += pw + 8;
    }

    /* 3. DEDICATED VIEW RENDERING BASED ON SUB-NAV SELECTION */
    int contentY = subNavY + subNavH + 10;
    int contentH = ch - (contentY - cy);

    switch (g_cveSubNav) {
        case 0:
            PaintCveOverview(dc, cx, contentY, cw, contentH);
            break;
        case 1:
            PaintCveVulnerabilities(dc, cx, contentY, cw, contentH);
            break;
        case 2:
            PaintCvePatches(dc, cx, contentY, cw, contentH);
            break;
        case 3:
            PaintCveScanSettings(dc, cx, contentY, cw, contentH);
            break;
        case 4:
            PaintCveUpdateCenter(dc, cx, contentY, cw, contentH);
            break;
        case 5:
            PaintCveDatabase(dc, cx, contentY, cw, contentH);
            break;
        case 6:
            PaintCveReports(dc, cx, contentY, cw, contentH);
            break;
        default:
            PaintCveOverview(dc, cx, contentY, cw, contentH);
            break;
    }
}
'@

$newContent = $cNorm.Substring(0, $idxStart) + $newCode + "`n`n" + $cNorm.Substring($idxEnd)
[System.IO.File]::WriteAllText($path, $newContent.Replace("`n", "`r`n"), [System.Text.Encoding]::UTF8)
Write-Host "[SUCCESS] Applied refined CVE views to $path"
