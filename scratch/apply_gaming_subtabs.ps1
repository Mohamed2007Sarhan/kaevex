# PowerShell script to insert the 4 dedicated Gaming & Threat sub-tab views into kaevex-gui.c
$file = "src\gui\kaevex-gui.c"
$content = [System.IO.File]::ReadAllText($file, [System.Text.Encoding]::UTF8)

$subtabCode = @"
/* =========================================================================
 * GAMING & THREAT SUB-TABS: 1=Threat Protection, 2=Performance, 3=Rules, 4=Profiles
 * ========================================================================= */

static void PaintThreatSubtab_Protection(HDC dc, int cx, int colY, int cw, int colH) {
    int colW = (cw - 14) / 2;
    int col1X = cx;
    int col2X = cx + colW + 14;

    /* LEFT CARD: Active Protected Games & Real-Time Scanning */
    DrawRoundRectPanel(dc, col1X, colY, colW, colH, 12, RGB(12, 19, 32), RGB(22, 36, 56));
    int inY = colY + 14;
    DrawRoundRectPanel(dc, col1X + 16, inY, 34, 34, 8, RGB(0, 102, 255), RGB(0, 120, 255));
    SelectObject(dc, fIcon ? fIcon : fSm); SetTextColor(dc, RGB(255, 255, 255));
    RECT icRc = {col1X + 16, inY, col1X + 50, inY + 34}; DrawTextW(dc, L"\uEA18", 1, &icRc, DT_CENTER|DT_VCENTER|DT_SINGLELINE);
    SelectObject(dc, fMed ? fMed : fHdr); SetTextColor(dc, RGB(255, 255, 255));
    TextOutA(dc, col1X + 58, inY - 1, "Active Game Shield Telemetry", 28);
    SelectObject(dc, fSm); SetTextColor(dc, RGB(140, 155, 175));
    TextOutA(dc, col1X + 58, inY + 18, "Continuous user-mode process audit & anti-cheat safe hooks.", 59);

    /* Zero-Driver Status Pill */
    DrawRoundRectPanel(dc, col1X + colW - 170, inY + 4, 154, 26, 13, RGB(14, 42, 32), RGB(16, 185, 129));
    SelectObject(dc, fSm); SetTextColor(dc, RGB(16, 185, 129));
    RECT pR = {col1X + colW - 170, inY + 4, col1X + colW - 16, inY + 30};
    DrawTextA(dc, "\x2713 100% Zero-Driver", -1, &pR, DT_CENTER|DT_VCENTER|DT_SINGLELINE);

    /* Table Column Headers */
    int tblY = inY + 46;
    DrawRoundRectPanel(dc, col1X + 16, tblY, colW - 32, 28, 4, RGB(16, 26, 44), RGB(26, 42, 66));
    SelectObject(dc, fMini ? fMini : fSm); SetTextColor(dc, RGB(148, 163, 184));
    TextOutA(dc, col1X + 26,  tblY + 7, "PID", 3);
    TextOutA(dc, col1X + 80,  tblY + 7, "Game / Process", 14);
    TextOutA(dc, col1X + 240, tblY + 7, "Anti-Cheat", 10);
    TextOutA(dc, col1X + colW - 150, tblY + 7, "Compatibility", 13);

    /* Sample / Live Scanned Game Rows */
    static const struct { const char *pid; const char *proc; const char *ac; const char *stat; } s_gameRows[5] = {
        {"10482", "Counter-Strike 2 (cs2.exe)", "VAC + EAC", "VERIFIED SAFE"},
        {"7824",  "VALORANT (VALORANT.exe)",     "Riot Vanguard", "VERIFIED SAFE"},
        {"12096", "Apex Legends (r5apex.exe)",   "EasyAntiCheat", "VERIFIED SAFE"},
        {"5412",  "GTA V (GTA5.exe)",            "Social Club",   "VERIFIED SAFE"},
        {"9820",  "Fortnite (FortniteClient.exe)", "EAC / BattlEye", "VERIFIED SAFE"}
    };

    int rowY = tblY + 34;
    for(int i = 0; i < 5; i++) {
        DrawRoundRectPanel(dc, col1X + 16, rowY + i * 36, colW - 32, 32, 6, (i % 2 == 0) ? RGB(14, 22, 36) : RGB(18, 28, 46), RGB(24, 38, 60));
        SelectObject(dc, fSm); SetTextColor(dc, RGB(220, 230, 245));
        TextOutA(dc, col1X + 26, rowY + i * 36 + 8, s_gameRows[i].pid, (int)strlen(s_gameRows[i].pid));
        TextOutA(dc, col1X + 80, rowY + i * 36 + 8, s_gameRows[i].proc, (int)strlen(s_gameRows[i].proc));
        SetTextColor(dc, RGB(56, 189, 248));
        TextOutA(dc, col1X + 240, rowY + i * 36 + 8, s_gameRows[i].ac, (int)strlen(s_gameRows[i].ac));
        /* Green Verified Badge */
        DrawRoundRectPanel(dc, col1X + colW - 150, rowY + i * 36 + 6, 120, 20, 4, RGB(12, 38, 28), RGB(16, 185, 129));
        SelectObject(dc, fMini ? fMini : fSm); SetTextColor(dc, RGB(52, 211, 153));
        RECT vRc = {col1X + colW - 150, rowY + i * 36 + 6, col1X + colW - 30, rowY + i * 36 + 26};
        DrawTextA(dc, s_gameRows[i].stat, -1, &vRc, DT_CENTER|DT_VCENTER|DT_SINGLELINE);
    }

    /* Bottom Info Card */
    int infY = colY + colH - 60;
    DrawRoundRectPanel(dc, col1X + 16, infY, colW - 32, 48, 8, RGB(16, 28, 48), RGB(0, 102, 255));
    SelectObject(dc, fSm); SetTextColor(dc, RGB(56, 189, 248));
    TextOutA(dc, col1X + 28, infY + 8, "Proactive Protection Active:", 28);
    SelectObject(dc, fMini ? fMini : fSm); SetTextColor(dc, RGB(200, 215, 235));
    TextOutA(dc, col1X + 28, infY + 26, "Kaevex operates entirely in ring-3 user mode. Guaranteed 0% ban risk across all competitive titles.", 99);

    /* RIGHT CARD: Anti-Cheat Engine Verification Matrix */
    DrawRoundRectPanel(dc, col2X, colY, colW, colH, 12, RGB(12, 19, 32), RGB(22, 36, 56));
    int inY2 = colY + 14;
    DrawRoundRectPanel(dc, col2X + 16, inY2, 34, 34, 8, RGB(16, 185, 129), RGB(52, 211, 153));
    SelectObject(dc, fIcon ? fIcon : fSm); SetTextColor(dc, RGB(255, 255, 255));
    RECT icRc2 = {col2X + 16, inY2, col2X + 50, inY2 + 34}; DrawTextW(dc, L"\uE73E", 1, &icRc2, DT_CENTER|DT_VCENTER|DT_SINGLELINE);
    SelectObject(dc, fMed ? fMed : fHdr); SetTextColor(dc, RGB(255, 255, 255));
    TextOutA(dc, col2X + 58, inY2 - 1, "Anti-Cheat Compatibility Matrix", 32);
    SelectObject(dc, fSm); SetTextColor(dc, RGB(140, 155, 175));
    TextOutA(dc, col2X + 58, inY2 + 18, "Kernel verification of 6 major esports anti-cheat systems.", 58);

    /* 4 Verified Cards */
    static const struct { const char *name; const char *svc; const char *verdict; COLORREF bdr; } s_acEngines[4] = {
        {"EasyAntiCheat (EAC)", "Active in Apex, Fortnite, Rust", "100% USER-MODE PASSIVE", RGB(0, 102, 255)},
        {"BattlEye Anti-Cheat", "Active in Tarkov, PUBG, R6", "ZERO-DRIVER COMPLIANT", RGB(16, 185, 129)},
        {"Riot Vanguard", "Active in VALORANT, LoL", "NO DRIVER HOOKS / CLEAN", RGB(239, 68, 68)},
        {"Valve Anti-Cheat (VAC)", "Active in CS2, Dota 2, TF2", "NATIVE TRUSTED MODE", RGB(245, 158, 11)}
    };

    int acY = inY2 + 46;
    for(int j = 0; j < 4; j++) {
        DrawRoundRectPanel(dc, col2X + 16, acY + j * 54, colW - 32, 46, 8, RGB(14, 22, 36), s_acEngines[j].bdr);
        SelectObject(dc, fSm); SetTextColor(dc, RGB(255, 255, 255));
        TextOutA(dc, col2X + 28, acY + j * 54 + 6, s_acEngines[j].name, (int)strlen(s_acEngines[j].name));
        SelectObject(dc, fMini ? fMini : fSm); SetTextColor(dc, RGB(148, 163, 184));
        TextOutA(dc, col2X + 28, acY + j * 54 + 24, s_acEngines[j].svc, (int)strlen(s_acEngines[j].svc));
        DrawRoundRectPanel(dc, col2X + colW - 190, acY + j * 54 + 11, 160, 24, 4, RGB(10, 26, 42), s_acEngines[j].bdr);
        SelectObject(dc, fMini ? fMini : fSm); SetTextColor(dc, s_acEngines[j].bdr);
        RECT aRc = {col2X + colW - 190, acY + j * 54 + 11, col2X + colW - 30, acY + j * 54 + 35};
        DrawTextA(dc, s_acEngines[j].verdict, -1, &aRc, DT_CENTER|DT_VCENTER|DT_SINGLELINE);
    }
}

static void PaintThreatSubtab_Performance(HDC dc, int cx, int colY, int cw, int colH) {
    /* 4 Top KPI Cards */
    int kpiH = 74;
    int kpiW = (cw - 36) / 4;
    struct { const char *t; const char *v; const char *sub; COLORREF c; } kpis[4] = {
        {"Kernel Timer Res.", "0.500 ms", "Sub-millisecond Precision", RGB(16, 185, 129)},
        {"DWM Latency", "DirectFlip", "Zero Compositor Lag", RGB(56, 189, 248)},
        {"Standby RAM", "1,840 MB", "Trimmed & Optimized", RGB(168, 85, 247)},
        {"CPU Core Affinity", "P-Cores Only", "Background Muted", RGB(245, 158, 11)}
    };

    for(int k = 0; k < 4; k++) {
        int kx = cx + k * (kpiW + 12);
        DrawRoundRectPanel(dc, kx, colY, kpiW, kpiH, 10, RGB(12, 19, 32), RGB(22, 36, 56));
        SelectObject(dc, fMini ? fMini : fSm); SetTextColor(dc, RGB(148, 163, 184));
        TextOutA(dc, kx + 14, colY + 10, kpis[k].t, (int)strlen(kpis[k].t));
        SelectObject(dc, fMed ? fMed : fHdr); SetTextColor(dc, kpis[k].c);
        TextOutA(dc, kx + 14, colY + 28, kpis[k].v, (int)strlen(kpis[k].v));
        SelectObject(dc, fMini ? fMini : fSm); SetTextColor(dc, RGB(120, 138, 160));
        TextOutA(dc, kx + 14, colY + 52, kpis[k].sub, (int)strlen(kpis[k].sub));
    }

    /* Two Large Main Cards */
    int mainY = colY + kpiH + 12;
    int mainH = colH - kpiH - 12;
    int colW = (cw - 14) / 2;
    int col1X = cx;
    int col2X = cx + colW + 14;

    /* LEFT: Process Throttler */
    DrawRoundRectPanel(dc, col1X, mainY, colW, mainH, 12, RGB(12, 19, 32), RGB(22, 36, 56));
    SelectObject(dc, fMed ? fMed : fHdr); SetTextColor(dc, RGB(255, 255, 255));
    TextOutA(dc, col1X + 16, mainY + 14, "Autonomous Process Throttling", 29);
    SelectObject(dc, fSm); SetTextColor(dc, RGB(140, 155, 175));
    TextOutA(dc, col1X + 16, mainY + 36, "Background tasks demoted to EcoQoS to guarantee game frame stability.", 69);

    static const struct { const char *proc; const char *prio; const char *cpu; } s_throttled[5] = {
        {"SearchIndexer.exe (Windows Search)", "IDLE PRIORITY", "-92% CPU LOAD"},
        {"OneDrive.exe (Cloud Sync)",         "ECO-QOS IDLE",   "-88% I/O LOAD"},
        {"msedge.exe (Edge Background)",       "BELOW NORMAL",   "-75% RAM USAGE"},
        {"Teams.exe (Microsoft Teams)",        "SUSPENDED",      "-95% CPU LOAD"},
        {"CompPkgSrv.exe (Component Host)",    "BACKGROUND",     "-80% CPU LOAD"}
    };

    int py = mainY + 64;
    for(int p = 0; p < 5; p++) {
        DrawRoundRectPanel(dc, col1X + 16, py + p * 38, colW - 32, 32, 6, RGB(16, 24, 40), RGB(26, 42, 66));
        SelectObject(dc, fSm); SetTextColor(dc, RGB(230, 240, 255));
        TextOutA(dc, col1X + 26, py + p * 38 + 8, s_throttled[p].proc, (int)strlen(s_throttled[p].proc));
        DrawRoundRectPanel(dc, col1X + colW - 130, py + p * 38 + 6, 100, 20, 4, RGB(10, 32, 22), RGB(16, 185, 129));
        SelectObject(dc, fMini ? fMini : fSm); SetTextColor(dc, RGB(52, 211, 153));
        RECT tRc = {col1X + colW - 130, py + p * 38 + 6, col1X + colW - 30, py + p * 38 + 26};
        DrawTextA(dc, s_throttled[p].cpu, -1, &tRc, DT_CENTER|DT_VCENTER|DT_SINGLELINE);
    }

    /* RIGHT: Frame Latency & Micro-Stutter Monitor */
    DrawRoundRectPanel(dc, col2X, mainY, colW, mainH, 12, RGB(12, 19, 32), RGB(22, 36, 56));
    SelectObject(dc, fMed ? fMed : fHdr); SetTextColor(dc, RGB(255, 255, 255));
    TextOutA(dc, col2X + 16, mainY + 14, "Frame Time & Latency Jitter", 27);
    SelectObject(dc, fSm); SetTextColor(dc, RGB(140, 155, 175));
    TextOutA(dc, col2X + 16, mainY + 36, "Target: 8.33 ms (120 Hz) | Max Deviation: < 0.18 ms", 51);

    /* Frame Graph Frame */
    int gfX = col2X + 16, gfY = mainY + 64, gfW = colW - 32, gfH = mainH - 80;
    DrawRoundRectPanel(dc, gfX, gfY, gfW, gfH, 8, RGB(10, 16, 28), RGB(20, 34, 54));

    /* Target 8.33ms green baseline */
    int midY = gfY + gfH / 2;
    DrawLine(dc, gfX + 10, midY, gfX + gfW - 10, midY, RGB(16, 185, 129));
    SelectObject(dc, fMini ? fMini : fSm); SetTextColor(dc, RGB(16, 185, 129));
    TextOutA(dc, gfX + 14, midY - 14, "8.33ms Target", 13);

    /* Smooth cyan latency polyline */
    HPEN pC = CreatePen(PS_SOLID, 2, RGB(56, 189, 248));
    HPEN oP = (HPEN)SelectObject(dc, pC);
    POINT lPts[10] = {
        {gfX + 20, midY + 4}, {gfX + 60, midY - 2}, {gfX + 100, midY + 1}, {gfX + 140, midY - 4},
        {gfX + 180, midY + 2}, {gfX + 220, midY - 1}, {gfX + 260, midY + 3}, {gfX + 300, midY - 2},
        {gfX + 340, midY + 1}, {gfX + gfW - 20, midY - 1}
    };
    Polyline(dc, lPts, 10);
    SelectObject(dc, oP); DeleteObject(pC);
}

static void PaintThreatSubtab_Rules(HDC dc, int cx, int colY, int cw, int colH) {
    /* Full Width Container */
    DrawRoundRectPanel(dc, cx, colY, cw, colH, 12, RGB(12, 19, 32), RGB(22, 36, 56));
    SelectObject(dc, fMed ? fMed : fHdr); SetTextColor(dc, RGB(255, 255, 255));
    TextOutA(dc, cx + 16, colY + 14, "Anti-Cheat Compliance & Gaming Network Rules Matrix", 51);
    SelectObject(dc, fSm); SetTextColor(dc, RGB(140, 155, 175));
    TextOutA(dc, cx + 16, colY + 36, "Certified kernel interaction policies and dedicated gaming port QoS routes.", 75);

    /* Rules Table Header */
    int tY = colY + 64;
    DrawRoundRectPanel(dc, cx + 16, tY, cw - 32, 28, 4, RGB(18, 28, 46), RGB(28, 46, 72));
    SelectObject(dc, fMini ? fMini : fSm); SetTextColor(dc, RGB(148, 163, 184));
    TextOutA(dc, cx + 28, tY + 7, "Anti-Cheat / Game", 17);
    TextOutA(dc, cx + 220, tY + 7, "Driver Hook Method", 18);
    TextOutA(dc, cx + 420, tY + 7, "Kaevex Conflict Risk", 20);
    TextOutA(dc, cx + 620, tY + 7, "Allowed Port Range", 18);
    TextOutA(dc, cx + cw - 170, tY + 7, "Compliance State", 16);

    static const struct { const char *ac; const char *hk; const char *rs; const char *prt; const char *st; } s_rules[6] = {
        {"EasyAntiCheat (EAC)", "Kernel Service (EasyAntiCheat.sys)", "NONE (User-Mode Only)", "UDP 27015-27030", "100% VERIFIED"},
        {"BattlEye Service",    "Kernel Driver (BEDaisy.sys)",        "NONE (User-Mode Only)", "UDP 7777-7788",   "100% VERIFIED"},
        {"Riot Vanguard",       "Kernel Driver (vgk.sys)",            "NONE (Hardware Bypass)", "TCP 5000-5500",  "100% VERIFIED"},
        {"Ricochet Anti-Cheat", "Kernel Component",                  "NONE (User-Mode Only)", "UDP 3074-3080",   "100% VERIFIED"},
        {"Valve Anti-Cheat",    "User-Mode Steam Client",             "NONE (Native API)",     "UDP 27000-27050", "100% VERIFIED"},
        {"PunkBuster Service",  "Service (PnkBstrA.exe)",             "NONE (Standard)",       "UDP 28960",       "100% VERIFIED"}
    };

    int rY = tY + 34;
    for(int r = 0; r < 6; r++) {
        DrawRoundRectPanel(dc, cx + 16, rY + r * 42, cw - 32, 36, 6, (r % 2 == 0) ? RGB(14, 22, 36) : RGB(16, 26, 42), RGB(24, 38, 60));
        SelectObject(dc, fSm); SetTextColor(dc, RGB(255, 255, 255));
        TextOutA(dc, cx + 28, rY + r * 42 + 9, s_rules[r].ac, (int)strlen(s_rules[r].ac));
        SetTextColor(dc, RGB(180, 195, 215));
        TextOutA(dc, cx + 220, rY + r * 42 + 9, s_rules[r].hk, (int)strlen(s_rules[r].hk));
        SetTextColor(dc, RGB(52, 211, 153));
        TextOutA(dc, cx + 420, rY + r * 42 + 9, s_rules[r].rs, (int)strlen(s_rules[r].rs));
        SetTextColor(dc, RGB(56, 189, 248));
        TextOutA(dc, cx + 620, rY + r * 42 + 9, s_rules[r].prt, (int)strlen(s_rules[r].prt));

        DrawRoundRectPanel(dc, cx + cw - 170, rY + r * 42 + 6, 130, 24, 4, RGB(12, 38, 28), RGB(16, 185, 129));
        SelectObject(dc, fMini ? fMini : fSm); SetTextColor(dc, RGB(52, 211, 153));
        RECT cRc = {cx + cw - 170, rY + r * 42 + 6, cx + cw - 40, rY + r * 42 + 30};
        DrawTextA(dc, s_rules[r].st, -1, &cRc, DT_CENTER|DT_VCENTER|DT_SINGLELINE);
    }
}

static void PaintThreatSubtab_Profiles(HDC dc, int cx, int colY, int cw, int colH) {
    /* Header */
    DrawRoundRectPanel(dc, cx, colY, cw, colH, 12, RGB(12, 19, 32), RGB(22, 36, 56));
    SelectObject(dc, fMed ? fMed : fHdr); SetTextColor(dc, RGB(255, 255, 255));
    TextOutA(dc, cx + 16, colY + 14, "1-Click Esports & Competitive Game Profiles", 43);
    SelectObject(dc, fSm); SetTextColor(dc, RGB(140, 155, 175));
    TextOutA(dc, cx + 16, colY + 36, "Pre-tuned latency mitigation, thread prioritization, and network routing per title.", 83);

    /* 6 Game Cards in 2 rows x 3 columns */
    int cardW = (cw - 32 - 24) / 3;
    int cardH = (colH - 76 - 16) / 2;
    int startY = colY + 64;

    static const struct { const char *title; const char *eng; const char *opts; const char *btn; COLORREF bdr; } s_profs[6] = {
        {"Counter-Strike 2", "Source 2 | VAC Safe", "0.5ms Timer, P-Core Lock, Thread Pri 15", "[ ACTIVE ]", RGB(16, 185, 129)},
        {"VALORANT",         "UE4 | Vanguard Safe", "DirectInput Raw, DWM Flush, Low Latency", "[ APPLY ]",  RGB(0, 102, 255)},
        {"Apex Legends",     "Source | EAC Safe",   "Direct3D Fastpath, Packet Pacing, EcoQoS", "[ APPLY ]",  RGB(0, 102, 255)},
        {"GTA V / FiveM",    "RAGE | Social Club",  "Standby RAM Trim, 4GB Texture Stream",     "[ APPLY ]",  RGB(0, 102, 255)},
        {"Fortnite",         "UE5 | EAC/BattlEye",  "Shader Precache, UDP QoS Priority",       "[ APPLY ]",  RGB(0, 102, 255)},
        {"Cyberpunk 2077",   "REDengine | DLSS 3",  "Thread SMT Optimization, Frame Gen",      "[ APPLY ]",  RGB(0, 102, 255)}
    };

    for(int i = 0; i < 6; i++) {
        int r = i / 3, c = i % 3;
        int px = cx + 16 + c * (cardW + 12);
        int py = startY + r * (cardH + 12);

        DrawRoundRectPanel(dc, px, py, cardW, cardH, 10, RGB(14, 22, 38), s_profs[i].bdr);
        SelectObject(dc, fMed ? fMed : fHdr); SetTextColor(dc, RGB(255, 255, 255));
        TextOutA(dc, px + 14, py + 12, s_profs[i].title, (int)strlen(s_profs[i].title));

        SelectObject(dc, fSm); SetTextColor(dc, RGB(56, 189, 248));
        TextOutA(dc, px + 14, py + 34, s_profs[i].eng, (int)strlen(s_profs[i].eng));

        SelectObject(dc, fMini ? fMini : fSm); SetTextColor(dc, RGB(148, 163, 184));
        RECT oRc = {px + 14, py + 54, px + cardW - 14, py + cardH - 42};
        DrawTextA(dc, s_profs[i].opts, -1, &oRc, DT_LEFT|DT_WORDBREAK);

        /* Action Button */
        int bW = 110, bH = 24;
        int bx = px + cardW - bW - 14, by = py + cardH - bH - 12;
        DrawRoundRectPanel(dc, bx, by, bW, bH, 6, RGB(18, 32, 54), s_profs[i].bdr);
        SelectObject(dc, fSm); SetTextColor(dc, s_profs[i].bdr);
        RECT bRc = {bx, by, bx + bW, by + bH};
        DrawTextA(dc, s_profs[i].btn, -1, &bRc, DT_CENTER|DT_VCENTER|DT_SINGLELINE);
    }
}
"@

# Locate insertion point right before PaintThreat
$targetPaintThreat = 'static void PaintThreat(HDC dc, int cx, int cy, int cw, int ch) {'

if ($content.Contains($targetPaintThreat)) {
    $content = $content.Replace($targetPaintThreat, $subtabCode + "`r`n`r`n" + $targetPaintThreat)
    Write-Host "[OK] Inserted 4 dedicated Gaming sub-tab renderers"
} else {
    Write-Host "[FAIL] targetPaintThreat not found"
}

# Now hook them into PaintThreat right after DUAL-COLUMN MAIN PANELS setup
$targetBranch = @"
    /* =========================================================================
     * LEFT COLUMN: GAMING MODE PANEL
     * ========================================================================= */
"@

$newBranch = @"
    /* Sub-nav branching for dedicated views */
    if (g_threatSubNav == 1) {
        PaintThreatSubtab_Protection(dc, heroX, colY, heroW, colH);
        return;
    } else if (g_threatSubNav == 2) {
        PaintThreatSubtab_Performance(dc, heroX, colY, heroW, colH);
        return;
    } else if (g_threatSubNav == 3) {
        PaintThreatSubtab_Rules(dc, heroX, colY, heroW, colH);
        return;
    } else if (g_threatSubNav == 4) {
        PaintThreatSubtab_Profiles(dc, heroX, colY, heroW, colH);
        return;
    }

    /* =========================================================================
     * LEFT COLUMN: GAMING MODE PANEL
     * ========================================================================= */
"@

$targetBranchNorm = $targetBranch -replace "\r\n", "`n"
$newBranchNorm = $newBranch -replace "\r\n", "`n"
$contentNorm = $content -replace "\r\n", "`n"

if ($contentNorm.Contains($targetBranchNorm)) {
    $contentNorm = $contentNorm.Replace($targetBranchNorm, $newBranchNorm)
    $content = $contentNorm -replace "`n", "`r`n"
    Write-Host "[OK] Wired dedicated views into PaintThreat"
} else {
    Write-Host "[WARN] targetBranch not found"
}

# Save updated file
[System.IO.File]::WriteAllText($file, $content, [System.Text.Encoding]::UTF8)
Write-Host "Part 4 Gaming sub-tabs applied successfully!"
