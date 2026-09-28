/* --- Settings Sidebar Category Metadata ----------------------------------- */
typedef struct {
    int id;
    const char *group;
    const wchar_t *iconW;
    const char *icon;
    const char *title;
    const char *subTitle;
} SetCatMeta;

static const SetCatMeta g_catMeta[SET_CAT_COUNT] = {
    { SET_GENERAL,    "GENERAL",           L"\uE713", "[SYS]", "General Preferences",    "Customize your Kaevex experience, appearance and behavior." },
    { SET_PERF,       "GENERAL",           L"\uE7FC", "[PRF]", "Performance & Gaming",   "Resource quotas, dynamic CPU throttling, battery saver, and gaming boost." },
    { SET_NOTIF,      "GENERAL",           L"\uEA8F", "[NTF]", "Alerts & Notifications", "Multi-channel priority dispatch, toast popups, acoustic chimes, and routing." },
    { SET_UPDATES,    "GENERAL",           L"\uE977", "[UPD]", "Software & Intelligence", "Signature catalogs, CVE databases, WAF patterns, and engine version management." },

    { SET_PROTECTION, "SECURITY SHIELDS",  L"\uE72E", "[PRO]", "Protection Center",      "Behavioral heuristics, cloud intelligence, and kernel-level self-defense." },
    { SET_AV,         "SECURITY SHIELDS",  L"\uE72E", "[AV ]", "Antivirus Core",         "Cryptographic SHA-256 signatures, 5-layer heuristic scanner & PE analysis." },
    { SET_NET,        "SECURITY SHIELDS",  L"\uE839", "[NET]", "NetGuard Traffic",       "L4/L7 socket classification, C2 beacon pattern analysis, and DNS sinkhole." },
    { SET_FW,         "SECURITY SHIELDS",  L"\uE83D", "[FW ]", "Adaptive Firewall",      "Dynamic inbound/outbound packet filtering, stealth mode, and port policies." },
    { SET_WAF,        "SECURITY SHIELDS",  L"\uE774", "[WAF]", "WebGuard WAF",           "18 attack vector inspection: SQLi, XSS, RCE, LFI, RFI, SSRF & bot throttling." },
    { SET_RANSOM,     "SECURITY SHIELDS",  L"\uE72D", "[RS ]", "RansomShield Traps",     "Zero-driver honeypot sentinels, mass-rename detection, and VSS rollback." },
    { SET_SBX,        "SECURITY SHIELDS",  L"\uE7B8", "[SBX]", "SmartSandbox",           "AppContainer containment, Job Object hard limits, and behavioral detours." },
    { SET_APPCTRL,    "SECURITY SHIELDS",  L"\uECAA", "[APP]", "Application Control",    "Execution allowlisting, code-signature verification, and zero-trust policies." },

    { SET_ENGINES,    "OPERATIONS & CLOUD",L"\uE74C", "[ENG]", "Engine Management",      "Operational lifecycle, health status, and live computing load for 8 engines." },
    { SET_AISOC,      "OPERATIONS & CLOUD",L"\uE99A", "[AI ]", "AI SOC Analyst",         "Autonomous threat correlation, natural language summaries, and copilot." },
    { SET_DEVICE,     "OPERATIONS & CLOUD",L"\uE88E", "[DEV]", "Device Control",         "USB storage authorization, hardware port locks, and peripheral blocking." },
    { SET_FORENSICS,  "OPERATIONS & CLOUD",L"\uE9D9", "[FOR]", "Forensics & Logs",        "HMAC-SHA256 telemetry, compliance retention cycles, and multi-format exports." },
    { SET_CLOUD,      "OPERATIONS & CLOUD",L"\uE753", "[CLD]", "Cloud & Supabase",       "Global threat intelligence federation, cloud policy deployment, and sync." },
    { SET_TEAM,       "OPERATIONS & CLOUD",L"\uE902", "[TEM]", "Team & Permissions",     "Role-based access control (RBAC): Owner, Admin, Analyst, Operator, Viewer." },

    { SET_PRIVACY,    "ENTERPRISE & OPS",  L"\uE72E", "[PRV]", "Security & Privacy",     "Multi-factor authentication (2FA), biometric passkeys, and data governance." },
    { SET_ENTERPRISE, "ENTERPRISE & OPS",  L"\uE8D7", "[ENT]", "Enterprise Policies",     "Multi-tenant governance, organization compliance profiles, and fleet control." },
    { SET_ADVANCED,   "ENTERPRISE & OPS",  L"\uE756", "[ADV]", "Developer & API",        "Local REST daemon (port 9009), SIEM webhooks, and developer diagnostics." },
    { SET_RECOVERY,   "ENTERPRISE & OPS",  L"\uE7BA", "[REC]", "Recovery & Lockdown",    "Instant boundary severing, quarantine management, and baseline reset." },
    { SET_ABOUT,      "ENTERPRISE & OPS",  L"\uE946", "[INF]", "About Kaevex Platform",  "Platform architecture, engine integrity, and verified digital signatures." }
};

/* Interactive State for General Preferences Glass Dashboard */
static int g_setGeneralSubTab   = 0; /* 0: Appearance, 1: Behavior, 2: Startup, 3: Sounds, 4: Layouts */
static int g_setLangIdx         = 0; /* 0: English (US), 1: Arabic, 2: French, 3: German */
static int g_setTimezoneIdx     = 0; /* 0: (GMT+2) Cairo, 1: (GMT+0) London, 2: (GMT+3) Riyadh, 3: (GMT-5) New York */
static int g_setNotifStyleIdx   = 0; /* 0: Modern (Toast), 1: Banner, 2: Minimal Tray */
static int g_setNotifSoundIdx   = 0; /* 0: Default, 1: Cyber Chime, 2: Radar Ping, 3: Mute */
static int g_setStartupDelayIdx = 1; /* 0: Fast (0 sec), 1: Normal (5 sec), 2: Delayed (15 sec) */
static int g_setLogLevelIdx     = 0; /* 0: Normal, 1: Verbose, 2: Debug, 3: Silent */
static BOOL g_cfg_blurEffects    = FALSE;
static BOOL g_cfg_roundedCorners = TRUE;
static BOOL g_cfg_showInTaskbar  = TRUE;

/* Interactive Click Registry for Settings */
typedef struct {
    RECT rc;
    int  actionType; /* 1=ToggleBool, 2=SetInt, 3=Save, 4=Reset, 5=SubTab, 6=URL, 7=Custom, 8=CycleInt, 10=ResetLayout */
    void *targetPtr;
    int  val;
} SetClick;
#define MAX_SET_CLICKS 256
static SetClick g_setClicks[MAX_SET_CLICKS];
static int g_setClickCnt = 0;

static void RegSetClick(RECT rc, int actionType, void *targetPtr, int val) {
    if (g_setClickCnt < MAX_SET_CLICKS) {
        g_setClicks[g_setClickCnt].rc = rc;
        g_setClicks[g_setClickCnt].actionType = actionType;
        g_setClicks[g_setClickCnt].targetPtr = targetPtr;
        g_setClicks[g_setClickCnt].val = val;
        g_setClickCnt++;
    }
}


typedef struct {
    const char *title;
    const char *desc;
    BOOL *pState;
    COLORREF accent;
} SetToggleDef;

/* Draw modern toggle card matching reference image media_1790393703824.png */
static void DrawSetToggleCard(HDC dc, int x, int y, int w, int h, const SetToggleDef *def) {
    /* Background card */
    HBRUSH bgBr = CreateSolidBrush(C_CARD);
    HPEN   pn   = CreatePen(PS_SOLID, 1, C_BORDER);
    HBRUSH ob   = (HBRUSH)SelectObject(dc, bgBr);
    HPEN   op   = (HPEN)SelectObject(dc, pn);
    RoundRect(dc, x, y, x + w, y + h, 8, 8);
    SelectObject(dc, ob); SelectObject(dc, op);
    DeleteObject(bgBr); DeleteObject(pn);

    /* Left accent line */
    HBRUSH accBr = CreateSolidBrush(def->accent);
    RECT accR = { x + 2, y + 4, x + 5, y + h - 4 };
    FillRect(dc, &accR, accBr);
    DeleteObject(accBr);

    /* Text */
    Txt(dc, def->title, x + 14, y + 6, w - 80, 16, C_TEXT, fSm, DT_LEFT | DT_SINGLELINE | DT_NOPREFIX);
    Txt(dc, def->desc,  x + 14, y + 24, w - 80, 14, C_TEXT2, fSm, DT_LEFT | DT_SINGLELINE | DT_NOPREFIX);

    /* Toggle pill button on the right */
    int pillW = 54, pillH = 22;
    int pillX = x + w - pillW - 12;
    int pillY = y + (h - pillH) / 2;
    BOOL on = def->pState ? *def->pState : FALSE;

    HBRUSH pillBg = CreateSolidBrush(on ? RGB(6, 44, 34) : RGB(20, 30, 46));
    HPEN   pillPn = CreatePen(PS_SOLID, 1, on ? RGB(16, 185, 129) : RGB(50, 70, 95));
    ob = (HBRUSH)SelectObject(dc, pillBg);
    op = (HPEN)SelectObject(dc, pillPn);
    RoundRect(dc, pillX, pillY, pillX + pillW, pillY + pillH, 6, 6);
    SelectObject(dc, ob); SelectObject(dc, op);
    DeleteObject(pillBg); DeleteObject(pillPn);

    Txt(dc, on ? "ON" : "OFF", pillX, pillY, pillW, pillH,
        on ? RGB(52, 211, 153) : RGB(148, 163, 184), fSm, DT_CENTER | DT_VCENTER | DT_SINGLELINE);

    /* Register click on entire toggle card */
    RECT clkR = { x, y, x + w, y + h };
    RegSetClick(clkR, 1, def->pState, 0);
}

/* Draw a segmented mode selector pill group */
static void DrawSetModeSelector(HDC dc, int x, int y, int w, const char *title, const char *subtitle,
                                const char **opts, int optCount, int *pCurVal) {
    int curVal = pCurVal ? *pCurVal : 0;
    int cardH = 58;

    /* Card background */
    HBRUSH bgBr = CreateSolidBrush(C_PANEL2);
    HPEN   pn   = CreatePen(PS_SOLID, 1, C_BORDER);
    HBRUSH ob   = (HBRUSH)SelectObject(dc, bgBr);
    HPEN   op   = (HPEN)SelectObject(dc, pn);
    RoundRect(dc, x, y, x + w, y + cardH, 8, 8);
    SelectObject(dc, ob); SelectObject(dc, op);
    DeleteObject(bgBr); DeleteObject(pn);

    int pillAreaW = (w > 560) ? (w * 56 / 100) : (w - 240);
    if (pillAreaW < 180) pillAreaW = 180;
    int pillStartX = x + w - pillAreaW - 12;
    int textW = pillStartX - x - 20;

    Txt(dc, title,    x + 14, y + 8,  textW, 16, C_TEXT, fSm, DT_LEFT | DT_SINGLELINE);
    Txt(dc, subtitle, x + 14, y + 26, textW, 14, C_DIM,  fSm, DT_LEFT | DT_SINGLELINE);

    int pillW = (pillAreaW - (optCount - 1) * 6) / (optCount > 0 ? optCount : 1);
    if (pillW > 140) pillW = 140;
    int pillH = 28;
    int pillY = y + (cardH - pillH) / 2;

    for (int i = 0; i < optCount; i++) {
        int px = pillStartX + i * (pillW + 6);
        BOOL sel = (curVal == i);

        HBRUSH pBg = CreateSolidBrush(sel ? C_NAV_ACT : RGB(10, 18, 32));
        HPEN   pPn = CreatePen(PS_SOLID, 1, sel ? RGB(6, 182, 212) : C_BORDER);
        HBRUSH ob2 = (HBRUSH)SelectObject(dc, pBg);
        HPEN   op2 = (HPEN)SelectObject(dc, pPn);
        RoundRect(dc, px, pillY, px + pillW, pillY + pillH, 6, 6);
        SelectObject(dc, ob2); SelectObject(dc, op2);
        DeleteObject(pBg); DeleteObject(pPn);

        Txt(dc, opts[i], px, pillY, pillW, pillH,
            sel ? RGB(255, 255, 255) : C_TEXT2, fSm, DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);

        RECT clkR = { px, pillY, px + pillW, pillY + pillH };
        RegSetClick(clkR, 2, pCurVal, i);
    }
}



/* Modern iOS/Cyber Style Toggle Switch */
static void DrawCyberSwitch(HDC dc, int x, int y, BOOL on) {
    int swW = 34, swH = 18;
    COLORREF bg = on ? RGB(37, 99, 235) : RGB(20, 32, 50);
    COLORREF bdr = on ? RGB(59, 130, 246) : RGB(38, 56, 82);
    DrawRoundRectPanel(dc, x, y, swW, swH, 9, bg, bdr);

    /* Circular knob */
    int knobSz = 14;
    int knobX = on ? (x + swW - knobSz - 2) : (x + 2);
    int knobY = y + 2;
    HBRUSH kb = CreateSolidBrush(on ? RGB(255, 255, 255) : RGB(140, 160, 185));
    HPEN   kp = (HPEN)GetStockObject(NULL_PEN);
    HBRUSH ob = (HBRUSH)SelectObject(dc, kb);
    HPEN   op = (HPEN)SelectObject(dc, kp);
    Ellipse(dc, knobX, knobY, knobX + knobSz, knobY + knobSz);
    SelectObject(dc, ob); SelectObject(dc, op);
    DeleteObject(kb);
}

/* Switch with Label Row */
static void DrawSwitchRow(HDC dc, int x, int y, int w, const char *label, BOOL *pVal) {
    BOOL on = pVal ? *pVal : FALSE;
    Txt(dc, label, x, y, w - 42, 18, RGB(220, 235, 255), fMini ? fMini : fSm, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
    DrawCyberSwitch(dc, x + w - 36, y, on);

    RECT rk = { x, y, x + w, y + 20 };
    RegSetClick(rk, 1, pVal, 0);
}

/* Dropdown Pill Button */
static void DrawDropdownPill(HDC dc, int x, int y, int w, int h, const char *text, int *pVal, int maxVal) {
    DrawRoundRectPanel(dc, x, y, w, h, 6, RGB(12, 18, 32), RGB(28, 44, 72));

    if (strncmp(text, "[US] ", 5) == 0) {
        /* Draw mini US flag vector */
        int fx = x + 10, fy = y + (h - 11) / 2, fw = 16, fh = 11;
        HBRUSH rBr = CreateSolidBrush(RGB(220, 38, 38));
        RECT frc = { fx, fy, fx + fw, fy + fh };
        FillRect(dc, &frc, rBr);
        DeleteObject(rBr);
        HBRUSH wBr = CreateSolidBrush(RGB(255, 255, 255));
        RECT s1 = { fx, fy + 2, fx + fw, fy + 4 };
        RECT s2 = { fx, fy + 6, fx + fw, fy + 8 };
        FillRect(dc, &s1, wBr);
        FillRect(dc, &s2, wBr);
        DeleteObject(wBr);
        HBRUSH bBr = CreateSolidBrush(RGB(30, 58, 138));
        RECT cant = { fx, fy, fx + 7, fy + 6 };
        FillRect(dc, &cant, bBr);
        DeleteObject(bBr);
        Txt(dc, text + 5, fx + fw + 8, y, w - fw - 36, h, RGB(230, 240, 255), fMini ? fMini : fSm, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
    } else {
        Txt(dc, text, x + 10, y, w - 28, h, RGB(230, 240, 255), fMini ? fMini : fSm, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
    }
    TxtW(dc, L"\u25BE", x + w - 18, y, 14, h, RGB(130, 155, 185), fMini ? fMini : fSm, DT_CENTER | DT_VCENTER | DT_SINGLELINE);

    RECT rk = { x, y, x + w, y + h };
    RegSetClick(rk, 8, pVal, maxVal);
}

/* Theme Selection Tile */
static void DrawThemeTile(HDC dc, int x, int y, int w, int h, const wchar_t *iconW, const char *name, BOOL sel, int themeVal) {
    COLORREF bg = sel ? RGB(16, 44, 98) : RGB(12, 18, 32);
    COLORREF bdr = sel ? RGB(37, 99, 235) : RGB(26, 40, 68);
    DrawRoundRectPanel(dc, x, y, w, h, 6, bg, bdr);
    if (sel) DrawLine(dc, x + 4, y + 1, x + w - 4, y + 1, RGB(100, 180, 255));

    SetTextColor(dc, sel ? RGB(255, 255, 255) : RGB(150, 175, 205));
    SelectObject(dc, fIcon ? fIcon : fSm);
    RECT icR = { x, y + 5, x + w, y + 23 };
    DrawTextW(dc, iconW, -1, &icR, DT_CENTER | DT_SINGLELINE | DT_NOPREFIX);

    Txt(dc, name, x + 2, y + 25, w - 4, 16, sel ? RGB(255, 255, 255) : RGB(140, 160, 185), fMini ? fMini : fSm, DT_CENTER | DT_SINGLELINE);

    RECT rk = { x, y, x + w, y + h };
    RegSetClick(rk, 2, &g_cfg.theme, themeVal);
}

/* Accent Color Selection Dot */
static void DrawAccentDot(HDC dc, int cx, int cy, COLORREF col, BOOL sel, int accentIdx) {
    int r = 8;
    if (sel) {
        /* Outer concentric ring */
        HPEN rp = CreatePen(PS_SOLID, 2, RGB(56, 189, 248));
        HPEN op = (HPEN)SelectObject(dc, rp);
        HBRUSH ob = (HBRUSH)SelectObject(dc, GetStockObject(NULL_BRUSH));
        Ellipse(dc, cx - r - 4, cy - r - 4, cx + r + 4, cy + r + 4);
        SelectObject(dc, ob); SelectObject(dc, op);
        DeleteObject(rp);
    }
    HBRUSH db = CreateSolidBrush(col);
    HPEN   dp = (HPEN)GetStockObject(NULL_PEN);
    HBRUSH ob2 = (HBRUSH)SelectObject(dc, db);
    HPEN   op2 = (HPEN)SelectObject(dc, dp);
    Ellipse(dc, cx - r, cy - r, cx + r, cy + r);
    SelectObject(dc, ob2); SelectObject(dc, op2);
    DeleteObject(db);

    RECT rk = { cx - r - 5, cy - r - 5, cx + r + 5, cy + r + 5 };
    RegSetClick(rk, 2, &g_cfg.accent, accentIdx);
}

/* Layout Mode Dual Pill: [ Comfortable ] vs [ Compact ] */
static void DrawLayoutDualPill(HDC dc, int x, int y, int w, int h) {
    int pillW = (w - 6) / 2;
    BOOL comp = g_cfg.compactLayout;

    /* Comfortable */
    COLORREF bg1 = !comp ? RGB(16, 44, 98) : RGB(12, 18, 32);
    COLORREF bdr1 = !comp ? RGB(37, 99, 235) : RGB(26, 40, 68);
    DrawRoundRectPanel(dc, x, y, pillW, h, 5, bg1, bdr1);
    if (!comp) DrawLine(dc, x + 4, y + 1, x + pillW - 4, y + 1, RGB(100, 180, 255));
    TxtW(dc, L"\uE7C3", x + 4, y, 16, h, !comp ? RGB(56, 189, 248) : RGB(100, 120, 145), fIcon ? fIcon : fSm, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
    Txt(dc, "Comfortable", x + 22, y, pillW - 24, h, !comp ? RGB(255, 255, 255) : RGB(140, 160, 185), fMini ? fMini : fSm, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
    RECT rk1 = { x, y, x + pillW, y + h };
    RegSetClick(rk1, 2, &g_cfg.compactLayout, 0);

    /* Compact */
    int x2 = x + pillW + 6;
    COLORREF bg2 = comp ? RGB(16, 44, 98) : RGB(12, 18, 32);
    COLORREF bdr2 = comp ? RGB(37, 99, 235) : RGB(26, 40, 68);
    DrawRoundRectPanel(dc, x2, y, pillW, h, 5, bg2, bdr2);
    if (comp) DrawLine(dc, x2 + 4, y + 1, x2 + pillW - 4, y + 1, RGB(100, 180, 255));
    TxtW(dc, L"\uE7C4", x2 + 4, y, 16, h, comp ? RGB(56, 189, 248) : RGB(100, 120, 145), fIcon ? fIcon : fSm, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
    Txt(dc, "Compact", x2 + 22, y, pillW - 24, h, comp ? RGB(255, 255, 255) : RGB(140, 160, 185), fMini ? fMini : fSm, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
    RECT rk2 = { x2, y, x2 + pillW, y + h };
    RegSetClick(rk2, 2, &g_cfg.compactLayout, 1);
}

/* ========================================================================= */
/* GENERAL PREFERENCES PIXEL-PERFECT GLASS DASHBOARD                         */
/* Matching media_1790543860024.jpg                                          */
/* ========================================================================= */
static void PaintGeneralPreferences(HDC dc, int mainX, int mainY, int mainW, int mainH) {
    /* --- Top Header Bar --- */
    int hIcSz = 40;
    DrawRoundRectPanel(dc, mainX, mainY + 2, hIcSz, hIcSz, 8, RGB(16, 42, 95), RGB(37, 99, 235));
    DrawLine(dc, mainX + 4, mainY + 3, mainX + hIcSz - 4, mainY + 3, RGB(100, 180, 255));
    SetTextColor(dc, RGB(56, 189, 248));
    SelectObject(dc, fIcon ? fIcon : fSm);
    RECT hIcR = { mainX, mainY + 2, mainX + hIcSz, mainY + 2 + hIcSz };
    DrawTextW(dc, L"\uE713", -1, &hIcR, DT_CENTER | DT_VCENTER | DT_SINGLELINE);

    Txt(dc, "[SYS]  General Preferences", mainX + hIcSz + 12, mainY + 2, mainW - 320, 20, RGB(245, 250, 255), fMed, DT_LEFT | DT_SINGLELINE | DT_VCENTER);
    Txt(dc, "Customize your Kaevex experience, appearance and behavior.", mainX + hIcSz + 12, mainY + 24, mainW - 320, 16, RGB(140, 165, 195), fMini ? fMini : fSm, DT_LEFT | DT_SINGLELINE | DT_VCENTER);

    /* Action Button 1: [ Reset to Default ] */
    int b1W = 144, b1H = 30;
    int b1X = mainX + mainW - b1W - 130 - 10;
    DrawRoundRectPanel(dc, b1X, mainY + 6, b1W, b1H, 6, RGB(12, 18, 32), RGB(30, 48, 80));
    TxtW(dc, L"\uE72C", b1X + 8, mainY + 6, 20, b1H, RGB(200, 220, 245), fIcon ? fIcon : fSm, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
    Txt(dc, "Reset to Default", b1X + 28, mainY + 6, b1W - 34, b1H, RGB(220, 235, 255), fSm, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
    RECT rkB1 = { b1X, mainY + 6, b1X + b1W, mainY + 6 + b1H };
    RegSetClick(rkB1, 4, NULL, 0);

    /* Action Button 2: [ Save Changes ] */
    int b2W = 130, b2H = 30;
    int b2X = mainX + mainW - b2W;
    DrawRoundRectPanel(dc, b2X, mainY + 6, b2W, b2H, 6, RGB(37, 99, 235), RGB(59, 130, 246));
    DrawLine(dc, b2X + 4, mainY + 7, b2X + b2W - 4, mainY + 7, RGB(120, 180, 255));
    TxtW(dc, L"\uE74E", b2X + 8, mainY + 6, 20, b2H, RGB(255, 255, 255), fIcon ? fIcon : fSm, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
    Txt(dc, "Save Changes", b2X + 28, mainY + 6, b2W - 34, b2H, RGB(255, 255, 255), fSm, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
    RECT rkB2 = { b2X, mainY + 6, b2X + b2W, mainY + 6 + b2H };
    RegSetClick(rkB2, 3, NULL, 0);

    /* --- Sub-Tab Navigation Bar (Horizontal Pills) --- */
    int stY = mainY + 48;
    int stH = 30;
    int stW = (mainW - 4 * 8) / 5;
    if (stW > 124) stW = 124;

    static const struct { const wchar_t *iconW; const char *title; } g_subTabs[5] = {
        { L"\uE7B3", "Appearance" },
        { L"\uE713", "Behavior"   },
        { L"\uE7E8", "Startup"    },
        { L"\uE767", "Sounds"     },
        { L"\uE7C3", "Layouts"    }
    };

    for (int t = 0; t < 5; t++) {
        int pX = mainX + t * (stW + 8);
        BOOL isPillSel = (g_setGeneralSubTab == t);
        COLORREF pBg = isPillSel ? RGB(37, 99, 235) : RGB(10, 16, 28);
        COLORREF pBc = isPillSel ? RGB(59, 130, 246) : RGB(22, 34, 56);
        DrawRoundRectPanel(dc, pX, stY, stW, stH, 6, pBg, pBc);
        if (isPillSel) DrawLine(dc, pX + 4, stY + 1, pX + stW - 4, stY + 1, RGB(120, 180, 255));

        SetTextColor(dc, isPillSel ? RGB(255, 255, 255) : RGB(150, 175, 205));
        SelectObject(dc, fIcon ? fIcon : fSm);
        RECT icR = { pX + 6, stY, pX + 24, stY + stH };
        DrawTextW(dc, g_subTabs[t].iconW, -1, &icR, DT_CENTER | DT_VCENTER | DT_SINGLELINE);

        Txt(dc, g_subTabs[t].title, pX + 24, stY, stW - 28, stH,
            isPillSel ? RGB(255, 255, 255) : RGB(160, 180, 210), fMini ? fMini : fSm, DT_LEFT | DT_VCENTER | DT_SINGLELINE);

        RECT rkP = { pX, stY, pX + stW, stY + stH };
        RegSetClick(rkP, 2, &g_setGeneralSubTab, t);
    }

    int gridY = stY + stH + 8;
    int gap = 10;
    int colW = (mainW - 2 * gap) / 3;
    int qaH = 68;
    int availH = mainH - (gridY - mainY) - qaH - gap;
    int cardH = (availH - gap) / 2;
    if (cardH < 180) cardH = 180;

    /* ========================================================================= */
    /* SUB-TAB 0: APPEARANCE (Exact 6 Cards Grid + Quick Actions from Reference) */
    /* ========================================================================= */
    if (g_setGeneralSubTab == 0) {
        int row1Y = gridY;
        int row2Y = row1Y + cardH + gap;

        /* --- CARD 1: Language & Region --- */
        int c1X = mainX, c1Y = row1Y;
        DrawRoundRectPanel(dc, c1X, c1Y, colW, cardH, 8, RGB(10, 15, 26), RGB(20, 32, 54));
        DrawLine(dc, c1X + 10, c1Y + 1, c1X + colW - 10, c1Y + 1, RGB(30, 48, 78));

        TxtW(dc, L"\uE774", c1X + 14, c1Y + 10, 18, 18, RGB(56, 189, 248), fIcon ? fIcon : fSm, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
        Txt(dc, "Language & Region", c1X + 36, c1Y + 10, colW - 44, 18, RGB(240, 245, 255), fMed, DT_LEFT | DT_VCENTER | DT_SINGLELINE);

        Txt(dc, "Language", c1X + 14, c1Y + 36, colW - 28, 14, RGB(130, 155, 185), fMini ? fMini : fSm, DT_LEFT | DT_SINGLELINE);
        const char *langStr = (g_setLangIdx == 1) ? "[AR] Arabic" :
                              (g_setLangIdx == 2) ? "[FR] Francais" :
                              (g_setLangIdx == 3) ? "[DE] Deutsch" : "[US] English (US)";
        DrawDropdownPill(dc, c1X + 14, c1Y + 54, colW - 28, 28, langStr, &g_setLangIdx, 4);

        Txt(dc, "Time Zone", c1X + 14, c1Y + 94, colW - 28, 14, RGB(130, 155, 185), fMini ? fMini : fSm, DT_LEFT | DT_SINGLELINE);
        const char *tzStr = (g_setTimezoneIdx == 1) ? "(GMT+0) London" :
                            (g_setTimezoneIdx == 2) ? "(GMT+3) Riyadh" :
                            (g_setTimezoneIdx == 3) ? "(GMT-5) New York" : "(GMT+2) Cairo";
        DrawDropdownPill(dc, c1X + 14, c1Y + 112, colW - 28, 28, tzStr, &g_setTimezoneIdx, 4);

        /* --- CARD 2: Theme & Appearance --- */
        int c2X = mainX + colW + gap, c2Y = row1Y;
        DrawRoundRectPanel(dc, c2X, c2Y, colW, cardH, 8, RGB(10, 15, 26), RGB(20, 32, 54));
        DrawLine(dc, c2X + 10, c2Y + 1, c2X + colW - 10, c2Y + 1, RGB(30, 48, 78));

        TxtW(dc, L"\uE790", c2X + 14, c2Y + 10, 18, 18, RGB(56, 189, 248), fIcon ? fIcon : fSm, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
        Txt(dc, "Theme & Appearance", c2X + 36, c2Y + 10, colW - 44, 18, RGB(240, 245, 255), fMed, DT_LEFT | DT_VCENTER | DT_SINGLELINE);

        Txt(dc, "Theme", c2X + 14, c2Y + 34, colW - 28, 14, RGB(130, 155, 185), fMini ? fMini : fSm, DT_LEFT | DT_SINGLELINE);
        int tW = (colW - 28 - 3 * 6) / 4;
        DrawThemeTile(dc, c2X + 14 + 0*(tW+6), c2Y + 52, tW, 44, L"\uE708", "Dark", (g_cfg.theme == 0), 0);
        DrawThemeTile(dc, c2X + 14 + 1*(tW+6), c2Y + 52, tW, 44, L"\uE793", "Dark OLED", (g_cfg.theme == 1), 1);
        DrawThemeTile(dc, c2X + 14 + 2*(tW+6), c2Y + 52, tW, 44, L"\uE706", "Light", (g_cfg.theme == 4), 4);
        DrawThemeTile(dc, c2X + 14 + 3*(tW+6), c2Y + 52, tW, 44, L"\uE7F8", "System", (g_cfg.theme == 2), 2);

        Txt(dc, "Accent Color", c2X + 14, c2Y + 106, colW - 28, 14, RGB(130, 155, 185), fMini ? fMini : fSm, DT_LEFT | DT_SINGLELINE);
        static const COLORREF accCols[8] = {
            RGB(37,99,235), RGB(139,92,246), RGB(236,72,153), RGB(239,68,68),
            RGB(249,115,22), RGB(234,179,8), RGB(16,185,129), RGB(6,182,212)
        };
        int dStartX = c2X + 14 + 10;
        int dSpacing = (colW - 48) / 7;
        for (int ac = 0; ac < 8; ac++) {
            DrawAccentDot(dc, dStartX + ac * dSpacing, c2Y + 128, accCols[ac], (g_cfg.accent == ac), ac);
        }

        /* --- CARD 3: UI & Effects --- */
        int c3X = mainX + 2 * (colW + gap), c3Y = row1Y;
        DrawRoundRectPanel(dc, c3X, c3Y, colW, cardH, 8, RGB(10, 15, 26), RGB(20, 32, 54));
        DrawLine(dc, c3X + 10, c3Y + 1, c3X + colW - 10, c3Y + 1, RGB(30, 48, 78));

        TxtW(dc, L"\uE7E7", c3X + 14, c3Y + 10, 18, 18, RGB(56, 189, 248), fIcon ? fIcon : fSm, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
        Txt(dc, "UI & Effects", c3X + 36, c3Y + 10, colW - 44, 18, RGB(240, 245, 255), fMed, DT_LEFT | DT_VCENTER | DT_SINGLELINE);

        Txt(dc, "UI Scale", c3X + 14, c3Y + 30, colW - 28, 13, RGB(130, 155, 185), fMini ? fMini : fSm, DT_LEFT | DT_SINGLELINE);
        const char *scaleStr = (g_cfg.scale == 1) ? "125%" : (g_cfg.scale == 2) ? "150%" : "100%";
        DrawDropdownPill(dc, c3X + 14, c3Y + 44, colW - 28, 22, scaleStr, &g_cfg.scale, 3);

        Txt(dc, "Layout Mode", c3X + 14, c3Y + 70, colW - 28, 13, RGB(130, 155, 185), fMini ? fMini : fSm, DT_LEFT | DT_SINGLELINE);
        DrawLayoutDualPill(dc, c3X + 14, c3Y + 84, colW - 28, 24);

        int swY = c3Y + 114;
        int swStep = 18;
        DrawSwitchRow(dc, c3X + 14, swY + 0*swStep, colW - 28, "Animations", &g_cfg.animations);
        DrawSwitchRow(dc, c3X + 14, swY + 1*swStep, colW - 28, "Glow Effects", &g_cfg.glowEffects);
        DrawSwitchRow(dc, c3X + 14, swY + 2*swStep, colW - 28, "Blur Effects", &g_cfg_blurEffects);
        DrawSwitchRow(dc, c3X + 14, swY + 3*swStep, colW - 28, "Rounded Corners", &g_cfg_roundedCorners);

        /* --- CARD 4: Notifications & Sound --- */
        int c4X = mainX, c4Y = row2Y;
        DrawRoundRectPanel(dc, c4X, c4Y, colW, cardH, 8, RGB(10, 15, 26), RGB(20, 32, 54));
        DrawLine(dc, c4X + 10, c4Y + 1, c4X + colW - 10, c4Y + 1, RGB(30, 48, 78));

        TxtW(dc, L"\uEA8F", c4X + 14, c4Y + 10, 18, 18, RGB(56, 189, 248), fIcon ? fIcon : fSm, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
        Txt(dc, "Notifications & Sound", c4X + 36, c4Y + 10, colW - 44, 18, RGB(240, 245, 255), fMed, DT_LEFT | DT_VCENTER | DT_SINGLELINE);

        Txt(dc, "Notification Style", c4X + 14, c4Y + 30, colW - 28, 13, RGB(130, 155, 185), fMini ? fMini : fSm, DT_LEFT | DT_SINGLELINE);
        const char *nstStr = (g_setNotifStyleIdx == 1) ? "Banner" : (g_setNotifStyleIdx == 2) ? "Subtle Drawer" : "Modern (Toast)";
        DrawDropdownPill(dc, c4X + 14, c4Y + 44, colW - 28, 22, nstStr, &g_setNotifStyleIdx, 3);

        Txt(dc, "Notification Sound", c4X + 14, c4Y + 70, colW - 28, 13, RGB(130, 155, 185), fMini ? fMini : fSm, DT_LEFT | DT_SINGLELINE);
        const char *nsnStr = (g_setNotifSoundIdx == 1) ? "Cyber Chime" : (g_setNotifSoundIdx == 2) ? "Radar Ping" : (g_setNotifSoundIdx == 3) ? "Mute" : "Default";
        DrawDropdownPill(dc, c4X + 14, c4Y + 84, colW - 28, 22, nsnStr, &g_setNotifSoundIdx, 4);

        int nswY = c4Y + 114;
        DrawSwitchRow(dc, c4X + 14, nswY + 0*swStep, colW - 28, "Sound Effects", &g_cfg.soundEffects);
        DrawSwitchRow(dc, c4X + 14, nswY + 1*swStep, colW - 28, "Notification Sounds", &g_cfg.notifSounds);
        DrawSwitchRow(dc, c4X + 14, nswY + 2*swStep, colW - 28, "Do Not Disturb (Focus Mode)", &g_cfg.notifDailyDigest);

        /* --- CARD 5: Startup & System Integration --- */
        int c5X = mainX + colW + gap, c5Y = row2Y;
        DrawRoundRectPanel(dc, c5X, c5Y, colW, cardH, 8, RGB(10, 15, 26), RGB(20, 32, 54));
        DrawLine(dc, c5X + 10, c5Y + 1, c5X + colW - 10, c5Y + 1, RGB(30, 48, 78));

        TxtW(dc, L"\uE782", c5X + 14, c5Y + 10, 18, 18, RGB(56, 189, 248), fIcon ? fIcon : fSm, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
        Txt(dc, "Startup & System Integration", c5X + 36, c5Y + 10, colW - 44, 18, RGB(240, 245, 255), fMed, DT_LEFT | DT_VCENTER | DT_SINGLELINE);

        int stswY = c5Y + 32;
        int stswStep = 19;
        DrawSwitchRow(dc, c5X + 14, stswY + 0*stswStep, colW - 28, "Start with Windows", &g_cfg.startWithWindows);
        DrawSwitchRow(dc, c5X + 14, stswY + 1*stswStep, colW - 28, "Minimize to Tray", &g_cfg.minimizeToTray);
        DrawSwitchRow(dc, c5X + 14, stswY + 2*stswStep, colW - 28, "Show in Taskbar", &g_cfg_showInTaskbar);
        DrawSwitchRow(dc, c5X + 14, stswY + 3*stswStep, colW - 28, "Confirm Before Exit", &g_cfg.confirmExit);

        Txt(dc, "Startup Delay", c5X + 14, c5Y + 116, colW - 28, 13, RGB(130, 155, 185), fMini ? fMini : fSm, DT_LEFT | DT_SINGLELINE);
        const char *sdelStr = (g_setStartupDelayIdx == 0) ? "Fast (0 sec)" : (g_setStartupDelayIdx == 2) ? "Delayed (15 sec)" : "Normal (5 sec)";
        DrawDropdownPill(dc, c5X + 14, c5Y + 130, colW - 28, 22, sdelStr, &g_setStartupDelayIdx, 3);

        /* --- CARD 6: Advanced Options --- */
        int c6X = mainX + 2 * (colW + gap), c6Y = row2Y;
        DrawRoundRectPanel(dc, c6X, c6Y, colW, cardH, 8, RGB(10, 15, 26), RGB(20, 32, 54));
        DrawLine(dc, c6X + 10, c6Y + 1, c6X + colW - 10, c6Y + 1, RGB(30, 48, 78));

        TxtW(dc, L"\uE71D", c6X + 14, c6Y + 10, 18, 18, RGB(56, 189, 248), fIcon ? fIcon : fSm, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
        Txt(dc, "Advanced Options", c6X + 36, c6Y + 10, colW - 44, 18, RGB(240, 245, 255), fMed, DT_LEFT | DT_VCENTER | DT_SINGLELINE);

        Txt(dc, "Logging Level", c6X + 14, c6Y + 30, colW - 28, 13, RGB(130, 155, 185), fMini ? fMini : fSm, DT_LEFT | DT_SINGLELINE);
        const char *logStr = (g_setLogLevelIdx == 1) ? "Verbose" : (g_setLogLevelIdx == 2) ? "Debug Trace" : (g_setLogLevelIdx == 3) ? "Silent" : "Normal";
        DrawDropdownPill(dc, c6X + 14, c6Y + 44, colW - 28, 22, logStr, &g_setLogLevelIdx, 4);

        int adswY = c6Y + 76;
        DrawSwitchRow(dc, c6X + 14, adswY + 0*stswStep, colW - 28, "Crash Reports", &g_cfg.cloudCrashDumps);
        DrawSwitchRow(dc, c6X + 14, adswY + 1*stswStep, colW - 28, "Send Anonymous Analytics", &g_cfg.cloudTelemetry);
        DrawSwitchRow(dc, c6X + 14, adswY + 2*stswStep, colW - 28, "Auto Check for Updates", &g_cfg.updAuto);
        DrawSwitchRow(dc, c6X + 14, adswY + 3*stswStep, colW - 28, "Beta Features", &g_cfg.updBeta);
    }
    else {
        /* Other General Sub-Tabs: Behavior, Startup, Sounds, Layouts */
        int col2W = (mainW - gap) / 2;
        int subCardH = (mainH - (gridY - mainY) - qaH - gap);

        /* Left Card */
        DrawRoundRectPanel(dc, mainX, gridY, col2W, subCardH, 8, RGB(10, 15, 26), RGB(20, 32, 54));
        DrawLine(dc, mainX + 10, gridY + 1, mainX + col2W - 10, gridY + 1, RGB(30, 48, 78));
        Txt(dc, g_subTabs[g_setGeneralSubTab].title, mainX + 14, gridY + 12, col2W - 28, 20, RGB(240, 245, 255), fMed, DT_LEFT | DT_SINGLELINE);

        /* Right Card */
        int rc2X = mainX + col2W + gap;
        DrawRoundRectPanel(dc, rc2X, gridY, col2W, subCardH, 8, RGB(10, 15, 26), RGB(20, 32, 54));
        DrawLine(dc, rc2X + 10, gridY + 1, rc2X + col2W - 10, gridY + 1, RGB(30, 48, 78));
        Txt(dc, "Operational Security Policies", rc2X + 14, gridY + 12, col2W - 28, 20, RGB(240, 245, 255), fMed, DT_LEFT | DT_SINGLELINE);

        if (g_setGeneralSubTab == 1) { /* Behavior */
            DrawSwitchRow(dc, mainX + 14, gridY + 44, col2W - 28, "Auto-minimize window when game starts", &g_cfg.perfPauseGaming);
            DrawSwitchRow(dc, mainX + 14, gridY + 70, col2W - 28, "Enable tactile audio click on controls", &g_cfg.soundEffects);
            DrawSwitchRow(dc, mainX + 14, gridY + 96, col2W - 28, "Prompt before stopping security engines", &g_cfg.confirmExit);
            DrawSwitchRow(dc, rc2X + 14, gridY + 44, col2W - 28, "Autonomous background threat correlation", &g_cfg.aiAutoInvestigate);
            DrawSwitchRow(dc, rc2X + 14, gridY + 70, col2W - 28, "Automatic quarantine of high-confidence threats", &g_cfg.avSigDetect);
        } else if (g_setGeneralSubTab == 2) { /* Startup */
            DrawSwitchRow(dc, mainX + 14, gridY + 44, col2W - 28, "Launch Kaevex background daemon at boot", &g_cfg.startWithWindows);
            DrawSwitchRow(dc, mainX + 14, gridY + 70, col2W - 28, "Start minimized in system notification area", &g_cfg.minimizeToTray);
            DrawSwitchRow(dc, rc2X + 14, gridY + 44, col2W - 28, "Verify kernel driver integrity before launch", &g_cfg.tamperProt);
            DrawSwitchRow(dc, rc2X + 14, gridY + 70, col2W - 28, "Pre-load offline vulnerability catalog", &g_cfg.updCveFeed);
        } else if (g_setGeneralSubTab == 3) { /* Sounds */
            DrawSwitchRow(dc, mainX + 14, gridY + 44, col2W - 28, "Enable audible siren on threat detection", &g_cfg.notifSounds);
            DrawSwitchRow(dc, mainX + 14, gridY + 70, col2W - 28, "AI voice assistant vocal synthesis (TTS)", &g_cfg.aiVoiceTts);
            DrawSwitchRow(dc, rc2X + 14, gridY + 44, col2W - 28, "Mute all alert sounds during gaming mode", &g_cfg.perfPauseGaming);
            DrawSwitchRow(dc, rc2X + 14, gridY + 70, col2W - 28, "Daily summary chime at 18:00 UTC", &g_cfg.notifDailyDigest);
        } else { /* Layouts */
            DrawSwitchRow(dc, mainX + 14, gridY + 44, col2W - 28, "High-density compact layout mode", &g_cfg.compactLayout);
            DrawSwitchRow(dc, mainX + 14, gridY + 70, col2W - 28, "GPU DirectX hardware accelerated rendering", &g_cfg.perfGpuAccel);
            DrawSwitchRow(dc, rc2X + 14, gridY + 44, col2W - 28, "Per-monitor DPI dynamic scaling aware", &g_cfg_roundedCorners);
            DrawSwitchRow(dc, rc2X + 14, gridY + 70, col2W - 28, "Always remember last window geometry", &g_cfg_showInTaskbar);
        }
    }

    /* --- BOTTOM QUICK ACTIONS BAR (Exact match to media_1790543860024.jpg) --- */
    int qaY = mainH - qaH + mainY - 6;
    TxtW(dc, L"\uE7C4", mainX, qaY, 18, 18, RGB(56, 189, 248), fIcon ? fIcon : fSm, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
    Txt(dc, "Quick Actions", mainX + 22, qaY, 140, 18, RGB(220, 235, 255), fMed, DT_LEFT | DT_VCENTER | DT_SINGLELINE);

    int panW = (mainW - 2 * gap) / 3;
    int panH = 40;
    int panY = qaY + 20;

    /* Panel 1: Reset UI Layout */
    DrawRoundRectPanel(dc, mainX, panY, panW, panH, 6, RGB(12, 18, 32), RGB(26, 40, 68));
    TxtW(dc, L"\uE72C", mainX + 10, panY, 22, panH, RGB(56, 189, 248), fIcon ? fIcon : fSm, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
    Txt(dc, "Reset UI Layout", mainX + 38, panY + 4, panW - 44, 15, RGB(245, 250, 255), fSm, DT_LEFT | DT_SINGLELINE);
    Txt(dc, "Restore default layout", mainX + 38, panY + 20, panW - 44, 13, RGB(120, 140, 170), fMini ? fMini : fSm, DT_LEFT | DT_SINGLELINE);
    RECT rkP1 = { mainX, panY, mainX + panW, panY + panH };
    RegSetClick(rkP1, 10, NULL, 0);

    /* Panel 2: Reset All Settings */
    int p2X = mainX + panW + gap;
    DrawRoundRectPanel(dc, p2X, panY, panW, panH, 6, RGB(12, 18, 32), RGB(26, 40, 68));
    TxtW(dc, L"\uE74D", p2X + 10, panY, 22, panH, RGB(239, 68, 68), fIcon ? fIcon : fSm, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
    Txt(dc, "Reset All Settings", p2X + 38, panY + 4, panW - 44, 15, RGB(245, 250, 255), fSm, DT_LEFT | DT_SINGLELINE);
    Txt(dc, "Reset everything to default", p2X + 38, panY + 20, panW - 44, 13, RGB(120, 140, 170), fMini ? fMini : fSm, DT_LEFT | DT_SINGLELINE);
    RECT rkP2 = { p2X, panY, p2X + panW, panY + panH };
    RegSetClick(rkP2, 4, NULL, 0);

    /* Panel 3: Synced Notice */
    int p3X = mainX + 2 * (panW + gap);
    DrawRoundRectPanel(dc, p3X, panY, panW, panH, 6, RGB(10, 24, 46), RGB(20, 52, 105));
    TxtW(dc, L"\uE72E", p3X + 10, panY, 22, panH, RGB(56, 189, 248), fIcon ? fIcon : fSm, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
    Txt(dc, "Your settings are saved securely and synced with your account.", p3X + 36, panY + 4, panW - 42, panH - 8, RGB(160, 195, 235), fMini ? fMini : fSm, DT_LEFT | DT_VCENTER | DT_WORDBREAK);
}

static void PaintSet(HDC dc, int cx, int cy, int cw, int ch) {
    g_setClickCnt = 0; /* Reset interactive click registry for this paint frame */
    HBRUSH ob;
    HPEN   op;

    /* === Left Inner Sidebar (CONFIGURATION CENTER) === */
    int sideW = 216;
    int sideH = ch - 16;
    int sideX = cx + 8;
    int sideY = cy + 6;

    /* Sidebar Background Panel */
    DrawRoundRectPanel(dc, sideX, sideY, sideW, sideH, 8, RGB(8, 14, 26), RGB(20, 32, 54));
    DrawLine(dc, sideX + 8, sideY + 1, sideX + sideW - 8, sideY + 1, RGB(35, 50, 80));

    /* Sidebar Title Banner */
    Txt(dc, "CONFIGURATION CENTER", sideX + 12, sideY + 10, sideW - 24, 18, RGB(56, 189, 248), fMed, DT_LEFT | DT_SINGLELINE | DT_VCENTER);
    DrawLine(dc, sideX + 10, sideY + 32, sideX + sideW - 10, sideY + 32, RGB(22, 34, 56));

    /* Categories List */
    int itemY = sideY + 36;
    const char *lastGroup = "";
    int itemH = 22;

    for (int i = 0; i < SET_CAT_COUNT; i++) {
        const SetCatMeta *m = &g_catMeta[i];

        /* Group Header */
        if (strcmp(m->group, lastGroup) != 0) {
            lastGroup = m->group;
            Txt(dc, m->group, sideX + 12, itemY + 2, sideW - 24, 14, RGB(100, 130, 165), fMini ? fMini : fSm, DT_LEFT | DT_SINGLELINE | DT_VCENTER);
            itemY += 18;
        }

        BOOL isSel = (g_setSubTab == m->id);
        RECT iRc = { sideX + 6, itemY, sideX + sideW - 6, itemY + itemH };

        if (isSel) {
            /* Active glowing royal blue pill */
            DrawRoundRectPanel(dc, iRc.left, iRc.top, iRc.right - iRc.left, itemH, 6, RGB(26, 86, 219), RGB(59, 130, 246));
            DrawLine(dc, iRc.left + 4, iRc.top + 1, iRc.right - 4, iRc.top + 1, RGB(100, 160, 255));
        }

        COLORREF icCol = isSel ? RGB(255, 255, 255) : RGB(96, 165, 250);
        COLORREF txCol = isSel ? RGB(255, 255, 255) : RGB(170, 190, 215);

        /* Icon */
        SetTextColor(dc, icCol);
        SelectObject(dc, fIcon ? fIcon : fSm);
        RECT icR = { iRc.left + 6, iRc.top, iRc.left + 22, iRc.bottom };
        DrawTextW(dc, m->iconW, -1, &icR, DT_CENTER | DT_VCENTER | DT_SINGLELINE);

        /* Title */
        Txt(dc, m->title, iRc.left + 24, iRc.top, iRc.right - iRc.left - 38, itemH, txCol, fMini ? fMini : fSm, DT_LEFT | DT_VCENTER | DT_SINGLELINE);

        /* Right Chevron '>' */
        Txt(dc, ">", iRc.right - 14, iRc.top, 10, itemH, isSel ? RGB(220, 235, 255) : RGB(65, 90, 120), fMini ? fMini : fSm, DT_CENTER | DT_VCENTER | DT_SINGLELINE);

        /* Register sidebar item click */
        RegSetClick(iRc, 5, NULL, m->id);

        itemY += itemH + 1;
    }

    /* === Right Main Content Area === */
    int mainX = sideX + sideW + 12;
    int mainY = sideY;
    int mainW = cw - (mainX - cx) - 8;
    int mainH = sideH;

    if (g_setSubTab == SET_GENERAL) {
        PaintGeneralPreferences(dc, mainX, mainY, mainW, mainH);
        return;
    }

    /* Specific Category Details (Other 22 categories) */
    const SetCatMeta *cur = &g_catMeta[0];
    for (int i = 0; i < SET_CAT_COUNT; i++) {
        if (g_catMeta[i].id == g_setSubTab) {
            cur = &g_catMeta[i];
            break;
        }
    }

    /* Header Bar */
    int hIcSz = 40;
    DrawRoundRectPanel(dc, mainX, mainY + 2, hIcSz, hIcSz, 8, RGB(16, 42, 95), RGB(37, 99, 235));
    DrawLine(dc, mainX + 4, mainY + 3, mainX + hIcSz - 4, mainY + 3, RGB(100, 180, 255));
    SetTextColor(dc, RGB(56, 189, 248));
    SelectObject(dc, fIcon ? fIcon : fSm);
    RECT hIcR = { mainX, mainY + 2, mainX + hIcSz, mainY + 2 + hIcSz };
    DrawTextW(dc, cur->iconW, -1, &hIcR, DT_CENTER | DT_VCENTER | DT_SINGLELINE);

    char hdrTitle[128];
    snprintf(hdrTitle, sizeof(hdrTitle), "%s  %s", cur->icon, cur->title);
    Txt(dc, hdrTitle, mainX + hIcSz + 12, mainY + 2, mainW - 320, 20, RGB(245, 250, 255), fMed, DT_LEFT | DT_SINGLELINE | DT_VCENTER | DT_NOPREFIX);
    Txt(dc, cur->subTitle, mainX + hIcSz + 12, mainY + 24, mainW - 320, 16, RGB(140, 165, 195), fMini ? fMini : fSm, DT_LEFT | DT_SINGLELINE | DT_VCENTER);

    /* Action Buttons */
    int b1W = 144, b1H = 30;
    int b1X = mainX + mainW - b1W - 130 - 10;
    DrawRoundRectPanel(dc, b1X, mainY + 6, b1W, b1H, 6, RGB(12, 18, 32), RGB(30, 48, 80));
    TxtW(dc, L"\uE72C", b1X + 8, mainY + 6, 20, b1H, RGB(200, 220, 245), fIcon ? fIcon : fSm, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
    Txt(dc, "Reset to Default", b1X + 28, mainY + 6, b1W - 34, b1H, RGB(220, 235, 255), fSm, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
    RECT saveRc = { b1X, mainY + 6, b1X + b1W, mainY + 6 + b1H };
    RegSetClick(saveRc, 4, NULL, 0);

    int b2W = 130, b2H = 30;
    int b2X = mainX + mainW - b2W;
    DrawRoundRectPanel(dc, b2X, mainY + 6, b2W, b2H, 6, RGB(37, 99, 235), RGB(59, 130, 246));
    DrawLine(dc, b2X + 4, mainY + 7, b2X + b2W - 4, mainY + 7, RGB(120, 180, 255));
    TxtW(dc, L"\uE74E", b2X + 8, mainY + 6, 20, b2H, RGB(255, 255, 255), fIcon ? fIcon : fSm, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
    Txt(dc, "Save Changes", b2X + 28, mainY + 6, b2W - 34, b2H, RGB(255, 255, 255), fSm, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
    RECT defRc = { b2X, mainY + 6, b2X + b2W, mainY + 6 + b2H };
    RegSetClick(defRc, 3, NULL, 0);

    DrawLine(dc, mainX, mainY + 48, mainX + mainW, mainY + 48, C_BORDER2);
    int contentY = mainY + 58;

    /* === Render Dynamic Content for Current SubTab === */
    if (g_setSubTab == SET_PROTECTION) {
        static const char *profiles[] = { "Balanced", "Strict", "Maximum", "Custom" };
        DrawSetModeSelector(dc, mainX, contentY, mainW, "Protection Profile", "Select behavioral aggressiveness and interception sensitivity", profiles, 4, &g_cfg.protMode);

        SetToggleDef togs[] = {
            { "Real-Time Interception", "Continuously intercept filesystem and process creation events", &g_cfg.realTimeProt, C_GREEN },
            { "Behavioral Heuristics", "Detect suspicious runtime parent-child and injection anomalies", &g_cfg.behaviorMon, C_CYAN },
            { "Static Heuristic Engine", "5-layer static code inspection and binary entropy scoring", &g_cfg.heuristicDetect, C_CYAN },
            { "Cloud Threat Intelligence", "Global hash verification and reputation lookup queries", &g_cfg.cloudProt, C_BLUE },
            { "Active Threat Intel Feeds", "Live streaming ingestion of verified C2 IP and URL IOCs", &g_cfg.threatIntel, C_BLUE },
            { "PUA / PUP In-Depth Guard", "Detect potentially unwanted crypto miners, adware & dialers", &g_cfg.puaPupProt, C_AMBER },
            { "AMSI Script Interception", "Inspect PowerShell, VBS, and office macro script blocks", &g_cfg.scriptProt, C_PURPLE },
            { "Tamper Shield & Self-Defense", "Prevent unauthorized task kill, file wipe or driver tampering", &g_cfg.tamperProt, C_RED },
        };
        int gridY = contentY + 68;
        int colW  = (mainW - 12) / 2;
        int rowH  = 46;
        for (int i = 0; i < 8; i++) {
            int cx2 = mainX + (i % 2) * (colW + 12);
            int cy2 = gridY + (i / 2) * (rowH + 8);
            DrawSetToggleCard(dc, cx2, cy2, colW, rowH, &togs[i]);
        }
    }
    else if (g_setSubTab == SET_AV) {
        static const char *actions[] = { "Prompt User", "Quarantine", "Block Access", "Instant Purge" };
        DrawSetModeSelector(dc, mainX, contentY, mainW, "Default Threat Remediation", "Automated policy when malicious signatures are matched", actions, 4, &g_cfg.avThreatAction);

        SetToggleDef togs[] = {
            { "Scan on Access", "Inspect files when opened, copied, or executed in user-space", &g_cfg.avScanOnAccess, C_GREEN },
            { "Download Stream Guard", "Automatically analyze binaries arriving from web browsers", &g_cfg.avScanDownloads, C_CYAN },
            { "Deep Archive Decompression", "Recursively inspect nested ZIP, RAR, 7Z and TAR payloads", &g_cfg.avScanArchives, C_BLUE },
            { "Removable Storage Audit", "Instantly scan external USB flash drives upon insertion", &g_cfg.avScanUsb, C_AMBER },
            { "Network Share Scanning", "Inspect files accessed over SMB, CIFS, or mapped network drives", &g_cfg.avScanNetwork, C_PURPLE },
            { "Script Engine Interceptor", "Monitor WScript, CScript, and batch interpreters in real-time", &g_cfg.avScanScripts, C_RED },
            { "Memory Disassembly Scan", "Detect unmapped DLLs, shellcode, and hollowed memory segments", &g_cfg.avScanProcs, C_RED },
            { "Signature DB Matcher", "Verify against 1000+ known APT, ransomware & trojan signatures", &g_cfg.avSigDetect, C_GREEN },
        };
        int gridY = contentY + 68;
        int colW  = (mainW - 12) / 2;
        int rowH  = 46;
        for (int i = 0; i < 8; i++) {
            int cx2 = mainX + (i % 2) * (colW + 12);
            int cy2 = gridY + (i / 2) * (rowH + 8);
            DrawSetToggleCard(dc, cx2, cy2, colW, rowH, &togs[i]);
        }

        /* Real Action Button: Purge Quarantine */
        int qBtnW = 280, qBtnH = 30;
        int qBtnX = mainX + 14;
        int qBtnY = gridY + 4 * (rowH + 8) + 6;
        HBRUSH qBg = CreateSolidBrush(RGB(40, 20, 25));
        HPEN   qPn = CreatePen(PS_SOLID, 1, RGB(239, 68, 68));
        HBRUSH oqb = (HBRUSH)SelectObject(dc, qBg);
        HPEN   oqp = (HPEN)SelectObject(dc, qPn);
        RoundRect(dc, qBtnX, qBtnY, qBtnX + qBtnW, qBtnY + qBtnH, 6, 6);
        SelectObject(dc, oqb); SelectObject(dc, oqp);
        DeleteObject(qBg); DeleteObject(qPn);
        Txt(dc, "[Q] Purge Quarantined Storage Now", qBtnX, qBtnY, qBtnW, qBtnH, RGB(255, 120, 120), fSm, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
        RECT qclk = { qBtnX, qBtnY, qBtnX + qBtnW, qBtnY + qBtnH };
        RegSetClick(qclk, 7, NULL, 12); /* Action 12 = Purge Quarantine */
    }
    else if (g_setSubTab == SET_NET) {
        static const char *policies[] = { "Allow All", "Ask Unknown", "Block Unknown" };
        DrawSetModeSelector(dc, mainX, contentY, mainW, "Connection Security Policy", "Default policy for newly created outbound application sockets", policies, 3, &g_cfg.netPolicy);

        SetToggleDef togs[] = {
            { "Socket Telemetry Monitor", "Live tracking of all established TCP and UDP socket sessions", &g_cfg.netMonConn, C_CYAN },
            { "Process Association", "Map active connections directly to executable name and PID", &g_cfg.netMonProc, C_CYAN },
            { "DNS Query Interception", "Inspect and record all outbound domain resolution queries", &g_cfg.netMonDns, C_BLUE },
            { "Open Port Sentinel", "Identify newly listening network ports and latent backdoors", &g_cfg.netMonPorts, C_AMBER },
            { "C2 Beacon Detection", "Calculate periodic jitter to uncover covert botnet beacons", &g_cfg.netDetectC2, C_RED },
            { "Suspicious IP Flagging", "Check remote endpoints against Tor relays & bulletproof hosts", &g_cfg.netDetectSusp, C_RED },
            { "Encrypted Connection Log", "Record cryptographic audit trail of all network connections", &g_cfg.netConnLogging, C_GREEN },
            { "DNS Sinkhole Shield", "Instantly poison and null-route blacklisted malware domains", &g_cfg.netDnsSinkhole, C_GREEN },
        };
        int gridY = contentY + 68;
        int colW  = (mainW - 12) / 2;
        int rowH  = 46;
        for (int i = 0; i < 8; i++) {
            int cx2 = mainX + (i % 2) * (colW + 12);
            int cy2 = gridY + (i / 2) * (rowH + 8);
            DrawSetToggleCard(dc, cx2, cy2, colW, rowH, &togs[i]);
        }

        /* Real Action Button: Flush DNS Cache */
        int fBtnW = 280, fBtnH = 30;
        int fBtnX = mainX + 14;
        int fBtnY = gridY + 4 * (rowH + 8) + 6;
        HBRUSH fBg = CreateSolidBrush(RGB(10, 36, 60));
        HPEN   fPn = CreatePen(PS_SOLID, 1, RGB(6, 182, 212));
        HBRUSH ofb = (HBRUSH)SelectObject(dc, fBg);
        HPEN   ofp = (HPEN)SelectObject(dc, fPn);
        RoundRect(dc, fBtnX, fBtnY, fBtnX + fBtnW, fBtnY + fBtnH, 6, 6);
        SelectObject(dc, ofb); SelectObject(dc, ofp);
        DeleteObject(fBg); DeleteObject(fPn);
        Txt(dc, "[F] Flush Windows DNS Cache Now", fBtnX, fBtnY, fBtnW, fBtnH, RGB(6, 182, 212), fSm, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
        RECT fclk = { fBtnX, fBtnY, fBtnX + fBtnW, fBtnY + fBtnH };
        RegSetClick(fclk, 7, NULL, 3); /* Action 3 = Flush DNS */
    }
    else if (g_setSubTab == SET_FW) {
        static const char *profiles[] = { "Public", "Private", "Domain" };
        DrawSetModeSelector(dc, mainX, contentY, mainW, "Active Firewall Profile", "Select boundary enforcement zone and inbound port restrictions", profiles, 3, &g_cfg.fwProfile);

        SetToggleDef togs[] = {
            { "Master Firewall Guard", "Engage packet boundary filtering via host netsh rules", &g_cfg.fwEnabled, C_GREEN },
            { "Inbound Packet Filter", "Drop unsolicited incoming connection probes from external networks", &g_cfg.fwInbound, C_CYAN },
            { "Outbound Leak Prevention", "Prevent rogue binaries from establishing unauthorized sockets", &g_cfg.fwOutbound, C_CYAN },
            { "Stealth Mode", "Silent drop of incoming ICMP echo pings and port scans", &g_cfg.fwStealth, C_BLUE },
            { "Block Unknown Binaries", "Prevent non-allowlisted applications from creating sockets", &g_cfg.fwBlockUnknown, C_AMBER },
            { "Block Suspicious Ports", "Hard block IRC, SMB over WAN, and known exploit ports", &g_cfg.fwBlockSuspicious, C_RED },
            { "Block Remote Access", "Restrict inbound RDP, Telnet, and VNC administrative ports", &g_cfg.fwBlockRemote, C_RED },
            { "Comprehensive Packet Log", "Record allowed and blocked packet metadata to security log", &g_cfg.fwPacketLogging, C_PURPLE },
        };
        int gridY = contentY + 68;
        int colW  = (mainW - 12) / 2;
        int rowH  = 46;
        for (int i = 0; i < 8; i++) {
            int cx2 = mainX + (i % 2) * (colW + 12);
            int cy2 = gridY + (i / 2) * (rowH + 8);
            DrawSetToggleCard(dc, cx2, cy2, colW, rowH, &togs[i]);
        }

        /* Real Action Button: Reset Firewall Rules */
        int rBtnW = 320, rBtnH = 30;
        int rBtnX = mainX + 14;
        int rBtnY = gridY + 4 * (rowH + 8) + 6;
        HBRUSH rBg = CreateSolidBrush(RGB(40, 20, 20));
        HPEN   rPn = CreatePen(PS_SOLID, 1, RGB(239, 68, 68));
        HBRUSH orb = (HBRUSH)SelectObject(dc, rBg);
        HPEN   orp = (HPEN)SelectObject(dc, rPn);
        RoundRect(dc, rBtnX, rBtnY, rBtnX + rBtnW, rBtnY + rBtnH, 6, 6);
        SelectObject(dc, orb); SelectObject(dc, orp);
        DeleteObject(rBg); DeleteObject(rPn);
        Txt(dc, "[R] Reset Firewall Rules to Windows Defaults", rBtnX, rBtnY, rBtnW, rBtnH, RGB(255, 120, 120), fSm, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
        RECT rclk = { rBtnX, rBtnY, rBtnX + rBtnW, rBtnY + rBtnH };
        RegSetClick(rclk, 7, NULL, 11); /* Action 11 = Reset Firewall */
    }
    else if (g_setSubTab == SET_WAF) {
        static const char *wafModes[] = { "Passive Monitor", "Active Block", "AI Learning" };
        DrawSetModeSelector(dc, mainX, contentY, mainW, "WAF Enforcement Profile", "Select operation posture for Layer 7 web application protection", wafModes, 3, &g_cfg.wafMode);

        SetToggleDef togs[] = {
            { "Master WAF Shield", "Layer 7 HTTP/HTTPS reverse proxy deep packet inspection", &g_cfg.wafEnabled, C_GREEN },
            { "Phishing Neural Filter", "Detect deceptive login patterns and credential harvesters", &g_cfg.wafPhishing, C_CYAN },
            { "Malicious URL Blocker", "Block known exploit kits and zero-day distribution URIs", &g_cfg.wafMaliciousUrl, C_BLUE },
            { "SQL Injection (SQLi)", "Intercept union selects, blind boolean, and hex query vectors", &g_cfg.wafSqli, C_RED },
            { "Cross-Site Scripting (XSS)", "Neutralize reflective, stored, and DOM-based script injections", &g_cfg.wafXss, C_RED },
            { "Remote Code Exec (RCE)", "Drop command injection, shell escapes, and bash pipe strings", &g_cfg.wafRce, C_RED },
            { "Local File Inclusion (LFI)", "Prevent traversal past web root via ../ and URI encodings", &g_cfg.wafLfi, C_AMBER },
            { "Rate Limiting & Anti-Bot", "Throttle high-frequency DDoS attempts and credential brute-force", &g_cfg.wafRateLimit, C_PURPLE },
        };
        int gridY = contentY + 68;
        int colW  = (mainW - 12) / 2;
        int rowH  = 46;
        for (int i = 0; i < 8; i++) {
            int cx2 = mainX + (i % 2) * (colW + 12);
            int cy2 = gridY + (i / 2) * (rowH + 8);
            DrawSetToggleCard(dc, cx2, cy2, colW, rowH, &togs[i]);
        }
    }
    else if (g_setSubTab == SET_RANSOM) {
        static const char *rsModes[] = { "Kill Process", "Suspend Thread", "Quarantine", "Auto Rollback" };
        DrawSetModeSelector(dc, mainX, contentY, mainW, "Automated Threat Response", "Action dispatched when decoy files or mass encryption is detected", rsModes, 4, &g_cfg.rsAction);

        SetToggleDef togs[] = {
            { "Real-Time Sentinel", "Watch filesystem for rapid attribute rewrites & mass changes", &g_cfg.rsRealtime, C_GREEN },
            { "Mass File Change Detect", "Flag processes modifying >10 user files per second", &g_cfg.rsMassFile, C_RED },
            { "Suspicious Encryption", "Detect high-entropy writes indicating AES or ChaCha20 locks", &g_cfg.rsSuspEncrypt, C_RED },
            { "Protected Folders", "Lock Documents, Desktop, and Pictures from untrusted code", &g_cfg.rsProtFolders, C_CYAN },
            { "Process Behavior Tree", "Trace parent processes attempting to spawn vssadmin or bcdedit", &g_cfg.rsProcBehavior, C_PURPLE },
            { "Immediate Process Kill", "Instantly terminate rogue encryptor binaries with zero delay", &g_cfg.rsAutoKill, C_RED },
            { "VSS Shadow Snapshots", "Keep protected system restore points active and armed", &g_cfg.rsVssSnapshots, C_GREEN },
            { "Autonomous Rollback", "Automatically recover altered files from verified shadow volume", &g_cfg.rsRollback, C_BLUE },
        };
        int gridY = contentY + 68;
        int colW  = (mainW - 12) / 2;
        int rowH  = 46;
        for (int i = 0; i < 8; i++) {
            int cx2 = mainX + (i % 2) * (colW + 12);
            int cy2 = gridY + (i / 2) * (rowH + 8);
            DrawSetToggleCard(dc, cx2, cy2, colW, rowH, &togs[i]);
        }

        /* Real Action Buttons: Deploy Decoys & Trigger VSS Snapshot */
        int dBtnW = 240, dBtnH = 30;
        int dBtnX = mainX + 14;
        int dBtnY = gridY + 4 * (rowH + 8) + 6;
        HBRUSH dBg = CreateSolidBrush(RGB(10, 44, 32));
        HPEN   dPn = CreatePen(PS_SOLID, 1, RGB(52, 211, 153));
        HBRUSH odb = (HBRUSH)SelectObject(dc, dBg);
        HPEN   odp = (HPEN)SelectObject(dc, dPn);
        RoundRect(dc, dBtnX, dBtnY, dBtnX + dBtnW, dBtnY + dBtnH, 6, 6);
        SelectObject(dc, odb); SelectObject(dc, odp);
        DeleteObject(dBg); DeleteObject(dPn);
        Txt(dc, "[D] Deploy Honeypot Decoys", dBtnX, dBtnY, dBtnW, dBtnH, RGB(52, 211, 153), fSm, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
        RECT dclk = { dBtnX, dBtnY, dBtnX + dBtnW, dBtnY + dBtnH };
        RegSetClick(dclk, 7, NULL, 5); /* Action 5 = Deploy Honeypots */

        int vBtnW = 240, vBtnH = 30;
        int vBtnX = dBtnX + dBtnW + 12;
        int vBtnY = dBtnY;
        HBRUSH vBg = CreateSolidBrush(RGB(12, 32, 60));
        HPEN   vPn = CreatePen(PS_SOLID, 1, RGB(6, 182, 212));
        HBRUSH ovb = (HBRUSH)SelectObject(dc, vBg);
        HPEN   ovp = (HPEN)SelectObject(dc, vPn);
        RoundRect(dc, vBtnX, vBtnY, vBtnX + vBtnW, vBtnY + vBtnH, 6, 6);
        SelectObject(dc, ovb); SelectObject(dc, ovp);
        DeleteObject(vBg); DeleteObject(vPn);
        Txt(dc, "[V] Create VSS Restore Snapshot", vBtnX, vBtnY, vBtnW, vBtnH, RGB(6, 182, 212), fSm, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
        RECT vclk = { vBtnX, vBtnY, vBtnX + vBtnW, vBtnY + vBtnH };
        RegSetClick(vclk, 7, NULL, 6); /* Action 6 = Create VSS Snapshot */
    }

    else if (g_setSubTab == SET_SBX) {
        static const char *netSims[] = { "Isolated (No Net)", "Simulated Honeynet", "DNS Mocking" };
        DrawSetModeSelector(dc, mainX, contentY, mainW, "Sandbox Network Simulation", "Select network containment posture for isolated executions", netSims, 3, &g_cfg.sbxSimulatedNet);

        SetToggleDef togs[] = {
            { "Auto-Submit Unknowns", "Automatically detour unclassified binaries to sandbox", &g_cfg.sbxAutoAnalysis, C_CYAN },
            { "AppContainer Isolation", "Execute in restricted low-integrity SID sandbox containment", &g_cfg.sbxProcIsol, C_GREEN },
            { "Network Virtualization", "Intercept outbound sockets to simulated honeynet nodes", &g_cfg.sbxNetIsol, C_BLUE },
            { "Filesystem Copy-on-Write", "Prevent any persistent writes to host physical storage drives", &g_cfg.sbxFsIsol, C_PURPLE },
            { "Static PE Disassembly", "Extract imports, exports, entropy and suspicious code strings", &g_cfg.sbxStaticAnalysis, C_CYAN },
            { "Dynamic API Tracing", "Record hooked Win32 / NT syscall execution trace in real-time", &g_cfg.sbxDynamicAnalysis, C_AMBER },
            { "Simulated Internet C2", "Provide mock 200 OK responses to observe malware callbacks", &g_cfg.sbxSimulatedNet, C_BLUE },
            { "DNS Response Mocking", "Sinkhole all sandbox domain resolution requests to localhost", &g_cfg.sbxDnsSim, C_GREEN },
        };
        int gridY = contentY + 68;
        int colW  = (mainW - 12) / 2;
        int rowH  = 46;
        for (int i = 0; i < 8; i++) {
            int cx2 = mainX + (i % 2) * (colW + 12);
            int cy2 = gridY + (i / 2) * (rowH + 8);
            DrawSetToggleCard(dc, cx2, cy2, colW, rowH, &togs[i]);
        }
    }
    else if (g_setSubTab == SET_APPCTRL) {
        static const char *appPols[] = { "Allow Known", "Ask Unknown", "Strict Whitelist" };
        DrawSetModeSelector(dc, mainX, contentY, mainW, "Application Execution Policy", "Rules governing execution of newly discovered or untrusted binaries", appPols, 3, &g_cfg.appExecPolicy);

        SetToggleDef togs[] = {
            { "Strict Allow List", "Only permit pre-authorized cryptographic hashes to run", &g_cfg.appAllowList, C_GREEN },
            { "Global Blocklist", "Block all binaries identified as malicious or hacktools", &g_cfg.appBlockList, C_RED },
            { "Block Unsigned Software", "Disallow executables lacking valid Authenticode certificates", &g_cfg.appBlockUnsigned, C_AMBER },
            { "Block Suspicious Utilities", "Prevent lolbins: certutil, bitsadmin, mshta and wmic abuse", &g_cfg.appBlockSuspicious, C_RED },
            { "Block Script Launchers", "Restrict execution of VBS, JS, HTA and unapproved scripts", &g_cfg.appBlockScripts, C_PURPLE },
            { "Portable Binary Guard", "Mandate sandbox execution for standalone non-installed EXEs", &g_cfg.appPortableGuard, C_BLUE },
            { "DLL Sideloading Guard", "Enforce safe DLL search order and hash verification checks", &g_cfg.appDllSideloadGuard, C_CYAN },
            { "Tamper-Proof Audit Log", "Record all process execution rejections to immutable log", &g_cfg.appAuditLog, C_GREEN },
        };
        int gridY = contentY + 68;
        int colW  = (mainW - 12) / 2;
        int rowH  = 46;
        for (int i = 0; i < 8; i++) {
            int cx2 = mainX + (i % 2) * (colW + 12);
            int cy2 = gridY + (i / 2) * (rowH + 8);
            DrawSetToggleCard(dc, cx2, cy2, colW, rowH, &togs[i]);
        }
    }
    else if (g_setSubTab == SET_ENGINES) {
        Txt(dc, "Defense Feature Modules", mainX, contentY + 6, mainW, 20, C_TEXT, fMed, DT_LEFT | DT_SINGLELINE);
        Txt(dc, "Modules run when their feature workflow is invoked. Service health is not available.", mainX, contentY + 28, mainW, 18, C_DIM, fSm, DT_LEFT | DT_SINGLELINE);

        int gridY = contentY + 68;
        int colW  = (mainW - 12) / 2;
        int rowH  = 64;

        for (int i = 0; i < 8; i++) {
            int ex = mainX + (i % 2) * (colW + 12);
            int ey = gridY + (i / 2) * (rowH + 8);

            HBRUSH eBg = CreateSolidBrush(C_CARD);
            HPEN   ePn = CreatePen(PS_SOLID, 1, C_BORDER);
            ob = (HBRUSH)SelectObject(dc, eBg); op = (HPEN)SelectObject(dc, ePn);
            RoundRect(dc, ex, ey, ex + colW, ey + rowH, 8, 8);
            SelectObject(dc, ob); SelectObject(dc, op);
            DeleteObject(eBg); DeleteObject(ePn);

            /* Status Dot */
            HBRUSH dotBr = CreateSolidBrush(C_DIM);
            HPEN   dotPn = CreatePen(PS_SOLID, 1, C_DIM);
            ob = (HBRUSH)SelectObject(dc, dotBr); op = (HPEN)SelectObject(dc, dotPn);
            Ellipse(dc, ex + 12, ey + 12, ex + 22, ey + 22);
            SelectObject(dc, ob); SelectObject(dc, op);
            DeleteObject(dotBr); DeleteObject(dotPn);

            Txt(dc, g_eng[i].name, ex + 28, ey + 8, colW - 130, 16, C_TEXT, fMed, DT_LEFT | DT_SINGLELINE | DT_NOPREFIX);
            Txt(dc, g_eng[i].detail, ex + 28, ey + 26, colW - 130, 14, C_DIM, fSm, DT_LEFT | DT_SINGLELINE | DT_NOPREFIX);

            char ldStr[64];
            snprintf(ldStr, sizeof(ldStr), "Health unavailable  |  v%s", g_eng[i].version);
            Txt(dc, ldStr, ex + 28, ey + 42, colW - 130, 14, RGB(6, 182, 212), fSm, DT_LEFT | DT_SINGLELINE);

            Txt(dc, "On demand", ex + colW - 100, ey + 22, 88, 20,
                C_DIM, fSm, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
        }
    }
    else if (g_setSubTab == SET_AISOC) {
        static const char *levels[] = { "Observation", "Suggestion", "Ask Before Action", "Autonomous Remediate" };
        DrawSetModeSelector(dc, mainX, contentY, mainW, "Copilot Autonomy Level", "Specify automated response permissions for AI SOC Agent", levels, 4, &g_cfg.aiAutoLevel);

        /* AI Key & Provider Config Panel */
        int pnlY = contentY + 66;
        int pnlH = 92;
        HBRUSH pBg = CreateSolidBrush(C_CARD);
        HPEN   pPn = CreatePen(PS_SOLID, 1, C_BORDER);
        ob = (HBRUSH)SelectObject(dc, pBg); op = (HPEN)SelectObject(dc, pPn);
        RoundRect(dc, mainX, pnlY, mainX + mainW, pnlY + pnlH, 8, 8);
        SelectObject(dc, ob); SelectObject(dc, op);
        DeleteObject(pBg); DeleteObject(pPn);

        Txt(dc, "AI Provider Model:", mainX + 16, pnlY + 16, 120, 22, C_DIM, fSm, DT_LEFT | DT_SINGLELINE | DT_VCENTER);
        Txt(dc, "Together AI API Key:", mainX + 16, pnlY + 54, 120, 22, C_DIM, fSm, DT_LEFT | DT_SINGLELINE | DT_VCENTER);

        SetToggleDef togs[] = {
            { "Master AI Copilot", "Enable DeepSeek-V4-Pro / Groq neural security assistant", &g_cfg.aiEnabled, C_CYAN },
            { "Auto Incident Correlation", "Aggregate isolated telemetry alerts into unified incidents", &g_cfg.aiAutoInvestigate, C_BLUE },
            { "MITRE ATT&CK Mapping", "Correlate malicious commands with MITRE matrix techniques", &g_cfg.aiThreatCorrelation, C_PURPLE },
            { "Executive Incident Briefs", "Synthesize plain-language root-cause threat explanations", &g_cfg.aiSummarize, C_GREEN },
            { "Autonomous Remediation", "Allow AI to execute safe containment and isolation playbooks", &g_cfg.aiAutoRemediate, C_RED },
            { "Local On-Device Intelligence", "Execute fallback rule engine entirely offline without cloud", &g_cfg.aiLocalOnly, C_AMBER },
            { "Voice Telemetry Output (TTS)", "Speak urgent incident advisories using synthesized audio", &g_cfg.aiVoiceTts, C_CYAN },
            { "Threat Intel Enrichment", "Enrich CVE alerts with live CVSS & exploit maturity ratings", &g_cfg.aiIntelEnrich, C_BLUE },
        };
        int gridY = pnlY + pnlH + 12;
        int colW  = (mainW - 12) / 2;
        int rowH  = 46;
        for (int i = 0; i < 8; i++) {
            int cx2 = mainX + (i % 2) * (colW + 12);
            int cy2 = gridY + (i / 2) * (rowH + 8);
            DrawSetToggleCard(dc, cx2, cy2, colW, rowH, &togs[i]);
        }
    }
    else if (g_setSubTab == SET_DEVICE) {
        static const char *usbModes[] = { "Full Access", "Read-Only Mode", "Block Storage" };
        DrawSetModeSelector(dc, mainX, contentY, mainW, "USB Storage Policy", "Removable flash drive and external hard drive access restrictions", usbModes, 3, &g_cfg.devUsbReadOnly);

        SetToggleDef togs[] = {
            { "USB Mass Storage Guard", "Monitor insertion of external flash drives & portable disks", &g_cfg.devUsbStorage, C_CYAN },
            { "Block Unknown USB Storage", "Reject unverified VID/PID hardware identifiers instantly", &g_cfg.devBlockUnknownUsb, C_RED },
            { "Enforce Read-Only Filesystem", "Prevent unauthorized data exfiltration or copying to USBs", &g_cfg.devUsbReadOnly, C_AMBER },
            { "Bluetooth Adapter Control", "Audit and restrict unauthorized wireless peripheral pairings", &g_cfg.devBluetooth, C_BLUE },
            { "Camera & Webcam Shield", "Alert on unauthorized video capture handles and process locks", &g_cfg.devCamera, C_PURPLE },
            { "Microphone Eavesdrop Shield", "Monitor and block covert background audio recording handles", &g_cfg.devMic, C_PURPLE },
            { "Thunderbolt / PCIe Bus Lock", "Protect against DMA memory dump attacks over high-speed buses", &g_cfg.devPcieLock, C_RED },
            { "Peripheral Hardware Audit", "Log all hardware attachment and removal events to forensics", &g_cfg.devAuditLog, C_GREEN },
        };
        int gridY = contentY + 68;
        int colW  = (mainW - 12) / 2;
        int rowH  = 46;
        for (int i = 0; i < 8; i++) {
            int cx2 = mainX + (i % 2) * (colW + 12);
            int cy2 = gridY + (i / 2) * (rowH + 8);
            DrawSetToggleCard(dc, cx2, cy2, colW, rowH, &togs[i]);
        }
    }
    else if (g_setSubTab == SET_FORENSICS) {
        static const char *rets[] = { "1 Day", "7 Days", "30 Days", "90 Days" };
        DrawSetModeSelector(dc, mainX, contentY, mainW, "Audit Log Retention Cycle", "Automatic rotation and cryptographic archiving lifecycle", rets, 4, &g_cfg.logRetention);

        /* Export Controls Panel */
        int pnlY = contentY + 66;
        int pnlH = 88;
        HBRUSH pBg = CreateSolidBrush(C_CARD);
        HPEN   pPn = CreatePen(PS_SOLID, 1, C_BORDER);
        ob = (HBRUSH)SelectObject(dc, pBg); op = (HPEN)SelectObject(dc, pPn);
        RoundRect(dc, mainX, pnlY, mainX + mainW, pnlY + pnlH, 8, 8);
        SelectObject(dc, ob); SelectObject(dc, op);
        DeleteObject(pBg); DeleteObject(pPn);

        Txt(dc, "Max Log Records:", mainX + 16, pnlY + 16, 120, 22, C_DIM, fSm, DT_LEFT | DT_SINGLELINE | DT_VCENTER);
        Txt(dc, "Export Archive Path:", mainX + 16, pnlY + 52, 120, 22, C_DIM, fSm, DT_LEFT | DT_SINGLELINE | DT_VCENTER);

        SetToggleDef togs[] = {
            { "Process Creation Log", "Capture parent PID, command line parameters and image hash", &g_cfg.logProcs, C_CYAN },
            { "Socket & Network Log", "Record inbound and outbound connection endpoints & ports", &g_cfg.logNetwork, C_BLUE },
            { "DNS Query Audit Log", "Store all resolved hostnames, query types, and returned IPs", &g_cfg.logDns, C_GREEN },
            { "Registry Modification Log", "Monitor modifications to Run keys, services, and policies", &g_cfg.logRegistry, C_PURPLE },
            { "Authentication Event Log", "Track user logon, privilege escalation, and token use", &g_cfg.logSecurity, C_AMBER },
            { "HMAC Integrity Seals", "Sign each forensic log entry with HMAC-SHA256 signature", &g_cfg.logHmacSeal, C_GREEN },
            { "Automated Log Rotation", "Purge entries exceeding the selected retention cycle", &g_cfg.logAutoRotate, C_BLUE },
            { "Tamper-Evident Chain", "Verify cryptographic hash continuity on every engine boot", &g_cfg.logHashChain, C_CYAN },
        };
        int gridY = pnlY + pnlH + 12;
        int colW  = (mainW - 12) / 2;
        int rowH  = 46;
        for (int i = 0; i < 8; i++) {
            int cx2 = mainX + (i % 2) * (colW + 12);
            int cy2 = gridY + (i / 2) * (rowH + 8);
            DrawSetToggleCard(dc, cx2, cy2, colW, rowH, &togs[i]);
        }

        /* Real Action Button: Export Forensic Audit Log */
        int eBtnW = 320, eBtnH = 30;
        int eBtnX = mainX + 14;
        int eBtnY = gridY + 4 * (rowH + 8) + 6;
        HBRUSH eBg = CreateSolidBrush(RGB(10, 36, 60));
        HPEN   ePn = CreatePen(PS_SOLID, 1, RGB(6, 182, 212));
        HBRUSH oeb = (HBRUSH)SelectObject(dc, eBg);
        HPEN   oep = (HPEN)SelectObject(dc, ePn);
        RoundRect(dc, eBtnX, eBtnY, eBtnX + eBtnW, eBtnY + eBtnH, 6, 6);
        SelectObject(dc, oeb); SelectObject(dc, oep);
        DeleteObject(eBg); DeleteObject(ePn);
        Txt(dc, "[E] Export Forensic Audit Log to Desktop", eBtnX, eBtnY, eBtnW, eBtnH, RGB(6, 182, 212), fSm, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
        RECT eclk = { eBtnX, eBtnY, eBtnX + eBtnW, eBtnY + eBtnH };
        RegSetClick(eclk, 7, NULL, 7); /* Action 7 = Export Forensics Log */
    }
    else if (g_setSubTab == SET_NOTIF) {
        static const char *prios[] = { "All Events", "Medium & High", "Critical Only", "Silent" };
        DrawSetModeSelector(dc, mainX, contentY, mainW, "Notification Priority Threshold", "Minimum alert severity required to trigger desktop dispatch", prios, 4, &g_cfg.notifCritical);

        SetToggleDef togs[] = {
            { "Critical Threat Popups", "Immediate modal dialogs on zero-day attacks & intrusion", &g_cfg.notifCritical, C_RED },
            { "High Severity Warnings", "Notify on heuristic detections and port violations", &g_cfg.notifHigh, C_AMBER },
            { "Malware Detection Toast", "Windows notification when a malicious file is quarantined", &g_cfg.notifMalware, C_CYAN },
            { "RansomShield Alerts", "Urgent dispatch when decoy honeypots are touched", &g_cfg.notifRansomware, C_RED },
            { "Firewall Boundary Blocks", "Subtle banner when untrusted outbound sockets are dropped", &g_cfg.notifFwBlock, C_BLUE },
            { "Audible Cyber Chimes", "Play synthesized acoustic chimes on critical alerts", &g_cfg.notifSound, C_PURPLE },
            { "Desktop Toast Badges", "Display native Windows action center notifications", &g_cfg.notifDesktop, C_GREEN },
            { "Daily Security Digest", "Show 24-hour protection summary upon user login", &g_cfg.notifDailyDigest, C_CYAN },
        };
        int gridY = contentY + 68;
        int colW  = (mainW - 12) / 2;
        int rowH  = 46;
        for (int i = 0; i < 8; i++) {
            int cx2 = mainX + (i % 2) * (colW + 12);
            int cy2 = gridY + (i / 2) * (rowH + 8);
            DrawSetToggleCard(dc, cx2, cy2, colW, rowH, &togs[i]);
        }

        /* Real Action Button: Diagnostic Test Alert */
        int tBtnW = 320, tBtnH = 30;
        int tBtnX = mainX + 14;
        int tBtnY = gridY + 4 * (rowH + 8) + 6;
        HBRUSH tBg = CreateSolidBrush(RGB(40, 30, 10));
        HPEN   tPn = CreatePen(PS_SOLID, 1, RGB(245, 158, 11));
        HBRUSH otb = (HBRUSH)SelectObject(dc, tBg);
        HPEN   otp = (HPEN)SelectObject(dc, tPn);
        RoundRect(dc, tBtnX, tBtnY, tBtnX + tBtnW, tBtnY + tBtnH, 6, 6);
        SelectObject(dc, otb); SelectObject(dc, otp);
        DeleteObject(tBg); DeleteObject(tPn);
        Txt(dc, "[T] Dispatch Diagnostic Test Alert Now", tBtnX, tBtnY, tBtnW, tBtnH, RGB(251, 191, 36), fSm, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
        RECT tclk = { tBtnX, tBtnY, tBtnX + tBtnW, tBtnY + tBtnH };
        RegSetClick(tclk, 7, NULL, 4); /* Action 4 = Diagnostic Test Alert */
    }
    else if (g_setSubTab == SET_CLOUD) {
        static const char *regions[] = { "Frankfurt (eu-central)", "US-East (AWS)", "Private On-Prem" };
        static int curRegion = 0;
        DrawSetModeSelector(dc, mainX, contentY, mainW, "Supabase Cloud Endpoint", "Select cryptographic sync cluster and data sovereignty zone", regions, 3, &curRegion);

        SetToggleDef togs[] = {
            { "Cloud Identity Sync", "Synchronize user credentials and multi-device identity", &g_cfg.cloudSync, C_GREEN },
            { "Security Policy Sync", "Pull corporate firewall and WAF rules from cloud", &g_cfg.cloudSyncPolicies, C_CYAN },
            { "Global Threat Feed", "Subscribe to real-time IOCs from Kaevex ThreatCloud", &g_cfg.cloudSyncThreats, C_BLUE },
            { "Cloud Incident Vault", "Securely upload encrypted forensics for enterprise review", &g_cfg.cloudSyncLogs, C_PURPLE },
            { "Anonymous Analytics", "Contribute telemetry to improve detection algorithms", &g_cfg.cloudTelemetry, C_AMBER },
            { "Automated Crash Dumps", "Send minidump diagnostics for engine stability", &g_cfg.cloudCrashDumps, C_BLUE },
            { "End-to-End Tunnel", "TLS 1.3 encrypted channel for all cloud sync traffic", &g_cfg.cloudTlsTunnel, C_GREEN },
            { "Multi-Device Fleet Map", "Visualize linked laptops, servers, and cloud instances", &g_cfg.cloudFleetMap, C_CYAN },
        };
        int gridY = contentY + 68;
        int colW  = (mainW - 12) / 2;
        int rowH  = 46;
        for (int i = 0; i < 8; i++) {
            int cx2 = mainX + (i % 2) * (colW + 12);
            int cy2 = gridY + (i / 2) * (rowH + 8);
            DrawSetToggleCard(dc, cx2, cy2, colW, rowH, &togs[i]);
        }

        /* Real Action Button: Test Supabase Cloud */
        int cBtnW = 320, cBtnH = 30;
        int cBtnX = mainX + 14;
        int cBtnY = gridY + 4 * (rowH + 8) + 6;
        HBRUSH cBg = CreateSolidBrush(RGB(10, 44, 32));
        HPEN   cPn = CreatePen(PS_SOLID, 1, RGB(52, 211, 153));
        HBRUSH ocb = (HBRUSH)SelectObject(dc, cBg);
        HPEN   ocp = (HPEN)SelectObject(dc, cPn);
        RoundRect(dc, cBtnX, cBtnY, cBtnX + cBtnW, cBtnY + cBtnH, 6, 6);
        SelectObject(dc, ocb); SelectObject(dc, ocp);
        DeleteObject(cBg); DeleteObject(cPn);
        Txt(dc, "[C] Test Supabase Cloud Connection Now", cBtnX, cBtnY, cBtnW, cBtnH, RGB(52, 211, 153), fSm, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
        RECT cclk = { cBtnX, cBtnY, cBtnX + cBtnW, cBtnY + cBtnH };
        RegSetClick(cclk, 7, NULL, 9); /* Action 9 = Test Supabase Cloud */
    }
    else if (g_setSubTab == SET_TEAM) {
        static const char *roles[] = { "Owner", "Admin", "Analyst", "Operator", "Viewer" };
        static int curRole = 2; /* Analyst */
        DrawSetModeSelector(dc, mainX, contentY, mainW, "Assigned Role (RBAC)", "Role-based access privileges for active platform console user", roles, 5, &curRole);

        /* Permissions Matrix Table */
        int tblY = contentY + 68;
        int tblH = 260;
        HBRUSH tBg = CreateSolidBrush(C_CARD);
        HPEN   tPn = CreatePen(PS_SOLID, 1, C_BORDER);
        ob = (HBRUSH)SelectObject(dc, tBg); op = (HPEN)SelectObject(dc, tPn);
        RoundRect(dc, mainX, tblY, mainX + mainW, tblY + tblH, 8, 8);
        SelectObject(dc, ob); SelectObject(dc, op);
        DeleteObject(tBg); DeleteObject(tPn);

        /* Table Headers */
        Txt(dc, "PLATFORM PERMISSION PRIVILEGE", mainX + 16, tblY + 12, 280, 18, RGB(6, 182, 212), fSm, DT_LEFT | DT_SINGLELINE);
        Txt(dc, "VIEWER", mainX + mainW - 320, tblY + 12, 60, 18, C_DIM, fSm, DT_CENTER | DT_SINGLELINE);
        Txt(dc, "OPERATOR", mainX + mainW - 240, tblY + 12, 60, 18, C_DIM, fSm, DT_CENTER | DT_SINGLELINE);
        Txt(dc, "ANALYST", mainX + mainW - 160, tblY + 12, 60, 18, C_DIM, fSm, DT_CENTER | DT_SINGLELINE);
        Txt(dc, "ADMIN", mainX + mainW - 80, tblY + 12, 60, 18, C_DIM, fSm, DT_CENTER | DT_SINGLELINE);
        DrawLine(dc, mainX + 16, tblY + 34, mainX + mainW - 16, tblY + 34, C_BORDER2);

        static const struct { const char *perm; const char *v; const char *op; const char *an; const char *ad; } rows[] = {
            { "View SOC Dashboard & Live Heatmap", "[OK]", "[OK]", "[OK]", "[OK]" },
            { "View Forensics Trail & Incident Logs", "[OK]", "[OK]", "[OK]", "[OK]" },
            { "Terminate Malicious Host Processes", "--", "[OK]", "[OK]", "[OK]" },
            { "Deploy Decoy Traps & Trigger VSS Snapshots", "--", "--", "[OK]", "[OK]" },
            { "Modify Adaptive Firewall Rules & Ports", "--", "--", "--", "[OK]" },
            { "Reconfigure Core Antivirus & Heuristics", "--", "--", "--", "[OK]" },
            { "Manage Team Members & API Credentials", "--", "--", "--", "[OK]" },
        };
        for (int r = 0; r < 7; r++) {
            int ry = tblY + 42 + r * 30;
            Txt(dc, rows[r].perm, mainX + 16, ry, 300, 20, C_TEXT, fSm, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
            Txt(dc, rows[r].v, mainX + mainW - 320, ry, 60, 20, strcmp(rows[r].v, "[OK]")==0 ? RGB(52, 211, 153) : C_DIM2, fSm, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
            Txt(dc, rows[r].op, mainX + mainW - 240, ry, 60, 20, strcmp(rows[r].op, "[OK]")==0 ? RGB(52, 211, 153) : C_DIM2, fSm, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
            Txt(dc, rows[r].an, mainX + mainW - 160, ry, 60, 20, strcmp(rows[r].an, "[OK]")==0 ? RGB(52, 211, 153) : C_DIM2, fSm, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
            Txt(dc, rows[r].ad, mainX + mainW - 80, ry, 60, 20, strcmp(rows[r].ad, "[OK]")==0 ? RGB(52, 211, 153) : C_DIM2, fSm, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
            if (r < 6) DrawLine(dc, mainX + 16, ry + 26, mainX + mainW - 16, ry + 26, C_BORDER2);
        }
    }
    else if (g_setSubTab == SET_PRIVACY) {
        static const char *sessPols[] = { "Standard (30d)", "Enhanced (7d)", "Zero-Trust (24h)" };
        static int curSess = 1;
        DrawSetModeSelector(dc, mainX, contentY, mainW, "Session Security & Authentication", "Session expiration and multi-factor validation constraints", sessPols, 3, &curSess);

        SetToggleDef togs[] = {
            { "Two-Factor Auth (2FA)", "Require TOTP authenticator code on account login", &g_cfg.priv2Fa, C_GREEN },
            { "Hardware Passkey (FIDO2)", "Authenticate using Windows Hello, YubiKey, or Touch ID", &g_cfg.privPasskey, C_CYAN },
            { "Session Timeout Guard", "Auto-lock platform console after 15 minutes of inactivity", &g_cfg.privSessionTimeout, C_AMBER },
            { "Revoke Remote Sessions", "Instantly invalidate all linked web and mobile tokens", &g_cfg.privRevokeRemote, C_RED },
            { "Zero-Telemetry Mode", "Strictly retain all security logs on the local workstation", &g_cfg.privZeroTelemetry, C_PURPLE },
            { "Local Encrypted Vault", "Encrypt cached passwords and keys with DPAPI AES-256", &g_cfg.privEncryptedVault, C_GREEN },
            { "Anonymize Telemetry", "Strip usernames, hostnames, and private IPs from reports", &g_cfg.privAnonymize, C_BLUE },
            { "Audit Credential Access", "Log all attempts to query or modify stored API tokens", &g_cfg.privAuditCredentials, C_CYAN },
        };
        int gridY = contentY + 68;
        int colW  = (mainW - 12) / 2;
        int rowH  = 46;
        for (int i = 0; i < 8; i++) {
            int cx2 = mainX + (i % 2) * (colW + 12);
            int cy2 = gridY + (i / 2) * (rowH + 8);
            DrawSetToggleCard(dc, cx2, cy2, colW, rowH, &togs[i]);
        }
    }
    else if (g_setSubTab == SET_UPDATES) {
        static const char *freqs[] = { "Every 6 Hours", "Daily", "Weekly", "Manual Only" };
        DrawSetModeSelector(dc, mainX, contentY, mainW, "Threat Intelligence Schedule", "Automatic background update frequency for threat signatures", freqs, 4, &g_cfg.updFreq);

        SetToggleDef togs[] = {
            { "Automatic Engine Updates", "Silently update defense binaries when patches release", &g_cfg.updAuto, C_GREEN },
            { "Early Beta Flighting", "Receive experimental detection models ahead of release", &g_cfg.updBeta, C_AMBER },
            { "Real-Time Signatures", "Update cryptographic virus definitions automatically", &g_cfg.updSignatures, C_CYAN },
            { "CVE Vulnerability Feed", "Synchronize known software security advisories", &g_cfg.updCveFeed, C_BLUE },
            { "WAF Virtual Patching", "Ingest new zero-day HTTP attack pattern regexes", &g_cfg.updWafPatches, C_PURPLE },
            { "DNS Threat Feeds", "Refresh malicious sinkhole hostnames dynamically", &g_cfg.updDnsFeeds, C_GREEN },
            { "Rollback on Failure", "Restore previous stable engine build if update fails", &g_cfg.updRollback, C_CYAN },
            { "P2P LAN Distribution", "Distribute update packages across local network nodes", &g_cfg.updP2pLan, C_BLUE },
        };
        int gridY = contentY + 68;
        int colW  = (mainW - 12) / 2;
        int rowH  = 46;
        for (int i = 0; i < 8; i++) {
            int cx2 = mainX + (i % 2) * (colW + 12);
            int cy2 = gridY + (i / 2) * (rowH + 8);
            DrawSetToggleCard(dc, cx2, cy2, colW, rowH, &togs[i]);
        }

        /* Real Action Button: Check Threat DB & Engine Updates Now */
        int uBtnW = 340, uBtnH = 30;
        int uBtnX = mainX + 14;
        int uBtnY = gridY + 4 * (rowH + 8) + 6;
        HBRUSH uBg = CreateSolidBrush(RGB(10, 36, 60));
        HPEN   uPn = CreatePen(PS_SOLID, 1, RGB(6, 182, 212));
        HBRUSH oub = (HBRUSH)SelectObject(dc, uBg);
        HPEN   oup = (HPEN)SelectObject(dc, uPn);
        RoundRect(dc, uBtnX, uBtnY, uBtnX + uBtnW, uBtnY + uBtnH, 6, 6);
        SelectObject(dc, oub); SelectObject(dc, oup);
        DeleteObject(uBg); DeleteObject(uPn);
        Txt(dc, "[U] Check Threat DB & Engine Updates Now", uBtnX, uBtnY, uBtnW, uBtnH, RGB(6, 182, 212), fSm, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
        RECT uclk = { uBtnX, uBtnY, uBtnX + uBtnW, uBtnY + uBtnH };
        RegSetClick(uclk, 7, NULL, 14); /* Action 14 = Check Updates */
    }
    else if (g_setSubTab == SET_PERF) {
        static const char *pModes[] = { "Eco / Low CPU", "Balanced", "Full Power (100%)", "Game Turbo" };
        DrawSetModeSelector(dc, mainX, contentY, mainW, "Hardware Optimization Profile", "Throttle security engine CPU quotas or engage ultra-low latency", pModes, 4, &g_cfg.perfMode);

        SetToggleDef togs[] = {
            { "Dynamic CPU Throttling", "Cap security engine core utilization to 15% max", &g_cfg.perfCpuThrottle, C_CYAN },
            { "RAM Footprint Minimizer", "Periodically trim process working sets to save memory", &g_cfg.perfRamThrottle, C_BLUE },
            { "Pause Scans in Gaming", "Halt background file inspections when games are running", &g_cfg.perfPauseGaming, C_GREEN },
            { "Battery Saver Mode", "Reduce background polling frequency when unplugged", &g_cfg.perfPauseBattery, C_AMBER },
            { "Scan Only When Idle", "Defer scheduled audits until keyboard/mouse is idle", &g_cfg.perfScanIdle, C_PURPLE },
            { "1ms High-Precision Timer", "Engage multimedia timer for zero-latency game boosts", &g_cfg.perfHighPrecisionTimer, C_GREEN },
            { "DirectX GPU Acceleration", "Offload UI graphics rendering to dedicated GPU", &g_cfg.perfGpuAccel, C_CYAN },
            { "Process Priority Optimizer", "Elevate active foreground applications over background tasks", &g_cfg.perfPriorityOpt, C_GREEN },
        };
        int gridY = contentY + 68;
        int colW  = (mainW - 12) / 2;
        int rowH  = 46;
        for (int i = 0; i < 8; i++) {
            int cx2 = mainX + (i % 2) * (colW + 12);
            int cy2 = gridY + (i / 2) * (rowH + 8);
            DrawSetToggleCard(dc, cx2, cy2, colW, rowH, &togs[i]);
        }

        /* Real Action Button: Purge RAM */
        int rBtnW = 340, rBtnH = 30;
        int rBtnX = mainX + 14;
        int rBtnY = gridY + 4 * (rowH + 8) + 6;
        HBRUSH rBg = CreateSolidBrush(RGB(10, 44, 32));
        HPEN   rPn = CreatePen(PS_SOLID, 1, RGB(52, 211, 153));
        HBRUSH orb = (HBRUSH)SelectObject(dc, rBg);
        HPEN   orp = (HPEN)SelectObject(dc, rPn);
        RoundRect(dc, rBtnX, rBtnY, rBtnX + rBtnW, rBtnY + rBtnH, 6, 6);
        SelectObject(dc, orb); SelectObject(dc, op);
        DeleteObject(rBg); DeleteObject(rPn);
        Txt(dc, "[P] Purge Standby Memory & Working Sets Now", rBtnX, rBtnY, rBtnW, rBtnH, RGB(52, 211, 153), fSm, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
        RECT rclk = { rBtnX, rBtnY, rBtnX + rBtnW, rBtnY + rBtnH };
        RegSetClick(rclk, 7, NULL, 2); /* Action 2 = Purge RAM */
    }
    else if (g_setSubTab == SET_ENTERPRISE) {
        static const char *benchmarks[] = { "NIST SP 800-53", "CIS v8 Level 2", "ISO 27001", "Custom" };
        static int curBench = 0;
        DrawSetModeSelector(dc, mainX, contentY, mainW, "Compliance Benchmark Standard", "Enforce organizational compliance rulesets and audit logging", benchmarks, 4, &curBench);

        SetToggleDef togs[] = {
            { "Central Fleet Compliance", "Enforce centralized security policies across all devices", &g_cfg.entFleetCompliance, C_CYAN },
            { "Mandatory Lockdown Mode", "Permit remote administrator to trigger endpoint isolation", &g_cfg.entEnforceLockdown, C_RED },
            { "Immutable Admin Audit", "Stream administrator actions to tamper-evident SIEM", &g_cfg.entAuditAdmin, C_PURPLE },
            { "Multi-Tenant Isolation", "Segment policies by organization unit and tenant ID", &g_cfg.entMultiTenant, C_BLUE },
            { "Centralized Syslog Stream", "Forward RFC 5424 security events to remote collectors", &g_cfg.entSyslog, C_GREEN },
            { "Automated Threat Dispatch", "Trigger containment actions without local user prompt", &g_cfg.entAutoDispatch, C_AMBER },
            { "Cryptographic Attestation", "Verify boot integrity and driver signing via TPM 2.0", &g_cfg.entTpmAttest, C_GREEN },
            { "Enterprise Policy Sync", "Poll central server every 10 minutes for rule changes", &g_cfg.entPolicySync, C_BLUE },
        };
        int gridY = contentY + 68;
        int colW  = (mainW - 12) / 2;
        int rowH  = 46;
        for (int i = 0; i < 8; i++) {
            int cx2 = mainX + (i % 2) * (colW + 12);
            int cy2 = gridY + (i / 2) * (rowH + 8);
            DrawSetToggleCard(dc, cx2, cy2, colW, rowH, &togs[i]);
        }
    }
    else if (g_setSubTab == SET_ADVANCED) {
        static const char *devModes[] = { "Production (Default)", "Verbose Diagnostics", "Mock Sandbox" };
        DrawSetModeSelector(dc, mainX, contentY, mainW, "Developer Environment Mode", "Diagnostic verbosity, trace logging, and local testing sandbox", devModes, 3, &g_cfg.advDebugMode);

        /* Advanced Endpoint Controls Panel */
        int pnlY = contentY + 66;
        int pnlH = 104;
        HBRUSH pBg = CreateSolidBrush(C_CARD);
        HPEN   pPn = CreatePen(PS_SOLID, 1, C_BORDER);
        ob = (HBRUSH)SelectObject(dc, pBg); op = (HPEN)SelectObject(dc, pPn);
        RoundRect(dc, mainX, pnlY, mainX + mainW, pnlY + pnlH, 8, 8);
        SelectObject(dc, ob); SelectObject(dc, op);
        DeleteObject(pBg); DeleteObject(pPn);

        Txt(dc, "SIEM Webhook URL:", mainX + 16, pnlY + 16, 130, 22, C_DIM, fSm, DT_LEFT | DT_SINGLELINE | DT_VCENTER);
        Txt(dc, "Test Webhook:", mainX + 16, pnlY + 50, 130, 22, C_DIM, fSm, DT_LEFT | DT_SINGLELINE | DT_VCENTER);
        Txt(dc, "REST API Daemon Port:", mainX + 16, pnlY + 80, 130, 22, C_DIM, fSm, DT_LEFT | DT_SINGLELINE | DT_VCENTER);

        SetToggleDef togs[] = {
            { "Debug Console Output", "Stream internal engine diagnostics to developer console", &g_cfg.advDebugMode, C_AMBER },
            { "Local REST API Daemon", "Expose endpoint status at http://127.0.0.1:9009/api", &g_cfg.advLocalApi, C_GREEN },
            { "IPC Event Bus Tracing", "Record inter-process message bus events in memory", &g_cfg.advIpcTracing, C_CYAN },
            { "SIEM Webhook Dispatcher", "Forward JSON alert payloads to custom HTTPS endpoints", &g_cfg.advSiemWebhook, C_BLUE },
            { "ETW Kernel Tracing", "Subscribe to Microsoft-Windows-Kernel-Process events", &g_cfg.advEtwTracing, C_PURPLE },
            { "Raw Packet Capture Buffer", "Retain circular PCAP ring buffer of recent traffic", &g_cfg.advRawPcap, C_RED },
            { "API Key Protection", "Require Bearer token header for REST API requests", &g_cfg.advApiKeyProt, C_GREEN },
            { "Diagnostic Crash Logging", "Write detailed stack traces upon unexpected failures", &g_cfg.advCrashLog, C_AMBER },
        };
        int gridY = pnlY + pnlH + 12;
        int colW  = (mainW - 12) / 2;
        int rowH  = 46;
        for (int i = 0; i < 8; i++) {
            int cx2 = mainX + (i % 2) * (colW + 12);
            int cy2 = gridY + (i / 2) * (rowH + 8);
            DrawSetToggleCard(dc, cx2, cy2, colW, rowH, &togs[i]);
        }

        /* Real Action Button: Open Local REST API */
        int aBtnW = 320, aBtnH = 30;
        int aBtnX = mainX + 14;
        int aBtnY = gridY + 4 * (rowH + 8) + 6;
        HBRUSH aBg = CreateSolidBrush(RGB(10, 44, 32));
        HPEN   aPn = CreatePen(PS_SOLID, 1, RGB(52, 211, 153));
        HBRUSH oab = (HBRUSH)SelectObject(dc, aBg);
        HPEN   oap = (HPEN)SelectObject(dc, aPn);
        RoundRect(dc, aBtnX, aBtnY, aBtnX + aBtnW, aBtnY + aBtnH, 6, 6);
        SelectObject(dc, oab); SelectObject(dc, oap);
        DeleteObject(aBg); DeleteObject(aPn);
        Txt(dc, "[API] Open Local REST API in Browser", aBtnX, aBtnY, aBtnW, aBtnH, RGB(52, 211, 153), fSm, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
        RECT aclk = { aBtnX, aBtnY, aBtnX + aBtnW, aBtnY + aBtnH };
        RegSetClick(aclk, 7, NULL, 8); /* Action 8 = Open Local API */
    }
    else if (g_setSubTab == SET_RECOVERY) {
        static const char *stances[] = { "Operational Normal", "Heightened Alert", "EMERGENCY LOCKDOWN" };
        DrawSetModeSelector(dc, mainX, contentY, mainW, "Emergency Containment Stance", "Immediate system-wide isolation and lockdown procedures", stances, 3, &g_cfg.recEmergencyLockdown);

        /* Big Emergency Lockdown Action Banner */
        int lckY = contentY + 68;
        int lckH = 68;
        HBRUSH lBg = CreateSolidBrush(g_cfg.recEmergencyLockdown ? RGB(60, 10, 18) : RGB(18, 24, 38));
        HPEN   lPn = CreatePen(PS_SOLID, 2, g_cfg.recEmergencyLockdown ? RGB(239, 68, 68) : RGB(40, 60, 90));
        ob = (HBRUSH)SelectObject(dc, lBg); op = (HPEN)SelectObject(dc, lPn);
        RoundRect(dc, mainX, lckY, mainX + mainW, lckY + lckH, 8, 8);
        SelectObject(dc, ob); SelectObject(dc, op);
        DeleteObject(lBg); DeleteObject(lPn);

        Txt(dc, g_cfg.recEmergencyLockdown ? "[!] EMERGENCY LOCKDOWN ACTIVE: ALL EXTERNAL CONNECTIONS SEVERED" : "INSTANT EMERGENCY SYSTEM LOCKDOWN",
            mainX + 20, lckY + 14, mainW - 220, 20,
            g_cfg.recEmergencyLockdown ? RGB(255, 100, 100) : RGB(255, 255, 255), fMed, DT_LEFT | DT_SINGLELINE);
        Txt(dc, "Isolate workstation from LAN and Internet while retaining local defense sentinels and VSS rollback.",
            mainX + 20, lckY + 36, mainW - 220, 16, RGB(140, 165, 195), fSm, DT_LEFT | DT_SINGLELINE);

        int lbtnW = 160, lbtnH = 34;
        int lbtnX = mainX + mainW - lbtnW - 16;
        int lbtnY = lckY + (lckH - lbtnH) / 2;

        HBRUSH lbBg = CreateSolidBrush(g_cfg.recEmergencyLockdown ? RGB(180, 20, 30) : RGB(40, 15, 20));
        HPEN   lbPn = CreatePen(PS_SOLID, 1, RGB(239, 68, 68));
        ob = (HBRUSH)SelectObject(dc, lbBg); op = (HPEN)SelectObject(dc, lbPn);
        RoundRect(dc, lbtnX, lbtnY, lbtnX + lbtnW, lbtnY + lbtnH, 6, 6);
        SelectObject(dc, ob); SelectObject(dc, op);
        DeleteObject(lbBg); DeleteObject(lbPn);

        Txt(dc, g_cfg.recEmergencyLockdown ? "DISENGAGE LOCK" : "ENGAGE LOCKDOWN",
            lbtnX, lbtnY, lbtnW, lbtnH, RGB(255, 255, 255), fMed, DT_CENTER | DT_VCENTER | DT_SINGLELINE);

        RECT lckBtnRc = { lbtnX, lbtnY, lbtnX + lbtnW, lbtnY + lbtnH };
        RegSetClick(lckBtnRc, 7, NULL, 10); /* Action 10 = Toggle Emergency Lockdown */

        SetToggleDef togs[] = {
            { "Emergency Network Lockdown", "Sever all external connections except DNS and Kaevex Cloud", &g_cfg.recEmergencyLockdown, C_RED },
            { "Safe Mode / Minimal Defense", "Disable heavy heuristic engines for diagnostic troubleshooting", &g_cfg.recSafeMode, C_AMBER },
        };
        int gridY = lckY + lckH + 12;
        int colW  = (mainW - 12) / 2;
        int rowH  = 46;
        for (int i = 0; i < 2; i++) {
            int cx2 = mainX + i * (colW + 12);
            int cy2 = gridY;
            DrawSetToggleCard(dc, cx2, cy2, colW, rowH, &togs[i]);
        }

        typedef struct {
            const char *title;
            const char *desc;
            const char *btnLabel;
            int actId;
            COLORREF accent;
            COLORREF btnBg;
            COLORREF btnBorder;
        } RecActionCard;

        static const RecActionCard recCards[6] = {
            { "Restore Security Baseline", "Revert all defense engines and shields to hardened factory baseline", "Baseline", 4, RGB(6, 182, 212), RGB(10, 36, 60), RGB(6, 182, 212) },
            { "Reset Windows Firewall", "Clear all rules and restore hardened inbound & outbound defaults", "Reset FW", 11, RGB(239, 68, 68), RGB(40, 20, 20), RGB(239, 68, 68) },
            { "Purge Quarantined Storage", "Permanently delete all locked threat files from secure quarantine vault", "Purge Vault", 12, RGB(239, 68, 68), RGB(40, 20, 20), RGB(239, 68, 68) },
            { "Create VSS Restore Snapshot", "Take an immutable Volume Shadow Copy snapshot of system state", "Create VSS", 6, RGB(147, 51, 234), RGB(30, 16, 50), RGB(168, 85, 247) },
            { "Re-Deploy Decoy Honeypots", "Regenerate 32 ransomware canary bait traps across user profile paths", "Deploy Traps", 5, RGB(16, 185, 129), RGB(10, 44, 32), RGB(52, 211, 153) },
            { "Factory Reset Platform", "Wipe all configurations, clear registry keys, and restore defaults", "Factory Reset", 13, RGB(245, 158, 11), RGB(40, 28, 10), RGB(245, 158, 11) },
        };

        int rgridY = gridY + rowH + 10;
        int rcardH = 50;
        for (int i = 0; i < 6; i++) {
            int rx = mainX + (i % 2) * (colW + 12);
            int ry = rgridY + (i / 2) * (rcardH + 8);
            const RecActionCard *rc = &recCards[i];

            /* Background card */
            HBRUSH cbg = CreateSolidBrush(C_CARD);
            HPEN   cpn = CreatePen(PS_SOLID, 1, C_BORDER);
            ob = (HBRUSH)SelectObject(dc, cbg); op = (HPEN)SelectObject(dc, cpn);
            RoundRect(dc, rx, ry, rx + colW, ry + rcardH, 8, 8);
            SelectObject(dc, ob); SelectObject(dc, op);
            DeleteObject(cbg); DeleteObject(cpn);

            /* Left accent */
            HBRUSH accBr = CreateSolidBrush(rc->accent);
            RECT accR = { rx + 2, ry + 4, rx + 5, ry + rcardH - 4 };
            FillRect(dc, &accR, accBr);
            DeleteObject(accBr);

            int actBtnW = 95, actBtnH = 26;
            int actBtnX = rx + colW - actBtnW - 10;
            int actBtnY = ry + (rcardH - actBtnH) / 2;

            /* Text */
            Txt(dc, rc->title, rx + 12, ry + 7, colW - actBtnW - 24, 16, C_TEXT, fSm, DT_LEFT | DT_SINGLELINE | DT_NOPREFIX);
            Txt(dc, rc->desc,  rx + 12, ry + 25, colW - actBtnW - 24, 14, C_DIM, fSm, DT_LEFT | DT_SINGLELINE | DT_NOPREFIX);

            /* Button */
            HBRUSH bbg = CreateSolidBrush(rc->btnBg);
            HPEN   bpn = CreatePen(PS_SOLID, 1, rc->btnBorder);
            ob = (HBRUSH)SelectObject(dc, bbg); op = (HPEN)SelectObject(dc, bpn);
            RoundRect(dc, actBtnX, actBtnY, actBtnX + actBtnW, actBtnY + actBtnH, 6, 6);
            SelectObject(dc, ob); SelectObject(dc, op);
            DeleteObject(bbg); DeleteObject(bpn);

            Txt(dc, rc->btnLabel, actBtnX, actBtnY, actBtnW, actBtnH, rc->accent, fSm, DT_CENTER | DT_VCENTER | DT_SINGLELINE);

            RECT clkR = { actBtnX, actBtnY, actBtnX + actBtnW, actBtnY + actBtnH };
            RegSetClick(clkR, 7, NULL, rc->actId);
        }
    }
    else if (g_setSubTab == SET_ABOUT) {
        int abtY = contentY;
        int abtH = 390;
        HBRUSH aBg = CreateSolidBrush(C_PANEL);
        HPEN   aPn = CreatePen(PS_SOLID, 1, C_BORDER);
        ob = (HBRUSH)SelectObject(dc, aBg); op = (HPEN)SelectObject(dc, aPn);
        RoundRect(dc, mainX, abtY, mainX + mainW, abtY + abtH, 8, 8);
        SelectObject(dc, ob); SelectObject(dc, op);
        DeleteObject(aBg); DeleteObject(aPn);

        Txt(dc, "KAEVEX UNIFIED CYBER DEFENSE PLATFORM", mainX + 24, abtY + 16, mainW - 48, 24, RGB(6, 182, 212), fMed, DT_LEFT | DT_SINGLELINE);
        Txt(dc, "Enterprise Edition v1.0.0 -- Autonomous On-Device & Cloud Intelligence", mainX + 24, abtY + 42, mainW - 48, 16, C_DIM, fSm, DT_LEFT | DT_SINGLELINE);
        DrawLine(dc, mainX + 24, abtY + 66, mainX + mainW - 24, abtY + 66, C_BORDER2);

        static const char *infoSpecs[] = {
            "Architecture:            Pure Win32 C + Native NT Subsystems (Zero-Driver User-Mode Architecture)",
            "Anti-Cheat Compliance:   100% Compatible with EAC, BattlEye, Riot Vanguard, Ricochet, and VAC",
            "Defense Engines:         8 Active Engines (Antivirus, NetGuard, CVE, RansomShield, Firewall, WAF, Sandbox, Hub)",
            "AI Copilot Integration:  Together AI (DeepSeek-V4-Pro) + Groq Cloud (Llama-3.3-70B) + Local On-Device Fallback",
            "Cryptographic Seals:     HMAC-SHA256 Tamper-Evident Append-Only Forensic Audit Trail",
            "Cloud Backend:           Supabase Cloud Federation + Realtime Sync Engine",
            "Digital Authenticity:    Binary Hash Verified  |  Build Date: September 2026",
            "Legal & Licensing:       Enterprise Commercial Edition -- All Rights Reserved to Kaevex Security Operations"
        };
        for (int s = 0; s < 8; s++) {
            Txt(dc, infoSpecs[s], mainX + 24, abtY + 76 + s * 26, mainW - 48, 20, C_TEXT, fSm, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
        }

        /* Official Portal & Documentation Button (User Request: kaevex.com/info/) */
        int wBtnW = mainW - 48;
        int wBtnH = 38;
        int wBtnX = mainX + 24;
        int wBtnY = abtY + abtH - wBtnH - 18;

        HBRUSH wbBg = CreateSolidBrush(RGB(10, 36, 60));
        HPEN   wbPn = CreatePen(PS_SOLID, 2, RGB(6, 182, 212));
        HBRUSH owb = (HBRUSH)SelectObject(dc, wbBg);
        HPEN   owp = (HPEN)SelectObject(dc, wbPn);
        RoundRect(dc, wBtnX, wBtnY, wBtnX + wBtnW, wBtnY + wBtnH, 8, 8);
        SelectObject(dc, owb); SelectObject(dc, owp);
        DeleteObject(wbBg); DeleteObject(wbPn);

        Txt(dc, "[WEB] Open Official Platform & Architecture Portal -> https://kaevex.com/info/",
            wBtnX, wBtnY, wBtnW, wBtnH, RGB(6, 182, 212), fMed, DT_CENTER | DT_VCENTER | DT_SINGLELINE);

        RECT wbRc = { wBtnX, wBtnY, wBtnX + wBtnW, wBtnY + wBtnH };
        RegSetClick(wbRc, 6, NULL, 0); /* Action 6 = Open https://kaevex.com/info/ */
    }
}

