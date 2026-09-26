/* --- Settings Sidebar Category Metadata ----------------------------------- */
typedef struct {
    int id;
    const char *group;
    const char *icon;
    const char *title;
    const char *subTitle;
} SetCatMeta;

static const SetCatMeta g_catMeta[SET_CAT_COUNT] = {
    { SET_GENERAL,    "PREFERENCES",       "[SYS]", "General Preferences",    "UI themes, scaling, animations, notification sounds, and startup options." },
    { SET_PERF,       "PREFERENCES",       "[PRF]", "Performance & Gaming",   "Resource quotas, dynamic CPU throttling, battery saver, and gaming boost." },
    { SET_NOTIF,      "PREFERENCES",       "[NTF]", "Alerts & Notifications", "Multi-channel priority dispatch, toast popups, acoustic chimes, and routing." },
    { SET_UPDATES,    "PREFERENCES",       "[UPD]", "Software & Intelligence", "Signature catalogs, CVE databases, WAF patterns, and engine version management." },

    { SET_PROTECTION, "SECURITY SHIELDS",  "[PRO]", "Protection Center",      "Behavioral heuristics, cloud intelligence, and kernel-level self-defense." },
    { SET_AV,         "SECURITY SHIELDS",  "[AV ]", "Antivirus Core",         "Cryptographic SHA-256 signatures, 5-layer heuristic scanner & PE analysis." },
    { SET_NET,        "SECURITY SHIELDS",  "[NET]", "NetGuard Traffic",       "L4/L7 socket classification, C2 beacon pattern analysis, and DNS sinkhole." },
    { SET_FW,         "SECURITY SHIELDS",  "[FW ]", "Adaptive Firewall",      "Dynamic inbound/outbound packet filtering, stealth mode, and port policies." },
    { SET_WAF,        "SECURITY SHIELDS",  "[WAF]", "WebGuard WAF",           "18 attack vector inspection: SQLi, XSS, RCE, LFI, RFI, SSRF & bot throttling." },
    { SET_RANSOM,     "SECURITY SHIELDS",  "[RS ]", "RansomShield Traps",     "Zero-driver honeypot sentinels, mass-rename detection, and VSS rollback." },
    { SET_SBX,        "SECURITY SHIELDS",  "[SBX]", "SmartSandbox",           "AppContainer containment, Job Object hard limits, and behavioral detours." },
    { SET_APPCTRL,    "SECURITY SHIELDS",  "[APP]", "Application Control",    "Execution allowlisting, code-signature verification, and zero-trust policies." },

    { SET_ENGINES,    "OPERATIONS & CLOUD","[ENG]", "Engine Management",      "Operational lifecycle, health status, and live computing load for 8 engines." },
    { SET_AISOC,      "OPERATIONS & CLOUD","[AI ]", "AI SOC Analyst",         "Autonomous threat correlation, natural language summaries, and copilot." },
    { SET_DEVICE,     "OPERATIONS & CLOUD","[DEV]", "Device Control",         "USB storage authorization, hardware port locks, and peripheral blocking." },
    { SET_FORENSICS,  "OPERATIONS & CLOUD","[FOR]", "Forensics & Logs",        "HMAC-SHA256 telemetry, compliance retention cycles, and multi-format exports." },
    { SET_CLOUD,      "OPERATIONS & CLOUD","[CLD]", "Cloud & Supabase",       "Global threat intelligence federation, cloud policy deployment, and sync." },
    { SET_TEAM,       "OPERATIONS & CLOUD","[TEM]", "Team & Permissions",     "Role-based access control (RBAC): Owner, Admin, Analyst, Operator, Viewer." },

    { SET_PRIVACY,    "ENTERPRISE & OPS",  "[PRV]", "Security & Privacy",     "Multi-factor authentication (2FA), biometric passkeys, and data governance." },
    { SET_ENTERPRISE, "ENTERPRISE & OPS",  "[ENT]", "Enterprise Policies",     "Multi-tenant governance, organization compliance profiles, and fleet control." },
    { SET_ADVANCED,   "ENTERPRISE & OPS",  "[ADV]", "Developer & API",        "Local REST daemon (port 9009), SIEM webhooks, and developer diagnostics." },
    { SET_RECOVERY,   "ENTERPRISE & OPS",  "[REC]", "Recovery & Lockdown",    "Instant boundary severing, quarantine management, and baseline reset." },
    { SET_ABOUT,      "ENTERPRISE & OPS",  "[INF]", "About Kaevex Platform",  "Platform architecture, engine integrity, and verified digital signatures." }
};

/* Interactive Click Registry for Settings */
typedef struct {
    RECT rc;
    int  actionType; /* 1=ToggleBool, 2=SetInt, 3=Save, 4=Reset, 5=Custom */
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



static void PaintSet(HDC dc, int cx, int cy, int cw, int ch) {
    g_setClickCnt = 0; /* Reset interactive click registry for this paint frame */

    /* === Left Inner Sidebar === */
    int sideW = 205;
    int sideH = ch - 22;
    int sideX = cx + MRG;
    int sideY = cy + 6;

    /* Sidebar Background Panel */
    HBRUSH sBg = CreateSolidBrush(C_SIDEBAR);
    HPEN   sPn = CreatePen(PS_SOLID, 1, C_BORDER);
    HBRUSH ob  = (HBRUSH)SelectObject(dc, sBg);
    HPEN   op  = (HPEN)SelectObject(dc, sPn);
    RoundRect(dc, sideX, sideY, sideX + sideW, sideY + sideH, 8, 8);
    SelectObject(dc, ob); SelectObject(dc, op);
    DeleteObject(sBg); DeleteObject(sPn);

    /* Sidebar Search / Title Banner */
    Txt(dc, "  CONFIGURATION CENTER", sideX + 8, sideY + 8, sideW - 16, 20, RGB(6, 182, 212), fMed, DT_LEFT | DT_SINGLELINE | DT_VCENTER);
    DrawLine(dc, sideX + 8, sideY + 30, sideX + sideW - 8, sideY + 30, C_BORDER2);

    /* Categories List */
    int itemY = sideY + 34;
    const char *lastGroup = "";
    int itemH = 22;

    for (int i = 0; i < SET_CAT_COUNT; i++) {
        const SetCatMeta *m = &g_catMeta[i];

        /* Group Header */
        if (strcmp(m->group, lastGroup) != 0) {
            lastGroup = m->group;
            Txt(dc, m->group, sideX + 12, itemY + 2, sideW - 24, 15, C_DIM2, fSm, DT_LEFT | DT_SINGLELINE | DT_VCENTER);
            itemY += 18;
        }

        BOOL isSel = (g_setSubTab == m->id);
        RECT iRc = { sideX + 6, itemY, sideX + sideW - 6, itemY + itemH };

        if (isSel) {
            /* Active glowing pill */
            HBRUSH aBg = CreateSolidBrush(C_PANEL2);
            HPEN   aPn = CreatePen(PS_SOLID, 1, RGB(6, 182, 212));
            ob = (HBRUSH)SelectObject(dc, aBg);
            op = (HPEN)SelectObject(dc, aPn);
            RoundRect(dc, iRc.left, iRc.top, iRc.right, iRc.bottom, 6, 6);
            SelectObject(dc, ob); SelectObject(dc, op);
            DeleteObject(aBg); DeleteObject(aPn);

            /* Left cyan indicator strip */
            HBRUSH strBr = CreateSolidBrush(RGB(6, 182, 212));
            RECT strR = { iRc.left + 2, iRc.top + 4, iRc.left + 5, iRc.bottom - 4 };
            FillRect(dc, &strR, strBr);
            DeleteObject(strBr);
        }

        /* Icon badge + Category label */
        char catLine[128];
        snprintf(catLine, sizeof(catLine), "%s  %s", m->icon, m->title);
        Txt(dc, catLine, iRc.left + 12, iRc.top, iRc.right - iRc.left - 16, itemH,
            isSel ? RGB(255, 255, 255) : C_TEXT2, fSm, DT_LEFT | DT_SINGLELINE | DT_VCENTER | DT_NOPREFIX);

        /* Register sidebar item click */
        RegSetClick(iRc, 5, NULL, m->id);

        itemY += itemH + 2;
    }

    /* === Right Main Content Area === */
    int mainX = sideX + sideW + 14;
    int mainY = sideY;
    int mainW = cw - sideW - MRG - 14;
    int mainH = sideH;

    const SetCatMeta *cur = &g_catMeta[0];
    for (int i = 0; i < SET_CAT_COUNT; i++) {
        if (g_catMeta[i].id == g_setSubTab) {
            cur = &g_catMeta[i];
            break;
        }
    }

    /* Header Bar */
    char hdrTitle[128];
    snprintf(hdrTitle, sizeof(hdrTitle), "%s  %s", cur->icon, cur->title);
    Txt(dc, hdrTitle, mainX, mainY + 2, mainW - 220, 22, C_TEXT, fMed, DT_LEFT | DT_SINGLELINE | DT_VCENTER | DT_NOPREFIX);
    Txt(dc, cur->subTitle, mainX, mainY + 26, mainW - 220, 16, C_DIM, fSm, DT_LEFT | DT_SINGLELINE | DT_VCENTER);

    /* Top Action Buttons */
    int btnW = 120, btnH = 26;
    int btn1X = mainX + mainW - btnW - 90;
    int btn2X = mainX + mainW - 80;
    int btnY  = mainY + 6;

    /* Save Changes Button */
    HBRUSH b1 = CreateSolidBrush(RGB(6, 44, 34));
    HPEN   p1 = CreatePen(PS_SOLID, 1, RGB(16, 185, 129));
    ob = (HBRUSH)SelectObject(dc, b1); op = (HPEN)SelectObject(dc, p1);
    RoundRect(dc, btn1X, btnY, btn1X + btnW, btnY + btnH, 6, 6);
    SelectObject(dc, ob); SelectObject(dc, op);
    DeleteObject(b1); DeleteObject(p1);
    Txt(dc, "[S] Save Changes", btn1X, btnY, btnW, btnH, RGB(52, 211, 153), fSm, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
    RECT saveRc = { btn1X, btnY, btn1X + btnW, btnY + btnH };
    RegSetClick(saveRc, 3, NULL, 0);

    /* Defaults Button */
    HBRUSH b2 = CreateSolidBrush(C_PANEL2);
    HPEN   p2 = CreatePen(PS_SOLID, 1, C_BORDER);
    ob = (HBRUSH)SelectObject(dc, b2); op = (HPEN)SelectObject(dc, p2);
    RoundRect(dc, btn2X, btnY, btn2X + 80, btnY + btnH, 6, 6);
    SelectObject(dc, ob); SelectObject(dc, op);
    DeleteObject(b2); DeleteObject(p2);
    Txt(dc, "Defaults", btn2X, btnY, 80, btnH, C_TEXT2, fSm, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
    RECT defRc = { btn2X, btnY, btn2X + 80, btnY + btnH };
    RegSetClick(defRc, 4, NULL, 0);

    DrawLine(dc, mainX, mainY + 48, mainX + mainW, mainY + 48, C_BORDER2);

    int contentY = mainY + 58;

    /* === Render Dynamic Content for Current SubTab === */
    if (g_setSubTab == SET_GENERAL) {
        static const char *themes[] = { "Cyber Dark (Default)", "Dark OLED", "Slate Navy", "Midnight Crimson", "Light Minimal" };
        DrawSetModeSelector(dc, mainX, contentY, mainW, "Theme Palette Mode", "Choose interface styling to match your SOC environment (Default: Cyber Dark)", themes, 5, &g_cfg.theme);

        SetToggleDef togs[] = {
            { "Smooth Cyber Animations", "GPU-accelerated interface transitions & fade effects", &g_cfg.animations, C_CYAN },
            { "Ambient Glow Effects", "Neon luminescent accents & status halos across panels", &g_cfg.glowEffects, C_CYAN },
            { "Tactile Sound Effects", "Audible feedback clicks on interactive control toggles", &g_cfg.soundEffects, C_BLUE },
            { "Critical Threat Chimes", "Audible sirens on active malware detections & breaches", &g_cfg.notifSounds, C_RED },
            { "Start with Windows", "Arm background protection automatically on OS boot", &g_cfg.startWithWindows, C_GREEN },
            { "Minimize to System Tray", "Keep background shields running when window is closed", &g_cfg.minimizeToTray, C_GREEN },
            { "Confirm Before Exit", "Display verification dialog before shutting down Kaevex", &g_cfg.confirmExit, C_AMBER },
            { "High-Density Compact Layout", "Increase data density for professional SOC multi-monitor ops", &g_cfg.compactLayout, C_PURPLE },
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
    else if (g_setSubTab == SET_PROTECTION) {
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
        static const char *engHealth[] = { "All 8 Online (Optimal)", "Auto-Heal Active" };
        static int curHealth = 0;
        DrawSetModeSelector(dc, mainX, contentY, mainW, "Defense Engines Fleet Status", "Real-time health monitoring and process control for core subsystems", engHealth, 2, &curHealth);

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
            HBRUSH dotBr = CreateSolidBrush(g_eng[i].run ? RGB(16, 185, 129) : RGB(239, 68, 68));
            HPEN   dotPn = CreatePen(PS_SOLID, 1, g_eng[i].run ? RGB(52, 211, 153) : RGB(248, 113, 113));
            ob = (HBRUSH)SelectObject(dc, dotBr); op = (HPEN)SelectObject(dc, dotPn);
            Ellipse(dc, ex + 12, ey + 12, ex + 22, ey + 22);
            SelectObject(dc, ob); SelectObject(dc, op);
            DeleteObject(dotBr); DeleteObject(dotPn);

            Txt(dc, g_eng[i].name, ex + 28, ey + 8, colW - 130, 16, C_TEXT, fMed, DT_LEFT | DT_SINGLELINE | DT_NOPREFIX);
            Txt(dc, g_eng[i].detail, ex + 28, ey + 26, colW - 130, 14, C_DIM, fSm, DT_LEFT | DT_SINGLELINE | DT_NOPREFIX);

            char ldStr[64];
            snprintf(ldStr, sizeof(ldStr), "Load: %d%%  |  v%s", g_eng[i].load, g_eng[i].version);
            Txt(dc, ldStr, ex + 28, ey + 42, colW - 130, 14, RGB(6, 182, 212), fSm, DT_LEFT | DT_SINGLELINE);

            /* Action button [ RESTART / STOP ] */
            int abW = 80, abH = 26;
            int abX = ex + colW - abW - 12;
            int abY = ey + (rowH - abH) / 2;

            HBRUSH abBg = CreateSolidBrush(C_PANEL2);
            HPEN   abPn = CreatePen(PS_SOLID, 1, C_BORDER);
            ob = (HBRUSH)SelectObject(dc, abBg); op = (HPEN)SelectObject(dc, abPn);
            RoundRect(dc, abX, abY, abX + abW, abY + abH, 6, 6);
            SelectObject(dc, ob); SelectObject(dc, op);
            DeleteObject(abBg); DeleteObject(abPn);

            Txt(dc, g_eng[i].run ? "Restart" : "Start", abX, abY, abW, abH,
                C_CYAN, fSm, DT_CENTER | DT_VCENTER | DT_SINGLELINE);

            RECT abRc = { abX, abY, abX + abW, abY + abH };
            RegSetClick(abRc, 1, (void*)&g_eng[i].run, 0);
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

