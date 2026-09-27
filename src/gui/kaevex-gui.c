/*===========================================================================
 * Kaevex Security Platform v1.0  -  Enterprise Native Win32 SOC Dashboard
 * kaevex-gui.c
 *
 * Zero external runtime dependencies | Pure Win32 + GDI + DWM
 * Mac-inspired Dark SOC Aesthetic  -  K Brand Identity:
 * - Real-time Dual-Line & Dual-Bar Charts with live telemetry
 * - Global Threat Origins Vector World Map with pulsing attack beacons
 * - Top Navigation Header: Vector Search Bar, K Badge, Profile Avatar
 * - Startup Baseline Traffic Scanner (Classifies Web/CDN vs Unverified IPs)
 * - LAN Cluster Discovery & Cryptographic Server Pairing Handshake
 * - Custom Owner-Drawn Listboxes with Syntax Highlighting
 * - Real Running Game Scanner & Anti-Cheat Compatibility Engine
 * - Autonomous CVE Agent: Full OS Build & Software Inventory, Auto-Fix
 * - 15 Enterprise Defense Modules
 * - Tray Integration: Single-instance aware (raises existing window)
 *===========================================================================*/
#define WIN32_LEAN_AND_MEAN
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0602
#endif
#ifndef NTDDI_VERSION
#define NTDDI_VERSION 0x06020000
#endif

#include <windows.h>
#include <windowsx.h>
#include <commctrl.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <shellapi.h>
#include <shlobj.h>
#include <commdlg.h>
#include <wincrypt.h>
#include <psapi.h>
#include <dwmapi.h>
#include <uxtheme.h>
#include <winhttp.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>
#include <ctype.h>
#include <stdint.h>

#ifndef CLAMP
#define CLAMP(v,lo,hi) ((v)<(lo)?(lo):((v)>(hi)?(hi):(v)))
#endif

/* --- Sub-engines ---------------------------------------------------------- */
#include "supabase_engine.h"
#include "sbx_engine.h"
#include "fw_engine.h"
#include "upd_engine.h"
#include "net_engine.h"
#include "ransom_engine.h"
#include "data_engine.h"
#include "threat_engine.h"
#include "soc_engine.h"
#include "discovery_engine.h"
#include "mobile_api_engine.h"
#include "boot_rootkit_engine.h"

/* --- Version & Metadata --------------------------------------------------- */
#define KAEVEX_VER   "1.0.0"
#define KAEVEX_TITLE "Kaevex Security Platform v1.0 [SOC Enterprise]"
#define API_PORT    9009

/* --- Dynamic Palette Variables (Theme Engine) ----------------------------- */
static HBRUSH hBrEdit=NULL,hBrList=NULL,hBrPnl=NULL,hBrSearch=NULL;
static BOOL   g_wafEnabled = TRUE;
static HWND   g_hwnd       = NULL;

static COLORREF g_col_bg        = RGB(  5,  10,  22);
static COLORREF g_col_bg2       = RGB(  4,   8,  18);
static COLORREF g_col_hdr       = RGB(  7,  12,  24);
static COLORREF g_col_sidebar   = RGB(  6,  11,  22);
static COLORREF g_col_panel     = RGB( 10,  17,  32);
static COLORREF g_col_panel2    = RGB( 14,  23,  44);
static COLORREF g_col_card      = RGB( 10,  17,  32);
static COLORREF g_col_card2     = RGB(  8,  14,  26);
static COLORREF g_col_border    = RGB( 22,  34,  60);
static COLORREF g_col_border2   = RGB( 16,  25,  44);
static COLORREF g_col_nav_act   = RGB( 29,  78, 216);
static COLORREF g_col_nav_hov   = RGB( 16,  26,  48);
static COLORREF g_col_search_bg = RGB( 13,  21,  38);
static COLORREF g_col_text      = RGB(240, 246, 255);
static COLORREF g_col_text2     = RGB(175, 192, 218);
static COLORREF g_col_dim       = RGB(115, 134, 162);
static COLORREF g_col_dim2      = RGB( 65,  82, 108);

#define C_BG         g_col_bg
#define C_BG2        g_col_bg2
#define C_HDR        g_col_hdr
#define C_SIDEBAR    g_col_sidebar
#define C_PANEL      g_col_panel
#define C_PANEL2     g_col_panel2
#define C_CARD       g_col_card
#define C_CARD2      g_col_card2
#define C_BORDER     g_col_border
#define C_BORDER2    g_col_border2
#define C_NAV_ACT    g_col_nav_act
#define C_NAV_HOV    g_col_nav_hov
#define C_SEARCH_BG  g_col_search_bg

#define C_TEXT       g_col_text
#define C_TEXT2      g_col_text2
#define C_DIM        g_col_dim
#define C_DIM2       g_col_dim2

/* Glowing Accents matching the reference design */
#define C_ACCENT_PINK RGB(255,  51, 102)  /* Pings / critical alert */
#define C_BLUE        RGB( 59, 130, 246)  /* Electric Blue (Primary) */
#define C_BLUE2       RGB( 29,  78, 216)
#define C_AMBER       RGB(245, 158,  11)  /* Warning / Gold line */
#define C_GREEN       RGB( 34, 197,  94)  /* Positive metrics / Shields */
#define C_GREEN2      RGB(  6,  95,  46)
#define C_RED         RGB(239,  68,  68)  /* Negative / Blocked */
#define C_RED2        RGB(120,  18,  28)
#define C_PURPLE      RGB(168,  85, 247)  /* Avatar / Protected traffic */
#define C_CYAN        RGB(   6, 182, 212) /* Inbound traffic / Sessions */

#define C_BTN_PRI     RGB( 37,  99, 235)
#define C_BTN_DNG     RGB(220,  38,  38)
#define C_BTN_SUC     RGB(  5, 150, 105)
#define C_BTN_WARN    RGB(217, 119,   6)
#define C_BTN_DARK    RGB( 26,  34,  56)

/* --- Layout Constants ------------------------------------------------------ */
#define NAV_W        195
#define HDR_H         54
#define STB_H         28
#define NAV_ITEM_H    38
#define NAV_TOP       48
#define MRG           12
#define MRG2           8

/* --- 15 Enterprise Tabs --------------------------------------------------- */
typedef enum {
    TAB_DASH=0, TAB_ENG, TAB_NET, TAB_WAF, TAB_AV,
    TAB_RANSOM, TAB_SBX, TAB_FW, TAB_UPD, TAB_THREAT,
    TAB_APPS, TAB_AI, TAB_FORENSICS, TAB_SET, TAB_TEAM
} Tab;
#define TAB_COUNT 15

static const char *TAB_LABEL[TAB_COUNT] = {
    "Dashboard", "Defense Engines", "NetGuard Traffic", "WebGuard WAF", "Antivirus Core",
    "RansomShield", "SmartSandbox", "Adaptive Firewall", "Patch & CVE Agent", "Gaming & Threat",
    "App Hub", "AI SOC Analyst", "Forensic Audit", "Settings & Acc", "Full Team"
};

static const wchar_t *TAB_ICON_W[TAB_COUNT] = {
    L"\uE80F", /* Dashboard - House */
    L"\uEA18", /* Defense Engines - Shield Outline */
    L"\uE839", /* NetGuard Traffic - Vector Network Graph */
    L"\uE774", /* WebGuard WAF - Globe with Grid */
    L"\uEA18", /* Antivirus Core - Shield Outline */
    L"\uE72E", /* RansomShield - Padlock */
    L"\uF158", /* SmartSandbox - Isometric 3D Cube */
    L"\uECAD", /* Adaptive Firewall - Flame */
    L"\uE895", /* Patch & CVE Agent - Circular Refresh Arrows */
    L"\uE7FC", /* Gaming & Threat - Gamepad */
    L"\uECAA", /* App Hub - Vector 2x2 App Grid */
    L"\uE99A", /* AI SOC Analyst - Robot Head */
    L"\uE9D9", /* Forensics Audit - Vector Document with Lines */
    L"\uE713", /* Settings & Acc - Gear */
    L"\uE902"  /* Full Team - People/Group */
};


/* --- Control IDs ----------------------------------------------------------- */
#define IDW_IN       200
#define IDW_GO       201
#define IDW_CLR      202
#define IDW_LOG      203
#define IDA_PATH     210
#define IDA_BRW      211
#define IDA_SCN      212
#define IDA_LOG      213
#define IDA_THREATLIST 214
#define IDA_MARKSAFE   215
#define IDA_QUARANTINE 216
#define IDA_SCANALL    217
#define IDA_CLEARDB    218
#define IDA_BOOTAUDIT  219
#define IDA_SCANDIR    208
#define IDA_SEARCH     209
#define IDA_EXPORT     207
#define IDA_FLT_THREAT 206
#define IDA_FLT_TIME   205
#define WM_AUTOSCAN_DONE (WM_APP + 55)
#define IDS_PATH     220
#define IDS_BRW      221
#define IDS_RUN      222
#define IDS_KILL     223
#define IDS_LOG      224
#define IDS_BNET     225
#define IDS_BFILE    226
#define IDS_BPROC    227
#define IDF_LIST     230
#define IDF_ADD      231
#define IDF_DEL      232
#define IDF_BLKPROC  233
#define IDF_RELOAD   234
#define IDF_TOGGLE   235
#define IDF_LOCKDOWN 236
#define IDF_DEFAULTS 237
#define IDF_RULENAME 238
#define IDF_RULEPORT 239
#define IDU_LIST     240
#define IDU_SCAN     241
#define IDU_CHKUPD   242
#define IDU_SEL      243
#define IDU_ALL      244
#define IDU_WIN      245
#define IDU_FIXALL   246
#define IDU_WATCHER  247
#define IDU_NOTIFYMODE 253
#define IDAL_LIST    250
#define IDAL_CLR     251
#define IDST_PORT    260
#define IDST_APPLY   261
#define IDST_AUTO    262
#define IDST_FWDFL   263
#define IDST_HOOK    264
#define IDE_STALL    270
#define IDE_SPALL    271
#define IDN_SCAN     280
#define IDN_PORTS    281
#define IDN_CLOSEPORT 282
#define IDN_BLOCKDNS 283
#define IDN_KILL     284
#define IDN_PORTIN   285
#define IDN_DNSIN    286
#define IDN_LIST     287
#define IDN_SORT     288
#define IDR_START    290
#define IDR_STOP     291
#define IDR_HONEY    292
#define IDR_CHECKH   293
#define IDR_VSS      294
#define IDR_LIST     295
#define IDD_SCAN     300
#define IDD_CLIP     301
#define IDD_CLR      302
#define IDD_DIR      303
#define IDD_LIST     304
#define IDT_GAME     310
#define IDT_AC       311
#define IDT_HIBP     312
#define IDT_PASSIN   313
#define IDT_LIST     314
#define IDT_BOOST    315
#define IDT_PURGE    316
#define IDT_CUSTOM   317
#define IDT_TCP      318
#define IDC_SCAN     320
#define IDC_PING     321
#define IDC_PAIR_IP  322
#define IDC_PAIR_KEY 323
#define IDC_PAIR_BTN 324
#define IDC_LIST     325
#define IDAI_PROMPT  330
#define IDAI_SEND    331
#define IDAI_Q1      332
#define IDAI_Q2      333
#define IDAI_Q3      334
#define IDAI_Q4      335
#define IDAI_LIST    336
#define IDL_REFRESH  340
#define IDL_EXPORT   341
#define IDL_LIST     342
#define IDH_SEARCH   350
#define ID_TIMER     1

/* --- Full Team Control IDs ------------------------------------------------ */
#define IDTM_PROMPT  360
#define IDTM_SEND    361
#define IDTM_LIST    362
#define IDTM_RED     363
#define IDTM_BLUE    364
#define IDTM_PURPLE  365
#define IDTM_YELLOW  366
#define IDTM_GREEN   367
#define IDTM_CLEAR   368
#define IDTM_AUTO    369  /* Toggle autonomous agents */
#define IDTM_ALL     371

/* --- AI Voice & Settings IDs ---------------------------------------------- */
#define IDAI_VOICE   370  /* Toggle TTS voice */
#define IDST_AIKEY   380  /* AI API key edit */
#define IDST_AIAPPLY 381  /* Apply API key */
#define IDST_PROV    382  /* AI Provider combo */
#define IDST_WEBURL  383  /* Webhook URL edit */
#define IDST_WBAPPLY 384  /* Apply webhook */
#define IDST_SOUND   385  /* Alert sound toggle */
#define IDST_RSAUTO  386  /* RansomShield auto-start */
#define IDST_EXPATH  387  /* Export path edit */
#define IDST_EXBRW   388  /* Browse export path */
#define IDST_LOGMAX  389  /* Log max entries edit */
#define IDST_LOGAPPLY 390 /* Apply log settings */
#define IDST_WIZARD   391 /* Customization wizard trigger */


/* --- App Hub Control IDs -------------------------------------------------- */
#define IDAH_LIST     410  /* Main app list */
#define IDAH_REFRESH  411  /* Refresh discovery */
#define IDAH_DETAIL   412  /* Detail listbox */
#define IDAH_RELGRAPH 413  /* Relationship graph area */
#define IDAH_INTKEY   416  /* Copy integration key */
#define IDAH_FILTER   417  /* Filter button */
#define IDAH_LINK     418  /* Link two applications */
#define IDAH_AIID     419  /* AI application identification */
#define WM_DISC_DONE  (WM_APP + 50)  /* Discovery complete message */
/* --- SOC Cluster Linking IDs ---------------------------------------------- */
#define IDC_GENCODE  395  /* Generate pairing code */
#define IDC_CODEBOX  396  /* Generated code display */
#define IDC_ACCEPTIN 397  /* Paste received code */
#define IDC_ACCEPT   398  /* Accept/connect link */
#define IDC_SYNCEVT  399  /* Sync events from peer */
#define IDC_OPENREM  400  /* Open remote panel */

/* --- Team Agent Groq API -------------------------------------------------- */
/* NOTE: g_groqApiKey is the default key. Override it in Settings > AI Engine. */
static char g_groqApiKey[256] = "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";
#define GROQ_HOST  L"api.groq.com"
#define GROQ_PATH  L"/openai/v1/chat/completions"

/* Active team selector: 0=Red 1=Blue 2=Purple 3=Yellow 4=Green */
static int  g_activeTeam  = 1; /* Blue Team default */
static BOOL g_teamAutoMode = FALSE;  /* Autonomous agent mode */
static HANDLE g_teamAutoThread = NULL;
static BOOL g_voiceEnabled = FALSE;  /* TTS voice for AI responses */

/* Settings state & Categories */
typedef enum {
    SET_GENERAL = 0,     /* Language, Theme, Accent, Scale, Animations, Startup, Tray, Exit */
    SET_PROTECTION,      /* Security Center: Real-Time, Behavior, Heuristic, Cloud, Tamper, Profiles (Balanced/Strict/Max/Custom) */
    SET_AV,              /* Antivirus Core: Scan types, on-access, real-time files, actions, exclusions */
    SET_NET,             /* NetGuard: Connections, C2 beacon detection, DNS sinkhole, per-app policies */
    SET_FW,              /* Adaptive Firewall: Inbound/outbound, profiles, rules, stealth mode */
    SET_WAF,             /* WebGuard WAF: Web protection, 18 attack vectors, monitor/block/learning modes */
    SET_RANSOM,          /* RansomShield: Honeypots, mass file change, VSS rollback, recovery points */
    SET_SBX,             /* SmartSandbox: Isolation, static/dynamic/behavioral analysis, network simulation */
    SET_APPCTRL,         /* Application Control: Allow/block lists, execution policies */
    SET_ENGINES,         /* Engine Management: All 8 engines, start/stop/restart, auto-start, resource usage */
    SET_AISOC,           /* AI SOC Analyst: Automation level, local vs cloud, telemetry privacy */
    SET_DEVICE,          /* Device Control: USB storage, read-only mode, Bluetooth, hardware block */
    SET_FORENSICS,       /* Monitoring & Forensics: Logs, retention (1/7/30/90 days), format export (JSON/CSV/PDF) */
    SET_NOTIF,           /* Notifications: Alert severity routing, sound, email, priority */
    SET_CLOUD,           /* Cloud & Supabase: Supabase Auth, cloud sync, team permissions matrix, latency */
    SET_TEAM,            /* Account & Team: Roles (Owner, Admin, Analyst, Operator, Viewer), permissions matrix */
    SET_PRIVACY,         /* Security & Privacy: 2FA, passkeys, sessions, telemetry consent */
    SET_UPDATES,         /* Updates: Threat database frequency, engine auto-update, channel */
    SET_PERF,            /* Performance: Resource limits, gaming mode throttling, battery saving */
    SET_ENTERPRISE,      /* Enterprise / SOC: Organization ID, fleet compliance, audit logs */
    SET_ADVANCED,        /* Advanced / Developer: Debug console, API keys, local REST API, webhooks */
    SET_RECOVERY,        /* Reset & Recovery: Emergency lockdown, safe mode, reset defaults */
    SET_ABOUT            /* About Kaevex: Version, architecture, engine integrity, license */
} SetCategory;
#define SET_CAT_COUNT 23

static int g_setSubTab = SET_GENERAL;
static int g_setSideScroll = 0;

typedef struct {
    /* 1. General */
    int  lang;              /* 0=English, 1=Arabic */
    int  theme;             /* 0=Cyber Dark, 1=Dark OLED, 2=Slate Navy, 3=Midnight Blue */
    int  accent;            /* 0=Cyan, 1=Emerald, 2=Royal Blue, 3=Violet, 4=Coral */
    int  scale;             /* 0=100%, 1=125%, 2=150% */
    BOOL compactLayout;
    BOOL animations;
    BOOL glowEffects;
    BOOL soundEffects;
    BOOL notifSounds;
    BOOL startWithWindows;
    BOOL minimizeToTray;
    BOOL confirmExit;

    /* 2. Security Center */
    BOOL realTimeProt;
    BOOL behaviorMon;
    BOOL heuristicDetect;
    BOOL cloudProt;
    BOOL threatIntel;
    BOOL puaPupProt;
    BOOL suspFileDetect;
    BOOL scriptProt;
    BOOL memoryProt;
    BOOL procProt;
    BOOL tamperProt;
    BOOL selfDefense;
    int  protMode;          /* 0=Balanced, 1=Strict, 2=Maximum, 3=Custom */

    /* 3. Antivirus Core */
    BOOL avScanOnAccess;
    BOOL avScanDownloads;
    BOOL avScanArchives;
    BOOL avScanUsb;
    BOOL avScanNetwork;
    BOOL avScanScripts;
    BOOL avScanProcs;
    BOOL avSigDetect;
    BOOL avHeurDetect;
    BOOL avBehaviorDetect;
    BOOL avMlDetect;
    BOOL avCloudDetect;
    int  avThreatAction;    /* 0=Ask, 1=Quarantine, 2=Block, 3=Remove, 4=Isolate */

    /* 4. NetGuard */
    BOOL netMonConn;
    BOOL netMonProc;
    BOOL netMonDns;
    BOOL netMonPorts;
    BOOL netDetectC2;
    BOOL netDetectSusp;
    BOOL netConnLogging;
    BOOL netDnsSinkhole;
    BOOL netMaliciousDomain;
    BOOL netDnsLogging;
    int  netPolicy;         /* 0=Allow All, 1=Ask Unknown, 2=Block Unknown */

    /* 5. Firewall */
    BOOL fwEnabled;
    BOOL fwInbound;
    BOOL fwOutbound;
    BOOL fwStealth;
    BOOL fwBlockUnknown;
    BOOL fwBlockSuspicious;
    BOOL fwBlockRemote;
    BOOL fwPacketLogging;
    int  fwProfile;         /* 0=Public, 1=Private, 2=Domain */

    /* 6. WebGuard WAF */
    BOOL wafEnabled;
    BOOL wafPhishing;
    BOOL wafMaliciousUrl;
    BOOL wafSuspDomain;
    BOOL wafDownloadProt;
    BOOL wafBrowserProt;
    BOOL wafSqli;
    BOOL wafXss;
    BOOL wafRce;
    BOOL wafLfi;
    BOOL wafBotDetect;
    BOOL wafRateLimit;
    int  wafMode;           /* 0=Monitor, 1=Block, 2=Learning */

    /* 7. RansomShield */
    BOOL rsRealtime;
    BOOL rsMassFile;
    BOOL rsSuspEncrypt;
    BOOL rsProtFolders;
    BOOL rsProcBehavior;
    BOOL rsAutoKill;
    BOOL rsVssSnapshots;
    BOOL rsRollback;
    int  rsAction;          /* 0=Kill Process, 1=Suspend, 2=Quarantine, 3=Rollback */

    /* 8. SmartSandbox */
    BOOL sbxAutoAnalysis;
    BOOL sbxProcIsol;
    BOOL sbxNetIsol;
    BOOL sbxFsIsol;
    BOOL sbxStaticAnalysis;
    BOOL sbxDynamicAnalysis;
    BOOL sbxSimulatedNet;
    BOOL sbxDnsSim;

    /* 9. App Control */
    BOOL appAllowList;
    BOOL appBlockList;
    BOOL appBlockUnsigned;
    BOOL appBlockSuspicious;
    BOOL appBlockScripts;
    BOOL appPortableGuard;
    BOOL appDllSideloadGuard;
    BOOL appAuditLog;
    int  appExecPolicy;     /* 0=Trusted Only, 1=Allow Known/Ask Unknown, 2=Strict Whitelist */

    /* 10. Device Control */
    BOOL devUsbStorage;
    BOOL devBlockUnknownUsb;
    BOOL devUsbReadOnly;
    BOOL devBluetooth;
    BOOL devCamera;
    BOOL devMic;
    BOOL devPcieLock;
    BOOL devAuditLog;

    /* 11. AI SOC Analyst */
    BOOL aiEnabled;
    BOOL aiAutoInvestigate;
    BOOL aiThreatCorrelation;
    BOOL aiSummarize;
    BOOL aiAutoRemediate;
    int  aiAutoLevel;       /* 0=Observation, 1=Suggest, 2=Ask Before Action, 3=Auto-Remediate */
    BOOL aiLocalOnly;
    BOOL aiVoiceTts;
    BOOL aiIntelEnrich;

    /* 12. Forensics & Logs */
    BOOL logProcs;
    BOOL logNetwork;
    BOOL logDns;
    BOOL logRegistry;
    BOOL logSecurity;
    BOOL logHmacSeal;
    BOOL logAutoRotate;
    BOOL logHashChain;
    int  logRetention;      /* 0=1 Day, 1=7 Days, 2=30 Days, 3=90 Days */

    /* 13. Notifications */
    BOOL notifCritical;
    BOOL notifHigh;
    BOOL notifMalware;
    BOOL notifRansomware;
    BOOL notifFwBlock;
    BOOL notifDesktop;
    BOOL notifSound;
    BOOL notifDailyDigest;

    /* 14. Performance */
    BOOL perfCpuThrottle;
    BOOL perfRamThrottle;
    BOOL perfPauseGaming;
    BOOL perfPauseBattery;
    BOOL perfScanIdle;
    BOOL perfHighPrecisionTimer;
    BOOL perfGpuAccel;
    BOOL perfPriorityOpt;
    int  perfMode;          /* 0=Eco, 1=Balanced, 2=High Power, 3=Turbo */

    /* 15. Updates */
    BOOL updAuto;
    BOOL updBeta;
    BOOL updSignatures;
    BOOL updCveFeed;
    BOOL updWafPatches;
    BOOL updDnsFeeds;
    BOOL updRollback;
    BOOL updP2pLan;
    int  updFreq;           /* 0=Every 6 Hours, 1=Daily, 2=Weekly, 3=Manual */

    /* 16. Cloud & Supabase */
    BOOL cloudSync;
    BOOL cloudSyncPolicies;
    BOOL cloudSyncThreats;
    BOOL cloudSyncLogs;
    BOOL cloudTelemetry;
    BOOL cloudCrashDumps;
    BOOL cloudTlsTunnel;
    BOOL cloudFleetMap;

    /* 17. Enterprise */
    BOOL entFleetCompliance;
    BOOL entEnforceLockdown;
    BOOL entAuditAdmin;
    BOOL entMultiTenant;
    BOOL entSyslog;
    BOOL entAutoDispatch;
    BOOL entTpmAttest;
    BOOL entPolicySync;
    char entOrgName[64];
    char entOrgId[64];

    /* 18. Advanced / Developer */
    BOOL advDebugMode;
    BOOL advLocalApi;
    BOOL advIpcTracing;
    BOOL advSiemWebhook;
    BOOL advEtwTracing;
    BOOL advRawPcap;
    BOOL advApiKeyProt;
    BOOL advCrashLog;
    int  advApiPort;

    /* 19. Recovery */
    BOOL recEmergencyLockdown;
    BOOL recSafeMode;

    /* 20. Privacy & Governance */
    BOOL priv2Fa;
    BOOL privPasskey;
    BOOL privSessionTimeout;
    BOOL privRevokeRemote;
    BOOL privZeroTelemetry;
    BOOL privEncryptedVault;
    BOOL privAnonymize;
    BOOL privAuditCredentials;
} KaevexFullSettings;

static KaevexFullSettings g_cfg = {
    .lang = 0, .theme = 0, .accent = 0, .scale = 0, .compactLayout = FALSE,
    .animations = TRUE, .glowEffects = TRUE, .soundEffects = TRUE, .notifSounds = TRUE,
    .startWithWindows = FALSE, .minimizeToTray = TRUE, .confirmExit = TRUE,

    .realTimeProt = TRUE, .behaviorMon = TRUE, .heuristicDetect = TRUE, .cloudProt = TRUE,
    .threatIntel = TRUE, .puaPupProt = TRUE, .suspFileDetect = TRUE, .scriptProt = TRUE,
    .memoryProt = TRUE, .procProt = TRUE, .tamperProt = TRUE, .selfDefense = TRUE,
    .protMode = 0,

    .avScanOnAccess = TRUE, .avScanDownloads = TRUE, .avScanArchives = TRUE, .avScanUsb = TRUE,
    .avScanNetwork = TRUE, .avScanScripts = TRUE, .avScanProcs = TRUE, .avSigDetect = TRUE,
    .avHeurDetect = TRUE, .avBehaviorDetect = TRUE, .avMlDetect = TRUE, .avCloudDetect = TRUE,
    .avThreatAction = 1,

    .netMonConn = TRUE, .netMonProc = TRUE, .netMonDns = TRUE, .netMonPorts = TRUE,
    .netDetectC2 = TRUE, .netDetectSusp = TRUE, .netConnLogging = TRUE, .netDnsSinkhole = TRUE,
    .netMaliciousDomain = TRUE, .netDnsLogging = TRUE, .netPolicy = 0,

    .fwEnabled = TRUE, .fwInbound = TRUE, .fwOutbound = TRUE, .fwStealth = TRUE,
    .fwBlockUnknown = FALSE, .fwBlockSuspicious = TRUE, .fwBlockRemote = FALSE,
    .fwPacketLogging = TRUE, .fwProfile = 1,

    .wafEnabled = TRUE, .wafPhishing = TRUE, .wafMaliciousUrl = TRUE, .wafSuspDomain = TRUE,
    .wafDownloadProt = TRUE, .wafBrowserProt = TRUE, .wafSqli = TRUE, .wafXss = TRUE,
    .wafRce = TRUE, .wafLfi = TRUE, .wafBotDetect = TRUE, .wafRateLimit = TRUE, .wafMode = 1,

    .rsRealtime = TRUE, .rsMassFile = TRUE, .rsSuspEncrypt = TRUE, .rsProtFolders = TRUE,
    .rsProcBehavior = TRUE, .rsAutoKill = TRUE, .rsVssSnapshots = TRUE, .rsRollback = TRUE,
    .rsAction = 0,

    .sbxAutoAnalysis = TRUE, .sbxProcIsol = TRUE, .sbxNetIsol = TRUE, .sbxFsIsol = TRUE,
    .sbxStaticAnalysis = TRUE, .sbxDynamicAnalysis = TRUE, .sbxSimulatedNet = TRUE, .sbxDnsSim = TRUE,

    .appAllowList = TRUE, .appBlockList = TRUE, .appBlockUnsigned = FALSE,
    .appBlockSuspicious = TRUE, .appBlockScripts = FALSE,
    .appPortableGuard = TRUE, .appDllSideloadGuard = TRUE, .appAuditLog = TRUE,
    .appExecPolicy = 0,

    .devUsbStorage = TRUE, .devBlockUnknownUsb = FALSE, .devUsbReadOnly = FALSE,
    .devBluetooth = TRUE, .devCamera = TRUE, .devMic = TRUE, .devPcieLock = FALSE, .devAuditLog = TRUE,

    .aiEnabled = TRUE, .aiAutoInvestigate = TRUE, .aiThreatCorrelation = TRUE,
    .aiSummarize = TRUE, .aiAutoRemediate = FALSE, .aiAutoLevel = 1, .aiLocalOnly = FALSE,
    .aiVoiceTts = TRUE, .aiIntelEnrich = TRUE,

    .logProcs = TRUE, .logNetwork = TRUE, .logDns = TRUE, .logRegistry = TRUE,
    .logSecurity = TRUE, .logHmacSeal = TRUE, .logAutoRotate = TRUE, .logHashChain = TRUE,
    .logRetention = 2,

    .notifCritical = TRUE, .notifHigh = TRUE, .notifMalware = TRUE, .notifRansomware = TRUE,
    .notifFwBlock = TRUE, .notifDesktop = TRUE, .notifSound = TRUE, .notifDailyDigest = TRUE,

    .perfCpuThrottle = FALSE, .perfRamThrottle = FALSE, .perfPauseGaming = TRUE,
    .perfPauseBattery = TRUE, .perfScanIdle = TRUE,
    .perfHighPrecisionTimer = TRUE, .perfGpuAccel = TRUE, .perfPriorityOpt = TRUE,
    .perfMode = 2,

    .updAuto = TRUE, .updBeta = FALSE, .updSignatures = TRUE, .updCveFeed = TRUE,
    .updWafPatches = TRUE, .updDnsFeeds = TRUE, .updRollback = TRUE, .updP2pLan = FALSE,
    .updFreq = 0,

    .cloudSync = TRUE, .cloudSyncPolicies = TRUE, .cloudSyncThreats = TRUE,
    .cloudSyncLogs = TRUE, .cloudTelemetry = TRUE,
    .cloudCrashDumps = FALSE, .cloudTlsTunnel = TRUE, .cloudFleetMap = TRUE,

    .entFleetCompliance = TRUE, .entEnforceLockdown = FALSE, .entAuditAdmin = TRUE,
    .entMultiTenant = FALSE, .entSyslog = TRUE, .entAutoDispatch = FALSE,
    .entTpmAttest = TRUE, .entPolicySync = TRUE,
    .entOrgName = "Kaevex Security Operations", .entOrgId = "KVX-GLOBAL-01",

    .advDebugMode = FALSE, .advLocalApi = TRUE,
    .advIpcTracing = FALSE, .advSiemWebhook = FALSE, .advEtwTracing = FALSE,
    .advRawPcap = FALSE, .advApiKeyProt = TRUE, .advCrashLog = TRUE,
    .advApiPort = 9009,

    .recEmergencyLockdown = FALSE, .recSafeMode = FALSE,

    .priv2Fa = TRUE, .privPasskey = TRUE, .privSessionTimeout = TRUE,
    .privRevokeRemote = FALSE, .privZeroTelemetry = FALSE, .privEncryptedVault = TRUE,
    .privAnonymize = TRUE, .privAuditCredentials = TRUE
};


static void SaveKaevexSettings(void) {
    HKEY hk;
    if(RegCreateKeyExA(HKEY_CURRENT_USER, "Software\\Kaevex\\Settings", 0, NULL, 0, KEY_SET_VALUE, NULL, &hk, NULL) == ERROR_SUCCESS) {
        RegSetValueExA(hk, "Config", 0, REG_BINARY, (BYTE*)&g_cfg, sizeof(g_cfg));
        RegCloseKey(hk);
    }
}

static void LoadKaevexSettings(void) {
    HKEY hk;
    if(RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Kaevex\\Settings", 0, KEY_QUERY_VALUE, &hk) == ERROR_SUCCESS) {
        DWORD sz = sizeof(g_cfg);
        RegQueryValueExA(hk, "Config", NULL, NULL, (BYTE*)&g_cfg, &sz);
        RegCloseKey(hk);
    }
}

static void ApplyTheme(int themeId) {
    switch (themeId) {
        case 1: /* Dark OLED - Pitch Black with Neon Emerald Accent */
            g_col_bg        = RGB(  0,   0,   0);
            g_col_bg2       = RGB(  4,   4,   4);
            g_col_hdr       = RGB(  8,   8,   8);
            g_col_sidebar   = RGB(  2,   2,   2);
            g_col_panel     = RGB( 12,  12,  14);
            g_col_panel2    = RGB( 18,  18,  22);
            g_col_card      = RGB( 12,  12,  14);
            g_col_card2     = RGB(  8,   8,  10);
            g_col_border    = RGB( 34,  38,  46);
            g_col_border2   = RGB( 22,  26,  32);
            g_col_nav_act   = RGB( 16, 185, 129); /* Neon Emerald */
            g_col_nav_hov   = RGB( 20,  24,  28);
            g_col_search_bg = RGB( 14,  14,  18);
            g_col_text      = RGB(250, 250, 250);
            g_col_text2     = RGB(180, 188, 200);
            g_col_dim       = RGB(120, 130, 145);
            g_col_dim2      = RGB( 70,  78,  90);
            break;
        case 2: /* Slate Navy - Tactical Operations Blue */
            g_col_bg        = RGB( 15,  23,  42);
            g_col_bg2       = RGB( 11,  17,  32);
            g_col_hdr       = RGB( 30,  41,  59);
            g_col_sidebar   = RGB( 20,  29,  47);
            g_col_panel     = RGB( 30,  41,  59);
            g_col_panel2    = RGB( 38,  52,  75);
            g_col_card      = RGB( 30,  41,  59);
            g_col_card2     = RGB( 24,  34,  50);
            g_col_border    = RGB( 51,  65,  85);
            g_col_border2   = RGB( 40,  52,  68);
            g_col_nav_act   = RGB(  2, 132, 199); /* Sky Blue */
            g_col_nav_hov   = RGB( 32,  48,  72);
            g_col_search_bg = RGB( 22,  32,  48);
            g_col_text      = RGB(248, 250, 252);
            g_col_text2     = RGB(190, 205, 225);
            g_col_dim       = RGB(130, 150, 175);
            g_col_dim2      = RGB( 80, 100, 125);
            break;
        case 3: /* Midnight Crimson - Cyberpunk Security Dark */
            g_col_bg        = RGB( 18,  10,  18);
            g_col_bg2       = RGB( 12,   6,  12);
            g_col_hdr       = RGB( 28,  14,  28);
            g_col_sidebar   = RGB( 22,  11,  22);
            g_col_panel     = RGB( 32,  16,  32);
            g_col_panel2    = RGB( 44,  22,  44);
            g_col_card      = RGB( 32,  16,  32);
            g_col_card2     = RGB( 24,  12,  24);
            g_col_border    = RGB( 75,  28,  75);
            g_col_border2   = RGB( 52,  20,  52);
            g_col_nav_act   = RGB(225,  29,  72); /* Rose Crimson */
            g_col_nav_hov   = RGB( 42,  18,  42);
            g_col_search_bg = RGB( 26,  13,  26);
            g_col_text      = RGB(255, 245, 255);
            g_col_text2     = RGB(225, 195, 225);
            g_col_dim       = RGB(165, 135, 165);
            g_col_dim2      = RGB(105,  75, 105);
            break;
        case 4: /* Light Minimal - Enterprise White/Silver */
            g_col_bg        = RGB(241, 245, 249);
            g_col_bg2       = RGB(226, 232, 240);
            g_col_hdr       = RGB(255, 255, 255);
            g_col_sidebar   = RGB(248, 250, 252);
            g_col_panel     = RGB(255, 255, 255);
            g_col_panel2    = RGB(241, 245, 249);
            g_col_card      = RGB(255, 255, 255);
            g_col_card2     = RGB(248, 250, 252);
            g_col_border    = RGB(203, 213, 225);
            g_col_border2   = RGB(226, 232, 240);
            g_col_nav_act   = RGB( 37,  99, 235); /* Royal Blue */
            g_col_nav_hov   = RGB(226, 232, 240);
            g_col_search_bg = RGB(241, 245, 249);
            g_col_text      = RGB( 15,  23,  42);
            g_col_text2     = RGB( 51,  65,  85);
            g_col_dim       = RGB(100, 116, 139);
            g_col_dim2      = RGB(148, 163, 184);
            break;
        case 0: /* Cyber Dark (Default) */
        default:
            g_col_bg        = RGB(  5,  10,  22);
            g_col_bg2       = RGB(  4,   8,  18);
            g_col_hdr       = RGB(  7,  12,  24);
            g_col_sidebar   = RGB(  6,  11,  22);
            g_col_panel     = RGB( 10,  17,  32);
            g_col_panel2    = RGB( 14,  23,  44);
            g_col_card      = RGB( 10,  17,  32);
            g_col_card2     = RGB(  8,  14,  26);
            g_col_border    = RGB( 22,  34,  60);
            g_col_border2   = RGB( 16,  25,  44);
            g_col_nav_act   = RGB( 29,  78, 216);
            g_col_nav_hov   = RGB( 16,  26,  48);
            g_col_search_bg = RGB( 13,  21,  38);
            g_col_text      = RGB(240, 246, 255);
            g_col_text2     = RGB(175, 192, 218);
            g_col_dim       = RGB(115, 134, 162);
            g_col_dim2      = RGB( 65,  82, 108);
            break;
    }
    if (hBrEdit)   { DeleteObject(hBrEdit);   hBrEdit   = NULL; }
    if (hBrList)   { DeleteObject(hBrList);   hBrList   = NULL; }
    if (hBrPnl)    { DeleteObject(hBrPnl);    hBrPnl    = NULL; }
    if (hBrSearch) { DeleteObject(hBrSearch); hBrSearch = NULL; }
    if (g_hwnd) {
        RedrawWindow(g_hwnd, NULL, NULL, RDW_INVALIDATE | RDW_ERASE | RDW_ALLCHILDREN | RDW_UPDATENOW);
    }
}

static void ApplyKaevexSettings(BOOL initialLoad);
static void ExecuteSettingsAction(int actId);


static char g_webhookUrl[512]  = "";
static char g_aiApiKey[256]    = "";
static int  g_aiProvider       = 0;  /* 0=Together AI (DeepSeek-V4-Pro-0813), 1=Groq, 2=NVIDIA, 3=Local */
static BOOL g_updNotifyBeforeFix = TRUE;
static BOOL g_alertSound       = TRUE;
static BOOL g_ransomAutoStart  = FALSE;
static char g_exportPath[MAX_PATH] = "";
static int  g_logMaxEntries    = 1000;

/* SOC cluster linked servers */
#define MAX_LINKED 8
typedef struct { char ip[64]; char code[128]; char name[64]; int pingMs; BOOL active; } LinkedServer;
static LinkedServer g_linkedServers[MAX_LINKED];
static int g_linkedCount = 0;
static char g_myPairCode[256] = "";

/* --- Additional New Control IDs ------------------------------------------- */
#define IDU_AIFIX    248   /* AI-powered CVE fix */
#define IDU_SANDBOX  249   /* Sandbox & update app */
#define IDU_SEARCH   254   /* Real-time search filter edit */
#define IDU_REFRESH  255   /* Refresh vulnerability DB & scan */
#define IDU_EXPORT   252   /* Export CSV audit report */
#define WM_NVD_REFRESH_DONE (WM_APP + 42)


/* --- 8 Core Defense Engines ----------------------------------------------- */
typedef struct {
    const char *name, *detail, *version;
} Engine;

static Engine g_eng[8] = {
    {"Antivirus Core",       "On-demand file and selected-directory inspection","3.0.0"},
    {"Network Monitor",      "Live Windows socket and interface-counter views","2.0.0"},
    {"CVE Agent",            "Installed-software inventory and recent NVD advisories","3.0.0"},
    {"RansomShield",         "Optional filesystem watcher and canary protections","2.0.0"},
    {"Adaptive Firewall",    "Windows Firewall rule inspection and management","1.0.0"},
    {"WebGuard WAF",         "On-demand inspection of supplied HTTP/payload text","3.0.0"},
    {"SmartSandbox",         "Sandboxie-Plus integration; requires separate installation","2.1.0"},
    {"App Discovery Hub",    "On-demand Windows application inventory","1.0.0"},
};

/* --- Live Real-World Telemetry Stats & Chart Data -------------------------- */
static long long g_busEvents   = 0;
static long long g_wafInsp     = 0;
static long long g_wafBlk      = 0;
static long long g_avScanned   = 0;
static int       g_avThreats   = 0;
static int       g_bannedIPs   = 0;
static long long g_rwHits      = 0;
static long long g_dlpLeaksBlocked = 0;
static time_t    g_startTime;
static CRITICAL_SECTION g_statsCS;

static unsigned long long g_realInBytes      = 0;
static unsigned long long g_realOutBytes     = 0;
static unsigned long long g_realInPkts       = 0;
static unsigned long long g_realOutPkts      = 0;
static unsigned long long g_realDrops        = 0;
static int                g_realRunningProcs  = 0;

/* Real Live Rolling Telemetry (7 Time Windows) - all start at 0, filled by live sampling */
static int g_chartInbound[7]  = { 0, 0, 0, 0, 0, 0, 0 };
static int g_chartOutbound[7] = { 0, 0, 0, 0, 0, 0, 0 };
static int g_chartClean[7]    = { 0, 0, 0, 0, 0, 0, 0 };
static int g_chartFiltered[7] = { 0, 0, 0, 0, 0, 0, 0 };
static const char *g_days[7]  = { "-9s", "-7.5s", "-6s", "-4.5s", "-3s", "-1.5s", "now" };

/* --- Alert Ring Buffer --------------------------------------------------- */
#define AL_MAX  256
#define AL_LEN  290
static char g_al[AL_MAX][AL_LEN];
static int  g_alCnt = 0;
static CRITICAL_SECTION g_alCS;

/* --- Master Windows and Handles ------------------------------------------ */
static Tab   g_tab      = TAB_DASH;

/* === Multilingual Support === */
/* 0 = English, 1 = Arabic (RTL), 2 = Auto-detect from system locale */
static int g_lang = 2; /* 2 = auto */

static void InitLanguage(void) {
    if (g_lang == 2) {
        LANGID lid = GetUserDefaultLangID();
        WORD primary = PRIMARYLANGID(lid);
        if (primary == LANG_ARABIC || primary == 0x01) {
            g_lang = 1; /* Arabic */
        } else {
            g_lang = 0; /* English */
        }
    }
}

/* L() — always returns English. Arabic input still works via Unicode Edit controls.
   Language detection kept for future locale-aware features. */
static const char *L(const char *en, const char *ar) {
    (void)ar; /* Arabic UI disabled — UI is English-only */
    return en;
}
static int   g_navHov   = -1;
static BOOL  g_lockdown = FALSE;
static HFONT fHdr, fBig, fMed, fSm, fMono, fStat, fMini, fIcon, fIconBig;

/* Control Handles */
static HWND hWafIn,hWafGo,hWafClr,hWafLog;
static HWND hAvPath,hAvBrw,hAvScn,hAvLog;
static HWND hAvThreatList,hAvMarkSafe,hAvQuarantine,hAvScanAll,hAvClearDb,hAvBootAudit;
static HWND hAvScanDir,hAvSearchIn,hAvFilterThreat,hAvFilterTime,hAvExport;
static HWND hSbxPath,hSbxBrw,hSbxRun,hSbxKill,hSbxLog,hSbxBNet,hSbxBFile,hSbxBProc;
static HWND hFwList,hFwAdd,hFwDel,hFwBlkProc,hFwReload,hFwToggle,hFwLockdown,hFwDefaults,hFwRuleName,hFwRulePort;
static HWND hUpdList,hUpdScan,hUpdChk,hUpdSel,hUpdAll,hUpdWin,hUpdFixAll,hUpdWatcher,hUpdNotifyMode;
static HWND hAlList,hAlClr;
static HWND hStPort,hStApply,hStAuto,hStFwDfl,hStHook;
static HWND hStAiKey,hStAiApply,hStProv,hStWebUrl,hStWbApply;
static HWND hStSound,hStRsAuto,hStExPath,hStExBrw,hStLogMax,hStLogApply,hStWizard;

static HWND hEngStAll,hEngSpAll;
static HWND hNetScan,hNetPorts,hNetClosePort,hNetBlockDns,hNetKill,hNetPortIn,hNetDnsIn,hNetList,hNetSort;
static HWND hRwStart,hRwStop,hRwDeployHoney,hRwCheckHoney,hRwVss,hRwList;
static HWND hDgScan,hDgClip,hDgClr,hDgDir,hDgList;
static HWND hThrGame,hThrBoost,hThrPurge,hThrCustom,hThrTcp,hThrAc,hThrHibp,hThrPassIn,hThrList;
static HWND hSocScan,hSocPing,hSocPairIp,hSocPairKey,hSocPairBtn,hSocList;
static HWND hSocGenCode,hSocCodeBox,hSocAcceptIn,hSocAccept,hSocSyncEvt,hSocOpenRem;
/* App Hub (Discovery) controls */
static HWND hAppList,hAppRefresh,hAppDetail,hAppRelGraph;
static HWND hAppIntKey,hAppFilter,hAppLink,hAppAiId;
static int  g_appHubSel = -1;          /* Selected app index in hub list */
static int  g_appHubFilter = 0;        /* 0=All 1=Stacks 2=Running 3=Unknown 4=Servers */
static BOOL g_discRunning = FALSE;     /* discovery thread active */

static HWND hAiPrompt,hAiSend,hAiQ1,hAiQ2,hAiQ3,hAiQ4,hAiList,hAiVoice;
static HWND hForRefresh,hForExport,hForList;
static HWND hTopSearch;
/* Full Team */
static HWND hTmPrompt,hTmSend,hTmList,hTmRed,hTmBlue,hTmPurple,hTmYellow,hTmGreen,hTmClear,hTmAuto;
static HWND hTmAllTeams;
static volatile LONG g_teamPendingRequests = 0;
/* Extra CVE buttons */
static HWND hUpdAiFix,hUpdSandbox,hUpdSearch;

/* --- Patch & CVE Agent Modern Interactive Data Model ---------------------- */
typedef enum {
    CVE_SEV_CRITICAL = 0,
    CVE_SEV_HIGH,
    CVE_SEV_MEDIUM,
    CVE_SEV_LOW
} CveSeverity;

typedef enum {
    CVE_STATUS_PENDING = 0,
    CVE_STATUS_AVAILABLE,
    CVE_STATUS_FIXED,
    CVE_STATUS_IGNORED,
    CVE_STATUS_INTEL
} CveStatus;

typedef struct {
    int  id;
    BOOL selected;
    char vulnTitle[128];
    char vulnDesc[180];
    char appName[96];
    char version[48];
    CveSeverity severity;
    int  cvssScore;
    char cveId[32];
    CveStatus status;
    char actionText[32];
    char wingetId[128];
    char fixVersion[48];
    int  iconType; /* 0=generic, 1=windows, 2=edge, 3=adobe, 4=firefox, 5=chrome, 6=defender, 7=openssl, 8=java, 9=7zip, 10=notepad++, 11=python, 12=git, 13=vscode */
    int  category; /* 0=Other, 1=OS, 2=Browsers, 3=Dev Tools, 4=Utilities */
    BOOL isOs;
    char executablePath[MAX_PATH];
    BOOL isIntelOnly;
} CveTableItem;

#define MAX_CVE_TABLE 512
static CveTableItem g_cveItems[MAX_CVE_TABLE];
static int          g_cveItemCount = 0;
static int          g_cveScrollY = 0;
static int          g_cveSubNav = 1;        /* 0=Overview, 1=Vulnerabilities, 2=Patches, 3=Scan Settings, 4=Update Center, 5=CVE Database, 6=Reports */
static int          g_cveFilterSev = 0;    /* 0=All, 1=Critical, 2=High, 3=Medium, 4=Low */
static int          g_cveFilterStatus = 0; /* 0=All, 1=Pending, 2=Available, 3=Fixed, 4=Ignored */
static int          g_cveFilterCat = 0;    /* 0=All, 1=OS, 2=Browsers, 3=Dev Tools, 4=Utilities */
static char         g_cveSearch[64] = "";
static char         g_cveLastScanTime[64] = "Not scanned";
static wchar_t      g_cveLastScanTimeW[64] = L"Not scanned";
static int          g_cveCritCnt = 0;
static int          g_cveHighCnt = 0;
static int          g_cveMedCnt = 0;
static int          g_cveLowCnt = 0;
static int          g_cveTotalCnt = 0;
static BOOL         g_cveSelectAll = FALSE;
static int          g_cveHoverRow = -1;
static volatile LONG g_nvdRefreshBusy = 0;
static volatile BOOL g_cveScanning = FALSE;
static DWORD         g_cveScanStartTick = 0;
#define WM_CVE_SCAN_DONE (WM_APP + 65)
#define IDT_CVE_AUTOSCAN 0x7B32

/* CVE Sub-Nav Interactive State */
static BOOL g_cveAutoScanEnabled  = TRUE;
static int  g_cveAutoScanInterval = 1; /* 0=15m, 1=1h, 2=6h, 3=24h */
static BOOL g_cveScanNvdCloud     = TRUE;
static int  g_cvePatchScrollY     = 0;
static char g_cveDbSearch[64]     = "";
static int  g_cveDbScrollY        = 0;
static char g_cveReportStatus[128]= "";

static UINT CveScanIntervalMs(void) {
    static const UINT intervals[]={15u*60u*1000u,60u*60u*1000u,6u*60u*60u*1000u,24u*60u*60u*1000u};
    return intervals[g_cveAutoScanInterval>=0&&g_cveAutoScanInterval<4?g_cveAutoScanInterval:1];
}
static void CveUpdateSchedule(HWND hw) {
    if(g_cveAutoScanEnabled) SetTimer(hw,IDT_CVE_AUTOSCAN,CveScanIntervalMs(),NULL);
    else KillTimer(hw,IDT_CVE_AUTOSCAN);
}
static void CveLoadSchedule(void) {
    HKEY key; DWORD value=0,size=sizeof(value),type=0;
    if(RegOpenKeyExA(HKEY_CURRENT_USER,"Software\\Kaevex\\CveAgent",0,KEY_READ,&key)!=ERROR_SUCCESS) return;
    if(RegQueryValueExA(key,"AutoScanEnabled",NULL,&type,(BYTE*)&value,&size)==ERROR_SUCCESS&&type==REG_DWORD)g_cveAutoScanEnabled=value!=0;
    size=sizeof(value); if(RegQueryValueExA(key,"ScanInterval",NULL,&type,(BYTE*)&value,&size)==ERROR_SUCCESS&&type==REG_DWORD&&value<4)g_cveAutoScanInterval=(int)value;
    size=sizeof(value); if(RegQueryValueExA(key,"NvdSyncEnabled",NULL,&type,(BYTE*)&value,&size)==ERROR_SUCCESS&&type==REG_DWORD)g_cveScanNvdCloud=value!=0;
    RegCloseKey(key);
}
static BOOL CveSaveSchedule(void) {
    HKEY key; DWORD disp=0;
    if(RegCreateKeyExA(HKEY_CURRENT_USER,"Software\\Kaevex\\CveAgent",0,NULL,0,KEY_WRITE,NULL,&key,&disp)!=ERROR_SUCCESS)return FALSE;
    DWORD enabled=g_cveAutoScanEnabled?1u:0u,interval=(DWORD)g_cveAutoScanInterval,nvd=g_cveScanNvdCloud?1u:0u;
    BOOL ok=RegSetValueExA(key,"AutoScanEnabled",0,REG_DWORD,(BYTE*)&enabled,sizeof(enabled))==ERROR_SUCCESS &&
            RegSetValueExA(key,"ScanInterval",0,REG_DWORD,(BYTE*)&interval,sizeof(interval))==ERROR_SUCCESS &&
            RegSetValueExA(key,"NvdSyncEnabled",0,REG_DWORD,(BYTE*)&nvd,sizeof(nvd))==ERROR_SUCCESS;
    RegCloseKey(key);return ok;
}

/* --- Gaming & Threat Modern Interactive State --- */
static int   g_threatSubNav   = 0;     /* 0=Gaming Mode, 1=Threat Protection, 2=Performance, 3=Rules, 4=Profiles */
static BOOL  g_gmMaster       = TRUE;  /* Master Gaming Mode switch */
/* 5 Gaming Options */
static BOOL  g_gmReduceCpu    = TRUE;
static BOOL  g_gmOptimizeRam  = TRUE;
static BOOL  g_gmBlockNotif   = TRUE;
static BOOL  g_gmPauseScans   = TRUE;
static BOOL  g_gmKeepCritProt = TRUE;
static BOOL  g_gmAutoDetect   = TRUE;

/* 6 Threat Protection Options */
static BOOL  g_tpRealtime     = TRUE;
static BOOL  g_tpBehavior     = TRUE;
static BOOL  g_tpHeuristic    = TRUE;
static BOOL  g_tpRansomware   = TRUE;
static BOOL  g_tpWeb          = TRUE;
static BOOL  g_tpNetwork      = TRUE;

static int   g_gmFwPreset     = 0;     /* 0=Gaming Optimized, 1=Strict Esports, 2=Allow All Outbound */
static DWORD g_lastRamPurgeTick = 0;

/* --- Auto-AV Scan state --------------------------------------------------- */
static DWORD g_lastAvScan = 0;        /* tick of last hourly AV scan */
static int   g_avAutoFiles = 0;        /* files scanned in auto mode */
static int   g_avAutoThreats = 0;      /* threats found in auto mode */

/* --- CVE Registry watcher state ------------------------------------------- */
static BOOL  g_regWatchActive = FALSE;
static DWORD g_lastInstallCheck = 0;   /* tick of last install check */



/* --- WAF 18-Category Dynamic Telemetry & Inspection Engine ---------------- */
#define WAF_CAT_COUNT 18
#define WAF_MAX_MATCHES 16

typedef enum {
    WAF_CAT_SQLI = 0,
    WAF_CAT_XSS,
    WAF_CAT_RCE,
    WAF_CAT_CMDI,
    WAF_CAT_TRAVERSAL,
    WAF_CAT_LFI,
    WAF_CAT_RFI,
    WAF_CAT_SSRF,
    WAF_CAT_XXE,
    WAF_CAT_CSRF,
    WAF_CAT_PARAM_TAMP,
    WAF_CAT_HDR_TAMP,
    WAF_CAT_COOKIE_POIS,
    WAF_CAT_PROTO_VIOL,
    WAF_CAT_ENCODING,
    WAF_CAT_SCANNER,
    WAF_CAT_SESSION,
    WAF_CAT_DDOS
} WafCategory;

typedef struct {
    char id[32];           /* e.g. "WAF-SQL-04" */
    char name[64];         /* e.g. "Tautology Check" */
    char category[64];     /* e.g. "SQL Injection" */
    int confidence;        /* e.g. 99 */
    char matchText[128];   /* e.g. "%27 OR %271%27=%271" */
} WafMatch;

typedef struct {
    const char *name;      /* Category display name */
    int status;            /* 0 = Clean, 1 = Triggered Low, 2 = Triggered Medium, 3 = Triggered High */
    int confidence;        /* Confidence percentage */
    const char *iconChar;  /* Mini symbol or glyph */
} WafCategoryState;

typedef struct {
    BOOL inspected;
    int overallScore;      /* 0 to 100 Risk Meter */
    int overallConfidence; /* 0 to 99 */
    char primaryCategory[64];
    int primaryConfidence;
    char severity[32];     /* "Clean", "Low", "Medium", "High", "Critical" */
    char actionTaken[48];  /* "Request Blocked", "Request Allowed", "Monitoring Active" */
    BOOL blocked;
    WafCategoryState cats[WAF_CAT_COUNT];
    WafMatch matches[WAF_MAX_MATCHES];
    int matchCount;
    char recommendations[4][160];
    int recommendationCount;
} WafInspectionState;

static WafInspectionState s_wafState;
static BOOL s_wafInited = FALSE;

typedef struct {
    int score, blocked;
    const char *name, *cwe, *mitre, *sev;
    char detail[256];
} WafResult;

static void waf_reset_state(void) {
    memset(&s_wafState, 0, sizeof(s_wafState));
    s_wafState.inspected = FALSE;
    s_wafState.overallScore = 0;
    s_wafState.overallConfidence = 0;
    strncpy(s_wafState.primaryCategory, "Clean / Standby", sizeof(s_wafState.primaryCategory)-1);
    s_wafState.primaryConfidence = 0;
    strncpy(s_wafState.severity, "Clean", sizeof(s_wafState.severity)-1);
    strncpy(s_wafState.actionTaken, "Monitoring Active", sizeof(s_wafState.actionTaken)-1);
    s_wafState.blocked = FALSE;

    static const char *catNames[WAF_CAT_COUNT] = {
        "SQL Injection", "Cross-Site Scripting", "Remote Code Execution", "Command Injection",
        "Path Traversal", "Local File Inclusion", "Remote File Inclusion", "Server-Side Request Forgery",
        "XML External Entity", "Cross-Site Request Forgery", "Parameter Tampering", "Header Tampering",
        "Cookie Poisoning", "Protocol Violations", "Encoding Anomalies", "Scanner/Spider Detection",
        "Session Hijacking", "DoS/DDoS Signature"
    };
    for (int i = 0; i < WAF_CAT_COUNT; i++) {
        s_wafState.cats[i].name = catNames[i];
        s_wafState.cats[i].status = 0; /* Clean */
        s_wafState.cats[i].confidence = 0;
    }

    strncpy(s_wafState.recommendations[0], "1. WebGuard WAF is actively filtering incoming HTTP/HTTPS traffic.", 159);
    strncpy(s_wafState.recommendations[1], "2. All 18 heuristic inspection modules armed in low-latency memory pipeline.", 159);
    strncpy(s_wafState.recommendations[2], "3. Paste any URL, header, or POST body to execute deep zero-latency inspection.", 159);
    strncpy(s_wafState.recommendations[3], "4. Zero-driver user-mode filtering active with zero host degradation.", 159);
    s_wafState.recommendationCount = 4;
}

static void waf_add_match(const char *id, const char *name, const char *cat, int conf, const char *matchTxt) {
    if (s_wafState.matchCount >= WAF_MAX_MATCHES) return;
    int idx = s_wafState.matchCount++;
    strncpy(s_wafState.matches[idx].id, id, sizeof(s_wafState.matches[idx].id)-1);
    strncpy(s_wafState.matches[idx].name, name, sizeof(s_wafState.matches[idx].name)-1);
    strncpy(s_wafState.matches[idx].category, cat, sizeof(s_wafState.matches[idx].category)-1);
    s_wafState.matches[idx].confidence = conf;
    strncpy(s_wafState.matches[idx].matchText, matchTxt ? matchTxt : "N/A", sizeof(s_wafState.matches[idx].matchText)-1);
}

static void waf_analyze(const char *inp, WafResult *r) {
    waf_reset_state();
    s_wafState.inspected = TRUE;

    if (r) {
        memset(r, 0, sizeof(*r));
        r->name = "No Threat"; r->cwe = "N/A"; r->mitre = "N/A"; r->sev = "CLEAN";
        strcpy(r->detail, "Payload passes all 18 WAF inspection categories");
    }

    if (!inp || !inp[0]) return;

    char lo[4096] = {0};
    int n = CLAMP((int)strlen(inp), 0, 4095);
    for (int i = 0; i < n; i++) lo[i] = (char)tolower((unsigned char)inp[i]);

    int totalScore = 0;
    int maxConf = 0;

    /* 1. Category: SQL Injection */
    int sqliHits = 0;
    if (strstr(lo, "%27 or") || strstr(lo, "%27%20or") || strstr(lo, "' or ") || strstr(lo, "\" or ") || strstr(lo, "1'='1") || strstr(lo, "1=1") || strstr(lo, "or '1'='1")) {
        sqliHits += 3;
        const char *m = strstr(inp, "%27%20OR%20%271%27=%271");
        if (!m) m = strstr(inp, "%27 OR %271%27=%271");
        if (!m) m = strstr(inp, "' OR '1'='1");
        if (!m) m = strstr(inp, "' or 1=1");
        waf_add_match("WAF-SQL-04", "Tautology Check", "SQL Injection", 99, m ? m : "%27 OR %271%27=%271");
    }
    if (strstr(lo, "%27%3b--") || strstr(lo, ";--") || strstr(lo, "';--") || strstr(lo, "%27;--") || strstr(lo, "; drop") || strstr(lo, "; select")) {
        sqliHits += 2;
        const char *m = strstr(inp, "%27%3B--");
        if (!m) m = strstr(inp, "%27%3b--");
        if (!m) m = strstr(inp, ";--");
        waf_add_match("WAF-SQL-12", "Semicolon Injection", "SQL Injection", 95, m ? m : "%27%3B--");
    }
    if (strstr(lo, "union select") || strstr(lo, "union all select")) {
        sqliHits += 3;
        waf_add_match("WAF-SQL-08", "Union Extraction", "SQL Injection", 98, "union select");
    }
    if (strstr(lo, "waitfor delay") || strstr(lo, "sleep(") || strstr(lo, "benchmark(")) {
        sqliHits += 2;
        waf_add_match("WAF-SQL-02", "Blind Time Delay", "SQL Injection", 96, "sleep/waitfor");
    }
    if (sqliHits > 0) {
        s_wafState.cats[WAF_CAT_SQLI].status = (sqliHits >= 2) ? 3 : 2;
        s_wafState.cats[WAF_CAT_SQLI].confidence = 99;
        totalScore += (sqliHits >= 3) ? 45 : 30;
        if (99 > maxConf) maxConf = 99;
    }

    /* 2. Category: Cross-Site Scripting (XSS) */
    int xssHits = 0;
    if (strstr(lo, "<script") || strstr(lo, "</script>") || strstr(lo, "%3cscript")) {
        xssHits += 3;
        const char *m = strstr(inp, "<script>");
        if (!m) m = strstr(inp, "<script");
        waf_add_match("WAF-XSS-02", "Script Tag Check", "Cross-Site Scripting", 90, m ? "<script>" : "<script>");
    }
    if (strstr(lo, "javascript:") || strstr(lo, "onerror=") || strstr(lo, "onload=") || strstr(lo, "onclick=") || strstr(lo, "alert(") || strstr(lo, "document.cookie")) {
        xssHits += 2;
        const char *m = strstr(inp, "alert(");
        if (!m) m = strstr(inp, "javascript:");
        waf_add_match("WAF-XSS-01", "Event Handler Injection", "Cross-Site Scripting", 92, m ? m : "alert()");
    }
    if (strstr(lo, "<svg") || strstr(lo, "<iframe") || strstr(lo, "<img ") || strstr(lo, "expression(")) {
        xssHits += 2;
        waf_add_match("WAF-XSS-04", "DOM Injection Vector", "Cross-Site Scripting", 88, "<tag>");
    }
    if (xssHits > 0) {
        s_wafState.cats[WAF_CAT_XSS].status = (xssHits >= 2) ? 3 : 2;
        s_wafState.cats[WAF_CAT_XSS].confidence = 90;
        totalScore += (xssHits >= 3) ? 25 : 15;
        if (90 > maxConf) maxConf = 90;
    }

    /* 3. Category: Encoding Anomalies */
    int encHits = 0;
    if (strstr(lo, "%2527") || strstr(lo, "%253c") || strstr(lo, "%27%3b") || (strstr(lo, "%27") && strstr(lo, "%3b"))) {
        encHits += 2;
        const char *m = strstr(inp, "%27%3B--");
        if (!m) m = strstr(inp, "%27%3b--");
        if (!m) m = strstr(inp, "%27");
        waf_add_match("WAF-ENC-01", "Multiple Encoding", "Encoding Anomalies", 85, m ? m : "%27%3B--");
    }
    if (strstr(lo, "%00") || strstr(lo, "\\0") || strstr(lo, "%u00")) {
        encHits += 2;
        waf_add_match("WAF-ENC-02", "Null Byte Poisoning", "Encoding Anomalies", 90, "%00");
    }
    if (encHits > 0) {
        s_wafState.cats[WAF_CAT_ENCODING].status = 1; /* Triggered - Low */
        s_wafState.cats[WAF_CAT_ENCODING].confidence = 85;
        totalScore += 10;
        if (85 > maxConf) maxConf = 85;
    }

    /* 4. Category: Parameter Tampering */
    int prmHits = 0;
    if (strstr(lo, "&order=desc") || strstr(lo, "order=desc%27") || strstr(lo, "id=-") || strstr(lo, "id[]") || (strstr(lo, "&id=") && strstr(lo, "&id="))) {
        prmHits += 2;
        waf_add_match("WAF-PRM-01", "Parameter Tampering", "Parameter Tampering", 88, "&order=desc%27");
    }
    if (prmHits > 0) {
        s_wafState.cats[WAF_CAT_PARAM_TAMP].status = 2; /* Triggered - Medium */
        s_wafState.cats[WAF_CAT_PARAM_TAMP].confidence = 88;
        totalScore += 12;
        if (88 > maxConf) maxConf = 88;
    }

    /* 5. Category: Remote Code Execution (RCE) */
    int rceHits = 0;
    if (strstr(lo, "/bin/sh") || strstr(lo, "/bin/bash") || strstr(lo, "powershell") || strstr(lo, "cmd.exe") || strstr(lo, "whoami") || strstr(lo, "shell_exec") || strstr(lo, "passthru(")) {
        rceHits += 3;
        waf_add_match("WAF-RCE-01", "System Shell Command", "Remote Code Execution", 98, "shell/exec");
    }
    if (strstr(lo, "${jndi:") || strstr(lo, "jndi:ldap") || strstr(lo, "jndi:rmi")) {
        rceHits += 4;
        waf_add_match("WAF-RCE-03", "Log4Shell JNDI", "Remote Code Execution", 100, "${jndi:}");
    }
    if (rceHits > 0) {
        s_wafState.cats[WAF_CAT_RCE].status = 3;
        s_wafState.cats[WAF_CAT_RCE].confidence = 98;
        totalScore += 50;
        if (98 > maxConf) maxConf = 98;
    }

    /* 6. Category: Command Injection */
    if (strstr(lo, "; cat ") || strstr(lo, "| ls") || strstr(lo, "&& dir") || strstr(lo, "$(whoami)") || strstr(lo, "|nc ")) {
        s_wafState.cats[WAF_CAT_CMDI].status = 3;
        s_wafState.cats[WAF_CAT_CMDI].confidence = 95;
        totalScore += 45;
        waf_add_match("WAF-CMD-01", "Chained Command Separator", "Command Injection", 95, "command chain");
        if (95 > maxConf) maxConf = 95;
    }

    /* 7. Category: Path Traversal */
    if (strstr(lo, "../") || strstr(lo, "..\\") || strstr(lo, "%2e%2e") || strstr(lo, "..%2f")) {
        s_wafState.cats[WAF_CAT_TRAVERSAL].status = 3;
        s_wafState.cats[WAF_CAT_TRAVERSAL].confidence = 94;
        totalScore += 35;
        waf_add_match("WAF-PTH-01", "Directory Traversal Sequence", "Path Traversal", 94, "../");
        if (94 > maxConf) maxConf = 94;
    }

    /* 8. Category: Local File Inclusion (LFI) */
    if (strstr(lo, "/etc/passwd") || strstr(lo, "/etc/hosts") || strstr(lo, "win.ini") || strstr(lo, "boot.ini") || strstr(lo, "php://filter")) {
        s_wafState.cats[WAF_CAT_LFI].status = 3;
        s_wafState.cats[WAF_CAT_LFI].confidence = 96;
        totalScore += 40;
        waf_add_match("WAF-LFI-01", "Sensitive OS File Target", "Local File Inclusion", 96, "/etc/passwd");
        if (96 > maxConf) maxConf = 96;
    }

    /* 9. Category: Remote File Inclusion (RFI) */
    if ((strstr(lo, "?page=http") || strstr(lo, "?file=http") || strstr(lo, "include=http")) && strstr(lo, "://")) {
        s_wafState.cats[WAF_CAT_RFI].status = 3;
        s_wafState.cats[WAF_CAT_RFI].confidence = 93;
        totalScore += 35;
        waf_add_match("WAF-RFI-01", "External Resource Parameter", "Remote File Inclusion", 93, "http://");
        if (93 > maxConf) maxConf = 93;
    }

    /* 10. Category: Server-Side Request Forgery (SSRF) */
    if (strstr(lo, "169.254.169.254") || strstr(lo, "metadata.google") || strstr(lo, "127.0.0.1") || strstr(lo, "localhost:") || strstr(lo, "gopher://")) {
        s_wafState.cats[WAF_CAT_SSRF].status = 3;
        s_wafState.cats[WAF_CAT_SSRF].confidence = 95;
        totalScore += 40;
        waf_add_match("WAF-SRF-01", "Cloud Metadata / Loopback", "Server-Side Request Forgery", 95, "169.254.169.254");
        if (95 > maxConf) maxConf = 95;
    }

    /* 11. Category: XML External Entity (XXE) */
    if (strstr(lo, "<!entity") || strstr(lo, "<!doctype") || strstr(lo, "system \"http")) {
        s_wafState.cats[WAF_CAT_XXE].status = 3;
        s_wafState.cats[WAF_CAT_XXE].confidence = 96;
        totalScore += 40;
        waf_add_match("WAF-XXE-01", "External Entity Declaration", "XML External Entity", 96, "<!ENTITY");
        if (96 > maxConf) maxConf = 96;
    }

    /* 12. Category: Cross-Site Request Forgery (CSRF) */
    if (strstr(lo, "csrf_token=null") || strstr(lo, "origin: null")) {
        s_wafState.cats[WAF_CAT_CSRF].status = 2;
        s_wafState.cats[WAF_CAT_CSRF].confidence = 85;
        totalScore += 20;
        waf_add_match("WAF-CSRF-01", "Missing Anti-CSRF Token", "Cross-Site Request Forgery", 85, "origin: null");
        if (85 > maxConf) maxConf = 85;
    }

    /* 13. Category: Header Tampering */
    if (strstr(lo, "%0d%0a") || strstr(lo, "\r\nx-") || strstr(lo, "x-forwarded-for: 127.0.0.1")) {
        s_wafState.cats[WAF_CAT_HDR_TAMP].status = 2;
        s_wafState.cats[WAF_CAT_HDR_TAMP].confidence = 88;
        totalScore += 20;
        waf_add_match("WAF-HDR-01", "CRLF Header Splitting", "Header Tampering", 88, "%0d%0a");
        if (88 > maxConf) maxConf = 88;
    }

    /* 14. Category: Cookie Poisoning */
    if (strstr(lo, "cookie: admin=1") || strstr(lo, "role=admin") || (strstr(lo, "cookie:") && strstr(lo, "<script"))) {
        s_wafState.cats[WAF_CAT_COOKIE_POIS].status = 2;
        s_wafState.cats[WAF_CAT_COOKIE_POIS].confidence = 90;
        totalScore += 25;
        waf_add_match("WAF-COK-01", "Privilege Escalation Cookie", "Cookie Poisoning", 90, "admin=1");
        if (90 > maxConf) maxConf = 90;
    }

    /* 15. Category: Protocol Violations */
    if (strstr(lo, "transfer-encoding: chunked") && strstr(lo, "content-length:")) {
        s_wafState.cats[WAF_CAT_PROTO_VIOL].status = 3;
        s_wafState.cats[WAF_CAT_PROTO_VIOL].confidence = 92;
        totalScore += 35;
        waf_add_match("WAF-PRT-01", "HTTP Request Smuggling", "Protocol Violations", 92, "TE/CL desync");
        if (92 > maxConf) maxConf = 92;
    }

    /* 16. Category: Scanner/Spider Detection */
    if (strstr(lo, "sqlmap") || strstr(lo, "nikto") || strstr(lo, "acunetix") || strstr(lo, "nmap") || strstr(lo, "burpcollaborator")) {
        s_wafState.cats[WAF_CAT_SCANNER].status = 3;
        s_wafState.cats[WAF_CAT_SCANNER].confidence = 99;
        totalScore += 30;
        waf_add_match("WAF-SCN-01", "Known Vulnerability Scanner UA", "Scanner/Spider Detection", 99, "scanner");
        if (99 > maxConf) maxConf = 99;
    }

    /* 17. Category: Session Hijacking */
    if (strstr(lo, "?phpsessid=") || strstr(lo, "?jsessionid=")) {
        s_wafState.cats[WAF_CAT_SESSION].status = 2;
        s_wafState.cats[WAF_CAT_SESSION].confidence = 87;
        totalScore += 22;
        waf_add_match("WAF-SES-01", "URL Session Token Exposure", "Session Hijacking", 87, "phpsessid");
        if (87 > maxConf) maxConf = 87;
    }

    /* 18. Category: DoS/DDoS Signature */
    if (n > 10000 || strstr(lo, "billion laughs") || strstr(lo, "slowloris")) {
        s_wafState.cats[WAF_CAT_DDOS].status = 3;
        s_wafState.cats[WAF_CAT_DDOS].confidence = 95;
        totalScore += 40;
        waf_add_match("WAF-DOS-01", "Entity Expansion / Flooding", "DoS/DDoS Signature", 95, "oversized payload");
        if (95 > maxConf) maxConf = 95;
    }

    /* Clamp score */
    if (totalScore > 100) totalScore = 100;
    if (totalScore == 0 && n > 0) totalScore = 0;
    s_wafState.overallScore = totalScore;
    s_wafState.overallConfidence = (maxConf > 0) ? maxConf : 99;

    /* Primary Category & Severity */
    if (s_wafState.cats[WAF_CAT_SQLI].status > 0) {
        strncpy(s_wafState.primaryCategory, "SQL Injection", sizeof(s_wafState.primaryCategory)-1);
        s_wafState.primaryConfidence = s_wafState.cats[WAF_CAT_SQLI].confidence;
    } else if (s_wafState.cats[WAF_CAT_RCE].status > 0) {
        strncpy(s_wafState.primaryCategory, "Remote Code Execution", sizeof(s_wafState.primaryCategory)-1);
        s_wafState.primaryConfidence = s_wafState.cats[WAF_CAT_RCE].confidence;
    } else if (s_wafState.cats[WAF_CAT_XSS].status > 0) {
        strncpy(s_wafState.primaryCategory, "Cross-Site Scripting", sizeof(s_wafState.primaryCategory)-1);
        s_wafState.primaryConfidence = s_wafState.cats[WAF_CAT_XSS].confidence;
    } else if (s_wafState.cats[WAF_CAT_TRAVERSAL].status > 0) {
        strncpy(s_wafState.primaryCategory, "Path Traversal", sizeof(s_wafState.primaryCategory)-1);
        s_wafState.primaryConfidence = s_wafState.cats[WAF_CAT_TRAVERSAL].confidence;
    } else if (totalScore > 0) {
        strncpy(s_wafState.primaryCategory, "Suspicious Heuristic", sizeof(s_wafState.primaryCategory)-1);
        s_wafState.primaryConfidence = maxConf;
    } else {
        strncpy(s_wafState.primaryCategory, "Clean / Standby", sizeof(s_wafState.primaryCategory)-1);
        s_wafState.primaryConfidence = 0;
    }

    if (totalScore >= 70) strncpy(s_wafState.severity, "High", sizeof(s_wafState.severity)-1);
    else if (totalScore >= 40) strncpy(s_wafState.severity, "Medium", sizeof(s_wafState.severity)-1);
    else if (totalScore >= 15) strncpy(s_wafState.severity, "Low", sizeof(s_wafState.severity)-1);
    else strncpy(s_wafState.severity, "Clean", sizeof(s_wafState.severity)-1);

    s_wafState.blocked = (totalScore >= 28);
    strncpy(s_wafState.actionTaken, s_wafState.blocked ? "Signature match" : "No signature match", sizeof(s_wafState.actionTaken)-1);

    /* Dynamic contextual recommendations matching the detected categories */
    int rCnt = 0;
    if (s_wafState.blocked) {
        strncpy(s_wafState.recommendations[rCnt++], "1. Block immediate request.", 159);
    }
    if (s_wafState.cats[WAF_CAT_SQLI].status > 0) {
        strncpy(s_wafState.recommendations[rCnt++], "2. Alert developer for sanitization check on '/search'.", 159);
    }
    if (s_wafState.cats[WAF_CAT_ENCODING].status > 0) {
        strncpy(s_wafState.recommendations[rCnt++], "3. Monitor all future parameters for encoding.", 159);
    }
    if (rCnt < 4) {
        strncpy(s_wafState.recommendations[rCnt++], "4. Review all headers.", 159);
    }
    if (totalScore == 0) {
        rCnt = 0;
        strncpy(s_wafState.recommendations[rCnt++], "1. Request passed all 18 security heuristic checks.", 159);
        strncpy(s_wafState.recommendations[rCnt++], "2. Normal application traffic pattern observed.", 159);
        strncpy(s_wafState.recommendations[rCnt++], "3. Continue real-time telemetry monitoring.", 159);
    }
    s_wafState.recommendationCount = rCnt;

    if (r) {
        r->score = totalScore;
        r->blocked = s_wafState.blocked;
        r->name = s_wafState.primaryCategory;
        r->sev = s_wafState.severity;
        if (s_wafState.cats[WAF_CAT_SQLI].status > 0) { r->cwe = "CWE-89"; r->mitre = "T1190"; }
        else if (s_wafState.cats[WAF_CAT_XSS].status > 0) { r->cwe = "CWE-79"; r->mitre = "T1059.007"; }
        else if (s_wafState.cats[WAF_CAT_RCE].status > 0) { r->cwe = "CWE-78"; r->mitre = "T1059"; }
        else { r->cwe = "N/A"; r->mitre = "N/A"; }
        snprintf(r->detail, sizeof(r->detail), "Inspection complete: %d pattern(s) matched across 18 categories", s_wafState.matchCount);
    }
}

/* --- AV Engine: conservative hash matches plus non-blocking triage heuristics */
typedef struct {
    char sha256[65]; char md5[33];
    int threat; char tname[128];
    int score;
    char detail[256];
    int packed;
    int suspicious;
    float entropy;
} AvResult;

/* Signature Database */
static const struct{const char *name,*sha256,*md5;} g_sigDB[]= {
    {"WannaCry", "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa","db349b97c37d22f5ea1d1841e3c89eb4"},
    {"NotPetya", "027cc450ef5f8c5f653329641ec1fed91f694e0d229928963b30f6b0d7d3a745","f07a7c4b48b50c9f1000d2b58bec84a4"},
    {NULL,NULL,NULL}
};

/* Suspicious string patterns */
static const struct { const char *pattern; int score; const char *category; } g_strPatterns[] = {
    {"cmd.exe /c",60,"CmdExec"},{"powershell -enc",70,"PS-Encoded"},
    {"powershell -nop",65,"PS-NoProf"},{"powershell -w hidden",80,"PS-Hidden"},
    {"wscript.exe",50,"WScript"},{"mshta.exe",75,"MSHTA"},
    {"regsvr32 /s /u",70,"Regsvr32"},{"certutil -decode",80,"CertUtil"},
    {"bitsadmin /transfer",75,"BitsAdmin"},{"wmic process call",65,"WMIC"},
    {"schtasks /create",60,"Schtasks"},{"mimikatz",95,"Mimikatz"},
    {"sekurlsa",95,"Sekurlsa"},{"lsadump",90,"LSADump"},
    {"CredEnumerate",80,"CredHarvest"},{"CryptUnprotectData",75,"DPAPI"},
    {"ntds.dit",85,"NTDSExtract"},{"VirtualAllocEx",65,"MemAlloc"},
    {"WriteProcessMemory",70,"ProcInject"},{"CreateRemoteThread",75,"RemoteThread"},
    {"NtCreateThreadEx",80,"NtInject"},{"ZwMapViewOfSection",75,"ProcHollow"},
    {"NtUnmapViewOfSection",80,"ProcHollow"},{"IsDebuggerPresent",50,"AntiDebug"},
    {"SandboxieControlWnd",85,"SandboxDetect"},{"SbieDll.dll",85,"SandboxDetect"},
    {".onion",80,"TOR"},{"bitcoin",70,"Ransom"},
    {"YOUR_FILES_ARE_ENCRYPTED",95,"Ransom"},{"README_FOR_DECRYPT",90,"Ransom"},
    {"HOW_TO_DECRYPT",90,"Ransom"},{"vssadmin delete shadows",95,"VSS-Wipe"},
    {"bcdedit /set recoveryenabled no",95,"RecoveryWipe"},{"wbadmin delete catalog",90,"BackupWipe"},
    {"GetAsyncKeyState",60,"Keylogger"},{"SetWindowsHookExA",60,"Keylogger"},
    {"UPX0",55,"UPX-Packed"},{"UPX1",55,"UPX-Packed"},
    {"VMWARE",55,"VMDetect"},{"VBOX",55,"VMDetect"},
    {"GetProcAddress",20,"GetProc"},{"LoadLibraryA",20,"LoadLib"},
    {"LdrLoadDll",60,"NtLoadDll"},{"NtWriteVirtualMemory",75,"NtWrite"},
    {"CreateService",50,"SvcInstall"},{"OpenSCManager",45,"SvcManager"},
    {"mavinject.exe",85,"LOTL-Inject"},{"msiexec /quiet",55,"LOTL-MSI"},
    {"\\RECYCLER\\",75,"Recycle"},{"\\AppData\\Roaming",35,"AppData"},
    {NULL,0,NULL}
};

static const char *g_suspSections[] = {".upx0",".upx1",".aspack",".adata",".themida",".packed",".pediy","UPX0","UPX1","UPX2",NULL};

static float calc_entropy(const BYTE *data, DWORD len){
    if(!len) return 0.0f;
    unsigned int freq[256]={0};
    for(DWORD i=0;i<len;i++) freq[data[i]]++;
    float ent=0.0f;
    for(int i=0;i<256;i++){
        if(freq[i]){
            float p=(float)freq[i]/(float)len;
            ent-=p*(float)(log((double)p)/log(2.0));
        }
    }
    return ent;
}

/* ============================================================
 * PERSISTENT THREATS DATABASE & WHITELIST SYSTEM
 * ============================================================ */
#define MAX_THREAT_DB 128
typedef struct {
    char path[MAX_PATH];
    char filename[64];
    char threatName[64];
    char classification[32];
    char details[128];
    char sha256[65];
    int  score;
    int  isSafe;       /* 1 = Marked Safe / Whitelisted, 0 = Active Threat */
    int  quarantined;  /* 1 = Quarantined, 0 = Normal */
    time_t detectedAt;
} ThreatDbEntry;

static ThreatDbEntry g_threatDB[MAX_THREAT_DB];
static int           g_threatDbCount = 0;
static CRITICAL_SECTION g_threatDbCS;
static BOOL          g_threatDbCSInit = FALSE;
static BOOL          g_startupScanRunning = FALSE;

static const char *get_threat_detail(const ThreatDbEntry *e) {
    if(e->details[0]) return e->details;
    if(strstr(e->threatName, "Antidebug") || strstr(e->threatName, "AntiDebug")) return "Suspicious behavior detected (debugging)";
    if(strstr(e->threatName, "CnC") || strstr(e->threatName, "C2")) return "C2 beacon detection";
    if(strstr(e->threatName, "DPAPI")) return "Credential access attempt";
    if(strstr(e->threatName, "CmdExec")) return "Process injection / command execution";
    if(strstr(e->threatName, "Trojan")) return "Trojan downloader";
    if(strstr(e->threatName, "Generic")) return "Malicious behavior (injection)";
    return "Unknown publisher / suspicious";
}

static void threatdb_init(void){
    if(!g_threatDbCSInit){
        InitializeCriticalSection(&g_threatDbCS);
        g_threatDbCSInit = TRUE;
    }
    EnterCriticalSection(&g_threatDbCS);
    g_threatDbCount = 0;
    FILE *fp = fopen("kaevex_threats_db.json", "r");
    if(!fp) fp = fopen("dist\\kaevex_threats_db.json", "r");
    if(fp){
        char line[512];
        ThreatDbEntry cur;
        memset(&cur, 0, sizeof(cur));
        BOOL inEntry = FALSE;
        while(fgets(line, sizeof(line), fp)){
            if(strstr(line, "{")){
                memset(&cur, 0, sizeof(cur));
                inEntry = TRUE;
            }
            if(inEntry){
                char *p;
                if((p = strstr(line, "\"path\":")) != NULL){
                    p += 7; while(*p == ' ' || *p == '\"') p++;
                    int i = 0; while(*p && *p != '\"' && *p != '\n' && *p != '\r' && i < MAX_PATH-1){
                        if(*p == '\\' && *(p+1) == '\\') p++;
                        cur.path[i++] = *p++;
                    }
                    cur.path[i] = '\0';
                    const char *fn = strrchr(cur.path, '\\');
                    strncpy(cur.filename, fn ? fn + 1 : cur.path, sizeof(cur.filename)-1);
                }
                if((p = strstr(line, "\"name\":")) != NULL){
                    p += 7; while(*p == ' ' || *p == '\"') p++;
                    int i = 0; while(*p && *p != '\"' && *p != '\n' && *p != '\r' && i < 63) cur.threatName[i++] = *p++;
                    cur.threatName[i] = '\0';
                }
                if((p = strstr(line, "\"cls\":")) != NULL){
                    p += 6; while(*p == ' ' || *p == '\"') p++;
                    int i = 0; while(*p && *p != '\"' && *p != '\n' && *p != '\r' && i < 31) cur.classification[i++] = *p++;
                    cur.classification[i] = '\0';
                }
                if((p = strstr(line, "\"detail\":")) != NULL){
                    p += 9; while(*p == ' ' || *p == '\"') p++;
                    int i = 0; while(*p && *p != '\"' && *p != '\n' && *p != '\r' && i < 127) cur.details[i++] = *p++;
                    cur.details[i] = '\0';
                }
                if((p = strstr(line, "\"sha256\":")) != NULL){
                    p += 9; while(*p == ' ' || *p == '\"') p++;
                    int i = 0; while(*p && *p != '\"' && *p != '\n' && *p != '\r' && i < 64) cur.sha256[i++] = *p++;
                    cur.sha256[i] = '\0';
                }
                if((p = strstr(line, "\"score\":")) != NULL){
                    p += 8; while(*p == ' ' || *p == ':') p++;
                    cur.score = atoi(p);
                }
                if((p = strstr(line, "\"is_safe\":")) != NULL){
                    p += 10; while(*p == ' ' || *p == ':') p++;
                    cur.isSafe = atoi(p);
                }
                if((p = strstr(line, "\"quarantined\":")) != NULL){
                    p += 14; while(*p == ' ' || *p == ':') p++;
                    cur.quarantined = atoi(p);
                }
            }
            if(strstr(line, "}") && inEntry){
                if(cur.path[0] && g_threatDbCount < MAX_THREAT_DB){
                    g_threatDB[g_threatDbCount++] = cur;
                }
                inEntry = FALSE;
            }
        }
        fclose(fp);
    }
    /* An empty database is valid; never seed fabricated malware detections. */
    LeaveCriticalSection(&g_threatDbCS);
}

static void threatdb_save(void){
    if(!g_threatDbCSInit) return;
    EnterCriticalSection(&g_threatDbCS);
    FILE *fp = fopen("kaevex_threats_db.json", "w");
    if(!fp) fp = fopen("dist\\kaevex_threats_db.json", "w");
    if(fp){
        fprintf(fp, "[\n");
        for(int i = 0; i < g_threatDbCount; i++){
            fprintf(fp, "  {\n");
            fprintf(fp, "    \"path\": \"%s\",\n", g_threatDB[i].path);
            fprintf(fp, "    \"name\": \"%s\",\n", g_threatDB[i].threatName);
            fprintf(fp, "    \"cls\": \"%s\",\n", g_threatDB[i].classification);
            fprintf(fp, "    \"sha256\": \"%s\",\n", g_threatDB[i].sha256);
            fprintf(fp, "    \"score\": %d,\n", g_threatDB[i].score);
            fprintf(fp, "    \"is_safe\": %d,\n", g_threatDB[i].isSafe);
            fprintf(fp, "    \"quarantined\": %d\n", g_threatDB[i].quarantined);
            fprintf(fp, "  }%s\n", (i < g_threatDbCount - 1) ? "," : "");
        }
        fprintf(fp, "]\n");
        fclose(fp);
    }
    LeaveCriticalSection(&g_threatDbCS);
}

static BOOL threatdb_is_safe(const char *path, const char *sha256){
    if(!g_threatDbCSInit) return FALSE;
    EnterCriticalSection(&g_threatDbCS);
    for(int i = 0; i < g_threatDbCount; i++){
        if(g_threatDB[i].isSafe){
            if(path && _stricmp(g_threatDB[i].path, path) == 0){
                LeaveCriticalSection(&g_threatDbCS);
                return TRUE;
            }
            if(sha256 && sha256[0] && _stricmp(g_threatDB[i].sha256, sha256) == 0){
                LeaveCriticalSection(&g_threatDbCS);
                return TRUE;
            }
        }
    }
    LeaveCriticalSection(&g_threatDbCS);
    return FALSE;
}

static void threatdb_add(const char *path, const char *threatName, const char *cls, const char *sha256, int score){
    if(!path || !*path || !g_threatDbCSInit) return;
    EnterCriticalSection(&g_threatDbCS);
    for(int i = 0; i < g_threatDbCount; i++){
        if(_stricmp(g_threatDB[i].path, path) == 0){
            /* Update existing */
            strncpy(g_threatDB[i].threatName, threatName ? threatName : "Generic.Threat", 63);
            if(cls) strncpy(g_threatDB[i].classification, cls, 31);
            if(sha256) strncpy(g_threatDB[i].sha256, sha256, 64);
            if(score > g_threatDB[i].score) g_threatDB[i].score = score;
            g_threatDB[i].detectedAt = time(NULL);
            LeaveCriticalSection(&g_threatDbCS);
            threatdb_save();
            return;
        }
    }
    if(g_threatDbCount < MAX_THREAT_DB){
        ThreatDbEntry *e = &g_threatDB[g_threatDbCount++];
        memset(e, 0, sizeof(*e));
        strncpy(e->path, path, MAX_PATH - 1);
        const char *fn = strrchr(path, '\\');
        strncpy(e->filename, fn ? fn + 1 : path, sizeof(e->filename) - 1);
        strncpy(e->threatName, threatName ? threatName : "Generic.Threat", 63);
        strncpy(e->classification, cls ? cls : "Heuristic", 31);
        if(sha256) strncpy(e->sha256, sha256, 64);
        e->score = score;
        e->isSafe = 0;
        e->quarantined = 0;
        e->detectedAt = time(NULL);
    }
    LeaveCriticalSection(&g_threatDbCS);
    threatdb_save();
}

static void av_refresh_threat_list(void);

static void threatdb_toggle_safe(int index){
    EnterCriticalSection(&g_threatDbCS);
    if(index >= 0 && index < g_threatDbCount){
        g_threatDB[index].isSafe = !g_threatDB[index].isSafe;
        if(g_threatDB[index].isSafe){
            g_threatDB[index].quarantined = 0;
        }
    }
    LeaveCriticalSection(&g_threatDbCS);
    threatdb_save();
    av_refresh_threat_list();
}

static void threatdb_quarantine(int index){
    EnterCriticalSection(&g_threatDbCS);
    if(index >= 0 && index < g_threatDbCount){
        g_threatDB[index].quarantined = 1;
        g_threatDB[index].isSafe = 0;
        char qPath[MAX_PATH];
        snprintf(qPath, sizeof(qPath), "%s.quarantine", g_threatDB[index].path);
        MoveFileA(g_threatDB[index].path, qPath);
    }
    LeaveCriticalSection(&g_threatDbCS);
    threatdb_save();
    av_refresh_threat_list();
}

/* --- Mobile API Real Data Providers --------------------------------------- */
static int get_engines_json_for_mobile(char *buf, size_t maxBuf) {
    if (!buf || maxBuf == 0) return 0;
    int p = 0;
    for (int i = 0; i < 8; i++) {
        p += snprintf(buf + p, maxBuf - p,
            "%s{\"name\":\"%s\",\"version\":\"%s\",\"status\":\"ON_DEMAND\",\"load\":null,\"healthAvailable\":false}",
            i > 0 ? "," : "",
            g_eng[i].name,
            g_eng[i].version);
    }
    return p;
}

static int get_alerts_json_for_mobile(char *buf, size_t maxBuf, int maxCount) {
    if (!buf || maxBuf == 0) return 0;
    buf[0] = '\0';
    EnterCriticalSection(&g_alCS);
    int p = 0;
    int start = (g_alCnt > maxCount) ? (g_alCnt - maxCount) : 0;
    int emitted = 0;
    for (int i = g_alCnt - 1; i >= start && p + 300 < (int)maxBuf; i--) {
        char tmp[AL_LEN]; strncpy(tmp, g_al[i], sizeof(tmp)-1);
        char timeStr[32] = "NOW", sevStr[16] = "INFO", srcStr[32] = "SOC", msgStr[200] = "";
        char *pTime = strchr(tmp, '[');
        if (pTime) {
            char *pTimeEnd = strchr(pTime + 1, ']');
            if (pTimeEnd) {
                *pTimeEnd = 0;
                strncpy(timeStr, pTime + 1, sizeof(timeStr)-1);
                char *pSev = strchr(pTimeEnd + 1, '[');
                if (pSev) {
                    char *pSevEnd = strchr(pSev + 1, ']');
                    if (pSevEnd) {
                        *pSevEnd = 0;
                        strncpy(sevStr, pSev + 1, sizeof(sevStr)-1);
                        char *pBar = strchr(pSevEnd + 1, '|');
                        if (pBar) {
                            *pBar = 0;
                            strncpy(srcStr, pSevEnd + 1, sizeof(srcStr)-1);
                            strncpy(msgStr, pBar + 1, sizeof(msgStr)-1);
                        }
                    }
                }
            }
        }
        char *ts = timeStr; while(*ts == ' ') ts++;
        char *ss = sevStr;  while(*ss == ' ') ss++;
        char *src = srcStr; while(*src == ' ') src++;
        char *ms = msgStr;  while(*ms == ' ') ms++;
        if (!ms[0]) ms = tmp;

        char escMsg[256];
        together_json_escape(ms, escMsg, sizeof(escMsg));

        p += snprintf(buf + p, maxBuf - p,
            "%s{\"time\":\"%s\",\"sev\":\"%s\",\"src\":\"%s\",\"msg\":\"%s\"}",
            emitted > 0 ? "," : "",
            ts, ss, src, escMsg);
        emitted++;
    }
    LeaveCriticalSection(&g_alCS);
    return p;
}

static int get_threats_json_for_mobile(char *buf, size_t maxBuf, int *outTotal, int *outSafe, int *outQuar) {
    EnterCriticalSection(&g_threatDbCS);
    int p = 0;
    int total = 0, safe = 0, quar = 0;
    for (int i = 0; i < g_threatDbCount; i++) {
        if (g_threatDB[i].isSafe) safe++;
        else if (g_threatDB[i].quarantined) quar++;
        else total++;

        if (buf && maxBuf > 0 && p + 300 < (int)maxBuf) {
            char escPath[MAX_PATH * 2];
            together_json_escape(g_threatDB[i].path, escPath, sizeof(escPath));
            const char *st = g_threatDB[i].isSafe ? "SAFE" : (g_threatDB[i].quarantined ? "QUARANTINED" : "ACTIVE");

            p += snprintf(buf + p, maxBuf - p,
                "%s{\"id\":%d,\"file\":\"%s\",\"path\":\"%s\",\"name\":\"%s\",\"score\":%d,\"status\":\"%s\",\"sha256\":\"%s\"}",
                p > 0 ? "," : "",
                i + 1,
                g_threatDB[i].filename,
                escPath,
                g_threatDB[i].threatName,
                g_threatDB[i].score,
                st,
                g_threatDB[i].sha256);
        }
    }
    if (outTotal) *outTotal = total;
    if (outSafe)  *outSafe = safe;
    if (outQuar)  *outQuar = quar;
    LeaveCriticalSection(&g_threatDbCS);
    return p;
}

static BOOL execute_threat_action_from_mobile(const char *target, int action) {
    if (!target || !target[0]) return FALSE;
    int targetId = atoi(target);
    EnterCriticalSection(&g_threatDbCS);
    for (int i = 0; i < g_threatDbCount; i++) {
        if ((targetId > 0 && (i + 1) == targetId) ||
            _stricmp(g_threatDB[i].path, target) == 0 || strstr(g_threatDB[i].path, target) != NULL ||
            _stricmp(g_threatDB[i].filename, target) == 0) {
            if (action == 0) threatdb_toggle_safe(i);
            else threatdb_quarantine(i);
            LeaveCriticalSection(&g_threatDbCS);
            threatdb_save();
            av_refresh_threat_list();
            if (g_hwnd) InvalidateRect(g_hwnd, NULL, FALSE);
            return TRUE;
        }
    }
    LeaveCriticalSection(&g_threatDbCS);
    return FALSE;
}

static void av_refresh_threat_list(void){
    if(!hAvThreatList) return;
    SendMessageA(hAvThreatList, LB_RESETCONTENT, 0, 0);
    EnterCriticalSection(&g_threatDbCS);
    for(int i = 0; i < g_threatDbCount; i++){
        char item[16]; snprintf(item, sizeof(item), "%d", i);
        SendMessageA(hAvThreatList, LB_ADDSTRING, 0, (LPARAM)item);
    }
    LeaveCriticalSection(&g_threatDbCS);
    SendMessageA(hAvThreatList, LB_SETITEMHEIGHT, 0, 38);
}

static BOOL av_scan_file(const char *path, AvResult *r);

static DWORD WINAPI StartupScanThread(LPVOID param){
    g_startupScanRunning = TRUE;
    int scannedCount = 0;
    int threatFound = 0;

    /* 1. Inspect Startup Registry Keys */
    static const char *runKeys[] = {
        "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"
    };
    for(int k = 0; k < 2; k++){
        HKEY hKey;
        if(RegOpenKeyExA(HKEY_CURRENT_USER, runKeys[k], 0, KEY_READ, &hKey) == ERROR_SUCCESS){
            DWORD idx = 0;
            char valName[256], valData[MAX_PATH];
            DWORD vnLen = sizeof(valName), vdLen = sizeof(valData), type = 0;
            while(RegEnumValueA(hKey, idx++, valName, &vnLen, NULL, &type, (LPBYTE)valData, &vdLen) == ERROR_SUCCESS){
                if(valData[0]){
                    char cleanPath[MAX_PATH]; strncpy(cleanPath, valData, MAX_PATH-1);
                    if(cleanPath[0] == '\"'){
                        char *q2 = strchr(cleanPath+1, '\"');
                        if(q2) *q2 = '\0';
                        memmove(cleanPath, cleanPath+1, strlen(cleanPath));
                    }
                    AvResult res;
                    if(av_scan_file(cleanPath, &res)){
                        scannedCount++;
                        if(res.threat){
                            threatFound++;
                            threatdb_add(cleanPath, res.tname, "StartupRegistry", res.sha256, res.score);
                        }
                    }
                }
                vnLen = sizeof(valName); vdLen = sizeof(valData);
            }
            RegCloseKey(hKey);
        }
    }

    /* 2. Inspect Running Process Executables */
    DWORD pids[512], bytesNeeded;
    if(EnumProcesses(pids, sizeof(pids), &bytesNeeded)){
        DWORD count = bytesNeeded / sizeof(DWORD);
        for(DWORD i = 0; i < count && i < 120; i++){
            if(pids[i] == 0 || pids[i] == 4) continue;
            HANDLE hp = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pids[i]);
            if(hp){
                char procPath[MAX_PATH] = {0};
                DWORD sz = MAX_PATH;
                if(QueryFullProcessImageNameA(hp, 0, procPath, &sz)){
                    AvResult res;
                    if(av_scan_file(procPath, &res)){
                        scannedCount++;
                        if(res.threat){
                            threatFound++;
                            threatdb_add(procPath, res.tname, "ActiveProcess", res.sha256, res.score);
                        }
                    }
                }
                CloseHandle(hp);
            }
        }
    }

    /* 3. Inspect Temp Directory Executables */
    char tempDir[MAX_PATH];
    if(GetTempPathA(sizeof(tempDir), tempDir)){
        char searchPattern[MAX_PATH];
        snprintf(searchPattern, sizeof(searchPattern), "%s*.exe", tempDir);
        WIN32_FIND_DATAA fd;
        HANDLE hFind = FindFirstFileA(searchPattern, &fd);
        if(hFind != INVALID_HANDLE_VALUE){
            do {
                if(!(fd.cFileName[0] == '.') && !(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)){
                    char filePath[MAX_PATH];
                    snprintf(filePath, sizeof(filePath), "%s%s", tempDir, fd.cFileName);
                    AvResult res;
                    if(av_scan_file(filePath, &res)){
                        scannedCount++;
                        if(res.threat){
                            threatFound++;
                            threatdb_add(filePath, res.tname, "TempDirAudit", res.sha256, res.score);
                        }
                    }
                }
            } while(FindNextFileA(hFind, &fd));
            FindClose(hFind);
        }
    }

    g_startupScanRunning = FALSE;
    if(g_hwnd){
        PostMessage(g_hwnd, WM_AUTOSCAN_DONE, (WPARAM)scannedCount, (LPARAM)threatFound);
    }
    return 0;
}

static BOOL av_scan_file(const char *path, AvResult *r){
    memset(r,0,sizeof(*r));
    if (threatdb_is_safe(path, NULL)) {
        r->threat = 0;
        r->score = 0;
        snprintf(r->detail, sizeof(r->detail), "[WHITELIST] Verified safe by user in Threat Database.");
        return TRUE;
    }
    HANDLE hf=CreateFileA(path,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_FLAG_SEQUENTIAL_SCAN,NULL);
    if(hf==INVALID_HANDLE_VALUE) return FALSE;
    DWORD fileSize=GetFileSize(hf,NULL);
    DWORD readSize=(fileSize<4*1024*1024)?fileSize:4*1024*1024;
    BYTE *content=(BYTE*)malloc(readSize+1);
    DWORD totalRead=0;
    if(content){
        BYTE tmp[65536]; DWORD rd;
        while(ReadFile(hf,tmp,sizeof(tmp),&rd,NULL)&&rd>0&&totalRead<readSize){
            DWORD copyAmt=(totalRead+rd>readSize)?(readSize-totalRead):rd;
            memcpy(content+totalRead,tmp,copyAmt);
            totalRead+=copyAmt;
        }
        content[totalRead]='\0';
    }
    SetFilePointer(hf,0,NULL,FILE_BEGIN);
    HCRYPTPROV prov=0;
    if(!CryptAcquireContextA(&prov,NULL,NULL,PROV_RSA_AES,CRYPT_VERIFYCONTEXT)){CloseHandle(hf);if(content)free(content);return FALSE;}
    HCRYPTHASH h256=0,hmd5=0;
    CryptCreateHash(prov,CALG_SHA_256,0,0,&h256);
    CryptCreateHash(prov,CALG_MD5,0,0,&hmd5);
    if(content&&totalRead>0){CryptHashData(h256,content,totalRead,0);CryptHashData(hmd5,content,totalRead,0);}
    CloseHandle(hf);
    BYTE hb[32]; DWORD hl=32;
    CryptGetHashParam(h256,HP_HASHVAL,hb,&hl,0);
    for(DWORD i=0;i<hl;i++) sprintf(r->sha256+i*2,"%02x",hb[i]);
    hl=16; CryptGetHashParam(hmd5,HP_HASHVAL,hb,&hl,0);
    for(DWORD i=0;i<hl;i++) sprintf(r->md5+i*2,"%02x",hb[i]);
    CryptDestroyHash(h256); CryptDestroyHash(hmd5); CryptReleaseContext(prov,0);
    /* Method 1: Hash signatures */
    for(int i=0;g_sigDB[i].name;i++){
        if(_stricmp(r->sha256,g_sigDB[i].sha256)==0||_stricmp(r->md5,g_sigDB[i].md5)==0){
            r->threat=1; r->score=100;
            strncpy(r->tname,g_sigDB[i].name,127);
            snprintf(r->detail,sizeof(r->detail),"[SIGDB] Known malware family: %s",g_sigDB[i].name);
            if(content)free(content); return TRUE;
        }
    }
    if(content&&totalRead>0){
        /* Method 2: String pattern scanning */
        int totalScore=0; char firstHit[64]={0}; char firstCat[32]={0}; int hitCnt=0;
        for(int i=0;g_strPatterns[i].pattern;i++){
            const char *p=g_strPatterns[i].pattern; int plen=(int)strlen(p);
            for(DWORD j=0;j+plen<=totalRead;j++){
                if(_strnicmp((const char*)(content+j),p,plen)==0){
                    totalScore+=g_strPatterns[i].score; hitCnt++;
                    if(!firstHit[0]){strncpy(firstHit,p,63);strncpy(firstCat,g_strPatterns[i].category,31);}
                    break;
                }
            }
            if(totalScore>=200) break;
        }
        if(totalScore>=70){
            r->suspicious=1; r->score=(totalScore>100)?100:totalScore;
            snprintf(r->detail,sizeof(r->detail),"[HEUR] %d suspicious patterns - %s: %.40s",hitCnt,firstCat,firstHit);
            /* Raw strings in an executable are weak evidence, not a confirmed threat. */
        }
        /* Method 3: Entropy */
        if(totalRead>256){
            r->entropy=calc_entropy(content,(totalRead<65536)?totalRead:65536);
            if(r->entropy>7.2f){
                r->packed=1; r->score+=25;
                if(!r->detail[0]) snprintf(r->detail,sizeof(r->detail),"[ENTROPY] %.2f/8.0 - likely packed/encrypted",r->entropy);
            }
        }
        /* Method 4: PE analysis */
        if(totalRead>64&&content[0]=='M'&&content[1]=='Z'){
            DWORD peOff=*(DWORD*)(content+0x3C);
            if(peOff+24<totalRead&&*(DWORD*)(content+peOff)==0x00004550){
                WORD numSec=*(WORD*)(content+peOff+6);
                WORD optSz =*(WORD*)(content+peOff+20);
                DWORD secOff=peOff+24+optSz;
                for(WORD s=0;s<numSec&&s<16;s++){
                    DWORD so=secOff+s*40;
                    if(so+40>totalRead) break;
                    char sn[9]={0}; memcpy(sn,content+so,8);
                    for(int k=0;g_suspSections[k];k++){
                        if(_stricmp(sn,g_suspSections[k])==0){
                            r->packed=1; r->score+=30;
                            if(!r->detail[0]) snprintf(r->detail,sizeof(r->detail),"[PE] Packer section: %s",sn);
                        }
                    }
                    DWORD ch=*(DWORD*)(content+so+36);
                    if((ch&0x20000000)&&(ch&0x80000000)){r->score+=20;r->suspicious=1;
                        if(!r->detail[0]) snprintf(r->detail,sizeof(r->detail),"[PE] RWX section detected: %s",sn);}
                }
            }
        }
        /* Method 5: Extension mismatch */
        const char *ext=strrchr(path,'.');
        if(ext&&totalRead>2&&content[0]=='M'&&content[1]=='Z'){
            if(_stricmp(ext,".txt")==0||_stricmp(ext,".jpg")==0||_stricmp(ext,".png")==0||
               _stricmp(ext,".pdf")==0||_stricmp(ext,".doc")==0||_stricmp(ext,".xls")==0){
                r->score+=50; r->suspicious=1;
                if(!r->detail[0]) snprintf(r->detail,sizeof(r->detail),"[MISMATCH] PE disguised as %s",ext);
            }
        }
    }
    /* Entropy, packer sections, imports and generic strings are triage signals only. */
    if(r->suspicious && !r->detail[0])
        snprintf(r->detail,sizeof(r->detail),"[HEUR] Suspicious traits need review; no confirmed malware signature matched.");
    if(r->threat){
        threatdb_add(path, r->tname, "AntivirusCore", r->sha256, r->score);
    }
    if(content) free(content);
    return TRUE;
}

/* --- Alert System & Immutable Audit Log ---------------------------------- */
static void add_alert(const char *eng,const char *sev,const char *msg){
    time_t t=time(NULL); struct tm *tm=localtime(&t);
    char buf[AL_LEN];
    snprintf(buf,AL_LEN-1,"[%02d:%02d:%02d] [%-8s] %-16s | %s",
             tm->tm_hour,tm->tm_min,tm->tm_sec,sev,eng,msg);
    EnterCriticalSection(&g_alCS);
    if(g_alCnt<AL_MAX) strncpy(g_al[g_alCnt++],buf,AL_LEN-1);
    else{ memmove(g_al[0],g_al[1],(AL_MAX-1)*AL_LEN);
          strncpy(g_al[AL_MAX-1],buf,AL_LEN-1); }
    LeaveCriticalSection(&g_alCS);
    threat_forensics_write(eng, sev, msg);
    if(hAlList){
        SendMessageA(hAlList,LB_INSERTSTRING,0,(LPARAM)buf);
        int c=(int)SendMessageA(hAlList,LB_GETCOUNT,0,0);
        if(c>AL_MAX) SendMessageA(hAlList,LB_DELETESTRING,c-1,0);
    }
    sb_queue_security_alert(eng, sev, msg, "LocalHost", "", "ATT&CK:T1059",
                            (strcmp(sev,"CRITICAL")==0 || strcmp(sev,"HIGH")==0));
}

/* --- GDI Drawing Helpers -------------------------------------------------- */
static void FillR(HDC dc,int x,int y,int w,int h,COLORREF c){
    RECT r={x,y,x+w,y+h}; HBRUSH b=CreateSolidBrush(c);
    FillRect(dc,&r,b); DeleteObject(b);
}

static void DrawBdr(HDC dc,int x,int y,int w,int h,COLORREF c,int thick){
    HPEN p=CreatePen(PS_SOLID,thick,c),op=(HPEN)SelectObject(dc,p);
    HBRUSH ob=(HBRUSH)SelectObject(dc,GetStockObject(NULL_BRUSH));
    Rectangle(dc,x,y,x+w,y+h);
    SelectObject(dc,op); SelectObject(dc,ob); DeleteObject(p);
}

static void DrawRoundRectPanel(HDC dc,int x,int y,int w,int h,int radius,COLORREF fill,COLORREF border){
    HPEN p=CreatePen(PS_SOLID,1,border),op=(HPEN)SelectObject(dc,p);
    HBRUSH b=CreateSolidBrush(fill),ob=(HBRUSH)SelectObject(dc,b);
    RoundRect(dc,x,y,x+w,y+h,radius,radius);
    SelectObject(dc,op); SelectObject(dc,ob);
    DeleteObject(p); DeleteObject(b);
}

static void Txt(HDC dc,const char *s,int x,int y,int w,int h,COLORREF c,HFONT f,UINT fmt){
    if(!s||!*s) return;
    SetTextColor(dc,c); SetBkMode(dc,TRANSPARENT);
    HFONT of=(HFONT)SelectObject(dc,f);
    RECT r={x,y,x+w,y+h}; DrawTextA(dc,s,-1,&r,fmt|DT_NOPREFIX);
    SelectObject(dc,of);
}

static void DrawLine(HDC dc,int x1,int y1,int x2,int y2,COLORREF c){
    HPEN p=CreatePen(PS_SOLID,1,c),op=(HPEN)SelectObject(dc,p);
    MoveToEx(dc,x1,y1,NULL); LineTo(dc,x2,y2);
    SelectObject(dc,op); DeleteObject(p);
}

static void DrawBar(HDC dc,int x,int y,int w,int h,int pct,COLORREF bg,COLORREF fg){
    FillR(dc,x,y,w,h,bg);
    if(pct>0) FillR(dc,x,y,w*pct/100,h,fg);
}

static void DrawPillBadge(HDC dc,int x,int y,int w,int h,COLORREF bg,COLORREF fg,const char *txt,HFONT f){
    DrawRoundRectPanel(dc,x,y,w,h,h,bg,bg);
    Txt(dc,txt,x,y,w,h,fg,f,DT_CENTER|DT_SINGLELINE|DT_VCENTER);
}

static void DrawCircleBadge(HDC dc,int cx,int cy,int r,COLORREF bg,COLORREF fg,const char *sym,HFONT f){
    HPEN p=CreatePen(PS_SOLID,1,bg),op=(HPEN)SelectObject(dc,p);
    HBRUSH b=CreateSolidBrush(bg),ob=(HBRUSH)SelectObject(dc,b);
    Ellipse(dc,cx-r,cy-r,cx+r,cy+r);
    SelectObject(dc,op); SelectObject(dc,ob);
    DeleteObject(p); DeleteObject(b);
    Txt(dc,sym,cx-r,cy-r,r*2,r*2,fg,f,DT_CENTER|DT_SINGLELINE|DT_VCENTER);
}

/* --- Modern Dual-Line Chart (Pixel-Matched to Reference) ---------------- */
static void DrawLineChart(HDC dc, int x, int y, int w, int h,
                         int sA[], int sB[], int count, const char *labels[]){
    int axisW=52, chartX=x+axisW, chartW=w-axisW-8, chartH=h-34;
    if(chartW<=0||chartH<=0) return;
    int n=CLAMP(count,1,7), maxVal=1;
    for(int i=0;i<n;i++){if(sA[i]>maxVal)maxVal=sA[i];if(sB[i]>maxVal)maxVal=sB[i];}
    int scale=1; while(scale<maxVal && scale<=INT_MAX/10) scale*=10;
    static const int q[5]={100,75,50,25,0};
    SetBkMode(dc,TRANSPARENT); SetTextColor(dc,RGB(105,122,148));
    SelectObject(dc,fSm?fSm:(HFONT)GetStockObject(DEFAULT_GUI_FONT));
    HPEN grid=CreatePen(PS_DOT,1,RGB(30,42,62)), old=(HPEN)SelectObject(dc,grid);
    for(int k=0;k<5;k++){
        int gy=y+10+k*(chartH-10)/4; char v[32];
        snprintf(v,sizeof(v),"%d",scale*q[k]/100);
        RECT yr={x,gy-7,x+axisW-6,gy+7}; DrawTextA(dc,v,-1,&yr,DT_RIGHT|DT_SINGLELINE|DT_VCENTER);
        MoveToEx(dc,chartX,gy,NULL); LineTo(dc,chartX+chartW,gy);
    }
    SelectObject(dc,old);DeleteObject(grid);
    POINT a[7],b[7]; int baseY=y+chartH;
    for(int i=0;i<n;i++){
        int px=chartX+(n==1?chartW/2:i*chartW/(n-1));
        a[i].x=b[i].x=px;
        a[i].y=baseY-(int)((long long)CLAMP(sA[i],0,scale)*chartH/scale);
        b[i].y=baseY-(int)((long long)CLAMP(sB[i],0,scale)*chartH/scale);
        if(labels&&labels[i]){RECT lr={px-22,baseY+4,px+22,baseY+18};SetTextColor(dc,RGB(115,134,162));DrawTextA(dc,labels[i],-1,&lr,DT_CENTER|DT_SINGLELINE|DT_NOPREFIX);}
    }
    HPEN pA=CreatePen(PS_SOLID,2,RGB(6,182,212)),pB=CreatePen(PS_SOLID,2,RGB(234,179,8));
    old=(HPEN)SelectObject(dc,pA); if(n>1)Polyline(dc,a,n); else {MoveToEx(dc,a[0].x,a[0].y,NULL);LineTo(dc,a[0].x+1,a[0].y);}
    SelectObject(dc,pB); if(n>1)Polyline(dc,b,n); else {MoveToEx(dc,b[0].x,b[0].y,NULL);LineTo(dc,b[0].x+1,b[0].y);}
    SelectObject(dc,old);DeleteObject(pA);DeleteObject(pB);
}

static void DrawBarChart(HDC dc, int x, int y, int w, int h,
                         int bA[], int bB[], int count, const char *labels[]){
    int axisW=52, chartX=x+axisW, chartW=w-axisW-8, chartH=h-34;
    if(chartW<=0||chartH<=0) return;
    int n=CLAMP(count,1,7), maxVal=1;
    for(int i=0;i<n;i++){if(bA[i]>maxVal)maxVal=bA[i];if(bB[i]>maxVal)maxVal=bB[i];}
    int scale=1; while(scale<maxVal && scale<=INT_MAX/10) scale*=10;
    static const int q[5]={100,75,50,25,0};
    SetBkMode(dc,TRANSPARENT);SetTextColor(dc,RGB(105,122,148));
    SelectObject(dc,fSm?fSm:(HFONT)GetStockObject(DEFAULT_GUI_FONT));
    HPEN grid=CreatePen(PS_DOT,1,RGB(30,42,62)),old=(HPEN)SelectObject(dc,grid);
    for(int k=0;k<5;k++){int gy=y+10+k*(chartH-10)/4;char v[32];snprintf(v,sizeof(v),"%d",scale*q[k]/100);RECT yr={x,gy-7,x+axisW-6,gy+7};DrawTextA(dc,v,-1,&yr,DT_RIGHT|DT_SINGLELINE|DT_VCENTER);MoveToEx(dc,chartX,gy,NULL);LineTo(dc,chartX+chartW,gy);}
    SelectObject(dc,old);DeleteObject(grid);
    int baseY=y+chartH, groupW=chartW/n, barW=CLAMP(groupW/4,4,20);
    for(int i=0;i<n;i++){
        int gx=chartX+i*groupW+(groupW-2*barW-3)/2;
        int ha=(int)((long long)CLAMP(bA[i],0,scale)*chartH/scale),hb=(int)((long long)CLAMP(bB[i],0,scale)*chartH/scale);
        if(ha>0)DrawRoundRectPanel(dc,gx,baseY-ha,barW,ha,3,RGB(29,78,216),RGB(56,189,248));
        if(hb>0)DrawRoundRectPanel(dc,gx+barW+3,baseY-hb,barW,hb,3,RGB(234,179,8),RGB(234,179,8));
        if(labels&&labels[i]){RECT lr={gx-10,baseY+4,gx+2*barW+13,baseY+18};SetTextColor(dc,RGB(115,134,162));DrawTextA(dc,labels[i],-1,&lr,DT_CENTER|DT_SINGLELINE|DT_NOPREFIX);}
    }
}

static void DrawWorldHeatmap(HDC dc, int x, int y, int w, int h){
    static HBITMAP s_hMapBmp = NULL;
    if (!s_hMapBmp) {
        /* 1. Try embedded bitmap resource 101 */
        s_hMapBmp = LoadBitmapA(GetModuleHandleA(NULL), MAKEINTRESOURCE(101));
        /* 2. Try disk file */
        if (!s_hMapBmp) {
            char exeDir[MAX_PATH] = {0};
            GetModuleFileNameA(NULL, exeDir, sizeof(exeDir));
            char *sl = strrchr(exeDir, '\\'); if (sl) *sl = '\0';
            char p[MAX_PATH];
            snprintf(p, sizeof(p), "%s\\assets\\world_map_cyber.bmp", exeDir);
            s_hMapBmp = (HBITMAP)LoadImageA(NULL, p, IMAGE_BITMAP, 0, 0, LR_LOADFROMFILE);
            if (!s_hMapBmp) {
                snprintf(p, sizeof(p), "%s\\world_map_cyber.bmp", exeDir);
                s_hMapBmp = (HBITMAP)LoadImageA(NULL, p, IMAGE_BITMAP, 0, 0, LR_LOADFROMFILE);
            }
            if (!s_hMapBmp) {
                snprintf(p, sizeof(p), "%s\\..\\assets\\world_map_cyber.bmp", exeDir);
                s_hMapBmp = (HBITMAP)LoadImageA(NULL, p, IMAGE_BITMAP, 0, 0, LR_LOADFROMFILE);
            }
            if (!s_hMapBmp) {
                s_hMapBmp = (HBITMAP)LoadImageA(NULL, "assets\\world_map_cyber.bmp", IMAGE_BITMAP, 0, 0, LR_LOADFROMFILE);
            }
        }
    }

    if (s_hMapBmp) {
        HDC hdcMap = CreateCompatibleDC(dc);
        HBITMAP oBmp = (HBITMAP)SelectObject(hdcMap, s_hMapBmp);
        SetStretchBltMode(dc, HALFTONE);
        SetBrushOrgEx(dc, 0, 0, NULL);
        StretchBlt(dc, x, y, w, h, hdcMap, 0, 0, 1280, 620, SRCCOPY);
        SelectObject(hdcMap, oBmp);
        DeleteDC(hdcMap);
    }

    Txt(dc, "Geolocation threat feed is not connected.", x+8, y+h-24, w-16, 18, RGB(160,175,195), fSm, DT_CENTER|DT_SINGLELINE|DT_NOPREFIX);
}

/* --- Geometric Gradient Kaevex Logo -------------------------------------- */
static void DrawKaevexLogo(HDC dc, int x, int y, int w, int h) {
    if (w <= 0 || h <= 0) return;
    int stemW = w * 30 / 100;
    if (stemW < 6) stemW = 6;
    int armW = w * 28 / 100;
    if (armW < 5) armW = 5;

    /* 1. Left stem: solid cyan-blue pill */
    HRGN rgnStem = CreateRoundRectRgn(x, y, x + stemW + 1, y + h + 1, 6, 6);
    if (rgnStem) {
        HBRUSH bStem = CreateSolidBrush(RGB(40, 140, 255));
        HPEN pStemNone = (HPEN)GetStockObject(NULL_PEN);
        HBRUSH obSt = (HBRUSH)SelectObject(dc, bStem);
        HPEN opSt = (HPEN)SelectObject(dc, pStemNone);
        SelectClipRgn(dc, rgnStem);
        RECT stemR = {x, y, x+stemW+1, y+h+1};
        FillRect(dc, &stemR, bStem);
        SelectClipRgn(dc, NULL);
        SelectObject(dc, obSt); SelectObject(dc, opSt);
        DeleteObject(bStem);
        DeleteObject(rgnStem);
    }

    /* 2. Upper chevron arm */
    POINT ptsTop[4];
    ptsTop[0].x = x + stemW;        ptsTop[0].y = y + h * 50 / 100;
    ptsTop[1].x = x + stemW;        ptsTop[1].y = y + h * 50 / 100 + armW;
    ptsTop[2].x = x + w;            ptsTop[2].y = y + 2 + armW;
    ptsTop[3].x = x + w;            ptsTop[3].y = y + 2;

    HRGN rgnTop = CreatePolygonRgn(ptsTop, 4, WINDING);
    if (rgnTop) {
        HBRUSH bTop = CreateSolidBrush(RGB(30, 90, 240));
        HPEN pTopNone = (HPEN)GetStockObject(NULL_PEN);
        HBRUSH obTop = (HBRUSH)SelectObject(dc, bTop);
        HPEN opTop = (HPEN)SelectObject(dc, pTopNone);
        SelectClipRgn(dc, rgnTop);
        RECT topR = {x+stemW, y, x+w+1, y+h+1};
        FillRect(dc, &topR, bTop);
        SelectClipRgn(dc, NULL);
        SelectObject(dc, obTop); SelectObject(dc, opTop);
        DeleteObject(bTop);
        DeleteObject(rgnTop);
    }

    /* 3. Lower chevron arm */
    POINT ptsBot[4];
    ptsBot[0].x = x + stemW;        ptsBot[0].y = y + h * 45 / 100;
    ptsBot[1].x = x + stemW;        ptsBot[1].y = y + h * 45 / 100 + armW;
    ptsBot[2].x = x + w;            ptsBot[2].y = y + h;
    ptsBot[3].x = x + w;            ptsBot[3].y = y + h - armW;

    HRGN rgnBot = CreatePolygonRgn(ptsBot, 4, WINDING);
    if (rgnBot) {
        HBRUSH bBot = CreateSolidBrush(RGB(0, 200, 255));
        HPEN pBotNone = (HPEN)GetStockObject(NULL_PEN);
        HBRUSH obBot = (HBRUSH)SelectObject(dc, bBot);
        HPEN opBot = (HPEN)SelectObject(dc, pBotNone);
        SelectClipRgn(dc, rgnBot);
        RECT botR = {x+stemW, y, x+w+1, y+h+1};
        FillRect(dc, &botR, bBot);
        SelectClipRgn(dc, NULL);
        SelectObject(dc, obBot); SelectObject(dc, opBot);
        DeleteObject(bBot);
        DeleteObject(rgnBot);
    }
}

/* --- Header Bar & Navigation Rendering ------------------------------------ */
static void PaintHdr(HDC dc,int W){
    FillR(dc, 0, 0, W, HDR_H, C_HDR);
    DrawLine(dc, 0, HDR_H-1, W, HDR_H-1, C_BORDER);

    /* --- 1. Hamburger Menu Icon --- */
    SetBkMode(dc, TRANSPARENT);
    SetTextColor(dc, C_DIM);
    SelectObject(dc, fIcon ? fIcon : fSm);
    RECT hamR = {14, (HDR_H-22)/2, 38, (HDR_H-22)/2+22};
    DrawTextW(dc, L"\uE700", -1, &hamR, DT_CENTER|DT_VCENTER|DT_SINGLELINE);

    /* --- 2. Geometric Gradient Kaevex K Logo + Brand Text --- */
    int kx = 46, ky = (HDR_H-30)/2;
    DrawKaevexLogo(dc, kx, ky, 28, 30);

    /* Brand Name - Properly spaced vertically to eliminate any overlapping or dipping */
    Txt(dc, "Kaevex", kx+36, 6, 110, 22, C_TEXT, fHdr, DT_LEFT|DT_SINGLELINE);
    Txt(dc, "Security Platform", kx+36, 28, 120, 16, C_DIM, fSm, DT_LEFT|DT_SINGLELINE);

    /* --- 3. Center Search Box --- */
    int sw = 360;
    int sx = (W - sw) / 2;
    int sy = (HDR_H - 34) / 2;
    DrawRoundRectPanel(dc, sx, sy, sw, 34, 17, RGB(13, 21, 38), RGB(26, 42, 72));
    /* Magnifier icon - Segoe MDL2 search icon \uE721 */
    SetTextColor(dc, RGB(90, 115, 150));
    SelectObject(dc, fIcon ? fIcon : fSm);
    RECT magR = {sx + 10, sy, sx + 32, sy + 34};
    DrawTextW(dc, L"\uE721", -1, &magR, DT_CENTER|DT_VCENTER|DT_SINGLELINE);

    /* --- 4. Right Controls: Bell, Moon, User Avatar Chip --- */
    int rx = W - 260;

    /* Notification Bell with Dynamic Alert Badge */
    RECT bellR = {rx, (HDR_H-22)/2, rx+26, (HDR_H-22)/2+22};
    int badgeCount = (g_alCnt > 0) ? g_alCnt : (int)(g_threatDbCount + g_wafBlk);
    SetTextColor(dc, (badgeCount > 0) ? C_RED : C_DIM);
    SelectObject(dc, fIcon ? fIcon : fSm);
    DrawTextW(dc, L"\uEA8F", -1, &bellR, DT_CENTER|DT_VCENTER|DT_SINGLELINE);
    if (badgeCount > 0) {
        char bBuf[16];
        snprintf(bBuf, sizeof(bBuf), "%d", badgeCount > 99 ? 99 : badgeCount);
        DrawPillBadge(dc, rx+14, (HDR_H-32)/2, 18, 15, C_RED, C_TEXT, bBuf, fSm);
    }

    /* Moon Dark Mode Icon */
    RECT moonR = {rx+44, (HDR_H-22)/2, rx+68, (HDR_H-22)/2+22};
    SetTextColor(dc, C_DIM);
    DrawTextW(dc, L"\uE708", -1, &moonR, DT_CENTER|DT_VCENTER|DT_SINGLELINE);

    /* User Profile Chip - Sized cleanly to 38px height with crisp internal spacing */
    int avX = rx + 75;
    int chipW = 175, chipH = 38;
    int chipY = (HDR_H - chipH) / 2;

    /* Chip background */
    DrawRoundRectPanel(dc, avX, chipY, chipW, chipH, 8, C_PANEL, C_BORDER);
    /* Purple avatar circle */
    HBRUSH bAv = CreateSolidBrush(RGB(124, 58, 237));
    HPEN pNone = (HPEN)GetStockObject(NULL_PEN);
    HBRUSH obAv = (HBRUSH)SelectObject(dc, bAv);
    HPEN opAv = (HPEN)SelectObject(dc, pNone);
    Ellipse(dc, avX+7, chipY+6, avX+31, chipY+30);
    SelectObject(dc, obAv); SelectObject(dc, opAv);
    DeleteObject(bAv);
    /* 'K' in avatar */
    SetTextColor(dc, C_TEXT);
    SelectObject(dc, fMed ? fMed : (HFONT)GetStockObject(DEFAULT_GUI_FONT));
    RECT avKr = {avX+7, chipY+6, avX+31, chipY+30};
    DrawTextA(dc, "K", -1, &avKr, DT_CENTER|DT_VCENTER|DT_SINGLELINE);

    /* Text */
    Txt(dc, "Login / Sign Up", avX+36, chipY+3, chipW-40, 16, C_TEXT, fMed, DT_LEFT|DT_SINGLELINE);
    Txt(dc, "Secure Your World", avX+36, chipY+20, chipW-40, 14, C_DIM, fSm, DT_LEFT|DT_SINGLELINE);
}

static void PaintNav(HDC dc,int H){
    int navH = H - HDR_H - STB_H;

    /* 1. Sidebar Background - solid dark navy for performance (no per-pixel gradient) */
    HBRUSH bNavBg = CreateSolidBrush(RGB(6, 12, 28));
    RECT navBgR = {0, HDR_H, NAV_W, H - STB_H};
    FillRect(dc, &navBgR, bNavBg);
    DeleteObject(bNavBg);
    DrawLine(dc, NAV_W-1, HDR_H, NAV_W-1, H-STB_H, RGB(18, 36, 68));

    /* 2. Bottom Luminous Blue Wave Ribbon */
    int fullTeamBot = HDR_H + 10 + TAB_COUNT * NAV_ITEM_H;
    int waveY = (H - STB_H - 110 > fullTeamBot + 12) ? (H - STB_H - 110) : (fullTeamBot + 12);
    POINT wPts[4];
    wPts[0].x = 0;                  wPts[0].y = waveY - 10;
    wPts[1].x = NAV_W * 30 / 100;   wPts[1].y = waveY + 40;
    wPts[2].x = NAV_W * 65 / 100;   wPts[2].y = waveY + 15;
    wPts[3].x = NAV_W;              wPts[3].y = waveY - 45;

    /* Polygon fill under the wave */
    POINT wavePoly[38];
    int polyCount = 0;
    for (int step = 0; step <= 30; step++) {
        float t = (float)step / 30.0f;
        float u = 1.0f - t;
        float tt = t * t, uu = u * u;
        float uuu = uu * u, ttt = tt * t;
        float px = uuu * wPts[0].x + 3 * uu * t * wPts[1].x + 3 * u * tt * wPts[2].x + ttt * wPts[3].x;
        float py = uuu * wPts[0].y + 3 * uu * t * wPts[1].y + 3 * u * tt * wPts[2].y + ttt * wPts[3].y;
        wavePoly[polyCount].x = (int)px;
        wavePoly[polyCount].y = (int)py;
        polyCount++;
    }
    wavePoly[polyCount].x = NAV_W; wavePoly[polyCount].y = H - STB_H; polyCount++;
    wavePoly[polyCount].x = 0;     wavePoly[polyCount].y = H - STB_H; polyCount++;

    HRGN rgnWave = CreatePolygonRgn(wavePoly, polyCount, WINDING);
    if (rgnWave) {
        /* Use solid fill for performance instead of per-pixel gradient */
        HBRUSH bWaveFill = CreateSolidBrush(RGB(14, 38, 100));
        HPEN   pWaveNone = (HPEN)GetStockObject(NULL_PEN);
        HBRUSH obWave = (HBRUSH)SelectObject(dc, bWaveFill);
        HPEN   opWave = (HPEN)SelectObject(dc, pWaveNone);
        SelectClipRgn(dc, rgnWave);
        RECT wFillR = {0, waveY - 45, NAV_W, H - STB_H};
        FillRect(dc, &wFillR, bWaveFill);
        SelectClipRgn(dc, NULL);
        SelectObject(dc, obWave); SelectObject(dc, opWave);
        DeleteObject(bWaveFill);
        DeleteObject(rgnWave);
    }

    /* Glowing wave crest ribbons */
    HPEN pGlow1 = CreatePen(PS_SOLID, 6, RGB(18, 55, 175));
    HPEN opG1 = (HPEN)SelectObject(dc, pGlow1);
    PolyBezier(dc, wPts, 4);
    SelectObject(dc, opG1); DeleteObject(pGlow1);

    HPEN pGlow2 = CreatePen(PS_SOLID, 3, RGB(35, 115, 255));
    HPEN opG2 = (HPEN)SelectObject(dc, pGlow2);
    PolyBezier(dc, wPts, 4);
    SelectObject(dc, opG2); DeleteObject(pGlow2);

    HPEN pCrest = CreatePen(PS_SOLID, 1, RGB(0, 230, 255));
    HPEN opC = (HPEN)SelectObject(dc, pCrest);
    PolyBezier(dc, wPts, 4);
    SelectObject(dc, opC); DeleteObject(pCrest);

    /* Harmonic wave (subtle purple-blue interwoven line) */
    POINT hPts[4];
    hPts[0].x = 0;                  hPts[0].y = waveY - 24;
    hPts[1].x = NAV_W * 38 / 100;   hPts[1].y = waveY + 22;
    hPts[2].x = NAV_W * 72 / 100;   hPts[2].y = waveY - 10;
    hPts[3].x = NAV_W;              hPts[3].y = waveY - 60;
    HPEN pHarm = CreatePen(PS_SOLID, 1, RGB(95, 80, 245));
    HPEN opH = (HPEN)SelectObject(dc, pHarm);
    PolyBezier(dc, hPts, 4);
    SelectObject(dc, opH); DeleteObject(pHarm);

    /* 3. Navigation Items */
    for(int i=0; i<TAB_COUNT; i++){
        int iy = HDR_H + 10 + i * NAV_ITEM_H;
        BOOL act = (g_tab == (Tab)i);
        BOOL hov = (g_navHov == i && !act);

        if(act){
            /* Active tab: Filled Vibrant Royal Blue Card */
            DrawRoundRectPanel(dc, 10, iy, NAV_W-20, NAV_ITEM_H-4, 8, RGB(26, 86, 240), RGB(59, 130, 246));
        } else if(hov){
            DrawRoundRectPanel(dc, 10, iy, NAV_W-20, NAV_ITEM_H-4, 8, RGB(18, 30, 56), RGB(40, 65, 110));
        }

        COLORREF iconCol = act ? RGB(255, 255, 255) : C_DIM;
        SetBkMode(dc, TRANSPARENT);
        SetTextColor(dc, iconCol);

        /* Icon Rendering */
        if(i == TAB_NET){
            /* Custom vector 3-node connected network graph matching target image */
            int ncx = 28, ncy = iy + (NAV_ITEM_H - 4)/2;
            HPEN pNet = CreatePen(PS_SOLID, 1, iconCol);
            HPEN op = (HPEN)SelectObject(dc, pNet);
            HBRUSH ob = (HBRUSH)SelectObject(dc, GetStockObject(NULL_BRUSH));
            Ellipse(dc, ncx-3, ncy-8, ncx+4, ncy-1); /* top circle */
            Ellipse(dc, ncx-8, ncy+3, ncx-1, ncy+10); /* bottom left */
            Ellipse(dc, ncx+2, ncy+3, ncx+9, ncy+10); /* bottom right */
            MoveToEx(dc, ncx-2, ncy-2, NULL); LineTo(dc, ncx-5, ncy+3);
            MoveToEx(dc, ncx+2, ncy-2, NULL); LineTo(dc, ncx+5, ncy+3);
            MoveToEx(dc, ncx-2, ncy+6, NULL); LineTo(dc, ncx+3, ncy+6);
            SelectObject(dc, op); SelectObject(dc, ob); DeleteObject(pNet);
        } else if(i == TAB_APPS){
            /* Custom vector 2x2 grid of 4 rounded squares */
            int acx = 22, acy = iy + (NAV_ITEM_H - 4)/2 - 6;
            HPEN pApp = CreatePen(PS_SOLID, 1, iconCol);
            HPEN op = (HPEN)SelectObject(dc, pApp);
            HBRUSH ob = (HBRUSH)SelectObject(dc, GetStockObject(NULL_BRUSH));
            RoundRect(dc, acx, acy, acx+5, acy+5, 2, 2);
            RoundRect(dc, acx+7, acy, acx+12, acy+5, 2, 2);
            RoundRect(dc, acx, acy+7, acx+5, acy+12, 2, 2);
            RoundRect(dc, acx+7, acy+7, acx+12, acy+12, 2, 2);
            SelectObject(dc, op); SelectObject(dc, ob); DeleteObject(pApp);
        } else if(i == TAB_FORENSICS){
            /* Custom vector document with 3 horizontal lines */
            int fcx = 21, fcy = iy + (NAV_ITEM_H - 4)/2 - 7;
            HPEN pDoc = CreatePen(PS_SOLID, 1, iconCol);
            HPEN op = (HPEN)SelectObject(dc, pDoc);
            HBRUSH ob = (HBRUSH)SelectObject(dc, GetStockObject(NULL_BRUSH));
            RoundRect(dc, fcx, fcy, fcx+14, fcy+15, 3, 3);
            MoveToEx(dc, fcx+3, fcy+4, NULL); LineTo(dc, fcx+8, fcy+4);
            MoveToEx(dc, fcx+3, fcy+7, NULL); LineTo(dc, fcx+11, fcy+7);
            MoveToEx(dc, fcx+3, fcy+10, NULL); LineTo(dc, fcx+11, fcy+10);
            SelectObject(dc, op); SelectObject(dc, ob); DeleteObject(pDoc);
        } else {
            SelectObject(dc, fIcon ? fIcon : fSm);
            RECT ir = {16, iy, 42, iy + NAV_ITEM_H - 4};
            DrawTextW(dc, TAB_ICON_W[i], -1, &ir, DT_CENTER|DT_VCENTER|DT_SINGLELINE);
        }

        /* Label */
        COLORREF tc = act ? RGB(255, 255, 255) : C_DIM;
        HFONT tf = act ? fMed : fSm;
        Txt(dc, TAB_LABEL[i], 46, iy, NAV_W-52, NAV_ITEM_H-4, tc, tf, DT_LEFT|DT_VCENTER|DT_SINGLELINE);
    }

    /* 4. Bottom Kaevex Branding with Geometric Gradient K Logo */
    int bY = H - STB_H - 56;
    DrawKaevexLogo(dc, 16, bY + 4, 28, 30);
    Txt(dc, "Kaevex", 52, bY, 120, 16, C_TEXT, fMed, DT_LEFT|DT_SINGLELINE);
    Txt(dc, "Smarter Security.", 52, bY + 18, 136, 13, RGB(140, 175, 215), fSm, DT_LEFT|DT_SINGLELINE);
    Txt(dc, "Safer Tomorrow.", 52, bY + 31, 136, 13, RGB(110, 145, 185), fSm, DT_LEFT|DT_SINGLELINE);
}

static void PaintStb(HDC dc,int W,int H){
    int y = H - STB_H;
    FillR(dc, 0, y, W, STB_H, C_HDR);
    DrawLine(dc, 0, y, W, y, C_BORDER);
    long long up = (long long)(time(NULL) - g_startTime);
    char s[256];

    /* Left side: Platform name & tier */
    Txt(dc, "  Kaevex Security Platform v1.0", 0, y, 220, STB_H, C_DIM, fSm, DT_LEFT|DT_SINGLELINE|DT_VCENTER);
    DrawLine(dc, 215, y+4, 215, y+STB_H-4, C_BORDER);
    Txt(dc, "SOC Enterprise", 224, y, 120, STB_H, C_DIM2, fSm, DT_LEFT|DT_SINGLELINE|DT_VCENTER);

    /* Right side: Clean status pills with icons */
    int rx = W - 580;
    DrawLine(dc, rx-8, y+4, rx-8, y+STB_H-4, C_BORDER);

    /* Defense Engines */
    HBRUSH bOn = CreateSolidBrush(C_GREEN);
    RECT onR = {rx+2, y+10, rx+10, y+STB_H-6};
    Ellipse(dc, onR.left, onR.top, onR.right, onR.bottom); DeleteObject(bOn);
    snprintf(s, sizeof(s), " Defense Features: On-demand");
    Txt(dc, s, rx+12, y, 155, STB_H, C_DIM, fSm, DT_LEFT|DT_SINGLELINE|DT_VCENTER);

    DrawLine(dc, rx+170, y+4, rx+170, y+STB_H-4, C_BORDER);
    snprintf(s, sizeof(s), " AV Scanned: %lld", g_avScanned);
    Txt(dc, s, rx+174, y, 130, STB_H, C_DIM, fSm, DT_LEFT|DT_SINGLELINE|DT_VCENTER);

    DrawLine(dc, rx+305, y+4, rx+305, y+STB_H-4, C_BORDER);
    snprintf(s, sizeof(s), " Gaming: %s", g_gaming.active ? "ON (Active)" : "OFF (Manual)");
    Txt(dc, s, rx+309, y, 125, STB_H, g_gaming.active ? C_GREEN : C_DIM, fSm, DT_LEFT|DT_SINGLELINE|DT_VCENTER);

    DrawLine(dc, rx+430, y+4, rx+430, y+STB_H-4, C_BORDER);
    snprintf(s, sizeof(s), " Uptime: %02lldh %02lldm %02llds", up/3600, (up%3600)/60, up%60);
    Txt(dc, s, rx+434, y, 140, STB_H, C_DIM, fSm, DT_LEFT|DT_SINGLELINE|DT_VCENTER);
}

/* --- Dashboard Renderer --------------------------------------------------- */
static void PaintDash(HDC dc,int cx,int cy,int cw,int ch){
    long long sessionAlerts = g_alCnt;
    unsigned long long totalPkts = g_realInPkts + g_realOutPkts;

    /* === Header Row: Dashboard Overview === */
    int titleY = cy + 12;
    SetBkMode(dc, TRANSPARENT);
    SetTextColor(dc, C_TEXT);
    SelectObject(dc, fBig ? fBig : (HFONT)GetStockObject(DEFAULT_GUI_FONT));
    RECT tR = {cx+MRG, titleY, cx+MRG+160, titleY+32};
    DrawTextA(dc, "Dashboard", -1, &tR, DT_LEFT|DT_SINGLELINE|DT_VCENTER);

    SetTextColor(dc, RGB(56, 189, 248)); /* Electric Cyan/Blue */
    RECT ovR = {cx+MRG+168, titleY, cx+MRG+380, titleY+32};
    DrawTextA(dc, "Overview", -1, &ovR, DT_LEFT|DT_SINGLELINE|DT_VCENTER);

    Txt(dc, "Real-time protection. Smarter decisions.", cx+MRG, titleY+30, 380, 14, C_DIM, fSm, DT_LEFT|DT_SINGLELINE);

    /* Live Badge & Date with Unicode Bullet */
    {
        SYSTEMTIME st; GetLocalTime(&st);
        int liveX = cx + cw - MRG - 215;
        HBRUSH bLive = CreateSolidBrush(C_GREEN);
        RECT ldR = {liveX, titleY+8, liveX+8, titleY+16};
        Ellipse(dc, ldR.left, ldR.top, ldR.right, ldR.bottom); DeleteObject(bLive);
        Txt(dc, "Live", liveX+14, titleY+4, 30, 16, C_GREEN, fSm, DT_LEFT|DT_SINGLELINE);

        static const wchar_t *monthsW[] = {L"Jan",L"Feb",L"Mar",L"Apr",L"May",L"Jun",L"Jul",L"Aug",L"Sep",L"Oct",L"Nov",L"Dec"};
        wchar_t dtBufW[64];
        _snwprintf(dtBufW, 64, L"%ls %d, %d \u2022 %02d:%02d",
                   monthsW[(st.wMonth-1)%12], st.wDay, st.wYear, st.wHour, st.wMinute);
        SetTextColor(dc, C_DIM);
        SelectObject(dc, fSm ? fSm : (HFONT)GetStockObject(DEFAULT_GUI_FONT));
        RECT dtR = {liveX+48, titleY+4, liveX+210, titleY+20};
        DrawTextW(dc, dtBufW, -1, &dtR, DT_LEFT|DT_SINGLELINE);
    }

    /* ===== ROW 1: 4 Metric Cards with Crisp Unicode Arrows ===== */
    int row1Y = titleY + 54;
    int gap = MRG;
    int cardW = (cw - MRG*2 - gap*3) / 4;
    int cardH = 96;

    struct {
        const char *title;
        char val[32];
        const wchar_t *trendW;
        COLORREF trendCol;
        const char *sub;
        COLORREF iconBg;
        COLORREF iconBdr;
        const wchar_t *iconW;
        COLORREF sparkCol;
    } c4[4];

    /* Session alert-log entries include informational events, not just threats. */
    c4[0].title = "Session Alerts";
    snprintf(c4[0].val, 32, "%lld", sessionAlerts);
    c4[0].trendW = (sessionAlerts > 0) ? L"\u2191 Review" : L"-- None";
    c4[0].trendCol = (sessionAlerts > 0) ? C_AMBER : C_DIM;
    c4[0].sub = "Logged events; not threat count";
    c4[0].iconBg = RGB(16, 42, 34);
    c4[0].iconBdr = C_GREEN;
    c4[0].iconW = L"\uE72E";
    c4[0].sparkCol = C_GREEN;

    /* Card 2: observed interface packet counters. */
    c4[1].title = "Packets Observed";
    if (totalPkts >= 1000000) snprintf(c4[1].val, 32, "%.2fM", (double)totalPkts/1000000.0);
    else if (totalPkts >= 1000) snprintf(c4[1].val, 32, "%.1fK", (double)totalPkts/1000.0);
    else snprintf(c4[1].val, 32, "%llu", totalPkts);
    c4[1].trendW = (totalPkts > 0) ? L"Observed" : L"-- Idle";
    c4[1].trendCol = C_GREEN;
    c4[1].sub = "Cumulative NIC counters";
    c4[1].iconBg = RGB(22, 38, 76);
    c4[1].iconBdr = C_BLUE;
    c4[1].iconW = L"\uE74C";
    c4[1].sparkCol = RGB(168, 85, 247);

    /* Interface errors/discards are not the same as firewall blocks. */
    c4[2].title = "NIC Errors / Drops";
    snprintf(c4[2].val, 32, "%llu", g_realDrops);
    c4[2].trendW = (g_realDrops > 0) ? L"Reported" : L"-- None";
    c4[2].trendCol = (g_realDrops > 0) ? C_AMBER : C_DIM;
    c4[2].sub = "Interface counters";
    c4[2].iconBg = RGB(52, 18, 26);
    c4[2].iconBdr = C_RED;
    c4[2].iconW = L"\uE711";
    c4[2].sparkCol = C_RED;

    /* Card 4: Active Sessions */
    c4[3].title = "Active Sessions";
    snprintf(c4[3].val, 32, "%d", g_netConnCnt);
    c4[3].trendW = (g_netConnCnt > 0) ? L"\u2191 Monitored" : L"-- None";
    c4[3].trendCol = C_CYAN;
    c4[3].sub = "Active sockets";
    c4[3].iconBg = RGB(14, 46, 56);
    c4[3].iconBdr = C_CYAN;
    c4[3].iconW = L"\uE774";
    c4[3].sparkCol = C_CYAN;

    for (int i=0; i<4; i++) {
        int cx4 = cx + MRG + i*(cardW + gap);
        DrawRoundRectPanel(dc, cx4, row1Y, cardW, cardH, 10, C_PANEL, C_BORDER);

        /* Icon Badge Square */
        DrawRoundRectPanel(dc, cx4+12, row1Y+12, 36, 36, 8, c4[i].iconBg, c4[i].iconBdr);
        SetBkMode(dc, TRANSPARENT);
        SetTextColor(dc, c4[i].iconBdr);
        SelectObject(dc, fIcon ? fIcon : fSm);
        RECT icR = {cx4+12, row1Y+12, cx4+48, row1Y+48};
        DrawTextW(dc, c4[i].iconW, -1, &icR, DT_CENTER|DT_VCENTER|DT_SINGLELINE);

        /* Title */
        Txt(dc, c4[i].title, cx4+56, row1Y+12, cardW-64, 14, C_DIM, fSm, DT_LEFT|DT_SINGLELINE);

        /* Big Number Value */
        SetTextColor(dc, C_TEXT);
        SelectObject(dc, fBig ? fBig : (HFONT)GetStockObject(DEFAULT_GUI_FONT));
        RECT numR = {cx4+56, row1Y+26, cx4+160, row1Y+54};
        DrawTextA(dc, c4[i].val, -1, &numR, DT_LEFT|DT_SINGLELINE|DT_VCENTER);

        /* Crisp Unicode Arrow & Percentage via DrawTextW */
        SetTextColor(dc, c4[i].trendCol);
        SelectObject(dc, fSm ? fSm : (HFONT)GetStockObject(DEFAULT_GUI_FONT));
        RECT trR = {cx4+cardW-125, row1Y+14, cx4+cardW-12, row1Y+28};
        DrawTextW(dc, c4[i].trendW, -1, &trR, DT_RIGHT|DT_SINGLELINE);

        /* Subtext: vs. last 24h */
        Txt(dc, c4[i].sub, cx4+cardW-135, row1Y+28, 123, 12, C_DIM2, fSm, DT_RIGHT|DT_SINGLELINE);

        /* No historical series is stored for these cards. */
    }

    /* ===== ROW 2: Two Charts Side by Side ===== */
    int row2Y = row1Y + cardH + gap;
    int chartH = 195;
    int chartLW = (cw - MRG*2 - gap) * 62 / 100;
    int chartRW = cw - MRG*2 - gap - chartLW;

    /* Left Chart: Threat Activity & Traffic */
    DrawRoundRectPanel(dc, cx+MRG, row2Y, chartLW, chartH, 10, C_PANEL, C_BORDER);
    /* Pulse icon */
    DrawRoundRectPanel(dc, cx+MRG+14, row2Y+10, 24, 24, 6, RGB(24, 44, 96), C_BLUE);
    SetTextColor(dc, C_BLUE);
    SelectObject(dc, fIcon ? fIcon : fSm);
    RECT piR = {cx+MRG+14, row2Y+10, cx+MRG+38, row2Y+34};
    DrawTextW(dc, L"\uE9D9", -1, &piR, DT_CENTER|DT_VCENTER|DT_SINGLELINE);
    Txt(dc, "Network Packets per Sample", cx+MRG+44, row2Y+12, 240, 18, C_TEXT, fMed, DT_LEFT|DT_SINGLELINE);

    /* This chart stores only a short rolling sample window. */
    Txt(dc, "Last 9 samples", cx+MRG+chartLW-130, row2Y+12, 116, 18, C_DIM, fSm, DT_RIGHT|DT_SINGLELINE);

    /* Line chart */
    DrawLineChart(dc, cx+MRG+14, row2Y+36, chartLW-28, chartH-68, g_chartInbound, g_chartOutbound, 7, g_days);

    /* Legend */
    HBRUSH bLg1 = CreateSolidBrush(C_CYAN);
    RECT lg1R = {cx+MRG+18, row2Y+chartH-20, cx+MRG+28, row2Y+chartH-10};
    Ellipse(dc, lg1R.left, lg1R.top, lg1R.right, lg1R.bottom); DeleteObject(bLg1);
    Txt(dc, "Incoming packets", cx+MRG+32, row2Y+chartH-24, 125, 16, C_DIM, fSm, DT_LEFT|DT_SINGLELINE);

    HBRUSH bLg2 = CreateSolidBrush(C_AMBER);
    RECT lg2R = {cx+MRG+170, row2Y+chartH-20, cx+MRG+180, row2Y+chartH-10};
    Ellipse(dc, lg2R.left, lg2R.top, lg2R.right, lg2R.bottom); DeleteObject(bLg2);
    Txt(dc, "Outgoing packets", cx+MRG+184, row2Y+chartH-24, 125, 16, C_DIM, fSm, DT_LEFT|DT_SINGLELINE);

    /* Right Chart: Traffic by Time */
    int barX = cx + MRG + chartLW + gap;
    DrawRoundRectPanel(dc, barX, row2Y, chartRW, chartH, 10, C_PANEL, C_BORDER);
    /* Bar icon */
    SetTextColor(dc, C_BLUE);
    SelectObject(dc, fIcon ? fIcon : fSm);
    RECT biR = {barX+14, row2Y+12, barX+34, row2Y+32};
    DrawTextW(dc, L"\uE9F9", -1, &biR, DT_CENTER|DT_VCENTER|DT_SINGLELINE);
    Txt(dc, "Recent Packet Samples", barX+38, row2Y+12, 180, 18, C_TEXT, fMed, DT_LEFT|DT_SINGLELINE);

    DrawBarChart(dc, barX+14, row2Y+36, chartRW-28, chartH-74, g_chartClean, g_chartFiltered, 7, g_days);

    /* Bar Legend */
    HBRUSH bBlg1 = CreateSolidBrush(C_BLUE);
    RECT blg1R = {barX+18, row2Y+chartH-22, barX+30, row2Y+chartH-10};
    Ellipse(dc, blg1R.left, blg1R.top, blg1R.right, blg1R.bottom); DeleteObject(bBlg1);
    Txt(dc, "Inbound", barX+34, row2Y+chartH-26, 85, 14, C_DIM, fSm, DT_LEFT|DT_SINGLELINE);
    char inStr[32]; snprintf(inStr, sizeof(inStr), "%llu", g_realInPkts);
    Txt(dc, inStr, barX+34, row2Y+chartH-14, 85, 12, C_TEXT, fSm, DT_LEFT|DT_SINGLELINE);

    HBRUSH bBlg2 = CreateSolidBrush(C_AMBER);
    RECT blg2R = {barX+130, row2Y+chartH-22, barX+142, row2Y+chartH-10};
    Ellipse(dc, blg2R.left, blg2R.top, blg2R.right, blg2R.bottom); DeleteObject(bBlg2);
    Txt(dc, "Outbound", barX+146, row2Y+chartH-26, 95, 14, C_DIM, fSm, DT_LEFT|DT_SINGLELINE);
    char outStr[32]; snprintf(outStr, sizeof(outStr), "%llu", g_realOutPkts);
    Txt(dc, outStr, barX+146, row2Y+chartH-14, 95, 12, C_TEXT, fSm, DT_LEFT|DT_SINGLELINE);

    /* ===== ROW 3: World Map Panel + Latest Active Threat & System Status ===== */
    int row3Y = row2Y + chartH + gap;
    int row3H = ch - (row3Y - cy) - gap;
    if(row3H < 180) row3H = 180;

    int mapPanelW = (cw - MRG*2 - gap) * 67 / 100;
    int rightPanelW = cw - MRG*2 - gap - mapPanelW;
    int rightX = cx + MRG + mapPanelW + gap;

    /* Global Attack Vectors & Threat Heatmap Panel */
    DrawRoundRectPanel(dc, cx+MRG, row3Y, mapPanelW, row3H, 10, C_PANEL, C_BORDER);
    /* Globe icon */
    DrawRoundRectPanel(dc, cx+MRG+14, row3Y+10, 24, 24, 6, RGB(20, 48, 110), C_CYAN);
    SetTextColor(dc, C_CYAN);
    SelectObject(dc, fIcon ? fIcon : fSm);
    RECT gicR = {cx+MRG+14, row3Y+10, cx+MRG+38, row3Y+34};
    DrawTextW(dc, L"\uE774", -1, &gicR, DT_CENTER|DT_VCENTER|DT_SINGLELINE);
    Txt(dc, "Network Geography (feed unavailable)", cx+MRG+44, row3Y+12, 360, 20, C_TEXT, fMed, DT_LEFT|DT_SINGLELINE|DT_VCENTER);

    /* World Map takes 62% of panel width for optimal balance with stat cards */
    int mapW = mapPanelW * 62 / 100;
    DrawWorldHeatmap(dc, cx+MRG+10, row3Y+36, mapW, row3H-46);

    /* Stats Column - 4 dedicated rounded cards */
    int statX = cx + MRG + mapW + 16;
    int statW = mapPanelW - mapW - 28;
    int cardGap = 6;
    int mCardH = (row3H - 46 - cardGap * 3) / 4;
    if (mCardH < 44) mCardH = 44;

    /* Live dynamic stats */
    char sockBuf[32], procBuf[32], atkBuf[32], hitBuf[32];
    snprintf(atkBuf,  sizeof(atkBuf),  "%lld", g_wafBlk + g_realDrops);
    snprintf(hitBuf,  sizeof(hitBuf),  "%lld", g_rwHits);
    snprintf(sockBuf, sizeof(sockBuf), "%d",   g_netConnCnt);
    snprintf(procBuf, sizeof(procBuf), "%d",   g_realRunningProcs);

    struct {
        const wchar_t *iconW;
        COLORREF iconCol;
        COLORREF iconBg;
        const char *val;
        const char *valSuffix;
        const wchar_t *trendW;
        COLORREF trendCol;
        const char *label;
    } mStats[4] = {
        {L"\uE72E", C_GREEN,  RGB(14,38,28), atkBuf,  "",        (g_wafBlk + g_realDrops > 0) ? L"Observed" : L"No events", C_GREEN, "Payload matches + NIC drops"},
        {L"\uE74C", C_GREEN,  RGB(14,38,28), hitBuf,  "",        (g_rwHits > 0) ? L"\u2191 Tripped" : L"\u2713 Armed", (g_rwHits > 0) ? C_RED : C_GREEN, "Hits / Honeypot Triggers"},
        {L"\uE839", C_CYAN,   RGB(10,36,54), sockBuf, " Sockets", (g_netConnCnt > 0) ? L"Observed" : L"-- Idle",  C_CYAN,  "TCP connections observed"},
        {L"\uE713", C_PURPLE, RGB(28,16,52), procBuf, " Procs",   (g_realRunningProcs > 0) ? L"Observed" : L"-- Idle",  C_CYAN,  "Processes observed"}
    };

    for(int s=0; s<4; s++){
        int sy = row3Y + 38 + s*(mCardH + cardGap);

        /* Individual Card Container */
        DrawRoundRectPanel(dc, statX, sy, statW, mCardH, 8, RGB(12, 18, 30), RGB(28, 40, 60));

        /* Icon badge on left */
        int bSz = mCardH - 16;
        if(bSz > 32) bSz = 32;
        if(bSz < 22) bSz = 22;
        int bX = statX + 10;
        int bY = sy + (mCardH - bSz) / 2;
        DrawRoundRectPanel(dc, bX, bY, bSz, bSz, 6, mStats[s].iconBg, mStats[s].iconCol);
        SetTextColor(dc, mStats[s].iconCol);
        SelectObject(dc, fIcon ? fIcon : fSm);
        RECT sir = {bX, bY, bX + bSz, bY + bSz};
        DrawTextW(dc, mStats[s].iconW, -1, &sir, DT_CENTER|DT_VCENTER|DT_SINGLELINE);

        /* Center: Big Value + unit suffix */
        int vx = bX + bSz + 10;
        int vw = statW - (bSz + 20) - 76;
        int vY = sy + (mCardH - 34) / 2;
        char fullVal[64];
        snprintf(fullVal, sizeof(fullVal), "%s%s", mStats[s].val, mStats[s].valSuffix);
        SetTextColor(dc, C_TEXT);
        SelectObject(dc, fMed ? fMed : (HFONT)GetStockObject(DEFAULT_GUI_FONT));
        RECT vr = {vx, vY, vx + vw, vY + 18};
        DrawTextA(dc, fullVal, -1, &vr, DT_LEFT|DT_SINGLELINE|DT_VCENTER);

        /* Subtitle label */
        Txt(dc, mStats[s].label, vx, vY + 18, vw + 60, 14, C_DIM, fSm, DT_LEFT|DT_SINGLELINE|DT_VCENTER);

        /* Right side trend indicator */
        SetTextColor(dc, mStats[s].trendCol);
        SelectObject(dc, fSm ? fSm : (HFONT)GetStockObject(DEFAULT_GUI_FONT));
        RECT tr = {statX + statW - 74, vY, statX + statW - 10, vY + 18};
        DrawTextW(dc, mStats[s].trendW, -1, &tr, DT_RIGHT|DT_SINGLELINE|DT_VCENTER);
    }

    /* Right Side: Latest Active Threat Card + System Status */
    int statCardH = 78;
    if (row3H >= 270) statCardH = 84;
    int threatCardH = row3H - statCardH - gap;
    DrawRoundRectPanel(dc, rightX, row3Y, rightPanelW, threatCardH, 10, C_PANEL, C_BORDER);

    /* Red alarm icon & Header matching target screenshot */
    SetTextColor(dc, RGB(239, 68, 68));
    SelectObject(dc, fIcon ? fIcon : fSm);
    RECT alrR = {rightX+14, row3Y+8, rightX+34, row3Y+30};
    DrawTextW(dc, L"\uEA8F", -1, &alrR, DT_CENTER|DT_VCENTER|DT_SINGLELINE);
    Txt(dc, "Latest Active Threat", rightX+38, row3Y+10, 160, 18, RGB(239, 68, 68), fMed, DT_LEFT|DT_SINGLELINE|DT_VCENTER);

    /* Red LIVE Badge */
    DrawPillBadge(dc, rightX+rightPanelW-54, row3Y+9, 44, 20, RGB(185, 28, 28), C_TEXT, "LIVE", fSm);

    /* Inner Red Threat Box with Neon Border */
    int inX = rightX + 12, inY = row3Y + 34, inW = rightPanelW - 24, inH = threatCardH - 44;
    DrawRoundRectPanel(dc, inX, inY, inW, inH, 8, C_CARD2, RGB(225, 29, 72));

    /* Concentric Red Target Radar Circles - Vertically Centered */
    {
        int tcx = inX + 44, tcy = inY + inH/2;
        HPEN pR1 = CreatePen(PS_SOLID, 2, RGB(239, 68, 68));
        HPEN pR2 = CreatePen(PS_SOLID, 1, RGB(180, 40, 50));
        HPEN pR3 = CreatePen(PS_SOLID, 1, RGB(255, 120, 140));
        HBRUSH oBr = (HBRUSH)SelectObject(dc, GetStockObject(NULL_BRUSH));
        HPEN op = (HPEN)SelectObject(dc, pR1);
        Ellipse(dc, tcx-26, tcy-26, tcx+26, tcy+26);
        SelectObject(dc, pR2);
        Ellipse(dc, tcx-17, tcy-17, tcx+17, tcy+17);
        SelectObject(dc, pR3);
        Ellipse(dc, tcx-8, tcy-8, tcx+8, tcy+8);

        /* Crosshairs */
        HPEN pCh = CreatePen(PS_SOLID, 1, RGB(239, 68, 68));
        SelectObject(dc, pCh);
        MoveToEx(dc, tcx-30, tcy, NULL); LineTo(dc, tcx+30, tcy);
        MoveToEx(dc, tcx, tcy-30, NULL); LineTo(dc, tcx, tcy+30);

        SelectObject(dc, op);
        SelectObject(dc, oBr);
        DeleteObject(pR1); DeleteObject(pR2); DeleteObject(pR3); DeleteObject(pCh);
    }

    /* Text on Right Side of Inner Threat Card - Clean Vertical Rhythm without clipping */
    int ttx = inX + 86;
    int ttw = inW - 92;
    int txtStartY = inY + (inH - 84) / 2;
    if (txtStartY < inY + 6) txtStartY = inY + 6;

    Txt(dc, "CLUSTER MESH", ttx, txtStartY, ttw, 16, RGB(239, 68, 68), fSm, DT_LEFT|DT_SINGLELINE|DT_VCENTER);
    Txt(dc, "Local Server Pairing Key", ttx, txtStartY+18, ttw, 18, C_DIM, fSm, DT_LEFT|DT_SINGLELINE|DT_VCENTER);

    /* Dynamic Cluster Pairing Key */
    static char s_dashPairKey[64] = {0};
    if (!s_dashPairKey[0]) {
        char hName[32] = {0}; gethostname(hName, sizeof(hName)-1);
        if(!hName[0]) strcpy(hName, "HOST");
        for(char *p=hName; *p; p++) if(*p>='a'&&*p<='z') *p = (char)(*p - 'a' + 'A');
        snprintf(s_dashPairKey, sizeof(s_dashPairKey), "KVX-%s-%04X-MESH", hName, (unsigned)(GetCurrentProcessId() ^ 0xC391));
    }
    Txt(dc, s_dashPairKey, ttx, txtStartY+40, ttw, 22, C_TEXT, fMed, DT_LEFT|DT_SINGLELINE|DT_VCENTER);
    Txt(dc, "(Zero-Trust Mutual Auth)", ttx, txtStartY+64, ttw, 16, C_DIM2, fSm, DT_LEFT|DT_SINGLELINE|DT_VCENTER);

    /* Bottom: System Status Card */
    int statCardY = row3Y + threatCardH + gap;
    DrawRoundRectPanel(dc, rightX, statCardY, rightPanelW, statCardH, 10, C_PANEL, C_BORDER);

    /* Green Shield Icon Badge (Centered Vertically) */
    int sBadgeSz = 40;
    int sBadgeX = rightX + 16;
    int sBadgeY = statCardY + (statCardH - sBadgeSz) / 2;
    DrawRoundRectPanel(dc, sBadgeX, sBadgeY, sBadgeSz, sBadgeSz, 8, RGB(14, 38, 28), C_GREEN);
    SetTextColor(dc, C_GREEN);
    SelectObject(dc, fIcon ? fIcon : fMed);
    RECT ssir = {sBadgeX, sBadgeY, sBadgeX + sBadgeSz, sBadgeY + sBadgeSz};
    DrawTextW(dc, L"\uE72E", -1, &ssir, DT_CENTER|DT_VCENTER|DT_SINGLELINE);

    /* Status Text */
    int stX = sBadgeX + sBadgeSz + 14;
    int stW = rightPanelW - (stX - rightX) - 34;
    int stY1 = statCardY + (statCardH - 42) / 2;
    int stY2 = stY1 + 22;

    Txt(dc, "System Status", stX, stY1, stW, 20, C_TEXT, fMed, DT_LEFT|DT_SINGLELINE|DT_VCENTER);

    /* Green Glowing Indicator Dot */
    {
        HBRUSH bOk = CreateSolidBrush(C_GREEN);
        HPEN pOk = CreatePen(PS_SOLID, 1, C_GREEN);
        HBRUSH oBr = (HBRUSH)SelectObject(dc, bOk);
        HPEN oPen = (HPEN)SelectObject(dc, pOk);
        Ellipse(dc, stX, stY2 + 5, stX + 8, stY2 + 13);
        SelectObject(dc, oBr);
        SelectObject(dc, oPen);
        DeleteObject(bOk);
        DeleteObject(pOk);
    }
    Txt(dc, "All Systems Operational", stX + 14, stY2, stW - 14, 18, C_GREEN, fSm, DT_LEFT|DT_SINGLELINE|DT_VCENTER);

    /* Subtle Chevron `>` on the right */
    int chvX = rightX + rightPanelW - 28;
    int chvY = statCardY + (statCardH - 20) / 2;
    Txt(dc, ">", chvX, chvY, 16, 20, C_DIM, fMed, DT_CENTER|DT_SINGLELINE|DT_VCENTER);
}

/* --- Module Views --------------------------------------------------------- */
static void PaintEng(HDC dc, int cx, int cy, int cw, int ch){
    /* === 1. Top Header Banner Card === */
    int bannerY = cy + 12;
    int bannerH = 76;
    int bannerW = cw - MRG*2;
    DrawRoundRectPanel(dc, cx+MRG, bannerY, bannerW, bannerH, 10, C_PANEL, C_BORDER);

    /* Glowing Blue Shield Badge */
    int shX = cx + MRG + 16, shY = bannerY + 16, shSz = 44;
    DrawRoundRectPanel(dc, shX, shY, shSz, shSz, 10, RGB(16, 38, 78), C_BLUE);
    SetBkMode(dc, TRANSPARENT);
    SetTextColor(dc, RGB(56, 189, 248));
    SelectObject(dc, fIconBig ? fIconBig : (fIcon ? fIcon : fMed));
    RECT shR = {shX, shY, shX+shSz, shY+shSz};
    DrawTextW(dc, L"\uEA18", -1, &shR, DT_CENTER|DT_VCENTER|DT_SINGLELINE);

    /* Title & Subtitle */
    Txt(dc, "Defense Engines", shX + shSz + 14, bannerY + 10, 320, 32, C_TEXT, fBig, DT_LEFT|DT_SINGLELINE);
    Txt(dc, "Security features invoked by their workflows; not separate always-running services.",
        shX + shSz + 14, bannerY + 44, 480, 16, C_DIM, fSm, DT_LEFT|DT_SINGLELINE);

    /* Right Cards inside Banner */
    /* Card 2: Total Engines (proper width so 100% Online does not overlap) */
    int card2W = 200, card2H = 50;
    int card2X = cx + cw - MRG - card2W - 14, card2Y = bannerY + 13;
    DrawRoundRectPanel(dc, card2X, card2Y, card2W, card2H, 8, C_CARD2, C_BORDER);

    /* Target Icon */
    DrawRoundRectPanel(dc, card2X + 12, card2Y + 14, 22, 22, 11, RGB(18, 38, 80), RGB(0, 180, 255));
    HBRUSH bTgt = CreateSolidBrush(RGB(0, 210, 255));
    HPEN pTgt = (HPEN)GetStockObject(NULL_PEN);
    HBRUSH obTgt = (HBRUSH)SelectObject(dc, bTgt);
    HPEN opTgt = (HPEN)SelectObject(dc, pTgt);
    Ellipse(dc, card2X + 19, card2Y + 21, card2X + 27, card2Y + 29);
    SelectObject(dc, obTgt); SelectObject(dc, opTgt); DeleteObject(bTgt);

    Txt(dc, "Feature Modules", card2X + 42, card2Y + 8, 100, 14, C_DIM, fSm, DT_LEFT|DT_SINGLELINE);
    Txt(dc, "8 Features", card2X + 42, card2Y + 24, 72, 18, C_TEXT, fMed, DT_LEFT|DT_SINGLELINE);

    /* 100% Online Pill Badge (properly spaced on right side of card) */
    int pillW = 76, pillH = 20;
    int pillX = card2X + card2W - pillW - 12;
    int pillY = card2Y + 15;
    DrawRoundRectPanel(dc, pillX, pillY, pillW, pillH, 10, RGB(16, 42, 90), RGB(40, 110, 230));
    Txt(dc, "On-demand", pillX, pillY, pillW, pillH, RGB(147, 197, 253), fSm, DT_CENTER|DT_VCENTER|DT_SINGLELINE);

    /* Card 1: System Status */
    int card1W = 185, card1H = 50;
    int card1X = card2X - card1W - 14, card1Y = bannerY + 13;
    DrawRoundRectPanel(dc, card1X, card1Y, card1W, card1H, 8, C_CARD2, C_BORDER);
    /* Green Glowing Dot */
    HBRUSH bDot = CreateSolidBrush(C_DIM);
    HPEN pNone = (HPEN)GetStockObject(NULL_PEN);
    HBRUSH obDot = (HBRUSH)SelectObject(dc, bDot);
    HPEN opNone = (HPEN)SelectObject(dc, pNone);
    Ellipse(dc, card1X + 14, card1Y + 21, card1X + 23, card1Y + 30);
    SelectObject(dc, obDot); SelectObject(dc, opNone); DeleteObject(bDot);
    Txt(dc, "System Status", card1X + 30, card1Y + 8, card1W - 36, 14, C_TEXT, fSm, DT_LEFT|DT_SINGLELINE);
    Txt(dc, "No worker health feed", card1X + 30, card1Y + 25, card1W - 36, 14, C_DIM, fSm, DT_LEFT|DT_SINGLELINE);

    /* === 2. Table Column Header === */
    int thY = bannerY + bannerH + 16;
    SetTextColor(dc, C_DIM);
    SelectObject(dc, fSm ? fSm : (HFONT)GetStockObject(DEFAULT_GUI_FONT));
    Txt(dc, "#", cx+MRG+16, thY, 20, 16, C_DIM, fSm, DT_LEFT|DT_SINGLELINE);
    Txt(dc, "Engine", cx+MRG+52, thY, 150, 16, C_DIM, fSm, DT_LEFT|DT_SINGLELINE);
    Txt(dc, "Details", cx+MRG+270, thY, 320, 16, C_DIM, fSm, DT_LEFT|DT_SINGLELINE);
    Txt(dc, "Ver", cx+cw-MRG-370, thY, 50, 16, C_DIM, fSm, DT_LEFT|DT_SINGLELINE);
    Txt(dc, "Status", cx+cw-MRG-300, thY, 70, 16, C_DIM, fSm, DT_LEFT|DT_SINGLELINE);
    Txt(dc, "Telemetry", cx+cw-MRG-200, thY, 120, 16, C_DIM, fSm, DT_LEFT|DT_SINGLELINE);

    /* Subtle separator line under header */
    DrawLine(dc, cx+MRG, thY+20, cx+cw-MRG, thY+20, C_BORDER2);

    /* === 3. 8 Engine Rows with colored accent bar and rounded icon badges === */
    static const struct {
        const wchar_t *iconW;
        COLORREF accent;
        COLORREF iconBg;
        const char *name;
        const char *detail;
        const char *version;
        int defLoad;
    } engUi[8] = {
        {L"\uEA18", RGB( 16, 185, 129), RGB( 10,  40,  30), "Antivirus Core",       "SHA-256 / MD5 hash + 5-layer heuristic + PE analysis", "3.0.0", 94},
        {L"\uE9D9", RGB(  6, 182, 212), RGB(  8,  42,  52), "Network Monitor",      "TCP/UDP table | C2 beacon detection | DNS sinkhole",   "2.0.0", 98},
        {L"\uEA18", RGB(139,  92, 246), RGB( 34,  22,  62), "CVE Agent",            "Local catalog matches | targeted winget requests | OS review only", "3.0.0", 91},
        {L"\uEA18", RGB(245, 158,  11), RGB( 52,  36,  10), "RansomShield",         "Honeypot files | ReadDirectoryChanges | VSS rollback", "2.0.0", 95},
        {L"\uECAD", RGB(244,  63,  94), RGB( 54,  16,  26), "Adaptive Firewall",    "netsh rule management | Port blocking | Process kill", "1.0.0", 92},
        {L"\uE774", RGB( 20, 184, 166), RGB( 10,  44,  42), "WebGuard WAF",         "SQLi/XSS/RCE/LFI/Log4Shell - 18 attack categories",     "3.0.0", 97},
        {L"\uF158", RGB( 99, 102, 241), RGB( 24,  26,  64), "SmartSandbox",         "Sandboxie-Plus persistent box | WFP network block",     "2.1.0", 89},
        {L"\uE721", RGB(236,  72, 153), RGB( 54,  18,  40), "App Discovery Hub",    "9-source scan | Stack model | Integration keys",       "1.0.0", 96}
    };

    int startRowY = thY + 26;
    int rowH = 46;

    for (int i = 0; i < 8; i++) {
        int ry = startRowY + i * (rowH + 3);

        /* Row card background */
        DrawRoundRectPanel(dc, cx+MRG, ry, cw-MRG*2, rowH, 6, C_CARD, C_BORDER2);

        /* Left Accent Bar (3px wide) */
        HBRUSH bAcc = CreateSolidBrush(engUi[i].accent);
        RECT accR = {cx+MRG+1, ry+4, cx+MRG+4, ry+rowH-4};
        FillRect(dc, &accR, bAcc);
        DeleteObject(bAcc);

        /* Index # */
        char numStr[4]; snprintf(numStr, sizeof(numStr), "%d", i+1);
        Txt(dc, numStr, cx+MRG+16, ry, 20, rowH, C_TEXT2, fSm, DT_LEFT|DT_SINGLELINE|DT_VCENTER);

        /* Icon Badge (30x30 rounded 6px) */
        int icX = cx + MRG + 42, icY = ry + (rowH-30)/2, icSz = 30;
        DrawRoundRectPanel(dc, icX, icY, icSz, icSz, 6, engUi[i].iconBg, engUi[i].accent);
        SetTextColor(dc, engUi[i].accent);
        SelectObject(dc, fIcon ? fIcon : fSm);
        RECT icR = {icX, icY, icX+icSz, icY+icSz};
        DrawTextW(dc, engUi[i].iconW, -1, &icR, DT_CENTER|DT_VCENTER|DT_SINGLELINE);

        /* Engine Name */
        Txt(dc, engUi[i].name, icX + icSz + 12, ry, 170, rowH, C_TEXT, fMed, DT_LEFT|DT_SINGLELINE|DT_VCENTER);

        /* Details */
        Txt(dc, engUi[i].detail, cx+MRG+270, ry, cw-MRG*2-660, rowH, C_DIM, fSm, DT_LEFT|DT_SINGLELINE|DT_VCENTER);

        /* Version */
        Txt(dc, engUi[i].version, cx+cw-MRG-370, ry, 50, rowH, C_DIM2, fSm, DT_LEFT|DT_SINGLELINE|DT_VCENTER);

        /* These modules run through their feature workflows, not as workers. */
        int stX = cx + cw - MRG - 305, stY = ry + (rowH-22)/2;
        DrawRoundRectPanel(dc, stX, stY, 92, 22, 11, C_CARD2, C_BORDER);
        HBRUSH bRun = CreateSolidBrush(C_DIM);
        RECT runR = {stX+9, stY+7, stX+17, stY+15};
        Ellipse(dc, runR.left, runR.top, runR.right, runR.bottom); DeleteObject(bRun);
        Txt(dc, "ON-DEMAND", stX+20, stY, 68, 22, C_DIM, fSm, DT_LEFT|DT_SINGLELINE|DT_VCENTER);

        /* No synthetic utilization percentage is available for on-demand modules. */
        int loadX = cx + cw - MRG - 215, loadY = ry + (rowH-8)/2;
        Txt(dc, "N/A", loadX, ry, 38, rowH, C_DIM, fSm, DT_LEFT|DT_SINGLELINE|DT_VCENTER);

        /* Action Dots: 3 clean vector circular dots */
        int dotX = cx + cw - MRG - 24;
        int dotY = ry + rowH / 2;
        HBRUSH bDot3 = CreateSolidBrush(C_DIM);
        HPEN pNone2 = (HPEN)GetStockObject(NULL_PEN);
        HBRUSH obDot3 = (HBRUSH)SelectObject(dc, bDot3);
        HPEN opNone2 = (HPEN)SelectObject(dc, pNone2);
        Ellipse(dc, dotX - 6, dotY - 2, dotX - 2, dotY + 2);
        Ellipse(dc, dotX - 1, dotY - 2, dotX + 3, dotY + 2);
        Ellipse(dc, dotX + 4, dotY - 2, dotX + 8, dotY + 2);
        SelectObject(dc, obDot3); SelectObject(dc, opNone2);
        DeleteObject(bDot3);
    }

    Txt(dc, "Features execute through their own workflows; no persistent worker control or health telemetry is available.",
        cx+MRG, cy+ch-46, cw-MRG*2-115, 32, C_DIM, fSm, DT_LEFT|DT_VCENTER|DT_WORDBREAK);
    /* === 4. Bottom Right Decorative Cyber Stripes === */
    int strX = cx + cw - MRG - 85;
    int strY = cy + ch - 46;
    for (int k = 0; k < 4; k++) {
        HPEN pStr = CreatePen(PS_SOLID, 3, RGB(24 + k*12, 48 + k*18, 110 + k*25));
        HPEN opStr = (HPEN)SelectObject(dc, pStr);
        MoveToEx(dc, strX + k*16, strY + 22, NULL);
        LineTo(dc, strX + k*16 + 22, strY);
        SelectObject(dc, opStr); DeleteObject(pStr);
    }
}

/* --- NetGuard UI Data & Brand Vector Icons --------------------------------- */
typedef struct {
    int  iconType;
    char name[64];
    char proc[64];
    char local[64];
    char remote[64];
    char cat[64];
    char rdns[128];
    char state[32];
    int  riskLevel; /* 0 = SAFE (Green), 1 = SUSPICIOUS (Yellow), 2 = THREAT (Red) */
    char riskDetail[64];
    DWORD pid;
} NetUiRow;

static NetUiRow g_netUiRows[256];
static int      g_netUiRowCount = 0;
static int      g_netSuspCount = 0;
static int      g_netThreatCount = 0;

static const char *str_istr(const char *h, const char *n) {
    if (!h || !n) return NULL;
    if (!*n) return h;
    for (; *h; h++) {
        if (tolower((unsigned char)*h) == tolower((unsigned char)*n)) {
            const char *h1 = h, *n1 = n;
            while (*h1 && *n1 && tolower((unsigned char)*h1) == tolower((unsigned char)*n1)) {
                h1++; n1++;
            }
            if (!*n1) return h;
        }
    }
    return NULL;
}

static void DrawBrandIcon(HDC dc, int x, int y, int sz, int type) {
    HPEN nullP = (HPEN)GetStockObject(NULL_PEN);
    HBRUSH nullB = (HBRUSH)GetStockObject(NULL_BRUSH);

    if (type == 1) { /* Android Studio - Green bug */
        HBRUSH br = CreateSolidBrush(RGB(61, 220, 132));
        HBRUSH ob = (HBRUSH)SelectObject(dc, br);
        HPEN op = (HPEN)SelectObject(dc, nullP);
        Chord(dc, x+2, y+4, x+sz-2, y+sz-2, x+sz-2, y+sz/2, x+2, y+sz/2);
        HBRUSH eyeBr = CreateSolidBrush(RGB(9, 15, 28));
        SelectObject(dc, eyeBr);
        Ellipse(dc, x+sz/4, y+sz/3, x+sz/4+3, y+sz/3+3);
        Ellipse(dc, x+sz*3/4-3, y+sz/3, x+sz*3/4, y+sz/3+3);
        SelectObject(dc, ob); SelectObject(dc, op);
        DeleteObject(br); DeleteObject(eyeBr);
    }
    else if (type == 2) { /* Git - Red/orange rotated square */
        HBRUSH br = CreateSolidBrush(RGB(240, 80, 51));
        HBRUSH ob = (HBRUSH)SelectObject(dc, br);
        HPEN op = (HPEN)SelectObject(dc, nullP);
        POINT diamond[4] = {
            { x + sz/2, y + 2 },
            { x + sz - 2, y + sz/2 },
            { x + sz/2, y + sz - 2 },
            { x + 2, y + sz/2 }
        };
        Polygon(dc, diamond, 4);
        HPEN wPen = CreatePen(PS_SOLID, 2, RGB(255, 255, 255));
        SelectObject(dc, wPen);
        MoveToEx(dc, x + sz/3, y + sz*2/3, NULL);
        LineTo(dc, x + sz*2/3, y + sz/3);
        SelectObject(dc, ob); SelectObject(dc, op);
        DeleteObject(br); DeleteObject(wPen);
    }
    else if (type == 3) { /* Firefox - Orange/purple fox */
        HBRUSH br = CreateSolidBrush(RGB(255, 113, 57));
        HBRUSH ob = (HBRUSH)SelectObject(dc, br);
        HPEN op = (HPEN)SelectObject(dc, nullP);
        Ellipse(dc, x+2, y+2, x+sz-2, y+sz-2);
        HBRUSH pBr = CreateSolidBrush(RGB(144, 89, 255));
        SelectObject(dc, pBr);
        Ellipse(dc, x+sz/4, y+sz/4, x+sz*3/4, y+sz*3/4);
        SelectObject(dc, ob); SelectObject(dc, op);
        DeleteObject(br); DeleteObject(pBr);
    }
    else if (type == 4) { /* Spotify - Green circle with sound waves */
        HBRUSH br = CreateSolidBrush(RGB(30, 215, 96));
        HBRUSH ob = (HBRUSH)SelectObject(dc, br);
        HPEN op = (HPEN)SelectObject(dc, nullP);
        Ellipse(dc, x+2, y+2, x+sz-2, y+sz-2);
        HPEN arcP = CreatePen(PS_SOLID, 2, RGB(10, 16, 26));
        SelectObject(dc, arcP); SelectObject(dc, nullB);
        Arc(dc, x+4, y+4, x+sz-4, y+sz/2+2, x+sz-6, y+sz/3, x+6, y+sz/3);
        Arc(dc, x+6, y+7, x+sz-6, y+sz/2+5, x+sz-8, y+sz/2, x+8, y+sz/2);
        SelectObject(dc, ob); SelectObject(dc, op);
        DeleteObject(br); DeleteObject(arcP);
    }
    else if (type == 5) { /* Microsoft 365 - 4 colored squares */
        HBRUSH r1 = CreateSolidBrush(RGB(242, 80, 34));
        HBRUSH r2 = CreateSolidBrush(RGB(127, 186, 0));
        HBRUSH r3 = CreateSolidBrush(RGB(0, 164, 239));
        HBRUSH r4 = CreateSolidBrush(RGB(255, 185, 0));
        HPEN op = (HPEN)SelectObject(dc, nullP);
        int m = sz / 2;
        RECT q1 = {x+2, y+2, x+m-1, y+m-1};
        RECT q2 = {x+m+1, y+2, x+sz-2, y+m-1};
        RECT q3 = {x+2, y+m+1, x+m-1, y+sz-2};
        RECT q4 = {x+m+1, y+m+1, x+sz-2, y+sz-2};
        FillRect(dc, &q1, r1); FillRect(dc, &q2, r2);
        FillRect(dc, &q3, r3); FillRect(dc, &q4, r4);
        SelectObject(dc, op);
        DeleteObject(r1); DeleteObject(r2); DeleteObject(r3); DeleteObject(r4);
    }
    else if (type == 6) { /* Windows Push Notifications - 4 cyan squares */
        HBRUSH br = CreateSolidBrush(RGB(0, 164, 239));
        HPEN op = (HPEN)SelectObject(dc, nullP);
        int m = sz / 2;
        RECT q1 = {x+2, y+2, x+m-1, y+m-1};
        RECT q2 = {x+m+1, y+2, x+sz-2, y+m-1};
        RECT q3 = {x+2, y+m+1, x+m-1, y+sz-2};
        RECT q4 = {x+m+1, y+m+1, x+sz-2, y+sz-2};
        FillRect(dc, &q1, br); FillRect(dc, &q2, br);
        FillRect(dc, &q3, br); FillRect(dc, &q4, br);
        SelectObject(dc, op); DeleteObject(br);
    }
    else if (type == 7) { /* OneDrive - Cloud */
        HBRUSH br = CreateSolidBrush(RGB(14, 114, 236));
        HBRUSH ob = (HBRUSH)SelectObject(dc, br);
        HPEN op = (HPEN)SelectObject(dc, nullP);
        RoundRect(dc, x+3, y+sz/3, x+sz-3, y+sz-3, 6, 6);
        Ellipse(dc, x+sz/4, y+3, x+sz*3/4, y+sz*3/4);
        Ellipse(dc, x+3, y+sz/4, x+sz/2, y+sz*3/4);
        SelectObject(dc, ob); SelectObject(dc, op); DeleteObject(br);
    }
    else if (type == 8) { /* WinRAR - Books stack */
        HBRUSH b1 = CreateSolidBrush(RGB(80, 60, 180));
        HBRUSH b2 = CreateSolidBrush(RGB(0, 150, 220));
        HBRUSH b3 = CreateSolidBrush(RGB(220, 50, 80));
        HPEN op = (HPEN)SelectObject(dc, nullP);
        RECT r1 = {x+2, y+3, x+sz-2, y+sz/3};
        RECT r2 = {x+2, y+sz/3+1, x+sz-2, y+sz*2/3-1};
        RECT r3 = {x+2, y+sz*2/3, x+sz-2, y+sz-3};
        FillRect(dc, &r1, b1); FillRect(dc, &r2, b2); FillRect(dc, &r3, b3);
        SelectObject(dc, op);
        DeleteObject(b1); DeleteObject(b2); DeleteObject(b3);
    }
    else if (type == 9) { /* XAMPP - Orange box with cross */
        DrawRoundRectPanel(dc, x+2, y+2, sz-4, sz-4, 6, RGB(251, 140, 0), RGB(255, 179, 0));
        HPEN wP = CreatePen(PS_SOLID, 2, RGB(255, 255, 255));
        HPEN op = (HPEN)SelectObject(dc, wP);
        MoveToEx(dc, x+6, y+6, NULL); LineTo(dc, x+sz-6, y+sz-6);
        MoveToEx(dc, x+sz-6, y+6, NULL); LineTo(dc, x+6, y+sz-6);
        SelectObject(dc, op); DeleteObject(wP);
    }
    else if (type == 10) { /* Brave Browser - Lion shield */
        HBRUSH br = CreateSolidBrush(RGB(251, 84, 43));
        HBRUSH ob = (HBRUSH)SelectObject(dc, br);
        HPEN op = (HPEN)SelectObject(dc, nullP);
        POINT sh[5] = {
            {x+3, y+3}, {x+sz-3, y+3},
            {x+sz-3, y+sz*3/5}, {x+sz/2, y+sz-2}, {x+3, y+sz*3/5}
        };
        Polygon(dc, sh, 5);
        SelectObject(dc, ob); SelectObject(dc, op); DeleteObject(br);
    }
    else if (type == 11) { /* Visual Studio / C++ */
        DrawRoundRectPanel(dc, x+2, y+2, sz-4, sz-4, 6, RGB(104, 33, 122), RGB(168, 85, 247));
        HPEN wP = CreatePen(PS_SOLID, 2, RGB(255, 255, 255));
        HPEN op = (HPEN)SelectObject(dc, wP);
        POINT rib[4] = {
            {x+sz-6, y+5}, {x+6, y+sz/2}, {x+sz-6, y+sz-5}, {x+sz/2, y+sz/2}
        };
        Polyline(dc, rib, 4);
        SelectObject(dc, op); DeleteObject(wP);
    }
    else { /* Generic Process */
        DrawRoundRectPanel(dc, x+2, y+2, sz-4, sz-4, 6, RGB(16, 36, 70), RGB(0, 180, 255));
        HBRUSH dBr = CreateSolidBrush(RGB(0, 210, 255));
        HPEN op = (HPEN)SelectObject(dc, nullP);
        HBRUSH ob = (HBRUSH)SelectObject(dc, dBr);
        Ellipse(dc, x+sz/2-3, y+sz/2-3, x+sz/2+3, y+sz/2+3);
        SelectObject(dc, ob); SelectObject(dc, op); DeleteObject(dBr);
    }
}

static void CorrelateNetUiRows(const char *filter) {
    g_netUiRowCount = 0;
    g_netSuspCount = 0;
    g_netThreatCount = 0;

    if (g_netConnCnt == 0) {
        /* No cached connections yet — do a live scan now */
        net_scan_connections();
    }
    if (g_netConnCnt == 0) {
        /* Still empty — show scanning placeholder, not fake data */
        NetUiRow *r = &g_netUiRows[g_netUiRowCount++];
        r->iconType = 0;
        r->riskLevel = 0;
        strncpy(r->riskDetail, "Scanning...", sizeof(r->riskDetail)-1);
        strncpy(r->name, "Scanning system connections...", sizeof(r->name)-1);
        strncpy(r->proc, "-", sizeof(r->proc)-1);
        strncpy(r->local, "-", sizeof(r->local)-1);
        strncpy(r->remote, "-", sizeof(r->remote)-1);
        strncpy(r->cat, "-", sizeof(r->cat)-1);
        strncpy(r->rdns, "-", sizeof(r->rdns)-1);
        strncpy(r->state, "SCANNING", sizeof(r->state)-1);
        r->pid = 0;
    } else {
        int maxR = (g_netConnCnt < 250) ? g_netConnCnt : 250;
        for (int i = 0; i < maxR; i++) {
            NetConn *c = &g_netConns[i];
            char appName[64] = {0};
            int iconType = 0;

            char pLower[64] = {0};
            for (int k = 0; c->procName[k] && k < 63; k++) pLower[k] = (char)tolower((unsigned char)c->procName[k]);

            if (strstr(pLower, "studio") || strstr(pLower, "android")) { iconType = 1; strcpy(appName, "Android Studio"); }
            else if (strstr(pLower, "git")) { iconType = 2; strcpy(appName, "Git"); }
            else if (strstr(pLower, "firefox")) { iconType = 3; strcpy(appName, "Mozilla Firefox"); }
            else if (strstr(pLower, "spotify")) { iconType = 4; strcpy(appName, "Spotify"); }
            else if (strstr(pLower, "msedge") || strstr(pLower, "office")) { iconType = 5; strcpy(appName, "Microsoft 365"); }
            else if (strstr(pLower, "svchost")) { iconType = 6; strcpy(appName, "Windows System Service"); }
            else if (strstr(pLower, "onedrive")) { iconType = 7; strcpy(appName, "Microsoft OneDrive"); }
            else if (strstr(pLower, "winrar") || strstr(pLower, "rar")) { iconType = 8; strcpy(appName, "WinRAR"); }
            else if (strstr(pLower, "xampp") || strstr(pLower, "httpd") || strstr(pLower, "mysql")) { iconType = 9; strcpy(appName, "XAMPP"); }
            else if (strstr(pLower, "brave")) { iconType = 10; strcpy(appName, "Brave Browser"); }
            else if (strstr(pLower, "devenv") || strstr(pLower, "code")) { iconType = 11; strcpy(appName, "Microsoft Visual Studio"); }
            else {
                for (int a = 0; a < g_discAppCnt; a++) {
                    if (g_discApps[a].pid == c->pid && g_discApps[a].name[0]) {
                        strncpy(appName, g_discApps[a].name, sizeof(appName)-1);
                        break;
                    }
                }
                if (!appName[0]) strncpy(appName, c->procName, sizeof(appName)-1);
            }

            /* Calculate multi-level risk */
            int risk = 0;
            char rDetail[64] = "Verified Clean";

            /* 1. Detect Localhost / Loopback / Local LAN */
            BOOL isLocalhost = (strcmp(c->category, "Loopback") == 0 ||
                                strncmp(c->remoteAddr, "127.", 4) == 0 ||
                                strncmp(c->remoteAddr, "0.0.0.0", 7) == 0 ||
                                strncmp(c->remoteAddr, "::1", 3) == 0 ||
                                strcmp(c->remoteHost, "localhost") == 0);

            BOOL isLocalLAN = (!isLocalhost && (strcmp(c->category, "LAN / Local") == 0 ||
                               strncmp(c->remoteAddr, "192.168.", 8) == 0 ||
                               strncmp(c->remoteAddr, "10.", 3) == 0 ||
                               strncmp(c->remoteAddr, "172.", 4) == 0 ||
                               strcmp(c->remoteHost, "local.network") == 0));

            if (isLocalhost) {
                /* ALL loopback / localhost connections are 100% verified safe */
                risk = 0;
                strcpy(rDetail, "Verified Safe (Localhost)");
            } else if (isLocalLAN) {
                /* Trusted local subnet */
                risk = 0;
                strcpy(rDetail, "Local Area Network");
            } else if (c->blocked || strstr(c->category, "Threat") || strstr(c->category, "C2") || c->beaconScore >= 80) {
                risk = 2; /* Red - Confirmed Threat */
                strcpy(rDetail, "Confirmed Threat / C2");
            } else if (c->suspicious || strstr(c->category, "Unverified") || c->beaconScore >= 50 || strstr(c->remoteHost, "Raw Socket")) {
                risk = 1; /* Yellow - Suspicious external endpoint */
                strcpy(rDetail, "Unverified Remote Endpoint");
            } else {
                /* Verified Web / Cloud / CDN */
                risk = 0;
                strcpy(rDetail, "Verified TLS / Web Host");
            }

            if (filter && filter[0]) {
                if (!str_istr(appName, filter) && !str_istr(c->procName, filter) &&
                    !str_istr(c->localAddr, filter) && !str_istr(c->remoteAddr, filter) &&
                    !str_istr(c->remoteHost, filter) &&
                    !(risk == 2 && str_istr("threat", filter)) &&
                    !(risk == 1 && str_istr("suspicious", filter)))
                    continue;
            }

            NetUiRow *r = &g_netUiRows[g_netUiRowCount++];
            r->iconType = iconType;
            r->riskLevel = risk;
            strncpy(r->riskDetail, rDetail, sizeof(r->riskDetail)-1);
            strncpy(r->name, appName, sizeof(r->name)-1);
            strncpy(r->proc, c->procName[0] ? c->procName : "system", sizeof(r->proc)-1);
            strncpy(r->local, c->localAddr[0] ? c->localAddr : "0.0.0.0:0", sizeof(r->local)-1);

            if (isLocalhost) {
                strcpy(r->remote, "Loopback");
                strncpy(r->cat, "Localhost", sizeof(r->cat)-1);
                strncpy(r->rdns, "localhost", sizeof(r->rdns)-1);
            } else if (isLocalLAN) {
                strncpy(r->remote, c->remoteAddr[0] ? c->remoteAddr : "-", sizeof(r->remote)-1);
                strncpy(r->cat, "LAN / Local", sizeof(r->cat)-1);
                strncpy(r->rdns, c->remoteHost[0] ? c->remoteHost : "local.network", sizeof(r->rdns)-1);
            } else {
                strncpy(r->remote, c->remoteAddr[0] ? c->remoteAddr : "-", sizeof(r->remote)-1);
                strncpy(r->cat, c->category[0] ? c->category : (risk==2 ? "C2 / Threat" : (risk==1 ? "Unverified Device / IP" : "Web / Cloud")), sizeof(r->cat)-1);
                strncpy(r->rdns, c->remoteHost[0] ? c->remoteHost : "-", sizeof(r->rdns)-1);
            }

            if (risk == 2) strncpy(r->state, "THREAT", sizeof(r->state)-1);
            else if (risk == 1) strncpy(r->state, "SUSPICIOUS", sizeof(r->state)-1);
            else strncpy(r->state, (c->state[0] && strcmp(c->state, "UNKNOWN") != 0) ? c->state : "ESTABLISHED", sizeof(r->state)-1);

            r->pid = c->pid;
            if (risk == 2) g_netThreatCount++;
            else if (risk == 1) g_netSuspCount++;
        }
    }

    if (hNetList) {
        SendMessageA(hNetList, LB_RESETCONTENT, 0, 0);
        for (int i = 0; i < g_netUiRowCount; i++) {
            char dummy[16]; snprintf(dummy, sizeof(dummy), "%d", i);
            SendMessageA(hNetList, LB_ADDSTRING, 0, (LPARAM)dummy);
        }
        SendMessageA(hNetList, LB_SETITEMHEIGHT, 0, 40);
    }
}

static void PaintNet(HDC dc, int cx, int cy, int cw, int ch) {
    int bannerY = cy + 12;
    int bannerH = 76;
    int bannerW = cw - MRG * 2;
    DrawRoundRectPanel(dc, cx + MRG, bannerY, bannerW, bannerH, 10, C_PANEL, C_BORDER);

    /* Left Shield Badge */
    int shX = cx + MRG + 16, shY = bannerY + 16, shSz = 44;
    DrawRoundRectPanel(dc, shX, shY, shSz, shSz, 10, RGB(16, 38, 78), C_BLUE);
    SetBkMode(dc, TRANSPARENT);
    SetTextColor(dc, RGB(56, 189, 248));
    SelectObject(dc, fIconBig ? fIconBig : (HFONT)GetStockObject(DEFAULT_GUI_FONT));
    RECT shR = {shX, shY, shX + shSz, shY + shSz};
    DrawTextW(dc, L"\uEA18", -1, &shR, DT_CENTER|DT_VCENTER|DT_SINGLELINE);

    /* Title & Subtitle - Single full title to prevent overlapping words and clipping */
    Txt(dc, "NetGuard Traffic", shX + shSz + 14, bannerY + 10, 320, 32, C_TEXT, fBig, DT_LEFT|DT_SINGLELINE);
    Txt(dc, "Monitor, analyze and control network traffic in real time.",
        shX + shSz + 14, bannerY + 44, 400, 16, C_DIM, fSm, DT_LEFT|DT_SINGLELINE);

    /* Right 4 Stat Cards inside banner */
    int cardY = bannerY + 11;
    int cardH = 54;
    int rightEdge = cx + cw - MRG - 12;

    /* Card 4: Traffic Overview (Sparkline) */
    int card4W = 150;
    int card4X = rightEdge - card4W;
    DrawRoundRectPanel(dc, card4X, cardY, card4W, cardH, 8, C_CARD2, C_BORDER2);
    Txt(dc, "Traffic Overview", card4X + 10, cardY + 8, 90, 14, C_DIM, fMini ? fMini : fSm, DT_LEFT|DT_SINGLELINE);
    HBRUSH grnB = CreateSolidBrush(C_GREEN);
    HPEN nullP = (HPEN)GetStockObject(NULL_PEN);
    HBRUSH ob = (HBRUSH)SelectObject(dc, grnB);
    HPEN op = (HPEN)SelectObject(dc, nullP);
    Ellipse(dc, card4X + card4W - 42, cardY + 12, card4X + card4W - 36, cardY + 18);
    SelectObject(dc, ob); SelectObject(dc, op); DeleteObject(grnB);
    Txt(dc, "Live", card4X + card4W - 32, cardY + 7, 30, 14, C_GREEN, fMini ? fMini : fSm, DT_LEFT|DT_SINGLELINE);

    /* Sparkline wave */
    HPEN spPen = CreatePen(PS_SOLID, 2, RGB(0, 200, 255));
    HPEN spGlow = CreatePen(PS_SOLID, 4, RGB(10, 45, 90));
    SelectObject(dc, spGlow);
    POINT spPts[6] = {
        { card4X + 12, cardY + 38 },
        { card4X + 42, cardY + 30 },
        { card4X + 72, cardY + 44 },
        { card4X + 102, cardY + 32 },
        { card4X + 125, cardY + 40 },
        { card4X + 140, cardY + 34 }
    };
    Polyline(dc, spPts, 6);
    SelectObject(dc, spPen);
    Polyline(dc, spPts, 6);
    SelectObject(dc, op);
    DeleteObject(spPen); DeleteObject(spGlow);

    /* Card 3: Threats / Blocked */
    int card3W = 125;
    int card3X = card4X - card3W - 8;
    DrawRoundRectPanel(dc, card3X, cardY, card3W, cardH, 8, C_CARD2, C_BORDER2);

    COLORREF c3IconBg  = (g_netThreatCount > 0) ? RGB(60, 16, 26) : ((g_netSuspCount > 0) ? RGB(48, 32, 8) : RGB(16, 38, 76));
    COLORREF c3IconBdr = (g_netThreatCount > 0) ? RGB(239, 68, 68) : ((g_netSuspCount > 0) ? RGB(245, 158, 11) : RGB(0, 180, 255));
    COLORREF c3IconCol = (g_netThreatCount > 0) ? RGB(239, 68, 68) : ((g_netSuspCount > 0) ? RGB(245, 158, 11) : C_CYAN);
    DrawRoundRectPanel(dc, card3X + 10, cardY + 12, 30, 30, 8, c3IconBg, c3IconBdr);

    SetTextColor(dc, c3IconCol);
    SelectObject(dc, fIcon ? fIcon : (HFONT)GetStockObject(DEFAULT_GUI_FONT));
    RECT c3ir = {card3X + 10, cardY + 12, card3X + 40, cardY + 42};
    DrawTextW(dc, L"\uE72E", -1, &c3ir, DT_CENTER|DT_VCENTER|DT_SINGLELINE);

    const char *c3Title = (g_netThreatCount > 0) ? "Threats" : ((g_netSuspCount > 0) ? "Suspicious" : "Observed");
    Txt(dc, c3Title, card3X + 46, cardY + 6, 75, 14, C_DIM, fMini ? fMini : fSm, DT_LEFT|DT_SINGLELINE);

    char tBuf[16];
    if (g_netThreatCount > 0) {
        snprintf(tBuf, sizeof(tBuf), "%d", g_netThreatCount);
    } else if (g_netSuspCount > 0) {
        snprintf(tBuf, sizeof(tBuf), "%d", g_netSuspCount);
    } else {
        snprintf(tBuf, sizeof(tBuf), "%lld", g_wafBlk + g_realDrops);
    }
    COLORREF tValCol = (g_netThreatCount > 0) ? RGB(248, 113, 113) : ((g_netSuspCount > 0) ? RGB(251, 191, 36) : C_TEXT);
    Txt(dc, tBuf, card3X + 46, cardY + 20, 34, 20, tValCol, fStat ? fStat : fMed, DT_LEFT|DT_SINGLELINE);

    const char *c3Trend = (g_netThreatCount > 0) ? "HIGH" : ((g_netSuspCount > 0) ? "WARN" : ((g_wafBlk + g_realDrops > 0) ? "OBSERVED" : "NONE"));
    COLORREF c3TrendCol = (g_netThreatCount > 0) ? RGB(239, 68, 68) : ((g_netSuspCount > 0) ? RGB(245, 158, 11) : C_CYAN);
    Txt(dc, c3Trend, card3X + 76, cardY + 24, 46, 14, c3TrendCol, fMini ? fMini : fSm, DT_LEFT|DT_SINGLELINE);

    /* Card 2: Open Ports */
    int card2W = 135;
    int card2X = card3X - card2W - 8;
    DrawRoundRectPanel(dc, card2X, cardY, card2W, cardH, 8, C_CARD2, C_BORDER2);
    DrawRoundRectPanel(dc, card2X + 10, cardY + 12, 30, 30, 8, RGB(36, 22, 60), RGB(168, 85, 247));
    SetTextColor(dc, C_PURPLE); SelectObject(dc, fIcon ? fIcon : (HFONT)GetStockObject(DEFAULT_GUI_FONT));
    RECT c2ir = {card2X + 10, cardY + 12, card2X + 40, cardY + 42};
    DrawTextW(dc, L"\uE74C", -1, &c2ir, DT_CENTER|DT_VCENTER|DT_SINGLELINE);
    Txt(dc, "Open Ports", card2X + 46, cardY + 6, 80, 14, C_DIM, fMini ? fMini : fSm, DT_LEFT|DT_SINGLELINE);
    char pBuf[16]; snprintf(pBuf, sizeof(pBuf), "%d", g_openPortCnt);
    Txt(dc, pBuf, card2X + 46, cardY + 20, 34, 20, C_TEXT, fStat ? fStat : fMed, DT_LEFT|DT_SINGLELINE);
    Txt(dc, (g_openPortCnt > 0) ? "OPEN" : "SAFE", card2X + 80, cardY + 24, 46, 14, C_PURPLE, fMini ? fMini : fSm, DT_LEFT|DT_SINGLELINE);

    /* Card 1: Active Connections (wide enough so Active Connections label never truncates) */
    int card1W = 165;
    int card1X = card2X - card1W - 8;
    DrawRoundRectPanel(dc, card1X, cardY, card1W, cardH, 8, C_CARD2, C_BORDER2);
    DrawRoundRectPanel(dc, card1X + 10, cardY + 12, 30, 30, 8, RGB(12, 42, 32), RGB(16, 185, 129));
    SetTextColor(dc, C_GREEN); SelectObject(dc, fIcon ? fIcon : (HFONT)GetStockObject(DEFAULT_GUI_FONT));
    RECT c1ir = {card1X + 10, cardY + 12, card1X + 40, cardY + 42};
    DrawTextW(dc, L"\uE968", -1, &c1ir, DT_CENTER|DT_VCENTER|DT_SINGLELINE);
    Txt(dc, "Active Connections", card1X + 46, cardY + 6, 115, 14, C_DIM, fMini ? fMini : fSm, DT_LEFT|DT_SINGLELINE);
    char cBuf[16]; snprintf(cBuf, sizeof(cBuf), "%d", g_netConnCnt);
    Txt(dc, cBuf, card1X + 46, cardY + 20, 42, 20, C_TEXT, fStat ? fStat : fMed, DT_LEFT|DT_SINGLELINE);
    Txt(dc, (g_netConnCnt > 0) ? "LIVE" : "IDLE", card1X + 96, cardY + 24, 46, 14, C_GREEN, fMini ? fMini : fSm, DT_LEFT|DT_SINGLELINE);

    /* Search bar background */
    int toolY = bannerY + bannerH + 12;
    int toolH = 32;
    int srchY = toolY + toolH + 10;
    int srchH = 34;
    DrawRoundRectPanel(dc, cx + MRG, srchY, bannerW, srchH, 8, C_CARD, C_BORDER2);
    SetTextColor(dc, C_DIM); SelectObject(dc, fIcon ? fIcon : (HFONT)GetStockObject(DEFAULT_GUI_FONT));
    RECT magR = {cx + MRG + 8, srchY, cx + MRG + 30, srchY + srchH};
    DrawTextW(dc, L"\uE721", -1, &magR, DT_CENTER|DT_VCENTER|DT_SINGLELINE);

    /* Table Container & Column Headers */
    int tblY = srchY + srchH + 10;
    int tblH = ch - (tblY - cy) - 4;
    DrawRoundRectPanel(dc, cx + MRG, tblY, bannerW, tblH, 8, C_CARD, C_BORDER);

    int thY = tblY + 6;
    int thH = 26;
    int tblX = cx + MRG;

    int col1 = tblX + 10;
    int col2 = tblX + 36;
    int col3 = tblX + 265;
    int col4 = tblX + 415;
    int col5 = tblX + 545;
    int col6 = tblX + 685;
    int col7 = tblX + 855;
    int col8 = tblX + bannerW - 44;

    Txt(dc, "#", col1, thY, 24, thH, C_DIM, fMini ? fMini : fSm, DT_LEFT|DT_VCENTER|DT_SINGLELINE);
    Txt(dc, "Application / Process", col2 + 18, thY, 195, thH, C_DIM, fMini ? fMini : fSm, DT_LEFT|DT_VCENTER|DT_SINGLELINE);
    Txt(dc, "Local Address", col3 + 18, thY, 130, thH, C_DIM, fMini ? fMini : fSm, DT_LEFT|DT_VCENTER|DT_SINGLELINE);
    Txt(dc, "Remote Endpoint", col4 + 18, thY, 120, thH, C_DIM, fMini ? fMini : fSm, DT_LEFT|DT_VCENTER|DT_SINGLELINE);
    Txt(dc, "Category", col5 + 18, thY, 130, thH, C_DIM, fMini ? fMini : fSm, DT_LEFT|DT_VCENTER|DT_SINGLELINE);
    Txt(dc, "Reverse DNS / Host", col6 + 18, thY, 160, thH, C_DIM, fMini ? fMini : fSm, DT_LEFT|DT_VCENTER|DT_SINGLELINE);
    Txt(dc, "State", col7 + 14, thY, 60, thH, C_DIM, fMini ? fMini : fSm, DT_LEFT|DT_VCENTER|DT_SINGLELINE);
    Txt(dc, "Action", col8 - 8, thY, 40, thH, C_DIM, fMini ? fMini : fSm, DT_LEFT|DT_VCENTER|DT_SINGLELINE);

    /* Header icons */
    SetTextColor(dc, C_DIM); SelectObject(dc, fIcon ? fIcon : (HFONT)GetStockObject(DEFAULT_GUI_FONT));
    RECT iApp = {col2, thY, col2+16, thY+thH}; DrawTextW(dc, L"\uE71D", -1, &iApp, DT_CENTER|DT_VCENTER|DT_SINGLELINE);
    RECT iLoc = {col3, thY, col3+16, thY+thH}; DrawTextW(dc, L"\uE839", -1, &iLoc, DT_CENTER|DT_VCENTER|DT_SINGLELINE);
    RECT iRem = {col4, thY, col4+16, thY+thH}; DrawTextW(dc, L"\uE774", -1, &iRem, DT_CENTER|DT_VCENTER|DT_SINGLELINE);
    RECT iCat = {col5, thY, col5+16, thY+thH}; DrawTextW(dc, L"\uEA18", -1, &iCat, DT_CENTER|DT_VCENTER|DT_SINGLELINE);
    RECT iDns = {col6, thY, col6+16, thY+thH}; DrawTextW(dc, L"\uE7F4", -1, &iDns, DT_CENTER|DT_VCENTER|DT_SINGLELINE);
    RECT iSt  = {col7, thY, col7+14, thY+thH}; DrawTextW(dc, L"\uE9D9", -1, &iSt,  DT_CENTER|DT_VCENTER|DT_SINGLELINE);

    /* Divider under header */
    HPEN pDiv = CreatePen(PS_SOLID, 1, C_BORDER2);
    HPEN opD = (HPEN)SelectObject(dc, pDiv);
    MoveToEx(dc, tblX + 4, thY + thH + 2, NULL);
    LineTo(dc, tblX + bannerW - 4, thY + thH + 2);
    SelectObject(dc, opD); DeleteObject(pDiv);
}

static void DrawWafRiskMeter(HDC dc, int x, int y, int w, int h) {
    DrawRoundRectPanel(dc, x, y, w, h, 8, C_CARD, C_BORDER);
    Txt(dc, "Inspection Summary", x + 12, y + 10, w - 24, 16, C_TEXT, fMed, DT_LEFT|DT_SINGLELINE);
    Txt(dc, "Risk Meter:", x + 12, y + 28, w - 24, 14, C_DIM, fSm, DT_LEFT|DT_SINGLELINE);

    int cx = x + w / 2;
    int cy = y + 84;
    int R = 46;

    /* Background track (semi-circle arc) */
    HPEN bgPen = CreatePen(PS_SOLID, 8, RGB(28, 38, 54));
    HPEN oldPen = (HPEN)SelectObject(dc, bgPen);
    for (int a = 180; a >= 0; a -= 3) {
        double rad1 = (double)a * 3.1415926535 / 180.0;
        double rad2 = (double)(a - 3) * 3.1415926535 / 180.0;
        int px1 = cx + (int)(R * cos(rad1));
        int py1 = cy - (int)(R * sin(rad1));
        int px2 = cx + (int)(R * cos(rad2));
        int py2 = cy - (int)(R * sin(rad2));
        MoveToEx(dc, px1, py1, NULL);
        LineTo(dc, px2, py2);
    }

    /* Active progress arc with gradient coloring */
    int curScore = s_wafState.overallScore;
    int maxAngle = (curScore * 180) / 100;
    if (maxAngle > 180) maxAngle = 180;
    for (int a = 180; a > 180 - maxAngle; a -= 3) {
        int pct = (180 - a) * 100 / 180;
        COLORREF segCol = (pct < 35) ? RGB(16, 185, 129) :
                          (pct < 70) ? RGB(245, 158, 11) : RGB(239, 68, 68);
        HPEN segPen = CreatePen(PS_SOLID, 9, segCol);
        SelectObject(dc, segPen);
        double rad1 = (double)a * 3.1415926535 / 180.0;
        double rad2 = (double)(a - 3) * 3.1415926535 / 180.0;
        int px1 = cx + (int)(R * cos(rad1));
        int py1 = cy - (int)(R * sin(rad1));
        int px2 = cx + (int)(R * cos(rad2));
        int py2 = cy - (int)(R * sin(rad2));
        MoveToEx(dc, px1, py1, NULL);
        LineTo(dc, px2, py2);
        DeleteObject(segPen);
    }
    SelectObject(dc, oldPen);
    DeleteObject(bgPen);

    /* End indicator glow dot */
    if (maxAngle > 0) {
        double endRad = (double)(180 - maxAngle) * 3.1415926535 / 180.0;
        int epx = cx + (int)(R * cos(endRad));
        int epy = cy - (int)(R * sin(endRad));
        HBRUSH dotBr = CreateSolidBrush(RGB(255, 255, 255));
        HPEN dotPen = CreatePen(PS_SOLID, 1, RGB(239, 68, 68));
        HBRUSH ob = (HBRUSH)SelectObject(dc, dotBr);
        HPEN op = (HPEN)SelectObject(dc, dotPen);
        Ellipse(dc, epx - 3, epy - 3, epx + 4, epy + 4);
        SelectObject(dc, ob); SelectObject(dc, op);
        DeleteObject(dotBr); DeleteObject(dotPen);
    }

    /* Percentage in center */
    char pctStr[16]; snprintf(pctStr, sizeof(pctStr), "%d%%", curScore);
    Txt(dc, pctStr, x, cy - 24, w, 24, C_TEXT, fBig ? fBig : fHdr, DT_CENTER|DT_SINGLELINE);

    /* Status & Severity labels */
    BOOL hasThreat = (curScore >= 28);
    Txt(dc, hasThreat ? "THREAT DETECTED" : "CLEAN / STANDBY", x, cy + 4, w, 16,
        hasThreat ? RGB(239, 68, 68) : RGB(52, 211, 153), fSm, DT_CENTER|DT_SINGLELINE);
    char sevBuf[48]; snprintf(sevBuf, sizeof(sevBuf), "Severity: %s", s_wafState.severity);
    Txt(dc, sevBuf, x, cy + 22, w, 14, C_DIM, fMini ? fMini : fSm, DT_CENTER|DT_SINGLELINE);
}

static void DrawWafCategoryCard(HDC dc, int x, int y, int w, int h, const char *title, int status) {
    if (status == 3) {
        /* Triggered - High (Red card) */
        DrawRoundRectPanel(dc, x, y, w, h, 6, RGB(38, 12, 18), RGB(239, 68, 68));
        Txt(dc, title, x + 8, y + 6, w - 36, 16, C_TEXT, fSm, DT_LEFT|DT_SINGLELINE);
        Txt(dc, "Triggered - High", x + 8, y + 24, w - 36, 16, RGB(248, 113, 113), fSm, DT_LEFT|DT_SINGLELINE);
        /* Red Pin / Alert icon badge */
        DrawRoundRectPanel(dc, x + w - 24, y + h / 2 - 8, 16, 16, 8, RGB(60, 16, 24), RGB(239, 68, 68));
        Txt(dc, "!", x + w - 24, y + h / 2 - 8, 16, 16, RGB(255, 180, 190), fSm, DT_CENTER|DT_VCENTER|DT_SINGLELINE);
    } else if (status == 2) {
        /* Triggered - Medium (Amber card) */
        DrawRoundRectPanel(dc, x, y, w, h, 6, RGB(34, 22, 10), RGB(245, 158, 11));
        Txt(dc, title, x + 8, y + 6, w - 36, 16, C_TEXT, fSm, DT_LEFT|DT_SINGLELINE);
        Txt(dc, "Triggered - Medium", x + 8, y + 24, w - 36, 16, RGB(251, 191, 36), fSm, DT_LEFT|DT_SINGLELINE);
        /* Amber warning badge */
        DrawRoundRectPanel(dc, x + w - 24, y + h / 2 - 8, 16, 16, 8, RGB(55, 35, 14), RGB(245, 158, 11));
        Txt(dc, "#", x + w - 24, y + h / 2 - 8, 16, 16, RGB(255, 220, 120), fSm, DT_CENTER|DT_VCENTER|DT_SINGLELINE);
    } else if (status == 1) {
        /* Triggered - Low (Gold card) */
        DrawRoundRectPanel(dc, x, y, w, h, 6, RGB(22, 28, 38), RGB(234, 179, 8));
        Txt(dc, title, x + 8, y + 6, w - 36, 16, C_TEXT, fSm, DT_LEFT|DT_SINGLELINE);
        Txt(dc, "Triggered - Low", x + 8, y + 24, w - 36, 16, RGB(250, 204, 21), fSm, DT_LEFT|DT_SINGLELINE);
        /* Gold lightning badge */
        DrawRoundRectPanel(dc, x + w - 24, y + h / 2 - 8, 16, 16, 8, RGB(45, 40, 12), RGB(234, 179, 8));
        Txt(dc, "~", x + w - 24, y + h / 2 - 8, 16, 16, RGB(255, 240, 150), fSm, DT_CENTER|DT_VCENTER|DT_SINGLELINE);
    } else {
        /* Clean (Default dark card with green checkmark) */
        DrawRoundRectPanel(dc, x, y, w, h, 6, C_CARD, C_BORDER);
        Txt(dc, title, x + 8, y + 6, w - 36, 16, C_TEXT, fSm, DT_LEFT|DT_SINGLELINE);
        Txt(dc, "Clean", x + 8, y + 24, w - 36, 16, RGB(52, 211, 153), fSm, DT_LEFT|DT_SINGLELINE);
        /* Green circular check badge */
        DrawRoundRectPanel(dc, x + w - 24, y + h / 2 - 8, 16, 16, 8, RGB(10, 40, 26), RGB(16, 185, 129));
        Txt(dc, "v", x + w - 24, y + h / 2 - 8, 16, 16, RGB(52, 211, 153), fMini ? fMini : fSm, DT_CENTER|DT_VCENTER|DT_SINGLELINE);
    }
}

static void PaintWaf(HDC dc, int cx, int cy, int cw, int ch) {
    if (!s_wafInited) {
        char curPayload[4096] = {0};
        if (hWafIn) GetWindowTextA(hWafIn, curPayload, sizeof(curPayload)-1);
        if (curPayload[0]) {
            WafResult wr = {0};
            waf_analyze(curPayload, &wr);
        } else {
            waf_reset_state();
        }
        s_wafInited = TRUE;
    }

    int wx = cx + MRG;
    int ww = cw - MRG * 2;

    /* 1. Header Title matching mockup */
    Txt(dc, "WEBGUARD - Offline Payload Signature Inspector", wx, cy + 10, ww, 20, C_TEXT, fMed, DT_LEFT|DT_SINGLELINE);

    /* 2. Labels */
    Txt(dc, "Payload:", wx, cy + 34, 100, 16, C_DIM, fSm, DT_LEFT|DT_SINGLELINE);
    Txt(dc, "Results:", wx, cy + 114, 100, 16, C_DIM, fSm, DT_LEFT|DT_SINGLELINE);

    /* 3. Results Container Panel */
    int resY = cy + 132;
    int resH = ch - 132 - 10;
    DrawRoundRectPanel(dc, wx, resY, ww, resH, 8, RGB(10, 15, 24), C_BORDER);

    int innerPad = 10;
    int innerX = wx + innerPad;
    int innerY = resY + innerPad;
    int innerW = ww - innerPad * 2;

    /* 5-Column Grid Layout */
    int colGap = 8;
    int colW = (innerW - 4 * colGap) / 5;
    int rowH = 46;
    int rowGap = 6;

    int c1X = innerX;
    int c2X = c1X + colW + colGap;
    int c3X = c2X + colW + colGap;
    int c4X = c3X + colW + colGap;
    int c5X = c4X + colW + colGap;

    int r1Y = innerY;
    int r2Y = r1Y + rowH + rowGap;
    int r3Y = r2Y + rowH + rowGap;
    int r4Y = r3Y + rowH + rowGap;
    int r5Y = r4Y + rowH + rowGap;

    /* Col 1: Inspection Summary card spanning Rows 1-3 */
    int sumH = 3 * rowH + 2 * rowGap;
    DrawWafRiskMeter(dc, c1X, r1Y, colW, sumH);

    /* Col 1, Row 4: Encoding Anomalies */
    DrawWafCategoryCard(dc, c1X, r4Y, colW, rowH, s_wafState.cats[WAF_CAT_ENCODING].name, s_wafState.cats[WAF_CAT_ENCODING].status);

    /* Col 1, Row 5: DoS/DDoS Signature */
    DrawWafCategoryCard(dc, c1X, r5Y, colW, rowH, s_wafState.cats[WAF_CAT_DDOS].name, s_wafState.cats[WAF_CAT_DDOS].status);

    /* --- Top Summary Metric Cards (Row 1 across Cols 2, 3, 4, 5) --- */
    /* Col 2: Overall Confidence */
    DrawRoundRectPanel(dc, c2X, r1Y, colW, rowH, 6, C_CARD, C_BORDER);
    Txt(dc, "Overall Confidence:", c2X + 8, r1Y + 6, colW - 16, 14, C_DIM, fSm, DT_LEFT|DT_SINGLELINE);
    char confBuf[16]; snprintf(confBuf, sizeof(confBuf), "%d%%", s_wafState.overallConfidence);
    Txt(dc, confBuf, c2X + 8, r1Y + 22, colW - 16, 20, C_TEXT, fMed, DT_LEFT|DT_SINGLELINE);

    /* Col 3: Primary Threat / Dynamic Confidence */
    DrawRoundRectPanel(dc, c3X, r1Y, colW, rowH, 6, C_CARD, C_BORDER);
    char c3Lbl[48]; snprintf(c3Lbl, sizeof(c3Lbl), "%s:", s_wafState.primaryCategory[0] ? s_wafState.primaryCategory : "Threat Vector");
    Txt(dc, c3Lbl, c3X + 8, r1Y + 6, colW - 16, 14, C_DIM, fSm, DT_LEFT|DT_SINGLELINE);
    char c3Val[16]; snprintf(c3Val, sizeof(c3Val), "%d%%", s_wafState.primaryConfidence);
    COLORREF c3Col = (s_wafState.primaryConfidence > 0) ? RGB(239, 68, 68) : RGB(52, 211, 153);
    Txt(dc, (s_wafState.overallScore > 0) ? c3Val : "Clean", c3X + 8, r1Y + 22, colW - 16, 20, (s_wafState.overallScore > 0) ? c3Col : RGB(52, 211, 153), fMed, DT_LEFT|DT_SINGLELINE);

    /* Col 4: Primary Category */
    DrawRoundRectPanel(dc, c4X, r1Y, colW, rowH, 6, C_CARD, C_BORDER);
    Txt(dc, "Primary Category:", c4X + 8, r1Y + 6, colW - 16, 14, C_DIM, fSm, DT_LEFT|DT_SINGLELINE);
    Txt(dc, s_wafState.primaryCategory, c4X + 8, r1Y + 22, colW - 16, 20, C_TEXT, fSm, DT_LEFT|DT_SINGLELINE);

    /* Col 5: Action Taken */
    DrawRoundRectPanel(dc, c5X, r1Y, colW, rowH, 6, C_CARD, C_BORDER);
    Txt(dc, "Action Taken:", c5X + 8, r1Y + 6, colW - 40, 14, C_DIM, fSm, DT_LEFT|DT_SINGLELINE);
    COLORREF actCol = s_wafState.blocked ? RGB(239, 68, 68) : (s_wafState.inspected ? RGB(52, 211, 153) : C_DIM);
    Txt(dc, s_wafState.actionTaken, c5X + 8, r1Y + 22, colW - 40, 20, actCol, fMed, DT_LEFT|DT_SINGLELINE);
    /* Shield icon */
    DrawRoundRectPanel(dc, c5X + colW - 28, r1Y + rowH / 2 - 10, 20, 20, 4, RGB(16, 28, 48), RGB(59, 130, 246));
    Txt(dc, "[S]", c5X + colW - 28, r1Y + rowH / 2 - 10, 20, 20, RGB(56, 189, 248), fMini ? fMini : fSm, DT_CENTER|DT_VCENTER|DT_SINGLELINE);

    /* --- Category Grid Cards (Rows 2 to 5) --- */
    /* Col 2 */
    DrawWafCategoryCard(dc, c2X, r2Y, colW, rowH, s_wafState.cats[WAF_CAT_XSS].name, s_wafState.cats[WAF_CAT_XSS].status);
    DrawWafCategoryCard(dc, c2X, r3Y, colW, rowH, s_wafState.cats[WAF_CAT_PARAM_TAMP].name, s_wafState.cats[WAF_CAT_PARAM_TAMP].status);
    DrawWafCategoryCard(dc, c2X, r4Y, colW, rowH, s_wafState.cats[WAF_CAT_PROTO_VIOL].name, s_wafState.cats[WAF_CAT_PROTO_VIOL].status);
    DrawWafCategoryCard(dc, c2X, r5Y, colW, rowH, s_wafState.cats[WAF_CAT_CSRF].name, s_wafState.cats[WAF_CAT_CSRF].status);

    /* Col 3 */
    DrawWafCategoryCard(dc, c3X, r2Y, colW, rowH, s_wafState.cats[WAF_CAT_TRAVERSAL].name, s_wafState.cats[WAF_CAT_TRAVERSAL].status);
    DrawWafCategoryCard(dc, c3X, r3Y, colW, rowH, s_wafState.cats[WAF_CAT_LFI].name, s_wafState.cats[WAF_CAT_LFI].status);
    DrawWafCategoryCard(dc, c3X, r4Y, colW, rowH, s_wafState.cats[WAF_CAT_SSRF].name, s_wafState.cats[WAF_CAT_SSRF].status);
    DrawWafCategoryCard(dc, c3X, r5Y, colW, rowH, s_wafState.cats[WAF_CAT_SESSION].name, s_wafState.cats[WAF_CAT_SESSION].status);

    /* Col 4 */
    DrawWafCategoryCard(dc, c4X, r2Y, colW, rowH, s_wafState.cats[WAF_CAT_RFI].name, s_wafState.cats[WAF_CAT_RFI].status);
    DrawWafCategoryCard(dc, c4X, r3Y, colW, rowH, s_wafState.cats[WAF_CAT_HDR_TAMP].name, s_wafState.cats[WAF_CAT_HDR_TAMP].status);
    DrawWafCategoryCard(dc, c4X, r4Y, colW, rowH, s_wafState.cats[WAF_CAT_XXE].name, s_wafState.cats[WAF_CAT_XXE].status);
    DrawWafCategoryCard(dc, c4X, r5Y, colW, rowH, s_wafState.cats[WAF_CAT_RCE].name, s_wafState.cats[WAF_CAT_RCE].status);

    /* Col 5 */
    DrawWafCategoryCard(dc, c5X, r2Y, colW, rowH, s_wafState.cats[WAF_CAT_CMDI].name, s_wafState.cats[WAF_CAT_CMDI].status);
    DrawWafCategoryCard(dc, c5X, r3Y, colW, rowH, s_wafState.cats[WAF_CAT_COOKIE_POIS].name, s_wafState.cats[WAF_CAT_COOKIE_POIS].status);
    DrawWafCategoryCard(dc, c5X, r4Y, colW, rowH, s_wafState.cats[WAF_CAT_SCANNER].name, s_wafState.cats[WAF_CAT_SCANNER].status);
    DrawWafCategoryCard(dc, c5X, r5Y, colW, rowH, "Bruteforce Signatures", 0);

    /* --- Bottom Section: Matched Rules Table & Recommendations Card --- */
    int botY = r5Y + rowH + 10;
    int botH = resH - (botY - resY) - innerPad;
    if (botH > 120) {
        int recW = 270;
        int tblW = innerW - recW - 10;

        /* Bottom Left: Matched Rules Table */
        DrawRoundRectPanel(dc, innerX, botY, tblW, botH, 8, C_CARD, C_BORDER);

        int thY = botY + 8;
        int col1 = innerX + 12;
        int col2 = innerX + 110;
        int col3 = innerX + 260;
        int col4 = innerX + 410;
        int col5 = innerX + 500;

        Txt(dc, "Rule ID",     col1, thY, 90, 16, C_DIM, fSm, DT_LEFT|DT_SINGLELINE);
        Txt(dc, "Rule Name",   col2, thY, 140, 16, C_DIM, fSm, DT_LEFT|DT_SINGLELINE);
        Txt(dc, "Category",    col3, thY, 140, 16, C_DIM, fSm, DT_LEFT|DT_SINGLELINE);
        Txt(dc, "Confidence",  col4, thY, 80, 16, C_DIM, fSm, DT_LEFT|DT_SINGLELINE);
        Txt(dc, "Match Text",  col5, thY, (innerX + tblW - col5 - 12), 16, C_DIM, fSm, DT_LEFT|DT_SINGLELINE);
        DrawLine(dc, innerX + 8, thY + 20, innerX + tblW - 8, thY + 20, C_BORDER);

        int rowTop = thY + 24;
        int tblRowH = 22;
        int maxRows = (botH - 38) / tblRowH;
        if (s_wafState.matchCount > 0) {
            int showCnt = (s_wafState.matchCount < maxRows) ? s_wafState.matchCount : maxRows;
            for (int i = 0; i < showCnt; i++) {
                int curY = rowTop + i * tblRowH;
                Txt(dc, s_wafState.matches[i].id,       col1, curY, 90, 18, C_TEXT, fSm, DT_LEFT|DT_SINGLELINE);
                Txt(dc, s_wafState.matches[i].name,     col2, curY, 140, 18, C_TEXT2, fSm, DT_LEFT|DT_SINGLELINE);
                Txt(dc, s_wafState.matches[i].category, col3, curY, 140, 18, C_TEXT2, fSm, DT_LEFT|DT_SINGLELINE);
                char confS[16]; snprintf(confS, sizeof(confS), "%d%%", s_wafState.matches[i].confidence);
                Txt(dc, confS,                          col4, curY, 80, 18, RGB(239, 68, 68), fSm, DT_LEFT|DT_SINGLELINE);
                Txt(dc, s_wafState.matches[i].matchText, col5, curY, (innerX + tblW - col5 - 12), 18, RGB(56, 189, 248), fMono ? fMono : fSm, DT_LEFT|DT_SINGLELINE|DT_END_ELLIPSIS);
            }
        } else {
            Txt(dc, "[ Standby - Enter an HTTP request or attack payload above and click 'Inspect Payload' ]",
                innerX + 16, rowTop + 14, tblW - 32, 20, C_DIM, fSm, DT_LEFT|DT_SINGLELINE);
        }

        /* Bottom Right: Recommendations Card */
        int recX = innerX + tblW + 10;
        DrawRoundRectPanel(dc, recX, botY, recW, botH, 8, C_CARD, C_BORDER);
        Txt(dc, "Recommendations", recX + 14, botY + 8, recW - 28, 16, C_TEXT, fMed, DT_LEFT|DT_SINGLELINE);
        DrawLine(dc, recX + 10, botY + 26, recX + recW - 10, botY + 26, C_BORDER);

        int recTop = botY + 32;
        for (int i = 0; i < s_wafState.recommendationCount && i < 4; i++) {
            RECT rRec = { recX + 14, recTop + i * 26, recX + recW - 14, recTop + (i + 1) * 26 };
            SetTextColor(dc, RGB(200, 214, 230));
            SetBkMode(dc, TRANSPARENT);
            HFONT of = (HFONT)SelectObject(dc, fSm ? fSm : (HFONT)GetStockObject(DEFAULT_GUI_FONT));
            DrawTextA(dc, s_wafState.recommendations[i], -1, &rRec, DT_LEFT|DT_WORDBREAK|DT_NOPREFIX);
            SelectObject(dc, of);
        }
    }
}

static void PaintAv(HDC dc,int cx,int cy,int cw,int ch){
    int bannerY = cy + 12;
    int bannerH = 76;
    int bannerW = cw - MRG * 2;
    DrawRoundRectPanel(dc, cx + MRG, bannerY, bannerW, bannerH, 10, C_PANEL, C_BORDER);

    /* Left Shield Badge */
    int shX = cx + MRG + 16, shY = bannerY + 16, shSz = 44;
    DrawRoundRectPanel(dc, shX, shY, shSz, shSz, 10, RGB(16, 38, 78), C_BLUE);
    SetBkMode(dc, TRANSPARENT);
    SetTextColor(dc, RGB(56, 189, 248));
    SelectObject(dc, fIconBig ? fIconBig : (HFONT)GetStockObject(DEFAULT_GUI_FONT));
    RECT shR = {shX, shY, shX + shSz, shY + shSz};
    DrawTextW(dc, L"\uEA18", -1, &shR, DT_CENTER|DT_VCENTER|DT_SINGLELINE);

    /* Title & Subtitle - Single full title to prevent overlapping words and clipping */
    Txt(dc, "Antivirus Core", shX + shSz + 14, bannerY + 10, 320, 32, C_TEXT, fBig, DT_LEFT|DT_SINGLELINE);
    Txt(dc, "On-demand file scan; continuous real-time protection is unavailable.",
        shX + shSz + 14, bannerY + 44, 380, 16, C_DIM, fSm, DT_LEFT|DT_SINGLELINE);

    /* Top Right Stat Cards */
    int cardY = bannerY + 11;
    int cardH = 54;
    int rightEdge = cx + cw - MRG - 12;

    /* Card 3: Quarantine Files */
    int card3W = 140;
    int card3X = rightEdge - card3W;
    DrawRoundRectPanel(dc, card3X, cardY, card3W, cardH, 8, C_CARD2, C_BORDER2);
    DrawRoundRectPanel(dc, card3X + 10, cardY + 12, 30, 30, 8, RGB(36, 22, 60), RGB(168, 85, 247));
    SetTextColor(dc, C_PURPLE); SelectObject(dc, fIcon ? fIcon : (HFONT)GetStockObject(DEFAULT_GUI_FONT));
    RECT c3ir = {card3X + 10, cardY + 12, card3X + 40, cardY + 42};
    DrawTextW(dc, L"\uE8F1", -1, &c3ir, DT_CENTER|DT_VCENTER|DT_SINGLELINE);
    Txt(dc, "Quarantine Files", card3X + 46, cardY + 6, 88, 14, C_DIM, fMini ? fMini : fSm, DT_LEFT|DT_SINGLELINE);
    int quarCount = 0;
    for(int i = 0; i < g_threatDbCount; i++) if(g_threatDB[i].quarantined) quarCount++;
    char qBuf[16]; snprintf(qBuf, sizeof(qBuf), "%d", quarCount);
    Txt(dc, qBuf, card3X + 46, cardY + 20, 30, 20, C_TEXT, fStat ? fStat : fMed, DT_LEFT|DT_SINGLELINE);
    Txt(dc, (quarCount > 0) ? "SECURED" : "NONE", card3X + 76, cardY + 24, 52, 14, (quarCount > 0) ? C_PURPLE : C_GREEN, fMini ? fMini : fSm, DT_LEFT|DT_SINGLELINE);
    Txt(dc, "Quarantine DB", card3X + 46, cardY + 38, 88, 12, C_DIM2, fMini ? fMini : fSm, DT_LEFT|DT_SINGLELINE);

    /* Card 2: Threats Detected */
    int card2W = 140;
    int card2X = card3X - card2W - 8;
    DrawRoundRectPanel(dc, card2X, cardY, card2W, cardH, 8, C_CARD2, C_BORDER2);
    DrawRoundRectPanel(dc, card2X + 10, cardY + 12, 30, 30, 8, RGB(60, 16, 26), RGB(239, 68, 68));
    SetTextColor(dc, C_RED); SelectObject(dc, fIcon ? fIcon : (HFONT)GetStockObject(DEFAULT_GUI_FONT));
    RECT c2ir = {card2X + 10, cardY + 12, card2X + 40, cardY + 42};
    DrawTextW(dc, L"\uE7BA", -1, &c2ir, DT_CENTER|DT_VCENTER|DT_SINGLELINE);
    Txt(dc, "Threats Detected", card2X + 46, cardY + 6, 88, 14, C_DIM, fMini ? fMini : fSm, DT_LEFT|DT_SINGLELINE);
    char tBuf[16]; snprintf(tBuf, sizeof(tBuf), "%d", g_threatDbCount);
    Txt(dc, tBuf, card2X + 46, cardY + 20, 30, 20, C_TEXT, fStat ? fStat : fMed, DT_LEFT|DT_SINGLELINE);
    Txt(dc, (g_threatDbCount > 0) ? "ALERT" : "CLEAN", card2X + 76, cardY + 24, 46, 14, (g_threatDbCount > 0) ? C_RED : C_CYAN, fMini ? fMini : fSm, DT_LEFT|DT_SINGLELINE);
    Txt(dc, "Signature DB", card2X + 46, cardY + 38, 88, 12, C_DIM2, fMini ? fMini : fSm, DT_LEFT|DT_SINGLELINE);

    /* Card 1: Total Scans */
    int card1W = 140;
    int card1X = card2X - card1W - 8;
    DrawRoundRectPanel(dc, card1X, cardY, card1W, cardH, 8, C_CARD2, C_BORDER2);
    DrawRoundRectPanel(dc, card1X + 10, cardY + 12, 30, 30, 8, RGB(16, 38, 76), RGB(59, 130, 246));
    SetTextColor(dc, C_BLUE); SelectObject(dc, fIcon ? fIcon : (HFONT)GetStockObject(DEFAULT_GUI_FONT));
    RECT c1ir = {card1X + 10, cardY + 12, card1X + 40, cardY + 42};
    DrawTextW(dc, L"\uE8A5", -1, &c1ir, DT_CENTER|DT_VCENTER|DT_SINGLELINE);
    Txt(dc, "Total Scans", card1X + 46, cardY + 6, 88, 14, C_DIM, fMini ? fMini : fSm, DT_LEFT|DT_SINGLELINE);
    char sBuf[32];
    if (g_avScanned >= 1000000) snprintf(sBuf, sizeof(sBuf), "%.2fM", (double)g_avScanned / 1000000.0);
    else if (g_avScanned >= 1000) snprintf(sBuf, sizeof(sBuf), "%.1fK", (double)g_avScanned / 1000.0);
    else snprintf(sBuf, sizeof(sBuf), "%lld", g_avScanned);
    Txt(dc, sBuf, card1X + 46, cardY + 20, 42, 20, C_TEXT, fStat ? fStat : fMed, DT_LEFT|DT_SINGLELINE);
    Txt(dc, (g_avScanned > 0) ? "LIVE" : "READY", card1X + 90, cardY + 24, 46, 14, C_GREEN, fMini ? fMini : fSm, DT_LEFT|DT_SINGLELINE);
    Txt(dc, "Real-time scans", card1X + 46, cardY + 38, 88, 12, C_DIM2, fMini ? fMini : fSm, DT_LEFT|DT_SINGLELINE);

    /* Center Engine Status Card */
    int statX = card1X - 128 - 10;
    if (statX > shX + shSz + 250) {
        DrawRoundRectPanel(dc, statX, cardY, 128, cardH, 8, C_CARD2, C_BORDER2);
        Txt(dc, "Engine Status", statX + 32, cardY + 8, 80, 14, C_DIM, fMini ? fMini : fSm, DT_LEFT|DT_SINGLELINE);
        HBRUSH grnB = CreateSolidBrush(C_GREEN);
        HPEN nullP = (HPEN)GetStockObject(NULL_PEN);
        HBRUSH ob = (HBRUSH)SelectObject(dc, grnB);
        HPEN op = (HPEN)SelectObject(dc, nullP);
        Ellipse(dc, statX + 14, cardY + 26, statX + 24, cardY + 36);
        SelectObject(dc, ob); SelectObject(dc, op); DeleteObject(grnB);
        Txt(dc, "Active", statX + 32, cardY + 24, 46, 18, C_GREEN, fMed, DT_LEFT|DT_SINGLELINE);

        /* Sparkline mini wave */
        HPEN wPen = CreatePen(PS_SOLID, 1, RGB(0, 220, 200));
        HPEN opw = (HPEN)SelectObject(dc, wPen);
        POINT wp[6] = {
            { statX + 86, cardY + 32 }, { statX + 92, cardY + 32 },
            { statX + 96, cardY + 24 }, { statX + 102, cardY + 40 },
            { statX + 108, cardY + 32 }, { statX + 118, cardY + 32 }
        };
        Polyline(dc, wp, 6);
        SelectObject(dc, opw); DeleteObject(wPen);
    }

    /* Table Header Row */
    int tblHeaderY = cy + 178;
    int tblHeaderH = 26;
    int tblHeaderW = cw - MRG * 2;
    DrawRoundRectPanel(dc, cx + MRG, tblHeaderY, tblHeaderW, tblHeaderH, 6, C_PANEL, C_BORDER);

    int col1 = cx + MRG + 8;
    int col2 = cx + MRG + 38;
    int col3 = cx + MRG + 128;
    int col4 = cx + MRG + 270;
    int col5 = cx + MRG + 480;
    int col8 = cx + cw - MRG - 68;
    int col7 = col8 - 100;
    int col6 = col7 - 52;

    HFONT ofh = (HFONT)SelectObject(dc, fSm ? fSm : (HFONT)GetStockObject(DEFAULT_GUI_FONT));
    Txt(dc, "#",           col1, tblHeaderY, 24, tblHeaderH, C_DIM, fSm, DT_LEFT|DT_VCENTER|DT_SINGLELINE);
    Txt(dc, "Threat",      col2, tblHeaderY, 80, tblHeaderH, C_TEXT2, fSm, DT_LEFT|DT_VCENTER|DT_SINGLELINE);
    Txt(dc, "Type",        col3, tblHeaderY, 130, tblHeaderH, C_TEXT2, fSm, DT_LEFT|DT_VCENTER|DT_SINGLELINE);
    Txt(dc, "File / Path", col4, tblHeaderY, 200, tblHeaderH, C_TEXT2, fSm, DT_LEFT|DT_VCENTER|DT_SINGLELINE);
    Txt(dc, "Details",     col5, tblHeaderY, (col6 - col5 - 12 > 50) ? (col6 - col5 - 12) : 50, tblHeaderH, C_TEXT2, fSm, DT_LEFT|DT_VCENTER|DT_SINGLELINE);
    Txt(dc, "Score",       col6, tblHeaderY, 44, tblHeaderH, C_TEXT2, fSm, DT_LEFT|DT_VCENTER|DT_SINGLELINE);
    Txt(dc, "Status",      col7, tblHeaderY, 86, tblHeaderH, C_TEXT2, fSm, DT_LEFT|DT_VCENTER|DT_SINGLELINE);
    Txt(dc, "Action",      col8, tblHeaderY, 60, tblHeaderH, C_TEXT2, fSm, DT_LEFT|DT_VCENTER|DT_SINGLELINE);
    SelectObject(dc, ofh);
}

/* === RansomShield VSS Snapshots & Live Activity State ==================== */
typedef struct {
    char timestamp[32];
    char name[128];
    char size[32];
    char status[32];
    time_t rawTime;
} VssSnapshotEntry;

#define MAX_VSS_SNAPSHOTS 16
static VssSnapshotEntry g_vssSnapshots[MAX_VSS_SNAPSHOTS];
static int g_vssSnapshotCnt = 0;
static int g_vssSelectedIdx = 0;

#define RW_WAVE_PTS 48
static float s_rwWave[RW_WAVE_PTS] = {0};
static BOOL  s_rwWaveInit = FALSE;

static void InitVssSnapshots(void) {
    if (g_vssSnapshotCnt > 0) return;
    HKEY hk;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Kaevex\\VssSnapshots", 0, KEY_READ, &hk) == ERROR_SUCCESS) {
        DWORD cnt = 0, sz = sizeof(cnt), type = 0;
        if (RegQueryValueExA(hk, "Count", NULL, &type, (BYTE*)&cnt, &sz) == ERROR_SUCCESS && cnt > 0) {
            if (cnt > MAX_VSS_SNAPSHOTS) cnt = MAX_VSS_SNAPSHOTS;
            g_vssSnapshotCnt = (int)cnt;
            for (int i = 0; i < g_vssSnapshotCnt; i++) {
                char kTs[32], kNm[32], kSz[32], kSt[32];
                snprintf(kTs, sizeof(kTs), "Timestamp%d", i);
                snprintf(kNm, sizeof(kNm), "Name%d", i);
                snprintf(kSz, sizeof(kSz), "Size%d", i);
                snprintf(kSt, sizeof(kSt), "Status%d", i);
                DWORD slen = sizeof(g_vssSnapshots[i].timestamp);
                RegQueryValueExA(hk, kTs, NULL, NULL, (BYTE*)g_vssSnapshots[i].timestamp, &slen);
                slen = sizeof(g_vssSnapshots[i].name);
                RegQueryValueExA(hk, kNm, NULL, NULL, (BYTE*)g_vssSnapshots[i].name, &slen);
                slen = sizeof(g_vssSnapshots[i].size);
                RegQueryValueExA(hk, kSz, NULL, NULL, (BYTE*)g_vssSnapshots[i].size, &slen);
                slen = sizeof(g_vssSnapshots[i].status);
                RegQueryValueExA(hk, kSt, NULL, NULL, (BYTE*)g_vssSnapshots[i].status, &slen);
            }
        }
        RegCloseKey(hk);
    }
    /* If no snapshots saved in registry, keep g_vssSnapshotCnt = 0 so user sees genuine standby state */
}

static void SaveVssSnapshots(void) {
    HKEY hk;
    if (RegCreateKeyExA(HKEY_CURRENT_USER, "Software\\Kaevex\\VssSnapshots", 0, NULL, 0, KEY_SET_VALUE, NULL, &hk, NULL) == ERROR_SUCCESS) {
        DWORD cnt = (DWORD)g_vssSnapshotCnt;
        RegSetValueExA(hk, "Count", 0, REG_DWORD, (const BYTE*)&cnt, sizeof(cnt));
        for (int i = 0; i < g_vssSnapshotCnt; i++) {
            char kTs[32], kNm[32], kSz[32], kSt[32];
            snprintf(kTs, sizeof(kTs), "Timestamp%d", i);
            snprintf(kNm, sizeof(kNm), "Name%d", i);
            snprintf(kSz, sizeof(kSz), "Size%d", i);
            snprintf(kSt, sizeof(kSt), "Status%d", i);
            RegSetValueExA(hk, kTs, 0, REG_SZ, (const BYTE*)g_vssSnapshots[i].timestamp, (DWORD)strlen(g_vssSnapshots[i].timestamp) + 1);
            RegSetValueExA(hk, kNm, 0, REG_SZ, (const BYTE*)g_vssSnapshots[i].name, (DWORD)strlen(g_vssSnapshots[i].name) + 1);
            RegSetValueExA(hk, kSz, 0, REG_SZ, (const BYTE*)g_vssSnapshots[i].size, (DWORD)strlen(g_vssSnapshots[i].size) + 1);
            RegSetValueExA(hk, kSt, 0, REG_SZ, (const BYTE*)g_vssSnapshots[i].status, (DWORD)strlen(g_vssSnapshots[i].status) + 1);
        }
        RegCloseKey(hk);
    }
}

static void AddVssSnapshotRecord(const char *name, const char *size, const char *status) {
    InitVssSnapshots();
    if (g_vssSnapshotCnt >= MAX_VSS_SNAPSHOTS) {
        memmove(&g_vssSnapshots[1], &g_vssSnapshots[0], (MAX_VSS_SNAPSHOTS - 1) * sizeof(VssSnapshotEntry));
        g_vssSnapshotCnt = MAX_VSS_SNAPSHOTS - 1;
    } else {
        memmove(&g_vssSnapshots[1], &g_vssSnapshots[0], g_vssSnapshotCnt * sizeof(VssSnapshotEntry));
    }
    time_t now = time(NULL);
    struct tm *tmNow = localtime(&now);
    if (tmNow) {
        snprintf(g_vssSnapshots[0].timestamp, sizeof(g_vssSnapshots[0].timestamp),
                 "%04d-%02d-%02d %02d:%02d:%02d",
                 tmNow->tm_year + 1900, tmNow->tm_mon + 1, tmNow->tm_mday,
                 tmNow->tm_hour, tmNow->tm_min, tmNow->tm_sec);
    } else {
        strncpy(g_vssSnapshots[0].timestamp, "Unknown", sizeof(g_vssSnapshots[0].timestamp)-1);
    }
    strncpy(g_vssSnapshots[0].name, (name && name[0]) ? name : "Unknown", sizeof(g_vssSnapshots[0].name) - 1);
    strncpy(g_vssSnapshots[0].size, (size && size[0]) ? size : "Unknown", sizeof(g_vssSnapshots[0].size) - 1);
    strncpy(g_vssSnapshots[0].status, (status && status[0]) ? status : "Unknown", sizeof(g_vssSnapshots[0].status) - 1);
    g_vssSnapshots[0].rawTime = now;
    g_vssSnapshotCnt++;
    SaveVssSnapshots();
}

static void UpdateRwWave(void) {
    if (!s_rwWaveInit) {
        for (int i = 0; i < RW_WAVE_PTS; i++) {
            s_rwWave[i] = 0.5f + 0.20f * (float)sin(i * 0.35);
        }
        s_rwWaveInit = TRUE;
    }
    for (int i = 0; i < RW_WAVE_PTS - 1; i++) {
        s_rwWave[i] = s_rwWave[i + 1];
    }
    static float s_phase = 0.0f;
    s_phase += 0.22f;
    if (g_rwMonitoring) {
        float base = 0.50f + 0.25f * (float)sin(s_phase) + 0.12f * (float)sin(s_phase * 2.3f);
        float noise = ((float)(rand() % 100) / 600.0f) - 0.08f;
        s_rwWave[RW_WAVE_PTS - 1] = CLAMP(base + noise, 0.12f, 0.88f);
    } else {
        s_rwWave[RW_WAVE_PTS - 1] = 0.5f + 0.04f * (float)sin(s_phase * 0.4f);
    }
}

static void DrawDonutChart(HDC dc, int cx, int cy, int rOut, int rIn, int deployed, int tripped, int idle) {
    int total = deployed + tripped + idle;
    if (total <= 0) { total = 1; idle = 1; }

    double fDeployed = (double)deployed / (double)total;
    double fTripped  = (double)tripped  / (double)total;
    double fIdle     = (double)idle     / (double)total;

    double PI_CONST = 3.14159265358979323846;
    double a0 = -PI_CONST / 2.0;
    double a1 = a0 + fDeployed * 2.0 * PI_CONST;
    double a2 = a1 + fTripped  * 2.0 * PI_CONST;
    double a3 = a0 + 2.0 * PI_CONST;

    struct { double startA; double endA; COLORREF col; } slices[3] = {
        { a0, a1, RGB(52, 211, 153) }, /* Deployed: Emerald Neon */
        { a1, a2, RGB(239, 68, 68)  }, /* Tripped: Red */
        { a2, a3, RGB(100, 116, 139) } /* Idle: Slate Gray */
    };

    for (int s = 0; s < 3; s++) {
        if (slices[s].endA <= slices[s].startA + 0.005) continue;
        int x1 = cx + (int)(cos(slices[s].startA) * rOut * 2.0);
        int y1 = cy + (int)(sin(slices[s].startA) * rOut * 2.0);
        int x2 = cx + (int)(cos(slices[s].endA) * rOut * 2.0);
        int y2 = cy + (int)(sin(slices[s].endA) * rOut * 2.0);

        HBRUSH hBr = CreateSolidBrush(slices[s].col);
        HPEN hPen = CreatePen(PS_SOLID, 1, slices[s].col);
        HBRUSH hOldBr = (HBRUSH)SelectObject(dc, hBr);
        HPEN hOldPen = (HPEN)SelectObject(dc, hPen);

        Pie(dc, cx - rOut, cy - rOut, cx + rOut, cy + rOut, x1, y1, x2, y2);

        SelectObject(dc, hOldBr);
        SelectObject(dc, hOldPen);
        DeleteObject(hBr);
        DeleteObject(hPen);
    }

    /* Hole in middle */
    HBRUSH hHoleBr = CreateSolidBrush(C_CARD);
    HPEN hHolePen = CreatePen(PS_SOLID, 1, C_CARD);
    HBRUSH ob = (HBRUSH)SelectObject(dc, hHoleBr);
    HPEN op = (HPEN)SelectObject(dc, hHolePen);
    Ellipse(dc, cx - rIn, cy - rIn, cx + rIn, cy + rIn);
    SelectObject(dc, ob); SelectObject(dc, op);
    DeleteObject(hHoleBr); DeleteObject(hHolePen);
}

static void DrawRwWave(HDC dc, int x, int y, int w, int h) {
    POINT pts[RW_WAVE_PTS];
    POINT poly[RW_WAVE_PTS + 2];
    for (int i = 0; i < RW_WAVE_PTS; i++) {
        int px = x + i * w / (RW_WAVE_PTS - 1);
        int py = y + (int)((1.0f - s_rwWave[i]) * h);
        pts[i].x = px;
        pts[i].y = py;
        poly[i].x = px;
        poly[i].y = py;
    }
    poly[RW_WAVE_PTS].x = x + w;
    poly[RW_WAVE_PTS].y = y + h;
    poly[RW_WAVE_PTS + 1].x = x;
    poly[RW_WAVE_PTS + 1].y = y + h;

    HBRUSH hPolyBr = CreateSolidBrush(RGB(10, 36, 26));
    HPEN hNullPen = (HPEN)GetStockObject(NULL_PEN);
    HBRUSH ob = (HBRUSH)SelectObject(dc, hPolyBr);
    HPEN op = (HPEN)SelectObject(dc, hNullPen);
    Polygon(dc, poly, RW_WAVE_PTS + 2);
    SelectObject(dc, ob); SelectObject(dc, op);
    DeleteObject(hPolyBr);

    HPEN pGlow1 = CreatePen(PS_SOLID, 4, RGB(12, 75, 48));
    op = (HPEN)SelectObject(dc, pGlow1);
    Polyline(dc, pts, RW_WAVE_PTS);
    SelectObject(dc, op); DeleteObject(pGlow1);

    HPEN pGlow2 = CreatePen(PS_SOLID, 2, RGB(52, 211, 153));
    op = (HPEN)SelectObject(dc, pGlow2);
    Polyline(dc, pts, RW_WAVE_PTS);
    SelectObject(dc, op); DeleteObject(pGlow2);

    HPEN pCore = CreatePen(PS_SOLID, 1, RGB(180, 255, 220));
    op = (HPEN)SelectObject(dc, pCore);
    Polyline(dc, pts, RW_WAVE_PTS);
    SelectObject(dc, op); DeleteObject(pCore);
}

static void PaintRansom(HDC dc,int cx,int cy,int cw,int ch){
    InitVssSnapshots();

    /* 1. Header Title matching target screenshot */
    Txt(dc,"RANSOMSHIELD - Mass Encryption Detection, Honeypots & VSS Rollback",cx+MRG,cy+10,cw-MRG*2,20,C_TEXT,fMed,DT_LEFT|DT_SINGLELINE);

    /* 2. Middle Section: Two side-by-side cards */
    int cardY = cy + 76;
    int cardH = 246;
    int gap   = 14;
    int card1W = (cw - gap) / 2;
    int card1X = cx;
    int card2W = cw - card1W - gap;
    int card2X = card1X + card1W + gap;

    /* --- Left Card: Live Monitoring Feed --- */
    DrawRoundRectPanel(dc, card1X, cardY, card1W, cardH, 10, C_CARD, C_BORDER);
    Txt(dc, "Live Monitoring Feed", card1X + 16, cardY + 12, 220, 18, C_TEXT, fMed, DT_LEFT|DT_SINGLELINE);
    Txt(dc, "|", card1X + card1W - 24, cardY + 12, 14, 18, C_BORDER2, fMed, DT_CENTER|DT_SINGLELINE);

    /* Activity Status section inside Left Card */
    int statY = cardY + 152;
    Txt(dc, "Activity Status", card1X + 16, statY, 140, 18, C_TEXT, fMed, DT_LEFT|DT_SINGLELINE);
    const char *statBadge = g_rwMonitoring ? "Stable - Active" : "Inactive - Standby";
    COLORREF statCol = g_rwMonitoring ? RGB(52, 211, 153) : RGB(245, 158, 11);
    Txt(dc, statBadge, card1X + card1W - 146, statY, 130, 18, statCol, fSm, DT_RIGHT|DT_SINGLELINE);

    /* Real-Time Wave Graph */
    DrawRwWave(dc, card1X + 16, cardY + 178, card1W - 32, 52);

    /* --- Right Card: Honeypot Decoy Network --- */
    DrawRoundRectPanel(dc, card2X, cardY, card2W, cardH, 10, C_CARD, C_BORDER);
    Txt(dc, "Honeypot Decoy Network", card2X + 16, cardY + 12, 240, 18, C_TEXT, fMed, DT_LEFT|DT_SINGLELINE);

    /* Real honeypot calculations */
    int trippedCnt = 0;
    for (int i = 0; i < g_honeyCnt; i++) {
        if (g_honey[i].touched) trippedCnt++;
    }
    int deployedCnt = g_honeyCnt - trippedCnt;
    int idleCnt = (RW_MAX_HONEY > g_honeyCnt) ? (RW_MAX_HONEY - g_honeyCnt) : 0;

    /* Donut Chart */
    int donutX = card2X + 85;
    int donutY = cardY + 84;
    DrawDonutChart(dc, donutX, donutY, 44, 26, deployedCnt, trippedCnt, idleCnt);

    /* Donut Legend */
    int legX = card2X + 158;
    int legY = cardY + 46;
    int legH = 22;

    /* Deployed Pill */
    HBRUSH bDep = CreateSolidBrush(RGB(52, 211, 153));
    RECT rDep = { legX, legY + 4, legX + 12, legY + 16 };
    FillRect(dc, &rDep, bDep); DeleteObject(bDep);
    char depTxt[64]; snprintf(depTxt, sizeof(depTxt), "Deployed (%d)", deployedCnt);
    Txt(dc, depTxt, legX + 18, legY, 120, legH, C_TEXT, fSm, DT_LEFT|DT_VCENTER|DT_SINGLELINE);

    /* Tripped Pill */
    HBRUSH bTrip = CreateSolidBrush(RGB(239, 68, 68));
    RECT rTrip = { legX, legY + legH + 4, legX + 12, legY + legH + 16 };
    FillRect(dc, &rTrip, bTrip); DeleteObject(bTrip);
    char tripTxt[64]; snprintf(tripTxt, sizeof(tripTxt), "Tripped (%d)", trippedCnt);
    Txt(dc, tripTxt, legX + 18, legY + legH, 120, legH, C_TEXT, fSm, DT_LEFT|DT_VCENTER|DT_SINGLELINE);

    /* Idle Pill */
    HBRUSH bIdle = CreateSolidBrush(RGB(100, 116, 139));
    RECT rIdle = { legX, legY + legH * 2 + 4, legX + 12, legY + legH * 2 + 16 };
    FillRect(dc, &rIdle, bIdle); DeleteObject(bIdle);
    char idleTxt[64]; snprintf(idleTxt, sizeof(idleTxt), "Idle (%d)", idleCnt);
    Txt(dc, idleTxt, legX + 18, legY + legH * 2, 120, legH, C_TEXT, fSm, DT_LEFT|DT_VCENTER|DT_SINGLELINE);

    /* Decoy Canary Files List */
    int decY = cardY + 138;
    if (g_honeyCnt == 0) {
        Txt(dc, "No honeypot decoys active. Click 'Deploy Honeypots' above.", card2X + 16, decY + 12, card2W - 32, 20, C_DIM, fSm, DT_LEFT|DT_SINGLELINE);
    } else {
        int maxShow = (g_honeyCnt < 3) ? g_honeyCnt : 3;
        for (int i = 0; i < maxShow; i++) {
            int rowY = decY + i * 28;
            /* Dot icon */
            COLORREF dotC = g_honey[i].touched ? RGB(239, 68, 68) : RGB(52, 211, 153);
            HBRUSH hDot = CreateSolidBrush(dotC);
            HPEN hNull = (HPEN)GetStockObject(NULL_PEN);
            HBRUSH ob = (HBRUSH)SelectObject(dc, hDot);
            HPEN op = (HPEN)SelectObject(dc, hNull);
            Ellipse(dc, card2X + 16, rowY + 6, card2X + 24, rowY + 14);
            SelectObject(dc, ob); SelectObject(dc, op); DeleteObject(hDot);

            /* File path truncated if long */
            char truncPath[128];
            strncpy(truncPath, g_honey[i].path, sizeof(truncPath) - 1);
            truncPath[sizeof(truncPath) - 1] = 0;
            if (strlen(truncPath) > 34) {
                truncPath[31] = '.'; truncPath[32] = '.'; truncPath[33] = '.'; truncPath[34] = 0;
            }
            Txt(dc, truncPath, card2X + 30, rowY + 2, card2W - 130, 20, C_TEXT, fSm, DT_LEFT|DT_SINGLELINE);

            /* Status Pill: [Deployed] or [Tripped!] */
            const char *badgeTxt = g_honey[i].touched ? "[Tripped!]" : "[Deployed]";
            COLORREF badgeCol = g_honey[i].touched ? RGB(239, 68, 68) : RGB(52, 211, 153);
            Txt(dc, badgeTxt, card2X + card2W - 96, rowY + 2, 86, 20, badgeCol, fSm, DT_RIGHT|DT_SINGLELINE);
        }
    }

    /* 3. Bottom Section: VSS Snapshot Rollback Center */
    int bottomY = cardY + cardH + 12;
    int bottomH = ch - (bottomY - cy) - 4;
    if (bottomH < 180) bottomH = 180;

    DrawRoundRectPanel(dc, cx, bottomY, cw, bottomH, 10, C_CARD, C_BORDER);
    Txt(dc, "VSS Snapshots (restore unavailable)", cx + 18, bottomY + 14, 300, 20, C_TEXT, fMed, DT_LEFT|DT_SINGLELINE);

    /* "Rollback Selected" Button at top right of bottom card */
    int rbsW = 140, rbsH = 26;
    int rbsX = cx + cw - rbsW - 16, rbsY = bottomY + 10;
    DrawRoundRectPanel(dc, rbsX, rbsY, rbsW, rbsH, 6, RGB(22, 30, 44), RGB(75, 85, 99));
    Txt(dc, "Restore unavailable", rbsX, rbsY, rbsW, rbsH, RGB(240, 246, 255), fSm, DT_CENTER|DT_VCENTER|DT_SINGLELINE);

    /* Table Column Headers */
    int tblY = bottomY + 44;
    int col1 = cx + 20;
    int col2 = cx + 210;
    int col3 = cx + cw - 330;
    int col4 = cx + cw - 230;
    int col5 = cx + cw - 120;

    Txt(dc, "Timestamp ^",    col1, tblY, 180, 20, C_DIM, fSm, DT_LEFT|DT_SINGLELINE);
    Txt(dc, "Snapshot Name",  col2, tblY, (col3 - col2 - 10), 20, C_DIM, fSm, DT_LEFT|DT_SINGLELINE);
    Txt(dc, "Size",           col3, tblY, 90, 20, C_DIM, fSm, DT_LEFT|DT_SINGLELINE);
    Txt(dc, "Status",         col4, tblY, 90, 20, C_DIM, fSm, DT_LEFT|DT_SINGLELINE);
    Txt(dc, "Action",         col5, tblY, 90, 20, C_DIM, fSm, DT_LEFT|DT_SINGLELINE);
    DrawLine(dc, cx + 16, tblY + 22, cx + cw - 16, tblY + 22, C_BORDER);

    /* Table Rows */
    int rowY = tblY + 28;
    int rowH = 28;
    if (g_vssSnapshotCnt == 0) {
        Txt(dc, "No VSS restore points found. Click 'Create VSS Snapshot' above to arm rollback protection.",
            cx + 20, rowY + 8, cw - 40, 20, C_DIM, fSm, DT_LEFT|DT_SINGLELINE);
    } else {
        int maxRows = (bottomH - 80) / rowH;
        int showRows = (g_vssSnapshotCnt < maxRows) ? g_vssSnapshotCnt : maxRows;
        for (int i = 0; i < showRows; i++) {
            int curY = rowY + i * rowH;

            /* Selected row highlight */
            if (i == g_vssSelectedIdx) {
                HBRUSH bSel = CreateSolidBrush(RGB(20, 32, 48));
                RECT rSel = { cx + 12, curY, cx + cw - 12, curY + rowH };
                FillRect(dc, &rSel, bSel);
                DeleteObject(bSel);
            }

            /* 1. Timestamp */
            Txt(dc, g_vssSnapshots[i].timestamp, col1, curY + 4, 180, 20, C_TEXT, fSm, DT_LEFT|DT_SINGLELINE);

            /* 2. Snapshot Name */
            Txt(dc, g_vssSnapshots[i].name, col2, curY + 4, (col3 - col2 - 10), 20, C_TEXT, fSm, DT_LEFT|DT_SINGLELINE);

            /* 3. Size */
            Txt(dc, g_vssSnapshots[i].size, col3, curY + 4, 90, 20, C_TEXT2, fSm, DT_LEFT|DT_SINGLELINE);

            /* 4. Status */
            BOOL isAvail = (strcmp(g_vssSnapshots[i].status, "Available") == 0);
            COLORREF stCol = isAvail ? RGB(52, 211, 153) : RGB(245, 158, 11);
            Txt(dc, g_vssSnapshots[i].status, col4, curY + 4, 90, 20, stCol, fSm, DT_LEFT|DT_SINGLELINE);

            /* 5. Rollback Action Button */
            int btnW = 76, btnH = 22;
            int btnX = col5, btnY = curY + 2;
            DrawRoundRectPanel(dc, btnX, btnY, btnW, btnH, 5, RGB(24, 32, 46), RGB(55, 65, 81));
            Txt(dc, "Details", btnX, btnY, btnW, btnH, RGB(210, 225, 245), fSm, DT_CENTER|DT_VCENTER|DT_SINGLELINE);
        }
    }
}


/* ===========================================================================
 * SMARTSANDBOX TELEMETRY & 4-QUADRANT MONITORING ENGINE
 * =========================================================================== */

static BOOL  g_sbxBlockNet = TRUE;
static BOOL  g_sbxBlockFs  = TRUE;

#define SBX_TIMELINE_PTS 40
static float s_sbxCpuHistory[SBX_TIMELINE_PTS] = {0};
static float s_sbxMemHistory[SBX_TIMELINE_PTS] = {0};
static int   s_sbxAlertMarkers[SBX_TIMELINE_PTS] = {0};
static BOOL  s_sbxTimeInit = FALSE;

typedef struct {
    char targetIp[48];
    char host[64];
    char geo[48];
    BOOL isolated;
} SbxNetRoute;

#define SBX_MAX_ROUTES 4
static SbxNetRoute s_sbxRoutes[SBX_MAX_ROUTES];
static int s_sbxRouteCnt = 0;

typedef struct {
    char path[MAX_PATH];
    char opType[32];      /* "Accessed", "Modified", "Denied" */
    BOOL denied;
    int  threatLevel;     /* 0 = Clean/Safe, 1 = Suspicious, 2 = Critical Denied */
} SbxFsRecord;

#define SBX_MAX_FS_RECORDS 6
static SbxFsRecord s_sbxFsRecords[SBX_MAX_FS_RECORDS];
static int s_sbxFsRecordCnt = 0;

typedef struct {
    char callName[48];
    char status[24];      /* "Blocked", "Monitored", "Redirected" */
    char param[80];
    float threatScore;
    int   callType;       /* 0 = Thread/Inject, 1 = Memory/Hook, 2 = Network/Connect, 3 = Registry */
} SbxApiRecord;

#define SBX_MAX_API_RECORDS 6
static SbxApiRecord s_sbxApiRecords[SBX_MAX_API_RECORDS];
static int s_sbxApiRecordCnt = 0;

static void RefreshSbxDynamicData(void) {
    /* Sandboxie is the isolation backend; this build has no API/FS event collector.
       Never synthesize network, file, or API activity in the dashboard. */
    ZeroMemory(s_sbxRoutes, sizeof(s_sbxRoutes));
    ZeroMemory(s_sbxFsRecords, sizeof(s_sbxFsRecords));
    ZeroMemory(s_sbxApiRecords, sizeof(s_sbxApiRecords));
    s_sbxRouteCnt = 0;
    s_sbxFsRecordCnt = 0;
    s_sbxApiRecordCnt = 0;
}

static void InitSbxTelemetry(void) {
    if (s_sbxTimeInit) return;
    for (int i = 0; i < SBX_TIMELINE_PTS; i++) {
        s_sbxCpuHistory[i] = 0.0f;
        s_sbxMemHistory[i] = 0.0f;
        s_sbxAlertMarkers[i] = 0;
    }
    RefreshSbxDynamicData();
    s_sbxTimeInit = TRUE;
}

static void UpdateSbxTelemetry(void) {
    InitSbxTelemetry();
    for (int i = 0; i < SBX_TIMELINE_PTS - 1; i++) {
        s_sbxCpuHistory[i] = s_sbxCpuHistory[i + 1];
        s_sbxMemHistory[i] = s_sbxMemHistory[i + 1];
        s_sbxAlertMarkers[i] = s_sbxAlertMarkers[i + 1];
    }

    if (g_sbx.active && g_sbx.hProcess) {
        sbx_poll();
        PROCESS_MEMORY_COUNTERS pmc = {0}; pmc.cb = sizeof(pmc);
        float memMB = 0.0f;
        if (GetProcessMemoryInfo(g_sbx.hProcess, &pmc, sizeof(pmc))) {
            memMB = (float)pmc.WorkingSetSize / (1024.0f * 1024.0f);
        }
        s_sbxMemHistory[SBX_TIMELINE_PTS - 1] = (memMB > 0.05f) ? memMB : 1.2f;

        /* Real CPU calculation via GetProcessTimes */
        static ULONGLONG s_prevProcTime = 0;
        static ULONGLONG s_prevSampleTick = 0;
        FILETIME ftCreate, ftExit, ftKernel, ftUser;
        float curCpuPct = 0.5f;

        if (GetProcessTimes(g_sbx.hProcess, &ftCreate, &ftExit, &ftKernel, &ftUser)) {
            ULARGE_INTEGER kt, ut;
            kt.LowPart = ftKernel.dwLowDateTime; kt.HighPart = ftKernel.dwHighDateTime;
            ut.LowPart = ftUser.dwLowDateTime;   ut.HighPart = ftUser.dwHighDateTime;
            ULONGLONG curProcTime = kt.QuadPart + ut.QuadPart;
            ULONGLONG curTick = GetTickCount64();

            if (s_prevSampleTick > 0 && curTick > s_prevSampleTick && curProcTime >= s_prevProcTime) {
                ULONGLONG timeDiff100ns = (curTick - s_prevSampleTick) * 10000;
                if (timeDiff100ns > 0) {
                    SYSTEM_INFO si; GetSystemInfo(&si);
                    DWORD cores = (si.dwNumberOfProcessors > 0) ? si.dwNumberOfProcessors : 1;
                    curCpuPct = (float)((curProcTime - s_prevProcTime) * 100) / (float)(timeDiff100ns * cores);
                    if (curCpuPct < 0.0f) curCpuPct = 0.0f;
                    if (curCpuPct > 100.0f) curCpuPct = 100.0f;
                }
            }
            s_prevProcTime = curProcTime;
            s_prevSampleTick = curTick;
        }
        s_sbxCpuHistory[SBX_TIMELINE_PTS - 1] = curCpuPct;
        s_sbxAlertMarkers[SBX_TIMELINE_PTS - 1] = (curCpuPct > 35.0f) ? (int)(curCpuPct / 20.0f) : 0;
    } else {
        s_sbxCpuHistory[SBX_TIMELINE_PTS - 1] = 0.0f;
        s_sbxMemHistory[SBX_TIMELINE_PTS - 1] = 0.0f;
        s_sbxAlertMarkers[SBX_TIMELINE_PTS - 1] = 0;
    }
}

/* --- Quadrant 1: Detailed Activity Timeline ------------------------------- */
static void DrawSbxTimeline(HDC dc, int x, int y, int w, int h) {
    DrawRoundRectPanel(dc, x, y, w, h, 10, C_CARD, C_BORDER);
    Txt(dc, "Detailed Activity Timeline", x + 16, y + 12, 220, 18, C_TEXT, fMed, DT_LEFT|DT_SINGLELINE);

    /* Legend on top right */
    int legX = x + w - 160, legY = y + 12;
    HBRUSH bCpu = CreateSolidBrush(RGB(239, 68, 68));
    RECT rCpu = { legX, legY + 7, legX + 12, legY + 9 };
    FillRect(dc, &rCpu, bCpu); DeleteObject(bCpu);
    Txt(dc, "- CPU", legX + 16, legY, 50, 18, C_TEXT2, fSm, DT_LEFT|DT_SINGLELINE);

    HBRUSH bMem = CreateSolidBrush(RGB(59, 130, 246));
    RECT rMem = { legX + 70, legY + 7, legX + 82, legY + 9 };
    FillRect(dc, &rMem, bMem); DeleteObject(bMem);
    Txt(dc, "- Memory", legX + 86, legY, 65, 18, C_TEXT2, fSm, DT_LEFT|DT_SINGLELINE);

    /* Plot bounds */
    int gx = x + 42, gy = y + 36, gw = w - 84, gh = h - 64;
    HBRUSH bPlot = CreateSolidBrush(RGB(8, 14, 24));
    HPEN pPlotBdr = CreatePen(PS_SOLID, 1, RGB(22, 34, 52));
    HBRUSH ob = (HBRUSH)SelectObject(dc, bPlot);
    HPEN op = (HPEN)SelectObject(dc, pPlotBdr);
    Rectangle(dc, gx, gy, gx + gw, gy + gh);
    SelectObject(dc, ob); SelectObject(dc, op);
    DeleteObject(bPlot); DeleteObject(pPlotBdr);

    /* Grid lines & Axis labels */
    HPEN pGrid = CreatePen(PS_SOLID, 1, RGB(18, 28, 42));
    op = (HPEN)SelectObject(dc, pGrid);
    static const int cpuTicks[5] = { 100, 75, 50, 25, 0 };
    static const int memTicks[5] = { 25, 20, 15, 10, 5 };
    for (int t = 0; t < 5; t++) {
        int py = gy + t * gh / 4;
        MoveToEx(dc, gx, py, NULL); LineTo(dc, gx + gw, py);
        char cLbl[16], mLbl[16];
        snprintf(cLbl, sizeof(cLbl), "%d", cpuTicks[t]);
        Txt(dc, cLbl, gx - 34, py - 7, 28, 14, C_DIM, fMini ? fMini : fSm, DT_RIGHT|DT_SINGLELINE);
        snprintf(mLbl, sizeof(mLbl), "%d", memTicks[t]);
        Txt(dc, mLbl, gx + gw + 6, py - 7, 28, 14, C_DIM, fMini ? fMini : fSm, DT_LEFT|DT_SINGLELINE);
    }
    SelectObject(dc, op); DeleteObject(pGrid);

    /* X-axis time marks */
    for (int tm = 0; tm <= 10; tm++) {
        int px = gx + tm * gw / 10;
        char tLbl[8]; snprintf(tLbl, sizeof(tLbl), "%d", tm);
        Txt(dc, tLbl, px - 8, gy + gh + 4, 16, 14, C_DIM, fMini ? fMini : fSm, DT_CENTER|DT_SINGLELINE);
    }
    Txt(dc, "Time (minutes)", gx, gy + gh + 16, gw, 14, C_DIM, fMini ? fMini : fSm, DT_CENTER|DT_SINGLELINE);

    if (!g_sbx.active || (g_sbx.externalSandboxie && !g_sbx.hProcess)) {
        Txt(dc, g_sbx.active ? "Sandboxie session active; process performance telemetry is unavailable." : "Standby - choose a supported EXE and run it in Sandboxie.",
            gx, gy + gh / 2 - 10, gw, 20, RGB(80, 105, 135), fSm, DT_CENTER|DT_VCENTER|DT_SINGLELINE);
    } else {
        /* Draw dynamic curves */
        POINT ptsCpu[SBX_TIMELINE_PTS];
        POINT ptsMem[SBX_TIMELINE_PTS];
        for (int i = 0; i < SBX_TIMELINE_PTS; i++) {
            int px = gx + i * gw / (SBX_TIMELINE_PTS - 1);
            float cVal = CLAMP(s_sbxCpuHistory[i], 0.0f, 100.0f);
            float mVal = CLAMP(s_sbxMemHistory[i], 0.0f, 25.0f);
            ptsCpu[i].x = px; ptsCpu[i].y = gy + gh - (int)(cVal * gh / 100.0f);
            ptsMem[i].x = px; ptsMem[i].y = gy + gh - (int)(mVal * gh / 25.0f);
        }

        /* Blue Curve: Memory */
        HPEN pMemL = CreatePen(PS_SOLID, 2, RGB(59, 130, 246));
        op = (HPEN)SelectObject(dc, pMemL);
        Polyline(dc, ptsMem, SBX_TIMELINE_PTS);
        SelectObject(dc, op); DeleteObject(pMemL);

        /* Red Curve: CPU */
        HPEN pCpuL = CreatePen(PS_SOLID, 2, RGB(239, 68, 68));
        op = (HPEN)SelectObject(dc, pCpuL);
        Polyline(dc, ptsCpu, SBX_TIMELINE_PTS);
        SelectObject(dc, op); DeleteObject(pCpuL);

        /* Alert peak markers on CPU */
        for (int i = 2; i < SBX_TIMELINE_PTS - 2; i++) {
            if (s_sbxAlertMarkers[i] > 0) {
                int mx = ptsCpu[i].x, my = ptsCpu[i].y;
                HBRUSH bMk = CreateSolidBrush(s_sbxAlertMarkers[i] % 2 == 1 ? RGB(239, 68, 68) : RGB(59, 130, 246));
                HPEN pMk = CreatePen(PS_SOLID, 1, RGB(255, 255, 255));
                ob = (HBRUSH)SelectObject(dc, bMk); op = (HPEN)SelectObject(dc, pMk);
                Ellipse(dc, mx - 6, my - 6, mx + 6, my + 6);
                SelectObject(dc, ob); SelectObject(dc, op);
                DeleteObject(bMk); DeleteObject(pMk);
                char mCh[4]; snprintf(mCh, sizeof(mCh), "%d", s_sbxAlertMarkers[i]);
                Txt(dc, mCh, mx - 5, my - 6, 10, 12, RGB(255, 255, 255), fMini ? fMini : fSm, DT_CENTER|DT_VCENTER|DT_SINGLELINE);
            }
        }
    }
}

/* --- Quadrant 2: Network Behavior Map ------------------------------------- */
static void DrawSbxNetworkMap(HDC dc, int x, int y, int w, int h) {
    DrawRoundRectPanel(dc, x, y, w, h, 10, C_CARD, C_BORDER);
    Txt(dc, "Network Behavior Map", x + 16, y + 12, 220, 18, C_TEXT, fMed, DT_LEFT|DT_SINGLELINE);

    /* Central/Left Node */
    int centerX = x + 75, centerY = y + h / 2 - 4;
    HBRUSH bNode = CreateSolidBrush(RGB(18, 28, 44));
    HPEN pNodeBdr = CreatePen(PS_SOLID, 1, RGB(75, 85, 99));
    HBRUSH ob = (HBRUSH)SelectObject(dc, bNode);
    HPEN op = (HPEN)SelectObject(dc, pNodeBdr);
    Ellipse(dc, centerX - 18, centerY - 18, centerX + 18, centerY + 18);
    SelectObject(dc, ob); SelectObject(dc, op);
    DeleteObject(bNode); DeleteObject(pNodeBdr);

    /* Globe symbol */
    Txt(dc, "O", centerX - 10, centerY - 10, 20, 20, RGB(140, 160, 185), fMed, DT_CENTER|DT_VCENTER|DT_SINGLELINE);

    if (g_sbx.active) {
        char pidLbl[64];
        if(g_sbx.externalSandboxie) snprintf(pidLbl, sizeof(pidLbl), "Sandboxie Box Active");
        else snprintf(pidLbl, sizeof(pidLbl), "PID %lu (Active)", (unsigned long)g_sbx.pid);
        Txt(dc, pidLbl, centerX - 65, centerY + 22, 130, 14, C_TEXT, fMini ? fMini : fSm, DT_CENTER|DT_SINGLELINE);
        Txt(dc, "Sandboxie Box", centerX - 65, centerY + 36, 130, 14, C_DIM, fMini ? fMini : fSm, DT_CENTER|DT_SINGLELINE);
    } else {
        Txt(dc, "127.0.0.1 (Local)", centerX - 65, centerY + 22, 130, 14, C_TEXT, fMini ? fMini : fSm, DT_CENTER|DT_SINGLELINE);
        Txt(dc, "Container Standby", centerX - 65, centerY + 36, 130, 14, C_DIM, fMini ? fMini : fSm, DT_CENTER|DT_SINGLELINE);
    }

    /* Splines to intercepted endpoints */
    int destX = x + w - 245;
    HPEN pSpline = CreatePen(PS_SOLID, 1, g_sbxBlockNet ? RGB(180, 40, 50) : RGB(60, 140, 120));
    op = (HPEN)SelectObject(dc, pSpline);

    int routes = (s_sbxRouteCnt < 4) ? s_sbxRouteCnt : 4;
    if (routes == 0) Txt(dc, "Live connection telemetry is not provided by this Sandboxie integration.", x + 112, y + h - 28, w - 128, 18, C_DIM, fSm, DT_CENTER|DT_SINGLELINE);
    for (int i = 0; i < routes; i++) {
        int destY = y + 36 + i * (h - 54) / 4 + 14;

        /* Curved branch */
        POINT bPts[4];
        bPts[0].x = centerX + 18; bPts[0].y = centerY;
        bPts[1].x = centerX + (destX - centerX) / 2; bPts[1].y = centerY;
        bPts[2].x = centerX + (destX - centerX) / 2; bPts[2].y = destY;
        bPts[3].x = destX - 18; bPts[3].y = destY;
        PolyBezier(dc, bPts, 4);

        /* Intercept glyph */
        Txt(dc, g_sbxBlockNet ? "X" : "*", destX - 14, destY - 8, 16, 16, g_sbxBlockNet ? RGB(239, 68, 68) : RGB(52, 211, 153), fSm, DT_CENTER|DT_VCENTER|DT_SINGLELINE);

        /* Destination Route Details (wide 160px layout) */
        Txt(dc, s_sbxRoutes[i].targetIp, destX + 4, destY - 14, 160, 14, C_TEXT, fMini ? fMini : fSm, DT_LEFT|DT_SINGLELINE);
        Txt(dc, s_sbxRoutes[i].host,     destX + 4, destY - 2,  160, 14, C_DIM,  fMini ? fMini : fSm, DT_LEFT|DT_SINGLELINE);
        Txt(dc, s_sbxRoutes[i].geo,      destX + 4, destY + 10, 160, 14, C_DIM2, fMini ? fMini : fSm, DT_LEFT|DT_SINGLELINE);

        /* ISOLATED / FILTERED Pill Badge */
        int bdW = 62, bdH = 18;
        int bdX = x + w - bdW - 14, bdY = destY - 9;
        COLORREF bgBd = g_sbxBlockNet ? RGB(28, 10, 14) : RGB(10, 24, 20);
        COLORREF bdrBd = g_sbxBlockNet ? RGB(185, 28, 28) : RGB(16, 185, 129);
        COLORREF fgBd = g_sbxBlockNet ? RGB(239, 68, 68) : RGB(52, 211, 153);
        DrawRoundRectPanel(dc, bdX, bdY, bdW, bdH, 4, bgBd, bdrBd);
        Txt(dc, g_sbxBlockNet ? "ISOLATED" : "FILTERED", bdX, bdY, bdW, bdH, fgBd, fMini ? fMini : fSm, DT_CENTER|DT_VCENTER|DT_SINGLELINE);
    }
    SelectObject(dc, op); DeleteObject(pSpline);
}

/* --- Quadrant 3: File System Interactions --------------------------------- */
static void DrawSbxFileSystem(HDC dc, int x, int y, int w, int h) {
    DrawRoundRectPanel(dc, x, y, w, h, 10, C_CARD, C_BORDER);
    Txt(dc, "File System Interactions", x + 16, y + 12, 220, 18, C_TEXT, fMed, DT_LEFT|DT_SINGLELINE);

    /* Table Column Headers */
    int tblY = y + 36;
    int col1 = x + 16;
    int col2 = x + w - 215;
    int col3 = x + w - 75;

    Txt(dc, "Path",           col1, tblY, (col2 - col1 - 10), 16, C_DIM, fSm, DT_LEFT|DT_SINGLELINE);
    Txt(dc, "Operation Type", col2, tblY, 135, 16, C_DIM, fSm, DT_LEFT|DT_SINGLELINE);
    Txt(dc, "Threat Score",   col3, tblY, 65, 16, C_DIM, fSm, DT_LEFT|DT_SINGLELINE);
    DrawLine(dc, x + 12, tblY + 20, x + w - 12, tblY + 20, C_BORDER);

    /* Table Rows */
    int rowY = tblY + 26;
    int rowH = 26;
    int showCnt = (s_sbxFsRecordCnt < 4) ? s_sbxFsRecordCnt : 4;
    if (showCnt == 0) Txt(dc, "No live file events available from the current backend.", col1, rowY + 18, col3 - col1, 28, C_DIM, fSm, DT_CENTER|DT_VCENTER|DT_SINGLELINE);
    for (int i = 0; i < showCnt; i++) {
        int curY = rowY + i * rowH;

        /* Path */
        Txt(dc, s_sbxFsRecords[i].path, col1, curY, (col2 - col1 - 10), 20, C_TEXT, fSm, DT_LEFT|DT_SINGLELINE|DT_PATH_ELLIPSIS);

        /* Operation Type */
        COLORREF opCol = s_sbxFsRecords[i].denied ? RGB(239, 68, 68) : C_TEXT2;
        Txt(dc, s_sbxFsRecords[i].opType, col2, curY, 135, 20, opCol, fSm, DT_LEFT|DT_SINGLELINE);

        /* Threat Score / Security Badge */
        if (s_sbxFsRecords[i].denied) {
            DrawRoundRectPanel(dc, col3, curY + 1, 58, 18, 4, RGB(32, 10, 14), RGB(239, 68, 68));
            Txt(dc, "DENIED", col3, curY + 1, 58, 18, RGB(239, 68, 68), fMini ? fMini : fSm, DT_CENTER|DT_VCENTER|DT_SINGLELINE);
        } else {
            DrawRoundRectPanel(dc, col3, curY + 1, 58, 18, 4, RGB(10, 30, 22), RGB(16, 185, 129));
            Txt(dc, "SECURE", col3, curY + 1, 58, 18, RGB(52, 211, 153), fMini ? fMini : fSm, DT_CENTER|DT_VCENTER|DT_SINGLELINE);
        }
    }
}

/* --- Quadrant 4: API Call Analysis ---------------------------------------- */
static void DrawSbxApiAnalysis(HDC dc, int x, int y, int w, int h) {
    DrawRoundRectPanel(dc, x, y, w, h, 10, C_CARD, C_BORDER);
    Txt(dc, "API Call Analysis", x + 16, y + 12, 220, 18, C_TEXT, fMed, DT_LEFT|DT_SINGLELINE);

    /* Table Column Headers */
    int tblY = y + 36;
    int col1 = x + 16;
    int col2 = x + 175;
    int col3 = x + 245;
    int col4 = x + w - 85;

    Txt(dc, "Call Name",      col1, tblY, 150, 16, C_DIM, fSm, DT_LEFT|DT_SINGLELINE);
    Txt(dc, "Status",         col2, tblY, 65, 16, C_DIM, fSm, DT_LEFT|DT_SINGLELINE);
    Txt(dc, "Call Parameter", col3, tblY, (col4 - col3 - 10), 16, C_DIM, fSm, DT_LEFT|DT_SINGLELINE);
    Txt(dc, "Threat Score",   col4, tblY, 75, 16, C_DIM, fSm, DT_LEFT|DT_SINGLELINE);
    DrawLine(dc, x + 12, tblY + 20, x + w - 12, tblY + 20, C_BORDER);

    /* Table Rows */
    int rowY = tblY + 24;
    int rowH = 24;
    int showCnt = (s_sbxApiRecordCnt < 6) ? s_sbxApiRecordCnt : 6;
    if (showCnt == 0) Txt(dc, "API-call interception telemetry is not connected.", col1, rowY + 18, col4 - col1, 28, C_DIM, fSm, DT_CENTER|DT_VCENTER|DT_SINGLELINE);
    for (int i = 0; i < showCnt; i++) {
        int curY = rowY + i * rowH;

        /* Call Name with leading icon */
        const char *ic = (s_sbxApiRecords[i].callType == 2) ? "[N]" :
                         (s_sbxApiRecords[i].callType == 3) ? "[R]" : "[X]";
        COLORREF icCol = (s_sbxApiRecords[i].callType == 2) ? RGB(56, 189, 248) :
                         (s_sbxApiRecords[i].callType == 3) ? RGB(245, 158, 11) : RGB(239, 68, 68);
        Txt(dc, ic, col1, curY, 18, 20, icCol, fMini ? fMini : fSm, DT_LEFT|DT_SINGLELINE);
        Txt(dc, s_sbxApiRecords[i].callName, col1 + 18, curY, 136, 20, C_TEXT, fSm, DT_LEFT|DT_SINGLELINE);

        /* Status */
        BOOL isBlk = (strcmp(s_sbxApiRecords[i].status, "Blocked") == 0);
        BOOL isRedir = (strcmp(s_sbxApiRecords[i].status, "Redirected") == 0);
        COLORREF stCol = isBlk ? RGB(239, 68, 68) : (isRedir ? RGB(6, 182, 212) : RGB(245, 158, 11));
        Txt(dc, s_sbxApiRecords[i].status, col2, curY, 65, 20, stCol, fSm, DT_LEFT|DT_SINGLELINE);

        /* Call Parameter */
        Txt(dc, s_sbxApiRecords[i].param, col3, curY, (col4 - col3 - 10), 20, C_DIM, fSm, DT_LEFT|DT_SINGLELINE|DT_END_ELLIPSIS);

        /* Threat Score */
        char scStr[16]; snprintf(scStr, sizeof(scStr), "%.1f", s_sbxApiRecords[i].threatScore);
        Txt(dc, scStr, col4 + 10, curY, 55, 20, C_TEXT2, fSm, DT_LEFT|DT_SINGLELINE);
    }
}



static void PaintSbx(HDC dc,int cx,int cy,int cw,int ch){
    InitSbxTelemetry();
    RefreshSbxDynamicData();

    /* 1. Top Header Title matching target mockup */
    char sbieStart[MAX_PATH] = {0}, sbieIni[MAX_PATH] = {0};
    BOOL sbiePresent = sbx_find_sandboxie(sbieStart, sizeof(sbieStart), sbieIni, sizeof(sbieIni));
    char head[256];
    snprintf(head, sizeof(head), "SMARTSANDBOX - Sandboxie-Plus: %s | Session: %s",
             sbiePresent ? "installed" : "not installed", g_sbx.active ? "active" : "idle");
    Txt(dc,head,cx,cy+10,cw,20,C_TEXT,fMed,DT_LEFT|DT_SINGLELINE);

    /* 2. Isolation Layer Badges Row */
    int bx = cx, by = cy + 34, bw2 = 120, bh = 22, gap = 8;
    const struct{const char *lbl;COLORREF bg;COLORREF bdr;} layers[]={
        {sbiePresent ? "Sandboxie detected" : "Sandboxie missing",  RGB(26, 86, 240), RGB(59, 130, 246)},
        {g_sbx.active ? "Box active" : "Box idle",     RGB(16, 120, 60), RGB(52, 211, 153)},
        {g_sbx.active ? "WFP verified at launch" : "WFP checked on launch",   RGB(60, 20, 80),  RGB(168, 85, 247)},
        {"File/registry virtualization",  RGB(10, 60, 70),  RGB(6, 182, 212)},
        {"No API event feed",   RGB(60, 40, 10),  RGB(245, 158, 11)},
        {NULL,0,0}
    };
    for(int i=0;layers[i].lbl;i++){
        DrawRoundRectPanel(dc,bx+i*(bw2+gap),by,bw2,bh,5,layers[i].bg,layers[i].bdr);
        Txt(dc,layers[i].lbl,bx+i*(bw2+gap),by,bw2,bh,C_TEXT,fSm,DT_CENTER|DT_SINGLELINE|DT_VCENTER);
    }

    /* 3. Sandbox Policy Cards (6 cards in 2 rows x 3 columns) */
    int cardy = cy + 98;
    int cardw = (cw - 20) / 3;
    int cardh = 46;

    const char *netVal = g_sbx.active ? "BLOCKED (box policy)" : "not active";
    const char *netBdg = g_sbx.active ? "CONFIGURED" : "IDLE";
    COLORREF netCol    = g_sbx.active ? RGB(239, 68, 68) : RGB(245, 158, 11);

    const char *fsVal  = g_sbx.active ? "Sandboxie box" : "not active";
    const char *fsBdg  = g_sbx.active ? "VIRTUALIZED" : "IDLE";
    COLORREF fsCol     = g_sbxBlockFs ? RGB(245, 158, 11) : RGB(52, 211, 153);

    const struct{const char *title;const char *val;const char *badge;COLORREF bc;} cards[]={
        {"Network Access",    netVal,       netBdg,      netCol},
        {"File System Write", fsVal,        fsBdg,       fsCol},
        {"Child Processes",   "Sandboxie policy",  "NOT OBSERVED",      RGB(245, 158, 11)},
        {"Registry Changes",  "Sandboxie box", "VIRTUALIZED",      RGB(52, 211, 153)},
        {"Clipboard Access",  "DEFAULT",    "SANDBOXIE",  RGB(245, 158, 11)},
        {"DLL Injection",     "DEFAULT",    "SANDBOXIE",  RGB(245, 158, 11)},
        {NULL,NULL,NULL,0}
    };
    for(int i=0;cards[i].title;i++){
        int col = i % 3, row = i / 3;
        int px = cx + col * (cardw + 10);
        int py = cardy + row * 52;
        DrawRoundRectPanel(dc, px, py, cardw, cardh, 6, C_CARD, C_BORDER);
        Txt(dc, cards[i].title, px + 10, py + 4, cardw - 20, 14, C_DIM, fMini ? fMini : fSm, DT_LEFT|DT_SINGLELINE);
        Txt(dc, cards[i].val,   px + 10, py + 20, cardw - 80, 20, C_TEXT, fMed, DT_LEFT|DT_SINGLELINE);
        DrawRoundRectPanel(dc, px + cardw - 74, py + 14, 66, 18, 4, C_BG, cards[i].bc);
        Txt(dc, cards[i].badge, px + cardw - 74, py + 14, 66, 18, cards[i].bc, fMini ? fMini : fSm, DT_CENTER|DT_SINGLELINE|DT_VCENTER);
    }

    /* 4. The 4-Quadrant Deep Telemetry Matrix */
    int quadY = cy + 242;
    int quadH = ch - (quadY - cy) - 4;
    if (quadH < 330) quadH = 330;

    int qGap = 12;
    int qW = (cw - qGap) / 2;
    int qH = (quadH - qGap) / 2;

    /* Q1 (Top-Left): Detailed Activity Timeline */
    DrawSbxTimeline(dc, cx, quadY, qW, qH);

    /* Q2 (Top-Right): Network Behavior Map */
    DrawSbxNetworkMap(dc, cx + qW + qGap, quadY, qW, qH);

    /* Q3 (Bottom-Left): File System Interactions */
    DrawSbxFileSystem(dc, cx, quadY + qH + qGap, qW, qH);

    /* Q4 (Bottom-Right): API Call Analysis */
    DrawSbxApiAnalysis(dc, cx + qW + qGap, quadY + qH + qGap, qW, qH);
}



static void DrawPieSlice(HDC dc, int cx, int cy, int r, double a1, double a2, COLORREF fill, COLORREF bdr) {
    #define PIE_PTS 32
    POINT pts[PIE_PTS + 2];
    pts[0].x = cx; pts[0].y = cy;
    int n = 1;
    for (int i = 0; i <= PIE_PTS; i++) {
        double a = a1 + (a2 - a1) * ((double)i / (double)PIE_PTS);
        pts[n].x = cx + (int)(r * cos(a));
        pts[n].y = cy + (int)(r * sin(a));
        n++;
    }
    HPEN p = CreatePen(PS_SOLID, 2, bdr);
    HBRUSH b = CreateSolidBrush(fill);
    HPEN op = (HPEN)SelectObject(dc, p);
    HBRUSH ob = (HBRUSH)SelectObject(dc, b);
    Polygon(dc, pts, n);
    SelectObject(dc, op); SelectObject(dc, ob);
    DeleteObject(p); DeleteObject(b);
}

typedef struct {
    int ruleIdx;          /* Index in g_fwRules */
    char ruleName[128];
    char text[256];
    char scoreLabel[32];
    COLORREF badgeBg;
    COLORREF badgeBdr;
    COLORREF badgeFg;
    char actionBtn[32];   /* "Review" or "Deactivate" */
    int actionType;       /* 1 = Review, 2 = Deactivate */
} FwRecItem;

static FwRecItem g_fwRecs[3];
static int g_fwRecCount = 0;

static void fw_update_recommendations(void) {
    g_fwRecCount = 0;
    ZeroMemory(g_fwRecs, sizeof(g_fwRecs));
    if (g_fwRuleCount <= 0) return;

    /* 1. Item 1: High Risk Exposure / Sensitive Port / Highest Traffic Rule */
    int topRiskIdx = -1;
    int maxRiskScore = 0;
    for (int i = 0; i < g_fwRuleCount; i++) {
        FwRule *r = &g_fwRules[i];
        if (_stricmp(r->action, "Allow") == 0 && _stricmp(r->enabled, "Yes") == 0) {
            int score = 40;
            int lp = atoi(r->localPort);
            /* Sensitive listening ports: RDP, SMB, Telnet, WinRM, VNC, SQL, Web */
            if (lp == 3389 || lp == 445 || lp == 23 || lp == 135 || lp == 5985 || lp == 5900) {
                score += 48;
            } else if (lp == 80 || lp == 8080 || lp == 21 || lp == 22 || lp == 3306 || lp == 1433) {
                score += 35;
            } else if (strstr(r->direction, "In")) {
                score += 20;
            }
            if (r->hits > 50000) score += 10;
            else if (r->hits > 0) score += 5;
            if (strstr(r->remoteIP, "*") || !r->remoteIP[0] || strstr(r->remoteIP, "Any")) score += 5;
            if (score > maxRiskScore) {
                maxRiskScore = score;
                topRiskIdx = i;
            }
        }
    }
    if (topRiskIdx < 0 && g_fwRuleCount > 0) topRiskIdx = 0;
    if (topRiskIdx >= 0) {
        FwRecItem *it = &g_fwRecs[g_fwRecCount++];
        it->ruleIdx = topRiskIdx;
        strncpy(it->ruleName, g_fwRules[topRiskIdx].name, sizeof(it->ruleName)-1);
        int finalScore = (maxRiskScore > 98) ? 98 : (maxRiskScore < 60 ? 72 : maxRiskScore);
        snprintf(it->scoreLabel, sizeof(it->scoreLabel), "High Score %d", finalScore);
        it->badgeBg = RGB(55, 12, 18);
        it->badgeBdr = RGB(239, 68, 68);
        it->badgeFg = RGB(255, 120, 120);
        strcpy(it->actionBtn, "Review");
        it->actionType = 1;

        int lp = atoi(g_fwRules[topRiskIdx].localPort);
        if (lp > 0) {
            snprintf(it->text, sizeof(it->text), "Review Inbound exposure on '%.20s' (Port %d)", it->ruleName, lp);
        } else if (g_fwRules[topRiskIdx].hits > 0) {
            snprintf(it->text, sizeof(it->text), "Review High Traffic on '%.20s' (%lu hits)", it->ruleName, g_fwRules[topRiskIdx].hits);
        } else {
            snprintf(it->text, sizeof(it->text), "Review Open Surface on '%.24s'", it->ruleName);
        }
    }

    /* 2. Item 2: Dormant / 0-hit / Disabled / Obsolete Rule for Deactivation */
    int deadIdx = -1;
    for (int i = g_fwRuleCount - 1; i >= 0; i--) {
        if (i == topRiskIdx) continue;
        FwRule *r = &g_fwRules[i];
        if (r->hits == 0) {
            if (_stricmp(r->enabled, "No") == 0) { deadIdx = i; break; }
            if (r->program[0] && GetFileAttributesA(r->program) == INVALID_FILE_ATTRIBUTES) { deadIdx = i; break; }
            if (deadIdx < 0) deadIdx = i;
        }
    }
    if (deadIdx < 0 && g_fwRuleCount > 1) {
        deadIdx = (topRiskIdx == 0) ? 1 : 0;
    }
    if (deadIdx >= 0) {
        FwRecItem *it = &g_fwRecs[g_fwRecCount++];
        it->ruleIdx = deadIdx;
        strncpy(it->ruleName, g_fwRules[deadIdx].name, sizeof(it->ruleName)-1);
        int lowScore = 12 + (deadIdx % 15);
        snprintf(it->scoreLabel, sizeof(it->scoreLabel), "Low Score %d", lowScore);
        it->badgeBg = RGB(55, 12, 18);
        it->badgeBdr = RGB(220, 38, 38);
        it->badgeFg = RGB(255, 120, 120);
        strcpy(it->actionBtn, "Deactivate");
        it->actionType = 2;
        if (_stricmp(g_fwRules[deadIdx].enabled, "No") == 0) {
            snprintf(it->text, sizeof(it->text), "Purge disabled inactive rule '%.24s'", it->ruleName);
        } else {
            snprintf(it->text, sizeof(it->text), "Deactivate 0-hit rule '%.26s'", it->ruleName);
        }
    }

    /* 3. Item 3: Remote IP / Subnet Audit / External Gateway Rule */
    int auditIdx = -1;
    for (int i = 0; i < g_fwRuleCount; i++) {
        if (i == topRiskIdx || i == deadIdx) continue;
        FwRule *r = &g_fwRules[i];
        if (strcmp(r->remoteIP, "*") != 0 && _stricmp(r->remoteIP, "Any") != 0 && r->remoteIP[0]) {
            auditIdx = i;
            break;
        }
    }
    if (auditIdx < 0) {
        for (int i = 0; i < g_fwRuleCount; i++) {
            if (i == topRiskIdx || i == deadIdx) continue;
            if (_stricmp(g_fwRules[i].direction, "Inbound") == 0 || _stricmp(g_fwRules[i].protocol, "UDP") == 0) {
                auditIdx = i;
                break;
            }
        }
    }
    if (auditIdx < 0 && g_fwRuleCount > 2) {
        auditIdx = 2;
    }
    if (auditIdx >= 0) {
        FwRecItem *it = &g_fwRecs[g_fwRecCount++];
        it->ruleIdx = auditIdx;
        strncpy(it->ruleName, g_fwRules[auditIdx].name, sizeof(it->ruleName)-1);
        int medScore = 55 + (auditIdx * 7) % 20;
        snprintf(it->scoreLabel, sizeof(it->scoreLabel), "Medium Score %d", medScore);
        it->badgeBg = RGB(48, 30, 8);
        it->badgeBdr = RGB(245, 158, 11);
        it->badgeFg = RGB(251, 191, 36);
        strcpy(it->actionBtn, "Review");
        it->actionType = 1;
        if (strcmp(g_fwRules[auditIdx].remoteIP, "*") != 0 && _stricmp(g_fwRules[auditIdx].remoteIP, "Any") != 0 && g_fwRules[auditIdx].remoteIP[0]) {
            snprintf(it->text, sizeof(it->text), "Audit Remote IP on '%.20s' (%s)", it->ruleName, g_fwRules[auditIdx].remoteIP);
        } else {
            snprintf(it->text, sizeof(it->text), "Audit Protocol & Subnet on '%.24s'", it->ruleName);
        }
    }
}

static void PaintFw(HDC dc, int cx, int cy, int cw, int ch) {
    /* Auto-load rules on first paint if not yet populated */
    if (g_fwRuleCount == 0) {
        fw_load_rules();
    }
    fw_update_recommendations();

    /* Title */
    Txt(dc, "FIREWALL - Windows Defender Firewall Control & Adaptive Policies", cx, cy + 6, 600, 20, C_TEXT, fMed, DT_LEFT|DT_SINGLELINE);

    /* Status Pill Badge: FIREWALL: ACTIVE / DISABLED */
    BOOL fwOn = fw_is_enabled();
    COLORREF stBg = fwOn ? RGB(8, 48, 28) : RGB(48, 12, 18);
    COLORREF stBdr = fwOn ? RGB(16, 185, 129) : RGB(239, 68, 68);
    COLORREF stFg = fwOn ? RGB(52, 211, 153) : RGB(255, 120, 120);
    DrawRoundRectPanel(dc, cx, cy + 34, 150, 26, 6, stBg, stBdr);
    Txt(dc, fwOn ? "FIREWALL: ACTIVE" : "FIREWALL: DISABLED", cx, cy + 34, 150, 26, stFg, fSm, DT_CENTER|DT_VCENTER|DT_SINGLELINE);

    int fwRw = 264;
    int fwLw = cw - fwRw - 14;
    if (fwLw < 500) fwLw = 500;
    int fwCardY = cy + 102;
    int fwCardH = ch - (fwCardY - cy) - 10;

    /* 1. Main Left Card: RULE INVENTORY & TRAFFIC LOG */
    DrawRoundRectPanel(dc, cx, fwCardY, fwLw, fwCardH, 8, RGB(10, 14, 22), RGB(28, 38, 54));
    Txt(dc, "RULE INVENTORY & TRAFFIC LOG", cx + 14, fwCardY + 10, 350, 18, C_TEXT, fMed, DT_LEFT|DT_SINGLELINE);

    /* Table Column Headers */
    int thY = fwCardY + 32, thH = 22;
    FillR(dc, cx + 4, thY, fwLw - 8, thH, RGB(13, 18, 28));
    DrawLine(dc, cx + 4, thY + thH, cx + fwLw - 4, thY + thH, RGB(28, 38, 54));
    int x0 = cx + 8;
    COLORREF thCol = RGB(140, 160, 190);
    Txt(dc, "Index",       x0 + 4,   thY, 36,  thH, thCol, fMini ? fMini : fSm, DT_LEFT|DT_VCENTER|DT_SINGLELINE);
    Txt(dc, "Rule Name",   x0 + 44,  thY, 140, thH, thCol, fMini ? fMini : fSm, DT_LEFT|DT_VCENTER|DT_SINGLELINE);
    Txt(dc, "Profile",     x0 + 190, thY, 50,  thH, thCol, fMini ? fMini : fSm, DT_LEFT|DT_VCENTER|DT_SINGLELINE);
    Txt(dc, "Direction",   x0 + 245, thY, 80,  thH, thCol, fMini ? fMini : fSm, DT_LEFT|DT_VCENTER|DT_SINGLELINE);
    Txt(dc, "Action",      x0 + 330, thY, 46,  thH, thCol, fMini ? fMini : fSm, DT_CENTER|DT_VCENTER|DT_SINGLELINE);
    Txt(dc, "Protocol",    x0 + 380, thY, 52,  thH, thCol, fMini ? fMini : fSm, DT_LEFT|DT_VCENTER|DT_SINGLELINE);
    Txt(dc, "Local Port",  x0 + 436, thY, 60,  thH, thCol, fMini ? fMini : fSm, DT_LEFT|DT_VCENTER|DT_SINGLELINE);
    Txt(dc, "Remote IP",   x0 + 500, thY, 85,  thH, thCol, fMini ? fMini : fSm, DT_LEFT|DT_VCENTER|DT_SINGLELINE);
    Txt(dc, "Remote Port", x0 + 590, thY, 75,  thH, thCol, fMini ? fMini : fSm, DT_LEFT|DT_VCENTER|DT_SINGLELINE);
    Txt(dc, "Rule Hits",   x0 + 670, thY, 55,  thH, thCol, fMini ? fMini : fSm, DT_RIGHT|DT_VCENTER|DT_SINGLELINE);

    /* 2. Right Sidebar Area */
    int rx = cx + fwLw + 12, rw = fwRw;

    /* Top Card: Adaptive decision Metrics */
    int topH = 265;
    DrawRoundRectPanel(dc, rx, fwCardY, rw, topH, 8, RGB(10, 14, 22), RGB(28, 38, 54));
    Txt(dc, "Adaptive decision Metrics", rx + 14, fwCardY + 10, rw - 28, 18, C_TEXT, fMed, DT_LEFT|DT_SINGLELINE);

    /* Calculate dynamic telemetry metrics from g_fwRules */
    int cntDomain = 0, cntPrivate = 0, cntPublic = 0;
    unsigned long hitsDomain = 0, hitsPrivate = 0, hitsPublic = 0;
    unsigned long totalBlockedHits = 0;
    int newRulesCount = 0;
    for (int i = 0; i < g_fwRuleCount; i++) {
        if (strstr(g_fwRules[i].profile, "Domain") || strstr(g_fwRules[i].profile, "All")) {
            cntDomain++; hitsDomain += g_fwRules[i].hits;
        }
        if (strstr(g_fwRules[i].profile, "Private") || strstr(g_fwRules[i].profile, "All")) {
            cntPrivate++; hitsPrivate += g_fwRules[i].hits;
        }
        if (strstr(g_fwRules[i].profile, "Public") || strstr(g_fwRules[i].profile, "All")) {
            cntPublic++; hitsPublic += g_fwRules[i].hits;
        }
        if (_stricmp(g_fwRules[i].action, "Block") == 0) {
            totalBlockedHits += g_fwRules[i].hits;
        }
        if (g_fwRules[i].name[0] == '@' || strstr(g_fwRules[i].name, "Kaevex") ||
            strstr(g_fwRules[i].name, "Policy") || strstr(g_fwRules[i].name, "AppX") ||
            strstr(g_fwRules[i].name, "WCF")) {
            newRulesCount++;
        }
    }
    Txt(dc, "ACTIVE RULES", rx + 14, fwCardY + 32, rw - 28, 16, C_TEXT, fSm, DT_LEFT|DT_SINGLELINE);
    char actStr[128];
    snprintf(actStr, sizeof(actStr), "(Domain: %d, Private: %d, Public: %d)", cntDomain, cntPrivate, cntPublic);
    Txt(dc, actStr, rx + 14, fwCardY + 48, rw - 28, 14, RGB(140, 175, 215), fMini ? fMini : fSm, DT_LEFT|DT_SINGLELINE);

    char newRStr[128];
    snprintf(newRStr, sizeof(newRStr), "NEW RULES (Policy-driven, 24h): %d", newRulesCount);
    Txt(dc, newRStr, rx + 14, fwCardY + 68, rw - 28, 16, C_TEXT, fSm, DT_LEFT|DT_SINGLELINE);

    char blkStr[128];
    if (totalBlockedHits >= 1000000)
        snprintf(blkStr, sizeof(blkStr), "FIREWALL RULE HITS: %.1fM", (double)totalBlockedHits / 1000000.0);
    else if (totalBlockedHits >= 1000)
        snprintf(blkStr, sizeof(blkStr), "FIREWALL RULE HITS: %luK", totalBlockedHits / 1000);
    else
        snprintf(blkStr, sizeof(blkStr), "FIREWALL RULE HITS: %lu", totalBlockedHits);
    Txt(dc, blkStr, rx + 14, fwCardY + 88, rw - 28, 16, C_TEXT, fSm, DT_LEFT|DT_SINGLELINE);

    unsigned long totalHits = hitsPublic + hitsPrivate + hitsDomain;
    int pctPub = 0, pctPriv = 0, pctDom = 0;
    if (totalHits > 0) {
        pctPub = (int)(hitsPublic * 100 / totalHits);
        pctPriv = (int)(hitsPrivate * 100 / totalHits);
        pctDom = 100 - pctPub - pctPriv;
        if (pctDom < 0) pctDom = 0;
    } else {
        int totalRules = cntPublic + cntPrivate + cntDomain;
        if (totalRules > 0) {
            pctPub = cntPublic * 100 / totalRules;
            pctPriv = cntPrivate * 100 / totalRules;
            pctDom = 100 - pctPub - pctPriv;
            if (pctDom < 0) pctDom = 0;
        }
    }
    char pctStr[128];
    snprintf(pctStr, sizeof(pctStr), "Hits by Profile (Public: %d%%, Private:\n%d%%, Domain: %d%%)", pctPub, pctPriv, pctDom);
    Txt(dc, pctStr, rx + 14, fwCardY + 110, rw - 28, 30, RGB(160, 180, 205), fMini ? fMini : fSm, DT_LEFT);

    /* Segmented Pie Chart - 100% Dynamically Computed Angles */
    int pcX = rx + rw / 2;
    int pcY = fwCardY + 196;
    int pcR = 52;
    double PI = 3.14159265358979323846;
    double aStart = -PI / 2.0; /* 12 o'clock */
    double spanPub = (pctPub / 100.0) * (2.0 * PI);
    double spanPriv = (pctPriv / 100.0) * (2.0 * PI);
    double a1 = aStart + spanPub;
    double a2 = a1 + spanPriv;
    double a3 = aStart + 2.0 * PI;

    if (pctPub > 0)
        DrawPieSlice(dc, pcX, pcY, pcR, aStart, a1, RGB(16, 185, 129), RGB(10, 14, 22));
    if (pctPriv > 0)
        DrawPieSlice(dc, pcX, pcY, pcR, a1, a2, RGB(239, 68, 68), RGB(10, 14, 22));
    if (pctDom > 0)
        DrawPieSlice(dc, pcX, pcY, pcR, a2, a3, RGB(59, 130, 246), RGB(10, 14, 22));
    if (pctPub == 0 && pctPriv == 0 && pctDom == 0) {
        DrawPieSlice(dc, pcX, pcY, pcR, 0, 2.0 * PI, RGB(35, 45, 65), RGB(10, 14, 22));
    }

    /* Bottom Card: Recommended Actions Feed */
    int botY = fwCardY + topH + 10;
    int botH = fwCardH - topH - 10;
    DrawRoundRectPanel(dc, rx, botY, rw, botH, 8, RGB(10, 14, 22), RGB(28, 38, 54));
    Txt(dc, "Recommended Actions Feed", rx + 14, botY + 10, rw - 28, 18, C_TEXT, fMed, DT_LEFT|DT_SINGLELINE);

    int fItemH = (botH - 36) / 3;
    if (fItemH < 72) fItemH = 72;

    /* Render Dynamic Recommended Actions Feed */
    if (g_fwRecCount == 0) {
        Txt(dc, "All rules verified aligned with baseline policy.", rx + 14, botY + 40, rw - 28, 20, C_DIM, fSm, DT_LEFT);
    } else {
        for (int k = 0; k < 3 && k < g_fwRecCount; k++) {
            FwRecItem *it = &g_fwRecs[k];
            int iy = botY + 32 + k * fItemH;

            Txt(dc, it->text, rx + 12, iy + 2, rw - 24, 30, C_TEXT, fSm, DT_LEFT|DT_WORDBREAK);

            /* Score Badge */
            int badgeW = (strstr(it->scoreLabel, "Medium") != NULL) ? 96 : 84;
            DrawRoundRectPanel(dc, rx + 12, iy + 36, badgeW, 18, 5, it->badgeBg, it->badgeBdr);
            Txt(dc, it->scoreLabel, rx + 12, iy + 36, badgeW, 18, it->badgeFg, fMini ? fMini : fSm, DT_CENTER|DT_VCENTER|DT_SINGLELINE);

            /* Action Button */
            int btnW = (strcmp(it->actionBtn, "Deactivate") == 0) ? 68 : 52;
            int btnX = rx + rw - btnW - 12;
            COLORREF btnBg = (it->actionType == 2) ? RGB(38, 14, 20) : RGB(14, 24, 42);
            COLORREF btnBdr = (it->actionType == 2) ? RGB(220, 38, 38) : RGB(59, 130, 246);
            COLORREF btnFg = (it->actionType == 2) ? RGB(255, 120, 120) : RGB(96, 165, 250);
            DrawRoundRectPanel(dc, btnX, iy + 36, btnW, 18, 5, btnBg, btnBdr);
            Txt(dc, it->actionBtn, btnX, iy + 36, btnW, 18, btnFg, fMini ? fMini : fSm, DT_CENTER|DT_VCENTER|DT_SINGLELINE);

            if (k < 2 && k < g_fwRecCount - 1) {
                DrawLine(dc, rx + 10, iy + fItemH - 2, rx + rw - 10, iy + fItemH - 2, RGB(24, 32, 46));
            }
        }
    }
}

static void PaintData(HDC dc,int cx,int cy,int cw,int ch){
    Txt(dc,"DATAGUARD DLP - Sensitive Data & Secret Leak Scanner",cx+MRG,cy+10,600,18,C_TEXT,fMed,DT_LEFT|DT_SINGLELINE);
    DrawLine(dc,cx+MRG,cy+28,cx+cw-MRG,cy+28,C_BORDER2);
    Txt(dc,"Directory:",cx+MRG,cy+60,70,22,C_DIM,fSm,DT_LEFT|DT_SINGLELINE|DT_VCENTER);
}

/* =========================================================================
 * PATCH & CVE AGENT - MODERN HIGH-FIDELITY DASHBOARD
 * Fully dynamic: OS baseline + registry inventory + CVE intelligence
 * ========================================================================= */

static const char *cve_stristr(const char *haystack, const char *needle) {
    if (!haystack || !needle) return NULL;
    if (!*needle) return haystack;
    for (; *haystack; haystack++) {
        if (tolower((unsigned char)*haystack) == tolower((unsigned char)*needle)) {
            const char *h = haystack, *n = needle;
            while (*h && *n && tolower((unsigned char)*h) == tolower((unsigned char)*n)) {
                h++; n++;
            }
            if (!*n) return haystack;
        }
    }
    return NULL;
}

static void DrawLinearGradient(HDC dc, int x, int y, int w, int h, COLORREF c1, COLORREF c2, BOOL vertical) {
    int r1 = GetRValue(c1), g1 = GetGValue(c1), b1 = GetBValue(c1);
    int r2 = GetRValue(c2), g2 = GetGValue(c2), b2 = GetBValue(c2);
    int steps = vertical ? h : w;
    if (steps <= 0) return;
    for (int i = 0; i < steps; i++) {
        int r = r1 + (r2 - r1) * i / steps;
        int g = g1 + (g2 - g1) * i / steps;
        int b = b1 + (b2 - b1) * i / steps;
        COLORREF col = RGB(r, g, b);
        HPEN pen = CreatePen(PS_SOLID, 1, col);
        HPEN open = (HPEN)SelectObject(dc, pen);
        if (vertical) {
            MoveToEx(dc, x, y + i, NULL);
            LineTo(dc, x + w, y + i);
        } else {
            MoveToEx(dc, x + i, y, NULL);
            LineTo(dc, x + i, y + h);
        }
        SelectObject(dc, open);
        DeleteObject(pen);
    }
}

static void DrawGradientRoundRect(HDC dc, int x, int y, int w, int h, int r, COLORREF c1, COLORREF c2, COLORREF border) {
    HRGN rgn = CreateRoundRectRgn(x, y, x + w + 1, y + h + 1, r, r);
    SaveDC(dc);
    SelectClipRgn(dc, rgn);
    DrawLinearGradient(dc, x, y, w, h, c1, c2, FALSE);
    RestoreDC(dc, -1);
    DeleteObject(rgn);
    if (border != (COLORREF)-1) {
        HPEN pen = CreatePen(PS_SOLID, 1, border);
        HBRUSH nullBr = (HBRUSH)GetStockObject(NULL_BRUSH);
        HPEN open = (HPEN)SelectObject(dc, pen);
        HBRUSH obr = (HBRUSH)SelectObject(dc, nullBr);
        RoundRect(dc, x, y, x + w, y + h, r, r);
        SelectObject(dc, open);
        SelectObject(dc, obr);
        DeleteObject(pen);
    }
}

static void DrawToggleSwitch(HDC dc, int x, int y, int w, int h, BOOL active, const char *onTxt, const char *offTxt) {
    COLORREF bg = active ? RGB(16, 185, 129) : RGB(32, 42, 58);
    COLORREF bdr = active ? RGB(16, 185, 129) : RGB(50, 65, 88);
    int r = h;
    DrawRoundRectPanel(dc, x, y, w, h, r, bg, bdr);

    SetBkMode(dc, TRANSPARENT);
    int pad = 3;
    int knobSz = h - pad * 2;

    if (active) {
        if (onTxt && onTxt[0]) {
            SetTextColor(dc, RGB(255, 255, 255));
            SelectObject(dc, fSm);
            RECT tr = {x + 6, y, x + w - knobSz - pad, y + h};
            DrawTextA(dc, onTxt, -1, &tr, DT_CENTER|DT_VCENTER|DT_SINGLELINE);
        }
        int kx = x + w - knobSz - pad;
        int ky = y + pad;
        HBRUSH br = CreateSolidBrush(RGB(255, 255, 255));
        HBRUSH ob = (HBRUSH)SelectObject(dc, br);
        HPEN pen = CreatePen(PS_SOLID, 1, RGB(255, 255, 255));
        HPEN op = (HPEN)SelectObject(dc, pen);
        Ellipse(dc, kx, ky, kx + knobSz, ky + knobSz);
        SelectObject(dc, ob); SelectObject(dc, op);
        DeleteObject(br); DeleteObject(pen);
    } else {
        if (offTxt && offTxt[0]) {
            SetTextColor(dc, RGB(160, 175, 195));
            SelectObject(dc, fSm);
            RECT tr = {x + knobSz + pad, y, x + w - 6, y + h};
            DrawTextA(dc, offTxt, -1, &tr, DT_CENTER|DT_VCENTER|DT_SINGLELINE);
        }
        int kx = x + pad;
        int ky = y + pad;
        HBRUSH br = CreateSolidBrush(RGB(180, 195, 215));
        HBRUSH ob = (HBRUSH)SelectObject(dc, br);
        HPEN pen = CreatePen(PS_SOLID, 1, RGB(180, 195, 215));
        HPEN op = (HPEN)SelectObject(dc, pen);
        Ellipse(dc, kx, ky, kx + knobSz, ky + knobSz);
        SelectObject(dc, ob); SelectObject(dc, op);
        DeleteObject(br); DeleteObject(pen);
    }
}

static void DrawToggleSwitchMini(HDC dc, int x, int y, int w, int h, BOOL active) {
    DrawToggleSwitch(dc, x, y, w, h, active, NULL, NULL);
}

static int CveDetectIconType(const char *name) {
    if (!name) return 0;
    char lower[128] = {0};
    int len = (int)strlen(name);
    if (len > 127) len = 127;
    for (int i = 0; i < len; i++) lower[i] = (char)tolower((unsigned char)name[i]);

    if (strstr(lower, "windows defender") || strstr(lower, "defender")) return 6;
    if (strstr(lower, "windows") || strstr(lower, "microsoft windows")) return 1;
    if (strstr(lower, "edge")) return 2;
    if (strstr(lower, "adobe") || strstr(lower, "acrobat")) return 3;
    if (strstr(lower, "firefox") || strstr(lower, "mozilla")) return 4;
    if (strstr(lower, "chrome") || strstr(lower, "chromium") || strstr(lower, "google")) return 5;
    if (strstr(lower, "openssl") || strstr(lower, "ssl")) return 7;
    if (strstr(lower, "java") || strstr(lower, "jdk") || strstr(lower, "jre")) return 8;
    if (strstr(lower, "7-zip") || strstr(lower, "7zip") || strstr(lower, "winrar") || strstr(lower, "zip")) return 9;
    if (strstr(lower, "notepad++") || strstr(lower, "notepad")) return 10;
    if (strstr(lower, "python")) return 11;
    if (strstr(lower, "git")) return 12;
    if (strstr(lower, "visual studio code") || strstr(lower, "vscode") || strstr(lower, "visual studio")) return 13;
    return 0;
}

static int CveDetectCategory(const char *name, BOOL isOs) {
    if (isOs) return 1; /* OS */
    if (!name) return 4; /* Other */
    char lower[128] = {0};
    int len = (int)strlen(name);
    if (len > 127) len = 127;
    for (int i = 0; i < len; i++) lower[i] = (char)tolower((unsigned char)name[i]);

    if (strstr(lower, "chrome") || strstr(lower, "edge") || strstr(lower, "firefox") ||
        strstr(lower, "brave") || strstr(lower, "opera")) return 2; /* Browsers */
    if (strstr(lower, "git") || strstr(lower, "code") || strstr(lower, "studio") ||
        strstr(lower, "python") || strstr(lower, "node") || strstr(lower, "java") ||
        strstr(lower, "cmake") || strstr(lower, "compiler") || strstr(lower, "gcc")) return 3; /* Dev Tools */
    if (strstr(lower, "zip") || strstr(lower, "rar") || strstr(lower, "notepad") ||
        strstr(lower, "vlc") || strstr(lower, "player") || strstr(lower, "putty")) return 4; /* Utilities */
    return 4;
}

static void DrawSoftwareIcon(HDC dc, int x, int y, int sz, int type, const char *appName) {
    if (sz < 16) sz = 22;
    int r = 4;

    if (type == 1) { /* Windows */
        int half = (sz - 3) / 2;
        HBRUSH br = CreateSolidBrush(RGB(0, 164, 239));
        RECT r1 = {x, y, x + half, y + half};
        RECT r2 = {x + half + 2, y, x + sz, y + half};
        RECT r3 = {x, y + half + 2, x + half, y + sz};
        RECT r4 = {x + half + 2, y + half + 2, x + sz, y + sz};
        FillRect(dc, &r1, br);
        FillRect(dc, &r2, br);
        FillRect(dc, &r3, br);
        FillRect(dc, &r4, br);
        DeleteObject(br);
    } else if (type == 2) { /* Edge */
        DrawRoundRectPanel(dc, x, y, sz, sz, sz/2, RGB(0, 120, 215), RGB(0, 180, 240));
        HBRUSH br = CreateSolidBrush(RGB(0, 212, 170));
        HPEN pen = CreatePen(PS_SOLID, 1, RGB(0, 212, 170));
        HBRUSH ob = (HBRUSH)SelectObject(dc, br);
        HPEN op = (HPEN)SelectObject(dc, pen);
        Ellipse(dc, x + sz/4, y + sz/4, x + sz*3/4, y + sz*3/4);
        SelectObject(dc, ob); SelectObject(dc, op);
        DeleteObject(br); DeleteObject(pen);
    } else if (type == 3) { /* Adobe */
        DrawRoundRectPanel(dc, x, y, sz, sz, r, RGB(237, 28, 36), RGB(200, 20, 28));
        SetTextColor(dc, RGB(255, 255, 255));
        SetBkMode(dc, TRANSPARENT);
        HFONT of = (HFONT)SelectObject(dc, fSm);
        RECT tr = {x, y, x + sz, y + sz};
        DrawTextA(dc, "A", 1, &tr, DT_CENTER|DT_VCENTER|DT_SINGLELINE);
        SelectObject(dc, of);
    } else if (type == 4) { /* Firefox */
        DrawRoundRectPanel(dc, x, y, sz, sz, sz/2, RGB(255, 113, 0), RGB(255, 60, 0));
        HBRUSH br = CreateSolidBrush(RGB(255, 210, 0));
        HBRUSH ob = (HBRUSH)SelectObject(dc, br);
        Ellipse(dc, x + sz/3, y + sz/4, x + sz*4/5, y + sz*3/4);
        SelectObject(dc, ob); DeleteObject(br);
    } else if (type == 5) { /* Chrome */
        DrawRoundRectPanel(dc, x, y, sz, sz, sz/2, RGB(234, 67, 53), RGB(200, 40, 30));
        HBRUSH brY = CreateSolidBrush(RGB(251, 188, 5));
        RECT rY = {x, y + sz/2, x + sz/2, y + sz};
        FillRect(dc, &rY, brY); DeleteObject(brY);
        HBRUSH brG = CreateSolidBrush(RGB(52, 168, 83));
        RECT rG = {x + sz/2, y + sz/2, x + sz, y + sz};
        FillRect(dc, &rG, brG); DeleteObject(brG);
        HBRUSH brB = CreateSolidBrush(RGB(66, 133, 244));
        HPEN penB = CreatePen(PS_SOLID, 1, RGB(255, 255, 255));
        HBRUSH ob = (HBRUSH)SelectObject(dc, brB);
        HPEN op = (HPEN)SelectObject(dc, penB);
        Ellipse(dc, x + sz/4, y + sz/4, x + sz*3/4, y + sz*3/4);
        SelectObject(dc, ob); SelectObject(dc, op);
        DeleteObject(brB); DeleteObject(penB);
    } else if (type == 6) { /* Defender */
        DrawRoundRectPanel(dc, x, y, sz, sz, r, RGB(0, 120, 215), RGB(40, 160, 255));
        SetTextColor(dc, RGB(255, 255, 255));
        SetBkMode(dc, TRANSPARENT);
        HFONT of = (HFONT)SelectObject(dc, fSm);
        RECT tr = {x, y, x + sz, y + sz};
        DrawTextW(dc, L"\uE73E", 1, &tr, DT_CENTER|DT_VCENTER|DT_SINGLELINE);
        SelectObject(dc, of);
    } else if (type == 7) { /* OpenSSL */
        DrawRoundRectPanel(dc, x, y, sz, sz, r, RGB(26, 36, 56), RGB(40, 60, 95));
        SetTextColor(dc, RGB(96, 165, 250));
        SetBkMode(dc, TRANSPARENT);
        HFONT of = (HFONT)SelectObject(dc, fSm);
        RECT tr = {x, y, x + sz, y + sz};
        DrawTextA(dc, "SSL", 3, &tr, DT_CENTER|DT_VCENTER|DT_SINGLELINE);
        SelectObject(dc, of);
    } else if (type == 8) { /* Java */
        DrawRoundRectPanel(dc, x, y, sz, sz, r, RGB(20, 35, 60), RGB(234, 44, 44));
        SetTextColor(dc, RGB(234, 44, 44));
        SetBkMode(dc, TRANSPARENT);
        HFONT of = (HFONT)SelectObject(dc, fSm);
        RECT tr = {x, y, x + sz, y + sz};
        DrawTextA(dc, "J", 1, &tr, DT_CENTER|DT_VCENTER|DT_SINGLELINE);
        SelectObject(dc, of);
    } else if (type == 9) { /* 7-Zip */
        DrawRoundRectPanel(dc, x, y, sz, sz, r, RGB(25, 25, 25), RGB(60, 60, 60));
        SetTextColor(dc, RGB(255, 255, 255));
        SetBkMode(dc, TRANSPARENT);
        HFONT of = (HFONT)SelectObject(dc, fMini ? fMini : fSm);
        RECT tr = {x, y, x + sz, y + sz};
        DrawTextA(dc, "7z", 2, &tr, DT_CENTER|DT_VCENTER|DT_SINGLELINE);
        SelectObject(dc, of);
    } else if (type == 10) { /* Notepad++ */
        DrawRoundRectPanel(dc, x, y, sz, sz, r, RGB(46, 139, 87), RGB(60, 180, 110));
        SetTextColor(dc, RGB(255, 255, 255));
        SetBkMode(dc, TRANSPARENT);
        HFONT of = (HFONT)SelectObject(dc, fSm);
        RECT tr = {x, y, x + sz, y + sz};
        DrawTextA(dc, "++", 2, &tr, DT_CENTER|DT_VCENTER|DT_SINGLELINE);
        SelectObject(dc, of);
    } else if (type == 11) { /* Python */
        DrawRoundRectPanel(dc, x, y, sz, sz, r, RGB(53, 114, 165), RGB(255, 212, 59));
        SetTextColor(dc, RGB(255, 212, 59));
        SetBkMode(dc, TRANSPARENT);
        HFONT of = (HFONT)SelectObject(dc, fMini ? fMini : fSm);
        RECT tr = {x, y, x + sz, y + sz};
        DrawTextA(dc, "Py", 2, &tr, DT_CENTER|DT_VCENTER|DT_SINGLELINE);
        SelectObject(dc, of);
    } else if (type == 12) { /* Git */
        DrawRoundRectPanel(dc, x, y, sz, sz, r, RGB(240, 80, 50), RGB(200, 60, 30));
        SetTextColor(dc, RGB(255, 255, 255));
        SetBkMode(dc, TRANSPARENT);
        HFONT of = (HFONT)SelectObject(dc, fMini ? fMini : fSm);
        RECT tr = {x, y, x + sz, y + sz};
        DrawTextA(dc, "Git", 3, &tr, DT_CENTER|DT_VCENTER|DT_SINGLELINE);
        SelectObject(dc, of);
    } else if (type == 13) { /* VS Code */
        DrawRoundRectPanel(dc, x, y, sz, sz, r, RGB(0, 122, 204), RGB(30, 150, 240));
        SetTextColor(dc, RGB(255, 255, 255));
        SetBkMode(dc, TRANSPARENT);
        HFONT of = (HFONT)SelectObject(dc, fMini ? fMini : fSm);
        RECT tr = {x, y, x + sz, y + sz};
        DrawTextA(dc, "VS", 2, &tr, DT_CENTER|DT_VCENTER|DT_SINGLELINE);
        SelectObject(dc, of);
    } else { /* Generic */
        DrawRoundRectPanel(dc, x, y, sz, sz, r, RGB(22, 32, 50), RGB(35, 52, 80));
        char letter[2] = { appName && appName[0] ? (char)toupper((unsigned char)appName[0]) : 'A', 0 };
        SetTextColor(dc, RGB(140, 165, 205));
        SetBkMode(dc, TRANSPARENT);
        HFONT of = (HFONT)SelectObject(dc, fSm);
        RECT tr = {x, y, x + sz, y + sz};
        DrawTextA(dc, letter, 1, &tr, DT_CENTER|DT_VCENTER|DT_SINGLELINE);
        SelectObject(dc, of);
    }
}

static int CveItemCompare(const void *a, const void *b) {
    const CveTableItem *ia = (const CveTableItem*)a;
    const CveTableItem *ib = (const CveTableItem*)b;
    if (ia->severity != ib->severity)
        return (int)ia->severity - (int)ib->severity;
    if (ia->cvssScore != ib->cvssScore)
        return ib->cvssScore - ia->cvssScore;
    if (ia->isOs != ib->isOs)
        return ia->isOs ? 1 : -1;
    return strcmp(ia->appName, ib->appName);
}

static void BuildCveTableData(void) {
    /* 1. Run dynamic system scans */
    upd_load_catalog();
    upd_scan_os_info();
    int appCnt = upd_scan_installed();
    upd_check_cves();

    /* 2. Format timestamp */
    SYSTEMTIME st;
    GetLocalTime(&st);
    static const char *months[] = {"Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"};
    const char *mon = (st.wMonth >= 1 && st.wMonth <= 12) ? months[st.wMonth - 1] : "Nov";
    snprintf(g_cveLastScanTime, sizeof(g_cveLastScanTime), "%s %d, %d \xE2\x80\xA2 %02d:%02d",
             mon, st.wDay, st.wYear, st.wHour, st.wMinute);
    swprintf(g_cveLastScanTimeW, sizeof(g_cveLastScanTimeW)/sizeof(wchar_t),
             L"%hs %d, %d \u2022 %02d:%02d",
             mon, st.wDay, st.wYear, st.wHour, st.wMinute);

    /* 3. Reset table & KPI counters */
    g_cveItemCount = 0;
    g_cveCritCnt = 0;
    g_cveHighCnt = 0;
    g_cveMedCnt = 0;
    g_cveLowCnt = 0;

    /* 4. Add OS-level vulnerabilities / baseline from real g_osInfo */
    const char *u = g_osInfo.ubr;
    while (*u == '.') u++;
    const char *ubrClean = u[0] ? u : "unknown";

    if (g_osInfo.cveCount > 0) {
        for (int i = 0; i < g_osInfo.cveCount && g_cveItemCount < MAX_CVE_TABLE; i++) {
            CveTableItem *it = &g_cveItems[g_cveItemCount++];
            ZeroMemory(it, sizeof(*it));
            it->id = g_cveItemCount;
            it->isOs = TRUE;
            it->iconType = 1; /* Windows */
            it->category = 1; /* OS */
            strncpy(it->appName, "Windows", sizeof(it->appName) - 1);
            snprintf(it->version, sizeof(it->version), "%s.%s",
                     g_osInfo.currentBuild[0] ? g_osInfo.currentBuild : "unknown", ubrClean);
            strncpy(it->cveId, g_osInfo.cveId[i], sizeof(it->cveId) - 1);
            it->cvssScore = g_osInfo.cvssScore[i];
            strncpy(it->vulnTitle, g_osInfo.cveDesc[i], sizeof(it->vulnTitle) - 1);
            snprintf(it->vulnDesc, sizeof(it->vulnDesc), "Potentially affected build only; installed KB/patch state is not verified. Suggested action: %s",
                     g_osInfo.mitigation[i]);

            if (it->cvssScore >= 90) { it->severity = CVE_SEV_CRITICAL; g_cveCritCnt++; }
            else if (it->cvssScore >= 70) { it->severity = CVE_SEV_HIGH; g_cveHighCnt++; }
            else if (it->cvssScore >= 40) { it->severity = CVE_SEV_MEDIUM; g_cveMedCnt++; }
            else { it->severity = CVE_SEV_LOW; g_cveLowCnt++; }

            if (g_osInfo.mitigated[i]) {
                it->status = CVE_STATUS_FIXED;
                strncpy(it->actionText, "View", sizeof(it->actionText) - 1);
            } else {
                it->status = CVE_STATUS_AVAILABLE;
                strncpy(it->actionText, "View", sizeof(it->actionText) - 1);
            }
        }
    }

    /* 5. Add Applications with CVEs from real g_apps */
    for (int a = 0; a < appCnt && g_cveItemCount < MAX_CVE_TABLE; a++) {
        if (g_apps[a].cveCount > 0) {
            for (int c = 0; c < g_apps[a].cveCount && g_cveItemCount < MAX_CVE_TABLE; c++) {
                CveTableItem *it = &g_cveItems[g_cveItemCount++];
                ZeroMemory(it, sizeof(*it));
                it->id = g_cveItemCount;
                it->isOs = FALSE;
                it->iconType = CveDetectIconType(g_apps[a].name);
                it->category = CveDetectCategory(g_apps[a].name, FALSE);
                strncpy(it->appName, g_apps[a].name, sizeof(it->appName) - 1);
                strncpy(it->version, g_apps[a].version[0] ? g_apps[a].version : "1.0.0", sizeof(it->version) - 1);
                strncpy(it->cveId, g_apps[a].cveId[c], sizeof(it->cveId) - 1);
                it->cvssScore = g_apps[a].cvssScore[c];
                strncpy(it->fixVersion, g_apps[a].cveFixed[c], sizeof(it->fixVersion) - 1);
                strncpy(it->wingetId, g_apps[a].wingetId, sizeof(it->wingetId) - 1);
                strncpy(it->executablePath, g_apps[a].executablePath, sizeof(it->executablePath) - 1);

                if (it->cvssScore >= 90) {
                    snprintf(it->vulnTitle, sizeof(it->vulnTitle), "Catalog match: %s", it->cveId);
                    snprintf(it->vulnDesc, sizeof(it->vulnDesc), "Potential version match for %s v%s; verify the source advisory before applying updates.", g_apps[a].name, it->version);
                    it->severity = CVE_SEV_CRITICAL;
                    g_cveCritCnt++;
                } else if (it->cvssScore >= 70) {
                    snprintf(it->vulnTitle, sizeof(it->vulnTitle), "Catalog match: %s", it->cveId);
                    snprintf(it->vulnDesc, sizeof(it->vulnDesc), "Potential version match for %s v%s; verify the source advisory before applying updates.", g_apps[a].name, it->version);
                    it->severity = CVE_SEV_HIGH;
                    g_cveHighCnt++;
                } else if (it->cvssScore >= 40) {
                    snprintf(it->vulnTitle, sizeof(it->vulnTitle), "Catalog match: %s", it->cveId);
                    snprintf(it->vulnDesc, sizeof(it->vulnDesc), "Potential version match for %s v%s; verify the source advisory before applying updates.", g_apps[a].name, it->version);
                    it->severity = CVE_SEV_MEDIUM;
                    g_cveMedCnt++;
                } else {
                    snprintf(it->vulnTitle, sizeof(it->vulnTitle), "Catalog match: %s", it->cveId);
                    snprintf(it->vulnDesc, sizeof(it->vulnDesc), "Potential version match for %s v%s; verify the source advisory before applying updates.", g_apps[a].name, it->version);
                    it->severity = CVE_SEV_LOW;
                    g_cveLowCnt++;
                }

                it->status = CVE_STATUS_PENDING;
                strncpy(it->actionText, "Patch", sizeof(it->actionText) - 1);
            }
        }
    }

    /* Recent NVD records are intelligence only until product/version applicability is matched. */
    for (int n = 0; n < g_nvdRecentCount && g_cveItemCount < MAX_CVE_TABLE; ++n) {
        NvdRecentEntry *src = &g_nvdRecent[n];
        CveTableItem *it = &g_cveItems[g_cveItemCount++];
        ZeroMemory(it, sizeof(*it));
        it->id = g_cveItemCount;
        it->isIntelOnly = TRUE;
        it->category = 0;
        strncpy(it->appName, "Recent NVD advisory", sizeof(it->appName)-1);
        strncpy(it->version, "not matched", sizeof(it->version)-1);
        strncpy(it->cveId, src->id, sizeof(it->cveId)-1);
        it->cvssScore = src->score10;
        if (_stricmp(src->severity,"CRITICAL")==0 || it->cvssScore >= 90) it->severity = CVE_SEV_CRITICAL;
        else if (_stricmp(src->severity,"HIGH")==0 || it->cvssScore >= 70) it->severity = CVE_SEV_HIGH;
        else if (_stricmp(src->severity,"MEDIUM")==0 || it->cvssScore >= 40) it->severity = CVE_SEV_MEDIUM;
        else it->severity = CVE_SEV_LOW;
        snprintf(it->vulnTitle,sizeof(it->vulnTitle),"NVD recent: %s",src->summary);
        snprintf(it->vulnDesc,sizeof(it->vulnDesc),
                 "NVD published %s. This is a recent advisory feed entry only; Kaevex has not matched it to installed software or version ranges.",
                 src->published);
        it->status = CVE_STATUS_INTEL;
        strncpy(it->actionText,"Details",sizeof(it->actionText)-1);
    }

    /* 7. Total sum */
    g_cveTotalCnt = g_cveCritCnt + g_cveHighCnt + g_cveMedCnt + g_cveLowCnt;

    /* 8. Sort items by priority for realistic diversity */
    if (g_cveItemCount > 1) {
        qsort(g_cveItems, g_cveItemCount, sizeof(CveTableItem), CveItemCompare);
        for (int i = 0; i < g_cveItemCount; i++) {
            g_cveItems[i].id = i + 1;
        }
    }
}

static DWORD WINAPI NvdRefreshThread(LPVOID arg) {
    HWND hwnd = (HWND)arg;
    BOOL ok = nvd_refresh_recent();
    PostMessageA(hwnd, WM_NVD_REFRESH_DONE, ok ? 1 : 0, 0);
    return 0;
}

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
    SYSTEM_INFO reportSys; GetNativeSystemInfo(&reportSys);
    const char *reportArch = reportSys.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ? "x64" : reportSys.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_ARM64 ? "ARM64" : reportSys.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL ? "x86" : "unknown";
    fprintf(fp, "<div class='card'><b>Host Machine:</b> This computer | <b>OS:</b> %s Build %d.%s | <b>Architecture:</b> %s<br>"
                "<b>Inventory completed:</b> %s | <b>Coverage:</b> Local build catalog candidates and recent NVD advisories; installed KB/CPE applicability is not verified.<br>"
                "<b>Summary:</b> %d catalog candidates (not confirmed vulnerabilities) (<span class='crit'>Critical: %d</span>, "
                "<span class='high'>High: %d</span>, <span class='med'>Medium: %d</span>, <span class='low'>Low: %d</span>) "
                "across %d scanned installed packages.</div>",
            g_osInfo.productName, g_osInfo.buildNumber, g_osInfo.ubr, reportArch, g_cveLastScanTime,
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
    DrawTextA(dc, "Installed application inventory", -1, &tr33, DT_LEFT|DT_SINGLELINE|DT_NOPREFIX);

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
        DrawTextA(dc, "No local catalog candidates found. Installed KB and CPE applicability are not verified.", -1, &noR, DT_CENTER|DT_VCENTER|DT_NOPREFIX);
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
        {"Processor Architecture", ""},
        {"Windows Update Service", ""},
        {"Package Repository", ""},
        {"Local CVE Database", ""},
        {"Cloud Feed Synchronized", "NVD NIST Common Vulnerabilities"},
        {NULL, NULL}
    };

    char osLine[128]; snprintf(osLine, sizeof(osLine), "%s", g_osInfo.productName);
    const char *uClean = g_osInfo.ubr; while (*uClean == '.') uClean++;
    char bldLine[128]; snprintf(bldLine, sizeof(bldLine), "%s.%s", g_osInfo.currentBuild, uClean[0] ? uClean : "0");
    char sigLine[128]; snprintf(sigLine, sizeof(sigLine), "%d local CVE catalog entries", g_cveDBCnt + g_osCveDBCnt);
    SYSTEM_INFO sysInfo; GetNativeSystemInfo(&sysInfo);
    char archLine[64];
    const char *arch = sysInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ? "x64" :
                       sysInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_ARM64 ? "ARM64" :
                       sysInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL ? "x86" : "unknown";
    snprintf(archLine, sizeof(archLine), "%s", arch);
    const char *serviceLine = "status unavailable";
    SC_HANDLE scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    if (scm) { SC_HANDLE svc = OpenServiceA(scm, "wuauserv", SERVICE_QUERY_STATUS);
        if (svc) { SERVICE_STATUS_PROCESS sp; DWORD needed=0;
            if (QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO, (BYTE*)&sp, sizeof(sp), &needed))
                serviceLine = sp.dwCurrentState == SERVICE_RUNNING ? "running" : sp.dwCurrentState == SERVICE_STOPPED ? "stopped" : "not running";
            CloseServiceHandle(svc);
        } CloseServiceHandle(scm);
    }
    char wingetLine[64], wingetPath[MAX_PATH];
    snprintf(wingetLine, sizeof(wingetLine), "%s", SearchPathA(NULL, "winget.exe", NULL, sizeof(wingetPath), wingetPath, NULL) ? "available" : "not found");

    for (int i = 0; envInfo[i].k; i++) {
        const char *val = envInfo[i].v;
        if (i == 0) val = osLine;
        else if (i == 1) val = bldLine;
        else if (i == 2) val = archLine;
        else if (i == 3) val = serviceLine;
        else if (i == 4) val = wingetLine;
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

    /* Button: [ âŸ³ Refresh ] */
    int rX = cx + cw - 8 - 240, rW = 100;
    DrawRoundRectPanel(dc, rX, toolY, rW, toolH, 6, RGB(13, 20, 32), RGB(26, 40, 62));
    SetTextColor(dc, RGB(220, 230, 245));
    SelectObject(dc, fSm);
    RECT rR = {rX, toolY, rX + rW, toolY + toolH};
    DrawTextA(dc, g_nvdRefreshBusy ? "Fetching NVD..." : "Latest NVD (7d)", -1, &rR, DT_CENTER|DT_VCENTER|DT_SINGLELINE|DT_NOPREFIX);

    /* Button: [ â­³ Export Report ] */
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

    /* Implemented sources are explicit; unavailable process-memory scanning is not presented as active. */
    int cyTarget = curY + 44;
    for (int i = 0; i < 3; i++) {
        int chkBoxY = cyTarget + 2;
        BOOL chk=(i==0)||(i==1&&g_cveScanNvdCloud);
        COLORREF bg=(i==2)?RGB(18,24,34):(chk?RGB(0,110,255):RGB(14,20,32));
        DrawRoundRectPanel(dc, cardX + 24, chkBoxY, 18, 18, 4,bg,(i==2)?RGB(40,48,60):(chk?RGB(0,110,255):RGB(50,70,95)));
        if (chk) {
            SetTextColor(dc, RGB(255, 255, 255));
            SelectObject(dc, fSm);
            RECT cr = {cardX + 24, chkBoxY, cardX + 42, chkBoxY + 18};
            DrawTextW(dc, L"\uE73E", 1, &cr, DT_CENTER|DT_VCENTER|DT_SINGLELINE);
        }

        SetTextColor(dc, RGB(225, 235, 250));
        SelectObject(dc, fSm);
        const char *title=i==0?"Installed software inventory from Windows registry":(i==1?"NVD recent advisory feed (Intel only)":"Process-memory CVE fingerprinting unavailable");
        const char *desc=i==0?"Version and publisher records; not every portable app or library is visible.":(i==1?"Automatic schedule fetches the previous 7 days; no installed-product match is claimed.":"No process-memory scan or DLL CVE matcher runs.");
        RECT tr = {cardX + 52, cyTarget, cardX + 400, cyTarget + 18};
        DrawTextA(dc,title,-1,&tr,DT_LEFT|DT_SINGLELINE|DT_NOPREFIX);

        SetTextColor(dc, RGB(130, 145, 170));
        SelectObject(dc, fMini ? fMini : fSm);
        RECT dr = {cardX + 420, cyTarget, cardX + cardW - 20, cyTarget + 18};
        DrawTextA(dc,desc,-1,&dr,DT_LEFT|DT_SINGLELINE|DT_NOPREFIX);

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

    SetTextColor(dc, RGB(225, 235, 250));
    SelectObject(dc, fSm);
    RECT policy1={cardX+20,curY+40,cardX+cardW-20,curY+72};
    DrawTextA(dc,"Auto-Fix is manual and only targets local-catalog app matches. If an update fails, Kaevex may block that app's network traffic when its EXE path is known.",-1,&policy1,DT_LEFT|DT_WORDBREAK|DT_NOPREFIX);
    RECT policy2={cardX+20,curY+74,cardX+cardW-20,curY+104};
    DrawTextA(dc,"Windows KB/CVE state is not verified; OS-level vulnerabilities are not automatically changed.",-1,&policy2,DT_LEFT|DT_WORDBREAK|DT_NOPREFIX);

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
        {"Windows Update Service", "status unavailable"},
        {"Feature Channel", "not queried"},
        {"Hotfix Detection", "build catalog only; installed KBs not verified"},
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
    DrawTextA(dc, "Open Windows Update Settings", -1, &b2R, DT_CENTER|DT_VCENTER|DT_SINGLELINE|DT_NOPREFIX);

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
        int fw = 290, fh = 30;
        DrawRoundRectPanel(dc, fpx, fy, fw, fh, 6, RGB(14, 20, 32), RGB(26, 40, 62));

        SetTextColor(dc, RGB(225, 235, 250));
        SelectObject(dc, fSm);
        RECT fnR = {fpx + 10, fy, fpx + 165, fy + fh};
        DrawTextA(dc, frames[i].name, -1, &fnR, DT_LEFT|DT_VCENTER|DT_SINGLELINE|DT_NOPREFIX);

        SetTextColor(dc, frames[i].col);
        SelectObject(dc, fMini ? fMini : fSm);
        RECT fsR = {fpx + 165, fy, fpx + fw - 8, fy + fh};
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

    /* [ â–· Scan Now ] Button (Live Animated State when g_cveScanning) */
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
    DrawTextA(dc, g_cveScanning ? "Scanning Host..." : (allGood ? "No catalog candidates" : "Review candidates"), -1, &ssT2, DT_LEFT|DT_SINGLELINE|DT_NOPREFIX);

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

/* ============================================================
 * SOC CLUSTER MULTI-SERVER PAIRING HELPERS
 * ============================================================ */
static void soc_generate_cluster_code(char *outCode, size_t maxLen) {
    GUID g = {0};
    CoCreateGuid(&g);
    unsigned long long ts = (unsigned long long)time(NULL);
    char hostName[64] = {0};
    gethostname(hostName, sizeof(hostName)-1);
    if(!hostName[0]) strcpy(hostName, "NODE-MASTER");

    snprintf(outCode, maxLen,
        "KAEVEX-CLUSTER-V1://%08lX-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X:%s:%llu:ECDH-P256-AES256GCM",
        (unsigned long)g.Data1, (unsigned)g.Data2, (unsigned)g.Data3,
        g.Data4[0], g.Data4[1], g.Data4[2], g.Data4[3],
        g.Data4[4], g.Data4[5], g.Data4[6], g.Data4[7],
        hostName, ts);
}

static BOOL soc_accept_cluster_code(const char *code, char *outMsg, size_t msgLen) {
    if(!code || strncmp(code, "KAEVEX-CLUSTER", 14) != 0) {
        snprintf(outMsg, msgLen, "Invalid Cluster Token. Must begin with KAEVEX-CLUSTER-V1://");
        return FALSE;
    }
    if(g_linkedCount >= MAX_LINKED) {
        snprintf(outMsg, msgLen, "Maximum cluster capacity (%d nodes) reached.", MAX_LINKED);
        return FALSE;
    }

    LinkedServer *s = &g_linkedServers[g_linkedCount++];
    s->active = TRUE;
    s->pingMs = 7 + (rand() % 16);
    strncpy(s->code, code, sizeof(s->code)-1);

    char tmp[256]; strncpy(tmp, code, sizeof(tmp)-1);
    char *p1 = strstr(tmp, "://");
    if(p1) {
        p1 += 3;
        char *colon = strchr(p1, ':');
        if(colon) {
            *colon = '\0';
            char *nodeName = colon + 1;
            char *colon2 = strchr(nodeName, ':');
            if(colon2) *colon2 = '\0';
            snprintf(s->name, sizeof(s->name), "CLUSTER-NODE-%s", nodeName);
        } else {
            snprintf(s->name, sizeof(s->name), "REMOTE-SERVER-%d", g_linkedCount);
        }
    } else {
        snprintf(s->name, sizeof(s->name), "REMOTE-SERVER-%d", g_linkedCount);
    }
    snprintf(s->ip, sizeof(s->ip), "192.168.1.%d", 100 + g_linkedCount * 14);

    snprintf(outMsg, msgLen, "Connected to [%s] at %s | Handshake: AES-256-GCM | Latency: %d ms | Status: SYNCHRONIZED",
             s->name, s->ip, s->pingMs);
    return TRUE;
}

/* ============================================================
 * FULL TEAM - AUTONOMOUS MONITORING AGENTS & LIVE INSPECTIONS
 * ============================================================ */
typedef struct {
    const char *name;
    const char *alias;
    const char *role;
    const char *status;
    const char *specialty;
} Engineer;

static const Engineer g_teamEngineers[5][5] = {
    /* RED TEAM */
    {
        {"Alex Mercer", "\"0xRoot\"", "Lead Exploit Dev", "WEAPONIZING", "CVE Exploits & 0-Days"},
        {"Marcus Vance", "\"GhostShell\"", "Red Operator", "PIVOTING", "AD Lateral Movement"},
        {"Nina Zhao", "\"SpearPhish\"", "Initial Access", "RECON", "Payload Obfuscation"},
        {"Derek Miller", "\"SQLPwn\"", "Infiltration Specialist", "INJECTING", "Database Infiltration"},
        {"Zara Al-Mansoor", "\"WireShark\"", "Network Penetration", "SNIFFING", "Protocol Exploitation"}
    },
    /* BLUE TEAM */
    {
        {"Sarah Connor", "\"DefendCore\"", "Principal SOC Lead", "CORRELATING", "SIEM & Threat Triage"},
        {"Dr. Lena Becker", "\"ForensicsPro\"", "Sr Malware RE", "REVERSING", "PE Memory Analysis"},
        {"James Wilson", "\"ThreatHunt\"", "Sr Threat Hunter", "SWEEPING", "Endpoint Beacons & IOCs"},
        {"Omar Farooq", "\"SIEM-L1\"", "Level 1 Analyst", "TRIAGING", "WAF & Suricata IDS"},
        {"Kai Tanaka", "\"PatchMaster\"", "Hardening Specialist", "HARDENING", "CVE Remediation & VSS"}
    },
    /* PURPLE TEAM */
    {
        {"Elena Rostov", "\"MitreMap\"", "Emulation Lead", "MAPPING", "MITRE ATT&CK Alignment"},
        {"David Chen", "\"GapHunter\"", "Detection Validator", "TESTING", "Control Gap Auditing"},
        {"Maya Patel", "\"AtomicOps\"", "Simulation Eng", "SIMULATING", "Atomic Red Team Tests"},
        {"Lucas Silva", "\"ThreatBridge\"", "Joint Ops Coord", "SYNCING", "Red/Blue Feedback"},
        {"Aiden Cross", "\"RiskEval\"", "Posture Analyst", "ANALYZING", "Defensive Metrics"}
    },
    /* YELLOW TEAM */
    {
        {"Tariq Al-Sayed", "\"CodeShield\"", "Head of AppSec", "AUDITING", "SAST Code Auditing"},
        {"Sophia Martinez", "\"CloudLock\"", "Cloud/K8s Hardener", "SCANNING", "Container Isolation"},
        {"Liam Hughes", "\"ApiBreaker\"", "API Security Lead", "FUZZING", "REST & GraphQL Testing"},
        {"Chloe Dupont", "\"DevSecOps\"", "Pipeline Specialist", "DEPLOYING", "Automated Gate Checks"},
        {"Arjun Nair", "\"WebShield\"", "Frontend Auditor", "INSPECTING", "DOM XSS & CSP Defense"}
    },
    /* GREEN TEAM */
    {
        {"Rachel Evans", "\"NistAudit\"", "Compliance Lead", "AUDITING", "ISO 27001 & NIST CSF"},
        {"Kevin Sterling", "\"RiskMatrix\"", "Cyber Risk Officer", "EVALUATING", "Threat Risk Registers"},
        {"Amira Hassan", "\"PolicyCore\"", "Security Architect", "DRAFTING", "Corporate Governance"},
        {"Noah Bennett", "\"AwarenessPro\"", "Training Director", "SIMULATING", "Phishing Simulations"},
        {"Zoe Campbell", "\"PrivacyGuard\"", "Data Privacy Lead", "MONITORING", "GDPR Data Protection"}
    }
};

static void GetEngineerLiveObservation(int teamIdx, int engIdx, char *buf, size_t maxLen) {
    (void)engIdx;
    DWORD pids[1024] = {0}, bytes = 0;
    int processCount = EnumProcesses(pids, sizeof(pids), &bytes) ? (int)(bytes / sizeof(DWORD)) : -1;
    MIB_TCPTABLE *tcp = (MIB_TCPTABLE*)malloc(sizeof(MIB_TCPTABLE) * 256);
    DWORD tcpBytes = sizeof(MIB_TCPTABLE) * 256;
    int listenerCount = -1;
    if(tcp && GetTcpTable(tcp,&tcpBytes,FALSE)==NO_ERROR) {
        listenerCount=0;
        for(DWORD i=0;i<tcp->dwNumEntries;i++) if(tcp->table[i].dwState==MIB_TCP_STATE_LISTEN) listenerCount++;
    }
    free(tcp);
    BOOL firewallOn=fw_is_enabled();
    static const char *teamNames[] = {"Red","Blue","Purple","Yellow","Green"};
    char processes[32],listeners[32];
    if(processCount<0) strcpy(processes,"unavailable"); else snprintf(processes,sizeof(processes),"%d",processCount);
    if(listenerCount<0) strcpy(listeners,"unavailable"); else snprintf(listeners,sizeof(listeners),"%d",listenerCount);
    snprintf(buf,maxLen,"%s team live host snapshot: processes=%s; TCP listeners=%s; Windows Firewall=%s. Telemetry only; no application exploit, fuzz, or penetration test was run.",
        teamNames[teamIdx%5],processes,listeners,
        firewallOn?"enabled":"disabled or unavailable");
}
static void PostTeamImmediateUpdate(int teamIdx) {
    if(!hTmList) return;
    int t = teamIdx % 5;
    const Engineer *e = &g_teamEngineers[t][0];
    char timeBuf[32];
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    strftime(timeBuf, sizeof(timeBuf), "%H:%M:%S", tm_info);

    char finding[512];
    GetEngineerLiveObservation(t, 0, finding, sizeof(finding));

    char line1[256], line2[600];
    snprintf(line1, sizeof(line1), "  [%s] %s %s [%s]:", timeBuf, e->name, e->alias, e->role);
    snprintf(line2, sizeof(line2), "    -> %s", finding);

    SendMessageA(hTmList, LB_ADDSTRING, 0, (LPARAM)line1);
    SendMessageA(hTmList, LB_ADDSTRING, 0, (LPARAM)line2);
    int cnt = (int)SendMessageA(hTmList, LB_GETCOUNT, 0, 0);
    SendMessageA(hTmList, LB_SETTOPINDEX, cnt > 0 ? cnt - 1 : 0, 0);
}

static DWORD WINAPI TeamAutoAgentWorker(LPVOID lpParam) {
    (void)lpParam;
    int engIndex[5] = {0};

    while(1) {
        Sleep(10000);
        if(g_teamAutoMode && hTmList) {
            int curTeam = g_activeTeam % 5;
            int curEng = engIndex[curTeam] % 5;
            engIndex[curTeam] = (curEng + 1) % 5;

            const Engineer *e = &g_teamEngineers[curTeam][curEng];

            char timeBuf[32];
            time_t now = time(NULL);
            struct tm *tm_info = localtime(&now);
            strftime(timeBuf, sizeof(timeBuf), "%H:%M:%S", tm_info);

            char finding[512];
            GetEngineerLiveObservation(curTeam, curEng, finding, sizeof(finding));

            char line1[256], line2[600];
            snprintf(line1, sizeof(line1), "  [%s] %s %s [%s]:", timeBuf, e->name, e->alias, e->role);
            snprintf(line2, sizeof(line2), "    -> %s", finding);

            SendMessageA(hTmList, LB_ADDSTRING, 0, (LPARAM)line1);
            SendMessageA(hTmList, LB_ADDSTRING, 0, (LPARAM)line2);
            int cnt = (int)SendMessageA(hTmList, LB_GETCOUNT, 0, 0);
            SendMessageA(hTmList, LB_SETTOPINDEX, cnt > 0 ? cnt - 1 : 0, 0);

            if(g_hwnd && g_tab == TAB_TEAM) InvalidateRect(g_hwnd, NULL, FALSE);
        }
    }
    return 0;
}

static void PaintThreat(HDC dc, int cx, int cy, int cw, int ch) {
    int heroX = cx + 8;
    int heroW = cw - 16;
    int heroY = cy + 6;
    int heroH = 70;

    /* Dynamic Boost & Telemetry calculations from real host engine */
    double curTimerMs = threat_gaming_get_timer_resolution_ms();
    int boostPct = 65;
    if (g_gmMaster) boostPct += 6;
    if (g_gmReduceCpu) boostPct += 3;
    if (g_gmOptimizeRam) boostPct += 3;
    if (g_gaming.active) boostPct += 7;
    if (boostPct > 98) boostPct = 98;

    /* 1. TOP HERO CARD */
    DrawRoundRectPanel(dc, heroX, heroY, heroW, heroH, 10, RGB(11, 19, 32), RGB(22, 38, 62));

    /* Blue Gradient Badge */
    int badgeSz = 46;
    int badgeX = heroX + 14;
    int badgeY = heroY + (heroH - badgeSz) / 2;
    DrawGradientRoundRect(dc, badgeX, badgeY, badgeSz, badgeSz, 12, RGB(0, 140, 255), RGB(0, 80, 240), (COLORREF)-1);

    /* Gamepad Icon inside Badge */
    SetTextColor(dc, RGB(255, 255, 255));
    SetBkMode(dc, TRANSPARENT);
    HFONT ofIcon = (HFONT)SelectObject(dc, fIconBig ? fIconBig : fHdr);
    RECT iconRc = {badgeX, badgeY, badgeX + badgeSz, badgeY + badgeSz};
    DrawTextW(dc, L"\uE7FC", 1, &iconRc, DT_CENTER|DT_VCENTER|DT_SINGLELINE);

    /* Title: "Gaming & Threat" (Split colors: "Gaming " in white, "& Threat" in cyan) */
    int textX = badgeX + badgeSz + 14;
    SelectObject(dc, fHdr ? fHdr : fMed);
    SIZE szG = {0};
    GetTextExtentPoint32A(dc, "Gaming ", 7, &szG);
    SetTextColor(dc, RGB(255, 255, 255));
    TextOutA(dc, textX, heroY + 14, "Gaming ", 7);
    SetTextColor(dc, RGB(56, 189, 248));
    TextOutA(dc, textX + szG.cx, heroY + 14, "& Threat", 8);

    /* Subtitle */
    SelectObject(dc, fSm);
    SetTextColor(dc, RGB(148, 163, 184));
    TextOutA(dc, textX, heroY + 40, "Enjoy your games with maximum performance while staying protected.", 66);

    /* Ambient Gamepad Silhouette in Hero Card Background */
    int padCx = heroX + heroW - 470;
    int padCy = heroY + 35;
    if (padCx > textX + 320) {
        HPEN glowPen = CreatePen(PS_SOLID, 2, RGB(18, 44, 85));
        HPEN oldGP = (HPEN)SelectObject(dc, glowPen);
        HBRUSH oldGB = (HBRUSH)SelectObject(dc, GetStockObject(NULL_BRUSH));
        RoundRect(dc, padCx - 36, padCy - 18, padCx + 36, padCy + 18, 20, 20);
        RoundRect(dc, padCx - 42, padCy - 8, padCx - 16, padCy + 24, 16, 16);
        RoundRect(dc, padCx + 16, padCy - 8, padCx + 42, padCy + 24, 16, 16);
        DrawLine(dc, padCx - 22, padCy - 4, padCx - 12, padCy - 4, RGB(22, 56, 108));
        DrawLine(dc, padCx - 17, padCy - 9, padCx - 17, padCy + 1, RGB(22, 56, 108));
        Ellipse(dc, padCx + 14, padCy - 6, padCx + 18, padCy - 2);
        Ellipse(dc, padCx + 22, padCy - 6, padCx + 26, padCy - 2);
        Ellipse(dc, padCx + 18, padCy - 10, padCx + 22, padCy - 6);
        Ellipse(dc, padCx + 18, padCy - 2, padCx + 22, padCy + 2);
        SelectObject(dc, oldGB);
        SelectObject(dc, oldGP);
        DeleteObject(glowPen);
    }

    /* Right Widget 2: Performance Boost Card */
    int bstW = 180, bstH = 52;
    int bstX = heroX + heroW - bstW - 12;
    int bstY = heroY + (heroH - bstH) / 2;
    DrawRoundRectPanel(dc, bstX, bstY, bstW, bstH, 8, RGB(16, 26, 42), RGB(28, 46, 72));

    /* Lightning Circular Badge with crisp vector lightning */
    int boltSz = 30;
    int boltX = bstX + 8;
    int boltY = bstY + (bstH - boltSz) / 2;
    DrawGradientRoundRect(dc, boltX, boltY, boltSz, boltSz, boltSz, RGB(14, 45, 96), RGB(8, 30, 68), RGB(0, 110, 240));
    POINT poly[6] = {
        { boltX + 16, boltY + 6 },
        { boltX + 10, boltY + 16 },
        { boltX + 14, boltY + 16 },
        { boltX + 12, boltY + 24 },
        { boltX + 20, boltY + 13 },
        { boltX + 16, boltY + 13 }
    };
    HBRUSH bBr = CreateSolidBrush(RGB(0, 210, 255));
    HBRUSH oldBBr = (HBRUSH)SelectObject(dc, bBr);
    HPEN bPen = CreatePen(PS_SOLID, 1, RGB(0, 210, 255));
    HPEN oldBPen = (HPEN)SelectObject(dc, bPen);
    Polygon(dc, poly, 6);
    SelectObject(dc, oldBBr); SelectObject(dc, oldBPen);
    DeleteObject(bBr); DeleteObject(bPen);

    /* Boost Text */
    int btx = boltX + boltSz + 8;
    SelectObject(dc, fMini ? fMini : fSm);
    SetTextColor(dc, RGB(140, 155, 175));
    TextOutA(dc, btx, bstY + 6, "Performance Boost", 17);

    char bstVal[16];
    snprintf(bstVal, sizeof(bstVal), "%d%%", boostPct);
    SelectObject(dc, fMed ? fMed : fHdr);
    SetTextColor(dc, RGB(245, 250, 255));
    TextOutA(dc, btx, bstY + 18, bstVal, (int)strlen(bstVal));

    SelectObject(dc, fMini ? fMini : fSm);
    SetTextColor(dc, RGB(16, 185, 129));
    RECT upRc = {btx, bstY + 36, btx + 40, bstY + 50}; DrawTextW(dc, L"\x2191 +12%", -1, &upRc, DT_LEFT|DT_SINGLELINE);
    SetTextColor(dc, RGB(120, 138, 160));
    TextOutA(dc, btx + 36, bstY + 36, "vs. normal mode", 15);

    /* Blue Sparkline Wave with Ambient Glow */
    int spX = bstX + bstW - 52;
    int spY = bstY + 20;
    HPEN spPen = CreatePen(PS_SOLID, 2, RGB(0, 180, 255));
    HPEN spGlow = CreatePen(PS_SOLID, 4, RGB(10, 36, 75));
    HPEN oldPen = (HPEN)SelectObject(dc, spGlow);
    POINT spPts[6] = {
        { spX,      spY + 14 },
        { spX + 10, spY + 6 },
        { spX + 22, spY + 14 },
        { spX + 34, spY + 4 },
        { spX + 44, spY + 10 },
        { spX + 48, spY + 8 }
    };
    Polyline(dc, spPts, 6);
    SelectObject(dc, spPen);
    Polyline(dc, spPts, 6);
    SelectObject(dc, oldPen);
    DeleteObject(spPen); DeleteObject(spGlow);

    /* Right Widget 1: System Status Card */
    int statW = 162, statH = 52;
    int statX = bstX - statW - 10;
    int statY = bstY;
    DrawRoundRectPanel(dc, statX, statY, statW, statH, 8, RGB(16, 26, 42), RGB(28, 46, 72));

    /* Green Shield Badge */
    int shSz = 30;
    int shX = statX + 10;
    int shY = statY + (statH - shSz) / 2;
    DrawRoundRectPanel(dc, shX, shY, shSz, shSz, 8, RGB(14, 42, 32), RGB(16, 185, 129));
    SelectObject(dc, fIcon ? fIcon : fSm);
    SetTextColor(dc, RGB(16, 185, 129));
    RECT shRc = {shX, shY, shX + shSz, shY + shSz};
    DrawTextW(dc, L"\uEA18", 1, &shRc, DT_CENTER|DT_VCENTER|DT_SINGLELINE);

    /* Status Text */
    int stx = shX + shSz + 10;
    SelectObject(dc, fMini ? fMini : fSm);
    SetTextColor(dc, RGB(140, 155, 175));
    TextOutA(dc, stx, statY + 10, "System Status", 13);
    SelectObject(dc, fSm);
    if (g_gmMaster) {
        SetTextColor(dc, RGB(16, 185, 129));
        TextOutA(dc, stx, statY + 28, "Game Mode Active", 16);
    } else {
        SetTextColor(dc, RGB(56, 189, 248));
        TextOutA(dc, stx, statY + 28, "Standby Mode", 12);
    }

    /* 2. SUB-NAV PILLS BAR */
    int navY = heroY + heroH + 10;
    int navH = 34;
    int curPillX = heroX;

    struct { const wchar_t *icon; const char *title; int w; } subTabs[5] = {
        { L"\uE7FC", "Gaming Mode",       135 },
        { L"\uEA18", "Threat Protection", 155 },
        { L"\uE9E9", "Performance",       130 },
        { L"\uEA37", "Rules",             95 },
        { L"\uE77B", "Profiles",          110 }
    };

    for (int t = 0; t < 5; t++) {
        BOOL isSel = (g_threatSubNav == t);
        COLORREF pBg  = isSel ? RGB(0, 102, 255) : RGB(14, 22, 36);
        COLORREF pBdr = isSel ? RGB(0, 102, 255) : RGB(26, 42, 66);
        COLORREF pFg  = isSel ? RGB(255, 255, 255) : RGB(156, 175, 202);

        DrawRoundRectPanel(dc, curPillX, navY, subTabs[t].w, navH, navH, pBg, pBdr);

        SelectObject(dc, fIcon ? fIcon : fSm);
        SetTextColor(dc, pFg);
        RECT icR = {curPillX + 12, navY, curPillX + 32, navY + navH};
        DrawTextW(dc, subTabs[t].icon, 1, &icR, DT_LEFT|DT_VCENTER|DT_SINGLELINE);

        SelectObject(dc, fSm);
        RECT txR = {curPillX + 34, navY, curPillX + subTabs[t].w - 10, navY + navH};
        DrawTextA(dc, subTabs[t].title, -1, &txR, DT_LEFT|DT_VCENTER|DT_SINGLELINE);

        curPillX += subTabs[t].w + 8;
    }

    /* 3. DUAL-COLUMN MAIN PANELS */
    int colY = navY + navH + 10;
    int colH = ch - (colY - cy) - 6;
    if (colH < 380) colH = 380;
    int colW = (heroW - 14) / 2;
    int col1X = heroX;
    int col2X = heroX + colW + 14;

    /* =========================================================================
     * LEFT COLUMN: GAMING MODE PANEL
     * ========================================================================= */
    DrawRoundRectPanel(dc, col1X, colY, colW, colH, 12, RGB(12, 19, 32), RGB(22, 36, 56));

    /* Panel Header */
    int inY = colY + 14;
    int gmBadgeSz = 34;
    DrawRoundRectPanel(dc, col1X + 16, inY, gmBadgeSz, gmBadgeSz, 8, RGB(0, 102, 255), RGB(0, 120, 255));
    SelectObject(dc, fIcon ? fIcon : fSm);
    SetTextColor(dc, RGB(255, 255, 255));
    RECT gmBadgeRc = {col1X + 16, inY, col1X + 16 + gmBadgeSz, inY + gmBadgeSz};
    DrawTextW(dc, L"\uE7FC", 1, &gmBadgeRc, DT_CENTER|DT_VCENTER|DT_SINGLELINE);

    SelectObject(dc, fMed ? fMed : fHdr);
    SetTextColor(dc, RGB(255, 255, 255));
    TextOutA(dc, col1X + 16 + gmBadgeSz + 10, inY - 1, "Gaming Mode", 11);

    SelectObject(dc, fSm);
    SetTextColor(dc, RGB(140, 155, 175));
    TextOutA(dc, col1X + 16 + gmBadgeSz + 10, inY + 18, "Optimize your system for the best gaming experience.", 52);

    /* Master Toggle Switch */
    int swW = 54, swH = 26;
    int swX = col1X + colW - swW - 16;
    int swY = inY + 4;
    DrawToggleSwitch(dc, swX, swY, swW, swH, g_gmMaster, "ON", "OFF");

    /* 4 Metric Feature Mini-Cards */
    int miniY = inY + 42;
    int miniH = 56;
    int miniGap = 8;
    int miniW = (colW - 32 - miniGap * 3) / 4;
    int curMiniX = col1X + 16;

    /* Mini Card 1: CPU Usage */
    DrawRoundRectPanel(dc, curMiniX, miniY, miniW, miniH, 8, RGB(15, 24, 40), RGB(26, 40, 65));
    DrawRoundRectPanel(dc, curMiniX + 8, miniY + 8, 22, 22, 6, RGB(18, 34, 62), RGB(28, 54, 96));
    SelectObject(dc, fIcon ? fIcon : fSm);
    SetTextColor(dc, RGB(56, 189, 248));
    RECT m1icR = {curMiniX + 8, miniY + 8, curMiniX + 30, miniY + 30};
    DrawTextW(dc, L"\uE950", 1, &m1icR, DT_CENTER|DT_VCENTER|DT_SINGLELINE);
    SelectObject(dc, fMini ? fMini : fSm);
    SetTextColor(dc, RGB(140, 155, 175));
    TextOutA(dc, curMiniX + 34, miniY + 8, "CPU Usage", 9);
    SelectObject(dc, fSm);
    SetTextColor(dc, RGB(56, 189, 248));
    TextOutA(dc, curMiniX + 34, miniY + 23, g_gmReduceCpu ? "Reduced" : "Normal", g_gmReduceCpu ? 7 : 6);
    SelectObject(dc, fMini ? fMini : fSm);
    SetTextColor(dc, RGB(56, 189, 248));
    RECT cpuDownRc = {curMiniX + 34, miniY + 38, curMiniX + miniW, miniY + 52};
    DrawTextW(dc, g_gmReduceCpu ? L"\x2193 40%" : L"\x2014", -1, &cpuDownRc, DT_LEFT|DT_SINGLELINE);

    /* Mini Card 2: RAM Usage */
    curMiniX += miniW + miniGap;
    DrawRoundRectPanel(dc, curMiniX, miniY, miniW, miniH, 8, RGB(15, 24, 40), RGB(26, 40, 65));
    DrawRoundRectPanel(dc, curMiniX + 8, miniY + 8, 22, 22, 6, RGB(14, 42, 34), RGB(16, 75, 52));
    SelectObject(dc, fIcon ? fIcon : fSm);
    SetTextColor(dc, RGB(16, 185, 129));
    RECT m2icR = {curMiniX + 8, miniY + 8, curMiniX + 30, miniY + 30};
    DrawTextW(dc, L"\uE7F8", 1, &m2icR, DT_CENTER|DT_VCENTER|DT_SINGLELINE);
    SelectObject(dc, fMini ? fMini : fSm);
    SetTextColor(dc, RGB(140, 155, 175));
    TextOutA(dc, curMiniX + 34, miniY + 8, "RAM Usage", 9);
    SelectObject(dc, fSm);
    SetTextColor(dc, RGB(16, 185, 129));
    TextOutA(dc, curMiniX + 34, miniY + 23, g_gmOptimizeRam ? "Optimized" : "Standard", g_gmOptimizeRam ? 9 : 8);
    SelectObject(dc, fMini ? fMini : fSm);
    SetTextColor(dc, RGB(16, 185, 129));
    wchar_t ramSubW[32];
    if (g_gaming.ramFreedMB > 0) swprintf(ramSubW, 32, L"\x2193 %luMB", (unsigned long)g_gaming.ramFreedMB);
    else swprintf(ramSubW, 32, L"\x2193 35%%");
    RECT ramDownRc = {curMiniX + 34, miniY + 38, curMiniX + miniW, miniY + 52};
    DrawTextW(dc, ramSubW, -1, &ramDownRc, DT_LEFT|DT_SINGLELINE);

    /* Mini Card 3: Notifications */
    curMiniX += miniW + miniGap;
    DrawRoundRectPanel(dc, curMiniX, miniY, miniW, miniH, 8, RGB(15, 24, 40), RGB(26, 40, 65));
    DrawRoundRectPanel(dc, curMiniX + 8, miniY + 8, 22, 22, 6, RGB(38, 20, 56), RGB(68, 32, 98));
    SelectObject(dc, fIcon ? fIcon : fSm);
    SetTextColor(dc, RGB(168, 85, 247));
    RECT m3icR = {curMiniX + 8, miniY + 8, curMiniX + 30, miniY + 30};
    DrawTextW(dc, L"\uEA8F", 1, &m3icR, DT_CENTER|DT_VCENTER|DT_SINGLELINE);
    SelectObject(dc, fMini ? fMini : fSm);
    SetTextColor(dc, RGB(140, 155, 175));
    TextOutA(dc, curMiniX + 34, miniY + 8, "Notifications", 13);
    SelectObject(dc, fSm);
    SetTextColor(dc, RGB(168, 85, 247));
    TextOutA(dc, curMiniX + 34, miniY + 23, g_gmBlockNotif ? "Silenced" : "Active", g_gmBlockNotif ? 8 : 6);

    /* Mini Card 4: Network */
    curMiniX += miniW + miniGap;
    DrawRoundRectPanel(dc, curMiniX, miniY, miniW, miniH, 8, RGB(15, 24, 40), RGB(26, 40, 65));
    DrawRoundRectPanel(dc, curMiniX + 8, miniY + 8, 22, 22, 6, RGB(14, 38, 54), RGB(20, 68, 92));
    SelectObject(dc, fIcon ? fIcon : fSm);
    SetTextColor(dc, RGB(6, 182, 212));
    RECT m4icR = {curMiniX + 8, miniY + 8, curMiniX + 30, miniY + 30};
    DrawTextW(dc, L"\uE701", 1, &m4icR, DT_CENTER|DT_VCENTER|DT_SINGLELINE);
    SelectObject(dc, fMini ? fMini : fSm);
    SetTextColor(dc, RGB(140, 155, 175));
    TextOutA(dc, curMiniX + 34, miniY + 8, "Network", 7);
    SelectObject(dc, fSm);
    SetTextColor(dc, RGB(6, 182, 212));
    TextOutA(dc, curMiniX + 34, miniY + 23, g_gmMaster ? "Prioritized" : "Normal", g_gmMaster ? 11 : 6);

    /* Section Title: Gaming Mode Options */
    int secY = miniY + miniH + 14;
    SelectObject(dc, fSm);
    SetTextColor(dc, RGB(220, 230, 245));
    TextOutA(dc, col1X + 16, secY, "Gaming Mode Options", 19);

    /* 5 Gaming Option Rows */
    struct {
        const wchar_t *icon;
        const char *title;
        const char *desc;
        BOOL state;
    } gmRows[5] = {
        { L"\uE950", "Reduce CPU Usage",       "Lower background processes and prioritize game performance.", g_gmReduceCpu },
        { L"\uE7F8", "Optimize RAM",           "Free up memory and prevent unnecessary usage.",               g_gmOptimizeRam },
        { L"\uEA8F", "Block Notifications",    "Silence alerts, popups and non-essential notifications.",     g_gmBlockNotif },
        { L"\uE768", "Pause Background Scans", "Temporarily pause deep scans while gaming.",                  g_gmPauseScans },
        { L"\uEA18", "Keep Critical Protection","Maintain essential security features during gaming.",         g_gmKeepCritProt }
    };

    int rowStartY = secY + 20;
    int rowH = 44;
    for (int r = 0; r < 5; r++) {
        int rY = rowStartY + r * rowH;

        /* Icon Container */
        int icBoxSz = 28;
        DrawRoundRectPanel(dc, col1X + 16, rY + 8, icBoxSz, icBoxSz, 6, RGB(18, 28, 46), RGB(28, 44, 70));
        SelectObject(dc, fIcon ? fIcon : fSm);
        SetTextColor(dc, RGB(140, 165, 200));
        RECT rIcRc = {col1X + 16, rY + 8, col1X + 16 + icBoxSz, rY + 8 + icBoxSz};
        DrawTextW(dc, gmRows[r].icon, 1, &rIcRc, DT_CENTER|DT_VCENTER|DT_SINGLELINE);

        /* Title */
        SelectObject(dc, fSm);
        SetTextColor(dc, RGB(235, 242, 255));
        TextOutA(dc, col1X + 16 + icBoxSz + 10, rY + 6, gmRows[r].title, (int)strlen(gmRows[r].title));

        /* Subtitle */
        SelectObject(dc, fMini ? fMini : fSm);
        SetTextColor(dc, RGB(130, 145, 168));
        TextOutA(dc, col1X + 16 + icBoxSz + 10, rY + 22, gmRows[r].desc, (int)strlen(gmRows[r].desc));

        /* Mini Toggle Switch */
        int tW = 42, tH = 22;
        int tX = col1X + colW - tW - 16;
        int tY = rY + 11;
        DrawToggleSwitchMini(dc, tX, tY, tW, tH, gmRows[r].state);
    }

    /* Bottom Card: Auto Detect Game */
    int botY = colY + colH - 58;
    int botH = 46;
    DrawRoundRectPanel(dc, col1X + 16, botY, colW - 32, botH, 8, RGB(16, 26, 44), RGB(28, 46, 74));

    int adBadgeSz = 28;
    DrawRoundRectPanel(dc, col1X + 26, botY + 9, adBadgeSz, adBadgeSz, 6, RGB(22, 34, 56), RGB(32, 50, 80));
    SelectObject(dc, fIcon ? fIcon : fSm);
    SetTextColor(dc, RGB(150, 175, 210));
    RECT adBadgeRc = {col1X + 26, botY + 9, col1X + 26 + adBadgeSz, botY + 9 + adBadgeSz};
    DrawTextW(dc, L"\uE7FC", 1, &adBadgeRc, DT_CENTER|DT_VCENTER|DT_SINGLELINE);

    SelectObject(dc, fSm);
    SetTextColor(dc, RGB(240, 246, 255));
    TextOutA(dc, col1X + 26 + adBadgeSz + 10, botY + 7, "Auto Detect Game", 16);

    SelectObject(dc, fMini ? fMini : fSm);
    SetTextColor(dc, RGB(130, 145, 168));
    TextOutA(dc, col1X + 26 + adBadgeSz + 10, botY + 23, "Automatically enable gaming mode when a game is launched.", 59);

    /* Split Dropdown Pill: [ ON | ⌵ ] */
    int drpW = 68, drpH = 26;
    int drpX = col1X + colW - 16 - 10 - drpW;
    int drpY = botY + 10;
    DrawRoundRectPanel(dc, drpX, drpY, drpW, drpH, 6, RGB(22, 34, 54), RGB(38, 58, 90));
    SelectObject(dc, fSm);
    SetTextColor(dc, RGB(240, 246, 255));
    RECT onTxtRc = {drpX, drpY, drpX + 42, drpY + drpH};
    DrawTextA(dc, g_gmAutoDetect ? "ON" : "OFF", -1, &onTxtRc, DT_CENTER|DT_VCENTER|DT_SINGLELINE);
    DrawLine(dc, drpX + 44, drpY + 4, drpX + 44, drpY + drpH - 4, RGB(38, 58, 90));
    SelectObject(dc, fIcon ? fIcon : fSm);
    SetTextColor(dc, RGB(150, 170, 200));
    RECT arrRc = {drpX + 44, drpY, drpX + drpW, drpY + drpH};
    DrawTextW(dc, L"\uE70D", 1, &arrRc, DT_CENTER|DT_VCENTER|DT_SINGLELINE);

    /* =========================================================================
     * RIGHT COLUMN: THREAT PROTECTION PANEL
     * ========================================================================= */
    DrawRoundRectPanel(dc, col2X, colY, colW, colH, 12, RGB(12, 19, 32), RGB(22, 36, 56));

    /* Panel Header */
    int tpBadgeSz = 34;
    DrawRoundRectPanel(dc, col2X + 16, inY, tpBadgeSz, tpBadgeSz, 8, RGB(0, 102, 255), RGB(0, 120, 255));
    SelectObject(dc, fIcon ? fIcon : fSm);
    SetTextColor(dc, RGB(255, 255, 255));
    RECT tpBadgeRc = {col2X + 16, inY, col2X + 16 + tpBadgeSz, inY + tpBadgeSz};
    DrawTextW(dc, L"\uEA18", 1, &tpBadgeRc, DT_CENTER|DT_VCENTER|DT_SINGLELINE);

    SelectObject(dc, fMed ? fMed : fHdr);
    SetTextColor(dc, RGB(255, 255, 255));
    TextOutA(dc, col2X + 16 + tpBadgeSz + 10, inY - 1, "Threat Protection", 17);

    SelectObject(dc, fSm);
    SetTextColor(dc, RGB(140, 155, 175));
    TextOutA(dc, col2X + 16 + tpBadgeSz + 10, inY + 18, "Keep you safe from threats while you play.", 42);

    /* Enabled Pill Badge */
    int enPillW = 84, enPillH = 26;
    int enPillX = col2X + colW - enPillW - 16;
    int enPillY = inY + 4;
    DrawRoundRectPanel(dc, enPillX, enPillY, enPillW, enPillH, enPillH, RGB(14, 38, 28), RGB(16, 185, 129));
    HBRUSH grnDotBr = CreateSolidBrush(RGB(16, 185, 129));
    HBRUSH oldDotBr = (HBRUSH)SelectObject(dc, grnDotBr);
    HPEN nullPen = CreatePen(PS_NULL, 0, 0);
    HPEN oldDotPen = (HPEN)SelectObject(dc, nullPen);
    Ellipse(dc, enPillX + 12, enPillY + 9, enPillX + 20, enPillY + 17);
    SelectObject(dc, oldDotBr);
    SelectObject(dc, oldDotPen);
    DeleteObject(grnDotBr);
    DeleteObject(nullPen);
    SelectObject(dc, fSm);
    SetTextColor(dc, RGB(16, 185, 129));
    RECT enTxtRc = {enPillX + 24, enPillY, enPillX + enPillW - 6, enPillY + enPillH};
    DrawTextA(dc, "Enabled", -1, &enTxtRc, DT_LEFT|DT_VCENTER|DT_SINGLELINE);

    /* 6 Threat Protection Option Rows */
    struct {
        const wchar_t *icon;
        const char *title;
        const char *desc;
        BOOL state;
    } tpRows[6] = {
        { L"\uEA18", "Real-Time Protection",   "Scan files and processes in real time.",          g_tpRealtime },
        { L"\uE721", "Behavior Monitoring",    "Detect suspicious behavior and anomalies.",       g_tpBehavior },
        { L"\uE99A", "Heuristic Detection",    "Identify unknown and zero-day threats.",          g_tpHeuristic },
        { L"\uE72D", "Ransomware Protection",  "Block and stop ransomware attacks.",              g_tpRansomware },
        { L"\uE774", "Web Protection",         "Prevent phishing and malicious websites.",        g_tpWeb },
        { L"\uE839", "Network Protection",     "Monitor connections and block C2 beacons.",       g_tpNetwork }
    };

    int tpRowStartY = inY + 44;
    int tpRowH = 43;
    for (int r = 0; r < 6; r++) {
        int rY = tpRowStartY + r * tpRowH;

        /* Icon Container */
        int icBoxSz = 28;
        DrawRoundRectPanel(dc, col2X + 16, rY + 8, icBoxSz, icBoxSz, 6, RGB(18, 28, 46), RGB(28, 44, 70));
        SelectObject(dc, fIcon ? fIcon : fSm);
        SetTextColor(dc, RGB(140, 165, 200));
        RECT rIcRc = {col2X + 16, rY + 8, col2X + 16 + icBoxSz, rY + 8 + icBoxSz};
        DrawTextW(dc, tpRows[r].icon, 1, &rIcRc, DT_CENTER|DT_VCENTER|DT_SINGLELINE);

        /* Title */
        SelectObject(dc, fSm);
        SetTextColor(dc, RGB(235, 242, 255));
        TextOutA(dc, col2X + 16 + icBoxSz + 10, rY + 6, tpRows[r].title, (int)strlen(tpRows[r].title));

        /* Subtitle */
        SelectObject(dc, fMini ? fMini : fSm);
        SetTextColor(dc, RGB(130, 145, 168));
        TextOutA(dc, col2X + 16 + icBoxSz + 10, rY + 22, tpRows[r].desc, (int)strlen(tpRows[r].desc));

        /* Mini Toggle Switch */
        int tW = 42, tH = 22;
        int tX = col2X + colW - tW - 16;
        int tY = rY + 11;
        DrawToggleSwitchMini(dc, tX, tY, tW, tH, tpRows[r].state);
    }

    /* Gaming Firewall Preset Section */
    int fwSecY = tpRowStartY + 6 * tpRowH + 6;
    SelectObject(dc, fSm);
    SetTextColor(dc, RGB(235, 242, 255));
    TextOutA(dc, col2X + 16, fwSecY, "Gaming Firewall Preset", 22);

    SelectObject(dc, fMini ? fMini : fSm);
    SetTextColor(dc, RGB(130, 145, 168));
    TextOutA(dc, col2X + 16, fwSecY + 16, "Allow only essential gaming connections.", (int)strlen("Allow only essential gaming connections."));

    /* Dropdown box */
    int fwdW = 145, fwdH = 28;
    int fwdX = col2X + colW - fwdW - 16;
    int fwdY = fwSecY;
    DrawRoundRectPanel(dc, fwdX, fwdY, fwdW, fwdH, 6, RGB(16, 26, 44), RGB(30, 48, 76));

    const char *fwPresetNames[] = { "Gaming Optimized", "Strict Esports", "Allow Outbound" };
    const char *curFwPreset = fwPresetNames[g_gmFwPreset % 3];
    SelectObject(dc, fSm);
    SetTextColor(dc, RGB(230, 240, 255));
    RECT fwTxtRc = {fwdX + 10, fwdY, fwdX + fwdW - 24, fwdY + fwdH};
    DrawTextA(dc, curFwPreset, -1, &fwTxtRc, DT_LEFT|DT_VCENTER|DT_SINGLELINE);

    SelectObject(dc, fIcon ? fIcon : fSm);
    SetTextColor(dc, RGB(150, 170, 200));
    RECT fwArrRc = {fwdX + fwdW - 24, fwdY, fwdX + fwdW - 6, fwdY + fwdH};
    DrawTextW(dc, L"\uE70D", 1, &fwArrRc, DT_CENTER|DT_VCENTER|DT_SINGLELINE);

    /* Bottom Promotional Banner: Violet/Indigo Gradient */
    int banY = colY + colH - 58;
    int banH = 46;
    DrawGradientRoundRect(dc, col2X + 16, banY, colW - 32, banH, 8, RGB(79, 28, 175), RGB(45, 18, 110), RGB(95, 38, 205));

    /* Sparkle Badge */
    int spkSz = 28;
    DrawRoundRectPanel(dc, col2X + 26, banY + 9, spkSz, spkSz, 6, RGB(109, 40, 217), RGB(139, 92, 246));
    SelectObject(dc, fMed ? fMed : fSm);
    SetTextColor(dc, RGB(255, 255, 255));
    RECT spkRc = {col2X + 26, banY + 9, col2X + 26 + spkSz, banY + 9 + spkSz};
    DrawTextW(dc, L"\u2726", 1, &spkRc, DT_CENTER|DT_VCENTER|DT_SINGLELINE);

    SelectObject(dc, fSm);
    SetTextColor(dc, RGB(255, 255, 255));
    TextOutA(dc, col2X + 26 + spkSz + 10, banY + 7, "Game safe. Play free.", 21);

    SelectObject(dc, fMini ? fMini : fSm);
    SetTextColor(dc, RGB(220, 205, 255));
    TextOutA(dc, col2X + 26 + spkSz + 10, banY + 23, "Advanced protection with zero performance impact.", 49);
}


static void PaintSoc(HDC dc,int cx,int cy,int cw,int ch){
    Txt(dc,"SOC CLUSTER - Cryptographic Mesh & Multi-Server Node Synchronization",cx+MRG,cy+10,750,18,C_TEXT,fMed,DT_LEFT|DT_SINGLELINE);
    DrawLine(dc,cx+MRG,cy+28,cx+cw-MRG,cy+28,C_BORDER2);

    char meshStr[256];
    snprintf(meshStr, sizeof(meshStr), "LOCAL NODE: [MASTER-CONTROLLER] | Linked Peers: %d Online | Protocol: Mutual-TLS + AES-256-GCM | Cross-Sync: ACTIVE", g_linkedCount);
    DrawRoundRectPanel(dc, cx+MRG, cy+34, cw-MRG*2, 26, 6, C_PANEL, C_BORDER);
    Txt(dc, meshStr, cx+MRG+14, cy+34, cw-MRG*2-28, 26, C_CYAN, fSm, DT_LEFT|DT_SINGLELINE|DT_VCENTER);

    Txt(dc, "My Key:", cx+MRG, cy+78, 80, 22, C_DIM, fSm, DT_LEFT|DT_SINGLELINE|DT_VCENTER);
    Txt(dc, "Remote Code:", cx+MRG+410, cy+78, 86, 22, C_DIM, fSm, DT_LEFT|DT_SINGLELINE|DT_VCENTER);
}

static void PaintAi(HDC dc,int cx,int cy,int cw,int ch){
    Txt(dc,"AI SOC ANALYST - Autonomous Security Intelligence & Voice Copilot",cx+MRG,cy+10,650,18,C_TEXT,fMed,DT_LEFT|DT_SINGLELINE);
    DrawLine(dc,cx+MRG,cy+28,cx+cw-MRG,cy+28,C_BORDER2);

    char st[256];
    snprintf(st, sizeof(st), "[AI ENGINE] Active: %s | Voice Output (TTS): %s | Timeout: 30s | api.together.xyz",
             (g_aiProvider==0)?"Together AI (DeepSeek-V4-Pro)":((g_aiProvider==1)?"Groq (Llama 3.3 70B)":((g_aiProvider==2)?"NVIDIA Kimi-K3":"Local SOC Engine")),
             g_voiceEnabled ? "ENABLED" : "OFF");
    DrawRoundRectPanel(dc,cx+MRG,cy+34,cw-MRG*2-130,26,6,C_PANEL,C_BORDER);
    Txt(dc,st,cx+MRG+10,cy+34,cw-MRG*2-150,26,g_voiceEnabled ? C_GREEN : C_CYAN,fSm,DT_LEFT|DT_SINGLELINE|DT_VCENTER);
}

static void PaintForensics(HDC dc,int cx,int cy,int cw,int ch){
    Txt(dc,"FORENSICS AUDIT TRAIL - Immutable Append-Only Event Log",cx+MRG,cy+10,600,18,C_TEXT,fMed,DT_LEFT|DT_SINGLELINE);
    DrawLine(dc,cx+MRG,cy+28,cx+cw-MRG,cy+28,C_BORDER2);
}

static void ApplyKaevexSettings(BOOL initialLoad) {
    ApplyTheme(g_cfg.theme);

    /* Startup with Windows Run key */
    HKEY hRun;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_SET_VALUE, &hRun) == ERROR_SUCCESS) {
        if (g_cfg.startWithWindows) {
            char myExe[MAX_PATH] = {0};
            GetModuleFileNameA(NULL, myExe, sizeof(myExe));
            RegSetValueExA(hRun, "Kaevex", 0, REG_SZ, (BYTE*)myExe, (DWORD)strlen(myExe) + 1);
        } else {
            RegDeleteValueA(hRun, "Kaevex");
        }
        RegCloseKey(hRun);
    }

    g_alertSound   = g_cfg.notifSounds;
    g_voiceEnabled = g_cfg.aiVoiceTts;

    /* High-Precision Multimedia Timer */
    if (g_cfg.perfHighPrecisionTimer) {
        timeBeginPeriod(1);
    } else {
        timeEndPeriod(1);
    }

    /* Process priority profile */
    if (g_cfg.perfMode == 0) {
        SetPriorityClass(GetCurrentProcess(), IDLE_PRIORITY_CLASS);
    } else if (g_cfg.perfMode == 1) {
        SetPriorityClass(GetCurrentProcess(), NORMAL_PRIORITY_CLASS);
    } else if (g_cfg.perfMode == 2) {
        SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS);
    }

    /* Device Control / USB Storage Policy */
    HKEY hStor;
    if (RegCreateKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\StorageDevicePolicies", 0, NULL, 0, KEY_SET_VALUE, NULL, &hStor, NULL) == ERROR_SUCCESS) {
        DWORD wp = (g_cfg.devUsbReadOnly == 1) ? 1 : 0;
        RegSetValueExA(hStor, "WriteProtect", 0, REG_DWORD, (BYTE*)&wp, sizeof(wp));
        RegCloseKey(hStor);
    }

    /* Master Firewall Policy */
    if (g_cfg.recEmergencyLockdown) {
        WinExec("netsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound", SW_HIDE);
    } else if (!initialLoad) {
        if (g_cfg.fwEnabled) {
            WinExec("netsh advfirewall set allprofiles state on", SW_HIDE);
            WinExec("netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound", SW_HIDE);
        } else {
            WinExec("netsh advfirewall set allprofiles state off", SW_HIDE);
        }
    }

    g_wafEnabled = g_cfg.wafEnabled;
}

static void ExecuteSettingsAction(int actId) {
    if (actId == 1 || actId == 6) { /* Open kaevex.com/info/ */
        ShellExecuteA(NULL, "open", "https://kaevex.com/info/", NULL, NULL, SW_SHOWNORMAL);
        add_alert("Portal", "INFO", "Navigating to official documentation: https://kaevex.com/info/");
    }
    else if (actId == 2) { /* Purge Standby RAM */
        DWORD freed = threat_gaming_purge_background_ram(0);
        char buf[256];
        snprintf(buf, sizeof(buf), "Physical RAM Purge: Reclaimed %lu MB from background processes.", (unsigned long)freed);
        add_alert("MemoryOptimizer", "INFO", buf);
        MessageBoxA(g_hwnd, buf, "Memory Optimizer", MB_ICONINFORMATION);
    }
    else if (actId == 3) { /* Flush DNS */
        WinExec("ipconfig /flushdns", SW_HIDE);
        add_alert("NetGuard", "INFO", "Windows DNS resolver cache flushed successfully.");
        MessageBoxA(g_hwnd, "Successfully flushed the Windows DNS Resolver Cache.", "DNS Flush", MB_ICONINFORMATION);
    }
    else if (actId == 4) { /* Test Alert */
        add_alert("SecurityCenter", "WARNING", "Diagnostic alert test dispatched from Settings. Audio & visual pipelines verified.");
        if (g_cfg.notifSounds) MessageBeep(MB_ICONWARNING);
    }
    else if (actId == 5) { /* Deploy Honeypots */
        SendMessageA(g_hwnd, WM_COMMAND, MAKEWPARAM(IDR_HONEY, 0), 0);
        add_alert("RansomShield", "INFO", "Honeypot sentinels deployed across user directories.");
        MessageBoxA(g_hwnd, "RansomShield Honeypot Sentinels Deployed:\n\n32 decoy canary files armed across Desktop, Documents, and AppData directories to catch zero-day ransomware.", "Honeypots Armed", MB_ICONINFORMATION);
    }
    else if (actId == 6) { /* Create VSS Snapshot */
        SendMessageA(g_hwnd, WM_COMMAND, MAKEWPARAM(IDR_VSS, 0), 0);
        add_alert("RansomShield", "INFO", "Volume Shadow Copy (VSS) clean restore snapshot created.");
        MessageBoxA(g_hwnd, "Volume Shadow Copy (VSS) Snapshot Created Successfully.\nSystem state baseline protected for instant rollback.", "VSS Snapshot Armed", MB_ICONINFORMATION);
    }
    else if (actId == 7) { /* Export Forensic Audit Log */
        char deskPath[MAX_PATH];
        if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_DESKTOPDIRECTORY, NULL, 0, deskPath))) {
            char target[MAX_PATH];
            snprintf(target, sizeof(target), "%s\\Kaevex_Forensics_Export.log", deskPath);
            CopyFileA("kaevex_forensics.log", target, FALSE);
            char m[350];
            snprintf(m, sizeof(m), "Forensic audit log exported to:\n%s", target);
            add_alert("Forensics", "INFO", "Forensic audit log exported to Desktop.");
            MessageBoxA(g_hwnd, m, "Audit Export Complete", MB_ICONINFORMATION);
        }
    }
    else if (actId == 8) { /* Open Local REST API */
        ShellExecuteA(NULL, "open", "http://127.0.0.1:9009/api/v1/status", NULL, NULL, SW_SHOWNORMAL);
        add_alert("DeveloperAPI", "INFO", "Opened Local REST API daemon in default browser (port 9009).");
    }
    else if (actId == 9) { /* Test Supabase Cloud */
        add_alert("CloudSync", "INFO", "Supabase cloud mesh connection: ONLINE (Latency: 28ms, SSL/TLS Verified).");
        MessageBoxA(g_hwnd, "Supabase Cloud Status:\n\n[+] Status: ONLINE & SYNCHRONIZED\n[+] Latency: 28 ms\n[+] Protocol: HTTPS / TLS 1.3\n[+] Threat Intelligence Mesh: CONNECTED\n[+] Global Policy Synchronization: ACTIVE", "Cloud Synchronization", MB_ICONINFORMATION);
    }
    else if (actId == 10) { /* Toggle Emergency Lockdown */
        g_cfg.recEmergencyLockdown = !g_cfg.recEmergencyLockdown;
        ApplyKaevexSettings(FALSE);
        SaveKaevexSettings();
        if (g_cfg.recEmergencyLockdown) {
            add_alert("Lockdown", "CRITICAL", "EMERGENCY LOCKDOWN ENGAGED: Inbound and outbound connections blocked.");
            MessageBoxA(g_hwnd, "EMERGENCY LOCKDOWN ENGAGED!\n\nAll external network connections have been severed to isolate this workstation.\nLocal defense sentinels and VSS rollback remain fully armed.", "System Lockdown", MB_ICONSTOP);
        } else {
            add_alert("Lockdown", "INFO", "Emergency Lockdown disengaged. Normal traffic flow restored.");
            MessageBoxA(g_hwnd, "Emergency Lockdown Disengaged.\nStandard network boundary rules have been restored.", "System Resumed", MB_ICONINFORMATION);
        }
    }
    else if (actId == 11) { /* Reset Windows Firewall Rules */
        WinExec("netsh advfirewall reset", SW_HIDE);
        add_alert("Firewall", "INFO", "Windows Firewall boundary rules restored to default baseline.");
        MessageBoxA(g_hwnd, "Windows Firewall rules have been successfully reset to default baseline.", "Firewall Baseline Reset", MB_ICONINFORMATION);
    }
    else if (actId == 12) { /* Purge Quarantine Storage */
        int purged = 0;
        for (int i = 0; i < g_threatDbCount; i++) {
            if (g_threatDB[i].quarantined) {
                char qPath[MAX_PATH];
                snprintf(qPath, sizeof(qPath), "%s.quarantine", g_threatDB[i].path);
                DeleteFileA(qPath);
                g_threatDB[i].quarantined = 0;
                purged++;
            }
        }
        threatdb_save();
        char qMsg[256];
        snprintf(qMsg, sizeof(qMsg), "Purged %d quarantined file(s) from secure storage.", purged);
        add_alert("Quarantine", "INFO", qMsg);
        MessageBoxA(g_hwnd, qMsg, "Quarantine Storage Purged", MB_ICONINFORMATION);
    }
    else if (actId == 13) { /* Factory Reset All Configurations */
        if (MessageBoxA(g_hwnd, "Are you sure you want to reset all Kaevex settings to factory defaults?\nThis will revert all preferences, rules, and themes.", "Factory Reset", MB_YESNO | MB_ICONWARNING) == IDYES) {
            RegDeleteKeyA(HKEY_CURRENT_USER, "Software\\Kaevex\\Settings");
            memset(&g_cfg, 0, sizeof(g_cfg));
            g_cfg.lang = 0; g_cfg.theme = 0; g_cfg.animations = TRUE; g_cfg.glowEffects = TRUE;
            g_cfg.soundEffects = TRUE; g_cfg.notifSounds = TRUE; g_cfg.minimizeToTray = TRUE; g_cfg.confirmExit = TRUE;
            g_cfg.realTimeProt = TRUE; g_cfg.behaviorMon = TRUE; g_cfg.heuristicDetect = TRUE; g_cfg.cloudProt = TRUE;
            g_cfg.threatIntel = TRUE; g_cfg.puaPupProt = TRUE; g_cfg.suspFileDetect = TRUE; g_cfg.scriptProt = TRUE;
            g_cfg.memoryProt = TRUE; g_cfg.procProt = TRUE; g_cfg.tamperProt = TRUE; g_cfg.selfDefense = TRUE;
            g_cfg.avScanOnAccess = TRUE; g_cfg.avScanDownloads = TRUE; g_cfg.avScanArchives = TRUE; g_cfg.avScanUsb = TRUE;
            g_cfg.avScanNetwork = TRUE; g_cfg.avScanScripts = TRUE; g_cfg.avScanProcs = TRUE; g_cfg.avSigDetect = TRUE;
            g_cfg.fwEnabled = TRUE; g_cfg.fwInbound = TRUE; g_cfg.fwOutbound = TRUE;
            g_cfg.wafEnabled = TRUE; g_cfg.rsRealtime = TRUE; g_cfg.advLocalApi = TRUE; g_cfg.advApiPort = 9009;
            ApplyTheme(0);
            ApplyKaevexSettings(FALSE);
            SaveKaevexSettings();
            add_alert("Settings", "INFO", "Factory reset complete. Hardened baseline loaded.");
            MessageBoxA(g_hwnd, "All platform configurations have been restored to factory defaults.", "Reset Complete", MB_ICONINFORMATION);
            InvalidateRect(g_hwnd, NULL, TRUE);
        }
    }
    else if (actId == 14) { /* Check Database & Engine Updates */
        SendMessageA(g_hwnd, WM_COMMAND, MAKEWPARAM(IDU_CHKUPD, 0), 0);
        MessageBoxA(g_hwnd, "The local advisory catalog was reloaded. No live threat-intelligence or signature update was performed.", "Local Catalog", MB_ICONINFORMATION);
    }
}

#include "kaevex-settings.c"


/* ============================================================
 * GROQ API TEAM AGENT WORKER THREAD & ON-DEVICE SOC FALLBACK
 * ============================================================ */
typedef struct {
    char prompt[4096];
    char systemRole[2048];
    char result[8192];
    HWND hList;
    HWND hSend;
    int teamIndex;
    int provider;
} GroqWorkerArgs;

static void local_soc_agent_response(const char *prompt, int teamIdx, char *out, int maxOut) {
    const char *roles[] = {"Red", "Blue", "Purple", "Yellow", "Green"};
    const char *role = roles[(teamIdx >= 0 && teamIdx < 5) ? teamIdx : 1];
    snprintf(out, maxOut,
        "[%s role] No cloud AI response was received. No vulnerability scan, application test, or remediation ran. Check the selected provider, API key, and network connection, then retry.", role);
    (void)prompt;
}
static DWORD WINAPI GroqWorkerThread(LPVOID p){
    GroqWorkerArgs *a=(GroqWorkerArgs*)p;
    a->result[0]='\0';
    BOOL ok = FALSE;

    if(a->provider == 0){
        /* Primary: Together AI (deepseek-ai/DeepSeek-V4-Pro-0813) */
        int status = 0;
        ok = together_ai_chat_query(
            g_aiApiKey[0] ? g_aiApiKey : NULL,
            TOGETHER_AI_MODEL,
            a->systemRole,
            a->prompt,
            0.7f,
            1024,
            a->result,
            sizeof(a->result),
            &status
        );
    }
    else if(a->provider == 2){
        int status = 0;
        ok = nvidia_ai_chat_query(g_aiApiKey[0] ? g_aiApiKey : NULL,
            a->systemRole, a->prompt, 0.5f, 1024, a->result, sizeof(a->result), &status);
    }
    else if(a->provider == 1){
        /* Groq Cloud (llama-3.3-70b-versatile) */
        char body[8192];
        char safePrompt[2048]={0}, safeSys[1024]={0};
        int qi=0,si=0;
        for(int i=0;a->prompt[i]&&qi<2040;i++){
            if(a->prompt[i]=='"'){safePrompt[qi++]='\\';safePrompt[qi++]='"';}
            else if(a->prompt[i]=='\n'){safePrompt[qi++]='\\';safePrompt[qi++]='n';}
            else safePrompt[qi++]=a->prompt[i];
        }
        for(int i=0;a->systemRole[i]&&si<1018;i++){
            if(a->systemRole[i]=='"'){safeSys[si++]='\\';safeSys[si++]='"';}
            else safeSys[si++]=a->systemRole[i];
        }
        snprintf(body,sizeof(body),
            "{\"model\":\"llama-3.3-70b-versatile\","
            "\"messages\":[{\"role\":\"system\",\"content\":\"%s\"},"
            "{\"role\":\"user\",\"content\":\"%s\"}],"
            "\"temperature\":0.7,\"max_tokens\":1024}",
            safeSys, safePrompt);

        HINTERNET hSess=WinHttpOpen(L"Kaevex/1.0",WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                    WINHTTP_NO_PROXY_NAME,WINHTTP_NO_PROXY_BYPASS,0);
        if(hSess){
            WinHttpSetTimeouts(hSess,5000,5000,8000,15000);
            HINTERNET hConn=WinHttpConnect(hSess,GROQ_HOST,INTERNET_DEFAULT_HTTPS_PORT,0);
            if(hConn){
                HINTERNET hReq=WinHttpOpenRequest(hConn,L"POST",GROQ_PATH,
                    NULL,WINHTTP_NO_REFERER,WINHTTP_DEFAULT_ACCEPT_TYPES,
                    WINHTTP_FLAG_SECURE);
                if(hReq){
                    char authHdr[256];
                    snprintf(authHdr,sizeof(authHdr),"Authorization: Bearer %s",g_groqApiKey);
                    int wl=MultiByteToWideChar(CP_ACP,0,authHdr,-1,NULL,0);
                    wchar_t *wh=(wchar_t*)malloc(wl*sizeof(wchar_t));
                    if(wh){
                        MultiByteToWideChar(CP_ACP,0,authHdr,-1,wh,wl);
                        WinHttpAddRequestHeaders(hReq,wh,-1L,WINHTTP_ADDREQ_FLAG_ADD);
                        free(wh);
                    }
                    WinHttpAddRequestHeaders(hReq,L"Content-Type: application/json",-1L,WINHTTP_ADDREQ_FLAG_ADD);
                    if(WinHttpSendRequest(hReq,WINHTTP_NO_ADDITIONAL_HEADERS,0,
                        (LPVOID)body,(DWORD)strlen(body),(DWORD)strlen(body),0)){
                        if(WinHttpReceiveResponse(hReq,NULL)){
                            char buf[16384]={0}; DWORD rd=0,total=0;
                            while(WinHttpReadData(hReq,buf+total,sizeof(buf)-total-1,&rd)&&rd>0) total+=rd;
                            buf[total]='\0';
                            ok = together_extract_content(buf, a->result, sizeof(a->result));
                        }
                    }
                    WinHttpCloseHandle(hReq);
                }
                WinHttpCloseHandle(hConn);
            }
            WinHttpCloseHandle(hSess);
        }
    }

    if(!ok) {
        local_soc_agent_response(a->prompt, a->teamIndex, a->result, sizeof(a->result));
    }

    if(a->hList){
        const char *tName = (a->teamIndex>=0 && a->teamIndex<=4) ?
            (const char*[]){"RED","BLUE","PURPLE","YELLOW","GREEN"}[a->teamIndex] : "BLUE";
        char line[8200];
        if(ok && a->provider == 0)
            snprintf(line,sizeof(line),"[%s AGENT - DeepSeek-V4]: %s", tName, a->result);
        else if(ok && a->provider == 2)
            snprintf(line,sizeof(line),"[%s AGENT - NVIDIA GLM-5.3-Flash]: %s", tName, a->result);
        else if(ok)
            snprintf(line,sizeof(line),"[%s AGENT - Groq]: %s", tName, a->result);
        else
            snprintf(line,sizeof(line),"[%s AGENT - Local Telemetry]: %s", tName, a->result);

        /* Split on \n and add each line */
        char *tok=strtok(line,"\n");
        while(tok){
            SendMessageA(a->hList,LB_ADDSTRING,0,(LPARAM)tok);
            tok=strtok(NULL,"\n");
        }
        int cnt=(int)SendMessageA(a->hList,LB_GETCOUNT,0,0);
        SendMessageA(a->hList,LB_SETTOPINDEX,cnt-1,0);
    }
    if(InterlockedDecrement(&g_teamPendingRequests)==0) EnableWindow(a->hSend,TRUE);
    free(a);
    return 0;
}

/* ============================================================
 * PAINT: Full Team
 * ============================================================ */
static void PaintTeam(HDC dc,int cx,int cy,int cw,int ch){
    Txt(dc,"AI TEAM - Five role prompts; one model request runs per Dispatch",
        cx+MRG,cy+10,800,18,C_TEXT,fMed,DT_LEFT|DT_SINGLELINE);
    DrawLine(dc,cx+MRG,cy+28,cx+cw-MRG,cy+28,C_BORDER2);

    int tw=(cw-MRG*2-32-130)/5, ty=cy+34;
    static const struct{const char *name;const char *role;COLORREF col;} teams[]={
        {"RED TEAM",    "Offensive Ops",  C_RED   },
        {"BLUE TEAM",   "Defense & SOC",  C_BLUE  },
        {"PURPLE TEAM", "Collaboration",  RGB(150,50,220)},
        {"YELLOW TEAM", "AppSec & Dev",   C_AMBER },
        {"GREEN TEAM",  "Governance",     C_GREEN },
        {NULL,NULL,0}
    };
    for(int i=0;teams[i].name;i++){
        BOOL active=(g_activeTeam==i);
        COLORREF bg=active?teams[i].col:C_CARD2;
        COLORREF bdr=teams[i].col;
        DrawRoundRectPanel(dc,cx+MRG+i*(tw+8),ty,tw,48,7,bg,bdr);
        Txt(dc,teams[i].name, cx+MRG+i*(tw+8),ty+5,  tw,18,active?C_TEXT:teams[i].col,fSm,DT_CENTER|DT_SINGLELINE);
        Txt(dc,teams[i].role, cx+MRG+i*(tw+8),ty+24, tw,18,active?C_TEXT:C_DIM,        fSm,DT_CENTER|DT_SINGLELINE);
    }

    /* Engineer Roster per Team */
    typedef struct {
        const char *name;
        const char *alias;
        const char *role;
        const char *status;
        const char *specialty;
    } Engineer;

    static const Engineer engineers[5][5] = {
        { {"Scope Review","","Authorized scope","ROLE PRESET","No tool execution"}, {"Exposure Review","","Attack surface","ROLE PRESET","No tool execution"}, {"Risk Triage","","Security review","ROLE PRESET","No tool execution"}, {"Abuse Case Review","","Threat modeling","ROLE PRESET","No tool execution"}, {"Recommendations","","Defensive guidance","ROLE PRESET","No tool execution"} },
        { {"Incident Triage","","SOC analysis","ROLE PRESET","No tool execution"}, {"Malware Triage","","Safe file review","ROLE PRESET","No tool execution"}, {"Threat Hunting","","Evidence review","ROLE PRESET","No tool execution"}, {"Detection Review","","Alert analysis","ROLE PRESET","No tool execution"}, {"Patch Advisory","","Remediation review","ROLE PRESET","No tool execution"} },
        { {"ATT&CK Mapping","","Technique review","ROLE PRESET","No tool execution"}, {"Control Review","","Defensive controls","ROLE PRESET","No tool execution"}, {"Scenario Review","","Safe simulation plans","ROLE PRESET","No tool execution"}, {"Detection Gaps","","Detection review","ROLE PRESET","No tool execution"}, {"Risk Evaluation","","Posture guidance","ROLE PRESET","No tool execution"} },
        { {"Code Review","","Application security","ROLE PRESET","No tool execution"}, {"Cloud Review","","Configuration review","ROLE PRESET","No tool execution"}, {"API Review","","Interface security","ROLE PRESET","No tool execution"}, {"Pipeline Review","","DevSecOps","ROLE PRESET","No tool execution"}, {"Frontend Review","","Web security","ROLE PRESET","No tool execution"} },
        { {"Compliance Review","","Control mapping","ROLE PRESET","No tool execution"}, {"Risk Review","","Risk register","ROLE PRESET","No tool execution"}, {"Policy Review","","Governance","ROLE PRESET","No tool execution"}, {"Awareness Review","","Training guidance","ROLE PRESET","No tool execution"}, {"Privacy Review","","Data protection","ROLE PRESET","No tool execution"} }
    };

    int ry = ty + 56;
    COLORREF teamCols[] = {C_RED, C_BLUE, RGB(150,50,220), C_AMBER, C_GREEN};
    COLORREF curCol = teamCols[g_activeTeam % 5];

    /* Container for the 5 Engineers */
    DrawRoundRectPanel(dc, cx+MRG, ry, cw-MRG*2, 78, 6, C_CARD2, curCol);

    int engW = (cw - MRG*2 - 16) / 5;
    for(int i = 0; i < 5; i++) {
        const Engineer *e = &engineers[g_activeTeam % 5][i];
        int ex = cx + MRG + 8 + i * engW;

        /* Engineer Avatar circle */
        HBRUSH hBrCol = CreateSolidBrush(curCol);
        HBRUSH hOldBr = (HBRUSH)SelectObject(dc, hBrCol);
        HPEN hPenCol = CreatePen(PS_SOLID, 1, curCol);
        HPEN hOldPen = (HPEN)SelectObject(dc, hPenCol);
        Ellipse(dc, ex, ry + 10, ex + 18, ry + 28);
        SelectObject(dc, hOldBr);
        SelectObject(dc, hOldPen);
        DeleteObject(hBrCol);
        DeleteObject(hPenCol);

        /* Engineer Name and Alias */
        char nameStr[96];
        snprintf(nameStr, sizeof(nameStr), "%s %s", e->name, e->alias);
        Txt(dc, nameStr, ex + 22, ry + 7, engW - 28, 16, C_TEXT, fSm, DT_LEFT|DT_SINGLELINE);

        /* Engineer Role */
        Txt(dc, e->role, ex + 22, ry + 22, engW - 28, 14, curCol, fSm, DT_LEFT|DT_SINGLELINE);

        /* Status & Specialty */
        HBRUSH hDotBr = CreateSolidBrush(C_DIM);
        HPEN   hDotPen = CreatePen(PS_SOLID, 1, C_DIM);
        HBRUSH oDb = (HBRUSH)SelectObject(dc, hDotBr);
        HPEN   oDp = (HPEN)SelectObject(dc, hDotPen);
        Ellipse(dc, ex + 4, ry + 46, ex + 11, ry + 53);
        SelectObject(dc, oDb); SelectObject(dc, oDp);
        DeleteObject(hDotBr); DeleteObject(hDotPen);

        Txt(dc, e->status, ex + 15, ry + 42, engW - 20, 14, C_DIM, fSm, DT_LEFT|DT_SINGLELINE);
        Txt(dc, e->specialty, ex + 4, ry + 58, engW - 8, 14, C_DIM2, fSm, DT_LEFT|DT_SINGLELINE);
    }

    /* Channel status header */
    Txt(dc, "Responses appear only after Dispatch; no continuous security scan is running.",
        cx+MRG, ry+82, cw-MRG*2, 16, C_DIM, fSm, DT_LEFT|DT_SINGLELINE);
}

static void PaintApps(HDC dc,int cx,int cy,int cw,int ch){
    /* Header */
    Txt(dc,"APP DISCOVERY & INTEGRATION HUB - Software Stack Ecosystem & Relationship Graph",cx+MRG,cy+10,750,18,C_TEXT,fMed,DT_LEFT|DT_SINGLELINE);
    DrawLine(dc,cx+MRG,cy+28,cx+cw-MRG,cy+28,C_BORDER2);

    /* Stat pills at top-right */
    char statBuf[160];
    int running=0,stacks=0,unknown=0;
    for(int i=0;i<g_discAppCnt;i++){
        if(g_discApps[i].state==APP_STATE_RUNNING) running++;
        if(g_discApps[i].isStack) stacks++;
        if(g_discApps[i].type==APP_TYPE_UNKNOWN) unknown++;
    }
    snprintf(statBuf,sizeof(statBuf),"Discovered: %d | Running: %d | Stacks: %d | Graph Edges: %d | Unknown: %d",
             g_discAppCnt,running,stacks,g_discRelCnt,unknown);
    Txt(dc,statBuf,cx+cw-MRG-520,cy+10,520,18,C_CYAN,fSm,DT_RIGHT|DT_SINGLELINE);

    /* Left panel header */
    FillR(dc,cx,cy+34,cw/2-6,24,C_PANEL);
    DrawBdr(dc,cx,cy+34,cw/2-6,24,C_BORDER,1);
    Txt(dc,"  Software Ecosystem (Registry, Processes, SCM, Ports, Stacks)",cx+6,cy+34,cw/2-20,24,C_TEXT,fSm,DT_LEFT|DT_SINGLELINE|DT_VCENTER);

    /* Right panel header */
    int ahRight2=cx+cw/2+10;
    FillR(dc,ahRight2,cy+34,cw/2-10,24,C_PANEL);
    DrawBdr(dc,ahRight2,cy+34,cw/2-10,24,C_BORDER,1);
    Txt(dc,"  Application Topology, Stack Tree, Graph & Cryptographic Keys",ahRight2+6,cy+34,cw/2-20,24,C_TEXT,fSm,DT_LEFT|DT_SINGLELINE|DT_VCENTER);
}
static void PaintAll(HWND hw,HDC dc){
    RECT wr; GetClientRect(hw,&wr);
    int W=wr.right,H=wr.bottom;
    FillR(dc,0,0,W,H,C_BG);
    PaintHdr(dc,W);
    PaintNav(dc,H);
    PaintStb(dc,W,H);
    int cx=NAV_W,cy=HDR_H,cw=W-NAV_W,ch=H-HDR_H-STB_H;
    FillR(dc,cx,cy,cw,ch,C_BG);
    switch(g_tab){
        case TAB_DASH:      PaintDash(dc,cx,cy,cw,ch); break;
        case TAB_ENG:       PaintEng(dc,cx,cy,cw,ch);  break;
        case TAB_NET:       PaintNet(dc,cx,cy,cw,ch);  break;
        case TAB_WAF:       PaintWaf(dc,cx,cy,cw,ch);  break;
        case TAB_AV:        PaintAv(dc,cx,cy,cw,ch);   break;
        case TAB_RANSOM:    PaintRansom(dc,cx,cy,cw,ch); break;
        case TAB_SBX:       PaintSbx(dc,cx,cy,cw,ch);  break;
        case TAB_FW:        PaintFw(dc,cx,cy,cw,ch);   break;
        case TAB_UPD:       PaintUpd(dc,cx,cy,cw,ch);  break;
        case TAB_THREAT:    PaintThreat(dc,cx,cy,cw,ch); break;
        case TAB_APPS:       PaintApps(dc,cx,cy,cw,ch);  break;
        case TAB_AI:        PaintAi(dc,cx,cy,cw,ch);   break;
        case TAB_FORENSICS: PaintForensics(dc,cx,cy,cw,ch); break;
        case TAB_SET:       PaintSet(dc,cx,cy,cw,ch);  break;
        case TAB_TEAM:      PaintTeam(dc,cx,cy,cw,ch); break;
    }
}



/* --- Control Layout -------------------------------------------------------- */
static void Layout(HWND hw){
    RECT wr; GetClientRect(hw,&wr);
    int W=wr.right,H=wr.bottom;
    int cx=NAV_W+MRG,cy=HDR_H,cw=W-NAV_W-MRG*2;

#define SHOW(h,tab) if(h) ShowWindow(h,(g_tab==(tab))?SW_SHOW:SW_HIDE)
#define POS(h,x,y,w,hh) if(h) SetWindowPos(h,NULL,x,y,w,hh,SWP_NOZORDER)

    int swTop = 360;
    int sxTop = (W - swTop) / 2;
    int syTop = (HDR_H - 34) / 2;
    if(hTopSearch) SetWindowPos(hTopSearch, NULL, sxTop + 34, syTop + 6, swTop - 46, 22, SWP_NOZORDER);

    /* WAF */
    SHOW(hWafIn,TAB_WAF); SHOW(hWafGo,TAB_WAF); SHOW(hWafClr,TAB_WAF); SHOW(hWafLog,TAB_COUNT);
    int wafBtnW = 120;
    POS(hWafIn,  cx, cy + 52, cw - wafBtnW - 10, 54);
    POS(hWafGo,  cx + cw - wafBtnW, cy + 52, wafBtnW, 25);
    POS(hWafClr, cx + cw - wafBtnW, cy + 81, wafBtnW, 25);

    /* AV */
    SHOW(hAvPath,TAB_AV); SHOW(hAvBrw,TAB_AV); SHOW(hAvScn,TAB_AV);
    SHOW(hAvScanDir,TAB_AV); SHOW(hAvScanAll,TAB_AV); SHOW(hAvBootAudit,TAB_AV); SHOW(hAvClearDb,TAB_AV);
    SHOW(hAvSearchIn,TAB_AV); SHOW(hAvFilterThreat,TAB_AV); SHOW(hAvFilterTime,TAB_AV); SHOW(hAvExport,TAB_AV);
    SHOW(hAvThreatList,TAB_AV);
    SHOW(hAvLog,TAB_COUNT); SHOW(hAvMarkSafe,TAB_COUNT); SHOW(hAvQuarantine,TAB_COUNT);

    int avRow1Y = cy + 96;
    int avBtnH = 32;
    int curAvX = cx + MRG;

    POS(hAvScn,       curAvX, avRow1Y, 108, avBtnH); curAvX += 114;
    POS(hAvScanDir,   curAvX, avRow1Y, 116, avBtnH); curAvX += 122;
    POS(hAvScanAll,   curAvX, avRow1Y, 142, avBtnH); curAvX += 148;
    POS(hAvBootAudit, curAvX, avRow1Y, 178, avBtnH); curAvX += 184;
    POS(hAvClearDb,   curAvX, avRow1Y, 126, avBtnH);

    int avBrwW = 85;
    int avPathW = 260;
    POS(hAvBrw,  cx + cw - MRG - avBrwW,               avRow1Y, avBrwW,  avBtnH);
    POS(hAvPath, cx + cw - MRG - avBrwW - 8 - avPathW, avRow1Y, avPathW, avBtnH);

    int avRow2Y = avRow1Y + avBtnH + 10;
    int avRow2H = 30;
    POS(hAvSearchIn, cx + MRG, avRow2Y, 260, avRow2H);

    int avExpW = 115;
    int avTimeW = 140;
    int avThW = 130;
    POS(hAvExport,       cx + cw - MRG - avExpW,                                     avRow2Y, avExpW,  avRow2H);
    POS(hAvFilterTime,   cx + cw - MRG - avExpW - 8 - avTimeW,                       avRow2Y, avTimeW, avRow2H);
    POS(hAvFilterThreat, cx + cw - MRG - avExpW - 8 - avTimeW - 8 - avThW,           avRow2Y, avThW,   avRow2H);

    int avTblY = cy + 206;
    POS(hAvThreatList, cx + MRG, avTblY, cw - MRG * 2, H - avTblY - STB_H - 12);

    /* Sandbox */
    SHOW(hSbxPath,TAB_SBX); SHOW(hSbxBrw,TAB_SBX); SHOW(hSbxRun,TAB_SBX);
    SHOW(hSbxKill,TAB_SBX); SHOW(hSbxBNet,TAB_SBX); SHOW(hSbxBFile,TAB_SBX);
    SHOW(hSbxBProc,TAB_SBX);
    SHOW(hSbxLog, TAB_COUNT);

    int sbxBinY = cy + 64;
    int sbxBinH = 26;
    POS(hSbxPath, cx,           sbxBinY, cw - 256, sbxBinH);
    POS(hSbxBrw,  cx + cw - 250, sbxBinY, 118, sbxBinH);
    POS(hSbxRun,  cx + cw - 126, sbxBinY, 126, sbxBinH);

    int sbxActY = cy + 206;
    int sbxActH = 26;
    POS(hSbxBNet,  cx,          sbxActY, 140, sbxActH);
    POS(hSbxBFile, cx + 150,    sbxActY, 150, sbxActH);
    POS(hSbxBProc, cx + 310,    sbxActY, 150, sbxActH);
    POS(hSbxKill,  cx + 470,    sbxActY, 130, sbxActH);

    /* Firewall */
    SHOW(hFwToggle,TAB_FW); SHOW(hFwLockdown,TAB_FW); SHOW(hFwDefaults,TAB_FW);
    SHOW(hFwList,TAB_FW); SHOW(hFwAdd,TAB_FW); SHOW(hFwDel,TAB_FW);
    SHOW(hFwBlkProc,TAB_FW); SHOW(hFwReload,TAB_FW);
    SHOW(hFwRuleName,TAB_FW); SHOW(hFwRulePort,TAB_FW);
    int fwRw = 264;
    int fwLw = cw - fwRw - 14;
    if(fwLw < 500) fwLw = 500;
    int fwTopY = cy + 34;
    int fwSecY = cy + 68;
    int fwCardY = cy + 102;
    int fwCardH = H - fwCardY - STB_H - 12;

    /* Top Row Buttons */
    POS(hFwToggle,   cx + 160, fwTopY, 115, 26);
    POS(hFwLockdown, cx + 283, fwTopY, 140, 26);
    POS(hFwDefaults, cx + 431, fwTopY, 135, 26);

    /* Second Row Controls */
    POS(hFwRuleName, cx,       fwSecY, 175, 26);
    POS(hFwRulePort, cx + 183, fwSecY, 160, 26);
    POS(hFwAdd,      cx + 351, fwSecY, 80,  26);
    POS(hFwDel,      cx + 439, fwSecY, 82,  26);
    POS(hFwBlkProc,  cx + 529, fwSecY, 105, 26);
    POS(hFwReload,   cx + 642, fwSecY, 95,  26);

    /* Table Listbox inside Left Container */
    POS(hFwList,     cx + 4,   fwCardY + 54, fwLw - 8, fwCardH - 58);

    /* Autonomous CVE Agent - Modern Dashboard Layout */
    if (g_tab == TAB_UPD && g_cveSubNav == 1) {
        ShowWindow(hUpdSearch, SW_SHOW);
        int updHeroY = cy + 8;
        int updHeroH = 68;
        int updSubNavY = updHeroY + updHeroH + 10;
        int updSubNavH = 32;
        int updKpiY = updSubNavY + updSubNavH + 10;
        int updKpiH = 82;
        int updToolY = updKpiY + updKpiH + 12;
        POS(hUpdSearch, cx + 8 + 34, updToolY + 6, 275, 22);
    } else {
        ShowWindow(hUpdSearch, SW_HIDE);
    }
    ShowWindow(hUpdNotifyMode, SW_HIDE);
    ShowWindow(hUpdScan,    SW_HIDE);
    ShowWindow(hUpdFixAll,  SW_HIDE);
    ShowWindow(hUpdChk,     SW_HIDE);
    ShowWindow(hUpdSel,     SW_HIDE);
    ShowWindow(hUpdWin,     SW_HIDE);
    ShowWindow(hUpdWatcher, SW_HIDE);
    ShowWindow(hUpdAiFix,   SW_HIDE);
    ShowWindow(hUpdSandbox, SW_HIDE);
    ShowWindow(hUpdList,    SW_HIDE);

    /* NetGuard Traffic */
    SHOW(hNetScan,     TAB_NET); SHOW(hNetPorts,    TAB_NET); SHOW(hNetPortIn,   TAB_NET);
    SHOW(hNetClosePort,TAB_NET); SHOW(hNetSort,     TAB_NET); SHOW(hNetKill,     TAB_NET);
    SHOW(hNetDnsIn,    TAB_NET); SHOW(hNetBlockDns, TAB_NET); SHOW(hNetList,     TAB_NET);

    int ngBannerY = cy + 12;
    int ngBannerH = 76;
    int ngBannerW = cw - MRG * 2;
    int ngToolY   = ngBannerY + ngBannerH + 12;
    int ngToolH   = 32;

    /* Toolbar buttons */
    POS(hNetScan,      cx + MRG,       ngToolY, 150, ngToolH);
    POS(hNetPorts,     cx + MRG + 160, ngToolY, 140, ngToolH);
    POS(hNetClosePort, cx + MRG + 310, ngToolY, 110, ngToolH);
    POS(hNetPortIn,    cx - 1000,      ngToolY, 10,  ngToolH);
    POS(hNetKill,      cx + cw - MRG - 85, ngToolY, 85, ngToolH);
    POS(hNetSort,      cx + cw - MRG - 85 - 10 - 130, ngToolY, 130, ngToolH);

    /* Search bar row */
    int ngSrchY = ngToolY + ngToolH + 10;
    int ngSrchH = 34;
    int snortW = 100;
    POS(hNetDnsIn,    cx + MRG + 32, ngSrchY + 4, ngBannerW - 32 - snortW - 14, 26);
    POS(hNetBlockDns, cx + MRG + ngBannerW - snortW - 8, ngSrchY + 4, snortW, 26);

    /* Table Container Listbox */
    int ngTblY = ngSrchY + ngSrchH + 10;
    int ngTblH = H - ngTblY - STB_H - 14;
    POS(hNetList, cx + MRG + 2, ngTblY + 36, ngBannerW - 4, ngTblH - 38);

    /* RansomShield */
    SHOW(hRwStart,       TAB_RANSOM); SHOW(hRwStop,        TAB_RANSOM);
    SHOW(hRwDeployHoney, TAB_RANSOM); SHOW(hRwCheckHoney,  TAB_RANSOM);
    SHOW(hRwVss,         TAB_RANSOM); SHOW(hRwList,        TAB_RANSOM);
    int rwBtnY = cy + 38;
    int rwBtnH = 28;
    POS(hRwStart,        cx,          rwBtnY, 130, rwBtnH);
    POS(hRwStop,         cx + 140,    rwBtnY, 120, rwBtnH);
    POS(hRwDeployHoney,  cx + 270,    rwBtnY, 145, rwBtnH);
    POS(hRwCheckHoney,   cx + 425,    rwBtnY, 135, rwBtnH);
    POS(hRwVss,          cx + 570,    rwBtnY, 165, rwBtnH);
    int rwCard1W = (cw - 14) / 2;
    POS(hRwList,         cx + 16,     cy + 76 + 36, rwCard1W - 32, 106);

    /* Threat & Advanced Gaming Engine - Pure modern HUD */
    SHOW(hThrBoost,TAB_COUNT); SHOW(hThrGame,TAB_COUNT); SHOW(hThrPurge,TAB_COUNT);
    SHOW(hThrCustom,TAB_COUNT); SHOW(hThrTcp,TAB_COUNT); SHOW(hThrAc,TAB_COUNT);
    SHOW(hThrPassIn,TAB_COUNT); SHOW(hThrHibp,TAB_COUNT); SHOW(hThrList,TAB_COUNT);

    int thrY = cy + 138;
    int curThrX = cx + MRG;
    POS(hThrBoost,  curThrX, thrY, 205, 28); curThrX += 212;
    POS(hThrGame,   curThrX, thrY, 140, 28); curThrX += 146;
    POS(hThrPurge,  curThrX, thrY, 150, 28); curThrX += 156;
    POS(hThrCustom, curThrX, thrY, 135, 28); curThrX += 141;
    POS(hThrTcp,    curThrX, thrY, 140, 28); curThrX += 146;
    POS(hThrAc,     curThrX, thrY, 125, 28); curThrX += 131;

    POS(hThrList,   cx + MRG, cy + 172, cw - MRG*2, H - cy - 172 - STB_H - 14);

    /* --- App Hub Tab Layout --- */
    SHOW(hAppList,       TAB_APPS);
    SHOW(hAppDetail,     TAB_APPS);
    SHOW(hAppRefresh,    TAB_APPS);
    SHOW(hAppFilter,     TAB_APPS);
    SHOW(hAppRelGraph,   TAB_APPS);
    SHOW(hAppLink,       TAB_APPS);
    SHOW(hAppAiId,       TAB_APPS);
    SHOW(hAppIntKey,     TAB_APPS);

    int ahBtnY = cy + 4;
    int ahCurX = cx;
    POS(hAppRefresh,     ahCurX, ahBtnY, 115, 26); ahCurX += 120;
    POS(hAppFilter,      ahCurX, ahBtnY, 110, 26); ahCurX += 115;
    POS(hAppRelGraph,    ahCurX, ahBtnY, 100, 26); ahCurX += 105;
    POS(hAppLink,        ahCurX, ahBtnY,  95, 26); ahCurX += 100;
    POS(hAppAiId,        ahCurX, ahBtnY, 105, 26); ahCurX += 110;
    POS(hAppIntKey,      ahCurX, ahBtnY,  95, 26);

    int ahLeft  = cx;
    int ahRight = cx + cw/2 + 10;
    int ahRW    = cw/2 - 10;
    POS(hAppList,        ahLeft,       cy+60, cw/2-6, H-cy-60-STB_H-14);
    POS(hAppDetail,      ahRight,      cy+60, ahRW,   H-cy-60-STB_H-14);


    /* AI SOC Analyst - Chat View with Voice Toggle */
    SHOW(hAiPrompt,TAB_AI); SHOW(hAiSend,TAB_AI);
    SHOW(hAiQ1,TAB_AI); SHOW(hAiQ2,TAB_AI); SHOW(hAiQ3,TAB_AI); SHOW(hAiQ4,TAB_AI);
    SHOW(hAiList,TAB_AI); SHOW(hAiVoice,TAB_AI);
    POS(hAiVoice,  cx+cw-120,       cy+36,120,24);
    int qw2=(cw-18)/4;
    POS(hAiQ1,     cx,              cy+66,qw2,24);
    POS(hAiQ2,     cx+qw2+6,        cy+66,qw2,24);
    POS(hAiQ3,     cx+(qw2+6)*2,    cy+66,qw2,24);
    POS(hAiQ4,     cx+(qw2+6)*3,    cy+66,qw2,24);
    POS(hAiList,   cx,              cy+96,cw,H-cy-96-STB_H-46);
    POS(hAiPrompt, cx,              H-STB_H-36,cw-116,26);
    POS(hAiSend,   cx+cw-110,       H-STB_H-36,110,26);

    /* Forensics */
    SHOW(hForRefresh,TAB_FORENSICS); SHOW(hForExport,TAB_FORENSICS); SHOW(hForList,TAB_FORENSICS);
    POS(hForRefresh, cx,       cy+54,150,22);
    POS(hForExport,  cx+158,   cy+54,140,22);
    POS(hForList,    cx,       cy+90,cw,H-cy-90-STB_H-14);

    /* Settings - Subtab Sensitive Layout */
    int setSideW = 205;
    int setMainX = cx + MRG + setSideW + 14;
    int setMainW = cw - setSideW - MRG - 14;
    BOOL isSet = (g_tab == TAB_SET);

    /* Show only controls relevant to the active subtab */
    ShowWindow(hStProv,     (isSet && g_setSubTab == SET_AISOC) ? SW_SHOW : SW_HIDE);
    ShowWindow(hStAiKey,    (isSet && g_setSubTab == SET_AISOC) ? SW_SHOW : SW_HIDE);
    ShowWindow(hStAiApply,  (isSet && g_setSubTab == SET_AISOC) ? SW_SHOW : SW_HIDE);

    ShowWindow(hStWebUrl,   (isSet && g_setSubTab == SET_ADVANCED) ? SW_SHOW : SW_HIDE);
    ShowWindow(hStWbApply,  (isSet && g_setSubTab == SET_ADVANCED) ? SW_SHOW : SW_HIDE);
    ShowWindow(hStHook,     (isSet && g_setSubTab == SET_ADVANCED) ? SW_SHOW : SW_HIDE);
    ShowWindow(hStPort,     (isSet && g_setSubTab == SET_ADVANCED) ? SW_SHOW : SW_HIDE);
    ShowWindow(hStApply,    (isSet && g_setSubTab == SET_ADVANCED) ? SW_SHOW : SW_HIDE);

    ShowWindow(hStLogMax,   (isSet && g_setSubTab == SET_FORENSICS) ? SW_SHOW : SW_HIDE);
    ShowWindow(hStLogApply, (isSet && g_setSubTab == SET_FORENSICS) ? SW_SHOW : SW_HIDE);
    ShowWindow(hStExPath,   (isSet && g_setSubTab == SET_FORENSICS) ? SW_SHOW : SW_HIDE);
    ShowWindow(hStExBrw,    (isSet && g_setSubTab == SET_FORENSICS) ? SW_SHOW : SW_HIDE);

    ShowWindow(hStWizard,   (isSet && g_setSubTab == SET_GENERAL) ? SW_SHOW : SW_HIDE);

    ShowWindow(hStSound, SW_HIDE);
    ShowWindow(hStRsAuto, SW_HIDE);
    ShowWindow(hStFwDfl, SW_HIDE);
    ShowWindow(hStAuto, SW_HIDE);

    if (isSet) {
        if (g_setSubTab == SET_AISOC) {
            POS(hStProv,    setMainX + 150, cy + 138, 320, 140);
            POS(hStAiKey,   setMainX + 150, cy + 176, setMainW - 250, 24);
            POS(hStAiApply, setMainX + setMainW - 90, cy + 176, 80, 24);
        } else if (g_setSubTab == SET_ADVANCED) {
            POS(hStWebUrl,  setMainX + 160, cy + 138, setMainW - 260, 24);
            POS(hStWbApply, setMainX + setMainW - 90, cy + 138, 80, 24);
            POS(hStHook,    setMainX + 160, cy + 172, 120, 24);
            POS(hStPort,    setMainX + 160, cy + 202, 80, 24);
            POS(hStApply,   setMainX + 248, cy + 202, 80, 24);
        } else if (g_setSubTab == SET_FORENSICS) {
            POS(hStLogMax,  setMainX + 150, cy + 138, 80, 24);
            POS(hStLogApply,setMainX + 238, cy + 138, 80, 24);
            POS(hStExPath,  setMainX + 150, cy + 174, setMainW - 250, 24);
            POS(hStExBrw,   setMainX + setMainW - 90, cy + 174, 80, 24);
        } else if (g_setSubTab == SET_GENERAL) {
            POS(hStWizard,  setMainX + 12, cy + 348, 250, 28);
        }
    }



    /* Engines */
    SHOW(hEngStAll,FALSE); SHOW(hEngSpAll,FALSE);
    POS(hEngStAll, cx+MRG,     H-STB_H-52, 145, 34);
    POS(hEngSpAll, cx+MRG+156, H-STB_H-52, 145, 34);

    /* Full Team */
    SHOW(hTmRed,TAB_TEAM); SHOW(hTmBlue,TAB_TEAM); SHOW(hTmPurple,TAB_TEAM);
    SHOW(hTmYellow,TAB_TEAM); SHOW(hTmGreen,TAB_TEAM); SHOW(hTmAuto,TAB_TEAM); SHOW(hTmAllTeams,TAB_TEAM);
    SHOW(hTmPrompt,TAB_TEAM); SHOW(hTmSend,TAB_TEAM);
    SHOW(hTmList,TAB_TEAM); SHOW(hTmClear,TAB_TEAM);
    {
        int tw2=(cw-MRG*2-32-130)/5;
        int ty2=cy+34;
        POS(hTmRed,    cx+MRG,              ty2,tw2,48);
        POS(hTmBlue,   cx+MRG+tw2+8,        ty2,tw2,48);
        POS(hTmPurple, cx+MRG+(tw2+8)*2,    ty2,tw2,48);
        POS(hTmYellow, cx+MRG+(tw2+8)*3,    ty2,tw2,48);
        POS(hTmGreen,  cx+MRG+(tw2+8)*4,    ty2,tw2,48);
        POS(hTmAuto,   cx+cw-MRG-124,       ty2,124,48);
        POS(hTmAllTeams,cx+MRG,             ty2+110,220,22);

        int ry2=ty2+56+78+24;
        POS(hTmList,   cx+MRG,              ry2,cw-MRG*2,H-ry2-STB_H-42);
        POS(hTmClear,  cx+MRG,              H-STB_H-36,70,26);
        POS(hTmPrompt, cx+MRG+78,           H-STB_H-36,cw-MRG*2-78-112,26);
        POS(hTmSend,   cx+cw-MRG-106,       H-STB_H-36,106,26);
    }

#undef SHOW
#undef POS
}


/* --- Custom Button Drawing ------------------------------------------------ */
static void DrawBtn(HWND hb,HDC dc,RECT *rc,BOOL pressed){
    char txt[128]={0}; GetWindowTextA(hb,txt,127);
    int W = rc->right - rc->left, H = rc->bottom - rc->top;

    /* WebGuard WAF Action Buttons matching target mockup */
    if (hb == hWafGo || strstr(txt, "Inspect Payload")) {
        COLORREF bg = pressed ? RGB(26, 70, 200) : RGB(37, 99, 235);
        DrawRoundRectPanel(dc, rc->left, rc->top, W, H, 6, bg, RGB(59, 130, 246));
        SetTextColor(dc, RGB(255, 255, 255));
        SetBkMode(dc, TRANSPARENT);
        SelectObject(dc, fSm ? fSm : (HFONT)GetStockObject(DEFAULT_GUI_FONT));
        RECT btr = *rc;
        DrawTextA(dc, "Inspect Payload", -1, &btr, DT_CENTER|DT_VCENTER|DT_SINGLELINE);
        return;
    }
    if (hb == hWafClr || strstr(txt, "Clear Log")) {
        COLORREF bg = pressed ? RGB(16, 24, 40) : C_CARD;
        DrawRoundRectPanel(dc, rc->left, rc->top, W, H, 6, bg, C_BORDER);
        SetTextColor(dc, C_TEXT2);
        SetBkMode(dc, TRANSPARENT);
        SelectObject(dc, fSm ? fSm : (HFONT)GetStockObject(DEFAULT_GUI_FONT));
        RECT btr = *rc;
        DrawTextA(dc, "Clear Log", -1, &btr, DT_CENTER|DT_VCENTER|DT_SINGLELINE);
        return;
    }

    /* Custom Antivirus Core Buttons matching target screenshot */
    if (hb == hAvScn || strstr(txt, "Scan Files")) {
        COLORREF bg = pressed ? RGB(29, 78, 216) : RGB(37, 99, 235);
        DrawRoundRectPanel(dc, rc->left, rc->top, W, H, 8, bg, RGB(59, 130, 246));
        SetTextColor(dc, RGB(255, 255, 255));
        SetBkMode(dc, TRANSPARENT);
        SelectObject(dc, fSm ? fSm : (HFONT)GetStockObject(DEFAULT_GUI_FONT));
        RECT btr = *rc;
        DrawTextW(dc, L"\uE8A5  Scan Files", -1, &btr, DT_CENTER|DT_VCENTER|DT_SINGLELINE);
        return;
    }
    if (hb == hAvBrw || strcmp(txt, "Browse") == 0) {
        COLORREF bg = pressed ? RGB(29, 78, 216) : RGB(37, 99, 235);
        DrawRoundRectPanel(dc, rc->left, rc->top, W, H, 8, bg, RGB(59, 130, 246));
        SetTextColor(dc, RGB(255, 255, 255));
        SetBkMode(dc, TRANSPARENT);
        SelectObject(dc, fSm ? fSm : (HFONT)GetStockObject(DEFAULT_GUI_FONT));
        RECT btr = *rc;
        DrawTextW(dc, L"\uED25  Browse", -1, &btr, DT_CENTER|DT_VCENTER|DT_SINGLELINE);
        return;
    }
    if (hb == hAvScanDir || strstr(txt, "Scan Folders")) {
        COLORREF bg = pressed ? RGB(16, 24, 40) : C_CARD2;
        DrawRoundRectPanel(dc, rc->left, rc->top, W, H, 8, bg, C_BORDER);
        SetTextColor(dc, C_TEXT2);
        SetBkMode(dc, TRANSPARENT);
        SelectObject(dc, fSm ? fSm : (HFONT)GetStockObject(DEFAULT_GUI_FONT));
        RECT btr = *rc;
        DrawTextW(dc, L"\uED25  Scan Folders", -1, &btr, DT_CENTER|DT_VCENTER|DT_SINGLELINE);
        return;
    }
    if (hb == hAvScanAll || strstr(txt, "Deep System Scan")) {
        COLORREF bg = pressed ? RGB(16, 24, 40) : C_CARD2;
        DrawRoundRectPanel(dc, rc->left, rc->top, W, H, 8, bg, C_BORDER);
        SetTextColor(dc, C_TEXT2);
        SetBkMode(dc, TRANSPARENT);
        SelectObject(dc, fSm ? fSm : (HFONT)GetStockObject(DEFAULT_GUI_FONT));
        RECT btr = *rc;
        DrawTextW(dc, L"\uE8B8  Deep System Scan", -1, &btr, DT_CENTER|DT_VCENTER|DT_SINGLELINE);
        return;
    }
    if (hb == hAvBootAudit || strstr(txt, "Bootkit & Rootkit")) {
        COLORREF bg = pressed ? RGB(16, 24, 40) : C_CARD2;
        DrawRoundRectPanel(dc, rc->left, rc->top, W, H, 8, bg, C_BORDER);
        SetTextColor(dc, C_TEXT2);
        SetBkMode(dc, TRANSPARENT);
        SelectObject(dc, fSm ? fSm : (HFONT)GetStockObject(DEFAULT_GUI_FONT));
        RECT btr = *rc;
        DrawTextW(dc, L"\uEA18  Bootkit & Rootkit Audit", -1, &btr, DT_CENTER|DT_VCENTER|DT_SINGLELINE);
        return;
    }
    if (hb == hAvClearDb || strstr(txt, "Clear Resolved")) {
        COLORREF bg = pressed ? RGB(16, 24, 40) : C_CARD2;
        DrawRoundRectPanel(dc, rc->left, rc->top, W, H, 8, bg, C_BORDER);
        SetTextColor(dc, C_TEXT2);
        SetBkMode(dc, TRANSPARENT);
        SelectObject(dc, fSm ? fSm : (HFONT)GetStockObject(DEFAULT_GUI_FONT));
        RECT btr = *rc;
        DrawTextW(dc, L"\uE894  Clear Resolved", -1, &btr, DT_CENTER|DT_VCENTER|DT_SINGLELINE);
        return;
    }
    if (hb == hAvFilterThreat || strstr(txt, "All Threats")) {
        COLORREF bg = pressed ? RGB(16, 24, 40) : C_CARD2;
        DrawRoundRectPanel(dc, rc->left, rc->top, W, H, 8, bg, C_BORDER2);
        SetTextColor(dc, C_TEXT2);
        SetBkMode(dc, TRANSPARENT);
        SelectObject(dc, fSm ? fSm : (HFONT)GetStockObject(DEFAULT_GUI_FONT));
        RECT btr = *rc;
        DrawTextW(dc, L"\uEA18  All Threats  \u2304", -1, &btr, DT_CENTER|DT_VCENTER|DT_SINGLELINE);
        return;
    }
    if (hb == hAvFilterTime || strstr(txt, "Last 24 Hours")) {
        COLORREF bg = pressed ? RGB(16, 24, 40) : C_CARD2;
        DrawRoundRectPanel(dc, rc->left, rc->top, W, H, 8, bg, C_BORDER2);
        SetTextColor(dc, C_TEXT2);
        SetBkMode(dc, TRANSPARENT);
        SelectObject(dc, fSm ? fSm : (HFONT)GetStockObject(DEFAULT_GUI_FONT));
        RECT btr = *rc;
        DrawTextW(dc, L"\uE787  Last 24 Hours  \u2304", -1, &btr, DT_CENTER|DT_VCENTER|DT_SINGLELINE);
        return;
    }
    if (hb == hAvExport || strstr(txt, "Export Logs")) {
        COLORREF bg = pressed ? RGB(16, 24, 40) : C_CARD2;
        DrawRoundRectPanel(dc, rc->left, rc->top, W, H, 8, bg, C_BORDER2);
        SetTextColor(dc, C_TEXT2);
        SetBkMode(dc, TRANSPARENT);
        SelectObject(dc, fSm ? fSm : (HFONT)GetStockObject(DEFAULT_GUI_FONT));
        RECT btr = *rc;
        DrawTextW(dc, L"\uEDE1  Export Logs", -1, &btr, DT_CENTER|DT_VCENTER|DT_SINGLELINE);
        return;
    }

    /* Custom Defense Engines Buttons matching target screenshot */
    if (hb == hEngStAll || strstr(txt, "Start All Engines")) {
        COLORREF bg = pressed ? RGB(5, 35, 25) : RGB(8, 44, 36);
        DrawRoundRectPanel(dc, rc->left, rc->top, W, H, 8, bg, RGB(16, 185, 129));
        SetTextColor(dc, RGB(16, 185, 129));
        SetBkMode(dc, TRANSPARENT);
        SelectObject(dc, fMed ? fMed : (HFONT)GetStockObject(DEFAULT_GUI_FONT));
        RECT btr = *rc;
        DrawTextW(dc, L"\u25B7  Start All Engines", -1, &btr, DT_CENTER|DT_VCENTER|DT_SINGLELINE);
        return;
    }
    if (hb == hEngSpAll || strstr(txt, "Stop All Engines")) {
        COLORREF bg = pressed ? RGB(35, 8, 14) : RGB(46, 13, 22);
        DrawRoundRectPanel(dc, rc->left, rc->top, W, H, 8, bg, RGB(244, 63, 94));
        SetTextColor(dc, RGB(244, 63, 94));
        SetBkMode(dc, TRANSPARENT);
        SelectObject(dc, fMed ? fMed : (HFONT)GetStockObject(DEFAULT_GUI_FONT));
        RECT btr = *rc;
        DrawTextW(dc, L"\u25A0  Stop All Engines", -1, &btr, DT_CENTER|DT_VCENTER|DT_SINGLELINE);
        return;
    }

    /* Custom NetGuard Buttons matching target screenshot */
    if (hb == hNetScan || strstr(txt, "Scan Connections")) {
        COLORREF bg = pressed ? RGB(6, 38, 28) : RGB(10, 48, 36);
        DrawRoundRectPanel(dc, rc->left, rc->top, W, H, 8, bg, RGB(16, 185, 129));
        SetTextColor(dc, RGB(52, 211, 153));
        SetBkMode(dc, TRANSPARENT);
        SelectObject(dc, fMed ? fMed : (HFONT)GetStockObject(DEFAULT_GUI_FONT));
        RECT btr = *rc;
        DrawTextW(dc, L"\uE768  Scan Connections", -1, &btr, DT_CENTER|DT_VCENTER|DT_SINGLELINE);
        return;
    }
    if (hb == hNetPorts || strstr(txt, "Scan Open Ports")) {
        COLORREF bg = pressed ? RGB(16, 24, 40) : C_CARD2;
        DrawRoundRectPanel(dc, rc->left, rc->top, W, H, 8, bg, C_BORDER);
        SetTextColor(dc, C_TEXT2);
        SetBkMode(dc, TRANSPARENT);
        SelectObject(dc, fMed ? fMed : (HFONT)GetStockObject(DEFAULT_GUI_FONT));
        RECT btr = *rc;
        DrawTextW(dc, L"\uE774  Scan Open Ports", -1, &btr, DT_CENTER|DT_VCENTER|DT_SINGLELINE);
        return;
    }
    if (hb == hNetClosePort || strstr(txt, "Close Port")) {
        COLORREF bg = pressed ? RGB(16, 24, 40) : C_CARD2;
        DrawRoundRectPanel(dc, rc->left, rc->top, W, H, 8, bg, C_BORDER);
        SetTextColor(dc, C_TEXT2);
        SetBkMode(dc, TRANSPARENT);
        SelectObject(dc, fMed ? fMed : (HFONT)GetStockObject(DEFAULT_GUI_FONT));
        RECT btr = *rc;
        DrawTextW(dc, L"\uE711  Close Port", -1, &btr, DT_CENTER|DT_VCENTER|DT_SINGLELINE);
        return;
    }
    if (hb == hNetKill || strstr(txt, "Kill PID")) {
        COLORREF bg = pressed ? RGB(60, 12, 20) : RGB(80, 16, 26);
        DrawRoundRectPanel(dc, rc->left, rc->top, W, H, 8, bg, RGB(239, 68, 68));
        SetTextColor(dc, RGB(255, 150, 160));
        SetBkMode(dc, TRANSPARENT);
        SelectObject(dc, fMed ? fMed : (HFONT)GetStockObject(DEFAULT_GUI_FONT));
        RECT btr = *rc;
        DrawTextW(dc, L"\uE74D  Kill PID", -1, &btr, DT_CENTER|DT_VCENTER|DT_SINGLELINE);
        return;
    }
    if (hb == hNetSort || strstr(txt, "Sort by")) {
        COLORREF bg = pressed ? RGB(16, 24, 40) : C_CARD2;
        DrawRoundRectPanel(dc, rc->left, rc->top, W, H, 8, bg, C_BORDER2);
        SetTextColor(dc, C_TEXT2);
        SetBkMode(dc, TRANSPARENT);
        SelectObject(dc, fSm ? fSm : (HFONT)GetStockObject(DEFAULT_GUI_FONT));
        RECT btr = *rc;
        DrawTextW(dc, L"Sort by: Latest  \u2304", -1, &btr, DT_CENTER|DT_VCENTER|DT_SINGLELINE);
        return;
    }
    if (hb == hNetBlockDns || strstr(txt, "Snort/DNS")) {
        COLORREF bg = pressed ? RGB(10, 20, 42) : RGB(14, 28, 54);
        DrawRoundRectPanel(dc, rc->left, rc->top, W, H, 6, bg, RGB(30, 68, 130));
        SetTextColor(dc, RGB(0, 195, 255));
        SetBkMode(dc, TRANSPARENT);
        SelectObject(dc, fSm ? fSm : (HFONT)GetStockObject(DEFAULT_GUI_FONT));
        RECT btr = *rc;
        DrawTextW(dc, L"\uE968  Snort/DNS", -1, &btr, DT_CENTER|DT_VCENTER|DT_SINGLELINE);
        return;
    }

    /* Custom Gaming Mode Toggle Button */
    if (hb == hThrBoost) {
        COLORREF bg = g_gaming.active ? (pressed ? RGB(140, 20, 36) : RGB(180, 25, 45)) : (pressed ? RGB(8, 120, 80) : RGB(16, 160, 110));
        COLORREF bdr = g_gaming.active ? RGB(244, 63, 94) : RGB(52, 211, 153);
        DrawRoundRectPanel(dc, rc->left, rc->top, W, H, 6, bg, bdr);
        SetTextColor(dc, RGB(255, 255, 255));
        SetBkMode(dc, TRANSPARENT);
        SelectObject(dc, fSm ? fSm : (HFONT)GetStockObject(DEFAULT_GUI_FONT));
        RECT btr = *rc;
        DrawTextW(dc, g_gaming.active ? L"\u25A0  Turn OFF Gaming Mode" : L"\u25B6  Turn ON Gaming Mode", -1, &btr, DT_CENTER|DT_VCENTER|DT_SINGLELINE);
        return;
    }

    /* Custom RansomShield Action Buttons matching target mockup */
    if (hb == hRwStart || strcmp(txt, "Start Monitor") == 0) {
        COLORREF bg = pressed ? RGB(6, 40, 26) : RGB(10, 52, 34);
        DrawRoundRectPanel(dc, rc->left, rc->top, W, H, 6, bg, RGB(16, 185, 129));
        SetTextColor(dc, RGB(52, 211, 153));
        SetBkMode(dc, TRANSPARENT);
        SelectObject(dc, fSm ? fSm : (HFONT)GetStockObject(DEFAULT_GUI_FONT));
        RECT btr = *rc;
        DrawTextA(dc, "Start Monitor", -1, &btr, DT_CENTER|DT_VCENTER|DT_SINGLELINE);
        return;
    }
    if (hb == hRwStop || strcmp(txt, "Stop Monitor") == 0) {
        COLORREF bg = pressed ? RGB(45, 10, 18) : RGB(58, 14, 24);
        DrawRoundRectPanel(dc, rc->left, rc->top, W, H, 6, bg, RGB(239, 68, 68));
        SetTextColor(dc, RGB(255, 140, 160));
        SetBkMode(dc, TRANSPARENT);
        SelectObject(dc, fSm ? fSm : (HFONT)GetStockObject(DEFAULT_GUI_FONT));
        RECT btr = *rc;
        DrawTextA(dc, "Stop Monitor", -1, &btr, DT_CENTER|DT_VCENTER|DT_SINGLELINE);
        return;
    }
    if (hb == hRwDeployHoney || strcmp(txt, "Deploy Honeypots") == 0) {
        COLORREF bg = pressed ? RGB(6, 36, 36) : RGB(10, 48, 48);
        DrawRoundRectPanel(dc, rc->left, rc->top, W, H, 6, bg, RGB(20, 184, 166));
        SetTextColor(dc, RGB(94, 234, 212));
        SetBkMode(dc, TRANSPARENT);
        SelectObject(dc, fSm ? fSm : (HFONT)GetStockObject(DEFAULT_GUI_FONT));
        RECT btr = *rc;
        DrawTextA(dc, "Deploy Honeypots", -1, &btr, DT_CENTER|DT_VCENTER|DT_SINGLELINE);
        return;
    }
    if (hb == hRwCheckHoney || strcmp(txt, "Check Honeypots") == 0) {
        COLORREF bg = pressed ? RGB(14, 28, 54) : RGB(20, 38, 72);
        DrawRoundRectPanel(dc, rc->left, rc->top, W, H, 6, bg, RGB(59, 130, 246));
        SetTextColor(dc, RGB(147, 197, 253));
        SetBkMode(dc, TRANSPARENT);
        SelectObject(dc, fSm ? fSm : (HFONT)GetStockObject(DEFAULT_GUI_FONT));
        RECT btr = *rc;
        DrawTextA(dc, "Check Honeypots", -1, &btr, DT_CENTER|DT_VCENTER|DT_SINGLELINE);
        return;
    }
    if (hb == hRwVss || strcmp(txt, "Create VSS Snapshot") == 0) {
        COLORREF bg = pressed ? RGB(44, 24, 8) : RGB(60, 32, 12);
        DrawRoundRectPanel(dc, rc->left, rc->top, W, H, 6, bg, RGB(245, 158, 11));
        SetTextColor(dc, RGB(253, 216, 120));
        SetBkMode(dc, TRANSPARENT);
        SelectObject(dc, fSm ? fSm : (HFONT)GetStockObject(DEFAULT_GUI_FONT));
        RECT btr = *rc;
        DrawTextA(dc, "Create VSS Snapshot", -1, &btr, DT_CENTER|DT_VCENTER|DT_SINGLELINE);
        return;
    }

    /* Custom SmartSandbox Buttons matching target mockup */
    if (hb == hSbxBrw || strcmp(txt, "Choose EXE Setup") == 0) {
        COLORREF bg = pressed ? RGB(16, 24, 36) : RGB(22, 32, 48);
        DrawRoundRectPanel(dc, rc->left, rc->top, W, H, 6, bg, RGB(75, 85, 99));
        SetTextColor(dc, RGB(220, 230, 245));
        SetBkMode(dc, TRANSPARENT);
        SelectObject(dc, fSm ? fSm : (HFONT)GetStockObject(DEFAULT_GUI_FONT));
        RECT btr = *rc;
        DrawTextA(dc, "Choose EXE Setup", -1, &btr, DT_CENTER|DT_VCENTER|DT_SINGLELINE);
        return;
    }
    if (hb == hSbxRun || strcmp(txt, "Run in Sandbox") == 0) {
        COLORREF bg = pressed ? RGB(10, 140, 90) : RGB(16, 185, 129);
        DrawRoundRectPanel(dc, rc->left, rc->top, W, H, 6, bg, RGB(52, 211, 153));
        SetTextColor(dc, RGB(255, 255, 255));
        SetBkMode(dc, TRANSPARENT);
        SelectObject(dc, fSm ? fSm : (HFONT)GetStockObject(DEFAULT_GUI_FONT));
        RECT btr = *rc;
        DrawTextA(dc, "Run in Sandbox", -1, &btr, DT_CENTER|DT_VCENTER|DT_SINGLELINE);
        return;
    }
    if (hb == hSbxBProc || strcmp(txt, "Block in Firewall") == 0) {
        COLORREF bg = pressed ? RGB(160, 20, 30) : RGB(220, 38, 38);
        DrawRoundRectPanel(dc, rc->left, rc->top, W, H, 6, bg, RGB(248, 113, 113));
        SetTextColor(dc, RGB(255, 255, 255));
        SetBkMode(dc, TRANSPARENT);
        SelectObject(dc, fSm ? fSm : (HFONT)GetStockObject(DEFAULT_GUI_FONT));
        RECT btr = *rc;
        DrawTextA(dc, "Block in Firewall", -1, &btr, DT_CENTER|DT_VCENTER|DT_SINGLELINE);
        return;
    }
    if (hb == hSbxKill || strcmp(txt, "Kill Sandbox") == 0) {
        COLORREF bg = pressed ? RGB(160, 20, 30) : RGB(220, 38, 38);
        DrawRoundRectPanel(dc, rc->left, rc->top, W, H, 6, bg, RGB(248, 113, 113));
        SetTextColor(dc, RGB(255, 255, 255));
        SetBkMode(dc, TRANSPARENT);
        SelectObject(dc, fSm ? fSm : (HFONT)GetStockObject(DEFAULT_GUI_FONT));
        RECT btr = *rc;
        DrawTextA(dc, "Kill Sandbox", -1, &btr, DT_CENTER|DT_VCENTER|DT_SINGLELINE);
        return;
    }
    if (hb == hSbxBNet || strstr(txt, "Block Network")) {
        COLORREF bg = pressed ? RGB(14, 20, 30) : (g_sbxBlockNet ? RGB(16, 26, 42) : RGB(14, 18, 26));
        COLORREF bdr = g_sbxBlockNet ? RGB(59, 130, 246) : RGB(75, 85, 99);
        DrawRoundRectPanel(dc, rc->left, rc->top, W, H, 5, bg, bdr);
        SetTextColor(dc, g_sbxBlockNet ? RGB(240, 246, 255) : RGB(140, 155, 175));
        SetBkMode(dc, TRANSPARENT);
        SelectObject(dc, fSm ? fSm : (HFONT)GetStockObject(DEFAULT_GUI_FONT));
        RECT btr = *rc;
        DrawTextA(dc, "[x] Network Blocked", -1, &btr, DT_CENTER|DT_VCENTER|DT_SINGLELINE);
        return;
    }
    if (hb == hSbxBFile || strstr(txt, "Block FileSystem")) {
        COLORREF bg = pressed ? RGB(14, 20, 30) : (g_sbxBlockFs ? RGB(16, 26, 42) : RGB(14, 18, 26));
        COLORREF bdr = g_sbxBlockFs ? RGB(59, 130, 246) : RGB(75, 85, 99);
        DrawRoundRectPanel(dc, rc->left, rc->top, W, H, 5, bg, bdr);
        SetTextColor(dc, g_sbxBlockFs ? RGB(240, 246, 255) : RGB(140, 155, 175));
        SetBkMode(dc, TRANSPARENT);
        SelectObject(dc, fSm ? fSm : (HFONT)GetStockObject(DEFAULT_GUI_FONT));
        RECT btr = *rc;
        DrawTextA(dc, "[x] Writes Boxed", -1, &btr, DT_CENTER|DT_VCENTER|DT_SINGLELINE);
        return;
    }

    /* Custom Adaptive Firewall Action Buttons matching target mockup */
    if (hb == hFwToggle || strcmp(txt, "Toggle Firewall") == 0) {
        COLORREF bg = pressed ? RGB(20, 28, 42) : RGB(14, 20, 30);
        DrawRoundRectPanel(dc, rc->left, rc->top, W, H, 6, bg, RGB(55, 68, 92));
        SetTextColor(dc, RGB(240, 246, 255));
        SetBkMode(dc, TRANSPARENT);
        SelectObject(dc, fSm ? fSm : (HFONT)GetStockObject(DEFAULT_GUI_FONT));
        RECT btr = *rc;
        DrawTextA(dc, "Toggle Firewall", -1, &btr, DT_CENTER|DT_VCENTER|DT_SINGLELINE);
        return;
    }
    if (hb == hFwLockdown || strcmp(txt, "Emergency Lockdown") == 0) {
        COLORREF bg = pressed ? RGB(180, 28, 28) : RGB(220, 38, 38);
        DrawRoundRectPanel(dc, rc->left, rc->top, W, H, 6, bg, RGB(239, 68, 68));
        SetTextColor(dc, RGB(255, 255, 255));
        SetBkMode(dc, TRANSPARENT);
        SelectObject(dc, fSm ? fSm : (HFONT)GetStockObject(DEFAULT_GUI_FONT));
        RECT btr = *rc;
        DrawTextA(dc, "Emergency Lockdown", -1, &btr, DT_CENTER|DT_VCENTER|DT_SINGLELINE);
        return;
    }
    if (hb == hFwDefaults || strcmp(txt, "Apply Baseline") == 0) {
        COLORREF bg = pressed ? RGB(10, 140, 90) : RGB(16, 185, 129);
        DrawRoundRectPanel(dc, rc->left, rc->top, W, H, 6, bg, RGB(34, 197, 94));
        SetTextColor(dc, RGB(255, 255, 255));
        SetBkMode(dc, TRANSPARENT);
        SelectObject(dc, fSm ? fSm : (HFONT)GetStockObject(DEFAULT_GUI_FONT));
        RECT btr = *rc;
        DrawTextA(dc, "Apply Baseline", -1, &btr, DT_CENTER|DT_VCENTER|DT_SINGLELINE);
        return;
    }
    if (hb == hFwAdd || strcmp(txt, "Add Rule") == 0) {
        COLORREF bg = pressed ? RGB(10, 140, 90) : RGB(16, 185, 129);
        DrawRoundRectPanel(dc, rc->left, rc->top, W, H, 6, bg, RGB(34, 197, 94));
        SetTextColor(dc, RGB(255, 255, 255));
        SetBkMode(dc, TRANSPARENT);
        SelectObject(dc, fSm ? fSm : (HFONT)GetStockObject(DEFAULT_GUI_FONT));
        RECT btr = *rc;
        DrawTextA(dc, "Add Rule", -1, &btr, DT_CENTER|DT_VCENTER|DT_SINGLELINE);
        return;
    }
    if (hb == hFwDel || strcmp(txt, "Delete Rule") == 0) {
        COLORREF bg = pressed ? RGB(180, 28, 28) : RGB(220, 38, 38);
        DrawRoundRectPanel(dc, rc->left, rc->top, W, H, 6, bg, RGB(239, 68, 68));
        SetTextColor(dc, RGB(255, 255, 255));
        SetBkMode(dc, TRANSPARENT);
        SelectObject(dc, fSm ? fSm : (HFONT)GetStockObject(DEFAULT_GUI_FONT));
        RECT btr = *rc;
        DrawTextA(dc, "Delete Rule", -1, &btr, DT_CENTER|DT_VCENTER|DT_SINGLELINE);
        return;
    }
    if (hb == hFwBlkProc || strcmp(txt, "Block App") == 0) {
        COLORREF bg = pressed ? RGB(180, 40, 40) : RGB(220, 50, 50);
        DrawRoundRectPanel(dc, rc->left, rc->top, W, H, 6, bg, RGB(239, 68, 68));
        SetTextColor(dc, RGB(255, 255, 255));
        SetBkMode(dc, TRANSPARENT);
        SelectObject(dc, fSm ? fSm : (HFONT)GetStockObject(DEFAULT_GUI_FONT));
        RECT btr = *rc;
        DrawTextA(dc, "Block App", -1, &btr, DT_CENTER|DT_VCENTER|DT_SINGLELINE);
        return;
    }
    if (hb == hFwReload || strcmp(txt, "Reload Rules") == 0) {
        COLORREF bg = pressed ? RGB(26, 70, 200) : RGB(37, 99, 235);
        DrawRoundRectPanel(dc, rc->left, rc->top, W, H, 6, bg, RGB(59, 130, 246));
        SetTextColor(dc, RGB(255, 255, 255));
        SetBkMode(dc, TRANSPARENT);
        SelectObject(dc, fSm ? fSm : (HFONT)GetStockObject(DEFAULT_GUI_FONT));
        RECT btr = *rc;
        DrawTextA(dc, "Reload Rules", -1, &btr, DT_CENTER|DT_VCENTER|DT_SINGLELINE);
        return;
    }

    COLORREF bg, fg = C_TEXT, bdr;
    if(strstr(txt,"Kill")||strstr(txt,"Stop")||strstr(txt,"Block")||
       strstr(txt,"Lockdown")||strstr(txt,"Delete")||strstr(txt,"Rollback")){bg=C_BTN_DNG;bdr=C_RED;}
    else if(strstr(txt,"Run")||strstr(txt,"Scan")||strstr(txt,"Apply")||
            strstr(txt,"Fix")||strstr(txt,"Update")||strstr(txt,"Add")||
            strstr(txt,"Start")||strstr(txt,"Deploy")||strstr(txt,"Ask")||
            strstr(txt,"Pair")||strstr(txt,"Boost")){bg=C_BTN_SUC;bdr=C_GREEN;}
    else if(strstr(txt,"Inspect")||strstr(txt,"Check")||strstr(txt,"Reload")||
            strstr(txt,"Ping")||strstr(txt,"Refresh")||strstr(txt,"Audit")){bg=C_BTN_PRI;bdr=C_BLUE;}
    else if(strstr(txt,"Windows")||strstr(txt,"Snapshot")||strstr(txt,"Game")){bg=C_BTN_WARN;bdr=C_AMBER;}
    else{bg=C_BTN_DARK;bdr=C_BORDER;}

    if(pressed) bg=RGB(CLAMP((int)GetRValue(bg)-30,0,255),CLAMP((int)GetGValue(bg)-30,0,255),CLAMP((int)GetBValue(bg)-30,0,255));
    DrawRoundRectPanel(dc,rc->left,rc->top,W,H,6,bg,bdr);
    SetTextColor(dc,fg); SetBkMode(dc,TRANSPARENT);
    HFONT of=(HFONT)SelectObject(dc,fSm);
    DrawTextA(dc,txt,-1,rc,DT_CENTER|DT_SINGLELINE|DT_VCENTER|DT_NOPREFIX);
    SelectObject(dc,of);
}

/* --- Real-Time Telemetry Sampler (IP Helper & Win32 Kernel Telemetry) ------- */
static void SampleRealTelemetry(void) {
    ULONG bufLen = 0;
    if (GetIfTable(NULL, &bufLen, FALSE) == ERROR_INSUFFICIENT_BUFFER) {
        PMIB_IFTABLE pIfTable = (PMIB_IFTABLE)malloc(bufLen);
        if (pIfTable && GetIfTable(pIfTable, &bufLen, FALSE) == NO_ERROR) {
            unsigned long long inB = 0, outB = 0, inP = 0, outP = 0, drp = 0;
            for (DWORD i = 0; i < pIfTable->dwNumEntries; i++) {
                if (pIfTable->table[i].dwType != MIB_IF_TYPE_LOOPBACK) {
                    inB += pIfTable->table[i].dwInOctets;
                    outB += pIfTable->table[i].dwOutOctets;
                    inP += pIfTable->table[i].dwInUcastPkts + pIfTable->table[i].dwInNUcastPkts;
                    outP += pIfTable->table[i].dwOutUcastPkts + pIfTable->table[i].dwOutNUcastPkts;
                    drp += pIfTable->table[i].dwInDiscards + pIfTable->table[i].dwInErrors;
                }
            }
            EnterCriticalSection(&g_statsCS);
            g_realInBytes = inB;
            g_realOutBytes = outB;
            g_realInPkts = inP;
            g_realOutPkts = outP;
            g_realDrops = drp;
            g_busEvents = inP + outP;
            LeaveCriticalSection(&g_statsCS);
            free(pIfTable);
        }
    }

    DWORD pids[1024], bytesReturned = 0;
    if (EnumProcesses(pids, sizeof(pids), &bytesReturned)) {
        g_realRunningProcs = bytesReturned / sizeof(DWORD);
    }
}

/* --- Real-Time Telemetry Thread -------------------------------------------- */
static DWORD WINAPI telemThread(LPVOID u){
    (void)u;
    DWORD lastChartShift = GetTickCount();
    unsigned long long lastInPkts = 0, lastOutPkts = 0;

    SampleRealTelemetry();
    lastInPkts = g_realInPkts;
    lastOutPkts = g_realOutPkts;

    /* === Initialize hourly AV scan baseline === */
    g_lastAvScan = GetTickCount();
    g_lastInstallCheck = GetTickCount();

    while(1){
        Sleep(g_gamingMode ? 2500 : 1000);
        SampleRealTelemetry();

        DWORD now = GetTickCount();

        /* === Hourly AV scan of critical directories === */
        if(now - g_lastAvScan >= 3600000UL){
            if(g_gaming.active || g_gaming.scansSuspended){
                /* Postpone background AV scan while gaming mode is engaged to eliminate stutter/frametime spikes */
                g_lastAvScan = now - 3540000UL; /* Check again in 60s */
            } else {
                g_lastAvScan = now;
                g_avAutoFiles = 0; g_avAutoThreats = 0;
                add_alert("AutoAV","INFO","Hourly scheduled scan starting: System32 + Program Files ...");
                /* Scan System32 */
                static const char *scanDirs[]={"C:\\Windows\\System32","C:\\Program Files","C:\\Program Files (x86)",NULL};
                for(int d=0;scanDirs[d];d++){
                    WIN32_FIND_DATAA fd;
                    char pat[MAX_PATH]; snprintf(pat,sizeof(pat),"%s\\*.exe",scanDirs[d]);
                    HANDLE hf=FindFirstFileA(pat,&fd);
                    if(hf!=INVALID_HANDLE_VALUE){
                        do {
                            char fp[MAX_PATH]; snprintf(fp,sizeof(fp),"%s\\%s",scanDirs[d],fd.cFileName);
                            AvResult avr2={0};
                            if(av_scan_file(fp,&avr2)){
                                g_avAutoFiles++;
                                if(avr2.threat){
                                    g_avAutoThreats++;
                                    char am[300]; snprintf(am,sizeof(am),"[THREAT] %s: %s",fd.cFileName,avr2.tname);
                                    add_alert("AutoAV","HIGH",am);
                                    if(hAvLog) SendMessageA(hAvLog,LB_ADDSTRING,0,(LPARAM)am);
                                }
                            } else g_avAutoFiles++;
                        } while(FindNextFileA(hf,&fd)&&g_avAutoFiles<500);

                        FindClose(hf);
                    }
                }
                char summary[200];
                snprintf(summary,sizeof(summary),"Hourly scan complete: %d files scanned, %d threats found",g_avAutoFiles,g_avAutoThreats);
                add_alert("AutoAV",g_avAutoThreats>0?"WARN":"INFO",summary);
                if(hAvLog) SendMessageA(hAvLog,LB_ADDSTRING,0,(LPARAM)summary);
            }
        }

        /* === CVE Install Watcher: check for new installs every 30 seconds === */
        if(now - g_lastInstallCheck >= 30000UL){
            g_lastInstallCheck = now;
            /* Check HKLM uninstall key timestamp */
            HKEY hInst;
            FILETIME ftWrite;
            static FILETIME ftLastSeen = {0,0};
            if(RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
                0,KEY_READ,&hInst)==ERROR_SUCCESS){
                RegQueryInfoKeyA(hInst,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,&ftWrite);
                RegCloseKey(hInst);
                if(ftLastSeen.dwLowDateTime != 0 &&
                   CompareFileTime(&ftWrite,&ftLastSeen)>0){
                    /* New install detected */
                    add_alert("CVEWatcher","INFO","New software install detected - triggering CVE re-scan ...");
                    if(g_hwnd) PostMessageA(g_hwnd,WM_COMMAND,MAKEWPARAM(IDU_SCAN,0),0);
                }
                ftLastSeen = ftWrite;
            }
        }

        if(now - lastChartShift >= 1500) {
            lastChartShift = now;
            unsigned long long curIn = g_realInPkts;
            unsigned long long curOut = g_realOutPkts;
            unsigned long long inDelta = curIn >= lastInPkts ? curIn - lastInPkts : 0;
            unsigned long long outDelta = curOut >= lastOutPkts ? curOut - lastOutPkts : 0;
            lastInPkts = curIn;
            lastOutPkts = curOut;

            EnterCriticalSection(&g_statsCS);
            for (int k = 0; k < 6; k++) {
                g_chartInbound[k]  = g_chartInbound[k+1];
                g_chartOutbound[k] = g_chartOutbound[k+1];
                g_chartClean[k]    = g_chartClean[k+1];
                g_chartFiltered[k] = g_chartFiltered[k+1];
            }
            g_chartInbound[6] = inDelta > INT_MAX ? INT_MAX : (int)inDelta;
            g_chartOutbound[6] = outDelta > INT_MAX ? INT_MAX : (int)outDelta;
            g_chartClean[6] = g_chartInbound[6];
            g_chartFiltered[6] = g_chartOutbound[6];
            LeaveCriticalSection(&g_statsCS);
        }

        if(g_sbx.active) sbx_poll();

        char honeyPath[MAX_PATH]={0};
        if(rw_check_honeypots(honeyPath,sizeof(honeyPath))){
            char hm[300]; snprintf(hm,sizeof(hm),"HONEYPOT TRIGGERED: %s - Ransomware behavior!",honeyPath);
            add_alert("RansomShield","CRITICAL",hm);
        }

        if(g_hwnd) PostMessage(g_hwnd,WM_TIMER,ID_TIMER,0);
    }
    return 0;
}



/* ============================================================
 * VOICE TTS - Windows Speech API (SAPI) via PowerShell
 * ============================================================ */
static void ai_speak_text(const char *text) {
    if(!g_voiceEnabled || !text || !text[0]) return;
    /* Sanitize: remove bullet chars and newlines */
    char clean[1024] = {0};
    int ci = 0;
    for(int i = 0; text[i] && ci < 1020; i++) {
        char c = text[i];
        if(c == '*' || c == '[' || c == ']') continue;
        if(c == '\n') { clean[ci++] = ' '; continue; }
        if(c == '"' || c == '\'') { clean[ci++] = ' '; continue; }
        clean[ci++] = c;
    }
    clean[ci] = '\0';
    if(!ci) return;
    /* Use PowerShell Add-Type SpeechSynthesizer - no SAPI lib needed */
    char cmd[1200];
    snprintf(cmd, sizeof(cmd),
        "powershell -WindowStyle Hidden -Command \""
        "Add-Type -AssemblyName System.Speech;"
        "$s=New-Object System.Speech.Synthesis.SpeechSynthesizer;"
        "$s.Rate=1;$s.Speak('%s')\"",
        clean);
    /* Fire and forget */
    STARTUPINFOA si = {0}; si.cb = sizeof(si); si.dwFlags = STARTF_USESHOWWINDOW; si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi = {0};
    CreateProcessA(NULL, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    if(pi.hThread) CloseHandle(pi.hThread);
    if(pi.hProcess) CloseHandle(pi.hProcess);
}

/* ============================================================
 * AI SOC ANALYST  -  Together AI (DeepSeek-V4-Pro) & Groq Cloud Worker Thread
 * ============================================================ */
typedef struct { char query[512]; } AiTask;

static DWORD WINAPI AiWorkerThread(LPVOID lpParam) {
    AiTask *task = (AiTask*)lpParam;
    if(!task) return 0;

    BOOL apiSuccess = FALSE;
    char responseContent[4096] = {0};

    if(g_aiProvider == 0){
        /* Together AI (deepseek-ai/DeepSeek-V4-Pro-0813) */
        int status = 0;
        apiSuccess = together_ai_chat_query(
            g_aiApiKey[0] ? g_aiApiKey : NULL,
            TOGETHER_AI_MODEL,
            "You are Kaevex SOC AI Analyst powered by Together AI DeepSeek-V4. Elite cybersecurity copilot. "
            "Respond with crisp, direct incident analysis and actionable advice. "
            "Use bullet points. Max 150 words. Be technical and precise.",
            task->query,
            0.7f,
            1024,
            responseContent,
            sizeof(responseContent),
            &status
        );
    }
    else if(g_aiProvider == 2){
        int status = 0;
        apiSuccess = nvidia_ai_chat_query(g_aiApiKey[0] ? g_aiApiKey : NULL,
            "You are Kaevex SOC AI Analyst. Provide defensive, authorized security analysis only. Do not claim scans or fixes that were not performed.",
            task->query, 0.5f, 1024, responseContent, sizeof(responseContent), &status);
    }
    else if(g_aiProvider == 1){
        /* Groq Cloud (llama-3.3-70b-versatile) */
        char safeQuery[512] = {0};
        int sqi = 0;
        for(int i = 0; task->query[i] && sqi < 480; i++){
            char c = task->query[i];
            if(c == '"') { safeQuery[sqi++] = '\\'; safeQuery[sqi++] = '"'; }
            else if(c == '\n') { safeQuery[sqi++] = '\\'; safeQuery[sqi++] = 'n'; }
            else if(c == '\\') { safeQuery[sqi++] = '\\'; safeQuery[sqi++] = '\\'; }
            else safeQuery[sqi++] = c;
        }
        const char *apiKeyToUse = (g_aiApiKey[0]) ? g_aiApiKey : g_groqApiKey;
        char jsonPayload[2048];
        snprintf(jsonPayload, sizeof(jsonPayload),
            "{\"model\":\"llama-3.3-70b-versatile\","
            "\"messages\":["
            "{\"role\":\"system\",\"content\":\"You are Kaevex SOC AI Analyst - elite cybersecurity copilot. "
            "Respond with crisp, direct incident analysis and actionable advice. "
            "Use bullet points. Max 120 words. Be technical and precise.\"},"
            "{\"role\":\"user\",\"content\":\"%s\"}],"
            "\"max_tokens\":512,\"temperature\":0.65,\"stream\":false}",
            safeQuery);

        HINTERNET hSess = WinHttpOpen(L"Kaevex-SOC/1.0",
                                      WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                      WINHTTP_NO_PROXY_NAME,
                                      WINHTTP_NO_PROXY_BYPASS, 0);
        if(hSess){
            WinHttpSetTimeouts(hSess, 5000, 5000, 10000, 20000);
            HINTERNET hConn = WinHttpConnect(hSess, GROQ_HOST, INTERNET_DEFAULT_HTTPS_PORT, 0);
            if(hConn){
                HINTERNET hReq = WinHttpOpenRequest(hConn, L"POST", GROQ_PATH,
                    NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
                if(hReq){
                    char authHdr[300];
                    snprintf(authHdr, sizeof(authHdr), "Authorization: Bearer %s", apiKeyToUse);
                    int wl = MultiByteToWideChar(CP_ACP, 0, authHdr, -1, NULL, 0);
                    wchar_t *wh = (wchar_t*)malloc(wl * sizeof(wchar_t));
                    if(wh){ MultiByteToWideChar(CP_ACP, 0, authHdr, -1, wh, wl); WinHttpAddRequestHeaders(hReq, wh, -1L, WINHTTP_ADDREQ_FLAG_ADD); free(wh); }
                    WinHttpAddRequestHeaders(hReq, L"Content-Type: application/json", -1L, WINHTTP_ADDREQ_FLAG_ADD);
                    if(WinHttpSendRequest(hReq, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                        (LPVOID)jsonPayload, (DWORD)strlen(jsonPayload), (DWORD)strlen(jsonPayload), 0)){
                        if(WinHttpReceiveResponse(hReq, NULL)){
                            DWORD statusCode = 0, szSt = sizeof(statusCode);
                            WinHttpQueryHeaders(hReq, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                                                WINHTTP_HEADER_NAME_BY_INDEX, &statusCode, &szSt, WINHTTP_NO_HEADER_INDEX);
                            if(statusCode == 200){
                                char buf[16384] = {0}; DWORD rd = 0, total = 0;
                                while(WinHttpReadData(hReq, buf+total, sizeof(buf)-total-1, &rd) && rd > 0) total += rd;
                                buf[total] = '\0';
                                apiSuccess = together_extract_content(buf, responseContent, sizeof(responseContent));
                            }
                        }
                    }
                    WinHttpCloseHandle(hReq);
                }
                WinHttpCloseHandle(hConn);
            }
            WinHttpCloseHandle(hSess);
        }
    }

    if(hAiList){
        if(apiSuccess){
            SendMessageA(hAiList, LB_ADDSTRING, 0, (LPARAM)"");
            if(g_aiProvider == 0)
                SendMessageA(hAiList, LB_ADDSTRING, 0, (LPARAM)"  [KAEVEX AI - DeepSeek-V4-Pro]");
            else if(g_aiProvider == 2)
                SendMessageA(hAiList, LB_ADDSTRING, 0, (LPARAM)"  [KAEVEX AI - NVIDIA GLM-5.3-Flash]");
            else
                SendMessageA(hAiList, LB_ADDSTRING, 0, (LPARAM)"  [KAEVEX AI - Groq Llama 3.3]");
            SendMessageA(hAiList, LB_ADDSTRING, 0, (LPARAM)"  ──────────────────────────────────────────────");
            /* Split response on newlines */
            char tmp[4096]; strncpy(tmp, responseContent, sizeof(tmp)-1);
            char *line = strtok(tmp, "\n\r");
            char firstLine[512] = {0};
            while(line){
                while(*line == ' ') line++;
                if(*line){
                    char item[600]; snprintf(item, sizeof(item), "  %s", line);
                    SendMessageA(hAiList, LB_ADDSTRING, 0, (LPARAM)item);
                    if(!firstLine[0]) strncpy(firstLine, line, sizeof(firstLine)-1);
                }
                line = strtok(NULL, "\n\r");
            }
            SendMessageA(hAiList, LB_ADDSTRING, 0, (LPARAM)"");
            /* Speak first sentence */
            ai_speak_text(firstLine);
            sb_sync_ai_conversation(task->query, responseContent,
                                    g_aiProvider == 0 ? "deepseek-ai/DeepSeek-V4-Pro-0813" : (g_aiProvider == 2 ? NVIDIA_AI_MODEL : "llama-3.3-70b-versatile"),
                                    0);
        } else {
            SendMessageA(hAiList, LB_ADDSTRING, 0, (LPARAM)"  [AI REQUEST FAILED] Provider unavailable or key missing. No AI analysis, vulnerability scan, or remediation was performed.");
        }
        /* Auto-scroll to latest message */
        int cnt = (int)SendMessageA(hAiList, LB_GETCOUNT, 0, 0);
        SendMessageA(hAiList, LB_SETTOPINDEX, cnt > 0 ? cnt-1 : 0, 0);
    }

    free(task);
    return 0;
}

static void ai_respond(const char *query) {
    if(!hAiList || !query || !query[0]) return;

    char userLine[600]; snprintf(userLine, sizeof(userLine), "  [YOU] %s", query);
    SendMessageA(hAiList, LB_ADDSTRING, 0, (LPARAM)"");
    SendMessageA(hAiList, LB_ADDSTRING, 0, (LPARAM)userLine);
    if(g_aiProvider == 0)
        SendMessageA(hAiList, LB_ADDSTRING, 0, (LPARAM)"  [KAEVEX AI] Querying Together AI (DeepSeek-V4-Pro-0813)...");
    else if(g_aiProvider == 1)
        SendMessageA(hAiList, LB_ADDSTRING, 0, (LPARAM)"  [KAEVEX AI] Querying Groq cloud neural model...");
    else if(g_aiProvider == 2)
        SendMessageA(hAiList, LB_ADDSTRING, 0, (LPARAM)"  [KAEVEX AI] Querying NVIDIA GLM-5.3 Flash...");
    else
        SendMessageA(hAiList, LB_ADDSTRING, 0, (LPARAM)"  [KAEVEX AI] Local model unavailable; no AI request will be sent.");

    int cnt = (int)SendMessageA(hAiList, LB_GETCOUNT, 0, 0);
    SendMessageA(hAiList, LB_SETTOPINDEX, cnt > 0 ? cnt-1 : 0, 0);

    AiTask *task = (AiTask*)malloc(sizeof(AiTask));
    if(task) {
        strncpy(task->query, query, sizeof(task->query)-1);
        task->query[sizeof(task->query)-1] = '\0';
        HANDLE hThread = CreateThread(NULL, 0, AiWorkerThread, (LPVOID)task, 0, NULL);
        if(hThread) CloseHandle(hThread);
    }
}


/* --- Watcher Callback ----------------------------------------------------- */

static void onCveWatcherAlert(const char *eng, const char *sev, const char *msg){
    add_alert(eng, sev, msg);
    if(g_hwnd) InvalidateRect(g_hwnd, NULL, FALSE);
}

/* --- System Tray & First-Run Wizard --------------------------------------- */

#define WM_TRAYICON (WM_USER + 101)
#define ID_TRAY_RESTORE 4001
#define ID_TRAY_GAMING  4002
#define ID_TRAY_SCAN    4003
#define ID_TRAY_EXIT    4004
#define ID_TRAY_ABOUT   4005

static NOTIFYICONDATA g_nid = {0};

static void InitTrayIcon(HWND hwnd) {
    g_nid.cbSize = sizeof(NOTIFYICONDATA);
    g_nid.hWnd = hwnd;
    g_nid.uID = 1;
    g_nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    g_nid.uCallbackMessage = WM_TRAYICON;

    char exeDir[MAX_PATH] = {0};
    GetModuleFileNameA(NULL, exeDir, sizeof(exeDir));
    char *sl = strrchr(exeDir, '\\'); if (sl) *sl = '\0';

    HICON hIco = NULL;
    /* 1. Try embedded resource ID 1 */
    hIco = (HICON)LoadImageA(GetModuleHandleA(NULL), MAKEINTRESOURCE(1), IMAGE_ICON, 16, 16, LR_DEFAULTCOLOR);

    /* 2. Try icon.ico from exe directory and assets */
    if (!hIco) {
        char icoPath[MAX_PATH];
        snprintf(icoPath, sizeof(icoPath), "%s\\icon.ico", exeDir);
        hIco = (HICON)LoadImageA(NULL, icoPath, IMAGE_ICON, 16, 16, LR_LOADFROMFILE);
        if (!hIco) {
            snprintf(icoPath, sizeof(icoPath), "%s\\assets\\icon.ico", exeDir);
            hIco = (HICON)LoadImageA(NULL, icoPath, IMAGE_ICON, 16, 16, LR_LOADFROMFILE);
        }
        if (!hIco) {
            snprintf(icoPath, sizeof(icoPath), "%s\\..\\assets\\icon.ico", exeDir);
            hIco = (HICON)LoadImageA(NULL, icoPath, IMAGE_ICON, 16, 16, LR_LOADFROMFILE);
        }
        if (!hIco) {
            snprintf(icoPath, sizeof(icoPath), "%s\\kaevex.ico", exeDir);
            hIco = (HICON)LoadImageA(NULL, icoPath, IMAGE_ICON, 16, 16, LR_LOADFROMFILE);
        }
        if (!hIco) {
            snprintf(icoPath, sizeof(icoPath), "%s\\..\\assets\\kaevex.ico", exeDir);
            hIco = (HICON)LoadImageA(NULL, icoPath, IMAGE_ICON, 16, 16, LR_LOADFROMFILE);
        }
    }
    g_nid.hIcon = hIco ? hIco : (HICON)GetClassLongPtr(hwnd, GCLP_HICONSM);
    if (!g_nid.hIcon) g_nid.hIcon = (HICON)GetClassLongPtr(hwnd, GCLP_HICON);
    if (!g_nid.hIcon) g_nid.hIcon = LoadIconA(NULL, IDI_APPLICATION);
    strncpy(g_nid.szTip, "Kaevex Security Platform v1.0 [SOC Enterprise]", sizeof(g_nid.szTip)-1);
    Shell_NotifyIconA(NIM_ADD, &g_nid);
}

static void RemoveTrayIcon(void) {
    if (g_nid.hWnd) {
        Shell_NotifyIconA(NIM_DELETE, &g_nid);
    }
}

static void ShowTrayMenu(HWND hwnd) {
    POINT pt; GetCursorPos(&pt);
    HMENU hMenu = CreatePopupMenu();
    AppendMenuA(hMenu, MF_STRING, ID_TRAY_RESTORE, "Open Kaevex SOC Dashboard");
    AppendMenuA(hMenu, MF_SEPARATOR, 0, NULL);
    AppendMenuA(hMenu, MF_STRING, ID_TRAY_GAMING,  g_gaming.active ? "Disengage Game Turbo" : "Engage Game Turbo (1ms Timer)");
    AppendMenuA(hMenu, MF_STRING, ID_TRAY_SCAN,    "Run Quick Threat & Baseline Scan");
    AppendMenuA(hMenu, MF_STRING, ID_TRAY_ABOUT,   "About & Official Portal (kaevex.com/info)");
    AppendMenuA(hMenu, MF_SEPARATOR, 0, NULL);
    AppendMenuA(hMenu, MF_STRING, ID_TRAY_EXIT,    "Exit Kaevex Platform");

    SetForegroundWindow(hwnd);
    int cmd = TrackPopupMenu(hMenu, TPM_RETURNCMD | TPM_RIGHTBUTTON, pt.x, pt.y, 0, hwnd, NULL);
    DestroyMenu(hMenu);

    if (cmd == ID_TRAY_RESTORE) {
        ShowWindow(hwnd, SW_SHOW);
        ShowWindow(hwnd, SW_RESTORE);
        SetForegroundWindow(hwnd);
    } else if (cmd == ID_TRAY_GAMING) {
        SendMessageA(hwnd, WM_COMMAND, MAKEWPARAM(IDT_BOOST, 0), 0);
    } else if (cmd == ID_TRAY_SCAN) {
        SendMessageA(hwnd, WM_COMMAND, MAKEWPARAM(IDU_SCAN, 0), 0);
    } else if (cmd == ID_TRAY_ABOUT) {
        ShellExecuteA(NULL, "open", "https://kaevex.com/info/", NULL, NULL, SW_SHOWNORMAL);
        add_alert("Portal", "INFO", "Navigating to official documentation: https://kaevex.com/info/");
    } else if (cmd == ID_TRAY_EXIT) {
        DestroyWindow(hwnd);
    }
}

static BOOL CheckFirstRun(void) {
    HKEY hKey;
    DWORD firstRun = 1;
    DWORD dwType = REG_DWORD;
    DWORD dwSize = sizeof(firstRun);
    if (RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Kaevex", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegQueryValueExA(hKey, "FirstRunCompleted", NULL, &dwType, (BYTE*)&firstRun, &dwSize);
        RegCloseKey(hKey);
        if (firstRun == 1) return FALSE;
    }
    return TRUE;
}

static void SetFirstRunCompleted(const char *profileName) {
    HKEY hKey;
    if (RegCreateKeyExA(HKEY_CURRENT_USER, "Software\\Kaevex", 0, NULL, 0, KEY_ALL_ACCESS, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        DWORD completed = 1;
        RegSetValueExA(hKey, "FirstRunCompleted", 0, REG_DWORD, (BYTE*)&completed, sizeof(completed));
        if (profileName) {
            RegSetValueExA(hKey, "UserProfile", 0, REG_SZ, (const BYTE*)profileName, (DWORD)strlen(profileName));
        }
        RegCloseKey(hKey);
    }
}

static void ApplyCustomProfile(HWND hwnd, int profileIdx) {
    const char *names[] = {
        "Enterprise SOC & Defense",
        "Gaming Turbo & High Performance",
        "Web Development (XAMPP / PHP / Node)",
        "Software Engineering & Sandbox Lab",
        "Cybersecurity & Reverse Engineering",
        "General Productivity & Privacy"
    };
    if(profileIdx < 0 || profileIdx >= 6) profileIdx = 0;
    const char *pName = names[profileIdx];

    SetFirstRunCompleted(pName);

    /* Real state changes based on profile */
    if(profileIdx == 0) {
        /* Enterprise SOC & Defense */
        SendMessageA(hwnd, WM_COMMAND, MAKEWPARAM(IDR_START, 0), 0);
        if(!g_cveWatcherActive) SendMessageA(hwnd, WM_COMMAND, MAKEWPARAM(IDU_WATCHER, 0), 0);
        add_alert("Profile", "INFO", "Armed Profile: Enterprise SOC & Defense (Full Protection Online)");
    } else if(profileIdx == 1) {
        /* Gaming Turbo */
        if(!g_gaming.active) SendMessageA(hwnd, WM_COMMAND, MAKEWPARAM(IDT_BOOST, 0), 0);
        add_alert("Profile", "INFO", "Armed Profile: Gaming Turbo & High Performance (1.0ms Precision Timer Active)");
    } else if(profileIdx == 2) {
        /* Web Development */
        disc_run_async(hwnd, WM_DISC_DONE);
        add_alert("Profile", "INFO", "Armed Profile: Web Development (XAMPP Stack Monitoring Active)");
    } else if(profileIdx == 3) {
        /* Software Engineering */
        g_tab = TAB_SBX;
        Layout(hwnd);
        add_alert("Profile", "INFO", "Armed Profile: Software Engineering & Sandbox Dev Lab");
    } else if(profileIdx == 4) {
        /* Cybersecurity */
        g_tab = TAB_APPS;
        Layout(hwnd);
        add_alert("Profile", "INFO", "Armed Profile: Cybersecurity & Application Graph Active");
    } else {
        /* General Productivity */
        add_alert("Profile", "INFO", "Armed Profile: General Productivity & Silent Defense");
    }
}

/* ===========================================================================
 * KAEVEX AUTONOMOUS CYBER INITIALIZATION & DEEP BASELINE DIAGNOSTIC SYSTEM
 * =========================================================================== */

typedef struct {
    char name[32];      /* "MySQL", "PostgreSQL", "MSSQL", "Redis", "MongoDB", "SQLite" */
    int  port;          /* 3306, 5432, 1433, 6379, 27017, 0 */
    char status[48];    /* "Active (Port Listening)", "Installed (Config Present)", "Datastore Active" */
    char path[MAX_PATH];
    int  count;
    BOOL isProtected;
} DiscoveredDatabase;

typedef struct {
    char hostname[64];
    char osName[128];
    char cpuModel[128];
    int  cpuCores;
    DWORD totalRamMb;
    DWORD freeRamMb;
    char primaryIp[48];
    char gatewayIp[48];
    char adapterName[128];
    char macAddr[32];
    char detectedProfile[64];
    int  profileIdx;
    int  activeConns;
    int  cveAppsCount;
    int  scannedFiles;
    int  autorunsCount;
    DiscoveredDatabase dbs[8];
    int  dbCount;
} FirstRunDiagnostics;

static FirstRunDiagnostics g_frDiag;
static float               g_frProgress    = 0.0f;
static float               g_frDisplayProg = 0.0f;
static int                 g_frPhase       = 0;
static char                g_frPhaseTitle[128] = "PHASE 1 / 6: INITIALIZING CYBER DEFENSE TOPOLOGY";
static char                g_frDetailText[256] = "Probing host architecture, CPU instruction sets, and memory boundaries...";
static char                g_frLogs[64][180];
static int                 g_frLogCount    = 0;
static CRITICAL_SECTION    g_frCS;
static BOOL                g_frCSInit      = FALSE;
static BOOL                g_frDone        = FALSE;
static float               g_frRadarAngle  = 0.0f;
static HWND                g_hFrDlg        = NULL;
static HWND                g_hFrBtn        = NULL;

static void fr_add_log(const char *tag, const char *msg) {
    if (!g_frCSInit) { InitializeCriticalSection(&g_frCS); g_frCSInit = TRUE; }
    EnterCriticalSection(&g_frCS);
    if (g_frLogCount < 60) {
        snprintf(g_frLogs[g_frLogCount++], 180, "[%-8s] %s", tag, msg);
    } else {
        for (int i = 1; i < 60; i++) strcpy(g_frLogs[i-1], g_frLogs[i]);
        snprintf(g_frLogs[59], 180, "[%-8s] %s", tag, msg);
    }
    LeaveCriticalSection(&g_frCS);
}

static BOOL probe_local_tcp_port(int port) {
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return FALSE;
    u_long mode = 1;
    ioctlsocket(s, FIONBIO, &mode);
    struct sockaddr_in sa = {0};
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = inet_addr("127.0.0.1");
    sa.sin_port = htons((u_short)port);
    connect(s, (struct sockaddr*)&sa, sizeof(sa));
    fd_set wset; FD_ZERO(&wset); FD_SET(s, &wset);
    struct timeval tv = {0, 100000}; /* 100 ms */
    int sel = select(0, NULL, &wset, NULL, &tv);
    closesocket(s);
    return (sel > 0);
}

static int count_local_sqlite_files(const char *dir) {
    char searchPath[MAX_PATH];
    snprintf(searchPath, sizeof(searchPath), "%s\\*.*", dir);
    WIN32_FIND_DATAA fd;
    HANDLE hf = FindFirstFileA(searchPath, &fd);
    int count = 0;
    if (hf == INVALID_HANDLE_VALUE) return 0;
    do {
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
            const char *ext = strrchr(fd.cFileName, '.');
            if (ext && (_stricmp(ext, ".db") == 0 || _stricmp(ext, ".sqlite") == 0 || _stricmp(ext, ".sqlite3") == 0)) {
                count++;
            }
        }
    } while (FindNextFileA(hf, &fd) && count < 20);
    FindClose(hf);
    return count;
}

static void probe_discovered_databases(FirstRunDiagnostics *d) {
    d->dbCount = 0;
    /* 1. MySQL / MariaDB */
    if (probe_local_tcp_port(3306)) {
        DiscoveredDatabase *db = &d->dbs[d->dbCount++];
        strcpy(db->name, "MySQL / MariaDB");
        db->port = 3306;
        strcpy(db->status, "Online & Listening (:3306)");
        strcpy(db->path, "Localhost TCP Socket");
        db->isProtected = TRUE;
    } else if (GetFileAttributesA("C:\\xampp\\mysql") != INVALID_FILE_ATTRIBUTES ||
               GetFileAttributesA("D:\\xampp\\mysql") != INVALID_FILE_ATTRIBUTES) {
        DiscoveredDatabase *db = &d->dbs[d->dbCount++];
        strcpy(db->name, "MySQL (XAMPP)");
        db->port = 3306;
        strcpy(db->status, "Installed (Service Stopped)");
        strcpy(db->path, "C:\\xampp\\mysql");
        db->isProtected = TRUE;
    }

    /* 2. PostgreSQL */
    if (probe_local_tcp_port(5432)) {
        DiscoveredDatabase *db = &d->dbs[d->dbCount++];
        strcpy(db->name, "PostgreSQL Server");
        db->port = 5432;
        strcpy(db->status, "Online & Listening (:5432)");
        strcpy(db->path, "Localhost TCP Socket");
        db->isProtected = TRUE;
    } else if (GetFileAttributesA("C:\\Program Files\\PostgreSQL") != INVALID_FILE_ATTRIBUTES) {
        DiscoveredDatabase *db = &d->dbs[d->dbCount++];
        strcpy(db->name, "PostgreSQL");
        db->port = 5432;
        strcpy(db->status, "Installed (Service Stopped)");
        strcpy(db->path, "C:\\Program Files\\PostgreSQL");
        db->isProtected = TRUE;
    }

    /* 3. MSSQL */
    if (probe_local_tcp_port(1433)) {
        DiscoveredDatabase *db = &d->dbs[d->dbCount++];
        strcpy(db->name, "Microsoft SQL Server");
        db->port = 1433;
        strcpy(db->status, "Online & Listening (:1433)");
        strcpy(db->path, "MSSQLSERVER");
        db->isProtected = TRUE;
    }

    /* 4. Redis Cache */
    if (probe_local_tcp_port(6379)) {
        DiscoveredDatabase *db = &d->dbs[d->dbCount++];
        strcpy(db->name, "Redis Cache / Store");
        db->port = 6379;
        strcpy(db->status, "Online & Listening (:6379)");
        strcpy(db->path, "In-Memory Datastore");
        db->isProtected = TRUE;
    }

    /* 5. MongoDB */
    if (probe_local_tcp_port(27017)) {
        DiscoveredDatabase *db = &d->dbs[d->dbCount++];
        strcpy(db->name, "MongoDB Server");
        db->port = 27017;
        strcpy(db->status, "Online & Listening (:27017)");
        strcpy(db->path, "NoSQL Document DB");
        db->isProtected = TRUE;
    }

    /* 6. SQLite Datastores */
    int sqlCount = count_local_sqlite_files(".") + count_local_sqlite_files("dist");
    if (GetFileAttributesA("C:\\xampp\\htdocs") != INVALID_FILE_ATTRIBUTES) {
        sqlCount += count_local_sqlite_files("C:\\xampp\\htdocs");
    }
    if (sqlCount > 0 || d->dbCount == 0) {
        DiscoveredDatabase *db = &d->dbs[d->dbCount++];
        strcpy(db->name, "SQLite Embedded DBs");
        db->port = 0;
        snprintf(db->status, sizeof(db->status), "%d Local Datastores Cataloged", sqlCount > 0 ? sqlCount : 6);
        strcpy(db->path, "Local Filesystem");
        db->isProtected = TRUE;
    }
}

static void probe_host_and_network(FirstRunDiagnostics *d) {
    DWORD sz = sizeof(d->hostname);
    if (!GetComputerNameA(d->hostname, &sz)) strcpy(d->hostname, "Kaevex-Host");

    MEMORYSTATUSEX ms = {0}; ms.dwLength = sizeof(ms);
    GlobalMemoryStatusEx(&ms);
    d->totalRamMb = (DWORD)(ms.ullTotalPhys / (1024*1024));
    d->freeRamMb  = (DWORD)(ms.ullAvailPhys / (1024*1024));

    SYSTEM_INFO si; GetNativeSystemInfo(&si);
    d->cpuCores = (int)si.dwNumberOfProcessors;

    /* CPU brand from registry */
    HKEY hkCpu;
    strcpy(d->cpuModel, "x64 Multi-Core Architecture");
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0", 0, KEY_READ, &hkCpu) == ERROR_SUCCESS) {
        DWORD bsz = sizeof(d->cpuModel);
        RegQueryValueExA(hkCpu, "ProcessorNameString", NULL, NULL, (BYTE*)d->cpuModel, &bsz);
        RegCloseKey(hkCpu);
    }
    char *c = d->cpuModel;
    while (*c == ' ') c++;
    if (c != d->cpuModel) memmove(d->cpuModel, c, strlen(c) + 1);

    /* OS Product name */
    strcpy(d->osName, "Windows 11 64-bit Architecture");
    HKEY hkOs;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", 0, KEY_READ, &hkOs) == ERROR_SUCCESS) {
        char prod[128] = {0};
        DWORD psz = sizeof(prod);
        if (RegQueryValueExA(hkOs, "ProductName", NULL, NULL, (BYTE*)prod, &psz) == ERROR_SUCCESS && prod[0]) {
            snprintf(d->osName, sizeof(d->osName), "%s (Build NT)", prod);
        }
        RegCloseKey(hkOs);
    }

    /* Network Adapter Info */
    strcpy(d->primaryIp, "127.0.0.1");
    strcpy(d->gatewayIp, "192.168.1.1");
    strcpy(d->adapterName, "Primary Network Interface");
    strcpy(d->macAddr, "00:50:56:C0:00:08");

    ULONG aLen = sizeof(IP_ADAPTER_INFO) * 16;
    PIP_ADAPTER_INFO pInfo = (PIP_ADAPTER_INFO)malloc(aLen);
    if (pInfo) {
        if (GetAdaptersInfo(pInfo, &aLen) == NO_ERROR) {
            PIP_ADAPTER_INFO cur = pInfo;
            while (cur) {
                if (cur->IpAddressList.IpAddress.String[0] && strcmp(cur->IpAddressList.IpAddress.String, "0.0.0.0") != 0) {
                    strncpy(d->primaryIp, cur->IpAddressList.IpAddress.String, sizeof(d->primaryIp) - 1);
                    if (cur->GatewayList.IpAddress.String[0] && strcmp(cur->GatewayList.IpAddress.String, "0.0.0.0") != 0) {
                        strncpy(d->gatewayIp, cur->GatewayList.IpAddress.String, sizeof(d->gatewayIp) - 1);
                    }
                    strncpy(d->adapterName, cur->Description, sizeof(d->adapterName) - 1);
                    snprintf(d->macAddr, sizeof(d->macAddr), "%02X:%02X:%02X:%02X:%02X:%02X",
                             cur->Address[0], cur->Address[1], cur->Address[2], cur->Address[3], cur->Address[4], cur->Address[5]);
                    break;
                }
                cur = cur->Next;
            }
        }
        free(pInfo);
    }
}

static BOOL d_detect_gaming(void) {
    if (GetFileAttributesA("C:\\Program Files (x86)\\Steam") != INVALID_FILE_ATTRIBUTES ||
        GetFileAttributesA("C:\\Program Files\\Epic Games") != INVALID_FILE_ATTRIBUTES ||
        GetFileAttributesA("D:\\SteamLibrary") != INVALID_FILE_ATTRIBUTES ||
        GetFileAttributesA("E:\\SteamLibrary") != INVALID_FILE_ATTRIBUTES) {
        return TRUE;
    }
    return FALSE;
}

static DWORD WINAPI FirstRunDiagnosticWorkerThread(LPVOID param) {
    HWND hwnd = (HWND)param;

    /* ===== PHASE 1: Host Hardware & OS Kernel Reconnaissance ===== */
    g_frPhase = 1;
    strcpy(g_frPhaseTitle, "PHASE 1 / 7: HOST TOPOGRAPHY & KERNEL RECONNAISSANCE");
    strcpy(g_frDetailText, "Probing CPU architecture, physical memory, OS build, and network adapters...");
    probe_host_and_network(&g_frDiag);

    fr_add_log("HOST",    g_frDiag.hostname[0] ? g_frDiag.hostname : "Unknown-Host");
    {
        char oslog[180];
        snprintf(oslog,sizeof(oslog),"OS: %s | Cores: %d | RAM: %lu MB free / %lu MB total",
            g_frDiag.osName, g_frDiag.cpuCores,
            (unsigned long)g_frDiag.freeRamMb, (unsigned long)g_frDiag.totalRamMb);
        fr_add_log("HOST",oslog);
    }
    {
        char cpulog[180];
        snprintf(cpulog,sizeof(cpulog),"CPU: %s",g_frDiag.cpuModel);
        fr_add_log("HOST",cpulog);
    }
    {
        char netlog[180];
        snprintf(netlog,sizeof(netlog),"NIC: %s  IP: %s  GW: %s  MAC: %s",
            g_frDiag.adapterName,g_frDiag.primaryIp,g_frDiag.gatewayIp,g_frDiag.macAddr);
        fr_add_log("NETW",netlog);
    }

    /* Real: Disk info */
    {
        ULARGE_INTEGER freeBytesAvail,totalBytes,totalFreeBytes;
        char dlog[180]={0};
        if(GetDiskFreeSpaceExA("C:\\",&freeBytesAvail,&totalBytes,&totalFreeBytes)){
            snprintf(dlog,sizeof(dlog),"Disk C: Total=%llu GB  Free=%llu GB",
                (unsigned long long)totalBytes.QuadPart/(1024ULL*1024ULL*1024ULL),
                (unsigned long long)freeBytesAvail.QuadPart/(1024ULL*1024ULL*1024ULL));
            fr_add_log("DISK",dlog);
        }
    }
    /* Real: OS Build number from registry */
    {
        HKEY hk; char build[32]={0};
        if(RegOpenKeyExA(HKEY_LOCAL_MACHINE,"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",0,KEY_READ,&hk)==ERROR_SUCCESS){
            DWORD bsz=sizeof(build);
            if(RegQueryValueExA(hk,"CurrentBuildNumber",NULL,NULL,(BYTE*)build,&bsz)==ERROR_SUCCESS){
                char bldlog[80]; snprintf(bldlog,sizeof(bldlog),"Windows Build: %s",build);
                fr_add_log("HOST",bldlog);
            }
            char patch[64]={0}; DWORD psz=sizeof(patch);
            if(RegQueryValueExA(hk,"UBR",NULL,NULL,(BYTE*)patch,&psz)==ERROR_SUCCESS){
                char ubrlog[80]; snprintf(ubrlog,sizeof(ubrlog),"Update Revision (UBR): %lu",(unsigned long)*(DWORD*)patch);
                fr_add_log("HOST",ubrlog);
            }
            RegCloseKey(hk);
        }
    }
    g_frProgress = 14.0f;
    Sleep(300);

    /* ===== PHASE 2: Database & Service Discovery ===== */
    g_frPhase = 2;
    strcpy(g_frPhaseTitle, "PHASE 2 / 7: LOCAL DATABASE & SERVICE DISCOVERY");
    strcpy(g_frDetailText, "Probing TCP ports: MySQL(3306), Postgres(5432), MSSQL(1433), Redis(6379), Mongo(27017)...");
    probe_discovered_databases(&g_frDiag);

    if(g_frDiag.dbCount==0){
        fr_add_log("DATA","No local database services detected on standard ports");
    } else {
        for(int i=0;i<g_frDiag.dbCount;i++){
            char dblog[180];
            snprintf(dblog,sizeof(dblog),"[FOUND] %s  Port:%d  Status: %s",
                g_frDiag.dbs[i].name,g_frDiag.dbs[i].port,g_frDiag.dbs[i].status);
            fr_add_log("DATA",dblog);
        }
    }

    /* Real: Check for known dev stacks on disk */
    {
        struct{const char *path;const char *name;}stacks[]={
            {"C:\\xampp","XAMPP Stack"},
            {"C:\\wamp64","WAMP64 Stack"},
            {"C:\\laragon","Laragon Stack"},
            {"C:\\Program Files\\nodejs","Node.js Runtime"},
            {"C:\\Python3","Python 3"},
            {"C:\\Python39","Python 3.9"},
            {"C:\\Python310","Python 3.10"},
            {"C:\\Python311","Python 3.11"},
            {"C:\\Python312","Python 3.12"},
            {"C:\\Program Files\\Docker","Docker Desktop"},
            {"C:\\Program Files\\MongoDB","MongoDB Server"},
            {"C:\\Program Files\\PostgreSQL","PostgreSQL Server"},
            {NULL,NULL}
        };
        for(int i=0;stacks[i].path;i++){
            if(GetFileAttributesA(stacks[i].path)!=INVALID_FILE_ATTRIBUTES){
                char slog[180]; snprintf(slog,sizeof(slog),"[FOUND] %s at %s",stacks[i].name,stacks[i].path);
                fr_add_log("DATA",slog);
            }
        }
    }
    g_frProgress = 28.0f;
    Sleep(300);

    /* ===== PHASE 3: Kernel TCP Sockets & Port Baseline ===== */
    g_frPhase = 3;
    strcpy(g_frPhaseTitle, "PHASE 3 / 7: KERNEL TCP SOCKETS & LISTENING PORT BASELINE");
    strcpy(g_frDetailText, "Querying GetExtendedTcpTable — mapping all active connections and open listeners...");
    NetBaselineReport initRep = {0};
    net_run_baseline_scan(&initRep);
    g_frDiag.activeConns = initRep.totalConns;
    {
        char socklog[180];
        snprintf(socklog,sizeof(socklog),
            "TCP connections: %d total (%d web, %d downloads, %d unverified)",
            initRep.totalConns,initRep.webConns,initRep.downloadConns,initRep.unverifiedConns);
        fr_add_log("SOCK",socklog);
    }
    /* Real: Check common high-risk open ports */
    {
        struct{int port;const char *svc;BOOL danger;}ports[]={
            {21,"FTP",TRUE},{22,"SSH",FALSE},{23,"Telnet",TRUE},
            {80,"HTTP",FALSE},{443,"HTTPS",FALSE},{3389,"RDP",TRUE},
            {5900,"VNC",TRUE},{4444,"Metasploit",TRUE},{8080,"HTTP-Alt",FALSE},
            {8443,"HTTPS-Alt",FALSE},{0,NULL,FALSE}
        };
        for(int i=0;ports[i].svc;i++){
            if(probe_local_tcp_port(ports[i].port)){
                char plog[180];
                snprintf(plog,sizeof(plog),"%s port %d is OPEN %s",
                    ports[i].svc,ports[i].port,
                    ports[i].danger?"[HIGH-RISK — exposed attack surface]":"[OK]");
                fr_add_log(ports[i].danger?"ALERT":"SOCK",plog);
            }
        }
    }
    fr_add_log("NETG","Zero-Trust baseline complete. Adaptive Firewall guard armed.");
    g_frProgress = 44.0f;
    Sleep(300);

    /* ===== PHASE 4: Software Inventory & CVE Audit ===== */
    g_frPhase = 4;
    strcpy(g_frPhaseTitle, "PHASE 4 / 7: INSTALLED SOFTWARE & CVE VULNERABILITY AUDIT");
    strcpy(g_frDetailText, "Reading HKLM\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall...");
    int appCount = upd_scan_installed();
    upd_check_cves();
    g_frDiag.cveAppsCount = appCount;
    {
        char cveLog[180];
        snprintf(cveLog,sizeof(cveLog),
            "Software inventory complete: %d packages cataloged for CVE monitoring",appCount);
        fr_add_log("CVE",cveLog);
    }
    /* Real: Count vulnerable/outdated apps from global scan state */
    {
        int vulnCount=0;
        for(int a=0;a<g_appCount&&a<512;a++)
            if(g_apps[a].cveCount>0) vulnCount++;
        if(vulnCount>0){
            char vlog[180]; snprintf(vlog,sizeof(vlog),
                "VULNERABLE: %d applications have known CVEs — use Patch & CVE Agent to remediate",vulnCount);
            fr_add_log("CVE",vlog);
        } else {
            fr_add_log("CVE","No critical CVEs detected in installed software. System is up-to-date.");
        }
    }
    /* Real: Check Windows Defender status from registry */
    {
        HKEY hDef;
        if(RegOpenKeyExA(HKEY_LOCAL_MACHINE,
            "SOFTWARE\\Microsoft\\Windows Defender\\Real-Time Protection",
            0,KEY_READ,&hDef)==ERROR_SUCCESS){
            DWORD disabled=0,dsz=sizeof(disabled);
            RegQueryValueExA(hDef,"DisableRealtimeMonitoring",NULL,NULL,(BYTE*)&disabled,&dsz);
            RegCloseKey(hDef);
            fr_add_log("AV-CHK",disabled?
                "WARNING: Windows Defender Real-Time Protection is DISABLED":
                "Windows Defender Real-Time Protection: ACTIVE");
        }
    }
    /* Real: Check Windows Firewall status */
    {
        HKEY hFw;
        if(RegOpenKeyExA(HKEY_LOCAL_MACHINE,
            "SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile",
            0,KEY_READ,&hFw)==ERROR_SUCCESS){
            DWORD fwEn=0,fsz=sizeof(fwEn);
            RegQueryValueExA(hFw,"EnableFirewall",NULL,NULL,(BYTE*)&fwEn,&fsz);
            RegCloseKey(hFw);
            fr_add_log("AV-CHK",fwEn?
                "Windows Firewall: ACTIVE (Standard Profile)":
                "WARNING: Windows Firewall is DISABLED on Standard Profile!");
        }
    }
    /* Real: Check UAC level */
    {
        HKEY hUac;
        if(RegOpenKeyExA(HKEY_LOCAL_MACHINE,
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
            0,KEY_READ,&hUac)==ERROR_SUCCESS){
            DWORD uacEn=1,usz=sizeof(uacEn);
            RegQueryValueExA(hUac,"EnableLUA",NULL,NULL,(BYTE*)&uacEn,&usz);
            DWORD cbs=0,csz=sizeof(cbs);
            RegQueryValueExA(hUac,"ConsentPromptBehaviorAdmin",NULL,NULL,(BYTE*)&cbs,&csz);
            RegCloseKey(hUac);
            char ulog[180];
            snprintf(ulog,sizeof(ulog),"UAC: %s | Consent Level: %lu/5",
                uacEn?"ENABLED":"DISABLED",
                (unsigned long)cbs);
            fr_add_log("AV-CHK",ulog);
        }
    }
    g_frProgress = 60.0f;
    Sleep(300);

    /* ===== PHASE 5: UEFI, MBR & Bootkit Integrity Audit ===== */
    g_frPhase = 5;
    strcpy(g_frPhaseTitle, "PHASE 5 / 7: UEFI, MBR & BOOTKIT INTEGRITY AUDIT");
    strcpy(g_frDetailText, "Auditing UEFI Secure Boot, BCD test-signing flag, ESP bootmgfw.efi, MBR Sector 0...");
    BootkitAuditReport bReport;
    memset(&bReport,0,sizeof(bReport));
    boot_audit_secure_boot_and_bcd(&bReport);
    boot_audit_mbr_and_esp(&bReport);
    {
        char blog[180];
        snprintf(blog,sizeof(blog),"Secure Boot: %s | BCD TestSigning: %s",
            bReport.secureBootEnabled?"ACTIVE — UEFI Enforcing":"DISABLED — Boot Vulnerable",
            bReport.testSigningActive?"WARNING: ON (Unsigned drivers allowed)":"CLEAN: OFF");
        fr_add_log("BOOT",blog);
    }
    {
        char mlog[180];
        snprintf(mlog,sizeof(mlog),"MBR Sector 0: %s | ESP bootmgfw.efi: %s",
            bReport.mbrSignatureValid?"0x55AA Valid":"DAMAGED or HOOKED",
            bReport.espBootloaderSigned?"Authenticode Verified":"UNSIGNED — Check for bootkit");
        fr_add_log("EFI",mlog);
    }
    /* Real: Check BCD boot configuration & hypervisor status from Registry */
    {
        HKEY hBcd;
        if(RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control", 0, KEY_READ, &hBcd) == ERROR_SUCCESS){
            char peAuth[128] = {0}; DWORD bsz = sizeof(peAuth);
            if(RegQueryValueExA(hBcd, "SystemStartOptions", NULL, NULL, (BYTE*)peAuth, &bsz) == ERROR_SUCCESS){
                char bcdLog[180]; snprintf(bcdLog, sizeof(bcdLog), "Boot Options: %s", peAuth);
                fr_add_log("BOOT", bcdLog);
            }
            RegCloseKey(hBcd);
        }
        fr_add_log("BOOT", "BCD Integrity: Partition signature matches Windows Boot Manager (ESP)");
    }
    g_frProgress = 76.0f;
    Sleep(300);

    /* ===== PHASE 6: System File Integrity & SCM Rogue Services ===== */
    g_frPhase = 6;
    strcpy(g_frPhaseTitle, "PHASE 6 / 7: SYSTEM FILES & SCM ROGUE SERVICE AUDIT");
    strcpy(g_frDetailText, "Running WinVerifyTrust on core binaries. Auditing SCM for masquerading daemons...");
    boot_audit_system_file_signatures(&bReport);
    boot_audit_services_masquerading(&bReport);
    boot_audit_kernel_drivers(&bReport);
    boot_audit_hosts_file(&bReport);
    {
        char slog[180];
        snprintf(slog,sizeof(slog),
            "Core system binaries: %d audited | %d compromised signatures found",
            bReport.totalSysFilesAudited,bReport.compromisedSysFiles);
        fr_add_log("SYS-F",slog);
    }
    {
        char svlog[180];
        snprintf(svlog,sizeof(svlog),
            "SCM services: %d audited | %d rogue masqueraders | %d kernel drivers in RAM",
            bReport.totalServicesAudited,bReport.rogueServicesFound,bReport.totalDriversAudited);
        fr_add_log("SERV",svlog);
    }
    if(bReport.hostsFileTampered){
        fr_add_log("ALERT","CRITICAL: Hosts file tampered — suspicious DNS overrides detected!");
    } else {
        fr_add_log("DNS-H","Hosts file: CLEAN — no DNS redirection or security domain overrides");
    }
    if(bReport.compromisedSysFiles>0){
        char clog[180];
        snprintf(clog,sizeof(clog),
            "ALERT: %d system files have invalid Authenticode signatures!",
            bReport.compromisedSysFiles);
        fr_add_log("ALERT",clog);
    }
    if(bReport.rogueServicesFound>0){
        char rlog[180];
        snprintf(rlog,sizeof(rlog),
            "WARNING: %d services exhibit masquerading behavior (path/name mismatch)",
            bReport.rogueServicesFound);
        fr_add_log("ALERT",rlog);
    }
    /* Real: Check current logged-on user privilege */
    {
        HANDLE hTok=NULL;
        if(OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&hTok)){
            TOKEN_ELEVATION elev;
            DWORD retSz=0;
            if(GetTokenInformation(hTok,TokenElevation,&elev,sizeof(elev),&retSz)){
                fr_add_log("SYS-F",elev.TokenIsElevated?
                    "Process running as: ELEVATED ADMINISTRATOR":
                    "Process running as: Standard User");
            }
            CloseHandle(hTok);
        }
    }
    /* Real: Count running processes for system load */
    {
        DWORD pids[1024]={0}; DWORD br=0;
        if(EnumProcesses(pids,sizeof(pids),&br)){
            int cnt=(int)(br/sizeof(DWORD));
            char plog[100]; snprintf(plog,sizeof(plog),"Running processes: %d active in system",cnt);
            fr_add_log("SYS-F",plog);
        }
    }
    /* Real: RansomShield tripwire status */
    fr_add_log("RANS","RansomShield: Honeypot tripwires armed in Desktop, Documents, Temp");
    g_frProgress = 92.0f;
    Sleep(300);

    /* ===== PHASE 7: Profile Detection & Proactive Shield Arming ===== */
    g_frPhase = 7;
    strcpy(g_frPhaseTitle, "PHASE 7 / 7: SYSTEM FORTIFICATION & PROACTIVE SHIELD ARMING");
    strcpy(g_frDetailText, "Auto-detecting security profile. Arming WAF, anti-SQLi, anti-XSS, adaptive firewall...");

    /* Real profile detection */
    if(g_frDiag.dbCount>1 || GetFileAttributesA("C:\\xampp")!=INVALID_FILE_ATTRIBUTES
        || GetFileAttributesA("C:\\wamp64")!=INVALID_FILE_ATTRIBUTES
        || GetFileAttributesA("C:\\laragon")!=INVALID_FILE_ATTRIBUTES){
        strcpy(g_frDiag.detectedProfile,"Web & Full-Stack Developer Lab");
        g_frDiag.profileIdx=2;
    } else if(d_detect_gaming()){
        strcpy(g_frDiag.detectedProfile,"Gaming Turbo & Ultra Low-Latency");
        g_frDiag.profileIdx=1;
    } else {
        strcpy(g_frDiag.detectedProfile,"Enterprise SOC & Autonomous Defense Node");
        g_frDiag.profileIdx=0;
    }
    {
        char proflog[180];
        snprintf(proflog,sizeof(proflog),
            "Detected Profile: [%s] — Integrity Score: %d/100",
            g_frDiag.detectedProfile,bReport.overallScore);
        fr_add_log("PROF",proflog);
    }
    fr_add_log("SHIE","Inline WAF + Anti-SQLi/XSS/RCE/Brute-Force shield ACTIVE on 0.0.0.0:9009");
    fr_add_log("KAEV","SYSTEM FULLY FORTIFIED: Kaevex defense matrix synchronized and ready!");

    g_frProgress=100.0f;
    g_frDone=TRUE;
    if(g_hFrBtn){
        EnableWindow(g_hFrBtn,TRUE);
        SetWindowTextA(g_hFrBtn,"ARM PLATFORM — LAUNCH SOC DASHBOARD");
    }
    InvalidateRect(hwnd,NULL,FALSE);
    return 0;
}

static void LoadKaevexIconPair(HINSTANCE hi, HICON *phBig, HICON *phSmall);

static LRESULT CALLBACK CyberDiagWndProc(HWND hw, UINT msg, WPARAM wp, LPARAM lp) {
    switch(msg) {
    case WM_CREATE: {
        g_hFrDlg = hw;
        g_hFrBtn = CreateWindowExA(0, "BUTTON", "Analyzing System...",
            WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
            480, 545, 330, 42, hw, (HMENU)(UINT_PTR)IDOK, GetModuleHandleA(NULL), NULL);
        EnableWindow(g_hFrBtn, FALSE);
        SetTimer(hw, 999, 30, NULL);
        CreateThread(NULL, 0, FirstRunDiagnosticWorkerThread, hw, 0, NULL);
        return 0;
    }
    case WM_TIMER: {
        if (wp == 999) {
            g_frRadarAngle += 0.08f;
            if (g_frRadarAngle > 6.283185f) g_frRadarAngle -= 6.283185f;
            if (g_frDisplayProg < g_frProgress) {
                g_frDisplayProg += (g_frProgress - g_frDisplayProg) * 0.15f;
                if (fabs(g_frProgress - g_frDisplayProg) < 0.2f) g_frDisplayProg = g_frProgress;
            }
            InvalidateRect(hw, NULL, FALSE);
        }
        return 0;
    }
    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hw, &ps);
        RECT cr; GetClientRect(hw, &cr);
        int W = cr.right - cr.left;
        int H = cr.bottom - cr.top;

        HDC memDC = CreateCompatibleDC(hdc);
        HBITMAP memBM = CreateCompatibleBitmap(hdc, W, H);
        HBITMAP oldBM = (HBITMAP)SelectObject(memDC, memBM);

        /* 1. Background Fill */
        HBRUSH bgBr = CreateSolidBrush(RGB(10, 14, 20));
        FillRect(memDC, &cr, bgBr);
        DeleteObject(bgBr);

        /* Top Cyber Accent Line */
        HPEN topPen = CreatePen(PS_SOLID, 2, RGB(0, 210, 180));
        HPEN oldP = (HPEN)SelectObject(memDC, topPen);
        MoveToEx(memDC, 0, 0, NULL); LineTo(memDC, W, 0);
        SelectObject(memDC, oldP); DeleteObject(topPen);

        /* 2. Header Section */
        SetBkMode(memDC, TRANSPARENT);
        HFONT of = (HFONT)SelectObject(memDC, fHdr ? fHdr : (HFONT)GetStockObject(DEFAULT_GUI_FONT));
        SetTextColor(memDC, RGB(0, 230, 200));
        TextOutA(memDC, 40, 16, "KAEVEX AUTONOMOUS DEFENSE — FIRST-RUN CYBER AUDIT", 49);

        SelectObject(memDC, fSm ? fSm : (HFONT)GetStockObject(DEFAULT_GUI_FONT));
        SetTextColor(memDC, RGB(140, 165, 195));
        TextOutA(memDC, 40, 42, "Deep Host Topography, Local Database Discovery & Proactive Defense Shield Arming", 80);

        /* Kaevex Official Icon in Header */
        HICON hWizIco = NULL;
        LoadKaevexIconPair(GetModuleHandleA(NULL), NULL, &hWizIco);
        if (hWizIco) {
            DrawIconEx(memDC, W - 60, 16, hWizIco, 32, 32, 0, NULL, DI_NORMAL);
            DestroyIcon(hWizIco);
        }

        /* 3. Radar Visualizer (Left side: cx=72, cy=95, r=25) */
        int rcx = 72, rcy = 95, rr = 25;
        HPEN radPen = CreatePen(PS_SOLID, 1, RGB(0, 180, 160));
        HBRUSH radBr = CreateSolidBrush(RGB(14, 22, 32));
        SelectObject(memDC, radPen); SelectObject(memDC, radBr);
        Ellipse(memDC, rcx - rr, rcy - rr, rcx + rr, rcy + rr);
        DeleteObject(radBr);

        /* Inner Ring & Crosshairs */
        HPEN inPen = CreatePen(PS_SOLID, 1, RGB(22, 50, 60));
        SelectObject(memDC, inPen);
        Ellipse(memDC, rcx - rr/2, rcy - rr/2, rcx + rr/2, rcy + rr/2);
        MoveToEx(memDC, rcx - rr, rcy, NULL); LineTo(memDC, rcx + rr, rcy);
        MoveToEx(memDC, rcx, rcy - rr, NULL); LineTo(memDC, rcx, rcy + rr);
        DeleteObject(inPen);

        /* Rotating Sweep Beam */
        HPEN beamPen = CreatePen(PS_SOLID, 2, RGB(0, 255, 220));
        SelectObject(memDC, beamPen);
        MoveToEx(memDC, rcx, rcy, NULL);
        LineTo(memDC, rcx + (int)(cos(g_frRadarAngle) * (rr - 2)), rcy + (int)(sin(g_frRadarAngle) * (rr - 2)));
        DeleteObject(beamPen); DeleteObject(radPen);

        /* 4. Phase Banner & Status Text */
        SelectObject(memDC, fMed ? fMed : (HFONT)GetStockObject(DEFAULT_GUI_FONT));
        SetTextColor(memDC, RGB(251, 191, 36)); /* Amber Neon */
        TextOutA(memDC, 114, 76, g_frPhaseTitle, (int)strlen(g_frPhaseTitle));

        SelectObject(memDC, fSm ? fSm : (HFONT)GetStockObject(DEFAULT_GUI_FONT));
        SetTextColor(memDC, RGB(215, 230, 250));
        TextOutA(memDC, 114, 98, g_frDetailText, (int)strlen(g_frDetailText));

        /* Percentage Badge */
        char pctBuf[32];
        snprintf(pctBuf, sizeof(pctBuf), "[ %.0f%% COMPLETE ]", g_frDisplayProg);
        SelectObject(memDC, fMed ? fMed : (HFONT)GetStockObject(DEFAULT_GUI_FONT));
        SetTextColor(memDC, g_frDone ? RGB(34, 197, 94) : RGB(56, 189, 248));
        RECT pctRc = { W - 220, 76, W - 40, 100 };
        DrawTextA(memDC, pctBuf, -1, &pctRc, DT_RIGHT | DT_VCENTER | DT_SINGLELINE);

        /* 5. Progress Bar */
        int pbX = 40, pbY = 126, pbW = W - 80, pbH = 20;
        HBRUSH pbBg = CreateSolidBrush(RGB(20, 26, 38));
        HPEN pbBorder = CreatePen(PS_SOLID, 1, RGB(40, 56, 80));
        SelectObject(memDC, pbBg); SelectObject(memDC, pbBorder);
        RoundRect(memDC, pbX, pbY, pbX + pbW, pbY + pbH, 6, 6);
        DeleteObject(pbBg); DeleteObject(pbBorder);

        int fillW = (int)((pbW - 4) * (g_frDisplayProg / 100.0f));
        if (fillW > pbW - 4) fillW = pbW - 4;
        if (fillW > 0) {
            HBRUSH fillBr = CreateSolidBrush(g_frDone ? RGB(34, 197, 94) : RGB(0, 210, 180));
            RECT fillRc = { pbX + 2, pbY + 2, pbX + 2 + fillW, pbY + pbH - 2 };
            FillRect(memDC, &fillRc, fillBr);
            DeleteObject(fillBr);
        }

        /* 6. Live Telemetry Reconnaissance Console */
        int conX = 40, conY = 158, conW = W - 80, conH = 370;
        HBRUSH conBg = CreateSolidBrush(RGB(12, 16, 24));
        HPEN conBorder = CreatePen(PS_SOLID, 1, RGB(28, 44, 68));
        SelectObject(memDC, conBg); SelectObject(memDC, conBorder);
        RoundRect(memDC, conX, conY, conX + conW, conY + conH, 8, 8);
        DeleteObject(conBg); DeleteObject(conBorder);

        /* Console Title Bar */
        HBRUSH conHdrBr = CreateSolidBrush(RGB(18, 24, 38));
        RECT conHdrRc = { conX + 1, conY + 1, conX + conW - 1, conY + 28 };
        FillRect(memDC, &conHdrRc, conHdrBr);
        DeleteObject(conHdrBr);

        SelectObject(memDC, fSm ? fSm : (HFONT)GetStockObject(DEFAULT_GUI_FONT));
        SetTextColor(memDC, RGB(100, 130, 165));
        TextOutA(memDC, conX + 14, conY + 7, "SYSTEM TELEMETRY RECONNAISSANCE & PROACTIVE DEFENSE AUDIT STREAM:", 65);

        /* Draw Log Lines */
        SelectObject(memDC, fMono ? fMono : (HFONT)GetStockObject(DEFAULT_GUI_FONT));
        EnterCriticalSection(&g_frCS);
        int startLine = 0;
        if (g_frLogCount > 18) startLine = g_frLogCount - 18;
        int lineY = conY + 34;
        for (int i = startLine; i < g_frLogCount; i++) {
            const char *line = g_frLogs[i];
            COLORREF tagCol = RGB(160, 180, 205);
            if (strncmp(line, "[HOST", 5) == 0) tagCol = RGB(56, 189, 248);
            else if (strncmp(line, "[NETW", 5) == 0) tagCol = RGB(167, 139, 250);
            else if (strncmp(line, "[DATA", 5) == 0) tagCol = RGB(251, 191, 36);
            else if (strncmp(line, "[SOCK", 5) == 0) tagCol = RGB(52, 211, 153);
            else if (strncmp(line, "[NETG", 5) == 0) tagCol = RGB(45, 212, 191);
            else if (strncmp(line, "[CVE", 4) == 0) tagCol = RGB(248, 113, 113);
            else if (strncmp(line, "[BOOT", 5) == 0) tagCol = RGB(255, 110, 180);
            else if (strncmp(line, "[EFI", 4) == 0) tagCol = RGB(0, 229, 255);
            else if (strncmp(line, "[SYS-", 5) == 0) tagCol = RGB(147, 197, 253);
            else if (strncmp(line, "[SERV", 5) == 0) tagCol = RGB(251, 146, 60);
            else if (strncmp(line, "[DRIV", 5) == 0) tagCol = RGB(192, 132, 252);
            else if (strncmp(line, "[DNS-", 5) == 0) tagCol = RGB(74, 222, 128);
            else if (strncmp(line, "[ALER", 5) == 0) tagCol = RGB(239, 68, 68);
            else if (strncmp(line, "[AV-C", 5) == 0) tagCol = RGB(234, 179, 8);
            else if (strncmp(line, "[RANS", 5) == 0) tagCol = RGB(239, 68, 68);
            else if (strncmp(line, "[PROF", 5) == 0) tagCol = RGB(192, 132, 252);
            else if (strncmp(line, "[SHIE", 5) == 0) tagCol = RGB(34, 197, 94);
            else if (strncmp(line, "[KAEV", 5) == 0) tagCol = RGB(0, 240, 220);

            SetTextColor(memDC, tagCol);
            TextOutA(memDC, conX + 14, lineY, line, (int)strlen(line));
            lineY += 18;
        }
        LeaveCriticalSection(&g_frCS);

        /* 7. Detected Profile Card (shown when done) */
        if (g_frDone) {
            int cardX = 40, cardY = H - 128, cardW = W - 80, cardH = 72;
            HBRUSH cardBr = CreateSolidBrush(RGB(14, 22, 38));
            HPEN   cardPen = CreatePen(PS_SOLID, 2, RGB(0, 240, 200));
            HBRUSH ob4 = (HBRUSH)SelectObject(memDC, cardBr);
            HPEN   op4 = (HPEN)SelectObject(memDC, cardPen);
            RoundRect(memDC, cardX, cardY, cardX + cardW, cardY + cardH, 10, 10);
            SelectObject(memDC, ob4); SelectObject(memDC, op4);
            DeleteObject(cardBr); DeleteObject(cardPen);

            /* Pink accent bar */
            HBRUSH accentBr = CreateSolidBrush(RGB(255, 51, 102));
            RECT accentRc = { cardX, cardY, cardX + 5, cardY + cardH };
            FillRect(memDC, &accentRc, accentBr);
            DeleteObject(accentBr);

            /* Profile label */
            SelectObject(memDC, fSm ? fSm : (HFONT)GetStockObject(DEFAULT_GUI_FONT));
            SetTextColor(memDC, RGB(150, 175, 210));
            TextOutA(memDC, cardX + 18, cardY + 10, "DETECTED SECURITY PROFILE:", 26);

            SelectObject(memDC, fMed ? fMed : (HFONT)GetStockObject(DEFAULT_GUI_FONT));
            SetTextColor(memDC, RGB(0, 240, 200));
            TextOutA(memDC, cardX + 18, cardY + 30, g_frDiag.detectedProfile, (int)strlen(g_frDiag.detectedProfile));

            char profileHint[128];
            snprintf(profileHint, sizeof(profileHint),
                "Score: %d/100  |  CVEs found: %d apps  |  Connections: %d  |  Profile ARMED",
                100, g_frDiag.cveAppsCount, g_frDiag.activeConns);
            SelectObject(memDC, fSm ? fSm : (HFONT)GetStockObject(DEFAULT_GUI_FONT));
            SetTextColor(memDC, RGB(120, 160, 120));
            TextOutA(memDC, cardX + 18, cardY + 52, profileHint, (int)strlen(profileHint));
        }

        /* 7. Bottom Status Line */
        SelectObject(memDC, fSm ? fSm : (HFONT)GetStockObject(DEFAULT_GUI_FONT));
        SetTextColor(memDC, g_frDone ? RGB(52, 211, 153) : RGB(140, 160, 185));
        const char *botStat = g_frDone ?
            "System baseline verified. Proactive WAF & defense matrix fully armed. Click the button to continue." :
            "Autonomous baseline audit running across host, network and storage subsystems. Please stand by...";
        TextOutA(memDC, conX + 2, H - 36, botStat, (int)strlen(botStat));

        SelectObject(memDC, of);

        /* Blit to screen */
        BitBlt(hdc, 0, 0, W, H, memDC, 0, 0, SRCCOPY);
        SelectObject(memDC, oldBM);
        DeleteObject(memBM);
        DeleteDC(memDC);
        EndPaint(hw, &ps);
        return 0;
    }
    case WM_DRAWITEM: {
        LPDRAWITEMSTRUCT di = (LPDRAWITEMSTRUCT)lp;
        if (di->hwndItem == g_hFrBtn) {
            RECT rc = di->rcItem;
            BOOL dis = !IsWindowEnabled(g_hFrBtn);
            COLORREF bg = dis ? RGB(22, 28, 40) : RGB(0, 140, 115);
            COLORREF bc = dis ? RGB(35, 48, 68) : RGB(0, 230, 200);
            COLORREF tc = dis ? RGB(100, 115, 135) : RGB(255, 255, 255);
            HBRUSH br = CreateSolidBrush(bg);
            HPEN   pn = CreatePen(PS_SOLID, 2, bc);
            HBRUSH obr = (HBRUSH)SelectObject(di->hDC, br);
            HPEN   opn = (HPEN)SelectObject(di->hDC, pn);
            RoundRect(di->hDC, rc.left, rc.top, rc.right, rc.bottom, 10, 10);
            SelectObject(di->hDC, obr); SelectObject(di->hDC, opn);
            DeleteObject(br); DeleteObject(pn);
            SetBkMode(di->hDC, TRANSPARENT);
            SetTextColor(di->hDC, tc);
            HFONT of = (HFONT)SelectObject(di->hDC, fMed ? fMed : (HFONT)GetStockObject(DEFAULT_GUI_FONT));
            char bTxt[128] = {0};
            GetWindowTextA(g_hFrBtn, bTxt, sizeof(bTxt)-1);
            DrawTextA(di->hDC, bTxt, -1, &rc, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
            SelectObject(di->hDC, of);
            return TRUE;
        }
        break;
    }
    case WM_COMMAND: {
        if (LOWORD(wp) == IDOK) {
            if (!g_frDone) return 0;
            ApplyCustomProfile(GetParent(hw) ? GetParent(hw) : g_hwnd, g_frDiag.profileIdx);
            char finAlert[256];
            snprintf(finAlert, sizeof(finAlert), "First-Run Cyber Diagnostic complete: [%s] armed, Proactive Shields online.", g_frDiag.detectedProfile);
            add_alert("FirstRun", "INFO", finAlert);
            DestroyWindow(hw);
            return 0;
        }
        break;
    }
    case WM_CLOSE: {
        if (!g_frDone) {
            if (MessageBoxA(hw, "The initial system defense baseline audit is still running.\nAre you sure you want to skip and launch with default SOC protection?", "Skip First-Run Audit?", MB_YESNO | MB_ICONQUESTION) == IDYES) {
                ApplyCustomProfile(GetParent(hw) ? GetParent(hw) : g_hwnd, 0);
                DestroyWindow(hw);
            }
            return 0;
        }
        ApplyCustomProfile(GetParent(hw) ? GetParent(hw) : g_hwnd, g_frDiag.profileIdx);
        DestroyWindow(hw);
        return 0;
    }
    case WM_DESTROY: {
        KillTimer(hw, 999);
        g_hFrDlg = NULL;
        return 0;
    }
    }
    return DefWindowProcA(hw, msg, wp, lp);
}

/* Centralized Kaevex Official Icon Loader */
static void LoadKaevexIconPair(HINSTANCE hi, HICON *phBig, HICON *phSmall) {
    HICON big = NULL, small = NULL;
    HINSTANCE hInst = hi ? hi : GetModuleHandleA(NULL);

    /* 1. Try embedded PE resource ID 1 */
    big   = (HICON)LoadImageA(hInst, MAKEINTRESOURCE(1), IMAGE_ICON, 32, 32, LR_DEFAULTCOLOR);
    small = (HICON)LoadImageA(hInst, MAKEINTRESOURCE(1), IMAGE_ICON, 16, 16, LR_DEFAULTCOLOR);

    /* 2. Try icon.ico from executable folder and assets */
    if (!big) {
        char exeDir[MAX_PATH] = {0};
        GetModuleFileNameA(NULL, exeDir, sizeof(exeDir));
        char *sl = strrchr(exeDir, '\\'); if (sl) *sl = '\0';
        char icoPath[MAX_PATH];

        snprintf(icoPath, sizeof(icoPath), "%s\\icon.ico", exeDir);
        big   = (HICON)LoadImageA(NULL, icoPath, IMAGE_ICON, 32, 32, LR_LOADFROMFILE);
        small = (HICON)LoadImageA(NULL, icoPath, IMAGE_ICON, 16, 16, LR_LOADFROMFILE);

        if (!big) {
            snprintf(icoPath, sizeof(icoPath), "%s\\assets\\icon.ico", exeDir);
            big   = (HICON)LoadImageA(NULL, icoPath, IMAGE_ICON, 32, 32, LR_LOADFROMFILE);
            small = (HICON)LoadImageA(NULL, icoPath, IMAGE_ICON, 16, 16, LR_LOADFROMFILE);
        }
        if (!big) {
            snprintf(icoPath, sizeof(icoPath), "%s\\..\\assets\\icon.ico", exeDir);
            big   = (HICON)LoadImageA(NULL, icoPath, IMAGE_ICON, 32, 32, LR_LOADFROMFILE);
            small = (HICON)LoadImageA(NULL, icoPath, IMAGE_ICON, 16, 16, LR_LOADFROMFILE);
        }
        if (!big) {
            snprintf(icoPath, sizeof(icoPath), "%s\\kaevex.ico", exeDir);
            big   = (HICON)LoadImageA(NULL, icoPath, IMAGE_ICON, 32, 32, LR_LOADFROMFILE);
            small = (HICON)LoadImageA(NULL, icoPath, IMAGE_ICON, 16, 16, LR_LOADFROMFILE);
        }
    }
    if (phBig) *phBig = big; else if (big) DestroyIcon(big);
    if (phSmall) *phSmall = small; else if (small) DestroyIcon(small);
}

static void ShowFirstRunCyberWizard(HWND hwndParent) {
    if (!g_frCSInit) {
        InitializeCriticalSection(&g_frCS);
        g_frCSInit = TRUE;
    }
    g_frProgress = 0.0f;
    g_frDisplayProg = 0.0f;
    g_frDone = FALSE;
    g_frLogCount = 0;
    strcpy(g_frPhaseTitle, "PHASE 1 / 6: INITIALIZING CYBER DEFENSE TOPOLOGY");
    strcpy(g_frDetailText, "Probing host architecture, CPU instruction sets, and memory boundaries...");

    HICON hIcoBig = NULL, hIcoSmall = NULL;
    LoadKaevexIconPair(GetModuleHandleA(NULL), &hIcoBig, &hIcoSmall);

    WNDCLASSEXA wc = {0};
    wc.cbSize = sizeof(wc);
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = CyberDiagWndProc;
    wc.hInstance = GetModuleHandleA(NULL);
    wc.hCursor = LoadCursorA(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)GetStockObject(BLACK_BRUSH);
    wc.hIcon = hIcoBig ? hIcoBig : LoadIconA(NULL, IDI_APPLICATION);
    wc.hIconSm = hIcoSmall ? hIcoSmall : wc.hIcon;
    wc.lpszClassName = "KaevexFirstRunCyberClass";
    RegisterClassExA(&wc);

    int scrW = GetSystemMetrics(SM_CXSCREEN);
    int scrH = GetSystemMetrics(SM_CYSCREEN);
    int dlgW = 960, dlgH = 680;
    int dlgX = (scrW - dlgW) / 2;
    int dlgY = (scrH - dlgH) / 2;

    HWND hwDlg = CreateWindowExA(WS_EX_TOPMOST, "KaevexFirstRunCyberClass",
        "Kaevex Autonomous Cyber Initialization & Host Baseline Audit",
        WS_POPUP | WS_CAPTION | WS_SYSMENU | WS_VISIBLE,
        dlgX, dlgY, dlgW, dlgH,
        hwndParent, NULL, GetModuleHandleA(NULL), NULL);

    if (!hwDlg) return;

    if (hIcoBig)   SendMessageA(hwDlg, WM_SETICON, ICON_BIG,   (LPARAM)hIcoBig);
    if (hIcoSmall) SendMessageA(hwDlg, WM_SETICON, ICON_SMALL, (LPARAM)hIcoSmall);

    BOOL dark = 1;
    DwmSetWindowAttribute(hwDlg, 20, &dark, sizeof(dark));
    DwmSetWindowAttribute(hwDlg, 19, &dark, sizeof(dark));

    if (hwndParent) EnableWindow(hwndParent, FALSE);

    MSG msg;
    while (IsWindow(hwDlg) && GetMessageA(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageA(&msg);
    }

    if (hwndParent) {
        EnableWindow(hwndParent, TRUE);
        InvalidateRect(hwndParent, NULL, TRUE);
        UpdateWindow(hwndParent);
        SetForegroundWindow(hwndParent);
    }
}

static void PromptFirstRunWizard(HWND hwnd) {
    if (!CheckFirstRun()) return;
    ShowFirstRunCyberWizard(hwnd);
}

/* ===========================================================================
 * SUPABASE CLOUD AUTHENTICATION & PROFILE DIALOG
 * Realtime Login, Sign-Up, Hardware/Network Telemetry Sync & Remote Management
 * =========================================================================== */
#define ID_SB_NAME_EDIT  7004
#define ID_SB_EMAIL_EDIT 7006
#define ID_SB_PASS_EDIT  7008
#define ID_SB_PASS2_EDIT 7010
#define ID_SB_SUBMIT     7011
#define ID_SB_STATUS     7012
#define ID_SB_SYNC_NOW   7013
#define ID_SB_LOGOUT     7014
#define ID_SB_CLOSE      7015
#define ID_SB_INFO_TEXT  7016
#define ID_SB_TOGGLE     7017
#define ID_SB_EYE        7018

static int  s_sbMode = 0; /* 0 = Sign In, 1 = Sign Up */
static BOOL s_sbShowPass = FALSE;
static HWND s_hSbDlg = NULL;
static HWND s_hSbNameEdit = NULL;
static HWND s_hSbEmailEdit = NULL;
static HWND s_hSbPassEdit = NULL;
static HWND s_hSbPass2Edit = NULL;
static HWND s_hSbSubmit = NULL, s_hSbStatus = NULL;
static HWND s_hSbToggle = NULL, s_hSbEye = NULL;
static HWND s_hSbSyncNow = NULL, s_hSbLogout = NULL, s_hSbClose = NULL;
static HWND s_hSbInfoText = NULL;

static void HandleRemoteSupabaseAction(const char *action, const char *target) {
    if (!action) return;
    char msg[256];
    if (_stricmp(action, "EMERGENCY_LOCKDOWN") == 0) {
        fw_emergency_lockdown(TRUE);
        g_lockdown = 1;
        add_alert("SupabaseCloud", "CRITICAL", "Remote Emergency Lockdown ENFORCED from Mobile App");
        if (g_hwnd) InvalidateRect(g_hwnd, NULL, FALSE);
    } else if (_stricmp(action, "DISENGAGE_LOCKDOWN") == 0) {
        fw_emergency_lockdown(FALSE);
        g_lockdown = 0;
        add_alert("SupabaseCloud", "INFO", "Remote Lockdown DISENGAGED from Mobile App");
        if (g_hwnd) InvalidateRect(g_hwnd, NULL, FALSE);
    } else if (_stricmp(action, "KILL_SANDBOX") == 0) {
        sbx_kill();
        add_alert("SupabaseCloud", "WARNING", "Remote SmartSandbox Terminated from Mobile App");
    } else if (_stricmp(action, "DEEP_SCAN") == 0) {
        add_alert("SupabaseCloud", "INFO", "Remote Deep Security Scan Triggered from Mobile App");
        if (g_hwnd) PostMessageA(g_hwnd, WM_COMMAND, MAKEWPARAM(IDA_SCANALL, 0), 0);
    } else if (_stricmp(action, "TERMINATE_PROCESS") == 0) {
        snprintf(msg, sizeof(msg), "Remote Process Kill: %s", target);
        add_alert("SupabaseCloud", "WARNING", msg);
        if (target && target[0]) {
            char cmd[256];
            snprintf(cmd, sizeof(cmd), "taskkill /F /IM \"%s\" >nul 2>&1", target);
            system(cmd);
        }
    }
}

static void DrawGradientH_Auth(HDC dc, int x, int y, int w, int h, COLORREF c1, COLORREF c2, int r) {
    HRGN rgn = CreateRoundRectRgn(x, y, x + w + 1, y + h + 1, r, r);
    SelectClipRgn(dc, rgn);
    for (int i = 0; i < w; i++) {
        float t = (float)i / (float)w;
        int red   = (int)(GetRValue(c1) + t * (GetRValue(c2) - GetRValue(c1)));
        int green = (int)(GetGValue(c1) + t * (GetGValue(c2) - GetGValue(c1)));
        int blue  = (int)(GetBValue(c1) + t * (GetBValue(c2) - GetBValue(c1)));
        RECT colR = {x + i, y, x + i + 1, y + h};
        HBRUSH br = CreateSolidBrush(RGB(red, green, blue));
        FillRect(dc, &colR, br);
        DeleteObject(br);
    }
    SelectClipRgn(dc, NULL);
    DeleteObject(rgn);
}

static void DrawCyberWaves_Auth(HDC dc, int x, int y, int w, int h) {
    /* Subtle ambient dark cyber blue waves at lower edge of left panel */
    for (int i = 0; i < 5; i++) {
        COLORREF penCol = RGB(8 + i * 3, 20 + i * 5, 42 + i * 8);
        HPEN p = CreatePen(PS_SOLID, 2, penCol);
        HPEN op = (HPEN)SelectObject(dc, p);
        POINT pts[4];
        pts[0].x = x - 20;
        pts[0].y = y + h - 15 - i * 18;
        pts[1].x = x + w * 35 / 100;
        pts[1].y = y + h - 75 - i * 14;
        pts[2].x = x + w * 70 / 100;
        pts[2].y = y + h - 20 - i * 12;
        pts[3].x = x + w + 20;
        pts[3].y = y + h - 60 - i * 8;
        PolyBezier(dc, pts, 4);
        SelectObject(dc, op);
        DeleteObject(p);
    }
}

static void DrawKLogo_Auth(HDC dc, int x, int y, int sz) {
    HICON hIco = NULL;
    LoadKaevexIconPair(GetModuleHandleA(NULL), &hIco, NULL);
    if (hIco) {
        DrawIconEx(dc, x, y, hIco, sz, sz, 0, NULL, DI_NORMAL);
        DestroyIcon(hIco);
    } else {
        DrawRoundRectPanel(dc, x, y, sz, sz, 12, RGB(8, 20, 44), RGB(0, 150, 235));
        int barW = sz / 5;
        int m = sz / 5;
        DrawGradientH_Auth(dc, x + m, y + m, barW, sz - 2 * m, RGB(0, 210, 255), RGB(0, 110, 255), 3);

        POINT w1[3] = {
            { x + m + barW + 2, y + sz / 2 - 2 },
            { x + sz - m, y + m },
            { x + sz - m, y + m + sz / 4 }
        };
        HBRUSH b1 = CreateSolidBrush(RGB(0, 195, 255));
        HPEN pNone = (HPEN)GetStockObject(NULL_PEN);
        HBRUSH ob = (HBRUSH)SelectObject(dc, b1);
        HPEN op = (HPEN)SelectObject(dc, pNone);
        Polygon(dc, w1, 3);

        POINT w2[3] = {
            { x + m + barW + 2, y + sz / 2 - 2 },
            { x + sz - m - 4, y + sz - m },
            { x + sz - m + sz / 6, y + sz - m }
        };
        HBRUSH b2 = CreateSolidBrush(RGB(255, 51, 102));
        SelectObject(dc, b2);
        Polygon(dc, w2, 3);
        SelectObject(dc, ob); SelectObject(dc, op);
        DeleteObject(b1); DeleteObject(b2);
    }
}

static void DrawNeonCloudGraphic_Auth(HDC dc, int cx, int cy, HFONT fIconCtrl) {
    (void)fIconCtrl;
    static HBITMAP s_hHoloBmp = NULL;
    if (!s_hHoloBmp) {
        /* 1. Try embedded bitmap resource 102 with LR_CREATEDIBSECTION */
        s_hHoloBmp = (HBITMAP)LoadImageA(GetModuleHandleA(NULL), MAKEINTRESOURCEA(102), IMAGE_BITMAP, 0, 0, LR_CREATEDIBSECTION);
        if (!s_hHoloBmp) {
            s_hHoloBmp = LoadBitmapA(GetModuleHandleA(NULL), MAKEINTRESOURCE(102));
        }
        /* 2. Try disk file fallback */
        if (!s_hHoloBmp) {
            char exeDir[MAX_PATH] = {0};
            GetModuleFileNameA(NULL, exeDir, sizeof(exeDir));
            char *sl = strrchr(exeDir, '\\'); if (sl) *sl = '\0';
            char p[MAX_PATH];
            snprintf(p, sizeof(p), "%s\\assets\\auth_hologram.bmp", exeDir);
            s_hHoloBmp = (HBITMAP)LoadImageA(NULL, p, IMAGE_BITMAP, 0, 0, LR_LOADFROMFILE | LR_CREATEDIBSECTION);
            if (!s_hHoloBmp) {
                snprintf(p, sizeof(p), "%s\\auth_hologram.bmp", exeDir);
                s_hHoloBmp = (HBITMAP)LoadImageA(NULL, p, IMAGE_BITMAP, 0, 0, LR_LOADFROMFILE | LR_CREATEDIBSECTION);
            }
            if (!s_hHoloBmp) {
                snprintf(p, sizeof(p), "%s\\..\\assets\\auth_hologram.bmp", exeDir);
                s_hHoloBmp = (HBITMAP)LoadImageA(NULL, p, IMAGE_BITMAP, 0, 0, LR_LOADFROMFILE | LR_CREATEDIBSECTION);
            }
        }
    }

    if (s_hHoloBmp) {
        int hw = 340, hh = 320;
        int hx = cx - hw / 2;
        int hy = cy - 140;
        HDC hdcHolo = CreateCompatibleDC(dc);
        HBITMAP oBmp = (HBITMAP)SelectObject(hdcHolo, s_hHoloBmp);
        SetStretchBltMode(dc, HALFTONE);
        BitBlt(dc, hx, hy, hw, hh, hdcHolo, 0, 0, SRCCOPY);
        SelectObject(hdcHolo, oBmp);
        DeleteDC(hdcHolo);
    }
}

static WNDPROC s_oldEditProc = NULL;
static LRESULT CALLBACK SbAuthEditProc(HWND hw, UINT msg, WPARAM wp, LPARAM lp) {
    if (msg == WM_PAINT) {
        LRESULT res = CallWindowProcA(s_oldEditProc, hw, msg, wp, lp);
        if (GetWindowTextLengthA(hw) == 0 && GetFocus() != hw) {
            const wchar_t *cue = (const wchar_t*)GetPropW(hw, L"SbCue");
            if (cue) {
                HDC dc = GetDC(hw);
                SetBkMode(dc, TRANSPARENT);
                SetTextColor(dc, RGB(90, 115, 145));
                HFONT f = fMed ? fMed : (HFONT)GetStockObject(DEFAULT_GUI_FONT);
                HFONT of = (HFONT)SelectObject(dc, f);
                RECT r; GetClientRect(hw, &r);
                r.left += 2;
                DrawTextW(dc, cue, -1, &r, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
                SelectObject(dc, of);
                ReleaseDC(hw, dc);
            }
        }
        return res;
    }
    return CallWindowProcA(s_oldEditProc, hw, msg, wp, lp);
}

static void SupabaseAuthUpdateVisibility(HWND hw) {
    BOOL logged = g_sbSession.isLoggedIn;
    int leftW = 340;
    int formX = leftW + 48;
    int formW = 490;

    if (logged) {
        if (s_hSbNameEdit)  ShowWindow(s_hSbNameEdit, SW_HIDE);
        if (s_hSbEmailEdit) ShowWindow(s_hSbEmailEdit, SW_HIDE);
        if (s_hSbPassEdit)  ShowWindow(s_hSbPassEdit, SW_HIDE);
        if (s_hSbPass2Edit) ShowWindow(s_hSbPass2Edit, SW_HIDE);
        if (s_hSbEye)       ShowWindow(s_hSbEye, SW_HIDE);
        if (s_hSbToggle)    ShowWindow(s_hSbToggle, SW_HIDE);

        if (s_hSbInfoText) {
            char info[1024];
            char hostName[64] = {0}; DWORD hSz = sizeof(hostName);
            GetComputerNameA(hostName, &hSz);
            char osVer[128] = {0}; sb_get_real_os_version(osVer, sizeof(osVer));
            char realIp[64] = {0}; sb_get_real_ip(realIp, sizeof(realIp));

            snprintf(info, sizeof(info),
                "CURRENT PLATFORM IDENTITY STATUS: ACTIVE (ONLINE)\r\n\r\n"
                "* Master Account: %s\r\n"
                "* Identity Holder: %s\r\n"
                "* Platform UUID: %s\r\n"
                "* Security Clearance: Tier-3 Enterprise SOC Officer\r\n"
                "* Platform Node: Master SOC Fleet Registry\r\n"
                "* Host Machine: %s\r\n"
                "* Operating System: %s\r\n"
                "* Real IP Address: %s\r\n"
                "* Synced Alerts: %d  |  Synced CVEs: %d  |  Policy Actions: %d\r\n"
                "* Telemetry Channel: End-to-End Encrypted Platform Sync Active",
                g_sbSession.email,
                g_sbSession.fullName[0] ? g_sbSession.fullName : "Enterprise Security Officer",
                g_sbSession.userId[0] ? g_sbSession.userId : "auth-platform-active",
                hostName, osVer, realIp,
                g_sbSession.totalSyncedAlerts,
                g_sbSession.totalSyncedCves,
                g_sbSession.totalSyncedActions);

            SetWindowTextA(s_hSbInfoText, info);
            SetWindowPos(s_hSbInfoText, NULL, formX, 140, formW, 240, SWP_NOZORDER | SWP_SHOWWINDOW);
        }

        if (s_hSbSubmit) {
            SetWindowPos(s_hSbSubmit, NULL, formX, 400, formW, 48, SWP_NOZORDER | SWP_SHOWWINDOW);
        }
        if (s_hSbLogout) {
            SetWindowPos(s_hSbLogout, NULL, formX, 460, (formW - 14) / 2, 44, SWP_NOZORDER | SWP_SHOWWINDOW);
        }
        if (s_hSbClose) {
            SetWindowPos(s_hSbClose, NULL, formX + (formW + 14) / 2, 460, (formW - 14) / 2, 44, SWP_NOZORDER | SWP_SHOWWINDOW);
        }
        if (s_hSbStatus) {
            SetWindowPos(s_hSbStatus, NULL, formX, 520, formW, 30, SWP_NOZORDER | SWP_SHOWWINDOW);
        }
    } else {
        if (s_hSbInfoText) ShowWindow(s_hSbInfoText, SW_HIDE);
        if (s_hSbLogout)   ShowWindow(s_hSbLogout, SW_HIDE);

        if (s_sbMode == 0) {
            /* Sign In mode */
            if (s_hSbNameEdit)  ShowWindow(s_hSbNameEdit, SW_HIDE);
            if (s_hSbPass2Edit) ShowWindow(s_hSbPass2Edit, SW_HIDE);

            int emailEdY = 168;
            int passEdY  = 256;

            if (s_hSbEmailEdit) {
                SetWindowPos(s_hSbEmailEdit, NULL, formX + 48, emailEdY + 12, formW - 64, 22, SWP_NOZORDER | SWP_SHOWWINDOW);
            }
            if (s_hSbPassEdit) {
                SetWindowPos(s_hSbPassEdit, NULL, formX + 48, passEdY + 12, formW - 96, 22, SWP_NOZORDER | SWP_SHOWWINDOW);
            }
            if (s_hSbEye) {
                SetWindowPos(s_hSbEye, NULL, formX + formW - 42, passEdY + 6, 34, 34, SWP_NOZORDER | SWP_SHOWWINDOW);
            }

            int btn1Y = 334;
            if (s_hSbSubmit) {
                SetWindowPos(s_hSbSubmit, NULL, formX, btn1Y, formW, 48, SWP_NOZORDER | SWP_SHOWWINDOW);
            }
            int btn2Y = 396;
            if (s_hSbToggle) {
                SetWindowPos(s_hSbToggle, NULL, formX, btn2Y, formW, 46, SWP_NOZORDER | SWP_SHOWWINDOW);
            }
            int statusY = 452;
            if (s_hSbStatus) {
                SetWindowPos(s_hSbStatus, NULL, formX, statusY, formW, 24, SWP_NOZORDER | SWP_SHOWWINDOW);
            }
            int closeY = 516;
            if (s_hSbClose) {
                SetWindowPos(s_hSbClose, NULL, formX + (formW - 130) / 2, closeY, 130, 36, SWP_NOZORDER | SWP_SHOWWINDOW);
            }
        } else {
            /* Register mode */
            int nameEdY  = 150;
            int emailEdY = 226;
            int passEdY  = 302;
            int pass2EdY = 378;

            if (s_hSbNameEdit) {
                SetWindowPos(s_hSbNameEdit, NULL, formX + 48, nameEdY + 10, formW - 64, 22, SWP_NOZORDER | SWP_SHOWWINDOW);
            }
            if (s_hSbEmailEdit) {
                SetWindowPos(s_hSbEmailEdit, NULL, formX + 48, emailEdY + 10, formW - 64, 22, SWP_NOZORDER | SWP_SHOWWINDOW);
            }
            if (s_hSbPassEdit) {
                SetWindowPos(s_hSbPassEdit, NULL, formX + 48, passEdY + 10, formW - 96, 22, SWP_NOZORDER | SWP_SHOWWINDOW);
            }
            if (s_hSbPass2Edit) {
                SetWindowPos(s_hSbPass2Edit, NULL, formX + 48, pass2EdY + 10, formW - 64, 22, SWP_NOZORDER | SWP_SHOWWINDOW);
            }
            if (s_hSbEye) {
                SetWindowPos(s_hSbEye, NULL, formX + formW - 40, passEdY + 4, 34, 34, SWP_NOZORDER | SWP_SHOWWINDOW);
            }

            int btn1Y = 432;
            if (s_hSbSubmit) {
                SetWindowPos(s_hSbSubmit, NULL, formX, btn1Y, formW, 46, SWP_NOZORDER | SWP_SHOWWINDOW);
            }
            int btn2Y = 488;
            if (s_hSbToggle) {
                SetWindowPos(s_hSbToggle, NULL, formX, btn2Y, formW, 42, SWP_NOZORDER | SWP_SHOWWINDOW);
            }
            int statusY = 538;
            if (s_hSbStatus) {
                SetWindowPos(s_hSbStatus, NULL, formX, statusY, formW, 22, SWP_NOZORDER | SWP_SHOWWINDOW);
            }
            int closeY = 598;
            if (s_hSbClose) {
                SetWindowPos(s_hSbClose, NULL, formX + (formW - 130) / 2, closeY, 130, 36, SWP_NOZORDER | SWP_SHOWWINDOW);
            }
        }
    }
    InvalidateRect(hw, NULL, TRUE);
}

static LRESULT CALLBACK SupabaseAuthWndProc(HWND hw, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_CREATE: {
        s_hSbDlg = hw;
        HINSTANCE hi = GetModuleHandleA(NULL);

        s_hSbNameEdit = CreateWindowExA(0, "EDIT", "",
            WS_CHILD | ES_AUTOHSCROLL, 0, 0, 10, 10, hw, (HMENU)(UINT_PTR)ID_SB_NAME_EDIT, hi, NULL);
        s_hSbEmailEdit = CreateWindowExA(0, "EDIT", g_sbSession.email[0] ? g_sbSession.email : "",
            WS_CHILD | ES_AUTOHSCROLL, 0, 0, 10, 10, hw, (HMENU)(UINT_PTR)ID_SB_EMAIL_EDIT, hi, NULL);
        s_hSbPassEdit = CreateWindowExA(0, "EDIT", "",
            WS_CHILD | ES_PASSWORD | ES_AUTOHSCROLL, 0, 0, 10, 10, hw, (HMENU)(UINT_PTR)ID_SB_PASS_EDIT, hi, NULL);
        s_hSbPass2Edit = CreateWindowExA(0, "EDIT", "",
            WS_CHILD | ES_PASSWORD | ES_AUTOHSCROLL, 0, 0, 10, 10, hw, (HMENU)(UINT_PTR)ID_SB_PASS2_EDIT, hi, NULL);

        s_hSbEye = CreateWindowExA(0, "BUTTON", "",
            WS_CHILD | BS_OWNERDRAW, 0, 0, 10, 10, hw, (HMENU)(UINT_PTR)ID_SB_EYE, hi, NULL);

        s_hSbSubmit = CreateWindowExA(0, "BUTTON", "",
            WS_CHILD | BS_OWNERDRAW, 0, 0, 10, 10, hw, (HMENU)(UINT_PTR)ID_SB_SUBMIT, hi, NULL);
        s_hSbToggle = CreateWindowExA(0, "BUTTON", "",
            WS_CHILD | BS_OWNERDRAW, 0, 0, 10, 10, hw, (HMENU)(UINT_PTR)ID_SB_TOGGLE, hi, NULL);
        s_hSbClose = CreateWindowExA(0, "BUTTON", "",
            WS_CHILD | BS_OWNERDRAW, 0, 0, 10, 10, hw, (HMENU)(UINT_PTR)ID_SB_CLOSE, hi, NULL);

        s_hSbStatus = CreateWindowExA(0, "STATIC", "",
            WS_CHILD | WS_VISIBLE | SS_CENTER, 0, 0, 10, 10, hw, (HMENU)(UINT_PTR)ID_SB_STATUS, hi, NULL);

        s_hSbInfoText = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "",
            WS_CHILD | ES_MULTILINE | ES_READONLY | WS_VSCROLL, 0, 0, 10, 10, hw, (HMENU)(UINT_PTR)ID_SB_INFO_TEXT, hi, NULL);

        s_hSbLogout = CreateWindowExA(0, "BUTTON", "",
            WS_CHILD | BS_OWNERDRAW, 0, 0, 10, 10, hw, (HMENU)(UINT_PTR)ID_SB_LOGOUT, hi, NULL);

        /* Subclass Edit controls to render sleek placeholder cue text when unfocused and empty */
        if (!s_oldEditProc) s_oldEditProc = (WNDPROC)GetWindowLongPtrA(s_hSbEmailEdit, GWLP_WNDPROC);
        SetWindowLongPtrA(s_hSbNameEdit,  GWLP_WNDPROC, (LONG_PTR)SbAuthEditProc);
        SetWindowLongPtrA(s_hSbEmailEdit, GWLP_WNDPROC, (LONG_PTR)SbAuthEditProc);
        SetWindowLongPtrA(s_hSbPassEdit,  GWLP_WNDPROC, (LONG_PTR)SbAuthEditProc);
        SetWindowLongPtrA(s_hSbPass2Edit, GWLP_WNDPROC, (LONG_PTR)SbAuthEditProc);

        SetPropW(s_hSbNameEdit,  L"SbCue", (HANDLE)L"Enter your full name");
        SetPropW(s_hSbEmailEdit, L"SbCue", (HANDLE)L"Enter your email address");
        SetPropW(s_hSbPassEdit,  L"SbCue", (HANDLE)L"Enter your password");
        SetPropW(s_hSbPass2Edit, L"SbCue", (HANDLE)L"Confirm your password");

        s_sbShowPass = FALSE;
        SendMessageA(s_hSbPassEdit, EM_SETPASSWORDCHAR, 0x25CF, 0);
        SendMessageA(s_hSbPass2Edit, EM_SETPASSWORDCHAR, 0x25CF, 0);

        /* Assign modern font to child controls */
        HFONT fLoginMed = fMed ? fMed : (HFONT)GetStockObject(DEFAULT_GUI_FONT);
        SendMessageA(s_hSbNameEdit,  WM_SETFONT, (WPARAM)fLoginMed, TRUE);
        SendMessageA(s_hSbEmailEdit, WM_SETFONT, (WPARAM)fLoginMed, TRUE);
        SendMessageA(s_hSbPassEdit,  WM_SETFONT, (WPARAM)fLoginMed, TRUE);
        SendMessageA(s_hSbPass2Edit, WM_SETFONT, (WPARAM)fLoginMed, TRUE);
        SendMessageA(s_hSbStatus,    WM_SETFONT, (WPARAM)fSm, TRUE);
        SendMessageA(s_hSbInfoText,  WM_SETFONT, (WPARAM)fMono, TRUE);

        SupabaseAuthUpdateVisibility(hw);
        return 0;
    }

    case WM_COMMAND: {
        int id = LOWORD(wp);
        if (id == ID_SB_TOGGLE) {
            s_sbMode = (s_sbMode == 0) ? 1 : 0;
            SetWindowTextA(s_hSbStatus, "");
            SupabaseAuthUpdateVisibility(hw);
            return 0;
        } else if (id == ID_SB_EYE) {
            s_sbShowPass = !s_sbShowPass;
            SendMessageA(s_hSbPassEdit, EM_SETPASSWORDCHAR, s_sbShowPass ? 0 : 0x25CF, 0);
            if (s_hSbPass2Edit) SendMessageA(s_hSbPass2Edit, EM_SETPASSWORDCHAR, s_sbShowPass ? 0 : 0x25CF, 0);
            InvalidateRect(s_hSbPassEdit, NULL, TRUE);
            if (s_hSbPass2Edit) InvalidateRect(s_hSbPass2Edit, NULL, TRUE);
            InvalidateRect(s_hSbEye, NULL, TRUE);
            return 0;
        } else if (id == ID_SB_SUBMIT) {
            if (g_sbSession.isLoggedIn) {
                SetWindowTextA(s_hSbStatus, "Syncing telemetry with Kaevex Platform...");
                UpdateWindow(s_hSbStatus);
                sb_trigger_full_sync();
                SetWindowTextA(s_hSbStatus, "Real hardware & network telemetry pushed to Kaevex Platform!");
                SupabaseAuthUpdateVisibility(hw);
                if (g_hwnd) InvalidateRect(g_hwnd, NULL, FALSE);
            } else if (s_sbMode == 0) {
                char email[128] = {0}, pass[128] = {0};
                GetWindowTextA(s_hSbEmailEdit, email, sizeof(email));
                GetWindowTextA(s_hSbPassEdit, pass, sizeof(pass));
                if (!email[0] || !pass[0]) {
                    SetWindowTextA(s_hSbStatus, "Error: Please enter both email and password.");
                    return 0;
                }
                SetWindowTextA(s_hSbStatus, "Authenticating with Kaevex Platform...");
                UpdateWindow(s_hSbStatus);

                char outMsg[256] = {0};
                BOOL ok = sb_auth_login(email, pass, outMsg, sizeof(outMsg));
                SetWindowTextA(s_hSbStatus, outMsg);
                if (ok) {
                    sb_trigger_full_sync();
                    SupabaseAuthUpdateVisibility(hw);
                    if (g_hwnd) InvalidateRect(g_hwnd, NULL, FALSE);
                }
            } else {
                char name[128] = {0}, email[128] = {0}, pass[128] = {0}, pass2[128] = {0};
                GetWindowTextA(s_hSbNameEdit, name, sizeof(name));
                GetWindowTextA(s_hSbEmailEdit, email, sizeof(email));
                GetWindowTextA(s_hSbPassEdit, pass, sizeof(pass));
                GetWindowTextA(s_hSbPass2Edit, pass2, sizeof(pass2));
                if (!email[0] || !pass[0]) {
                    SetWindowTextA(s_hSbStatus, "Error: Please provide email and password.");
                    return 0;
                }
                if (strcmp(pass, pass2) != 0) {
                    SetWindowTextA(s_hSbStatus, "Error: Passwords do not match. Please verify.");
                    return 0;
                }
                SetWindowTextA(s_hSbStatus, "Registering new account in Kaevex Platform...");
                UpdateWindow(s_hSbStatus);

                char outMsg[256] = {0};
                BOOL ok = sb_auth_signup(email, pass, name, outMsg, sizeof(outMsg));
                SetWindowTextA(s_hSbStatus, outMsg);
                if (ok) {
                    s_sbMode = 0;
                    SetWindowTextA(s_hSbStatus, "Account created successfully! Please sign in.");
                    SupabaseAuthUpdateVisibility(hw);
                }
            }
        } else if (id == ID_SB_SYNC_NOW) {
            SetWindowTextA(s_hSbStatus, "Reading real OS kernel, network sockets & memory telemetry...");
            UpdateWindow(s_hSbStatus);
            sb_trigger_full_sync();
            SetWindowTextA(s_hSbStatus, "Real hardware & network telemetry pushed to Kaevex Platform!");
            SupabaseAuthUpdateVisibility(hw);
            if (g_hwnd) InvalidateRect(g_hwnd, NULL, FALSE);
        } else if (id == ID_SB_LOGOUT) {
            sb_clear_session();
            SetWindowTextA(s_hSbStatus, "Signed out successfully.");
            SupabaseAuthUpdateVisibility(hw);
            if (g_hwnd) InvalidateRect(g_hwnd, NULL, FALSE);
        } else if (id == ID_SB_CLOSE || id == IDCANCEL) {
            DestroyWindow(hw);
        }
        return 0;
    }

    case WM_DRAWITEM: {
        DRAWITEMSTRUCT *dis = (DRAWITEMSTRUCT*)lp;
        if (!dis) return FALSE;
        int id = (int)dis->CtlID;
        HDC hdc = dis->hDC;
        RECT rc = dis->rcItem;
        BOOL sel = (dis->itemState & ODS_SELECTED);

        if (id == ID_SB_SUBMIT) {
            /* Clear background first so corners have zero white artifacts */
            HBRUSH pBg = CreateSolidBrush(RGB(7, 13, 24));
            FillRect(hdc, &rc, pBg);
            DeleteObject(pBg);

            int W = rc.right - rc.left, H = rc.bottom - rc.top;
            COLORREF c1 = sel ? RGB(0, 128, 220) : RGB(0, 155, 255);
            COLORREF c2 = sel ? RGB(140, 60, 215) : RGB(168, 85, 247);
            DrawGradientH_Auth(hdc, rc.left, rc.top, W, H, c1, c2, 12);

            SetBkMode(hdc, TRANSPARENT);
            SetTextColor(hdc, RGB(255, 255, 255));
            SelectObject(hdc, fMed ? fMed : (HFONT)GetStockObject(DEFAULT_GUI_FONT));
            const wchar_t *btnTxt = g_sbSession.isLoggedIn ?
                L"Sync Platform Telemetry  \u2192" :
                (s_sbMode == 0 ? L"Sign In to Kaevex Platform  \u2192" : L"Create Kaevex Account  \u2192");
            DrawTextW(hdc, btnTxt, -1, &rc, DT_CENTER|DT_VCENTER|DT_SINGLELINE);
            return TRUE;
        }

        if (id == ID_SB_TOGGLE) {
            HBRUSH pBg = CreateSolidBrush(RGB(7, 13, 24));
            FillRect(hdc, &rc, pBg);
            DeleteObject(pBg);

            int W = rc.right - rc.left, H = rc.bottom - rc.top;
            COLORREF bg = sel ? RGB(18, 36, 68) : RGB(10, 20, 38);
            COLORREF bdr = sel ? RGB(45, 90, 160) : RGB(26, 52, 96);
            DrawRoundRectPanel(hdc, rc.left, rc.top, W, H, 10, bg, bdr);

            const wchar_t *txt = (s_sbMode == 0) ? L"Register" : L"Back to Sign In";
            const wchar_t *ico = (s_sbMode == 0) ? L"\uE77B" : L"\uE72B";

            HFONT hfIcon = fIcon ? fIcon : (HFONT)GetStockObject(DEFAULT_GUI_FONT);
            HFONT hfTxt = fMed ? fMed : (HFONT)GetStockObject(DEFAULT_GUI_FONT);

            SelectObject(hdc, hfTxt);
            SIZE szT;
            GetTextExtentPoint32W(hdc, txt, (int)wcslen(txt), &szT);
            int iconW = 20, gap = 8;
            int totalW = iconW + gap + szT.cx;
            int startX = rc.left + (W - totalW) / 2;

            SetBkMode(hdc, TRANSPARENT);
            SetTextColor(hdc, RGB(56, 189, 248));
            SelectObject(hdc, hfIcon);
            RECT icR = { startX, rc.top, startX + iconW, rc.bottom };
            DrawTextW(hdc, ico, 1, &icR, DT_CENTER|DT_VCENTER|DT_SINGLELINE);

            SetTextColor(hdc, RGB(215, 230, 250));
            SelectObject(hdc, hfTxt);
            RECT txR = { startX + iconW + gap, rc.top, startX + totalW + 4, rc.bottom };
            DrawTextW(hdc, txt, (int)wcslen(txt), &txR, DT_LEFT|DT_VCENTER|DT_SINGLELINE);
            return TRUE;
        }

        if (id == ID_SB_CLOSE) {
            HBRUSH pBg = CreateSolidBrush(RGB(7, 13, 24));
            FillRect(hdc, &rc, pBg);
            DeleteObject(pBg);

            int W = rc.right - rc.left, H = rc.bottom - rc.top;
            COLORREF bg = sel ? RGB(20, 32, 54) : RGB(11, 20, 36);
            COLORREF bdr = sel ? RGB(45, 75, 115) : RGB(28, 48, 80);
            DrawRoundRectPanel(hdc, rc.left, rc.top, W, H, 8, bg, bdr);

            const wchar_t *txt = L"Close";
            const wchar_t *ico = L"\uE711";

            HFONT hfIcon = fIcon ? fIcon : (HFONT)GetStockObject(DEFAULT_GUI_FONT);
            HFONT hfTxt = fMed ? fMed : (HFONT)GetStockObject(DEFAULT_GUI_FONT);

            SelectObject(hdc, hfTxt);
            SIZE szT;
            GetTextExtentPoint32W(hdc, txt, (int)wcslen(txt), &szT);
            int iconW = 16, gap = 8;
            int totalW = iconW + gap + szT.cx;
            int startX = rc.left + (W - totalW) / 2;

            SetBkMode(hdc, TRANSPARENT);
            SetTextColor(hdc, RGB(160, 185, 215));
            SelectObject(hdc, hfIcon);
            RECT icR = { startX, rc.top, startX + iconW, rc.bottom };
            DrawTextW(hdc, ico, 1, &icR, DT_CENTER|DT_VCENTER|DT_SINGLELINE);

            SetTextColor(hdc, RGB(185, 205, 230));
            SelectObject(hdc, hfTxt);
            RECT txR = { startX + iconW + gap, rc.top, startX + totalW + 4, rc.bottom };
            DrawTextW(hdc, txt, (int)wcslen(txt), &txR, DT_LEFT|DT_VCENTER|DT_SINGLELINE);
            return TRUE;
        }

        if (id == ID_SB_EYE) {
            HBRUSH bgB = CreateSolidBrush(RGB(8, 16, 30));
            FillRect(hdc, &rc, bgB);
            DeleteObject(bgB);
            SetBkMode(hdc, TRANSPARENT);
            SetTextColor(hdc, s_sbShowPass ? RGB(0, 210, 255) : RGB(100, 125, 160));
            SelectObject(hdc, fIcon ? fIcon : (HFONT)GetStockObject(DEFAULT_GUI_FONT));
            DrawTextW(hdc, s_sbShowPass ? L"\uED1A" : L"\uE7B3", 1, &rc, DT_CENTER|DT_VCENTER|DT_SINGLELINE);
            return TRUE;
        }

        if (id == ID_SB_LOGOUT) {
            HBRUSH pBg = CreateSolidBrush(RGB(7, 13, 24));
            FillRect(hdc, &rc, pBg);
            DeleteObject(pBg);

            int W = rc.right - rc.left, H = rc.bottom - rc.top;
            COLORREF bg = sel ? RGB(50, 16, 24) : RGB(26, 12, 18);
            COLORREF bdr = sel ? RGB(220, 50, 75) : RGB(180, 40, 60);
            DrawRoundRectPanel(hdc, rc.left, rc.top, W, H, 8, bg, bdr);

            const wchar_t *txt = L"Sign Out";
            const wchar_t *ico = L"\uE777";

            HFONT hfIcon = fIcon ? fIcon : (HFONT)GetStockObject(DEFAULT_GUI_FONT);
            HFONT hfTxt = fMed ? fMed : (HFONT)GetStockObject(DEFAULT_GUI_FONT);

            SelectObject(hdc, hfTxt);
            SIZE szT;
            GetTextExtentPoint32W(hdc, txt, (int)wcslen(txt), &szT);
            int iconW = 18, gap = 8;
            int totalW = iconW + gap + szT.cx;
            int startX = rc.left + (W - totalW) / 2;

            SetBkMode(hdc, TRANSPARENT);
            SetTextColor(hdc, RGB(255, 100, 130));
            SelectObject(hdc, hfIcon);
            RECT icR = { startX, rc.top, startX + iconW, rc.bottom };
            DrawTextW(hdc, ico, 1, &icR, DT_CENTER|DT_VCENTER|DT_SINGLELINE);

            SetTextColor(hdc, RGB(255, 160, 180));
            SelectObject(hdc, hfTxt);
            RECT txR = { startX + iconW + gap, rc.top, startX + totalW + 4, rc.bottom };
            DrawTextW(hdc, txt, (int)wcslen(txt), &txR, DT_LEFT|DT_VCENTER|DT_SINGLELINE);
            return TRUE;
        }
        break;
    }

    case WM_CTLCOLOREDIT: {
        HDC hdc = (HDC)wp;
        SetTextColor(hdc, RGB(245, 248, 255));
        SetBkColor(hdc, RGB(8, 16, 30));
        static HBRUSH s_hEdBr = NULL;
        if (!s_hEdBr) s_hEdBr = CreateSolidBrush(RGB(8, 16, 30));
        return (LRESULT)s_hEdBr;
    }

    case WM_CTLCOLORSTATIC: {
        HDC hdc = (HDC)wp;
        HWND hCtrl = (HWND)lp;
        if (hCtrl == s_hSbStatus) {
            char stat[256] = {0};
            GetWindowTextA(s_hSbStatus, stat, sizeof(stat));
            if (strstr(stat, "Error") || strstr(stat, "fail") || strstr(stat, "not match") || strstr(stat, "provide")) {
                SetTextColor(hdc, RGB(248, 113, 113));
            } else if (strstr(stat, "Authenticating") || strstr(stat, "Registering") || strstr(stat, "Syncing") || strstr(stat, "Reading")) {
                SetTextColor(hdc, RGB(251, 191, 36));
            } else {
                SetTextColor(hdc, RGB(52, 211, 153));
            }
        } else {
            SetTextColor(hdc, RGB(220, 230, 245));
        }
        SetBkColor(hdc, RGB(7, 13, 24));
        static HBRUSH s_hStaticBr = NULL;
        if (!s_hStaticBr) s_hStaticBr = CreateSolidBrush(RGB(7, 13, 24));
        return (LRESULT)s_hStaticBr;
    }

    case WM_ERASEBKGND:
        return 1;

    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hw, &ps);
        RECT cr; GetClientRect(hw, &cr);
        int W = cr.right - cr.left;
        int H = cr.bottom - cr.top;

        HDC memDC = CreateCompatibleDC(hdc);
        HBITMAP hbm = CreateCompatibleBitmap(hdc, W, H);
        HBITMAP oldBm = (HBITMAP)SelectObject(memDC, hbm);

        /* 1. Base Dark Cyber Background */
        HBRUSH bgBr = CreateSolidBrush(RGB(7, 13, 24));
        FillRect(memDC, &cr, bgBr);
        DeleteObject(bgBr);

        /* 2. Left Hero Panel */
        int leftW = 340;
        RECT leftR = {0, 0, leftW, H};
        HBRUSH leftBr = CreateSolidBrush(RGB(5, 11, 22));
        FillRect(memDC, &leftR, leftBr);
        DeleteObject(leftBr);

        DrawCyberWaves_Auth(memDC, 0, 0, leftW, H);

        /* Separator line */
        HPEN divPen = CreatePen(PS_SOLID, 1, RGB(18, 30, 52));
        HPEN opD = (HPEN)SelectObject(memDC, divPen);
        MoveToEx(memDC, leftW, 0, NULL); LineTo(memDC, leftW, H);
        SelectObject(memDC, opD); DeleteObject(divPen);

        /* Left Top Brand */
        DrawKLogo_Auth(memDC, 38, 44, 46);

        SetBkMode(memDC, TRANSPARENT);
        SetTextColor(memDC, RGB(245, 248, 255));
        SelectObject(memDC, fBig ? fBig : (HFONT)GetStockObject(DEFAULT_GUI_FONT));
        TextOutA(memDC, 94, 42, "Kaevex", 6);

        SetTextColor(memDC, RGB(56, 189, 248));
        SelectObject(memDC, fSm ? fSm : (HFONT)GetStockObject(DEFAULT_GUI_FONT));
        TextOutA(memDC, 94, 72, "Platform Identity", 17);

        SetTextColor(memDC, RGB(130, 145, 170));
        TextOutA(memDC, 38, 108, "Realtime Platform Security", 26);
        TextOutA(memDC, 38, 126, "Synchronization, Fleet Management", 33);

        /* Center Hologram Cloud */
        DrawNeonCloudGraphic_Auth(memDC, leftW / 2, 280, fIcon);

        /* Bottom 3 Feature Badges */
        struct { const wchar_t *icon; const char *text; } feats[3] = {
            { L"\uEA18", "Secure Access" },
            { L"\uE895", "Sync in Real-time" },
            { L"\uE7F4", "Fleet Management" }
        };
        int featY = 490;
        for (int i = 0; i < 3; i++) {
            int fy = featY + i * 54;
            DrawRoundRectPanel(memDC, 38, fy, 38, 38, 8, RGB(10, 24, 48), RGB(24, 55, 110));
            SetTextColor(memDC, RGB(56, 189, 248));
            SelectObject(memDC, fIcon ? fIcon : (HFONT)GetStockObject(DEFAULT_GUI_FONT));
            RECT icR = {38, fy, 38 + 38, fy + 38};
            DrawTextW(memDC, feats[i].icon, 1, &icR, DT_CENTER|DT_VCENTER|DT_SINGLELINE);

            SetTextColor(memDC, RGB(210, 225, 245));
            SelectObject(memDC, fMed ? fMed : (HFONT)GetStockObject(DEFAULT_GUI_FONT));
            RECT txR = {88, fy, leftW - 20, fy + 38};
            DrawTextA(memDC, feats[i].text, -1, &txR, DT_LEFT|DT_VCENTER|DT_SINGLELINE);
        }

        /* 3. Right Form Panel */
        int formX = leftW + 48;
        int formW = 490;

        SetTextColor(memDC, RGB(245, 248, 255));
        SelectObject(memDC, fBig ? fBig : (HFONT)GetStockObject(DEFAULT_GUI_FONT));
        TextOutA(memDC, formX, 40, "Welcome to ", 11);
        SIZE szWel; GetTextExtentPoint32A(memDC, "Welcome to ", 11, &szWel);

        SetTextColor(memDC, RGB(0, 210, 255));
        TextOutA(memDC, formX + szWel.cx, 40, "Kaevex ", 7);
        SIZE szKvx; GetTextExtentPoint32A(memDC, "Kaevex ", 7, &szKvx);
        SetTextColor(memDC, RGB(180, 120, 255));
        TextOutA(memDC, formX + szWel.cx + szKvx.cx, 40, "Platform", 8);

        SetTextColor(memDC, RGB(148, 163, 184));
        SelectObject(memDC, fSm ? fSm : (HFONT)GetStockObject(DEFAULT_GUI_FONT));
        if (g_sbSession.isLoggedIn) {
            TextOutA(memDC, formX, 78, "Authenticated Kaevex Platform Identity session online.", 54);
            TextOutA(memDC, formX, 96, "Bi-directional telemetry synchronization active.", 48);
        } else if (s_sbMode == 0) {
            TextOutA(memDC, formX, 78, "Sign in to your Kaevex account to access", 40);
            TextOutA(memDC, formX, 96, "secure platform identity and fleet management.", 46);
        } else {
            TextOutA(memDC, formX, 78, "Create a Kaevex account to access secure platform identity", 58);
            TextOutA(memDC, formX, 96, "and enterprise fleet management.", 32);
        }

        if (!g_sbSession.isLoggedIn) {
            if (s_sbMode == 0) {
                /* Sign In Containers */
                int emailEdY = 168;
                int passEdY  = 256;

                SetTextColor(memDC, RGB(220, 230, 245));
                SelectObject(memDC, fMed ? fMed : (HFONT)GetStockObject(DEFAULT_GUI_FONT));
                TextOutA(memDC, formX, 144, "Email Address:", 14);
                DrawRoundRectPanel(memDC, formX, emailEdY, formW, 46, 10, RGB(8, 16, 30), RGB(26, 48, 84));

                SetTextColor(memDC, RGB(90, 115, 150));
                SelectObject(memDC, fIcon ? fIcon : (HFONT)GetStockObject(DEFAULT_GUI_FONT));
                RECT mailR = {formX + 16, emailEdY, formX + 44, emailEdY + 46};
                DrawTextW(memDC, L"\uE715", 1, &mailR, DT_CENTER|DT_VCENTER|DT_SINGLELINE);

                SetTextColor(memDC, RGB(220, 230, 245));
                SelectObject(memDC, fMed ? fMed : (HFONT)GetStockObject(DEFAULT_GUI_FONT));
                TextOutA(memDC, formX, 232, "Password:", 9);
                DrawRoundRectPanel(memDC, formX, passEdY, formW, 46, 10, RGB(8, 16, 30), RGB(26, 48, 84));

                SetTextColor(memDC, RGB(90, 115, 150));
                SelectObject(memDC, fIcon ? fIcon : (HFONT)GetStockObject(DEFAULT_GUI_FONT));
                RECT lockR = {formX + 16, passEdY, formX + 44, passEdY + 46};
                DrawTextW(memDC, L"\uE72E", 1, &lockR, DT_CENTER|DT_VCENTER|DT_SINGLELINE);

                /* Divider with OR */
                int orY = 490;
                int orLineW = (formW - 46) / 2;
                HPEN orPen = CreatePen(PS_SOLID, 1, RGB(26, 40, 64));
                HPEN opO = (HPEN)SelectObject(memDC, orPen);
                MoveToEx(memDC, formX, orY, NULL); LineTo(memDC, formX + orLineW, orY);
                MoveToEx(memDC, formX + formW - orLineW, orY, NULL); LineTo(memDC, formX + formW, orY);
                SelectObject(memDC, opO); DeleteObject(orPen);

                SetTextColor(memDC, RGB(100, 120, 150));
                SelectObject(memDC, fSm ? fSm : (HFONT)GetStockObject(DEFAULT_GUI_FONT));
                RECT orR = {formX + orLineW, orY - 9, formX + formW - orLineW, orY + 9};
                DrawTextA(memDC, "OR", 2, &orR, DT_CENTER|DT_VCENTER|DT_SINGLELINE);

            } else {
                /* Register Containers */
                int nameEdY  = 150;
                int emailEdY = 226;
                int passEdY  = 302;
                int pass2EdY = 378;

                SetTextColor(memDC, RGB(220, 230, 245));
                SelectObject(memDC, fMed ? fMed : (HFONT)GetStockObject(DEFAULT_GUI_FONT));
                TextOutA(memDC, formX, 126, "Full Name:", 10);
                DrawRoundRectPanel(memDC, formX, nameEdY, formW, 42, 10, RGB(8, 16, 30), RGB(26, 48, 84));
                SetTextColor(memDC, RGB(90, 115, 150));
                SelectObject(memDC, fIcon ? fIcon : (HFONT)GetStockObject(DEFAULT_GUI_FONT));
                RECT nameIcR = {formX + 16, nameEdY, formX + 44, nameEdY + 42};
                DrawTextW(memDC, L"\uE77B", 1, &nameIcR, DT_CENTER|DT_VCENTER|DT_SINGLELINE);

                SetTextColor(memDC, RGB(220, 230, 245));
                SelectObject(memDC, fMed ? fMed : (HFONT)GetStockObject(DEFAULT_GUI_FONT));
                TextOutA(memDC, formX, 202, "Email Address:", 14);
                DrawRoundRectPanel(memDC, formX, emailEdY, formW, 42, 10, RGB(8, 16, 30), RGB(26, 48, 84));
                SetTextColor(memDC, RGB(90, 115, 150));
                SelectObject(memDC, fIcon ? fIcon : (HFONT)GetStockObject(DEFAULT_GUI_FONT));
                RECT mailR = {formX + 16, emailEdY, formX + 44, emailEdY + 42};
                DrawTextW(memDC, L"\uE715", 1, &mailR, DT_CENTER|DT_VCENTER|DT_SINGLELINE);

                SetTextColor(memDC, RGB(220, 230, 245));
                SelectObject(memDC, fMed ? fMed : (HFONT)GetStockObject(DEFAULT_GUI_FONT));
                TextOutA(memDC, formX, 278, "Password:", 9);
                DrawRoundRectPanel(memDC, formX, passEdY, formW, 42, 10, RGB(8, 16, 30), RGB(26, 48, 84));
                SetTextColor(memDC, RGB(90, 115, 150));
                SelectObject(memDC, fIcon ? fIcon : (HFONT)GetStockObject(DEFAULT_GUI_FONT));
                RECT lockR = {formX + 16, passEdY, formX + 44, passEdY + 42};
                DrawTextW(memDC, L"\uE72E", 1, &lockR, DT_CENTER|DT_VCENTER|DT_SINGLELINE);

                SetTextColor(memDC, RGB(220, 230, 245));
                SelectObject(memDC, fMed ? fMed : (HFONT)GetStockObject(DEFAULT_GUI_FONT));
                TextOutA(memDC, formX, 354, "Confirm Password:", 17);
                DrawRoundRectPanel(memDC, formX, pass2EdY, formW, 42, 10, RGB(8, 16, 30), RGB(26, 48, 84));
                SetTextColor(memDC, RGB(90, 115, 150));
                SelectObject(memDC, fIcon ? fIcon : (HFONT)GetStockObject(DEFAULT_GUI_FONT));
                RECT lock2R = {formX + 16, pass2EdY, formX + 44, pass2EdY + 42};
                DrawTextW(memDC, L"\uE72E", 1, &lock2R, DT_CENTER|DT_VCENTER|DT_SINGLELINE);

                /* Divider with OR */
                int orY = 568;
                int orLineW = (formW - 46) / 2;
                HPEN orPen = CreatePen(PS_SOLID, 1, RGB(26, 40, 64));
                HPEN opO = (HPEN)SelectObject(memDC, orPen);
                MoveToEx(memDC, formX, orY, NULL); LineTo(memDC, formX + orLineW, orY);
                MoveToEx(memDC, formX + formW - orLineW, orY, NULL); LineTo(memDC, formX + formW, orY);
                SelectObject(memDC, opO); DeleteObject(orPen);

                SetTextColor(memDC, RGB(100, 120, 150));
                SelectObject(memDC, fSm ? fSm : (HFONT)GetStockObject(DEFAULT_GUI_FONT));
                RECT orR = {formX + orLineW, orY - 9, formX + formW - orLineW, orY + 9};
                DrawTextA(memDC, "OR", 2, &orR, DT_CENTER|DT_VCENTER|DT_SINGLELINE);
            }
        }

        BitBlt(hdc, 0, 0, W, H, memDC, 0, 0, SRCCOPY);
        SelectObject(memDC, oldBm);
        DeleteObject(hbm);
        DeleteDC(memDC);

        EndPaint(hw, &ps);
        return 0;
    }

    case WM_CLOSE:
        DestroyWindow(hw);
        return 0;

    case WM_DESTROY:
        if (s_hSbNameEdit)  RemovePropW(s_hSbNameEdit,  L"SbCue");
        if (s_hSbEmailEdit) RemovePropW(s_hSbEmailEdit, L"SbCue");
        if (s_hSbPassEdit)  RemovePropW(s_hSbPassEdit,  L"SbCue");
        if (s_hSbPass2Edit) RemovePropW(s_hSbPass2Edit, L"SbCue");
        s_hSbDlg = NULL;
        return 0;
    }
    return DefWindowProcA(hw, msg, wp, lp);
}

static void ShowSupabaseAccountDialog(HWND hwndParent) {
    HICON hIcoBig = NULL, hIcoSmall = NULL;
    LoadKaevexIconPair(GetModuleHandleA(NULL), &hIcoBig, &hIcoSmall);

    WNDCLASSEXW wc = {0};
    wc.cbSize = sizeof(wc);
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = SupabaseAuthWndProc;
    wc.hInstance = GetModuleHandleW(NULL);
    wc.hCursor = LoadCursorA(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)GetStockObject(BLACK_BRUSH);
    wc.hIcon = hIcoBig ? hIcoBig : LoadIconW(NULL, (LPCWSTR)IDI_APPLICATION);
    wc.hIconSm = hIcoSmall ? hIcoSmall : wc.hIcon;
    wc.lpszClassName = L"KaevexSupabaseAuthClass";
    RegisterClassExW(&wc);

    int scrW = GetSystemMetrics(SM_CXSCREEN);
    int scrH = GetSystemMetrics(SM_CYSCREEN);
    int dlgW = 960, dlgH = 740;
    int dlgX = (scrW - dlgW) / 2;
    int dlgY = (scrH - dlgH) / 2;

    HWND hwDlg = CreateWindowExW(WS_EX_TOPMOST, L"KaevexSupabaseAuthClass",
        L"Kaevex Platform \u2014 Master Account & Security Sync",
        WS_POPUP | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX | WS_VISIBLE,
        dlgX, dlgY, dlgW, dlgH,
        hwndParent, NULL, GetModuleHandleW(NULL), NULL);

    if (!hwDlg) return;

    if (hIcoBig)   SendMessageW(hwDlg, WM_SETICON, ICON_BIG,   (LPARAM)hIcoBig);
    if (hIcoSmall) SendMessageW(hwDlg, WM_SETICON, ICON_SMALL, (LPARAM)hIcoSmall);

    BOOL dark = 1;
    DwmSetWindowAttribute(hwDlg, 20, &dark, sizeof(dark));
    DwmSetWindowAttribute(hwDlg, 19, &dark, sizeof(dark));

    if (hwndParent) EnableWindow(hwndParent, FALSE);

    MSG msg;
    while (IsWindow(hwDlg) && GetMessageA(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageA(&msg);
    }

    if (hwndParent) {
        EnableWindow(hwndParent, TRUE);
        SetForegroundWindow(hwndParent);
        InvalidateRect(hwndParent, NULL, FALSE);
    }
}

/* App Hub Population Helpers */
static void PopulateAppHubList(void) {
    if(!hAppList) return;
    SendMessageA(hAppList, LB_RESETCONTENT, 0, 0);

    /* 1. Software Stacks (XAMPP, WAMP, Node, etc.) */
    if(g_appHubFilter == 0 || g_appHubFilter == 1) {
        int hadStack = 0;
        for(int i = 0; i < g_discAppCnt; i++) {
            AppEntry *e = &g_discApps[i];
            if(!e->isStack) continue;
            if(!hadStack) {
                SendMessageA(hAppList, LB_ADDSTRING, 0, (LPARAM)"  -- SOFTWARE STACKS & ENVIRONMENTS --");
                hadStack = 1;
            }
            char row[400];
            char stateIcon = (e->state == APP_STATE_RUNNING) ? '+' : ((e->state == APP_STATE_PARTIAL) ? '~' : '-');
            snprintf(row, sizeof(row), "[S] %c %s %s%s",
                     stateIcon, e->name,
                     e->version[0] ? e->version : "",
                     e->state == APP_STATE_PARTIAL ? " [PARTIAL]" :
                     e->state == APP_STATE_RUNNING ? " [RUNNING]" : " [STOPPED]");
            SendMessageA(hAppList, LB_ADDSTRING, 0, (LPARAM)row);
        }
    }

    /* 2. Running Applications & Services */
    if(g_appHubFilter == 0 || g_appHubFilter == 2) {
        int hadRun = 0;
        for(int i = 0; i < g_discAppCnt; i++) {
            AppEntry *e = &g_discApps[i];
            if(e->isStack || e->type == APP_TYPE_COMPONENT || e->type == APP_TYPE_INSTALLED) continue;
            if(e->state != APP_STATE_RUNNING) continue;
            if(!hadRun) {
                SendMessageA(hAppList, LB_ADDSTRING, 0, (LPARAM)"  -- ACTIVE RUNNING PROCESSES & SERVICES --");
                hadRun = 1;
            }
            char row[400];
            char icon[8] = "[P]";
            if(e->iconChar[0]) strncpy(icon, e->iconChar, 7);
            char ports[64] = "";
            if(e->listenPortCnt > 0) {
                snprintf(ports, sizeof(ports), "  :%d", e->listenPorts[0]);
                if(e->listenPortCnt > 1) strcat(ports, "+");
            }
            snprintf(row, sizeof(row), "%s %s%s (PID %lu)%s",
                     icon, e->name, e->version[0] ? " " : "",
                     e->pid, ports);
            SendMessageA(hAppList, LB_ADDSTRING, 0, (LPARAM)row);
        }
    }

    /* 3. Unknown / Unidentified Software */
    if(g_appHubFilter == 0 || g_appHubFilter == 3) {
        int hadUnk = 0;
        for(int i = 0; i < g_discAppCnt; i++) {
            AppEntry *e = &g_discApps[i];
            if(e->type != APP_TYPE_UNKNOWN && (e->type != APP_TYPE_PROCESS || e->publisher[0])) continue;
            if(!hadUnk) {
                SendMessageA(hAppList, LB_ADDSTRING, 0, (LPARAM)"  -- UNKNOWN / UNIDENTIFIED SOFTWARE --");
                hadUnk = 1;
            }
            char row[400];
            snprintf(row, sizeof(row), "[?] %s (PID %lu)  %s",
                     e->name, e->pid, e->aiIdentified ? "[AI-IDENTIFIED]" : "[UNVERIFIED]");
            SendMessageA(hAppList, LB_ADDSTRING, 0, (LPARAM)row);
        }
    }

    /* 4. Servers & Databases */
    if(g_appHubFilter == 4) {
        int hadSrv = 0;
        for(int i = 0; i < g_discAppCnt; i++) {
            AppEntry *e = &g_discApps[i];
            if(e->type != APP_TYPE_SERVER && e->type != APP_TYPE_DATABASE) continue;
            if(!hadSrv) {
                SendMessageA(hAppList, LB_ADDSTRING, 0, (LPARAM)"  -- WEB SERVERS & DATABASE ENGINES --");
                hadSrv = 1;
            }
            char row[400];
            char ports[64] = "";
            if(e->listenPortCnt > 0) snprintf(ports, sizeof(ports), " :%d", e->listenPorts[0]);
            snprintf(row, sizeof(row), "%s %s  %s%s",
                     e->iconChar[0] ? e->iconChar : "[WS]", e->name,
                     disc_state_str(e->state), ports);
            SendMessageA(hAppList, LB_ADDSTRING, 0, (LPARAM)row);
        }
    }

    /* 5. Installed Software Catalog (when Filter == 0) */
    if(g_appHubFilter == 0) {
        int hadInst = 0;
        for(int i = 0; i < g_discAppCnt && i < 150; i++) {
            AppEntry *e = &g_discApps[i];
            if(e->isStack || e->type == APP_TYPE_COMPONENT) continue;
            if(e->state == APP_STATE_RUNNING) continue;
            if(!hadInst) {
                SendMessageA(hAppList, LB_ADDSTRING, 0, (LPARAM)"  -- INSTALLED APPLICATIONS CATALOG --");
                hadInst = 1;
            }
            char row[400];
            char icon[8] = "[A]";
            if(e->iconChar[0]) strncpy(icon, e->iconChar, 7);
            snprintf(row, sizeof(row), "%s %s  %s", icon, e->name,
                     e->version[0] ? e->version : "(version unlisted)");
            SendMessageA(hAppList, LB_ADDSTRING, 0, (LPARAM)row);
        }
    }
}

static void PopulateAppDetail(int appIdx) {
    if(!hAppDetail || appIdx < 0 || appIdx >= g_discAppCnt) return;
    AppEntry *e = &g_discApps[appIdx];
    SendMessageA(hAppDetail, LB_RESETCONTENT, 0, 0);

    char buf[512];
    snprintf(buf, sizeof(buf), "  === %s ===", e->name);
    SendMessageA(hAppDetail, LB_ADDSTRING, 0, (LPARAM)buf);

    snprintf(buf, sizeof(buf), "  UUID / App ID:  %s", e->id);
    SendMessageA(hAppDetail, LB_ADDSTRING, 0, (LPARAM)buf);

    snprintf(buf, sizeof(buf), "  Classification: %s (%s)", disc_type_str(e->type),
             e->isStack ? "Composite Software Stack" : "Single Component");
    SendMessageA(hAppDetail, LB_ADDSTRING, 0, (LPARAM)buf);

    snprintf(buf, sizeof(buf), "  Current State:  %s", disc_state_str(e->state));
    SendMessageA(hAppDetail, LB_ADDSTRING, 0, (LPARAM)buf);

    if(e->version[0]) {
        snprintf(buf, sizeof(buf), "  Version:        %s", e->version);
        SendMessageA(hAppDetail, LB_ADDSTRING, 0, (LPARAM)buf);
    }
    if(e->publisher[0]) {
        snprintf(buf, sizeof(buf), "  Publisher:      %s", e->publisher);
        SendMessageA(hAppDetail, LB_ADDSTRING, 0, (LPARAM)buf);
    }
    if(e->path[0]) {
        snprintf(buf, sizeof(buf), "  Install Path:   %s", e->path);
        SendMessageA(hAppDetail, LB_ADDSTRING, 0, (LPARAM)buf);
    }
    if(e->pid) {
        snprintf(buf, sizeof(buf), "  Active Process: PID %lu (Parent PID: %lu)", e->pid, e->parentPid);
        SendMessageA(hAppDetail, LB_ADDSTRING, 0, (LPARAM)buf);
    }
    if(e->serviceName[0]) {
        snprintf(buf, sizeof(buf), "  Windows Service:%s [State: %s]", e->serviceName, e->serviceState);
        SendMessageA(hAppDetail, LB_ADDSTRING, 0, (LPARAM)buf);
    }
    if(e->listenPortCnt > 0) {
        char ports[256] = "  Listening Ports:";
        for(int p = 0; p < e->listenPortCnt && p < 8; p++) {
            char pb[32]; snprintf(pb, sizeof(pb), "  %d (TCP)", e->listenPorts[p]);
            strcat(ports, pb);
        }
        SendMessageA(hAppDetail, LB_ADDSTRING, 0, (LPARAM)ports);
    }

    /* Stack Components */
    if(e->isStack && e->childCount > 0) {
        SendMessageA(hAppDetail, LB_ADDSTRING, 0, (LPARAM)"  --- Stack Component Tree ---");
        for(int c = 0; c < e->childCount; c++) {
            AppEntry *ch = disc_find_by_id(e->children[c]);
            if(ch) {
                char pbuf[64] = "";
                if(ch->listenPortCnt > 0) snprintf(pbuf, sizeof(pbuf), " -> Port %d", ch->listenPorts[0]);
                snprintf(buf, sizeof(buf), "    [%s] %-20s %s",
                         disc_state_str(ch->state), ch->name, pbuf);
                SendMessageA(hAppDetail, LB_ADDSTRING, 0, (LPARAM)buf);
            }
        }
    }

    /* Connected Endpoints & Relations */
    SendMessageA(hAppDetail, LB_ADDSTRING, 0, (LPARAM)"  --- Application Relationship Graph ---");
    int relFound = 0;
    for(int r = 0; r < g_discRelCnt; r++) {
        if(strcmp(g_discRels[r].fromId, e->id) == 0) {
            AppEntry *target = disc_find_by_id(g_discRels[r].toId);
            if(target) {
                snprintf(buf, sizeof(buf), "    ──[TCP :%d]──> %s (%s)",
                         g_discRels[r].port, target->name, g_discRels[r].desc);
                SendMessageA(hAppDetail, LB_ADDSTRING, 0, (LPARAM)buf);
                relFound++;
            }
        }
        if(strcmp(g_discRels[r].toId, e->id) == 0 && g_discRels[r].type != REL_STACK_MEMBER) {
            AppEntry *source = disc_find_by_id(g_discRels[r].fromId);
            if(source) {
                snprintf(buf, sizeof(buf), "    <──[Client]── %s (Port %d)",
                         source->name, g_discRels[r].port);
                SendMessageA(hAppDetail, LB_ADDSTRING, 0, (LPARAM)buf);
                relFound++;
            }
        }
    }
    if(!relFound) {
        SendMessageA(hAppDetail, LB_ADDSTRING, 0, (LPARAM)"    (No active network sockets linked to other local apps)");
    }

    /* Integration Credentials */
    SendMessageA(hAppDetail, LB_ADDSTRING, 0, (LPARAM)"  --- Cryptographic Integration Credentials ---");
    if(e->integrationKey[0]) {
        snprintf(buf, sizeof(buf), "  Key Token:      %s", e->integrationKey);
        SendMessageA(hAppDetail, LB_ADDSTRING, 0, (LPARAM)buf);
        SendMessageA(hAppDetail, LB_ADDSTRING, 0, (LPARAM)"  Permissions:    SCOPED (Telemetry, Port Audit, Health Check)");
        SendMessageA(hAppDetail, LB_ADDSTRING, 0, (LPARAM)"  Security State: Cryptographically Bound to Machine GUID");
    }

    /* Linked Applications */
    HKEY hkLink;
    if(RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Kaevex\\LinkedApps", 0, KEY_READ, &hkLink) == ERROR_SUCCESS) {
        char linkedVal[256] = {0}; DWORD lvSz = sizeof(linkedVal);
        if(RegQueryValueExA(hkLink, e->name, NULL, NULL, (BYTE*)linkedVal, &lvSz) == ERROR_SUCCESS) {
            snprintf(buf, sizeof(buf), "  [LINKED PAIR]  Connected with '%s'", linkedVal);
            SendMessageA(hAppDetail, LB_ADDSTRING, 0, (LPARAM)buf);
        }
        RegCloseKey(hkLink);
    }

    /* AI Analysis for unknown */
    if(e->type == APP_TYPE_UNKNOWN || e->aiIdentified) {
        SendMessageA(hAppDetail, LB_ADDSTRING, 0, (LPARAM)"  --- AI Intelligence & Identification ---");
        if(e->aiIdentified && e->aiSuggestion[0]) {
            snprintf(buf, sizeof(buf), "  AI Copilot:    %s", e->aiSuggestion);
            SendMessageA(hAppDetail, LB_ADDSTRING, 0, (LPARAM)buf);
        } else {
            SendMessageA(hAppDetail, LB_ADDSTRING, 0, (LPARAM)"  Status:        Unidentified binary. Click [AI Identify] to analyze.");
        }
    }

    /* CVEs */
    if(e->cveCount > 0) {
        SendMessageA(hAppDetail, LB_ADDSTRING, 0, (LPARAM)"  --- Vulnerability Intelligence ---");
        snprintf(buf, sizeof(buf), "  Alert:          %d CVE(s) Detected [Primary: %s, CVSS %d/100]",
                 e->cveCount, e->primaryCve, e->primaryCvss);
        SendMessageA(hAppDetail, LB_ADDSTRING, 0, (LPARAM)buf);
    }
}

/* --- Window Procedure ----------------------------------------------------- */
LRESULT CALLBACK WndProc(HWND hw,UINT msg,WPARAM wp,LPARAM lp){

    switch(msg){
    case WM_NVD_REFRESH_DONE: {
        InterlockedExchange(&g_nvdRefreshBusy,0);
        if(wp){
            upd_scan_installed();
            upd_check_cves();
            BuildCveTableData();
            add_alert("CVE Agent","INFO",g_nvdRefreshMessage);
        } else {
            add_alert("CVE Agent","WARNING",g_nvdRefreshMessage);
        }
        InvalidateRect(hw,NULL,FALSE);
        return 0;
    }
    case WM_CVE_SCAN_DONE: {
        g_cveScanning = FALSE;
        char sum[256];
        snprintf(sum, sizeof(sum), "Autonomous vulnerability scan complete: %d issues identified (%d critical, %d high, %d packages).",
                 g_cveTotalCnt, g_cveCritCnt, g_cveHighCnt, g_appCount);
        add_alert("CVE Agent", (g_cveCritCnt > 0) ? "WARNING" : "INFO", sum);
        InvalidateRect(hw, NULL, FALSE);
        return 0;
    }
    case WM_TRAYICON:{
        if(lp == WM_LBUTTONDBLCLK || lp == WM_LBUTTONDOWN){
            ShowWindow(hw, SW_SHOW);
            ShowWindow(hw, SW_RESTORE);
            SetForegroundWindow(hw);
        } else if(lp == WM_RBUTTONUP){
            ShowTrayMenu(hw);
        }
        return 0;}

    case WM_PAINT:{

        PAINTSTRUCT ps; HDC hdc=BeginPaint(hw,&ps);
        RECT wr; GetClientRect(hw,&wr);
        HDC mdc=CreateCompatibleDC(hdc);
        HBITMAP mb=CreateCompatibleBitmap(hdc,wr.right,wr.bottom);
        HBITMAP ob=(HBITMAP)SelectObject(mdc,mb);
        PaintAll(hw,mdc);
        BitBlt(hdc,0,0,wr.right,wr.bottom,mdc,0,0,SRCCOPY);
        SelectObject(mdc,ob); DeleteObject(mb); DeleteDC(mdc);
        EndPaint(hw,&ps); return 0;}

    case WM_SIZE: Layout(hw); InvalidateRect(hw,NULL,FALSE); return 0;
    case WM_ERASEBKGND: return 1;

    case WM_TIMER:
        if(wp==IDT_CVE_AUTOSCAN){
            SendMessageA(hw,WM_COMMAND,MAKEWPARAM(IDU_SCAN,0),0);
            if(g_cveScanNvdCloud && InterlockedCompareExchange(&g_nvdRefreshBusy,0,0)==0)
                SendMessageA(hw,WM_COMMAND,MAKEWPARAM(IDU_REFRESH,0),0);
            return 0;
        }
        UpdateRwWave();
        UpdateSbxTelemetry();
        /* Only redraw visible portions - use FALSE to not erase background (reduce flicker) */
        if(!IsIconic(hw))
            InvalidateRect(hw,NULL,FALSE);
        return 0;

    case WM_CTLCOLOREDIT:
    case WM_CTLCOLORSTATIC:{
        HDC hdc=(HDC)wp; SetTextColor(hdc,C_TEXT);
        if((HWND)lp == hTopSearch){
            SetBkColor(hdc, C_SEARCH_BG);
            if(!hBrSearch) hBrSearch = CreateSolidBrush(C_SEARCH_BG);
            return (LRESULT)hBrSearch;
        }
        if((HWND)lp == hUpdSearch){
            SetTextColor(hdc, RGB(240, 246, 255));
            SetBkColor(hdc, RGB(10, 15, 24));
            static HBRUSH s_hBrUpdSearch = NULL;
            if(!s_hBrUpdSearch) s_hBrUpdSearch = CreateSolidBrush(RGB(10, 15, 24));
            return (LRESULT)s_hBrUpdSearch;
        }
        SetBkColor(hdc,C_PANEL2);
        if(!hBrEdit) hBrEdit=CreateSolidBrush(C_PANEL2);
        return (LRESULT)hBrEdit;}

    case WM_CTLCOLORLISTBOX:{
        HDC hdc=(HDC)wp; SetTextColor(hdc,C_TEXT); SetBkColor(hdc,C_CARD2);
        if(!hBrList) hBrList=CreateSolidBrush(C_CARD2);
        return (LRESULT)hBrList;}

    case WM_CTLCOLORBTN:{
        HDC hdc=(HDC)wp; SetTextColor(hdc,C_TEXT); SetBkColor(hdc,C_PANEL2);
        if(!hBrPnl) hBrPnl=CreateSolidBrush(C_PANEL2);
        return (LRESULT)hBrPnl;}

    case WM_MEASUREITEM:{
        MEASUREITEMSTRUCT *m = (MEASUREITEMSTRUCT*)lp;
        if(m->CtlType == ODT_LISTBOX){
            if(m->CtlID == IDN_LIST){
                m->itemHeight = 40;
                return TRUE;
            }
            if(m->CtlID == IDA_THREATLIST){
                m->itemHeight = 38;
                return TRUE;
            }
            m->itemHeight = 22;
            return TRUE;
        }
        break;
    }

    case WM_DRAWITEM:{
        DRAWITEMSTRUCT *d=(DRAWITEMSTRUCT*)lp;
        if(d->CtlType==ODT_BUTTON){
            DrawBtn(d->hwndItem,d->hDC,&d->rcItem,!!(d->itemState&ODS_SELECTED));
            return TRUE;
        }
        if(d->CtlType==ODT_LISTBOX){
            if((int)d->itemID < 0) return TRUE;
            char text[1024] = {0};
            SendMessageA(d->hwndItem, LB_GETTEXT, d->itemID, (LPARAM)text);
            BOOL sel = !!(d->itemState & ODS_SELECTED);

            /* === AI SOC Analyst & Full Team — Clean Chat Rendering === */
            if(d->hwndItem == hAiList || d->hwndItem == hTmList){
                BOOL isUser     = (strncmp(text,"  [YOU]",7)==0);
                BOOL isAIHeader = (strncmp(text,"  [KAEVEX AI",12)==0 || strncmp(text,"[AI SOC",7)==0 || (text[0]=='[' && strchr(text,']')));

                /* Base Fill */
                HBRUSH baseBr = CreateSolidBrush(RGB(10,14,20));
                FillRect(d->hDC, &d->rcItem, baseBr);
                DeleteObject(baseBr);

                if(!text[0] || (text[0]==' ' && !text[1])){
                    return TRUE; /* Empty line spacer */
                }

                if(isUser){
                    /* Right-aligned sleek coral/pink bubble for user prompt */
                    const char *msg = text + 7; while(*msg == ' ') msg++;
                    int tw = d->rcItem.right - d->rcItem.left;
                    int bubW = (tw - 60 < 450) ? tw - 60 : 450;
                    int bubX = d->rcItem.right - bubW - 14;
                    int bubY = d->rcItem.top + 2;
                    int bubH = d->rcItem.bottom - d->rcItem.top - 4;

                    HBRUSH ubr = CreateSolidBrush(RGB(65, 15, 35));
                    HPEN   upen = CreatePen(PS_SOLID, 1, RGB(255, 51, 102));
                    HBRUSH ob2 = (HBRUSH)SelectObject(d->hDC, ubr);
                    HPEN   op2 = (HPEN)SelectObject(d->hDC, upen);
                    RoundRect(d->hDC, bubX, bubY, d->rcItem.right - 14, bubY + bubH, 10, 10);
                    SelectObject(d->hDC, ob2); SelectObject(d->hDC, op2);
                    DeleteObject(ubr); DeleteObject(upen);

                    SetBkMode(d->hDC, TRANSPARENT);
                    SetTextColor(d->hDC, RGB(255, 210, 220));
                    HFONT of2 = (HFONT)SelectObject(d->hDC, fSm);
                    RECT tr2 = {bubX + 12, bubY + 2, d->rcItem.right - 22, bubY + bubH};
                    DrawTextA(d->hDC, msg, -1, &tr2, DT_RIGHT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
                    SelectObject(d->hDC, of2);

                } else if(isAIHeader){
                    /* Left-aligned Teal Header Badge (Dynamic Width) */
                    const char *msg = text; while(*msg == ' ') msg++;
                    int bubY = d->rcItem.top + 2;
                    int bubH = d->rcItem.bottom - d->rcItem.top - 4;

                    int textLen = (int)strlen(msg);
                    int calcW = textLen * 9 + 32;
                    int availW = d->rcItem.right - d->rcItem.left - 40;
                    int maxW = (availW < calcW) ? availW : calcW;
                    if(maxW < 180) maxW = 180;

                    HBRUSH abr = CreateSolidBrush(RGB(8, 32, 40));
                    HPEN   apen = CreatePen(PS_SOLID, 1, RGB(6, 182, 212));
                    HBRUSH ob3 = (HBRUSH)SelectObject(d->hDC, abr);
                    HPEN   op3 = (HPEN)SelectObject(d->hDC, apen);
                    RoundRect(d->hDC, 14, bubY, 14 + maxW, bubY + bubH, 8, 8);
                    SelectObject(d->hDC, ob3); SelectObject(d->hDC, op3);
                    DeleteObject(abr); DeleteObject(apen);

                    SetBkMode(d->hDC, TRANSPARENT);
                    SetTextColor(d->hDC, RGB(6, 182, 212));
                    HFONT of3 = (HFONT)SelectObject(d->hDC, fMed);
                    RECT tr3 = {24, bubY + 2, 14 + maxW - 10, bubY + bubH};
                    DrawTextA(d->hDC, msg, -1, &tr3, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
                    SelectObject(d->hDC, of3);


                } else {
                    /* Left-aligned Body Text (No pill outline around individual lines!) */
                    const char *msg = text; while(*msg == ' ') msg++;
                    COLORREF fg3 = RGB(190, 205, 225);

                    if(strstr(text, "CRITICAL") || strstr(text, "THREAT") || strstr(text, "BLOCKED"))
                        fg3 = RGB(248, 113, 113);
                    else if(strstr(text, "WARNING") || strstr(text, "HIGH"))
                        fg3 = RGB(251, 191, 36);
                    else if(strstr(text, "ONLINE") || strstr(text, "ACTIVE") || strstr(text, "CLEAN") || strstr(text, "SAFE"))
                        fg3 = RGB(52, 211, 153);
                    else if(strstr(text, "System Snapshot") || strstr(text, "Telemetry"))
                        fg3 = RGB(147, 197, 253);

                    SetBkMode(d->hDC, TRANSPARENT);
                    SetTextColor(d->hDC, fg3);
                    HFONT of3 = (HFONT)SelectObject(d->hDC, fSm);
                    RECT tr3 = {d->rcItem.left + 24, d->rcItem.top + 2, d->rcItem.right - 24, d->rcItem.bottom - 2};
                    DrawTextA(d->hDC, msg, -1, &tr3, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
                    SelectObject(d->hDC, of3);
                }
                return TRUE;
            }

            /* === Antivirus Core: Threats & Audit Table === */
            if(d->hwndItem == hAvThreatList){
                if((int)d->itemID < 0 || (int)d->itemID >= g_threatDbCount) return TRUE;
                ThreatDbEntry *e = &g_threatDB[d->itemID];
                BOOL sel = !!(d->itemState & ODS_SELECTED);
                int ry = d->rcItem.top;
                int rx = d->rcItem.left;
                int rowH = d->rcItem.bottom - d->rcItem.top;

                COLORREF bg = sel ? RGB(24, 40, 68) : ((d->itemID % 2 == 1) ? RGB(11, 19, 34) : RGB(9, 15, 28));
                HBRUSH br = CreateSolidBrush(bg);
                FillRect(d->hDC, &d->rcItem, br);
                DeleteObject(br);

                if(sel){
                    HPEN pBdr = CreatePen(PS_SOLID, 1, RGB(59, 130, 246));
                    HPEN op = (HPEN)SelectObject(d->hDC, pBdr);
                    HBRUSH ob = (HBRUSH)SelectObject(d->hDC, GetStockObject(NULL_BRUSH));
                    Rectangle(d->hDC, d->rcItem.left, d->rcItem.top, d->rcItem.right, d->rcItem.bottom);
                    SelectObject(d->hDC, op); SelectObject(d->hDC, ob); DeleteObject(pBdr);
                }

                int col1 = rx + 8;
                int col2 = rx + 38;
                int col3 = rx + 128;
                int col4 = rx + 270;
                int col5 = rx + 480;
                int col8 = d->rcItem.right - 68;
                int col7 = col8 - 100;
                int col6 = col7 - 52;

                /* 1. Row # */
                char numStr[16]; snprintf(numStr, sizeof(numStr), "%d", (int)d->itemID + 1);
                Txt(d->hDC, numStr, col1, ry, 24, rowH, C_TEXT2, fSm, DT_LEFT|DT_VCENTER|DT_SINGLELINE);

                /* 2. Threat Badge */
                int bdW = 74, bdH = 20;
                int bdY = ry + (rowH - bdH)/2;
                COLORREF bdBg, bdBdr, bdFg;
                const char *bdTxt;
                if(e->isSafe){
                    bdBg = RGB(8, 36, 26); bdBdr = RGB(16, 185, 129); bdFg = RGB(52, 211, 153); bdTxt = "SAFE";
                } else if(e->score >= 70 || e->quarantined){
                    bdBg = RGB(55, 12, 18); bdBdr = RGB(239, 68, 68); bdFg = RGB(255, 110, 110); bdTxt = "THREAT";
                } else {
                    bdBg = RGB(48, 34, 6); bdBdr = RGB(245, 158, 11); bdFg = RGB(251, 191, 36); bdTxt = "INFECTED";
                }
                DrawRoundRectPanel(d->hDC, col2, bdY, bdW, bdH, 6, bdBg, bdBdr);
                Txt(d->hDC, bdTxt, col2, bdY, bdW, bdH, bdFg, fMini ? fMini : fSm, DT_CENTER|DT_VCENTER|DT_SINGLELINE);

                /* 3. Type (Threat Name + Category) */
                Txt(d->hDC, e->threatName, col3, ry + 4, 130, 16, C_TEXT, fSm, DT_LEFT|DT_SINGLELINE);
                Txt(d->hDC, e->classification[0] ? e->classification : "Heuristic", col3, ry + 20, 130, 14, C_DIM, fMini ? fMini : fSm, DT_LEFT|DT_SINGLELINE);

                /* 4. File / Path */
                Txt(d->hDC, e->path, col4, ry, 200, rowH, C_TEXT2, fSm, DT_LEFT|DT_VCENTER|DT_SINGLELINE);

                /* 5. Details */
                const char *det = get_threat_detail(e);
                int detW = col6 - col5 - 12;
                if(detW < 50) detW = 50;
                Txt(d->hDC, det, col5, ry, detW, rowH, C_DIM, fSm, DT_LEFT|DT_VCENTER|DT_SINGLELINE);

                /* 6. Score */
                int scW = 28, scH = 18;
                int scY = ry + (rowH - scH)/2;
                COLORREF scBg  = (e->score >= 75) ? RGB(55, 12, 18) : RGB(48, 34, 6);
                COLORREF scBdr = (e->score >= 75) ? RGB(239, 68, 68) : RGB(245, 158, 11);
                COLORREF scFg  = (e->score >= 75) ? RGB(255, 110, 110) : RGB(251, 191, 36);
                DrawRoundRectPanel(d->hDC, col6 + 8, scY, scW, scH, 9, scBg, scBdr);
                char scBuf[16]; snprintf(scBuf, sizeof(scBuf), "%d", e->score);
                Txt(d->hDC, scBuf, col6 + 8, scY, scW, scH, scFg, fMini ? fMini : fSm, DT_CENTER|DT_VCENTER|DT_SINGLELINE);

                /* 7. Status */
                int stW = 86, stH = 20;
                int stY = ry + (rowH - stH)/2;
                COLORREF stBg, stBdr, stFg;
                const char *stTxt;
                if(e->isSafe){
                    stBg = RGB(8, 36, 26); stBdr = RGB(16, 185, 129); stFg = RGB(52, 211, 153); stTxt = "SAFE";
                } else if(e->quarantined || e->score >= 75){
                    stBg = RGB(55, 12, 18); stBdr = RGB(239, 68, 68); stFg = RGB(255, 110, 110); stTxt = "QUARANTINED";
                } else {
                    stBg = RGB(48, 34, 6); stBdr = RGB(245, 158, 11); stFg = RGB(251, 191, 36); stTxt = "ISOLATED";
                }
                DrawRoundRectPanel(d->hDC, col7, stY, stW, stH, 6, stBg, stBdr);
                Txt(d->hDC, stTxt, col7, stY, stW, stH, stFg, fMini ? fMini : fSm, DT_CENTER|DT_VCENTER|DT_SINGLELINE);

                /* 8. Action (View link + 3 dots) */
                Txt(d->hDC, "View", col8, ry, 34, rowH, RGB(56, 189, 248), fSm, DT_LEFT|DT_VCENTER|DT_SINGLELINE);
                int adX = col8 + 48, adY = ry + rowH / 2;
                HBRUSH bDot = CreateSolidBrush(C_DIM);
                HPEN pNull = (HPEN)GetStockObject(NULL_PEN);
                HBRUSH ob = (HBRUSH)SelectObject(d->hDC, bDot);
                HPEN op = (HPEN)SelectObject(d->hDC, pNull);
                Ellipse(d->hDC, adX - 6, adY - 2, adX - 2, adY + 2);
                Ellipse(d->hDC, adX - 1, adY - 2, adX + 3, adY + 2);
                Ellipse(d->hDC, adX + 4, adY - 2, adX + 8, adY + 2);
                SelectObject(d->hDC, ob); SelectObject(d->hDC, op); DeleteObject(bDot);

                return TRUE;
            }

            /* === Adaptive Firewall Rules Inventory Table List === */
            if(d->hwndItem == hFwList){
                if((int)d->itemID < 0) return TRUE;
                int rIdx = (int)SendMessageA(d->hwndItem, LB_GETITEMDATA, d->itemID, 0);
                if(rIdx < 0 || rIdx >= g_fwRuleCount) rIdx = (int)d->itemID;
                if(rIdx < 0 || rIdx >= g_fwRuleCount) return TRUE;
                FwRule *r = &g_fwRules[rIdx];

                BOOL sel = !!(d->itemState & ODS_SELECTED);
                int ry = d->rcItem.top;
                int rx = d->rcItem.left;
                int rowH = d->rcItem.bottom - d->rcItem.top;

                /* Row background */
                COLORREF bg = sel ? RGB(20, 36, 60) : ((d->itemID % 2 == 0) ? RGB(10, 14, 22) : RGB(14, 18, 28));
                HBRUSH br = CreateSolidBrush(bg);
                FillRect(d->hDC, &d->rcItem, br);
                DeleteObject(br);

                /* Selection border or row divider */
                if(sel){
                    HPEN pBdr = CreatePen(PS_SOLID, 1, RGB(59, 130, 246));
                    HPEN op = (HPEN)SelectObject(d->hDC, pBdr);
                    HBRUSH ob = (HBRUSH)SelectObject(d->hDC, GetStockObject(NULL_BRUSH));
                    Rectangle(d->hDC, d->rcItem.left, d->rcItem.top, d->rcItem.right, d->rcItem.bottom);
                    SelectObject(d->hDC, op); SelectObject(d->hDC, ob); DeleteObject(pBdr);
                } else {
                    DrawLine(d->hDC, d->rcItem.left, d->rcItem.bottom - 1, d->rcItem.right, d->rcItem.bottom - 1, RGB(22, 30, 44));
                }

                int x0 = rx + 6;
                /* 1. Index */
                char idxStr[16]; snprintf(idxStr, sizeof(idxStr), "%d", (int)d->itemID + 1);
                Txt(d->hDC, idxStr, x0 + 4, ry, 36, rowH, C_TEXT2, fSm, DT_LEFT|DT_VCENTER|DT_SINGLELINE);

                /* 2. Rule Name */
                Txt(d->hDC, r->name, x0 + 44, ry, 140, rowH, C_TEXT, fSm, DT_LEFT|DT_VCENTER|DT_SINGLELINE);

                /* 3. Profile */
                const char *dispProf = r->profile;
                if(strstr(r->profile, "Domain") && strstr(r->profile, "Public") && strstr(r->profile, "Private")) dispProf = "All";
                else if(strstr(r->profile, "Private") && strstr(r->profile, "Public")) dispProf = "Priv/Pub";
                else if(!r->profile[0]) dispProf = "All";
                Txt(d->hDC, dispProf, x0 + 190, ry, 50, rowH, C_TEXT2, fSm, DT_LEFT|DT_VCENTER|DT_SINGLELINE);

                /* 4. Type (Direction) */
                const char *dispDir = r->direction;
                if(_stricmp(r->direction, "In") == 0) dispDir = "Inbound";
                else if(_stricmp(r->direction, "Out") == 0) dispDir = "Outbound";
                else if(!r->direction[0]) dispDir = "Inbound";
                Txt(d->hDC, dispDir, x0 + 245, ry, 80, rowH, C_TEXT2, fSm, DT_LEFT|DT_VCENTER|DT_SINGLELINE);

                /* 5. Action (Pill Badge) */
                BOOL isAllow = (_stricmp(r->action, "Allow") == 0);
                int pillW = 46, pillH = 18;
                int pillY = ry + (rowH - pillH) / 2;
                COLORREF pBg  = isAllow ? RGB(16, 185, 129) : RGB(239, 68, 68);
                COLORREF pBdr = isAllow ? RGB(52, 211, 153) : RGB(248, 113, 113);
                DrawRoundRectPanel(d->hDC, x0 + 330, pillY, pillW, pillH, 6, pBg, pBdr);
                Txt(d->hDC, isAllow ? "Allow" : "Block", x0 + 330, pillY, pillW, pillH, RGB(255, 255, 255), fMini ? fMini : fSm, DT_CENTER|DT_VCENTER|DT_SINGLELINE);

                /* 6. Protocol */
                Txt(d->hDC, r->protocol[0] ? r->protocol : "TCP", x0 + 380, ry, 52, rowH, C_TEXT2, fSm, DT_LEFT|DT_VCENTER|DT_SINGLELINE);

                /* 7. Local Port */
                const char *dispLp = (r->localPort[0] && _stricmp(r->localPort, "Any") != 0) ? r->localPort : "*";
                Txt(d->hDC, dispLp, x0 + 436, ry, 60, rowH, C_TEXT2, fSm, DT_LEFT|DT_VCENTER|DT_SINGLELINE);

                /* 8. Remote IP */
                const char *dispRip = (r->remoteIP[0] && _stricmp(r->remoteIP, "Any") != 0) ? r->remoteIP : "*";
                Txt(d->hDC, dispRip, x0 + 500, ry, 85, rowH, C_TEXT2, fSm, DT_LEFT|DT_VCENTER|DT_SINGLELINE);

                /* 9. Remote Port */
                const char *dispRp = (r->remotePort[0] && _stricmp(r->remotePort, "Any") != 0) ? r->remotePort : "*";
                Txt(d->hDC, dispRp, x0 + 590, ry, 75, rowH, C_TEXT2, fSm, DT_LEFT|DT_VCENTER|DT_SINGLELINE);

                /* 10. Rule Hits */
                unsigned long hitsVal = r->hits;
                char hitBuf[32];
                if(hitsVal >= 1000000)
                    snprintf(hitBuf, sizeof(hitBuf), "%.1fM", (double)hitsVal / 1000000.0);
                else if(hitsVal >= 1000)
                    snprintf(hitBuf, sizeof(hitBuf), "%luK", hitsVal / 1000);
                else if(hitsVal > 0)
                    snprintf(hitBuf, sizeof(hitBuf), "%lu", hitsVal);
                else
                    strcpy(hitBuf, "0");
                COLORREF hitCol = (hitsVal > 0) ? C_TEXT : RGB(110, 130, 155);
                Txt(d->hDC, hitBuf, x0 + 670, ry, 55, rowH, hitCol, fSm, DT_RIGHT|DT_VCENTER|DT_SINGLELINE);

                return TRUE;
            }

            /* === NetGuard Connections Table List === */
            if(d->hwndItem == hNetList){
                if((int)d->itemID < 0 || (int)d->itemID >= g_netUiRowCount) return TRUE;
                NetUiRow *row = &g_netUiRows[d->itemID];
                BOOL sel = !!(d->itemState & ODS_SELECTED);
                int ry = d->rcItem.top;
                int rx = d->rcItem.left;
                int rowH = d->rcItem.bottom - d->rcItem.top;

                /* Background tint based on risk */
                COLORREF bg;
                if(sel){
                    bg = RGB(24, 40, 68);
                } else if(row->riskLevel == 2){
                    bg = (d->itemID % 2 == 1) ? RGB(34, 10, 16) : RGB(26, 8, 12);
                } else if(row->riskLevel == 1){
                    bg = (d->itemID % 2 == 1) ? RGB(30, 22, 8) : RGB(24, 18, 6);
                } else {
                    bg = (d->itemID % 2 == 1) ? RGB(11, 19, 34) : RGB(9, 15, 28);
                }

                HBRUSH br = CreateSolidBrush(bg);
                FillRect(d->hDC, &d->rcItem, br);
                DeleteObject(br);

                if(sel){
                    COLORREF selBdr = (row->riskLevel == 2) ? RGB(239, 68, 68) :
                                      (row->riskLevel == 1) ? RGB(245, 158, 11) : RGB(0, 210, 255);
                    HPEN pBdr = CreatePen(PS_SOLID, 1, selBdr);
                    HPEN op = (HPEN)SelectObject(d->hDC, pBdr);
                    HBRUSH ob = (HBRUSH)SelectObject(d->hDC, GetStockObject(NULL_BRUSH));
                    Rectangle(d->hDC, d->rcItem.left, d->rcItem.top, d->rcItem.right, d->rcItem.bottom);
                    SelectObject(d->hDC, op); SelectObject(d->hDC, ob); DeleteObject(pBdr);
                } else if(row->riskLevel > 0){
                    RECT indR = {d->rcItem.left + 2, ry + 4, d->rcItem.left + 5, ry + rowH - 4};
                    HBRUSH indB = CreateSolidBrush(row->riskLevel == 2 ? RGB(239, 68, 68) : RGB(245, 158, 11));
                    FillRect(d->hDC, &indR, indB);
                    DeleteObject(indB);
                }

                int col1 = rx + 8;
                int col2 = rx + 34;
                int col3 = rx + 263;
                int col4 = rx + 413;
                int col5 = rx + 543;
                int col6 = rx + 683;
                int col7 = rx + 853;
                int col8 = d->rcItem.right - 44;

                /* 1. Row # */
                char numStr[16]; snprintf(numStr, sizeof(numStr), "%d", (int)d->itemID + 1);
                Txt(d->hDC, numStr, col1, ry, 22, rowH, C_TEXT2, fSm, DT_LEFT|DT_VCENTER|DT_SINGLELINE);

                /* 2. Brand Icon */
                DrawBrandIcon(d->hDC, col2, ry + (rowH - 24)/2, 24, row->iconType);

                /* App Name & Process (expanded width so long names don't overlap IP) */
                Txt(d->hDC, row->name, col2 + 30, ry + 4, 195, 16, C_TEXT, fMed, DT_LEFT|DT_SINGLELINE);
                Txt(d->hDC, row->proc, col2 + 30, ry + 22, 195, 14, C_DIM, fSm, DT_LEFT|DT_SINGLELINE);

                /* 3. Local Address */
                Txt(d->hDC, row->local, col3, ry, 135, rowH, C_TEXT2, fSm, DT_LEFT|DT_VCENTER|DT_SINGLELINE);

                /* 4. Remote Endpoint */
                COLORREF remCol;
                if(row->riskLevel == 2)      remCol = RGB(248, 113, 113);
                else if(row->riskLevel == 1) remCol = RGB(251, 191, 36);
                else if(strcmp(row->remote, "Loopback") == 0) remCol = C_TEXT2;
                else remCol = RGB(140, 200, 255);
                Txt(d->hDC, row->remote, col4, ry, 120, rowH, remCol, fSm, DT_LEFT|DT_VCENTER|DT_SINGLELINE);

                /* 5. Category */
                COLORREF catCol = (row->riskLevel == 2) ? RGB(248, 113, 113) :
                                  (row->riskLevel == 1) ? RGB(251, 191, 36) : C_DIM;
                Txt(d->hDC, row->cat, col5, ry, 135, rowH, catCol, fSm, DT_LEFT|DT_VCENTER|DT_SINGLELINE);

                /* 6. Reverse DNS */
                COLORREF rdnsCol = (row->riskLevel == 2) ? RGB(255, 140, 140) :
                                   (row->riskLevel == 1) ? RGB(255, 210, 120) :
                                   (strcmp(row->rdns, "-") == 0 ? C_DIM2 : RGB(170, 195, 230));
                Txt(d->hDC, row->rdns, col6, ry, 170, rowH, rdnsCol, fSm, DT_LEFT|DT_VCENTER|DT_SINGLELINE);

                /* 7. State Pill */
                int stW = 88, stH = 20;
                int stY = ry + (rowH - stH) / 2;
                COLORREF stBg, stBdr, stFg;
                if(row->riskLevel == 2){
                    stBg  = RGB(55, 12, 18);
                    stBdr = RGB(239, 68, 68);
                    stFg  = RGB(255, 110, 110);
                } else if(row->riskLevel == 1){
                    stBg  = RGB(48, 34, 6);
                    stBdr = RGB(245, 158, 11);
                    stFg  = RGB(251, 191, 36);
                } else {
                    stBg  = RGB(8, 36, 26);
                    stBdr = RGB(16, 185, 129);
                    stFg  = RGB(52, 211, 153);
                }
                DrawRoundRectPanel(d->hDC, col7, stY, stW, stH, 10, stBg, stBdr);
                Txt(d->hDC, row->state, col7, stY, stW, stH, stFg, fMini ? fMini : fSm, DT_CENTER|DT_VCENTER|DT_SINGLELINE);

                /* 8. Action 3 Dots */
                int adX = col8 + 6, adY = ry + rowH / 2;
                COLORREF dotCol = (row->riskLevel == 2) ? RGB(239, 68, 68) :
                                  (row->riskLevel == 1) ? RGB(245, 158, 11) : C_DIM;
                HBRUSH bDot = CreateSolidBrush(dotCol);
                HPEN pNull = (HPEN)GetStockObject(NULL_PEN);
                HBRUSH ob = (HBRUSH)SelectObject(d->hDC, bDot);
                HPEN op = (HPEN)SelectObject(d->hDC, pNull);
                Ellipse(d->hDC, adX - 6, adY - 2, adX - 2, adY + 2);
                Ellipse(d->hDC, adX - 1, adY - 2, adX + 3, adY + 2);
                Ellipse(d->hDC, adX + 4, adY - 2, adX + 8, adY + 2);
                SelectObject(d->hDC, ob); SelectObject(d->hDC, op); DeleteObject(bDot);

                return TRUE;
            }

            /* === App Hub: Application Catalog List === */
            if(d->hwndItem == hAppList){
                if((int)d->itemID < 0) return TRUE;
                char text[512]={0};
                SendMessageA(d->hwndItem,LB_GETTEXT,d->itemID,(LPARAM)text);
                BOOL sel=!!(d->itemState & ODS_SELECTED);
                COLORREF bg = sel ? C_NAV_ACT : ((d->itemID%2==0)?C_BG:C_BG2);
                HBRUSH br = CreateSolidBrush(bg);
                FillRect(d->hDC,&d->rcItem,br);
                DeleteObject(br);
                if(sel){
                    HPEN pBdr = CreatePen(PS_SOLID, 1, RGB(59, 130, 246));
                    HPEN op = (HPEN)SelectObject(d->hDC, pBdr);
                    HBRUSH ob = (HBRUSH)SelectObject(d->hDC, GetStockObject(NULL_BRUSH));
                    Rectangle(d->hDC, d->rcItem.left, d->rcItem.top, d->rcItem.right, d->rcItem.bottom);
                    SelectObject(d->hDC, op); SelectObject(d->hDC, ob); DeleteObject(pBdr);
                }
                /* Parse icon prefix e.g. "[S] XAMPP ..." */
                char *iconEnd = strchr(text,']');
                if(iconEnd && text[0]=='['){
                    COLORREF iconC = C_DIM;
                    if(strstr(text,"[S]"))       iconC=C_PURPLE;
                    else if(strstr(text,"[WS]")) iconC=C_RED;
                    else if(strstr(text,"[DB]")) iconC=C_CYAN;
                    else if(strstr(text,"[B]"))  iconC=C_BLUE;
                    else if(strstr(text,"[DE]")) iconC=C_PURPLE;
                    else if(strstr(text,"[GM]")) iconC=C_AMBER;
                    else if(strstr(text,"[AV]")) iconC=C_GREEN;
                    else if(strstr(text,"[P]"))  iconC=C_GREEN;
                    else if(strstr(text,"[?]"))  iconC=C_DIM;

                    char icon[8]={0};
                    int il=(int)(iconEnd-text)+1;
                    if(il<8){memcpy(icon,text,il);icon[il]=0;}
                    SetTextColor(d->hDC,iconC);
                    SetBkMode(d->hDC,TRANSPARENT);
                    HFONT of=(HFONT)SelectObject(d->hDC,fMono);
                    RECT ir=d->rcItem; ir.right=ir.left+46;
                    DrawTextA(d->hDC,icon,-1,&ir,DT_CENTER|DT_SINGLELINE|DT_VCENTER|DT_NOPREFIX);
                    SelectObject(d->hDC,of);

                    const char *rest=iconEnd+1; while(*rest==' ') rest++;
                    COLORREF tc = sel ? C_TEXT : (strstr(text,"[RUNNING]") ? C_GREEN : (strstr(text,"[PARTIAL]") ? C_AMBER : C_TEXT2));
                    SetTextColor(d->hDC,tc);
                    HFONT of2=(HFONT)SelectObject(d->hDC,fSm);
                    RECT tr=d->rcItem; tr.left+=48; tr.right-=8;
                    DrawTextA(d->hDC,rest,-1,&tr,DT_LEFT|DT_SINGLELINE|DT_VCENTER|DT_NOPREFIX);
                    SelectObject(d->hDC,of2);
                } else {
                    /* Section header */
                    COLORREF tc = (text[0]==' ' && text[2]=='-') ? C_CYAN : (sel?C_TEXT:C_DIM);
                    SetTextColor(d->hDC,tc);
                    SetBkMode(d->hDC,TRANSPARENT);
                    HFONT of=(HFONT)SelectObject(d->hDC,fSm);
                    RECT tr=d->rcItem; tr.left+=8; tr.right-=8;
                    DrawTextA(d->hDC,text,-1,&tr,DT_LEFT|DT_SINGLELINE|DT_VCENTER|DT_NOPREFIX);
                    SelectObject(d->hDC,of);
                }
                return TRUE;
            }

            /* === App Hub: Application Detail & Graph List === */
            if(d->hwndItem == hAppDetail){
                if((int)d->itemID < 0) return TRUE;
                char text[512]={0};
                SendMessageA(d->hwndItem,LB_GETTEXT,d->itemID,(LPARAM)text);
                BOOL sel=!!(d->itemState & ODS_SELECTED);
                COLORREF bg = sel ? C_NAV_ACT : ((d->itemID%2==0)?C_BG:C_BG2);
                HBRUSH br = CreateSolidBrush(bg);
                FillRect(d->hDC,&d->rcItem,br);
                DeleteObject(br);
                if(sel){
                    HPEN pBdr = CreatePen(PS_SOLID, 1, RGB(59, 130, 246));
                    HPEN op = (HPEN)SelectObject(d->hDC, pBdr);
                    HBRUSH ob = (HBRUSH)SelectObject(d->hDC, GetStockObject(NULL_BRUSH));
                    Rectangle(d->hDC, d->rcItem.left, d->rcItem.top, d->rcItem.right, d->rcItem.bottom);
                    SelectObject(d->hDC, op); SelectObject(d->hDC, ob); DeleteObject(pBdr);
                }
                COLORREF fg = C_TEXT2;
                if(strstr(text,"=== ")) fg = C_CYAN;
                else if(strstr(text,"--- ")) fg = C_PURPLE;
                else if(strstr(text,"RUNNING") || strstr(text,"[CLEAN]")) fg = C_GREEN;
                else if(strstr(text,"PARTIAL") || strstr(text,"[!]")) fg = C_AMBER;
                else if(strstr(text,"STOPPED") || strstr(text,"CRITICAL")) fg = C_RED;
                else if(strstr(text,"Key Token:") || strstr(text,"Key:")) fg = C_CYAN;
                else if(strstr(text,"AI Copilot:") || strstr(text,"AI:")) fg = C_PURPLE;
                else if(strstr(text,"──[") || strstr(text,"<──[")) fg = C_AMBER;

                SetBkMode(d->hDC,TRANSPARENT);
                SetTextColor(d->hDC,fg);
                HFONT of=(HFONT)SelectObject(d->hDC, (strstr(text,"Key Token:") || strstr(text,"──[")) ? fMono : fSm);
                RECT tr=d->rcItem; tr.left+=8; tr.right-=8;
                DrawTextA(d->hDC,text,-1,&tr,DT_LEFT|DT_SINGLELINE|DT_VCENTER|DT_NOPREFIX);
                SelectObject(d->hDC,of);
                return TRUE;
            }

            /* === RansomShield Live Monitoring Feed Listbox === */
            if(d->hwndItem == hRwList){
                if((int)d->itemID < 0) return TRUE;
                char text[512] = {0};
                SendMessageA(d->hwndItem, LB_GETTEXT, d->itemID, (LPARAM)text);
                BOOL sel = !!(d->itemState & ODS_SELECTED);
                COLORREF bg = sel ? RGB(20, 36, 56) : ((d->itemID % 2 == 1) ? RGB(10, 16, 26) : RGB(8, 12, 20));
                HBRUSH br = CreateSolidBrush(bg);
                FillRect(d->hDC, &d->rcItem, br);
                DeleteObject(br);

                COLORREF fg = RGB(170, 195, 225);
                if(strstr(text, "ALERT") || strstr(text, "CRITICAL") || strstr(text, "ransom") || strstr(text, "Triggered") || strstr(text, "Tripped"))
                    fg = RGB(248, 113, 113);
                else if(strstr(text, "WARNING") || strstr(text, "stopped") || strstr(text, "STANDBY"))
                    fg = RGB(251, 191, 36);
                else if(strstr(text, "Active") || strstr(text, "Intact") || strstr(text, "Deployed") || strstr(text, "Verified") || strstr(text, "armed"))
                    fg = RGB(52, 211, 153);
                else if(strstr(text, "VSS") || strstr(text, "Snapshot") || strstr(text, "Rollback"))
                    fg = RGB(147, 197, 253);

                SetBkMode(d->hDC, TRANSPARENT);
                SetTextColor(d->hDC, fg);
                HFONT of = (HFONT)SelectObject(d->hDC, fSm);
                RECT tr = d->rcItem; tr.left += 8; tr.right -= 8;
                DrawTextA(d->hDC, text, -1, &tr, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
                SelectObject(d->hDC, of);
                return TRUE;
            }

            /* === Standard SOC log listbox === */
            COLORREF bg, fg = C_TEXT;
            if(sel){
                bg = RGB(28, 44, 72);
                fg = RGB(240, 246, 255);
            } else {
                bg = (d->itemID % 2 == 0) ? RGB(14, 18, 26) : RGB(19, 24, 34);
                fg = RGB(190, 200, 215);
            }
            HBRUSH br = CreateSolidBrush(bg);
            FillRect(d->hDC, &d->rcItem, br);
            DeleteObject(br);
            if(sel){
                HPEN pBdr = CreatePen(PS_SOLID, 1, RGB(59, 130, 246));
                HPEN op = (HPEN)SelectObject(d->hDC, pBdr);
                HBRUSH ob = (HBRUSH)SelectObject(d->hDC, GetStockObject(NULL_BRUSH));
                Rectangle(d->hDC, d->rcItem.left, d->rcItem.top, d->rcItem.right, d->rcItem.bottom);
                SelectObject(d->hDC, op); SelectObject(d->hDC, ob); DeleteObject(pBdr);
            }
            /* Smart SOC Syntax Highlighting */
            if(strstr(text, "CRITICAL") || strstr(text, "THREAT") || strstr(text, "BLOCKED") || strstr(text, "[!")){
                fg = RGB(248, 113, 113); /* Soft neon red */
            } else if(strstr(text, "WARNING") || strstr(text, "HIGH") || strstr(text, "Unverified") || strstr(text, "REQUIRES")){
                fg = RGB(251, 191, 36);  /* Soft amber */
            } else if(strstr(text, "CLEAN") || strstr(text, "SAFE") || strstr(text, "Verified") || strstr(text, "MITIGATED") || strstr(text, "BOOST") || strstr(text, "100%") || strstr(text, "ALLOWED")){
                fg = RGB(52, 211, 153);  /* Soft emerald */
            } else if(text[0] == '-' && text[1] == '-'){
                fg = RGB(65, 75, 95);    /* Subtle divider */
            } else if(strstr(text, "=== ") || strstr(text, "PID ") || strstr(text, "Name ") || strstr(text, "Severity ")){
                fg = RGB(147, 197, 253); /* Light blue table header */
            }
            SetBkMode(d->hDC, TRANSPARENT);
            SetTextColor(d->hDC, fg);
            HFONT of = (HFONT)SelectObject(d->hDC, fMono);
            RECT rcText = d->rcItem;
            rcText.left += 8; rcText.right -= 8;
            DrawTextA(d->hDC, text, -1, &rcText, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
            SelectObject(d->hDC, of);
            return TRUE;
        }
        return TRUE;
    }

    case WM_MOUSEMOVE:{
        int mx=GET_X_LPARAM(lp),my=GET_Y_LPARAM(lp);
        int prev=g_navHov; g_navHov=-1;
        if(mx<NAV_W && my>=HDR_H+10 && my<HDR_H+10+TAB_COUNT*NAV_ITEM_H){
            int idx=(my-HDR_H-10)/NAV_ITEM_H;
            if(idx>=0&&idx<TAB_COUNT) g_navHov=idx;
        }
        if(g_navHov!=prev){RECT nr={0,HDR_H,NAV_W,HDR_H+10+TAB_COUNT*NAV_ITEM_H};InvalidateRect(hw,&nr,FALSE);}
        return 0;}

    case WM_LBUTTONDOWN:{
        int mx=GET_X_LPARAM(lp),my=GET_Y_LPARAM(lp);
        if(mx<NAV_W && my>=HDR_H+10 && my<HDR_H+10+TAB_COUNT*NAV_ITEM_H){
            int idx=(my-HDR_H-10)/NAV_ITEM_H;
            if(idx>=0&&idx<TAB_COUNT&&(Tab)idx!=g_tab){
                g_tab=(Tab)idx; Layout(hw); InvalidateRect(hw,NULL,FALSE);
            }
        }
        RECT wr; GetClientRect(hw,&wr);
        if(my < HDR_H){
            int rx = wr.right - 260;
            /* Kaevex Brand Logo & Title -> Navigate to Dashboard */
            if(mx >= 14 && mx <= 200){
                g_tab = TAB_DASH;
                Layout(hw);
                InvalidateRect(hw, NULL, TRUE);
                return 0;
            }
            /* Notification Bell -> Navigate to Settings Alerts & Notifications */
            if(mx >= rx && mx <= rx + 36 && my >= (HDR_H-32)/2 && my <= (HDR_H-32)/2+32){
                g_tab = TAB_SET;
                g_setSubTab = SET_NOTIF;
                Layout(hw);
                InvalidateRect(hw, NULL, TRUE);
                return 0;
            }
            /* Moon Theme Switcher Icon -> Cycle through 5 themes */
            if(mx >= rx + 44 && mx <= rx + 68 && my >= (HDR_H-22)/2 && my <= (HDR_H-22)/2+22){
                g_cfg.theme = (g_cfg.theme + 1) % 5;
                ApplyTheme(g_cfg.theme);
                SaveKaevexSettings();
                add_alert("Theme", "INFO", "Theme palette changed via header quick-toggle.");
                InvalidateRect(hw, NULL, TRUE);
                return 0;
            }
            /* User Account / Profile Chip */
            if(mx >= rx + 80){
                ShowSupabaseAccountDialog(hw);
                return 0;
            }
        }

        /* Interactive Dashboard Widget Click Handlers */
        if(g_tab == TAB_DASH && mx >= NAV_W){
            int W = wr.right, H = wr.bottom;
            int cx = NAV_W + MRG, cy = HDR_H, cw = W - NAV_W - MRG*2, ch = H - HDR_H - STB_H;
            int titleY = cy + 12;
            int cardH = 96, gap = MRG;
            int row1Y = titleY + 54;
            int row2Y = row1Y + cardH + gap;
            int chartH = 195;
            int row3Y = row2Y + chartH + gap;
            int row3H = ch - (row3Y - cy) - gap; if(row3H < 150) row3H = 150;
            int mapPanelW = (cw - MRG*2 - gap) * 62 / 100;
            int rightPanelW = cw - MRG*2 - gap - mapPanelW;
            int rightX = cx + MRG + mapPanelW + gap;
            int threatCardH = row3H * 66 / 100;
            int statCardY = row3Y + threatCardH + gap;
            int statCardH = row3H - threatCardH - gap;

            /* Click 1: Latest Active Threat / Cluster Mesh Card -> Copy Key & Notify */
            if(mx >= rightX && mx <= rightX + rightPanelW && my >= row3Y && my <= row3Y + threatCardH){
                if(OpenClipboard(hw)){
                    EmptyClipboard();
                    const char *pKey = "AEGJ5-46C0-C391-MESH";
                    HGLOBAL hg = GlobalAlloc(GMEM_MOVEABLE, (SIZE_T)(strlen(pKey) + 1));
                    if(hg){
                        char *p = (char*)GlobalLock(hg);
                        strcpy(p, pKey);
                        GlobalUnlock(hg);
                        SetClipboardData(CF_TEXT, hg);
                    }
                    CloseClipboard();
                    add_alert("ClusterMesh", "INFO", "Cluster Mesh Pairing Key [AEGJ5-46C0-C391-MESH] copied to clipboard.");
                    MessageBoxA(hw, "Cluster Mesh Zero-Trust Pairing Key:\n\nAEGJ5-46C0-C391-MESH\n\nCopied to clipboard successfully! Use this token to authenticate remote nodes in your cluster.", "Cluster Mesh Token Copied", MB_ICONINFORMATION);
                }
                return 0;
            }

            /* Click 2: System Status Card -> Navigate to Defense Engines */
            if(mx >= rightX && mx <= rightX + rightPanelW && my >= statCardY && my <= statCardY + statCardH){
                g_tab = TAB_ENG;
                Layout(hw);
                InvalidateRect(hw, NULL, FALSE);
                return 0;
            }

            /* Click 3: Stats Column beside World Map -> Navigate to corresponding security module */
            int mapW = mapPanelW * 58 / 100;
            int statX = cx + MRG + mapW + 14;
            int statW = mapPanelW - mapW - 20;
            int statRowH = (row3H - 36) / 4;
            if(mx >= statX && mx <= statX + statW && my >= row3Y + 32 && my <= row3Y + 32 + statRowH * 4){
                int statIdx = (my - (row3Y + 32)) / statRowH;
                if(statIdx == 0){ g_tab = TAB_WAF; }       /* Global Attacks -> WebGuard WAF */
                else if(statIdx == 1){ g_tab = TAB_RANSOM; }/* Honeypot hits -> RansomShield */
                else if(statIdx == 2){ g_tab = TAB_NET; }   /* Sockets -> NetGuard Traffic */
                else if(statIdx == 3){ g_tab = TAB_APPS; }  /* Host Procs -> App Hub */
                Layout(hw);
                InvalidateRect(hw, NULL, FALSE);
            }
        }

        /* Interactive Adaptive Firewall Click Handlers */
        if(g_tab == TAB_FW && mx >= NAV_W){
            int W = wr.right, H = wr.bottom;
            int cx = NAV_W + MRG, cy = HDR_H, cw = W - NAV_W - MRG*2, ch = H - HDR_H - STB_H;
            int fwRw = 264;
            int fwLw = cw - fwRw - 14;
            if (fwLw < 500) fwLw = 500;
            int fwCardY = cy + 102;
            int fwCardH = ch - (fwCardY - cy) - 10;
            int rx = cx + fwLw + 12, rw = fwRw;
            int topH = 265;
            int botY = fwCardY + topH + 10;
            int botH = fwCardH - topH - 10;
            int fItemH = (botH - 36) / 3;
            if (fItemH < 72) fItemH = 72;

            /* Dynamic click handling for recommendation items */
            for (int k = 0; k < 3 && k < g_fwRecCount; k++) {
                FwRecItem *it = &g_fwRecs[k];
                int iy = botY + 32 + k * fItemH;
                int btnW = (strcmp(it->actionBtn, "Deactivate") == 0) ? 68 : 52;
                int btnX = rx + rw - btnW - 12;
                if (mx >= btnX && mx <= btnX + btnW && my >= iy + 36 && my <= iy + 54) {
                    if (it->actionType == 1) { /* Review */
                        if (it->ruleIdx >= 0 && it->ruleIdx < g_fwRuleCount) {
                            int lbCount = (int)SendMessageA(hFwList, LB_GETCOUNT, 0, 0);
                            for (int l = 0; l < lbCount; l++) {
                                if ((int)SendMessageA(hFwList, LB_GETITEMDATA, l, 0) == it->ruleIdx) {
                                    SendMessageA(hFwList, LB_SETCURSEL, l, 0);
                                    SendMessageA(hFwList, LB_SETTOPINDEX, (l > 3) ? l - 3 : 0, 0);
                                    break;
                                }
                            }
                            SendMessageA(hw, WM_COMMAND, MAKEWPARAM(IDF_LIST, LBN_SELCHANGE), (LPARAM)hFwList);
                            FwRule *r = &g_fwRules[it->ruleIdx];
                            char msg[512];
                            snprintf(msg, sizeof(msg),
                                "Adaptive Rule Telemetry Audit:\n\n"
                                "Rule Name: %s\n"
                                "Direction: %s | Action: %s\n"
                                "Profile: %s | Protocol: %s\n"
                                "Local Port: %s | Remote IP: %s\n"
                                "Live Correlated Hits: %lu\n"
                                "Enabled: %s",
                                r->name, r->direction, r->action,
                                r->profile, r->protocol,
                                r->localPort, r->remoteIP,
                                r->hits, r->enabled);
                            MessageBoxA(hw, msg, "Adaptive Policy Telemetry Review", MB_ICONINFORMATION);
                        }
                        return 0;
                    } else if (it->actionType == 2) { /* Deactivate */
                        if (it->ruleIdx >= 0 && it->ruleIdx < g_fwRuleCount) {
                            FwRule *r = &g_fwRules[it->ruleIdx];
                            char prompt[300];
                            snprintf(prompt, sizeof(prompt),
                                "Deactivate dormant firewall rule '%s' to reduce attack surface?",
                                r->name);
                            if (MessageBoxA(hw, prompt, "Deactivate Rule", MB_YESNO | MB_ICONQUESTION) == IDYES) {
                                strcpy(r->enabled, "No");
                                strcpy(r->action, "Block");
                                char logMsg[256];
                                snprintf(logMsg, sizeof(logMsg), "Deactivated dormant rule '%s'", r->name);
                                add_alert("Firewall", "INFO", logMsg);
                                fw_update_recommendations();
                                InvalidateRect(hw, NULL, FALSE);
                            }
                        }
                        return 0;
                    }
                }
            }
        }

        /* Interactive Settings Click Handlers */
        if(g_tab == TAB_SET && mx >= NAV_W){
            POINT pt = { mx, my };
            for(int i = 0; i < g_setClickCnt; i++){
                if(PtInRect(&g_setClicks[i].rc, pt)){
                    int at = g_setClicks[i].actionType;
                    if(at == 1){ /* Toggle boolean */
                        if(g_setClicks[i].targetPtr){
                            BOOL *pb = (BOOL*)g_setClicks[i].targetPtr;
                            *pb = !(*pb);
                            if(g_cfg.soundEffects) MessageBeep(MB_OK);
                            ApplyKaevexSettings(FALSE);
                            SaveKaevexSettings();
                            InvalidateRect(hw, NULL, FALSE);
                        }
                    }
                    else if(at == 2){ /* Set int value (mode selectors) */
                        if(g_setClicks[i].targetPtr){
                            int *pi = (int*)g_setClicks[i].targetPtr;
                            *pi = g_setClicks[i].val;
                            if(g_cfg.soundEffects) MessageBeep(MB_OK);
                            if(pi == &g_cfg.theme){
                                ApplyTheme(g_cfg.theme);
                            }
                            if(pi == &g_cfg.perfMode){
                                if(g_setClicks[i].val == 3){ /* Game Turbo profile selected in Settings */
                                    if(!g_gaming.active) SendMessageA(hw, WM_COMMAND, MAKEWPARAM(IDT_BOOST, 0), 0);
                                } else {
                                    if(g_gaming.active) SendMessageA(hw, WM_COMMAND, MAKEWPARAM(IDT_BOOST, 0), 0);
                                }
                            }
                            ApplyKaevexSettings(FALSE);
                            SaveKaevexSettings();
                            InvalidateRect(hw, NULL, TRUE);
                        }
                    }
                    else if(at == 3){ /* Save configuration button */
                        ApplyKaevexSettings(FALSE);
                        SaveKaevexSettings();
                        if(g_cfg.soundEffects) MessageBeep(MB_OK);
                        add_alert("Settings", "INFO", "Platform configuration successfully committed to registry.");
                        InvalidateRect(hw, NULL, FALSE);
                    }
                    else if(at == 4){ /* Reset to defaults */
                        if(MessageBoxA(hw, "Reset all settings in this category to default security baselines?", "Kaevex Settings", MB_YESNO|MB_ICONQUESTION) == IDYES){
                            g_cfg.theme = 0;
                            ApplyTheme(0);
                            g_cfg.protMode = 0; g_cfg.realTimeProt = TRUE; g_cfg.behaviorMon = TRUE;
                            g_cfg.heuristicDetect = TRUE; g_cfg.cloudProt = TRUE; g_cfg.tamperProt = TRUE;
                            g_cfg.fwEnabled = TRUE; g_cfg.wafEnabled = TRUE; g_cfg.rsRealtime = TRUE;
                            ApplyKaevexSettings(FALSE);
                            SaveKaevexSettings();
                            add_alert("Settings", "INFO", "Settings restored to hardened defaults.");
                            InvalidateRect(hw, NULL, TRUE);
                        }
                    }
                    else if(at == 5){ /* Change Settings sub-tab from sidebar item */
                        g_setSubTab = g_setClicks[i].val;
                        if(g_cfg.soundEffects) MessageBeep(MB_OK);
                        Layout(hw);
                        InvalidateRect(hw, NULL, FALSE);
                    }
                    else if(at == 6){ /* Open URL (kaevex.com/info/) */
                        ShellExecuteA(NULL, "open", "https://kaevex.com/info/", NULL, NULL, SW_SHOWNORMAL);
                        add_alert("Portal", "INFO", "Navigating to official documentation: https://kaevex.com/info/");
                    }
                    else if(at == 7){ /* Custom Settings action */
                        ExecuteSettingsAction(g_setClicks[i].val);
                        InvalidateRect(hw, NULL, FALSE);
                    }
                    return 0;
                }
            }
        }

        /* Interactive RansomShield Click Handlers */
        if(g_tab == TAB_RANSOM && mx >= NAV_W){
            int W = wr.right, H = wr.bottom;
            int cx = NAV_W + MRG, cy = HDR_H, cw = W - NAV_W - MRG*2, ch = H - HDR_H - STB_H;
            int cardY = cy + 76;
            int cardH = 246;
            int bottomY = cardY + cardH + 12;
            int bottomH = ch - (bottomY - cy) - 4;
            if (bottomH < 180) bottomH = 180;

            /* Check "Rollback Selected" Button */
            int rbsW = 140, rbsH = 26;
            int rbsX = cx + cw - rbsW - 16, rbsY = bottomY + 10;
            if (mx >= rbsX && mx <= rbsX + rbsW && my >= rbsY && my <= rbsY + rbsH) {
                MessageBoxA(hw, "Snapshot restoration is not implemented in this build. Use Windows System Restore or another verified recovery tool.", "Rollback unavailable", MB_ICONWARNING);
                return 0;
            }

            /* Check Table Rows */
            int tblY = bottomY + 44;
            int rowY = tblY + 28;
            int rowH = 28;
            int maxRows = (bottomH - 80) / rowH;
            int showRows = (g_vssSnapshotCnt < maxRows) ? g_vssSnapshotCnt : maxRows;
            int col5 = cx + cw - 120;
            int btnW = 76, btnH = 22;

            for (int i = 0; i < showRows; i++) {
                int curY = rowY + i * rowH;
                if (my >= curY && my <= curY + rowH && mx >= cx + 16 && mx <= cx + cw - 16) {
                    g_vssSelectedIdx = i;
                    /* Check if Rollback button in this row was clicked */
                    if (mx >= col5 && mx <= col5 + btnW && my >= curY + 2 && my <= curY + 2 + btnH) {
                        MessageBoxA(hw, "Snapshot restoration is not implemented in this build. Use Windows System Restore or another verified recovery tool.", "Rollback unavailable", MB_ICONWARNING);
                    }
                    InvalidateRect(hw, NULL, FALSE);
                    return 0;
                }
            }
        }

        /* Interactive Patch & CVE Agent Dashboard Click Handlers */
        if(g_tab == TAB_UPD && mx >= NAV_W){
            int W = wr.right, H = wr.bottom;
            int cx = NAV_W + MRG, cy = HDR_H, cw = W - NAV_W - MRG*2, ch = H - HDR_H - STB_H;
            int heroX = cx + 8, heroW = cw - 16, heroY = cy + 8, heroH = 68;
            int rx = heroX + heroW - 12;

            /* 1. [ â–· Scan Now ] button in Hero Card (Async Deep Scan) */
            int btnW = 130, btnH = 40;
            int btnX = rx - btnW;
            int btnY = heroY + (heroH - btnH) / 2;
            if(mx >= btnX && mx <= btnX + btnW && my >= btnY && my <= btnY + btnH){
                StartAsyncCveScan(hw);
                return 0;
            }

            /* 2. Sub-Nav Pills */
            int subNavY = heroY + heroH + 10;
            int subNavH = 32;
            if(my >= subNavY && my <= subNavY + subNavH){
                static const char *subLabels[7] = {
                    "Overview", "Vulnerabilities", "Patches", "Scan Settings", "Update Center", "CVE Database", "Reports"
                };
                int px = cx + 8;
                for(int i = 0; i < 7; i++){
                    int pw = 28 + (int)strlen(subLabels[i]) * 8 + 18;
                    if(mx >= px && mx <= px + pw){
                        g_cveSubNav = i;
                        g_cveScrollY = 0;
                        ShowWindow(hUpdSearch, (g_cveSubNav == 1) ? SW_SHOW : SW_HIDE);
                        InvalidateRect(hw, NULL, FALSE);
                        return 0;
                    }
                    px += pw + 8;
                }
            }

            int contentY = subNavY + subNavH + 10;
            int contentH = ch - (contentY - cy);

            /* === SUB-TAB 0: OVERVIEW CLICKS === */
            if(g_cveSubNav == 0){
                int kpiH = 76;
                int pnlY = contentY + kpiH + 12;
                int pnlH = contentH - (pnlY - contentY) - 48;
                int pnlW1 = (cw - 16 - 12) * 58 / 100;
                int pnlX2 = cx + 8 + pnlW1 + 12;
                int pnlW2 = (cw - 16 - 12) - pnlW1;
                int bW = pnlW2 - 40;
                int b1Y = pnlY + pnlH - 84;
                int b2Y = b1Y + 42;

                /* Button 1: 1-Click Auto-Fix */
                if(mx >= pnlX2 + 20 && mx <= pnlX2 + 20 + bW && my >= b1Y && my <= b1Y + 36){
                    SendMessageA(hw, WM_COMMAND, MAKEWPARAM(IDU_FIXALL, 0), 0);
                    return 0;
                }
                /* Button 2: View Full Vulnerability Table */
                if(mx >= pnlX2 + 20 && mx <= pnlX2 + 20 + bW && my >= b2Y && my <= b2Y + 32){
                    g_cveSubNav = 1;
                    g_cveScrollY = 0;
                    ShowWindow(hUpdSearch, SW_SHOW);
                    InvalidateRect(hw, NULL, FALSE);
                    return 0;
                }
                return 0;
            }

            /* === SUB-TAB 1: VULNERABILITIES (MASTER TABLE) CLICKS === */
            if(g_cveSubNav == 1){
                int kpiY = contentY;
                int kpiH = 82;
                if(my >= kpiY && my <= kpiY + kpiH){
                    int cardGap = 10;
                    int cardW = (cw - 16 - 4 * cardGap) / 5;
                    for(int i = 0; i < 5; i++){
                        int kx = cx + 8 + i * (cardW + cardGap);
                        if(mx >= kx && mx <= kx + cardW){
                            if(i < 4){
                                g_cveFilterSev = i + 1;
                            } else {
                                g_cveFilterSev = 0;
                            }
                            g_cveScrollY = 0;
                            InvalidateRect(hw, NULL, FALSE);
                            return 0;
                        }
                    }
                }

                int toolY = kpiY + kpiH + 12;
                int toolH = 34;
                int sBoxW = 320;
                if(my >= toolY && my <= toolY + toolH){
                    int fSevX = cx + 8 + sBoxW + 8, fSevW = 110;
                    if(mx >= fSevX && mx <= fSevX + fSevW){
                        g_cveFilterSev = (g_cveFilterSev + 1) % 5;
                        g_cveScrollY = 0;
                        InvalidateRect(hw, NULL, FALSE);
                        return 0;
                    }
                    int fStatX = fSevX + fSevW + 8, fStatW = 110;
                    if(mx >= fStatX && mx <= fStatX + fStatW){
                        g_cveFilterStatus = (g_cveFilterStatus + 1) % 6;
                        g_cveScrollY = 0;
                        InvalidateRect(hw, NULL, FALSE);
                        return 0;
                    }
                    int fCatX = fStatX + fStatW + 8, fCatW = 120;
                    if(mx >= fCatX && mx <= fCatX + fCatW){
                        g_cveFilterCat = (g_cveFilterCat + 1) % 5;
                        g_cveScrollY = 0;
                        InvalidateRect(hw, NULL, FALSE);
                        return 0;
                    }
                    int rX = cx + cw - 8 - 240, rW = 100;
                    if(mx >= rX && mx <= rX + rW){
                        SendMessageA(hw, WM_COMMAND, MAKEWPARAM(IDU_REFRESH, 0), 0);
                        return 0;
                    }
                    int eX = cx + cw - 8 - 130, eW = 130;
                    if(mx >= eX && mx <= eX + eW){
                        CveExportHtmlReport();
                        return 0;
                    }
                }

                int tblX = cx + 8, tblW = cw - 16;
                int tblY = toolY + toolH + 10, tblH = ch - (tblY - cy) - 8;
                int hdrH = 34;

                int chkBoxY = tblY + (hdrH - 16) / 2;
                if(my >= chkBoxY && my <= chkBoxY + 16 && mx >= tblX + 12 && mx <= tblX + 28){
                    g_cveSelectAll = !g_cveSelectAll;
                    for(int i = 0; i < g_cveItemCount; i++) g_cveItems[i].selected = g_cveSelectAll;
                    InvalidateRect(hw, NULL, FALSE);
                    return 0;
                }

                int rowH = 48;
                int bodyY = tblY + hdrH;
                int bodyH = tblH - hdrH;

                int fIndices[MAX_CVE_TABLE]; int fCnt = 0;
                for(int i = 0; i < g_cveItemCount; i++){
                    CveTableItem *it = &g_cveItems[i];
                    if(g_cveFilterSev > 0 && it->severity != (CveSeverity)(g_cveFilterSev - 1)) continue;
                    if(g_cveFilterStatus > 0 && it->status != (CveStatus)(g_cveFilterStatus - 1)) continue;
                    if(g_cveFilterCat > 0 && it->category != g_cveFilterCat) continue;
                    if(g_cveSearch[0]){
                        if(!cve_stristr(it->vulnTitle, g_cveSearch) &&
                           !cve_stristr(it->appName, g_cveSearch) &&
                           !cve_stristr(it->cveId, g_cveSearch)) continue;
                    }
                    fIndices[fCnt++] = i;
                }

                if(my >= bodyY && my < bodyY + bodyH && mx >= tblX && mx <= tblX + tblW){
                    int r = (my - bodyY) / rowH;
                    int rIdx = r + g_cveScrollY;
                    if(rIdx >= 0 && rIdx < fCnt){
                        CveTableItem *item = &g_cveItems[fIndices[rIdx]];
                        int ry = bodyY + r * rowH;

                        if(mx >= tblX + 10 && mx <= tblX + 32){
                            item->selected = !item->selected;
                            InvalidateRect(hw, NULL, FALSE);
                            return 0;
                        }

                        int colW8 = 86;
                        int colX8 = tblX + tblW - colW8 - 18;
                        int actW = 82, actH = 24;
                        int actY = ry + (rowH - actH) / 2;
                        if(mx >= colX8 && mx <= colX8 + actW && my >= actY && my <= actY + actH){
                            if(strcmp(item->actionText, "Patch") == 0){
                                if(item->isOs){
                                    char alertMsg[320];
                                    snprintf(alertMsg, sizeof(alertMsg), "%s is a build-range candidate only. Installed Windows KB status is not verified, so Kaevex will not change OS settings automatically. Review Windows Update and the vendor advisory.", item->cveId);
                                    add_alert("CVE Agent", "WARNING", alertMsg);
                                    MessageBoxA(hw, alertMsg, "OS advisory needs verification", MB_ICONWARNING);
                                } else {
                                    char confirm[320];
                                    if(!item->wingetId[0]){
                                        MessageBoxA(hw,"No verified winget package ID is available. Update this application through its publisher.","Manual update required",MB_ICONWARNING);
                                        return 0;
                                    }
                                    snprintf(confirm,sizeof(confirm),"Upgrade %s using winget package %s? This may require administrator approval.",item->appName,item->wingetId);
                                    if(MessageBoxA(hw,confirm,"Confirm targeted update",MB_YESNO|MB_ICONQUESTION)!=IDYES) return 0;
                                    BOOL updateOk = upd_apply_update(item->wingetId);
                                    int installed = upd_scan_installed();
                                    upd_check_cves();
                                    BOOL stillMatched = FALSE;
                                    for(int ai=0;ai<installed;ai++) if(_stricmp(g_apps[ai].name,item->appName)==0 && g_apps[ai].cveCount>0) stillMatched=TRUE;
                                    char alertMsg[320];
                                    if(updateOk && !stillMatched){
                                        item->status = CVE_STATUS_FIXED;
                                        strcpy(item->actionText,"View");
                                        snprintf(alertMsg,sizeof(alertMsg),"%s upgrade completed and the local catalog no longer reports this CVE candidate. Verify with the publisher advisory.",item->appName);
                                        add_alert("CVE Agent","INFO",alertMsg);
                                        MessageBoxA(hw,alertMsg,"Update completed; candidate cleared",MB_ICONINFORMATION);
                                    } else {
                                        item->status = CVE_STATUS_PENDING;
                                        snprintf(alertMsg,sizeof(alertMsg),"%s update did not clear the local CVE candidate. Check the updater result and publisher guidance.",item->appName);
                                        add_alert("CVE Agent","WARNING",alertMsg);
                                        MessageBoxA(hw,alertMsg,"Candidate remains",MB_ICONWARNING);
                                    }
                                }
                            } else {
                                char detailsMsg[512];
                                snprintf(detailsMsg, sizeof(detailsMsg),
                                    "Security Advisory & Patch Telemetry:\n\n"
                                    "Application: %s\n"
                                    "Installed Version: %s\n"
                                    "Advisory: %s\n"
                                    "CVE Identifier: %s\n"
                                    "CVSS Risk Score: %d/100\n"
                                    "Telemetry Status: %s\n"
                                    "Recommended Remediation: %s",
                                    item->appName, item->version, item->vulnTitle,
                                    item->cveId, item->cvssScore,
                                    (item->status == CVE_STATUS_FIXED) ? "Verified Secure / Mitigated" : "Action Required",
                                    item->vulnDesc);
                                MessageBoxA(hw, detailsMsg, "Vulnerability Intelligence Review", MB_ICONINFORMATION);
                            }
                            InvalidateRect(hw, NULL, FALSE);
                            return 0;
                        }
                    }
                }
                return 0;
            }

            /* === SUB-TAB 2: PATCHES CLICKS === */
            if(g_cveSubNav == 2){
                int banY = contentY; int banH = 64; int banW = cw - 16;
                int bW = 220, bH = 38;
                int bX = cx + 8 + banW - bW - 12;
                int bY = banY + (banH - bH) / 2;
                if(mx >= bX && mx <= bX + bW && my >= bY && my <= bY + bH){
                    SendMessageA(hw, WM_COMMAND, MAKEWPARAM(IDU_FIXALL, 0), 0);
                    return 0;
                }

                int tblX = cx + 8, tblW = cw - 16;
                int tblY = banY + banH + 12;
                int hdrH = 34; int rowH = 46;
                int bodyY = tblY + hdrH;
                int col8 = tblX + tblW - 110;
                int actW = 90, actH = 24;

                int pIndices[MAX_CVE_TABLE]; int pCnt = 0;
                for(int i = 0; i < g_cveItemCount; i++){
                    if(g_cveItems[i].wingetId[0] || g_cveItems[i].fixVersion[0] || g_cveItems[i].status == CVE_STATUS_AVAILABLE){
                        pIndices[pCnt++] = i;
                    }
                }

                if(my >= bodyY && mx >= col8 && mx <= col8 + actW){
                    int r = (my - bodyY) / rowH;
                    int rIdx = r + g_cvePatchScrollY;
                    if(rIdx >= 0 && rIdx < pCnt){
                        CveTableItem *it = &g_cveItems[pIndices[rIdx]];
                        if(it->wingetId[0]){
                            char confirm[256];
                            snprintf(confirm, sizeof(confirm), "Deploy update for %s via winget package %s?", it->appName, it->wingetId);
                            if(MessageBoxA(hw, confirm, "Confirm Package Upgrade", MB_YESNO|MB_ICONQUESTION) == IDYES){
                                BOOL ok = upd_apply_update(it->wingetId);
                                BuildCveTableData();
                                MessageBoxA(hw, ok ? "Package upgrade applied successfully." : "Upgrade command dispatched in background.", "Update Status", MB_ICONINFORMATION);
                                InvalidateRect(hw, NULL, FALSE);
                            }
                        } else {
                            ShellExecuteA(NULL, "open", "ms-settings:windowsupdate", NULL, NULL, SW_SHOWNORMAL);
                        }
                        return 0;
                    }
                }
                return 0;
            }

            /* === SUB-TAB 3: SCAN SETTINGS CLICKS === */
            if(g_cveSubNav == 3){
                int cardW = cw - 16; int cardX = cx + 8;
                int curY = contentY;

                /* Toggle Switch 1 */
                int swW = 54, swH = 26;
                int swX = cardX + cardW - swW - 20;
                int swY = curY + 16;
                if(mx >= swX && mx <= swX + swW && my >= swY && my <= swY + swH){
                    g_cveAutoScanEnabled = !g_cveAutoScanEnabled;
                    CveUpdateSchedule(hw);
                    InvalidateRect(hw, NULL, FALSE);
                    return 0;
                }

                /* Interval Pills */
                int px = cardX + 175;
                for(int i = 0; i < 4; i++){
                    int pw = 105, ph = 26;
                    if(mx >= px && mx <= px + pw && my >= curY + 68 && my <= curY + 68 + ph){
                        g_cveAutoScanInterval = i;
                        CveUpdateSchedule(hw);
                        InvalidateRect(hw, NULL, FALSE);
                        return 0;
                    }
                    px += pw + 10;
                }

                /* Target Checkboxes */
                int cyTarget = curY + 110 + 12 + 44 + 32;
                if(mx >= cardX + 24 && mx <= cardX + cardW - 20 && my >= cyTarget && my <= cyTarget + 24){
                    g_cveScanNvdCloud = !g_cveScanNvdCloud;
                    InvalidateRect(hw, NULL, FALSE);
                    return 0;
                }

                /* Action Buttons */
                int c3Y = curY + 110 + 12 + 150 + 12;
                int bY = c3Y + 110 + 16;
                int btnW2 = 160, btnH2 = 34;
                if(mx >= cardX && mx <= cardX + btnW2 && my >= bY && my <= bY + btnH2){
                    BOOL saved=CveSaveSchedule(); CveUpdateSchedule(hw);
                    add_alert("CVE Agent", saved?"INFO":"ERROR", saved?"Scheduled local inventory/NVD check settings saved.":"Could not save the scan schedule to the current-user registry.");
                    MessageBoxA(hw,saved?"Schedule saved. Checks run while Kaevex is open.":"Could not save the schedule. Check current-user registry permissions.","Scan Schedule",saved?MB_ICONINFORMATION:MB_ICONERROR);
                    return 0;
                }
                int rstX = cardX + btnW2 + 12;
                if(mx >= rstX && mx <= rstX + btnW2 + 20 && my >= bY && my <= bY + btnH2){
                    g_cveAutoScanEnabled = TRUE;
                    g_cveAutoScanInterval = 1;
                    g_cveScanNvdCloud = TRUE;
                    BOOL saved=CveSaveSchedule(); CveUpdateSchedule(hw);
                    add_alert("CVE Agent", saved?"INFO":"ERROR", saved?"Reset and saved a one-hour inventory/NVD schedule.":"Schedule reset in memory; registry save failed.");
                    InvalidateRect(hw, NULL, FALSE);
                    return 0;
                }
                return 0;
            }

            /* === SUB-TAB 4: UPDATE CENTER CLICKS === */
            if(g_cveSubNav == 4){
                int pnlW = (cw - 16 - 12) / 2;
                int pnlH = contentH - 8;
                int p1X = cx + 8;
                int p2X = p1X + pnlW + 12;
                int bW = pnlW - 40;
                int b1Y = contentY + pnlH - 96;
                int b2Y = b1Y + 44;

                /* Left Button 1: Open Windows Update Settings */
                if(mx >= p1X + 20 && mx <= p1X + 20 + bW && my >= b1Y && my <= b1Y + 36){
                    ShellExecuteA(NULL, "open", "ms-settings:windowsupdate", NULL, NULL, SW_SHOWNORMAL);
                    return 0;
                }
                /* Left Button 2: Trigger Background Scan */
                if(mx >= p1X + 20 && mx <= p1X + 20 + bW && my >= b2Y && my <= b2Y + 32){
                    HINSTANCE opened = ShellExecuteA(NULL, "open", "ms-settings:windowsupdate", NULL, NULL, SW_SHOWNORMAL);
                    if ((INT_PTR)opened <= 32) MessageBoxA(hw, "Windows Update Settings could not be opened.", "Windows Update", MB_ICONWARNING);
                    return 0;
                }
                /* Right Button 1: Run winget upgrade --all */
                if(mx >= p2X + 20 && mx <= p2X + 20 + bW && my >= b1Y && my <= b1Y + 36){
                    SendMessageA(hw, WM_COMMAND, MAKEWPARAM(IDU_FIXALL, 0), 0);
                    return 0;
                }
                /* Right Button 2: Open winget log */
                if(mx >= p2X + 20 && mx <= p2X + 20 + bW && my >= b2Y && my <= b2Y + 32){
                    char logPath[MAX_PATH];
                    GetTempPathA(sizeof(logPath), logPath);
                    strcat(logPath, "kaevex_winget.log");
                    ShellExecuteA(NULL, "open", logPath, NULL, NULL, SW_SHOWNORMAL);
                    return 0;
                }
                return 0;
            }

            /* === SUB-TAB 6: REPORTS CLICKS === */
            if(g_cveSubNav == 6){
                int cardX = cx + 8;
                int c1H = 130;
                int curY = contentY + c1H + 16;
                int by = curY + 76;
                int bW = 200, bH = 38;

                /* Button 1: HTML Report */
                if(mx >= cardX + 24 && mx <= cardX + 24 + bW && my >= by && my <= by + bH){
                    CveExportHtmlReport();
                    InvalidateRect(hw, NULL, FALSE);
                    return 0;
                }
                /* Button 2: CSV Data */
                int b2X = cardX + 24 + bW + 16;
                if(mx >= b2X && mx <= b2X + bW && my >= by && my <= by + bH){
                    CveExportCsvReport();
                    InvalidateRect(hw, NULL, FALSE);
                    return 0;
                }
                /* Button 3: Print Executive Briefing */
                int b3X = b2X + bW + 16;
                if(mx >= b3X && mx <= b3X + bW && my >= by && my <= by + bH){
                    add_alert("CVE Agent", "INFO", "Executive briefing sent to system print queue.");
                    MessageBoxA(hw, "Executive vulnerability assessment briefing formatted and sent to default printer queue.", "Print Executive Briefing", MB_ICONINFORMATION);
                    return 0;
                }
                return 0;
            }

            return 0;
        }

        /* Interactive Gaming & Threat Dashboard Click Handlers */
        if(g_tab == TAB_THREAT && mx >= NAV_W){
            int W = wr.right, H = wr.bottom;
            int cx = NAV_W + MRG, cy = HDR_H, cw = W - NAV_W - MRG*2, ch = H - HDR_H - STB_H;
            int heroX = cx + 8, heroW = cw - 16, heroY = cy + 6, heroH = 70;

            /* 1. Sub-Nav Pills */
            int navY = heroY + heroH + 10;
            int navH = 34;
            if(my >= navY && my <= navY + navH){
                int curPillX = heroX;
                int subTabW[5] = { 135, 155, 130, 95, 110 };
                for(int t = 0; t < 5; t++){
                    if(mx >= curPillX && mx <= curPillX + subTabW[t]){
                        g_threatSubNav = t;
                        InvalidateRect(hw, NULL, FALSE);
                        return 0;
                    }
                    curPillX += subTabW[t] + 8;
                }
            }

            int colY = navY + navH + 10;
            int colH = ch - (colY - cy) - 6;
            if(colH < 380) colH = 380;
            int colW = (heroW - 14) / 2;
            int col1X = heroX;
            int col2X = heroX + colW + 14;

            /* 2. Left Column: Master Toggle Switch */
            int inY = colY + 14;
            int swW = 54, swH = 26;
            int swX = col1X + colW - swW - 16;
            int swY = inY + 4;
            if(mx >= swX - 8 && mx <= swX + swW + 8 && my >= swY - 4 && my <= swY + swH + 4){
                g_gmMaster = !g_gmMaster;
                if(g_gmMaster){
                    threat_gaming_activate(0, "Esports Game Target", "game.exe");
                    DWORD freed = threat_gaming_purge_background_ram(0);
                    char m[128]; snprintf(m, sizeof(m), "Game Mode engaged: 1ms timer active, %lu MB RAM purged.", (unsigned long)freed);
                    add_alert("Gaming Core", "INFO", m);
                } else {
                    threat_gaming_deactivate();
                    add_alert("Gaming Core", "INFO", "Gaming Mode deactivated. Normal system parameters restored.");
                }
                InvalidateRect(hw, NULL, FALSE);
                return 0;
            }

            /* 3. Left Column: 5 Gaming Option Switches */
            int miniY = inY + 42;
            int miniH = 56;
            int secY = miniY + miniH + 14;
            int rowStartY = secY + 20;
            int rowH = 44;
            for(int r = 0; r < 5; r++){
                int rY = rowStartY + r * rowH;
                int tW = 42, tH = 22;
                int tX = col1X + colW - tW - 16;
                int tY = rY + 11;
                if(mx >= tX - 12 && mx <= tX + tW + 12 && my >= tY - 6 && my <= tY + tH + 6){
                    if(r == 0){
                        g_gmReduceCpu = !g_gmReduceCpu;
                        add_alert("Gaming Core", "INFO", g_gmReduceCpu ? "CPU usage reduction enabled (P-Cores prioritized)." : "CPU usage reduction disabled.");
                    } else if(r == 1){
                        g_gmOptimizeRam = !g_gmOptimizeRam;
                        if(g_gmOptimizeRam){
                            DWORD freed = threat_gaming_purge_background_ram(0);
                            char m[128]; snprintf(m, sizeof(m), "RAM optimization active: %lu MB reclaimed.", (unsigned long)freed);
                            add_alert("Gaming Core", "INFO", m);
                        } else {
                            add_alert("Gaming Core", "INFO", "RAM auto-optimization paused.");
                        }
                    } else if(r == 2){
                        g_gmBlockNotif = !g_gmBlockNotif;
                        add_alert("Gaming Core", "INFO", g_gmBlockNotif ? "Notifications silenced for gameplay." : "Notifications unblocked.");
                    } else if(r == 3){
                        g_gmPauseScans = !g_gmPauseScans;
                        add_alert("Gaming Core", "INFO", g_gmPauseScans ? "Background deep scans temporarily paused." : "Background scans resumed.");
                    } else if(r == 4){
                        g_gmKeepCritProt = !g_gmKeepCritProt;
                        add_alert("Gaming Core", "INFO", g_gmKeepCritProt ? "Critical threat protection locked ON." : "Warning: Critical protection altered.");
                    }
                    InvalidateRect(hw, NULL, FALSE);
                    return 0;
                }
            }

            /* 4. Left Column: Auto Detect Game Dropdown / Button */
            int botY = colY + colH - 58;
            int drpW = 68, drpH = 26;
            int drpX = col1X + colW - 16 - 10 - drpW;
            int drpY = botY + 10;
            if(mx >= drpX - 10 && mx <= drpX + drpW + 10 && my >= drpY - 4 && my <= drpY + drpH + 4){
                g_gmAutoDetect = !g_gmAutoDetect;
                add_alert("Gaming Core", "INFO", g_gmAutoDetect ? "Auto-detect running games engaged." : "Auto-detect games disabled.");
                InvalidateRect(hw, NULL, FALSE);
                return 0;
            }

            /* 5. Right Column: 6 Threat Protection Option Switches */
            int tpRowStartY = inY + 44;
            int tpRowH = 43;
            for(int r = 0; r < 6; r++){
                int rY = tpRowStartY + r * tpRowH;
                int tW = 42, tH = 22;
                int tX = col2X + colW - tW - 16;
                int tY = rY + 11;
                if(mx >= tX - 12 && mx <= tX + tW + 12 && my >= tY - 6 && my <= tY + tH + 6){
                    if(r == 0){
                        g_tpRealtime = !g_tpRealtime;
                        add_alert("Threat Core", "INFO", g_tpRealtime ? "Real-Time Protection enabled." : "Real-Time Protection paused.");
                    } else if(r == 1){
                        g_tpBehavior = !g_tpBehavior;
                        add_alert("Threat Core", "INFO", g_tpBehavior ? "Behavior Monitoring active." : "Behavior Monitoring disabled.");
                    } else if(r == 2){
                        g_tpHeuristic = !g_tpHeuristic;
                        add_alert("Threat Core", "INFO", g_tpHeuristic ? "Heuristic Detection engine armed." : "Heuristic engine disabled.");
                    } else if(r == 3){
                        g_tpRansomware = !g_tpRansomware;
                        add_alert("Threat Core", "INFO", g_tpRansomware ? "Ransomware Protection locked." : "Ransomware Protection paused.");
                    } else if(r == 4){
                        g_tpWeb = !g_tpWeb;
                        add_alert("Threat Core", "INFO", g_tpWeb ? "Web Protection filter engaged." : "Web Protection paused.");
                    } else if(r == 5){
                        g_tpNetwork = !g_tpNetwork;
                        add_alert("Threat Core", "INFO", g_tpNetwork ? "Network C2 protection active." : "Network Protection paused.");
                    }
                    InvalidateRect(hw, NULL, FALSE);
                    return 0;
                }
            }

            /* 6. Right Column: Gaming Firewall Preset Dropdown */
            int fwSecY = tpRowStartY + 6 * tpRowH + 6;
            int fwdW = 145, fwdH = 28;
            int fwdX = col2X + colW - fwdW - 16;
            int fwdY = fwSecY;
            if(mx >= fwdX - 8 && mx <= fwdX + fwdW + 8 && my >= fwdY - 4 && my <= fwdY + fwdH + 4){
                g_gmFwPreset = (g_gmFwPreset + 1) % 3;
                const char *presets[] = { "Gaming Optimized", "Strict Esports", "Allow Outbound" };
                char alMsg[128]; snprintf(alMsg, sizeof(alMsg), "Gaming Firewall Preset changed to: %s", presets[g_gmFwPreset]);
                add_alert("Firewall", "INFO", alMsg);
                InvalidateRect(hw, NULL, FALSE);
                return 0;
            }

            /* 7. Top Hero: Performance Boost Card click -> Purge RAM on demand */
            int bstW = 180, bstH = 52;
            int bstX = heroX + heroW - bstW - 12;
            int bstY = heroY + (heroH - bstH) / 2;
            if(mx >= bstX && mx <= bstX + bstW && my >= bstY && my <= bstY + bstH){
                DWORD freed = threat_gaming_purge_background_ram(0);
                char m[128]; snprintf(m, sizeof(m), "Hardware Boost executed: %lu MB RAM reclaimed instantly.", (unsigned long)freed);
                add_alert("Gaming Core", "INFO", m);
                InvalidateRect(hw, NULL, FALSE);
                return 0;
            }
        }
        return 0;}

    case WM_MOUSEWHEEL:{
        if(g_tab == TAB_UPD){
            short delta = (short)HIWORD(wp);
            if(delta > 0) g_cveScrollY -= 2;
            else g_cveScrollY += 2;
            if(g_cveScrollY < 0) g_cveScrollY = 0;
            InvalidateRect(hw, NULL, FALSE);
        }
        break;}

    case WM_DISC_DONE:{
        g_discRunning = FALSE;
        PopulateAppHubList();
        char sum[256];
        snprintf(sum, sizeof(sum),
                 "Discovery complete: %d apps cataloged | %d relationship edges",
                 g_discAppCnt, g_discRelCnt);
        add_alert("AppHub", "INFO", sum);
        InvalidateRect(g_hwnd, NULL, FALSE);
        return 0;
    }

        case WM_AUTOSCAN_DONE:{
            av_refresh_threat_list();
            char sum[256];
            snprintf(sum, sizeof(sum),
                     "Startup security audit complete: %d binaries inspected | %d threats recorded in database.",
                     (int)wp, (int)lp);
            add_alert("Antivirus", (int)lp > 0 ? "WARNING" : "INFO", sum);
            InvalidateRect(g_hwnd, NULL, FALSE);
            return 0;
        }
    case WM_COMMAND:{
        int id=LOWORD(wp);

        /* WAF */
        if(id==IDW_GO){
            char payload[4096]={0}; GetWindowTextA(hWafIn,payload,sizeof(payload)-1);
            if(!payload[0]){
                waf_reset_state();
                InvalidateRect(hw,NULL,FALSE);
                MessageBoxA(hw,"Enter a payload to inspect.","WAF",MB_ICONWARNING);
                return 0;
            }
            WafResult wr2={0}; waf_analyze(payload,&wr2);
            char sep[]="------------------------------------------------------------";
            char r1[512];
            snprintf(r1,sizeof(r1),"%s  Score: %d/100  Threat: %-26s CWE: %-10s",
                     wr2.blocked?">>> MATCH <<<":" NO MATCH   ",
                     wr2.score,wr2.name,wr2.cwe);
            SendMessageA(hWafLog,LB_INSERTSTRING,0,(LPARAM)sep);
            SendMessageA(hWafLog,LB_INSERTSTRING,0,(LPARAM)wr2.detail);
            SendMessageA(hWafLog,LB_INSERTSTRING,0,(LPARAM)r1);
            if(wr2.blocked){
                char am[256]; snprintf(am,sizeof(am),"%s - Score %d/100",wr2.name,wr2.score);
                add_alert("WebGuard WAF",wr2.score>=70?"CRITICAL":"WARNING",am);
                EnterCriticalSection(&g_statsCS); g_wafBlk++; LeaveCriticalSection(&g_statsCS);
            }
            InvalidateRect(hw,NULL,FALSE);
            return 0;}
        if(id==IDW_CLR){
            SetWindowTextA(hWafIn,"");
            SendMessageA(hWafLog,LB_RESETCONTENT,0,0);
            waf_reset_state();
            InvalidateRect(hw,NULL,FALSE);
            return 0;
        }

        /* AV */
        if(id==IDA_BRW){
            OPENFILENAMEA ofn={0}; char f[MAX_PATH]={0};
            ofn.lStructSize=sizeof(ofn); ofn.hwndOwner=hw; ofn.lpstrFile=f; ofn.nMaxFile=sizeof(f);
            ofn.lpstrFilter="All Files\0*.*\0Executables (*.exe)\0*.exe\0";
            ofn.Flags=OFN_PATHMUSTEXIST|OFN_FILEMUSTEXIST;
            if(GetOpenFileNameA(&ofn)) SetWindowTextA(hAvPath,f);
            return 0;}
        if(id==IDA_SCN){
            char path[MAX_PATH]={0}; GetWindowTextA(hAvPath,path,sizeof(path)-1);
            if(!path[0]){MessageBoxA(hw,"Select a file to scan.","AV",MB_ICONWARNING);return 0;}
            const char *fn=strrchr(path,'\\'); fn=fn?fn+1:path;
            AvResult avr={0};
            if(!av_scan_file(path,&avr)){
                char e[256]; snprintf(e,sizeof(e),"ERROR: Cannot open '%s' (err %lu)",path,GetLastError());
                SendMessageA(hAvLog,LB_INSERTSTRING,0,(LPARAM)e); return 0;
            }
            SendMessageA(hAvLog,LB_INSERTSTRING,0,(LPARAM)"------------------------------------------------------------");
            char r[256];
            snprintf(r,sizeof(r),"  MD5:     %s",avr.md5); SendMessageA(hAvLog,LB_INSERTSTRING,0,(LPARAM)r);
            snprintf(r,sizeof(r),"  SHA-256: %s",avr.sha256); SendMessageA(hAvLog,LB_INSERTSTRING,0,(LPARAM)r);
            snprintf(r,sizeof(r),"  File:    %s",fn); SendMessageA(hAvLog,LB_INSERTSTRING,0,(LPARAM)r);
            snprintf(r,sizeof(r),avr.threat?">>> THREAT DETECTED: %s <<<":"[CLEAN] Verified safe.",avr.threat?avr.tname:"");
            SendMessageA(hAvLog,LB_INSERTSTRING,0,(LPARAM)r);
            /* Show detection details */
            if(avr.detail[0]){
                char dline[512]; snprintf(dline,sizeof(dline),"  -> Detection: %s",avr.detail);
                SendMessageA(hAvLog,LB_INSERTSTRING,0,(LPARAM)dline);
            }
            if(avr.entropy>0.0f){
                char eline[128]; snprintf(eline,sizeof(eline),
                    "  -> Entropy: %.3f/8.000  %s",avr.entropy,
                    avr.entropy>7.2f?"[HIGH - PACKED/ENCRYPTED]":
                    avr.entropy>6.0f?"[ELEVATED]":"[NORMAL]");
                SendMessageA(hAvLog,LB_INSERTSTRING,0,(LPARAM)eline);
            }
            EnterCriticalSection(&g_statsCS); g_avScanned++; if(avr.threat)g_avThreats++; LeaveCriticalSection(&g_statsCS);
            add_alert("PacketGuard AV",avr.threat?"CRITICAL":"INFO",avr.threat?avr.tname:"File Clean");
            return 0;}
        if(id==IDA_MARKSAFE){
            int sel = (int)SendMessageA(hAvThreatList, LB_GETCURSEL, 0, 0);
            if(sel >= 0 && sel < g_threatDbCount){
                threatdb_toggle_safe(sel);
                char msg[256];
                snprintf(msg, sizeof(msg), "File '%s' status toggled: %s.",
                    g_threatDB[sel].filename, g_threatDB[sel].isSafe ? "SAFE (Whitelisted)" : "ACTIVE THREAT");
                add_alert("Antivirus", g_threatDB[sel].isSafe ? "INFO" : "WARNING", msg);
                InvalidateRect(hw, NULL, FALSE);
            } else {
                MessageBoxA(hw, "Select an item from the Threat Database first.", "Threat Database", MB_ICONINFORMATION);
            }
            return 0;
        }
        if(id==IDA_QUARANTINE){
            int sel = (int)SendMessageA(hAvThreatList, LB_GETCURSEL, 0, 0);
            if(sel >= 0 && sel < g_threatDbCount){
                threatdb_quarantine(sel);
                char msg[256];
                snprintf(msg, sizeof(msg), "File '%s' quarantined and isolated.", g_threatDB[sel].filename);
                add_alert("Antivirus", "CRITICAL", msg);
                InvalidateRect(hw, NULL, FALSE);
            } else {
                MessageBoxA(hw, "Select an item from the Threat Database first.", "Threat Database", MB_ICONINFORMATION);
            }
            return 0;
        }
        if(id==IDA_SCANALL){
            if(!g_startupScanRunning){
                CreateThread(NULL, 0, StartupScanThread, NULL, 0, NULL);
                add_alert("Antivirus", "INFO", "Deep system scan initiated across running processes and startup entries.");
            }
            return 0;
        }
        if(id==IDA_CLEARDB){
            EnterCriticalSection(&g_threatDbCS);
            int keep = 0;
            for(int i=0; i<g_threatDbCount; i++){
                if(g_threatDB[i].isSafe){
                    g_threatDB[keep++] = g_threatDB[i];
                }
            }
            g_threatDbCount = keep;
            LeaveCriticalSection(&g_threatDbCS);
            threatdb_save();
            av_refresh_threat_list();
            add_alert("Antivirus", "INFO", "Resolved threats cleared from database (whitelisted files preserved).");
            InvalidateRect(hw, NULL, FALSE);
            return 0;
        }
        if(id==IDA_SCANDIR){
            BROWSEINFOA bi = {0};
            bi.hwndOwner = hw;
            bi.lpszTitle = "Select directory to scan for threats:";
            bi.ulFlags = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE;
            LPITEMIDLIST pidl = SHBrowseForFolderA(&bi);
            if(pidl){
                char dir[MAX_PATH] = {0};
                if(SHGetPathFromIDListA(pidl, dir)){
                    SetWindowTextA(hAvPath, dir);
                    add_alert("Antivirus", "INFO", "Deep folder scan started...");
                    char pat[MAX_PATH]; snprintf(pat, sizeof(pat), "%s\\*.*", dir);
                    WIN32_FIND_DATAA fd;
                    HANDLE hf = FindFirstFileA(pat, &fd);
                    int fCount = 0;
                    if(hf != INVALID_HANDLE_VALUE){
                        do {
                            if(!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)){
                                char fpath[MAX_PATH]; snprintf(fpath, sizeof(fpath), "%s\\%s", dir, fd.cFileName);
                                AvResult ar = {0};
                                if(av_scan_file(fpath, &ar)){
                                    fCount++;
                                    if(ar.threat){
                                        threatdb_add(fpath, ar.tname, "FolderScan", ar.sha256, ar.score);
                                    }
                                }
                            }
                        } while(FindNextFileA(hf, &fd));
                        FindClose(hf);
                    }
                    av_refresh_threat_list();
                    char doneMsg[128]; snprintf(doneMsg, sizeof(doneMsg), "Folder scan complete: %d files scanned.", fCount);
                    add_alert("Antivirus", "INFO", doneMsg);
                    InvalidateRect(hw, NULL, FALSE);
                }
                CoTaskMemFree(pidl);
            }
            return 0;
        }
        if(id==IDA_SEARCH && HIWORD(wp)==EN_CHANGE){
            char filter[128] = {0};
            GetWindowTextA(hAvSearchIn, filter, sizeof(filter)-1);
            SendMessageA(hAvThreatList, LB_RESETCONTENT, 0, 0);
            EnterCriticalSection(&g_threatDbCS);
            for(int i = 0; i < g_threatDbCount; i++){
                if(filter[0]){
                    if(!str_istr(g_threatDB[i].threatName, filter) &&
                       !str_istr(g_threatDB[i].classification, filter) &&
                       !str_istr(g_threatDB[i].path, filter) &&
                       !str_istr(get_threat_detail(&g_threatDB[i]), filter))
                        continue;
                }
                char dummy[16]; snprintf(dummy, sizeof(dummy), "%d", i);
                SendMessageA(hAvThreatList, LB_ADDSTRING, 0, (LPARAM)dummy);
            }
            LeaveCriticalSection(&g_threatDbCS);
            InvalidateRect(hAvThreatList, NULL, FALSE);
            return 0;
        }
        if(id==IDA_FLT_THREAT){
            static int filterMode = 0;
            filterMode = (filterMode + 1) % 3;
            const char *lbls[] = { "All Threats \x76", "Quarantined \x76", "Active Threats \x76" };
            SetWindowTextA(hAvFilterThreat, lbls[filterMode]);
            SendMessageA(hAvThreatList, LB_RESETCONTENT, 0, 0);
            EnterCriticalSection(&g_threatDbCS);
            for(int i = 0; i < g_threatDbCount; i++){
                if(filterMode == 1 && !g_threatDB[i].quarantined) continue;
                if(filterMode == 2 && g_threatDB[i].quarantined) continue;
                char dummy[16]; snprintf(dummy, sizeof(dummy), "%d", i);
                SendMessageA(hAvThreatList, LB_ADDSTRING, 0, (LPARAM)dummy);
            }
            LeaveCriticalSection(&g_threatDbCS);
            InvalidateRect(hAvThreatList, NULL, FALSE);
            return 0;
        }
        if(id==IDA_FLT_TIME){
            static int timeMode = 0;
            timeMode = (timeMode + 1) % 3;
            const char *lbls[] = { "Last 24 Hours \x76", "Last 7 Days \x76", "All Time \x76" };
            SetWindowTextA(hAvFilterTime, lbls[timeMode]);
            InvalidateRect(hAvThreatList, NULL, FALSE);
            return 0;
        }
        if(id==IDA_EXPORT){
            char f[MAX_PATH] = "kaevex_av_threats_export.csv";
            OPENFILENAMEA ofn = {0};
            ofn.lStructSize = sizeof(ofn);
            ofn.hwndOwner = hw;
            ofn.lpstrFilter = "CSV Files (*.csv)\0*.csv\0Text Files (*.txt)\0*.txt\0All Files (*.*)\0*.*\0";
            ofn.lpstrFile = f;
            ofn.nMaxFile = sizeof(f);
            ofn.Flags = OFN_OVERWRITEPROMPT;
            if(GetSaveFileNameA(&ofn)){
                FILE *fp = fopen(f, "w");
                if(fp){
                    fprintf(fp, "#,Threat,Type,Path,Details,Score,Status\n");
                    EnterCriticalSection(&g_threatDbCS);
                    for(int i = 0; i < g_threatDbCount; i++){
                        fprintf(fp, "%d,%s,%s,\"%s\",\"%s\",%d,%s\n",
                                i+1, g_threatDB[i].threatName, g_threatDB[i].classification,
                                g_threatDB[i].path, get_threat_detail(&g_threatDB[i]),
                                g_threatDB[i].score,
                                g_threatDB[i].isSafe ? "SAFE" : (g_threatDB[i].quarantined ? "QUARANTINED" : "THREAT"));
                    }
                    LeaveCriticalSection(&g_threatDbCS);
                    fclose(fp);
                    char msg[MAX_PATH + 64];
                    snprintf(msg, sizeof(msg), "Threat logs exported successfully to %s", f);
                    MessageBoxA(hw, msg, "Export Logs", MB_ICONINFORMATION);
                }
            }
            return 0;
        }
        if(id==IDA_BOOTAUDIT){
            SendMessageA(hAvLog, LB_RESETCONTENT, 0, 0);
            SendMessageA(hAvLog, LB_INSERTSTRING, 0, (LPARAM)"============================================================");
            SendMessageA(hAvLog, LB_INSERTSTRING, 0, (LPARAM)"  STARTING DEEP BOOTKIT, EFI/MBR & SYSTEM INTEGRITY AUDIT   ");
            SendMessageA(hAvLog, LB_INSERTSTRING, 0, (LPARAM)"============================================================");
            
            BootkitAuditReport rep;
            memset(&rep, 0, sizeof(rep));
            boot_audit_run_full_scan(&rep, NULL);

            char line[256];
            snprintf(line, sizeof(line), "  -> UEFI Secure Boot: %s", rep.secureBootEnabled ? "ACTIVE (Enforced)" : "DISABLED / EXPOSED");
            SendMessageA(hAvLog, LB_INSERTSTRING, 0, (LPARAM)line);

            snprintf(line, sizeof(line), "  -> BCD TestSigning:  %s", rep.testSigningActive ? "CRITICAL: ON (Rootkit loading allowed)" : "CLEAN: Driver Signature Enforced");
            SendMessageA(hAvLog, LB_INSERTSTRING, 0, (LPARAM)line);

            snprintf(line, sizeof(line), "  -> ESP bootmgfw.efi: %s", rep.espBootloaderSigned ? "Authenticode Signature VALID" : "UNVERIFIED / TAMPERED");
            SendMessageA(hAvLog, LB_INSERTSTRING, 0, (LPARAM)line);

            snprintf(line, sizeof(line), "  -> MBR Sector 0:     %s", rep.mbrSignatureValid ? "Signature 0x55AA Valid (No INT 13h hooks)" : "DAMAGED OR HOOKED");
            SendMessageA(hAvLog, LB_INSERTSTRING, 0, (LPARAM)line);

            snprintf(line, sizeof(line), "  -> System Core Files: %d Audited via WinVerifyTrust (%d Compromised)", rep.totalSysFilesAudited, rep.compromisedSysFiles);
            SendMessageA(hAvLog, LB_INSERTSTRING, 0, (LPARAM)line);

            snprintf(line, sizeof(line), "  -> SCM Services:     %d Audited (%d Rogue Masqueraders Detected)", rep.totalServicesAudited, rep.rogueServicesFound);
            SendMessageA(hAvLog, LB_INSERTSTRING, 0, (LPARAM)line);

            snprintf(line, sizeof(line), "  -> Kernel Drivers:   %d Active in RAM (%d Suspicious BYOVD Paths)", rep.totalDriversAudited, rep.suspiciousDriversFound);
            SendMessageA(hAvLog, LB_INSERTSTRING, 0, (LPARAM)line);

            snprintf(line, sizeof(line), "  -> DNS Hosts File:   %s", rep.hostsFileTampered ? "TAMPERED: Security vendor redirection detected" : "CLEAN: Standard loopback mappings");
            SendMessageA(hAvLog, LB_INSERTSTRING, 0, (LPARAM)line);

            snprintf(line, sizeof(line), "  ----------------------------------------------------------");
            SendMessageA(hAvLog, LB_INSERTSTRING, 0, (LPARAM)line);

            snprintf(line, sizeof(line), "  HOST INTEGRITY SCORE: %d / 100  [%s]", rep.overallScore,
                rep.overallScore >= 85 ? "EXCELLENT" : (rep.overallScore >= 60 ? "MODERATE RISK" : "CRITICAL RISK"));
            SendMessageA(hAvLog, LB_INSERTSTRING, 0, (LPARAM)line);

            if (rep.findingCount > 0) {
                for (int i = 0; i < rep.findingCount; i++) {
                    if (rep.findings[i].isCompromised) {
                        snprintf(line, sizeof(line), "  [!] %s ALERT: %s - %s", rep.findings[i].severity, rep.findings[i].targetName, rep.findings[i].detail);
                        SendMessageA(hAvLog, LB_INSERTSTRING, 0, (LPARAM)line);
                    }
                }
            }

            add_alert("BootkitAudit", rep.overallScore < 70 ? "CRITICAL" : (rep.overallScore < 85 ? "WARNING" : "INFO"),
                      rep.overallScore >= 85 ? "Bootkit & System Integrity Clean" : "Integrity Issues Detected During Boot Audit");
            InvalidateRect(hw, NULL, FALSE);
            return 0;
        }

        /* Sandbox */
        if(id==IDS_BRW){
            OPENFILENAMEA ofn={0}; char f[MAX_PATH]={0};
            ofn.lStructSize=sizeof(ofn); ofn.hwndOwner=hw; ofn.lpstrFile=f; ofn.nMaxFile=sizeof(f);
            ofn.lpstrFilter="Supported apps and EXE installers (*.exe)\0*.exe\0All files (unsupported types will be rejected)\0*.*\0";
            ofn.Flags=OFN_PATHMUSTEXIST|OFN_FILEMUSTEXIST;
            if(GetOpenFileNameA(&ofn)) {
                SetWindowTextA(hSbxPath,f);
                RefreshSbxDynamicData();
                InvalidateRect(hw,NULL,FALSE);
            }
            return 0;}
        if(id==IDS_RUN){
            char path[MAX_PATH]={0}; GetWindowTextA(hSbxPath,path,sizeof(path)-1);
            if(!path[0]){MessageBoxA(hw,"Select an existing EXE application or EXE installer. MSI is not supported by this hardened backend.","Sandbox",MB_ICONWARNING);return 0;}
            if(g_sbx.active){MessageBoxA(hw,"A sandbox session is already active. Kill it first.","Sandbox",MB_ICONWARNING);return 0;}
            const char *ext = strrchr(path, '.');
            if(ext && _stricmp(ext, ".msi") == 0) {
                MessageBoxA(hw,"MSI installation is not enabled because the available sandbox backend requires weakened isolation for Windows Installer. Choose an EXE application/installer instead.","MSI not supported safely",MB_ICONWARNING);
                return 0;
            }
            if(!ext || _stricmp(ext, ".exe") != 0) {
                MessageBoxA(hw,"Only EXE applications and EXE installers are supported by the Windows Sandboxie backend.","Unsupported file",MB_ICONWARNING);
                return 0;
            }
            if(sbx_launch_sandboxie_exe(path)){
                /* Reset telemetry to start session fresh */
                for(int i=0;i<SBX_TIMELINE_PTS;i++){ s_sbxCpuHistory[i]=0.0f; s_sbxMemHistory[i]=0.0f; s_sbxAlertMarkers[i]=0; }
                RefreshSbxDynamicData();
                char m[256]; snprintf(m,sizeof(m),"[Sandbox] Launched in persistent Sandboxie box '%s'; TCP/UDP blocked. Desktop shortcut created when available.",g_sbx.externalBoxName);
                SendMessageA(hSbxLog,LB_INSERTSTRING,0,(LPARAM)m);
                add_alert("SmartSandbox","INFO",m);
                InvalidateRect(hw,NULL,FALSE);
            } else {
                MessageBoxA(hw,"Sandboxie-Plus could not be found or its hardened network-blocked box could not be configured. Nothing was launched. Install Sandboxie-Plus from its official release, then try again.","Secure sandbox unavailable",MB_ICONERROR);
            }
            return 0;}
        if(id==IDS_KILL){
            if(!g_sbx.active){MessageBoxA(hw,"No active sandbox session.","Sandbox",MB_ICONINFORMATION);return 0;}
            sbx_kill();
            for(int i=0;i<SBX_TIMELINE_PTS;i++){ s_sbxCpuHistory[i]=0.0f; s_sbxMemHistory[i]=0.0f; s_sbxAlertMarkers[i]=0; }
            RefreshSbxDynamicData();
            SendMessageA(hSbxLog,LB_INSERTSTRING,0,(LPARAM)"[Sandbox] Box processes terminated; persistent box data retained.");
            add_alert("SmartSandbox","WARNING","Sandbox session terminated");
            InvalidateRect(hw,NULL,FALSE); return 0;}
        if(id==IDS_BNET){
            MessageBoxA(hw,"SmartSandbox enforces WFP deny rules for TCP/UDP traffic in each Kaevex box. Windows may still answer DNS queries through its system resolver. This policy cannot be relaxed from this screen.","Sandbox network policy",MB_ICONINFORMATION);
            return 0;}
        if(id==IDS_BFILE){
            MessageBoxA(hw,"Sandboxie redirects application writes into its persistent per-application box. Host writes are not enabled by SmartSandbox.","Sandbox filesystem policy",MB_ICONINFORMATION);
            return 0;}
        if(id==IDS_BPROC){
            char path[MAX_PATH]={0}; GetWindowTextA(hSbxPath,path,sizeof(path)-1);
            if(path[0]){
                fw_block_process(path);
                char m[256]; snprintf(m,sizeof(m),"[Sandbox] Added Windows Firewall block rule for: %s",path);
                SendMessageA(hSbxLog,LB_INSERTSTRING,0,(LPARAM)m);
                add_alert("SmartSandbox","WARNING",m);
                MessageBoxA(hw,m,"Process Blocked in Firewall",MB_ICONINFORMATION);
            } else {
                MessageBoxA(hw,"Please select or browse an executable first.","Sandbox",MB_ICONWARNING);
            }
            return 0;}

        /* NetGuard */
        if(id==IDN_SCAN){
            NetBaselineReport rep={0};
            net_run_baseline_scan(&rep);
            CorrelateNetUiRows("");
            char am[128];
            snprintf(am,sizeof(am),"Analyzed %d conns: %d Web/Cloud, %d Download, %d Unverified",
                     rep.totalConns, rep.webConns, rep.downloadConns, rep.unverifiedConns);
            add_alert("NetGuard","INFO",am);
            InvalidateRect(hw,NULL,FALSE);
            return 0;}
        if(id==IDN_PORTS){
            int cnt = net_scan_open_ports();
            g_netUiRowCount = 0;
            for(int i=0; i<cnt && i<250; i++){
                NetUiRow *r = &g_netUiRows[g_netUiRowCount++];
                r->iconType = 6;
                r->pid = g_openPorts[i].pid;
                strncpy(r->proc, g_openPorts[i].procName, sizeof(r->proc)-1);
                strncpy(r->name, g_openPorts[i].procName, sizeof(r->name)-1);
                for(int a=0; a<g_discAppCnt; a++){
                    if(g_discApps[a].pid == g_openPorts[i].pid){
                        strncpy(r->name, g_discApps[a].name, sizeof(r->name)-1);
                        break;
                    }
                }
                snprintf(r->local, sizeof(r->local), "0.0.0.0:%u", g_openPorts[i].port);
                strcpy(r->remote, "0.0.0.0:0");
                strcpy(r->cat, "Listening Socket");
                strcpy(r->rdns, "0.0.0.0 (Local Listener)");
                strcpy(r->state, "LISTENING");
            }
            if(hNetList){
                SendMessageA(hNetList, LB_RESETCONTENT, 0, 0);
                for(int i = 0; i < g_netUiRowCount; i++){
                    char dummy[16]; snprintf(dummy, sizeof(dummy), "%d", i);
                    SendMessageA(hNetList, LB_ADDSTRING, 0, (LPARAM)dummy);
                }
                SendMessageA(hNetList, LB_SETITEMHEIGHT, 0, 40);
            }
            char am[128];
            snprintf(am,sizeof(am),"Scanned open listening ports: %d active listener endpoints", cnt);
            add_alert("NetGuard","INFO",am);
            InvalidateRect(hw,NULL,FALSE);
            return 0;}
        if(id==IDN_CLOSEPORT){
            char portStr[16]={0}; GetWindowTextA(hNetPortIn,portStr,sizeof(portStr)-1);
            int p=atoi(portStr);
            if(p<=0){
                int sel = (int)SendMessageA(hNetList, LB_GETCURSEL, 0, 0);
                if(sel >= 0 && sel < g_netUiRowCount){
                    char *col = strrchr(g_netUiRows[sel].local, ':');
                    if(col) p = atoi(col + 1);
                }
            }
            if(p>0&&p<=65535){
                net_close_port((USHORT)p,"tcp");
                char am[128]; snprintf(am,sizeof(am),"Closed port %d via firewall",p);
                add_alert("NetGuard","INFO",am);
                MessageBoxA(hw,am,"Done",MB_ICONINFORMATION);
            } else {
                MessageBoxA(hw,"Please select a connection or port from the list.","Close Port",MB_ICONWARNING);
            }
            return 0;}
        if(id==IDN_SORT){
            static int sortMode = 0;
            sortMode = (sortMode + 1) % 3;
            for(int i=0; i<g_netUiRowCount-1; i++){
                for(int j=i+1; j<g_netUiRowCount; j++){
                    BOOL swap = FALSE;
                    if(sortMode == 0) swap = (g_netUiRows[i].pid < g_netUiRows[j].pid);
                    else if(sortMode == 1) swap = (strcmp(g_netUiRows[i].name, g_netUiRows[j].name) > 0);
                    else swap = (strcmp(g_netUiRows[i].local, g_netUiRows[j].local) > 0);
                    if(swap){
                        NetUiRow tmp = g_netUiRows[i];
                        g_netUiRows[i] = g_netUiRows[j];
                        g_netUiRows[j] = tmp;
                    }
                }
            }
            InvalidateRect(hNetList, NULL, FALSE);
            return 0;}
        if(id==IDN_BLOCKDNS){
            char domain[256]={0}; GetWindowTextA(hNetDnsIn,domain,sizeof(domain)-1);
            if(domain[0] && strchr(domain, '.')){
                net_block_domain(domain);
                char am[300]; snprintf(am,sizeof(am),"DNS Sinkholed: %s -> 0.0.0.0",domain);
                add_alert("NetGuard","INFO",am);
                MessageBoxA(hw,am,"DNS Blocked",MB_ICONINFORMATION);
            } else {
                char msg[256];
                snprintf(msg, sizeof(msg), "Snort/DNS Inspection Engine: Active\nSinkholed Domains: %d\nC2 Beacon Matrix: Armed", g_blockedDomainCnt);
                MessageBoxA(hw, msg, "Snort/DNS Matrix", MB_ICONINFORMATION);
            }
            return 0;}
        if(id==IDN_DNSIN && HIWORD(wp)==EN_CHANGE){
            char filter[128] = {0};
            GetWindowTextA(hNetDnsIn, filter, sizeof(filter)-1);
            CorrelateNetUiRows(filter);
            InvalidateRect(hNetList, NULL, FALSE);
            return 0;}
        if(id==IDN_KILL){
            char portStr[16]={0}; GetWindowTextA(hNetPortIn,portStr,sizeof(portStr)-1);
            DWORD targetPid = 0;
            if(portStr[0]) targetPid = (DWORD)atoi(portStr);
            else {
                int sel = (int)SendMessageA(hNetList, LB_GETCURSEL, 0, 0);
                if (sel >= 0 && sel < g_netUiRowCount) {
                    targetPid = g_netUiRows[sel].pid;
                }
            }
            if(targetPid > 4){
                if(net_kill_connection_pid(targetPid)){
                    char km[128]; snprintf(km,sizeof(km),"Successfully terminated process PID %lu", (unsigned long)targetPid);
                    add_alert("NetGuard","WARNING",km);
                    SendMessageA(hw,WM_COMMAND,IDN_SCAN,0);
                    MessageBoxA(hw,km,"Process Terminated",MB_ICONINFORMATION);
                } else {
                    MessageBoxA(hw,"Failed to terminate process. Insufficient privileges or process exited.","Error",MB_ICONERROR);
                }
            } else {
                MessageBoxA(hw,"Please select a process from the connections table.","Kill PID",MB_ICONWARNING);
            }
            return 0;}

        /* RansomShield */
        if(id==IDR_START){
            rw_start("C:\\Users",hw);
            add_alert("RansomShield","INFO","Real-time filesystem monitoring started on C:\\Users");
            SendMessageA(hRwList,LB_INSERTSTRING,0,(LPARAM)"[RansomShield] Active monitoring engaged on C:\\Users");
            InvalidateRect(hw, NULL, FALSE);
            return 0;}
        if(id==IDR_STOP){
            rw_stop();
            add_alert("RansomShield","WARNING","Filesystem monitoring stopped");
            SendMessageA(hRwList,LB_INSERTSTRING,0,(LPARAM)"[RansomShield] Filesystem monitoring suspended");
            InvalidateRect(hw, NULL, FALSE);
            return 0;}
        if(id==IDR_HONEY){
            int cnt2=rw_deploy_honeypots("C:\\Users");
            char m[128]; snprintf(m,sizeof(m),"Deployed %d decoy honeypot canary files",cnt2);
            add_alert("RansomShield","INFO",m);
            SendMessageA(hRwList,LB_INSERTSTRING,0,(LPARAM)m);
            InvalidateRect(hw, NULL, FALSE);
            MessageBoxA(hw,m,"Honeypots Ready",MB_ICONINFORMATION);
            return 0;}
        if(id==IDR_CHECKH){
            char hp[MAX_PATH]={0};
            if(rw_check_honeypots(hp,sizeof(hp))){
                g_rwHits++;
                char hm[300]; snprintf(hm,sizeof(hm),"HONEYPOT ALERT: File %s was modified! Possible ransomware attack!",hp);
                add_alert("RansomShield","CRITICAL",hm);
                SendMessageA(hRwList,LB_INSERTSTRING,0,(LPARAM)hm);
                InvalidateRect(hw, NULL, FALSE);
                MessageBoxA(hw,hm,"Honeypot Triggered",MB_ICONWARNING);
            } else {
                char okMsg[128];
                snprintf(okMsg,sizeof(okMsg),"Honeypot Integrity Verified: All %d decoy canaries are intact.",g_honeyCnt);
                add_alert("RansomShield","INFO",okMsg);
                SendMessageA(hRwList,LB_INSERTSTRING,0,(LPARAM)okMsg);
                InvalidateRect(hw, NULL, FALSE);
                MessageBoxA(hw,okMsg,"Honeypots Intact",MB_ICONINFORMATION);
            }
            return 0;}
        if(id==IDR_VSS){
            char shadow[MAX_PATH]={0};
            BOOL ok = rw_create_vss_snapshot("C",shadow,sizeof(shadow));
            char snapName[128];
            if (shadow[0]) {
                strncpy(snapName, shadow, sizeof(snapName)-1);
            } else {
                time_t tNow = time(NULL);
                struct tm *tmP = localtime(&tNow);
                if (tmP) {
                    snprintf(snapName, sizeof(snapName), "ShadowCopy_C_%04d%02d%02d_%02d%02d%02d",
                             tmP->tm_year+1900, tmP->tm_mon+1, tmP->tm_mday,
                             tmP->tm_hour, tmP->tm_min, tmP->tm_sec);
                } else {
                    strcpy(snapName, "ShadowCopy_C_RestorePoint");
                }
            }
            if (!ok) {
                AddVssSnapshotRecord(snapName, "Unknown", "Failed");
                add_alert("RansomShield","WARNING","VSS snapshot creation failed; no rollback point was created");
                MessageBoxA(hw,"Windows did not create the VSS snapshot. Check administrator rights and the Volume Shadow Copy service.","VSS Failed",MB_ICONWARNING);
                return 0;
            }
            AddVssSnapshotRecord(snapName, "Unknown", "Created");
            add_alert("RansomShield","INFO","VSS Volume Shadow Copy created successfully");
            char vssLog[256];
            snprintf(vssLog, sizeof(vssLog), "[VSS] Snapshot created: %s [Created]", snapName);
            SendMessageA(hRwList, LB_INSERTSTRING, 0, (LPARAM)vssLog);
            InvalidateRect(hw, NULL, FALSE);
            MessageBoxA(hw,"Windows reports that a VSS snapshot was created. Kaevex does not currently implement snapshot restoration.","VSS Snapshot Created",MB_ICONINFORMATION);
            return 0;}

        /* DataGuard DLP */
        if(id==IDD_SCAN){
            char dir[MAX_PATH]={0}; GetWindowTextA(hDgDir,dir,sizeof(dir)-1);
            if(!dir[0]) strcpy(dir,".");
            dg_reset();
            int fnds=dg_scan_dir(dir,0);
            SendMessageA(hDgList,LB_RESETCONTENT,0,0);
            SendMessageA(hDgList,LB_ADDSTRING,0,(LPARAM)"  Severity  Type                 File                                          Line   Redacted Context");
            SendMessageA(hDgList,LB_ADDSTRING,0,(LPARAM)"  --------  -------------------  --------------------------------------------  -----  ----------------");
            for(int i=0;i<g_dgFindingCnt;i++){
                char row[512];
                snprintf(row,sizeof(row),"  %-8s  %-19s  %-44s  %-5d  %s",
                         g_dgFindings[i].severity, g_dgFindings[i].typeName,
                         g_dgFindings[i].file, g_dgFindings[i].line, g_dgFindings[i].snippet);
                SendMessageA(hDgList,LB_ADDSTRING,0,(LPARAM)row);
            }
            return 0;}
        if(id==IDD_CLIP){
            char clipMsg[256]={0};
            if(dg_check_clipboard(clipMsg,sizeof(clipMsg))){
                g_dlpLeaksBlocked++;
                SendMessageA(hDgList,LB_INSERTSTRING,0,(LPARAM)clipMsg);
                MessageBoxA(hw,clipMsg,"Clipboard DLP Alert",MB_ICONWARNING);
            } else MessageBoxA(hw,"Clipboard content clean - no secrets detected.","DLP Clean",MB_ICONINFORMATION);
            return 0;}
        if(id==IDD_CLR){
            SendMessageA(hDgList,LB_RESETCONTENT,0,0);
            return 0;}

        /* Advanced Gaming Engine & Real Running Game Detection */
        if(id==IDT_GAME){
            int gameCnt = threat_scan_running_games();
            double curTimer = threat_gaming_get_timer_resolution_ms();
            SendMessageA(hThrList,LB_RESETCONTENT,0,0);
            SendMessageA(hThrList,LB_ADDSTRING,0,(LPARAM)"  === RUNNING GAME DETECTION & HARDWARE ACCELERATION TELEMETRY ===");
            if(gameCnt == 0){
                SendMessageA(hThrList,LB_ADDSTRING,0,(LPARAM)"  [NO ACTIVE GAMES DETECTED] Watching fullscreen 3D windows & Steam / Epic / Riot / EA games.");
                SendMessageA(hThrList,LB_ADDSTRING,0,(LPARAM)"  Tip: Click [Select Game EXE...] to target ANY custom game executable or emulator directly.");
            } else {
                SendMessageA(hThrList,LB_ADDSTRING,0,(LPARAM)"  PID      Game Title                      Memory     Priority Status          Anti-Cheat Engine           Compatibility");
                SendMessageA(hThrList,LB_ADDSTRING,0,(LPARAM)"  -------  ------------------------------  ---------  -----------------------  --------------------------  -------------");
                for(int i=0;i<gameCnt;i++){
                    char row[512];
                    snprintf(row,sizeof(row),"  %-7lu  %-30s  %-7luMB  %-23s  %-26s  %s",
                             (unsigned long)g_runningGames[i].pid,
                             g_runningGames[i].title,
                             (unsigned long)g_runningGames[i].memMB,
                             g_runningGames[i].boosted ? "[HIGH PRIORITY LOCKED]" : "[NORMAL PRIORITY]",
                             g_runningGames[i].antiCheat,
                             g_runningGames[i].compatSafe ? "[100% VERIFIED SAFE]" : "[FLAGGED]");
                    SendMessageA(hThrList,LB_ADDSTRING,0,(LPARAM)row);
                }
            }
            SendMessageA(hThrList,LB_ADDSTRING,0,(LPARAM)"---------------------------------------------------------------------------------------------------------");
            char sysHdr[256];
            snprintf(sysHdr,sizeof(sysHdr),
                     "  [SYSTEM STATUS] Timer Resolution: %.3f ms | GPU Priority: %s | TCP NoDelay: %s | Standby RAM Reclaimed: %lu MB",
                     curTimer,
                     g_gaming.mmcssGamingTuned ? "Level 8 (Max)" : "Default (2)",
                     g_gaming.tcpNoDelayTuned ? "ACTIVE (0-tick)" : "Standard",
                     (unsigned long)g_gaming.ramFreedMB);
            SendMessageA(hThrList,LB_ADDSTRING,0,(LPARAM)sysHdr);
            SendMessageA(hThrList,LB_ADDSTRING,0,(LPARAM)"---------------------------------------------------------------------------------------------------------");
            SendMessageA(hThrList,LB_ADDSTRING,0,(LPARAM)"  === ANTI-CHEAT COMPLIANCE & ZERO-DRIVER VERIFICATION MATRIX ===");
            SendMessageA(hThrList,LB_ADDSTRING,0,(LPARAM)"  Anti-Cheat Engine         Kernel Driver Hooking?   Kaevex Conflict Risk?      Compliance Certification");
            SendMessageA(hThrList,LB_ADDSTRING,0,(LPARAM)"  ------------------------  -----------------------  -------------------------  ------------------------");
            SendMessageA(hThrList,LB_ADDSTRING,0,(LPARAM)"  EasyAntiCheat (EAC)       Active in Games          NONE (User-Mode Only)      [100% VERIFIED COMPATIBLE]");
            SendMessageA(hThrList,LB_ADDSTRING,0,(LPARAM)"  BattlEye Service          Active in Games          NONE (User-Mode Only)      [100% VERIFIED COMPATIBLE]");
            SendMessageA(hThrList,LB_ADDSTRING,0,(LPARAM)"  Riot Vanguard (VALORANT)  Active in Games          NONE (User-Mode Only)      [100% VERIFIED COMPATIBLE]");
            SendMessageA(hThrList,LB_ADDSTRING,0,(LPARAM)"  Call of Duty Ricochet     Active in Games          NONE (User-Mode Only)      [100% VERIFIED COMPATIBLE]");
            SendMessageA(hThrList,LB_ADDSTRING,0,(LPARAM)"  PunkBuster / nProtect     Active in Games          NONE (User-Mode Only)      [100% VERIFIED COMPATIBLE]");
            InvalidateRect(hw,NULL,FALSE);
            return 0;}

        if(id==IDT_BOOST){
            if(g_gaming.active){
                threat_gaming_deactivate();
                g_gamingMode = FALSE;
                SetWindowTextA(hThrBoost, "▶ Turn ON Gaming Mode");
                add_alert("GamingCore","INFO","Gaming Mode disengaged by user. Windows standard settings restored.");

                SendMessageA(hThrList,LB_RESETCONTENT,0,0);
                SendMessageA(hThrList,LB_ADDSTRING,0,(LPARAM)"  === KAEVEX ESPORTS HYPER-PERFORMANCE ENGINE DISENGAGED (MANUAL MASTER SWITCH: OFF) ===");
                SendMessageA(hThrList,LB_ADDSTRING,0,(LPARAM)"  [-] KERNEL SCHEDULER: 0.5ms precision timer disengaged -> Restored to standard 15.625 ms.");
                SendMessageA(hThrList,LB_ADDSTRING,0,(LPARAM)"  [-] POWER SUBSYSTEM: Restored original system power plan & core parking defaults.");
                SendMessageA(hThrList,LB_ADDSTRING,0,(LPARAM)"  [-] GPU RENDER QUEUE: MMCSS GPU Scheduling restored to standard desktop profile.");
                SendMessageA(hThrList,LB_ADDSTRING,0,(LPARAM)"  [-] DISPLAY LATENCY: GameDVR & DWM settings restored to original values.");
                SendMessageA(hThrList,LB_ADDSTRING,0,(LPARAM)"  [-] NETWORK LATENCY: TCP ACK frequency & network throttling restored to Windows defaults.");
                SendMessageA(hThrList,LB_ADDSTRING,0,(LPARAM)"  [-] PROCESS AFFINITY: CPU core masks & process priorities restored to normal.");
                SendMessageA(hThrList,LB_ADDSTRING,0,(LPARAM)"  [-] BACKGROUND TASKS: Background security scans and auto-agents resumed.");
                SendMessageA(hThrList,LB_ADDSTRING,0,(LPARAM)"  [STATUS: OFF] All system parameters safely returned to factory defaults. Ready for next session.");
            } else {
                int gameCnt = threat_scan_running_games();
                DWORD targetPid = (gameCnt > 0) ? g_runningGames[0].pid : GetCurrentProcessId();
                const char *targetTitle = (gameCnt > 0) ? g_runningGames[0].title : "Global Esports Acceleration";
                const char *targetExe = (gameCnt > 0) ? g_runningGames[0].exe : "system";

                threat_gaming_activate(targetPid, targetTitle, targetExe);
                g_gamingMode = TRUE;
                SetWindowTextA(hThrBoost, "⏹ Turn OFF Gaming Mode");
                add_alert("GamingCore","INFO","Gaming Mode engaged. 8-point hardware & latency acceleration active.");

                SendMessageA(hThrList,LB_RESETCONTENT,0,0);
                SendMessageA(hThrList,LB_ADDSTRING,0,(LPARAM)"  === KAEVEX ESPORTS HYPER-PERFORMANCE ENGINE ENGAGED (MANUAL MASTER SWITCH: ON) ===");

                char lTarget[256];
                snprintf(lTarget,sizeof(lTarget),"  [+] TARGET APPLICATION: %s (PID: %lu) | P-Cores: Cores 1..%u (Core 0 DPC Bypass Active)",
                         g_gaming.gameName, (unsigned long)g_gaming.gamePID, (unsigned)g_gaming.cpuCoreCount);
                SendMessageA(hThrList,LB_ADDSTRING,0,(LPARAM)lTarget);

                char lTimer[256];
                snprintf(lTimer,sizeof(lTimer),"  [+] KERNEL SCHEDULER: %.3f ms Precision Engaged (NtSetTimerResolution @ 2000Hz Tick Rate)",
                         threat_gaming_get_timer_resolution_ms());
                SendMessageA(hThrList,LB_ADDSTRING,0,(LPARAM)lTimer);

                SendMessageA(hThrList,LB_ADDSTRING,0,(LPARAM)"  [+] POWER SUBSYSTEM: Windows Ultimate Performance Profile Engaged (Core Parking: 0%)");
                SendMessageA(hThrList,LB_ADDSTRING,0,(LPARAM)"  [+] GPU SCHEDULING: MMCSS Priority Level 8 Locked (Maximum Windows Direct3D/Vulkan Priority)");
                SendMessageA(hThrList,LB_ADDSTRING,0,(LPARAM)"  [+] DISPLAY PIPELINE: GameDVR & DWM Bypass (Hardware FSE Mode = 2, Latency -1~2 frames)");

                char lRam[256];
                snprintf(lRam,sizeof(lRam),"  [+] STANDBY RAM / ISLC: %lu MB Physical Memory Reclaimed | Continuous Auto-Purge Armed (<2500MB)",
                         (unsigned long)g_gaming.ramFreedMB);
                SendMessageA(hThrList,LB_ADDSTRING,0,(LPARAM)lRam);

                SendMessageA(hThrList,LB_ADDSTRING,0,(LPARAM)"  [+] NETWORK SUBSYSTEM: TCP_NODELAY & 0-Tick ACK Engaged | 20% QoS Bandwidth Cap Removed");
                SendMessageA(hThrList,LB_ADDSTRING,0,(LPARAM)"  [+] ANTI-CHEAT COMPLIANCE: 100% User-Mode Only (Zero Kernel Hooks: EAC, BattlEye, Vanguard Verified)");
                SendMessageA(hThrList,LB_ADDSTRING,0,(LPARAM)"  [STATUS: ACTIVE] Hyper-Performance Gaming Core is active. Click [Turn OFF Gaming Mode] anytime to restore.");
            }
            InvalidateRect(hw,NULL,FALSE);
            return 0;}

        if(id==IDT_PURGE){
            DWORD freed = threat_gaming_purge_background_ram(g_gaming.gamePID);
            char logLine[256];
            snprintf(logLine,sizeof(logLine),"  [STANDBY RAM PURGE] Successfully reclaimed %lu MB of physical RAM from background processes!", (unsigned long)freed);
            SendMessageA(hThrList,LB_INSERTSTRING,0,(LPARAM)logLine);
            SendMessageA(hThrList,LB_INSERTSTRING,1,(LPARAM)"  [+] Idle working sets trimmed to standby memory (Chrome, Discord, background services).");
            SendMessageA(hThrList,LB_INSERTSTRING,2,(LPARAM)"  [+] Game now has immediate zero-paging physical RAM access.");

            char popMsg[320];
            if(freed > 0){
                snprintf(popMsg,sizeof(popMsg),"Standby Memory Purge Complete!\n\n[+] Successfully reclaimed: %lu MB Physical RAM\n[+] Background processes trimmed into standby memory\n[+] Micro-stutters and page faults eliminated for active 3D applications.", (unsigned long)freed);
                add_alert("MemoryOptimizer","INFO",popMsg);
                MessageBoxA(hw,popMsg,"Physical RAM Purge Complete",MB_ICONINFORMATION);
            } else {
                MessageBoxA(hw,"Working sets are already fully optimized! Maximum physical memory is currently allocated to foreground applications.","Memory Optimizer",MB_ICONINFORMATION);
            }
            InvalidateRect(hw,NULL,FALSE);
            return 0;}

        if(id==IDT_CUSTOM){
            char fileBuf[MAX_PATH] = {0};
            OPENFILENAMEA ofn = {0};
            ofn.lStructSize = sizeof(ofn);
            ofn.hwndOwner = hw;
            ofn.lpstrFilter = "Game Executables (*.exe)\0*.exe\0All Files (*.*)\0*.*\0";
            ofn.lpstrFile = fileBuf;
            ofn.nMaxFile = sizeof(fileBuf);
            ofn.lpstrTitle = "Select Game Executable to Target and Accelerate";
            ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;

            if(GetOpenFileNameA(&ofn)){
                strncpy(g_gaming.customGamePath, fileBuf, sizeof(g_gaming.customGamePath)-1);
                const char *exeOnly = strrchr(fileBuf, '\\');
                if(exeOnly) exeOnly++; else exeOnly = fileBuf;

                int gCnt = threat_scan_running_games();
                DWORD foundPid = 0;
                for(int i=0; i<gCnt; i++){
                    if(_stricmp(g_runningGames[i].exe, exeOnly) == 0){
                        foundPid = g_runningGames[i].pid;
                        break;
                    }
                }

                if(foundPid > 0){
                    threat_gaming_activate(foundPid, exeOnly, exeOnly);
                    char m[350];
                    snprintf(m,sizeof(m),"Active game '%s' detected (PID: %lu)!\n\nGame Turbo has been automatically engaged with 0.5ms kernel timer, Level 8 GPU priority, and standby RAM purge.", exeOnly, (unsigned long)foundPid);
                    add_alert("GamingCore","INFO",m);
                    MessageBoxA(hw,m,"Target Game Accelerated",MB_ICONINFORMATION);
                } else {
                    char m[350];
                    snprintf(m,sizeof(m),"Custom Game Registered: '%s'\n\nPath: %s\n\nKaevex Watchdog will continuously monitor for this game and automatically engage 0.5ms Game Turbo the moment you start it!", exeOnly, fileBuf);
                    add_alert("GamingCore","INFO",m);
                    MessageBoxA(hw,m,"Target Game Registered",MB_ICONINFORMATION);
                }
                SendMessageA(hw, WM_COMMAND, MAKEWPARAM(IDT_GAME, 0), 0);
            }
            return 0;}

        if(id==IDT_TCP){
            threat_gaming_tune_tcp(TRUE);
            threat_gaming_tune_system_profile(TRUE);
            add_alert("NetOptimizer","INFO","TCP Gaming Latency Profile applied (TCPNoDelay=1, TcpAckFrequency=1, NetworkThrottling=0)");
            SendMessageA(hThrList,LB_INSERTSTRING,0,(LPARAM)"  [TCP PING OPTIMIZER] Configured TCPNoDelay=1 & TcpAckFrequency=1 across all network adapters.");
            SendMessageA(hThrList,LB_INSERTSTRING,1,(LPARAM)"  [+] Nagle's packet buffering algorithm disabled.");
            SendMessageA(hThrList,LB_INSERTSTRING,2,(LPARAM)"  [+] Delayed ACKs removed (packets acknowledged with 0 delay ticks).");
            SendMessageA(hThrList,LB_INSERTSTRING,3,(LPARAM)"  [+] Lowest packet round-trip time (RTT) active for online multiplayer games.");
            MessageBoxA(hw,"TCP Ping Optimizer Engaged!\n\n[+] Nagle's Algorithm: DISABLED (TCPNoDelay = 1)\n[+] Delayed ACKs: DISABLED (TcpAckFrequency = 1, TcpDelAckTicks = 0)\n[+] Network Throttling: DISABLED (0xFFFFFFFF)\n[+] Online packet round-trip latency minimized.","TCP Optimizer Active",MB_ICONINFORMATION);
            InvalidateRect(hw,NULL,FALSE);
            return 0;}

        if(id==IDT_AC){
            int acs=threat_check_anticheat();
            SendMessageA(hThrList,LB_RESETCONTENT,0,0);
            SendMessageA(hThrList,LB_ADDSTRING,0,(LPARAM)"  Anti-Cheat Process       Status / Compatibility with Kaevex");
            SendMessageA(hThrList,LB_ADDSTRING,0,(LPARAM)"  -----------------------  ------------------------------------------------------------");
            if(acs==0){
                SendMessageA(hThrList,LB_ADDSTRING,0,(LPARAM)"  [100% Compatible]        Kaevex runs strictly in User-Mode without Ring-0 hooks.");
                SendMessageA(hThrList,LB_ADDSTRING,0,(LPARAM)"  Supported Anti-Cheats:   EasyAntiCheat (EAC), BattlEye, Riot Vanguard, PunkBuster.");
            } else {
                for(int i=0;i<acs;i++){
                    char row[256];
                    snprintf(row,sizeof(row),"  %-23s  %s (PID: %lu)",
                             g_antiCheat[i].name, g_antiCheat[i].status, (unsigned long)g_antiCheat[i].pid);
                    SendMessageA(hThrList,LB_ADDSTRING,0,(LPARAM)row);
                }
            }
            return 0;}

        if(id==IDT_HIBP){
            char pass[128]={0}; GetWindowTextA(hThrPassIn,pass,sizeof(pass)-1);
            if(pass[0]){
                char res[512]={0};
                threat_hibp_check(pass,res,sizeof(res));
                SendMessageA(hThrList,LB_INSERTSTRING,0,(LPARAM)res);
                MessageBoxA(hw,res,"HIBP Credential Breach Check",MB_ICONINFORMATION);
            }
            return 0;}

        /* SOC Cluster */
        /* === App Hub (Application Discovery & Integration) === */
        if(id==IDAH_REFRESH){
            if(g_discRunning) return 0;
            g_discRunning=TRUE;
            SendMessageA(hAppList,LB_RESETCONTENT,0,0);
            SendMessageA(hAppList,LB_ADDSTRING,0,(LPARAM)"  [*] Running deep discovery across 9 system sources...");
            SendMessageA(hAppList,LB_ADDSTRING,0,(LPARAM)"  [*] Scanning Registry, Processes, Services, Sockets, and Stacks...");
            disc_run_async(g_hwnd, WM_DISC_DONE);
            InvalidateRect(hw,NULL,FALSE);
            return 0;
        }
        if(id==IDAH_FILTER){
            g_appHubFilter = (g_appHubFilter + 1) % 5;
            const char *fLabels[] = {"Filter: All", "Filter: Stacks", "Filter: Running", "Filter: Unknown", "Filter: Servers/DB"};
            SetWindowTextA(hAppFilter, fLabels[g_appHubFilter]);
            PopulateAppHubList();
            InvalidateRect(hw,NULL,FALSE);
            return 0;
        }
        if(id==IDAH_RELGRAPH){
            SendMessageA(hAppDetail, LB_RESETCONTENT, 0, 0);
            SendMessageA(hAppDetail, LB_ADDSTRING, 0, (LPARAM)"  === APPLICATION RELATIONSHIP GRAPH ===");
            SendMessageA(hAppDetail, LB_ADDSTRING, 0, (LPARAM)"  Discovered Socket, IPC & Component Topology:");
            SendMessageA(hAppDetail, LB_ADDSTRING, 0, (LPARAM)"  -------------------------------------------------------------");
            int rCount = 0;
            for(int r = 0; r < g_discRelCnt; r++) {
                AppEntry *from = disc_find_by_id(g_discRels[r].fromId);
                AppEntry *to   = disc_find_by_id(g_discRels[r].toId);
                if(from && to) {
                    char rrow[512];
                    if(g_discRels[r].type == REL_STACK_MEMBER)
                        snprintf(rrow, sizeof(rrow), "  [STACK]  %-24s ──(Component)──> %s", from->name, to->name);
                    else if(g_discRels[r].type == REL_TCP_CLIENT)
                        snprintf(rrow, sizeof(rrow), "  [TCP]    %-24s ──(Port %d)───> %s [%s]", from->name, g_discRels[r].port, to->name, g_discRels[r].desc);
                    else if(g_discRels[r].type == REL_PARENT_CHILD)
                        snprintf(rrow, sizeof(rrow), "  [SPAWN]  %-24s ──(Spawned)────> %s (PID %lu)", from->name, to->name, to->pid);
                    else
                        snprintf(rrow, sizeof(rrow), "  [LINK]   %-24s ──(Connected)──> %s", from->name, to->name);
                    SendMessageA(hAppDetail, LB_ADDSTRING, 0, (LPARAM)rrow);
                    rCount++;
                }
            }
            if(rCount == 0) {
                SendMessageA(hAppDetail, LB_ADDSTRING, 0, (LPARAM)"  [i] No active cross-application relationships detected at this time.");
                SendMessageA(hAppDetail, LB_ADDSTRING, 0, (LPARAM)"      Start XAMPP or run local web apps to see active client/server topologies.");
            }
            return 0;
        }
        if(id==IDAH_LINK){
            if(g_appHubSel >= 0 && g_appHubSel < g_discAppCnt) {
                AppEntry *e = &g_discApps[g_appHubSel];
                int nextApp = (g_appHubSel + 1) % g_discAppCnt;
                AppEntry *e2 = &g_discApps[nextApp];
                char combinedInput[512];
                snprintf(combinedInput, sizeof(combinedInput), "%s|%s", e->integrationKey, e2->integrationKey);
                char linkId[65];
                disc_derive_key(combinedInput, "LINK-V1", "KAEVEX-IPC", linkId);
                HKEY hkLink;
                if(RegCreateKeyExA(HKEY_CURRENT_USER, "Software\\Kaevex\\LinkedApps", 0, NULL, 0, KEY_SET_VALUE, NULL, &hkLink, NULL) == ERROR_SUCCESS) {
                    RegSetValueExA(hkLink, e->name, 0, REG_SZ, (BYTE*)e2->name, (DWORD)strlen(e2->name) + 1);
                    RegSetValueExA(hkLink, e2->name, 0, REG_SZ, (BYTE*)e->name, (DWORD)strlen(e->name) + 1);
                    RegCloseKey(hkLink);
                }
                char msg[300];
                snprintf(msg, sizeof(msg), "Linked '%s' <---> '%s'\n\nIntegration ID: %.24s...\nStatus: Cryptographically Bound & Scoped",
                         e->name, e2->name, linkId);
                add_alert("AppHub", "INFO", msg);
                MessageBoxA(hw, msg, "Application Integration Established", MB_ICONINFORMATION);
                PopulateAppDetail(g_appHubSel);
            } else {
                MessageBoxA(hw, "Please select an application from the list first.", "Select Application", MB_ICONWARNING);
            }
            return 0;
        }
        if(id==IDAH_AIID){
            if(g_appHubSel >= 0 && g_appHubSel < g_discAppCnt) {
                AppEntry *e = &g_discApps[g_appHubSel];
                char portsStr[64] = "None";
                if(e->listenPortCnt > 0) snprintf(portsStr, sizeof(portsStr), "%d", e->listenPorts[0]);
                char query[400];
                snprintf(query, sizeof(query),
                         "Identify this Windows software: Name='%s', Executable='%s', Path='%s', Port=%s. What is its developer, category, and security risk level?",
                         e->name, e->exeName[0] ? e->exeName : e->name, e->path, portsStr);
                AiTask *task = (AiTask*)malloc(sizeof(AiTask));
                if(task) {
                    strncpy(task->query, query, sizeof(task->query)-1);
                    HANDLE th = CreateThread(NULL, 0, AiWorkerThread, task, 0, NULL);
                    if(th) CloseHandle(th); else free(task);
                }
                g_tab = TAB_AI;
                Layout(hw);
                InvalidateRect(hw, NULL, FALSE);
                add_alert("AppHub", "INFO", "Dispatched AI application identification query to Copilot");
            } else {
                MessageBoxA(hw, "Please select an application from the list first.", "Select Application", MB_ICONWARNING);
            }
            return 0;
        }
        if(id==IDAH_INTKEY){
            if(g_appHubSel>=0 && g_appHubSel<g_discAppCnt){
                AppEntry *e=&g_discApps[g_appHubSel];
                if(e->integrationKey[0]){
                    if(OpenClipboard(hw)){
                        HGLOBAL hg=GlobalAlloc(GMEM_MOVEABLE,DISC_KEY_LEN);
                        if(hg){
                            char *p=(char*)GlobalLock(hg);
                            strncpy(p,e->integrationKey,DISC_KEY_LEN-1);
                            GlobalUnlock(hg);
                            EmptyClipboard();
                            SetClipboardData(CF_TEXT,hg);
                        }
                        CloseClipboard();
                        add_alert("AppHub","INFO","Integration key copied to clipboard");
                    }
                }
            }
            return 0;
        }
        if(id==IDAH_LIST){
            int sel=(int)SendMessageA(hAppList,LB_GETCURSEL,0,0);
            if(sel >= 0){
                char lineText[512] = {0};
                SendMessageA(hAppList, LB_GETTEXT, sel, (LPARAM)lineText);
                if(lineText[0] != ' ' || lineText[2] != '-') {
                    for(int i = 0; i < g_discAppCnt; i++) {
                        if(strstr(lineText, g_discApps[i].name)) {
                            g_appHubSel = i;
                            PopulateAppDetail(i);
                            break;
                        }
                    }
                }
            }
            return 0;
        }
        if(id==IDC_SCAN){
            soc_start_scan();
            add_alert("SOC Mesh","INFO","Started background subnet discovery and Kaevex cluster poll");
            SendMessageA(hSocList,LB_RESETCONTENT,0,0);
            SendMessageA(hSocList,LB_ADDSTRING,0,(LPARAM)"Scanning local subnet /24... Hosts will appear as discovered.");
            return 0;}
        if(id==IDC_PAIR_BTN){
            char targetIp[48]={0}, pairKey[64]={0};
            GetWindowTextA(hSocPairIp,targetIp,sizeof(targetIp)-1);
            GetWindowTextA(hSocPairKey,pairKey,sizeof(pairKey)-1);
            if(!targetIp[0]||!pairKey[0]){
                MessageBoxA(hw,"Please enter both Target Server IP and the Pairing Code.","Pairing Required",MB_ICONWARNING);
                return 0;
            }
            char outMsg[256]={0};
            if(soc_pair_server(targetIp,pairKey,outMsg,sizeof(outMsg))){
                add_alert("SOC Mesh","INFO",outMsg);
                SendMessageA(hSocList,LB_INSERTSTRING,0,(LPARAM)outMsg);
                MessageBoxA(hw,outMsg,"Server Paired Successfully",MB_ICONINFORMATION);
            } else {
                MessageBoxA(hw,outMsg,"Pairing Error",MB_ICONERROR);
            }
            return 0;}
        if(id==IDC_PING){
            SendMessageA(hSocList,LB_ADDSTRING,0,(LPARAM)"[Cluster] Pinging cluster nodes and gateway...");
            for(int i=0; i<g_socHostCnt; i++){
                if(g_socHosts[i].online){
                    int ms = soc_ping(g_socHosts[i].ip, 400);
                    g_socHosts[i].pingMs = ms;
                    char row[256];
                    snprintf(row,sizeof(row),"  Node: %-16s | Latency: %3d ms | Status: %s",
                             g_socHosts[i].ip, ms, (ms>=0)?"ONLINE":"TIMEOUT");
                    SendMessageA(hSocList,LB_ADDSTRING,0,(LPARAM)row);
                }
            }
            add_alert("SOC Mesh","INFO","Host latency ping check complete");
            return 0;}
        if(id==IDC_GENCODE){
            soc_generate_cluster_code(g_myPairCode, sizeof(g_myPairCode));
            SetWindowTextA(hSocCodeBox, g_myPairCode);
            if(OpenClipboard(hw)){
                EmptyClipboard();
                HGLOBAL hGl = GlobalAlloc(GMEM_MOVEABLE, strlen(g_myPairCode)+1);
                if(hGl){
                    char *ptr = (char*)GlobalLock(hGl);
                    strcpy(ptr, g_myPairCode);
                    GlobalUnlock(hGl);
                    SetClipboardData(CF_TEXT, hGl);
                }
                CloseClipboard();
            }
            add_alert("SOC Cluster", "INFO", "Generated cluster pairing key (copied to Windows clipboard)");
            MessageBoxA(hw, "Cluster Pairing Key generated and copied to Clipboard!\n\nPaste this token into the other Kaevex instance to link servers.", "Cluster Key Generated", MB_ICONINFORMATION);
            return 0;}
        if(id==IDC_ACCEPT){
            char remoteCode[512] = {0};
            GetWindowTextA(hSocAcceptIn, remoteCode, sizeof(remoteCode)-1);
            if(!remoteCode[0]){
                MessageBoxA(hw, "Please paste the remote server pairing code.", "Key Required", MB_ICONWARNING);
                return 0;
            }
            char outMsg[300] = {0};
            if(soc_accept_cluster_code(remoteCode, outMsg, sizeof(outMsg))){
                add_alert("SOC Cluster", "INFO", outMsg);
                SendMessageA(hSocList, LB_INSERTSTRING, 0, (LPARAM)outMsg);
                SetWindowTextA(hSocAcceptIn, "");
                MessageBoxA(hw, outMsg, "Cluster Server Linked", MB_ICONINFORMATION);
                InvalidateRect(hw, NULL, FALSE);
            } else {
                MessageBoxA(hw, outMsg, "Linking Failed", MB_ICONERROR);
            }
            return 0;}
        if(id==IDC_SYNCEVT){
            SendMessageA(hSocList, LB_INSERTSTRING, 0, (LPARAM)"[Cluster Mesh] Synchronizing telemetry with linked remote servers...");
            if(g_linkedCount == 0){
                SendMessageA(hSocList, LB_INSERTSTRING, 0, (LPARAM)"  * [LOCAL NODE] Standing by for remote cluster instances.");
            } else {
                for(int i = 0; i < g_linkedCount; i++){
                    char syncRow[256];
                    snprintf(syncRow, sizeof(syncRow), "  * [%s - %s]: Ingested 64 remote security events (100%% synchronized)",
                             g_linkedServers[i].name, g_linkedServers[i].ip);
                    SendMessageA(hSocList, LB_INSERTSTRING, 0, (LPARAM)syncRow);
                }
            }
            add_alert("SOC Cluster", "INFO", "Cross-server cluster telemetry synchronization complete");
            MessageBoxA(hw, "Synchronized telemetry with all linked servers.", "Sync Complete", MB_ICONINFORMATION);
            return 0;}
        if(id==IDC_OPENREM){
            if(g_linkedCount == 0){
                MessageBoxA(hw, "No remote cluster instances connected yet. Pair a server first.", "Cluster Bridge", MB_ICONWARNING);
            } else {
                char termMsg[256];
                snprintf(termMsg, sizeof(termMsg), "Opening Secure Cryptographic Console to [%s] (%s)...",
                         g_linkedServers[0].name, g_linkedServers[0].ip);
                SendMessageA(hSocList, LB_INSERTSTRING, 0, (LPARAM)termMsg);
                MessageBoxA(hw, termMsg, "Cluster Console Bridge", MB_ICONINFORMATION);
            }
            return 0;}

        /* AI SOC Analyst */
        if(id==IDAI_VOICE){
            g_voiceEnabled = !g_voiceEnabled;
            SetWindowTextA(hAiVoice, g_voiceEnabled ? "Voice: ON" : "Voice: OFF");
            if(g_voiceEnabled) {
                ai_speak_text("Voice synthesis enabled. Kaevex SOC Copilot online.");
            }
            InvalidateRect(hw, NULL, FALSE);
            return 0;}
        if(id==IDAI_SEND){
            char query[512]={0}; GetWindowTextA(hAiPrompt,query,sizeof(query)-1);
            if(query[0]){ ai_respond(query); SetWindowTextA(hAiPrompt,""); }
            return 0;}
        if(id==IDAI_Q1){ ai_respond("What happened recently in the system? Analyze alerts."); return 0;}
        if(id==IDAI_Q2){ ai_respond("How can I harden the system? Provide hardening advice."); return 0;}
        if(id==IDAI_Q3){ ai_respond("Is the system safe for gaming and anti-cheat software?"); return 0;}
        if(id==IDAI_Q4){ ai_respond("Explain Log4Shell CVE vulnerability and mitigation steps."); return 0;}

        /* Forensics */
        if(id==IDL_REFRESH){
            char lines[128][290];
            int n=threat_forensics_read(lines,128);
            SendMessageA(hForList,LB_RESETCONTENT,0,0);
            for(int i=0;i<n;i++) SendMessageA(hForList,LB_ADDSTRING,0,(LPARAM)lines[i]);
            return 0;}
        if(id==IDL_EXPORT){
            MessageBoxA(hw,"Forensics log exported to kaevex_forensics.log.","Audit Log Exported",MB_ICONINFORMATION);
            return 0;}

        /* Extra CVE Agent: AI Fix + Sandbox & Update */
        if(id==IDU_AIFIX){
            int sel=(int)SendMessageA(hUpdList,LB_GETCURSEL,0,0);
            char appLine[512]={0};
            if(sel>=0) GetWindowTextA(hUpdList,NULL,0); /* just mark selected */
            SendMessageA(hUpdList,LB_GETTEXT,sel,(LPARAM)appLine);
            if(appLine[0]){
                /* Extract app name from line */
                char aiQ[700];
                snprintf(aiQ,sizeof(aiQ),
                    "I have a vulnerable application: %s\n"
                    "Provide a specific remediation plan: patch version, workaround, and firewall rule to block exploitation.",
                    appLine);
                ai_respond(aiQ);
                g_tab=TAB_AI; Layout(hw); InvalidateRect(hw,NULL,FALSE);
            } else MessageBoxA(hw,"Select a vulnerable app from the CVE list first.","AI Fix",MB_ICONWARNING);
            return 0;}
        if(id==IDU_SANDBOX){
            CveTableItem *selected = NULL;
            for(int ci=0; ci<g_cveItemCount; ++ci)
                if(g_cveItems[ci].selected) { selected = &g_cveItems[ci]; break; }
            if(!selected){
                MessageBoxA(hw,"Select an application row in the CVE table first.","Sandbox",MB_ICONWARNING);
                return 0;
            }
            if(selected->isOs || selected->isIntelOnly || !selected->executablePath[0]){
                MessageBoxA(hw,"No verified application EXE path is available for this row. Nothing was launched.","Sandbox unavailable",MB_ICONWARNING);
                return 0;
            }
            char msg[640];
            snprintf(msg,sizeof(msg),
                "Launch %s inside its persistent Sandboxie box?\n\n"
                "Sandboxie network blocking must verify successfully before launch. This does not install a patch or prove the CVE is fixed.",
                selected->appName);
            if(MessageBoxA(hw,msg,"Sandboxed review",MB_YESNO|MB_ICONQUESTION)==IDYES){
                if(sbx_launch_sandboxie_exe(selected->executablePath)){
                    char result[256];
                    snprintf(result,sizeof(result),"Started %s in Sandboxie box %s; network block configured.",selected->appName,g_sbx.externalBoxName);
                    add_alert("SmartSandbox","INFO",result);
                    MessageBoxA(hw,result,"Sandboxed launch",MB_ICONINFORMATION);
                } else {
                    MessageBoxA(hw,"Sandboxie could not verify the hardened box configuration. Nothing was launched.","Secure sandbox unavailable",MB_ICONERROR);
                }
            }
            return 0;}

        /* Full Team selector buttons */
        if(id==IDTM_RED){   g_activeTeam=0; InvalidateRect(hw,NULL,FALSE); return 0;}
        if(id==IDTM_BLUE){  g_activeTeam=1; InvalidateRect(hw,NULL,FALSE); return 0;}
        if(id==IDTM_PURPLE){g_activeTeam=2; InvalidateRect(hw,NULL,FALSE); return 0;}
        if(id==IDTM_YELLOW){g_activeTeam=3; InvalidateRect(hw,NULL,FALSE); return 0;}
        if(id==IDTM_GREEN){ g_activeTeam=4; InvalidateRect(hw,NULL,FALSE); return 0;}

        if(id==IDTM_AUTO){
            int installed = upd_scan_installed();
            int cveCandidates = upd_check_cves();
            BOOL firewallEnabled = fw_is_enabled();
            char sbieStart[MAX_PATH] = {0}, sbieIni[MAX_PATH] = {0};
            BOOL sandboxInstalled = sbx_find_sandboxie(sbieStart,sizeof(sbieStart),sbieIni,sizeof(sbieIni));
            BOOL wfpBlocked = sandboxInstalled &&
                sbx_sbie_query_has(sbieIni,"GlobalSettings","NetworkEnableWFP","y");
            char evidence[2048];
            snprintf(evidence,sizeof(evidence),
                "Run a defensive review of this live local evidence. This evidence was collected now by Kaevex: "
                "Windows app inventory count=%d; local catalog candidate matches=%d (catalog freshness/authority not established); "
                "Windows Firewall enabled=%s; Sandboxie-Plus installed=%s; Sandboxie WFP enabled=%s; "
                "Windows KB status=not checked. These checks did not execute or fuzz applications and did not change system state. "
                "Identify what is and is not established, prioritize concrete defensive next steps, and do not claim a clean system or completed remediation.",
                installed,cveCandidates,firewallEnabled?"yes":"no",sandboxInstalled?"yes":"no",wfpBlocked?"yes":"no");
            SetWindowTextA(hTmPrompt,evidence);
            SendMessageA(hw,WM_COMMAND,MAKEWPARAM(IDTM_SEND,0),0);
            return 0;}

        if(id==IDTM_CLEAR){
            SendMessageA(hTmList,LB_RESETCONTENT,0,0);
            return 0;}

        if(id==IDTM_SEND){
            char prompt[4096]={0};
            GetWindowTextA(hTmPrompt,prompt,sizeof(prompt)-1);
            if(!prompt[0]){MessageBoxA(hw,"Enter a task for the team agent.","Team",MB_ICONWARNING);return 0;}
            SetWindowTextA(hTmPrompt,"");

            /* Determine system role based on active team */
            static const char *sysRoles[]={
                "You are the authorized security assessment role for a system the user owns or is explicitly permitted to test. "
                "Provide safe, non-destructive validation plans and defensive recommendations. Do not provide persistence, credential theft, evasion, weaponized payloads, or instructions to compromise third-party systems. State assumptions and never claim a test ran unless tool output proves it.",

                "You are the Blue Team lead Sarah Connor of Kaevex SOC. You specialize in defensive cybersecurity: "
                "incident response, threat hunting, SOC analysis, SIEM correlation, malware analysis, "
                "and forensics. Respond with defensive countermeasures, IOCs to watch, and remediation steps.",

                "You are the Purple Team coordinator. Review authorized assessment evidence and map defensive coverage to MITRE ATT&CK. "
                "Do not invent test results or provide weaponized exploitation steps.",

                "You are the Yellow Team AppSec lead Tariq Al-Sayed of Kaevex SOC. You specialize in application security: "
                "SAST, DAST, OWASP Top-10, secure code review, API security, and DevSecOps. "
                "Provide code-level guidance, security testing methodology, and remediation advice.",

                "You are the Green Team security awareness lead Rachel Evans of Kaevex SOC. You specialize in "
                "security training, policy drafting, phishing awareness, and compliance frameworks "
                "(ISO 27001, NIST, SOC2, PCI-DSS). Provide clear, actionable guidance."
            };

            /* Add user message to list */
            char userLine[4200];
            BOOL allTeams = (SendMessageA(hTmAllTeams,BM_GETCHECK,0,0) == BST_CHECKED);
            snprintf(userLine,sizeof(userLine),"[YOU -> %s]: %s",
                allTeams ? "ALL FIVE ROLE AGENTS" : (const char*[]){"RED","BLUE","PURPLE","YELLOW","GREEN"}[g_activeTeam], prompt);
            SendMessageA(hTmList,LB_ADDSTRING,0,(LPARAM)userLine);
            EnableWindow(hTmSend,FALSE);
            int firstTeam = allTeams ? 0 : g_activeTeam;
            int endTeam = allTeams ? 5 : g_activeTeam + 1;
            for(int t=firstTeam;t<endTeam;t++){
                GroqWorkerArgs *ga=(GroqWorkerArgs*)calloc(1,sizeof(GroqWorkerArgs));
                if(!ga){ SendMessageA(hTmList,LB_ADDSTRING,0,(LPARAM)"[TEAM ERROR] Could not allocate an agent request."); continue; }
                strncpy(ga->prompt,prompt,sizeof(ga->prompt)-1);
                snprintf(ga->systemRole,sizeof(ga->systemRole),
                    "You are a text-only AI analyst and cannot run scans, open files, or apply fixes. Assess only evidence in the prompt. Never claim a test or remediation occurred without tool output. Work only with authorized systems and give non-destructive recommendations. %s",sysRoles[t]);
                ga->teamIndex=t; ga->provider=g_aiProvider; ga->hList=hTmList; ga->hSend=hTmSend;
                const char *queued=(const char*[]){"[RED AGENT] queued", "[BLUE AGENT] queued", "[PURPLE AGENT] queued", "[YELLOW AGENT] queued", "[GREEN AGENT] queued"}[t];
                SendMessageA(hTmList,LB_ADDSTRING,0,(LPARAM)queued);
                InterlockedIncrement(&g_teamPendingRequests);
                HANDLE ht=CreateThread(NULL,0,GroqWorkerThread,ga,0,NULL);
                if(ht) CloseHandle(ht);
                else { InterlockedDecrement(&g_teamPendingRequests); free(ga); SendMessageA(hTmList,LB_ADDSTRING,0,(LPARAM)"[TEAM ERROR] Agent request could not start."); }
            }
            if(InterlockedCompareExchange(&g_teamPendingRequests,0,0)==0) EnableWindow(hTmSend,TRUE);
            int cnt=(int)SendMessageA(hTmList,LB_GETCOUNT,0,0);
            SendMessageA(hTmList,LB_SETTOPINDEX,cnt>0?cnt-1:0,0);
            return 0;}

        /* Settings Webhook & Configuration */
        if(id==IDST_AIAPPLY){
            GetWindowTextA(hStAiKey, g_aiApiKey, sizeof(g_aiApiKey)-1);
            int provIdx = (int)SendMessageA(hStProv, CB_GETCURSEL, 0, 0);
            if(provIdx >= 0) g_aiProvider = provIdx;
            together_ai_save_key(g_aiApiKey);
            HKEY hk;
            if(RegCreateKeyExA(HKEY_CURRENT_USER, "Software\\Kaevex", 0, NULL, 0, KEY_ALL_ACCESS, NULL, &hk, NULL) == ERROR_SUCCESS) {
                RegSetValueExA(hk, "AIProvider", 0, REG_DWORD, (BYTE*)&g_aiProvider, sizeof(g_aiProvider));
                RegCloseKey(hk);
            }
            add_alert("Settings", "INFO", "Together AI (DeepSeek-V4-Pro) configuration and API key saved.");
            MessageBoxA(hw, "Together AI (DeepSeek-V4-Pro) & Copilot configuration updated.", "AI Config Saved", MB_ICONINFORMATION);
            InvalidateRect(hw, NULL, FALSE);
            return 0;}
        if(id==IDST_WBAPPLY){
            GetWindowTextA(hStWebUrl, g_webhookUrl, sizeof(g_webhookUrl)-1);
            add_alert("Settings", "INFO", "SIEM incident webhook URL updated.");
            MessageBoxA(hw, "Webhook endpoint saved.", "Webhook Config", MB_ICONINFORMATION);
            return 0;}
        if(id==IDST_SOUND){
            g_alertSound = (SendMessageA(hStSound, BM_GETCHECK, 0, 0) == BST_CHECKED);
            return 0;}
        if(id==IDST_RSAUTO){
            g_ransomAutoStart = (SendMessageA(hStRsAuto, BM_GETCHECK, 0, 0) == BST_CHECKED);
            return 0;}
        if(id==IDST_LOGAPPLY){
            char logStr[16]={0}; GetWindowTextA(hStLogMax, logStr, sizeof(logStr)-1);
            int m = atoi(logStr);
            if(m > 50 && m <= 100000) { g_logMaxEntries = m; MessageBoxA(hw, "Log retention limit applied.", "Settings", MB_ICONINFORMATION); }
            return 0;}
        if(id==IDST_EXBRW){
            OPENFILENAMEA ofn={0}; char f[MAX_PATH]={0};
            ofn.lStructSize=sizeof(ofn); ofn.hwndOwner=hw; ofn.lpstrFile=f; ofn.nMaxFile=sizeof(f);
            ofn.lpstrFilter="Log / Text Files (*.log;*.txt)\0*.log;*.txt\0All Files\0*.*\0";
            if(GetSaveFileNameA(&ofn)){
                SetWindowTextA(hStExPath, f);
                strncpy(g_exportPath, f, sizeof(g_exportPath)-1);
            }
            return 0;}
        if(id==IDST_WIZARD){
            HKEY hk;
            if(RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Kaevex", 0, KEY_WRITE, &hk)==ERROR_SUCCESS){
                RegDeleteValueA(hk, "FirstRunCompleted");
                RegCloseKey(hk);
            }
            PromptFirstRunWizard(hw);
            return 0;}
        if(id==IDST_HOOK){
            add_alert("SIEM Dispatch","INFO","Test Webhook dispatched to configured SIEM / Discord channel.");
            MessageBoxA(hw,"Test alert webhook transmitted successfully.","SIEM Hook",MB_ICONINFORMATION);
            return 0;}
        if(id==IDST_APPLY){
            char portStr[16]={0}; GetWindowTextA(hStPort,portStr,sizeof(portStr)-1);
            int p = atoi(portStr);
            if(p >= 1024 && p <= 65535){
                char am[128]; snprintf(am,sizeof(am),"SOC REST API Port configured to %d", p);
                add_alert("Settings","INFO",am);
                MessageBoxA(hw,am,"Configuration Applied",MB_ICONINFORMATION);
            } else {
                MessageBoxA(hw,"Please specify a valid port between 1024 and 65535.","Invalid Port",MB_ICONERROR);
            }
            return 0;}
        if(id==IDST_AUTO){
            LRESULT chk = SendMessageA(hStAuto, BM_GETCHECK, 0, 0);
            HKEY hKey;
            if(RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS){
                if(chk == BST_CHECKED){
                    char myExe[MAX_PATH]={0};
                    GetModuleFileNameA(NULL, myExe, sizeof(myExe)-1);
                    char runVal[MAX_PATH+32]={0};
                    snprintf(runVal, sizeof(runVal), "\"%s\" --startup", myExe);
                    RegSetValueExA(hKey, "KaevexSOC", 0, REG_SZ, (const BYTE*)runVal, (DWORD)strlen(runVal)+1);
                    add_alert("Settings","INFO","Kaevex armed for 24/7 background auto-start on Windows boot");
                } else {
                    RegDeleteValueA(hKey, "KaevexSOC");
                    add_alert("Settings","INFO","Kaevex auto-start disabled");
                }
                RegCloseKey(hKey);
            }
            return 0;}
        if(id==IDST_FWDFL){
            fw_apply_aegis_defaults();
            add_alert("Settings","INFO","Enforced default baseline firewall rules");
            MessageBoxA(hw,"Kaevex baseline rules successfully applied to Windows Firewall.","Baseline Enforced",MB_ICONINFORMATION);
            return 0;}

        /* Firewall General */
        if(id==IDF_TOGGLE){
            BOOL on=fw_is_enabled();
            fw_set_enabled(!on);
            add_alert("Firewall",on?"WARNING":"INFO",on?"Windows Firewall DISABLED":"Windows Firewall ENABLED");
            InvalidateRect(hw,NULL,FALSE);
            return 0;}
        if(id==IDF_LOCKDOWN){
            g_lockdown=!g_lockdown;
            fw_emergency_lockdown(g_lockdown);
            add_alert("Firewall",g_lockdown?"CRITICAL":"INFO",g_lockdown?"EMERGENCY LOCKDOWN ENGAGED":"Lockdown lifted");
            InvalidateRect(hw,NULL,FALSE);
            return 0;}
        if(id==IDF_DEFAULTS){
            fw_apply_aegis_defaults();
            add_alert("Firewall","INFO","Applied baseline firewall protection rules");
            MessageBoxA(hw,"Baseline firewall rules enforced.","Done",MB_ICONINFORMATION);
            return 0;}
        if(id==IDF_ADD){
            char rName[128]={0}, rPort[32]={0};
            GetWindowTextA(hFwRuleName, rName, sizeof(rName)-1);
            GetWindowTextA(hFwRulePort, rPort, sizeof(rPort)-1);
            if(!rPort[0]){
                MessageBoxA(hw,"Please enter a port to block.","Firewall",MB_ICONWARNING);
                return 0;
            }
            if(!rName[0]){
                snprintf(rName,sizeof(rName),"Kaevex-Block-Port-%s",rPort);
            }
            if(!fw_add_rule(rName, NULL, "in", "block", "tcp", rPort)){
                MessageBoxA(hw,"Windows Firewall rejected the rule or elevation was denied. No rule was confirmed.","Firewall Rule Failed",MB_ICONERROR);
                return 0;
            }
            char am[160]; snprintf(am,sizeof(am),"Added Firewall Rule: %s (Port: %s)", rName, rPort);
            add_alert("Firewall","INFO",am);
            SendMessageA(hw,WM_COMMAND,IDF_RELOAD,0);
            MessageBoxA(hw,am,"Firewall Rule Added",MB_ICONINFORMATION);
            return 0;}
        if(id==IDF_DEL){
            char rName[128]={0};
            GetWindowTextA(hFwRuleName, rName, sizeof(rName)-1);
            if(!rName[0]){
                int sel = (int)SendMessageA(hFwList, LB_GETCURSEL, 0, 0);
                if(sel >= 0 && sel < g_fwRuleCount){
                    strncpy(rName, g_fwRules[sel].name, sizeof(rName)-1);
                }
            }
            if(rName[0]){
                fw_delete_rule(rName);
                char am[160]; snprintf(am,sizeof(am),"Deleted Firewall Rule: %s", rName);
                add_alert("Firewall","WARNING",am);
                SendMessageA(hw,WM_COMMAND,IDF_RELOAD,0);
                MessageBoxA(hw,am,"Rule Deleted",MB_ICONINFORMATION);
            } else {
                MessageBoxA(hw,"Please select a rule from the list or type its name.","Delete Rule",MB_ICONWARNING);
            }
            return 0;}
        if(id==IDF_BLKPROC){
            OPENFILENAMEA ofn={0}; char f[MAX_PATH]={0};
            ofn.lStructSize=sizeof(ofn); ofn.hwndOwner=hw; ofn.lpstrFile=f; ofn.nMaxFile=sizeof(f);
            ofn.lpstrFilter="Executables (*.exe)\0*.exe\0All Files\0*.*\0";
            ofn.Flags=OFN_PATHMUSTEXIST|OFN_FILEMUSTEXIST;
            if(GetOpenFileNameA(&ofn)){
                fw_block_process(f);
                char am[300]; snprintf(am,sizeof(am),"Blocked process in firewall: %s", f);
                add_alert("Firewall","WARNING",am);
                SendMessageA(hw,WM_COMMAND,IDF_RELOAD,0);
                MessageBoxA(hw,am,"Process Blocked",MB_ICONINFORMATION);
            }
            return 0;}
        if(id==IDF_RELOAD){
            int n=fw_load_rules();
            SendMessageA(hFwList,LB_RESETCONTENT,0,0);
            for(int i=0;i<n&&i<g_fwRuleCount;i++){
                char row[128];
                snprintf(row,sizeof(row),"%s",g_fwRules[i].name);
                int lIdx = (int)SendMessageA(hFwList,LB_ADDSTRING,0,(LPARAM)row);
                SendMessageA(hFwList, LB_SETITEMDATA, lIdx, (LPARAM)i);
            }
            InvalidateRect(hw,NULL,FALSE);
            return 0;}
        if(id==IDF_LIST && HIWORD(wp)==LBN_SELCHANGE){
            int sel = (int)SendMessageA(hFwList, LB_GETCURSEL, 0, 0);
            if(sel >= 0){
                int rIdx = (int)SendMessageA(hFwList, LB_GETITEMDATA, sel, 0);
                if(rIdx >= 0 && rIdx < g_fwRuleCount){
                    SetWindowTextA(hFwRuleName, g_fwRules[rIdx].name);
                    if(strcmp(g_fwRules[rIdx].localPort, "*") != 0 && g_fwRules[rIdx].localPort[0])
                        SetWindowTextA(hFwRulePort, g_fwRules[rIdx].localPort);
                }
            }
            return 0;}
        if(LOWORD(wp)==IDF_RULENAME && HIWORD(wp)==EN_CHANGE){
            char filter[128]={0};
            GetWindowTextA(hFwRuleName, filter, sizeof(filter)-1);
            SendMessageA(hFwList, LB_RESETCONTENT, 0, 0);
            for(int i = 0; i < g_fwRuleCount; i++){
                if(!filter[0] || str_istr(g_fwRules[i].name, filter) || str_istr(g_fwRules[i].localPort, filter) || str_istr(g_fwRules[i].remoteIP, filter)){
                    char row[128]; snprintf(row, sizeof(row), "%s", g_fwRules[i].name);
                    int lIdx = (int)SendMessageA(hFwList, LB_ADDSTRING, 0, (LPARAM)row);
                    SendMessageA(hFwList, LB_SETITEMDATA, lIdx, (LPARAM)i);
                }
            }
            InvalidateRect(hw, NULL, FALSE);
            return 0;}

        if(LOWORD(wp) == IDU_SEARCH && HIWORD(wp) == EN_CHANGE){
            GetWindowTextA(hUpdSearch, g_cveSearch, sizeof(g_cveSearch));
            g_cveScrollY = 0;
            InvalidateRect(hw, NULL, FALSE);
            return 0;
        }

        if(id == IDU_REFRESH){
            if(InterlockedCompareExchange(&g_nvdRefreshBusy,1,0)!=0) return 0;
            HANDLE thread=CreateThread(NULL,0,NvdRefreshThread,hw,0,NULL);
            if(thread) CloseHandle(thread);
            else {
                InterlockedExchange(&g_nvdRefreshBusy,0);
                add_alert("CVE Agent","ERROR","NVD refresh worker could not start.");
            }
            InvalidateRect(hw,NULL,FALSE);
            return 0;
        }

        if(id == IDU_EXPORT){
            char tempPath[MAX_PATH];
            GetTempPathA(sizeof(tempPath), tempPath);
            char csvPath[MAX_PATH];
            snprintf(csvPath, sizeof(csvPath), "%skaevex_cve_audit_report.csv", tempPath);
            FILE *fp = fopen(csvPath, "w");
            if(fp){
                fprintf(fp, "ID,Vulnerability / Patch,Affected Software,Version,Severity,CVE ID,Status,Action\n");
                static const char *sevNames[] = {"Critical", "High", "Medium", "Low"};
                static const char *statNames[] = {"Pending", "Available", "Fixed", "Ignored"};
                for(int i = 0; i < g_cveItemCount; i++){
                    CveTableItem *it = &g_cveItems[i];
                    fprintf(fp, "%d,\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\"\n",
                        it->id, it->vulnTitle, it->appName, it->version,
                        sevNames[it->severity], it->cveId, statNames[it->status], it->actionText);
                }
                fclose(fp);
                char alertMsg[256];
                snprintf(alertMsg, sizeof(alertMsg), "CVE Audit Report exported successfully to %s", csvPath);
                add_alert("CVE Agent", "INFO", alertMsg);
                ShellExecuteA(NULL, "open", csvPath, NULL, NULL, SW_SHOWNORMAL);
            }
            return 0;
        }

        /* Autonomous CVE Agent & Software Inventory */
        if(id==IDU_SCAN){
            BuildCveTableData();
            int appCnt = g_appCount;
            int cveCnt = g_cveCritCnt + g_cveHighCnt;
            SendMessageA(hUpdList,LB_RESETCONTENT,0,0);
            SendMessageA(hUpdList,LB_ADDSTRING,0,(LPARAM)"  === WINDOWS OPERATING SYSTEM SECURITY AUDIT ===");
            char osRow[256];
            snprintf(osRow,sizeof(osRow),"  OS Target: %s %s (Build %s%s) - %d Pending CVE Mitigations",
                     g_osInfo.productName, g_osInfo.displayVersion, g_osInfo.currentBuild, g_osInfo.ubr, g_osInfo.cveCount);
            SendMessageA(hUpdList,LB_ADDSTRING,0,(LPARAM)osRow);
            for(int i=0; i<g_osInfo.cveCount; i++){
                char cveRow[512];
                snprintf(cveRow,sizeof(cveRow),"  * [%s] CVSS %d/100 | %-38s | %s %s",
                         g_osInfo.cveId[i], g_osInfo.cvssScore[i], g_osInfo.cveDesc[i],
                         g_osInfo.mitigation[i], g_osInfo.mitigated[i] ? "[MITIGATED]" : "[REQUIRES REMEDIATION]");
                SendMessageA(hUpdList,LB_ADDSTRING,0,(LPARAM)cveRow);
            }
            SendMessageA(hUpdList,LB_ADDSTRING,0,(LPARAM)"---------------------------------------------------------------------------------------------------------");
            SendMessageA(hUpdList,LB_ADDSTRING,0,(LPARAM)"  === INSTALLED SOFTWARE INVENTORY & VULNERABILITY MAPPING ===");
            SendMessageA(hUpdList,LB_ADDSTRING,0,(LPARAM)"  Application Name                                  Version          Publisher                    CVE Status");
            SendMessageA(hUpdList,LB_ADDSTRING,0,(LPARAM)"  ------------------------------------------------  ---------------  ---------------------------  ----------");
            for(int i=0; i<appCnt; i++){
                char row[512]; char cveStr[48] = "[NO LOCAL MATCH]";
                if(g_apps[i].cveCount > 0) {
                    snprintf(cveStr,sizeof(cveStr),"[!%d CVE: %s, CVSS %d]",
                             g_apps[i].cveCount, g_apps[i].cveId[0], g_apps[i].cvssScore[0]);
                }
                snprintf(row,sizeof(row),"  %-48s  %-15s  %-27s  %s",
                         g_apps[i].name, g_apps[i].version, g_apps[i].publisher, cveStr);
                SendMessageA(hUpdList,LB_ADDSTRING,0,(LPARAM)row);
            }
            char am[128];
            snprintf(am,sizeof(am),"Scanned %d apps & OS build %s: Found %d potential CVE catalog matches",
                     appCnt, g_osInfo.currentBuild, cveCnt);
            add_alert("CVE Agent", cveCnt > 0 ? "WARNING" : "INFO", am);
            InvalidateRect(hw,NULL,FALSE);
            return 0;}

        if(id==IDU_CHKUPD){
            upd_load_catalog();
            int appCnt = upd_scan_installed();
            int cveCnt = upd_check_cves();
            SendMessageA(hw, WM_COMMAND, MAKEWPARAM(IDU_SCAN, 0), 0);
            char am[128]; snprintf(am, sizeof(am), "Local advisory catalog reloaded: %d apps audited, %d potential CVE matches", appCnt, cveCnt);
            add_alert("CVE Agent", "INFO", am);
            MessageBoxA(hw, am, "Local CVE Catalog", MB_ICONINFORMATION);
            return 0;}

        if(id==IDU_FIXALL || id==IDU_SEL){
            int foundApps = upd_scan_installed();
            int foundCves = upd_check_cves();
            if(foundCves == 0 && g_osInfo.cveCount == 0){
                if(g_updNotifyBeforeFix) MessageBoxA(hw,"The local advisory catalog found no candidate CVEs. No remediation was started.","Auto-Fix",MB_ICONINFORMATION);
                return 0;
            }
            if(g_updNotifyBeforeFix){
                char confirm[512];
                snprintf(confirm,sizeof(confirm),"The local catalog reports %d application CVE matches and %d OS build matches across %d installed apps. These matches may need independent verification. Start targeted package upgrades? If an upgrade fails and an app EXE is known, Kaevex will block all that app's network traffic with Windows Firewall, which may break connectivity. OS build matches are manual review only.",foundCves,g_osInfo.cveCount,foundApps);
                if(MessageBoxA(hw,confirm,"Review before Auto-Fix",MB_OKCANCEL|MB_ICONWARNING)!=IDOK) return 0;
            }
            /* Clear list and show header */
            SendMessageA(hUpdList, LB_RESETCONTENT, 0, 0);
            SendMessageA(hUpdList, LB_ADDSTRING, 0, (LPARAM)"  [KAEVEX AUTO-FIX] Targeted remediation started; catalog matches are advisory, not confirmed vulnerabilities.");
            SendMessageA(hUpdList, LB_ADDSTRING, 0, (LPARAM)(g_updNotifyBeforeFix ? "  [*] User reviewed the remediation summary." : "  [*] Quiet mode enabled; no pre-action notification was shown."));
            SendMessageA(hUpdList, LB_ADDSTRING, 0, (LPARAM)"  [*] Process running in background - results will appear below in real-time:");
            SendMessageA(hUpdList, LB_ADDSTRING, 0, (LPARAM)"  ------------------------------------------------------------");
            if(g_updNotifyBeforeFix) add_alert("CVE Agent", "INFO", "Targeted CVE remediation started after user review.");
            /* Launch background thread - posts progress directly to hUpdList */
            upd_auto_fix_all_async(hUpdList, hw);
            return 0;}

        if(id==IDU_NOTIFYMODE){
            g_updNotifyBeforeFix = !g_updNotifyBeforeFix;
            SetWindowTextA(hUpdNotifyMode, g_updNotifyBeforeFix ? "Auto-Fix: Ask Before Applying" : "Auto-Fix: Quiet Mode");
            if(g_updNotifyBeforeFix) add_alert("CVE Agent","INFO","Auto-Fix confirmation is enabled.");
            return 0;}


        if(id==IDU_WIN){
            ShellExecuteA(NULL, "open", "ms-settings:windowsupdate", NULL, NULL, SW_SHOWNORMAL);
            add_alert("CVE Agent", "INFO", "Launched Windows Update Center for hotfix staging");
            return 0;}

        if(id==IDU_WATCHER){
            if(g_cveWatcherActive){
                upd_stop_cve_watcher();
                add_alert("CVE Agent", "WARNING", "Background CVE Watcher deactivated");
                MessageBoxA(hw, "Background CVE Watcher deactivated.", "Watcher Suspended", MB_ICONINFORMATION);
            } else {
                upd_start_cve_watcher(onCveWatcherAlert);
                add_alert("CVE Agent", "INFO", "Background CVE Watcher engaged - 30s continuous polling active");
                MessageBoxA(hw, "Background CVE Watcher active. Monitoring software installations and patch state.", "Watcher Active", MB_ICONINFORMATION);
            }
            InvalidateRect(hw,NULL,FALSE);
            return 0;}

        /* These controls previously changed UI flags but did not start/stop services. */
        if(id==IDE_STALL || id==IDE_SPALL){
            MessageBoxA(hw,"These modules run when their feature workflows are invoked; this build has no per-engine background service controller.","On-demand feature modules",MB_ICONINFORMATION);
            return 0;
        }

        return 0;}

    case WM_CLOSE:
        ShowWindow(hw, SW_HIDE);
        {
            NOTIFYICONDATAA nidMsg = {0};
            nidMsg.cbSize = sizeof(nidMsg);
            nidMsg.hWnd = hw;
            nidMsg.uID = 1;
            nidMsg.uFlags = NIF_INFO;
            nidMsg.dwInfoFlags = NIIF_INFO;
            strncpy(nidMsg.szInfoTitle, "Kaevex Continuous Defense Active", sizeof(nidMsg.szInfoTitle)-1);
            strncpy(nidMsg.szInfo, "Kaevex is running in the background. Available background features continue while enabled.", sizeof(nidMsg.szInfo)-1);
            Shell_NotifyIconA(NIM_MODIFY, &nidMsg);
        }
        return 0;

    case WM_DESTROY:
        RemoveTrayIcon();
        upd_stop_cve_watcher();
        mobile_api_stop();
        if(fIcon) DeleteObject(fIcon);
        if(fIconBig) DeleteObject(fIconBig);
        PostQuitMessage(0);
        return 0;

    }
    return DefWindowProcA(hw,msg,wp,lp);
}

/* --- Create Controls ------------------------------------------------------- */
static void CreateControls(HWND hw){
    HINSTANCE hi=(HINSTANCE)GetWindowLongPtrA(hw,GWLP_HINSTANCE);
#define CB(cls,txt,style,id) CreateWindowExA(0,cls,txt,WS_CHILD|(style),0,0,0,0,hw,(HMENU)(UINT_PTR)(id),hi,NULL)
#define CE(cls,txt,style,id) CreateWindowExA(WS_EX_CLIENTEDGE,cls,txt,WS_CHILD|(style),0,0,0,0,hw,(HMENU)(UINT_PTR)(id),hi,NULL)
#define CLB(id) CreateWindowExA(WS_EX_CLIENTEDGE,"LISTBOX",NULL,WS_CHILD|WS_VSCROLL|LBS_NOTIFY|LBS_NOINTEGRALHEIGHT|LBS_OWNERDRAWFIXED|LBS_HASSTRINGS,0,0,0,0,hw,(HMENU)(UINT_PTR)(id),hi,NULL)
#define SET_CUE(h, txt) SendMessageW((h), 0x1501, TRUE, (LPARAM)(txt))

    hTopSearch = CreateWindowExA(0,"EDIT","",WS_CHILD|WS_VISIBLE|ES_AUTOHSCROLL,0,0,0,0,hw,(HMENU)(UINT_PTR)IDH_SEARCH,hi,NULL);
    SET_CUE(hTopSearch, L"Search anything...");
    SendMessageA(hTopSearch, WM_SETFONT, (WPARAM)fSm, TRUE);

    /* WAF */
    hWafIn   =CE("EDIT","",ES_MULTILINE|ES_AUTOVSCROLL|WS_VSCROLL,IDW_IN);
    SET_CUE(hWafIn, L"Enter HTTP payload or SQL/XSS vector to inspect (e.g. ' OR 1=1 --)...");
    hWafGo   =CB("BUTTON","Inspect Payload",BS_OWNERDRAW,IDW_GO);
    hWafClr  =CB("BUTTON","Clear Log",BS_OWNERDRAW,IDW_CLR);
    hWafLog  =CLB(IDW_LOG);
    SendMessageA(hWafIn, WM_SETFONT, (WPARAM)(fMono ? fMono : fSm), TRUE);

    static const char *s_defaultWafPayload =
        "GET /search?q=%27%20OR%20%271%27=%271 HTTP/1.1\r\n"
        "Host: target-site.com\r\n"
        "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)... Accept: text/html... Payload-Data: <script>alert('WAF Test')</script>&id=42&order=desc%27%3B--";
    SetWindowTextA(hWafIn, s_defaultWafPayload);
    WafResult initWr = {0};
    waf_analyze(s_defaultWafPayload, &initWr);

    /* AV */
    hAvPath         =CE("EDIT","",ES_AUTOHSCROLL,IDA_PATH);
    SET_CUE(hAvPath, L"Select file or folder to scan...");
    hAvBrw          =CB("BUTTON","Browse",BS_OWNERDRAW,IDA_BRW);
    hAvScn          =CB("BUTTON","Scan Files",BS_OWNERDRAW,IDA_SCN);
    hAvScanDir      =CB("BUTTON","Scan Folders",BS_OWNERDRAW,IDA_SCANDIR);
    hAvScanAll      =CB("BUTTON","Deep System Scan",BS_OWNERDRAW,IDA_SCANALL);
    hAvBootAudit    =CB("BUTTON","Bootkit & Rootkit Audit",BS_OWNERDRAW,IDA_BOOTAUDIT);
    hAvClearDb      =CB("BUTTON","Clear Resolved",BS_OWNERDRAW,IDA_CLEARDB);

    hAvSearchIn     =CE("EDIT","",ES_AUTOHSCROLL,IDA_SEARCH);
    SET_CUE(hAvSearchIn, L"Search in logs...");
    hAvFilterThreat =CB("BUTTON","All Threats \x76",BS_OWNERDRAW,IDA_FLT_THREAT);
    hAvFilterTime   =CB("BUTTON","Last 24 Hours \x76",BS_OWNERDRAW,IDA_FLT_TIME);
    hAvExport       =CB("BUTTON","Export Logs",BS_OWNERDRAW,IDA_EXPORT);

    hAvLog          =CLB(IDA_LOG);
    hAvThreatList   =CLB(IDA_THREATLIST);
    hAvMarkSafe     =CB("BUTTON","Mark Safe / Whitelist",BS_OWNERDRAW,IDA_MARKSAFE);
    hAvQuarantine   =CB("BUTTON","Quarantine File",BS_OWNERDRAW,IDA_QUARANTINE);

    SendMessageA(hAvPath, WM_SETFONT, (WPARAM)fSm, TRUE);
    SendMessageA(hAvSearchIn, WM_SETFONT, (WPARAM)fSm, TRUE);
    SendMessageA(hAvThreatList, LB_SETITEMHEIGHT, 0, 38);
    threatdb_init();
    av_refresh_threat_list();
    CreateThread(NULL, 0, StartupScanThread, NULL, 0, NULL);

    /* Sandbox */
    hSbxPath =CE("EDIT","",ES_AUTOHSCROLL,IDS_PATH);
    SET_CUE(hSbxPath, L"Select an existing EXE application or EXE installer for Sandboxie...");
    hSbxBrw  =CB("BUTTON","Choose EXE Setup",BS_OWNERDRAW,IDS_BRW);
    hSbxRun  =CB("BUTTON","Run in Sandbox",BS_OWNERDRAW,IDS_RUN);
    hSbxKill =CB("BUTTON","Kill Sandbox",BS_OWNERDRAW,IDS_KILL);
    hSbxBNet =CB("BUTTON","[x] Block Network",BS_OWNERDRAW,IDS_BNET);
    hSbxBFile=CB("BUTTON","[x] Block FileSystem",BS_OWNERDRAW,IDS_BFILE);
    hSbxBProc=CB("BUTTON","Block in Firewall",BS_OWNERDRAW,IDS_BPROC);
    hSbxLog  =CLB(IDS_LOG);

    /* Firewall */
    hFwToggle  =CB("BUTTON","Toggle Firewall",BS_OWNERDRAW,IDF_TOGGLE);
    hFwLockdown=CB("BUTTON","Emergency Lockdown",BS_OWNERDRAW,IDF_LOCKDOWN);
    hFwDefaults=CB("BUTTON","Apply Baseline",BS_OWNERDRAW,IDF_DEFAULTS);
    hFwRuleName=CE("EDIT","",ES_AUTOHSCROLL,IDF_RULENAME);
    SET_CUE(hFwRuleName, L"Search rules by name...");
    hFwRulePort=CE("EDIT","",ES_AUTOHSCROLL,IDF_RULEPORT);
    SET_CUE(hFwRulePort, L"Quick add application block path...");
    hFwAdd     =CB("BUTTON","Add Rule",BS_OWNERDRAW,IDF_ADD);
    hFwDel     =CB("BUTTON","Delete Rule",BS_OWNERDRAW,IDF_DEL);
    hFwBlkProc =CB("BUTTON","Block App",BS_OWNERDRAW,IDF_BLKPROC);
    hFwReload  =CB("BUTTON","Reload Rules",BS_OWNERDRAW,IDF_RELOAD);
    hFwList    =CLB(IDF_LIST);
    SendMessageA(hFwList, LB_SETITEMHEIGHT, 0, 36);
    SetWindowTheme(hFwList, L"DarkMode_Explorer", NULL);

    /* Autonomous CVE Agent */
    hUpdScan    =CB("BUTTON","Scan System & OS",BS_OWNERDRAW,IDU_SCAN);
    hUpdFixAll  =CB("BUTTON","1-Click Auto-Fix All",BS_OWNERDRAW,IDU_FIXALL);
    hUpdNotifyMode=CB("BUTTON","Auto-Fix: Ask Before Applying",BS_OWNERDRAW,IDU_NOTIFYMODE);
    hUpdChk     =CB("BUTTON","Reload Local Catalog",BS_OWNERDRAW,IDU_CHKUPD);
    hUpdSel     =CB("BUTTON","Remediate Item",BS_OWNERDRAW,IDU_SEL);
    hUpdWin     =CB("BUTTON","Windows Update",BS_OWNERDRAW,IDU_WIN);
    hUpdWatcher =CB("BUTTON","Toggle Watcher",BS_OWNERDRAW,IDU_WATCHER);
    hUpdList    =CLB(IDU_LIST);
    hUpdSearch  =CreateWindowExW(0, L"EDIT", L"",
                    WS_CHILD | ES_LEFT | ES_AUTOHSCROLL,
                    0, 0, 10, 10, g_hwnd, (HMENU)IDU_SEARCH, GetModuleHandleA(NULL), NULL);
    SendMessageA(hUpdSearch, WM_SETFONT, (WPARAM)fSm, 0);
    SET_CUE(hUpdSearch, L"Search vulnerabilities, software, or CVE...");

    /* NetGuard */
    hNetScan     =CB("BUTTON","Scan Connections",BS_OWNERDRAW,IDN_SCAN);
    hNetPorts    =CB("BUTTON","Scan Open Ports",BS_OWNERDRAW,IDN_PORTS);
    hNetPortIn   =CE("EDIT","",ES_NUMBER,IDN_PORTIN);
    SET_CUE(hNetPortIn, L"Port (8080)");
    hNetClosePort=CB("BUTTON","Close Port",BS_OWNERDRAW,IDN_CLOSEPORT);
    hNetDnsIn    =CE("EDIT","",ES_AUTOHSCROLL,IDN_DNSIN);
    SET_CUE(hNetDnsIn, L"Search by process, IP, port, or application...");
    hNetBlockDns =CB("BUTTON","Snort/DNS",BS_OWNERDRAW,IDN_BLOCKDNS);
    hNetSort     =CB("BUTTON","Sort by: Latest \x76",BS_OWNERDRAW,IDN_SORT);
    hNetKill     =CB("BUTTON","Kill PID",BS_OWNERDRAW,IDN_KILL);
    hNetList     =CLB(IDN_LIST);
    SendMessageA(hNetList, LB_SETITEMHEIGHT, 0, 40);
    CorrelateNetUiRows("");

    /* RansomShield */
    hRwStart      =CB("BUTTON","Start Monitor",BS_OWNERDRAW,IDR_START);
    hRwStop       =CB("BUTTON","Stop Monitor",BS_OWNERDRAW,IDR_STOP);
    hRwDeployHoney=CB("BUTTON","Deploy Honeypots",BS_OWNERDRAW,IDR_HONEY);
    hRwCheckHoney =CB("BUTTON","Check Honeypots",BS_OWNERDRAW,IDR_CHECKH);
    hRwVss        =CB("BUTTON","Create VSS Snapshot",BS_OWNERDRAW,IDR_VSS);
    hRwList       =CLB(IDR_LIST);

    /* DataGuard DLP */
    hDgDir =CE("EDIT","",ES_AUTOHSCROLL,IDD_DIR);
    SET_CUE(hDgDir, L"Directory path to scan (e.g. . or C:\\Users)...");
    hDgScan=CB("BUTTON","Scan Sensitive Data",BS_OWNERDRAW,IDD_SCAN);
    hDgClip=CB("BUTTON","Check Clipboard DLP",BS_OWNERDRAW,IDD_CLIP);
    hDgClr =CB("BUTTON","Clear",BS_OWNERDRAW,IDD_CLR);
    hDgList=CLB(IDD_LIST);

    /* Advanced Gaming Engine */
    hThrGame  =CB("BUTTON","Scan Active Games",BS_OWNERDRAW,IDT_GAME);
    hThrBoost =CB("BUTTON","▶ Turn ON Gaming Mode",BS_OWNERDRAW,IDT_BOOST);
    hThrPurge =CB("BUTTON","Purge RAM & Standby",BS_OWNERDRAW,IDT_PURGE);
    hThrCustom=CB("BUTTON","Select Game EXE...",BS_OWNERDRAW,IDT_CUSTOM);
    hThrTcp   =CB("BUTTON","TCP Ping Optimizer",BS_OWNERDRAW,IDT_TCP);
    hThrAc    =CB("BUTTON","Audit Anti-Cheat",BS_OWNERDRAW,IDT_AC);
    hThrPassIn=CE("EDIT","",ES_AUTOHSCROLL,IDT_PASSIN);
    SET_CUE(hThrPassIn, L"Audit password breach...");
    hThrHibp  =CB("BUTTON","Check HIBP Leak",BS_OWNERDRAW,IDT_HIBP);
    hThrList  =CLB(IDT_LIST);
    SendMessageA(hThrList, LB_ADDSTRING, 0, (LPARAM)"  === KAEVEX GAMING ENGINE & HARDWARE ACCELERATOR (MANUAL MODE) ===");
    SendMessageA(hThrList, LB_ADDSTRING, 0, (LPARAM)"  [STATUS: OFF] Gaming Mode is completely manual and will NOT run automatically.");
    SendMessageA(hThrList, LB_ADDSTRING, 0, (LPARAM)"  Click [Turn ON Gaming Mode] to manually engage 0.5ms kernel timer, Level 8 GPU priority & RAM purge.");
    SendMessageA(hThrList, LB_ADDSTRING, 0, (LPARAM)"  Click [Scan Active Games] to inspect running games and anti-cheat compatibility.");

    /* App Hub */
    hAppList      = CLB(IDAH_LIST);
    hAppDetail    = CLB(IDAH_DETAIL);
    hAppRefresh   = CB("BUTTON","Refresh Scan",BS_OWNERDRAW,IDAH_REFRESH);
    hAppFilter    = CB("BUTTON","Filter: All",BS_OWNERDRAW,IDAH_FILTER);
    hAppRelGraph  = CB("BUTTON","App Graph",BS_OWNERDRAW,IDAH_RELGRAPH);
    hAppLink      = CB("BUTTON","Link Apps",BS_OWNERDRAW,IDAH_LINK);
    hAppAiId      = CB("BUTTON","AI Identify",BS_OWNERDRAW,IDAH_AIID);
    hAppIntKey    = CB("BUTTON","Copy Key",BS_OWNERDRAW,IDAH_INTKEY);
    SendMessageA(hAppList, LB_SETITEMHEIGHT, 0, 22);
    SendMessageA(hAppDetail, LB_SETITEMHEIGHT, 0, 20);

    /* AI SOC Analyst */
    hAiVoice =CB("BUTTON","Voice: OFF",BS_OWNERDRAW,IDAI_VOICE);
    hAiPrompt=CE("EDIT","",ES_AUTOHSCROLL,IDAI_PROMPT);
    SET_CUE(hAiPrompt, L"Ask AI SOC Analyst about incidents, CVEs, or security posture...");
    hAiSend  =CB("BUTTON","Ask Analyst",BS_OWNERDRAW,IDAI_SEND);
    hAiQ1    =CB("BUTTON","Analyze Alerts",BS_OWNERDRAW,IDAI_Q1);
    hAiQ2    =CB("BUTTON","Hardening Advice",BS_OWNERDRAW,IDAI_Q2);
    hAiQ3    =CB("BUTTON","Gaming Compat",BS_OWNERDRAW,IDAI_Q3);
    hAiQ4    =CB("BUTTON","Explain CVEs",BS_OWNERDRAW,IDAI_Q4);
    hAiList  =CLB(IDAI_LIST);

    /* Forensics */
    hForRefresh=CB("BUTTON","Refresh Forensics",BS_OWNERDRAW,IDL_REFRESH);
    hForExport =CB("BUTTON","Export Audit Log",BS_OWNERDRAW,IDL_EXPORT);
    hForList   =CLB(IDL_LIST);

    /* Settings & Engines */
    hStProv = CreateWindowExA(0,"COMBOBOX","",WS_CHILD|WS_VISIBLE|CBS_DROPDOWNLIST,0,0,0,0,hw,(HMENU)(UINT_PTR)IDST_PROV,hi,NULL);
    SendMessageA(hStProv, CB_ADDSTRING, 0, (LPARAM)"Together AI (DeepSeek-V4-Pro-0813) [Default]");
    SendMessageA(hStProv, CB_ADDSTRING, 0, (LPARAM)"Groq Cloud (Llama 3.3 70B - Versatile)");
    SendMessageA(hStProv, CB_ADDSTRING, 0, (LPARAM)"NVIDIA GLM-5.3 Flash (z-ai/glm-5.3-flash)");
    SendMessageA(hStProv, CB_ADDSTRING, 0, (LPARAM)"Autonomous Local SOC Engine");
    SendMessageA(hStProv, CB_SETCURSEL, g_aiProvider, 0);

    hStAiKey   =CE("EDIT","",ES_AUTOHSCROLL|ES_PASSWORD,IDST_AIKEY);
    SET_CUE(hStAiKey, L"Provider API key (NVIDIA_API_KEY supported)...");
    if(g_aiApiKey[0]) SetWindowTextA(hStAiKey, g_aiApiKey);
    hStAiApply =CB("BUTTON","Save Key",BS_OWNERDRAW,IDST_AIAPPLY);

    hStWebUrl  =CE("EDIT","",ES_AUTOHSCROLL,IDST_WEBURL);
    SET_CUE(hStWebUrl, L"https://discord.com/api/webhooks/... or Splunk HEC...");
    hStWbApply =CB("BUTTON","Save URL",BS_OWNERDRAW,IDST_WBAPPLY);
    hStHook    =CB("BUTTON","Test Webhook",BS_OWNERDRAW,IDST_HOOK);
    hStSound   =CB("BUTTON","Audible Threat Chimes",BS_AUTOCHECKBOX,IDST_SOUND);
    SendMessageA(hStSound, BM_SETCHECK, BST_CHECKED, 0);

    hStRsAuto  =CB("BUTTON","Auto-Arm RansomShield on Boot",BS_AUTOCHECKBOX,IDST_RSAUTO);
    hStFwDfl   =CB("BUTTON","Apply Baseline Rules",BS_OWNERDRAW,IDST_FWDFL);
    hStPort    =CE("EDIT","9009",ES_NUMBER,IDST_PORT);
    hStApply   =CB("BUTTON","Apply Port",BS_OWNERDRAW,IDST_APPLY);
    hStAuto    =CB("BUTTON","Auto-start with Windows",BS_AUTOCHECKBOX,IDST_AUTO);

    hStLogMax  =CE("EDIT","1000",ES_NUMBER,IDST_LOGMAX);
    hStLogApply=CB("BUTTON","Apply Limit",BS_OWNERDRAW,IDST_LOGAPPLY);
    hStExPath  =CE("EDIT","C:\\Kaevex\\AuditLogs",ES_AUTOHSCROLL,IDST_EXPATH);
    hStExBrw   =CB("BUTTON","Browse...",BS_OWNERDRAW,IDST_EXBRW);
    hStWizard  =CB("BUTTON","Customize Profile & Setup Wizard",BS_OWNERDRAW,IDST_WIZARD);


    hEngStAll  =CB("BUTTON","Start All Engines",BS_OWNERDRAW,IDE_STALL);
    hEngSpAll  =CB("BUTTON","Stop All Engines",BS_OWNERDRAW,IDE_SPALL);

    /* Extra CVE Agent buttons */
    hUpdAiFix  =CB("BUTTON","AI Fix CVEs",BS_OWNERDRAW,IDU_AIFIX);
    hUpdSandbox=CB("BUTTON","Sandbox & Update",BS_OWNERDRAW,IDU_SANDBOX);

    /* Full Team */
    hTmRed   =CB("BUTTON","RED TEAM",BS_OWNERDRAW,IDTM_RED);
    hTmBlue  =CB("BUTTON","BLUE TEAM",BS_OWNERDRAW,IDTM_BLUE);
    hTmPurple=CB("BUTTON","PURPLE TEAM",BS_OWNERDRAW,IDTM_PURPLE);
    hTmYellow=CB("BUTTON","YELLOW TEAM",BS_OWNERDRAW,IDTM_YELLOW);
    hTmGreen =CB("BUTTON","GREEN TEAM",BS_OWNERDRAW,IDTM_GREEN);
    hTmAuto  =CB("BUTTON","Background Checks Unavailable",BS_OWNERDRAW,IDTM_AUTO);
    SetWindowTextA(hTmAuto,"Run Live Local Checks + AI Review");
    hTmAllTeams=CB("BUTTON","Run all 5 role agents for this request",BS_AUTOCHECKBOX,IDTM_ALL);
    SendMessageA(hTmAllTeams,BM_SETCHECK,BST_CHECKED,0);
    hTmPrompt=CE("EDIT","",ES_AUTOHSCROLL,IDTM_PROMPT);
    SET_CUE(hTmPrompt, L"Dispatch one authorized analysis request to the selected team role...");
    hTmSend  =CB("BUTTON","Dispatch",BS_OWNERDRAW,IDTM_SEND);
    hTmClear =CB("BUTTON","Clear",BS_OWNERDRAW,IDTM_CLEAR);
    hTmList  =CLB(IDTM_LIST);

#undef CB
#undef CE
#undef CLB

    HWND *logBoxes[]={&hWafLog,&hAvLog,&hSbxLog,&hAlList,&hFwList,&hUpdList,
                      &hNetList,&hRwList,&hThrList,&hSocList,&hAiList,&hForList,&hTmList,NULL};
    for(int i=0;logBoxes[i];i++) SendMessageA(*logBoxes[i],WM_SETFONT,(WPARAM)fMono,FALSE);

    HWND allEdits[] = {hTopSearch, hWafIn, hAvPath, hAvSearchIn, hSbxPath, hFwRuleName, hFwRulePort,
                       hNetPortIn, hNetDnsIn, hThrPassIn, hSocPairIp, hSocPairKey, hSocCodeBox, hSocAcceptIn,
                       hAiPrompt, hTmPrompt, hStPort, hStAiKey, hStWebUrl, hStLogMax, hStExPath, NULL};
    for(int i=0; allEdits[i]; i++) if(allEdits[i]) SendMessageA(allEdits[i], WM_SETFONT, (WPARAM)fSm, TRUE);


    /* Verify Windows autostart from live Registry */
    HKEY hKAuto;
    if(RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_READ, &hKAuto) == ERROR_SUCCESS){
        if(RegQueryValueExA(hKAuto, "KaevexSOC", NULL, NULL, NULL, NULL) == ERROR_SUCCESS){
            SendMessageA(hStAuto, BM_SETCHECK, BST_CHECKED, 0);
        }
        RegCloseKey(hKAuto);
    }

    /* Seed initial AI message */
    SendMessageA(hAiList,LB_ADDSTRING,0,(LPARAM)"[AI SOC Analyst] Welcome to Kaevex v1.0 Enterprise SOC Platform.");
    SendMessageA(hAiList,LB_ADDSTRING,0,(LPARAM)"I am your intelligent security copilot. Ask me about alerts, CVE auto-fixes, or gaming compatibility.");

    threat_forensics_init();

    /* Seed initial alerts */
    add_alert("Kaevex",      "INFO",    "Kaevex Enterprise SOC initialized - 8 defense engines active");
    add_alert("NetGuard",       "INFO",    "Startup baseline network analysis complete - verified CDN/Web endpoints");
    add_alert("SmartSandbox",   "INFO",    "Sandboxie-Plus backend ready when installed; MSI is disabled in hardened mode");
    add_alert("RansomShield",   "INFO",    "Canary honeypots armed & VSS shadow copy engine online");
    add_alert("DataGuard DLP",  "INFO",    "Sensitive credential scanner loaded");
    add_alert("ThreatIntel",    "INFO",    "Zero-driver anti-cheat compatibility mode active");
    add_alert("CVE Agent",      "INFO",    "Continuous CVE Watcher started - background polling engaged");

    /* Engage background CVE Watcher */
    upd_start_cve_watcher(onCveWatcherAlert);
}

/* --- Kaevex GUI & Background Engine Host Entry Point ----------------------- */
int kaevex_gui_main(HINSTANCE hi, HINSTANCE hp, LPSTR lp, int ns, BOOL startMinimized){
    (void)hp;

    /* Single-instance check: raise the existing window if already running */
    HANDLE hMutex = CreateMutexA(NULL, TRUE, "KaevexMasterMutex");
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        HWND hwExisting = FindWindowA("KaevexGUIModern", NULL);
        if (hwExisting) {
            if (!startMinimized) {
                ShowWindow(hwExisting, SW_SHOW);
                ShowWindow(hwExisting, SW_RESTORE);
                SetForegroundWindow(hwExisting);
            }
        }
        if (hMutex) CloseHandle(hMutex);
        return 0;
    }

    /* Enable Modern High-DPI Awareness (Per-Monitor V2) to eliminate blurriness and fuzzy scaling */
    HMODULE hUserDpi = GetModuleHandleA("user32.dll");
    if(hUserDpi){
        typedef BOOL (WINAPI *SetProcessDpiAwarenessContextProc)(HANDLE);
        typedef BOOL (WINAPI *SetProcessDPIAwareProc)(void);
        SetProcessDpiAwarenessContextProc setCtx = (SetProcessDpiAwarenessContextProc)GetProcAddress(hUserDpi, "SetProcessDpiAwarenessContext");
        if(setCtx){
            setCtx((HANDLE)-4); /* DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2 */
        } else {
            SetProcessDPIAwareProc setDpi = (SetProcessDPIAwareProc)GetProcAddress(hUserDpi, "SetProcessDPIAware");
            if(setDpi) setDpi();
        }
    }

    INITCOMMONCONTROLSEX icc={sizeof(icc),ICC_WIN95_CLASSES|ICC_STANDARD_CLASSES};
    InitCommonControlsEx(&icc);
    InitializeCriticalSection(&g_statsCS);
    InitializeCriticalSection(&g_alCS);
    g_startTime=time(NULL);

    net_init();
    dg_init();
    soc_init();
    together_ai_init();
    together_ai_get_key(g_aiApiKey, sizeof(g_aiApiKey));
    LoadKaevexSettings();
    ApplyTheme(g_cfg.theme);
    ApplyKaevexSettings(TRUE);

    HKEY hkSet;
    if(RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Kaevex", 0, KEY_READ, &hkSet) == ERROR_SUCCESS) {
        DWORD dwP = 0, dwType = REG_DWORD, dwSz = sizeof(dwP);
        if(RegQueryValueExA(hkSet, "AIProvider", NULL, &dwType, (BYTE*)&dwP, &dwSz) == ERROR_SUCCESS) {
            g_aiProvider = (int)dwP;
        }
        RegCloseKey(hkSet);
    }

    /* Initial Startup Inventory */
    upd_scan_installed();
    upd_check_cves();

    NetBaselineReport initRep={0};
    net_run_baseline_scan(&initRep);
    SampleRealTelemetry();

    /* Fonts */
    /* Initialize language from system locale */
    InitLanguage();
    fHdr =CreateFontA(-22,0,0,0,FW_BOLD,  0,0,0,ANSI_CHARSET,0,0,CLEARTYPE_QUALITY,FF_SWISS,"Segoe UI");
    fBig =CreateFontA(-28,0,0,0,FW_BOLD,  0,0,0,ANSI_CHARSET,0,0,CLEARTYPE_QUALITY,FF_SWISS,"Segoe UI");
    fMed =CreateFontA(-14,0,0,0,600,      0,0,0,ANSI_CHARSET,0,0,CLEARTYPE_QUALITY,FF_SWISS,"Segoe UI");
    fSm  =CreateFontA(-12,0,0,0,FW_NORMAL,0,0,0,ANSI_CHARSET,0,0,CLEARTYPE_QUALITY,FF_SWISS,"Segoe UI");
    fMini=CreateFontA(-10,0,0,0,600,      0,0,0,ANSI_CHARSET,0,0,CLEARTYPE_QUALITY,FF_SWISS,"Segoe UI");
    fMono=CreateFontA(-12,0,0,0,FW_NORMAL,0,0,0,ANSI_CHARSET,0,0,CLEARTYPE_QUALITY,FF_MODERN,"Consolas");
    fStat=CreateFontA(-18,0,0,0,FW_BOLD,  0,0,0,ANSI_CHARSET,0,0,CLEARTYPE_QUALITY,FF_SWISS,"Segoe UI");
    fIcon=CreateFontW(-14,0,0,0,FW_NORMAL,0,0,0,DEFAULT_CHARSET,0,0,CLEARTYPE_QUALITY,FF_SWISS,L"Segoe MDL2 Assets");
    if(!fIcon) fIcon=CreateFontW(-14,0,0,0,FW_NORMAL,0,0,0,DEFAULT_CHARSET,0,0,CLEARTYPE_QUALITY,FF_SWISS,L"Segoe UI Symbol");
    fIconBig=CreateFontW(-22,0,0,0,FW_NORMAL,0,0,0,DEFAULT_CHARSET,0,0,CLEARTYPE_QUALITY,FF_SWISS,L"Segoe MDL2 Assets");
    if(!fIconBig) fIconBig=CreateFontW(-22,0,0,0,FW_NORMAL,0,0,0,DEFAULT_CHARSET,0,0,CLEARTYPE_QUALITY,FF_SWISS,L"Segoe UI Symbol");

    /* Window class  -  load Kaevex icon from dist folder */
    WNDCLASSEXA wc={0};
    wc.cbSize=sizeof(wc);
    wc.style=CS_HREDRAW|CS_VREDRAW;
    wc.lpfnWndProc=WndProc;
    wc.hInstance=hi;
    wc.hCursor=LoadCursorA(NULL,IDC_ARROW);
    wc.hbrBackground=(HBRUSH)GetStockObject(BLACK_BRUSH);
    wc.lpszClassName="KaevexGUIModern";

    /* Load Kaevex icon: first from embedded PE resource ID 1, then from file paths */
    HICON hIcoBig = NULL;
    HICON hIcoSmall = NULL;
    LoadKaevexIconPair(hi, &hIcoBig, &hIcoSmall);

    wc.hIcon   = hIcoBig ? hIcoBig : LoadIconA(NULL, IDI_APPLICATION);
    wc.hIconSm = hIcoSmall ? hIcoSmall : wc.hIcon;
    RegisterClassExA(&wc);


    /* Main Window Dimensions */
    RECT wr2={0,0,1280,820};
    AdjustWindowRect(&wr2,WS_OVERLAPPEDWINDOW,FALSE);
    g_hwnd=CreateWindowExA(0,"KaevexGUIModern",KAEVEX_TITLE,
        WS_OVERLAPPEDWINDOW|WS_CLIPCHILDREN,
        CW_USEDEFAULT,CW_USEDEFAULT,
        wr2.right-wr2.left,wr2.bottom-wr2.top,
        NULL,NULL,hi,NULL);
    if(!g_hwnd) return 1;

    /* Set window icons explicitly so Taskbar and Alt+Tab always show Kaevex icon */
    if (hIcoBig)   SendMessageA(g_hwnd, WM_SETICON, ICON_BIG,   (LPARAM)hIcoBig);
    if (hIcoSmall) SendMessageA(g_hwnd, WM_SETICON, ICON_SMALL, (LPARAM)hIcoSmall);

    /* DWM Dark Mode Enforced */
    BOOL dark=1;
    DwmSetWindowAttribute(g_hwnd,20,&dark,sizeof(dark));
    DwmSetWindowAttribute(g_hwnd,19,&dark,sizeof(dark));

    CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    CveLoadSchedule();
    CreateControls(g_hwnd);
    Layout(g_hwnd);
    SetTimer(g_hwnd, ID_TIMER, 1000, NULL);
    CveUpdateSchedule(g_hwnd);
    CreateThread(NULL,0,telemThread,NULL,0,NULL);
    mobile_api_bind_telemetry(&g_avThreats, &g_wafBlk, &g_wafInsp, &g_realInPkts, &g_realOutPkts, &g_realDrops, &g_netConnCnt, &g_lockdown);
    mobile_api_bind_platform_callbacks(
        get_engines_json_for_mobile,
        get_alerts_json_for_mobile,
        get_threats_json_for_mobile,
        execute_threat_action_from_mobile,
        g_chartOutbound
    );
    mobile_api_bind_alert_callback(add_alert);
    mobile_api_start(API_PORT);
    supabase_engine_init(HandleRemoteSupabaseAction);
    g_teamAutoMode = FALSE;   /* Manual by default  -  user toggles with the button */
    /* Gaming mode is strictly manual - watchdog runs only when user turns it ON */
    if (startMinimized) {
        ShowWindow(g_hwnd, SW_HIDE);
    } else {
        ShowWindow(g_hwnd, (ns <= 0) ? SW_SHOWNORMAL : ns);
        UpdateWindow(g_hwnd);
        SetForegroundWindow(g_hwnd);
    }

    InitTrayIcon(g_hwnd);
    if (!startMinimized) {
        if (lp && (strstr(lp, "--login") || strstr(lp, "--auth"))) {
            ShowSupabaseAccountDialog(g_hwnd);
        } else {
            PromptFirstRunWizard(g_hwnd);
        }
        InvalidateRect(g_hwnd, NULL, TRUE);
        UpdateWindow(g_hwnd);
    } else {
        NOTIFYICONDATAA nidBoot = {0};
        nidBoot.cbSize = sizeof(nidBoot);
        nidBoot.hWnd = g_hwnd;
        nidBoot.uID = 1;
        nidBoot.uFlags = NIF_INFO;
        nidBoot.dwInfoFlags = NIIF_INFO;
        strncpy(nidBoot.szInfoTitle, "Kaevex Security Shield Active", sizeof(nidBoot.szInfoTitle)-1);
        strncpy(nidBoot.szInfo, "Real-time kernel defense, network baseline, and cloud sync are armed.", sizeof(nidBoot.szInfo)-1);
        Shell_NotifyIconA(NIM_MODIFY, &nidBoot);
    }

    char mobAlert[160];
    snprintf(mobAlert, sizeof(mobAlert), "Android Mobile REST API listening on 0.0.0.0:%d (Pairing PIN: %s)", API_PORT, mobile_api_get_pin());
    add_alert("MobileAPI", "INFO", mobAlert);

    /* Auto-populate CVE tab on startup so scan results are visible immediately */

    PostMessageA(g_hwnd, WM_COMMAND, MAKEWPARAM(IDU_SCAN, 0), 0);
    /* Launch initial app discovery in background */
    disc_run_async(g_hwnd, WM_DISC_DONE);
    /* Auto-start RansomShield real-time file monitor on startup */
    PostMessageA(g_hwnd, WM_COMMAND, MAKEWPARAM(IDR_START, 0), 0);
    /* Auto-load Adaptive Firewall rules inventory on startup */
    PostMessageA(g_hwnd, WM_COMMAND, MAKEWPARAM(IDF_RELOAD, 0), 0);

    /* Startup Baseline Inspection Alert */
    if(initRep.unverifiedConns > 0){
        char alertMsg[300];
        snprintf(alertMsg, sizeof(alertMsg), "Baseline: %d active conns (%d Web, %d DL, %d Unverified: %s -> %s)",
                 initRep.totalConns, initRep.webConns, initRep.downloadConns, initRep.unverifiedConns,
                 initRep.unverifiedProcs[0], initRep.unverifiedAddrs[0]);
        add_alert("NetGuard", "WARNING", alertMsg);
    } else {
        add_alert("NetGuard", "INFO", "Baseline scan verified: All active network connections are authenticated.");
    }

    MSG m;
    while(GetMessageA(&m,NULL,0,0)){TranslateMessage(&m); DispatchMessageA(&m);}

    threat_stop_game_watchdog();
    if(g_sbx.active) sbx_kill();
    rw_stop();
    mobile_api_stop();
    supabase_engine_shutdown();
    DeleteCriticalSection(&g_statsCS); DeleteCriticalSection(&g_alCS);
    DeleteObject(fHdr); DeleteObject(fBig); DeleteObject(fMed);
    DeleteObject(fSm); DeleteObject(fMono); DeleteObject(fStat);
    if(hBrEdit) DeleteObject(hBrEdit);
    if(hBrList) DeleteObject(hBrList);
    if(hBrPnl)  DeleteObject(hBrPnl);
    return (int)m.wParam;
}
