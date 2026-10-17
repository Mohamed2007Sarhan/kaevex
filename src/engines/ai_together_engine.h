/*===========================================================================
 * Kaevex Security Platform - ai_together_engine.h  (rewritten: unified AI layer)
 *
 * One transport for all cloud providers (Together / Groq / NVIDIA), each with
 * its OWN API key stored per-user with DPAPI. Fixes the previous failures:
 *   - single shared key sent to the wrong provider            -> per-provider keys
 *   - retired / wrong model IDs                               -> verified IDs (ai_core.h)
 *   - JSON broken by backslashes / non-UTF-8 (Arabic ANSI)    -> strict escaping + ANSI<->UTF-8
 *   - reasoning models returned empty text (max_tokens 1024)  -> 4096 + clear diagnosis
 *   - errors swallowed, UI said only "provider unavailable"   -> HTTP status + reason returned
 *   - 30 s receive timeout, no retry, no proxy auto-detect    -> 120 s, retry, auto proxy, TLS 1.2/1.3
 * Old function names (together_ai_*) remain as wrappers for existing callers.
 *===========================================================================*/
#pragma once
#ifndef AI_TOGETHER_ENGINE_H
#define AI_TOGETHER_ENGINE_H

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winhttp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <psapi.h>
#include <wincrypt.h>
#include "ai_core.h"

#pragma comment(lib, "winhttp.lib")

#ifndef WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY
#define WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY 4
#endif
#ifndef WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2
#define WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2 0x00000800
#endif
#ifndef WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3
#define WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3 0x00002000
#endif

#define KVAI_ANSI_IO 0x1   /* caller strings are ANSI (CP_ACP); convert to/from UTF-8 */

/* ---- Global state --------------------------------------------------------- */
static int              g_aiProvider = 0;   /* 0 Together, 1 Groq, 2 NVIDIA, 3 Local */
static char             g_kvKey[KVAI_PROVIDER_COUNT][256];
static char             g_kvModel[KVAI_PROVIDER_COUNT][128];
static CRITICAL_SECTION g_kvCS;
static volatile LONG    g_kvInit = 0;
static char             g_kvLastError[384] = "";

static void kvai_init(void) {
    if (InterlockedCompareExchange(&g_kvInit, 1, 0) == 0) {
        InitializeCriticalSection(&g_kvCS);
        InterlockedExchange(&g_kvInit, 2);
    } else {
        while (g_kvInit != 2) Sleep(1);
    }
}

static int kvai_cloud_provider(int p) { return (p >= 0 && p < KVAI_PROVIDER_COUNT) ? p : 0; }

/* Trim whitespace/quotes and an accidental "Bearer " prefix - a pasted key with a
 * trailing newline or space is a very common cause of HTTP 401. */
static void kvai_key_clean(char *k) {
    size_t n = strlen(k), a = 0;
    while (n && (isspace((unsigned char)k[n-1]) || k[n-1] == '"' || k[n-1] == '\'')) k[--n] = '\0';
    while (k[a] && (isspace((unsigned char)k[a]) || k[a] == '"' || k[a] == '\'')) a++;
    if (a) memmove(k, k + a, strlen(k + a) + 1);
    if (_strnicmp(k, "Bearer ", 7) == 0) memmove(k, k + 7, strlen(k + 7) + 1);
    n = strlen(k);
    while (n && isspace((unsigned char)k[n-1])) k[--n] = '\0';
}

static void kvai_reg_name(int prov, char *out, size_t n) {
    snprintf(out, n, "AIKeyProtected_%s", g_kvProv[kvai_cloud_provider(prov)].id);
}

static BOOL kvai_reg_read_key(int prov, char *out, size_t max) {
    BOOL ok = FALSE; HKEY hk; char name[64];
    kvai_reg_name(prov, name, sizeof(name));
    if (RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Kaevex", 0, KEY_READ, &hk) != ERROR_SUCCESS) return FALSE;
    DWORD type = 0, sz = 0;
    if (RegQueryValueExA(hk, name, NULL, &type, NULL, &sz) == ERROR_SUCCESS &&
        type == REG_BINARY && sz > 0 && sz <= 4096) {
        BYTE *blob = (BYTE *)malloc(sz);
        if (blob && RegQueryValueExA(hk, name, NULL, &type, blob, &sz) == ERROR_SUCCESS) {
            DATA_BLOB in = { sz, blob }, plain = { 0, NULL };
            if (CryptUnprotectData(&in, NULL, NULL, NULL, NULL, CRYPTPROTECT_UI_FORBIDDEN, &plain)) {
                if (plain.cbData > 0 && plain.cbData < max) {
                    memcpy(out, plain.pbData, plain.cbData);
                    out[plain.cbData] = '\0';
                    ok = TRUE;
                }
                SecureZeroMemory(plain.pbData, plain.cbData);
                LocalFree(plain.pbData);
            }
        }
        free(blob);
    }
    RegCloseKey(hk);
    return ok;
}

static void kvai_key_save(int prov, const char *keyIn) {
    kvai_init();
    prov = kvai_cloud_provider(prov);
    char key[256] = {0};
    if (keyIn) { strncpy(key, keyIn, sizeof(key) - 1); kvai_key_clean(key); }
    EnterCriticalSection(&g_kvCS);
    strncpy(g_kvKey[prov], key, sizeof(g_kvKey[prov]) - 1);
    g_kvKey[prov][sizeof(g_kvKey[prov]) - 1] = '\0';
    LeaveCriticalSection(&g_kvCS);

    HKEY hk; char name[64];
    kvai_reg_name(prov, name, sizeof(name));
    if (RegCreateKeyExA(HKEY_CURRENT_USER, "Software\\Kaevex", 0, NULL, 0, KEY_ALL_ACCESS, NULL, &hk, NULL) == ERROR_SUCCESS) {
        if (key[0]) {
            DATA_BLOB plain = { (DWORD)strlen(key), (BYTE *)key }, enc = { 0, NULL };
            if (CryptProtectData(&plain, L"Kaevex provider API key", NULL, NULL, NULL, CRYPTPROTECT_UI_FORBIDDEN, &enc)) {
                RegSetValueExA(hk, name, 0, REG_BINARY, enc.pbData, enc.cbData);
                LocalFree(enc.pbData);
            }
        } else {
            RegDeleteValueA(hk, name);
        }
        RegCloseKey(hk);
    }
    SecureZeroMemory(key, sizeof(key));
}

/* One-time migration of the old single shared key to the correct provider slot. */
static void kvai_migrate_legacy(void) {
    HKEY hk;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Kaevex", 0, KEY_ALL_ACCESS, &hk) != ERROR_SUCCESS) return;
    char legacy[256] = {0};
    DWORD type = 0, sz = 0;
    if (RegQueryValueExA(hk, "AIKeyProtected", NULL, &type, NULL, &sz) == ERROR_SUCCESS &&
        type == REG_BINARY && sz > 0 && sz <= 4096) {
        BYTE *blob = (BYTE *)malloc(sz);
        if (blob && RegQueryValueExA(hk, "AIKeyProtected", NULL, &type, blob, &sz) == ERROR_SUCCESS) {
            DATA_BLOB in = { sz, blob }, plain = { 0, NULL };
            if (CryptUnprotectData(&in, NULL, NULL, NULL, NULL, CRYPTPROTECT_UI_FORBIDDEN, &plain)) {
                if (plain.cbData > 0 && plain.cbData < sizeof(legacy)) { memcpy(legacy, plain.pbData, plain.cbData); legacy[plain.cbData] = 0; }
                SecureZeroMemory(plain.pbData, plain.cbData); LocalFree(plain.pbData);
            }
        }
        free(blob);
    }
    if (!legacy[0]) {
        DWORD s2 = sizeof(legacy), t2 = REG_SZ;
        if (RegQueryValueExA(hk, "TogetherApiKey", NULL, &t2, (BYTE *)legacy, &s2) != ERROR_SUCCESS || !legacy[0]) {
            s2 = sizeof(legacy); t2 = REG_SZ;
            RegQueryValueExA(hk, "AIApiKey", NULL, &t2, (BYTE *)legacy, &s2);
        }
    }
    DWORD savedProv = 0, ps = sizeof(savedProv), pt = REG_DWORD;
    if (RegQueryValueExA(hk, "AIProvider", NULL, &pt, (BYTE *)&savedProv, &ps) != ERROR_SUCCESS) savedProv = 0;
    RegCloseKey(hk);

    if (legacy[0]) {
        kvai_key_clean(legacy);
        int target = (savedProv < KVAI_PROVIDER_COUNT) ? (int)savedProv : 0;
        for (int i = 0; i < KVAI_PROVIDER_COUNT; i++)
            if (g_kvProv[i].keyPrefix[0] && strncmp(legacy, g_kvProv[i].keyPrefix, strlen(g_kvProv[i].keyPrefix)) == 0) target = i;
        char tmp[256] = {0};
        if (!kvai_reg_read_key(target, tmp, sizeof(tmp))) kvai_key_save(target, legacy);
        SecureZeroMemory(tmp, sizeof(tmp));
        if (RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Kaevex", 0, KEY_ALL_ACCESS, &hk) == ERROR_SUCCESS) {
            RegDeleteValueA(hk, "AIKeyProtected"); RegDeleteValueA(hk, "TogetherApiKey"); RegDeleteValueA(hk, "AIApiKey");
            RegCloseKey(hk);
        }
        SecureZeroMemory(legacy, sizeof(legacy));
    }
}

/* Resolution order: memory -> environment -> DPAPI registry. */
static void kvai_key_get(int prov, char *out, size_t max) {
    kvai_init();
    prov = kvai_cloud_provider(prov);
    out[0] = '\0';
    EnterCriticalSection(&g_kvCS);
    if (g_kvKey[prov][0]) { strncpy(out, g_kvKey[prov], max - 1); out[max - 1] = 0; LeaveCriticalSection(&g_kvCS); return; }
    LeaveCriticalSection(&g_kvCS);
    char tmp[256] = {0};
    const char *env = getenv(g_kvProv[prov].envKey);
    if (env && env[0]) strncpy(tmp, env, sizeof(tmp) - 1);
    else kvai_reg_read_key(prov, tmp, sizeof(tmp));
    kvai_key_clean(tmp);
    if (tmp[0]) {
        EnterCriticalSection(&g_kvCS);
        strncpy(g_kvKey[prov], tmp, sizeof(g_kvKey[prov]) - 1);
        LeaveCriticalSection(&g_kvCS);
        strncpy(out, tmp, max - 1); out[max - 1] = 0;
    }
    SecureZeroMemory(tmp, sizeof(tmp));
}

/* "environment" / "saved (DPAPI)" / "none" - for honest status display. */
static const char *kvai_key_source(int prov) {
    prov = kvai_cloud_provider(prov);
    const char *env = getenv(g_kvProv[prov].envKey);
    if (env && env[0]) return "environment variable";
    char tmp[256] = {0};
    BOOL has = kvai_reg_read_key(prov, tmp, sizeof(tmp));
    SecureZeroMemory(tmp, sizeof(tmp));
    return has ? "saved (DPAPI-encrypted)" : "none";
}

static void kvai_model_get(int prov, char *out, size_t max) {
    kvai_init();
    prov = kvai_cloud_provider(prov);
    EnterCriticalSection(&g_kvCS);
    const char *m = g_kvModel[prov][0] ? g_kvModel[prov] : NULL;
    if (m) { strncpy(out, m, max - 1); out[max - 1] = 0; LeaveCriticalSection(&g_kvCS); return; }
    LeaveCriticalSection(&g_kvCS);
    const char *env = getenv(g_kvProv[prov].envModel);
    strncpy(out, (env && env[0]) ? env : g_kvProv[prov].defModel, max - 1);
    out[max - 1] = 0;
}

static void kvai_model_set(int prov, const char *model) {
    kvai_init();
    prov = kvai_cloud_provider(prov);
    EnterCriticalSection(&g_kvCS);
    if (model && model[0]) { strncpy(g_kvModel[prov], model, sizeof(g_kvModel[prov]) - 1); }
    else g_kvModel[prov][0] = '\0';
    LeaveCriticalSection(&g_kvCS);
}

/* ---- Encoding helpers ----------------------------------------------------- */
static char *kvai_ansi_to_utf8_alloc(const char *s) {
    if (!s) return NULL;
    if (kvai_is_valid_utf8(s)) return _strdup(s);       /* ASCII or already UTF-8 */
    int wl = MultiByteToWideChar(CP_ACP, 0, s, -1, NULL, 0);
    if (wl <= 0) return _strdup(s);
    wchar_t *w = (wchar_t *)malloc((size_t)wl * sizeof(wchar_t));
    if (!w) return NULL;
    MultiByteToWideChar(CP_ACP, 0, s, -1, w, wl);
    int ul = WideCharToMultiByte(CP_UTF8, 0, w, -1, NULL, 0, NULL, NULL);
    char *u = (char *)malloc((size_t)ul + 1);
    if (u) WideCharToMultiByte(CP_UTF8, 0, w, -1, u, ul, NULL, NULL);
    free(w);
    return u;
}

static void kvai_utf8_to_ansi(const char *u, char *out, size_t max) {
    int wl = MultiByteToWideChar(CP_UTF8, 0, u, -1, NULL, 0);
    if (wl <= 0) { strncpy(out, u, max - 1); out[max - 1] = 0; return; }
    wchar_t *w = (wchar_t *)malloc((size_t)wl * sizeof(wchar_t));
    if (!w) { strncpy(out, u, max - 1); out[max - 1] = 0; return; }
    MultiByteToWideChar(CP_UTF8, 0, u, -1, w, wl);
    if (WideCharToMultiByte(CP_ACP, 0, w, -1, out, (int)max, "?", NULL) == 0) {
        strncpy(out, u, max - 1); out[max - 1] = 0;
    }
    out[max - 1] = 0;
    free(w);
}

/* ---- HTTP transport ------------------------------------------------------- */
static const char *kvai_winerr_text(DWORD e) {
    switch (e) {
        case 12007: return "DNS lookup failed (no internet or DNS blocked).";
        case 12002: case 12005: return "Connection timed out.";
        case 12029: return "Could not connect to the provider (firewall, VPN, or the host is blocked).";
        case 12030: return "Connection was dropped.";
        case 12038: case 12044: case 12045: case 12157: case 12175:
                    return "TLS/certificate error (check system date/time, antivirus HTTPS scanning, or proxy).";
        case 12017: return "Request was cancelled.";
        default:    return "Network error.";
    }
}

static int kvai_http_post(const char *host, const char *path, const char *key, const char *body,
                          int *status, char **resp, DWORD *winErr) {
    *status = 0; *resp = NULL; *winErr = 0;
    wchar_t wHost[128], wPath[256];
    MultiByteToWideChar(CP_UTF8, 0, host, -1, wHost, 128);
    MultiByteToWideChar(CP_UTF8, 0, path, -1, wPath, 256);

    HINTERNET hS = WinHttpOpen(L"Kaevex-AI/2.0", WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
                               WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hS) hS = WinHttpOpen(L"Kaevex-AI/2.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                              WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hS) { *winErr = GetLastError(); return 0; }

    DWORD protos = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2 | WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3;
    if (!WinHttpSetOption(hS, WINHTTP_OPTION_SECURE_PROTOCOLS, &protos, sizeof(protos))) {
        protos = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2;
        WinHttpSetOption(hS, WINHTTP_OPTION_SECURE_PROTOCOLS, &protos, sizeof(protos));
    }
    /* Reasoning models can think for a long time before the first byte. */
    WinHttpSetTimeouts(hS, 10000, 10000, 20000, 120000);

    int ok = 0;
    HINTERNET hC = WinHttpConnect(hS, wHost, INTERNET_DEFAULT_HTTPS_PORT, 0);
    HINTERNET hR = hC ? WinHttpOpenRequest(hC, L"POST", wPath, NULL, WINHTTP_NO_REFERER,
                                           WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE) : NULL;
    if (hR) {
        char hdr[640];
        snprintf(hdr, sizeof(hdr), "Authorization: Bearer %s\r\nContent-Type: application/json\r\nAccept: application/json\r\n", key);
        wchar_t wHdr[700];
        MultiByteToWideChar(CP_UTF8, 0, hdr, -1, wHdr, 700);
        DWORD blen = (DWORD)strlen(body);
        if (WinHttpSendRequest(hR, wHdr, (DWORD)-1L, (LPVOID)body, blen, blen, 0) &&
            WinHttpReceiveResponse(hR, NULL)) {
            DWORD sc = 0, ssz = sizeof(sc);
            WinHttpQueryHeaders(hR, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                                WINHTTP_HEADER_NAME_BY_INDEX, &sc, &ssz, WINHTTP_NO_HEADER_INDEX);
            *status = (int)sc;
            size_t cap = 32768, len = 0;
            char *buf = (char *)malloc(cap);
            if (buf) {
                for (;;) {
                    if (cap - len < 8192) {
                        if (cap >= (4u << 20)) break;            /* 4 MB hard cap */
                        char *nb = (char *)realloc(buf, cap * 2);
                        if (!nb) break;
                        buf = nb; cap *= 2;
                    }
                    DWORD rd = 0;
                    if (!WinHttpReadData(hR, buf + len, (DWORD)(cap - len - 1), &rd) || rd == 0) break;
                    len += rd;
                }
                buf[len] = '\0';
                *resp = buf;
                ok = 1;
            }
        } else {
            *winErr = GetLastError();
        }
        WinHttpCloseHandle(hR);
    } else {
        *winErr = GetLastError();
    }
    if (hC) WinHttpCloseHandle(hC);
    WinHttpCloseHandle(hS);
    return ok;
}

/* ---- Public API ----------------------------------------------------------- */
/* prov: 0..2. keyOverride/modelOverride may be NULL. out receives the answer
 * (ANSI if KVAI_ANSI_IO, else UTF-8). res always describes what happened. */
static int kvai_chat(int prov, const char *keyOverride, const char *modelOverride,
                     const char *sys, const char *user, float temp, int maxTok,
                     char *out, size_t outLen, int flags, KvAiResult *res) {
    KvAiResult local; if (!res) res = &local;
    memset(res, 0, sizeof(*res));
    if (out && outLen) out[0] = '\0';
    kvai_init();
    res->provider = prov;
    DWORD t0 = GetTickCount();

    if (prov < 0 || prov >= KVAI_PROVIDER_COUNT) {
        snprintf(res->error, sizeof(res->error), "No cloud provider selected (Local mode sends nothing to the cloud).");
        return 0;
    }
    const KvAiProviderDef *pd = &g_kvProv[prov];

    char key[256] = {0};
    if (keyOverride && keyOverride[0]) { strncpy(key, keyOverride, sizeof(key) - 1); kvai_key_clean(key); }
    else kvai_key_get(prov, key, sizeof(key));
    if (!key[0]) {
        snprintf(res->error, sizeof(res->error),
                 "No API key for %s. Add it in Settings > AI Engine or set %s.", pd->label, pd->envKey);
        return 0;
    }
    char model[128];
    if (modelOverride && modelOverride[0]) { strncpy(model, modelOverride, sizeof(model) - 1); model[sizeof(model) - 1] = 0; }
    else kvai_model_get(prov, model, sizeof(model));
    strncpy(res->model, model, sizeof(res->model) - 1);

    char *sysU = (flags & KVAI_ANSI_IO) ? kvai_ansi_to_utf8_alloc(sys) : (sys ? _strdup(sys) : NULL);
    char *usrU = (flags & KVAI_ANSI_IO) ? kvai_ansi_to_utf8_alloc(user) : (user ? _strdup(user) : NULL);
    char *body = kvai_build_request(model, sysU, usrU, temp, maxTok > 0 ? maxTok : pd->defMaxTokens);
    free(sysU); free(usrU);
    if (!body) { snprintf(res->error, sizeof(res->error), "Out of memory building request."); SecureZeroMemory(key, sizeof(key)); return 0; }

    char *u8 = (char *)malloc(outLen * 2 + 16);   /* UTF-8 answer may be larger than ANSI */
    char perr[384] = {0};
    int ok = 0;
    for (int attempt = 1; attempt <= 2 && !ok; attempt++) {
        res->attempts = attempt;
        char *resp = NULL; int status = 0; DWORD we = 0;
        int got = kvai_http_post(pd->host, pd->path, key, body, &status, &resp, &we);
        res->status = status;
        if (got && u8) {
            ok = kvai_parse_response(status, resp, prov, u8, outLen * 2 + 16, perr, sizeof(perr));
        } else {
            snprintf(perr, sizeof(perr), "Network failure (Win32 error %lu): %s", (unsigned long)we, kvai_winerr_text(we));
        }
        free(resp);
        int transient = (!got) || status == 429 || status >= 500;
        if (ok || !transient || attempt == 2) break;
        Sleep(1500 * (DWORD)attempt);
    }
    if (ok) {
        if (flags & KVAI_ANSI_IO) kvai_utf8_to_ansi(u8, out, outLen);
        else { strncpy(out, u8, outLen - 1); out[outLen - 1] = 0; }
    } else {
        snprintf(res->error, sizeof(res->error), "%s", perr);
    }
    res->ok = ok;
    res->ms = GetTickCount() - t0;
    EnterCriticalSection(&g_kvCS);
    snprintf(g_kvLastError, sizeof(g_kvLastError), "%s", ok ? "" : res->error);
    LeaveCriticalSection(&g_kvCS);
    free(u8); free(body);
    SecureZeroMemory(key, sizeof(key));
    return ok;
}

/* ---- Backwards-compatible wrappers (mobile API etc.) ---------------------- */
static void together_ai_init(void) { kvai_init(); kvai_migrate_legacy(); }
static void together_ai_set_key(const char *key) { kvai_key_save(kvai_cloud_provider(g_aiProvider), key); }
static void together_ai_save_key(const char *key) { kvai_key_save(kvai_cloud_provider(g_aiProvider), key); }
static void together_ai_get_key(char *out, size_t max) { kvai_key_get(kvai_cloud_provider(g_aiProvider), out, max); }
static void together_ai_set_model(const char *m) { kvai_model_set(kvai_cloud_provider(g_aiProvider), m); }
static void together_ai_get_model(char *out, size_t max) { kvai_model_get(kvai_cloud_provider(g_aiProvider), out, max); }

static void together_json_escape(const char *src, char *dst, size_t maxDst) {
    if (!dst || maxDst == 0) return;
    char *e = kvai_escape_alloc(src);
    if (!e) { dst[0] = '\0'; return; }
    strncpy(dst, e, maxDst - 1); dst[maxDst - 1] = '\0';
    /* never leave a dangling backslash if truncated */
    size_t n = strlen(dst), bs = 0;
    while (n > bs && dst[n - 1 - bs] == '\\') bs++;
    if (bs & 1) dst[n - 1] = '\0';
    free(e);
}

static BOOL together_ai_chat_query(const char *key, const char *model, const char *systemPrompt,
    const char *userPrompt, float temperature, int maxTokens, char *out, size_t outLen, int *status) {
    KvAiResult r;
    int p = kvai_cloud_provider(g_aiProvider);
    BOOL ok = kvai_chat(p, key, model, systemPrompt, userPrompt, temperature, maxTokens, out, outLen, 0, &r);
    if (status) *status = r.status;
    return ok;
}

/* Honest local summary used when no cloud answer is available. */
static void together_ai_generate_local_fallback(const char *prompt, const char *team, char *out, size_t maxOut) {
    (void)prompt;
    if (!out || maxOut == 0) return;
    MEMORYSTATUSEX ms = { sizeof(ms) };
    GlobalMemoryStatusEx(&ms);
    DWORD pids[1024] = {0}; DWORD br = 0; int procCount = 0;
    if (EnumProcesses(pids, sizeof(pids), &br)) procCount = (int)(br / sizeof(DWORD));
    snprintf(out, maxOut,
        "[Local telemetry - %s] RAM load %lu%%, %d running processes. "
        "No AI model answered, so this is only a local snapshot, not an analysis.",
        (team && team[0]) ? team : "Blue", (unsigned long)ms.dwMemoryLoad, procCount);
}

#endif /* AI_TOGETHER_ENGINE_H */
