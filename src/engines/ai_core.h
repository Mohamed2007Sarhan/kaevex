/*===========================================================================
 * Kaevex Security Platform - ai_core.h
 * Portable (no Windows dependencies) core of the AI layer:
 *   - provider table (one entry per cloud provider, each with its OWN key)
 *   - strict JSON string escaping (always emits valid UTF-8 JSON)
 *   - structure-aware JSON reader (never confused by text inside strings)
 *   - HTTP/API error classification with actionable messages
 * The Windows transport lives in ai_together_engine.h.
 *===========================================================================*/
#pragma once
#ifndef KVAI_CORE_H
#define KVAI_CORE_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

/* ---- Providers ----------------------------------------------------------- */
#define KVAI_PROVIDER_COUNT 3
#define KVAI_P_TOGETHER 0
#define KVAI_P_GROQ     1
#define KVAI_P_NVIDIA   2
#define KVAI_P_LOCAL    3   /* no network: local analysis only */

typedef struct {
    const char *id;        /* registry/value suffix */
    const char *label;     /* shown in UI */
    const char *host;
    const char *path;
    const char *defModel;
    const char *envKey;
    const char *envModel;
    const char *keyPrefix; /* used only to guess the owner of a legacy key */
    int         defMaxTokens;
} KvAiProviderDef;

/* Model IDs verified against provider docs (Oct 2026):
 *  - Together : deepseek-ai/DeepSeek-V4-Pro   (the old "-0813" suffix does not exist)
 *  - Groq     : openai/gpt-oss-120b           (llama-3.3-70b-versatile was retired 2026-08-16)
 *  - NVIDIA   : z-ai/glm-5.3-flash
 * All three are reasoning models, so they need a generous max_tokens: a small
 * limit is consumed by hidden reasoning and the visible answer comes back empty. */
static const KvAiProviderDef g_kvProv[KVAI_PROVIDER_COUNT] = {
    { "together", "Together AI (DeepSeek-V4-Pro)", "api.together.xyz",
      "/v1/chat/completions", "deepseek-ai/DeepSeek-V4-Pro",
      "TOGETHER_API_KEY", "TOGETHER_MODEL", "", 4096 },
    { "groq", "Groq (gpt-oss-120b)", "api.groq.com",
      "/openai/v1/chat/completions", "openai/gpt-oss-120b",
      "GROQ_API_KEY", "GROQ_MODEL", "gsk_", 4096 },
    { "nvidia", "NVIDIA NIM (GLM-5.3-Flash)", "integrate.api.nvidia.com",
      "/v1/chat/completions", "z-ai/glm-5.3-flash",
      "NVIDIA_API_KEY", "NVIDIA_MODEL", "nvapi-", 4096 },
};

typedef struct {
    int      ok;
    int      status;        /* HTTP status, 0 = network failure */
    int      attempts;
    unsigned ms;
    int      provider;
    char     model[128];
    char     error[384];    /* human readable reason when !ok */
} KvAiResult;

/* ---- UTF-8 helpers -------------------------------------------------------- */
/* Returns length of a valid UTF-8 sequence starting at s, or 0 if invalid. */
static int kvai_utf8_seq(const unsigned char *s) {
    if (s[0] < 0x80) return 1;
    if (s[0] >= 0xC2 && s[0] <= 0xDF && (s[1] & 0xC0) == 0x80) return 2;
    if (s[0] >= 0xE0 && s[0] <= 0xEF && (s[1] & 0xC0) == 0x80 && (s[2] & 0xC0) == 0x80) {
        if (s[0] == 0xE0 && s[1] < 0xA0) return 0;     /* overlong */
        if (s[0] == 0xED && s[1] >= 0xA0) return 0;    /* surrogate */
        return 3;
    }
    if (s[0] >= 0xF0 && s[0] <= 0xF4 && (s[1] & 0xC0) == 0x80 &&
        (s[2] & 0xC0) == 0x80 && (s[3] & 0xC0) == 0x80) {
        if (s[0] == 0xF0 && s[1] < 0x90) return 0;
        if (s[0] == 0xF4 && s[1] > 0x8F) return 0;
        return 4;
    }
    return 0;
}

static int kvai_is_valid_utf8(const char *s) {
    const unsigned char *p = (const unsigned char *)s;
    while (*p) { int n = kvai_utf8_seq(p); if (!n) return 0; p += n; }
    return 1;
}

/* ---- JSON escaping -------------------------------------------------------- */
/* Escapes src for use inside a JSON string. Output is ALWAYS valid UTF-8:
 * invalid bytes become '?'. Fixes the old escaper that ignored backslashes
 * (any Windows path in a prompt produced invalid JSON -> HTTP 400). */
static char *kvai_escape_alloc(const char *src) {
    size_t n = src ? strlen(src) : 0;
    char *o = (char *)malloc(n * 6 + 1);
    if (!o) return NULL;
    size_t d = 0;
    const unsigned char *p = (const unsigned char *)(src ? src : "");
    while (*p) {
        unsigned char c = *p;
        if (c == '"')       { o[d++] = '\\'; o[d++] = '"';  p++; }
        else if (c == '\\') { o[d++] = '\\'; o[d++] = '\\'; p++; }
        else if (c == '\n') { o[d++] = '\\'; o[d++] = 'n';  p++; }
        else if (c == '\r') { o[d++] = '\\'; o[d++] = 'r';  p++; }
        else if (c == '\t') { o[d++] = '\\'; o[d++] = 't';  p++; }
        else if (c < 0x20)  { d += (size_t)sprintf(o + d, "\\u%04x", c); p++; }
        else if (c < 0x80)  { o[d++] = (char)c; p++; }
        else {
            int sl = kvai_utf8_seq(p);
            if (!sl) { o[d++] = '?'; p++; }
            else { memcpy(o + d, p, (size_t)sl); d += (size_t)sl; p += sl; }
        }
    }
    o[d] = '\0';
    return o;
}

/* Request body (OpenAI-compatible chat completions). Caller frees. */
static char *kvai_build_request(const char *model, const char *sys, const char *user,
                                float temperature, int maxTokens) {
    char *eM = kvai_escape_alloc(model);
    char *eS = kvai_escape_alloc(sys && sys[0] ? sys : "You are a helpful assistant.");
    char *eU = kvai_escape_alloc(user ? user : "");
    if (!eM || !eS || !eU) { free(eM); free(eS); free(eU); return NULL; }
    if (temperature < 0.0f) temperature = 0.0f;
    if (temperature > 1.5f) temperature = 1.5f;
    if (maxTokens < 64) maxTokens = 64;
    size_t cap = strlen(eM) + strlen(eS) + strlen(eU) + 256;
    char *body = (char *)malloc(cap);
    if (!body) { free(eM); free(eS); free(eU); return NULL; }
    snprintf(body, cap,
        "{\"model\":\"%s\",\"messages\":["
        "{\"role\":\"system\",\"content\":\"%s\"},"
        "{\"role\":\"user\",\"content\":\"%s\"}],"
        "\"temperature\":%.2f,\"max_tokens\":%d,\"stream\":false}",
        eM, eS, eU, (double)temperature, maxTokens);
    free(eM); free(eS); free(eU);
    return body;
}

/* ---- JSON reading --------------------------------------------------------- */
static const char *kvai_ws(const char *p) {
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
    return p;
}

/* p points at an opening quote. Returns pointer just past the closing quote,
 * or NULL if the string is unterminated. */
static const char *kvai_skip_str(const char *p) {
    if (*p != '"') return NULL;
    p++;
    while (*p) {
        if (*p == '\\') { if (!p[1]) return NULL; p += 2; continue; }
        if (*p == '"') return p + 1;
        p++;
    }
    return NULL;
}

/* Finds an object KEY at any depth, skipping over string contents so text
 * inside values can never be mistaken for a key. Returns pointer to the value
 * (first non-space char after ':'), or NULL. */
static const char *kvai_find_key(const char *json, const char *key) {
    if (!json || !key) return NULL;
    size_t kl = strlen(key);
    const char *p = json;
    while (*p) {
        if (*p == '"') {
            const char *e = kvai_skip_str(p);
            if (!e) return NULL;
            size_t len = (size_t)(e - p) - 2;
            const char *q = kvai_ws(e);
            if (*q == ':' && len == kl && memcmp(p + 1, key, kl) == 0)
                return kvai_ws(q + 1);
            p = e;
        } else p++;
    }
    return NULL;
}

static void kvai_put_utf8(char *out, size_t *o, size_t max, unsigned long cp) {
    if (cp < 0x80) { if (*o + 1 < max) out[(*o)++] = (char)cp; }
    else if (cp < 0x800) { if (*o + 2 < max) { out[(*o)++] = (char)(0xC0 | (cp >> 6)); out[(*o)++] = (char)(0x80 | (cp & 0x3F)); } }
    else if (cp < 0x10000) { if (*o + 3 < max) { out[(*o)++] = (char)(0xE0 | (cp >> 12)); out[(*o)++] = (char)(0x80 | ((cp >> 6) & 0x3F)); out[(*o)++] = (char)(0x80 | (cp & 0x3F)); } }
    else { if (*o + 4 < max) { out[(*o)++] = (char)(0xF0 | (cp >> 18)); out[(*o)++] = (char)(0x80 | ((cp >> 12) & 0x3F)); out[(*o)++] = (char)(0x80 | ((cp >> 6) & 0x3F)); out[(*o)++] = (char)(0x80 | (cp & 0x3F)); } }
}

static int kvai_hex4(const char *p, unsigned long *v) {
    for (int i = 0; i < 4; i++) if (!isxdigit((unsigned char)p[i])) return 0;
    char h[5] = { p[0], p[1], p[2], p[3], 0 };
    *v = strtoul(h, NULL, 16);
    return 1;
}

/* Decodes the JSON string at p (must start with '"') into out (UTF-8).
 * Returns decoded length, or -1 if p is not a string. */
static int kvai_read_str(const char *p, char *out, size_t max) {
    if (!p || *p != '"' || !out || max == 0) return -1;
    p++;
    size_t o = 0;
    while (*p && *p != '"') {
        if (*p == '\\') {
            p++;
            switch (*p) {
                case 'n': if (o + 1 < max) out[o++] = '\n'; break;
                case 'r': if (o + 1 < max) out[o++] = '\r'; break;
                case 't': if (o + 1 < max) out[o++] = '\t'; break;
                case 'b': if (o + 1 < max) out[o++] = '\b'; break;
                case 'f': if (o + 1 < max) out[o++] = '\f'; break;
                case 'u': {
                    unsigned long cp = 0;
                    if (kvai_hex4(p + 1, &cp)) {
                        p += 4;
                        if (cp >= 0xD800 && cp <= 0xDBFF && p[1] == '\\' && p[2] == 'u') {
                            unsigned long lo = 0;
                            if (kvai_hex4(p + 3, &lo) && lo >= 0xDC00 && lo <= 0xDFFF) {
                                cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                                p += 6;
                            }
                        }
                        kvai_put_utf8(out, &o, max, cp);
                    }
                    break; }
                case '\0': goto done;
                default: if (o + 1 < max) out[o++] = *p; break;
            }
            p++;
        } else {
            if (o + 1 < max) out[o++] = *p;
            p++;
        }
    }
done:
    out[o] = '\0';
    return (int)o;
}

static void kvai_trim(char *s) {
    size_t n = strlen(s), a = 0;
    while (n > 0 && isspace((unsigned char)s[n - 1])) s[--n] = '\0';
    while (s[a] && isspace((unsigned char)s[a])) a++;
    if (a) memmove(s, s + a, strlen(s + a) + 1);
}

/* ---- Error classification ------------------------------------------------- */
static const char *kvai_status_hint(int status, int provider) {
    switch (status) {
        case 400: return "Bad request - the model name or request body was rejected.";
        case 401:
        case 403: (void)provider;
                  return "API key rejected. Keys are provider-specific: use a key issued by this provider.";
        case 402: return "Provider reports insufficient credit/billing.";
        case 404: return "Model or endpoint not found - the model ID may be retired or misspelled.";
        case 408: return "Provider timed out.";
        case 413: return "Request too large.";
        case 422: return "Provider could not process the request parameters.";
        case 429: return "Rate limit or quota exceeded - wait and retry, or check the plan.";
        default: break;
    }
    if (status >= 500) return "Provider-side error - try again later or switch provider.";
    return "";
}

/* Parses an HTTP response body. On success writes the assistant text (UTF-8)
 * to out and returns 1. On failure fills err and returns 0. */
static int kvai_parse_response(int status, const char *json, int provider,
                               char *out, size_t outLen, char *err, size_t errLen) {
    if (out && outLen) out[0] = '\0';
    if (err && errLen) err[0] = '\0';
    if (!json || !*json) {
        snprintf(err, errLen, "HTTP %d: empty response from provider.", status);
        return 0;
    }

    const char *choices = kvai_find_key(json, "choices");
    if (status >= 200 && status < 300 && choices) {
        const char *msg = kvai_find_key(choices, "message");
        const char *content = msg ? kvai_find_key(msg, "content") : NULL;
        if (content && *content == '"') {
            kvai_read_str(content, out, outLen);
            kvai_trim(out);
            if (out[0]) return 1;
        }
        char fin[40] = "unknown";
        const char *fr = kvai_find_key(choices, "finish_reason");
        if (fr && *fr == '"') kvai_read_str(fr, fin, sizeof(fin));
        int hasReasoning = msg && (kvai_find_key(msg, "reasoning_content") || kvai_find_key(msg, "reasoning"));
        snprintf(err, errLen,
            "Model returned an empty answer (finish_reason=%s)%s",
            fin,
            (hasReasoning || strcmp(fin, "length") == 0)
                ? ": a reasoning model used all tokens thinking - raise max tokens."
                : ".");
        return 0;
    }

    char msgbuf[256] = "";
    const char *e = kvai_find_key(json, "error");
    if (e && *e == '{') {
        const char *m = kvai_find_key(e, "message");
        if (m && *m == '"') kvai_read_str(m, msgbuf, sizeof(msgbuf));
    } else if (e && *e == '"') {
        kvai_read_str(e, msgbuf, sizeof(msgbuf));
    }
    if (!msgbuf[0]) {
        const char *keys[] = { "detail", "message", "title" };
        for (int i = 0; i < 3 && !msgbuf[0]; i++) {
            const char *m = kvai_find_key(json, keys[i]);
            if (m && *m == '"') kvai_read_str(m, msgbuf, sizeof(msgbuf));
        }
    }
    const char *hint = kvai_status_hint(status, provider);
    snprintf(err, errLen, "HTTP %d%s%s%s%s", status,
             msgbuf[0] ? ": " : "", msgbuf,
             hint[0] ? " - " : "", hint);
    return 0;
}

#endif /* KVAI_CORE_H */
