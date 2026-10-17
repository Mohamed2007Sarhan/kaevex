/*===========================================================================
 * Kaevex CVE Intelligence - cve_intel_core.h  (portable, no Windows deps)
 *
 *   installed app (name, publisher, version)
 *        + NVD CVE record (CPE ranges)     -> version-verified match + confidence
 *        + CISA KEV entry                  -> "actively exploited" flag / candidate source
 *   AI remediation plan                    -> strictly validated; the AI can only pick
 *                                             from a CLOSED list of actions and package IDs.
 *
 * A match is evidence, not proof: NVD CPE data can be incomplete, and product-name
 * matching is heuristic (a confidence level is always reported).
 *===========================================================================*/
#pragma once
#ifndef CVE_INTEL_CORE_H
#define CVE_INTEL_CORE_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "ai_core.h"          /* kvai_find_key / kvai_read_str / kvai_skip_str (JSON helpers) */
#ifdef _WIN32
#define _strnicmp_kv _strnicmp
#define _stricmp_kv  _stricmp
#else
#include <strings.h>
#define _strnicmp_kv strncasecmp
#define _stricmp_kv  strcasecmp
#endif

/* ---- Versions --------------------------------------------------------------------- */
typedef struct { long seg[10]; int n; } CviVer;

/* Digit groups only: "2.45.1.windows.1" -> 2,45,1,1 ; "v131.0.6778.205" -> 131,0,6778,205 */
static void cvi_ver_parse(const char *s, CviVer *v) {
    v->n = 0;
    while (s && *s && v->n < 10) {
        while (*s && !isdigit((unsigned char)*s)) s++;
        if (!*s) break;
        long x = 0; int d = 0;
        while (isdigit((unsigned char)*s)) { if (d < 9) x = x * 10 + (*s - '0'); d++; s++; }
        v->seg[v->n++] = x;
    }
}
static int cvi_ver_has_digits(const char *s) { for (; s && *s; s++) if (isdigit((unsigned char)*s)) return 1; return 0; }

static int cvi_ver_cmp(const char *a, const char *b) {
    CviVer x, y; cvi_ver_parse(a, &x); cvi_ver_parse(b, &y);
    int n = x.n > y.n ? x.n : y.n;
    for (int i = 0; i < n; i++) {
        long p = i < x.n ? x.seg[i] : 0, q = i < y.n ? y.seg[i] : 0;
        if (p < q) return -1;
        if (p > q) return 1;
    }
    return 0;
}

/* ---- CPE 2.3:  cpe:2.3:a:vendor:product:version:update:... (':' inside a field is "\:") ---- */
typedef struct { char part; char vendor[64]; char product[64]; char version[32]; } CviCpe;

static int cvi_cpe_parse(const char *cpe, CviCpe *o) {
    memset(o, 0, sizeof *o);
    if (!cpe || strncmp(cpe, "cpe:2.3:", 8) != 0) return 0;
    const char *p = cpe + 8; char *dst[4] = { NULL, o->vendor, o->product, o->version };
    size_t cap[4] = { 2, sizeof o->vendor, sizeof o->product, sizeof o->version };
    char part[2] = {0};
    dst[0] = part;
    for (int f = 0; f < 4; f++) {
        size_t w = 0;
        while (*p && *p != ':') {
            if (*p == '\\' && p[1]) p++;                 /* unescape */
            if (w + 1 < cap[f]) dst[f][w++] = *p;
            p++;
        }
        dst[f][w] = 0;
        if (*p == ':') p++; else if (f < 3) return 0;
    }
    o->part = part[0];
    if (strcmp(o->version, "*") == 0 || strcmp(o->version, "-") == 0) o->version[0] = 0;
    return 1;
}

/* ---- Name normalisation & token matching ------------------------------------------------- */
#define CVI_MAXTOK 24
typedef struct { char t[CVI_MAXTOK][24]; int n; } CviToks;

static int cvi_is_noise(const char *w) {
    static const char *noise[] = { "x64", "x86", "amd64", "arm64", "64", "32", "bit", "version", "update", "setup", "installer", "inc", "corporation", "corp",
        "ltd", "llc", "gmbh", "the", "for", "and", "of", "msi", "edition", "release", "stable", "beta", "preview", "current", "user", "system", "wide", "all", "users", NULL };
    for (int i = 0; noise[i]; i++) if (strcmp(w, noise[i]) == 0) return 1;
    return 0;
}
static int cvi_is_extra_ok(const char *w) {        /* suffix words that do not change the product identity */
    static const char *ok[] = { "desktop", "app", "client", "community", "enterprise", "professional", "pro", "standard", "lts", "personal", "free", "home", "business", "dc", "x", NULL };
    for (int i = 0; ok[i]; i++) if (strcmp(w, ok[i]) == 0) return 1;
    return 0;
}

/* Lowercase, split on non-alphanumerics, drop noise and version-looking tokens ("3.12.1", "2024", "23"). */
static void cvi_tokens(const char *s, CviToks *o) {
    o->n = 0; char cur[32]; int w = 0; int hadDot = 0;
    for (const char *p = s ? s : ""; ; p++) {
        unsigned char c = (unsigned char)*p;
        if (isalnum(c)) { if (w < 23) cur[w++] = (char)tolower(c); }
        else {
            if (c == '.' && w > 0 && isdigit((unsigned char)cur[0])) { hadDot = 1; if (w < 23) cur[w++] = '.'; continue; }
            if (w > 0) {
                cur[w] = 0;
                int allDigits = 1; for (int i = 0; i < w; i++) if (!isdigit((unsigned char)cur[i])) allDigits = 0;
                int verLike = hadDot || (allDigits && w >= 3);
                if (!verLike && !cvi_is_noise(cur) && o->n < CVI_MAXTOK) { strncpy(o->t[o->n], cur, 23); o->t[o->n][23] = 0; o->n++; }
            }
            w = 0; hadDot = 0;
            if (!c) break;
        }
    }
}

static int cvi_tok_eq(const char *a, const char *b) {
    if (strcmp(a, b) == 0) return 1;
    size_t la = strlen(a), lb = strlen(b), m = la < lb ? la : lb;
    if (m < 5) return 0;
    size_t i = 0; while (i < m && a[i] == b[i]) i++;
    return i >= 5 && i * 4 >= m * 3;                 /* chrome ~ chromium */
}
static int cvi_has_tok(const CviToks *s, const char *w) { for (int i = 0; i < s->n; i++) if (cvi_tok_eq(s->t[i], w)) return 1; return 0; }

enum { CVI_NO = 0, CVI_LOW = 1, CVI_MED = 2, CVI_HIGH = 3 };
static const char *cvi_conf_name(int c) { return c == CVI_HIGH ? "HIGH" : c == CVI_MED ? "MEDIUM" : c == CVI_LOW ? "LOW" : "NONE"; }

static int cvi_generic_product(const char *w) {
    static const char *g[] = { "windows", "server", "client", "tools", "agent", "manager", "sdk", "runtime", "framework", "driver", "studio", "office", "player", "viewer",
        "editor", "reader", "browser", "database", "core", "api", "service", "services", "management", "security", "network", "web", "cloud", NULL };
    for (int i = 0; g[i]; i++) if (strcmp(w, g[i]) == 0) return 1; return 0;
}

/* How well does CPE vendor:product describe the installed application?
 *   HIGH : all product tokens present, no unexplained extra words, vendor confirms
 *   MED  : product matches fully (multi-word) but vendor not confirmed, or one harmless extra word
 * Fixes classic false positives: "Visual Studio Code" is NOT cpe "visual_studio". */
static int cvi_name_match(const char *appName, const char *publisher, const char *cpeVendor, const char *cpeProduct) {
    CviToks A, Pub, V, P; char prod[64], ven[64];
    snprintf(prod, sizeof prod, "%s", cpeProduct); snprintf(ven, sizeof ven, "%s", cpeVendor);
    for (char *c = prod; *c; c++) if (*c == '_') *c = ' ';
    for (char *c = ven; *c; c++) if (*c == '_') *c = ' ';
    cvi_tokens(appName, &A); cvi_tokens(publisher, &Pub); cvi_tokens(ven, &V); cvi_tokens(prod, &P);
    if (P.n == 0 || A.n == 0) return CVI_NO;
    for (int i = 0; i < P.n; i++) if (!cvi_has_tok(&A, P.t[i])) {
        /* "edge_chromium" vs "Microsoft Edge": a trailing engine word may be absent from the app name */
        if (!(i == P.n - 1 && (strcmp(P.t[i], "chromium") == 0 || strcmp(P.t[i], "desktop") == 0) && P.n > 1)) return CVI_NO;
    }
    int vendorHit = 0;
    for (int i = 0; i < V.n; i++) if (cvi_has_tok(&A, V.t[i]) || cvi_has_tok(&Pub, V.t[i])) vendorHit = 1;
    /* unexplained words in the app name */
    int extras = 0;
    for (int i = 0; i < A.n; i++) {
        int explained = 0;
        for (int k = 0; k < P.n; k++) if (cvi_tok_eq(A.t[i], P.t[k])) explained = 1;
        for (int k = 0; k < V.n; k++) if (cvi_tok_eq(A.t[i], V.t[k])) explained = 1;
        if (!explained && !cvi_is_extra_ok(A.t[i])) extras++;
    }
    if (P.n == 1 && (cvi_generic_product(P.t[0]) || !vendorHit)) return extras == 0 && vendorHit ? CVI_MED : CVI_NO;
    if (extras > 0 && P.n >= 2) return CVI_NO;          /* extra word extends a multi-word product name: "Visual Studio Code" != "visual_studio" */
    if (extras > 1) return CVI_NO;
    if (extras == 1) return CVI_LOW;                    /* single-word product + one more word (edition/variant): weak */
    return vendorHit ? CVI_HIGH : CVI_MED;
}

/* CISA KEV vendorProject/product are human strings; use them only to propose CANDIDATES (NVD verifies). */
static int cvi_kev_candidate(const char *appName, const char *publisher, const char *kevVendor, const char *kevProduct) {
    CviToks A, K, Pub; char kv[200]; snprintf(kv, sizeof kv, "%s %s", kevVendor, kevProduct);
    cvi_tokens(appName, &A); cvi_tokens(kv, &K); cvi_tokens(publisher, &Pub);
    if (A.n == 0 || K.n == 0) return 0;
    int sig = 0, hit = 0;
    for (int i = 0; i < A.n; i++) {
        if (cvi_generic_product(A.t[i])) continue;
        sig++; if (cvi_has_tok(&K, A.t[i])) hit++;
    }
    if (sig == 0) return 0;
    if (hit < sig) return 0;
    CviToks KP; cvi_tokens(kevProduct, &KP);
    int prodHit = 0; for (int i = 0; i < A.n; i++) if (!cvi_generic_product(A.t[i]) && cvi_has_tok(&KP, A.t[i])) prodHit = 1;
    (void)Pub;
    return prodHit;
}

/* ---- JSON object iteration (string aware) ---------------------------------------------------- */
/* p points inside an array/object; finds next '{' at the current level and its matching '}'. */
static int cvi_next_object(const char **p, const char **start, const char **end) {
    const char *s = *p;
    while (*s && *s != '{' && *s != ']') { if (*s == '"') { const char *e = kvai_skip_str(s); if (!e) return 0; s = e; } else s++; }
    if (*s != '{') return 0;
    int depth = 0; const char *q = s;
    while (*q) {
        if (*q == '"') { const char *e = kvai_skip_str(q); if (!e) return 0; q = e; continue; }
        if (*q == '{') depth++;
        else if (*q == '}') { depth--; if (depth == 0) { *start = s; *end = q + 1; *p = q + 1; return 1; } }
        q++;
    }
    return 0;
}

static int cvi_str_in(const char *objStart, const char *objEnd, const char *key, char *out, size_t n) {
    out[0] = 0; size_t len = (size_t)(objEnd - objStart);
    char *tmp = (char *)malloc(len + 1); if (!tmp) return 0;
    memcpy(tmp, objStart, len); tmp[len] = 0;
    const char *v = kvai_find_key(tmp, key); int ok = 0;
    if (v && *v == '"') ok = kvai_read_str(v, out, n) >= 0;
    free(tmp); return ok;
}

/* ---- NVD 2.0 CVE records ---------------------------------------------------------------------- */
#define CVI_MAX_RANGES 12
typedef struct {
    char vendor[40], product[40];
    char exact[24];                     /* specific version in the CPE, "" if a range / all versions */
    char startInc[24], startExc[24], endInc[24], endExc[24];
} CviRange;

typedef struct {
    char id[24], published[12], severity[12];
    int  score10;                       /* CVSS base score x10 */
    int  kev, ransomware;
    char summary[240];
    int  nr; CviRange r[CVI_MAX_RANGES];
} CviCve;

/* obj = one element of "vulnerabilities": {"cve":{...}}; NUL-terminated. Returns 1 if an id was found. */
static int cvi_parse_nvd_cve(const char *obj, CviCve *c) {
    memset(c, 0, sizeof *c);
    const char *v = kvai_find_key(obj, "id");
    if (!v || *v != '"') return 0;
    kvai_read_str(v, c->id, sizeof c->id);
    if (strncmp(c->id, "CVE-", 4) != 0) return 0;
    v = kvai_find_key(obj, "published"); if (v && *v == '"') { char t[40]; kvai_read_str(v, t, sizeof t); snprintf(c->published, sizeof c->published, "%.10s", t); }
    /* english description */
    const char *d = kvai_find_key(obj, "descriptions");
    if (d && *d == '[') {
        const char *p = d + 1, *s, *e;
        while (cvi_next_object(&p, &s, &e)) {
            char lang[8], val[400];
            if (cvi_str_in(s, e, "lang", lang, sizeof lang) && strcmp(lang, "en") == 0 && cvi_str_in(s, e, "value", val, sizeof val)) { snprintf(c->summary, sizeof c->summary, "%s", val); break; }
        }
    }
    /* score: v3.1 -> v3.0 -> v4.0 -> v2 */
    static const char *metrics[] = { "cvssMetricV31", "cvssMetricV30", "cvssMetricV40", "cvssMetricV2", NULL };
    for (int m = 0; metrics[m] && !c->score10; m++) {
        const char *mv = kvai_find_key(obj, metrics[m]);
        if (!mv || *mv != '[') continue;
        const char *bs = kvai_find_key(mv, "baseScore");
        if (bs) { double sc = atof(bs); c->score10 = (int)(sc * 10.0 + 0.5); }
        const char *sv = kvai_find_key(mv, "baseSeverity"); if (sv && *sv == '"') kvai_read_str(sv, c->severity, sizeof c->severity);
    }
    if (!c->severity[0] && c->score10) snprintf(c->severity, sizeof c->severity, "%s", c->score10 >= 90 ? "CRITICAL" : c->score10 >= 70 ? "HIGH" : c->score10 >= 40 ? "MEDIUM" : "LOW");
    /* configurations -> every cpeMatch element */
    const char *cfg = kvai_find_key(obj, "configurations");
    const char *scan = cfg;
    while (scan && c->nr < CVI_MAX_RANGES) {
        const char *cm = kvai_find_key(scan, "cpeMatch");
        if (!cm || *cm != '[') break;
        const char *p = cm + 1, *s, *e;
        while (c->nr < CVI_MAX_RANGES && cvi_next_object(&p, &s, &e)) {
            char crit[200], vuln[8] = "true"; CviCpe cpe;
            if (!cvi_str_in(s, e, "criteria", crit, sizeof crit)) continue;
            size_t len = (size_t)(e - s); char *tmp = (char *)malloc(len + 1); if (!tmp) break; memcpy(tmp, s, len); tmp[len] = 0;
            const char *vv = kvai_find_key(tmp, "vulnerable"); if (vv && strncmp(vv, "false", 5) == 0) { free(tmp); continue; }
            free(tmp);
            if (!cvi_cpe_parse(crit, &cpe) || cpe.part != 'a') continue;          /* applications only */
            CviRange *r = &c->r[c->nr];
            memset(r, 0, sizeof *r);
            snprintf(r->vendor, sizeof r->vendor, "%s", cpe.vendor); snprintf(r->product, sizeof r->product, "%s", cpe.product);
            snprintf(r->exact, sizeof r->exact, "%s", cpe.version);
            cvi_str_in(s, e, "versionStartIncluding", r->startInc, sizeof r->startInc);
            cvi_str_in(s, e, "versionStartExcluding", r->startExc, sizeof r->startExc);
            cvi_str_in(s, e, "versionEndIncluding", r->endInc, sizeof r->endInc);
            cvi_str_in(s, e, "versionEndExcluding", r->endExc, sizeof r->endExc);
            (void)vuln; c->nr++;
        }
        scan = p;                                                            /* continue after this array */
    }
    return 1;
}

/* Is `installed` inside the range? Returns 1 affected, 0 not affected, -1 unknown (no usable installed version). */
static int cvi_affects(const char *installed, const CviRange *r) {
    if (!cvi_ver_has_digits(installed)) return -1;
    if (r->exact[0]) return cvi_ver_cmp(installed, r->exact) == 0;
    if (r->startInc[0] && cvi_ver_cmp(installed, r->startInc) < 0) return 0;
    if (r->startExc[0] && cvi_ver_cmp(installed, r->startExc) <= 0) return 0;
    if (r->endInc[0] && cvi_ver_cmp(installed, r->endInc) > 0) return 0;
    if (r->endExc[0] && cvi_ver_cmp(installed, r->endExc) >= 0) return 0;
    return 1;
}

typedef struct { int conf; char fixed[32]; int allVersions; int rangeIdx; } CviHit;

/* Does this CVE (verified by CPE + version range) apply to the installed app? Returns confidence (0 = no). */
static int cvi_match(const CviCve *c, const char *appName, const char *publisher, const char *installed, CviHit *hit) {
    memset(hit, 0, sizeof *hit); hit->rangeIdx = -1;
    int best = CVI_NO;
    for (int i = 0; i < c->nr; i++) {
        const CviRange *r = &c->r[i];
        int nm = cvi_name_match(appName, publisher, r->vendor, r->product);
        if (nm == CVI_NO) continue;
        if (cvi_affects(installed, r) != 1) continue;
        int all = !r->exact[0] && !r->startInc[0] && !r->startExc[0] && !r->endInc[0] && !r->endExc[0];
        int conf = all ? (nm > CVI_LOW ? CVI_LOW : nm) : nm;      /* "all versions" ranges are weak evidence */
        if (conf > best) { best = conf; hit->rangeIdx = i; hit->allVersions = all; snprintf(hit->fixed, sizeof hit->fixed, "%s", r->endExc); }
        else if (conf == best && r->endExc[0] && (!hit->fixed[0] || cvi_ver_cmp(r->endExc, hit->fixed) < 0)) snprintf(hit->fixed, sizeof hit->fixed, "%s", r->endExc);
    }
    hit->conf = best; return best;
}

/* ---- CISA KEV --------------------------------------------------------------------------------------------- */
typedef struct { char cve[24], vendor[64], product[96], name[160], added[12], action[200]; int ransomware; } CviKev;

static int cvi_parse_kev(const char *json, CviKev *out, int maxN) {
    const char *arr = kvai_find_key(json, "vulnerabilities"); if (!arr || *arr != '[') return 0;
    const char *p = arr + 1, *s, *e; int n = 0;
    while (n < maxN && cvi_next_object(&p, &s, &e)) {
        CviKev *k = &out[n]; memset(k, 0, sizeof *k); char ran[16] = "";
        if (!cvi_str_in(s, e, "cveID", k->cve, sizeof k->cve) || strncmp(k->cve, "CVE-", 4) != 0) continue;
        cvi_str_in(s, e, "vendorProject", k->vendor, sizeof k->vendor); cvi_str_in(s, e, "product", k->product, sizeof k->product);
        cvi_str_in(s, e, "vulnerabilityName", k->name, sizeof k->name); cvi_str_in(s, e, "dateAdded", k->added, sizeof k->added);
        cvi_str_in(s, e, "requiredAction", k->action, sizeof k->action); cvi_str_in(s, e, "knownRansomwareCampaignUse", ran, sizeof ran);
        k->ransomware = _stricmp_kv(ran, "Known") == 0; n++;
    }
    return n;
}

/* ---- AI remediation plan: validated, closed-world -------------------------------------------------------------- */
enum { CVI_ACT_NONE = 0, CVI_ACT_UPGRADE = 1, CVI_ACT_CONTAIN = 2, CVI_ACT_MANUAL = 3 };
typedef struct {
    int  action;
    char wingetId[100];
    char reason[220];
    char steps[3][160]; int nsteps;
    int  fromAi;               /* 1 = plan came from the model, 0 = deterministic fallback */
} CviPlan;

static const char *cvi_action_name(int a) { return a == CVI_ACT_UPGRADE ? "UPGRADE_WINGET" : a == CVI_ACT_CONTAIN ? "CONTAIN_NETWORK" : a == CVI_ACT_MANUAL ? "MANUAL" : "NONE"; }

/* Publisher.Package[.Sub] - letters, digits, + _ - and single dots only. */
static int cvi_valid_winget_id(const char *id) {
    size_t n = id ? strlen(id) : 0;
    if (n < 3 || n > 99) return 0;
    int dots = 0;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)id[i];
        if (c == '.') { if (i == 0 || i == n - 1 || id[i - 1] == '.') return 0; dots++; }
        else if (!(isalnum(c) || c == '+' || c == '_' || c == '-')) return 0;
    }
    return dots >= 1;
}

/* Extract the JSON object from model text (it may add prose or ```json fences). */
static int cvi_extract_json(const char *text, char *out, size_t n) {
    const char *a = strchr(text, '{'); if (!a) return 0;
    const char *b = strrchr(text, '}'); if (!b || b < a) return 0;
    size_t len = (size_t)(b - a) + 1; if (len >= n) return 0;
    memcpy(out, a, len); out[len] = 0; return 1;
}

/* allowedIds: closed list the model was shown. Anything else is rejected -> MANUAL. */
static int cvi_parse_plan(const char *aiText, char (*allowedIds)[100], int nAllowed, CviPlan *pl) {
    memset(pl, 0, sizeof *pl); pl->action = CVI_ACT_MANUAL; pl->fromAi = 1;
    char *js = (char *)malloc(strlen(aiText) + 2); if (!js) return 0;
    if (!cvi_extract_json(aiText, js, strlen(aiText) + 2)) { snprintf(pl->reason, sizeof pl->reason, "AI did not return a JSON plan"); free(js); return 0; }
    char act[40] = "", id[100] = "";
    const char *v = kvai_find_key(js, "action"); if (v && *v == '"') kvai_read_str(v, act, sizeof act);
    v = kvai_find_key(js, "winget_id"); if (v && *v == '"') kvai_read_str(v, id, sizeof id);
    v = kvai_find_key(js, "reason"); if (v && *v == '"') kvai_read_str(v, pl->reason, sizeof pl->reason);
    v = kvai_find_key(js, "steps");
    if (v && *v == '[') {
        const char *p = v + 1;
        while (pl->nsteps < 3) { while (*p == ' ' || *p == ',' || *p == '\n' || *p == '\r' || *p == '\t') p++; if (*p != '"') break;
            kvai_read_str(p, pl->steps[pl->nsteps], sizeof pl->steps[0]); pl->nsteps++; const char *e = kvai_skip_str(p); if (!e) break; p = e; }
    }
    int ok = 1;
    if (_stricmp_kv(act, "UPGRADE_WINGET") == 0) {
        int allowed = 0; for (int i = 0; i < nAllowed; i++) if (strcmp(allowedIds[i], id) == 0) allowed = 1;
        if (cvi_valid_winget_id(id) && allowed) { pl->action = CVI_ACT_UPGRADE; snprintf(pl->wingetId, sizeof pl->wingetId, "%s", id); }
        else { pl->action = CVI_ACT_MANUAL; snprintf(pl->reason, sizeof pl->reason, "AI proposed package '%.60s' which is not one of the installed winget packages offered - rejected", id); ok = 0; }
    } else if (_stricmp_kv(act, "CONTAIN_NETWORK") == 0) pl->action = CVI_ACT_CONTAIN;
    else if (_stricmp_kv(act, "NONE") == 0) pl->action = CVI_ACT_NONE;
    else if (_stricmp_kv(act, "MANUAL") == 0) pl->action = CVI_ACT_MANUAL;
    else { pl->action = CVI_ACT_MANUAL; snprintf(pl->reason, sizeof pl->reason, "AI proposed an unknown action '%.40s' - rejected", act); ok = 0; }
    free(js); return ok;
}

/* ---- winget export (installed package identifiers) + candidate selection ------------------------------------------- */
static int cvi_parse_winget_export(const char *json, char (*ids)[100], int maxN) {
    int n = 0; const char *p = json;
    while (n < maxN) {
        const char *v = kvai_find_key(p, "PackageIdentifier"); if (!v || *v != '"') break;
        char id[100]; kvai_read_str(v, id, sizeof id);
        if (cvi_valid_winget_id(id)) { int dup = 0; for (int i = 0; i < n; i++) if (strcmp(ids[i], id) == 0) dup = 1; if (!dup) snprintf(ids[n++], 100, "%s", id); }
        const char *e = kvai_skip_str(v); if (!e) break; p = e;
    }
    return n;
}

static int cvi_joined_eq(const CviToks *A, const char *tok) {
    for (int i = 0; i < A->n; i++) {
        char cat[96] = "";
        for (int j = i; j < A->n && j < i + 3; j++) { strncat(cat, A->t[j], sizeof cat - strlen(cat) - 1); if (j > i && strcmp(cat, tok) == 0) return 1; }
    }
    return 0;
}

/* Up to maxOut installed winget IDs whose words overlap the app name/publisher, best first. */
static int cvi_candidates(const char *appName, const char *publisher, char (*ids)[100], int nIds, char (*out)[100], int maxOut) {
    CviToks A, Pub; cvi_tokens(appName, &A); cvi_tokens(publisher, &Pub);
    int score[64]; int idx[64]; int m = 0;
    for (int i = 0; i < nIds && m < 64; i++) {
        char tmp[100]; snprintf(tmp, sizeof tmp, "%s", ids[i]); for (char *c = tmp; *c; c++) if (*c == '.' || *c == '-' || *c == '_' || *c == '+') *c = ' ';
        CviToks T; cvi_tokens(tmp, &T); int sc = 0, appHits = 0;
        for (int k = 0; k < T.n; k++) { if ((cvi_has_tok(&A, T.t[k]) || cvi_joined_eq(&A, T.t[k])) && !cvi_generic_product(T.t[k])) { sc += 2; appHits++; } else if (cvi_has_tok(&Pub, T.t[k])) sc += 1; }
        if (appHits >= 1 && sc >= 2) { score[m] = sc; idx[m] = i; m++; }
    }
    for (int i = 0; i < m; i++) for (int j = i + 1; j < m; j++) if (score[j] > score[i]) { int t = score[i]; score[i] = score[j]; score[j] = t; t = idx[i]; idx[i] = idx[j]; idx[j] = t; }
    int n = m < maxOut ? m : maxOut;
    for (int i = 0; i < n; i++) snprintf(out[i], 100, "%s", ids[idx[i]]);
    return n;
}

/* Deterministic plan used when no AI answer is available. */
static void cvi_fallback_plan(int havePath, int kev, char (*cands)[100], int nc, CviPlan *pl) {
    memset(pl, 0, sizeof *pl); pl->fromAi = 0;
    if (nc == 1) { pl->action = CVI_ACT_UPGRADE; snprintf(pl->wingetId, sizeof pl->wingetId, "%s", cands[0]); snprintf(pl->reason, sizeof pl->reason, "Single winget-managed package matches this application."); }
    else if (nc > 1) { pl->action = CVI_ACT_MANUAL; snprintf(pl->reason, sizeof pl->reason, "Several winget packages could match; pick one manually."); }
    else if (kev && havePath) { pl->action = CVI_ACT_CONTAIN; snprintf(pl->reason, sizeof pl->reason, "Actively exploited and no winget package found: block the app's network access until patched."); }
    else { pl->action = CVI_ACT_MANUAL; snprintf(pl->reason, sizeof pl->reason, "No automatic fix available; update from the vendor."); }
}

#endif /* CVE_INTEL_CORE_H */
