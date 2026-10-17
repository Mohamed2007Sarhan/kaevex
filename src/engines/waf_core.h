/*===========================================================================
 * Kaevex WAF - waf_core.h  (portable C, no dependencies)
 *
 * Inspects an HTTP request (URI, query, headers, body) and returns a verdict.
 *
 * Pipeline
 *   1. split the request into inspection targets (path, each query/form parameter, each header, body)
 *   2. normalise every target against evasion: repeated URL-decoding (%xx, %uxxxx), '+', HTML entities
 *      (&lt; &#60; &#x3c;), \xNN and \uNNNN escapes, NUL removal, SQL inline comments (also MySQL versioned ones),
 *      whitespace folding, case folding
 *   3. run category detectors on the normalised text, each with a score, CWE and MITRE ATT&CK id
 *   4. combine the scores; block above a threshold chosen by the paranoia level (1 low .. 3 strict)
 *
 * Categories: SQLi, XSS, XXE (+XML bombs), path traversal, LFI/RFI, command injection, SSRF, SSTI, NoSQLi, LDAPi,
 * XPath injection, CRLF/header injection, Log4Shell/JNDI, Shellshock, OGNL/Struts/Spring4Shell, deserialization
 * (Java/PHP/.NET), prototype pollution, webshell upload, sensitive-file probing, scanner fingerprints,
 * request-smuggling/protocol anomalies, encoding evasion, oversize/DoS, open redirect, GraphQL abuse.
 *
 * It is signature + heuristic based: it blocks the known classes of attack on the traffic that passes through it,
 * it does not replace secure coding, and a determined attacker may find an unlisted bypass.
 *===========================================================================*/
#pragma once
#ifndef WAF_CORE_H
#define WAF_CORE_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#ifdef _WIN32
#define waf_strncasecmp _strnicmp
#else
#include <strings.h>
#define waf_strncasecmp strncasecmp
#endif

#define WAF_MAX_HITS 24
typedef struct { char rule[12]; char name[44]; char cat[28]; char cwe[10]; char mitre[12]; int score; char snippet[80]; } WafHit;
typedef struct {
    int  score;                 /* 0..100 */
    int  blocked;
    int  paranoia;
    int  nhits;
    WafHit hits[WAF_MAX_HITS];
    char top[28];               /* category of the highest-scoring hit */
    const char *severity;       /* Clean / Low / Medium / High / Critical */
    int  evasion;               /* number of decoding rounds that changed the data (>1 = double encoding) */
} WafVerdict;

typedef struct {
    const char *method;
    const char *uri;            /* raw request target incl. query */
    const char *headers;        /* "Name: value\n" lines (no request line) */
    const unsigned char *body;  size_t bodyLen;
} WafRequest;

/* ---- helpers -------------------------------------------------------------------------------------------- */
static int waf_hexv(int c) { return isdigit(c) ? c - '0' : (c >= 'a' && c <= 'f') ? c - 'a' + 10 : (c >= 'A' && c <= 'F') ? c - 'A' + 10 : -1; }

static int waf_put_cp(unsigned cp, char *o, size_t cap, size_t *w) {
    if (cp == 0) return 1;                         /* NUL bytes are dropped (classic filter bypass) */
    if (cp < 0x80) { if (*w + 1 < cap) o[(*w)++] = (char)cp; }
    else if (cp < 0x800) { if (*w + 2 < cap) { o[(*w)++] = (char)(0xC0 | (cp >> 6)); o[(*w)++] = (char)(0x80 | (cp & 63)); } }
    else if (cp < 0x10000) { if (*w + 3 < cap) { o[(*w)++] = (char)(0xE0 | (cp >> 12)); o[(*w)++] = (char)(0x80 | ((cp >> 6) & 63)); o[(*w)++] = (char)(0x80 | (cp & 63)); } }
    return 1;
}

/* one decoding round; returns 1 if anything changed */
static int waf_decode_round(const char *in, size_t n, char *out, size_t cap, size_t *outLen, int plusIsSpace) {
    size_t w = 0; int changed = 0;
    for (size_t i = 0; i < n && w + 4 < cap; i++) {
        unsigned char c = (unsigned char)in[i];
        if (c == '%' && i + 2 < n + 0 && waf_hexv((unsigned char)in[i + 1]) >= 0 && waf_hexv((unsigned char)in[i + 2]) >= 0) { unsigned v = (unsigned)(waf_hexv((unsigned char)in[i + 1]) * 16 + waf_hexv((unsigned char)in[i + 2])); waf_put_cp(v, out, cap, &w); i += 2; changed = 1; }
        else if (c == '%' && i + 5 < n + 0 && (in[i + 1] == 'u' || in[i + 1] == 'U') && waf_hexv((unsigned char)in[i + 2]) >= 0 && waf_hexv((unsigned char)in[i + 3]) >= 0 && waf_hexv((unsigned char)in[i + 4]) >= 0 && waf_hexv((unsigned char)in[i + 5]) >= 0) {
            unsigned v = (unsigned)((waf_hexv((unsigned char)in[i + 2]) << 12) | (waf_hexv((unsigned char)in[i + 3]) << 8) | (waf_hexv((unsigned char)in[i + 4]) << 4) | waf_hexv((unsigned char)in[i + 5]));
            if (v >= 0xFF00 && v <= 0xFF5E) v -= 0xFEE0;                      /* full-width forms -> ASCII */
            waf_put_cp(v, out, cap, &w); i += 5; changed = 1; }
        else if (c == '+' && plusIsSpace) { out[w++] = ' '; changed = 1; }
        else if (c == '&' && i + 3 < n) {
            size_t j = i + 1; unsigned v = 0; int ok = 0;
            if (in[j] == '#') { j++; int hex = (in[j] == 'x' || in[j] == 'X'); if (hex) j++; size_t st = j; while (j < n && j - st < 8 && (hex ? waf_hexv((unsigned char)in[j]) >= 0 : isdigit((unsigned char)in[j]))) { v = v * (hex ? 16 : 10) + (unsigned)(hex ? waf_hexv((unsigned char)in[j]) : in[j] - '0'); j++; } if (j > st) { if (j < n && in[j] == ';') j++; ok = 1; } }
            else { static const struct { const char *n; unsigned v; } ent[] = { {"lt;", '<'}, {"gt;", '>'}, {"amp;", '&'}, {"quot;", '"'}, {"apos;", '\''}, {"tab;", '\t'}, {"newline;", '\n'}, {"colon;", ':'}, {"lpar;", '('}, {"rpar;", ')'}, {"sol;", '/'}, {"bsol;", '\\'}, {"equals;", '='}, {"semi;", ';'}, {"num;", '#'}, {"percnt;", '%'} };
                   for (unsigned e = 0; e < sizeof ent / sizeof *ent; e++) { size_t l = strlen(ent[e].n); if (j + l <= n) { int eq = 1; for (size_t k = 0; k < l; k++) if (tolower((unsigned char)in[j + k]) != ent[e].n[k]) { eq = 0; break; } if (eq) { v = ent[e].v; j += l; ok = 1; break; } } } }
            if (ok && v < 0x110000) { waf_put_cp(v, out, cap, &w); i = j - 1; changed = 1; } else out[w++] = (char)c;
        }
        else if (c == '\\' && i + 3 < n && (in[i + 1] == 'x' || in[i + 1] == 'X') && waf_hexv((unsigned char)in[i + 2]) >= 0 && waf_hexv((unsigned char)in[i + 3]) >= 0) { waf_put_cp((unsigned)(waf_hexv((unsigned char)in[i + 2]) * 16 + waf_hexv((unsigned char)in[i + 3])), out, cap, &w); i += 3; changed = 1; }
        else if (c == '\\' && i + 5 < n && (in[i + 1] == 'u' || in[i + 1] == 'U') && waf_hexv((unsigned char)in[i + 2]) >= 0 && waf_hexv((unsigned char)in[i + 3]) >= 0 && waf_hexv((unsigned char)in[i + 4]) >= 0 && waf_hexv((unsigned char)in[i + 5]) >= 0) {
            unsigned v = (unsigned)((waf_hexv((unsigned char)in[i + 2]) << 12) | (waf_hexv((unsigned char)in[i + 3]) << 8) | (waf_hexv((unsigned char)in[i + 4]) << 4) | waf_hexv((unsigned char)in[i + 5])); waf_put_cp(v, out, cap, &w); i += 5; changed = 1; }
        else if (c == 0) { changed = 1; }
        else out[w++] = (char)c;
    }
    out[w] = 0; *outLen = w; return changed;
}

/* Full normalisation. out is lowercase, SQL comments removed, whitespace folded. */
static size_t waf_normalize2(const char *in, size_t n, char *out, size_t cap, int plusIsSpace, int *rounds, char *out2, size_t *len2) {
    size_t cap2 = cap < (1 << 18) ? cap : (1 << 18) - 8; char *x = (char *)malloc(cap2 + 8), *y = (char *)malloc(cap2 + 8); if (!x || !y) { free(x); free(y); out[0] = 0; return 0; }
    size_t xl = n < cap2 ? n : cap2; memcpy(x, in, xl); x[xl] = 0; int r = 0;
    for (int pass = 0; pass < 5; pass++) { size_t yl; int ch = waf_decode_round(x, xl, y, cap2, &yl, plusIsSpace && pass == 0); if (!ch) break; r++; char *t = x; x = y; y = t; xl = yl; }
    if (rounds) *rounds = r;
    size_t w = 0, w2 = 0; int lastSp = 1, lastSp2 = 1;
    for (size_t i = 0; i < xl && w + 2 < cap; i++) {
        unsigned char c = (unsigned char)x[i];
        if (c == '/' && i + 1 < xl && x[i + 1] == '*') {                       /* SQL comment */
            size_t j = i + 2; int ver = (j < xl && x[j] == '!'); if (ver) { j++; while (j < xl && isdigit((unsigned char)x[j])) j++; }
            size_t e = j; while (e + 1 < xl && !(x[e] == '*' && x[e + 1] == '/')) e++;
            if (ver) { for (size_t k = j; k < e && w + 2 < cap; k++) { out[w++] = (char)tolower((unsigned char)x[k]); if (out2) out2[w2++] = (char)tolower((unsigned char)x[k]); } lastSp = lastSp2 = 0; }
            else { if (!lastSp && w + 2 < cap) { out[w++] = ' '; lastSp = 1; } }
            i = (e + 1 < xl) ? e + 1 : xl; continue; }
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\v' || c == '\f' || c == 0xA0) { if (!lastSp) { out[w++] = ' '; lastSp = 1; } if (out2 && !lastSp2) { out2[w2++] = ' '; lastSp2 = 1; } continue; }
        out[w++] = (char)tolower(c); lastSp = 0; if (out2) { out2[w2++] = (char)tolower(c); lastSp2 = 0; }
    }
    out[w] = 0; if (out2) { out2[w2] = 0; if (len2) *len2 = w2; } free(x); free(y); return w;
}
static size_t waf_normalize(const char *in, size_t n, char *out, size_t cap, int plusIsSpace, int *rounds) { return waf_normalize2(in, n, out, cap, plusIsSpace, rounds, NULL, NULL); }

/* ---- matching helpers -------------------------------------------------------------------------------------- */
static const char *waf_has(const char *h, const char *needle) { return strstr(h, needle); }
static int waf_hasany(const char *h, const char *const *list, const char **which) { for (int i = 0; list[i]; i++) if (strstr(h, list[i])) { if (which) *which = list[i]; return 1; } return 0; }
static int waf_isword(int c) { return isalnum(c) || c == '_'; }
/* needle present as a whole word */
static const char *waf_word(const char *h, const char *needle) { size_t l = strlen(needle); for (const char *p = h; (p = strstr(p, needle)); p++) { int lb = p == h || !waf_isword((unsigned char)p[-1]); int rb = !waf_isword((unsigned char)p[l]); if (lb && rb) return p; } return NULL; }

static void waf_hit(WafVerdict *v, const char *rule, const char *name, const char *cat, const char *cwe, const char *mitre, int score, const char *snip) {
    for (int i = 0; i < v->nhits; i++) if (!strcmp(v->hits[i].rule, rule)) { if (score > v->hits[i].score) v->hits[i].score = score; return; }
    if (v->nhits >= WAF_MAX_HITS) return; WafHit *h = &v->hits[v->nhits++];
    snprintf(h->rule, sizeof h->rule, "%s", rule); snprintf(h->name, sizeof h->name, "%s", name); snprintf(h->cat, sizeof h->cat, "%s", cat); snprintf(h->cwe, sizeof h->cwe, "%s", cwe); snprintf(h->mitre, sizeof h->mitre, "%s", mitre); h->score = score;
    size_t k = 0; if (snip) for (; snip[k] && k < sizeof h->snippet - 1; k++) h->snippet[k] = (unsigned char)snip[k] < 0x20 ? ' ' : snip[k]; h->snippet[k] = 0;
}

/* ---- detectors ---------------------------------------------------------------------------------------------------- */
/* ' or 1=1 / " or "a"="a" / and 5>3 : parses  (or|and|||&&) <operand> <op> <operand>  with equal / always-true operands */
static int waf_sqli_tautology(const char *s, char *snip, size_t sn) {
    for (const char *p = s; *p; p++) {
        const char *q = NULL;
        if ((p == s || !waf_isword((unsigned char)p[-1])) && (!strncmp(p, "or ", 3) || !strncmp(p, "and ", 4))) q = p + (p[0] == 'o' ? 3 : 4);
        else if (!strncmp(p, "||", 2) || !strncmp(p, "&&", 2)) q = p + 2;
        if (!q) continue;
        while (*q == ' ' || *q == '(') q++;
        char l1[40] = "", l2[40] = ""; int quote = 0;
        if (*q == '\'' || *q == '"') { quote = *q; q++; }
        size_t k = 0; while (*q && *q != quote && (waf_isword((unsigned char)*q) || (!quote && *q == '.')) && k < 38) l1[k++] = *q++; l1[k] = 0;
        if (quote) { if (*q == quote) q++; else continue; }
        while (*q == ' ') q++;
        const char *op = NULL; int oplen = 0;
        if (!strncmp(q, "<>", 2) || !strncmp(q, "!=", 2) || !strncmp(q, ">=", 2) || !strncmp(q, "<=", 2)) { op = q; oplen = 2; }
        else if (*q == '=' || *q == '<' || *q == '>') { op = q; oplen = 1; }
        else if (!strncmp(q, "like ", 5)) { op = q; oplen = 4; }
        if (!op || !l1[0]) continue;
        q += oplen; while (*q == ' ') q++;
        int quote2 = 0; if (*q == '\'' || *q == '"') { quote2 = *q; q++; }
        k = 0; while (*q && *q != quote2 && (waf_isword((unsigned char)*q) || (!quote2 && *q == '.')) && k < 38) l2[k++] = *q++; l2[k] = 0;
        if (!l2[0] && !quote2) continue;
        int same = !strcmp(l1, l2); int num1 = isdigit((unsigned char)l1[0]), num2 = l2[0] && isdigit((unsigned char)l2[0]);
        int truth = (oplen == 1 && *op == '=' && same) || (oplen == 4 && same) || (num1 && num2 && ((*op == '>' && oplen == 1 && atol(l1) > atol(l2)) || (*op == '<' && oplen == 1 && atol(l1) < atol(l2)) || (!strncmp(op, "<>", 2) && atol(l1) != atol(l2)) || (!strncmp(op, "!=", 2) && atol(l1) != atol(l2))));
        if (truth) { snprintf(snip, sn, "%.30s", p); return 1; }
    }
    return 0;
}

static void waf_check_sqli(const char *s, WafVerdict *v) {
    char snip[80]; static const char *union_pats[] = { "union select", "union all select", "union distinct select", "union (select", "union/**/select", NULL }; const char *w = NULL;
    if (waf_hasany(s, union_pats, &w)) waf_hit(v, "SQLI-01", "UNION-based injection", "SQL Injection", "CWE-89", "T1190", 90, w);
    if (waf_sqli_tautology(s, snip, sizeof snip)) { int quoted = strchr(s, '\'') || strchr(s, '"') || strstr(s, "--") || strstr(s, "#"); waf_hit(v, "SQLI-02", "Boolean tautology", "SQL Injection", "CWE-89", "T1190", quoted ? 85 : 55, snip); }
    static const char *time_pats[] = { "sleep(", "benchmark(", "pg_sleep(", "waitfor delay", "waitfor time", "dbms_pipe.receive_message", "dbms_lock.sleep", "randomblob(", "generate_series(", NULL };
    if (waf_hasany(s, time_pats, &w)) waf_hit(v, "SQLI-03", "Time-based blind injection", "SQL Injection", "CWE-89", "T1190", 85, w);
    static const char *err_pats[] = { "extractvalue(", "updatexml(", "exp(~(", "convert(int,", "cast((select", "geometrycollection(", "multipoint(", "ctxsys.drithsx", "utl_inaddr", "xmltype(", "floor(rand(", NULL };
    if (waf_hasany(s, err_pats, &w)) waf_hit(v, "SQLI-04", "Error-based injection", "SQL Injection", "CWE-89", "T1190", 85, w);
    static const char *meta[] = { "information_schema", "sysobjects", "syscolumns", "pg_catalog", "sqlite_master", "all_tables", "mysql.user", "sys.databases", "master..", "xp_cmdshell", "sp_executesql", "sp_oacreate", "load_file(", "into outfile", "into dumpfile", "utl_file", "copy (select", "pg_read_file", NULL };
    if (waf_hasany(s, meta, &w)) waf_hit(v, "SQLI-05", "Database metadata / file access", "SQL Injection", "CWE-89", "T1190", 80, w);
    if (strstr(s, "select ") && strstr(s, " from ") && (strchr(s, '\'') || strstr(s, "--") || strstr(s, "(select") || strstr(s, ") from"))) {
        const char *sel = strstr(s, "select "); if (strstr(sel, " from ")) waf_hit(v, "SQLI-06", "Inline subquery", "SQL Injection", "CWE-89", "T1190", 60, sel);
    }
    static const char *stack[] = { "; drop ", ";drop ", "; delete from", "; insert into", "; update ", "; exec ", ";exec ", "; shutdown", "; truncate ", "; alter ", "; create user", "; grant ", "'; ", "\"; ", NULL };
    for (int i = 0; stack[i]; i++) if (strstr(s, stack[i])) { const char *p = strstr(s, stack[i]); int dang = i < 12; if (dang || strstr(p, "--") || strstr(p, "select") || strstr(p, "drop") || strstr(p, "insert")) { waf_hit(v, "SQLI-07", "Stacked queries", "SQL Injection", "CWE-89", "T1190", dang ? 90 : 55, p); break; } }
    if (strstr(s, "'--") || strstr(s, "'#") || strstr(s, "' --") || strstr(s, "\"--") || strstr(s, "');--") || strstr(s, "'/*")) waf_hit(v, "SQLI-08", "Quote + comment truncation", "SQL Injection", "CWE-89", "T1190", 70, "'--");
    if ((strstr(s, " order by ") || strstr(s, " group by ")) && (strstr(s, "--") || strstr(s, "'"))) { const char *o = strstr(s, "order by "); if (o && isdigit((unsigned char)o[9])) waf_hit(v, "SQLI-09", "Column enumeration (ORDER BY n)", "SQL Injection", "CWE-89", "T1190", 65, o); }
    if (strstr(s, "case when") && (strstr(s, " then ") || strstr(s, "(select"))) waf_hit(v, "SQLI-10", "Conditional blind injection", "SQL Injection", "CWE-89", "T1190", 70, "case when");
    if (strstr(s, "0x") && strstr(s, "select")) { const char *z = strstr(s, "0x"); if (waf_hexv((unsigned char)z[2]) >= 0 && waf_hexv((unsigned char)z[3]) >= 0) waf_hit(v, "SQLI-11", "Hex-encoded literal in query", "SQL Injection", "CWE-89", "T1190", 60, z); }
    if (strstr(s, "char(") && strstr(s, "concat")) waf_hit(v, "SQLI-12", "CHAR()/CONCAT obfuscation", "SQL Injection", "CWE-89", "T1190", 65, "char(");
    if ((strstr(s, "' or ") || strstr(s, "\" or ") || strstr(s, "' and ") || strstr(s, "') or ") || strstr(s, "') and ")) && (strstr(s, "--") || strstr(s, "'") )) { const char *p = strstr(s, "' or "); if (!p) p = strstr(s, "\" or "); if (!p) p = strstr(s, "' and "); if (!p) p = strstr(s, "') or "); if (!p) p = strstr(s, "') and "); if (strchr(p + 1, '=') || strstr(p, "like") || strstr(p, "--")) waf_hit(v, "SQLI-13", "Quote-break boolean clause", "SQL Injection", "CWE-89", "T1190", 70, p); }
    if (strstr(s, "having ") && strstr(s, " group by")) waf_hit(v, "SQLI-14", "HAVING/GROUP BY probing", "SQL Injection", "CWE-89", "T1190", 55, "having");
    if (strstr(s, "procedure analyse(") || strstr(s, "@@version") || (strstr(s, "version()") && strstr(s, "select"))) waf_hit(v, "SQLI-15", "Fingerprinting (version/analyse)", "SQL Injection", "CWE-89", "T1190", 60, "version");
    if (strstr(s, "'||") || strstr(s, "'+'") ) waf_hit(v, "SQLI-16", "String concatenation break-out", "SQL Injection", "CWE-89", "T1190", 40, "'||");
}

static void waf_check_xss(const char *s, WafVerdict *v) {
    const char *w = NULL;
    static const char *tags[] = { "<script", "</script", "<iframe", "<object", "<embed", "<svg", "<math", "<link", "<meta http-equiv", "<base ", "<form ", "<body", "<img", "<video", "<audio", "<details", "<marquee", "<input", "<textarea", "<style", "<frameset", "<applet", "<isindex", "<x ", NULL };
    int tag = 0; const char *tp = NULL; for (int i = 0; tags[i]; i++) if ((tp = strstr(s, tags[i]))) { tag = i + 1; break; }
    int hasEvent = 0; const char *ev = NULL; for (const char *p = s; (p = strstr(p, "on")); p++) { if (p > s && waf_isword((unsigned char)p[-1])) continue; const char *q = p + 2; size_t k = 0; while (isalpha((unsigned char)q[k]) && k < 14) k++; if (k >= 3 && (q[k] == '=' || (q[k] == ' ' && q[k + 1] == '='))) { hasEvent = 1; ev = p; break; } }
    if (tag == 1 || tag == 2) waf_hit(v, "XSS-01", "Script element", "Cross-Site Scripting", "CWE-79", "T1059.007", 95, tp);
    else if (tag && (hasEvent || strstr(s, "javascript:") || strstr(s, "src=") || strstr(s, "href="))) waf_hit(v, "XSS-02", "HTML element with active attribute", "Cross-Site Scripting", "CWE-79", "T1059.007", 90, tp);
    else if (tag > 2) waf_hit(v, "XSS-02B", "Suspicious HTML element", "Cross-Site Scripting", "CWE-79", "T1059.007", 45, tp);
    if (hasEvent && (strchr(s, '<') || strchr(s, '"') || strchr(s, '\'') || strchr(s, '/'))) waf_hit(v, "XSS-03", "Inline event handler", "Cross-Site Scripting", "CWE-79", "T1059.007", 80, ev);
    static const char *uri[] = { "javascript:", "vbscript:", "livescript:", "data:text/html", "data:application/x", "data:image/svg", "jar:", NULL };
    if (waf_hasany(s, uri, &w)) { int sch = 1; if (!strncmp(w, "jar:", 4)) sch = 0; if (sch) waf_hit(v, "XSS-04", "Script URI scheme", "Cross-Site Scripting", "CWE-79", "T1059.007", 80, w); }
    static const char *sinks[] = { "document.cookie", "document.write", "document.domain", "window.location", "location.href=", "location.replace(", "eval(atob(", "string.fromcharcode", ".innerhtml=", "settimeout(\"", "setinterval(\"", "new function(", "constructor.constructor", "alert(", "prompt(", "confirm(", "expression(", "-moz-binding", "behavior:url", NULL };
    for (int i = 0; sinks[i]; i++) if (strstr(s, sinks[i])) { const char *p = strstr(s, sinks[i]); int ctx = strchr(s, '<') || strchr(s, '"') || strchr(s, '\'') || strchr(s, ';') || strchr(s, '('); if (ctx || i < 4) { waf_hit(v, "XSS-05", "JavaScript sink / payload", "Cross-Site Scripting", "CWE-79", "T1059.007", (strchr(s, '<') || i < 3) ? 75 : 50, p); break; } }
    if (strstr(s, "srcdoc=") || strstr(s, "formaction=") || strstr(s, "xlink:href") || (strstr(s, "<![cdata[") && strstr(s, "script"))) waf_hit(v, "XSS-06", "Alternative XSS vector", "Cross-Site Scripting", "CWE-79", "T1059.007", 75, "srcdoc");
    if (strstr(s, "{{") && (strstr(s, "constructor") || strstr(s, "$on.constructor") || strstr(s, "__proto__"))) waf_hit(v, "XSS-07", "Client-side template injection", "Cross-Site Scripting", "CWE-79", "T1059.007", 80, "{{");
    if ((strstr(s, "\"><") || strstr(s, "'><") || strstr(s, "\"/><") || strstr(s, "</title>") || strstr(s, "</textarea>") || strstr(s, "</style>")) && strchr(s, '<')) waf_hit(v, "XSS-08", "Context break-out", "Cross-Site Scripting", "CWE-79", "T1059.007", 70, "\"><");
}

static void waf_check_xxe(const char *s, WafVerdict *v) {
    int doctype = strstr(s, "<!doctype") != NULL, entity = strstr(s, "<!entity") != NULL;
    if (entity && (strstr(s, " system ") || strstr(s, " public ") || strstr(s, "system\"") || strstr(s, "system '"))) waf_hit(v, "XXE-01", "External entity declaration", "XML External Entity", "CWE-611", "T1190", 95, strstr(s, "<!entity"));
    else if (entity && strstr(s, "<!entity %")) waf_hit(v, "XXE-02", "Parameter entity", "XML External Entity", "CWE-611", "T1190", 90, "<!entity %");
    else if (doctype && (strstr(s, "[<!") || strstr(s, "[ <!") || strstr(s, " system ") || strstr(s, " public "))) waf_hit(v, "XXE-03", "DOCTYPE with internal subset / external DTD", "XML External Entity", "CWE-611", "T1190", 75, strstr(s, "<!doctype"));
    if ((strstr(s, "system \"file:") || strstr(s, "system 'file:") || strstr(s, "system \"http") || strstr(s, "system 'http") || strstr(s, "system \"php:") || strstr(s, "system \"expect:") || strstr(s, "system \"jar:") || strstr(s, "system \"gopher:") || strstr(s, "system \"ftp:") || strstr(s, "system \"netdoc:")) ) waf_hit(v, "XXE-04", "SYSTEM identifier to local/remote resource", "XML External Entity", "CWE-611", "T1190", 95, "system");
    if (strstr(s, "xi:include") || strstr(s, "xmlns:xi=") ) waf_hit(v, "XXE-05", "XInclude", "XML External Entity", "CWE-611", "T1190", 90, "xi:include");
    { int cnt = 0; for (const char *p = s; (p = strstr(p, "<!entity")); p++) cnt++; if (cnt >= 4) waf_hit(v, "XXE-06", "Entity expansion (XML bomb)", "XML External Entity", "CWE-776", "T1499", 90, "<!entity x N"); }
    if (strstr(s, "<!entity") && strstr(s, "&lol") ) waf_hit(v, "XXE-07", "Billion laughs", "XML External Entity", "CWE-776", "T1499", 95, "&lol");
}

static void waf_check_traversal(const char *s, int isPath, WafVerdict *v) {
    const char *w = NULL;
    static const char *dots[] = { "../", "..\\", "..;/", "/..", "\\..", "....//", "..././", "%2e%2e", ".%2e", "%2e.", "..%2f", "..%5c", "..%c0%af", "..%c1%9c", "..%255c", NULL };
    int dot = waf_hasany(s, dots, &w); int seq = 0; for (const char *p = s; (p = strstr(p, "..")); p++) { if ((p[2] == '/' || p[2] == '\\' || p[2] == ';') && (p == s || p[-1] == '/' || p[-1] == '\\' || p[-1] == '=' || p[-1] == ' ' || p[-1] == '.' || p[-1] == '"' || p[-1] == '\'')) seq++; }
    static const char *targets[] = { "/etc/passwd", "/etc/shadow", "/etc/group", "/etc/hosts", "/etc/issue", "/etc/sudoers", "/etc/ssh/", "/proc/self/", "/proc/version", "/proc/cmdline", "/var/log/", "/var/www/", "/root/.", "/home/", "boot.ini", "win.ini", "windows/system32", "windows\\system32", "winnt/", "system.ini", "\\windows\\", "c:\\", "c:/", "web.config", "/.ssh/", "id_rsa", ".htpasswd", "/.bash_history", NULL };
    const char *tw = NULL; int tgt = waf_hasany(s, targets, &tw);
    if (seq >= 1 && (tgt || seq >= 2 || isPath)) waf_hit(v, "TRAV-01", "Directory traversal sequence", "Path Traversal", "CWE-22", "T1083", tgt ? 90 : 75, w ? w : "../");
    else if (dot && seq >= 1) waf_hit(v, "TRAV-01B", "Traversal sequence", "Path Traversal", "CWE-22", "T1083", 45, w);
    if (tgt && !seq) { if (tw && (tw[0] == '/' ? (strstr(s, "/etc/passwd") || strstr(s, "/etc/shadow") || strstr(s, "/proc/self/") || strstr(s, "/etc/sudoers") || strstr(s, "id_rsa")) : (strstr(s, "boot.ini") || strstr(s, "win.ini") || strstr(s, "system32"))))
        waf_hit(v, "TRAV-02", "Direct access to sensitive system file", "Path Traversal", "CWE-22", "T1083", 80, tw); }
    if (strstr(s, "%00") || strstr(s, "\\x00")) waf_hit(v, "TRAV-03", "Null-byte path truncation", "Path Traversal", "CWE-158", "T1083", 60, "%00");
}

static void waf_check_lfi_rfi(const char *s, const char *pname, WafVerdict *v) {
    static const char *wrappers[] = { "php://filter", "php://input", "php://fd", "php://memory", "data://text", "data:text/plain;base64", "expect://", "zip://", "phar://", "glob://", "ogg://", "rar://", "compress.zlib://", "compress.bzip2://", NULL }; const char *w = NULL;
    if (waf_hasany(s, wrappers, &w)) waf_hit(v, "LFI-01", "PHP/stream wrapper abuse", "Local File Inclusion", "CWE-98", "T1190", 90, w);
    if (strstr(s, "/proc/self/environ") || strstr(s, "/proc/self/fd/") || strstr(s, "/var/log/apache") || strstr(s, "/var/log/nginx") || strstr(s, "/var/log/auth.log") || strstr(s, "access.log")) waf_hit(v, "LFI-02", "Log/proc file inclusion (poisoning)", "Local File Inclusion", "CWE-98", "T1190", 85, "/proc/self");
    static const char *inc[] = { "file", "page", "include", "inc", "path", "template", "tpl", "doc", "document", "folder", "dir", "load", "view", "lang", "module", "conf", "content", "layout", "style", "pg", "name", "src", "filename", NULL };
    if (pname && pname[0] && (strstr(s, "http://") == s || strstr(s, "https://") == s || strstr(s, "ftp://") == s || strstr(s, "//") == s || strstr(s, "\\\\") == s)) { for (int i = 0; inc[i]; i++) if (!strcmp(pname, inc[i])) { waf_hit(v, "RFI-01", "Remote file inclusion via include-like parameter", "Remote File Inclusion", "CWE-98", "T1190", 70, s); break; } }
    if (strstr(s, "<?php") || strstr(s, "<?=")) waf_hit(v, "RFI-02", "PHP tag in parameter", "Remote File Inclusion", "CWE-98", "T1505.003", 80, "<?php");
}

static int waf_cmd_word(const char *p) {
    static const char *cmds[] = { "cat", "ls", "id", "whoami", "uname", "pwd", "wget", "curl", "nc", "ncat", "netcat", "bash", "sh", "zsh", "dash", "ksh", "python", "python3", "perl", "ruby", "php", "node", "powershell", "pwsh", "cmd", "certutil", "bitsadmin", "nslookup", "ping", "ifconfig", "ipconfig", "netstat", "net", "tasklist", "systeminfo", "wmic", "reg", "type", "dir", "echo", "rm", "mv", "cp", "chmod", "chown", "sudo", "su", "kill", "nohup", "telnet", "ssh", "scp", "ftp", "tftp", "mkfifo", "base64", "xxd", "awk", "sed", "find", "xargs", "env", "printenv", "set", "head", "tail", "more", "less", "tar", "zip", "unzip", "gcc", "make", "mshta", "rundll32", "regsvr32", "cscript", "wscript", "sc", "schtasks", "at", "crontab", "useradd", "passwd", "shutdown", "reboot", "dd", "mount", "nmap", NULL };
    while (*p == ' ' || *p == '\t') p++; if (*p == '/') { const char *sl = strrchr(p, '/'); while (*p && *p != ' ') { if (*p == '/') sl = p; p++; } p = sl + 1; }
    for (int i = 0; cmds[i]; i++) { size_t l = strlen(cmds[i]); if (!strncmp(p, cmds[i], l) && !waf_isword((unsigned char)p[l])) return 1; if (!strncmp(p, "bin/", 4)) { p += 4; i = -1; } }
    return 0;
}
static void waf_check_cmdi(const char *s, WafVerdict *v) {
    for (const char *p = s; *p; p++) {
        const char *after = NULL; int bt = 0;
        if (*p == ';' || *p == '|' || *p == '\n') after = p + (p[1] == '|' ? 2 : 1);
        else if (*p == '&' && p[1] == '&') after = p + 2; else if (*p == '&' && p > s && p[1] != '=' && p[1] != '#' && !isalnum((unsigned char)p[1]) ) after = p + 1;
        else if (*p == '`') { after = p + 1; bt = 1; } else if (*p == '$' && p[1] == '(') { after = p + 2; bt = 1; }
        if (!after) continue; if (!waf_cmd_word(after)) continue;
        const char *rest = after; while (*rest == ' ') rest++;
        int dangerous = strstr(rest, "/etc/") || strstr(rest, "/bin/") || strstr(rest, "http") || strstr(rest, "-e ") || strstr(rest, ">") || strstr(rest, "/dev/") || strstr(rest, "-c ") || strstr(rest, "whoami") || strstr(rest, "id") || bt || strstr(rest, "|") || strstr(rest, "&");
        waf_hit(v, "CMDI-01", "Shell metacharacter followed by command", "Command Injection", "CWE-78", "T1059", (bt || dangerous) ? 90 : 65, p); return;
    }
    static const char *sig[] = { "/bin/sh", "/bin/bash", "cmd.exe /c", "cmd /c", "cmd.exe/c", "powershell -", "powershell.exe -", "pwsh -", "nc -e", "ncat -e", "bash -i", "/dev/tcp/", "mkfifo /tmp", "python -c", "python3 -c", "perl -e", "ruby -e", "php -r", "| bash", "|bash", "| sh", "|sh", "curl http", "wget http", "certutil -urlcache", "bitsadmin /transfer", "invoke-expression", "iex(", "iex (", "downloadstring", "-encodedcommand", " -enc ", "frombase64string", "system32\\cmd", NULL };
    const char *w = NULL; if (waf_hasany(s, sig, &w)) waf_hit(v, "CMDI-02", "Shell/interpreter invocation", "Command Injection", "CWE-78", "T1059", 85, w);
    if (strstr(s, "${ifs}") || strstr(s, "$ifs") || strstr(s, "{cat,") || strstr(s, "c''at") || strstr(s, "c\"\"at")) waf_hit(v, "CMDI-03", "Shell obfuscation", "Command Injection", "CWE-78", "T1027", 70, "${ifs}");
}

static void waf_check_ssrf(const char *s, const char *pname, WafVerdict *v) {
    static const char *meta[] = { "169.254.169.254", "metadata.google.internal", "169.254.170.2", "100.100.100.200", "metadata.azure.com", "/latest/meta-data", "/computemetadata/v1", "/metadata/instance", "instance-data", NULL }; const char *w = NULL;
    if (waf_hasany(s, meta, &w)) waf_hit(v, "SSRF-01", "Cloud metadata endpoint", "Server-Side Request Forgery", "CWE-918", "T1552.005", 95, w);
    static const char *schemes[] = { "gopher://", "dict://", "ldap://", "tftp://", "sftp://", "jar:http", "netdoc://", "ftp://127.", "file:///", "file://localhost", NULL };
    if (waf_hasany(s, schemes, &w)) waf_hit(v, "SSRF-02", "Dangerous URL scheme", "Server-Side Request Forgery", "CWE-918", "T1190", 85, w);
    static const char *urlp[] = { "url", "uri", "link", "src", "source", "dest", "destination", "redirect", "next", "target", "callback", "webhook", "feed", "host", "domain", "proxy", "fetch", "image", "img", "avatar", "file", "path", "return", "returnurl", "continue", "data", "reference", "site", "html", "page", "val", NULL };
    int urlParam = 0; if (pname && pname[0]) for (int i = 0; urlp[i]; i++) if (!strcmp(pname, urlp[i])) urlParam = 1;
    const char *u = strstr(s, "://");
    if (u && (urlParam || strstr(s, "http") == s)) { const char *h = u + 3; while (*h == '/' || *h == '@') h++; const char *at = strchr(h, '@'); const char *sl = strchr(h, '/'); if (at && (!sl || at < sl)) h = at + 1;
        int internal = !strncmp(h, "127.", 4) || !strncmp(h, "localhost", 9) || !strncmp(h, "0.0.0.0", 7) || !strncmp(h, "[::1]", 5) || !strncmp(h, "[::]", 4) || !strncmp(h, "10.", 3) || !strncmp(h, "192.168.", 8) || !strncmp(h, "169.254.", 8) || !strncmp(h, "0x7f", 4) || !strncmp(h, "2130706433", 10) || !strncmp(h, "017700000001", 12) || !strncmp(h, "127.1", 5) || !strncmp(h, "0177.", 5)
            || (!strncmp(h, "172.", 4) && atoi(h + 4) >= 16 && atoi(h + 4) <= 31) || strstr(h, ".internal") == h + strcspn(h, "/:?#") - 9 || !strncmp(h, "[::ffff:", 8) || !strncmp(h, "0:0:0:0:0:ffff", 14);
        if (internal) waf_hit(v, "SSRF-03", "Request to internal/loopback address", "Server-Side Request Forgery", "CWE-918", "T1190", urlParam ? 85 : 55, h); }
}

static void waf_check_ssti(const char *s, WafVerdict *v) {
    const char *w = NULL; static const char *sig[] = { "{{config", "{{self.", "{{request.", "{{''.__class__", "{{\"\".__class__", "__class__.__mro__", "__subclasses__", "__globals__", "__builtins__", "__import__(", "{{lipsum", "{{cycler", "{{joiner", "{{namespace", "freemarker.template", "<#assign", "${\"freemarker", "#set(", "$class.inspect", "{php}", "{{_self.env", "getruntime().exec", "{%import", "{% import", "{%set", "{% set", "{% for", "{%for", "{%if", "{% if", "${{", "#{t(", "*{t(", "@(", NULL };
    if (waf_hasany(s, sig, &w)) { int strong = strstr(w, "__") || strstr(w, "freemarker") || strstr(w, "getruntime") || strstr(w, "assign") || strstr(w, "config") || strstr(w, "lipsum"); waf_hit(v, "SSTI-01", "Template injection payload", "Server-Side Template Injection", "CWE-1336", "T1190", strong ? 90 : 60, w); }
    for (const char *p = s; (p = strstr(p, "{{")); p++) { const char *e = strstr(p, "}}"); if (!e) break; const char *q = p + 2; while (*q == ' ') q++; if (isdigit((unsigned char)*q)) { while (isdigit((unsigned char)*q)) q++; while (*q == ' ') q++; if (*q == '*' || *q == '+' || *q == '-' || *q == '/') { waf_hit(v, "SSTI-02", "Arithmetic probe {{7*7}}", "Server-Side Template Injection", "CWE-1336", "T1190", 80, p); return; } } }
    for (const char *p = s; (p = strstr(p, "${")); p++) { const char *q = p + 2; while (*q == ' ') q++; if (isdigit((unsigned char)*q)) { while (isdigit((unsigned char)*q)) q++; if (*q == '*' || *q == '+') { waf_hit(v, "SSTI-03", "Arithmetic probe ${7*7}", "Server-Side Template Injection", "CWE-1336", "T1190", 75, p); return; } } }
    if (strstr(s, "<%=") || strstr(s, "<%-") || strstr(s, "<%@ page") || strstr(s, "<%@page")) waf_hit(v, "SSTI-04", "Server-page scriptlet", "Server-Side Template Injection", "CWE-1336", "T1505.003", 80, "<%=");
}

static void waf_check_nosql_ldap_xpath(const char *s, const char *pname, WafVerdict *v) {
    static const char *ops[] = { "[$ne]", "[$gt]", "[$gte]", "[$lt]", "[$lte]", "[$regex]", "[$where]", "[$or]", "[$and]", "[$nin]", "[$in]", "[$exists]", "{\"$ne\"", "{\"$gt\"", "{\"$regex\"", "{\"$where\"", "{\"$or\"", "$where:", "'$where'", "{'$ne'", "{$ne:", "{$gt:", "{ \"$ne\"", "{ \"$gt\"", "{ \"$regex\"", "{ \"$where\"", NULL }; const char *w = NULL;
    if (waf_hasany(s, ops, &w) || (pname && (strstr(pname, "[$") || strstr(pname, "$ne") || strstr(pname, "$gt") || strstr(pname, "$where") || strstr(pname, "$regex")))) waf_hit(v, "NOSQL-01", "NoSQL operator injection", "NoSQL Injection", "CWE-943", "T1190", 85, w ? w : pname);
    if (strstr(s, "this.") && (strstr(s, "sleep(") || strstr(s, "function") || strstr(s, "return"))) waf_hit(v, "NOSQL-02", "JavaScript in NoSQL query", "NoSQL Injection", "CWE-943", "T1190", 70, "this.");
    static const char *ld[] = { "*)(", ")(|", "*)(|", ")(&", "(|(", "*)(uid=*", "*)(objectclass=*", "(objectclass=*)", "(cn=*)", "(uid=*)", "admin)(&", "*))(|", NULL };
    if (waf_hasany(s, ld, &w)) waf_hit(v, "LDAP-01", "LDAP filter injection", "LDAP Injection", "CWE-90", "T1190", 80, w);
    if ((strstr(s, "' or '") || strstr(s, "' or \"") || strstr(s, "\" or \"")) && (strstr(s, "//") || strstr(s, "text()") || strstr(s, "count(") || strstr(s, "name(") || strstr(s, "string-length(") || strstr(s, "substring(")))
        waf_hit(v, "XPATH-01", "XPath injection", "XPath Injection", "CWE-643", "T1190", 80, "xpath");
    else if (strstr(s, "string-length(") || (strstr(s, "//*") && strstr(s, "[") ) || strstr(s, "/*[1]") || strstr(s, "text()=")) waf_hit(v, "XPATH-02", "XPath probe", "XPath Injection", "CWE-643", "T1190", 55, "xpath");
}

static void waf_check_header_inj(const char *raw, const char *s, WafVerdict *v) {
    if (strstr(raw, "%0d%0a") || strstr(raw, "%0D%0A") || strstr(raw, "%0d%0A") || strstr(raw, "%0D%0a") || strstr(raw, "%0a%0d") || strstr(raw, "\r\n") || strstr(raw, "%e5%98%8a")) {
        int hdr = strstr(s, "set-cookie") || strstr(s, "location:") || strstr(s, "content-length") || strstr(s, "content-type") || strstr(s, "http/1.") || strstr(s, "x-") || strstr(s, "host:") || strstr(s, "bcc:") || strstr(s, "to:") || strstr(s, "cc:") || strstr(s, "subject:") || strstr(s, "<script");
        waf_hit(v, "CRLF-01", "CRLF / header injection", "Header Injection", "CWE-113", "T1190", hdr ? 90 : 50, "%0d%0a"); }
    if (strstr(s, "\nbcc:") || strstr(s, "\ncc:") || strstr(s, "\nto:") || strstr(s, "\ncontent-type:") ) waf_hit(v, "CRLF-02", "Mail/header injection", "Header Injection", "CWE-93", "T1190", 80, "\\nbcc:");
}

static void waf_check_java_etc(const char *s, const char *raw, WafVerdict *v) {
    const char *w = NULL;
    if (strstr(s, "${jndi:") || strstr(s, "${${") || strstr(s, "${::-") || strstr(s, "${lower:") || strstr(s, "${upper:") || strstr(s, "${env:") || strstr(s, "${sys:") || strstr(s, "${java:") || strstr(s, "${date:") || strstr(s, "jndi:ldap") || strstr(s, "jndi:rmi") || strstr(s, "jndi:dns") || strstr(s, "jndi:iiop")) {
        int strong = strstr(s, "jndi") || strstr(s, "${::-") || strstr(s, "${${"); waf_hit(v, "JNDI-01", "Log4Shell / JNDI lookup", "Log4Shell/JNDI", "CWE-917", "T1190", strong ? 99 : 60, "${jndi:"); }
    if (strstr(s, "() {") && (strstr(s, ";};") || strstr(s, "; };") || strstr(s, ":;};") || strstr(s, ":; };"))) waf_hit(v, "SHELL-01", "Shellshock", "Shellshock", "CWE-78", "T1190", 99, "() { :;};");
    static const char *ognl[] = { "%{", "#_memberaccess", "#context[", "ognlutil", "@java.lang.runtime", "java.lang.processbuilder", "java.lang.runtime", "class.module.classloader", "class.classloader", "#rt=@java", "xwork.methodaccessor", "allowstaticmethodaccess", "${t(java", "spel", "new java.lang.processbuilder", "javax.script.scriptenginemanager", NULL };
    if (waf_hasany(s, ognl, &w) && (strchr(s, '{') || strchr(s, '#') || strstr(s, "class.") )) waf_hit(v, "OGNL-01", "OGNL / Spring / Java expression injection", "Expression Injection", "CWE-917", "T1190", 90, w);
    if (strstr(raw, "rO0AB") || strstr(raw, "ro0ab") || strstr(s, "aced0005") || (strstr(s, "h4sia") && strstr(s, "yso")) || strstr(s, "ysoserial") || strstr(s, "java.util.priorityqueue") || strstr(s, "commons.collections") || strstr(s, "org.apache.commons.beanutils") || strstr(s, "com.sun.org.apache.xalan") || strstr(s, "javax.naming.initialcontext") || strstr(s, "java.net.urlclassloader"))
        waf_hit(v, "DESER-01", "Java deserialization gadget", "Insecure Deserialization", "CWE-502", "T1190", 90, "rO0AB");
    if ((strstr(s, "o:") && strstr(s, ":\"") && strstr(s, "{s:")) || strstr(s, "a:1:{") || strstr(s, "__wakeup") || strstr(s, "__destruct") || strstr(s, "phar://")) { const char *p = strstr(s, "o:"); if (p && isdigit((unsigned char)p[2])) waf_hit(v, "DESER-02", "PHP object injection", "Insecure Deserialization", "CWE-502", "T1190", 85, p); }
    if (strstr(s, "__type") && (strstr(s, "system.") || strstr(s, "objectdataprovider") || strstr(s, "windowsidentity") || strstr(s, "assembly"))) waf_hit(v, "DESER-03", ".NET gadget", "Insecure Deserialization", "CWE-502", "T1190", 85, "__type");
    if (strstr(s, "!!python/") || strstr(s, "!!ruby/") || strstr(s, "!!java") || strstr(s, "!ruby/object") || strstr(s, "cos\nsystem") || strstr(s, "pickle")) waf_hit(v, "DESER-04", "YAML/pickle deserialization", "Insecure Deserialization", "CWE-502", "T1190", 80, "!!python");
    if (strstr(s, "__proto__") || strstr(s, "constructor.prototype") || strstr(s, "constructor[prototype]") || strstr(s, "[__proto__]")) waf_hit(v, "PROTO-01", "Prototype pollution", "Prototype Pollution", "CWE-1321", "T1190", 80, "__proto__");
    if (strstr(s, "<?php") || strstr(s, "<?=") || strstr(s, "eval(base64_decode") || strstr(s, "eval($_") || strstr(s, "system($_") || strstr(s, "passthru(") || strstr(s, "shell_exec(") || strstr(s, "assert($_") || strstr(s, "preg_replace(\"/e") || strstr(s, "proc_open(") || strstr(s, "popen(") || strstr(s, "<%@ page import") || strstr(s, "runtime.getruntime().exec") || strstr(s, "processbuilder(") || strstr(s, "<%eval") || strstr(s, "<script runat=\"server\"") || strstr(s, "response.write(eval") || strstr(s, "wscript.shell"))
        waf_hit(v, "WSHELL-01", "Web shell / server-side code", "Webshell Upload", "CWE-434", "T1505.003", 90, "<?php");
    if (strstr(s, "__schema") || strstr(s, "__type(") || strstr(s, "introspectionquery")) waf_hit(v, "GQL-01", "GraphQL introspection", "GraphQL Abuse", "CWE-200", "T1590", 45, "__schema");
}

static void waf_check_path_probe(const char *path, WafVerdict *v) {
    static const char *probe[] = { "/.env", "/.git/", "/.git/config", "/.svn/", "/.hg/", "/.ds_store", "/.htaccess", "/.htpasswd", "/.aws/", "/.ssh/", "/wp-config", "/config.php", "/configuration.php", "/phpinfo", "/info.php", "/server-status", "/server-info", "/actuator", "/jolokia", "/console", "/manager/html", "/phpmyadmin", "/pma/", "/adminer", "/backup.", "/dump.sql", "/db.sql", "/database.sql", ".bak", ".old", ".swp", ".sql", "/web-inf/", "/meta-inf/", "/cgi-bin/", "/vendor/phpunit", "/_ignition/", "/solr/admin", "/api/v1/pods", "/.docker", "/.kube", "/id_rsa", "/composer.json", "/package.json", "/.npmrc", "/debug", "/trace.axd", "/elmah.axd", "/wp-admin/install", "/xmlrpc.php", NULL };
    const char *w = NULL; if (waf_hasany(path, probe, &w)) { int strong = !strcmp(w, "/.env") || !strncmp(w, "/.git", 5) || !strncmp(w, "/.aws", 5) || !strncmp(w, "/.ssh", 5) || strstr(w, "id_rsa") || strstr(w, "web-inf") || strstr(w, "phpunit") || strstr(w, "ignition") || strstr(w, ".sql") || strstr(w, "wp-config"); waf_hit(v, "PROBE-01", "Sensitive file / admin endpoint probe", "Reconnaissance", "CWE-538", "T1595", strong ? 80 : 45, w); }
}

static void waf_check_scanner(const char *ua, const char *allh, WafVerdict *v) {
    static const char *sc[] = { "sqlmap", "nikto", "nessus", "acunetix", "netsparker", "appscan", "openvas", "w3af", "wpscan", "masscan", "nmap", "zgrab", "dirbuster", "gobuster", "wfuzz", "ffuf", "feroxbuster", "nuclei", "havij", "arachni", "skipfish", "burpcollaborator", "owasp zap", "zaproxy", "metasploit", "hydra", "jaeles", "xsstrike", "commix", "joomscan", "whatweb", "dirb", "paros", "webinspect", "fimap", "grabber", "sqlninja", "vega/", "libwww-perl", "python-requests/2.6", "go-http-client/1.1 (scan", NULL };
    const char *w = NULL; if (ua && waf_hasany(ua, sc, &w)) waf_hit(v, "SCAN-01", "Known attack/scanner tool", "Scanner Detection", "CWE-693", "T1595", 70, w);
    else if (allh && (strstr(allh, "x-scanner") || strstr(allh, "acunetix-") || strstr(allh, "x-wipp") || strstr(allh, "x-sqlmap"))) waf_hit(v, "SCAN-02", "Scanner header", "Scanner Detection", "CWE-693", "T1595", 70, "x-scanner");
}

static void waf_check_open_redirect(const char *s, const char *pname, WafVerdict *v) {
    static const char *rp[] = { "redirect", "redirect_uri", "redirect_url", "return", "returnurl", "return_url", "next", "continue", "goto", "dest", "destination", "url", "target", "rurl", "forward", "callback", "back", "out", NULL };
    if (!pname || !pname[0]) return; int isr = 0; for (int i = 0; rp[i]; i++) if (!strcmp(pname, rp[i])) isr = 1; if (!isr) return;
    if ((s[0] == '/' && s[1] == '/') || (s[0] == '/' && s[1] == '\\') || !strncmp(s, "\\\\", 2) || (!strncmp(s, "http", 4) && strstr(s, "://") && strstr(s, "@")) || !strncmp(s, "javascript:", 11) || !strncmp(s, "data:", 5)) waf_hit(v, "REDIR-01", "Open redirect target", "Open Redirect", "CWE-601", "T1204", 45, s);
}

/* ---- request level ------------------------------------------------------------------------------------------------------ */
static const char *waf_hdr(const char *headers, const char *name, char *out, size_t cap) {
    out[0] = 0; size_t nl = strlen(name);
    for (const char *p = headers; p && *p;) { const char *e = strchr(p, '\n'); size_t len = e ? (size_t)(e - p) : strlen(p);
        if (len > nl + 1 && p[nl] == ':') { int eq = 1; for (size_t i = 0; i < nl; i++) if (tolower((unsigned char)p[i]) != tolower((unsigned char)name[i])) { eq = 0; break; } if (eq) { const char *v = p + nl + 1; while (*v == ' ') v++; size_t l = (size_t)(p + len - v); while (l && (v[l - 1] == '\r' || v[l - 1] == ' ')) l--; if (l >= cap) l = cap - 1; memcpy(out, v, l); out[l] = 0; return out; } }
        p = e ? e + 1 : NULL; }
    return NULL;
}

static void waf_scan_target(const char *raw, size_t n, const char *pname, int kind, WafVerdict *v) {
    /* kind: 0 path, 1 query/form value, 2 header value, 3 body, 4 param name */
    if (!n) return; size_t cap = n * 2 + 64 > (1 << 18) ? (1 << 18) : n * 2 + 64; char *s = (char *)malloc(cap); if (!s) return;
    char *s2 = (char *)malloc(cap); int rounds = 0; size_t sl = waf_normalize2(raw, n, s, cap, kind == 1 || kind == 3, &rounds, s2, NULL); (void)sl; if (rounds > v->evasion) v->evasion = rounds;
    if (s2 && strcmp(s, s2) != 0) waf_check_sqli(s2, v);        /* comments joined: a comment inside a keyword is removed, not replaced by a space */
    free(s2);
    if (rounds >= 2 && (strstr(s, "<") || strstr(s, "'") || strstr(s, "..") || strstr(s, "union") || strstr(s, "script") || strstr(s, "select") )) waf_hit(v, "ENC-01", "Multi-layer encoding evasion", "Encoding Evasion", "CWE-172", "T1027", rounds >= 3 ? 70 : 50, "double-encoded");
    if (kind == 4) { waf_check_nosql_ldap_xpath("", s, v); free(s); return; }
    char *rawcopy = (char *)malloc(n + 1); if (rawcopy) { memcpy(rawcopy, raw, n); rawcopy[n] = 0; }
    waf_check_sqli(s, v);
    waf_check_xss(s, v);
    waf_check_traversal(s, kind == 0, v);
    waf_check_lfi_rfi(s, pname, v);
    waf_check_cmdi(s, v);
    waf_check_ssrf(s, pname, v);
    waf_check_ssti(s, v);
    waf_check_nosql_ldap_xpath(s, pname, v);
    waf_check_header_inj(rawcopy ? rawcopy : raw, s, v);
    waf_check_java_etc(s, rawcopy ? rawcopy : raw, v);
    if (kind == 3 || kind == 1) waf_check_xxe(s, v);
    if (kind == 0) waf_check_path_probe(s, v);
    waf_check_open_redirect(s, pname, v);
    free(rawcopy); free(s);
}

static void waf_split_params(const char *q, size_t n, int isBody, WafVerdict *v) {
    size_t i = 0;
    while (i < n) {
        size_t e = i; while (e < n && q[e] != '&') e++;
        const char *eq = memchr(q + i, '=', e - i); size_t nl = eq ? (size_t)(eq - (q + i)) : e - i; char pname[64]; size_t k = 0;
        { char nb[160]; int rounds; size_t m = waf_normalize(q + i, nl > 150 ? 150 : nl, nb, sizeof nb, 1, &rounds); (void)rounds; for (k = 0; k < m && k < 63; k++) pname[k] = nb[k]; pname[k] = 0; }
        if (nl) waf_scan_target(q + i, nl, NULL, 4, v);
        if (eq) waf_scan_target(eq + 1, e - (size_t)(eq - q) - 1, pname, isBody ? 3 : 1, v); else if (!nl) {}
        i = e + 1;
    }
}

static int waf_threshold(int paranoia) { return paranoia <= 1 ? 70 : paranoia == 2 ? 50 : 30; }

static void waf_inspect(const WafRequest *rq, int paranoia, WafVerdict *v) {
    memset(v, 0, sizeof *v); v->paranoia = paranoia < 1 ? 1 : paranoia > 3 ? 3 : paranoia; v->severity = "Clean";
    const char *uri = rq->uri ? rq->uri : ""; const char *qm = strchr(uri, '?'); size_t pathLen = qm ? (size_t)(qm - uri) : strlen(uri);
    /* protocol / size anomalies */
    if (strlen(uri) > 8192) waf_hit(v, "PROTO-02", "Oversized request line", "Protocol Violation", "CWE-400", "T1499", 60, "uri>8192");
    if (rq->bodyLen > (size_t)32 * 1024 * 1024) waf_hit(v, "DOS-01", "Oversized body", "DoS Signature", "CWE-400", "T1499", 60, "body>32MB");
    if (rq->method) { static const char *ok[] = { "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", NULL }; int m = 0; for (int i = 0; ok[i]; i++) if (!strcmp(rq->method, ok[i])) m = 1; if (!m) waf_hit(v, "PROTO-03", "Unusual HTTP method", "Protocol Violation", "CWE-749", "T1190", !strcmp(rq->method, "TRACE") || !strcmp(rq->method, "CONNECT") ? 55 : 45, rq->method); }
    char cl[32], te[64], ua[300], ct[120];
    if (rq->headers) {
        int hasCl = waf_hdr(rq->headers, "content-length", cl, sizeof cl) != NULL, hasTe = waf_hdr(rq->headers, "transfer-encoding", te, sizeof te) != NULL;
        if (hasCl && hasTe) waf_hit(v, "SMUG-01", "Content-Length + Transfer-Encoding (request smuggling)", "Request Smuggling", "CWE-444", "T1190", 90, "CL+TE");
        if (hasTe) { char t[64]; size_t k = 0; for (; te[k] && k < 63; k++) t[k] = (char)tolower((unsigned char)te[k]); t[k] = 0; if (strcmp(t, "chunked") && strcmp(t, "identity")) waf_hit(v, "SMUG-02", "Obfuscated Transfer-Encoding", "Request Smuggling", "CWE-444", "T1190", 80, te); }
        { int dup = 0; const char *p = rq->headers; while ((p = strstr(p, "ontent-"))) { if (!waf_strncasecmp(p, "ontent-length", 13)) dup++; p += 7; } if (dup > 1) waf_hit(v, "SMUG-03", "Duplicate Content-Length", "Request Smuggling", "CWE-444", "T1190", 85, "CL x2"); }
        waf_check_scanner(waf_hdr(rq->headers, "user-agent", ua, sizeof ua) ? ua : NULL, rq->headers, v);
        waf_hdr(rq->headers, "content-type", ct, sizeof ct);
    } else ct[0] = 0;
    /* path */
    waf_scan_target(uri, pathLen, NULL, 0, v);
    if (qm) waf_split_params(qm + 1, strlen(qm + 1), 0, v);
    /* headers */
    if (rq->headers) {
        for (const char *p = rq->headers; p && *p;) { const char *e = strchr(p, '\n'); size_t len = e ? (size_t)(e - p) : strlen(p); const char *c = memchr(p, ':', len);
            if (c) { size_t nl = (size_t)(c - p); char name[48]; size_t k = 0; for (; k < nl && k < 47; k++) name[k] = (char)tolower((unsigned char)p[k]); name[k] = 0; const char *val = c + 1; size_t vl = len - nl - 1; while (vl && *val == ' ') { val++; vl--; } while (vl && (val[vl - 1] == '\r' || val[vl - 1] == ' ')) vl--;
                if (strcmp(name, "content-length") && strcmp(name, "accept") && strcmp(name, "accept-encoding") && strcmp(name, "accept-language") && strcmp(name, "connection") && strcmp(name, "host") && strcmp(name, "content-type"))
                    waf_scan_target(val, vl, name, 2, v);
                else if (!strcmp(name, "host") || !strcmp(name, "content-type")) { WafVerdict t; memset(&t, 0, sizeof t); waf_scan_target(val, vl, name, 2, &t); for (int i = 0; i < t.nhits; i++) if (t.hits[i].score >= 80) waf_hit(v, t.hits[i].rule, t.hits[i].name, t.hits[i].cat, t.hits[i].cwe, t.hits[i].mitre, t.hits[i].score, t.hits[i].snippet); }
                if (!strcmp(name, "cookie")) { /* cookie values are scanned above as a whole */ } }
            p = e ? e + 1 : NULL; }
    }
    /* body */
    if (rq->body && rq->bodyLen) {
        size_t lim = rq->bodyLen > (size_t)(256 * 1024) ? (size_t)(256 * 1024) : rq->bodyLen; int form = strstr(ct, "x-www-form-urlencoded") != NULL; int multi = strstr(ct, "multipart/") != NULL;
        if (form) waf_split_params((const char *)rq->body, lim, 1, v);
        else {
            waf_scan_target((const char *)rq->body, lim, NULL, 3, v);
            if (multi) { const char *b = (const char *)rq->body; for (size_t i = 0; i + 10 < lim; i++) if (!waf_strncasecmp(b + i, "filename=\"", 10)) { const char *f = b + i + 10; const char *e2 = memchr(f, '"', lim - i - 10); if (!e2) break; char fn[160]; size_t l = (size_t)(e2 - f); if (l > 150) l = 150; memcpy(fn, f, l); fn[l] = 0; for (char *c = fn; *c; c++) *c = (char)tolower((unsigned char)*c);
                static const char *bad[] = { ".php", ".phtml", ".php5", ".phar", ".jsp", ".jspx", ".asp", ".aspx", ".ashx", ".cer", ".asa", ".cgi", ".pl", ".sh", ".exe", ".dll", ".bat", ".cmd", ".htaccess", NULL }; const char *w = NULL; if (waf_hasany(fn, bad, &w)) waf_hit(v, "UPLOAD-01", "Executable/server-side file upload", "Webshell Upload", "CWE-434", "T1505.003", 85, fn); if (strstr(fn, ".php.") || strstr(fn, ".jpg.php") || strstr(fn, "%00")) waf_hit(v, "UPLOAD-02", "Double extension upload", "Webshell Upload", "CWE-434", "T1505.003", 90, fn); } }
        }
    }
    /* combine */
    int mx = 0, sum = 0; const char *top = ""; for (int i = 0; i < v->nhits; i++) { sum += v->hits[i].score; if (v->hits[i].score > mx) { mx = v->hits[i].score; top = v->hits[i].cat; } }
    int score = mx + (sum - mx) / 3; if (score > 100) score = 100; v->score = score; snprintf(v->top, sizeof v->top, "%s", top);
    v->blocked = score >= waf_threshold(v->paranoia);
    v->severity = score >= 90 ? "Critical" : score >= 70 ? "High" : score >= 45 ? "Medium" : score > 0 ? "Low" : "Clean";
}

/* convenience for the payload tester: the text is sent as the value of GET /?q=<text> ('&' and '#' are encoded like a real client would) */
static void waf_inspect_text(const char *text, int paranoia, WafVerdict *v) {
    size_t n = strlen(text); char *uri = (char *)malloc(n * 3 + 16); if (!uri) { memset(v, 0, sizeof *v); return; }
    size_t w = (size_t)snprintf(uri, 8, "/?q=");
    for (size_t i = 0; i < n; i++) { if (text[i] == '&') { memcpy(uri + w, "%26", 3); w += 3; } else if (text[i] == '#') { memcpy(uri + w, "%23", 3); w += 3; } else uri[w++] = text[i]; }
    uri[w] = 0;
    WafRequest rq = { "GET", uri, "User-Agent: test\nHost: example.com", NULL, 0 }; waf_inspect(&rq, paranoia, v); free(uri);
}

#endif /* WAF_CORE_H */
