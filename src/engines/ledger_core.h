/*===========================================================================
 * Kaevex tamper-evident ledger - ledger_core.h (portable)
 * Portable SHA-256 + HMAC-SHA256 and the verification of a log file against
 * its HMAC chain:   mac_i = HMAC(key, mac_{i-1} || line_i),  mac_-1 = 0^32
 * The chain file holds "<line index> <hex mac>" per sealed line.
 * Detects: edited line, deleted/inserted line, truncation, tail appended
 * without sealing. It is tamper-EVIDENT (not tamper-proof, not WORM): someone
 * who also holds the key could rewrite both files.
 *===========================================================================*/
#pragma once
#ifndef LEDGER_CORE_H
#define LEDGER_CORE_H
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { uint32_t h[8]; uint64_t len; uint8_t buf[64]; size_t n; } Sha256Ctx;
static const uint32_t K256[64] = {
0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2 };
#define ROR(x,n) (((x)>>(n))|((x)<<(32-(n))))
static void sha256_block(Sha256Ctx *c, const uint8_t *p) {
    uint32_t w[64], a, b, cc, d, e, f, g, h;
    for (int i = 0; i < 16; i++) w[i] = ((uint32_t)p[i*4] << 24) | ((uint32_t)p[i*4+1] << 16) | ((uint32_t)p[i*4+2] << 8) | p[i*4+3];
    for (int i = 16; i < 64; i++) { uint32_t s0 = ROR(w[i-15],7) ^ ROR(w[i-15],18) ^ (w[i-15] >> 3), s1 = ROR(w[i-2],17) ^ ROR(w[i-2],19) ^ (w[i-2] >> 10); w[i] = w[i-16] + s0 + w[i-7] + s1; }
    a=c->h[0]; b=c->h[1]; cc=c->h[2]; d=c->h[3]; e=c->h[4]; f=c->h[5]; g=c->h[6]; h=c->h[7];
    for (int i = 0; i < 64; i++) {
        uint32_t S1 = ROR(e,6) ^ ROR(e,11) ^ ROR(e,25), ch = (e & f) ^ (~e & g), t1 = h + S1 + ch + K256[i] + w[i];
        uint32_t S0 = ROR(a,2) ^ ROR(a,13) ^ ROR(a,22), mj = (a & b) ^ (a & cc) ^ (b & cc), t2 = S0 + mj;
        h=g; g=f; f=e; e=d+t1; d=cc; cc=b; b=a; a=t1+t2;
    }
    c->h[0]+=a; c->h[1]+=b; c->h[2]+=cc; c->h[3]+=d; c->h[4]+=e; c->h[5]+=f; c->h[6]+=g; c->h[7]+=h;
}
static void sha256_init(Sha256Ctx *c) {
    static const uint32_t i0[8] = { 0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19 };
    memcpy(c->h, i0, sizeof i0); c->len = 0; c->n = 0;
}
static void sha256_update(Sha256Ctx *c, const void *d, size_t n) {
    const uint8_t *p = (const uint8_t *)d; c->len += n;
    while (n) { size_t k = 64 - c->n; if (k > n) k = n; memcpy(c->buf + c->n, p, k); c->n += k; p += k; n -= k; if (c->n == 64) { sha256_block(c, c->buf); c->n = 0; } }
}
static void sha256_final(Sha256Ctx *c, uint8_t out[32]) {
    uint64_t bits = c->len * 8; uint8_t pad = 0x80; sha256_update(c, &pad, 1);
    uint8_t z = 0; while (c->n != 56) sha256_update(c, &z, 1);
    uint8_t lb[8]; for (int i = 0; i < 8; i++) lb[i] = (uint8_t)(bits >> (56 - 8 * i));
    sha256_update(c, lb, 8);
    for (int i = 0; i < 8; i++) { out[i*4] = (uint8_t)(c->h[i] >> 24); out[i*4+1] = (uint8_t)(c->h[i] >> 16); out[i*4+2] = (uint8_t)(c->h[i] >> 8); out[i*4+3] = (uint8_t)c->h[i]; }
}
static void sha256_buf(const void *d, size_t n, uint8_t out[32]) { Sha256Ctx c; sha256_init(&c); sha256_update(&c, d, n); sha256_final(&c, out); }

/* HMAC-SHA256 over m1||m2 (either may be NULL) with a key of any length. */
static void hmac_sha256(const uint8_t *key, size_t kl, const void *m1, size_t n1, const void *m2, size_t n2, uint8_t out[32]) {
    uint8_t k[64] = {0}, ip[64], op[64], inner[32];
    if (kl > 64) sha256_buf(key, kl, k); else memcpy(k, key, kl);
    for (int i = 0; i < 64; i++) { ip[i] = k[i] ^ 0x36; op[i] = k[i] ^ 0x5c; }
    Sha256Ctx c; sha256_init(&c); sha256_update(&c, ip, 64); if (m1 && n1) sha256_update(&c, m1, n1); if (m2 && n2) sha256_update(&c, m2, n2); sha256_final(&c, inner);
    sha256_init(&c); sha256_update(&c, op, 64); sha256_update(&c, inner, 32); sha256_final(&c, out);
}
static void ledger_hex(const uint8_t *b, size_t n, char *o) { for (size_t i = 0; i < n; i++) sprintf(o + i * 2, "%02x", b[i]); }
static int ledger_unhex(const char *h, uint8_t *o, size_t n) {
    for (size_t i = 0; i < n; i++) { unsigned v; if (sscanf(h + i * 2, "%2x", &v) != 1) return 0; o[i] = (uint8_t)v; } return 1;
}

/* mac for one line given the previous mac */
static void ledger_mac(const uint8_t key[32], const uint8_t prev[32], const char *line, size_t ll, uint8_t out[32]) {
    hmac_sha256(key, 32, prev, 32, line, ll, out);
}

enum { LEDGER_OK = 1, LEDGER_BROKEN = 0, LEDGER_NOCHAIN = 2, LEDGER_TAIL = 3 };
typedef struct { int state; int sealed; int unsealedTail; int badLine; char why[160]; char head[65]; } LedgerVerdict;

/* logText: whole log file; chainText: whole chain file ("<idx> <hex>\n" per line). */
static void ledger_verify(const uint8_t key[32], const char *logText, const char *chainText, LedgerVerdict *v) {
    memset(v, 0, sizeof *v); v->badLine = -1;
    size_t nl = 0, cap = 1024; const char **ls = (const char **)malloc(cap * sizeof *ls); size_t *ll = (size_t *)malloc(cap * sizeof *ll);
    if (!ls || !ll) { free(ls); free(ll); snprintf(v->why, sizeof v->why, "out of memory"); return; }
    const char *p = logText;
    while (*p) {
        const char *e = strchr(p, '\n'); size_t n = e ? (size_t)(e - p) : strlen(p); size_t nn = n; if (nn && p[nn-1] == '\r') nn--;
        if (nl == cap) { cap *= 2; ls = (const char **)realloc(ls, cap * sizeof *ls); ll = (size_t *)realloc(ll, cap * sizeof *ll); }
        ls[nl] = p; ll[nl] = nn; nl++; p = e ? e + 1 : p + n;
    }
    uint8_t prev[32] = {0}; long lastIdx = -1; const char *c = chainText ? chainText : "";
    if (!*c) { v->state = LEDGER_NOCHAIN; snprintf(v->why, sizeof v->why, "no HMAC chain yet - new entries will be sealed"); free(ls); free(ll); return; }
    while (*c) {
        unsigned long idx; char hex[80]; int pos = 0;
        if (sscanf(c, "%lu %64s%n", &idx, hex, &pos) != 2 || strlen(hex) != 64) { v->state = LEDGER_BROKEN; snprintf(v->why, sizeof v->why, "chain file is corrupt"); goto out; }
        uint8_t want[32]; if (!ledger_unhex(hex, want, 32)) { v->state = LEDGER_BROKEN; snprintf(v->why, sizeof v->why, "chain file is corrupt"); goto out; }
        if (idx >= nl) { v->state = LEDGER_BROKEN; v->badLine = (int)idx; snprintf(v->why, sizeof v->why, "log is shorter than the chain: lines were deleted or the log was truncated"); goto out; }
        for (long g = lastIdx + 1; g < (long)idx; g++) {            /* unsealed lines between sealed ones: only session headers are legitimate */
            if (!(ll[g] > 4 && strncmp(ls[g], "=== ", 4) == 0)) { v->state = LEDGER_BROKEN; v->badLine = (int)g; snprintf(v->why, sizeof v->why, "line %ld is not covered by the chain (inserted or reordered)", g + 1); goto out; }
        }
        uint8_t got[32]; ledger_mac(key, prev, ls[idx], ll[idx], got);
        if (memcmp(got, want, 32) != 0) { v->state = LEDGER_BROKEN; v->badLine = (int)idx; snprintf(v->why, sizeof v->why, "line %lu was modified (or the key changed)", idx + 1); goto out; }
        memcpy(prev, got, 32); lastIdx = (long)idx; v->sealed++;
        c += pos; while (*c == '\n' || *c == '\r') c++;
    }
    ledger_hex(prev, 32, v->head);
    for (size_t g = (size_t)(lastIdx + 1); g < nl; g++) if (!(ll[g] > 4 && strncmp(ls[g], "=== ", 4) == 0)) v->unsealedTail++;
    if (v->unsealedTail) { v->state = LEDGER_TAIL; snprintf(v->why, sizeof v->why, "%d line(s) at the end are not sealed (appended outside Kaevex, or chain truncated)", v->unsealedTail); }
    else { v->state = LEDGER_OK; snprintf(v->why, sizeof v->why, "all %d sealed entries verify", v->sealed); }
out:
    free(ls); free(ll);
}
#endif
