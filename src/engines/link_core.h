/*===========================================================================
 * Kaevex node linking - link_core.h (portable)
 * Link code:  KAEVEX-LINK-V2://<host>:<port>/<6-digit PIN>
 *===========================================================================*/
#pragma once
#ifndef LINK_CORE_H
#define LINK_CORE_H
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define LINK_PREFIX "KAEVEX-LINK-V2://"

typedef struct { char host[64]; int port; char pin[8]; } LinkCode;

static int link_valid_host(const char *h) {
    size_t n = strlen(h);
    if (n == 0 || n > 63) return 0;
    for (size_t i = 0; i < n; i++) if (!(isalnum((unsigned char)h[i]) || h[i] == '.' || h[i] == '-')) return 0;
    return h[0] != '.' && h[0] != '-';
}

static int link_build_code(const char *host, int port, const char *pin, char *out, size_t n) {
    if (!link_valid_host(host) || port < 1 || port > 65535 || strlen(pin) != 6) return 0;
    for (int i = 0; i < 6; i++) if (!isdigit((unsigned char)pin[i])) return 0;
    int w = snprintf(out, n, LINK_PREFIX "%s:%d/%s", host, port, pin);
    return w > 0 && (size_t)w < n;
}

/* Tolerates surrounding whitespace / quotes from copy-paste. */
static int link_parse_code(const char *in, LinkCode *o) {
    char t[160]; size_t a = 0; while (in[a] && (isspace((unsigned char)in[a]) || in[a] == '"' || in[a] == '\'')) a++;
    strncpy(t, in + a, sizeof t - 1); t[sizeof t - 1] = 0;
    size_t n = strlen(t); while (n && (isspace((unsigned char)t[n - 1]) || t[n - 1] == '"' || t[n - 1] == '\'')) t[--n] = 0;
    if (strncmp(t, LINK_PREFIX, strlen(LINK_PREFIX)) != 0) return 0;
    char *p = t + strlen(LINK_PREFIX);
    char *slash = strchr(p, '/'); if (!slash) return 0;
    *slash = 0; char *pin = slash + 1;
    char *colon = strrchr(p, ':'); if (!colon) return 0;
    *colon = 0;
    char *e; long port = strtol(colon + 1, &e, 10);
    if (*e || port < 1 || port > 65535) return 0;
    if (!link_valid_host(p) || strlen(pin) != 6) return 0;
    for (int i = 0; i < 6; i++) if (!isdigit((unsigned char)pin[i])) return 0;
    memset(o, 0, sizeof *o);
    strcpy(o->host, p); o->port = (int)port; strcpy(o->pin, pin);
    return 1;
}

/* Splits a raw HTTP response in place. Returns 1 on success. */
static int link_parse_http(char *raw, int *status, char **body) {
    if (strncmp(raw, "HTTP/1.", 7) != 0) return 0;
    char *sp = strchr(raw, ' '); if (!sp) return 0;
    *status = atoi(sp + 1);
    char *b = strstr(raw, "\r\n\r\n");
    *body = b ? b + 4 : raw + strlen(raw);
    return *status >= 100 && *status < 600;
}

/* Only RFC1918, loopback, link-local and CGNAT (100.64/10, used by Tailscale) may use the node API. */
static int link_is_private_ip(const char *ip) {
    unsigned a, b, c, d; int pos = 0;
    if (sscanf(ip, "%u.%u.%u.%u%n", &a, &b, &c, &d, &pos) != 4 || ip[pos]) return 0;
    if (a > 255 || b > 255 || c > 255 || d > 255) return 0;
    return a == 10 || a == 127 || (a == 172 && b >= 16 && b <= 31) || (a == 192 && b == 168) ||
           (a == 169 && b == 254) || (a == 100 && b >= 64 && b <= 127);
}
#endif
