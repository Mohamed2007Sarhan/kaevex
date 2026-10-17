/*===========================================================================
 * Kaevex Firewall Pro - fw_pro_core.h   (portable, no Windows dependencies)
 *
 * Policy model + all logic that can be verified off-Windows:
 *   - rule validation (names, ports, IPv4/IPv6 lists, program paths)
 *   - injection-proof netsh argument building (no cmd.exe, validated tokens)
 *   - priority-ordered policy evaluation (simulator) + schedules
 *   - complement ranges (port / IPv4) used to build per-app "allow-list"
 *     sandboxes out of Windows Firewall block rules
 *   - pfirewall.log parser + filter
 *   - process-tree descendants
 *   - adaptive baseline (learn per-app destinations, flag new ones)
 *===========================================================================*/
#pragma once
#ifndef FW_PRO_CORE_H
#define FW_PRO_CORE_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <stdint.h>

#ifdef _WIN32
#define _strnicmp_portable _strnicmp
#else
#define _strnicmp_portable strncasecmp
#include <strings.h>
#endif

#ifndef FWP_MAX_RULES
#define FWP_MAX_RULES 512
#endif

enum { FWP_ALLOW = 0, FWP_BLOCK = 1 };
enum { FWP_IN = 0, FWP_OUT = 1, FWP_BOTH = 2 };
enum { FWP_ANY = 0, FWP_TCP = 1, FWP_UDP = 2, FWP_ICMP4 = 3, FWP_ICMP6 = 4 };
enum { FWP_IF_LAN = 1, FWP_IF_WIFI = 2, FWP_IF_RAS = 4 };
enum { FWP_PROF_DOMAIN = 1, FWP_PROF_PRIVATE = 2, FWP_PROF_PUBLIC = 4 };

typedef struct {
    char name[96];
    char group[48];
    int  priority;          /* 1 = evaluated first */
    int  action;            /* FWP_ALLOW / FWP_BLOCK */
    int  dir;               /* FWP_IN / FWP_OUT / FWP_BOTH */
    int  proto;
    char program[260];      /* "" = any program */
    char localPorts[64];    /* "80,443,8000-8100"; "" = any */
    char remotePorts[64];
    char remoteAddrs[256];  /* comma list: IPv4, IPv4/len, a-b, IPv6, IPv6/len, LocalSubnet...; "" = any */
    char domain[128];       /* optional: resolved to addresses when applied */
    int  ifaceMask;         /* 0 = any */
    int  profileMask;       /* 0 = all */
    int  schedDays;         /* bit0=Sunday .. bit6=Saturday; 0 = every day */
    int  schedStart;        /* minutes from 00:00; start==end==0 -> all day */
    int  schedEnd;
    int  enabled;
    char progHash[65];      /* SHA-256 of the program when the rule was created ("" = unchecked) */
} FwpRule;

/* ---- Validation ---------------------------------------------------------- */
static int fwp_safe_name(const char *s) {
    size_t n = s ? strlen(s) : 0;
    if (n == 0 || n > 90) return 0;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (!(isalnum(c) || c == ' ' || c == '_' || c == '-' || c == '.')) return 0;
    }
    return s[0] != ' ' && s[n - 1] != ' ';
}

static int fwp_valid_ports(const char *s) {
    if (!s || !*s) return 1;                       /* empty = any */
    if (strlen(s) > 63) return 0;
    const char *p = s;
    for (;;) {
        char *e; long a = strtol(p, &e, 10);
        if (e == p || a < 1 || a > 65535) return 0;
        long b = a;
        if (*e == '-') { p = e + 1; b = strtol(p, &e, 10); if (e == p || b < a || b > 65535) return 0; }
        if (*e == '\0') return 1;
        if (*e != ',') return 0;
        p = e + 1;
    }
}

static int fwp_parse_ipv4(const char *s, size_t len, uint32_t *out) {
    char b[20]; if (len == 0 || len > 15) return 0;
    memcpy(b, s, len); b[len] = 0;
    unsigned a[4]; int pos = 0;
    if (sscanf(b, "%u.%u.%u.%u%n", &a[0], &a[1], &a[2], &a[3], &pos) != 4 || (size_t)pos != len) return 0;
    for (int i = 0; i < 4; i++) if (a[i] > 255) return 0;
    for (size_t i = 0; i < len; i++) if (!(isdigit((unsigned char)b[i]) || b[i] == '.')) return 0;
    *out = (a[0] << 24) | (a[1] << 16) | (a[2] << 8) | a[3];
    return 1;
}

static int fwp_ipv6_groups(const char *s, size_t len, int *count) {
    /* s may be empty (e.g. left side of "::1"). groups separated by ':', each 1..4 hex digits */
    *count = 0;
    if (len == 0) return 1;
    size_t i = 0;
    while (i <= len) {
        size_t j = i, d = 0;
        while (j < len && s[j] != ':') { if (!isxdigit((unsigned char)s[j])) return 0; j++; d++; }
        if (d < 1 || d > 4) return 0;
        (*count)++;
        if (j >= len) break;
        i = j + 1;
        if (i >= len) return 0;          /* trailing single ':' */
    }
    return 1;
}

static int fwp_valid_ipv6(const char *s, size_t len) {
    if (len < 2 || len > 45) return 0;
    const char *dbl = NULL;
    for (size_t i = 0; i + 1 < len; i++) {
        if (s[i] == ':' && s[i + 1] == ':') {
            if (dbl || (i + 2 < len && s[i + 2] == ':')) return 0;
            dbl = s + i;
        }
    }
    int l, r;
    if (dbl) {
        if (!fwp_ipv6_groups(s, (size_t)(dbl - s), &l)) return 0;
        if (!fwp_ipv6_groups(dbl + 2, len - (size_t)(dbl - s) - 2, &r)) return 0;
        return l + r <= 7;
    }
    if (!fwp_ipv6_groups(s, len, &l)) return 0;
    return l == 8;
}

static int fwp_is_keyword(const char *s, size_t len) {
    static const char *kw[] = { "LocalSubnet", "DNS", "DHCP", "WINS", "DefaultGateway", "Internet", NULL };
    for (int i = 0; kw[i]; i++) if (strlen(kw[i]) == len && _strnicmp_portable(s, kw[i], len) == 0) return 1;
    return 0;
}

/* Validate a comma separated address list. */
static int fwp_valid_addrs(const char *s) {
    if (!s || !*s) return 1;
    if (strlen(s) > 255) return 0;
    const char *p = s;
    while (*p) {
        const char *e = strchr(p, ','); size_t n = e ? (size_t)(e - p) : strlen(p);
        if (n == 0) return 0;
        const char *slash = memchr(p, '/', n), *dash = memchr(p, '-', n);
        uint32_t v, w;
        if (fwp_is_keyword(p, n)) { /* ok */ }
        else if (slash) {
            size_t an = (size_t)(slash - p); char *me; long m = strtol(slash + 1, &me, 10);
            if (me != p + n || m < 0) return 0;
            if (fwp_parse_ipv4(p, an, &v)) { if (m > 32) return 0; }
            else if (fwp_valid_ipv6(p, an)) { if (m > 128) return 0; }
            else return 0;
        } else if (dash && fwp_parse_ipv4(p, (size_t)(dash - p), &v)) {
            if (!fwp_parse_ipv4(dash + 1, n - (size_t)(dash - p) - 1, &w) || w < v) return 0;
        } else if (!fwp_parse_ipv4(p, n, &v) && !fwp_valid_ipv6(p, n)) return 0;
        if (!e) break;
        p = e + 1;
    }
    return 1;
}

static int fwp_valid_program(const char *s) {
    if (!s || !*s) return 1;
    size_t n = strlen(s);
    if (n < 7 || n > 259) return 0;
    if (!(isalpha((unsigned char)s[0]) && s[1] == ':' && s[2] == '\\')) return 0;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c < 0x20 || strchr("\"<>|*?%^&;,", c)) return 0;
    }
    if (strstr(s, "..")) return 0;
    return _strnicmp_portable(s + n - 4, ".exe", 4) == 0;
}

static int fwp_valid_domain(const char *s) {
    if (!s || !*s) return 1;
    size_t n = strlen(s);
    if (n > 253) return 0;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (!(isalnum(c) || c == '-' || c == '.')) return 0;
    }
    return s[0] != '.' && s[0] != '-' && strchr(s, '.') != NULL;
}

/* Returns NULL if valid, otherwise a short reason. */
static const char *fwp_validate(const FwpRule *r) {
    if (!fwp_safe_name(r->name)) return "name: use letters, digits, space, _ - . only (max 90)";
    if (r->group[0] && !fwp_safe_name(r->group)) return "group: invalid characters";
    if (r->action != FWP_ALLOW && r->action != FWP_BLOCK) return "action must be allow or block";
    if (r->dir < FWP_IN || r->dir > FWP_BOTH) return "direction invalid";
    if (r->proto < FWP_ANY || r->proto > FWP_ICMP6) return "protocol invalid";
    if (!fwp_valid_ports(r->localPorts)) return "local ports invalid (use 80,443,1000-2000)";
    if (!fwp_valid_ports(r->remotePorts)) return "remote ports invalid (use 80,443,1000-2000)";
    if ((r->localPorts[0] || r->remotePorts[0]) && r->proto != FWP_TCP && r->proto != FWP_UDP)
        return "ports require protocol TCP or UDP";
    if (!fwp_valid_addrs(r->remoteAddrs)) return "remote addresses invalid (IPv4/IPv6, CIDR, a-b, LocalSubnet, DNS...)";
    if (!fwp_valid_program(r->program)) return "program must be an absolute path ending in .exe (no special characters)";
    if (!fwp_valid_domain(r->domain)) return "domain invalid";
    if (r->priority < 1 || r->priority > 9999) return "priority must be 1..9999";
    if (r->schedStart < 0 || r->schedStart > 1439 || r->schedEnd < 0 || r->schedEnd > 1439) return "schedule time invalid";
    if (r->schedDays < 0 || r->schedDays > 127) return "schedule days invalid";
    return NULL;
}

/* ---- netsh argument building ---------------------------------------------- */
/* Builds ONE netsh command line (without "netsh.exe") for the given direction
 * (FWP_IN or FWP_OUT). Every interpolated token was validated, so no quoting
 * escape is possible. extraAddrs (resolved domain IPs) overrides remoteAddrs if non-NULL. */
static int fwp_build_add(const FwpRule *r, int dir, const char *extraAddrs, char *out, size_t n) {
    if (fwp_validate(r)) return 0;
    const char *protoS[] = { "any", "tcp", "udp", "icmpv4:any,any", "icmpv6:any,any" };
    char ifs[32] = "", prof[40] = "any";
    if (r->ifaceMask) {
        snprintf(ifs, sizeof ifs, "%s%s%s%s%s",
                 (r->ifaceMask & FWP_IF_LAN) ? "lan" : "",
                 ((r->ifaceMask & FWP_IF_LAN) && (r->ifaceMask & (FWP_IF_WIFI | FWP_IF_RAS))) ? "," : "",
                 (r->ifaceMask & FWP_IF_WIFI) ? "wireless" : "",
                 ((r->ifaceMask & FWP_IF_WIFI) && (r->ifaceMask & FWP_IF_RAS)) ? "," : "",
                 (r->ifaceMask & FWP_IF_RAS) ? "ras" : "");
    }
    if (r->profileMask) {
        snprintf(prof, sizeof prof, "%s%s%s%s%s",
                 (r->profileMask & FWP_PROF_DOMAIN) ? "domain" : "",
                 ((r->profileMask & FWP_PROF_DOMAIN) && (r->profileMask & (FWP_PROF_PRIVATE | FWP_PROF_PUBLIC))) ? "," : "",
                 (r->profileMask & FWP_PROF_PRIVATE) ? "private" : "",
                 ((r->profileMask & FWP_PROF_PRIVATE) && (r->profileMask & FWP_PROF_PUBLIC)) ? "," : "",
                 (r->profileMask & FWP_PROF_PUBLIC) ? "public" : "");
    }
    const char *addrs = (extraAddrs && *extraAddrs) ? extraAddrs : r->remoteAddrs;
    int w = snprintf(out, n, "advfirewall firewall add rule name=\"Kaevex-FW-%s-%s\" dir=%s action=%s enable=%s protocol=%s profile=%s",
                     r->name, dir == FWP_IN ? "In" : "Out", dir == FWP_IN ? "in" : "out",
                     r->action == FWP_BLOCK ? "block" : "allow", r->enabled ? "yes" : "no",
                     protoS[r->proto], prof);
    if (w < 0 || (size_t)w >= n) return 0;
    #define APP(...) do { int k_ = snprintf(out + w, n - (size_t)w, __VA_ARGS__); if (k_ < 0 || (size_t)(w + k_) >= n) return 0; w += k_; } while (0)
    if (r->program[0])     APP(" program=\"%s\"", r->program);
    if (r->localPorts[0])  APP(" localport=%s", r->localPorts);
    if (r->remotePorts[0]) APP(" remoteport=%s", r->remotePorts);
    if (addrs[0])          APP(" remoteip=%s", addrs);
    if (ifs[0])            APP(" interfacetype=%s", ifs);
    if (r->group[0])       APP(" description=\"Kaevex group: %s\"", r->group);
    #undef APP
    return 1;
}

/* ---- Complements (for allow-list style sandboxes) ------------------------- */
typedef struct { uint32_t lo, hi; } FwpRange;

static int fwp_cmp_range(const void *a, const void *b) {
    const FwpRange *x = (const FwpRange *)a, *y = (const FwpRange *)b;
    return x->lo < y->lo ? -1 : x->lo > y->lo ? 1 : 0;
}

static int fwp_merge(FwpRange *r, int n) {
    if (n <= 1) return n;
    qsort(r, (size_t)n, sizeof *r, fwp_cmp_range);
    int m = 0;
    for (int i = 1; i < n; i++) {
        if ((uint64_t)r[i].lo <= (uint64_t)r[m].hi + 1) { if (r[i].hi > r[m].hi) r[m].hi = r[i].hi; }
        else r[++m] = r[i];
    }
    return m + 1;
}

/* allowed ports -> ports to BLOCK ("1-79,81-442,444-65535"). Empty allowed => all ports. */
static int fwp_ports_complement(const char *allowed, char *out, size_t n) {
    out[0] = 0;
    if (!fwp_valid_ports(allowed)) return 0;
    FwpRange r[64]; int cnt = 0;
    const char *p = allowed;
    while (p && *p && cnt < 64) {
        char *e; long a = strtol(p, &e, 10), b = a;
        if (*e == '-') { b = strtol(e + 1, &e, 10); }
        r[cnt].lo = (uint32_t)a; r[cnt].hi = (uint32_t)b; cnt++;
        if (*e != ',') break;
        p = e + 1;
    }
    cnt = fwp_merge(r, cnt);
    size_t w = 0; uint32_t next = 1;
    for (int i = 0; i <= cnt; i++) {
        uint32_t lo = (i < cnt) ? r[i].lo : 65536;
        if (lo > next) {
            int k = (lo - 1 == next) ? snprintf(out + w, n - w, "%s%u", w ? "," : "", next)
                                     : snprintf(out + w, n - w, "%s%u-%u", w ? "," : "", next, lo - 1);
            if (k < 0 || w + (size_t)k >= n) return 0;
            w += (size_t)k;
        }
        if (i < cnt) next = r[i].hi + 1;
    }
    return 1;
}

static void fwp_fmt_ipv4(uint32_t v, char *b) { sprintf(b, "%u.%u.%u.%u", v >> 24, (v >> 16) & 255, (v >> 8) & 255, v & 255); }

/* allowed IPv4 list (single, CIDR, a-b) -> addresses to BLOCK as "a-b,c-d". IPv6 items are ignored. */
static int fwp_ipv4_complement(const char *allowed, char *out, size_t n) {
    out[0] = 0;
    if (!fwp_valid_addrs(allowed)) return 0;
    FwpRange r[64]; int cnt = 0;
    const char *p = allowed;
    while (p && *p && cnt < 64) {
        const char *e = strchr(p, ','); size_t len = e ? (size_t)(e - p) : strlen(p);
        const char *slash = memchr(p, '/', len), *dash = memchr(p, '-', len);
        uint32_t v, w;
        if (slash && fwp_parse_ipv4(p, (size_t)(slash - p), &v)) {
            int m = atoi(slash + 1);
            uint32_t mask = m == 0 ? 0 : (0xFFFFFFFFu << (32 - m));
            r[cnt].lo = v & mask; r[cnt].hi = (v & mask) | ~mask; cnt++;
        } else if (dash && fwp_parse_ipv4(p, (size_t)(dash - p), &v) &&
                   fwp_parse_ipv4(dash + 1, len - (size_t)(dash - p) - 1, &w)) {
            r[cnt].lo = v; r[cnt].hi = w; cnt++;
        } else if (fwp_parse_ipv4(p, len, &v)) { r[cnt].lo = v; r[cnt].hi = v; cnt++; }
        if (!e) break;
        p = e + 1;
    }
    cnt = fwp_merge(r, cnt);
    size_t w = 0; uint64_t next = 0;
    for (int i = 0; i <= cnt; i++) {
        uint64_t lo = (i < cnt) ? r[i].lo : 0x100000000ULL;
        if (lo > next) {
            char a[16], b[16];
            fwp_fmt_ipv4((uint32_t)next, a); fwp_fmt_ipv4((uint32_t)(lo - 1), b);
            int k = snprintf(out + w, n - w, "%s%s-%s", w ? "," : "", a, b);
            if (k < 0 || w + (size_t)k >= n) return 0;
            w += (size_t)k;
        }
        if (i < cnt) next = (uint64_t)r[i].hi + 1;
    }
    return 1;
}

/* ---- Per-application network sandbox ---------------------------------------- */
typedef struct {
    char program[260];
    int  allowInternet;      /* public addresses */
    int  allowLan;           /* RFC1918/link-local/LocalSubnet */
    char allowHosts[200];    /* IPv4 allow-list; "" with allowInternet=1 => any public host */
    char allowPorts[64];     /* "" => any port */
} FwpSandbox;

#define FWP_LAN_RANGES "10.0.0.0-10.255.255.255,172.16.0.0-172.31.255.255,192.168.0.0-192.168.255.255,169.254.0.0-169.254.255.255,LocalSubnet"

/* Compiles a sandbox into block rules (Windows Firewall: block overrides allow).
 * Returns number of rules written to out[]. */
static int fwp_sandbox_compile(const FwpSandbox *sb, const char *baseName, FwpRule *out, int maxOut) {
    int n = 0; char buf[400];
    #define NEWRULE(nm) do { if (n >= maxOut) return n; memset(&out[n], 0, sizeof(FwpRule)); \
        snprintf(out[n].name, sizeof out[n].name, "%s %s", baseName, nm); \
        snprintf(out[n].group, sizeof out[n].group, "Sandbox"); \
        out[n].priority = 100; out[n].action = FWP_BLOCK; out[n].dir = FWP_BOTH; out[n].enabled = 1; \
        snprintf(out[n].program, sizeof out[n].program, "%s", sb->program); } while (0)
    if (!sb->allowLan) {
        NEWRULE("no-LAN");
        snprintf(out[n].remoteAddrs, sizeof out[n].remoteAddrs, "%s", FWP_LAN_RANGES);
        n++;
    }
    if (!sb->allowInternet && !sb->allowHosts[0]) {
        NEWRULE("no-Internet");           /* block everything (LAN handled above) */
        n++;
    } else if (sb->allowHosts[0]) {
        if (!fwp_ipv4_complement(sb->allowHosts, buf, sizeof buf)) return -1;
        if (buf[0]) {
            if (strlen(buf) >= sizeof out[0].remoteAddrs) return -1;   /* never truncate silently */
            NEWRULE("host-allowlist");
            snprintf(out[n].remoteAddrs, sizeof out[n].remoteAddrs, "%s", buf);
            n++;
        }
    }
    if (sb->allowPorts[0]) {
        if (!fwp_ports_complement(sb->allowPorts, buf, sizeof buf)) return -1;
        if (buf[0]) {
            if (strlen(buf) >= sizeof out[0].remotePorts) return -1;   /* never truncate silently */
            NEWRULE("port-allowlist-tcp"); out[n].proto = FWP_TCP; out[n].dir = FWP_OUT;
            snprintf(out[n].remotePorts, sizeof out[n].remotePorts, "%s", buf); n++;
            NEWRULE("port-allowlist-udp"); out[n].proto = FWP_UDP; out[n].dir = FWP_OUT;
            snprintf(out[n].remotePorts, sizeof out[n].remotePorts, "%s", buf); n++;
        }
    }
    #undef NEWRULE
    return n;
}

/* ---- Policy simulation (priority + schedule) ------------------------------- */
typedef struct {
    int  dir, proto, localPort, remotePort;
    char remoteIp[48];
    char program[260];
} FwpConn;

static int fwp_port_in(const char *list, int port) {
    if (!list || !*list) return 1;
    const char *p = list;
    while (*p) {
        char *e; long a = strtol(p, &e, 10), b = a;
        if (*e == '-') b = strtol(e + 1, &e, 10);
        if (port >= a && port <= b) return 1;
        if (*e != ',') break;
        p = e + 1;
    }
    return 0;
}

static int fwp_addr_match(const char *list, const char *ip) {
    if (!list || !*list) return 1;
    uint32_t v;
    int isV4 = fwp_parse_ipv4(ip, strlen(ip), &v);
    const char *p = list;
    while (*p) {
        const char *e = strchr(p, ','); size_t n = e ? (size_t)(e - p) : strlen(p);
        const char *slash = memchr(p, '/', n), *dash = memchr(p, '-', n);
        uint32_t a, b;
        if (isV4) {
            if (slash && fwp_parse_ipv4(p, (size_t)(slash - p), &a)) {
                int m = atoi(slash + 1); uint32_t mask = m == 0 ? 0 : (0xFFFFFFFFu << (32 - m));
                if ((v & mask) == (a & mask)) return 1;
            } else if (dash && fwp_parse_ipv4(p, (size_t)(dash - p), &a) && fwp_parse_ipv4(dash + 1, n - (size_t)(dash - p) - 1, &b)) {
                if (v >= a && v <= b) return 1;
            } else if (fwp_parse_ipv4(p, n, &a) && a == v) return 1;
        } else if (strlen(ip) == n && _strnicmp_portable(p, ip, n) == 0) return 1;
        if (!e) break;
        p = e + 1;
    }
    return 0;
}

static int fwp_sched_active(const FwpRule *r, const struct tm *t) {
    if (r->schedDays && !(r->schedDays & (1 << t->tm_wday))) return 0;
    if (r->schedStart == 0 && r->schedEnd == 0) return 1;
    int m = t->tm_hour * 60 + t->tm_min;
    if (r->schedStart <= r->schedEnd) return m >= r->schedStart && m < r->schedEnd;
    return m >= r->schedStart || m < r->schedEnd;      /* overnight window */
}

static int fwp_rule_matches(const FwpRule *r, const FwpConn *c) {
    if (!r->enabled) return 0;
    if (r->dir != FWP_BOTH && r->dir != c->dir) return 0;
    if (r->proto != FWP_ANY && r->proto != c->proto) return 0;
    if (r->program[0] && _strnicmp_portable(r->program, c->program, strlen(r->program) + 1) != 0) return 0;
    if (!fwp_port_in(r->localPorts, c->localPort)) return 0;
    if (!fwp_port_in(r->remotePorts, c->remotePort)) return 0;
    if (!fwp_addr_match(r->remoteAddrs, c->remoteIp)) return 0;
    return 1;
}

/* First match by (priority, index). Returns action; *matched = index or -1 (default).
 * Defaults mirror Windows: inbound blocked, outbound allowed. */
static int fwp_eval(const FwpRule *rules, int n, const FwpConn *c, const struct tm *now, int *matched) {
    int best = -1;
    for (int i = 0; i < n; i++) {
        if (!fwp_rule_matches(&rules[i], c)) continue;
        if (now && !fwp_sched_active(&rules[i], now)) continue;
        if (best < 0 || rules[i].priority < rules[best].priority) best = i;
    }
    if (matched) *matched = best;
    if (best >= 0) return rules[best].action;
    return c->dir == FWP_IN ? FWP_BLOCK : FWP_ALLOW;
}

/* Detects rules whose Kaevex priority would be overridden by Windows' "block beats allow"
 * semantics: an ALLOW rule with better priority than a BLOCK rule that overlaps it.
 * Returns number of conflicts and fills pairs (allowIdx, blockIdx). */
static int fwp_find_conflicts(const FwpRule *rules, int n, int (*pairs)[2], int maxPairs) {
    int k = 0;
    for (int i = 0; i < n; i++) for (int j = 0; j < n; j++) {
        if (i == j || rules[i].action != FWP_ALLOW || rules[j].action != FWP_BLOCK) continue;
        if (rules[i].priority >= rules[j].priority) continue;
        if (!rules[i].enabled || !rules[j].enabled) continue;
        if (rules[i].dir != FWP_BOTH && rules[j].dir != FWP_BOTH && rules[i].dir != rules[j].dir) continue;
        if (rules[i].program[0] && rules[j].program[0] && _strnicmp_portable(rules[i].program, rules[j].program, 260) != 0) continue;
        if (rules[i].proto != FWP_ANY && rules[j].proto != FWP_ANY && rules[i].proto != rules[j].proto) continue;
        if (k < maxPairs) { pairs[k][0] = i; pairs[k][1] = j; }
        k++;
    }
    return k;
}

/* ---- pfirewall.log parser ---------------------------------------------------- */
typedef struct {
    char date[12], time[10], action[8], proto[8];
    char src[48], dst[48];
    int  sport, dport, size;
    char path[8];
    unsigned pid;     /* 0 if the column is absent */
} FwpLogEntry;

/* "2026-10-05 02:15:01 ALLOW TCP 192.168.1.5 142.250.1.1 51234 443 0 - 0 0 0 - - - SEND 4216" */
static int fwp_parse_log_line(const char *line, FwpLogEntry *e) {
    if (!line || line[0] == '#' || !isdigit((unsigned char)line[0])) return 0;
    char tmp[512]; strncpy(tmp, line, sizeof tmp - 1); tmp[sizeof tmp - 1] = 0;
    char *f[24]; int nf = 0;
    for (char *p = strtok(tmp, " \t\r\n"); p && nf < 24; p = strtok(NULL, " \t\r\n")) f[nf++] = p;
    if (nf < 8) return 0;
    memset(e, 0, sizeof *e);
    snprintf(e->date, sizeof e->date, "%s", f[0]); snprintf(e->time, sizeof e->time, "%s", f[1]);
    snprintf(e->action, sizeof e->action, "%s", f[2]); snprintf(e->proto, sizeof e->proto, "%s", f[3]);
    snprintf(e->src, sizeof e->src, "%s", f[4]); snprintf(e->dst, sizeof e->dst, "%s", f[5]);
    e->sport = f[6][0] == '-' ? 0 : atoi(f[6]);
    e->dport = f[7][0] == '-' ? 0 : atoi(f[7]);
    if (nf > 8) e->size = atoi(f[8]);
    if (nf > 16) snprintf(e->path, sizeof e->path, "%s", f[16]);
    if (nf > 17) e->pid = (unsigned)strtoul(f[17], NULL, 10);
    return 1;
}

static int fwp_log_matches(const FwpLogEntry *e, const char *needle, const char *procName) {
    if (!needle || !*needle) return 1;
    char hay[400];
    snprintf(hay, sizeof hay, "%s %s %s %s %s %d %d %s", e->date, e->time, e->action, e->proto, e->src, e->sport, e->dport,
             procName ? procName : "");
    for (char *c = hay; *c; c++) *c = (char)tolower((unsigned char)*c);
    char nd[96]; size_t i = 0;
    for (; needle[i] && i < sizeof nd - 1; i++) nd[i] = (char)tolower((unsigned char)needle[i]);
    nd[i] = 0;
    char hay2[420]; snprintf(hay2, sizeof hay2, "%s %s", hay, e->dst);
    for (char *c = hay2; *c; c++) *c = (char)tolower((unsigned char)*c);
    return strstr(hay2, nd) != NULL;
}

/* ---- Process tree ---------------------------------------------------------------- */
/* Fills out[] with rootPid and all descendants (BFS, cycle safe). Returns count. */
static int fwp_descendants(const unsigned *pid, const unsigned *ppid, int n, unsigned root, unsigned *out, int maxOut) {
    int cnt = 0;
    if (maxOut <= 0) return 0;
    out[cnt++] = root;
    for (int head = 0; head < cnt; head++) {
        for (int i = 0; i < n; i++) {
            if (ppid[i] != out[head] || pid[i] == out[head]) continue;
            int seen = 0;
            for (int k = 0; k < cnt; k++) if (out[k] == pid[i]) { seen = 1; break; }
            if (!seen && cnt < maxOut) out[cnt++] = pid[i];
        }
    }
    return cnt;
}


/* ---- Compact rule language (shared by GUI and CLI) --------------------------------------------
 *   block out tcp app="C:\Games\g.exe" rport=80,443 raddr=10.0.0.0/8 prio=10 group=Games name="Block game LAN"
 *   words:  allow|block  in|out|both  tcp|udp|icmp4|icmp6|any  off
 *   keys:   app= lport= rport= raddr= domain= prio= group= name= iface=lan,wifi,ras
 *           profile=domain,private,public  days=mon,tue,...  time=22:00-06:00
 * Returns 1 and fills r, or 0 with a reason in err. */
static int fwp_tokenize(const char *text, char (*tok)[300], int maxTok) {
    int n = 0; const char *p = text;
    while (*p && n < maxTok) {
        while (*p == ' ' || *p == '\t') p++;
        if (!*p) break;
        size_t w = 0; int inq = 0;
        while (*p && (inq || (*p != ' ' && *p != '\t'))) {
            if (*p == '"') { inq = !inq; p++; continue; }
            if (w < 299) tok[n][w++] = *p;
            p++;
        }
        if (inq) return -1;                    /* unterminated quote */
        tok[n][w] = 0; n++;
    }
    return n;
}

static int fwp_parse_list_mask(const char *v, const char **names, const int *bits, int cnt, int *out) {
    char t[64]; strncpy(t, v, 63); t[63] = 0; *out = 0;
    for (char *w = strtok(t, ","); w; w = strtok(NULL, ",")) {
        int f = 0; for (int i = 0; i < cnt; i++) if (_strnicmp_portable(w, names[i], strlen(names[i]) + 1) == 0) { *out |= bits[i]; f = 1; }
        if (!f) return 0;
    }
    return 1;
}

static int fwp_parse_rule_text(const char *text, FwpRule *r, char *err, size_t en) {
    static char tok[24][300]; int n = fwp_tokenize(text, tok, 24);
    memset(r, 0, sizeof *r); r->priority = 100; r->enabled = 1; r->dir = FWP_BOTH; r->action = -1;
    if (n < 0) { snprintf(err, en, "unterminated quote"); return 0; }
    if (n == 0) { snprintf(err, en, "empty rule"); return 0; }
    static const char *dayN[] = { "sun","mon","tue","wed","thu","fri","sat" }; static const int dayB[] = { 1,2,4,8,16,32,64 };
    static const char *ifN[] = { "lan","wifi","ras" }; static const int ifB[] = { FWP_IF_LAN, FWP_IF_WIFI, FWP_IF_RAS };
    static const char *prN[] = { "domain","private","public" }; static const int prB[] = { FWP_PROF_DOMAIN, FWP_PROF_PRIVATE, FWP_PROF_PUBLIC };
    for (int i = 0; i < n; i++) {
        char *t = tok[i], *eq = strchr(t, '=');
        if (!eq) {
            if (!_strnicmp_portable(t, "allow", 6)) r->action = FWP_ALLOW;
            else if (!_strnicmp_portable(t, "block", 6)) r->action = FWP_BLOCK;
            else if (!_strnicmp_portable(t, "in", 3)) r->dir = FWP_IN;
            else if (!_strnicmp_portable(t, "out", 4)) r->dir = FWP_OUT;
            else if (!_strnicmp_portable(t, "both", 5)) r->dir = FWP_BOTH;
            else if (!_strnicmp_portable(t, "tcp", 4)) r->proto = FWP_TCP;
            else if (!_strnicmp_portable(t, "udp", 4)) r->proto = FWP_UDP;
            else if (!_strnicmp_portable(t, "icmp4", 6)) r->proto = FWP_ICMP4;
            else if (!_strnicmp_portable(t, "icmp6", 6)) r->proto = FWP_ICMP6;
            else if (!_strnicmp_portable(t, "any", 4)) r->proto = FWP_ANY;
            else if (!_strnicmp_portable(t, "off", 4)) r->enabled = 0;
            else { snprintf(err, en, "unknown word '%.40s'", t); return 0; }
            continue;
        }
        *eq = 0; const char *k = t, *v = eq + 1;
        if (!_strnicmp_portable(k, "app", 4)) snprintf(r->program, sizeof r->program, "%s", v);
        else if (!_strnicmp_portable(k, "lport", 6)) snprintf(r->localPorts, sizeof r->localPorts, "%s", v);
        else if (!_strnicmp_portable(k, "rport", 6)) snprintf(r->remotePorts, sizeof r->remotePorts, "%s", v);
        else if (!_strnicmp_portable(k, "raddr", 6)) snprintf(r->remoteAddrs, sizeof r->remoteAddrs, "%s", v);
        else if (!_strnicmp_portable(k, "domain", 7)) snprintf(r->domain, sizeof r->domain, "%s", v);
        else if (!_strnicmp_portable(k, "group", 6)) snprintf(r->group, sizeof r->group, "%s", v);
        else if (!_strnicmp_portable(k, "name", 5)) snprintf(r->name, sizeof r->name, "%s", v);
        else if (!_strnicmp_portable(k, "prio", 5)) { char *e; long x = strtol(v, &e, 10); if (*e || !*v) { snprintf(err, en, "prio must be a number"); return 0; } r->priority = (int)x; }
        else if (!_strnicmp_portable(k, "iface", 6)) { if (!fwp_parse_list_mask(v, ifN, ifB, 3, &r->ifaceMask)) { snprintf(err, en, "iface: use lan,wifi,ras"); return 0; } }
        else if (!_strnicmp_portable(k, "profile", 8)) { if (!fwp_parse_list_mask(v, prN, prB, 3, &r->profileMask)) { snprintf(err, en, "profile: use domain,private,public"); return 0; } }
        else if (!_strnicmp_portable(k, "days", 5)) { if (!fwp_parse_list_mask(v, dayN, dayB, 7, &r->schedDays)) { snprintf(err, en, "days: use sun,mon,tue,wed,thu,fri,sat"); return 0; } }
        else if (!_strnicmp_portable(k, "time", 5)) {
            int h1, m1, h2, m2, pos = 0;
            if (sscanf(v, "%d:%d-%d:%d%n", &h1, &m1, &h2, &m2, &pos) != 4 || v[pos] || h1 < 0 || h1 > 23 || h2 < 0 || h2 > 23 || m1 < 0 || m1 > 59 || m2 < 0 || m2 > 59) { snprintf(err, en, "time: use HH:MM-HH:MM"); return 0; }
            r->schedStart = h1 * 60 + m1; r->schedEnd = h2 * 60 + m2;
        } else { snprintf(err, en, "unknown key '%.30s'", k); return 0; }
    }
    if (r->action < 0) { snprintf(err, en, "say allow or block"); return 0; }
    if (!r->name[0]) { snprintf(err, en, "name=\"...\" is required"); return 0; }
    const char *why = fwp_validate(r);
    if (why) { snprintf(err, en, "%s", why); return 0; }
    err[0] = 0; return 1;
}

static void fwp_describe(const FwpRule *r, char *o, size_t n) {
    static const char *pn[] = { "any","tcp","udp","icmp4","icmp6" }, *dn[] = { "in","out","both" };
    char sched[48] = "always";
    if (r->schedDays || r->schedStart || r->schedEnd) snprintf(sched, sizeof sched, "d%02x %02d:%02d-%02d:%02d", r->schedDays, r->schedStart / 60, r->schedStart % 60, r->schedEnd / 60, r->schedEnd % 60);
    snprintf(o, n, "%s %s %s%s%s%s%s%s%s%s [%s]%s", r->action ? "BLOCK" : "ALLOW", dn[r->dir], pn[r->proto],
             r->program[0] ? " app=" : "", r->program, r->remoteAddrs[0] ? " raddr=" : "", r->remoteAddrs,
             r->remotePorts[0] ? " rport=" : "", r->remotePorts, r->domain[0] ? " (domain)" : "", sched, r->enabled ? "" : " OFF");
}

/* ---- Adaptive baseline ------------------------------------------------------------- */
#define FWP_BL_SIZE 4096
typedef struct { char key[168]; unsigned count; time_t first, last; } FwpBlEntry;
typedef struct {
    FwpBlEntry e[FWP_BL_SIZE];
    int used;
    time_t started;
    unsigned observations;
    time_t learnSeconds;     /* before this, everything is only learned */
    unsigned minObs;         /* and at least this many observations */
} FwpBaseline;

static unsigned fwp_hash(const char *s) { unsigned h = 2166136261u; while (*s) h = (h ^ (unsigned char)*s++) * 16777619u; return h; }

/* destination bucket: IPv4 /16 (or IPv6 first 3 groups) + port class */
static void fwp_bucket(const char *exe, const char *ip, int port, char *key, size_t n) {
    char base[48]; strncpy(base, ip, sizeof base - 1); base[sizeof base - 1] = 0;
    if (strchr(base, '.')) {
        int dots = 0; for (char *c = base; *c; c++) if (*c == '.' && ++dots == 2) { *c = 0; break; }
    } else {
        int colons = 0; for (char *c = base; *c; c++) if (*c == ':' && ++colons == 3) { *c = 0; break; }
    }
    char lower[96]; size_t i = 0;
    for (; exe[i] && i < sizeof lower - 1; i++) lower[i] = (char)tolower((unsigned char)exe[i]);
    lower[i] = 0;
    snprintf(key, n, "%s|%s|%d", lower, base, port);
}

/* Records an observation. Returns 1 if this destination is NEW and the baseline is mature
 * (i.e. worth alerting), 0 otherwise. */
static int fwp_baseline_observe(FwpBaseline *b, const char *exe, const char *ip, int port, time_t now) {
    if (!b->started) b->started = now;
    char key[168]; fwp_bucket(exe, ip, port, key, sizeof key);
    unsigned h = fwp_hash(key) % FWP_BL_SIZE;
    for (int probe = 0; probe < FWP_BL_SIZE; probe++) {
        FwpBlEntry *en = &b->e[(h + (unsigned)probe) % FWP_BL_SIZE];
        if (en->key[0] == 0) {
            if (b->used >= FWP_BL_SIZE - 16) return 0;      /* table full: stop learning, never crash */
            strncpy(en->key, key, sizeof en->key - 1); en->count = 1; en->first = en->last = now; b->used++;
            b->observations++;
            return (now - b->started >= b->learnSeconds && b->observations >= b->minObs);
        }
        if (strcmp(en->key, key) == 0) { en->count++; en->last = now; b->observations++; return 0; }
    }
    return 0;
}

#endif /* FW_PRO_CORE_H */
