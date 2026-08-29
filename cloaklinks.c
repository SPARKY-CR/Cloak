/*
 * cloaklinks.c
 *
 * A companion tool to cloak: reads a batch of VLESS/Trojan/VMess
 * config links (the kind shared in Telegram channels), classifies
 * which ones can actually work through cloak's decoy technique, and
 * for the ones that can, REALLY tests whether their server currently
 * answers TLS -- not just a guess based on the link's text. Compatible
 * links get rewritten to point at cloak's local listen port, ready to
 * paste into v2rayNG.
 *
 * WHY THIS EXISTS: a link's parameters (security=tls vs reality,
 * type=ws vs grpc) only tell you whether the PROTOCOL could work
 * through a CDN cloaking proxy -- they say nothing about whether the
 * server is actually reachable right now. This tool checks both.
 *
 * BUILD:
 *   gcc -O2 -Wall -o cloaklinks cloaklinks.c -lpthread
 *
 * RUN:
 *   ./cloaklinks                  # reads ./cloaklinks.conf (auto-created)
 *   nano links.txt                # paste your links, one per line
 *   ./cloaklinks
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <signal.h>
#include <time.h>
#include <errno.h>
#include <ctype.h>
#include <poll.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>

/* ---------------------------------------------------------------
 * Logging (same minimal style as cloakscan.c)
 * ------------------------------------------------------------- */

static pthread_mutex_t g_log_lock = PTHREAD_MUTEX_INITIALIZER;

static void log_line(const char *fmt, ...) {
    pthread_mutex_lock(&g_log_lock);
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fprintf(stderr, "\n");
    pthread_mutex_unlock(&g_log_lock);
}

/* ---------------------------------------------------------------
 * Config
 * ------------------------------------------------------------- */

typedef struct {
    char links_file[256];
    char local_host[64];
    int  local_port;
    int  timeout_ms;
    int  concurrency;
    char output_path[256];
    int  include_ok;
    int  include_warn;
    int  include_reality;
    int  include_no_tls;
    int  include_not_cf;
} Config;

static Config g_cfg = {
    .links_file = "links.txt",
    .local_host = "127.0.0.1",
    .local_port = 40443,
    .timeout_ms = 3000,
    .concurrency = 10,
    .output_path = "cloaklinks_results.txt",
    .include_ok = 1,
    .include_warn = 1,
    .include_reality = 0,
    .include_no_tls = 0,
    .include_not_cf = 0,
};

static char *trim(char *s) {
    while (isspace((unsigned char)*s)) s++;
    if (*s == '\0') return s;
    char *end = s + strlen(s) - 1;
    while (end > s && isspace((unsigned char)*end)) *end-- = '\0';
    return s;
}

static void parse_output_include(const char *value) {
    g_cfg.include_ok = g_cfg.include_warn = g_cfg.include_reality =
        g_cfg.include_no_tls = g_cfg.include_not_cf = 0;

    char buf[256];
    strncpy(buf, value, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
    char *tok = strtok(buf, ",");
    while (tok) {
        char *t = trim(tok);
        if (!strcasecmp(t, "ok")) g_cfg.include_ok = 1;
        else if (!strcasecmp(t, "warn")) g_cfg.include_warn = 1;
        else if (!strcasecmp(t, "reality")) g_cfg.include_reality = 1;
        else if (!strcasecmp(t, "no_tls")) g_cfg.include_no_tls = 1;
        else if (!strcasecmp(t, "not_cloudflare")) g_cfg.include_not_cf = 1;
        else log_line("[config] unknown output_include value '%s', ignoring", t);
        tok = strtok(NULL, ",");
    }
}

static void parse_cloudflare_ranges(const char *value); /* defined below, needed here for apply_setting */

static void apply_setting(const char *key, const char *value) {
    if (!strcasecmp(key, "links_file")) strncpy(g_cfg.links_file, value, sizeof(g_cfg.links_file) - 1);
    else if (!strcasecmp(key, "local_host")) strncpy(g_cfg.local_host, value, sizeof(g_cfg.local_host) - 1);
    else if (!strcasecmp(key, "local_port")) g_cfg.local_port = atoi(value);
    else if (!strcasecmp(key, "timeout_ms")) g_cfg.timeout_ms = atoi(value);
    else if (!strcasecmp(key, "concurrency")) g_cfg.concurrency = atoi(value);
    else if (!strcasecmp(key, "output")) strncpy(g_cfg.output_path, value, sizeof(g_cfg.output_path) - 1);
    else if (!strcasecmp(key, "output_include")) parse_output_include(value);
    else if (!strcasecmp(key, "cloudflare_ranges")) parse_cloudflare_ranges(value);
    else log_line("[config] unknown key '%s', ignoring", key);
}

static int load_config(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    char line[2048];
    while (fgets(line, sizeof(line), f)) {
        char *s = trim(line);
        if (*s == '\0' || *s == '#') continue;
        char *eq = strchr(s, '=');
        if (!eq) continue;
        *eq = '\0';
        apply_setting(trim(s), trim(eq + 1));
    }
    fclose(f);
    return 0;
}

static void write_example_config(const char *path) {
    FILE *f = fopen(path, "w");
    if (!f) return;
    fprintf(f,
"# ============================================================\n"
"#  cloaklinks.conf -- classify VLESS/Trojan/VMess links and\n"
"#  check whether each server is actually on Cloudflare\n"
"# ============================================================\n"
"\n"
"# File with one config link per line. To fill it: open this file\n"
"# in a text editor (e.g. `nano links.txt`), paste your links with\n"
"# the keyboard's Paste option, save. Blank lines and lines\n"
"# starting with # are ignored.\n"
"links_file = links.txt\n"
"\n"
"# Where cloak is listening -- compatible links get rewritten to\n"
"# point here instead of their original server address.\n"
"local_host = 127.0.0.1\n"
"local_port = 40443\n"
"\n"
"# Max simultaneous DNS lookups in flight (each link's host needs\n"
"# resolving to an IP before it can be checked against the ranges\n"
"# below).\n"
"concurrency = 10\n"
"\n"
"# Cloudflare's published IP ranges (IPv4 + IPv6) -- a link's server\n"
"# is only useful for cloak's technique if its address actually\n"
"# falls in here. Defaults to Cloudflare's current ranges; check\n"
"# https://www.cloudflare.com/ips/ if these ever go stale.\n"
"cloudflare_ranges = 104.16.0.0/13, 104.24.0.0/14, 172.64.0.0/13, 131.0.72.0/22, 2606:4700::/32, 2803:f800::/32, 2405:b500::/32, 2a06:98c0::/29, 2c0f:f248::/32\n"
"\n"
"# Where to write the results.\n"
"output = cloaklinks_results.txt\n"
"\n"
"# Which categories to actually include in the output file, comma-\n"
"# separated. The categories are:\n"
"#   ok             - WebSocket+TLS AND on a Cloudflare IP -- ready to use\n"
"#   warn           - other transport (e.g. gRPC), on a Cloudflare IP --\n"
"#                    might work, untested territory through a CDN\n"
"#   reality        - Reality security, incompatible with CDN routing\n"
"#   no_tls         - no TLS at all, cloak has no SNI to hide, dead end\n"
"#   not_cloudflare - protocol looked fine, but the server's IP isn't\n"
"#                    actually on Cloudflare, so cloak's technique\n"
"#                    doesn't apply here regardless of how fast/alive\n"
"#                    the server currently is\n"
"# Categories left out still get logged to the terminal and counted\n"
"# in the summary -- they're just not written into the output file.\n"
"output_include = ok, warn\n"
    );
    fclose(f);
}

/* ---------------------------------------------------------------
 * Minimal base64 (for decoding vmess:// links, which wrap a JSON
 * blob in standard base64 rather than URI authority syntax)
 * ------------------------------------------------------------- */

static int b64_val(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+' || c == '-') return 62;
    if (c == '/' || c == '_') return 63;
    return -1;
}

static int base64_decode(const char *in, uint8_t *out, size_t out_cap) {
    size_t out_len = 0;
    int val = 0, bits = -8;
    for (const char *p = in; *p; p++) {
        if (*p == '=' || isspace((unsigned char)*p)) continue;
        int v = b64_val(*p);
        if (v < 0) continue; /* skip anything unexpected rather than fail */
        val = (val << 6) + v;
        bits += 6;
        if (bits >= 0) {
            if (out_len >= out_cap) return -1;
            out[out_len++] = (uint8_t)((val >> bits) & 0xFF);
            bits -= 8;
        }
    }
    if (out_len >= out_cap) return -1;
    out[out_len] = '\0';
    return (int)out_len;
}

/* Extracts a string field like "add":"1.2.3.4" or a numeric field
 * like "port":443 from vmess's flat JSON. Not a real JSON parser --
 * deliberately simple pattern search, which is fine since we trust
 * this is v2ray-generated JSON, not arbitrary untrusted input. */
static int json_get_string(const char *json, const char *key, char *out, size_t out_cap) {
    char pattern[64];
    snprintf(pattern, sizeof(pattern), "\"%s\"", key);
    const char *p = strstr(json, pattern);
    if (!p) return 0;
    p = strchr(p + strlen(pattern), ':');
    if (!p) return 0;
    p++;
    while (isspace((unsigned char)*p)) p++;
    if (*p != '"') return 0;
    p++;
    size_t i = 0;
    while (*p && *p != '"' && i < out_cap - 1) out[i++] = *p++;
    out[i] = '\0';
    return 1;
}

/* ---------------------------------------------------------------
 * Link record: everything we know about one parsed link
 * ------------------------------------------------------------- */

typedef enum { LINK_VLESS, LINK_TROJAN, LINK_VMESS, LINK_UNKNOWN } LinkProto;
typedef enum { STATUS_OK, STATUS_WARN, STATUS_REALITY, STATUS_NO_TLS, STATUS_NOT_CF } LinkStatus;

typedef struct {
    char original[2048];
    char name[256];
    LinkProto proto;
    char host[256];
    int  port;
    LinkStatus status;
    char reason[320];
    char rewritten[4096]; /* only valid if status is OK/WARN and reachable */
} LinkResult;

#define MAX_LINKS 512
static LinkResult g_links[MAX_LINKS];
static int g_link_count = 0;

/* ---------------------------------------------------------------
 * Parsing + classification for vless:// and trojan:// (URI-shaped)
 * ------------------------------------------------------------- */

static int get_query_param(const char *query, const char *key, char *out, size_t out_cap) {
    size_t klen = strlen(key);
    const char *p = query;
    while (p && *p) {
        const char *eq = strchr(p, '=');
        const char *amp = strchr(p, '&');
        if (!eq) break;
        size_t name_len = (size_t)(eq - p);
        if (name_len == klen && !strncasecmp(p, key, klen)) {
            const char *val_start = eq + 1;
            size_t val_len = amp ? (size_t)(amp - val_start) : strlen(val_start);
            if (val_len >= out_cap) val_len = out_cap - 1;
            strncpy(out, val_start, val_len);
            out[val_len] = '\0';
            return 1;
        }
        if (!amp) break;
        p = amp + 1;
    }
    return 0;
}

static void classify_uri_link(LinkResult *r, const char *security, const char *type) {
    if (!strcasecmp(security, "reality")) {
        r->status = STATUS_REALITY;
        strncpy(r->reason, "Reality -- needs a direct connection, incompatible with CDN routing", sizeof(r->reason) - 1);
    } else if (security[0] == '\0' || !strcasecmp(security, "none")) {
        r->status = STATUS_NO_TLS;
        strncpy(r->reason, "no TLS -- nothing for cloak to hide an SNI inside of", sizeof(r->reason) - 1);
    } else if (!strcasecmp(type, "ws") && !strcasecmp(security, "tls")) {
        r->status = STATUS_OK;
        strncpy(r->reason, "WebSocket + TLS -- compatible", sizeof(r->reason) - 1);
    } else {
        r->status = STATUS_WARN;
        snprintf(r->reason, sizeof(r->reason), "transport=%s, security=%s -- uncertain through a CDN", type, security);
    }
}

/* Parses vless:// or trojan:// links: scheme://userinfo@host:port?query#fragment */
static int parse_uri_link(const char *line, LinkResult *r) {
    const char *scheme_end = strstr(line, "://");
    if (!scheme_end) return 0;
    size_t scheme_len = (size_t)(scheme_end - line);

    if (scheme_len == 5 && !strncasecmp(line, "vless", 5)) r->proto = LINK_VLESS;
    else if (scheme_len == 6 && !strncasecmp(line, "trojan", 6)) r->proto = LINK_TROJAN;
    else return 0;

    const char *authority = scheme_end + 3;
    const char *at = strchr(authority, '@');
    if (!at) return 0; /* userinfo (uuid/password) is required for our purposes */
    const char *host_start = at + 1;

    const char *query_start = strchr(host_start, '?');
    const char *frag_start = strchr(host_start, '#');
    const char *authority_end = query_start ? query_start : (frag_start ? frag_start : host_start + strlen(host_start));

    char hostport[300];
    size_t hp_len = (size_t)(authority_end - host_start);
    if (hp_len >= sizeof(hostport)) hp_len = sizeof(hostport) - 1;
    strncpy(hostport, host_start, hp_len);
    hostport[hp_len] = '\0';

    /* host:port, or [ipv6]:port */
    if (hostport[0] == '[') {
        char *close = strchr(hostport, ']');
        if (!close) return 0;
        size_t hl = (size_t)(close - hostport - 1);
        if (hl >= sizeof(r->host)) hl = sizeof(r->host) - 1;
        strncpy(r->host, hostport + 1, hl);
        r->host[hl] = '\0';
        r->port = (*(close + 1) == ':') ? atoi(close + 2) : 443;
    } else {
        char *colon = strrchr(hostport, ':');
        if (colon) {
            size_t hl = (size_t)(colon - hostport);
            if (hl >= sizeof(r->host)) hl = sizeof(r->host) - 1;
            strncpy(r->host, hostport, hl);
            r->host[hl] = '\0';
            r->port = atoi(colon + 1);
        } else {
            strncpy(r->host, hostport, sizeof(r->host) - 1);
            r->port = 443;
        }
    }

    char query[1024] = "";
    if (query_start) {
        const char *qend = frag_start ? frag_start : query_start + strlen(query_start);
        size_t qlen = (size_t)(qend - (query_start + 1));
        if (qlen >= sizeof(query)) qlen = sizeof(query) - 1;
        strncpy(query, query_start + 1, qlen);
        query[qlen] = '\0';
    }

    if (frag_start) {
        strncpy(r->name, frag_start + 1, sizeof(r->name) - 1);
    } else {
        strncpy(r->name, "(unnamed)", sizeof(r->name) - 1);
    }

    char security[32] = "", type[32] = "";
    get_query_param(query, "security", security, sizeof(security));
    get_query_param(query, "type", type, sizeof(type));
    if (security[0] == '\0' && r->proto == LINK_TROJAN) strncpy(security, "tls", sizeof(security) - 1);
    if (type[0] == '\0') strncpy(type, "tcp", sizeof(type) - 1);

    classify_uri_link(r, security, type);

    /* Only build the rewritten link for statuses that will actually
     * be offered for use -- REALITY/NO_TLS links are dead ends
     * regardless of reachability, so we deliberately leave
     * r->rewritten empty for them (already zeroed by memset in
     * main()) rather than compute a rewrite nobody should paste in. */
    if (r->status == STATUS_OK || r->status == STATUS_WARN) {
        char before_host[2048];
        size_t before_len = (size_t)(at + 1 - line);
        if (before_len >= sizeof(before_host)) before_len = sizeof(before_host) - 1;
        strncpy(before_host, line, before_len);
        before_host[before_len] = '\0';

        snprintf(r->rewritten, sizeof(r->rewritten), "%s%s:%d%s",
                 before_host, g_cfg.local_host, g_cfg.local_port,
                 authority_end); /* keeps ?query#fragment verbatim */
    }

    return 1;
}

/* Parses vmess:// links: base64-encoded JSON blob */
static int parse_vmess_link(const char *line, LinkResult *r) {
    if (strncasecmp(line, "vmess://", 8) != 0) return 0;
    r->proto = LINK_VMESS;

    uint8_t decoded[2048];
    int n = base64_decode(line + 8, decoded, sizeof(decoded));
    if (n <= 0) {
        r->status = STATUS_NO_TLS;
        strncpy(r->reason, "vmess payload wasn't valid base64/JSON", sizeof(r->reason) - 1);
        strncpy(r->name, "(unreadable)", sizeof(r->name) - 1);
        return 1;
    }
    const char *json = (const char *)decoded;

    char add[256] = "", port_s[16] = "", net[32] = "", tls[32] = "", ps[256] = "";
    json_get_string(json, "add", add, sizeof(add));
    json_get_string(json, "port", port_s, sizeof(port_s));
    json_get_string(json, "net", net, sizeof(net));
    json_get_string(json, "tls", tls, sizeof(tls));
    json_get_string(json, "ps", ps, sizeof(ps));

    strncpy(r->host, add, sizeof(r->host) - 1);
    r->port = atoi(port_s);
    strncpy(r->name, ps[0] ? ps : "(unnamed)", sizeof(r->name) - 1);

    if (tls[0] == '\0' || !strcasecmp(tls, "none")) {
        r->status = STATUS_NO_TLS;
        strncpy(r->reason, "no TLS -- nothing for cloak to hide an SNI inside of", sizeof(r->reason) - 1);
    } else if (!strcasecmp(net, "ws") && !strcasecmp(tls, "tls")) {
        r->status = STATUS_OK;
        strncpy(r->reason, "WebSocket + TLS -- compatible", sizeof(r->reason) - 1);
    } else {
        r->status = STATUS_WARN;
        snprintf(r->reason, sizeof(r->reason), "net=%s, tls=%s -- uncertain through a CDN", net, tls);
    }

    /* Only build the rewritten link for statuses that will actually
     * be offered for use -- a NO_TLS vmess link is a dead end
     * regardless of reachability, so we deliberately skip building
     * r->rewritten for it (already left empty by memset in main()). */
    if (r->status == STATUS_OK || r->status == STATUS_WARN) {
        /* Rebuild the JSON with add/port swapped, re-encode. Simple
         * string substitution rather than round-tripping through a
         * JSON writer -- fine since we already located the exact
         * substrings. */
        char rebuilt[2048];
        strncpy(rebuilt, json, sizeof(rebuilt) - 1);
        rebuilt[sizeof(rebuilt) - 1] = '\0';

        char *add_pos = strstr(rebuilt, "\"add\"");
        if (add_pos) {
            char *colon = strchr(add_pos, ':');
            char *quote1 = colon ? strchr(colon, '"') : NULL;
            char *quote2 = quote1 ? strchr(quote1 + 1, '"') : NULL;
            if (quote1 && quote2) {
                char tail[2048];
                strncpy(tail, quote2, sizeof(tail) - 1);
                tail[sizeof(tail) - 1] = '\0';
                snprintf(quote1, sizeof(rebuilt) - (size_t)(quote1 - rebuilt), "\"%s%s", g_cfg.local_host, tail);
            }
        }
        char *port_pos = strstr(rebuilt, "\"port\"");
        if (port_pos) {
            char *colon = strchr(port_pos, ':');
            if (colon) {
                colon++;
                while (isspace((unsigned char)*colon)) colon++;
                char *num_start = colon;
                int in_quotes = (*num_start == '"');
                if (in_quotes) num_start++;
                char *num_end = num_start;
                while (isdigit((unsigned char)*num_end)) num_end++;
                char tail[2048];
                strncpy(tail, num_end, sizeof(tail) - 1);
                tail[sizeof(tail) - 1] = '\0';
                snprintf(num_start, sizeof(rebuilt) - (size_t)(num_start - rebuilt), "%d%s", g_cfg.local_port, tail);
            }
        }

        char b64out[3072];
        /* simple standard base64 encoder */
        static const char *tbl = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        size_t rlen = strlen(rebuilt);
        size_t oi = 0;
        for (size_t i = 0; i < rlen; i += 3) {
            unsigned int a = (unsigned char)rebuilt[i];
            unsigned int b = (i + 1 < rlen) ? (unsigned char)rebuilt[i + 1] : 0;
            unsigned int c = (i + 2 < rlen) ? (unsigned char)rebuilt[i + 2] : 0;
            unsigned int triple = (a << 16) | (b << 8) | c;
            if (oi + 4 >= sizeof(b64out)) break;
            b64out[oi++] = tbl[(triple >> 18) & 0x3F];
            b64out[oi++] = tbl[(triple >> 12) & 0x3F];
            b64out[oi++] = (i + 1 < rlen) ? tbl[(triple >> 6) & 0x3F] : '=';
            b64out[oi++] = (i + 2 < rlen) ? tbl[triple & 0x3F] : '=';
        }
        b64out[oi] = '\0';
        snprintf(r->rewritten, sizeof(r->rewritten), "vmess://%s", b64out);
    }

    return 1;
}

/* ---------------------------------------------------------------
 * Cloudflare IP-range containment check
 *
 * Instead of testing whether the server currently answers (that's
 * what v2rayNG's own latency test already does), this checks a
 * narrower and more relevant question: is the config's IP actually
 * inside Cloudflare's published ranges at all? cloak's whole
 * technique only makes sense against a Cloudflare-fronted server --
 * a config on a plain VPS would never benefit from it regardless of
 * how fast or reachable it is right now.
 * ------------------------------------------------------------- */

#define MAX_CF_RANGES 32

typedef struct {
    int family;              /* AF_INET or AF_INET6 */
    uint32_t v4_base;        /* host byte order, IPv4 only */
    struct in6_addr v6_base; /* IPv6 only */
    int prefix;
} CfRange;

static CfRange g_cf_ranges[MAX_CF_RANGES];
static int g_cf_range_count = 0;

static void parse_cloudflare_ranges(const char *value) {
    char buf[2048];
    strncpy(buf, value, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    g_cf_range_count = 0;
    char *tok = strtok(buf, ",");
    while (tok && g_cf_range_count < MAX_CF_RANGES) {
        char *t = trim(tok);
        char *slash = strchr(t, '/');
        if (!slash) { tok = strtok(NULL, ","); continue; }
        *slash = '\0';
        int prefix = atoi(slash + 1);
        int is_v6 = (strchr(t, ':') != NULL);

        CfRange *r = &g_cf_ranges[g_cf_range_count];
        if (is_v6) {
            struct in6_addr a6;
            if (inet_pton(AF_INET6, t, &a6) != 1) { tok = strtok(NULL, ","); continue; }
            r->family = AF_INET6;
            r->v6_base = a6;
            r->prefix = prefix;
        } else {
            struct in_addr a4;
            if (inet_pton(AF_INET, t, &a4) != 1) { tok = strtok(NULL, ","); continue; }
            r->family = AF_INET;
            r->v4_base = ntohl(a4.s_addr);
            r->prefix = prefix;
        }
        g_cf_range_count++;
        tok = strtok(NULL, ",");
    }
}

static int ip_in_range(struct sockaddr *addr, const CfRange *r) {
    if (addr->sa_family != r->family) return 0;

    if (r->family == AF_INET) {
        uint32_t ip = ntohl(((struct sockaddr_in *)addr)->sin_addr.s_addr);
        uint32_t mask = (r->prefix == 0) ? 0 : (0xFFFFFFFFu << (32 - r->prefix));
        return (ip & mask) == (r->v4_base & mask);
    } else {
        uint8_t *ip_bytes = ((struct sockaddr_in6 *)addr)->sin6_addr.s6_addr;
        const uint8_t *base_bytes = r->v6_base.s6_addr;
        for (int byte = 0; byte < 16; byte++) {
            int bit_start = byte * 8;
            if (bit_start >= r->prefix) break; /* past the network part, matched so far */
            if (bit_start + 8 <= r->prefix) {
                if (ip_bytes[byte] != base_bytes[byte]) return 0;
            } else {
                int network_bits_here = r->prefix - bit_start;
                uint8_t mask = (uint8_t)(0xFF << (8 - network_bits_here));
                if ((ip_bytes[byte] & mask) != (base_bytes[byte] & mask)) return 0;
            }
        }
        return 1;
    }
}

/* Resolves host (which may be a domain name -- unlike cloak/cloakscan,
 * links commonly use real domains, not just raw IPs) and checks
 * whether ANY of its resolved addresses fall inside a configured
 * Cloudflare range. */
static int host_is_cloudflare(const char *host) {
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(host, NULL, &hints, &res) != 0) return 0;

    int found = 0;
    for (struct addrinfo *rp = res; rp != NULL && !found; rp = rp->ai_next) {
        for (int i = 0; i < g_cf_range_count && !found; i++) {
            if (ip_in_range(rp->ai_addr, &g_cf_ranges[i])) found = 1;
        }
    }
    freeaddrinfo(res);
    return found;
}

/* ---------------------------------------------------------------
 * Bounded-concurrency worker pool (same pattern as cloakscan.c)
 * ------------------------------------------------------------- */

typedef struct {
    int count, max;
    pthread_mutex_t lock;
    pthread_cond_t cond;
} Semaphore;

static void sem_init_custom(Semaphore *s, int max) {
    s->count = 0; s->max = max;
    pthread_mutex_init(&s->lock, NULL);
    pthread_cond_init(&s->cond, NULL);
}
static void sem_acquire(Semaphore *s) {
    pthread_mutex_lock(&s->lock);
    while (s->count >= s->max) pthread_cond_wait(&s->cond, &s->lock);
    s->count++;
    pthread_mutex_unlock(&s->lock);
}
static void sem_release(Semaphore *s) {
    pthread_mutex_lock(&s->lock);
    s->count--;
    pthread_cond_signal(&s->cond);
    pthread_mutex_unlock(&s->lock);
}

static Semaphore g_sem;
static int g_tested = 0;
static pthread_mutex_t g_progress_lock = PTHREAD_MUTEX_INITIALIZER;

static const char *status_tag(LinkStatus s) {
    switch (s) {
        case STATUS_OK: return "OK   ";
        case STATUS_WARN: return "WARN ";
        case STATUS_REALITY: return "SKIP ";
        case STATUS_NO_TLS: return "SKIP ";
        default: return "FAIL ";
    }
}

static void *test_worker(void *arg) {
    LinkResult *r = (LinkResult *)arg;

    if (r->status == STATUS_OK || r->status == STATUS_WARN) {
        int on_cf = host_is_cloudflare(r->host);
        if (!on_cf) {
            r->status = STATUS_NOT_CF;
            snprintf(r->reason, sizeof(r->reason), "%s does not resolve to a Cloudflare IP", r->host);
            r->rewritten[0] = '\0'; /* cloak's technique doesn't apply to a non-Cloudflare server */
        }
    }

    pthread_mutex_lock(&g_progress_lock);
    g_tested++;
    log_line("[%s %3d/%-3d] %-28s -- %s", status_tag(r->status), g_tested, g_link_count, r->name, r->reason);
    pthread_mutex_unlock(&g_progress_lock);

    sem_release(&g_sem);
    return NULL;
}

/* ---------------------------------------------------------------
 * main
 * ------------------------------------------------------------- */

static void write_results(void) {
    FILE *f = fopen(g_cfg.output_path, "w");
    if (!f) { log_line("error: cannot open output file '%s'", g_cfg.output_path); return; }

    fprintf(f, "# cloaklinks results -- generated %ld\n", (long)time(NULL));
    fprintf(f, "# rewritten links point at %s:%d -- paste directly into v2rayNG\n\n",
            g_cfg.local_host, g_cfg.local_port);

    struct { LinkStatus status; const char *title; int include; } sections[] = {
        { STATUS_OK, "compatible", g_cfg.include_ok },
        { STATUS_WARN, "uncertain", g_cfg.include_warn },
        { STATUS_REALITY, "reality -- incompatible, not rewritten", g_cfg.include_reality },
        { STATUS_NO_TLS, "no-tls -- can't work at all, not rewritten", g_cfg.include_no_tls },
        { STATUS_NOT_CF, "not on Cloudflare, not rewritten", g_cfg.include_not_cf },
    };

    for (size_t s = 0; s < sizeof(sections)/sizeof(sections[0]); s++) {
        if (!sections[s].include) continue;
        int count = 0;
        for (int i = 0; i < g_link_count; i++) if (g_links[i].status == sections[s].status) count++;
        if (count == 0) continue;

        fprintf(f, "## %s (%d)\n", sections[s].title, count);
        for (int i = 0; i < g_link_count; i++) {
            if (g_links[i].status != sections[s].status) continue;
            if (g_links[i].rewritten[0])
                fprintf(f, "%s\n", g_links[i].rewritten);
            else
                fprintf(f, "# %s\n", g_links[i].name);
        }
        fprintf(f, "\n");
    }
    fclose(f);
}

int main(int argc, char **argv) {
    srand((unsigned)time(NULL));

    const char *config_path = (argc > 1) ? argv[1] : "cloaklinks.conf";
    FILE *check = fopen(config_path, "r");
    if (!check) {
        printf("no config found at '%s' -- writing a starter one.\n", config_path);
        write_example_config(config_path);
        printf("edit it, then run this program again.\n");
        return 0;
    }
    fclose(check);
    load_config(config_path);
    if (g_cf_range_count == 0) {
        parse_cloudflare_ranges(
            "104.16.0.0/13,104.24.0.0/14,172.64.0.0/13,131.0.72.0/22,"
            "2606:4700::/32,2803:f800::/32,2405:b500::/32,2a06:98c0::/29,2c0f:f248::/32");
    }

    FILE *lf = fopen(g_cfg.links_file, "r");
    if (!lf) {
        log_line("error: could not open links_file '%s'", g_cfg.links_file);
        return 1;
    }

    int lines_read = 0;
    int lines_skipped = 0;
    char line[2048];
    while (g_link_count < MAX_LINKS && fgets(line, sizeof(line), lf)) {
        char *s = trim(line);
        if (*s == '\0' || *s == '#') continue;
        lines_read++;

        LinkResult *r = &g_links[g_link_count];
        memset(r, 0, sizeof(*r));
        strncpy(r->original, s, sizeof(r->original) - 1);

        int parsed = 0;
        if (!strncasecmp(s, "vless://", 8) || !strncasecmp(s, "trojan://", 9)) {
            parsed = parse_uri_link(s, r);
            if (!parsed) log_line("[SKIP] malformed vless/trojan link (missing @ or unparseable): %.47s...", s);
        } else if (!strncasecmp(s, "vmess://", 8)) {
            parsed = parse_vmess_link(s, r);
            if (!parsed) log_line("[SKIP] malformed vmess link: %.47s...", s);
        } else {
            char preview[48];
            strncpy(preview, s, sizeof(preview) - 1);
            preview[sizeof(preview) - 1] = '\0';
            log_line("[SKIP] unsupported scheme (only vless/trojan/vmess): %s...", preview);
        }

        if (!parsed) {
            lines_skipped++;
            continue;
        }
        g_link_count++;
    }
    fclose(lf);

    if (lines_skipped > 0) {
        log_line("note: %d of %d lines couldn't be parsed and were skipped (see [SKIP] lines above)\n",
                  lines_skipped, lines_read);
    }

    if (g_link_count == 0) {
        log_line("error: no recognizable links found in '%s'", g_cfg.links_file);
        return 1;
    }

    log_line("cloaklinks: testing %d links from %s (target: %s:%d)\n",
             g_link_count, g_cfg.links_file, g_cfg.local_host, g_cfg.local_port);

    sem_init_custom(&g_sem, g_cfg.concurrency);
    pthread_t threads[MAX_LINKS];
    for (int i = 0; i < g_link_count; i++) {
        sem_acquire(&g_sem);
        pthread_create(&threads[i], NULL, test_worker, &g_links[i]);
    }
    for (int i = 0; i < g_link_count; i++) pthread_join(threads[i], NULL);

    int c_ok = 0, c_warn = 0, c_reality = 0, c_no_tls = 0, c_notcf = 0;
    for (int i = 0; i < g_link_count; i++) {
        switch (g_links[i].status) {
            case STATUS_OK: c_ok++; break;
            case STATUS_WARN: c_warn++; break;
            case STATUS_REALITY: c_reality++; break;
            case STATUS_NO_TLS: c_no_tls++; break;
            case STATUS_NOT_CF: c_notcf++; break;
        }
    }

    write_results();

    log_line("\ndone: %d tested -- %d ok, %d warn, %d no-tls, %d reality, %d unreachable",
             g_link_count, c_ok, c_warn, c_no_tls, c_reality, c_notcf);
    log_line("results written to %s", g_cfg.output_path);

    return 0;
}
