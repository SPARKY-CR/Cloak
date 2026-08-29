/*
 * cloakscan.c
 *
 * A companion tool to cloak: scans a Cloudflare (or any CDN) IP range
 * against a list of candidate SNI domains, and reports which
 * (IP, SNI) combinations are actually reachable and answer with a
 * real TLS response right now -- output is ready to paste straight
 * into cloak.conf's connect_list / sni_list.
 *
 * WHY THIS EXISTS: cloak itself never discovers new IPs -- you give
 * it a fixed connect_list and it just races/learns among those. When
 * every IP in that list gets blocked (which happens regularly, since
 * popular "clean IP" lists get noticed and blocked), you need a way
 * to find fresh ones. That's what this does.
 *
 * HOW IT DECIDES "WORKING": for each (ip, sni) pair, it opens a
 * normal TCP connection, sends a real TLS ClientHello with that SNI,
 * and checks whether it gets back something that looks like the
 * start of a real TLS ServerHello (record type 0x16). If yes, that
 * IP is currently not blocked and is actually terminating TLS for
 * that SNI (or at least responding to it) -- a reasonable candidate.
 * This does NOT guarantee it will stay unblocked, or that a specific
 * DPI system won't still catch it another way -- it's a snapshot of
 * "reachable right now", nothing more.
 *
 * BUILD:
 *   gcc -O2 -Wall -o cloakscan cloakscan.c -lpthread
 *
 * RUN:
 *   ./cloakscan                  # reads ./cloakscan.conf (auto-created)
 *   ./cloakscan other.conf
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <netinet/in.h>
#include <arpa/inet.h>
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
 * Minimal logging (same style as cloak.c, kept self-contained here
 * so this file compiles standalone without depending on cloak.c)
 * ------------------------------------------------------------- */

static pthread_mutex_t g_log_lock = PTHREAD_MUTEX_INITIALIZER;

static void log_line(const char *fmt, ...) {
    pthread_mutex_lock(&g_log_lock);
    time_t now = time(NULL);
    struct tm tmv;
    localtime_r(&now, &tmv);
    char timestr[16];
    strftime(timestr, sizeof(timestr), "%H:%M:%S", &tmv);
    fprintf(stderr, "%s ", timestr);
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fprintf(stderr, "\n");
    pthread_mutex_unlock(&g_log_lock);
}

/* ---------------------------------------------------------------
 * Thread-safe random (see cloak.c for the full explanation of why
 * plain rand() is unsafe across threads)
 * ------------------------------------------------------------- */

static __thread unsigned int t_seed;
static __thread int t_seeded = 0;

static unsigned int safe_rand(void) {
    if (!t_seeded) {
        t_seed = (unsigned int)(time(NULL) ^ (uintptr_t)pthread_self());
        t_seeded = 1;
    }
    return (unsigned int)rand_r(&t_seed);
}

/* ---------------------------------------------------------------
 * Config
 * ------------------------------------------------------------- */

#define MAX_RANGES 16
#define MAX_SNIS   32
#define MAX_PORTS  8

typedef struct {
    int family;             /* AF_INET or AF_INET6 */
    uint32_t v4_base;       /* network address, host byte order (IPv4 only) */
    struct in6_addr v6_base;/* network address (IPv6 only) */
    int prefix;             /* CIDR prefix length */
} IpRange;

typedef struct {
    IpRange ranges[MAX_RANGES];
    int     range_count;

    char sni_list[MAX_SNIS][256];
    int  sni_count;

    int  ports[MAX_PORTS];
    int  port_count; /* one is picked at random per probe, same as sni_list */
    int samples_per_range; /* how many random IPs to try per range */
    int concurrency;       /* max simultaneous probes */
    int timeout_ms;
    char output_path[256];

    int  auto_update;         /* write results straight into cloak.conf */
    char cloak_conf_path[256];
    int  max_servers_write;   /* cap, should match cloak.c's MAX_SERVER_LIST */
    int  max_snis_write;      /* cap, should match cloak.c's MAX_SNI_LIST */
    int  prune_dead_entries;  /* re-test existing connect_list entries, drop dead ones */
} ScanConfig;

static ScanConfig g_cfg = {
    .range_count = 0,
    .sni_count = 0,
    .port_count = 0,
    .samples_per_range = 40,
    .concurrency = 20,
    .timeout_ms = 2000,
    .output_path = "cloakscan_results.txt",
    .auto_update = 1,
    .cloak_conf_path = "cloak.conf",
    .max_servers_write = 8,
    .max_snis_write = 12,
    .prune_dead_entries = 1,
};

static char *trim(char *s) {
    while (isspace((unsigned char)*s)) s++;
    if (*s == '\0') return s;
    char *end = s + strlen(s) - 1;
    while (end > s && isspace((unsigned char)*end)) *end-- = '\0';
    return s;
}

static void parse_ranges(const char *value) {
    char buf[1024];
    strncpy(buf, value, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    g_cfg.range_count = 0;
    char *tok = strtok(buf, ",");
    while (tok && g_cfg.range_count < MAX_RANGES) {
        char *t = trim(tok);
        char *slash = strchr(t, '/');
        if (!slash) {
            log_line("[config] '%s' is not CIDR (missing /prefix), skipping", t);
            tok = strtok(NULL, ",");
            continue;
        }
        *slash = '\0';
        int prefix = atoi(slash + 1);

        /* An IPv6 literal always contains ':'; IPv4 never does. That's
         * the simplest reliable way to tell which parser to use. */
        int is_v6 = (strchr(t, ':') != NULL);

        IpRange *r = &g_cfg.ranges[g_cfg.range_count];
        if (is_v6) {
            struct in6_addr a6;
            if (inet_pton(AF_INET6, t, &a6) != 1) {
                log_line("[config] '%s' is not a valid IPv6 base, skipping", t);
                tok = strtok(NULL, ",");
                continue;
            }
            if (prefix < 8 || prefix > 128) {
                log_line("[config] IPv6 prefix /%d out of supported range (8-128), skipping", prefix);
                tok = strtok(NULL, ",");
                continue;
            }
            r->family = AF_INET6;
            r->v6_base = a6;
            r->prefix = prefix;
        } else {
            struct in_addr a4;
            if (inet_pton(AF_INET, t, &a4) != 1) {
                log_line("[config] '%s' is not a valid IPv4 base, skipping", t);
                tok = strtok(NULL, ",");
                continue;
            }
            if (prefix < 8 || prefix > 30) {
                log_line("[config] IPv4 prefix /%d out of supported range (8-30), skipping", prefix);
                tok = strtok(NULL, ",");
                continue;
            }
            r->family = AF_INET;
            r->v4_base = ntohl(a4.s_addr);
            r->prefix = prefix;
        }
        g_cfg.range_count++;
        tok = strtok(NULL, ",");
    }
}

static void parse_snis(const char *value) {
    char buf[2048];
    strncpy(buf, value, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    g_cfg.sni_count = 0;
    char *tok = strtok(buf, ",");
    while (tok && g_cfg.sni_count < MAX_SNIS) {
        strncpy(g_cfg.sni_list[g_cfg.sni_count], trim(tok), 255);
        g_cfg.sni_count++;
        tok = strtok(NULL, ",");
    }
}

static void parse_ports(const char *value) {
    char buf[256];
    strncpy(buf, value, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    g_cfg.port_count = 0;
    char *tok = strtok(buf, ",");
    while (tok && g_cfg.port_count < MAX_PORTS) {
        g_cfg.ports[g_cfg.port_count++] = atoi(trim(tok));
        tok = strtok(NULL, ",");
    }
}

static void apply_setting(const char *key, const char *value) {
    if (!strcasecmp(key, "ranges")) parse_ranges(value);
    else if (!strcasecmp(key, "sni_list")) parse_snis(value);
    else if (!strcasecmp(key, "ports")) parse_ports(value);
    else if (!strcasecmp(key, "port")) parse_ports(value); /* old singular key, still accepted */
    else if (!strcasecmp(key, "samples_per_range")) g_cfg.samples_per_range = atoi(value);
    else if (!strcasecmp(key, "concurrency")) g_cfg.concurrency = atoi(value);
    else if (!strcasecmp(key, "timeout_ms")) g_cfg.timeout_ms = atoi(value);
    else if (!strcasecmp(key, "output")) strncpy(g_cfg.output_path, value, sizeof(g_cfg.output_path) - 1);
    else if (!strcasecmp(key, "auto_update")) g_cfg.auto_update = (!strcasecmp(value, "true") || !strcasecmp(value, "1"));
    else if (!strcasecmp(key, "cloak_conf_path")) strncpy(g_cfg.cloak_conf_path, value, sizeof(g_cfg.cloak_conf_path) - 1);
    else if (!strcasecmp(key, "max_servers_write")) g_cfg.max_servers_write = atoi(value);
    else if (!strcasecmp(key, "max_snis_write")) g_cfg.max_snis_write = atoi(value);
    else if (!strcasecmp(key, "prune_dead_entries")) g_cfg.prune_dead_entries = (!strcasecmp(value, "true") || !strcasecmp(value, "1"));
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
"#  cloakscan.conf -- find live Cloudflare IP + SNI combinations\n"
"# ============================================================\n"
"\n"
"# CIDR ranges to sample from -- IPv4 and IPv6 can be mixed freely.\n"
"# These are a few of Cloudflare's published ranges (see\n"
"# https://www.cloudflare.com/ips/ for the full/current list -- it\n"
"# does change over time, check there if these stop working).\n"
"ranges = 104.16.0.0/13, 104.24.0.0/14, 172.64.0.0/13, 131.0.72.0/22, 2606:4700::/32, 2803:f800::/32, 2405:b500::/32, 2a06:98c0::/29, 2c0f:f248::/32\n"
"\n"
"# Candidate SNI values to test against each sampled IP. Pick\n"
"# domains you're fairly sure are themselves unblocked and are\n"
"# likely served via Cloudflare.\n"
"sni_list = www.hcaptcha.com, www.speedtest.net, www.bing.com, www.cloudflare.com\n"
"\n"
"# Candidate ports to test each sampled IP on, one picked at random\n"
"# per probe (same idea as sni_list above). These are Cloudflare's\n"
"# published HTTPS-capable ports -- matches cloak.conf's\n"
"# fallback_ports, so an IP that's only reachable on a non-443 port\n"
"# still gets found and correctly kept alive by prune_dead_entries,\n"
"# instead of being wrongly treated as dead just because 443 alone\n"
"# didn't answer.\n"
"ports = 443, 2053, 2083, 2087, 2096, 8443\n"
"\n"
"# How many random IPs to sample from EACH range above. Keep this\n"
"# modest on a phone connection -- each sample is a real connection\n"
"# attempt, and mobile networks/CPUs don't love thousands of these.\n"
"samples_per_range = 40\n"
"\n"
"# Max simultaneous probes in flight. Higher = faster scan, but\n"
"# more load on your connection and the remote side.\n"
"concurrency = 20\n"
"\n"
"# How long to wait for each probe before giving up (milliseconds).\n"
"timeout_ms = 2000\n"
"\n"
"# Where to write results, in a format ready to paste into cloak.conf.\n"
"output = cloakscan_results.txt\n"
"\n"
"# true/false -- if true, cloakscan writes its findings DIRECTLY into\n"
"# cloak.conf's connect_list and sni_list, merged with what's already\n"
"# there (no manual copy-paste needed). It only touches those two\n"
"# lines -- every other setting and comment in cloak.conf is left\n"
"# untouched. Defaults to true, so make sure cloak_conf_path below\n"
"# actually points at YOUR cloak.conf before running this for real.\n"
"auto_update = true\n"
"\n"
"# Path to the cloak.conf to update (only used if auto_update=true).\n"
"# If cloakscan sits in the same folder as cloak, the default below\n"
"# is correct as-is.\n"
"cloak_conf_path = cloak.conf\n"
"\n"
"# Caps on how many entries auto_update writes into connect_list /\n"
"# sni_list -- keep these at or below cloak.c's own MAX_SERVER_LIST\n"
"# (8) and MAX_SNI_LIST (16), or cloak will silently ignore the rest.\n"
"max_servers_write = 8\n"
"max_snis_write = 12\n"
"\n"
"# true/false -- before merging in new finds, re-test every server\n"
"# ALREADY in cloak.conf's connect_list and drop the ones that no\n"
"# longer respond. This is what keeps connect_list from silently\n"
"# accumulating dead IPs over weeks of scanning -- without it,\n"
"# cloakscan only ever adds, never removes. IPv6 entries ([...]:port)\n"
"# are left as-is (not re-tested) since this scanner is IPv4-only.\n"
"prune_dead_entries = true\n"
    );
    fclose(f);
}

/* ---------------------------------------------------------------
 * Minimal TLS ClientHello builder (same shape as cloak.c's, kept
 * duplicated here so this file has no dependency on cloak.c)
 * ------------------------------------------------------------- */

static void put_u16(uint8_t *buf, size_t *p, uint16_t v) {
    buf[(*p)++] = (v >> 8) & 0xFF;
    buf[(*p)++] = v & 0xFF;
}

static size_t build_client_hello(uint8_t *out, size_t cap, const char *sni) {
    size_t sni_len = strlen(sni);
    uint8_t body[512];
    size_t p = 0;

    body[p++] = 0x03; body[p++] = 0x03;
    for (int i = 0; i < 32; i++) body[p++] = (uint8_t)safe_rand();
    body[p++] = 0x00;

    static const uint16_t ciphers[] = {
        0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC02C, 0xC030, 0x009C, 0x009D
    };
    put_u16(body, &p, (uint16_t)(sizeof(ciphers)));
    for (size_t i = 0; i < sizeof(ciphers)/sizeof(ciphers[0]); i++) put_u16(body, &p, ciphers[i]);

    body[p++] = 0x01; body[p++] = 0x00;

    size_t ext_len_pos = p; p += 2;
    size_t ext_start = p;

    put_u16(body, &p, 0x0000);
    put_u16(body, &p, (uint16_t)(sni_len + 5));
    put_u16(body, &p, (uint16_t)(sni_len + 3));
    body[p++] = 0x00;
    put_u16(body, &p, (uint16_t)sni_len);
    memcpy(body + p, sni, sni_len); p += sni_len;

    put_u16(body, &p, 0x002B); put_u16(body, &p, 0x0003);
    body[p++] = 0x02; put_u16(body, &p, 0x0303);

    size_t ext_total = p - ext_start;
    body[ext_len_pos] = (ext_total >> 8) & 0xFF;
    body[ext_len_pos+1] = ext_total & 0xFF;

    size_t body_len = p;
    uint8_t hs[4 + 512];
    hs[0] = 0x01;
    hs[1] = (uint8_t)((body_len >> 16) & 0xFF);
    hs[2] = (uint8_t)((body_len >> 8) & 0xFF);
    hs[3] = (uint8_t)(body_len & 0xFF);
    memcpy(hs + 4, body, body_len);
    size_t hs_len = 4 + body_len;

    if (cap < hs_len + 5) return 0;
    out[0] = 0x16; out[1] = 0x03; out[2] = 0x01;
    out[3] = (uint8_t)((hs_len >> 8) & 0xFF);
    out[4] = (uint8_t)(hs_len & 0xFF);
    memcpy(out + 5, hs, hs_len);
    return hs_len + 5;
}

/* ---------------------------------------------------------------
 * connect() with a real, enforced timeout (see cloak.c for why
 * SO_SNDTIMEO alone doesn't bound connect())
 * ------------------------------------------------------------- */

static int connect_with_timeout(int fd, struct sockaddr *dst, socklen_t dst_len, int timeout_ms) {
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    int rc = connect(fd, dst, dst_len);
    if (rc == 0) return 0;
    if (errno != EINPROGRESS) return -1;

    struct pollfd pfd = { .fd = fd, .events = POLLOUT };
    rc = poll(&pfd, 1, timeout_ms);
    if (rc <= 0) return -1;

    int err = 0;
    socklen_t len = sizeof(err);
    getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len);
    return (err == 0) ? 0 : -1;
}

/* ---------------------------------------------------------------
 * One probe: does (ip, sni) answer with a real TLS response?
 * ------------------------------------------------------------- */

/* Shared core: connects to a given sockaddr, sends a ClientHello for
 * the given SNI, and checks for a real TLS response. Used by both
 * probe_one (random samples from a CIDR range) and
 * probe_existing_entry (re-checking a known host:port), regardless
 * of whether it's IPv4 or IPv6 -- the sockaddr already encodes that. */
static int probe_sockaddr(struct sockaddr *dst, socklen_t dst_len, int family, const char *sni) {
    int fd = socket(family, SOCK_STREAM, 0);
    if (fd < 0) return 0;

    if (connect_with_timeout(fd, dst, dst_len, g_cfg.timeout_ms) < 0) { close(fd); return 0; }

    uint8_t hello[600];
    size_t n = build_client_hello(hello, sizeof(hello), sni);
    if (n == 0) { close(fd); return 0; }

    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
    struct timeval tv = { .tv_sec = g_cfg.timeout_ms / 1000, .tv_usec = (g_cfg.timeout_ms % 1000) * 1000 };
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    if (send(fd, hello, n, 0) < 0) { close(fd); return 0; }

    uint8_t resp[8];
    ssize_t got = recv(fd, resp, sizeof(resp), 0);
    close(fd);

    /* A real TLS ServerHello (or even an alert) starts with 0x16 or
     * 0x15 as the record type. Anything else, or nothing at all,
     * means this IP/SNI combo isn't giving us a real TLS response
     * right now. */
    return (got > 0 && (resp[0] == 0x16 || resp[0] == 0x15));
}

/* Same probe logic, but for a specific "ip:port" or "[ipv6]:port"
 * string we already have (used to re-verify existing connect_list
 * entries) rather than a randomly-sampled address from a CIDR range. */
static int probe_existing_entry(const char *hostport, const char *sni) {
    char host[64];
    int port;

    if (hostport[0] == '[') {
        const char *close_br = strchr(hostport, ']');
        if (!close_br) return -1;
        size_t hl = (size_t)(close_br - hostport - 1);
        if (hl >= sizeof(host)) return -1;
        strncpy(host, hostport + 1, hl);
        host[hl] = '\0';
        const char *colon = strchr(close_br, ':');
        if (!colon) return -1;
        port = atoi(colon + 1);

        struct sockaddr_in6 dst;
        memset(&dst, 0, sizeof(dst));
        dst.sin6_family = AF_INET6;
        dst.sin6_port = htons((uint16_t)port);
        if (inet_pton(AF_INET6, host, &dst.sin6_addr) != 1) return -1;
        return probe_sockaddr((struct sockaddr *)&dst, sizeof(dst), AF_INET6, sni);
    } else {
        const char *colon = strrchr(hostport, ':');
        if (!colon) return -1;
        size_t hl = (size_t)(colon - hostport);
        if (hl >= sizeof(host)) return -1;
        strncpy(host, hostport, hl);
        host[hl] = '\0';
        port = atoi(colon + 1);

        struct sockaddr_in dst;
        memset(&dst, 0, sizeof(dst));
        dst.sin_family = AF_INET;
        dst.sin_port = htons((uint16_t)port);
        if (inet_pton(AF_INET, host, &dst.sin_addr) != 1) return -1;
        return probe_sockaddr((struct sockaddr *)&dst, sizeof(dst), AF_INET, sni);
    }
}

static int probe_one(const IpRange *range, const char *sni, int port, char *ip_str_out) {
    if (range->family == AF_INET) {
        uint32_t host_bits = 32 - range->prefix;
        uint32_t range_size = (host_bits >= 32) ? 0xFFFFFFFFu : (1u << host_bits);
        uint32_t offset = (range_size > 2) ? (1 + (safe_rand() % (range_size - 2))) : 0;
        uint32_t ip = range->v4_base + offset;

        struct in_addr a;
        a.s_addr = htonl(ip);
        inet_ntop(AF_INET, &a, ip_str_out, INET_ADDRSTRLEN);

        struct sockaddr_in dst;
        memset(&dst, 0, sizeof(dst));
        dst.sin_family = AF_INET;
        dst.sin_port = htons((uint16_t)port);
        dst.sin_addr = a;
        return probe_sockaddr((struct sockaddr *)&dst, sizeof(dst), AF_INET, sni);
    } else {
        /* IPv6: randomize only the host bits, byte by byte, keeping
         * the network bits from v6_base untouched. 128-bit addresses
         * don't fit in a normal integer, so this works directly on
         * the 16 raw bytes instead of doing arithmetic on a number. */
        struct in6_addr addr = range->v6_base;
        for (int byte = 0; byte < 16; byte++) {
            int bit_start = byte * 8;
            if (bit_start + 8 <= range->prefix) {
                continue; /* fully inside the network part, leave as-is */
            } else if (bit_start >= range->prefix) {
                addr.s6_addr[byte] = (uint8_t)safe_rand(); /* fully host part */
            } else {
                /* boundary byte: keep the top bits (network), randomize the rest */
                int network_bits_here = range->prefix - bit_start;
                uint8_t mask = (uint8_t)(0xFF << (8 - network_bits_here));
                uint8_t random_byte = (uint8_t)safe_rand();
                addr.s6_addr[byte] = (addr.s6_addr[byte] & mask) | (random_byte & ~mask);
            }
        }

        inet_ntop(AF_INET6, &addr, ip_str_out, INET6_ADDRSTRLEN);

        struct sockaddr_in6 dst;
        memset(&dst, 0, sizeof(dst));
        dst.sin6_family = AF_INET6;
        dst.sin6_port = htons((uint16_t)port);
        dst.sin6_addr = addr;
        return probe_sockaddr((struct sockaddr *)&dst, sizeof(dst), AF_INET6, sni);
    }
}

/* ---------------------------------------------------------------
 * Bounded-concurrency thread pool for scanning
 *
 * Unlike an unbounded "spawn a thread per probe", this caps how many
 * probes run at once using a counting semaphore built from a mutex +
 * condition variable -- important on a phone, where firing off
 * thousands of threads at once is a good way to run out of memory or
 * just make the whole scan slower via contention.
 * ------------------------------------------------------------- */

typedef struct {
    int count;
    int max;
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
static pthread_mutex_t g_results_lock = PTHREAD_MUTEX_INITIALIZER;
static FILE *g_out = NULL;
static int g_found = 0;
static int g_tried = 0;
static int g_total = 0;

/* Unique servers/SNIs discovered during this run, kept in memory so
 * we can merge them into cloak.conf at the end (in addition to the
 * plain-text results file, which stays as a full audit log). */
#define MAX_FOUND 256
static char g_found_servers[MAX_FOUND][256]; /* "ip:port" */
static int  g_found_server_count = 0;
static char g_found_snis[MAX_FOUND][256];
static int  g_found_sni_count = 0;

static int already_have(char arr[][256], int count, const char *val) {
    for (int i = 0; i < count; i++) if (!strcmp(arr[i], val)) return 1;
    return 0;
}

static void record_found(const char *ip, int port, const char *sni) {
    char combo[64];
    snprintf(combo, sizeof(combo), "%s:%d", ip, port);
    if (g_found_server_count < MAX_FOUND &&
        !already_have(g_found_servers, g_found_server_count, combo)) {
        strncpy(g_found_servers[g_found_server_count], combo, 255);
        g_found_servers[g_found_server_count][255] = '\0';
        g_found_server_count++;
    }
    if (g_found_sni_count < MAX_FOUND && !already_have(g_found_snis, g_found_sni_count, sni)) {
        strncpy(g_found_snis[g_found_sni_count], sni, 255);
        g_found_snis[g_found_sni_count][255] = '\0';
        g_found_sni_count++;
    }
}

typedef struct {
    IpRange range;
    char sni[256];
    int port;
} ProbeTask;

static void *probe_worker(void *arg) {
    ProbeTask *task = (ProbeTask *)arg;
    char ip_str[INET6_ADDRSTRLEN];

    int ok = probe_one(&task->range, task->sni, task->port, ip_str);

    /* IPv6 addresses need bracket notation in cloak.conf's connect_list
     * syntax ([2606:4700::1]:443), since the address itself is full of
     * colons -- IPv4 doesn't need that. */
    int is_v6 = (task->range.family == AF_INET6);

    pthread_mutex_lock(&g_results_lock);
    g_tried++;
    if (ok) {
        g_found++;
        if (is_v6)
            fprintf(g_out, "[%s]:%d  sni=%s\n", ip_str, task->port, task->sni);
        else
            fprintf(g_out, "%s:%d  sni=%s\n", ip_str, task->port, task->sni);
        fflush(g_out);

        char combo_host[INET6_ADDRSTRLEN + 2];
        if (is_v6) snprintf(combo_host, sizeof(combo_host), "[%s]", ip_str);
        else strncpy(combo_host, ip_str, sizeof(combo_host) - 1);
        record_found(combo_host, task->port, task->sni);

        log_line("[FOUND %4d/%-4d] %s:%d -> %s", g_tried, g_total, ip_str, task->port, task->sni);
    } else if (g_tried % 10 == 0) {
        log_line("[progress %4d/%-4d] %d found so far", g_tried, g_total, g_found);
    }
    pthread_mutex_unlock(&g_results_lock);

    free(task);
    sem_release(&g_sem);
    return NULL;
}

/* ---------------------------------------------------------------
 * Merging results into cloak.conf
 *
 * This only ever touches the connect_list and sni_list lines --
 * every other line (including all the explanatory comments) is read
 * back out byte-for-byte unchanged. New entries are appended after
 * whatever's already there, deduplicated, capped at the configured
 * maximums.
 * ------------------------------------------------------------- */

static int line_is_key(const char *line, const char *key) {
    const char *p = line;
    while (isspace((unsigned char)*p)) p++;
    size_t klen = strlen(key);
    if (strncasecmp(p, key, klen) != 0) return 0;
    p += klen;
    while (isspace((unsigned char)*p)) p++;
    return *p == '=';
}

static void extract_existing_values(const char *line, char items[][256], int *count, int max) {
    const char *eq = strchr(line, '=');
    if (!eq) return;
    char buf[2048];
    strncpy(buf, eq + 1, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
    char *tok = strtok(buf, ",");
    while (tok && *count < max) {
        char *t = trim(tok);
        if (*t && !already_have(items, *count, t)) {
            strncpy(items[*count], t, 255);
            (*count)++;
        }
        tok = strtok(NULL, ",");
    }
}

static void update_cloak_conf(void) {
    FILE *f = fopen(g_cfg.cloak_conf_path, "r");
    if (!f) {
        log_line("[auto_update] could not open '%s', skipping merge", g_cfg.cloak_conf_path);
        return;
    }

    char *lines[2000];
    int line_count = 0;
    char buf[2048];
    while (line_count < 2000 && fgets(buf, sizeof(buf), f)) {
        lines[line_count++] = strdup(buf);
    }
    fclose(f);

    int connect_idx = -1, sni_idx = -1;
    char merged_servers[MAX_FOUND][256];
    int merged_server_count = 0;
    char merged_snis[MAX_FOUND][256];
    int merged_sni_count = 0;

    for (int i = 0; i < line_count; i++) {
        if (line_is_key(lines[i], "connect_list")) {
            connect_idx = i;
            extract_existing_values(lines[i], merged_servers, &merged_server_count, g_cfg.max_servers_write);
        } else if (line_is_key(lines[i], "sni_list")) {
            sni_idx = i;
            extract_existing_values(lines[i], merged_snis, &merged_sni_count, g_cfg.max_snis_write);
        }
    }

    if (g_cfg.prune_dead_entries && merged_server_count > 0) {
        const char *test_sni = merged_sni_count > 0 ? merged_snis[0] : "www.bing.com";
        int kept = 0;
        for (int i = 0; i < merged_server_count; i++) {
            int result = probe_existing_entry(merged_servers[i], test_sni);
            if (result == 0) {
                log_line("[prune] %s no longer responds -- removing", merged_servers[i]);
                continue; /* drop it: don't copy forward */
            }
            /* result == 1 (still alive) or result == -1 (IPv6 / unparseable,
             * left alone rather than guessed at) both get kept */
            if (kept != i) strcpy(merged_servers[kept], merged_servers[i]);
            kept++;
        }
        merged_server_count = kept;
    }

    for (int i = 0; i < g_found_server_count && merged_server_count < g_cfg.max_servers_write; i++)
        if (!already_have(merged_servers, merged_server_count, g_found_servers[i]))
            { strncpy(merged_servers[merged_server_count], g_found_servers[i], 255); merged_servers[merged_server_count][255] = '\0'; merged_server_count++; }

    for (int i = 0; i < g_found_sni_count && merged_sni_count < g_cfg.max_snis_write; i++)
        if (!already_have(merged_snis, merged_sni_count, g_found_snis[i]))
            { strncpy(merged_snis[merged_sni_count], g_found_snis[i], 255); merged_snis[merged_sni_count][255] = '\0'; merged_sni_count++; }

    char new_connect_line[4096] = "connect_list = ";
    for (int i = 0; i < merged_server_count; i++) {
        strcat(new_connect_line, merged_servers[i]);
        if (i < merged_server_count - 1) strcat(new_connect_line, ", ");
    }
    strcat(new_connect_line, "\n");

    char new_sni_line[4096] = "sni_list = ";
    for (int i = 0; i < merged_sni_count; i++) {
        strcat(new_sni_line, merged_snis[i]);
        if (i < merged_sni_count - 1) strcat(new_sni_line, ", ");
    }
    strcat(new_sni_line, "\n");

    FILE *out = fopen(g_cfg.cloak_conf_path, "w");
    if (!out) {
        log_line("[auto_update] could not write '%s', merge aborted", g_cfg.cloak_conf_path);
        for (int i = 0; i < line_count; i++) free(lines[i]);
        return;
    }

    int wrote_connect = 0, wrote_sni = 0;
    for (int i = 0; i < line_count; i++) {
        if (i == connect_idx) { fputs(new_connect_line, out); wrote_connect = 1; }
        else if (i == sni_idx) { fputs(new_sni_line, out); wrote_sni = 1; }
        else fputs(lines[i], out);
        free(lines[i]);
    }
    if (!wrote_connect) fputs(new_connect_line, out);
    if (!wrote_sni) fputs(new_sni_line, out);
    fclose(out);

    log_line("[auto_update] wrote %d server(s) and %d SNI(s) into %s",
             merged_server_count, merged_sni_count, g_cfg.cloak_conf_path);
}

int main(int argc, char **argv) {
    srand((unsigned)time(NULL));

    const char *config_path = (argc > 1) ? argv[1] : "cloakscan.conf";
    FILE *check = fopen(config_path, "r");
    if (!check) {
        printf("no config found at '%s' -- writing a starter one.\n", config_path);
        write_example_config(config_path);
        printf("edit it, then run this program again.\n");
        return 0;
    }
    fclose(check);

    load_config(config_path);

    if (g_cfg.range_count == 0) { log_line("error: no valid 'ranges' configured"); return 1; }
    if (g_cfg.sni_count == 0) parse_snis("www.hcaptcha.com,www.speedtest.net,www.bing.com");
    if (g_cfg.port_count == 0) parse_ports("443,2053,2083,2087,2096,8443");

    g_out = fopen(g_cfg.output_path, "w");
    if (!g_out) { log_line("error: cannot open output file '%s'", g_cfg.output_path); return 1; }
    fprintf(g_out, "# cloakscan results -- generated %ld\n", (long)time(NULL));
    fprintf(g_out, "# paste the IPs below into cloak.conf's connect_list,\n");
    fprintf(g_out, "# and the SNI values into sni_list.\n\n");
    fflush(g_out);

    g_total = g_cfg.range_count * g_cfg.samples_per_range;
    sem_init_custom(&g_sem, g_cfg.concurrency);

    log_line("cloakscan: %d range(s), %d samples each, %d SNI candidate(s), concurrency=%d",
             g_cfg.range_count, g_cfg.samples_per_range, g_cfg.sni_count, g_cfg.concurrency);

    pthread_t *threads = malloc(sizeof(pthread_t) * (size_t)g_total);
    int tcount = 0;

    for (int r = 0; r < g_cfg.range_count; r++) {
        for (int s = 0; s < g_cfg.samples_per_range; s++) {
            ProbeTask *task = malloc(sizeof(ProbeTask));
            task->range = g_cfg.ranges[r]; /* random offset is picked inside probe_one() */
            const char *sni = g_cfg.sni_list[safe_rand() % g_cfg.sni_count];
            strncpy(task->sni, sni, sizeof(task->sni) - 1);
            task->port = g_cfg.ports[safe_rand() % g_cfg.port_count];

            sem_acquire(&g_sem);
            pthread_create(&threads[tcount], NULL, probe_worker, task);
            tcount++;
        }
    }

    for (int i = 0; i < tcount; i++) pthread_join(threads[i], NULL);
    free(threads);

    fclose(g_out);

    if (g_cfg.auto_update) update_cloak_conf();

    log_line("done: %d/%d probes succeeded. Results in %s", g_found, g_tried, g_cfg.output_path);
    return 0;
}
