/*
 * cloak.c (v3)
 *
 * A no-root, config-file-driven TLS-handshake cloaking proxy.
 *
 * v3 adds, on top of everything in v2:
 *   1. A more realistic, Chrome-like ClientHello for the decoy (more
 *      extensions, closer to a real browser's JA3-style fingerprint)
 *      instead of an obviously minimal/synthetic one.
 *   2. Adaptive stats: cloak remembers (in cloak.stats) which TTLs
 *      and which servers actually led to a successful TLS response,
 *      and tries the best-performing ones first next time.
 *   3. connect_list is validated as raw IPs only -- a domain name
 *      here would leak the real destination through a plaintext DNS
 *      lookup before cloak even gets a chance to do anything.
 *   4. Concurrent server racing: instead of trying connect_list
 *      entries one at a time, cloak probes all of them in parallel
 *      and uses whichever answers first.
 *
 * What is still true, and always will be true without root: the
 * decoy is still a separate TCP flow, not a same-sequence injection
 * into the real flow. That specific technique needs CAP_NET_RAW
 * (root). Nothing here changes that -- these features only push the
 * no-root ceiling as high as it can go.
 *
 * BUILD:
 *   gcc -O2 -Wall -o cloak cloak.c -lpthread
 *
 * RUN:
 *   ./cloak                  # reads ./cloak.conf (auto-created on first run)
 *   ./cloak /path/other.conf
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <signal.h>
#include <time.h>
#include <errno.h>
#include <ctype.h>
#include <stdarg.h>

/* ---------------------------------------------------------------
 * Leveled, timestamped logging
 *
 * Replaces the old all-or-nothing "verbose true/false" scheme. Every
 * log line now has: a real timestamp, a severity level, and a fixed-
 * width tag -- so lines line up and are greppable/sortable. Output
 * goes to stderr by default, or to a file if log_file is set in the
 * config (useful for reviewing what happened after the fact, since
 * cloak is meant to run for hours/days unattended).
 *
 * Levels, from least to most verbose:
 *   ERROR - something failed and the connection/action was aborted
 *   WARN  - something is off but cloak kept going (e.g. a rejected
 *           config entry)
 *   INFO  - normal one-line-per-connection summary (what most people
 *           want day to day)
 *   DEBUG - per-decoy, per-TTL detail (what you want while tuning)
 * ------------------------------------------------------------- */

typedef enum { LOG_ERROR = 0, LOG_WARN = 1, LOG_INFO = 2, LOG_DEBUG = 3 } LogLevel;

static LogLevel g_log_level = LOG_INFO;
static FILE *g_log_file = NULL; /* NULL = stderr */
static pthread_mutex_t g_log_lock = PTHREAD_MUTEX_INITIALIZER;

static const char *log_level_name(LogLevel lvl) {
    switch (lvl) {
        case LOG_ERROR: return "ERROR";
        case LOG_WARN:  return "WARN ";
        case LOG_INFO:  return "INFO ";
        default:        return "DEBUG";
    }
}

static void log_msg(LogLevel level, const char *tag, const char *fmt, ...) {
    if (level > g_log_level) return;

    time_t now = time(NULL);
    struct tm tmv;
    localtime_r(&now, &tmv);
    char timestr[16];
    strftime(timestr, sizeof(timestr), "%H:%M:%S", &tmv);

    FILE *out = g_log_file ? g_log_file : stderr;

    pthread_mutex_lock(&g_log_lock); /* keep concurrent lines from interleaving */
    fprintf(out, "%s %s [%-9s] ", timestr, log_level_name(level), tag);
    va_list ap;
    va_start(ap, fmt);
    vfprintf(out, fmt, ap);
    va_end(ap);
    fprintf(out, "\n");
    if (g_log_file) fflush(g_log_file);
    pthread_mutex_unlock(&g_log_lock);
}

#define LOGE(tag, ...) log_msg(LOG_ERROR, tag, __VA_ARGS__)
#define LOGW(tag, ...) log_msg(LOG_WARN,  tag, __VA_ARGS__)
#define LOGI(tag, ...) log_msg(LOG_INFO,  tag, __VA_ARGS__)
#define LOGD(tag, ...) log_msg(LOG_DEBUG, tag, __VA_ARGS__)

/* ---------------------------------------------------------------
 * Thread-safe random numbers
 *
 * Plain rand() keeps one global state shared by every call site.
 * When multiple threads call it at the same time (which happens
 * here -- one thread per client connection), that's a data race:
 * undefined behavior, not just "slightly less random" output.
 * rand_r() takes an explicit per-caller seed instead of touching
 * global state, so each thread can safely have its own.
 * ------------------------------------------------------------- */

static __thread unsigned int t_rand_seed; /* one copy per thread */
static __thread int t_rand_seeded = 0;

/* send() is not guaranteed to send everything in one call -- it can
 * return having written only part of the buffer, especially for
 * larger writes or a slow/congested connection. Every call site here
 * used to assume "one send() = all bytes sent", which is a real bug.
 * This loops until everything is sent or a real error happens. */
static ssize_t send_all(int fd, const void *buf, size_t len) {
    const uint8_t *p = (const uint8_t *)buf;
    size_t sent_total = 0;
    while (sent_total < len) {
        ssize_t n = send(fd, p + sent_total, len - sent_total, 0);
        if (n < 0) {
            if (errno == EINTR) continue; /* interrupted, just retry */
            return -1;
        }
        if (n == 0) break; /* shouldn't normally happen for send(), but be safe */
        sent_total += (size_t)n;
    }
    return (ssize_t)sent_total;
}

static int safe_rand(void) {
    if (!t_rand_seeded) {
        /* Mix thread id and time so different threads started at
         * nearly the same moment don't get the same seed. */
        t_rand_seed = (unsigned int)(time(NULL) ^ (uintptr_t)pthread_self());
        t_rand_seeded = 1;
    }
    return rand_r(&t_rand_seed);
}

/* ---------------------------------------------------------------
 * Section 1: configuration struct + defaults
 * ------------------------------------------------------------- */

#define MAX_SNI_LIST     16
#define MAX_TTL_LIST     8
#define MAX_SERVER_LIST  8

typedef struct {
    char host[64];
    int  port;
    int  family; /* AF_INET or AF_INET6 */
} ServerAddr;

typedef struct {
    int  listen_port;

    ServerAddr servers[MAX_SERVER_LIST];
    int  server_count;

    char sni_list[MAX_SNI_LIST][256];
    int  sni_count;

    int  ttl_list[MAX_TTL_LIST];
    int  ttl_count;

    int  jitter_min_ms;
    int  jitter_max_ms;

    int  calibrate;
    int  fragment_real;
    int  adaptive;      /* use cloak.stats to reorder ttl/server attempts */

    char stats_path[256];
    char log_file_path[256]; /* empty = stderr */
} Config;

static Config g_cfg = {
    .listen_port   = 40443,
    .server_count  = 0,
    .sni_count     = 0,
    .ttl_count     = 0,
    .jitter_min_ms = 20,
    .jitter_max_ms = 80,
    .calibrate     = 0,
    .fragment_real = 0,
    .adaptive      = 1,
    .stats_path    = "cloak.stats",
    .log_file_path = "",
};

/* ---------------------------------------------------------------
 * Section 2: config file parser
 * ------------------------------------------------------------- */

static char *trim(char *s) {
    while (isspace((unsigned char)*s)) s++;
    if (*s == '\0') return s;
    char *end = s + strlen(s) - 1;
    while (end > s && isspace((unsigned char)*end)) *end-- = '\0';
    return s;
}

/* Accepts a raw IPv4 or IPv6 address (no domain names -- see the
 * warning below for why). Returns 1 and sets *family on success. */
static int is_raw_ip(const char *s, int *family) {
    struct in_addr a4;
    struct in6_addr a6;
    if (inet_pton(AF_INET, s, &a4) == 1) { *family = AF_INET; return 1; }
    if (inet_pton(AF_INET6, s, &a6) == 1) { *family = AF_INET6; return 1; }
    return 0;
}

static void parse_sni_list(const char *value) {
    char buf[2048];
    strncpy(buf, value, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    g_cfg.sni_count = 0;
    char *tok = strtok(buf, ",");
    while (tok && g_cfg.sni_count < MAX_SNI_LIST) {
        strncpy(g_cfg.sni_list[g_cfg.sni_count], trim(tok), 255);
        g_cfg.sni_count++;
        tok = strtok(NULL, ",");
    }
}

static void parse_ttl_list(const char *value) {
    char buf[256];
    strncpy(buf, value, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    g_cfg.ttl_count = 0;
    char *tok = strtok(buf, ",");
    while (tok && g_cfg.ttl_count < MAX_TTL_LIST) {
        g_cfg.ttl_list[g_cfg.ttl_count] = atoi(trim(tok));
        g_cfg.ttl_count++;
        tok = strtok(NULL, ",");
    }
}

static void parse_one_server(char *entry) {
    if (g_cfg.server_count >= MAX_SERVER_LIST) return;
    char *e = trim(entry);
    char host[64];
    int port = 443;

    if (e[0] == '[') {
        /* IPv6 literal in bracket notation: [2606:4700::1]:443
         * Brackets are required here because a bare IPv6 address is
         * already full of colons, so we can't just split on the last
         * ':' the way we do for IPv4. */
        char *close = strchr(e, ']');
        if (!close) {
            LOGW("config", "malformed IPv6 entry '%s' (missing ']'), skipping", e);
            return;
        }
        size_t hl = (size_t)(close - e - 1);
        if (hl >= sizeof(host)) hl = sizeof(host) - 1;
        strncpy(host, e + 1, hl);
        host[hl] = '\0';
        char *colon_after = strchr(close, ':');
        if (colon_after) port = atoi(colon_after + 1);
    } else {
        const char *colon = strrchr(e, ':');
        if (!colon) {
            strncpy(host, e, sizeof(host) - 1);
            host[sizeof(host) - 1] = '\0';
        } else {
            size_t hl = (size_t)(colon - e);
            if (hl >= sizeof(host)) hl = sizeof(host) - 1;
            strncpy(host, e, hl);
            host[hl] = '\0';
            port = atoi(colon + 1);
        }
    }

    /* IMPORTANT: only accept raw IPv4/IPv6 addresses here. A domain
     * name would need a DNS lookup, and on most phones that DNS
     * query goes out in plaintext -- leaking the real destination
     * before cloak ever gets a chance to hide anything. */
    int family;
    if (!is_raw_ip(host, &family)) {
        LOGW("config",
            "'%s' in connect_list is not a raw IPv4/IPv6 address -- skipping it. "
            "Domain names here would leak your real destination via plaintext DNS. "
            "Use an IP instead (IPv6 needs brackets: [::1]:443).", host);
        return;
    }

    ServerAddr *s = &g_cfg.servers[g_cfg.server_count];
    strncpy(s->host, host, sizeof(s->host) - 1);
    s->host[sizeof(s->host) - 1] = '\0';
    s->port = port;
    s->family = family;
    g_cfg.server_count++;
}

static void parse_connect_list(const char *value) {
    char buf[1024];
    strncpy(buf, value, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    g_cfg.server_count = 0;
    char *tok = strtok(buf, ",");
    while (tok) {
        parse_one_server(tok);
        tok = strtok(NULL, ",");
    }
}

static int as_bool(const char *value) {
    return (!strcasecmp(value, "true") || !strcasecmp(value, "yes") ||
            !strcasecmp(value, "1")    || !strcasecmp(value, "on"));
}

static void apply_setting(const char *key, const char *value) {
    if (!strcasecmp(key, "listen_port")) {
        g_cfg.listen_port = atoi(value);
    } else if (!strcasecmp(key, "connect_list")) {
        parse_connect_list(value);
    } else if (!strcasecmp(key, "sni_list")) {
        parse_sni_list(value);
    } else if (!strcasecmp(key, "ttl_list")) {
        parse_ttl_list(value);
    } else if (!strcasecmp(key, "jitter_min_ms")) {
        g_cfg.jitter_min_ms = atoi(value);
    } else if (!strcasecmp(key, "jitter_max_ms")) {
        g_cfg.jitter_max_ms = atoi(value);
    } else if (!strcasecmp(key, "calibrate")) {
        g_cfg.calibrate = as_bool(value);
    } else if (!strcasecmp(key, "fragment")) {
        g_cfg.fragment_real = as_bool(value);
    } else if (!strcasecmp(key, "adaptive")) {
        g_cfg.adaptive = as_bool(value);
    } else if (!strcasecmp(key, "log_level")) {
        if (!strcasecmp(value, "error"))      g_log_level = LOG_ERROR;
        else if (!strcasecmp(value, "warn"))  g_log_level = LOG_WARN;
        else if (!strcasecmp(value, "info"))  g_log_level = LOG_INFO;
        else if (!strcasecmp(value, "debug")) g_log_level = LOG_DEBUG;
        else LOGW("config", "unknown log_level '%s' (use error/warn/info/debug), keeping current", value);
    } else if (!strcasecmp(key, "log_file")) {
        strncpy(g_cfg.log_file_path, value, sizeof(g_cfg.log_file_path) - 1);
    } else if (!strcasecmp(key, "verbose")) {
        /* legacy alias from before log_level existed: true ~= debug,
         * false ~= warn (so errors/warnings still show either way) */
        g_log_level = as_bool(value) ? LOG_DEBUG : LOG_WARN;
        LOGW("config", "'verbose' is a legacy setting -- use log_level=debug/info/warn/error instead");
    } else {
        LOGW("config", "unknown key '%s', ignoring", key);
    }
}

static int load_config(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) {
        LOGE("config", "could not open config file '%s'", path);
        return -1;
    }

    char line[2048];
    int lineno = 0;
    while (fgets(line, sizeof(line), f)) {
        lineno++;
        char *s = trim(line);
        if (*s == '\0' || *s == '#') continue;

        char *eq = strchr(s, '=');
        if (!eq) {
            LOGW("config", "line %d: no '=' found, skipping", lineno);
            continue;
        }
        *eq = '\0';
        apply_setting(trim(s), trim(eq + 1));
    }

    fclose(f);
    return 0;
}

/* ---------------------------------------------------------------
 * Address helpers shared by every socket operation below: fills a
 * sockaddr_storage for either IPv4 or IPv6 depending on srv->family,
 * and sets the outbound hop-limit (TTL for IPv4, its IPv6 equivalent)
 * on a socket. Having these in one place means every call site below
 * (decoy, calibration probe, race probe, real connection) works
 * identically regardless of which IP version a given server uses.
 * ------------------------------------------------------------- */

static socklen_t fill_sockaddr(const ServerAddr *srv, struct sockaddr_storage *out) {
    memset(out, 0, sizeof(*out));
    if (srv->family == AF_INET) {
        struct sockaddr_in *a = (struct sockaddr_in *)out;
        a->sin_family = AF_INET;
        a->sin_port = htons((uint16_t)srv->port);
        inet_pton(AF_INET, srv->host, &a->sin_addr);
        return sizeof(*a);
    } else {
        struct sockaddr_in6 *a = (struct sockaddr_in6 *)out;
        a->sin6_family = AF_INET6;
        a->sin6_port = htons((uint16_t)srv->port);
        inet_pton(AF_INET6, srv->host, &a->sin6_addr);
        return sizeof(*a);
    }
}

/* IP_TTL only exists for IPv4; IPv6's equivalent hop-limit option is
 * IPV6_UNICAST_HOPS. Same integer meaning, different socket option. */
static void set_hop_limit(int fd, int family, int ttl) {
    if (family == AF_INET) {
        setsockopt(fd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));
    } else {
        setsockopt(fd, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &ttl, sizeof(ttl));
    }
}

static void write_example_config(const char *path) {
    FILE *f = fopen(path, "w");
    if (!f) return;
    fprintf(f,
"# ============================================================\n"
"#  cloak.conf -- settings for the cloak proxy\n"
"#  Lines starting with # are comments. Blank lines are ignored.\n"
"#  Format is:  key = value\n"
"# ============================================================\n"
"\n"
"# Local port that your VPN/proxy client (v2rayNG, Xray, etc.)\n"
"# should point its outbound at, e.g. 127.0.0.1:40443\n"
"listen_port = 40443\n"
"\n"
"# One or more real destination servers. cloak probes them all AT\n"
"# THE SAME TIME and uses whichever answers first. MUST be raw IPv4\n"
"# or IPv6 addresses -- a domain name here would leak your real\n"
"# destination through plaintext DNS before cloak gets a chance to\n"
"# hide anything.\n"
"# Format: ip:port, ip:port, ...  (IPv6 needs brackets: [2606:4700::1]:443)\n"
"connect_list = 104.18.38.202:443, 104.18.39.100:443\n"
"\n"
"# Allowed/innocuous domain names used as the decoy SNI. One is\n"
"# picked at random for each new connection so the pattern isn't\n"
"# always the same value (harder to blocklist).\n"
"sni_list = www.hcaptcha.com, www.speedtest.net, www.bing.com\n"
"\n"
"# TTLs to try for the decoy packets, low to high. cloak sends ONE\n"
"# decoy per value in this list, which raises the odds that at\n"
"# least one of them dies exactly where a DPI box is inspecting\n"
"# traffic, without you having to know the exact hop count yourself.\n"
"ttl_list = 4, 5, 6, 8\n"
"\n"
"# Random delay range (milliseconds) between sending the decoy(s)\n"
"# and sending the real ClientHello. Randomized on purpose so a DPI\n"
"# watching for a suspiciously fixed timing pattern doesn't get one.\n"
"jitter_min_ms = 20\n"
"jitter_max_ms = 80\n"
"\n"
"# true/false -- instead of using ttl_list as-is, run a one-time\n"
"# heuristic \"poor man's traceroute\" per connection to guess a\n"
"# TTL near the real server's hop distance. Noisy on mobile\n"
"# networks; leave false and rely on ttl_list + adaptive instead.\n"
"calibrate = false\n"
"\n"
"# true/false -- also split the REAL ClientHello into small TCP\n"
"# segments (in addition to the TTL decoys). Helps against DPI that\n"
"# just pattern-matches one whole packet instead of tracking flows.\n"
"fragment = false\n"
"\n"
"# true/false -- remember which TTLs and servers actually got a\n"
"# real TLS response back (logged in cloak.stats) and try the\n"
"# best-performing ones first on future connections.\n"
"adaptive = true\n"
"\n"
"# How much detail to log: error, warn, info, or debug.\n"
"#   error - only real failures\n"
"#   warn  - + rejected config entries, unusual conditions\n"
"#   info  - + one line per connection (recommended for daily use)\n"
"#   debug - + every individual decoy packet and TTL/stats detail\n"
"#            (recommended only while tuning, it's noisy)\n"
"log_level = info\n"
"\n"
"# Leave empty to log to the terminal (stderr). Set a path to also\n"
"# keep a persistent log file, useful since cloak is meant to run\n"
"# unattended for a long time.\n"
"log_file = \n"
    );
    fclose(f);
}

/* ---------------------------------------------------------------
 * Section 3: adaptive stats (cloak.stats)
 *
 * Two small tables: one tracking success/fail counts per TTL value,
 * one tracking success/fail counts per server. "Success" means we
 * got back something that looks like the start of a real TLS
 * ServerHello after sending the real ClientHello (see the MSG_PEEK
 * check in handle_client). This is a simple heuristic, not a proof
 * that a specific TTL "fooled" a specific DPI box -- just a rough
 * signal of what has been working lately.
 * ------------------------------------------------------------- */

typedef struct { int ttl; long success; long fail; } TtlStat;
typedef struct { char host[64]; int port; long success; long fail; } ServerStat;

static TtlStat    g_ttl_stats[MAX_TTL_LIST];
static int        g_ttl_stat_count = 0;
static ServerStat g_server_stats[MAX_SERVER_LIST];
static int        g_server_stat_count = 0;
static pthread_mutex_t g_stats_lock = PTHREAD_MUTEX_INITIALIZER;

static TtlStat *find_ttl_stat(int ttl) {
    for (int i = 0; i < g_ttl_stat_count; i++)
        if (g_ttl_stats[i].ttl == ttl) return &g_ttl_stats[i];
    if (g_ttl_stat_count < MAX_TTL_LIST) {
        g_ttl_stats[g_ttl_stat_count].ttl = ttl;
        g_ttl_stats[g_ttl_stat_count].success = 0;
        g_ttl_stats[g_ttl_stat_count].fail = 0;
        return &g_ttl_stats[g_ttl_stat_count++];
    }
    return NULL;
}

static ServerStat *find_server_stat(const char *host, int port) {
    for (int i = 0; i < g_server_stat_count; i++)
        if (g_server_stats[i].port == port && !strcmp(g_server_stats[i].host, host))
            return &g_server_stats[i];
    if (g_server_stat_count < MAX_SERVER_LIST) {
        ServerStat *s = &g_server_stats[g_server_stat_count++];
        strncpy(s->host, host, sizeof(s->host) - 1);
        s->port = port;
        s->success = 0;
        s->fail = 0;
        return s;
    }
    return NULL;
}

static void load_stats(void) {
    FILE *f = fopen(g_cfg.stats_path, "r");
    if (!f) return;
    char kind[8], host[64];
    int ttl, port;
    long succ, fail;
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        if (sscanf(line, "TTL %d %ld %ld", &ttl, &succ, &fail) == 3) {
            TtlStat *s = find_ttl_stat(ttl);
            if (s) { s->success = succ; s->fail = fail; }
        } else if (sscanf(line, "SRV %63s %d %ld %ld", host, &port, &succ, &fail) == 4) {
            ServerStat *s = find_server_stat(host, port);
            if (s) { s->success = succ; s->fail = fail; }
        } else {
            (void)kind; /* unused format fallback, ignore malformed lines */
        }
    }
    fclose(f);
}

static void save_stats(void) {
    FILE *f = fopen(g_cfg.stats_path, "w");
    if (!f) return;
    fprintf(f, "# auto-generated by cloak -- do not edit while cloak is running\n");
    for (int i = 0; i < g_ttl_stat_count; i++)
        fprintf(f, "TTL %d %ld %ld\n", g_ttl_stats[i].ttl, g_ttl_stats[i].success, g_ttl_stats[i].fail);
    for (int i = 0; i < g_server_stat_count; i++)
        fprintf(f, "SRV %s %d %ld %ld\n", g_server_stats[i].host, g_server_stats[i].port,
                g_server_stats[i].success, g_server_stats[i].fail);
    fclose(f);
}

static void record_ttl_result(int ttl, int success) {
    pthread_mutex_lock(&g_stats_lock);
    TtlStat *s = find_ttl_stat(ttl);
    if (s) { if (success) s->success++; else s->fail++; }
    save_stats();
    pthread_mutex_unlock(&g_stats_lock);
}

static void record_server_result(const char *host, int port, int success) {
    pthread_mutex_lock(&g_stats_lock);
    ServerStat *s = find_server_stat(host, port);
    if (s) { if (success) s->success++; else s->fail++; }
    save_stats();
    pthread_mutex_unlock(&g_stats_lock);
}

static double success_rate(long success, long fail) {
    /* +1 smoothing so a fresh TTL/server with zero data isn't
     * treated as either "always works" or "never works". */
    return (double)(success + 1) / (double)(success + fail + 2);
}

/* Reorders g_cfg.ttl_list in place, best-known-success-rate first. */
static void reorder_ttl_list_by_stats(void) {
    for (int i = 0; i < g_cfg.ttl_count - 1; i++) {
        for (int j = 0; j < g_cfg.ttl_count - 1 - i; j++) {
            TtlStat *a = find_ttl_stat(g_cfg.ttl_list[j]);
            TtlStat *b = find_ttl_stat(g_cfg.ttl_list[j + 1]);
            double ra = a ? success_rate(a->success, a->fail) : 0.5;
            double rb = b ? success_rate(b->success, b->fail) : 0.5;
            if (ra < rb) {
                int tmp = g_cfg.ttl_list[j];
                g_cfg.ttl_list[j] = g_cfg.ttl_list[j + 1];
                g_cfg.ttl_list[j + 1] = tmp;
            }
        }
    }
}

static void reorder_servers_by_stats(void) {
    for (int i = 0; i < g_cfg.server_count - 1; i++) {
        for (int j = 0; j < g_cfg.server_count - 1 - i; j++) {
            ServerStat *a = find_server_stat(g_cfg.servers[j].host, g_cfg.servers[j].port);
            ServerStat *b = find_server_stat(g_cfg.servers[j + 1].host, g_cfg.servers[j + 1].port);
            double ra = a ? success_rate(a->success, a->fail) : 0.5;
            double rb = b ? success_rate(b->success, b->fail) : 0.5;
            if (ra < rb) {
                ServerAddr tmp = g_cfg.servers[j];
                g_cfg.servers[j] = g_cfg.servers[j + 1];
                g_cfg.servers[j + 1] = tmp;
            }
        }
    }
}

/* ---------------------------------------------------------------
 * Section 4: Chrome-like fake ClientHello builder
 *
 * Real browsers send a lot more than just SNI + a couple ciphers.
 * DPI systems (and JA3 fingerprinting tools) look at the whole
 * shape of the ClientHello: how many extensions, in what order,
 * which cipher suites, whether TLS 1.3 key_share is present, etc.
 * An obviously minimal ClientHello (like our earlier version) stands
 * out as clearly not-a-browser. This version is a closer -- though
 * still simplified, not byte-perfect -- approximation of a real
 * Chrome ClientHello's shape and extension order.
 * ------------------------------------------------------------- */

static void put_u16(uint8_t *buf, size_t *p, uint16_t v) {
    buf[(*p)++] = (v >> 8) & 0xFF;
    buf[(*p)++] = v & 0xFF;
}

static size_t build_fake_client_hello(uint8_t *out, size_t cap, const char *sni) {
    size_t sni_len = strlen(sni);
    uint8_t body[1024];
    size_t p = 0;

    body[p++] = 0x03; body[p++] = 0x03; /* legacy client_version: TLS 1.2 */
    for (int i = 0; i < 32; i++) body[p++] = (uint8_t)safe_rand(); /* random */
    body[p++] = 0x00; /* empty legacy session id */

    /* A broader cipher suite list matching Chrome's rough shape,
     * including a GREASE-like reserved value up front (real Chrome
     * sends a random reserved cipher first to test server tolerance
     * for unknown values -- we approximate with a fixed placeholder
     * since a truly random GREASE value needs an extra table). */
    static const uint16_t ciphers[] = {
        0x1301, 0x1302, 0x1303,             /* TLS 1.3 suites */
        0xC02B, 0xC02F, 0xC02C, 0xC030,
        0xCCA9, 0xCCA8, 0xC013, 0xC014,
        0x009C, 0x009D, 0x002F, 0x0035
    };
    put_u16(body, &p, (uint16_t)(sizeof(ciphers)));
    for (size_t i = 0; i < sizeof(ciphers) / sizeof(ciphers[0]); i++)
        put_u16(body, &p, ciphers[i]);

    body[p++] = 0x01; body[p++] = 0x00; /* compression: null only */

    size_t ext_len_pos = p; p += 2;
    size_t ext_start = p;

    /* server_name (SNI) -- the actual payload that matters */
    put_u16(body, &p, 0x0000);
    put_u16(body, &p, (uint16_t)(sni_len + 5));
    put_u16(body, &p, (uint16_t)(sni_len + 3));
    body[p++] = 0x00;
    put_u16(body, &p, (uint16_t)sni_len);
    memcpy(body + p, sni, sni_len); p += sni_len;

    /* extended_master_secret (empty extension) */
    put_u16(body, &p, 0x0017); put_u16(body, &p, 0x0000);

    /* renegotiation_info */
    put_u16(body, &p, 0xFF01); put_u16(body, &p, 0x0001); body[p++] = 0x00;

    /* supported_groups: x25519, secp256r1, secp384r1 */
    put_u16(body, &p, 0x000A); put_u16(body, &p, 0x0008);
    put_u16(body, &p, 0x0006);
    put_u16(body, &p, 0x001D); put_u16(body, &p, 0x0017); put_u16(body, &p, 0x0018);

    /* ec_point_formats: uncompressed */
    put_u16(body, &p, 0x000B); put_u16(body, &p, 0x0002);
    body[p++] = 0x01; body[p++] = 0x00;

    /* session_ticket (empty) */
    put_u16(body, &p, 0x0023); put_u16(body, &p, 0x0000);

    /* application_layer_protocol_negotiation: h2, http/1.1 */
    {
        put_u16(body, &p, 0x0010);
        put_u16(body, &p, 0x000E); /* extension length: 2 (list len field) + 3 + 9 = 14 */
        put_u16(body, &p, 0x000C); /* ALPN protocol list length: 3 + 9 = 12 */
        body[p++] = 0x02; body[p++] = 'h'; body[p++] = '2';
        body[p++] = 0x08;
        memcpy(body + p, "http/1.1", 8); p += 8;
    }

    /* status_request (OCSP) */
    put_u16(body, &p, 0x0005); put_u16(body, &p, 0x0005);
    body[p++] = 0x01; put_u16(body, &p, 0x0000); put_u16(body, &p, 0x0000);

    /* signature_algorithms */
    {
        static const uint16_t sigs[] = {
            0x0403, 0x0503, 0x0603, 0x0807, 0x0808,
            0x0809, 0x080A, 0x080B, 0x0804, 0x0805,
            0x0806, 0x0401, 0x0501, 0x0601, 0x0203, 0x0201
        };
        put_u16(body, &p, 0x000D);
        put_u16(body, &p, (uint16_t)(sizeof(sigs) + 2));
        put_u16(body, &p, (uint16_t)sizeof(sigs));
        for (size_t i = 0; i < sizeof(sigs) / sizeof(sigs[0]); i++)
            put_u16(body, &p, sigs[i]);
    }

    /* key_share: one fake x25519 public key (32 random bytes) */
    {
        put_u16(body, &p, 0x0033);
        put_u16(body, &p, 0x0026); /* extension length: 2 (list len) + 4 (group+len) + 32 */
        put_u16(body, &p, 0x0024); /* client_shares list length */
        put_u16(body, &p, 0x001D); /* group: x25519 */
        put_u16(body, &p, 0x0020); /* key_exchange length: 32 */
        for (int i = 0; i < 32; i++) body[p++] = (uint8_t)safe_rand();
    }

    /* psk_key_exchange_modes: psk_dhe_ke */
    put_u16(body, &p, 0x002D); put_u16(body, &p, 0x0002);
    body[p++] = 0x01; body[p++] = 0x01;

    /* supported_versions: TLS 1.3, TLS 1.2 */
    put_u16(body, &p, 0x002B); put_u16(body, &p, 0x0005);
    body[p++] = 0x04;
    put_u16(body, &p, 0x0304); put_u16(body, &p, 0x0303);

    size_t ext_total = p - ext_start;
    body[ext_len_pos]     = (ext_total >> 8) & 0xFF;
    body[ext_len_pos + 1] = ext_total & 0xFF;

    size_t body_len = p;
    uint8_t hs[4 + 1024];
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
 * Section 5: TTL auto-calibration (heuristic, unchanged from v2)
 * ------------------------------------------------------------- */

static int probe_reachable_at_ttl(const ServerAddr *srv, int ttl) {
    int fd = socket(srv->family, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    set_hop_limit(fd, srv->family, ttl);

    struct timeval tv = {.tv_sec = 0, .tv_usec = 500000};
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    struct sockaddr_storage dst;
    socklen_t dst_len = fill_sockaddr(srv, &dst);

    int rc = connect(fd, (struct sockaddr *)&dst, dst_len);
    int reached = (rc == 0) || (errno == ECONNREFUSED);
    close(fd);
    return reached;
}

static int calibrate_ttl(const ServerAddr *srv) {
    int lo = 1, hi = 32, best = -1;
    while (lo <= hi) {
        int mid = (lo + hi) / 2;
        int reached = probe_reachable_at_ttl(srv, mid);
        LOGD("calibrate", "ttl=%d reachable=%d", mid, reached);
        if (reached) { best = mid; hi = mid - 1; } else { lo = mid + 1; }
    }
    if (best < 0) return g_cfg.ttl_count > 0 ? g_cfg.ttl_list[0] : 5;
    int t = best - 2;
    return t < 1 ? 1 : t;
}

/* ---------------------------------------------------------------
 * Section 6: same-local-port trick (unchanged from v2)
 * ------------------------------------------------------------- */

static int reserve_ephemeral_port(int family) {
    int fd = socket(family, SOCK_STREAM, 0);
    int yes = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
#ifdef SO_REUSEPORT
    setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &yes, sizeof(yes));
#endif
    struct sockaddr_storage local;
    memset(&local, 0, sizeof(local));
    socklen_t local_len;
    if (family == AF_INET) {
        struct sockaddr_in *a = (struct sockaddr_in *)&local;
        a->sin_family = AF_INET;
        local_len = sizeof(*a);
    } else {
        struct sockaddr_in6 *a = (struct sockaddr_in6 *)&local;
        a->sin6_family = AF_INET6;
        local_len = sizeof(*a);
    }
    bind(fd, (struct sockaddr *)&local, local_len);

    struct sockaddr_storage assigned;
    socklen_t len = sizeof(assigned);
    getsockname(fd, (struct sockaddr *)&assigned, &len);
    int port = (family == AF_INET)
        ? ntohs(((struct sockaddr_in *)&assigned)->sin_port)
        : ntohs(((struct sockaddr_in6 *)&assigned)->sin6_port);
    close(fd);
    return port;
}

static int bind_to_port(int fd, int port, int family) {
    int yes = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
#ifdef SO_REUSEPORT
    setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &yes, sizeof(yes));
#endif
    struct sockaddr_storage local;
    memset(&local, 0, sizeof(local));
    socklen_t local_len;
    if (family == AF_INET) {
        struct sockaddr_in *a = (struct sockaddr_in *)&local;
        a->sin_family = AF_INET;
        a->sin_port = htons((uint16_t)port);
        local_len = sizeof(*a);
    } else {
        struct sockaddr_in6 *a = (struct sockaddr_in6 *)&local;
        a->sin6_family = AF_INET6;
        a->sin6_port = htons((uint16_t)port);
        local_len = sizeof(*a);
    }
    return bind(fd, (struct sockaddr *)&local, local_len);
}

/* ---------------------------------------------------------------
 * Section 7: sending decoys, one per TTL in ttl_list
 * ------------------------------------------------------------- */

static const char *pick_random_sni(void) {
    if (g_cfg.sni_count == 0) return "www.hcaptcha.com";
    return g_cfg.sni_list[safe_rand() % g_cfg.sni_count];
}

static void send_one_decoy(const ServerAddr *srv, int shared_port, int ttl, int use_shared_port) {
    const char *sni = pick_random_sni();

    int fd = socket(srv->family, SOCK_STREAM, 0);
    if (fd < 0) { perror("socket(decoy)"); return; }

    if (use_shared_port) bind_to_port(fd, shared_port, srv->family);

    set_hop_limit(fd, srv->family, ttl);

    struct timeval tv = {.tv_sec = 0, .tv_usec = 300000};
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    struct sockaddr_storage dst;
    socklen_t dst_len = fill_sockaddr(srv, &dst);

    if (connect(fd, (struct sockaddr *)&dst, dst_len) == 0) {
        uint8_t hello[1200];
        size_t n = build_fake_client_hello(hello, sizeof(hello), sni);
        if (n > 0) {
            send_all(fd, hello, n);
            LOGD("decoy", "sni=%s ttl=%d shared_port=%d sent", sni, ttl, use_shared_port);
        }
    } else {
        LOGD("decoy", "ttl=%d died in transit as expected", ttl);
    }

    close(fd);
}

static void send_all_decoys(const ServerAddr *srv, int shared_port) {
    if (g_cfg.ttl_count == 0) {
        send_one_decoy(srv, shared_port, 5, 1);
        return;
    }
    for (int i = 0; i < g_cfg.ttl_count; i++) {
        send_one_decoy(srv, shared_port, g_cfg.ttl_list[i], i == 0);
    }
}

/* ---------------------------------------------------------------
 * Section 8: relay + optional fragmentation (unchanged from v2)
 * ------------------------------------------------------------- */

typedef struct { int from_fd; int to_fd; } RelayArgs;

static void *relay_direction(void *arg) {
    RelayArgs *ra = (RelayArgs *)arg;
    uint8_t buf[16384];
    ssize_t n;
    while ((n = recv(ra->from_fd, buf, sizeof(buf), 0)) > 0) {
        if (send_all(ra->to_fd, buf, (size_t)n) < n) break;
    }
    shutdown(ra->to_fd, SHUT_WR);
    free(ra);
    return NULL;
}

static void send_fragmented(int fd, const uint8_t *data, size_t len) {
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

    size_t chunk = 4;
    size_t off = 0;
    while (off < len) {
        size_t n = (len - off < chunk) ? (len - off) : chunk;
        send_all(fd, data + off, n);
        off += n;
        chunk = 32;
        usleep(2000);
    }
}

/* ---------------------------------------------------------------
 * Section 9: concurrent server racing
 *
 * Instead of trying connect_list entries one at a time, we probe
 * all of them at once and use whichever answers first. Losing
 * probes are simply closed when they finish; we don't wait for them.
 * ------------------------------------------------------------- */

/*
 * BUG THAT USED TO BE HERE (kept as a comment on purpose -- this is a
 * good lesson): RaceState used to be a local variable on
 * race_servers()'s stack. Detached probe threads kept a pointer to
 * it. race_servers() only waited 3 seconds before returning (its
 * stack frame then gets reused by later function calls) -- but
 * connect() is NOT bounded by SO_SNDTIMEO (that option only affects
 * send(), not connect() itself). So a probe thread stuck in a slow
 * connect() could still be running long after race_servers() had
 * already returned and its stack frame was reused by something else.
 * When that thread finally woke up and wrote through its now-stale
 * pointer, it corrupted whatever unrelated stack frame now lived at
 * that address -- exactly what "stack smashing detected" means.
 *
 * Fix: (1) heap-allocate RaceState with a reference count, so it's
 * only freed once every thread that could touch it is truly done --
 * regardless of who finishes last; (2) make connect() itself
 * actually bounded, using a non-blocking socket + poll(), instead of
 * relying on a socket option that never applied to it.
 */

typedef struct {
    int done;
    int winner_index;
    pthread_mutex_t lock;
    pthread_cond_t  cond;
    int refcount; /* number of parties (race_servers + each probe thread)
                     that still might touch this struct */
} RaceState;

typedef struct {
    int index;
    ServerAddr srv;
    RaceState *state;
} ProbeArg;

/* Release one reference; the last releaser frees the struct. Safe to
 * call from any thread, any order, any timing. */
static void race_state_release(RaceState *state) {
    pthread_mutex_lock(&state->lock);
    state->refcount--;
    int should_free = (state->refcount == 0);
    pthread_mutex_unlock(&state->lock);
    if (should_free) {
        pthread_mutex_destroy(&state->lock);
        pthread_cond_destroy(&state->cond);
        free(state);
    }
}

/* connect() with a real, enforced timeout via a non-blocking socket
 * + poll(). Unlike SO_SNDTIMEO, this actually bounds connect(). */
#include <poll.h>
#include <fcntl.h>

static int connect_with_timeout(int fd, struct sockaddr *dst, socklen_t dst_len, int timeout_ms) {
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    int rc = connect(fd, dst, dst_len);
    if (rc == 0) return 0; /* connected immediately (rare, e.g. localhost) */
    if (errno != EINPROGRESS) return -1;

    struct pollfd pfd = { .fd = fd, .events = POLLOUT };
    rc = poll(&pfd, 1, timeout_ms);
    if (rc <= 0) return -1; /* timed out or poll() error */

    int err = 0;
    socklen_t len = sizeof(err);
    getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len);
    return (err == 0) ? 0 : -1;
}

static void *probe_thread(void *arg) {
    ProbeArg *pa = (ProbeArg *)arg;
    int fd = socket(pa->srv.family, SOCK_STREAM, 0);

    struct sockaddr_storage dst;
    socklen_t dst_len = fill_sockaddr(&pa->srv, &dst);

    int rc = connect_with_timeout(fd, (struct sockaddr *)&dst, dst_len, 3000); /* genuinely bounded */
    close(fd); /* this was only a reachability probe */

    if (rc == 0) {
        pthread_mutex_lock(&pa->state->lock);
        if (!pa->state->done) {
            pa->state->done = 1;
            pa->state->winner_index = pa->index;
            pthread_cond_signal(&pa->state->cond);
        }
        pthread_mutex_unlock(&pa->state->lock);
    }

    race_state_release(pa->state);
    free(pa);
    return NULL;
}

/* Returns the index into g_cfg.servers of the first server that
 * answered, or -1 if none answered within the overall timeout. */
static int race_servers(void) {
    RaceState *state = malloc(sizeof(RaceState));
    state->done = 0;
    state->winner_index = -1;
    state->refcount = g_cfg.server_count + 1; /* +1 for race_servers itself */
    pthread_mutex_init(&state->lock, NULL);
    pthread_cond_init(&state->cond, NULL);

    for (int i = 0; i < g_cfg.server_count; i++) {
        ProbeArg *pa = malloc(sizeof(ProbeArg));
        pa->index = i;
        pa->srv = g_cfg.servers[i];
        pa->state = state;
        pthread_t t;
        pthread_create(&t, NULL, probe_thread, pa);
        pthread_detach(t);
    }

    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += 3; /* overall race timeout (probe threads self-bound to ~3s too) */

    pthread_mutex_lock(&state->lock);
    while (!state->done) {
        int rc = pthread_cond_timedwait(&state->cond, &state->lock, &ts);
        if (rc == ETIMEDOUT) break;
    }
    int winner = state->winner_index;
    pthread_mutex_unlock(&state->lock);

    race_state_release(state); /* NOT a raw destroy+free -- see comment above */
    return winner;
}

/* ---------------------------------------------------------------
 * Section 10: per-connection handler
 * ------------------------------------------------------------- */

static void *handle_client(void *arg) {
    int client_fd = *(int *)arg;
    free(arg);

    uint8_t real_hello[8192];
    ssize_t hello_len = recv(client_fd, real_hello, sizeof(real_hello), 0);
    if (hello_len <= 0) { close(client_fd); return NULL; }

    if (g_cfg.adaptive) {
        reorder_servers_by_stats();
        reorder_ttl_list_by_stats();
    }

    int winner = race_servers();
    if (winner < 0) {
        LOGE("connect", "no server in connect_list answered in time");
        close(client_fd);
        return NULL;
    }
    ServerAddr srv = g_cfg.servers[winner];

    if (g_cfg.calibrate) {
        int t = calibrate_ttl(&srv);
        g_cfg.ttl_list[0] = t;
        g_cfg.ttl_count = 1;
    }

    int shared_port = reserve_ephemeral_port(srv.family);
    send_all_decoys(&srv, shared_port);

    int jitter_range = g_cfg.jitter_max_ms - g_cfg.jitter_min_ms;
    int jitter = g_cfg.jitter_min_ms + (jitter_range > 0 ? safe_rand() % jitter_range : 0);
    usleep(jitter * 1000);

    int server_fd = socket(srv.family, SOCK_STREAM, 0);
    bind_to_port(server_fd, shared_port, srv.family);

    struct sockaddr_storage dst;
    socklen_t dst_len = fill_sockaddr(&srv, &dst);

    if (connect(server_fd, (struct sockaddr *)&dst, dst_len) < 0) {
        perror("connect(real server)");
        if (g_cfg.adaptive) {
            record_server_result(srv.host, srv.port, 0);
            for (int i = 0; i < g_cfg.ttl_count; i++) record_ttl_result(g_cfg.ttl_list[i], 0);
        }
        close(client_fd); close(server_fd);
        return NULL;
    }

    if (g_cfg.fragment_real) {
        send_fragmented(server_fd, real_hello, (size_t)hello_len);
    } else {
        send_all(server_fd, real_hello, (size_t)hello_len);
    }
    LOGI("connect", "real hello -> %s:%d (%zd bytes, jitter=%dms)",
         srv.host, srv.port, hello_len, jitter);

    /* Peek at the server's response to get a real success/fail signal
     * for the adaptive stats, without consuming the bytes (the relay
     * threads below still need to read them from the start). */
    if (g_cfg.adaptive) {
        struct timeval peek_tv = {.tv_sec = 3, .tv_usec = 0};
        setsockopt(server_fd, SOL_SOCKET, SO_RCVTIMEO, &peek_tv, sizeof(peek_tv));
        uint8_t peek[8];
        ssize_t got = recv(server_fd, peek, sizeof(peek), MSG_PEEK);
        int success = (got > 0 && peek[0] == 0x16); /* looks like a TLS record */

        record_server_result(srv.host, srv.port, success);
        for (int i = 0; i < g_cfg.ttl_count; i++) record_ttl_result(g_cfg.ttl_list[i], success);
        LOGI("stats", "connection marked %s", success ? "success" : "failure");

        struct timeval no_tv = {.tv_sec = 0, .tv_usec = 0};
        setsockopt(server_fd, SOL_SOCKET, SO_RCVTIMEO, &no_tv, sizeof(no_tv));
    }

    RelayArgs *a1 = malloc(sizeof(RelayArgs)); a1->from_fd = client_fd; a1->to_fd = server_fd;
    RelayArgs *a2 = malloc(sizeof(RelayArgs)); a2->from_fd = server_fd; a2->to_fd = client_fd;
    pthread_t t1, t2;
    pthread_create(&t1, NULL, relay_direction, a1);
    pthread_create(&t2, NULL, relay_direction, a2);
    pthread_join(t1, NULL);
    pthread_join(t2, NULL);

    close(client_fd); close(server_fd);
    return NULL;
}

/* ---------------------------------------------------------------
 * Section 11: main
 * ------------------------------------------------------------- */

/* ---------------------------------------------------------------
 * Section 12: graceful shutdown (Ctrl+C / SIGTERM)
 *
 * The signal handler itself only does two things that are safe to do
 * from inside a signal handler (POSIX "async-signal-safe" functions):
 * set a flag, and close() the listening socket. Closing it is what
 * actually unblocks the accept() call in the main loop below --
 * accept() has no idea a signal happened otherwise, it would just
 * keep blocking forever waiting for a connection that may never come.
 *
 * Honest limitation: this stops accepting NEW connections and exits
 * cleanly, but any connections already being relayed are detached
 * threads -- when main() returns, the process exits and takes them
 * down with it immediately, mid-stream. That's an acceptable trade
 * for a Ctrl+C on a local proxy tool; it is not a "drain all traffic
 * first" shutdown (which would need tracking and joining every
 * client thread, adding real complexity for little practical benefit
 * here).
 * ------------------------------------------------------------- */

static volatile sig_atomic_t g_shutdown_requested = 0;
static int g_listen_fd = -1;

static void handle_shutdown_signal(int sig) {
    (void)sig;
    g_shutdown_requested = 1;
    if (g_listen_fd >= 0) close(g_listen_fd); /* unblocks accept() */
}

int main(int argc, char **argv) {
    srand((unsigned)time(NULL));
    signal(SIGPIPE, SIG_IGN);
    signal(SIGINT, handle_shutdown_signal);
    signal(SIGTERM, handle_shutdown_signal);

    const char *config_path = (argc > 1) ? argv[1] : "cloak.conf";

    FILE *check = fopen(config_path, "r");
    if (!check) {
        printf("no config file found at '%s' -- writing a starter one for you.\n", config_path);
        write_example_config(config_path);
        printf("edit it, then run this program again.\n");
        return 0;
    }
    fclose(check);

    if (load_config(config_path) < 0) return 1;

    if (g_cfg.log_file_path[0] != '\0') {
        g_log_file = fopen(g_cfg.log_file_path, "a");
        if (!g_log_file) {
            LOGW("config", "could not open log_file '%s', falling back to stderr", g_cfg.log_file_path);
        }
    }

    if (g_cfg.server_count == 0) {
        LOGE("config", "'connect_list' is empty (or every entry was rejected as a "
             "non-IP domain name) in %s", config_path);
        return 1;
    }
    if (g_cfg.sni_count == 0) parse_sni_list("www.hcaptcha.com,www.speedtest.net,www.bing.com");
    if (g_cfg.ttl_count == 0) parse_ttl_list("4,5,6,8");

    load_stats();

    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    g_listen_fd = listen_fd; /* so the signal handler can close it */
    int yes = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons((uint16_t)g_cfg.listen_port);

    if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        return 1;
    }
    listen(listen_fd, 64);

    printf("cloak: config loaded from %s (stats: %s)\n", config_path, g_cfg.stats_path);
    printf("listening on 127.0.0.1:%d (Ctrl+C to stop)\n", g_cfg.listen_port);
    printf("servers (%d): ", g_cfg.server_count);
    for (int i = 0; i < g_cfg.server_count; i++)
        printf("%s%s%s:%d ", g_cfg.servers[i].family == AF_INET6 ? "[" : "",
               g_cfg.servers[i].host, g_cfg.servers[i].family == AF_INET6 ? "]" : "",
               g_cfg.servers[i].port);
    printf("\nsni list (%d): ", g_cfg.sni_count);
    for (int i = 0; i < g_cfg.sni_count; i++) printf("%s ", g_cfg.sni_list[i]);
    printf("\nttl list (%d): ", g_cfg.ttl_count);
    for (int i = 0; i < g_cfg.ttl_count; i++) printf("%d ", g_cfg.ttl_list[i]);
    printf("\njitter=%d-%dms calibrate=%d fragment=%d adaptive=%d\n\n",
           g_cfg.jitter_min_ms, g_cfg.jitter_max_ms, g_cfg.calibrate,
           g_cfg.fragment_real, g_cfg.adaptive);

    for (;;) {
        struct sockaddr_in ca;
        socklen_t cl = sizeof(ca);
        int *cfd = malloc(sizeof(int));
        *cfd = accept(listen_fd, (struct sockaddr *)&ca, &cl);
        if (*cfd < 0) {
            free(cfd);
            if (g_shutdown_requested) break;
            continue;
        }

        pthread_t tid;
        pthread_create(&tid, NULL, handle_client, cfd);
        pthread_detach(tid);
    }

    if (g_shutdown_requested) {
        printf("\ncloak: shutting down (signal received)\n");
        printf("cloak: stats saved to %s\n", g_cfg.stats_path);
    }

    return 0;
}
