/*
 * tcp_state_analyzer.c
 *
 * Simple TCP state machine analyzer using libpcap.
 * Captures IPv4 TCP packets, tracks connection states, prints transitions
 * and can write a DOT file representing connection lifecycle events.
 *
 * Build: gcc -o tcp_state_analyzer src/tcp_state_analyzer.c -lpcap
 * Run (requires privileges to open an interface):
 *   sudo ./tcp_state_analyzer -i <interface> [-o out.dot]
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <signal.h>

/* Platform-specific includes
 * On Unix-like systems include the usual BSD sockets and header files.
 * On Windows, use Winsock2 and the WinPcap/Npcap pcap.h. The editor on
 * Windows may show red-underlines for the POSIX headers; guarding them
 * prevents that while keeping the Linux build path unchanged.
 */
#if defined(_WIN32) || defined(_WIN64)
#include <winsock2.h>
#include <ws2tcpip.h>
#if defined(__has_include)
#if __has_include(<pcap.h>)
#include <pcap.h>
#else
/* pcap.h not available: provide lightweight stubs so the file can compile
 * (functionality will be disabled at runtime). Prefer installing Npcap SDK
 * on Windows or libpcap-dev on Linux for real packet capture.
 */
#define NO_PCAP 1
typedef void pcap_t;
struct pcap_pkthdr
{
    unsigned int caplen;
    unsigned int len;
};
struct bpf_program
{
    void *bf_insns;
};
#define PCAP_ERRBUF_SIZE 256
#define PCAP_NETMASK_UNKNOWN 0
static inline pcap_t *pcap_open_live(const char *device, int snaplen, int promisc, int to_ms, char *errbuf)
{
    if (errbuf)
        snprintf(errbuf, PCAP_ERRBUF_SIZE, "pcap not available");
    return NULL;
}
static inline int pcap_compile(pcap_t *p, struct bpf_program *fp, const char *str, int optimize, unsigned int netmask)
{
    (void)p;
    (void)fp;
    (void)str;
    (void)optimize;
    (void)netmask;
    return -1;
}
static inline int pcap_setfilter(pcap_t *p, struct bpf_program *fp)
{
    (void)p;
    (void)fp;
    return -1;
}
static inline void pcap_loop(pcap_t *p, int cnt, void (*cb)(u_char *, const struct pcap_pkthdr *, const u_char *), u_char *user)
{
    (void)p;
    (void)cnt;
    (void)cb;
    (void)user;
}
static inline void pcap_close(pcap_t *p) { (void)p; }
static inline void pcap_breakloop(pcap_t *p) { (void)p; }
#endif
#else
#include <pcap.h>
#endif
/* Define common network headers/types on Windows when building with Npcap/WinPcap
 * The Npcap SDK provides pcap.h but not the BSD-style netinet headers.
 * Provide minimal definitions used by this program so it compiles under MSVC.
 */
#ifndef u_char
typedef unsigned char u_char;
#endif

/* Ethernet header */
struct ether_header
{
    u_char ether_dhost[6];
    u_char ether_shost[6];
    uint16_t ether_type;
};

/* IPv4 header (minimal fields used) */
struct ip
{
    unsigned char ip_hl : 4, ip_v : 4; /* header length, version */
    u_char ip_tos;
    uint16_t ip_len;
    uint16_t ip_id;
    uint16_t ip_off;
    u_char ip_ttl;
    u_char ip_p;
    uint16_t ip_sum;
    struct in_addr ip_src;
    struct in_addr ip_dst;
};

/* TCP header (minimal fields used) */
struct tcphdr
{
    uint16_t th_sport;
    uint16_t th_dport;
    uint32_t th_seq;
    uint32_t th_ack;
    uint8_t th_offx2; /* data offset and reserved */
    uint8_t th_flags;
    uint16_t th_win;
    uint16_t th_sum;
    uint16_t th_urp;
};

/* Ether type for IPv4 */
#ifndef ETHERTYPE_IP
#define ETHERTYPE_IP 0x0800
#endif

/* inet_ntop replacement macro to use InetNtopA on Windows */
#ifndef inet_ntop
#define inet_ntop InetNtopA
#endif
#else
#if defined(__has_include)
#if __has_include(<pcap.h>)
#include <pcap.h>
#else
/* pcap.h not available: provide lightweight stubs so the file can compile
 * (functionality will be disabled at runtime). Prefer installing libpcap-dev
 * on Linux for real packet capture.
 */
#define NO_PCAP 1
typedef void pcap_t;
struct pcap_pkthdr
{
    unsigned int caplen;
    unsigned int len;
};
struct bpf_program
{
    void *bf_insns;
};
#define PCAP_ERRBUF_SIZE 256
#define PCAP_NETMASK_UNKNOWN 0
static inline pcap_t *pcap_open_live(const char *device, int snaplen, int promisc, int to_ms, char *errbuf)
{
    if (errbuf)
        snprintf(errbuf, PCAP_ERRBUF_SIZE, "pcap not available");
    return NULL;
}
static inline int pcap_compile(pcap_t *p, struct bpf_program *fp, const char *str, int optimize, unsigned int netmask)
{
    (void)p;
    (void)fp;
    (void)str;
    (void)optimize;
    (void)netmask;
    return -1;
}
static inline int pcap_setfilter(pcap_t *p, struct bpf_program *fp)
{
    (void)p;
    (void)fp;
    return -1;
}
static inline void pcap_loop(pcap_t *p, int cnt, void (*cb)(u_char *, const struct pcap_pkthdr *, const u_char *), u_char *user)
{
    (void)p;
    (void)cnt;
    (void)cb;
    (void)user;
}
static inline void pcap_close(pcap_t *p) { (void)p; }
static inline void pcap_breakloop(pcap_t *p) { (void)p; }
#endif
#else
#include <pcap.h>
#endif
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <net/ethernet.h>
#endif

/* Provide TCP flag definitions if not available (helps on some Windows setups)
 * TH_FIN  0x01
 * TH_SYN  0x02
 * TH_RST  0x04
 * TH_PUSH 0x08
 * TH_ACK  0x10
 * TH_URG  0x20
 */
#ifndef TH_SYN
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#endif

#define MAX_EVENTS 1024
#define KEYLEN 128

typedef enum
{
    S_NEW = 0,
    S_SYN_SENT,
    S_SYN_RECEIVED,
    S_ESTABLISHED,
    S_FIN_WAIT_1,
    S_FIN_WAIT_2,
    S_CLOSE_WAIT,
    S_CLOSING,
    S_LAST_ACK,
    S_TIME_WAIT,
    S_CLOSED
} tcp_state_t;

typedef struct event
{
    time_t t;
    char src[64];
    char dst[64];
    uint8_t flags;
    tcp_state_t new_state;
} event_t;

typedef struct conn
{
    char key[KEYLEN]; /* src:port-dst:port as first-seen direction */
    char a_ip[64];
    char b_ip[64];
    uint16_t a_port;
    uint16_t b_port;
    tcp_state_t state;
    time_t last_seen;
    event_t events[64];
    int ev_count;
    struct conn *next;
} conn_t;

static conn_t *conns = NULL;
static pcap_t *handle = NULL;
static char *dot_out = NULL;

/* helper to format key */
static void make_key(char *dst, const char *s_ip, uint16_t s_port, const char *d_ip, uint16_t d_port)
{
    snprintf(dst, KEYLEN, "%s:%u-%s:%u", s_ip, s_port, d_ip, d_port);
}

/* find connection by key or reverse key */
static conn_t *find_conn(const char *s_ip, uint16_t s_port, const char *d_ip, uint16_t d_port, int *rev)
{
    char key[KEYLEN], rkey[KEYLEN];
    make_key(key, s_ip, s_port, d_ip, d_port);
    make_key(rkey, d_ip, d_port, s_ip, s_port);
    conn_t *c = conns;
    while (c)
    {
        if (strcmp(c->key, key) == 0)
        {
            if (rev)
                *rev = 0;
            return 0;
        }
        {
            if (rev)
                *rev = 1;
            return c;
        }
        c = c->next;
    }
    if (rev)
        *rev = 0;
    return NULL;
}

static conn_t *create_conn(const char *s_ip, uint16_t s_port, const char *d_ip, uint16_t d_port)
{
    conn_t *c = calloc(1, sizeof(conn_t));
    if (!c)
        return NULL;
    make_key(c->key, s_ip, s_port, d_ip, d_port);
    strncpy(c->a_ip, s_ip, sizeof(c->a_ip) - 1);
    strncpy(c->b_ip, d_ip, sizeof(c->b_ip) - 1);
    c->a_port = s_port;
    c->b_port = d_port;
    c->state = S_NEW;
    c->last_seen = time(NULL);
    c->next = conns;
    conns = c;
    return c;
}

/* record an event on the connection */
static void record_event(conn_t *c, const char *s_ip, const char *d_ip, uint16_t flags, tcp_state_t newstate)
{
    if (!c)
        return;
    if (c->ev_count < (int)(sizeof(c->events) / sizeof(c->events[0])))
    {
        event_t *e = &c->events[c->ev_count++];
        e->t = time(NULL);
        strncpy(e->src, s_ip, sizeof(e->src) - 1);
        strncpy(e->dst, d_ip, sizeof(e->dst) - 1);
        e->flags = flags;
        e->new_state = newstate;
    }
}

/* Simplified state machine update based on observed flags
 * This is heuristic-based and intended for visualization rather than protocol conformance.
 */
static tcp_state_t update_state(conn_t *c, int from_a, uint8_t flags)
{
    (void)from_a; /* unused currently; keep the parameter for future use */
    tcp_state_t s = c->state;
    int syn = flags & TH_SYN;
    int ack = flags & TH_ACK;
    int fin = flags & TH_FIN;
    int rst = flags & TH_RST;

    if (rst)
    {
        s = S_CLOSED;
        return s;
    }

    switch (s)
    {
    case S_NEW:
        if (syn && !ack)
            s = S_SYN_SENT;
        else if (syn && ack)
            s = S_SYN_RECEIVED;
        else if (ack && !syn)
            s = S_ESTABLISHED;
        break;
    case S_SYN_SENT:
        if (syn && ack)
            s = S_SYN_RECEIVED; /* saw SYN+ACK */
        else if (ack)
            s = S_ESTABLISHED;
        break;
    case S_SYN_RECEIVED:
        if (ack)
            s = S_ESTABLISHED;
        break;
    case S_ESTABLISHED:
        if (fin)
            s = S_FIN_WAIT_1;
        break;
    case S_FIN_WAIT_1:
        if (ack)
            s = S_FIN_WAIT_2;
        if (fin)
            s = S_CLOSING;
        break;
    case S_FIN_WAIT_2:
        if (fin)
            s = S_TIME_WAIT;
        break;
    case S_CLOSING:
        if (ack)
            s = S_TIME_WAIT;
        break;
    case S_TIME_WAIT:
        /* timeout later to closed */
        break;
    case S_CLOSE_WAIT:
        if (fin)
            s = S_LAST_ACK;
        break;
    case S_LAST_ACK:
        if (ack)
            s = S_CLOSED;
        break;
    case S_CLOSED:
        break;
    }

    return s;
}

static void print_state_name(tcp_state_t s, char *buf, size_t n)
{
    const char *names[] = {
        "NEW", "SYN-SENT", "SYN-RECEIVED", "ESTABLISHED", "FIN-WAIT-1", "FIN-WAIT-2", "CLOSE-WAIT", "CLOSING", "LAST-ACK", "TIME-WAIT", "CLOSED"};
    if ((int)s < (int)(sizeof(names) / sizeof(names[0])))
        strncpy(buf, names[s], n - 1);
    else
        strncpy(buf, "?", n - 1);
}

static void handle_packet(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes)
{
    (void)user;
    (void)h;
    const struct ether_header *eth = (const struct ether_header *)bytes;
    if (ntohs(eth->ether_type) != ETHERTYPE_IP)
        return;
    const struct ip *ip = (const struct ip *)(bytes + sizeof(struct ether_header));
    if (ip->ip_p != IPPROTO_TCP)
        return;
    int ip_hdr_len = ip->ip_hl * 4;
    const struct tcphdr *tcp = (const struct tcphdr *)((const u_char *)ip + sizeof(struct ether_header) + ip_hdr_len);
    uint16_t sport = ntohs(tcp->th_sport);
    uint16_t dport = ntohs(tcp->th_dport);
    char s_ip[64], d_ip[64];
    inet_ntop(AF_INET, &ip->ip_src, s_ip, sizeof(s_ip));
    inet_ntop(AF_INET, &ip->ip_dst, d_ip, sizeof(d_ip));

    int rev = 0;
    conn_t *c = find_conn(s_ip, sport, d_ip, dport, &rev);
    if (!c)
    {
        c = create_conn(s_ip, sport, d_ip, dport);
        if (!c)
            return;
    }

    int from_a = (strcmp(s_ip, c->a_ip) == 0 && sport == c->a_port) ? 1 : 0;
    uint8_t flags = tcp->th_flags;
    tcp_state_t old = c->state;
    tcp_state_t new = update_state(c, from_a, flags);
    c->state = new;
    c->last_seen = time(NULL);
    record_event(c, s_ip, d_ip, flags, new);

    if (new != old)
    {
        char oldn[32], newn[32];
        print_state_name(old, oldn, sizeof(oldn));
        print_state_name(new, newn, sizeof(newn));
        printf("[%ld] %s:%u -> %s:%u flags=0x%02x %s -> %s\n",
               (long)time(NULL), s_ip, sport, d_ip, dport, flags, oldn, newn);
        fflush(stdout);
    }
}

static void write_dot(FILE *f)
{
    fprintf(f, "digraph tcp_lifecycle {\n");
    fprintf(f, "  rankdir=LR;\n");
    conn_t *c = conns;
    while (c)
    {
        char a[128], b[128];
        snprintf(a, sizeof(a), "%s:%u", c->a_ip, c->a_port);
        snprintf(b, sizeof(b), "%s:%u", c->b_ip, c->b_port);
        /* Build a label from events */
        fprintf(f, "  \"%s->%s\" [label=\"%s->%s\\nstate=%d\"];\n", a, b, a, b, c->state);
        for (int i = 0; i < c->ev_count; ++i)
        {
            event_t *e = &c->events[i];
            char stname[32];
            print_state_name(e->new_state, stname, sizeof(stname));
            fprintf(f, "  \"%s:%s\" -> \"%s:%s\" [label=\"%s\nflags=0x%02x\"];\n",
                    e->src, stname, e->dst, stname, stname, e->flags);
        }
        c = c->next;
    }
    fprintf(f, "}\n");
}

static void cleanup_and_exit(int sig)
{
    (void)sig;
    printf("\nShutting down, writing dot if requested...\n");
    if (dot_out)
    {
        FILE *f = fopen(dot_out, "w");
        if (f)
        {
            write_dot(f);
            fclose(f);
            printf("Wrote %s\n", dot_out);
        }
        else
        {
            perror("fopen");
        }
    }
    if (handle)
        pcap_breakloop(handle);
    exit(0);
}

int main(int argc, char **argv)
{
    char *dev = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];
    int opt_i = 0;

#if defined(_WIN32) || defined(_WIN64)
    /* Initialize Winsock for Windows builds (needed for InetNtop/other APIs) */
    {
        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
        {
            fprintf(stderr, "WSAStartup failed\n");
            return 1;
        }
    }
#endif

    if (argc < 2)
    {
        fprintf(stderr, "Usage: %s -i <interface> [-o out.dot]\n", argv[0]);
        return 1;
    }

    for (int i = 1; i < argc; ++i)
    {
        if (strcmp(argv[i], "-i") == 0 && i + 1 < argc)
        {
            dev = argv[++i];
            opt_i = 1;
        }
        else if (strcmp(argv[i], "-o") == 0 && i + 1 < argc)
        {
            dot_out = argv[++i];
        }
        else
        {
            fprintf(stderr, "Unknown arg: %s\n", argv[i]);
        }
    }

    if (!opt_i)
    {
        fprintf(stderr, "Interface required (-i)\n");
        return 1;
    }

    signal(SIGINT, cleanup_and_exit);
    signal(SIGTERM, cleanup_and_exit);

    handle = pcap_open_live(dev, 65536, 1, 1000, errbuf);
    if (!handle)
    {
        fprintf(stderr, "pcap_open_live failed: %s\n", errbuf);
        return 1;
    }

    char filter_exp[] = "tcp";
    struct bpf_program fp;
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1)
    {
        fprintf(stderr, "pcap_compile failed\n");
        return 1;
    }
    if (pcap_setfilter(handle, &fp) == -1)
    {
        fprintf(stderr, "pcap_setfilter failed\n");
        return 1;
    }

    printf("Listening on %s for TCP packets...\n", dev);
    pcap_loop(handle, -1, handle_packet, NULL);

    pcap_close(handle);

#if defined(_WIN32) || defined(_WIN64)
    WSACleanup();
#endif
    return 0;
}
