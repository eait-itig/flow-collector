/* */

/*
 * Copyright (c) 2020 The University of Queensland
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/ioctl.h>
#include <sys/resource.h>

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <err.h>
#include <errno.h>
#include <pwd.h>
#include <paths.h>
#include <signal.h>
#include <limits.h>

#include <net/if.h>
#include <net/if_arp.h>
#include <net/bpf.h>
#include <netdb.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <sys/time.h>

#include <sys/queue.h>
#include <sys/tree.h>

#include <pcap.h>
#include <event.h>

#include "log.h"
#include "task.h"

#ifndef nitems
#define nitems(_a)	(sizeof((_a)) / sizeof((_a)[0]))
#endif

#ifndef ISSET
#define ISSET(_v, _m)	((_v) & (_m))
#endif

static const unsigned int pkt_lens[] = {
	64,
	128,
	256,
	512,
	1024,
	1514,	/* XXX 1500 would make more sense for IP */
	2048,
	4096,
	8192,
	65535,	/* > 8192 */
};

#define NUM_PKT_LENS	nitems(pkt_lens)

struct gre_header {
	uint16_t		gre_flags;
#define GRE_CP				0x8000	/* Checksum Present */
#define GRE_KP				0x2000	/* Key Present */
#define GRE_SP				0x1000	/* Sequence Present */

#define GRE_VERS_MASK			0x0007
#define GRE_VERS_0			0x0000
#define GRE_VERS_1			0x0001

	uint16_t		gre_proto;
} __packed __aligned(4);

struct gre_h_cksum {
	uint16_t		gre_cksum;
	uint16_t		gre_reserved1;
} __packed __aligned(4);

struct gre_h_key {
	uint32_t		gre_key;
} __packed __aligned(4);

struct esp_header {
	uint32_t		esp_spi;
	uint32_t		esp_seq;
} __packed __aligned(4);

struct ah_header {
	uint8_t			ah_proto;
	uint8_t			ah_len;
	uint16_t		ah_reserved;
	uint32_t		ah_spi;
	uint32_t		ah_seq;
} __packed __aligned(4);

struct sctp_header {
	uint16_t		sctp_sport;
	uint16_t		sctp_dport;
	uint32_t		sctp_vtag;
	uint32_t		sctp_cksum;
} __packed __aligned(4);

int		rdaemon(int);

union flow_addr {
	struct in_addr		addr4;
	struct in6_addr		addr6;
};

struct flow_key {
	uint16_t		k_sport;
	uint16_t		k_dport;

	int			k_vlan;
#define FLOW_VLAN_UNSET			-1
	uint8_t			k_ipv;
	uint8_t			k_ipproto;
	uint8_t			k_dir;

	union flow_addr		k_saddr;
#define k_saddr4			k_saddr.addr4
#define k_saddr6			k_saddr.addr6
	union flow_addr		k_daddr;
#define k_daddr4			k_daddr.addr4
#define k_daddr6			k_daddr.addr6

#define k_icmp_type			k_sport
#define k_icmp_code			k_dport

#define k_gre_flags			k_sport
#define k_gre_proto			k_dport

	uint32_t		k_gre_key;
#define k_ipsec_spi			k_gre_key

	uint32_t		k_ospi;

	union flow_addr		k_osaddr;
#define k_osaddr4			k_osaddr.addr4
#define k_osaddr6			k_osaddr.addr6
	union flow_addr		k_odaddr;
#define k_odaddr4			k_odaddr.addr4
#define k_odaddr6			k_odaddr.addr6
} __aligned(8);

struct flow {
	struct flow_key		f_key;

	uint64_t		f_packets;
	uint64_t		f_bytes;
	uint64_t		f_frags;

	uint64_t		f_syns;
	uint64_t		f_fins;
	uint64_t		f_rsts;
	uint64_t		f_rstacks;

	uint64_t		f_pkt_lens[NUM_PKT_LENS];

	uint16_t		f_min_tcpwin;
	uint16_t		f_max_tcpwin;

	unsigned int		f_min_pktlen;
	unsigned int		f_max_pktlen;
	uint8_t			f_min_ttl;
	uint8_t			f_max_ttl;

	RBT_ENTRY(flow)		f_entry_tree;
	TAILQ_ENTRY(flow)	f_entry_list;
};

RBT_HEAD(flow_tree, flow);
TAILQ_HEAD(flow_list, flow);

static inline int
flow_cmp(const struct flow *a, const struct flow *b)
{
	const struct flow_key *ka = &a->f_key;
	const struct flow_key *kb = &b->f_key;
	const unsigned long *la = (const unsigned long *)ka;
	const unsigned long *lb = (const unsigned long *)kb;
	size_t i;

	for (i = 0; i < sizeof(*ka) / sizeof(*la); i++) {
		if (la[i] > lb[i])
			return (1);
		if (la[i] < lb[i])
			return (-1);
	}

	return (0);
}

RBT_PROTOTYPE(flow_tree, flow, f_entry_tree, flow_cmp);

struct timeslice {
	const char		*ts_hostname;
	unsigned int		ts_flow_count;
	struct flow_tree	ts_flow_tree;
	struct flow_list	ts_flow_list;

	struct timeval		ts_begin;
	struct timeval		ts_end;
	struct timeval		ts_utime;
	struct timeval		ts_stime;
	uint64_t		ts_reads;
	uint64_t		ts_packets;
	uint64_t		ts_bytes;

	uint64_t		ts_mdrop;

	uint64_t		ts_short_ether;
	uint64_t		ts_short_vlan;
	uint64_t		ts_short_ip4;
	uint64_t		ts_short_ip6;
	uint64_t		ts_short_ipproto;
	uint64_t		ts_nonip;

	unsigned int		ts_pcap_recv;
	unsigned int		ts_pcap_drop;
	unsigned int		ts_pcap_ifdrop;

	struct task		ts_task;
};

struct timeslice	*timeslice_alloc(const struct timeval *);
static struct flow	*flow_alloc(void);

struct flow_daemon;
struct flow_pkt;

struct pkt_source {
	const char		*ps_name;
	struct flow_daemon	*ps_d;
	pcap_t			*ps_ph;
	struct pcap_stat	 ps_pstat;
	struct event		 ps_ev;

	TAILQ_ENTRY(pkt_source)	 ps_entry;

	int (*ps_dlt_input)(struct timeslice *, struct flow *,
	    struct flow_pkt *);
};

TAILQ_HEAD(pkt_sources, pkt_source);

struct flow_daemon {
	const char		*d_hostname;
	struct taskq		*d_taskq;
	struct event		 d_tick;
	struct timeval		 d_tv;

	struct pkt_sources	 d_pkt_sources;
	struct flow		*d_flow;

	struct timeslice	*d_ts;

	struct rusage		 d_rusage[2];
	unsigned int		 d_rusage_gen;
};

static int	bpf_maxbufsize(void);
static void	flow_tick(int, short, void *);
void		pkt_capture(int, short, void *);
static struct addrinfo *
		clickhouse_resolve(void);

static int	flow_pcap_filter(pcap_t *);

static int	pkt_dlt_ether(struct timeslice *, struct flow *,
		    struct flow_pkt *);

__dead static void
usage(void)
{
	extern char *__progname;

	fprintf(stderr, "usage: %s [-46d] [-u user] [-h clickhouse_host] "
	    "[-p clickhouse_port] [-D clickhouse_db] [-U clickhouse_user] "
	    "[-k clickhouse_key] if0 ...\n", __progname);

	exit(1);
}

static int clickhouse_af = PF_UNSPEC;
static const char *clickhouse_host = "localhost";
static const char *clickhouse_port = "8123";
static const char *clickhouse_user = "default";
static const char *clickhouse_database = NULL;
static const char *clickhouse_key = NULL;
static struct addrinfo *clickhouse_res;

static int debug = 0;
static int pagesize;

int
main(int argc, char *argv[])
{
	char hostname[HOST_NAME_MAX + 1];
	const char *user = "_flow";
	char errbuf[PCAP_ERRBUF_SIZE];
	const char *errstr;
	struct flow_daemon _d = {
		.d_tv = { 2, 500000 },
		.d_pkt_sources = TAILQ_HEAD_INITIALIZER(_d.d_pkt_sources),
		.d_hostname = hostname,
	};
	struct flow_daemon *d = &_d;
	struct pkt_source *ps;

	struct timeval now;
	struct passwd *pw;
	int ch;
	int devnull = -1;
	int maxbufsize;

	maxbufsize = bpf_maxbufsize();
	if (maxbufsize == -1)
		err(1, "sysctl net.bpf.maxbufsize");

	pagesize = sysconf(_SC_PAGESIZE);
	if (pagesize == -1)
		err(1, "page size");
	if (pagesize < 1024) /* in case we're run on a crappy vax OS */
		pagesize = 1024;

	if (gethostname(hostname, sizeof(hostname)) == -1)
		err(1, "gethostname");

	while ((ch = getopt(argc, argv, "46dD:u:w:h:p:U:k:n:")) != -1) {
		switch (ch) {
		case '4':
			clickhouse_af = PF_INET;
			break;
		case '6':
			clickhouse_af = PF_INET6;
			break;
		case 'd':
			debug = 1;
			break;
		case 'D':
			clickhouse_database = optarg;
			break;
		case 'u':
			user = optarg;
			break;
		case 'w':
			d->d_tv.tv_sec = strtonum(optarg, 1, 900, &errstr);
			if (errstr != NULL)
				errx(1, "%s: %s", optarg, errstr);
			break;
		case 'h':
			clickhouse_host = optarg;
			break;
		case 'p':
			clickhouse_port = optarg;
			break;
		case 'U':
			clickhouse_user = optarg;
			break;
		case 'k':
			clickhouse_key = optarg;
			break;
		case 'n':
			d->d_hostname = optarg;
			break;
		default:
			usage();
		}
	}

	argc -= optind;
	argv += optind;

	if (argc == 0)
		usage();

	clickhouse_res = clickhouse_resolve();

	signal(SIGPIPE, SIG_IGN);

	if (geteuid())
		lerrx(1, "need root privileges");

	pw = getpwnam(user);
	if (pw == NULL)
		errx(1, "%s: unknown user", user);

	if (!debug) {
		extern char *__progname;

		devnull = open(_PATH_DEVNULL, O_RDWR, 0);
		if (devnull == -1)
			err(1, "open %s", _PATH_DEVNULL);

		logger_syslog(__progname);
	}

	for (ch = 0; ch < argc; ch++) {
		int bpfd;
		u_int dlt;
		const char *dltname;

		ps = malloc(sizeof(*ps));
		if (ps == NULL)
			err(1, NULL);

		ps->ps_ph = pcap_create(argv[ch], errbuf);
		if (ps->ps_ph == NULL)
			errx(1, "%s", errbuf);

		/* XXX TOCTOU */
		if (pcap_set_buffer_size(ps->ps_ph, maxbufsize) != 0)
			errx(1, "%s: %s", argv[ch], pcap_geterr(ps->ps_ph));

		if (pcap_set_promisc(ps->ps_ph, 1) != 0)
			errx(1, "%s", errbuf);

		if (pcap_set_snaplen(ps->ps_ph, 256) != 0)
			errx(1, "%s", errbuf);

		if (pcap_set_timeout(ps->ps_ph, 10) != 0)
			errx(1, "%s", errbuf);

		if (pcap_activate(ps->ps_ph) != 0)
			errx(1, "%s", errbuf);

		if (pcap_setnonblock(ps->ps_ph, 1, errbuf) != 0)
			errx(1, "%s", errbuf);

		if (flow_pcap_filter(ps->ps_ph) != 0)
			errx(1, "%s: %s", argv[ch], pcap_geterr(ps->ps_ph));

		ps->ps_d = d;
		ps->ps_name = argv[ch];

		bpfd = pcap_fileno(ps->ps_ph);
		if (ioctl(bpfd, BIOCGDLT, &dlt) == -1)
			err(1, "%s BIOCGDLT", argv[ch]);

		switch (dlt) {
		case DLT_EN10MB:
			ps->ps_dlt_input = pkt_dlt_ether;
			break;
		default:
			dltname = pcap_datalink_val_to_name(dlt);
			if (dltname == NULL)
				errx(1, "%s unknown dlt %u", argv[ch], dlt);

			errx(1, "%s unknown dlt %s", argv[ch], dltname);
			/* NOTREACHED */
		}

		/* fetch a baseline */
		memset(&ps->ps_pstat, 0, sizeof(ps->ps_pstat));
		if (pcap_stats(ps->ps_ph, &ps->ps_pstat) != 0)
			errx(1, "%s %s", ps->ps_name, pcap_geterr(ps->ps_ph));

		TAILQ_INSERT_TAIL(&d->d_pkt_sources, ps, ps_entry);
	}

	if (chroot(pw->pw_dir) == -1)
		err(1, "chroot %s", pw->pw_dir);
	if (chdir("/") == -1)
		err(1, "chdir %s", pw->pw_dir);

	if (setgroups(1, &pw->pw_gid) ||
	    setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) ||
	    setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid))
		errx(1, "unable to drop privileges");

	endpwent();

	d->d_taskq = taskq_create("store");
	if (d->d_taskq == NULL)
		err(1, "taskq");

	d->d_flow = flow_alloc();
	if (d->d_flow == NULL)
		err(1, NULL);

	gettimeofday(&now, NULL);

	d->d_ts = timeslice_alloc(&now);
	if (d->d_ts == NULL)
		err(1, NULL);

	if (!debug && rdaemon(devnull) == -1)
		err(1, "unable to daemonize");

	event_init();

	evtimer_set(&d->d_tick, flow_tick, d);
	evtimer_add(&d->d_tick, &d->d_tv);

	TAILQ_FOREACH(ps, &d->d_pkt_sources, ps_entry) {
		event_set(&ps->ps_ev, pcap_get_selectable_fd(ps->ps_ph),
		    EV_READ | EV_PERSIST, pkt_capture, ps);
		event_add(&ps->ps_ev, NULL);
	}

	event_dispatch();

	return (0);
}

static int
bpf_maxbufsize(void)
{
	int mib[] = { CTL_NET, PF_BPF, NET_BPF_MAXBUFSIZE };
	int maxbuf;
	size_t maxbufsize = sizeof(maxbuf);

	if (sysctl(mib, nitems(mib), &maxbuf, &maxbufsize, NULL, 0) == -1)
		return (-1);

	return (maxbuf);
}

static int
flow_pcap_filter(pcap_t *p)
{
	struct bpf_insn bpf_filter[] = {
		BPF_STMT(BPF_RET+BPF_K, pcap_snapshot(p)),
	};
	struct bpf_program bp = {
		.bf_insns = bpf_filter,
		.bf_len = nitems(bpf_filter),
	};

	return (pcap_setfilter(p, &bp));
}

static inline int
flow_gre_key_valid(const struct flow *f)
{
	uint16_t v = f->f_key.k_gre_flags;
	/* ignore checksum and seq no */
	v &= ~htons(GRE_CP|GRE_SP);
	return (v == htons(GRE_VERS_0|GRE_KP));
}

static struct addrinfo *
clickhouse_resolve(void)
{
	struct addrinfo hints, *res0;
	int error;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = clickhouse_af;
	hints.ai_socktype = SOCK_STREAM;
	error = getaddrinfo(clickhouse_host, clickhouse_port, &hints, &res0);
	if (error) {
		errx(1, "clickhouse host %s port %s resolve: %s",
		    clickhouse_host, clickhouse_port, gai_strerror(error));
	}

	return (res0);
}

static int
clickhouse_connect(void)
{
	struct addrinfo *res0 = clickhouse_res, *res;
	int serrno;
	int s;
	const char *cause = NULL;

	s = -1;
	for (res = res0; res; res = res->ai_next) {
		s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
		if (s == -1) {
			cause = "socket";
			serrno = errno;
			continue;
		}

		if (connect(s, res->ai_addr, res->ai_addrlen) == -1) {
			cause = "connect";
			serrno = errno;
			close(s);
			s = -1;
			continue;
		}

		break;  /* okay we got one */
	}

	if (s == -1) {
		errno = serrno;
		lwarnx("clickhouse host %s port %s %s",
		    clickhouse_host, clickhouse_port, cause);
		return (-1);
	}

	return (s);
}

struct buf {
	char	*mem;
	size_t	 len;
	size_t	 off;
};

static inline void
buf_init(struct buf *b)
{
	b->off = 0;
}

static void
buf_resize(struct buf *b)
{
	b->len += pagesize;
	b->mem = realloc(b->mem, b->len);
	if (b->mem == NULL)
		lerr(1, "buffer resize");
}

static void
buf_reserve(struct buf *b)
{
	if ((b->off + pagesize) > b->len)
		buf_resize(b);
}

static void
buf_cat(struct buf *b, const char *str)
{
	size_t off, rv;

	buf_reserve(b);

	for (;;) {
		rv = strlcpy(b->mem + b->off, str, b->len - b->off);
		off = b->off + rv;
		if (off < b->len)
			break;

		buf_resize(b);
	}

	b->off = off;
}

static void
buf_printf(struct buf *b, const char *fmt, ...)
{
	va_list ap;
	size_t off;
	int rv;

	buf_reserve(b);

	for (;;) {
		va_start(ap, fmt);
		rv = vsnprintf(b->mem + b->off, b->len - b->off, fmt, ap);
		va_end(ap);

		if (rv == -1)
			lerr(1, "%s", __func__);

		off = b->off + rv;
		if (off < b->len)
			break;

		buf_resize(b);
	}

	b->off = off;
}

static void
do_clickhouse_sql(const struct buf *sqlbuf, size_t rows, const char *what)
{
	static struct buf reqbuf;
	int sock;
	struct iovec iov[2];
	FILE *ss;
	char head[256];

	buf_init(&reqbuf);

	sock = clickhouse_connect();
	if (sock == -1) {
		/* error was already logged */
		return;
	}

	buf_printf(&reqbuf, "POST / HTTP/1.0\r\n");
	buf_printf(&reqbuf, "Host: %s:%s\r\n",
	    clickhouse_host, clickhouse_port);
	if (clickhouse_database != NULL) {
		buf_printf(&reqbuf, "X-ClickHouse-Database: %s\r\n",
		    clickhouse_database);
	}
	buf_printf(&reqbuf, "X-ClickHouse-User: %s\r\n", clickhouse_user);
	if (clickhouse_key != NULL)
		buf_printf(&reqbuf, "X-ClickHouse-Key: %s\r\n", clickhouse_key);
	buf_printf(&reqbuf, "Content-Length: %zu\r\n", sqlbuf->off);
	buf_printf(&reqbuf, "Content-Type: text/sql\r\n");
	buf_printf(&reqbuf, "\r\n");

	iov[0].iov_base = reqbuf.mem;
	iov[0].iov_len = reqbuf.off;
	iov[1].iov_base = sqlbuf->mem;
	iov[1].iov_len = sqlbuf->off;

	writev(sock, iov, nitems(iov)); /* XXX */

	ss = fdopen(sock, "r");
	if (ss == NULL)
		lerr(1, "fdopen");

	fgets(head, sizeof (head), ss);
	head[strlen(head) - 1] = '\0';
	head[strlen(head) - 1] = '\0';
	if (strcmp(head, "HTTP/1.0 200 OK") != 0)
		lwarnx("clickhouse: error: returned %s", head);

	if (debug) {
		linfo("clickhouse: POST of %zu %s rows (%zu bytes): %s",
		    rows, what, sqlbuf->off, head);
	}

	fclose(ss);
}

static uint32_t
tv_to_msec(const struct timeval *tv)
{
	uint32_t msecs;

	msecs = tv->tv_sec * 1000;
	msecs += tv->tv_usec / 1000;

	return (msecs);
}

static void
timeslice_post_flows(struct timeslice *ts, struct buf *sqlbuf,
    const char *st, const char *et)
{
	char ipbuf[NI_MAXHOST];
	struct flow *f, *nf;
	const struct flow_key *k;
	size_t rows = 0;
	const char *join = "";

	if (TAILQ_EMPTY(&ts->ts_flow_list))
		return;

	buf_init(sqlbuf);
	buf_cat(sqlbuf, "INSERT INTO flows ("
	    "host, begin_at, end_at, "
	    "dir_in, dir_out, "
	    "osaddr, odaddr, spi, "
	    "vlan, ipv, ipproto, saddr, daddr, sport, dport, gre_key, "
	    "packets, bytes, frags, "
	    "syns, fins, rsts, rstacks, mintcpwin, maxtcpwin, "
	    "minpktlen, maxpktlen, min_ttl, max_ttl, pkt_lens"
	    ")\n" "FORMAT Values\n");

	TAILQ_FOREACH_SAFE(f, &ts->ts_flow_list, f_entry_list, nf) {
		const char *mjoin = "";
		unsigned int i;

		k = &f->f_key;
		buf_printf(sqlbuf, "%s('%s',%s,%s,", join,
		    ts->ts_hostname, st, et);
		buf_printf(sqlbuf, "%s,%s,",
		    ISSET(k->k_dir, BPF_F_DIR_IN) ? "true" : "false",
		    ISSET(k->k_dir, BPF_F_DIR_OUT) ? "true" : "false");
		inet_ntop(PF_INET6, &k->k_osaddr6, ipbuf, sizeof(ipbuf));
		buf_printf(sqlbuf, "toIPv6('%s'),", ipbuf);
		inet_ntop(PF_INET6, &k->k_odaddr6, ipbuf, sizeof(ipbuf));
		buf_printf(sqlbuf, "toIPv6('%s'),", ipbuf);
		buf_printf(sqlbuf, "%u,", k->k_ospi);
		buf_printf(sqlbuf, "%u,%u,%u,", k->k_vlan, k->k_ipv,
		    k->k_ipproto);
		if (k->k_ipv == 4) {
			inet_ntop(PF_INET, &k->k_saddr4, ipbuf, sizeof(ipbuf));
			buf_printf(sqlbuf, "IPv4ToIPv6(toIPv4('%s')),", ipbuf);
			inet_ntop(PF_INET, &k->k_daddr4, ipbuf, sizeof(ipbuf));
			buf_printf(sqlbuf, "IPv4ToIPv6(toIPv4('%s')),", ipbuf);
		} else if (k->k_ipv == 6) {
			inet_ntop(PF_INET6, &k->k_saddr6, ipbuf, sizeof(ipbuf));
			buf_printf(sqlbuf, "toIPv6('%s'),", ipbuf);
			inet_ntop(PF_INET6, &k->k_daddr6, ipbuf, sizeof(ipbuf));
			buf_printf(sqlbuf, "toIPv6('%s'),", ipbuf);
		} else {
			buf_printf(sqlbuf, "toIPv6('::'),toIPv6('::'),");
		}
		buf_printf(sqlbuf,
		    "%u,%u,%u,%llu,%llu,%llu,%llu,%llu,%llu,%llu,"
		    "%u,%u,%u,%u,%u,%u,{",
		    ntohs(k->k_sport), ntohs(k->k_dport), ntohl(k->k_gre_key),
		    f->f_packets, f->f_bytes, f->f_frags,
		    f->f_syns, f->f_fins, f->f_rsts, f->f_rstacks,
		    f->f_min_tcpwin, f->f_max_tcpwin,
		    f->f_min_pktlen, f->f_max_pktlen,
		    f->f_min_ttl, f->f_max_ttl);
		for (i = 0; i < nitems(f->f_pkt_lens); i++) {
			uint64_t pkts = f->f_pkt_lens[i];
			if (pkts == 0)
				continue;

			buf_printf(sqlbuf, "%s%u:%llu", mjoin,
			    pkt_lens[i], pkts);

			mjoin = ",";
		}
		buf_printf(sqlbuf, "})");

		free(f);
		join = ",\n";

		++rows;
	}
	buf_printf(sqlbuf, ";\n");

	do_clickhouse_sql(sqlbuf, rows, "flow");
}

static void
timeslice_post_flowstats(struct timeslice *ts, struct buf *sqlbuf,
    const char *st, const char *et)
{
	buf_init(sqlbuf);
	buf_cat(sqlbuf, "INSERT INTO flowstats ("
	    "host, begin_at, end_at, user_ms, kern_ms, "
	    "reads, packets, bytes, flows, "
	    "pcap_recv, pcap_drop, pcap_ifdrop, mdrop"
	    ")\n" "FORMAT Values\n");
	buf_printf(sqlbuf, "('%s',%s,%s,", ts->ts_hostname, st, et);
	buf_printf(sqlbuf, "%u,%u,",
	    tv_to_msec(&ts->ts_utime), tv_to_msec(&ts->ts_stime));
	buf_printf(sqlbuf, "%llu,%llu,%llu,%lu,", ts->ts_reads,
	    ts->ts_packets, ts->ts_bytes, ts->ts_flow_count);
	buf_printf(sqlbuf, "%u,%u,%u,%llu", ts->ts_pcap_recv, ts->ts_pcap_drop,
	    ts->ts_pcap_ifdrop, ts->ts_mdrop);
	buf_cat(sqlbuf, ");\n");

	do_clickhouse_sql(sqlbuf, 1, "flowstats");
}

static void
timeslice_post(void *arg)
{
	static struct buf sqlbuf;
	struct timeslice *ts = arg;

	char stbuf[128], etbuf[128];
	snprintf(stbuf, sizeof(stbuf), "%lld.%06lld",
	    (long long)ts->ts_begin.tv_sec, (long long)ts->ts_begin.tv_usec);
	snprintf(etbuf, sizeof(etbuf), "%lld.%06lld",
	    (long long)ts->ts_end.tv_sec, (long long)ts->ts_end.tv_usec);

	timeslice_post_flows(ts, &sqlbuf, stbuf, etbuf);
	timeslice_post_flowstats(ts, &sqlbuf, stbuf, etbuf);

	free(ts);
}

struct timeslice *
timeslice_alloc(const struct timeval *now)
{
	struct timeslice *ts;

	ts = calloc(1, sizeof(*ts));
	if (ts == NULL)
		return (NULL);

	ts->ts_begin = *now;
	ts->ts_flow_count = 0;
	RBT_INIT(flow_tree, &ts->ts_flow_tree);
	TAILQ_INIT(&ts->ts_flow_list);

	task_set(&ts->ts_task, timeslice_post, ts);

	return (ts);
}

static struct flow *
flow_alloc(void)
{
	struct flow *f;
	size_t i;

	f = malloc(sizeof(*f));
	if (f == NULL)
		return (NULL);

	for (i = 0; i < nitems(f->f_pkt_lens); i++)
		f->f_pkt_lens[i] = 0;

	return (f);
}

static void
flow_tick(int nope, short events, void *arg)
{
	struct flow_daemon *d = arg;
	struct pkt_source *ps;
	struct timeslice *ts = d->d_ts;
	struct timeslice *nts;
	struct timeval now;
	unsigned int gen;
	struct rusage *oru, *nru;

	gettimeofday(&now, NULL);

	evtimer_add(&d->d_tick, &d->d_tv);

	nts = timeslice_alloc(&now);
	if (nts == NULL) {
		/* just make this ts wider if we can't get a new one */
		return;
	}

	TAILQ_FOREACH(ps, &d->d_pkt_sources, ps_entry) {
		struct pcap_stat pstat;

		pkt_capture(pcap_get_selectable_fd(ps->ps_ph), 0, ps);

		memset(&pstat, 0, sizeof(pstat)); /* for ifdrop */

		if (pcap_stats(ps->ps_ph, &pstat) != 0)
			lerrx(1, "%s %s", ps->ps_name, pcap_geterr(ps->ps_ph));

		ts->ts_pcap_recv += pstat.ps_recv - ps->ps_pstat.ps_recv;
		ts->ts_pcap_drop += pstat.ps_drop - ps->ps_pstat.ps_drop;
		ts->ts_pcap_ifdrop += pstat.ps_ifdrop - ps->ps_pstat.ps_ifdrop;

		ps->ps_pstat = pstat;
	}

	gen = d->d_rusage_gen;
	oru = &d->d_rusage[gen % nitems(d->d_rusage)];
	gen++;
	nru = &d->d_rusage[gen % nitems(d->d_rusage)];
	d->d_rusage_gen = gen;

	if (getrusage(RUSAGE_THREAD, nru) == -1)
		lerr(1, "getrusage");

	timersub(&nru->ru_utime, &oru->ru_utime, &ts->ts_utime);
	timersub(&nru->ru_stime, &oru->ru_stime, &ts->ts_stime);

	ts->ts_end = now;
	ts->ts_hostname = d->d_hostname;
	task_add(d->d_taskq, &ts->ts_task);

	d->d_ts = nts;
}

static int
pkt_count_tcp(struct timeslice *ts, struct flow *f,
    const u_char *buf, u_int buflen)
{
	const struct tcphdr *th;

	if (buflen < sizeof(*th)) {
		ts->ts_short_ipproto++;
		return (-1);
	}

	th = (const struct tcphdr *)buf;

	f->f_key.k_sport = th->th_sport;
	f->f_key.k_dport = th->th_dport;
	if ((th->th_flags & (TH_SYN | TH_ACK)) == TH_SYN)
		f->f_syns = 1;
	if (th->th_flags & TH_FIN)
		f->f_fins = 1;
	if (th->th_flags & TH_RST) {
		if (th->th_flags & TH_ACK)
			f->f_rstacks = 1;
		else
			f->f_rsts = 1;
	}
	f->f_min_tcpwin = f->f_max_tcpwin = ntohs(th->th_win);

	return (0);
}

static int
pkt_count_udp(struct timeslice *ts, struct flow *f,
    const u_char *buf, u_int buflen)
{
	const struct udphdr *uh;

	if (buflen < sizeof(*uh)) {
		ts->ts_short_ipproto++;
		return (-1);
	}

	uh = (const struct udphdr *)buf;

	f->f_key.k_sport = uh->uh_sport;
	f->f_key.k_dport = uh->uh_dport;

	return (0);
}

static int
pkt_count_gre(struct timeslice *ts, struct flow *f,
    const u_char *buf, u_int buflen)
{
	const struct gre_header *gh;
	const struct gre_h_key *gkh;
	u_int hlen;

	if (buflen < sizeof(*gh)) {
		ts->ts_short_ipproto++;
		return (-1);
	}

	gh = (const struct gre_header *)buf;

	f->f_key.k_gre_flags = gh->gre_flags;
	f->f_key.k_gre_proto = gh->gre_proto;

	if (!flow_gre_key_valid(f))
		return (0);

	hlen = sizeof(*gh);
	if (ISSET(f->f_key.k_gre_flags, htons(GRE_CP)))
		hlen += sizeof(struct gre_h_cksum);
	gkh = (const struct gre_h_key *)buf;
	hlen += sizeof(*gkh);
	if (buflen < hlen) {
		return ts->ts_short_ipproto++;
		return (-1);
	}

	f->f_key.k_gre_key = gkh->gre_key;

	return (0);
}

static int
pkt_count_esp(struct timeslice *ts, struct flow *f,
    const u_char *buf, u_int buflen)
{
	const struct esp_header *eh;

	if (buflen < sizeof(*eh)) {
		ts->ts_short_ipproto++;
		return (-1);
	}

	eh = (const struct esp_header *)buf;

	f->f_key.k_ipsec_spi = eh->esp_spi;

	return (0);
}

static int
pkt_count_ah(struct timeslice *ts, struct flow *f,
    const u_char *buf, u_int buflen)
{
	const struct ah_header *ah;

	if (buflen < sizeof(*ah)) {
		ts->ts_short_ipproto++;
		return (-1);
	}

	ah = (const struct ah_header *)buf;

	f->f_key.k_ipsec_spi = ah->ah_spi;

	return (0);
}

static int
pkt_count_sctp(struct timeslice *ts, struct flow *f,
    const u_char *buf, u_int buflen)
{
	const struct sctp_header *sh;

	if (buflen < sizeof(*sh)) {
		ts->ts_short_ipproto++;
		return (-1);
	}

	sh = (const struct sctp_header *)buf;

	f->f_key.k_sport = sh->sctp_sport;
	f->f_key.k_dport = sh->sctp_dport;
	f->f_key.k_gre_key = sh->sctp_vtag;

	return (0);
}

static int
pkt_count_ipproto(struct timeslice *ts, struct flow *f,
    const u_char *buf, u_int buflen)
{
	switch (f->f_key.k_ipproto) {
	case IPPROTO_TCP:
		return (pkt_count_tcp(ts, f, buf, buflen));
	case IPPROTO_UDP:
	case IPPROTO_UDPLITE:
		return (pkt_count_udp(ts, f, buf, buflen));
	case IPPROTO_GRE:
		return (pkt_count_gre(ts, f, buf, buflen));
	case IPPROTO_ESP:
		return (pkt_count_esp(ts, f, buf, buflen));
	case IPPROTO_AH:
		return (pkt_count_ah(ts, f, buf, buflen));
	case IPPROTO_SCTP:
		return (pkt_count_sctp(ts, f, buf, buflen));
	}

	return (0);
}

static int
pkt_count_icmp4(struct timeslice *ts, struct flow *f,
    const u_char *buf, u_int buflen)
{
	const struct icmp *icmp4h;

	if (buflen < offsetof(struct icmp, icmp_cksum)) {
		ts->ts_short_ipproto++;
		return (-1);
	}

	icmp4h = (const struct icmp *)buf;

	f->f_key.k_icmp_type = htons(icmp4h->icmp_type);
	f->f_key.k_icmp_code = htons(icmp4h->icmp_code);
	switch (icmp4h->icmp_type) {
	case ICMP_ECHO:
	case ICMP_ECHOREPLY:
		if (buflen < offsetof(struct icmp, icmp_seq)) {
			ts->ts_short_ipproto++;
			return (-1);
		}
		f->f_key.k_gre_key = htonl(ntohs(icmp4h->icmp_id));
		break;
	}

	return (0);
}

static int
pkt_count_ip4(struct timeslice *ts, struct flow *f,
    const u_char *buf, u_int buflen)
{
	const struct ip *iph;
	u_int hlen;
	uint8_t proto;

	if (buflen < sizeof(*iph)) {
		ts->ts_short_ip4++;
		return (-1);
	}

	iph = (const struct ip *)buf;

	/* XXX check ipv and all that poop? */

	hlen = iph->ip_hl << 2;
	if (buflen < hlen) {
		ts->ts_short_ip4++;
		return (-1);
	}

	buf += hlen;
	buflen -= hlen;

	proto = iph->ip_p;

	if (iph->ip_off & htons(~(IP_DF | IP_RF))) {
		if ((iph->ip_off & htons(IP_OFFMASK)) != htons(0))
			proto = IPPROTO_FRAGMENT;

		f->f_frags = 1;
	}

	f->f_key.k_ipv = 4;
	f->f_key.k_ipproto = proto;
	f->f_key.k_saddr4 = iph->ip_src;
	f->f_key.k_daddr4 = iph->ip_dst;
	f->f_min_ttl = f->f_max_ttl = iph->ip_ttl;

	if (f->f_key.k_ipproto == IPPROTO_ICMP)
 		return (pkt_count_icmp4(ts, f, buf, buflen));

	return (pkt_count_ipproto(ts, f, buf, buflen));
}

static int
pkt_count_icmp6(struct timeslice *ts, struct flow *f,
    const u_char *buf, u_int buflen)
{
	const struct icmp6_hdr *icmp6h;

	if (buflen < offsetof(struct icmp6_hdr, icmp6_cksum)) {
		ts->ts_short_ipproto++;
		return (-1);
	}

	icmp6h = (const struct icmp6_hdr *)buf;

	f->f_key.k_icmp_type = htons(icmp6h->icmp6_type);
	f->f_key.k_icmp_code = htons(icmp6h->icmp6_code);

	switch (icmp6h->icmp6_type) {
	case ICMP6_ECHO_REQUEST:
	case ICMP6_ECHO_REPLY:
		if (buflen < offsetof(struct icmp6_hdr, icmp6_seq)) {
			ts->ts_short_ipproto++;
			return (-1);
		}
		f->f_key.k_gre_key = htonl(ntohs(icmp6h->icmp6_id));
		break;
	}

	return (0);
}

static int
pkt_count_ip6(struct timeslice *ts, struct flow *f,
    const u_char *buf, u_int buflen)
{
	const struct ip6_hdr *ip6;
	uint8_t nxt;

	if (buflen < sizeof(*ip6)) {
		ts->ts_short_ip6++;
		return (-1);
	}

	ip6 = (const struct ip6_hdr *)buf;

	/* XXX check ipv and all that poop? */

	buf += sizeof(*ip6);
	buflen -= sizeof(*ip6);

	nxt = ip6->ip6_nxt;
	if (nxt == IPPROTO_FRAGMENT) {
		const struct ip6_frag *ip6f;

		if (buflen < sizeof(*ip6f)) {
			ts->ts_short_ip6++;
			return (-1);
		}

		ip6f = (const struct ip6_frag *)buf;
		if ((ip6f->ip6f_offlg & htons(IP6F_OFF_MASK)) == htons(0)) {
			/* we can parse the first fragment */
			buf += sizeof(*ip6f);
			buflen -= sizeof(*ip6f);
			nxt = ip6f->ip6f_nxt;
		}

		f->f_frags = 1;
	}

	f->f_key.k_ipv = 6;
	f->f_key.k_ipproto = nxt;
	f->f_key.k_saddr6 = ip6->ip6_src;
	f->f_key.k_daddr6 = ip6->ip6_dst;
	f->f_min_ttl = f->f_max_ttl = ip6->ip6_hlim;

	if (nxt == IPPROTO_ICMPV6)
		return (pkt_count_icmp6(ts, f, buf, buflen));

	return (pkt_count_ipproto(ts, f, buf, buflen));
}

static inline unsigned int
pkt_len_bucket(unsigned int pktlen)
{
	unsigned int i;

	/* the last bucket is special */
	for (i = 0; i < NUM_PKT_LENS - 1; i++) {
		if (pktlen <= pkt_lens[i])
			break;
	}

	return (i);
}

struct flow_pkt {
	const uint8_t	*buf;
	unsigned int	 buflen;
	unsigned int	 pktlen;
	uint16_t	 type; /* network endian ethertype */
};

static int
pkt_dlt_ether(struct timeslice *ts, struct flow *f, struct flow_pkt *fp)
{
	struct ether_header *eh;
	unsigned int hlen = sizeof(*eh);
	uint16_t type;

	if (fp->buflen < hlen) {
		ts->ts_short_ether++;
		return (-1);
	}

	eh = (struct ether_header *)fp->buf;
	type = eh->ether_type;

	if (type == htons(ETHERTYPE_VLAN)) {
		struct ether_vlan_header *evh;
		hlen = sizeof(*evh);

		if (fp->buflen < hlen) {
			ts->ts_short_vlan++;
			return (-1);
		}

		evh = (struct ether_vlan_header *)fp->buf;
		f->f_key.k_vlan = EVL_VLANOFTAG(htons(evh->evl_tag));
		type = evh->evl_proto;
	} else
		f->f_key.k_vlan = FLOW_VLAN_UNSET;

	fp->buf += hlen;
	fp->buflen -= hlen;
	fp->pktlen -= hlen;
	fp->type = type;

	return (0);
}

static void
pkt_count(u_char *arg, const struct pcap_pkthdr *hdr, const u_char *buf)
{
	const struct bpf_hdr *bh;
	struct pkt_source *ps = (struct pkt_source *)arg;
	struct flow_daemon *d = ps->ps_d;
	struct timeslice *ts = d->d_ts;
	struct flow *f = d->d_flow;
	struct flow *of;
	unsigned int len_bucket;

	struct flow_pkt fp = {
		.buf = buf,
		.buflen = hdr->caplen,
		.pktlen = hdr->len,
	};

	memset(&f->f_key, 0, sizeof(f->f_key));

	ts->ts_packets++;
	ts->ts_bytes += fp.pktlen;

	if (ps->ps_dlt_input(ts, f, &fp) != 0)
		return;

	/* fp should contain an IP packet now */

	f->f_packets = 1;
	f->f_bytes = fp.pktlen;
	f->f_frags = 0;
	f->f_syns = 0;
	f->f_fins = 0;
	f->f_rsts = 0;
	f->f_rstacks = 0;
	f->f_min_tcpwin = 0;
	f->f_max_tcpwin = 0;
	f->f_min_pktlen = f->f_max_pktlen = fp.pktlen;
	f->f_min_ttl = f->f_max_ttl = 0;

	switch (fp.type) {
	case htons(ETHERTYPE_IP):
		if (pkt_count_ip4(ts, f, fp.buf, fp.buflen) == -1)
			return;
		break;
	case htons(ETHERTYPE_IPV6):
		if (pkt_count_ip6(ts, f, fp.buf, fp.buflen) == -1)
			return;
		break;

	default:
		ts->ts_nonip++;
		return;
	}

	/*
	 * XXX this knows too much about how bpf and libpcap interact.
	 */
	bh = (const struct bpf_hdr *)hdr;
	f->f_key.k_dir = bh->bh_flags & BPF_F_DIR_MASK;

	of = RBT_INSERT(flow_tree, &ts->ts_flow_tree, f);
	if (of == NULL) {
		struct flow *nf = flow_alloc();
		if (nf == NULL) {
			/* drop this packet due to lack of memory */
			RBT_REMOVE(flow_tree, &ts->ts_flow_tree, f);
			ts->ts_mdrop++;
			return;
		}
		d->d_flow = nf;

		ts->ts_flow_count++;
		TAILQ_INSERT_TAIL(&ts->ts_flow_list, f, f_entry_list);

		of = f;
	} else {
		of->f_packets++;
		of->f_bytes += f->f_bytes;
		of->f_frags += f->f_frags;

		if (f->f_key.k_ipproto == IPPROTO_TCP) {
			of->f_syns += f->f_syns;
			of->f_fins += f->f_fins;
			of->f_rsts += f->f_rsts;
			of->f_rstacks += f->f_rstacks;

			if (of->f_min_tcpwin > f->f_min_tcpwin)
				of->f_min_tcpwin = f->f_min_tcpwin;
			if (of->f_max_tcpwin < f->f_max_tcpwin)
				of->f_max_tcpwin = f->f_max_tcpwin;
		}

		if (of->f_min_pktlen > f->f_min_pktlen)
			of->f_min_pktlen = f->f_min_pktlen;
		if (of->f_max_pktlen < f->f_max_pktlen)
			of->f_max_pktlen = f->f_max_pktlen;

		if (of->f_min_ttl > f->f_min_ttl)
			of->f_min_ttl = f->f_min_ttl;
		if (of->f_max_ttl < f->f_max_ttl)
			of->f_max_ttl = f->f_max_ttl;
	}

	len_bucket = pkt_len_bucket(fp.pktlen);
	of->f_pkt_lens[len_bucket]++;
}

void
pkt_capture(int fd, short events, void *arg)
{
	struct pkt_source *ps = arg;
	struct flow_daemon *d = ps->ps_d;
	struct timeslice *ts = d->d_ts;

	if (pcap_dispatch(ps->ps_ph, -1, pkt_count, (u_char *)ps) < 0)
		lerrx(1, "%s", pcap_geterr(ps->ps_ph));

	ts->ts_reads++;
}

RBT_GENERATE(flow_tree, flow, f_entry_tree, flow_cmp);

/* daemon(3) clone, intended to be used in a "r"estricted environment */
int
rdaemon(int devnull)
{
	if (devnull == -1) {
		errno = EBADF;
		return (-1);
	}
	if (fcntl(devnull, F_GETFL) == -1)
		return (-1);

	switch (fork()) {
	case -1:
		return (-1);
	case 0:
		break;
	default:
		_exit(0);
	}

	if (setsid() == -1)
		return (-1);

	(void)dup2(devnull, STDIN_FILENO);
	(void)dup2(devnull, STDOUT_FILENO);
	(void)dup2(devnull, STDERR_FILENO);
	if (devnull > 2)
		(void)close(devnull);

	return (0);
}
