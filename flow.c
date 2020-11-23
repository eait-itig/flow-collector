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

#include <net/if.h>
#include <net/if_arp.h>
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
#include "dns.h"

#ifndef nitems
#define nitems(_a)	(sizeof((_a)) / sizeof((_a)[0]))
#endif

#ifndef ISSET
#define ISSET(_v, _m)	((_v) & (_m))
#endif

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

int		rdaemon(int);

union flow_addr {
	struct in_addr		addr4;
	struct in6_addr		addr6;
};

struct flow_key {
	int			k_vlan;
#define FLOW_VLAN_UNSET			-1
	uint8_t			k_ipv;
	uint8_t			k_ipproto;
	union flow_addr		k_saddr;
#define k_saddr4			k_saddr.addr4
#define k_saddr6			k_saddr.addr6
	union flow_addr		k_daddr;
#define k_daddr4			k_daddr.addr4
#define k_daddr6			k_daddr.addr6
	union {
		struct {
			uint16_t	_k_sport;
			uint16_t	_k_dport;
		}		_k_ports;
		struct {
			uint8_t		_k_type;
			uint8_t		_k_code;
		}		_k_icmp;
		struct {
			uint16_t	_k_flags;
			uint16_t	_k_proto;
			uint32_t	_k_key;
		}		_k_gre;
	}			k_proto;
#define k_sport				k_proto._k_ports._k_sport
#define k_dport				k_proto._k_ports._k_dport

#define k_icmp_type			k_proto._k_icmp._k_type
#define k_icmp_code			k_proto._k_icmp._k_code

#define k_gre_flags			k_proto._k_gre._k_flags
#define k_gre_proto			k_proto._k_gre._k_proto
#define k_gre_key			k_proto._k_gre._k_key

	union {
		struct {
			uint8_t			_k_syn;
			uint8_t			_k_fin;
			uint8_t			_k_rst;
		} _k_tcpflags;
	} k_protoinf;
#define	k_syn				k_protoinf._k_tcpflags._k_syn
#define	k_fin				k_protoinf._k_tcpflags._k_fin
#define	k_rst				k_protoinf._k_tcpflags._k_rst
};

struct flow {
	struct flow_key		f_key;

	uint64_t		f_packets;
	uint64_t		f_bytes;

	uint64_t		f_syns;
	uint64_t		f_fins;
	uint64_t		f_rsts;

	RBT_ENTRY(flow)		f_entry_tree;
	TAILQ_ENTRY(flow)	f_entry_list;
};

RBT_HEAD(flow_tree, flow);
TAILQ_HEAD(flow_list, flow);

struct lookup {
	uint8_t			l_ipv;
	union flow_addr		l_saddr;
	union flow_addr		l_daddr;
	uint16_t		l_sport;
	uint16_t		l_dport;

	uint16_t		l_qid;
	char *			l_name;

	TAILQ_ENTRY(lookup)	l_entry;
};

struct rdns {
	char *			r_name;
	uint32_t		r_ttl;
	uint8_t			r_ipv;
	union flow_addr		r_addr;

	TAILQ_ENTRY(rdns)	r_entry;
};

TAILQ_HEAD(lookup_list, lookup);
TAILQ_HEAD(rdns_list, rdns);

static inline int
flow_cmp(const struct flow *a, const struct flow *b)
{
	return (memcmp(&a->f_key, &b->f_key, sizeof(a->f_key)));
}

RBT_PROTOTYPE(flow_tree, flow, f_entry_tree, flow_cmp);

struct timeslice {
	unsigned int		ts_flow_count;
	struct flow_tree	ts_flow_tree;
	struct flow_list	ts_flow_list;

	struct lookup_list	ts_lookup_list;
	struct rdns_list	ts_rdns_list;

	struct timeval		ts_begin;
	struct timeval		ts_end;

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

struct timeslice	*timeslice_alloc(void);

struct flow_daemon;

struct pkt_source {
	const char		*ps_name;
	struct flow_daemon	*ps_d;
	pcap_t			*ps_ph;
	struct pcap_stat	 ps_pstat;
	struct event		 ps_ev;

	TAILQ_ENTRY(pkt_source)	 ps_entry;
};

TAILQ_HEAD(pkt_sources, pkt_source);

struct flow_daemon {
	struct taskq		*d_taskq;
	struct event		 d_tick;
	struct timeval		 d_tv;

	struct pkt_sources	 d_pkt_sources;
	struct flow		*d_flow;

	struct timeslice	*d_ts;
};

static int	bpf_maxbufsize(void);
static void	flow_tick(int, short, void *);
void		pkt_capture(int, short, void *);

__dead static void
usage(void)
{
	extern char *__progname;

	fprintf(stderr, "usage: %s [-d] [-u user] [-h clickhouse_host] "
	    "[-p clickhouse_port] [-U clickhouse_user] [-k clickhouse_key] "
	    "if0 ...\n", __progname);

	exit(1);
}

static const char *clickhouse_host = "localhost";
static const char *clickhouse_user = "default";
static const char *clickhouse_key = NULL;
static uint16_t clickhouse_port = 8123;

static int debug = 0;

int
main(int argc, char *argv[])
{
	const char *user = "_flow";
	char errbuf[PCAP_ERRBUF_SIZE];
	const char *errstr;
	struct flow_daemon _d = {
		.d_tv = { 1, 0 },
		.d_pkt_sources = TAILQ_HEAD_INITIALIZER(_d.d_pkt_sources),
	};
	struct flow_daemon *d = &_d;
	struct pkt_source *ps;

	struct passwd *pw;
	int ch;
	int devnull = -1;
	int maxbufsize;

	maxbufsize = bpf_maxbufsize();
	if (maxbufsize == -1)
		err(1, "sysctl net.bpf.maxbufsize");

	while ((ch = getopt(argc, argv, "du:w:h:p:U:k:")) != -1) {
		switch (ch) {
		case 'd':
			debug = 1;
			break;
		case 'u':
			user = optarg;
			break;
		case 'w':
			d->d_tv.tv_sec = strtonum(optarg, 1, 900, &errstr);
			if (errstr != NULL)
				errx(1, "%s: %s", optarg, errstr);
		case 'h':
			clickhouse_host = optarg;
			break;
		case 'p':
			clickhouse_port = atoi(optarg);
			break;
		case 'U':
			clickhouse_user = optarg;
			break;
		case 'k':
			clickhouse_key = optarg;
			break;
		default:
			usage();
		}
	}

	argc -= optind;
	argv += optind;

	if (argc == 0)
		usage();

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

		ps->ps_d = d;
		ps->ps_name = argv[ch];
		memset(&ps->ps_pstat, 0, sizeof(ps->ps_pstat));

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

	d->d_flow = malloc(sizeof(*d->d_flow));
	if (d->d_flow == NULL)
		err(1, NULL);

	d->d_ts = timeslice_alloc();
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

static inline int
flow_gre_key_valid(const struct flow_key *k)
{
	uint16_t v = k->k_gre_flags;
	/* ignore checksum and seq no */
	v &= ~htons(GRE_CP|GRE_SP);
	return (v == htons(GRE_VERS_0|GRE_KP));
}

static void
check_resize_buf(FILE **fp, char **reqbufp, size_t *reqlenp)
{
	const size_t off = 2 * ftell(*fp);
	if (off >= *reqlenp) {
		fclose(*fp);
		*fp = NULL;

		*reqlenp *= 2;
		*reqbufp = realloc(*reqbufp, *reqlenp);

		*fp = fmemopen(*reqbufp, *reqlenp, "a");
	}
}

static void
do_clickhouse_sql(const char *sqlbuf, size_t rows, size_t len, const char *what)
{
	static char *reqbuf;
	static size_t reqlen;
	FILE *rs, *ss;
	int sock;
	struct sockaddr_in serv;
	struct hostent *servh;
	char head[256];

	if (reqlen == 0) {
		reqlen = 1024;
		reqbuf = malloc(reqlen);
		if (reqbuf == NULL)
			lerr(1, "malloc");
	}
	rs = fmemopen(reqbuf, reqlen, "w");
	fprintf(rs, "POST / HTTP/1.0\r\n");
	fprintf(rs, "Host: %s:%u\r\n", clickhouse_host, clickhouse_port);
	fprintf(rs, "X-ClickHouse-User: %s\r\n", clickhouse_user);
	if (clickhouse_key != NULL)
		fprintf(rs, "X-ClickHouse-Key: %s\r\n", clickhouse_key);
	fprintf(rs, "Content-Length: %zu\r\n", len - 1);
	fprintf(rs, "Content-Type: text/sql\r\n");
	fprintf(rs, "\r\n");
	fclose(rs);

	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
		lwarn("socket()");
		return;
	}
	servh = gethostbyname(clickhouse_host);
	if (servh == NULL) {
		lwarnx("gethostbyname(): %d", h_errno);
		return;
	}
	bzero(&serv, sizeof (serv));
	serv.sin_family = AF_INET;
	bcopy(servh->h_addr, &serv.sin_addr.s_addr, servh->h_length);
	serv.sin_port = htons(clickhouse_port);

	if (connect(sock, (struct sockaddr *)&serv, sizeof (serv)) < 0) {
		lwarn("connect()");
		return;
	}

	ss = fdopen(sock, "w+");
	fprintf(ss, "%s%s", reqbuf, sqlbuf);
	fflush(ss);

	fgets(head, sizeof (head), ss);
	head[strlen(head) - 1] = '\0';
	head[strlen(head) - 1] = '\0';
	if (strcmp(head, "HTTP/1.0 200 OK") != 0)
		lwarnx("clickhouse: error: returned %s", head);

	if (debug) {
		linfo("clickhouse: POST of %zu %s rows (%zu bytes): %s",
		    rows, what, len, head);
	}

	fclose(ss);
}

static void
timeslice_post(void *arg)
{
	struct timeslice *ts = arg;
	struct flow *f, *nf;
	struct lookup *l, *nl;
	struct rdns *r, *nr;
	size_t len, rows = 0;

	char stbuf[128], etbuf[128];
	struct tm tm;
	time_t time;

	static char *sqlbuf;
	static size_t sqllen = 0;

	const struct flow_key *k;
	uint i;
	const char *join;
	FILE *s;

	if (sqllen == 0) {
		sqllen = 256*1024;
		sqlbuf = malloc(sqllen);
		if (sqlbuf == NULL)
			lerr(1, "malloc");
	}

	time = ts->ts_begin.tv_sec;
	gmtime_r(&time, &tm);
	stbuf[0] = '\0';
	strftime(stbuf, sizeof (stbuf), "%Y-%m-%d %H:%M:%S", &tm);
	snprintf(stbuf, sizeof (stbuf), "%s.%03lu", stbuf,
	    (ts->ts_begin.tv_usec / 1000) % 1000);

	time = ts->ts_end.tv_sec;
	gmtime_r(&time, &tm);
	etbuf[0] = '\0';
	strftime(etbuf, sizeof (etbuf), "%Y-%m-%d %H:%M:%S", &tm);
	snprintf(etbuf, sizeof (etbuf), "%s.%03lu", etbuf,
	    (ts->ts_end.tv_usec / 1000) % 1000);


	rows = 0;
	join = "";
	s = fmemopen(sqlbuf, sqllen, "w");
	if (s == NULL)
		lerr(1, "fmemopen");
	fprintf(s,
	    "INSERT INTO\n"
	    "  flows (begin_at, end_at, vlan, ipv, ipproto, saddr, daddr,\n"
	    "         sport, dport, gre_key, packets, bytes, syns, fins, rsts)\n"
	    "FORMAT Values\n");
	TAILQ_FOREACH_SAFE(f, &ts->ts_flow_list, f_entry_list, nf) {
		k = &f->f_key;
		fprintf(s, "%s('%s','%s',", join, stbuf, etbuf);
		fprintf(s, "%u,%u,%u,", k->k_vlan, k->k_ipv, k->k_ipproto);
		if (k->k_ipv == 4) {
			fprintf(s, "IPv4ToIPv6(toUInt32(%u)),"
			    "IPv4ToIPv6(toUInt32(%u)),",
			    htonl(k->k_saddr.addr4.s_addr),
			    htonl(k->k_daddr.addr4.s_addr));
		} else if (k->k_ipv == 6) {
			fprintf(s, "unhex('");
			for (i = 0; i < sizeof (k->k_saddr.addr6.s6_addr); ++i)
				fprintf(s, "%02x", k->k_saddr.addr6.s6_addr[i]);
			fprintf(s, "'),unhex('");
			for (i = 0; i < sizeof (k->k_daddr.addr6.s6_addr); ++i)
				fprintf(s, "%02x", k->k_daddr.addr6.s6_addr[i]);
			fprintf(s, "'),");
		} else {
			fprintf(s, "unhex('00000000000000000000000000000000'),"
			    "unhex('00000000000000000000000000000000'),");
		}
		fprintf(s, "%u,%u,0,%llu,%llu,%llu,%llu,%llu)", htons(k->k_sport),
		    htons(k->k_dport), f->f_packets, f->f_bytes, f->f_syns,
		    f->f_fins, f->f_rsts);
		free(f);
		join = ",\n";

		check_resize_buf(&s, &sqlbuf, &sqllen);
		++rows;
	}
	fprintf(s, ";\n");
	len = ftell(s);
	fclose(s);

	do_clickhouse_sql(sqlbuf, rows, len, "flow");


	rows = 0;
	join = "";
	s = fmemopen(sqlbuf, sqllen, "w");
	if (s == NULL)
		lerr(1, "fmemopen");
	fprintf(s,
	    "INSERT INTO\n"
	    "  dns_lookups (begin_at, end_at, saddr, daddr, sport, dport,\n"
	    "               qid, name)\n"
	    "FORMAT Values\n");
	TAILQ_FOREACH_SAFE(l, &ts->ts_lookup_list, l_entry, nl) {
		fprintf(s, "%s('%s','%s',", join, stbuf, etbuf);
		if (l->l_ipv == 4) {
			fprintf(s, "IPv4ToIPv6(toUInt32(%u)),"
			    "IPv4ToIPv6(toUInt32(%u)),",
			    htonl(l->l_saddr.addr4.s_addr),
			    htonl(l->l_daddr.addr4.s_addr));
		} else if (l->l_ipv == 6) {
			fprintf(s, "unhex('");
			for (i = 0; i < sizeof (l->l_saddr.addr6.s6_addr); ++i)
				fprintf(s, "%02x", l->l_saddr.addr6.s6_addr[i]);
			fprintf(s, "'),unhex('");
			for (i = 0; i < sizeof (l->l_daddr.addr6.s6_addr); ++i)
				fprintf(s, "%02x", l->l_daddr.addr6.s6_addr[i]);
			fprintf(s, "'),");
		} else {
			fprintf(s, "unhex('00000000000000000000000000000000'),"
			    "unhex('00000000000000000000000000000000'),");
		}
		fprintf(s, "%u,%u,%u,'%s')",
		    htons(l->l_sport), htons(l->l_dport), l->l_qid, l->l_name);

		free(l->l_name);
		free(l);
		join = ",\n";

		check_resize_buf(&s, &sqlbuf, &sqllen);
		++rows;
	}
	fprintf(s, ";\n");
	len = ftell(s);
	fclose(s);

	do_clickhouse_sql(sqlbuf, rows, len, "lookup");



	rows = 0;
	join = "";
	s = fmemopen(sqlbuf, sqllen, "w");
	if (s == NULL)
		lerr(1, "fmemopen");
	fprintf(s,
	    "INSERT INTO\n"
	    "  rdns (begin_at, end_at, addr, name)\n"
	    "FORMAT Values\n");
	TAILQ_FOREACH_SAFE(r, &ts->ts_rdns_list, r_entry, nr) {
		time = ts->ts_end.tv_sec + r->r_ttl;
		gmtime_r(&time, &tm);
		etbuf[0] = '\0';
		strftime(etbuf, sizeof (etbuf), "%Y-%m-%d %H:%M:%S", &tm);
		snprintf(etbuf, sizeof (etbuf), "%s.%03lu", etbuf,
		    (ts->ts_end.tv_usec / 1000) % 1000);

		fprintf(s, "%s('%s','%s',", join, stbuf, etbuf);
		if (r->r_ipv == 4) {
			fprintf(s, "IPv4ToIPv6(toUInt32(%u)),",
			    htonl(r->r_addr.addr4.s_addr));
		} else if (r->r_ipv == 6) {
			fprintf(s, "unhex('");
			for (i = 0; i < sizeof (r->r_addr.addr6.s6_addr); ++i)
				fprintf(s, "%02x", r->r_addr.addr6.s6_addr[i]);
			fprintf(s, "'),");
		} else {
			fprintf(s,
			    "unhex('00000000000000000000000000000000'),");
		}
		fprintf(s, "'%s')", r->r_name);

		free(r->r_name);
		free(r);
		join = ",\n";

		check_resize_buf(&s, &sqlbuf, &sqllen);
		++rows;
	}
	fprintf(s, ";\n");
	len = ftell(s);
	fclose(s);

	do_clickhouse_sql(sqlbuf, rows, len, "rdns");

	free(ts);
}

struct timeslice *
timeslice_alloc(void)
{
	struct timeslice *ts;

	ts = calloc(1, sizeof(*ts));
	if (ts == NULL)
		return (NULL);

	gettimeofday(&ts->ts_begin, NULL);
	ts->ts_flow_count = 0;
	RBT_INIT(flow_tree, &ts->ts_flow_tree);
	TAILQ_INIT(&ts->ts_flow_list);
	TAILQ_INIT(&ts->ts_lookup_list);
	TAILQ_INIT(&ts->ts_rdns_list);

	task_set(&ts->ts_task, timeslice_post, ts);

	return (ts);
}

static void
flow_tick(int nope, short events, void *arg)
{
	struct flow_daemon *d = arg;
	struct pkt_source *ps;
	struct timeslice *ts = d->d_ts;

	evtimer_add(&d->d_tick, &d->d_tv);

	d->d_ts = timeslice_alloc();
	if (d->d_ts == NULL)
		lerr(1, "timeslice alloc");

	TAILQ_FOREACH(ps, &d->d_pkt_sources, ps_entry) {
		struct pcap_stat pstat;

		memset(&pstat, 0, sizeof(pstat)); /* for ifdrop */

		if (pcap_stats(ps->ps_ph, &pstat) != 0)
			errx(1, "%s %s", ps->ps_name, pcap_geterr(ps->ps_ph));

		ts->ts_pcap_recv += pstat.ps_recv - ps->ps_pstat.ps_recv;
		ts->ts_pcap_drop += pstat.ps_drop - ps->ps_pstat.ps_drop;
		ts->ts_pcap_ifdrop += pstat.ps_ifdrop - ps->ps_pstat.ps_ifdrop;

		ps->ps_pstat = pstat;
	}

	gettimeofday(&ts->ts_end, NULL);
	task_add(d->d_taskq, &ts->ts_task);
}

static void
pkt_count_dns(struct timeslice *ts, struct flow_key *k,
    const u_char *buf, u_int buflen)
{
	struct dns_buf *db = NULL;
	const struct dns_header *h;
	const struct dns_question *dq;
	const struct dns_record *dr;
	struct lookup *l;
	struct rdns *r;
	enum dns_parser_rc rc = DNS_R_OK;
	u_int i;

	db = dns_buf_from(buf, buflen);
	if (db == NULL)
		goto nodns;
	if ((rc = dns_read_header(db, &h)))
		goto nodns;
	if (h->dh_opcode != DNS_QUERY)
		goto nodns;
	if ((h->dh_flags & DNS_QR) && h->dh_rcode != DNS_NOERROR)
		goto nodns;
	if (h->dh_questions > 8 || h->dh_answers > 16)
		goto nodns;
	for (i = 0; i < h->dh_questions; ++i) {
		if ((rc = dns_read_question(db, &dq)))
			goto nodns;

		l = calloc(1, sizeof (struct lookup));
		if (l == NULL) {
			rc = DNS_R_NOMEM;
			goto nodns;
		}
		l->l_ipv = k->k_ipv;
		l->l_saddr = k->k_saddr;
		l->l_daddr = k->k_daddr;
		l->l_sport = k->k_sport;
		l->l_dport = k->k_dport;
		l->l_qid = h->dh_id;
		l->l_name = strdup(dq->dq_name);
		TAILQ_INSERT_TAIL(&ts->ts_lookup_list, l, l_entry);
	}
	for (i = 0; i < h->dh_answers; ++i) {
		if ((rc = dns_read_record(db, &dr)))
			goto nodns;

		if (dr->dr_type == DNS_T_A) {
			r = calloc(1, sizeof (struct rdns));
			if (r == NULL) {
				rc = DNS_R_NOMEM;
				goto nodns;
			}
			r->r_ipv = 4;
			r->r_ttl = dr->dr_ttl;
			r->r_name = strdup(dr->dr_name);
			r->r_addr.addr4 = dr->dr_data._dr_a_data;
			TAILQ_INSERT_TAIL(&ts->ts_rdns_list, r, r_entry);

		} else if (dr->dr_type == DNS_T_AAAA) {
			r = calloc(1, sizeof (struct rdns));
			if (r == NULL) {
				rc = DNS_R_NOMEM;
				goto nodns;
			}
			r->r_ipv = 6;
			r->r_ttl = dr->dr_ttl;
			r->r_name = strdup(dr->dr_name);
			r->r_addr.addr6 = dr->dr_data._dr_aaaa_data;
			TAILQ_INSERT_TAIL(&ts->ts_rdns_list, r, r_entry);
		}
	}

nodns:
	switch (rc) {
	case DNS_R_OK:
	case DNS_R_SHORT:
		break;
	case DNS_R_PTRLIMIT:
		//linfo("dns: hit ptr chase limit");
		break;
	case DNS_R_ERROR:
		//linfo("dns: parse error");
		break;
	case DNS_R_NOMEM:
		//linfo("dns: out of memory");
		break;
	}
	dns_buf_free(db);
}

static int
pkt_count_tcp(struct timeslice *ts, struct flow_key *k,
    const u_char *buf, u_int buflen)
{
	const struct tcphdr *th;

	if (buflen < sizeof(*th)) {
		ts->ts_short_ipproto++;
		return (-1);
	}

	th = (const struct tcphdr *)buf;

	k->k_sport = th->th_sport;
	k->k_dport = th->th_dport;
	k->k_syn = (th->th_flags & (TH_SYN | TH_ACK)) == TH_SYN;
	k->k_fin = (th->th_flags & (TH_FIN | TH_ACK)) == TH_FIN;
	k->k_rst = (th->th_flags & (TH_RST | TH_ACK)) == TH_RST;

	if ((htons(th->th_dport) == 53 || htons(th->th_sport) == 53) &&
	    buflen > th->th_off * 4) {
		buf += th->th_off * 4;
		buflen -= th->th_off * 4;
		/* TCP DNS queries have a 16-bit length prefix. */
		if (buflen > 2) {
			buflen -= 2;
			buf += 2;
			pkt_count_dns(ts, k, buf, buflen);
		}
	}

	return (0);
}

static int
pkt_count_udp(struct timeslice *ts, struct flow_key *k,
    const u_char *buf, u_int buflen)
{
	const struct udphdr *uh;

	if (buflen < sizeof(*uh)) {
		ts->ts_short_ipproto++;
		return (-1);
	}

	uh = (const struct udphdr *)buf;

	k->k_sport = uh->uh_sport;
	k->k_dport = uh->uh_dport;

	if ((htons(uh->uh_dport) == 53 || htons(uh->uh_sport) == 53) &&
	    buflen > sizeof (struct udphdr)) {
		buf += sizeof (struct udphdr);
		buflen -= sizeof (struct udphdr);
		pkt_count_dns(ts, k, buf, buflen);
	}
	return (0);
}

static int
pkt_count_gre(struct timeslice *ts, struct flow_key *k,
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

	k->k_gre_flags = gh->gre_flags;
	k->k_gre_proto = gh->gre_proto;

	if (!flow_gre_key_valid(k))
		return (0);

	hlen = sizeof(*gh);
	if (ISSET(k->k_gre_flags, htons(GRE_CP)))
		hlen += sizeof(struct gre_h_cksum);
	gkh = (const struct gre_h_key *)buf;
	hlen += sizeof(*gkh);
	if (buflen < hlen) {
		return ts->ts_short_ipproto++;
		return (-1);
	}

	k->k_gre_key = gkh->gre_key;

	return (0);
}

static int
pkt_count_ipproto(struct timeslice *ts, struct flow_key *k,
    const u_char *buf, u_int buflen)
{
	switch (k->k_ipproto) {
	case IPPROTO_TCP:
		return (pkt_count_tcp(ts, k, buf, buflen));
	case IPPROTO_UDP:
	case IPPROTO_UDPLITE:
		return (pkt_count_udp(ts, k, buf, buflen));
	case IPPROTO_GRE:
		return (pkt_count_gre(ts, k, buf, buflen));
	}

	return (0);
}

static int
pkt_count_icmp4(struct timeslice *ts, struct flow_key *k,
    const u_char *buf, u_int buflen)
{
	const struct icmp *icmp4h;

	if (buflen < offsetof(struct icmp, icmp_cksum)) {
		ts->ts_short_ipproto++;
		return (-1);
	}

	icmp4h = (const struct icmp *)buf;

	k->k_icmp_type = icmp4h->icmp_type;
	k->k_icmp_code = icmp4h->icmp_code;

	return (0);
}

static int
pkt_count_ip4(struct timeslice *ts, struct flow_key *k,
    const u_char *buf, u_int buflen)
{
	const struct ip *iph;
	u_int hlen;

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

	k->k_ipv = 4;
	k->k_ipproto = iph->ip_p;
	k->k_saddr4 = iph->ip_src;
	k->k_daddr4 = iph->ip_dst;

	if (k->k_ipproto == IPPROTO_ICMP)
		return (pkt_count_icmp4(ts, k, buf, buflen));

	return (pkt_count_ipproto(ts, k, buf, buflen));
}

static int
pkt_count_icmp6(struct timeslice *ts, struct flow_key *k,
    const u_char *buf, u_int buflen)
{
	const struct icmp6_hdr *icmp6h;

	if (buflen < offsetof(struct icmp6_hdr, icmp6_cksum)) {
		ts->ts_short_ipproto++;
		return (-1);
	}

	icmp6h = (const struct icmp6_hdr *)buf;

	k->k_icmp_type = icmp6h->icmp6_type;
	k->k_icmp_code = icmp6h->icmp6_code;

	return (0);
}

static int
pkt_count_ip6(struct timeslice *ts, struct flow_key *k,
    const u_char *buf, u_int buflen)
{
	const struct ip6_hdr *ip6;

	if (buflen < sizeof(*ip6)) {
		ts->ts_short_ip6++;
		return (-1);
	}

	ip6 = (const struct ip6_hdr *)buf;

	/* XXX check ipv and all that poop? */

	buf += sizeof(*ip6);
	buflen -= sizeof(*ip6);

	k->k_ipv = 6;
	k->k_ipproto = ip6->ip6_nxt;
	k->k_saddr6 = ip6->ip6_src;
	k->k_daddr6 = ip6->ip6_dst;

	if (k->k_ipproto == IPPROTO_ICMPV6)
		return (pkt_count_icmp6(ts, k, buf, buflen));

	return (pkt_count_ipproto(ts, k, buf, buflen));
}

static void
pkt_count(u_char *arg, const struct pcap_pkthdr *hdr, const u_char *buf)
{
	struct flow_daemon *d = (struct flow_daemon *)arg;
	struct timeslice *ts = d->d_ts;
	struct flow *f = d->d_flow;
	struct flow *of;

	struct ether_header *eh;
	uint16_t type;
	u_int hlen = sizeof(*eh);

	u_int buflen = hdr->caplen;
	u_int pktlen = hdr->len;

	memset(&f->f_key, 0, sizeof(f->f_key));

	if (buflen < hlen) {
		ts->ts_short_ether++;
		return;
	}

	eh = (struct ether_header *)buf;
	type = eh->ether_type;

	if (type == htons(ETHERTYPE_VLAN)) {
		struct ether_vlan_header *evh;
		hlen = sizeof(*evh);

		if (buflen < hlen) {
			ts->ts_short_vlan++;
			return;
		}

		evh = (struct ether_vlan_header *)buf;
		f->f_key.k_vlan = EVL_VLANOFTAG(htons(evh->evl_tag));
		type = evh->evl_proto;
	} else
		f->f_key.k_vlan = FLOW_VLAN_UNSET;

	buf += hlen;
	buflen -= hlen;
	pktlen -= hlen;

	f->f_packets = 1;
	f->f_bytes = pktlen;

	switch (type) {
	case htons(ETHERTYPE_IP):
		if (pkt_count_ip4(ts, &f->f_key, buf, buflen) == -1)
			return;
		break;
	case htons(ETHERTYPE_IPV6):
		if (pkt_count_ip6(ts, &f->f_key, buf, buflen) == -1)
			return;
		break;

	default:
		ts->ts_nonip++;
		return;
	}

	f->f_syns = f->f_key.k_syn;
	f->f_fins = f->f_key.k_fin;
	f->f_rsts = f->f_key.k_rst;

	of = RBT_INSERT(flow_tree, &ts->ts_flow_tree, f);
	if (of == NULL) {
		d->d_flow = malloc(sizeof(*d->d_flow));
		if (d->d_flow == NULL)
			lerr(1, "flow alloc");

		ts->ts_flow_count++;
		TAILQ_INSERT_TAIL(&ts->ts_flow_list, f, f_entry_list);
	} else {
		of->f_packets++;
		of->f_bytes += f->f_bytes;
		of->f_syns += f->f_syns;
		of->f_fins += f->f_fins;
		of->f_rsts += f->f_rsts;
	}
}

void
pkt_capture(int fd, short events, void *arg)
{
	struct pkt_source *ps = arg;

	if (pcap_dispatch(ps->ps_ph, -1, pkt_count, (u_char *)ps->ps_d) < 0)
		lerrx(1, "%s", pcap_geterr(ps->ps_ph));
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
