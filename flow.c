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
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>

#include <sys/queue.h>
#include <sys/tree.h>

#include <pcap.h>
#include <event.h>

#include "log.h"
#include "task.h"

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
			uint16_t	_k_flags;
			uint16_t	_k_proto;
			uint32_t	_k_key;
		}		_k_gre;
	}			k_proto;
#define k_sport				k_proto._k_ports._k_sport
#define k_dport				k_proto._k_ports._k_dport

};

struct flow {
	struct flow_key		f_key;

	uint64_t		f_packets;
	uint64_t		f_bytes;

	RBT_ENTRY(flow)		f_entry_tree;
	TAILQ_ENTRY(flow)	f_entry_list;
};

RBT_HEAD(flow_tree, flow);
TAILQ_HEAD(flow_list, flow);

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

	uint64_t		ts_short_ether;
	uint64_t		ts_short_vlan;
	uint64_t		ts_short_ip4;
	uint64_t		ts_short_ip6;
	uint64_t		ts_short_ipproto;
	uint64_t		ts_nonip;

	unsigned int		ts_pcap_recv;
	unsigned int		ts_pcap_drop;

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

static void	flow_tick(int, short, void *);
void		pkt_capture(int, short, void *);

__dead static void
usage(void)
{
	extern char *__progname;

	fprintf(stderr, "usage: %s [-d] [-u user] if0 ...\n", __progname);

	exit(1);
}

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
	int debug = 0;

	if (geteuid())
		lerrx(1, "neet root privileges");

	while ((ch = getopt(argc, argv, "du:w:")) != -1) {
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
			break;
		default:
			usage();
		}
	}

	argc -= optind;
	argv += optind;

	if (argc == 0)
		usage();

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

		ps->ps_ph = pcap_open_live(argv[ch], 256, 1, 2000, errbuf);
		if (ps->ps_ph == NULL)
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

static void
timeslice_post(void *arg)
{
	struct timeslice *ts = arg;
	struct flow *f, *nf;
	uint64_t packets = 0;
	uint64_t bytes = 0;

	TAILQ_FOREACH_SAFE(f, &ts->ts_flow_list, f_entry_list, nf) {
		packets += f->f_packets;
		bytes += f->f_bytes;
		free(f);
	}

	printf("flows %u packets %llu bytes %llu\n", ts->ts_flow_count,
	    packets, bytes);
	printf("short ether %llu, short vlan %llu, short ip4 %llu, "
	    "short ip6 %llu, short proto %llu, nonip %llu "
	    "pcap_recv %u pcap_drop %u\n",
	    ts->ts_short_ether, ts->ts_short_vlan, ts->ts_short_ip4, 
	    ts->ts_short_ip6, ts->ts_short_ipproto, ts->ts_nonip,
	    ts->ts_pcap_recv, ts->ts_pcap_drop);

	free(ts);
}

struct timeslice *
timeslice_alloc(void)
{
	struct timeslice *ts;

	ts = calloc(1, sizeof(*ts));
	if (ts == NULL)
		return (NULL);

	ts->ts_flow_count = 0;
	RBT_INIT(flow_tree, &ts->ts_flow_tree);
	TAILQ_INIT(&ts->ts_flow_list);

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

		if (pcap_stats(ps->ps_ph, &pstat) != 0)
			errx(1, "%s %s", ps->ps_name, pcap_geterr(ps->ps_ph));

		ts->ts_pcap_recv += pstat.ps_recv - ps->ps_pstat.ps_recv;
		ts->ts_pcap_drop += pstat.ps_drop - ps->ps_pstat.ps_drop;

		ps->ps_pstat = pstat;
	}

	task_add(d->d_taskq, &ts->ts_task);
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
	}

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
	k->k_saddr4 = iph->ip_src;
	k->k_daddr4 = iph->ip_dst;
	k->k_ipproto = iph->ip_p;

	return (pkt_count_ipproto(ts, k, buf, buflen));
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
	k->k_saddr6 = ip6->ip6_src;
	k->k_daddr6 = ip6->ip6_dst;
	k->k_ipproto = ip6->ip6_nxt;

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
