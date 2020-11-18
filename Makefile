
PROG=	flow
SRCS=	flow.c
#PROG=	dnstest
#SRCS=	dns_test.c
SRCS+=	log.c task.c dns.c
MAN=

LDADD=-lpcap -lpthread -levent
DPADD=${LIBPCAP} ${LIBPTHREAD} ${LIBEVENT}

DEBUG=-g
WARNINGS=yes

.include <bsd.prog.mk>
