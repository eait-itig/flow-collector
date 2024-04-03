
PROG=	flow
SRCS=	flow.c
SRCS+=	log.c task.c
MAN=

LDADD=-lpcap -lpthread -levent
DPADD=${LIBPCAP} ${LIBPTHREAD} ${LIBEVENT}

DEBUG=-g
WARNINGS=yes

.include <bsd.prog.mk>
