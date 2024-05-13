
PROG=	flow
SRCS=	flow.c
SRCS+=	log.c task.c
MAN=

CFLAGS+=-I${.CURDIR}/llhttp/include

LLHTTP_SRCS=llhttp.c api.c http.c

.for S in ${LLHTTP_SRCS}
${S:T:.c=.o}: llhttp/src/${S}
	${COMPILE.c} -Wno-missing-prototypes -o ${.TARGET} ${.IMPSRC}
.endfor

OBJS+=${LLHTTP_SRCS:T:.c=.o}

LDADD=-lpcap -lpthread -levent -ltls
DPADD=${LIBPCAP} ${LIBPTHREAD} ${LIBEVENT} ${LIBTLS}

DEBUG=-g
WARNINGS=yes

.include <bsd.prog.mk>
