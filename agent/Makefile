PROG=		cloud-agent
SRCS=		main.c xml.c azure.c cloudinit.c http.c log.c
BINDIR=		/usr/local/libexec
MANDIR=		/usr/local/share/man/man

MAN=		cloud-agent.8

.ifdef USE_OPENSSL
CFLAGS+=	-DUSE_OPENSSL=1
.endif

CFLAGS+=	-Wall
CFLAGS+=	-Wstrict-prototypes -Wmissing-prototypes
CFLAGS+=	-Wmissing-declarations
CFLAGS+=	-Wshadow -Wpointer-arith
CFLAGS+=	-Wsign-compare -Wcast-qual

LDADD+=		-lexpat -ltls -lssl -lcrypto
DPADD+=		${LIBEXPAT} ${LIBTLS} ${LIBSSL} ${LIBCRYPTO}

beforeinstall:
	mkdir -p ${MANDIR}8

.include <bsd.prog.mk>
