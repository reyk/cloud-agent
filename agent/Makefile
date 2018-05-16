PROG=		cloud-agent
SRCS=		azure.c cloudinit.c http.c json.c jsmn.c log.c openstack.c main.c xml.c
BINDIR=		/usr/local/libexec
MANDIR=		/usr/local/man/man

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

.include <bsd.prog.mk>
