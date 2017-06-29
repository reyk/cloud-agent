.PATH:	${BSDSRCDIR}/usr.bin/openssl

PROG=	cms
SRCS=	cms.c apps.c app_rand.c

LDADD+=	-lcrypto
NOMAN=	yes

.include <bsd.prog.mk>
