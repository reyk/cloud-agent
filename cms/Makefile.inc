.include <bsd.own.mk>
.include <bsd.obj.mk>

BINDIR?=        /usr/local/bin

LIBCRYPTOSRC=	${BSDSRCDIR}/lib/libcrypto

CFLAGS+=	-I${.CURDIR}
CFLAGS+=	-I${.CURDIR}/../lib
CFLAGS+=	-I${LIBCRYPTOSRC}/asn1
CFLAGS+=	-I${LIBCRYPTOSRC}/evp
CFLAGS+=	-Wall

.if exists(${.CURDIR}/../lib/${__objdir})
LDADD+=         -L${.CURDIR}/../lib/${__objdir} -lcms
DPADD+=         ${.CURDIR}/../lib/${__objdir}/libcms.a
.else
LDADD+=         -L${.CURDIR}/../lib -lcms
DPADD+=         ${.CURDIR}/../lib/libcms.a
.endif
