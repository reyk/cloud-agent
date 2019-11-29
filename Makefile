#
# The Azure agents needs CMS to obtain the SSH public keys.
# LibreSSL has removed CMS, so either use OpenSSL to decrypt CMS
# messages or compile the old CMS code for LibreSSL.  Or use
# CMS that has returned to newer versions of LibreSSL.
#
.ifdef USE_OPENSSL
MAKE_FLAGS+=	USE_OPENSSL=1
.elifdef USE_LIBRESSL_CMS
MAKE_FLAGS+=	USE_LIBRESSL_CMS=1
.else
SUBDIR=		cms
.endif

SUBDIR+=	agent

.include <bsd.subdir.mk>
