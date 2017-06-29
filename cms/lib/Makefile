LIB=		cms

SRCS+=		cms_asn1.c   cms_dd.c     cms_err.c    cms_kari.c   cms_sd.c
SRCS+=		cms_att.c    cms_enc.c    cms_ess.c    cms_lib.c    cms_smime.c
SRCS+=		cms_cd.c     cms_env.c    cms_io.c     cms_pwri.c
SRCS+=		libressl_pkey.c libressl_stubs.c

DEBUGLIBS=	no
NOPROFILE=	yes
NOPIC=		yes

LDADD+=		-lcrypto
NOMAN=		yes

install:
	@echo -n

.include <bsd.own.mk>
.include <bsd.lib.mk>
