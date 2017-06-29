#include <openssl/asn1t.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/asn1.h>
#ifdef USE_OPENSSL
#include <openssl/cms.h>
#else
#include "cms.h"
#include "cms_lcl.h"
#endif
#include "apps.h"
#include <unistd.h>

#define OPENSSL_CONF "openssl.cnf"
#define OPENSSL_NO_ENGINE
#define MS_STATIC static
int cms_main(int argc, char **argv);
