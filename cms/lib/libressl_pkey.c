/* crypto/rsa/rsa_ameth.c */
/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL project
 * 2006.
 */
/* ====================================================================
 * Copyright (c) 2006 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    licensing@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */

#include "cryptlib.h"
#include <openssl/asn1t.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/x509v3.h>
#include "cms.h"
#include "cms_lcl.h"
#include "evp_locl.h"
#include "asn1_locl.h"

#include "libressl_evp.h"

/* RSA pkey context structure */

typedef struct {
	/* Key gen parameters */
	int nbits;
	BIGNUM *pub_exp;
	/* Keygen callback info */
	int gentmp[2];
	/* RSA padding mode */
	int pad_mode;
	/* message digest */
	const EVP_MD *md;
	/* message digest for MGF1 */
	const EVP_MD *mgf1md;
	/* PSS/OAEP salt length */
	int saltlen;
	/* Temp buffer */
	unsigned char *tbuf;
} RSA_PKEY_CTX;

static int pkey_rsa_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2);
static int pkey_rsa_ctrl_str(EVP_PKEY_CTX *ctx, const char *type,
    const char *value);
static int rsa_cms_sign(CMS_SignerInfo *si);
static int rsa_cms_verify(CMS_SignerInfo *si);
static int rsa_cms_decrypt(CMS_RecipientInfo *ri);
static int rsa_cms_encrypt(CMS_RecipientInfo *ri);

int libressl_pkey_ctrl(EVP_PKEY *pkey, int op, long arg1, void *arg2)
{
    X509_ALGOR *alg = NULL;

    if (pkey->ameth->pkey_id != EVP_PKEY_RSA)
	return -2;

    switch (op) {

    case ASN1_PKEY_CTRL_CMS_SIGN:
        if (arg1 == 0)
            return rsa_cms_sign(arg2);
        else if (arg1 == 1)
            return rsa_cms_verify(arg2);
        break;

    case ASN1_PKEY_CTRL_CMS_ENVELOPE:
        if (arg1 == 0)
            return rsa_cms_encrypt(arg2);
        else if (arg1 == 1)
            return rsa_cms_decrypt(arg2);
        break;

    case ASN1_PKEY_CTRL_CMS_RI_TYPE:
        *(int *)arg2 = CMS_RECIPINFO_TRANS;
        return 1;

    default:
	return -2;

    }

    if (alg)
        X509_ALGOR_set0(alg, OBJ_nid2obj(NID_rsaEncryption), V_ASN1_NULL, 0);

    return 1;
}

int libressl_pkey_ctx_ctrl(EVP_PKEY_CTX *ctx, int keytype, int optype,
    int cmd, int p1, void *p2)
{
    int ret;
    if (!ctx || !ctx->pmeth || !ctx->pmeth->ctrl) {
        EVPerr(EVP_F_EVP_PKEY_CTX_CTRL, EVP_R_COMMAND_NOT_SUPPORTED);
        return -2;
    }
    if ((keytype != -1) && (ctx->pmeth->pkey_id != keytype))
        return -1;

    if (ctx->operation == EVP_PKEY_OP_UNDEFINED) {
        EVPerr(EVP_F_EVP_PKEY_CTX_CTRL, EVP_R_NO_OPERATION_SET);
        return -1;
    }

    if ((optype != -1) && !(ctx->operation & optype)) {
        EVPerr(EVP_F_EVP_PKEY_CTX_CTRL, EVP_R_INVALID_OPERATION);
        return -1;
    }

    if (ctx->pmeth->pkey_id != EVP_PKEY_RSA)
        return -1;

    ret = pkey_rsa_ctrl(ctx, cmd, p1, p2);

    if (ret == -2)
        EVPerr(EVP_F_EVP_PKEY_CTX_CTRL, EVP_R_COMMAND_NOT_SUPPORTED);

    return ret;

}

static int check_padding_md(const EVP_MD *md, int padding)
{
    if (!md)
        return 1;

    if (padding == RSA_NO_PADDING) {
        RSAerr(RSA_F_CHECK_PADDING_MD, RSA_R_INVALID_PADDING_MODE);
        return 0;
    }

    if (padding == RSA_X931_PADDING) {
        if (RSA_X931_hash_id(EVP_MD_type(md)) == -1) {
            RSAerr(RSA_F_CHECK_PADDING_MD, RSA_R_INVALID_X931_DIGEST);
            return 0;
        }
        return 1;
    }

    return 1;
}

static int pkey_rsa_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2)
{
    RSA_PKEY_CTX *rctx = ctx->data;
    switch (type) {
    case EVP_PKEY_CTRL_RSA_PADDING:
        if ((p1 >= RSA_PKCS1_PADDING) && (p1 <= RSA_PKCS1_PSS_PADDING)) {
            if (!check_padding_md(rctx->md, p1))
                return 0;
            if (p1 == RSA_PKCS1_PSS_PADDING) {
                if (!(ctx->operation &
                      (EVP_PKEY_OP_SIGN | EVP_PKEY_OP_VERIFY)))
                    goto bad_pad;
                if (!rctx->md)
                    rctx->md = EVP_sha1();
            } else
                    goto bad_pad;
            rctx->pad_mode = p1;
            return 1;
        }
 bad_pad:
        RSAerr(RSA_F_PKEY_RSA_CTRL,
               RSA_R_ILLEGAL_OR_UNSUPPORTED_PADDING_MODE);
        return -2;

    case EVP_PKEY_CTRL_GET_RSA_PADDING:
        *(int *)p2 = rctx->pad_mode;
        return 1;

    case EVP_PKEY_CTRL_RSA_PSS_SALTLEN:
    case EVP_PKEY_CTRL_GET_RSA_PSS_SALTLEN:
        if (rctx->pad_mode != RSA_PKCS1_PSS_PADDING) {
            RSAerr(RSA_F_PKEY_RSA_CTRL, RSA_R_INVALID_PSS_SALTLEN);
            return -2;
        }
        if (type == EVP_PKEY_CTRL_GET_RSA_PSS_SALTLEN)
            *(int *)p2 = rctx->saltlen;
        else {
            if (p1 < -2)
                return -2;
            rctx->saltlen = p1;
        }
        return 1;

    case EVP_PKEY_CTRL_RSA_KEYGEN_BITS:
        if (p1 < 256) {
            RSAerr(RSA_F_PKEY_RSA_CTRL, RSA_R_INVALID_KEYBITS);
            return -2;
        }
        rctx->nbits = p1;
        return 1;

    case EVP_PKEY_CTRL_RSA_KEYGEN_PUBEXP:
        if (p2 == NULL || !BN_is_odd((BIGNUM *)p2) || BN_is_one((BIGNUM *)p2)) {
            RSAerr(RSA_F_PKEY_RSA_CTRL, RSA_R_BAD_E_VALUE);
            return -2;
        }
        BN_free(rctx->pub_exp);
        rctx->pub_exp = p2;
        return 1;

    case EVP_PKEY_CTRL_MD:
        if (!check_padding_md(p2, rctx->pad_mode))
            return 0;
        rctx->md = p2;
        return 1;

    case EVP_PKEY_CTRL_GET_MD:
        *(const EVP_MD **)p2 = rctx->md;
        return 1;

    case EVP_PKEY_CTRL_RSA_MGF1_MD:
    case EVP_PKEY_CTRL_GET_RSA_MGF1_MD:
        if (rctx->pad_mode != RSA_PKCS1_PSS_PADDING) {
            RSAerr(RSA_F_PKEY_RSA_CTRL, RSA_R_INVALID_MGF1_MD);
            return -2;
        }
        if (type == EVP_PKEY_CTRL_GET_RSA_MGF1_MD) {
            if (rctx->mgf1md)
                *(const EVP_MD **)p2 = rctx->mgf1md;
            else
                *(const EVP_MD **)p2 = rctx->md;
        } else
            rctx->mgf1md = p2;
        return 1;

    case EVP_PKEY_CTRL_DIGESTINIT:
    case EVP_PKEY_CTRL_PKCS7_ENCRYPT:
    case EVP_PKEY_CTRL_PKCS7_DECRYPT:
    case EVP_PKEY_CTRL_PKCS7_SIGN:
        return 1;
    case EVP_PKEY_CTRL_CMS_DECRYPT:
    case EVP_PKEY_CTRL_CMS_ENCRYPT:
    case EVP_PKEY_CTRL_CMS_SIGN:
        return 1;
    case EVP_PKEY_CTRL_PEER_KEY:
        RSAerr(RSA_F_PKEY_RSA_CTRL,
               RSA_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
        return -2;

    default:
        return -2;

    }
}

int libressl_pkey_ctx_ctrl_str(EVP_PKEY_CTX *ctx, const char *name,
    const char *value)
{
    if (!ctx || !ctx->pmeth || !ctx->pmeth->ctrl_str) {
        EVPerr(EVP_F_EVP_PKEY_CTX_CTRL_STR, EVP_R_COMMAND_NOT_SUPPORTED);
        return -2;
    }
    if (!strcmp(name, "digest")) {
        const EVP_MD *md;
        if (!value || !(md = EVP_get_digestbyname(value))) {
            EVPerr(EVP_F_EVP_PKEY_CTX_CTRL_STR, EVP_R_INVALID_DIGEST);
            return 0;
        }
        return EVP_PKEY_CTX_set_signature_md(ctx, md);
    }
    return pkey_rsa_ctrl_str(ctx, name, value);
}

static int pkey_rsa_ctrl_str(EVP_PKEY_CTX *ctx, const char *type,
    const char *value)
{
    if (!value) {
        RSAerr(RSA_F_PKEY_RSA_CTRL_STR, RSA_R_VALUE_MISSING);
        return 0;
    }
    if (!strcmp(type, "rsa_padding_mode")) {
        int pm;
        if (!strcmp(value, "pkcs1"))
            pm = RSA_PKCS1_PADDING;
        else if (!strcmp(value, "sslv23"))
            pm = RSA_SSLV23_PADDING;
        else if (!strcmp(value, "none"))
            pm = RSA_NO_PADDING;
        else if (!strcmp(value, "x931"))
            pm = RSA_X931_PADDING;
        else if (!strcmp(value, "pss"))
            pm = RSA_PKCS1_PSS_PADDING;
        else {
            RSAerr(RSA_F_PKEY_RSA_CTRL_STR, RSA_R_UNKNOWN_PADDING_TYPE);
            return -2;
        }
        return EVP_PKEY_CTX_set_rsa_padding(ctx, pm);
    }

    if (!strcmp(type, "rsa_pss_saltlen")) {
        int saltlen;
        saltlen = atoi(value);
        return EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx, saltlen);
    }

    if (!strcmp(type, "rsa_keygen_bits")) {
        int nbits;
        nbits = atoi(value);
        return EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, nbits);
    }

    if (!strcmp(type, "rsa_keygen_pubexp")) {
        int ret;
        BIGNUM *pubexp = NULL;
        if (!BN_asc2bn(&pubexp, value))
            return 0;
        ret = EVP_PKEY_CTX_set_rsa_keygen_pubexp(ctx, pubexp);
        if (ret <= 0)
            BN_free(pubexp);
        return ret;
    }

    if (!strcmp(type, "rsa_mgf1_md")) {
        const EVP_MD *md;
        if (!(md = EVP_get_digestbyname(value))) {
            return 0;
        }
        return EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, md);
    }

    return -2;
}

/* Given an MGF1 Algorithm ID decode to an Algorithm Identifier */
static X509_ALGOR *rsa_mgf1_decode(X509_ALGOR *alg)
{
    const unsigned char *p;
    int plen;
    if (alg == NULL || alg->parameter == NULL)
        return NULL;
    if (OBJ_obj2nid(alg->algorithm) != NID_mgf1)
        return NULL;
    if (alg->parameter->type != V_ASN1_SEQUENCE)
        return NULL;

    p = alg->parameter->value.sequence->data;
    plen = alg->parameter->value.sequence->length;
    return d2i_X509_ALGOR(NULL, &p, plen);
}

static RSA_PSS_PARAMS *rsa_pss_decode(const X509_ALGOR *alg,
                                      X509_ALGOR **pmaskHash)
{
    const unsigned char *p;
    int plen;
    RSA_PSS_PARAMS *pss;

    *pmaskHash = NULL;

    if (!alg->parameter || alg->parameter->type != V_ASN1_SEQUENCE)
        return NULL;
    p = alg->parameter->value.sequence->data;
    plen = alg->parameter->value.sequence->length;
    pss = d2i_RSA_PSS_PARAMS(NULL, &p, plen);

    if (!pss)
        return NULL;

    *pmaskHash = rsa_mgf1_decode(pss->maskGenAlgorithm);

    return pss;
}

/* allocate and set algorithm ID from EVP_MD, default SHA1 */
static int rsa_md_to_algor(X509_ALGOR **palg, const EVP_MD *md)
{
    if (EVP_MD_type(md) == NID_sha1)
        return 1;
    *palg = X509_ALGOR_new();
    if (!*palg)
        return 0;
    X509_ALGOR_set_md(*palg, md);
    return 1;
}

/* Allocate and set MGF1 algorithm ID from EVP_MD */
static int rsa_md_to_mgf1(X509_ALGOR **palg, const EVP_MD *mgf1md)
{
    X509_ALGOR *algtmp = NULL;
    ASN1_STRING *stmp = NULL;
    *palg = NULL;
    if (EVP_MD_type(mgf1md) == NID_sha1)
        return 1;
    /* need to embed algorithm ID inside another */
    if (!rsa_md_to_algor(&algtmp, mgf1md))
        goto err;
    if (!ASN1_item_pack(algtmp, ASN1_ITEM_rptr(X509_ALGOR), &stmp))
         goto err;
    *palg = X509_ALGOR_new();
    if (!*palg)
        goto err;
    X509_ALGOR_set0(*palg, OBJ_nid2obj(NID_mgf1), V_ASN1_SEQUENCE, stmp);
    stmp = NULL;
 err:
    if (stmp)
        ASN1_STRING_free(stmp);
    if (algtmp)
        X509_ALGOR_free(algtmp);
    if (*palg)
        return 1;
    return 0;
}

/* convert algorithm ID to EVP_MD, default SHA1 */
static const EVP_MD *rsa_algor_to_md(X509_ALGOR *alg)
{
    const EVP_MD *md;
    if (!alg)
        return EVP_sha1();
    md = EVP_get_digestbyobj(alg->algorithm);
    return md;
}

/* convert MGF1 algorithm ID to EVP_MD, default SHA1 */
static const EVP_MD *rsa_mgf1_to_md(X509_ALGOR *alg, X509_ALGOR *maskHash)
{
    const EVP_MD *md;
    if (!alg)
        return EVP_sha1();
    /* Check mask and lookup mask hash algorithm */
    if (OBJ_obj2nid(alg->algorithm) != NID_mgf1) {
        return NULL;
    }
    if (!maskHash) {
        return NULL;
    }
    md = EVP_get_digestbyobj(maskHash->algorithm);
    return md;
}

/*
 * Convert EVP_PKEY_CTX is PSS mode into corresponding algorithm parameter,
 * suitable for setting an AlgorithmIdentifier.
 */

static ASN1_STRING *rsa_ctx_to_pss(EVP_PKEY_CTX *pkctx)
{
    const EVP_MD *sigmd, *mgf1md;
    RSA_PSS_PARAMS *pss = NULL;
    ASN1_STRING *os = NULL;
    EVP_PKEY *pk = EVP_PKEY_CTX_get0_pkey(pkctx);
    int saltlen, rv = 0;
    if (EVP_PKEY_CTX_get_signature_md(pkctx, &sigmd) <= 0)
        goto err;
    if (EVP_PKEY_CTX_get_rsa_mgf1_md(pkctx, &mgf1md) <= 0)
        goto err;
    if (!EVP_PKEY_CTX_get_rsa_pss_saltlen(pkctx, &saltlen))
        goto err;
    if (saltlen == -1)
        saltlen = EVP_MD_size(sigmd);
    else if (saltlen == -2) {
        saltlen = EVP_PKEY_size(pk) - EVP_MD_size(sigmd) - 2;
        if (((EVP_PKEY_bits(pk) - 1) & 0x7) == 0)
            saltlen--;
    }
    pss = RSA_PSS_PARAMS_new();
    if (!pss)
        goto err;
    if (saltlen != 20) {
        pss->saltLength = ASN1_INTEGER_new();
        if (!pss->saltLength)
            goto err;
        if (!ASN1_INTEGER_set(pss->saltLength, saltlen))
            goto err;
    }
    if (!rsa_md_to_algor(&pss->hashAlgorithm, sigmd))
        goto err;
    if (!rsa_md_to_mgf1(&pss->maskGenAlgorithm, mgf1md))
        goto err;
    /* Finally create string with pss parameter encoding. */
    if (!ASN1_item_pack(pss, ASN1_ITEM_rptr(RSA_PSS_PARAMS), &os))
         goto err;
    rv = 1;
 err:
    if (pss)
        RSA_PSS_PARAMS_free(pss);
    if (rv)
        return os;
    if (os)
        ASN1_STRING_free(os);
    return NULL;
}

/*
 * From PSS AlgorithmIdentifier set public key parameters. If pkey isn't NULL
 * then the EVP_MD_CTX is setup and initalised. If it is NULL parameters are
 * passed to pkctx instead.
 */

static int rsa_pss_to_ctx(EVP_MD_CTX *ctx, EVP_PKEY_CTX *pkctx,
                          X509_ALGOR *sigalg, EVP_PKEY *pkey)
{
    int rv = -1;
    int saltlen;
    const EVP_MD *mgf1md = NULL, *md = NULL;
    RSA_PSS_PARAMS *pss;
    X509_ALGOR *maskHash;
    /* Sanity check: make sure it is PSS */
    if (OBJ_obj2nid(sigalg->algorithm) != NID_rsassaPss) {
        return -1;
    }
    /* Decode PSS parameters */
    pss = rsa_pss_decode(sigalg, &maskHash);

    if (pss == NULL) {
        goto err;
    }
    mgf1md = rsa_mgf1_to_md(pss->maskGenAlgorithm, maskHash);
    if (!mgf1md)
        goto err;
    md = rsa_algor_to_md(pss->hashAlgorithm);
    if (!md)
        goto err;

    if (pss->saltLength) {
        saltlen = ASN1_INTEGER_get(pss->saltLength);

        /*
         * Could perform more salt length sanity checks but the main RSA
         * routines will trap other invalid values anyway.
         */
        if (saltlen < 0) {
            goto err;
        }
    } else
        saltlen = 20;

    /*
     * low-level routines support only trailer field 0xbc (value 1) and
     * PKCS#1 says we should reject any other value anyway.
     */
    if (pss->trailerField && ASN1_INTEGER_get(pss->trailerField) != 1) {
        goto err;
    }

    /* We have all parameters now set up context */

    if (pkey) {
        if (!EVP_DigestVerifyInit(ctx, &pkctx, md, NULL, pkey))
            goto err;
    } else {
        const EVP_MD *checkmd;
        if (EVP_PKEY_CTX_get_signature_md(pkctx, &checkmd) <= 0)
            goto err;
        if (EVP_MD_type(md) != EVP_MD_type(checkmd)) {
            goto err;
        }
    }

    if (EVP_PKEY_CTX_set_rsa_padding(pkctx, RSA_PKCS1_PSS_PADDING) <= 0)
        goto err;

    if (EVP_PKEY_CTX_set_rsa_pss_saltlen(pkctx, saltlen) <= 0)
        goto err;

    if (EVP_PKEY_CTX_set_rsa_mgf1_md(pkctx, mgf1md) <= 0)
        goto err;
    /* Carry on */
    rv = 1;

 err:
    RSA_PSS_PARAMS_free(pss);
    if (maskHash)
        X509_ALGOR_free(maskHash);
    return rv;
}



static int rsa_cms_verify(CMS_SignerInfo *si)
{
    int nid, nid2;
    X509_ALGOR *alg;
    EVP_PKEY_CTX *pkctx = CMS_SignerInfo_get0_pkey_ctx(si);
    CMS_SignerInfo_get0_algs(si, NULL, NULL, NULL, &alg);
    nid = OBJ_obj2nid(alg->algorithm);
    if (nid == NID_rsaEncryption)
        return 1;
    if (nid == NID_rsassaPss)
        return rsa_pss_to_ctx(NULL, pkctx, alg, NULL);
    /* Workaround for some implementation that use a signature OID */
    if (OBJ_find_sigid_algs(nid, NULL, &nid2)) {
        if (nid2 == NID_rsaEncryption)
            return 1;
    }
    return 0;
}

static int rsa_cms_sign(CMS_SignerInfo *si)
{
    int pad_mode = RSA_PKCS1_PADDING;
    X509_ALGOR *alg;
    EVP_PKEY_CTX *pkctx = CMS_SignerInfo_get0_pkey_ctx(si);
    ASN1_STRING *os = NULL;
    CMS_SignerInfo_get0_algs(si, NULL, NULL, NULL, &alg);
    if (pkctx) {
        if (EVP_PKEY_CTX_get_rsa_padding(pkctx, &pad_mode) <= 0)
            return 0;
    }
    if (pad_mode == RSA_PKCS1_PADDING) {
        X509_ALGOR_set0(alg, OBJ_nid2obj(NID_rsaEncryption), V_ASN1_NULL, 0);
        return 1;
    }
    /* We don't support it */
    if (pad_mode != RSA_PKCS1_PSS_PADDING)
        return 0;
    os = rsa_ctx_to_pss(pkctx);
    if (!os)
        return 0;
    X509_ALGOR_set0(alg, OBJ_nid2obj(NID_rsassaPss), V_ASN1_SEQUENCE, os);
    return 1;
}

static int rsa_cms_decrypt(CMS_RecipientInfo *ri)
{
    EVP_PKEY_CTX *pkctx;
    X509_ALGOR *cmsalg;
    int nid;
    pkctx = CMS_RecipientInfo_get0_pkey_ctx(ri);
    if (!pkctx)
        return 0;
    if (!CMS_RecipientInfo_ktri_get0_algs(ri, NULL, NULL, &cmsalg))
        return -1;
    nid = OBJ_obj2nid(cmsalg->algorithm);
    if (nid == NID_rsaEncryption)
        return 1;
    return -1;
}

static int rsa_cms_encrypt(CMS_RecipientInfo *ri)
{
    X509_ALGOR *alg;
    EVP_PKEY_CTX *pkctx = CMS_RecipientInfo_get0_pkey_ctx(ri);
    int pad_mode = RSA_PKCS1_PADDING;
    CMS_RecipientInfo_ktri_get0_algs(ri, NULL, NULL, &alg);
    if (pkctx) {
        if (EVP_PKEY_CTX_get_rsa_padding(pkctx, &pad_mode) <= 0)
            return 0;
    }
    if (pad_mode == RSA_PKCS1_PADDING) {
        X509_ALGOR_set0(alg, OBJ_nid2obj(NID_rsaEncryption), V_ASN1_NULL, 0);
        return 1;
    }
    return 0;
}
