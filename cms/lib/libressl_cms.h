/* ====================================================================
 * Copyright (c) 2008 The OpenSSL Project.  All rights reserved.
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
 */

#include <openssl/opensslconf.h>

/* this is defined too late here but work */
#undef OPENSSL_NO_CMS

/* ... */
typedef ssize_t ossl_ssize_t;
typedef size_t ossl_size_t;

/* safestack.h */
#define sk_CMS_CertificateChoices_deep_copy(st, copy_func, free_func) SKM_sk_deep_copy(CMS_CertificateChoices, (st), (copy_func), (free_func))
#define sk_CMS_CertificateChoices_delete(st, i) SKM_sk_delete(CMS_CertificateChoices, (st), (i))
#define sk_CMS_CertificateChoices_delete_ptr(st, ptr) SKM_sk_delete_ptr(CMS_CertificateChoices, (st), (ptr))
#define sk_CMS_CertificateChoices_dup(st) SKM_sk_dup(CMS_CertificateChoices, st)
#define sk_CMS_CertificateChoices_find(st, val) SKM_sk_find(CMS_CertificateChoices, (st), (val))
#define sk_CMS_CertificateChoices_find_ex(st, val) SKM_sk_find_ex(CMS_CertificateChoices, (st), (val))
#define sk_CMS_CertificateChoices_free(st) SKM_sk_free(CMS_CertificateChoices, (st))
#define sk_CMS_CertificateChoices_insert(st, val, i) SKM_sk_insert(CMS_CertificateChoices, (st), (val), (i))
#define sk_CMS_CertificateChoices_is_sorted(st) SKM_sk_is_sorted(CMS_CertificateChoices, (st))
#define sk_CMS_CertificateChoices_new(cmp) SKM_sk_new(CMS_CertificateChoices, (cmp))
#define sk_CMS_CertificateChoices_new_null() SKM_sk_new_null(CMS_CertificateChoices)
#define sk_CMS_CertificateChoices_num(st) SKM_sk_num(CMS_CertificateChoices, (st))
#define sk_CMS_CertificateChoices_pop(st) SKM_sk_pop(CMS_CertificateChoices, (st))
#define sk_CMS_CertificateChoices_pop_free(st, free_func) SKM_sk_pop_free(CMS_CertificateChoices, (st), (free_func))
#define sk_CMS_CertificateChoices_push(st, val) SKM_sk_push(CMS_CertificateChoices, (st), (val))
#define sk_CMS_CertificateChoices_set(st, i, val) SKM_sk_set(CMS_CertificateChoices, (st), (i), (val))
#define sk_CMS_CertificateChoices_set_cmp_func(st, cmp) SKM_sk_set_cmp_func(CMS_CertificateChoices, (st), (cmp))
#define sk_CMS_CertificateChoices_shift(st) SKM_sk_shift(CMS_CertificateChoices, (st))
#define sk_CMS_CertificateChoices_sort(st) SKM_sk_sort(CMS_CertificateChoices, (st))
#define sk_CMS_CertificateChoices_unshift(st, val) SKM_sk_unshift(CMS_CertificateChoices, (st), (val))
#define sk_CMS_CertificateChoices_value(st, i) SKM_sk_value(CMS_CertificateChoices, (st), (i))
#define sk_CMS_CertificateChoices_zero(st) SKM_sk_zero(CMS_CertificateChoices, (st))
#define sk_CMS_RecipientEncryptedKey_deep_copy(st, copy_func, free_func) SKM_sk_deep_copy(CMS_RecipientEncryptedKey, (st), (copy_func), (free_func))
#define sk_CMS_RecipientEncryptedKey_delete(st, i) SKM_sk_delete(CMS_RecipientEncryptedKey, (st), (i))
#define sk_CMS_RecipientEncryptedKey_delete_ptr(st, ptr) SKM_sk_delete_ptr(CMS_RecipientEncryptedKey, (st), (ptr))
#define sk_CMS_RecipientEncryptedKey_dup(st) SKM_sk_dup(CMS_RecipientEncryptedKey, st)
#define sk_CMS_RecipientEncryptedKey_find(st, val) SKM_sk_find(CMS_RecipientEncryptedKey, (st), (val))
#define sk_CMS_RecipientEncryptedKey_find_ex(st, val) SKM_sk_find_ex(CMS_RecipientEncryptedKey, (st), (val))
#define sk_CMS_RecipientEncryptedKey_free(st) SKM_sk_free(CMS_RecipientEncryptedKey, (st))
#define sk_CMS_RecipientEncryptedKey_insert(st, val, i) SKM_sk_insert(CMS_RecipientEncryptedKey, (st), (val), (i))
#define sk_CMS_RecipientEncryptedKey_is_sorted(st) SKM_sk_is_sorted(CMS_RecipientEncryptedKey, (st))
#define sk_CMS_RecipientEncryptedKey_new(cmp) SKM_sk_new(CMS_RecipientEncryptedKey, (cmp))
#define sk_CMS_RecipientEncryptedKey_new_null() SKM_sk_new_null(CMS_RecipientEncryptedKey)
#define sk_CMS_RecipientEncryptedKey_num(st) SKM_sk_num(CMS_RecipientEncryptedKey, (st))
#define sk_CMS_RecipientEncryptedKey_pop(st) SKM_sk_pop(CMS_RecipientEncryptedKey, (st))
#define sk_CMS_RecipientEncryptedKey_pop_free(st, free_func) SKM_sk_pop_free(CMS_RecipientEncryptedKey, (st), (free_func))
#define sk_CMS_RecipientEncryptedKey_push(st, val) SKM_sk_push(CMS_RecipientEncryptedKey, (st), (val))
#define sk_CMS_RecipientEncryptedKey_set(st, i, val) SKM_sk_set(CMS_RecipientEncryptedKey, (st), (i), (val))
#define sk_CMS_RecipientEncryptedKey_set_cmp_func(st, cmp) SKM_sk_set_cmp_func(CMS_RecipientEncryptedKey, (st), (cmp))
#define sk_CMS_RecipientEncryptedKey_shift(st) SKM_sk_shift(CMS_RecipientEncryptedKey, (st))
#define sk_CMS_RecipientEncryptedKey_sort(st) SKM_sk_sort(CMS_RecipientEncryptedKey, (st))
#define sk_CMS_RecipientEncryptedKey_unshift(st, val) SKM_sk_unshift(CMS_RecipientEncryptedKey, (st), (val))
#define sk_CMS_RecipientEncryptedKey_value(st, i) SKM_sk_value(CMS_RecipientEncryptedKey, (st), (i))
#define sk_CMS_RecipientEncryptedKey_zero(st) SKM_sk_zero(CMS_RecipientEncryptedKey, (st))
#define sk_CMS_RecipientInfo_deep_copy(st, copy_func, free_func) SKM_sk_deep_copy(CMS_RecipientInfo, (st), (copy_func), (free_func))
#define sk_CMS_RecipientInfo_delete(st, i) SKM_sk_delete(CMS_RecipientInfo, (st), (i))
#define sk_CMS_RecipientInfo_delete_ptr(st, ptr) SKM_sk_delete_ptr(CMS_RecipientInfo, (st), (ptr))
#define sk_CMS_RecipientInfo_dup(st) SKM_sk_dup(CMS_RecipientInfo, st)
#define sk_CMS_RecipientInfo_find(st, val) SKM_sk_find(CMS_RecipientInfo, (st), (val))
#define sk_CMS_RecipientInfo_find_ex(st, val) SKM_sk_find_ex(CMS_RecipientInfo, (st), (val))
#define sk_CMS_RecipientInfo_free(st) SKM_sk_free(CMS_RecipientInfo, (st))
#define sk_CMS_RecipientInfo_insert(st, val, i) SKM_sk_insert(CMS_RecipientInfo, (st), (val), (i))
#define sk_CMS_RecipientInfo_is_sorted(st) SKM_sk_is_sorted(CMS_RecipientInfo, (st))
#define sk_CMS_RecipientInfo_new(cmp) SKM_sk_new(CMS_RecipientInfo, (cmp))
#define sk_CMS_RecipientInfo_new_null() SKM_sk_new_null(CMS_RecipientInfo)
#define sk_CMS_RecipientInfo_num(st) SKM_sk_num(CMS_RecipientInfo, (st))
#define sk_CMS_RecipientInfo_pop(st) SKM_sk_pop(CMS_RecipientInfo, (st))
#define sk_CMS_RecipientInfo_pop_free(st, free_func) SKM_sk_pop_free(CMS_RecipientInfo, (st), (free_func))
#define sk_CMS_RecipientInfo_push(st, val) SKM_sk_push(CMS_RecipientInfo, (st), (val))
#define sk_CMS_RecipientInfo_set(st, i, val) SKM_sk_set(CMS_RecipientInfo, (st), (i), (val))
#define sk_CMS_RecipientInfo_set_cmp_func(st, cmp) SKM_sk_set_cmp_func(CMS_RecipientInfo, (st), (cmp))
#define sk_CMS_RecipientInfo_shift(st) SKM_sk_shift(CMS_RecipientInfo, (st))
#define sk_CMS_RecipientInfo_sort(st) SKM_sk_sort(CMS_RecipientInfo, (st))
#define sk_CMS_RecipientInfo_unshift(st, val) SKM_sk_unshift(CMS_RecipientInfo, (st), (val))
#define sk_CMS_RecipientInfo_value(st, i) SKM_sk_value(CMS_RecipientInfo, (st), (i))
#define sk_CMS_RecipientInfo_zero(st) SKM_sk_zero(CMS_RecipientInfo, (st))
#define sk_CMS_RevocationInfoChoice_deep_copy(st, copy_func, free_func) SKM_sk_deep_copy(CMS_RevocationInfoChoice, (st), (copy_func), (free_func))
#define sk_CMS_RevocationInfoChoice_delete(st, i) SKM_sk_delete(CMS_RevocationInfoChoice, (st), (i))
#define sk_CMS_RevocationInfoChoice_delete_ptr(st, ptr) SKM_sk_delete_ptr(CMS_RevocationInfoChoice, (st), (ptr))
#define sk_CMS_RevocationInfoChoice_dup(st) SKM_sk_dup(CMS_RevocationInfoChoice, st)
#define sk_CMS_RevocationInfoChoice_find(st, val) SKM_sk_find(CMS_RevocationInfoChoice, (st), (val))
#define sk_CMS_RevocationInfoChoice_find_ex(st, val) SKM_sk_find_ex(CMS_RevocationInfoChoice, (st), (val))
#define sk_CMS_RevocationInfoChoice_free(st) SKM_sk_free(CMS_RevocationInfoChoice, (st))
#define sk_CMS_RevocationInfoChoice_insert(st, val, i) SKM_sk_insert(CMS_RevocationInfoChoice, (st), (val), (i))
#define sk_CMS_RevocationInfoChoice_is_sorted(st) SKM_sk_is_sorted(CMS_RevocationInfoChoice, (st))
#define sk_CMS_RevocationInfoChoice_new(cmp) SKM_sk_new(CMS_RevocationInfoChoice, (cmp))
#define sk_CMS_RevocationInfoChoice_new_null() SKM_sk_new_null(CMS_RevocationInfoChoice)
#define sk_CMS_RevocationInfoChoice_num(st) SKM_sk_num(CMS_RevocationInfoChoice, (st))
#define sk_CMS_RevocationInfoChoice_pop(st) SKM_sk_pop(CMS_RevocationInfoChoice, (st))
#define sk_CMS_RevocationInfoChoice_pop_free(st, free_func) SKM_sk_pop_free(CMS_RevocationInfoChoice, (st), (free_func))
#define sk_CMS_RevocationInfoChoice_push(st, val) SKM_sk_push(CMS_RevocationInfoChoice, (st), (val))
#define sk_CMS_RevocationInfoChoice_set(st, i, val) SKM_sk_set(CMS_RevocationInfoChoice, (st), (i), (val))
#define sk_CMS_RevocationInfoChoice_set_cmp_func(st, cmp) SKM_sk_set_cmp_func(CMS_RevocationInfoChoice, (st), (cmp))
#define sk_CMS_RevocationInfoChoice_shift(st) SKM_sk_shift(CMS_RevocationInfoChoice, (st))
#define sk_CMS_RevocationInfoChoice_sort(st) SKM_sk_sort(CMS_RevocationInfoChoice, (st))
#define sk_CMS_RevocationInfoChoice_unshift(st, val) SKM_sk_unshift(CMS_RevocationInfoChoice, (st), (val))
#define sk_CMS_RevocationInfoChoice_value(st, i) SKM_sk_value(CMS_RevocationInfoChoice, (st), (i))
#define sk_CMS_RevocationInfoChoice_zero(st) SKM_sk_zero(CMS_RevocationInfoChoice, (st))
#define sk_CMS_SignerInfo_deep_copy(st, copy_func, free_func) SKM_sk_deep_copy(CMS_SignerInfo, (st), (copy_func), (free_func))
#define sk_CMS_SignerInfo_delete(st, i) SKM_sk_delete(CMS_SignerInfo, (st), (i))
#define sk_CMS_SignerInfo_delete_ptr(st, ptr) SKM_sk_delete_ptr(CMS_SignerInfo, (st), (ptr))
#define sk_CMS_SignerInfo_dup(st) SKM_sk_dup(CMS_SignerInfo, st)
#define sk_CMS_SignerInfo_find(st, val) SKM_sk_find(CMS_SignerInfo, (st), (val))
#define sk_CMS_SignerInfo_find_ex(st, val) SKM_sk_find_ex(CMS_SignerInfo, (st), (val))
#define sk_CMS_SignerInfo_free(st) SKM_sk_free(CMS_SignerInfo, (st))
#define sk_CMS_SignerInfo_insert(st, val, i) SKM_sk_insert(CMS_SignerInfo, (st), (val), (i))
#define sk_CMS_SignerInfo_is_sorted(st) SKM_sk_is_sorted(CMS_SignerInfo, (st))
#define sk_CMS_SignerInfo_new(cmp) SKM_sk_new(CMS_SignerInfo, (cmp))
#define sk_CMS_SignerInfo_new_null() SKM_sk_new_null(CMS_SignerInfo)
#define sk_CMS_SignerInfo_num(st) SKM_sk_num(CMS_SignerInfo, (st))
#define sk_CMS_SignerInfo_pop(st) SKM_sk_pop(CMS_SignerInfo, (st))
#define sk_CMS_SignerInfo_pop_free(st, free_func) SKM_sk_pop_free(CMS_SignerInfo, (st), (free_func))
#define sk_CMS_SignerInfo_push(st, val) SKM_sk_push(CMS_SignerInfo, (st), (val))
#define sk_CMS_SignerInfo_set(st, i, val) SKM_sk_set(CMS_SignerInfo, (st), (i), (val))
#define sk_CMS_SignerInfo_set_cmp_func(st, cmp) SKM_sk_set_cmp_func(CMS_SignerInfo, (st), (cmp))
#define sk_CMS_SignerInfo_shift(st) SKM_sk_shift(CMS_SignerInfo, (st))
#define sk_CMS_SignerInfo_sort(st) SKM_sk_sort(CMS_SignerInfo, (st))
#define sk_CMS_SignerInfo_unshift(st, val) SKM_sk_unshift(CMS_SignerInfo, (st), (val))
#define sk_CMS_SignerInfo_value(st, i) SKM_sk_value(CMS_SignerInfo, (st), (i))
#define sk_CMS_SignerInfo_zero(st) SKM_sk_zero(CMS_SignerInfo, (st))
