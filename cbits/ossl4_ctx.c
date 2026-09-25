/* Narrow OpenSSL 4 provider-only shim: private libctx lifecycle plus
 * typed fetch+run helpers. See ossl4_ctx.h for the contract.
 *
 * Provider-only API surface used here: OSSL_LIB_CTX_*, OSSL_PROVIDER_*,
 * EVP_MD_fetch, EVP_CIPHER_fetch, EVP_MAC_fetch, EVP_PKEY_* (CTX_new_from_name,
 * CTX_new_from_pkey, keygen, DigestSign/Verify, sign/verify, RSA padding
 * selection, get_octet_string_param), OSSL_PARAM, d2i/i2d
 * key codecs, RAND_bytes_ex (libctx DRBG), plus BIGNUM/ECDSA_SIG
 * helpers for the DER<->raw signature encoding conversion (encoding
 * only; no key operations). Banned and absent by construction:
 * ENGINE_*, *_meth_*, RSA_sign, AES_encrypt, EC_KEY_*,
 * OPENSSL_cleanup, OPENSSL_atexit.
 */

#include "ossl4_ctx.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/x509.h>
#include <openssl/provider.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/rsaerr.h>
#include <openssl/x509.h>

#define HSK_OSSL4_MAX_PROV 4

struct hsk_ossl4_md {
    EVP_MD_CTX *mctx;
    EVP_MD *md;
};

struct hsk_ossl4_env {
    OSSL_LIB_CTX *ctx;
    OSSL_PROVIDER *provs[HSK_OSSL4_MAX_PROV];
    size_t nprov;
};

/* --- private context lifecycle -------------------------------------- */

OSSL_LIB_CTX *hsk_ossl4_new_ctx(void)
{
    return OSSL_LIB_CTX_new();
}

OSSL_PROVIDER *hsk_ossl4_load_provider(OSSL_LIB_CTX *ctx, const char *name)
{
    if (ctx == NULL || name == NULL)
        return NULL;
    return OSSL_PROVIDER_load(ctx, name);
}

void hsk_ossl4_unload_provider(OSSL_PROVIDER *prov)
{
    if (prov != NULL)
        OSSL_PROVIDER_unload(prov);
}

void hsk_ossl4_free_ctx(OSSL_LIB_CTX *ctx)
{
    if (ctx != NULL)
        OSSL_LIB_CTX_free(ctx);
}

/* --- env wrapper ----------------------------------------------------- */

hsk_ossl4_env_t *hsk_ossl4_env_new(void)
{
    hsk_ossl4_env_t *env = OPENSSL_malloc(sizeof(*env));
    if (env == NULL)
        return NULL;
    env->ctx = hsk_ossl4_new_ctx();
    env->nprov = 0;
    if (env->ctx == NULL) {
        OPENSSL_free(env);
        return NULL;
    }
    return env;
}

int hsk_ossl4_env_load(hsk_ossl4_env_t *env, const char *name)
{
    OSSL_PROVIDER *prov;
    if (env == NULL || name == NULL || env->nprov >= HSK_OSSL4_MAX_PROV)
        return HSK_OSSL4_ERR_BADPARAM;
    prov = hsk_ossl4_load_provider(env->ctx, name);
    if (prov == NULL)
        return HSK_OSSL4_ERR_NATIVE;
    env->provs[env->nprov++] = prov;
    return HSK_OSSL4_OK;
}

OSSL_LIB_CTX *hsk_ossl4_env_ctx(const hsk_ossl4_env_t *env)
{
    if (env == NULL)
        return NULL;
    return env->ctx;
}

void hsk_ossl4_env_free(hsk_ossl4_env_t *env)
{
    size_t i;
    if (env == NULL)
        return;
    for (i = 0; i < env->nprov; i++)
        hsk_ossl4_unload_provider(env->provs[i]);
    hsk_ossl4_free_ctx(env->ctx);
    OPENSSL_free(env);
}

/* --- misc ------------------------------------------------------------ */

const char *hsk_ossl4_version(void)
{
    return OpenSSL_version(OPENSSL_VERSION_STRING);
}

void hsk_ossl4_free(void *ptr, size_t len)
{
    if (ptr != NULL)
        OPENSSL_clear_free(ptr, len);
}

size_t hsk_ossl4_last_error(char *buf, size_t buflen)
{
    unsigned long code;
    if (buf == NULL || buflen == 0) {
        ERR_clear_error();
        return 0;
    }
    code = ERR_get_error();
    if (code == 0) {
        buf[0] = '\0';
        return 0;
    }
    ERR_error_string_n(code, buf, buflen);
    ERR_clear_error();
    buf[buflen - 1] = '\0';
    return strlen(buf);
}

int hsk_ossl4_probe(OSSL_LIB_CTX *ctx, const char *kind, const char *name,
                    const char *propq)
{
    int ok = 0;
    if (ctx == NULL || kind == NULL || name == NULL || propq == NULL)
        return HSK_OSSL4_ERR_BADPARAM;
    if (strcmp(kind, "md") == 0) {
        EVP_MD *md = EVP_MD_fetch(ctx, name, propq);
        ok = (md != NULL);
        EVP_MD_free(md);
    } else if (strcmp(kind, "mac") == 0) {
        EVP_MAC *mac = EVP_MAC_fetch(ctx, name, propq);
        ok = (mac != NULL);
        EVP_MAC_free(mac);
    } else if (strcmp(kind, "cipher") == 0) {
        EVP_CIPHER *c = EVP_CIPHER_fetch(ctx, name, propq);
        ok = (c != NULL);
        EVP_CIPHER_free(c);
    } else if (strcmp(kind, "pkey") == 0) {
        EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_from_name(ctx, name, propq);
        ok = (pctx != NULL);
        EVP_PKEY_CTX_free(pctx);
    } else {
        return HSK_OSSL4_ERR_BADPARAM;
    }
    if (!ok)
        ERR_clear_error();
    return ok;
}

/* --- one-shot digest ------------------------------------------------- */

long hsk_ossl4_digest(OSSL_LIB_CTX *ctx, const char *mdname, const char *propq,
                      const unsigned char *msg, size_t msglen,
                      unsigned char **out)
{
    ERR_clear_error(); /* fresh queue; failures keep it for last_error */
    EVP_MD *md = NULL;
    EVP_MD_CTX *mctx = NULL;
    unsigned char *buf = NULL;
    unsigned int outlen = 0;
    long rc = HSK_OSSL4_ERR_NATIVE;

    if (ctx == NULL || mdname == NULL || propq == NULL || out == NULL ||
        (msg == NULL && msglen > 0))
        return HSK_OSSL4_ERR_BADPARAM;

    md = EVP_MD_fetch(ctx, mdname, propq);
    if (md == NULL)
        goto end;
    mctx = EVP_MD_CTX_new();
    if (mctx == NULL)
        goto end;
    if (!EVP_DigestInit_ex2(mctx, md, NULL))
        goto end;
    if (msglen > 0 && !EVP_DigestUpdate(mctx, msg, msglen))
        goto end;
    buf = OPENSSL_malloc(EVP_MAX_MD_SIZE);
    if (buf == NULL) {
        rc = HSK_OSSL4_ERR_NOMEM;
        goto end;
    }
    if (!EVP_DigestFinal_ex(mctx, buf, &outlen)) {
        OPENSSL_clear_free(buf, EVP_MAX_MD_SIZE);
        goto end;
    }
    *out = buf;
    rc = (long)outlen;

end:
    EVP_MD_CTX_free(mctx);
    EVP_MD_free(md);
    return rc;
}

/* --- multipart digest ------------------------------------------------ */

hsk_ossl4_md_t *hsk_ossl4_digest_init(OSSL_LIB_CTX *ctx, const char *mdname,
                                     const char *propq)
{
    ERR_clear_error(); /* fresh queue; failures keep it for last_error */
    hsk_ossl4_md_t *h = NULL;
    if (ctx == NULL || mdname == NULL || propq == NULL)
        return NULL;
    h = OPENSSL_malloc(sizeof(*h));
    if (h == NULL)
        return NULL;
    h->mctx = NULL;
    h->md = EVP_MD_fetch(ctx, mdname, propq);
    if (h->md == NULL)
        goto fail;
    h->mctx = EVP_MD_CTX_new();
    if (h->mctx == NULL)
        goto fail;
    if (!EVP_DigestInit_ex2(h->mctx, h->md, NULL))
        goto fail;
    return h;
fail:
    EVP_MD_CTX_free(h->mctx);
    EVP_MD_free(h->md);
    OPENSSL_free(h);
    return NULL;
}

int hsk_ossl4_digest_update(hsk_ossl4_md_t *h, const unsigned char *msg,
                            size_t msglen)
{
    ERR_clear_error(); /* fresh queue; failures keep it for last_error */
    if (h == NULL || (msg == NULL && msglen > 0))
        return HSK_OSSL4_ERR_BADPARAM;
    if (msglen > 0 && !EVP_DigestUpdate(h->mctx, msg, msglen))
        return HSK_OSSL4_ERR_NATIVE;
    return HSK_OSSL4_OK;
}

long hsk_ossl4_digest_final(hsk_ossl4_md_t *h, unsigned char **out)
{
    ERR_clear_error(); /* fresh queue; failures keep it for last_error */
    unsigned char *buf;
    unsigned int outlen = 0;
    long rc = HSK_OSSL4_ERR_NATIVE;
    if (h == NULL || out == NULL)
        return HSK_OSSL4_ERR_BADPARAM;
    buf = OPENSSL_malloc(EVP_MAX_MD_SIZE);
    if (buf == NULL)
        goto end;
    if (!EVP_DigestFinal_ex(h->mctx, buf, &outlen)) {
        OPENSSL_clear_free(buf, EVP_MAX_MD_SIZE);
        goto end;
    }
    *out = buf;
    rc = (long)outlen;
end:
    /* Final consumes the handle: digest contexts are single-shot. */
    hsk_ossl4_digest_free(h);
    return rc;
}

void hsk_ossl4_digest_free(hsk_ossl4_md_t *h)
{
    if (h == NULL)
        return;
    EVP_MD_CTX_free(h->mctx);
    EVP_MD_free(h->md);
    OPENSSL_clear_free(h, sizeof(*h));
}

/* --- HMAC ------------------------------------------------------------ */

long hsk_ossl4_hmac(OSSL_LIB_CTX *ctx, const char *mdname, const char *propq,
                    const unsigned char *key, size_t keylen,
                    const unsigned char *msg, size_t msglen,
                    unsigned char **out)
{
    ERR_clear_error(); /* fresh queue; failures keep it for last_error */
    EVP_MAC *mac = NULL;
    EVP_MAC_CTX *mctx = NULL;
    OSSL_PARAM params[2];
    unsigned char *buf = NULL;
    size_t outlen = 0;
    long rc = HSK_OSSL4_ERR_NATIVE;

    if (ctx == NULL || mdname == NULL || propq == NULL || out == NULL ||
        (key == NULL && keylen > 0) || (msg == NULL && msglen > 0))
        return HSK_OSSL4_ERR_BADPARAM;

    mac = EVP_MAC_fetch(ctx, "HMAC", propq);
    if (mac == NULL)
        goto end;
    mctx = EVP_MAC_CTX_new(mac);
    if (mctx == NULL)
        goto end;
    params[0] =
        OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST,
                                         (char *)mdname, 0);
    params[1] = OSSL_PARAM_construct_end();
    if (!EVP_MAC_init(mctx, key, keylen, params))
        goto end;
    if (msglen > 0 && !EVP_MAC_update(mctx, msg, msglen))
        goto end;
    buf = OPENSSL_malloc(EVP_MAX_MD_SIZE);
    if (buf == NULL) {
        rc = HSK_OSSL4_ERR_NOMEM;
        goto end;
    }
    outlen = EVP_MAX_MD_SIZE;
    if (!EVP_MAC_final(mctx, buf, &outlen, outlen)) {
        OPENSSL_clear_free(buf, EVP_MAX_MD_SIZE);
        goto end;
    }
    *out = buf;
    rc = (long)outlen;

end:
    EVP_MAC_CTX_free(mctx);
    EVP_MAC_free(mac);
    return rc;
}

/* --- AES-CBC without padding ----------------------------------------- */

long hsk_ossl4_cipher_cbc(OSSL_LIB_CTX *ctx, const char *ciphername,
                          const char *propq, int enc, const unsigned char *key,
                          size_t keylen, const unsigned char *iv, size_t ivlen,
                          const unsigned char *in, size_t inlen,
                          unsigned char **out)
{
    ERR_clear_error(); /* fresh queue; failures keep it for last_error */
    EVP_CIPHER *cipher = NULL;
    EVP_CIPHER_CTX *cctx = NULL;
    unsigned char *buf = NULL;
    int outl1 = 0, outl2 = 0;
    long rc = HSK_OSSL4_ERR_NATIVE;

    if (ctx == NULL || ciphername == NULL || propq == NULL || out == NULL ||
        key == NULL || iv == NULL || (in == NULL && inlen > 0))
        return HSK_OSSL4_ERR_BADPARAM;

    cipher = EVP_CIPHER_fetch(ctx, ciphername, propq);
    if (cipher == NULL)
        goto end;
    if (keylen != (size_t)EVP_CIPHER_get_key_length(cipher) ||
        ivlen != (size_t)EVP_CIPHER_get_iv_length(cipher)) {
        rc = HSK_OSSL4_ERR_BADPARAM;
        goto end;
    }
    if (inlen % (size_t)EVP_CIPHER_get_block_size(cipher) != 0) {
        rc = HSK_OSSL4_ERR_BADPARAM;
        goto end;
    }
    cctx = EVP_CIPHER_CTX_new();
    if (cctx == NULL)
        goto end;
    if (!EVP_CipherInit_ex2(cctx, cipher, key, iv, enc, NULL)) {
        rc = HSK_OSSL4_ERR_BADPARAM;
        goto end;
    }
    EVP_CIPHER_CTX_set_padding(cctx, 0);
    buf = OPENSSL_malloc(inlen > 0 ? inlen : 1);
    if (buf == NULL) {
        rc = HSK_OSSL4_ERR_NOMEM;
        goto end;
    }
    if (inlen > 0 && !EVP_CipherUpdate(cctx, buf, &outl1, in, (int)inlen))
        goto end;
    if (!EVP_CipherFinal_ex(cctx, buf + outl1, &outl2))
        goto end;
    *out = buf;
    rc = (long)(outl1 + outl2);

end:
    EVP_CIPHER_CTX_free(cctx);
    EVP_CIPHER_free(cipher);
    if (rc < 0 && buf != NULL)
        OPENSSL_clear_free(buf, inlen > 0 ? inlen : 1);
    return rc;
}

/* --- EC keygen -------------------------------------------------------- */

int hsk_ossl4_ec_gen(OSSL_LIB_CTX *ctx, const char *groupname,
                     const char *propq, unsigned char **priv_der,
                     size_t *priv_len, unsigned char **pub_der,
                     size_t *pub_len)
{
    ERR_clear_error(); /* fresh queue; failures keep it for last_error */
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *pkey = NULL;
    OSSL_PARAM params[2];
    unsigned char *priv = NULL, *pub = NULL;
    int privlen = 0, publen = 0;
    int rc = HSK_OSSL4_ERR_NATIVE;

    if (ctx == NULL || groupname == NULL || propq == NULL || priv_der == NULL ||
        priv_len == NULL || pub_der == NULL || pub_len == NULL)
        return HSK_OSSL4_ERR_BADPARAM;

    pctx = EVP_PKEY_CTX_new_from_name(ctx, "EC", propq);
    if (pctx == NULL)
        goto end;
    if (!EVP_PKEY_keygen_init(pctx))
        goto end;
    params[0] =
        OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME,
                                         (char *)groupname, 0);
    params[1] = OSSL_PARAM_construct_end();
    if (!EVP_PKEY_CTX_set_params(pctx, params)) {
        rc = HSK_OSSL4_ERR_BADPARAM;
        goto end;
    }
    if (!EVP_PKEY_generate(pctx, &pkey))
        goto end;
    privlen = i2d_PrivateKey(pkey, &priv);
    publen = i2d_PUBKEY(pkey, &pub);
    if (privlen <= 0 || publen <= 0) {
        OPENSSL_free(priv);
        OPENSSL_free(pub);
        goto end;
    }
    *priv_der = priv;
    *priv_len = (size_t)privlen;
    *pub_der = pub;
    *pub_len = (size_t)publen;
    rc = HSK_OSSL4_OK;

end:
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pctx);
    return rc;
}

/* --- RSA keygen ------------------------------------------------------- */

int hsk_ossl4_rsa_gen_keypair(OSSL_LIB_CTX *ctx, int bits,
                              const unsigned char *e_be, size_t e_len,
                              const char *propq, unsigned char **priv_der,
                              size_t *priv_len, unsigned char **pub_der,
                              size_t *pub_len)
{
    ERR_clear_error(); /* fresh queue; failures keep it for last_error */
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *pkey = NULL;
    OSSL_PARAM params[3];
    unsigned char *priv = NULL, *pub = NULL;
    int privlen = 0, publen = 0;
    int rc = HSK_OSSL4_ERR_NATIVE;

    if (ctx == NULL || e_be == NULL || e_len == 0 || e_len > 8 ||
        propq == NULL || priv_der == NULL || priv_len == NULL ||
        pub_der == NULL || pub_len == NULL)
        return HSK_OSSL4_ERR_BADPARAM;
    if (bits != 2048 && bits != 3072 && bits != 4096)
        return HSK_OSSL4_ERR_BADPARAM;
    if ((e_be[e_len - 1] & 1) == 0)
        return HSK_OSSL4_ERR_BADPARAM;

    pctx = EVP_PKEY_CTX_new_from_name(ctx, "RSA", propq);
    if (pctx == NULL)
        goto end;
    if (!EVP_PKEY_keygen_init(pctx))
        goto end;
    params[0] = OSSL_PARAM_construct_int(OSSL_PKEY_PARAM_RSA_BITS, &bits);
    params[1] = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_E,
                                        (unsigned char *)e_be, e_len);
    params[2] = OSSL_PARAM_construct_end();
    if (!EVP_PKEY_CTX_set_params(pctx, params)) {
        rc = HSK_OSSL4_ERR_BADPARAM;
        goto end;
    }
    if (!EVP_PKEY_generate(pctx, &pkey))
        goto end;
    /* PKCS#8 explicitly: i2d_PrivateKey prefers the traditional
     * (PKCS#1) encoding for RSA, but the house convention (and the
     * keygen stamping that parses these bytes) is PKCS#8. */
    {
        PKCS8_PRIV_KEY_INFO *p8 = EVP_PKEY2PKCS8(pkey);
        if (p8 == NULL)
            goto end;
        privlen = i2d_PKCS8_PRIV_KEY_INFO(p8, &priv);
        PKCS8_PRIV_KEY_INFO_free(p8);
    }
    publen = i2d_PUBKEY(pkey, &pub);
    if (privlen <= 0 || publen <= 0) {
        OPENSSL_free(priv);
        OPENSSL_free(pub);
        goto end;
    }
    *priv_der = priv;
    *priv_len = (size_t)privlen;
    *pub_der = pub;
    *pub_len = (size_t)publen;
    rc = HSK_OSSL4_OK;

end:
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pctx);
    return rc;
}

/* --- Random bytes ------------------------------------------------ */

long hsk_ossl4_rand_bytes(OSSL_LIB_CTX *ctx, size_t nbytes,
                          unsigned char **out)
{
    unsigned char *buf = NULL;

    ERR_clear_error(); /* fresh queue; failures keep it for last_error */
    if (ctx == NULL || out == NULL)
        return HSK_OSSL4_ERR_BADPARAM;
    if (nbytes < 1 || nbytes > 1048576)
        return HSK_OSSL4_ERR_BADPARAM;
    buf = OPENSSL_malloc(nbytes);
    if (buf == NULL)
        return HSK_OSSL4_ERR_NOMEM;
    if (RAND_bytes_ex(ctx, buf, nbytes, 0) != 1) {
        OPENSSL_clear_free(buf, nbytes);
        return HSK_OSSL4_ERR_NATIVE;
    }
    *out = buf;
    return (long)nbytes;
}

/* --- Random reseed -------------------------------------------------- */

/* The ONLY entropy estimate the seed path ever claims: 0.0. RAND_add
 * mixes additional input without replacing the DRBG state, and caller
 * bytes are never credited as entropy. Pinned by
 * tests/engine/OpenSSLSpec.hs (caseSeedEntropyHonesty). */
#define HSK_OSSL4_SEED_ENTROPY_ESTIMATE 0.0

long hsk_ossl4_rand_seed(OSSL_LIB_CTX *ctx, const unsigned char *seed,
                         size_t seedlen)
{
    ERR_clear_error(); /* fresh queue; failures keep it for last_error */
    if (ctx == NULL || (seed == NULL && seedlen != 0))
        return HSK_OSSL4_ERR_BADPARAM;
    if (seedlen > 1048576)
        return HSK_OSSL4_ERR_BADPARAM;
    if (seedlen == 0)
        return HSK_OSSL4_OK; /* vacuous seed: nothing to mix */
    RAND_add(seed, (int)seedlen, HSK_OSSL4_SEED_ENTROPY_ESTIMATE);
    return HSK_OSSL4_OK;
}

/* --- ECDSA sign/verify -------------------------------------------------- */

/* Decode one private key (PKCS#8 DER) or public key (SPKI DER) under the
 * private libctx. Returns NULL on bad DER, leaving the queue for
 * hsk_ossl4_last_error. */
static EVP_PKEY *hsk_ossl4_load_priv(OSSL_LIB_CTX *ctx, const char *propq,
                                     const unsigned char *der, size_t derlen)
{
    EVP_PKEY *pkey = NULL;
    const unsigned char *p = der;
    if (der == NULL || derlen == 0 || derlen > (size_t)INT_MAX)
        return NULL;
    /* PKCS#8 PrivateKeyInfo carries its algorithm OID; auto-detect it. */
    pkey = d2i_AutoPrivateKey_ex(NULL, &p, (long)derlen, ctx, propq);
    return pkey;
}

static EVP_PKEY *hsk_ossl4_load_pub(OSSL_LIB_CTX *ctx, const char *propq,
                                    const unsigned char *der, size_t derlen)
{
    EVP_PKEY *pkey = NULL;
    const unsigned char *p = der;
    if (der == NULL || derlen == 0 || derlen > (size_t)INT_MAX)
        return NULL;
    pkey = d2i_PUBKEY_ex(NULL, &p, (long)derlen, ctx, propq);
    return pkey;
}

/* Raw SEC1 peer fallback for ECDH: PKCS#11 carries the peer as a
 * bare point (0x04 || X || Y), not SPKI. Build the peer key from
 * the private key's group plus the point octets (fromdata checks
 * on-curve membership). Uncompressed form only; anything else is
 * NULL. Group name buffer fits every named curve. */
static EVP_PKEY *hsk_ossl4_load_raw_point(OSSL_LIB_CTX *ctx, const char *propq,
                                          EVP_PKEY *priv,
                                          const unsigned char *pt, size_t len)
{
    char group[64];
    size_t grouplen = 0;
    OSSL_PARAM params[3];
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *peer = NULL;

    if (pt == NULL || len < 3 || pt[0] != 0x04)
        return NULL;
    if (!EVP_PKEY_get_utf8_string_param(priv, OSSL_PKEY_PARAM_GROUP_NAME,
                                        group, sizeof(group), &grouplen))
        return NULL;
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME,
                                                 group, 0);
    params[1] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY,
                                                  (void *)pt, len);
    params[2] = OSSL_PARAM_construct_end();
    pctx = EVP_PKEY_CTX_new_from_name(ctx, "EC", propq);
    if (pctx == NULL)
        return NULL;
    if (EVP_PKEY_fromdata_init(pctx) <= 0
        || EVP_PKEY_fromdata(pctx, &peer, EVP_PKEY_PUBLIC_KEY, params) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return NULL;
    }
    EVP_PKEY_CTX_free(pctx);
    return peer;
}

/* Curve coordinate size in bytes from an EC key's encoded point
 * (0x04 || X || Y). Returns 1 on success, 0 otherwise. */
static int hsk_ossl4_ec_coordlen(EVP_PKEY *pkey, size_t *coordlen)
{
    unsigned char point[1 + 2 * 66]; /* 0x04 || X || Y, P-521 max */
    size_t pointlen = 0;

    if (!EVP_PKEY_get_octet_string_param(pkey,
                                         OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY,
                                         point, sizeof(point), &pointlen)
        || pointlen < 3 || point[0] != 0x04
        || ((pointlen - 1) % 2) != 0)
        return 0;
    *coordlen = (pointlen - 1) / 2;
    return 1;
}

long hsk_ossl4_ecdsa_sign(OSSL_LIB_CTX *ctx, const char *mdname,
                          const char *propq, const unsigned char *priv_der,
                          size_t priv_len, const unsigned char *msg,
                          size_t msglen, int want_raw, int no_hash,
                          unsigned char **out)
{
    ERR_clear_error(); /* fresh queue; failures keep it for last_error */
    EVP_PKEY *pkey = NULL;
    EVP_MD_CTX *mctx = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    unsigned char *der = NULL;
    size_t derlen = 0;
    long rc = HSK_OSSL4_ERR_NATIVE;

    if (ctx == NULL || propq == NULL || out == NULL ||
        (msg == NULL && msglen > 0) ||
        (no_hash != 0 && no_hash != 1) || (no_hash == 0 && mdname == NULL))
        return HSK_OSSL4_ERR_BADPARAM;

    pkey = hsk_ossl4_load_priv(ctx, propq, priv_der, priv_len);
    if (pkey == NULL)
        return HSK_OSSL4_ERR_BADKEY;
    if (no_hash) {
        /* Raw operation (CKM_ECDSA): sign the input directly with no
         * hashing; overlong input is a typed refusal. */
        size_t coordlen = 0;
        if (!hsk_ossl4_ec_coordlen(pkey, &coordlen) || msglen > coordlen) {
            rc = HSK_OSSL4_ERR_BADPARAM;
            goto end;
        }
        pctx = EVP_PKEY_CTX_new_from_pkey(ctx, pkey, propq);
        if (pctx == NULL)
            goto end;
        if (EVP_PKEY_sign_init(pctx) <= 0 ||
            EVP_PKEY_sign(pctx, NULL, &derlen, msg, msglen) <= 0)
            goto end;
        der = OPENSSL_malloc(derlen);
        if (der == NULL) {
            rc = HSK_OSSL4_ERR_NOMEM;
            goto end;
        }
        if (EVP_PKEY_sign(pctx, der, &derlen, msg, msglen) <= 0) {
            OPENSSL_clear_free(der, derlen);
            der = NULL;
            goto end;
        }
    } else {
        mctx = EVP_MD_CTX_new();
        if (mctx == NULL)
            goto end;
        /* OpenSSL 4 fetches the digest by name under libctx+propq here. */
        if (!EVP_DigestSignInit_ex(mctx, NULL, mdname, ctx, propq, pkey, NULL))
            goto end;
        if (!EVP_DigestSign(mctx, NULL, &derlen, msg, msglen))
            goto end;
        der = OPENSSL_malloc(derlen);
        if (der == NULL) {
            rc = HSK_OSSL4_ERR_NOMEM;
            goto end;
        }
        if (!EVP_DigestSign(mctx, der, &derlen, msg, msglen)) {
            OPENSSL_clear_free(der, derlen);
            der = NULL;
            goto end;
        }
    }
    if (!want_raw) {
        *out = der;
        rc = (long)derlen;
        der = NULL;
        goto end;
    }
    /* DER -> raw r||s: parse the ASN.1 signature, pad each scalar to
     * the curve coordinate size derived from the key's encoded point. */
    {
        const unsigned char *p = der;
        ECDSA_SIG *sig = d2i_ECDSA_SIG(NULL, &p, (long)derlen);
        const BIGNUM *r = NULL, *s = NULL;
        unsigned char *raw = NULL;
        unsigned char point[1 + 2 * 66]; /* 0x04 || X || Y, P-521 max */
        size_t pointlen = 0;
        size_t coordlen = 0;
        if (sig == NULL)
            goto end;
        ECDSA_SIG_get0(sig, &r, &s);
        if (!EVP_PKEY_get_octet_string_param(pkey,
                                             OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY,
                                             point, sizeof(point), &pointlen)
            || pointlen < 3 || point[0] != 0x04
            || ((pointlen - 1) % 2) != 0) {
            ECDSA_SIG_free(sig);
            goto end;
        }
        coordlen = (pointlen - 1) / 2;
        raw = OPENSSL_malloc(2 * coordlen);
        if (raw == NULL) {
            ECDSA_SIG_free(sig);
            rc = HSK_OSSL4_ERR_NOMEM;
            goto end;
        }
        if (BN_bn2binpad(r, raw, (int)coordlen) < 0 ||
            BN_bn2binpad(s, raw + coordlen, (int)coordlen) < 0) {
            OPENSSL_clear_free(raw, 2 * coordlen);
            ECDSA_SIG_free(sig);
            goto end;
        }
        ECDSA_SIG_free(sig);
        *out = raw;
        rc = (long)(2 * coordlen);
    }

end:
    if (der != NULL)
        OPENSSL_clear_free(der, derlen);
    EVP_PKEY_CTX_free(pctx);
    EVP_MD_CTX_free(mctx);
    EVP_PKEY_free(pkey);
    return rc;
}

int hsk_ossl4_ecdsa_verify(OSSL_LIB_CTX *ctx, const char *mdname,
                           const char *propq, const unsigned char *pub_der,
                           size_t pub_len, const unsigned char *msg,
                           size_t msglen, const unsigned char *sig,
                           size_t siglen, int is_raw, int no_hash)
{
    ERR_clear_error(); /* fresh queue; failures keep it for last_error */
    EVP_PKEY *pkey = NULL;
    EVP_MD_CTX *mctx = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    const unsigned char *der = NULL;
    size_t derlen = 0;
    unsigned char *conv = NULL; /* raw -> DER conversion buffer, if any */
    size_t convlen = 0;
    int rc = HSK_OSSL4_ERR_NATIVE;

    if (ctx == NULL || propq == NULL || sig == NULL ||
        (msg == NULL && msglen > 0) ||
        (no_hash != 0 && no_hash != 1) || (no_hash == 0 && mdname == NULL))
        return HSK_OSSL4_ERR_BADPARAM;

    pkey = hsk_ossl4_load_pub(ctx, propq, pub_der, pub_len);
    if (pkey == NULL)
        return HSK_OSSL4_ERR_BADKEY;
    if (no_hash) {
        /* Raw operation: overlong input is a typed refusal. */
        size_t coordlen = 0;
        if (!hsk_ossl4_ec_coordlen(pkey, &coordlen) || msglen > coordlen) {
            rc = HSK_OSSL4_ERR_BADPARAM;
            goto end;
        }
    } else {
        mctx = EVP_MD_CTX_new();
        if (mctx == NULL)
            goto end;
    }

    if (!is_raw) {
        /* Malformed DER can never verify: answer mismatch (0) without
         * calling the provider, so encoding errors surface as
         * authentication failures rather than native errors. */
        const unsigned char *q = sig;
        ECDSA_SIG *chk = NULL;
        if (siglen == 0 || siglen > (size_t)INT_MAX) {
            rc = HSK_OSSL4_ERR_BADPARAM;
            goto end;
        }
        chk = d2i_ECDSA_SIG(NULL, &q, (long)siglen);
        if (chk == NULL || (size_t)(q - sig) != siglen) {
            ECDSA_SIG_free(chk);
            ERR_clear_error();
            rc = 0;
            goto end;
        }
        ECDSA_SIG_free(chk);
        der = sig;
        derlen = siglen;
    } else {
        /* Raw r||s -> DER: split halves, range-check against the curve
         * order size, re-encode. Odd lengths can never be valid. */
        ECDSA_SIG *osig = NULL;
        BIGNUM *r = NULL, *s = NULL;
        unsigned char *p = NULL;
        int len;
        if (siglen == 0 || (siglen % 2) != 0) {
            rc = HSK_OSSL4_ERR_BADPARAM;
            goto end;
        }
        r = BN_bin2bn(sig, (int)(siglen / 2), NULL);
        s = BN_bin2bn(sig + siglen / 2, (int)(siglen / 2), NULL);
        osig = ECDSA_SIG_new();
        if (r == NULL || s == NULL || osig == NULL ||
            !ECDSA_SIG_set0(osig, r, s)) {
            BN_free(r);
            BN_free(s);
            ECDSA_SIG_free(osig);
            rc = HSK_OSSL4_ERR_BADPARAM;
            goto end;
        }
        r = s = NULL; /* owned by osig now */
        len = i2d_ECDSA_SIG(osig, NULL);
        if (len <= 0) {
            ECDSA_SIG_free(osig);
            goto end;
        }
        conv = OPENSSL_malloc((size_t)len);
        if (conv == NULL) {
            ECDSA_SIG_free(osig);
            rc = HSK_OSSL4_ERR_NOMEM;
            goto end;
        }
        p = conv;
        convlen = (size_t)len;
        if (i2d_ECDSA_SIG(osig, &p) != len) {
            ECDSA_SIG_free(osig);
            goto end;
        }
        ECDSA_SIG_free(osig);
        der = conv;
        derlen = convlen;
    }

    if (no_hash) {
        /* Raw operation (CKM_ECDSA): verify the input directly. */
        pctx = EVP_PKEY_CTX_new_from_pkey(ctx, pkey, propq);
        if (pctx == NULL)
            goto end;
        if (EVP_PKEY_verify_init(pctx) <= 0)
            goto end;
        rc = EVP_PKEY_verify(pctx, der, derlen, msg, msglen);
    } else {
        /* OpenSSL 4 fetches the digest by name under libctx+propq here. */
        if (!EVP_DigestVerifyInit_ex(mctx, NULL, mdname, ctx, propq, pkey, NULL))
            goto end;
        rc = EVP_DigestVerify(mctx, der, derlen, msg, msglen);
    }
    if (rc < 0) {
        /* Internal error (not a plain mismatch); keep the queue clean. */
        rc = HSK_OSSL4_ERR_NATIVE;
        goto end;
    }
    /* rc is 1 (valid) or 0 (bad signature) here. */
    ERR_clear_error();

end:
    if (conv != NULL)
        OPENSSL_clear_free(conv, convlen);
    EVP_PKEY_CTX_free(pctx);
    EVP_MD_CTX_free(mctx);
    EVP_PKEY_free(pkey);
    return rc;
}

/* --- ECDH agreement ------------------------------------------- */

long hsk_ossl4_ecdh_derive(OSSL_LIB_CTX *ctx, const char *propq,
                           const unsigned char *priv_der, size_t priv_len,
                           const unsigned char *peer_der, size_t peer_len,
                           int cofactor, unsigned char **out)
{
    ERR_clear_error(); /* fresh queue; failures keep it for last_error */
    EVP_PKEY *priv = NULL;
    EVP_PKEY *peer = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    unsigned char *secret = NULL;
    size_t secretlen = 0;
    long rc = HSK_OSSL4_ERR_NATIVE;

    if (ctx == NULL || propq == NULL || out == NULL ||
        (cofactor != 0 && cofactor != 1))
        return HSK_OSSL4_ERR_BADPARAM;

    priv = hsk_ossl4_load_priv(ctx, propq, priv_der, priv_len);
    if (priv == NULL)
        return HSK_OSSL4_ERR_BADKEY;
    peer = hsk_ossl4_load_pub(ctx, propq, peer_der, peer_len);
    if (peer == NULL) {
        /* Not SPKI: try the PKCS#11 raw-point form on the
         * private key's group. */
        ERR_clear_error();
        peer = hsk_ossl4_load_raw_point(ctx, propq, priv, peer_der, peer_len);
    }
    if (peer == NULL) {
        rc = HSK_OSSL4_ERR_BADKEY;
        goto end;
    }
    pctx = EVP_PKEY_CTX_new_from_pkey(ctx, priv, propq);
    if (pctx == NULL)
        goto end;
    if (EVP_PKEY_derive_init(pctx) <= 0)
        goto end;
    if (cofactor && EVP_PKEY_CTX_set_ecdh_cofactor_mode(pctx, 1) <= 0)
        goto end;
    /* A peer on another curve (or a non-EC peer) fails here: key
     * shape, not a native malfunction. */
    if (EVP_PKEY_derive_set_peer(pctx, peer) <= 0) {
        rc = HSK_OSSL4_ERR_BADKEY;
        goto end;
    }
    if (EVP_PKEY_derive(pctx, NULL, &secretlen) <= 0)
        goto end;
    secret = OPENSSL_malloc(secretlen);
    if (secret == NULL) {
        rc = HSK_OSSL4_ERR_NOMEM;
        goto end;
    }
    if (EVP_PKEY_derive(pctx, secret, &secretlen) <= 0) {
        OPENSSL_clear_free(secret, secretlen);
        secret = NULL;
        goto end;
    }
    *out = secret;
    rc = (long)secretlen;
    secret = NULL;

end:
    EVP_PKEY_CTX_free(pctx);
    EVP_PKEY_free(peer);
    EVP_PKEY_free(priv);
    return rc;
}

/* --- RSA PKCS#1 v1.5 sign/verify ------------------------------- */

long hsk_ossl4_rsa_sign(OSSL_LIB_CTX *ctx, const char *mdname,
                        const char *propq, const unsigned char *priv_der,
                        size_t priv_len, const unsigned char *msg,
                        size_t msglen, int raw, unsigned char **out)
{
    ERR_clear_error(); /* fresh queue; failures keep it for last_error */
    EVP_PKEY *pkey = NULL;
    EVP_MD_CTX *mctx = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    unsigned char *buf = NULL;
    size_t buflen = 0;
    long rc = HSK_OSSL4_ERR_NATIVE;

    if (ctx == NULL || propq == NULL || out == NULL ||
        (msg == NULL && msglen > 0) ||
        (raw != 0 && raw != 1) || (raw == 0 && mdname == NULL))
        return HSK_OSSL4_ERR_BADPARAM;

    pkey = hsk_ossl4_load_priv(ctx, propq, priv_der, priv_len);
    if (pkey == NULL)
        return HSK_OSSL4_ERR_BADKEY;

    if (raw == 0) {
        /* Hash-and-sign: the provider defaults RSA to PKCS#1 v1.5. */
        mctx = EVP_MD_CTX_new();
        if (mctx == NULL)
            goto end;
        if (!EVP_DigestSignInit_ex(mctx, NULL, mdname, ctx, propq, pkey, NULL))
            goto end;
        if (!EVP_DigestSign(mctx, NULL, &buflen, msg, msglen))
            goto end;
        buf = OPENSSL_malloc(buflen);
        if (buf == NULL) {
            rc = HSK_OSSL4_ERR_NOMEM;
            goto end;
        }
        if (!EVP_DigestSign(mctx, buf, &buflen, msg, msglen)) {
            OPENSSL_clear_free(buf, buflen);
            buf = NULL;
            goto end;
        }
    } else {
        /* Raw block-type-1 operation over the input (CKM_RSA_PKCS):
         * no hashing; the provider pads. */
        pctx = EVP_PKEY_CTX_new_from_pkey(ctx, pkey, propq);
        if (pctx == NULL)
            goto end;
        if (EVP_PKEY_sign_init(pctx) <= 0 ||
            EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PADDING) <= 0 ||
            EVP_PKEY_sign(pctx, NULL, &buflen, msg, msglen) <= 0)
            goto end;
        buf = OPENSSL_malloc(buflen);
        if (buf == NULL) {
            rc = HSK_OSSL4_ERR_NOMEM;
            goto end;
        }
        if (EVP_PKEY_sign(pctx, buf, &buflen, msg, msglen) <= 0) {
            OPENSSL_clear_free(buf, buflen);
            buf = NULL;
            goto end;
        }
    }
    *out = buf;
    buf = NULL;
    rc = (long)buflen;

end:
    if (buf != NULL)
        OPENSSL_clear_free(buf, buflen);
    EVP_PKEY_CTX_free(pctx);
    EVP_MD_CTX_free(mctx);
    EVP_PKEY_free(pkey);
    return rc;
}

int hsk_ossl4_rsa_verify(OSSL_LIB_CTX *ctx, const char *mdname,
                         const char *propq, const unsigned char *pub_der,
                         size_t pub_len, const unsigned char *msg,
                         size_t msglen, const unsigned char *sig,
                         size_t siglen, int raw)
{
    ERR_clear_error(); /* fresh queue; failures keep it for last_error */
    EVP_PKEY *pkey = NULL;
    EVP_MD_CTX *mctx = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    int rc = HSK_OSSL4_ERR_NATIVE;

    if (ctx == NULL || propq == NULL || sig == NULL ||
        (msg == NULL && msglen > 0) ||
        (raw != 0 && raw != 1) || (raw == 0 && mdname == NULL))
        return HSK_OSSL4_ERR_BADPARAM;

    pkey = hsk_ossl4_load_pub(ctx, propq, pub_der, pub_len);
    if (pkey == NULL)
        return HSK_OSSL4_ERR_BADKEY;

    if (raw == 0) {
        mctx = EVP_MD_CTX_new();
        if (mctx == NULL)
            goto end;
        if (!EVP_DigestVerifyInit_ex(mctx, NULL, mdname, ctx, propq, pkey, NULL))
            goto end;
        rc = EVP_DigestVerify(mctx, sig, siglen, msg, msglen);
    } else {
        pctx = EVP_PKEY_CTX_new_from_pkey(ctx, pkey, propq);
        if (pctx == NULL)
            goto end;
        if (EVP_PKEY_verify_init(pctx) <= 0 ||
            EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PADDING) <= 0)
            goto end;
        rc = EVP_PKEY_verify(pctx, sig, siglen, msg, msglen);
    }
    if (rc < 0) {
        /* Internal error (not a plain mismatch); keep the queue clean. */
        rc = HSK_OSSL4_ERR_NATIVE;
        goto end;
    }
    /* rc is 1 (valid) or 0 (bad signature) here. */
    ERR_clear_error();

end:
    EVP_PKEY_CTX_free(pctx);
    EVP_MD_CTX_free(mctx);
    EVP_PKEY_free(pkey);
    return rc;
}

/* --- RSA-PSS sign/verify --------------------------------------- */

/* Configure PSS padding on an initialized DigestSign/Verify md context:
 * fetch the MGF1 digest under libctx+propq, select PSS + salt length +
 * MGF. The md context owns pctx (freed by EVP_MD_CTX_free). */
static int hsk_ossl4_pss_params(OSSL_LIB_CTX *ctx, EVP_PKEY_CTX **pctx,
                                const char *mgfname, int saltlen,
                                const char *propq)
{
    EVP_MD *mgfmd = NULL;
    int ok = 0;

    if (saltlen < 0)
        return 0;
    mgfmd = EVP_MD_fetch(ctx, mgfname, propq);
    if (mgfmd == NULL)
        return 0;
    if (*pctx == NULL)
        goto end;
    ok = EVP_PKEY_CTX_set_rsa_padding(*pctx, RSA_PKCS1_PSS_PADDING) > 0 &&
        EVP_PKEY_CTX_set_rsa_pss_saltlen(*pctx, saltlen) > 0 &&
        EVP_PKEY_CTX_set_rsa_mgf1_md(*pctx, mgfmd) > 0;

end:
    EVP_MD_free(mgfmd);
    return ok;
}

long hsk_ossl4_rsa_pss_sign(OSSL_LIB_CTX *ctx, const char *mdname,
                            const char *mgfname, int saltlen,
                            const char *propq, const unsigned char *priv_der,
                            size_t priv_len, const unsigned char *msg,
                            size_t msglen, unsigned char **out)
{
    ERR_clear_error(); /* fresh queue; failures keep it for last_error */
    EVP_PKEY *pkey = NULL;
    EVP_MD_CTX *mctx = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    unsigned char *buf = NULL;
    size_t buflen = 0;
    long rc = HSK_OSSL4_ERR_NATIVE;

    if (ctx == NULL || mdname == NULL || mgfname == NULL || propq == NULL ||
        out == NULL || (msg == NULL && msglen > 0))
        return HSK_OSSL4_ERR_BADPARAM;

    pkey = hsk_ossl4_load_priv(ctx, propq, priv_der, priv_len);
    if (pkey == NULL)
        return HSK_OSSL4_ERR_BADKEY;
    mctx = EVP_MD_CTX_new();
    if (mctx == NULL)
        goto end;
    if (!EVP_DigestSignInit_ex(mctx, &pctx, mdname, ctx, propq, pkey, NULL))
        goto end;
    if (!hsk_ossl4_pss_params(ctx, &pctx, mgfname, saltlen, propq)) {
        rc = HSK_OSSL4_ERR_BADPARAM;
        goto end;
    }
    if (!EVP_DigestSign(mctx, NULL, &buflen, msg, msglen))
        goto end;
    buf = OPENSSL_malloc(buflen);
    if (buf == NULL) {
        rc = HSK_OSSL4_ERR_NOMEM;
        goto end;
    }
    if (!EVP_DigestSign(mctx, buf, &buflen, msg, msglen)) {
        OPENSSL_clear_free(buf, buflen);
        buf = NULL;
        goto end;
    }
    *out = buf;
    buf = NULL;
    rc = (long)buflen;

end:
    if (buf != NULL)
        OPENSSL_clear_free(buf, buflen);
    EVP_MD_CTX_free(mctx);
    EVP_PKEY_free(pkey);
    return rc;
}

int hsk_ossl4_rsa_pss_verify(OSSL_LIB_CTX *ctx, const char *mdname,
                             const char *mgfname, int saltlen,
                             const char *propq, const unsigned char *pub_der,
                             size_t pub_len, const unsigned char *msg,
                             size_t msglen, const unsigned char *sig,
                             size_t siglen)
{
    ERR_clear_error(); /* fresh queue; failures keep it for last_error */
    EVP_PKEY *pkey = NULL;
    EVP_MD_CTX *mctx = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    int rc = HSK_OSSL4_ERR_NATIVE;

    if (ctx == NULL || mdname == NULL || mgfname == NULL || propq == NULL ||
        sig == NULL || (msg == NULL && msglen > 0))
        return HSK_OSSL4_ERR_BADPARAM;

    pkey = hsk_ossl4_load_pub(ctx, propq, pub_der, pub_len);
    if (pkey == NULL)
        return HSK_OSSL4_ERR_BADKEY;
    mctx = EVP_MD_CTX_new();
    if (mctx == NULL)
        goto end;
    if (!EVP_DigestVerifyInit_ex(mctx, &pctx, mdname, ctx, propq, pkey, NULL))
        goto end;
    if (!hsk_ossl4_pss_params(ctx, &pctx, mgfname, saltlen, propq)) {
        rc = HSK_OSSL4_ERR_BADPARAM;
        goto end;
    }
    rc = EVP_DigestVerify(mctx, sig, siglen, msg, msglen);
    if (rc < 0) {
        /* Internal error (not a plain mismatch); keep the queue clean. */
        rc = HSK_OSSL4_ERR_NATIVE;
        goto end;
    }
    /* rc is 1 (valid) or 0 (bad signature) here. */
    ERR_clear_error();

end:
    EVP_MD_CTX_free(mctx);
    EVP_PKEY_free(pkey);
    return rc;
}

/* --- RSA-OAEP encrypt/decrypt ----------------------------------- */

/* A failed OAEP decrypt is a verdict (padding/label mismatch) unless
 * the queued reason says otherwise; internal errors stay native. */
static long hsk_ossl4_oaep_fail(void)
{
    unsigned long code = ERR_peek_error();
    int reason = ERR_GET_REASON(code);
    ERR_clear_error();
    if (reason == RSA_R_OAEP_DECODING_ERROR ||
        reason == RSA_R_BLOCK_TYPE_IS_NOT_01 ||
        reason == RSA_R_PKCS_DECODING_ERROR)
        return HSK_OSSL4_ERR_AUTHFAIL;
    return HSK_OSSL4_ERR_NATIVE;
}

/* Configure OAEP padding on an encrypt/decrypt pkey context: hash,
 * MGF1 digest, and the label (empty label when labellen is 0). The
 * label travels as an OSSL_PARAM octet string (copied by the
 * provider; no ownership questions). */
static int hsk_ossl4_oaep_params(EVP_PKEY_CTX *pctx, EVP_MD *md, EVP_MD *mgfmd,
                                 const unsigned char *label, size_t labellen)
{
    OSSL_PARAM params[2];

    if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_OAEP_PADDING) <= 0 ||
        EVP_PKEY_CTX_set_rsa_oaep_md(pctx, md) <= 0 ||
        EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, mgfmd) <= 0)
        return 0;
    if (labellen == 0)
        return 1;
    params[0] = OSSL_PARAM_construct_octet_string(
        OSSL_ASYM_CIPHER_PARAM_OAEP_LABEL, (void *)label, labellen);
    params[1] = OSSL_PARAM_construct_end();
    return EVP_PKEY_CTX_set_params(pctx, params) > 0;
}

long hsk_ossl4_rsa_oaep_encrypt(OSSL_LIB_CTX *ctx, const char *mdname,
                               const char *mgfname,
                               const unsigned char *label, size_t labellen,
                               const char *propq, const unsigned char *pub_der,
                               size_t pub_len, const unsigned char *in,
                               size_t inlen, unsigned char **out)
{
    ERR_clear_error(); /* fresh queue; failures keep it for last_error */
    EVP_PKEY *pkey = NULL;
    EVP_MD *md = NULL;
    EVP_MD *mgfmd = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    unsigned char *buf = NULL;
    size_t buflen = 0;
    size_t hlen;
    size_t k;
    int ksize;
    int mdsize;
    long rc = HSK_OSSL4_ERR_NATIVE;

    if (ctx == NULL || mdname == NULL || mgfname == NULL || propq == NULL ||
        out == NULL || (in == NULL && inlen > 0) ||
        (label == NULL && labellen > 0))
        return HSK_OSSL4_ERR_BADPARAM;

    pkey = hsk_ossl4_load_pub(ctx, propq, pub_der, pub_len);
    if (pkey == NULL)
        return HSK_OSSL4_ERR_BADKEY;
    md = EVP_MD_fetch(ctx, mdname, propq);
    mgfmd = EVP_MD_fetch(ctx, mgfname, propq);
    if (md == NULL || mgfmd == NULL) {
        rc = HSK_OSSL4_ERR_BADPARAM;
        goto end;
    }
    /* Typed input bound: mLen <= k - 2*hLen - 2. */
    ksize = EVP_PKEY_get_size(pkey);
    mdsize = EVP_MD_get_size(md);
    if (ksize <= 0 || mdsize <= 0) {
        rc = HSK_OSSL4_ERR_BADPARAM;
        goto end;
    }
    k = (size_t)ksize;
    hlen = (size_t)mdsize;
    if (k <= 2 * hlen + 2 || inlen > k - 2 * hlen - 2) {
        rc = HSK_OSSL4_ERR_BADPARAM;
        goto end;
    }
    pctx = EVP_PKEY_CTX_new_from_pkey(ctx, pkey, propq);
    if (pctx == NULL)
        goto end;
    if (EVP_PKEY_encrypt_init(pctx) <= 0 ||
        !hsk_ossl4_oaep_params(pctx, md, mgfmd, label, labellen) ||
        EVP_PKEY_encrypt(pctx, NULL, &buflen, in, inlen) <= 0)
        goto end;
    buf = OPENSSL_malloc(buflen);
    if (buf == NULL) {
        rc = HSK_OSSL4_ERR_NOMEM;
        goto end;
    }
    if (EVP_PKEY_encrypt(pctx, buf, &buflen, in, inlen) <= 0) {
        OPENSSL_clear_free(buf, buflen);
        buf = NULL;
        goto end;
    }
    *out = buf;
    buf = NULL;
    rc = (long)buflen;

end:
    if (buf != NULL)
        OPENSSL_clear_free(buf, buflen);
    EVP_PKEY_CTX_free(pctx);
    EVP_MD_free(mgfmd);
    EVP_MD_free(md);
    EVP_PKEY_free(pkey);
    return rc;
}

long hsk_ossl4_rsa_oaep_decrypt(OSSL_LIB_CTX *ctx, const char *mdname,
                               const char *mgfname,
                               const unsigned char *label, size_t labellen,
                               const char *propq, const unsigned char *priv_der,
                               size_t priv_len, const unsigned char *in,
                               size_t inlen, unsigned char **out)
{
    ERR_clear_error(); /* fresh queue; failures keep it for last_error */
    EVP_PKEY *pkey = NULL;
    EVP_MD *md = NULL;
    EVP_MD *mgfmd = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    unsigned char *buf = NULL;
    size_t buflen = 0;
    long rc = HSK_OSSL4_ERR_NATIVE;

    if (ctx == NULL || mdname == NULL || mgfname == NULL || propq == NULL ||
        out == NULL || (in == NULL && inlen > 0) ||
        (label == NULL && labellen > 0))
        return HSK_OSSL4_ERR_BADPARAM;

    pkey = hsk_ossl4_load_priv(ctx, propq, priv_der, priv_len);
    if (pkey == NULL)
        return HSK_OSSL4_ERR_BADKEY;
    /* OAEP ciphertexts are exactly one modulus wide; anything else
     * is a typed length refusal, never a padding verdict. */
    if (inlen != (size_t)EVP_PKEY_get_size(pkey)) {
        rc = HSK_OSSL4_ERR_BADPARAM;
        goto end;
    }
    md = EVP_MD_fetch(ctx, mdname, propq);
    mgfmd = EVP_MD_fetch(ctx, mgfname, propq);
    if (md == NULL || mgfmd == NULL) {
        rc = HSK_OSSL4_ERR_BADPARAM;
        goto end;
    }
    pctx = EVP_PKEY_CTX_new_from_pkey(ctx, pkey, propq);
    if (pctx == NULL)
        goto end;
    if (EVP_PKEY_decrypt_init(pctx) <= 0 ||
        !hsk_ossl4_oaep_params(pctx, md, mgfmd, label, labellen)) {
        rc = HSK_OSSL4_ERR_BADPARAM;
        goto end;
    }
    if (EVP_PKEY_decrypt(pctx, NULL, &buflen, in, inlen) <= 0) {
        rc = hsk_ossl4_oaep_fail();
        goto end;
    }
    buf = OPENSSL_malloc(buflen > 0 ? buflen : 1);
    if (buf == NULL) {
        rc = HSK_OSSL4_ERR_NOMEM;
        goto end;
    }
    if (EVP_PKEY_decrypt(pctx, buf, &buflen, in, inlen) <= 0) {
        OPENSSL_clear_free(buf, buflen > 0 ? buflen : 1);
        buf = NULL;
        rc = hsk_ossl4_oaep_fail();
        goto end;
    }
    *out = buf;
    buf = NULL;
    rc = (long)buflen;

end:
    if (buf != NULL)
        OPENSSL_clear_free(buf, buflen > 0 ? buflen : 1);
    EVP_PKEY_CTX_free(pctx);
    EVP_MD_free(mgfmd);
    EVP_MD_free(md);
    EVP_PKEY_free(pkey);
    return rc;
}