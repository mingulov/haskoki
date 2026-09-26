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
#include <openssl/decoder.h>
#include <openssl/dsa.h>
#include <openssl/ec.h>
#include <openssl/ecerr.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/x509.h>
#include <openssl/provider.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/rsa.h>
#include <openssl/rsaerr.h>
#include <openssl/x509.h>

#define HSK_OSSL4_MAX_PROV 4

/* Largest EC coordinate width over the covered curves (sect571, 72
 * bytes; P-521's 66 no longer the max). Uncompressed-point scratch
 * buffers derive from this. */
#define HSK_OSSL4_EC_MAX_COORD 72

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

/* --- AES key wrap (RFC 3394 KW / RFC 5649 KWP) ------------------------ */

long hsk_ossl4_cipher_wrap(OSSL_LIB_CTX *ctx, const char *ciphername,
                           const char *propq, int enc, int kwp,
                           const unsigned char *key, size_t keylen,
                           const unsigned char *in, size_t inlen,
                           unsigned char **out)
{
    ERR_clear_error(); /* fresh queue; failures keep it for last_error */
    EVP_CIPHER *cipher = NULL;
    EVP_CIPHER_CTX *cctx = NULL;
    unsigned char *buf = NULL;
    size_t cap = 0;
    int outl1 = 0, outl2 = 0;
    long rc = HSK_OSSL4_ERR_NATIVE;

    if (ctx == NULL || ciphername == NULL || propq == NULL || out == NULL ||
        key == NULL || (in == NULL && inlen > 0))
        return HSK_OSSL4_ERR_BADPARAM;

    cipher = EVP_CIPHER_fetch(ctx, ciphername, propq);
    if (cipher == NULL)
        goto end;
    if (keylen != (size_t)EVP_CIPHER_get_key_length(cipher)) {
        rc = HSK_OSSL4_ERR_BADPARAM;
        goto end;
    }
    if (kwp) {
        if (inlen == 0) {
            rc = HSK_OSSL4_ERR_BADPARAM;
            goto end;
        }
    } else {
        if (inlen < 16 || inlen % 8 != 0) {
            rc = HSK_OSSL4_ERR_BADPARAM;
            goto end;
        }
    }
    cctx = EVP_CIPHER_CTX_new();
    if (cctx == NULL)
        goto end;
    /* Direction-specific init (probe record: NULL IV works; wraps
     * use the fixed AIV). Padding disabled: KW/KWP frame the
     * input themselves. */
    if (enc) {
        if (!EVP_EncryptInit_ex(cctx, cipher, NULL, key, NULL)) {
            rc = HSK_OSSL4_ERR_BADPARAM;
            goto end;
        }
    } else {
        if (!EVP_DecryptInit_ex(cctx, cipher, NULL, key, NULL)) {
            rc = HSK_OSSL4_ERR_BADPARAM;
            goto end;
        }
    }
    EVP_CIPHER_CTX_set_padding(cctx, 0);
    /* KW emits inlen + 8; KWP emits ceil8(inlen) + 8 (<= inlen + 15). */
    cap = inlen + 16;
    buf = OPENSSL_malloc(cap);
    if (buf == NULL) {
        rc = HSK_OSSL4_ERR_NOMEM;
        goto end;
    }
    if (enc) {
        if (!EVP_EncryptUpdate(cctx, buf, &outl1, in, (int)inlen))
            goto end;
        if (!EVP_EncryptFinal_ex(cctx, buf + outl1, &outl2))
            goto end;
    } else {
        /* Integrity failures surface at Update for wraps (probe
         * record); either way a decrypt-side EVP failure is an
         * authentication failure, never wrong plaintext. */
        if (!EVP_DecryptUpdate(cctx, buf, &outl1, in, (int)inlen)) {
            rc = HSK_OSSL4_ERR_AUTHFAIL;
            goto end;
        }
        if (!EVP_DecryptFinal_ex(cctx, buf + outl1, &outl2)) {
            rc = HSK_OSSL4_ERR_AUTHFAIL;
            goto end;
        }
    }
    *out = buf;
    rc = (long)(outl1 + outl2);

end:
    EVP_CIPHER_CTX_free(cctx);
    EVP_CIPHER_free(cipher);
    if (rc < 0 && buf != NULL)
        OPENSSL_clear_free(buf, cap);
    return rc;
}

/* --- AES-XTS (IEEE 1619 disk mode) ------------------------------------ */

long hsk_ossl4_cipher_xts(OSSL_LIB_CTX *ctx, const char *ciphername,
                          const char *propq, int enc,
                          const unsigned char *key, size_t keylen,
                          const unsigned char *tweak, size_t tweaklen,
                          const unsigned char *in, size_t inlen,
                          unsigned char **out)
{
    ERR_clear_error(); /* fresh queue; failures keep it for last_error */
    EVP_CIPHER *cipher = NULL;
    EVP_CIPHER_CTX *cctx = NULL;
    unsigned char *buf = NULL;
    size_t cap = 0;
    int outl1 = 0, outl2 = 0;
    long rc = HSK_OSSL4_ERR_NATIVE;

    if (ctx == NULL || ciphername == NULL || propq == NULL || out == NULL ||
        key == NULL || tweak == NULL || (in == NULL && inlen > 0))
        return HSK_OSSL4_ERR_BADPARAM;

    cipher = EVP_CIPHER_fetch(ctx, ciphername, propq);
    if (cipher == NULL)
        goto end;
    if (keylen != (size_t)EVP_CIPHER_get_key_length(cipher)) {
        rc = HSK_OSSL4_ERR_BADPARAM;
        goto end;
    }
    if (tweaklen != (size_t)EVP_CIPHER_get_iv_length(cipher)) {
        rc = HSK_OSSL4_ERR_BADPARAM;
        goto end;
    }
    /* XTS floor (provider-proven): >= 16 bytes, any length above. */
    if (inlen < 16) {
        rc = HSK_OSSL4_ERR_BADPARAM;
        goto end;
    }
    cctx = EVP_CIPHER_CTX_new();
    if (cctx == NULL)
        goto end;
    /* Init failure is the provider's weak-key refusal (equal data
     * and tweak halves): a bad key, never a bad parameter. */
    if (enc) {
        if (!EVP_EncryptInit_ex(cctx, cipher, NULL, key, tweak)) {
            rc = HSK_OSSL4_ERR_BADKEY;
            goto end;
        }
    } else {
        if (!EVP_DecryptInit_ex(cctx, cipher, NULL, key, tweak)) {
            rc = HSK_OSSL4_ERR_BADKEY;
            goto end;
        }
    }
    EVP_CIPHER_CTX_set_padding(cctx, 0);
    /* XTS is length-preserving (block size 1); margin for safety. */
    cap = inlen + 16;
    buf = OPENSSL_malloc(cap);
    if (buf == NULL) {
        rc = HSK_OSSL4_ERR_NOMEM;
        goto end;
    }
    if (enc) {
        if (!EVP_EncryptUpdate(cctx, buf, &outl1, in, (int)inlen))
            goto end;
        if (!EVP_EncryptFinal_ex(cctx, buf + outl1, &outl2))
            goto end;
    } else {
        if (!EVP_DecryptUpdate(cctx, buf, &outl1, in, (int)inlen))
            goto end;
        if (!EVP_DecryptFinal_ex(cctx, buf + outl1, &outl2))
            goto end;
    }
    *out = buf;
    rc = (long)(outl1 + outl2);

end:
    EVP_CIPHER_CTX_free(cctx);
    EVP_CIPHER_free(cipher);
    if (rc < 0 && buf != NULL)
        OPENSSL_clear_free(buf, cap);
    return rc;
}

/* --- AES-CTS (CBC-CS1) ------------------------------------------------ */

/* Fixed 16-byte XOR over stack block buffers. */
static void
hsk_cts_xor(unsigned char dst[16], const unsigned char a[16],
            const unsigned char b[16])
{
    size_t i;
    for (i = 0; i < 16; i++)
        dst[i] = (unsigned char)(a[i] ^ b[i]);
}

/* One ECB block through an Update-only context (padding disabled at
 * init; each 16-byte Update emits exactly one block). Returns 1 on
 * success, 0 on failure. */
static int
hsk_cts_block(EVP_CIPHER_CTX *cctx, unsigned char out[16],
              const unsigned char in[16])
{
    int outl = 0;
    if (!EVP_CipherUpdate(cctx, out, &outl, in, 16))
        return 0;
    return outl == 16;
}

long hsk_ossl4_cipher_cts(OSSL_LIB_CTX *ctx, const char *ecbname,
                          const char *propq, int enc, const unsigned char *key,
                          size_t keylen, const unsigned char *iv, size_t ivlen,
                          const unsigned char *in, size_t inlen,
                          unsigned char **out)
{
    ERR_clear_error(); /* fresh queue; failures keep it for last_error */
    EVP_CIPHER *ecb = NULL;
    EVP_CIPHER_CTX *cctx = NULL;
    unsigned char *buf = NULL;
    unsigned char chain[16], tmp[16], e1[16], pad[16];
    size_t nfull, rem, pairOff, tailLen, i;
    long rc = HSK_OSSL4_ERR_NATIVE;

    if (ctx == NULL || ecbname == NULL || propq == NULL || out == NULL ||
        key == NULL || iv == NULL || (in == NULL && inlen > 0))
        return HSK_OSSL4_ERR_BADPARAM;

    ecb = EVP_CIPHER_fetch(ctx, ecbname, propq);
    if (ecb == NULL)
        goto end;
    /* The construction below is written for a 16-byte block; refuse
     * anything else rather than mis-framing. */
    if (EVP_CIPHER_get_block_size(ecb) != 16 ||
        EVP_CIPHER_get_mode(ecb) != EVP_CIPH_ECB_MODE ||
        keylen != (size_t)EVP_CIPHER_get_key_length(ecb) || ivlen != 16) {
        rc = HSK_OSSL4_ERR_BADPARAM;
        goto end;
    }
    if (inlen < 16 || inlen > INT_MAX) {
        rc = HSK_OSSL4_ERR_BADPARAM;
        goto end;
    }
    cctx = EVP_CIPHER_CTX_new();
    if (cctx == NULL)
        goto end;
    if (!EVP_CipherInit_ex2(cctx, ecb, key, NULL, enc ? 1 : 0, NULL)) {
        rc = HSK_OSSL4_ERR_BADPARAM;
        goto end;
    }
    EVP_CIPHER_CTX_set_padding(cctx, 0);
    buf = OPENSSL_malloc(inlen);
    if (buf == NULL) {
        rc = HSK_OSSL4_ERR_NOMEM;
        goto end;
    }

    nfull = inlen / 16;
    rem = inlen % 16;
    if (nfull == 1 && rem == 0) {
        /* Single block: plain CBC. */
        if (enc) {
            hsk_cts_xor(tmp, in, iv);
            if (!hsk_cts_block(cctx, buf, tmp))
                goto end;
        } else {
            if (!hsk_cts_block(cctx, tmp, in))
                goto end;
            hsk_cts_xor(buf, tmp, iv);
        }
        rc = (long)inlen;
        goto end;
    }
    /* Steal pair: the last full block plus the tail (a partial tail
     * when rem > 0, else the final full block). Everything before the
     * pair chains as plain CBC. */
    pairOff = rem > 0 ? (nfull - 1) * 16 : (nfull - 2) * 16;
    tailLen = rem > 0 ? rem : 16;
    memcpy(chain, iv, 16);
    if (enc) {
        for (i = 0; i < pairOff; i += 16) {
            hsk_cts_xor(tmp, in + i, chain);
            if (!hsk_cts_block(cctx, buf + i, tmp))
                goto end;
            memcpy(chain, buf + i, 16);
        }
        hsk_cts_xor(tmp, in + pairOff, chain);
        if (!hsk_cts_block(cctx, e1, tmp))
            goto end;
        /* CS1 wire order: the stolen tail first, then the full pair
         * block (ACVP CBC-CS1 vectors pin this order). */
        memcpy(buf + pairOff, e1, tailLen);
        memset(pad, 0, 16);
        memcpy(pad, in + pairOff + 16, tailLen);
        hsk_cts_xor(tmp, pad, e1);
        if (!hsk_cts_block(cctx, buf + pairOff + tailLen, tmp))
            goto end;
    } else {
        for (i = 0; i < pairOff; i += 16) {
            if (!hsk_cts_block(cctx, tmp, in + i))
                goto end;
            hsk_cts_xor(buf + i, tmp, chain);
            memcpy(chain, in + i, 16);
        }
        /* Ciphertext wire order: stolen tail first, full pair block
         * second; the plaintext pair stays in place. */
        if (!hsk_cts_block(cctx, e1, in + pairOff + tailLen))
            goto end;
        /* P_tail = head(D(C_pair)) ^ C_tail: the decrypted head still
         * carries the stolen bytes. */
        for (i = 0; i < tailLen; i++)
            buf[pairOff + 16 + i] = (unsigned char)(e1[i] ^ in[pairOff + i]);
        /* Splice the transmitted tail over the decrypted head. */
        memcpy(tmp, e1, 16);
        memcpy(tmp, in + pairOff, tailLen);
        if (!hsk_cts_block(cctx, pad, tmp))
            goto end;
        hsk_cts_xor(buf + pairOff, pad, chain);
    }
    rc = (long)inlen;

end:
    OPENSSL_cleanse(chain, sizeof chain);
    OPENSSL_cleanse(tmp, sizeof tmp);
    OPENSSL_cleanse(e1, sizeof e1);
    OPENSSL_cleanse(pad, sizeof pad);
    EVP_CIPHER_CTX_free(cctx);
    EVP_CIPHER_free(ecb);
    if (rc < 0) {
        if (buf != NULL)
            OPENSSL_clear_free(buf, inlen);
    } else {
        *out = buf;
    }
    return rc;
}

/* --- AEAD (AES-GCM) --------------------------------------------------- */

long hsk_ossl4_aead_encrypt(OSSL_LIB_CTX *ctx, const char *ciphername,
                            const char *propq, const unsigned char *key,
                            size_t keylen, const unsigned char *iv,
                            size_t ivlen, const unsigned char *aad,
                            size_t aadlen, const unsigned char *in,
                            size_t inlen, size_t taglen,
                            unsigned char **out)
{
    ERR_clear_error();
    EVP_CIPHER *cipher = NULL;
    EVP_CIPHER_CTX *cctx = NULL;
    unsigned char *buf = NULL;
    int outl1 = 0, outl2 = 0;
    long rc = HSK_OSSL4_ERR_NATIVE;

    if (ctx == NULL || ciphername == NULL || propq == NULL || out == NULL ||
        key == NULL || iv == NULL || ivlen < 1 || ivlen > 64 ||
        taglen < 1 || taglen > 16 || inlen > INT_MAX || aadlen > INT_MAX ||
        (in == NULL && inlen > 0) || (aad == NULL && aadlen > 0))
        return HSK_OSSL4_ERR_BADPARAM;

    cipher = EVP_CIPHER_fetch(ctx, ciphername, propq);
    if (cipher == NULL)
        goto end;
    if (keylen != (size_t)EVP_CIPHER_get_key_length(cipher) ||
        EVP_CIPHER_get_mode(cipher) != EVP_CIPH_GCM_MODE) {
        rc = HSK_OSSL4_ERR_BADPARAM;
        goto end;
    }
    cctx = EVP_CIPHER_CTX_new();
    if (cctx == NULL)
        goto end;
    if (!EVP_EncryptInit_ex(cctx, cipher, NULL, NULL, NULL) ||
        !EVP_CIPHER_CTX_ctrl(cctx, EVP_CTRL_GCM_SET_IVLEN, (int)ivlen, NULL) ||
        !EVP_EncryptInit_ex(cctx, NULL, NULL, key, iv)) {
        rc = HSK_OSSL4_ERR_BADPARAM;
        goto end;
    }
    buf = OPENSSL_malloc(inlen + taglen > 0 ? inlen + taglen : 1);
    if (buf == NULL) {
        rc = HSK_OSSL4_ERR_NOMEM;
        goto end;
    }
    /* AAD Update reports aadlen through its outl argument; keep it in a
       throwaway so an empty message cannot inherit aadlen as ct length. */
    if (aadlen > 0) {
        int aadl = 0;
        if (!EVP_EncryptUpdate(cctx, NULL, &aadl, aad, (int)aadlen))
            goto end;
    }
    if (inlen > 0 &&
        !EVP_EncryptUpdate(cctx, buf, &outl1, in, (int)inlen))
        goto end;
    if (!EVP_EncryptFinal_ex(cctx, buf + outl1, &outl2))
        goto end;
    if (!EVP_CIPHER_CTX_ctrl(cctx, EVP_CTRL_GCM_GET_TAG, (int)taglen,
                             buf + outl1 + outl2))
        goto end;
    *out = buf;
    rc = (long)(outl1 + outl2 + taglen);

end:
    EVP_CIPHER_CTX_free(cctx);
    EVP_CIPHER_free(cipher);
    if (rc < 0 && buf != NULL)
        OPENSSL_clear_free(buf, inlen + taglen > 0 ? inlen + taglen : 1);
    return rc;
}

long hsk_ossl4_aead_decrypt(OSSL_LIB_CTX *ctx, const char *ciphername,
                            const char *propq, const unsigned char *key,
                            size_t keylen, const unsigned char *iv,
                            size_t ivlen, const unsigned char *aad,
                            size_t aadlen, const unsigned char *in,
                            size_t inlen, const unsigned char *tag,
                            size_t taglen, unsigned char **out)
{
    ERR_clear_error();
    EVP_CIPHER *cipher = NULL;
    EVP_CIPHER_CTX *cctx = NULL;
    unsigned char *buf = NULL;
    int outl1 = 0, outl2 = 0;
    long rc = HSK_OSSL4_ERR_NATIVE;

    if (ctx == NULL || ciphername == NULL || propq == NULL || out == NULL ||
        key == NULL || iv == NULL || ivlen < 1 || ivlen > 64 ||
        tag == NULL || taglen < 1 || taglen > 16 ||
        inlen > INT_MAX || aadlen > INT_MAX ||
        (in == NULL && inlen > 0) || (aad == NULL && aadlen > 0))
        return HSK_OSSL4_ERR_BADPARAM;

    cipher = EVP_CIPHER_fetch(ctx, ciphername, propq);
    if (cipher == NULL)
        goto end;
    if (keylen != (size_t)EVP_CIPHER_get_key_length(cipher) ||
        EVP_CIPHER_get_mode(cipher) != EVP_CIPH_GCM_MODE) {
        rc = HSK_OSSL4_ERR_BADPARAM;
        goto end;
    }
    cctx = EVP_CIPHER_CTX_new();
    if (cctx == NULL)
        goto end;
    if (!EVP_DecryptInit_ex(cctx, cipher, NULL, NULL, NULL) ||
        !EVP_CIPHER_CTX_ctrl(cctx, EVP_CTRL_GCM_SET_IVLEN, (int)ivlen, NULL) ||
        !EVP_DecryptInit_ex(cctx, NULL, NULL, key, iv)) {
        rc = HSK_OSSL4_ERR_BADPARAM;
        goto end;
    }
    if (!EVP_CIPHER_CTX_ctrl(cctx, EVP_CTRL_GCM_SET_TAG, (int)taglen,
                             (void *)tag)) {
        rc = HSK_OSSL4_ERR_BADPARAM;
        goto end;
    }
    buf = OPENSSL_malloc(inlen > 0 ? inlen : 1);
    if (buf == NULL) {
        rc = HSK_OSSL4_ERR_NOMEM;
        goto end;
    }
    /* AAD Update reports aadlen through its outl argument; keep it in a
       throwaway so an empty message cannot inherit aadlen as pt length. */
    if (aadlen > 0) {
        int aadl = 0;
        if (!EVP_DecryptUpdate(cctx, NULL, &aadl, aad, (int)aadlen)) {
            rc = HSK_OSSL4_ERR_AUTHFAIL;
            goto end;
        }
    }
    if (inlen > 0 &&
        !EVP_DecryptUpdate(cctx, buf, &outl1, in, (int)inlen)) {
        rc = HSK_OSSL4_ERR_AUTHFAIL;
        goto end;
    }
    if (!EVP_DecryptFinal_ex(cctx, buf + outl1, &outl2)) {
        rc = HSK_OSSL4_ERR_AUTHFAIL;
        goto end;
    }
    *out = buf;
    rc = (long)(outl1 + outl2);

end:
    EVP_CIPHER_CTX_free(cctx);
    EVP_CIPHER_free(cipher);
    if (rc < 0 && buf != NULL)
        OPENSSL_clear_free(buf, inlen > 0 ? inlen : 1);
    return rc;
}

/* --- AEAD (AES-CCM) --------------------------------------------------- */
/* Same contract as the GCM shims, plus the CCM call-order rules: the
 * tag length and nonce length are fixed before key/iv init, and the
 * total plaintext length is preset with a NULL-data Update before
 * any AAD or data. Nonce 7..13 bytes, tag even 4..16 (SP 800-38C);
 * anything else is BADPARAM, never a native failure. */

long hsk_ossl4_aead_ccm_encrypt(OSSL_LIB_CTX *ctx, const char *ciphername,
                            const char *propq, const unsigned char *key,
                            size_t keylen, const unsigned char *iv,
                            size_t ivlen, const unsigned char *aad,
                            size_t aadlen, const unsigned char *in,
                            size_t inlen, size_t taglen,
                            unsigned char **out)
{
    ERR_clear_error();
    EVP_CIPHER *cipher = NULL;
    EVP_CIPHER_CTX *cctx = NULL;
    unsigned char *buf = NULL;
    int outl1 = 0, outl2 = 0;
    long rc = HSK_OSSL4_ERR_NATIVE;

    if (ctx == NULL || ciphername == NULL || propq == NULL || out == NULL ||
        key == NULL || iv == NULL || ivlen < 7 || ivlen > 13 ||
        taglen < 4 || taglen > 16 || (taglen % 2 != 0) ||
        inlen > INT_MAX || aadlen > INT_MAX ||
        (in == NULL && inlen > 0) || (aad == NULL && aadlen > 0))
        return HSK_OSSL4_ERR_BADPARAM;

    cipher = EVP_CIPHER_fetch(ctx, ciphername, propq);
    if (cipher == NULL)
        goto end;
    if (keylen != (size_t)EVP_CIPHER_get_key_length(cipher) ||
        EVP_CIPHER_get_mode(cipher) != EVP_CIPH_CCM_MODE) {
        rc = HSK_OSSL4_ERR_BADPARAM;
        goto end;
    }
    cctx = EVP_CIPHER_CTX_new();
    if (cctx == NULL)
        goto end;
    if (!EVP_EncryptInit_ex(cctx, cipher, NULL, NULL, NULL) ||
        !EVP_CIPHER_CTX_ctrl(cctx, EVP_CTRL_CCM_SET_IVLEN, (int)ivlen, NULL) ||
        !EVP_CIPHER_CTX_ctrl(cctx, EVP_CTRL_CCM_SET_TAG, (int)taglen, NULL) ||
        !EVP_EncryptInit_ex(cctx, NULL, NULL, key, iv)) {
        rc = HSK_OSSL4_ERR_BADPARAM;
        goto end;
    }
    buf = OPENSSL_malloc(inlen + taglen > 0 ? inlen + taglen : 1);
    if (buf == NULL) {
        rc = HSK_OSSL4_ERR_NOMEM;
        goto end;
    }
    /* CCM requires the total plaintext length before any AAD or data. */
    {
        int tmplen = 0;
        if (!EVP_EncryptUpdate(cctx, NULL, &tmplen, NULL, (int)inlen))
            goto end;
    }
    /* AAD Update reports aadlen through its outl argument; keep it in a
       throwaway so an empty message cannot inherit aadlen as ct length. */
    if (aadlen > 0) {
        int aadl = 0;
        if (!EVP_EncryptUpdate(cctx, NULL, &aadl, aad, (int)aadlen))
            goto end;
    }
    if (inlen > 0 &&
        !EVP_EncryptUpdate(cctx, buf, &outl1, in, (int)inlen))
        goto end;
    if (!EVP_EncryptFinal_ex(cctx, buf + outl1, &outl2))
        goto end;
    if (!EVP_CIPHER_CTX_ctrl(cctx, EVP_CTRL_CCM_GET_TAG, (int)taglen,
                             buf + outl1 + outl2))
        goto end;
    *out = buf;
    rc = (long)(outl1 + outl2 + taglen);

end:
    EVP_CIPHER_CTX_free(cctx);
    EVP_CIPHER_free(cipher);
    if (rc < 0 && buf != NULL)
        OPENSSL_clear_free(buf, inlen + taglen > 0 ? inlen + taglen : 1);
    return rc;
}

long hsk_ossl4_aead_ccm_decrypt(OSSL_LIB_CTX *ctx, const char *ciphername,
                            const char *propq, const unsigned char *key,
                            size_t keylen, const unsigned char *iv,
                            size_t ivlen, const unsigned char *aad,
                            size_t aadlen, const unsigned char *in,
                            size_t inlen, const unsigned char *tag,
                            size_t taglen, unsigned char **out)
{
    ERR_clear_error();
    EVP_CIPHER *cipher = NULL;
    EVP_CIPHER_CTX *cctx = NULL;
    unsigned char *buf = NULL;
    int outl1 = 0, outl2 = 0;
    long rc = HSK_OSSL4_ERR_NATIVE;

    if (ctx == NULL || ciphername == NULL || propq == NULL || out == NULL ||
        key == NULL || iv == NULL || ivlen < 7 || ivlen > 13 ||
        tag == NULL || taglen < 4 || taglen > 16 || (taglen % 2 != 0) ||
        inlen > INT_MAX || aadlen > INT_MAX ||
        (in == NULL && inlen > 0) || (aad == NULL && aadlen > 0))
        return HSK_OSSL4_ERR_BADPARAM;

    cipher = EVP_CIPHER_fetch(ctx, ciphername, propq);
    if (cipher == NULL)
        goto end;
    if (keylen != (size_t)EVP_CIPHER_get_key_length(cipher) ||
        EVP_CIPHER_get_mode(cipher) != EVP_CIPH_CCM_MODE) {
        rc = HSK_OSSL4_ERR_BADPARAM;
        goto end;
    }
    cctx = EVP_CIPHER_CTX_new();
    if (cctx == NULL)
        goto end;
    if (!EVP_DecryptInit_ex(cctx, cipher, NULL, NULL, NULL) ||
        !EVP_CIPHER_CTX_ctrl(cctx, EVP_CTRL_CCM_SET_IVLEN, (int)ivlen, NULL) ||
        !EVP_CIPHER_CTX_ctrl(cctx, EVP_CTRL_CCM_SET_TAG, (int)taglen,
                             (void *)tag) ||
        !EVP_DecryptInit_ex(cctx, NULL, NULL, key, iv)) {
        rc = HSK_OSSL4_ERR_BADPARAM;
        goto end;
    }
    buf = OPENSSL_malloc(inlen > 0 ? inlen : 1);
    if (buf == NULL) {
        rc = HSK_OSSL4_ERR_NOMEM;
        goto end;
    }
    /* CCM requires the total ciphertext length before any AAD or data. */
    {
        int tmplen = 0;
        if (!EVP_DecryptUpdate(cctx, NULL, &tmplen, NULL, (int)inlen)) {
            rc = HSK_OSSL4_ERR_AUTHFAIL;
            goto end;
        }
    }
    /* AAD Update reports aadlen through its outl argument; keep it in a
       throwaway so an empty message cannot inherit aadlen as pt length. */
    if (aadlen > 0) {
        int aadl = 0;
        if (!EVP_DecryptUpdate(cctx, NULL, &aadl, aad, (int)aadlen)) {
            rc = HSK_OSSL4_ERR_AUTHFAIL;
            goto end;
        }
    }
    if (inlen > 0 &&
        !EVP_DecryptUpdate(cctx, buf, &outl1, in, (int)inlen)) {
        rc = HSK_OSSL4_ERR_AUTHFAIL;
        goto end;
    }
    if (!EVP_DecryptFinal_ex(cctx, buf + outl1, &outl2)) {
        rc = HSK_OSSL4_ERR_AUTHFAIL;
        goto end;
    }
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

/* Group order size in bits from the provider key (SEC1 truncation
 * input: E is the leftmost min(N, n) bits of the input). Exact for
 * every curve, including non-byte-aligned orders (P-521: 521).
 * Returns 1 on success, 0 otherwise. */
static int hsk_ossl4_ec_orderbits(EVP_PKEY *pkey, unsigned int *bits)
{
    BIGNUM *ord = NULL;
    int n = 0;

    if (!EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_EC_ORDER, &ord)
        || ord == NULL)
        return 0;
    n = BN_num_bits(ord);
    BN_free(ord);
    if (n <= 0)
        return 0;
    *bits = (unsigned int)n;
    return 1;
}

/* Truncate a raw-operation input to the leftmost orderbits bits
 * (SEC1 §4.1.3 / PKCS#11 §2.3.1): full bytes plus a masked partial
 * byte when the order is not byte-aligned. Returns 1 with *out
 * holding a fresh *outlen-byte buffer when truncation applies, 0
 * when the input already fits (caller keeps the original), -1 on
 * allocation failure. The fits check is overflow-free: msglen*8 >
 * orderbits iff msglen > orderbits/8 over the integers. */
static int hsk_ossl4_ec_truncate(const unsigned char *msg, size_t msglen,
                                 unsigned int orderbits,
                                 unsigned char **out, size_t *outlen)
{
    size_t keep;
    unsigned int rem;
    unsigned char *buf;

    if (out == NULL || outlen == NULL || orderbits == 0)
        return -1;
    if (msglen <= orderbits / 8)
        return 0;
    if (msg == NULL)
        return -1;
    rem = orderbits % 8;
    keep = orderbits / 8 + (rem ? 1 : 0);
    buf = OPENSSL_malloc(keep);
    if (buf == NULL)
        return -1;
    memcpy(buf, msg, keep);
    if (rem)
        buf[keep - 1] &= (unsigned char)(0xFF00 >> rem);
    *out = buf;
    *outlen = keep;
    return 1;
}

/* Map a failed ECDSA verify return onto the shim contract. X9.62
 * §7.4.2 says verification math landing on the point at infinity
 * REJECTS the signature, but OpenSSL reports it as an internal
 * error (rc -1 with EC_R_POINT_AT_INFINITY at the head of the
 * queue). That one degenerate-math reason answers mismatch (0);
 * anything else — including a queue that also carries a malloc
 * failure or overflows the drain bound — stays native.
 * Non-infinity failures leave the queue untouched for last_error
 * (peek only); the re-put path below runs solely when an
 * infinity-headed queue also signals resource exhaustion (lib and
 * reason codes preserved; func is legacy-ignored by ERR_PACK, and
 * file/line/data strings are dropped on that path only). */
static int hsk_ossl4_ecdsa_verify_post(int rc)
{
    unsigned long first, saved[32];
    int n = 0, saw_nomem = 0, i;
    unsigned long e;

    if (rc >= 0)
        return rc;
    first = ERR_peek_error();
    if (ERR_GET_LIB(first) != ERR_LIB_EC
        || ERR_GET_REASON(first) != EC_R_POINT_AT_INFINITY)
        return HSK_OSSL4_ERR_NATIVE;
    /* Infinity-headed: drain (bounded) and scan for malloc failure. */
    while (n < 32 && (e = ERR_get_error()) != 0) {
        saved[n++] = e;
        if (ERR_GET_REASON(e) == ERR_R_MALLOC_FAILURE)
            saw_nomem = 1;
    }
    while (ERR_get_error() != 0)
        saw_nomem = 1; /* overfull queue: fail safe, stay native */
    if (saw_nomem) {
        for (i = 0; i < n; i++)
            ERR_put_error(ERR_GET_LIB(saved[i]), 0,
                          ERR_GET_REASON(saved[i]), "", 0);
        return HSK_OSSL4_ERR_NATIVE;
    }
    return 0;
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
    unsigned char *trunc = NULL; /* SEC1 truncation buffer, if any */
    size_t trunclen = 0;
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
         * hashing; overlong input truncates to the leftmost order
         * bits (SEC1 §4.1.3 / PKCS#11 §2.3.1). */
        unsigned int orderbits = 0;
        int trc;
        if (!hsk_ossl4_ec_orderbits(pkey, &orderbits)) {
            rc = HSK_OSSL4_ERR_BADPARAM;
            goto end;
        }
        trc = hsk_ossl4_ec_truncate(msg, msglen, orderbits, &trunc, &trunclen);
        if (trc < 0) {
            rc = HSK_OSSL4_ERR_NOMEM;
            goto end;
        }
        if (trc > 0) {
            msg = trunc;
            msglen = trunclen;
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
        unsigned char point[1 + 2 * HSK_OSSL4_EC_MAX_COORD]; /* 0x04 || X || Y */
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
    if (trunc != NULL)
        OPENSSL_clear_free(trunc, trunclen);
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
    unsigned char *trunc = NULL; /* SEC1 truncation buffer, if any */
    size_t trunclen = 0;
    int rc = HSK_OSSL4_ERR_NATIVE;

    if (ctx == NULL || propq == NULL || sig == NULL ||
        (msg == NULL && msglen > 0) ||
        (no_hash != 0 && no_hash != 1) || (no_hash == 0 && mdname == NULL))
        return HSK_OSSL4_ERR_BADPARAM;

    pkey = hsk_ossl4_load_pub(ctx, propq, pub_der, pub_len);
    if (pkey == NULL)
        return HSK_OSSL4_ERR_BADKEY;
    if (no_hash) {
        /* Raw operation: overlong input truncates to the leftmost
         * order bits (SEC1 §4.1.3 / PKCS#11 §2.3.1). */
        unsigned int orderbits = 0;
        int trc;
        if (!hsk_ossl4_ec_orderbits(pkey, &orderbits)) {
            rc = HSK_OSSL4_ERR_BADPARAM;
            goto end;
        }
        trc = hsk_ossl4_ec_truncate(msg, msglen, orderbits, &trunc, &trunclen);
        if (trc < 0) {
            rc = HSK_OSSL4_ERR_NOMEM;
            goto end;
        }
        if (trc > 0) {
            msg = trunc;
            msglen = trunclen;
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
        /* Raw r||s -> DER: split halves, re-encode (range is
         * enforced by the provider math, not here). Odd lengths
         * cannot split into halves and can never be valid: answer
         * mismatch, like malformed DER. */
        ECDSA_SIG *osig = NULL;
        BIGNUM *r = NULL, *s = NULL;
        unsigned char *p = NULL;
        int len;
        if (siglen == 0) {
            rc = HSK_OSSL4_ERR_BADPARAM;
            goto end;
        }
        if ((siglen % 2) != 0) {
            ERR_clear_error();
            rc = 0;
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
    rc = hsk_ossl4_ecdsa_verify_post(rc);
    if (rc < 0)
        goto end;
    /* rc is 1 (valid) or 0 (bad signature) here. */
    ERR_clear_error();

end:
    if (conv != NULL)
        OPENSSL_clear_free(conv, convlen);
    if (trunc != NULL)
        OPENSSL_clear_free(trunc, trunclen);
    EVP_PKEY_CTX_free(pctx);
    EVP_MD_CTX_free(mctx);
    EVP_PKEY_free(pkey);
    return rc;
}

/* --- DSA sign/verify ---------------------------------------------------- */

/* Subprime (q) size in bits from the provider key (FIPS 186-4 §4.6
 * truncation input: the signed digest is the leftmost min(N, n)
 * bits of the input). Returns 1 on success, 0 otherwise. */
static int hsk_ossl4_dsa_qbits(EVP_PKEY *pkey, unsigned int *bits)
{
    BIGNUM *q = NULL;
    int n = 0;

    if (!EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_FFC_Q, &q)
        || q == NULL)
        return 0;
    n = BN_num_bits(q);
    BN_free(q);
    if (n <= 0)
        return 0;
    *bits = (unsigned int)n;
    return 1;
}

/* Truncate a raw-operation input to the leftmost qbits bits (FIPS
 * 186-4 §4.6): full bytes plus a masked partial byte when the
 * subprime is not byte-aligned. Returns 1 with *out holding a
 * fresh *outlen-byte buffer when truncation applies, 0 when the
 * input already fits (caller keeps the original), -1 on allocation
 * failure. The fits check is overflow-free: msglen*8 > qbits iff
 * msglen > qbits/8 over the integers. */
static int hsk_ossl4_dsa_truncate(const unsigned char *msg, size_t msglen,
                                 unsigned int qbits,
                                 unsigned char **out, size_t *outlen)
{
    size_t keep;
    unsigned int rem;
    unsigned char *buf;

    if (out == NULL || outlen == NULL || qbits == 0)
        return -1;
    if (msglen <= qbits / 8)
        return 0;
    if (msg == NULL)
        return -1;
    rem = qbits % 8;
    keep = qbits / 8 + (rem ? 1 : 0);
    buf = OPENSSL_malloc(keep);
    if (buf == NULL)
        return -1;
    memcpy(buf, msg, keep);
    if (rem)
        buf[keep - 1] &= (unsigned char)(0xFF00 >> rem);
    *out = buf;
    *outlen = keep;
    return 1;
}

long hsk_ossl4_dsa_sign(OSSL_LIB_CTX *ctx, const char *mdname,
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
    unsigned char *trunc = NULL; /* FIPS truncation buffer, if any */
    size_t trunclen = 0;
    long rc = HSK_OSSL4_ERR_NATIVE;

    if (ctx == NULL || propq == NULL || out == NULL ||
        (msg == NULL && msglen > 0) ||
        (no_hash != 0 && no_hash != 1) || (no_hash == 0 && mdname == NULL))
        return HSK_OSSL4_ERR_BADPARAM;
    if (no_hash && msglen < 20)
        return HSK_OSSL4_ERR_BADPARAM; /* PKCS#11 20-byte digest floor */

    pkey = hsk_ossl4_load_priv(ctx, propq, priv_der, priv_len);
    if (pkey == NULL)
        return HSK_OSSL4_ERR_BADKEY;
    /* A well-formed non-DSA key (EC, RSA) must refuse here rather
     * than execute past the advertised cap set. */
    if (EVP_PKEY_get_base_id(pkey) != EVP_PKEY_DSA) {
        EVP_PKEY_free(pkey);
        return HSK_OSSL4_ERR_BADKEY;
    }
    if (no_hash) {
        /* Raw operation (CKM_DSA): sign the input directly with no
         * hashing; overlong input truncates to the leftmost q bits
         * (FIPS 186-4 §4.6). */
        unsigned int qbits = 0;
        int trc;
        if (!hsk_ossl4_dsa_qbits(pkey, &qbits)) {
            rc = HSK_OSSL4_ERR_BADPARAM;
            goto end;
        }
        trc = hsk_ossl4_dsa_truncate(msg, msglen, qbits, &trunc, &trunclen);
        if (trc < 0) {
            rc = HSK_OSSL4_ERR_NOMEM;
            goto end;
        }
        if (trc > 0) {
            msg = trunc;
            msglen = trunclen;
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
     * the subprime length derived from the key's FFC parameters. */
    {
        const unsigned char *p = der;
        DSA_SIG *sig = d2i_DSA_SIG(NULL, &p, (long)derlen);
        const BIGNUM *r = NULL, *s = NULL;
        unsigned char *raw = NULL;
        unsigned int qbits = 0;
        size_t qlen = 0;
        if (sig == NULL)
            goto end;
        DSA_SIG_get0(sig, &r, &s);
        if (!hsk_ossl4_dsa_qbits(pkey, &qbits) || qbits == 0) {
            DSA_SIG_free(sig);
            goto end;
        }
        qlen = (size_t)((qbits + 7) / 8);
        raw = OPENSSL_malloc(2 * qlen);
        if (raw == NULL) {
            DSA_SIG_free(sig);
            rc = HSK_OSSL4_ERR_NOMEM;
            goto end;
        }
        if (BN_bn2binpad(r, raw, (int)qlen) < 0 ||
            BN_bn2binpad(s, raw + qlen, (int)qlen) < 0) {
            OPENSSL_clear_free(raw, 2 * qlen);
            DSA_SIG_free(sig);
            goto end;
        }
        DSA_SIG_free(sig);
        *out = raw;
        rc = (long)(2 * qlen);
    }

end:
    if (der != NULL)
        OPENSSL_clear_free(der, derlen);
    if (trunc != NULL)
        OPENSSL_clear_free(trunc, trunclen);
    EVP_PKEY_CTX_free(pctx);
    EVP_MD_CTX_free(mctx);
    EVP_PKEY_free(pkey);
    return rc;
}

int hsk_ossl4_dsa_verify(OSSL_LIB_CTX *ctx, const char *mdname,
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
    unsigned char *trunc = NULL; /* FIPS truncation buffer, if any */
    size_t trunclen = 0;
    int rc = HSK_OSSL4_ERR_NATIVE;

    if (ctx == NULL || propq == NULL || sig == NULL ||
        (msg == NULL && msglen > 0) ||
        (no_hash != 0 && no_hash != 1) || (no_hash == 0 && mdname == NULL))
        return HSK_OSSL4_ERR_BADPARAM;
    if (no_hash && msglen < 20)
        return HSK_OSSL4_ERR_BADPARAM; /* PKCS#11 20-byte digest floor */

    pkey = hsk_ossl4_load_pub(ctx, propq, pub_der, pub_len);
    if (pkey == NULL)
        return HSK_OSSL4_ERR_BADKEY;
    /* A well-formed non-DSA key (EC, RSA) must refuse here rather
     * than execute past the advertised cap set. */
    if (EVP_PKEY_get_base_id(pkey) != EVP_PKEY_DSA) {
        EVP_PKEY_free(pkey);
        return HSK_OSSL4_ERR_BADKEY;
    }
    if (no_hash) {
        /* Raw operation: overlong input truncates to the leftmost
         * q bits (FIPS 186-4 §4.6). */
        unsigned int qbits = 0;
        int trc;
        if (!hsk_ossl4_dsa_qbits(pkey, &qbits)) {
            rc = HSK_OSSL4_ERR_BADPARAM;
            goto end;
        }
        trc = hsk_ossl4_dsa_truncate(msg, msglen, qbits, &trunc, &trunclen);
        if (trc < 0) {
            rc = HSK_OSSL4_ERR_NOMEM;
            goto end;
        }
        if (trc > 0) {
            msg = trunc;
            msglen = trunclen;
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
        DSA_SIG *chk = NULL;
        if (siglen == 0 || siglen > (size_t)INT_MAX) {
            rc = HSK_OSSL4_ERR_BADPARAM;
            goto end;
        }
        chk = d2i_DSA_SIG(NULL, &q, (long)siglen);
        if (chk == NULL || (size_t)(q - sig) != siglen) {
            DSA_SIG_free(chk);
            ERR_clear_error();
            rc = 0;
            goto end;
        }
        DSA_SIG_free(chk);
        der = sig;
        derlen = siglen;
    } else {
        /* Raw r||s -> DER: split halves, re-encode (range is
         * enforced by the provider math, not here). Odd lengths
         * cannot split into halves and can never be valid: answer
         * mismatch, like malformed DER. */
        DSA_SIG *osig = NULL;
        BIGNUM *r = NULL, *s = NULL;
        unsigned char *p = NULL;
        int len;
        if (siglen == 0) {
            rc = HSK_OSSL4_ERR_BADPARAM;
            goto end;
        }
        if ((siglen % 2) != 0) {
            ERR_clear_error();
            rc = 0;
            goto end;
        }
        r = BN_bin2bn(sig, (int)(siglen / 2), NULL);
        s = BN_bin2bn(sig + siglen / 2, (int)(siglen / 2), NULL);
        osig = DSA_SIG_new();
        if (r == NULL || s == NULL || osig == NULL ||
            !DSA_SIG_set0(osig, r, s)) {
            BN_free(r);
            BN_free(s);
            DSA_SIG_free(osig);
            rc = HSK_OSSL4_ERR_BADPARAM;
            goto end;
        }
        r = s = NULL; /* owned by osig now */
        len = i2d_DSA_SIG(osig, NULL);
        if (len <= 0) {
            DSA_SIG_free(osig);
            goto end;
        }
        conv = OPENSSL_malloc((size_t)len);
        if (conv == NULL) {
            DSA_SIG_free(osig);
            rc = HSK_OSSL4_ERR_NOMEM;
            goto end;
        }
        p = conv;
        convlen = (size_t)len;
        if (i2d_DSA_SIG(osig, &p) != len) {
            DSA_SIG_free(osig);
            goto end;
        }
        DSA_SIG_free(osig);
        der = conv;
        derlen = convlen;
    }

    if (no_hash) {
        /* Raw operation (CKM_DSA): verify the input directly. */
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
    /* 1 (valid) or 0 (bad signature); provider-internal failures
     * (rc < 0: DSA has no degenerate-math mismatch case) stay
     * native. */
    if (rc < 0)
        rc = HSK_OSSL4_ERR_NATIVE;
    else
        ERR_clear_error();

end:
    if (conv != NULL)
        OPENSSL_clear_free(conv, convlen);
    if (trunc != NULL)
        OPENSSL_clear_free(trunc, trunclen);
    EVP_PKEY_CTX_free(pctx);
    EVP_MD_CTX_free(mctx);
    EVP_PKEY_free(pkey);
    return rc;
}

/* --- DSA paramgen + keygen -------------------------------------------- */

long hsk_ossl4_dsa_gen_params(OSSL_LIB_CTX *ctx, const char *propq,
                              int pbits, int qbits, unsigned char **out)
{
    ERR_clear_error(); /* fresh queue; failures keep it for last_error */
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *params = NULL;
    OSSL_PARAM bld[3];
    unsigned char *der = NULL;
    int derlen = 0;
    long rc = HSK_OSSL4_ERR_NATIVE;

    if (ctx == NULL || propq == NULL || out == NULL)
        return HSK_OSSL4_ERR_BADPARAM;
    /* Approved FIPS 186-4 (L, N) pairs only. */
    if (!((pbits == 1024 && qbits == 160) ||
          (pbits == 2048 && (qbits == 224 || qbits == 256)) ||
          (pbits == 3072 && qbits == 256)))
        return HSK_OSSL4_ERR_BADPARAM;

    pctx = EVP_PKEY_CTX_new_from_name(ctx, "DSA", propq);
    if (pctx == NULL)
        goto end;
    if (EVP_PKEY_paramgen_init(pctx) <= 0)
        goto end;
    bld[0] = OSSL_PARAM_construct_int(OSSL_PKEY_PARAM_FFC_PBITS, &pbits);
    bld[1] = OSSL_PARAM_construct_int(OSSL_PKEY_PARAM_FFC_QBITS, &qbits);
    bld[2] = OSSL_PARAM_construct_end();
    if (EVP_PKEY_CTX_set_params(pctx, bld) <= 0) {
        rc = HSK_OSSL4_ERR_BADPARAM;
        goto end;
    }
    if (EVP_PKEY_paramgen(pctx, &params) <= 0)
        goto end;
    derlen = i2d_KeyParams(params, &der);
    if (derlen <= 0) {
        OPENSSL_free(der);
        goto end;
    }
    *out = der;
    rc = (long)derlen;

end:
    EVP_PKEY_free(params);
    EVP_PKEY_CTX_free(pctx);
    return rc;
}

int hsk_ossl4_dsa_gen_keypair(OSSL_LIB_CTX *ctx, const char *propq,
                              const unsigned char *params_der,
                              size_t params_len, unsigned char **priv_der,
                              size_t *priv_len, unsigned char **pub_der,
                              size_t *pub_len)
{
    ERR_clear_error(); /* fresh queue; failures keep it for last_error */
    OSSL_DECODER_CTX *dctx = NULL;
    EVP_PKEY *params = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *pkey = NULL;
    unsigned char *priv = NULL, *pub = NULL;
    int privlen = 0, publen = 0;
    int rc = HSK_OSSL4_ERR_NATIVE;

    if (ctx == NULL || propq == NULL || params_der == NULL ||
        params_len == 0 || params_len > (size_t)INT_MAX ||
        priv_der == NULL || priv_len == NULL ||
        pub_der == NULL || pub_len == NULL)
        return HSK_OSSL4_ERR_BADPARAM;

    /* Decode DER domain parameters into a provider key (libctx +
     * propq bound); undecodable params are BADKEY. */
    dctx = OSSL_DECODER_CTX_new_for_pkey(&params, "DER", NULL, "DSA",
                                         OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS,
                                         ctx, propq);
    if (dctx == NULL)
        goto end;
    {
        const unsigned char *p = params_der;
        size_t len = params_len;
        if (!OSSL_DECODER_from_data(dctx, &p, &len)) {
            rc = HSK_OSSL4_ERR_BADKEY;
            goto end;
        }
    }
    if (params == NULL) {
        rc = HSK_OSSL4_ERR_BADKEY;
        goto end;
    }
    pctx = EVP_PKEY_CTX_new(params, NULL);
    if (pctx == NULL)
        goto end;
    if (EVP_PKEY_keygen_init(pctx) <= 0 || EVP_PKEY_keygen(pctx, &pkey) <= 0)
        goto end;
    /* PKCS#8 explicitly: i2d_PrivateKey prefers the traditional
     * (DSAPrivateKey) encoding for DSA, but the house convention (and the
     * keygen stamping that parses these bytes) is PKCS#8. Same quirk as
     * the RSA keygen above. */
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
    EVP_PKEY_free(params);
    OSSL_DECODER_CTX_free(dctx);
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
        /* The peer arrives inside the mechanism parameters, so a
         * rejected peer is a parameter fault (BADPEER), distinct
         * from a bad base key (BADKEY). */
        rc = HSK_OSSL4_ERR_BADPEER;
        goto end;
    }
    pctx = EVP_PKEY_CTX_new_from_pkey(ctx, priv, propq);
    if (pctx == NULL)
        goto end;
    if (EVP_PKEY_derive_init(pctx) <= 0)
        goto end;
    if (cofactor && EVP_PKEY_CTX_set_ecdh_cofactor_mode(pctx, 1) <= 0)
        goto end;
    /* A peer on another curve (or a non-EC peer) fails here: a
     * parameter fault (the peer rides in the mechanism params),
     * not a native malfunction. */
    if (EVP_PKEY_derive_set_peer(pctx, peer) <= 0) {
        rc = HSK_OSSL4_ERR_BADPEER;
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

/* A failed OAEP decrypt is always a padding verdict. This function
 * runs only after init succeeded and the ciphertext length checked,
 * so every failure here is data-dependent: distinguishing OpenSSL
 * reason codes would partition invalid ciphertexts into categories
 * (Manger 2001). Error uniformity is the security property;
 * PKCS#11 v3.2 says implementations SHOULD return
 * CKR_ENCRYPTED_DATA_INVALID uniformly. Typed caller/key faults
 * (BADPARAM/BADKEY/NOMEM) return before this point and stay typed. */
static long hsk_ossl4_oaep_fail(void)
{
    ERR_clear_error();
    return HSK_OSSL4_ERR_AUTHFAIL;
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

long hsk_ossl4_rsa_pkcs1_encrypt(OSSL_LIB_CTX *ctx, const char *propq,
                                 const unsigned char *pub_der, size_t pub_len,
                                 const unsigned char *in, size_t inlen,
                                 unsigned char **out)
{
    ERR_clear_error(); /* fresh queue; failures keep it for last_error */
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    unsigned char *buf = NULL;
    size_t buflen = 0;
    size_t k;
    int ksize;
    long rc = HSK_OSSL4_ERR_NATIVE;

    if (ctx == NULL || propq == NULL || out == NULL ||
        (in == NULL && inlen > 0))
        return HSK_OSSL4_ERR_BADPARAM;

    pkey = hsk_ossl4_load_pub(ctx, propq, pub_der, pub_len);
    if (pkey == NULL)
        return HSK_OSSL4_ERR_BADKEY;
    /* Typed input bound: mLen <= k - 11. */
    ksize = EVP_PKEY_get_size(pkey);
    if (ksize <= 0) {
        rc = HSK_OSSL4_ERR_BADPARAM;
        goto end;
    }
    k = (size_t)ksize;
    if (k <= 11 || inlen > k - 11) {
        rc = HSK_OSSL4_ERR_BADPARAM;
        goto end;
    }
    pctx = EVP_PKEY_CTX_new_from_pkey(ctx, pkey, propq);
    if (pctx == NULL)
        goto end;
    if (EVP_PKEY_encrypt_init(pctx) <= 0 ||
        EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PADDING) <= 0 ||
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
    EVP_PKEY_free(pkey);
    return rc;
}

long hsk_ossl4_rsa_pkcs1_decrypt(OSSL_LIB_CTX *ctx, const char *propq,
                                 const unsigned char *priv_der,
                                 size_t priv_len, const unsigned char *in,
                                 size_t inlen, unsigned char **out)
{
    ERR_clear_error(); /* fresh queue; failures keep it for last_error */
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    unsigned char *em = NULL;
    unsigned char *msg = NULL;
    unsigned char *outbuf = NULL;
    size_t emlen = 0;
    size_t k;
    size_t mlen;
    int ksize;
    int padlen;
    long rc = HSK_OSSL4_ERR_NATIVE;

    if (ctx == NULL || propq == NULL || out == NULL ||
        (in == NULL && inlen > 0))
        return HSK_OSSL4_ERR_BADPARAM;

    pkey = hsk_ossl4_load_priv(ctx, propq, priv_der, priv_len);
    if (pkey == NULL)
        return HSK_OSSL4_ERR_BADKEY;
    /* Off-modulus input is a caller shape error, not a padding verdict. */
    ksize = EVP_PKEY_get_size(pkey);
    if (ksize <= 0) {
        rc = HSK_OSSL4_ERR_BADPARAM;
        goto end;
    }
    k = (size_t)ksize;
    if (inlen != k) {
        rc = HSK_OSSL4_ERR_BADPARAM;
        goto end;
    }
    /* Raw decrypt plus manual type-2 unpad: the 4.0 provider
     * answers PKCS#1 v1.5 padding failures with implicit rejection
     * (rc 0, random bytes), which cannot surface the PKCS#11
     * ENCRYPTED_DATA_INVALID verdict. Unpadding here keeps every
     * padding failure a uniform AUTHFAIL. */
    pctx = EVP_PKEY_CTX_new_from_pkey(ctx, pkey, propq);
    if (pctx == NULL)
        goto end;
    if (EVP_PKEY_decrypt_init(pctx) <= 0 ||
        EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_NO_PADDING) <= 0) {
        rc = HSK_OSSL4_ERR_NATIVE;
        goto end;
    }
    if (EVP_PKEY_decrypt(pctx, NULL, &emlen, in, inlen) <= 0 ||
        emlen != k) {
        /* Modulus-wide but unusable (e.g. above n): a verdict,
         * uniform with every other padding failure. */
        rc = HSK_OSSL4_ERR_AUTHFAIL;
        goto end;
    }
    em = OPENSSL_malloc(emlen);
    if (em == NULL) {
        rc = HSK_OSSL4_ERR_NOMEM;
        goto end;
    }
    if (EVP_PKEY_decrypt(pctx, em, &emlen, in, inlen) <= 0 ||
        emlen != k) {
        rc = HSK_OSSL4_ERR_AUTHFAIL;
        goto end;
    }
    /* Constant-time type-2 unpad via the vetted primitive
     * (EM = 00 02 PS 00 M, |PS| >= 8): the message length, or -1
     * for every padding failure shape — one AUTHFAIL verdict, no
     * secret-dependent branches of our own. Unpad into a scratch
     * k-block, then move exactly mlen bytes to the owned output. */
    msg = OPENSSL_malloc(k);
    if (msg == NULL) {
        rc = HSK_OSSL4_ERR_NOMEM;
        goto end;
    }
    /* Deprecated since 3.0 in favor of EVP, but the EVP padded
     * path answers failures with implicit rejection (no verdict),
     * so the vetted constant-time unpad stays. The toolchain pins
     * OpenSSL 4.0.2, where the symbol ships. */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
    padlen = RSA_padding_check_PKCS1_type_2(msg, ksize, em, ksize, ksize);
#pragma GCC diagnostic pop
    if (padlen < 0) {
        rc = HSK_OSSL4_ERR_AUTHFAIL;
        goto end;
    }
    mlen = (size_t)padlen;
    outbuf = OPENSSL_malloc(mlen > 0 ? mlen : 1);
    if (outbuf == NULL) {
        rc = HSK_OSSL4_ERR_NOMEM;
        goto end;
    }
    if (mlen > 0)
        memcpy(outbuf, msg, mlen);
    *out = outbuf;
    outbuf = NULL;
    rc = (long)mlen;

end:
    /* outbuf is NULL on every arrival (moved to *out on success);
     * msg is the k-byte unpad scratch (cleared whole). */
    if (msg != NULL)
        OPENSSL_clear_free(msg, k);
    if (em != NULL)
        OPENSSL_clear_free(em, emlen);
    EVP_PKEY_CTX_free(pctx);
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