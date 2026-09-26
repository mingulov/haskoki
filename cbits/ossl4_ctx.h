/* Narrow OpenSSL 4 provider-only shim for the Haskoki OpenSSL4 backend.
 *
 * Exposes exactly: private OSSL_LIB_CTX lifecycle, explicit provider
 * load/unload, fetch probing, and typed fetch+run helpers per family.
 * Every helper takes OSSL_LIB_CTX* + property query and returns fresh
 * caller-owned buffers (OPENSSL_malloc); the Haskell side copies them
 * into ByteStrings and releases them with hsk_ossl4_free
 * (OPENSSL_clear_free).
 *
 * Provider-only surface: EVP_MD/EVP_CIPHER/EVP_MAC fetch, EVP_PKEY,
 * OSSL_PARAM, OSSL_PROVIDER_*. No ENGINE_*, no *_meth_*, no low-level
 * RSA_/AES_/EC_KEY_*, no OPENSSL_cleanup/OPENSSL_atexit, and no
 * PKCS#11-backed provider is ever loaded here.
 */
#ifndef HSK_OSSL4_CTX_H
#define HSK_OSSL4_CTX_H

#include <stddef.h>

#include <openssl/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Opaque multipart-digest handle (owns EVP_MD_CTX + fetched EVP_MD). */
typedef struct hsk_ossl4_md hsk_ossl4_md_t;

/* Opaque backend env: owns one private libctx + loaded providers so the
 * Haskell ForeignPtr finalizer tears them down in the right order
 * (unload providers, then free ctx). */
typedef struct hsk_ossl4_env hsk_ossl4_env_t;

/* Error codes (negative return values). AUTHFAIL is a verdict
 * (padding/tag mismatch: wrong key, label, or tampered input), not
 * a malfunction; the Haskell side maps it onto BackendAuthFailed. */
#define HSK_OSSL4_OK 0
#define HSK_OSSL4_ERR_NATIVE (-1)
#define HSK_OSSL4_ERR_BADPARAM (-2)
#define HSK_OSSL4_ERR_BADKEY (-3)
#define HSK_OSSL4_ERR_NOMEM (-4)
#define HSK_OSSL4_ERR_AUTHFAIL (-5)
#define HSK_OSSL4_ERR_BADPEER (-6)

/* --- private context lifecycle -------------------------------------- */

/* Create a fresh private OSSL_LIB_CTX (NULL on failure). */
OSSL_LIB_CTX *hsk_ossl4_new_ctx(void);

/* Load a named provider (e.g. "default") into ctx (NULL on failure). */
OSSL_PROVIDER *hsk_ossl4_load_provider(OSSL_LIB_CTX *ctx, const char *name);

/* Unload one provider previously returned by hsk_ossl4_load_provider. */
void hsk_ossl4_unload_provider(OSSL_PROVIDER *prov);

/* Free a context created by hsk_ossl4_new_ctx. */
void hsk_ossl4_free_ctx(OSSL_LIB_CTX *ctx);

/* --- env wrapper (ordered teardown for one ForeignPtr finalizer) ----- */

hsk_ossl4_env_t *hsk_ossl4_env_new(void);
int hsk_ossl4_env_load(hsk_ossl4_env_t *env, const char *name);
OSSL_LIB_CTX *hsk_ossl4_env_ctx(const hsk_ossl4_env_t *env);
void hsk_ossl4_env_free(hsk_ossl4_env_t *env);

/* --- misc ------------------------------------------------------------ */

/* Static libcrypto version string ("OpenSSL 4.0.2 ..."); do not free. */
const char *hsk_ossl4_version(void);

/* Release a buffer returned by a fetch+run helper (clears it first). */
void hsk_ossl4_free(void *ptr, size_t len);

/* Copy the oldest queued error into buf (NUL-terminated, up to buflen
 * bytes incl. NUL); clears the queue. Returns bytes written excl. NUL. */
size_t hsk_ossl4_last_error(char *buf, size_t buflen);

/* Probe: can kind/name be fetched under propq? kind is "md", "mac",
 * "cipher", or "pkey". Returns 1 (yes), 0 (no), HSK_OSSL4_ERR_* (<0)
 * on misuse (NULL args, unknown kind). */
int hsk_ossl4_probe(OSSL_LIB_CTX *ctx, const char *kind, const char *name,
                    const char *propq);

/* --- one-shot digest ------------------------------------------------- */

/* Returns output length (>=0) with *out set to a fresh buffer, or a
 * negative HSK_OSSL4_ERR_* code with *out untouched. */
long hsk_ossl4_digest(OSSL_LIB_CTX *ctx, const char *mdname, const char *propq,
                      const unsigned char *msg, size_t msglen,
                      unsigned char **out);

/* --- multipart digest ------------------------------------------------ */

hsk_ossl4_md_t *hsk_ossl4_digest_init(OSSL_LIB_CTX *ctx, const char *mdname,
                                     const char *propq);
int hsk_ossl4_digest_update(hsk_ossl4_md_t *h, const unsigned char *msg,
                            size_t msglen);
/* Finalizes and frees the handle; returns output length with *out set,
 * or a negative HSK_OSSL4_ERR_* code. */
long hsk_ossl4_digest_final(hsk_ossl4_md_t *h, unsigned char **out);
void hsk_ossl4_digest_free(hsk_ossl4_md_t *h);

/* --- HMAC ------------------------------------------------------------ */

long hsk_ossl4_hmac(OSSL_LIB_CTX *ctx, const char *mdname, const char *propq,
                    const unsigned char *key, size_t keylen,
                    const unsigned char *msg, size_t msglen,
                    unsigned char **out);

/* --- AES-CBC without padding (input must be block-aligned) ----------- */

/* enc: 1 = encrypt, 0 = decrypt. Key/iv lengths are checked against
 * the fetched cipher; misaligned input returns HSK_OSSL4_ERR_BADPARAM. */
long hsk_ossl4_cipher_cbc(OSSL_LIB_CTX *ctx, const char *ciphername,
                          const char *propq, int enc, const unsigned char *key,
                          size_t keylen, const unsigned char *iv, size_t ivlen,
                          const unsigned char *in, size_t inlen,
                          unsigned char **out);

/* --- AES-CTS (CBC-CS1 over the fetched ECB primitive) ------------------ */

/* enc: 1 = encrypt, 0 = decrypt. The provider has no CTS mode (fetch
 * probe record: "AES-128-CTS" unimplemented), so the shim runs the
 * NIST SP 800-38A Addendum CBC-CS1 construction with the fetched
 * ECB cipher as the block primitive. Wire order is short-tail
 * first, full pair block second (pinned by the ACVP CBC-CS1
 * vectors, not the RFC 3962 order).
 * Key length must match the fetched ECB cipher; iv is one block;
 * input keeps its length and must be >= 1 block (shorter input
 * returns HSK_OSSL4_ERR_BADPARAM). A single-block input degenerates
 * to plain CBC. Output length always equals input length. */
long hsk_ossl4_cipher_cts(OSSL_LIB_CTX *ctx, const char *ecbname,
                          const char *propq, int enc, const unsigned char *key,
                          size_t keylen, const unsigned char *iv, size_t ivlen,
                          const unsigned char *in, size_t inlen,
                          unsigned char **out);

/* --- AES key wrap (RFC 3394 KW / RFC 5649 KWP) ------------------------- */

/* enc: 1 = wrap, 0 = unwrap. kwp: 0 = KW (ciphername AES-*-WRAP),
 * 1 = KWP (ciphername AES-*-WRAP-PAD). The provider implements both
 * (fetch probe record: AES-{128,192,256}-WRAP{,-PAD} fetch from the
 * default provider); the shim runs the fetched cipher one-shot with
 * padding disabled and no IV (wraps use the fixed AIV). Key length
 * must match the fetched cipher. Geometry (provider-proven):
 * KW input is a multiple of 8 bytes and >= 16 (shorter or
 * unaligned input returns HSK_OSSL4_ERR_BADPARAM); KWP input is
 * >= 1 byte (empty input is HSK_OSSL4_ERR_BADPARAM — the provider
 * answers empty input with a vacuous 0-byte success, which the
 * shim refuses rather than emitting a non-unwrappable blob).
 * Output expands: KW outlen is inlen + 8; KWP outlen is
 * ceil8(inlen) + 8. Any decrypt-side EVP failure (integrity)
 * returns HSK_OSSL4_ERR_AUTHFAIL with *out untouched (GCM
 * tag-failure precedent). */
long hsk_ossl4_cipher_wrap(OSSL_LIB_CTX *ctx, const char *ciphername,
                           const char *propq, int enc, int kwp,
                           const unsigned char *key, size_t keylen,
                           const unsigned char *in, size_t inlen,
                           unsigned char **out);

/* --- AES-XTS (IEEE 1619 disk mode) ------------------------------------ */

/* enc: 1 = encrypt, 0 = decrypt. The provider implements XTS (fetch
 * probe record: AES-128-XTS/AES-256-XTS fetch from the default
 * provider; AES-192-XTS is absent); the shim runs the fetched
 * cipher one-shot with padding disabled over the 16-byte tweak IV
 * (tweak rides as the IV). Key length (32/64: data + tweak
 * halves) and tweak length (16) must match the fetched cipher.
 * Geometry (provider-proven): input is >= 16 bytes, any length
 * above (stealing covers ragged tails, length-preserving);
 * shorter input returns HSK_OSSL4_ERR_BADPARAM. Init failure
 * (the provider's equal-halves weak-key refusal) returns
 * HSK_OSSL4_ERR_BADKEY. */
long hsk_ossl4_cipher_xts(OSSL_LIB_CTX *ctx, const char *ciphername,
                          const char *propq, int enc,
                          const unsigned char *key, size_t keylen,
                          const unsigned char *tweak, size_t tweaklen,
                          const unsigned char *in, size_t inlen,
                          unsigned char **out);

/* --- AEAD (AES-GCM; output is ct || tag) ------------------------------- */

/* Encrypt: *out is ct || tag (inlen + taglen bytes). Decrypt takes
 * ct and the expected tag separately; a tag mismatch (or any
 * authentication failure) returns HSK_OSSL4_ERR_AUTHFAIL with *out
 * untouched. Key length must match the fetched cipher; iv 1..64
 * bytes (non-default lengths via SET_IVLEN); tag 1..16 bytes (the
 * recipe admits only the approved widths). */
long hsk_ossl4_aead_encrypt(OSSL_LIB_CTX *ctx, const char *ciphername,
                            const char *propq, const unsigned char *key,
                            size_t keylen, const unsigned char *iv,
                            size_t ivlen, const unsigned char *aad,
                            size_t aadlen, const unsigned char *in,
                            size_t inlen, size_t taglen,
                            unsigned char **out);
long hsk_ossl4_aead_decrypt(OSSL_LIB_CTX *ctx, const char *ciphername,
                            const char *propq, const unsigned char *key,
                            size_t keylen, const unsigned char *iv,
                            size_t ivlen, const unsigned char *aad,
                            size_t aadlen, const unsigned char *in,
                            size_t inlen, const unsigned char *tag,
                            size_t taglen, unsigned char **out);
/* CCM twins: same signatures; nonce 7..13 bytes, tag even 4..16. */
long hsk_ossl4_aead_ccm_encrypt(OSSL_LIB_CTX *ctx, const char *ciphername,
                            const char *propq, const unsigned char *key,
                            size_t keylen, const unsigned char *iv,
                            size_t ivlen, const unsigned char *aad,
                            size_t aadlen, const unsigned char *in,
                            size_t inlen, size_t taglen,
                            unsigned char **out);
long hsk_ossl4_aead_ccm_decrypt(OSSL_LIB_CTX *ctx, const char *ciphername,
                            const char *propq, const unsigned char *key,
                            size_t keylen, const unsigned char *iv,
                            size_t ivlen, const unsigned char *aad,
                            size_t aadlen, const unsigned char *in,
                            size_t inlen, const unsigned char *tag,
                            size_t taglen, unsigned char **out);

/* --- EC keygen (SEC1-traditional + SPKI DER out) ---------------------- */
/* NOTE: the private half is traditional SEC1 (i2d_PrivateKey
 * prefers the traditional encoding), NOT PKCS#8 as the import
 * path ('ecPrivateDer') assembles. Every consumer re-imports
 * through d2i auto-detection, so the split is invisible today;
 * unifying on PKCS#8 needs an oracle length/format audit first
 * (CKA_VALUE reads serve these bytes verbatim). */

int hsk_ossl4_ec_gen(OSSL_LIB_CTX *ctx, const char *groupname,
                     const char *propq, unsigned char **priv_der,
                     size_t *priv_len, unsigned char **pub_der,
                     size_t *pub_len);

/* --- RSA keygen (PKCS#8 + SPKI DER out) ------------------------------- */

/* bits in {2048, 3072, 4096}, e_len/e_be the big-endian public
 * exponent (odd, >= 3); anything else is HSK_OSSL4_ERR_BADPARAM.
 * Ownership mirrors ec_gen (OPENSSL_malloc'd DERs, caller frees). */
int hsk_ossl4_rsa_gen_keypair(OSSL_LIB_CTX *ctx, int bits,
                              const unsigned char *e_be, size_t e_len,
                              const char *propq, unsigned char **priv_der,
                              size_t *priv_len, unsigned char **pub_der,
                              size_t *pub_len);

/* --- Random bytes ------------------------------------------------ */

/* nbytes of RAND_bytes_ex under ctx (1..1048576); returns the byte
 * count with *out set, or a negative HSK_OSSL4_ERR_* code. */
long hsk_ossl4_rand_bytes(OSSL_LIB_CTX *ctx, size_t nbytes,
                          unsigned char **out);

/* Mix seed[0..seedlen) into the DRBG via RAND_add: additional
 * input only, never a state replacement, with entropy estimate 0.0
 * (the single named home in ossl4_ctx.c -- caller bytes are never
 * credited as entropy). seedlen 0..1048576 (empty is a vacuous OK);
 * returns HSK_OSSL4_OK or a negative HSK_OSSL4_ERR_* code. */
long hsk_ossl4_rand_seed(OSSL_LIB_CTX *ctx, const unsigned char *seed,
                         size_t seedlen);

/* --- ECDSA sign/verify ------------------------------------------------ */

/* priv_der: PKCS#8 DER. want_raw: 0 = DER signature, nonzero = raw
 * fixed-size r||s. no_hash: 0 = hash-and-sign via EVP_DigestSign
 * (mdname fetched under libctx+propq), nonzero = raw operation over
 * the input (mdname ignored; overlong input truncates to the
 * leftmost group-order bits per SEC1 §4.1.3 / PKCS#11 §2.3.1). The
 * curve always follows the key (the DER<->raw conversion derives
 * the coordinate size from the key's point). Returns output length
 * with *out set, or a negative HSK_OSSL4_ERR_* code (bad DER key ->
 * HSK_OSSL4_ERR_BADKEY). */
long hsk_ossl4_ecdsa_sign(OSSL_LIB_CTX *ctx, const char *mdname,
                          const char *propq, const unsigned char *priv_der,
                          size_t priv_len, const unsigned char *msg,
                          size_t msglen, int want_raw, int no_hash,
                          unsigned char **out);

/* pub_der: SPKI DER. is_raw: 0 = DER signature, nonzero = raw r||s.
 * no_hash selects the same operation as sign (overlong input
 * truncates likewise). Malformed DER and odd-length raw
 * signatures answer 0 (mismatch — they can never be valid), as
 * does degenerate verification math landing on the point at
 * infinity (X9.62 §7.4.2 rejects; OpenSSL reports rc -1). Returns
 * 1 (valid), 0 (bad signature), HSK_OSSL4_ERR_BADKEY (bad DER
 * key), or HSK_OSSL4_ERR_* on other failures. */
int hsk_ossl4_ecdsa_verify(OSSL_LIB_CTX *ctx, const char *mdname,
                           const char *propq, const unsigned char *pub_der,
                           size_t pub_len, const unsigned char *msg,
                           size_t msglen, const unsigned char *sig,
                           size_t siglen, int is_raw, int no_hash);

/* --- ECDH agreement ------------------------------------------ */

/* priv_der: PKCS#8 DER base key; peer_der: SPKI DER peer key. cofactor:
 * 0 = plain agreement, nonzero = cofactor multiplication (a no-op on
 * the h=1 NIST prime curves, threaded through for mechanism honesty).
 * Returns the raw x-coordinate secret length with *out set, or a
 * negative HSK_OSSL4_ERR_* code (bad base DER ->
 * HSK_OSSL4_ERR_BADKEY; a rejected peer — bad encoding, off-curve,
 * or a base/peer curve mismatch — answers
 * HSK_OSSL4_ERR_BADPEER: the peer rides in the mechanism
 * parameters, so it is a parameter fault, not a key fault). */
long hsk_ossl4_ecdh_derive(OSSL_LIB_CTX *ctx, const char *propq,
                           const unsigned char *priv_der, size_t priv_len,
                           const unsigned char *peer_der, size_t peer_len,
                           int cofactor, unsigned char **out);

/* --- RSA PKCS#1 v1.5 sign/verify ------------------------------ */

/* priv_der: PKCS#8 DER. raw: 0 = hash-and-sign via EVP_DigestSign
 * (mdname fetched under libctx+propq; PKCS#1 v1.5 is the provider
 * default for RSA), nonzero = raw block-type-1 operation over the
 * input (mdname ignored). Returns output length with *out set, or a
 * negative HSK_OSSL4_ERR_* code (bad DER key -> HSK_OSSL4_ERR_BADKEY). */
long hsk_ossl4_rsa_sign(OSSL_LIB_CTX *ctx, const char *mdname,
                        const char *propq, const unsigned char *priv_der,
                        size_t priv_len, const unsigned char *msg,
                        size_t msglen, int raw, unsigned char **out);

/* pub_der: SPKI DER. raw selects the same operation as sign.
 * Returns 1 (valid), 0 (bad signature), HSK_OSSL4_ERR_BADKEY (bad DER
 * key), or HSK_OSSL4_ERR_* on other failures. */
int hsk_ossl4_rsa_verify(OSSL_LIB_CTX *ctx, const char *mdname,
                         const char *propq, const unsigned char *pub_der,
                         size_t pub_len, const unsigned char *msg,
                         size_t msglen, const unsigned char *sig,
                         size_t siglen, int raw);

/* --- RSA-PSS sign/verify -------------------------------------- */

/* priv_der: PKCS#8 DER. PSS hash-and-sign with explicit MGF1 digest
 * and salt length (negative saltlen is rejected). Returns output
 * length with *out set, or a negative HSK_OSSL4_ERR_* code. */
long hsk_ossl4_rsa_pss_sign(OSSL_LIB_CTX *ctx, const char *mdname,
                            const char *mgfname, int saltlen,
                            const char *propq, const unsigned char *priv_der,
                            size_t priv_len, const unsigned char *msg,
                            size_t msglen, unsigned char **out);

/* pub_der: SPKI DER. Returns 1 (valid), 0 (bad signature),
 * HSK_OSSL4_ERR_BADKEY (bad DER key), or HSK_OSSL4_ERR_* on other
 * failures. */
int hsk_ossl4_rsa_pss_verify(OSSL_LIB_CTX *ctx, const char *mdname,
                             const char *mgfname, int saltlen,
                             const char *propq, const unsigned char *pub_der,
                             size_t pub_len, const unsigned char *msg,
                             size_t msglen, const unsigned char *sig,
                             size_t siglen);

/* --- RSA-OAEP encrypt/decrypt ---------------------------------- */

/* pub_der: SPKI DER. OAEP with explicit hash, MGF1 digest, and label
 * (labellen 0 selects the empty label). Overlong input is
 * HSK_OSSL4_ERR_BADPARAM (typed bound: k - 2*hLen - 2). Returns
 * output length with *out set, or a negative HSK_OSSL4_ERR_* code. */
long hsk_ossl4_rsa_oaep_encrypt(OSSL_LIB_CTX *ctx, const char *mdname,
                               const char *mgfname,
                               const unsigned char *label, size_t labellen,
                               const char *propq, const unsigned char *pub_der,
                               size_t pub_len, const unsigned char *in,
                               size_t inlen, unsigned char **out);

/* priv_der: PKCS#8 DER. Padding/label failures answer
 * HSK_OSSL4_ERR_AUTHFAIL (a verdict); off-modulus input lengths
 * answer HSK_OSSL4_ERR_BADPARAM; internal errors stay
 * HSK_OSSL4_ERR_NATIVE. Returns output length with *out set. */
long hsk_ossl4_rsa_oaep_decrypt(OSSL_LIB_CTX *ctx, const char *mdname,
                               const char *mgfname,
                               const unsigned char *label, size_t labellen,
                               const char *propq, const unsigned char *priv_der,
                               size_t priv_len, const unsigned char *in,
                               size_t inlen, unsigned char **out);

/* --- RSA PKCS#1 v1.5 encrypt/decrypt ------------------------------ */

/* pub_der: SPKI DER. Overlong input is HSK_OSSL4_ERR_BADPARAM
 * (typed bound: k - 11). Returns output length with *out set, or a
 * negative HSK_OSSL4_ERR_* code. */
long hsk_ossl4_rsa_pkcs1_encrypt(OSSL_LIB_CTX *ctx, const char *propq,
                                 const unsigned char *pub_der, size_t pub_len,
                                 const unsigned char *in, size_t inlen,
                                 unsigned char **out);

/* priv_der: PKCS#8 DER. Raw decrypt plus constant-time type-2
 * unpad (the 4.0 provider answers padded v1.5 failures with
 * implicit rejection, which cannot surface a verdict). Padding
 * failures answer HSK_OSSL4_ERR_AUTHFAIL (a verdict, uniform
 * like OAEP); off-modulus input lengths answer
 * HSK_OSSL4_ERR_BADPARAM; internal errors stay
 * HSK_OSSL4_ERR_NATIVE. Returns output length with *out set. */
long hsk_ossl4_rsa_pkcs1_decrypt(OSSL_LIB_CTX *ctx, const char *propq,
                                 const unsigned char *priv_der,
                                 size_t priv_len, const unsigned char *in,
                                 size_t inlen, unsigned char **out);

#ifdef __cplusplus
}
#endif

#endif /* HSK_OSSL4_CTX_H */
