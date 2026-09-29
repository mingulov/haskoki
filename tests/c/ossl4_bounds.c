/* tests/c/ossl4_bounds.c — ossl4 FFI regression proof for audit findings 1-3.
 *
 * Standalone C program (non-Haskell executable): dlopen()s the built
 * libhaskoki shared module, resolves the hsk_ossl4_* entry points,
 * and pins the success + error contracts of the functions the findings 1-3
 * hardening touched (2026-09-29 C audit):
 *   finding 3: AEAD bounds: AES-GCM + AES-CCM round-trips (incl. empty
 *       message and empty AAD) still succeed through the new
 *       outl1+outl2 bound; tampered tags refuse with AUTHFAIL and
 *       *out untouched.
 *   findings 1+2: DH derive: ffdhe2048 KAT (A->B agrees with the pinned CLI
 *       secret from tests/engine/OpenSSLSpec.hs); bad key/peer/param
 *       inputs refuse with the documented codes and *out untouched.
 * The findings-1+2 fault triggers (BN conversion failure, a second-derive
 * provider fault mutating secretlen) are not deterministically
 * inducible against the default provider, so this pins the
 * surrounding contracts instead of the faults themselves.
 *
 * Usage: ossl4_bounds <path-to-libhaskoki.so>
 * Exit status: 0 iff every check passes.
 */

#define _POSIX_C_SOURCE 200809L

#include <dlfcn.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Mirrors cbits/ossl4_ctx.h (opaque libctx/provider stay void* so this
 * driver needs no OpenSSL headers). */
#define HSK_OSSL4_ERR_BADPARAM (-2L)
#define HSK_OSSL4_ERR_BADKEY (-3L)
#define HSK_OSSL4_ERR_AUTHFAIL (-5L)
#define HSK_OSSL4_ERR_BADPEER (-6L)

typedef void *(*fn_new_ctx)(void);
typedef void *(*fn_load_provider)(void *ctx, const char *name);
typedef void (*fn_unload_provider)(void *prov);
typedef void (*fn_free_ctx)(void *ctx);
typedef void (*fn_free)(void *ptr, size_t len);
typedef long (*fn_aead_enc)(void *ctx, const char *ciphername,
                            const char *propq, const unsigned char *key,
                            size_t keylen, const unsigned char *iv,
                            size_t ivlen, const unsigned char *aad,
                            size_t aadlen, const unsigned char *in,
                            size_t inlen, size_t taglen,
                            unsigned char **out);
typedef long (*fn_aead_dec)(void *ctx, const char *ciphername,
                            const char *propq, const unsigned char *key,
                            size_t keylen, const unsigned char *iv,
                            size_t ivlen, const unsigned char *aad,
                            size_t aadlen, const unsigned char *in,
                            size_t inlen, const unsigned char *tag,
                            size_t taglen, unsigned char **out);
typedef long (*fn_dh_derive)(void *ctx, const char *propq,
                             const unsigned char *priv_der, size_t priv_len,
                             const unsigned char *peer_val, size_t peer_len,
                             unsigned char **out);

/* DH KAT (S10e fixtures, tests/engine/OpenSSLSpec.hs): two ffdhe2048
 * pairs from pinned-CLI genpkey; secret is pinned-CLI pkeyutl output. */
static const unsigned char kPrivA[] = {
  0x30, 0x82, 0x01, 0x3f, 0x02, 0x01, 0x00, 0x30, 0x82, 0x01, 0x17, 0x06,
  0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x03, 0x01, 0x30, 0x82,
  0x01, 0x08, 0x02, 0x82, 0x01, 0x01, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xad, 0xf8, 0x54, 0x58, 0xa2, 0xbb, 0x4a, 0x9a, 0xaf,
  0xdc, 0x56, 0x20, 0x27, 0x3d, 0x3c, 0xf1, 0xd8, 0xb9, 0xc5, 0x83, 0xce,
  0x2d, 0x36, 0x95, 0xa9, 0xe1, 0x36, 0x41, 0x14, 0x64, 0x33, 0xfb, 0xcc,
  0x93, 0x9d, 0xce, 0x24, 0x9b, 0x3e, 0xf9, 0x7d, 0x2f, 0xe3, 0x63, 0x63,
  0x0c, 0x75, 0xd8, 0xf6, 0x81, 0xb2, 0x02, 0xae, 0xc4, 0x61, 0x7a, 0xd3,
  0xdf, 0x1e, 0xd5, 0xd5, 0xfd, 0x65, 0x61, 0x24, 0x33, 0xf5, 0x1f, 0x5f,
  0x06, 0x6e, 0xd0, 0x85, 0x63, 0x65, 0x55, 0x3d, 0xed, 0x1a, 0xf3, 0xb5,
  0x57, 0x13, 0x5e, 0x7f, 0x57, 0xc9, 0x35, 0x98, 0x4f, 0x0c, 0x70, 0xe0,
  0xe6, 0x8b, 0x77, 0xe2, 0xa6, 0x89, 0xda, 0xf3, 0xef, 0xe8, 0x72, 0x1d,
  0xf1, 0x58, 0xa1, 0x36, 0xad, 0xe7, 0x35, 0x30, 0xac, 0xca, 0x4f, 0x48,
  0x3a, 0x79, 0x7a, 0xbc, 0x0a, 0xb1, 0x82, 0xb3, 0x24, 0xfb, 0x61, 0xd1,
  0x08, 0xa9, 0x4b, 0xb2, 0xc8, 0xe3, 0xfb, 0xb9, 0x6a, 0xda, 0xb7, 0x60,
  0xd7, 0xf4, 0x68, 0x1d, 0x4f, 0x42, 0xa3, 0xde, 0x39, 0x4d, 0xf4, 0xae,
  0x56, 0xed, 0xe7, 0x63, 0x72, 0xbb, 0x19, 0x0b, 0x07, 0xa7, 0xc8, 0xee,
  0x0a, 0x6d, 0x70, 0x9e, 0x02, 0xfc, 0xe1, 0xcd, 0xf7, 0xe2, 0xec, 0xc0,
  0x34, 0x04, 0xcd, 0x28, 0x34, 0x2f, 0x61, 0x91, 0x72, 0xfe, 0x9c, 0xe9,
  0x85, 0x83, 0xff, 0x8e, 0x4f, 0x12, 0x32, 0xee, 0xf2, 0x81, 0x83, 0xc3,
  0xfe, 0x3b, 0x1b, 0x4c, 0x6f, 0xad, 0x73, 0x3b, 0xb5, 0xfc, 0xbc, 0x2e,
  0xc2, 0x20, 0x05, 0xc5, 0x8e, 0xf1, 0x83, 0x7d, 0x16, 0x83, 0xb2, 0xc6,
  0xf3, 0x4a, 0x26, 0xc1, 0xb2, 0xef, 0xfa, 0x88, 0x6b, 0x42, 0x38, 0x61,
  0x28, 0x5c, 0x97, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02,
  0x01, 0x02, 0x04, 0x1f, 0x02, 0x1d, 0x00, 0x9f, 0xa3, 0xef, 0x2b, 0x4c,
  0x8d, 0xfa, 0x3c, 0x47, 0xdf, 0x39, 0x1c, 0x7a, 0x7b, 0xc8, 0x01, 0x86,
  0x09, 0x29, 0x1f, 0x24, 0xa7, 0x61, 0xa5, 0x69, 0x69, 0x9d, 0xe1,
};
static const unsigned char kPeerB[] = {
  0xc7, 0x5a, 0xe3, 0x46, 0x5d, 0xfd, 0x93, 0xb6, 0xa1, 0xb5, 0x08, 0x41,
  0xc6, 0x79, 0x44, 0x8a, 0x34, 0xef, 0x08, 0x7b, 0x30, 0xed, 0xfe, 0x7c,
  0x25, 0xbd, 0x9d, 0x89, 0x7d, 0x10, 0x5e, 0x6d, 0xd9, 0x43, 0x41, 0x98,
  0x67, 0xa2, 0x00, 0x9e, 0xea, 0x2f, 0x0e, 0x93, 0x1b, 0x19, 0x25, 0xe1,
  0x34, 0x46, 0x88, 0x89, 0xa0, 0x6d, 0x92, 0xc3, 0xa5, 0x25, 0x1a, 0xf1,
  0xb3, 0x9a, 0x40, 0x92, 0xba, 0x99, 0xe1, 0x24, 0xf7, 0x95, 0x85, 0x2a,
  0x9d, 0xe4, 0x6f, 0x85, 0xb4, 0x21, 0xf4, 0xd5, 0x23, 0x2d, 0x73, 0xb0,
  0xb2, 0xba, 0x42, 0xf0, 0x33, 0x60, 0x97, 0x89, 0xf0, 0xca, 0x2b, 0xc3,
  0x16, 0xf7, 0x9b, 0x7a, 0x64, 0xad, 0x04, 0xf4, 0x10, 0xdf, 0xb0, 0x44,
  0x3e, 0xba, 0xc1, 0xe8, 0x84, 0x44, 0x85, 0xe9, 0xe1, 0xc3, 0x77, 0x2e,
  0xf0, 0x55, 0x86, 0x23, 0xa9, 0xef, 0x34, 0x76, 0xff, 0x85, 0x49, 0xd3,
  0xa2, 0x59, 0x51, 0x1e, 0x04, 0x90, 0xa7, 0xb4, 0xaf, 0x4f, 0x8f, 0x0b,
  0x73, 0x58, 0x2e, 0x1c, 0xf2, 0xba, 0xfd, 0xc4, 0x34, 0x86, 0x14, 0x16,
  0x31, 0x97, 0x20, 0x39, 0x38, 0xe4, 0xc9, 0x5e, 0xcb, 0xdd, 0xf0, 0xbc,
  0x63, 0x8d, 0x09, 0xa1, 0x2d, 0x47, 0x3e, 0x5b, 0x1c, 0xc5, 0x76, 0x83,
  0x1e, 0x43, 0xa0, 0xcb, 0x35, 0xf8, 0x56, 0x1e, 0x40, 0xf5, 0xc2, 0x64,
  0xd6, 0x6a, 0x58, 0xf3, 0xfc, 0xc1, 0x4e, 0xd3, 0xbf, 0x9a, 0x71, 0xac,
  0x13, 0x48, 0x10, 0xfc, 0xa2, 0xda, 0x8a, 0x98, 0xc4, 0x7c, 0x3d, 0xb5,
  0x5f, 0x05, 0xd2, 0x28, 0xa9, 0xef, 0xd4, 0xa3, 0xde, 0x7d, 0xb7, 0xd1,
  0xe4, 0x5b, 0x79, 0xa0, 0x63, 0x6f, 0xc3, 0xf6, 0x88, 0x5e, 0xfc, 0xe4,
  0x3b, 0x24, 0x90, 0x0b, 0x23, 0x41, 0xef, 0x07, 0x45, 0x43, 0xd5, 0x41,
  0x20, 0xdc, 0xd7, 0x00,
};
static const unsigned char kSecretAB[] = {
  0x96, 0xcb, 0xac, 0xbf, 0xc6, 0xda, 0x3d, 0x06, 0xa2, 0x80, 0x60, 0x52,
  0x84, 0xb5, 0x72, 0x9c, 0xcc, 0xe8, 0x4f, 0x18, 0x96, 0x87, 0x0e, 0xce,
  0x31, 0x46, 0x8d, 0x38, 0xf3, 0x46, 0x3c, 0x90, 0x98, 0xc3, 0x03, 0xe4,
  0xab, 0xc6, 0x7e, 0xda, 0xcb, 0xb6, 0xa7, 0x8a, 0x07, 0x4a, 0x86, 0x9e,
  0xa3, 0x2e, 0x29, 0x3f, 0x62, 0x1a, 0xc0, 0x54, 0x62, 0x14, 0x31, 0x09,
  0x32, 0xa0, 0x24, 0xe9, 0x1f, 0x0f, 0x9f, 0x60, 0xff, 0x8b, 0x32, 0x9c,
  0xf6, 0x55, 0x73, 0x40, 0x12, 0xa6, 0x7f, 0xb3, 0x7c, 0xc0, 0x3a, 0x28,
  0x15, 0x22, 0xb5, 0x6c, 0x52, 0x94, 0x4f, 0x03, 0x32, 0x81, 0x0a, 0xd2,
  0xa7, 0xc4, 0x68, 0x0c, 0xe6, 0x4d, 0xb5, 0xc1, 0x31, 0x55, 0x15, 0x3d,
  0xfa, 0x9e, 0xce, 0x12, 0x16, 0x22, 0xc9, 0x33, 0x8b, 0x60, 0x54, 0x41,
  0x09, 0x7d, 0x4a, 0x5c, 0x83, 0xda, 0x8d, 0x8d, 0x52, 0x8c, 0xeb, 0x3b,
  0x25, 0x50, 0xeb, 0x6b, 0x2d, 0xfd, 0xb2, 0xf7, 0x6f, 0xfa, 0x8f, 0xbc,
  0xb6, 0xaa, 0xbf, 0x7e, 0x93, 0x49, 0x5c, 0x84, 0xc3, 0x95, 0xc9, 0xe2,
  0xd2, 0xa2, 0x44, 0x2b, 0x61, 0x7f, 0x2a, 0xf6, 0x5e, 0xf6, 0x34, 0x36,
  0xee, 0x5d, 0xf3, 0x63, 0x4b, 0x53, 0x0b, 0x93, 0x73, 0xf3, 0xc9, 0x85,
  0xa9, 0x1d, 0x49, 0x30, 0x99, 0x5e, 0x1b, 0x05, 0xdb, 0x29, 0xd8, 0x2d,
  0x95, 0x76, 0x2e, 0x42, 0x02, 0x5f, 0x58, 0xf5, 0x9e, 0x08, 0xc8, 0x05,
  0xe6, 0x5b, 0xe0, 0x3c, 0x13, 0x10, 0x16, 0xf0, 0x5c, 0x1c, 0xfe, 0xc0,
  0x8c, 0x94, 0xa0, 0x46, 0xec, 0x05, 0x30, 0x48, 0x5d, 0x3d, 0x85, 0x16,
  0xe9, 0xde, 0x0a, 0x33, 0x1e, 0x6e, 0xc0, 0x41, 0xcc, 0x35, 0x4c, 0x7b,
  0x44, 0x95, 0x0f, 0x18, 0x11, 0xdf, 0xe0, 0x63, 0x24, 0x27, 0x81, 0xd7,
  0xa7, 0xfe, 0x0c, 0xc4,
};

static int gFails = 0;

#define CHECK(cond, msg) do { \
    if (!(cond)) { \
      printf("FAIL: %s (line %d)\n", (msg), __LINE__); \
      gFails++; \
    } else { \
      printf("ok: %s\n", (msg)); \
    } \
  } while (0)

static fn_free pFree;

/* Fixed 43-byte message (deliberately not block-aligned). */
static const unsigned char kMsg[] = "the quick brown fox jumps over 43 bytes!..";
static const unsigned char kAad[] = "aad-vec!";

static void fill_key_iv(unsigned char *key, unsigned char *iv) {
  size_t i;
  for (i = 0; i < 32; i++) {
    key[i] = (unsigned char)(0x10 + i);
  }
  for (i = 0; i < 12; i++) {
    iv[i] = (unsigned char)(0xa0 + i);
  }
}

/* One AEAD round-trip through the bound-check helpers: encrypt, split
 * ct || tag, decrypt, compare. Returns 1 on full agreement. */
static int roundtrip(void *lctx, fn_aead_enc enc, fn_aead_dec dec,
                     const char *cipher, const unsigned char *key,
                     size_t keylen, const unsigned char *iv, size_t ivlen,
                     const unsigned char *aad, size_t aadlen,
                     const unsigned char *in, size_t inlen, size_t taglen) {
  unsigned char *ct = NULL;
  unsigned char *pt = NULL;
  long enclen;
  long declen;
  int ok = 0;
  enclen = enc(lctx, cipher, "provider=default", key, keylen, iv, ivlen,
               aad, aadlen, in, inlen, taglen, &ct);
  if (enclen != (long)(inlen + taglen) || ct == NULL) {
    return 0;
  }
  declen = dec(lctx, cipher, "provider=default", key, keylen, iv, ivlen,
               aad, aadlen, ct, inlen, ct + inlen, taglen, &pt);
  if (declen == (long)inlen && pt != NULL &&
      (inlen == 0 || memcmp(pt, in, inlen) == 0)) {
    ok = 1;
  }
  if (ct != NULL) {
    pFree(ct, (size_t)enclen);
  }
  if (pt != NULL) {
    pFree(pt, declen > 0 ? (size_t)declen : 0);
  }
  return ok;
}

int main(int argc, char **argv) {
  void *h;
  fn_new_ctx pNewCtx;
  fn_load_provider pLoad;
  fn_unload_provider pUnload;
  fn_free_ctx pFreeCtx;
  fn_aead_enc pGcmEnc;
  fn_aead_dec pGcmDec;
  fn_aead_enc pCcmEnc;
  fn_aead_dec pCcmDec;
  fn_dh_derive pDh;
  void *lctx;
  void *prov;
  unsigned char key[32];
  unsigned char iv[12];
  unsigned char *out = NULL;
  unsigned char *ct = NULL;
  long rc;

  if (argc != 2) {
    fprintf(stderr, "usage: %s <libhaskoki.so>\n", argv[0]);
    return 2;
  }
  h = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
  if (!h) {
    fprintf(stderr, "dlopen failed: %s\n", dlerror());
    return 2;
  }
  pNewCtx = (fn_new_ctx)dlsym(h, "hsk_ossl4_new_ctx");
  pLoad = (fn_load_provider)dlsym(h, "hsk_ossl4_load_provider");
  pUnload = (fn_unload_provider)dlsym(h, "hsk_ossl4_unload_provider");
  pFreeCtx = (fn_free_ctx)dlsym(h, "hsk_ossl4_free_ctx");
  pFree = (fn_free)dlsym(h, "hsk_ossl4_free");
  pGcmEnc = (fn_aead_enc)dlsym(h, "hsk_ossl4_aead_encrypt");
  pGcmDec = (fn_aead_dec)dlsym(h, "hsk_ossl4_aead_decrypt");
  pCcmEnc = (fn_aead_enc)dlsym(h, "hsk_ossl4_aead_ccm_encrypt");
  pCcmDec = (fn_aead_dec)dlsym(h, "hsk_ossl4_aead_ccm_decrypt");
  pDh = (fn_dh_derive)dlsym(h, "hsk_ossl4_dh_derive");
  CHECK(pNewCtx && pLoad && pUnload && pFreeCtx && pFree &&
        pGcmEnc && pGcmDec && pCcmEnc && pCcmDec && pDh,
        "ossl4 entry points resolve");
  if (gFails) {
    return 1;
  }
  lctx = pNewCtx();
  CHECK(lctx != NULL, "libctx opens");
  if (gFails) {
    return 1;
  }
  prov = pLoad(lctx, "default");
  CHECK(prov != NULL, "default provider loads");
  if (gFails) {
    return 1;
  }
  fill_key_iv(key, iv);

  /* bound-check: GCM round-trips through the new bound. */
  CHECK(roundtrip(lctx, pGcmEnc, pGcmDec, "AES-256-GCM", key, sizeof(key),
                  iv, sizeof(iv), kAad, sizeof(kAad),
                  kMsg, sizeof(kMsg), 16),
        "gcm round-trip (43-byte msg, aad, tag16)");
  CHECK(roundtrip(lctx, pGcmEnc, pGcmDec, "AES-256-GCM", key, sizeof(key),
                  iv, sizeof(iv), kAad, sizeof(kAad), NULL, 0, 16),
        "gcm round-trip (empty msg)");
  CHECK(roundtrip(lctx, pGcmEnc, pGcmDec, "AES-256-GCM", key, sizeof(key),
                  iv, sizeof(iv), NULL, 0, kMsg, sizeof(kMsg), 16),
        "gcm round-trip (empty aad)");

  /* bound-check: GCM error legs — codes plus *out untouched. */
  rc = pGcmEnc(lctx, "AES-256-GCM", "provider=default", key, sizeof(key),
               iv, sizeof(iv), kAad, sizeof(kAad), kMsg, sizeof(kMsg), 16,
               &ct);
  CHECK(rc == (long)(sizeof(kMsg) + 16) && ct != NULL, "gcm enc for tamper leg");
  if (ct != NULL && rc > 0) {
    unsigned char *pt = NULL;
    ct[sizeof(kMsg)] ^= 0x01; /* flip one tag bit */
    rc = pGcmDec(lctx, "AES-256-GCM", "provider=default", key, sizeof(key),
                 iv, sizeof(iv), kAad, sizeof(kAad), ct, sizeof(kMsg),
                 ct + sizeof(kMsg), 16, &pt);
    CHECK(rc == HSK_OSSL4_ERR_AUTHFAIL && pt == NULL,
          "gcm tampered tag is AUTHFAIL, out untouched");
    pFree(ct, sizeof(kMsg) + 16);
    ct = NULL;
  }
  out = NULL;
  rc = pGcmEnc(lctx, "AES-256-GCM", "provider=default", key, sizeof(key) - 1,
               iv, sizeof(iv), NULL, 0, kMsg, sizeof(kMsg), 16, &out);
  CHECK(rc == HSK_OSSL4_ERR_BADPARAM && out == NULL,
        "gcm short key is BADPARAM, out untouched");
  rc = pGcmEnc(lctx, "AES-256-GCM", "provider=default", key, sizeof(key),
               iv, sizeof(iv), NULL, 0, kMsg, sizeof(kMsg), 16, NULL);
  CHECK(rc == HSK_OSSL4_ERR_BADPARAM, "gcm null out is BADPARAM");

  /* bound-check: CCM twins (nonce 12 in 7..13, tag 8 in even 4..16). */
  CHECK(roundtrip(lctx, pCcmEnc, pCcmDec, "AES-256-CCM", key, sizeof(key),
                  iv, sizeof(iv), kAad, sizeof(kAad),
                  kMsg, sizeof(kMsg), 8),
        "ccm round-trip (43-byte msg, aad, tag8)");
  CHECK(roundtrip(lctx, pCcmEnc, pCcmDec, "AES-256-CCM", key, sizeof(key),
                  iv, sizeof(iv), kAad, sizeof(kAad), NULL, 0, 8),
        "ccm round-trip (empty msg)");
  rc = pCcmEnc(lctx, "AES-256-CCM", "provider=default", key, sizeof(key),
               iv, sizeof(iv), kAad, sizeof(kAad), kMsg, sizeof(kMsg), 8,
               &ct);
  CHECK(rc == (long)(sizeof(kMsg) + 8) && ct != NULL, "ccm enc for tamper leg");
  if (ct != NULL && rc > 0) {
    unsigned char *pt = NULL;
    ct[sizeof(kMsg)] ^= 0x01;
    rc = pCcmDec(lctx, "AES-256-CCM", "provider=default", key, sizeof(key),
                 iv, sizeof(iv), kAad, sizeof(kAad), ct, sizeof(kMsg),
                 ct + sizeof(kMsg), 8, &pt);
    CHECK(rc == HSK_OSSL4_ERR_AUTHFAIL && pt == NULL,
          "ccm tampered tag is AUTHFAIL, out untouched");
    pFree(ct, sizeof(kMsg) + 8);
    ct = NULL;
  }
  out = NULL;
  rc = pCcmEnc(lctx, "AES-256-CCM", "provider=default", key, sizeof(key),
               iv, sizeof(iv), NULL, 0, kMsg, sizeof(kMsg), 7, &out);
  CHECK(rc == HSK_OSSL4_ERR_BADPARAM && out == NULL,
        "ccm odd taglen is BADPARAM, out untouched");

  /* derive-KAT: DH derive KAT plus error legs. */
  out = NULL;
  rc = pDh(lctx, "provider=default", kPrivA, sizeof(kPrivA),
           kPeerB, sizeof(kPeerB), &out);
  CHECK(rc == (long)sizeof(kSecretAB) && out != NULL &&
        memcmp(out, kSecretAB, sizeof(kSecretAB)) == 0,
        "dh derive A->B agrees with pinned secret");
  if (out != NULL && rc > 0) {
    pFree(out, (size_t)rc);
    out = NULL;
  }
  {
    static const unsigned char kGarbage[] = "not-a-key";
    static const unsigned char kOne[1] = { 0x01 };
    out = NULL;
    rc = pDh(lctx, "provider=default", kGarbage, sizeof(kGarbage),
             kPeerB, sizeof(kPeerB), &out);
    CHECK(rc == HSK_OSSL4_ERR_BADKEY && out == NULL,
          "dh garbage base is BADKEY, out untouched");
    out = NULL;
    rc = pDh(lctx, "provider=default", kPrivA, sizeof(kPrivA),
             kOne, sizeof(kOne), &out);
    CHECK(rc == HSK_OSSL4_ERR_BADPEER && out == NULL,
          "dh y=1 peer is BADPEER, out untouched");
    out = NULL;
    rc = pDh(lctx, "provider=default", kPrivA, sizeof(kPrivA), NULL, 0,
             &out);
    CHECK(rc == HSK_OSSL4_ERR_BADPEER && out == NULL,
          "dh empty peer is BADPEER, out untouched");
    rc = pDh(lctx, "provider=default", kPrivA, sizeof(kPrivA),
             kPeerB, sizeof(kPeerB), NULL);
    CHECK(rc == HSK_OSSL4_ERR_BADPARAM, "dh null out is BADPARAM");
  }

  pUnload(prov);
  pFreeCtx(lctx);
  dlclose(h);

  if (gFails) {
    printf("RESULT: %d check(s) failed\n", gFails);
    return 1;
  }
  printf("RESULT: all ossl4 bound checks passed\n");
  return 0;
}
