/* tests/c/consumer_aead.c — AEAD application journey on the C surface.
 *
 * Standalone C consumer (non-Haskell executable): dlopen()s the built
 * libhaskoki shared module and drives AES-GCM through the pinned 3.2
 * headers:
 *   - two byte-exact vectors replicated from the engine suite's
 *     pinned oracle root (Python cryptography AESGCM, quoted from
 *     tests/engine/OpenSSLSpec.hs caseAeadReal and
 *     caseAeadEmptyPlaintext, never from memory): key 00..0f,
 *     nonce 00..0b, aad "aad-data", pt "Hello GCM world!" seals to
 *     ct db09cba2... with tag 39f03850...; empty plaintext seals to
 *     the pinned tags with and without AAD
 *   - a tag-negative matrix: flipped tag/ciphertext/AAD/IV bytes,
 *     short and truncated inputs, and decryption under the wrong
 *     key all fail closed with CKR_ENCRYPTED_DATA_INVALID
 *   - the SP 800-38D tag-width sweep (128 down to 32 bits): each
 *     width seals to plaintext length plus tag length and opens
 *     back to the exact plaintext
 *   - pinned refusals: provider-generated IV refused; IV
 *     length/bits disagreement and off-list tag widths never seal
 *
 * Topology: runs identically in direct and proxy modes; every
 * session-touching leg uses the "crypto:" prefix so the parity
 * script excludes these lines from its direct-vs-proxied diff while
 * the legs themselves assert strictly per mode.
 *
 * This TU deliberately includes ONLY the pinned vendor headers; it
 * never consumes provider-generated artifacts (enforced by the
 * driver script's independence guard).
 *
 * Compile with -Ispec/vendor. Part of
 * scripts/test-consumers.sh and scripts/test-proxy-parity.sh.
 * Usage: consumer_aead <path-to-libhaskoki.so>
 */
#define _POSIX_C_SOURCE 200809L

#define CK_PTR *
#define CK_DECLARE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType(*name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType(*name)
/* NULL_PTR comes from the vendored PD header (always defined). */
#include "pkcs11.h"

#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int g_failures = 0;

#define CHECK(cond, ...)                                                   \
  do {                                                                     \
    if (!(cond)) {                                                         \
      printf("FAIL [%s:%d]: ", __FILE__, __LINE__);                        \
      printf(__VA_ARGS__);                                                 \
      printf("\n");                                                        \
      g_failures++;                                                        \
    } else {                                                               \
      printf("ok: ");                                                      \
      printf(__VA_ARGS__);                                                 \
      printf("\n");                                                        \
    }                                                                      \
  } while (0)

/* Topology-scoped checks: prefixed so the parity script excludes them
 * from its direct-vs-proxied diff; the legs assert strictly per mode. */
#define CHECKC(cond, ...)                                                  \
  do {                                                                     \
    if (!(cond)) {                                                         \
      printf("crypto: FAIL [%s:%d]: ", __FILE__, __LINE__);                \
      printf(__VA_ARGS__);                                                 \
      printf("\n");                                                        \
      g_failures++;                                                        \
    } else {                                                               \
      printf("crypto: ok: ");                                              \
      printf(__VA_ARGS__);                                                 \
      printf("\n");                                                        \
    }                                                                      \
  } while (0)

/* Pinned vector bytes, quoted from tests/engine/OpenSSLSpec.hs
 * (caseAeadReal, caseAeadEmptyPlaintext; oracle root: Python
 * cryptography AESGCM). Key 00..0f, nonce 00..0b. */
static const CK_BYTE kKey[16] = {
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
  0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};
static const CK_BYTE kOtherKey[16] = {
  0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
  0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
};
static const CK_BYTE kNonce[12] = {
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
  0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b
};
static const CK_BYTE kCt1[16] = {
  0xdb, 0x09, 0xcb, 0xa2, 0x09, 0x3b, 0xb0, 0x17,
  0x06, 0xf2, 0x16, 0xe5, 0x44, 0xcf, 0x14, 0x29
};
static const CK_BYTE kTag1[16] = {
  0x39, 0xf0, 0x38, 0x50, 0x41, 0xaf, 0xdf, 0xd3,
  0xa2, 0xd5, 0xa8, 0xe8, 0xed, 0x69, 0xa2, 0xe6
};
static const CK_BYTE kTagEmptyAad[16] = {
  0xe0, 0x13, 0x12, 0x14, 0x61, 0x76, 0xab, 0xd6,
  0x43, 0xfc, 0xee, 0x9d, 0x4a, 0x64, 0x01, 0x84
};
static const CK_BYTE kTagEmptyBare[16] = {
  0x43, 0x5b, 0x9b, 0xa1, 0x2d, 0x75, 0xa4, 0xbe,
  0x8a, 0x97, 0x7e, 0xa3, 0xcd, 0x01, 0x18, 0x90
};

static char g_cfg_path[256];

static void write_config(void) {
  static const char body[] = "schema_version = 1\n"
                             "profile = \"real-crypto\"\n"
                             "[storage]\n"
                             "kind = \"memory\"\n"
                             "[engine]\n"
                             "kind = \"openssl\"\n"
                             "allow_synthetic_fallback = false\n"
                             "private_library_context = true\n"
                             "[trace]\n"
                             "enabled = false\n";
  char tmpl[] = "/tmp/haskoki-aead-XXXXXX";
  int fd = mkstemp(tmpl);
  size_t want;
  if (fd < 0) {
    perror("mkstemp");
    exit(2);
  }
  want = sizeof(body) - 1;
  if (write(fd, body, want) != (ssize_t)want) {
    perror("write");
    exit(2);
  }
  close(fd);
  snprintf(g_cfg_path, sizeof(g_cfg_path), "%s", tmpl);
  if (setenv("HASKOKI_CONFIG", g_cfg_path, 1) != 0) {
    perror("setenv");
    exit(2);
  }
}

int main(int argc, char **argv) {
  void *handle;
  CK_C_GetFunctionList pGetList;
  CK_FUNCTION_LIST_PTR f = NULL_PTR;
  CK_RV rv;
  CK_SESSION_HANDLE sess = 0;
  CK_SLOT_ID slots[8];
  CK_ULONG nslots = 8;
  CK_OBJECT_CLASS scls = CKO_SECRET_KEY;
  CK_KEY_TYPE akt = CKK_AES;
  CK_BBOOL bTrue = CK_TRUE, bFalse = CK_FALSE;
  CK_OBJECT_HANDLE key = 0, other = 0;
  CK_BYTE ct[64], pt[64], work[64];
  CK_ULONG ctLen, ptLen;
  const char *topo;
  static const CK_ULONG kWidths[] = { 128, 120, 112, 104, 96, 64, 32 };
  size_t i;

  if (argc != 2) {
    fprintf(stderr, "usage: %s <libhaskoki.so>\n", argv[0]);
    return 2;
  }
  topo = getenv("HASKOKI_CONSUMER_TOPOLOGY");
  printf("topology: %s\n",
         (topo && strcmp(topo, "proxy") == 0) ? "proxy" : "direct");
  write_config();
  handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
  if (!handle) {
    fprintf(stderr, "dlopen failed: %s\n", dlerror());
    return 2;
  }
  pGetList = (CK_C_GetFunctionList)dlsym(handle, "C_GetFunctionList");
  CHECK(pGetList != NULL, "C_GetFunctionList resolves");
  rv = pGetList(&f);
  CHECK(rv == CKR_OK && f, "function list fetches");
  rv = f->C_Initialize(NULL_PTR);
  CHECK(rv == CKR_OK, "C_Initialize ok");

  rv = f->C_GetSlotList(CK_FALSE, slots, &nslots);
  CHECKC(rv == CKR_OK && nslots >= 1, "slot list names a slot");
  rv = f->C_OpenSession(slots[0], CKF_SERIAL_SESSION | CKF_RW_SESSION,
                            NULL_PTR, NULL_PTR, &sess);
  CHECKC(rv == CKR_OK && sess != 0, "session opens");
  rv = f->C_Login(sess, CKU_USER, (CK_UTF8CHAR_PTR)"1234", 4);
  CHECKC(rv == CKR_OK, "user login ok");

  /* Fixed-key import: the vectors need exact key bytes, so the keys
   * arrive via C_CreateObject, not keygen. */
  {
    CK_ATTRIBUTE ktmpl[] = {
      { CKA_CLASS, &scls, sizeof(scls) },
      { CKA_KEY_TYPE, &akt, sizeof(akt) },
      { CKA_VALUE, (CK_VOID_PTR)kKey, sizeof(kKey) },
      { CKA_TOKEN, &bFalse, sizeof(bFalse) },
      { CKA_PRIVATE, &bTrue, sizeof(bTrue) },
      { CKA_ENCRYPT, &bTrue, sizeof(bTrue) },
      { CKA_DECRYPT, &bTrue, sizeof(bTrue) }
    };
    CK_ATTRIBUTE otmpl[] = {
      { CKA_CLASS, &scls, sizeof(scls) },
      { CKA_KEY_TYPE, &akt, sizeof(akt) },
      { CKA_VALUE, (CK_VOID_PTR)kOtherKey, sizeof(kOtherKey) },
      { CKA_TOKEN, &bFalse, sizeof(bFalse) },
      { CKA_PRIVATE, &bTrue, sizeof(bTrue) },
      { CKA_ENCRYPT, &bTrue, sizeof(bTrue) },
      { CKA_DECRYPT, &bTrue, sizeof(bTrue) }
    };
    rv = f->C_CreateObject(sess, ktmpl, 7, &key);
    CHECKC(rv == CKR_OK && key != 0, "vector key imports");
    rv = f->C_CreateObject(sess, otmpl, 7, &other);
    CHECKC(rv == CKR_OK && other != 0, "wrong key imports");
  }

  /* Vector one: "Hello GCM world!" seals to the pinned ct and tag. */
  {
    CK_BYTE iv[12], aad[8];
    CK_AES_GCM_PARAMS gp;
    CK_MECHANISM gm;
    memcpy(iv, kNonce, sizeof(iv));
    memcpy(aad, "aad-data", sizeof(aad));
    gp.pIv = iv;
    gp.ulIvLen = sizeof(iv);
    gp.ulIvBits = sizeof(iv) * 8;
    gp.pAAD = aad;
    gp.ulAADLen = sizeof(aad);
    gp.ulTagBits = 128;
    gm.mechanism = CKM_AES_GCM;
    gm.pParameter = &gp;
    gm.ulParameterLen = sizeof(gp);
    rv = f->C_EncryptInit(sess, &gm, key);
    CHECKC(rv == CKR_OK, "vector one EncryptInit ok");
    ctLen = sizeof(ct);
    rv = f->C_Encrypt(sess, (CK_BYTE_PTR)"Hello GCM world!", 16, ct, &ctLen);
    CHECKC(rv == CKR_OK && ctLen == 32, "vector one seals 32 bytes");
    CHECKC(memcmp(ct, kCt1, 16) == 0, "vector one ct matches");
    CHECKC(memcmp(ct + 16, kTag1, 16) == 0, "vector one tag matches");
    rv = f->C_DecryptInit(sess, &gm, key);
    CHECKC(rv == CKR_OK, "vector one DecryptInit ok");
    ptLen = sizeof(pt);
    rv = f->C_Decrypt(sess, ct, ctLen, pt, &ptLen);
    CHECKC(rv == CKR_OK && ptLen == 16
               && memcmp(pt, "Hello GCM world!", 16) == 0,
           "vector one opens to the plaintext");
  }

  /* Vector two: empty plaintext with AAD seals to the pinned tag. */
  {
    CK_BYTE iv[12], aad[8], lone[1];
    CK_AES_GCM_PARAMS gp;
    CK_MECHANISM gm;
    lone[0] = 0;
    memcpy(iv, kNonce, sizeof(iv));
    memcpy(aad, "aad-data", sizeof(aad));
    gp.pIv = iv;
    gp.ulIvLen = sizeof(iv);
    gp.ulIvBits = sizeof(iv) * 8;
    gp.pAAD = aad;
    gp.ulAADLen = sizeof(aad);
    gp.ulTagBits = 128;
    gm.mechanism = CKM_AES_GCM;
    gm.pParameter = &gp;
    gm.ulParameterLen = sizeof(gp);
    rv = f->C_EncryptInit(sess, &gm, key);
    CHECKC(rv == CKR_OK, "vector two EncryptInit ok");
    ctLen = sizeof(ct);
    rv = f->C_Encrypt(sess, lone, 0, ct, &ctLen);
    CHECKC(rv == CKR_OK && ctLen == 16, "vector two seals tag only");
    CHECKC(memcmp(ct, kTagEmptyAad, 16) == 0, "vector two tag matches");
    rv = f->C_DecryptInit(sess, &gm, key);
    CHECKC(rv == CKR_OK, "vector two DecryptInit ok");
    ptLen = sizeof(pt);
    rv = f->C_Decrypt(sess, ct, ctLen, pt, &ptLen);
    CHECKC(rv == CKR_OK && ptLen == 0, "vector two opens to empty");
  }

  /* Vector three: empty plaintext without AAD seals to its tag. */
  {
    CK_BYTE iv[12], lone[1];
    CK_AES_GCM_PARAMS gp;
    CK_MECHANISM gm;
    lone[0] = 0;
    memcpy(iv, kNonce, sizeof(iv));
    gp.pIv = iv;
    gp.ulIvLen = sizeof(iv);
    gp.ulIvBits = sizeof(iv) * 8;
    gp.pAAD = NULL_PTR;
    gp.ulAADLen = 0;
    gp.ulTagBits = 128;
    gm.mechanism = CKM_AES_GCM;
    gm.pParameter = &gp;
    gm.ulParameterLen = sizeof(gp);
    rv = f->C_EncryptInit(sess, &gm, key);
    CHECKC(rv == CKR_OK, "vector three EncryptInit ok");
    ctLen = sizeof(ct);
    rv = f->C_Encrypt(sess, lone, 0, ct, &ctLen);
    CHECKC(rv == CKR_OK && ctLen == 16, "vector three seals tag only");
    CHECKC(memcmp(ct, kTagEmptyBare, 16) == 0, "vector three tag matches");
    rv = f->C_DecryptInit(sess, &gm, key);
    CHECKC(rv == CKR_OK, "vector three DecryptInit ok");
    ptLen = sizeof(pt);
    rv = f->C_Decrypt(sess, ct, ctLen, pt, &ptLen);
    CHECKC(rv == CKR_OK && ptLen == 0, "vector three opens to empty");
  }

  /* Tag-negative matrix over the vector-one seal. */
  {
    CK_BYTE iv[12], aad[8], adaad[8];
    CK_AES_GCM_PARAMS gp;
    CK_MECHANISM gm;
    memcpy(iv, kNonce, sizeof(iv));
    memcpy(aad, "aad-data", sizeof(aad));
    memcpy(adaad, "aad-datX", sizeof(adaad));
    gp.pIv = iv;
    gp.ulIvLen = sizeof(iv);
    gp.ulIvBits = sizeof(iv) * 8;
    gp.pAAD = aad;
    gp.ulAADLen = sizeof(aad);
    gp.ulTagBits = 128;
    gm.mechanism = CKM_AES_GCM;
    gm.pParameter = &gp;
    gm.ulParameterLen = sizeof(gp);
    rv = f->C_EncryptInit(sess, &gm, key);
    CHECKC(rv == CKR_OK, "matrix seal EncryptInit ok");
    ctLen = sizeof(ct);
    rv = f->C_Encrypt(sess, (CK_BYTE_PTR)"Hello GCM world!", 16, ct, &ctLen);
    CHECKC(rv == CKR_OK && ctLen == 32, "matrix seal ok");

    memcpy(work, ct, 32);
    work[31] ^= 0x01;
    rv = f->C_DecryptInit(sess, &gm, key);
    CHECKC(rv == CKR_OK, "matrix tag-flip DecryptInit ok");
    ptLen = sizeof(pt);
    rv = f->C_Decrypt(sess, work, 32, pt, &ptLen);
    CHECKC(rv == CKR_ENCRYPTED_DATA_INVALID, "flipped tag fails closed");

    memcpy(work, ct, 32);
    work[0] ^= 0x01;
    rv = f->C_DecryptInit(sess, &gm, key);
    CHECKC(rv == CKR_OK, "matrix ct-flip DecryptInit ok");
    ptLen = sizeof(pt);
    rv = f->C_Decrypt(sess, work, 32, pt, &ptLen);
    CHECKC(rv == CKR_ENCRYPTED_DATA_INVALID, "flipped ct fails closed");

    gp.pAAD = adaad;
    rv = f->C_DecryptInit(sess, &gm, key);
    CHECKC(rv == CKR_OK, "matrix aad-swap DecryptInit ok");
    ptLen = sizeof(pt);
    rv = f->C_Decrypt(sess, ct, 32, pt, &ptLen);
    CHECKC(rv == CKR_ENCRYPTED_DATA_INVALID, "changed AAD fails closed");
    gp.pAAD = aad;

    iv[0] ^= 0x01;
    rv = f->C_DecryptInit(sess, &gm, key);
    CHECKC(rv == CKR_OK, "matrix iv-flip DecryptInit ok");
    ptLen = sizeof(pt);
    rv = f->C_Decrypt(sess, ct, 32, pt, &ptLen);
    CHECKC(rv == CKR_ENCRYPTED_DATA_INVALID, "flipped IV fails closed");
    iv[0] ^= 0x01;

    rv = f->C_DecryptInit(sess, &gm, key);
    CHECKC(rv == CKR_OK, "matrix short DecryptInit ok");
    ptLen = sizeof(pt);
    rv = f->C_Decrypt(sess, ct, 4, pt, &ptLen);
    CHECKC(rv == CKR_ENCRYPTED_DATA_INVALID, "short input fails closed");

    rv = f->C_DecryptInit(sess, &gm, key);
    CHECKC(rv == CKR_OK, "matrix truncated DecryptInit ok");
    ptLen = sizeof(pt);
    rv = f->C_Decrypt(sess, ct, 31, pt, &ptLen);
    CHECKC(rv == CKR_ENCRYPTED_DATA_INVALID, "truncated seal fails closed");

    rv = f->C_DecryptInit(sess, &gm, other);
    CHECKC(rv == CKR_OK, "matrix wrong-key DecryptInit ok");
    ptLen = sizeof(pt);
    rv = f->C_Decrypt(sess, ct, 32, pt, &ptLen);
    CHECKC(rv == CKR_ENCRYPTED_DATA_INVALID, "wrong key fails closed");
  }

  /* Tag-width sweep: each approved width seals pt plus tag bytes. */
  for (i = 0; i < 7; i++) {
    CK_BYTE iv[12], aad[8];
    CK_AES_GCM_PARAMS gp;
    CK_MECHANISM gm;
    CK_ULONG want = 16 + kWidths[i] / 8;
    memcpy(iv, kNonce, sizeof(iv));
    memcpy(aad, "aad-data", sizeof(aad));
    gp.pIv = iv;
    gp.ulIvLen = sizeof(iv);
    gp.ulIvBits = sizeof(iv) * 8;
    gp.pAAD = aad;
    gp.ulAADLen = sizeof(aad);
    gp.ulTagBits = kWidths[i];
    gm.mechanism = CKM_AES_GCM;
    gm.pParameter = &gp;
    gm.ulParameterLen = sizeof(gp);
    rv = f->C_EncryptInit(sess, &gm, key);
    CHECKC(rv == CKR_OK, "width sweep EncryptInit ok");
    ctLen = sizeof(ct);
    rv = f->C_Encrypt(sess, (CK_BYTE_PTR)"Hello GCM world!", 16, ct, &ctLen);
    CHECKC(rv == CKR_OK && ctLen == want, "width sweep seals exact bytes");
    rv = f->C_DecryptInit(sess, &gm, key);
    CHECKC(rv == CKR_OK, "width sweep DecryptInit ok");
    ptLen = sizeof(pt);
    rv = f->C_Decrypt(sess, ct, ctLen, pt, &ptLen);
    CHECKC(rv == CKR_OK && ptLen == 16
               && memcmp(pt, "Hello GCM world!", 16) == 0,
           "width sweep opens to the plaintext");
  }

  /* Pinned refusals: generated IV, IV disagreement, off-list width. */
  {
    CK_BYTE iv[12], aad[8];
    CK_AES_GCM_PARAMS gp;
    CK_MECHANISM gm;
    memcpy(iv, kNonce, sizeof(iv));
    memcpy(aad, "aad-data", sizeof(aad));
    gp.pIv = iv;
    gp.ulIvLen = sizeof(iv);
    gp.ulIvBits = sizeof(iv) * 8;
    gp.pAAD = aad;
    gp.ulAADLen = sizeof(aad);
    gp.ulTagBits = 128;
    gm.mechanism = CKM_AES_GCM;
    gm.pParameter = &gp;
    gm.ulParameterLen = sizeof(gp);
    gp.ulIvLen = 0;
    gp.ulIvBits = 96;
    rv = f->C_EncryptInit(sess, &gm, key);
    CHECKC(rv == CKR_ARGUMENTS_BAD, "generated IV refused");
    gp.ulIvLen = sizeof(iv);
    gp.ulIvBits = 64;
    rv = f->C_EncryptInit(sess, &gm, key);
    CHECKC(rv != CKR_OK, "IV length/bits disagreement never seals");
    printf("crypto: note: IV disagreement rv=0x%lx\n", (unsigned long)rv);
    gp.ulIvBits = sizeof(iv) * 8;
    gp.ulTagBits = 16;
    rv = f->C_EncryptInit(sess, &gm, key);
    CHECKC(rv != CKR_OK, "off-list tag width never seals");
    printf("crypto: note: off-list width rv=0x%lx\n", (unsigned long)rv);
  }

  rv = f->C_Logout(sess);
  CHECKC(rv == CKR_OK, "logout ok");
  rv = f->C_CloseSession(sess);
  CHECKC(rv == CKR_OK, "CloseSession ok");
  rv = f->C_Finalize(NULL_PTR);
  CHECK(rv == CKR_OK, "C_Finalize ok");
  rv = f->C_OpenSession(slots[0], CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR,
                        &sess);
  CHECK(rv == CKR_CRYPTOKI_NOT_INITIALIZED,
        "post-finalize OpenSession needs init");

  dlclose(handle);
  unlink(g_cfg_path);
  if (g_failures == 0) {
    printf("PASS: consumer_aead (%s)\n", argv[1]);
    return 0;
  }
  printf("FAILURES: %d\n", g_failures);
  return 1;
}