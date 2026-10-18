/* tests/c/consumer_siglen_range.c — wrong-length signatures refuse
 * end to end with CKR_SIGNATURE_LEN_RANGE.
 *
 * Every asymmetric signature family requires its length: RSA one
 * modulus width, raw DSA twice the order width, EdDSA/ML-DSA/SLH-DSA
 * their fixed widths, and raw ECDSA any even non-zero length up to
 * twice the wider of the order and coordinate widths. For each
 * family this consumer signs, verifies the exact bytes, then
 * verifies overlong (zero-appended), short (truncated) and tiny
 * (9-byte) forgeries and expects CKR_SIGNATURE_LEN_RANGE every
 * time; a right-length tampered signature still fails with
 * CKR_SIGNATURE_INVALID. Raw ECDSA also runs the zero-padded-halves
 * shape, the short-form positives (stripped P-521, padded
 * secp160r1), and the bound-plus-two refusal.
 *
 * Standalone C consumer (non-Haskell executable): dlopen()s the built
 * libhaskoki shared module and drives it through the pinned 3.2 headers.
 * This TU deliberately includes ONLY the pinned vendor headers; it never
 * consumes provider-generated artifacts (enforced by the driver script's
 * independence guard).
 *
 * Compile with -Ispec/vendor. Part of scripts/test-consumers.sh.
 * Usage: consumer_siglen_range <path-to-libhaskoki.so>
 */
#define _POSIX_C_SOURCE 200809L

#define CK_PTR *
#define CK_DECLARE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType(*name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType(*name)
#include "pkcs11.h"

#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_failures = 0;

#define CHECK(cond, ...)                                                   \
  do {                                                                     \
    if (!(cond)) {                                                         \
      printf("FAIL [%s:%d]: ", __FILE__, __LINE__);                        \
      printf(__VA_ARGS__);                                                 \
      printf("\n");                                                        \
      g_failures++;                                                        \
    }                                                                      \
  } while (0)

static CK_FUNCTION_LIST_PTR f = NULL;
static CK_BBOOL bTrue = CK_TRUE, bFalse = CK_FALSE;
static CK_OBJECT_CLASS pubcls = CKO_PUBLIC_KEY, privcls = CKO_PRIVATE_KEY;

/* One C_Verify round: init, verify, compare the code. */
static void verify_expect(CK_SESSION_HANDLE s, CK_MECHANISM *mech,
                          CK_OBJECT_HANDLE pub, const CK_BYTE *msg,
                          CK_ULONG msgLen, const CK_BYTE *sig, CK_ULONG sigLen,
                          CK_RV want, const char *tag) {
  CK_RV rv = f->C_VerifyInit(s, mech, pub);
  CHECK(rv == CKR_OK, "%s: VerifyInit ok (rv=0x%lx)", tag,
        (unsigned long)rv);
  if (rv != CKR_OK) {
    return;
  }
  rv = f->C_Verify(s, (CK_BYTE_PTR)msg, msgLen, (CK_BYTE_PTR)sig, sigLen);
  CHECK(rv == want, "%s: verify gives 0x%lx, want 0x%lx", tag,
        (unsigned long)rv, (unsigned long)want);
}

/* Sign once into sig (cap-sized): the length, or 0 on failure. */
static CK_ULONG sign_once(CK_SESSION_HANDLE s, CK_MECHANISM *mech,
                          CK_OBJECT_HANDLE priv, const CK_BYTE *msg,
                          CK_ULONG msgLen, CK_BYTE *sig, CK_ULONG cap,
                          const char *tag) {
  CK_ULONG sigLen = cap;
  CK_RV rv = f->C_SignInit(s, mech, priv);
  CHECK(rv == CKR_OK, "%s: SignInit ok (rv=0x%lx)", tag,
        (unsigned long)rv);
  if (rv != CKR_OK) {
    return 0;
  }
  rv = f->C_Sign(s, (CK_BYTE_PTR)msg, msgLen, sig, &sigLen);
  CHECK(rv == CKR_OK, "%s: signs (rv=0x%lx)", tag, (unsigned long)rv);
  if (rv != CKR_OK) {
    return 0;
  }
  return sigLen;
}

/* Full length battery for one family: exact verifies, overlong /
 * short / tiny refuse by length, right-length tamper mismatches. */
static void family(CK_SESSION_HANDLE s, CK_MECHANISM *mech,
                   CK_OBJECT_HANDLE pub, CK_OBJECT_HANDLE priv,
                   const CK_BYTE *msg, CK_ULONG msgLen, CK_ULONG width,
                   const char *tag) {
  static CK_BYTE sig[8192];
  static CK_BYTE bad[8192];
  static CK_BYTE pad[8192];
  CK_ULONG sigLen = sizeof(sig);
  CK_ULONG half, i;
  CK_RV rv;

  CHECK(width + 128 < sizeof(sig), "%s: width %lu fits scratch", tag,
        (unsigned long)width);
  rv = f->C_SignInit(s, mech, priv);
  CHECK(rv == CKR_OK, "%s: SignInit ok (rv=0x%lx)", tag, (unsigned long)rv);
  rv = f->C_Sign(s, (CK_BYTE_PTR)msg, msgLen, sig, &sigLen);
  CHECK(rv == CKR_OK && sigLen == width, "%s: signs %lu bytes (rv=0x%lx)", tag,
        (unsigned long)width, (unsigned long)rv);
  if (rv != CKR_OK || sigLen != width) {
    return;
  }
  verify_expect(s, mech, pub, msg, msgLen, sig, sigLen, CKR_OK, tag);
  /* Overlong: the valid bytes plus 16 zeros. */
  memcpy(bad, sig, sigLen);
  memset(bad + sigLen, 0, 16);
  verify_expect(s, mech, pub, msg, msgLen, bad, sigLen + 16,
                CKR_SIGNATURE_LEN_RANGE, tag);
  /* Short: one byte truncated. */
  verify_expect(s, mech, pub, msg, msgLen, sig, sigLen - 1,
                CKR_SIGNATURE_LEN_RANGE, tag);
  /* Tiny: 9 bytes can never hold a signature. */
  verify_expect(s, mech, pub, msg, msgLen, sig, 9,
                CKR_SIGNATURE_LEN_RANGE, tag);
  /* Right-length tamper still mismatches, never length-refuses. */
  memcpy(bad, sig, sigLen);
  bad[sigLen - 1] ^= 0xFF;
  if (memcmp(bad, sig, sigLen) == 0) {
    bad[sigLen - 1] ^= 0x01;
  }
  verify_expect(s, mech, pub, msg, msgLen, bad, sigLen,
                CKR_SIGNATURE_INVALID, tag);
  /* Zero-padded halves (raw EC/DSA shape): 64 zeros before each
   * half keep the numeric value and must still refuse by length. */
  if (width <= 128 && (width % 2) == 0) {
    half = width / 2;
    memset(pad, 0, 64);
    memcpy(pad + 64, sig, half);
    memset(pad + 64 + half, 0, 64);
    memcpy(pad + 128 + half, sig + half, half);
    verify_expect(s, mech, pub, msg, msgLen, pad, width + 128,
                  CKR_SIGNATURE_LEN_RANGE, tag);
  }
  for (i = 0; i < sizeof(sig); i++) {
    sig[i] = 0;
    bad[i] = 0;
    pad[i] = 0;
  }
}

int main(int argc, char **argv) {
  CK_RV rv;
  CK_C_GetFunctionList getList = NULL;
  void *dl = NULL;
  CK_SLOT_ID slots[8];
  CK_ULONG nslots = 8;
  CK_SESSION_HANDLE sess = 0;
  CK_BYTE msg[] = "siglen-range probe";
  CK_BYTE raw32[32];
  CK_ULONG i;

  static CK_BYTE p256[] = {
    0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07
  };
  static CK_BYTE edParams[] = { 0x06, 0x03, 0x2b, 0x65, 0x70 };

  if (argc != 2) {
    fprintf(stderr, "usage: %s <libhaskoki.so>\n", argv[0]);
    return 2;
  }
  dl = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
  CHECK(dl != NULL, "dlopen %s", argv[1]);
  if (dl == NULL) {
    return 1;
  }
  getList = (CK_C_GetFunctionList)dlsym(dl, "C_GetFunctionList");
  CHECK(getList != NULL, "dlsym C_GetFunctionList");
  if (getList == NULL) {
    return 1;
  }
  rv = getList(&f);
  CHECK(rv == CKR_OK && f != NULL, "C_GetFunctionList ok");
  if (rv != CKR_OK || f == NULL) {
    return 1;
  }
  rv = f->C_Initialize(NULL_PTR);
  CHECK(rv == CKR_OK, "C_Initialize ok");
  rv = f->C_GetSlotList(CK_FALSE, slots, &nslots);
  CHECK(rv == CKR_OK && nslots >= 1, "slot present");
  rv = f->C_OpenSession(slots[0], CKF_SERIAL_SESSION | CKF_RW_SESSION,
                        NULL_PTR, NULL_PTR, &sess);
  CHECK(rv == CKR_OK && sess != 0, "OpenSession RW ok");
  rv = f->C_Login(sess, CKU_USER, (CK_UTF8CHAR_PTR)"1234", 4);
  CHECK(rv == CKR_OK, "Login user ok");

  for (i = 0; i < sizeof(raw32); i++) {
    raw32[i] = (CK_BYTE)(0x30 + i);
  }

  /* RSA-2048 v1.5: exactly one modulus width. */
  {
    CK_OBJECT_HANDLE pub = 0, priv = 0;
    CK_MECHANISM gen, mech;
    CK_ULONG bits = 2048;
    CK_BYTE e[3] = { 0x01, 0x00, 0x01 };
    CK_ATTRIBUTE pubT[] = {
      { CKA_MODULUS_BITS, &bits, sizeof(bits) },
      { CKA_PUBLIC_EXPONENT, e, sizeof(e) },
      { CKA_TOKEN, &bFalse, sizeof(bFalse) },
      { CKA_VERIFY, &bTrue, sizeof(bTrue) }
    };
    CK_ATTRIBUTE privT[] = {
      { CKA_TOKEN, &bFalse, sizeof(bFalse) },
      { CKA_PRIVATE, &bTrue, sizeof(bTrue) },
      { CKA_SENSITIVE, &bTrue, sizeof(bTrue) },
      { CKA_SIGN, &bTrue, sizeof(bTrue) }
    };
    gen.mechanism = CKM_RSA_PKCS_KEY_PAIR_GEN;
    gen.pParameter = NULL_PTR;
    gen.ulParameterLen = 0;
    rv = f->C_GenerateKeyPair(sess, &gen, pubT, 4, privT, 4, &pub, &priv);
    CHECK(rv == CKR_OK && pub != 0 && priv != 0, "RSA pair mints (rv=0x%lx)",
          (unsigned long)rv);
    if (rv == CKR_OK && pub != 0 && priv != 0) {
      mech.mechanism = CKM_SHA256_RSA_PKCS;
      mech.pParameter = NULL_PTR;
      mech.ulParameterLen = 0;
      family(sess, &mech, pub, priv, msg, sizeof(msg) - 1, 256, "rsa");
      /* PSS, X.509 and X9.31 share the modulus-width rule. */
      {
        CK_RSA_PKCS_PSS_PARAMS pss;
        CK_MECHANISM pm, xm, nm;
        CK_BYTE dig32[32];
        CK_ULONG di;
        pss.hashAlg = CKM_SHA256;
        pss.mgf = CKG_MGF1_SHA256;
        pss.sLen = 32;
        pm.mechanism = CKM_SHA256_RSA_PKCS_PSS;
        pm.pParameter = &pss;
        pm.ulParameterLen = sizeof(pss);
        family(sess, &pm, pub, priv, msg, sizeof(msg) - 1, 256,
               "rsa-pss");
        xm.mechanism = CKM_RSA_X_509;
        xm.pParameter = NULL_PTR;
        xm.ulParameterLen = 0;
        family(sess, &xm, pub, priv, msg, sizeof(msg) - 1, 256,
               "rsa-x509");
        for (di = 0; di < sizeof(dig32); di++) {
          dig32[di] = (CK_BYTE)(di * 7 + 1);
        }
        nm.mechanism = CKM_RSA_X9_31;
        nm.pParameter = NULL_PTR;
        nm.ulParameterLen = 0;
        family(sess, &nm, pub, priv, dig32, sizeof(dig32), 256,
               "rsa-x931");
      }
      /* Multi-part verify: the full signature verifies, the
       * truncated one refuses by length at final. */
      {
        static CK_BYTE msig[512];
        static CK_BYTE part1[] = "siglen-range ";
        CK_ULONG fullLen;
        fullLen = sign_once(sess, &mech, priv, msg, sizeof(msg) - 1,
                            msig, sizeof(msig), "rsa-multipart");
        CHECK(fullLen == 256, "rsa-multipart: signs 256 bytes");
        if (fullLen == 256) {
          rv = f->C_VerifyInit(sess, &mech, pub);
          CHECK(rv == CKR_OK, "rsa-multipart: VerifyInit ok (rv=0x%lx)",
                (unsigned long)rv);
          rv = f->C_VerifyUpdate(sess, part1, sizeof(part1) - 1);
          CHECK(rv == CKR_OK, "rsa-multipart: VerifyUpdate 1 ok (rv=0x%lx)",
                (unsigned long)rv);
          rv = f->C_VerifyUpdate(sess, msg + sizeof(part1) - 1,
                                 sizeof(msg) - sizeof(part1));
          CHECK(rv == CKR_OK, "rsa-multipart: VerifyUpdate 2 ok (rv=0x%lx)",
                (unsigned long)rv);
          rv = f->C_VerifyFinal(sess, msig, fullLen);
          CHECK(rv == CKR_OK, "rsa-multipart: full verifies (rv=0x%lx)",
                (unsigned long)rv);
          rv = f->C_VerifyInit(sess, &mech, pub);
          CHECK(rv == CKR_OK, "rsa-multipart: re-VerifyInit ok (rv=0x%lx)",
                (unsigned long)rv);
          rv = f->C_VerifyUpdate(sess, msg, sizeof(msg) - 1);
          CHECK(rv == CKR_OK, "rsa-multipart: VerifyUpdate ok (rv=0x%lx)",
                (unsigned long)rv);
          rv = f->C_VerifyFinal(sess, msig, fullLen - 1);
          CHECK(rv == CKR_SIGNATURE_LEN_RANGE,
                "rsa-multipart: truncated refuses by length (rv=0x%lx)",
                (unsigned long)rv);
        }
      }
      f->C_DestroyObject(sess, pub);
      f->C_DestroyObject(sess, priv);
    }
  }

  /* Raw ECDSA P-256: exactly 64 bytes. */
  {
    CK_OBJECT_HANDLE pub = 0, priv = 0;
    CK_MECHANISM gen, mech;
    CK_ATTRIBUTE pubT[] = {
      { CKA_EC_PARAMS, p256, sizeof(p256) },
      { CKA_TOKEN, &bFalse, sizeof(bFalse) },
      { CKA_VERIFY, &bTrue, sizeof(bTrue) }
    };
    CK_ATTRIBUTE privT[] = {
      { CKA_TOKEN, &bFalse, sizeof(bFalse) },
      { CKA_PRIVATE, &bTrue, sizeof(bTrue) },
      { CKA_SENSITIVE, &bTrue, sizeof(bTrue) },
      { CKA_SIGN, &bTrue, sizeof(bTrue) }
    };
    gen.mechanism = CKM_EC_KEY_PAIR_GEN;
    gen.pParameter = NULL_PTR;
    gen.ulParameterLen = 0;
    rv = f->C_GenerateKeyPair(sess, &gen, pubT, 3, privT, 4, &pub, &priv);
    CHECK(rv == CKR_OK && pub != 0 && priv != 0, "EC pair mints (rv=0x%lx)",
          (unsigned long)rv);
    if (rv == CKR_OK && pub != 0 && priv != 0) {
      mech.mechanism = CKM_ECDSA;
      mech.pParameter = NULL_PTR;
      mech.ulParameterLen = 0;
      family(sess, &mech, pub, priv, raw32, sizeof(raw32), 64, "ecdsa-raw");
      /* Bound + 2 refuses by length; a short even prefix is a
       * length-plausible forgery and mismatches. */
      {
        static CK_BYTE s2[80];
        static CK_BYTE over[80];
        CK_ULONG n2 = sign_once(sess, &mech, priv, raw32, sizeof(raw32),
                                s2, sizeof(s2), "ecdsa-raw");
        CHECK(n2 == 64, "ecdsa-raw: resigns 64 bytes");
        if (n2 == 64) {
          memcpy(over, s2, 64);
          over[64] = 0;
          over[65] = 0;
          verify_expect(sess, &mech, pub, raw32, sizeof(raw32), over, 66,
                        CKR_SIGNATURE_LEN_RANGE, "ecdsa-raw");
          verify_expect(sess, &mech, pub, raw32, sizeof(raw32), s2, 10,
                        CKR_SIGNATURE_INVALID, "ecdsa-raw");
        }
      }
      f->C_DestroyObject(sess, pub);
      f->C_DestroyObject(sess, priv);
    }
  }

  /* Raw ECDSA P-521: a signature with leading-zero bytes stripped
   * from both halves still verifies (130 bytes). */
  {
    static CK_BYTE p521[] = { 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23 };
    CK_OBJECT_HANDLE pub = 0, priv = 0;
    CK_MECHANISM gen, mech;
    CK_BYTE raw66[66];
    CK_ATTRIBUTE pubT[] = {
      { CKA_EC_PARAMS, p521, sizeof(p521) },
      { CKA_TOKEN, &bFalse, sizeof(bFalse) },
      { CKA_VERIFY, &bTrue, sizeof(bTrue) }
    };
    CK_ATTRIBUTE privT[] = {
      { CKA_TOKEN, &bFalse, sizeof(bFalse) },
      { CKA_PRIVATE, &bTrue, sizeof(bTrue) },
      { CKA_SENSITIVE, &bTrue, sizeof(bTrue) },
      { CKA_SIGN, &bTrue, sizeof(bTrue) }
    };
    for (i = 0; i < sizeof(raw66); i++) {
      raw66[i] = (CK_BYTE)(0x40 + i);
    }
    gen.mechanism = CKM_EC_KEY_PAIR_GEN;
    gen.pParameter = NULL_PTR;
    gen.ulParameterLen = 0;
    rv = f->C_GenerateKeyPair(sess, &gen, pubT, 3, privT, 4, &pub, &priv);
    CHECK(rv == CKR_OK && pub != 0 && priv != 0,
          "EC P-521 pair mints (rv=0x%lx)", (unsigned long)rv);
    if (rv == CKR_OK && pub != 0 && priv != 0) {
      static CK_BYTE sig[144];
      static CK_BYTE shortsig[144];
      CK_ULONG tries;
      int found = 0;
      mech.mechanism = CKM_ECDSA;
      mech.pParameter = NULL_PTR;
      mech.ulParameterLen = 0;
      for (tries = 0; tries < 64 && !found; tries++) {
        CK_ULONG n = sign_once(sess, &mech, priv, raw66, sizeof(raw66),
                               sig, sizeof(sig), "ecdsa-p521");
        if (n != 132) {
          CHECK(0, "ecdsa-p521: signs 132 bytes");
          break;
        }
        if (sig[0] == 0 && sig[66] == 0) {
          memcpy(shortsig, sig + 1, 65);
          memcpy(shortsig + 65, sig + 67, 65);
          found = 1;
        }
      }
      CHECK(found, "ecdsa-p521: short signature found in 64 signs");
      if (found) {
        verify_expect(sess, &mech, pub, raw66, sizeof(raw66),
                      shortsig, 130, CKR_OK, "ecdsa-p521");
      }
      f->C_DestroyObject(sess, pub);
      f->C_DestroyObject(sess, priv);
    }
  }

  /* Raw ECDSA secp160r1: the order is 21 bytes against a 20-byte
   * field, so the 40-byte signature pads out to the 42-byte bound
   * form and verifies. */
  {
    static CK_BYTE p160[] = { 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x08 };
    CK_OBJECT_HANDLE pub = 0, priv = 0;
    CK_MECHANISM gen, mech;
    CK_BYTE raw20[20];
    CK_ATTRIBUTE pubT[] = {
      { CKA_EC_PARAMS, p160, sizeof(p160) },
      { CKA_TOKEN, &bFalse, sizeof(bFalse) },
      { CKA_VERIFY, &bTrue, sizeof(bTrue) }
    };
    CK_ATTRIBUTE privT[] = {
      { CKA_TOKEN, &bFalse, sizeof(bFalse) },
      { CKA_PRIVATE, &bTrue, sizeof(bTrue) },
      { CKA_SENSITIVE, &bTrue, sizeof(bTrue) },
      { CKA_SIGN, &bTrue, sizeof(bTrue) }
    };
    for (i = 0; i < sizeof(raw20); i++) {
      raw20[i] = (CK_BYTE)(0x50 + i);
    }
    gen.mechanism = CKM_EC_KEY_PAIR_GEN;
    gen.pParameter = NULL_PTR;
    gen.ulParameterLen = 0;
    rv = f->C_GenerateKeyPair(sess, &gen, pubT, 3, privT, 4, &pub, &priv);
    CHECK(rv == CKR_OK && pub != 0 && priv != 0,
          "EC secp160r1 pair mints (rv=0x%lx)", (unsigned long)rv);
    if (rv == CKR_OK && pub != 0 && priv != 0) {
      static CK_BYTE sig[64];
      static CK_BYTE wide[64];
      CK_ULONG n;
      mech.mechanism = CKM_ECDSA;
      mech.pParameter = NULL_PTR;
      mech.ulParameterLen = 0;
      n = sign_once(sess, &mech, priv, raw20, sizeof(raw20),
                    sig, sizeof(sig), "ecdsa-secp160r1");
      CHECK(n == 40, "ecdsa-secp160r1: signs 40 bytes");
      if (n == 40) {
        wide[0] = 0;
        memcpy(wide + 1, sig, 20);
        wide[21] = 0;
        memcpy(wide + 22, sig + 20, 20);
        verify_expect(sess, &mech, pub, raw20, sizeof(raw20),
                      wide, 42, CKR_OK, "ecdsa-secp160r1");
      }
      f->C_DestroyObject(sess, pub);
      f->C_DestroyObject(sess, priv);
    }
  }

  /* DSA 1024/160: exactly 40 bytes. */
  {
    CK_OBJECT_HANDLE params = 0, pub = 0, priv = 0;
    CK_MECHANISM gen, mech;
    CK_OBJECT_CLASS dpcls = CKO_DOMAIN_PARAMETERS;
    CK_KEY_TYPE dkt = CKK_DSA;
    CK_ULONG pbits = 1024;
    CK_BYTE pbuf[128], qbuf[32], gbuf[128];
    CK_ATTRIBUTE pgtmpl[] = {
      { CKA_CLASS, &dpcls, sizeof(dpcls) },
      { CKA_KEY_TYPE, &dkt, sizeof(dkt) },
      { CKA_PRIME_BITS, &pbits, sizeof(pbits) },
      { CKA_TOKEN, &bFalse, sizeof(bFalse) }
    };
    CK_ATTRIBUTE pget[3];
    CK_ULONG plen = 0, qlen = 0, glen = 0;
    gen.mechanism = CKM_DSA_PARAMETER_GEN;
    gen.pParameter = NULL_PTR;
    gen.ulParameterLen = 0;
    rv = f->C_GenerateKey(sess, &gen, pgtmpl, 4, &params);
    CHECK(rv == CKR_OK && params != 0, "DSA params mint (rv=0x%lx)",
          (unsigned long)rv);
    if (rv == CKR_OK && params != 0) {
      CK_ATTRIBUTE pubT[7], privT[4];
      pget[0].type = CKA_PRIME;
      pget[0].pValue = NULL_PTR;
      pget[0].ulValueLen = 0;
      pget[1].type = CKA_SUBPRIME;
      pget[1].pValue = NULL_PTR;
      pget[1].ulValueLen = 0;
      pget[2].type = CKA_BASE;
      pget[2].pValue = NULL_PTR;
      pget[2].ulValueLen = 0;
      rv = f->C_GetAttributeValue(sess, params, pget, 3);
      plen = pget[0].ulValueLen;
      qlen = pget[1].ulValueLen;
      glen = pget[2].ulValueLen;
      CHECK(rv == CKR_OK && plen <= sizeof(pbuf) && qlen <= sizeof(qbuf) &&
              glen <= sizeof(gbuf) && plen > 0 && qlen > 0 && glen > 0,
            "DSA param lengths sane");
      pget[0].pValue = pbuf;
      pget[0].ulValueLen = plen;
      pget[1].pValue = qbuf;
      pget[1].ulValueLen = qlen;
      pget[2].pValue = gbuf;
      pget[2].ulValueLen = glen;
      rv = f->C_GetAttributeValue(sess, params, pget, 3);
      CHECK(rv == CKR_OK, "DSA params read");
      pubT[0].type = CKA_CLASS;
      pubT[0].pValue = &pubcls;
      pubT[0].ulValueLen = sizeof(pubcls);
      pubT[1].type = CKA_KEY_TYPE;
      pubT[1].pValue = &dkt;
      pubT[1].ulValueLen = sizeof(dkt);
      pubT[2].type = CKA_PRIME;
      pubT[2].pValue = pbuf;
      pubT[2].ulValueLen = plen;
      pubT[3].type = CKA_SUBPRIME;
      pubT[3].pValue = qbuf;
      pubT[3].ulValueLen = qlen;
      pubT[4].type = CKA_BASE;
      pubT[4].pValue = gbuf;
      pubT[4].ulValueLen = glen;
      pubT[5].type = CKA_TOKEN;
      pubT[5].pValue = &bFalse;
      pubT[5].ulValueLen = sizeof(bFalse);
      pubT[6].type = CKA_VERIFY;
      pubT[6].pValue = &bTrue;
      pubT[6].ulValueLen = sizeof(bTrue);
      privT[0].type = CKA_CLASS;
      privT[0].pValue = &privcls;
      privT[0].ulValueLen = sizeof(privcls);
      privT[1].type = CKA_KEY_TYPE;
      privT[1].pValue = &dkt;
      privT[1].ulValueLen = sizeof(dkt);
      privT[2].type = CKA_TOKEN;
      privT[2].pValue = &bFalse;
      privT[2].ulValueLen = sizeof(bFalse);
      privT[3].type = CKA_SIGN;
      privT[3].pValue = &bTrue;
      privT[3].ulValueLen = sizeof(bTrue);
      gen.mechanism = CKM_DSA_KEY_PAIR_GEN;
      gen.pParameter = NULL_PTR;
      gen.ulParameterLen = 0;
      rv = f->C_GenerateKeyPair(sess, &gen, pubT, 7, privT, 4, &pub, &priv);
      CHECK(rv == CKR_OK && pub != 0 && priv != 0, "DSA pair mints (rv=0x%lx)",
            (unsigned long)rv);
      if (rv == CKR_OK && pub != 0 && priv != 0) {
        mech.mechanism = CKM_DSA_SHA256;
        mech.pParameter = NULL_PTR;
        mech.ulParameterLen = 0;
        family(sess, &mech, pub, priv, msg, sizeof(msg) - 1, 40, "dsa");
        f->C_DestroyObject(sess, pub);
        f->C_DestroyObject(sess, priv);
      }
      f->C_DestroyObject(sess, params);
    }
  }

  /* Ed25519: exactly 64 bytes. */
  {
    CK_OBJECT_HANDLE pub = 0, priv = 0;
    CK_MECHANISM gen, mech;
    CK_KEY_TYPE ekt = CKK_EC_EDWARDS;
    CK_ATTRIBUTE pubT[] = {
      { CKA_CLASS, &pubcls, sizeof(pubcls) },
      { CKA_KEY_TYPE, &ekt, sizeof(ekt) },
      { CKA_EC_PARAMS, edParams, sizeof(edParams) },
      { CKA_TOKEN, &bFalse, sizeof(bFalse) },
      { CKA_VERIFY, &bTrue, sizeof(bTrue) }
    };
    CK_ATTRIBUTE privT[] = {
      { CKA_CLASS, &privcls, sizeof(privcls) },
      { CKA_KEY_TYPE, &ekt, sizeof(ekt) },
      { CKA_TOKEN, &bFalse, sizeof(bFalse) },
      { CKA_SIGN, &bTrue, sizeof(bTrue) }
    };
    gen.mechanism = CKM_EC_EDWARDS_KEY_PAIR_GEN;
    gen.pParameter = NULL_PTR;
    gen.ulParameterLen = 0;
    rv = f->C_GenerateKeyPair(sess, &gen, pubT, 5, privT, 4, &pub, &priv);
    CHECK(rv == CKR_OK && pub != 0 && priv != 0, "Edwards pair mints (rv=0x%lx)",
          (unsigned long)rv);
    if (rv == CKR_OK && pub != 0 && priv != 0) {
      mech.mechanism = CKM_EDDSA;
      mech.pParameter = NULL_PTR;
      mech.ulParameterLen = 0;
      family(sess, &mech, pub, priv, msg, sizeof(msg) - 1, 64, "eddsa");
      f->C_DestroyObject(sess, pub);
      f->C_DestroyObject(sess, priv);
    }
  }

  /* ML-DSA-44: exactly 2420 bytes. */
  {
    CK_OBJECT_HANDLE pub = 0, priv = 0;
    CK_MECHANISM gen, mech;
    CK_KEY_TYPE mkt = CKK_ML_DSA;
    CK_ULONG mset44 = CKP_ML_DSA_44;
    CK_ATTRIBUTE pubT[] = {
      { CKA_CLASS, &pubcls, sizeof(pubcls) },
      { CKA_KEY_TYPE, &mkt, sizeof(mkt) },
      { CKA_PARAMETER_SET, &mset44, sizeof(mset44) },
      { CKA_TOKEN, &bFalse, sizeof(bFalse) },
      { CKA_VERIFY, &bTrue, sizeof(bTrue) }
    };
    CK_ATTRIBUTE privT[] = {
      { CKA_CLASS, &privcls, sizeof(privcls) },
      { CKA_KEY_TYPE, &mkt, sizeof(mkt) },
      { CKA_TOKEN, &bFalse, sizeof(bFalse) },
      { CKA_SIGN, &bTrue, sizeof(bTrue) }
    };
    gen.mechanism = CKM_ML_DSA_KEY_PAIR_GEN;
    gen.pParameter = NULL_PTR;
    gen.ulParameterLen = 0;
    rv = f->C_GenerateKeyPair(sess, &gen, pubT, 5, privT, 4, &pub, &priv);
    CHECK(rv == CKR_OK && pub != 0 && priv != 0, "ML-DSA-44 pair mints (rv=0x%lx)",
          (unsigned long)rv);
    if (rv == CKR_OK && pub != 0 && priv != 0) {
      mech.mechanism = CKM_ML_DSA;
      mech.pParameter = NULL_PTR;
      mech.ulParameterLen = 0;
      family(sess, &mech, pub, priv, msg, sizeof(msg) - 1, 2420, "mldsa");
      f->C_DestroyObject(sess, pub);
      f->C_DestroyObject(sess, priv);
    }
  }

  /* SLH-DSA SHA2-128s (default set): exactly 7856 bytes. */
  {
    CK_OBJECT_HANDLE pub = 0, priv = 0;
    CK_MECHANISM gen, mech;
    CK_KEY_TYPE skt = CKK_SLH_DSA;
    CK_ATTRIBUTE pubT[] = {
      { CKA_CLASS, &pubcls, sizeof(pubcls) },
      { CKA_KEY_TYPE, &skt, sizeof(skt) },
      { CKA_TOKEN, &bFalse, sizeof(bFalse) },
      { CKA_VERIFY, &bTrue, sizeof(bTrue) }
    };
    CK_ATTRIBUTE privT[] = {
      { CKA_CLASS, &privcls, sizeof(privcls) },
      { CKA_KEY_TYPE, &skt, sizeof(skt) },
      { CKA_TOKEN, &bFalse, sizeof(bFalse) },
      { CKA_SIGN, &bTrue, sizeof(bTrue) }
    };
    gen.mechanism = CKM_SLH_DSA_KEY_PAIR_GEN;
    gen.pParameter = NULL_PTR;
    gen.ulParameterLen = 0;
    rv = f->C_GenerateKeyPair(sess, &gen, pubT, 4, privT, 4, &pub, &priv);
    CHECK(rv == CKR_OK && pub != 0 && priv != 0,
          "SLH-DSA pair mints (rv=0x%lx)", (unsigned long)rv);
    if (rv == CKR_OK && pub != 0 && priv != 0) {
      mech.mechanism = CKM_SLH_DSA;
      mech.pParameter = NULL_PTR;
      mech.ulParameterLen = 0;
      family(sess, &mech, pub, priv, msg, sizeof(msg) - 1, 7856, "slhdsa");
      f->C_DestroyObject(sess, pub);
      f->C_DestroyObject(sess, priv);
    }
  }

  rv = f->C_Logout(sess);
  CHECK(rv == CKR_OK, "Logout ok");
  rv = f->C_CloseSession(sess);
  CHECK(rv == CKR_OK, "CloseSession ok");
  rv = f->C_Finalize(NULL_PTR);
  CHECK(rv == CKR_OK, "C_Finalize ok");
  dlclose(dl);

  if (g_failures == 0) {
    printf("PASS: consumer_siglen_range (signature length strictness)\n");
    return 0;
  }
  printf("FAILURES: %d\n", g_failures);
  return 1;
}
