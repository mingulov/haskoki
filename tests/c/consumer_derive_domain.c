/* tests/c/consumer_derive_domain.c — a derived object satisfies its
 * declared key domain (public C_DeriveKey).
 *
 * Two shared-validator paths are driven through the public surface:
 * CKM_CONCATENATE_BASE_AND_DATA (byte operation, natural width 33) and
 * CKM_SHA256_KEY_DERIVATION (hash KDF, digest width 32). For each:
 *
 *   - negatives: SECRET_KEY/AES with CKA_VALUE_LEN 1, 15, 17, 20, 31
 *     and 33, SECRET_KEY/RSA and SECRET_KEY/EC with a fitting length,
 *     and an unserved vendor numeric key type refuse
 *     CKR_TEMPLATE_INCONSISTENT (SHA-256 AES/33 is past the digest
 *     width and keeps the family's CKR_KEY_SIZE_RANGE); the
 *     output-handle canary is
 *     unchanged, no object carries the attempt's label, the visible
 *     object census is unchanged, and the next object handle shows no
 *     consumed counter;
 *   - positives: AES 16/24/32 on both paths publish
 *     CKK_AES objects whose CKA_VALUE equals independently known bytes
 *     (concatenation prefix; SHA-256("abc") prefix) and whose AES-ECB
 *     encryption of the FIPS-197 plaintext matches constants computed
 *     outside Haskoki (FIPS-197 Appendix C; system OpenSSL for the
 *     SHA-derived keys);
 *   - length defaults (PKCS#11 concat and SHA key derivation rules):
 *     explicit generic length 1, absent key type with an explicit
 *     length, absent type and length (generic secret of the natural
 *     width / digest width), DES3 without a length (a 24-byte DES3 key)
 *     and AES without a length (CKR_TEMPLATE_INCOMPLETE: no single
 *     defined length);
 *   - a protected (sensitive, unextractable) concat base still yields a
 *     sealed AES-16 child that passes the known-answer encryption.
 *
 * Standalone C consumer (non-Haskell executable): dlopen()s the built
 * libhaskoki shared module and drives it through the pinned 3.2 headers.
 * This TU deliberately includes ONLY the pinned vendor headers; it never
 * consumes provider-generated artifacts (enforced by the driver script's
 * independence guard).
 *
 * Compile with -Ispec/vendor. Part of scripts/test-consumers.sh.
 * Usage: consumer_derive_domain <path-to-libhaskoki.so>
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

#define CANARY ((CK_OBJECT_HANDLE)0x5ca1ab1eUL)
#define NO_LEN ((CK_ULONG)-1)
#define VENDOR_KT ((CK_KEY_TYPE)(CKK_VENDOR_DEFINED | 0x123UL))

static CK_FUNCTION_LIST_PTR f = NULL;
static CK_BBOOL bTrue = CK_TRUE, bFalse = CK_FALSE;

/* FIPS-197 Appendix C plaintext and ciphertexts for the keys
 * 000102..0f / ..17 / ..1f. */
static CK_BYTE fips_pt[16] = {
  0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
  0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
};
static CK_BYTE fips_ct128[16] = {
  0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30,
  0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a
};
static CK_BYTE fips_ct192[16] = {
  0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0,
  0x6e, 0xaf, 0x70, 0xa0, 0xec, 0x0d, 0x71, 0x91
};
static CK_BYTE fips_ct256[16] = {
  0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf,
  0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89
};
/* SHA-256("abc") (FIPS 180-2 Appendix B.1). */
static CK_BYTE sha_abc[32] = {
  0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
  0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
  0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
  0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
};
/* AES-ECB(fips_pt) under SHA-256("abc")[0..16), [0..24) and [0..32),
 * computed with the system OpenSSL CLI (independent of Haskoki). */
static CK_BYTE sha_ct128[16] = {
  0x7b, 0x7b, 0xc8, 0x62, 0x6d, 0xb6, 0xd6, 0xe7,
  0x0a, 0x9d, 0x63, 0x03, 0x13, 0xed, 0xe7, 0x58
};
static CK_BYTE sha_ct192[16] = {
  0x66, 0x1f, 0x8c, 0x52, 0x08, 0xa0, 0xaa, 0xfb,
  0xce, 0xd4, 0x43, 0x2f, 0xcd, 0x9a, 0x2f, 0x25
};
static CK_BYTE sha_ct256[16] = {
  0x47, 0xc9, 0x2e, 0x22, 0x14, 0x6d, 0x0f, 0xd1,
  0xe9, 0x80, 0xcf, 0x18, 0x2b, 0x43, 0x9d, 0xc0
};

static CK_OBJECT_HANDLE mksecret(CK_SESSION_HANDLE s, const char *label,
                                 CK_BYTE *val, CK_ULONG vlen,
                                 CK_BBOOL sens, CK_BBOOL extr) {
  CK_OBJECT_CLASS cls = CKO_SECRET_KEY;
  CK_KEY_TYPE kt = CKK_GENERIC_SECRET;
  CK_ATTRIBUTE t[] = {
    { CKA_CLASS, &cls, sizeof(cls) },
    { CKA_KEY_TYPE, &kt, sizeof(kt) },
    { CKA_LABEL, (CK_VOID_PTR)label, (CK_ULONG)strlen(label) },
    { CKA_TOKEN, &bFalse, sizeof(bFalse) },
    { CKA_PRIVATE, &bTrue, sizeof(bTrue) },
    { CKA_DERIVE, &bTrue, sizeof(bTrue) },
    { CKA_SENSITIVE, &sens, sizeof(sens) },
    { CKA_EXTRACTABLE, &extr, sizeof(extr) },
    { CKA_VALUE, val, vlen }
  };
  CK_OBJECT_HANDLE h = 0;
  CK_RV rv = f->C_CreateObject(s, t, 9, &h);
  CHECK(rv == CKR_OK && h != 0, "import %s (rv=0x%lx)",
        label, (unsigned long)rv);
  return h;
}

/* A throwaway data object: its handle samples the object-handle
 * counter (handles are allocated sequentially). */
static CK_OBJECT_HANDLE mkprobe(CK_SESSION_HANDLE s) {
  CK_OBJECT_CLASS cls = CKO_DATA;
  CK_BYTE v = 0x42;
  CK_ATTRIBUTE t[] = {
    { CKA_CLASS, &cls, sizeof(cls) },
    { CKA_TOKEN, &bFalse, sizeof(bFalse) },
    { CKA_VALUE, &v, sizeof(v) }
  };
  CK_OBJECT_HANDLE h = 0;
  CK_RV rv = f->C_CreateObject(s, t, 3, &h);
  CHECK(rv == CKR_OK && h != 0, "probe object (rv=0x%lx)",
        (unsigned long)rv);
  return h;
}

static CK_ULONG count_match(CK_SESSION_HANDLE s, CK_ATTRIBUTE *match,
                            CK_ULONG nmatch) {
  CK_OBJECT_HANDLE found[64];
  CK_ULONG n = 0, total = 0;
  CK_RV rv = f->C_FindObjectsInit(s, match, nmatch);
  CHECK(rv == CKR_OK, "find init");
  if (rv != CKR_OK) {
    return 9999;
  }
  do {
    rv = f->C_FindObjects(s, found, 64, &n);
    CHECK(rv == CKR_OK, "find");
    if (rv != CKR_OK) {
      break;
    }
    total += n;
  } while (n == 64);
  rv = f->C_FindObjectsFinal(s);
  CHECK(rv == CKR_OK, "find final");
  return total;
}

static CK_ULONG count_label(CK_SESSION_HANDLE s, const char *label) {
  CK_ATTRIBUTE match[] = {
    { CKA_LABEL, (CK_VOID_PTR)label, (CK_ULONG)strlen(label) }
  };
  return count_match(s, match, 1);
}

static CK_ULONG count_all(CK_SESSION_HANDLE s) {
  return count_match(s, NULL_PTR, 0);
}

/* Build a derive template: class SECRET_KEY, optional key type
 * (has_kt), optional length (len != NO_LEN), label, session object,
 * readable and encrypt-capable unless the caller seals it. */
static CK_ULONG build_tmpl(CK_ATTRIBUTE *t, CK_OBJECT_CLASS *cls,
                           int has_kt, CK_KEY_TYPE *kt, CK_ULONG *len,
                           const char *label, int readable) {
  CK_ULONG n = 0;
  t[n].type = CKA_CLASS; t[n].pValue = cls; t[n].ulValueLen = sizeof(*cls); n++;
  if (has_kt) {
    t[n].type = CKA_KEY_TYPE; t[n].pValue = kt; t[n].ulValueLen = sizeof(*kt); n++;
  }
  if (*len != NO_LEN) {
    t[n].type = CKA_VALUE_LEN; t[n].pValue = len; t[n].ulValueLen = sizeof(*len); n++;
  }
  t[n].type = CKA_LABEL; t[n].pValue = (CK_VOID_PTR)label;
  t[n].ulValueLen = (CK_ULONG)strlen(label); n++;
  t[n].type = CKA_TOKEN; t[n].pValue = &bFalse; t[n].ulValueLen = sizeof(bFalse); n++;
  t[n].type = CKA_ENCRYPT; t[n].pValue = &bTrue; t[n].ulValueLen = sizeof(bTrue); n++;
  if (readable) {
    t[n].type = CKA_SENSITIVE; t[n].pValue = &bFalse; t[n].ulValueLen = sizeof(bFalse); n++;
    t[n].type = CKA_EXTRACTABLE; t[n].pValue = &bTrue; t[n].ulValueLen = sizeof(bTrue); n++;
  }
  return n;
}

/* One refused request: the expected CKR, an unchanged output-handle
 * canary, no labelled child, an unchanged census and an unconsumed
 * handle counter. */
static void expect_refused(CK_SESSION_HANDLE s, CK_MECHANISM *m,
                           CK_OBJECT_HANDLE base, int has_kt, CK_KEY_TYPE kt,
                           CK_ULONG len, int readable, CK_RV want,
                           const char *what) {
  CK_OBJECT_CLASS cls = CKO_SECRET_KEY;
  CK_ATTRIBUTE t[10];
  const char *label = "dom-refused-child";
  CK_ULONG n = build_tmpl(t, &cls, has_kt, &kt, &len, label, readable);
  CK_OBJECT_HANDLE h = CANARY, before, after;
  CK_ULONG census = count_all(s);
  CK_RV rv;
  before = mkprobe(s);
  rv = f->C_DeriveKey(s, m, base, t, n, &h);
  after = mkprobe(s);
  printf("derive-domain: %s -> rv=0x%lx handle=0x%lx\n", what,
         (unsigned long)rv, (unsigned long)h);
  CHECK(rv == want, "%s refuses 0x%lx (rv=0x%lx)", what,
        (unsigned long)want, (unsigned long)rv);
  CHECK(h == CANARY, "%s leaves the output-handle canary (h=0x%lx)",
        what, (unsigned long)h);
  CHECK(count_label(s, label) == 0, "%s publishes no child", what);
  CHECK(count_all(s) == census + 2, "%s census unchanged (probes only)",
        what);
  CHECK(after == before + 1, "%s consumes no handle (0x%lx -> 0x%lx)",
        what, (unsigned long)before, (unsigned long)after);
  /* Cleanup: probes, plus any child the unmodified module minted. */
  if (rv == CKR_OK && h != CANARY && h != 0) {
    f->C_DestroyObject(s, h);
  }
  f->C_DestroyObject(s, before);
  f->C_DestroyObject(s, after);
}

static CK_ULONG read_ulong(CK_SESSION_HANDLE s, CK_OBJECT_HANDLE h,
                           CK_ATTRIBUTE_TYPE at, const char *what) {
  CK_ULONG v = 0xa5a5a5a5UL;
  CK_ATTRIBUTE q[] = { { at, &v, sizeof(v) } };
  CK_RV rv = f->C_GetAttributeValue(s, h, q, 1);
  CHECK(rv == CKR_OK && q[0].ulValueLen == sizeof(v),
        "%s reads attribute 0x%lx (rv=0x%lx)", what, (unsigned long)at,
        (unsigned long)rv);
  return v;
}

/* AES-ECB one block under h must equal want. */
static void expect_kat(CK_SESSION_HANDLE s, CK_OBJECT_HANDLE h,
                       const CK_BYTE *want, const char *what) {
  CK_MECHANISM m = { CKM_AES_ECB, NULL_PTR, 0 };
  CK_BYTE ct[32];
  CK_ULONG ctLen = sizeof(ct);
  CK_RV rv = f->C_EncryptInit(s, &m, h);
  CHECK(rv == CKR_OK, "%s AES-ECB init (rv=0x%lx)", what, (unsigned long)rv);
  if (rv != CKR_OK) {
    return;
  }
  memset(ct, 0, sizeof(ct));
  rv = f->C_Encrypt(s, fips_pt, sizeof(fips_pt), ct, &ctLen);
  CHECK(rv == CKR_OK && ctLen == 16 && memcmp(ct, want, 16) == 0,
        "%s AES known-answer (rv=0x%lx len=%lu)", what, (unsigned long)rv,
        (unsigned long)ctLen);
}

/* One accepted request: CKR_OK, the declared type and length, exact
 * expected value bytes (readable children) and the known-answer
 * encryption for AES children (want_ct != NULL). */
static void expect_derived(CK_SESSION_HANDLE s, CK_MECHANISM *m,
                           CK_OBJECT_HANDLE base, int has_kt, CK_KEY_TYPE kt,
                           CK_ULONG len, int readable, CK_KEY_TYPE want_kt,
                           const CK_BYTE *want, CK_ULONG want_len,
                           const CK_BYTE *want_ct, const char *what) {
  CK_OBJECT_CLASS cls = CKO_SECRET_KEY;
  CK_ATTRIBUTE t[10];
  CK_ULONG n = build_tmpl(t, &cls, has_kt, &kt, &len, "dom-child", readable);
  CK_OBJECT_HANDLE h = CANARY;
  CK_RV rv = f->C_DeriveKey(s, m, base, t, n, &h);
  printf("derive-domain: %s -> rv=0x%lx\n", what, (unsigned long)rv);
  CHECK(rv == CKR_OK && h != CANARY && h != 0, "%s derives (rv=0x%lx)",
        what, (unsigned long)rv);
  if (rv != CKR_OK || h == CANARY || h == 0) {
    return;
  }
  CHECK(read_ulong(s, h, CKA_KEY_TYPE, what) == want_kt,
        "%s key type 0x%lx", what, (unsigned long)want_kt);
  CHECK(read_ulong(s, h, CKA_VALUE_LEN, what) == want_len,
        "%s value length %lu", what, (unsigned long)want_len);
  if (readable) {
    CK_BYTE got[64];
    CK_ATTRIBUTE g[] = { { CKA_VALUE, got, sizeof(got) } };
    memset(got, 0, sizeof(got));
    rv = f->C_GetAttributeValue(s, h, g, 1);
    CHECK(rv == CKR_OK && g[0].ulValueLen == want_len &&
          memcmp(got, want, want_len) == 0,
          "%s value equals the independent bytes (rv=0x%lx len=%lu)", what,
          (unsigned long)rv, (unsigned long)g[0].ulValueLen);
  }
  if (want_ct != NULL) {
    expect_kat(s, h, want_ct, what);
  }
  rv = f->C_DestroyObject(s, h);
  CHECK(rv == CKR_OK, "%s child destroyed", what);
}

/* The shared negative matrix for one mechanism and base. A protected
 * base takes sealed (protection-omitting) templates, so the protection
 * rule cannot mask the domain refusal. */
static void negative_matrix(CK_SESSION_HANDLE s, CK_MECHANISM *m,
                            CK_OBJECT_HANDLE base, int readable,
                            CK_RV aes33_rv, CK_RV aes0_rv, const char *tag) {
  static const CK_ULONG bad_aes[] = { 1, 15, 17, 20, 31 };
  char what[96];
  size_t i;
  for (i = 0; i < sizeof(bad_aes) / sizeof(bad_aes[0]); i++) {
    snprintf(what, sizeof(what), "%s AES/%lu", tag,
             (unsigned long)bad_aes[i]);
    expect_refused(s, m, base, 1, CKK_AES, bad_aes[i], readable,
                   CKR_TEMPLATE_INCONSISTENT, what);
  }
  /* AES/33 is off-domain; past the family ceiling (SHA-256: the
   * 32-byte digest) the family's sourced ceiling code wins. */
  snprintf(what, sizeof(what), "%s AES/33", tag);
  expect_refused(s, m, base, 1, CKK_AES, 33, readable, aes33_rv, what);
  snprintf(what, sizeof(what), "%s SECRET_KEY/RSA/16", tag);
  expect_refused(s, m, base, 1, CKK_RSA, 16, readable,
                 CKR_TEMPLATE_INCONSISTENT, what);
  snprintf(what, sizeof(what), "%s SECRET_KEY/EC/16", tag);
  expect_refused(s, m, base, 1, CKK_EC, 16, readable,
                 CKR_TEMPLATE_INCONSISTENT, what);
  snprintf(what, sizeof(what), "%s SECRET_KEY/vendor/16", tag);
  expect_refused(s, m, base, 1, VENDOR_KT, 16, readable,
                 CKR_TEMPLATE_INCONSISTENT, what);
  /* AES has no single defined length: a missing one is incomplete. */
  snprintf(what, sizeof(what), "%s AES/no-length", tag);
  expect_refused(s, m, base, 1, CKK_AES, NO_LEN, readable,
                 CKR_TEMPLATE_INCOMPLETE, what);
  /* A zero length is never a shortening: it keeps its
   * pre-existing size-range code on every base. */
  snprintf(what, sizeof(what), "%s AES/0", tag);
  expect_refused(s, m, base, 1, CKK_AES, 0, readable, aes0_rv, what);
}

int main(int argc, char **argv) {
  CK_RV rv;
  CK_C_GetFunctionList getList = NULL;
  void *dl = NULL;
  CK_SLOT_ID slots[8];
  CK_ULONG nslots = 8;
  CK_SESSION_HANDLE sess = 0;
  CK_OBJECT_HANDLE cbase = 0, pbase = 0, sbase = 0;
  CK_BYTE kb[16], dat[17], concat[33], abc[3] = { 'a', 'b', 'c' };
  CK_KEY_DERIVATION_STRING_DATA sd;
  CK_MECHANISM mcat, msha;
  CK_ULONG i;

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

  /* base 00..0f ++ data 10..20: the concatenation is 00..20, so the
   * 16/24/32-byte prefixes are the FIPS-197 Appendix C keys. */
  for (i = 0; i < sizeof(kb); i++) {
    kb[i] = (CK_BYTE)i;
  }
  for (i = 0; i < sizeof(dat); i++) {
    dat[i] = (CK_BYTE)(i + 16);
  }
  for (i = 0; i < sizeof(concat); i++) {
    concat[i] = (CK_BYTE)i;
  }
  cbase = mksecret(sess, "dom-concat-base", kb, sizeof(kb), CK_FALSE, CK_TRUE);
  pbase = mksecret(sess, "dom-prot-base", kb, sizeof(kb), CK_TRUE, CK_FALSE);
  sbase = mksecret(sess, "dom-sha-base", abc, sizeof(abc), CK_FALSE, CK_TRUE);

  sd.pData = dat;
  sd.ulLen = sizeof(dat);
  mcat.mechanism = CKM_CONCATENATE_BASE_AND_DATA;
  mcat.pParameter = &sd;
  mcat.ulParameterLen = sizeof(sd);
  msha.mechanism = CKM_SHA256_KEY_DERIVATION;
  msha.pParameter = NULL_PTR;
  msha.ulParameterLen = 0;

  /* Byte-concatenation path. */
  negative_matrix(sess, &mcat, cbase, 1, CKR_TEMPLATE_INCONSISTENT,
                  CKR_KEY_SIZE_RANGE, "concat");
  expect_derived(sess, &mcat, cbase, 1, CKK_AES, 16, 1, CKK_AES,
                 concat, 16, fips_ct128, "concat AES/16");
  expect_derived(sess, &mcat, cbase, 1, CKK_AES, 24, 1, CKK_AES,
                 concat, 24, fips_ct192, "concat AES/24");
  expect_derived(sess, &mcat, cbase, 1, CKK_AES, 32, 1, CKK_AES,
                 concat, 32, fips_ct256, "concat AES/32");
  expect_derived(sess, &mcat, cbase, 1, CKK_GENERIC_SECRET, 1, 1,
                 CKK_GENERIC_SECRET, concat, 1, NULL, "concat GENERIC/1");
  expect_derived(sess, &mcat, cbase, 0, 0, 5, 1, CKK_GENERIC_SECRET,
                 concat, 5, NULL, "concat no-type/5");
  expect_derived(sess, &mcat, cbase, 0, 0, NO_LEN, 1, CKK_GENERIC_SECRET,
                 concat, 33, NULL, "concat no-type/no-length");
  /* A fixed-length type without a length takes that length (value
   * bytes unpinned: DES parity adjustment is a separate item). */
  expect_derived(sess, &mcat, cbase, 1, CKK_DES3, NO_LEN, 0, CKK_DES3,
                 NULL, 24, NULL, "concat DES3/no-length");
  /* Protected base: a sealed base refuses truncation, so the
   * full-width AES child carries the known-answer leg (base 16 +
   * data 16 is the 32-byte FIPS key). */
  negative_matrix(sess, &mcat, pbase, 0, CKR_TEMPLATE_INCONSISTENT,
                  CKR_KEY_SIZE_RANGE, "concat-protected");
  /* A sealed base refuses the truncated AES/16 child it used to
   * mint: pin the refusal (natural width is 33). */
  expect_refused(sess, &mcat, pbase, 1, CKK_AES, 16, 0,
                 CKR_TEMPLATE_INCONSISTENT, "concat-protected AES/16");
  {
    CK_KEY_DERIVATION_STRING_DATA sd16;
    CK_MECHANISM mcat32;
    sd16.pData = dat;
    sd16.ulLen = 16;
    mcat32.mechanism = CKM_CONCATENATE_BASE_AND_DATA;
    mcat32.pParameter = &sd16;
    mcat32.ulParameterLen = sizeof(sd16);
    expect_derived(sess, &mcat32, pbase, 1, CKK_AES, 32, 0, CKK_AES,
                   concat, 32, fips_ct256, "concat-protected AES/32");
  }

  /* Hash-KDF path. */
  negative_matrix(sess, &msha, sbase, 1, CKR_KEY_SIZE_RANGE, CKR_KEY_SIZE_RANGE,
                  "sha256");
  expect_derived(sess, &msha, sbase, 1, CKK_AES, 16, 1, CKK_AES,
                 sha_abc, 16, sha_ct128, "sha256 AES/16");
  expect_derived(sess, &msha, sbase, 1, CKK_AES, 24, 1, CKK_AES,
                 sha_abc, 24, sha_ct192, "sha256 AES/24");
  expect_derived(sess, &msha, sbase, 1, CKK_AES, 32, 1, CKK_AES,
                 sha_abc, 32, sha_ct256, "sha256 AES/32");
  expect_derived(sess, &msha, sbase, 1, CKK_DES3, NO_LEN, 0, CKK_DES3,
                 NULL, 24, NULL, "sha256 DES3/no-length");
  expect_derived(sess, &msha, sbase, 1, CKK_GENERIC_SECRET, 1, 1,
                 CKK_GENERIC_SECRET, sha_abc, 1, NULL, "sha256 GENERIC/1");
  expect_derived(sess, &msha, sbase, 0, 0, 20, 1, CKK_GENERIC_SECRET,
                 sha_abc, 20, NULL, "sha256 no-type/20");
  expect_derived(sess, &msha, sbase, 0, 0, NO_LEN, 1, CKK_GENERIC_SECRET,
                 sha_abc, 32, NULL, "sha256 no-type/no-length");
  /* Past the digest width: the mechanism ceiling keeps its code. */
  expect_refused(sess, &msha, sbase, 1, CKK_GENERIC_SECRET, 33, 1,
                 CKR_KEY_SIZE_RANGE, "sha256 GENERIC/33");

  rv = f->C_DestroyObject(sess, cbase);
  CHECK(rv == CKR_OK, "concat base destroyed");
  rv = f->C_DestroyObject(sess, pbase);
  CHECK(rv == CKR_OK, "protected base destroyed");
  rv = f->C_DestroyObject(sess, sbase);
  CHECK(rv == CKR_OK, "sha base destroyed");
  rv = f->C_Logout(sess);
  CHECK(rv == CKR_OK, "Logout ok");
  rv = f->C_CloseSession(sess);
  CHECK(rv == CKR_OK, "CloseSession ok");
  rv = f->C_Finalize(NULL_PTR);
  CHECK(rv == CKR_OK, "C_Finalize ok");
  dlclose(dl);

  if (g_failures == 0) {
    printf("PASS: consumer_derive_domain (derived key-domain validation)\n");
    return 0;
  }
  printf("FAILURES: %d\n", g_failures);
  return 1;
}
