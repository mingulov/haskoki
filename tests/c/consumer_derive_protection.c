/* tests/c/consumer_derive_protection.c — byte-derivation
 * preserves source protection (OASIS PKCS#11 3.2 §6.43.3–§6.43.7).
 *
 * A protected derivable generic-secret fixture (sensitive, unextractable,
 * unreadable positive control) must not produce a readable child through
 * any of the five byte-operation mechanisms: an explicit protection
 * downgrade refuses CKR_TEMPLATE_INCONSISTENT with no object created,
 * while matching and omitted templates resolve to the inherited sealed
 * flags with an unreadable value. Split-flag fixtures prove the two
 * rules are independent, aux-only and mixed concat-key inputs combine,
 * a protected overrun still refuses typed, and a sealed child refuses
 * C_WrapKey. The history-attribute boundary and two unaffected-rule
 * controls (unprotected byte-op inputs, HKDF over a protected base)
 * pin the scope to the named mechanisms.
 *
 * A successful downgrade derive is tolerated only with inherited sealed
 * flags and an unreadable value (never weakened attributes or fixture
 * bytes), matching the diagnostic probe's acceptance.
 *
 * Standalone C consumer (non-Haskell executable): dlopen()s the built
 * libhaskoki shared module and drives it through the pinned 3.2 headers.
 * This TU deliberately includes ONLY the pinned vendor headers; it never
 * consumes provider-generated artifacts (enforced by the driver script's
 * independence guard).
 *
 * Compile with -Ispec/vendor. Part of scripts/test-consumers.sh.
 * Usage: consumer_derive_protection <path-to-libhaskoki.so>
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

static CK_ULONG count_label(CK_SESSION_HANDLE s, const char *label) {
  CK_ATTRIBUTE match[] = {
    { CKA_LABEL, (CK_VOID_PTR)label, (CK_ULONG)strlen(label) }
  };
  CK_OBJECT_HANDLE found[8];
  CK_ULONG n = 0;
  CK_RV rv = f->C_FindObjectsInit(s, match, 1);
  CHECK(rv == CKR_OK, "find init %s", label);
  if (rv != CKR_OK) {
    return 999;
  }
  rv = f->C_FindObjects(s, found, 8, &n);
  CHECK(rv == CKR_OK, "find %s", label);
  rv = f->C_FindObjectsFinal(s);
  CHECK(rv == CKR_OK, "find final %s", label);
  return n;
}

/* Expect sealed flags with exact lengths. */
static void expect_flags(CK_SESSION_HANDLE s, CK_OBJECT_HANDLE h,
                         CK_BBOOL sens, CK_BBOOL extr, const char *what) {
  CK_BBOOL gs = 0xa5, ge = 0xa5;
  CK_ATTRIBUTE q[] = {
    { CKA_SENSITIVE, &gs, sizeof(gs) },
    { CKA_EXTRACTABLE, &ge, sizeof(ge) }
  };
  CK_RV rv = f->C_GetAttributeValue(s, h, q, 2);
  CHECK(rv == CKR_OK, "%s flags read (rv=0x%lx)", what, (unsigned long)rv);
  CHECK(q[0].ulValueLen == sizeof(gs) && q[1].ulValueLen == sizeof(ge) &&
        gs == sens && ge == extr,
        "%s flags sensitive=%u extractable=%u", what,
        (unsigned)gs, (unsigned)ge);
}

/* Expect CKA_VALUE refused with an intact canary buffer. */
static void expect_sealed(CK_SESSION_HANDLE s, CK_OBJECT_HANDLE h,
                          CK_ULONG vlen, const char *what) {
  CK_BYTE guard[96];
  CK_ATTRIBUTE g;
  CK_ULONG i;
  int intact = 1;
  memset(guard, 0xa5, sizeof(guard));
  g.type = CKA_VALUE;
  g.pValue = guard + 16;
  g.ulValueLen = vlen;
  CK_RV rv = f->C_GetAttributeValue(s, h, &g, 1);
  CHECK(rv == CKR_ATTRIBUTE_SENSITIVE, "%s value sealed (rv=0x%lx)",
        what, (unsigned long)rv);
  for (i = 0; i < sizeof(guard); i++) {
    if (guard[i] != 0xa5) {
      intact = 0;
    }
  }
  CHECK(intact, "%s sealed buffer untouched", what);
}

/* Expect the exact readable bytes. */
static void expect_bytes(CK_SESSION_HANDLE s, CK_OBJECT_HANDLE h,
                         CK_BYTE *want, CK_ULONG wantLen, const char *what) {
  CK_BYTE got[96];
  CK_ATTRIBUTE g[] = { { CKA_VALUE, got, sizeof(got) } };
  memset(got, 0, sizeof(got));
  g[0].ulValueLen = sizeof(got);
  CK_RV rv = f->C_GetAttributeValue(s, h, g, 1);
  CHECK(rv == CKR_OK && g[0].ulValueLen == wantLen &&
        memcmp(got, want, wantLen) == 0,
        "%s reads exact bytes (rv=0x%lx)", what, (unsigned long)rv);
}

/* Downgrade leg: primary expectation is typed refusal with no handle;
 * a successful derive is accepted only with inherited sealed flags
 * and an unreadable value (then destroyed). Returns the derive rv. */
static CK_RV downgrade_leg(CK_SESSION_HANDLE s, CK_MECHANISM *m,
                           CK_OBJECT_HANDLE base, CK_ATTRIBUTE *dt,
                           CK_ULONG ndt, CK_ULONG sealedLen,
                           const char *tag, const char *row) {
  CK_OBJECT_HANDLE h = 0;
  CK_RV rv = f->C_DeriveKey(s, m, base, dt, ndt, &h);
  if (rv == CKR_TEMPLATE_INCONSISTENT) {
    CHECK(h == 0, "%s %s refused without handle", tag, row);
    printf("derive-protection: %s %s refused CKR_TEMPLATE_INCONSISTENT\n",
           tag, row);
    return rv;
  }
  CHECK(rv == CKR_OK && h != 0, "%s %s derive ok-or-refused (rv=0x%lx)",
        tag, row, (unsigned long)rv);
  if (rv == CKR_OK && h != 0) {
    printf("derive-protection: %s %s derived (verifying inherited seal)\n",
           tag, row);
    expect_flags(s, h, CK_TRUE, CK_FALSE, row);
    expect_sealed(s, h, sealedLen, row);
    rv = f->C_DestroyObject(s, h);
    CHECK(rv == CKR_OK, "%s %s tolerance child destroyed", tag, row);
    return CKR_OK;
  }
  return rv;
}

/* Downgrade matrix over all five byte-operation rows for one base
 * key and concat-key aux handle. The extract row carries
 * refused_label for the no-object proof. Returns the extract rv. */
static CK_RV downgrade_matrix(CK_SESSION_HANDLE s, CK_OBJECT_HANDLE base,
                              CK_OBJECT_HANDLE aux, CK_BYTE *dat,
                              CK_BYTE *xord, const char *tag,
                              const char *refused_label) {
  CK_OBJECT_CLASS seccls = CKO_SECRET_KEY;
  CK_KEY_TYPE genkt = CKK_GENERIC_SECRET;
  CK_ULONG len64 = 64, len32 = 32, len16 = 16;
  CK_OBJECT_HANDLE second = aux;
  CK_KEY_DERIVATION_STRING_DATA sd, sx;
  CK_ULONG off0 = 0;
  CK_MECHANISM m;
  CK_RV rv_extract;
  printf("derive-protection: downgrade matrix for %s\n", tag);
  sd.pData = dat;
  sd.ulLen = 16;
  sx.pData = xord;
  sx.ulLen = 32;
  /* concat-key. */
  {
    CK_ATTRIBUTE dt[] = {
      { CKA_CLASS, &seccls, sizeof(seccls) },
      { CKA_KEY_TYPE, &genkt, sizeof(genkt) },
      { CKA_VALUE_LEN, &len64, sizeof(len64) },
      { CKA_TOKEN, &bFalse, sizeof(bFalse) },
      { CKA_SENSITIVE, &bFalse, sizeof(bFalse) },
      { CKA_EXTRACTABLE, &bTrue, sizeof(bTrue) }
    };
    m.mechanism = CKM_CONCATENATE_BASE_AND_KEY;
    m.pParameter = &second;
    m.ulParameterLen = sizeof(second);
    downgrade_leg(s, &m, base, dt, 6, len64, tag, "concat-key downgrade");
  }
  /* concat-data. */
  {
    CK_ATTRIBUTE dt[] = {
      { CKA_CLASS, &seccls, sizeof(seccls) },
      { CKA_KEY_TYPE, &genkt, sizeof(genkt) },
      { CKA_VALUE_LEN, &len16, sizeof(len16) },
      { CKA_TOKEN, &bFalse, sizeof(bFalse) },
      { CKA_SENSITIVE, &bFalse, sizeof(bFalse) },
      { CKA_EXTRACTABLE, &bTrue, sizeof(bTrue) }
    };
    m.mechanism = CKM_CONCATENATE_BASE_AND_DATA;
    m.pParameter = &sd;
    m.ulParameterLen = sizeof(sd);
    downgrade_leg(s, &m, base, dt, 6, len16, tag, "concat-data downgrade");
  }
  /* data-concat. */
  {
    CK_ATTRIBUTE dt[] = {
      { CKA_CLASS, &seccls, sizeof(seccls) },
      { CKA_KEY_TYPE, &genkt, sizeof(genkt) },
      { CKA_VALUE_LEN, &len16, sizeof(len16) },
      { CKA_TOKEN, &bFalse, sizeof(bFalse) },
      { CKA_SENSITIVE, &bFalse, sizeof(bFalse) },
      { CKA_EXTRACTABLE, &bTrue, sizeof(bTrue) }
    };
    m.mechanism = CKM_CONCATENATE_DATA_AND_BASE;
    m.pParameter = &sd;
    m.ulParameterLen = sizeof(sd);
    downgrade_leg(s, &m, base, dt, 6, len16, tag, "data-concat downgrade");
  }
  /* xor. */
  {
    CK_ATTRIBUTE dt[] = {
      { CKA_CLASS, &seccls, sizeof(seccls) },
      { CKA_KEY_TYPE, &genkt, sizeof(genkt) },
      { CKA_VALUE_LEN, &len16, sizeof(len16) },
      { CKA_TOKEN, &bFalse, sizeof(bFalse) },
      { CKA_SENSITIVE, &bFalse, sizeof(bFalse) },
      { CKA_EXTRACTABLE, &bTrue, sizeof(bTrue) }
    };
    m.mechanism = CKM_XOR_BASE_AND_DATA;
    m.pParameter = &sx;
    m.ulParameterLen = sizeof(sx);
    downgrade_leg(s, &m, base, dt, 6, len16, tag, "xor downgrade");
  }
  /* extract (full-length, labeled for the no-object proof). */
  {
    CK_ATTRIBUTE dt[] = {
      { CKA_CLASS, &seccls, sizeof(seccls) },
      { CKA_KEY_TYPE, &genkt, sizeof(genkt) },
      { CKA_VALUE_LEN, &len32, sizeof(len32) },
      { CKA_TOKEN, &bFalse, sizeof(bFalse) },
      { CKA_SENSITIVE, &bFalse, sizeof(bFalse) },
      { CKA_EXTRACTABLE, &bTrue, sizeof(bTrue) },
      { CKA_LABEL, (CK_VOID_PTR)refused_label,
        (CK_ULONG)strlen(refused_label) }
    };
    m.mechanism = CKM_EXTRACT_KEY_FROM_KEY;
    m.pParameter = &off0;
    m.ulParameterLen = sizeof(off0);
    rv_extract =
      downgrade_leg(s, &m, base, dt, 7, len32, tag, "extract downgrade");
  }
  return rv_extract;
}

int main(int argc, char **argv) {
  CK_RV rv;
  CK_C_GetFunctionList getList = NULL;
  void *dl = NULL;
  CK_SLOT_ID slots[8];
  CK_ULONG nslots = 8;
  CK_SESSION_HANDLE sess = 0;
  CK_OBJECT_HANDLE pbase = 0, paux = 0, qbase = 0, qaux = 0;
  CK_OBJECT_HANDLE sobase = 0, uobase = 0;
  CK_BYTE base[32], aux[32], dat[16], xord[32];
  CK_ULONG i;
  CK_OBJECT_CLASS seccls = CKO_SECRET_KEY;
  CK_KEY_TYPE genkt = CKK_GENERIC_SECRET;
  CK_RV rv_prot = 0, rv_sens = 0, rv_unextr = 0;

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

  for (i = 0; i < 32; i++) {
    base[i] = (CK_BYTE)i;
    aux[i] = (CK_BYTE)(i + 32);
    xord[i] = 0x0f;
  }
  for (i = 0; i < 16; i++) {
    dat[i] = 1;
  }
  pbase = mksecret(sess, "p1-prot-base", base, sizeof(base), CK_TRUE, CK_FALSE);
  paux = mksecret(sess, "p1-prot-aux", aux, sizeof(aux), CK_TRUE, CK_FALSE);
  qbase = mksecret(sess, "p1-plain-base", base, sizeof(base), CK_FALSE, CK_TRUE);
  qaux = mksecret(sess, "p1-plain-aux", aux, sizeof(aux), CK_FALSE, CK_TRUE);
  sobase = mksecret(sess, "p1-sens-base", base, sizeof(base), CK_TRUE, CK_TRUE);
  uobase = mksecret(sess, "p1-unextr-base", base, sizeof(base), CK_FALSE, CK_FALSE);

  /* Positive control: the protected fixture value is unreadable. */
  expect_sealed(sess, pbase, sizeof(base), "protected base control");

  /* Downgrade matrix over all five byte-operation rows, run for
   * the fully protected base and both split-flag bases: each flag
   * alone refuses its own downgrade. */
  rv_prot = downgrade_matrix(sess, pbase, qaux, dat, xord,
                             "prot", "p1-refused-child");
  rv_sens = downgrade_matrix(sess, sobase, qaux, dat, xord,
                             "sens-only", "p1-refused-sens");
  rv_unextr = downgrade_matrix(sess, uobase, qaux, dat, xord,
                               "unextr-only", "p1-refused-unextr");

  /* A refused derivation creates no object. */
  if (rv_prot == CKR_TEMPLATE_INCONSISTENT) {
    CHECK(count_label(sess, "p1-refused-child") == 0,
          "refused derive publishes no object");
  }
  if (rv_sens == CKR_TEMPLATE_INCONSISTENT) {
    CHECK(count_label(sess, "p1-refused-sens") == 0,
          "refused sens-only derive publishes no object");
  }
  if (rv_unextr == CKR_TEMPLATE_INCONSISTENT) {
    CHECK(count_label(sess, "p1-refused-unextr") == 0,
          "refused unextr-only derive publishes no object");
  }

  /* Matching and omitted templates resolve sealed (extract). */
  {
    CK_ULONG len32 = 32;
    CK_ULONG off0 = 0;
    CK_MECHANISM m;
    CK_OBJECT_HANDLE h = 0;
    m.mechanism = CKM_EXTRACT_KEY_FROM_KEY;
    m.pParameter = &off0;
    m.ulParameterLen = sizeof(off0);
    {
      CK_ATTRIBUTE dt[] = {
        { CKA_CLASS, &seccls, sizeof(seccls) },
        { CKA_KEY_TYPE, &genkt, sizeof(genkt) },
        { CKA_VALUE_LEN, &len32, sizeof(len32) },
        { CKA_TOKEN, &bFalse, sizeof(bFalse) },
        { CKA_SENSITIVE, &bTrue, sizeof(bTrue) },
        { CKA_EXTRACTABLE, &bFalse, sizeof(bFalse) }
      };
      rv = f->C_DeriveKey(sess, &m, pbase, dt, 6, &h);
      CHECK(rv == CKR_OK && h != 0, "matching extract derives");
      if (rv == CKR_OK && h != 0) {
        expect_flags(sess, h, CK_TRUE, CK_FALSE, "matching extract");
        expect_sealed(sess, h, len32, "matching extract");
        rv = f->C_DestroyObject(sess, h);
        CHECK(rv == CKR_OK, "matching extract destroyed");
      }
    }
    h = 0;
    {
      CK_ATTRIBUTE dt[] = {
        { CKA_CLASS, &seccls, sizeof(seccls) },
        { CKA_KEY_TYPE, &genkt, sizeof(genkt) },
        { CKA_VALUE_LEN, &len32, sizeof(len32) },
        { CKA_TOKEN, &bFalse, sizeof(bFalse) }
      };
      rv = f->C_DeriveKey(sess, &m, pbase, dt, 4, &h);
      CHECK(rv == CKR_OK && h != 0, "omitted extract derives");
      if (rv == CKR_OK && h != 0) {
        expect_flags(sess, h, CK_TRUE, CK_FALSE, "omitted extract");
        expect_sealed(sess, h, len32, "omitted extract");
        /* History attributes with no stored value report the
         * effective view: false until creation stamps real history. */
        {
          CK_BBOOL hist = 0xa5;
          CK_ATTRIBUTE q[] = { { CKA_ALWAYS_SENSITIVE, &hist, sizeof(hist) } };
          rv = f->C_GetAttributeValue(sess, h, q, 1);
          CHECK(rv == CKR_OK && hist == CK_FALSE,
                "ALWAYS_SENSITIVE reads false (rv=0x%lx)",
                (unsigned long)rv);
        }
        {
          CK_BBOOL hist = 0xa5;
          CK_ATTRIBUTE q[] = { { CKA_NEVER_EXTRACTABLE, &hist, sizeof(hist) } };
          rv = f->C_GetAttributeValue(sess, h, q, 1);
          CHECK(rv == CKR_OK && hist == CK_FALSE,
                "NEVER_EXTRACTABLE reads false (rv=0x%lx)",
                (unsigned long)rv);
        }
        rv = f->C_DestroyObject(sess, h);
        CHECK(rv == CKR_OK, "omitted extract destroyed");
      }
    }
    /* History attributes in a derive template refuse inconsistent:
     * caller templates may not forge them. */
    {
      CK_BBOOL hist = CK_TRUE;
      CK_ATTRIBUTE dt[] = {
        { CKA_CLASS, &seccls, sizeof(seccls) },
        { CKA_KEY_TYPE, &genkt, sizeof(genkt) },
        { CKA_VALUE_LEN, &len32, sizeof(len32) },
        { CKA_TOKEN, &bFalse, sizeof(bFalse) },
        { CKA_ALWAYS_SENSITIVE, &hist, sizeof(hist) }
      };
      h = 0;
      rv = f->C_DeriveKey(sess, &m, pbase, dt, 5, &h);
      CHECK(rv == CKR_TEMPLATE_INCONSISTENT && h == 0,
            "history-attr template refused inconsistent (rv=0x%lx)",
            (unsigned long)rv);
    }
  }

  /* Aux-only concat-key protection: plain base plus protected aux. */
  {
    CK_ULONG len64 = 64;
    CK_OBJECT_HANDLE second = paux;
    CK_MECHANISM m;
    CK_OBJECT_HANDLE h = 0;
    m.mechanism = CKM_CONCATENATE_BASE_AND_KEY;
    m.pParameter = &second;
    m.ulParameterLen = sizeof(second);
    {
      CK_ATTRIBUTE dt[] = {
        { CKA_CLASS, &seccls, sizeof(seccls) },
        { CKA_KEY_TYPE, &genkt, sizeof(genkt) },
        { CKA_VALUE_LEN, &len64, sizeof(len64) },
        { CKA_TOKEN, &bFalse, sizeof(bFalse) },
        { CKA_SENSITIVE, &bFalse, sizeof(bFalse) },
        { CKA_EXTRACTABLE, &bTrue, sizeof(bTrue) }
      };
      downgrade_leg(sess, &m, qbase, dt, 6, len64,
                    "aux-only", "concat-key downgrade");
    }
    {
      CK_ATTRIBUTE dt[] = {
        { CKA_CLASS, &seccls, sizeof(seccls) },
        { CKA_KEY_TYPE, &genkt, sizeof(genkt) },
        { CKA_VALUE_LEN, &len64, sizeof(len64) },
        { CKA_TOKEN, &bFalse, sizeof(bFalse) }
      };
      rv = f->C_DeriveKey(sess, &m, qbase, dt, 4, &h);
      CHECK(rv == CKR_OK && h != 0, "aux-only omitted derives");
      if (rv == CKR_OK && h != 0) {
        expect_flags(sess, h, CK_TRUE, CK_FALSE, "aux-only omitted");
        expect_sealed(sess, h, len64, "aux-only omitted");
        rv = f->C_DestroyObject(sess, h);
        CHECK(rv == CKR_OK, "aux-only omitted destroyed");
      }
    }
  }

  /* Mixed concat-key inputs combine: a sensitivity-only base plus a
   * nonextractable-only aux requires both flags, either direction. */
  {
    CK_ULONG len64 = 64;
    CK_OBJECT_HANDLE second = uobase;
    CK_MECHANISM m;
    CK_OBJECT_HANDLE h = 0;
    CK_ATTRIBUTE down[] = {
      { CKA_CLASS, &seccls, sizeof(seccls) },
      { CKA_KEY_TYPE, &genkt, sizeof(genkt) },
      { CKA_VALUE_LEN, &len64, sizeof(len64) },
      { CKA_TOKEN, &bFalse, sizeof(bFalse) },
      { CKA_SENSITIVE, &bFalse, sizeof(bFalse) },
      { CKA_EXTRACTABLE, &bTrue, sizeof(bTrue) }
    };
    CK_ATTRIBUTE omit[] = {
      { CKA_CLASS, &seccls, sizeof(seccls) },
      { CKA_KEY_TYPE, &genkt, sizeof(genkt) },
      { CKA_VALUE_LEN, &len64, sizeof(len64) },
      { CKA_TOKEN, &bFalse, sizeof(bFalse) }
    };
    m.mechanism = CKM_CONCATENATE_BASE_AND_KEY;
    m.pParameter = &second;
    m.ulParameterLen = sizeof(second);
    downgrade_leg(sess, &m, sobase, down, 6, len64,
                  "mixed", "concat-key downgrade");
    rv = f->C_DeriveKey(sess, &m, sobase, omit, 4, &h);
    CHECK(rv == CKR_OK && h != 0, "mixed omitted derives");
    if (rv == CKR_OK && h != 0) {
      expect_flags(sess, h, CK_TRUE, CK_FALSE, "mixed omitted");
      expect_sealed(sess, h, len64, "mixed omitted");
      rv = f->C_DestroyObject(sess, h);
      CHECK(rv == CKR_OK, "mixed omitted destroyed");
    }
    second = sobase;
    h = 0;
    rv = f->C_DeriveKey(sess, &m, uobase, omit, 4, &h);
    CHECK(rv == CKR_OK && h != 0, "mixed reversed omitted derives");
    if (rv == CKR_OK && h != 0) {
      expect_flags(sess, h, CK_TRUE, CK_FALSE, "mixed reversed omitted");
      expect_sealed(sess, h, len64, "mixed reversed omitted");
      rv = f->C_DestroyObject(sess, h);
      CHECK(rv == CKR_OK, "mixed reversed omitted destroyed");
    }
  }

  /* Split omitted templates stamp only the required flag: a
   * sensitivity-only source keeps an explicitly readable
   * extractable flag, and vice versa. */
  {
    CK_ULONG len32 = 32;
    CK_ULONG off0 = 0;
    CK_MECHANISM m;
    CK_OBJECT_HANDLE h = 0;
    m.mechanism = CKM_EXTRACT_KEY_FROM_KEY;
    m.pParameter = &off0;
    m.ulParameterLen = sizeof(off0);
    {
      CK_ATTRIBUTE dt[] = {
        { CKA_CLASS, &seccls, sizeof(seccls) },
        { CKA_KEY_TYPE, &genkt, sizeof(genkt) },
        { CKA_VALUE_LEN, &len32, sizeof(len32) },
        { CKA_TOKEN, &bFalse, sizeof(bFalse) },
        { CKA_EXTRACTABLE, &bTrue, sizeof(bTrue) }
      };
      rv = f->C_DeriveKey(sess, &m, sobase, dt, 5, &h);
      CHECK(rv == CKR_OK && h != 0, "sens-only half-template derives");
      if (rv == CKR_OK && h != 0) {
        expect_flags(sess, h, CK_TRUE, CK_TRUE, "sens-only half-template");
        expect_sealed(sess, h, len32, "sens-only half-template");
        rv = f->C_DestroyObject(sess, h);
        CHECK(rv == CKR_OK, "sens-only half-template destroyed");
      }
    }
    h = 0;
    {
      CK_ATTRIBUTE dt[] = {
        { CKA_CLASS, &seccls, sizeof(seccls) },
        { CKA_KEY_TYPE, &genkt, sizeof(genkt) },
        { CKA_VALUE_LEN, &len32, sizeof(len32) },
        { CKA_TOKEN, &bFalse, sizeof(bFalse) },
        { CKA_SENSITIVE, &bFalse, sizeof(bFalse) }
      };
      rv = f->C_DeriveKey(sess, &m, uobase, dt, 5, &h);
      CHECK(rv == CKR_OK && h != 0, "unextr-only half-template derives");
      if (rv == CKR_OK && h != 0) {
        expect_flags(sess, h, CK_FALSE, CK_FALSE, "unextr-only half-template");
        expect_sealed(sess, h, len32, "unextr-only half-template");
        rv = f->C_DestroyObject(sess, h);
        CHECK(rv == CKR_OK, "unextr-only half-template destroyed");
      }
    }
  }

  /* A protected overrun still refuses typed: bit offset 248 leaves
   * a one-byte window, so 16 bytes overrun even with a matching
   * protected template. */
  {
    CK_ULONG len16 = 16;
    CK_ULONG off248 = 248;
    CK_MECHANISM m;
    CK_OBJECT_HANDLE h = 0;
    CK_ATTRIBUTE dt[] = {
      { CKA_CLASS, &seccls, sizeof(seccls) },
      { CKA_KEY_TYPE, &genkt, sizeof(genkt) },
      { CKA_VALUE_LEN, &len16, sizeof(len16) },
      { CKA_TOKEN, &bFalse, sizeof(bFalse) },
      { CKA_SENSITIVE, &bTrue, sizeof(bTrue) },
      { CKA_EXTRACTABLE, &bFalse, sizeof(bFalse) }
    };
    m.mechanism = CKM_EXTRACT_KEY_FROM_KEY;
    m.pParameter = &off248;
    m.ulParameterLen = sizeof(off248);
    rv = f->C_DeriveKey(sess, &m, pbase, dt, 6, &h);
    CHECK(rv == CKR_ARGUMENTS_BAD && h == 0,
          "protected overrun refused typed (rv=0x%lx)", (unsigned long)rv);
  }

  /* A sealed child refuses C_WrapKey with CKR_KEY_UNEXTRACTABLE. */
  {
    CK_ULONG len32 = 32;
    CK_ULONG off0 = 0;
    CK_MECHANISM m, wm;
    CK_OBJECT_HANDLE h = 0, wrap = 0;
    CK_KEY_TYPE aeskt = CKK_AES;
    CK_BYTE wkey[32], wiv[16];
    CK_ULONG wlen = 0;
    CK_ATTRIBUTE wt[] = {
      { CKA_CLASS, &seccls, sizeof(seccls) },
      { CKA_KEY_TYPE, &aeskt, sizeof(aeskt) },
      { CKA_TOKEN, &bFalse, sizeof(bFalse) },
      { CKA_PRIVATE, &bTrue, sizeof(bTrue) },
      { CKA_WRAP, &bTrue, sizeof(bTrue) },
      { CKA_EXTRACTABLE, &bFalse, sizeof(bFalse) },
      { CKA_VALUE, wkey, sizeof(wkey) }
    };
    CK_ATTRIBUTE dt[] = {
      { CKA_CLASS, &seccls, sizeof(seccls) },
      { CKA_KEY_TYPE, &genkt, sizeof(genkt) },
      { CKA_VALUE_LEN, &len32, sizeof(len32) },
      { CKA_TOKEN, &bFalse, sizeof(bFalse) }
    };
    for (i = 0; i < sizeof(wkey); i++) {
      wkey[i] = (CK_BYTE)(i + 64);
    }
    for (i = 0; i < sizeof(wiv); i++) {
      wiv[i] = (CK_BYTE)0x1b;
    }
    rv = f->C_CreateObject(sess, wt, 7, &wrap);
    CHECK(rv == CKR_OK && wrap != 0, "wrapping key imports");
    m.mechanism = CKM_EXTRACT_KEY_FROM_KEY;
    m.pParameter = &off0;
    m.ulParameterLen = sizeof(off0);
    rv = f->C_DeriveKey(sess, &m, pbase, dt, 4, &h);
    CHECK(rv == CKR_OK && h != 0, "sealed wrap target derives");
    if (rv == CKR_OK && h != 0) {
      wm.mechanism = CKM_AES_CBC;
      wm.pParameter = wiv;
      wm.ulParameterLen = sizeof(wiv);
      rv = f->C_WrapKey(sess, &wm, wrap, h, NULL_PTR, &wlen);
      CHECK(rv == CKR_KEY_UNEXTRACTABLE,
            "sealed child wrap refused (rv=0x%lx)", (unsigned long)rv);
      rv = f->C_DestroyObject(sess, h);
      CHECK(rv == CKR_OK, "sealed wrap target destroyed");
    }
    if (wrap != 0) {
      rv = f->C_DestroyObject(sess, wrap);
      CHECK(rv == CKR_OK, "wrapping key destroyed");
    }
  }

  /* Unaffected control: unprotected inputs keep a readable child. */
  {
    CK_ULONG len32 = 32;
    CK_ULONG off0 = 0;
    CK_MECHANISM m;
    CK_OBJECT_HANDLE h = 0;
    CK_ATTRIBUTE dt[] = {
      { CKA_CLASS, &seccls, sizeof(seccls) },
      { CKA_KEY_TYPE, &genkt, sizeof(genkt) },
      { CKA_VALUE_LEN, &len32, sizeof(len32) },
      { CKA_TOKEN, &bFalse, sizeof(bFalse) },
      { CKA_SENSITIVE, &bFalse, sizeof(bFalse) },
      { CKA_EXTRACTABLE, &bTrue, sizeof(bTrue) }
    };
    m.mechanism = CKM_EXTRACT_KEY_FROM_KEY;
    m.pParameter = &off0;
    m.ulParameterLen = sizeof(off0);
    rv = f->C_DeriveKey(sess, &m, qbase, dt, 6, &h);
    CHECK(rv == CKR_OK && h != 0, "plain extract derives");
    if (rv == CKR_OK && h != 0) {
      expect_flags(sess, h, CK_FALSE, CK_TRUE, "plain extract");
      expect_bytes(sess, h, base, sizeof(base), "plain extract");
      rv = f->C_DestroyObject(sess, h);
      CHECK(rv == CKR_OK, "plain extract destroyed");
    }
  }

  /* Scoping control: HKDF carries no §6.43 rule, so a readable
   * template over the protected base still derives readable bytes. */
  {
    CK_HKDF_PARAMS hkdf;
    CK_MECHANISM m;
    CK_BYTE info[] = { 'p', '1' };
    CK_ULONG len32 = 32;
    CK_OBJECT_HANDLE h = 0;
    CK_ATTRIBUTE dt[] = {
      { CKA_CLASS, &seccls, sizeof(seccls) },
      { CKA_KEY_TYPE, &genkt, sizeof(genkt) },
      { CKA_VALUE_LEN, &len32, sizeof(len32) },
      { CKA_TOKEN, &bFalse, sizeof(bFalse) },
      { CKA_SENSITIVE, &bFalse, sizeof(bFalse) },
      { CKA_EXTRACTABLE, &bTrue, sizeof(bTrue) }
    };
    CK_BYTE got[32];
    CK_ATTRIBUTE g[] = { { CKA_VALUE, got, sizeof(got) } };
    m.mechanism = CKM_HKDF_DERIVE;
    m.pParameter = &hkdf;
    m.ulParameterLen = sizeof(hkdf);
    hkdf.bExtract = CK_FALSE;
    hkdf.bExpand = CK_TRUE;
    hkdf.prfHashMechanism = CKM_SHA256;
    hkdf.ulSaltType = CKF_HKDF_SALT_NULL;
    hkdf.pSalt = NULL_PTR;
    hkdf.ulSaltLen = 0;
    hkdf.hSaltKey = 0;
    hkdf.pInfo = info;
    hkdf.ulInfoLen = sizeof(info);
    rv = f->C_DeriveKey(sess, &m, pbase, dt, 6, &h);
    CHECK(rv == CKR_OK && h != 0, "HKDF control derives (rv=0x%lx)",
          (unsigned long)rv);
    if (rv == CKR_OK && h != 0) {
      g[0].ulValueLen = sizeof(got);
      rv = f->C_GetAttributeValue(sess, h, g, 1);
      CHECK(rv == CKR_OK && g[0].ulValueLen == sizeof(got),
            "HKDF control reads 32 bytes");
      rv = f->C_DestroyObject(sess, h);
      CHECK(rv == CKR_OK, "HKDF control destroyed");
    }
  }

  rv = f->C_DestroyObject(sess, pbase);
  CHECK(rv == CKR_OK, "protected base destroyed");
  rv = f->C_DestroyObject(sess, paux);
  CHECK(rv == CKR_OK, "protected aux destroyed");
  rv = f->C_DestroyObject(sess, qbase);
  CHECK(rv == CKR_OK, "plain base destroyed");
  rv = f->C_DestroyObject(sess, qaux);
  CHECK(rv == CKR_OK, "plain aux destroyed");
  rv = f->C_DestroyObject(sess, sobase);
  CHECK(rv == CKR_OK, "sens-only base destroyed");
  rv = f->C_DestroyObject(sess, uobase);
  CHECK(rv == CKR_OK, "unextr-only base destroyed");

  rv = f->C_Logout(sess);
  CHECK(rv == CKR_OK, "Logout ok");
  rv = f->C_CloseSession(sess);
  CHECK(rv == CKR_OK, "CloseSession ok");
  rv = f->C_Finalize(NULL_PTR);
  CHECK(rv == CKR_OK, "C_Finalize ok");
  dlclose(dl);

  if (g_failures == 0) {
    printf("PASS: consumer_derive_protection (byte-derivation protection)\n");
    return 0;
  }
  printf("FAILURES: %d\n", g_failures);
  return 1;
}
