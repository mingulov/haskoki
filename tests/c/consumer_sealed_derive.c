/* tests/c/consumer_sealed_derive.c — sealed generic secrets refuse
 * shortening byte derivations.
 *
 * A sealed base (sensitive, unextractable, on the effective view) must
 * not mint a child with less unknown material than itself through the
 * byte-operation mechanisms: CKM_EXTRACT_KEY_FROM_KEY refuses with
 * CKR_KEY_FUNCTION_NOT_PERMITTED, CKM_XOR_BASE_AND_DATA with data
 * shorter than the base refuses the same way, and a child length
 * below the natural output width — an explicit CKA_VALUE_LEN or a
 * fixed-length template key type — refuses with
 * CKR_TEMPLATE_INCONSISTENT on the concatenate and XOR rows. A
 * child key type outside the allow-list (generic secret, the HMAC
 * types, AES, ChaCha20, Camellia, ARIA, SEED) refuses
 * the same way even at full width, since the child's own mechanism
 * would expose the sealed bytes. The auxiliary key of
 * CKM_CONCATENATE_BASE_AND_KEY seals the same way, and
 * CKM_IKE1_EXTENDED_DERIVE without aux key or extra data refuses
 * with CKR_KEY_FUNCTION_NOT_PERMITTED. Full-width allow-listed
 * derives on sealed inputs still succeed, and unsealed inputs keep
 * every row, including the shortening ones.
 *
 * Legs mirror the reported recovery chains (extract, short-data XOR,
 * VALUE_LEN-truncated XOR, the HMAC-oracle child template, the
 * DERIVE-set-later and no-PIN variants, IKE truncation, the
 * fixed-type shortening, and the full-width Poly1305/RC2 children)
 * and assert the refusal at the derive step, with a no-object proof
 * per refusal and readable-byte positive controls on unsealed keys.
 *
 * Standalone C consumer (non-Haskell executable): dlopen()s the built
 * libhaskoki shared module and drives it through the pinned 3.2 headers.
 * This TU deliberately includes ONLY the pinned vendor headers; it never
 * consumes provider-generated artifacts (enforced by the driver script's
 * independence guard).
 *
 * Compile with -Ispec/vendor. Part of scripts/test-consumers.sh.
 * Usage: consumer_sealed_derive <path-to-libhaskoki.so>
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
static CK_OBJECT_CLASS seccls = CKO_SECRET_KEY;
static CK_KEY_TYPE genkt = CKK_GENERIC_SECRET;

static CK_OBJECT_HANDLE mksecret(CK_SESSION_HANDLE s, const char *label,
                                 CK_BYTE *val, CK_ULONG vlen,
                                 CK_BBOOL sens, CK_BBOOL extr,
                                 CK_BBOOL derive) {
  CK_ATTRIBUTE t[] = {
    { CKA_CLASS, &seccls, sizeof(seccls) },
    { CKA_KEY_TYPE, &genkt, sizeof(genkt) },
    { CKA_LABEL, (CK_VOID_PTR)label, (CK_ULONG)strlen(label) },
    { CKA_TOKEN, &bFalse, sizeof(bFalse) },
    { CKA_PRIVATE, &bTrue, sizeof(bTrue) },
    { CKA_DERIVE, &derive, sizeof(derive) },
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

/* Objects carrying this label: the no-object proof after a refusal. */
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

/* Expect sealed flags and an unreadable value. */
static void expect_sealed_child(CK_SESSION_HANDLE s, CK_OBJECT_HANDLE h,
                                CK_ULONG vlen, const char *what) {
  CK_BBOOL gs = 0xa5, ge = 0xa5;
  CK_ATTRIBUTE q[] = {
    { CKA_SENSITIVE, &gs, sizeof(gs) },
    { CKA_EXTRACTABLE, &ge, sizeof(ge) }
  };
  CK_BYTE guard[96];
  CK_ATTRIBUTE g;
  CK_RV rv = f->C_GetAttributeValue(s, h, q, 2);
  CHECK(rv == CKR_OK && gs == CK_TRUE && ge == CK_FALSE,
        "%s sealed flags (rv=0x%lx)", what, (unsigned long)rv);
  memset(guard, 0xa5, sizeof(guard));
  g.type = CKA_VALUE;
  g.pValue = guard + 16;
  g.ulValueLen = vlen;
  rv = f->C_GetAttributeValue(s, h, &g, 1);
  CHECK(rv == CKR_ATTRIBUTE_SENSITIVE, "%s value sealed (rv=0x%lx)",
        what, (unsigned long)rv);
}

/* One refusal leg: the derive must refuse with the pinned code, mint
 * no handle, and leave no object behind under the child label. */
static void refuse_leg(CK_SESSION_HANDLE s, CK_MECHANISM *m,
                       CK_OBJECT_HANDLE base, CK_ATTRIBUTE *dt, CK_ULONG ndt,
                       CK_RV want, const char *childLabel, const char *what) {
  CK_OBJECT_HANDLE h = 0;
  CK_RV rv = f->C_DeriveKey(s, m, base, dt, ndt, &h);
  CHECK(rv == want && h == 0, "%s refuses 0x%lx (rv=0x%lx)",
        what, (unsigned long)want, (unsigned long)rv);
  CHECK(count_label(s, childLabel) == 0, "%s leaves no object", what);
  printf("sealed-derive: %s refused 0x%lx\n", what, (unsigned long)rv);
}

int main(int argc, char **argv) {
  CK_RV rv;
  CK_C_GetFunctionList getList = NULL;
  void *dl = NULL;
  CK_SLOT_ID slots[8];
  CK_ULONG nslots = 8;
  CK_SESSION_HANDLE sess = 0;
  CK_OBJECT_HANDLE sealed = 0, sealedAux = 0, open = 0, openAux = 0;
  CK_OBJECT_HANDLE lateH = 0, hmacBase = 0;
  CK_BYTE sval[16], auxval[16], oval[16], oauxval[16], hmacval[4];
  CK_BYTE zeros[32];
  CK_ULONG i;
  CK_MECHANISM kg;
  CK_ULONG klen = 16;
  CK_OBJECT_HANDLE genSealed = 0;

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

  for (i = 0; i < 16; i++) {
    sval[i] = (CK_BYTE)(0x30 + i);
    auxval[i] = (CK_BYTE)(0x50 + i);
    oval[i] = (CK_BYTE)(0x70 + i);
    oauxval[i] = (CK_BYTE)(0x90 + i);
  }
  hmacval[0] = 0x3c;
  hmacval[1] = 0x00;
  hmacval[2] = 0xff;
  hmacval[3] = 0x7e;
  memset(zeros, 0, sizeof(zeros));

  /* A generated sealed key with no usage flags: DERIVE defaults
   * false, and any read-write session can set it, so the seal gate
   * must refuse on its own. */
  kg.mechanism = CKM_GENERIC_SECRET_KEY_GEN;
  kg.pParameter = NULL_PTR;
  kg.ulParameterLen = 0;
  {
    CK_ATTRIBUTE gt[] = {
      { CKA_VALUE_LEN, &klen, sizeof(klen) },
      { CKA_TOKEN, &bFalse, sizeof(bFalse) },
      { CKA_SENSITIVE, &bTrue, sizeof(bTrue) },
      { CKA_EXTRACTABLE, &bFalse, sizeof(bFalse) }
    };
    CK_BBOOL der = 0xa5;
    CK_ATTRIBUTE fl[] = { { CKA_DERIVE, &der, sizeof(der) } };
    rv = f->C_GenerateKey(sess, &kg, gt, 4, &genSealed);
    CHECK(rv == CKR_OK && genSealed != 0, "generate sealed (rv=0x%lx)",
          (unsigned long)rv);
    rv = f->C_GetAttributeValue(sess, genSealed, fl, 1);
    CHECK(rv == CKR_OK && der == CK_FALSE, "generated DERIVE defaults false");
  }

  sealed = mksecret(sess, "sealed-base", sval, 16, CK_TRUE, CK_FALSE, CK_TRUE);
  sealedAux = mksecret(sess, "sealed-aux", auxval, 16, CK_TRUE, CK_FALSE,
                       CK_TRUE);
  open = mksecret(sess, "open-base", oval, 16, CK_FALSE, CK_TRUE, CK_TRUE);
  openAux = mksecret(sess, "open-aux", oauxval, 16, CK_FALSE, CK_TRUE,
                     CK_TRUE);

  /* Extract chain: the recovery's step A refuses outright. */
  {
    CK_ULONG off0 = 0, off8 = 8, one = 1, full = 16;
    CK_MECHANISM em0, em8;
    CK_ATTRIBUTE dt1[] = {
      { CKA_CLASS, &seccls, sizeof(seccls) },
      { CKA_KEY_TYPE, &genkt, sizeof(genkt) },
      { CKA_VALUE_LEN, &one, sizeof(one) },
      { CKA_TOKEN, &bFalse, sizeof(bFalse) },
      { CKA_LABEL, (CK_VOID_PTR)"ref-x1", 6 }
    };
    CK_ATTRIBUTE dtFull[] = {
      { CKA_CLASS, &seccls, sizeof(seccls) },
      { CKA_KEY_TYPE, &genkt, sizeof(genkt) },
      { CKA_VALUE_LEN, &full, sizeof(full) },
      { CKA_TOKEN, &bFalse, sizeof(bFalse) },
      { CKA_LABEL, (CK_VOID_PTR)"ref-xf", 6 }
    };
    CK_ATTRIBUTE dtNoLen[] = {
      { CKA_CLASS, &seccls, sizeof(seccls) },
      { CKA_KEY_TYPE, &genkt, sizeof(genkt) },
      { CKA_TOKEN, &bFalse, sizeof(bFalse) },
      { CKA_LABEL, (CK_VOID_PTR)"ref-xn", 6 }
    };
    em0.mechanism = CKM_EXTRACT_KEY_FROM_KEY;
    em0.pParameter = &off0;
    em0.ulParameterLen = sizeof(off0);
    em8.mechanism = CKM_EXTRACT_KEY_FROM_KEY;
    em8.pParameter = &off8;
    em8.ulParameterLen = sizeof(off8);
    refuse_leg(sess, &em0, sealed, dt1, 5, CKR_KEY_FUNCTION_NOT_PERMITTED,
               "ref-x1", "sealed extract 1 byte");
    refuse_leg(sess, &em8, sealed, dt1, 5, CKR_KEY_FUNCTION_NOT_PERMITTED,
               "ref-x1", "sealed extract at offset");
    refuse_leg(sess, &em0, sealed, dtFull, 5, CKR_KEY_FUNCTION_NOT_PERMITTED,
               "ref-xf", "sealed extract full width");
    refuse_leg(sess, &em0, sealed, dtNoLen, 4, CKR_KEY_FUNCTION_NOT_PERMITTED,
               "ref-xn", "sealed extract without length");
    refuse_leg(sess, &em0, genSealed, dt1, 5, CKR_KEY_FUNCTION_NOT_PERMITTED,
               "ref-x1", "generated sealed extract, DERIVE unset");
    /* Flipping DERIVE on does not reopen the seal gate. */
    {
      CK_ATTRIBUTE flip[] = { { CKA_DERIVE, &bTrue, sizeof(bTrue) } };
      CK_BBOOL der = 0xa5;
      CK_ATTRIBUTE fl[] = { { CKA_DERIVE, &der, sizeof(der) } };
      rv = f->C_SetAttributeValue(sess, genSealed, flip, 1);
      CHECK(rv == CKR_OK, "set generated DERIVE true (rv=0x%lx)",
            (unsigned long)rv);
      rv = f->C_GetAttributeValue(sess, genSealed, fl, 1);
      CHECK(rv == CKR_OK && der == CK_TRUE,
            "generated DERIVE reads back true (rv=0x%lx)",
            (unsigned long)rv);
    }
    refuse_leg(sess, &em0, genSealed, dt1, 5, CKR_KEY_FUNCTION_NOT_PERMITTED,
               "ref-x1", "generated sealed extract 1 byte (DERIVE set)");
  }

  /* Control: a generated unsealed key with explicit DERIVE extracts. */
  {
    CK_OBJECT_HANDLE genOpen = 0;
    CK_ULONG off = 0, one = 1;
    CK_MECHANISM em;
    CK_ATTRIBUTE gt[] = {
      { CKA_VALUE_LEN, &klen, sizeof(klen) },
      { CKA_TOKEN, &bFalse, sizeof(bFalse) },
      { CKA_SENSITIVE, &bFalse, sizeof(bFalse) },
      { CKA_EXTRACTABLE, &bTrue, sizeof(bTrue) },
      { CKA_DERIVE, &bTrue, sizeof(bTrue) }
    };
    CK_ATTRIBUTE dt[] = {
      { CKA_CLASS, &seccls, sizeof(seccls) },
      { CKA_KEY_TYPE, &genkt, sizeof(genkt) },
      { CKA_VALUE_LEN, &one, sizeof(one) },
      { CKA_TOKEN, &bFalse, sizeof(bFalse) },
      { CKA_LABEL, (CK_VOID_PTR)"open-gen-x1", 11 }
    };
    CK_OBJECT_HANDLE h = 0;
    rv = f->C_GenerateKey(sess, &kg, gt, 5, &genOpen);
    CHECK(rv == CKR_OK && genOpen != 0, "generate open (rv=0x%lx)",
          (unsigned long)rv);
    em.mechanism = CKM_EXTRACT_KEY_FROM_KEY;
    em.pParameter = &off;
    em.ulParameterLen = sizeof(off);
    rv = f->C_DeriveKey(sess, &em, genOpen, dt, 5, &h);
    CHECK(rv == CKR_OK && h != 0, "generated open extract 1 byte (rv=0x%lx)",
          (unsigned long)rv);
    if (rv == CKR_OK && h != 0) {
      rv = f->C_DestroyObject(sess, h);
      CHECK(rv == CKR_OK, "generated open extract child destroyed");
    }
    rv = f->C_DestroyObject(sess, genOpen);
    CHECK(rv == CKR_OK, "generated open destroyed");
  }

  /* Short-data XOR chain: data shorter than the sealed base refuses. */
  {
    CK_KEY_DERIVATION_STRING_DATA sd;
    CK_MECHANISM xm;
    CK_ULONG len8 = 8;
    CK_ATTRIBUTE dt[] = {
      { CKA_CLASS, &seccls, sizeof(seccls) },
      { CKA_KEY_TYPE, &genkt, sizeof(genkt) },
      { CKA_VALUE_LEN, &len8, sizeof(len8) },
      { CKA_TOKEN, &bFalse, sizeof(bFalse) },
      { CKA_LABEL, (CK_VOID_PTR)"ref-xs", 6 }
    };
    CK_ATTRIBUTE dtNoLen[] = {
      { CKA_CLASS, &seccls, sizeof(seccls) },
      { CKA_KEY_TYPE, &genkt, sizeof(genkt) },
      { CKA_TOKEN, &bFalse, sizeof(bFalse) },
      { CKA_LABEL, (CK_VOID_PTR)"ref-xn", 6 }
    };
    sd.pData = zeros;
    sd.ulLen = 8;
    xm.mechanism = CKM_XOR_BASE_AND_DATA;
    xm.pParameter = &sd;
    xm.ulParameterLen = sizeof(sd);
    refuse_leg(sess, &xm, sealed, dt, 5, CKR_KEY_FUNCTION_NOT_PERMITTED,
               "ref-xs", "sealed xor short data");
    refuse_leg(sess, &xm, sealed, dtNoLen, 4, CKR_KEY_FUNCTION_NOT_PERMITTED,
               "ref-xn", "sealed xor short data without length");
  }

  /* VALUE_LEN truncation chains: below the natural width refuses. */
  {
    CK_KEY_DERIVATION_STRING_DATA sd;
    CK_MECHANISM xm, cm, dm, km;
    CK_ULONG len8 = 8, natural;
    CK_OBJECT_HANDLE second = sealedAux;
    CK_ATTRIBUTE dt[] = {
      { CKA_CLASS, &seccls, sizeof(seccls) },
      { CKA_KEY_TYPE, &genkt, sizeof(genkt) },
      { CKA_VALUE_LEN, &len8, sizeof(len8) },
      { CKA_TOKEN, &bFalse, sizeof(bFalse) },
      { CKA_LABEL, (CK_VOID_PTR)"ref-xt", 6 }
    };
    sd.pData = zeros;
    sd.ulLen = 16;
    xm.mechanism = CKM_XOR_BASE_AND_DATA;
    xm.pParameter = &sd;
    xm.ulParameterLen = sizeof(sd);
    cm.mechanism = CKM_CONCATENATE_BASE_AND_DATA;
    cm.pParameter = &sd;
    cm.ulParameterLen = sizeof(sd);
    dm.mechanism = CKM_CONCATENATE_DATA_AND_BASE;
    dm.pParameter = &sd;
    dm.ulParameterLen = sizeof(sd);
    km.mechanism = CKM_CONCATENATE_BASE_AND_KEY;
    km.pParameter = &second;
    km.ulParameterLen = sizeof(second);
    refuse_leg(sess, &xm, sealed, dt, 5, CKR_TEMPLATE_INCONSISTENT,
               "ref-xt", "sealed xor truncation");
    refuse_leg(sess, &cm, sealed, dt, 5, CKR_TEMPLATE_INCONSISTENT,
               "ref-xt", "sealed concat-data truncation");
    refuse_leg(sess, &dm, sealed, dt, 5, CKR_TEMPLATE_INCONSISTENT,
               "ref-xt", "sealed data-concat truncation");
    refuse_leg(sess, &km, sealed, dt, 5, CKR_TEMPLATE_INCONSISTENT,
               "ref-xt", "sealed concat-key truncation");
    /* The natural width itself still derives a sealed child. */
    natural = 32;
    {
      CK_ATTRIBUTE dtNat[] = {
        { CKA_CLASS, &seccls, sizeof(seccls) },
        { CKA_KEY_TYPE, &genkt, sizeof(genkt) },
        { CKA_VALUE_LEN, &natural, sizeof(natural) },
        { CKA_TOKEN, &bFalse, sizeof(bFalse) },
        { CKA_LABEL, (CK_VOID_PTR)"sealed-full", 11 }
      };
      CK_OBJECT_HANDLE h = 0;
      rv = f->C_DeriveKey(sess, &cm, sealed, dtNat, 5, &h);
      CHECK(rv == CKR_OK && h != 0, "sealed concat full width (rv=0x%lx)",
            (unsigned long)rv);
      if (rv == CKR_OK && h != 0) {
        expect_sealed_child(sess, h, 32, "sealed concat child");
        rv = f->C_DestroyObject(sess, h);
        CHECK(rv == CKR_OK, "sealed concat child destroyed");
      }
    }
    /* Omitted lengths default to the natural width and derive. */
    {
      CK_ATTRIBUTE dtDef[] = {
        { CKA_CLASS, &seccls, sizeof(seccls) },
        { CKA_KEY_TYPE, &genkt, sizeof(genkt) },
        { CKA_TOKEN, &bFalse, sizeof(bFalse) },
        { CKA_LABEL, (CK_VOID_PTR)"sealed-def", 10 }
      };
      CK_OBJECT_HANDLE h = 0;
      rv = f->C_DeriveKey(sess, &xm, sealed, dtDef, 4, &h);
      CHECK(rv == CKR_OK && h != 0, "sealed xor default width (rv=0x%lx)",
            (unsigned long)rv);
      if (rv == CKR_OK && h != 0) {
        expect_sealed_child(sess, h, 16, "sealed xor child");
        rv = f->C_DestroyObject(sess, h);
        CHECK(rv == CKR_OK, "sealed xor child destroyed");
      }
    }
    /* Data longer than the base covers the base and derives. */
    {
      CK_KEY_DERIVATION_STRING_DATA sl;
      CK_MECHANISM xl;
      CK_ATTRIBUTE dtDef[] = {
        { CKA_CLASS, &seccls, sizeof(seccls) },
        { CKA_KEY_TYPE, &genkt, sizeof(genkt) },
        { CKA_TOKEN, &bFalse, sizeof(bFalse) },
        { CKA_LABEL, (CK_VOID_PTR)"sealed-def", 10 }
      };
      CK_OBJECT_HANDLE h = 0;
      sl.pData = zeros;
      sl.ulLen = 32;
      xl.mechanism = CKM_XOR_BASE_AND_DATA;
      xl.pParameter = &sl;
      xl.ulParameterLen = sizeof(sl);
      rv = f->C_DeriveKey(sess, &xl, sealed, dtDef, 4, &h);
      CHECK(rv == CKR_OK && h != 0, "sealed xor long data (rv=0x%lx)",
            (unsigned long)rv);
      if (rv == CKR_OK && h != 0) {
        expect_sealed_child(sess, h, 16, "sealed xor long child");
        rv = f->C_DestroyObject(sess, h);
        CHECK(rv == CKR_OK, "sealed xor long child destroyed");
      }
    }
  }

  /* HMAC-oracle chain: the 1-byte SIGN child never mints. */
  hmacBase = mksecret(sess, "hmac-base", hmacval, 4, CK_TRUE, CK_FALSE,
                      CK_TRUE);
  {
    CK_ULONG off = 0, one = 1;
    CK_MECHANISM em;
    CK_ATTRIBUTE dt[] = {
      { CKA_CLASS, &seccls, sizeof(seccls) },
      { CKA_KEY_TYPE, &genkt, sizeof(genkt) },
      { CKA_VALUE_LEN, &one, sizeof(one) },
      { CKA_TOKEN, &bFalse, sizeof(bFalse) },
      { CKA_SIGN, &bTrue, sizeof(bTrue) },
      { CKA_LABEL, (CK_VOID_PTR)"ref-hmac", 8 }
    };
    em.mechanism = CKM_EXTRACT_KEY_FROM_KEY;
    em.pParameter = &off;
    em.ulParameterLen = sizeof(off);
    refuse_leg(sess, &em, hmacBase, dt, 6, CKR_KEY_FUNCTION_NOT_PERMITTED,
               "ref-hmac", "sealed extract sign child");
  }

  /* DERIVE-set-later chain: flipping the flag does not reopen it. */
  {
    CK_ATTRIBUTE noDerive[] = {
      { CKA_CLASS, &seccls, sizeof(seccls) },
      { CKA_KEY_TYPE, &genkt, sizeof(genkt) },
      { CKA_LABEL, (CK_VOID_PTR)"late-base", 9 },
      { CKA_TOKEN, &bFalse, sizeof(bFalse) },
      { CKA_PRIVATE, &bTrue, sizeof(bTrue) },
      { CKA_DERIVE, &bFalse, sizeof(bFalse) },
      { CKA_SENSITIVE, &bTrue, sizeof(bTrue) },
      { CKA_EXTRACTABLE, &bFalse, sizeof(bFalse) },
      { CKA_VALUE, hmacval, 4 }
    };
    CK_ATTRIBUTE flip[] = { { CKA_DERIVE, &bTrue, sizeof(bTrue) } };
    CK_ULONG off = 0, one = 1;
    CK_MECHANISM em;
    CK_ATTRIBUTE dt[] = {
      { CKA_CLASS, &seccls, sizeof(seccls) },
      { CKA_KEY_TYPE, &genkt, sizeof(genkt) },
      { CKA_VALUE_LEN, &one, sizeof(one) },
      { CKA_TOKEN, &bFalse, sizeof(bFalse) },
      { CKA_LABEL, (CK_VOID_PTR)"ref-late", 8 }
    };
    rv = f->C_CreateObject(sess, noDerive, 9, &lateH);
    CHECK(rv == CKR_OK && lateH != 0, "import derive-false (rv=0x%lx)",
          (unsigned long)rv);
    rv = f->C_SetAttributeValue(sess, lateH, flip, 1);
    CHECK(rv == CKR_OK, "set DERIVE true (rv=0x%lx)", (unsigned long)rv);
    em.mechanism = CKM_EXTRACT_KEY_FROM_KEY;
    em.pParameter = &off;
    em.ulParameterLen = sizeof(off);
    refuse_leg(sess, &em, lateH, dt, 5, CKR_KEY_FUNCTION_NOT_PERMITTED,
               "ref-late", "derive-set-later extract");
  }

  /* IKEv1-extended truncation chain: no aux key and empty extra
   * data would return raw base bytes, so a sealed base refuses. */
  {
    CK_IKE1_EXTENDED_DERIVE_PARAMS ip;
    CK_MECHANISM im;
    CK_ULONG full = 16;
    CK_ATTRIBUTE dt[] = {
      { CKA_CLASS, &seccls, sizeof(seccls) },
      { CKA_KEY_TYPE, &genkt, sizeof(genkt) },
      { CKA_VALUE_LEN, &full, sizeof(full) },
      { CKA_TOKEN, &bFalse, sizeof(bFalse) },
      { CKA_SENSITIVE, &bFalse, sizeof(bFalse) },
      { CKA_EXTRACTABLE, &bTrue, sizeof(bTrue) },
      { CKA_LABEL, (CK_VOID_PTR)"ref-ike", 7 }
    };
    CK_ATTRIBUTE dtOpen[] = {
      { CKA_CLASS, &seccls, sizeof(seccls) },
      { CKA_KEY_TYPE, &genkt, sizeof(genkt) },
      { CKA_VALUE_LEN, &full, sizeof(full) },
      { CKA_TOKEN, &bFalse, sizeof(bFalse) },
      { CKA_LABEL, (CK_VOID_PTR)"open-ike", 8 }
    };
    CK_OBJECT_HANDLE h = 0;
    ip.prfMechanism = CKM_SHA256_HMAC;
    ip.bHasKeygxy = CK_FALSE;
    ip.hKeygxy = 0;
    ip.pExtraData = NULL_PTR;
    ip.ulExtraDataLen = 0;
    im.mechanism = CKM_IKE1_EXTENDED_DERIVE;
    im.pParameter = &ip;
    im.ulParameterLen = sizeof(ip);
    refuse_leg(sess, &im, sealed, dt, 7, CKR_KEY_FUNCTION_NOT_PERMITTED,
               "ref-ike", "sealed ike truncation");
    /* Unsealed control: the truncation derives the base bytes. */
    rv = f->C_DeriveKey(sess, &im, open, dtOpen, 5, &h);
    CHECK(rv == CKR_OK && h != 0, "open ike truncation derives (rv=0x%lx)",
          (unsigned long)rv);
    if (rv == CKR_OK && h != 0) {
      expect_bytes(sess, h, oval, 16, "open ike truncation child");
      rv = f->C_DestroyObject(sess, h);
      CHECK(rv == CKR_OK, "open ike truncation child destroyed");
    }
  }

  /* Fixed-length type chain: a template naming CKK_POLY1305 with
   * no length fills in 32 bytes, below the 47-byte natural width
   * (31 data + 16 base), so a sealed base refuses. */
  {
    CK_KEY_DERIVATION_STRING_DATA sd;
    CK_MECHANISM dm;
    CK_KEY_TYPE poly = CKK_POLY1305;
    CK_BYTE data31[31];
    CK_ULONG j31;
    CK_ATTRIBUTE dt[] = {
      { CKA_CLASS, &seccls, sizeof(seccls) },
      { CKA_KEY_TYPE, &poly, sizeof(poly) },
      { CKA_TOKEN, &bFalse, sizeof(bFalse) },
      { CKA_SIGN, &bTrue, sizeof(bTrue) },
      { CKA_LABEL, (CK_VOID_PTR)"ref-poly", 8 }
    };
    for (j31 = 0; j31 < sizeof(data31); j31++) {
      data31[j31] = (CK_BYTE)j31;
    }
    sd.pData = data31;
    sd.ulLen = sizeof(data31);
    dm.mechanism = CKM_CONCATENATE_DATA_AND_BASE;
    dm.pParameter = &sd;
    dm.ulParameterLen = sizeof(sd);
    refuse_leg(sess, &dm, sealed, dt, 5, CKR_TEMPLATE_INCONSISTENT,
               "ref-poly", "sealed data-concat poly1305 typelen");
  }

  /* Full-width typed-child chain: 16 zero data bytes plus the
   * 16-byte sealed base give a 32-byte natural width, so a
   * CKK_POLY1305 child fills in exactly. The child would be zero
   * bytes concatenated with the sealed value; with r = 0 the
   * Poly1305 tag of any message equals the sealed half, so the
   * derive refuses with no object created. */
  {
    CK_KEY_DERIVATION_STRING_DATA sd;
    CK_MECHANISM dm;
    CK_KEY_TYPE poly = CKK_POLY1305;
    CK_ATTRIBUTE dt[] = {
      { CKA_CLASS, &seccls, sizeof(seccls) },
      { CKA_KEY_TYPE, &poly, sizeof(poly) },
      { CKA_TOKEN, &bFalse, sizeof(bFalse) },
      { CKA_SIGN, &bTrue, sizeof(bTrue) },
      { CKA_LABEL, (CK_VOID_PTR)"ref-fullpoly", 12 }
    };
    sd.pData = zeros;
    sd.ulLen = 16;
    dm.mechanism = CKM_CONCATENATE_DATA_AND_BASE;
    dm.pParameter = &sd;
    dm.ulParameterLen = sizeof(sd);
    refuse_leg(sess, &dm, sealed, dt, 5, CKR_TEMPLATE_INCONSISTENT,
               "ref-fullpoly", "sealed data-concat poly1305 full width");
  }

  /* RC2/128 chain: 112 data bytes plus the 16-byte sealed base give
   * a 128-byte natural width; a full-width RC2 child would expose
   * the sealed bytes through effective-bits stepping, so it refuses. */
  {
    CK_KEY_DERIVATION_STRING_DATA sd;
    CK_MECHANISM cm;
    CK_KEY_TYPE rc2 = CKK_RC2;
    CK_BYTE data112[112];
    CK_ULONG j112, vlen = 128;
    CK_ATTRIBUTE dt[] = {
      { CKA_CLASS, &seccls, sizeof(seccls) },
      { CKA_KEY_TYPE, &rc2, sizeof(rc2) },
      { CKA_VALUE_LEN, &vlen, sizeof(vlen) },
      { CKA_TOKEN, &bFalse, sizeof(bFalse) },
      { CKA_ENCRYPT, &bTrue, sizeof(bTrue) },
      { CKA_LABEL, (CK_VOID_PTR)"ref-rc2", 7 }
    };
    for (j112 = 0; j112 < sizeof(data112); j112++) {
      data112[j112] = (CK_BYTE)j112;
    }
    sd.pData = data112;
    sd.ulLen = sizeof(data112);
    cm.mechanism = CKM_CONCATENATE_BASE_AND_DATA;
    cm.pParameter = &sd;
    cm.ulParameterLen = sizeof(sd);
    refuse_leg(sess, &cm, sealed, dt, 6, CKR_TEMPLATE_INCONSISTENT,
               "ref-rc2", "sealed concat-data rc2 full width");
  }

  /* DES3 chain: 8 zero data bytes plus the 16-byte sealed base
   * give a 24-byte natural width, so a CKK_DES3 child fills in
   * exactly. A known part of a DES3 key reduces the sealed bytes
   * to DES-strength search, so the derive refuses with no object
   * created. */
  {
    CK_KEY_DERIVATION_STRING_DATA sd;
    CK_MECHANISM dm;
    CK_KEY_TYPE des3 = CKK_DES3;
    CK_ATTRIBUTE dt[] = {
      { CKA_CLASS, &seccls, sizeof(seccls) },
      { CKA_KEY_TYPE, &des3, sizeof(des3) },
      { CKA_TOKEN, &bFalse, sizeof(bFalse) },
      { CKA_ENCRYPT, &bTrue, sizeof(bTrue) },
      { CKA_LABEL, (CK_VOID_PTR)"ref-des3", 8 }
    };
    sd.pData = zeros;
    sd.ulLen = 8;
    dm.mechanism = CKM_CONCATENATE_DATA_AND_BASE;
    dm.pParameter = &sd;
    dm.ulParameterLen = sizeof(sd);
    refuse_leg(sess, &dm, sealed, dt, 5, CKR_TEMPLATE_INCONSISTENT,
               "ref-des3", "sealed data-concat des3 full width");
  }

  /* Unsealed control: the same Poly1305 derive on the open base
   * succeeds, and C_Sign returns the open value (r = 0, tag = s),
   * proving both the readout shape and that only the seal refuses. */
  {
    CK_KEY_DERIVATION_STRING_DATA sd;
    CK_MECHANISM dm, sm;
    CK_KEY_TYPE poly = CKK_POLY1305;
    CK_OBJECT_HANDLE h = 0;
    CK_BYTE msg[] = "poly1305 readout control";
    CK_BYTE tag[16];
    CK_ULONG tagLen = sizeof(tag);
    CK_ATTRIBUTE dt[] = {
      { CKA_CLASS, &seccls, sizeof(seccls) },
      { CKA_KEY_TYPE, &poly, sizeof(poly) },
      { CKA_TOKEN, &bFalse, sizeof(bFalse) },
      { CKA_SIGN, &bTrue, sizeof(bTrue) },
      { CKA_LABEL, (CK_VOID_PTR)"open-poly", 9 }
    };
    sd.pData = zeros;
    sd.ulLen = 16;
    dm.mechanism = CKM_CONCATENATE_DATA_AND_BASE;
    dm.pParameter = &sd;
    dm.ulParameterLen = sizeof(sd);
    rv = f->C_DeriveKey(sess, &dm, open, dt, 5, &h);
    CHECK(rv == CKR_OK && h != 0, "open data-concat poly1305 derives (rv=0x%lx)",
          (unsigned long)rv);
    if (rv == CKR_OK && h != 0) {
      sm.mechanism = CKM_POLY1305;
      sm.pParameter = NULL_PTR;
      sm.ulParameterLen = 0;
      rv = f->C_SignInit(sess, &sm, h);
      CHECK(rv == CKR_OK, "open poly1305 sign init (rv=0x%lx)",
            (unsigned long)rv);
      rv = f->C_Sign(sess, msg, sizeof(msg) - 1, tag, &tagLen);
      CHECK(rv == CKR_OK && tagLen == 16 && memcmp(tag, oval, 16) == 0,
            "open poly1305 tag equals the open value (rv=0x%lx)",
            (unsigned long)rv);
      rv = f->C_DestroyObject(sess, h);
      CHECK(rv == CKR_OK, "open poly1305 child destroyed");
    }
  }

  /* Unsealed control: the same DES3 derive on the open base
   * succeeds with the data-then-base bytes. */
  {
    CK_KEY_DERIVATION_STRING_DATA sd;
    CK_MECHANISM dm;
    CK_KEY_TYPE des3 = CKK_DES3;
    CK_OBJECT_HANDLE h = 0;
    CK_BYTE want[24];
    CK_ULONG j;
    CK_ATTRIBUTE dt[] = {
      { CKA_CLASS, &seccls, sizeof(seccls) },
      { CKA_KEY_TYPE, &des3, sizeof(des3) },
      { CKA_TOKEN, &bFalse, sizeof(bFalse) },
      { CKA_ENCRYPT, &bTrue, sizeof(bTrue) },
      { CKA_LABEL, (CK_VOID_PTR)"open-des3", 9 }
    };
    sd.pData = zeros;
    sd.ulLen = 8;
    dm.mechanism = CKM_CONCATENATE_DATA_AND_BASE;
    dm.pParameter = &sd;
    dm.ulParameterLen = sizeof(sd);
    rv = f->C_DeriveKey(sess, &dm, open, dt, 5, &h);
    CHECK(rv == CKR_OK && h != 0, "open data-concat des3 derives (rv=0x%lx)",
          (unsigned long)rv);
    if (rv == CKR_OK && h != 0) {
      for (j = 0; j < 8; j++) {
        want[j] = 0;
      }
      for (j = 0; j < 16; j++) {
        want[8 + j] = oval[j];
      }
      expect_bytes(sess, h, want, 24, "open des3 child");
      rv = f->C_DestroyObject(sess, h);
      CHECK(rv == CKR_OK, "open des3 child destroyed");
    }
  }

  /* Unsealed positive controls: every shortening row still derives. */
  {
    CK_ULONG off8 = 8, one = 1, len8 = 8;
    CK_MECHANISM em;
    CK_KEY_DERIVATION_STRING_DATA sd8, sd16;
    CK_MECHANISM xm8, xm16, cm;
    CK_OBJECT_HANDLE second = openAux;
    CK_MECHANISM km;
    CK_OBJECT_HANDLE h = 0;
    CK_BYTE want1[1], want8[8], wantCat[8];
    CK_ULONG j;
    CK_ATTRIBUTE dt1[] = {
      { CKA_CLASS, &seccls, sizeof(seccls) },
      { CKA_KEY_TYPE, &genkt, sizeof(genkt) },
      { CKA_VALUE_LEN, &one, sizeof(one) },
      { CKA_TOKEN, &bFalse, sizeof(bFalse) },
      { CKA_LABEL, (CK_VOID_PTR)"open-x1", 7 }
    };
    CK_ATTRIBUTE dt8[] = {
      { CKA_CLASS, &seccls, sizeof(seccls) },
      { CKA_KEY_TYPE, &genkt, sizeof(genkt) },
      { CKA_VALUE_LEN, &len8, sizeof(len8) },
      { CKA_TOKEN, &bFalse, sizeof(bFalse) },
      { CKA_LABEL, (CK_VOID_PTR)"open-x8", 7 }
    };
    em.mechanism = CKM_EXTRACT_KEY_FROM_KEY;
    em.pParameter = &off8;
    em.ulParameterLen = sizeof(off8);
    rv = f->C_DeriveKey(sess, &em, open, dt1, 5, &h);
    CHECK(rv == CKR_OK && h != 0, "open extract derives (rv=0x%lx)",
          (unsigned long)rv);
    if (rv == CKR_OK && h != 0) {
      want1[0] = oval[1];
      expect_bytes(sess, h, want1, 1, "open extract child");
      rv = f->C_DestroyObject(sess, h);
      CHECK(rv == CKR_OK, "open extract child destroyed");
      h = 0;
    }
    sd8.pData = zeros;
    sd8.ulLen = 8;
    xm8.mechanism = CKM_XOR_BASE_AND_DATA;
    xm8.pParameter = &sd8;
    xm8.ulParameterLen = sizeof(sd8);
    rv = f->C_DeriveKey(sess, &xm8, open, dt8, 5, &h);
    CHECK(rv == CKR_OK && h != 0, "open xor short derives (rv=0x%lx)",
          (unsigned long)rv);
    if (rv == CKR_OK && h != 0) {
      for (j = 0; j < 8; j++) {
        want8[j] = oval[j];
      }
      expect_bytes(sess, h, want8, 8, "open xor short child");
      rv = f->C_DestroyObject(sess, h);
      CHECK(rv == CKR_OK, "open xor short child destroyed");
      h = 0;
    }
    sd16.pData = zeros;
    sd16.ulLen = 16;
    xm16.mechanism = CKM_XOR_BASE_AND_DATA;
    xm16.pParameter = &sd16;
    xm16.ulParameterLen = sizeof(sd16);
    rv = f->C_DeriveKey(sess, &xm16, open, dt8, 5, &h);
    CHECK(rv == CKR_OK && h != 0, "open xor truncation derives (rv=0x%lx)",
          (unsigned long)rv);
    if (rv == CKR_OK && h != 0) {
      for (j = 0; j < 8; j++) {
        want8[j] = oval[j];
      }
      expect_bytes(sess, h, want8, 8, "open xor truncated child");
      rv = f->C_DestroyObject(sess, h);
      CHECK(rv == CKR_OK, "open xor truncated child destroyed");
      h = 0;
    }
    cm.mechanism = CKM_CONCATENATE_BASE_AND_DATA;
    cm.pParameter = &sd16;
    cm.ulParameterLen = sizeof(sd16);
    rv = f->C_DeriveKey(sess, &cm, open, dt8, 5, &h);
    CHECK(rv == CKR_OK && h != 0, "open concat truncation derives (rv=0x%lx)",
          (unsigned long)rv);
    if (rv == CKR_OK && h != 0) {
      for (j = 0; j < 8; j++) {
        wantCat[j] = oval[j];
      }
      expect_bytes(sess, h, wantCat, 8, "open concat truncated child");
      rv = f->C_DestroyObject(sess, h);
      CHECK(rv == CKR_OK, "open concat truncated child destroyed");
      h = 0;
    }
    km.mechanism = CKM_CONCATENATE_BASE_AND_KEY;
    km.pParameter = &second;
    km.ulParameterLen = sizeof(second);
    rv = f->C_DeriveKey(sess, &km, open, dt8, 5, &h);
    CHECK(rv == CKR_OK && h != 0, "open concat-key truncation (rv=0x%lx)",
          (unsigned long)rv);
    if (rv == CKR_OK && h != 0) {
      for (j = 0; j < 8; j++) {
        wantCat[j] = oval[j];
      }
      expect_bytes(sess, h, wantCat, 8, "open concat-key truncated child");
      rv = f->C_DestroyObject(sess, h);
      CHECK(rv == CKR_OK, "open concat-key truncated child destroyed");
      h = 0;
    }
  }

  rv = f->C_DestroyObject(sess, sealed);
  CHECK(rv == CKR_OK, "sealed base destroyed");
  rv = f->C_DestroyObject(sess, sealedAux);
  CHECK(rv == CKR_OK, "sealed aux destroyed");
  rv = f->C_DestroyObject(sess, open);
  CHECK(rv == CKR_OK, "open base destroyed");
  rv = f->C_DestroyObject(sess, openAux);
  CHECK(rv == CKR_OK, "open aux destroyed");
  rv = f->C_DestroyObject(sess, genSealed);
  CHECK(rv == CKR_OK, "generated sealed destroyed");
  rv = f->C_DestroyObject(sess, hmacBase);
  CHECK(rv == CKR_OK, "hmac base destroyed");
  rv = f->C_DestroyObject(sess, lateH);
  CHECK(rv == CKR_OK, "late base destroyed");

  /* No-PIN variant: a sealed token key with public visibility is
   * found and flipped from an unauthenticated session, yet the
   * extract still refuses. Runs last: the logout below drops
   * private session objects. */
  {
    CK_OBJECT_HANDLE victim = 0;
    CK_SESSION_HANDLE pub = 0;
    CK_ULONG vlen = 16;
    CK_ATTRIBUTE gt[] = {
      { CKA_VALUE_LEN, &vlen, sizeof(vlen) },
      { CKA_TOKEN, &bTrue, sizeof(bTrue) },
      { CKA_PRIVATE, &bFalse, sizeof(bFalse) },
      { CKA_SENSITIVE, &bTrue, sizeof(bTrue) },
      { CKA_EXTRACTABLE, &bFalse, sizeof(bFalse) },
      { CKA_DERIVE, &bFalse, sizeof(bFalse) },
      { CKA_LABEL, (CK_VOID_PTR)"nopin-victim", 12 }
    };
    CK_ATTRIBUTE want[] = {
      { CKA_LABEL, (CK_VOID_PTR)"nopin-victim", 12 }
    };
    CK_OBJECT_HANDLE found[2];
    CK_ULONG nfound = 0;
    CK_ATTRIBUTE flip[] = { { CKA_DERIVE, &bTrue, sizeof(bTrue) } };
    CK_ULONG off = 0, one = 1;
    CK_MECHANISM em;
    CK_ATTRIBUTE dt[] = {
      { CKA_CLASS, &seccls, sizeof(seccls) },
      { CKA_KEY_TYPE, &genkt, sizeof(genkt) },
      { CKA_VALUE_LEN, &one, sizeof(one) },
      { CKA_TOKEN, &bFalse, sizeof(bFalse) },
      { CKA_LABEL, (CK_VOID_PTR)"ref-nopin", 9 }
    };
    rv = f->C_GenerateKey(sess, &kg, gt, 7, &victim);
    CHECK(rv == CKR_OK && victim != 0, "generate nopin victim (rv=0x%lx)",
          (unsigned long)rv);
    rv = f->C_Logout(sess);
    CHECK(rv == CKR_OK, "logout for nopin (rv=0x%lx)", (unsigned long)rv);
    rv = f->C_OpenSession(slots[0], CKF_SERIAL_SESSION | CKF_RW_SESSION,
                          NULL_PTR, NULL_PTR, &pub);
    CHECK(rv == CKR_OK && pub != 0, "nopin public session (rv=0x%lx)",
          (unsigned long)rv);
    if (rv == CKR_OK && pub != 0 && victim != 0) {
      rv = f->C_FindObjectsInit(pub, want, 1);
      CHECK(rv == CKR_OK, "nopin find init (rv=0x%lx)", (unsigned long)rv);
      rv = f->C_FindObjects(pub, found, 2, &nfound);
      CHECK(rv == CKR_OK && nfound == 1, "nopin victim found (rv=0x%lx n=%lu)",
            (unsigned long)rv, (unsigned long)nfound);
      rv = f->C_FindObjectsFinal(pub);
      CHECK(rv == CKR_OK, "nopin find final (rv=0x%lx)", (unsigned long)rv);
      if (nfound == 1) {
        rv = f->C_SetAttributeValue(pub, found[0], flip, 1);
        CHECK(rv == CKR_OK, "nopin set DERIVE true (rv=0x%lx)",
              (unsigned long)rv);
        em.mechanism = CKM_EXTRACT_KEY_FROM_KEY;
        em.pParameter = &off;
        em.ulParameterLen = sizeof(off);
        refuse_leg(pub, &em, found[0], dt, 5, CKR_KEY_FUNCTION_NOT_PERMITTED,
                   "ref-nopin", "nopin extract");
      }
      rv = f->C_CloseSession(pub);
      CHECK(rv == CKR_OK, "nopin public session closed");
    }
    rv = f->C_Login(sess, CKU_USER, (CK_UTF8CHAR_PTR)"1234", 4);
    CHECK(rv == CKR_OK, "re-login after nopin (rv=0x%lx)", (unsigned long)rv);
    if (victim != 0) {
      rv = f->C_DestroyObject(sess, victim);
      CHECK(rv == CKR_OK, "nopin victim destroyed");
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
    printf("PASS: consumer_sealed_derive (sealed byte-derivation refusals)\n");
    return 0;
  }
  printf("FAILURES: %d\n", g_failures);
  return 1;
}
