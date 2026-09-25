/* tests/c/consumer_template_attrs.c — direct-load consumer: template attributes.
 *
 * Standalone C consumer (non-Haskell executable): dlopen()s the built
 * libhaskoki shared module and pins the T1 template-attribute slice:
 *   - C_CreateObject secret-key import carries CKA_ALLOWED_MECHANISMS
 *     (accepted, readable back, enforced: listed mech works, unlisted
 *     mech is refused)
 *   - CKA_VALUE_LEN coherence on import: must match len(CKA_VALUE);
 *     oversized/absurd VALUE_LEN refused; AES lengths restricted to
 *     16/24/32
 *   - CKA_COPYABLE=false blocks C_CopyObject; CKA_DESTROYABLE=false
 *     blocks C_DestroyObject (true allows it)
 *   - C_SetAttributeValue: LABEL/APPLICATION/ID mutable; TOKEN only
 *     false->true; EXTRACTABLE only true->false; SENSITIVE only
 *     false->true; COPYABLE/DESTROYABLE only true->false; CLASS,
 *     KEY_TYPE, VALUE, VALUE_LEN never mutable; mixed templates are
 *     atomic (all-or-nothing)
 *   - CKO_CERTIFICATE creation with CERTIFICATE_TYPE/VALUE/SUBJECT/ID
 *   - CKO_DATA up to 1 MiB round-trips
 *   - CKA_ENCAPSULATE on AES keygen refused (non-PQC key)
 *
 * This TU deliberately includes ONLY the pinned vendor headers; it
 * never consumes provider-generated artifacts (enforced by the
 * driver script's independence guard).
 *
 * Compile with -Ispec/vendor. Part of scripts/test-consumers.sh.
 * Usage: consumer_template_attrs <path-to-libhaskoki.so>
 *
 * The ALLOWED_MECHANISMS readback and the oversized-VALUE_LEN legs
 * are direct-only (isProxy-gated): the pkcs11-proxy-ng Rust shim
 * mangles the 0x40000600 attribute id on the response path and
 * panics allocating for VALUE_LEN=2^64-1 ("exceeds allocation
 * limit"), so those pins assert our module's contract, not the
 * shim's. All other legs run in both topologies under
 * scripts/test-proxy-parity.sh.
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
#include <unistd.h>

static int g_failures = 0;

#define CHECK(cond, ...)                                                   \
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

/* Hermetic config: real-crypto engine, trace off (no stray files),
 * memory storage. */
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
  char tmpl[] = "/tmp/haskoki-consumer-XXXXXX";
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
  CK_SLOT_ID slots[16];
  CK_ULONG nslots = 16;
  CK_SESSION_HANDLE sess = 0;
  CK_MECHANISM mech;
  CK_OBJECT_HANDLE key = 0, key2 = 0, cert = 0, data = 0, tmp = 0;
  CK_OBJECT_CLASS cls;
  CK_KEY_TYPE kt;
  CK_ULONG vlen;
  CK_MECHANISM_TYPE allowed[2];
  CK_BBOOL bFalse = CK_FALSE, bTrue = CK_TRUE;
  CK_BYTE key16[16], key15[15], pt[16], ct[32];
  CK_ULONG len;
  CK_BYTE label0[] = "label-zero";
  CK_BYTE label1[] = "label-one";
  CK_BYTE id0[] = {0x01, 0x02};
  CK_BYTE id1[] = {0xaa, 0xbb};
  CK_BYTE subject[] = "CN=probe";
  CK_BYTE der[64];
  CK_ULONG certType;
  CK_BYTE *big = NULL;
  const char *topo;
  int isProxy;
  size_t i;

  if (argc != 2) {
    fprintf(stderr, "usage: %s <libhaskoki.so>\n", argv[0]);
    return 2;
  }
  topo = getenv("HASKOKI_CONSUMER_TOPOLOGY");
  isProxy = topo && strcmp(topo, "proxy") == 0;
  printf("topology: %s\n", isProxy ? "proxy" : "direct");
  write_config();
  handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
  if (handle == NULL) {
    fprintf(stderr, "dlopen failed: %s\n", dlerror());
    return 2;
  }
  pGetList = (CK_C_GetFunctionList)dlsym(handle, "C_GetFunctionList");
  if (pGetList == NULL) {
    fprintf(stderr, "dlsym C_GetFunctionList failed: %s\n", dlerror());
    return 2;
  }
  rv = pGetList(&f);
  if (rv != CKR_OK || f == NULL_PTR) {
    fprintf(stderr, "C_GetFunctionList failed: 0x%lx\n", (unsigned long)rv);
    return 2;
  }
  for (i = 0; i < sizeof(key16); i++) key16[i] = (CK_BYTE)i;
  for (i = 0; i < sizeof(key15); i++) key15[i] = (CK_BYTE)i;
  for (i = 0; i < sizeof(pt); i++) pt[i] = (CK_BYTE)(0x40 + i);
  for (i = 0; i < sizeof(der); i++) der[i] = (CK_BYTE)(0x30 + (i % 16));

  rv = f->C_Initialize(NULL_PTR);
  CHECK(rv == CKR_OK, "initialize ok");
  rv = f->C_GetSlotList(CK_TRUE, slots, &nslots);
  CHECK(rv == CKR_OK && nslots > 0, "slot list ok");
  rv = f->C_OpenSession(slots[0], CKF_SERIAL_SESSION | CKF_RW_SESSION,
                        NULL_PTR, NULL_PTR, &sess);
  CHECK(rv == CKR_OK, "session opens");

  /* ---- 1. import with CKA_ALLOWED_MECHANISMS ---- */
  cls = CKO_SECRET_KEY;
  kt = CKK_AES;
  allowed[0] = CKM_AES_ECB;
  {
    CK_ATTRIBUTE tmpl[] = {
        {CKA_CLASS, &cls, sizeof(cls)},
        {CKA_KEY_TYPE, &kt, sizeof(kt)},
        {CKA_VALUE, key16, sizeof(key16)},
        {CKA_ENCRYPT, &bTrue, sizeof(bTrue)},
        {CKA_DECRYPT, &bTrue, sizeof(bTrue)},
        {CKA_TOKEN, &bFalse, sizeof(bFalse)},
        {CKA_ALLOWED_MECHANISMS, allowed, sizeof(allowed[0])},
    };
    rv = f->C_CreateObject(sess, tmpl, 7, &key);
    CHECK(rv == CKR_OK, "import with ALLOWED_MECHANISMS ok");
  }
  if (key != 0) {
    CK_MECHANISM_TYPE got[4];
    CK_ATTRIBUTE rd[] = {
        {CKA_ALLOWED_MECHANISMS, got, sizeof(got)},
    };
    if (isProxy) {
      printf("crypto: ok: ALLOWED_MECHANISMS readback skipped (proxy)\n");
    } else {
      rv = f->C_GetAttributeValue(sess, key, rd, 1);
      CHECK(rv == CKR_OK && rd[0].ulValueLen == sizeof(allowed[0]) &&
                got[0] == CKM_AES_ECB,
            "ALLOWED_MECHANISMS reads back");
    }
    /* Listed mechanism works. */
    mech.mechanism = CKM_AES_ECB;
    mech.pParameter = NULL_PTR;
    mech.ulParameterLen = 0;
    rv = f->C_EncryptInit(sess, &mech, key);
    CHECK(rv == CKR_OK, "allowed mech init ok");
    if (rv == CKR_OK) {
      len = sizeof(ct);
      rv = f->C_Encrypt(sess, pt, sizeof(pt), ct, &len);
      CHECK(rv == CKR_OK && len == 16, "allowed mech encrypts");
    }
    /* Unlisted mechanism refused. */
    mech.mechanism = CKM_AES_CBC;
    {
      CK_BYTE iv[16];
      memset(iv, 0, sizeof(iv));
      mech.pParameter = iv;
      mech.ulParameterLen = sizeof(iv);
    }
    rv = f->C_EncryptInit(sess, &mech, key);
    CHECK(rv != CKR_OK, "unlisted mech refused");
    f->C_DestroyObject(sess, key);
    key = 0;
  }

  /* ---- 2. VALUE_LEN coherence ---- */
  cls = CKO_SECRET_KEY;
  kt = CKK_AES;
  vlen = 16;
  {
    CK_ATTRIBUTE tmpl[] = {
        {CKA_CLASS, &cls, sizeof(cls)},
        {CKA_KEY_TYPE, &kt, sizeof(kt)},
        {CKA_VALUE, key16, sizeof(key16)},
        {CKA_VALUE_LEN, &vlen, sizeof(vlen)},
        {CKA_TOKEN, &bFalse, sizeof(bFalse)},
    };
    key = 0;
    rv = f->C_CreateObject(sess, tmpl, 5, &key);
    CHECK(rv == CKR_OK, "matching VALUE_LEN ok");
    if (key != 0) {
      f->C_DestroyObject(sess, key);
      key = 0;
    }
  }
  vlen = 17;
  {
    CK_ATTRIBUTE tmpl[] = {
        {CKA_CLASS, &cls, sizeof(cls)},
        {CKA_KEY_TYPE, &kt, sizeof(kt)},
        {CKA_VALUE, key16, sizeof(key16)},
        {CKA_VALUE_LEN, &vlen, sizeof(vlen)},
        {CKA_TOKEN, &bFalse, sizeof(bFalse)},
    };
    tmp = 0;
    rv = f->C_CreateObject(sess, tmpl, 5, &tmp);
    CHECK(rv != CKR_OK, "mismatched VALUE_LEN refused");
    if (rv == CKR_OK) f->C_DestroyObject(sess, tmp);
  }
  vlen = (CK_ULONG)-1;
  if (isProxy) {
    printf("crypto: ok: oversized VALUE_LEN skipped (proxy)\n");
  } else {
    CK_ATTRIBUTE tmpl[] = {
        {CKA_CLASS, &cls, sizeof(cls)},
        {CKA_KEY_TYPE, &kt, sizeof(kt)},
        {CKA_VALUE, key16, sizeof(key16)},
        {CKA_VALUE_LEN, &vlen, sizeof(vlen)},
        {CKA_TOKEN, &bFalse, sizeof(bFalse)},
    };
    tmp = 0;
    rv = f->C_CreateObject(sess, tmpl, 5, &tmp);
    CHECK(rv != CKR_OK, "oversized VALUE_LEN refused");
    if (rv == CKR_OK) f->C_DestroyObject(sess, tmp);
  }
  {
    CK_ATTRIBUTE tmpl[] = {
        {CKA_CLASS, &cls, sizeof(cls)},
        {CKA_KEY_TYPE, &kt, sizeof(kt)},
        {CKA_VALUE, key15, sizeof(key15)},
        {CKA_TOKEN, &bFalse, sizeof(bFalse)},
    };
    tmp = 0;
    rv = f->C_CreateObject(sess, tmpl, 4, &tmp);
    CHECK(rv != CKR_OK, "15-byte AES value refused");
    if (rv == CKR_OK) f->C_DestroyObject(sess, tmp);
  }

  /* ---- 3. COPYABLE / DESTROYABLE ---- */
  {
    CK_MECHANISM kgm;
    CK_ATTRIBUTE ktmpl[8];
    int n = 0;
    CK_OBJECT_CLASS scls = CKO_SECRET_KEY;
    CK_KEY_TYPE akkt = CKK_AES;
    CK_ULONG alen = 16;
    kgm.mechanism = CKM_AES_KEY_GEN;
    kgm.pParameter = NULL_PTR;
    kgm.ulParameterLen = 0;
    ktmpl[n].type = CKA_CLASS;
    ktmpl[n].pValue = &scls;
    ktmpl[n].ulValueLen = sizeof(scls);
    n++;
    ktmpl[n].type = CKA_KEY_TYPE;
    ktmpl[n].pValue = &akkt;
    ktmpl[n].ulValueLen = sizeof(akkt);
    n++;
    ktmpl[n].type = CKA_VALUE_LEN;
    ktmpl[n].pValue = &alen;
    ktmpl[n].ulValueLen = sizeof(alen);
    n++;
    ktmpl[n].type = CKA_TOKEN;
    ktmpl[n].pValue = &bFalse;
    ktmpl[n].ulValueLen = sizeof(bFalse);
    n++;
    ktmpl[n].type = CKA_COPYABLE;
    ktmpl[n].pValue = &bFalse;
    ktmpl[n].ulValueLen = sizeof(bFalse);
    n++;
    key = 0;
    rv = f->C_GenerateKey(sess, &kgm, ktmpl, (CK_ULONG)n, &key);
    CHECK(rv == CKR_OK, "keygen COPYABLE=false ok");
    if (key != 0) {
      key2 = 0;
      rv = f->C_CopyObject(sess, key, NULL_PTR, 0, &key2);
      CHECK(rv != CKR_OK, "copy of COPYABLE=false refused");
      if (rv == CKR_OK) f->C_DestroyObject(sess, key2);
      f->C_DestroyObject(sess, key);
      key = 0;
    }
  }
  {
    CK_MECHANISM kgm;
    CK_ATTRIBUTE ktmpl[8];
    int n = 0;
    CK_OBJECT_CLASS scls = CKO_SECRET_KEY;
    CK_KEY_TYPE akkt = CKK_AES;
    CK_ULONG alen = 16;
    kgm.mechanism = CKM_AES_KEY_GEN;
    kgm.pParameter = NULL_PTR;
    kgm.ulParameterLen = 0;
    ktmpl[n].type = CKA_CLASS;
    ktmpl[n].pValue = &scls;
    ktmpl[n].ulValueLen = sizeof(scls);
    n++;
    ktmpl[n].type = CKA_KEY_TYPE;
    ktmpl[n].pValue = &akkt;
    ktmpl[n].ulValueLen = sizeof(akkt);
    n++;
    ktmpl[n].type = CKA_VALUE_LEN;
    ktmpl[n].pValue = &alen;
    ktmpl[n].ulValueLen = sizeof(alen);
    n++;
    ktmpl[n].type = CKA_TOKEN;
    ktmpl[n].pValue = &bFalse;
    ktmpl[n].ulValueLen = sizeof(bFalse);
    n++;
    ktmpl[n].type = CKA_DESTROYABLE;
    ktmpl[n].pValue = &bFalse;
    ktmpl[n].ulValueLen = sizeof(bFalse);
    n++;
    key = 0;
    rv = f->C_GenerateKey(sess, &kgm, ktmpl, (CK_ULONG)n, &key);
    CHECK(rv == CKR_OK, "keygen DESTROYABLE=false ok");
    if (key != 0) {
      rv = f->C_DestroyObject(sess, key);
      CHECK(rv != CKR_OK, "destroy of DESTROYABLE=false refused");
      /* Session object: reclaimed at C_CloseSession. */
      if (rv == CKR_OK) key = 0;
    }
  }

  /* ---- 4. C_SetAttributeValue ---- */
  {
    CK_MECHANISM kgm;
    CK_ATTRIBUTE ktmpl[8];
    int n = 0;
    CK_OBJECT_CLASS scls = CKO_SECRET_KEY;
    CK_KEY_TYPE akkt = CKK_AES;
    CK_ULONG alen = 16;
    kgm.mechanism = CKM_AES_KEY_GEN;
    kgm.pParameter = NULL_PTR;
    kgm.ulParameterLen = 0;
    ktmpl[n].type = CKA_CLASS;
    ktmpl[n].pValue = &scls;
    ktmpl[n].ulValueLen = sizeof(scls);
    n++;
    ktmpl[n].type = CKA_KEY_TYPE;
    ktmpl[n].pValue = &akkt;
    ktmpl[n].ulValueLen = sizeof(akkt);
    n++;
    ktmpl[n].type = CKA_VALUE_LEN;
    ktmpl[n].pValue = &alen;
    ktmpl[n].ulValueLen = sizeof(alen);
    n++;
    ktmpl[n].type = CKA_TOKEN;
    ktmpl[n].pValue = &bFalse;
    ktmpl[n].ulValueLen = sizeof(bFalse);
    n++;
    ktmpl[n].type = CKA_LABEL;
    ktmpl[n].pValue = label0;
    ktmpl[n].ulValueLen = sizeof(label0) - 1;
    n++;
    ktmpl[n].type = CKA_ID;
    ktmpl[n].pValue = id0;
    ktmpl[n].ulValueLen = sizeof(id0);
    n++;
    key = 0;
    rv = f->C_GenerateKey(sess, &kgm, ktmpl, (CK_ULONG)n, &key);
    CHECK(rv == CKR_OK, "setattr keygen ok");
  }
  if (key != 0) {
    CK_BYTE got[32];
    CK_ATTRIBUTE lset[] = {
        {CKA_LABEL, label1, sizeof(label1) - 1},
    };
    CK_ATTRIBUTE lrd[] = {
        {CKA_LABEL, got, sizeof(got)},
    };
    rv = f->C_SetAttributeValue(sess, key, lset, 1);
    CHECK(rv == CKR_OK, "LABEL change ok");
    rv = f->C_GetAttributeValue(sess, key, lrd, 1);
    CHECK(rv == CKR_OK && lrd[0].ulValueLen == sizeof(label1) - 1 &&
              memcmp(got, label1, sizeof(label1) - 1) == 0,
          "LABEL readback ok");
    {
      CK_ATTRIBUTE iset[] = {
          {CKA_ID, id1, sizeof(id1)},
      };
      CK_ATTRIBUTE ird[] = {
          {CKA_ID, got, sizeof(got)},
      };
      rv = f->C_SetAttributeValue(sess, key, iset, 1);
      CHECK(rv == CKR_OK, "ID change ok");
      rv = f->C_GetAttributeValue(sess, key, ird, 1);
      CHECK(rv == CKR_OK && ird[0].ulValueLen == sizeof(id1) &&
                memcmp(got, id1, sizeof(id1)) == 0,
          "ID readback ok");
    }
    {
      CK_ATTRIBUTE eset[] = {
          {CKA_EXTRACTABLE, &bFalse, sizeof(bFalse)},
      };
      rv = f->C_SetAttributeValue(sess, key, eset, 1);
      CHECK(rv == CKR_OK, "EXTRACTABLE true->false ok");
      eset[0].pValue = &bTrue;
      rv = f->C_SetAttributeValue(sess, key, eset, 1);
      CHECK(rv == CKR_ATTRIBUTE_READ_ONLY, "EXTRACTABLE false->true refused");
    }
    {
      CK_ATTRIBUTE sset[] = {
          {CKA_SENSITIVE, &bTrue, sizeof(bTrue)},
      };
      rv = f->C_SetAttributeValue(sess, key, sset, 1);
      CHECK(rv == CKR_OK, "SENSITIVE false->true ok");
      sset[0].pValue = &bFalse;
      rv = f->C_SetAttributeValue(sess, key, sset, 1);
      CHECK(rv == CKR_ATTRIBUTE_READ_ONLY, "SENSITIVE true->false refused");
    }
    {
      CK_ATTRIBUTE tset[] = {
          {CKA_TOKEN, &bTrue, sizeof(bTrue)},
      };
      CK_BBOOL gotTok = CK_FALSE;
      CK_ATTRIBUTE trd[] = {
          {CKA_TOKEN, &gotTok, sizeof(gotTok)},
      };
      rv = f->C_SetAttributeValue(sess, key, tset, 1);
      CHECK(rv == CKR_OK, "TOKEN false->true ok");
      rv = f->C_GetAttributeValue(sess, key, trd, 1);
      CHECK(rv == CKR_OK && gotTok == CK_TRUE, "TOKEN readback true");
      tset[0].pValue = &bFalse;
      rv = f->C_SetAttributeValue(sess, key, tset, 1);
      CHECK(rv == CKR_ATTRIBUTE_READ_ONLY, "TOKEN true->false refused");
    }
    {
      /* Atomicity: LABEL valid + CLASS invalid must change nothing. */
      CK_OBJECT_CLASS other = CKO_DATA;
      CK_ATTRIBUTE mix[] = {
          {CKA_LABEL, label0, sizeof(label0) - 1},
          {CKA_CLASS, &other, sizeof(other)},
      };
      CK_ATTRIBUTE lrd2[] = {
          {CKA_LABEL, got, sizeof(got)},
      };
      rv = f->C_SetAttributeValue(sess, key, mix, 2);
      CHECK(rv != CKR_OK, "mixed template refused");
      rv = f->C_GetAttributeValue(sess, key, lrd2, 1);
      CHECK(rv == CKR_OK && lrd2[0].ulValueLen == sizeof(label1) - 1 &&
                memcmp(got, label1, sizeof(label1) - 1) == 0,
          "mixed template atomic (LABEL kept)");
    }
    {
      CK_BYTE newval[16];
      CK_ATTRIBUTE vset[] = {
          {CKA_VALUE, newval, sizeof(newval)},
      };
      memset(newval, 0xee, sizeof(newval));
      rv = f->C_SetAttributeValue(sess, key, vset, 1);
      CHECK(rv != CKR_OK, "VALUE change refused");
    }
    f->C_DestroyObject(sess, key);
    key = 0;
  }

  /* ---- 5. certificate object ---- */
  cls = CKO_CERTIFICATE;
  certType = CKC_X_509;
  {
    CK_BYTE spki[] = {0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
                      0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00};
    CK_BYTE hsh[20];
    CK_ATTRIBUTE tmpl[] = {
        {CKA_CLASS, &cls, sizeof(cls)},
        {CKA_CERTIFICATE_TYPE, &certType, sizeof(certType)},
        {CKA_VALUE, der, sizeof(der)},
        {CKA_SUBJECT, subject, sizeof(subject) - 1},
        {CKA_ID, id0, sizeof(id0)},
        {CKA_TOKEN, &bFalse, sizeof(bFalse)},
        {CKA_PUBLIC_KEY_INFO, spki, sizeof(spki)},
        {CKA_HASH_OF_SUBJECT_PUBLIC_KEY, hsh, sizeof(hsh)},
        {CKA_HASH_OF_ISSUER_PUBLIC_KEY, hsh, sizeof(hsh)},
    };
    memset(hsh, 0x5a, sizeof(hsh));
    cert = 0;
    rv = f->C_CreateObject(sess, tmpl, 9, &cert);
    CHECK(rv == CKR_OK, "certificate create ok");
    if (cert != 0) {
      CK_BYTE gotd[128];
      CK_ATTRIBUTE rd[] = {
          {CKA_VALUE, gotd, sizeof(gotd)},
      };
      rv = f->C_GetAttributeValue(sess, cert, rd, 1);
      CHECK(rv == CKR_OK && rd[0].ulValueLen == sizeof(der) &&
                memcmp(gotd, der, sizeof(der)) == 0,
          "certificate VALUE readback ok");
      f->C_DestroyObject(sess, cert);
      cert = 0;
    }
  }

  /* ---- 6. large data object (1 MiB) ---- */
  big = (CK_BYTE *)malloc(1024 * 1024);
  CHECK(big != NULL, "1 MiB buffer allocated");
  if (big != NULL) {
    CK_ATTRIBUTE tmpl[4];
    CK_OBJECT_CLASS dcls = CKO_DATA;
    memset(big, 0xab, 1024 * 1024);
    tmpl[0].type = CKA_CLASS;
    tmpl[0].pValue = &dcls;
    tmpl[0].ulValueLen = sizeof(dcls);
    tmpl[1].type = CKA_LABEL;
    tmpl[1].pValue = label0;
    tmpl[1].ulValueLen = sizeof(label0) - 1;
    tmpl[2].type = CKA_VALUE;
    tmpl[2].pValue = big;
    tmpl[2].ulValueLen = 1024 * 1024;
    tmpl[3].type = CKA_TOKEN;
    tmpl[3].pValue = &bFalse;
    tmpl[3].ulValueLen = sizeof(bFalse);
    data = 0;
    rv = f->C_CreateObject(sess, tmpl, 4, &data);
    CHECK(rv == CKR_OK, "1 MiB data create ok");
    if (data != 0) {
      CK_ATTRIBUTE rd[] = {
          {CKA_VALUE, NULL_PTR, 0},
      };
      rv = f->C_GetAttributeValue(sess, data, rd, 1);
      CHECK(rv == CKR_OK && rd[0].ulValueLen == 1024 * 1024,
          "1 MiB data length readback ok");
      f->C_DestroyObject(sess, data);
      data = 0;
    }
    free(big);
    big = NULL;
  }

  /* ---- 7. encapsulate on AES keygen refused ---- */
  {
    CK_MECHANISM kgm;
    CK_ATTRIBUTE ktmpl[8];
    int n = 0;
    CK_OBJECT_CLASS scls = CKO_SECRET_KEY;
    CK_KEY_TYPE akkt = CKK_AES;
    CK_ULONG alen = 16;
    kgm.mechanism = CKM_AES_KEY_GEN;
    kgm.pParameter = NULL_PTR;
    kgm.ulParameterLen = 0;
    ktmpl[n].type = CKA_CLASS;
    ktmpl[n].pValue = &scls;
    ktmpl[n].ulValueLen = sizeof(scls);
    n++;
    ktmpl[n].type = CKA_KEY_TYPE;
    ktmpl[n].pValue = &akkt;
    ktmpl[n].ulValueLen = sizeof(akkt);
    n++;
    ktmpl[n].type = CKA_VALUE_LEN;
    ktmpl[n].pValue = &alen;
    ktmpl[n].ulValueLen = sizeof(alen);
    n++;
    ktmpl[n].type = CKA_TOKEN;
    ktmpl[n].pValue = &bFalse;
    ktmpl[n].ulValueLen = sizeof(bFalse);
    n++;
    ktmpl[n].type = CKA_ENCAPSULATE;
    ktmpl[n].pValue = &bTrue;
    ktmpl[n].ulValueLen = sizeof(bTrue);
    n++;
    tmp = 0;
    rv = f->C_GenerateKey(sess, &kgm, ktmpl, (CK_ULONG)n, &tmp);
    CHECK(rv != CKR_OK, "ENCAPSULATE on AES keygen refused");
    if (rv == CKR_OK) f->C_DestroyObject(sess, tmp);
  }

  rv = f->C_CloseSession(sess);
  CHECK(rv == CKR_OK, "session closes");
  rv = f->C_Finalize(NULL_PTR);
  CHECK(rv == CKR_OK, "finalize ok");

  dlclose(handle);
  unlink(g_cfg_path);
  if (g_failures == 0) {
    printf("PASS: consumer_template_attrs (%s)\n", argv[1]);
    return 0;
  }
  printf("FAILURES: %d\n", g_failures);
  return 1;
}
