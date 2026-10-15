/* tests/c/consumer_derive_atomic.c — a multi-output derivation that
 * mixes valid and invalid destinations publishes nothing (public
 * C_DeriveKey, SQLite token store).
 *
 * Route: CKM_SP800_108_COUNTER_KDF (HMAC-SHA256 PRF, 32-bit big-endian
 * counter, one fixed-input byte array, 32-bit SUM_OF_KEYS DKM length)
 * with CK_SP800_108_KDF_PARAMS.pAdditionalDerivedKeys: the primary
 * template plus every additional-key template reach the shared derive
 * planner as one template set, and the handles are written back into
 * the caller's phKey and each CK_DERIVED_KEY.phKey on success only.
 *
 * Each mixed request carries at least one valid destination and one
 * invalid one, in the primary, a middle or the last slot:
 *   - malformed encodings (3-byte CKA_VALUE_LEN, CKA_VALUE_LEN past
 *     the platform integer, a 2-byte CK_BBOOL, a CKA_ID past the 4 MiB
 *     value cap, an unmapped attribute id), each once in the primary
 *     and once in the last additional slot: the additional-key
 *     template must refuse with exactly the primary template's code
 *     (template decode, before planning);
 *   - off-domain AES length (AES/7), an asymmetric key type under
 *     CKO_SECRET_KEY and a typed destination without a length
 *     (planner stage);
 *   - a CKA_TRUSTED=TRUE destination from a normal-user session and a
 *     token destination from a read-only session (owner/session
 *     admission, which runs after planning and before any effect);
 *   - a NULL CK_DERIVED_KEY.phKey next to valid templates (parameter
 *     stage).
 * Every refused request must leave the primary output-handle canary
 * and every additional-key handle canary unchanged, publish no object
 * under any of its labels, leave the visible and token object census
 * unchanged, and consume no object handle (a data probe immediately
 * before and after must be consecutive). The derived destinations are
 * token objects (CKA_TOKEN=TRUE), so a leaked subset would be durable.
 *
 * The all-valid control derives AES/16 + AES/32 + GENERIC/20 token
 * keys in one request: every handle slot is written, the values equal
 * an independent SP 800-108 oracle (HMAC-SHA256 computed outside
 * Haskoki with Python's hmac module), the AES keys reproduce AES-ECB
 * known answers computed with the system OpenSSL CLI, and the counter
 * probe advances by exactly the three outputs plus one.
 *
 * Durability: the SQLite store is closed (C_Finalize) and reopened
 * (C_Initialize) on the same database file. After reopen, exactly the
 * three control objects survive with byte-equal values, and no label
 * of any refused request names an object.
 *
 * DIRECT-ONLY store journey (the consumer_login_reopen precedent:
 * behind pkcs11-proxy-ng the daemon owns the store and ignores the
 * client HASKOKI_CONFIG, so the reopen leg cannot be driven). Behind
 * the proxy the scenario skips loud with an invent: note; every
 * direct-only progress line is invent:-prefixed so the parity diff
 * compares only the PASS trailer.
 *
 * Standalone C consumer (non-Haskell executable): dlopen()s the built
 * libhaskoki shared module and drives it through the pinned 3.2 headers.
 * This TU deliberately includes ONLY the pinned vendor headers; it never
 * consumes provider-generated artifacts (enforced by the driver script's
 * independence guard).
 *
 * Compile with -Ispec/vendor. Part of scripts/test-consumers.sh.
 * Usage: consumer_derive_atomic <path-to-libhaskoki.so>
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
      printf("invent: FAIL [%s:%d]: ", __FILE__, __LINE__);                \
      printf(__VA_ARGS__);                                                 \
      printf("\n");                                                        \
      g_failures++;                                                        \
    }                                                                      \
  } while (0)

#define PRIMARY_CANARY ((CK_OBJECT_HANDLE)0x5ca1ab1eUL)
#define ADD_CANARY(i) ((CK_OBJECT_HANDLE)(0x0ddba110UL + (CK_ULONG)(i)))
#define MAX_ADD 3
#define MAX_LABELS 64

static CK_FUNCTION_LIST_PTR f = NULL;
static CK_BBOOL bTrue = CK_TRUE, bFalse = CK_FALSE;

static char g_sql_cfg[256];
static char g_sql_dir[256];
static char g_sql_db[256];

/* Labels of every output of every refused request (re-checked after
 * the store reopens). */
static char g_refused[MAX_LABELS][48];
static int g_nrefused = 0;

/* Base key 40..5f; fixed input "atomic" 00 "set". */
static CK_BYTE base_val[32];
static CK_BYTE fixed_in[10] = { 'a', 't', 'o', 'm', 'i', 'c', 0x00,
                                's', 'e', 't' };

/* SP 800-108 counter KDF, HMAC-SHA256, K = 40..5f,
 * input_i = [i]_32 || fixed_in || [544]_32 (L = 16+32+20 bytes), first
 * 68 bytes of K(1)||K(2)||K(3); computed independently with Python's
 * hmac/hashlib. Split: AES/16 | AES/32 | GENERIC/20. */
static const CK_BYTE dkm[68] = {
  0x36, 0xae, 0x67, 0x78, 0xe9, 0x0d, 0xe3, 0x97,
  0x8a, 0xd7, 0x86, 0x5b, 0x27, 0x30, 0xa8, 0xb8,
  0x42, 0xf0, 0x47, 0x70, 0x06, 0xc3, 0x24, 0xb9,
  0xb3, 0x8b, 0xa5, 0x28, 0x0c, 0xc6, 0xd3, 0x6d,
  0xbf, 0xa9, 0xfc, 0x8b, 0xec, 0x06, 0xd0, 0x1d,
  0x03, 0xeb, 0xcf, 0xdc, 0xd5, 0x60, 0x3b, 0x5e,
  0xbd, 0xb6, 0xc3, 0x9b, 0xab, 0x2b, 0x9b, 0x0a,
  0x88, 0x3e, 0xe9, 0x42, 0x62, 0xd6, 0x8c, 0x88,
  0xdd, 0xd8, 0x45, 0x1b
};
/* FIPS-197 plaintext and its AES-ECB encryption under dkm[0..16) and
 * dkm[16..48) (system OpenSSL CLI, independent of Haskoki). */
static const CK_BYTE kat_pt[16] = {
  0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
  0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
};
static const CK_BYTE kat_ct128[16] = {
  0xd8, 0xce, 0x31, 0xb2, 0xdd, 0x4b, 0x59, 0x05,
  0x3a, 0xf0, 0x0c, 0xd4, 0xb3, 0x88, 0xbe, 0x35
};
static const CK_BYTE kat_ct256[16] = {
  0x07, 0x82, 0x43, 0x70, 0xf6, 0x0d, 0xa6, 0x30,
  0xaa, 0xda, 0x34, 0x2a, 0xd1, 0xb0, 0xa1, 0xf6
};

/* One destination template shape. */
enum out_kind {
  OK_AES16,     /* valid: token AES/16 */
  OK_AES32,     /* valid: token AES/32 */
  OK_GEN20,     /* valid: token GENERIC/20 */
  OK_SESS16,    /* valid: session AES/16 */
  BAD_AES7,     /* off-domain AES length */
  BAD_RSA16,    /* asymmetric type under CKO_SECRET_KEY */
  BAD_AESNOLEN, /* AES without a length */
  BAD_LENSHAPE, /* CKA_VALUE_LEN encoded in 3 bytes */
  BAD_HUGELEN,  /* AES with CKA_VALUE_LEN 2^63 (past the platform int) */
  BAD_BOOLSHAPE,/* AES/16 with CKA_SENSITIVE encoded in 2 bytes */
  BAD_BIGID,    /* AES/16 with a CKA_ID one byte past the 4 MiB cap */
  BAD_UNKATTR,  /* AES/16 plus an unmapped vendor attribute id */
  BAD_TRUSTED   /* GENERIC/20 with CKA_TRUSTED=TRUE (normal user) */
};

/* Attribute-value byte cap of the template decoder (4 MiB). */
#define BIG_ID_LEN (4194304UL + 1UL)
static CK_BYTE g_big_id[BIG_ID_LEN];
static CK_BYTE g_bool2[2] = { 0, 0 };
static CK_BYTE g_unk_val = 0x01;

struct out_tmpl {
  CK_ATTRIBUTE a[12];
  CK_ULONG n;
  CK_OBJECT_CLASS cls;
  CK_KEY_TYPE kt;
  CK_ULONG len;
  CK_BYTE shortlen[3];
  char label[48];
};

static void add_attr(struct out_tmpl *o, CK_ATTRIBUTE_TYPE t, void *p,
                     CK_ULONG l) {
  o->a[o->n].type = t;
  o->a[o->n].pValue = p;
  o->a[o->n].ulValueLen = l;
  o->n++;
}

static void build_out(struct out_tmpl *o, enum out_kind k,
                      const char *label) {
  int aes = (k == OK_AES16 || k == OK_AES32 || k == OK_SESS16 ||
             k == BAD_AES7 || k == BAD_AESNOLEN || k == BAD_LENSHAPE ||
             k == BAD_HUGELEN || k == BAD_BOOLSHAPE || k == BAD_BIGID ||
             k == BAD_UNKATTR);
  memset(o, 0, sizeof(*o));
  snprintf(o->label, sizeof(o->label), "%s", label);
  o->cls = CKO_SECRET_KEY;
  o->kt = aes ? CKK_AES : (k == BAD_RSA16 ? CKK_RSA : CKK_GENERIC_SECRET);
  switch (k) {
  case OK_AES16: case OK_SESS16: case BAD_RSA16: case BAD_BOOLSHAPE:
  case BAD_BIGID: case BAD_UNKATTR: o->len = 16; break;
  case BAD_HUGELEN: o->len = (CK_ULONG)1 << 63; break;
  case OK_AES32: o->len = 32; break;
  case BAD_AES7: o->len = 7; break;
  default: o->len = 20; break;
  }
  add_attr(o, CKA_CLASS, &o->cls, sizeof(o->cls));
  add_attr(o, CKA_KEY_TYPE, &o->kt, sizeof(o->kt));
  if (k == BAD_LENSHAPE) {
    o->shortlen[0] = 16;
    add_attr(o, CKA_VALUE_LEN, o->shortlen, sizeof(o->shortlen));
  } else if (k != BAD_AESNOLEN) {
    add_attr(o, CKA_VALUE_LEN, &o->len, sizeof(o->len));
  }
  add_attr(o, CKA_LABEL, o->label, (CK_ULONG)strlen(o->label));
  add_attr(o, CKA_TOKEN, k == OK_SESS16 ? &bFalse : &bTrue, sizeof(bTrue));
  add_attr(o, CKA_PRIVATE, &bTrue, sizeof(bTrue));
  if (k == BAD_BOOLSHAPE) {
    add_attr(o, CKA_SENSITIVE, g_bool2, sizeof(g_bool2));
  } else {
    add_attr(o, CKA_SENSITIVE, &bFalse, sizeof(bFalse));
  }
  add_attr(o, CKA_EXTRACTABLE, &bTrue, sizeof(bTrue));
  if (aes) {
    add_attr(o, CKA_ENCRYPT, &bTrue, sizeof(bTrue));
  }
  if (k == BAD_TRUSTED) {
    add_attr(o, CKA_TRUSTED, &bTrue, sizeof(bTrue));
  }
  if (k == BAD_BIGID) {
    add_attr(o, CKA_ID, g_big_id, BIG_ID_LEN);
  }
  if (k == BAD_UNKATTR) {
    add_attr(o, CKA_VENDOR_DEFINED | 0x4242UL, &g_unk_val, 1);
  }
}

/* One SP 800-108 counter-mode request: primary template plus nadd
 * additional-key templates; nullSlot >= 0 passes a NULL phKey in that
 * additional entry. */
static CK_RV derive_set(CK_SESSION_HANDLE s, CK_OBJECT_HANDLE base,
                        struct out_tmpl *prim, struct out_tmpl *adds,
                        CK_ULONG nadd, int nullSlot, CK_OBJECT_HANDLE *hPrim,
                        CK_OBJECT_HANDLE *hAdds) {
  CK_SP800_108_COUNTER_FORMAT cf;
  CK_SP800_108_DKM_LENGTH_FORMAT df;
  CK_PRF_DATA_PARAM dp[3];
  CK_DERIVED_KEY dk[MAX_ADD];
  CK_SP800_108_KDF_PARAMS kp;
  CK_MECHANISM m;
  CK_ULONG i;
  memset(&cf, 0, sizeof(cf));
  memset(&df, 0, sizeof(df));
  cf.bLittleEndian = CK_FALSE;
  cf.ulWidthInBits = 32;
  df.dkmLengthMethod = CK_SP800_108_DKM_LENGTH_SUM_OF_KEYS;
  df.bLittleEndian = CK_FALSE;
  df.ulWidthInBits = 32;
  dp[0].type = CK_SP800_108_ITERATION_VARIABLE;
  dp[0].pValue = &cf;
  dp[0].ulValueLen = sizeof(cf);
  dp[1].type = CK_SP800_108_BYTE_ARRAY;
  dp[1].pValue = fixed_in;
  dp[1].ulValueLen = sizeof(fixed_in);
  dp[2].type = CK_SP800_108_DKM_LENGTH;
  dp[2].pValue = &df;
  dp[2].ulValueLen = sizeof(df);
  for (i = 0; i < nadd; i++) {
    dk[i].pTemplate = adds[i].a;
    dk[i].ulAttributeCount = adds[i].n;
    dk[i].phKey = ((int)i == nullSlot) ? NULL_PTR : &hAdds[i];
  }
  kp.prfType = CKM_SHA256_HMAC;
  kp.ulNumberOfDataParams = 3;
  kp.pDataParams = dp;
  kp.ulAdditionalDerivedKeys = nadd;
  kp.pAdditionalDerivedKeys = nadd ? dk : NULL_PTR;
  m.mechanism = CKM_SP800_108_COUNTER_KDF;
  m.pParameter = &kp;
  m.ulParameterLen = sizeof(kp);
  return f->C_DeriveKey(s, &m, base, prim->a, prim->n, hPrim);
}

static CK_ULONG count_match(CK_SESSION_HANDLE s, CK_ATTRIBUTE *match,
                            CK_ULONG nmatch) {
  CK_OBJECT_HANDLE found[64];
  CK_ULONG n = 0, total = 0;
  CK_RV rv = f->C_FindObjectsInit(s, match, nmatch);
  CHECK(rv == CKR_OK, "find init (rv=0x%lx)", (unsigned long)rv);
  if (rv != CKR_OK) {
    return 9999;
  }
  do {
    rv = f->C_FindObjects(s, found, 64, &n);
    CHECK(rv == CKR_OK, "find (rv=0x%lx)", (unsigned long)rv);
    if (rv != CKR_OK) {
      break;
    }
    total += n;
  } while (n == 64);
  rv = f->C_FindObjectsFinal(s);
  CHECK(rv == CKR_OK, "find final (rv=0x%lx)", (unsigned long)rv);
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

static CK_ULONG count_token(CK_SESSION_HANDLE s) {
  CK_ATTRIBUTE match[] = { { CKA_TOKEN, &bTrue, sizeof(bTrue) } };
  return count_match(s, match, 1);
}

/* A throwaway session data object: its handle samples the
 * object-handle counter (handles are allocated sequentially; the
 * control below pins that token and session objects share it). */
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

/* One mixed request that must refuse as a whole. ds is the deriving
 * session; census and probes run on the read-write session ws. */
static void expect_atomic(CK_SESSION_HANDLE ws, CK_SESSION_HANDLE ds,
                          CK_OBJECT_HANDLE base, const char *name,
                          enum out_kind pk, const enum out_kind *ak,
                          CK_ULONG nadd, int nullSlot, CK_RV want) {
  struct out_tmpl prim, adds[MAX_ADD];
  CK_OBJECT_HANDLE hPrim = PRIMARY_CANARY, hAdds[MAX_ADD];
  CK_OBJECT_HANDLE before, after;
  CK_ULONG census, tokens, i;
  char label[48];
  CK_RV rv;
  snprintf(label, sizeof(label), "atom-%s-p", name);
  build_out(&prim, pk, label);
  for (i = 0; i < nadd; i++) {
    snprintf(label, sizeof(label), "atom-%s-a%lu", name, (unsigned long)i);
    build_out(&adds[i], ak[i], label);
    hAdds[i] = ADD_CANARY(i);
  }
  census = count_all(ws);
  tokens = count_token(ws);
  before = mkprobe(ws);
  rv = derive_set(ds, base, &prim, adds, nadd, nullSlot, &hPrim, hAdds);
  after = mkprobe(ws);
  printf("invent: derive-atomic: %s -> rv=0x%lx primary=0x%lx\n", name,
         (unsigned long)rv, (unsigned long)hPrim);
  CHECK(rv == want, "%s refuses 0x%lx (rv=0x%lx)", name,
        (unsigned long)want, (unsigned long)rv);
  CHECK(hPrim == PRIMARY_CANARY,
        "%s leaves the primary handle canary (h=0x%lx)", name,
        (unsigned long)hPrim);
  for (i = 0; i < nadd; i++) {
    CHECK(hAdds[i] == ADD_CANARY(i),
          "%s leaves additional handle canary %lu (h=0x%lx)", name,
          (unsigned long)i, (unsigned long)hAdds[i]);
  }
  CHECK(count_label(ws, prim.label) == 0, "%s publishes no primary", name);
  if (g_nrefused < MAX_LABELS) {
    snprintf(g_refused[g_nrefused++], 48, "%s", prim.label);
  }
  for (i = 0; i < nadd; i++) {
    CHECK(count_label(ws, adds[i].label) == 0,
          "%s publishes no additional key %lu", name, (unsigned long)i);
    if (g_nrefused < MAX_LABELS) {
      snprintf(g_refused[g_nrefused++], 48, "%s", adds[i].label);
    }
  }
  CHECK(count_all(ws) == census + 2, "%s census unchanged (probes only)",
        name);
  CHECK(count_token(ws) == tokens, "%s token census unchanged", name);
  CHECK(after == before + 1, "%s consumes no handle (0x%lx -> 0x%lx)",
        name, (unsigned long)before, (unsigned long)after);
  /* Leaked objects are deliberately kept: the reopen leg re-checks
   * every refused label against the durable store. */
  f->C_DestroyObject(ws, before);
  f->C_DestroyObject(ws, after);
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

/* The object's type, length, token flag and exact value bytes. */
static void expect_value(CK_SESSION_HANDLE s, CK_OBJECT_HANDLE h,
                         CK_KEY_TYPE kt, const CK_BYTE *want,
                         CK_ULONG wlen, const char *what) {
  CK_BYTE got[64];
  CK_BBOOL tok = CK_FALSE;
  CK_ATTRIBUTE g[] = { { CKA_VALUE, got, sizeof(got) },
                       { CKA_TOKEN, &tok, sizeof(tok) } };
  CK_RV rv;
  CHECK(read_ulong(s, h, CKA_KEY_TYPE, what) == kt, "%s key type 0x%lx",
        what, (unsigned long)kt);
  CHECK(read_ulong(s, h, CKA_VALUE_LEN, what) == wlen, "%s length %lu",
        what, (unsigned long)wlen);
  memset(got, 0, sizeof(got));
  rv = f->C_GetAttributeValue(s, h, g, 2);
  CHECK(rv == CKR_OK && g[0].ulValueLen == wlen &&
            memcmp(got, want, wlen) == 0 && tok == CK_TRUE,
        "%s is a token object with the oracle bytes (rv=0x%lx len=%lu)",
        what, (unsigned long)rv, (unsigned long)g[0].ulValueLen);
}

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
  rv = f->C_Encrypt(s, (CK_BYTE_PTR)kat_pt, sizeof(kat_pt), ct, &ctLen);
  CHECK(rv == CKR_OK && ctLen == 16 && memcmp(ct, want, 16) == 0,
        "%s AES known-answer (rv=0x%lx len=%lu)", what, (unsigned long)rv,
        (unsigned long)ctLen);
}

static CK_OBJECT_HANDLE find_one(CK_SESSION_HANDLE s, const char *label) {
  CK_ATTRIBUTE match[] = {
    { CKA_LABEL, (CK_VOID_PTR)label, (CK_ULONG)strlen(label) }
  };
  CK_OBJECT_HANDLE found[4] = { 0, 0, 0, 0 };
  CK_ULONG n = 0;
  CK_RV rv = f->C_FindObjectsInit(s, match, 1);
  CHECK(rv == CKR_OK, "find %s init", label);
  if (rv != CKR_OK) {
    return 0;
  }
  rv = f->C_FindObjects(s, found, 4, &n);
  CHECK(rv == CKR_OK && n == 1, "exactly one %s (rv=0x%lx n=%lu)", label,
        (unsigned long)rv, (unsigned long)n);
  f->C_FindObjectsFinal(s);
  return n == 1 ? found[0] : 0;
}

static void write_sql_config(void) {
  char tmpl[] = "/tmp/haskoki-derive-atomic-db-XXXXXX";
  char cfg[] = "/tmp/haskoki-derive-atomic-cfg-XXXXXX";
  char body[1024];
  size_t want;
  int fd;
  if (mkdtemp(tmpl) == NULL) {
    perror("mkdtemp");
    exit(2);
  }
  snprintf(g_sql_dir, sizeof(g_sql_dir), "%s", tmpl);
  snprintf(g_sql_db, sizeof(g_sql_db), "%s/store.db", tmpl);
  snprintf(body, sizeof(body),
           "schema_version = 1\n"
           "profile = \"real-crypto\"\n"
           "[storage]\n"
           "kind = \"sqlite\"\n"
           "path = \"%s\"\n"
           "[engine]\n"
           "kind = \"openssl\"\n"
           "allow_synthetic_fallback = false\n"
           "private_library_context = true\n"
           "[trace]\n"
           "enabled = false\n",
           g_sql_db);
  fd = mkstemp(cfg);
  if (fd < 0) {
    perror("mkstemp");
    exit(2);
  }
  want = strlen(body);
  if (write(fd, body, want) != (ssize_t)want) {
    perror("write");
    exit(2);
  }
  close(fd);
  snprintf(g_sql_cfg, sizeof(g_sql_cfg), "%s", cfg);
  if (setenv("HASKOKI_CONFIG", g_sql_cfg, 1) != 0) {
    perror("setenv");
    exit(2);
  }
}

static CK_SESSION_HANDLE open_login(CK_SLOT_ID slot, const char *what) {
  CK_SESSION_HANDLE s = 0;
  CK_RV rv = f->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                              NULL_PTR, NULL_PTR, &s);
  CHECK(rv == CKR_OK && s != 0, "%s: OpenSession RW (rv=0x%lx)", what,
        (unsigned long)rv);
  rv = f->C_Login(s, CKU_USER, (CK_UTF8CHAR_PTR) "1234", 4);
  CHECK(rv == CKR_OK, "%s: user login (rv=0x%lx)", what, (unsigned long)rv);
  return s;
}

static void run_journey(void) {
  static const char *ctl_labels[3] = { "atom-ctl-p", "atom-ctl-a0",
                                       "atom-ctl-a1" };
  CK_SLOT_ID slots[8];
  CK_ULONG nslots = 8, tok0, i;
  CK_SESSION_HANDLE ws, ro = 0;
  CK_OBJECT_HANDLE base = 0;
  CK_RV rv;

  for (i = 0; i < sizeof(base_val); i++) {
    base_val[i] = (CK_BYTE)(0x40 + i);
  }
  rv = f->C_Initialize(NULL_PTR);
  CHECK(rv == CKR_OK, "Initialize (rv=0x%lx)", (unsigned long)rv);
  rv = f->C_GetSlotList(CK_TRUE, slots, &nslots);
  CHECK(rv == CKR_OK && nslots == 1, "single token slot");
  ws = open_login(slots[0], "phase 1");
  tok0 = count_token(ws);
  printf("invent: derive-atomic: baseline token objects %lu\n",
         (unsigned long)tok0);

  /* Base: a session generic secret (not part of the durable census). */
  {
    CK_OBJECT_CLASS cls = CKO_SECRET_KEY;
    CK_KEY_TYPE kt = CKK_GENERIC_SECRET;
    CK_ATTRIBUTE t[] = {
      { CKA_CLASS, &cls, sizeof(cls) },
      { CKA_KEY_TYPE, &kt, sizeof(kt) },
      { CKA_LABEL, "atom-base", 9 },
      { CKA_TOKEN, &bFalse, sizeof(bFalse) },
      { CKA_PRIVATE, &bTrue, sizeof(bTrue) },
      { CKA_DERIVE, &bTrue, sizeof(bTrue) },
      { CKA_SENSITIVE, &bFalse, sizeof(bFalse) },
      { CKA_EXTRACTABLE, &bTrue, sizeof(bTrue) },
      { CKA_VALUE, base_val, sizeof(base_val) }
    };
    rv = f->C_CreateObject(ws, t, 9, &base);
    CHECK(rv == CKR_OK && base != 0, "base import (rv=0x%lx)",
          (unsigned long)rv);
  }

  /* ---- Mixed valid/invalid requests (every one refuses whole) ---- */
  {
    static const enum out_kind good2[2] = { OK_AES32, OK_GEN20 };
    static const enum out_kind mid_bad[3] = { OK_AES32, BAD_AES7, OK_GEN20 };
    static const enum out_kind last_rsa[2] = { OK_AES32, BAD_RSA16 };
    static const enum out_kind nolen[2] = { BAD_AESNOLEN, OK_GEN20 };
    static const enum out_kind trusted[2] = { OK_AES32, BAD_TRUSTED };
    static const enum out_kind ro_tok[2] = { OK_AES32, OK_GEN20 };

    expect_atomic(ws, ws, base, "prim-aes7", BAD_AES7, good2, 2, -1,
                  CKR_TEMPLATE_INCONSISTENT);
    expect_atomic(ws, ws, base, "mid-aes7", OK_AES16, mid_bad, 3, -1,
                  CKR_TEMPLATE_INCONSISTENT);
    expect_atomic(ws, ws, base, "last-rsa", OK_AES16, last_rsa, 2, -1,
                  CKR_TEMPLATE_INCONSISTENT);
    expect_atomic(ws, ws, base, "first-nolen", OK_AES16, nolen, 2, -1,
                  CKR_TEMPLATE_INCOMPLETE);
    /* Malformed encodings: the primary template's frame decoder sets
     * the code, and an additional-key template carrying the same
     * encoding must refuse with that same code (one shared decoder),
     * publishing nothing (the valid primary included). */
    {
      static const struct {
        enum out_kind k;
        const char *tag;
        CK_RV want;
      } shapes[] = {
        { BAD_LENSHAPE, "lenshape", CKR_TEMPLATE_INCONSISTENT },
        { BAD_HUGELEN, "hugelen", CKR_KEY_SIZE_RANGE },
        { BAD_BOOLSHAPE, "boolshape", CKR_TEMPLATE_INCONSISTENT },
        { BAD_BIGID, "bigid", CKR_TEMPLATE_INCONSISTENT },
        { BAD_UNKATTR, "unkattr", CKR_ATTRIBUTE_TYPE_INVALID },
      };
      size_t j;
      char name[48];
      for (j = 0; j < sizeof(shapes) / sizeof(shapes[0]); j++) {
        enum out_kind last[2];
        last[0] = OK_AES32;
        last[1] = shapes[j].k;
        snprintf(name, sizeof(name), "prim-%s", shapes[j].tag);
        expect_atomic(ws, ws, base, name, shapes[j].k, good2, 2, -1,
                      shapes[j].want);
        snprintf(name, sizeof(name), "last-%s", shapes[j].tag);
        expect_atomic(ws, ws, base, name, OK_AES16, last, 2, -1,
                      shapes[j].want);
      }
    }
    /* Owner admission (after planning, before any effect). */
    expect_atomic(ws, ws, base, "last-trusted", OK_AES16, trusted, 2, -1,
                  CKR_ATTRIBUTE_READ_ONLY);
    /* All templates valid, one additional handle slot NULL. */
    expect_atomic(ws, ws, base, "null-slot", OK_AES16, good2, 2, 1,
                  CKR_ARGUMENTS_BAD);
    /* Read-only session: a session primary plus token additional
     * keys; the session admits the primary but not the tokens. */
    rv = f->C_OpenSession(slots[0], CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR,
                          &ro);
    CHECK(rv == CKR_OK && ro != 0, "OpenSession RO (rv=0x%lx)",
          (unsigned long)rv);
    expect_atomic(ws, ro, base, "ro-token", OK_SESS16, ro_tok, 2, -1,
                  CKR_SESSION_READ_ONLY);
    rv = f->C_CloseSession(ro);
    CHECK(rv == CKR_OK, "CloseSession RO (rv=0x%lx)", (unsigned long)rv);
  }

  /* ---- All-valid control: every output publishes ---- */
  {
    struct out_tmpl prim, adds[2];
    CK_OBJECT_HANDLE hPrim = PRIMARY_CANARY, hAdds[2];
    CK_OBJECT_HANDLE before, after;
    CK_ULONG tokens = count_token(ws);
    build_out(&prim, OK_AES16, ctl_labels[0]);
    build_out(&adds[0], OK_AES32, ctl_labels[1]);
    build_out(&adds[1], OK_GEN20, ctl_labels[2]);
    hAdds[0] = ADD_CANARY(0);
    hAdds[1] = ADD_CANARY(1);
    before = mkprobe(ws);
    rv = derive_set(ws, base, &prim, adds, 2, -1, &hPrim, hAdds);
    after = mkprobe(ws);
    printf("invent: derive-atomic: control -> rv=0x%lx\n",
           (unsigned long)rv);
    CHECK(rv == CKR_OK, "control derives (rv=0x%lx)", (unsigned long)rv);
    CHECK(hPrim != PRIMARY_CANARY && hAdds[0] != ADD_CANARY(0) &&
              hAdds[1] != ADD_CANARY(1),
          "control writes every handle slot");
    CHECK(hPrim > before && hPrim < after && hAdds[0] > before &&
              hAdds[0] < after && hAdds[1] > before && hAdds[1] < after &&
              hPrim != hAdds[0] && hPrim != hAdds[1] && hAdds[0] != hAdds[1],
          "control handles are three distinct fresh handles");
    CHECK(after == before + 4,
          "control consumes exactly three handles (0x%lx -> 0x%lx)",
          (unsigned long)before, (unsigned long)after);
    CHECK(count_token(ws) == tokens + 3, "control publishes three tokens");
    if (rv == CKR_OK) {
      expect_value(ws, hPrim, CKK_AES, dkm, 16, "control primary AES/16");
      expect_value(ws, hAdds[0], CKK_AES, dkm + 16, 32,
                   "control additional AES/32");
      expect_value(ws, hAdds[1], CKK_GENERIC_SECRET, dkm + 48, 20,
                   "control additional GENERIC/20");
      expect_kat(ws, hPrim, kat_ct128, "control primary AES/16");
      expect_kat(ws, hAdds[0], kat_ct256, "control additional AES/32");
    }
    f->C_DestroyObject(ws, before);
    f->C_DestroyObject(ws, after);
  }

  rv = f->C_DestroyObject(ws, base);
  CHECK(rv == CKR_OK, "base destroyed");
  rv = f->C_Logout(ws);
  CHECK(rv == CKR_OK, "phase 1 logout");
  rv = f->C_CloseSession(ws);
  CHECK(rv == CKR_OK, "phase 1 close");
  rv = f->C_Finalize(NULL_PTR);
  CHECK(rv == CKR_OK, "store closed (rv=0x%lx)", (unsigned long)rv);

  /* ---- Reopen the same SQLite store: no durable subset ---- */
  nslots = 8;
  rv = f->C_Initialize(NULL_PTR);
  CHECK(rv == CKR_OK, "store reopened (rv=0x%lx)", (unsigned long)rv);
  rv = f->C_GetSlotList(CK_TRUE, slots, &nslots);
  CHECK(rv == CKR_OK && nslots == 1, "slot survives reopen");
  ws = open_login(slots[0], "reopen");
  printf("invent: derive-atomic: reopened token objects %lu\n",
         (unsigned long)count_token(ws));
  CHECK(count_token(ws) == tok0 + 3,
        "reopen: exactly the three control token objects are durable");
  for (i = 0; i < (CK_ULONG)g_nrefused; i++) {
    CHECK(count_label(ws, g_refused[i]) == 0,
          "reopen: no durable object for refused output %s", g_refused[i]);
  }
  {
    CK_OBJECT_HANDLE hp = find_one(ws, ctl_labels[0]);
    CK_OBJECT_HANDLE h0 = find_one(ws, ctl_labels[1]);
    CK_OBJECT_HANDLE h1 = find_one(ws, ctl_labels[2]);
    if (hp != 0) {
      expect_value(ws, hp, CKK_AES, dkm, 16, "reopen primary AES/16");
      expect_kat(ws, hp, kat_ct128, "reopen primary AES/16");
      f->C_DestroyObject(ws, hp);
    }
    if (h0 != 0) {
      expect_value(ws, h0, CKK_AES, dkm + 16, 32, "reopen additional AES/32");
      f->C_DestroyObject(ws, h0);
    }
    if (h1 != 0) {
      expect_value(ws, h1, CKK_GENERIC_SECRET, dkm + 48, 20,
                   "reopen additional GENERIC/20");
      f->C_DestroyObject(ws, h1);
    }
  }
  CHECK(count_token(ws) == tok0, "reopen: control objects destroyed");
  rv = f->C_Logout(ws);
  CHECK(rv == CKR_OK, "reopen logout");
  rv = f->C_CloseSession(ws);
  CHECK(rv == CKR_OK, "reopen close");
  rv = f->C_Finalize(NULL_PTR);
  CHECK(rv == CKR_OK, "final finalize");
}

int main(int argc, char **argv) {
  CK_RV rv;
  CK_C_GetFunctionList getList = NULL;
  void *dl = NULL;
  const char *topo;
  int isProxy;

  if (argc != 2) {
    fprintf(stderr, "usage: %s <libhaskoki.so>\n", argv[0]);
    return 2;
  }
  topo = getenv("HASKOKI_CONSUMER_TOPOLOGY");
  isProxy = topo && strcmp(topo, "proxy") == 0;
  printf("topology: %s\n", isProxy ? "proxy" : "direct");
  if (!isProxy) {
    write_sql_config();
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
  if (isProxy) {
    /* The store journey does not transport (header note). */
    printf("invent: proxy skips the SQLite derive-atomicity journey\n");
  } else {
    char sidecar[300];
    run_journey();
    unlink(g_sql_cfg);
    unlink(g_sql_db);
    snprintf(sidecar, sizeof(sidecar), "%s-journal", g_sql_db);
    unlink(sidecar);
    snprintf(sidecar, sizeof(sidecar), "%s-wal", g_sql_db);
    unlink(sidecar);
    snprintf(sidecar, sizeof(sidecar), "%s-shm", g_sql_db);
    unlink(sidecar);
    rmdir(g_sql_dir);
  }
  dlclose(dl);

  if (g_failures == 0) {
    printf("PASS: consumer_derive_atomic (mixed multi-output derive)\n");
    return 0;
  }
  printf("FAILURES: %d\n", g_failures);
  return 1;
}
