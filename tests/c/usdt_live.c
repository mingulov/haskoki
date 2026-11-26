/* USDT live-capture workload (fixture matrix + edge scenarios).
 *
 * Usage: usdt_live <libhaskoki.so>
 * Drives one logged-in session through the capture matrix, printing
 * PHASE:<name> markers on stderr for correlation with the probe
 * capture (tests/gdb/usdt_cap.txt). scripts/test-usdt-live.sh runs
 * this under GDB and asserts the typed records per phase:
 *   wrong-pin/login  policy_reject + bare end claims
 *   keygen           pk::generate, no hash/padding fields
 *   sign/verify-ok   pk::sign / pk::verify, exact RSA/SHA256 fields
 *   verify-bad       real crypto failure still emits pk::verify
 *   verify-empty     degenerate verdict emits like a wrong signature
 *   verify-null      NULL refusal arms nothing (silent)
 *   sign-shortbuf    short buffer + retry emits exactly one record
 *   shortbuf-verify  the retry signature verifies (separate phase)
 *   init-denied      init denial reports the requested mechanism
 *   digestkey-denied DigestKey policy denial: reject, no end
 *   digestkey-staged-denied
 *                    staged digest killed by policy DigestKey: one
 *                    op carries reject + abandoned end
 *   msg-sign         pk::sign record via the message one-shot path
 *   msg-verify-next  multipart verify: silent part, terminal final
 *   msg-encrypt-next multipart encrypt: silent part, one delivery
 *   msg-abandon      staged message recall killed by close
 *   msg-init-denied  message-init denial reports requested mech
 *   msg-query-modes    same failure: silent non-final, failed
 *                    end final
 *   msg-query-staged  staged query reports length; close
 *                    abandons exactly once
 *   sign-pss/verify-pss
 *                    generic PSS hash from validated slot params
 *   sign-abandon     staged recall killed by CloseSession emits
 *                    an abandoned end (disp=5)
 *   sign-abandon-nullguard
 *                    staged recall killed by a NULL recall (C guard)
 *   sign-abandon-oversize
 *                    staged recall killed by an oversize recall
 *                    (Haskell decoder)
 *   digest           symmetric/digest traffic is private-only (no pk)
 *   digest-abandon-key
 *                    staged digest recall killed by a bad-handle
 *                    DigestKey refusal
 *   derive           unmappable base: end only, no pk record
 *   derive-dh        pk::derive (DH/group), no hash/padding fields
 *   wrap/unwrap      symmetric: ends only, no pk records
 *   wrap-oaep/unwrap-oaep
 *                    pk::encrypt / pk::decrypt (RSA/OAEP/SHA-256)
 *   wrap-query-denied
 *                    refused NULL query: reject + failed end
 *   encaps-query-denied
 *                    refused NULL encaps query: reject + failed end
 *   eddsa            Ed25519 keygen/sign/verify (pub-side params)
 *   kem              pk::encapsulate / pk::decapsulate, algorithm-only
 *   logout-staged/fires/clean
 *                    two-session logout retires + flushes; the next
 *                    op resolves clean metadata (no stale retention)
 *   logout-ec-verify ECDSA verify via the public half (DER params)
 *   async-deliver    job accepted->ready->delivered + end
 *   async-cancel     job canceled
 *   async-xthread    cross-thread poll+complete still correlates
 *   async-detach/rejoin
 *                    detach hands off (handoff pair); rejoin is a
 *                    fresh op (Accepted, Ready on claim win)
 * Exit status: 0 iff every functional check passes (a failed op
 * fails the recipe before any capture assert runs).
 */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <dlfcn.h>
#include <unistd.h>
#include <pthread.h>

#include "pkcs11.h"

static void settle_ms(long ms) {
  struct timespec ts;
  ts.tv_sec = ms / 1000;
  ts.tv_nsec = (ms % 1000) * 1000000L;
  nanosleep(&ts, NULL);
}

/* Phase marker with a 20ms settle on both sides: GDB otherwise
 * interleaves its probe prints with inferior markers (observed
 * swapping across runs), which would misattribute boundary lines.
 * 33 phases x 40ms is ~1.3s per recipe run. */
#define PHASE(name) do { \
    settle_ms(20); \
    fprintf(stderr, "PHASE:%s\n", name); \
    fflush(stderr); \
    settle_ms(20); \
  } while (0)
#define CHECKM(cond, msg) do { \
    if (!(cond)) { fprintf(stderr, "FAIL: %s\n", msg); return 1; } \
  } while (0)
#define CHECKRV(rv, want, msg) do { \
    if ((rv) != (want)) { \
      fprintf(stderr, "FAIL: %s: rv=0x%lx want 0x%lx\n", msg, \
              (unsigned long)(rv), (unsigned long)(want)); \
      return 1; \
    } \
  } while (0)

/* Async-detached native surface (mirrors tests/c/async_attached.c;
 * the PKCS#11 CK_* types come from pkcs11.h here). */
typedef struct async_data {
  CK_ULONG ulVersion;
  CK_BYTE_PTR pValue;
  CK_ULONG ulValue;
  CK_ULONG hObject;
  CK_ULONG hAdditionalObject;
} async_data_t;

#define FN_SIGN 1UL
#define FN_DIGEST 2UL

typedef void *haskoki_async_ctx_t;
typedef void *haskoki_async_job_t;
typedef haskoki_async_ctx_t (*fn_open)(void);
typedef void (*fn_close)(haskoki_async_ctx_t *pctx);
typedef CK_RV (*fn_init)(haskoki_async_ctx_t ctx, CK_SESSION_HANDLE hSession,
                         CK_MECHANISM_TYPE mech, CK_BYTE_PTR pParams,
                         CK_ULONG ulParamsLen);
typedef CK_RV (*fn_start)(haskoki_async_ctx_t ctx, CK_SESSION_HANDLE hSession,
                          CK_ULONG func, CK_BYTE_PTR pData, CK_ULONG ulDataLen,
                          CK_ULONG cap, CK_ULONG ticks,
                          haskoki_async_job_t *pHandle);
typedef CK_RV (*fn_poll)(haskoki_async_ctx_t ctx, haskoki_async_job_t job,
                         CK_ULONG func);
typedef CK_RV (*fn_complete)(haskoki_async_ctx_t ctx, haskoki_async_job_t job,
                             CK_ULONG func, async_data_t *pResult);
typedef CK_RV (*fn_cancel)(haskoki_async_ctx_t ctx, haskoki_async_job_t job);
typedef void *haskoki_async_store_t;
typedef haskoki_async_store_t (*fn_store_open)(const char *path);
typedef void (*fn_store_close)(haskoki_async_store_t *pbox);
typedef haskoki_async_ctx_t (*fn_open_on)(haskoki_async_store_t box);
typedef CK_RV (*fn_get_id)(haskoki_async_ctx_t ctx, haskoki_async_job_t job,
                           CK_ULONG func, CK_ULONG *pId);
typedef CK_RV (*fn_join)(haskoki_async_ctx_t ctx, CK_ULONG id, CK_ULONG func,
                         CK_SESSION_HANDLE hSession, CK_ULONG cap,
                         haskoki_async_job_t *pHandle, CK_ULONG *pNeed);

/* FIPS 180-4: SHA-256("abc"). */
static const CK_BYTE kWant[32] = {
  0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde,
  0x5d, 0xae, 0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
  0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
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
  char tmpl[] = "/tmp/haskoki-usdt-live-XXXXXX";
  int fd = mkstemp(tmpl);
  size_t want = sizeof(body) - 1;
  if (fd < 0) { perror("mkstemp"); exit(2); }
  if (write(fd, body, want) != (ssize_t)want) { perror("write"); exit(2); }
  close(fd);
  snprintf(g_cfg_path, sizeof(g_cfg_path), "%s", tmpl);
  if (setenv("HASKOKI_CONFIG", g_cfg_path, 1) != 0) { perror("setenv"); exit(2); }
}

static CK_FUNCTION_LIST_PTR T;
static CK_FUNCTION_LIST_3_2_PTR tab32;
static CK_SESSION_HANDLE g_sess;

/* P-256 OID for EC legs (mirrors consumer_roundtrip). */
static const CK_BYTE kP256Oid[] = {
  0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07
};

/* Short-buffer retry signature, saved for the verify leg. */
static CK_BYTE g_shortSig[512];
static CK_ULONG g_shortSigLen;
static CK_OBJECT_HANDLE g_pub, g_priv;
static CK_BYTE g_sig[512];
static CK_ULONG g_sigLen;
static CK_MECHANISM g_rsaSign;

static int open_session(CK_SESSION_HANDLE *out) {
  CK_RV rv = T->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                              NULL, NULL, out);
  if (rv == CKR_SLOT_ID_INVALID) {
    CK_SLOT_ID psl[8];
    CK_ULONG pn = 8;
    if (T->C_GetSlotList(0, psl, &pn) == CKR_OK && pn >= 1) {
      rv = T->C_OpenSession(psl[0], CKF_SERIAL_SESSION | CKF_RW_SESSION,
                            NULL, NULL, out);
    }
  }
  return rv == CKR_OK && *out != 0 ? 0 : 1;
}

static int phase_login(void) {
  CK_RV rv;
  PHASE("wrong-pin");
  rv = T->C_Login(g_sess, CKU_USER, (CK_UTF8CHAR_PTR)"0000", 4);
  CHECKRV(rv, CKR_PIN_INCORRECT, "wrong pin refused");
  PHASE("login");
  rv = T->C_Login(g_sess, CKU_USER, (CK_UTF8CHAR_PTR)"1234", 4);
  CHECKRV(rv, CKR_OK, "login-user");
  return 0;
}

static int phase_keygen(void) {
  CK_RV rv;
  CK_MECHANISM mech;
  CK_ULONG bits = 2048;
  static CK_BYTE exp3[] = {1, 0, 1};
  CK_BBOOL ckFalse = CK_FALSE, ckTrue = CK_TRUE;
  CK_OBJECT_CLASS pubClass = CKO_PUBLIC_KEY, privClass = CKO_PRIVATE_KEY;
  CK_KEY_TYPE rsaType = CKK_RSA;
  CK_ATTRIBUTE pubTmpl[] = {
    {CKA_CLASS, &pubClass, sizeof pubClass},
    {CKA_KEY_TYPE, &rsaType, sizeof rsaType},
    {CKA_TOKEN, &ckFalse, sizeof ckFalse},
    {CKA_MODULUS_BITS, &bits, sizeof bits},
    {CKA_PUBLIC_EXPONENT, exp3, sizeof exp3},
  };
  CK_ATTRIBUTE privTmpl[] = {
    {CKA_CLASS, &privClass, sizeof privClass},
    {CKA_KEY_TYPE, &rsaType, sizeof rsaType},
    {CKA_TOKEN, &ckFalse, sizeof ckFalse},
    {CKA_PRIVATE, &ckTrue, sizeof ckTrue},
  };
  PHASE("keygen");
  mech.mechanism = CKM_RSA_PKCS_KEY_PAIR_GEN;
  mech.pParameter = NULL_PTR;
  mech.ulParameterLen = 0;
  g_pub = g_priv = 0;
  rv = T->C_GenerateKeyPair(g_sess, &mech, pubTmpl, 5, privTmpl, 4,
                            &g_pub, &g_priv);
  CHECKRV(rv, CKR_OK, "keygen");
  CHECKM(g_pub != 0 && g_priv != 0, "key handles minted");
  return 0;
}

static const char kMsg[] = "hello-usdt-trace-me";

static int phase_sign(void) {
  CK_RV rv;
  PHASE("sign");
  g_rsaSign.mechanism = CKM_SHA256_RSA_PKCS;
  g_rsaSign.pParameter = NULL_PTR;
  g_rsaSign.ulParameterLen = 0;
  rv = T->C_SignInit(g_sess, &g_rsaSign, g_priv);
  CHECKRV(rv, CKR_OK, "sign-init");
  g_sigLen = sizeof g_sig;
  rv = T->C_Sign(g_sess, (CK_BYTE_PTR)kMsg, strlen(kMsg), g_sig, &g_sigLen);
  CHECKRV(rv, CKR_OK, "sign");
  CHECKM(g_sigLen == 256, "sig length 256");
  return 0;
}

static int phase_verify_ok(void) {
  CK_RV rv;
  PHASE("verify-ok");
  rv = T->C_VerifyInit(g_sess, &g_rsaSign, g_pub);
  CHECKRV(rv, CKR_OK, "verify-init");
  rv = T->C_Verify(g_sess, (CK_BYTE_PTR)kMsg, strlen(kMsg), g_sig, g_sigLen);
  CHECKRV(rv, CKR_OK, "verify");
  return 0;
}

static int phase_verify_bad(void) {
  CK_RV rv;
  CK_BYTE bad[512];
  PHASE("verify-bad");
  CHECKM(g_sigLen <= sizeof bad, "bad-sig buffer fits");
  memcpy(bad, g_sig, g_sigLen);
  bad[g_sigLen - 1] ^= 0xFF;
  rv = T->C_VerifyInit(g_sess, &g_rsaSign, g_pub);
  CHECKRV(rv, CKR_OK, "bad verify-init");
  rv = T->C_Verify(g_sess, (CK_BYTE_PTR)kMsg, strlen(kMsg), bad, g_sigLen);
  CHECKRV(rv, CKR_SIGNATURE_INVALID, "real crypto failure verdict");
  return 0;
}

static int phase_verify_empty(void) {
  CK_RV rv;
  PHASE("verify-empty");
  rv = T->C_VerifyInit(g_sess, &g_rsaSign, g_pub);
  CHECKRV(rv, CKR_OK, "empty verify-init");
  /* Empty signature with a valid buffer: a committed degenerate
   * verdict, emitting exactly like a wrong-signature verdict. */
  rv = T->C_Verify(g_sess, (CK_BYTE_PTR)kMsg, strlen(kMsg), g_sig, 0);
  CHECKRV(rv, CKR_SIGNATURE_INVALID, "empty signature verdict");
  return 0;
}

static int phase_verify_null(void) {
  CK_RV rv;
  PHASE("verify-null");
  rv = T->C_VerifyInit(g_sess, &g_rsaSign, g_pub);
  CHECKRV(rv, CKR_OK, "null verify-init");
  /* NULL signature with nonzero length: refused by the C guard
   * before crypto (ARGS_BAD), arming nothing. */
  rv = T->C_Verify(g_sess, (CK_BYTE_PTR)kMsg, strlen(kMsg), NULL, 5);
  CHECKRV(rv, CKR_ARGUMENTS_BAD, "null signature refused");
  return 0;
}

static int phase_sign_shortbuf(void) {
  CK_RV rv;
  CK_BYTE small[10];
  CK_ULONG smallLen, fullLen;
  CK_BYTE full[512];
  PHASE("sign-shortbuf");
  rv = T->C_SignInit(g_sess, &g_rsaSign, g_priv);
  CHECKRV(rv, CKR_OK, "shortbuf sign-init");
  smallLen = sizeof small;
  rv = T->C_Sign(g_sess, (CK_BYTE_PTR)kMsg, strlen(kMsg), small, &smallLen);
  CHECKRV(rv, CKR_BUFFER_TOO_SMALL, "short buffer sizes");
  fullLen = sizeof full;
  rv = T->C_Sign(g_sess, (CK_BYTE_PTR)kMsg, strlen(kMsg), full, &fullLen);
  CHECKRV(rv, CKR_OK, "retry delivers");
  CHECKM(fullLen == 256, "retry sig length 256");
  CHECKM(fullLen <= sizeof g_shortSig, "retry sig fits");
  memcpy(g_shortSig, full, fullLen);
  g_shortSigLen = fullLen;
  return 0;
}

static int phase_shortbuf_verify(void) {
  /* The retry signature is real: it verifies under the same key. */
  CK_RV rv;
  PHASE("shortbuf-verify");
  rv = T->C_VerifyInit(g_sess, &g_rsaSign, g_pub);
  CHECKRV(rv, CKR_OK, "shortbuf verify-init");
  rv = T->C_Verify(g_sess, (CK_BYTE_PTR)kMsg, strlen(kMsg),
                   g_shortSig, g_shortSigLen);
  CHECKRV(rv, CKR_OK, "retry signature verifies");
  return 0;
}

static int phase_init_denied(void) {
  /* Init denial reports the REQUESTED mechanism: ECDSA init with an
   * AES key refuses KEY_TYPE_INCONSISTENT on an empty slot. */
  CK_RV rv;
  CK_OBJECT_CLASS ckcls = CKO_SECRET_KEY;
  CK_KEY_TYPE akt = CKK_AES;
  CK_ULONG vlen = 16;
  CK_BBOOL bFalse = CK_FALSE;
  CK_MECHANISM em;
  CK_OBJECT_HANDLE aes = 0;
  CK_MECHANISM kgm;
  CK_ATTRIBUTE tmpl[] = {
    { CKA_CLASS, &ckcls, sizeof(ckcls) },
    { CKA_KEY_TYPE, &akt, sizeof(akt) },
    { CKA_VALUE_LEN, &vlen, sizeof(vlen) },
    { CKA_TOKEN, &bFalse, sizeof(bFalse) },
  };
  PHASE("init-denied");
  kgm.mechanism = CKM_AES_KEY_GEN;
  kgm.pParameter = NULL_PTR;
  kgm.ulParameterLen = 0;
  rv = T->C_GenerateKey(g_sess, &kgm, tmpl, 4, &aes);
  CHECKRV(rv, CKR_OK, "denied-leg aes mints");
  em.mechanism = CKM_ECDSA_SHA256;
  em.pParameter = NULL_PTR;
  em.ulParameterLen = 0;
  rv = T->C_SignInit(g_sess, &em, aes);
  CHECKRV(rv, CKR_KEY_TYPE_INCONSISTENT, "ecdsa/aes refused");
  return 0;
}

static int phase_digestkey_denied(void) {
  /* DigestKey with a non-secret key refuses KEY_TYPE_INCONSISTENT
   * (policy) on a live-but-unstaged digest slot: reject, no end. */
  CK_RV rv;
  CK_MECHANISM mech;
  PHASE("digestkey-denied");
  mech.mechanism = CKM_SHA256;
  mech.pParameter = NULL_PTR;
  mech.ulParameterLen = 0;
  rv = T->C_DigestInit(g_sess, &mech);
  CHECKRV(rv, CKR_OK, "denied digest-init");
  rv = T->C_DigestKey(g_sess, g_pub);
  CHECKRV(rv, CKR_KEY_TYPE_INCONSISTENT, "non-secret refused");
  return 0;
}

static int phase_sign_pss(void) {
  /* Generic PSS names no digest: the record's hash comes from the
   * validated slot params (SHA-384 here). */
  CK_RV rv;
  CK_MECHANISM mech;
  CK_RSA_PKCS_PSS_PARAMS pss;
  CK_BYTE sig[512];
  CK_ULONG sigLen;
  CK_BYTE vmsg[] = "hello-usdt-pss";
  PHASE("sign-pss");
  pss.hashAlg = CKM_SHA384;
  pss.mgf = CKG_MGF1_SHA384;
  pss.sLen = 48;
  mech.mechanism = CKM_RSA_PKCS_PSS;
  mech.pParameter = &pss;
  mech.ulParameterLen = sizeof(pss);
  rv = T->C_SignInit(g_sess, &mech, g_priv);
  CHECKRV(rv, CKR_OK, "pss sign-init");
  sigLen = sizeof sig;
  rv = T->C_Sign(g_sess, vmsg, sizeof(vmsg) - 1, sig, &sigLen);
  CHECKRV(rv, CKR_OK, "pss sign");
  CHECKM(sigLen == 256, "pss sig length 256");
  PHASE("verify-pss");
  rv = T->C_VerifyInit(g_sess, &mech, g_pub);
  CHECKRV(rv, CKR_OK, "pss verify-init");
  rv = T->C_Verify(g_sess, vmsg, sizeof(vmsg) - 1, sig, sigLen);
  CHECKRV(rv, CKR_OK, "pss verify");
  return 0;
}

/* Short-buffered recall data killed by CloseSession: the staged
 * bytes die here, so an abandoned end (disp=5) must fire. Closes
 * the login session; the caller reopens a fresh session. */
static int phase_sign_abandon(void) {
  CK_RV rv;
  CK_BYTE small[10];
  CK_ULONG smallLen;
  PHASE("sign-abandon");
  rv = T->C_SignInit(g_sess, &g_rsaSign, g_priv);
  CHECKRV(rv, CKR_OK, "abandon sign-init");
  smallLen = sizeof small;
  rv = T->C_Sign(g_sess, (CK_BYTE_PTR)kMsg, strlen(kMsg), small, &smallLen);
  CHECKRV(rv, CKR_BUFFER_TOO_SMALL, "abandon short stages recall");
  rv = T->C_CloseSession(g_sess);
  CHECKRV(rv, CKR_OK, "abandon close kills staged bytes");
  g_sess = 0;
  g_pub = g_priv = 0;
  return 0;
}

/* HMAC key for the post-reopen abandon legs (fast import, no
 * keygen; HMAC sign is private-route, which also covers retained
 * metadata without a pk record). */
static CK_OBJECT_HANDLE g_hmac;

static int make_hmac_key(void) {
  CK_RV rv;
  CK_OBJECT_CLASS cls = CKO_SECRET_KEY;
  CK_KEY_TYPE kt = CKK_GENERIC_SECRET;
  CK_BBOOL t = CK_TRUE, fa = CK_FALSE;
  static CK_BYTE raw[16] = {
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15
  };
  CK_ATTRIBUTE tmpl[] = {
    { CKA_CLASS, &cls, sizeof(cls) },
    { CKA_KEY_TYPE, &kt, sizeof(kt) },
    { CKA_TOKEN, &fa, sizeof(fa) },
    { CKA_SIGN, &t, sizeof(t) },
    { CKA_VERIFY, &t, sizeof(t) },
    { CKA_VALUE, raw, sizeof(raw) },
  };
  g_hmac = 0;
  rv = T->C_CreateObject(g_sess, tmpl, 6, &g_hmac);
  CHECKRV(rv, CKR_OK, "hmac key imports");
  CHECKM(g_hmac != 0, "hmac handle minted");
  return 0;
}

/* Staged recall killed by a NULL-data recall: the C guard refuses
 * ARGS_BAD and the abandoned end must fire. */
static int phase_sign_abandon_nullguard(void) {
  CK_RV rv;
  CK_MECHANISM hm;
  CK_BYTE small[10], buf[128];
  CK_ULONG smallLen, bufLen;
  PHASE("sign-abandon-nullguard");
  hm.mechanism = CKM_SHA256_HMAC;
  hm.pParameter = NULL_PTR;
  hm.ulParameterLen = 0;
  rv = T->C_SignInit(g_sess, &hm, g_hmac);
  CHECKRV(rv, CKR_OK, "nullguard sign-init");
  smallLen = sizeof small;
  rv = T->C_Sign(g_sess, (CK_BYTE_PTR)kMsg, strlen(kMsg), small, &smallLen);
  CHECKRV(rv, CKR_BUFFER_TOO_SMALL, "nullguard short stages recall");
  bufLen = sizeof buf;
  rv = T->C_Sign(g_sess, NULL, 10, buf, &bufLen);
  CHECKRV(rv, CKR_ARGUMENTS_BAD, "null data refused");
  return 0;
}

/* Staged recall killed by an oversize recall: the Haskell decoder
 * refuses ARGS_BAD and the abandoned end must fire. The length is
 * checked before any byte is read, so the small buffer is safe. */
static int phase_sign_abandon_oversize(void) {
  CK_RV rv;
  CK_MECHANISM hm;
  CK_BYTE small[10], buf[128];
  CK_ULONG smallLen, bufLen;
  PHASE("sign-abandon-oversize");
  hm.mechanism = CKM_SHA256_HMAC;
  hm.pParameter = NULL_PTR;
  hm.ulParameterLen = 0;
  rv = T->C_SignInit(g_sess, &hm, g_hmac);
  CHECKRV(rv, CKR_OK, "oversize sign-init");
  smallLen = sizeof small;
  rv = T->C_Sign(g_sess, (CK_BYTE_PTR)kMsg, strlen(kMsg), small, &smallLen);
  CHECKRV(rv, CKR_BUFFER_TOO_SMALL, "oversize short stages recall");
  bufLen = sizeof buf;
  rv = T->C_Sign(g_sess, (CK_BYTE_PTR)kMsg, 17UL * 1024UL * 1024UL,
                 buf, &bufLen);
  CHECKRV(rv, CKR_ARGUMENTS_BAD, "oversize data refused");
  return 0;
}

static int phase_digest(void) {
  CK_RV rv;
  CK_MECHANISM mech;
  CK_BYTE out[64];
  CK_ULONG outLen;
  PHASE("digest");
  mech.mechanism = CKM_SHA256;
  mech.pParameter = NULL_PTR;
  mech.ulParameterLen = 0;
  rv = T->C_DigestInit(g_sess, &mech);
  CHECKRV(rv, CKR_OK, "digest-init");
  outLen = sizeof out;
  rv = T->C_Digest(g_sess, (CK_BYTE_PTR)"abc", 3, out, &outLen);
  CHECKRV(rv, CKR_OK, "digest");
  CHECKM(outLen == 32 && memcmp(out, kWant, 32) == 0, "digest KAT bytes");
  return 0;
}

static int phase_msg_sign(void) {
  /* RSA message-sign one-shot: a pk::sign record via the message
   * path (F_SignMessage routes like a classic final). */
  CK_RV rv;
  CK_MECHANISM mech;
  CK_BYTE sig[512];
  CK_ULONG sigLen;
  CK_BYTE msg[] = "hello-msg-sign";
  PHASE("msg-sign");
  mech.mechanism = CKM_SHA256_RSA_PKCS;
  mech.pParameter = NULL_PTR;
  mech.ulParameterLen = 0;
  rv = tab32->C_MessageSignInit(g_sess, &mech, g_priv);
  CHECKRV(rv, CKR_OK, "msg sign-init");
  sigLen = sizeof sig;
  rv = tab32->C_SignMessage(g_sess, NULL, 0, msg, sizeof(msg) - 1,
                          sig, &sigLen);
  CHECKRV(rv, CKR_OK, "msg sign");
  CHECKM(sigLen == 256, "msg sig length 256");
  rv = tab32->C_MessageSignFinal(g_sess);
  CHECKRV(rv, CKR_OK, "msg sign final closes silently");
  return 0;
}

static int phase_msg_verify_next(void) {
  /* Multipart message verify: the no-signature part is an update
   * (silent); the part carrying the candidate is the final verdict
   * (record + end, exactly once). */
  CK_RV rv;
  CK_MECHANISM mech;
  CK_BYTE sig[512];
  CK_ULONG sigLen;
  CK_BYTE msg[] = "hello-msg-verify-partitioned";
  PHASE("msg-verify-next");
  mech.mechanism = CKM_SHA256_RSA_PKCS;
  mech.pParameter = NULL_PTR;
  mech.ulParameterLen = 0;
  rv = tab32->C_MessageSignInit(g_sess, &mech, g_priv);
  CHECKRV(rv, CKR_OK, "msg setup sign-init");
  sigLen = sizeof sig;
  rv = tab32->C_SignMessage(g_sess, NULL, 0, msg, sizeof(msg) - 1,
                          sig, &sigLen);
  CHECKRV(rv, CKR_OK, "msg setup sign");
  rv = tab32->C_MessageSignFinal(g_sess);
  CHECKRV(rv, CKR_OK, "msg setup sign final frees");
  rv = tab32->C_MessageVerifyInit(g_sess, &mech, g_pub);
  CHECKRV(rv, CKR_OK, "msg verify-init");
  rv = tab32->C_VerifyMessageBegin(g_sess, NULL, 0);
  CHECKRV(rv, CKR_OK, "msg verify begin");
  rv = tab32->C_VerifyMessageNext(g_sess, NULL, 0, msg, 12, NULL, 0);
  CHECKRV(rv, CKR_OK, "msg verify part steps silently");
  rv = tab32->C_VerifyMessageNext(g_sess, NULL, 0, msg + 12,
                                sizeof(msg) - 1 - 12, sig, sigLen);
  CHECKRV(rv, CKR_OK, "msg verify final part delivers");
  rv = tab32->C_MessageVerifyFinal(g_sess);
  CHECKRV(rv, CKR_OK, "msg verify final closes silently");
  return 0;
}

static int phase_msg_encrypt_next(void) {
  /* Multipart message encrypt: the non-final part is an update
   * (silent); the end==1 part delivers exactly once; final closes
   * silently. AES stays private-only (no pk record). */
  CK_RV rv;
  CK_OBJECT_CLASS ckcls = CKO_SECRET_KEY;
  CK_KEY_TYPE akt = CKK_AES;
  CK_ULONG vlen = 16;
  CK_BBOOL bFalse = CK_FALSE;
  CK_MECHANISM kgm, cm;
  CK_OBJECT_HANDLE aes = 0;
  CK_ATTRIBUTE tmpl[] = {
    { CKA_CLASS, &ckcls, sizeof(ckcls) },
    { CKA_KEY_TYPE, &akt, sizeof(akt) },
    { CKA_VALUE_LEN, &vlen, sizeof(vlen) },
    { CKA_TOKEN, &bFalse, sizeof(bFalse) },
  };
  static CK_BYTE iv[16] = {
    7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7
  };
  static CK_BYTE p1[] = "0123456789abcdef";
  static CK_BYTE p2[] = "fedcba9876543210";
  CK_BYTE ct[64];
  CK_ULONG ctLen;
  PHASE("msg-encrypt-next");
  kgm.mechanism = CKM_AES_KEY_GEN;
  kgm.pParameter = NULL_PTR;
  kgm.ulParameterLen = 0;
  rv = T->C_GenerateKey(g_sess, &kgm, tmpl, 4, &aes);
  CHECKRV(rv, CKR_OK, "msg aes mints");
  cm.mechanism = CKM_AES_CBC;
  cm.pParameter = iv;
  cm.ulParameterLen = sizeof(iv);
  rv = tab32->C_MessageEncryptInit(g_sess, &cm, aes);
  CHECKRV(rv, CKR_OK, "msg encrypt-init");
  rv = tab32->C_EncryptMessageBegin(g_sess, iv, sizeof(iv), NULL, 0);
  CHECKRV(rv, CKR_OK, "msg encrypt begin");
  ctLen = sizeof(ct);
  rv = tab32->C_EncryptMessageNext(g_sess, NULL, 0, p1, 16,
                                 ct, &ctLen, 0);
  CHECKRV(rv, CKR_OK, "msg non-final part steps silently");
  ctLen = sizeof(ct);
  rv = tab32->C_EncryptMessageNext(g_sess, NULL, 0, p2, 16,
                                 ct, &ctLen, CKF_END_OF_MESSAGE);
  CHECKRV(rv, CKR_OK, "msg final part delivers");
  CHECKM(ctLen == 32, "msg ciphertext length 32");
  rv = tab32->C_MessageEncryptFinal(g_sess);
  CHECKRV(rv, CKR_OK, "msg encrypt final closes silently");
  return 0;
}

static int phase_msg_abandon(void) {
  /* A short-buffered message part stages recall metadata; closing
   * the session kills it (abandoned end). Own session: opened and
   * closed inside the leg. */
  CK_RV rv;
  CK_SESSION_HANDLE msess = 0;
  CK_OBJECT_CLASS ckcls = CKO_SECRET_KEY;
  CK_KEY_TYPE akt = CKK_AES;
  CK_ULONG vlen = 16;
  CK_BBOOL bFalse = CK_FALSE;
  CK_MECHANISM kgm, cm;
  CK_OBJECT_HANDLE aes = 0;
  CK_ATTRIBUTE tmpl[] = {
    { CKA_CLASS, &ckcls, sizeof(ckcls) },
    { CKA_KEY_TYPE, &akt, sizeof(akt) },
    { CKA_VALUE_LEN, &vlen, sizeof(vlen) },
    { CKA_TOKEN, &bFalse, sizeof(bFalse) },
  };
  static CK_BYTE iv[16] = {
    9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9
  };
  static CK_BYTE pt[] = "abandon-this-msg!";
  CK_BYTE small[4];
  CK_ULONG smallLen;
  PHASE("msg-abandon");
  if (open_session(&msess)) CHECKM(0, "abandon session opens");
  kgm.mechanism = CKM_AES_KEY_GEN;
  kgm.pParameter = NULL_PTR;
  kgm.ulParameterLen = 0;
  rv = T->C_GenerateKey(msess, &kgm, tmpl, 4, &aes);
  CHECKRV(rv, CKR_OK, "abandon aes mints");
  cm.mechanism = CKM_AES_CBC;
  cm.pParameter = iv;
  cm.ulParameterLen = sizeof(iv);
  rv = tab32->C_MessageEncryptInit(msess, &cm, aes);
  CHECKRV(rv, CKR_OK, "abandon encrypt-init");
  rv = tab32->C_EncryptMessageBegin(msess, iv, sizeof(iv), NULL, 0);
  CHECKRV(rv, CKR_OK, "abandon begin");
  smallLen = sizeof(small);
  rv = tab32->C_EncryptMessageNext(msess, NULL, 0, pt, 16,
                                 small, &smallLen, CKF_END_OF_MESSAGE);
  CHECKRV(rv, CKR_BUFFER_TOO_SMALL, "abandon short stages recall");
  rv = T->C_CloseSession(msess);
  CHECKRV(rv, CKR_OK, "abandon close kills staged message");
  return 0;
}

/* Staged digest recall killed by a key-resolution refusal:
 * C_DigestKey with a bad handle refuses KEY_HANDLE_INVALID and the
 * abandoned end must fire (the code is not policy: no reject). */
static int phase_digest_abandon_key(void) {
  CK_RV rv;
  CK_MECHANISM mech;
  CK_BYTE small[10];
  CK_ULONG smallLen;
  PHASE("digest-abandon-key");
  mech.mechanism = CKM_SHA256;
  mech.pParameter = NULL_PTR;
  mech.ulParameterLen = 0;
  rv = T->C_DigestInit(g_sess, &mech);
  CHECKRV(rv, CKR_OK, "key-abandon digest-init");
  smallLen = sizeof small;
  rv = T->C_Digest(g_sess, (CK_BYTE_PTR)"abc", 3, small, &smallLen);
  CHECKRV(rv, CKR_BUFFER_TOO_SMALL, "key-abandon short stages recall");
  rv = T->C_DigestKey(g_sess, 9999);
  CHECKRV(rv, CKR_KEY_HANDLE_INVALID, "bad handle refused");
  return 0;
}

static int phase_derive(void) {
  /* XOR_BASE_AND_DATA, base 16 / data 24 -> 16 bytes (mirrors the
   * consumer_roundtrip xor-unequal leg, including its oracle). */
  static const CK_BYTE want[16] = {
    0x0e, 0x22, 0x4a, 0x56, 0xa6, 0x82, 0xba, 0x6e,
    0x5e, 0x22, 0xfa, 0x36, 0x66, 0x42, 0xaa, 0xfe
  };
  CK_RV rv;
  CK_BYTE base[24], data[24], got[24];
  CK_OBJECT_HANDLE hb = 0, hd = 0;
  CK_KEY_DERIVATION_STRING_DATA sd;
  CK_MECHANISM m;
  CK_OBJECT_CLASS cls = CKO_SECRET_KEY;
  CK_KEY_TYPE kt = CKK_GENERIC_SECRET;
  CK_BBOOL t = CK_TRUE, fa = CK_FALSE;
  CK_ULONG len16 = 16;
  CK_ATTRIBUTE baseT[] = {
    { CKA_CLASS, &cls, sizeof(cls) },
    { CKA_KEY_TYPE, &kt, sizeof(kt) },
    { CKA_TOKEN, &fa, sizeof(fa) },
    { CKA_DERIVE, &t, sizeof(t) },
    { CKA_SENSITIVE, &fa, sizeof(fa) },
    { CKA_EXTRACTABLE, &t, sizeof(t) },
    { CKA_VALUE, base, 16 },
  };
  CK_ATTRIBUTE outT[] = {
    { CKA_CLASS, &cls, sizeof(cls) },
    { CKA_KEY_TYPE, &kt, sizeof(kt) },
    { CKA_TOKEN, &fa, sizeof(fa) },
    { CKA_SENSITIVE, &fa, sizeof(fa) },
    { CKA_EXTRACTABLE, &t, sizeof(t) },
    { CKA_VALUE_LEN, &len16, sizeof(len16) },
  };
  CK_ATTRIBUTE g[] = { { CKA_VALUE, got, sizeof(got) } };
  int i;
  PHASE("derive");
  for (i = 0; i < 24; i++) {
    base[i] = (CK_BYTE)(i * 13 + 5);
    data[i] = (CK_BYTE)(i * 37 + 11);
  }
  rv = T->C_CreateObject(g_sess, baseT, 7, &hb);
  CHECKRV(rv, CKR_OK, "derive base imports");
  sd.pData = data;
  sd.ulLen = 24;
  m.mechanism = CKM_XOR_BASE_AND_DATA;
  m.pParameter = &sd;
  m.ulParameterLen = sizeof(sd);
  rv = T->C_DeriveKey(g_sess, &m, hb, outT, 6, &hd);
  CHECKRV(rv, CKR_OK, "derive ok");
  g[0].ulValueLen = sizeof(got);
  rv = T->C_GetAttributeValue(g_sess, hd, g, 1);
  CHECKRV(rv, CKR_OK, "derive readback");
  CHECKM(g[0].ulValueLen == 16 && memcmp(got, want, 16) == 0,
         "derive bytes match the oracle");
  return 0;
}

/* RFC 3526 MODP-2048 prime (public constants, copied from the
 * consumer_roundtrip DH leg). */
static const CK_BYTE kFfdhe2048[256] = {
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xad, 0xf8, 0x54, 0x58, 0xa2, 0xbb, 0x4a, 0x9a,
  0xaf, 0xdc, 0x56, 0x20, 0x27, 0x3d, 0x3c, 0xf1, 0xd8, 0xb9, 0xc5, 0x83, 0xce, 0x2d, 0x36, 0x95,
  0xa9, 0xe1, 0x36, 0x41, 0x14, 0x64, 0x33, 0xfb, 0xcc, 0x93, 0x9d, 0xce, 0x24, 0x9b, 0x3e, 0xf9,
  0x7d, 0x2f, 0xe3, 0x63, 0x63, 0x0c, 0x75, 0xd8, 0xf6, 0x81, 0xb2, 0x02, 0xae, 0xc4, 0x61, 0x7a,
  0xd3, 0xdf, 0x1e, 0xd5, 0xd5, 0xfd, 0x65, 0x61, 0x24, 0x33, 0xf5, 0x1f, 0x5f, 0x06, 0x6e, 0xd0,
  0x85, 0x63, 0x65, 0x55, 0x3d, 0xed, 0x1a, 0xf3, 0xb5, 0x57, 0x13, 0x5e, 0x7f, 0x57, 0xc9, 0x35,
  0x98, 0x4f, 0x0c, 0x70, 0xe0, 0xe6, 0x8b, 0x77, 0xe2, 0xa6, 0x89, 0xda, 0xf3, 0xef, 0xe8, 0x72,
  0x1d, 0xf1, 0x58, 0xa1, 0x36, 0xad, 0xe7, 0x35, 0x30, 0xac, 0xca, 0x4f, 0x48, 0x3a, 0x79, 0x7a,
  0xbc, 0x0a, 0xb1, 0x82, 0xb3, 0x24, 0xfb, 0x61, 0xd1, 0x08, 0xa9, 0x4b, 0xb2, 0xc8, 0xe3, 0xfb,
  0xb9, 0x6a, 0xda, 0xb7, 0x60, 0xd7, 0xf4, 0x68, 0x1d, 0x4f, 0x42, 0xa3, 0xde, 0x39, 0x4d, 0xf4,
  0xae, 0x56, 0xed, 0xe7, 0x63, 0x72, 0xbb, 0x19, 0x0b, 0x07, 0xa7, 0xc8, 0xee, 0x0a, 0x6d, 0x70,
  0x9e, 0x02, 0xfc, 0xe1, 0xcd, 0xf7, 0xe2, 0xec, 0xc0, 0x34, 0x04, 0xcd, 0x28, 0x34, 0x2f, 0x61,
  0x91, 0x72, 0xfe, 0x9c, 0xe9, 0x85, 0x83, 0xff, 0x8e, 0x4f, 0x12, 0x32, 0xee, 0xf2, 0x81, 0x83,
  0xc3, 0xfe, 0x3b, 0x1b, 0x4c, 0x6f, 0xad, 0x73, 0x3b, 0xb5, 0xfc, 0xbc, 0x2e, 0xc2, 0x20, 0x05,
  0xc5, 0x8e, 0xf1, 0x83, 0x7d, 0x16, 0x83, 0xb2, 0xc6, 0xf3, 0x4a, 0x26, 0xc1, 0xb2, 0xef, 0xfa,
  0x88, 0x6b, 0x42, 0x38, 0x61, 0x28, 0x5c, 0x97, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};

static int phase_derive_dh(void) {
  CK_RV rv;
  CK_OBJECT_CLASS pcls = CKO_PUBLIC_KEY, scls = CKO_PRIVATE_KEY,
                  seccls = CKO_SECRET_KEY;
  CK_KEY_TYPE dhkt = CKK_DH, genkt = CKK_GENERIC_SECRET;
  CK_BBOOL bFalse = CK_FALSE, bTrue = CK_TRUE;
  CK_ULONG dhvlen = 256;
  CK_BYTE dhg[1] = { 0x02 };
  CK_MECHANISM dhkgm, dhdm;
  CK_ATTRIBUTE dhPubT[6], dhPrivT[4];
  CK_ATTRIBUTE dhDtmpl[] = {
    { CKA_CLASS, &seccls, sizeof(seccls) },
    { CKA_KEY_TYPE, &genkt, sizeof(genkt) },
    { CKA_VALUE_LEN, &dhvlen, sizeof(dhvlen) },
    { CKA_TOKEN, &bFalse, sizeof(bFalse) },
    { CKA_SENSITIVE, &bFalse, sizeof(bFalse) },
    { CKA_EXTRACTABLE, &bTrue, sizeof(bTrue) },
  };
  CK_OBJECT_HANDLE dhPubA = 0, dhPrivA = 0, dhPubB = 0, dhPrivB = 0;
  CK_OBJECT_HANDLE dhS1 = 0, dhS2 = 0;
  CK_BYTE dhYA[256], dhYB[256], dhSAB[256], dhSBA[256];
  CK_ULONG dhLenA = 0, dhLenB = 0, dhLenS1 = 0, dhLenS2 = 0;
  CK_ATTRIBUTE dhGY[1], dhGS[1];
  PHASE("derive-dh");
  dhPubT[0].type = CKA_CLASS; dhPubT[0].pValue = &pcls;
  dhPubT[0].ulValueLen = sizeof(pcls);
  dhPubT[1].type = CKA_KEY_TYPE; dhPubT[1].pValue = &dhkt;
  dhPubT[1].ulValueLen = sizeof(dhkt);
  dhPubT[2].type = CKA_PRIME; dhPubT[2].pValue = (CK_VOID_PTR)kFfdhe2048;
  dhPubT[2].ulValueLen = sizeof(kFfdhe2048);
  dhPubT[3].type = CKA_BASE; dhPubT[3].pValue = dhg;
  dhPubT[3].ulValueLen = sizeof(dhg);
  dhPubT[4].type = CKA_TOKEN; dhPubT[4].pValue = &bFalse;
  dhPubT[4].ulValueLen = sizeof(bFalse);
  dhPubT[5].type = CKA_DERIVE; dhPubT[5].pValue = &bTrue;
  dhPubT[5].ulValueLen = sizeof(bTrue);
  dhPrivT[0].type = CKA_CLASS; dhPrivT[0].pValue = &scls;
  dhPrivT[0].ulValueLen = sizeof(scls);
  dhPrivT[1].type = CKA_KEY_TYPE; dhPrivT[1].pValue = &dhkt;
  dhPrivT[1].ulValueLen = sizeof(dhkt);
  dhPrivT[2].type = CKA_TOKEN; dhPrivT[2].pValue = &bFalse;
  dhPrivT[2].ulValueLen = sizeof(bFalse);
  dhPrivT[3].type = CKA_DERIVE; dhPrivT[3].pValue = &bTrue;
  dhPrivT[3].ulValueLen = sizeof(bTrue);
  dhkgm.mechanism = CKM_DH_PKCS_KEY_PAIR_GEN;
  dhkgm.pParameter = NULL_PTR;
  dhkgm.ulParameterLen = 0;
  rv = T->C_GenerateKeyPair(g_sess, &dhkgm, dhPubT, 6, dhPrivT, 4,
                            &dhPubA, &dhPrivA);
  CHECKRV(rv, CKR_OK, "dh pair A mints");
  rv = T->C_GenerateKeyPair(g_sess, &dhkgm, dhPubT, 6, dhPrivT, 4,
                            &dhPubB, &dhPrivB);
  CHECKRV(rv, CKR_OK, "dh pair B mints");
  dhGY[0].type = CKA_VALUE;
  dhGY[0].pValue = dhYA;
  dhGY[0].ulValueLen = sizeof(dhYA);
  rv = T->C_GetAttributeValue(g_sess, dhPubA, dhGY, 1);
  CHECKRV(rv, CKR_OK, "dh pub A reads");
  dhLenA = dhGY[0].ulValueLen;
  CHECKM(dhLenA >= 1 && dhLenA <= 256, "dh pub A sane length");
  dhGY[0].pValue = dhYB;
  dhGY[0].ulValueLen = sizeof(dhYB);
  rv = T->C_GetAttributeValue(g_sess, dhPubB, dhGY, 1);
  CHECKRV(rv, CKR_OK, "dh pub B reads");
  dhLenB = dhGY[0].ulValueLen;
  CHECKM(dhLenB >= 1 && dhLenB <= 256, "dh pub B sane length");
  dhdm.mechanism = CKM_DH_PKCS_DERIVE;
  dhdm.pParameter = dhYB;
  dhdm.ulParameterLen = dhLenB;
  rv = T->C_DeriveKey(g_sess, &dhdm, dhPrivA, dhDtmpl, 6, &dhS1);
  CHECKRV(rv, CKR_OK, "dh derive A->B ok");
  dhdm.pParameter = dhYA;
  dhdm.ulParameterLen = dhLenA;
  rv = T->C_DeriveKey(g_sess, &dhdm, dhPrivB, dhDtmpl, 6, &dhS2);
  CHECKRV(rv, CKR_OK, "dh derive B->A ok");
  dhGS[0].type = CKA_VALUE;
  dhGS[0].pValue = dhSAB;
  dhGS[0].ulValueLen = sizeof(dhSAB);
  rv = T->C_GetAttributeValue(g_sess, dhS1, dhGS, 1);
  CHECKRV(rv, CKR_OK, "dh secret A reads");
  dhLenS1 = dhGS[0].ulValueLen;
  dhGS[0].pValue = dhSBA;
  dhGS[0].ulValueLen = sizeof(dhSBA);
  rv = T->C_GetAttributeValue(g_sess, dhS2, dhGS, 1);
  CHECKRV(rv, CKR_OK, "dh secret B reads");
  dhLenS2 = dhGS[0].ulValueLen;
  CHECKM(dhLenS1 == dhLenS2 && dhLenS1 > 0
         && memcmp(dhSAB, dhSBA, dhLenS1) == 0,
         "dh shared secrets agree");
  return 0;
}

static int phase_wrap(void) {
  CK_RV rv;
  CK_OBJECT_CLASS ckcls = CKO_SECRET_KEY;
  CK_KEY_TYPE akt = CKK_AES;
  CK_ULONG vlen = 32, tlen = 16;
  CK_BBOOL bFalse = CK_FALSE, bTrue = CK_TRUE;
  CK_BYTE iv[16], blob[64], ct[32], pt[32];
  CK_ULONG blobLen, ctl, ptl;
  CK_OBJECT_HANDLE wrapKey = 0, targetKey = 0, unwrapped = 0;
  CK_MECHANISM wm, um, cem;
  CK_ATTRIBUTE wtmpl[] = {
    { CKA_CLASS, &ckcls, sizeof(ckcls) },
    { CKA_KEY_TYPE, &akt, sizeof(akt) },
    { CKA_VALUE_LEN, &vlen, sizeof(vlen) },
    { CKA_TOKEN, &bFalse, sizeof(bFalse) },
    { CKA_WRAP, &bTrue, sizeof(bTrue) },
    { CKA_UNWRAP, &bTrue, sizeof(bTrue) }
  };
  CK_ATTRIBUTE ttmpl[] = {
    { CKA_CLASS, &ckcls, sizeof(ckcls) },
    { CKA_KEY_TYPE, &akt, sizeof(akt) },
    { CKA_VALUE_LEN, &tlen, sizeof(tlen) },
    { CKA_TOKEN, &bFalse, sizeof(bFalse) },
    { CKA_EXTRACTABLE, &bTrue, sizeof(bTrue) }
  };
  CK_ATTRIBUTE dtmpl[] = {
    { CKA_CLASS, &ckcls, sizeof(ckcls) },
    { CKA_KEY_TYPE, &akt, sizeof(akt) },
    { CKA_TOKEN, &bFalse, sizeof(bFalse) },
    { CKA_EXTRACTABLE, &bTrue, sizeof(bTrue) },
    { CKA_ENCRYPT, &bTrue, sizeof(bTrue) },
    { CKA_DECRYPT, &bTrue, sizeof(bTrue) }
  };
  CK_MECHANISM kgm;
  PHASE("wrap");
  memset(iv, 0x1B, sizeof(iv));
  kgm.mechanism = CKM_AES_KEY_GEN;
  kgm.pParameter = NULL_PTR;
  kgm.ulParameterLen = 0;
  rv = T->C_GenerateKey(g_sess, &kgm, wtmpl, 6, &wrapKey);
  CHECKRV(rv, CKR_OK, "wrapping key mints");
  rv = T->C_GenerateKey(g_sess, &kgm, ttmpl, 5, &targetKey);
  CHECKRV(rv, CKR_OK, "wrap target mints");
  wm.mechanism = CKM_AES_CBC;
  wm.pParameter = iv;
  wm.ulParameterLen = sizeof(iv);
  blobLen = sizeof(blob);
  rv = T->C_WrapKey(g_sess, &wm, wrapKey, targetKey, blob, &blobLen);
  CHECKRV(rv, CKR_OK, "wrap ok");
  PHASE("unwrap");
  um.mechanism = CKM_AES_CBC;
  um.pParameter = iv;
  um.ulParameterLen = sizeof(iv);
  rv = T->C_UnwrapKey(g_sess, &um, wrapKey, blob, blobLen,
                      dtmpl, 6, &unwrapped);
  CHECKRV(rv, CKR_OK, "unwrap ok");
  CHECKM(unwrapped != 0 && unwrapped != targetKey,
         "unwrap mints a distinct key");
  /* Prove the unwrapped key is the target: it encrypts what the
   * target decrypts. */
  cem.mechanism = CKM_AES_CBC_PAD;
  cem.pParameter = iv;
  cem.ulParameterLen = sizeof(iv);
  rv = T->C_EncryptInit(g_sess, &cem, unwrapped);
  CHECKRV(rv, CKR_OK, "unwrapped key encrypts");
  ctl = sizeof(ct);
  rv = T->C_Encrypt(g_sess, (CK_BYTE_PTR)"wrap-proved", 11, ct, &ctl);
  CHECKRV(rv, CKR_OK, "unwrapped encrypt yields");
  rv = T->C_DecryptInit(g_sess, &cem, targetKey);
  CHECKRV(rv, CKR_OK, "target key decrypts");
  ptl = sizeof(pt);
  rv = T->C_Decrypt(g_sess, ct, ctl, pt, &ptl);
  CHECKRV(rv, CKR_OK, "target decrypts");
  CHECKM(ptl == 11 && memcmp(pt, "wrap-proved", 11) == 0,
         "wrap round-trip agrees");
  return 0;
}

static int phase_wrap_oaep(void) {
  /* RSA-OAEP(SHA-256) wrap/unwrap of an AES-128 target: the
   * wrapping key maps to facts, so pk::encrypt/pk::decrypt
   * records carry algorithm/bits/hash/padding. */
  CK_RV rv;
  CK_OBJECT_CLASS pubClass = CKO_PUBLIC_KEY, privClass = CKO_PRIVATE_KEY,
                  ckcls = CKO_SECRET_KEY;
  CK_KEY_TYPE rsaType = CKK_RSA, akt = CKK_AES;
  CK_ULONG bits = 2048, tlen = 16;
  CK_BBOOL ckFalse = CK_FALSE, ckTrue = CK_TRUE;
  static CK_BYTE exp3[] = {1, 0, 1};
  CK_ATTRIBUTE pubTmpl[] = {
    {CKA_CLASS, &pubClass, sizeof pubClass},
    {CKA_KEY_TYPE, &rsaType, sizeof rsaType},
    {CKA_TOKEN, &ckFalse, sizeof ckFalse},
    {CKA_MODULUS_BITS, &bits, sizeof bits},
    {CKA_PUBLIC_EXPONENT, exp3, sizeof exp3},
  };
  CK_ATTRIBUTE privTmpl[] = {
    {CKA_CLASS, &privClass, sizeof privClass},
    {CKA_KEY_TYPE, &rsaType, sizeof rsaType},
    {CKA_TOKEN, &ckFalse, sizeof ckFalse},
    {CKA_PRIVATE, &ckTrue, sizeof ckTrue},
  };
  CK_ATTRIBUTE ttmpl[] = {
    { CKA_CLASS, &ckcls, sizeof(ckcls) },
    { CKA_KEY_TYPE, &akt, sizeof(akt) },
    { CKA_VALUE_LEN, &tlen, sizeof(tlen) },
    { CKA_TOKEN, &ckFalse, sizeof(ckFalse) },
    { CKA_EXTRACTABLE, &ckTrue, sizeof(ckTrue) },
    { CKA_SENSITIVE, &ckFalse, sizeof(ckFalse) },
  };
  CK_ATTRIBUTE dtmpl[] = {
    { CKA_CLASS, &ckcls, sizeof(ckcls) },
    { CKA_KEY_TYPE, &akt, sizeof(akt) },
    { CKA_TOKEN, &ckFalse, sizeof(ckFalse) },
    { CKA_EXTRACTABLE, &ckTrue, sizeof(ckTrue) },
    { CKA_SENSITIVE, &ckFalse, sizeof(ckFalse) },
  };
  CK_MECHANISM kgm, aeskgm, wm, um;
  CK_RSA_PKCS_OAEP_PARAMS oaep;
  CK_OBJECT_HANDLE rPub = 0, rPriv = 0, target = 0, unwrapped = 0;
  CK_BYTE blob[512], want[32], got[32];
  CK_ULONG blobLen;
  CK_ATTRIBUTE g[1];
  PHASE("wrap-oaep");
  kgm.mechanism = CKM_RSA_PKCS_KEY_PAIR_GEN;
  kgm.pParameter = NULL_PTR;
  kgm.ulParameterLen = 0;
  rv = T->C_GenerateKeyPair(g_sess, &kgm, pubTmpl, 5, privTmpl, 4,
                            &rPub, &rPriv);
  CHECKRV(rv, CKR_OK, "oaep rsa pair mints");
  aeskgm.mechanism = CKM_AES_KEY_GEN;
  aeskgm.pParameter = NULL_PTR;
  aeskgm.ulParameterLen = 0;
  rv = T->C_GenerateKey(g_sess, &aeskgm, ttmpl, 6, &target);
  CHECKRV(rv, CKR_OK, "oaep target mints");
  oaep.hashAlg = CKM_SHA256;
  oaep.mgf = CKG_MGF1_SHA256;
  oaep.source = CKZ_DATA_SPECIFIED;
  oaep.pSourceData = NULL_PTR;
  oaep.ulSourceDataLen = 0;
  wm.mechanism = CKM_RSA_PKCS_OAEP;
  wm.pParameter = &oaep;
  wm.ulParameterLen = sizeof(oaep);
  blobLen = sizeof(blob);
  rv = T->C_WrapKey(g_sess, &wm, rPub, target, blob, &blobLen);
  CHECKRV(rv, CKR_OK, "oaep wrap ok");
  g[0].type = CKA_VALUE;
  g[0].pValue = want;
  g[0].ulValueLen = sizeof(want);
  rv = T->C_GetAttributeValue(g_sess, target, g, 1);
  CHECKRV(rv, CKR_OK, "oaep target reads");
  CHECKM(g[0].ulValueLen == 16, "oaep target is 16 bytes");
  PHASE("unwrap-oaep");
  um.mechanism = CKM_RSA_PKCS_OAEP;
  um.pParameter = &oaep;
  um.ulParameterLen = sizeof(oaep);
  rv = T->C_UnwrapKey(g_sess, &um, rPriv, blob, blobLen, dtmpl, 5,
                      &unwrapped);
  CHECKRV(rv, CKR_OK, "oaep unwrap ok");
  g[0].type = CKA_VALUE;
  g[0].pValue = got;
  g[0].ulValueLen = sizeof(got);
  rv = T->C_GetAttributeValue(g_sess, unwrapped, g, 1);
  CHECKRV(rv, CKR_OK, "oaep unwrapped reads");
  CHECKM(g[0].ulValueLen == 16 && memcmp(want, got, 16) == 0,
         "oaep round-trip agrees");
  return 0;
}

static int phase_wrap_query_denied(void) {
  /* A NULL wrap query against an unextractable target refuses with
   * KEY_UNEXTRACTABLE (policy): reject + failed-publish end. */
  CK_RV rv;
  CK_OBJECT_CLASS ckcls = CKO_SECRET_KEY;
  CK_KEY_TYPE akt = CKK_AES;
  CK_ULONG vlen = 32, tlen = 16;
  CK_BBOOL bFalse = CK_FALSE, bTrue = CK_TRUE;
  CK_BYTE iv[16];
  CK_ULONG blobLen = 0;
  CK_OBJECT_HANDLE wrapKey = 0, sealed = 0;
  CK_MECHANISM wm, kgm;
  CK_ATTRIBUTE wtmpl[] = {
    { CKA_CLASS, &ckcls, sizeof(ckcls) },
    { CKA_KEY_TYPE, &akt, sizeof(akt) },
    { CKA_VALUE_LEN, &vlen, sizeof(vlen) },
    { CKA_TOKEN, &bFalse, sizeof(bFalse) },
    { CKA_WRAP, &bTrue, sizeof(bTrue) },
    { CKA_UNWRAP, &bTrue, sizeof(bTrue) }
  };
  CK_ATTRIBUTE stmpl[] = {
    { CKA_CLASS, &ckcls, sizeof(ckcls) },
    { CKA_KEY_TYPE, &akt, sizeof(akt) },
    { CKA_VALUE_LEN, &tlen, sizeof(tlen) },
    { CKA_TOKEN, &bFalse, sizeof(bFalse) },
    { CKA_EXTRACTABLE, &bFalse, sizeof(bFalse) }
  };
  PHASE("wrap-query-denied");
  memset(iv, 0x33, sizeof(iv));
  kgm.mechanism = CKM_AES_KEY_GEN;
  kgm.pParameter = NULL_PTR;
  kgm.ulParameterLen = 0;
  rv = T->C_GenerateKey(g_sess, &kgm, wtmpl, 6, &wrapKey);
  CHECKRV(rv, CKR_OK, "denied wrapKey mints");
  rv = T->C_GenerateKey(g_sess, &kgm, stmpl, 5, &sealed);
  CHECKRV(rv, CKR_OK, "sealed target mints");
  wm.mechanism = CKM_AES_CBC;
  wm.pParameter = iv;
  wm.ulParameterLen = sizeof(iv);
  rv = T->C_WrapKey(g_sess, &wm, wrapKey, sealed, NULL, &blobLen);
  CHECKRV(rv, CKR_KEY_UNEXTRACTABLE, "sealed query refused");
  return 0;
}

static int phase_logout_staged(void) {
  /* Two-session logout: B stages a short HMAC recall on a private
   * key; A's logout retires it (abandoned end, cross-session flush).
   * B then mints an EC pair and signs: the ECDSA record must be
   * clean (no stale HMAC retention behind it). */
  CK_RV rv;
  CK_SESSION_HANDLE sessA = 0, sessB = 0;
  CK_OBJECT_CLASS ckcls = CKO_SECRET_KEY;
  CK_OBJECT_CLASS pubClass = CKO_PUBLIC_KEY, privClass = CKO_PRIVATE_KEY;
  CK_KEY_TYPE gkt = CKK_GENERIC_SECRET, ekt = CKK_EC;
  CK_BBOOL t = CK_TRUE, fa = CK_FALSE;
  CK_OBJECT_HANDLE hm = 0, epub = 0, epriv = 0;
  CK_MECHANISM sm, em, kgm;
  CK_BYTE small[4], sig[128];
  CK_ULONG smallLen, sigLen;
  CK_BYTE hraw[16] = {
    5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5
  };
  CK_ATTRIBUTE htmpl[] = {
    { CKA_CLASS, &ckcls, sizeof(ckcls) },
    { CKA_KEY_TYPE, &gkt, sizeof(gkt) },
    { CKA_TOKEN, &fa, sizeof(fa) },
    { CKA_PRIVATE, &t, sizeof(t) },
    { CKA_SIGN, &t, sizeof(t) },
    { CKA_VALUE, hraw, sizeof(hraw) },
  };
  CK_ATTRIBUTE epubT[] = {
    { CKA_CLASS, &pubClass, sizeof(pubClass) },
    { CKA_KEY_TYPE, &ekt, sizeof(ekt) },
    { CKA_EC_PARAMS, (CK_VOID_PTR)kP256Oid, sizeof(kP256Oid) },
    { CKA_TOKEN, &fa, sizeof(fa) },
    { CKA_VERIFY, &t, sizeof(t) },
  };
  CK_ATTRIBUTE eprivT[] = {
    { CKA_CLASS, &privClass, sizeof(privClass) },
    { CKA_KEY_TYPE, &ekt, sizeof(ekt) },
    { CKA_TOKEN, &fa, sizeof(fa) },
    { CKA_SIGN, &t, sizeof(t) },
  };
  PHASE("logout-staged");
  if (open_session(&sessA)) CHECKM(0, "logout sessA opens");
  if (open_session(&sessB)) CHECKM(0, "logout sessB opens");
  /* No explicit logins: auth is token-level and the slot is already
   * user-logged-in, so a second login refuses ALREADY_LOGGED_IN. */
  rv = T->C_CreateObject(sessB, htmpl, 6, &hm);
  CHECKRV(rv, CKR_OK, "logout hmac imports");
  sm.mechanism = CKM_SHA256_HMAC;
  sm.pParameter = NULL_PTR;
  sm.ulParameterLen = 0;
  rv = T->C_SignInit(sessB, &sm, hm);
  CHECKRV(rv, CKR_OK, "logout sign-init");
  smallLen = sizeof(small);
  rv = T->C_Sign(sessB, (CK_BYTE_PTR)kMsg, strlen(kMsg), small, &smallLen);
  CHECKRV(rv, CKR_BUFFER_TOO_SMALL, "logout short stages");
  PHASE("logout-fires");
  rv = T->C_Logout(sessA);
  CHECKRV(rv, CKR_OK, "logout lands");
  PHASE("logout-clean");
  kgm.mechanism = CKM_EC_KEY_PAIR_GEN;
  kgm.pParameter = NULL_PTR;
  kgm.ulParameterLen = 0;
  rv = T->C_GenerateKeyPair(sessB, &kgm, epubT, 5, eprivT, 4,
                            &epub, &epriv);
  CHECKRV(rv, CKR_OK, "logout ec pair mints");
  em.mechanism = CKM_ECDSA_SHA256;
  em.pParameter = NULL_PTR;
  em.ulParameterLen = 0;
  rv = T->C_SignInit(sessB, &em, epriv);
  CHECKRV(rv, CKR_OK, "logout ecdsa sign-init");
  sigLen = sizeof(sig);
  rv = T->C_Sign(sessB, (CK_BYTE_PTR)kMsg, strlen(kMsg), sig, &sigLen);
  CHECKRV(rv, CKR_OK, "logout ecdsa signs");
  CHECKM(sigLen == 64, "ecdsa sig raw 64 bytes");
  PHASE("logout-ec-verify");
  rv = T->C_VerifyInit(sessB, &em, epub);
  CHECKRV(rv, CKR_OK, "logout ecdsa verify-init");
  rv = T->C_Verify(sessB, (CK_BYTE_PTR)kMsg, strlen(kMsg), sig, sigLen);
  CHECKRV(rv, CKR_OK, "logout ecdsa verifies");
  rv = T->C_CloseSession(sessA);
  CHECKRV(rv, CKR_OK, "logout sessA closes");
  rv = T->C_CloseSession(sessB);
  CHECKRV(rv, CKR_OK, "logout sessB closes");
  return 0;
}

static int phase_eddsa(void) {
  /* Ed25519 keygen/sign/verify: the verify record resolves the
   * public half (engine-name params, no value attribute). */
  CK_RV rv;
  CK_OBJECT_CLASS pcls = CKO_PUBLIC_KEY, scls = CKO_PRIVATE_KEY;
  CK_KEY_TYPE ekt = CKK_EC_EDWARDS;
  CK_BBOOL bFalse = CK_FALSE, bTrue = CK_TRUE;
  CK_BYTE edParams[] = { 0x06, 0x03, 0x2B, 0x65, 0x70 };
  CK_ATTRIBUTE epubT[] = {
    { CKA_CLASS, &pcls, sizeof(pcls) },
    { CKA_KEY_TYPE, &ekt, sizeof(ekt) },
    { CKA_EC_PARAMS, edParams, sizeof(edParams) },
    { CKA_TOKEN, &bFalse, sizeof(bFalse) },
    { CKA_VERIFY, &bTrue, sizeof(bTrue) },
  };
  CK_ATTRIBUTE eprivT[] = {
    { CKA_CLASS, &scls, sizeof(scls) },
    { CKA_KEY_TYPE, &ekt, sizeof(ekt) },
    { CKA_TOKEN, &bFalse, sizeof(bFalse) },
    { CKA_SIGN, &bTrue, sizeof(bTrue) },
  };
  CK_MECHANISM kgm, sm;
  CK_EDDSA_PARAMS epure;
  CK_OBJECT_HANDLE epub = 0, epriv = 0;
  CK_BYTE sig[64], msg[] = "hello-eddsa";
  CK_ULONG sigLen;
  PHASE("eddsa");
  kgm.mechanism = CKM_EC_EDWARDS_KEY_PAIR_GEN;
  kgm.pParameter = NULL_PTR;
  kgm.ulParameterLen = 0;
  rv = T->C_GenerateKeyPair(g_sess, &kgm, epubT, 5, eprivT, 4,
                            &epub, &epriv);
  CHECKRV(rv, CKR_OK, "eddsa pair mints");
  epure.phFlag = CK_FALSE;
  epure.ulContextDataLen = 0;
  epure.pContextData = NULL_PTR;
  sm.mechanism = CKM_EDDSA;
  sm.pParameter = &epure;
  sm.ulParameterLen = sizeof(epure);
  rv = T->C_SignInit(g_sess, &sm, epriv);
  CHECKRV(rv, CKR_OK, "eddsa sign-init");
  sigLen = sizeof(sig);
  rv = T->C_Sign(g_sess, msg, sizeof(msg) - 1, sig, &sigLen);
  CHECKRV(rv, CKR_OK, "eddsa signs");
  CHECKM(sigLen == 64, "eddsa sig 64 bytes");
  rv = T->C_VerifyInit(g_sess, &sm, epub);
  CHECKRV(rv, CKR_OK, "eddsa verify-init");
  rv = T->C_Verify(g_sess, msg, sizeof(msg) - 1, sig, sigLen);
  CHECKRV(rv, CKR_OK, "eddsa verifies");
  return 0;
}

static int phase_msg_init_denied(void) {
  /* Message-init denial reports the requested mechanism, like the
   * classic path: ECDSA message-sign init on an AES key. */
  CK_RV rv;
  CK_OBJECT_CLASS ckcls = CKO_SECRET_KEY;
  CK_KEY_TYPE akt = CKK_AES;
  CK_ULONG vlen = 16;
  CK_BBOOL bFalse = CK_FALSE;
  CK_MECHANISM kgm, em;
  CK_OBJECT_HANDLE aes = 0;
  CK_ATTRIBUTE tmpl[] = {
    { CKA_CLASS, &ckcls, sizeof(ckcls) },
    { CKA_KEY_TYPE, &akt, sizeof(akt) },
    { CKA_VALUE_LEN, &vlen, sizeof(vlen) },
    { CKA_TOKEN, &bFalse, sizeof(bFalse) },
  };
  PHASE("msg-init-denied");
  kgm.mechanism = CKM_AES_KEY_GEN;
  kgm.pParameter = NULL_PTR;
  kgm.ulParameterLen = 0;
  rv = T->C_GenerateKey(g_sess, &kgm, tmpl, 4, &aes);
  CHECKRV(rv, CKR_OK, "msg-denied aes mints");
  em.mechanism = CKM_ECDSA_SHA256;
  em.pParameter = NULL_PTR;
  em.ulParameterLen = 0;
  rv = tab32->C_MessageSignInit(g_sess, &em, aes);
  CHECKRV(rv, CKR_KEY_TYPE_INCONSISTENT, "msg ecdsa/aes refused");
  return 0;
}

static int phase_msg_query_modes(void) {
  /* Query finality: the same NOT_INITIALIZED failure stays silent
   * for a non-final query but reports a failed end for a final
   * one. Own session. */
  CK_RV rv;
  CK_SESSION_HANDLE msess = 0;
  CK_OBJECT_CLASS ckcls = CKO_SECRET_KEY;
  CK_KEY_TYPE akt = CKK_AES;
  CK_ULONG vlen = 16;
  CK_BBOOL bFalse = CK_FALSE;
  CK_MECHANISM kgm, cm;
  CK_OBJECT_HANDLE aes = 0;
  CK_ATTRIBUTE tmpl[] = {
    { CKA_CLASS, &ckcls, sizeof(ckcls) },
    { CKA_KEY_TYPE, &akt, sizeof(akt) },
    { CKA_VALUE_LEN, &vlen, sizeof(vlen) },
    { CKA_TOKEN, &bFalse, sizeof(bFalse) },
  };
  static CK_BYTE iv[16] = {
    11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11
  };
  static CK_BYTE pt[] = "query-blk-16byte";
  CK_ULONG qLen;
  PHASE("msg-query-modes");
  if (open_session(&msess)) CHECKM(0, "query session opens");
  kgm.mechanism = CKM_AES_KEY_GEN;
  kgm.pParameter = NULL_PTR;
  kgm.ulParameterLen = 0;
  rv = T->C_GenerateKey(msess, &kgm, tmpl, 4, &aes);
  CHECKRV(rv, CKR_OK, "query aes mints");
  cm.mechanism = CKM_AES_CBC;
  cm.pParameter = iv;
  cm.ulParameterLen = sizeof(iv);
  rv = tab32->C_MessageEncryptInit(msess, &cm, aes);
  CHECKRV(rv, CKR_OK, "query encrypt-init");
  qLen = 0;
  rv = tab32->C_EncryptMessageNext(msess, NULL, 0, pt, sizeof(pt) - 1,
                                 NULL, &qLen, 0);
  CHECKRV(rv, CKR_OPERATION_NOT_INITIALIZED, "non-final query silent");
  qLen = 0;
  rv = tab32->C_EncryptMessageNext(msess, NULL, 0, pt, sizeof(pt) - 1,
                                 NULL, &qLen, CKF_END_OF_MESSAGE);
  CHECKRV(rv, CKR_OPERATION_NOT_INITIALIZED, "final query reports");
  rv = T->C_CloseSession(msess);
  CHECKRV(rv, CKR_OK, "query session closes");
  return 0;
}

static int phase_msg_query_staged(void) {
  /* Queries neither disturb nor duplicate staged output: a NULL
   * query on a staged slot reports its length, and closing still
   * abandons exactly once. Own session. */
  CK_RV rv;
  CK_SESSION_HANDLE msess = 0;
  CK_OBJECT_CLASS ckcls = CKO_SECRET_KEY;
  CK_KEY_TYPE akt = CKK_AES;
  CK_ULONG vlen = 16;
  CK_BBOOL bFalse = CK_FALSE;
  CK_MECHANISM kgm, cm;
  CK_OBJECT_HANDLE aes = 0;
  CK_ATTRIBUTE tmpl[] = {
    { CKA_CLASS, &ckcls, sizeof(ckcls) },
    { CKA_KEY_TYPE, &akt, sizeof(akt) },
    { CKA_VALUE_LEN, &vlen, sizeof(vlen) },
    { CKA_TOKEN, &bFalse, sizeof(bFalse) },
  };
  static CK_BYTE iv[16] = {
    13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13
  };
  static CK_BYTE pt[] = "staged-query-16!";
  CK_BYTE small[4];
  CK_ULONG smallLen, qLen;
  PHASE("msg-query-staged");
  if (open_session(&msess)) CHECKM(0, "staged session opens");
  kgm.mechanism = CKM_AES_KEY_GEN;
  kgm.pParameter = NULL_PTR;
  kgm.ulParameterLen = 0;
  rv = T->C_GenerateKey(msess, &kgm, tmpl, 4, &aes);
  CHECKRV(rv, CKR_OK, "staged aes mints");
  cm.mechanism = CKM_AES_CBC;
  cm.pParameter = iv;
  cm.ulParameterLen = sizeof(iv);
  rv = tab32->C_MessageEncryptInit(msess, &cm, aes);
  CHECKRV(rv, CKR_OK, "staged encrypt-init");
  rv = tab32->C_EncryptMessageBegin(msess, iv, sizeof(iv), NULL, 0);
  CHECKRV(rv, CKR_OK, "staged begin");
  smallLen = sizeof(small);
  rv = tab32->C_EncryptMessageNext(msess, NULL, 0, pt, sizeof(pt) - 1,
                                 small, &smallLen, CKF_END_OF_MESSAGE);
  CHECKRV(rv, CKR_BUFFER_TOO_SMALL, "staged short stages");
  qLen = 0;
  rv = tab32->C_EncryptMessageNext(msess, NULL, 0, pt, sizeof(pt) - 1,
                                 NULL, &qLen, 0);
  CHECKRV(rv, CKR_OK, "staged query reports length");
  CHECKM(qLen == 16, "staged length 16");
  rv = T->C_CloseSession(msess);
  CHECKRV(rv, CKR_OK, "staged close abandons once");
  return 0;
}

static int phase_msg_recall_nonfinal(void) {
  /* N1: a non-final recall on a staged slot still delivers the
   * staged final output: the staged state, not the caller's end
   * flag, decides terminality. Final short, then a non-final
   * recall with room (one delivered end — unfixed, zero ends),
   * then a re-init plus a one-shot pinning F_EncryptMessage
   * (one-shots need init; the recall's terminal delivery is what
   * drops the retention, in the same path that emits its end).
   * Own session. */
  CK_RV rv;
  CK_SESSION_HANDLE msess = 0;
  CK_OBJECT_CLASS ckcls = CKO_SECRET_KEY;
  CK_KEY_TYPE akt = CKK_AES;
  CK_ULONG vlen = 16;
  CK_BBOOL bFalse = CK_FALSE;
  CK_MECHANISM kgm, cm;
  CK_OBJECT_HANDLE aes = 0;
  CK_ATTRIBUTE tmpl[] = {
    { CKA_CLASS, &ckcls, sizeof(ckcls) },
    { CKA_KEY_TYPE, &akt, sizeof(akt) },
    { CKA_VALUE_LEN, &vlen, sizeof(vlen) },
    { CKA_TOKEN, &bFalse, sizeof(bFalse) },
  };
  static CK_BYTE iv[16] = {
    17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17
  };
  static CK_BYTE pt[] = "recall-nonfin-16";
  CK_BYTE small[4], out[32], once[32];
  CK_ULONG smallLen, outLen, onceLen;
  PHASE("msg-recall-nonfinal");
  if (open_session(&msess)) CHECKM(0, "recall session opens");
  kgm.mechanism = CKM_AES_KEY_GEN;
  kgm.pParameter = NULL_PTR;
  kgm.ulParameterLen = 0;
  rv = T->C_GenerateKey(msess, &kgm, tmpl, 4, &aes);
  CHECKRV(rv, CKR_OK, "recall aes mints");
  cm.mechanism = CKM_AES_CBC;
  cm.pParameter = iv;
  cm.ulParameterLen = sizeof(iv);
  rv = tab32->C_MessageEncryptInit(msess, &cm, aes);
  CHECKRV(rv, CKR_OK, "recall encrypt-init");
  rv = tab32->C_EncryptMessageBegin(msess, iv, sizeof(iv), NULL, 0);
  CHECKRV(rv, CKR_OK, "recall begin");
  smallLen = sizeof(small);
  rv = tab32->C_EncryptMessageNext(msess, NULL, 0, pt, sizeof(pt) - 1,
                                 small, &smallLen, CKF_END_OF_MESSAGE);
  CHECKRV(rv, CKR_BUFFER_TOO_SMALL, "recall final short stages");
  outLen = sizeof(out);
  rv = tab32->C_EncryptMessageNext(msess, NULL, 0, pt, sizeof(pt) - 1,
                                 out, &outLen, 0);
  CHECKRV(rv, CKR_OK, "recall non-final delivers");
  CHECKM(outLen == 16, "recall delivers 16");
  rv = tab32->C_MessageEncryptFinal(msess);
  CHECKRV(rv, CKR_OK, "recall final closes context");
  rv = tab32->C_MessageEncryptInit(msess, &cm, aes);
  CHECKRV(rv, CKR_OK, "recall re-init for one-shot");
  onceLen = sizeof(once);
  rv = tab32->C_EncryptMessage(msess, iv, sizeof(iv), NULL, 0, pt,
                             sizeof(pt) - 1, once, &onceLen);
  CHECKRV(rv, CKR_OK, "recall one-shot clean");
  rv = T->C_CloseSession(msess);
  CHECKRV(rv, CKR_OK, "recall close");
  return 0;
}

static int phase_digestkey_staged_denied(void) {
  /* Staged digest recall killed by a policy DigestKey refusal: one
   * op carries the reject (ov=1) plus the abandoned end. */
  CK_RV rv;
  CK_MECHANISM mech;
  CK_BYTE small[10];
  CK_ULONG smallLen;
  PHASE("digestkey-staged-denied");
  mech.mechanism = CKM_SHA256;
  mech.pParameter = NULL_PTR;
  mech.ulParameterLen = 0;
  rv = T->C_DigestInit(g_sess, &mech);
  CHECKRV(rv, CKR_OK, "staged digest-init");
  smallLen = sizeof small;
  rv = T->C_Digest(g_sess, (CK_BYTE_PTR)"abc", 3, small, &smallLen);
  CHECKRV(rv, CKR_BUFFER_TOO_SMALL, "staged short stages");
  rv = T->C_DigestKey(g_sess, g_pub);
  CHECKRV(rv, CKR_KEY_TYPE_INCONSISTENT, "staged non-secret refused");
  return 0;
}

static int phase_encaps_query_denied(void) {
  /* A NULL encapsulate query against a key without the encapsulate
   * flag refuses with KEY_FUNCTION_NOT_PERMITTED (policy). */
  CK_RV rv;
  CK_OBJECT_CLASS pcls = CKO_PUBLIC_KEY, scls = CKO_PRIVATE_KEY,
                  ckcls = CKO_SECRET_KEY;
  CK_KEY_TYPE kkt = CKK_ML_KEM, akt = CKK_AES;
  CK_ULONG ckp = CKP_ML_KEM_768, vlen32 = 32;
  CK_BBOOL bFalse = CK_FALSE, bTrue = CK_TRUE;
  CK_MECHANISM kgm, kem;
  CK_ATTRIBUTE pubT[6], privT[6], secT[6];
  CK_OBJECT_HANDLE pub = 0, priv = 0;
  CK_ULONG ctLen = 0;
  CK_OBJECT_HANDLE secret = 0;
  PHASE("encaps-query-denied");
  kgm.mechanism = CKM_ML_KEM_KEY_PAIR_GEN;
  kgm.pParameter = NULL_PTR;
  kgm.ulParameterLen = 0;
  kem.mechanism = CKM_ML_KEM;
  kem.pParameter = NULL_PTR;
  kem.ulParameterLen = 0;
  pubT[0].type = CKA_CLASS; pubT[0].pValue = &pcls;
  pubT[0].ulValueLen = sizeof(pcls);
  pubT[1].type = CKA_KEY_TYPE; pubT[1].pValue = &kkt;
  pubT[1].ulValueLen = sizeof(kkt);
  pubT[2].type = CKA_PARAMETER_SET; pubT[2].pValue = &ckp;
  pubT[2].ulValueLen = sizeof(ckp);
  pubT[3].type = CKA_TOKEN; pubT[3].pValue = &bFalse;
  pubT[3].ulValueLen = sizeof(bFalse);
  pubT[4].type = CKA_ENCAPSULATE; pubT[4].pValue = &bFalse;
  pubT[4].ulValueLen = sizeof(bFalse);
  pubT[5].type = CKA_EXTRACTABLE; pubT[5].pValue = &bTrue;
  pubT[5].ulValueLen = sizeof(bTrue);
  privT[0].type = CKA_CLASS; privT[0].pValue = &scls;
  privT[0].ulValueLen = sizeof(scls);
  privT[1].type = CKA_KEY_TYPE; privT[1].pValue = &kkt;
  privT[1].ulValueLen = sizeof(kkt);
  privT[2].type = CKA_TOKEN; privT[2].pValue = &bFalse;
  privT[2].ulValueLen = sizeof(bFalse);
  privT[3].type = CKA_DECAPSULATE; privT[3].pValue = &bTrue;
  privT[3].ulValueLen = sizeof(bTrue);
  privT[4].type = CKA_EXTRACTABLE; privT[4].pValue = &bTrue;
  privT[4].ulValueLen = sizeof(bTrue);
  privT[5].type = CKA_SENSITIVE; privT[5].pValue = &bFalse;
  privT[5].ulValueLen = sizeof(bFalse);
  rv = T->C_GenerateKeyPair(g_sess, &kgm, pubT, 6, privT, 6, &pub, &priv);
  CHECKRV(rv, CKR_OK, "denied kem pair mints");
  secT[0].type = CKA_CLASS; secT[0].pValue = &ckcls;
  secT[0].ulValueLen = sizeof(ckcls);
  secT[1].type = CKA_KEY_TYPE; secT[1].pValue = &akt;
  secT[1].ulValueLen = sizeof(akt);
  secT[2].type = CKA_VALUE_LEN; secT[2].pValue = &vlen32;
  secT[2].ulValueLen = sizeof(vlen32);
  secT[3].type = CKA_TOKEN; secT[3].pValue = &bFalse;
  secT[3].ulValueLen = sizeof(bFalse);
  secT[4].type = CKA_EXTRACTABLE; secT[4].pValue = &bTrue;
  secT[4].ulValueLen = sizeof(bTrue);
  secT[5].type = CKA_SENSITIVE; secT[5].pValue = &bFalse;
  secT[5].ulValueLen = sizeof(bFalse);
  rv = tab32->C_EncapsulateKey(g_sess, &kem, pub, secT, 6, NULL,
                             &ctLen, &secret);
  CHECKRV(rv, CKR_KEY_FUNCTION_NOT_PERMITTED, "sealed query refused");
  return 0;
}

static int phase_kem(void) {
  /* ML-KEM-768 round-trip (mirrors the consumer_kem 768 flow). */
  CK_RV rv;
  CK_OBJECT_CLASS pcls = CKO_PUBLIC_KEY, scls = CKO_PRIVATE_KEY,
                  ckcls = CKO_SECRET_KEY;
  CK_KEY_TYPE kkt = CKK_ML_KEM, akt = CKK_AES;
  CK_ULONG ckp = CKP_ML_KEM_768, vlen32 = 32;
  CK_BBOOL bFalse = CK_FALSE, bTrue = CK_TRUE;
  CK_MECHANISM kgm, kem;
  CK_ATTRIBUTE pubT[6], privT[6], secT[6];
  CK_OBJECT_HANDLE pub = 0, priv = 0, secret = 0, recovered = 0;
  CK_BYTE ct[1600], ss1[32], ss2[32];
  CK_ULONG ctLen;
  CK_ATTRIBUTE getT[1];
  PHASE("kem-keygen");
  kgm.mechanism = CKM_ML_KEM_KEY_PAIR_GEN;
  kgm.pParameter = NULL_PTR;
  kgm.ulParameterLen = 0;
  kem.mechanism = CKM_ML_KEM;
  kem.pParameter = NULL_PTR;
  kem.ulParameterLen = 0;
  pubT[0].type = CKA_CLASS; pubT[0].pValue = &pcls;
  pubT[0].ulValueLen = sizeof(pcls);
  pubT[1].type = CKA_KEY_TYPE; pubT[1].pValue = &kkt;
  pubT[1].ulValueLen = sizeof(kkt);
  pubT[2].type = CKA_PARAMETER_SET; pubT[2].pValue = &ckp;
  pubT[2].ulValueLen = sizeof(ckp);
  pubT[3].type = CKA_TOKEN; pubT[3].pValue = &bFalse;
  pubT[3].ulValueLen = sizeof(bFalse);
  pubT[4].type = CKA_ENCAPSULATE; pubT[4].pValue = &bTrue;
  pubT[4].ulValueLen = sizeof(bTrue);
  pubT[5].type = CKA_EXTRACTABLE; pubT[5].pValue = &bTrue;
  pubT[5].ulValueLen = sizeof(bTrue);
  privT[0].type = CKA_CLASS; privT[0].pValue = &scls;
  privT[0].ulValueLen = sizeof(scls);
  privT[1].type = CKA_KEY_TYPE; privT[1].pValue = &kkt;
  privT[1].ulValueLen = sizeof(kkt);
  privT[2].type = CKA_TOKEN; privT[2].pValue = &bFalse;
  privT[2].ulValueLen = sizeof(bFalse);
  privT[3].type = CKA_DECAPSULATE; privT[3].pValue = &bTrue;
  privT[3].ulValueLen = sizeof(bTrue);
  privT[4].type = CKA_EXTRACTABLE; privT[4].pValue = &bTrue;
  privT[4].ulValueLen = sizeof(bTrue);
  privT[5].type = CKA_SENSITIVE; privT[5].pValue = &bFalse;
  privT[5].ulValueLen = sizeof(bFalse);
  rv = T->C_GenerateKeyPair(g_sess, &kgm, pubT, 6, privT, 6, &pub, &priv);
  CHECKRV(rv, CKR_OK, "kem keygen");
  CHECKM(pub != 0 && priv != 0, "kem handles minted");
  secT[0].type = CKA_CLASS; secT[0].pValue = &ckcls;
  secT[0].ulValueLen = sizeof(ckcls);
  secT[1].type = CKA_KEY_TYPE; secT[1].pValue = &akt;
  secT[1].ulValueLen = sizeof(akt);
  secT[2].type = CKA_VALUE_LEN; secT[2].pValue = &vlen32;
  secT[2].ulValueLen = sizeof(vlen32);
  secT[3].type = CKA_TOKEN; secT[3].pValue = &bFalse;
  secT[3].ulValueLen = sizeof(bFalse);
  secT[4].type = CKA_EXTRACTABLE; secT[4].pValue = &bTrue;
  secT[4].ulValueLen = sizeof(bTrue);
  secT[5].type = CKA_SENSITIVE; secT[5].pValue = &bFalse;
  secT[5].ulValueLen = sizeof(bFalse);
  PHASE("encaps");
  ctLen = sizeof(ct);
  rv = tab32->C_EncapsulateKey(g_sess, &kem, pub, secT, 6, ct, &ctLen, &secret);
  CHECKRV(rv, CKR_OK, "encapsulates");
  CHECKM(ctLen == 1088 && secret != 0, "encaps 1088 bytes plus a secret");
  getT[0].type = CKA_VALUE;
  getT[0].pValue = ss1;
  getT[0].ulValueLen = sizeof(ss1);
  rv = T->C_GetAttributeValue(g_sess, secret, getT, 1);
  CHECKRV(rv, CKR_OK, "encaps secret reads");
  PHASE("decaps");
  rv = tab32->C_DecapsulateKey(g_sess, &kem, priv, secT, 6, ct, ctLen, &recovered);
  CHECKRV(rv, CKR_OK, "decapsulates");
  getT[0].type = CKA_VALUE;
  getT[0].pValue = ss2;
  getT[0].ulValueLen = sizeof(ss2);
  rv = T->C_GetAttributeValue(g_sess, recovered, getT, 1);
  CHECKRV(rv, CKR_OK, "decaps secret reads");
  CHECKM(memcmp(ss1, ss2, 32) == 0, "kem shared secrets agree");
  return 0;
}

/* ---- async legs (attached ctx, digest jobs) ---- */

static fn_open pOpen;
static fn_close pClose;
static fn_init pInit;
static fn_start pStart;
static fn_poll pPoll;
static fn_complete pComplete;
static fn_cancel pCancel;
static fn_store_open pStoreOpen;
static fn_store_close pStoreClose;
static fn_open_on pOpenOn;
static fn_get_id pGetId;
static fn_join pJoin;

static int async_resolve(void *h) {
  pOpen = (fn_open)dlsym(h, "haskoki_async_open");
  pClose = (fn_close)dlsym(h, "haskoki_async_close");
  pInit = (fn_init)dlsym(h, "haskoki_async_digest_init");
  pStart = (fn_start)dlsym(h, "haskoki_async_start");
  pPoll = (fn_poll)dlsym(h, "haskoki_async_poll");
  pComplete = (fn_complete)dlsym(h, "haskoki_async_complete");
  pCancel = (fn_cancel)dlsym(h, "haskoki_async_cancel");
  pStoreOpen = (fn_store_open)dlsym(h, "haskoki_async_store_open");
  pStoreClose = (fn_store_close)dlsym(h, "haskoki_async_store_close");
  pOpenOn = (fn_open_on)dlsym(h, "haskoki_async_open_on");
  pGetId = (fn_get_id)dlsym(h, "haskoki_async_get_id");
  pJoin = (fn_join)dlsym(h, "haskoki_async_join");
  CHECKM(pOpen && pClose && pInit && pStart && pPoll && pComplete && pCancel
         && pStoreOpen && pStoreClose && pOpenOn && pGetId && pJoin,
         "async trampolines resolve");
  return 0;
}

static int phase_async_deliver(void) {
  haskoki_async_ctx_t ctx;
  haskoki_async_job_t job = NULL;
  CK_RV rv;
  async_data_t res;
  CK_BYTE buf[64];
  PHASE("async-deliver");
  ctx = pOpen();
  CHECKM(ctx != NULL, "async ctx opens");
  rv = pInit(ctx, 1, CKM_SHA256, NULL, 0);
  CHECKRV(rv, CKR_OK, "async digest init");
  rv = pStart(ctx, 1, FN_DIGEST, (CK_BYTE_PTR)"abc", 3, 32, 1, &job);
  CHECKRV(rv, CKR_PENDING, "async start pending");
  CHECKM(job != NULL, "async job handle");
  memset(&res, 0, sizeof(res));
  res.pValue = buf;
  res.ulValue = sizeof(buf);
  rv = pPoll(ctx, job, FN_DIGEST);
  CHECKRV(rv, CKR_OK, "async poll ready");
  rv = pComplete(ctx, job, FN_DIGEST, &res);
  CHECKRV(rv, CKR_OK, "async complete delivers");
  CHECKM(res.ulValue == 32 && memcmp(buf, kWant, 32) == 0,
         "async KAT bytes exact");
  pClose(&ctx);
  CHECKM(ctx == NULL, "async ctx closes");
  return 0;
}

static int phase_async_cancel(void) {
  haskoki_async_ctx_t ctx;
  haskoki_async_job_t job = NULL;
  CK_RV rv;
  PHASE("async-cancel");
  ctx = pOpen();
  CHECKM(ctx != NULL, "cancel ctx opens");
  rv = pInit(ctx, 1, CKM_SHA256, NULL, 0);
  CHECKRV(rv, CKR_OK, "cancel digest init");
  rv = pStart(ctx, 1, FN_DIGEST, (CK_BYTE_PTR)"abc", 3, 32, 5, &job);
  CHECKRV(rv, CKR_PENDING, "cancel job starts");
  rv = pPoll(ctx, job, FN_DIGEST);
  CHECKRV(rv, CKR_PENDING, "cancel job still pending");
  rv = pCancel(ctx, job);
  CHECKRV(rv, CKR_OK, "cancel lands");
  pClose(&ctx);
  return 0;
}

struct xthread_args {
  haskoki_async_ctx_t ctx;
  haskoki_async_job_t job;
  async_data_t *res;
  int rc;
};

static void *xthread_worker(void *arg) {
  struct xthread_args *a = (struct xthread_args *)arg;
  CK_RV rv = pPoll(a->ctx, a->job, FN_DIGEST);
  if (rv != CKR_OK) {
    fprintf(stderr, "FAIL: xthread poll ready: rv=0x%lx\n",
            (unsigned long)rv);
    a->rc = 1;
    return NULL;
  }
  rv = pComplete(a->ctx, a->job, FN_DIGEST, a->res);
  if (rv != CKR_OK) {
    fprintf(stderr, "FAIL: xthread complete: rv=0x%lx\n",
            (unsigned long)rv);
    a->rc = 1;
    return NULL;
  }
  a->rc = 0;
  return NULL;
}

static int phase_async_xthread(void) {
  haskoki_async_ctx_t ctx;
  haskoki_async_job_t job = NULL;
  CK_RV rv;
  async_data_t res;
  CK_BYTE buf[64];
  struct xthread_args args;
  pthread_t worker;
  PHASE("async-xthread");
  ctx = pOpen();
  CHECKM(ctx != NULL, "xthread ctx opens");
  rv = pInit(ctx, 1, CKM_SHA256, NULL, 0);
  CHECKRV(rv, CKR_OK, "xthread digest init");
  rv = pStart(ctx, 1, FN_DIGEST, (CK_BYTE_PTR)"abc", 3, 32, 2, &job);
  CHECKRV(rv, CKR_PENDING, "xthread job starts");
  memset(&res, 0, sizeof(res));
  res.pValue = buf;
  res.ulValue = sizeof(buf);
  rv = pPoll(ctx, job, FN_DIGEST);
  CHECKRV(rv, CKR_PENDING, "xthread main poll pending");
  PHASE("async-xthread-handoff");
  args.ctx = ctx;
  args.job = job;
  args.res = &res;
  args.rc = -1;
  if (pthread_create(&worker, NULL, xthread_worker, &args) != 0)
    CHECKM(0, "worker spawns");
  if (pthread_join(worker, NULL) != 0)
    CHECKM(0, "worker joins");
  CHECKM(args.rc == 0, "worker poll+complete delivered");
  CHECKM(res.ulValue == 32 && memcmp(buf, kWant, 32) == 0,
         "xthread KAT bytes exact");
  pClose(&ctx);
  return 0;
}

static int phase_async_detach(void) {
  /* Detached handoff: start on ctx1, detach (get_id closes the
   * source op with handoff + handed-off end), close ctx1, rejoin
   * on ctx2 (fresh op: Accepted, Ready on claim win), poll and
   * complete there (Delivered + end). */
  haskoki_async_store_t store = NULL;
  haskoki_async_ctx_t ctx1 = NULL, ctx2 = NULL;
  haskoki_async_job_t job = NULL, job2 = NULL;
  CK_ULONG pid = 0, need = 0;
  CK_RV rv;
  async_data_t res;
  CK_BYTE buf[64];
  PHASE("async-detach");
  store = pStoreOpen(NULL);
  CHECKM(store != NULL, "detach store opens");
  ctx1 = pOpenOn(store);
  CHECKM(ctx1 != NULL, "detach ctx1 opens");
  rv = pInit(ctx1, 1, CKM_SHA256, NULL, 0);
  CHECKRV(rv, CKR_OK, "detach digest init");
  rv = pStart(ctx1, 1, FN_DIGEST, (CK_BYTE_PTR)"abc", 3, 32, 1, &job);
  CHECKRV(rv, CKR_PENDING, "detach job starts");
  CHECKM(job != NULL, "detach job handle");
  rv = pGetId(ctx1, job, FN_DIGEST, &pid);
  CHECKRV(rv, CKR_OK, "detach get_id lands");
  CHECKM(pid != 0, "detach persistent id minted");
  pClose(&ctx1);
  CHECKM(ctx1 == NULL, "detach ctx1 closes");
  PHASE("async-rejoin");
  ctx2 = pOpenOn(store);
  CHECKM(ctx2 != NULL, "rejoin ctx2 opens");
  rv = pInit(ctx2, 1, CKM_SHA256, NULL, 0);
  CHECKRV(rv, CKR_OK, "rejoin digest init");
  rv = pJoin(ctx2, pid, FN_DIGEST, 1, 32, &job2, &need);
  CHECKRV(rv, CKR_PENDING, "rejoin join reports pending");
  CHECKM(job2 != NULL, "rejoin job handle");
  rv = pPoll(ctx2, job2, FN_DIGEST);
  CHECKRV(rv, CKR_OK, "rejoin poll ready");
  memset(&res, 0, sizeof(res));
  res.pValue = buf;
  res.ulValue = sizeof(buf);
  rv = pComplete(ctx2, job2, FN_DIGEST, &res);
  CHECKRV(rv, CKR_OK, "rejoin complete delivers");
  CHECKM(res.ulValue == 32 && memcmp(buf, kWant, 32) == 0,
         "rejoin KAT bytes exact");
  pClose(&ctx2);
  CHECKM(ctx2 == NULL, "rejoin ctx2 closes");
  pStoreClose(&store);
  CHECKM(store == NULL, "detach store closes");
  return 0;
}

int main(int argc, char **argv) {
  void *handle;
  CK_C_GetFunctionList pGetList;
  CK_C_GetInterface pGetInterface;
  CK_INTERFACE_PTR pIf = NULL_PTR;
  CK_VERSION v;
  CK_RV rv;
  if (argc != 2) {
    fprintf(stderr, "usage: %s <libhaskoki.so>\n", argv[0]);
    return 2;
  }
  write_config();
  handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
  if (!handle) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 2; }
  pGetList = (CK_C_GetFunctionList)dlsym(handle, "C_GetFunctionList");
  pGetInterface = (CK_C_GetInterface)dlsym(handle, "C_GetInterface");
  CHECKM(pGetList && pGetInterface, "discovery symbols resolve");
  rv = pGetList(&T);
  CHECKM(rv == CKR_OK && T != NULL, "function list fetches");
  v.major = 3;
  v.minor = 2;
  rv = pGetInterface((CK_UTF8CHAR_PTR)"PKCS 11", &v, &pIf, 0);
  CHECKM(rv == CKR_OK && pIf != NULL_PTR, "GetInterface selects 3.2");
  tab32 = (CK_FUNCTION_LIST_3_2_PTR)pIf->pFunctionList;
  CHECKM(tab32 != NULL, "3.2 table fetched");
  if (async_resolve(handle)) return 1;

  PHASE("init");
  rv = T->C_Initialize(NULL);
  CHECKRV(rv, CKR_OK, "C_Initialize");
  if (open_session(&g_sess)) CHECKM(0, "session opens");

  if (phase_login()) return 1;
  if (phase_keygen()) return 1;
  if (phase_sign()) return 1;
  if (phase_verify_ok()) return 1;
  if (phase_verify_bad()) return 1;
  if (phase_verify_empty()) return 1;
  if (phase_verify_null()) return 1;
  if (phase_sign_shortbuf()) return 1;
  if (phase_shortbuf_verify()) return 1;
  if (phase_init_denied()) return 1;
  if (phase_digestkey_denied()) return 1;
  if (phase_digestkey_staged_denied()) return 1;
  if (phase_msg_sign()) return 1;
  if (phase_msg_verify_next()) return 1;
  if (phase_msg_encrypt_next()) return 1;
  if (phase_msg_abandon()) return 1;
  if (phase_msg_init_denied()) return 1;
  if (phase_msg_query_modes()) return 1;
  if (phase_msg_query_staged()) return 1;
  if (phase_msg_recall_nonfinal()) return 1;
  if (phase_sign_pss()) return 1;
  if (phase_sign_abandon()) return 1;
  if (open_session(&g_sess)) CHECKM(0, "session reopens");
  PHASE("relogin");
  rv = T->C_Login(g_sess, CKU_USER, (CK_UTF8CHAR_PTR)"1234", 4);
  CHECKRV(rv, CKR_OK, "relogin-user");
  PHASE("setup-hmac");
  if (make_hmac_key()) return 1;
  if (phase_sign_abandon_nullguard()) return 1;
  if (phase_sign_abandon_oversize()) return 1;

  if (phase_digest()) return 1;
  if (phase_digest_abandon_key()) return 1;
  if (phase_derive()) return 1;
  if (phase_derive_dh()) return 1;
  if (phase_wrap()) return 1;
  if (phase_wrap_oaep()) return 1;
  if (phase_wrap_query_denied()) return 1;
  if (phase_encaps_query_denied()) return 1;
  if (phase_eddsa()) return 1;
  if (phase_kem()) return 1;
  if (phase_logout_staged()) return 1;

  PHASE("teardown");
  rv = T->C_CloseSession(g_sess);
  CHECKRV(rv, CKR_OK, "close");
  rv = T->C_Finalize(NULL);
  CHECKRV(rv, CKR_OK, "finalize");

  if (phase_async_deliver()) return 1;
  if (phase_async_cancel()) return 1;
  if (phase_async_xthread()) return 1;
  if (phase_async_detach()) return 1;

  PHASE("done");
  return 0;
}
