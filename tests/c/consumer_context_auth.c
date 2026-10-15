/* tests/c/consumer_context_auth.c — WP02b: per-use context-specific
 * authentication (CKA_ALWAYS_AUTHENTICATE / CKU_CONTEXT_SPECIFIC) matrix
 * through the public C ABI.
 *
 * The implemented policy (core/Haskoki/Operation.hs gateDataCall,
 * grantAdmitsPending; core/Haskoki/Session.hs loginAttempt;
 * core/Haskoki/Transition.hs planLogin/planSessionCancel/
 * invalidateStaleGrant/logoutTransition; ffi terminateSlotDelta) is
 * pinned at the model level by tests/model/OperationSpec.hs
 * (caseGate, caseHasAuthPendingOp, caseSecondPendingInitRefused,
 * caseCancelDropsPendingAuth, caseGrantTwoKey, casePremature) and
 * tests/model/SessionSpec.hs (caseContextGrant, caseContextEligible,
 * casePinLockout). This consumer qualifies the same contract end to end
 * with real marked-key DATA USE, never stopping at the context login:
 *
 *   C1  marked one-shot sign succeeds after C_Login(CKU_CONTEXT_SPECIFIC)
 *       (RFC 4231 test case 6 HMAC-SHA256 known answer); the op ends.
 *   C2  replay: a fresh init of the same key without a new context login
 *       denies CKR_USER_NOT_LOGGED_IN and terminates (no output); a late
 *       grant finds nothing pending (CKR_OPERATION_NOT_INITIALIZED,
 *       refused before PIN evaluation: no attempt consumed).
 *   C3  next key: a grant spent on key A never authorizes key B; B then
 *       succeeds under its own grant (bytes = unmarked twin reference).
 *   C4  multipart: the grant spends on the first SignUpdate; later
 *       updates and the final proceed; bytes are the known answer.
 *   C5  query (NULL output) and short buffer (CKR_BUFFER_TOO_SMALL) keep
 *       the authorization for the retry, one-shot and final; the spent
 *       grant does not survive into the next operation.
 *   C6  two-session isolation: an idle session takes no grant while a
 *       sibling holds the pending op; a grant on session 1 never
 *       authorizes session 2's pending op on the same key.
 *   C7  premature use: a held grant does not spend on a plain digest
 *       (denied, not consumed, digest slot survives); the marked op
 *       then succeeds and the digest completes.
 *   C8  while a grant is outstanding a second marked init refuses
 *       CKR_OPERATION_ACTIVE (verify and sign re-init) without
 *       disturbing the bound op (bytes prove key A, not B).
 *   C9  ambiguity: two pending marked ops take no grant.
 *   C10 terminal failure (NULL-argument data call) retires the grant
 *       (DIRECT-ONLY, invent:-scoped: the proxy shim normalizes NULL
 *       input, so the failing call never reaches the module).
 *   C11 C_SessionCancel: an unrelated mask keeps the grant; the sign
 *       mask (and the zero mask) retire it.
 *   C12 a context-PIN miss bumps the user counter without granting;
 *       the correct context PIN then grants and clears the counter.
 *   C13 context-PIN lockout (LAST: the token is this process's fresh
 *       in-memory token directly, a fresh per-scenario daemon behind the
 *       proxy): the locking miss performs the full logout transition —
 *       every session public, pending marked ops on BOTH sessions
 *       retired, private session keys destroyed, user/context logins
 *       PIN_LOCKED — then the SO restores the user PIN (C_InitPIN, the
 *       policy's recovery path) and the per-use contract works again.
 *
 * Every case asserts the exact CKR, the exact output bytes on success,
 * and an untouched output canary on every refusal.
 *
 * Standalone C consumer (non-Haskell executable): dlopen()s the built
 * libhaskoki shared module (or the pkcs11-proxy-ng shim in proxy
 * topology) and drives it through the pinned 3.2 headers. The config is
 * hermetic (single default token, memory storage, real OpenSSL engine),
 * the same serving shape as the proxy parity backend.
 *
 * This TU deliberately includes ONLY the pinned vendor headers; it never
 * consumes provider-generated artifacts (enforced by the driver script's
 * independence guard).
 *
 * Compile with -Ispec/vendor. Part of scripts/test-consumers.sh and
 * scripts/test-proxy-parity.sh.
 * Usage: consumer_context_auth <path-to-libhaskoki.so>
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
static int g_checks = 0;
static int g_isProxy = 0;
/* Line prefix: "" for forwarded-call lines (diffed by the proxy parity
 * driver); "invent: " inside the DIRECT-ONLY leg (diff-excluded,
 * asserted strictly direct, skipped loud behind the proxy). */
static const char *g_pfx = "";

#define CHECK(cond, ...)                                                   \
  do {                                                                     \
    g_checks++;                                                            \
    if (!(cond)) {                                                         \
      printf("%sFAIL [%s:%d]: ", g_pfx, __FILE__, __LINE__);               \
      printf(__VA_ARGS__);                                                 \
      printf("\n");                                                        \
      g_failures++;                                                        \
    } else {                                                               \
      printf("%sok: ", g_pfx);                                             \
      printf(__VA_ARGS__);                                                 \
      printf("\n");                                                        \
    }                                                                      \
  } while (0)

/* Expect an exact CKR; the message carries the observed code on failure. */
#define EXPECT_RV(call, want, msg)                                         \
  do {                                                                     \
    CK_RV rv_ = (call);                                                    \
    CHECK(rv_ == (CK_RV)(want), "%s (want 0x%lx, got 0x%lx)", msg,         \
          (unsigned long)(want), (unsigned long)rv_);                      \
  } while (0)

static CK_FUNCTION_LIST_3_2_PTR F = NULL_PTR;
static CK_SLOT_ID g_slot = 0;
static char g_cfg_path[256];

static const CK_UTF8CHAR kUserPin[] = "1234";
static const CK_UTF8CHAR kSoPin[] = "5678";
static const CK_UTF8CHAR kBadPin[] = "9999";

/* RFC 4231 test case 6: HMAC-SHA-256, 131-byte 0xaa key. */
static const char kMsgA[] =
    "Test Using Larger Than Block-Size Key - Hash Key First";
static const CK_BYTE kMacA[32] = {
    0x60, 0xe4, 0x31, 0x59, 0x1e, 0xe0, 0xb6, 0x7f, 0x0d, 0x8a, 0x26,
    0xaa, 0xcb, 0xf5, 0xb7, 0x7f, 0x8e, 0x0b, 0xc6, 0x21, 0x37, 0x28,
    0xc5, 0x14, 0x05, 0x46, 0x04, 0x0f, 0x0e, 0xe3, 0x7f, 0x54};
/* FIPS 180-2 SHA-256("abc"). */
static const CK_BYTE kSha256Abc[32] = {
    0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40,
    0xde, 0x5d, 0xae, 0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17,
    0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad};

static CK_BYTE g_keyA[131];
static CK_BYTE g_keyB[32];
static CK_BYTE g_macB[32]; /* reference via the unmarked twin of B */

#define CANARY 0xEE
#define SIG_CAP 64

static void fill(CK_BYTE *b, size_t n) { memset(b, CANARY, n); }

static int untouched(const CK_BYTE *b, size_t n) {
  size_t i;
  for (i = 0; i < n; i++) {
    if (b[i] != CANARY) {
      return 0;
    }
  }
  return 1;
}

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
  char tmpl[] = "/tmp/haskoki-ctxauth-XXXXXX";
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

static CK_SESSION_HANDLE open_rw(const char *tag) {
  CK_SESSION_HANDLE s = 0;
  CK_RV rv = F->C_OpenSession(g_slot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                              NULL_PTR, NULL_PTR, &s);
  CHECK(rv == CKR_OK && s != 0, "%s: RW session opens", tag);
  return s;
}

static CK_RV ctx_login(CK_SESSION_HANDLE s, const CK_UTF8CHAR *pin) {
  return F->C_Login(s, CKU_CONTEXT_SPECIFIC, (CK_UTF8CHAR_PTR)pin,
                    (CK_ULONG)strlen((const char *)pin));
}

/* Private session HMAC key; marked = CKA_ALWAYS_AUTHENTICATE. */
static CK_OBJECT_HANDLE make_key(CK_SESSION_HANDLE s, const CK_BYTE *val,
                                 CK_ULONG len, CK_BBOOL marked,
                                 const char *tag) {
  CK_OBJECT_CLASS cls = CKO_SECRET_KEY;
  CK_KEY_TYPE kt = CKK_GENERIC_SECRET;
  CK_BBOOL yes = CK_TRUE, no = CK_FALSE;
  CK_OBJECT_HANDLE h = 0;
  CK_ATTRIBUTE t[] = {
      {CKA_CLASS, &cls, sizeof(cls)},
      {CKA_KEY_TYPE, &kt, sizeof(kt)},
      {CKA_VALUE, (CK_VOID_PTR)val, len},
      {CKA_TOKEN, &no, sizeof(no)},
      {CKA_PRIVATE, &yes, sizeof(yes)},
      {CKA_SIGN, &yes, sizeof(yes)},
      {CKA_VERIFY, &yes, sizeof(yes)},
      {CKA_ALWAYS_AUTHENTICATE, &marked, sizeof(marked)},
  };
  CK_RV rv = F->C_CreateObject(s, t, sizeof(t) / sizeof(t[0]), &h);
  CHECK(rv == CKR_OK && h != 0, "%s: key created", tag);
  return h;
}

static CK_RV sign_init(CK_SESSION_HANDLE s, CK_OBJECT_HANDLE k) {
  CK_MECHANISM m = {CKM_SHA256_HMAC, NULL_PTR, 0};
  return F->C_SignInit(s, &m, k);
}

static CK_RV verify_init(CK_SESSION_HANDLE s, CK_OBJECT_HANDLE k) {
  CK_MECHANISM m = {CKM_SHA256_HMAC, NULL_PTR, 0};
  return F->C_VerifyInit(s, &m, k);
}

static CK_RV sign_msg_a(CK_SESSION_HANDLE s, CK_BYTE *out, CK_ULONG *len) {
  return F->C_Sign(s, (CK_BYTE_PTR)kMsgA, (CK_ULONG)(sizeof(kMsgA) - 1), out,
                   len);
}

/* A data call that must refuse with `want` and leave the output canary. */
static void sign_refused(CK_SESSION_HANDLE s, CK_RV want, const char *tag) {
  CK_BYTE out[SIG_CAP];
  CK_ULONG len = sizeof(out);
  CK_RV rv;
  fill(out, sizeof(out));
  rv = sign_msg_a(s, out, &len);
  CHECK(rv == want, "%s: C_Sign refuses (want 0x%lx, got 0x%lx)", tag,
        (unsigned long)want, (unsigned long)rv);
  CHECK(untouched(out, sizeof(out)), "%s: no signature bytes written", tag);
}

/* A full one-shot sign that must succeed with exactly `expect`. */
static void sign_exact(CK_SESSION_HANDLE s, const CK_BYTE *expect,
                       const char *tag) {
  CK_BYTE out[SIG_CAP];
  CK_ULONG len = sizeof(out);
  CK_RV rv;
  fill(out, sizeof(out));
  rv = sign_msg_a(s, out, &len);
  CHECK(rv == CKR_OK, "%s: C_Sign ok (got 0x%lx)", tag, (unsigned long)rv);
  CHECK(len == 32 && memcmp(out, expect, 32) == 0,
        "%s: signature bytes exact", tag);
  CHECK(untouched(out + 32, sizeof(out) - 32), "%s: no write past length",
        tag);
}

static CK_FLAGS token_flags(void) {
  CK_TOKEN_INFO ti;
  memset(&ti, 0, sizeof(ti));
  if (F->C_GetTokenInfo(g_slot, &ti) != CKR_OK) {
    return (CK_FLAGS)~(CK_FLAGS)0;
  }
  return ti.flags;
}

static CK_STATE session_state(CK_SESSION_HANDLE s) {
  CK_SESSION_INFO si;
  memset(&si, 0, sizeof(si));
  if (F->C_GetSessionInfo(s, &si) != CKR_OK) {
    return (CK_STATE)~(CK_STATE)0;
  }
  return si.state;
}

#define PIN_FLAGS                                                          \
  (CKF_USER_PIN_COUNT_LOW | CKF_USER_PIN_FINAL_TRY | CKF_USER_PIN_LOCKED)

int main(int argc, char **argv) {
  void *dl;
  CK_C_GetInterface pGetInterface;
  CK_INTERFACE_PTR pIf = NULL_PTR;
  CK_VERSION v;
  CK_RV rv;
  const char *topo;
  CK_SLOT_ID slots[8];
  CK_ULONG nslots = 8;
  CK_SESSION_HANDLE s1 = 0, s2 = 0;
  CK_OBJECT_HANDLE kA = 0, kB = 0, kBref = 0;
  size_t i;

  if (argc != 2) {
    fprintf(stderr, "usage: %s <libhaskoki.so>\n", argv[0]);
    return 2;
  }
  topo = getenv("HASKOKI_CONSUMER_TOPOLOGY");
  g_isProxy = topo && strcmp(topo, "proxy") == 0;
  printf("topology: %s\n", g_isProxy ? "proxy" : "direct");
  for (i = 0; i < sizeof(g_keyA); i++) {
    g_keyA[i] = 0xaa;
  }
  for (i = 0; i < sizeof(g_keyB); i++) {
    g_keyB[i] = (CK_BYTE)(0x5b ^ i);
  }
  write_config();
  dl = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
  if (!dl) {
    fprintf(stderr, "dlopen failed: %s\n", dlerror());
    unlink(g_cfg_path);
    return 2;
  }
  pGetInterface = (CK_C_GetInterface)dlsym(dl, "C_GetInterface");
  CHECK(pGetInterface != NULL, "C_GetInterface resolves");
  if (!pGetInterface) {
    unlink(g_cfg_path);
    return 2;
  }
  v.major = 3;
  v.minor = 2;
  rv = pGetInterface((CK_UTF8CHAR_PTR) "PKCS 11", &v, &pIf, 0);
  CHECK(rv == CKR_OK && pIf != NULL_PTR, "GetInterface selects 3.2");
  if (rv != CKR_OK || pIf == NULL_PTR) {
    unlink(g_cfg_path);
    return 2;
  }
  F = (CK_FUNCTION_LIST_3_2_PTR)pIf->pFunctionList;
  EXPECT_RV(F->C_Initialize(NULL_PTR), CKR_OK, "C_Initialize");
  rv = F->C_GetSlotList(CK_TRUE, slots, &nslots);
  CHECK(rv == CKR_OK && nslots >= 1, "token slot present");
  if (rv != CKR_OK || nslots < 1) {
    unlink(g_cfg_path);
    return 1;
  }
  g_slot = slots[0];

  /* ---- setup: user login, two marked keys, B's unmarked twin ---- */
  s1 = open_rw("setup");
  EXPECT_RV(ctx_login(s1, kUserPin), CKR_USER_NOT_LOGGED_IN,
            "setup: context login needs a user login");
  EXPECT_RV(F->C_Login(s1, CKU_USER, (CK_UTF8CHAR_PTR)kUserPin, 4), CKR_OK,
            "setup: user login");
  CHECK((token_flags() & PIN_FLAGS) == 0, "setup: no user PIN flags");
  kA = make_key(s1, g_keyA, sizeof(g_keyA), CK_TRUE, "setup A (marked)");
  kB = make_key(s1, g_keyB, sizeof(g_keyB), CK_TRUE, "setup B (marked)");
  kBref = make_key(s1, g_keyB, sizeof(g_keyB), CK_FALSE,
                   "setup B twin (unmarked)");
  {
    CK_ULONG len = sizeof(g_macB);
    EXPECT_RV(sign_init(s1, kBref), CKR_OK, "setup: unmarked twin init");
    rv = sign_msg_a(s1, g_macB, &len);
    CHECK(rv == CKR_OK && len == 32,
          "setup: unmarked key signs without any context login");
    CHECK(memcmp(g_macB, kMacA, 32) != 0,
          "setup: B reference differs from A known answer");
  }
  EXPECT_RV(ctx_login(s1, kUserPin), CKR_OPERATION_NOT_INITIALIZED,
            "setup: idle session takes no context grant");

  /* ---- C1: marked one-shot data use after the context login ---- */
  EXPECT_RV(sign_init(s1, kA), CKR_OK, "C1: marked sign init under user");
  EXPECT_RV(ctx_login(s1, kUserPin), CKR_OK, "C1: context login grants");
  CHECK(session_state(s1) == CKS_RW_USER_FUNCTIONS,
        "C1: session shows user functions under the grant");
  sign_exact(s1, kMacA, "C1 (RFC 4231 TC6)");
  sign_refused(s1, CKR_OPERATION_NOT_INITIALIZED, "C1 after completion");

  /* ---- C2: replay of the same key needs a new context login ---- */
  EXPECT_RV(sign_init(s1, kA), CKR_OK, "C2: re-init same marked key");
  sign_refused(s1, CKR_USER_NOT_LOGGED_IN, "C2 replay without grant");
  sign_refused(s1, CKR_OPERATION_NOT_INITIALIZED,
               "C2 grantless first use terminated the op");
  EXPECT_RV(ctx_login(s1, kBadPin), CKR_OPERATION_NOT_INITIALIZED,
            "C2: late grant refuses before PIN evaluation");
  CHECK((token_flags() & PIN_FLAGS) == 0,
        "C2: refused late grant consumed no attempt");
  EXPECT_RV(ctx_login(s1, kUserPin), CKR_OPERATION_NOT_INITIALIZED,
            "C2: late correct grant finds nothing pending");
  sign_refused(s1, CKR_OPERATION_NOT_INITIALIZED, "C2 after late grant");

  /* ---- C3: a grant spent on key A never authorizes key B ---- */
  EXPECT_RV(sign_init(s1, kA), CKR_OK, "C3: init A");
  EXPECT_RV(ctx_login(s1, kUserPin), CKR_OK, "C3: grant for A");
  sign_exact(s1, kMacA, "C3 A");
  EXPECT_RV(sign_init(s1, kB), CKR_OK, "C3: init B after A's grant spent");
  sign_refused(s1, CKR_USER_NOT_LOGGED_IN, "C3 B under A's spent grant");
  sign_refused(s1, CKR_OPERATION_NOT_INITIALIZED, "C3 B terminated");
  EXPECT_RV(sign_init(s1, kB), CKR_OK, "C3: re-init B");
  EXPECT_RV(ctx_login(s1, kUserPin), CKR_OK, "C3: grant for B");
  sign_exact(s1, g_macB, "C3 B under its own grant");

  /* ---- C4: multipart; the grant spends on the first update ---- */
  {
    CK_BYTE out[SIG_CAP];
    CK_ULONG len = sizeof(out);
    const CK_ULONG cut = 20;
    EXPECT_RV(sign_init(s1, kA), CKR_OK, "C4: init A");
    EXPECT_RV(ctx_login(s1, kUserPin), CKR_OK, "C4: grant");
    EXPECT_RV(F->C_SignUpdate(s1, (CK_BYTE_PTR)kMsgA, cut), CKR_OK,
              "C4: first update spends the grant");
    EXPECT_RV(F->C_SignUpdate(s1, (CK_BYTE_PTR)kMsgA + cut,
                              (CK_ULONG)(sizeof(kMsgA) - 1) - cut),
              CKR_OK, "C4: second update proceeds on the satisfied op");
    fill(out, sizeof(out));
    EXPECT_RV(F->C_SignFinal(s1, out, &len), CKR_OK, "C4: final");
    CHECK(len == 32 && memcmp(out, kMacA, 32) == 0,
          "C4: multipart bytes equal the known answer");
    EXPECT_RV(sign_init(s1, kA), CKR_OK, "C4: next op init");
    EXPECT_RV(F->C_SignUpdate(s1, (CK_BYTE_PTR)kMsgA, cut),
              CKR_USER_NOT_LOGGED_IN, "C4: next multipart needs a new grant");
    EXPECT_RV(F->C_SignUpdate(s1, (CK_BYTE_PTR)kMsgA, cut),
              CKR_OPERATION_NOT_INITIALIZED, "C4: grantless update terminated");
  }

  /* ---- C5: query and short buffer retain the authorization ---- */
  {
    CK_BYTE out[SIG_CAP];
    CK_ULONG len;
    EXPECT_RV(sign_init(s1, kA), CKR_OK, "C5: init A (one-shot)");
    EXPECT_RV(ctx_login(s1, kUserPin), CKR_OK, "C5: grant");
    len = 0;
    rv = sign_msg_a(s1, NULL_PTR, &len);
    CHECK(rv == CKR_OK && len == 32,
          "C5: NULL-output query reports 32 (rv 0x%lx len %lu)",
          (unsigned long)rv, (unsigned long)len);
    fill(out, sizeof(out));
    len = 8;
    rv = sign_msg_a(s1, out, &len);
    CHECK(rv == CKR_BUFFER_TOO_SMALL && len == 32,
          "C5: short buffer is BUFFER_TOO_SMALL with length 32 "
          "(rv 0x%lx len %lu)",
          (unsigned long)rv, (unsigned long)len);
    CHECK(untouched(out, sizeof(out)), "C5: short buffer left untouched");
    sign_exact(s1, kMacA, "C5 retry after query+short (no new login)");
    sign_refused(s1, CKR_OPERATION_NOT_INITIALIZED, "C5 one-shot finished");

    EXPECT_RV(sign_init(s1, kA), CKR_OK, "C5: init A (multipart final)");
    EXPECT_RV(ctx_login(s1, kUserPin), CKR_OK, "C5: grant (final)");
    EXPECT_RV(F->C_SignUpdate(s1, (CK_BYTE_PTR)kMsgA,
                              (CK_ULONG)(sizeof(kMsgA) - 1)),
              CKR_OK, "C5: update spends the grant");
    len = 0;
    rv = F->C_SignFinal(s1, NULL_PTR, &len);
    CHECK(rv == CKR_OK && len == 32, "C5: final query reports 32");
    fill(out, sizeof(out));
    len = 16;
    rv = F->C_SignFinal(s1, out, &len);
    CHECK(rv == CKR_BUFFER_TOO_SMALL && len == 32,
          "C5: short final is BUFFER_TOO_SMALL with length 32");
    CHECK(untouched(out, sizeof(out)), "C5: short final left untouched");
    fill(out, sizeof(out));
    len = sizeof(out);
    EXPECT_RV(F->C_SignFinal(s1, out, &len), CKR_OK, "C5: final retry");
    CHECK(len == 32 && memcmp(out, kMacA, 32) == 0,
          "C5: final retry bytes exact");

    /* The query spent the grant: it does not carry to the next op. */
    EXPECT_RV(sign_init(s1, kA), CKR_OK, "C5: next op init");
    len = 0;
    rv = sign_msg_a(s1, NULL_PTR, &len);
    CHECK(rv == CKR_USER_NOT_LOGGED_IN,
          "C5: next op's query needs a new grant (got 0x%lx)",
          (unsigned long)rv);
    sign_refused(s1, CKR_OPERATION_NOT_INITIALIZED,
                 "C5 grantless query terminated");
  }

  /* ---- C6: two-session isolation (same key, same token login) ---- */
  s2 = open_rw("C6");
  CHECK(session_state(s2) == CKS_RW_USER_FUNCTIONS,
        "C6: second session observes the token-wide user login");
  EXPECT_RV(sign_init(s1, kA), CKR_OK, "C6: session 1 pending");
  EXPECT_RV(ctx_login(s2, kUserPin), CKR_OPERATION_NOT_INITIALIZED,
            "C6: idle session 2 takes no grant for session 1's op");
  EXPECT_RV(sign_init(s2, kA), CKR_OK, "C6: session 2 pending");
  EXPECT_RV(ctx_login(s1, kUserPin), CKR_OK, "C6: grant on session 1");
  sign_refused(s2, CKR_USER_NOT_LOGGED_IN, "C6 session 2 under s1 grant");
  sign_refused(s2, CKR_OPERATION_NOT_INITIALIZED, "C6 session 2 terminated");
  sign_exact(s1, kMacA, "C6 session 1 spends its own grant");
  EXPECT_RV(sign_init(s2, kA), CKR_OK, "C6: session 2 re-init");
  EXPECT_RV(ctx_login(s2, kUserPin), CKR_OK, "C6: grant on session 2");
  sign_exact(s2, kMacA, "C6 session 2 under its own grant");

  /* ---- C7: premature use on a plain digest does not spend ---- */
  {
    CK_MECHANISM dm = {CKM_SHA256, NULL_PTR, 0};
    CK_BYTE dg[SIG_CAP];
    CK_ULONG dlen = sizeof(dg);
    EXPECT_RV(sign_init(s1, kA), CKR_OK, "C7: init A");
    EXPECT_RV(ctx_login(s1, kUserPin), CKR_OK, "C7: grant");
    EXPECT_RV(F->C_DigestInit(s1, &dm), CKR_OK,
              "C7: plain digest init admits under the grant");
    fill(dg, sizeof(dg));
    rv = F->C_Digest(s1, (CK_BYTE_PTR) "abc", 3, dg, &dlen);
    CHECK(rv == CKR_USER_NOT_LOGGED_IN,
          "C7: grant does not spend on the plain digest (got 0x%lx)",
          (unsigned long)rv);
    CHECK(untouched(dg, sizeof(dg)), "C7: no digest bytes written");
    sign_exact(s1, kMacA, "C7 grant survived premature use");
    fill(dg, sizeof(dg));
    dlen = sizeof(dg);
    rv = F->C_Digest(s1, (CK_BYTE_PTR) "abc", 3, dg, &dlen);
    CHECK(rv == CKR_OK && dlen == 32 && memcmp(dg, kSha256Abc, 32) == 0,
          "C7: digest slot survived and completes exactly");
  }

  /* ---- C8: second marked init refuses while a grant is held ---- */
  EXPECT_RV(sign_init(s1, kA), CKR_OK, "C8: init A");
  EXPECT_RV(ctx_login(s1, kUserPin), CKR_OK, "C8: grant");
  EXPECT_RV(verify_init(s1, kA), CKR_OPERATION_ACTIVE,
            "C8: second marked (verify) init refuses under the grant");
  EXPECT_RV(sign_init(s1, kB), CKR_OPERATION_ACTIVE,
            "C8: sign re-init refuses while the bound op is live");
  sign_exact(s1, kMacA, "C8 bound op intact (key A bytes, not B)");

  /* ---- C9: two pending marked ops take no grant ---- */
  {
    CK_BYTE out[SIG_CAP];
    EXPECT_RV(sign_init(s1, kA), CKR_OK, "C9: sign A pending");
    EXPECT_RV(verify_init(s1, kA), CKR_OK,
              "C9: ungranted pending pair admits");
    EXPECT_RV(ctx_login(s1, kUserPin), CKR_OPERATION_NOT_INITIALIZED,
              "C9: ambiguous pair takes no grant");
    sign_refused(s1, CKR_USER_NOT_LOGGED_IN, "C9 sign side grantless");
    memcpy(out, kMacA, 32);
    EXPECT_RV(F->C_Verify(s1, (CK_BYTE_PTR)kMsgA,
                          (CK_ULONG)(sizeof(kMsgA) - 1), out, 32),
              CKR_USER_NOT_LOGGED_IN, "C9: verify side grantless");
    EXPECT_RV(F->C_Verify(s1, (CK_BYTE_PTR)kMsgA,
                          (CK_ULONG)(sizeof(kMsgA) - 1), out, 32),
              CKR_OPERATION_NOT_INITIALIZED, "C9: verify side terminated");
  }

  /* ---- C10: a terminal failure retires the unspent grant ----
   * DIRECT-ONLY (invent:-scoped). Every pre-consumption terminal
   * failure of a pending marked op is a C-ABI argument refusal
   * (refuse_null_arg / refuseArgsTerminate -> terminateSlotDelta):
   * planner-side failures all sit after gateDataCall, where the grant
   * is already spent. The pinned pkcs11-proxy-ng shim normalizes NULL
   * input before forwarding (observed: C_Sign(NULL, 5, ...) returns
   * CKR_OK with a 32-byte signature behind the shim), so the failing
   * call never reaches the module and the leg has nothing to compare
   * proxied. */
  if (g_isProxy) {
    printf("invent: C10 skipped: DIRECT-ONLY (shim normalizes NULL input; "
           "the failing call never reaches the module)\n");
  } else {
    CK_BYTE out[SIG_CAP];
    CK_ULONG len = sizeof(out);
    g_pfx = "invent: ";
    EXPECT_RV(sign_init(s1, kA), CKR_OK, "C10: init A");
    EXPECT_RV(ctx_login(s1, kUserPin), CKR_OK, "C10: grant");
    fill(out, sizeof(out));
    rv = F->C_Sign(s1, NULL_PTR, 5, out, &len);
    CHECK(rv == CKR_ARGUMENTS_BAD,
          "C10: NULL data with length is ARGUMENTS_BAD (got 0x%lx)",
          (unsigned long)rv);
    CHECK(untouched(out, sizeof(out)), "C10: no bytes on the failure");
    /* No intermediate data call: a probe on the dead slot would retire
     * a stranded grant on the step path and mask the terminal-failure
     * retirement under test. The fresh init admitting (instead of
     * OPERATION_ACTIVE) is itself the proof the failure terminated. */
    EXPECT_RV(sign_init(s1, kA), CKR_OK,
              "C10: failure terminated the op (fresh init admits)");
    sign_refused(s1, CKR_USER_NOT_LOGGED_IN,
                 "C10 retired grant does not authorize the fresh op");
    sign_refused(s1, CKR_OPERATION_NOT_INITIALIZED,
                 "C10 grantless fresh op terminated");
    g_pfx = "";
  }

  /* ---- C11: C_SessionCancel keeps or retires the grant by mask ---- */
  if (F->C_SessionCancel == NULL) {
    printf("invent: C11 skipped: C_SessionCancel slot is NULL (%s)\n",
           g_isProxy ? "proxy shim" : "direct");
    CHECK(g_isProxy, "C11: only the proxy shim may omit C_SessionCancel");
  } else {
    EXPECT_RV(sign_init(s1, kA), CKR_OK, "C11: init A");
    EXPECT_RV(ctx_login(s1, kUserPin), CKR_OK, "C11: grant");
    EXPECT_RV(F->C_SessionCancel(s1, CKF_DECRYPT), CKR_OK,
              "C11: unrelated-mask cancel");
    sign_exact(s1, kMacA, "C11 unrelated cancel keeps the grant");

    EXPECT_RV(sign_init(s1, kA), CKR_OK, "C11: init A again");
    EXPECT_RV(ctx_login(s1, kUserPin), CKR_OK, "C11: grant again");
    EXPECT_RV(F->C_SessionCancel(s1, CKF_SIGN), CKR_OK,
              "C11: sign-mask cancel");
    /* As in C10: no probe between cancel and re-init (a data call on
     * the empty slot would retire a stranded grant on the step path). */
    EXPECT_RV(sign_init(s1, kA), CKR_OK,
              "C11: cancelled op gone (re-init admits)");
    sign_refused(s1, CKR_USER_NOT_LOGGED_IN,
                 "C11 cancelled grant does not authorize the re-init");
    sign_refused(s1, CKR_OPERATION_NOT_INITIALIZED,
                 "C11 grantless re-init terminated");

    EXPECT_RV(sign_init(s1, kA), CKR_OK, "C11: init A (zero mask)");
    EXPECT_RV(ctx_login(s1, kUserPin), CKR_OK, "C11: grant (zero mask)");
    EXPECT_RV(F->C_SessionCancel(s1, 0), CKR_OK, "C11: zero-mask cancel");
    EXPECT_RV(sign_init(s1, kA), CKR_OK, "C11: re-init after zero mask");
    sign_refused(s1, CKR_USER_NOT_LOGGED_IN,
                 "C11 zero-mask cancel retired the grant");
    sign_refused(s1, CKR_OPERATION_NOT_INITIALIZED,
                 "C11 zero-mask grantless re-init terminated");
  }

  /* ---- C12: a context-PIN miss neither grants nor ends the op ---- */
  EXPECT_RV(sign_init(s1, kA), CKR_OK, "C12: init A");
  EXPECT_RV(ctx_login(s1, kBadPin), CKR_PIN_INCORRECT,
            "C12: wrong context PIN");
  CHECK((token_flags() & PIN_FLAGS) == CKF_USER_PIN_COUNT_LOW,
        "C12: the miss counts against the user PIN");
  EXPECT_RV(ctx_login(s1, kUserPin), CKR_OK,
            "C12: correct context PIN grants for the still-pending op");
  CHECK((token_flags() & PIN_FLAGS) == 0, "C12: grant clears the counter");
  sign_exact(s1, kMacA, "C12 after miss then grant");

  /* ---- C13: context-PIN lockout retires everything (runs LAST) ---- */
  {
    CK_BYTE out[SIG_CAP];
    CK_ULONG len = sizeof(out);
    EXPECT_RV(sign_init(s1, kA), CKR_OK, "C13: session 1 pending");
    EXPECT_RV(sign_init(s2, kB), CKR_OK, "C13: session 2 pending");
    EXPECT_RV(ctx_login(s1, kBadPin), CKR_PIN_INCORRECT, "C13: miss 1");
    CHECK((token_flags() & PIN_FLAGS) == CKF_USER_PIN_COUNT_LOW,
          "C13: count low after miss 1");
    EXPECT_RV(ctx_login(s1, kBadPin), CKR_PIN_INCORRECT, "C13: miss 2");
    CHECK((token_flags() & PIN_FLAGS) ==
              (CKF_USER_PIN_COUNT_LOW | CKF_USER_PIN_FINAL_TRY),
          "C13: final try after miss 2");
    EXPECT_RV(ctx_login(s1, kBadPin), CKR_PIN_LOCKED,
              "C13: miss 3 locks the user PIN");
    CHECK((token_flags() & CKF_USER_PIN_LOCKED) != 0,
          "C13: token reports the user PIN locked");
    CHECK(session_state(s1) == CKS_RW_PUBLIC_SESSION,
          "C13: session 1 returned to public");
    CHECK(session_state(s2) == CKS_RW_PUBLIC_SESSION,
          "C13: session 2 returned to public");
    sign_refused(s1, CKR_OPERATION_NOT_INITIALIZED,
                 "C13 session 1 pending op retired");
    sign_refused(s2, CKR_OPERATION_NOT_INITIALIZED,
                 "C13 session 2 pending op retired");
    EXPECT_RV(F->C_Logout(s1), CKR_USER_NOT_LOGGED_IN,
              "C13: lockout already logged the token out");
    EXPECT_RV(ctx_login(s1, kUserPin), CKR_PIN_LOCKED,
              "C13: correct context PIN stays locked");
    EXPECT_RV(F->C_Login(s1, CKU_USER, (CK_UTF8CHAR_PTR)kUserPin, 4),
              CKR_PIN_LOCKED, "C13: correct user PIN stays locked");
    /* Logout destroys private session objects and stales their handles;
     * init refuses a dead handle with OBJECT_HANDLE_INVALID (the code
     * consumer_so_isolation pins for an invisible key). */
    EXPECT_RV(sign_init(s1, kA), CKR_OBJECT_HANDLE_INVALID,
              "C13: private session key gone after the lockout logout");
    fill(out, sizeof(out));
    rv = sign_msg_a(s1, out, &len);
    CHECK(rv == CKR_OPERATION_NOT_INITIALIZED && untouched(out, sizeof(out)),
          "C13: nothing signs after the lockout");

    /* Recovery path the policy allows: SO C_InitPIN clears the lock. */
    EXPECT_RV(F->C_Login(s1, CKU_SO, (CK_UTF8CHAR_PTR)kSoPin, 4), CKR_OK,
              "C13: SO login for recovery");
    EXPECT_RV(F->C_InitPIN(s1, (CK_UTF8CHAR_PTR)kUserPin, 4), CKR_OK,
              "C13: SO re-initializes the user PIN");
    CHECK((token_flags() & PIN_FLAGS) == 0, "C13: lock cleared");
    EXPECT_RV(F->C_Logout(s1), CKR_OK, "C13: SO logout");
    EXPECT_RV(F->C_Login(s1, CKU_USER, (CK_UTF8CHAR_PTR)kUserPin, 4), CKR_OK,
              "C13: user login after recovery");
    kA = make_key(s1, g_keyA, sizeof(g_keyA), CK_TRUE, "C13 fresh A");
    EXPECT_RV(sign_init(s1, kA), CKR_OK, "C13: fresh marked init");
    sign_refused(s1, CKR_USER_NOT_LOGGED_IN,
                 "C13 per-use contract after recovery: no grant");
    EXPECT_RV(sign_init(s1, kA), CKR_OK, "C13: fresh marked re-init");
    EXPECT_RV(ctx_login(s1, kUserPin), CKR_OK, "C13: grant after recovery");
    sign_exact(s1, kMacA, "C13 per-use contract after recovery");
    EXPECT_RV(F->C_Logout(s1), CKR_OK, "C13: final logout");
  }

  EXPECT_RV(F->C_CloseSession(s2), CKR_OK, "close session 2");
  EXPECT_RV(F->C_CloseSession(s1), CKR_OK, "close session 1");
  EXPECT_RV(F->C_Finalize(NULL_PTR), CKR_OK, "C_Finalize");
  unlink(g_cfg_path);
  /* Check totals differ by topology (the DIRECT-ONLY leg): diff-excluded. */
  printf("topology: context-auth: %d checks, %d failures\n", g_checks,
         g_failures);
  if (g_failures) {
    printf("FAIL: %d check(s) failed\n", g_failures);
    return 1;
  }
  printf("PASS: context-auth consumer\n");
  return 0;
}
