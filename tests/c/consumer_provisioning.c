/* tests/c/consumer_provisioning.c — token-provisioning lifecycle
 * proof through the legacy C table (C_InitToken / C_InitPIN /
 * C_SetPIN), on a two-token SQLite store:
 *   - reinit authorization: InitToken with a wrong SO PIN
 *     refuses CKR_PIN_INCORRECT and preserves objects, PINs,
 *     flags, and SO attempts; the token stays initialized
 *   - ordinary-tool init: InitToken with sessions open refuses
 *     CKR_SESSION_EXISTS; with sessions closed it sets the SO PIN
 *     and label, clears CKF_USER_PIN_INITIALIZED, and resets auth
 *   - precedence: bad slot first, then PIN length
 *     (CKR_PIN_LEN_RANGE), then label shape/uniqueness, then
 *     sessions; bad sessions refuse SESSION_HANDLE_INVALID
 *   - user-PIN init/change: SO InitPIN sets the user PIN (the SO
 *     recovery shape); SetPIN changes the logged-in role's own PIN
 *   - old-PIN refusal: a wrong old PIN is CKR_PIN_INCORRECT and
 *     consumes one attempt; the third consecutive strike locks
 *   - lockout + SO recovery: a locked user denies everything
 *     until the SO runs InitPIN, which unlocks and resets
 *   - reset scoping: InitToken destroys only its own token's
 *     objects, jobs, and credential; the sibling token serves on
 *   - restart persistence: changed PINs survive Finalize +
 *     Initialize; a relabel needs the catalog updated to match
 *     (the operator flow: rewrite config, restart, serve on)
 *   - linearization: barrier-start load stays clean. The
 *     same-value leg races login-vs-SetPIN(A->A): every call
 *     answers, sessions conserve, and the stale leg pins the
 *     strike counter. The replace legs race two distinct
 *     transitions (A->B vs A->C, then winner->D/E): exactly one
 *     racer wins, the loser is refused on the superseded old
 *     credential, and the durable credential advances with no
 *     torn state.
 *
 * Standalone C consumer (non-Haskell executable): dlopen()s the built
 * libhaskoki shared module and drives it through the pinned 3.2
 * headers. Scenario lines carry "crypto:" and run direct-only:
 * the proxy shim's forwarding contract for the newly routed
 * entries is out of scope, so behind the proxy this consumer only
 * initializes and finalizes (mirrors the stub-beats-args pins in
 * consumer_errors.c). Setup lines are topology-independent ("ok:").
 *
 * This TU deliberately includes ONLY the pinned vendor headers; it
 * never consumes provider-generated artifacts (enforced by the
 * driver script's independence guard).
 *
 * Compile with -Ispec/vendor. Part of
 * scripts/test-consumers.sh and scripts/test-proxy-parity.sh.
 * Usage: consumer_provisioning <path-to-libhaskoki.so>
 */
#define _POSIX_C_SOURCE 200809L

#define CK_PTR *
#define CK_DECLARE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType(*name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType(*name)
/* NULL_PTR comes from the vendored PD header (always defined). */
#include "pkcs11.h"

#include <dlfcn.h>
#include <pthread.h>
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
    } else {                                                               \
      printf("ok: ");                                                      \
      printf(__VA_ARGS__);                                                 \
      printf("\n");                                                        \
    }                                                                      \
  } while (0)

/* Scenario lines (direct-only; excluded from the parity transcript
 * exactly like the stub-beats-args pins). */
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

static CK_FUNCTION_LIST_PTR g_api = NULL_PTR;
static char g_dir[256];
static char g_cfg[320];
static char g_db[320];

static void die(const char *what) {
  fprintf(stderr, "provisioning setup failed: %s\n", what);
  exit(2);
}

/* Write the two-token SQLite config (slot 0 demo, slot 1 ops).
 * Labels and PINs are parameters so the relabel leg can rewrite
 * the catalog to match a provisioned label, and the PIN-rewrite
 * leg can edit the configured PINs under a seeded store. */
static void write_config_pins(const char *slot0_label, const char *slot1_label,
                              const char *so0, const char *so1,
                              const char *user0, const char *user1) {
  FILE *f;
  if (!g_dir[0]) {
    char pattern[] = "/tmp/haskoki-provisioning-XXXXXX";
    if (!mkdtemp(pattern)) die("mkdtemp");
    snprintf(g_dir, sizeof(g_dir), "%s", pattern);
    snprintf(g_db, sizeof(g_db), "%s/prov.db", pattern);
    snprintf(g_cfg, sizeof(g_cfg), "%s/prov.toml", pattern);
  }
  f = fopen(g_cfg, "w");
  if (!f) die("config open");
  if (fprintf(f,
              "schema_version = 1\n"
              "profile = \"real-crypto\"\n"
              "[tokens]\n"
              "labels = [\"%s\", \"%s\"]\n"
              "so_pins = [\"%s\", \"%s\"]\n"
              "user_pins = [\"%s\", \"%s\"]\n"
              "[storage]\n"
              "kind = \"sqlite\"\n"
              "path = \"%s\"\n"
              "[engine]\n"
              "kind = \"openssl\"\n"
              "allow_synthetic_fallback = false\n"
              "private_library_context = true\n"
              "[trace]\n"
              "enabled = false\n",
              slot0_label, slot1_label, so0, so1, user0, user1, g_db) < 0) {
    fclose(f);
    die("config write");
  }
  if (fclose(f) != 0) die("config close");
  if (setenv("HASKOKI_CONFIG", g_cfg, 1) != 0) die("setenv");
}

static void write_config(const char *slot0_label, const char *slot1_label) {
  write_config_pins(slot0_label, slot1_label, "5678", "6789", "1234", "2345");
}

static CK_RV open_rw(CK_SLOT_ID slot, CK_SESSION_HANDLE *ph) {
  return g_api->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                              NULL_PTR, NULL_PTR, ph);
}

static CK_RV open_ro(CK_SLOT_ID slot, CK_SESSION_HANDLE *ph) {
  return g_api->C_OpenSession(slot, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, ph);
}

static void make_label32(const char *text, CK_UTF8CHAR out[32]) {
  size_t n, i;
  memset(out, ' ', 32);
  n = strlen(text);
  if (n > 32) n = 32;
  for (i = 0; i < n; i++) out[i] = (CK_UTF8CHAR)text[i];
}

static int label_is(const CK_TOKEN_INFO *info, const char *text) {
  CK_UTF8CHAR want[32];
  make_label32(text, want);
  return memcmp(info->label, want, 32) == 0;
}

static CK_RV token_info(CK_SLOT_ID slot, CK_TOKEN_INFO *info) {
  return g_api->C_GetTokenInfo(slot, info);
}

/* Count the token objects visible from a session. */
static CK_RV find_count(CK_SESSION_HANDLE sess, CK_ULONG *n) {
  CK_RV rv;
  CK_OBJECT_HANDLE hs[16];
  CK_ULONG got = 0;
  *n = 0;
  rv = g_api->C_FindObjectsInit(sess, NULL_PTR, 0);
  if (rv != CKR_OK) return rv;
  rv = g_api->C_FindObjects(sess, hs, 16, &got);
  if (rv == CKR_OK) *n = got;
  {
    CK_RV frv = g_api->C_FindObjectsFinal(sess);
    if (rv == CKR_OK) rv = frv;
  }
  return rv;
}

/* Create one persistent data object carrying a label. */
static CK_RV create_data(CK_SESSION_HANDLE sess, const char *label,
                         CK_OBJECT_HANDLE *ph) {
  CK_OBJECT_CLASS klass = CKO_DATA;
  CK_BBOOL token = CK_TRUE;
  CK_BYTE value[] = "provisioning-marker";
  CK_ATTRIBUTE tmpl[4];
  tmpl[0].type = CKA_CLASS;
  tmpl[0].pValue = &klass;
  tmpl[0].ulValueLen = sizeof(klass);
  tmpl[1].type = CKA_TOKEN;
  tmpl[1].pValue = &token;
  tmpl[1].ulValueLen = sizeof(token);
  tmpl[2].type = CKA_LABEL;
  tmpl[2].pValue = (CK_VOID_PTR)label;
  tmpl[2].ulValueLen = (CK_ULONG)strlen(label);
  tmpl[3].type = CKA_VALUE;
  tmpl[3].pValue = value;
  tmpl[3].ulValueLen = (CK_ULONG)(sizeof(value) - 1);
  return g_api->C_CreateObject(sess, tmpl, 4, ph);
}

/* ---------- phase: reinit authorization ---------- */

static void phase_reinit_guard(void) {
  CK_RV rv;
  CK_SESSION_HANDLE sess = 0;
  CK_OBJECT_HANDLE obj = 0;
  CK_ULONG n = 0;
  CK_TOKEN_INFO info;
  CK_UTF8CHAR label[32];

  /* Stage one persistent object on the catalog PINs. */
  rv = open_rw(0, &sess);
  CHECKC(rv == CKR_OK && sess != 0, "guard: session opens");
  if (rv != CKR_OK) return;
  rv = g_api->C_Login(sess, CKU_USER, (CK_UTF8CHAR_PTR) "1234", 4);
  CHECKC(rv == CKR_OK, "guard: user login on catalog PIN");
  rv = create_data(sess, "guard-victim", &obj);
  CHECKC(rv == CKR_OK && obj != 0, "guard: object created");
  (void)obj;
  rv = g_api->C_Logout(sess);
  CHECKC(rv == CKR_OK, "guard: logout");
  rv = g_api->C_CloseSession(sess);
  CHECKC(rv == CKR_OK, "guard: session closes");

  /* A wrong SO PIN refuses without mutating. */
  make_label32("haskoki-demo", label);
  rv = g_api->C_InitToken(0, (CK_UTF8CHAR_PTR) "wrong-pin", 9, label);
  CHECKC(rv == CKR_PIN_INCORRECT, "guard: wrong SO PIN refuses");

  /* Token identity and flags untouched. */
  rv = token_info(0, &info);
  CHECKC(rv == CKR_OK && label_is(&info, "haskoki-demo"), "guard: label kept");
  CHECKC((info.flags & CKF_TOKEN_INITIALIZED) != 0, "guard: token stays initialized");
  CHECKC((info.flags & CKF_USER_PIN_INITIALIZED) != 0,
         "guard: user PIN stays initialized");

  /* Object, PINs, and counters preserved. The wrong-SO-login
   * strikes come before any successful SO login (which would
   * reset the counter and mask a consumed attempt): two
   * strikes still answer PIN_INCORRECT, so the refusal
   * consumed nothing — a consumed attempt would lock on the
   * second strike. */
  rv = open_rw(0, &sess);
  CHECKC(rv == CKR_OK && sess != 0, "guard: session reopens");
  if (rv != CKR_OK) return;
  rv = find_count(sess, &n);
  CHECKC(rv == CKR_OK && n == 1, "guard: object survives");
  rv = g_api->C_Login(sess, CKU_SO, (CK_UTF8CHAR_PTR) "bad-so-0001", 10);
  CHECKC(rv == CKR_PIN_INCORRECT, "guard: first wrong SO login");
  rv = g_api->C_Login(sess, CKU_SO, (CK_UTF8CHAR_PTR) "bad-so-0002", 10);
  CHECKC(rv == CKR_PIN_INCORRECT, "guard: second wrong SO login");
  rv = g_api->C_Login(sess, CKU_SO, (CK_UTF8CHAR_PTR) "5678", 4);
  CHECKC(rv == CKR_OK, "guard: SO PIN serves after strikes");
  rv = g_api->C_Logout(sess);
  CHECKC(rv == CKR_OK, "guard: SO logout");
  rv = g_api->C_Login(sess, CKU_USER, (CK_UTF8CHAR_PTR) "1234", 4);
  CHECKC(rv == CKR_OK, "guard: user PIN serves");
  rv = g_api->C_Logout(sess);
  CHECKC(rv == CKR_OK, "guard: user logout");

  /* Clean up: later phases assume a fresh object set. */
  rv = g_api->C_Login(sess, CKU_USER, (CK_UTF8CHAR_PTR) "1234", 4);
  CHECKC(rv == CKR_OK, "guard: user login for cleanup");
  {
    CK_OBJECT_HANDLE hs[4];
    CK_ULONG got = 0;
    rv = g_api->C_FindObjectsInit(sess, NULL_PTR, 0);
    CHECKC(rv == CKR_OK, "guard: find init for cleanup");
    rv = g_api->C_FindObjects(sess, hs, 4, &got);
    CHECKC(rv == CKR_OK && got == 1, "guard: one object found");
    rv = g_api->C_FindObjectsFinal(sess);
    CHECKC(rv == CKR_OK, "guard: find final");
    if (got == 1) {
      rv = g_api->C_DestroyObject(sess, hs[0]);
      CHECKC(rv == CKR_OK, "guard: object destroyed");
    }
  }
  rv = find_count(sess, &n);
  CHECKC(rv == CKR_OK && n == 0, "guard: token holds no objects");
  rv = g_api->C_Logout(sess);
  CHECKC(rv == CKR_OK, "guard: logout");
  rv = g_api->C_CloseSession(sess);
  CHECKC(rv == CKR_OK, "guard: session closes");
}

/* ---------- phase: ordinary-tool init + precedence ---------- */

static void phase_init_token(void) {
  CK_RV rv;
  CK_SESSION_HANDLE sess = 0;
  CK_TOKEN_INFO info;
  CK_UTF8CHAR label[32];

  rv = open_rw(0, &sess);
  CHECKC(rv == CKR_OK && sess != 0, "init: session opens");
  if (rv != CKR_OK) return;

  /* Sessions open: InitToken refuses. */
  make_label32("haskoki-demo", label);
  rv = g_api->C_InitToken(0, (CK_UTF8CHAR_PTR) "so-fresh", 8, label);
  CHECKC(rv == CKR_SESSION_EXISTS, "init: open session refuses with SESSION_EXISTS");

  rv = g_api->C_CloseSession(sess);
  CHECKC(rv == CKR_OK, "init: session closes");

  /* Bad slot first, whatever the args. */
  rv = g_api->C_InitToken(99, (CK_UTF8CHAR_PTR) "so-fresh", 8, label);
  CHECKC(rv == CKR_SLOT_ID_INVALID, "init: bad slot refuses first");

  /* NULL label refuses (after the slot check). */
  rv = g_api->C_InitToken(0, (CK_UTF8CHAR_PTR) "so-fresh", 8, NULL_PTR);
  CHECKC(rv == CKR_ARGUMENTS_BAD, "init: NULL label refuses");

  /* Short SO PIN refuses with the length code. */
  rv = g_api->C_InitToken(0, (CK_UTF8CHAR_PTR) "ab", 2, label);
  CHECKC(rv == CKR_PIN_LEN_RANGE, "init: short SO PIN refuses with PIN_LEN_RANGE");

  /* A duplicate of the sibling token's label refuses: the
   * catalog cannot express two tokens under one label, so the
   * relabel must not strand the next open. */
  make_label32("haskoki-ops", label);
  rv = g_api->C_InitToken(0, (CK_UTF8CHAR_PTR) "so-fresh", 8, label);
  CHECKC(rv == CKR_ARGUMENTS_BAD, "init: duplicate label refuses");
  make_label32("haskoki-demo", label);

  /* The valid re-init authorizes with the existing SO PIN: label
   * kept, user PIN unset, SO PIN unchanged (rotation is SetPIN). */
  rv = g_api->C_InitToken(0, (CK_UTF8CHAR_PTR) "5678", 4, label);
  CHECKC(rv == CKR_OK, "init: valid call succeeds");

  rv = token_info(0, &info);
  CHECKC(rv == CKR_OK && label_is(&info, "haskoki-demo"), "init: label kept");
  CHECKC((info.flags & CKF_USER_PIN_INITIALIZED) == 0,
         "init: user-PIN-initialized flag clears");
  CHECKC((info.flags & CKF_TOKEN_INITIALIZED) != 0, "init: token stays initialized");

  rv = open_rw(0, &sess);
  CHECKC(rv == CKR_OK && sess != 0, "init: session reopens");
  if (rv != CKR_OK) return;
  rv = g_api->C_Login(sess, CKU_USER, (CK_UTF8CHAR_PTR) "1234", 4);
  CHECKC(rv == CKR_USER_PIN_NOT_INITIALIZED, "init: unset user PIN refuses login");
  rv = g_api->C_Login(sess, CKU_SO, (CK_UTF8CHAR_PTR) "5678", 4);
  CHECKC(rv == CKR_OK, "init: SO PIN serves");
  rv = g_api->C_Logout(sess);
  CHECKC(rv == CKR_OK, "init: SO logout");
  rv = g_api->C_CloseSession(sess);
  CHECKC(rv == CKR_OK, "init: session closes");
}

/* ---------- phase: user-PIN init/change + old-PIN refusal ---------- */

static void phase_pin_lifecycle(void) {
  CK_RV rv;
  CK_SESSION_HANDLE sess = 0;
  CK_TOKEN_INFO info;

  rv = open_rw(0, &sess);
  CHECKC(rv == CKR_OK && sess != 0, "pin: session opens");
  if (rv != CKR_OK) return;

  /* InitPIN needs an SO login. */
  rv = g_api->C_InitPIN(sess, (CK_UTF8CHAR_PTR) "user-one", 8);
  CHECKC(rv == CKR_USER_NOT_LOGGED_IN, "pin: InitPIN without SO login refuses");

  rv = g_api->C_Login(sess, CKU_SO, (CK_UTF8CHAR_PTR) "5678", 4);
  CHECKC(rv == CKR_OK, "pin: SO login");

  /* Bad new-PIN length refuses before anything commits. */
  rv = g_api->C_InitPIN(sess, (CK_UTF8CHAR_PTR) "ab", 2);
  CHECKC(rv == CKR_PIN_LEN_RANGE, "pin: short InitPIN refuses with PIN_LEN_RANGE");

  rv = g_api->C_InitPIN(sess, (CK_UTF8CHAR_PTR) "user-one", 8);
  CHECKC(rv == CKR_OK, "pin: InitPIN sets the user PIN");

  rv = token_info(0, &info);
  CHECKC(rv == CKR_OK && (info.flags & CKF_USER_PIN_INITIALIZED) != 0,
         "pin: user-PIN-initialized flag sets");

  rv = g_api->C_Logout(sess);
  CHECKC(rv == CKR_OK, "pin: SO logout");
  rv = g_api->C_Login(sess, CKU_USER, (CK_UTF8CHAR_PTR) "user-one", 8);
  CHECKC(rv == CKR_OK, "pin: user login on the fresh PIN");

  /* SetPIN on a bad session refuses by handle. */
  rv = g_api->C_SetPIN(0xFFFFFFFFUL, (CK_UTF8CHAR_PTR) "user-one", 8,
                       (CK_UTF8CHAR_PTR) "nope-nope", 9);
  CHECKC(rv == CKR_SESSION_HANDLE_INVALID, "pin: SetPIN on bad session refuses");

  /* Wrong old PIN refuses and consumes one attempt. */
  rv = g_api->C_SetPIN(sess, (CK_UTF8CHAR_PTR) "wrong-old", 9,
                       (CK_UTF8CHAR_PTR) "nope-nope", 9);
  CHECKC(rv == CKR_PIN_INCORRECT, "pin: wrong old PIN refuses");

  /* Bad new-PIN length refuses (no attempt consumed for it). */
  rv = g_api->C_SetPIN(sess, (CK_UTF8CHAR_PTR) "user-one", 8,
                       (CK_UTF8CHAR_PTR) "ab", 2);
  CHECKC(rv == CKR_PIN_LEN_RANGE, "pin: short new PIN refuses with PIN_LEN_RANGE");

  rv = g_api->C_SetPIN(sess, (CK_UTF8CHAR_PTR) "user-one", 8,
                       (CK_UTF8CHAR_PTR) "user-final", 10);
  CHECKC(rv == CKR_OK, "pin: SetPIN changes the user PIN");

  rv = g_api->C_Logout(sess);
  CHECKC(rv == CKR_OK, "pin: logout stays clean after change");
  rv = g_api->C_Login(sess, CKU_USER, (CK_UTF8CHAR_PTR) "user-one", 8);
  CHECKC(rv == CKR_PIN_INCORRECT, "pin: superseded PIN refuses");
  rv = g_api->C_Login(sess, CKU_USER, (CK_UTF8CHAR_PTR) "user-final", 10);
  CHECKC(rv == CKR_OK, "pin: changed PIN serves");
  rv = g_api->C_Logout(sess);
  CHECKC(rv == CKR_OK, "pin: logout");

  /* The old PIN authenticates: a public read/write session
   * changes the user PIN without logging in. */
  rv = g_api->C_SetPIN(sess, (CK_UTF8CHAR_PTR) "user-final", 10,
                       (CK_UTF8CHAR_PTR) "user-pub", 8);
  CHECKC(rv == CKR_OK, "pin: public session changes the user PIN");
  rv = g_api->C_Login(sess, CKU_USER, (CK_UTF8CHAR_PTR) "user-pub", 8);
  CHECKC(rv == CKR_OK, "pin: publicly changed PIN serves");
  rv = g_api->C_Logout(sess);
  CHECKC(rv == CKR_OK, "pin: logout");
  rv = g_api->C_CloseSession(sess);
  CHECKC(rv == CKR_OK, "pin: session closes");
}

/* ---------- phase: read-only guards ---------- */

static void phase_ro_guards(void) {
  CK_RV rv;
  CK_SESSION_HANDLE rw = 0, ro = 0;

  rv = open_rw(0, &rw);
  CHECKC(rv == CKR_OK && rw != 0, "ro: read/write session opens");
  rv = open_ro(0, &ro);
  CHECKC(rv == CKR_OK && ro != 0, "ro: read-only session opens");
  if (rv != CKR_OK || rw == 0 || ro == 0) return;

  /* Logged in or not, a read-only session never provisions. */
  rv = g_api->C_Login(ro, CKU_USER, (CK_UTF8CHAR_PTR) "user-pub", 8);
  CHECKC(rv == CKR_OK, "ro: user login on read-only session");
  rv = g_api->C_SetPIN(ro, (CK_UTF8CHAR_PTR) "user-pub", 8,
                       (CK_UTF8CHAR_PTR) "unused-zz", 9);
  CHECKC(rv == CKR_SESSION_READ_ONLY, "ro: logged-in read-only refuses SetPIN");
  rv = g_api->C_InitPIN(ro, (CK_UTF8CHAR_PTR) "unused-zz", 9);
  CHECKC(rv == CKR_USER_NOT_LOGGED_IN, "ro: read-only refuses InitPIN");
  rv = g_api->C_InitPIN(rw, (CK_UTF8CHAR_PTR) "unused-zz", 9);
  CHECKC(rv == CKR_USER_NOT_LOGGED_IN, "ro: public session refuses InitPIN");
  rv = g_api->C_Logout(ro);
  CHECKC(rv == CKR_OK, "ro: logout");
  rv = g_api->C_CloseSession(rw);
  CHECKC(rv == CKR_OK, "ro: read/write session closes");
  rv = g_api->C_CloseSession(ro);
  CHECKC(rv == CKR_OK, "ro: read-only session closes");
}

/* ---------- phase: lockout + SO recovery ---------- */

static void phase_lockout_recovery(void) {
  CK_RV rv;
  CK_SESSION_HANDLE sess = 0;
  CK_TOKEN_INFO info;

  rv = open_rw(0, &sess);
  CHECKC(rv == CKR_OK && sess != 0, "lockout: session opens");
  if (rv != CKR_OK) return;

  /* Three consecutive wrong SetPIN old-PINs lock the user role
   * (the strike count restarts: the earlier phases logged in
   * clean, which resets it). */
  rv = g_api->C_Login(sess, CKU_USER, (CK_UTF8CHAR_PTR) "user-pub", 8);
  CHECKC(rv == CKR_OK, "lockout: user login");
  rv = g_api->C_SetPIN(sess, (CK_UTF8CHAR_PTR) "bad-one!!", 9,
                       (CK_UTF8CHAR_PTR) "unused-aa", 9);
  CHECKC(rv == CKR_PIN_INCORRECT, "lockout: strike one");
  rv = g_api->C_SetPIN(sess, (CK_UTF8CHAR_PTR) "bad-two!!", 9,
                       (CK_UTF8CHAR_PTR) "unused-bb", 9);
  CHECKC(rv == CKR_PIN_INCORRECT, "lockout: strike two");
  rv = g_api->C_SetPIN(sess, (CK_UTF8CHAR_PTR) "bad-three!", 10,
                       (CK_UTF8CHAR_PTR) "unused-cc", 9);
  CHECKC(rv == CKR_PIN_LOCKED, "lockout: strike three locks");

  /* A locked role denies everything, consuming nothing. */
  rv = g_api->C_SetPIN(sess, (CK_UTF8CHAR_PTR) "user-pub", 8,
                       (CK_UTF8CHAR_PTR) "unused-dd", 9);
  CHECKC(rv == CKR_PIN_LOCKED, "lockout: correct old PIN still locked");
  rv = g_api->C_Logout(sess);
  CHECKC(rv == CKR_OK, "lockout: logout while locked");
  rv = g_api->C_Login(sess, CKU_USER, (CK_UTF8CHAR_PTR) "user-pub", 8);
  CHECKC(rv == CKR_PIN_LOCKED, "lockout: login locked");
  rv = token_info(0, &info);
  CHECKC(rv == CKR_OK && (info.flags & CKF_USER_PIN_LOCKED) != 0,
         "lockout: locked flag shows");

  /* SO recovery: the SO sets a fresh user PIN, unlocking. */
  rv = g_api->C_Login(sess, CKU_SO, (CK_UTF8CHAR_PTR) "5678", 4);
  CHECKC(rv == CKR_OK, "lockout: SO login during user lockout");
  rv = g_api->C_InitPIN(sess, (CK_UTF8CHAR_PTR) "recovered", 9);
  CHECKC(rv == CKR_OK, "lockout: SO InitPIN recovers");
  rv = g_api->C_Logout(sess);
  CHECKC(rv == CKR_OK, "lockout: SO logout");
  rv = token_info(0, &info);
  CHECKC(rv == CKR_OK && (info.flags & CKF_USER_PIN_LOCKED) == 0,
         "lockout: locked flag clears");
  rv = g_api->C_Login(sess, CKU_USER, (CK_UTF8CHAR_PTR) "recovered", 9);
  CHECKC(rv == CKR_OK, "lockout: recovered PIN serves");
  rv = g_api->C_Logout(sess);
  CHECKC(rv == CKR_OK, "lockout: logout");
  rv = g_api->C_CloseSession(sess);
  CHECKC(rv == CKR_OK, "lockout: session closes");
}

/* ---------- phase: reset scoping across two tokens ---------- */

static void phase_reset_scoping(void) {
  CK_RV rv;
  CK_SESSION_HANDLE s0 = 0, s1 = 0;
  CK_OBJECT_HANDLE o0 = 0, o1 = 0;
  CK_ULONG n = 0;
  CK_TOKEN_INFO info;
  CK_UTF8CHAR label[32];

  rv = open_rw(0, &s0);
  CHECKC(rv == CKR_OK && s0 != 0, "scope: slot-0 session opens");
  rv = open_rw(1, &s1);
  CHECKC(rv == CKR_OK && s1 != 0, "scope: slot-1 session opens");
  if (rv != CKR_OK || s0 == 0 || s1 == 0) return;

  /* Log in on both tokens (also re-proving both PINs). */
  rv = g_api->C_Login(s0, CKU_USER, (CK_UTF8CHAR_PTR) "recovered", 9);
  CHECKC(rv == CKR_OK, "scope: slot-0 login before reset");
  rv = g_api->C_Login(s1, CKU_USER, (CK_UTF8CHAR_PTR) "2345", 4);
  CHECKC(rv == CKR_OK, "scope: sibling login before reset");

  /* One persistent object per token. */
  rv = create_data(s0, "slot0-victim", &o0);
  CHECKC(rv == CKR_OK && o0 != 0, "scope: slot-0 object created");
  rv = create_data(s1, "slot1-kept", &o1);
  CHECKC(rv == CKR_OK && o1 != 0, "scope: slot-1 object created");
  (void)o1;

  rv = find_count(s0, &n);
  CHECKC(rv == CKR_OK && n == 1, "scope: slot-0 holds one object");
  rv = find_count(s1, &n);
  CHECKC(rv == CKR_OK && n == 1, "scope: slot-1 holds one object");

  rv = g_api->C_Logout(s0);
  CHECKC(rv == CKR_OK, "scope: slot-0 logout before reset");
  rv = g_api->C_Logout(s1);
  CHECKC(rv == CKR_OK, "scope: sibling logout before reset");

  rv = g_api->C_CloseSession(s0);
  CHECKC(rv == CKR_OK, "scope: slot-0 session closes");
  rv = g_api->C_CloseSession(s1);
  CHECKC(rv == CKR_OK, "scope: slot-1 session closes");

  /* Reset slot 0 only. */
  make_label32("haskoki-demo", label);
  rv = g_api->C_InitToken(0, (CK_UTF8CHAR_PTR) "5678", 4, label);
  CHECKC(rv == CKR_OK, "scope: slot-0 re-initialized");

  rv = open_rw(0, &s0);
  CHECKC(rv == CKR_OK && s0 != 0, "scope: slot-0 session reopens");
  rv = open_rw(1, &s1);
  CHECKC(rv == CKR_OK && s1 != 0, "scope: slot-1 session reopens");
  if (rv != CKR_OK || s0 == 0 || s1 == 0) return;

  rv = find_count(s0, &n);
  CHECKC(rv == CKR_OK && n == 0, "scope: reset token holds no objects");
  rv = find_count(s1, &n);
  CHECKC(rv == CKR_OK && n == 1, "scope: sibling object survives");

  rv = g_api->C_Login(s1, CKU_USER, (CK_UTF8CHAR_PTR) "2345", 4);
  CHECKC(rv == CKR_OK, "scope: sibling PIN unaffected");
  rv = g_api->C_Logout(s1);
  CHECKC(rv == CKR_OK, "scope: sibling logout");
  rv = token_info(1, &info);
  CHECKC(rv == CKR_OK && (info.flags & CKF_USER_PIN_INITIALIZED) != 0,
         "scope: sibling initialized flag intact");
  rv = token_info(0, &info);
  CHECKC(rv == CKR_OK && (info.flags & CKF_USER_PIN_INITIALIZED) == 0,
         "scope: reset token user PIN unset");

  /* Re-provision slot 0 so later phases start clean. */
  rv = g_api->C_Login(s0, CKU_SO, (CK_UTF8CHAR_PTR) "5678", 4);
  CHECKC(rv == CKR_OK, "scope: reset SO PIN serves");
  rv = g_api->C_InitPIN(s0, (CK_UTF8CHAR_PTR) "scoped-pin", 10);
  CHECKC(rv == CKR_OK, "scope: reset user PIN set");
  rv = g_api->C_Logout(s0);
  CHECKC(rv == CKR_OK, "scope: SO logout");

  rv = g_api->C_CloseSession(s0);
  CHECKC(rv == CKR_OK, "scope: slot-0 session closes");
  rv = g_api->C_CloseSession(s1);
  CHECKC(rv == CKR_OK, "scope: slot-1 session closes");
}

/* ---------- phase: restart persistence ---------- */

static void phase_restart(void) {
  CK_RV rv;
  CK_SESSION_HANDLE sess = 0;

  rv = g_api->C_Finalize(NULL_PTR);
  CHECKC(rv == CKR_OK, "restart: finalize");
  rv = g_api->C_Initialize(NULL_PTR);
  CHECKC(rv == CKR_OK, "restart: re-initialize");

  rv = open_rw(0, &sess);
  CHECKC(rv == CKR_OK && sess != 0, "restart: session opens");
  if (rv != CKR_OK) return;
  rv = g_api->C_Login(sess, CKU_USER, (CK_UTF8CHAR_PTR) "scoped-pin", 10);
  CHECKC(rv == CKR_OK, "restart: provisioned user PIN survives");
  rv = g_api->C_Logout(sess);
  CHECKC(rv == CKR_OK, "restart: logout");
  rv = g_api->C_Login(sess, CKU_SO, (CK_UTF8CHAR_PTR) "5678", 4);
  CHECKC(rv == CKR_OK, "restart: provisioned SO PIN survives");
  rv = g_api->C_Logout(sess);
  CHECKC(rv == CKR_OK, "restart: SO logout");
  rv = g_api->C_Login(sess, CKU_USER, (CK_UTF8CHAR_PTR) "recovered", 9);
  CHECKC(rv == CKR_PIN_INCORRECT, "restart: superseded PIN stays refused");
  rv = g_api->C_CloseSession(sess);
  CHECKC(rv == CKR_OK, "restart: session closes");

  rv = open_rw(1, &sess);
  CHECKC(rv == CKR_OK && sess != 0, "restart: sibling session opens");
  if (rv != CKR_OK) return;
  rv = g_api->C_Login(sess, CKU_USER, (CK_UTF8CHAR_PTR) "2345", 4);
  CHECKC(rv == CKR_OK, "restart: sibling catalog PIN serves");
  rv = g_api->C_Logout(sess);
  CHECKC(rv == CKR_OK, "restart: sibling logout");
  rv = g_api->C_CloseSession(sess);
  CHECKC(rv == CKR_OK, "restart: sibling session closes");
}

/* ---------- phase: idempotent same-value race ---------- */

#define RACE_WORKERS 4
#define RACE_ITERS 25
#define STALE_ITERS 10

static pthread_barrier_t g_race_start;
static int g_race_bad = 0;
static int g_race_login_ok = 0;
static int g_race_login_dup = 0;
static int g_stale_incorrect = 0;
static int g_stale_locked = 0;

static void race_note_bad(void) {
  __sync_fetch_and_add(&g_race_bad, 1);
}

static void *stale_worker(void *arg);

static void *race_worker(void *arg) {
  long id = (long)arg;
  int iter;
  CK_RV rv;
  CK_SESSION_HANDLE sess = 0;
  int brc;
  (void)id;
  rv = open_rw(0, &sess);
  if (rv != CKR_OK || sess == 0) {
    race_note_bad();
    return NULL;
  }
  brc = pthread_barrier_wait(&g_race_start);
  if (brc != 0 && brc != PTHREAD_BARRIER_SERIAL_THREAD) {
    race_note_bad();
    g_api->C_CloseSession(sess);
    return NULL;
  }
  /* The logins serialize: exactly one grants, the rest observe
   * the already-logged-in token (no PIN is consumed either
   * way). Every worker's own login call leaves the token
   * logged in, so every same-value change below must answer OK
   * no matter how the gate orders the interleavings — and
   * nobody logs out mid-race. */
  rv = g_api->C_Login(sess, CKU_USER, (CK_UTF8CHAR_PTR) "pin-alpha-01",
                      strlen("pin-alpha-01"));
  if (rv == CKR_OK) {
    __sync_fetch_and_add(&g_race_login_ok, 1);
  } else if (rv == CKR_USER_ALREADY_LOGGED_IN) {
    __sync_fetch_and_add(&g_race_login_dup, 1);
  } else {
    race_note_bad();
  }
  for (iter = 0; iter < RACE_ITERS; iter++) {
    rv = g_api->C_SetPIN(sess, (CK_UTF8CHAR_PTR) "pin-alpha-01",
                         strlen("pin-alpha-01"),
                         (CK_UTF8CHAR_PTR) "pin-alpha-01",
                         strlen("pin-alpha-01"));
    if (rv != CKR_OK) race_note_bad();
  }
  rv = g_api->C_CloseSession(sess);
  if (rv != CKR_OK) race_note_bad();
  return NULL;
}

static void phase_race_idempotent(void) {
  CK_RV rv;
  CK_SESSION_HANDLE sess = 0;
  pthread_t workers[RACE_WORKERS];
  long i;
  int created = 0;

  /* Stage the race PIN first (single-threaded). */
  rv = open_rw(0, &sess);
  CHECKC(rv == CKR_OK && sess != 0, "race: staging session opens");
  if (rv != CKR_OK) return;
  rv = g_api->C_Login(sess, CKU_USER, (CK_UTF8CHAR_PTR) "scoped-pin", 10);
  CHECKC(rv == CKR_OK, "race: staging login");
  rv = g_api->C_SetPIN(sess, (CK_UTF8CHAR_PTR) "scoped-pin", 10,
                       (CK_UTF8CHAR_PTR) "pin-alpha-01",
                       strlen("pin-alpha-01"));
  CHECKC(rv == CKR_OK, "race: staging PIN set");
  rv = g_api->C_Logout(sess);
  CHECKC(rv == CKR_OK, "race: staging logout");
  rv = g_api->C_CloseSession(sess);
  CHECKC(rv == CKR_OK, "race: staging session closes");

  g_race_bad = 0;
  g_race_login_ok = 0;
  g_race_login_dup = 0;
  if (pthread_barrier_init(&g_race_start, NULL, RACE_WORKERS) != 0) {
    CHECKC(0, "race: barrier init");
    return;
  }
  for (i = 0; i < RACE_WORKERS; i++) {
    if (pthread_create(&workers[i], NULL, race_worker, (void *)i) != 0) {
      CHECKC(0, "race: worker spawn");
      break;
    }
    created++;
  }
  for (i = 0; i < created; i++) pthread_join(workers[i], NULL);
  pthread_barrier_destroy(&g_race_start);
  CHECKC(created == RACE_WORKERS && g_race_bad == 0 &&
         g_race_login_ok == 1 && g_race_login_dup == RACE_WORKERS - 1,
         "race: one login grants, rest observe, every SetPIN/close answers OK");

  /* Leg two: concurrent stale-credential verification. Every
   * worker presents a superseded PIN, so exactly the first
   * two answers (in gate order) are PIN_INCORRECT, the third
   * locks, and every later one is PIN_LOCKED — the attempt
   * counter serializes the race, and the aggregate counts pin
   * the linearization. */
  g_stale_incorrect = 0;
  g_stale_locked = 0;
  if (pthread_barrier_init(&g_race_start, NULL, RACE_WORKERS) != 0) {
    CHECKC(0, "race: stale barrier init");
    return;
  }
  created = 0;
  for (i = 0; i < RACE_WORKERS; i++) {
    if (pthread_create(&workers[i], NULL, stale_worker, (void *)i) != 0) {
      CHECKC(0, "race: stale worker spawn");
      break;
    }
    created++;
  }
  for (i = 0; i < created; i++) pthread_join(workers[i], NULL);
  pthread_barrier_destroy(&g_race_start);
  CHECKC(created == RACE_WORKERS && g_race_bad == 0 &&
         g_stale_incorrect == 2 &&
         g_stale_locked == RACE_WORKERS * STALE_ITERS - 2,
         "race: stale logins serialize into two strikes then locked");

  /* SO recovery unlocks for the phases after. */
  rv = open_rw(0, &sess);
  CHECKC(rv == CKR_OK && sess != 0, "race: recovery session opens");
  if (rv != CKR_OK) return;
  rv = g_api->C_Login(sess, CKU_SO, (CK_UTF8CHAR_PTR) "5678", 4);
  CHECKC(rv == CKR_OK, "race: SO login after stale lockout");
  rv = g_api->C_InitPIN(sess, (CK_UTF8CHAR_PTR) "pin-alpha-01",
                        strlen("pin-alpha-01"));
  CHECKC(rv == CKR_OK, "race: SO recovery resets the PIN");
  rv = g_api->C_Logout(sess);
  CHECKC(rv == CKR_OK, "race: SO logout");

  /* The token serves on A afterwards: sessions conserved,
   * counters settled, ready for the replace race. */
  rv = g_api->C_Login(sess, CKU_USER, (CK_UTF8CHAR_PTR) "pin-alpha-01",
                      strlen("pin-alpha-01"));
  CHECKC(rv == CKR_OK, "race: PIN serves after the idempotent race");
  rv = g_api->C_Logout(sess);
  CHECKC(rv == CKR_OK, "race: logout after the idempotent race");
  rv = g_api->C_CloseSession(sess);
  CHECKC(rv == CKR_OK, "race: session closes after the idempotent race");
}

static void *stale_worker(void *arg) {
  long id = (long)arg;
  int iter;
  CK_RV rv;
  CK_SESSION_HANDLE sess = 0;
  int brc;
  (void)id;
  rv = open_rw(0, &sess);
  if (rv != CKR_OK || sess == 0) {
    race_note_bad();
    return NULL;
  }
  brc = pthread_barrier_wait(&g_race_start);
  if (brc != 0 && brc != PTHREAD_BARRIER_SERIAL_THREAD) {
    race_note_bad();
    g_api->C_CloseSession(sess);
    return NULL;
  }
  for (iter = 0; iter < STALE_ITERS; iter++) {
    rv = g_api->C_Login(sess, CKU_USER, (CK_UTF8CHAR_PTR) "scoped-pin", 10);
    if (rv == CKR_PIN_INCORRECT) {
      __sync_fetch_and_add(&g_stale_incorrect, 1);
    } else if (rv == CKR_PIN_LOCKED) {
      __sync_fetch_and_add(&g_stale_locked, 1);
    } else {
      race_note_bad();
    }
  }
  rv = g_api->C_CloseSession(sess);
  if (rv != CKR_OK) race_note_bad();
  return NULL;
}

/* ---------- phase: distinct-value replace races ---------- */

#define REPLACE_WORKERS 2

static pthread_barrier_t g_replace_start;
static CK_RV g_replace_rv[REPLACE_WORKERS];
static const char *g_replace_old = "pin-alpha-01";
static const char *g_replace_new[REPLACE_WORKERS] = { "pin-bravo-02",
                                                      "pin-charlie-03" };

static void *replace_worker(void *arg) {
  long id = (long)arg;           /* 0 -> B, 1 -> C */
  CK_SESSION_HANDLE sess = 0;
  int brc;
  /* public RW session; NO login: the old PIN authenticates */
  if (open_rw(0, &sess) != CKR_OK) { race_note_bad(); return NULL; }
  brc = pthread_barrier_wait(&g_replace_start);
  if (brc != 0 && brc != PTHREAD_BARRIER_SERIAL_THREAD) {
    race_note_bad();
    g_api->C_CloseSession(sess);
    return NULL;
  }
  g_replace_rv[id] = g_api->C_SetPIN(sess, (CK_UTF8CHAR_PTR)g_replace_old,
    strlen(g_replace_old), (CK_UTF8CHAR_PTR)g_replace_new[id],
    strlen(g_replace_new[id]));
  if (g_api->C_CloseSession(sess) != CKR_OK) race_note_bad();
  return NULL;
}

/* Run one replace race over the current old/new pair: exactly
 * one racer wins (CKR_OK), the other is refused with
 * CKR_PIN_INCORRECT on the superseded old credential, in
 * either order. Returns nonzero when the barrier ran. */
static int run_replace_race(const char *tag) {
  pthread_t workers[REPLACE_WORKERS];
  long i;
  int created = 0;
  int ok = 0;
  int refused = 0;

  g_race_bad = 0;
  if (pthread_barrier_init(&g_replace_start, NULL, REPLACE_WORKERS) != 0) {
    CHECKC(0, "race: replace barrier init");
    return 0;
  }
  for (i = 0; i < REPLACE_WORKERS; i++) {
    if (pthread_create(&workers[i], NULL, replace_worker, (void *)i) != 0)
      break;
    created++;
  }
  for (i = 0; i < created; i++) pthread_join(workers[i], NULL);
  pthread_barrier_destroy(&g_replace_start);
  for (i = 0; i < created; i++) {
    if (g_replace_rv[i] == CKR_OK) {
      ok++;
    } else if (g_replace_rv[i] == CKR_PIN_INCORRECT) {
      refused++;
    }
  }
  CHECKC(created == REPLACE_WORKERS && g_race_bad == 0 && ok == 1 && refused == 1,
         "race: %s: one winner, one old-credential refusal", tag);
  return created == REPLACE_WORKERS;
}

static void phase_race_replace(void) {
  CK_RV rv;
  CK_SESSION_HANDLE sess = 0;
  const char *w;
  const char *l;

  /* Leg one: two distinct transitions off A behind one
   * barrier. Exactly one wins; the loser finds the old
   * credential superseded and is refused. */
  if (!run_replace_race("replace")) return;
  w = (g_replace_rv[0] == CKR_OK) ? g_replace_new[0] : g_replace_new[1];
  l = (g_replace_rv[0] == CKR_OK) ? g_replace_new[1] : g_replace_new[0];

  /* Post-race probes, fixed order: the strike budget peaks
   * at two and never locks. The winner login first resets
   * the loser's strike; the two refusals accrue one strike
   * each; the closing winner login resets again. */
  rv = open_rw(0, &sess);
  CHECKC(rv == CKR_OK && sess != 0, "race: probe session opens");
  if (rv != CKR_OK) return;
  rv = g_api->C_Login(sess, CKU_USER, (CK_UTF8CHAR_PTR)w, strlen(w));
  CHECKC(rv == CKR_OK, "race: winner serves after the replace race");
  rv = g_api->C_Logout(sess);
  CHECKC(rv == CKR_OK, "race: logout after the winner probe");
  rv = g_api->C_Login(sess, CKU_USER, (CK_UTF8CHAR_PTR)"pin-alpha-01",
                      strlen("pin-alpha-01"));
  CHECKC(rv == CKR_PIN_INCORRECT, "race: superseded PIN refuses");
  rv = g_api->C_Login(sess, CKU_USER, (CK_UTF8CHAR_PTR)l, strlen(l));
  CHECKC(rv == CKR_PIN_INCORRECT, "race: loser value refuses");
  rv = g_api->C_Login(sess, CKU_USER, (CK_UTF8CHAR_PTR)w, strlen(w));
  CHECKC(rv == CKR_OK, "race: winner serves again after the refusals");
  rv = g_api->C_Logout(sess);
  CHECKC(rv == CKR_OK, "race: logout after the replace probes");
  rv = g_api->C_CloseSession(sess);
  CHECKC(rv == CKR_OK, "race: probe session closes");

  /* Leg two: the chained race off the winner composes the
   * ordering (element-wise: whole-array assignment is
   * illegal C). */
  g_replace_old = w;
  g_replace_new[0] = "pin-delta-04";
  g_replace_new[1] = "pin-echo-05";
  if (!run_replace_race("chained")) return;

  /* SO recovery hands slot 0 on with the agreed PIN; the
   * phases after depend on it. */
  rv = open_rw(0, &sess);
  CHECKC(rv == CKR_OK && sess != 0, "race: handoff recovery session opens");
  if (rv != CKR_OK) return;
  rv = g_api->C_Login(sess, CKU_SO, (CK_UTF8CHAR_PTR) "5678", 4);
  CHECKC(rv == CKR_OK, "race: SO login before the handoff");
  rv = g_api->C_InitPIN(sess, (CK_UTF8CHAR_PTR) "race-done!", 10);
  CHECKC(rv == CKR_OK, "race: SO recovery resets the PIN");
  rv = g_api->C_Logout(sess);
  CHECKC(rv == CKR_OK, "race: SO logout");

  /* The token serves on afterwards: sessions conserved, one
   * PIN wins, counters settled. */
  rv = g_api->C_Login(sess, CKU_USER, (CK_UTF8CHAR_PTR) "race-done!", 10);
  CHECKC(rv == CKR_OK, "race: PIN serves after the race");
  rv = g_api->C_Logout(sess);
  CHECKC(rv == CKR_OK, "race: logout after the race");
  rv = g_api->C_CloseSession(sess);
  CHECKC(rv == CKR_OK, "race: session closes after the race");
}

/* ---------- phase: relabel + catalog update + restart ---------- */

static void phase_relabel(void) {
  CK_RV rv;
  CK_TOKEN_INFO info;
  CK_UTF8CHAR label[32];

  /* Slot 0 keeps the demo label: the catalog anchors slot 0 to
   * it, so an in-band slot-0 relabel would strand the next
   * open and refuses instead. */
  make_label32("renamed-token", label);
  rv = g_api->C_InitToken(0, (CK_UTF8CHAR_PTR) "so-renamed", 10, label);
  CHECKC(rv == CKR_ARGUMENTS_BAD, "relabel: slot-0 relabel refuses on the anchor");
  rv = token_info(0, &info);
  CHECKC(rv == CKR_OK && label_is(&info, "haskoki-demo"),
         "relabel: refused relabel changes nothing");

  /* Relabel slot 1 through InitToken (sessions closed). */
  make_label32("renamed-ops", label);
  rv = g_api->C_InitToken(1, (CK_UTF8CHAR_PTR) "6789", 4, label);
  CHECKC(rv == CKR_OK, "relabel: InitToken with new label");
  rv = token_info(1, &info);
  CHECKC(rv == CKR_OK && label_is(&info, "renamed-ops"), "relabel: new label reports");

  {
    CK_SESSION_HANDLE sess = 0;
    rv = open_rw(1, &sess);
    CHECKC(rv == CKR_OK && sess != 0, "relabel: session opens");
    if (rv != CKR_OK) return;
    rv = g_api->C_Login(sess, CKU_SO, (CK_UTF8CHAR_PTR) "6789", 4);
    CHECKC(rv == CKR_OK, "relabel: SO PIN serves");
    rv = g_api->C_InitPIN(sess, (CK_UTF8CHAR_PTR) "renamed-u!", 10);
    CHECKC(rv == CKR_OK, "relabel: user PIN set");
    rv = g_api->C_Logout(sess);
    CHECKC(rv == CKR_OK, "relabel: SO logout");
    rv = g_api->C_CloseSession(sess);
    CHECKC(rv == CKR_OK, "relabel: session closes");
  }

  /* The operator flow: update the catalog to the durable label,
   * restart, and serve on. */
  rv = g_api->C_Finalize(NULL_PTR);
  CHECKC(rv == CKR_OK, "relabel: finalize");
  write_config("haskoki-demo", "renamed-ops");
  rv = g_api->C_Initialize(NULL_PTR);
  CHECKC(rv == CKR_OK, "relabel: re-initialize on updated catalog");

  {
    CK_SESSION_HANDLE sess = 0;
    rv = token_info(1, &info);
    CHECKC(rv == CKR_OK && label_is(&info, "renamed-ops"),
           "relabel: label survives restart");
    rv = open_rw(1, &sess);
    CHECKC(rv == CKR_OK && sess != 0, "relabel: session opens after restart");
    if (rv != CKR_OK) return;
    rv = g_api->C_Login(sess, CKU_USER, (CK_UTF8CHAR_PTR) "renamed-u!", 10);
    CHECKC(rv == CKR_OK, "relabel: user PIN serves after restart");
    rv = g_api->C_Logout(sess);
    CHECKC(rv == CKR_OK, "relabel: logout");
    rv = g_api->C_CloseSession(sess);
    CHECKC(rv == CKR_OK, "relabel: session closes");
  }
}

/* ---------- phase: config PIN rewrite under a seeded store ---------- */

/* The durable credentials win over edited config PINs: rewrite
 * every configured PIN and restart. The provisioned PINs still
 * serve, the edited ones are refused, and the identity-derived
 * serial does not move. */
static void phase_pin_rewrite(void) {
  CK_RV rv;
  CK_SESSION_HANDLE sess = 0;
  CK_TOKEN_INFO info;
  CK_UTF8CHAR serial_before[16];

  rv = token_info(1, &info);
  CHECKC(rv == CKR_OK && memcmp(info.serialNumber, "0000000000000002", 16) == 0,
         "pin-rewrite: ops serial is its durable identity");
  memcpy(serial_before, info.serialNumber, sizeof(serial_before));

  rv = g_api->C_Finalize(NULL_PTR);
  CHECKC(rv == CKR_OK, "pin-rewrite: finalize");
  write_config_pins("haskoki-demo", "renamed-ops", "1111", "2222", "3333", "4444");
  rv = g_api->C_Initialize(NULL_PTR);
  CHECKC(rv == CKR_OK, "pin-rewrite: re-initialize on edited PINs");
  if (rv != CKR_OK) return;

  rv = token_info(1, &info);
  CHECKC(rv == CKR_OK && memcmp(info.serialNumber, serial_before, 16) == 0,
         "pin-rewrite: serial survives the restart");

  rv = open_rw(0, &sess);
  CHECKC(rv == CKR_OK && sess != 0, "pin-rewrite: slot-0 session opens");
  if (rv != CKR_OK) return;
  rv = g_api->C_Login(sess, CKU_USER, (CK_UTF8CHAR_PTR) "3333", 4);
  CHECKC(rv == CKR_PIN_INCORRECT, "pin-rewrite: edited user PIN refused");
  rv = g_api->C_Login(sess, CKU_USER, (CK_UTF8CHAR_PTR) "race-done!", 10);
  CHECKC(rv == CKR_OK, "pin-rewrite: provisioned user PIN serves");
  rv = g_api->C_Logout(sess);
  CHECKC(rv == CKR_OK, "pin-rewrite: user logout");
  rv = g_api->C_Login(sess, CKU_SO, (CK_UTF8CHAR_PTR) "1111", 4);
  CHECKC(rv == CKR_PIN_INCORRECT, "pin-rewrite: edited SO PIN refused");
  rv = g_api->C_Login(sess, CKU_SO, (CK_UTF8CHAR_PTR) "5678", 4);
  CHECKC(rv == CKR_OK, "pin-rewrite: provisioned SO PIN serves");
  rv = g_api->C_Logout(sess);
  CHECKC(rv == CKR_OK, "pin-rewrite: SO logout");
  rv = g_api->C_CloseSession(sess);
  CHECKC(rv == CKR_OK, "pin-rewrite: slot-0 session closes");

  rv = open_rw(1, &sess);
  CHECKC(rv == CKR_OK && sess != 0, "pin-rewrite: slot-1 session opens");
  if (rv != CKR_OK) return;
  rv = g_api->C_Login(sess, CKU_USER, (CK_UTF8CHAR_PTR) "4444", 4);
  CHECKC(rv == CKR_PIN_INCORRECT, "pin-rewrite: edited sibling PIN refused");
  rv = g_api->C_Login(sess, CKU_USER, (CK_UTF8CHAR_PTR) "renamed-u!", 10);
  CHECKC(rv == CKR_OK, "pin-rewrite: provisioned sibling PIN serves");
  rv = g_api->C_Logout(sess);
  CHECKC(rv == CKR_OK, "pin-rewrite: sibling logout");
  rv = g_api->C_CloseSession(sess);
  CHECKC(rv == CKR_OK, "pin-rewrite: slot-1 session closes");
}

static void run_scenario(void) {
  phase_reinit_guard();
  phase_init_token();
  phase_pin_lifecycle();
  phase_ro_guards();
  phase_lockout_recovery();
  phase_reset_scoping();
  phase_restart();
  phase_race_idempotent();
  phase_race_replace();
  phase_relabel();
  phase_pin_rewrite();
}

int main(int argc, char **argv) {
  void *handle;
  CK_C_GetFunctionList pGetList;
  CK_FUNCTION_LIST_PTR legacy = NULL_PTR;
  CK_RV rv;
  const char *topo;
  int isProxy;

  if (argc != 2) {
    fprintf(stderr, "usage: %s <libhaskoki.so>\n", argv[0]);
    return 2;
  }
  topo = getenv("HASKOKI_CONSUMER_TOPOLOGY");
  isProxy = topo && strcmp(topo, "proxy") == 0;
  printf("topology: %s\n", isProxy ? "proxy" : "direct");
  write_config("haskoki-demo", "haskoki-ops");
  CHECK(1, "provisioning config written");
  handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
  if (!handle) {
    fprintf(stderr, "dlopen failed: %s\n", dlerror());
    return 2;
  }
  pGetList = (CK_C_GetFunctionList)dlsym(handle, "C_GetFunctionList");
  CHECK(pGetList != NULL_PTR, "C_GetFunctionList resolves");
  rv = pGetList(&legacy);
  CHECK(rv == CKR_OK && legacy, "legacy table resolves");
  CHECK(legacy->version.major == 2 && legacy->version.minor == 40,
        "legacy table version is 2.40");
  g_api = legacy;
  rv = g_api->C_Initialize(NULL_PTR);
  CHECK(rv == CKR_OK, "initialize");
  if (rv != CKR_OK) return 2;
  if (!isProxy) {
    run_scenario();
  }
  rv = g_api->C_Finalize(NULL_PTR);
  CHECK(rv == CKR_OK, "finalize");
  dlclose(handle);
  if (g_failures) {
    printf("FAIL: consumer_provisioning (%d failures)\n", g_failures);
    return 1;
  }
  printf("PASS: consumer_provisioning\n");
  return 0;
}
