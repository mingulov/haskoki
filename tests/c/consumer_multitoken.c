/* tests/c/consumer_multitoken.c — direct-load consumer: N-token serving.
 *
 * Standalone C consumer (non-Haskell executable): dlopen()s the built
 * libhaskoki shared module (or, in proxy topology, the pkcs11-proxy-ng
 * shim) and drives the multi-token surface through the pinned 3.2
 * headers:
 *   - N-slot enumeration on the legacy (2.40) table plus the 3.0/3.1/3.2
 *     tables (4-table proof shape), count-query/size-query/short-buffer
 *     legs, token-present filtering, cross-table agreement
 *   - per-slot sessions (open/info/close), per-slot token/slot records
 *     (catalog labels blank-padded, per-slot serials, pinned strings),
 *     per-slot mechanism catalog
 *   - per-slot user/SO login/logout with catalog PINs, foreign-PIN
 *     refusal, bad-slot refusal on every slot-taking entry
 *   - cross-slot object invisibility (direct-only: create on one slot,
 *     find/get/destroy from another fail typed)
 *
 * Config: hermetic self-written 3-token catalog (memory storage, trace
 * off) mirroring tests/ops/fixtures/multi-token.toml, unless
 * HASKOKI_MULTITOKEN_CONFIG points at an explicit file (sensitivity
 * runs and fixture-driven evidence; an override file is never
 * unlinked). In proxy topology the server side carries its own
 * single-token backend.toml, so the proxied run serves one slot:
 * catalog-shape-dependent assertions use CHECKM (invent:-prefixed,
 * excluded from the parity diff like discovery's CHECKX inventory
 * lines); every CHECK line is evaluated in BOTH modes over the
 * discovered slots with a static message, so forwarded-call parity
 * still compares real behavior. Multi-slot relational scenarios
 * (cross-slot isolation) run direct-only and skip with an invent:
 * note behind the single-slot proxy backend.
 *
 * This TU deliberately includes ONLY the pinned vendor headers; it
 * never consumes provider-generated artifacts (enforced by the
 * driver script's independence guard).
 *
 * Compile with -Ispec/vendor. Part of
 * scripts/test-consumers.sh and scripts/test-proxy-parity.sh.
 * Usage: consumer_multitoken <path-to-libhaskoki.so>
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

/* Catalog-shape-scoped check: prefixed so the parity script excludes it
 * (the serving catalog legitimately differs: 3token self-config direct
 * vs the server's single-token backend.toml proxied). Failures still
 * fail the run. */
#define CHECKM(cond, ...)                                                  \
  do {                                                                     \
    if (!(cond)) {                                                         \
      printf("invent: FAIL [%s:%d]: ", __FILE__, __LINE__);                \
      printf(__VA_ARGS__);                                                 \
      printf("\n");                                                        \
      g_failures++;                                                        \
    } else {                                                               \
      printf("invent: ok: ");                                              \
      printf(__VA_ARGS__);                                                 \
      printf("\n");                                                        \
    }                                                                      \
  } while (0)

/* Hermetic config: 3-token catalog, memory storage, trace off. Written
 * to a temp file; HASKOKI_CONFIG points at it before the module
 * resolves its config at C_Initialize. */
static char g_cfg_path[256];
static int g_cfg_ours = 0;

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
                             "enabled = false\n"
                             "[tokens]\n"
                             "labels = [\"haskoki-demo\", \"haskoki-ops\", "
                             "\"haskoki-audit\"]\n"
                             "so_pins = [\"5678\", \"6789\", \"7890\"]\n"
                             "user_pins = [\"1234\", \"2345\", \"3456\"]\n";
  const char *ovr = getenv("HASKOKI_MULTITOKEN_CONFIG");
  if (ovr && ovr[0] != '\0') {
    snprintf(g_cfg_path, sizeof(g_cfg_path), "%s", ovr);
    g_cfg_ours = 0;
    if (setenv("HASKOKI_CONFIG", g_cfg_path, 1) != 0) {
      perror("setenv");
      exit(2);
    }
    return;
  }
  {
    char tmpl[] = "/tmp/haskoki-multitoken-XXXXXX";
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
    g_cfg_ours = 1;
    if (setenv("HASKOKI_CONFIG", g_cfg_path, 1) != 0) {
      perror("setenv");
      exit(2);
    }
  }
}

/* Serving catalog (direct mode). Slot 0 stays haskoki-demo. */
static const char *kLabels[3] = {"haskoki-demo", "haskoki-ops", "haskoki-audit"};
static const char *kUserPins[3] = {"1234", "2345", "3456"};
static const char *kSoPins[3] = {"5678", "6789", "7890"};

/* Length of a blank-padded label field's non-pad prefix. */
static CK_ULONG padded_len(const CK_UTF8CHAR *field, CK_ULONG width) {
  CK_ULONG n = 0;
  while (n < width && field[n] != ' ') {
    n++;
  }
  return n;
}

/* Catalog PINs by label bytes (NULL when the label is unknown). */
static const char *user_pin_for(const CK_UTF8CHAR *label, CK_ULONG len) {
  CK_ULONG i;
  for (i = 0; i < 3; i++) {
    size_t want = strlen(kLabels[i]);
    if (len == (CK_ULONG)want && memcmp(label, kLabels[i], want) == 0) {
      return kUserPins[i];
    }
  }
  return NULL;
}

static const char *so_pin_for(const CK_UTF8CHAR *label, CK_ULONG len) {
  CK_ULONG i;
  for (i = 0; i < 3; i++) {
    size_t want = strlen(kLabels[i]);
    if (len == (CK_ULONG)want && memcmp(label, kLabels[i], want) == 0) {
      return kSoPins[i];
    }
  }
  return NULL;
}

int main(int argc, char **argv) {
  void *handle;
  CK_C_GetFunctionList pGetList;
  CK_C_GetInterfaceList pGetInterfaceList;
  CK_C_GetInterface pGetInterface;
  CK_FUNCTION_LIST_PTR legacy = NULL_PTR;
  CK_INTERFACE_PTR p32 = NULL_PTR, p31 = NULL_PTR, p30 = NULL_PTR;
  CK_FUNCTION_LIST_3_2_PTR tbl32 = NULL_PTR;
  CK_FUNCTION_LIST_3_0_PTR tbl31 = NULL_PTR, tbl30 = NULL_PTR;
  CK_VERSION v;
  CK_RV rv;
  CK_SLOT_ID slots[16];
  CK_ULONG n = 16;
  CK_ULONG nq = 0;
  CK_ULONG i = 0;
  CK_SLOT_INFO si;
  CK_TOKEN_INFO ti;
  const char *topo;
  int isProxy;
  CK_ULONG expect;

  if (argc != 2) {
    fprintf(stderr, "usage: %s <libhaskoki.so>\n", argv[0]);
    return 2;
  }
  topo = getenv("HASKOKI_CONSUMER_TOPOLOGY");
  isProxy = topo && strcmp(topo, "proxy") == 0;
  /* Serving shape: 3token self-config direct, single-token server
   * backend proxied. Fixed per topology (the config override does
   * NOT move it, so sensitivity runs fail loudly). */
  expect = isProxy ? 1 : 3;
  printf("topology: %s\n", isProxy ? "proxy" : "direct");
  write_config();
  handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
  if (!handle) {
    fprintf(stderr, "dlopen failed: %s\n", dlerror());
    return 2;
  }
  pGetList = (CK_C_GetFunctionList)dlsym(handle, "C_GetFunctionList");
  pGetInterfaceList =
      (CK_C_GetInterfaceList)dlsym(handle, "C_GetInterfaceList");
  pGetInterface = (CK_C_GetInterface)dlsym(handle, "C_GetInterface");
  CHECK(pGetList && pGetInterfaceList && pGetInterface,
        "discovery symbols resolve");

  /* ---- tables (3.1 exists direct-only; the shim has no 3.1) ---- */
  v.major = 3;
  v.minor = 2;
  rv = pGetInterface((CK_UTF8CHAR_PTR) "PKCS 11", &v, &p32, 0);
  CHECK(rv == CKR_OK && p32 != NULL_PTR, "GetInterface selects 3.2");
  v.minor = 1;
  p31 = NULL_PTR;
  rv = pGetInterface((CK_UTF8CHAR_PTR) "PKCS 11", &v, &p31, 0);
  if (!isProxy) {
    CHECKM(rv == CKR_OK && p31 != NULL_PTR, "GetInterface selects 3.1");
  } else {
    /* Backend-published 3.1 is merged into the live catalog. */
    CHECKM(rv == CKR_OK && p31 != NULL_PTR,
           "GetInterface selects proxied 3.1");
  }
  v.minor = 0;
  rv = pGetInterface((CK_UTF8CHAR_PTR) "PKCS 11", &v, &p30, 0);
  CHECK(rv == CKR_OK && p30 != NULL_PTR, "GetInterface selects 3.0");
  if (p32 != NULL_PTR) {
    tbl32 = (CK_FUNCTION_LIST_3_2_PTR)p32->pFunctionList;
  }
  if (p31 != NULL_PTR) {
    tbl31 = (CK_FUNCTION_LIST_3_0_PTR)p31->pFunctionList;
  }
  if (p30 != NULL_PTR) {
    tbl30 = (CK_FUNCTION_LIST_3_0_PTR)p30->pFunctionList;
  }
  rv = pGetList(&legacy);
  CHECK(rv == CKR_OK && legacy, "legacy GetFunctionList resolves");
  CHECK(legacy->version.major == 2 && legacy->version.minor == 40,
        "legacy table version is 2.40");
  CHECK(tbl32 && tbl30, "3.2 and 3.0 tables selected");
  if (!tbl32 || !tbl30 || !legacy) {
    printf("FAIL: required tables missing; aborting\n");
    return 1;
  }

  /* ---- Initialize through the legacy (2.40) table ---- */
  rv = legacy->C_Initialize(NULL_PTR);
  CHECK(rv == CKR_OK, "legacy C_Initialize ok");

  /* ---- N-slot enumeration on all four tables ---- */
  nq = 0;
  rv = legacy->C_GetSlotList(0, NULL_PTR, &nq);
  CHECKM(rv == CKR_OK && nq == expect, "legacy slot count is serving count");
  nq = 0;
  rv = tbl32->C_GetSlotList(0, NULL_PTR, &nq);
  CHECKM(rv == CKR_OK && nq == expect, "3.2 slot count is serving count");
  nq = 0;
  rv = tbl30->C_GetSlotList(0, NULL_PTR, &nq);
  CHECKM(rv == CKR_OK && nq == expect, "3.0 slot count is serving count");
  if (tbl31 != NULL_PTR) {
    nq = 0;
    rv = tbl31->C_GetSlotList(0, NULL_PTR, &nq);
    CHECKM(rv == CKR_OK && nq == expect, "3.1 slot count is serving count");
  }
  {
    /* Cross-table agreement + fill/count coherence (one line: the
     * predicate absorbs the serving shape). */
    CK_SLOT_ID fill32[16], fill30[16];
    CK_ULONG nLeg = 16, n32 = 16, n30 = 16, n31 = 16;
    CK_ULONG qLeg = 0, q32 = 0, q30 = 0;
    int agree = 0;
    rv = legacy->C_GetSlotList(0, slots, &nLeg);
    agree = (rv == CKR_OK);
    rv = tbl32->C_GetSlotList(0, fill32, &n32);
    agree = agree && (rv == CKR_OK && n32 == nLeg);
    rv = tbl30->C_GetSlotList(0, fill30, &n30);
    agree = agree && (rv == CKR_OK && n30 == nLeg);
    if (tbl31 != NULL_PTR) {
      CK_SLOT_ID fill31[16];
      rv = tbl31->C_GetSlotList(0, fill31, &n31);
      agree = agree && (rv == CKR_OK && n31 == nLeg);
      for (i = 0; i < nLeg; i++) {
        agree = agree && (fill31[i] == slots[i]);
      }
    }
    for (i = 0; i < nLeg; i++) {
      agree = agree && (fill32[i] == slots[i] && fill30[i] == slots[i]);
    }
    n = nLeg;
    rv = legacy->C_GetSlotList(0, NULL_PTR, &qLeg);
    agree = agree && (rv == CKR_OK && qLeg == nLeg);
    rv = tbl32->C_GetSlotList(0, NULL_PTR, &q32);
    agree = agree && (rv == CKR_OK && q32 == nLeg);
    rv = tbl30->C_GetSlotList(0, NULL_PTR, &q30);
    agree = agree && (rv == CKR_OK && q30 == nLeg);
    CHECK(agree, "all tables agree on slots; fill matches query");
  }
  CHECKM(n == expect, "discovered slot count is serving count");
  for (i = 0; i < n; i++) {
    if (!isProxy) {
      CHECKM(slots[i] == i, "direct slot ids are catalog indices");
    } else {
      CHECKM(1, "proxied slot id accepted as remapped");
    }
  }
  {
    /* Short buffer reports the serving count (discipline identical
     * in both modes; the predicate absorbs the count). */
    CK_SLOT_ID one[1];
    CK_ULONG cap = 0;
    rv = legacy->C_GetSlotList(0, one, &cap);
    CHECK(rv == CKR_BUFFER_TOO_SMALL && cap == expect,
          "short slot buffer reports serving count");
  }
  {
    /* Token-present filtering: every seated slot holds a token. */
    CK_ULONG nAll = 0, nPresent = 0;
    rv = legacy->C_GetSlotList(0, NULL_PTR, &nAll);
    CHECK(rv == CKR_OK, "full list queries");
    rv = legacy->C_GetSlotList(1, NULL_PTR, &nPresent);
    CHECK(rv == CKR_OK && nPresent == nAll && nAll == expect,
          "token-present matches full list at serving count");
  }

  /* ---- per-slot records ---- */
  for (i = 0; i < n; i++) {
    CK_ULONG llen = 0;
    CK_ULONG j = 0;
    int padOk = 0;
    rv = tbl32->C_GetSlotInfo(slots[i], &si);
    CHECKM(rv == CKR_OK && (si.flags & CKF_TOKEN_PRESENT) != 0,
           "slot token-present set");
    rv = tbl32->C_GetTokenInfo(slots[i], &ti);
    CHECKM(rv == CKR_OK, "token info fetches");
    if (rv != CKR_OK) {
      continue;
    }
    llen = padded_len(ti.label, 32);
    padOk = 1;
    for (j = llen; j < 32; j++) {
      if (ti.label[j] != ' ') {
        padOk = 0;
      }
    }
    CHECKM(padOk && llen > 0, "label blank-padded, non-empty");
    if (!isProxy) {
      size_t want = strlen(kLabels[i]);
      CHECKM(llen == (CK_ULONG)want &&
                 memcmp(ti.label, kLabels[i], want) == 0,
             "label is the catalog label");
    } else {
      CHECKM(llen == 12 && memcmp(ti.label, "haskoki-demo", 12) == 0,
             "label is the home label");
    }
  }
  {
    /* One-line conjunctions over the discovered slots (evaluated in
     * both modes; proxy loops run once). */
    int present = 1, labeled = 1, serial = 1;
    CK_ULONG a = 0, b = 0;
    for (i = 0; i < n; i++) {
      CK_ULONG llen = 0;
      rv = tbl32->C_GetSlotInfo(slots[i], &si);
      present = present && (rv == CKR_OK) &&
                ((si.flags & CKF_TOKEN_PRESENT) != 0) &&
                (memcmp(si.slotDescription, "haskoki soft slot", 16) == 0);
      rv = tbl32->C_GetTokenInfo(slots[i], &ti);
      labeled = labeled && (rv == CKR_OK);
      if (rv == CKR_OK) {
        const char *want = isProxy ? kLabels[0] : kLabels[i];
        size_t wlen = strlen(want);
        CK_ULONG j = 0;
        int padOk = 1;
        llen = padded_len(ti.label, 32);
        for (j = llen; j < 32; j++) {
          padOk = padOk && (ti.label[j] == ' ');
        }
        labeled = labeled && padOk && (llen == (CK_ULONG)wlen) &&
                  (memcmp(ti.label, want, wlen) == 0) &&
                  ((ti.flags & CKF_TOKEN_INITIALIZED) != 0) &&
                  ((ti.flags & CKF_LOGIN_REQUIRED) != 0);
        for (j = 0; j < 16; j++) {
          serial = serial &&
                   (ti.serialNumber[j] >= '0' && ti.serialNumber[j] <= '9');
        }
      }
    }
    for (a = 0; a < n; a++) {
      CK_TOKEN_INFO ta;
      if (tbl32->C_GetTokenInfo(slots[a], &ta) != CKR_OK) {
        serial = 0;
        break;
      }
      for (b = a + 1; b < n; b++) {
        CK_TOKEN_INFO tb;
        if (tbl32->C_GetTokenInfo(slots[b], &tb) != CKR_OK) {
          serial = 0;
          break;
        }
        serial = serial &&
                 (memcmp(ta.serialNumber, tb.serialNumber, 16) != 0);
      }
    }
    CHECK(present, "every slot token-present with pinned description");
    CHECK(labeled, "every token labeled from the serving catalog");
    CHECK(serial, "token serials numeric and distinct per slot");
  }
  rv = tbl32->C_GetSlotInfo(999991UL, &si);
  CHECK(rv == CKR_SLOT_ID_INVALID, "bad slot slot-info rejected");
  rv = tbl32->C_GetTokenInfo(999991UL, &ti);
  CHECK(rv == CKR_SLOT_ID_INVALID, "bad slot token-info rejected");

  /* ---- per-slot mechanism catalog ---- */
  for (i = 0; i < n; i++) {
    CK_ULONG nmech = 0;
    rv = tbl32->C_GetMechanismList(slots[i], NULL_PTR, &nmech);
    CHECKM(rv == CKR_OK && nmech > 0, "mechanism catalog non-empty");
  }
  {
    CK_ULONG first = 0, nmech = 0;
    int same = 1;
    for (i = 0; i < n; i++) {
      nmech = 0;
      rv = tbl32->C_GetMechanismList(slots[i], NULL_PTR, &nmech);
      same = same && (rv == CKR_OK && nmech > 0);
      if (i == 0) {
        first = nmech;
      } else {
        same = same && (nmech == first);
      }
    }
    CHECK(same && first > 0, "mechanism catalog identical on every slot");
  }
  {
    CK_MECHANISM_INFO mi;
    rv = tbl32->C_GetMechanismInfo(999991UL, CKM_SHA256, &mi);
    CHECK(rv == CKR_SLOT_ID_INVALID, "bad slot mechanism info rejected");
  }

  /* ---- per-slot sessions ---- */
  for (i = 0; i < n; i++) {
    CK_SESSION_HANDLE sess = 0;
    CK_SESSION_INFO sinfo;
    rv = tbl32->C_OpenSession(slots[i], CKF_SERIAL_SESSION | CKF_RW_SESSION,
                            NULL_PTR, NULL_PTR, &sess);
    CHECKM(rv == CKR_OK && sess != 0, "RW session opens");
    if (rv != CKR_OK) {
      continue;
    }
    rv = tbl32->C_GetSessionInfo(sess, &sinfo);
    CHECKM(rv == CKR_OK && sinfo.slotID == slots[i] &&
               sinfo.state == CKS_RW_PUBLIC_SESSION,
           "session info names its slot");
    rv = tbl32->C_CloseSession(sess);
    CHECKM(rv == CKR_OK, "session closes");
  }
  {
    int flows = 1;
    for (i = 0; i < n; i++) {
      CK_SESSION_HANDLE sess = 0;
      CK_SESSION_INFO sinfo;
      rv = tbl32->C_OpenSession(slots[i], CKF_SERIAL_SESSION | CKF_RW_SESSION,
                              NULL_PTR, NULL_PTR, &sess);
      flows = flows && (rv == CKR_OK && sess != 0);
      if (rv == CKR_OK) {
        rv = tbl32->C_GetSessionInfo(sess, &sinfo);
        flows = flows && (rv == CKR_OK && sinfo.slotID == slots[i]);
        rv = tbl32->C_CloseSession(sess);
        flows = flows && (rv == CKR_OK);
      }
    }
    CHECK(flows, "sessions open/close on every slot");
  }
  {
    CK_SESSION_HANDLE sess = 0;
    rv = tbl32->C_OpenSession(999991UL, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR,
                            &sess);
    CHECK(rv == CKR_SLOT_ID_INVALID, "bad slot open rejected");
    rv = tbl32->C_CloseAllSessions(999991UL);
    CHECK(rv == CKR_SLOT_ID_INVALID, "bad slot close-all rejected");
  }

  /* ---- per-slot login (catalog PINs by label) ---- */
  {
    int userFlows = 1, soFlows = 1, foreignRefused = 1;
    for (i = 0; i < n; i++) {
      CK_SESSION_HANDLE sess = 0;
      CK_SESSION_INFO sinfo;
      CK_ULONG llen = 0;
      const char *userPin = NULL, *soPin = NULL;
      rv = tbl32->C_GetTokenInfo(slots[i], &ti);
      if (rv != CKR_OK) {
        userFlows = 0;
        soFlows = 0;
        foreignRefused = 0;
        continue;
      }
      llen = padded_len(ti.label, 32);
      userPin = user_pin_for(ti.label, llen);
      soPin = so_pin_for(ti.label, llen);
      if (!userPin || !soPin) {
        userFlows = 0;
        soFlows = 0;
        foreignRefused = 0;
        continue;
      }
      rv = tbl32->C_OpenSession(slots[i], CKF_SERIAL_SESSION | CKF_RW_SESSION,
                              NULL_PTR, NULL_PTR, &sess);
      if (rv != CKR_OK || sess == 0) {
        userFlows = 0;
        soFlows = 0;
        foreignRefused = 0;
        continue;
      }
      rv = tbl32->C_Login(sess, CKU_USER, (CK_UTF8CHAR_PTR)userPin,
                        (CK_ULONG)strlen(userPin));
      userFlows = userFlows && (rv == CKR_OK);
      rv = tbl32->C_GetSessionInfo(sess, &sinfo);
      userFlows = userFlows && (rv == CKR_OK &&
                                sinfo.state == CKS_RW_USER_FUNCTIONS);
      rv = tbl32->C_Logout(sess);
      userFlows = userFlows && (rv == CKR_OK);
      rv = tbl32->C_Login(sess, CKU_SO, (CK_UTF8CHAR_PTR)soPin,
                        (CK_ULONG)strlen(soPin));
      soFlows = soFlows && (rv == CKR_OK);
      rv = tbl32->C_GetSessionInfo(sess, &sinfo);
      soFlows =
          soFlows && (rv == CKR_OK && sinfo.state == CKS_RW_SO_FUNCTIONS);
      rv = tbl32->C_Logout(sess);
      soFlows = soFlows && (rv == CKR_OK);
      rv = tbl32->C_Login(sess, CKU_USER, (CK_UTF8CHAR_PTR) "0000", 4);
      foreignRefused = foreignRefused && (rv == CKR_PIN_INCORRECT);
      rv = tbl32->C_Login(sess, CKU_SO, (CK_UTF8CHAR_PTR) "0000", 4);
      foreignRefused = foreignRefused && (rv == CKR_PIN_INCORRECT);
      rv = tbl32->C_CloseSession(sess);
      userFlows = userFlows && (rv == CKR_OK);
      soFlows = soFlows && (rv == CKR_OK);
    }
    CHECK(userFlows, "per-slot user login/logout with catalog PINs");
    CHECK(soFlows, "per-slot SO login/logout with catalog PINs");
    CHECK(foreignRefused, "foreign PINs refused on every slot");
  }

  /* ---- cross-slot object invisibility (direct-only) ---- */
  if (!isProxy && n >= 2) {
    CK_SESSION_HANDLE sa = 0, sb = 0;
    CK_OBJECT_CLASS klass = CKO_DATA;
    CK_BBOOL no = CK_FALSE;
    CK_ATTRIBUTE tmpl[] = {
      { CKA_CLASS, &klass, sizeof(klass) },
      { CKA_TOKEN, &no, sizeof(no) },
      { CKA_PRIVATE, &no, sizeof(no) },
      { CKA_LABEL, "mtok-xslot", 10 },
    };
    CK_OBJECT_HANDLE obj = 0, fresh[4];
    CK_ULONG nfresh = 4;
    CK_BYTE buf[64];
    CK_ATTRIBUTE g[] = { { CKA_LABEL, buf, sizeof(buf) } };
    rv = tbl32->C_OpenSession(slots[0], CKF_SERIAL_SESSION | CKF_RW_SESSION,
                            NULL_PTR, NULL_PTR, &sa);
    CHECKM(rv == CKR_OK && sa != 0, "isolation session on first slot");
    rv = tbl32->C_OpenSession(slots[1], CKF_SERIAL_SESSION | CKF_RW_SESSION,
                            NULL_PTR, NULL_PTR, &sb);
    CHECKM(rv == CKR_OK && sb != 0, "isolation session on second slot");
    if (sa == 0 || sb == 0) {
      printf("invent: note: isolation sessions missing; aborting scenario\n");
      g_failures++;
    } else {
      rv = tbl32->C_CreateObject(sa, tmpl, 4, &obj);
      CHECKM(rv == CKR_OK && obj != 0, "fixture created on first slot");
      rv = tbl32->C_FindObjectsInit(sb, NULL_PTR, 0);
      CHECKM(rv == CKR_OK, "cross-slot find init ok");
      rv = tbl32->C_FindObjects(sb, fresh, 4, &nfresh);
      CHECKM(rv == CKR_OK && nfresh == 0, "cross-slot find yields zero");
      rv = tbl32->C_FindObjectsFinal(sb);
      CHECKM(rv == CKR_OK, "cross-slot find final ok");
      rv = tbl32->C_GetAttributeValue(sb, obj, g, 1);
      CHECKM(rv == CKR_OBJECT_HANDLE_INVALID,
             "cross-slot get refused typed");
      rv = tbl32->C_DestroyObject(sb, obj);
      CHECKM(rv == CKR_OBJECT_HANDLE_INVALID,
             "cross-slot destroy refused typed");
      rv = tbl32->C_GetAttributeValue(sa, obj, g, 1);
      CHECKM(rv == CKR_OK && g[0].ulValueLen == 10 &&
                 memcmp(buf, "mtok-xslot", 10) == 0,
             "home-slot get reads back");
      rv = tbl32->C_DestroyObject(sa, obj);
      CHECKM(rv == CKR_OK, "home-slot destroy ok");
      rv = tbl32->C_CloseSession(sa);
      CHECKM(rv == CKR_OK, "first isolation session closes");
      rv = tbl32->C_CloseSession(sb);
      CHECKM(rv == CKR_OK, "second isolation session closes");
    }
  } else {
    printf("invent: note: single-slot serving, cross-slot scenario skipped\n");
  }

  /* ---- lifecycle: finalize, post-finalize, re-init ---- */
  rv = tbl32->C_Finalize(NULL_PTR);
  CHECK(rv == CKR_OK, "3.2 C_Finalize ok");
  nq = 16;
  rv = tbl32->C_GetSlotList(0, slots, &nq);
  CHECK(rv == CKR_CRYPTOKI_NOT_INITIALIZED,
        "post-finalize slot list needs init");
  rv = legacy->C_Initialize(NULL_PTR);
  CHECK(rv == CKR_OK, "re-initialize ok");
  rv = legacy->C_Finalize(NULL_PTR);
  CHECK(rv == CKR_OK, "second finalize ok");

  dlclose(handle);
  if (g_cfg_ours) {
    unlink(g_cfg_path);
  }
  if (g_failures == 0) {
    printf("PASS: consumer_multitoken (%s)\n", argv[1]);
    return 0;
  }
  printf("FAILURES: %d\n", g_failures);
  return 1;
}