/* tests/c/consumer_login_reopen.c — the complete C login/write/reopen
 * journey at the C ABI surface (a known storage-testing leftover;
 * no such test existed).
 *
 * Phase A (shared, parity-compared): single-slot discovery, token-label
 * pin, R/W session open, then the honest error legs — a private token
 * write on a public session refuses with CKR_USER_NOT_LOGGED_IN
 * (admitPrivate: only the normal user creates private objects;
 * permitted public-RW mutation of public token objects is pinned
 * by the Phase B matrix below, per the retained standard baseline),
 * a wrong user PIN refuses with CKR_PIN_INCORRECT — followed by a
 * clean user login/logout pair. Every Phase-A line is static text
 * over backend-independent values, so it compares byte-identical
 * direct-vs-proxied (the daemon serves the same home singleton, and
 * every earlier Group-R scenario leaves it logged out and unlocked).
 *
 * Phase B (DIRECT-ONLY, invent:-scoped): the store-level journey the
 * proxy cannot transport, so the V4b matrix semantics give it no
 * parity leg (precedent: consumer_certificates:restart is DIRECT-ONLY
 * — upstream mingulov/pkcs11-proxy-ng#27: client Finalize/Initialize
 * does not reach the daemon-owned store; the client HASKOKI_CONFIG
 * is ignored daemon-side; the Group-R daemon backend is shared
 * across scenarios). Behind the proxy these legs skip loud with an
 * invent: note (the multitoken cross-slot precedent); direct, they
 * assert strictly:
 *   - memory: login -> create two private token CKO_DATA objects ->
 *     find/readback -> close -> Finalize -> Initialize -> login ->
 *     find yields ZERO (memory is interval-scoped: the honest reset;
 *     handles are never compared across the boundary — reopened
 *     stores re-mint handles from fresh counters, so numeric
 *     coincidence would prove nothing);
 *   - sqlite: the same journey against a hermetic temp database, but
 *     after the Finalize/Initialize boundary both objects reload
 *     with byte-equal labels and values (durable), then destroy and
 *     re-verify zero;
 *   - SO: an SO session creating a private token object refuses with
 *     CKR_USER_NOT_LOGGED_IN (SO administers public objects only);
 *   - matrix: public-RW positive control + refusal cells (DIRECT-ONLY).
 *
 * Standalone C consumer (non-Haskell executable): dlopen()s the built
 * libhaskoki shared module and drives it through the pinned 3.2 headers.
 * This TU deliberately includes ONLY the pinned vendor headers; it never
 * consumes provider-generated artifacts (enforced by the driver script's
 * independence guard).
 *
 * Compile with -Ispec/vendor. Part of scripts/test-consumers.sh (globbed
 * automatically like every consumer_*.c) and scripts/test-proxy-parity.sh
 * (Phase A compares; Phase B is diff-excluded by construction).
 * Usage: consumer_login_reopen <path-to-libhaskoki.so>
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

/* Store-level checks: asserted strictly in direct topology but
 * excluded from the parity diff (the journey does not transport
 * across the proxy — see the header note). Failures still fail
 * the run. */
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

static char g_mem_cfg[256];
static char g_sql_cfg[256];
static char g_sql_dir[256];
static char g_sql_db[256];

/* Hermetic configs: the consumer_errors memory body verbatim (home
 * singleton catalog: haskoki-demo / SO 5678 / user 1234), plus the
 * sqlite twin with an explicit fresh path (never silently shared). */
static void write_mem_config(void) {
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
  char tmpl[] = "/tmp/haskoki-login-reopen-XXXXXX";
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
  snprintf(g_mem_cfg, sizeof(g_mem_cfg), "%s", tmpl);
}

static void write_sql_config(void) {
  char tmpl[] = "/tmp/haskoki-login-reopen-db-XXXXXX";
  char body[1024];
  char cfg[] = "/tmp/haskoki-login-reopen-sql-XXXXXX";
  int fd;
  size_t want;
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
}

static void use_config(const char *path) {
  if (setenv("HASKOKI_CONFIG", path, 1) != 0) {
    perror("setenv");
    exit(2);
  }
}

/* Length of a blank-padded label field's non-pad prefix (mirrors
 * consumer_multitoken.c). */
static CK_ULONG padded_len(const CK_UTF8CHAR *field, CK_ULONG width) {
  CK_ULONG n = 0;
  while (n < width && field[n] != ' ') {
    n++;
  }
  return n;
}

int main(int argc, char **argv) {
  CK_RV rv;
  CK_FUNCTION_LIST_PTR f = NULL;
  CK_C_GetFunctionList getList = NULL;
  void *dl = NULL;
  CK_SLOT_ID slots[8] = { 0, 0, 0, 0, 0, 0, 0, 0 };
  CK_ULONG nslots = 8;
  const char *topo;
  int isProxy;

  if (argc != 2) {
    fprintf(stderr, "usage: %s <libhaskoki.so>\n", argv[0]);
    return 2;
  }
  topo = getenv("HASKOKI_CONSUMER_TOPOLOGY");
  isProxy = topo && strcmp(topo, "proxy") == 0;
  printf("topology: %s\n", isProxy ? "proxy" : "direct");
  write_mem_config();
  use_config(g_mem_cfg);
  dl = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
  CHECK(dl != NULL, "dlopen module");
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

  /* ---- Phase A (shared): discovery, error legs, login pair ---- */
  {
    CK_SESSION_HANDLE sess = 0;
    CK_TOKEN_INFO tinf;
    CK_OBJECT_CLASS klass = CKO_DATA;
    CK_BBOOL yes = CK_TRUE;
    CK_OBJECT_HANDLE stale = 0;
    CK_ATTRIBUTE unauth[] = {
      { CKA_CLASS, &klass, sizeof(klass) },
      { CKA_TOKEN, &yes, sizeof(yes) },
      { CKA_PRIVATE, &yes, sizeof(yes) },
      { CKA_LABEL, "c2x-unauth", 10 },
      { CKA_VALUE, "refused", 7 },
    };
    CK_ULONG i;
    int padded = 1;

    rv = f->C_Initialize(NULL_PTR);
    CHECK(rv == CKR_OK, "C_Initialize ok");
    rv = f->C_GetSlotList(CK_TRUE, slots, &nslots);
    CHECK(rv == CKR_OK && nslots == 1, "single token slot");
    rv = f->C_GetTokenInfo(slots[0], &tinf);
    CHECK(rv == CKR_OK, "token info reads");
    for (i = 12; i < 32; i++) {
      if (tinf.label[i] != ' ') {
        padded = 0;
      }
    }
    CHECK(padded_len(tinf.label, 32) == 12 &&
              memcmp(tinf.label, "haskoki-demo", 12) == 0 && padded,
          "token label pins the home singleton");
    rv = f->C_OpenSession(slots[0], CKF_SERIAL_SESSION | CKF_RW_SESSION,
                          NULL_PTR, NULL_PTR, &sess);
    CHECK(rv == CKR_OK && sess != 0, "OpenSession RW ok");
    rv = f->C_CreateObject(sess, unauth, 5, &stale);
    CHECK(rv == CKR_USER_NOT_LOGGED_IN && stale == 0,
          "public write of a private token object refused");
    rv = f->C_Login(sess, CKU_USER, (CK_UTF8CHAR_PTR) "9999", 4);
    CHECK(rv == CKR_PIN_INCORRECT, "wrong user PIN refused");
    rv = f->C_Login(sess, CKU_USER, (CK_UTF8CHAR_PTR) "1234", 4);
    CHECK(rv == CKR_OK, "user login ok");
    rv = f->C_Logout(sess);
    CHECK(rv == CKR_OK, "user logout ok");
    rv = f->C_CloseSession(sess);
    CHECK(rv == CKR_OK, "CloseSession ok");
    rv = f->C_Finalize(NULL_PTR);
    CHECK(rv == CKR_OK, "C_Finalize ok");
  }

  if (isProxy) {
    /* Store-level legs do not transport (header note): the daemon
     * owns the store, so client config switches and client
     * Finalize/Initialize boundaries cannot drive reopen behavior
     * here. Loud skip, exactly like multitoken's cross-slot legs. */
    printf("invent: proxy skips the memory reopen journey\n");
    printf("invent: proxy skips the sqlite reopen journey\n");
    printf("invent: proxy skips the SO private-write leg\n");
    printf("invent: proxy skips the role-matrix legs\n");
    printf("invent: proxy skips the removed-session page legs\n");
  } else {
    /* ---- Phase B/memory: write, close, reopen, honest reset ---- */
    CK_SESSION_HANDLE sess = 0;
    CK_OBJECT_CLASS klass = CKO_DATA;
    CK_BBOOL yes = CK_TRUE;
    CK_OBJECT_HANDLE h1 = 0, h2 = 0;
    CK_ATTRIBUTE tmpl1[] = {
      { CKA_CLASS, &klass, sizeof(klass) },
      { CKA_TOKEN, &yes, sizeof(yes) },
      { CKA_PRIVATE, &yes, sizeof(yes) },
      { CKA_LABEL, "c2x-mem-first", 13 },
      { CKA_VALUE, "mem-payload-one", 15 },
    };
    CK_ATTRIBUTE tmpl2[] = {
      { CKA_CLASS, &klass, sizeof(klass) },
      { CKA_TOKEN, &yes, sizeof(yes) },
      { CKA_PRIVATE, &yes, sizeof(yes) },
      { CKA_LABEL, "c2x-mem-second", 14 },
      { CKA_VALUE, "mem-payload-two", 15 },
    };
    CK_ATTRIBUTE match1[] = { { CKA_LABEL, "c2x-mem-first", 13 } };
    CK_ATTRIBUTE match2[] = { { CKA_LABEL, "c2x-mem-second", 14 } };
    /* Zero-initialized (the so_isolation precedent): a failed find
     * leaves a typed zero handle for dependent reads, never an
     * indeterminate value — the CHECK still records the failure. */
    CK_OBJECT_HANDLE found[4] = { 0, 0, 0, 0 };
    CK_ULONG nfound = 4;
    CK_BYTE label[64];
    CK_BYTE value[64];
    CK_ATTRIBUTE get[] = {
      { CKA_LABEL, label, sizeof(label) },
      { CKA_VALUE, value, sizeof(value) },
    };

    nslots = 8;
    rv = f->C_Initialize(NULL_PTR);
    CHECKM(rv == CKR_OK, "memory: Initialize ok");
    rv = f->C_GetSlotList(CK_TRUE, slots, &nslots);
    CHECKM(rv == CKR_OK && nslots == 1, "memory: single slot again");
    rv = f->C_OpenSession(slots[0], CKF_SERIAL_SESSION | CKF_RW_SESSION,
                          NULL_PTR, NULL_PTR, &sess);
    CHECKM(rv == CKR_OK && sess != 0, "memory: session opens");
    rv = f->C_Login(sess, CKU_USER, (CK_UTF8CHAR_PTR) "1234", 4);
    CHECKM(rv == CKR_OK, "memory: user login ok");
    rv = f->C_CreateObject(sess, tmpl1, 5, &h1);
    CHECKM(rv == CKR_OK && h1 != 0, "memory: first object written");
    rv = f->C_CreateObject(sess, tmpl2, 5, &h2);
    CHECKM(rv == CKR_OK && h2 != 0 && h2 != h1,
           "memory: second object written");
    rv = f->C_FindObjectsInit(sess, match1, 1);
    CHECKM(rv == CKR_OK, "memory: find init ok");
    nfound = 4;
    rv = f->C_FindObjects(sess, found, 4, &nfound);
    CHECKM(rv == CKR_OK && nfound == 1, "memory: first object found");
    rv = f->C_FindObjectsFinal(sess);
    CHECKM(rv == CKR_OK, "memory: find final ok");
    /* The read resets ulValueLen to the served sizes: re-arm the
     * buffer lengths before every call. */
    get[0].ulValueLen = sizeof(label);
    get[1].ulValueLen = sizeof(value);
    rv = f->C_GetAttributeValue(sess, found[0], get, 2);
    CHECKM(rv == CKR_OK && get[0].ulValueLen == 13 &&
               memcmp(label, "c2x-mem-first", 13) == 0 &&
               get[1].ulValueLen == 15 &&
               memcmp(value, "mem-payload-one", 15) == 0,
           "memory: label and value read back");
    rv = f->C_FindObjectsInit(sess, match2, 1);
    CHECKM(rv == CKR_OK, "memory: second find init ok");
    nfound = 4;
    rv = f->C_FindObjects(sess, found, 4, &nfound);
    CHECKM(rv == CKR_OK && nfound == 1, "memory: second object found");
    rv = f->C_FindObjectsFinal(sess);
    CHECKM(rv == CKR_OK, "memory: second find final ok");
    get[0].ulValueLen = sizeof(label);
    get[1].ulValueLen = sizeof(value);
    rv = f->C_GetAttributeValue(sess, found[0], get, 2);
    CHECKM(rv == CKR_OK && get[0].ulValueLen == 14 &&
               memcmp(label, "c2x-mem-second", 14) == 0 &&
               get[1].ulValueLen == 15 &&
               memcmp(value, "mem-payload-two", 15) == 0,
           "memory: second label and value read back");
    rv = f->C_Logout(sess);
    CHECKM(rv == CKR_OK, "memory: logout before SO leg");
    rv = f->C_Login(sess, CKU_SO, (CK_UTF8CHAR_PTR) "5678", 4);
    CHECKM(rv == CKR_OK, "memory: SO login ok");
    {
      CK_OBJECT_HANDLE refused = 0;
      rv = f->C_CreateObject(sess, tmpl1, 5, &refused);
      CHECKM(rv == CKR_USER_NOT_LOGGED_IN && refused == 0,
             "memory: SO private write refused");
    }
    rv = f->C_Logout(sess);
    CHECKM(rv == CKR_OK, "memory: SO logout ok");
    rv = f->C_CloseSession(sess);
    CHECKM(rv == CKR_OK, "memory: session closes");
    rv = f->C_Finalize(NULL_PTR);
    CHECKM(rv == CKR_OK, "memory: store closed");
    /* Reopen the same memory identity: interval-scoped state is
     * honestly gone — the fresh generation serves zero objects. */
    sess = 0;
    nslots = 8;
    rv = f->C_Initialize(NULL_PTR);
    CHECKM(rv == CKR_OK, "memory: reopen ok");
    rv = f->C_GetSlotList(CK_TRUE, slots, &nslots);
    CHECKM(rv == CKR_OK && nslots == 1, "memory: slot survives reopen");
    rv = f->C_OpenSession(slots[0], CKF_SERIAL_SESSION | CKF_RW_SESSION,
                          NULL_PTR, NULL_PTR, &sess);
    CHECKM(rv == CKR_OK && sess != 0, "memory: session reopens");
    rv = f->C_Login(sess, CKU_USER, (CK_UTF8CHAR_PTR) "1234", 4);
    CHECKM(rv == CKR_OK, "memory: login required again after reopen");
    rv = f->C_FindObjectsInit(sess, match1, 1);
    CHECKM(rv == CKR_OK, "memory: post-reopen find init ok");
    nfound = 4;
    rv = f->C_FindObjects(sess, found, 4, &nfound);
    CHECKM(rv == CKR_OK && nfound == 0, "memory: first object reset");
    rv = f->C_FindObjectsFinal(sess);
    CHECKM(rv == CKR_OK, "memory: post-reopen find final ok");
    rv = f->C_FindObjectsInit(sess, match2, 1);
    CHECKM(rv == CKR_OK, "memory: second find init ok");
    nfound = 4;
    rv = f->C_FindObjects(sess, found, 4, &nfound);
    CHECKM(rv == CKR_OK && nfound == 0, "memory: second object reset");
    rv = f->C_FindObjectsFinal(sess);
    CHECKM(rv == CKR_OK, "memory: second find final ok");
    rv = f->C_Logout(sess);
    CHECKM(rv == CKR_OK, "memory: final logout ok");
    rv = f->C_CloseSession(sess);
    CHECKM(rv == CKR_OK, "memory: final close ok");
    rv = f->C_Finalize(NULL_PTR);
    CHECKM(rv == CKR_OK, "memory: final finalize ok");

    /* ---- Phase B/sqlite: write, close, reopen, durable ---- */
    {
      CK_ATTRIBUTE tmpl1[] = {
        { CKA_CLASS, &klass, sizeof(klass) },
        { CKA_TOKEN, &yes, sizeof(yes) },
        { CKA_PRIVATE, &yes, sizeof(yes) },
        { CKA_LABEL, "c2x-sql-first", 13 },
        { CKA_VALUE, "sql-payload-one", 15 },
      };
      CK_ATTRIBUTE tmpl2[] = {
        { CKA_CLASS, &klass, sizeof(klass) },
        { CKA_TOKEN, &yes, sizeof(yes) },
        { CKA_PRIVATE, &yes, sizeof(yes) },
        { CKA_LABEL, "c2x-sql-second", 14 },
        { CKA_VALUE, "sql-payload-two", 15 },
      };
      CK_ATTRIBUTE match1[] = { { CKA_LABEL, "c2x-sql-first", 13 } };
      CK_ATTRIBUTE match2[] = { { CKA_LABEL, "c2x-sql-second", 14 } };

      write_sql_config();
      use_config(g_sql_cfg);
      sess = 0;
      h1 = 0;
      h2 = 0;
      nslots = 8;
      rv = f->C_Initialize(NULL_PTR);
      CHECKM(rv == CKR_OK, "sqlite: Initialize ok");
      rv = f->C_GetSlotList(CK_TRUE, slots, &nslots);
      CHECKM(rv == CKR_OK && nslots == 1, "sqlite: single slot");
      rv = f->C_OpenSession(slots[0], CKF_SERIAL_SESSION | CKF_RW_SESSION,
                            NULL_PTR, NULL_PTR, &sess);
      CHECKM(rv == CKR_OK && sess != 0, "sqlite: session opens");
      rv = f->C_Login(sess, CKU_USER, (CK_UTF8CHAR_PTR) "1234", 4);
      CHECKM(rv == CKR_OK, "sqlite: user login ok");
      rv = f->C_CreateObject(sess, tmpl1, 5, &h1);
      CHECKM(rv == CKR_OK && h1 != 0, "sqlite: first object written");
      rv = f->C_CreateObject(sess, tmpl2, 5, &h2);
      CHECKM(rv == CKR_OK && h2 != 0 && h2 != h1,
             "sqlite: second object written");
      rv = f->C_FindObjectsInit(sess, match1, 1);
      CHECKM(rv == CKR_OK, "sqlite: find init ok");
      nfound = 4;
      rv = f->C_FindObjects(sess, found, 4, &nfound);
      CHECKM(rv == CKR_OK && nfound == 1, "sqlite: first object found");
      rv = f->C_FindObjectsFinal(sess);
      CHECKM(rv == CKR_OK, "sqlite: find final ok");
      get[0].ulValueLen = sizeof(label);
      get[1].ulValueLen = sizeof(value);
      rv = f->C_GetAttributeValue(sess, found[0], get, 2);
      CHECKM(rv == CKR_OK && get[0].ulValueLen == 13 &&
                 memcmp(label, "c2x-sql-first", 13) == 0 &&
                 get[1].ulValueLen == 15 &&
                 memcmp(value, "sql-payload-one", 15) == 0,
             "sqlite: label and value read back");
      rv = f->C_FindObjectsInit(sess, match2, 1);
      CHECKM(rv == CKR_OK, "sqlite: pre-close second find init ok");
      nfound = 4;
      rv = f->C_FindObjects(sess, found, 4, &nfound);
      CHECKM(rv == CKR_OK && nfound == 1, "sqlite: second object found");
      rv = f->C_FindObjectsFinal(sess);
      CHECKM(rv == CKR_OK, "sqlite: pre-close second find final ok");
      get[0].ulValueLen = sizeof(label);
      get[1].ulValueLen = sizeof(value);
      rv = f->C_GetAttributeValue(sess, found[0], get, 2);
      CHECKM(rv == CKR_OK && get[0].ulValueLen == 14 &&
                 memcmp(label, "c2x-sql-second", 14) == 0 &&
                 get[1].ulValueLen == 15 &&
                 memcmp(value, "sql-payload-two", 15) == 0,
             "sqlite: second label and value read back");
      rv = f->C_Logout(sess);
      CHECKM(rv == CKR_OK, "sqlite: logout ok");
      rv = f->C_CloseSession(sess);
      CHECKM(rv == CKR_OK, "sqlite: session closes");
      rv = f->C_Finalize(NULL_PTR);
      CHECKM(rv == CKR_OK, "sqlite: store closed");
      /* Reopen the SAME database path: both objects reload with
       * byte-equal labels and values — the durability pin. */
      sess = 0;
      nslots = 8;
      rv = f->C_Initialize(NULL_PTR);
      CHECKM(rv == CKR_OK, "sqlite: reopen ok");
      rv = f->C_GetSlotList(CK_TRUE, slots, &nslots);
      CHECKM(rv == CKR_OK && nslots == 1, "sqlite: slot survives reopen");
      rv = f->C_OpenSession(slots[0], CKF_SERIAL_SESSION | CKF_RW_SESSION,
                            NULL_PTR, NULL_PTR, &sess);
      CHECKM(rv == CKR_OK && sess != 0, "sqlite: session reopens");
      rv = f->C_Login(sess, CKU_USER, (CK_UTF8CHAR_PTR) "1234", 4);
      CHECKM(rv == CKR_OK, "sqlite: login required again after reopen");
      rv = f->C_FindObjectsInit(sess, match1, 1);
      CHECKM(rv == CKR_OK, "sqlite: post-reopen find init ok");
      nfound = 4;
      rv = f->C_FindObjects(sess, found, 4, &nfound);
      CHECKM(rv == CKR_OK && nfound == 1,
             "sqlite: first object durable across reopen");
      rv = f->C_FindObjectsFinal(sess);
      CHECKM(rv == CKR_OK, "sqlite: post-reopen find final ok");
      get[0].ulValueLen = sizeof(label);
      get[1].ulValueLen = sizeof(value);
      rv = f->C_GetAttributeValue(sess, found[0], get, 2);
      CHECKM(rv == CKR_OK && get[0].ulValueLen == 13 &&
                 memcmp(label, "c2x-sql-first", 13) == 0 &&
                 get[1].ulValueLen == 15 &&
                 memcmp(value, "sql-payload-one", 15) == 0,
             "sqlite: first object bytes durable");
      rv = f->C_FindObjectsInit(sess, match2, 1);
      CHECKM(rv == CKR_OK, "sqlite: second find init ok");
      nfound = 4;
      rv = f->C_FindObjects(sess, found, 4, &nfound);
      CHECKM(rv == CKR_OK && nfound == 1,
             "sqlite: second object durable across reopen");
      rv = f->C_FindObjectsFinal(sess);
      CHECKM(rv == CKR_OK, "sqlite: second find final ok");
      get[0].ulValueLen = sizeof(label);
      get[1].ulValueLen = sizeof(value);
      rv = f->C_GetAttributeValue(sess, found[0], get, 2);
      CHECKM(rv == CKR_OK && get[0].ulValueLen == 14 &&
                 memcmp(label, "c2x-sql-second", 14) == 0 &&
                 get[1].ulValueLen == 15 &&
                 memcmp(value, "sql-payload-two", 15) == 0,
             "sqlite: second object bytes durable");
      rv = f->C_DestroyObject(sess, found[0]);
      CHECKM(rv == CKR_OK, "sqlite: second object destroyed");
      rv = f->C_FindObjectsInit(sess, match1, 1);
      CHECKM(rv == CKR_OK, "sqlite: destroy-verify find init ok");
      nfound = 4;
      rv = f->C_FindObjects(sess, found, 4, &nfound);
      CHECKM(rv == CKR_OK && nfound == 1, "sqlite: first still present");
      rv = f->C_FindObjectsFinal(sess);
      CHECKM(rv == CKR_OK, "sqlite: destroy-verify find final ok");
      rv = f->C_DestroyObject(sess, found[0]);
      CHECKM(rv == CKR_OK, "sqlite: first object destroyed");
      rv = f->C_FindObjectsInit(sess, match1, 1);
      CHECKM(rv == CKR_OK, "sqlite: empty-verify find init ok");
      nfound = 4;
      rv = f->C_FindObjects(sess, found, 4, &nfound);
      CHECKM(rv == CKR_OK && nfound == 0, "sqlite: first object gone");
      rv = f->C_FindObjectsFinal(sess);
      CHECKM(rv == CKR_OK, "sqlite: empty-verify find final ok");
      rv = f->C_FindObjectsInit(sess, match2, 1);
      CHECKM(rv == CKR_OK, "sqlite: empty-verify second find init ok");
      nfound = 4;
      rv = f->C_FindObjects(sess, found, 4, &nfound);
      CHECKM(rv == CKR_OK && nfound == 0, "sqlite: second object gone");
      rv = f->C_FindObjectsFinal(sess);
      CHECKM(rv == CKR_OK, "sqlite: empty-verify second find final ok");
      rv = f->C_Logout(sess);
      CHECKM(rv == CKR_OK, "sqlite: final logout ok");
      rv = f->C_CloseSession(sess);
      CHECKM(rv == CKR_OK, "sqlite: final close ok");
      rv = f->C_Finalize(NULL_PTR);
      CHECKM(rv == CKR_OK, "sqlite: final finalize ok");
    }

    /* ---- Phase B/matrix: public-RW positive control + refusal cells ----
     * Fresh memory interval. Order is load-bearing: token login is
     * token-global, cross-role login denies, and SO login is refused
     * while any read-only session is open. So public legs run logged
     * out, user legs run between login/logout (RO-shape checks use
     * pubro while usr holds the user login), pubro closes before the
     * SO legs, and visibility runs logged out again. */
    {
      CK_SESSION_HANDLE pubrw = 0, pubro = 0, usr = 0, so = 0;
      CK_OBJECT_CLASS klass = CKO_DATA;
      CK_BBOOL yes = CK_TRUE, no = CK_FALSE;
      CK_OBJECT_HANDLE h = 0, h2 = 0;
      CK_BYTE label[64], value[64];
      CK_ATTRIBUTE get[] = { { CKA_LABEL, label, sizeof(label) },
                             { CKA_VALUE, value, sizeof(value) } };
      CK_ATTRIBUTE pubtok[] = {
        { CKA_CLASS, &klass, sizeof(klass) },
        { CKA_TOKEN, &yes, sizeof(yes) },
        { CKA_PRIVATE, &no, sizeof(no) },
        { CKA_LABEL, "matrix-pub", 10 },
        { CKA_VALUE, "matrix-bytes", 12 },
      };
      CK_ATTRIBUTE privtok[] = {
        { CKA_CLASS, &klass, sizeof(klass) },
        { CKA_TOKEN, &yes, sizeof(yes) },
        { CKA_PRIVATE, &yes, sizeof(yes) },
        { CKA_LABEL, "matrix-priv", 11 },
        { CKA_VALUE, "secret-bytes", 12 },
      };
      CK_ATTRIBUTE pubsess[] = {
        { CKA_CLASS, &klass, sizeof(klass) },
        { CKA_TOKEN, &no, sizeof(no) },
        { CKA_PRIVATE, &no, sizeof(no) },
        { CKA_LABEL, "matrix-psess", 12 },
        { CKA_VALUE, "sess-bytes", 10 },
      };
      CK_ATTRIBUTE privsess[] = {
        { CKA_CLASS, &klass, sizeof(klass) },
        { CKA_TOKEN, &no, sizeof(no) },
        { CKA_PRIVATE, &yes, sizeof(yes) },
        { CKA_LABEL, "matrix-vsess", 12 },
        { CKA_VALUE, "vess-secret", 11 },
      };
      CK_ATTRIBUTE trustedtok[] = {
        { CKA_CLASS, &klass, sizeof(klass) },
        { CKA_TOKEN, &yes, sizeof(yes) },
        { CKA_PRIVATE, &no, sizeof(no) },
        { CKA_LABEL, "matrix-trust", 12 },
        { CKA_VALUE, "trust-bytes", 11 },
        { CKA_TRUSTED, &yes, sizeof(yes) },
      };
      nslots = 8;
      use_config(g_mem_cfg);
      rv = f->C_Initialize(NULL_PTR);
      CHECKM(rv == CKR_OK, "matrix: Initialize ok");
      rv = f->C_GetSlotList(CK_TRUE, slots, &nslots);
      CHECKM(rv == CKR_OK && nslots == 1, "matrix: single slot");
      rv = f->C_OpenSession(slots[0], CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &pubrw);
      CHECKM(rv == CKR_OK && pubrw != 0, "matrix: public RW opens");
      rv = f->C_OpenSession(slots[0], CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &pubro);
      CHECKM(rv == CKR_OK && pubro != 0, "matrix: public RO opens");
      rv = f->C_OpenSession(slots[0], CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &usr);
      CHECKM(rv == CKR_OK && usr != 0, "matrix: user RW opens");
      rv = f->C_OpenSession(slots[0], CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &so);
      CHECKM(rv == CKR_OK && so != 0, "matrix: SO RW opens");
      /* 1. PUBLIC legs while logged out: the positive control + public refusals */
      h = 0;
      rv = f->C_CreateObject(pubrw, pubtok, 5, &h);
      CHECKM(rv == CKR_OK && h != 0, "matrix: public RW creates public token object");
      memset(label, 0xa5, sizeof(label)); memset(value, 0xa5, sizeof(value));
      get[0].ulValueLen = sizeof(label);
      get[1].ulValueLen = sizeof(value);
      rv = f->C_GetAttributeValue(pubrw, h, get, 2);
      CHECKM(rv == CKR_OK && get[0].ulValueLen == 10 &&
                 memcmp(label, "matrix-pub", 10) == 0 &&
                 get[1].ulValueLen == 12 &&
                 memcmp(value, "matrix-bytes", 12) == 0,
             "matrix: public readback matches");
      { CK_ATTRIBUTE over[] = { { CKA_LABEL, "matrix-copy", 11 } };
        h2 = 0;
        rv = f->C_CopyObject(pubrw, h, over, 1, &h2);
        CHECKM(rv == CKR_OK && h2 != 0 && h2 != h, "matrix: public RW copies public token object"); }
      memset(label, 0xa5, sizeof(label)); memset(value, 0xa5, sizeof(value));
      get[0].ulValueLen = sizeof(label);
      get[1].ulValueLen = sizeof(value);
      rv = f->C_GetAttributeValue(pubrw, h2, get, 2);
      CHECKM(rv == CKR_OK && get[0].ulValueLen == 11 &&
                 memcmp(label, "matrix-copy", 11) == 0 &&
                 get[1].ulValueLen == 12 &&
                 memcmp(value, "matrix-bytes", 12) == 0,
             "matrix: public copy readback matches");
      { CK_ATTRIBUTE set[] = { { CKA_LABEL, "matrix-set", 10 } };
        rv = f->C_SetAttributeValue(pubrw, h, set, 1);
        CHECKM(rv == CKR_OK, "matrix: public RW sets label on public token object"); }
      memset(label, 0xa5, sizeof(label)); memset(value, 0xa5, sizeof(value));
      get[0].ulValueLen = sizeof(label);
      get[1].ulValueLen = sizeof(value);
      rv = f->C_GetAttributeValue(pubrw, h, get, 2);
      CHECKM(rv == CKR_OK && get[0].ulValueLen == 10 &&
                 memcmp(label, "matrix-set", 10) == 0 &&
                 get[1].ulValueLen == 12 &&
                 memcmp(value, "matrix-bytes", 12) == 0,
             "matrix: public set readback matches");
      rv = f->C_DestroyObject(pubrw, h);
      CHECKM(rv == CKR_OK, "matrix: public RW destroys public token object");
      rv = f->C_DestroyObject(pubrw, h2);
      CHECKM(rv == CKR_OK, "matrix: public RW destroys the copy");
      h = 0;
      rv = f->C_CreateObject(pubrw, privtok, 5, &h);
      CHECKM(rv == CKR_USER_NOT_LOGGED_IN && h == 0, "matrix: public RW private create refused");
      h = 0;
      rv = f->C_CreateObject(pubro, pubtok, 5, &h);
      CHECKM(rv == CKR_SESSION_READ_ONLY && h == 0, "matrix: public RO token create refused");
      /* A keeper for the public-RO set refusal: pubro observes the same
       * logged-out token state, so the set refuses read-only. */
      h = 0;
      rv = f->C_CreateObject(pubrw, pubtok, 5, &h);
      CHECKM(rv == CKR_OK && h != 0, "matrix: public RO refusal keeper written");
      { CK_ATTRIBUTE set[] = { { CKA_LABEL, "matrix-roset", 12 } };
        rv = f->C_SetAttributeValue(pubro, h, set, 1);
        CHECKM(rv == CKR_SESSION_READ_ONLY, "matrix: public RO set on token object refused"); }
      rv = f->C_DestroyObject(pubrw, h);
      CHECKM(rv == CKR_OK, "matrix: public RO refusal keeper destroyed");
      /* 2. USER legs: login, full positive incl. private token, RO cells,
       * user-TRUSTED refusals, logout. */
      rv = f->C_Login(usr, CKU_USER, (CK_UTF8CHAR_PTR)"1234", 4);
      CHECKM(rv == CKR_OK, "matrix: user login");
      h = 0;
      rv = f->C_CreateObject(usr, privtok, 5, &h);
      CHECKM(rv == CKR_OK && h != 0, "matrix: user RW creates private token object");
      memset(label, 0xa5, sizeof(label)); memset(value, 0xa5, sizeof(value));
      get[0].ulValueLen = sizeof(label);
      get[1].ulValueLen = sizeof(value);
      rv = f->C_GetAttributeValue(usr, h, get, 2);
      CHECKM(rv == CKR_OK && get[0].ulValueLen == 11 &&
                 memcmp(label, "matrix-priv", 11) == 0 &&
                 get[1].ulValueLen == 12 &&
                 memcmp(value, "secret-bytes", 12) == 0,
             "matrix: user private readback matches");
      { CK_ATTRIBUTE over[] = { { CKA_LABEL, "matrix-pcopy", 12 } };
        h2 = 0;
        rv = f->C_CopyObject(usr, h, over, 1, &h2);
        CHECKM(rv == CKR_OK && h2 != 0 && h2 != h, "matrix: user RW copies private token object"); }
      memset(label, 0xa5, sizeof(label)); memset(value, 0xa5, sizeof(value));
      get[0].ulValueLen = sizeof(label);
      get[1].ulValueLen = sizeof(value);
      rv = f->C_GetAttributeValue(usr, h2, get, 2);
      CHECKM(rv == CKR_OK && get[0].ulValueLen == 12 &&
                 memcmp(label, "matrix-pcopy", 12) == 0 &&
                 get[1].ulValueLen == 12 &&
                 memcmp(value, "secret-bytes", 12) == 0,
             "matrix: user copy readback matches");
      { CK_ATTRIBUTE set[] = { { CKA_LABEL, "matrix-pset", 11 } };
        rv = f->C_SetAttributeValue(usr, h, set, 1);
        CHECKM(rv == CKR_OK, "matrix: user RW sets label on private token object"); }
      memset(label, 0xa5, sizeof(label)); memset(value, 0xa5, sizeof(value));
      get[0].ulValueLen = sizeof(label);
      get[1].ulValueLen = sizeof(value);
      rv = f->C_GetAttributeValue(usr, h, get, 2);
      CHECKM(rv == CKR_OK && get[0].ulValueLen == 11 &&
                 memcmp(label, "matrix-pset", 11) == 0 &&
                 get[1].ulValueLen == 12 &&
                 memcmp(value, "secret-bytes", 12) == 0,
             "matrix: user set readback matches");
      rv = f->C_DestroyObject(usr, h);
      CHECKM(rv == CKR_OK, "matrix: user RW destroys private token object");
      rv = f->C_DestroyObject(usr, h2);
      CHECKM(rv == CKR_OK, "matrix: user RW destroys the private copy");
      /* User RO cells: pubro observes the token-global user login. */
      h = 0;
      rv = f->C_CreateObject(pubro, pubtok, 5, &h);
      CHECKM(rv == CKR_SESSION_READ_ONLY && h == 0, "matrix: user RO token create refused");
      h = 0;
      rv = f->C_CreateObject(pubro, privtok, 5, &h);
      CHECKM(rv == CKR_SESSION_READ_ONLY && h == 0, "matrix: user RO private token create refused");
      h = 0;
      rv = f->C_CreateObject(pubro, pubsess, 5, &h);
      CHECKM(rv == CKR_OK && h != 0, "matrix: user RO creates public session object");
      h2 = 0;
      rv = f->C_CreateObject(pubro, privsess, 5, &h2);
      CHECKM(rv == CKR_OK && h2 != 0 && h2 != h, "matrix: user RO creates private session object");
      rv = f->C_DestroyObject(pubro, h);
      CHECKM(rv == CKR_OK, "matrix: user RO destroys public session object");
      rv = f->C_DestroyObject(pubro, h2);
      CHECKM(rv == CKR_OK, "matrix: user RO destroys private session object");
      /* A public token keeper for the RO set/destroy and TRUSTED legs. */
      h = 0;
      rv = f->C_CreateObject(usr, pubtok, 5, &h);
      CHECKM(rv == CKR_OK && h != 0, "matrix: user RW creates keeper public token object");
      { CK_ATTRIBUTE set[] = { { CKA_LABEL, "matrix-roset", 12 } };
        rv = f->C_SetAttributeValue(pubro, h, set, 1);
        CHECKM(rv == CKR_SESSION_READ_ONLY, "matrix: user RO set on token object refused"); }
      rv = f->C_DestroyObject(pubro, h);
      CHECKM(rv == CKR_SESSION_READ_ONLY, "matrix: user RO destroy of token object refused");
      h2 = 0;
      rv = f->C_CreateObject(usr, trustedtok, 6, &h2);
      CHECKM(rv == CKR_ATTRIBUTE_READ_ONLY && h2 == 0, "matrix: user TRUSTED create refused");
      { CK_ATTRIBUTE set[] = { { CKA_TRUSTED, &yes, sizeof(yes) } };
        rv = f->C_SetAttributeValue(usr, h, set, 1);
        CHECKM(rv == CKR_ATTRIBUTE_READ_ONLY, "matrix: user TRUSTED set refused"); }
      rv = f->C_DestroyObject(usr, h);
      CHECKM(rv == CKR_OK, "matrix: user RW destroys the keeper");
      rv = f->C_Logout(usr);
      CHECKM(rv == CKR_OK, "matrix: user logout");
      /* pubro MUST close before SO login (else READ_ONLY_EXISTS); it stays closed:
       * an RO session cannot be reopened under SO login. All remaining RO-shape
       * checks are done; visibility runs logged out below. */
      rv = f->C_CloseSession(pubro);
      CHECKM(rv == CKR_OK, "matrix: public RO closes before SO");
      pubro = 0;
      /* 3. SO legs: login, public positives, private refusal, trusted split,
       * logout. */
      rv = f->C_Login(so, CKU_SO, (CK_UTF8CHAR_PTR)"5678", 4);
      CHECKM(rv == CKR_OK, "matrix: SO login");
      h = 0;
      rv = f->C_CreateObject(so, privtok, 5, &h);
      CHECKM(rv == CKR_USER_NOT_LOGGED_IN && h == 0, "matrix: SO private create refused");
      h = 0;
      rv = f->C_CreateObject(so, pubtok, 5, &h);
      CHECKM(rv == CKR_OK && h != 0, "matrix: SO creates public token object");
      memset(label, 0xa5, sizeof(label)); memset(value, 0xa5, sizeof(value));
      get[0].ulValueLen = sizeof(label);
      get[1].ulValueLen = sizeof(value);
      rv = f->C_GetAttributeValue(so, h, get, 2);
      CHECKM(rv == CKR_OK && get[0].ulValueLen == 10 &&
                 memcmp(label, "matrix-pub", 10) == 0 &&
                 get[1].ulValueLen == 12 &&
                 memcmp(value, "matrix-bytes", 12) == 0,
             "matrix: SO readback matches");
      { CK_ATTRIBUTE over[] = { { CKA_LABEL, "matrix-copy", 11 } };
        h2 = 0;
        rv = f->C_CopyObject(so, h, over, 1, &h2);
        CHECKM(rv == CKR_OK && h2 != 0 && h2 != h, "matrix: SO copies public token object"); }
      memset(label, 0xa5, sizeof(label)); memset(value, 0xa5, sizeof(value));
      get[0].ulValueLen = sizeof(label);
      get[1].ulValueLen = sizeof(value);
      rv = f->C_GetAttributeValue(so, h2, get, 2);
      CHECKM(rv == CKR_OK && get[0].ulValueLen == 11 &&
                 memcmp(label, "matrix-copy", 11) == 0 &&
                 get[1].ulValueLen == 12 &&
                 memcmp(value, "matrix-bytes", 12) == 0,
             "matrix: SO copy readback matches");
      { CK_ATTRIBUTE set[] = { { CKA_LABEL, "matrix-set", 10 } };
        rv = f->C_SetAttributeValue(so, h, set, 1);
        CHECKM(rv == CKR_OK, "matrix: SO sets label on public token object"); }
      memset(label, 0xa5, sizeof(label)); memset(value, 0xa5, sizeof(value));
      get[0].ulValueLen = sizeof(label);
      get[1].ulValueLen = sizeof(value);
      rv = f->C_GetAttributeValue(so, h, get, 2);
      CHECKM(rv == CKR_OK && get[0].ulValueLen == 10 &&
                 memcmp(label, "matrix-set", 10) == 0 &&
                 get[1].ulValueLen == 12 &&
                 memcmp(value, "matrix-bytes", 12) == 0,
             "matrix: SO set readback matches");
      rv = f->C_DestroyObject(so, h);
      CHECKM(rv == CKR_OK, "matrix: SO destroys public token object");
      rv = f->C_DestroyObject(so, h2);
      CHECKM(rv == CKR_OK, "matrix: SO destroys the copy");
      h = 0;
      rv = f->C_CreateObject(so, trustedtok, 6, &h);
      CHECKM(rv == CKR_OK && h != 0, "matrix: SO creates TRUSTED object");
      h2 = 0;
      rv = f->C_CreateObject(so, pubtok, 5, &h2);
      CHECKM(rv == CKR_OK && h2 != 0 && h2 != h, "matrix: SO creates plain target");
      { CK_ATTRIBUTE set[] = { { CKA_TRUSTED, &yes, sizeof(yes) } };
        rv = f->C_SetAttributeValue(so, h2, set, 1);
        CHECKM(rv == CKR_OK, "matrix: SO sets TRUSTED on plain target"); }
      rv = f->C_DestroyObject(so, h);
      CHECKM(rv == CKR_OK, "matrix: SO destroys TRUSTED object");
      rv = f->C_DestroyObject(so, h2);
      CHECKM(rv == CKR_OK, "matrix: SO destroys the plain target");
      rv = f->C_Logout(so);
      CHECKM(rv == CKR_OK, "matrix: SO logout");
      /* 4. visibility, logged out again: find-all over one public + one
       * private token object yields exactly the public handle (the
       * trailing found slot stays a zero canary); the remembered
       * private handle refuses. */
      rv = f->C_Login(usr, CKU_USER, (CK_UTF8CHAR_PTR)"1234", 4);
      CHECKM(rv == CKR_OK, "matrix: visibility setup login");
      h = 0;
      rv = f->C_CreateObject(usr, pubtok, 5, &h);
      CHECKM(rv == CKR_OK && h != 0, "matrix: visibility public object written");
      h2 = 0;
      rv = f->C_CreateObject(usr, privtok, 5, &h2);
      CHECKM(rv == CKR_OK && h2 != 0 && h2 != h, "matrix: visibility private object written");
      rv = f->C_Logout(usr);
      CHECKM(rv == CKR_OK, "matrix: visibility logout");
      memset(found, 0, sizeof(found));
      nfound = 4;
      rv = f->C_FindObjectsInit(pubrw, NULL_PTR, 0);
      CHECKM(rv == CKR_OK, "matrix: visibility find init ok");
      nfound = 4;
      rv = f->C_FindObjects(pubrw, found, 4, &nfound);
      CHECKM(rv == CKR_OK && nfound == 1 && found[1] == 0,
             "matrix: visibility find yields the public handle only");
      rv = f->C_FindObjectsFinal(pubrw);
      CHECKM(rv == CKR_OK, "matrix: visibility find final ok");
      memset(label, 0xa5, sizeof(label)); memset(value, 0xa5, sizeof(value));
      get[0].ulValueLen = sizeof(label);
      get[1].ulValueLen = sizeof(value);
      rv = f->C_GetAttributeValue(pubrw, found[0], get, 2);
      CHECKM(rv == CKR_OK && get[0].ulValueLen == 10 &&
                 memcmp(label, "matrix-pub", 10) == 0,
             "matrix: visibility found handle is the public object");
      rv = f->C_DestroyObject(pubrw, h2);
      CHECKM(rv == CKR_OBJECT_HANDLE_INVALID, "matrix: remembered private handle refused");
      rv = f->C_Login(usr, CKU_USER, (CK_UTF8CHAR_PTR)"1234", 4);
      CHECKM(rv == CKR_OK, "matrix: visibility cleanup login");
      memset(found, 0, sizeof(found));
      nfound = 4;
      rv = f->C_FindObjectsInit(usr, NULL_PTR, 0);
      CHECKM(rv == CKR_OK, "matrix: cleanup find init ok");
      nfound = 4;
      rv = f->C_FindObjects(usr, found, 4, &nfound);
      CHECKM(rv == CKR_OK && nfound == 2, "matrix: cleanup find yields both objects");
      rv = f->C_FindObjectsFinal(usr);
      CHECKM(rv == CKR_OK, "matrix: cleanup find final ok");
      rv = f->C_DestroyObject(usr, found[0]);
      CHECKM(rv == CKR_OK, "matrix: cleanup destroys first object");
      rv = f->C_DestroyObject(usr, found[1]);
      CHECKM(rv == CKR_OK, "matrix: cleanup destroys second object");
      rv = f->C_Logout(usr);
      CHECKM(rv == CKR_OK, "matrix: visibility cleanup logout");
      rv = f->C_CloseSession(pubrw);
      CHECKM(rv == CKR_OK, "matrix: public RW closes");
      rv = f->C_CloseSession(usr);
      CHECKM(rv == CKR_OK, "matrix: user session closes");
      rv = f->C_CloseSession(so);
      CHECKM(rv == CKR_OK, "matrix: SO session closes");
      rv = f->C_Finalize(NULL_PTR);
      CHECKM(rv == CKR_OK, "matrix: Finalize ok");
    }

    /* ---- Phase B/find-page: removed-session page refuses first ---- */
    {
      CK_SESSION_HANDLE sess = 0, fresh = 0;
      CK_OBJECT_CLASS klass = CKO_DATA;
      CK_BBOOL no = CK_FALSE;
      CK_OBJECT_HANDLE h1 = 0, h2 = 0;
      CK_OBJECT_HANDLE found[4];
      CK_ULONG count = 0;
      int i, clean;
      CK_ATTRIBUTE t1[] = { { CKA_CLASS, &klass, sizeof(klass) },
        { CKA_TOKEN, &no, sizeof(no) }, { CKA_PRIVATE, &no, sizeof(no) },
        { CKA_LABEL, "page-one", 8 } };
      CK_ATTRIBUTE t2[] = { { CKA_CLASS, &klass, sizeof(klass) },
        { CKA_TOKEN, &no, sizeof(no) }, { CKA_PRIVATE, &no, sizeof(no) },
        { CKA_LABEL, "page-two", 8 } };
      CK_OBJECT_HANDLE warm[4] = { 0, 0, 0, 0 };
      CK_ULONG nwarm = 0;
      nslots = 8;
      use_config(g_mem_cfg);
      rv = f->C_Initialize(NULL_PTR);
      CHECKM(rv == CKR_OK, "page: Initialize ok");
      rv = f->C_GetSlotList(CK_TRUE, slots, &nslots);
      CHECKM(rv == CKR_OK && nslots == 1, "page: single slot");
      rv = f->C_OpenSession(slots[0], CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &sess);
      CHECKM(rv == CKR_OK && sess != 0, "page: session opens");
      h1 = 0; h2 = 0;
      rv = f->C_CreateObject(sess, t1, 4, &h1);
      CHECKM(rv == CKR_OK && h1 != 0, "page: first object created");
      rv = f->C_CreateObject(sess, t2, 4, &h2);
      CHECKM(rv == CKR_OK && h2 != 0, "page: second object created");
      rv = f->C_FindObjectsInit(sess, NULL_PTR, 0);
      CHECKM(rv == CKR_OK, "page: cursor opens");
      rv = f->C_FindObjects(sess, warm, 4, &nwarm);
      CHECKM(rv == CKR_OK && nwarm == 2, "page: warm page holds both handles");
      rv = f->C_FindObjectsFinal(sess);
      CHECKM(rv == CKR_OK, "page: warm cursor closes");
      rv = f->C_FindObjectsInit(sess, NULL_PTR, 0);
      CHECKM(rv == CKR_OK, "page: cursor reopens");
      rv = f->C_CloseSession(sess);
      CHECKM(rv == CKR_OK, "page: session closes with a live cursor");
      for (i = 0; i < 4; i++) found[i] = (CK_OBJECT_HANDLE)0xA5A5A5A5UL;
      count = (CK_ULONG)0xA5A5A5A5UL;
      rv = f->C_FindObjects(sess, found, 4, &count);
      clean = 1;
      for (i = 0; i < 4; i++) clean = clean && (found[i] == (CK_OBJECT_HANDLE)0xA5A5A5A5UL);
      clean = clean && (count == (CK_ULONG)0xA5A5A5A5UL);
      CHECKM(rv == CKR_SESSION_HANDLE_INVALID && clean, "page: removed session refuses, outputs untouched");
      rv = f->C_FindObjectsFinal(sess);
      CHECKM(rv == CKR_SESSION_HANDLE_INVALID, "page: removed final refuses (unchanged)");
      /* retired cursor: a fresh session has no cursor to page */
      rv = f->C_OpenSession(slots[0], CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &fresh);
      CHECKM(rv == CKR_OK && fresh != 0, "page: fresh session opens");
      for (i = 0; i < 4; i++) found[i] = (CK_OBJECT_HANDLE)0xA5A5A5A5UL;
      count = (CK_ULONG)0xA5A5A5A5UL;
      rv = f->C_FindObjects(fresh, found, 4, &count);
      clean = 1;
      for (i = 0; i < 4; i++) clean = clean && (found[i] == (CK_OBJECT_HANDLE)0xA5A5A5A5UL);
      clean = clean && (count == (CK_ULONG)0xA5A5A5A5UL);
      CHECKM(rv == CKR_OPERATION_NOT_INITIALIZED && clean, "page: fresh session has no cursor, outputs untouched");
      rv = f->C_CloseSession(fresh);
      CHECKM(rv == CKR_OK, "page: fresh session closes");
      rv = f->C_Finalize(NULL_PTR);
      CHECKM(rv == CKR_OK, "page: Finalize ok");
    }
  }

  dlclose(dl);
  unlink(g_mem_cfg);
  if (!isProxy) {
    char sidecar[300];
    unlink(g_sql_cfg);
    unlink(g_sql_db);
    snprintf(sidecar, sizeof(sidecar), "%s-journal", g_sql_db);
    unlink(sidecar);
    rmdir(g_sql_dir);
  }
  if (g_failures == 0) {
    printf("PASS: consumer_login_reopen (%s)\n", argv[1]);
    return 0;
  }
  printf("FAILURES: %d\n", g_failures);
  return 1;
}
