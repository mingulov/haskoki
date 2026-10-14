/* tests/c/consumer_multithread.c — distinct-session multithread digest proof.
 *
 * Standalone C program (non-Haskell executable): dlopen()s the built
 * libhaskoki shared module and drives N worker threads, released from
 * a common start barrier, through distinct-session digest plus
 * symmetric load. Each worker owns its sessions exclusively: per
 * iteration it opens one session, runs a size-query + one-shot
 * C_Digest and a split multipart C_DigestUpdate/C_DigestFinal over
 * a worker-unique input, then an AES-256-CBC-PAD generate +
 * encrypt + decrypt round-trip over the same input, and closes
 * the session. The suite asserts per-session isolation invariants
 * (stable under scheduling nondeterminism), never interleavings:
 *
 *   * one-shot and multipart digests of the same input agree on all
 *     32 bytes (full-byte compare, exact length, canary-guarded
 *     output buffers);
 *   * the symmetric round-trip encrypts to the exact padded length
 *     and decrypts back to the input bytes (worker-unique key and
 *     input per iteration, key destroyed before close);
 *   * the size query reports 32 and leaves the op live (PKCS#11 v3.1
 *     C_Digest behavior, as the roundtrip consumer proves);
 *   * the sha256("abc") known vector matches its FIPS bytes once, as
 *     an independent oracle besides the self-consistency compares;
 *   * the AES-256-CBC-PAD known answer (fixed key/IV from the
 *     openssl CLI) matches its ciphertext once, as the symmetric
 *     oracle beside the per-worker round-trips;
 *   * every worker's first digest differs from every other worker's
 *     (unique inputs must digest distinctly — cross-talk would
 *     collide them);
 *   * every C_OpenSession is matched by a C_CloseSession (per-thread
 *     and global opens == closes) and a final quiet-module smoke
 *     (slot list + open/info/close) succeeds.
 *
 * Any crash, hang (caught by the alarm below), return-code surprise,
 * byte mismatch, canary breach, collision, or conservation mismatch
 * is a FAIL. Exit 2 marks a setup failure (module/slot/init), which
 * is never a passing behavior test.
 *
 * Defaults N=4, ITERS=50 (overridable via HASKOKI_MT_N/_ITERS for
 * window tuning). The V4b matrix adds env-selected legs, each a
 * no-op unless its selector is exactly "1" (default behavior is
 * unchanged when no selector is set):
 *   HASKOKI_MT_PIN_ROTATE=1  auth rotation pre-phase: exact-code
 *                            USER/SO role rotation, double-login
 *                            and stray-logout refusals, wrong-PIN
 *                            flag progression with correct-PIN
 *                            clearing (roundtrip login oracle)
 *   HASKOKI_MT_AGING=1       auth aging pre-phase: repeated
 *                            login/digest/logout rounds with
 *                            session churn and conservation
 *   HASKOKI_MT_MUTEX=1       application-mutex init (counting
 *                            callbacks, policy_metadata shape):
 *                            conservation created==destroyed and
 *                            locked==unlocked past finalize
 *   HASKOKI_MT_FAIR=1        strict fairness: every worker
 *                            completes every iteration and the
 *                            run consumes exactly the predicted
 *                            session count (the matrix sweeps
 *                            1/2/4/8 workers in both the default
 *                            and application-mutex init modes)
 *   HASKOKI_MT_HINT_STRICT=1 length-hint strictness pre-phase:
 *                            short-buffer C_Digest/C_DigestFinal
 *                            report CKR_BUFFER_TOO_SMALL with the
 *                            exact 32 required, canaries intact,
 *                            op live, recall carries FIPS bytes
 *                            (roundtrip size-query oracle)
 * Compile-time HASKOKI_WIDTH_LEG=64 asserts the LP64 width the
 * 64-bit matrix cell pins (CK_ULONG and pointers are 8 bytes).
 * Flakiness cuts AGAINST the provider: any observed failure fails
 * the run.
 *
 * This TU deliberately includes ONLY the pinned vendor headers; it
 * never consumes provider-generated artifacts (enforced by the
 * driver script's independence guard).
 *
 * Compile with -Ispec/vendor. Part of scripts/test-consumers.sh,
 * which picks this file up automatically via its consumer_*.c glob.
 * Usage: consumer_multithread <path-to-libhaskoki.so>
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
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_WORKERS 8
#define DIGEST_LEN 32UL

static const CK_BYTE kSha256Abc[DIGEST_LEN] = {
  0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
  0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
  0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
  0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
};

/* AES-256-CBC-PAD known answer (independent oracle bytes from the
 * openssl CLI: key 0x00..0x1f, IV 0xa5 * 16, input "abc"). */
static const CK_BYTE kAes256Key[32] = {
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
  0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
  0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
  0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
};
static const CK_BYTE kAesKatCt[16] = {
  0xf1, 0xe6, 0x9e, 0x35, 0x75, 0xc0, 0xd3, 0x58,
  0x50, 0x03, 0x2e, 0x95, 0x72, 0x33, 0xf8, 0x0c
};

static CK_FUNCTION_LIST_PTR g_f = NULL_PTR;
static CK_SLOT_ID g_slot = 0;
static pthread_barrier_t g_start;
static int g_iters = 50;
static atomic_long g_bad = 0;
static atomic_long g_prints = 0;
static atomic_long g_opens = 0;
static atomic_long g_closes = 0;
static CK_BYTE g_first[MAX_WORKERS][DIGEST_LEN];
/* Completed iterations per worker (worker i writes its own slot;
 * main reads after join): the fairness leg asserts every worker
 * finished every iteration, so no worker starved. */
static long g_done[MAX_WORKERS];
/* Application-mutex callback counts (the provider may call back
 * from any thread, hence atomics). */
static atomic_long g_mu_created = 0;
static atomic_long g_mu_destroyed = 0;
static atomic_long g_mu_locked = 0;
static atomic_long g_mu_unlocked = 0;

typedef struct {
  CK_BYTE prefix[16];
  CK_BYTE bytes[64];
  CK_BYTE tail[16];
} Guarded;

static void note_bad(const char *what) {
  long n;
  atomic_fetch_add(&g_bad, 1);
  n = atomic_fetch_add(&g_prints, 1);
  if (n < 20) {
    printf("BAD %s\n", what);
    fflush(stdout);
  }
}

static void guard_init(Guarded *g) {
  memset(g->prefix, 0xa5, sizeof(g->prefix));
  memset(g->bytes, 0x5a, sizeof(g->bytes));
  memset(g->tail, 0xa5, sizeof(g->tail));
}

static int guard_ok(const Guarded *g, CK_ULONG len, const char *what) {
  size_t i;
  for (i = 0; i < sizeof(g->prefix); ++i) {
    if (g->prefix[i] != 0xa5 || g->tail[i] != 0xa5) {
      note_bad(what);
      return 0;
    }
  }
  if (len != DIGEST_LEN) {
    note_bad(what);
    return 0;
  }
  return 1;
}

/* Canary-only guard for variable-length outputs (the caller pins
 * the exact length separately). */
static int guard_bytes_intact(const Guarded *g, const char *what) {
  size_t i;
  for (i = 0; i < sizeof(g->prefix); ++i) {
    if (g->prefix[i] != 0xa5 || g->tail[i] != 0xa5) {
      note_bad(what);
      return 0;
    }
  }
  return 1;
}

static void *worker_main(void *arg) {
  long id = (long)arg;
  CK_MECHANISM mech;
  CK_SESSION_HANDLE sess = 0;
  CK_RV rv;
  long opens = 0, closes = 0;
  int iter;
  long done = 0;
  char detail[160];

  mech.mechanism = CKM_SHA256;
  mech.pParameter = NULL_PTR;
  mech.ulParameterLen = 0;

  {
    int brc = pthread_barrier_wait(&g_start);
    if (brc != 0 && brc != PTHREAD_BARRIER_SERIAL_THREAD) {
      note_bad("worker barrier");
      return NULL;
    }
  }

  for (iter = 0; iter < g_iters; ++iter) {
    char input[64];
    int inlen;
    Guarded one, multi;
    CK_ULONG one_len, qlen, multi_len;
    CK_ULONG half;

    inlen = snprintf(input, sizeof(input), "haskoki-mt-%ld-%d", id, iter);
    if (inlen <= 0 || (size_t)inlen >= sizeof(input)) {
      note_bad("worker input format");
      return NULL;
    }

    rv = g_f->C_OpenSession(g_slot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                            NULL_PTR, NULL_PTR, &sess);
    if (rv != CKR_OK || sess == 0) {
      snprintf(detail, sizeof(detail), "worker %ld open: 0x%lx", id, (unsigned long)rv);
      note_bad(detail);
      return NULL;
    }
    opens++;

    /* One-shot leg: size query first (reports 32, op stays live). */
    rv = g_f->C_DigestInit(sess, &mech);
    if (rv != CKR_OK) {
      snprintf(detail, sizeof(detail), "worker %ld digest-init: 0x%lx", id, (unsigned long)rv);
      note_bad(detail);
      goto close_out;
    }
    qlen = 0;
    rv = g_f->C_Digest(sess, (CK_BYTE_PTR)input, (CK_ULONG)inlen, NULL_PTR, &qlen);
    if (rv != CKR_OK || qlen != DIGEST_LEN) {
      snprintf(detail, sizeof(detail), "worker %ld size-query: 0x%lx len %lu",
               id, (unsigned long)rv, (unsigned long)qlen);
      note_bad(detail);
      goto close_out;
    }
    guard_init(&one);
    one_len = sizeof(one.bytes);
    rv = g_f->C_Digest(sess, (CK_BYTE_PTR)input, (CK_ULONG)inlen, one.bytes, &one_len);
    if (rv != CKR_OK || !guard_ok(&one, one_len, "worker one-shot bytes")) {
      if (rv != CKR_OK) {
        snprintf(detail, sizeof(detail), "worker %ld one-shot: 0x%lx", id, (unsigned long)rv);
        note_bad(detail);
      }
      goto close_out;
    }

    /* Multipart leg over the same input, split at an odd point. */
    rv = g_f->C_DigestInit(sess, &mech);
    if (rv != CKR_OK) {
      snprintf(detail, sizeof(detail), "worker %ld re-init: 0x%lx", id, (unsigned long)rv);
      note_bad(detail);
      goto close_out;
    }
    half = (CK_ULONG)inlen / 2 + 1;
    rv = g_f->C_DigestUpdate(sess, (CK_BYTE_PTR)input, half);
    if (rv != CKR_OK) {
      snprintf(detail, sizeof(detail), "worker %ld update-1: 0x%lx", id, (unsigned long)rv);
      note_bad(detail);
      goto close_out;
    }
    rv = g_f->C_DigestUpdate(sess, (CK_BYTE_PTR)input + half, (CK_ULONG)inlen - half);
    if (rv != CKR_OK) {
      snprintf(detail, sizeof(detail), "worker %ld update-2: 0x%lx", id, (unsigned long)rv);
      note_bad(detail);
      goto close_out;
    }
    guard_init(&multi);
    multi_len = sizeof(multi.bytes);
    rv = g_f->C_DigestFinal(sess, multi.bytes, &multi_len);
    if (rv != CKR_OK || !guard_ok(&multi, multi_len, "worker multipart bytes")) {
      if (rv != CKR_OK) {
        snprintf(detail, sizeof(detail), "worker %ld final: 0x%lx", id, (unsigned long)rv);
        note_bad(detail);
      }
      goto close_out;
    }
    if (memcmp(one.bytes, multi.bytes, DIGEST_LEN) != 0) {
      snprintf(detail, sizeof(detail), "worker %ld single/multipart mismatch iter %d", id, iter);
      note_bad(detail);
      goto close_out;
    }

    /* Symmetric leg: AES-256-CBC-PAD round-trip over the same
     * input on the same session (roundtrip crypt oracle: generated
     * session key, one-shot encrypt, one-shot decrypt recovers). */
    {
      CK_OBJECT_CLASS symcls = CKO_SECRET_KEY;
      CK_KEY_TYPE symtype = CKK_AES;
      CK_ULONG symvlen = 32;
      CK_BBOOL symno = CK_FALSE, symyes = CK_TRUE;
      CK_ATTRIBUTE symtmpl[] = {
        { CKA_CLASS, &symcls, sizeof(symcls) },
        { CKA_KEY_TYPE, &symtype, sizeof(symtype) },
        { CKA_VALUE_LEN, &symvlen, sizeof(symvlen) },
        { CKA_TOKEN, &symno, sizeof(symno) },
        { CKA_ENCRYPT, &symyes, sizeof(symyes) },
        { CKA_DECRYPT, &symyes, sizeof(symyes) }
      };
      CK_MECHANISM symkgm;
      CK_OBJECT_HANDLE symkey = 0;
      CK_BYTE symiv[16];
      CK_MECHANISM symem, symdm;
      Guarded symct;
      CK_ULONG symct_len;
      Guarded sympt;
      CK_ULONG sympt_len;
      CK_ULONG want_ct;
      symkgm.mechanism = CKM_AES_KEY_GEN;
      symkgm.pParameter = NULL_PTR;
      symkgm.ulParameterLen = 0;
      rv = g_f->C_GenerateKey(sess, &symkgm, symtmpl, 6, &symkey);
      if (rv != CKR_OK || symkey == 0) {
        snprintf(detail, sizeof(detail), "worker %ld sym-keygen: 0x%lx", id, (unsigned long)rv);
        note_bad(detail);
        goto close_out;
      }
      memset(symiv, 0xA5, sizeof(symiv));
      symem.mechanism = CKM_AES_CBC_PAD;
      symem.pParameter = symiv;
      symem.ulParameterLen = sizeof(symiv);
      symdm = symem;
      rv = g_f->C_EncryptInit(sess, &symem, symkey);
      if (rv != CKR_OK) {
        snprintf(detail, sizeof(detail), "worker %ld sym-encrypt-init: 0x%lx", id, (unsigned long)rv);
        note_bad(detail);
        goto close_out;
      }
      want_ct = ((CK_ULONG)inlen / 16 + 1) * 16;
      symct_len = 0;
      rv = g_f->C_Encrypt(sess, (CK_BYTE_PTR)input, (CK_ULONG)inlen, NULL_PTR, &symct_len);
      if (rv != CKR_OK || symct_len != want_ct) {
        snprintf(detail, sizeof(detail), "worker %ld sym-encrypt-query: 0x%lx len %lu",
                 id, (unsigned long)rv, (unsigned long)symct_len);
        note_bad(detail);
        goto close_out;
      }
      guard_init(&symct);
      symct_len = sizeof(symct.bytes);
      rv = g_f->C_Encrypt(sess, (CK_BYTE_PTR)input, (CK_ULONG)inlen, symct.bytes, &symct_len);
      if (rv != CKR_OK || symct_len != want_ct ||
          !guard_bytes_intact(&symct, "worker sym-encrypt canary")) {
        if (rv != CKR_OK || symct_len != want_ct) {
          snprintf(detail, sizeof(detail), "worker %ld sym-encrypt: 0x%lx len %lu",
                   id, (unsigned long)rv, (unsigned long)symct_len);
          note_bad(detail);
        }
        goto close_out;
      }
      rv = g_f->C_DecryptInit(sess, &symdm, symkey);
      if (rv != CKR_OK) {
        snprintf(detail, sizeof(detail), "worker %ld sym-decrypt-init: 0x%lx", id, (unsigned long)rv);
        note_bad(detail);
        goto close_out;
      }
      sympt_len = 0;
      rv = g_f->C_Decrypt(sess, symct.bytes, symct_len, NULL_PTR, &sympt_len);
      if (rv != CKR_OK || sympt_len != (CK_ULONG)inlen) {
        snprintf(detail, sizeof(detail), "worker %ld sym-decrypt-query: 0x%lx len %lu",
                 id, (unsigned long)rv, (unsigned long)sympt_len);
        note_bad(detail);
        goto close_out;
      }
      guard_init(&sympt);
      sympt_len = sizeof(sympt.bytes);
      rv = g_f->C_Decrypt(sess, symct.bytes, symct_len, sympt.bytes, &sympt_len);
      if (rv != CKR_OK || sympt_len != (CK_ULONG)inlen ||
          memcmp(sympt.bytes, input, (size_t)inlen) != 0 ||
          !guard_bytes_intact(&sympt, "worker sym-decrypt canary")) {
        if (rv != CKR_OK || sympt_len != (CK_ULONG)inlen ||
            memcmp(sympt.bytes, input, (size_t)inlen) != 0) {
          snprintf(detail, sizeof(detail), "worker %ld sym-decrypt: 0x%lx len %lu",
                   id, (unsigned long)rv, (unsigned long)sympt_len);
          note_bad(detail);
        }
        goto close_out;
      }
      rv = g_f->C_DestroyObject(sess, symkey);
      if (rv != CKR_OK) {
        snprintf(detail, sizeof(detail), "worker %ld sym-destroy: 0x%lx", id, (unsigned long)rv);
        note_bad(detail);
        goto close_out;
      }
    }
    if (iter == 0) {
      memcpy(g_first[id], one.bytes, DIGEST_LEN);
    }

  close_out:
    rv = g_f->C_CloseSession(sess);
    sess = 0;
    if (rv != CKR_OK) {
      snprintf(detail, sizeof(detail), "worker %ld close: 0x%lx", id, (unsigned long)rv);
      note_bad(detail);
      break;
    }
    closes++;
    done++;
    if (atomic_load(&g_bad) != 0) {
      break;
    }
  }

  atomic_fetch_add(&g_opens, opens);
  atomic_fetch_add(&g_closes, closes);
  if (id >= 0 && id < MAX_WORKERS) {
    g_done[id] = done;
  }
  return NULL;
}

static long env_long(const char *name, long dflt, long lo, long hi) {
  const char *text = getenv(name);
  char *end = NULL;
  long val;
  if (text == NULL || *text == '\0') {
    return dflt;
  }
  val = strtol(text, &end, 10);
  if (end == text || *end != '\0' || val < lo || val > hi) {
    return dflt;
  }
  return val;
}

/* Matrix leg selectors are strict: only exactly "1" enables a leg. */
static int env_enabled(const char *name) {
  const char *text = getenv(name);
  return text != NULL && strcmp(text, "1") == 0;
}

/* ---------- application-mutex callbacks (counting) ---------- */

static CK_RV mt_create(CK_VOID_PTR_PTR pp) {
  pthread_mutex_t *m;
  if (pp == NULL) {
    return CKR_ARGUMENTS_BAD;
  }
  m = (pthread_mutex_t *)malloc(sizeof(*m));
  if (m == NULL) {
    return CKR_HOST_MEMORY;
  }
  if (pthread_mutex_init(m, NULL) != 0) {
    free(m);
    return CKR_GENERAL_ERROR;
  }
  *pp = m;
  atomic_fetch_add(&g_mu_created, 1);
  return CKR_OK;
}

static CK_RV mt_destroy(CK_VOID_PTR p) {
  if (p == NULL) {
    return CKR_MUTEX_BAD;
  }
  pthread_mutex_destroy((pthread_mutex_t *)p);
  free(p);
  atomic_fetch_add(&g_mu_destroyed, 1);
  return CKR_OK;
}

static CK_RV mt_lock(CK_VOID_PTR p) {
  if (p == NULL) {
    return CKR_MUTEX_BAD;
  }
  if (pthread_mutex_lock((pthread_mutex_t *)p) != 0) {
    return CKR_GENERAL_ERROR;
  }
  atomic_fetch_add(&g_mu_locked, 1);
  return CKR_OK;
}

static CK_RV mt_unlock(CK_VOID_PTR p) {
  if (p == NULL) {
    return CKR_MUTEX_BAD;
  }
  if (pthread_mutex_unlock((pthread_mutex_t *)p) != 0) {
    return CKR_GENERAL_ERROR;
  }
  atomic_fetch_add(&g_mu_unlocked, 1);
  return CKR_OK;
}

/* ---------- pin-rotate pre-phase ---------- */

#define PIN_EXPECT(call, want, what) do { \
    CK_RV _got = (call); ++pin_checks; \
    if (_got != (want)) { \
      snprintf(pin_detail, sizeof(pin_detail), "pin-rotate %s: got 0x%lx want 0x%lx", \
               (what), (unsigned long)_got, (unsigned long)(want)); \
      note_bad(pin_detail); \
    } \
  } while (0)

static void pin_rotate_phase(CK_FUNCTION_LIST_PTR f) {
  CK_SESSION_HANDLE sess = 0;
  CK_SESSION_INFO info;
  CK_TOKEN_INFO token;
  CK_RV rv;
  unsigned pin_checks = 0;
  char pin_detail[192];
  rv = f->C_OpenSession(g_slot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                        NULL_PTR, NULL_PTR, &sess);
  if (rv != CKR_OK || sess == 0) {
    note_bad("pin-rotate open");
    return;
  }
  atomic_fetch_add(&g_opens, 1);
  rv = f->C_GetSessionInfo(sess, &info);
  ++pin_checks;
  if (rv != CKR_OK || info.state != CKS_RW_PUBLIC_SESSION) {
    note_bad("pin-rotate pre-login state public");
  }
  PIN_EXPECT(f->C_Login(sess, CKU_USER, (CK_UTF8CHAR_PTR) "1234", 4), CKR_OK, "user login");
  rv = f->C_GetSessionInfo(sess, &info);
  ++pin_checks;
  if (rv != CKR_OK || info.state != CKS_RW_USER_FUNCTIONS) {
    note_bad("pin-rotate post-login state user");
  }
  PIN_EXPECT(f->C_Login(sess, CKU_USER, (CK_UTF8CHAR_PTR) "1234", 4),
             CKR_USER_ALREADY_LOGGED_IN, "double login");
  PIN_EXPECT(f->C_Logout(sess), CKR_OK, "logout");
  PIN_EXPECT(f->C_Logout(sess), CKR_USER_NOT_LOGGED_IN, "stray logout");
  PIN_EXPECT(f->C_Login(sess, CKU_USER, (CK_UTF8CHAR_PTR) "9999", 4),
             CKR_PIN_INCORRECT, "wrong PIN");
  rv = f->C_GetTokenInfo(g_slot, &token);
  ++pin_checks;
  if (rv != CKR_OK || (token.flags & CKF_USER_PIN_COUNT_LOW) == 0 ||
      (token.flags & CKF_USER_PIN_FINAL_TRY) != 0) {
    note_bad("pin-rotate miss shows count-low");
  }
  PIN_EXPECT(f->C_Login(sess, CKU_USER, (CK_UTF8CHAR_PTR) "1234", 4), CKR_OK,
             "correct PIN after a miss");
  rv = f->C_GetTokenInfo(g_slot, &token);
  ++pin_checks;
  if (rv != CKR_OK || (token.flags & CKF_USER_PIN_COUNT_LOW) != 0) {
    note_bad("pin-rotate success clears count-low");
  }
  PIN_EXPECT(f->C_Logout(sess), CKR_OK, "logout after clear");
  PIN_EXPECT(f->C_Login(sess, CKU_SO, (CK_UTF8CHAR_PTR) "5678", 4), CKR_OK, "SO login");
  rv = f->C_GetSessionInfo(sess, &info);
  ++pin_checks;
  if (rv != CKR_OK || info.state != CKS_RW_SO_FUNCTIONS) {
    note_bad("pin-rotate SO session state");
  }
  PIN_EXPECT(f->C_Logout(sess), CKR_OK, "SO logout");
  PIN_EXPECT(f->C_Login(sess, CKU_CONTEXT_SPECIFIC, (CK_UTF8CHAR_PTR) "1234", 4),
             CKR_USER_NOT_LOGGED_IN, "context login needs a user login");
  PIN_EXPECT(f->C_Login(sess, CKU_USER, (CK_UTF8CHAR_PTR) "1234", 4), CKR_OK,
             "user login for context probe");
  PIN_EXPECT(f->C_Login(sess, CKU_CONTEXT_SPECIFIC, (CK_UTF8CHAR_PTR) "1234", 4),
             CKR_OPERATION_NOT_INITIALIZED, "context probe needs an active op");
  PIN_EXPECT(f->C_Logout(sess), CKR_OK, "logout after context probe");
  PIN_EXPECT(f->C_Login(sess, 99, (CK_UTF8CHAR_PTR) "1234", 4),
             CKR_USER_TYPE_INVALID, "bogus user type");
  PIN_EXPECT(f->C_Login(sess, CKU_USER, NULL_PTR, 0), CKR_PIN_INCORRECT, "empty PIN");
  PIN_EXPECT(f->C_Login(sess, CKU_USER, (CK_UTF8CHAR_PTR) "1234", 4), CKR_OK,
             "correct PIN clears the empty miss");
  PIN_EXPECT(f->C_Logout(sess), CKR_OK, "final logout");
  rv = f->C_CloseSession(sess);
  if (rv != CKR_OK) {
    note_bad("pin-rotate close");
  } else {
    atomic_fetch_add(&g_closes, 1);
  }
  printf("pin-rotate: %u checks\n", pin_checks);
}
#undef PIN_EXPECT

/* ---------- aging pre-phase ---------- */

static void aging_phase(CK_FUNCTION_LIST_PTR f) {
  static const int rounds = 25;
  CK_MECHANISM mech;
  int round;
  long opens = 0, closes = 0;
  mech.mechanism = CKM_SHA256;
  mech.pParameter = NULL_PTR;
  mech.ulParameterLen = 0;
  for (round = 0; round < rounds; round++) {
    CK_SESSION_HANDLE sess = 0;
    CK_BYTE digest[32];
    CK_ULONG digest_len = sizeof(digest);
    char input[48];
    int inlen;
    CK_RV rv;
    inlen = snprintf(input, sizeof(input), "haskoki-aging-%d", round);
    if (inlen <= 0 || (size_t)inlen >= sizeof(input)) {
      note_bad("aging input format");
      return;
    }
    rv = f->C_OpenSession(g_slot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                          NULL_PTR, NULL_PTR, &sess);
    if (rv != CKR_OK || sess == 0) {
      note_bad("aging open");
      return;
    }
    opens++;
    rv = f->C_Login(sess, CKU_USER, (CK_UTF8CHAR_PTR) "1234", 4);
    if (rv != CKR_OK) {
      note_bad("aging login");
      f->C_CloseSession(sess);
      closes++;
      return;
    }
    rv = f->C_DigestInit(sess, &mech);
    if (rv == CKR_OK) {
      rv = f->C_Digest(sess, (CK_BYTE_PTR)input, (CK_ULONG)inlen,
                       digest, &digest_len);
    }
    if (rv != CKR_OK || digest_len != DIGEST_LEN) {
      note_bad("aging authed digest");
      f->C_Logout(sess);
      f->C_CloseSession(sess);
      closes++;
      return;
    }
    rv = f->C_Logout(sess);
    if (rv != CKR_OK) {
      note_bad("aging logout");
      f->C_CloseSession(sess);
      closes++;
      return;
    }
    /* Session churn: every fifth round opens and closes a spare. */
    if (round % 5 == 0) {
      CK_SESSION_HANDLE spare = 0;
      rv = f->C_OpenSession(g_slot, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &spare);
      if (rv != CKR_OK || spare == 0) {
        note_bad("aging spare open");
        f->C_CloseSession(sess);
        closes++;
        return;
      }
      opens++;
      rv = f->C_CloseSession(spare);
      if (rv != CKR_OK) {
        note_bad("aging spare close");
        f->C_CloseSession(sess);
        closes++;
        return;
      }
      closes++;
    }
    rv = f->C_CloseSession(sess);
    if (rv != CKR_OK) {
      note_bad("aging close");
      return;
    }
    closes++;
  }
  atomic_fetch_add(&g_opens, opens);
  atomic_fetch_add(&g_closes, closes);
  if (opens != closes) {
    note_bad("aging opens==closes");
    return;
  }
  printf("aging: %d rounds opens=%ld closes=%ld\n", rounds, opens, closes);
}

/* ---------- hint-strictness pre-phase ---------- */

/* Filler beyond the advertised capacity must be intact after a
 * short-buffer refusal: the call must not have written past what
 * the caller advertised (guard_init fills bytes[] with 0x5a, so
 * any byte past the advertised length that differs is an
 * overrun the outer canaries alone would miss). */
static int beyond_capacity_intact(const Guarded *buf, size_t advertised, const char *what) {
  size_t i;
  for (i = advertised; i < sizeof(buf->bytes); ++i) {
    if (buf->bytes[i] != 0x5a) {
      note_bad(what);
      return 0;
    }
  }
  return 1;
}

static void hint_strict_phase(CK_FUNCTION_LIST_PTR f) {
  CK_SESSION_HANDLE sess = 0;
  CK_MECHANISM mech;
  Guarded buf;
  CK_ULONG out_len;
  CK_RV rv;
  unsigned hint_checks = 0;
  mech.mechanism = CKM_SHA256;
  mech.pParameter = NULL_PTR;
  mech.ulParameterLen = 0;
  rv = f->C_OpenSession(g_slot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                        NULL_PTR, NULL_PTR, &sess);
  if (rv != CKR_OK || sess == 0) {
    note_bad("hint-strict open");
    return;
  }
  atomic_fetch_add(&g_opens, 1);
  rv = f->C_DigestInit(sess, &mech);
  ++hint_checks;
  if (rv != CKR_OK) {
    note_bad("hint-strict one-shot init");
    goto hint_close;
  }
  guard_init(&buf);
  out_len = 8;
  rv = f->C_Digest(sess, (CK_BYTE_PTR) "abc", 3, buf.bytes, &out_len);
  ++hint_checks;
  if (rv != CKR_BUFFER_TOO_SMALL || out_len != DIGEST_LEN ||
      !guard_ok(&buf, DIGEST_LEN, "hint-strict one-shot canary") ||
      !beyond_capacity_intact(&buf, 8, "hint-strict one-shot overrun past 8")) {
    note_bad("hint-strict short one-shot reports 32");
    goto hint_close;
  }
  out_len = sizeof(buf.bytes);
  rv = f->C_Digest(sess, (CK_BYTE_PTR) "abc", 3, buf.bytes, &out_len);
  ++hint_checks;
  if (rv != CKR_OK || out_len != DIGEST_LEN ||
      memcmp(buf.bytes, kSha256Abc, DIGEST_LEN) != 0) {
    note_bad("hint-strict one-shot recall FIPS bytes");
    goto hint_close;
  }
  rv = f->C_DigestInit(sess, &mech);
  ++hint_checks;
  if (rv != CKR_OK) {
    note_bad("hint-strict multipart init");
    goto hint_close;
  }
  rv = f->C_DigestUpdate(sess, (CK_BYTE_PTR) "abc", 3);
  ++hint_checks;
  if (rv != CKR_OK) {
    note_bad("hint-strict update");
    goto hint_close;
  }
  guard_init(&buf);
  out_len = 8;
  rv = f->C_DigestFinal(sess, buf.bytes, &out_len);
  ++hint_checks;
  if (rv != CKR_BUFFER_TOO_SMALL || out_len != DIGEST_LEN ||
      !guard_ok(&buf, DIGEST_LEN, "hint-strict final canary") ||
      !beyond_capacity_intact(&buf, 8, "hint-strict final overrun past 8")) {
    note_bad("hint-strict short final reports 32");
    goto hint_close;
  }
  out_len = 8;
  rv = f->C_DigestFinal(sess, buf.bytes, &out_len);
  ++hint_checks;
  if (rv != CKR_BUFFER_TOO_SMALL || out_len != DIGEST_LEN ||
      !guard_ok(&buf, DIGEST_LEN, "hint-strict repeat canary") ||
      !beyond_capacity_intact(&buf, 8, "hint-strict repeat overrun past 8")) {
    note_bad("hint-strict second short final reports 32");
    goto hint_close;
  }
  out_len = sizeof(buf.bytes);
  rv = f->C_DigestFinal(sess, buf.bytes, &out_len);
  ++hint_checks;
  if (rv != CKR_OK || out_len != DIGEST_LEN ||
      memcmp(buf.bytes, kSha256Abc, DIGEST_LEN) != 0) {
    note_bad("hint-strict final recall FIPS bytes");
    goto hint_close;
  }
  printf("hint-strict: %u checks\n", hint_checks);
hint_close:
  rv = f->C_CloseSession(sess);
  if (rv != CKR_OK) {
    note_bad("hint-strict close");
  } else {
    atomic_fetch_add(&g_closes, 1);
  }
}

/* ---------- symmetric known-answer phase ---------- */

static void symmetric_kat_phase(CK_FUNCTION_LIST_PTR f) {
  CK_OBJECT_CLASS kcls = CKO_SECRET_KEY;
  CK_KEY_TYPE ktype = CKK_AES;
  CK_BBOOL kno = CK_FALSE, kyes = CK_TRUE;
  CK_ATTRIBUTE ktmpl[] = {
    { CKA_CLASS, &kcls, sizeof(kcls) },
    { CKA_KEY_TYPE, &ktype, sizeof(ktype) },
    { CKA_VALUE, (CK_VOID_PTR)kAes256Key, sizeof(kAes256Key) },
    { CKA_TOKEN, &kno, sizeof(kno) },
    { CKA_ENCRYPT, &kyes, sizeof(kyes) },
    { CKA_DECRYPT, &kyes, sizeof(kyes) }
  };
  CK_SESSION_HANDLE sess = 0;
  CK_OBJECT_HANDLE key = 0;
  CK_BYTE iv[16];
  CK_MECHANISM em, dm;
  Guarded ct, pt;
  CK_ULONG ct_len, pt_len;
  CK_RV rv;
  rv = f->C_OpenSession(g_slot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                        NULL_PTR, NULL_PTR, &sess);
  if (rv != CKR_OK || sess == 0) {
    note_bad("sym-kat open");
    return;
  }
  atomic_fetch_add(&g_opens, 1);
  rv = f->C_CreateObject(sess, ktmpl, 6, &key);
  if (rv != CKR_OK || key == 0) {
    note_bad("sym-kat key import");
    goto kat_close;
  }
  memset(iv, 0xa5, sizeof(iv));
  em.mechanism = CKM_AES_CBC_PAD;
  em.pParameter = iv;
  em.ulParameterLen = sizeof(iv);
  dm = em;
  rv = f->C_EncryptInit(sess, &em, key);
  if (rv != CKR_OK) {
    note_bad("sym-kat encrypt-init");
    goto kat_close;
  }
  guard_init(&ct);
  ct_len = sizeof(ct.bytes);
  rv = f->C_Encrypt(sess, (CK_BYTE_PTR) "abc", 3, ct.bytes, &ct_len);
  if (rv != CKR_OK || ct_len != sizeof(kAesKatCt) ||
      memcmp(ct.bytes, kAesKatCt, sizeof(kAesKatCt)) != 0 ||
      !guard_bytes_intact(&ct, "sym-kat encrypt canary")) {
    note_bad("sym-kat encrypt vector");
    goto kat_close;
  }
  rv = f->C_DecryptInit(sess, &dm, key);
  if (rv != CKR_OK) {
    note_bad("sym-kat decrypt-init");
    goto kat_close;
  }
  guard_init(&pt);
  pt_len = sizeof(pt.bytes);
  rv = f->C_Decrypt(sess, ct.bytes, ct_len, pt.bytes, &pt_len);
  if (rv != CKR_OK || pt_len != 3 || memcmp(pt.bytes, "abc", 3) != 0 ||
      !guard_bytes_intact(&pt, "sym-kat decrypt canary")) {
    note_bad("sym-kat decrypt recovers abc");
    goto kat_close;
  }
  rv = f->C_DestroyObject(sess, key);
  if (rv != CKR_OK) {
    note_bad("sym-kat destroy");
    goto kat_close;
  }
  printf("sym-kat: AES-256-CBC-PAD vector ok\n");
kat_close:
  rv = f->C_CloseSession(sess);
  if (rv != CKR_OK) {
    note_bad("sym-kat close");
  } else {
    atomic_fetch_add(&g_closes, 1);
  }
}

int main(int argc, char **argv) {
  void *handle;
  CK_C_GetFunctionList pGetList;
  CK_FUNCTION_LIST_PTR f;
  CK_SLOT_ID slots[16];
  CK_ULONG nslots = 16;
  CK_RV rv;
  long nworkers;
  pthread_t workers[MAX_WORKERS];
  long i, j;
  long bad, opens, closes;
  long opens_at_workers = 0;
  int mutex_mode = 0;
  int fair_mode = 0;
  CK_SESSION_HANDLE smoke = 0;
  CK_SESSION_INFO info;
  CK_MECHANISM mech;
  Guarded vec;
  CK_ULONG vec_len;

  setvbuf(stdout, NULL, _IONBF, 0);
  if (argc != 2) {
    fprintf(stderr, "usage: %s <path-to-libhaskoki.so>\n", argv[0]);
    return 2;
  }
  nworkers = env_long("HASKOKI_MT_N", 4, 1, MAX_WORKERS);
  g_iters = (int)env_long("HASKOKI_MT_ITERS", 50, 1, 10000);

  handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
  if (!handle) {
    fprintf(stderr, "dlopen failed: %s\n", dlerror());
    return 2;
  }
  pGetList = (CK_C_GetFunctionList)dlsym(handle, "C_GetFunctionList");
  if (pGetList == NULL) {
    fprintf(stderr, "dlsym C_GetFunctionList failed\n");
    return 2;
  }
  rv = pGetList(&f);
  if (rv != CKR_OK || f == NULL_PTR) {
    fprintf(stderr, "C_GetFunctionList failed: 0x%lx\n", (unsigned long)rv);
    return 2;
  }
  g_f = f;

  /* Hang guard: stranded workers fail loudly instead of blocking join. */
  alarm(300);

  mutex_mode = env_enabled("HASKOKI_MT_MUTEX");
  if (mutex_mode) {
    CK_C_INITIALIZE_ARGS args;
    memset(&args, 0, sizeof(args));
    args.CreateMutex = mt_create;
    args.DestroyMutex = mt_destroy;
    args.LockMutex = mt_lock;
    args.UnlockMutex = mt_unlock;
    rv = f->C_Initialize(&args);
  } else {
    rv = f->C_Initialize(NULL_PTR);
  }
  if (rv != CKR_OK) {
    fprintf(stderr, "C_Initialize failed: 0x%lx\n", (unsigned long)rv);
    return 2;
  }
  rv = f->C_GetSlotList(CK_TRUE, slots, &nslots);
  if (rv != CKR_OK || nslots < 1) {
    fprintf(stderr, "no token-present slot: 0x%lx count %lu\n",
            (unsigned long)rv, (unsigned long)nslots);
    return 2;
  }
  g_slot = slots[0];

#ifdef HASKOKI_WIDTH_LEG
  /* 64-bit matrix cell: pin the LP64 width at runtime. */
  if (sizeof(CK_ULONG) != 8 || sizeof(void *) != 8) {
    note_bad("width leg requires 64-bit CK_ULONG and pointers");
  } else {
    printf("width: CK_ULONG=%lu ptr=%lu leg=%d\n",
           (unsigned long)sizeof(CK_ULONG),
           (unsigned long)sizeof(void *), HASKOKI_WIDTH_LEG);
  }
#endif

  /* Matrix pre-phases: each a no-op unless its selector is set. */
  if (env_enabled("HASKOKI_MT_PIN_ROTATE")) {
    pin_rotate_phase(f);
  }
  if (env_enabled("HASKOKI_MT_AGING")) {
    aging_phase(f);
  }
  if (env_enabled("HASKOKI_MT_HINT_STRICT")) {
    hint_strict_phase(f);
  }
  fair_mode = env_enabled("HASKOKI_MT_FAIR");

  /* Independent oracle: the FIPS sha256("abc") vector, once. */
  mech.mechanism = CKM_SHA256;
  mech.pParameter = NULL_PTR;
  mech.ulParameterLen = 0;
  rv = f->C_OpenSession(g_slot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                        NULL_PTR, NULL_PTR, &smoke);
  if (rv != CKR_OK || smoke == 0) {
    fprintf(stderr, "oracle session failed: 0x%lx\n", (unsigned long)rv);
    return 2;
  }
  atomic_fetch_add(&g_opens, 1);
  rv = f->C_DigestInit(smoke, &mech);
  guard_init(&vec);
  vec_len = sizeof(vec.bytes);
  if (rv == CKR_OK) {
    rv = f->C_Digest(smoke, (CK_BYTE_PTR) "abc", 3, vec.bytes, &vec_len);
  }
  if (rv != CKR_OK || !guard_ok(&vec, vec_len, "oracle bytes") ||
      memcmp(vec.bytes, kSha256Abc, DIGEST_LEN) != 0) {
    printf("BAD oracle vector\n");
    atomic_fetch_add(&g_bad, 1);
  }
  rv = f->C_CloseSession(smoke);
  smoke = 0;
  if (rv != CKR_OK) {
    printf("BAD oracle close: 0x%lx\n", (unsigned long)rv);
    atomic_fetch_add(&g_bad, 1);
  } else {
    atomic_fetch_add(&g_closes, 1);
  }

  /* Independent symmetric oracle: the AES-256-CBC-PAD known answer. */
  symmetric_kat_phase(f);

  if (atomic_load(&g_bad) == 0) {
    opens_at_workers = atomic_load(&g_opens);
    if (pthread_barrier_init(&g_start, NULL, (unsigned)nworkers) != 0) {
      fprintf(stderr, "barrier init failed\n");
      return 2;
    }
    for (i = 0; i < nworkers; ++i) {
      if (pthread_create(&workers[i], NULL, worker_main, (void *)i) != 0) {
        fprintf(stderr, "pthread_create worker %ld failed\n", i);
        return 2;
      }
    }
    for (i = 0; i < nworkers; ++i) {
      pthread_join(workers[i], NULL);
    }
    pthread_barrier_destroy(&g_start);
  }

  /* Distinctness: unique inputs must digest distinctly. */
  if (atomic_load(&g_bad) == 0) {
    for (i = 0; i < nworkers; ++i) {
      for (j = i + 1; j < nworkers; ++j) {
        if (memcmp(g_first[i], g_first[j], DIGEST_LEN) == 0) {
          printf("BAD digest collision workers %ld/%ld\n", i, j);
          atomic_fetch_add(&g_bad, 1);
        }
      }
    }
  }

  /* Strict fairness: every worker finished every iteration (no
   * starvation) and the workers consumed exactly their predicted
   * sessions on top of the pre-phase/oracle opens. */
  if (fair_mode && atomic_load(&g_bad) == 0) {
    long expect = opens_at_workers + nworkers * (long)g_iters;
    char detail[160];
    for (i = 0; i < nworkers; ++i) {
      if (g_done[i] != (long)g_iters) {
        snprintf(detail, sizeof(detail), "fairness worker %ld completed %ld of %d",
                 i, g_done[i], g_iters);
        note_bad(detail);
      }
    }
    opens = atomic_load(&g_opens);
    if (opens != expect) {
      snprintf(detail, sizeof(detail), "fairness opens %ld want %ld", opens, expect);
      note_bad(detail);
    }
    printf("fairness: workers=%ld iters=%d opens=%ld\n", nworkers, g_iters, opens);
  }

  /* Final quiet-module smoke. */
  if (atomic_load(&g_bad) == 0) {
    rv = f->C_GetSlotList(CK_FALSE, NULL_PTR, &nslots);
    if (rv != CKR_OK) {
      note_bad("final-GetSlotList");
    }
    rv = f->C_OpenSession(g_slot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                          NULL_PTR, NULL_PTR, &smoke);
    if (rv == CKR_OK && smoke != 0) {
      atomic_fetch_add(&g_opens, 1);
      rv = f->C_GetSessionInfo(smoke, &info);
      if (rv != CKR_OK) {
        note_bad("final-GetSessionInfo");
      }
      rv = f->C_CloseSession(smoke);
      smoke = 0;
      if (rv == CKR_OK) {
        atomic_fetch_add(&g_closes, 1);
      } else {
        note_bad("final-CloseSession");
      }
    } else {
      note_bad("final-OpenSession");
    }
  }

  rv = f->C_Finalize(NULL_PTR);
  if (rv != CKR_OK) {
    note_bad("final-Finalize");
  }

  if (mutex_mode) {
    long created = atomic_load(&g_mu_created);
    long destroyed = atomic_load(&g_mu_destroyed);
    long locked = atomic_load(&g_mu_locked);
    long unlocked = atomic_load(&g_mu_unlocked);
    printf("mutex-callbacks: created=%ld destroyed=%ld locked=%ld unlocked=%ld\n",
           created, destroyed, locked, unlocked);
    if (created != destroyed) {
      note_bad("mutex-callbacks created==destroyed");
    }
    if (locked != unlocked) {
      note_bad("mutex-callbacks locked==unlocked");
    }
  }

  alarm(0);
  bad = atomic_load(&g_bad);
  opens = atomic_load(&g_opens);
  closes = atomic_load(&g_closes);
  printf("SUMMARY: %ld workers, opens %ld closes %ld, %ld bad\n",
         nworkers, opens, closes, bad);
  if (opens != closes || opens < nworkers + 2) {
    printf("RESULT: FAIL (session conservation: opens %ld closes %ld)\n", opens, closes);
    return 1;
  }
  if (bad != 0) {
    printf("RESULT: FAIL\n");
    return 1;
  }
  printf("RESULT: PASS\n");
  return 0;
}
