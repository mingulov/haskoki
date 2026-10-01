/* Independent notifications contract, through each actual public table.
 * Build: cc -std=c11 -O2 -g -Wall -Wextra -Werror -Ispec/vendor
 *   tests/c/notifications_routed.c -ldl -lpthread -o notifications_routed
 * No implementation headers, private entry points, or manufactured slot IDs.
 * T-N01..T-N07 own behavior; this T-N08 consumer independently consolidates it.
 * First-failure children are isolated; their parent still runs every matrix cell.
 */
#define _GNU_SOURCE
#define CK_PTR *
#define CK_DECLARE_FUNCTION(r, n) r n
#define CK_DECLARE_FUNCTION_POINTER(r, n) r (*n)
#define CK_CALLBACK_FUNCTION(r, n) r (*n)
#include "pkcs11.h"
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <setjmp.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

_Static_assert(sizeof(CK_ULONG) == 8, "LP64 consumer");
#define SENTINEL 0xa5a5a5a5a5a5a5a5UL
#define N(a) (sizeof(a) / sizeof((a)[0]))
#define COMMON(F) F(Initialize) F(Finalize) F(GetInfo) F(GetSlotList) \
  F(GetSlotInfo) F(GetTokenInfo) F(GetMechanismList) F(GetMechanismInfo) \
  F(OpenSession) F(CloseSession) F(CloseAllSessions) F(GetSessionInfo) \
  F(Login) F(Logout) F(CreateObject) F(DestroyObject) F(GetAttributeValue) \
  F(FindObjectsInit) F(FindObjects) F(FindObjectsFinal) F(DigestInit) \
  F(Digest) F(DigestUpdate) F(DigestFinal) F(GenerateRandom) F(WaitForSlotEvent)
#define FIELD(n) CK_C_##n n;
typedef struct { COMMON(FIELD) CK_C_SessionCancel SessionCancel;
  CK_C_AsyncComplete AsyncComplete; CK_C_AsyncGetID AsyncGetID;
  CK_C_AsyncJoin AsyncJoin; } Api;
#undef FIELD
/* Independent declaration of the sole vendor extension used here. */
typedef CK_RV (*Control)(const CK_BYTE *, CK_ULONG, CK_BYTE *, CK_ULONG *);
static Api a;
static Control ctl;
static CK_C_GetFunctionList get_list;
static CK_C_GetInterface get_interface;
static CK_C_GetInterfaceList get_interfaces;
static const char *version, *storage, *leg, *directory;
static const char *versions[] = {"2.40", "3.0", "3.1", "3.2"};
static const char *stores[] = {"memory", "sqlite"};
static const char *legs[] = {"entry", "initial", "presence", "coalescing",
  "cleanup", "waiters", "notify", "reentry", "restart"};
static CK_SLOT_ID slots[2];
static int live, failed;
static unsigned assertions;
static void *module;
static CK_BYTE *pages;
static size_t page_size;
static char fixture_config[PATH_MAX];
static const CK_BYTE kat[32] = {0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,
  0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,0xb0,0x03,0x61,0xa3,0x96,0x17,
  0x7a,0x9c,0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad};
typedef struct { CK_BYTE pre[16], bytes[64], post[16]; CK_ULONG length; } Output;
typedef struct { CK_BYTE pre[16]; CK_SLOT_INFO value; CK_BYTE post[16]; } SlotInfo;
typedef struct { CK_BYTE pre[16]; CK_TOKEN_INFO value; CK_BYTE post[16]; } TokenInfo;
typedef struct { CK_BYTE pre[16]; CK_SESSION_INFO value; CK_BYTE post[16]; } SessionInfo;
typedef struct { CK_BYTE pre[16]; CK_ASYNC_DATA value; CK_BYTE post[16]; } AsyncResult;
typedef struct { CK_BYTE pre[16]; CK_SLOT_ID value[3]; CK_BYTE post[16]; } SlotList;
typedef struct {
  CK_SESSION_HANDLE session; void *cookie; pthread_t thread; CK_RV result;
  atomic_uint calls; int reentry, caught_exception;
} Callback;
static Callback cb;
static atomic_uint app_held, app_locks, app_unlocks;
static int application_locks;
typedef struct { pthread_t thread; CK_RV rv; CK_SLOT_ID slot; int started, done; } Waiter;
static Waiter waiters[2];
static unsigned waiter_count;
static pthread_mutex_t wait_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t wait_cond = PTHREAD_COND_INITIALIZER;

/* All nine assertion functions precede fixture implementations. Ownership
 * links name the recorded T-N01..T-N07 assertion cycles, not new provider reds. */
static int check(int, const char *);
static int expect(CK_RV, CK_RV, const char *);
static int filled(const void *, size_t);
static void setup_error(const char *);
static void configure(int);
static void initialize(int);
static void finalize(void);
static void discover_slots(void);
static void status_epochs(CK_ULONG [2]);
static void mutate(unsigned, int);
static void event(CK_RV, unsigned, const char *);
static void lists(CK_ULONG);
static CK_SESSION_HANDLE session(unsigned, int, void *, CK_NOTIFY);
static void digest_init(CK_SESSION_HANDLE);
static void reset_output(Output *, CK_ULONG);
static void digest_exact(Output *);
static void stale(CK_SESSION_HANDLE);
static void slot_flags(unsigned, CK_FLAGS, const char *);
static void wait_shape_matrix(int, const char *);
static void list_boundaries(void);
static void boundary_slots(void);
static CK_RV notify(CK_SESSION_HANDLE, CK_NOTIFICATION, void *);
static void callback_for(CK_SESSION_HANDLE, void *, CK_RV, int);
static void digest_call(CK_SESSION_HANDLE, Output *, CK_RV);
static void submit(CK_SESSION_HANDLE, Output *);
static void complete(CK_SESSION_HANDLE, Output *);
static void start_waiters(unsigned);
static void join_waiters(void);
static void await_decision(void);
static void allocate_pages(void);
static void revoke_pages(void);
static void retirement(unsigned);
static void cleanup(void);
static void durable_snapshot(int);
static CK_BYTE *durable_copy;
static size_t durable_size;
#define REQUIRE(c, s) do { if (!check((c), (s))) return; } while (0)
#define RV(c, w, s) do { if (!expect((c), (w), (s))) return; } while (0)
#define STEP(c) do { c; if (failed) return; } while (0)

/* T-N04: task-n04/before reserved-pointer/native-width/output assertions;
 * T-N02: coherent owner; T-N03: catalog and absence precedence. */
static void leg_entry(void) {
  STEP(wait_shape_matrix(0, "before-init"));
  STEP(initialize(0));
  STEP(wait_shape_matrix(1, "live"));
  STEP(list_boundaries());
  STEP(boundary_slots());
  STEP(finalize());
  STEP(wait_shape_matrix(0, "after-finalize"));
}

/* T-N01 caseServingInitialCore, T-N02 caseServingInitialSnapshot/config limits.
 * Clear startup and fixed-slot facts may already pass on the baseline. */
static void leg_initial(void) {
  for (unsigned fixed = 0; fixed < 2; ++fixed) {
    STEP(configure(!fixed)); STEP(initialize(0)); STEP(lists(2));
    STEP(event(CKR_NO_EVENT, 0, fixed ? "fixed-clear" : "removable-clear"));
    for (unsigned i = 0; i < 2; ++i)
      STEP(slot_flags(i, CKF_TOKEN_PRESENT | (fixed ? 0 : CKF_REMOVABLE_DEVICE),
                      fixed ? "fixed-flags" : "removable-flags"));
    CK_ULONG epochs[2]; STEP(status_epochs(epochs));
    REQUIRE(epochs[0] == 0 && epochs[1] == 0, "initial-epochs-zero");
    if (fixed) {
      char request[256]; CK_BYTE reply[65536]; CK_ULONG len = sizeof(reply);
      snprintf(request, sizeof(request), "{\"schema_version\":1,\"command\":\"token.remove\",\"arguments\":{\"slot\":%lu}}", slots[0]);
      RV(ctl((const CK_BYTE *)request, strlen(request), reply, &len),
         CKR_ARGUMENTS_BAD, "fixed-mutation-refused");
      STEP(lists(2)); STEP(event(CKR_NO_EVENT, 0, "fixed-refusal-clear"));
    }
    printf("notifications:initial/%s/%s/%s count=2 epochs=0,0 canary=pass\n",
           fixed ? "fixed" : "removable", version, storage);
    STEP(finalize());
  }
}

/* T-N03 casePresencePublication/removal; T-N04 empty versus unknown boundary. */
static void leg_presence(void) {
  STEP(initialize(0)); STEP(mutate(0, 0));
  STEP(lists(1)); STEP(slot_flags(0, CKF_REMOVABLE_DEVICE, "coherence-removed-flags"));
  TokenInfo info; memset(&info, 0xa5, sizeof(info)); TokenInfo before = info;
  RV(a.GetTokenInfo(slots[0], &info.value), CKR_TOKEN_NOT_PRESENT, "coherence-empty-token");
  REQUIRE(!memcmp(&info, &before, sizeof(info)), "empty-token-whole-canary");
  CK_SESSION_HANDLE h = SENTINEL;
  RV(a.OpenSession(slots[0], CKF_SERIAL_SESSION, NULL, NULL, &h),
     CKR_TOKEN_NOT_PRESENT, "coherence-empty-admission");
  REQUIRE(h == SENTINEL, "empty-session-sentinel");
  CK_ULONG epochs[2]; STEP(status_epochs(epochs));
  REQUIRE(epochs[0] == 1 && epochs[1] == 0, "coherence-remove-epoch");
  STEP(event(CKR_OK, 0, "queries-do-not-acknowledge"));
  STEP(event(CKR_NO_EVENT, 0, "remove-once"));
  STEP(mutate(0, 1)); STEP(lists(2));
  STEP(slot_flags(0, CKF_TOKEN_PRESENT | CKF_REMOVABLE_DEVICE, "insert-flags"));
  h = session(0, 0, NULL, NULL); if (failed) return;
  RV(a.CloseSession(h), CKR_OK, "insert-new-admission");
  STEP(event(CKR_OK, 0, "insert-event")); STEP(event(CKR_NO_EVENT, 0, "insert-once"));
}

/* T-N01 caseServingCoalesces/reference traces; T-N03 publication epoch.
 * A FIFO edge queue fails coalescing-second-poll, not a timeout. */
static void leg_coalescing(void) {
  STEP(initialize(0));
  STEP(mutate(0, 0)); STEP(mutate(0, 1)); STEP(mutate(0, 0));
  STEP(event(CKR_OK, 0, "coalescing-first-poll"));
  STEP(event(CKR_NO_EVENT, 0, "coalescing-second-poll"));
  CK_ULONG epochs[2]; STEP(status_epochs(epochs));
  REQUIRE(epochs[0] == 3 && epochs[1] == 0, "coalescing-epoch-plus-three");
  STEP(mutate(0, 0)); STEP(status_epochs(epochs));
  REQUIRE(epochs[0] == 3, "duplicate-remove-zero-epoch");
  STEP(event(CKR_NO_EVENT, 0, "duplicate-remove-zero-events"));
  STEP(mutate(0, 1)); STEP(event(CKR_OK, 0, "new-pending-after-consume"));
  STEP(mutate(0, 1)); STEP(status_epochs(epochs));
  REQUIRE(epochs[0] == 4, "duplicate-insert-zero-epoch");
  STEP(event(CKR_NO_EVENT, 0, "duplicate-insert-zero-events"));
  STEP(mutate(1, 0)); STEP(mutate(0, 0)); STEP(mutate(1, 1));
  STEP(lists(1)); STEP(event(CKR_OK, 1, "first-pending-slot-B"));
  STEP(event(CKR_OK, 0, "second-pending-slot-A"));
  STEP(event(CKR_NO_EVENT, 0, "both-consumed-once"));
  CK_ULONG count = 0; RV(a.GetSlotList(CK_TRUE, NULL, &count), CKR_OK, "grow-size");
  REQUIRE(count == 1, "grow-old-count-one"); STEP(mutate(0, 1));
  SlotList array; memset(&array, 0xa5, sizeof(array)); SlotList before = array;
  RV(a.GetSlotList(CK_TRUE, array.value, &count), CKR_BUFFER_TOO_SMALL, "grow-short");
  REQUIRE(count == 2 && !memcmp(&array, &before, sizeof(array)), "grow-short-count-and-canary");
  RV(a.GetSlotList(CK_TRUE, array.value, &count), CKR_OK, "grow-retry");
  REQUIRE(count == 2 && array.value[0] == slots[0] && array.value[1] == slots[1]
    && array.value[2] == SENTINEL && filled(array.pre, 16) && filled(array.post, 16),
    "grow-retry-discovered-identities");
  STEP(event(CKR_OK, 0, "grow-query-not-acknowledged"));
  STEP(event(CKR_NO_EVENT, 0, "grow-once"));
}

/* T-N03 caseRemovalOwnsActualJobs/casePresenceCleanupFault; T-N06 retirement.
 * No async tail reads on old layouts. T-N05 owns deterministic close ordering. */
static void leg_cleanup(void) {
  STEP(initialize(0)); STEP(allocate_pages());
  CK_SESSION_HANDLE ordinary = session(0, 0, NULL, NULL); if (failed) return;
  CK_SESSION_HANDLE other = session(1, 0, NULL, NULL); if (failed) return;
  CK_SESSION_HANDLE pending = session(0, 1, NULL, NULL); if (failed) return;
  RV(a.Login(ordinary, CKU_USER, (CK_UTF8CHAR *)"1234", 4), CKR_OK, "login-before-removal");
  CK_OBJECT_CLASS cls = CKO_DATA; CK_BBOOL yes = CK_TRUE, no = CK_FALSE;
  CK_ATTRIBUTE attrs[] = {{CKA_CLASS, &cls, sizeof(cls)}, {CKA_TOKEN, &no, sizeof(no)},
    {CKA_PRIVATE, &no, sizeof(no)}, {CKA_LABEL, (void *)"notifications-object", 20},
    {CKA_VALUE, (void *)"abc", 3}};
  CK_OBJECT_HANDLE so = SENTINEL, to = SENTINEL;
  RV(a.CreateObject(ordinary, attrs, N(attrs), &so), CKR_OK, "session-object");
  attrs[1].pValue = &yes;
  RV(a.CreateObject(ordinary, attrs, N(attrs), &to), CKR_OK, "token-object");
  RV(a.FindObjectsInit(ordinary, NULL, 0), CKR_OK, "cursor-before-removal");
  STEP(digest_init(ordinary));
  RV(a.DigestUpdate(ordinary, (CK_BYTE *)"abc", 3), CKR_OK, "multipart-before-removal");
  Output *bound = (Output *)pages; STEP(submit(pending, bound));
  CK_ULONG idle_id = SENTINEL, joined_id = SENTINEL;
  CK_SESSION_HANDLE joined = SENTINEL;
  Output idle_old, joined_old;
  int detached = a.AsyncGetID && !strcmp(storage, "sqlite");
  if (detached) {
    CK_SESSION_HANDLE source = session(0, 1, NULL, NULL); if (failed) return;
    STEP(submit(source, &idle_old));
    RV(a.AsyncGetID(source, (CK_UTF8CHAR *)"C_Digest", &idle_id), CKR_OK, "idle-detach");
    RV(a.CloseSession(source), CKR_OK, "idle-source-close");
    source = session(0, 1, NULL, NULL); if (failed) return;
    STEP(submit(source, &joined_old));
    RV(a.AsyncGetID(source, (CK_UTF8CHAR *)"C_Digest", &joined_id), CKR_OK, "joined-detach");
    joined = session(0, 1, NULL, NULL); if (failed) return;
    Output *joined_bound = (Output *)(pages + 256); reset_output(joined_bound, 32);
    STEP(digest_init(joined));
    RV(a.AsyncJoin(joined, (CK_UTF8CHAR *)"C_Digest", joined_id, joined_bound->bytes, 32),
       CKR_OK, "joined-attachment");
  }
  STEP(mutate(0, 0)); STEP(event(CKR_OK, 0, "retirement-indication"));
  REQUIRE(filled(bound->pre, 16) && filled(bound->bytes, 64) && filled(bound->post, 16)
          && bound->length == 32, "removed-async-output-untouched");
  STEP(stale(ordinary)); STEP(stale(pending));
  STEP(revoke_pages()); /* Only after proved retirement: no baseline UAF stunt. */
  if (detached) STEP(stale(joined));
  Output out; reset_output(&out, 32); STEP(digest_init(other));
  STEP(digest_call(other, &out, CKR_OK)); STEP(digest_exact(&out));
  STEP(mutate(0, 1)); STEP(event(CKR_OK, 0, "reinsert"));
  STEP(stale(ordinary)); STEP(stale(pending));
  CK_SESSION_HANDLE fresh = session(0, 0, NULL, NULL); if (failed) return;
  SessionInfo info; memset(&info, 0xa5, sizeof(info));
  RV(a.GetSessionInfo(fresh, &info.value), CKR_OK, "reinsert-session");
  REQUIRE(info.value.state == CKS_RW_PUBLIC_SESSION, "login-retired");
  CK_BYTE value[8]; memset(value, 0xa5, sizeof(value));
  CK_ATTRIBUTE query = {CKA_VALUE, value, sizeof(value)};
  RV(a.GetAttributeValue(fresh, so, &query, 1), CKR_OBJECT_HANDLE_INVALID, "session-object-handle-retired");
  RV(a.GetAttributeValue(fresh, to, &query, 1), CKR_OBJECT_HANDLE_INVALID, "token-object-handle-retired");
  RV(a.FindObjectsFinal(ordinary), CKR_SESSION_HANDLE_INVALID, "old-cursor-retired");
  reset_output(&out, 32);
  RV(a.DigestFinal(ordinary, out.bytes, &out.length), CKR_SESSION_HANDLE_INVALID, "old-multipart-retired");
  REQUIRE(filled(out.bytes, 64) && out.length == 32, "old-multipart-canary");
  RV(a.FindObjectsInit(fresh, &attrs[3], 1), CKR_OK, "rediscover-token-object");
  CK_OBJECT_HANDLE found[4]; CK_ULONG count = 0;
  RV(a.FindObjects(fresh, found, N(found), &count), CKR_OK, "rediscover-fetch");
  REQUIRE(count == 1 && found[0] != to && found[0] != so, "parked-token-fresh-handle");
  RV(a.FindObjectsFinal(fresh), CKR_OK, "rediscover-finish");
  RV(a.GetAttributeValue(fresh, to, &query, 1), CKR_OBJECT_HANDLE_INVALID, "stale-after-rediscovery");
  CK_OBJECT_HANDLE another = SENTINEL;
  attrs[1].pValue = &no;
  RV(a.CreateObject(fresh, attrs, N(attrs), &another), CKR_OK, "later-object-generation");
  RV(a.GetAttributeValue(fresh, to, &query, 1), CKR_OBJECT_HANDLE_INVALID, "stale-after-generation-change");
  if (a.AsyncComplete) {
    AsyncResult result; memset(&result, 0xa5, sizeof(result)); result.value.pValue = NULL;
    AsyncResult saved = result;
    RV(a.AsyncComplete(pending, (CK_UTF8CHAR *)"C_Digest", &result.value),
       CKR_SESSION_HANDLE_INVALID, "removed-completion");
    REQUIRE(!memcmp(&saved, &result, sizeof(result)), "removed-completion-canary");
    if (detached) {
      CK_SESSION_HANDLE target = session(0, 1, NULL, NULL); if (failed) return;
      reset_output(&out, 32);
      RV(a.AsyncJoin(target, (CK_UTF8CHAR *)"C_Digest", joined_id, out.bytes, 32),
         CKR_FUNCTION_CANCELED, "joined-removal-canceled");
      STEP(digest_init(target));
      RV(a.AsyncJoin(target, (CK_UTF8CHAR *)"C_Digest", idle_id, out.bytes, 32),
         CKR_OK, "idle-detached-rejoin");
      STEP(complete(target, &out));
      REQUIRE(filled(idle_old.bytes, 64) && filled(joined_old.bytes, 64), "detached-old-bindings-untouched");
      printf("notifications:cleanup/detached/%s/%s idle_join=pass joined_cancel=pass canary=pass\n", version, storage);
    }
  }
  printf("notifications:cleanup/revoked-output/%s/%s post_removal_writes=0 canary=pass\n", version, storage);
}

/* T-N05 before: service close precedes teardown. Native readiness is ONLY a
 * pre-call acknowledgement; T-N05's STM seams prove admission and winners. */
static void leg_waiters(void) {
  STEP(initialize(0)); STEP(mutate(0, 0));
  STEP(event(CKR_OK, 0, "prepare-absent"));
  STEP(start_waiters(2)); STEP(mutate(0, 1));
  unsigned successes = 0;
  for (unsigned i = 0; i < 16; ++i) {
    CK_SLOT_ID slot = SENTINEL; CK_RV rv = a.WaitForSlotEvent(CKF_DONT_BLOCK, &slot, NULL);
    REQUIRE(rv == CKR_OK || rv == CKR_NO_EVENT, "competing-poll-exact-rv");
    if (rv == CKR_OK) { REQUIRE(slot == slots[0], "competing-poll-slot-A"); ++successes; }
    else REQUIRE(slot == SENTINEL, "competing-poll-canary");
  }
  if (!successes) STEP(await_decision());
  STEP(finalize()); STEP(join_waiters());
  unsigned closed = 0;
  for (unsigned i = 0; i < 2; ++i) {
    if (waiters[i].rv == CKR_OK) {
      REQUIRE(waiters[i].slot == slots[0], "blocking-event-slot-A"); ++successes;
    } else {
      REQUIRE(waiters[i].rv == CKR_CRYPTOKI_NOT_INITIALIZED && waiters[i].slot == SENTINEL,
              "closed-blocker-exact-rv-canary"); ++closed;
    }
  }
  REQUIRE(successes == 1 && closed >= 1, "one-event-no-duplicates");
  printf("notifications:waiters/competition/%s/%s success=1 duplicates=0 canary=pass\n", version, storage);
  STEP(initialize(0)); STEP(event(CKR_NO_EVENT, 0, "reopened-clear"));
  for (unsigned i = 0; i < 100; ++i) {
    STEP(start_waiters(2)); STEP(event(CKR_NO_EVENT, 0, "empty-race-poll"));
    STEP(finalize()); STEP(join_waiters()); STEP(initialize(0));
    for (unsigned j = 0; j < 2; ++j)
      REQUIRE(waiters[j].rv == CKR_CRYPTOKI_NOT_INITIALIZED && waiters[j].slot == SENTINEL,
              "empty-race-closed-output");
    STEP(event(CKR_NO_EVENT, 0, "empty-race-reopen"));
  }
  printf("notifications:waiters/stress/%s/%s iterations=100 unexplained_ok=0 canary=pass\n", version, storage);
}

/* T-N06 native association/guard-before; T-N07 before: callback count 0
 * instead of 1. Cancellation/other returns must never publish output. */
static void leg_notify(void) {
  STEP(initialize(0));
  unsigned cookie = 7, second_cookie = 9;
  for (unsigned shape = 0; shape < 4; ++shape) {
    void *app = shape & 1 ? &cookie : NULL;
    CK_NOTIFY fn = shape & 2 ? notify : NULL;
    CK_SESSION_HANDLE h = session(0, 0, app, fn); if (failed) return;
    callback_for(h, app, CKR_OK, 0); STEP(digest_init(h));
    Output out; reset_output(&out, 32); STEP(digest_call(h, &out, CKR_OK));
    REQUIRE(atomic_load(&cb.calls) == (fn ? 1U : 0U), "callback-nullness-count");
    STEP(digest_exact(&out)); RV(a.CloseSession(h), CKR_OK, "shape-close");
  }
  CK_SESSION_HANDLE h = session(0, 0, &cookie, notify); if (failed) return;
  CK_SESSION_HANDLE other = session(0, 0, &second_cookie, notify); if (failed) return;
  const CK_RV responses[] = {CKR_OK, CKR_CANCEL, 0x1234567887654321UL};
  const CK_RV results[] = {CKR_OK, CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED};
  const char *names[] = {"callback-ok", "callback-cancel", "callback-other"};
  for (unsigned i = 0; i < 3; ++i) {
    STEP(digest_init(h)); STEP(digest_init(other));
    callback_for(h, &cookie, responses[i], 0);
    Output out; reset_output(&out, 32); Output saved = out;
    RV(a.Digest(h, (CK_BYTE *)"abc", 3, out.bytes, &out.length), results[i], names[i]);
    REQUIRE(atomic_load(&cb.calls) == 1, "callback-exactly-once");
    if (i == 0) STEP(digest_exact(&out));
    else REQUIRE(!memcmp(&out, &saved, sizeof(out)), "callback-refusal-whole-canary");
    reset_output(&out, 32); saved = out;
    RV(a.Digest(h, (CK_BYTE *)"abc", 3, out.bytes, &out.length), CKR_OPERATION_NOT_INITIALIZED,
       "callback-operation-terminated");
    REQUIRE(!memcmp(&out, &saved, sizeof(out)), "terminated-output-canary");
    callback_for(other, &second_cookie, CKR_OK, 0); reset_output(&out, 32);
    STEP(digest_call(other, &out, CKR_OK)); STEP(digest_exact(&out));
    REQUIRE(atomic_load(&cb.calls) == 1, "distinct-cookie-other-session");
  }
  callback_for(h, &cookie, CKR_OK, 0);
  Output out;
  for (unsigned shape = 0; shape < 3; ++shape) {
    STEP(digest_init(h)); reset_output(&out, shape == 1 ? 0 : 31);
    CK_RV want = shape ? CKR_BUFFER_TOO_SMALL : CKR_OK;
    RV(a.Digest(h, (CK_BYTE *)"abc", 3, shape ? out.bytes : NULL, &out.length), want,
       "query-short-nonproducer");
    REQUIRE(out.length == 32 && filled(out.bytes, 64), "query-short-canary");
    out.length = 64; STEP(digest_call(h, &out, CKR_OK)); STEP(digest_exact(&out));
    REQUIRE(atomic_load(&cb.calls) == 0, "query-short-recall-silent");
  }
  STEP(digest_init(h)); RV(a.DigestUpdate(h, (CK_BYTE *)"abc", 3), CKR_OK, "multipart-update");
  reset_output(&out, 32); RV(a.DigestFinal(h, out.bytes, &out.length), CKR_OK, "multipart-final");
  STEP(digest_exact(&out));
  CK_SESSION_HANDLE async = session(0, 1, &cookie, notify); if (failed) return;
  STEP(submit(async, &out));
  if (a.AsyncComplete) STEP(complete(async, &out));
  RV(a.CloseSession(async), CKR_OK, "async-close");
  SessionInfo info; RV(a.GetSessionInfo(h, &info.value), CKR_OK, "info-nonproducer");
  STEP(mutate(1, 0)); STEP(mutate(1, 1));
  STEP(event(CKR_OK, 1, "control-event-only")); STEP(event(CKR_NO_EVENT, 0, "callback-no-event"));
  RV(a.CloseSession(h), CKR_OK, "close-nonproducer");
  RV(a.CloseAllSessions(slots[0]), CKR_OK, "close-all-nonproducer");
  STEP(finalize()); REQUIRE(atomic_load(&cb.calls) == 0, "all-nonproducers-silent");
  printf("notifications:notify/nonproducers/%s/%s calls=0 nullness_shapes=4 canary=pass\n", version, storage);
}

/* T-N06 first-body guards and native association; T-N07 real callback reentry.
 * A C fixture catches its own simulated language exception as a status and
 * returns normally; no longjmp or foreign exception crosses the callback ABI. */
static void leg_reentry(void) {
  for (unsigned app = 0; app < 2; ++app) {
    STEP(initialize(app));
    unsigned cookie = 3;
    CK_SESSION_HANDLE h = session(0, 0, &cookie, notify); if (failed) return;
    callback_for(h, &cookie, CKR_OK, 1); STEP(digest_init(h));
    Output out; reset_output(&out, 32); STEP(digest_call(h, &out, CKR_OK));
    REQUIRE(atomic_load(&cb.calls) == 1, "reentry-real-callback-once"); STEP(digest_exact(&out));
    callback_for(h, &cookie, CKR_OK, 0); cb.caught_exception = 1;
    STEP(digest_init(h)); reset_output(&out, 32); Output saved = out;
    STEP(digest_call(h, &out, CKR_FUNCTION_FAILED));
    REQUIRE(cb.caught_exception == 2 && !memcmp(&out, &saved, sizeof(out)), "fixture-caught-exception");
    cb.caught_exception = 0;
    reset_output(&out, 32);
    STEP(digest_call(h, &out, CKR_OPERATION_NOT_INITIALIZED));
    RV(a.CloseSession(h), CKR_OK, "reentry-close");
    printf("notifications:reentry/%s/%s/%s static=pass prohibited=pass canary=pass\n",
           app ? "application-locks" : "internal-locks", version, storage);
    for (unsigned mode = 0; mode < 4; ++mode) STEP(retirement(mode));
    STEP(finalize());
    REQUIRE(!app || (atomic_load(&app_held) == 0 && atomic_load(&app_locks) == atomic_load(&app_unlocks)),
            "application-locks-balanced");
  }
}

/* T-N02 acquisition and T-N03 caseServingStorageRestart. Native query labels
 * and read-only SQLite generation snapshot corroborate unchanged identity;
 * ordinary object durability is deliberately not inferred. */
static void leg_restart(void) {
  STEP(initialize(0));
  TokenInfo before, after; memset(&before, 0xa5, sizeof(before));
  RV(a.GetTokenInfo(slots[0], &before.value), CKR_OK, "restart-initial-identity");
  CK_SLOT_ID original[2] = {slots[0], slots[1]};
  if (!strcmp(storage, "sqlite")) {
    STEP(finalize()); STEP(durable_snapshot(0)); STEP(initialize(0));
  }
  unsigned cookie = 5;
  CK_SESSION_HANDLE old = session(0, 0, &cookie, notify); if (failed) return;
  callback_for(old, &cookie, CKR_OK, 0);
  STEP(mutate(0, 0)); STEP(finalize()); STEP(initialize(0));
  REQUIRE(slots[0] == original[0] && slots[1] == original[1], "restart-configured-slot-identity");
  STEP(lists(2)); STEP(event(CKR_NO_EVENT, 0, "restart-no-replay"));
  memset(&after, 0xa5, sizeof(after));
  RV(a.GetTokenInfo(slots[0], &after.value), CKR_OK, "restart-token-info");
  REQUIRE(!memcmp(before.value.label, after.value.label, sizeof(before.value.label)) &&
          !memcmp(before.value.serialNumber, after.value.serialNumber, sizeof(before.value.serialNumber)),
          "restart-token-identity");
  CK_ULONG epochs[2]; STEP(status_epochs(epochs));
  REQUIRE(!epochs[0] && !epochs[1], "restart-epochs-zero");
  REQUIRE(atomic_load(&cb.calls) == 0, "restart-no-old-callback");
  CK_SESSION_HANDLE fresh = session(0, 0, NULL, NULL); if (failed) return;
  STEP(digest_init(fresh)); Output out; reset_output(&out, 32);
  STEP(digest_call(fresh, &out, CKR_OK)); STEP(digest_exact(&out));
  REQUIRE(atomic_load(&cb.calls) == 0, "restart-registration-not-reused");
  if (!strcmp(storage, "sqlite")) { STEP(finalize()); STEP(durable_snapshot(1)); }
  printf("notifications:restart/storage/%s/%s identity=pass generation=%s replay=0 canary=pass\n",
         version, storage, !strcmp(storage, "sqlite") ? "unchanged" : "transient");
}

/* Fixture implementations are added only after the nine assertion bodies. */
static int check(int good, const char *name) {
  if (failed) return 0;
  ++assertions;
  printf("notifications:%s/%s/%s/%s check=%s\n", leg, name, version, storage, good ? "pass" : "FAIL");
  if (!good) failed = 1;
  return good;
}
static int expect(CK_RV got, CK_RV want, const char *name) {
  if (failed) return 0;
  printf("notifications:%s/%s/%s/%s rv=0x%lx expected=0x%lx\n", leg, name, version, storage, got, want);
  return check(got == want, name);
}
static int filled(const void *memory, size_t n) {
  const CK_BYTE *p = memory;
  for (size_t i = 0; i < n; ++i) if (p[i] != 0xa5) return 0;
  return 1;
}
static void setup_error(const char *what) {
  printf("notifications:%s/setup-error/%s/%s reason=%s\n", leg, version, storage, what);
  /* Process exit, never a semantic-red relabel. Parent reaps this child. */
  _Exit(2);
}
static void path_for(char *out, size_t size, const char *base) {
  int n = snprintf(out, size, "%s/%s", directory, base);
  if (n < 0 || (size_t)n >= size) setup_error("path-length");
}
static void configure(int removable) {
  path_for(fixture_config, sizeof(fixture_config), removable ? "removable.toml" : "fixed.toml");
  int fd = open(fixture_config, O_CREAT | O_EXCL | O_WRONLY | O_NOFOLLOW, 0600);
  if (fd < 0) {
    if (errno != EEXIST) setup_error("config-create");
    /* Within one owned child only: fixed/removable may be selected again. */
  } else {
    FILE *f = fdopen(fd, "w"); if (!f) setup_error("config-stream");
    int wrote = fprintf(f, "schema_version = 1\nprofile = \"real-crypto\"\n"
      "[tokens]\nlabels = [\"haskoki-demo\", \"notifications-B\"]\n"
      "so_pins = [\"5678\", \"5678\"]\nuser_pins = [\"1234\", \"1234\"]\n"
      "[storage]\nkind = \"%s\"\n", storage);
    if (!strcmp(storage, "sqlite") && fprintf(f, "path = \"%s/tokens.db\"\n", directory) < 0)
      setup_error("sqlite-config");
    int rest = fprintf(f, "[engine]\nkind = \"openssl\"\nallow_synthetic_fallback = false\n"
      "private_library_context = true\n[trace]\nenabled = false\n"
      "[control]\nenabled = true\ntest_enabled = %s\n[limits]\nevents = 2\n", removable ? "true" : "false");
    if (fclose(f) || wrote < 0 || rest < 0) setup_error("config-write");
  }
  if (setenv("HASKOKI_CONFIG", fixture_config, 1)) setup_error("config-environment");
}
static CK_RV create_mutex(void **out) {
  pthread_mutex_t *p = malloc(sizeof(*p)); if (!p) return CKR_HOST_MEMORY;
  /* Default POSIX mutexes are nonrecursive: guard bugs deadlock and the
   * process supervisor reports setup/timeout, never an expected red. */
  if (pthread_mutex_init(p, NULL)) { free(p); return CKR_GENERAL_ERROR; }
  *out = p; return CKR_OK;
}
static CK_RV destroy_mutex(void *p) {
  int rc = pthread_mutex_destroy(p); free(p); return rc ? CKR_GENERAL_ERROR : CKR_OK;
}
static CK_RV lock_mutex(void *p) {
  atomic_fetch_add(&app_locks, 1);
  int rc = pthread_mutex_lock(p);
  if (!rc) atomic_fetch_add(&app_held, 1);
  return rc ? CKR_GENERAL_ERROR : CKR_OK;
}
static CK_RV unlock_mutex(void *p) {
  atomic_fetch_add(&app_unlocks, 1); atomic_fetch_sub(&app_held, 1);
  return pthread_mutex_unlock(p) ? CKR_GENERAL_ERROR : CKR_OK;
}
static void initialize(int app) {
  CK_C_INITIALIZE_ARGS args = {0}; args.flags = CKF_OS_LOCKING_OK;
  application_locks = app;
  if (app) {
    args.CreateMutex = create_mutex; args.DestroyMutex = destroy_mutex;
    args.LockMutex = lock_mutex; args.UnlockMutex = unlock_mutex;
  }
  RV(a.Initialize(&args), CKR_OK, "initialize"); live = 1;
  STEP(discover_slots());
}
static void finalize(void) {
  RV(a.Finalize(NULL), CKR_OK, "finalize"); live = 0;
}
static void discover_slots(void) {
  CK_ULONG count = 0;
  RV(a.GetSlotList(CK_FALSE, NULL, &count), CKR_OK, "discover-count");
  REQUIRE(count == 2, "discover-two-configured-slots");
  RV(a.GetSlotList(CK_FALSE, slots, &count), CKR_OK, "discover-list");
  REQUIRE(count == 2 && slots[0] < slots[1], "discover-ordered-unique");
  printf("notifications:%s/discovered/%s/%s count=2 logical=slot-A,slot-B\n", leg, version, storage);
}
static CK_SLOT_ID unknown_slot(void) {
  CK_SLOT_ID id = ~0UL;
  while (id == slots[0] || id == slots[1]) --id;
  return id;
}
static void mutate(unsigned slot, int present) {
  char request[256]; CK_BYTE reply[65536]; CK_ULONG length = sizeof(reply);
  snprintf(request, sizeof(request), "{\"schema_version\":1,\"command\":\"token.%s\",\"arguments\":{\"slot\":%lu}}",
           present ? "insert" : "remove", slots[slot]);
  RV(ctl((const CK_BYTE *)request, strlen(request), reply, &length), CKR_OK,
     present ? "control-insert" : "control-remove");
}
static void status_epochs(CK_ULONG epochs[2]) {
  static const char request[] = "{\"schema_version\":1,\"command\":\"status\",\"arguments\":{}}";
  char reply[65537]; CK_ULONG length = 65536;
  RV(ctl((const CK_BYTE *)request, strlen(request), (CK_BYTE *)reply, &length), CKR_OK, "status");
  REQUIRE(length <= 65536, "status-bounded"); reply[length] = 0;
  /* Parse the bounded, flat slot records, by discovered identity. JSON key
   * order is immaterial. Never print the response's physical slot numbers. */
  const char *array = strstr(reply, "\"presence\"");
  REQUIRE(array != NULL, "status-catalog");
  unsigned found = 0, rows = 0;
  while ((array = strchr(array, '{')) != NULL) {
    const char *end = strchr(array, '}'); REQUIRE(end != NULL, "status-record-closed");
    const char *id = strstr(array, "\"slot\"");
    const char *gen = strstr(array, "\"generation\"");
    if (!id || id > end || !gen || gen > end) break;
    id = strchr(id, ':'); gen = strchr(gen, ':');
    REQUIRE(id && gen, "status-scalars");
    unsigned long slot = strtoul(id + 1, NULL, 10), epoch = strtoul(gen + 1, NULL, 10);
    for (unsigned i = 0; i < 2; ++i) if (slot == slots[i]) { epochs[i] = epoch; found |= 1U << i; }
    ++rows; array = end + 1;
  }
  REQUIRE(found == 3 && rows == 2, "status-actual-catalog");
  printf("notifications:%s/epochs/%s/%s slot-A=%lu slot-B=%lu\n", leg, version, storage, epochs[0], epochs[1]);
}
static void event(CK_RV want, unsigned index, const char *name) {
  CK_SLOT_ID slot = SENTINEL;
  RV(a.WaitForSlotEvent(CKF_DONT_BLOCK, &slot, NULL), want, name);
  REQUIRE(want == CKR_OK ? slot == slots[index] : slot == SENTINEL, "event-identity-or-canary");
  printf("notifications:%s/event-output/%s/%s logical=%s canary=pass\n", leg, version, storage,
         want == CKR_OK ? (index ? "slot-B" : "slot-A") : "unchanged");
}
static void lists(CK_ULONG present) {
  for (unsigned b = 0; b < 2; ++b) {
    CK_ULONG count = 3; SlotList list; memset(&list, 0xa5, sizeof(list));
    RV(a.GetSlotList(b ? CK_TRUE : CK_FALSE, list.value, &count), CKR_OK,
       b ? "coherence-present-list" : "coherence-full-list");
    REQUIRE(count == (b ? present : 2), "coherence-list-count");
    REQUIRE(filled(list.pre, 16) && filled(list.post, 16) && list.value[count] == SENTINEL,
            "list-prefix-tail-canary");
    for (CK_ULONG i = 0; i < count; ++i)
      REQUIRE((list.value[i] == slots[0] || list.value[i] == slots[1]) &&
              (!i || list.value[i-1] < list.value[i]), "list-discovered-identities");
    printf("notifications:%s/list-count/%s/%s present_filter=%u count=%lu canary=pass\n", leg, version, storage, b, count);
  }
}
static void slot_flags(unsigned i, CK_FLAGS want, const char *name) {
  SlotInfo info; memset(&info, 0xa5, sizeof(info));
  RV(a.GetSlotInfo(slots[i], &info.value), CKR_OK, "slot-info");
  printf("notifications:%s/%s/%s/%s flags=0x%lx expected=0x%lx\n", leg, name, version, storage, info.value.flags, want);
  REQUIRE(info.value.flags == want && !(info.value.flags & CKF_HW_SLOT), name);
  REQUIRE(filled(info.pre, 16) && filled(info.post, 16), "slot-info-canaries");
}
static CK_SESSION_HANDLE session(unsigned i, int async, void *cookie, CK_NOTIFY fn) {
  CK_SESSION_HANDLE h = SENTINEL;
  if (!expect(a.OpenSession(slots[i], CKF_SERIAL_SESSION | CKF_RW_SESSION |
      (async ? CKF_ASYNC_SESSION : 0), cookie, fn, &h), CKR_OK, "session-open")) return SENTINEL;
  check(h != SENTINEL && h != CK_INVALID_HANDLE, "session-published"); return h;
}
static void digest_init(CK_SESSION_HANDLE h) {
  CK_MECHANISM mechanism = {CKM_SHA256, NULL, 0};
  RV(a.DigestInit(h, &mechanism), CKR_OK, "digest-init");
}
static void reset_output(Output *out, CK_ULONG capacity) {
  memset(out, 0xa5, sizeof(*out)); out->length = capacity;
}
static void digest_exact(Output *out) {
  printf("notifications:%s/digest/%s/%s length=%lu hex=", leg, version, storage, out->length);
  for (unsigned i = 0; i < 32; ++i) printf("%02x", out->bytes[i]);
  putchar('\n');
  REQUIRE(out->length == 32 && !memcmp(out->bytes, kat, 32) && filled(out->pre, 16) &&
          filled(out->bytes + 32, 32) && filled(out->post, 16), "digest-exact-canary");
}
static void digest_call(CK_SESSION_HANDLE h, Output *out, CK_RV want) {
  RV(a.Digest(h, (CK_BYTE *)"abc", 3, out->bytes, &out->length), want, "digest-result");
}
static void stale(CK_SESSION_HANDLE h) {
  SessionInfo info; memset(&info, 0xa5, sizeof(info)); SessionInfo before = info;
  RV(a.GetSessionInfo(h, &info.value), CKR_SESSION_HANDLE_INVALID, "removed-session-invalid");
  REQUIRE(!memcmp(&info, &before, sizeof(info)), "removed-session-whole-canary");
}
static void submit(CK_SESSION_HANDLE h, Output *out) {
  STEP(digest_init(h)); reset_output(out, 32); Output before = *out;
  RV(a.Digest(h, (CK_BYTE *)"abc", 3, out->bytes, &out->length), CKR_PENDING, "async-submit");
  REQUIRE(!memcmp(out, &before, sizeof(*out)), "async-submit-unchanged");
}
static void complete(CK_SESSION_HANDLE h, Output *out) {
  AsyncResult result; memset(&result, 0xa5, sizeof(result)); result.value.pValue = NULL;
  AsyncResult saved = result; Output before = *out;
  RV(a.AsyncComplete(h, (CK_UTF8CHAR *)"C_Digest", &result.value), CKR_PENDING, "async-complete-pending");
  REQUIRE(!memcmp(&result, &saved, sizeof(result)) && !memcmp(out, &before, sizeof(*out)), "async-pending-canary");
  RV(a.AsyncComplete(h, (CK_UTF8CHAR *)"C_Digest", &result.value), CKR_OK, "async-complete");
  REQUIRE(result.value.ulVersion == 0 && result.value.pValue == out->bytes && result.value.ulValue == 32 &&
    result.value.hObject == 0 && result.value.hAdditionalObject == 0 && filled(result.pre, 16) && filled(result.post, 16),
    "async-result-whole-canary");
  STEP(digest_exact(out));
}
static void wait_shape_matrix(int is_live, const char *phase) {
  CK_FLAGS high = 1UL << (sizeof(CK_FLAGS) * CHAR_BIT - 1);
  const char *names[] = {"null", "reserved", "flags-two", "flags-three", "high", "combined"};
  for (unsigned mode = 0; mode < 2; ++mode) {
    for (unsigned shape = 0; shape < N(names); ++shape) {
      CK_SLOT_ID slot = SENTINEL;
      CK_FLAGS flags = mode ? CKF_DONT_BLOCK : 0;
      if (shape == 2) flags |= 2;
      if (shape == 3) flags |= CKF_DONT_BLOCK | 2;
      if (shape >= 4) flags |= high;
      if (is_live) {
        /* Deliberately seed BOTH blocking and polling probes. A broken old
         * guard can consume and return OK; it cannot hang this intended red. */
        STEP(mutate(0, 0)); STEP(mutate(0, 1));
      }
      char name[128]; snprintf(name, sizeof(name), "%s-%s-%s", phase, names[shape], mode ? "poll" : "block");
      void *reserved = shape == 1 || shape == 5 ? (void *)(uintptr_t)1 : NULL;
      RV(a.WaitForSlotEvent(flags, shape == 0 || shape == 5 ? NULL : &slot, reserved),
         is_live ? CKR_ARGUMENTS_BAD : CKR_CRYPTOKI_NOT_INITIALIZED, name);
      REQUIRE(slot == SENTINEL, "malformed-wait-canary");
      if (is_live) {
        STEP(event(CKR_OK, 0, "malformed-no-consumption"));
        STEP(event(CKR_NO_EVENT, 0, "malformed-pending-once"));
      }
    }
    if (!is_live) {
      CK_SLOT_ID slot = SENTINEL;
      RV(a.WaitForSlotEvent(mode ? CKF_DONT_BLOCK : 0, &slot, NULL), CKR_CRYPTOKI_NOT_INITIALIZED,
         "lifecycle-valid-shape");
      REQUIRE(slot == SENTINEL, "lifecycle-valid-canary");
    }
  }
  if (is_live) STEP(event(CKR_NO_EVENT, 0, "live-empty-poll"));
}
static void list_boundaries(void) {
  RV(a.GetSlotList(CK_FALSE, NULL, NULL), CKR_ARGUMENTS_BAD, "list-null-count");
  for (unsigned b = 0; b < 3; ++b) {
    CK_BBOOL filter = b == 0 ? CK_FALSE : b == 1 ? CK_TRUE : (CK_BBOOL)0xff;
    CK_ULONG count = SENTINEL;
    RV(a.GetSlotList(filter, NULL, &count), CKR_OK, "list-null-ignores-count");
    REQUIRE(count == 2, "list-null-count-two");
    for (unsigned capacity = 0; capacity < 3; ++capacity) {
      SlotList list; memset(&list, 0xa5, sizeof(list)); SlotList before = list;
      count = capacity;
      RV(a.GetSlotList(filter, list.value, &count), capacity < 2 ? CKR_BUFFER_TOO_SMALL : CKR_OK,
         capacity < 2 ? "list-short" : "list-adequate");
      REQUIRE(count == 2, "list-required-two");
      if (capacity < 2) REQUIRE(!memcmp(&list, &before, sizeof(list)), "list-short-whole-canary");
      else REQUIRE(list.value[0] == slots[0] && list.value[1] == slots[1] && list.value[2] == SENTINEL &&
                   filled(list.pre, 16) && filled(list.post, 16), "list-adequate-identities-canary");
    }
  }
}
static void boundary_slots(void) {
  CK_SLOT_ID unknown = unknown_slot();
  SlotInfo info; memset(&info, 0xa5, sizeof(info)); SlotInfo si = info;
  TokenInfo token; memset(&token, 0xa5, sizeof(token)); TokenInfo ti = token;
  RV(a.GetSlotInfo(unknown, NULL), CKR_SLOT_ID_INVALID, "unknown-slot-null");
  RV(a.GetSlotInfo(unknown, &info.value), CKR_SLOT_ID_INVALID, "unknown-slot");
  REQUIRE(!memcmp(&si, &info, sizeof(info)), "unknown-slot-whole-canary");
  RV(a.GetTokenInfo(unknown, NULL), CKR_SLOT_ID_INVALID, "unknown-token-null");
  RV(a.GetTokenInfo(unknown, &token.value), CKR_SLOT_ID_INVALID, "unknown-token");
  REQUIRE(!memcmp(&ti, &token, sizeof(token)), "unknown-token-whole-canary");
  RV(a.GetSlotInfo(slots[0], NULL), CKR_ARGUMENTS_BAD, "present-slot-null");
  RV(a.GetTokenInfo(slots[0], NULL), CKR_ARGUMENTS_BAD, "present-token-null");
  CK_SESSION_HANDLE h = SENTINEL;
  RV(a.OpenSession(unknown, CKF_SERIAL_SESSION, NULL, NULL, &h), CKR_SLOT_ID_INVALID, "unknown-session");
  REQUIRE(h == SENTINEL, "unknown-session-canary");
  RV(a.OpenSession(unknown, 0, NULL, NULL, NULL), CKR_ARGUMENTS_BAD, "open-null-first");
  RV(a.OpenSession(unknown, 0, NULL, NULL, &h), CKR_SESSION_PARALLEL_NOT_SUPPORTED, "open-serial-first");
  RV(a.OpenSession(unknown, CKF_SERIAL_SESSION | (1UL << 63), NULL, NULL, &h), CKR_ARGUMENTS_BAD, "open-unknown-flags");
  RV(a.CloseAllSessions(unknown), CKR_SLOT_ID_INVALID, "unknown-close-all");
  char request[256]; CK_BYTE reply[65536]; CK_ULONG length = sizeof(reply);
  snprintf(request, sizeof(request), "{\"schema_version\":1,\"command\":\"token.remove\",\"arguments\":{\"slot\":%lu}}", unknown);
  RV(ctl((CK_BYTE *)request, strlen(request), reply, &length), CKR_ARGUMENTS_BAD, "unknown-control");
  STEP(event(CKR_NO_EVENT, 0, "unknown-control-no-event")); STEP(mutate(0, 0));
  RV(a.GetSlotInfo(slots[0], NULL), CKR_ARGUMENTS_BAD, "empty-slot-null");
  STEP(slot_flags(0, CKF_REMOVABLE_DEVICE, "empty-slot-valid"));
  RV(a.GetTokenInfo(slots[0], NULL), CKR_TOKEN_NOT_PRESENT, "empty-token-null");
  RV(a.GetTokenInfo(slots[0], &token.value), CKR_TOKEN_NOT_PRESENT, "empty-token");
  REQUIRE(!memcmp(&ti, &token, sizeof(token)), "empty-token-whole-canary");
  RV(a.OpenSession(slots[0], CKF_SERIAL_SESSION, NULL, NULL, &h), CKR_TOKEN_NOT_PRESENT, "empty-open");
  REQUIRE(h == SENTINEL, "empty-open-canary");
  CK_ULONG count = SENTINEL;
  RV(a.GetMechanismList(slots[0], NULL, &count), CKR_TOKEN_NOT_PRESENT, "empty-mechanisms");
  REQUIRE(count == SENTINEL, "empty-mechanism-count-canary");
  RV(a.CloseAllSessions(slots[0]), CKR_OK, "empty-close-all");
  STEP(event(CKR_OK, 0, "boundary-queries-no-consumption"));
}
static void callback_for(CK_SESSION_HANDLE h, void *cookie, CK_RV result, int reentry) {
  cb.session = h; cb.cookie = cookie; cb.thread = pthread_self(); cb.result = result;
  cb.reentry = reentry; cb.caught_exception = 0; atomic_store(&cb.calls, 0);
}
static int catch_fixture_exception(void) {
  /* This jump is entirely inside the fixture's own frame. It cannot skip a
   * provider or callback ABI frame, unlike an application longjmp to main. */
  jmp_buf scope;
  if (setjmp(scope) == 0) longjmp(scope, 1);
  return 1;
}
static CK_RV notify(CK_SESSION_HANDLE h, CK_NOTIFICATION event_value, void *cookie) {
  atomic_fetch_add(&cb.calls, 1);
  if (!check(h == cb.session && cookie == cb.cookie && event_value == CKN_SURRENDER &&
             pthread_equal(cb.thread, pthread_self()), "native-callback-session-cookie-thread")) return CKR_FUNCTION_FAILED;
  if (cookie && !check(*(const unsigned *)cookie != 0, "callback-cookie-readable")) return CKR_FUNCTION_FAILED;
  if (application_locks && !check(atomic_load(&app_held) == 1, "callback-state-lease")) return CKR_FUNCTION_FAILED;
  if (cb.caught_exception == 1) {
    cb.caught_exception = catch_fixture_exception() ? 2 : 0;
    return CKR_GENERAL_ERROR; /* Dispatcher must map this to FUNCTION_FAILED. */
  }
  if (cb.reentry) {
    CK_FUNCTION_LIST *legacy = NULL; CK_INTERFACE *interface = NULL;
    CK_ULONG count = 0; CK_VERSION v = {3, 2}; CK_INFO info;
    if (!expect(get_list(&legacy), CKR_OK, "static-list") || !check(legacy != NULL, "static-legacy-table") ||
        !expect(get_interfaces(NULL, &count), CKR_OK, "static-interfaces") || !check(count == 3, "static-interface-count") ||
        !expect(get_interface(NULL, &v, &interface, 0), CKR_OK, "static-interface") ||
        !check(interface != NULL, "static-interface-present") || !expect(a.GetInfo(&info), CKR_OK, "static-info"))
      return CKR_FUNCTION_FAILED;
    unsigned locks = atomic_load(&app_locks), unlocks = atomic_load(&app_unlocks);
    Output out; reset_output(&out, 32); Output saved = out;
    CK_SLOT_ID slot = SENTINEL; count = SENTINEL;
    SlotInfo si; memset(&si, 0xa5, sizeof(si)); SlotInfo si_before = si;
    CK_SESSION_HANDLE s = SENTINEL;
#define REJECT(c, n) do { if (!expect((c), CKR_FUNCTION_FAILED, (n))) return CKR_FUNCTION_FAILED; } while (0)
    REJECT(a.GetSlotList(CK_TRUE, &slot, &count), "reentry-slot-list");
    REJECT(a.GetSlotInfo(slots[0], &si.value), "reentry-slot-info");
    REJECT(a.GetTokenInfo(slots[0], (void *)(uintptr_t)1), "reentry-token-invalid-pointer");
    REJECT(a.OpenSession(slots[0], CKF_SERIAL_SESSION, cookie, notify, &s), "reentry-open");
    REJECT(a.GetSessionInfo(h, (void *)(uintptr_t)1), "reentry-session-invalid-pointer");
    REJECT(a.Digest(h, NULL, 3, out.bytes, &out.length), "reentry-digest");
    REJECT(a.DigestInit(h, (void *)(uintptr_t)1), "reentry-init-invalid-pointer");
    REJECT(a.DigestUpdate(h, NULL, 3), "reentry-update");
    REJECT(a.DigestFinal(h, out.bytes, &out.length), "reentry-final");
    REJECT(a.GenerateRandom(h, out.bytes, 32), "reentry-rng");
    REJECT(a.WaitForSlotEvent(0, &slot, NULL), "reentry-wait-block");
    REJECT(a.WaitForSlotEvent(CKF_DONT_BLOCK, &slot, NULL), "reentry-wait-poll");
    REJECT(a.WaitForSlotEvent(~0UL, (void *)(uintptr_t)1, (void *)(uintptr_t)1), "reentry-wait-invalid-pointer");
    REJECT(ctl(NULL, 1, out.bytes, &out.length), "reentry-control-malformed");
    char req[256]; snprintf(req, sizeof(req), "{\"schema_version\":1,\"command\":\"token.remove\",\"arguments\":{\"slot\":%lu}}", slots[0]);
    REJECT(ctl((CK_BYTE *)req, strlen(req), out.bytes, &out.length), "reentry-control-remove");
    if (a.SessionCancel) REJECT(a.SessionCancel(h, CKF_DIGEST), "reentry-session-cancel");
    REJECT(a.CloseSession(h), "reentry-close");
    REJECT(a.CloseAllSessions(slots[0]), "reentry-close-all");
    REJECT(a.Initialize((void *)(uintptr_t)1), "reentry-initialize");
    REJECT(a.Finalize(NULL), "reentry-finalize");
#undef REJECT
    if (!check(!memcmp(&out, &saved, sizeof(out)) && !memcmp(&si, &si_before, sizeof(si)) &&
               slot == SENTINEL && count == SENTINEL && s == SENTINEL, "reentry-whole-canaries") ||
        !check(locks == atomic_load(&app_locks) && unlocks == atomic_load(&app_unlocks), "reentry-before-locks"))
      return CKR_FUNCTION_FAILED;
  }
  return cb.result;
}
static void allocate_pages(void) {
  if (pages) setup_error("duplicate-pages");
  long size = sysconf(_SC_PAGESIZE); if (size < 4096) setup_error("page-size");
  page_size = (size_t)size;
  pages = mmap(NULL, page_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (pages == MAP_FAILED) { pages = NULL; setup_error("guarded-allocation"); }
}
static void revoke_pages(void) {
  if (mprotect(pages, page_size, PROT_NONE)) setup_error("revoke-pages");
}
static void retirement(unsigned mode) {
  STEP(allocate_pages()); *(unsigned *)pages = 17;
  CK_SESSION_HANDLE old = session(0, 0, pages, notify); if (failed) return;
  callback_for(old, pages, CKR_OK, 0);
  if (mode == 0) RV(a.CloseSession(old), CKR_OK, "retirement-close");
  if (mode == 1) RV(a.CloseAllSessions(slots[0]), CKR_OK, "retirement-close-all");
  if (mode == 2) STEP(mutate(0, 0));
  int app = application_locks;
  if (mode == 3) STEP(finalize());
  REQUIRE(atomic_load(&cb.calls) == 0, "retirement-silent");
  STEP(revoke_pages());
  if (mode < 3) STEP(stale(old));
  else STEP(initialize(app));
  if (mode == 2) STEP(mutate(0, 1));
  CK_SESSION_HANDLE fresh = session(0, 0, NULL, NULL); if (failed) return;
  STEP(digest_init(fresh)); Output out; reset_output(&out, 32);
  STEP(digest_call(fresh, &out, CKR_OK)); STEP(digest_exact(&out));
  REQUIRE(atomic_load(&cb.calls) == 0, "retired-cookie-no-access");
  RV(a.CloseSession(fresh), CKR_OK, "retirement-fresh-close");
  if (munmap(pages, page_size)) setup_error("unmap-cookie");
  pages = NULL;
  static const char *names[] = {"retired-close", "retired-all", "retired-remove", "retired-finalize"};
  printf("notifications:reentry/%s/%s/%s retired_callback_accesses=0 canary=pass\n", names[mode], version, storage);
}
static struct timespec deadline(unsigned seconds) {
  struct timespec time; if (clock_gettime(CLOCK_REALTIME, &time)) setup_error("clock");
  time.tv_sec += seconds; return time;
}
static void *wait_thread(void *arg) {
  Waiter *w = arg;
  pthread_mutex_lock(&wait_mutex); w->started = 1; pthread_cond_broadcast(&wait_cond); pthread_mutex_unlock(&wait_mutex);
  CK_SLOT_ID slot = SENTINEL; CK_RV rv = a.WaitForSlotEvent(0, &slot, NULL);
  pthread_mutex_lock(&wait_mutex); w->rv = rv; w->slot = slot; w->done = 1;
  pthread_cond_broadcast(&wait_cond); pthread_mutex_unlock(&wait_mutex);
  return NULL;
}
static void start_waiters(unsigned count) {
  if (waiter_count || count > 2) setup_error("waiter-ownership");
  memset(waiters, 0, sizeof(waiters));
  for (unsigned i = 0; i < count; ++i) {
    if (pthread_create(&waiters[i].thread, NULL, wait_thread, &waiters[i])) setup_error("create-waiter");
    ++waiter_count;
  }
  struct timespec until = deadline(10);
  pthread_mutex_lock(&wait_mutex);
  for (;;) {
    unsigned started = 0;
    for (unsigned i = 0; i < count; ++i) started += (unsigned)waiters[i].started;
    if (started == count) break;
    if (pthread_cond_timedwait(&wait_cond, &wait_mutex, &until)) { pthread_mutex_unlock(&wait_mutex); setup_error("waiter-start-timeout"); }
  }
  pthread_mutex_unlock(&wait_mutex);
}
static void await_decision(void) {
  struct timespec until = deadline(10);
  pthread_mutex_lock(&wait_mutex);
  while (!waiters[0].done && !waiters[1].done) {
    if (pthread_cond_timedwait(&wait_cond, &wait_mutex, &until)) { pthread_mutex_unlock(&wait_mutex); setup_error("waiter-decision-timeout"); }
  }
  pthread_mutex_unlock(&wait_mutex);
}
static void join_waiters(void) {
  for (unsigned i = 0; i < waiter_count; ++i) {
    struct timespec until = deadline(10);
    if (pthread_timedjoin_np(waiters[i].thread, NULL, &until)) setup_error("waiter-join-timeout");
  }
  waiter_count = 0;
}
static void durable_snapshot(int compare) {
  /* With this token-only fixture the closed SQLite image must remain byte
   * identical. That includes the durable generation fields, without a system
   * SQLite dependency or a second store owner. No ordinary objects are created.
   * The host evidence checker also decodes the saved token-generation rows. */
  if (live) setup_error("database-snapshot-while-live");
  char path[PATH_MAX]; path_for(path, sizeof(path), "tokens.db");
  FILE *f = fopen(path, "rb"); if (!f) setup_error("database-snapshot-open");
  if (fseek(f, 0, SEEK_END)) setup_error("database-snapshot-seek");
  long length = ftell(f);
  if (length < 100 || length > 4 * 1024 * 1024 || fseek(f, 0, SEEK_SET)) setup_error("database-snapshot-size");
  CK_BYTE *bytes = malloc((size_t)length); if (!bytes) setup_error("database-snapshot-memory");
  if (fread(bytes, 1, (size_t)length, f) != (size_t)length || fclose(f)) setup_error("database-snapshot-read");
  if (memcmp(bytes, "SQLite format 3", 16)) { free(bytes); setup_error("database-snapshot-format"); }
  path_for(path, sizeof(path), compare ? "generation-after.db" : "generation-before.db");
  int fd = open(path, O_CREAT | O_EXCL | O_WRONLY | O_NOFOLLOW, 0600);
  if (fd < 0) setup_error("database-snapshot-create");
  FILE *saved = fdopen(fd, "wb"); if (!saved) setup_error("database-snapshot-stream");
  if (fwrite(bytes, 1, (size_t)length, saved) != (size_t)length || fclose(saved)) setup_error("database-snapshot-save");
  if (!compare) { durable_copy = bytes; durable_size = (size_t)length; }
  else {
    int same = durable_size == (size_t)length && !memcmp(durable_copy, bytes, durable_size);
    free(bytes); free(durable_copy); durable_copy = NULL;
    REQUIRE(same, "restart-durable-generation-unchanged");
  }
}
static void load_table(const char *path, unsigned index) {
  module = dlopen(path, RTLD_NOW | RTLD_LOCAL); if (!module) setup_error("module-load");
  get_list = (CK_C_GetFunctionList)dlsym(module, "C_GetFunctionList");
  get_interface = (CK_C_GetInterface)dlsym(module, "C_GetInterface");
  get_interfaces = (CK_C_GetInterfaceList)dlsym(module, "C_GetInterfaceList");
  ctl = (Control)dlsym(module, "HASKOKI_Control");
  if (!get_list || !get_interface || !get_interfaces || !ctl) setup_error("discovery-symbols");
#define COPY(n) a.n = table->C_##n;
  if (index == 0) {
    CK_FUNCTION_LIST *table = NULL;
    RV(get_list(&table), CKR_OK, "legacy-discovery"); REQUIRE(table != NULL, "legacy-table");
    REQUIRE(table->version.major == 2 && table->version.minor == 40, "legacy-version");
    COMMON(COPY)
  } else {
    CK_VERSION want = {3, (CK_BYTE)(index - 1)}, actual;
    CK_INTERFACE *interface = NULL;
    RV(get_interface(NULL, &want, &interface, 0), CKR_OK, "requested-discovery");
    REQUIRE(interface && interface->pFunctionList, "requested-table");
    memcpy(&actual, interface->pFunctionList, sizeof(actual));
    REQUIRE(actual.major == want.major && actual.minor == want.minor, "requested-version");
    if (index < 3) {
      CK_FUNCTION_LIST_3_0 *table = interface->pFunctionList;
      COMMON(COPY) a.SessionCancel = table->C_SessionCancel;
    } else {
      CK_FUNCTION_LIST_3_2 *table = interface->pFunctionList;
      COMMON(COPY) a.SessionCancel = table->C_SessionCancel;
      a.AsyncComplete = table->C_AsyncComplete; a.AsyncGetID = table->C_AsyncGetID; a.AsyncJoin = table->C_AsyncJoin;
      REQUIRE(a.AsyncComplete && a.AsyncGetID && a.AsyncJoin, "async-tail-members");
    }
  }
#undef COPY
#define NONNULL(n) REQUIRE(a.n != NULL, "member-" #n);
  COMMON(NONNULL)
#undef NONNULL
}
static void cleanup(void) {
  if (live) {
    CK_RV rv = a.Finalize(NULL); live = 0;
    if (rv != CKR_OK) setup_error("cleanup-finalize");
  }
  join_waiters();
  free(durable_copy); durable_copy = NULL;
  if (pages) { if (munmap(pages, page_size)) setup_error("cleanup-unmap"); pages = NULL; }
  /* Do not dlclose a module with Haskell process-lifetime roots. */
}
static int child(const char *path, unsigned v, unsigned l) {
  struct stat st;
  if (lstat(directory, &st) || !S_ISDIR(st.st_mode) || st.st_uid != geteuid() || (st.st_mode & 0777) != 0700)
    setup_error("owned-child-directory");
  /* A process alarm is a crash/timeout, never assertion exit 1. */
  alarm(150); configure(1); load_table(path, v);
  static void (*const tests[])(void) = {leg_entry, leg_initial, leg_presence, leg_coalescing,
    leg_cleanup, leg_waiters, leg_notify, leg_reentry, leg_restart};
  if (!failed) tests[l]();
  cleanup(); alarm(0);
  printf("notifications:%s/result/%s/%s assertions=%u failures=%d\n", leg, version, storage, assertions, failed);
  return failed ? 1 : 0;
}
static void remove_owned(const char *dir) {
  static const char *files[] = {"removable.toml", "fixed.toml", "tokens.db", "tokens.db-wal", "tokens.db-shm", "tokens.db.lock", "tokens.db-journal", "generation-before.db", "generation-after.db"};
  char path[PATH_MAX];
  for (unsigned i = 0; i < N(files); ++i) {
    int n = snprintf(path, sizeof(path), "%s/%s", dir, files[i]);
    if (n < 0 || (size_t)n >= sizeof(path)) setup_error("cleanup-path");
    if (unlink(path) && errno != ENOENT) setup_error("cleanup-owned-file");
  }
  if (rmdir(dir)) setup_error("cleanup-owned-directory");
}
int main(int argc, char **argv) {
  setvbuf(stdout, NULL, _IONBF, 0);
  version = "setup"; storage = "setup"; leg = "fixture";
  if (argc == 10 && !strcmp(argv[2], "--version") && !strcmp(argv[4], "--storage") &&
      !strcmp(argv[6], "--leg") && !strcmp(argv[8], "--directory")) {
    unsigned v, s, l;
    for (v = 0; v < N(versions) && strcmp(versions[v], argv[3]); ++v) {}
    for (s = 0; s < N(stores) && strcmp(stores[s], argv[5]); ++s) {}
    for (l = 0; l < N(legs) && strcmp(legs[l], argv[7]); ++l) {}
    if (v == N(versions) || s == N(stores) || l == N(legs)) return 2;
    version = versions[v]; storage = stores[s]; leg = legs[l]; directory = argv[9];
    return child(argv[1], v, l);
  }
  if (argc != 2) { puts("notifications:setup-error usage"); return 2; }
  if (mkdir("/tmp/haskoki-notifications", 0700) && errno != EEXIST) return 2;
  if (mkdir("/tmp/haskoki-notifications/native", 0700) && errno != EEXIST) return 2;
  char base[] = "/tmp/haskoki-notifications/native/full-XXXXXX";
  if (!mkdtemp(base)) return 2;
  int result = 0;
  for (unsigned v = 0; v < N(versions); ++v) for (unsigned s = 0; s < N(stores); ++s)
    for (unsigned l = 0; l < N(legs); ++l) {
      char dir[PATH_MAX]; int n = snprintf(dir, sizeof(dir), "%s/%u-%u-%u", base, v, s, l);
      if (n < 0 || (size_t)n >= sizeof(dir) || mkdir(dir, 0700)) setup_error("child-directory");
      pid_t pid = fork(); if (pid < 0) setup_error("fork");
      if (!pid) {
        alarm(180);
        execl(argv[0], argv[0], argv[1], "--version", versions[v], "--storage", stores[s],
              "--leg", legs[l], "--directory", dir, (char *)NULL); _exit(2);
      }
      int status;
      while (waitpid(pid, &status, 0) < 0) if (errno != EINTR) setup_error("waitpid");
      int rc = WIFEXITED(status) ? WEXITSTATUS(status) : 2;
      if (rc > 2) rc = 2;
      if (rc > result) result = rc;
      remove_owned(dir);
    }
  if (rmdir(base)) setup_error("parent-directory");
  printf("notifications:matrix legs=72 exit=%d child_leaks=0\n", result);
  return result;
}
