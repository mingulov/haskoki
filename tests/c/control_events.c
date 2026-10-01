/* tests/c/control_events.c — native control/slot-event proof.
 *
 * A native thread blocks in C_WaitForSlotEvent on the loaded module;
 * the SAME instance's HASKOKI_Control entry point inserts a token;
 * the waiter WAKES with the slot event. Then the control budget rule
 * (§5.1) is exercised: pure budget query, too-small executes nothing,
 * unknown command without mutation, and DON'T_BLOCK no-event mode.
 *
 * HASKOKI_Control is resolved by dlsym as a global extension symbol
 * through a locally declared prototype (independent oracle: this TU
 * deliberately does NOT include cbits/haskoki_control.h); it is NOT
 * a member of any standard function table. The standard surface is
 * reached through the pinned 2.40 headers + C_GetFunctionList only.
 *
 * Compile with -Ispec/vendor. Part of
 * scripts/test-control-events.sh.
 * Usage: control_events <path-to-libhaskoki.so>
 */
#define _GNU_SOURCE

#define CK_PTR *
#define CK_DECLARE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType(*name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType(*name)
/* NULL_PTR comes from the vendored PD header (always defined). */
#include "pkcs11.h"

#include <dlfcn.h>
#include <pthread.h>
#include <stdint.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* Extension entry: local prototype (must match cbits/haskoki_control.h). */
typedef CK_RV (*HASKOKI_Control_fn)(const CK_BYTE_PTR pRequest,
                                    CK_ULONG ulRequestLen,
                                    CK_BYTE_PTR pResponse,
                                    CK_ULONG_PTR pulResponseLen);

#define CONTROL_BUDGET 65536UL

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

typedef struct waiter_arg {
  CK_C_WaitForSlotEvent fn;
  CK_RV rv;
  CK_SLOT_ID slot;
  atomic_int done;
  int started;
  pthread_mutex_t mutex;
  pthread_cond_t ready;
} waiter_arg;

static void *waiter_thread(void *arg) {
  waiter_arg *wa = (waiter_arg *)arg;
  pthread_mutex_lock(&wa->mutex);
  wa->started = 1;
  pthread_cond_signal(&wa->ready);
  pthread_mutex_unlock(&wa->mutex);
  wa->slot = 0xa5a5a5a5a5a5a5a5UL;
  wa->rv = wa->fn(0 /* blocking */, &wa->slot, NULL_PTR);
  atomic_store(&wa->done, 1);
  return 0;
}

static void write_test_config(char *path_out, size_t path_cap) {
  static const char body[] = "schema_version = 1\n"
                             "profile = \"demo-maximal\"\n"
                             "[control]\n"
                             "enabled = true\n"
                             "test_enabled = true\n";
  char tmpl[] = "/tmp/haskoki-proof-XXXXXX";
  int fd = mkstemp(tmpl);
  ssize_t want;
  if (fd < 0) {
    perror("mkstemp");
    exit(2);
  }
  want = (ssize_t)(sizeof(body) - 1);
  if (write(fd, body, (size_t)want) != want) {
    perror("write");
    exit(2);
  }
  close(fd);
  snprintf(path_out, path_cap, "%s", tmpl);
}

static CK_RV control_call(HASKOKI_Control_fn ctl, const char *req_json,
                          CK_BYTE_PTR resp, CK_ULONG cap, CK_ULONG *out_len) {
  CK_ULONG len = cap;
  CK_RV rv = ctl((const CK_BYTE_PTR)req_json, (CK_ULONG)strlen(req_json),
                 resp, &len);
  *out_len = len;
  return rv;
}

int main(int argc, char **argv) {
  void *handle;
  CK_C_GetFunctionList pGetList;
  CK_FUNCTION_LIST_PTR fns = 0;
  HASKOKI_Control_fn pControl;
  CK_RV rv;
  char cfg_path[256];
  static CK_BYTE resp[CONTROL_BUDGET];
  CK_ULONG out_len = 0;
  waiter_arg wa;
  pthread_t th;

  if (argc != 2) {
    fprintf(stderr, "usage: %s <libhaskoki.so>\n", argv[0]);
    return 2;
  }

  /* A test-enabled instance: the proof config is resolved once at init. */
  write_test_config(cfg_path, sizeof(cfg_path));
  setenv("HASKOKI_CONFIG", cfg_path, 1);

  handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
  CHECK(handle != 0, "dlopen module");
  if (!handle) {
    fprintf(stderr, "dlerror: %s\n", dlerror());
    return 1;
  }
  pGetList = (CK_C_GetFunctionList)dlsym(handle, "C_GetFunctionList");
  CHECK(pGetList != 0, "dlsym C_GetFunctionList");
  pControl = (HASKOKI_Control_fn)dlsym(handle, "HASKOKI_Control");
  CHECK(pControl != 0, "dlsym HASKOKI_Control (extension, not in tables)");
  if (!pGetList || !pControl) {
    return 1;
  }

  rv = pGetList(&fns);
  CHECK(rv == CKR_OK && fns != 0, "C_GetFunctionList ok");
  rv = fns->C_Initialize(NULL_PTR);
  CHECK(rv == CKR_OK, "C_Initialize ok (rv=%lu)", rv);

  /* Discovery supplies the comparison identity. Startup is already present;
   * remove A and consume that indication before testing blocking reinsertion. */
  CK_SLOT_ID slots[16]; CK_ULONG slot_count = 16;
  rv = fns->C_GetSlotList(CK_TRUE, slots, &slot_count);
  CHECK(rv == CKR_OK && slot_count > 0, "discover logical slot-A");
  if (rv != CKR_OK || !slot_count) { fns->C_Finalize(NULL_PTR); return 1; }
  CK_SLOT_ID slot_a = slots[0];
  char mutation[256];
  snprintf(mutation, sizeof(mutation),
           "{\"schema_version\":1,\"command\":\"token.remove\",\"arguments\":{\"slot\":%lu}}", slot_a);
  rv = control_call(pControl, mutation, resp, CONTROL_BUDGET, &out_len);
  CHECK(rv == CKR_OK, "remove initially present slot-A (rv=%lu)", rv);
  CK_SLOT_ID indication = 0xa5a5a5a5a5a5a5a5UL;
  rv = fns->C_WaitForSlotEvent(CKF_DONT_BLOCK, &indication, NULL_PTR);
  CHECK(rv == CKR_OK && indication == slot_a, "initial removal event is slot-A");
  CK_SLOT_INFO slot_info;
  rv = fns->C_GetSlotInfo(slot_a, &slot_info);
  CHECK(rv == CKR_OK && slot_info.flags == CKF_REMOVABLE_DEVICE,
        "removal query agrees with event");
  CK_ULONG present = 0;
  rv = fns->C_GetSlotList(CK_TRUE, NULL_PTR, &present);
  CHECK(rv == CKR_OK && present + 1 == slot_count, "removed slot absent from filtered list");
  if (g_failures) { fns->C_Finalize(NULL_PTR); return 1; }

  memset(&wa, 0, sizeof(wa));
  atomic_init(&wa.done, 0);
  if (pthread_mutex_init(&wa.mutex, NULL) || pthread_cond_init(&wa.ready, NULL)) return 2;
  wa.fn = fns->C_WaitForSlotEvent;
  CHECK(wa.fn != 0, "table carries C_WaitForSlotEvent");
  if (pthread_create(&th, 0, waiter_thread, &wa) != 0) return 2;
  struct timespec until;
  clock_gettime(CLOCK_REALTIME, &until); until.tv_sec += 10;
  pthread_mutex_lock(&wa.mutex);
  while (!wa.started) {
    if (pthread_cond_timedwait(&wa.ready, &wa.mutex, &until)) {
      pthread_mutex_unlock(&wa.mutex); fns->C_Finalize(NULL_PTR); return 2;
    }
  }
  pthread_mutex_unlock(&wa.mutex);
  /* This acknowledges native entry preparation, not Haskell STM admission.
   * The real transition below remains pending until one waiter consumes it. */
  snprintf(mutation, sizeof(mutation),
           "{\"schema_version\":1,\"command\":\"token.insert\",\"arguments\":{\"slot\":%lu}}", slot_a);
  rv = control_call(pControl, mutation, resp, CONTROL_BUDGET, &out_len);
  CHECK(rv == CKR_OK, "control token.insert ok (rv=%lu)", rv);
  clock_gettime(CLOCK_REALTIME, &until); until.tv_sec += 10;
  if (pthread_timedjoin_np(th, NULL, &until)) { fns->C_Finalize(NULL_PTR); return 2; }
  CHECK(atomic_load(&wa.done) == 1, "waiter returned");
  CHECK(wa.rv == CKR_OK, "waiter woke with CKR_OK (rv=%lu)", wa.rv);
  CHECK(wa.slot == slot_a, "waiter reports discovered slot-A");
  rv = fns->C_GetSlotInfo(slot_a, &slot_info);
  CHECK(rv == CKR_OK && slot_info.flags == (CKF_REMOVABLE_DEVICE | CKF_TOKEN_PRESENT),
        "insertion query agrees with event");
  rv = fns->C_GetSlotList(CK_TRUE, NULL_PTR, &present);
  CHECK(rv == CKR_OK && present == slot_count, "inserted slot restored to filtered list");
  pthread_cond_destroy(&wa.ready); pthread_mutex_destroy(&wa.mutex);

  /* DON'T_BLOCK with an empty queue: immediate NO_EVENT. */
  {
    CK_SLOT_ID s = 0xDEADu;
    rv = fns->C_WaitForSlotEvent(CKF_DONT_BLOCK, &s, NULL_PTR);
    CHECK(rv == CKR_NO_EVENT, "dont-block empty -> NO_EVENT (rv=%lu)", rv);
  }

  /* Budget query: null response pointer, pure, required == budget. */
  {
    CK_ULONG need = 0;
    const char *q =
        "{\"schema_version\":1,\"command\":\"status\",\"arguments\":{}}";
    rv = pControl((const CK_BYTE_PTR)q, (CK_ULONG)strlen(q), 0, &need);
    CHECK(rv == CKR_OK, "budget query ok (rv=%lu)", rv);
    CHECK(need == CONTROL_BUDGET, "budget query needs 65536 (need=%lu)",
          need);
  }

  /* Too-small capacity: BUFFER_TOO_SMALL + required + NO mutation.
   * No-mutation is proven by status-body equality across the call. */
  {
    static CK_BYTE before[CONTROL_BUDGET];
    static CK_BYTE after[CONTROL_BUDGET];
    CK_ULONG blen = 0, alen = 0;
    const char *q =
        "{\"schema_version\":1,\"command\":\"status\",\"arguments\":{}}";
    const char *mut = "{\"schema_version\":1,\"command\":\"token.insert\","
                      "\"arguments\":{\"slot\":3}}";
    rv = control_call(pControl, q, before, CONTROL_BUDGET, &blen);
    CHECK(rv == CKR_OK, "status before ok");
    {
      CK_BYTE tiny[100];
      CK_ULONG tcap = sizeof(tiny);
      rv = pControl((const CK_BYTE_PTR)mut, (CK_ULONG)strlen(mut), tiny,
                    &tcap);
      CHECK(rv == CKR_BUFFER_TOO_SMALL, "short capacity refused (rv=%lu)",
            rv);
      CHECK(tcap == CONTROL_BUDGET, "short capacity needs 65536 (%lu)",
            tcap);
    }
    rv = control_call(pControl, q, after, CONTROL_BUDGET, &alen);
    CHECK(rv == CKR_OK, "status after ok");
    CHECK(blen == alen && memcmp(before, after, blen) == 0,
          "short call executed nothing (status identical)");
  }

  /* Unknown command: argument error, no mutation. */
  {
    const char *bad =
        "{\"schema_version\":1,\"command\":\"nope\",\"arguments\":{}}";
    rv = control_call(pControl, bad, resp, CONTROL_BUDGET, &out_len);
    CHECK(rv == CKR_ARGUMENTS_BAD, "unknown command refused (rv=%lu)", rv);
  }

  rv = fns->C_Finalize(NULL_PTR);
  CHECK(rv == CKR_OK, "C_Finalize ok (rv=%lu)", rv);

  unlink(cfg_path);
  dlclose(handle);

  if (g_failures == 0) {
    printf("PASS: control_events (%s)\n", argv[1]);
    return 0;
  }
  printf("FAIL: control_events (%d failures)\n", g_failures);
  return 1;
}
