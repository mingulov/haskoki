/* Parity-eligible notifications: only valid empty polls, sequential lifecycle,
 * and live structural checks. No control, malformed wait, reentry, or blocker.
 * Direct covers four real public layouts. The pinned shim has no 3.1 table;
 * its exact discovery miss and direct 3.1 checks are topology-only inventory.
 * Common 2.40/3.0/3.2 polling transcripts remain fully parity-eligible.
 * Use only the independent vendored PKCS #11 header.
 */
#define _GNU_SOURCE
#define CK_PTR *
#define CK_DECLARE_FUNCTION(r, n) r n
#define CK_DECLARE_FUNCTION_POINTER(r, n) r (*n)
#define CK_CALLBACK_FUNCTION(r, n) r (*n)
#include "pkcs11.h"
#include <dlfcn.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

#define SENTINEL 0xa5a5a5a5a5a5a5a5UL
#define COMMON(F) F(Initialize) F(Finalize) F(GetSlotList) F(GetSlotInfo) F(WaitForSlotEvent)
#define FIELD(n) CK_C_##n n;
static struct { COMMON(FIELD) } a;
#undef FIELD
static const char *versions[] = {"2.40", "3.0", "3.1", "3.2"};
static const char *version;
static const char *line_prefix;
static unsigned assertions;
static int failed;
static int check(int ok, const char *name) {
  if (failed) return 0;
  ++assertions;
  printf("%snotifications-poll:%s/%s check=%s\n", line_prefix, name, version, ok ? "pass" : "FAIL");
  if (!ok) failed = 1;
  return ok;
}
static int expect(CK_RV got, CK_RV want, const char *name) {
  if (failed) return 0;
  printf("%snotifications-poll:%s/%s rv=0x%lx expected=0x%lx\n", line_prefix, name, version, got, want);
  return check(got == want, name);
}
#define CHECK(c, n) do { if (!check((c), (n))) return; } while (0)
#define RV(c, w, n) do { if (!expect((c), (w), (n))) return; } while (0)
static void assertions_live(void) {
  CK_SLOT_ID slot = SENTINEL;
  RV(a.WaitForSlotEvent(CKF_DONT_BLOCK, &slot, NULL), CKR_NO_EVENT, "empty-poll");
  CHECK(slot == SENTINEL, "poll-canary");
  RV(a.GetSlotList(CK_FALSE, NULL, NULL), CKR_ARGUMENTS_BAD, "live-null-count");
  CK_ULONG count = 0;
  RV(a.GetSlotList(CK_FALSE, NULL, &count), CKR_OK, "live-size");
  CHECK(count > 0 && count <= 16, "live-catalog-bound");
  CK_SLOT_ID list[16]; memset(list, 0xa5, sizeof(list));
  CK_ULONG cap = 0;
  RV(a.GetSlotList(CK_FALSE, list, &cap), CKR_BUFFER_TOO_SMALL, "live-zero-capacity");
  CHECK(cap == count, "live-required-count");
  for (unsigned i = 0; i < 16; ++i) CHECK(list[i] == SENTINEL, "short-array-canary");
  RV(a.GetSlotList(CK_FALSE, list, &cap), CKR_OK, "live-list");
  CHECK(cap == count, "live-list-count");
  /* Logical name only: the shim is entitled to renumber the slot. */
  printf("%snotifications-poll:discovered logical=slot-A\n", line_prefix);
  RV(a.GetSlotInfo(list[0], NULL), CKR_ARGUMENTS_BAD, "live-null-slot-info");
  slot = SENTINEL;
  RV(a.WaitForSlotEvent(CKF_DONT_BLOCK, &slot, NULL), CKR_NO_EVENT, "queries-no-event");
  CHECK(slot == SENTINEL, "queries-canary");
}
static int run_table(const char *path, unsigned index) {
  version = versions[index];
  line_prefix = index == 2 ? "topology: " : "";
  const char *topology = getenv("HASKOKI_CONSUMER_TOPOLOGY");
  int is_proxy = topology && !strcmp(topology, "proxy");
  void *module = dlopen(path, RTLD_NOW | RTLD_LOCAL);
  if (!module) { puts("notifications-poll:setup module-load"); return 2; }
  CK_C_GetFunctionList get = (CK_C_GetFunctionList)dlsym(module, "C_GetFunctionList");
  CK_C_GetInterface iface = (CK_C_GetInterface)dlsym(module, "C_GetInterface");
  if (!get || !iface) { puts("notifications-poll:setup discovery"); return 2; }
#define COPY(n) a.n = t->C_##n;
  if (!index) {
    CK_FUNCTION_LIST *t = NULL;
    if (!expect(get(&t), CKR_OK, "discovery") || !check(t != NULL, "table")) return 1;
    if (!check(t->version.major == 2 && t->version.minor == 40, "layout-version")) return 1;
    COMMON(COPY)
  } else {
    CK_VERSION want = {3, (CK_BYTE)(index - 1)}; CK_INTERFACE *i = NULL;
    if (!expect(iface(NULL, &want, &i, 0), CKR_OK, "discovery")) return 1;
    if (index == 2 && is_proxy) {
      /* Merged catalog: the backend-published 3.1 is present and
       * takes the same polling pass as 3.0 (same table layout). */
      if (!check(i != NULL, "proxied-3.1-present")) return 1;
    }
    if (!check(i && i->pFunctionList, "table")) return 1;
    CK_VERSION actual; memcpy(&actual, i->pFunctionList, sizeof(actual));
    if (!check(actual.major == want.major && actual.minor == want.minor, "layout-version")) return 1;
    if (index == 3) { CK_FUNCTION_LIST_3_2 *t = i->pFunctionList; COMMON(COPY) }
    else { CK_FUNCTION_LIST_3_0 *t = i->pFunctionList; COMMON(COPY) }
  }
#undef COPY
  CK_SLOT_ID slot = SENTINEL;
  if (!expect(a.WaitForSlotEvent(CKF_DONT_BLOCK, &slot, NULL), CKR_CRYPTOKI_NOT_INITIALIZED,
              "before-init") || !check(slot == SENTINEL, "before-canary")) return 1;
  if (!expect(a.Initialize(NULL), CKR_OK, "initialize")) return 1;
  assertions_live();
  CK_RV closed = a.Finalize(NULL);
  if (!failed) expect(closed, CKR_OK, "finalize");
  if (!failed) {
    slot = SENTINEL;
    expect(a.WaitForSlotEvent(CKF_DONT_BLOCK, &slot, NULL), CKR_CRYPTOKI_NOT_INITIALIZED, "after-finalize");
    check(slot == SENTINEL, "after-canary");
  }
  printf("%snotifications-poll:result/%s assertions=%u failures=%d\n", line_prefix, version, assertions, failed);
  return failed ? 1 : 0;
}
int main(int argc, char **argv) {
  setvbuf(stdout, NULL, _IONBF, 0);
  if (argc == 4 && !strcmp(argv[2], "--version")) {
    for (unsigned i = 0; i < 4; ++i) if (!strcmp(argv[3], versions[i])) return run_table(argv[1], i);
    return 2;
  }
  if (argc != 2) return 2;
  int result = 0;
  for (unsigned i = 0; i < 4; ++i) {
    pid_t pid = fork();
    if (pid < 0) return 2;
    if (!pid) { alarm(60); execl(argv[0], argv[0], argv[1], "--version", versions[i], (char *)NULL); _exit(2); }
    int status;
    while (waitpid(pid, &status, 0) < 0) { if (errno != EINTR) return 2; }
    int rc = WIFEXITED(status) ? WEXITSTATUS(status) : 2;
    if (rc > 2) rc = 2;
    if (rc > result) result = rc;
  }
  return result;
}
