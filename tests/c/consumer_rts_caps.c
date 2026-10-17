/* tests/c/consumer_rts_caps.c — capability-count consumer.
 *
 * The provider pins one RTS capability and ignores GHCRTS: a second
 * capability lets two host threads first-evaluate the same constant
 * table and orphan a string-literal black hole (GHC #27272), hanging
 * the whole host process, and an unsafe GHCRTS option used to abort
 * the host inside startup.
 *
 * Two legs, each in a fresh child process (the RTS starts once per
 * process, and GHCRTS is read at startup):
 *   so-n4   load the built module with GHCRTS=-N4: C_Initialize must
 *           succeed and the live capability count must read 1.
 *   so-a8m  load it with an unsafe GHCRTS=-A8m: the host must survive
 *           startup and the count must read 1 all the same.
 *
 * The count is read through the RTS's own n_capabilities global via
 * dlsym over the loaded module (RTLD_GLOBAL): no provider surface
 * takes part, so the shipped module carries no test symbol for this.
 * The source-level legs (rts_bootstrap.c compiled with its test-only
 * accessor) live in tests/c/rts_caps_probe.c, run by the same script.
 *
 * Usage: consumer_rts_caps <module.so>             (parent: runs both legs)
 *        consumer_rts_caps <module.so> child <leg> (one leg; run by the parent)
 */
#define _GNU_SOURCE

#include "pkcs11.h"

#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
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

/* Hermetic config (consumer_discovery.c precedent): real-crypto
 * engine, trace off (no stray files), memory storage. The parent
 * writes it once; children inherit HASKOKI_CONFIG across exec. */
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
  const char *tmpd = getenv("TMPDIR");
  char tmpl[256];
  int fd;
  size_t want;
  if (tmpd == NULL || tmpd[0] == '\0') {
    tmpd = "/tmp";
  }
  snprintf(tmpl, sizeof(tmpl), "%s/haskoki-rts-caps-XXXXXX", tmpd);
  fd = mkstemp(tmpl);
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
  if (setenv("HASKOKI_CONFIG", tmpl, 1) != 0) {
    perror("setenv");
    exit(2);
  }
}

/* One leg: load the module, initialize, read the live capability
 * count through the RTS global, finalize. Runs under the GHCRTS the
 * parent installed; a 30s self-alarm bounds a wedged child. */
static int run_leg(const char *mod, const char *leg) {
  void *handle;
  CK_C_GetFunctionList pGetList;
  CK_FUNCTION_LIST_PTR tbl = NULL_PTR;
  const uint32_t *caps;
  CK_RV rv;

  alarm(30);
  printf("leg %s: GHCRTS=%s\n", leg, getenv("GHCRTS") ? getenv("GHCRTS") : "(unset)");
  /* RTLD_GLOBAL: the RTS global resolves through RTLD_DEFAULT only
   * when the loaded module's dependencies join the global scope. */
  handle = dlopen(mod, RTLD_NOW | RTLD_GLOBAL);
  CHECK(handle != NULL, "leg %s: dlopen ok", leg);
  if (handle == NULL) {
    printf("dlopen failed: %s\n", dlerror());
    return 1;
  }
  pGetList = (CK_C_GetFunctionList)dlsym(handle, "C_GetFunctionList");
  CHECK(pGetList != NULL, "leg %s: C_GetFunctionList resolves", leg);
  if (pGetList == NULL) {
    return 1;
  }
  rv = pGetList(&tbl);
  CHECK(rv == CKR_OK && tbl != NULL_PTR, "leg %s: function list ok", leg);
  if (rv != CKR_OK || tbl == NULL_PTR) {
    return 1;
  }
  /* Survival point: with an unsafe GHCRTS the old startup aborted
   * the host here, before any check could run. */
  rv = tbl->C_Initialize(NULL_PTR);
  CHECK(rv == CKR_OK, "leg %s: C_Initialize ok (rv=%lu)", leg, (unsigned long)rv);
  if (rv != CKR_OK) {
    return 1;
  }
  caps = (const uint32_t *)dlsym(RTLD_DEFAULT, "n_capabilities");
  CHECK(caps != NULL, "leg %s: capability count resolves", leg);
  if (caps == NULL) {
    printf("dlsym failed: %s\n", dlerror());
    return 1;
  }
  printf("leg %s: capability count = %u\n", leg, *caps);
  CHECK(*caps == 1, "leg %s: exactly one capability", leg);
  rv = tbl->C_Finalize(NULL_PTR);
  CHECK(rv == CKR_OK, "leg %s: C_Finalize ok (rv=%lu)", leg, (unsigned long)rv);
  return g_failures == 0 ? 0 : 1;
}

static int run_parent(const char *self, const char *mod) {
  static const char *const leg_names[] = { "so-n4", "so-a8m" };
  static const char *const leg_env[] = { "-N4", "-A8m" };
  size_t i;
  int failed = 0;

  write_config();
  for (i = 0; i < sizeof(leg_names) / sizeof(leg_names[0]); i++) {
    const char *leg = leg_names[i];
    pid_t pid;
    int st;
    pid = fork();
    if (pid < 0) {
      perror("fork");
      return 1;
    }
    if (pid == 0) {
      char *const args[] = { (char *)self, (char *)mod, (char *)"child",
                             (char *)leg, NULL };
      if (setenv("GHCRTS", leg_env[i], 1) != 0) {
        perror("setenv");
        _exit(2);
      }
      execv(self, args);
      perror("execv");
      _exit(2);
    }
    while (waitpid(pid, &st, 0) < 0) {
    }
    if (WIFEXITED(st) && WEXITSTATUS(st) == 0) {
      printf("leg %s: PASS\n", leg);
    } else if (WIFEXITED(st)) {
      printf("leg %s: FAIL (exit %d)\n", leg, WEXITSTATUS(st));
      failed = 1;
    } else if (WIFSIGNALED(st)) {
      printf("leg %s: FAIL (signal %d)\n", leg, WTERMSIG(st));
      failed = 1;
    } else {
      printf("leg %s: FAIL (unknown wait status)\n", leg);
      failed = 1;
    }
  }
  if (failed) {
    printf("FAIL: capability-count consumer\n");
    return 1;
  }
  printf("PASS: capability-count consumer (both legs)\n");
  return 0;
}

int main(int argc, char **argv) {
  if (argc == 4 && strcmp(argv[2], "child") == 0) {
    return run_leg(argv[1], argv[3]);
  }
  if (argc != 2) {
    fprintf(stderr, "usage: %s <libhaskoki.so>\n", argv[0]);
    return 2;
  }
  return run_parent(argv[0], argv[1]);
}
