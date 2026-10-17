/* tests/c/consumer_rts_midfork.c — deterministic mid-init fork probe.
 *
 * The unlocked native exports reach haskoki_rts_ensure without any
 * lock. The thread that wins the boot-PID swap starts the RTS with
 * hs_init_ghc while losers in the boot process wait for that start
 * to finish; a process forked mid-init must refuse instead of
 * waiting on a winner thread that does not exist in the child.
 *
 * Deterministic interposition: this executable exports its own
 * hs_init_ghc (linked -rdynamic; scripts/test-consumers.sh builds
 * this probe the way it builds rts_caps_probe, with the RTS
 * include dir). The dlopen'd module's undefined hs_init_ghc binds
 * to it, so the winner thread parks inside "init" until the probe
 * releases it. While parked, the probe forks the mid-init child
 * and checks it refuses every surface promptly:
 * haskoki_c_entry_ok 0, haskoki_rts_ensure -1,
 * haskoki_async_open NULL, C_Initialize CKR_GENERAL_ERROR.
 * A loser thread started while parked must still be waiting (it
 * must not enter Haskell early); after release both contexts must
 * be live, and a post-init fork child must refuse the same way.
 *
 * Every wait is bounded: a 60s self-alarm covers the whole parent
 * run (the joins, the reaps, and the release spin), each forked
 * child carries a 10s one, and the winner-parked poll gives up
 * after 5000 tries.
 *
 * Usage: consumer_rts_midfork <module.so>
 */
#define _GNU_SOURCE

#include "pkcs11.h"

#include <Rts.h>

#include <dlfcn.h>
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

/* Local opaque handles (consumer-independence: no provider headers
 * beyond dlsym names; cf. tests/c/async_attached.c). Rts.h is the
 * toolchain header for the interposed init signature; pkcs11.h is
 * the pinned interface family. */
typedef void *(*open_fn)(void);
typedef void (*close_fn)(void **);
typedef int (*int_fn)(void);
typedef void (*init_fn)(int *, char ***, RtsConfig);

static void *g_h;
static open_fn g_open;
static close_fn g_close;
static int_fn g_entry_ok;
static int_fn g_ensure;
static CK_C_GetFunctionList g_get_list;
static atomic_int g_in_init;
static atomic_int g_release;
static atomic_int g_loser_done;
static atomic_int g_interposed;

/* Hermetic config (consumer_rts_caps.c precedent): real-crypto
 * engine, trace off (no stray files), memory storage. Written once
 * here; unlinked before return. */
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
  const char *tmpd = getenv("TMPDIR");
  char tmpl[256];
  int fd;
  size_t want;
  if (tmpd == NULL || tmpd[0] == '\0') {
    tmpd = "/tmp";
  }
  snprintf(tmpl, sizeof(tmpl), "%s/haskoki-rts-midfork-XXXXXX", tmpd);
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
  snprintf(g_cfg_path, sizeof(g_cfg_path), "%s", tmpl);
  if (setenv("HASKOKI_CONFIG", g_cfg_path, 1) != 0) {
    perror("setenv");
    exit(2);
  }
}

/* Interposed hs_init_ghc: park the winning thread inside "init"
 * until the probe releases it, then run the module's own init.
 * Exported via -rdynamic so the dlopen'd module binds here. */
void hs_init_ghc(int *argc, char **argv[], RtsConfig conf) {
  init_fn real = (init_fn)dlsym(g_h, "hs_init_ghc");
  atomic_store(&g_interposed, 1);
  atomic_store(&g_in_init, 1);
  while (!atomic_load(&g_release)) {
    usleep(1000);
  }
  real(argc, argv, conf);
}

static void *r_winner;
static void *r_loser;

static void *winner(void *arg) {
  (void)arg;
  r_winner = g_open();
  return NULL;
}

static void *loser(void *arg) {
  (void)arg;
  r_loser = g_open();
  atomic_store(&g_loser_done, 1);
  return NULL;
}

/* One fork child (mid- or post-init): refuse every surface. Runs
 * under a 10s self-alarm; silent except for the refusal lines. */
static int child_checks(const char *tag) {
  void *r;
  int e;
  int ok = 1;
  CK_FUNCTION_LIST_PTR fl = NULL_PTR;
  CK_RV rv;
  alarm(10);
  e = g_entry_ok();
  printf("%s child: entry_ok=%d\n", tag, e);
  if (e != 0) {
    ok = 0;
  }
  e = g_ensure();
  printf("%s child: rts_ensure=%d\n", tag, e);
  if (e != -1) {
    ok = 0;
  }
  r = g_open();
  printf("%s child: async_open=%p\n", tag, r);
  if (r != NULL) {
    ok = 0;
  }
  if (g_get_list(&fl) != CKR_OK || fl == NULL_PTR) {
    printf("%s child: function list unavailable\n", tag);
    ok = 0;
  } else {
    rv = fl->C_Initialize(NULL_PTR);
    printf("%s child: C_Initialize=0x%lx\n", tag, (unsigned long)rv);
    if (rv != CKR_GENERAL_ERROR) {
      ok = 0;
    }
  }
  fflush(stdout);
  return ok ? 0 : 1;
}

static int fork_and_check(const char *tag) {
  int st;
  int w;
  pid_t p;
  fflush(stdout);
  p = fork();
  if (p < 0) {
    printf("%s child: FAIL: fork failed\n", tag);
    return 1;
  }
  if (p == 0) {
    _exit(child_checks(tag));
  }
  w = waitpid(p, &st, 0);
  while (w < 0 && errno == EINTR) {
    w = waitpid(p, &st, 0);
  }
  if (w < 0) {
    printf("%s child: FAIL: waitpid failed\n", tag);
    return 1;
  }
  if (WIFEXITED(st)) {
    printf("%s child exit %d\n", tag, WEXITSTATUS(st));
    return WEXITSTATUS(st);
  }
  printf("%s child SIGNAL %d (blocked/crashed)\n", tag, WTERMSIG(st));
  return 1;
}

int main(int argc, char **argv) {
  pthread_t w;
  pthread_t l;
  int i;
  int fails = 0;
  int parent_ok;

  if (argc != 2) {
    fprintf(stderr, "usage: %s <libhaskoki.so>\n", argv[0]);
    return 2;
  }
  alarm(60);
  write_config();
  g_h = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
  if (g_h == NULL) {
    printf("dlopen failed: %s\n", dlerror());
    unlink(g_cfg_path);
    return 2;
  }
  g_open = (open_fn)dlsym(g_h, "haskoki_async_open");
  g_close = (close_fn)dlsym(g_h, "haskoki_async_close");
  g_entry_ok = (int_fn)dlsym(g_h, "haskoki_c_entry_ok");
  g_ensure = (int_fn)dlsym(g_h, "haskoki_rts_ensure");
  g_get_list = (CK_C_GetFunctionList)dlsym(g_h, "C_GetFunctionList");
  if (g_open == NULL || g_close == NULL || g_entry_ok == NULL ||
      g_ensure == NULL || g_get_list == NULL) {
    printf("dlsym failed: %s\n", dlerror());
    unlink(g_cfg_path);
    return 2;
  }
  printf("pre-claim entry_ok=%d\n", g_entry_ok());
  if (pthread_create(&w, NULL, winner, NULL) != 0) {
    printf("FAIL: winner thread did not start\n");
    unlink(g_cfg_path);
    return 2;
  }
  for (i = 0; i < 5000 && !atomic_load(&g_in_init); i++) {
    usleep(1000);
  }
  if (!atomic_load(&g_interposed)) {
    printf("FAIL: interposition did not take\n");
    atomic_store(&g_release, 1);
    pthread_join(w, NULL);
    unlink(g_cfg_path);
    return 3;
  }
  printf("winner parked inside hs_init_ghc\n");
  parent_ok = g_entry_ok();
  printf("mid-init parent entry_ok=%d\n", parent_ok);
  if (parent_ok != 1) {
    printf("FAIL: parent entry_ok mid-init must stay 1\n");
    fails++;
  }
  if (pthread_create(&l, NULL, loser, NULL) != 0) {
    printf("FAIL: loser thread did not start\n");
    atomic_store(&g_release, 1);
    pthread_join(w, NULL);
    unlink(g_cfg_path);
    return 2;
  }
  usleep(200000);
  printf("loser returned before init finished? %s\n",
         atomic_load(&g_loser_done) ? "YES (BAD)" : "no (waiting)");
  if (atomic_load(&g_loser_done)) {
    fails++;
  }
  fails += fork_and_check("mid-init");
  atomic_store(&g_release, 1);
  pthread_join(w, NULL);
  pthread_join(l, NULL);
  printf("winner=%p loser=%p\n", r_winner, r_loser);
  if (r_winner == NULL || r_loser == NULL) {
    fails++;
  }
  fails += fork_and_check("post-init");
  if (r_winner != NULL) {
    g_close(&r_winner);
  }
  if (r_loser != NULL) {
    g_close(&r_loser);
  }
  unlink(g_cfg_path);
  printf("%s (fails=%d)\n", fails ? "FAIL" : "PASS", fails);
  return fails ? 1 : 0;
}
