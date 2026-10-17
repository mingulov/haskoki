/* tests/c/consumer_rts_race.c — concurrent first-call RTS-start race.
 *
 * The unlocked native exports (haskoki_async_*, haskoki_crypto_* in
 * cbits/exports.c) reach haskoki_rts_ensure without any lock. When N
 * host threads make their FIRST provider call at the same time, the
 * compare-and-swap winner starts the RTS with hs_init_ghc while the
 * losers must wait for that start to finish before they enter
 * Haskell; entering early kills the process with "newBoundTask: RTS
 * is not initialised".
 *
 * Each child process loads the built module fresh (the RTS starts
 * once per process), resolves haskoki_async_open/close, and releases
 * 8 threads from a pthread barrier onto their first call. All 8 must
 * return the normal result (a non-NULL context, closable through the
 * handle slot). After the opens succeed and close, each child forks
 * once more: the post-init fork child must refuse the native
 * surface (haskoki_rts_ensure answers -1, haskoki_async_open
 * answers NULL) instead of entering inherited Haskell state; the
 * child's exit status is that leg's verdict. The parent runs 20
 * such fresh processes and requires every one to succeed.
 *
 * Usage: consumer_rts_race <module.so>               (parent: runs 20 children)
 *        consumer_rts_race <module.so> child <i>      (one child; run by the parent)
 */
#define _GNU_SOURCE

#include <dlfcn.h>
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

/* Local opaque handles (consumer-independence: no provider headers
 * beyond dlsym names; cf. tests/c/async_attached.c). */
typedef void *haskoki_async_ctx_t;
typedef haskoki_async_ctx_t (*fn_open)(void);
typedef void (*fn_close)(haskoki_async_ctx_t *pctx);
typedef int (*fn_ensure)(void);

#define NTHREADS 8
#define NPROCS 20

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

/* Hermetic config (consumer_rts_caps.c precedent): real-crypto
 * engine, trace off (no stray files), memory storage. The parent
 * writes it once; children inherit HASKOKI_CONFIG across exec. The
 * parent unlinks it after the last child is reaped. */
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
  snprintf(tmpl, sizeof(tmpl), "%s/haskoki-rts-race-XXXXXX", tmpd);
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

static fn_open g_open;
static fn_close g_close;
static fn_ensure g_ensure;
static pthread_barrier_t g_bar;
static haskoki_async_ctx_t g_results[NTHREADS];

static void *worker(void *arg) {
  long i = (long)arg;
  int brc = pthread_barrier_wait(&g_bar);
  (void)brc;
  g_results[i] = g_open();
  return NULL;
}

/* One child: load the module, then make the first provider call from
 * 8 barrier-released threads at once. Nothing here may enter the
 * provider before the barrier (dlopen/dlsym stay outside Haskell).
 * A 60s self-alarm bounds a wedged child; the post-init fork child
 * below carries its own 10s alarm. */
static int run_child(const char *mod, const char *tag) {
  void *handle;
  pthread_t threads[NTHREADS];
  long i;
  int nulls = 0;
  pid_t fork_pid;
  int fork_st;
  int fork_w;

  alarm(60);
  handle = dlopen(mod, RTLD_NOW | RTLD_LOCAL);
  CHECK(handle != NULL, "child %s: dlopen ok", tag);
  if (handle == NULL) {
    printf("dlopen failed: %s\n", dlerror());
    return 1;
  }
  g_open = (fn_open)dlsym(handle, "haskoki_async_open");
  g_close = (fn_close)dlsym(handle, "haskoki_async_close");
  g_ensure = (fn_ensure)dlsym(handle, "haskoki_rts_ensure");
  CHECK(g_open != NULL && g_close != NULL && g_ensure != NULL,
        "child %s: trampolines resolve", tag);
  if (g_open == NULL || g_close == NULL || g_ensure == NULL) {
    printf("dlsym failed: %s\n", dlerror());
    return 1;
  }
  for (i = 0; i < NTHREADS; i++) {
    g_results[i] = NULL;
  }
  if (pthread_barrier_init(&g_bar, NULL, NTHREADS) != 0) {
    printf("child %s: FAIL: barrier init failed\n", tag);
    return 1;
  }
  for (i = 0; i < NTHREADS; i++) {
    if (pthread_create(&threads[i], NULL, worker, (void *)i) != 0) {
      printf("child %s: FAIL: thread %ld did not start\n", tag, i);
      return 1;
    }
  }
  for (i = 0; i < NTHREADS; i++) {
    pthread_join(threads[i], NULL);
  }
  pthread_barrier_destroy(&g_bar);
  for (i = 0; i < NTHREADS; i++) {
    if (g_results[i] == NULL) {
      nulls++;
    }
  }
  printf("child %s: nulls=%d\n", tag, nulls);
  CHECK(nulls == 0, "child %s: every first call returns a context", tag);
  if (nulls != 0) {
    return 1;
  }
  for (i = 0; i < NTHREADS; i++) {
    g_close(&g_results[i]);
    if (g_results[i] != NULL) {
      printf("child %s: FAIL: close did not null slot %ld\n", tag, i);
      return 1;
    }
  }
  /* Post-init fork leg: a child forked after the start completed
   * must refuse the native surface instead of entering inherited
   * Haskell state (ensure answers -1, open answers NULL). The
   * forked child is silent; its exit status is the verdict. */
  fflush(stdout);
  fork_pid = fork();
  if (fork_pid < 0) {
    printf("child %s: FAIL: post-init fork failed\n", tag);
    return 1;
  }
  if (fork_pid == 0) {
    int e;
    void *r;
    alarm(10);
    e = g_ensure();
    r = g_open();
    _exit(e == -1 && r == NULL ? 0 : 1);
  }
  fork_w = waitpid(fork_pid, &fork_st, 0);
  while (fork_w < 0 && errno == EINTR) {
    fork_w = waitpid(fork_pid, &fork_st, 0);
  }
  if (fork_w < 0) {
    printf("child %s: FAIL: post-init waitpid failed\n", tag);
    return 1;
  }
  if (WIFEXITED(fork_st) && WEXITSTATUS(fork_st) == 0) {
    printf("ok: child %s: post-init fork refuses the native surface\n", tag);
  } else if (WIFSIGNALED(fork_st)) {
    printf("child %s: FAIL: post-init fork child took signal %d\n", tag,
           WTERMSIG(fork_st));
    return 1;
  } else {
    printf("child %s: FAIL: post-init fork child entered Haskell state\n",
           tag);
    return 1;
  }
  printf("child %s: PASS\n", tag);
  return g_failures == 0 ? 0 : 1;
}

static int run_parent(const char *self, const char *mod) {
  int i;
  int failed = 0;

  write_config();
  for (i = 0; i < NPROCS; i++) {
    char tag[32];
    pid_t pid;
    int st;
    int w;
    snprintf(tag, sizeof(tag), "%d", i);
    pid = fork();
    if (pid < 0) {
      perror("fork");
      unlink(g_cfg_path);
      return 1;
    }
    if (pid == 0) {
      char *const args[] = { (char *)self, (char *)mod, (char *)"child",
                             (char *)tag, NULL };
      execv(self, args);
      perror("execv");
      _exit(2);
    }
    w = waitpid(pid, &st, 0);
    while (w < 0 && errno == EINTR) {
      w = waitpid(pid, &st, 0);
    }
    if (w < 0) {
      printf("proc %s: FAIL (waitpid failed)\n", tag);
      failed = 1;
      continue;
    }
    if (WIFEXITED(st) && WEXITSTATUS(st) == 0) {
      printf("proc %s: PASS\n", tag);
    } else if (WIFEXITED(st)) {
      printf("proc %s: FAIL (exit %d)\n", tag, WEXITSTATUS(st));
      failed = 1;
    } else if (WIFSIGNALED(st)) {
      printf("proc %s: FAIL (signal %d)\n", tag, WTERMSIG(st));
      failed = 1;
    } else {
      printf("proc %s: FAIL (unknown wait status)\n", tag);
      failed = 1;
    }
  }
  unlink(g_cfg_path);
  if (failed) {
    printf("FAIL: concurrent first-call race (%d procs)\n", NPROCS);
    return 1;
  }
  printf("PASS: concurrent first-call race (%d procs x %d threads)\n", NPROCS,
         NTHREADS);
  return 0;
}

int main(int argc, char **argv) {
  if (argc == 4 && strcmp(argv[2], "child") == 0) {
    return run_child(argv[1], argv[3]);
  }
  if (argc != 2) {
    fprintf(stderr, "usage: %s <libhaskoki.so>\n", argv[0]);
    return 2;
  }
  return run_parent(argv[0], argv[1]);
}
