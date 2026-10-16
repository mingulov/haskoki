/* tests/c/ossl4_sanitize.c -- native ownership harness for the ossl4 shim.
 *
 * Links the shim object directly (not the shipped module) and drives
 * ownership cases against an exact, independent allocation count.
 *
 *   ossl4_sanitize --mem track|plain --case NAME [--no-arm]
 *   ossl4_sanitize --list
 *
 * --mem track installs a tracking allocator (CRYPTO_set_mem_functions)
 * that counts live blocks, brackets every block with canaries, poisons
 * fresh memory, and logs every free (pointer, size, nonzero user bytes,
 * canary state). The count is independent of the shim's own test
 * bookkeeping. --mem plain leaves the OpenSSL allocator alone so the
 * same cases run under AddressSanitizer.
 *
 * --no-arm runs a case without arming its fault seam; a case whose seam
 * never fires must fail, which proves the seam is what the case tests.
 *
 * One output line per run:
 *   CASE <name> PASS|FAIL variant=<hooks|prod> mem=<m> live_delta=<n>
 *        target_frees=<n> nonzero=<n> canary_bad=<n> seam_fired=<n>
 *        doublefree=<n> reason=<text>
 * Exit: 0 pass, 1 fail, 2 usage, 70 the shim's exit-time gate.
 */

#define _POSIX_C_SOURCE 200809L

#include "ossl4_ctx.h"

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/dh.h>
#include <openssl/encoder.h>
#include <openssl/evp.h>

#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* --- tracking allocator ---------------------------------------------- */

#define TRK_MAGIC 0x48534b54524b4d41ULL
#define TRK_HDR 32
#define TRK_CANARY 16
#define TRK_BYTE 0xC3
#define TRK_FILL 0xA5

typedef struct {
    unsigned long long magic;
    size_t size;
    unsigned long long serial;
    size_t pad;
} trk_hdr_t;

typedef struct {
    const void *ptr;
    size_t size;
    size_t nonzero;
    int canary_ok;
} trk_freed_t;

static pthread_mutex_t trk_mu = PTHREAD_MUTEX_INITIALIZER;
static long trk_live;        /* live tracked blocks */
static long trk_canary_bad;  /* frees with a damaged canary */
static unsigned long long trk_serial;
#define TRK_LOG 16384
static trk_freed_t trk_log[TRK_LOG];
static size_t trk_nlog; /* frees since trk_mark() */
static const void *trk_reuse_target;
static void *trk_stash; /* base of a block held back for reuse */
static size_t trk_stash_size;
static long trk_stash_hits; /* mallocs served from the stash */

static void trk_mark(void)
{
    pthread_mutex_lock(&trk_mu);
    trk_nlog = 0;
    pthread_mutex_unlock(&trk_mu);
}

#ifdef HSK_OSSL4_TEST_HOOKS
/* Number of logged frees matching (p, size); reports the first match's
 * nonzero count and canary state. */
static long trk_freed(const void *p, size_t size, size_t *nonzero,
                      int *canary_ok)
{
    long n = 0;
    size_t i;
    pthread_mutex_lock(&trk_mu);
    for (i = 0; i < trk_nlog; i++) {
        if (trk_log[i].ptr == p && trk_log[i].size == size) {
            if (n == 0) {
                if (nonzero != NULL)
                    *nonzero = trk_log[i].nonzero;
                if (canary_ok != NULL)
                    *canary_ok = trk_log[i].canary_ok;
            }
            n++;
        }
    }
    pthread_mutex_unlock(&trk_mu);
    return n;
}
#endif

static void *trk_wrap(unsigned char *base, size_t n)
{
    trk_hdr_t *hd = (trk_hdr_t *)base;
    unsigned char *user = base + TRK_HDR + TRK_CANARY;
    hd->magic = TRK_MAGIC;
    hd->size = n;
    hd->serial = ++trk_serial;
    hd->pad = 0;
    memset(base + TRK_HDR, TRK_BYTE, TRK_CANARY);
    memset(user, TRK_FILL, n);
    memset(user + n, TRK_BYTE, TRK_CANARY);
    trk_live++;
    return user;
}

static void *trk_malloc(size_t n, const char *file, int line)
{
    unsigned char *base;
    (void)file;
    (void)line;
    pthread_mutex_lock(&trk_mu);
    if (trk_stash != NULL && trk_stash_size == n) {
        base = trk_stash;
        trk_stash = NULL;
        trk_stash_size = 0;
        trk_stash_hits++;
    } else {
        base = malloc(TRK_HDR + 2 * TRK_CANARY + n);
        if (base == NULL) {
            pthread_mutex_unlock(&trk_mu);
            return NULL;
        }
    }
    {
        void *u = trk_wrap(base, n);
        pthread_mutex_unlock(&trk_mu);
        return u;
    }
}

static void trk_free(void *ptr, const char *file, int line)
{
    unsigned char *user = ptr, *base;
    trk_hdr_t *hd;
    size_t i, nz = 0, n;
    int ok = 1;
    (void)file;
    (void)line;
    if (ptr == NULL)
        return;
    pthread_mutex_lock(&trk_mu);
    base = user - TRK_HDR - TRK_CANARY;
    hd = (trk_hdr_t *)base;
    if (hd->magic != TRK_MAGIC) {
        fprintf(stderr, "foreign free %p\n", ptr);
        trk_canary_bad++;
        pthread_mutex_unlock(&trk_mu);
        return;
    }
    n = hd->size;
    for (i = 0; i < n; i++)
        if (user[i] != 0)
            nz++;
    for (i = 0; i < TRK_CANARY; i++)
        if (base[TRK_HDR + i] != TRK_BYTE || user[n + i] != TRK_BYTE)
            ok = 0;
    if (!ok)
        trk_canary_bad++;
    if (trk_nlog < TRK_LOG) {
        trk_log[trk_nlog].ptr = ptr;
        trk_log[trk_nlog].size = n;
        trk_log[trk_nlog].nonzero = nz;
        trk_log[trk_nlog].canary_ok = ok;
        trk_nlog++;
    }
    trk_live--;
    if (ptr == trk_reuse_target) {
        trk_reuse_target = NULL;
        trk_stash = base;
        trk_stash_size = n;
    } else {
        hd->magic = 0;
        free(base);
    }
    pthread_mutex_unlock(&trk_mu);
}

static void *trk_realloc(void *ptr, size_t n, const char *file, int line)
{
    void *np;
    if (ptr == NULL)
        return trk_malloc(n, file, line);
    np = trk_malloc(n, file, line);
    if (np != NULL) {
        size_t old = ((trk_hdr_t *)((unsigned char *)ptr - TRK_HDR -
                                    TRK_CANARY))->size;
        memcpy(np, ptr, old < n ? old : n);
        trk_free(ptr, file, line);
    }
    return np;
}

static long live_now(void)
{
    long r;
    pthread_mutex_lock(&trk_mu);
    r = trk_live;
    pthread_mutex_unlock(&trk_mu);
    return r;
}

/* --- case plumbing ---------------------------------------------------- */

static int g_track;
static int g_noarm;
static OSSL_LIB_CTX *g_lib;
static OSSL_PROVIDER *g_prov;

static const char *g_reason = "";
static long g_live_delta;
static long g_target_frees;
static long g_nonzero;
static long g_seam;
static long g_doublefree;
#ifdef HSK_OSSL4_TEST_HOOKS
static int g_skip_final_ack; /* the exit-gate case leaves its attempt */
#endif

#define REQ(cond, msg)                                                      \
    do {                                                                    \
        if (!(cond)) {                                                      \
            g_reason = (msg);                                               \
            return;                                                         \
        }                                                                   \
    } while (0)

/* The allocation-count check: only meaningful with the tracker. */
#define REQ_LIVE(before)                                                    \
    do {                                                                    \
        if (g_track) {                                                      \
            g_live_delta = live_now() - (before);                           \
            REQ(g_live_delta == 0, "trk_live-moved");                       \
        }                                                                   \
    } while (0)

static long mark_live(void)
{
    trk_mark();
    return g_track ? live_now() : 0;
}

typedef struct {
    const char *name;
    void (*fn)(void);
    int hooks_only;
    int track_only;
} case_t;

/* --- cases available in both configurations --------------------------- */

static void digest_cycle(long n)
{
    long i;
    for (i = 0; i < n; i++) {
        unsigned char *out = NULL;
        long rc;
        hsk_ossl4_md_t *h = hsk_ossl4_digest_init(g_lib, "SHA256", "");
        if (h == NULL || hsk_ossl4_digest_update(h, (const unsigned char *)"abc", 3) != 0) {
            g_reason = "digest-cycle-step";
            return;
        }
        rc = hsk_ossl4_digest_final(h, &out);
        if (rc != 32 || out == NULL) {
            g_reason = "digest-final";
            return;
        }
        hsk_ossl4_free(out, (size_t)rc);
    }
}

static void case_prod_digest_cycle(void)
{
    long before;
    digest_cycle(10);
    REQ(*g_reason == 0, "warm-up");
    before = mark_live();
    digest_cycle(10000);
    REQ(*g_reason == 0, g_reason);
    REQ_LIVE(before);
}

static void env_cycle(long n)
{
    long i;
    for (i = 0; i < n; i++) {
        hsk_ossl4_env_t *e = hsk_ossl4_env_new();
        if (e == NULL || hsk_ossl4_env_load(e, "default") != 0) {
            g_reason = "env-cycle-step";
            return;
        }
        hsk_ossl4_env_free(e);
    }
}

static void case_prod_env_cycle(void)
{
    long before;
    env_cycle(2);
    REQ(*g_reason == 0, "warm-up");
    before = mark_live();
    env_cycle(200);
    REQ(*g_reason == 0, g_reason);
    REQ_LIVE(before);
}

#ifdef HSK_OSSL4_TEST_HOOKS

static long ack(void)
{
    long n = hsk_ossl4_test_live_acknowledge();
    g_doublefree += n;
    return n;
}

static const unsigned char abc[3] = { 'a', 'b', 'c' };

/* --- hooks-only cases ---------------------------------------------------- */

#define N1000 1000

static void live_1000_run(hsk_ossl4_test_gate_t *g, long n, int check)
{
    hsk_ossl4_md_t **h = calloc((size_t)n, sizeof(*h));
    long i;
    if (h == NULL) {
        g_reason = "calloc";
        return;
    }
    for (i = 0; i < n; i++) {
        h[i] = hsk_ossl4_digest_init_gated(g, g_lib, "SHA256", "");
        if (h[i] == NULL) {
            g_reason = "init";
            free(h);
            return;
        }
    }
    if (check && hsk_ossl4_test_gate_digest_outstanding(g) != n) {
        g_reason = "outstanding-after-inits";
        free(h);
        return;
    }
    for (i = 0; i < n; i++)
        hsk_ossl4_digest_free(h[(i * 7) % n]);
    if (check && hsk_ossl4_test_gate_digest_outstanding(g) != 0) {
        g_reason = "outstanding-after-frees";
        free(h);
        return;
    }
    free(h);
}

static void case_live_1000(void)
{
    hsk_ossl4_test_gate_t *g = hsk_ossl4_test_gate_new();
    long before;
    REQ(g != NULL, "gate");
    live_1000_run(g, 10, 0);
    REQ(*g_reason == 0, "warm-up");
    ack();
    before = mark_live();
    live_1000_run(g, N1000, 1);
    REQ(*g_reason == 0, g_reason);
    REQ(hsk_ossl4_test_digest_doublefree() == 0, "doublefree-nonzero");
    REQ(ack() == 0, "doublefree-attempts");
    REQ_LIVE(before);
    hsk_ossl4_test_gate_free(g);
}

static void credit_run(hsk_ossl4_test_gate_t *g, int bogus)
{
    enum { N = 300 };
    hsk_ossl4_md_t *h[N];
    int i;
    for (i = 0; i < N; i++) {
        h[i] = hsk_ossl4_digest_init_gated(g, g_lib, "SHA256", "");
        if (h[i] == NULL) {
            g_reason = "init";
            return;
        }
    }
    if (bogus) {
        void *p = malloc(64);
        if (p == NULL) {
            g_reason = "malloc";
            return;
        }
        memset(p, 0, 64);
        hsk_ossl4_digest_free((hsk_ossl4_md_t *)p);
        free(p);
    }
    for (i = 0; i < N; i++)
        hsk_ossl4_digest_free(h[i]);
}

static void case_credit_gone(void)
{
    hsk_ossl4_test_gate_t *g = hsk_ossl4_test_gate_new();
    long before;
    REQ(g != NULL, "gate");
    credit_run(g, 0);
    REQ(*g_reason == 0, g_reason);
    ack();
    before = mark_live();
    credit_run(g, 1);
    REQ(*g_reason == 0, g_reason);
    {
        long n = hsk_ossl4_test_live_acknowledge();
        g_doublefree += n;
        REQ(n == 1, "bogus-pointer-not-counted");
    }
    REQ(hsk_ossl4_test_gate_digest_outstanding(g) == 0, "outstanding");
    REQ(trk_canary_bad == 0, "foreign-free");
    REQ_LIVE(before);
    hsk_ossl4_test_gate_free(g);
}

static void case_address_reuse(void)
{
    hsk_ossl4_test_gate_t *g1 = hsk_ossl4_test_gate_new();
    hsk_ossl4_test_gate_t *g2 = hsk_ossl4_test_gate_new();
    hsk_ossl4_md_t *a, *b;
    long before, hits0;
    REQ(g1 != NULL && g2 != NULL, "gate");
    a = hsk_ossl4_digest_init_gated(g1, g_lib, "SHA256", "");
    REQ(a != NULL, "warm-init");
    hsk_ossl4_digest_free(a);
    before = mark_live();
    a = hsk_ossl4_digest_init_gated(g1, g_lib, "SHA256", "");
    REQ(a != NULL, "init-a");
    hits0 = trk_stash_hits;
    if (!g_noarm)
        trk_reuse_target = a;
    hsk_ossl4_digest_free(a);
    b = hsk_ossl4_digest_init_gated(g2, g_lib, "SHA256", "");
    REQ(b != NULL, "init-b");
    g_seam = (b == a && trk_stash_hits == hits0 + 1);
    REQ(g_seam, "seam-not-fired");
    hsk_ossl4_digest_free(a); /* stale free of A, which is now B */
    REQ(hsk_ossl4_test_gate_digest_outstanding(g2) == 0,
        "stale-free-did-not-destroy-b");
    REQ(ack() == 0, "stale-free-counted-early");
    hsk_ossl4_digest_free(b); /* owner */
    {
        long n = hsk_ossl4_test_live_acknowledge();
        g_doublefree += n;
        REQ(n == 1, "owner-free-not-counted");
    }
    REQ_LIVE(before);
    hsk_ossl4_test_gate_free(g1);
    hsk_ossl4_test_gate_free(g2);
}

static void copy_fault_run(hsk_ossl4_test_gate_t *g, int arm, int measure)
{
    unsigned char *out = NULL;
    long rc = hsk_ossl4_digest_gated(g, g_lib, "SHA256", "", abc, 3, &out);
    if (rc != 32 || out == NULL) {
        g_reason = "digest-gated";
        return;
    }
    hsk_ossl4_test_gate_note_buf(g, 1);
    if (arm)
        hsk_ossl4_test_gate_arm_checkpoint(g, 1);
    g_seam = (hsk_ossl4_test_gate_poll(g) == 1);
    if (measure) {
        size_t nz = 0;
        int ok = 0;
        long n;
        trk_mark();
        hsk_ossl4_free_gated(g, out, (size_t)rc);
        n = trk_freed(out, 64, &nz, &ok);
        g_target_frees = n;
        g_nonzero = (long)nz;
        if (n != 1)
            g_reason = "target-not-freed-once";
        else if (!ok)
            g_reason = "canary-damaged";
        else if (nz != 64 - (size_t)rc)
            g_reason = "prefix-not-cleansed";
    } else {
        hsk_ossl4_free_gated(g, out, (size_t)rc);
    }
}

static void case_copy_fault(void)
{
    hsk_ossl4_test_gate_t *g = hsk_ossl4_test_gate_new();
    long before;
    REQ(g != NULL, "gate");
    copy_fault_run(g, 1, 0);
    REQ(*g_reason == 0, g_reason);
    before = mark_live();
    copy_fault_run(g, !g_noarm, 1);
    REQ(*g_reason == 0, g_reason);
    REQ(g_seam == 1, "seam-not-fired");
    REQ(hsk_ossl4_test_gate_buf_outstanding(g) == 0, "buf-outstanding");
    REQ_LIVE(before);
    hsk_ossl4_test_gate_free(g);
}

static void case_adoption_alloc(void)
{
    hsk_ossl4_test_gate_t *g = hsk_ossl4_test_gate_new();
    hsk_ossl4_env_t *e;
    long before;
    REQ(g != NULL, "gate");
    e = hsk_ossl4_env_new_gated(g);
    REQ(e != NULL, "warm-env");
    hsk_ossl4_env_free(e);
    before = mark_live();
    if (!g_noarm)
        hsk_ossl4_test_gate_arm_alloc_fail(g);
    e = hsk_ossl4_env_new_gated(g);
    g_seam = (e == NULL);
    if (e != NULL) {
        hsk_ossl4_env_free(e);
        REQ(0, "seam-not-fired");
    }
    REQ(hsk_ossl4_test_gate_env_outstanding(g) == 0, "env-outstanding");
    REQ_LIVE(before);
    hsk_ossl4_test_gate_free(g);
}

static void case_adoption_load(void)
{
    hsk_ossl4_test_gate_t *g = hsk_ossl4_test_gate_new();
    hsk_ossl4_env_t *e;
    long before, lrc;
    REQ(g != NULL, "gate");
    e = hsk_ossl4_env_new_gated(g);
    REQ(e != NULL, "warm-env");
    REQ(hsk_ossl4_env_load_gated(g, e, "default") == 0, "warm-load");
    hsk_ossl4_env_free(e);
    ack();
    before = mark_live();
    e = hsk_ossl4_env_new_gated(g);
    REQ(e != NULL, "env");
    if (!g_noarm)
        hsk_ossl4_test_gate_arm_checkpoint(g, 1);
    lrc = hsk_ossl4_env_load_gated(g, e, "default");
    g_seam = (lrc == -1);
    hsk_ossl4_env_free(e);
    REQ(lrc == -1, "load-not-faulted");
    REQ(hsk_ossl4_test_gate_env_outstanding(g) == 0, "env-outstanding");
    REQ(ack() == 0, "doublefree-attempts");
    REQ_LIVE(before);
    hsk_ossl4_test_gate_free(g);
}

static void final_fault_run(hsk_ossl4_test_gate_t *g, int arm, int check)
{
    unsigned char *out = NULL;
    long rc;
    hsk_ossl4_md_t *h = hsk_ossl4_digest_init_gated(g, g_lib, "SHA256", "");
    if (h == NULL || hsk_ossl4_digest_update(h, abc, 3) != 0) {
        g_reason = "init-update";
        return;
    }
    if (arm)
        hsk_ossl4_test_gate_arm_alloc_fail(g);
    rc = hsk_ossl4_digest_final_gated(g, h, &out);
    g_seam = (rc == HSK_OSSL4_ERR_NOMEM);
    if (out != NULL)
        hsk_ossl4_free_gated(g, out, rc > 0 ? (size_t)rc : 0);
    if (check) {
        if (rc != HSK_OSSL4_ERR_NOMEM)
            g_reason = "seam-not-fired";
        else if (out != NULL)
            g_reason = "out-set-on-fault";
    }
}

static void case_final_fault(void)
{
    hsk_ossl4_test_gate_t *g = hsk_ossl4_test_gate_new();
    long before;
    REQ(g != NULL, "gate");
    final_fault_run(g, 0, 0);
    REQ(*g_reason == 0, g_reason);
    before = mark_live();
    final_fault_run(g, !g_noarm, 1);
    REQ(*g_reason == 0, g_reason);
    REQ(hsk_ossl4_test_gate_digest_outstanding(g) == 0, "digest-outstanding");
    REQ_LIVE(before);
    hsk_ossl4_test_gate_free(g);
}

static void case_exit_gate(void)
{
    hsk_ossl4_md_t *h = hsk_ossl4_digest_init(g_lib, "SHA256", "");
    REQ(h != NULL, "init");
    hsk_ossl4_digest_free(h);
    hsk_ossl4_digest_free(h); /* a second free: counted, never destroyed */
    g_skip_final_ack = 1;     /* left unacknowledged on purpose */
}

#endif /* HSK_OSSL4_TEST_HOOKS */

static const case_t cases[] = {
    { "prod-digest-cycle", case_prod_digest_cycle, 0, 0 },
    { "prod-env-cycle", case_prod_env_cycle, 0, 0 },
#ifdef HSK_OSSL4_TEST_HOOKS
    { "live-1000", case_live_1000, 1, 0 },
    { "credit-gone", case_credit_gone, 1, 0 },
    { "address-reuse", case_address_reuse, 1, 1 },
    { "copy-fault", case_copy_fault, 1, 1 },
    { "adoption-alloc", case_adoption_alloc, 1, 0 },
    { "adoption-load", case_adoption_load, 1, 0 },
    { "final-fault", case_final_fault, 1, 0 },
    { "exit-gate", case_exit_gate, 1, 0 },
#endif
};

#define NCASES (sizeof(cases) / sizeof(cases[0]))

#ifdef HSK_OSSL4_TEST_HOOKS
#define VARIANT "hooks"
#else
#define VARIANT "prod"
#endif

static int usage(void)
{
    fprintf(stderr,
            "usage: ossl4_sanitize --mem track|plain --case NAME [--no-arm]\n"
            "       ossl4_sanitize --list\n");
    return 2;
}

int main(int argc, char **argv)
{
    const char *mem = NULL, *name = NULL;
    const case_t *c = NULL;
    size_t i;
    int pass;
    int a;

    for (a = 1; a < argc; a++) {
        if (strcmp(argv[a], "--list") == 0) {
            for (i = 0; i < NCASES; i++)
                printf("%s\n", cases[i].name);
            return 0;
        } else if (strcmp(argv[a], "--mem") == 0 && a + 1 < argc) {
            mem = argv[++a];
        } else if (strcmp(argv[a], "--case") == 0 && a + 1 < argc) {
            name = argv[++a];
        } else if (strcmp(argv[a], "--no-arm") == 0) {
            g_noarm = 1;
        } else {
            return usage();
        }
    }
    if (mem == NULL || name == NULL)
        return usage();
    if (strcmp(mem, "track") == 0)
        g_track = 1;
    else if (strcmp(mem, "plain") != 0)
        return usage();
    for (i = 0; i < NCASES; i++)
        if (strcmp(cases[i].name, name) == 0)
            c = &cases[i];
    if (c == NULL)
        return usage();
    if (c->track_only && !g_track) {
        fprintf(stderr, "case %s needs --mem track\n", name);
        return 2;
    }

    if (g_track && !CRYPTO_set_mem_functions(trk_malloc, trk_realloc,
                                             trk_free)) {
        printf("CASE %s FAIL variant=%s mem=%s live_delta=0 target_frees=0 "
               "nonzero=0 canary_bad=0 seam_fired=0 doublefree=0 "
               "reason=mem-functions-not-installed\n",
               name, VARIANT, mem);
        return 1;
    }

    g_lib = hsk_ossl4_new_ctx();
    if (g_lib != NULL)
        g_prov = hsk_ossl4_load_provider(g_lib, "default");
    if (g_lib == NULL || g_prov == NULL) {
        g_reason = "lib-setup";
    } else {
        c->fn();
    }
#ifdef HSK_OSSL4_TEST_HOOKS
    if (!g_skip_final_ack)
        g_doublefree += hsk_ossl4_test_live_acknowledge();
#endif
    pass = (*g_reason == 0 && trk_canary_bad == 0);
    if (pass && g_doublefree != 0 && strcmp(name, "credit-gone") != 0 &&
        strcmp(name, "address-reuse") != 0)
        pass = 0, g_reason = "unexpected-doublefree";
    if (!pass && *g_reason == 0)
        g_reason = "canary-or-foreign-free";
    printf("CASE %s %s variant=%s mem=%s live_delta=%ld target_frees=%ld "
           "nonzero=%ld canary_bad=%ld seam_fired=%ld doublefree=%ld "
           "reason=%s\n",
           name, pass ? "PASS" : "FAIL", VARIANT, mem, g_live_delta,
           g_target_frees, g_nonzero, trk_canary_bad, g_seam, g_doublefree,
           *g_reason ? g_reason : "ok");
    fflush(stdout);
    if (g_prov != NULL)
        hsk_ossl4_unload_provider(g_prov);
    hsk_ossl4_free_ctx(g_lib);
    OPENSSL_cleanup();
    return pass ? 0 : 1;
}
