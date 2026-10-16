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
 * The seam-* cases force the BN export and second-derive faults of the
 * three key agreements and check the freed extents.
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
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

#include <limits.h>
#include <stdint.h>
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
static int trk_quarantine; /* never hand a freed block back to libc */
static const void *trk_reuse_target;
static void *trk_stash; /* base of a block held back for reuse */
static size_t trk_stash_size;
/* Blocks withheld from libc stay on this list so a leak checker sees them
 * as reachable (a withheld block is not a leak); the link is stored in the
 * dead header's pad word. */
static unsigned char *trk_held;
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
        if (!trk_quarantine) {
            free(base);
        } else {
            hd->pad = (size_t)(uintptr_t)trk_held;
            trk_held = base;
        }
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
    int hidden; /* a negative control: run by name, not listed */
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

typedef struct {
    unsigned char *priv;
    size_t privlen;
    unsigned char *peer;
    size_t peerlen;
} seam_keys_t;

static void seam_keys_free(seam_keys_t *k)
{
    OPENSSL_free(k->priv);
    OPENSSL_free(k->peer);
    memset(k, 0, sizeof(*k));
}

/* PKCS#8 DER of a private key through the encoder. */
static int priv_der(EVP_PKEY *pkey, unsigned char **der, size_t *len)
{
    OSSL_ENCODER_CTX *ec = OSSL_ENCODER_CTX_new_for_pkey(
        pkey, EVP_PKEY_KEYPAIR, "DER", "PrivateKeyInfo", NULL);
    int ok = 0;
    *der = NULL;
    *len = 0;
    if (ec != NULL && OSSL_ENCODER_CTX_get_num_encoders(ec) > 0 &&
        OSSL_ENCODER_to_data(ec, der, len))
        ok = 1;
    OSSL_ENCODER_CTX_free(ec);
    return ok;
}

static EVP_PKEY *gen_from(const char *alg, const char *group)
{
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_name(g_lib, alg, "");
    EVP_PKEY *k = NULL;
    if (c == NULL || EVP_PKEY_keygen_init(c) <= 0)
        goto done;
    if (group != NULL) {
        OSSL_PARAM p[2];
        p[0] = OSSL_PARAM_construct_utf8_string(
            "group", (char *)group, 0);
        p[1] = OSSL_PARAM_construct_end();
        if (EVP_PKEY_CTX_set_params(c, p) <= 0)
            goto done;
    }
    if (EVP_PKEY_generate(c, &k) <= 0)
        k = NULL;
done:
    EVP_PKEY_CTX_free(c);
    return k;
}

/* Big-endian public value of a DH key. */
static int dh_pub_bytes(EVP_PKEY *k, unsigned char **out, size_t *len)
{
    BIGNUM *bn = NULL;
    int n;
    if (EVP_PKEY_get_bn_param(k, "pub", &bn) <= 0)
        return 0;
    n = BN_num_bytes(bn);
    *out = OPENSSL_malloc((size_t)n);
    if (*out == NULL) {
        BN_free(bn);
        return 0;
    }
    BN_bn2bin(bn, *out);
    *len = (size_t)n;
    BN_free(bn);
    return 1;
}


/* --- agreement and AEAD cases, both configurations ----------------------- */

typedef struct {
    EVP_PKEY *a, *b;
    seam_keys_t ka, kb; /* priv = own private DER, peer = other's public */
} pair_t;

static void pair_free(pair_t *p)
{
    seam_keys_free(&p->ka);
    seam_keys_free(&p->kb);
    EVP_PKEY_free(p->a);
    EVP_PKEY_free(p->b);
    memset(p, 0, sizeof(*p));
}

/* kind 0 = EC P-256, 1 = X25519, 2 = ffdhe2048. */
static int peer_of(int kind, EVP_PKEY *k, unsigned char **o, size_t *l)
{
    if (kind == 0) {
        unsigned char *q = NULL;
        int n = i2d_PUBKEY(k, &q);
        if (n <= 0)
            return 0;
        *o = q;
        *l = (size_t)n;
        return 1;
    }
    if (kind == 1) {
        size_t n = 32;
        *o = OPENSSL_malloc(n);
        if (*o == NULL || EVP_PKEY_get_raw_public_key(k, *o, &n) <= 0 ||
            n != 32)
            return 0;
        *l = n;
        return 1;
    }
    return dh_pub_bytes(k, o, l);
}

static int pair_new(int kind, pair_t *p)
{
    const char *alg = kind == 0 ? "EC" : kind == 1 ? "X25519" : "DH";
    const char *grp = kind == 0 ? "P-256" : kind == 1 ? NULL : "ffdhe2048";
    memset(p, 0, sizeof(*p));
    p->a = gen_from(alg, grp);
    p->b = gen_from(alg, grp);
    if (p->a == NULL || p->b == NULL ||
        !priv_der(p->a, &p->ka.priv, &p->ka.privlen) ||
        !priv_der(p->b, &p->kb.priv, &p->kb.privlen) ||
        !peer_of(kind, p->b, &p->ka.peer, &p->ka.peerlen) ||
        !peer_of(kind, p->a, &p->kb.peer, &p->kb.peerlen)) {
        pair_free(p);
        return 0;
    }
    return 1;
}

static long pair_derive(int kind, const seam_keys_t *k, unsigned char **out)
{
    *out = NULL;
    if (kind == 0)
        return hsk_ossl4_ecdh_derive(g_lib, "", k->priv, k->privlen, k->peer,
                                     k->peerlen, 0, out);
    if (kind == 1)
        return hsk_ossl4_xdh_derive(g_lib, "", k->priv, k->privlen, k->peer,
                                    k->peerlen, out);
    return hsk_ossl4_dh_derive(g_lib, "", k->priv, k->privlen, k->peer,
                               k->peerlen, out);
}

/* A to B equals B to A; the secret is the full width of the group. */
static void agree_case(int kind, long width)
{
    pair_t p;
    unsigned char *x = NULL, *y = NULL;
    long rx, ry;
    REQ(pair_new(kind, &p), "keys");
    rx = pair_derive(kind, &p.ka, &x);
    ry = pair_derive(kind, &p.kb, &y);
    if (rx != width || ry != width || x == NULL || y == NULL)
        g_reason = "derive-failed";
    else if (memcmp(x, y, (size_t)width) != 0)
        g_reason = "secrets-differ";
    if (x != NULL)
        hsk_ossl4_free(x, (size_t)rx);
    if (y != NULL)
        hsk_ossl4_free(y, (size_t)ry);
    pair_free(&p);
}

static void case_prod_dh_kat(void)
{
    agree_case(2, 256);
}

static void case_prod_ecdh(void)
{
    agree_case(0, 32);
}

static void case_prod_xdh(void)
{
    agree_case(1, 32);
}

static void case_prod_aead(void)
{
    unsigned char key[32], iv[12], tag[16];
    unsigned char *ct = NULL, *pt = NULL;
    static const unsigned char msg[20] = "sanitizer aead test";
    long n, m;
    size_t i;
    for (i = 0; i < sizeof(key); i++)
        key[i] = (unsigned char)i;
    for (i = 0; i < sizeof(iv); i++)
        iv[i] = (unsigned char)(0x40 + i);
    n = hsk_ossl4_aead_encrypt(g_lib, "AES-256-GCM", "", key, sizeof(key), iv,
                               sizeof(iv), (const unsigned char *)"hdr", 3,
                               msg, sizeof(msg), 16, &ct);
    REQ(n == (long)(sizeof(msg) + 16) && ct != NULL, "encrypt");
    memcpy(tag, ct + sizeof(msg), sizeof(tag));
    m = hsk_ossl4_aead_decrypt(g_lib, "AES-256-GCM", "", key, sizeof(key), iv,
                               sizeof(iv), (const unsigned char *)"hdr", 3,
                               ct, sizeof(msg), tag, sizeof(tag), &pt);
    if (m != (long)sizeof(msg) || pt == NULL ||
        memcmp(pt, msg, sizeof(msg)) != 0) {
        g_reason = "roundtrip";
    }
    if (pt != NULL)
        hsk_ossl4_free(pt, (size_t)(m > 0 ? m : 0));
    pt = NULL;
    if (*g_reason == 0) {
        tag[0] ^= 1;
        m = hsk_ossl4_aead_decrypt(g_lib, "AES-256-GCM", "", key, sizeof(key),
                                   iv, sizeof(iv),
                                   (const unsigned char *)"hdr", 3, ct,
                                   sizeof(msg), tag, sizeof(tag), &pt);
        if (m != HSK_OSSL4_ERR_AUTHFAIL || pt != NULL)
            g_reason = "tamper-not-authfail";
        else if (pt != NULL)
            hsk_ossl4_free(pt, (size_t)m);
    }
    hsk_ossl4_free(ct, (size_t)n);
}

/* --- negative controls (prod configuration, plain memory) ---------------- */

static int g_argc;

/* A result buffer freed twice: the plain double-free report. The handle
 * controls below cover repeat destruction of a handle. */
static void case_neg_double_free(void)
{
    unsigned char *out = NULL;
    long rc;
    hsk_ossl4_md_t *h = hsk_ossl4_digest_init(g_lib, "SHA256", "");
    REQ(h != NULL, "init");
    rc = hsk_ossl4_digest_final(h, &out);
    REQ(rc == 32 && out != NULL, "final");
    hsk_ossl4_free(out, (size_t)rc);
    OPENSSL_free(out);
}

/* A handle freed twice. Production destruction is unconditional, so
 * ASan reports the second free (as a use-after-free of the handle, or as
 * a double free). A registry that absorbed repeat frees in the
 * production configuration would make these controls exit cleanly. */
static void case_neg_handle_double_free(void)
{
    hsk_ossl4_md_t *h = hsk_ossl4_digest_init(g_lib, "SHA256", "");
    REQ(h != NULL, "init");
    hsk_ossl4_digest_free(h);
    hsk_ossl4_digest_free(h);
}

static void case_neg_env_double_free(void)
{
    hsk_ossl4_env_t *e = hsk_ossl4_env_new();
    REQ(e != NULL && hsk_ossl4_env_load(e, "default") == 0, "env");
    hsk_ossl4_env_free(e);
    hsk_ossl4_env_free(e);
}

static void case_neg_heap_overflow(void)
{
    pair_t p;
    unsigned char *x = NULL;
    long rc;
    REQ(pair_new(2, &p), "keys");
    rc = pair_derive(2, &p.ka, &x);
    REQ(rc == 256 && x != NULL, "derive");
    x[rc] = 0; /* one byte past the allocation */
    hsk_ossl4_free(x, (size_t)rc);
    pair_free(&p);
}

static void case_neg_ubsan(void)
{
    volatile int big = INT_MAX;
    volatile int r = big + (g_argc > 0);
    (void)r;
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
    if (measure && g_track) {
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

/* --- native error seams ------------------------------------------------ */

enum { K_ECDH, K_XDH, K_DH_NAMED, K_DH_EXPLICIT };

/* Fresh pair: the private DER of A and the peer value of B. */
static int seam_keys(int kind, seam_keys_t *k)
{
    EVP_PKEY *a = NULL, *b = NULL, *params = NULL;
    int ok = 0;
    memset(k, 0, sizeof(*k));
    if (kind == K_DH_EXPLICIT) {
        EVP_PKEY_CTX *pc = EVP_PKEY_CTX_new_from_name(g_lib, "DHX", "");
        EVP_PKEY_CTX *kc;
        unsigned int pbits = 2048, qbits = 224;
        OSSL_PARAM gp[4];
        gp[0] = OSSL_PARAM_construct_utf8_string("type", (char *)"fips186_4",
                                                 0);
        gp[1] = OSSL_PARAM_construct_uint("pbits", &pbits);
        gp[2] = OSSL_PARAM_construct_uint("qbits", &qbits);
        gp[3] = OSSL_PARAM_construct_end();
        /* FIPS 186-4 explicit parameters with a 224-bit subgroup. */
        if (pc == NULL || EVP_PKEY_paramgen_init(pc) <= 0 ||
            EVP_PKEY_CTX_set_params(pc, gp) <= 0 ||
            EVP_PKEY_paramgen(pc, &params) <= 0) {
            EVP_PKEY_CTX_free(pc);
            return 0;
        }
        EVP_PKEY_CTX_free(pc);
        kc = EVP_PKEY_CTX_new_from_pkey(g_lib, params, "");
        if (kc != NULL && EVP_PKEY_keygen_init(kc) > 0 &&
            EVP_PKEY_generate(kc, &a) > 0 && EVP_PKEY_generate(kc, &b) > 0)
            ok = 1;
        EVP_PKEY_CTX_free(kc);
        if (!ok)
            goto done;
        ok = 0;
    } else if (kind == K_ECDH) {
        a = gen_from("EC", "P-256");
        b = gen_from("EC", "P-256");
    } else if (kind == K_XDH) {
        a = gen_from("X25519", NULL);
        b = gen_from("X25519", NULL);
    } else {
        a = gen_from("DH", "ffdhe2048");
        b = gen_from("DH", "ffdhe2048");
    }
    if (a == NULL || b == NULL || !priv_der(a, &k->priv, &k->privlen))
        goto done;
    if (kind == K_ECDH) {
        unsigned char *p = NULL;
        int n = i2d_PUBKEY(b, &p);
        if (n <= 0)
            goto done;
        k->peer = p;
        k->peerlen = (size_t)n;
    } else if (kind == K_XDH) {
        size_t n = 32;
        k->peer = OPENSSL_malloc(n);
        if (k->peer == NULL ||
            EVP_PKEY_get_raw_public_key(b, k->peer, &n) <= 0 || n != 32)
            goto done;
        k->peerlen = n;
    } else if (!dh_pub_bytes(b, &k->peer, &k->peerlen)) {
        goto done;
    }
    ok = 1;
done:
    if (!ok)
        seam_keys_free(k);
    EVP_PKEY_free(a);
    EVP_PKEY_free(b);
    EVP_PKEY_free(params);
    return ok;
}

static long seam_derive(int kind, const seam_keys_t *k, unsigned char **out)
{
    *out = NULL;
    if (kind == K_ECDH)
        return hsk_ossl4_ecdh_derive(g_lib, "", k->priv, k->privlen, k->peer,
                                     k->peerlen, 0, out);
    if (kind == K_XDH)
        return hsk_ossl4_xdh_derive(g_lib, "", k->priv, k->privlen, k->peer,
                                    k->peerlen, out);
    return hsk_ossl4_dh_derive(g_lib, "", k->priv, k->privlen, k->peer,
                               k->peerlen, out);
}

/* One unarmed derive to warm provider caches, then reset the seam. */
static int seam_warm(int kind, const seam_keys_t *k)
{
    unsigned char *out = NULL;
    long rc = seam_derive(kind, k, &out);
    if (rc <= 0 || out == NULL)
        return 0;
    hsk_ossl4_free(out, (size_t)rc);
    hsk_ossl4_test_seam_reset();
    return 1;
}

/* The noted allocation of `which` was freed exactly once, cleansed over
 * its whole extent, canary intact. Only the tracking allocator logs frees:
 * on the plain allocator the case checks that the buffer was noted and
 * leaves the boundaries and the free to ASan. */
static void check_target(int which)
{
    void *p = NULL;
    size_t alloc = 0, nz = 0;
    int ok = 0;
    long n;
    REQ(hsk_ossl4_test_seam_target(which, &p, &alloc) == 1, "no-target");
    if (!g_track)
        return;
    n = trk_freed(p, alloc, &nz, &ok);
    g_target_frees = n;
    g_nonzero = (long)nz;
    REQ(n == 1, "target-not-freed-once");
    REQ(nz == 0, "target-not-cleansed");
    REQ(ok, "canary-damaged");
}

static void seam_fired_check(void)
{
    g_seam = hsk_ossl4_test_seam_fired();
    REQ(g_seam == 1, "seam-not-reached");
}

static void bn_case(int kind, int nth, long expect_calls)
{
    trk_quarantine = 1; /* unique addresses: one free per allocation */
    seam_keys_t k;
    unsigned char *out = NULL;
    long before, rc;
    REQ(seam_keys(kind, &k), "keys");
    REQ(seam_warm(kind, &k), "warmup");
    rc = seam_derive(kind, &k, &out);
    REQ(rc > 0, "unarmed-derive");
    hsk_ossl4_free(out, (size_t)rc);
    REQ(hsk_ossl4_test_seam_bn_calls() == expect_calls, "bn-call-count");
    hsk_ossl4_test_seam_reset();
    before = mark_live();
    if (!g_noarm)
        hsk_ossl4_test_seam_arm_bn_fail(nth);
    rc = seam_derive(kind, &k, &out);
    seam_fired_check();
    REQ(*g_reason == 0, g_reason);
    REQ(rc == -1, "rc-not-native");
    REQ(out == NULL, "out-set");
    check_target(HSK_OSSL4_SEAM_PACK);
    REQ_LIVE(before);
    seam_keys_free(&k);
}

static void case_seam_bn_named(void)
{
    bn_case(K_DH_NAMED, 1, 1);
}

static void case_seam_bn_explicit(void)
{
    int nth;
    for (nth = 1; nth <= 4; nth++) {
        bn_case(K_DH_EXPLICIT, nth, 4);
        if (*g_reason != 0)
            return;
        if (g_noarm)
            return;
    }
}

enum { M_FAIL, M_OK };

static void derive_case(int kind, int grow, int mode)
{
    seam_keys_t k;
    unsigned char *out = NULL;
    long before, rc;
    long delta = grow ? 1 : -1;
    trk_quarantine = 1; /* unique addresses: one free per allocation */
    void *tp = NULL;
    size_t alloc = 0;
    REQ(seam_keys(kind, &k), "keys");
    REQ(seam_warm(kind, &k), "warmup");
    before = mark_live();
    if (!g_noarm)
        hsk_ossl4_test_seam_arm_derive(delta, mode == M_OK);
    rc = seam_derive(kind, &k, &out);
    seam_fired_check();
    REQ(*g_reason == 0, g_reason);
    REQ(hsk_ossl4_test_seam_target(HSK_OSSL4_SEAM_SECRET, &tp, &alloc) == 1,
        "no-target");
    if (mode == M_FAIL) {
        REQ(rc == (kind == K_XDH ? -6 : -1), "rc-code");
        REQ(out == NULL, "out-set");
    } else if (grow) {
        REQ(rc == -1, "grow-rc");
        REQ(out == NULL, "out-set");
    } else {
        REQ(rc == (long)alloc - 1, "shrink-rc");
        REQ(out != NULL, "out-null");
        hsk_ossl4_free(out, (size_t)rc);
        out = NULL;
    }
    check_target(HSK_OSSL4_SEAM_SECRET);
    REQ_LIVE(before);
    seam_keys_free(&k);
}

#define DERIVE_CASES(kindname, kind)                                        \
    static void case_seam_fail_shrink_##kindname(void)                      \
    {                                                                       \
        derive_case(kind, 0, M_FAIL);                                       \
    }                                                                       \
    static void case_seam_fail_grow_##kindname(void)                        \
    {                                                                       \
        derive_case(kind, 1, M_FAIL);                                       \
    }                                                                       \
    static void case_seam_ok_shrink_##kindname(void)                        \
    {                                                                       \
        derive_case(kind, 0, M_OK);                                         \
    }                                                                       \
    static void case_seam_ok_grow_##kindname(void)                          \
    {                                                                       \
        derive_case(kind, 1, M_OK);                                         \
    }

DERIVE_CASES(ecdh, K_ECDH)
DERIVE_CASES(xdh, K_XDH)
DERIVE_CASES(dh, K_DH_NAMED)

/* --- per-helper failure-path extent cases -------------------------------
 * Every helper that cleanses an allocation after a length-mutating output
 * call gets its own shrink/grow pair: the seam fills the buffer and moves
 * the reported length by delta, so cleansing the reported length overruns
 * (grow) or leaves a dirty tail byte (shrink). One driver serves them all;
 * each fail-leg cleanse is covered by its own helper pair. */
typedef struct {
    EVP_PKEY *key;          /* live key, when keygen was used */
    unsigned char *priv;    /* PKCS#8 private DER (sign/decrypt) */
    size_t privlen;
    unsigned char *pub;     /* SPKI public DER (encrypt) */
    size_t publen;
    unsigned char *in;      /* decrypt input (OAEP zeroes, PKCS#1 ct) */
    size_t inlen;
    const unsigned char *msg;
    size_t msglen;
    long warm_len;          /* warmup exact length, 0 = any positive */
} fail_keys_t;

typedef struct {
    void (*arm)(long delta, int mode);
    int arm_mode;           /* decrypt realfirst / digest succeed */
    int slot;               /* seam slot for the extent check */
    long armed_rc;          /* expected armed-call return */
    long warm_fail_rc;      /* 0 = the warmup must succeed */
    int (*prepare)(fail_keys_t *k);
    long (*invoke)(fail_keys_t *k, unsigned char **out);
} fail_spec_t;

static const unsigned char fail_msg5[5] = { 'h', 'e', 'l', 'l', 'o' };
/* The DSA raw operation enforces a 20-byte digest floor and the X9.31
 * prehash signs a caller digest, so those two cases use longer fixed
 * inputs. */
static unsigned char fail_msg20[20];
static unsigned char fail_msg32[32];
static int fail_msg_filled;

static void fill_fail_msgs(void)
{
    size_t i;
    if (fail_msg_filled)
        return;
    for (i = 0; i < sizeof(fail_msg20); i++)
        fail_msg20[i] = (unsigned char)(i + 1);
    for (i = 0; i < sizeof(fail_msg32); i++)
        fail_msg32[i] = (unsigned char)(0xA0 + i);
    fail_msg_filled = 1;
}

static void arm2_encrypt(long delta, int mode)
{
    (void)mode;
    hsk_ossl4_test_seam_arm_encrypt(delta);
}

static void arm2_pkey_sign(long delta, int mode)
{
    (void)mode;
    hsk_ossl4_test_seam_arm_pkey_sign(delta);
}

static void fail_keys_free(fail_keys_t *k)
{
    OPENSSL_free(k->priv);
    OPENSSL_free(k->pub);
    OPENSSL_free(k->in);
    EVP_PKEY_free(k->key);
    memset(k, 0, sizeof(*k));
}

static void fail_case(const fail_spec_t *spec, int grow)
{
    fail_keys_t keys;
    unsigned char *out = NULL;
    long before, rc;
    long delta = grow ? 1 : -1;
    memset(&keys, 0, sizeof(keys));
    trk_quarantine = 1; /* unique addresses: one free per allocation */
    fill_fail_msgs();
    REQ(spec->prepare(&keys), "keys");
    /* Warmup: an unarmed call populates the libctx caches before the
     * live mark. Drop the note the warmup recorded. */
    rc = spec->invoke(&keys, &out);
    if (spec->warm_fail_rc != 0) {
        REQ(rc == spec->warm_fail_rc && out == NULL, "warmup");
    } else {
        REQ(rc > 0 && out != NULL, "warmup");
        if (keys.warm_len > 0)
            REQ(rc == keys.warm_len, "warmup-len");
        hsk_ossl4_free(out, (size_t)rc);
        out = NULL;
    }
    hsk_ossl4_test_seam_reset();
    /* Drain OpenSSL's per-thread error state around the measurement:
     * provider calls raise soft errors whose file/func/data strings
     * live in thread state until the next clear, so a stale entry
     * freed by the measured call (or a fresh one it raises) would
     * move the live count without any shim leak. The drains only
     * release error-state strings; every shim block stays counted. */
    ERR_clear_error();
    before = mark_live();
    if (!g_noarm)
        spec->arm(delta, spec->arm_mode);
    rc = spec->invoke(&keys, &out);
    seam_fired_check();
    REQ(*g_reason == 0, g_reason);
    REQ(rc == spec->armed_rc, "rc-code");
    REQ(out == NULL, "out-set");
    check_target(spec->slot);
    ERR_clear_error();
    REQ_LIVE(before);
    fail_keys_free(&keys);
}

/* --- RSA key material (decrypt, encrypt, raw/hash/PSS/X9.31 sign) --- */
static int prep_rsa_priv(fail_keys_t *k)
{
    int ksize;
    k->key = gen_from("RSA", NULL);
    if (k->key == NULL)
        return 0;
    ksize = EVP_PKEY_get_size(k->key);
    if (ksize <= 0 || !priv_der(k->key, &k->priv, &k->privlen))
        return 0;
    k->msg = fail_msg5;
    k->msglen = sizeof(fail_msg5);
    k->warm_len = ksize;
    return 1;
}

static int prep_rsa_pub(fail_keys_t *k)
{
    int n;
    if (!prep_rsa_priv(k))
        return 0;
    n = i2d_PUBKEY(k->key, &k->pub);
    if (n <= 0 || k->pub == NULL)
        return 0;
    k->publen = (size_t)n;
    return 1;
}

/* OAEP decrypt: the all-zero input is never valid padding, so the warmup
 * fails the same way the armed call does. */
static int prep_oaep(fail_keys_t *k)
{
    if (!prep_rsa_priv(k))
        return 0;
    k->in = OPENSSL_malloc((size_t)k->warm_len);
    if (k->in == NULL)
        return 0;
    k->inlen = (size_t)k->warm_len;
    memset(k->in, 0, k->inlen);
    return 1;
}

/* PKCS#1 decrypt: a valid ciphertext (built with an unarmed encrypt),
 * so the realfirst seam performs the real call before reporting failure
 * and provider state matches the unarmed run. */
static int prep_pkcs1dec(fail_keys_t *k)
{
    unsigned char *ct = NULL;
    long rc;
    if (!prep_rsa_pub(k))
        return 0;
    rc = hsk_ossl4_rsa_pkcs1_encrypt(g_lib, "", k->pub, k->publen, k->msg,
                                     k->msglen, &ct);
    if (rc <= 0 || ct == NULL) {
        OPENSSL_free(ct);
        return 0;
    }
    k->in = ct;
    k->inlen = (size_t)rc;
    k->warm_len = (long)k->msglen; /* the warmup recovers the input */
    return 1;
}

static int prep_x931_prehash(fail_keys_t *k)
{
    if (!prep_rsa_priv(k))
        return 0;
    /* A fixed digest stand-in: the prehash path signs the caller digest
     * directly (mdname selects the X9.31 hash id only). */
    k->msg = fail_msg32;
    k->msglen = sizeof(fail_msg32);
    return 1;
}

static long inv_rsa_oaep_decrypt(fail_keys_t *k, unsigned char **out)
{
    return hsk_ossl4_rsa_oaep_decrypt(g_lib, "SHA256", "SHA256", NULL, 0, "",
                                      k->priv, k->privlen, k->in, k->inlen,
                                      out);
}

static long inv_rsa_pkcs1_decrypt(fail_keys_t *k, unsigned char **out)
{
    return hsk_ossl4_rsa_pkcs1_decrypt(g_lib, "", k->priv, k->privlen, k->in,
                                       k->inlen, out);
}

static long inv_rsa_pkcs1_encrypt(fail_keys_t *k, unsigned char **out)
{
    return hsk_ossl4_rsa_pkcs1_encrypt(g_lib, "", k->pub, k->publen, k->msg,
                                       k->msglen, out);
}

static long inv_rsa_oaep_encrypt(fail_keys_t *k, unsigned char **out)
{
    return hsk_ossl4_rsa_oaep_encrypt(g_lib, "SHA256", "SHA256", NULL, 0, "",
                                      k->pub, k->publen, k->msg, k->msglen,
                                      out);
}

static long inv_rsa_raw_sign(fail_keys_t *k, unsigned char **out)
{
    return hsk_ossl4_rsa_sign(g_lib, NULL, "", k->priv, k->privlen, k->msg,
                              k->msglen, 1, out);
}

static long inv_rsa_hash_sign(fail_keys_t *k, unsigned char **out)
{
    return hsk_ossl4_rsa_sign(g_lib, "SHA256", "", k->priv, k->privlen, k->msg,
                              k->msglen, 0, out);
}

static long inv_pss_sign(fail_keys_t *k, unsigned char **out)
{
    return hsk_ossl4_rsa_pss_sign(g_lib, "SHA256", "SHA256", 32, "", k->priv,
                                  k->privlen, k->msg, k->msglen, out);
}

static long inv_x931_prehash(fail_keys_t *k, unsigned char **out)
{
    return hsk_ossl4_rsa_x931_sign(g_lib, "SHA256", "", k->priv, k->privlen,
                                   k->msg, k->msglen, 1, out);
}

static long inv_x931_digested(fail_keys_t *k, unsigned char **out)
{
    return hsk_ossl4_rsa_x931_sign(g_lib, "SHA256", "", k->priv, k->privlen,
                                   k->msg, k->msglen, 0, out);
}

/* --- ECDSA/DSA (raw and hash branches each own a pair) --- */
static int prep_ec(fail_keys_t *k)
{
    k->key = gen_from("EC", "P-256");
    if (k->key == NULL || !priv_der(k->key, &k->priv, &k->privlen))
        return 0;
    k->msg = fail_msg5;
    k->msglen = sizeof(fail_msg5);
    k->warm_len = 0; /* DER length varies per signature */
    return 1;
}

static int prep_dsa(fail_keys_t *k)
{
    unsigned char *pd = NULL;
    long prc;
    int kr;
    prc = hsk_ossl4_dsa_gen_params(g_lib, "", 1024, 160, &pd);
    if (prc <= 0) {
        OPENSSL_free(pd);
        return 0;
    }
    kr = hsk_ossl4_dsa_gen_keypair(g_lib, "", pd, (size_t)prc, &k->priv,
                                   &k->privlen, &k->pub, &k->publen);
    OPENSSL_free(pd);
    if (kr != 0)
        return 0;
    k->msg = fail_msg5;
    k->msglen = sizeof(fail_msg5);
    k->warm_len = 0;
    return 1;
}

static int prep_dsa_raw(fail_keys_t *k)
{
    if (!prep_dsa(k))
        return 0;
    /* The raw operation enforces the 20-byte digest floor. */
    k->msg = fail_msg20;
    k->msglen = sizeof(fail_msg20);
    return 1;
}

static long inv_ecdsa_raw(fail_keys_t *k, unsigned char **out)
{
    return hsk_ossl4_ecdsa_sign(g_lib, NULL, "", k->priv, k->privlen, k->msg,
                                k->msglen, 0, 1, out);
}

static long inv_ecdsa_hash(fail_keys_t *k, unsigned char **out)
{
    return hsk_ossl4_ecdsa_sign(g_lib, "SHA256", "", k->priv, k->privlen,
                                k->msg, k->msglen, 0, 0, out);
}

static long inv_dsa_raw(fail_keys_t *k, unsigned char **out)
{
    return hsk_ossl4_dsa_sign(g_lib, NULL, "", k->priv, k->privlen, k->msg,
                              k->msglen, 0, 1, out);
}

static long inv_dsa_hash(fail_keys_t *k, unsigned char **out)
{
    return hsk_ossl4_dsa_sign(g_lib, "SHA1", "", k->priv, k->privlen, k->msg,
                              k->msglen, 0, 0, out);
}

static long inv_ecdsa_hash_raw(fail_keys_t *k, unsigned char **out)
{
    return hsk_ossl4_ecdsa_sign(g_lib, "SHA256", "", k->priv, k->privlen,
                                k->msg, k->msglen, 1, 0, out);
}

static long inv_dsa_hash_raw(fail_keys_t *k, unsigned char **out)
{
    return hsk_ossl4_dsa_sign(g_lib, "SHA1", "", k->priv, k->privlen, k->msg,
                              k->msglen, 1, 0, out);
}

/* --- EdDSA/ML-DSA/SLH-DSA (fixed signature lengths pin the warmup) --- */
static int prep_evp(fail_keys_t *k, const char *alg, long siglen)
{
    k->key = gen_from(alg, NULL);
    if (k->key == NULL || !priv_der(k->key, &k->priv, &k->privlen))
        return 0;
    k->msg = fail_msg5;
    k->msglen = sizeof(fail_msg5);
    k->warm_len = siglen;
    return 1;
}

static int prep_ed25519(fail_keys_t *k)
{
    return prep_evp(k, "Ed25519", 64);
}

static int prep_mldsa44(fail_keys_t *k)
{
    return prep_evp(k, "ML-DSA-44", 2420);
}

static int prep_slhdsa128s(fail_keys_t *k)
{
    return prep_evp(k, "SLH-DSA-SHA2-128s", 7856);
}

static long inv_eddsa(fail_keys_t *k, unsigned char **out)
{
    return hsk_ossl4_eddsa_sign(g_lib, "ED25519", "", k->priv, k->privlen,
                                k->msg, k->msglen, out);
}

static long inv_mldsa(fail_keys_t *k, unsigned char **out)
{
    return hsk_ossl4_mldsa_sign(g_lib, "ML-DSA-44", "", k->priv, k->privlen,
                                k->msg, k->msglen, NULL, 0, 0, out);
}

static long inv_slhdsa(fail_keys_t *k, unsigned char **out)
{
    return hsk_ossl4_slhdsa_sign(g_lib, "SLH-DSA-SHA2-128s", "", k->priv,
                                 k->privlen, k->msg, k->msglen, NULL, 0, 0,
                                 out);
}

/* One row per helper and per branch; the pair name follows the row. */
static const fail_spec_t spec_oaep_decrypt = {
    hsk_ossl4_test_seam_arm_decrypt, 0, HSK_OSSL4_SEAM_OAEP,
    HSK_OSSL4_ERR_AUTHFAIL, HSK_OSSL4_ERR_AUTHFAIL,
    prep_oaep, inv_rsa_oaep_decrypt
};
static const fail_spec_t spec_pkcs1_decrypt = {
    hsk_ossl4_test_seam_arm_decrypt, 1, HSK_OSSL4_SEAM_OAEP,
    HSK_OSSL4_ERR_AUTHFAIL, 0,
    prep_pkcs1dec, inv_rsa_pkcs1_decrypt
};
static const fail_spec_t spec_rsa_pkcs1_encrypt = {
    arm2_encrypt, 0, HSK_OSSL4_SEAM_ENCRYPT,
    HSK_OSSL4_ERR_NATIVE, 0,
    prep_rsa_pub, inv_rsa_pkcs1_encrypt
};
static const fail_spec_t spec_oaep_encrypt = {
    arm2_encrypt, 0, HSK_OSSL4_SEAM_ENCRYPT,
    HSK_OSSL4_ERR_NATIVE, 0,
    prep_rsa_pub, inv_rsa_oaep_encrypt
};
static const fail_spec_t spec_rsa_raw = {
    arm2_pkey_sign, 0, HSK_OSSL4_SEAM_PKEY_SIGN,
    HSK_OSSL4_ERR_NATIVE, 0,
    prep_rsa_priv, inv_rsa_raw_sign
};
static const fail_spec_t spec_rsa_hash = {
    hsk_ossl4_test_seam_arm_digest_sign, 0, HSK_OSSL4_SEAM_DIGEST_SIGN,
    HSK_OSSL4_ERR_NATIVE, 0,
    prep_rsa_priv, inv_rsa_hash_sign
};
static const fail_spec_t spec_ecdsa_raw = {
    arm2_pkey_sign, 0, HSK_OSSL4_SEAM_PKEY_SIGN,
    HSK_OSSL4_ERR_NATIVE, 0,
    prep_ec, inv_ecdsa_raw
};
static const fail_spec_t spec_ecdsa_hash = {
    hsk_ossl4_test_seam_arm_digest_sign, 0, HSK_OSSL4_SEAM_DIGEST_SIGN,
    HSK_OSSL4_ERR_NATIVE, 0,
    prep_ec, inv_ecdsa_hash
};
static const fail_spec_t spec_dsa_raw = {
    arm2_pkey_sign, 0, HSK_OSSL4_SEAM_PKEY_SIGN,
    HSK_OSSL4_ERR_NATIVE, 0,
    prep_dsa_raw, inv_dsa_raw
};
static const fail_spec_t spec_dsa_hash = {
    hsk_ossl4_test_seam_arm_digest_sign, 0, HSK_OSSL4_SEAM_DIGEST_SIGN,
    HSK_OSSL4_ERR_NATIVE, 0,
    prep_dsa, inv_dsa_hash
};
static const fail_spec_t spec_eddsa = {
    hsk_ossl4_test_seam_arm_digest_sign, 0, HSK_OSSL4_SEAM_DIGEST_SIGN,
    HSK_OSSL4_ERR_NATIVE, 0,
    prep_ed25519, inv_eddsa
};
static const fail_spec_t spec_mldsa = {
    hsk_ossl4_test_seam_arm_digest_sign, 0, HSK_OSSL4_SEAM_DIGEST_SIGN,
    HSK_OSSL4_ERR_NATIVE, 0,
    prep_mldsa44, inv_mldsa
};
static const fail_spec_t spec_slhdsa = {
    hsk_ossl4_test_seam_arm_digest_sign, 0, HSK_OSSL4_SEAM_DIGEST_SIGN,
    HSK_OSSL4_ERR_NATIVE, 0,
    prep_slhdsa128s, inv_slhdsa
};
static const fail_spec_t spec_pss = {
    hsk_ossl4_test_seam_arm_digest_sign, 0, HSK_OSSL4_SEAM_DIGEST_SIGN,
    HSK_OSSL4_ERR_NATIVE, 0,
    prep_rsa_priv, inv_pss_sign
};
static const fail_spec_t spec_x931_prehash = {
    arm2_pkey_sign, 0, HSK_OSSL4_SEAM_PKEY_SIGN,
    HSK_OSSL4_ERR_NATIVE, 0,
    prep_x931_prehash, inv_x931_prehash
};
static const fail_spec_t spec_x931_digested = {
    hsk_ossl4_test_seam_arm_digest_sign, 0, HSK_OSSL4_SEAM_DIGEST_SIGN,
    HSK_OSSL4_ERR_NATIVE, 0,
    prep_rsa_priv, inv_x931_digested
};

#define FAIL_CASES(tag, spec)                                             \
    static void case_seam_##tag##_shrink(void)                             \
    {                                                                      \
        fail_case(&(spec), 0);                                            \
    }                                                                      \
    static void case_seam_##tag##_grow(void)                               \
    {                                                                      \
        fail_case(&(spec), 1);                                            \
    }

FAIL_CASES(oaep_fail, spec_oaep_decrypt)
FAIL_CASES(encrypt_fail, spec_rsa_pkcs1_encrypt)
FAIL_CASES(pkey_sign_fail, spec_rsa_raw)
FAIL_CASES(digest_sign_fail, spec_rsa_hash)
FAIL_CASES(ecdsa_raw_fail, spec_ecdsa_raw)
FAIL_CASES(ecdsa_hash_fail, spec_ecdsa_hash)
FAIL_CASES(dsa_raw_fail, spec_dsa_raw)
FAIL_CASES(dsa_hash_fail, spec_dsa_hash)
FAIL_CASES(eddsa_fail, spec_eddsa)
FAIL_CASES(mldsa_fail, spec_mldsa)
FAIL_CASES(slhdsa_fail, spec_slhdsa)
FAIL_CASES(pss_fail, spec_pss)
FAIL_CASES(x931_prehash_fail, spec_x931_prehash)
FAIL_CASES(x931_digested_fail, spec_x931_digested)
FAIL_CASES(oaep_encrypt_fail, spec_oaep_encrypt)
FAIL_CASES(pkcs1_decrypt_fail, spec_pkcs1_decrypt)

/* The ECDSA/DSA shared end block frees the DER buffer after a successful
 * output call on the want_raw path; the fail pairs above never reach it.
 * The succeed+shrink seam runs the real DigestSign and then shortens the
 * reported length by one, so the DER parse fails deterministically and
 * the end block frees a diverged length. */
static void ok_shrink_raw_case(int is_dsa)
{
    fail_keys_t keys;
    unsigned char *out = NULL;
    long (*invoke)(fail_keys_t *k, unsigned char **out);
    long before, rc;
    memset(&keys, 0, sizeof(keys));
    trk_quarantine = 1; /* unique addresses: one free per allocation */
    fill_fail_msgs();
    if (is_dsa) {
        REQ(prep_dsa(&keys), "keys");
        invoke = inv_dsa_hash_raw;
    } else {
        REQ(prep_ec(&keys), "keys");
        invoke = inv_ecdsa_hash_raw;
    }
    /* Warmup: an unarmed call populates the libctx caches before the
     * live mark. Drop the note the warmup recorded. */
    rc = invoke(&keys, &out);
    REQ(rc > 0 && out != NULL, "warmup");
    hsk_ossl4_free(out, (size_t)rc);
    out = NULL;
    hsk_ossl4_test_seam_reset();
    before = mark_live();
    if (!g_noarm)
        hsk_ossl4_test_seam_arm_digest_sign(-1, 1);
    rc = invoke(&keys, &out);
    seam_fired_check();
    REQ(*g_reason == 0, g_reason);
    REQ(rc == HSK_OSSL4_ERR_NATIVE, "rc-code");
    REQ(out == NULL, "out-set");
    check_target(HSK_OSSL4_SEAM_DIGEST_SIGN);
    REQ_LIVE(before);
    fail_keys_free(&keys);
}

static void case_seam_ecdsa_hash_raw_ok_shrink(void)
{
    ok_shrink_raw_case(0);
}

static void case_seam_dsa_hash_raw_ok_shrink(void)
{
    ok_shrink_raw_case(1);
}

/* The detector itself: a partly cleansed block and a one-byte overrun
 * must both be reported. */
static void case_canary_selftest(void)
{
    unsigned char *p = OPENSSL_malloc(48), *q = OPENSSL_malloc(16);
    size_t nz = 0;
    int ok = 1;
    long ret = 0;
    REQ(p != NULL && q != NULL, "alloc");
    memset(p, 0xAB, 48);
    trk_mark();
    hsk_ossl4_free(p, 47);
    REQ(trk_freed(p, 48, &nz, &ok) == 1, "p-not-logged");
    REQ(nz == 1, "p-nonzero-not-seen");
    g_nonzero = (long)nz;
    ((volatile unsigned char *)q)[16] = 0; /* one byte past the allocation, on purpose */
    OPENSSL_free(q);
    REQ(trk_freed(q, 16, &nz, &ok) == 1, "q-not-logged");
    REQ(!ok, "overrun-not-seen");
    ret = trk_canary_bad;
    REQ(ret == 1, "canary-count");
    trk_canary_bad = 0; /* the damage was the point of the case */
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
    { "prod-digest-cycle", case_prod_digest_cycle, 0, 0, 0 },
    { "prod-env-cycle", case_prod_env_cycle, 0, 0, 0 },
    { "prod-dh-kat", case_prod_dh_kat, 0, 0, 0 },
    { "prod-ecdh", case_prod_ecdh, 0, 0, 0 },
    { "prod-xdh", case_prod_xdh, 0, 0, 0 },
    { "prod-aead", case_prod_aead, 0, 0, 0 },
    { "neg-double-free", case_neg_double_free, 0, 0, 1 },
    { "neg-handle-double-free", case_neg_handle_double_free, 0, 0, 1 },
    { "neg-env-double-free", case_neg_env_double_free, 0, 0, 1 },
    { "neg-heap-overflow", case_neg_heap_overflow, 0, 0, 1 },
    { "neg-ubsan", case_neg_ubsan, 0, 0, 1 },
#ifdef HSK_OSSL4_TEST_HOOKS
    { "live-1000", case_live_1000, 1, 0, 0 },
    { "credit-gone", case_credit_gone, 1, 0, 0 },
    { "address-reuse", case_address_reuse, 1, 1, 0 },
    { "copy-fault", case_copy_fault, 1, 0, 0 },
    { "adoption-alloc", case_adoption_alloc, 1, 0, 0 },
    { "adoption-load", case_adoption_load, 1, 0, 0 },
    { "final-fault", case_final_fault, 1, 0, 0 },
    { "exit-gate", case_exit_gate, 1, 0, 1 },
    { "seam-bn-named", case_seam_bn_named, 1, 0, 0 },
    { "seam-bn-explicit", case_seam_bn_explicit, 1, 0, 0 },
    { "seam-derive-fail-shrink-ecdh", case_seam_fail_shrink_ecdh, 1, 0, 0 },
    { "seam-derive-fail-grow-ecdh", case_seam_fail_grow_ecdh, 1, 0, 0 },
    { "seam-derive-ok-shrink-ecdh", case_seam_ok_shrink_ecdh, 1, 0, 0 },
    { "seam-derive-ok-grow-ecdh", case_seam_ok_grow_ecdh, 1, 0, 0 },
    { "seam-derive-fail-shrink-xdh", case_seam_fail_shrink_xdh, 1, 0, 0 },
    { "seam-derive-fail-grow-xdh", case_seam_fail_grow_xdh, 1, 0, 0 },
    { "seam-derive-ok-shrink-xdh", case_seam_ok_shrink_xdh, 1, 0, 0 },
    { "seam-derive-ok-grow-xdh", case_seam_ok_grow_xdh, 1, 0, 0 },
    { "seam-derive-fail-shrink-dh", case_seam_fail_shrink_dh, 1, 0, 0 },
    { "seam-derive-fail-grow-dh", case_seam_fail_grow_dh, 1, 0, 0 },
    { "seam-derive-ok-shrink-dh", case_seam_ok_shrink_dh, 1, 0, 0 },
    { "seam-derive-ok-grow-dh", case_seam_ok_grow_dh, 1, 0, 0 },
    { "seam-oaep-fail-shrink", case_seam_oaep_fail_shrink, 1, 0, 0 },
    { "seam-oaep-fail-grow", case_seam_oaep_fail_grow, 1, 0, 0 },
    { "seam-encrypt-fail-shrink", case_seam_encrypt_fail_shrink, 1, 0, 0 },
    { "seam-encrypt-fail-grow", case_seam_encrypt_fail_grow, 1, 0, 0 },
    { "seam-pkey-sign-fail-shrink", case_seam_pkey_sign_fail_shrink, 1, 0, 0 },
    { "seam-pkey-sign-fail-grow", case_seam_pkey_sign_fail_grow, 1, 0, 0 },
    { "seam-digest-sign-fail-shrink", case_seam_digest_sign_fail_shrink, 1, 0, 0 },
    { "seam-digest-sign-fail-grow", case_seam_digest_sign_fail_grow, 1, 0, 0 },
    { "seam-ecdsa-raw-fail-shrink", case_seam_ecdsa_raw_fail_shrink, 1, 0, 0 },
    { "seam-ecdsa-raw-fail-grow", case_seam_ecdsa_raw_fail_grow, 1, 0, 0 },
    { "seam-ecdsa-hash-fail-shrink", case_seam_ecdsa_hash_fail_shrink, 1, 0, 0 },
    { "seam-ecdsa-hash-fail-grow", case_seam_ecdsa_hash_fail_grow, 1, 0, 0 },
    { "seam-dsa-raw-fail-shrink", case_seam_dsa_raw_fail_shrink, 1, 0, 0 },
    { "seam-dsa-raw-fail-grow", case_seam_dsa_raw_fail_grow, 1, 0, 0 },
    { "seam-dsa-hash-fail-shrink", case_seam_dsa_hash_fail_shrink, 1, 0, 0 },
    { "seam-dsa-hash-fail-grow", case_seam_dsa_hash_fail_grow, 1, 0, 0 },
    { "seam-eddsa-fail-shrink", case_seam_eddsa_fail_shrink, 1, 0, 0 },
    { "seam-eddsa-fail-grow", case_seam_eddsa_fail_grow, 1, 0, 0 },
    { "seam-mldsa-fail-shrink", case_seam_mldsa_fail_shrink, 1, 0, 0 },
    { "seam-mldsa-fail-grow", case_seam_mldsa_fail_grow, 1, 0, 0 },
    { "seam-slhdsa-fail-shrink", case_seam_slhdsa_fail_shrink, 1, 0, 0 },
    { "seam-slhdsa-fail-grow", case_seam_slhdsa_fail_grow, 1, 0, 0 },
    { "seam-pss-fail-shrink", case_seam_pss_fail_shrink, 1, 0, 0 },
    { "seam-pss-fail-grow", case_seam_pss_fail_grow, 1, 0, 0 },
    { "seam-x931-prehash-fail-shrink", case_seam_x931_prehash_fail_shrink, 1, 0, 0 },
    { "seam-x931-prehash-fail-grow", case_seam_x931_prehash_fail_grow, 1, 0, 0 },
    { "seam-x931-digested-fail-shrink", case_seam_x931_digested_fail_shrink, 1, 0, 0 },
    { "seam-x931-digested-fail-grow", case_seam_x931_digested_fail_grow, 1, 0, 0 },
    { "seam-oaep-encrypt-fail-shrink", case_seam_oaep_encrypt_fail_shrink, 1, 0, 0 },
    { "seam-oaep-encrypt-fail-grow", case_seam_oaep_encrypt_fail_grow, 1, 0, 0 },
    { "seam-pkcs1-decrypt-fail-shrink", case_seam_pkcs1_decrypt_fail_shrink, 1, 0, 0 },
    { "seam-pkcs1-decrypt-fail-grow", case_seam_pkcs1_decrypt_fail_grow, 1, 0, 0 },
    { "seam-ecdsa-hash-raw-ok-shrink", case_seam_ecdsa_hash_raw_ok_shrink, 1, 0, 0 },
    { "seam-dsa-hash-raw-ok-shrink", case_seam_dsa_hash_raw_ok_shrink, 1, 0, 0 },
    { "canary-selftest", case_canary_selftest, 1, 1, 0 },
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

    g_argc = argc;
    for (a = 1; a < argc; a++) {
        if (strcmp(argv[a], "--list") == 0) {
            for (i = 0; i < NCASES; i++)
                if (!cases[i].hidden)
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
