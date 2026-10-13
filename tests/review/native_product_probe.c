/* Remote-only, independent public PKCS#11 consumer. No provider private headers. */
#define _XOPEN_SOURCE 700
#include <dlfcn.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "pkcs11.h"
#include "native_product_vectors.h"

#define NATTR(a) ((CK_ULONG)(sizeof(a) / sizeof((a)[0])))
#define LOOPS 64
static CK_FUNCTION_LIST_PTR f;
static CK_SLOT_ID slot;
static int initialized;
static const char *mode;
static CK_BBOOL yes = CK_TRUE, no = CK_FALSE;
static CK_C_INITIALIZE_ARGS init_args;

static void rvlog(const char *what, CK_RV rv) {
    printf("CALL mode=%s op=%s rv=0x%08lx\n", mode, what, rv);
}
static int setup(const char *what, CK_RV rv) {
    rvlog(what, rv);
    if (rv == CKR_OK) return 0;
    printf("SETUP-FAIL mode=%s op=%s rv=0x%08lx (no bug proof)\n", mode, what, rv);
    return 2;
}
static int violation(const char *what) {
    printf("CANDIDATE mode=%s contract=%s\n", mode, what);
    return 1;
}
static CK_RV mutex_create(void **out) {
    pthread_mutex_t *m = malloc(sizeof(*m));
    if (m == NULL) return CKR_HOST_MEMORY;
    if (pthread_mutex_init(m, NULL) != 0) { free(m); return CKR_GENERAL_ERROR; }
    *out = m;
    return CKR_OK;
}
static CK_RV mutex_destroy(void *p) {
    if (p == NULL) return CKR_MUTEX_BAD;
    if (pthread_mutex_destroy(p) != 0) return CKR_GENERAL_ERROR;
    free(p);
    return CKR_OK;
}
static CK_RV mutex_lock(void *p) {
    if (p == NULL) return CKR_MUTEX_BAD;
    return pthread_mutex_lock(p) == 0 ? CKR_OK : CKR_GENERAL_ERROR;
}
static CK_RV mutex_unlock(void *p) {
    if (p == NULL) return CKR_MUTEX_BAD;
    return pthread_mutex_unlock(p) == 0 ? CKR_OK : CKR_GENERAL_ERROR;
}
static int initialize(void) {
    CK_RV rv = f->C_Initialize(&init_args);
    if (setup("C_Initialize", rv)) return 2;
    initialized = 1;
    return 0;
}
static int finalize(void) {
    CK_RV rv = f->C_Finalize(NULL);
    rvlog("C_Finalize", rv);
    if (rv == CKR_OK) initialized = 0;
    return rv == CKR_OK ? 0 : violation("finalize-after-joined-or-idle-sessions");
}
static int open_session(CK_SESSION_HANDLE *h) {
    return setup("C_OpenSession", f->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                                  NULL, NULL, h));
}
static int login(CK_SESSION_HANDLE h, CK_USER_TYPE role) {
    const char *pin = getenv(role == CKU_SO ? "HSK_REVIEW_SO_PIN" : "HSK_REVIEW_USER_PIN");
    if (pin == NULL) pin = role == CKU_SO ? "5678" : "1234";
    return setup(role == CKU_SO ? "C_Login(SO)" : "C_Login(user)",
                 f->C_Login(h, role, (CK_UTF8CHAR_PTR)pin, (CK_ULONG)strlen(pin)));
}
static int destroy(CK_SESSION_HANDLE h, CK_OBJECT_HANDLE o) {
    CK_RV rv = f->C_DestroyObject(h, o);
    rvlog("C_DestroyObject(cleanup)", rv);
    return rv == CKR_OK ? 0 : violation("cleanup-object-destroy");
}
static void hexlog(const char *name, const unsigned char *b, size_t n) {
    printf("VALUE mode=%s name=%s len=%zu hex=", mode, name, n);
    for (size_t i = 0; i < n; i++) printf("%02x", b[i]);
    putchar('\n');
}
static int derive_read(CK_SESSION_HANDLE h, CK_OBJECT_HANDLE key,
                       unsigned char *peer, CK_ULONG peer_len, unsigned char out[256]) {
    CK_MECHANISM mech = {CKM_DH_PKCS_DERIVE, peer, peer_len};
    CK_OBJECT_CLASS cls = CKO_SECRET_KEY;
    CK_KEY_TYPE kt = CKK_GENERIC_SECRET;
    CK_ULONG len = 256;
    CK_ATTRIBUTE attrs[] = {
        {CKA_CLASS, &cls, sizeof(cls)}, {CKA_KEY_TYPE, &kt, sizeof(kt)},
        {CKA_TOKEN, &no, sizeof(no)}, {CKA_PRIVATE, &no, sizeof(no)},
        {CKA_SENSITIVE, &no, sizeof(no)}, {CKA_EXTRACTABLE, &yes, sizeof(yes)},
        {CKA_VALUE_LEN, &len, sizeof(len)}
    };
    CK_OBJECT_HANDLE derived = CK_INVALID_HANDLE;
    if (setup("C_DeriveKey", f->C_DeriveKey(h, &mech, key, attrs, NATTR(attrs), &derived))) return 2;
    unsigned char guarded[288];
    memset(guarded, 0xa5, sizeof(guarded));
    CK_ATTRIBUTE value = {CKA_VALUE, guarded + 16, 256};
    CK_RV rv = f->C_GetAttributeValue(h, derived, &value, 1);
    int result = setup("C_GetAttributeValue(derived-value)", rv);
    if (result == 0 && value.ulValueLen != 256) result = violation("derived-secret-width-256");
    for (size_t i = 0; i < 16; i++) {
        if (guarded[i] != 0xa5 || guarded[272 + i] != 0xa5) result = violation("derived-output-canary");
    }
    if (result == 0) memcpy(out, guarded + 16, 256);
    int cleanup = destroy(h, derived);
    return result != 0 ? result : cleanup;
}
static int dh_collision(void) {
    CK_SESSION_HANDLE h;
    if (open_session(&h) || login(h, CKU_USER)) return 2;
    CK_OBJECT_CLASS cls = CKO_PRIVATE_KEY;
    CK_KEY_TYPE kt = CKK_DH;
    unsigned char x[] = {0x30, 0x39}, g = 2;
    CK_ATTRIBUTE attrs[] = {
        {CKA_CLASS, &cls, sizeof(cls)}, {CKA_KEY_TYPE, &kt, sizeof(kt)},
        {CKA_TOKEN, &no, sizeof(no)}, {CKA_PRIVATE, &yes, sizeof(yes)},
        {CKA_DERIVE, &yes, sizeof(yes)}, {CKA_SENSITIVE, &yes, sizeof(yes)},
        {CKA_EXTRACTABLE, &no, sizeof(no)},
        {CKA_PRIME, (void *)dh_prime, sizeof(dh_prime)},
        {CKA_BASE, &g, sizeof(g)}, {CKA_VALUE, x, sizeof(x)}
    };
    CK_OBJECT_HANDLE key;
    if (setup("C_CreateObject(DH-x12345)", f->C_CreateObject(h, attrs, NATTR(attrs), &key))) return 2;
    unsigned char peer[256] = {0}, control[256], actual[256];
    peer[15] = 240;
    peer[255] = 2;
    int rc = derive_read(h, key, &g, 1, control);
    if (rc == 0) {
        hexlog("peer2-control", control, 256);
        if (memcmp(control, dh_control, 256) != 0) {
            puts("SETUP-FAIL peer2 control does not match independent pow(2,12345,p); collision unproven");
            rc = 2;
        }
    }
    if (rc == 0) rc = derive_read(h, key, peer, sizeof(peer), actual);
    if (rc == 0) {
        hexlog("full-width-peer-result", actual, 256);
        hexlog("independent-full-width-expected", dh_expected, 256);
        if (memcmp(actual, dh_expected, 256) == 0) puts("PASS DH full native peer preserved");
        else if (memcmp(actual, control, 256) == 0) rc = violation("DH-full-width-native-peer-silently-substituted-with-two");
        else rc = violation("DH-result-mismatches-independent-modular-power");
    }
    int cleanup = destroy(h, key);
    return rc != 0 ? rc : cleanup;
}

static int derive_protection(void) {
    CK_SESSION_HANDLE h;
    if (open_session(&h) || login(h, CKU_USER)) return 2;
    CK_OBJECT_CLASS cls = CKO_SECRET_KEY;
    CK_KEY_TYPE kt = CKK_GENERIC_SECRET;
    unsigned char fixture[32];
    for (size_t i = 0; i < sizeof(fixture); i++) fixture[i] = (unsigned char)i;
    CK_ATTRIBUTE base_attrs[] = {
        {CKA_CLASS, &cls, sizeof(cls)}, {CKA_KEY_TYPE, &kt, sizeof(kt)},
        {CKA_TOKEN, &no, sizeof(no)}, {CKA_PRIVATE, &yes, sizeof(yes)},
        {CKA_DERIVE, &yes, sizeof(yes)}, {CKA_SENSITIVE, &yes, sizeof(yes)},
        {CKA_EXTRACTABLE, &no, sizeof(no)}, {CKA_VALUE, fixture, sizeof(fixture)}
    };
    CK_OBJECT_HANDLE base = CK_INVALID_HANDLE, derived = CK_INVALID_HANDLE;
    if (setup("create-sensitive-nonextractable-fixture", f->C_CreateObject(h, base_attrs, NATTR(base_attrs), &base))) return 2;
    unsigned char guarded[64];
    memset(guarded, 0xa5, sizeof(guarded));
    CK_ATTRIBUTE value = {CKA_VALUE, guarded + 16, sizeof(fixture)};
    CK_RV rv = f->C_GetAttributeValue(h, base, &value, 1);
    rvlog("base-CKA_VALUE-unreadability-control", rv);
    int rc = 0;
    if (rv == CKR_OK) { rc = violation("sensitive-nonextractable-base-value-readable"); goto cleanup; }
    if (rv != CKR_ATTRIBUTE_SENSITIVE) {
        rc = setup("base-unreadability-control-unexpected-refusal", rv); goto cleanup;
    }
    for (size_t i = 0; i < sizeof(guarded); i++) {
        if (guarded[i] != 0xa5) {
            rc = violation("base-value-buffer-written-on-sensitive-refusal"); goto cleanup;
        }
    }
    CK_ULONG length = sizeof(fixture);
    CK_EXTRACT_PARAMS offset = 0;
    CK_MECHANISM mech = {CKM_EXTRACT_KEY_FROM_KEY, &offset, sizeof(offset)};
    CK_ATTRIBUTE derived_attrs[] = {
        {CKA_CLASS, &cls, sizeof(cls)}, {CKA_KEY_TYPE, &kt, sizeof(kt)},
        {CKA_TOKEN, &no, sizeof(no)}, {CKA_PRIVATE, &yes, sizeof(yes)},
        {CKA_SENSITIVE, &no, sizeof(no)}, {CKA_EXTRACTABLE, &yes, sizeof(yes)},
        {CKA_VALUE_LEN, &length, sizeof(length)}
    };
    rv = f->C_DeriveKey(h, &mech, base, derived_attrs, NATTR(derived_attrs), &derived);
    rvlog("extract-offset-zero-full-length-with-downgrade-template", rv);
    if (rv == CKR_TEMPLATE_INCONSISTENT || rv == CKR_ATTRIBUTE_VALUE_INVALID || rv == CKR_KEY_FUNCTION_NOT_PERMITTED) {
        puts("PASS protection-downgrade-request-refused (template/policy refusal; no material disclosure)");
        derived = CK_INVALID_HANDLE;
        goto cleanup;
    }
    if (rv != CKR_OK) {
        derived = CK_INVALID_HANDLE;
        rc = setup("extract-derivation-unexpected-refusal", rv); goto cleanup;
    }
    CK_BBOOL sensitive = 0xa5, extractable = 0xa5;
    CK_ATTRIBUTE flags[] = {
        {CKA_SENSITIVE, &sensitive, sizeof(sensitive)},
        {CKA_EXTRACTABLE, &extractable, sizeof(extractable)}
    };
    if (setup("derived-protection-attributes", f->C_GetAttributeValue(h, derived, flags, NATTR(flags)))) {
        rc = 2; goto cleanup;
    }
    printf("OBSERVATION derived-sensitive=%u derived-extractable=%u\n", sensitive, extractable);
    if (flags[0].ulValueLen != sizeof(sensitive) || flags[1].ulValueLen != sizeof(extractable) ||
        sensitive != CK_TRUE || extractable != CK_FALSE) rc = violation("extract-derived-protection-inheritance-weakened");
    memset(guarded, 0xa5, sizeof(guarded));
    value.ulValueLen = sizeof(fixture);
    rv = f->C_GetAttributeValue(h, derived, &value, 1);
    rvlog("extracted-fixture-CKA_VALUE", rv);
    if (rv == CKR_OK) {
        if (value.ulValueLen == sizeof(fixture) && memcmp(guarded + 16, fixture, sizeof(fixture)) == 0)
            rc = violation("protected-base-entire-fixture-recovered-through-extraction");
        else rc = violation("protected-derived-value-readable-with-unexpected-bytes");
    } else if (rv != CKR_ATTRIBUTE_SENSITIVE) {
        int uncertain = setup("derived-value-unexpected-refusal", rv);
        if (rc == 0) rc = uncertain;
    } else {
        for (size_t i = 16; i < 48; i++) {
            if (guarded[i] != 0xa5) rc = violation("derived-value-buffer-written-on-sensitive-refusal");
        }
    }
    for (size_t i = 0; i < 16; i++) {
        if (guarded[i] != 0xa5 || guarded[48 + i] != 0xa5) rc = violation("extraction-output-canary");
    }
    if (rc == 0) puts("PASS extracted key retained sensitivity/nonextractability and value stayed unreadable");
cleanup:
    if (derived != CK_INVALID_HANDLE && destroy(h, derived) != 0 && rc == 0) rc = 1;
    if (destroy(h, base) != 0 && rc == 0) rc = 1;
    return rc;
}

static CK_RV create_data(CK_SESSION_HANDLE h, CK_BBOOL token, CK_BBOOL priv,
                         const char *label, CK_OBJECT_HANDLE *obj) {
    CK_OBJECT_CLASS cls = CKO_DATA;
    unsigned char value[] = "review-nonsecret-value";
    CK_ATTRIBUTE attrs[] = {
        {CKA_CLASS, &cls, sizeof(cls)}, {CKA_TOKEN, &token, sizeof(token)},
        {CKA_PRIVATE, &priv, sizeof(priv)},
        {CKA_LABEL, (void *)label, (CK_ULONG)strlen(label)},
        {CKA_VALUE, value, sizeof(value) - 1}
    };
    return f->C_CreateObject(h, attrs, NATTR(attrs), obj);
}
static int find_label(CK_SESSION_HANDLE h, const char *label, CK_OBJECT_HANDLE *obj,
                      CK_ULONG *count) {
    CK_ATTRIBUTE attr = {CKA_LABEL, (void *)label, (CK_ULONG)strlen(label)};
    if (setup("C_FindObjectsInit(exact-label)", f->C_FindObjectsInit(h, &attr, 1))) return 2;
    CK_OBJECT_HANDLE handles[4];
    *count = 0;
    CK_RV rv = f->C_FindObjects(h, handles, NATTR(handles), count);
    CK_RV final_rv = f->C_FindObjectsFinal(h);
    if (setup("C_FindObjects", rv) || setup("C_FindObjectsFinal", final_rv)) return 2;
    if (*count > 0) *obj = handles[0];
    printf("OBSERVATION mode=%s label=%s count=%lu\n", mode, label, *count);
    return 0;
}
static void label_for(char *out, size_t n, const char *kind) {
    (void)snprintf(out, n, "haskoki-review-%s-%s-%ld", mode, kind, (long)getpid());
}
static int private_logout(void) {
    CK_SESSION_HANDLE h;
    CK_OBJECT_HANDLE session_obj, token_obj, found = CK_INVALID_HANDLE;
    char slabel[128], tlabel[128];
    label_for(slabel, sizeof(slabel), "session");
    label_for(tlabel, sizeof(tlabel), "token");
    if (open_session(&h) || login(h, CKU_USER)) return 2;
    if (setup("create-private-session", create_data(h, no, yes, slabel, &session_obj))) return 2;
    if (setup("create-private-token", create_data(h, yes, yes, tlabel, &token_obj))) return 2;
    CK_ULONG count;
    if (find_label(h, slabel, &found, &count) || count != 1) return setup("session-control-count", CKR_FUNCTION_FAILED);
    if (find_label(h, tlabel, &found, &count) || count != 1) return setup("token-control-count", CKR_FUNCTION_FAILED);
    if (setup("C_Logout", f->C_Logout(h))) return 2;
    if (find_label(h, slabel, &found, &count)) return 2;
    int rc = count == 0 ? 0 : violation("private-session-visible-while-logged-out");
    if (find_label(h, tlabel, &found, &count)) return 2;
    if (count != 0) rc = violation("private-token-visible-while-logged-out");
    if (login(h, CKU_USER)) return 2;
    if (find_label(h, slabel, &found, &count)) return 2;
    if (count != 0) {
        rc = violation("private-session-object-resurrected-after-logout-login");
        (void)destroy(h, found);
    }
    if (find_label(h, tlabel, &found, &count)) return 2;
    if (count != 1) rc = violation("private-token-control-did-not-persist-through-logout");
    else if (destroy(h, found) != 0) rc = 1;
    if (rc == 0) puts("PASS private session removed at logout; private token persisted");
    return rc;
}
static int private_so(void) {
    CK_SESSION_HANDLE h;
    CK_OBJECT_HANDLE obj;
    char label[128];
    label_for(label, sizeof(label), "private");
    if (open_session(&h)) return 2;
    CK_RV rv = create_data(h, no, yes, label, &obj);
    rvlog("create-private-no-login", rv);
    int rc = 0;
    if (rv == CKR_OK) { rc = violation("public-session-created-private-object"); (void)destroy(h, obj); }
    else if (rv != CKR_USER_NOT_LOGGED_IN) return setup("no-login-control-unexpected-refusal", rv);
    if (setup("create-public-no-login", create_data(h, no, no, label, &obj))) return 2;
    if (destroy(h, obj) != 0) return 1;
    if (login(h, CKU_USER)) return 2;
    if (setup("create-private-user-control", create_data(h, no, yes, label, &obj))) return 2;
    if (destroy(h, obj) != 0) return 1;
    if (setup("C_Logout(user)", f->C_Logout(h)) || login(h, CKU_SO)) return 2;
    rv = create_data(h, no, yes, label, &obj);
    rvlog("create-private-SO", rv);
    if (rv == CKR_OK) rc = violation("SO-session-created-private-object");
    else if (rv != CKR_USER_NOT_LOGGED_IN) return setup("SO-unexpected-refusal", rv);
    /* SO-created private handles can themselves be invisible. Clean by finding as user. */
    if (setup("C_Logout(SO)", f->C_Logout(h)) || login(h, CKU_USER)) return 2;
    CK_ULONG count;
    if (find_label(h, label, &obj, &count)) return 2;
    if (count != 0 && destroy(h, obj) != 0) rc = 1;
    if (rc == 0) puts("PASS private-object-create requires user login; public and user controls succeeded");
    return rc;
}

struct gate {
    pthread_mutex_t lock;
    pthread_cond_t cond;
    unsigned ready;
    int release;
    int abort;
};
struct worker {
    unsigned id;
    CK_SESSION_HANDLE h;
    struct gate *gate;
    int failed;
    CK_RV rv;
    unsigned iteration;
    const char *failure;
};
static void *digest_worker(void *arg) {
    struct worker *w = arg;
    char input[80];
    int n = snprintf(input, sizeof(input), "haskoki-native-review-worker-%u", w->id);
    pthread_mutex_lock(&w->gate->lock);
    w->gate->ready++;
    pthread_cond_broadcast(&w->gate->cond);
    while (!w->gate->release) pthread_cond_wait(&w->gate->cond, &w->gate->lock);
    int abort = w->gate->abort;
    pthread_mutex_unlock(&w->gate->lock);
    if (abort) return NULL;
    for (unsigned i = 0; i < LOOPS; i++) {
        CK_MECHANISM mech = {CKM_SHA256, NULL, 0};
        unsigned char guarded[64];
        memset(guarded, 0xa5, sizeof(guarded));
        CK_ULONG len = 32;
        w->iteration = i;
        w->rv = f->C_DigestInit(w->h, &mech);
        w->failure = "C_DigestInit";
        if (w->rv == CKR_OK && (i % 2) == 0) {
            w->rv = f->C_Digest(w->h, (CK_BYTE_PTR)input, (CK_ULONG)n, guarded + 16, &len);
            w->failure = "C_Digest";
        } else if (w->rv == CKR_OK) {
            w->rv = f->C_DigestUpdate(w->h, (CK_BYTE_PTR)input, 7);
            w->failure = "C_DigestUpdate(first)";
            if (w->rv == CKR_OK) {
                w->rv = f->C_DigestUpdate(w->h, (CK_BYTE_PTR)input + 7, (CK_ULONG)n - 7);
                w->failure = "C_DigestUpdate(second)";
            }
            if (w->rv == CKR_OK) {
                w->rv = f->C_DigestFinal(w->h, guarded + 16, &len);
                w->failure = "C_DigestFinal";
            }
        }
        if (w->rv != CKR_OK) { w->failed = 1; break; }
        if (len != 32 || memcmp(guarded + 16, digest_expected[w->id], 32) != 0) {
            w->failed = 1; w->failure = "SHA256-full-byte-or-length-mismatch"; break;
        }
        for (size_t j = 0; j < 16; j++) {
            if (guarded[j] != 0xa5 || guarded[48 + j] != 0xa5) {
                w->failed = 1; w->failure = "digest-output-canary"; break;
            }
        }
        if (w->failed) break;
    }
    return NULL;
}
static int digest_batch(unsigned count) {
    pthread_t threads[8];
    struct worker workers[8];
    struct gate gate = {PTHREAD_MUTEX_INITIALIZER, PTHREAD_COND_INITIALIZER, 0, 0, 0};
    memset(workers, 0, sizeof(workers));
    unsigned opened = 0, started = 0;
    int rc = 0;
    for (unsigned i = 0; i < count; i++) {
        workers[i].id = i;
        workers[i].gate = &gate;
        if (open_session(&workers[i].h)) { rc = 2; break; }
        opened++;
    }
    if (rc == 0) {
        for (unsigned i = 0; i < count; i++) {
            if (pthread_create(&threads[i], NULL, digest_worker, &workers[i]) != 0) {
                puts("SETUP-FAIL pthread_create; aborting gate and joining started workers");
                rc = 2; break;
            }
            started++;
        }
    }
    pthread_mutex_lock(&gate.lock);
    while (gate.ready < started) pthread_cond_wait(&gate.cond, &gate.lock);
    gate.abort = rc != 0;
    gate.release = 1;
    printf("OBSERVATION mode=%s barrier-ready=%u requested=%u loops=%d\n", mode, gate.ready, count, LOOPS);
    pthread_cond_broadcast(&gate.cond);
    pthread_mutex_unlock(&gate.lock);
    for (unsigned i = 0; i < started; i++) {
        /* A failed join cannot safely be followed by finalization or dlclose. */
        if (pthread_join(threads[i], NULL) != 0) {
            puts("SETUP-FAIL pthread_join; exiting without teardown of possibly live workers");
            fflush(stdout);
            _Exit(2);
        }
        if (workers[i].failed) {
            printf("CANDIDATE mode=%s sessions=%u worker=%u iteration=%u op=%s rv=0x%08lx\n",
                   mode, count, i, workers[i].iteration, workers[i].failure, workers[i].rv);
            rc = 1;
        }
    }
    for (unsigned i = 0; i < opened; i++) {
        CK_RV rv = f->C_CloseSession(workers[i].h);
        if (rv != CKR_OK) { rvlog("C_CloseSession", rv); rc = violation("close-joined-worker-session"); }
    }
    pthread_cond_destroy(&gate.cond);
    pthread_mutex_destroy(&gate.lock);
    if (rc == 0) printf("PASS mode=%s sessions=%u operations=%u full-byte-SHA256-and-canaries\n", mode, count, count * LOOPS);
    return rc;
}
static int digests(void) {
    CK_MECHANISM_INFO info;
    if (setup("C_GetMechanismInfo(SHA256)", f->C_GetMechanismInfo(slot, CKM_SHA256, &info))) return 2;
    if ((info.flags & CKF_DIGEST) == 0) {
        puts("SETUP-FAIL SHA256 digest capability not advertised");
        return 2;
    }
    int rc = 0;
    for (unsigned count = 1; count <= 8; count *= 2) {
        int batch = digest_batch(count);
        if (batch != 0 && rc == 0) rc = batch;
        if (batch == 2) break;
    }
    return rc;
}

static int token_info(void) {
    CK_TOKEN_INFO info;
    if (setup("C_GetTokenInfo", f->C_GetTokenInfo(slot, &info))) return 2;
    printf("OBSERVATION token.flags=0x%08lx max-sessions=%lu sessions=%lu max-rw-sessions=%lu rw-sessions=%lu min-pin=%lu max-pin=%lu\n",
           info.flags, info.ulMaxSessionCount, info.ulSessionCount, info.ulMaxRwSessionCount,
           info.ulRwSessionCount, info.ulMinPinLen, info.ulMaxPinLen);
    return 0;
}
static int lifecycle(void) {
    for (unsigned i = 0; i < 4; i++) {
        if (token_info()) return 2;
        unsigned char label[32];
        memset(label, ' ', sizeof(label));
        rvlog("C_InitToken(disclosed-stub)", f->C_InitToken(slot, (CK_UTF8CHAR_PTR)"5678", 4, label));
        CK_SESSION_HANDLE h;
        if (open_session(&h)) return 2;
        rvlog("C_InitPIN(disclosed-stub)", f->C_InitPIN(h, (CK_UTF8CHAR_PTR)"1234", 4));
        rvlog("C_SetPIN(disclosed-stub)", f->C_SetPIN(h, (CK_UTF8CHAR_PTR)"1234", 4, (CK_UTF8CHAR_PTR)"1234", 4));
        printf("OBSERVATION cycle=%u finalize-with-still-open-idle-session=%lu\n", i, h);
        if (finalize()) return 1;
        CK_SESSION_INFO info;
        CK_RV rv = f->C_GetSessionInfo(h, &info);
        rvlog("C_GetSessionInfo(after-finalize)", rv);
        if (rv != CKR_CRYPTOKI_NOT_INITIALIZED) return violation("session-call-after-finalize");
        if (initialize()) return 2;
        rv = f->C_GetSessionInfo(h, &info);
        rvlog("C_GetSessionInfo(old-handle-after-reinitialize)", rv);
        if (rv != CKR_SESSION_HANDLE_INVALID) return violation("old-idle-session-survived-finalize");
    }
    puts("PASS repeated sameprocess idle-session finalize/reinitialize; disclosed provisioning returns are observations");
    return 0;
}
static int pin_reopen(void) {
    CK_SESSION_HANDLE h;
    if (open_session(&h)) return 2;
    CK_RV rv = CKR_OK;
    for (unsigned i = 0; i < 3; i++) {
        rv = f->C_Login(h, CKU_USER, (CK_UTF8CHAR_PTR)"review-deliberately-wrong-pin", 29);
        rvlog("C_Login(wrong-pin)", rv);
        if (rv != CKR_PIN_INCORRECT && rv != CKR_PIN_LOCKED) return setup("wrong-pin-control", rv == CKR_OK ? CKR_FUNCTION_FAILED : rv);
    }
    if (rv != CKR_PIN_LOCKED) {
        puts("SETUP-FAIL lockout not reached after three attempts; inspect configured lockout threshold");
        return 2;
    }
    if (token_info()) return 2;
    if (setup("C_CloseAllSessions", f->C_CloseAllSessions(slot))) return 2;
    if (finalize()) return 1;
    if (initialize() || open_session(&h) || token_info()) return 2;
    const char *pin = getenv("HSK_REVIEW_USER_PIN");
    if (pin == NULL) pin = "1234";
    rv = f->C_Login(h, CKU_USER, (CK_UTF8CHAR_PTR)pin, (CK_ULONG)strlen(pin));
    rvlog("C_Login(correct-pin-after-reinitialize)", rv);
    if (rv == CKR_OK) {
        puts("OBSERVATION pin-lockout-cleared-after-reinitialize; policy/storage assessment required, not standalone contract proof");
        return 0;
    }
    if (rv == CKR_PIN_LOCKED) {
        puts("OBSERVATION pin-lockout-retained-after-reinitialize");
        return 0;
    }
    return setup("correct-pin-after-reinitialize-unexpected-result", rv);
}
int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc != 3) {
        fprintf(stderr, "usage: %s MODULE {dh-collision|derive-protection|private-logout|private-so|digest-os|digest-app|lifecycle|token-info|pin-lockout-reopen}\n", argv[0]);
        return 2;
    }
    mode = argv[2];
    if (strcmp(mode, "dh-collision") && strcmp(mode, "private-logout") && strcmp(mode, "private-so") &&
        strcmp(mode, "digest-os") && strcmp(mode, "digest-app") && strcmp(mode, "lifecycle") &&
        strcmp(mode, "token-info") && strcmp(mode, "pin-lockout-reopen") && strcmp(mode, "derive-protection")) {
        fprintf(stderr, "SETUP-FAIL unknown mode %s\n", mode); return 2;
    }
    void *module = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (module == NULL) { fprintf(stderr, "SETUP-FAIL dlopen: %s\n", dlerror()); return 2; }
    CK_RV (*get_list)(CK_FUNCTION_LIST_PTR_PTR) = NULL;
    void *sym = dlsym(module, "C_GetFunctionList");
    _Static_assert(sizeof(sym) == sizeof(get_list), "POSIX function pointer size");
    memcpy(&get_list, &sym, sizeof(sym));
    if (get_list == NULL || setup("C_GetFunctionList", get_list(&f))) return 2;
    memset(&init_args, 0, sizeof(init_args));
    if (strcmp(mode, "digest-app") == 0) {
        init_args.CreateMutex = mutex_create;
        init_args.DestroyMutex = mutex_destroy;
        init_args.LockMutex = mutex_lock;
        init_args.UnlockMutex = mutex_unlock;
    } else init_args.flags = CKF_OS_LOCKING_OK;
    if (initialize()) return 2;
    CK_SLOT_ID slots[16];
    CK_ULONG count = NATTR(slots);
    int rc = setup("C_GetSlotList", f->C_GetSlotList(CK_TRUE, slots, &count));
    if (rc == 0 && count == 0) { puts("SETUP-FAIL no present token"); rc = 2; }
    if (rc == 0) {
        slot = slots[0];
        printf("OBSERVATION mode=%s slot=%lu module-version=%u.%u\n", mode, slot, f->version.major, f->version.minor);
        if (strcmp(mode, "dh-collision") == 0) rc = dh_collision();
        else if (strcmp(mode, "derive-protection") == 0) rc = derive_protection();
        else if (strcmp(mode, "private-logout") == 0) rc = private_logout();
        else if (strcmp(mode, "private-so") == 0) rc = private_so();
        else if (strcmp(mode, "lifecycle") == 0) rc = lifecycle();
        else if (strcmp(mode, "token-info") == 0) rc = token_info();
        else if (strcmp(mode, "pin-lockout-reopen") == 0) rc = pin_reopen();
        else rc = digests();
    }
    if (initialized) {
        int end_rc = finalize();
        if (rc == 0) rc = end_rc;
    }
    /* Haskoki owns a live process RTS: do not dlclose its code before exit. */
    printf("RESULT mode=%s status=%s exit=%d\n", mode, rc == 0 ? "PASS-OR-OBSERVATION" : rc == 1 ? "CANDIDATE" : "SETUP-FAIL", rc);
    return rc;
}
