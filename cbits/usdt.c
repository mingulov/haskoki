/* Haskoki USDT shim implementation. See cbits/usdt.h for the contract.
 * Compiled only when HSK_USDT is defined (cabal `usdt` flag).
 * Allocation-free, callback-free, no blocking: safe under the GHC
 * single-capability RTS via `foreign import ccall unsafe`. */
#include "usdt.h"

#ifdef HSK_USDT
#include <stdatomic.h>

static _Atomic uint_fast32_t hsk_op_counter = 1;
static _Atomic uint_fast64_t hsk_op_saturations = 0;

uint32_t hsk_usdt_alloc_op(void)
{
    uint_fast32_t prev =
        atomic_fetch_add_explicit(&hsk_op_counter, 1, memory_order_relaxed);
    if (prev == 0 || prev >= UINT32_MAX) {
        atomic_fetch_add_explicit(&hsk_op_saturations, 1, memory_order_relaxed);
        return 0;
    }
    return (uint32_t)prev;
}

uint64_t hsk_usdt_saturations(void)
{
    return (uint64_t)atomic_load_explicit(&hsk_op_saturations,
        memory_order_relaxed);
}

static const char *const hsk_pk_names[] = {
    [HSK_PK_SIGN] = "pk::sign",
    [HSK_PK_VERIFY] = "pk::verify",
    [HSK_PK_ENCRYPT] = "pk::encrypt",
    [HSK_PK_DECRYPT] = "pk::decrypt",
    [HSK_PK_ENCAPSULATE] = "pk::encapsulate",
    [HSK_PK_DECAPSULATE] = "pk::decapsulate",
    [HSK_PK_GENERATE] = "pk::generate",
    [HSK_PK_DERIVE] = "pk::derive",
};

static const char *const hsk_algs[] = {
    [HSK_ALG_RSA] = "RSA",
    [HSK_ALG_EC] = "EC",
    [HSK_ALG_DSA] = "DSA",
    [HSK_ALG_DH] = "DH",
    [HSK_ALG_XDH] = "XDH",
    [HSK_ALG_EDDSA] = "EDDSA",
    [HSK_ALG_ML_DSA] = "ML-DSA",
    [HSK_ALG_ML_KEM] = "ML-KEM",
    [HSK_ALG_SLH_DSA] = "SLH-DSA",
};

static const char *const hsk_curves[] = {
    [HSK_CURVE_SECP256R1] = "secp256r1",
    [HSK_CURVE_SECP384R1] = "secp384r1",
    [HSK_CURVE_SECP521R1] = "secp521r1",
    [HSK_CURVE_SECP256K1] = "secp256k1",
    [HSK_CURVE_ED25519] = "ed25519",
    [HSK_CURVE_X25519] = "x25519",
    [HSK_CURVE_ED448] = "ed448",
    [HSK_CURVE_X448] = "x448",
};

static const char *const hsk_groups[] = {
    [HSK_GROUP_MODP2048] = "modp2048",
    [HSK_GROUP_MODP3072] = "modp3072",
    [HSK_GROUP_MODP4096] = "modp4096",
    [HSK_GROUP_MODP6144] = "modp6144",
    [HSK_GROUP_MODP8192] = "modp8192",
};

static const char *const hsk_hashes[] = {
    [HSK_HASH_MD5] = "MD5",
    [HSK_HASH_SHA1] = "SHA1",
    [HSK_HASH_SHA224] = "SHA224",
    [HSK_HASH_SHA256] = "SHA256",
    [HSK_HASH_SHA384] = "SHA384",
    [HSK_HASH_SHA512] = "SHA512",
    [HSK_HASH_SHA3_224] = "SHA3-224",
    [HSK_HASH_SHA3_256] = "SHA3-256",
    [HSK_HASH_SHA3_384] = "SHA3-384",
    [HSK_HASH_SHA3_512] = "SHA3-512",
};

static const char *const hsk_pads[] = {
    [HSK_PAD_PSS] = "pss",
    [HSK_PAD_OAEP] = "oaep",
    [HSK_PAD_PKCS1_V1_5] = "pkcs1-v1.5",
};

void hsk_usdt_pk_record(uint64_t op, uint32_t name, uint32_t alg,
    uint32_t curve, uint32_t group, uint64_t bits, uint32_t hash,
    uint32_t padding)
{
    HSK_USDT_DATA data[HSK_USDT_MAX_FIELDS];
    unsigned long n = 0;

    if (op == 0 || name == HSK_PK_NONE
        || name >= sizeof(hsk_pk_names) / sizeof(hsk_pk_names[0])
        || hsk_pk_names[name] == 0) {
        return;
    }
    data[n].key = "name";
    data[n].value = hsk_pk_names[name];
    data[n].value_size = (unsigned long)-1;
    n++;
    if (alg != HSK_ALG_NONE
        && alg < sizeof(hsk_algs) / sizeof(hsk_algs[0])
        && hsk_algs[alg] != 0) {
        data[n].key = "pk::algorithm";
        data[n].value = hsk_algs[alg];
        data[n].value_size = (unsigned long)-1;
        n++;
    }
    if (curve != HSK_CURVE_NONE
        && curve < sizeof(hsk_curves) / sizeof(hsk_curves[0])
        && hsk_curves[curve] != 0) {
        data[n].key = "pk::curve";
        data[n].value = hsk_curves[curve];
        data[n].value_size = (unsigned long)-1;
        n++;
    }
    if (group != HSK_GROUP_NONE
        && group < sizeof(hsk_groups) / sizeof(hsk_groups[0])
        && hsk_groups[group] != 0) {
        data[n].key = "pk::group";
        data[n].value = hsk_groups[group];
        data[n].value_size = (unsigned long)-1;
        n++;
    }
    if (bits != 0) {
        data[n].key = "pk::bits";
        data[n].value = (const void *)(uintptr_t)bits;
        data[n].value_size = (unsigned long)-2;
        n++;
    }
    if (hash != HSK_HASH_NONE
        && hash < sizeof(hsk_hashes) / sizeof(hsk_hashes[0])
        && hsk_hashes[hash] != 0) {
        data[n].key = "pk::hash";
        data[n].value = hsk_hashes[hash];
        data[n].value_size = (unsigned long)-1;
        n++;
    }
    if (padding != HSK_PAD_NONE
        && padding < sizeof(hsk_pads) / sizeof(hsk_pads[0])
        && hsk_pads[padding] != 0) {
        data[n].key = "pk::rsa_padding";
        data[n].value = hsk_pads[padding];
        data[n].value_size = (unsigned long)-1;
        n++;
    }
    DTRACE_PROBE4(crypto_auditing, new_context_with_data,
        (long)op, HSK_USDT_ORPHAN, data, n);
    DTRACE_PROBE1(crypto_auditing, release_context, (long)op);
}

void hsk_usdt_operation_end(uint64_t op, uint32_t func, uint64_t mech,
    uint32_t mech_present, uint32_t ckr, uint32_t disposition,
    uint32_t mode)
{
    HSK_HASKOKI_OPERATION_END(op, func, mech, mech_present, ckr,
        disposition, mode);
}

void hsk_usdt_policy_reject(uint64_t op, uint32_t op_valid, uint32_t func,
    uint64_t mech, uint32_t mech_present, uint32_t reason, uint32_t ckr)
{
    HSK_HASKOKI_POLICY_REJECT(op, op_valid, func, mech, mech_present,
        reason, ckr);
}

void hsk_usdt_job_state(uint32_t table, uint64_t job, uint64_t op,
    uint32_t op_valid, uint32_t phase, uint32_t ckr, uint32_t ckr_valid)
{
    HSK_HASKOKI_JOB_STATE(table, job, op, op_valid, phase, ckr,
        ckr_valid);
}

#endif /* HSK_USDT */
