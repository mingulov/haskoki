/* Haskoki USDT shim: Latchset-compatible crypto_auditing records plus
 * the private haskoki provider. Mirrors the OpenSSL 4.2 usdt.h shape
 * (extended array probes), adapted: emission always pairs
 * new_context_with_data with release_context in one call, because the
 * collector binds context identity to pid_tgid and Haskoki operations
 * can complete on a different thread than they started on.
 *
 * Build contract: define HSK_USDT (via the cabal `usdt` flag) to
 * compile probes in; <sys/sdt.h> must exist then (clear #error
 * otherwise). Without HSK_USDT every macro expands to nothing and
 * cbits/usdt.c is not compiled, so the off build has zero probe path.
 * No secret bytes may cross this interface: enums and metadata only.
 */
#ifndef HSK_USDT_H
#define HSK_USDT_H

#include <stdint.h>

#ifdef HSK_USDT

#if defined(__has_include)
#if __has_include(<sys/sdt.h>)
#include <sys/sdt.h>
#else
#error "HSK_USDT requires <sys/sdt.h> (systemtap-sdt-dev)"
#endif
#else
#include <sys/sdt.h>
#endif

/* Batched event element, matching struct crypto_auditing_data:
 * value_size -1 = NUL-terminated string, -2 = machine word by value,
 * else blob length. The reader accepts at most 15 elements (16 is
 * masked to 0 and rejected), so HSK_USDT_MAX_FIELDS is 8. */
typedef struct hsk_usdt_data_st {
    const char *key;
    const void *value;
    unsigned long value_size;
} HSK_USDT_DATA;

#define HSK_USDT_MAX_FIELDS 8

#define HSK_USDT_STRING(s) s, (unsigned long)-1
#define HSK_USDT_WORD(w) (void *)(intptr_t)(w), (unsigned long)-2

/* pk:: context names (0 omits; never emitted without a name). */
#define HSK_PK_NONE 0
#define HSK_PK_SIGN 1
#define HSK_PK_VERIFY 2
#define HSK_PK_ENCRYPT 3
#define HSK_PK_DECRYPT 4
#define HSK_PK_ENCAPSULATE 5
#define HSK_PK_DECAPSULATE 6
#define HSK_PK_GENERATE 7
#define HSK_PK_DERIVE 8

/* pk::algorithm values (0 omits the field). */
#define HSK_ALG_NONE 0
#define HSK_ALG_RSA 1
#define HSK_ALG_EC 2
#define HSK_ALG_DSA 3
#define HSK_ALG_DH 4
#define HSK_ALG_XDH 5
#define HSK_ALG_EDDSA 6
#define HSK_ALG_ML_DSA 7
#define HSK_ALG_ML_KEM 8
#define HSK_ALG_SLH_DSA 9

/* pk::curve values (0 omits the field). */
#define HSK_CURVE_NONE 0
#define HSK_CURVE_SECP256R1 1
#define HSK_CURVE_SECP384R1 2
#define HSK_CURVE_SECP521R1 3
#define HSK_CURVE_SECP256K1 4
#define HSK_CURVE_ED25519 5
#define HSK_CURVE_X25519 6
#define HSK_CURVE_ED448 7
#define HSK_CURVE_X448 8

/* pk::group values: RFC 3526 MODP groups (0 omits the field). */
#define HSK_GROUP_NONE 0
#define HSK_GROUP_MODP2048 1
#define HSK_GROUP_MODP3072 2
#define HSK_GROUP_MODP4096 3
#define HSK_GROUP_MODP6144 4
#define HSK_GROUP_MODP8192 5

/* pk::hash values (0 omits the field). */
#define HSK_HASH_NONE 0
#define HSK_HASH_MD5 1
#define HSK_HASH_SHA1 2
#define HSK_HASH_SHA224 3
#define HSK_HASH_SHA256 4
#define HSK_HASH_SHA384 5
#define HSK_HASH_SHA512 6
#define HSK_HASH_SHA3_224 7
#define HSK_HASH_SHA3_256 8
#define HSK_HASH_SHA3_384 9
#define HSK_HASH_SHA3_512 10

/* pk::rsa_padding values, registry spellings (0 omits the field). */
#define HSK_PAD_NONE 0
#define HSK_PAD_PSS 1
#define HSK_PAD_OAEP 2
#define HSK_PAD_PKCS1_V1_5 3

/* Orphan parent for parentless contexts (crau.h CRAU_ORPHANED_CONTEXT). */
#define HSK_USDT_ORPHAN ((long)-1)

/* Emit one Latchset record with a static field list (macro form, for
 * C-side and test use): new_context_with_data immediately followed
 * by release_context, same thread, no cross-call span. */
#define HSK_AUDIT_RECORD(context, name)                                      \
    do {                                                                     \
        HSK_USDT_DATA hsk_data_[] = { { "name", HSK_USDT_STRING(name) } };    \
        DTRACE_PROBE4(crypto_auditing, new_context_with_data,                \
            (long)(context), HSK_USDT_ORPHAN, hsk_data_,                     \
            sizeof(hsk_data_) / sizeof(hsk_data_[0]));                       \
        DTRACE_PROBE1(crypto_auditing, release_context, (long)(context));    \
    } while (0)

#define HSK_USDT_RELEASE(context) \
    DTRACE_PROBE1(crypto_auditing, release_context, (long)(context))

/* Private haskoki provider. All arguments are machine words; small
 * enums travel zero-extended (the readelf gate asserts 8-byte args).
 * Field order and widths are frozen by the 0.6.1 plan. */
#define HSK_HASKOKI_OPERATION_END(op, func, mech, mech_present, ckr, \
        disposition, mode)                                          \
    DTRACE_PROBE7(haskoki, operation_end, (unsigned long)(op),       \
        (unsigned long)(func), (unsigned long)(mech),                \
        (unsigned long)(mech_present), (unsigned long)(ckr),         \
        (unsigned long)(disposition), (unsigned long)(mode))

#define HSK_HASKOKI_POLICY_REJECT(op, op_valid, func, mech, mech_present, \
        reason, ckr)                                                     \
    DTRACE_PROBE7(haskoki, policy_reject, (unsigned long)(op),            \
        (unsigned long)(op_valid), (unsigned long)(func),                \
        (unsigned long)(mech), (unsigned long)(mech_present),            \
        (unsigned long)(reason), (unsigned long)(ckr))

#define HSK_HASKOKI_JOB_STATE(table, job, op, op_valid, phase, ckr, \
        ckr_valid)                                                 \
    DTRACE_PROBE7(haskoki, job_state, (unsigned long)(table),       \
        (unsigned long)(job), (unsigned long)(op),                  \
        (unsigned long)(op_valid), (unsigned long)(phase),          \
        (unsigned long)(ckr), (unsigned long)(ckr_valid))

/* FFI entry points (cbits/usdt.c, compiled only with HSK_USDT).
 * hsk_usdt_pk_record emits name + present fields (bits==0 omits)
 * then releases, all in this call. Enum 0 omits its field.
 * Op ids come from a C-owned atomic counter (no Haskell globals):
 * hsk_usdt_alloc_op returns the 1-based counter value, or 0 once
 * saturated (the caller skips emission); hsk_usdt_saturations
 * counts the saturated allocations. */
uint32_t hsk_usdt_alloc_op(void);
uint64_t hsk_usdt_saturations(void);
void hsk_usdt_pk_record(uint64_t op, uint32_t name, uint32_t alg,
    uint32_t curve, uint32_t group, uint64_t bits, uint32_t hash,
    uint32_t padding);
void hsk_usdt_operation_end(uint64_t op, uint32_t func, uint64_t mech,
    uint32_t mech_present, uint32_t ckr, uint32_t disposition,
    uint32_t mode);
void hsk_usdt_policy_reject(uint64_t op, uint32_t op_valid, uint32_t func,
    uint64_t mech, uint32_t mech_present, uint32_t reason, uint32_t ckr);
void hsk_usdt_job_state(uint32_t table, uint64_t job, uint64_t op,
    uint32_t op_valid, uint32_t phase, uint32_t ckr, uint32_t ckr_valid);

#else /* !HSK_USDT */

#define HSK_AUDIT_RECORD(context, name) do {} while (0)
#define HSK_USDT_RELEASE(context) do {} while (0)
#define HSK_HASKOKI_OPERATION_END(op, func, mech, mech_present, ckr, \
    disposition, mode) do {} while (0)
#define HSK_HASKOKI_POLICY_REJECT(op, op_valid, func, mech, mech_present, \
    reason, ckr) do {} while (0)
#define HSK_HASKOKI_JOB_STATE(table, job, op, op_valid, phase, ckr, \
    ckr_valid) do {} while (0)

#endif /* HSK_USDT */
#endif /* HSK_USDT_H */
