/* cbits/native_bindings.h — native output-contract primitives.
 *
 * The C side of the exact-output contract, mirroring
 * core/Haskoki/Output.hs: plan decisions (size-query/short/exact),
 * bounded writes that never go partial, checked conversions, and
 * nested IV writeback. Refusals return nonzero and touch nothing.
 */
#ifndef HASKOKI_NATIVE_BINDINGS_H
#define HASKOKI_NATIVE_BINDINGS_H

/* Planned outcome codes (mirror the CKR_* query/short/args slice). */
typedef enum {
  HASKOKI_OK = 0,
  HASKOKI_BUFFER_TOO_SMALL = 1,
  HASKOKI_ARGS_BAD = 2
} haskoki_rv;

/* One plan decision: the code, the required length to report, and
 * whether the caller should perform the write. */
typedef struct {
  haskoki_rv rv;
  unsigned long report;
  int do_write;
} haskoki_plan;

/* Decide one byte output: null queries, short buffers report the
 * required length without writing, sufficient buffers write. */
haskoki_plan haskoki_plan_output(int is_null, unsigned long capacity,
    unsigned long required);

/* Bounded copy: 0 on success, nonzero refusal without touching the
 * destination (short, or null pointers with a nonzero length).
 * A zero length with any pointers is a no-op success. */
int haskoki_write_bytes(unsigned char *dst, unsigned long cap,
    const unsigned char *src, unsigned long n);

/* Checked narrowing to 32 bits (the ILP32 CK_ULONG shape): 0 with
 * *out set, else nonzero with *out untouched. */
int haskoki_u32_from_u64(unsigned long long v, unsigned *out);

/* Checked unsigned-long addition: 0 with *out set, else nonzero
 * with *out untouched (wrap-around never hides a total). */
int haskoki_checked_total(unsigned long a, unsigned long b,
    unsigned long *out);

/* Simplified mechanism params carrying a fixed 16-byte IV slot. */
typedef struct {
  unsigned char iv[16];
  unsigned long iv_len;
} haskoki_gcm_params;

/* Nested IV writeback: exactly 16 bytes land in the params and
 * iv_len becomes 16. Anything else (nulls, wrong length) refuses
 * with the struct untouched. */
int haskoki_writeback_iv(haskoki_gcm_params *params,
    const unsigned char *iv, unsigned long iv_len);

#endif /* HASKOKI_NATIVE_BINDINGS_H */
