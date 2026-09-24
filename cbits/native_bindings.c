/* cbits/native_bindings.c — native output-contract primitives.
 *
 * Implements native_bindings.h. Every refusal path is total: it
 * returns nonzero having written nothing, so canary-guarded callers
 * can prove untouched buffers.
 */

#include "native_bindings.h"

#include <limits.h>
#include <stddef.h>
#include <string.h>

haskoki_plan haskoki_plan_output(int is_null, unsigned long capacity,
    unsigned long required) {
  haskoki_plan plan;
  plan.report = required;
  if (is_null) {
    plan.rv = HASKOKI_OK;
    plan.do_write = 0;
    return plan;
  }
  if (capacity < required) {
    plan.rv = HASKOKI_BUFFER_TOO_SMALL;
    plan.do_write = 0;
    return plan;
  }
  plan.rv = HASKOKI_OK;
  plan.do_write = 1;
  return plan;
}

int haskoki_write_bytes(unsigned char *dst, unsigned long cap,
    const unsigned char *src, unsigned long n) {
  if (n > cap) {
    return 1;
  }
  if (n == 0) {
    return 0;
  }
  if (dst == NULL || src == NULL) {
    return 1;
  }
  memcpy(dst, src, (size_t)n);
  return 0;
}

int haskoki_u32_from_u64(unsigned long long v, unsigned *out) {
  if (out == NULL) {
    return 1;
  }
  if (v > (unsigned long long)UINT_MAX) {
    return 1;
  }
  *out = (unsigned)v;
  return 0;
}

int haskoki_checked_total(unsigned long a, unsigned long b,
    unsigned long *out) {
  unsigned long sum;
  if (out == NULL) {
    return 1;
  }
  sum = a + b;
  if (sum < a) {
    return 1;
  }
  *out = sum;
  return 0;
}

int haskoki_writeback_iv(haskoki_gcm_params *params,
    const unsigned char *iv, unsigned long iv_len) {
  if (params == NULL || iv == NULL) {
    return 1;
  }
  if (iv_len != sizeof(params->iv)) {
    return 1;
  }
  memcpy(params->iv, iv, sizeof(params->iv));
  params->iv_len = (unsigned long)sizeof(params->iv);
  return 0;
}
