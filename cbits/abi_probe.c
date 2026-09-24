/* cbits/abi_probe.c - shared probe helpers.
 *
 * Implements section 1 of abi_probe.h. Deliberately self-contained (C
 * library only, no provider state, no Cryptoki types): the provider links
 * it into libhaskoki.so AND each independent probe compiles this same file
 * from source against its own pinned headers.
 */

#include "abi_probe.h"

void haskoki_canary_fill(unsigned char *buf, size_t len) {
  size_t i;
  if (buf == 0) {
    return;
  }
  for (i = 0; i < len; i++) {
    buf[i] = HASKOKI_CANARY_BYTE;
  }
}

int haskoki_canary_check(const unsigned char *buf, size_t len) {
  size_t i;
  if (buf == 0) {
    return 0;
  }
  for (i = 0; i < len; i++) {
    if (buf[i] != HASKOKI_CANARY_BYTE) {
      return 0;
    }
  }
  return 1;
}

int haskoki_version_eq(unsigned major_a, unsigned minor_a, unsigned major_b,
                       unsigned minor_b) {
  return major_a == major_b && minor_a == minor_b;
}

int haskoki_version_supported(unsigned major, unsigned minor) {
  return (major == 2 && minor == 40) || (major == 3 && minor == 0) ||
         (major == 3 && minor == 1) || (major == 3 && minor == 2);
}

int haskoki_str_eq_bounded(const char *s, const char *want, size_t max) {
  size_t i;
  if (s == 0 || want == 0) {
    return 0;
  }
  for (i = 0; i < max; i++) {
    if (s[i] != want[i]) {
      return 0;
    }
    if (s[i] == '\0') {
      return 1;
    }
  }
  return 0;
}
