/* cbits/abi_probe.h - shared helpers for ABI probes and version checks.
 *
 * This header has two sections:
 *   1. SHARED probe helpers (canaries, version matching): used both by the
 *      provider (cbits/exports.c) and by the independent C probes, which
 *      compile cbits/abi_probe.c from source against their own pinned
 *      headers. The shared section depends only on the C library.
 *   2. PROVIDER-INTERNAL legacy<->versioned wiring (opaque function-pointer produce
 *      /consume API plus liveness): used only inside libhaskoki.so.
 *      Probes never call these (they exercise only public C_ symbols).
 */
#ifndef HASKOKI_ABI_PROBE_H
#define HASKOKI_ABI_PROBE_H

#include <stddef.h>

/* ---------- 1. Shared probe helpers ---------- */

/* Guard bytes placed around caller buffers by probes. */
#define HASKOKI_CANARY_LEN 16
#define HASKOKI_CANARY_BYTE 0xA5

void haskoki_canary_fill(unsigned char *buf, size_t len);
/* Returns 1 when all len bytes still hold the canary pattern, else 0. */
int haskoki_canary_check(const unsigned char *buf, size_t len);

/* Compare (major, minor) version pairs. Returns 1 when equal. */
int haskoki_version_eq(unsigned major_a, unsigned minor_a, unsigned major_b,
                       unsigned minor_b);
/* Returns 1 for exactly the four shipped interfaces. */
int haskoki_version_supported(unsigned major, unsigned minor);

/* Bounded NUL-terminated string match: returns 1 when s (scanned at most
 * max bytes, NUL required) equals want. Returns 0 on mismatch or when no
 * NUL appears within max bytes (never over-reads). */
int haskoki_str_eq_bounded(const char *s, const char *want, size_t max);

/* ---------- 2. Provider-internal legacy<->versioned wiring ---------- */

/* Opaque provider function pointer: the mirror TU publishes legacy implementations
 * through this type and exports.c re-homes them into the versioned tables.
 * Conversions to/from concrete CK_C_* pointer types round-trip exactly;
 * nothing is ever CALLED through this type. Using void(*)(void) keeps this
 * header free of Cryptoki types so both the mirror TU and the pinned
 * header TU can share it. */
typedef void (*haskoki_fn_t)(void);

/* Number of legacy (2.40) function pointers, in generated order. */
size_t haskoki_legacy_fn_count(void);
/* Copy up to n legacy function pointers (generated 2.40 order) into out.
 * Returns the total available (HASKOKI_ABI_COUNT_240), or 0 on failure. */
size_t haskoki_legacy_fns(haskoki_fn_t *out, size_t n);
/* True when a provider interval is live in this process image (includes the
 * fork-child guard). Implemented by cbits/function_tables.c. */
int haskoki_live_interval(void);

#endif /* HASKOKI_ABI_PROBE_H */
