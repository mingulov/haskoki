/* cbits/standard_surface.h — standard-surface integrator API.
 *
 * The per-init-interval standard-surface instance (a StablePtr from
 * Haskoki.FFI.Standard): installed by C_Initialize, uninstalled by
 * C_Finalize, resolved by every routed table body through
 * haskoki_std_get() (the control instance-root precedent in
 * cbits/control_entry.c). The handle is a plain pointer here;
 * Haskell manages its lifetime.
 *
 * Also the template-frame packer: caller CK_ATTRIBUTE arrays become
 * the flat frames Haskoki.FFI.Standard.parseTemplateFrame decodes
 * (count:u64le, then per attribute type:u64le, len:u64le,
 * value:len bytes). The packer signature is Cryptoki-type-free so
 * this header stays includable from both the mirror TU
 * (cbits/function_tables.c) and the pinned-header TU
 * (cbits/standard_surface.c); both spellings are ABI-identical
 * (unsigned long + pointers on LP64).
 *
 * Discipline: this header includes only <stdint.h>. It never takes
 * the legacy state lock (callers hold it across pack + call).
 */
#ifndef HASKOKI_STANDARD_SURFACE_H
#define HASKOKI_STANDARD_SURFACE_H

#include <stdint.h>

/* Bound on attributes per template frame (mirrors
 * Haskoki.FFI.Standard.maxTemplateAttrs; both sides enforce it). */
#define HASKOKI_STD_TEMPLATE_MAX_ATTRS 64UL

void *haskoki_std_open_fresh(void);
void haskoki_std_install(void *instance);
void *haskoki_std_get(void);
void haskoki_std_shutdown(void);

/* Pack a caller template into a flat frame. tmpl is a
 * CK_ATTRIBUTE_PTR in the caller's spelling (NULL iff count is 0).
 * Returns 0 with (*out, *out_len) holding a malloc'd frame the
 * caller frees; returns nonzero (arguments bad) with outputs
 * untouched on: NULL out-words, count past the bound, NULL array
 * with nonzero count, NULL value with nonzero length, any value
 * past 16 MiB, or a frame total past the 16 MiB input bound plus
 * record headers. */
int haskoki_std_pack_template(const void *tmpl, unsigned long count,
                              uint8_t **out, uint64_t *out_len);

#endif /* HASKOKI_STANDARD_SURFACE_H */
