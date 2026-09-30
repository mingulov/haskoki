/* cbits/standard_surface.c — standard-surface integrator.
 *
 * Owns the per-init-interval standard-surface instance handle (a
 * StablePtr from Haskoki.FFI.Standard): installed by C_Initialize,
 * uninstalled by C_Finalize. Every routed table body resolves the
 * SAME handle through haskoki_std_get(), so all standard calls in
 * one process share one Env, one backend, and one store binding.
 *
 * Also the template-frame packer (haskoki_std_pack_template) and
 * the routed table bodies (on_*), which run under the
 * caller's C state lock with the Haskell side owning all instance
 * synchronization (the control-entry precedent: this TU never takes the
 * legacy state lock itself).
 *
 * This TU includes the pinned 3.2 headers (real CK_ATTRIBUTE field
 * layout for the packer, CKF_* macros for the mechanism/info
 * and token/slot records). Cross-TU function bodies bridge to the
 * mirror TU (cbits/function_tables.c) by name with
 * ABI-identical signatures (unsigned long + pointers on LP64);
 * the compiler checks each TU separately, as with the
 * re-homing casts in cbits/exports.c.
 */

#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CK_PTR *
#define CK_DECLARE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType (*name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType (*name)
/* NULL_PTR comes from the vendored PD header (always defined). */
#include "pkcs11.h"

#include "abi_probe.h"
#include "mech_catalog.inc"
#include "standard_surface.h"

/* Haskell instance exports (ffi/Haskoki/FFI/Standard.hs). Prefer
 * the GHC-generated stub header when available; else the manual
 * declarations below (HsPtr shape). */
#if defined(__has_include)
#if __has_include("Haskoki/FFI/Standard_stub.h")
#include "Haskoki/FFI/Standard_stub.h"
#define HASKOKI_HAVE_STD_STUB_H 1
#elif __has_include("Haskoki_FFI_Standard_stub.h")
#include "Haskoki_FFI_Standard_stub.h"
#define HASKOKI_HAVE_STD_STUB_H 1
#endif
#endif
#ifndef HASKOKI_HAVE_STD_STUB_H
#include <stdint.h>
extern void *haskoki_std_open(void);
extern void haskoki_std_close(void *instance);
extern uint64_t haskoki_std_terminate_slot(void *instance, uint64_t h_session,
                                               uint64_t slot);
extern uint64_t haskoki_std_get_slot_list(void *instance, uint8_t token_present,
                                          uint64_t *p_slot_list,
                                          uint64_t *p_count);
extern uint64_t haskoki_std_open_session(void *instance, uint64_t slot,
                                         uint64_t read_only,
                                         uint64_t *ph_session);
extern uint64_t haskoki_std_close_session(void *instance, uint64_t h_session);
extern uint64_t haskoki_std_close_all_sessions(void *instance, uint64_t slot);
extern uint64_t haskoki_std_session_cancel(void *instance, uint64_t h_session,
                                           uint64_t flags);
extern uint64_t haskoki_std_get_session_info(void *instance, uint64_t h_session,
                                             uint64_t *p_slot, uint64_t *p_ro,
                                             uint64_t *p_login,
                                             uint64_t *p_deverr);
extern uint64_t haskoki_std_token_live(void *instance, uint64_t slot,
                                       uint64_t *p_sess, uint64_t *p_rw,
                                       uint64_t *p_ulock, uint64_t *p_slock,
                                       uint64_t *p_urem, uint64_t *p_srem);
extern uint64_t haskoki_std_token_label(void *instance, uint64_t slot,
                                        uint8_t *p_label32);
extern uint64_t haskoki_std_slot_present(void *instance, uint64_t slot);
extern uint64_t haskoki_std_create_object(void *instance, uint64_t h_session,
                                          uint8_t *p_frame, uint64_t frame_len,
                                          uint64_t *ph_object);
extern uint64_t haskoki_std_copy_object(void *instance, uint64_t h_session,
                                        uint64_t h_object, uint8_t *p_frame,
                                        uint64_t frame_len, uint64_t *ph_new);
extern uint64_t haskoki_std_set_attribute_value(void *instance,
                                                uint64_t h_session,
                                                uint64_t h_object,
                                                uint8_t *p_frame,
                                                uint64_t frame_len);
extern uint64_t haskoki_std_destroy_object(void *instance, uint64_t h_session,
                                           uint64_t h_object);
extern uint64_t haskoki_std_get_one_attr(void *instance, uint64_t h_session,
                                         uint64_t h_object, uint64_t cka_id,
                                         uint8_t *p_value, uint64_t *p_len);
extern uint64_t haskoki_std_find_init(void *instance, uint64_t h_session,
                                      uint8_t *p_frame, uint64_t frame_len);
extern uint64_t haskoki_std_find(void *instance, uint64_t h_session,
                                 uint64_t max_count, uint64_t *p_handles,
                                 uint64_t *p_count);
extern uint64_t haskoki_std_find_final(void *instance, uint64_t h_session);
extern uint64_t haskoki_std_login(void *instance, uint64_t h_session,
                                  uint64_t user_type, uint8_t *p_pin,
                                  uint64_t pin_len);
extern uint64_t haskoki_std_logout(void *instance, uint64_t h_session);
extern uint64_t haskoki_std_digest_init(void *instance, uint64_t h_session,
                                        uint64_t mechanism, uint8_t *p_params,
                                        uint64_t params_len);
extern uint64_t haskoki_std_digest(void *instance, uint64_t h_session,
                                   uint8_t *p_data, uint64_t data_len,
                                   uint8_t *p_out, uint64_t *p_len);
extern uint64_t haskoki_std_digest_update(void *instance, uint64_t h_session,
                                          uint8_t *p_data, uint64_t data_len);
extern uint64_t haskoki_std_digest_key(void *instance, uint64_t h_session,
                                       uint64_t h_key);
extern uint64_t haskoki_std_digest_final(void *instance, uint64_t h_session,
                                         uint8_t *p_out, uint64_t *p_len);
extern uint64_t haskoki_std_generate_key(void *instance, uint64_t h_session,
                                         uint64_t mechanism, uint8_t *p_frame,
                                         uint64_t frame_len, uint8_t *p_params,
                                         uint64_t params_len, uint64_t *ph_key);
extern uint64_t haskoki_std_generate_key_pair(void *instance, uint64_t h_session,
                                              uint64_t mechanism,
                                              uint8_t *p_pub_frame,
                                              uint64_t pub_len,
                                              uint8_t *p_priv_frame,
                                              uint64_t priv_len,
                                              uint64_t *ph_pub,
                                              uint64_t *ph_priv);
extern uint64_t haskoki_std_sign_init(void *instance, uint64_t h_session,
                                      uint64_t mechanism, uint8_t *p_params,
                                      uint64_t params_len, uint64_t h_key);
extern uint64_t haskoki_std_sign(void *instance, uint64_t h_session,
                                 uint8_t *p_data, uint64_t data_len,
                                 uint8_t *p_sig, uint64_t *p_len);
extern uint64_t haskoki_std_sign_update(void *instance, uint64_t h_session,
                                        uint8_t *p_part, uint64_t part_len);
extern uint64_t haskoki_std_sign_final(void *instance, uint64_t h_session,
                                       uint8_t *p_sig, uint64_t *p_len);
extern uint64_t haskoki_std_verify_init(void *instance, uint64_t h_session,
                                        uint64_t mechanism, uint8_t *p_params,
                                        uint64_t params_len, uint64_t h_key);
extern uint64_t haskoki_std_verify(void *instance, uint64_t h_session,
                                   uint8_t *p_data, uint64_t data_len,
                                   uint8_t *p_sig, uint64_t sig_len);
extern uint64_t haskoki_std_verify_update(void *instance, uint64_t h_session,
                                          uint8_t *p_part, uint64_t part_len);
extern uint64_t haskoki_std_verify_final(void *instance, uint64_t h_session,
                                         uint8_t *p_sig, uint64_t sig_len);
extern uint64_t haskoki_std_encrypt_init(void *instance, uint64_t h_session,
                                         uint64_t mechanism, uint8_t *p_params,
                                         uint64_t params_len, uint64_t h_key);
extern uint64_t haskoki_std_encrypt(void *instance, uint64_t h_session,
                                    uint8_t *p_data, uint64_t data_len,
                                    uint8_t *p_out, uint64_t *p_len);
extern uint64_t haskoki_std_encrypt_update(void *instance, uint64_t h_session,
                                           uint8_t *p_part, uint64_t part_len,
                                           uint8_t *p_out, uint64_t *p_len);
extern uint64_t haskoki_std_encrypt_final(void *instance, uint64_t h_session,
                                          uint8_t *p_out, uint64_t *p_len);
extern uint64_t haskoki_std_decrypt_init(void *instance, uint64_t h_session,
                                         uint64_t mechanism, uint8_t *p_params,
                                         uint64_t params_len, uint64_t h_key);
extern uint64_t haskoki_std_decrypt(void *instance, uint64_t h_session,
                                    uint8_t *p_data, uint64_t data_len,
                                    uint8_t *p_out, uint64_t *p_len);
extern uint64_t haskoki_std_decrypt_update(void *instance, uint64_t h_session,
                                           uint8_t *p_part, uint64_t part_len,
                                           uint8_t *p_out, uint64_t *p_len);
extern uint64_t haskoki_std_decrypt_final(void *instance, uint64_t h_session,
                                          uint8_t *p_out, uint64_t *p_len);
extern uint64_t haskoki_std_generate_random(void *instance, uint64_t h_session,
                                            uint8_t *p_out, uint64_t out_len);
extern uint64_t haskoki_std_seed_random(void *instance, uint64_t h_session,
                                        uint8_t *p_seed, uint64_t seed_len);
extern uint64_t haskoki_std_wrap_key(void *instance, uint64_t h_session,
                                     uint64_t mechanism, uint8_t *p_iv,
                                     uint64_t iv_len, uint64_t h_wrap,
                                     uint64_t h_target, uint8_t *p_out,
                                     uint64_t *p_len);
extern uint64_t haskoki_std_unwrap_key(void *instance, uint64_t h_session,
                                       uint64_t mechanism, uint8_t *p_iv,
                                       uint64_t iv_len, uint64_t h_wrap,
                                       uint8_t *p_blob, uint64_t blob_len,
                                       uint8_t *p_frame, uint64_t frame_len,
                                       uint64_t *ph_key);
extern uint64_t haskoki_std_derive_hkdf(void *instance, uint64_t h_session,
                                        uint64_t mechanism,
                                        uint8_t *p_info, uint64_t info_len,
                                        uint8_t *p_salt, uint64_t salt_len,
                                        uint64_t hkdf_mode, uint64_t hkdf_prf,
                                        uint64_t h_base, uint8_t *p_frame,
                                        uint64_t frame_len, uint64_t *ph_key);
extern uint64_t haskoki_std_derive_opaque(void *instance, uint64_t h_session,
                                          uint64_t mechanism, uint8_t *p_params,
                                          uint64_t params_len, uint64_t h_base,
                                          uint8_t *p_frame, uint64_t frame_len,
                                          uint64_t *ph_key);
extern uint64_t haskoki_std_encapsulate_key(void *instance, uint64_t h_session,
                                            uint64_t mechanism, uint8_t *p_params,
                                            uint64_t params_len, uint64_t h_key,
                                            uint8_t *p_frame, uint64_t frame_len,
                                            uint8_t *p_out, uint64_t *p_len,
                                            uint64_t *ph_key);
extern uint64_t haskoki_std_decapsulate_key(void *instance, uint64_t h_session,
                                            uint64_t mechanism, uint8_t *p_params,
                                            uint64_t params_len, uint64_t h_key,
                                            uint8_t *p_ct, uint64_t ct_len,
                                            uint8_t *p_frame, uint64_t frame_len,
                                            uint64_t *ph_key);

unsigned long haskoki_std_message_encrypt_init(void *ctx, unsigned long session,
    unsigned long mechanism, unsigned char *params, unsigned long paramsLen,
    unsigned long key);
unsigned long haskoki_std_message_encrypt(void *ctx, unsigned long session,
    unsigned char *params, unsigned long paramsLen,
    unsigned char *aad, unsigned long aadLen,
    unsigned char *input, unsigned long inputLen,
    unsigned char *output, unsigned long *outputLen);
unsigned long haskoki_std_message_encrypt_begin(void *ctx, unsigned long session,
    unsigned char *params, unsigned long paramsLen,
    unsigned char *aad, unsigned long aadLen);
unsigned long haskoki_std_message_encrypt_next(void *ctx, unsigned long session,
    unsigned char *params, unsigned long paramsLen,
    unsigned char *part, unsigned long partLen,
    unsigned char *output, unsigned long *outputLen, unsigned long end);
unsigned long haskoki_std_message_encrypt_final(void *ctx, unsigned long session);

unsigned long haskoki_std_message_decrypt_init(void *ctx, unsigned long session,
    unsigned long mechanism, unsigned char *params, unsigned long paramsLen,
    unsigned long key);
unsigned long haskoki_std_message_decrypt(void *ctx, unsigned long session,
    unsigned char *params, unsigned long paramsLen,
    unsigned char *aad, unsigned long aadLen,
    unsigned char *input, unsigned long inputLen,
    unsigned char *output, unsigned long *outputLen);
unsigned long haskoki_std_message_decrypt_begin(void *ctx, unsigned long session,
    unsigned char *params, unsigned long paramsLen,
    unsigned char *aad, unsigned long aadLen);
unsigned long haskoki_std_message_decrypt_next(void *ctx, unsigned long session,
    unsigned char *params, unsigned long paramsLen,
    unsigned char *part, unsigned long partLen,
    unsigned char *output, unsigned long *outputLen, unsigned long end);
unsigned long haskoki_std_message_decrypt_final(void *ctx, unsigned long session);

unsigned long haskoki_std_message_sign_init(void *ctx, unsigned long session,
    unsigned long mechanism, unsigned char *params, unsigned long paramsLen,
    unsigned long key);
unsigned long haskoki_std_message_sign(void *ctx, unsigned long session,
    unsigned char *params, unsigned long paramsLen,
    unsigned char *input, unsigned long inputLen,
    unsigned char *signature, unsigned long *signatureLen);
unsigned long haskoki_std_message_sign_begin(void *ctx, unsigned long session,
    unsigned char *params, unsigned long paramsLen);
unsigned long haskoki_std_message_sign_next(void *ctx, unsigned long session,
    unsigned char *params, unsigned long paramsLen,
    unsigned char *part, unsigned long partLen,
    unsigned char *signature, unsigned long *signatureLen);
unsigned long haskoki_std_message_sign_final(void *ctx, unsigned long session);

unsigned long haskoki_std_message_verify_init(void *ctx, unsigned long session,
    unsigned long mechanism, unsigned char *params, unsigned long paramsLen,
    unsigned long key);
unsigned long haskoki_std_message_verify(void *ctx, unsigned long session,
    unsigned char *params, unsigned long paramsLen,
    unsigned char *input, unsigned long inputLen,
    unsigned char *signature, unsigned long signatureLen);
unsigned long haskoki_std_message_verify_begin(void *ctx, unsigned long session,
    unsigned char *params, unsigned long paramsLen);
unsigned long haskoki_std_message_verify_next(void *ctx, unsigned long session,
    unsigned char *params, unsigned long paramsLen,
    unsigned char *part, unsigned long partLen,
    unsigned char *signature, unsigned long signatureLen);
unsigned long haskoki_std_message_verify_final(void *ctx, unsigned long session);
#endif

/* C interval state lock (cbits/function_tables.c): every routed
 * body holds it across its Haskell call, honoring the negotiated
 * host-mutex contract exactly like the original slice. Lock order is
 * globally C-then-Haskell (Haskell never calls back into C). */
extern CK_RV haskoki_state_lock(void);
extern CK_RV haskoki_state_unlock(void);



/* Single lock discipline: the handle is an atomic pointer, not
 * a lock-guarded plain one, because readers resolve it under the
 * state lock while install runs under the init lock. Install
 * release-stores; serving bodies acquire-load under the state lock;
 * shutdown exchange-NULLs while C_Finalize holds BOTH locks across
 * teardown, so no entrant can resolve a handle being closed. */
static _Atomic(void *) g_std_instance = ATOMIC_VAR_INIT(0);

/* Install (C_Initialize) / uninstall (C_Finalize) the handle. */
void haskoki_std_install(void *instance) {
  atomic_store_explicit(&g_std_instance, instance, memory_order_release);
}

void *haskoki_std_get(void) {
  return atomic_load_explicit(&g_std_instance, memory_order_acquire);
}

/* Open a fresh owned instance (C_Initialize path). The RTS is up by
 * construction (rts_ensure runs first in on_Initialize). */
void *haskoki_std_open_fresh(void) { return haskoki_std_open(); }

/* Close the installed handle: shuts the backend and the process
 * store, then uninstalls. Idempotent on NULL. */
void haskoki_std_shutdown(void) {
  void *inst =
      atomic_exchange_explicit(&g_std_instance, 0, memory_order_acq_rel);
  if (inst != 0) {
    haskoki_std_close(inst);
  }
}

/* The direct surface, C-owned (no Haskell global). The
 * provider-liveness flag lives here beside g_std_instance under the
 * same atomic discipline; the completed-interval flag g_initialized
 * in function_tables.c is a separate lifecycle twin (set only after
 * a full C_Initialize, cleared first in C_Finalize). Tri-state
 * contract, kept bit-for-bit from the Haskell version: direct-init
 * sets (ALREADY if set), direct-finalize clears (NOT_INITIALIZED if
 * clear), direct slot-list observes (NOT_INITIALIZED unless set).
 * Behavior matrix pinned by tests/c/loader.c case T00D. */
static _Atomic(int) g_provider_live = ATOMIC_VAR_INIT(0);

uint64_t haskoki_initialize(void) {
  int was =
      atomic_exchange_explicit(&g_provider_live, 1, memory_order_acq_rel);
  return was ? CKR_CRYPTOKI_ALREADY_INITIALIZED : CKR_OK;
}

uint64_t haskoki_finalize(void) {
  int was =
      atomic_exchange_explicit(&g_provider_live, 0, memory_order_acq_rel);
  return was ? CKR_OK : CKR_CRYPTOKI_NOT_INITIALIZED;
}

uint64_t haskoki_get_slot_list(uint8_t token_present,
                               uint64_t *p_slot_list, uint64_t *p_count) {
  uint64_t want;
  if (!atomic_load_explicit(&g_provider_live, memory_order_acquire)) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  if (p_count == NULL) {
    return CKR_ARGUMENTS_BAD;
  }
  want = (token_present == 0) ? 1u : 0u;
  if (p_slot_list == NULL) {
    *p_count = want;
    return CKR_OK;
  }
  if (*p_count < want) {
    *p_count = want;
    return CKR_BUFFER_TOO_SMALL;
  }
  if (want == 1u) {
    *p_slot_list = 0u;
  }
  *p_count = want;
  return CKR_OK;
}

/* Frame sizing: 8-byte count header, 16 bytes of record headers
 * per attribute, values capped at 16 MiB each and in total. */
#define STD_VALUE_MAX 16777216UL
#define STD_FRAME_MAX (16777216UL + 8UL + 16UL * 64UL)

static void put_u64le(uint8_t *dst, uint64_t v) {
  int i;
  for (i = 0; i < 8; i++) {
    dst[i] = (uint8_t)((v >> (8 * i)) & 0xFFU);
  }
}

/* ---------- routed bodies: slots, mechanisms, sessions ---------- */

/* Resolve the live instance or report NOT_INITIALIZED (defensive:
 * live_interval gates first; both must agree). Call ONLY with
 * the state lock held — C_Finalize closes under that same lock, so
 * a handle resolved here stays live through the Haskell entry. */
static void *live_std(void) {
  if (!haskoki_live_interval()) {
    return 0;
  }
  return haskoki_std_get();
}

/* Op-slot codes for haskoki_std_terminate_slot (mirrored by
 * decodeSlotKind in ffi/Haskoki/FFI/Standard.hs). */
#define HSK_SLOT_DIGEST 0u
#define HSK_SLOT_SIGN 1u
#define HSK_SLOT_VERIFY 2u
#define HSK_SLOT_ENCRYPT 3u
#define HSK_SLOT_DECRYPT 4u

/* Refuse a NULL argument after terminating the session's active op
 * of this slot kind (spec: every error other than BUFFER_TOO_SMALL
 * terminates; only the successful length query keeps the slot).
 * Lock failures and dead instances still refuse: there is nothing
 * to terminate, but the caller's pointers are still NULL. */
static CK_RV refuse_null_arg(CK_SESSION_HANDLE hSession, uint64_t slot) {
  CK_RV lr = 0;
  void *inst = 0;
  lr = haskoki_state_lock();
  if (lr != CKR_OK) {
    return CKR_ARGUMENTS_BAD;
  }
  inst = live_std();
  if (inst != 0) {
    (void)haskoki_std_terminate_slot(inst, (uint64_t)hSession, slot);
  }
  (void)haskoki_state_unlock();
  return CKR_ARGUMENTS_BAD;
}

CK_RV std_GetSlotList(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList,
                      CK_ULONG_PTR pulCount) {
  void *inst = 0;
  /* Fast-path precedence peek (the resolve under the state lock
   * below is authoritative; this keeps NOT_INITIALIZED first). */
  if (!haskoki_live_interval()) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  CK_RV lr = 0;
  CK_RV rv = 0;
  lr = haskoki_state_lock();
  if (lr != CKR_OK) {
    return lr;
  }
  inst = live_std();
  if (inst == 0) {
    (void)haskoki_state_unlock();
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  rv = (CK_RV)haskoki_std_get_slot_list(inst, (uint8_t)tokenPresent,
                                        (uint64_t *)pSlotList,
                                        (uint64_t *)pulCount);
  (void)haskoki_state_unlock();
  return rv;
}

/* Provisioned slot record: static strings, token always present in
 * a live interval. Seating is per-slot (one Haskell entry), the
 * record shape is identical on every seated slot. */
CK_RV std_GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo) {
  static const char kDesc[] = "haskoki soft slot";
  static const char kManu[] = "haskoki contributors";
  void *inst = 0;
  CK_SLOT_INFO tmp;
  CK_RV lr = 0;
  CK_RV rv = 0;
  if (!haskoki_live_interval()) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  lr = haskoki_state_lock();
  if (lr != CKR_OK) {
    return lr;
  }
  inst = live_std();
  if (inst == 0) {
    (void)haskoki_state_unlock();
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  rv = (CK_RV)haskoki_std_slot_present(inst, (uint64_t)slotID);
  (void)haskoki_state_unlock();
  if (rv != CKR_OK) {
    return rv;
  }
  if (pInfo == NULL_PTR) {
    return CKR_ARGUMENTS_BAD;
  }
  memset(tmp.slotDescription, ' ', sizeof(tmp.slotDescription));
  memcpy(tmp.slotDescription, kDesc, sizeof(kDesc) - 1);
  memset(tmp.manufacturerID, ' ', sizeof(tmp.manufacturerID));
  memcpy(tmp.manufacturerID, kManu, sizeof(kManu) - 1);
  tmp.flags = CKF_TOKEN_PRESENT;
  tmp.hardwareVersion.major = 1;
  tmp.hardwareVersion.minor = 0;
  tmp.firmwareVersion.major = 0;
  tmp.firmwareVersion.minor = 3;
  memcpy(pInfo, &tmp, sizeof(tmp));
  return CKR_OK;
}

/* Provisioned token record: per-slot label plus live session
 * counts and PIN-state flags from the model. Session bound 1024
 * and PIN lengths 4..32 are the provisioned policy (the 1024
 * duplicates Rules.defaultRules.rulesMaxSessions, pinned by
 * StandardSurfaceSpec casePolicyPins). Serials are per-slot
 * (1-based, slot 0 keeps ...0001). */
CK_RV std_GetTokenInfo(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo) {
  static const char kManu[] = "haskoki contributors";
  static const char kModel[] = "soft-token";
  static const char kUtc[] = "0000000000000000";
  void *inst = 0;
  /* Fast-path precedence peek (the resolve under the state lock
   * below is authoritative; this keeps NOT_INITIALIZED first). */
  if (!haskoki_live_interval()) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  CK_TOKEN_INFO tmp;
  CK_RV lr = 0;
  CK_RV rv = 0;
  uint64_t nSess = 0, nRw = 0, uLock = 0, sLock = 0, uRem = 0, sRem = 0;
  uint8_t label32[32];
  char serial16[17];
  lr = haskoki_state_lock();
  if (lr != CKR_OK) {
    return lr;
  }
  inst = live_std();
  if (inst == 0) {
    (void)haskoki_state_unlock();
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  /* Bad slots refuse first (before the NULL check below). */
  rv = (CK_RV)haskoki_std_token_label(inst, (uint64_t)slotID, label32);
  if (rv != CKR_OK) {
    (void)haskoki_state_unlock();
    return rv;
  }
  rv = (CK_RV)haskoki_std_token_live(inst, (uint64_t)slotID, &nSess, &nRw,
                                     &uLock, &sLock, &uRem, &sRem);
  (void)haskoki_state_unlock();
  if (rv != CKR_OK) {
    return rv;
  }
  if (pInfo == NULL_PTR) {
    return CKR_ARGUMENTS_BAD;
  }
  memcpy(tmp.label, label32, sizeof(tmp.label));
  memset(tmp.manufacturerID, ' ', sizeof(tmp.manufacturerID));
  memcpy(tmp.manufacturerID, kManu, sizeof(kManu) - 1);
  memset(tmp.model, ' ', sizeof(tmp.model));
  memcpy(tmp.model, kModel, sizeof(kModel) - 1);
  /* Seated slots are catalog indices (< 16), so the narrowing is
   * exact; %016u can never truncate into serial16. */
  snprintf(serial16, sizeof(serial16), "%016u", (unsigned)slotID + 1u);
  memcpy(tmp.serialNumber, serial16, sizeof(tmp.serialNumber));
  tmp.flags = (CK_FLAGS)(CKF_RNG | CKF_LOGIN_REQUIRED |
                         CKF_USER_PIN_INITIALIZED | CKF_TOKEN_INITIALIZED);
  if (uLock != 0) {
    tmp.flags |= CKF_USER_PIN_LOCKED;
  } else if (uRem == 1) {
    tmp.flags |= (CK_FLAGS)(CKF_USER_PIN_COUNT_LOW | CKF_USER_PIN_FINAL_TRY);
  } else if (uRem == 2) {
    tmp.flags |= CKF_USER_PIN_COUNT_LOW;
  }
  if (sLock != 0) {
    tmp.flags |= CKF_SO_PIN_LOCKED;
  } else if (sRem == 1) {
    tmp.flags |= (CK_FLAGS)(CKF_SO_PIN_COUNT_LOW | CKF_SO_PIN_FINAL_TRY);
  } else if (sRem == 2) {
    tmp.flags |= CKF_SO_PIN_COUNT_LOW;
  }
  tmp.ulMaxSessionCount = 1024;
  tmp.ulSessionCount = (CK_ULONG)nSess;
  tmp.ulMaxRwSessionCount = 1024;
  tmp.ulRwSessionCount = (CK_ULONG)nRw;
  tmp.ulMaxPinLen = 32;
  tmp.ulMinPinLen = 4;
  tmp.ulTotalPublicMemory = CK_UNAVAILABLE_INFORMATION;
  tmp.ulFreePublicMemory = CK_UNAVAILABLE_INFORMATION;
  tmp.ulTotalPrivateMemory = CK_UNAVAILABLE_INFORMATION;
  tmp.ulFreePrivateMemory = CK_UNAVAILABLE_INFORMATION;
  tmp.hardwareVersion.major = 1;
  tmp.hardwareVersion.minor = 0;
  tmp.firmwareVersion.major = 0;
  tmp.firmwareVersion.minor = 3;
  memcpy(tmp.utcTime, kUtc, sizeof(tmp.utcTime));
  memcpy(pInfo, &tmp, sizeof(tmp));
  return CKR_OK;
}

CK_RV std_GetMechanismList(CK_SLOT_ID slotID,
                           CK_MECHANISM_TYPE_PTR pMechanismList,
                           CK_ULONG_PTR pulCount) {
  void *inst = 0;
  CK_RV lr = 0;
  CK_RV rv = CKR_OK;
  size_t i = 0;
  if (!haskoki_live_interval()) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  lr = haskoki_state_lock();
  if (lr != CKR_OK) {
    return lr;
  }
  inst = live_std();
  if (inst == 0) {
    (void)haskoki_state_unlock();
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  /* Bad slots refuse first (before the NULL check below). */
  rv = (CK_RV)haskoki_std_slot_present(inst, (uint64_t)slotID);
  if (rv != CKR_OK) {
    (void)haskoki_state_unlock();
    return rv;
  }
  if (pulCount == NULL_PTR) {
    (void)haskoki_state_unlock();
    return CKR_ARGUMENTS_BAD;
  }
  if (pMechanismList == NULL_PTR) {
    *pulCount = (CK_ULONG)HASKOKI_MECH_COUNT;
  } else if (*pulCount < (CK_ULONG)HASKOKI_MECH_COUNT) {
    *pulCount = (CK_ULONG)HASKOKI_MECH_COUNT;
    rv = CKR_BUFFER_TOO_SMALL;
  } else {
    for (i = 0; i < (size_t)HASKOKI_MECH_COUNT; i++) {
      pMechanismList[i] = (CK_MECHANISM_TYPE)haskoki_mech_catalog[i].id;
    }
    *pulCount = (CK_ULONG)HASKOKI_MECH_COUNT;
  }
  (void)haskoki_state_unlock();
  return rv;
}

CK_RV std_GetMechanismInfo(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type,
                           CK_MECHANISM_INFO_PTR pInfo) {
  void *inst = 0;
  CK_RV lr = 0;
  CK_RV rv = CKR_MECHANISM_INVALID;
  size_t i = 0;
  if (!haskoki_live_interval()) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  lr = haskoki_state_lock();
  if (lr != CKR_OK) {
    return lr;
  }
  inst = live_std();
  if (inst == 0) {
    (void)haskoki_state_unlock();
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  /* Bad slots refuse first (before the NULL check below). */
  {
    CK_RV present = (CK_RV)haskoki_std_slot_present(inst, (uint64_t)slotID);
    if (present != CKR_OK) {
      (void)haskoki_state_unlock();
      return present;
    }
  }
  if (pInfo == NULL_PTR) {
    (void)haskoki_state_unlock();
    return CKR_ARGUMENTS_BAD;
  }
  for (i = 0; i < (size_t)HASKOKI_MECH_COUNT; i++) {
    if ((CK_MECHANISM_TYPE)haskoki_mech_catalog[i].id == type) {
      pInfo->ulMinKeySize = (CK_ULONG)haskoki_mech_catalog[i].min_key;
      pInfo->ulMaxKeySize = (CK_ULONG)haskoki_mech_catalog[i].max_key;
      pInfo->flags = (CK_FLAGS)haskoki_mech_catalog[i].flags;
      rv = CKR_OK;
      break;
    }
  }
  (void)haskoki_state_unlock();
  return rv;
}

CK_RV std_OpenSession(CK_SLOT_ID slotID, CK_FLAGS flags,
                      CK_VOID_PTR pApplication, CK_NOTIFY Notify,
                      CK_SESSION_HANDLE_PTR phSession) {
  void *inst = 0;
  /* Fast-path precedence peek (the resolve under the state lock
   * below is authoritative; this keeps NOT_INITIALIZED first). */
  if (!haskoki_live_interval()) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  CK_RV lr = 0;
  CK_RV rv = 0;
  (void)pApplication;
  if (phSession == NULL_PTR) {
    return CKR_ARGUMENTS_BAD;
  }
  /* A supplied Notify is accepted, never refused: the
   * C_OpenSession return list (v3.2 §5.6.1) carries no
   * callback-refusal code, so refusing would invent one
   * (rc2's callback matrix pins accept-or-SESSION_COUNT).
   * The module generates no notification events (no
   * surrender/device callbacks), so the callback is
   * retained nowhere and never invoked; see
   * docs/operations-notes.md ("Session notification
   * callbacks"). */
  (void)Notify;
  if ((flags & CKF_SERIAL_SESSION) == 0) {
    return CKR_SESSION_PARALLEL_NOT_SUPPORTED;
  }
  if ((flags & ~(CKF_SERIAL_SESSION | CKF_RW_SESSION)) != 0) {
    return CKR_ARGUMENTS_BAD;
  }
  lr = haskoki_state_lock();
  if (lr != CKR_OK) {
    return lr;
  }
  inst = live_std();
  if (inst == 0) {
    (void)haskoki_state_unlock();
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  rv = (CK_RV)haskoki_std_open_session(
      inst, (uint64_t)slotID,
      (flags & CKF_RW_SESSION) != 0 ? (uint64_t)0 : (uint64_t)1,
      (uint64_t *)phSession);
  (void)haskoki_state_unlock();
  return rv;
}

CK_RV std_CloseSession(CK_SESSION_HANDLE hSession) {
  void *inst = 0;
  /* Fast-path precedence peek (the resolve under the state lock
   * below is authoritative; this keeps NOT_INITIALIZED first). */
  if (!haskoki_live_interval()) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  CK_RV lr = 0;
  CK_RV rv = 0;
  lr = haskoki_state_lock();
  if (lr != CKR_OK) {
    return lr;
  }
  inst = live_std();
  if (inst == 0) {
    (void)haskoki_state_unlock();
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  rv = (CK_RV)haskoki_std_close_session(inst, (uint64_t)hSession);
  (void)haskoki_state_unlock();
  return rv;
}

CK_RV std_CloseAllSessions(CK_SLOT_ID slotID) {
  void *inst = 0;
  /* Fast-path precedence peek (the resolve under the state lock
   * below is authoritative; this keeps NOT_INITIALIZED first). */
  if (!haskoki_live_interval()) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  CK_RV lr = 0;
  CK_RV rv = 0;
  lr = haskoki_state_lock();
  if (lr != CKR_OK) {
    return lr;
  }
  inst = live_std();
  if (inst == 0) {
    (void)haskoki_state_unlock();
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  rv = (CK_RV)haskoki_std_close_all_sessions(inst, (uint64_t)slotID);
  (void)haskoki_state_unlock();
  return rv;
}

CK_RV std_SessionCancel(CK_SESSION_HANDLE hSession, CK_FLAGS flags) {
  void *inst = 0;
  /* Fast-path precedence peek (the resolve under the state lock
   * below is authoritative; this keeps NOT_INITIALIZED first). */
  if (!haskoki_live_interval()) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  CK_RV lr = 0;
  CK_RV rv = 0;
  lr = haskoki_state_lock();
  if (lr != CKR_OK) {
    return lr;
  }
  inst = live_std();
  if (inst == 0) {
    (void)haskoki_state_unlock();
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  rv = (CK_RV)haskoki_std_session_cancel(inst, (uint64_t)hSession,
                                         (uint64_t)flags);
  (void)haskoki_state_unlock();
  return rv;
}

CK_RV std_GetSessionInfo(CK_SESSION_HANDLE hSession,
                         CK_SESSION_INFO_PTR pInfo) {
  void *inst = 0;
  /* Fast-path precedence peek (the resolve under the state lock
   * below is authoritative; this keeps NOT_INITIALIZED first). */
  if (!haskoki_live_interval()) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  CK_RV lr = 0;
  CK_RV rv = 0;
  uint64_t slot = 0, ro = 0, login = 0, devErr = 0;
  CK_STATE state = 0;
  if (pInfo == NULL_PTR) {
    return CKR_ARGUMENTS_BAD;
  }
  lr = haskoki_state_lock();
  if (lr != CKR_OK) {
    return lr;
  }
  inst = live_std();
  if (inst == 0) {
    (void)haskoki_state_unlock();
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  rv = (CK_RV)haskoki_std_get_session_info(inst, (uint64_t)hSession, &slot,
                                           &ro, &login, &devErr);
  (void)haskoki_state_unlock();
  if (rv != CKR_OK) {
    return rv;
  }
  /* Login codes are provider-local (0 public, 1 user, 2 SO,
   * 3 context grant). RO+SO is unreachable (admission denies
   * both directions) and maps defensively to RO public. */
  if (ro != 0) {
    if (login == 1 || login == 3) {
      state = CKS_RO_USER_FUNCTIONS;
    } else {
      state = CKS_RO_PUBLIC_SESSION;
    }
  } else {
    if (login == 1 || login == 3) {
      state = CKS_RW_USER_FUNCTIONS;
    } else if (login == 2) {
      state = CKS_RW_SO_FUNCTIONS;
    } else {
      state = CKS_RW_PUBLIC_SESSION;
    }
  }
  pInfo->slotID = (CK_SLOT_ID)slot;
  pInfo->state = state;
  pInfo->flags = CKF_SERIAL_SESSION;
  if (ro == 0) {
    pInfo->flags |= CKF_RW_SESSION;
  }
  pInfo->ulDeviceError = (CK_ULONG)devErr;
  return CKR_OK;
}

/* ---------- routed bodies: objects ---------- */

CK_RV std_CreateObject(CK_SESSION_HANDLE hSession,
                       CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
                       CK_OBJECT_HANDLE_PTR phObject) {
  void *inst = 0;
  /* Fast-path precedence peek (the resolve under the state lock
   * below is authoritative; this keeps NOT_INITIALIZED first). */
  if (!haskoki_live_interval()) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  uint8_t *frame = NULL;
  uint64_t frameLen = 0;
  CK_RV lr = 0;
  CK_RV rv = 0;
  if (phObject == NULL_PTR) {
    return CKR_ARGUMENTS_BAD;
  }
  if (ulCount > 0 && pTemplate == NULL_PTR) {
    return CKR_ARGUMENTS_BAD;
  }
  if (haskoki_std_pack_template(pTemplate, (unsigned long)ulCount, &frame,
                                &frameLen) != 0) {
    return CKR_ARGUMENTS_BAD;
  }
  lr = haskoki_state_lock();
  if (lr != CKR_OK) {
    free(frame);
    return lr;
  }
  inst = live_std();
  if (inst == 0) {
    free(frame);
    (void)haskoki_state_unlock();
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  rv = (CK_RV)haskoki_std_create_object(inst, (uint64_t)hSession, frame,
                                        frameLen, (uint64_t *)phObject);
  (void)haskoki_state_unlock();
  free(frame);
  return rv;
}

CK_RV std_CopyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
                     CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
                     CK_OBJECT_HANDLE_PTR phNewObject) {
  void *inst = 0;
  /* Fast-path precedence peek (the resolve under the state lock
   * below is authoritative; this keeps NOT_INITIALIZED first). */
  if (!haskoki_live_interval()) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  uint8_t *frame = NULL;
  uint64_t frameLen = 0;
  CK_RV lr = 0;
  CK_RV rv = 0;
  if (phNewObject == NULL_PTR) {
    return CKR_ARGUMENTS_BAD;
  }
  if (ulCount > 0 && pTemplate == NULL_PTR) {
    return CKR_ARGUMENTS_BAD;
  }
  if (haskoki_std_pack_template(pTemplate, (unsigned long)ulCount, &frame,
                                &frameLen) != 0) {
    return CKR_ARGUMENTS_BAD;
  }
  lr = haskoki_state_lock();
  if (lr != CKR_OK) {
    free(frame);
    return lr;
  }
  inst = live_std();
  if (inst == 0) {
    free(frame);
    (void)haskoki_state_unlock();
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  rv = (CK_RV)haskoki_std_copy_object(inst, (uint64_t)hSession,
                                      (uint64_t)hObject, frame, frameLen,
                                      (uint64_t *)phNewObject);
  (void)haskoki_state_unlock();
  free(frame);
  return rv;
}

CK_RV std_SetAttributeValue(CK_SESSION_HANDLE hSession,
                           CK_OBJECT_HANDLE hObject,
                           CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount) {
  void *inst = 0;
  /* Fast-path precedence peek (the resolve under the state lock
   * below is authoritative; this keeps NOT_INITIALIZED first). */
  if (!haskoki_live_interval()) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  uint8_t *frame = NULL;
  uint64_t frameLen = 0;
  CK_RV lr = 0;
  CK_RV rv = 0;
  if (ulCount > 0 && pTemplate == NULL_PTR) {
    return CKR_ARGUMENTS_BAD;
  }
  if (haskoki_std_pack_template(pTemplate, (unsigned long)ulCount, &frame,
                                &frameLen) != 0) {
    return CKR_ARGUMENTS_BAD;
  }
  lr = haskoki_state_lock();
  if (lr != CKR_OK) {
    free(frame);
    return lr;
  }
  inst = live_std();
  if (inst == 0) {
    free(frame);
    (void)haskoki_state_unlock();
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  rv = (CK_RV)haskoki_std_set_attribute_value(inst, (uint64_t)hSession,
                                              (uint64_t)hObject, frame,
                                              frameLen);
  (void)haskoki_state_unlock();
  free(frame);
  return rv;
}

CK_RV std_DestroyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject) {
  void *inst = 0;
  /* Fast-path precedence peek (the resolve under the state lock
   * below is authoritative; this keeps NOT_INITIALIZED first). */
  if (!haskoki_live_interval()) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  CK_RV lr = 0;
  CK_RV rv = 0;
  lr = haskoki_state_lock();
  if (lr != CKR_OK) {
    return lr;
  }
  inst = live_std();
  if (inst == 0) {
    (void)haskoki_state_unlock();
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  rv = (CK_RV)haskoki_std_destroy_object(inst, (uint64_t)hSession,
                                         (uint64_t)hObject);
  (void)haskoki_state_unlock();
  return rv;
}

CK_RV std_GetAttributeValue(CK_SESSION_HANDLE hSession,
                            CK_OBJECT_HANDLE hObject,
                            CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount) {
  void *inst = 0;
  /* Fast-path precedence peek (the resolve under the state lock
   * below is authoritative; this keeps NOT_INITIALIZED first). */
  if (!haskoki_live_interval()) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  CK_RV lr = 0;
  CK_RV overall = CKR_OK;
  CK_ULONG i = 0;
  int sawSens = 0, sawType = 0, sawShort = 0, aborted = 0;
  if (ulCount > 0 && pTemplate == NULL_PTR) {
    return CKR_ARGUMENTS_BAD;
  }
  /* Same template-entry bound as the pack path (haskoki_std_pack_template):
   * the per-attribute loop below dereferences pTemplate[i], so an
   * unbounded count reads out of bounds (oracle: template_count
   * overflow probes segfaulted). Refuse loudly, never truncate. */
  if (ulCount > HASKOKI_STD_TEMPLATE_MAX_ATTRS) {
    return CKR_ARGUMENTS_BAD;
  }
  lr = haskoki_state_lock();
  if (lr != CKR_OK) {
    return lr;
  }
  inst = live_std();
  if (inst == 0) {
    (void)haskoki_state_unlock();
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  for (i = 0; i < ulCount; i++) {
    CK_RV r = (CK_RV)haskoki_std_get_one_attr(
        inst, (uint64_t)hSession, (uint64_t)hObject,
        (uint64_t)pTemplate[i].type, (uint8_t *)pTemplate[i].pValue,
        (uint64_t *)&pTemplate[i].ulValueLen);
    if (r == CKR_OK) {
      continue;
    }
    if (r == CKR_ATTRIBUTE_SENSITIVE) {
      sawSens = 1;
      continue;
    }
    if (r == CKR_ATTRIBUTE_TYPE_INVALID) {
      sawType = 1;
      continue;
    }
    if (r == CKR_BUFFER_TOO_SMALL) {
      sawShort = 1;
      continue;
    }
    /* Whole-call failure (bad session/object, general error):
     * abort; untouched entries stay untouched. */
    overall = r;
    aborted = 1;
    break;
  }
  (void)haskoki_state_unlock();
  if (!aborted) {
    if (sawSens) {
      overall = CKR_ATTRIBUTE_SENSITIVE;
    } else if (sawType) {
      overall = CKR_ATTRIBUTE_TYPE_INVALID;
    } else if (sawShort) {
      overall = CKR_BUFFER_TOO_SMALL;
    }
  }
  return overall;
}

CK_RV std_FindObjectsInit(CK_SESSION_HANDLE hSession,
                          CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount) {
  void *inst = 0;
  /* Fast-path precedence peek (the resolve under the state lock
   * below is authoritative; this keeps NOT_INITIALIZED first). */
  if (!haskoki_live_interval()) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  uint8_t *frame = NULL;
  uint64_t frameLen = 0;
  CK_RV lr = 0;
  CK_RV rv = 0;
  if (ulCount > 0 && pTemplate == NULL_PTR) {
    return CKR_ARGUMENTS_BAD;
  }
  if (haskoki_std_pack_template(pTemplate, (unsigned long)ulCount, &frame,
                                &frameLen) != 0) {
    return CKR_ARGUMENTS_BAD;
  }
  lr = haskoki_state_lock();
  if (lr != CKR_OK) {
    free(frame);
    return lr;
  }
  inst = live_std();
  if (inst == 0) {
    free(frame);
    (void)haskoki_state_unlock();
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  rv = (CK_RV)haskoki_std_find_init(inst, (uint64_t)hSession, frame, frameLen);
  (void)haskoki_state_unlock();
  free(frame);
  return rv;
}

CK_RV std_FindObjects(CK_SESSION_HANDLE hSession,
                      CK_OBJECT_HANDLE_PTR phObject, CK_ULONG ulMaxObjectCount,
                      CK_ULONG_PTR pulObjectCount) {
  void *inst = 0;
  /* Fast-path precedence peek (the resolve under the state lock
   * below is authoritative; this keeps NOT_INITIALIZED first). */
  if (!haskoki_live_interval()) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  CK_RV lr = 0;
  CK_RV rv = 0;
  if (pulObjectCount == NULL_PTR) {
    return CKR_ARGUMENTS_BAD;
  }
  if (ulMaxObjectCount > 0 && phObject == NULL_PTR) {
    return CKR_ARGUMENTS_BAD;
  }
  lr = haskoki_state_lock();
  if (lr != CKR_OK) {
    return lr;
  }
  inst = live_std();
  if (inst == 0) {
    (void)haskoki_state_unlock();
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  rv = (CK_RV)haskoki_std_find(inst, (uint64_t)hSession,
                               (uint64_t)ulMaxObjectCount,
                               (uint64_t *)phObject,
                               (uint64_t *)pulObjectCount);
  (void)haskoki_state_unlock();
  return rv;
}

CK_RV std_FindObjectsFinal(CK_SESSION_HANDLE hSession) {
  void *inst = 0;
  /* Fast-path precedence peek (the resolve under the state lock
   * below is authoritative; this keeps NOT_INITIALIZED first). */
  if (!haskoki_live_interval()) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  CK_RV lr = 0;
  CK_RV rv = 0;
  lr = haskoki_state_lock();
  if (lr != CKR_OK) {
    return lr;
  }
  inst = live_std();
  if (inst == 0) {
    (void)haskoki_state_unlock();
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  rv = (CK_RV)haskoki_std_find_final(inst, (uint64_t)hSession);
  (void)haskoki_state_unlock();
  return rv;
}

/* ---------- routed bodies: login/logout ---------- */

CK_RV std_Login(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType,
                CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen) {
  void *inst = 0;
  /* Fast-path precedence peek (the resolve under the state lock
   * below is authoritative; this keeps NOT_INITIALIZED first). */
  if (!haskoki_live_interval()) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  CK_RV lr = 0;
  CK_RV rv = 0;
  if (ulPinLen > 0 && pPin == NULL_PTR) {
    return CKR_ARGUMENTS_BAD;
  }
  lr = haskoki_state_lock();
  if (lr != CKR_OK) {
    return lr;
  }
  inst = live_std();
  if (inst == 0) {
    (void)haskoki_state_unlock();
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  rv = (CK_RV)haskoki_std_login(inst, (uint64_t)hSession, (uint64_t)userType,
                                (uint8_t *)pPin, (uint64_t)ulPinLen);
  (void)haskoki_state_unlock();
  return rv;
}

CK_RV std_Logout(CK_SESSION_HANDLE hSession) {
  void *inst = 0;
  /* Fast-path precedence peek (the resolve under the state lock
   * below is authoritative; this keeps NOT_INITIALIZED first). */
  if (!haskoki_live_interval()) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  CK_RV lr = 0;
  CK_RV rv = 0;
  lr = haskoki_state_lock();
  if (lr != CKR_OK) {
    return lr;
  }
  inst = live_std();
  if (inst == 0) {
    (void)haskoki_state_unlock();
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  rv = (CK_RV)haskoki_std_logout(inst, (uint64_t)hSession);
  (void)haskoki_state_unlock();
  return rv;
}

/* ---------- routed bodies: digest ---------- */

CK_RV std_DigestInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism) {
  void *inst = 0;
  /* Fast-path precedence peek (the resolve under the state lock
   * below is authoritative; this keeps NOT_INITIALIZED first). */
  if (!haskoki_live_interval()) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  CK_RV lr = 0;
  CK_RV rv = 0;
  if (pMechanism == NULL_PTR) {
    return CKR_ARGUMENTS_BAD;
  }
  if (pMechanism->ulParameterLen > 0 && pMechanism->pParameter == NULL_PTR) {
    return CKR_ARGUMENTS_BAD;
  }
  lr = haskoki_state_lock();
  if (lr != CKR_OK) {
    return lr;
  }
  inst = live_std();
  if (inst == 0) {
    (void)haskoki_state_unlock();
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  rv = (CK_RV)haskoki_std_digest_init(
      inst, (uint64_t)hSession, (uint64_t)pMechanism->mechanism,
      (uint8_t *)pMechanism->pParameter, (uint64_t)pMechanism->ulParameterLen);
  (void)haskoki_state_unlock();
  return rv;
}

CK_RV std_Digest(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData,
                 CK_ULONG ulDataLen, CK_BYTE_PTR pDigest,
                 CK_ULONG_PTR pulDigestLen) {
  void *inst = 0;
  /* Fast-path precedence peek (the resolve under the state lock
   * below is authoritative; this keeps NOT_INITIALIZED first). */
  if (!haskoki_live_interval()) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  CK_RV lr = 0;
  CK_RV rv = 0;
  if (pulDigestLen == NULL_PTR) {
    return refuse_null_arg(hSession, HSK_SLOT_DIGEST);
  }
  if (ulDataLen > 0 && pData == NULL_PTR) {
    return refuse_null_arg(hSession, HSK_SLOT_DIGEST);
  }
  lr = haskoki_state_lock();
  if (lr != CKR_OK) {
    return lr;
  }
  inst = live_std();
  if (inst == 0) {
    (void)haskoki_state_unlock();
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  rv = (CK_RV)haskoki_std_digest(inst, (uint64_t)hSession, (uint8_t *)pData,
                                 (uint64_t)ulDataLen, (uint8_t *)pDigest,
                                 (uint64_t *)pulDigestLen);
  (void)haskoki_state_unlock();
  return rv;
}

CK_RV std_DigestUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart,
                       CK_ULONG ulPartLen) {
  void *inst = 0;
  /* Fast-path precedence peek (the resolve under the state lock
   * below is authoritative; this keeps NOT_INITIALIZED first). */
  if (!haskoki_live_interval()) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  CK_RV lr = 0;
  CK_RV rv = 0;
  if (ulPartLen > 0 && pPart == NULL_PTR) {
    return refuse_null_arg(hSession, HSK_SLOT_DIGEST);
  }
  lr = haskoki_state_lock();
  if (lr != CKR_OK) {
    return lr;
  }
  inst = live_std();
  if (inst == 0) {
    (void)haskoki_state_unlock();
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  rv = (CK_RV)haskoki_std_digest_update(inst, (uint64_t)hSession,
                                        (uint8_t *)pPart,
                                        (uint64_t)ulPartLen);
  (void)haskoki_state_unlock();
  return rv;
}

CK_RV std_DigestKey(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey) {
  void *inst = 0;
  /* Fast-path precedence peek (the resolve under the state lock
   * below is authoritative; this keeps NOT_INITIALIZED first). */
  if (!haskoki_live_interval()) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  CK_RV lr = 0;
  CK_RV rv = 0;
  lr = haskoki_state_lock();
  if (lr != CKR_OK) {
    return lr;
  }
  inst = live_std();
  if (inst == 0) {
    (void)haskoki_state_unlock();
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  rv = (CK_RV)haskoki_std_digest_key(inst, (uint64_t)hSession,
                                     (uint64_t)hKey);
  (void)haskoki_state_unlock();
  return rv;
}

CK_RV std_DigestFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pDigest,
                      CK_ULONG_PTR pulDigestLen) {
  void *inst = 0;
  /* Fast-path precedence peek (the resolve under the state lock
   * below is authoritative; this keeps NOT_INITIALIZED first). */
  if (!haskoki_live_interval()) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  CK_RV lr = 0;
  CK_RV rv = 0;
  if (pulDigestLen == NULL_PTR) {
    return refuse_null_arg(hSession, HSK_SLOT_DIGEST);
  }
  lr = haskoki_state_lock();
  if (lr != CKR_OK) {
    return lr;
  }
  inst = live_std();
  if (inst == 0) {
    (void)haskoki_state_unlock();
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  rv = (CK_RV)haskoki_std_digest_final(inst, (uint64_t)hSession,
                                       (uint8_t *)pDigest,
                                       (uint64_t *)pulDigestLen);
  (void)haskoki_state_unlock();
  return rv;
}

CK_RV std_GenerateKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
                      CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
                      CK_OBJECT_HANDLE_PTR phKey) {
  void *inst = 0;
  /* Fast-path precedence peek (the resolve under the state lock
   * below is authoritative; this keeps NOT_INITIALIZED first). */
  if (!haskoki_live_interval()) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  uint8_t *frame = NULL;
  uint64_t frameLen = 0;
  CK_RV lr = 0;
  CK_RV rv = 0;
  if (pMechanism == NULL_PTR || phKey == NULL_PTR) {
    return CKR_ARGUMENTS_BAD;
  }
  if (ulCount > 0 && pTemplate == NULL_PTR) {
    return CKR_ARGUMENTS_BAD;
  }
  if (haskoki_std_pack_template(pTemplate, (unsigned long)ulCount, &frame,
                                &frameLen) != 0) {
    return CKR_ARGUMENTS_BAD;
  }
  lr = haskoki_state_lock();
  if (lr != CKR_OK) {
    free(frame);
    return lr;
  }
  inst = live_std();
  if (inst == 0) {
    free(frame);
    (void)haskoki_state_unlock();
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  rv = (CK_RV)haskoki_std_generate_key(
      inst, (uint64_t)hSession, (uint64_t)pMechanism->mechanism, frame,
      frameLen, (uint8_t *)pMechanism->pParameter,
      (uint64_t)pMechanism->ulParameterLen, (uint64_t *)phKey);
  (void)haskoki_state_unlock();
  free(frame);
  return rv;
}

CK_RV std_GenerateKeyPair(CK_SESSION_HANDLE hSession,
                          CK_MECHANISM_PTR pMechanism,
                          CK_ATTRIBUTE_PTR pPublicKeyTemplate,
                          CK_ULONG ulPublicKeyAttributeCount,
                          CK_ATTRIBUTE_PTR pPrivateKeyTemplate,
                          CK_ULONG ulPrivateKeyAttributeCount,
                          CK_OBJECT_HANDLE_PTR phPublicKey,
                          CK_OBJECT_HANDLE_PTR phPrivateKey) {
  void *inst = 0;
  /* Fast-path precedence peek (the resolve under the state lock
   * below is authoritative; this keeps NOT_INITIALIZED first). */
  if (!haskoki_live_interval()) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  uint8_t *pubFrame = NULL;
  uint64_t pubLen = 0;
  uint8_t *privFrame = NULL;
  uint64_t privLen = 0;
  CK_RV lr = 0;
  CK_RV rv = 0;
  if (pMechanism == NULL_PTR || phPublicKey == NULL_PTR ||
      phPrivateKey == NULL_PTR) {
    return CKR_ARGUMENTS_BAD;
  }
  if (ulPublicKeyAttributeCount > 0 && pPublicKeyTemplate == NULL_PTR) {
    return CKR_ARGUMENTS_BAD;
  }
  if (ulPrivateKeyAttributeCount > 0 && pPrivateKeyTemplate == NULL_PTR) {
    return CKR_ARGUMENTS_BAD;
  }
  if (haskoki_std_pack_template(pPublicKeyTemplate,
                                (unsigned long)ulPublicKeyAttributeCount,
                                &pubFrame, &pubLen) != 0) {
    return CKR_ARGUMENTS_BAD;
  }
  if (haskoki_std_pack_template(pPrivateKeyTemplate,
                                (unsigned long)ulPrivateKeyAttributeCount,
                                &privFrame, &privLen) != 0) {
    free(pubFrame);
    return CKR_ARGUMENTS_BAD;
  }
  lr = haskoki_state_lock();
  if (lr != CKR_OK) {
    free(pubFrame);
    free(privFrame);
    return lr;
  }
  inst = live_std();
  if (inst == 0) {
    free(pubFrame);
    free(privFrame);
    (void)haskoki_state_unlock();
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  rv = (CK_RV)haskoki_std_generate_key_pair(
      inst, (uint64_t)hSession, (uint64_t)pMechanism->mechanism, pubFrame,
      pubLen, privFrame, privLen, (uint64_t *)phPublicKey,
      (uint64_t *)phPrivateKey);
  (void)haskoki_state_unlock();
  free(pubFrame);
  free(privFrame);
  return rv;
}

CK_RV std_SignInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
                   CK_OBJECT_HANDLE hKey) {
  void *inst = 0;
  /* Fast-path precedence peek (the resolve under the state lock
   * below is authoritative; this keeps NOT_INITIALIZED first). */
  if (!haskoki_live_interval()) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  CK_RV lr = 0;
  CK_RV rv = 0;
  if (pMechanism == NULL_PTR) {
    return CKR_ARGUMENTS_BAD;
  }
  if (pMechanism->ulParameterLen > 0 && pMechanism->pParameter == NULL_PTR) {
    return CKR_ARGUMENTS_BAD;
  }
  lr = haskoki_state_lock();
  if (lr != CKR_OK) {
    return lr;
  }
  inst = live_std();
  if (inst == 0) {
    (void)haskoki_state_unlock();
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  rv = (CK_RV)haskoki_std_sign_init(
      inst, (uint64_t)hSession, (uint64_t)pMechanism->mechanism,
      (uint8_t *)pMechanism->pParameter, (uint64_t)pMechanism->ulParameterLen,
      (uint64_t)hKey);
  (void)haskoki_state_unlock();
  return rv;
}

CK_RV std_Sign(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen,
               CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen) {
  void *inst = 0;
  /* Fast-path precedence peek (the resolve under the state lock
   * below is authoritative; this keeps NOT_INITIALIZED first). */
  if (!haskoki_live_interval()) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  CK_RV lr = 0;
  CK_RV rv = 0;
  if (pulSignatureLen == NULL_PTR) {
    return refuse_null_arg(hSession, HSK_SLOT_SIGN);
  }
  if (ulDataLen > 0 && pData == NULL_PTR) {
    return refuse_null_arg(hSession, HSK_SLOT_SIGN);
  }
  lr = haskoki_state_lock();
  if (lr != CKR_OK) {
    return lr;
  }
  inst = live_std();
  if (inst == 0) {
    (void)haskoki_state_unlock();
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  rv = (CK_RV)haskoki_std_sign(inst, (uint64_t)hSession, (uint8_t *)pData,
                               (uint64_t)ulDataLen, (uint8_t *)pSignature,
                               (uint64_t *)pulSignatureLen);
  (void)haskoki_state_unlock();
  return rv;
}

CK_RV std_SignUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart,
                     CK_ULONG ulPartLen) {
  void *inst = 0;
  /* Fast-path precedence peek (the resolve under the state lock
   * below is authoritative; this keeps NOT_INITIALIZED first). */
  if (!haskoki_live_interval()) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  CK_RV lr = 0;
  CK_RV rv = 0;
  if (ulPartLen > 0 && pPart == NULL_PTR) {
    return refuse_null_arg(hSession, HSK_SLOT_SIGN);
  }
  lr = haskoki_state_lock();
  if (lr != CKR_OK) {
    return lr;
  }
  inst = live_std();
  if (inst == 0) {
    (void)haskoki_state_unlock();
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  rv = (CK_RV)haskoki_std_sign_update(inst, (uint64_t)hSession, (uint8_t *)pPart,
                                      (uint64_t)ulPartLen);
  (void)haskoki_state_unlock();
  return rv;
}

CK_RV std_SignFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature,
                    CK_ULONG_PTR pulSignatureLen) {
  void *inst = 0;
  /* Fast-path precedence peek (the resolve under the state lock
   * below is authoritative; this keeps NOT_INITIALIZED first). */
  if (!haskoki_live_interval()) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  CK_RV lr = 0;
  CK_RV rv = 0;
  if (pulSignatureLen == NULL_PTR) {
    return refuse_null_arg(hSession, HSK_SLOT_SIGN);
  }
  lr = haskoki_state_lock();
  if (lr != CKR_OK) {
    return lr;
  }
  inst = live_std();
  if (inst == 0) {
    (void)haskoki_state_unlock();
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  rv = (CK_RV)haskoki_std_sign_final(inst, (uint64_t)hSession,
                                     (uint8_t *)pSignature,
                                     (uint64_t *)pulSignatureLen);
  (void)haskoki_state_unlock();
  return rv;
}

CK_RV std_VerifyInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
                     CK_OBJECT_HANDLE hKey) {
  void *inst = 0;
  /* Fast-path precedence peek (the resolve under the state lock
   * below is authoritative; this keeps NOT_INITIALIZED first). */
  if (!haskoki_live_interval()) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  CK_RV lr = 0;
  CK_RV rv = 0;
  if (pMechanism == NULL_PTR) {
    return CKR_ARGUMENTS_BAD;
  }
  if (pMechanism->ulParameterLen > 0 && pMechanism->pParameter == NULL_PTR) {
    return CKR_ARGUMENTS_BAD;
  }
  lr = haskoki_state_lock();
  if (lr != CKR_OK) {
    return lr;
  }
  inst = live_std();
  if (inst == 0) {
    (void)haskoki_state_unlock();
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  rv = (CK_RV)haskoki_std_verify_init(
      inst, (uint64_t)hSession, (uint64_t)pMechanism->mechanism,
      (uint8_t *)pMechanism->pParameter, (uint64_t)pMechanism->ulParameterLen,
      (uint64_t)hKey);
  (void)haskoki_state_unlock();
  return rv;
}

CK_RV std_Verify(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData,
                 CK_ULONG ulDataLen, CK_BYTE_PTR pSignature,
                 CK_ULONG ulSignatureLen) {
  void *inst = 0;
  /* Fast-path precedence peek (the resolve under the state lock
   * below is authoritative; this keeps NOT_INITIALIZED first). */
  if (!haskoki_live_interval()) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  CK_RV lr = 0;
  CK_RV rv = 0;
  if (ulDataLen > 0 && pData == NULL_PTR) {
    return refuse_null_arg(hSession, HSK_SLOT_VERIFY);
  }
  if (ulSignatureLen > 0 && pSignature == NULL_PTR) {
    return refuse_null_arg(hSession, HSK_SLOT_VERIFY);
  }
  lr = haskoki_state_lock();
  if (lr != CKR_OK) {
    return lr;
  }
  inst = live_std();
  if (inst == 0) {
    (void)haskoki_state_unlock();
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  rv = (CK_RV)haskoki_std_verify(inst, (uint64_t)hSession, (uint8_t *)pData,
                                 (uint64_t)ulDataLen, (uint8_t *)pSignature,
                                 (uint64_t)ulSignatureLen);
  (void)haskoki_state_unlock();
  return rv;
}

CK_RV std_VerifyUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart,
                       CK_ULONG ulPartLen) {
  void *inst = 0;
  /* Fast-path precedence peek (the resolve under the state lock
   * below is authoritative; this keeps NOT_INITIALIZED first). */
  if (!haskoki_live_interval()) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  CK_RV lr = 0;
  CK_RV rv = 0;
  if (ulPartLen > 0 && pPart == NULL_PTR) {
    return refuse_null_arg(hSession, HSK_SLOT_VERIFY);
  }
  lr = haskoki_state_lock();
  if (lr != CKR_OK) {
    return lr;
  }
  inst = live_std();
  if (inst == 0) {
    (void)haskoki_state_unlock();
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  rv = (CK_RV)haskoki_std_verify_update(inst, (uint64_t)hSession,
                                        (uint8_t *)pPart, (uint64_t)ulPartLen);
  (void)haskoki_state_unlock();
  return rv;
}

CK_RV std_VerifyFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature,
                      CK_ULONG ulSignatureLen) {
  void *inst = 0;
  /* Fast-path precedence peek (the resolve under the state lock
   * below is authoritative; this keeps NOT_INITIALIZED first). */
  if (!haskoki_live_interval()) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  CK_RV lr = 0;
  CK_RV rv = 0;
  if (ulSignatureLen > 0 && pSignature == NULL_PTR) {
    return refuse_null_arg(hSession, HSK_SLOT_VERIFY);
  }
  lr = haskoki_state_lock();
  if (lr != CKR_OK) {
    return lr;
  }
  inst = live_std();
  if (inst == 0) {
    (void)haskoki_state_unlock();
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  rv = (CK_RV)haskoki_std_verify_final(inst, (uint64_t)hSession,
                                       (uint8_t *)pSignature,
                                       (uint64_t)ulSignatureLen);
  (void)haskoki_state_unlock();
  return rv;
}

CK_RV std_EncryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
                      CK_OBJECT_HANDLE hKey) {
  void *inst = 0;
  /* Fast-path precedence peek (the resolve under the state lock
   * below is authoritative; this keeps NOT_INITIALIZED first). */
  if (!haskoki_live_interval()) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  CK_RV lr = 0;
  CK_RV rv = 0;
  if (pMechanism == NULL_PTR) {
    return CKR_ARGUMENTS_BAD;
  }
  if (pMechanism->ulParameterLen > 0 && pMechanism->pParameter == NULL_PTR) {
    return CKR_ARGUMENTS_BAD;
  }
  lr = haskoki_state_lock();
  if (lr != CKR_OK) {
    return lr;
  }
  inst = live_std();
  if (inst == 0) {
    (void)haskoki_state_unlock();
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  rv = (CK_RV)haskoki_std_encrypt_init(
      inst, (uint64_t)hSession, (uint64_t)pMechanism->mechanism,
      (uint8_t *)pMechanism->pParameter, (uint64_t)pMechanism->ulParameterLen,
      (uint64_t)hKey);
  (void)haskoki_state_unlock();
  return rv;
}

CK_RV std_Encrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData,
                  CK_ULONG ulDataLen, CK_BYTE_PTR pEncryptedData,
                  CK_ULONG_PTR pulEncryptedDataLen) {
  void *inst = 0;
  /* Fast-path precedence peek (the resolve under the state lock
   * below is authoritative; this keeps NOT_INITIALIZED first). */
  if (!haskoki_live_interval()) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  CK_RV lr = 0;
  CK_RV rv = 0;
  if (pulEncryptedDataLen == NULL_PTR) {
    return refuse_null_arg(hSession, HSK_SLOT_ENCRYPT);
  }
  if (ulDataLen > 0 && pData == NULL_PTR) {
    return refuse_null_arg(hSession, HSK_SLOT_ENCRYPT);
  }
  lr = haskoki_state_lock();
  if (lr != CKR_OK) {
    return lr;
  }
  inst = live_std();
  if (inst == 0) {
    (void)haskoki_state_unlock();
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  rv = (CK_RV)haskoki_std_encrypt(inst, (uint64_t)hSession, (uint8_t *)pData,
                                  (uint64_t)ulDataLen, (uint8_t *)pEncryptedData,
                                  (uint64_t *)pulEncryptedDataLen);
  (void)haskoki_state_unlock();
  return rv;
}

CK_RV std_EncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart,
                        CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart,
                        CK_ULONG_PTR pulEncryptedPartLen) {
  void *inst = 0;
  /* Fast-path precedence peek (the resolve under the state lock
   * below is authoritative; this keeps NOT_INITIALIZED first). */
  if (!haskoki_live_interval()) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  CK_RV lr = 0;
  CK_RV rv = 0;
  if (pulEncryptedPartLen == NULL_PTR) {
    return refuse_null_arg(hSession, HSK_SLOT_ENCRYPT);
  }
  if (ulPartLen > 0 && pPart == NULL_PTR) {
    return refuse_null_arg(hSession, HSK_SLOT_ENCRYPT);
  }
  lr = haskoki_state_lock();
  if (lr != CKR_OK) {
    return lr;
  }
  inst = live_std();
  if (inst == 0) {
    (void)haskoki_state_unlock();
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  rv = (CK_RV)haskoki_std_encrypt_update(
      inst, (uint64_t)hSession, (uint8_t *)pPart, (uint64_t)ulPartLen,
      (uint8_t *)pEncryptedPart, (uint64_t *)pulEncryptedPartLen);
  (void)haskoki_state_unlock();
  return rv;
}

CK_RV std_EncryptFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastEncryptedPart,
                       CK_ULONG_PTR pulLastEncryptedPartLen) {
  void *inst = 0;
  /* Fast-path precedence peek (the resolve under the state lock
   * below is authoritative; this keeps NOT_INITIALIZED first). */
  if (!haskoki_live_interval()) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  CK_RV lr = 0;
  CK_RV rv = 0;
  if (pulLastEncryptedPartLen == NULL_PTR) {
    return refuse_null_arg(hSession, HSK_SLOT_ENCRYPT);
  }
  lr = haskoki_state_lock();
  if (lr != CKR_OK) {
    return lr;
  }
  inst = live_std();
  if (inst == 0) {
    (void)haskoki_state_unlock();
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  rv = (CK_RV)haskoki_std_encrypt_final(inst, (uint64_t)hSession,
                                        (uint8_t *)pLastEncryptedPart,
                                        (uint64_t *)pulLastEncryptedPartLen);
  (void)haskoki_state_unlock();
  return rv;
}

CK_RV std_DecryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
                      CK_OBJECT_HANDLE hKey) {
  void *inst = 0;
  /* Fast-path precedence peek (the resolve under the state lock
   * below is authoritative; this keeps NOT_INITIALIZED first). */
  if (!haskoki_live_interval()) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  CK_RV lr = 0;
  CK_RV rv = 0;
  if (pMechanism == NULL_PTR) {
    return CKR_ARGUMENTS_BAD;
  }
  if (pMechanism->ulParameterLen > 0 && pMechanism->pParameter == NULL_PTR) {
    return CKR_ARGUMENTS_BAD;
  }
  lr = haskoki_state_lock();
  if (lr != CKR_OK) {
    return lr;
  }
  inst = live_std();
  if (inst == 0) {
    (void)haskoki_state_unlock();
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  rv = (CK_RV)haskoki_std_decrypt_init(
      inst, (uint64_t)hSession, (uint64_t)pMechanism->mechanism,
      (uint8_t *)pMechanism->pParameter, (uint64_t)pMechanism->ulParameterLen,
      (uint64_t)hKey);
  (void)haskoki_state_unlock();
  return rv;
}

CK_RV std_Decrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData,
                  CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData,
                  CK_ULONG_PTR pulDataLen) {
  void *inst = 0;
  /* Fast-path precedence peek (the resolve under the state lock
   * below is authoritative; this keeps NOT_INITIALIZED first). */
  if (!haskoki_live_interval()) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  CK_RV lr = 0;
  CK_RV rv = 0;
  if (pulDataLen == NULL_PTR) {
    return refuse_null_arg(hSession, HSK_SLOT_DECRYPT);
  }
  if (ulEncryptedDataLen > 0 && pEncryptedData == NULL_PTR) {
    return refuse_null_arg(hSession, HSK_SLOT_DECRYPT);
  }
  lr = haskoki_state_lock();
  if (lr != CKR_OK) {
    return lr;
  }
  inst = live_std();
  if (inst == 0) {
    (void)haskoki_state_unlock();
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  rv = (CK_RV)haskoki_std_decrypt(inst, (uint64_t)hSession,
                                  (uint8_t *)pEncryptedData,
                                  (uint64_t)ulEncryptedDataLen, (uint8_t *)pData,
                                  (uint64_t *)pulDataLen);
  (void)haskoki_state_unlock();
  return rv;
}

CK_RV std_DecryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart,
                        CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart,
                        CK_ULONG_PTR pulPartLen) {
  void *inst = 0;
  /* Fast-path precedence peek (the resolve under the state lock
   * below is authoritative; this keeps NOT_INITIALIZED first). */
  if (!haskoki_live_interval()) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  CK_RV lr = 0;
  CK_RV rv = 0;
  if (pulPartLen == NULL_PTR) {
    return refuse_null_arg(hSession, HSK_SLOT_DECRYPT);
  }
  if (ulEncryptedPartLen > 0 && pEncryptedPart == NULL_PTR) {
    return refuse_null_arg(hSession, HSK_SLOT_DECRYPT);
  }
  lr = haskoki_state_lock();
  if (lr != CKR_OK) {
    return lr;
  }
  inst = live_std();
  if (inst == 0) {
    (void)haskoki_state_unlock();
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  rv = (CK_RV)haskoki_std_decrypt_update(
      inst, (uint64_t)hSession, (uint8_t *)pEncryptedPart,
      (uint64_t)ulEncryptedPartLen, (uint8_t *)pPart, (uint64_t *)pulPartLen);
  (void)haskoki_state_unlock();
  return rv;
}

CK_RV std_DecryptFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastPart,
                       CK_ULONG_PTR pulLastPartLen) {
  void *inst = 0;
  /* Fast-path precedence peek (the resolve under the state lock
   * below is authoritative; this keeps NOT_INITIALIZED first). */
  if (!haskoki_live_interval()) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  CK_RV lr = 0;
  CK_RV rv = 0;
  if (pulLastPartLen == NULL_PTR) {
    return refuse_null_arg(hSession, HSK_SLOT_DECRYPT);
  }
  lr = haskoki_state_lock();
  if (lr != CKR_OK) {
    return lr;
  }
  inst = live_std();
  if (inst == 0) {
    (void)haskoki_state_unlock();
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  rv = (CK_RV)haskoki_std_decrypt_final(inst, (uint64_t)hSession,
                                        (uint8_t *)pLastPart,
                                        (uint64_t *)pulLastPartLen);
  (void)haskoki_state_unlock();
  return rv;
}

CK_RV std_GenerateRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pRandomData,
                         CK_ULONG ulRandomLen) {
  void *inst = 0;
  /* Fast-path precedence peek (the resolve under the state lock
   * below is authoritative; this keeps NOT_INITIALIZED first). */
  if (!haskoki_live_interval()) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  CK_RV lr = 0;
  CK_RV rv = 0;
  if (pRandomData == NULL_PTR) {
    return CKR_ARGUMENTS_BAD;
  }
  lr = haskoki_state_lock();
  if (lr != CKR_OK) {
    return lr;
  }
  inst = live_std();
  if (inst == 0) {
    (void)haskoki_state_unlock();
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  rv = (CK_RV)haskoki_std_generate_random(inst, (uint64_t)hSession,
                                          (uint8_t *)pRandomData,
                                          (uint64_t)ulRandomLen);
  (void)haskoki_state_unlock();
  return rv;
}

CK_RV std_SeedRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSeed,
                     CK_ULONG ulSeedLen) {
  void *inst = 0;
  /* Fast-path precedence peek (the resolve under the state lock
   * below is authoritative; this keeps NOT_INITIALIZED first). */
  if (!haskoki_live_interval()) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  CK_RV lr = 0;
  CK_RV rv = 0;
  /* No C-level NULL check here (unlike std_GenerateRandom): NULL
   * with length 0 is a vacuous OK, and the bad-session-first
   * precedence lives in Haskell, which owns the buffer checks. */
  lr = haskoki_state_lock();
  if (lr != CKR_OK) {
    return lr;
  }
  inst = live_std();
  if (inst == 0) {
    (void)haskoki_state_unlock();
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  rv = (CK_RV)haskoki_std_seed_random(inst, (uint64_t)hSession,
                                      (uint8_t *)pSeed,
                                      (uint64_t)ulSeedLen);
  (void)haskoki_state_unlock();
  return rv;
}

CK_RV std_WrapKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
                  CK_OBJECT_HANDLE hWrappingKey, CK_OBJECT_HANDLE hKey,
                  CK_BYTE_PTR pWrappedKey, CK_ULONG_PTR pulWrappedKeyLen) {
  void *inst = 0;
  /* Fast-path precedence peek (the resolve under the state lock
   * below is authoritative; this keeps NOT_INITIALIZED first). */
  if (!haskoki_live_interval()) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  CK_RV lr = 0;
  CK_RV rv = 0;
  if (pMechanism == NULL_PTR || pulWrappedKeyLen == NULL_PTR) {
    return CKR_ARGUMENTS_BAD;
  }
  if (pMechanism->ulParameterLen > 0 && pMechanism->pParameter == NULL_PTR) {
    return CKR_ARGUMENTS_BAD;
  }
  lr = haskoki_state_lock();
  if (lr != CKR_OK) {
    return lr;
  }
  inst = live_std();
  if (inst == 0) {
    (void)haskoki_state_unlock();
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  rv = (CK_RV)haskoki_std_wrap_key(
      inst, (uint64_t)hSession, (uint64_t)pMechanism->mechanism,
      (uint8_t *)pMechanism->pParameter, (uint64_t)pMechanism->ulParameterLen,
      (uint64_t)hWrappingKey, (uint64_t)hKey, (uint8_t *)pWrappedKey,
      (uint64_t *)pulWrappedKeyLen);
  (void)haskoki_state_unlock();
  return rv;
}

CK_RV std_UnwrapKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
                    CK_OBJECT_HANDLE hUnwrappingKey, CK_BYTE_PTR pWrappedKey,
                    CK_ULONG ulWrappedKeyLen, CK_ATTRIBUTE_PTR pTemplate,
                    CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey) {
  void *inst = 0;
  /* Fast-path precedence peek (the resolve under the state lock
   * below is authoritative; this keeps NOT_INITIALIZED first). */
  if (!haskoki_live_interval()) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  uint8_t *frame = NULL;
  uint64_t frameLen = 0;
  CK_RV lr = 0;
  CK_RV rv = 0;
  if (pMechanism == NULL_PTR || phKey == NULL_PTR) {
    return CKR_ARGUMENTS_BAD;
  }
  if (pMechanism->ulParameterLen > 0 && pMechanism->pParameter == NULL_PTR) {
    return CKR_ARGUMENTS_BAD;
  }
  if (ulWrappedKeyLen > 0 && pWrappedKey == NULL_PTR) {
    return CKR_ARGUMENTS_BAD;
  }
  if (ulAttributeCount > 0 && pTemplate == NULL_PTR) {
    return CKR_ARGUMENTS_BAD;
  }
  if (haskoki_std_pack_template(pTemplate, (unsigned long)ulAttributeCount,
                                &frame, &frameLen) != 0) {
    return CKR_ARGUMENTS_BAD;
  }
  lr = haskoki_state_lock();
  if (lr != CKR_OK) {
    free(frame);
    return lr;
  }
  inst = live_std();
  if (inst == 0) {
    free(frame);
    (void)haskoki_state_unlock();
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  rv = (CK_RV)haskoki_std_unwrap_key(
      inst, (uint64_t)hSession, (uint64_t)pMechanism->mechanism,
      (uint8_t *)pMechanism->pParameter, (uint64_t)pMechanism->ulParameterLen,
      (uint64_t)hUnwrappingKey, (uint8_t *)pWrappedKey,
      (uint64_t)ulWrappedKeyLen, frame, frameLen, (uint64_t *)phKey);
  (void)haskoki_state_unlock();
  free(frame);
  return rv;
}

CK_RV std_EncapsulateKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
                         CK_OBJECT_HANDLE hPublicKey, CK_ATTRIBUTE_PTR pTemplate,
                         CK_ULONG ulAttributeCount, CK_BYTE_PTR pCiphertext,
                         CK_ULONG_PTR pulCiphertextLen, CK_OBJECT_HANDLE_PTR phKey) {
  void *inst = 0;
  /* Fast-path precedence peek (the resolve under the state lock
   * below is authoritative; this keeps NOT_INITIALIZED first). */
  if (!haskoki_live_interval()) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  uint8_t *frame = NULL;
  uint64_t frameLen = 0;
  CK_RV lr = 0;
  CK_RV rv = 0;
  /* NULL pCiphertext is the length query (legal); the length
   * out-word and the key handle out-pointer are mandatory. */
  if (pMechanism == NULL_PTR || pulCiphertextLen == NULL_PTR ||
      phKey == NULL_PTR) {
    return CKR_ARGUMENTS_BAD;
  }
  if (pMechanism->ulParameterLen > 0 && pMechanism->pParameter == NULL_PTR) {
    return CKR_ARGUMENTS_BAD;
  }
  if (ulAttributeCount > 0 && pTemplate == NULL_PTR) {
    return CKR_ARGUMENTS_BAD;
  }
  if (haskoki_std_pack_template(pTemplate, (unsigned long)ulAttributeCount,
                                &frame, &frameLen) != 0) {
    return CKR_ARGUMENTS_BAD;
  }
  lr = haskoki_state_lock();
  if (lr != CKR_OK) {
    free(frame);
    return lr;
  }
  inst = live_std();
  if (inst == 0) {
    free(frame);
    (void)haskoki_state_unlock();
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  rv = (CK_RV)haskoki_std_encapsulate_key(
      inst, (uint64_t)hSession, (uint64_t)pMechanism->mechanism,
      (uint8_t *)pMechanism->pParameter, (uint64_t)pMechanism->ulParameterLen,
      (uint64_t)hPublicKey, frame, frameLen, (uint8_t *)pCiphertext,
      (uint64_t *)pulCiphertextLen, (uint64_t *)phKey);
  (void)haskoki_state_unlock();
  free(frame);
  return rv;
}

CK_RV std_DecapsulateKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
                         CK_OBJECT_HANDLE hPrivateKey, CK_ATTRIBUTE_PTR pTemplate,
                         CK_ULONG ulAttributeCount, CK_BYTE_PTR pCiphertext,
                         CK_ULONG ulCiphertextLen, CK_OBJECT_HANDLE_PTR phKey) {
  void *inst = 0;
  /* Fast-path precedence peek (the resolve under the state lock
   * below is authoritative; this keeps NOT_INITIALIZED first). */
  if (!haskoki_live_interval()) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  uint8_t *frame = NULL;
  uint64_t frameLen = 0;
  CK_RV lr = 0;
  CK_RV rv = 0;
  if (pMechanism == NULL_PTR || phKey == NULL_PTR) {
    return CKR_ARGUMENTS_BAD;
  }
  if (pMechanism->ulParameterLen > 0 && pMechanism->pParameter == NULL_PTR) {
    return CKR_ARGUMENTS_BAD;
  }
  if (ulCiphertextLen > 0 && pCiphertext == NULL_PTR) {
    return CKR_ARGUMENTS_BAD;
  }
  if (ulAttributeCount > 0 && pTemplate == NULL_PTR) {
    return CKR_ARGUMENTS_BAD;
  }
  if (haskoki_std_pack_template(pTemplate, (unsigned long)ulAttributeCount,
                                &frame, &frameLen) != 0) {
    return CKR_ARGUMENTS_BAD;
  }
  lr = haskoki_state_lock();
  if (lr != CKR_OK) {
    free(frame);
    return lr;
  }
  inst = live_std();
  if (inst == 0) {
    free(frame);
    (void)haskoki_state_unlock();
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  rv = (CK_RV)haskoki_std_decapsulate_key(
      inst, (uint64_t)hSession, (uint64_t)pMechanism->mechanism,
      (uint8_t *)pMechanism->pParameter, (uint64_t)pMechanism->ulParameterLen,
      (uint64_t)hPrivateKey, (uint8_t *)pCiphertext,
      (uint64_t)ulCiphertextLen, frame, frameLen, (uint64_t *)phKey);
  (void)haskoki_state_unlock();
  free(frame);
  return rv;
}

/* HKDF parameter classes: the engine serves expand-only and
 * extract-and-expand with the SHA-256 base-hash PRF and NULL/DATA
 * salt. Malformed calls (bad pointers, unknown salt type, no
 * stage selected) are ARGUMENTS_BAD; well-formed but unserved
 * profiles (other PRFs, salt-as-key, extract-only) are
 * MECHANISM_PARAM_INVALID. Nothing is silently reinterpreted. */
typedef enum hkdf_class {
  HKDF_SERVE = 0,
  HKDF_MALFORMED = 1,
  HKDF_UNSERVED = 2
} hkdf_class_t;

/* Native PRF hash mechanism onto the engine-local digest code
 * (core/Haskoki/Recipe/Kdf.hs kdfCodeDigest): the served class is
 * the seven SHA-2 hashes. Anything else (SHA-3, MD5, HMAC
 * mechanisms, unknown ids) maps to 0 and refuses UNSERVED. */
static uint64_t hkdf_prf_code(CK_MECHANISM_TYPE prf) {
  switch (prf) {
  case CKM_SHA_1:
    return 2ULL;
  case CKM_SHA224:
    return 3ULL;
  case CKM_SHA256:
    return 4ULL;
  case CKM_SHA384:
    return 5ULL;
  case CKM_SHA512:
    return 6ULL;
  case CKM_SHA512_224:
    return 7ULL;
  case CKM_SHA512_256:
    return 8ULL;
  default:
    return 0ULL;
  }
}

static hkdf_class_t hkdf_params_class(const CK_HKDF_PARAMS *hp) {
  if (hp->bExtract == CK_FALSE && hp->bExpand == CK_FALSE) {
    return HKDF_MALFORMED;
  }
  if (hp->ulSaltType != CKF_HKDF_SALT_NULL &&
      hp->ulSaltType != CKF_HKDF_SALT_DATA &&
      hp->ulSaltType != CKF_HKDF_SALT_KEY) {
    return HKDF_MALFORMED;
  }
  if (hp->ulSaltType == CKF_HKDF_SALT_NULL && hp->ulSaltLen != 0) {
    return HKDF_MALFORMED;
  }
  if (hp->ulSaltType == CKF_HKDF_SALT_DATA && hp->ulSaltLen > 0 &&
      hp->pSalt == NULL_PTR) {
    return HKDF_MALFORMED;
  }
  if (hp->ulSaltType == CKF_HKDF_SALT_KEY && hp->hSaltKey == 0) {
    return HKDF_MALFORMED;
  }
  if (hp->ulSaltType != CKF_HKDF_SALT_KEY && hp->hSaltKey != 0) {
    return HKDF_MALFORMED;
  }
  if (hp->ulInfoLen > 0 && hp->pInfo == NULL_PTR) {
    return HKDF_MALFORMED;
  }
  if (hkdf_prf_code(hp->prfHashMechanism) == 0ULL) {
    return HKDF_UNSERVED;
  }
  if (hp->ulSaltType == CKF_HKDF_SALT_KEY) {
    return HKDF_UNSERVED;
  }
  if (hp->bExtract != CK_FALSE && hp->bExpand == CK_FALSE) {
    return HKDF_UNSERVED;
  }
  return HKDF_SERVE;
}

/* Derive mechanisms served through the opaque Haskell intake
 * (ECDH + DH + SHA-KDF rows + TLS-PRF + SP 800-108 rows + TLS-KDF
 * rows + the pub-from-priv row; mirrors the
 * Haskoki.Recipe.Ecdh/Dh/Kdf/TlsPrf/Sp800108/TlsKdf/Ssl3/PubPriv
 * tables — Haskell re-checks membership before planning). */
static int derive_opaque_ok(CK_MECHANISM_TYPE mech) {
  switch (mech) {
  case CKM_TLS_PRF:
  case CKM_SP800_108_COUNTER_KDF:
  case CKM_SP800_108_FEEDBACK_KDF:
  case CKM_SP800_108_DOUBLE_PIPELINE_KDF:
  case CKM_TLS_MASTER_KEY_DERIVE:
  case CKM_TLS_MASTER_KEY_DERIVE_DH:
  case CKM_TLS12_MASTER_KEY_DERIVE:
  case CKM_TLS12_MASTER_KEY_DERIVE_DH:
  case CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE:
  case CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE_DH:
  case CKM_TLS12_KDF:
  case CKM_TLS_KDF:
  case CKM_BLAKE2B_160_KEY_DERIVE:
  case CKM_BLAKE2B_256_KEY_DERIVE:
  case CKM_BLAKE2B_384_KEY_DERIVE:
  case CKM_BLAKE2B_512_KEY_DERIVE:
  case CKM_AES_CBC_ENCRYPT_DATA:
  case CKM_AES_ECB_ENCRYPT_DATA:
  case CKM_ARIA_CBC_ENCRYPT_DATA:
  case CKM_ARIA_ECB_ENCRYPT_DATA:
  case CKM_CAMELLIA_CBC_ENCRYPT_DATA:
  case CKM_CAMELLIA_ECB_ENCRYPT_DATA:
  case CKM_DES3_CBC_ENCRYPT_DATA:
  case CKM_DES3_ECB_ENCRYPT_DATA:
  case CKM_ECDH1_DERIVE:
  case CKM_ECDH1_COFACTOR_DERIVE:
  case CKM_DH_PKCS_DERIVE:
  case CKM_X9_42_DH_DERIVE:
  case CKM_MD5_KEY_DERIVATION:
  case CKM_SHAKE_128_KEY_DERIVATION:
  case CKM_SHAKE_256_KEY_DERIVATION:
  case CKM_SHA1_KEY_DERIVATION:
  case CKM_SHA224_KEY_DERIVATION:
  case CKM_SHA256_KEY_DERIVATION:
  case CKM_SHA384_KEY_DERIVATION:
  case CKM_SHA512_KEY_DERIVATION:
  case CKM_SHA512_224_KEY_DERIVATION:
  case CKM_SHA512_256_KEY_DERIVATION:
  case CKM_SHA3_224_KEY_DERIVATION:
  case CKM_SHA3_256_KEY_DERIVATION:
  case CKM_SHA3_384_KEY_DERIVATION:
  case CKM_SHA3_512_KEY_DERIVATION:
  case CKM_IKE2_PRF_PLUS_DERIVE:
  case CKM_IKE_PRF_DERIVE:
  case CKM_IKE1_PRF_DERIVE:
  case CKM_IKE1_EXTENDED_DERIVE:
  case CKM_CONCATENATE_BASE_AND_KEY:
  case CKM_CONCATENATE_BASE_AND_DATA:
  case CKM_CONCATENATE_DATA_AND_BASE:
  case CKM_XOR_BASE_AND_DATA:
  case CKM_EXTRACT_KEY_FROM_KEY:
  case CKM_TLS_KEY_AND_MAC_DERIVE:
  case CKM_TLS12_KEY_AND_MAC_DERIVE:
  case CKM_TLS12_KEY_SAFE_DERIVE:
  case CKM_SSL3_MASTER_KEY_DERIVE:
  case CKM_SSL3_MASTER_KEY_DERIVE_DH:
  case CKM_SSL3_KEY_AND_MAC_DERIVE:
  case CKM_PUB_KEY_FROM_PRIV_KEY:
    return 1;
  default:
    return 0;
  }
}

/* The key-material quartet accepts a NULL phKey: its outputs live in
 * the mechanism params (v3.2 §6.39.6/§6.40.6: phKey "should be a
 * NULL_PTR"). Every other row still demands the slot. */
static int derive_null_phkey_ok(CK_MECHANISM_TYPE mech) {
  return mech == CKM_TLS_KEY_AND_MAC_DERIVE ||
         mech == CKM_TLS12_KEY_AND_MAC_DERIVE ||
         mech == CKM_TLS12_KEY_SAFE_DERIVE ||
         mech == CKM_SSL3_KEY_AND_MAC_DERIVE;
}

/* Opaque derive arm: pack the template frame and forward the
 * mechanism id plus the raw parameter image; struct decoding and
 * all checks after the frame pack run in Haskell (ECDH base
 * resolution and the EC key-type check run before parameter shape
 * is examined). */
static CK_RV std_derive_opaque(CK_SESSION_HANDLE hSession,
                               CK_MECHANISM_PTR pMechanism,
                               CK_OBJECT_HANDLE hBaseKey,
                               CK_ATTRIBUTE_PTR pTemplate,
                               CK_ULONG ulAttributeCount,
                               CK_OBJECT_HANDLE_PTR phKey) {
  void *inst = 0;
  uint8_t *frame = NULL;
  uint64_t frameLen = 0;
  CK_RV lr = 0;
  CK_RV rv = 0;
  if (ulAttributeCount > 0 && pTemplate == NULL_PTR) {
    return CKR_ARGUMENTS_BAD;
  }
  if (haskoki_std_pack_template(pTemplate, (unsigned long)ulAttributeCount,
                                &frame, &frameLen) != 0) {
    return CKR_ARGUMENTS_BAD;
  }
  lr = haskoki_state_lock();
  if (lr != CKR_OK) {
    free(frame);
    return lr;
  }
  inst = live_std();
  if (inst == 0) {
    free(frame);
    (void)haskoki_state_unlock();
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  rv = (CK_RV)haskoki_std_derive_opaque(inst, (uint64_t)hSession,
                                        (uint64_t)pMechanism->mechanism,
                                        (uint8_t *)pMechanism->pParameter,
                                        (uint64_t)pMechanism->ulParameterLen,
                                        (uint64_t)hBaseKey, frame, frameLen,
                                        (uint64_t *)phKey);
  (void)haskoki_state_unlock();
  free(frame);
  return rv;
}

CK_RV std_DeriveKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
                    CK_OBJECT_HANDLE hBaseKey, CK_ATTRIBUTE_PTR pTemplate,
                    CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey) {
  void *inst = 0;
  /* Fast-path precedence peek (the resolve under the state lock
   * below is authoritative; this keeps NOT_INITIALIZED first). */
  if (!haskoki_live_interval()) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  const CK_HKDF_PARAMS *hp = NULL;
  uint8_t *frame = NULL;
  uint64_t frameLen = 0;
  CK_RV lr = 0;
  CK_RV rv = 0;
  if (pMechanism == NULL_PTR) {
    return CKR_ARGUMENTS_BAD;
  }
  if (phKey == NULL_PTR && !derive_null_phkey_ok(pMechanism->mechanism)) {
    return CKR_ARGUMENTS_BAD;
  }
  if (pMechanism->mechanism != CKM_HKDF_DERIVE &&
      pMechanism->mechanism != CKM_HKDF_DATA) {
    if (!derive_opaque_ok(pMechanism->mechanism)) {
      return CKR_FUNCTION_NOT_SUPPORTED;
    }
    return std_derive_opaque(hSession, pMechanism, hBaseKey, pTemplate,
                             ulAttributeCount, phKey);
  }
  if (pMechanism->pParameter == NULL_PTR ||
      pMechanism->ulParameterLen != (CK_ULONG)sizeof(CK_HKDF_PARAMS)) {
    return CKR_ARGUMENTS_BAD;
  }
  hp = (const CK_HKDF_PARAMS *)pMechanism->pParameter;
  {
    hkdf_class_t cls = hkdf_params_class(hp);
    if (cls == HKDF_MALFORMED) {
      return CKR_ARGUMENTS_BAD;
    }
    if (cls == HKDF_UNSERVED) {
      return CKR_MECHANISM_PARAM_INVALID;
    }
  }
  if (ulAttributeCount > 0 && pTemplate == NULL_PTR) {
    return CKR_ARGUMENTS_BAD;
  }
  if (haskoki_std_pack_template(pTemplate, (unsigned long)ulAttributeCount,
                                &frame, &frameLen) != 0) {
    return CKR_ARGUMENTS_BAD;
  }
  lr = haskoki_state_lock();
  if (lr != CKR_OK) {
    free(frame);
    return lr;
  }
  inst = live_std();
  if (inst == 0) {
    free(frame);
    (void)haskoki_state_unlock();
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  {
    uint64_t hkdfMode = (hp->bExtract == CK_FALSE ? 0ULL : 1ULL) |
                        (hp->bExpand == CK_FALSE ? 0ULL : 2ULL);
    uint64_t hkdfPrf = hkdf_prf_code(hp->prfHashMechanism);
    rv = (CK_RV)haskoki_std_derive_hkdf(inst, (uint64_t)hSession,
                                        (uint64_t)pMechanism->mechanism,
                                        (uint8_t *)hp->pInfo,
                                        (uint64_t)hp->ulInfoLen,
                                        (uint8_t *)hp->pSalt,
                                        (uint64_t)hp->ulSaltLen,
                                        hkdfMode, hkdfPrf,
                                        (uint64_t)hBaseKey, frame, frameLen,
                                        (uint64_t *)phKey);
  }
  (void)haskoki_state_unlock();
  free(frame);
  return rv;
}

CK_RV std_MessageEncryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM *pMechanism, CK_OBJECT_HANDLE hKey) {
  void *inst;
  CK_RV lr, rv;
  if (!haskoki_live_interval()) return CKR_CRYPTOKI_NOT_INITIALIZED;
  if (pMechanism == NULL) return CKR_ARGUMENTS_BAD;
  if (pMechanism->pParameter == NULL && pMechanism->ulParameterLen > 0) return CKR_ARGUMENTS_BAD;
  lr = haskoki_state_lock();
  if (lr != CKR_OK) return lr;
  inst = live_std();
  if (inst == NULL) {
    (void)haskoki_state_unlock();
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  rv = (CK_RV)haskoki_std_message_encrypt_init(inst, hSession, pMechanism->mechanism, (unsigned char *)pMechanism->pParameter, pMechanism->ulParameterLen, hKey);
  (void)haskoki_state_unlock();
  return rv;
}

CK_RV std_EncryptMessage(CK_SESSION_HANDLE hSession, void *pParameter, CK_ULONG ulParameterLen, CK_BYTE *pAssociatedData, CK_ULONG ulAssociatedDataLen, CK_BYTE *pPlaintext, CK_ULONG ulPlaintextLen, CK_BYTE *pCiphertext, CK_ULONG *pulCiphertextLen) {
  void *inst;
  CK_RV lr, rv;
  if (!haskoki_live_interval()) return CKR_CRYPTOKI_NOT_INITIALIZED;
  if (pulCiphertextLen == NULL) return CKR_ARGUMENTS_BAD;
  if (pParameter == NULL && ulParameterLen > 0) return CKR_ARGUMENTS_BAD;
  if (pAssociatedData == NULL && ulAssociatedDataLen > 0) return CKR_ARGUMENTS_BAD;
  if (pPlaintext == NULL && ulPlaintextLen > 0) return CKR_ARGUMENTS_BAD;
  lr = haskoki_state_lock();
  if (lr != CKR_OK) return lr;
  inst = live_std();
  if (inst == NULL) {
    (void)haskoki_state_unlock();
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  rv = (CK_RV)haskoki_std_message_encrypt(inst, hSession, (unsigned char *)pParameter, ulParameterLen, pAssociatedData, ulAssociatedDataLen, pPlaintext, ulPlaintextLen, pCiphertext, pulCiphertextLen);
  (void)haskoki_state_unlock();
  return rv;
}

CK_RV std_EncryptMessageBegin(CK_SESSION_HANDLE hSession, void *pParameter, CK_ULONG ulParameterLen, CK_BYTE *pAssociatedData, CK_ULONG ulAssociatedDataLen) {
  void *inst;
  CK_RV lr, rv;
  if (!haskoki_live_interval()) return CKR_CRYPTOKI_NOT_INITIALIZED;
  if (pParameter == NULL && ulParameterLen > 0) return CKR_ARGUMENTS_BAD;
  if (pAssociatedData == NULL && ulAssociatedDataLen > 0) return CKR_ARGUMENTS_BAD;
  lr = haskoki_state_lock();
  if (lr != CKR_OK) return lr;
  inst = live_std();
  if (inst == NULL) {
    (void)haskoki_state_unlock();
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  rv = (CK_RV)haskoki_std_message_encrypt_begin(inst, hSession, (unsigned char *)pParameter, ulParameterLen, pAssociatedData, ulAssociatedDataLen);
  (void)haskoki_state_unlock();
  return rv;
}

CK_RV std_EncryptMessageNext(CK_SESSION_HANDLE hSession, void *pParameter, CK_ULONG ulParameterLen, CK_BYTE *pPlaintextPart, CK_ULONG ulPlaintextPartLen, CK_BYTE *pCiphertextPart, CK_ULONG *pulCiphertextPartLen, CK_FLAGS flags) {
  void *inst;
  CK_RV lr, rv;
  if (!haskoki_live_interval()) return CKR_CRYPTOKI_NOT_INITIALIZED;
  if (pulCiphertextPartLen == NULL) return CKR_ARGUMENTS_BAD;
  if (pParameter == NULL && ulParameterLen > 0) return CKR_ARGUMENTS_BAD;
  if (pPlaintextPart == NULL && ulPlaintextPartLen > 0) return CKR_ARGUMENTS_BAD;
  if ((flags & ~CKF_END_OF_MESSAGE) != 0) return CKR_ARGUMENTS_BAD;
  lr = haskoki_state_lock();
  if (lr != CKR_OK) return lr;
  inst = live_std();
  if (inst == NULL) {
    (void)haskoki_state_unlock();
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  rv = (CK_RV)haskoki_std_message_encrypt_next(inst, hSession, (unsigned char *)pParameter, ulParameterLen, pPlaintextPart, ulPlaintextPartLen, pCiphertextPart, pulCiphertextPartLen, (flags & CKF_END_OF_MESSAGE) ? 1UL : 0UL);
  (void)haskoki_state_unlock();
  return rv;
}

CK_RV std_MessageEncryptFinal(CK_SESSION_HANDLE hSession) {
  void *inst;
  CK_RV lr, rv;
  if (!haskoki_live_interval()) return CKR_CRYPTOKI_NOT_INITIALIZED;
  lr = haskoki_state_lock();
  if (lr != CKR_OK) return lr;
  inst = live_std();
  if (inst == NULL) {
    (void)haskoki_state_unlock();
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  rv = (CK_RV)haskoki_std_message_encrypt_final(inst, hSession);
  (void)haskoki_state_unlock();
  return rv;
}

CK_RV std_MessageDecryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM *pMechanism, CK_OBJECT_HANDLE hKey) {
  void *inst;
  CK_RV lr, rv;
  if (!haskoki_live_interval()) return CKR_CRYPTOKI_NOT_INITIALIZED;
  if (pMechanism == NULL) return CKR_ARGUMENTS_BAD;
  if (pMechanism->pParameter == NULL && pMechanism->ulParameterLen > 0) return CKR_ARGUMENTS_BAD;
  lr = haskoki_state_lock();
  if (lr != CKR_OK) return lr;
  inst = live_std();
  if (inst == NULL) {
    (void)haskoki_state_unlock();
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  rv = (CK_RV)haskoki_std_message_decrypt_init(inst, hSession, pMechanism->mechanism, (unsigned char *)pMechanism->pParameter, pMechanism->ulParameterLen, hKey);
  (void)haskoki_state_unlock();
  return rv;
}

CK_RV std_DecryptMessage(CK_SESSION_HANDLE hSession, void *pParameter, CK_ULONG ulParameterLen, CK_BYTE *pAssociatedData, CK_ULONG ulAssociatedDataLen, CK_BYTE *pCiphertext, CK_ULONG ulCiphertextLen, CK_BYTE *pPlaintext, CK_ULONG *pulPlaintextLen) {
  void *inst;
  CK_RV lr, rv;
  if (!haskoki_live_interval()) return CKR_CRYPTOKI_NOT_INITIALIZED;
  if (pulPlaintextLen == NULL) return CKR_ARGUMENTS_BAD;
  if (pParameter == NULL && ulParameterLen > 0) return CKR_ARGUMENTS_BAD;
  if (pAssociatedData == NULL && ulAssociatedDataLen > 0) return CKR_ARGUMENTS_BAD;
  if (pCiphertext == NULL && ulCiphertextLen > 0) return CKR_ARGUMENTS_BAD;
  lr = haskoki_state_lock();
  if (lr != CKR_OK) return lr;
  inst = live_std();
  if (inst == NULL) {
    (void)haskoki_state_unlock();
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  rv = (CK_RV)haskoki_std_message_decrypt(inst, hSession, (unsigned char *)pParameter, ulParameterLen, pAssociatedData, ulAssociatedDataLen, pCiphertext, ulCiphertextLen, pPlaintext, pulPlaintextLen);
  (void)haskoki_state_unlock();
  return rv;
}

CK_RV std_DecryptMessageBegin(CK_SESSION_HANDLE hSession, void *pParameter, CK_ULONG ulParameterLen, CK_BYTE *pAssociatedData, CK_ULONG ulAssociatedDataLen) {
  void *inst;
  CK_RV lr, rv;
  if (!haskoki_live_interval()) return CKR_CRYPTOKI_NOT_INITIALIZED;
  if (pParameter == NULL && ulParameterLen > 0) return CKR_ARGUMENTS_BAD;
  if (pAssociatedData == NULL && ulAssociatedDataLen > 0) return CKR_ARGUMENTS_BAD;
  lr = haskoki_state_lock();
  if (lr != CKR_OK) return lr;
  inst = live_std();
  if (inst == NULL) {
    (void)haskoki_state_unlock();
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  rv = (CK_RV)haskoki_std_message_decrypt_begin(inst, hSession, (unsigned char *)pParameter, ulParameterLen, pAssociatedData, ulAssociatedDataLen);
  (void)haskoki_state_unlock();
  return rv;
}

CK_RV std_DecryptMessageNext(CK_SESSION_HANDLE hSession, void *pParameter, CK_ULONG ulParameterLen, CK_BYTE *pCiphertextPart, CK_ULONG ulCiphertextPartLen, CK_BYTE *pPlaintextPart, CK_ULONG *pulPlaintextPartLen, CK_FLAGS flags) {
  void *inst;
  CK_RV lr, rv;
  if (!haskoki_live_interval()) return CKR_CRYPTOKI_NOT_INITIALIZED;
  if (pulPlaintextPartLen == NULL) return CKR_ARGUMENTS_BAD;
  if (pParameter == NULL && ulParameterLen > 0) return CKR_ARGUMENTS_BAD;
  if (pCiphertextPart == NULL && ulCiphertextPartLen > 0) return CKR_ARGUMENTS_BAD;
  if ((flags & ~CKF_END_OF_MESSAGE) != 0) return CKR_ARGUMENTS_BAD;
  lr = haskoki_state_lock();
  if (lr != CKR_OK) return lr;
  inst = live_std();
  if (inst == NULL) {
    (void)haskoki_state_unlock();
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  rv = (CK_RV)haskoki_std_message_decrypt_next(inst, hSession, (unsigned char *)pParameter, ulParameterLen, pCiphertextPart, ulCiphertextPartLen, pPlaintextPart, pulPlaintextPartLen, (flags & CKF_END_OF_MESSAGE) ? 1UL : 0UL);
  (void)haskoki_state_unlock();
  return rv;
}

CK_RV std_MessageDecryptFinal(CK_SESSION_HANDLE hSession) {
  void *inst;
  CK_RV lr, rv;
  if (!haskoki_live_interval()) return CKR_CRYPTOKI_NOT_INITIALIZED;
  lr = haskoki_state_lock();
  if (lr != CKR_OK) return lr;
  inst = live_std();
  if (inst == NULL) {
    (void)haskoki_state_unlock();
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  rv = (CK_RV)haskoki_std_message_decrypt_final(inst, hSession);
  (void)haskoki_state_unlock();
  return rv;
}

CK_RV std_MessageSignInit(CK_SESSION_HANDLE hSession, CK_MECHANISM *pMechanism, CK_OBJECT_HANDLE hKey) {
  void *inst;
  CK_RV lr, rv;
  if (!haskoki_live_interval()) return CKR_CRYPTOKI_NOT_INITIALIZED;
  if (pMechanism == NULL) return CKR_ARGUMENTS_BAD;
  if (pMechanism->pParameter == NULL && pMechanism->ulParameterLen > 0) return CKR_ARGUMENTS_BAD;
  lr = haskoki_state_lock();
  if (lr != CKR_OK) return lr;
  inst = live_std();
  if (inst == NULL) {
    (void)haskoki_state_unlock();
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  rv = (CK_RV)haskoki_std_message_sign_init(inst, hSession, pMechanism->mechanism, (unsigned char *)pMechanism->pParameter, pMechanism->ulParameterLen, hKey);
  (void)haskoki_state_unlock();
  return rv;
}

CK_RV std_SignMessage(CK_SESSION_HANDLE hSession, void *pParameter, CK_ULONG ulParameterLen, CK_BYTE *pData, CK_ULONG ulDataLen, CK_BYTE *pSignature, CK_ULONG *pulSignatureLen) {
  void *inst;
  CK_RV lr, rv;
  if (!haskoki_live_interval()) return CKR_CRYPTOKI_NOT_INITIALIZED;
  if (pulSignatureLen == NULL) return CKR_ARGUMENTS_BAD;
  if (pParameter == NULL && ulParameterLen > 0) return CKR_ARGUMENTS_BAD;
  if (pData == NULL && ulDataLen > 0) return CKR_ARGUMENTS_BAD;
  lr = haskoki_state_lock();
  if (lr != CKR_OK) return lr;
  inst = live_std();
  if (inst == NULL) {
    (void)haskoki_state_unlock();
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  rv = (CK_RV)haskoki_std_message_sign(inst, hSession, (unsigned char *)pParameter, ulParameterLen, pData, ulDataLen, pSignature, pulSignatureLen);
  (void)haskoki_state_unlock();
  return rv;
}

CK_RV std_SignMessageBegin(CK_SESSION_HANDLE hSession, void *pParameter, CK_ULONG ulParameterLen) {
  void *inst;
  CK_RV lr, rv;
  if (!haskoki_live_interval()) return CKR_CRYPTOKI_NOT_INITIALIZED;
  if (pParameter == NULL && ulParameterLen > 0) return CKR_ARGUMENTS_BAD;
  lr = haskoki_state_lock();
  if (lr != CKR_OK) return lr;
  inst = live_std();
  if (inst == NULL) {
    (void)haskoki_state_unlock();
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  rv = (CK_RV)haskoki_std_message_sign_begin(inst, hSession, (unsigned char *)pParameter, ulParameterLen);
  (void)haskoki_state_unlock();
  return rv;
}

CK_RV std_SignMessageNext(CK_SESSION_HANDLE hSession, void *pParameter, CK_ULONG ulParameterLen, CK_BYTE *pDataPart, CK_ULONG ulDataPartLen, CK_BYTE *pSignature, CK_ULONG *pulSignatureLen) {
  void *inst;
  CK_RV lr, rv;
  if (!haskoki_live_interval()) return CKR_CRYPTOKI_NOT_INITIALIZED;
  if (pParameter == NULL && ulParameterLen > 0) return CKR_ARGUMENTS_BAD;
  if (pDataPart == NULL && ulDataPartLen > 0) return CKR_ARGUMENTS_BAD;
  lr = haskoki_state_lock();
  if (lr != CKR_OK) return lr;
  inst = live_std();
  if (inst == NULL) {
    (void)haskoki_state_unlock();
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  rv = (CK_RV)haskoki_std_message_sign_next(inst, hSession, (unsigned char *)pParameter, ulParameterLen, pDataPart, ulDataPartLen, pSignature, pulSignatureLen);
  (void)haskoki_state_unlock();
  return rv;
}

CK_RV std_MessageSignFinal(CK_SESSION_HANDLE hSession) {
  void *inst;
  CK_RV lr, rv;
  if (!haskoki_live_interval()) return CKR_CRYPTOKI_NOT_INITIALIZED;
  lr = haskoki_state_lock();
  if (lr != CKR_OK) return lr;
  inst = live_std();
  if (inst == NULL) {
    (void)haskoki_state_unlock();
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  rv = (CK_RV)haskoki_std_message_sign_final(inst, hSession);
  (void)haskoki_state_unlock();
  return rv;
}

CK_RV std_MessageVerifyInit(CK_SESSION_HANDLE hSession, CK_MECHANISM *pMechanism, CK_OBJECT_HANDLE hKey) {
  void *inst;
  CK_RV lr, rv;
  if (!haskoki_live_interval()) return CKR_CRYPTOKI_NOT_INITIALIZED;
  if (pMechanism == NULL) return CKR_ARGUMENTS_BAD;
  if (pMechanism->pParameter == NULL && pMechanism->ulParameterLen > 0) return CKR_ARGUMENTS_BAD;
  lr = haskoki_state_lock();
  if (lr != CKR_OK) return lr;
  inst = live_std();
  if (inst == NULL) {
    (void)haskoki_state_unlock();
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  rv = (CK_RV)haskoki_std_message_verify_init(inst, hSession, pMechanism->mechanism, (unsigned char *)pMechanism->pParameter, pMechanism->ulParameterLen, hKey);
  (void)haskoki_state_unlock();
  return rv;
}

CK_RV std_VerifyMessage(CK_SESSION_HANDLE hSession, void *pParameter, CK_ULONG ulParameterLen, CK_BYTE *pData, CK_ULONG ulDataLen, CK_BYTE *pSignature, CK_ULONG ulSignatureLen) {
  void *inst;
  CK_RV lr, rv;
  if (!haskoki_live_interval()) return CKR_CRYPTOKI_NOT_INITIALIZED;
  if (pParameter == NULL && ulParameterLen > 0) return CKR_ARGUMENTS_BAD;
  if (pData == NULL && ulDataLen > 0) return CKR_ARGUMENTS_BAD;
  if (pSignature == NULL && ulSignatureLen > 0) return CKR_ARGUMENTS_BAD;
  lr = haskoki_state_lock();
  if (lr != CKR_OK) return lr;
  inst = live_std();
  if (inst == NULL) {
    (void)haskoki_state_unlock();
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  rv = (CK_RV)haskoki_std_message_verify(inst, hSession, (unsigned char *)pParameter, ulParameterLen, pData, ulDataLen, pSignature, ulSignatureLen);
  (void)haskoki_state_unlock();
  return rv;
}

CK_RV std_VerifyMessageBegin(CK_SESSION_HANDLE hSession, void *pParameter, CK_ULONG ulParameterLen) {
  void *inst;
  CK_RV lr, rv;
  if (!haskoki_live_interval()) return CKR_CRYPTOKI_NOT_INITIALIZED;
  if (pParameter == NULL && ulParameterLen > 0) return CKR_ARGUMENTS_BAD;
  lr = haskoki_state_lock();
  if (lr != CKR_OK) return lr;
  inst = live_std();
  if (inst == NULL) {
    (void)haskoki_state_unlock();
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  rv = (CK_RV)haskoki_std_message_verify_begin(inst, hSession, (unsigned char *)pParameter, ulParameterLen);
  (void)haskoki_state_unlock();
  return rv;
}

CK_RV std_VerifyMessageNext(CK_SESSION_HANDLE hSession, void *pParameter, CK_ULONG ulParameterLen, CK_BYTE *pDataPart, CK_ULONG ulDataPartLen, CK_BYTE *pSignature, CK_ULONG ulSignatureLen) {
  void *inst;
  CK_RV lr, rv;
  if (!haskoki_live_interval()) return CKR_CRYPTOKI_NOT_INITIALIZED;
  if (pParameter == NULL && ulParameterLen > 0) return CKR_ARGUMENTS_BAD;
  if (pDataPart == NULL && ulDataPartLen > 0) return CKR_ARGUMENTS_BAD;
  if (pSignature == NULL && ulSignatureLen > 0) return CKR_ARGUMENTS_BAD;
  lr = haskoki_state_lock();
  if (lr != CKR_OK) return lr;
  inst = live_std();
  if (inst == NULL) {
    (void)haskoki_state_unlock();
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  rv = (CK_RV)haskoki_std_message_verify_next(inst, hSession, (unsigned char *)pParameter, ulParameterLen, pDataPart, ulDataPartLen, pSignature, ulSignatureLen);
  (void)haskoki_state_unlock();
  return rv;
}

CK_RV std_MessageVerifyFinal(CK_SESSION_HANDLE hSession) {
  void *inst;
  CK_RV lr, rv;
  if (!haskoki_live_interval()) return CKR_CRYPTOKI_NOT_INITIALIZED;
  lr = haskoki_state_lock();
  if (lr != CKR_OK) return lr;
  inst = live_std();
  if (inst == NULL) {
    (void)haskoki_state_unlock();
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  rv = (CK_RV)haskoki_std_message_verify_final(inst, hSession);
  (void)haskoki_state_unlock();
  return rv;
}

int haskoki_std_pack_template(const void *tmpl, unsigned long count,
                              uint8_t **out, uint64_t *out_len) {
  const CK_ATTRIBUTE_PTR attrs = (const CK_ATTRIBUTE_PTR)tmpl;
  uint64_t total = 8;
  uint8_t *buf = NULL;
  uint8_t *p = NULL;
  unsigned long i = 0;
  if (out == NULL || out_len == NULL) {
    return -1;
  }
  *out = NULL;
  *out_len = 0;
  if (count > HASKOKI_STD_TEMPLATE_MAX_ATTRS) {
    return -1;
  }
  if (count > 0 && tmpl == NULL) {
    return -1;
  }
  for (i = 0; i < count; i++) {
    uint64_t vlen = 0;
    if (attrs[i].pValue == NULL_PTR && attrs[i].ulValueLen != 0) {
      return -1;
    }
    if (attrs[i].ulValueLen > STD_VALUE_MAX) {
      return -1;
    }
    vlen = (uint64_t)attrs[i].ulValueLen;
    if (total > (uint64_t)STD_FRAME_MAX - 16U - vlen) {
      return -1;
    }
    total += 16U + vlen;
  }
  buf = (uint8_t *)malloc((size_t)total);
  if (buf == NULL) {
    return -1;
  }
  p = buf;
  put_u64le(p, (uint64_t)count);
  p += 8;
  for (i = 0; i < count; i++) {
    uint64_t vlen = (uint64_t)attrs[i].ulValueLen;
    put_u64le(p, (uint64_t)attrs[i].type);
    put_u64le(p + 8, vlen);
    if (vlen > 0) {
      memcpy(p + 16, attrs[i].pValue, (size_t)vlen);
    }
    p += 16 + vlen;
  }
  *out = buf;
  *out_len = total;
  return 0;
}
