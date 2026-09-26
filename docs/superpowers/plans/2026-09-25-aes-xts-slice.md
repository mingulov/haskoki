# AES XTS slice plan: disk mode (0x1071), tweak-param shape

Target: `acvp/aes/test_xts.py` 1200 skipped (KAT r9) + mechanism
matrix legs (`test_mech_flags`/`test_mech_probe`/`test_mech_negative`
over the new row).

## Discovery (proven, not assumed)

- Spike (no commit): provider XTS C probe — DONE. OpenSSL 4.0.2
  default provider fetches `AES-128-XTS` (key 32) and
  `AES-256-XTS` (key 64), 16-byte tweak IV, block size 1.
  One-shot no-pad: 32B and ragged 20B roundtrip
  length-preserved, byte-identical to the `cryptography`
  oracle. 15B input refused at encrypt-update; equal-halves
  keys (data key == tweak key) refused at init (provider
  weak-key check); `AES-192-XTS` absent (no 192 width,
  honest).
- Oracle shape (`test_xts.py`): keys are `CKK_AES_XTS`
  (0x35) imported by value (32/64 bytes, no keygen legs —
  `CKM_AES_XTS_KEY_GEN` stays catalog-only); the 16-byte
  tweak rides as the raw mechanism parameter (CBC shape);
  each `C_Encrypt`/`C_Decrypt` call carries one data unit
  (>= 16 bytes, ragged tails allowed via stealing); the
  canonical probe is AES-128-XTS over key/tweak/pt
  `range(32)`/`range(16)`/`range(32)`.
- One-shot only in the oracle (`encrypt_single` per data
  unit); multipart XTS is unexercised anywhere.
- `CKK_AES_XTS` is already in the generated key-type table;
  import needs no new code (structural template checks only).

## Design

- Shim `hsk_ossl4_cipher_xts` + header contract (fetch by
  ciphername, key/iv checks, >= 16 floor at both layers,
  no-pad one-shot enc/dec; equal-halves init refusal maps
  to the bad-key code, provider-owned).
- FFI `Raw.cipherXts` binding (mirror `cipherWrap`).
- Engine `C_AES128_XTS` (32B key) / `C_AES256_XTS` (64B key):
  fetch names, key/length gates, runner, capability sets,
  notes, probes. No 192 (provider-absent).
- Driver: `cipherCtor` x 2 for 0x1071 by key length (32/64)
  with 16-byte tweak params.
- Recipe row: block 16, keys [32, 64], iv 16, no pad, type
  `CKK_AES_XTS`; params codec `iv-bytes/1`.
- Planners: `isXtsMech` arms mirroring CTS (encrypt floor
  >= 16 any length; decrypt finish stages answers >= 16).
  Multipart never streams (buffer-to-final, OFB precedent:
  within-call tweak evolution is GF doubling per block,
  planner-hostile; one-shot covers the oracle and the
  buffered path stays correct).
- Synthetic: keyed length-preserving stub with its own
  domain separator (parity, not vectors).
- Registry/catalog: 1 JSON row (0x1071), flags
  [ENCRYPT, DECRYPT], encrypt/decrypt routes, bytes 32-64;
  regen + pin updates (120 behavior / 118 real).
- Confusion boundary: `publishUnwrap` learns `CKK_AES_XTS`
  (32/64) alongside AES/DES3 (no wrap routes mint XTS
  today; the fixed-length set stays complete).
- Recipe module doc: drop `CKM_AES_XTS` from the deferred
  list.

## Committed tests (failing test first)

- `OpenSSLSpec.caseAesXts`: ACVP vectors as independent
  oracles (hardcoded, hermetic) enc+dec x 128/256, ragged
  lengths, short-input + bad-key negatives.
- `RecipeCipherSpec`: groupShape +1, params/init/driver/
  geometry legs, >= 16 floor.
- `OperationSmokeSpec`: XTS roundtrip through cipher slots.
- `KeyManagementSpec`: XTS confusion legs (32-as-XTS
  commits, 20-as-XTS refuses).
- `OperationSpec` (or split suite): XTS buffers updates to
  final (OFB precedent pin).
- Caps pins (both engines), registry/exhaustiveness/ctl/
  honesty pins, C discovery updates.
- C: XTS encrypt/decrypt leg in `consumer_roundtrip.c`
  (import + roundtrip + short-input refusal).

## Lanes + gates + docs

- Targeted `test_xts.py` r1 → expect 1200 newly collected
  legs passing; fast + KAT full lanes with per-unit diffs vs
  r27/r9; static gates (history-codes pre-broken at HEAD, zero
  new hits); triage entry (Round 11 + KAT r10); single slice
  commit.
