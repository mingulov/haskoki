# AES wrap/KWP slice plan: Key Wrap / KWP (0x2109/0x210A/0x210B)

Target: `acvp/aes/test_wrap.py` 7200 skipped + `test_mech_wrap.py`
AES legs + security/error-path wrap files (~58 skipped:
`test_error_path_kwp`, `test_aes_keywrap_pad_overflow`,
`test_unwrap_reimport`, `test_aead_wrap_outputs`,
`test_authenticated_wrap`, `ckr/test_ckr_wrap`).

## Discovery (proven, not assumed)

- Spike (no commit): provider wrap C probes — DONE. OpenSSL 4.0.2
  default provider fetches `AES-{128,192,256}-WRAP` and
  `AES-{128,192,256}-WRAP-PAD` (no legacy flag, libctx
  discipline kept). One-shot no-pad: KW 16B→24B / 24B→32B
  (+8 IV, RFC 3394); KWP 1B→16B / 7B→16B / 20B→32B
  (RFC 5649). KW refuses 8B input at encrypt-update (provider
  minimum is 16B); decrypt integrity failures (corrupt/trunc)
  surface at decrypt-UPDATE, not final, for both modes.
- Dual surface (test_wrap.py header cites OASIS v3.2):
  CKM_AES_KEY_WRAP + CKM_AES_KEY_WRAP_KWP serve BOTH
  C_Encrypt/C_Decrypt (raw data, ACVP vectors) and
  C_WrapKey/C_UnwrapKey (key objects). Wrap params are
  no-param (`mech_simple`), like ECB.
- CKM_AES_KEY_WRAP_PAD (0x210A) ≡ KWP semantics: the oracle
  calls it the "KWP-PAD path" and runs no distinct vectors
  for it (only the overflow crash probe). Serve 0x210A as
  KWP, documented.
- CKM_AES_KEY_WRAP_PKCS7 stays catalog-only (different
  construction, zero oracle legs — honest skip).
- The C route already exists end-to-end (`std_WrapKey` /
  `std_UnwrapKey` → `haskokiStdWrapKey` / `haskokiStdUnwrapKey`
  → `planWrapKey` → driver `FxWrap`/`FxUnwrap`; T8 RSA wrap
  passes through it), but the contract rows for C_WrapKey /
  C_UnwrapKey still claim "no C-table route" — stale, fix in
  this slice (second contract-vs-code gap after cancel).
- Output EXPANDS (+8 IV): the GCM tag-expansion precedent
  covers the output planner; length rules live at recipe
  level, shared by both backends.

## Design

- Shim `hsk_ossl4_cipher_wrap` + header contract (fetch by
  ciphername, no-pad one-shot enc/dec; decrypt-update failure
  maps to the auth-failure code, GCM-tag-failure precedent).
- FFI `Raw.cipherWrap` binding (mirror `cipherCbc`).
- Engine `C_AES{128,192,256}_{KW,KWP}` specs: fetch names,
  key/length gates, runner, capability sets, notes, probes.
- Driver: `cipherCtor` × 6 for the encrypt path;
  `FxWrap`/`FxUnwrap` KW/KWP arms for the object path.
- Recipe rows: empty params, block 8, expansion +8. Planner
  gates: KW input multiple-of-8 AND ≥16 (provider-proven);
  KWP input ≥1 (any length; 0B refused — KWP pads, never
  empty... confirm against vectors before trusting it).
- Registry/catalog: flags [ENCRYPT, DECRYPT, WRAP, UNWRAP],
  routes, notes, evidence; regen + pin updates.
- Synthetic: generic stub rows (parity, not vectors).
- Promotion: 3 JSON rows (0x2109/0x210A/0x210B), canonical +
  mech catalog regen, all pins.

## Committed tests (failing test first)

- `OpenSSLSpec.caseAesWrapKwp`: RFC 3394 appendix + RFC 5649
  vectors as independent oracles (hardcoded, hermetic),
  enc+dec × KW/KWP × 128/256, edge lengths (KW 16/24,
  KWP 1/7/20), corrupt-integrity negatives.
- `RecipeCipherSpec`: groupShape +3, params/init/driver/
  geometry legs, expansion +8, length gates.
- `OperationSpec`/`KeyManagementSpec`: wrap/unwrap object-path
  rows (AES KEK + AES target roundtrip, wrong-key-type gates).
- `OperationSmokeSpec`: KW + KWP roundtrips through slots.
- Caps pins (both engines), registry/exhaustiveness/ctl/
  honesty pins, C discovery updates.
- C: extend wrap coverage in consumers if the file shape
  allows (else the KAT lane is the live proof).

## Lanes + gates + docs

- Targeted wrap files → expect ~7260 newly collected legs
  passing; fast + KAT full lanes with per-unit diffs vs
  r25/r8; static gates (history-codes pre-broken at HEAD);
  triage entry (Round 10 + KAT r9); single slice commit.
- Lane finding (fast r26): Tookan §3.2 unwrapped a 16-byte KW
  blob as CKK_DES3 and got a live key — the unwrap commit
  never measured material against the template key type.
  Fixed at the shared commit (`publishUnwrap`: AES 16/24/32,
  DES3 24, else any length; mismatch refuses
  CKR_TEMPLATE_INCONSISTENT), pinned by KeyManagementSpec
  caseUnwrapKeyTypeLength, re-laned in fast r27.
