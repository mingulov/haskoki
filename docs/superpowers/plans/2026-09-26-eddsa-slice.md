# EdDSA slice plan: CKM_EDDSA + CKM_EC_EDWARDS_KEY_PAIR_GEN (0x1057, 0x1055)

Target: `test_eddsa.py` 15 skipped (fast r30 + KAT r12) +
`test_eddsa_public_key_encoding.py` 1 skipped +
`acvp/test_acvp_eddsa.py` 29 skipped + `test_cctv_ed25519.py`
914 skipped + `wycheproof/test_wycheproof_ed25519.py` 238
skipped (KAT r12) + mechanism-matrix legs over the 2 new rows.

## Discovery (proven, not assumed)

- Spike (no commit): `/tmp/eddsa_probe.c` — fails=0 against
  `OpenSSL 4.0.2 25 Aug 2026`. Keygen Ed25519/Ed448 OK.
  One-shot `EVP_DigestSign/Verify` with md NULL OK both
  curves; siglens exactly 64/114; empty message OK;
  deterministic; tamper rejected. `EVP_DigestSignUpdate`
  REFUSED (streaming unsupported: Haskoki multipart must
  buffer to one effect — the DSA precedent, driver sees only
  concatenated input). Direct `EVP_PKEY_sign` refused: shims
  must use the DigestSign path. Raw private/public import
  OK; SPKI/PKCS#8 DER roundtrips OK. Independent KAT:
  Wycheproof TEST 1 bytes (tcId 80) verify through the
  provider.
- Memory hazard, caught by the probe: hand-transcribed RFC
  8032 TEST 1 seed/sig tails were WRONG (3 probe FAILs).
  Committed KATs copy bytes from
  `/tmp/pkcs11-ws/data/wycheproof/testvectors_v1/ed25519_test.json`
  only (verify KATs: TEST 1 tcId 80 pk/sig + group0 pk/msg/
  sig). No seed-bearing sign KAT exists locally; sign is
  proven by roundtrip + determinism + oracle cross-verify
  (`test_sign_p11_verify_crypto`).
- Oracle shape (`test_eddsa.py`): fixture gates
  `has_mechanism("EDDSA")`; keygen via
  `CKM_EC_EDWARDS_KEY_PAIR_GEN` with `CKA_EC_PARAMS` = DER
  OID (`06 03 2B 65 70` ed25519, `06 03 2B 65 71` ed448),
  `CKA_VERIFY/CKA_SIGN` + `CKA_TOKEN` False; key type
  `CKK_EC_EDWARDS` (0x40); EC_PARAMS readback; roundtrips;
  wrong-data fails; sig length; determinism; cross-verify
  vs python `cryptography`.
- Oracle default mech for `CKM_EDDSA` is explicit
  `CK_EDDSA_PARAMS{phFlag=0, NULL, 0}` (`mech_eddsa` pure);
  vector drivers probe (raw, DER point) x (null, explicit
  params) in that order but FALL BACK on
  `PARAM_INVALID`/`ARGUMENTS_BAD` — null-first is probe
  order, not a requirement. The oracle registry marks
  `CKM_EDDSA` `param_required`, and `test_mech_negative`
  demands NULL rejection with exactly
  `CKR_MECHANISM_PARAM_INVALID` (accepting NULL also
  wedges the shared session: the stale op cascades
  `OPERATION_ACTIVE` into 50 later legs). Haskoki serves
  raw RFC 8032 `CKA_EC_POINT` (DER-wrapped accepted on
  import for maximal coverage, normalized to raw at
  readback).
- ACVP loader enforces pure only (`preHash=False`,
  `contextLength=0`); Wycheproof covers ed25519+ed448
  verify; CCTV 914 ed25519 vectors. No oracle caller sends
  context/phFlag (no scalar-params fuzz exists in this
  oracle); the FFI length-boundary probes accept either
  `CKR_MECHANISM_PARAM_INVALID` or `CKR_ARGUMENTS_BAD`, so
  non-pure structs refuse `CKR_ARGUMENTS_BAD` (canonical
  translate, recipe refusal — the DSA/ECDSA sibling
  convention, never a malformed-struct path).
- `CKM_XEDDSA`: no 4.0.2 provider support — stays
  catalog-only. Prehash/context EdDSA: no provider
  context/ph entry — non-pure refuses honestly.
- Haskoki precedent is a full DSA/ECDSA mirror:
  `Recipe/Dsa.hs` (recipe + codec + validation),
  `NativeParams.hs` (caller-native struct normalization at
  the FFI boundary, PSS/OAEP/ECDH/GCM/CCM/CTR arms),
  `Driver.eddsaSpecFor`-shaped dispatch, `SigEdDSA` backend
  spec, `Raw.eddsa*` shims, DER key storage, `GenEc`-style
  planner-driver frames (new tag 7).

## Design

- Recipe `Recipe/Eddsa.hs` (new): 1 row `CKM_EDDSA`;
  codec `eddsa-params/1`: `encodeEddsaParams phFlag
  context`; empty never decodes (the struct is required);
  `eddsaParamsValid` accepts pure explicit only (ph=0,
  empty ctx). Deferred: `CKM_XEDDSA` named.
- `NativeParams.hs`: `eddsaNativeSize` (u8 flag + pad to
  word alignment + length word + ptr, header order
  flag/len/ptr, Storable-derived),
  `eddsaStructToCanonical` (pure translate onto
  `encodeEddsaParams`; non-pure translates too and refuses
  downstream), `decodeEddsaNative` arm in
  `normalizeMechParams`.
- Engine `SigEdDSA { sigEddsaCurve }` (`Ed25519`/`Ed448`
  from the key's SPKI OID via `eddsaCurveOfDer`, ECDSA
  precedent); caps/notes/probes (`eddsaSigCap`).
- Driver: `eddsaSpecFor`/`isEddsaMech` + 4 sign/verify
  arms (mirror DSA) + `GenEdwardsKeypair` keygen arm (tag
  7) + `eddsaRefusal`.
- KeyManagement: `GenEdwardsKeypair !ByteString` frame
  (DER OID); `planGenerateKeyPair` arm (EC_PARAMS
  required->incomplete; non-Edwards OID->mechanism-invalid;
  `CKK_EC_EDWARDS` enforcement); `finishWork` stamps raw
  EC_POINT + EC_PARAMS via new `Der.hs` readers;
  `importMaterial` learns both `CKK_EC_EDWARDS` shapes
  (public: EC_PARAMS + EC_POINT raw-or-DER; private:
  EC_PARAMS + VALUE 32/57B seed; short->incomplete,
  malformed->inconsistent); `keyPairCompatible` learns the
  frame.
- `Der.hs`: `edwardsTable` (name, OID DER, seed width, sig
  width); `eddsaPublicDer` (SPKI from OID + raw point),
  `eddsaPrivateDer` (PKCS#8 `OneAsymmetricKey` with nested
  OCTET seed), `eddsaSpkiFields`/`eddsaPkcs8Fields`
  readers.
- FFI `Raw.eddsaSign/eddsaVerify/eddsaKeygen` (mirror
  `dsa*`); shim `hsk_ossl4_eddsa_sign/verify` (DigestSign
  one-shot, curve by name) + `hsk_ossl4_edwards_gen`
  (SPKI/PKCS#8/point answers) + header contracts.
- Backends: `OpenSSL4.hs` SigEdDSA arms + caps; `Synthetic.hs`
  keyed stubs with own domain separator.
- Registry/catalog: 2 served rows (sign/verify flags +
  generate route); `CKM_XEDDSA` stays catalog-only with a
  provider-absence note; regen + pin updates
  (`mech_catalog.inc`, canonical.txt, mechanisms.json,
  coverage/boundary/smoke/test-client pins).
- Verify error mapping: provider reject on bad length or
  bad signature -> `CKR_SIGNATURE_INVALID` (the module maps
  every verify mismatch to INVALID — RSA/ECDSA/HMAC all
  xfail the oracle's `LEN_RANGE` preference identically, so
  EdDSA matches the global stance; a length split would be a
  cross-cutting change, out of slice).
- Driver curve sniff MUST cover both `KeyMaterial`
  constructors: production resolves every stored key as
  `KeyBytes` (`stdResolver`), so a `KeyDer`-only sniff
  misdispatches every production Ed448 op as Ed25519 and
  the shim's base-id check refuses with BADKEY
  (`GENERAL_ERROR`). Found by KAT r13: all 87 wycheproof
  Ed448 + 10 ACVP Ed448 legs xfailed while Ed25519 passed
  and engine-level Ed448 roundtrips passed — the dispatch
  default is only correct for Ed25519. (ECDSA survives the
  same shape because its shim takes no curve name: the
  provider reads the curve off the key DER, so a wrong
  label is harmless there and fatal here.)

## Committed tests (failing test first)

- `OpenSSLSpec.caseEddsa`: Wycheproof TEST 1 (tcId 80) +
  group0 vectors as hardcoded hermetic KATs (raw-import
  pubkey -> verify, tamper negatives); keygen roundtrips
  both curves; empty msg; determinism; sig widths;
  cross-curve negative.
- `RecipeEddsaSpec` (new): row count/shape, codec
  roundtrips, pure/non-pure validation legs.
- `NativeParams` legs (mirror PSS struct tests): native
  `CK_EDDSA_PARAMS` image (LP64 24B) -> canonical; wrong
  size passes through; null-with-length context refuses.
- `OperationSmokeSpec`: EdDSA roundtrip through sign slots
  (single + multipart).
- `KeyManagementSpec`: keypair/import legs (missing
  EC_PARAMS incomplete, foreign OID invalid, garbage point
  inconsistent, DER-wrapped accepted, raw point stamped,
  VALUE widths 32/57 enforced).
- `OperationSpec`: params legs (NULL refuses
  PARAM_INVALID exactly, pure struct ok, phFlag=1 refuses
  ARGUMENTS_BAD, non-empty context refuses).
- `DerSpec`: SPKI/PKCS#8 goldens (hand-constructed layout
  + parse roundtrips + malformed refuses; d2i-ability
  proven in OpenSSLSpec via import->sign roundtrip).
- `SyntheticSpec` parity legs with the new separator.
- Caps pins (both engines), registry/exhaustiveness/ctl/
  honesty pins, C discovery updates.
- C: EdDSA leg in `consumer_roundtrip.c` (keygen + pure
  struct sign/verify + NULL refuses PARAM_INVALID +
  struct tamper negative).

## Lanes + gates + docs

- Targeted `test_eddsa.py` + `test_wycheproof_ed25519.py` +
  `test_cctv_ed25519.py` + `acvp/test_acvp_eddsa.py` r1 ->
  expect 15 + 238 + 914 + 29 newly collected legs passing
  (minus honest holds); fast + KAT full lanes with
  per-unit diffs vs r30/r12; static gates (history-codes
  pre-broken at HEAD, zero new hits); triage entry
  (Round 13 + KAT r13); single slice commit.
