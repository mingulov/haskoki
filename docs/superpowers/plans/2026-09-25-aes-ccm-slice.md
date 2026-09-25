# AES-CCM Slice Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add real AES-CCM single-part encrypt/decrypt (CKM_AES_CCM, AES-128/192/256) routed over OpenSSL 4.0.2, flipping the ~8,962 KAT CCM skips to pass with zero new failures.

**Architecture:** Mirror the AES-GCM wiring exactly: new `Haskoki.Recipe.Ccm` recipe module with a `ccm-params/1` canonical image, FFI unmarshal of `CK_AES_CCM_PARAMS`/`CK_CCM_PARAMS` (layout-identical), new `hsk_ossl4_aead_ccm_*` C shims beside the GCM shims, a Driver AEAD arm with the `ulDataLen` precondition, synthetic-engine parity arm, and catalog promotion with regenerated docs.

**Tech Stack:** Haskell (GHC 9.10.3, tasty suites), C (cbits EVPs against pinned OpenSSL 4.0.2), Python lane tooling (pkcs11-check 0.2.1).

**Spec:** Approved chat design 2026-09-25 (bounded slice 1) + NIST SP 800-38C (CCM: nonce 7..13 bytes, tag even 4..16 bytes) + oracle contract `testcases/acvp/aes/test_ccm.py` + `base_runner_aead.py:376-565` (single-part `encrypt_single`/`decrypt_single`, tag appended, invalid-tag rejects in `{ENCRYPTED_DATA_INVALID, ENCRYPTED_DATA_LEN_RANGE, AEAD_DECRYPT_FAILED, DEVICE_ERROR}`) + wycheproof `testvectors_v1/aes_ccm_test.json` (local pinned copy at `/tmp/pkcs11-ws/data/wycheproof/testvectors_v1/aes_ccm_test.json`).

## Global Constraints

- Pinned libcrypto is OpenSSL 4.0.2 at `/opt/openssl-4.0.2`; never the system 3.5.5 `/usr/bin/openssl`.
- TDD red-green per task: watch each new test fail for the right reason before implementing.
- No new test frameworks: tasty suites `haskoki-model-tests` (recipes) and `haskoki-engine-tests` (OpenSSL4 engine).
- Wycheproof result mapping: `valid` must pass, `invalid` must fail, `acceptable` is investigated, never silently passed.
- CCM is single-part only per oracle registry (`multi_part_supported=False`); multipart Update with CCM refuses.
- Every slice ends lane-proven (targeted + fast + KAT delta attributed) with gates green before commit.
- B catalog rows (`CKM_ML_DSA_EXTERNAL_MU_*`) are OUT of this slice (deferred to PQC slice 9 by user call).

## Ranked program (all slices; this plan implements slice 1 only)

| # | Slice | KAT skips unlocked | Status |
|---|---|---|---|
| 1 | AES-CCM | ~8,962 | this plan |
| 2 | Curves (secp224r1, secp256k1, brainpool) | ~19,233 | later plan |
| 3 | AES-CTS | ~7,529 | later plan |
| 4 | AES-CFB1/8/128 + OFB | ~8,584 | later plan |
| 5 | AES-WRAP / KWP | ~7,720 | later plan |
| 6 | AES-XTS | ~1,328 | later plan |
| 7 | DSA sign/verify | ~1,956 | later plan |
| 8 | EdDSA | ~1,197 | later plan |
| 9 | PQC + B rows | ~2,228 | later plan |
| 10-11 | Legacy + TLS/KDF | tail | later plan |

Note on CCM variants (user observation): the oracle runs CCM + CCM-ECMA + wycheproof AES legs. ECMA edge nonce/tag sizes outside SP 800-38C ranges stay honest skips/xfails via `classify_kat_clean_error`, never failures.

---

## File structure

- Create `core/Haskoki/Recipe/Ccm.hs`: `ccm-params/1` image (macLen u64be, nonceLen u64be, nonce, aad); strict validation (nonce 7..13 bytes, tag in {4,6,8,10,12,14,16}); mirrors `core/Haskoki/Recipe/Gcm.hs`.
- Create `tests/recipes/RecipeCcmSpec.hs`: tasty codec tests + embedded wycheproof vectors (tcId cited); registered in `haskoki.cabal` module list and `tests/model/Main.hs` imports.
- Modify `ffi/Haskoki/FFI/NativeParams.hs`: `ccmStructToCanonical` + `ccmNativeSize` (lengths in BYTES, unlike GCM bits); dispatch beside `decodeGcmNative` (~line 286).
- Modify `cbits/ossl4_ctx.c`: `hsk_ossl4_aead_ccm_encrypt/decrypt` beside `hsk_ossl4_aead_encrypt` (~line 412); CCM needs `EVP_CTRL_CCM_SET_IVLEN`, `EVP_CTRL_CCM_SET_TAG`, and total-length preset via `EVP_EncryptUpdate(cctx, NULL, &len, NULL, inlen)` before AAD.
- Modify `src/Haskoki/Engine/OpenSSL4.hs`: `ccAead` caps + `AES-*-CCM` alg arms (~lines 535, 983, 1012).
- Modify `src/Haskoki/Engine/Driver.hs`: `isCcmMech` arm beside `isGcmMech` (~line 454, 702-708); enforce `ulDataLen` precondition (encrypt: equals pt length; decrypt: equals ct length minus tag); tag failure maps to `CKR_ENCRYPTED_DATA_INVALID`.
- Modify `src/Haskoki/Engine/Synthetic.hs`: deterministic fake-CCM arm mirroring synth GCM (~line 898).
- Modify `core/Haskoki/Registry.hs`: CCM behavior descriptors beside `gcmRecipes` (~line 830).
- Modify `spec/mechanisms.json`: promote row `CKM_AES_CCM` (0x00001088) to tested with `test_evidence`, `routes`, reviewed `mechanism_info` (flags `[CKF_ENCRYPT, CKF_DECRYPT]`, min 16 / max 32 key bytes); regenerate via `python3 scripts/generate-mechanisms.py` + `python3 scripts/publish-coverage.py`; fix 108→109 count pins (mirror commit cf0a164 file list).
- Modify `tests/engine/OpenSSLSpec.hs`: engine-level CCM KAT case against real libcrypto.

### Task 1: CCM recipe codec red

**Files:**
- Create: `tests/recipes/RecipeCcmSpec.hs`
- Modify: `haskoki.cabal` (add `RecipeCcmSpec` after `RecipeCipherSpec`), `tests/model/Main.hs` (import + test entry)

**Interfaces:**
- Consumes: nothing yet (`Haskoki.Recipe.Ccm` does not exist; test must fail to compile/run)
- Produces: `spec :: TestTree` named `RecipeCcm` covering encode/decode roundtrip + validation rejects

- [x] **Step 1: Write the failing test**

```haskell
module RecipeCcmSpec (spec) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertBool, assertFailure, testCase)

import Haskoki.Recipe.Ccm (ccmParamsValid, decodeCcmParams, encodeCcmParams)

spec :: TestTree
spec = testGroup "RecipeCcm"
  [ testCase "ccm-params roundtrip" $ do
      let nonce = BS.replicate 12 0x01
          aad = BS.pack [0x02, 0x03]
          img = encodeCcmParams nonce aad 16
      case decodeCcmParams img of
        Nothing -> assertFailure "valid image refused"
        Just (n, a, t) -> do
          assertBool "nonce" (n == nonce)
          assertBool "aad" (a == aad)
          assertBool "taglen" (t == 16)
  , testCase "ccm-params rejects bad nonce/tag widths" $ do
      assertBool "6-byte nonce refuses" (not (ccmParamsValid (encodeCcmParams (BS.replicate 6 0) BS.empty 16)))
      assertBool "14-byte nonce refuses" (not (ccmParamsValid (encodeCcmParams (BS.replicate 14 0) BS.empty 16)))
      assertBool "5-byte tag refuses" (not (ccmParamsValid (encodeCcmParams (BS.replicate 12 0) BS.empty 5)))
  ]
```

- [x] **Step 2: Run test to verify it fails**

Run: `cabal test haskoki-model-tests --test-option=-p --test-option=/RecipeCcm/`
Expected: FAIL (compile error: module `Haskoki.Recipe.Ccm` not found)

- [x] **Step 3: Write minimal implementation** (see Task 2)

### Task 2: CCM recipe module green

**Files:**
- Create: `core/Haskoki/Recipe/Ccm.hs` (mirror `core/Haskoki/Recipe/Gcm.hs` lines 1-80: `CcmRecipe`, `ccmRecipes = [CcmRecipe "CKM_AES_CCM"]`, `ccmCodec = ParameterCodec "ccm-params" 1`, `ccmCodecFor`, `ccmRecipeFor` via `mustGeneratedId "CKM_AES_CCM"`, `encodeWord64`/`decodeWord64`, `encodeCcmParams`, `decodeCcmParams`, `ccmParamsValid`)
- Validation constants: `ccmNonceMin = 7`, `ccmNonceMax = 13`, `ccmTagLens = [4,6,8,10,12,14,16]`

**Interfaces:**
- Consumes: `Haskoki.Registry.Generated.mustGeneratedId`, `Haskoki.Registry.Types`
- Produces: `encodeCcmParams :: ByteString -> ByteString -> Int -> ByteString`, `decodeCcmParams :: ByteString -> Maybe (ByteString, ByteString, Int)`, `ccmParamsValid :: ByteString -> Bool`, `ccmRecipeFor :: MechanismId -> Maybe CcmRecipe`, `ccmCodecFor :: CcmRecipe -> ParameterCodec`

- [x] **Step 1: Implement `core/Haskoki/Recipe/Ccm.hs` per the Gcm.hs mirror above**
- [x] **Step 2: Run test to verify it passes**

Run: `cabal test haskoki-model-tests --test-option=-p --test-option=/RecipeCcm/`
Expected: PASS (2/2)

- [x] **Step 3: Run full model suite for regressions**

Run: `cabal test haskoki-model-tests`
Expected: PASS, no new failures

- [x] **Step 4: Commit**

```bash
git add core/Haskoki/Recipe/Ccm.hs tests/recipes/RecipeCcmSpec.hs haskoki.cabal tests/model/Main.hs
git commit -m "CCM slice 1/8: ccm-params/1 recipe codec + focused spec (red-green)"
```

### Task 3: FFI unmarshal red-green

**Files:**
- Modify: `ffi/Haskoki/FFI/NativeParams.hs` (add `ccmStructToCanonical`, `ccmNativeSize`, export list entries, dispatch beside `decodeGcmNative`)
- Modify: `tests/recipes/RecipeCcmSpec.hs` (native-image test vectors: hand-packed `CK_AES_CCM_PARAMS` bytes)

**Interfaces:**
- Consumes: `Haskoki.Recipe.Ccm.encodeCcmParams`
- Produces: `ccmNativeSize :: Int` (= `4 * wordSize + 2 * ptrSize`, 48 on 64-bit), `ccmStructToCanonical :: ByteString -> ByteString -> Word64 -> Word64 -> Word64 -> Maybe ByteString` (nonce bytes, aad bytes, dataLen, nonceLen, macLen; lengths in BYTES; `Nothing` unless lengths match buffers and widths validate)

- [x] **Step 1: Extend the spec with a native-image case** (hand-pack ulDataLen=2, nonce=12 bytes of 0x01, aad=2 bytes, macLen=16 in host order; dispatch must yield the `ccm-params/1` image; a `paramsLen /= ccmNativeSize` buffer must yield `Nothing`)

- [x] **Step 2: Run test to verify it fails**

Run: `cabal test haskoki-model-tests --test-option=-p --test-option=/RecipeCcm/`
Expected: FAIL (compile error: `ccmStructToCanonical` not in scope)

- [x] **Step 3: Implement unmarshal in `NativeParams.hs`** (mirror `gcmStructToCanonical` at line 200 and `decodeGcmNative` at line 286; chase `pNonce`/`pAAD` pointers exactly like the GCM arm)

- [x] **Step 4: Run test to verify it passes**

Run: `cabal test haskoki-model-tests --test-option=-p --test-option=/RecipeCcm/`
Expected: PASS

- [x] **Step 5: Commit**

```bash
git add ffi/Haskoki/FFI/NativeParams.hs tests/recipes/RecipeCcmSpec.hs
git commit -m "CCM slice 2/8: CK_AES_CCM_PARAMS FFI unmarshal (red-green)"
```

### Task 4: OpenSSL CCM shims + engine call path red-green

**Files:**
- Modify: `cbits/ossl4_ctx.c` (new `hsk_ossl4_aead_ccm_encrypt/decrypt` after line ~481; mode check `EVP_CIPH_CCM_MODE`; ctrls `EVP_CTRL_CCM_SET_IVLEN`/`EVP_CTRL_CCM_SET_TAG`; preset plaintext length with `EVP_EncryptUpdate(cctx, NULL, &tmplen, NULL, inlen)` before AAD; keep the AAD `aadl` throwaway pattern from the GCM shims)
- Modify: `src/Haskoki/Engine/OpenSSL4.hs` (add `"AES-128-CCM"`, `"AES-192-CCM"`, `"AES-256-CCM"` to `ccAead` at line 535 and to the guards at lines 983/1012; foreign import the two new shims beside the GCM imports)
- Modify: `tests/engine/OpenSSLSpec.hs` (engine KAT: wycheproof `aes_ccm_test.json` group 0 tcId 1 — key `bedcfb5a011ebc84600fcb296c15af0d`, iv `438a547a94ea88dce46c6c85`, empty msg/aad, tag `25d1a38495a7dea45bda049705627d10`, result valid)

**Interfaces:**
- Consumes: `Haskoki.Recipe.Ccm.decodeCcmParams` (nonce, aad, tagLen)
- Produces: engine encrypt returns `ct <> tag`, decrypt verifies tag and returns `pt` or maps failure to `CKR_ENCRYPTED_DATA_INVALID`

- [x] **Step 1: Write the engine KAT test** (encrypt tcId 1 through the OpenSSL4 engine, assert ct+tag bytes; decrypt roundtrip asserts pt)

- [x] **Step 2: Run test to verify it fails**

Run: `cabal test haskoki-engine-tests --test-option=-p --test-option=/CCM/`
Expected: FAIL (no CCM route: `CCM not routed` or equivalent)

- [x] **Step 3: Implement C shims + engine arms**

- [x] **Step 4: Run test to verify it passes**

Run: `cabal test haskoki-engine-tests --test-option=-p --test-option=/CCM/`
Expected: PASS

- [x] **Step 5: Run both engine and model suites for regressions**

Run: `cabal test haskoki-engine-tests haskoki-model-tests`
Expected: PASS

- [x] **Step 6: Commit**

```bash
git add cbits/ossl4_ctx.c src/Haskoki/Engine/OpenSSL4.hs tests/engine/OpenSSLSpec.hs
git commit -m "CCM slice 3/8: OpenSSL CCM shims + engine route (red-green)"
```

### Task 5: Driver arm + synthetic parity red-green

**Files:**
- Modify: `src/Haskoki/Engine/Driver.hs` (`isCcmMech` beside `isGcmMech` line 454; AEAD arm beside lines 702-708; `ulDataLen` precondition: encrypt requires `dataLen == pt length`, decrypt requires `dataLen == ct length - tagLen`, else `CKR_MECHANISM_PARAM_INVALID`; multipart Update with CCM refuses with `CKR_MECHANISM_PARAM_INVALID`)
- Modify: `src/Haskoki/Engine/Synthetic.hs` (deterministic fake-CCM arm mirroring synth GCM at line 898; document NOT-real-CCM)
- Modify: `tests/engine/OperationSmokeSpec.hs` (dataLen-mismatch refusal test; follow the CTR smoke additions in cf0a164)

**Interfaces:**
- Consumes: Task 4 engine route
- Produces: end-to-end single-part CCM encrypt/decrypt through `Driver`; synthetic determinism (same input, same output, differs from real)

- [x] **Step 1: Write refusal + roundtrip smoke tests**

- [x] **Step 2: Run tests to verify they fail**

Run: `cabal test haskoki-engine-tests --test-option=-p --test-option=/CCM/`
Expected: FAIL (CCM not dispatched)

- [x] **Step 3: Implement Driver + Synthetic arms**

- [x] **Step 4: Run tests to verify they pass**

Run: `cabal test haskoki-engine-tests`
Expected: PASS

- [x] **Step 5: Commit**

```bash
git add src/Haskoki/Engine/Driver.hs src/Haskoki/Engine/Synthetic.hs tests/engine/OperationSmokeSpec.hs
git commit -m "CCM slice 4/8: driver arm + synthetic parity (red-green)"
```

### Task 6: Negative KAT (invalid tag, bad widths)

**Files:**
- Modify: `tests/recipes/RecipeCcmSpec.hs` (extend: wycheproof invalid-tag vector must fail decrypt; 6-byte nonce / 5-byte tag / dataLen mismatch refuse at the right layer)
- Vector: wycheproof `aes_ccm_test.json`, first group with `result: invalid` and `ModifiedTag` flag (embed key/iv/aad/msg/ct/tag + tcId + comment inline)

**Interfaces:**
- Consumes: Tasks 4-5 routes
- Produces: invalid-tag decrypt returns exactly `CKR_ENCRYPTED_DATA_INVALID` (in oracle `_CCM_DATA_REJECTS`)

- [x] **Step 1: Write negative tests**

- [x] **Step 2: Run tests to verify they fail**

Run: `cabal test haskoki-model-tests --test-option=-p --test-option=/RecipeCcm/`
Expected: FAIL (new assertions fail)

- [x] **Step 3: Fix product code until green** (no test-expectation weakening; if a width the oracle needs refuses, widen the recipe constants with a cited reason)

- [x] **Step 4: Run tests to verify they pass**

Run: `cabal test haskoki-model-tests`
Expected: PASS

- [x] **Step 5: Commit**

```bash
git add tests/recipes/RecipeCcmSpec.hs
git commit -m "CCM slice 5/8: negative CCM KAT (invalid tag, bad widths)"
```

### Task 7: Registry + catalog promotion + doc regen

**Files:**
- Modify: `core/Haskoki/Registry.hs` (CCM descriptors beside line 830 via `ccmCodecFor`)
- Modify: `spec/mechanisms.json` (row `CKM_AES_CCM`: `support.real: tested`, `behavior/synthetic: tested`, `routes`, reviewed `mechanism_info`, `test_evidence` citing `RecipeCcmSpec` + `OpenSSLSpec` case ids)
- Regenerate: `python3 scripts/generate-mechanisms.py`, `python3 scripts/publish-coverage.py`
- Fix 108→109 pins: mirror commit cf0a164's list (`scripts/check-coverage-boundary.py`, `scripts/check-smoke-surface.py`, `scripts/publish-coverage.py`, `scripts/test-client.sh`, `spec/mechanisms-canonical.txt`, `tests/c/*`, `tests/model/RegistrySpec.hs`, `MechanismExhaustivenessSpec`, `ConfigHonestySpec`, `CtlSpec`, `docs/*`)

**Interfaces:**
- Consumes: Tasks 1-6 evidence (case ids must exist before citing)
- Produces: 109-row tested real catalog; `check-coverage-boundary.py` + `check-docs.py` green

- [x] **Step 1: Promote registry + JSON row, regenerate, fix pins**

- [x] **Step 2: Verify docs**

Run: `python3 scripts/check-coverage-boundary.py && python3 scripts/check-docs.py && cabal test haskoki-model-tests`
Expected: all green

- [x] **Step 3: Commit**

```bash
git add -A
git commit -m "CCM slice 6/8: catalog promotion to 109-row tested real (+docs regen)"
```

### Task 8: Lane proof + gates + release

**Files:**
- Modify: `docs/pkcs11-oracle-triage.md` (r22/KAT-r5 entries with fully attributed deltas)

**Interfaces:**
- Consumes: release bundle rebuilt via `scripts/make-release.sh`
- Produces: targeted CCM legs pass; fast lane ≥2947 passed with only the 2 HOTP asserts; KAT lane complete with only the 2 HOTP asserts; `run-gates.sh` green

- [x] **Step 1: Rebuild bundle**

Run: `bash scripts/make-release.sh`
Expected: exit 0

- [x] **Step 2: Targeted CCM legs**

Run: `pkcs11-check test` on `testcases/acvp/aes/test_ccm.py` + `testcases/test_mech_encrypt.py` with canonical data dir
Expected: CCM legs pass; ECMA edge sizes skip/xfail only, zero failures

- [x] **Step 3: Fast + KAT lanes with per-unit diff vs r21d/r4**

Expected: CCM units flip skip→pass; zero pass→fail; 2 HOTP asserts only; 0 crashes

- [x] **Step 4: Gates**

Run: `HASKOKI_PROXY_DIR=/opt/pkcs11-proxy-ng bash scripts/run-gates.sh`
Expected: `GATES: all passing`

- [x] **Step 5: Commit triage + slice**

```bash
git add docs/pkcs11-oracle-triage.md
git commit -m "Triage r22/KAT-r5: CCM slice lane proof (fast N/2, KAT N/2 HOTP-only)"
```

## Self-review

- Spec coverage: recipe codec (Tasks 1-2), FFI (Task 3), EVP + engine (Task 4), driver/synth (Task 5), negatives (Task 6), catalog/docs (Task 7), lanes (Task 8). Oracle single-part-only + tag-appended + reject codes covered in Tasks 4-6. Wycheproof valid/invalid mapping covered in Tasks 4/6.
- Placeholder scan: all steps name exact files, line anchors, commands, and expected outputs. Vector bytes cited by file+tcId; Task 6 names the selection rule (first ModifiedTag invalid) rather than bytes — executor embeds on read. Acceptable: the rule is deterministic.
- Type consistency: `encodeCcmParams/decodeCcmParams/ccmParamsValid/ccmRecipeFor/ccmCodecFor` signatures fixed in Task 2 and reused verbatim in Tasks 3-5.


