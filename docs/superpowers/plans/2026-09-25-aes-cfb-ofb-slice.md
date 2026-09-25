# Slice 4 plan: AES CFB1/CFB8/CFB128/OFB (0x2108/0x2106/0x2107/0x2104)

## Discovery (proven, not assumed)

- Provider 4.0.2 fetches `AES-{128,192,256}-{CFB,CFB8,CFB1,OFB}`
  (block size 1, stream semantics); `AES-*-CFB128` alias MISSING
  (`-CFB` IS the 128-bit variant). No AES-CFB64 mode exists.
- 48/48 CLI spot-checks match ACVP encrypt vectors across all four
  modes × three widths, including sub-byte CFB1 payloads (top-bits
  masking, oracle-side).
- KAT r7 skip census: test_cfb1 2138, test_cfb128 2144, test_cfb8
  2144, test_ofb 2144 skipped (~8570 hidden tests).
- Oracle semantics: full-byte input (8 CFB1 ops/byte); ct length ==
  pt length (size-query skipped); raw IV params; MCT excluded.
- Scope is AES-only: registry has no DES3/ARIA/CAMELLIA CFB/OFB ids;
  CKM_AES_CFB64 (0x2105) stays catalog-only (provider lacks CFB64).

## Design (no new C entry: CTR precedent)

- Existing `hsk_ossl4_cipher_cbc` shim serves all four modes unchanged
  (provider block size 1 passes any length; key/iv gates hold).
- 12 `CipherSpec`s (`C_AES{w}_{CFB128,CFB8,CFB1,OFB}`), `cipherBlockLen`
  1, fetch names `AES-{w}-{CFB,CFB8,CFB1,OFB}`; caps probe per name.
- Recipe rows: iv-bytes/1, keys 16/24/32, block 16, no pad. Codec
  shape (16,False) for all four.
- Planners: new stream rows accept ANY length (even empty,
  length-preserving) via `isAesStreamMech`; CFB* stream 16-byte
  chunks with ciphertext-tail chaining (correct: streamed answers
  are ≥16 bytes, so the tail IS the next register); OFB buffers
  all updates to final (`isOfbMech` split guard — its register
  evolves through E(), underivable in the planner).
- Driver `cipherCtor` × 4; synthetic list +12 (generic stub).
- Promotion: 4 JSON rows (encrypt/decrypt, A16/A37/A39), canonical +
  mech catalog regen, 112→116 behavior / 110→114 real / C 110→114,
  all pins (C tests, scripts, CtlSpec, docs via publisher).

## Committed tests (TDD RED first)

- `OpenSSLSpec.caseAesCfbOfb`: 12 ACVP KAT legs (mode × width,
  enc+dec), ragged + multiblock coverage, bad key/iv negatives.
- `RecipeCipherSpec`: groupShape +4 (count 15), params/init/driver/
  geometry legs.
- `OperationSpec`: split-table rows (CFB* stream, OFB buffer-all),
  CFB128 multipart chain advance, any-length floor incl. empty.
- `OperationSmokeSpec`: CFB128 + OFB ragged roundtrips through slots.
- Caps pins (both engines), registry/exhaustiveness/ctl/honesty pins.

## Lanes + gates + docs

- Targeted `test_cfb1/cfb8/cfb128/ofb` → expect ~8570 newly collected
  legs passing (MCT excluded upstream); fast + KAT full lanes with
  per-unit diffs vs r24/r7; static gates (history-codes pre-broken
  at HEAD); triage entry; single slice commit.

## Targeted r1 → r2: C_SessionCancel (MCT recovery)

- The "MCT excluded upstream" expectation was wrong: r1 collected
  the MCT legs and 12 failed with CKR_OPERATION_ACTIVE (6 CFB8 +
  6 OFB encrypt/decrypt). Root cause: the MCT fallback calls
  C_SessionCancel to clear a dangling op, but our table slot was
  the generated stub (CKR_FUNCTION_NOT_SUPPORTED once live), so
  the stale op survived and the retry init refused.
- Fix: real C_SessionCancel, full stack. `F_SessionCancel` core
  planner (CKF_* selector mask; zero mask cancels all; recovery
  bits select their shared slot; live digest streams drain),
  `haskoki_std_session_cancel` FFI export (zero/CKF_FIND_OBJECTS
  also drops the find cursor), `std_SessionCancel` C surface
  routed out of the stub generator (first routed post-2.40 entry).
  Contract row corrected: it claimed the async-job cancel export,
  which was never reachable from the C_SessionCancel slot.
- Committed tests: `SessionCancelSpec` (11: codec, cancel-all,
  selective, recover bits, dual, stream release, idle, unknown,
  malformed) + `consumer_session_cancel.c` (live 3.2/3.0
  init→cancel→re-init proof).
- r2 (same 13 files, fresh bundle): CFB8/OFB 2144/2144 pass, 0
  MCT failures; the only 2 failures are the pre-existing HOTP
  registry asserts (same pair as fast r24 / KAT r7).
