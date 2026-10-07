# HPC triage (F-15 / T-5 phase 1 + T-23)

Informational measurement only: this file records phase-1 numbers and
names the concrete next property per below-threshold module. It sets
NO ratchet, NO floors, and NO gate — those stay deferred per the F-15
brief until a later task calibrates them against these numbers.

## 1. Method

- Command: `cabal test --enable-coverage all` (GHC 9.10.3, pinned
  OpenSSL 4.0.2), then `hpc sum --union` over the six per-suite
  `.tix` files, then one `hpc report`/`hpc markup` per library
  (`--include=<unitid>:` with the trailing colon scoping the whole
  package). Same recipe the `hpc` workflow
  (`.github/workflows/hpc.yml`) runs; see §6 to reproduce.
- Scope: the two LIBRARY mix dirs only, so suite runners (`Main`),
  specs, and test helpers cannot inflate a number. Documented
  excludes (T-5): `Haskoki.PKCS11` (untested stub) and the cabal
  autogen module `Paths_haskoki` (no `.mix` emitted for it here, so
  the flag is a no-op today).
- Conditions: measured 2026-10-07 on branch
  `fix/audit-20261006-f1-f16` with uncommitted F-1..F-14 work in the
  tree; 2054/2055 cases pass under `-fhpc` (the one failure is a
  coverage-sensitive new case, §5 — its suite still contributes a
  full-run `.tix`).
- Triage set (§3): every library module at or below 85% expression
  coverage, plus the three modules with no `.tix` entry at all (§4),
  plus the T-5 provisional-floor check and the T-23 thin-list
  disposition (§5). The 85% line is a TRIAGE threshold, not a floor:
  nothing fails on it.

## 2. Totals and per-module expression coverage

- `haskoki-core`: 83% expressions used (36540/43716); 52% boolean
  coverage; 73% alternatives; 64% top-level declarations.
- `haskoki`: 78% expressions used (42418/53959); 38% boolean
  coverage; 64% alternatives; 67% top-level declarations.

Per-module expression coverage, ascending (from the per-library
`--per-module` reports; `*` marks the §3 triage set):

`haskoki-core`:

| expr | module | expr | module |
|---|---|---|---|
| 33%* | Operation.Effect | 84%* | Object |
| 35%* | Request | 85%* | Operation.Derive |
| 56%* | Operation.Dual | 85%* | Output |
| 56%* | Operation.Signature | 86% | Registry.KeyMatrix |
| 61%* | Operation.Digest | 88% | Operation |
| 65%* | Operation.Message | 90% | Der |
| 68%* | Recipe.RsaOaep | 91% | Operation.Codec |
| 73%* | Operation.Cipher | 92% | Recipe.WrapComp |
| 73%* | Operation.Kem | 92% | Types |
| 75%* | Attribute.Generated | 93% | Registry.Generated |
| 78%* | Operation.State | 94% | Recipe.RsaPss |
| 79%* | Transition | 95% | Session |
| 80%* | Attribute | 97% | Recipe.Dh |
| 80%* | Outcome | 97% | Registry |
| 81%* | Operation.KeyManagement | 98% | Model |
| 81%* | Snapshot | 98-99% | 11 Recipe.* |
| 83%* | Recipe.Chacha20 | 100% | 19 Recipe.* + Registry.Types + Rules |

`haskoki`:

| expr | module | expr | module |
|---|---|---|---|
| 62%* | FFI.Standard | 82%* | Runtime.Detached |
| 67%* | FFI.Exports | 85%* | Runtime.Storage.Memory |
| 72%* | Ctl | 87% | Runtime.Config |
| 73%* | FFI.Instance | 89% | Engine.Synthetic |
| 74%* | Runtime.Storage | 89% | Runtime.Trace |
| 75%* | Runtime.Control | 92% | FFI.Encode |
| 77%* | Runtime.Storage.SQLite | 92% | Runtime.Events |
| 79%* | Engine.Driver | 93% | Engine.Backend |
| 79%* | FFI.Async | 93% | FFI.MessageParams |
| 79%* | Runtime.Async | 97% | FFI.OpenSSL4.Raw |
| 80%* | FFI.KeyOutputs | 98% | Runtime.Lifecycle |
| 80%* | FFI.NativeParams | 99% | Runtime.SlotEvents |
| 82%* | Engine.OpenSSL4 | 100% | FFI.Decode, FFI.Notify, Runtime.Catalog |

No `.tix` entry (never imported by any suite): `Haskoki`,
`Haskoki.Runtime`, `Haskoki.PKCS11` — see §4.

## 3. Triage: concrete next property per below-threshold module

Gap evidence is the unused-declaration list (`hpc report
--decl-list`) plus the boolean/alternatives detail. Each item names
one property with its catalog formula (roundtrip / oracle /
invariant / idempotence / easy-to-verify, per the PBT discipline —
or an explicit none-with-covering-reference where no standalone
property is proposed), its target suite, and its owning
testing-recs item — or an explicit statement that no T-item owns
it (new coverage).
No item here is implemented (that is T-7…T-13/T-16/T-17/T-20/T-21
expansion work, deferred per the brief).

`haskoki-core` (all paths under `core/`):

1. `Operation.Effect` 33% — gap is derived `Eq`/`Show` plus the
   `fx*` record selectors, all unused. Next: `FxLawsProps`
   (prop suite; no owning T-item — new derived-law coverage):
   invariant (`Eq` reflexive/symmetric over generated `Fx`
   values) + easy-to-verify (directed definedness table: each
   `fx*` selector returns its record field on the constructors
   that carry it — e.g. `fxMech` is NOT defined on
   `FxDigestFeed`/`FxDigestConsume`, `fxResource` only on those
   two — pinning the carrying set so a new constructor cannot
   silently widen partiality). Cheap; kills derived-code noise
   deliberately.
2. `Request` 35% — same shape: `dr*` selectors, derived
   `Eq`/`Ord`/`Enum`/`Show`, plus `regionFields`/`regionIntent`/
   `intentCapacity` unused. Next: `RequestShapeProps` (prop; no
   owning T-item — new shape coverage): easy-to-verify
   (directed selector table: each `dr*` selector on its
   carrying constructors only — e.g. `drHandle` is NOT defined
   on `DRCreateObject`/`DRFindObjects`) + oracle
   (`intentCapacity` agrees with the admission accounting in
   `Transition`).
3. `Operation.Dual` 56% — all 10 top-levels used, but boolean
   coverage is 14% and `planDualUpdate.total` never runs. Next:
   `DualCmdProps` (prop, T-10 pattern): Begin/Update/Finalize
   command sequences with generated payloads/chunkings; oracle
   against sequential digest-then-cipher; illegal-order scripts as
   anchors (pins the SPEC6 parallel-pair rows).
4. `Operation.Signature` 56% — all 19 top-levels used; guard/`if`
   branches uncovered. Next: `SignatureCmdProps` (prop, T-10
   pattern): multipart sign/verify sequences incl. short-buffer
   retry, empty-signature refusal, staged-output legs; oracle
   against the one-shot reference.
5. `Operation.Digest` 61% — `planDigestUpdate.runBuffered` never
   runs; boolean 10%. Next: extend `DigestCmdProps` (prop, T-10
   pattern): buffered-run legs + short-buffer retry scripts
   pinning the `runBuffered` path; oracle (same sequential
   reference the suite already uses).
6. `Operation.Message` 65% — `mo*`/`mn*` selectors unused;
   boolean 35%. Next: `MessageCmdProps` (prop, T-10 as specified):
   Begin/Next/OneShot/Finish/Retry/Finalize commands; oracle
   (planner vs phase/slot-occupancy reference model).
7. `Recipe.RsaOaep` 68% — guards 21% (12 unevaluated),
   alternatives 38%. Next: `RsaOaepProps` (prop; no owning
   T-item — new recipe coverage): oracle (Haskell OAEP
   wrap/unwrap vs the pinned `openssl` CLI on generated
   keys/labels) + invariant (decoding failures pin documented
   errors; label-length boundary roundtrips).
8. `Operation.Cipher` 73% — `planCipherUpdate.ctrChain` never
   runs. Next: `CipherModeProps` (prop; no owning T-item — new
   planner-leg coverage): CTR-chain legs through
   `planCipherUpdate` with generated counters/IVs/chunkings;
   oracle against a block-wise reference.
9. `Operation.Kem` 73% — `kemAlgOfKey` unused plus derived
   `Enum`/`Ord`/`Show`. Next: `KemProps` (prop; no owning
   T-item — new KEM coverage): oracle (encaps/decaps
   roundtrip; KAT vectors where the KAT lane has them) +
   invariant (wrong-key decaps refuses with the documented
   code) + easy-to-verify (directed `kemAlgOfKey` mapping
   table).
10. `Attribute.Generated` 75% — no booleans; alternatives 2/4.
    Next: extend the attribute specs (model; no owning T-item —
    new table coverage): easy-to-verify (per-class template
    vectors hitting the 2 uncovered generated-table arms; read
    the exact arms from `hpc/html-core/`).
11. `Operation.State` 78% — gap is ~50 unused derived
    `Show`/`Eq`/`Enum` decls. Next: one rendering golden over
    generated `SessionState` values (model; T-21 pattern):
    easy-to-verify (golden comparison), or record an accepted
    derived-noise note instead. Do not hand-write 50 unit
    cases.
12. `Transition` 79% — `planDecoded` field selectors
    (`args`/`env`/`func`/`key`/`op`) and `updateIntent` unused.
    Next: `TransitionIntentProps` (prop): oracle (`planDecoded`
    fields agree with the `planCall` inputs on generated calls)
    + `updateIntent` roundtrips through `publishDelta` legs
    (subsumed later by the T-11 session DSL).
13. `Attribute` 80% — top-level 32/57. Next: extend
    `ObjectSpec`/attribute specs (model; no owning T-item — new
    table coverage): easy-to-verify (template vectors for the
    25 unused attribute constructors; exact list in
    `hpc/html-core/`).
14. `Outcome` 80% — 25 expressions; `envBackend`/`outRegion`/
    `pcPersist`/`pcReasons`/`resResource` selectors unused.
    Next: fold selector assertions into the existing outcome
    tests (model, directed unit — no new suite; no owning
    T-item): easy-to-verify (assertions on existing test
    values only — no totality claim).
15. `Operation.KeyManagement` 81% — `planAuthWrapKey.lenOut`,
    `planGenerateKeyPair` tag, `planPbkd2Gen` length desc, `pw*`
    selectors unused. Next: `KeyMgmtRefusalProps` (prop):
    invariant (generated bad-length/bad-param keygen/wrap plans
    refuse with documented reasons, incl. the length-desc paths)
    + oracle (accepted plans match the recipe row's key type —
    pairs with T-7).
16. `Snapshot` 81% — `decBody`/`decProfile`/`decSlot`,
    `encodeStagedOutput`, the dual-staged flag unused: the decode
    legs. Next: `SnapshotProps` over generated slot states (prop,
    T-12 as specified): roundtrip (`restore (save s) == s`;
    `save live == Refused`), staged-output/dual slots first.
17. `Recipe.Chacha20` 83% — `decodeChachaIv`/`decodeWord32LE`
    unused. Next: `ChachaIvProps` (prop; no owning T-item — new
    recipe coverage): roundtrip (encode/decode IV at boundary
    widths, pinning the GAP-CHACHA20-COUNTER byte order) +
    oracle against the ChaCha20 vectors.
18. `Object` 84% — SLH-DSA import legs (`needSlhdsaSet`,
    `resolveSlhdsaSet`, `slhdsaPrivate`/`slhdsaPublic`) plus
    `trClass`/`trKeyType` unused. Next: `SlhdsaImportProps`
    (model; no owning T-item — import legs sit outside T-7's
    classic-init matrix domain): oracle (SLH-DSA key import
    over generated fixtures) + easy-to-verify
    (transition-record selector pins).
19. `Operation.Derive` 85% — all 24 top-levels used; guards 48%.
    Next: `KdfRefusalProps` (prop; no owning T-item — new KDF
    coverage): invariant (generated bad-length/bad-mech KDF
    plans refuse with documented codes; HKDF/TLS-PRF boundary
    lengths). Branches only.
20. `Output` 85% — `bindRegion`, `rd*`/`ro*` selectors unused.
    Next: `RegionProps` (prop; no owning T-item — new region
    coverage): invariant (`bindRegion`/`roRegion` roundtrip on
    generated regions; `rdPath`/`rdDisposition` agree with plan
    outputs).

`haskoki` (all paths under `src/` + `ffi/`):

21. `FFI.Standard` 62% — dual-link fns (`establishDualLink`,
    `dualLinkAuth`, `dualPeerEligible`, `dualCipherBytes`),
    `haskokiStdDecapsulateKey`, `haskokiStdDecryptUpdate/Final`,
    `ckrAttrSensitive`/`ckrUserTypeInvalid`, exception-render
    helpers unused; boolean 17%. Next: `StdDualProps` +
    `StdFinalProps` (model, in-process over the model backend):
    oracle (dual-link command sequences + DecryptUpdate/Final
    multipart legs against the model-backend reference) +
    easy-to-verify (refusal-code pins for the two `ckr*` codes;
    pairs with the T-20 vocabulary map).
22. `FFI.Exports` 67% — `caCloseBackend`, `reportShortLength`,
    `ckrGeneralError`, the exception-bridge fns unused. Next:
    `ExportsBridgeProps` (model; pairs with the T-20 vocabulary
    map): invariant (every export maps injected faults to
    documented CKR values, never throws across the boundary) +
    easy-to-verify (close-backend lifecycle cases).
23. `Ctl` 72% — `fixtureSoPin`, `lsId`/`lsLoggedIn`,
    `rnFinalized`, `rsSaveAs` unused. Next: `ls` login-state
    rendering + `scenario save-as` goldens over fixture configs
    (model; T-21 pattern): easy-to-verify (golden comparisons +
    run-finalized flag pins).
24. `FFI.Instance` 73% — `haskokiControl` write legs (`rv`,
    `whenFits`, `writeBytes`) unused; boolean 29%. Next:
    `ControlFrameProps` (prop; folds into T-8 `FfiCodecProps` —
    boundary-frame codecs are T-8's domain): roundtrip
    (control request/response frames at truncation boundaries,
    incl. short-write legs) + oracle against C-side decode
    where the consumer harness allows.
25. `Runtime.Storage` 74% — `reconcileJobsReload.jobDropAbsent`,
    `reconcileReload.tokenDropAbsent`, JSON `\u` legs
    (`hex4`/`hexChar`), `jb*`/`opExpected`/`sev*` selectors
    unused. Next: the T-16 interleaving DSL covers the
    reconcile/drop-absent legs; plus `StorageJsonProps` (prop):
    roundtrip (render/parse torture incl. `\u` escapes).
26. `Runtime.Control` 75% — `dispatchCommand`/`dispatchPresence`
    refuse legs, `parseStr`/`renderJson` hex legs,
    `scRules`/`stAction`/`stArgs` selectors unused. Next:
    `ControlDispatchProps` (model; pairs with T-20 for the
    documented-code pins): invariant (malformed or unauthorized
    commands refuse with documented codes; JSON string torture
    for the hex legs).
27. `Runtime.Storage.SQLite` 77% — `dropTokenStmt`,
    `removeIfOurs`, `rollbackQuiet`, `sqPath`,
    `trySQLite.toStore` unused. Next: `SQLiteLifecycleProps`
    (storage suite; pairs with the T-16 seam): invariant
    (store post-state after drop/remove/rollback legs under the
    fault-injected opener) + easy-to-verify (path-handling
    unit cases).
28. `Engine.Driver` 79% — `dsaRefusal`/`eddsaRefusal`/
    `mldsaRefusal`/`slhdsaRefusal`, `runEffect.runAeadMessage`,
    `runEffect.shortMac`, `kme*` selectors unused. Next:
    `DriverRefusalProps` (engine; pairs with T-20 for the
    refusal-code pins): oracle (refusal bytes match the pinned
    provider on unsupported algs) + AEAD-message legs through
    `runEffect` (generated aad/plaintext/chunkings).
29. `FFI.Async` 79% — `openStoreByPath.sqlite`, `toRV` unused.
    Next: `AsyncOpenProps` (model; `toRV` pins pair with T-20):
    easy-to-verify (open-by-path sqlite-vs-memory legs +
    `toRV` mapping pins; directed cases, no new suite).
30. `Runtime.Async` 79% — `co*`/`cw*`/`jobSnapshot*`/`js*`
    selectors, `completeJob.heldTag`/`why` unused. Next: extend
    `AsyncSpec` (model): invariant (completion-cause/held-tag
    assertions + snapshot-epoch pins on generated job
    histories; job-lifecycle legs move to the T-11 session DSL
    when it exists).
31. `FFI.KeyOutputs` 80% — 94 expressions; top-level 7/11. Next:
    fold key-output encode/decode roundtrips at boundary widths
    into T-8 `FfiCodecProps` (prop).
32. `FFI.NativeParams` 80% — `decodeCcmNative`,
    `decodeCtrNative`, `decodeSlhdsaNative`, `ccmNativeSize`,
    `ctrNativeSize`, `normalizePbkd2Params2` unused. Next:
    `ParamShapeProps` (prop, T-9 as specified): invariant
    (generated shapes accepted-or-refused per the shape table,
    CCM/CTR/SLH-DSA shapes + PBKDF2-v2 legs first — the named
    uncovered decoders) + easy-to-verify (the ERR2-13
    regression row).
33. `Engine.OpenSSL4` 82% — `importKey`/`exportKey`/
    `destroyKey`/`restoreResource`, `keyFamily`/`backendName`
    unused. Next: `OsslKeyLifecycleProps` (engine):
    import/export/destroy/restore roundtrips against the pinned
    libcrypto (owned-output discipline per T-14).
34. `Runtime.Detached` 82% — `detachStats*`,
    `attachmentGate.st`, `jaPolicy`, `duReason`/`dw*` selectors
    unused. Next: `DetachStatsProps` (model; no owning T-item —
    new ledger coverage): invariant (stats counters agree with
    the attached/detached job ledger on generated histories) +
    easy-to-verify (gate/policy pins).
35. `Runtime.Storage.Memory` 85% — all 30 top-levels used;
    guards 12%. Next: no standalone property (formula: none —
    covered by reference): the T-16 interleaving DSL
    (put/commit/close/reopen/crash, storage suite) covers the
    guard legs on both backends through the shared contract.

## 4. Modules with no `.tix` entry

Three library modules never load under any suite (present as
`.mix`, absent from every per-suite `.tix`):

- `Haskoki` (`src/Haskoki.hs`) and `Haskoki.Runtime`
  (`src/Haskoki/Runtime.hs`): pure re-export facades (verified by
  reading: `Haskoki` re-exports `Haskoki.Types` +
  `Haskoki.PKCS11`; `Haskoki.Runtime` re-exports
  `Haskoki.Runtime.Lifecycle`). No executable expressions of
  their own — no property needed; their submodules carry the
  numbers. A facade import smoke test would assert nothing.
  Revisit only if a facade gains logic (same discipline as the
  T-24 stub guard).
- `Haskoki.PKCS11`: the documented untested stub, deliberately
  excluded from the reports (T-5). No property until someone
  implements the facade.

## 5. Provisional-floor check, T-23 thin list, coverage signal

T-5 phase-3 provisional floors against the phase-1 numbers (check
only — nothing enforced):

| provisional floor | measured | verdict |
|---|---|---|
| `Registry.KeyMatrix` 100% | 86% (244/283) | below: `matrixTable` lazy rows never forced (`ckkRsa`, `ckkEc`, `ckkAria`, `ckkCamellia`, `ckkChacha20`, `ckkPoly1305`, `cbmKeyType`) — T-7 `KeyMatrixProps` (query every mech×op) is the fix |
| `Der` ≥90% | 90% (2331/2590) | meets; residual is PQC OID legs (`mldsa*OfOid`, `mlkem*OfOid`, `slhdsa*OfOid`) — T-13 `DerProps` with PQC fixtures |
| `FFI.Decode`/`FFI.Encode` ≥90% | 100% / 92% | meet |
| `FFI.MessageParams` ≥85% | 93% (304/324) | meets |
| `Snapshot` ≥90% | 81% (1410/1732) | below — item 16 above (T-12) |

T-23 thin-list disposition (every module either triaged in §3 or
closed with a reason — zero untriaged):

| module | measured | disposition |
|---|---|---|
| `FFI.Notify` | 100% (27/27) | covered — no task |
| `FFI.Instance` | 73% | §3 item 24 |
| `Runtime.Trace` | 89% | above threshold; residual is `escapeJson.hex4` legs — fold `\u`-escape torture into items 25/26 or accept |
| `Runtime.Detached` | 82% | §3 item 34 |
| `Runtime.Control` | 75% | §3 item 26 |
| `Runtime.SlotEvents` | 99% (252/253) | covered — no task |
| `Operation.Signature` | 56% | §3 item 4 |
| `Operation.State` | 78% | §3 item 11 |
| `Operation.Kem` | 73% | §3 item 9 |
| `FFI.Async` | 79% | §3 item 29 |
| `Snapshot` | 81% | §3 item 16 |

Coverage-sensitive test (hardened in final triage, not a lane
defect): the worktree-new `AsyncSpec` case "committed eviction
reclaims without a later table read" (`tests/model/AsyncSpec.hs`,
F-3 area — absent on base `b03abca`) failed under `-fhpc` in two
full runs, one isolated run, and one controller repro
(`expected: Just () but got: Nothing`), while passing without
coverage flags. Root cause (proven, not timing): the newest-payload
sub-assert observed heap-object identity via `Weak` + `performGC`,
whose transient-root survival differs under instrumentation —
while the product behavior held in every run (`(live, term) ==
(0, 1)`, elder oracle passing). The fix keeps the no-table-read
property byte-for-byte and proves newest-retention by measured
bytes (`retainedBytes` over the 64 MiB budget; verified failing at
68,160,304 bytes). The `hpc` job is passing; it gates nothing, and
every other lane's verdicts are unchanged.

## 6. Reproduce

From `haskoki/` (dash-safe; host needs the lib64 OpenSSL layout
via the git-ignored `cabal.project.local`, as in CI):

    cabal test --enable-coverage all > hpc-test.log 2>&1; echo "EXIT: $?"
    hpc sum --union $(find dist-newstyle -name '*.tix') --output=hpc/combined.tix
    CORE_MIX=$(find dist-newstyle -type d -path '*l/haskoki-core/build/*/extra-compilation-artifacts/hpc/vanilla/mix')
    MAIN_MIX=$(find dist-newstyle -type d -path '*extra-compilation-artifacts/hpc/vanilla/mix' | grep -v '/l/\|/t/' | sort | head -n 1)
    CORE_UNIT=$(ls "$CORE_MIX"); MAIN_UNIT=$(ls "$MAIN_MIX")
    hpc report hpc/combined.tix --hpcdir="$CORE_MIX" --hpcdir="$MAIN_MIX" \
      --include="$CORE_UNIT:" --exclude=Haskoki.PKCS11 --exclude=Paths_haskoki \
      --per-module > hpc/report-haskoki-core.txt
    hpc report hpc/combined.tix --hpcdir="$CORE_MIX" --hpcdir="$MAIN_MIX" \
      --include="$MAIN_UNIT:" --exclude=Haskoki.PKCS11 --exclude=Paths_haskoki \
      --per-module > hpc/report-haskoki.txt

Open `hpc/html-core/hpc_index.html` / `hpc/html-main/hpc_index.html`
(from `hpc markup` with the same flags) for the annotated sources.
Load-bearing details: `--union` (the default intersection keeps
only the one module the scaffold suite touches), `--hpcdir`
taking the `mix/` parent (hpc appends `<unitid>/<Module>.mix`),
the trailing colon in `--include=<unitid>:` (one module otherwise),
and mix-dir discovery scoped to `extra-compilation-artifacts/`
(the per-suite `html/` dirs reuse the unit-id names).
