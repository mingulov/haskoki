# B3 Haskell surface and onboarding inventory (for H3/V5 owners)

Survey at `f4a967a` (B1+B2 integration tip). Inventory only: no behavior
change, no code change. Sources are read, not modified: `haskoki.cabal`,
`src/Haskoki.hs`, `src/Haskoki/PKCS11.hs`, `cbits/function_tables.c`,
`cbits/exports.c`, `cbits/abi_stubs.inc`, `cbits/standard_surface.c`,
`spec/function-contracts.json`, `scripts/generate-function-contracts.py`,
and the onboarding docs checked against the artifacts named in section 5.

## 1. Exposed vs private Haskell modules (`haskoki.cabal`)

| Component | Visibility | Modules | Notes |
|---|---|---:|---|
| Main library, `exposed-modules` | public | 30 | `haskoki.cabal:160-190` |
| Main library, `other-modules` | private | 1 | `Haskoki.FFI.OpenSSL4.Raw` (`haskoki.cabal:192-193`), provider-only bindings |
| `haskoki-core` | `private` component | 67 | `haskoki.cabal:78-156`; module list at `:81-148`; not the package public API |
| Foreign library `haskoki`, `other-modules` | bundled, not imported | 25 | `haskoki.cabal:244-269`; compiled into `libhaskoki.so` |

Main-library exposed set (30): `Haskoki`, `Haskoki.PKCS11`,
`Haskoki.Engine.Backend`, `Haskoki.Engine.Driver`, `Haskoki.Engine.OpenSSL4`,
`Haskoki.Engine.Synthetic`, `Haskoki.Ctl`, `Haskoki.Runtime`,
`Haskoki.Runtime.Async`, `Haskoki.Runtime.Catalog`, `Haskoki.Runtime.Config`,
`Haskoki.Runtime.Control`, `Haskoki.Runtime.Detached`,
`Haskoki.Runtime.Events`, `Haskoki.Runtime.Lifecycle`,
`Haskoki.Runtime.SlotEvents`, `Haskoki.Runtime.Storage`,
`Haskoki.Runtime.Storage.Memory`, `Haskoki.Runtime.Storage.SQLite`,
`Haskoki.Runtime.Trace`, `Haskoki.FFI.Async`, `Haskoki.FFI.Decode`,
`Haskoki.FFI.Encode`, `Haskoki.FFI.Exports`, `Haskoki.FFI.Instance`,
`Haskoki.FFI.KeyOutputs`, `Haskoki.FFI.MessageParams`,
`Haskoki.FFI.NativeParams`, `Haskoki.FFI.Notify`, `Haskoki.FFI.Standard`.

Library/flib divergence (for H3/V5; unexplained in-tree):

| Fact | Detail |
|---|---|
| 7 library-exposed modules absent from the flib | `Haskoki`, `Haskoki.PKCS11`, `Haskoki.Ctl`, `Haskoki.Engine.Synthetic`, `Haskoki.FFI.KeyOutputs`, `Haskoki.FFI.MessageParams`, `Haskoki.Runtime` |
| `Engine.Synthetic` omission is consistent | `src/Haskoki/Engine/Driver.hs` imports `Haskoki.Engine.Backend` only, never `Synthetic`; synthetic stays test-only |
| 1 flib-only module, absent from the library | `Haskoki.FFI.Types` (`ffi/Haskoki/FFI/Types.hsc:16`); zero in-tree `import` sites found by search over `src/`, `ffi/`, `app/`, `tests/`, `test/` |
| `Haskoki` re-exports a core module | `src/Haskoki.hs:12-20` re-exports `Haskoki.Types` (a `haskoki-core` module) alongside `Haskoki.PKCS11` |

## 2. The 4 always-failing facade functions

`src/Haskoki/PKCS11.hs:1-10` states every function there is unimplemented.
Each body returns `OutcomeErr CKR_GENERAL_ERROR` unconditionally:

| Function | Line | Signature |
|---|---|---|
| `initialize` | `:21-22` | `IO (Outcome ())` |
| `finalize` | `:26-27` | `IO (Outcome ())` |
| `getInfo` | `:30-31` | `IO (Outcome String)` |
| `getSlotList` | `:34-35` | `IO (Outcome [SlotId])` |

Re-exported through `src/Haskoki.hs:12-20`. The serving path does not use
them: real callers go through the versioned C tables (`cbits/` + `ffi/`)
and the `planCall` / `finishEffect` / `publishDelta` contracts. A Haskell
newcomer importing `Haskoki` meets these 4 failures first; see gap D1.

## 3. C-table stub inventory (11 + 2)

Stub rule (both table layers): liveness first (`CKR_CRYPTOKI_NOT_INITIALIZED`
outside a live interval, `CKR_FUNCTION_FAILED` on callback reentry), then
the stub code; arguments are never inspected
(`cbits/function_tables.c:791-810`, `cbits/exports.c:81-90`).

Legacy 2.40 table, 3 `stub_probe` stubs (live code
`CKR_FUNCTION_NOT_SUPPORTED`, `cbits/function_tables.c:812-818`).
Provisioning (`C_InitToken`/`C_InitPIN`/`C_SetPIN`) left this table when
its lifecycle lane landed, and is routed in every table now
(`std_InitToken/std_InitPIN/std_SetPIN`,
`cbits/function_tables.c:1070-1072`):

| Entry | Stub body |
|---|---|
| `C_GetOperationState` | `stub_GetOperationState` |
| `C_SetOperationState` | `stub_SetOperationState` |
| `C_GetObjectSize` | `stub_probe` body |

Post-2.40 tables, 8 `x_live_check` stubs (live code
`CKR_FUNCTION_NOT_SUPPORTED`, `cbits/exports.c:84-90`,
bodies in `cbits/abi_stubs.inc:9-86`):

| Entry | Stub body |
|---|---|
| `C_LoginUser` | `abi_stubs.inc:9-18` |
| `C_VerifySignatureInit` | `abi_stubs.inc:20-28` |
| `C_VerifySignature` | `abi_stubs.inc:30-36` |
| `C_VerifySignatureUpdate` | `abi_stubs.inc:38-44` |
| `C_VerifySignatureFinal` | `abi_stubs.inc:46-50` |
| `C_GetSessionValidationFlags` | `abi_stubs.inc:52-58` |
| `C_WrapKeyAuthenticated` | `abi_stubs.inc:60-71` |
| `C_UnwrapKeyAuthenticated` | `abi_stubs.inc:73-86` |

Outside the 11 (named so the count reconciles): the legacy parallel pair
`C_GetFunctionStatus` / `C_CancelFunction` use `stub_parallel` (live code
`CKR_FUNCTION_NOT_PARALLEL`, `cbits/function_tables.c:820-826`,
bodies `:891-898`) and are classified `not-applicable` in the contracts;
their reason wording matches the stub return (fixed reason-side in B12;
see R11 in section 4).
Reconciliation: 81 planned + 21 `unsupported-with-reason` + 2
`not-applicable` (parallel pair) = 104 functions in
`spec/function-contracts.json` (`scope` + counts read from the file).
The 21 unsupported = 11 genuine stubs (section 3 entries still unrouted,
incl. the Wrap/UnwrapAuthenticated pair) + 10 reworded in B12 (R1-R10:
R4-R10 were literal stale denials, R1-R3 planner-scope). The provisioning
lane moved 3 rows to planned (81 vs 78 at B3 time).

## 4. Generated function-contract descriptions (named gap items, reworded in B12)

`spec/function-contracts.json` declares
`"scope": "planner/in-process reachability, NOT C-table routing"`.
Seven rows (R4-R10) used to deny C-table routes that exist as `std_`
bodies wired into the versioned tables; B12 reworded those reasons to
planner-scope-only claims ("served above the planner by the routed
entry"). Three rows (R1-R3) stated planner-scope limits that read as
serving denials; B12 gave them serving-context rewording instead.
The planner-scope half of all 10 still holds (search over
`core/Haskoki/Request.hs` and `core/Haskoki/Transition.hs` finds no `F_`
constructor for any of them). Reasons quoted from
`scripts/generate-function-contracts.py` (`...` marks shortened shared
prefixes).

| # | Kind | Function | Reason text | Routed evidence |
|---|---|---|---|---|
| R1 | planner-scope | `C_CloseAllSessions` | `no close-all planning (single-session close only; served above the planner by the routed entry)` | `std_CloseAllSessions`, `cbits/standard_surface.c:794`, table `cbits/function_tables.c:1089` |
| R2 | planner-scope | `C_FindObjectsInit` | `planner scope: one-shot find model only, no cursor state (serving cursors live in the public FFI layer above)` | `std_FindObjectsInit`, `standard_surface.c:1222`, table `:1101` |
| R3 | planner-scope | `C_FindObjectsFinal` | `planner scope: one-shot find model only, no cursor state (serving cursors live in the public FFI layer above)` | `std_FindObjectsFinal`, `standard_surface.c:1294`, table `:1103` |
| R4 | reworded (was stale denial) | `C_GenerateKey` | `operation-layer behavior tested but no planCall FunctionId (served above the planner by the routed entry) (KeyManagementSpec keygen cases)` | `std_GenerateKey`, `standard_surface.c:1526`, table `:1133` |
| R5 | reworded (was stale denial) | `C_GenerateKeyPair` | `... (served above the planner by the routed entry) (KeyManagementSpec keypair + KEM cases)` | `std_GenerateKeyPair`, `standard_surface.c:1570`, table `:1134` |
| R6 | reworded (was stale denial) | `C_DeriveKey` | `... (served above the planner by the routed entry) (KeyManagementSpec derive cases)` | `std_DeriveKey`, `standard_surface.c:2899`, table `:1137` |
| R7 | reworded (was stale denial) | `C_SeedRandom` | `no model planning (served above the planner by the routed entry)` | `std_SeedRandom`, `standard_surface.c:2471`, table `:1138` |
| R8 | reworded (was stale denial) | `C_GenerateRandom` | `no model planning (served above the planner by the routed entry)` | `std_GenerateRandom`, `standard_surface.c:2441`, table `:1139` |
| R9 | reworded (was stale denial) | `C_EncapsulateKey` | `... (served above the planner by the routed entry) (KeyManagementSpec KEM encaps cases, SyntheticSpec KEM)` | `std_EncapsulateKey`, `standard_surface.c:2589`, fill `cbits/abi_stubs.inc:120` |
| R10 | reworded (was stale denial) | `C_DecapsulateKey` | `... (served above the planner by the routed entry) (KeyManagementSpec KEM cases, SyntheticSpec KEM)` | `std_DecapsulateKey`, `standard_surface.c:2641`, fill `abi_stubs.inc:121` |
| R0 | (meta, resolved) `scope` vs reason wording | — | The `scope` field disclaims C-table routing; since B12 no reason asserts routing claims, so the tension is gone | `spec/function-contracts.json` `scope`; generator `UNSUPPORTED` table |
| R11 | (wording, fixed reason-side) parallel-pair code name | `C_GetFunctionStatus`, `C_CancelFunction` | `not-applicable` reason now names `CKR_FUNCTION_NOT_PARALLEL` (matches `stub_parallel` at `cbits/function_tables.c:825`, pinned by `tests/c/loader.c:1134-1137`); code+test agreed, so B12 changed the reason, not the code | reason text in `spec/function-contracts.json` |

Routing comments in `cbits/function_tables.c:770-788` confirm the same
10 as routed (sessions, find, keygen, random/seed, encaps note in
`cbits/exports.c:19-20`). The 11 section-3 stubs keep accurate reasons
(their entries really are stubs); R4-R10 were the only literal stale
denials (reworded in B12), R1-R3 got serving-context rewording, and R11
is fixed reason-side.

## 5. Onboarding accuracy vs artifacts

| Doc claim | Artifact | Result |
|---|---|---|
| README: demo image `ghcr.io/mingulov/haskoki-demo:v0.3.0.0`, `demo-ok: 8/8` | `docker/haskoki-demo:479` marker; `scripts/test-demo-image.sh:244`, `scripts/test-demo-onboarding.sh:25` gates | holds |
| README: checkout prepares v0.4.0.0 | `haskoki.cabal:3` reads `version: 0.4.0.0` | holds |
| README + cabal description: 316 tested of 464 catalog mechanisms | `docs/coverage.md:5,19-21` (464 rows; behavior/real/synthetic 316 tested) | holds |
| README: full profile 18 findings (22 before the v0.5 re-freeze), smoke expects zero | `docs/release-results.md` "What the findings mean" (18 after the v0.5 re-freeze); the `:11-14` table and `summary.json` are the dated October baseline (22) | holds |
| `try-it.md`: smoke collects 743 cases (not 743 passes) | `summary.json` `total: 743` both smoke lanes | holds |
| `try-it.md`: `proxy-example-ok: 5/5`, `p11-kit-demo-ok: 7/7` | `examples/release/p11-kit-example:104`; `test-demo-image.sh:553`; `test-demo-onboarding.sh:91,99` | holds |
| `try-it.md`: `shell` / `proxy-demo` / `p11-kit-demo` modes | `docker/haskoki-demo:1121-1123` dispatch; usage `:50-58` | holds |
| `try-it.md`: image pins checker 0.2.3, proxy v0.2.2 | checker gates `docker/Dockerfile.demo:155,230`; proxy `ARG PROXY_COMMIT` `:64` + v0.2.2 note `:72`, provenance gate `:97-98` | holds |
| `try-it.md`: image sizes 112.45 MiB compressed / 341.97 MiB unpacked (v0.3.0.0), 346.66 MiB candidate | cited CI run/job links in the text | stated with links; runs live outside the tree, not re-measured here |
| `release-notes-0.3.0.0.md`: published Oct 9 from `c49aa45`, workflow run 37961585654, 5 unsigned assets | same run id cited in `try-it.md` and `publishing.md`; asset table matches the publishing asset list | holds |
| `release-notes-0.3.1.0.md`: bare `docker run <image>` runs the demo | `docker/Dockerfile.demo:245-246` (`ENTRYPOINT` + `CMD ["demo"]`) | holds |
| `release-notes-0.3.1.0.md`: `SHA256SUMS.asc` only when signed | `docs/publishing.md` 5-vs-6 asset table | holds |
| `publishing.md`: Actions `mode=release` + `version` inputs on main | `.github/workflows/ci.yml:46,54` | holds |
| `publishing.md`: version/revision labels checked on the image | declarations `docker/Dockerfile.demo:177-178`; assertions `scripts/test-demo-image.sh:217-219` | holds |

## 6. Named gaps for H3/V5

| # | Gap | Owner direction |
|---|---|---|
| D1 | The facade explanation lives only in-source: `src/Haskoki/PKCS11.hs:3-9` plus per-function `Stub` notes already name the C serving path and unconditional failure, but nothing at the `Haskoki` re-export site points there | H3: one pointer sentence in the `src/Haskoki.hs` header or a deprecation marker; do not duplicate the existing header text |
| D2 | Stale denials R4-R10 and planner-scope R1-R3 read as serving truth to anyone who opens `spec/function-contracts.json` without the planner-scope context | V5: reword the 7 stale denials to name the existing `std_` route, add serving context to the 3 planner-scope rows, and resolve the R11 code-name wording |
| D3 | Meta item R0: `scope` disclaims C-table routing while reasons assert routing facts | V5: pick one level per field and pin it in the generator docstring |
| D4 | 7 library-exposed modules missing from the flib, and flib-only `Haskoki.FFI.Types` with zero in-tree importers, are unexplained | H3: document which Haskell API (if any) external consumers should use |
| D5 | Image-size figures in `try-it.md` cite CI runs that cannot be re-measured from the tree | V5: keep the run links adjacent to the figures (already the case); re-measure on publication |
| D6 | `v0.3.1.0` tag/publication wording across README, `try-it.md`, and the 0.3.1.0 notes is time-sensitive | V5: refresh once after publication instead of patching per-branch |
