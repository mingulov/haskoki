# FIPS compatibility research

Research + design doc: can haskoki run its OpenSSL4 engine against a
CMVP-validated FIPS module, and what would it take? This doc records
the verdict, the mechanism, a build recipe, code touchpoints, the
compliance boundary, and the unresolved register. It proposes no
behavior change by itself: every future knob below is marked
**PROPOSED** and deferred to `docs/config-honesty.md` treatment
(parseable-but-unimplemented values must refuse loudly; nothing here
may be read as implemented).

Conventions:

- Every external claim cites a URL fetched live on **2026-09-24**
  (access date in the cite) or the `/tmp` build spike whose logs stay
  out of the repo (spike log names in the cite).
- Every code claim cites `file:line` at the 0.3.0.0 tree.
  Line numbers drift; symbols are stable.
- No claim rests on the prior workflow synthesis alone; where the
  workflow hypothesis is confirmed, the fresh citation is given.
- `fips.so` = the OpenSSL FIPS provider shared object (Unix name).

## §1 — verdict: POSSIBLE-WITH-FLAVOR

**Verdict: POSSIBLE-WITH-FLAVOR.** Haskoki cannot do FIPS on its
current tree (static 4.0.2 libcrypto, default provider only, no FIPS
API surface), but no separate 3.x library rebuild is needed either:
the FIPS flavor keeps the 4.0.2 libcrypto pin and loads a validated
3.1.2-built `fips.so` sidecar. Three legs hold this up, each re-cited
fresh below:

1. **No 4.x module is validated or publicly queued; the validated
   line is 3.x.** The OpenSSL Library certificate table lists #4985
   (FIPS 140-3, module 3.1.2, Active, ends 10 March 2030) and the
   140-2 certs #4282/#4811 (modules 3.0.8/3.0.9, end 21 September
   2026) — no 4.x row
   (https://openssl-library.org/news/fips-cve/ — the
   `index.html` form of the same page; accessed 2026-09-24). The
   CMVP validated-modules search (ModuleName=OpenSSL, Active;
   accessed 2026-09-24) returns 59 rows whose only OpenSSL-project
   row is #4985 ("OpenSSL FIPS Provider", Software, 03/11/2025);
   the version strings appearing in module names are 3.0- and
   3.1.2-based (plus Ubuntu-release false positives such as
   "24.04"); no 4.x module name appears
   (https://csrc.nist.gov/projects/cryptographic-module-validation-program/validated-modules/search?SearchMode=Basic&ModuleName=OpenSSL&CertificateStatus=Active&ValidationYear=0;
   accessed 2026-09-24). The CMVP modules-in-process list
   (accessed 2026-09-24) carries exactly one OpenSSL Corporation
   row — "OpenSSL FIPS Provider", FIPS 140-3, "Comment Resolution
   - Lab (9/21/2026)" — and zero "4.0" strings anywhere in the
   table, so no 4.x module is publicly queued
   (https://csrc.nist.gov/projects/cryptographic-module-validation-program/modules-in-process/modules-in-process-list;
   accessed 2026-09-24). The single queued row is consistent with
   the announced OpenSSL 3.5.4 submission (Lightship Security +
   OpenSSL Corporation press release, 9 Oct 2025, via PRLog:
   https://www.prlog.org/13104111-lightship-security-and-the-openssl-corporation-submit-openssl-3-54-for-fips-140-3-validation.html;
   accessed 2026-09-24). Migration guidance names "the 3.5 LTS
   line plus the FIPS 140-3 provider, certificate #4985, valid
   through March 2030" as the single destination
   (https://openssl-corporation.org/blog/fips-140-3-migration.html;
   accessed 2026-09-24). Direct per-certificate CMVP pages are
   frame/JS-gated and not machine-readable (verified 2026-09-24
   for #4985); the rows above come from CMVP's own search/MIP
   tables, which render server-side.
2. **A validated 3.x provider is sanctioned for use with newer
   libraries, including future majors.** README-FIPS.md on the
   `openssl-4.0` branch states: "A FIPS provider built from any
   validated version may be used together with an OpenSSL library
   built from any supported release from OpenSSL 3.0 onwards;
   provider compatibility is maintained backward and forward
   across these releases, including future major release series,
   for as long as the module remains supported", with a worked
   two-source recipe (validated 3.1.2 provider + newer library)
   (https://raw.githubusercontent.com/openssl/openssl/openssl-4.0/README-FIPS.md;
   accessed 2026-09-24). The same file's example pairs 3.1.2
   artifacts (`fips.so`, `fipsmodule.cnf`) with a newer tree and
   shows `version: 3.1.2, status: active` under the newer
   `openssl list` (same cite).
3. **The spike proves the exact combination on haskoki's build
   shape.** A `/tmp`-only spike built OpenSSL 4.0.2 with
   `enable-fips` ADDED to haskoki's own flags (`no-shared
   no-pinshared`, tarball sha256
   `736b4675…543a8` matching `toolchain.lock`; spike logs
   `/tmp/fips-spike/build-noshared.log`,
   `/tmp/fips-spike/build-modules-noshared.log`) and showed:
   `providers/fips.so` (3,329,280 bytes) links with NEEDED=libc
   only and ZERO undefined OSSL/EVP/BN symbols (pure dispatch-table
   coupling); the static-linked `apps/openssl` binary (ldd shows
   no libcrypto) runs `fipsinstall` to INSTALL PASSED and
   config-activates base 4.0.2 + fips 4.0.2 side by side
   (`/tmp/fips-spike/fips-openssl.cnf`). Then a 3.1.2 tree
   (`enable-fips no-asm`, after the 3.1.2 AVX512 asm failed
   against the modern binutils and a dual-target parallel make
   raced; `/tmp/fips-spike/build-312b.log` SW_RC=0 MOD_RC=0)
   produced `providers/fips.so` (1,429,272 bytes), and the 4.0.2
   static binary loaded it: `fipsinstall` → INSTALL PASSED
   reporting `version: 3.1.2`, and config activation shows base
   4.0.2 + fips 3.1.2 both `active` with `sha256` answering
   (`/tmp/fips-spike/fips312-openssl.cnf`). So the static
   no-shared pin is NOT a technical blocker to loading an
   external validated `fips.so` (Q2 resolved; full ruling in §3).
   Caveat: the spike's self-built 3.1.2 `.so` is NOT the
   validated artifact — validated use requires the exact
   Security Policy build (§3/§5).

What "WITH-FLAVOR" means, concretely: the same 4.0.2 static
libcrypto + a validated 3.1.2 `fips.so` sidecar shipped in
`ossl-modules/` + a per-machine `fipsinstall` step + code deltas
(provider-name parameter, pin policy, FIPS activation/propq,
self-test→CKR mapping, config knobs — §4) + release-evidence
deltas (§3). BLOCKED would require either a 4.x-only rule (the
cross-version statement refutes it) or a static-linking
impossibility (the spike refutes it). POSSIBLE-NOW would require
zero tree change (the hardcoded `"default"` at
`src/Haskoki/Engine/OpenSSL4.hs:95` and the `fips = out of scope`
pin at `toolchain.lock` `[openssl]` refute it).

## §2 — mechanism: how OpenSSL FIPS mode engages

All mechanism claims below cite the `openssl-4.0`-branch sources
fetched 2026-09-24 unless noted; 3.x vs 4.x differences are called
out inline.

**What the module is.** The FIPS module is implemented as an
OpenSSL provider — "essentially a dynamically loadable module"
— and only counts as validated after the FIPS 140 process; the
certificate's Security Policy dictates the compliant build and
must be followed
(https://raw.githubusercontent.com/openssl/openssl/openssl-4.0/README-FIPS.md;
accessed 2026-09-24). The provider binary is `fips.so` (Unix)
and is NOT built/installed by default; `enable-fips` at
Configure time enables it (same cite). A provider "may be a
dynamically loadable module, or may be built-in, in OpenSSL
libraries or in the application"; a loadable one exports
`OSSL_provider_init` and talks to libcrypto purely through the
in/out `OSSL_DISPATCH` tables
(https://raw.githubusercontent.com/openssl/openssl/openssl-4.0/doc/man7/provider.pod;
accessed 2026-09-24) — which is why the spike's `fips.so` has
zero undefined libcrypto symbols (§1 leg 3).

**Install: fipsinstall + module config file.** Installation is
two steps: copy `fips.so` to the modules dir (default
`/usr/local/lib/ossl-modules/fips.so`), then run
`openssl fipsinstall`, which runs the module self-tests and
writes the FIPS module config file (`fipsmodule.cnf`) holding
the module checksum (and, for 3.1.2, the self-test status)
(README-FIPS.md cite above). The self-tests must run and the
config be generated ON EVERY MACHINE of use; for 3.1.2 the
config output must NOT be copied machine-to-machine (same
cite). Default invocation:
`openssl fipsinstall -out /usr/local/ssl/fipsmodule.cnf -module
/usr/local/lib/ossl-modules/fips.so` (same cite). New in 4.0:
`-defer_tests` defers the power-on self-tests so they run lazily
on first use of a validated algorithm instead of at load
(spike: flag present in 4.0.2 `fipsinstall -help`, "Enables test
deferral"; corroborated by the 4.0 release coverage, e.g.
https://linuxiac.com/openssl-4-0-released-with-ech-support-and-significant-legacy-code-removal/;
accessed 2026-09-24).

**Activate (config-file path).** The guide's primary path is
pure configuration: include `fipsmodule.cnf` from `openssl.cnf`,
declare `fips` + `base` providers under `[provider_sect]`, and
set `default_properties = fips=yes` under `[algorithm_sect]`,
with `config_diagnostics = 1` recommended "to prevent accidental
use of non-FIPS validated algorithms via broken or mistaken
configuration"
(https://raw.githubusercontent.com/openssl/openssl/openssl-4.0/doc/man7/fips_module.pod;
accessed 2026-09-24). The `base` provider carries no
cryptographic algorithms (encoders/decoders only) so it does not
affect validation status, and is designed to sit beside the FIPS
module (same cite). A per-application variant points
`OPENSSL_CONF` at a non-default config (same cite, "Selectively
making applications use the FIPS module by default"). The spike
ran exactly this shape (include + provider_sect + base) to
activate base 4.0.2 + fips 3.1.2 under a static 4.0.2 binary
(`/tmp/fips-spike/fips312-openssl.cnf`).

**Activate (programmatic path).** `OSSL_PROVIDER_load(NULL,
"fips")` (+ `"base"`) loads explicitly, but the config file is
STILL required to hold the module config data (self-test status,
integrity data); the guide removes `activate = 1` from
`fipsmodule.cnf` (setting 0 is NOT sufficient) so config
provides data without auto-activation (fips_module.pod cite
above). Loading must happen before any crypto call, else the
default provider auto-loads and fetch results across co-loaded
providers are unspecified without a property query (same cite).

**Routing: property queries.** Co-loaded providers are
disambiguated per-fetch: `EVP_MD_fetch(NULL, "SHA2-256",
"fips=yes")` pins the FIPS implementation;
`provider=default`/`provider=fips` pins by provider; with no
query (or several matches) the choice is unspecified
(fips_module.pod cite above). `EVP_set_default_properties(ctx,
"fips=yes")` sets the default query per libctx; explicit and
default queries merge, with the explicit one winning on
conflict (same cite). `EVP_default_properties_enable_fips(ctx,
enable)` merges/clears `fips=yes` into the default query;
`..._is_fips_enabled` reports it; both setters are NOT thread
safe and belong to libctx init phase only; added in 3.0
(`EVP_get1_default_properties` in 3.5)
(https://raw.githubusercontent.com/openssl/openssl/openssl-4.0/doc/man3/EVP_set_default_properties.pod;
accessed 2026-09-24). The nondefault-libctx pattern (one FIPS
libctx with config + `fips=yes` default, one plain libctx, and
the `null` provider parked in the default context so accidental
default-context use fails loudly) matches haskoki's existing
private-libctx shape (fips_module.pod cite above; haskoki side
in §4).

**Self-test / KAT behavior.** KATs run at `fipsinstall` time
(spike: `KAT_Digest`/`KAT_AsymmetricCipher` Pass lines) and the
module re-verifies at load against the config data; a load
without config data fails (`SELF_TEST_post: missing config
data`, module "entering error state" — observed in the spike
when `list -provider fips` ran without the config, then
resolved by the config-driven run). On self-test failure the
module enters the error state and stays there (same error
strings). For 3.1.2 the install status lives in the
machine-local config, hence the no-copy rule (README-FIPS.md
cite above).

**Confirming the source provider.** Walk
`EVP_MD_CTX` → `EVP_MD_CTX_md` → `EVP_MD_get0_provider` →
`OSSL_PROVIDER_get0_name` (fips_module.pod cite above,
"Confirming that an algorithm is being provided by the FIPS
module") — the audit primitive a FIPS flavor would expose in
traces (§4).

**Encoders/decoders.** Implemented in default/base, outside the
module boundary, but carry `fips=yes` so PEM/DER key transit
works under a `fips=yes` default; one of default/base must be
loaded alongside (fips_module.pod cite above).

**3.x vs 4.x differences that matter here.**

- `fipsinstall -defer_tests`: 4.0+ only (§1 cites). The 3.1.2
  module config semantics (no-copy rule, install-status entry)
  still govern a 3.1.2 sidecar regardless of the driving
  library version.
- FIPS indicators (`fips-indicator` query, `key-check` style
  setters, `OSSL_INDICATOR_set_callback`): added in 3.4
  (fips_module.pod cite above). A 3.1.2 sidecar predates them:
  fetching returns approved implementations or fails, with no
  per-operation approved-status query — simpler contract,
  coarser signal.
- Removed APIs are gone in 4.0 (`FIPS_mode`/`FIPS_mode_set`
  long removed; low-level/METHOD-customizing APIs deprecated
  since 3.0 and bypass the module — fips_module.pod cite
  above). Haskoki's EVP-only cbits surface already satisfies
  this (§4).
- Entropy: the FIPS provider defaults to the external `os`
  entropy source; `enable-fips-jitter` (3.5+) switches to an
  internal jitter source but is explicitly non-compliant
  without a separate ESV + CMVP validation (README-FIPS.md
  cite above). A compliant 3.1.2 sidecar build uses the
  Security Policy's entropy recipe, not jitter.

## §3 — build recipe for a haskoki FIPS flavor + Q2 ruling

**Q2 ruling: RESOLVED — the no-shared static pin does NOT block
loading a `fips.so`.** Q2 asked whether haskoki's static-only
pin (`no-shared no-pinshared` in the `Dockerfile` `openssl-build`
stage, `toolchain.lock` `[openssl]`) is compatible with a FIPS
provider that
ships as a shared object. The spike answers yes, on three
observations: (1) `enable-fips` ADDED to haskoki's exact flags
configures and builds cleanly (MAKE_RC=0,
`/tmp/fips-spike/build-noshared.log`) and still emits
`providers/fips.so`; (2) that `.so` is self-contained —
NEEDED=libc only, zero undefined OSSL/EVP/BN symbols — because
all provider↔libcrypto traffic crosses the dispatch tables
(§2 provider.pod cite); (3) the static-linked 4.0.2 binary
drives it end to end (`fipsinstall` INSTALL PASSED;
config-driven base+fips activation; digest answers), including
a 3.1.2-built `.so` under the 4.0.2 binary (§1 leg 3). The
consequence cuts the recipe IN HALF: **haskoki does not need
`enable-fips` on its own 4.0.2 build at all.** The FIPS module
comes from a separate validated-3.1.2 build; haskoki's
libcrypto only dlopens it, which static builds already support
(spike observation 3). The Dockerfile's `openssl-build` stage stays byte-identical; the
flavor ADDS a module stage beside it.

**Recipe (PROPOSED; nothing below exists in the tree).**

1. **Module stage (new).** A second builder stage fetches the
   validated 3.1.2 sources, verifies the tarball hash, and
   builds EXACTLY per the #4985 Security Policy (configure
   flags, platform, install recipe — the Policy, not this doc,
   is authoritative; README-FIPS.md: "you MUST follow the
   instructions in the Security Policy in order to be FIPS
   compliant"). Output: `fips.so` + the install procedure. Do
   NOT reuse the spike's `no-asm` build (it exists only to
   prove loadability; a validated artifact follows the Policy
   build to the letter).
2. **Ship the sidecar.** Copy `fips.so` into the release
   artifact under `ossl-modules/` (the
   `MODULESDIR`-equivalent path the flavor controls) and record
   its sha256 in the release evidence (below). The module
   config file (`fipsmodule.cnf`) is NOT shipped: it is
   generated per machine (§2 no-copy rule).
3. **Per-machine install step.** The operator (or installer)
   runs the pinned `openssl fipsinstall -out <path>
   -module <path>/fips.so` on each target machine, capturing
   the INSTALL PASSED output. Without this step the module
   refuses to load (spike: "missing config data" → error
   state), so the flavor's startup must treat a missing/invalid
   module config as a loud open failure, never a silent
   default-provider fallback (§4, per the Backend never-
   substitutes law at `src/Haskoki/Engine/Backend.hs:442-452`).
4. **Point the libctx at it.** Provider path + module config
   reach the private libctx via the §4 touchpoints (provider
   search path and config-data load before first fetch).
5. **No `enable-fips` on the 4.0.2 pin.** Deliberately absent:
   an `enable-fips` 4.0.2 build would emit an UNVALIDATED 4.0.2
   `fips.so` (§1 leg 1) that must never be mistaken for the
   validated sidecar. Keeping the pin `enable-fips`-free
   removes that confusion at the source. `toolchain.lock` gains
   a `[fips-module]` stanza (PROPOSED) recording the validated
   module version, certificate, tarball hash, and Policy
   reference, mirroring the existing `[openssl]` stanza.

**ldd-gate impact: none on existing gates, one new artifact.**
`fips.so` is dlopen'd at runtime, never DT_NEEDED, so the
"no dynamic libcrypto/libssl in module closure" gate
(`scripts/make-release.sh:80-83`) and the host-deps allowlist
(`scripts/make-release.sh` host-deps gate, exactly
{libm, libgmp, libffi, libnuma, libc, ld-linux, vdso}) stay
passing unchanged — the sidecar is invisible to `ldd`. That
invisibility is itself the risk: the closure review
(`scripts/make-release.sh` review record,
"libcrypto: STATIC, pinned ... build") must gain a
`fips-module` section recording sidecar path, sha256, provider
`version:` string (spike: `list -providers` reports it), and
the `fipsinstall` transcript hash — otherwise the most
security-relevant file in the artifact is the one file the
evidence never mentions.

**Release-evidence impact.** `scripts/release-evidence.sh`
writes per-driver logs + `MANIFEST.txt` for 13 container
drivers + release build + host install (:6-40, :116). The
flavor adds: (a) the module-stage build log + Policy-conformance
checklist to the evidence dir; (b) a 14th driver (PROPOSED)
that installs the sidecar in a clean container, runs
`fipsinstall`, asserts provider `version: 3.1.2, status:
active` and a `fips=yes`-pinned digest, and asserts startup
REFUSES when the sidecar/config is absent (no silent fallback);
(c) the sidecar + transcript hashes in `MANIFEST.txt`. The
existing 13 drivers and the manifest's current rows are
untouched.

## §4 — code touchpoints (PROPOSED diff plan)

Every touchpoint cites its seam at the 0.3.0.0 tree.
Seams first (what already fits), then blockers (what must
change). All items are PROPOSED — no code changes in this task.

**Seams (keep and reuse).**

- **Private libctx per env.** `openBackend` builds a fresh
  `OSSL_LIB_CTX` per backend env
  (`src/Haskoki/Engine/OpenSSL4.hs:90-114`, `Raw.envNew` at
  :91) — the exact shape the nondefault-libctx FIPS pattern
  wants (§2). No default-context crypto anywhere on this path.
- **Provider-name-taking load.** `Raw.envLoad envp "default"`
  (`src/Haskoki/Engine/OpenSSL4.hs:95`) funnels through
  `hsk_ossl4_env_load(env, name)`
  (`cbits/ossl4_ctx.c:89-99`), which passes ANY name to
  `OSSL_PROVIDER_load` (`cbits/ossl4_ctx.c:54-60`) and stores
  up to 4 providers (`HSK_OSSL4_MAX_PROV`,
  `cbits/ossl4_ctx.c:34,43`) — so `fips`+`base` fits the
  existing array with no struct change.
- **propq threaded everywhere.** The fetch property query
  lives in `osslPropQ`
  (`src/Haskoki/Engine/OpenSSL4.hs:77,114`) and reaches every
  fetch call (`Raw.digest` :136, `digestInit` :148, `hmac`
  :198/:214, sign/verify :246-305, cipher :336/:354, `ecGen`
  :363, `ecdhDerive` :443, `probe` :644) and the capability
  note (`t07Caps`, "default only; propquery " ++ propq,
  :479-490). A `fips=yes` default (§2) is a value change at
  ONE site (:114) plus the note text (:490), not a threading
  refactor.
- **Never-substitutes law.** Every execute path checks its
  cap predicate first and answers `BackendUnsupported` on
  miss, never substituting another alg/param set
  (`src/Haskoki/Engine/Backend.hs:442-452`) — the FIPS
  no-fallback requirement (§3 step 3) is this law applied to
  provider availability.
- **EVP-only native surface.** cbits fetches exclusively via
  `EVP_*_fetch` with explicit propq (`cbits/ossl4_ctx.c:150-
  368`); no low-level/METHOD APIs that would bypass the
  module (§2 3.x/4.x notes). The ossl4-surface gate pins this
  (`scripts/check-ossl4-surface.py`).
- **Total error mirror.** `toCryptoError`
  (`src/Haskoki/Engine/Driver.hs:1156-1163`) maps every
  `BackendError` constructor to its `CryptoError` mirror with
  fields intact, and core operations interpret via
  `interpretError (TyCrypto err)` (e.g.
  `core/Haskoki/Operation/Cipher.hs:278-281`) — the extension
  path for a self-test-failure CKR (below) without touching
  per-operation code.

**Blockers (must change).**

1. **Hardcoded provider name.** `Raw.envLoad envp "default"`
   (`src/Haskoki/Engine/OpenSSL4.hs:95`) must become a
   parameter (PROPOSED: load list from config — `["fips",
   "base"]` in FIPS mode, `["default"]` today). The cbits
   side already takes names; only the Haskell call site is
   hardcoded. Failure stays loud: load failure already maps
   to `BackendNative "open"` (:96-100).
2. **Version-pin policy.** `"4.0.2" isInfixOf version`
   (`src/Haskoki/Engine/OpenSSL4.hs:103-108`) pins the
   LIBRARY. The flavor keeps that pin AND adds a module-pin
   check (PROPOSED: assert the loaded `fips` provider reports
   `name: OpenSSL FIPS Provider, version: 3.1.2` via the §2
   audit walk, else `BackendNative "open"` refuse). Two pins,
   two artifacts — never conflate them in one string.
3. **Provider path + module config plumbing.** NOTHING today
   sets a provider search path or loads module config data:
   `Raw` exposes `envNew/envLoad/envCtx` only
   (`ffi/Haskoki/FFI/OpenSSL4/Raw.hs:23-30,80-93`). PROPOSED
   cbits additions: set module dir (equivalent of
   `OPENSSL_MODULES`/`OSSL_PROVIDER_set_default_search_path`)
   and load the machine-local `fipsmodule.cnf` data into the
   private libctx (`OSSL_LIB_CTX_load_config` on the private
   ctx, per the §2 nondefault-libctx pattern) — both BEFORE
   the first fetch, inside `openBackend`, with any failure a
   `BackendNative "open"` refuse.
4. **Default propq = `fips=yes` in FIPS mode.** Value change
   at the :114 site + note text at :490 (PROPOSED: mode-driven
   string), optionally via `EVP_default_properties_enable_fips`
   on the private ctx at init (§2 thread-safety note: init
   phase only — `openBackend` qualifies). Explicit per-fetch
   queries keep merging as today.
5. **Self-test failure → CKR mapping.** The FIPS error-state
   signal (§2: module "entering error state", fetch/load
   failures thereafter) must surface as
   `CKR_FIPS_SELF_TEST_FAILED` (`0x1B6`), which exists in the
   vendored header (`spec/vendor/pkcs11.h`,
   `CKR_FIPS_SELF_TEST_FAILED` `0x000001B6`) but is referenced
   NOWHERE in `src/`/`ffi/`/`core/` (verified by grep at
   base). PROPOSED: a dedicated `BackendError`/`CryptoError`
   constructor (or a `BackendNative` sub-code the mirror
   preserves) plus ONE `interpretError` arm mapping it to the
   new CKR — never collapsed into `CKR_GENERAL_ERROR`, or
   operators cannot distinguish "bad input" from "module
   failed its self-test".
6. **`engine.kind` third value vs separate flag.** `engine.kind`
   today admits `synthetic|openssl` only
   (`src/Haskoki/Runtime/Config.hs:497-501`). PROPOSED
   (config-honesty treatment, `docs/config-honesty.md` cross-ref):
   EITHER `engine.kind = openssl-fips` (one enum, refused
   unless the sidecar exists) OR keep `openssl` + a new
   `engine.fips_sidecar` path knob (REFUSED when the path is
   missing/invalid — no silent fallback, per the Backend law).
   Whichever is chosen, the disposition table gains the row
   with a contract test; until implemented, any FIPS-shaped
   value is `CfgInvalid`/`CfgUnknownKey` (today's behavior —
   no knob exists, so there is nothing to mis-set).
7. **Audit: source-provider in traces.** Expose the §2 audit
   walk (`EVP_MD_get0_provider` →
   `OSSL_PROVIDER_get0_name`) per operation trace (PROPOSED),
   so FIPS-mode evidence can show "this digest came from
   provider fips" rather than asserting it.
8. **Capability narrowing.** The FIPS module offers a SUBSET
   of default-provider algorithms (§2), and the 3.1.2 sidecar
   predates FIPS indicators (§2) — so `ossl4Caps`
   (:479-490) needs a FIPS-mode variant (PROPOSED) whose
   predicate-first checks fail closed on anything the sidecar
   lacks, with `probe` (:644) re-run against the FIPS libctx
   at open. The never-substitutes law makes this safe by
   construction.

## §5 — compliance boundary: what "FIPS-compatible" may honestly claim

This section stays CONSISTENT with the existing no-certification
stance — it does not propose changing it. The stance, verified
at base: "No certification, FIPS, Common Criteria, or
production-security claim is made anywhere in this release"
(`docs/coverage.md:208-209`); `fips = out of scope (default
provider only)` (`toolchain.lock` `[openssl]`); the working-paper
PRD excludes "FIPS/CC validation" from scope (unshipped, outside
this package). A FIPS flavor built per §3/§4 would narrow
but not erase that stance: the module inside the boundary is
validated; haskoki itself holds no CMVP certificate and this
doc proposes no haskoki-owned validation.

**Module-boundary diagram (prose).** Draw the FIPS 140
boundary EXACTLY around the validated `fips.so` sidecar (the
#4985 module: 3.1.2 sources built per its Security Policy).
Inside: the provider's approved algorithms, its KATs, its
integrity check, its DRBG. Outside: haskoki's Haskell/FFI/cbits
layers, the 4.0.2 libcrypto driver, the `base`/`default`
encoders-decoders (§2: outside the boundary but permitted
alongside), the operator's config files, and the host OS
entropy source the module is built against (§2 entropy note).
"Validated module inside, provider outside" is the whole
posture: haskoki is a CONSUMER of a validated module, the way
any application links a validated library — haskoki's own code
is never described as validated, certified, or inside the
boundary.

**Operator responsibilities (the flavor cannot absorb these).**

- Run `fipsinstall` on EVERY machine (§2); keep the INSTALL
  PASSED transcript with the deployment record.
- Never copy `fipsmodule.cnf` machine-to-machine for the 3.1.2
  sidecar (§2 no-copy rule).
- Keep `config_diagnostics = 1` (§2) or an equivalent startup
  assertion, so a broken module path refuses loudly instead
  of running unvalidated crypto.
- Procure the sidecar ONLY as the Policy-built artifact
  (§3 step 1); a self-built `.so` (like the spike's) proves
  loadability and NOTHING about compliance.
- Track the certificate lifecycle: #4985 ends 10 March 2030
  (§1); the queued successor row (MIP, §1) is the migration
  target when it issues — see Q1 in §6.

**Wording allowlist (may appear in docs/release notes).**

- "routes FIPS-mode operations through CMVP certificate #4985
  (OpenSSL FIPS Provider 3.1.2)" — with the §1 cites.
- "refuses to start in FIPS mode without the validated
  sidecar + machine-local module config" — §3 step 3 / §4.
- "per-operation traces name the serving provider" — §4 item
  7 (once implemented; PROPOSED until then).
- "no silent fallback to the default provider" — the Backend
  law cite (`src/Haskoki/Engine/Backend.hs:442-452`).

**Wording blocklist (must NOT appear anywhere).**

- "FIPS validated", "FIPS certified", "FIPS compliant" applied
  to haskoki (any component outside the sidecar). NIST-side,
  the module is "validated"; nothing else in the artifact is.
- "FIPS mode" without immediately naming the certificate +
  module version it routes through.
- Any sentence suggesting the 4.0.2 libcrypto pin, the
  default provider, or a self-built `.so` carries validation
  (§1 leg 1 refutes it).
- "Approved" for algorithms the 3.1.2 sidecar lacks or that
  run outside it; the capability predicate (§4 item 8) is the
  enforcement point, prose is not.

**Stance-change bar (explicitly NOT proposed).** If a future
task wants haskoki-owned validation (own CMVP certificate,
vendor rebrand like the §6 Q3 examples, or a changed PRD),
it must FIRST update the three stance sites above
(`docs/coverage.md:208-209`, `toolchain.lock` `[openssl]`, PRD:102)
in the same diff as the claim — a claim without the stance
update fails review. This doc makes no such proposal.

## §6 — unresolved register (Q1–Q5 carried)

| Q | Question | Status | Resolution criterion + owner |
|---|---|---|---|
| Q1 | Is any 4.x (or other successor) module publicly queued on the CMVP MIP list? | RESOLVED (negative for 4.x) | Criterion: MIP list inspectable server-side and showing module rows — MET (§1: one OpenSSL Corporation row, "Comment Resolution - Lab (9/21/2026)", zero "4.0" strings). Standing watch passes to the FIPS-flavor owner: re-check the MIP URL each release cycle; the row's issuance (expected: 3.5.4-based cert) starts the #4985→successor migration clock (§5 operator duty). Owner: future FIPS-flavor task. |
| Q2 | `fips.so` vs the no-shared static pin — can they coexist? | RESOLVED by the §3 spike | Criterion: build-system ruling with logs — MET (§3: static pin loads + drives `fips.so`, incl. 3.1.2-built module under the 4.0.2 binary). No watch needed; the ruling is structural (dispatch-table coupling, §2). Owner: none (closed). |
| Q3 | Is the #5132 "vendor rebrand" rumor real, and does it change the module choice? | RESOLVED (real, no change) | #5132 is CONFIRMED: CMVP validated-modules search shows "5132 \| Chainguard, Inc. \| Chainguard FIPS Provider for OpenSSL \| Software \| 01/14/2026" (§1 CMVP cite), and Chainguard's announcement states the 3.4.0-based module is "the only OpenSSL 3.4-based module to receive FIPS 140-3 validation", effective in their images 17 Mar 2026 (https://www.chainguard.dev/unchained/introducing-the-chainguard-fips-provider-for-openssl-3-4-0; published 11 Mar 2026; accessed 2026-09-24). It does NOT change the recipe: it is a vendor-owned cert on 3.4.0 sources a haskoki deployer cannot self-build under; the self-buildable upstream path stays #4985/3.1.2 (§3 step 1). NOTE for the watch: a NEWER Chainguard row exists — #5523, 09/15/2026 (same CMVP search cite; module version not shown in the table) — plus #5102 (Chainguard's 3.1.2, per the same announcement: "a version upgrade from OpenSSL 3.1.2 (CMVP #5102)"). Vendor-cert tracking is the flavor owner's job, not this doc's. Owner: future FIPS-flavor task (watch). |
| Q4 | PQC boundary: does the validated module cover post-quantum algorithms? | OPEN with criterion | No: the #4985 module is 3.1.2-based, which predates OpenSSL's PQC support (ML-KEM, ML-DSA, SLH-DSA arrived in 3.5, April 2025; the 3.5.4 submission is "the first step toward a FIPS-140 validated PQC-ready module" — PRLog 9 Oct 2025 cite in §1). Haskoki's catalog has no PQC mechanisms today (`scPqcSign = Set.empty`, `kcAlgs = Set.empty` at `src/Haskoki/Engine/OpenSSL4.hs:484-485`), so the gap is inherited, not created, by the flavor. Criterion to close: a validated PQC-ready module issues (watch Q1's row) AND a task extends the catalog + §4 item 8 narrowing to cover it. Owner: PQC-catalog task (future). |
| Q5 | Prior-synthesis-only note: does any claim in this doc rest solely on the earlier workflow synthesis? | RESOLVED by construction | Criterion: every load-bearing claim carries a fresh cite (live URL + access date, repo file:line, or spike log) — MET: §1–§5 cite 11 distinct live URLs (all accessed 2026-09-24), ~30 file:line pins at the 0.3.0.0 tree, and 6 spike logs. The workflow verdict survived as hypothesis only; §1 records where fresh evidence confirmed it (no 4.x validation/queue) and where it refined it (no 3.x library rebuild needed — the cross-version + spike finding). Owner: none (closed). |

## Citation index (load-bearing claims → fresh sources)

External (all accessed 2026-09-24): openssl-library.org
FIPS cert table (§1.1); CMVP validated-modules search +
MIP list (§1.1, Q1, Q3); openssl-corporation.org 140-3
migration blog (§1.1); PRLog 3.5.4-submission release
(§1.1, Q4); README-FIPS.md @openssl-4.0 (§1.2, §2, §3);
fips_module.pod @openssl-4.0 (§2); provider.pod @openssl-4.0
(§2); EVP_set_default_properties.pod @openssl-4.0 (§2);
chainguard.dev #5132 announcement (Q3); linuxiac.com 4.0
release notes (§2 `-defer_tests` corroboration). Tree:
toolchain.lock, Dockerfile, scripts/make-release.sh,
scripts/release-evidence.sh, src/Haskoki/Engine/{Backend,
Driver, OpenSSL4}.hs, ffi/Haskoki/FFI/OpenSSL4/Raw.hs,
cbits/ossl4_ctx.c, core/Haskoki/Operation/Cipher.hs,
src/Haskoki/Runtime/Config.hs, docs/{coverage,
config-honesty}.md, spec/vendor/pkcs11.h, working-paper PRD
(unshipped) — all pinned file:line at the 0.3.0.0 tree in §1–§6.
Spike (`/tmp`, NOT committed): build-noshared.log,
build-modules-noshared.log, build-312b.log, fips-openssl.cnf,
fips312-openssl.cnf, fipsmodule-312.cnf + install transcripts
(§1.3, §3).
