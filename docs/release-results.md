# Release results — Haskoki 0.3.0.0 demo image (R4/R5)

What the external `pkcs11-check` oracle reports against the
release bundle, measured through the demo image on
`release/first-public`. Machine-readable companions in
[`release-results/`](release-results/) (`summary.json`,
`environment.json` — same numbers, normalized shapes).

Scope of every number below: the FROZEN offline profiles only
(smoke/full, `not (wycheproof or acvp or cctv or stress or fuzz
or slow)`), checker `0.2.3` (PyPI). Vector-corpus runs are
a separate, explicitly invoked path (§6). No number here is called
"all tests": each table row names its profile, mode, and selection.

No conformance percentage appears anywhere in this document by
design: pass counts do not measure feature coverage.

## One screen

Native runner counters (one entry per collected test; `failed`
and `crashed` are separate counters — findings = failed + crashed):

| lane | collected | executed | passed | failed | skipped | xfailed | crashed | timeout | exit |
|---|---|---|---|---|---|---|---|---|---|
| smoke direct | 743 | 379 | 373 | 0 | 364 | 6 | 0 | 0 | 0 |
| smoke proxy (a48b60b, R4) | 743 | 379 | 374 | 0 | 364 | 5 | 0 | 0 | 0 |
| smoke proxy (v0.2.0, R5) | 743 | 379 | 375 | 0 | 364 | 4 | 0 | 0 | 0 |
| smoke proxy (v0.2.2, R9, 3 samples identical) | 743 | 379 | 374 | 0 | 364 | 5 | 0 | 0 | 0 |
| full direct | 11003 | 6060 | 5058 | 27 | 4943 | 975 | 0 | 0 | 1 |
| full proxy (standalone r4b, a48b60b) | 11003 | 6063 | 4838 | 39 | 4940 | 1185 | 1 | 0 | 1 |
| full proxy (driver4, a48b60b) | 11003 | 6064 | 4837 | 40 | 4939 | 1186 | 1 | 0 | 1 |
| full proxy (v0.2.0, R5, 2 samples identical) | 11003 | 6060 | 4884 | 25 | 4943 | 1151 | 0 | 0 | 1 |
| full proxy (v0.2.2, R9) | 11003 | 6060 | 5019 | 27 | 4943 | 1014 | 0 | 0 | 1 |
| cctv vectors direct | 1365 | 1365 | 1364 | 0 | 0 | 1 | 0 | 0 | 0 |
| full direct + vectors | 11711 | 6776 | 5772 | 27 | 4935 | 977 | 0 | 0 | 1 |

`collected` = runner total; `executed` = NON-SKIPPED verdicts
(= passed+failed+error+xfailed+xpassed+crashed+timeout;
identity verified on every lane above). This is outcome
arithmetic, NOT test-body execution: call-phase skips (4876
direct) executed setup before skipping, while setup-phase
xfails (12) never reached the test body — and crashed/timeout
verdicts mean the body may have run only partially. The native
summary does not report per-test body execution, so true
executed-test count is `unknown`; phase detail comes from the
jsonl census (R4 report §2).

Direct rows are pin-independent: the v0.2.0 image reproduces
the exact R4 direct summaries and the identical 27-finding set
(backend unchanged; verified diff-empty), and the v0.2.2 image
reproduces them again (R9 driver: same counters, exact-27 match).

Proxy full on v0.2.0 carries 25 failed + 0 crashed. The
2 historical failed-pair ids (`test_verify_in_ro_session`,
`test_open_session_is_public`) now PASS as R5 §4
stable-eligible and sit OUTSIDE the 25 findings (both passed
in both R5 full samples, as in all R4 rc1 samples — which
does not prove fixed; any re-flip fails the gate).
The proxy counters above are complete per-sample snapshots.
Compare direct-vs-proxy on v0.2.0 (parity subset FROZEN in
R5): 188 exclusion lines in 7 reasoned families, ZERO allowed
variants (all 5 R4 flaky ids re-qualified stable-eligible in
R5 §4) + 25 shared findings, zero proxy-only findings.
(R4 a48b60b numbers retained above for the pin delta: 40/41
findings, including one crash, 238 diffs, 12 shared.)

Counting model: the checker's `results.json` summary.
`units[].tests` lists non-passed outcomes only. Unknown outcomes
are never reported as 0 — every outcome counter above comes
straight from the runner summary; `executed` is derived outcome
arithmetic (see above), and true test-body execution is
explicitly `unknown` (not measurable from the native summary).

Top limitations (see §5 for the full triage, with oracle
attributions from `docs/pkcs11-oracle-triage.md` §T-M06):

1. Message-init shape contract: native `CK_GCM_MESSAGE_PARAMS`
   refused with `CKR_ARGUMENTS_BAD` — message-init accepts
   classic-shaped params only (provider capability contract,
   T-M06 F-GCM-SHAPE); HOTP NULL params refused (oracle recipe
   gap, F-HOTP-PARAMS) — direct + proxy.
2. Wrong-key-type negatives accepted (`CKR_OK` instead of
   rejection) on BLAKE2B-HMAC message sign/verify — no
   `KeyMatrix` BLAKE2B rows (provider matrix gap,
   F-BLAKE2B-KEYTYPE) — direct + proxy (all 16 shared on
   v0.2.0; the a48b60b `_GENERAL` lane divergence is gone).
3. Proxy message-init validation (v0.2.0, subset-excluded):
   IV-shaped message params refused with `0x71` for 153 tests
   the backend serves (upstream
   `mingulov/pkcs11-proxy-ng#39`, repro + 3-lane proof in R5
   report §2); proxied Blowfish fully inoperative through the
   same advertised-but-rejected shape (20 tests, embedded
   catalog lacks `0x1094`, checker lanes run embedded-only).
4. Proxy derive/template validation deltas (v0.2.0,
   subset-excluded): TLS key-and-mac derive `0x71` (×2),
   WTLS premaster `0x71` (×3), two boundary
   check-order inversions (×2) — reasons in R5 report §1.
5. `C_AsyncGetID` error tests fail on a CHECKER probe defect,
   not provider behavior: the child probe passes a `c_char`
   buffer where the declared signature requires `POINTER
   (c_ubyte)`, so ctypes raises `ArgumentError` before any
   module call (reproduced in-memory; R4 report §6.1 D4) —
   direct + proxy, native `failed` verdicts kept.

Fixed by the v0.2.0 proxy (gone vs a48b60b, 27 findings +
crash): NULL-acceptance ×5 + NULL op-termination ×8,
PBE zero-IV ×9, session-visibility stable ×1,
AES-GCM-wrap crash ×1, TLS/key/mac/safe derive ×4
(three now pass both lanes, `tls_key_and_mac_derive`
xfails on `0x71`) — zero proxy-only findings remain (25
proxy = 25 shared; v0.2.0 newly fails the GCM-message ×5
and BLAKE2B-`_GENERAL` ×8 that direct fails, all shared).
Fixed by the rc1 oracle (gone
vs 0.2.2): CBC message singles ×4 (F-CBC-IV) and recover
×3 (F-RECOVER-ATTRS) — 7 findings removed on both lanes
with zero retained-id churn.

## Profiles (FROZEN in R4)

`examples/release/pkcs11-check/profiles.conf` — the profile
SELECTORS are identical in the image; only measurement comments
differ (R3 values updated to R4 in the repo file; both hashes in
`environment.json`):

- `SMOKE_MARKER` / `FULL_MARKER`: `not (wycheproof or acvp or
  cctv or stress or fuzz or slow)` — the CI fast-lane marker
  verbatim (`scripts/ci-pkcs11-lane.sh`).
- `SMOKE_MATCH`: `interface or slot or digest or profiles`.
- `FULL_MATCH`: empty (whole suite under the offline marker).
- `CHECK_SLOT=0`, `CHECK_TIMEOUT=180` (per-test seconds),
  isolation `auto`, PINs user `1234` / SO `5678` (PUBLIC
  fixtures), memory-store backend (`backend-memory.toml`, body
  identical to `scripts/ci-backend.toml`).
- `doctor` is a hard gate before every `test`.

Scope: offline only — no vector corpora, no stress/fuzz/slow,
destructive tests OFF (55 destructive skips are by design; there
is no destructive profile in this image, and no entrypoint flag
can enable destructive runs against non-disposable state: the
checker manages its own keys in a per-run memory store).

## Environment (summary; full manifest in `environment.json`)

- Image: `haskoki-demo:0.3.0.0` (id recorded in
  `environment.json` from the passing driver record).
- Bundle: `haskoki-0.3.0.0` rebuilt inside the image;
  `libhaskoki.so` exposes PKCS#11 v3.2, 316 mechanisms.
- Slot 0: `haskoki-demo` token (memory backend +
  minimal-demo fixtures seat exactly one token-present slot;
  `--slot` is a 0-based index into token-present slots —
  `--slot 1` fails with that hint).
- Checker `pkcs11-check 0.2.3` (PyPI pin), Python 3.14.4,
  opensc `0.27.0~rc1-1`, proxy `v0.2.2` (tag `v0.2.2` =
  `1ed7cc15…`; daemon/shim hashes in `environment.json`;
  R4/R5 rows above retain the superseded pins).
- OS/arch: Ubuntu 26.04 container, x86_64.

## Reproduce

```sh
# Build (from the `haskoki/` repo root — the git root of this commit):
docker build -f docker/Dockerfile.demo -t haskoki-demo:0.3.0.0 .
# Lanes (each writes a run dir under ./out):
docker run --rm --network none -v "$PWD/out:/out" haskoki-demo:0.3.0.0 \
  check --mode direct --profile smoke
docker run --rm --network none -v "$PWD/out:/out" haskoki-demo:0.3.0.0 \
  check --mode direct --profile full
docker run --rm --network none -v "$PWD/out:/out" haskoki-demo:0.3.0.0 \
  check --mode proxy --profile full
docker run --rm --network none -v "$PWD/out:/out" haskoki-demo:0.3.0.0 compare
# Full gate (rebuilds the image; asserts the offline finding sets —
# smoke zero-findings, direct exact-27, proxy exact-27, compare
# exact-83 + shared-27 (zero variants anywhere) — plus exits,
# verdicts, and doctor/help/version gates; vector rows and full
# native counters are separate probe receipts, not driver asserts):
HASKOKI_DEMO_TEST_OUT=/tmp/r9-driver2 sh scripts/test-demo-image.sh
```

Each run dir keeps the raw reports unedited (`results.json`,
`report.jsonl`, `checker.log`, `report.json`, `findings.txt`,
plus `doctor.out`/`doctor.err`, `backend.toml`, `state.json`;
proxy runs add `proxy.toml`); no outcome is ever edited. Big raw
logs belong to release assets/CI artifacts; this document
carries the compact numbers. (Bare-checker probe dirs carry a
subset: `results.json`, `report.jsonl`, `test.log`,
`backend.toml` — no `report.json`/`findings.txt`, which are
entrypoint products.)

## Finding triage (condensed; R4 full text in its report §6, R5 in §1)

Direct 27 (4 families, identical set R4→R5): GCM-shape ×7;
HOTP-params ×2; BLAKE2B wrong-key-type ×16; async child-result
×2. Proxy on v0.2.0: 25, all shared, zero proxy-only (async ×2;
GCM-message ×5; HOTP ×2; BLAKE2B ×16). Compare exclusions (188,
frozen subset): message-init `0x71` ×153 (upstream #39);
Blowfish catalog ×20; TLS-derive ×2; WTLS-premaster ×3;
boundary check-order ×2; GMAC direct-only ×2; proxy-better
spec-code inversions ×6 — per-id reasons in R5 report §1.
(R4 a48b60b for the delta: proxy 40 in 9 families, 238 diffs,
12 shared.)

Skip/xfail causes, one model (R5 jsonl census on v0.2.0 lanes;
direct table byte-identical to R4): direct 4,876 plain in 85
groups + 963 wasxfail; proxy 4,876 plain (same table) + 1,139
wasxfail; setup 67 plain + 12 xfail both lanes.
not-advertised 1859; registered-elsewhere 939;
params-not-required 710; registry negatives needing secret-key
keygen 283+196; derive negatives 144; unsupported-by-module
138+111; no-KAT-vectors (persisted post-fetch;
mechanism-vs-mapping ambiguity) 90; generic-secret 88; DSA
domain params 54; no-objects 23; tail 241 (73 groups). Setup:
destructive-gated 55, edwards setup-xfail 12, empty-param 5,
limbo-missing 3, DigestXof-absent 4. wasxfail top (identical
both lanes): `CKA_LOCAL` 49, unwrap suites, keygen-rejected
suites. Proxy-only xfail delta (+176 over direct): message-init
`0x71` family, Blowfish, TLS/WTLS/boundary validation.

Core dumps: `crashed=0` verdicts both lanes on v0.2.0 (the two
counted AES-GCM worker crashes are gone). The
hostile-probe-grandchildren mechanism (R4 §6.5: crashing is the
probe's design, each maps to EXTENDED-pass) stands by
reference; no counted-crash counterpart exists to explain on
this pin, so no recount was run.

## Vector-data runs (§6)

Fetch inside the image (CA store present since R4; without it
every fetch fails TLS verification):

```sh
mkdir -p vectors
docker run --rm --entrypoint /opt/p11c/bin/pkcs11-check \
  -v "$PWD/vectors:/data" haskoki-demo:0.3.0.0 \
  fetch-data all --data-dir /data
```

Measured: exit 0, `Done. All sources fetched.`, 872M —
wycheproof 27.1MB/344 files, cctv 1.6MB/53, acvp 527MB/881,
x509-limbo 15.9MB/129 — each `Checksum OK`. Pins: `usnistgov/
ACVP-Server 975de31e` (2026-08-12), `C2SP/CCTV 4448f209`
(2026-08-29), `C2SP/wycheproof 3fa63dd0` (2026-09-02),
C2SP/x509-limbo `11872133` (2026-09-14); full hashes in
`environment.json` and the data dir's `versions.json`
(identical between 0.2.2 and 0.2.3 modulo `fetched_at`).

`fetch-data` exits: 0 fetched, 1 failure (per-source failure
listed; checksum mismatch aborts that source), 2 unknown
source. Retry = re-run the same command: it re-downloads,
re-verifies, and replaces each `data/<source>/` dir in place
(not incremental). Keep the data dir exclusively owned by
fetch-data: the installer `rmtree`s `data_dir/<source>` before
installing, which deletes ANY file inside that per-source dir —
including foreign files you placed there. Outside the per-source
dirs it rewrites only `data_dir/versions.json` (the fetch
manifest) — nothing else — so cleanup = delete the per-source
dir(s) (or the whole exclusively-owned data dir); never point
`--data-dir` at a directory containing other work.

Run vectors against the image (read-only mount; the checker
resolves data via `PKCS11_CHECK_DATA_DIR`, evaluated at module
load — `test` has no `--data-dir` flag). The guard is
mandatory: a vector selection without data collapses to a
near-empty passing run (measured: the 1365-test `cctv` group
collects 4 tests and exits 0 with no data mounted). Require the
SELECTED corpus plus its frozen pin plus every vector file the
marker consumes — an unrelated dir, an empty dir, a wrong pin,
or a partial corpus must not pass:

```sh
DATA="$PWD/vectors"; MARK=cctv   # the marker you are about to run
[ -d "$DATA/$MARK" ] && [ -n "$(ls -A "$DATA/$MARK")" ] \
  || { echo "no $MARK vectors under $DATA" >&2; exit 2; }
# The pin must EQUAL the frozen value (environment.json
# corpora.cctv.commit) — a missing, null, or wrong pin fails here:
python3 -c "
import json, sys
want = '4448f2097b2daa812c91a26141f9f36c2096b9ca'
got = json.load(open('$DATA/versions.json')).get('$MARK', {}).get('commit')
sys.exit(0 if got == want else 'bad $MARK pin: %r' % (got,))" || exit 2
# The checker loads these files and silently skips when they are
# absent — measured: cctv without the 188-vector ML-DSA-44 file
# still collects 1177 tests and exits 0, above the floor — so
# require each one (paths the checker resolves under
# PKCS11_CHECK_DATA_DIR/cctv):
for f in ed25519/ed25519vectors.json ML-DSA/benchmark/ML-DSA-44.json \
    ML-DSA/benchmark/ML-DSA-65.json ML-DSA/benchmark/ML-DSA-87.json; do
  [ -s "$DATA/cctv/$f" ] \
    || { echo "missing cctv vector file: $f" >&2; exit 2; }
done
```

Run vectors against the image (read-only mount; the checker
resolves data via `PKCS11_CHECK_DATA_DIR`, evaluated at module
load — `test` has no `--data-dir` flag). Each run gets a FRESH
unique dir (`mktemp -d`): never reuse a run dir, or the floor
check below can validate a previous run's output after a failed
invocation. The pasted sequence ends by propagating both
checker statuses — a checker exit 1 must not be masked by a
passing floor check:

```sh
VOUT="$(mktemp -d "$PWD/vout.XXXXXX")"; STATUS=0
docker run --rm --network none --entrypoint sh \
  -e PKCS11_CHECK_DATA_DIR=/data -e P11TEST_PIN=1234 \
  -e P11TEST_SO_PIN=5678 -v "$DATA:/data:ro" \
  -v "$VOUT:/out" haskoki-demo:0.3.0.0 -c '
  cp /opt/haskoki/examples/release/pkcs11-check/backend-memory.toml /out/backend.toml
  cd /out && HASKOKI_CONFIG=/out/backend.toml /opt/p11c/bin/pkcs11-check test \
    --module /opt/haskoki/dist-release/haskoki-0.3.0.0/lib/libhaskoki.so \
    --slot 0 --isolation auto --timeout 180 --marker "cctv" \
    --output json --output-file /out/results.json' || STATUS=$?
```

(`cd /out` matters: the checker writes `report.jsonl` to its
working directory.) After the run, assert meaningful collection —
a floor appropriate to the marker (`cctv` collected 1365 with
data vs 4 without; fail below 1000) — the checker status
captured in `$STATUS` is propagated by the last line of the
sequence:

```sh
python3 -c "
import json, sys
t = json.load(open('$VOUT/results.json'))['summary']['total']
sys.exit(0 if t > 1000 else 'vector run collected only %d tests' % t)" \
  || exit 2
```

Repeat without `--network none` into a second fresh dir and
require byte-equal summaries (the corpus is local; network must
change nothing):

```sh
VOUT_NET="$(mktemp -d "$PWD/vout-net.XXXXXX")"; STATUS_NET=0
docker run --rm --entrypoint sh \
  -e PKCS11_CHECK_DATA_DIR=/data -e P11TEST_PIN=1234 \
  -e P11TEST_SO_PIN=5678 -v "$DATA:/data:ro" \
  -v "$VOUT_NET:/out" haskoki-demo:0.3.0.0 -c '
  cp /opt/haskoki/examples/release/pkcs11-check/backend-memory.toml /out/backend.toml
  cd /out && HASKOKI_CONFIG=/out/backend.toml /opt/p11c/bin/pkcs11-check test \
    --module /opt/haskoki/dist-release/haskoki-0.3.0.0/lib/libhaskoki.so \
    --slot 0 --isolation auto --timeout 180 --marker "cctv" \
    --output json --output-file /out/results.json' || STATUS_NET=$?
python3 -c "
import json, sys
t = json.load(open('$VOUT_NET/results.json'))['summary']['total']
sys.exit(0 if t > 1000 else 'vector run collected only %d tests' % t)" \
  || exit 2
python3 -c "
import json, sys
a = json.load(open('$VOUT/results.json'))['summary']
b = json.load(open('$VOUT_NET/results.json'))['summary']
sys.exit(0 if a == b else 'nonet summary differs: %r vs %r' % (a, b))" \
  || exit 2
[ "$STATUS" -eq 0 ] && [ "$STATUS_NET" -eq 0 ]
```

Measured `cctv` with data: 1365 tests, 1364 passed, 1 xfailed
(RFC 6979 deterministic-k: the module uses random-k ECDSA),
0 failed — byte-identical summaries with and without
`--network none`. Unavailable data, explicitly: with no data
mounted the group collapses to 4 tests (1 passed, 2 skipped,
1 xfailed) and exits 0 — the guard + floor above exist to forbid
exactly that. Full offline selection with data: 11711 tests
(+708: 698 x509-limbo import vectors and others), same exact 27
findings. The 90 `No KAT vectors` skips persisted after fetching
the full corpus: either those mechanisms have no vectors in any
fetched corpus, or the checker has no mapping from those
mechanisms to the corpus files — the skip text does not
distinguish the two, and R4 did not chase it further. Smoke
fixtures stay embedded in the image — offline lanes need no mount.

Timeout guidance (measured unit durations, seconds of test
execution, 0.2.3 lanes): direct 227 units / 966s sum / 125s
max; proxy 227 units / 1160s sum / 118s max; `cctv` 16s total.
The 180s per-test default never fired (0 timeouts in every R4
lane). Measured wall clock: direct/full ~17 min, proxy/full
~20 min, compare ~47 min on this class of machine — and never
run two checker lanes concurrently (R3d timing sensitivity).

## What R4 did not do

- No parity-subset freeze (R5), no flaky-id re-qualification
  (R5), no engine behavior change of any kind.
- No full `not (stress or fuzz)` kat sweep from the image (the
  CI kat lane owns that; R4 proved the data path on the `cctv`
  group + full-offline-with-data instead).
- No destructive profile (destructive tests stay off; nothing
  in the image can aim them at non-disposable state).
- Checker 0.2.3 notes: r4b evidence lanes ran on 0.2.3rc1,
  proven code-identical to the 0.2.3 final (wheel diff apart
  from version stamps) with a behavioral smoke confirm; the
  driver re-proves the offline entrypoint lanes on the final
  pin (fetch/CCTV/nonet-vector/full-with-vectors evidence is
  rc1-measured, transferred by verified checker source
  identity).
- Update (R5): parity subset frozen (188 exclusions, zero
  variants, §1 of the R5 report), the 5 R4 flaky ids
  re-qualified stable-eligible (R5 §4), proxy re-pinned
  `a48b60b` → `v0.2.0` and qualified (parity 49 holds / 40
  skips + full checker lanes, R5 §2). Still no engine
  behavior change of any kind.
- Update (R9): proxy re-pinned `v0.2.0` → `v0.2.2`
  (`1ed7cc15…`; upstream #35/#36/#37/#39 closed with
  verification probes) and re-qualified: parity 70 holds /
  19 skipped legs in 5 quarantine entries, proxy/full stable
  set 27 (all shared, +2 GMAC),
  subset re-frozen to 83 exclusions in 6 families + 27
  shared (every delta caused in §4 of the R9 report; the
  R5 figures above stay as the v0.2.0 historical record).
  Still no engine behavior change of any kind.

## Figure sourcing record (R6 completeness correction)

Every user-facing figure traces to exactly one record in this
document; nothing here is re-measured (all values were measured
in R3/R5/R6 or by the cited publication/spec checks — the R6
rows are the installed-`ctl` outputs, the `doctor` outcomes,
and the p11scope capture below). README and the walkthrough
cite this document, never a log.

Headline lanes (measured through the demo image; rows in One
screen above): smoke 743 collected, zero findings direct and
proxied; full 11003 collected, direct 27 findings, proxy
(v0.2.0, R5) 25 findings all shared, zero proxy-only; proxy
(v0.2.2, R9) 27 findings all shared, zero proxy-only. Compare:
R5 188 frozen exclusions in 7 families + 25 shared findings;
R9 83 in 6 families + 27 shared (Finding triage above; per-id
reasons in the frozen sets).

Driver-lane figures (passing R5 driver record,
`HASKOKI_DEMO_TEST_OUT=… sh scripts/test-demo-image.sh`, exit
0; R9 driver re-verified identical figures on the v0.2.2
image): demo 8/8 verifications hold (`demo-ok` marker,
asserted by the driver); proxy-example 5/5 steps hold
(`proxy-example-ok`, `known_differences: []`); usage-error
matrix 8/8 exit 2; glibc floor GLIBC_2.43 overall (driver
assert over bundle + proxy + venv ELFs), proxy ELFs group
maximum 2.34 (driver floor-leg record).

Catalog figures (`python3 scripts/publish-coverage.py --check`,
464 rows, 14 issues): 464 catalog mechanisms = 316
behavior-tested + 89 unsupported-with-reason + 2 not-applicable
+ 57 planned (behavior column; the 316 tested rows are the
C-surface served catalog; `docs/coverage.md`).

p11scope capture (primary record `docs/p11scope-trace.md`;
artifact `cap.json`, 315966 bytes, schema
`p11scope/observed-profile/v3`, NOT shipped — re-run the recipe
there): 60 s of `check --mode direct --profile full` (start
2026-10-06T03:12:28Z), 36 attributed calls across 9 named
functions, `evidence.completeness = PARTIAL`, 496 slots
count-only, mechanisms table EMPTY (`[]`), attach refusal
"module needs 104 more of the 512 attach slots; 496 are in
use", provider `libhaskoki.so` hash-pinned `sha256
5bad965f…`, 40 pid/descendant gaps, 20 `discovery unavailable`
+ 1 unwalked function-table-layout subjects. Per-function
attribution (the full 36 calls; replicated from the primary
record so this document stays the sole number source):

| Function | Calls | Errors | Return codes |
|---|---|---|---|
| C_GetSlotList | 8 | 0 | 8 × `0x0` |
| C_CloseSession | 5 | 0 | 5 × `0x0` |
| C_Finalize | 4 | 0 | 4 × `0x0` |
| C_OpenSession | 4 | 0 | 4 × `0x0` |
| C_Login | 4 | 0 | 4 × `0x0` |
| C_Initialize | 3 | 0 | 3 × `0x0` |
| C_CreateObject | 3 | 3 | 3 × `0xd0` |
| C_GetInterface | 3 | 0 | 3 × `0x0` |
| C_Logout | 2 | 0 | 2 × `0x0` |

Native test extents and observed operator outputs (R6):
installed `haskoki-ctl` 0.3.0.0 prints `template-bounds:
entries=64 bytes=4194304`; scenario
`pending-sign-and-token-removal` runs 12 steps and
`sim-delay-token-fault` 22 steps (byte-identical across 3 runs
per `SimBridgeSpec.caseSimScenario`); streaming legs are 1/8/20
MiB in 64 KiB parts (`tests/c/consumer_streaming.c`) against
the 16 MiB `maxBuffered` backstop
(`core/Haskoki/Operation.hs`) and under the proxy's 4 MiB
default message cap; notifications parity (T-N09 reviewed
evidence) is 72 rich direct legs with 153 matching eligible
polling lines, direct 3.1 executing all 37 assertions as
topology inventory; the function catalog is 104 rows = 78
planned-with-behavior + 24 unsupported-with-reason + 2
not-applicable (`spec/function-contracts.json`); sim stress
defaults are N=4/M=50/iters=20000
(`tests/c/sim_threaded.c`); seed and generate caps are 1 MiB
each (`seedRandomMaxBytes`, `generateRandomMaxBytes`);
p11scope `doctor` exits 0 with zero FAILs privileged, exit 1
with 3 FAILs unprivileged.

## Staging appendix (R8 release candidate)

Built from worktree at `a2fe4f9` plus the R8 changes (OCI
labels + staged-bundle consumption: the Dockerfile COPYs the
tree the driver stages instead of rebuilding it). Measurement
lanes re-run in full on the staged image:

- Driver `HASKOKI_DEMO_TEST_OUT=/tmp/r8-driver2 sh
  scripts/test-demo-image.sh`: exit 0,
  `PASS: test-demo-image.sh (demo + check x4 + compare +
  help/matrix/examples/json + UID + nonet + floor)`. Wall
  ~85 min (staging + cached build, then lanes 07:48Z→09:10Z,
  console close 09:13Z, 5100 s total): staging (3 s, warm
  incremental) + cached build ≈ 23 s to the first lane,
  demo seconds + smokes 129 s / 134 s, full direct 841 s
  (exact 27), full proxy 1159 s (25 stable, byte-exact),
  compare 2105 s (188+25 exact), tail legs ≈ 12 min
  (report mtimes: demo 07:48:46Z, smokes 07:50:56Z /
  07:53:11Z, fulls 08:07:13Z / 08:26:38Z, compare
  09:01:44Z).
- Driver image id
  `sha256:0780f24f86ddad546f876f204717960794da0edf0b01a592710458635181ff1b`
  (revision label `unknown`, honest local default);
  506300511 B.
- Candidate `haskoki-demo:r8-candidate` (the CI form:
  staged tree + `--build-arg
  REVISION=a2fe4f93f242c28185daacf46da9865a49f01e08`):
  id `sha256:1561da951cf365e1bf4cf7472681ef0531c44702f5d4399402df5713724ca1fa`,
  506300885 B, demo 8/8 + smoke zero-findings re-proven on
  it (direct 09:14Z, proxy 09:20Z).
- Full-filesystem comparison (driver image vs candidate:
  both `docker save` outputs unpacked layer by layer,
  every regular file hashed — method in
  `ws/r8-evidence/tree-diff/round2/fsdiff.sh`): 12,339
  files per image, identical file sets, 12,333
  byte-identical; the 6 that differ are build-mechanical
  only — `/tmp/ldd-so.txt` (ASLR addresses, zero
  non-address lines after normalization),
  `/var/cache/ldconfig/aux-cache` (regenerated binary
  cache, same 5458 B), and four apt/dpkg logs
  (timestamps / APT-ID numbers only: history, term, and
  dpkg are strip-identical, eipp differs in 12 APT-ID
  lines). The five bundle record files are identical
  across images (single staged tree). Spot shas on the
  candidate: libhaskoki `ef13f1a0…` (the staged tree,
  same in both images), entrypoint `1afe3bdf…`, proxy
  `8b7def0f…`; same deb versions. Layer-history commands
  differ in 4 line-pairs, all carrying only the REVISION
  value (unknown vs tag SHA) — that arg cache-busts the
  apt layer, which explains the log/cache diffs above.
  Whole-image byte identity is NOT claimed.
- Base `ubuntu:26.04`
  `sha256:513c074113a871b51a8d16ab445c88779d6452d937a164fb5cc479f32668a41d`;
  proxy toolchain `rust:1.94-bookworm`
  `sha256:6ae102bdbf528294bc79ad6e1fae682f6f7c2a6e6621506ba959f9685b308a55`;
  builder `haskoki-dev:ghc-9.10.3`
  `sha256:0ee486d207331df09625f19cceeca3fe63f245477a6374e085e61da04c2bf699`.
- Group maxima (re-measured on the candidate): bundle
  GLIBC_2.43 (27 ELFs), proxy GLIBC_2.34 (2 ELFs), venv
  GLIBC_2.34 (10 ELFs); floor GLIBC_2.43 holds (system
  python3.14 at 2.38).
- Negatives (candidate image; full commands + exits in
  `ws/r8-evidence/negatives/`): readonly `/out` →
  `haskoki-demo: output dir not writable: /out`, exit 2;
  busy proxy port (port occupied in-container, proven by a
  bind probe) → `haskoki-demo: proxy port 17512 already
  busy (one run at a time)`, exit 2; kat missing-data
  guard → exit 1 with the exact script message; post-run:
  no stray containers, port free, run dirs intact.
- Content audit (commands + exits preserved): no
  credentials, key material, journals, or stray workspace
  files in image or archives. Name hits are checker/venv
  code only (`_secrets.py` redaction policy,
  `test_*secret*`/`test_private_key*` modules,
  `asn1crypto/pem.py`, CA bundle); `BEGIN … PRIVATE KEY`
  hits are `cryptography` format-string constants
  (`_SK_START`). Demo PINs are public fixtures by design.
  Archive top dirs match the documented tree.
- Tag-build delta (observed vs future): the comparison
  above measures one cached rebuild pair (same tree,
  different REVISION) — 6 build-mechanical diffs. A future
  tag build additionally re-resolves floating inputs
  (apt/PyPI/crates registries, base/toolchain tags), so
  its delta is NOT limited to those 6; the CI `demo-image`
  job re-runs all entrypoint lanes on the tag tree, and
  `publish` records the pushed digest. No equivalence
  with any earlier build is claimed.
- Single-bundle provenance (staged-only): the bundle is
  built ONCE — by the CI `bundle` job (`/work`) or the
  local driver staging step — and consumed unchanged by
  the demo image (`COPY staged-bundle/`), the lanes, and
  the archives. `libhaskoki.so` RUNPATH anchors at
  `/work/dist-newstyle/…` in all of them. The staged
  module hash `ef13f1a0…` reproduces exactly across the
  R1, driver, and candidate builds (core sources
  unchanged); the earlier cross-image pair is closed by
  construction — there is no second bundle build.
