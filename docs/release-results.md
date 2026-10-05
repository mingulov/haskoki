# Release results — Haskoki 0.3.0.0 demo image (R4)

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
| smoke proxy | 743 | 379 | 374 | 0 | 364 | 5 | 0 | 0 | 0 |
| full direct | 11003 | 6060 | 5058 | 27 | 4943 | 975 | 0 | 0 | 1 |
| full proxy (standalone r4b) | 11003 | 6063 | 4838 | 39 | 4940 | 1185 | 1 | 0 | 1 |
| full proxy (driver4) | 11003 | 6064 | 4837 | 40 | 4939 | 1186 | 1 | 0 | 1 |
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

Proxy full carries 39 stable failed + 1 stable crash + 2
timing-flaky session-visibility ids (`test_verify_in_ro_session`,
`test_open_session_is_public`), each independently passed or
failed per run: r4b samples show 40 findings (pair passed),
driver4 shows 41 (`verify_in_ro` failed plus one skip-to-xfail
shift). The proxy counters above are complete per-sample
snapshots — passed/skipped/xfailed shift with the flaky ids, so
no cross-sample "exact" claim is made for them. Compare
direct-vs-proxy: 238 stable diff lines + 0–4 classified flaky
(r4b sample 240 with skip pair both; driver4 sample 240 the
same) + 12 shared findings. (R5 re-qualifies the 5 flaky ids
against the frozen parity subset.)

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
   F-BLAKE2B-KEYTYPE); proxied `_GENERAL` variants xfail earlier
   (lane divergence).
3. Proxy-only NULL-acceptance: NULL pointer + nonzero length
   accepted for HKDF salt/info, EDDSA context, CONCATENATE base
   data, `CKA_ALLOWED_MECHANISMS`; NULL length pointers leave
   encrypt/decrypt operations active.
4. Proxy-only PBE: generated IV reads back as 8 zero bytes.
5. `C_AsyncGetID` error tests fail on a CHECKER probe defect,
   not provider behavior: the child probe passes a `c_char`
   buffer where the declared signature requires `POINTER
   (c_ubyte)`, so ctypes raises `ArgumentError` before any
   module call (reproduced in-memory; R4 report §6.1 D4) —
   direct + proxy, native `failed` verdicts kept.

Fixed by the rc1 oracle (gone vs 0.2.2): CBC message singles ×4
(oracle recipe gap F-CBC-IV) and recover ×3 (oracle template gap
F-RECOVER-ATTRS) — 7 findings removed on both lanes with zero
retained-id churn.

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
  opensc `0.27.0~rc1-1`, proxy `a48b60b` (daemon/shim hashes in
  `environment.json`).
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
# smoke zero-findings, direct exact-27, proxy stable-40 core + flaky
# classification, compare 238 stable + shared-12 — plus exits,
# verdicts, and doctor/help/version gates; vector rows and full
# native counters are separate probe receipts, not driver asserts):
HASKOKI_DEMO_TEST_OUT=/tmp/r4-driver sh scripts/test-demo-image.sh
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

## Finding triage (condensed; full text in the R4 report §6)

Direct 27 (4 families): GCM-shape ×7; HOTP-params ×2; BLAKE2B
wrong-key-type ×16; async child-result ×2 (new). Proxy 40 (9
families): NULL-accepted ×5; session-visibility 1 stable (+2
flaky ids, passed in rc1 samples); counted AES-GCM-wrap crash ×1;
HOTP ×2; BLAKE2B non-GENERAL ×8; NULL op-termination ×8; PBE
zero-IV ×9; TLS/key/mac/safe derive ×4; async ×2. Shared
direct∩proxy: 12 (2 async + 2 HOTP + 8 BLAKE2B).

Skip/xfail causes, one model (jsonl call-record census, direct:
4,876 plain in 85 groups + 963 wasxfail; proxy: 4,873 + 1,173;
setup 67 plain + 12 xfail both lanes): not-advertised 1859;
registered-elsewhere 939; params-not-required 710; registry
negatives needing secret-key keygen 283+196; derive negatives
144; unsupported-by-module 138+111; no-KAT-vectors (persisted
post-fetch; mechanism-vs-mapping ambiguity) 90; generic-secret
88; DSA domain params 54; no-objects 23; tail 241 (73 groups).
Setup: destructive-gated 55, edwards setup-xfail 12, empty-param
5, limbo-missing 3, DigestXof-absent 4. wasxfail top: `CKA_LOCAL`
49, unwrap suites, keygen-rejected suites. Proxy-only xfail delta
(+210): BLAKE2B-HMAC, BLOWFISH, AES-GMAC, DES, AES-GCM-wrap.

Core dumps: direct 4, all `ffi_length` hostile-probe
grandchildren (crashing is the probe's design; each maps to an
EXTENDED-pass, `crashed=0`); proxy 21 = 19 identical probes + 2
counted AES-GCM worker crashes (the `crashed=1` verdict's
counterpart).

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
