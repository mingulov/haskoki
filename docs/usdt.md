# Haskoki USDT observability

Haskoki emits USDT probes in two providers from `libhaskoki.so`:

- `crypto_auditing`: Latchset-compatible records, one per delivered
  public-key operation, consumable by an unmodified `crau-agent`.
- `haskoki`: private namespace with per-operation outcomes
  (`operation_end`), admission denials (`policy_reject`), and async
  job lifecycle (`job_state`).

Probes compile in behind the manual `usdt` Cabal flag
(`haskoki.cabal`, default off). The official release bundle and
demo image build with `--flags=+usdt` (`scripts/make-release.sh`
gates the shipped module's exact probe manifest); source builds
carry zero probe notes unless the flag is enabled (gated both ways
in CI: `check-usdt-probes.py`, exact manifest on, zero notes off).

## Probe reference

### `crypto_auditing` (Latchset-compatible)

Two probes, always paired within one call (see
[Emission semantics](#emission-semantics)):

| Probe | Args |
|---|---|
| `new_context_with_data` | `(long)ctx_id`, `(long)parent_id`, `data*`, `n_fields` |
| `release_context` | `(long)ctx_id` |

Each `data` element is `{const char *key; const void *value;
unsigned long value_size}` with `value_size == -1` for
NUL-terminated strings and `-2` for machine words by value
(`cbits/usdt.h`, mirroring OpenSSL's extended array shape).

One record per delivered operation; contexts and their fields:

| Context | Fields |
|---|---|
| `pk::sign`, `pk::verify` | `name`, `pk::algorithm`, `pk::bits`, `pk::hash`, `pk::rsa_padding` |
| `pk::encrypt`, `pk::decrypt` | `name`, `pk::algorithm`, `pk::bits`, `pk::hash`, `pk::rsa_padding` |
| `pk::encapsulate`, `pk::decapsulate` | `name`, `pk::algorithm` (algorithm-only) |
| `pk::generate`, `pk::derive` | `name`, `pk::algorithm`, `pk::curve`/`pk::group`/`pk::bits` as known |

Fields with code 0 omit. Hash/padding appear only on sign,
verify, encrypt, and decrypt contexts. Generic PSS/OAEP mechanisms
resolve the real hash from the validated parameters (slot spec on
the live path, plan-accepted call params on the slotless wrap
path); anything else resolves from the mechanism name
(`hashOfValidated` in `src/Haskoki/Runtime/Usdt.hs`, pinned by
`tests/model/UsdtMapSpec.hs` and the OAEP/PSS live legs).

Symmetric, MAC, KDF, and digest traffic stays private-only (an
`operation_end`, never a `pk::` record), as do unmappable bases
(the XOR-over-generic-secret leg asserts end-only). Composite
wraps stay private pending upstream agreement.

### `haskoki` (private)

All arguments are machine words.

`operation_end(op, func, mech, mech_present, ckr, disposition, mode)`:
one end per admitted operation. `func` is the `FunctionId` code,
`mech` the mechanism id (0/absent when slotless), `ckr` the
reported code word.

`policy_reject(op, op_valid, func, mech, mech_present, reason, ckr)`:
admission denials with a reason class (see below). Zero or more
per denied call; terminal only when the same decision commits the
teardown.

`job_state(table, job, op, op_valid, phase, ckr, ckr_valid)`:
async job transitions; `table`/`job` identify the job, `op`
correlates with the operation end.

Code tables:

| Enum | Codes |
|---|---|
| Disposition | 1 delivered, 3 failed-publish, 4 failed-writeback, 5 abandoned (2 failed-exec reserved, never emitted) |
| OpMode | 0 sync, 1 async |
| PolicyReason | 1 auth, 2 usage, 3 readonly, 4 template, 5 state |
| JobPhase | 1 accepted, 2 claimed, 3 ready, 4 delivered, 5 failed, 6 canceled |

Codes are pinned both ways: `tests/model/UsdtMapSpec.hs` on the
Haskell side, `scripts/check-usdt-codes.py` against `cbits/usdt.h`.

## Emission semantics

- Same-call pairing: every `new_context_with_data` is released in
  the same C call, because collectors bind context identity to
  pid/tgid while Haskoki operations can complete on another thread
  than they started on.
- Correlation: the context id equals the `haskoki` op id of the
  same delivery (`ctx == op`), so the private end joins the public
  record without inference.
- Orphan parents: `parent_id` is always `(long)-1`; Haskoki never
  nests contexts.
- Exactly-once ends: each admitted operation gets one
  `operation_end`. Staged (short-buffered) bytes dying anywhere —
  close, cancel, logout, guard refusal, decoder refusal,
  key-resolution refusal — get the abandoned end from the
  centralized teardown flush (`terminateSlot`); finalize-time
  abandonment stays silent by design.
- Silence: inits, updates, and size queries emit nothing on
  success; failures without policy relevance and without dying
  staged bytes stay silent. Caller-bug refusals before admission
  (NULL arguments, oversize lengths) arm nothing.
- Verdicts: committed negative verdicts (bad signature, including
  degenerate empty-signature calls) emit exactly like successful
  deliveries; the record describes the attempt, the end carries
  the verdict code.
- Op ids: C-owned atomic counter, 1-based, tagged `'HSK0'` in the
  low word, nonzero and ordered. Silent failures still allocate
  ids, so ids are neither contiguous nor dense; correlate, never
  count on sequence. Saturation (past `UINT32_MAX`) skips emission
  and counts `hsk_usdt_saturations`.
- Slots: management calls without slots (login, PIN changes,
  object create/copy/set-attribute) emit the policy half on
  denials plus a bare end claim carrying only function identity.

## Redaction boundary

No secret bytes cross the probe interface, by construction and by
gate. The FFI imports take `Word32`/`Word64` only; the C entry
points take `uint32_t`/`uint64_t` only; record strings come from
C static tables indexed by enum code
(`scripts/check-usdt-redaction.py` pins all three layers plus the
fixture battery). The mapping layer is content-independent in key
material: swapping distinctive fixture secrets changes no emitted
fact (`UsdtMapSpec` "secret content independence"). This matches
the JSONL trace redaction discipline. Curve/group selection from
validated OIDs is metadata, not secret, and the registry requires
`pk::curve`.

## Consumer guide

### crau-agent

Point the agent at the built module. With the Latchset
`crypto-auditing` collector checked out beside the bundle:

```
# agent.conf: the staged library path is the only Haskoki-specific
# setting; providers/probes are the standard crypto_auditing set.
```

Run the agent against any PKCS#11 workload over
`libhaskoki.so`; RSA/ECDSA/ML-DSA and KEM usage land in the
existing `crypto_auditing` event stream with no collector
changes. Validated with the pinned agent (`e9004d5`, built per
the upstream README with a `bpftool`-generated `vmlinux.h`,
run as root):

```
crau-agent -c /dev/null --library /path/to/libhaskoki.so \
  --log-file /tmp/crau-log.cbor &
<run the workload>
crau-query --log-file /tmp/crau-log.cbor
```

which ingested all 18 pk records of the reference workload with
typed fields intact. When both Haskoki and its OpenSSL backend
emit for one logical operation, count the layer under test to
avoid double-counting.

### bpftrace one-liners

```
# Count delivered pk records by context name (needs a bpftrace
# with working USDT arg access; 0.25 crashes rendering warnings,
# so prefer the GDB recipe below on affected hosts).
bpftrace -e 'usdt:./libhaskoki.so:crypto_auditing:new_context_with_data { @[str(arg2)] = count(); }'

# Operation outcomes by disposition code.
bpftrace -e 'usdt:./libhaskoki.so:haskoki:operation_end { @[arg5] = count(); }'

# Admission denials by reason class.
bpftrace -e 'usdt:./libhaskoki.so:haskoki:policy_reject { @[arg5] = count(); }'
```

### GDB recipe (unprivileged, deterministic)

`scripts/test-usdt-live.sh` is the durable form: it builds the
flag-on module, compiles `tests/c/usdt_live.c`, runs the committed
`tests/gdb/usdt_cap.txt` recipe, and checks every record with
`scripts/usdt-live-check.py`. The recipe breaks on all five probes
and decodes the array elements in-line; the driver prints
`PHASE:` markers with settle delays so boundary lines attribute
deterministically.

## Overhead

Dormant probes (flag on, no consumer) cost a semaphore check plus
the FFI crossing per emission site. Measured through the real
`.so` over a warmed AES-CBC workload
(`scripts/test-usdt-bench.sh`, 300 encrypt+decrypt round-trips per
leg): ~429us/op off vs ~453us/op unattached, ratio 1.055 — inside
run-to-run noise on crypto-dominated legs, and the gate fails only
past a 2x bound (catastrophe detection, not a tight budget).

## Build and CI shape

- `cabal build --flags=+usdt` enables probes; without the flag the
  shim does not compile and the Haskell side stubs out.
- CI matrix: `haskell` (default flags) plus `haskell-usdt`
  (flag on, full 8-suite matrix incl. non-root storage), with the
  readelf manifest gate on both halves and the bench in the
  flag-on leg. Publication needs the flag-on leg.
- `scripts/test-usdt-bench.sh` and `scripts/test-usdt-live.sh`
  also run in the release-evidence manifest (17 container
  drivers); the live recipe is the publish-time proof.
- `Dockerfile` carries `systemtap-sdt-dev` (probe headers),
  `python3` (gate scripts), and `gdb` (live recipe); the drivers
  self-provision via apt on stale images and fail loudly without.

## Deferred and known limits

- DH group enrichment: DH records carry algorithm + bits; the
  `pk::group` (`modp2048`…) enrichment needs prime matching that
  is not implemented. The field omits honestly; the live leg pins
  the current shape.
- Exotic EC curves (brainpool, binary) omit curve codes while
  keeping algorithm + mechanism; same honest-omission rule.
- Publication-failure emission has no live leg: no fault-injection
  knob exists for the C driver. The unit and mapping coverage
  stands; the scenario stays a follow-up.
- `crau-agent` ingestion validation: the GDB recipe proves
  emission shape and counts; running the pinned agent against the
  module end to end remains owner follow-up (needs BPF-capable
  runners, per the upstream external-test pattern).
- Finalize-time abandonment stays silent (documented): process
  teardown claims nothing.
