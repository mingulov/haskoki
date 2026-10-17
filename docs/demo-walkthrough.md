# Native clients and operator reference

For the Docker demo and hands-on signing, start with [Try Haskoki](try-it.md).
This page covers loading the native module, configuration, and developer
checks. [docs/trust-ladder.md](trust-ladder.md) explains their evidence levels.

## Install the native bundle

Download the native archive, `release-manifest.json`, and `SHA256SUMS` from
[GitHub Releases](https://github.com/mingulov/haskoki/releases). Check its
checksum against the downloaded file. Linux x86-64, glibc >= 2.43, and the
system libraries in [host requirements](../SUPPORTED-HOSTS.md) are required.
Extract the whole bundle so the module can find its runtime libraries.

```sh
# v0.4.0.0 is the latest published release.
HASKOKI_VERSION=0.4.0.0
tar -xzf "haskoki-$HASKOKI_VERSION-linux-x86_64.tar.gz"
HASKOKI_BUNDLE="$PWD/haskoki-$HASKOKI_VERSION"
"$HASKOKI_BUNDLE/bin/haskoki-ctl" --version
export HASKOKI_MODULE="$HASKOKI_BUNDLE/lib/libhaskoki.so"
```

Create a configuration for a disposable persistent token. Replace this
store with a new path to start over; keep it single-writer.

```sh
cat > backend.toml <<EOF
schema_version = 1
profile = "demo-maximal"
[storage]
kind = "sqlite"
path = "$PWD/token.sqlite"
[engine]
kind = "openssl"
[trace]
enabled = false
EOF
export HASKOKI_CONFIG="$PWD/backend.toml"
"$HASKOKI_BUNDLE/bin/haskoki-ctl" config check --config "$HASKOKI_CONFIG"
"$HASKOKI_BUNDLE/bin/haskoki-ctl" capabilities --config "$HASKOKI_CONFIG"

# Requires OpenSC installed on the host.
pkcs11-tool --module "$HASKOKI_MODULE" --list-slots
```

Use `$HASKOKI_MODULE` as your application's PKCS#11 library and pass
`HASKOKI_CONFIG` to the process loading it. Direct loading brings the GHC
runtime into that process; the [remoting examples](try-it.md#try-another-process)
show two ways to move it to another process.

### Upgrading a v0.4 token store

A store written by v0.4 or earlier needs one migration to schema 3 before
v0.5 serves it. Rehearse on a copy first (see Upgrade, backup and recovery
in [operations-notes.md](operations-notes.md#upgrade-backup-and-recovery)):

```sh
mkdir -p /tmp/rehearsal /tmp/rehearsal/backups
cp "$PWD/token.sqlite" /tmp/rehearsal/token.sqlite
sed "s#^path = .*#path = \"/tmp/rehearsal/token.sqlite\"#" "$PWD/backend.toml" > /tmp/rehearsal/backend.toml
haskoki-ctl store check --path /tmp/rehearsal/token.sqlite --config /tmp/rehearsal/backend.toml
haskoki-ctl store migrate --path /tmp/rehearsal/token.sqlite \
  --config /tmp/rehearsal/backend.toml --backup-dir /tmp/rehearsal/backups
haskoki-ctl store check --path /tmp/rehearsal/token.sqlite --config /tmp/rehearsal/backend.toml
```

## Token provisioning and state

The default token is slot 0, label `haskoki-demo`, with public fixture PINs:
user `1234`, security officer `5678`; these are the initial credentials the
token serves until they are changed in-band. With a SQLite store they are
stored with the token when it is created, so a later edit of the configured
PINs does not change an existing token. `C_InitToken` reinitializes a
token (no sessions may be open: the label becomes the caller label, the
caller PIN must match the existing SO PIN to authorize the reset, every
object and pending detached job on the token is destroyed, and the user
PIN becomes uninitialized), the SO then sets the user PIN
with `C_InitPIN` from a read/write SO session, and `C_SetPIN` changes the
session role's own PIN (a read/write SO session changes the SO PIN; any
other read/write session — public, user, or context — changes the user
PIN, with the old PIN as the authentication, so no login is required;
read-only sessions refuse). New PINs keep the 4..32 policy; a refused call
changes nothing. Changed PINs persist across restarts; a relabel takes
effect at once, and the next open refuses until the catalog entry carries
the new label; `haskoki-ctl store check --path token.sqlite --config
backend.toml` names the token and both labels. Slot 0 keeps
`haskoki-demo`: the catalog
anchors slot 0 to that label, so slot-0 relabels refuse in-band and only
other slots relabel.
Wrong guesses commit per-role retries before the return code is observed,
until `CKR_PIN_LOCKED`; a restart keeps the counters, and the third strike
locks durably. A correct login resets retries before lockout and commits
the reset, but does not unlock a locked role; a wrong old PIN in `C_SetPIN`
consumes one attempt exactly like a login strike. A user login against an
uninitialized user PIN refuses with `CKR_USER_PIN_NOT_INITIALIZED` without
consuming an attempt.

Memory storage starts fresh in each process. SQLite reloads token objects
and attempt/lockout state; session objects are transient, and a reopened
session is always public: the login itself is never restored, so a second
process observes the same lockout through its own `C_Login` return codes
but never inherits an authenticated session. Both store types use
unencrypted key material. Stop clients before removing or replacing a
store. SQLite refuses a second concurrent owner.

Recovery: a locked-out user recovers through the SO — an SO login plus
`C_InitPIN` sets a fresh user PIN, clears the lock, and resets the counter.
A retry write that cannot land fails the call with `CKR_GENERAL_ERROR`
instead of answering as if it had counted. An uncertain commit reloads and
reconciles instead of replaying the operation: a landed write reloads inline
and serves on, while an unlanded one stays unserved until close and reopen.
`MultiSessionSpec` (`caseLoginLockoutDurable`, `caseLoginFailClosed`,
`caseLoginUnknownLanded`, plus the `caseSetPinDurable`,
`caseInitPinRecovery`, `caseInitTokenResets`, and
`caseSetPinRefusedPreserves` provisioning cases), `CommitSpec` (the
`auth-only` and `credential` cases), and `tests/c/consumer_provisioning.c`
hold the checks behind these behaviors.

A `[tokens]` catalog can configure up to 16 tokens. Slot IDs are their array
indices; slot 0 must remain `haskoki-demo`. Labels and PIN arrays must have
equal lengths, and the configured slot limit must fit the catalog:

```toml
[tokens]
labels = ["haskoki-demo", "haskoki-ops", "haskoki-audit"]
so_pins = ["5678", "6789", "7890"]
user_pins = ["1234", "2345", "3456"]
```

Objects and login state are scoped to their token. SQLite restart seats
tokens as present with clear pending slot flags; removal/reinsertion does
not reset their durable data. See the [configuration reference](config-honesty.md)
and [runtime limits](operations-notes.md).

## Operator scenarios

`haskoki-ctl scenario run` interprets an owned local model; it does not
control another process's loaded module. From a source checkout, the
[fixtures](../tests/ops/fixtures) provide normal, simulation, and multi-token
examples:

```sh
"$HASKOKI_BUNDLE/bin/haskoki-ctl" scenario run \
  --config tests/ops/fixtures/maximal-demo.toml \
  --scenario tests/ops/fixtures/scenario.json
# scenario-ok (owned logical simulation, 12 steps)

"$HASKOKI_BUNDLE/bin/haskoki-ctl" scenario run \
  --config tests/ops/fixtures/sim-demo.toml \
  --scenario tests/ops/fixtures/sim-scenario.json
# scenario-ok (owned logical simulation, 23 steps)
```

`scenario-ok` reports the owned logical simulation only: the simulator
boundary is the [configuration reference](config-honesty.md#serving-presence-and-private-scenario-scope),
and a passing scenario is not a statement about native serving.

Simulation can add logical delay ticks, token-script actions, and fault
windows. These are deterministic test controls, not real-time guarantees.
Native presence changes instead use the loaded instance's in-process
`HASKOKI_Control`, with test controls enabled.

## Native behavior checks

Contributors use the [developer environment](toolchain.md); GitHub runs the
build and qualification jobs. From a prepared source checkout:

```sh
scripts/test-consumers.sh
scripts/test-proxy-parity.sh
scripts/test-control-events.sh
python3 scripts/publish-coverage.py --check
```

| Consumer | Coverage |
| --- | --- |
| [consumer_discovery.c](../tests/c/consumer_discovery.c) | Function tables, slots, tokens, sessions, and mechanism records |
| [consumer_roundtrip.c](../tests/c/consumer_roundtrip.c) | Real crypto, authentication, objects, wrapping, derivation, and refusals |
| [consumer_multitoken.c](../tests/c/consumer_multitoken.c) | Token-scoped authentication and object isolation |
| [consumer_streaming.c](../tests/c/consumer_streaming.c) | Multipart digest bytes, larger inputs, and close-mid-stream cleanup |
| [message_routed.c](../tests/c/message_routed.c) | Actual 3.x message entries, bytes, canaries, retries, and lifecycle |
| [async_routed.c](../tests/c/async_routed.c) | Public 3.2 Digest submission, completion, output revocation, and SQLite recovery |
| [notifications_routed.c](../tests/c/notifications_routed.c) | Slot indications, waits, removal, finalization, and surrender callbacks |
| [consumer_certificates.c](../tests/c/consumer_certificates.c) | Certificate attributes, lifecycle, persistence, and ID linkage |

Parity covers matching forwarded calls only. Message, public async, rich
notifications, and certificate visibility/restart have explicit transport
exclusions in the driver. The p11-kit demo checks basic operations separately;
it is not the full parity matrix.

## Coverage and buffering

The [inventory](coverage.md) has 464 mechanisms: 316 behavior-tested,
89 unsupported with reasons, 2 not applicable, and 57 planned. The native
surface serves the 316 `support.real == "tested"` rows; a listed mechanism
does not mean every parameter shape has been exercised through C.

Classic multipart digest streams through backend contexts. Resource cleanup
runs through the three `publishCommit` funnels and the `Runtime`/`Async`
drains, including close-mid-stream and rejected allocations. Live native
contexts are not portable. The internal model snapshot rejects a live stream
with `CKR_STATE_UNSAVEABLE` ([SnapshotSpec](../tests/model/SnapshotSpec.hs)).
Public `C_GetOperationState` and `C_SetOperationState` remain unsupported.

Sign/verify remain **STAY BUFFERED**: `sign`/`verify` take the full message,
as do `macSign`/`macVerify` in [Backend.hs](../src/Haskoki/Engine/Backend.hs).
The 16 MiB bound also applies to one-shot input, message inner buffering,
and fully buffered cipher modes. Framed block modes (CBC/ECB/CFB/CTR and
DES equivalents) emit the releasable prefix per update and retain the suffix.
AEAD, asymmetric, CTS, OFB, key-wrap, XTS, and RC4 accumulate input instead.
The proxy imposes its separate default 4 MiB request limit.

## Random and seed semantics

`C_GenerateRandom` and `C_SeedRandom` are served through all four tables.
Seeds cap at 1048576 bytes (`seedRandomMaxBytes`); empty seeds are accepted.
The synthetic `seedRandom` replaces the stream origin and resets its
counter; `caseSeedRandomReplay` in
[SyntheticSpec](../tests/engine/SyntheticSpec.hs) checks replay.
C-table determinism is **NOT asserted**, because native serving uses OpenSSL.

OpenSSL mixes caller bytes via `RAND_add`, with no entropy credit;
`HSK_OSSL4_SEED_ENTROPY_ESTIMATE` in [ossl4_ctx.c](../cbits/ossl4_ctx.c)
pins that estimate. The mix lands on the default-context DRBG while `randomBytes` reads draw from the private libctx DRBG, so no read-observable effect is asserted.
OpenSSL bytes and labeled synthetic test bytes have a structural agreement
contract, not byte equality.

## Full checker comparison

`compare` runs the full checker profile in both modes. It intentionally
exits 1 for documented findings. The shipped classifier checks the frozen
exclusions and shared findings; it must exit 0 when those sets match. The
v0.5.0.0 candidate checks 61 exclusions and 18 shared findings; the
published v0.4.0.0 image checks 83 and 22.
From your host terminal, with the image selected in [Try Haskoki](try-it.md#choose-the-image):

```sh
mkdir -p out
docker run --rm --network none --user "$(id -u):$(id -g)" \
  -v "$PWD/out:/out" "$HASKOKI_IMAGE" compare
# Use the compare directory printed by the command.
HASKOKI_COMPARE_DIR=/out/compare-XXXXXXXX
docker run --rm --network none --user "$(id -u):$(id -g)" \
  -v "$PWD/out:/out" --entrypoint /bin/sh "$HASKOKI_IMAGE" \
  /opt/haskoki/examples/release/compare-classify/compare-classify \
  "$HASKOKI_COMPARE_DIR"
```

Read [release results](release-results.md) for counts, finding families, and
expected duration before running this longer check.
