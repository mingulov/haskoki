# Proxy parity exclusions

The [parity driver](../scripts/test-proxy-parity.sh) runs each native
consumer twice: directly against `libhaskoki.so`, and through the pinned
pkcs11-proxy-ng pair (daemon plus client shim). It normalizes and diffs
the two transcripts, and any difference fails the run. A consumer, leg
or version listed in the driver's `DIRECT_ONLY` table skips the proxied
run. Every entry names the upstream proxy issue that keeps it there.
This page records the dated evidence for each remaining entry.

Pinned pair (`/opt/pkcs11-proxy-ng`, proxy commit `1ed7cc15`, v0.2.2):

- daemon `pkcs11-proxy-ng` sha256
  `91d9ccba8e579891fb5a8815f66518baef0a757bd9a2563097983ca9d056385b`
- shim `libpkcs11_proxy_ng_shim.so` sha256
  `87eb3f651c82de637e30666f305fae540375680bc754cf76249e17b6e7cb1d75`

## Re-probe mode

`HASKOKI_PARITY_REPROBE=1 scripts/test-proxy-parity.sh` runs every
excluded proxied leg anyway and records the outcome in
`$HASKOKI_PARITY_ARTIFACTS/reprobe.tsv`. Each excluded leg is queued
and runs on its own fresh daemon (and, for sqlite, its own empty
database directory) after the gate daemon of its group has stopped. A
re-probe never shares daemon state with a gated leg or with another
re-probe, and never changes the gate result. The run ends in a
`REPROBE-RUN` line, never the `PASS` line. Without the variable the
excluded legs are skipped as before.

Two earlier probes shared daemon state and gave misleading results:
re-probing on the live certificate daemon left objects that failed the
next gated atomicity census (`matches=3 expected=1`), and one daemon
serving the whole version matrix made `visibility` fail from 3.0 on
(`matches=2`). Both were driver artifacts. The gated certificate legs
now use one fresh daemon per storage, version and leg too, as the direct side gives every leg a fresh store (a shared daemon also failed the atomicity census once `visibility` ran on it, `matches=3 expected=1`).

An entry leaves the table only when its re-probe passes with an empty
diff in every version and storage the entry covers. An entry may be
narrowed by a leg, version or storage qualifier
(`consumer_certificates:restart:sqlite`) to what the evidence supports.

Development filters never produce a `PASS` line: `HASKOKI_PARITY_GROUPS`
(an unknown group name fails) ends in `PARTIAL` with exit 1 unless
`HASKOKI_PARITY_ALLOW_PARTIAL=1`.

## Changes in fix round 1 (2026-10-16)

Re-probe with a fresh daemon per version and storage (receipt:
`ws/evidence/v050-wp11/fix1/probe-artifacts/reprobe.tsv` in the
development workspace, sha256 `ffc57ccded61426c3b8a8bc4479dbf74204aeba676219bfd356b8eb2ceac9b3b`):

- `consumer_certificates:visibility`: REMOVED. Passes with an empty
  diff in all four versions and both storages, and is gated.
- `consumer_certificates:restart`: NARROWED to sqlite storage. Passes
  with an empty diff in all four versions with memory storage (gated);
  with sqlite storage it fails in all four versions.

## Changes after the storage-attribute fix (2026-10-16)

Haskoki now reports the common storage-object attributes an object was
created without (see the changelog). Re-probe with that fix, one fresh
daemon per version and storage (receipt:
`ws/evidence/v050-attr-defaults/parity-run2/artifacts/reprobe.tsv` in
the development workspace, sha256
`916a842f4a70b7d2b462830bc119a782c8639399868b7552bf0f9d1c18594042`):

- `consumer_certificates:restart:sqlite`: KEPT, with a new cause. The
  assertion it was excluded for, `restart-token-refind`, now passes
  proxied in all four versions. Its cause was a Haskoki defect, now
  fixed: an object created without `CKA_PRIVATE` returned
  `CKR_ATTRIBUTE_TYPE_INVALID` for it, and the proxy hides an object of
  unknown privacy from a logged-out session unless that client context
  created it. After the client's `C_Finalize` and `C_Initialize` the
  context is new, so the object was hidden (0 matches proxied, 1
  direct). It now reads `CKA_PRIVATE` false and is found. The leg now
  fails one assertion later, on proxy behavior: `restart-stale-fault`
  returns `0x150` where direct returns `CKR_OBJECT_HANDLE_INVALID`
  (`0x82`), in all four versions. The proxy's object handles are per
  client context and start again at 1, so the handle from before the
  restart names the first object found after it.
- `consumer_certificates:restart:memory`: NEW. With `CKA_PRIVATE`
  reported, the proxied run finds the memory-store object after the
  client restart: `restart-memory-volatile matches=1 expected=0`, in
  all four versions (2.40 first failed gated, receipt
  `ws/evidence/v050-attr-defaults/parity-run1/driver.log`). The daemon
  does not finalize the backend when a client calls `C_Finalize`, so the
  object survives; direct, `C_Finalize` drops the memory store. The
  "passes with memory storage" result in fix round 1 held only because
  the `CKA_PRIVATE` defect hid that object.

## Remaining entries (re-probed 2026-10-15 and 2026-10-16)

Receipts (development workspace): `ws/evidence/v050-wp11/task3/`
(`reprobe-artifacts/reprobe.tsv`, the first three rows below) and
`ws/evidence/v050-attr-defaults/parity-run2/artifacts/` (the two
certificate rows). Every row ran against the pinned pair above.

| Entry | Upstream | Re-probe result | Why it stays |
| --- | --- | --- | --- |
| `message_routed` | [#23](https://github.com/mingulov/pkcs11-proxy-ng/issues/23) | error (exit 1) | 10 failed checks: `C_EncryptMessageNext` IV repair, supply-at-end and replace-at-end; five GCM IV-placement shapes (supply-at-end and recover, sealed and opened); and the GCM KAT sweep (sealed, opened). |
| `async_routed` | [#24](https://github.com/mingulov/pkcs11-proxy-ng/issues/24) | error (exit 1) | 80 failed checks, and the table-proof child dies with signal 11 under 3.2. Async completion does not preserve the caller's output bindings. |
| `notifications_routed` | [#25](https://github.com/mingulov/pkcs11-proxy-ng/issues/25) | error (exit 2) | All 72 matrix legs report `setup-error reason=discovery-symbols`. Callback association and provider control are not transported. |
| `consumer_certificates:restart:sqlite` | [#27](https://github.com/mingulov/pkcs11-proxy-ng/issues/27) | error (exit 1) in 2.40, 3.0, 3.1 and 3.2 | `restart-token-refind` passes. Assertion `restart-stale-fault` fails: the pre-restart handle returns `0x150` proxied and `CKR_OBJECT_HANDLE_INVALID` (`0x82`) direct, because the proxy's per-context handles start again at 1 after the client re-initializes. |
| `consumer_certificates:restart:memory` | [#27](https://github.com/mingulov/pkcs11-proxy-ng/issues/27) | error (exit 1) in 2.40, 3.0, 3.1 and 3.2 | Assertion `restart-memory-volatile` fails, `matches=1 expected=0`: the memory-store object outlives the client's `C_Finalize` because the daemon keeps the backend initialized. |

#27 is closed upstream as by design (2026-10-05: backend objects outlive
a client `C_Finalize`; per-client teardown is deferred to v0.3). It is
the reference for both restart entries: the memory object that
survives the restart, and the per-context handles that make a
pre-restart handle name another object. Neither has its own upstream
issue yet. The earlier sqlite symptom, the object not found after the
restart, was not a proxy issue: it was the Haskoki `CKA_PRIVATE` defect
described above, now fixed.

## Policy and metadata scenarios (#17)

`consumer_policy_metadata` is no longer excluded. Group P of the driver
runs it proxied with one daemon per scenario. Each daemon starts on the
config the consumer prints with `--print-config`:

- Five scenarios are compared direct against proxied: `limit2-null`,
  `limit2-os`, `limit2-app`, `multitoken` and `pin`.
- The three PIN-refusal scenarios (`pin-short`, `pin-empty`, `pin-long`)
  have no proxied session. Their proxied equivalent is a startup
  refusal: the daemon must exit nonzero without ever accepting on its
  port, and its log must show `Health status: NOT_SERVING`. The pinned
  daemon exits with status 70 and prints no backend error text. The
  `pin` scenario, which uses a valid PIN on the same config shape,
  starts and runs, so a refusal is not caused by a missing library or a
  bad path.
- Four negative controls run before the configured legs. Each runs a
  proxied child against a daemon whose config differs in exactly the
  property the scenario asserts, and must be refused with the named
  cause: `limit2-null` against the unconfigured daemon (exit 3,
  `max want=2 got=1024`), `multitoken` against it (exit 3,
  `slots want=2 got=1`), `pin` against it (exit 3, `slots want=2 got=1`;
  the `pin` config carries a second token and its own PINs), and `pin`
  against a daemon with the right catalog but another demo user PIN
  (exit 1, `pin correct user login ok` fails). A parity pass therefore
  shows the daemon serves the scenario's own session limit, token
  catalog and PINs.
- `limit2-app` is a supported refusal, with no upstream issue. The
  pinned shim refuses application mutex callbacks, so `C_Initialize`
  returns `CKR_CANT_LOCK` (0xa). In proxy mode the consumer requires
  exactly that code and prints a `topology:` line, which the driver
  excludes from the diff. It then initializes again with OS locking, and
  all remaining session and policy assertions are compared. Application
  mutex behavior itself is not parity-tested through the proxy.
- The driver checks its own guards at startup: the squatter self-check
  requires the refusal to say `already bound`, and a daemon counts as
  ready only when its own log shows `listening on tcp` and its process
  is alive.

## Proxy-owned divergences inside gated consumers

These legs are not `DIRECT_ONLY` entries: the consumer runs proxied and
is compared, but one leg branches on topology because the pinned shim
behaves differently from the provider. The proxied branch asserts the
shim's behavior, so a change in either side fails the run. No upstream
issue has been filed for either.

| Leg | Proxied behavior | Direct behavior | Introduced |
| --- | --- | --- | --- |
| `consumer_errors` refusal legs, digest-key control | The shim refuses `C_DigestKey` on a destroyed key handle itself (client-side handle translation), so the backend never sees the error and its digest stays active: the next `C_DigestInit` returns `CKR_OPERATION_ACTIVE`. The consumer prints a `topology:` line (excluded from the diff), finishes the stale digest and re-initializes. | The refused `C_DigestKey` returns `CKR_KEY_HANDLE_INVALID` and terminates the digest (PKCS#11 v3.1 section 5.12), so `C_DigestInit` succeeds. | `f520105` |
| `consumer_roundtrip` HOTP `CK_OTP_PARAMS` legs | The shim's operation check refuses any parameterized `CKM_HOTP` (0x291 has no entry in its mechanism parameter registry) with `CKR_MECHANISM_PARAM_INVALID` before forwarding, because it does not marshal the pointer inside `CK_OTP_PARAMS`. The proxied run asserts that refusal; the RFC 4226 vectors and the parameter-decoder refusals run direct only. | `CK_OTP_PARAMS` with a `CK_OTP_COUNTER` entry signs and verifies the RFC 4226 vectors. | `8caf66f` |

Both are recorded in `proxy_owned_divergences` of the
[findings ledger](../spec/findings-ledger.json), whose gate checks that
each introducing commit is an ancestor of the checked-out tree.

## Ledger rows

The qualification ledger's proxy rows come from the same pinned pair.
They were re-frozen at the v0.5 checker re-freeze.
