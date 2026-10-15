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
`$HASKOKI_PARITY_ARTIFACTS/reprobe.tsv`. Each excluded leg is queued, and the
queue runs on a fresh daemon with the same backend config after the gate
daemon of its group has stopped. A re-probe never shares daemon state
with a gated leg and never changes the gate result. The first re-probe
run (2026-10-15) ran the excluded legs on the live certificate daemon.
The leftover objects then failed the next gated atomicity census
(`matches=3 expected=1`). The queue design comes from that run.
Without the variable the excluded legs are skipped as before.

An entry leaves the table only when its re-probe passes with an empty
diff in every version and storage the entry covers.

## Remaining entries (re-probed 2026-10-15)

Receipt: `ws/evidence/v050-wp11/task3/` in the development workspace
(`reprobe-run.log`, `reprobe-artifacts/reprobe.tsv`, and the per-leg
direct, proxied and diff logs). Every row ran against the pinned pair
above. The gate run with re-probes enabled passed.

| Entry | Upstream | Re-probe result | Why it stays |
| --- | --- | --- | --- |
| `message_routed` | [#23](https://github.com/mingulov/pkcs11-proxy-ng/issues/23) | error (exit 1) | 10 failed checks: `C_EncryptMessageNext` IV repair, supply-at-end and replace-at-end; five GCM IV-placement shapes (supply-at-end and recover, sealed and opened); and the GCM KAT sweep (sealed, opened). |
| `async_routed` | [#24](https://github.com/mingulov/pkcs11-proxy-ng/issues/24) | error (exit 1) | 80 failed checks, and the table-proof child dies with signal 11 under 3.2. Async completion does not preserve the caller's output bindings. |
| `notifications_routed` | [#25](https://github.com/mingulov/pkcs11-proxy-ng/issues/25) | error (exit 2) | All 72 matrix legs report `setup-error reason=discovery-symbols`. Callback association and provider control are not transported. |
| `consumer_certificates:visibility` | [#27](https://github.com/mingulov/pkcs11-proxy-ng/issues/27) | pass for 2.40 only; 3.0, 3.1 and 3.2 error in both storages | One daemon serves the whole version matrix and the leg uses a fixed token label, so the cross-session census finds `matches=2` after the first version. A per-version entry would make the gate depend on run order. |
| `consumer_certificates:restart` | [#27](https://github.com/mingulov/pkcs11-proxy-ng/issues/27) | pass with memory storage; error with sqlite storage in all four versions | Token objects outlive a client `C_Finalize`/`C_Initialize` through the proxy. With sqlite storage, `restart-token-refind` fails. The driver's entry grammar has no storage qualifier, so the whole leg stays. |

No entry passed with an empty diff, so none was removed.

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
  daemon exits with status 70 and prints no backend error text.
- A negative control runs the proxied `limit2-null` child against a
  daemon on the unconfigured default backend. It must exit 3 with
  `policy:backend-mismatch max want=2 got=1024`. This shows the
  comparison can fail.
- `limit2-app` is a supported refusal, with no upstream issue. The
  pinned shim refuses application mutex callbacks, so `C_Initialize`
  returns `CKR_CANT_LOCK` (0xa). In proxy mode the consumer requires
  exactly that code and prints a `topology:` line, which the driver
  excludes from the diff. It then initializes again with OS locking, and
  all remaining session and policy assertions are compared.

## Ledger rows

The qualification ledger's proxy rows come from the same pinned pair.
They are re-frozen by v0.5 WP12 Task 7.
