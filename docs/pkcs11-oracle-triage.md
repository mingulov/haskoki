# Interpreting external checks

Haskoki is tested through its model, native C consumers, and external
PKCS#11 clients. Each covers a different boundary. The
[evidence levels](trust-ladder.md) explain that distinction; the
[release results](release-results.md) contain the measured counters.

## A successful job can still contain findings

The [CI checker wrapper](../scripts/ci-pkcs11-lane.sh) first requires
`doctor` to load the module. It then accepts a checker exit of 0 or 1:
1 means the run completed with findings. Setup/usage errors fail the job.
Read `results.json` and the per-case report instead of treating its success
badge as a clean result.

A listed mechanism, non-null function pointer, collected test, skipped
case, or source-defined stress test is not evidence of successful execution.
Compare the actual input, return code, and output before assigning a finding
in [the upstream register](pkcs11-check-upstream-issues.md).

## Reproduce a checker run

The easiest route is the image's `check` command in
[Try Haskoki](try-it.md#check-the-token). For a native reproduction, first
install the bundle in the [developer environment](toolchain.md). Install
the checker using the **Checkout framework** and `uv sync` steps in
[CI](../.github/workflows/ci.yml), whose default framework ref is `v0.2.1`.
Then run from the repository root with that environment:

```sh
# Adjust the path to your extracted bundle.
export PKCS11_CHECK='uv run --project pkcs11-check pkcs11-check'
scripts/ci-pkcs11-lane.sh fast "$PWD/haskoki-0.3.0.0" fast-results.json

# Optional larger-vector run; fetching needs network access and disk space.
mkdir -p vectors
uv run --project pkcs11-check pkcs11-check fetch-data all --data-dir "$PWD/vectors"
PKCS11_CHECK_DATA_DIR="$PWD/vectors" \
  scripts/ci-pkcs11-lane.sh kat "$PWD/haskoki-0.3.0.0" kat-results.json
```

Use a directory owned by this vector download: fetching replaces its
per-source subdirectories. Check the corpus and collected counts so missing
data does not turn the run into mostly skips. CI's fast/vector framework
pin differs from the image's checker pin; keep their results separate.

## Current demo findings

The frozen full profile has 22 findings shared by direct and proxy modes:

| Family | Count | Interpretation |
| --- | ---: | --- |
| GMAC message shape | 2 | Haskoki's message-init path accepts its classic-shaped parameters, not native `CK_GCM_MESSAGE_PARAMS` |
| HOTP parameters | 2 | Checker message-init probes send NULL. The provider takes the standard `CK_OTP_PARAMS` and, keeping no token counter, requires its `CK_OTP_COUNTER` entry; NULL refuses with `CKR_MECHANISM_PARAM_INVALID` |
| BLAKE2B key type | 16 | Checker defect. Its wrong-key test uses a generic-secret key, but PKCS#11 3.1 sections 6.33.3 to 6.36.3 list "generic secret or CKK_BLAKE2B_n_HMAC" for these mechanisms, so Haskoki correctly accepts it. A native leg pins the acceptance and the refusal of a key type outside the list ([upstream report](pkcs11-check-upstream-issues.md#pending-upstream-reports)) |
| Async child results | 2 | A checker child passes a ctypes character buffer where its declared binding expects unsigned bytes; it fails before the module call |

The AES-GCM message flags were withdrawn because that route was not
supported as advertised. Basic classic-shaped message tests do not establish
general v3 message conformance. CBC/recover recipe findings from earlier
runs are not current baseline findings.

## Native behavior beyond checker availability tests

### Message operations

[message_routed.c](../tests/c/message_routed.c) exercises all twenty message
entries through 3.0, 3.1, and 3.2 tables, with AES-CBC and HMAC bytes,
output canaries, staged retries, and lifecycle/error cases. Mechanism
parameters and advertised flags remain separate from function reachability.

### Public async operations

[async_routed.c](../tests/c/async_routed.c) submits a real pending Digest
on an explicit async session through the 3.2 table, checks completed SHA-256
bytes, revokes old output storage, and exercises SQLite restart/rejoin.
Ordinary sessions and query/short-buffer recalls stay synchronous. This
is Digest-only public async coverage, not async Sign or key generation.
See the [output contract](operations-notes.md#public-32-async-routing).
A failed durable delivery mark cannot undo delivered bytes, so the
successful-store restart case does not prove crash-safe exactly-once delivery.

### Notifications

[notifications_routed.c](../tests/c/notifications_routed.c) exercises actual
slot indications, waits, finalization, removal, and Digest surrender
callbacks. Presence changes coalesce into pending slot flags; queries do not
consume them. Callback reentry has strict restrictions. The
[runtime reference](operations-notes.md#session-notification-callbacks-and-reentry)
describes ownership and the callback contract.

### Certificates

[consumer_certificates.c](../tests/c/consumer_certificates.c) exercises
creation, attributes, lifecycle, persistence, and identity linkage.
Certificate metadata remains caller-supplied opaque bytes; there is no DER
coherence or chain-validation claim. See the [certificate policy](certificate-objects.md).

## Direct and proxy scope

The demo pins `pkcs11-proxy-ng` v0.2.2. Its qualified subset supports the
backend's 3.1 table and ordinary certificate lifecycle calls. The
[parity driver](../scripts/test-proxy-parity.sh) keeps these direct-only
boundaries:

- Message operations: [issue 23](https://github.com/mingulov/pkcs11-proxy-ng/issues/23).
- Public async output ownership and detach/join: [issue 24](https://github.com/mingulov/pkcs11-proxy-ng/issues/24).
- Rich waits/callback/control semantics: [issue 25](https://github.com/mingulov/pkcs11-proxy-ng/issues/25).
- Certificate cross-session visibility/restart: [issue 27](https://github.com/mingulov/pkcs11-proxy-ng/issues/27).

Larger direct-only probes also exceed the proxy's request limit. These
exclusions and the checker's frozen comparison differences are different
sets; neither should be counted as successful forwarded coverage.
