# Native product diagnostics (remote execution only)

These test-only consumers target production baseline `e9c5162fff7b2649a47c7b736506b84353bb7718`.
Production code is unchanged. Preparation generated constants with Python standard
library arithmetic/hashlib and inspected source; it did not compile or execute any
native provider code locally. Runtime results belong to the remote workflow log.

Build on the remote runner from the repository root:

```sh
cc -std=c11 -O2 -g -Wall -Wextra -Werror -Ispec/vendor \
  tests/review/native_product_probe.c -o native_product_probe -ldl -lpthread
timeout --signal=TERM --kill-after=10s 180s ./native_product_probe MODULE dh-collision
```

Use the pinned `spec/vendor/pkcs11.h`. There is no dependency on generated provider
headers or a consumer OpenSSL library. `native_product_vectors.h` is an independent
expected-value fixture, not a provider artifact. Each mode must be a distinct
process with an isolated fresh token configuration/store. Capture every process
exit; do not mask a failing probe with a successful logging command. Timeouts and
signals are separate harness failures, not passes or specific bug proofs.

The module remains loaded until process exit because Haskoki owns a process RTS.
All started digest workers are joined before session closure and finalization;
this probe does not race public `C_Finalize` against application workers.

## Interface and result classes

`native_product_probe MODULE MODE`; optional `HSK_REVIEW_USER_PIN` and
`HSK_REVIEW_SO_PIN` override fixture PINs `1234` and `5678`. The first present slot
is used. Run with the ordinary OpenSSL-backed fresh demonstrator configuration.

| Mode | Evidence |
| --- | --- |
| `dh-collision` | Imports ffdhe2048 private exponent 12345, validates a peer-2 derivation against independent modular power, then derives from the full native collision peer and checks all 256 bytes. Refused setup or mismatched peer-2 control is explicitly inconclusive. |
| `derive-protection` | Imports the obvious generic-secret fixture `00 01 ... 1f` with sensitivity true, extractability false, derivation permitted. First proves direct value unreadability, then requests offset-zero, full-length `CKM_EXTRACT_KEY_FROM_KEY` with an explicit protection downgrade. Records allowed template/policy refusal, inherited protection, weakened attributes, or full fixture recovery. No real material is used. |
| `context-binding` | Requests the public version-3.0 interface through `C_GetInterface`, then uses that table's `C_SessionCancel`. Generates two disposable P-256 key pairs with explicit, read-back `CKA_ALWAYS_AUTHENTICATE=true`. Requires missing-grant denial and a valid correctly authenticated B signature as controls. Authenticates marked operation A, cancels before first data use, then signs with key B without a new context grant. A valid B signature is the precise stale-grant candidate. |
| `session-limit` | Requires runner configuration with exactly two allowed sessions. Prints advertised token metadata, opens two RW sessions, requires the third open to return `CKR_SESSION_COUNT`, then closes all sessions. Metadata is an observation for separate comparison against the effective configuration. |
| `private-logout` | Logged-in user creates private session and token CKO_DATA objects. Exact-label searches check both controls, invisibility after logout, then session-object destruction versus token-object persistence after login. Reappearing session object is a contract candidate. |
| `private-so` | Public creation without login and private creation as user are positive controls. Private creation without login and as SO must return `CKR_USER_NOT_LOGGED_IN`. Successful SO creation is a candidate even if its new handle is invisible to SO. |
| `digest-os` | `CKF_OS_LOCKING_OK`, no application callbacks. 1/2/4/8 separate RW sessions; each worker performs 64 operations, alternating one-shot and two-update multipart SHA-256. A start gate releases workers only after all are ready. Every byte and both 16-byte output canaries are checked. |
| `digest-app` | Same checks with all four pthread mutex callbacks and flags zero, selecting application mutexes. |
| `lifecycle` | Four sameprocess intervals: token flags/count metadata, disclosed provisioning stub return codes, finalize with an idle session still open, uninitialized-state check, reinitialize and check stale session invalidity. Main finalizes the fifth initialized interval. |
| `token-info` | Prints token flags and session/PIN metadata. Observation only; compare against the runner's effective config separately. |
| `pin-lockout-reopen` | Three wrong user PIN attempts must reach lockout, then close all sessions/finalize/reinitialize and retry correct PIN. Use an isolated fresh SQLite store retained between intervals. Lockout retention/reset is a policy/storage observation, not an unconditional PKCS#11 violation claim. |

Exit 0: checks passed or mode produced observations only. Exit 1: `CANDIDATE`
identifies an actual mismatch with the checked contract. Exit 2: `SETUP-FAIL`,
inconclusive for the targeted bug. The runner must preserve this distinction.
The final `RESULT` includes mode, status, and exit. Successful setup calls include
their raw return values. Fixture DH derived-secret bytes are deliberately public
test values; do not run these probes with real key material or a real token store.

Provisioning calls `C_InitToken`, `C_InitPIN`, and `C_SetPIN` are disclosed stubs
at this baseline, so lifecycle records their results without reclassifying that
known limitation as a surprise defect. Token flag observations alone do not prove
the implementation enforces each advertised policy. The bounded digest exercise
checks ordinary supported usage, not absence of all concurrency/lifetime defects.

`context-binding` uses raw `CKM_ECDSA` over a fixed public SHA-256 fixture digest,
checks the 64-byte P-256 signature and output canaries, and verifies signatures
through the matching generated public key. This is a public call-sequence control,
not an independent cryptographic oracle. The v3 table is obtained for an explicit
requested version; no legacy function table is reinterpreted as a larger table.
An unsupported generation/interface/context-login setup is inconclusive. A denial
after cancellation must be `CKR_USER_NOT_LOGGED_IN`; unrelated failures do not
prove operation-bound authentication. All four fixture key objects are cleaned up.

## Independent expected values

`dh_prime` is the public RFC 7919 ffdhe2048 prime, also present as `dhPrime2048` in
`tests/engine/OpenSSLSpec.hs`. Python standard integers generated:

```python
p = int.from_bytes(prime_bytes, 'big')
y = 240 * 256**240 + 2
assert 1 < y < p - 1
assert pow(y, (p - 1)//2, p) == 1
assert pow(2, (p - 1)//2, p) == 1
expected = pow(y, 12345, p).to_bytes(256, 'big')
control = pow(2, 12345, p).to_bytes(256, 'big')
assert expected != control
```

The native 256-byte peer is eight zero bytes, BE64(240), 239 zero bytes and `02`.
It is a valid subgroup element. The bug candidate is strongest when the control
matches its independent expectation and the collision result equals that control
instead of `expected`. Another incorrect result is reported separately. Requests
for a 256-byte `CKK_GENERIC_SECRET`, with `CKA_SENSITIVE=false` and
`CKA_EXTRACTABLE=true`, permit reading the derived fixture output. Import or derive
refusal cannot prove a peer substitution.

Digest worker `i` (0 through 7) hashes exactly the ASCII bytes
`haskoki-native-review-worker-i`, without a terminating NUL. Expected bytes are
`hashlib.sha256(('haskoki-native-review-worker-%d' % i).encode('ascii')).digest()`.
Different workers use different messages, exposing cross-session output swaps.
One-shot and multipart iterations use the same independently expected digest.

Source review anchors: `ffi/Haskoki/FFI/NativeParams.hs` (`dhPkcsStructToCanonical`),
`core/Haskoki/Object.hs` (DH import and private visibility),
`src/Haskoki/Engine/Driver.hs` (DH output truncation), and
`cbits/function_tables.c` (disclosed provisioning stubs).
