# Haskell reference example: logout/object lifetime

One buildable program teaching one checked rule end to end. Start here
if you want to trace a policy from a user call to durable state.

## The rule

Logging out a slot (OASIS PKCS#11 3.2, section 5.6.10):

- destroys every **private session object** on that slot;
- stale-marks the handles bound to private objects there (destroyed
  bindings are retained stale, never deleted);
- retires the cached operations bound to a private key on the slot;
- returns every session on the slot to public and clears the login.

Public session objects, token objects, and other slots are untouched.
Logging out a public token is refused with `CKR_USER_NOT_LOGGED_IN`
and changes nothing.

## The pipeline

```text
user call (C_Logout, C_Login, C_Sign, ...)
  -> Request ADT (function, session, handle, input blob, regions)
  -> planCall: Reject | Immediate PreparedCommit | Execute Reservation EffectRequest
  -> effect runs outside the model gate (crypto backend)
  -> finishEffect: Reservation + EngineResult -> commit or rejection
  -> commit decision: PreparedCommit (code, delta, persist ops, outputs)
  -> durability (runtime): the storage backend performs pcPersist
  -> publication: publishDelta applies the StateDelta to the Model
  -> read the facts back from the Model
```

This program performs no storage IO: it shows the commit decision
(the `PreparedCommit`, whose `pcPersist` names the writes the
runtime would durably perform) and the in-memory publication
(`publishDelta`). Durability itself lives in the runtime/storage
layer, outside this example.

Lifecycle calls (open/close/login/logout) commit immediately: they are
pure state transitions with no engine effect. Effect-carrying calls
(sign, digest, ...) return `Execute`, and the reservation guards the
snapshot the finisher runs over.

## Build and run

From the repository root:

```sh
cabal build exe:logout-journey
cabal run exe:logout-journey
```

The program prints each stage and checks every expectation as it goes;
any violated expectation ends it with a nonzero exit, so the run is
itself the check. (Wired as an `executable` stanza rather than an
`example` stanza: the pinned cabal-install 3.12.1.0 cannot plan or
address `example` components, so only an executable is buildable.)

## What the run shows

0. Seat a token, open a session: `Request` -> `Immediate` -> publish.
1. Refusal: logout while public is rejected, and the model is
   byte-identical before and after.
2. Login commits and publishes the new token auth.
3. Three objects are created, one per lifetime corner: a private
   session HMAC key, a public token object, a public session object.
4. Effect: `C_SignInit` commits, `C_Sign` returns `Execute` with a
   reservation plus an `EffectCrypto` request, and `finishEffect`
   turns clearly marked *simulated* engine bytes into a commit that
   publishes. The real backend is out of scope for this example.
4b. A second sign is initialized and deliberately left running, so
   the logout has a live private-key operation to retire.
5. Logout: the planner returns one `Immediate` commit; the printed
   delta ops name exactly what the rule destroys, stales, retires,
   and clears.
6. Publication: the facts are read back from the model — the private
   session key is gone, the live sign is retired, the other two
   objects survive, the session is public, the token is logged out.

## Relation to the oracle suite

`tests/model/LogoutOracleMain.hs` (suite `haskoki-logout-oracle-tests`)
checks the same rule from the other side: an independent miniature
model re-derives the expected outcome from the contract text and
compares it against planner runs, observing through raw maps only.
The example teaches; the oracle pins. A companion known-answer group
in the same suite pins one mechanism variant (CKM_AES_GCM init
framing plus cipher shape) with hand-derived bytes.

## Reference exercise: traced GCM parameters

The logout journey above teaches pipeline shape with simulated engine
bytes. The bounded extension exercise traces one real parameter path
instead: a native `CK_GCM_PARAMS` image travels through
`normalizeMechParams` to the canonical `gcm-params/1` image, an init
frame, a real `F_EncryptInit`/`F_Encrypt` plan, `checkedCallWork`, the
real backend seal, finish and commit — and back through the decrypt
leg. The tests live in `tests/engine/RoutingE2ESpec.hs`:

- `gcm checked parameters drive the backend vector end to end` seals
  the pinned independent vector (key `00..0f`, nonce `00..0b`, AAD
  `"aad-data"`) and asserts every stage against hand-derived bytes.
- `gcm traced overwrites fail closed` overwrites the first IV byte,
  the tag width, the first AAD byte and the key width in turn (each
  re-seal must diverge from the pinned seal, and the four mutant
  seals plus the base seal must differ pairwise), and flips the
  direction through a decrypt plan (which must fail authentication);
  the check fails if any perturbation leaves the seal unchanged.

Run them with:

```sh
E=$(cabal list-bin haskoki:test:haskoki-engine-tests)
"$E" -p '$2 == "Routed end-to-end" && (/gcm checked/ || /gcm traced/)'
```

Serialise heavy test runs as your setup requires.

The mechanism-variant KAT in `tests/model/LogoutOracleMain.hs` stays
the outer-framing control: it pins the frame bytes and the cipher
shape with an opaque parameter tail and must stay passing untouched.
