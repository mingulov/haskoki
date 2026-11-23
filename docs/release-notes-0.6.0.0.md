# Haskoki 0.6.0.0 release notes (accumulating draft)

Developer preview: entries land per task and finalize at release.

## Removed — public Haskell API

- The package has no installable Haskell library anymore: the
  main `library` stanza is gone, `haskoki-core` and
  `haskoki-internal` are `visibility: private`, and the 0.5.0.0
  stub facade (`Haskoki.PKCS11`, four functions answering
  `CKR_GENERAL_ERROR`) plus its top-level re-export were
  deleted. Out-of-tree `import Haskoki.*` fails at dependency
  resolution. The product interface is the C ABI, unchanged.
  (No external Haskell consumers are known to exist.)

## Changed — exact per-function errors

- Rejected backend key material now reports `CKR_FUNCTION_FAILED`
  on sign, verify, cipher and message legs (was
  `CKR_GENERAL_ERROR`).
- Key generation with rejected domain material reports
  `CKR_ATTRIBUTE_VALUE_INVALID` (`C_GenerateKey`) and
  `CKR_DOMAIN_PARAMS_INVALID` (`C_GenerateKeyPair`, newly served);
  derivation from an incompatible base reports
  `CKR_KEY_TYPE_INCONSISTENT`.
- Over-length input reports `CKR_DATA_LEN_RANGE` on sign, verify
  and encrypt legs, `CKR_ENCRYPTED_DATA_LEN_RANGE` on decrypt
  legs, `CKR_SIGNATURE_LEN_RANGE` on verify-recover,
  `CKR_KEY_SIZE_RANGE` on wrap, and `CKR_WRAPPED_KEY_LEN_RANGE`
  (newly served) on unwrap and decapsulation.
- Lost backend state (digest streams, key references) reports
  `CKR_DEVICE_ERROR` (newly served) on digest-update/final,
  crypto and key legs (was `CKR_GENERAL_ERROR`).
- Pub-from-priv derivation from a non-private base reports
  `CKR_KEY_TYPE_INCONSISTENT` (was `CKR_TEMPLATE_INCONSISTENT`),
  matching the agreement arms.
- The IKE prf+ output ceiling is per-PRF (255 blocks of the hash
  width: SHA-256 tops out at 8160, not 16320); over-ceiling
  derivation reports `CKR_KEY_SIZE_RANGE` (was
  `CKR_ARGUMENTS_BAD`).
- Deliberately unclassified failures (driver, invalid-state,
  native) keep `CKR_GENERAL_ERROR` and now emit one JSONL trace
  row each with the typed cause (function, code, constructor).
- Six strict conformance checks now pass instead of expected-fail:
  misaligned ECB ciphertexts and truncated OAEP ciphertexts report
  `CKR_ENCRYPTED_DATA_LEN_RANGE`.

## Added

- Three newly served return codes (63 total): `CKR_DEVICE_ERROR`,
  `CKR_DOMAIN_PARAMS_INVALID`, `CKR_WRAPPED_KEY_LEN_RANGE`.
- Config-gated test seams: `storage.allow_env_seams` (default
  `false`) opts the config-driven serving open into consulting
  `HASKOKI_PROC_ROOT` (owner liveness) and `HASKOKI_OPEN_PAUSE*`
  (fresh-init pause on create, with a `go`-file handshake and a
  ~30s poll-budget fallback). Env seams are inert everywhere
  without the opt-in; `haskoki-ctl` destructive paths never opt
  in. Serving opens run masked with bounded, single-deadline
  cancellation cleanup.

## Removed

- No public Haskell library: the package exposes only the C ABI.
  The stub facade (`Haskoki.PKCS11`, already deprecated) and its
  top-level re-export are deleted; out-of-tree `import Haskoki.*`
  now fails at dependency resolution (checked in CI).
