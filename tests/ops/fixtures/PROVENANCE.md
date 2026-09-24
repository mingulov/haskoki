# Provenance — operations fixtures

Copied verbatim (read-only source) from the design bundle:

- `ws/docs/incoming/haskell-pkcs11-design/examples/maximal-demo.toml`
- `ws/docs/incoming/haskell-pkcs11-design/examples/persistent-demo.toml`
- `ws/docs/incoming/haskell-pkcs11-design/examples/real-crypto.toml`
- `ws/docs/incoming/haskell-pkcs11-design/examples/scenario.json`

Copied so config/CLI tests run hermetically from
the repo tree. The design bundle remains the source of truth; any drift
must be reconciled by re-copying, never by editing both sides.
`scenario.json` keeps its `status: design-example-not-executed` marker:
the owned-instance runner interprets an adapted copy of these steps
(see `Haskoki.Ctl`), it never controls another live process.

Repo-authored (NOT from the design bundle):

- `sim-demo.toml`: the `[sim]` surface demo (delay schedules, token
  script, fault window) for the ConfigSpec/CtlSpec pins and the
  sim-scenario runs. Owned by the repo tree; edit in place.
- `sim-scenario.json`: the sim verb demo (`token.insert`,
  `async.delay`, `fault.window` over an async sign flow). Run with
  `sim-demo.toml` (test-enabled); edit in place.
- `multi-token.toml`: the `[tokens]` catalog demo (3 tokens:
  `haskoki-demo`/`haskoki-ops`/`haskoki-audit`, slot = catalog
  index) for the ConfigSpec pins, the MultiTokenSpec seating/
  auth/isolation suites, and the C consumer proof. Catalog PINs
  are EXAMPLE-GRADE fixture material ("Do not use production
  secrets", same discipline as the design fixtures). Owned by the
  repo tree; edit in place.
