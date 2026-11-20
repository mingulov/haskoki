# Private Haskell APIs

The product interface is the C ABI (the versioned PKCS#11 tables
in `cbits/` plus `ffi/`). There is intentionally no public
Haskell API: the package has no main library, and both
implementation libraries are `visibility: private`, so no
downstream package can depend on them. `scripts/check-exposure.py`
(pinned by CI) and `scripts/check-consumer.sh` (an out-of-tree
build probe) enforce this mechanically.

## Library layout

- `haskoki-core` (private): pure core — types, requests, outcomes,
  the model, transitions, operations, recipes, the registry.
  Same-package components (suites, tools) import it directly.
- `haskoki-internal` (private): engines, runtimes, storage, the
  FFI layers, the operator tool surface. Same-package components
  import it directly.
- No `library` stanza: `import Haskoki` fails out of tree by
  construction. The 0.5.0.0 stub facade (`Haskoki.PKCS11`: four
  functions answering `CKR_GENERAL_ERROR`) and its top-level
  re-export were deleted with this policy; the C tables never
  routed through them.

## Test seams

Engine suites exercise rejection tracing and close-time flushing
through the real implementation, which needs three
otherwise-internal names: `publishRejectionE` (Standard),
`publishRejection` (Exports) and `publishRejection` (Async),
plus `CryptoCtx` selectors. They stay exported inside the
private library (component visibility keeps them out of any
downstream API); re-adding a public library must re-audit them.

## Why it holds (solver semantics, probed)

Three independent mechanisms, each verified by mutation
against the pinned toolchain (cabal-install 3.12.1.0):

- **No main library.** A package without a main `library`
  stanza fails every bare out-of-tree package goal with
  "requires library from haskoki, but the component does not
  exist".
- **Per-library privacy.** An out-of-tree dependency on a
  `visibility: private` sublibrary fails with "requires
  library '…' from haskoki, but the component is private" —
  each library independently. (A public library may still
  build against a private sublibrary from source inside its
  own closure; privacy blocks downstream *dependencies*,
  not the build. Flipping one library public was verified
  to resolve exactly its probe.)
- **Static gate.** `check-exposure.py` rejects any main stanza
  and any non-`private` visibility marker (layout or brace
  syntax, any letter case, conditionals included — a marker
  in dead configuration fails closed so it gets removed).
  Unmarked named libraries are private by default (probed);
  `common` stanzas cannot carry visibility (Cabal parses
  them with the build-info grammar, which has no such
  field). Partial publicity fails the build even where
  the solver would already refuse it.

The consumer check (`check-consumer.sh`) runs one fixture
probe *project* per library — separate projects because
Cabal solves a whole project before selecting targets, so
probes sharing a project cannot fail independently. Every
probe must fail at dependency resolution with its own
pinned diagnostic. Flipping any single library public was
verified to break exactly its probe (positive controls).
New named libraries must gain a probe project — the script
errors loudly while the fixture is stale.

## Re-introducing a public API

Restore an unnamed `library` stanza exposing exactly the
blessed surface, teach the exposure gate the blessed set,
convert the consumer fixture's negative probes for the
restored libraries into positive ones (they must resolve and
import the blessed surface), and re-audit the test seams
above. PVP applies from that version on.
