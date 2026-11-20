# ADR-21 — Private Haskell libraries, no public API

Status: Accepted

**Problem:** 32 modules were publicly importable from the main
library (the 69-module core was already private), including a
four-function stub facade answering `CKR_GENERAL_ERROR` — a new
consumer's first import yielded unusable functions, against
the documented "C ABI is the interface" stance.

**Decision:** privatize (cabal-only, no behavior change). The
main `library` stanza is deleted; `haskoki-core` and the new
`haskoki-internal` (`src` + `ffi`) are `visibility: private`,
so same-package components (suites, tools, exes) import them
while no downstream package can depend on them. The stub
facade and its top re-export are deleted (sole in-repo
importer, the smoke suite, switched to `Haskoki.Types`).
Test seams stay exported inside the private library.

**Alternatives:** a minimal PVP surface (rejected: no
external Haskell consumers exist — the client uses the C ABI
only — so versioning a surface would promise stability
nobody needs); an empty main library (rejected: a public
dependency target with zero imports misleads more than its
absence).

**Consequences:** out-of-tree `import Haskoki.*` fails at
dependency resolution (proven by the consumer check);
in-repo components take `haskoki:haskoki-internal` /
`haskoki:haskoki-core` deps. Enforcement is threefold and
mutation-proven: bare goals fail on main-less packages,
each private sublibrary fails direct external goals
independently, and the static gate rejects any publicity
(see `docs/private-apis.md`). Restoring a public API means
re-adding an unnamed stanza with a blessed surface plus PVP
discipline (same doc).
