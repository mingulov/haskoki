# Operator example fixtures

The first four examples originated in the project's initial design; the
remaining examples were added alongside their tests. They are maintained
in this repository.

| File | Purpose |
| --- | --- |
| `maximal-demo.toml` | Target-profile capabilities and local scenario checks |
| `persistent-demo.toml` | SQLite storage with an explicit path |
| `real-crypto.toml` | OpenSSL configuration |
| `scenario.json` | Pending signing and token-removal scenario |
| `sim-demo.toml` and `sim-scenario.json` | Logical delays, token actions, and fault windows |
| `multi-token.toml` | Three-token catalog and per-token authentication/isolation |
| `small-limits.toml` | Disclosure of reserved settings and effective template bounds |

`scenario.json` retains its `design-example-not-executed` origin marker.
The CLI reads this file and runs an owned local scenario; it never
controls another process's loaded provider. [CtlSpec](../../model/CtlSpec.hs)
and [SimBridgeSpec](../../model/SimBridgeSpec.hs) exercise these examples.
Its `rules` array stays empty: the scenario loader rejects nonempty
rules because the runner executes steps only. Pending comes from the
`[async] pending_polls` setting plus the `async.delay` verb (extra
polls on a session), never from rules; `fault.window` selects the
device-error window.

PINs are public test fixtures. Use disposable keys and paths. Configuration
behavior, including reserved settings, is described in the
[configuration reference](../../../docs/config-honesty.md).

`scenario.json`: the top-level `status`/`notice` markers moved under a
documentary `note` object; validation drops them.
`sim-scenario.json`: the top-level `status`/`notice` markers moved under a
documentary `note` object; validation drops them.
`scenario.json`: the retired `only_if_new_store` argument dropped from
`fixture.load`; the fresh-store assumption recorded in the top-level note.
`sim-scenario.json`: the retired `only_if_new_store` argument dropped from
`fixture.load`; the fresh-store assumption recorded in the top-level note.
`scenario.json`: the `token` arguments now name the served slot-0 label
(`session.open` and `token.remove`); other labels refuse at execution.
`sim-scenario.json`: the `token` arguments now name the served slot-0 label
(`session.open` and `token.remove`); other labels refuse at execution.
