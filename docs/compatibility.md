# Compatibility matrix

Do not edit by hand: regenerate with `python3 scripts/generate_compat.py`.
Every cell resolves to works, migrate, or refuse; there are no blanks.

## Versions

- Binary: `0.6.1.0` (authority: `haskoki.cabal`; the CLI carries it, pinned by `caseVersionExact`).
- Store schema served: `3` (authority: `sqliteSchemaVersion`).
- Config schema accepted: `1` (absent means default).
- Interfaces: `2.40`, `3.0`, `3.1`, `3.2` (config allowlist, cross-checked against the ABI inventory; advertisement parity pinned by the discovery legs).

## Rules

- `refuse` wins: any unsupported version refuses the open; no migration writes. The refusal is not side-effect-free: lock acquisition and journal-mode setup precede the schema check. On the pinned default-mode v1 fixture nothing persists (testV1RefusesWithoutWriting); a stale lock is taken over and unlinked on refusal; on WAL-mode stores whose open reaches the journal switch, the DELETE pragma persists.
- `migrate`: store schemas `1`, `2` open only via an explicit `haskoki-ctl store migrate` (verified backup and receipt). Both halves pinned: testV1RefusesWithoutWriting, testV2RefusesWithoutWriting.
- `works` means version compatibility only: no cell version refuses on version grounds. It is not an open guarantee: serving-time conditions refuse separately (tokens without credential rows (migration-required), pinned by caseOpenLegacyRefusesMigrationRequired; reordered token identities (StdStoreIdentityRefusal), pinned by caseOpenReorderRefuses).
- Interface `2.40` is reached through `C_GetFunctionList` only (`C_GetInterface` with 2.40 returns `CKR_ARGUMENTS_BAD`; pinned by the consumer_discovery native leg).
- `memory` stores carry no persisted schema; `other` means any value outside the listed sets.

## Matrix

| Binary | Store | Config | Interface | Verdict |
| --- | --- | --- | --- | --- |
| 0.6.1.0 | memory | 1 | 2.40 | works |
| 0.6.1.0 | memory | 1 | 3.0 | works |
| 0.6.1.0 | memory | 1 | 3.1 | works |
| 0.6.1.0 | memory | 1 | 3.2 | works |
| 0.6.1.0 | memory | 1 | other | refuse |
| 0.6.1.0 | memory | other | 2.40 | refuse |
| 0.6.1.0 | memory | other | 3.0 | refuse |
| 0.6.1.0 | memory | other | 3.1 | refuse |
| 0.6.1.0 | memory | other | 3.2 | refuse |
| 0.6.1.0 | memory | other | other | refuse |
| 0.6.1.0 | 1 | 1 | 2.40 | migrate |
| 0.6.1.0 | 1 | 1 | 3.0 | migrate |
| 0.6.1.0 | 1 | 1 | 3.1 | migrate |
| 0.6.1.0 | 1 | 1 | 3.2 | migrate |
| 0.6.1.0 | 1 | 1 | other | refuse |
| 0.6.1.0 | 1 | other | 2.40 | refuse |
| 0.6.1.0 | 1 | other | 3.0 | refuse |
| 0.6.1.0 | 1 | other | 3.1 | refuse |
| 0.6.1.0 | 1 | other | 3.2 | refuse |
| 0.6.1.0 | 1 | other | other | refuse |
| 0.6.1.0 | 2 | 1 | 2.40 | migrate |
| 0.6.1.0 | 2 | 1 | 3.0 | migrate |
| 0.6.1.0 | 2 | 1 | 3.1 | migrate |
| 0.6.1.0 | 2 | 1 | 3.2 | migrate |
| 0.6.1.0 | 2 | 1 | other | refuse |
| 0.6.1.0 | 2 | other | 2.40 | refuse |
| 0.6.1.0 | 2 | other | 3.0 | refuse |
| 0.6.1.0 | 2 | other | 3.1 | refuse |
| 0.6.1.0 | 2 | other | 3.2 | refuse |
| 0.6.1.0 | 2 | other | other | refuse |
| 0.6.1.0 | 3 | 1 | 2.40 | works |
| 0.6.1.0 | 3 | 1 | 3.0 | works |
| 0.6.1.0 | 3 | 1 | 3.1 | works |
| 0.6.1.0 | 3 | 1 | 3.2 | works |
| 0.6.1.0 | 3 | 1 | other | refuse |
| 0.6.1.0 | 3 | other | 2.40 | refuse |
| 0.6.1.0 | 3 | other | 3.0 | refuse |
| 0.6.1.0 | 3 | other | 3.1 | refuse |
| 0.6.1.0 | 3 | other | 3.2 | refuse |
| 0.6.1.0 | 3 | other | other | refuse |
| 0.6.1.0 | other | 1 | 2.40 | refuse |
| 0.6.1.0 | other | 1 | 3.0 | refuse |
| 0.6.1.0 | other | 1 | 3.1 | refuse |
| 0.6.1.0 | other | 1 | 3.2 | refuse |
| 0.6.1.0 | other | 1 | other | refuse |
| 0.6.1.0 | other | other | 2.40 | refuse |
| 0.6.1.0 | other | other | 3.0 | refuse |
| 0.6.1.0 | other | other | 3.1 | refuse |
| 0.6.1.0 | other | other | 3.2 | refuse |
| 0.6.1.0 | other | other | other | refuse |
