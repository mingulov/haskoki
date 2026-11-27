# Haskoki 0.6.2.0 release notes (accumulating draft)

Developer preview: entries land per task and finalize at release.

## Fixed — null recall on staged message slots

- A NULL query against staged message bytes used to deliver the
  staged output and drop the slot; it now re-reports the staged
  length (`CKR_BUFFER_TOO_SMALL`) and keeps both the slot and
  the outer message context, matching classic retry semantics
  (`retryMessageStaged` IntentNull arm, Tier-2 follow-up from
  the 0.6.1 review).

## Fixed — `file:` URI spelling agreement

- The decode-once rule (guards and SQLite agree on the decoded
  file; divergent spellings refuse) is now fully pinned:
  literal-vs-decoded twins for lock, sidecar, and alias checks
  across `%2e%2e`, `%00`, query/fragment, nested, authority,
  and symlinked-parent spellings. Non-UTF-8 spellings that do
  not round-trip stay explicitly out of scope.

## Fixed — spec validation gate

- `validate-spec.py` GENERATED-HEADER pins refreshed (1 x30_ +
  7 x32_ stubs; the 22/12 pins dated from before message and
  async entries gained routed implementations) and the script
  is now wired into the static gates plus the local mirror, so
  it cannot rot silently again.

## Changed — KAT lane sharding

- The `pkcs11-kat` lane runs as 4 file-balanced shards
  (checker-native deterministic planning) with a merge job
  recombining the same `pkcs11-kat-report` artifact; expected
  unit-wall ~15-20m per shard instead of ~35-105m single.

## Verification

- Full 8-suite Haskell matrix, default and `+usdt` flags, zero
  warnings; static gate block green including the newly wired
  `validate-spec.py`; KAT wall compared per shard against the
  34m40s FLUSH_K baseline on the release PR.
