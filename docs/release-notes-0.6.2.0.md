# Haskoki 0.6.2.0 release notes (accumulating draft)

Developer preview: entries land per task and finalize at release.

## Fixed — null retry on staged message slots

- Model contract fix (Tier-2 follow-up from the 0.6.1 review):
  a null-intent `retryMessageStaged` used to deliver, count,
  and drop the staged bytes; it now re-reports the staged
  length and keeps them, mirroring the classic `retryStaged`
  arm while the outer message context survives. C API behavior
  is unchanged (NULL queries already answered OK plus length);
  the visible effect is that re-queries pass through the
  retain path like classic retries.

## Tests — `file:` URI spelling agreement

- The decode-once rule (guards and SQLite agree on the decoded
  file; divergent spellings refuse) is now fully pinned: new
  lock and alias twin tests over `%2e%2e` spellings (plus a
  symlinked parent for alias) join the pre-existing sidecar,
  undecodable, query (plus a new fragment case), nested,
  and authority twins.
  No behavior change. Non-UTF-8 spellings that do not
  round-trip stay explicitly out of scope.

## Fixed — spec validation gate

- `validate-spec.py` GENERATED-HEADER pins refreshed (1 x30_ +
  7 x32_ stubs; the 22/12 pins went stale as the crypto slices
  began routing stubs, then message and async routing) and the
  script is now wired into the static gates plus the local
  mirror, so it cannot rot silently again.

## CI — KAT lane sharding

- The `pkcs11-kat` lane runs as 4 file-balanced shards
  (checker-native deterministic planning) with a merge job
  recombining the same `pkcs11-kat-report` artifact; expected
  unit-wall ~15-20m per shard instead of ~35-105m single.

## Verification

- Full 8-suite Haskell matrix, default and `+usdt` flags, zero
  warnings; static gate block passing including the newly wired
  `validate-spec.py`; KAT wall compared per shard against the
  34m40s FLUSH_K baseline on the release PR.
