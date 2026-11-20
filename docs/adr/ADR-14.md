# ADR-14 — Serialization lock

Status: Accepted

**Decision:** durable bytes are versioned and logic-only: operation
snapshots carry the `HKSNAP02` schema id plus format version
(`core/Haskoki/Snapshot.hs:13`), logical state only (never resource
ids, pointers, or native handles), big-endian integers with rejecting
tags. Recipe/durable bytes stay frozen. Format changes ship as a
version bump with a compat note, never silently.

**Rejected:** unversioned snapshot bytes; persisting pointers,
resource ids, or native handles; silent format drift.

**Consequence:** old bytes stay readable or explicitly migratable;
a fixture scan can pin the absence of handles in snapshots.

**Wrong if:** a format must change incompatibly without a version
bump because a supported reader rejects new versions and cannot be
upgraded before rollout — then a compatibility/migration review
precedes any change, and only then is the bump procedure itself
reviewed, with that reader's constraint attached.
