# ADR-22 — Reserve profile, interfaces, engine.kind (report-only keys)

Status: Accepted

**Problem:** `profile`, `interfaces` and `engine.kind` are
classified Enforced but select no behavior: the read-site
audit finds only `Ctl.hs` reporting reads (labels, declared
set, configured catalog). The Enforced label promises
enforcement that does not exist.

**Decision:** reclassify all three to Reserved
(config-not-policy): every documented value keeps parsing,
validating and reporting, and three loud `reserved-*`
capabilities lines disclose the reservation, pinned by
`ConfigHonestySpec` like the existing reserved knobs.

**Alternatives:** making them bite (profile-selected
behavior, native interface gating, engine-routed backends)
would change native behavior beyond an honesty task — and
for `engine.kind` would contradict the pinned
native-always-OpenSSL4 architecture. Refused would reject
meaningful validated labels; for `engine.kind` it would
additionally break existing `openssl` configs (the default
is `synthetic`).

**Consequences:** the key catalog counts 9 reserved keys;
the config-honesty doc table, Reserved section, audit lists
and the three disclosure lines move together (mechanically
compared). Restoring enforcement means proving a behavior
read site per key and re-pinning the contract tests.
