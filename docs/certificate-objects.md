# Certificate objects

Certificate-object policy and disposition record. This file is created
by T-C04 and later tasks append their own headed sections after it
(T-C05/T-C06/T-C07/T-C11 append; T-C10 finalizes).

Spec trace: §2.1 G05, §3 C04 (this skeleton plus the two sections
below). Later sections carry their own spec traces.

Evidence root: `dist-release-evidence/certificates/task-c04/`; the
focused pins run in `task-c04/after.log` and the prose gate runs in
`task-c04/docs.log` (full suites in `task-c04/retained.log`).

## Supplied-values metadata position

Normative supplied-values position: `SUBJECT`, `ISSUER`,
`SERIAL_NUMBER`, `PUBLIC_KEY_INFO`, and both hash attributes are
opaque caller-supplied bytes. The token never derives them from
`VALUE`, never validates DER structure, and never checks
metadata-to-VALUE coherence. Wrong-metadata cases are refused only
where the standard defines refusal (missing required fields per
C01: TYPE/VALUE/SUBJECT presence for X.509).

Pins (synthetic bytes deliberately, pinning the absence of parsing;
real DER is qualified by T-C02/T-C09): `caseSuppliedOpaque` creates
X.509 with garbage non-DER VALUE plus arbitrary SUBJECT/ISSUER/
SERIAL/SPKI/both-hashes, reads every field back exactly, and matches
find by each supplied field; `caseNoCoherenceGate` creates with
SUBJECT/ISSUER/SERIAL contradicting each other and VALUE, and shows
only missing required fields refuse. See
`dist-release-evidence/certificates/task-c04/after.log`
(`task-c04/after`), `task-c04/docs`, and `task-c04/retained` for the
green runs.

## Durability convergence note

The T-C02 convergence rule below is incorporated verbatim from
`dist-release-evidence/certificates/task-c02/convergence-note.md`:

After an unknown store commit, the gate-held caller re-reads tokens
plus meta and compares every projected put, drop, and meta row
against the reread state: all rows present means the commit landed
and the projected model publishes; any row absent means it did not,
so the pre model is kept and the store fault is returned; an
unreadable re-read fails closed the same way (model kept, fault
returned). Nothing reissues the operation, so the durable state
stays single-writer consistent, and the next open replays the
reservation from the persisted counters and converges to the same
high-waters.

Later tasks append their headed sections below this line.
