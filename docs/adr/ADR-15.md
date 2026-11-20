# ADR-15 — Storage encryption stance: demo forever

Status: Accepted

**Decision:** no at-rest encryption, PIN verifiers, or store MAC
(S-02/S-07 answered "never — demo forever"; owner decision
2026-11-19). The SQLite store and memory backend hold key material
in the clear; the plaintext-store warning and demo labels carry the
honesty burden. Checker lanes stay memory-only regardless.

**Rejected:** at-rest encryption, PIN verifiers, store MACs, and
any "persistent secrets are safe here" implication.

**Consequence:** Haskoki must never be mistaken for secure key
storage; persistent mode is a demo/convenience feature with
documented plaintext semantics.

**Wrong if:** an owner-approved use case arrives that needs real
secrets to survive a restart — then a full threat model and a new
ADR precede any build, and this record is superseded rather than
edited.
