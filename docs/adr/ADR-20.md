# ADR-20 — Per-function error interpretation

Status: Accepted

**Decision:** thread FunctionId to error interpretation, then set
per-function cells with an OASIS 3.2 section cited per changed cell.
Bare bound-key refusals take the 5.1.1 `FUNCTION_FAILED` fallback
(`KEY_FUNCTION_NOT_PERMITTED` is a 5.1.6 usage-attribute denial,
absent from the 5.8–5.16 execution sets). The pub-from-priv
base-class arm unifies to `KEY_TYPE_INCONSISTENT`; the derived-type
arm stays `TEMPLATE_INCONSISTENT` per 4.1.1/6.43.8 (a template
conflict, not a key contradiction). The error snapshot regenerates
with per-function rows.

**Rejected:** the collapsing interpreter (one code regardless of
calling function); per-family codes; any code outside the OASIS
sets for the calling function.

**Decision (GENERAL_ERROR retention):** kept deliberately for
exactly three legs — unclassified driver failures, backend
invalid-state, and native failures — plus defensive arms for
(function, error) pairs no producer reaches. These name
haskoki-internal breach classes, not caller-actionable conditions,
and no OASIS set offers them a more specific code. Every kept
failure reaches the trace sink with its typed cause, so kept
errors stay diagnosable.

**Consequence:** callers see distinct, OASIS-listed codes for
key/param/resource failures on every routed leg.

**Wrong if:** an OASIS errata or a newly served mechanism gives a
kept leg a listable code (adopt it, shrink the kept set), or a
producer starts emitting a kept constructor for a caller-actionable
condition (reclassify the producer, not the cell).
