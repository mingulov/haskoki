# ADR-20 — Per-function error interpretation

Status: Accepted

**Problem:** one collapsing `interpretError` maps distinct
failures (bad key, bad param, gone resource) to one code
regardless of calling function, against OASIS per-function
cells.

**Approach (landed):** FunctionId threaded to interpretation,
then per-function cells with an OASIS 3.2 section cited per
changed cell (spec-lawyer pass corrected the headline
instinct: `KEY_FUNCTION_NOT_PERMITTED` is a 5.1.6
usage-attribute denial absent from the 5.8-5.16 execution
sets, so bare bound-key refusals take the 5.1.1
`FUNCTION_FAILED` fallback); pub-from-priv base-class arm
unified to `KEY_TYPE_INCONSISTENT` (the derived-type arm
stays `TEMPLATE_INCONSISTENT` per 4.1.1/6.43.8 — a template
conflict, not a key contradiction); snapshot regenerated
with per-function rows.

**GENERAL_ERROR retention verdict:** kept deliberately for
exactly three legs — unclassified driver failures
(`CryptoFailed`), backend-invalid-state, and native failures —
plus defensive arms for (function, error) pairs no producer
reaches (unreachable by construction: no finishing route, or
no backend failure of that shape for the family). Rationale:
these legs name haskoki-internal breach classes (driver bugs,
closed backends, shim failures), not caller-actionable
conditions, and no OASIS set offers a more specific code for
them. Every kept failure reaches the trace sink: finishers
attach a `(FunctionId, CryptoError)` cause to the rejection
(`keptCause`, gated on the served code staying general),
publishers and the async drive emit one JSONL row per kept
failure (function, general-error value, typed constructor,
"rejected" disposition). Approximation: the driver converts
`CryptoFailed` to native `("driver", -1)` before finishing,
so the traced constructor is the post-conversion one with
the original message preserved. Gap: stepless legacy
finishes carry no cause (no function to name).

**Consequence:** callers see distinct, OASIS-listed codes for
key/param/resource failures on every routed leg; kept
general errors stay diagnosable via trace. Wrong if: an OASIS
errata or a newly served mechanism gives a kept leg a
listable code (adopt it, shrink the kept set), or a producer
starts emitting a kept constructor for a caller-actionable
condition (reclassify the producer, not the cell).
