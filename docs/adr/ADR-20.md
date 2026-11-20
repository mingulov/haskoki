# ADR-20 — Per-function error interpretation

Status: Proposed

**Problem:** one collapsing `interpretError` maps distinct
failures (bad key, bad param, gone resource) to one code
regardless of calling function, against OASIS per-function
cells.

**Planned approach:** thread FunctionId to interpretation
(behavior-identical plumbing first), then map per-function
cells with an OASIS 3.2 section cited per changed cell;
unify pub-from-priv; regenerate the error snapshot with
per-function rows. GENERAL_ERROR retention, if any, needs
its own verdict with trace reachability.

**Open:** the GENERAL_ERROR retention verdict (decided in
the per-function-errors task). Flips to Accepted in that task's commit.
