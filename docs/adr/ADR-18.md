# ADR-18 — Planner/C join register

Status: Accepted

**Decision:** `spec/function-contracts.json` carries a `c_route`
per function joining the planner site to the C site, with
`test_evidence` on every row (proving suites for served rows,
refusal evidence for refused rows). The join is generated
(`scripts/generate-function-contracts.py` inputs, never hand
edits) and gated (`scripts/check-planner-join.py`).

**Rejected:** a split register (planner rows here, C routes
there); hand-maintained JSON; evidence-free rows.

**Consequence:** one function register answers "where is it
planned, where is it served, what proves it" for all 104
functions; the T-06 backfill closes here.

**Wrong if:** a function needs more than one route (multi-site
dispatch) — then the schema gains a routes list via the
generator, not a second register.
