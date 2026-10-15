#!/usr/bin/env python3
"""Regenerate docs/coverage.md from the spec data.

Reads spec/mechanisms.json + spec/source-issues.json + the served-count
macro HASKOKI_MECH_COUNT in cbits/mech_catalog.inc (consistency only, no
new claims beyond evidence), asserts internal consistency, and writes the
coverage / limitations / source-issues publication. Usage:

  scripts/publish-coverage.py          # regenerate docs/coverage.md
  scripts/publish-coverage.py --check  # fail if docs/coverage.md is stale

Exit status: 0 iff generated output matches the committed doc (--check)
or was written successfully.
"""

import collections
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MECH = ROOT / "spec" / "mechanisms.json"
ISSUES = ROOT / "spec" / "source-issues.json"
OUT = ROOT / "docs" / "coverage.md"
INC = ROOT / "cbits" / "mech_catalog.inc"
FUNCS = ROOT / "spec" / "function-contracts.json"
LEDGER = ROOT / "spec" / "findings-ledger.json"
PLACEHOLDER = "Catalog-only (generator note)"

# Templates, not fixed text: the served-row count is derived from
# spec/mechanisms.json (support.real == "tested") and proven equal
# to HASKOKI_MECH_COUNT in cbits/mech_catalog.inc (see
# check_consistency). Never hardcode the count here.
BOUNDARY_TEMPLATE = """\
> Scope: the row evidence names in-process Haskell tests using
> pinned OpenSSL 4.0.2 and/or the synthetic engine. The C surface
> serves the {n}-row real-tested catalog; listing a mechanism does
> not establish coverage of every parameter or operation through C.
> Native checks: [consumer tests](../scripts/test-consumers.sh),
> [proxy parity](../scripts/test-proxy-parity.sh), and
> [bundle installation](../scripts/test-release-install.sh).
"""

LIMITATIONS_TEMPLATE = """\
- C surface: the default config serves 1 slot with its token (a
  `[tokens]` catalog serves N slots; see [host requirements](../SUPPORTED-HOSTS.md)
  and [token provisioning](demo-walkthrough.md#token-provisioning-and-state)). Real C-surface crypto routes
  over the {n}-row tested catalog; genuinely unsupported calls
  keep their documented refusals.
- `haskoki-ctl scenario run` simulates against an owned in-memory
  model; it never controls another live process.
- No certification, FIPS, Common Criteria, or production-security
  claim is made anywhere in this release.
"""


def sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()[:16]


def load():
    mechs = json.loads(MECH.read_text())["mechanisms"]
    issues = json.loads(ISSUES.read_text())["issues"]
    return mechs, issues


def load_functions():
    funcs = json.loads(FUNCS.read_text())["functions"]
    ledger = json.loads(LEDGER.read_text())["rows"]
    refusals = sorted(r["input"] for r in ledger
                      if r["kind"] == "function"
                      and r["dimension"] == "c-routing")
    return funcs, refusals


def check_functions(funcs, refusals):
    assert len(funcs) == 104, f"function contract drift: {len(funcs)} want 104"
    names = {f["name"] for f in funcs}
    assert len(names) == len(funcs), "duplicate function contract"
    assert len(refusals) == 11, f"C hard refusals: {len(refusals)} want 11"
    # The C hard refusals are served by the C tables; two of them are
    # grouped under one contract name (C_VerifySignature*), so every
    # refusal must name a contract row.
    for n in refusals:
        assert n in names, f"hard refusal {n} has no function contract row"
    n_unsup = sum(1 for f in funcs if f["contract"] == "unsupported-with-reason")
    assert n_unsup == 21, f"planner-unsupported drift: {n_unsup} want 21"


def real_tested_count(mechs):
    return sum(1 for r in mechs if r["support"]["real"] == "tested")


# Catalog sweep batteries: shared catalog-level evidence (F-11). A
# tested row is `sweep-only` when every test_evidence entry cites one
# of these; otherwise it carries behavior-exercising evidence
# (engine/key-management/operation suites or a per-mechanism recipe)
# and renders `dedicated`. Computed per row from the spec module
# (artifact basename), never from the case_id: Recipe* specs share
# case A40 with RegistrySpec but are dedicated per-mechanism cases.
SWEEP_SPECS = frozenset({"MechanismExhaustivenessSpec", "RegistrySpec"})


def evidence_kind(row):
    arts = {e["artifact"].split("/")[-1] for e in row["test_evidence"]}
    return "sweep-only" if arts <= SWEEP_SPECS else "dedicated"


def c_surface_count():
    for line in INC.read_text().splitlines():
        if line.startswith("#define HASKOKI_MECH_COUNT"):
            return int(line.split()[-1])
    raise AssertionError(
        "HASKOKI_MECH_COUNT not found in cbits/mech_catalog.inc")


def check_consistency(mechs):
    total = len(mechs)
    assert total == 464, f"denominator drift: {total} rows, want the 464 catalog rows"
    n_real = real_tested_count(mechs)
    n_c = c_surface_count()
    assert n_real == n_c, (
        f"C surface drift: {n_real} real-tested rows vs "
        f"HASKOKI_MECH_COUNT {n_c} (re-run generate-mechanisms.py)")
    ids = [r["numeric_id"] for r in mechs]
    assert len(set(ids)) == total, "duplicate numeric_id"
    n_alias = sum(len(r["aliases"]) for r in mechs)
    assert total + n_alias == 480, (
        f"header denominator drift: {total}+{n_alias}, want 480")
    for col in ("behavior", "real", "synthetic"):
        states = collections.Counter(r["support"][col] for r in mechs)
        assert sum(states.values()) == total, f"{col} counts do not sum"
    for r in mechs:
        b = r["support"]["behavior"]
        if b == "tested":
            assert r["test_evidence"], f"{r['canonical_name']}: tested without evidence"
        if b in ("unsupported-with-reason", "not-applicable"):
            assert r["notes"].strip(), f"{r['canonical_name']}: {b} without reason"
        if b in ("unsupported-with-reason", "not-applicable", "planned"):
            # The rendered reason is the first line of the notes; a
            # generator placeholder there is not a reviewed reason.
            assert not r["notes"].strip().splitlines()[0].startswith(
                PLACEHOLDER), (
                f"{r['canonical_name']}: placeholder reason, needs a "
                f"reviewed note")
        if b == "planned":
            assert not r["test_evidence"], (
                f"{r['canonical_name']}: planned row carries evidence")


def fmt_counts(counter, total):
    order = ["tested", "unsupported-with-reason", "not-applicable", "planned"]
    return ", ".join(f"{counter.get(k, 0)} {k}" for k in order
                     if counter.get(k, 0)) + f" ({total} total)"


def render(mechs, issues, funcs, refusals):
    total = len(mechs)
    n_alias = sum(len(r["aliases"]) for r in mechs)
    by_beh = collections.Counter(r["support"]["behavior"] for r in mechs)
    by_real = collections.Counter(r["support"]["real"] for r in mechs)
    by_syn = collections.Counter(r["support"]["synthetic"] for r in mechs)
    fams = collections.defaultdict(lambda: collections.Counter())
    for r in mechs:
        fams[r["family"]][r["support"]["behavior"]] += 1

    L = []
    L.append("# Coverage, limitations and source issues")
    L.append("")
    L.append("GENERATED by scripts/publish-coverage.py — DO NOT EDIT.")
    L.append(f"Sources: spec/mechanisms.json (sha {sha(MECH)}), "
             f"spec/source-issues.json (sha {sha(ISSUES)}).")
    L.append("Denominator: 464 catalog rows "
             f"(+ {n_alias} aliases = 480 header CKM).")
    L.append("")
    n_real = real_tested_count(mechs)
    L.append(BOUNDARY_TEMPLATE.format(n=n_real))
    L.append("## Mechanism coverage")
    L.append("")
    L.append(f"- behavior: {fmt_counts(by_beh, total)}")
    L.append(f"- real (libcrypto): {fmt_counts(by_real, total)}")
    L.append(f"- synthetic: {fmt_counts(by_syn, total)}")
    L.append("")
    L.append("Tested behavior rows carry `test_evidence` (suite/case ids); "
             "every unsupported/not-applicable row carries its reason in "
             "the row notes; planned rows carry no evidence (asserted by "
             "the publisher).")
    # The reporting closure, enumerated from the source of
    # truth (never from what's present): every suite named by any
    # test_evidence artifact. A suite dropped from evidence (or
    # from the build) changes this line loudly via --check.
    suites = sorted({e["artifact"].split("/")[0]
                     for r in mechs for e in r["test_evidence"]})
    n_ev = sum(len(r["test_evidence"]) for r in mechs)
    n_tested = len([r for r in mechs
                    if r["support"]["behavior"] == "tested"])
    L.append(f"Evidence suites: {', '.join(suites)} "
             f"({n_ev} evidence entries over {n_tested} tested rows).")
    L.append("")
    L.append("### By family (behavior column)")
    L.append("")
    L.append("| family | tested | unsupported | n/a | planned | total |")
    L.append("|---|---|---|---|---|---|")
    for fam in sorted(fams):
        c = fams[fam]
        L.append(f"| {fam} | {c.get('tested', 0)} | "
                 f"{c.get('unsupported-with-reason', 0)} | "
                 f"{c.get('not-applicable', 0)} | {c.get('planned', 0)} | "
                 f"{sum(c.values())} |")
    L.append("")
    L.append("### Behavior-tested mechanisms (executable recipes, in-process)")
    L.append("")
    L.append("Each row names its in-process evidence (suite/case). See the "
             "scope above for the C surface. The kind "
             "column marks rows carried only by the catalog sweep batteries "
             "(`sweep-only`) versus rows with behavior-exercising evidence "
             "(`dedicated`).")
    L.append("")
    L.append("| mechanism | id | evidence cases | kind |")
    L.append("|---|---|---|---|")
    tested = sorted((r for r in mechs if r["support"]["behavior"] == "tested"),
                    key=lambda r: int(r["numeric_id"], 16))
    for r in tested:
        ev = ", ".join(f"{e['artifact'].split('/')[-1]}:{e['case_id']}"
                       for e in r["test_evidence"][:4])
        if len(r["test_evidence"]) > 4:
            ev += f" (+{len(r['test_evidence']) - 4})"
        L.append(f"| {r['canonical_name']} | {r['numeric_id']} | {ev} | "
                 f"{evidence_kind(r)} |")
    L.append("")
    L.append("## Known limitations (from unsupported-with-reason rows)")
    L.append("")
    L.append("The behavior column's unsupported/not-applicable rows, with "
             "their recorded reasons (first line of row notes):")
    L.append("")
    L.append("| mechanism | id | disposition | reason |")
    L.append("|---|---|---|---|")
    lim = sorted((r for r in mechs
                  if r["support"]["behavior"] in
                  ("unsupported-with-reason", "not-applicable")),
                 key=lambda r: int(r["numeric_id"], 16))
    for r in lim:
        reason = r["notes"].strip().splitlines()[0][:160]
        reason = reason.replace("|", "/")
        L.append(f"| {r['canonical_name']} | {r['numeric_id']} | "
                 f"{r['support']['behavior']} | {reason} |")
    L.append("")
    planned = sorted((r for r in mechs if r["support"]["behavior"] == "planned"),
                     key=lambda r: int(r["numeric_id"], 16))
    L.append("## Planned mechanisms (catalog rows, not yet served)")
    L.append("")
    L.append(f"{len(planned)} rows carry behavior `planned`: catalogued with "
             "their header identity, no evidence and no C route. Each is "
             "tracked as a target-gap in the [findings ledger]"
             "(../spec/findings-ledger.json). Reason is the first line of "
             "the row notes.")
    L.append("")
    L.append("| mechanism | id | family | reason |")
    L.append("|---|---|---|---|")
    for r in planned:
        reason = r["notes"].strip().splitlines()[0][:160].replace("|", "/")
        L.append(f"| {r['canonical_name']} | {r['numeric_id']} | "
                 f"{r['family']} | {reason} |")
    L.append("")
    refset = set(refusals)
    n_contract = collections.Counter(f["contract"] for f in funcs)
    L.append("## Function contracts")
    L.append("")
    L.append(f"{len(funcs)} function contracts from "
             "spec/function-contracts.json "
             + ", ".join(f"{n_contract[k]} {k}" for k in sorted(n_contract))
             + ". The contract scope is planner/in-process reachability, "
             "NOT C-table routing, so the planner and C columns can differ.")
    L.append("")
    L.append("### C hard refusals")
    L.append("")
    L.append(f"{len(refusals)} C functions are refused by the C function "
             "tables with `CKR_FUNCTION_NOT_SUPPORTED` once the library is "
             "initialised (`CKR_CRYPTOKI_NOT_INITIALIZED` before): "
             + ", ".join(f"`{n}`" for n in refusals) + ". "
             "Two further entries (`C_GetFunctionStatus`, `C_CancelFunction`) "
             "give the mandated legacy responses and are not counted. These "
             "are the \"C routing\" refusals; they are a different set from "
             "the planner-unsupported contracts below. Decisions are in the "
             "[findings ledger](../spec/findings-ledger.json).")
    L.append("")
    L.append("| function | ordinal (3.2) | C routing | planner contract | "
             "planner reason |")
    L.append("|---|---|---|---|---|")
    for f in sorted(funcs, key=lambda f: f["ordinal_3_2"]):
        c = ("hard refusal (C routing)" if f["name"] in refset
             else "served")
        if f["contract"] == "not-applicable":
            c = "legacy response"
        reason = (f["reason"] or "").replace("|", "/")
        L.append(f"| {f['name']} | {f['ordinal_3_2']} | {c} | "
                 f"{f['contract']} | {reason} |")
    L.append("")
    L.append("Release-wide limitations (reviewed, non-generated):")
    L.append("")
    L.append(LIMITATIONS_TEMPLATE.format(n=real_tested_count(mechs)))
    L.append("## Source issues")
    L.append("")
    n_open = sum(1 for i in issues if str(i.get("status", "?")).strip().lower() == "open")
    L.append(f"{len(issues)} registered issues ({n_open} open) in spec/source-issues.json:")
    L.append("")
    L.append("| id | title | status |")
    L.append("|---|---|---|")
    for i in issues:
        iid = i.get("id", "?")
        title = str(i.get("title", i.get("summary", "?")))[:120].replace("|", "/")
        status = str(i.get("status", "?"))
        L.append(f"| {iid} | {title} | {status} |")
    L.append("")
    return "\n".join(L)


def main():
    check = len(sys.argv) > 1 and sys.argv[1] == "--check"
    if len(sys.argv) > 1 and not check:
        print("usage: scripts/publish-coverage.py [--check]", file=sys.stderr)
        return 2
    mechs, issues = load()
    funcs, refusals = load_functions()
    try:
        check_consistency(mechs)
        check_functions(funcs, refusals)
    except AssertionError as e:
        print(f"FAIL: coverage data inconsistent: {e}", file=sys.stderr)
        return 1
    text = render(mechs, issues, funcs, refusals)
    if check:
        if not OUT.exists():
            print(f"FAIL: {OUT.relative_to(ROOT)} missing "
                  "(run: scripts/publish-coverage.py)", file=sys.stderr)
            return 1
        if OUT.read_text() != text:
            print(f"FAIL: {OUT.relative_to(ROOT)} stale "
                  "(run: scripts/publish-coverage.py)", file=sys.stderr)
            return 1
        print(f"coverage publication current "
              f"({len(mechs)} rows, {len(issues)} issues)")
        return 0
    OUT.write_text(text)
    print(f"wrote {OUT.relative_to(ROOT)} "
          f"({len(mechs)} rows, {len(issues)} issues)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
