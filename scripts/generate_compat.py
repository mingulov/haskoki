#!/usr/bin/env python3
"""Generate docs/compatibility.md from the tree's version constants.

Reads four pinned one-line shapes textually (no Haskell lexer: the
shapes are documented at their definitions and the gate fails closed
when any is absent):
  - binary:        haskoki.cabal  `version: X.Y.Z.W`
  - store schema:  sqliteSchemaVersion = N   (Storage/SQLite/Types.hs)
  - config schema: configSchemaVersion = N   (Runtime/Config.hs)
  - interfaces:    supportedInterfaces = [...] (Runtime/Config.hs)

Emits the Versions bullets, the fixed compatibility Rules, and the
total binary x store x config x interface table (verdicts computed
by the same rule the gate rechecks: refuse wins, store 1..N-1
migrates, memory + served works).

STDLIB ONLY. Run from anywhere:
  python3 scripts/generate_compat.py [--root DIR]
"""
import argparse
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


def read_constants(root):
    cabal = (root / "haskoki.cabal").read_text()
    m = re.search(r"^version:\s+(\d+\.\d+\.\d+\.\d+)\s*$", cabal, re.M)
    if not m:
        raise SystemExit("generate_compat: haskoki.cabal carries no X.Y.Z.W version")
    binary = m.group(1)
    sqlite = (root / "src/Haskoki/Runtime/Storage/SQLite/Types.hs").read_text()
    m = re.search(r"^sqliteSchemaVersion = (\d+)$", sqlite, re.M)
    if not m:
        raise SystemExit("generate_compat: SQLite/Types.hs lacks 'sqliteSchemaVersion = N'")
    store = m.group(1)
    config = (root / "src/Haskoki/Runtime/Config.hs").read_text()
    m = re.search(r"^configSchemaVersion = (\d+)$", config, re.M)
    if not m:
        raise SystemExit("generate_compat: Config.hs lacks 'configSchemaVersion = N'")
    schema = m.group(1)
    m = re.search(r"^supportedInterfaces = \[(.*)\]$", config, re.M)
    if not m:
        raise SystemExit("generate_compat: Config.hs lacks 'supportedInterfaces = [...]'")
    ifaces = re.findall(r'"([^"]+)"', m.group(1))
    if not ifaces:
        raise SystemExit("generate_compat: supportedInterfaces list is empty")
    return {"binary": binary, "store": store, "config": schema, "interfaces": ifaces}


def verdict(store, config, iface, consts):
    served = int(consts["store"])
    if config != consts["config"] or iface not in consts["interfaces"]:
        return "refuse"
    if store == "memory" or store == str(served):
        return "works"
    try:
        n = int(store)
    except ValueError:
        return "refuse"
    if 1 <= n < served:
        return "migrate"
    return "refuse"


RULES = """\
## Rules

- `refuse` wins: any unsupported version refuses the open; no migration writes. The refusal is not side-effect-free: lock acquisition and journal-mode setup precede the schema check. On the pinned default-mode v1 fixture nothing persists (testV1RefusesWithoutWriting); a stale lock is taken over and unlinked on refusal; on WAL-mode stores whose open reaches the journal switch, the DELETE pragma persists.
- `migrate`: store schemas `1`, `2` open only via an explicit `haskoki-ctl store migrate` (verified backup and receipt). Both halves pinned: testV1RefusesWithoutWriting, testV2RefusesWithoutWriting.
- `works` means version compatibility only: no cell version refuses on version grounds. It is not an open guarantee: serving-time conditions refuse separately (tokens without credential rows (migration-required), pinned by caseOpenLegacyRefusesMigrationRequired; reordered token identities (StdStoreIdentityRefusal), pinned by caseOpenReorderRefuses).
- Interface `2.40` is reached through `C_GetFunctionList` only (`C_GetInterface` with 2.40 returns `CKR_ARGUMENTS_BAD`; pinned by the consumer_discovery native leg).
- `memory` stores carry no persisted schema; `other` means any value outside the listed sets.
"""


def render(consts):
    served = int(consts["store"])
    stores = ["memory"] + [str(i) for i in range(1, served + 1)] + ["other"]
    configs = [consts["config"], "other"]
    ifaces = list(consts["interfaces"]) + ["other"]
    lines = []
    lines.append("# Compatibility matrix")
    lines.append("")
    lines.append("Do not edit by hand: regenerate with `python3 scripts/generate_compat.py`.")
    lines.append("Every cell resolves to works, migrate, or refuse; there are no blanks.")
    lines.append("")
    lines.append("## Versions")
    lines.append("")
    lines.append("- Binary: `%s` (authority: `haskoki.cabal`; the CLI carries it, pinned by `caseVersionExact`)." % consts["binary"])
    lines.append("- Store schema served: `%s` (authority: `sqliteSchemaVersion`)." % consts["store"])
    lines.append("- Config schema accepted: `%s` (absent means default)." % consts["config"])
    lines.append("- Interfaces: %s (config allowlist, cross-checked against the ABI inventory; advertisement parity pinned by the discovery legs)." % ", ".join("`%s`" % i for i in consts["interfaces"]))
    lines.append("")
    lines.append(RULES.rstrip("\n"))
    lines.append("")
    lines.append("## Matrix")
    lines.append("")
    lines.append("| Binary | Store | Config | Interface | Verdict |")
    lines.append("| --- | --- | --- | --- | --- |")
    for s in stores:
        for c in configs:
            for i in ifaces:
                lines.append("| %s | %s | %s | %s | %s |"
                             % (consts["binary"], s, c, i, verdict(s, c, i, consts)))
    return "\n".join(lines) + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=str(REPO))
    args = ap.parse_args(argv)
    root = Path(args.root)
    consts = read_constants(root)
    doc = render(consts)
    out = root / "docs/compatibility.md"
    out.write_text(doc)
    cells = doc.count("| %s |" % consts["binary"])
    print("generate_compat: wrote %s (%d cells, binary %s, store %s, config %s)"
          % (out, cells, consts["binary"], consts["store"], consts["config"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
