#!/usr/bin/env python3
"""Compatibility-matrix gate: the checked-in doc must agree with the
tree's version constants and resolve every cell.

Asserts on docs/compatibility.md:
  - the Versions bullets equal the textual constants (binary from
    haskoki.cabal, store schema from sqliteSchemaVersion, config
    schema + interfaces from configSchemaVersion/supportedInterfaces)
  - the table covers binary x store x config x interface exactly once
    (no missing combo, no extra row, no blank)
  - every verdict is works/migrate/refuse AND equals the recomputed
    rule (refuse wins: unknown config/interface refuses; store 1..N-1
    migrates; memory + served works; anything else refuses)
  - the doc is byte-identical to a fresh generator run (the gate runs
    scripts/generate_compat.py against copies in a temp dir, so the
    check itself never modifies the tree)
  - the interface chain closes twice: the ABI inventory keys must
    equal the generator-defined set (executed from a temp copy with
    bytecode writes disabled — exact runtime value, so aliasing and
    mutation resolve as the generator sees them — and a hand-added
    key fails), and the config allowlist must equal the inventory
    keys. The matrix then certifies exactly the
    defined set — neither an interface native discovery rejects
    nor omitting a served one. Native service itself is pinned
    behaviorally by the consumer_discovery legs (exact 3.2/3.1/3.0
    inventory + 2.40-via-C_GetFunctionList).

STDLIB ONLY. Run from anywhere:
  python3 scripts/check-compat.py [--self-test]
"""
import argparse
import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
GENERATOR = REPO / "scripts" / "generate_compat.py"

RULE_VERDICTS = ("works", "migrate", "refuse")


def read_constants(root):
    """Read the four version constants textually. Returns
    (consts, errors): consts is None when any read fails closed."""
    errors = []
    consts = {}
    try:
        cabal = (root / "haskoki.cabal").read_text()
    except (OSError, ValueError) as exc:
        return None, ["cannot read haskoki.cabal: %s" % exc]
    m = re.search(r"^version:\s+(\d+\.\d+\.\d+\.\d+)\s*$", cabal, re.M)
    if not m:
        errors.append("haskoki.cabal carries no X.Y.Z.W version line")
    else:
        consts["binary"] = m.group(1)
    try:
        sqlite = (root / "src/Haskoki/Runtime/Storage/SQLite/Types.hs").read_text()
    except (OSError, ValueError) as exc:
        return None, ["cannot read Storage/SQLite/Types.hs: %s" % exc]
    m = re.search(r"^sqliteSchemaVersion = (\d+)$", sqlite, re.M)
    if not m:
        errors.append("SQLite/Types.hs lacks a one-line 'sqliteSchemaVersion = N'")
    else:
        consts["store"] = m.group(1)
    try:
        config = (root / "src/Haskoki/Runtime/Config.hs").read_text()
    except (OSError, ValueError) as exc:
        return None, ["cannot read Runtime/Config.hs: %s" % exc]
    m = re.search(r"^configSchemaVersion = (\d+)$", config, re.M)
    if not m:
        errors.append("Config.hs lacks a one-line 'configSchemaVersion = N'")
    else:
        consts["config"] = m.group(1)
    m = re.search(r"^supportedInterfaces = \[(.*)\]$", config, re.M)
    if not m:
        errors.append("Config.hs lacks a one-line 'supportedInterfaces = [...]'")
    else:
        ifaces = re.findall(r'"([^"]+)"', m.group(1))
        if not ifaces:
            errors.append("supportedInterfaces list is empty")
        else:
            consts["interfaces"] = ifaces
    if errors:
        return None, errors
    return consts, []


def rule_verdict(store, config, iface, consts):
    """Recompute one cell: refuse wins, then migrate, then works."""
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


def expected_combos(consts):
    served = int(consts["store"])
    stores = ["memory"] + [str(i) for i in range(1, served + 1)] + ["other"]
    configs = [consts["config"], "other"]
    ifaces = list(consts["interfaces"]) + ["other"]
    return [(consts["binary"], s, c, i)
            for s in stores for c in configs for i in ifaces]


def parse_table(doc):
    """Return table rows; each is [binary, store, config, iface, verdict]."""
    rows = []
    for line in doc.splitlines():
        s = line.strip()
        if not s.startswith("|"):
            continue
        cells = [c.strip() for c in s.strip("|").split("|")]
        if len(cells) != 5:
            continue
        if cells[0] == "Binary" or set(cells[0]) == {"-"}:
            continue
        rows.append(cells)
    return rows


def check_versions(doc, consts):
    errors = []
    needles = [
        ("Binary: `%s`" % consts["binary"], "binary"),
        ("Store schema served: `%s`" % consts["store"], "store schema"),
        ("Config schema accepted: `%s`" % consts["config"], "config schema"),
    ]
    for needle, what in needles:
        if needle not in doc:
            errors.append("Versions bullet disagrees on %s (want %r)" % (what, needle))
    m = re.search(r"^- Interfaces: (.*)$", doc, re.M)
    if not m:
        errors.append("Versions lack an Interfaces bullet")
    else:
        for i in consts["interfaces"]:
            if ("`%s`" % i) not in m.group(1):
                errors.append("Interfaces bullet omits `%s`" % i)
    if "Do not edit by hand: regenerate with `python3 scripts/generate_compat.py`" not in doc:
        errors.append("doc lacks the generated-file header")
    return errors


def check_table(doc, consts):
    errors = []
    rows = parse_table(doc)
    if not rows:
        return ["matrix table has no data rows"]
    want = expected_combos(consts)
    have = [(b, s, c, i) for [b, s, c, i, _] in rows]
    if sorted(have) != sorted(want):
        missing = sorted(set(want) - set(have))
        extra = sorted(set(have) - set(want))
        if missing:
            errors.append("matrix misses %d combo(s), first: %s" % (len(missing), missing[0]))
        if extra:
            errors.append("matrix has %d extra row(s), first: %s" % (len(extra), extra[0]))
    if len(have) != len(set(have)):
        errors.append("matrix has duplicated combos")
    for row in rows:
        b, s, c, i, v = row
        if v not in RULE_VERDICTS:
            errors.append("cell %s has no verdict (blank %r)" % ([b, s, c, i], v))
        elif v != rule_verdict(s, c, i, consts):
            errors.append("cell %s says %s, rule says %s"
                          % ([b, s, c, i], v, rule_verdict(s, c, i, consts)))
    return errors


def check_idempotent(root):
    """Regenerate into a temp copy and byte-compare. Read-only on root."""
    if not GENERATOR.is_file():
        return ["generator missing: scripts/generate_compat.py does not exist"]
    doc_path = root / "docs/compatibility.md"
    try:
        before = doc_path.read_bytes()
    except OSError as exc:
        return ["cannot read docs/compatibility.md: %s" % exc]
    with tempfile.TemporaryDirectory(prefix="compat-gate-") as tmp:
        tmp = Path(tmp)
        for rel in ("haskoki.cabal", "src/Haskoki/Runtime/Storage/SQLite/Types.hs",
                    "src/Haskoki/Runtime/Config.hs", "docs/compatibility.md"):
            dst = tmp / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            try:
                shutil.copyfile(root / rel, dst)
            except OSError as exc:
                return ["cannot stage %s: %s" % (rel, exc)]
        try:
            p = subprocess.run([sys.executable, str(GENERATOR), "--root", str(tmp)],
                               capture_output=True, text=True, timeout=120)
        except (OSError, subprocess.TimeoutExpired) as exc:
            return ["generator run failed: %s" % exc]
        if p.returncode != 0:
            return ["generator exits %d: %s" % (p.returncode, (p.stderr or "").strip()[:300])]
        try:
            after = (tmp / "docs/compatibility.md").read_bytes()
        except OSError as exc:
            return ["generator wrote no doc: %s" % exc]
    if after != before:
        return ["doc differs from a fresh generator run (regenerate and commit)"]
    return []


def generator_defined_interfaces(gen_path):
    """LAYOUTS keys from executing a temp copy of the generator.

    Executes (not parses) so aliasing, mutation, and conditional
    definition resolve exactly as at runtime — there is no
    static/dynamic gap left to exploit. Bytecode-clean: the copy
    lives in a fresh temp dir (no cache to go stale) and imports
    run with bytecode writes disabled, so the tree gains no
    __pycache__ entries. Returns None (fail closed) on any
    failure, a missing/non-dict/non-string LAYOUTS included.
    """
    import importlib.util
    try:
        source = Path(gen_path).read_bytes()
    except OSError:
        return None
    with tempfile.TemporaryDirectory(prefix="compat-gen-") as tmp:
        copy = Path(tmp) / "generate_abi_copy.py"
        try:
            copy.write_bytes(source)
        except OSError:
            return None
        saved = sys.dont_write_bytecode
        sys.dont_write_bytecode = True
        try:
            spec = importlib.util.spec_from_file_location(
                "compat_gen_abi", copy)
            gen = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(gen)
        except Exception:
            return None
        finally:
            sys.dont_write_bytecode = saved
    layouts = getattr(gen, "LAYOUTS", None)
    if not isinstance(layouts, dict) or not layouts:
        return None
    if not all(isinstance(k, str) and isinstance(v, str)
               for k, v in layouts.items()):
        return None
    return sorted(layouts.keys())


def check_native_interfaces(root, consts):
    """Two links: inventory keys must equal the generator-defined
    set (a hand-added key fails even when the allowlist matches
    it), and the allowlist must equal the inventory keys."""
    inv_path = root / "spec/abi-inventory.json"
    try:
        inv = json.loads(inv_path.read_text())
    except (OSError, ValueError) as exc:
        return ["cannot read ABI inventory %s: %s" % (inv_path, exc)]
    native = sorted(inv.get("interfaces", {}).keys())
    if not native:
        return ["ABI inventory lists no interfaces"]
    defined = generator_defined_interfaces(REPO / "scripts" / "generate-abi.py")
    if defined is None:
        return ["cannot import generate-abi.py for the interface set"]
    if native != defined:
        return ["ABI inventory keys %s != generator-defined %s: "
                "hand-added interface keys are not served"
                % (native, defined)]
    allowed = sorted(consts["interfaces"])
    if allowed != native:
        return ["config allowlist %s != ABI inventory %s: the matrix "
                "must certify exactly what native discovery serves"
                % (allowed, native)]
    return []


def check(root):
    consts, errors = read_constants(root)
    if errors:
        return errors
    errors = check_native_interfaces(root, consts)
    doc_path = root / "docs/compatibility.md"
    try:
        doc = doc_path.read_text()
    except OSError:
        return errors + ["docs/compatibility.md is missing (run scripts/generate_compat.py)"]
    except ValueError as exc:
        return errors + ["docs/compatibility.md is not valid UTF-8: %s" % exc]
    errors += check_versions(doc, consts)
    errors += check_table(doc, consts)
    return errors


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args(argv)
    if args.self_test:
        return self_test()
    errors = check(REPO)
    errors += check_idempotent(REPO)
    if errors:
        print("compat: FAIL:")
        for e in errors[:10]:
            print("  - %s" % e)
        return 1
    print("compat: OK (versions agree, all cells resolve, regen byte-identical)")
    return 0


# ---------------------------------------------------------------------------
# Self-test: fixture trees exercising every leg.
# ---------------------------------------------------------------------------

FIX_CABAL = "cabal-version: 3.0\nname: haskoki\nversion:            0.6.0.0\n"
FIX_SQLITE = "-- fixture\nsqliteSchemaVersion :: Int\nsqliteSchemaVersion = 3\n"
FIX_CONFIG = ("-- fixture\nconfigSchemaVersion :: Int\nconfigSchemaVersion = 1\n\n"
              "supportedInterfaces :: [String]\n"
              "supportedInterfaces = [\"2.40\", \"3.0\", \"3.1\", \"3.2\"]\n")
FIX_ABI = ('{"interfaces": {"2.40": {}, "3.0": {}, "3.1": {}, '
           '"3.2": {}}}')


def write_fixture(tmp, cabal=FIX_CABAL, sqlite=FIX_SQLITE, config=FIX_CONFIG,
                  abi=FIX_ABI, doc=None):
    tmp = Path(tmp)
    tmp.mkdir(parents=True, exist_ok=True)
    (tmp / "haskoki.cabal").write_text(cabal)
    (tmp / "src/Haskoki/Runtime/Storage/SQLite").mkdir(parents=True, exist_ok=True)
    (tmp / "src/Haskoki/Runtime/Storage/SQLite/Types.hs").write_text(sqlite)
    (tmp / "src/Haskoki/Runtime/Config.hs").write_text(config)
    (tmp / "spec").mkdir(parents=True, exist_ok=True)
    (tmp / "spec/abi-inventory.json").write_text(abi)
    (tmp / "docs").mkdir(parents=True, exist_ok=True)
    if doc is not None:
        (tmp / "docs/compatibility.md").write_text(doc)
    return tmp


def self_test():
    bad = []

    def expect(name, errors, want_fail):
        failed = len(errors) > 0
        ok = failed == want_fail
        print("%s %s%s" % ("ok  " if ok else "FAIL", name,
                            "" if ok else (" -> " + "; ".join(errors))))
        if not ok:
            bad.append(name)

    with tempfile.TemporaryDirectory(prefix="compat-self-") as tmp:
        # Leg 1: a generated doc passes (needs the real generator).
        if GENERATOR.is_file():
            root = write_fixture(Path(tmp) / "good")
            p = subprocess.run([sys.executable, str(GENERATOR), "--root", str(root)],
                               capture_output=True, text=True, timeout=120)
            if p.returncode != 0:
                expect("generated doc passes", ["generator failed: %s" % p.stderr[:200]], False)
            else:
                expect("generated doc passes", check(root), False)
                expect("generated doc is idempotent", check_idempotent(root), False)
        else:
            expect("generated doc passes", ["generator missing (not yet written)"], False)
        # Leg 2: drifted binary constant fails.
        root = write_fixture(Path(tmp) / "drift", doc=(
            "# Compatibility matrix\n\nDo not edit by hand: regenerate with "
            "`python3 scripts/generate_compat.py`.\n\n## Versions\n\n"
            "- Binary: `9.9.9.9` (x)\n- Store schema served: `3` (x)\n"
            "- Config schema accepted: `1` (x)\n- Interfaces: `2.40`, `3.0`, `3.1`, `3.2` (x)\n"))
        expect("drifted binary fails", check(root), True)
        # Leg 3: blank verdict fails.
        root = write_fixture(Path(tmp) / "blank", doc=(
            "# Compatibility matrix\n\nDo not edit by hand: regenerate with "
            "`python3 scripts/generate_compat.py`.\n\n## Versions\n\n"
            "- Binary: `0.6.0.0` (x)\n- Store schema served: `3` (x)\n"
            "- Config schema accepted: `1` (x)\n- Interfaces: `2.40`, `3.0`, `3.1`, `3.2` (x)\n\n"
            "## Matrix\n\n| Binary | Store | Config | Interface | Verdict |\n"
            "| --- | --- | --- | --- | --- |\n"
            "| 0.6.0.0 | memory | 1 | 2.40 |  |\n"))
        expect("blank verdict fails", check(root), True)
        # Leg 4: missing doc fails.
        root = write_fixture(Path(tmp) / "nodoc")
        expect("missing doc fails", check(root), True)
        # Leg 5: wrong verdict fails (works where the rule says migrate).
        root = write_fixture(Path(tmp) / "wrong", doc=(
            "# Compatibility matrix\n\nDo not edit by hand: regenerate with "
            "`python3 scripts/generate_compat.py`.\n\n## Versions\n\n"
            "- Binary: `0.6.0.0` (x)\n- Store schema served: `3` (x)\n"
            "- Config schema accepted: `1` (x)\n- Interfaces: `2.40`, `3.0`, `3.1`, `3.2` (x)\n\n"
            "## Matrix\n\n| Binary | Store | Config | Interface | Verdict |\n"
            "| --- | --- | --- | --- | --- |\n"
            "| 0.6.0.0 | 1 | 1 | 2.40 | works |\n"))
        expect("wrong verdict fails", check(root), True)
        # Leg 6: missing constant line fails closed (no traceback).
        root = write_fixture(Path(tmp) / "noconst",
                             config="-- fixture\n-- no schema line here\n", doc="x\n")
        expect("missing constant fails closed", check(root), True)
        # Leg 7: dropped combo fails (totality).
        root = write_fixture(Path(tmp) / "drop", doc=(
            "# Compatibility matrix\n\nDo not edit by hand: regenerate with "
            "`python3 scripts/generate_compat.py`.\n\n## Versions\n\n"
            "- Binary: `0.6.0.0` (x)\n- Store schema served: `3` (x)\n"
            "- Config schema accepted: `1` (x)\n- Interfaces: `2.40`, `3.0`, `3.1`, `3.2` (x)\n\n"
            "## Matrix\n\n| Binary | Store | Config | Interface | Verdict |\n"
            "| --- | --- | --- | --- | --- |\n"
            "| 0.6.0.0 | memory | 1 | 2.40 | works |\n"))
        expect("dropped combo fails", check(root), True)
        # Legs 8-9: the doc is generated from the drifted
        # allowlist, so versions/table/idempotency all pass and ONLY
        # the native cross-check can fail each leg.
        for name, spelling in (("wide", '["2.40", "3.0", "3.1", "3.2", "3.3"]'),
                               ("narrow", '["2.40", "3.0", "3.1"]')):
            root = write_fixture(
                Path(tmp) / name,
                config=FIX_CONFIG.replace('["2.40", "3.0", "3.1", "3.2"]',
                                          spelling))
            if GENERATOR.is_file():
                p = subprocess.run(
                    [sys.executable, str(GENERATOR), "--root", str(root)],
                    capture_output=True, text=True, timeout=120)
                if p.returncode != 0:
                    expect("%s allowlist fails" % name,
                           ["generator failed: %s" % p.stderr[:200]], True)
                else:
                    errs = check(root)
                    isolated = [e for e in errs if "ABI inventory" in e]
                    expect("%s allowlist fails on inventory" % name,
                           isolated, True)
            else:
                expect("%s allowlist fails" % name,
                       ["generator missing (not yet written)"], True)
        # Leg 10: coordinated drift fails (the r36 repro):
        # allowlist AND inventory both gain 3.3, so the pairwise
        # check passes and only the generator-defined set catches it.
        root = write_fixture(
            Path(tmp) / "extrakey",
            config=FIX_CONFIG.replace(
                '["2.40", "3.0", "3.1", "3.2"]',
                '["2.40", "3.0", "3.1", "3.2", "3.3"]'),
            abi=('{"interfaces": {"2.40": {}, "3.0": {}, "3.1": {}, '
                 '"3.2": {}, "3.3": {}}}'))
        if GENERATOR.is_file():
            p = subprocess.run(
                [sys.executable, str(GENERATOR), "--root", str(root)],
                capture_output=True, text=True, timeout=120)
            if p.returncode != 0:
                expect("extra inventory key fails",
                       ["generator failed: %s" % p.stderr[:200]], True)
            else:
                errs = check(root)
                isolated = [e for e in errs if "ABI inventory" in e]
                expect("extra inventory key fails on inventory",
                       isolated, True)
        else:
            expect("extra inventory key fails",
                   ["generator missing (not yet written)"], True)
        # Legs 11-15: the generator-defined set comes from executing
        # a temp copy (exact runtime value; the r42 alias endgame).
        def gen_root(name, gen_source):
            d = Path(tmp) / name
            d.mkdir(parents=True, exist_ok=True)
            (d / "generate-abi.py").write_text(gen_source)
            return d / "generate-abi.py"
        plain = gen_root("gen-plain",
                         'LAYOUTS = {"2.40": "A", "3.0": "B"}\n')
        expect("defined set reads the runtime value",
               [] if generator_defined_interfaces(plain) == ["2.40", "3.0"]
               else ["misread"], False)
        aliased = gen_root("gen-alias",
                           'LAYOUTS = {"3.2": "A", "3.3": "B"}\n'
                           'layouts = LAYOUTS\n'
                           'del layouts["3.3"]\n')
        expect("defined set resolves aliasing",
               [] if generator_defined_interfaces(aliased) == ["3.2"]
               else ["misread"], False)
        broken = gen_root("gen-broken", "LAYOUTS = {\n")
        expect("defined set fails closed on syntax error",
               [] if generator_defined_interfaces(broken) is None
               else ["should be None"], False)
        expect("defined set fails closed on missing file",
               [] if generator_defined_interfaces(
                   Path(tmp) / "gen-absent" / "generate-abi.py") is None
               else ["should be None"], False)
        nonstr = gen_root("gen-nonstr", 'LAYOUTS = {"3.2": 5}\n')
        expect("defined set fails closed on non-string layout",
               [] if generator_defined_interfaces(nonstr) is None
               else ["should be None"], False)

    print("compat: self-test %s" % ("ok" if not bad else "FAIL"))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
