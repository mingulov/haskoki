#!/usr/bin/env python3
"""History-code gate: no task/slice/milestone/phase/group codes, no
prose plan codes, no red/green/BASE TDD words, no failing-first
labels in tracked sources.

Covered patterns (case-sensitive except where noted):
  T[0-9]{2}          task codes (T00..T39) incl. compounds (T16-S4)
  t[0-9]{2}          lowercase task codes (tmpdirs, labels, locals)
  [SMFPG][0-9]       slice/milestone/finding/phase/group codes
  WP[0-9]{2}         prose work-package codes (WP04..WP14)
  Task [0-9]+        prose task references ("Task 7")
  RED/GREEN/BASE     TDD revision words (uppercase only: lowercase
                     `base` is an ordinary identifier)
  red/green          lowercase TDD verdict words
  Slice [A-Z0-9]     labeled slice headers (bare "slice" prose is fine)
  failing-first      TDD labels (case-insensitive)

Deliberate keeps (narrow allowlist below, each with its reason):
  docs/byte-formats.md F1-F9  live byte-format taxonomy (not findings)
  OpenSSLSpec KAT messages    frozen vectors; expectations were derived
                              from the external pinned CLI, so the input
                              bytes must not churn
  SyntheticSpec t06-* labels  golden-fixture KDF inputs; changing them
                              would invalidate pinned goldens
  notifications test comments execution-evidence hash lock; T-N07/T-N08
                              receipts bind these bytes by SHA-256, so
                              comment-only churn would void evidence
consumer test comment   execution-evidence hash lock; T-C09 receipts bind
                        this source SHA-256, so comment-only churn is barred

Acceptance ids (A00-A99) are stable external handles and are NOT
flagged. Lowercase s/m/f/p/g + digit locals (s1, m2) are ordinary
identifiers and are NOT flagged.

STDLIB ONLY. Run on HOST python3 from anywhere:
  python3 scripts/check-history-codes.py
  python3 scripts/check-history-codes.py --self-test
"""
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
# This checker's own pattern definitions necessarily contain the trigger
# words, so it excludes exactly itself (narrow: this one path only).
SELF = "scripts/check-history-codes.py"

PATTERNS = [
    ("TASK", re.compile(r"(?<![A-Za-z0-9_])T[0-9]{2}\b")),
    ("TASK-LOWER", re.compile(r"(?<![A-Za-z0-9_])t[0-9]{2}\b")),
    ("SLICE-GROUP", re.compile(r"(?<![A-Za-z0-9_])[SMFPG][0-9]\b")),
    ("TDD-UPPER", re.compile(r"\b(RED|GREEN|BASE)\b")),
    ("TDD-LOWER", re.compile(r"\b(red|green)\b")),
    ("SLICE-LABEL", re.compile(r"Slice [A-Z0-9]")),
    ("FAILING-FIRST", re.compile(r"failing-first", re.IGNORECASE)),
]

NEW_PATTERNS = [
    ("PLAN-WP", re.compile(r"\bWP[0-9]{2}\b")),
    ("PLAN-TASK", re.compile(r"\bTask [0-9]+\b")),
]

# Scope of the NEW prose-plan-code rule only: the findings ledger
# is the historical findings record keyed by work package (its WP
# codes are the record keys, not stray prose), so the NEW patterns
# do not apply to exactly this path. This is the new rule's scope,
# not a widening of any existing exclusion: every PATTERNS rule
# (T-codes, slice codes, TDD words) still applies to the ledger.
NEW_PATTERN_EXCLUDE = {"spec/findings-ledger.json"}

# (path suffix, compiled line allowlist, reason)
ALLOW = [
    ("docs/byte-formats.md", re.compile(r"\bF[0-9]\b"),
     "F1-F9 byte-format taxonomy"),
    ("tests/engine/OpenSSLSpec.hs",
     re.compile(r'^\w+ = "T16 S\d '),
     "frozen KAT message bytes"),
    ("tests/engine/OpenSSLSpec.hs",
     re.compile(r'T16 (curves ECDSA|S7 X9\.31 KAT)'),
     "frozen KAT message bytes (curve-labeled inputs, comment quote)"),
    ("tests/engine/SyntheticSpec.hs",
     re.compile(r'"t06-(pin|sig)'),
     "golden-fixture KDF labels"),
    ("tests/c/notifications_routed.c",
     re.compile(r"semantic-red relabel|never an expected red|cannot hang this intended red"),
     "execution-evidence hash lock (T-N08 consumers receipt binds source SHA-256)"),
    ("tests/engine/NotificationsEngineSpec.hs",
     re.compile(r"red/green probe|pre-implementation behavioral red"),
     "execution-evidence hash lock (T-N07 retained receipt binds source SHA-256)"),
    ("tests/c/consumer_certificates.c",
     re.compile(r"semantic-red relabel"),
     "execution-evidence hash lock (T-C09/CERT_BASE receipts bind source SHA-256)"),
]

EXTS = {".hs", ".c", ".h", ".py", ".sh", ".cabal", ".md", ".toml",
        ".json", ".yml", ".yaml", ".sql", ".hsc"}
ALSO = {"Dockerfile", "CHANGELOG.md", "README.md", "SUPPORTED-HOSTS.md",
        "cabal.project", "cabal.project.freeze", "toolchain.lock"}


def tracked():
    # Container-proof: checkouts mounted from the CI host are owned
    # by another uid, which git refuses (dubious ownership, exit
    # 128) unless declared safe — scope the declaration to this one
    # read-only invocation so the gate runs from anywhere.
    try:
        out = subprocess.run(
            ["git", "-c", f"safe.directory={REPO}", "ls-files"],
            cwd=REPO, capture_output=True, text=True, check=True).stdout
    except subprocess.CalledProcessError as e:
        print("history-codes: cannot list tracked files: "
              f"{(e.stderr or '').strip()[:300]}")
        sys.exit(2)
    for rel in out.splitlines():
        rel = rel.strip()
        if not rel or rel == SELF:
            continue
        p = Path(rel)
        if p.suffix in EXTS or p.name in ALSO:
            yield rel


def scan_text(rel, text):
    """Content failures for one (path, text) pair. The NEW prose
    plan-code patterns skip exactly NEW_PATTERN_EXCLUDE; every
    PATTERNS rule applies everywhere."""
    failures = []
    allows = [(rx, why) for (suf, rx, why) in ALLOW
              if rel == suf or rel.endswith("/" + suf)]
    pats = PATTERNS + ([] if rel in NEW_PATTERN_EXCLUDE else NEW_PATTERNS)
    for i, line in enumerate(text.splitlines(), 1):
        for name, pat in pats:
            m = pat.search(line)
            if not m:
                continue
            if any(rx.search(line) for rx, _ in allows):
                continue
            failures.append(
                f"{name}:{rel}:{i}: {line.strip()[:100]}")
            break
    return failures


def main(argv):
    if len(argv) == 2 and argv[1] == "--self-test":
        return self_test()
    if len(argv) != 1:
        print("usage: check-history-codes.py [--self-test]")
        return 2
    failures = []
    # 1. filenames must not carry codes either.
    for rel in tracked():
        low = rel.lower()
        if re.search(r"t[0-9]{2}", low):
            failures.append(f"PATH:{rel}: task code in filename")
    # 2. content sweep with narrow per-file allowlists.
    for rel in tracked():
        text = (REPO / rel).read_text(errors="replace")
        failures.extend(scan_text(rel, text))
    if failures:
        print("history-codes: FAIL:")
        for f in failures[:20]:
            print(f"  [{f}]")
        if len(failures) > 20:
            print(f"  ... and {len(failures) - 20} more")
        return 1
    print("history-codes: OK (no task/slice/TDD codes in tracked sources)")
    return 0


def self_test():
    """Positive controls (each NEW pattern fires) and precision
    controls (near-misses stay clean; the ledger keeps the old
    rules but skips the new ones)."""
    failures = []

    def check_rule(rule, cond, detail):
        print(f"{'ok' if cond else 'FAIL'}: self: {rule}: {detail}")
        if not cond:
            failures.append(rule)

    wp = scan_text("docs/note.md", "measured in the WP12 review\n")
    check_rule("wp-fires", any(f.startswith("PLAN-WP:") for f in wp),
               "a prose WP code is rejected")
    task = scan_text("docs/note.md", "see Task 7 for the bundle\n")
    check_rule("task-fires", any(f.startswith("PLAN-TASK:") for f in task),
               "a prose Task reference is rejected")
    near = scan_text("docs/note.md", "task 7 assigned\nWP1 draft\nWPA review\n")
    check_rule("near-miss-clean", not near,
               "lowercase task, short WP1 and WP letters stay clean")
    ledger_new = scan_text("spec/findings-ledger.json",
                           '"target": "WP12 proxy pin (Task 7)"\n')
    check_rule("ledger-skips-new", not ledger_new,
               "the ledger keeps its historical WP keys")
    ledger_old = scan_text("spec/findings-ledger.json", "see T16\n")
    check_rule("ledger-keeps-old",
               any(f.startswith("TASK:") for f in ledger_old),
               "the T-code rule still applies to the ledger")

    if failures:
        print(f"self-test: FAIL ({', '.join(failures)})")
        return 1
    print("self-test: OK (prose plan-code controls behave)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
