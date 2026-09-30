#!/usr/bin/env python3
"""History-code gate: no task/slice/milestone/phase/group codes, no
red/green/BASE TDD words, no failing-first labels in tracked sources.

Covered patterns (case-sensitive except where noted):
  T[0-9]{2}          task codes (T00..T39) incl. compounds (T16-S4)
  t[0-9]{2}          lowercase task codes (tmpdirs, labels, locals)
  [SMFPG][0-9]       slice/milestone/finding/phase/group codes
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

Acceptance ids (A00-A99) are stable external handles and are NOT
flagged. Lowercase s/m/f/p/g + digit locals (s1, m2) are ordinary
identifiers and are NOT flagged.

STDLIB ONLY. Run on HOST python3 from anywhere:
  python3 scripts/check-history-codes.py
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
    ("docs/superpowers/plans/2026-09-25-aes-cfb-ofb-slice.md",
     re.compile(r'Slice 4 plan|TDD RED first'),
     "frozen 2026-09-25 process record (title + test-order note)"),
    ("docs/superpowers/plans/2026-09-25-ec-curves-slice.md",
     re.compile(r't06-\* goldens|no red/green verdict words'),
     "frozen 2026-09-25 process record (fixture refs + wording note)"),
    ("docs/superpowers/plans/2026-09-26-dsa-slice.md",
     re.compile(r'CKA_PRIME/SUBPRIME/BASE'),
     "frozen 2026-09-26 process record (attribute-name quote)"),
    ("docs/superpowers/plans/2026-09-26-pqc-slice.md",
     re.compile(r'Slice 9 plan|KATs green|TDD RED first'),
     "frozen 2026-09-26 process record (title + status + test-order note)"),
]

EXTS = {".hs", ".c", ".h", ".py", ".sh", ".cabal", ".md", ".toml",
        ".json", ".yml", ".yaml", ".sql", ".hsc"}
ALSO = {"Dockerfile", "CHANGELOG.md", "README.md", "SUPPORTED-HOSTS.md",
        "cabal.project", "cabal.project.freeze", "toolchain.lock"}


def tracked():
    out = subprocess.run(["git", "ls-files"], cwd=REPO, capture_output=True,
                         text=True, check=True).stdout
    for rel in out.splitlines():
        rel = rel.strip()
        if not rel or rel == SELF:
            continue
        p = Path(rel)
        if p.suffix in EXTS or p.name in ALSO:
            yield rel


def main():
    failures = []
    # 1. filenames must not carry codes either.
    for rel in tracked():
        low = rel.lower()
        if re.search(r"t[0-9]{2}", low):
            failures.append(f"PATH:{rel}: task code in filename")
    # 2. content sweep with narrow per-file allowlists.
    for rel in tracked():
        text = (REPO / rel).read_text(errors="replace")
        allows = [(rx, why) for (suf, rx, why) in ALLOW
                  if rel == suf or rel.endswith("/" + suf)]
        for i, line in enumerate(text.splitlines(), 1):
            for name, pat in PATTERNS:
                m = pat.search(line)
                if not m:
                    continue
                if any(rx.search(line) for rx, _ in allows):
                    continue
                failures.append(
                    f"{name}:{rel}:{i}: {line.strip()[:100]}")
                break
    if failures:
        print("history-codes: FAIL:")
        for f in failures[:20]:
            print(f"  [{f}]")
        if len(failures) > 20:
            print(f"  ... and {len(failures) - 20} more")
        return 1
    print("history-codes: OK (no task/slice/TDD codes in tracked sources)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
