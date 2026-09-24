#!/usr/bin/env python3
"""Core-boundary checker: check core/ imports no native/SQLite/runtime modules.

A textual denylist, not a proof of purity:
it matches import lines against banned-module patterns.

Fails (exit 1) if any module under core/ imports Foreign.*, System.IO,
concurrency/STM, SQLite-ish, GHC runtime, or engine/FFI modules, or
declares foreign imports. Pure data libraries (base, bytestring,
containers, text) are allowed. (IO-mentioning stubs are retired, so
no core signature mentions IO at all anymore.)

Unsafe policy: unsafe operations are banned in core/ both by
import (Unsafe.Coerce, Debug.Trace, System.Mem, IORefs) and by use:
the unsafe*IO/unsafeCoerce/trace identifiers below fail validation
even if smuggled past the import denylist. The scan strips line and
block comments, so documenting the policy does not trip it.
"""
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
CORE = REPO / "core"
RUNTIME_LIFECYCLE = REPO / "src/Haskoki/Runtime/Lifecycle.hs"

BANNED = [
    r"^import\s+(?:qualified\s+)?Foreign\b",
    r"^import\s+(?:qualified\s+)?System\.IO\b",
    r"^import\s+(?:qualified\s+)?System\.IO\.Unsafe\b",
    r"^import\s+(?:qualified\s+)?Control\.Concurrent",
    r"^import\s+(?:qualified\s+)?Control\.Monad\.STM\b",
    r"^import\s+(?:qualified\s+)?GHC\.",
    r"^import\s+(?:qualified\s+)?Database\.",
    r"^import\s+(?:qualified\s+)?Haskoki\.Engine\b",
    r"^import\s+(?:qualified\s+)?Haskoki\.FFI\b",
    r"^import\s+(?:qualified\s+)?Haskoki\.Runtime\b",
    r"^import\s+(?:qualified\s+)?Haskoki\.Storage\b",
    # Unsafe-operation modules (import half of the policy).
    r"^import\s+(?:qualified\s+)?Unsafe\.Coerce\b",
    r"^import\s+(?:qualified\s+)?Debug\.Trace",
    r"^import\s+(?:qualified\s+)?System\.Mem\b",
    r"^import\s+(?:qualified\s+)?Data\.IORef\b",
    r"^import\s+(?:qualified\s+)?System\.IORef\b",
    r"^foreign\s+import\b",
    r"\{-#\s*LANGUAGE[^\-]*\bForeignFunctionInterface\b",
]

BANNED_RE = [re.compile(p) for p in BANNED]

# Unsafe-identifier uses (use half of the policy). Matched
# against comment-stripped code so docs never trip it.
UNSAFE_USE = [
    r"\bunsafePerformIO\b",
    r"\bunsafeDupablePerformIO\b",
    r"\bunsafeInterleaveIO\b",
    r"\bunsafeFixIO\b",
    r"\bunsafeCoerce\b",
    r"\bnoDuplicate\b",
    r"\btrace(Id|ShowId|ShowM|Show|M|IO|EventIO|Event|MarkerIO|Marker|Stack)?\b",
    r"\bputTraceMsg\b",
    r"\bperformGC\b",
    r"\bperformIO\b",
]

UNSAFE_USE_RE = [re.compile(p) for p in UNSAFE_USE]


def strip_comments(lines):
    """Yield (lineno, code) with line/block comments removed."""
    in_block = False
    for lineno, line in enumerate(lines, start=1):
        code = line
        if in_block:
            if "-}" in code:
                code = code.split("-}", 1)[1]
                in_block = False
            else:
                continue
        while "{-" in code:
            before, rest = code.split("{-", 1)
            if "-}" in rest:
                code = before + rest.split("-}", 1)[1]
            else:
                code = before
                in_block = True
        yield (lineno, code.split("--", 1)[0])


def main() -> int:
    files = sorted(CORE.rglob("*.hs"))
    if not files:
        print("core-boundary: no Haskell files under core/", file=sys.stderr)
        return 1
    failures = []
    for path in files:
        raw = path.read_text().splitlines()
        for lineno, line in enumerate(raw, start=1):
            stripped = line.strip()
            for rx in BANNED_RE:
                if rx.match(stripped):
                    failures.append(f"{path.relative_to(REPO)}:{lineno}: {stripped}")
        for lineno, code in strip_comments(raw):
            for rx in UNSAFE_USE_RE:
                if rx.search(code):
                    failures.append(
                        f"{path.relative_to(REPO)}:{lineno}: {code.strip()}")
    if failures:
        print("core-boundary: BANNED imports/uses in pure core:", file=sys.stderr)
        for f in failures:
            print(f"  {f}", file=sys.stderr)
        return 1
    print(f"core-boundary: OK ({len(files)} files clean)")
    return check_stm_hygiene()


# STM transactions coordinate TVar state only. No crypto, SQLite,
# pointer, callback, or logging IO may appear inside `atomically`
# blocks in the lifecycle runtime. Line-based: a block starts at a
# line mentioning `atomically` and continues while lines stay more
# indented than it (comments stripped before matching).
STM_BANNED = [
    r"\bhook(Create|Destroy|Lock|Unlock)\b",
    r"\b(create|destroy)Counted\b",
    r"\bwithAdapterLock\b",
    r"\b(putStr|print|hPutStr|hPrint)\b",
    r"\bunsafe(Perform|Interleave)IO\b",
    r"\b(sqlite|SQLite|Database\.|cryptonite|Crypto\.|Ptr|Foreign\.|alloca|peek|poke)\b",
    r"\b(IORef|MVar|readFile|writeFile|appendFile)\b",
]

STM_BANNED_RE = [re.compile(p) for p in STM_BANNED]


def atomically_blocks(lines):
    """Yield (start_lineno, [(lineno, code)]) for each atomically block.

    Haddock block comments, -- comments, and bare import-list mentions
    never start blocks. The start line's own code is included in the
    yielded block so same-line violations are scannable.
    """
    i, n = 0, len(lines)
    in_block_comment = False
    while i < n:
        line = lines[i]
        if "{-" in line:
            in_block_comment = True
        if "-}" in line:
            in_block_comment = False
            i += 1
            continue
        if in_block_comment:
            i += 1
            continue
        code = line.split("--", 1)[0]
        # A call site runs code after `atomically`; a bare import-list
        # mention (`  , atomically`) starts no block.
        if line.strip().startswith("--") or not re.search(r"\batomically\s+\S", code):
            i += 1
            continue
        else:
            base = len(line) - len(line.lstrip(" "))
            # The start line itself is scanned too: a same-line
            # violation (e.g. atomically (… >> hookLock …)) must not
            # evade detection.
            block = [(i + 1, code)]
            j = i + 1
            while j < n:
                nxt = lines[j]
                if nxt.strip() == "":
                    j += 1
                    continue
                indent = len(nxt) - len(nxt.lstrip(" "))
                if indent <= base:
                    break
                block.append((j + 1, nxt.split("--", 1)[0]))
                j += 1
            yield (i + 1, block)
            i = j


def stm_self_test() -> int:
    """Regression probes for the hygiene scanner itself.

    Same-line violations must be caught; haddock/line comments and
    bare import-list mentions must not start blocks.
    """
    same_line = ["  x <- atomically (readTVar v >>= hookLock)"]
    blocks = list(atomically_blocks(same_line))
    if [s for s, _ in blocks] != [1]:
        print("stm-hygiene self-test: same-line block missed", file=sys.stderr)
        return 1
    hits = [
        lineno
        for _, block in blocks
        for lineno, code in block
        for rx in STM_BANNED_RE
        if rx.search(code)
    ]
    if hits != [1]:
        print("stm-hygiene self-test: same-line violation missed", file=sys.stderr)
        return 1

    noise = [
        "{- | mention atomically here",
        "more",
        "-}",
        "-- atomically in a comment",
        "  , atomically",
        "  x <- atomically $ do",
        "    m <- readTVar v",
    ]
    if [s for s, _ in atomically_blocks(noise)] != [6]:
        print("stm-hygiene self-test: comment/import skip broken", file=sys.stderr)
        return 1
    print("stm-hygiene self-test: OK (same-line + skip probes)")
    return 0


def check_stm_hygiene() -> int:
    if stm_self_test() != 0:
        return 1
    if not RUNTIME_LIFECYCLE.exists():
        print("stm-hygiene: no lifecycle runtime yet, skipping")
        return 0
    lines = RUNTIME_LIFECYCLE.read_text().splitlines()
    blocks = list(atomically_blocks(lines))
    if not blocks:
        print("stm-hygiene: no atomically blocks found", file=sys.stderr)
        return 1
    failures = []
    for start, block in blocks:
        for lineno, code in block:
            for rx in STM_BANNED_RE:
                if rx.search(code):
                    failures.append(
                        f"{RUNTIME_LIFECYCLE.relative_to(REPO)}:{lineno}: "
                        f"{code.strip()} (block at {start})"
                    )
    if failures:
        print("stm-hygiene: BANNED effect inside atomically:", file=sys.stderr)
        for f in failures:
            print(f"  {f}", file=sys.stderr)
        return 1
    print(f"stm-hygiene: OK ({len(blocks)} atomically blocks clean)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
