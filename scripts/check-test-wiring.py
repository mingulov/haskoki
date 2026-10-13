#!/usr/bin/env python3
"""Test-wiring gate: no suite silently drops a spec module.

Fails (exit 1) when any rule fails. For every `test-suite` stanza
in haskoki.cabal, every `other-modules` spec module (`*Spec`,
`*Props`) must be BOTH imported AND run as a tree entry by that
suite's Main: a spec removed from Main but left in `other-modules`
compiles while its tests silently stop running, and this gate is
what fails loudly instead. Helper modules (e.g. `EnvLock`, `Gen`)
must exist as files under the suite's `hs-source-dirs`; every spec
module must exist too.

Matching is lexical, not textual: the runner source is stripped of
comments and string/char literals before matching, so a commented
invocation (`-- Mod.spec`), a string mention (`"Mod.spec"`), or a
commented import never satisfies the gate. A tree entry must sit
inside a list literal (square-bracket depth >= 1) within the
runner's executed tree — `main`'s equation plus the top-level
bindings it names, transitively, minus every `let`/`where`
region — so an unused top-level binding (`unused = Mod.spec`),
an unreferenced top-level list, or an unused local list
(`let _u = [Mod.spec] in ...`) never satisfies the run leg,
while genuine indirection (`main = defaultMain spec`) still
does. Top-level equations must start at column 0; anything
indented merges into the preceding span by design. Positions are
reported by line.

Suite membership is pinned in tests/suite-inventory.json, the
reviewed executable-suite manifest: the cabal suite set must equal
the inventoried set, and each suite's cabal module set must equal
its pinned set, so a module removed from BOTH the runner and Cabal
fails here (removal is reviewed in the manifest, never silent).
Each runner carries one `-- REGISTRATION: <suite>` marker naming
its owning suite; each suite's required tasty groups must appear
as string literals in its Main; each `executed_by` lane must name
a real workflow job whose steps run the suite (a commented-out
`cabal test` line never satisfies the lane leg). Each module's
top-level tasty names are pinned per suite (`module_groups`) and
must equal the shallowest test-name literals of its `spec`
equation, recomputed from source here: a renamed or removed
module battery fails at pin time, and an emptied one fails at
join time (Tasty `--list-tests` emits leaves only, so an empty
group contributes no names). Top names must be unambiguous
within a suite — distinct across modules, disjoint from the
suite groups, extending no other top by a separator, and
shadowed by no same-named nested case elsewhere — and Main
itself must carry no inline batteries besides the suite root
(the scaffold suite, which has no modules, is exempt):
everything but imports is scanned (no declaration form is
skipped), every test-name constructor needs its literal name
(a parenthesized, concatenated, bound, or computed name is
unclassified and fails), and CPP directives, Template
Haskell splices, and quasiquotes are refused outright.
The ten name-first builders of the frozen toolchain
(tasty-1.5.4's testGroup, dependentTestGroup,
sequentialTestGroup, inOrderTestGroup, and singleTest;
tasty-hunit-0.10.2's testCase, testCaseSteps, and
testCaseInfo; tasty-quickcheck-0.11.1's testProperty and
testProperties) are all constructors here, so a renamed
builder smuggles nothing. Main's executed tree must be
statically attributable: runner arguments resolve through
top-level bindings and `(++)` to literal lists whose
elements are `Mod.spec` applications, leaf constructors,
or option wrappers around the same — a bound, imported,
or computed tree reference fails closed, as does a bare
top-level name no equation continues and any rewrite
rule, compiler plugin, preprocessor flag, foreign
declaration, or explicit-brace layout. Main's imports are
pinned per suite (`allowed_imports`, with `(..)` types in
`allowed_dotdot`): unqualified imports need explicit
lists, `hiding` is refused, and every new module or name
fails here until it is reviewed into the pin.
Batteries hang directly under the suite root, and the executed
join anchors them there, so anything else at depth two would
receive — or dilute — a battery's execution credit.

This layer checks intended membership and valid runner structure;
it is not a general Haskell parser and not a proof of assertions.
Whether the suites actually ran and what their trees emitted is
joined separately by scripts/check-test-execution.py.

The "singleton modules / one construct per suite" disposition: the
phrase has no in-tree form (repo-wide grep: zero hits for
"singleton module", "one construct per suite", or any per-suite
construct claim) — there is no such spec sentence to verify. Its
closest living equivalent is this per-suite spec inventory: every
suite's module set is enumerated here from the build file and
pinned to its runner, so suite/module removals fail loudly
instead of narrowing coverage silently.

STDLIB ONLY. Run on HOST python3 from anywhere:
  python3 scripts/check-test-wiring.py [--root DIR]
        [--inventory PATH] [--self-test]
The --root/--inventory overrides exist for scratch negative
controls; --self-test runs the durable controls (commented,
string-only, unused-binding, unused-list, and unreferenced-list
invocations, coordinated removal, module-group drift and
ambiguity, and inline Main batteries must fail; the clean
fixture and genuine indirection must pass).
"""

import argparse
import io
import json
import re
import sys
import tempfile
import unicodedata
from contextlib import redirect_stdout
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
INVENTORY = REPO / "tests" / "suite-inventory.json"
CABAL = REPO / "haskoki.cabal"

failures = []


def check(rule, cond, detail):
    print(f"{'ok' if cond else 'FAIL'}: {rule}: {detail}")
    if not cond:
        failures.append(rule)


def parse_suites(text):
    """name -> {dirs: [...], modules: [...], main: ...} for test-suites.

    other-modules accepts continuation lines and same-line entries;
    stanzas with conditionals are out of scope (none in-tree).
    """
    suites = {}
    cur = None
    field = None
    for line in text.splitlines():
        m = re.match(r"test-suite\s+(\S+)\s*$", line)
        if m:
            cur = m.group(1)
            suites[cur] = {"dirs": [], "modules": [], "main": None}
            field = None
            continue
        if cur is None:
            continue
        if re.match(r"\S", line):
            cur = None  # next top-level stanza
            field = None
            continue
        m = re.match(r"\s+([\w-]+):\s*(.*?)\s*$", line)
        if m:
            field = m.group(1)
            rest = m.group(2)
            if field == "hs-source-dirs" and rest:
                suites[cur]["dirs"] = rest.split()
            elif field == "main-is" and rest:
                suites[cur]["main"] = rest
            elif field == "other-modules" and rest:
                suites[cur]["modules"].extend(rest.split())
            continue
        m = re.match(r"\s+(\S+)\s*$", line)
        if m and field == "other-modules":
            suites[cur]["modules"].append(m.group(1))
    return suites


# Haskell ASCII operator constituents for the dash-run rule (`--`
# opens a line comment unless the char after the dash run is a
# symbol char). Mirrors scripts/check-test-evidence.py SYMBOL_CHARS
# plus its Unicode symbol categories; see _is_symbol there for the
# probed rationale.
SYMBOL_CHARS = set("!#$%&*+./<=>?@\\^|-~:")
_SYMBOL_CATS = frozenset({"Sm", "Sc", "Sk", "So", "Po", "Pd", "Pc"})
_GAP_WS = " \t\n\r\v\f"


def _is_sym(ch):
    if ch in SYMBOL_CHARS:
        return True
    if ord(ch) < 128:
        return False
    return unicodedata.category(ch) in _SYMBOL_CATS


def _char_end(text, i):
    """End offset of the char literal at text[i] == "'", else None.

    A lone apostrophe (prime/tick, unterminated span) is plain code,
    never a literal: the caller rewinds and continues. Multi-char
    escapes (numeric, named, control) are consumed exactly so the
    closing quote is not mistaken for content.
    """
    n = len(text)
    j = i + 1
    if j >= n or text[j] == "\n":
        return None
    if text[j] == "\\":
        j += 1
        if j >= n:
            return None
        c = text[j]
        if c == "^":
            j += 2
        elif c.isdigit():
            while j < n and text[j].isdigit():
                j += 1
        elif c.isalpha() and ord(c) < 128:
            while j < n and text[j].isalpha() and ord(text[j]) < 128:
                j += 1
        else:
            j += 1
    else:
        j += 1
    if j < n and text[j] == "'":
        return j + 1
    return None


def strip_haskell(text):
    """(code, strings): Main-scoped lexical strip of a runner source.

    `code` keeps every newline and every quote (line numbers and
    columns stable, so positions align with the raw source) with
    comments and string/char literal contents blanked to spaces;
    `strings` collects each string literal's raw inner text.
    Handles nesting block comments (pragmas are lexically block
    comments), line comments (operator-vs-comment dash rule),
    string gaps and escapes, and char literals. An unterminated
    literal resyncs at the next newline; an unterminated block
    comment consumes to EOF (GHC would reject the file, and the
    missing tree entries then fail loudly here). Runner Mains
    are gap-free single-line sources; the executed-tree join in
    check-test-execution.py is the backstop for shapes this
    stripper cannot bound.
    """
    code = []
    strings = []
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        if ch == '"':
            start = i + 1
            j = start
            closed = False
            while j < n:
                c = text[j]
                if c == '"':
                    closed = True
                    break
                if c == "\\":
                    k = j + 1
                    while k < n and text[k] in _GAP_WS:
                        k += 1
                    if k < n and text[k] == "\\":
                        j = k + 1  # string gap: through the closer
                    else:
                        j += 2  # escape (a lone backslash-newline
                        # continues; a bare newline resyncs below)
                    continue
                if c == "\n":
                    break  # unterminated: resync at newline
                j += 1
            strings.append(text[start:j])
            end = j + (1 if closed else 0)
            code.append("".join(
                c if c in "\"\n" else " " for c in text[i:end]))
            i = end
            continue
        if ch == "'":
            end = _char_end(text, i)
            if end is None:
                code.append(ch)
                i += 1
            else:
                code.append("".join(
                    c if c == "'" else " " for c in text[i:end]))
                i = end
            continue
        if ch == "-" and text.startswith("--", i):
            k = i + 2
            while k < n and text[k] == "-":
                k += 1
            nxt = text[k] if k < n else "\n"
            if _is_sym(nxt):
                code.append("--")  # operator run: plain code
                i += 2
                continue
            while i < n and text[i] != "\n":  # line comment
                i += 1
            if i < n:
                code.append("\n")
                i += 1
            continue
        if ch == "{" and text.startswith("{-", i):
            depth = 0
            while i < n:
                if text.startswith("{-", i):
                    depth += 1
                    code.append("  ")
                    i += 2
                elif text.startswith("-}", i):
                    depth -= 1
                    code.append("  ")
                    i += 2
                    if depth == 0:
                        break
                else:
                    code.append("\n" if text[i] == "\n" else " ")
                    i += 1
            continue
        code.append(ch)
        i += 1
    return "".join(code), strings


def _depths(code):
    """Square-bracket depth before each offset (floored at zero)."""
    depths = [0] * (len(code) + 1)
    d = 0
    for i, ch in enumerate(code):
        depths[i] = d
        if ch == "[":
            d += 1
        elif ch == "]" and d > 0:
            d -= 1
    depths[len(code)] = d
    return depths


def spec_run_positions(code, mod):
    """[(line, depth, offset)] for each `Mod.spec` tree-entry candidate.

    Word-boundary matching both sides (a primed `Mod.spec'` or a
    longer qualification's tail never matches); the caller requires
    depth >= 1 (inside a list literal) inside the executed tree
    (see executed_regions), which an unused binding — top-level
    or local, bare or in-list — cannot satisfy.
    """
    rx = re.compile(r"(?<![A-Za-z0-9_.'])" + re.escape(mod)
                    + r"\.spec(?![A-Za-z0-9_'])")
    depths = _depths(code)
    return [(code.count("\n", 0, m.start()) + 1, depths[m.start()],
             m.start())
            for m in rx.finditer(code)]


# Haskell reserved words: never a top-level binding name, never an
# executed-tree reference (a `where x = ...` continuation or a
# `data` header must not split the runner into phantom bindings).
_HS_KEYWORDS = frozenset({
    "as", "case", "class", "data", "default", "deriving", "do",
    "else", "foreign", "hiding", "if", "import", "in", "infix",
    "infixl", "infixr", "instance", "let", "module", "newtype",
    "of", "qualified", "then", "type", "where",
})

_RX_LET = re.compile(r"(?<![A-Za-z0-9_'])let(?![A-Za-z0-9_'])")
_RX_IN = re.compile(r"(?<![A-Za-z0-9_'])in(?![A-Za-z0-9_'])")
_RX_WHERE = re.compile(r"(?<![A-Za-z0-9_'])where(?![A-Za-z0-9_'])")
_RX_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_']*")


def _binding_header(line):
    """Binding name when a col-0 line opens an equation, else None.

    Type signatures (`main :: IO ()`), imports, and the module
    header hold no equation `=`; operator runs (`==`, `/=`, `=>`)
    never count as the equation mark.
    """
    m = re.match(r"([A-Za-z_][A-Za-z0-9_']*)\b", line)
    if not m or m.group(1) in _HS_KEYWORDS:
        return None
    rest = line[m.end():]
    for i, ch in enumerate(rest):
        if ch != "=":
            continue
        prev = rest[i - 1] if i else " "
        nxt = rest[i + 1] if i + 1 < len(rest) else " "
        if prev in "=!<>/" or nxt in "=>":
            continue
        return m.group(1)
    return None


def binding_spans(code):
    """[(name, start, end)] top-level equations (col-0 headers).

    Only column-0 equations split the runner: an indented
    continuation can never open a binding (a future indented
    top-level equation would merge into the preceding span and
    fail closed on its `let`-free review, never pass silently).
    """
    lines = code.splitlines(True)
    heads = []
    off = 0
    for line in lines:
        name = _binding_header(line)
        if name is not None:
            heads.append((name, off))
        off += len(line)
    spans = []
    for i, (name, start) in enumerate(heads):
        end = heads[i + 1][1] if i + 1 < len(heads) else len(code)
        spans.append((name, start, end))
    return spans


def _excluded_spans(code, start, end):
    """`let`/`where` regions inside one binding span (offsets).

    A `where` runs to the end of its binding; a `let` runs to its
    matching `in` (nesting-aware: an inner `let...in` never ends
    the outer span), else to the end of the binding (a do-block
    let has no `in`, so spec references after one fail closed —
    hoist the list to a top-level binding instead). Both
    directions are conservative: references under either never
    count as executed and never pull a binding into the tree.
    """
    body = code[start:end]
    out = []
    for m in _RX_WHERE.finditer(body):
        out.append((start + m.start(), end))
    events = [(m.start(), "let") for m in _RX_LET.finditer(body)]
    events += [(m.start(), "in") for m in _RX_IN.finditer(body)]
    events.sort()
    stack = []
    for pos, kind in events:
        if kind == "let":
            stack.append(pos)
        elif stack:
            out.append((start + stack.pop(), start + pos))
    for pos in stack:
        out.append((start + pos, end))
    return out


def _in_spans(off, spans):
    return any(s <= off < e for s, e in spans)


def executed_regions(code):
    """[(start, end, excluded)] spans of the runner's executed tree.

    `main`'s equation plus every top-level binding it names,
    transitively, each minus its `let`/`where` regions. A
    `.spec` suffix never counts as a reference (otherwise every
    tree entry would pull in any binding named `spec`).
    """
    spans = binding_spans(code)
    by_name = {}
    for name, s, e in spans:
        by_name.setdefault(name, []).append((s, e))
    if "main" not in by_name:
        return []
    excl = {(s, e): _excluded_spans(code, s, e) for _, s, e in spans}
    keep = set()
    frontier = ["main"]
    while frontier:
        name = frontier.pop()
        if name in keep or name not in by_name:
            continue
        keep.add(name)
        for s, e in by_name[name]:
            for m in _RX_NAME.finditer(code, s, e):
                if _in_spans(m.start(), excl[(s, e)]):
                    continue
                if m.start() > s and code[m.start() - 1] == ".":
                    continue  # qualified tail, not a reference
                if m.group(0) not in keep and m.group(0) in by_name:
                    frontier.append(m.group(0))
    regions = []
    for name in keep:
        for s, e in by_name[name]:
            regions.append((s, e, excl[(s, e)]))
    return regions


def _runs_in_tree(code, mod):
    """(live, total) tree entries for `mod`: in-list and executed."""
    regions = executed_regions(code)
    live = 0
    total = 0
    for _, d, o in spec_run_positions(code, mod):
        total += 1
        if d >= 1 and any(s <= o < e and not _in_spans(o, xs)
                          for s, e, xs in regions):
            live += 1
    return live, total


def _strip_comments(text):
    """(lines, terminated): comment-free lines, literals intact.

    Single whole-text pass (newlines preserved, so line numbers
    are stable): strings span gaps exactly like strip_haskell
    and resync at a bare newline, char literals copy verbatim,
    and block comments nest. Pragmas (`{-# ... #-}`) copy
    through verbatim instead of vanishing as block comments,
    so rewrite rules and compiler plugins stay visible to the
    Main checks while pragma-shaped prose inside real comments
    and strings is still dropped or blanked. `terminated` is
    False when a block comment or pragma runs past EOF: GHC
    would reject the file, and the swallowed tail must fail
    here rather than scan clean.
    """
    out = []
    i, n = 0, len(text)
    in_str = False
    in_block = 0
    gap_before = False
    terminated = True
    while i < n:
        ch = text[i]
        if in_block:
            if text.startswith("{-", i):
                in_block += 1
                i += 2
            elif text.startswith("-}", i):
                in_block -= 1
                i += 2
                if in_block == 0 and gap_before and i < n \
                        and not text[i].isspace():
                    out.append(" ")  # comments are whitespace:
                    # removing one must not fuse its neighbors
            else:
                if ch == "\n":
                    out.append("\n")
                i += 1
            continue
        if in_str:
            out.append(ch)
            if ch == "\\":
                k = i + 1
                while k < n and text[k] in _GAP_WS:
                    k += 1
                if k < n and text[k] == "\\":
                    out.append(text[i + 1:k + 1])  # gap: keep
                    i = k + 1
                    continue
                if i + 1 < n and text[i + 1] != "\n":
                    out.append(text[i + 1])  # escape pair: keep
                    i += 2
                    continue
                i += 1  # lone backslash-newline: the newline
                continue  # below resyncs the string
            if ch == '"':
                in_str = False
            elif ch == "\n":
                in_str = False  # bare newline: resync (GHC agrees)
            i += 1
            continue
        if ch == "'":
            end = _char_end(text, i)
            if end is None:
                out.append(ch)
                i += 1
            else:
                out.append(text[i:end])
                i = end
            continue
        if ch == '"':
            in_str = True
            out.append(ch)
            i += 1
            continue
        if text.startswith("{-#", i):
            end = text.find("-}", i + 3)
            if end == -1:
                terminated = False  # pragma runs past EOF
                out.append(text[i:])
                break
            out.append(text[i:end + 2])  # pragma: keep verbatim
            i = end + 2
            continue
        if text.startswith("{-", i):
            gap_before = bool(out) and not out[-1][-1:].isspace()
            in_block = 1
            i += 2
            continue
        if ch == "-" and text.startswith("--", i):
            k = i + 2
            while k < n and text[k] == "-":
                k += 1
            nxt = text[k] if k < n else "\n"
            if _is_sym(nxt):
                out.append("--")
                i += 2
            else:
                while i < n and text[i] != "\n":
                    i += 1  # line comment: drop to the newline
            continue
        out.append(ch)
        i += 1
    if in_block:
        terminated = False  # block comment runs past EOF
    return "".join(out).splitlines(True), terminated


# Test-tree builders taking the name first, across the frozen
# toolchain (tasty-1.5.4 Test.Tasty and Test.Tasty.Providers,
# tasty-hunit-0.10.2, tasty-quickcheck-0.11.1 — every signature
# name-first per the published Haddocks): a hostile Main must
# not smuggle a battery through a builder the pin never
# enumerates. Longest-first: shared prefixes backtrack
# correctly either way, but the order keeps it obvious.
_RX_TEST_CTOR = re.compile(
    r"(dependentTestGroup|sequentialTestGroup|inOrderTestGroup|"
    r"testCaseSteps|testCaseInfo|testProperties|testProperty|"
    r"testGroup|testCase|singleTest)\b")
_RX_PROPWITH = re.compile(r"propWith\b")
_RX_TOKEN = re.compile(r"\S+")


def _gap(span, j):
    """Offset past spaces and at most one newline (a name gap).

    Test names sit on the constructor's line or the immediately
    following one (`testGroup\\n  "x"`); in compilable code the
    next string there is always the constructor's argument (a
    complete value followed by a stray string cannot parse).
    """
    n = len(span)
    while j < n and span[j] in " \t":
        j += 1
    if j < n and span[j] == "\n":
        j += 1
        while j < n and span[j] in " \t":
            j += 1
    return j


def _test_names_in(span):
    """([(literal, depth)], error): test-name literals in one span.

    The frozen ten take the name first, propWith second (a
    simple token: `seedOv`, `Nothing`; the gap allows the name
    on the next line). A constructor without a following
    literal (partial application, dynamic name) contributes
    nothing; a span with constructors but zero literals, an
    escaped name, or an unterminated string fails closed with an
    error.
    """
    lits = []
    saw_ctor = False
    depth = 0
    i = 0
    n = len(span)
    while i < n:
        ch = span[i]
        if ch in "([{":
            depth += 1
            i += 1
            continue
        if ch in ")]}":
            depth = max(0, depth - 1)
            i += 1
            continue
        if ch == '"':
            j = i + 1
            closed = False
            while j < n:
                c = span[j]
                if c == '"':
                    closed = True
                    break
                if c == "\\":
                    j += 2
                    continue
                if c == "\n":
                    break
                j += 1
            if not closed:
                return lits, "unterminated string in spec span"
            i = j + 1
            continue
        m = _RX_TEST_CTOR.match(span, i)
        if m and (i == 0 or not (span[i - 1].isalnum()
                                or span[i - 1] in "_'")):
            saw_ctor = True
            j = _gap(span, m.end())
            if j < n and span[j] == '"':
                k = j + 1
                while k < n and span[k] != '"':
                    k += 2 if span[k] == "\\" else 1
                lit = span[j + 1:k]
                if "\\" in lit:
                    return lits, f"escaped test name {lit!r}"
                lits.append((lit, depth))
                i = k + 1
                continue
            i = m.end()
            continue
        m = _RX_PROPWITH.match(span, i)
        if m and (i == 0 or not (span[i - 1].isalnum()
                                or span[i - 1] in "_'")):
            saw_ctor = True
            j = _gap(span, m.end())
            t = _RX_TOKEN.match(span, j)
            if t and not t.group(0).startswith('"'):
                j = _gap(span, t.end())
            if j < n and span[j] == '"':
                k = j + 1
                while k < n and span[k] != '"':
                    k += 2 if span[k] == "\\" else 1
                lit = span[j + 1:k]
                if "\\" in lit:
                    return lits, f"escaped test name {lit!r}"
                lits.append((lit, depth))
                i = k + 1
                continue
            i = m.end()
            continue
        i += 1
    if saw_ctor and not lits:
        return lits, "test constructors but no literal names"
    return lits, None


def spec_top_names(text):
    """(names, error): shallowest test-name literals in `spec`.

    A module without a `spec` equation (helpers like `Gen`) yields
    the empty set: it contributes no battery to pin.
    """
    cleaned, _ = _strip_comments(text)
    offs = []
    off = 0
    for line in cleaned:
        offs.append(off)
        off += len(line)
    joined = "".join(cleaned)
    heads = [(ln, _binding_header(line))
             for ln, line in enumerate(cleaned)]
    heads = [(ln, name) for ln, name in heads if name is not None]
    spec_at = next((ln for ln, name in heads if name == "spec"),
                   None)
    if spec_at is None:
        return set(), None
    following = [ln for ln, _ in heads if ln > spec_at]
    end_ln = min(following) if following else len(cleaned)
    span = joined[offs[spec_at]:offs[end_ln] if end_ln < len(offs)
                  else len(joined)]
    lits, err = _test_names_in(span)
    if err is not None:
        return set(), err
    if not lits:
        return set(), None
    floor = min(d for _, d in lits)
    return {lit for lit, d in lits if d == floor}, None


def spec_all_names(text):
    """Every test-name literal in a spec source (any depth)."""
    cleaned, _ = _strip_comments(text)
    lits, _ = _test_names_in("".join(cleaned))
    return {lit for lit, _ in lits}


def _ctor_count(code):
    """Test-name constructor occurrences in stripped code.

    Same occurrence rule as _test_names_in (leading boundary
    checked, trailing `\\b` in the patterns, qualified
    `M.testCase` counts): the two tallies agree by
    construction, so any gap is a genuinely unclassified
    constructor — parenthesized, concatenated, bound, or
    computed — never a counting artifact.
    """
    n = 0
    for rx in (_RX_TEST_CTOR, _RX_PROPWITH):
        for m in rx.finditer(code):
            i = m.start()
            if i == 0 or not (code[i - 1].isalnum()
                              or code[i - 1] in "_'"):
                n += 1
    return n


def _split_semi(line):
    """`line` split on `;` outside strings and char literals."""
    parts = []
    cur = []
    i, n = 0, len(line)
    in_str = False
    while i < n:
        ch = line[i]
        if in_str:
            cur.append(ch)
            if ch == "\\" and i + 1 < n and line[i + 1] != "\n":
                cur.append(line[i + 1])
                i += 2
                continue
            if ch == '"':
                in_str = False
            i += 1
            continue
        if ch == '"':
            in_str = True
            cur.append(ch)
            i += 1
            continue
        if ch == "'":
            end = _char_end(line, i)
            if end is None:
                cur.append(ch)
                i += 1
            else:
                cur.append(line[i:end])
                i = end
            continue
        if ch == ";":
            parts.append("".join(cur))
            cur = []
            i += 1
            continue
        cur.append(ch)
        i += 1
    parts.append("".join(cur))
    return parts


_RX_IMPORT_START = re.compile(r"[ \t]*import\b")


def _without_imports(cleaned_lines):
    """(kept, bare_semi): stripped lines minus import statements.

    Layout-aware: an import statement plus its indented
    continuations (blank lines included) is skipped; the next
    non-blank, non-indented line ends it. In compiling code an
    indented line after an import is always its continuation —
    anything else there is a parse error — so no expression is
    ever skipped, however imports wrap. Import lists name
    values but render no trees, so excluding them loses
    nothing. Every `;`-separated segment is classified on its
    own: a declaration hiding behind an import semicolon
    (`import M; evil = ...`) is kept as its own column-0 line
    and scanned like any other, while a continuation that
    grows a code tail ends the import there. `bare_semi` is
    True when a non-import line carries a `;` outside strings:
    single-line `do` blocks and explicit top-level separators
    defeat line attribution, so Main must use layout.
    """
    out = []
    bare_semi = False
    skipping = False
    for line in cleaned_lines:
        if skipping and (line.strip() == ""
                          or line[:1] in (" ", "\t")):
            segs = _split_semi(line)
            if len(segs) == 1:
                continue  # pure continuation
            skipping = False
            for seg in segs[1:]:
                if _RX_IMPORT_START.match(seg):
                    skipping = True  # ends in an import
                elif seg.strip():
                    out.append(seg.strip() + "\n")
                    skipping = False  # ends in code: import over
            continue
        skipping = False
        if _RX_IMPORT_START.match(line):
            skipping = True
            for seg in _split_semi(line)[1:]:
                if _RX_IMPORT_START.match(seg):
                    skipping = True
                elif seg.strip():
                    out.append(seg.strip() + "\n")
                    skipping = False
            continue
        if len(_split_semi(line)) > 1:
            bare_semi = True
        out.append(line)
    return out, bare_semi


# Any preprocessor line: the finite directive list cannot
# enumerate every spelling (`# define`, `#  pragma`, ...),
# and only a directive puts `#` first on its line — in
# compiling code a `#` anywhere else is a lex error (outside
# MagicHash suffixes, which never start a line), so the
# ban has no false shape. Checked pre-exclusion: an
# indented directive after an import is still a directive
# (CPP runs before layout).
_RX_PREPROC = re.compile(r"(?m)^[ \t]*#")

# `$` plus a name start (Unicode-aware: Template Haskell
# splices are not ASCII-bound).
_RX_SPLICE = re.compile(r"\$[^\W\d]")


def _has_splice(frag):
    """True when stripped code splices Template Haskell.

    `$(...)` unconditionally (GHC lexes it as one splice-open
    token, never application — operator sections like `($)`
    are refused with it, which no Main writes), or a bare
    `$var`/`$$var` in splice position, mirroring GHC's own
    positional disambiguation: `$` continues an application
    only when the preceding token can end an expression (a
    non-keyword name, a literal, a closing bracket), and
    opens a splice everywhere else — after `do`/`of`/`then`,
    after an operator (including `.`), or at the start. Plain
    application (`f $ x`, even unspaced as `f $x`) never
    counts. Quotes are kept by the stripper, so a string or
    char literal before `$` still reads as expression-ending.
    """
    if "$(" in frag:
        return True
    for m in _RX_SPLICE.finditer(frag):
        j = m.start() - 1
        while j >= 0 and frag[j] in " \t\n\r":
            j -= 1
        if j < 0:
            return True
        ch = frag[j]
        if ch in "\"'":
            continue  # a literal ends here (a prime extends
            # the preceding name, which ends here instead)
        if ch.isalnum() or ch in "_'":
            k = j
            while k >= 0 and (frag[k].isalnum()
                              or frag[k] in "_'"):
                k -= 1
            if frag[k + 1:j + 1] in _HS_KEYWORDS:
                return True  # keywords end no expression
            continue
        if ch in ")]}":
            continue
        return True
    return False


# Quasiquote opener: `[quoter|`, qualified, spaced, or bare
# (`[|`, which GHC rejects — failing closed on it costs
# nothing). Comprehensions share the shape; the closer rule
# below tells them apart.
_RX_QQ_OPEN = re.compile(
    r"\[\s*([^\W\d][\w']*(\.[^\W\d][\w']*)*)?\s*\|")


def _qq_after(frag, raw_text):
    """True when a quasiquote opener in `frag` closes in raw text.

    Line-aware (stripping preserves newlines and columns, so
    fragment coordinates index the raw lines soundly): an
    opener counts only with `|]` on its raw line at or after
    its column, or on any later raw line. Structured this
    way because payload text — comments, strings — can hide
    the closer from the stripped view while GHC still
    terminates the quote. Residual shape: a list
    comprehension plus a later `|]` inside a string or
    comment trips the rule; spell the string differently.
    """
    raw_lines = raw_text.splitlines()
    for m in _RX_QQ_OPEN.finditer(frag):
        ln = frag.count("\n", 0, m.start())
        col = m.start() - (frag.rfind("\n", 0, m.start()) + 1)
        if ln < len(raw_lines) and "|]" in raw_lines[ln][col:]:
            return True
        if any("|]" in raw_lines[i]
               for i in range(ln + 1, len(raw_lines))):
            return True
    return False


# Metaprogramming pragmas on comment-stripped (pragma-kept)
# text: rewrite rules plus the preprocessor/plugin flags.
# Checked pre-exclusion with the directives, for the same
# reason. `[^#]` cannot span pragmas (the closer carries
# `#`), so each match stays inside one pragma.
_RX_PRAGMA_META = re.compile(
    r"\{-#\s*RULES\b"
    r"|\{-#\s*OPTIONS(_GHC)?\b[^#]*?(?<![A-Za-z0-9_])"
    r"(-fplugin\b|-pgmF\b|-F\b)")

# `foreign` is reserved: any occurrence declares FFI (or
# fails to compile), and Main performs no FFI.
_RX_FOREIGN = re.compile(r"(?<![A-Za-z0-9_'])foreign(?![A-Za-z0-9_'])")

# A top-level bare name, possibly qualified (Unicode-aware).
_RX_BARE = re.compile(r"[^\W\d][\w']*(\.[^\W\d][\w']*)*")


def _bare_names(scoped_lines):
    """Bare declaration-position names no equation continues.

    A column-0 name (possibly qualified; import tails are
    emitted column-0 by the import exclusion) followed only
    by more declarations or EOF is unclassifiable: split
    equations continue with indented `=`/`|`/`:` (and are
    scanned normally), while anything else is either invalid
    Haskell or an implicit generator the constructor scan
    cannot see. Keywords start multi-line declarations of
    their own and are exempt; every other bare name fails
    closed.
    """
    found = []
    for i, line in enumerate(scoped_lines):
        s = line.strip()
        if not s or line[:1].isspace():
            continue  # indented: expression, not declaration
        if not _RX_BARE.fullmatch(s) or s in _HS_KEYWORDS:
            continue
        nxt = None
        for j in range(i + 1, len(scoped_lines)):
            t = scoped_lines[j].strip()
            if t:
                nxt = t
                break
        if nxt is not None and nxt[:1] in "=|:":
            continue  # split equation/signature/infix head
        found.append(s)
    return found


def _braces_ok(frag):
    """(ok, detail): no explicit-brace layout in stripped code.

    Braces without `;` are records and pass (their contents
    scan normally); a `;` inside braces is explicit layout
    (`do { x; y }`), which defeats line attribution, and an
    unmatched `{` fails closed. Strings and comments are
    already blanked, and pragmas with them, so every brace
    here is code.
    """
    depth = 0
    start = None
    for i, ch in enumerate(frag):
        if ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}":
            if depth == 0:
                return False, "unmatched `}` in Main"
            depth -= 1
            if depth == 0 and ";" in frag[start:i]:
                return False, "explicit-brace layout in Main"
    if depth:
        return False, "unmatched `{` in Main"
    return True, ""


# An import statement head: optional PackageImports string,
# optional `qualified`, then the dotted module path.
_RX_IMPORT_STMT = re.compile(
    r"[ \t]*import\s+"
    r"(?:\"[^\"]*\"\s+)?"
    r"(qualified\s+)?"
    r"([A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*)")


def _import_stmts(full_lines):
    """Import statements joined with their continuations."""
    stmts = []
    buf = None
    for line in full_lines:
        if _RX_IMPORT_START.match(line):
            if buf is not None:
                stmts.append(buf)
            buf = line
        elif buf is not None and (line.strip() == ""
                                  or line[:1] in (" ", "\t")):
            buf += line
        else:
            if buf is not None:
                stmts.append(buf)
                buf = None
    if buf is not None:
        stmts.append(buf)
    return stmts


def _parse_import(seg):
    """(module, qualified, names|None, hiding, dotdots, error).

    `names` None means no list (whole module); `dotdots` are
    the `(..)` types. Import lists name values only, never
    strings, so paren matching needs no lexer.
    """
    seg = re.sub(r"\{-#.*?#-\}", " ", seg)  # SOURCE pragma
    m = _RX_IMPORT_STMT.match(seg)
    if not m:
        return None, False, None, False, [], "unparseable import"
    module, qualified = m.group(2), bool(m.group(1))
    rest = seg[m.end():]
    rest = re.sub(r"^[ \t\n]+as[ \t\n]+[A-Za-z_][\w']*"
                  r"(\.[A-Za-z_][\w']*)*", " ", rest)
    hiding = re.match(r"^[ \t\n]+hiding\b", rest) is not None
    if hiding:
        return module, qualified, None, True, [], None
    i = rest.find("(")
    if i == -1:
        if rest.strip():
            return (None, False, None, False, [],
                    "unparseable import tail")
        return module, qualified, None, False, [], None
    depth = 0
    for j in range(i, len(rest)):
        if rest[j] == "(":
            depth += 1
        elif rest[j] == ")":
            depth -= 1
            if depth == 0:
                listed = rest[i + 1:j]
                tail = rest[j + 1:]
                break
    else:
        return (None, False, None, False, [],
                "unbalanced import list")
    if tail.strip():
        return (None, False, None, False, [],
                "unparseable import tail")
    names = []
    dotdots = []
    for item in re.split(r",(?![^()]*\))", listed):
        item = item.strip()
        if not item:
            continue
        dm = re.match(r"([A-Za-z_][\w']*)\s*\(\s*\.\.\s*\)$",
                      item)
        if dm:
            dotdots.append(dm.group(1))
            names.append(dm.group(1))
            continue
        tm = re.match(r"([A-Za-z_][\w']*)\s*\(([^()]*)\)$",
                      item)
        if tm:
            names.append(tm.group(1))
            names.extend(t.strip() for t in
                         tm.group(2).split(",") if t.strip())
        else:
            names.append(item)
    for nm in names:
        if not re.fullmatch(r"[A-Za-z_][\w']*", nm):
            return (None, False, None, False, [],
                    f"operator import {nm!r}")
    return module, qualified, names, False, dotdots, None


def main_import_issues(main_text, modules, allowed_imports,
                       allowed_dotdot):
    """(ok, detail): Main imports only pinned modules and names.

    Every import must name a suite module or a pinned module;
    anything else — helper, package, or exotic — fails here
    until it is reviewed into `allowed_imports`. Unqualified
    imports need explicit lists (every listed name pinned),
    `hiding` and operator imports are refused, and each
    `(..)` type must sit in `allowed_dotdot` (verified data
    types only: `(..)` on a class would leak methods, so a
    new `(..)` entry is a human data-vs-class check at pin
    time; the constructors it leaks are uppercase and can
    never be trees). Suite modules import for their `spec`,
    so their explicit lists hold `spec` plus any pinned
    extra names. Shared by the wiring gate and the execution
    join: the pin forces human review at every import
    boundary, which is what backstops the tree positions
    below against imported tree values.
    """
    if not isinstance(allowed_imports, dict):
        return False, "allowed_imports not pinned"
    dotdot = allowed_dotdot if isinstance(allowed_dotdot, dict) \
        else {}
    cleaned, _ = _strip_comments(main_text)
    for stmt in _import_stmts(cleaned):
        for seg in _split_semi(stmt):
            if not _RX_IMPORT_START.match(seg):
                continue  # code tail: scanned elsewhere
            mod, qualified, names, hiding, dots, err = \
                _parse_import(seg)
            if err is not None:
                return False, f"{err} in Main"
            if mod in modules:
                want = {"spec"} | set(
                    allowed_imports.get(mod, []))
                if names is not None:
                    bad = [x for x in names if x not in want]
                    if bad:
                        return False, (
                            f"unpinned names {bad} from suite "
                            f"module {mod} in Main")
                bad = [x for x in dots
                       if x not in dotdot.get(mod, [])]
                if bad:
                    return False, (
                        f"unpinned (..) types {bad} from {mod} "
                        "in Main")
                continue
            if mod not in allowed_imports:
                return False, f"unpinned import {mod} in Main"
            if hiding:
                return False, f"`hiding` import of {mod} in Main"
            if names is None and not qualified:
                return False, (
                    f"whole-module import of {mod} in Main "
                    "(explicit import lists required)")
            if names is not None:
                bad = [x for x in names
                       if x not in allowed_imports[mod]]
                if bad:
                    return False, (
                        f"unpinned names {bad} from {mod} "
                        "in Main")
            bad = [x for x in dots
                   if x not in dotdot.get(mod, [])]
            if bad:
                return False, (f"unpinned (..) types {bad} from "
                               f"{mod} in Main")
    return True, "Main imports are pinned"


_RX_RUNNER = re.compile(
    r"(?<![A-Za-z0-9_'])(?:[A-Za-z_][\w']*\.)*"
    r"(defaultMain|defaultMainWithIngredients)(?![A-Za-z0-9_'])")
_RX_TREEBANNED = re.compile(
    r"(?<![A-Za-z0-9_'])(?:[A-Za-z_][\w']*\.)*"
    r"(askOption|withResource)(?![A-Za-z0-9_'])")
_RX_QUALSPEC = re.compile(
    r"(?<![A-Za-z0-9_'])[A-Za-z_][\w']*"
    r"(?:\.[A-Za-z_][\w']*)*\.spec(?![A-Za-z0-9_'])")
_RX_QUALLOWER = re.compile(
    r"(?<![A-Za-z0-9_'])[A-Za-z_][\w']*"
    r"(?:\.[A-Za-z_][\w']*)*\.([a-z_][\w']*)")
_RX_DOBIND = re.compile(r"(?<![A-Za-z0-9_'])([^\W\d][\w']*)\s*<-")
_RX_LAMBDA = re.compile(r"\\([^\\]*?)->")
_RX_BARENAME = re.compile(r"(?<![A-Za-z0-9_'])([^\W\d][\w']*)")
_RX_IMPLICIT = re.compile(
    r"(?<![!#$%&*+./<=>?@\\^|~:\-])\?(?![!#$%&*+./<=>?@\\^|~:\-])"
    r"[A-Za-z_]")
_SYM_RUN = frozenset("!#$%&*+./<=>?@\\^|~:-")

# Constructor heads for tree classification: the frozen ten
# plus propWith (a leaf: name plus property, no children).
_CTOR_HEADS = frozenset({
    "testGroup", "dependentTestGroup", "sequentialTestGroup",
    "inOrderTestGroup", "testCase", "testCaseSteps",
    "testCaseInfo", "testProperty", "testProperties",
    "singleTest", "propWith",
})


def _strip_parens(t):
    """`t` minus spaces and enclosing parens, repeatedly."""
    while True:
        t = t.strip()
        if len(t) < 2 or t[0] != "(":
            return t
        depth = 0
        for i, ch in enumerate(t):
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0 and i != len(t) - 1:
                    return t
                if depth == 0:
                    break
        else:
            return t
        t = t[1:i]


def _split_top(t, token, boundaries=True):
    """Split `t` on top-level `token` ([{-aware).

    Strings are already blanked (frag), so no lexer is
    needed; quotes are kept but their contents are spaces.
    With boundaries, the token must not touch a symbol run
    (`+++` is not `++`, `<<>>` is not `<>`).
    """
    parts = []
    depth = 0
    cur = []
    i, n = 0, len(t)
    while i < n:
        ch = t[i]
        if ch in "([{":
            depth += 1
            cur.append(ch)
            i += 1
        elif ch in ")]}":
            depth = max(0, depth - 1)
            cur.append(ch)
            i += 1
        elif depth == 0 and t.startswith(token, i):
            if boundaries:
                prev = t[i - 1] if i else " "
                nxt = t[i + len(token)] if i + len(token) < n \
                    else " "
                if prev in _SYM_RUN or nxt in _SYM_RUN:
                    cur.append(ch)
                    i += 1
                    continue
            parts.append("".join(cur))
            cur = []
            i += len(token)
        else:
            cur.append(ch)
            i += 1
    parts.append("".join(cur))
    return parts


def _top_atoms(t):
    """Top-level space-separated atoms of `t` ([{- and quote-aware).

    Blanking keeps quotes but spaces string contents, so a
    quoted span counts as one atom however many spaces it
    holds (char literals with spaces would split, but no
    such shape exists in runner or option positions).
    """
    atoms = []
    depth = 0
    in_q = False
    cur = []
    for ch in t:
        if ch == '"':
            in_q = not in_q
            cur.append(ch)
        elif ch in "([{":
            depth += 1
            cur.append(ch)
        elif ch in ")]}":
            depth = max(0, depth - 1)
            cur.append(ch)
        elif depth == 0 and not in_q and ch in " \t\n\r":
            if cur:
                atoms.append("".join(cur))
                cur = []
        else:
            cur.append(ch)
    if cur:
        atoms.append("".join(cur))
    return atoms


def _eq_offset(line):
    """Offset of the equation `=` in a header line, else None.

    Same operator rule as _binding_header (`==`, `/=`, `=>`
    never count).
    """
    m = re.match(r"([A-Za-z_][A-Za-z0-9_']*)\b", line)
    if not m or m.group(1) in _HS_KEYWORDS:
        return None
    rest = line[m.end():]
    for i, ch in enumerate(rest):
        if ch != "=":
            continue
        prev = rest[i - 1] if i else " "
        nxt = rest[i + 1] if i + 1 < len(rest) else " "
        if prev in "=!<>/" or nxt in "=>":
            continue
        return m.end() + i
    return None


def _cut_col0(text):
    """`text` cut before the first depth-0 column-0 line.

    A runner argument or resolved right-hand side never
    continues onto a column-0 line at depth 0: layout ends
    the equation there (a new declaration or signature
    follows), so everything past the cut is sibling code,
    never tree. The first line always survives (the
    equation's own), as do column-0 lines inside brackets:
    explicit parens override layout.
    """
    lines = text.split("\n")
    keep = [lines[0]] if lines else []
    depth = 0
    for ch in keep[0] if keep else "":
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth = max(0, depth - 1)
    for line in lines[1:]:
        if depth == 0 and line[:1] not in ("",) \
                and not line[:1].isspace():
            break
        for ch in line:
            if ch in "([{":
                depth += 1
            elif ch in ")]}":
                depth = max(0, depth - 1)
        keep.append(line)
    return "\n".join(keep)


def _guard_rhs(span, start):
    """Right-hand sides after each top-level `=` past `start`."""
    rhs = []
    for piece in _split_top(span[start:], "|", boundaries=False):
        # The equation mark: first `=` outside operators.
        eq = None
        for i, ch in enumerate(piece):
            if ch != "=":
                continue
            prev = piece[i - 1] if i else " "
            nxt = piece[i + 1] if i + 1 < len(piece) else " "
            if prev in "=!<>/" or nxt in "=>":
                continue
            eq = i
            break
        if eq is not None:
            rhs.append(_cut_col0(piece[eq + 1:]))
    return rhs


def _top_bindings(frag):
    """name -> [rhs, ...]: arity-0 top-level equations.

    Single-line (`name = rhs`, `name | g = rhs`) via the
    column-0 headers, plus split equations (`name` alone on
    its line, `=`/`|`-continued after): each contributes its
    right-hand sides for tree resolution. Functions with
    arguments, pattern bindings, and `where`-locals never
    resolve — a tree reference through them fails closed.
    """
    out = {}
    heads = []
    off = 0
    lines = frag.splitlines(True)
    for line in lines:
        name = _binding_header(line)
        if name is not None:
            heads.append((name, off, False))
        else:
            stripped = line.strip()
            if line[:1] not in (" ", "\t", "\n", "\r", "") \
                    and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_']*",
                                     stripped) \
                    and stripped not in _HS_KEYWORDS:
                heads.append((stripped, off, True))
        off += len(line)
    for i, (name, start, split) in enumerate(heads):
        end = heads[i + 1][1] if i + 1 < len(heads) else len(frag)
        span = frag[start:end]
        if not split:
            first = span.split("\n", 1)[0]
            eq = _eq_offset(first)
            if eq is None:
                continue
            between = first[len(name):eq]
            if "|" in between and "=" not in between.split(
                    "|", 1)[0]:
                rhs = _guard_rhs(span, 0)
            elif between.strip():
                continue  # function with arguments
            else:
                rhs = _guard_rhs(span, 0)
            if rhs:
                out.setdefault(name, []).extend(rhs)
        else:
            rest = span.split("\n", 1)
            if len(rest) < 2:
                continue
            tail = rest[1].lstrip()
            if tail.startswith("="):
                out.setdefault(name, []).append(_cut_col0(
                    rest[1][rest[1].index("=") + 1:]))
            elif tail.startswith("|"):
                rhs = _guard_rhs(span, len(rest[0]) + 1)
                if rhs:
                    out.setdefault(name, []).extend(rhs)
    return out


class _TreeCtx:
    """Bindings, binds, pins, and specs for tree classification."""

    def __init__(self, frag, pin_names, modules=()):
        self.bindings = _top_bindings(frag)
        self.do_binds = set(_RX_DOBIND.findall(frag))
        lam = set()
        for body in _RX_LAMBDA.findall(frag):
            lam.update(_RX_BARENAME.findall(body))
        self.lam_binds = lam
        self.pin_names = set(pin_names) - {"spec"}
        self.spec_modules = {m for m in modules
                             if m.endswith("Spec")
                             or m.endswith("Props")}


def _spec_args_ok(args, ctx):
    """True when `.spec` arguments carry no tree structure.

    Arguments are values: no `.spec` of any qualification,
    no qualified lowercase reference, no implicit parameter.
    Bare lowercase names must be do-bound, lambda-bound,
    top-level-bound, or import-pinned (uppercase constructors
    and types can never be trees); `let`/`where`/`case`
    locals fail closed — hoist tree-position values to a
    `do`-bind. Anything deeper (a tree-typed argument, a
    monadic tree) is guarded by the spec's own signature
    plus the import pin forcing review, never by this scan.
    """
    if _RX_QUALSPEC.search(args):
        return False
    if _RX_QUALLOWER.search(args):
        return False
    if _RX_IMPLICIT.search(args):
        return False
    bound = set(ctx.bindings) | ctx.do_binds | ctx.lam_binds \
        | ctx.pin_names
    for nm in _RX_BARENAME.findall(args):
        if nm in _HS_KEYWORDS or nm[0].isupper():
            continue
        if nm not in bound:
            return False
    return True


def _classify_tree(expr, ctx, seen):
    """error-or-None: tree expression `expr` is attributable."""
    t = _strip_parens(expr)
    if not t:
        return "empty tree expression in Main"
    if t.startswith("\\"):
        return "computed tree in Main"
    if re.match(r"(case|if|do|let|where)\b", t):
        return "computed tree in Main"
    if _RX_TREEBANNED.match(t):
        return ("option-dependent tree in Main "
                "(askOption/withResource hide trees in functions)")
    if _RX_RUNNER.match(t):
        return "runner in tree position in Main"
    if len(_split_top(t, "++")) > 1:
        return "list spliced into tree position in Main"
    for i, ch in enumerate(t):
        if ch in "([{":
            break
        if ch in _SYM_RUN and ch not in "$.":
            prev = t[i - 1] if i else " "
            if ch == "-" and (prev in " \t\n\r([,"
                               or i == 0):
                continue  # unary minus: a value, not an op
            return "operator-composed tree in Main"
        if ch == ".":
            prev = t[i - 1] if i else " "
            nxt = t[i + 1] if i + 1 < len(t) else " "
            wordish = (lambda c: c.isalnum() or c in "_'")
            if not (wordish(prev) and wordish(nxt)):
                return "operator-composed tree in Main"
    hm = re.match(r"(?:([A-Za-z_][\w']*(?:\.[A-Za-z_][\w']*)*)\.)?"
                  r"([A-Za-z_][\w']*)", t)
    if hm is None:
        return "unexpected tree element in Main"
    qual, head = hm.group(1), hm.group(2)
    if qual is not None:
        if head == "spec":
            if qual not in ctx.spec_modules:
                return (f"`.spec` from non-spec module {qual} "
                        "in Main")
            if not _spec_args_ok(t[hm.end():], ctx):
                return "unattributable `.spec` argument in Main"
            return None
        if head in _CTOR_HEADS:
            return _classify_ctor(t, head, hm.end(), ctx, seen)
        if head in ("localOption", "adjustOption"):
            return _classify_wrapper(t[hm.end():], ctx, seen)
        # askOption/withResource/runners matched earlier.
        if head[0].islower() or head[0] == "_":
            return "imported tree reference in Main"
        return "unexpected tree element in Main"
    if head in _CTOR_HEADS:
        return _classify_ctor(t, head, hm.end(), ctx, seen)
    if head in ("localOption", "adjustOption"):
        return _classify_wrapper(t[hm.end():], ctx, seen)
    if head in _HS_KEYWORDS or head[0].isupper():
        return "unexpected tree element in Main"
    if hm.end() != len(t) and t[hm.end():].strip():
        return "applied tree reference in Main"
    if head in seen:
        return "cyclic tree reference in Main"
    if head not in ctx.bindings:
        return "unattributable tree reference in Main"
    for rhs in ctx.bindings[head]:
        err = _classify_tree(rhs, ctx, seen | {head})
        if err is not None:
            return err
    return None


def _classify_wrapper(rest, ctx, seen):
    """error-or-None: option wrapper applies to a sound tree."""
    segs = _split_top(rest, "$", boundaries=False)
    if len(segs) > 1:
        inner = segs[1]
        for extra in segs[2:]:
            inner += "$" + extra
        return _classify_tree(inner, ctx, seen)
    inner = _top_atoms(rest)
    if len(inner) < 2:
        return "option wrapper without a tree in Main"
    return _classify_tree(inner[-1], ctx, seen)


def _classify_ctor(t, ctor, head_end, ctx, seen):
    """error-or-None: constructor-headed tree `t` is sound."""
    pos = head_end
    n = len(t)
    while pos < n and t[pos] in " \t\n\r":
        pos += 1
    if pos >= n or t[pos] != '"':
        return "unclassified tree name in Main"
    pos += 1
    while pos < n and t[pos] != '"':
        pos += 1
    pos += 1  # past the name literal (validated elsewhere)
    if ctor in ("dependentTestGroup", "sequentialTestGroup"):
        while pos < n and t[pos] in " \t\n\r":
            pos += 1
        dm = re.match(r"[A-Za-z_][\w']*"
                      r"(\.[A-Za-z_][\w']*)*", t[pos:])
        if not dm:
            return "dependency type must be a bare constructor"
        pos += dm.end()
    while pos < n and (t[pos] in " \t\n\r" or t[pos] == "$"):
        pos += 1
    if ctor in ("testGroup", "dependentTestGroup",
                "sequentialTestGroup", "inOrderTestGroup"):
        depth = 0
        k = pos
        while k < n:
            ch = t[k]
            if ch in "([{":
                depth += 1
            elif ch in ")]}":
                if depth == 0:
                    break
                depth -= 1
            elif depth == 0 and ch == ",":
                break
            k += 1
        return _classify_list(t[pos:k], ctx, seen)
    if ctor == "propWith":
        return None  # leaf: name plus property, no children
    return None  # leaf constructor: no children to classify


def _classify_list(expr, ctx, seen):
    """error-or-None: tree-children expression is attributable."""
    t = _strip_parens(expr)
    if not t:
        return "empty tree-children expression in Main"
    parts = _split_top(t, "++")
    if len(parts) > 1:
        for part in parts:
            err = _classify_list(part, ctx, seen)
            if err is not None:
                return err
        return None
    if t.startswith("["):
        inner = t[1:-1] if t.endswith("]") else t[1:]
        for el in _split_top(inner, ",", boundaries=False):
            if not el.strip():
                continue
            err = _classify_tree(el, ctx, seen)
            if err is not None:
                return err
        return None
    bm = re.match(r"[^\W\d][\w']*", t)
    if bm and bm.end() == len(t) and \
            bm.group(0) not in _HS_KEYWORDS:
        name = bm.group(0)
        if name in seen:
            return "cyclic tree reference in Main"
        if name not in ctx.bindings:
            return "tree children must be a literal list in Main"
        for rhs in ctx.bindings[name]:
            err = _classify_list(rhs, ctx, seen | {name})
            if err is not None:
                return err
        return None
    return "tree children must be a literal list in Main"


def _tree_issues(scoped_frag, pin_names, modules=()):
    """error-or-None: every runner tree in Main is attributable.

    Each `defaultMain`/`defaultMainWithIngredients` call
    resolves its tree argument — through top-level bindings
    (single-line and split equations alike), `(++)`, and
    option wrappers — to literal lists of `Mod.spec`
    applications and leaf constructors. Anything else (a
    bound or imported tree, a computed branch, an
    option-dependent or runner-nested tree) fails closed:
    the executed tree must be visible in Main, never
    assembled where the pin cannot see it. A `.spec` suffix
    resolves to its owner: only the suite's own spec
    modules may head a tree element.
    """
    ctx = _TreeCtx(scoped_frag, pin_names, modules)
    spans = binding_spans(scoped_frag)
    for m in _RX_RUNNER.finditer(scoped_frag):
        start = next((e for _, s, e in spans
                      if s <= m.start() < e), len(scoped_frag))
        rest = _cut_col0(scoped_frag[m.end():start])
        segs = _split_top(rest, "$", boundaries=False)
        if len(segs) > 1:
            tree = segs[1]
            for extra in segs[2:]:
                tree += "$" + extra
        else:
            atoms = _top_atoms(rest)
            tree = atoms[-1] if atoms else ""
        err = _classify_tree(tree, ctx, set())
        if err is not None:
            return err
    return None


def main_inline_issues(main_text, groups, has_modules,
                       pin_names=(), modules=()):
    """(ok, detail): Main carries no batteries beyond the roots.

    Everything but imports is scanned (no declaration form is
    recognized or skipped: split, pattern, and guarded
    equations all count): every test-name constructor needs
    its literal name, every literal must be a suite root
    (suites without modules keep their inline scaffold tree
    here, and only here), and no CPP directives, Template
    Haskell splices, quasiquotes, rewrite rules, compiler
    plugins, foreign declarations, explicit-brace layout, or
    bare semicolons may appear — generated or computed trees
    have no visible constructor to classify, so a quasiquote
    opener counts with its raw-text closer however the
    payload hides it. Runner trees must resolve to literal
    lists of `Mod.spec` applications and leaf constructors
    (see _tree_issues). Shared by the wiring gate and the
    execution join, so a hostile tree is refused build-free
    and never joins standalone either.
    """
    cleaned, terminated = _strip_comments(main_text)
    if not terminated:
        return False, "unterminated comment or pragma in Main"
    full = "".join(cleaned)
    if _RX_PREPROC.search(full):
        return False, "cpp directives in Main"
    if _RX_PRAGMA_META.search(full):
        return False, "rewrite rules or compiler plugins in Main"
    frag_full, _ = strip_haskell(full)
    ok, detail = _braces_ok(frag_full)
    if not ok:
        return False, detail
    kept, bare_semi = _without_imports(cleaned)
    if bare_semi:
        return False, ("explicit semicolons outside imports "
                       "in Main (use layout)")
    scoped = "".join(kept)
    lits, err = _test_names_in(scoped)
    if err is not None:
        return False, err
    frag, _ = strip_haskell(scoped)
    if _has_splice(frag):
        return False, "template haskell splice in Main"
    if "|]" in frag or _qq_after(frag_full, main_text):
        return False, "quasiquote in Main"
    if _RX_FOREIGN.search(frag):
        return False, "foreign declarations in Main"
    nctors = _ctor_count(frag)
    if nctors != len(lits):
        return False, (f"{nctors} test-name constructors but "
                       f"{len(lits)} literal names (unclassified "
                       "inline constructors in Main)")
    stray = sorted({lit for lit, _ in lits} - set(groups))
    if stray and has_modules:
        return False, ("Main carries no inline batteries "
                       f"(stray={stray})")
    bare = _bare_names(kept)
    if bare:
        return False, (f"unclassifiable bare name in Main "
                       f"({bare[0]})")
    terr = _tree_issues(frag, pin_names, modules)
    if terr is not None:
        return False, terr
    if not has_modules:
        return True, "no modules: the inline scaffold tree is the suite"
    return True, "Main carries no inline batteries"


def has_import(code, mod):
    """True when stripped code imports exactly `mod` (any form)."""
    rx = re.compile(r"^[ \t]*import\s+(?:qualified\s+)?"
                    + re.escape(mod) + r"(?![A-Za-z0-9_'])",
                    re.MULTILINE)
    return rx.search(code) is not None


def find_registration(raw):
    """Suite names claimed by `-- REGISTRATION: <suite>` markers."""
    return re.findall(r"^[ \t]*--[ \t]*REGISTRATION:[ \t]*(\S+)[ \t]*$",
                      raw, re.MULTILINE)


def wiring_of(mod, main_text):
    """{'imported': bool, 'run': bool} for one module in one Main."""
    code, _ = strip_haskell(main_text)
    live, _ = _runs_in_tree(code, mod)
    return {"imported": has_import(code, mod), "run": live > 0}


def job_runs_suite(workflow_text, job, suite):
    """True when job's steps run the suite via an active line.

    A step line counts when it holds `cabal test` plus `all` or the
    suite name; full-line `#` comments never count (a commented-out
    lane is a lane that runs nothing).
    """
    start = re.search(r"(?m)^  " + re.escape(job) + r":\s*$", workflow_text)
    if not start:
        return False
    rest = workflow_text[start.end():]
    nxt = re.search(r"(?m)^  [A-Za-z0-9_-]+:\s*$", rest)
    body = rest[:nxt.start()] if nxt else rest
    for line in body.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if "cabal test" not in line:
            continue
        if re.search(r"\ball\b", line) or suite in line:
            return True
    return False


# Constructor token: Delta-prefixed type name other than DeltaOp
# itself (matched on comment/string-stripped sources, so prose and
# literals never contribute).
RX_CTOR = re.compile(r"Delta[A-Z][A-Za-z0-9_']*")


def _span(text, start_rx, end_rx):
    """Source span from the start line through (not incl.) the end line."""
    lines = text.splitlines()
    begin = next((i for i, l in enumerate(lines)
                  if re.match(start_rx, l)), None)
    if begin is None:
        return None
    for j in range(begin + 1, len(lines)):
        if re.match(end_rx, lines[j]):
            return "\n".join(lines[begin:j])
    return "\n".join(lines[begin:])


def _ctors_in(span):
    """Ordered-unique constructor names tokenized from a span."""
    seen = []
    for tok in RX_CTOR.findall(span or ""):
        if tok != "DeltaOp" and tok not in seen:
            seen.append(tok)
    return seen


def constructors_check(outcome_raw, gen_raw, ns_raw, delta_raw):
    """Constructor-evolution pin. Returns (failures, count).

    Every `data DeltaOp` constructor must be enumerated in each
    reviewed test site (Gen.ctorName, the NamespaceProps
    classifiers, the representative table, the full generator),
    and the numeric pins (generator modulus, hit summary, hit
    assertion) must equal the constructor count — so a new
    constructor fails here until the generator and corpora cover
    it, instead of compiling past a silent gap.
    """
    fails = []
    try:
        outcome_code, _ = strip_haskell(outcome_raw)
        gen_code, _ = strip_haskell(gen_raw)
        ns_code, _ = strip_haskell(ns_raw)
    except Exception as e:  # noqa: BLE001 - reported, not hidden
        return [f"constructor scan failed: {e}"], 0
    want = _ctors_in(_span(outcome_code, r"^data DeltaOp\s*$",
                           r"^\s*deriving\b"))
    if not want:
        return ["no DeltaOp constructors parsed from Outcome.hs"], 0
    # Spans anchor on the equation (`name ... =`), never the
    # signature line, so the arms are always inside.
    sites = [
        ("Gen.ctorName", _span(gen_code, r"^ctorName\b[^=]*=", r"^\S")),
        ("NamespaceProps.opClass",
         _span(ns_code, r"^opClass\b[^=]*=", r"^\S")),
        ("NamespaceProps.isSessionOp",
         _span(ns_code, r"^isSessionOp\b[^=]*=", r"^\S")),
        ("NamespaceProps.constOpsFull",
         _span(ns_code, r"^constOpsFull\b[^=]*=", r"^\S")),
        ("Gen.genOpFull14",
         _span(gen_code, r"^genOpFull14\b[^=]*=", r"^\S")),
    ]
    for site, span in sites:
        if span is None:
            fails.append(f"{site}: definition not found")
            continue
        have = _ctors_in(span)
        missing = [c for c in want if c not in have]
        extra = [c for c in have if c not in want]
        if missing or extra:
            fails.append(f"{site}: missing={missing} extra={extra}")
    n = len(want)
    # Numeric pins resolve inside their own definition spans, so
    # older generators and other literals never shadow them.
    gen_span = _span(gen_raw, r"^genOpFull14\b[^=]*=", r"^\S") or ""
    pick = re.search(r"s1\s+`mod`\s+(\d+)", gen_span)
    if pick is None or int(pick.group(1)) != n:
        got = pick.group(1) if pick else "none"
        fails.append(f"generator modulus is {got}, want {n}")
    sum_span = _span(gen_raw, r"^hitSummary\b[^=]*=", r"^\S") or ""
    summary = re.search(r"/(\d+) constructors", sum_span)
    if summary is None or int(summary.group(1)) != n:
        got = summary.group(1) if summary else "none"
        fails.append(f"hit summary pins {got}, want {n}")
    hit_span = _span(delta_raw, r"^caseSeededHits\b[^=]*=", r"^\S") or ""
    assertion = re.search(
        r'"seeded corpus covers all constructors"\s+(\d+)', hit_span)
    if assertion is None or int(assertion.group(1)) != n:
        got = assertion.group(1) if assertion else "none"
        fails.append(f"seeded hit assertion pins {got}, want {n}")
    return fails, n


def load_inventory(path):
    """(suites-by-name, error-or-None) for the manifest file."""
    try:
        doc = json.loads(Path(path).read_text())
    except Exception as e:  # noqa: BLE001 - reported, not hidden
        return None, f"cannot parse {path}: {e}"
    if doc.get("schema") != "haskoki-suite-inventory/1":
        return None, f"{path}: want schema haskoki-suite-inventory/1"
    entries = doc.get("suites")
    if not isinstance(entries, list) or not entries:
        return None, f"{path}: no suites listed"
    by_name = {}
    for e in entries:
        name = e.get("name")
        if not name or name in by_name:
            return None, f"{path}: duplicate or missing suite name"
        by_name[name] = e
    return by_name, None


def module_source(root, dirs, mod):
    """First suite dir holding the module's source, else None.

    Shared with generate-function-contracts.py, which pins
    each evidence citation to the file its suite actually
    compiles (same stem, right directory).
    """
    rel = mod.replace(".", "/") + ".hs"
    for d in dirs:
        cand = Path(root) / d / rel
        if cand.is_file():
            return cand
    return None


def check_tree(root, inventory_path):
    """Run every rule. Returns (failures, stats)."""
    root = Path(root)
    fails = []
    stats = {"specs": 0, "suites": 0}

    def rule(name, cond, detail):
        check(name, cond, detail)
        if not cond:
            fails.append(name)

    try:
        suites = parse_suites((root / "haskoki.cabal").read_text())
    except Exception as e:  # noqa: BLE001
        rule("CABAL-PARSE", False, f"cannot parse haskoki.cabal: {e}")
        return fails, stats
    inv, err = load_inventory(inventory_path)
    if err is not None:
        rule("INVENTORY-PARSE", False, err)
        return fails, stats
    missing = sorted(set(inv) - set(suites))
    extra = sorted(set(suites) - set(inv))
    rule("SUITES-SYNC", not missing and not extra,
         f"cabal {sorted(suites)} vs inventory {sorted(inv)}"
         + ("" if not missing and not extra
            else f" (missing={missing} extra={extra})"))
    stats["suites"] = len(suites)
    try:
        ctor_raw = {
            "outcome": (root / "core" / "Haskoki" / "Outcome.hs").read_text(),
            "gen": (root / "tests" / "prop" / "Gen.hs").read_text(),
            "ns": (root / "tests" / "prop" / "NamespaceProps.hs").read_text(),
            "delta": (root / "tests" / "prop" / "DeltaProps.hs").read_text(),
        }
    except Exception as e:  # noqa: BLE001
        rule("CONSTRUCTORS", False, f"cannot read constructor sources: {e}")
        return fails, stats
    ctor_fails, ctor_n = constructors_check(
        ctor_raw["outcome"], ctor_raw["gen"], ctor_raw["ns"],
        ctor_raw["delta"])
    rule("CONSTRUCTORS", not ctor_fails,
         f"{ctor_n} DeltaOp constructors enumerated in every test site"
         + ("" if not ctor_fails else f" ({'; '.join(ctor_fails)})"))
    for name in sorted(suites):
        s = suites[name]
        if not s["dirs"] or not s["main"]:
            rule(f"WIRING-{name}", False, "dirs/main-is unparsed")
            continue
        main_path = root / s["dirs"][0] / s["main"]
        if not main_path.exists():
            rule(f"WIRING-{name}", False, f"missing {main_path}")
            continue
        main_text = main_path.read_text()
        code, strings = strip_haskell(main_text)
        regions = executed_regions(code)
        files = []
        for d in s["dirs"]:
            files.extend((root / d).glob("*.hs"))
        have = {f.stem for f in files}
        pinned = inv.get(name, {}).get("modules")
        if pinned is None:
            rule(f"INVENTORY-{name}-MODULES", False,
                 f"{name} not registered in the suite inventory")
            continue
        dropped = sorted(set(pinned) - set(s["modules"]))
        added = sorted(set(s["modules"]) - set(pinned))
        rule(f"INVENTORY-{name}-MODULES", not dropped and not added,
             f"{len(pinned)} pinned modules match cabal"
             + ("" if not dropped and not added
                else f" (dropped={dropped} added={added})"))
        for mod in s["modules"]:
            is_spec = mod.endswith("Spec") or mod.endswith("Props")
            if mod not in have:
                rule(f"WIRING-{name}-{mod}", False,
                     f"{mod} listed but no file under {s['dirs']}")
                continue
            if not is_spec:
                rule(f"WIRING-{name}-{mod}", True,
                     f"helper {mod} exists")
                continue
            stats["specs"] += 1
            imported = has_import(code, mod)
            hits = spec_run_positions(code, mod)
            live = [(ln, d) for ln, d, o in hits
                    if d >= 1 and any(s <= o < e
                                      and not _in_spans(o, xs)
                                      for s, e, xs in regions)]
            run = bool(live)
            at = ",".join(f"L{ln}:d{d}" for ln, d in live) or "none"
            cold = len(hits) - len(live)
            rule(f"WIRING-{name}-{mod}", imported and run,
                 f"{mod} imported={imported} run={run} at {at}"
                 + ("" if not cold
                    else f" ({cold} mention(s) outside "
                    "the executed tree)"))
        regs = find_registration(main_text)
        rule(f"REGISTRATION-{name}", regs == [name],
             f"marker claims {regs}, want exactly [{name}]")
        groups = inv[name].get("required_groups", [])
        missing_groups = [g for g in groups if g not in strings]
        rule(f"GROUPS-{name}", bool(groups) and not missing_groups,
             f"required groups {groups} as literals in Main"
             + ("" if not missing_groups
                else f" (missing={missing_groups})"))
        mg = inv[name].get("module_groups")
        if mg is None:
            rule(f"MODULE-GROUPS-{name}", False,
                 "module_groups not pinned")
        else:
            mism = {}
            if sorted(mg) != sorted(s["modules"]):
                mism["<keys>"] = (f"pinned {sorted(mg)} vs cabal "
                                  f"{sorted(s['modules'])}")
            found = {}
            for mod in s["modules"]:
                src = module_source(root, s["dirs"], mod)
                if src is None:
                    continue  # missing file: the WIRING leg fails
                names, err = spec_top_names(src.read_text())
                found[mod] = names
                if err is not None:
                    mism[mod] = err
                elif mod not in mg:
                    mism[mod] = "not pinned"
                elif sorted(mg[mod]) != sorted(names):
                    mism[mod] = (f"pinned {sorted(mg[mod])} vs source "
                                 f"{sorted(names)}")
            if not mism:
                seen = {}
                for mod in s["modules"]:
                    for nm in sorted(found.get(mod, set())):
                        if nm in groups:
                            mism[f"{mod}::{nm}"] = (
                                "top name equals a suite group")
                        if nm in seen:
                            mism[f"{mod}::{nm}"] = (
                                "top name shared with "
                                f"{seen[nm]}")
                        seen.setdefault(nm, mod)
                tops = [(mod, nm) for mod in s["modules"]
                        for nm in sorted(found.get(mod, set()))]
                for i, (m1, t1) in enumerate(tops):
                    for m2, t2 in tops[i + 1:]:
                        if (len(t2) > len(t1)
                                and t2.startswith(t1)
                                and t2[len(t1)] in "./"):
                            mism[f"{m2}::{t2}"] = (
                                "top name extends "
                                f"{m1}::{t1}")
                        elif (len(t1) > len(t2)
                                and t1.startswith(t2)
                                and t1[len(t2)] in "./"):
                            mism[f"{m1}::{t1}"] = (
                                "top name extends "
                                f"{m2}::{t2}")
                whole = {}
                for mod in s["modules"]:
                    src = module_source(root, s["dirs"], mod)
                    if src is not None:
                        whole[mod] = spec_all_names(src.read_text())
                for mod in s["modules"]:
                    for nm in sorted(found.get(mod, set())):
                        for other in s["modules"]:
                            if other != mod and nm in whole.get(
                                    other, set()):
                                mism[f"{mod}::{nm}"] = (
                                    "shadowed by a same-named case in "
                                    f"{other}")
            rule(f"MODULE-GROUPS-{name}", not mism,
                 f"{len(s['modules'])} modules' top test names pinned"
                 + ("" if not mism else f" ({mism})"))
        # Suites whose batteries live in modules must not also
        # carry inline batteries in Main: depth-two names are
        # pinned tops, so an unpinned inline tree could credit a
        # module battery invisibly.
        allowed = inv[name].get("allowed_imports")
        pin_names = set()
        if isinstance(allowed, dict):
            for names in allowed.values():
                pin_names.update(names)
        ok, detail = main_inline_issues(main_text, groups,
                                        bool(s["modules"]),
                                        pin_names, s["modules"])
        rule(f"MAIN-NO-INLINE-{name}", ok, detail)
        ok, detail = main_import_issues(
            main_text, s["modules"], allowed,
            inv[name].get("allowed_dotdot"))
        rule(f"MAIN-IMPORTS-{name}", ok, detail)
        lanes = inv[name].get("executed_by", [])
        if not lanes:
            rule(f"LANES-{name}", False, "no executed_by lanes pinned")
        for lane in lanes:
            wf_rel = lane.get("workflow", "")
            job = lane.get("job", "")
            wf_path = root / wf_rel
            if not wf_path.is_file():
                rule(f"LANES-{name}-{job}", False,
                     f"workflow missing: {wf_rel}")
                continue
            ok = job_runs_suite(wf_path.read_text(), job, name)
            rule(f"LANES-{name}-{job}", ok,
                 f"{wf_rel} job {job} runs {name}")
    # Secondary tripwire only: per-suite pinned rules above are the
    # gate; this count merely notices mass disappearance.
    rule("SPECS-COUNT", stats["specs"] > 60,
         f"{stats['specs']} spec modules pinned across suites")
    return fails, stats


def _selftest_root(tmp, mains, cabal_suites, inventory, workflows):
    root = Path(tmp)
    root.mkdir(parents=True, exist_ok=True)
    cabal = []
    for suite, spec in cabal_suites.items():
        cabal.append(f"test-suite {suite}\n"
                     f"  main-is: {spec['main']}\n"
                     f"  hs-source-dirs: {' '.join(spec['dirs'])}\n"
                     f"  other-modules:\n"
                     + "".join(f"    {m}\n" for m in spec["modules"]))
    (root / "haskoki.cabal").write_text("".join(cabal))
    for rel, text in mains.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    for rel in {m for spec in cabal_suites.values()
                for d in spec["dirs"] for m in spec["modules"]}:
        for spec in cabal_suites.values():
            for d in spec["dirs"]:
                p = root / d / f"{rel}.hs"
                if not p.exists() and rel in spec["modules"]:
                    p.parent.mkdir(parents=True, exist_ok=True)
                    p.write_text(f"module {rel} where\n")
    (root / "tests" / "suite-inventory.json").parent.mkdir(
        parents=True, exist_ok=True)
    (root / "tests" / "suite-inventory.json").write_text(
        json.dumps(inventory))
    # Constructor-evolution stubs (two-ctor shape mirroring the live
    # sources; mutation controls below rewrite these per case).
    stub_src = root / "core" / "Haskoki" / "Outcome.hs"
    stub_src.parent.mkdir(parents=True, exist_ok=True)
    stub_src.write_text(
        "module Stub where\n"
        "data DeltaOp\n"
        "  = DeltaTouchSession !Int\n"
        "  | DeltaCloseSession !Int\n"
        "  deriving (Eq, Show)\n")
    stub_gen = root / "tests" / "prop" / "Gen.hs"
    stub_gen.parent.mkdir(parents=True, exist_ok=True)
    stub_gen.write_text(
        "module Gen where\n"
        "ctorName op = case op of\n"
        "  DeltaTouchSession _ -> \"TouchSession\"\n"
        "  DeltaCloseSession _ -> \"CloseSession\"\n"
        "hitSummary hits = show 2 ++ \"/2 constructors\"\n"
        "genOpFull14 s0 =\n"
        "  let pick = s1 `mod` 2\n"
        "  in case pick of\n"
        "    0 -> (DeltaTouchSession 0, s0)\n"
        "    _ -> (DeltaCloseSession 0, s0)\n")
    (root / "tests" / "prop" / "NamespaceProps.hs").write_text(
        "module NamespaceProps where\n"
        "opClass op = case op of\n"
        "  DeltaTouchSession _ -> OCSession\n"
        "  DeltaCloseSession _ -> OCSession\n"
        "isSessionOp op = case op of\n"
        "  DeltaTouchSession _ -> True\n"
        "  DeltaCloseSession _ -> True\n"
        "constOpsFull = [DeltaTouchSession 0, DeltaCloseSession 0]\n")
    (root / "tests" / "prop" / "DeltaProps.hs").write_text(
        "module DeltaProps where\n"
        "caseSeededHits count = do\n"
        "  assertEqual \"seeded corpus covers all constructors\" 2 "
        "(Map.size hits)\n")
    for rel, text in workflows.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    return root


# Tripwire ballast: the SPECS-COUNT rule (> 60) is calibrated for
# the live tree, so fixtures wire 61 spec modules and the count
# rule holds there too (no fixture-only exemptions in the gate).
PAD_SPECS = [f"Pad{i:02d}Spec" for i in range(60)]
PAD_RUN = ", ".join(f"{m}.spec" for m in PAD_SPECS)
PAD_IMP = "\n".join(f"import qualified {m}" for m in PAD_SPECS)


def _fixture_main(focus=None, registration="suite-a", extra=""):
    entries = focus if focus is not None else f"[FooSpec.spec, {PAD_RUN}]"
    return ("-- REGISTRATION: " + registration + "\n"
            "module Main (main) where\n"
            "import Test.Tasty (defaultMain, testGroup)\n"
            "import qualified FooSpec\n"
            f"{PAD_IMP}\n"
            "import Helper (help)\n"
            "main :: IO ()\n"
            f'main = defaultMain $ testGroup "alpha group" {entries}\n'
            f"{extra}")


GOOD_MAIN = _fixture_main()

GOOD_CABAL = {"suite-a": {"dirs": ["tests/alpha"],
                          "modules": ["FooSpec", "Helper"] + PAD_SPECS,
                          "main": "Main.hs"}}

GOOD_WF = """name: ci
on: [push]
jobs:
  haskell:
    runs-on: ubuntu-latest
    steps:
      - name: Build and test
        run: |
          cabal build all --enable-tests
          cabal test all
"""


def _good_inventory(extra_modules=None, extra_groups=None, lanes=None):
    mods = ["FooSpec", "Helper"] + PAD_SPECS + (extra_modules or [])
    groups = ["alpha group"] + (extra_groups or [])
    if lanes is None:
        lanes = [{"workflow": ".github/workflows/ci.yml",
                  "job": "haskell"}]
    return {"schema": "haskoki-suite-inventory/1", "suites": [
        {"name": "suite-a", "main": "tests/alpha/Main.hs",
         "modules": mods, "required_groups": groups,
         "module_groups": {m: []
                            for m in ["FooSpec", "Helper"] + PAD_SPECS},
         "allowed_imports": {
             "Helper": ["help"],
             "Test.Tasty": ["TestTree", "defaultMain",
                            "testGroup"],
             "Test.Tasty.HUnit": []},
         "executed_by": lanes}]}


def self_test():
    """Durable negative controls: commented, string-only,
    unused-binding, unused-list, and unreferenced-list invocations,
    coordinated runner+Cabal removal, registration drift, missing
    group literals, module-group drift/ambiguity/extension,
    inline Main batteries in every declaration and spelling
    (split, pattern, guarded, tuple, record, infix, instance,
    and class equations; literal, parenthesized, concatenated,
    bound, and computed names; keyword and Unicode splices;
    hidden-closer quasiquotes; CPP in any spelling; rewrite
    rules, plugins, foreign declarations, bare names,
    import-semicolon tails, and explicit layout), unattributable
    runner trees (bound, imported, computed, cyclic, applied,
    and option-dependent, including `.spec` from non-spec
    modules), and unpinned imports (comment-gap spellings
    included), dotdot types, and lanes that run nothing must
    fail; the clean fixture, genuine indirection, wrappers,
    the alternate runner, records, comment-gap spec imports,
    and per-directory module sources must pass."""
    fails = []
    ran = []

    def expect(name, cond, detail=""):
        ran.append(name)
        print(f"{'PASS' if cond else 'FAIL'}: self-test: {name}"
              + (f": {detail}" if detail and not cond else ""))
        if not cond:
            fails.append(name)

    def run_fixture(tmp, mains, cabal_suites, inventory, workflows,
                    mutate=None):
        root = _selftest_root(tmp, mains, cabal_suites, inventory,
                              workflows)
        if mutate is not None:
            mutate(root)
        buf = io.StringIO()
        with redirect_stdout(buf):
            fails_out, _ = check_tree(
                root, root / "tests" / "suite-inventory.json")
        return fails_out, buf.getvalue()

    mains = {"tests/alpha/Main.hs": GOOD_MAIN}
    workflows = {".github/workflows/ci.yml": GOOD_WF}
    with tempfile.TemporaryDirectory(prefix="v3-wiring") as tmp:
        fails_out, _ = run_fixture(
            tmp + "/clean", mains, GOOD_CABAL, _good_inventory(),
            workflows)
        expect("clean-tree-passes", not fails_out, repr(fails_out))

        commented = dict(mains)
        commented["tests/alpha/Main.hs"] = _fixture_main(
            focus="[\n-- FooSpec.spec\n, " + PAD_RUN + "\n]")
        fails_out, _ = run_fixture(
            tmp + "/commented", commented, GOOD_CABAL,
            _good_inventory(), workflows)
        expect("commented-invocation-fails",
               fails_out == ["WIRING-suite-a-FooSpec"], repr(fails_out))

        imp_commented = dict(mains)
        imp_commented["tests/alpha/Main.hs"] = GOOD_MAIN.replace(
            "import qualified FooSpec", "-- import qualified FooSpec")
        fails_out, _ = run_fixture(
            tmp + "/impcommented", imp_commented, GOOD_CABAL,
            _good_inventory(), workflows)
        expect("commented-import-fails",
               fails_out == ["WIRING-suite-a-FooSpec"], repr(fails_out))

        stringy = dict(mains)
        stringy["tests/alpha/Main.hs"] = _fixture_main(
            focus=f'["FooSpec.spec", {PAD_RUN}]')
        fails_out, _ = run_fixture(
            tmp + "/stringy", stringy, GOOD_CABAL, _good_inventory(),
            workflows)
        expect("string-only-invocation-fails",
               fails_out == ["WIRING-suite-a-FooSpec",
                             "MAIN-NO-INLINE-suite-a"],
               repr(fails_out))

        unused = dict(mains)
        unused["tests/alpha/Main.hs"] = _fixture_main(
            focus=f'["placeholder", {PAD_RUN}]',
            extra="unused = FooSpec.spec\n")
        fails_out, _ = run_fixture(
            tmp + "/unused", unused, GOOD_CABAL, _good_inventory(),
            workflows)
        expect("unused-binding-fails",
               fails_out == ["WIRING-suite-a-FooSpec",
                             "MAIN-NO-INLINE-suite-a"],
               repr(fails_out))

        fails_out, _ = run_fixture(
            tmp + "/removed", mains, GOOD_CABAL,
            _good_inventory(extra_modules=["GoneSpec"]), workflows)
        expect("removed-from-runner-and-cabal-fails",
               fails_out == ["INVENTORY-suite-a-MODULES"],
               repr(fails_out))

        extra_cabal = {"suite-a": {"dirs": ["tests/alpha"],
                                  "modules": ["FooSpec", "Helper"]
                                  + PAD_SPECS + ["ExtraSpec"],
                                  "main": "Main.hs"}}
        fails_out, _ = run_fixture(
            tmp + "/extra", mains, extra_cabal, _good_inventory(),
            workflows)
        expect("unreviewed-cabal-addition-fails",
               any(f == "INVENTORY-suite-a-MODULES" for f in fails_out),
               repr(fails_out))

        wrong_reg = dict(mains)
        wrong_reg["tests/alpha/Main.hs"] = GOOD_MAIN.replace(
            "suite-a", "suite-b", 1)
        fails_out, _ = run_fixture(
            tmp + "/wrongreg", wrong_reg, GOOD_CABAL,
            _good_inventory(), workflows)
        expect("registration-mismatch-fails",
               fails_out == ["REGISTRATION-suite-a"], repr(fails_out))

        no_reg = dict(mains)
        no_reg["tests/alpha/Main.hs"] = "".join(
            GOOD_MAIN.splitlines(True)[1:])
        fails_out, _ = run_fixture(
            tmp + "/noreg", no_reg, GOOD_CABAL, _good_inventory(),
            workflows)
        expect("registration-missing-fails",
               fails_out == ["REGISTRATION-suite-a"], repr(fails_out))

        fails_out, _ = run_fixture(
            tmp + "/group", mains, GOOD_CABAL,
            _good_inventory(extra_groups=["missing group"]), workflows)
        expect("group-literal-missing-fails",
               fails_out == ["GROUPS-suite-a"], repr(fails_out))

        commented_lane = dict(workflows)
        commented_lane[".github/workflows/ci.yml"] = GOOD_WF.replace(
            "cabal test all", "# cabal test all")
        fails_out, _ = run_fixture(
            tmp + "/lane", mains, GOOD_CABAL, _good_inventory(),
            commented_lane)
        expect("commented-lane-fails",
               fails_out == ["LANES-suite-a-haskell"], repr(fails_out))

        no_job = dict(workflows)
        no_job[".github/workflows/ci.yml"] = GOOD_WF.replace(
            "  haskell:", "  other:")
        fails_out, _ = run_fixture(
            tmp + "/nojob", mains, GOOD_CABAL, _good_inventory(),
            no_job)
        expect("lane-missing-job-fails",
               fails_out == ["LANES-suite-a-haskell"], repr(fails_out))

        unknown_inv = _good_inventory()
        unknown_inv["suites"].append(
            {"name": "suite-b", "main": "tests/beta/Main.hs",
             "modules": [], "required_groups": ["beta"],
             "executed_by": [{"workflow": ".github/workflows/ci.yml",
                              "job": "haskell"}]})
        fails_out, _ = run_fixture(
            tmp + "/unknown", mains, GOOD_CABAL, unknown_inv,
            workflows)
        expect("unknown-suite-fails",
               "SUITES-SYNC" in fails_out, repr(fails_out))

        # Constructor evolution: the live sources agree (fail-closed
        # on drift), and each evolution shape fails loudly.
        live = {}
        for key, rel in (
                ("outcome", "core/Haskoki/Outcome.hs"),
                ("gen", "tests/prop/Gen.hs"),
                ("ns", "tests/prop/NamespaceProps.hs"),
                ("delta", "tests/prop/DeltaProps.hs")):
            live[key] = (REPO / rel).read_text()
        live_fails, live_n = constructors_check(
            live["outcome"], live["gen"], live["ns"], live["delta"])
        expect("constructors-live-consistent",
               not live_fails and live_n == 14, repr(live_fails))

        def add_ctor(root):
            p = root / "core" / "Haskoki" / "Outcome.hs"
            p.write_text(p.read_text().replace(
                "  deriving (Eq, Show)\n",
                "  | DeltaExtra !Int\n  deriving (Eq, Show)\n"))

        fails_out, _ = run_fixture(
            tmp + "/newctor", mains, GOOD_CABAL, _good_inventory(),
            workflows, mutate=add_ctor)
        expect("added-constructor-fails",
               fails_out == ["CONSTRUCTORS"], repr(fails_out))

        def drop_arm(root):
            p = root / "tests" / "prop" / "Gen.hs"
            p.write_text(p.read_text().replace(
                "  DeltaCloseSession _ -> \"CloseSession\"\n", ""))

        fails_out, _ = run_fixture(
            tmp + "/droparm", mains, GOOD_CABAL, _good_inventory(),
            workflows, mutate=drop_arm)
        expect("dropped-enumeration-fails",
               fails_out == ["CONSTRUCTORS"], repr(fails_out))

        def drift_mod(root):
            p = root / "tests" / "prop" / "Gen.hs"
            p.write_text(p.read_text().replace("`mod` 2", "`mod` 3"))

        fails_out, _ = run_fixture(
            tmp + "/driftmod", mains, GOOD_CABAL, _good_inventory(),
            workflows, mutate=drift_mod)
        expect("modulus-drift-fails",
               fails_out == ["CONSTRUCTORS"], repr(fails_out))

        def drift_assert(root):
            p = root / "tests" / "prop" / "DeltaProps.hs"
            p.write_text(p.read_text().replace(
                "covers all constructors\" 2 ", "covers all constructors\" 3 "))

        fails_out, _ = run_fixture(
            tmp + "/driftassert", mains, GOOD_CABAL, _good_inventory(),
            workflows, mutate=drift_assert)
        expect("assertion-drift-fails",
               fails_out == ["CONSTRUCTORS"], repr(fails_out))

        let_head = ("-- REGISTRATION: suite-a\n"
                    "module Main (main) where\n"
                    "import Test.Tasty (defaultMain, testGroup)\n"
                    "import qualified FooSpec\n"
                    f"{PAD_IMP}\n"
                    "import Helper (help)\n"
                    "main :: IO ()\n")
        fails_out, _ = run_fixture(
            tmp + "/unusedlist",
            {"tests/alpha/Main.hs": let_head
             + "main = let _unused = [FooSpec.spec] in defaultMain "
             f'$ testGroup "alpha group" [{PAD_RUN}]\n'},
            GOOD_CABAL, _good_inventory(), workflows)
        expect("unused-list-fails",
               fails_out == ["WIRING-suite-a-FooSpec"], repr(fails_out))

        fails_out, _ = run_fixture(
            tmp + "/dolet",
            {"tests/alpha/Main.hs": let_head
             + "main = do\n"
             + "  let _unused = [FooSpec.spec]\n"
             f'  defaultMain $ testGroup "alpha group" [{PAD_RUN}]\n'},
            GOOD_CABAL, _good_inventory(), workflows)
        expect("dolet-list-fails-closed",
               "WIRING-suite-a-FooSpec" in fails_out, repr(fails_out))

        fails_out, _ = run_fixture(
            tmp + "/nestedlet",
            {"tests/alpha/Main.hs": let_head
             + "main = defaultMain $ testGroup \"alpha group\"\n"
             + "  [ let _unused = let _unit = () in [FooSpec.spec] in "
             "Pad00Spec.spec\n"
             f"  , {PAD_RUN}\n"
             + "  ]\n"},
            GOOD_CABAL, _good_inventory(), workflows)
        expect("nested-unused-list-fails",
               fails_out == ["WIRING-suite-a-FooSpec",
                             "MAIN-NO-INLINE-suite-a"],
               repr(fails_out))

        toplevel = dict(mains)
        toplevel["tests/alpha/Main.hs"] = _fixture_main(
            focus=f'["placeholder", {PAD_RUN}]',
            extra="unusedList = [FooSpec.spec]\n")
        fails_out, _ = run_fixture(
            tmp + "/toplevel", toplevel, GOOD_CABAL, _good_inventory(),
            workflows)
        expect("unreferenced-list-fails",
               fails_out == ["WIRING-suite-a-FooSpec",
                             "MAIN-NO-INLINE-suite-a"],
               repr(fails_out))

        indirect = dict(mains)
        indirect["tests/alpha/Main.hs"] = _fixture_main(
            focus=f"([{PAD_RUN}] ++ extra)",
            extra="extra = [FooSpec.spec]\n")
        fails_out, _ = run_fixture(
            tmp + "/indirect", indirect, GOOD_CABAL, _good_inventory(),
            workflows)
        expect("referenced-list-passes", not fails_out, repr(fails_out))

        fails_out, _ = run_fixture(
            tmp + "/coreidiom",
            {"tests/alpha/Main.hs":
             let_head.replace(
                 "import Test.Tasty (defaultMain, testGroup)",
                 "import Test.Tasty (TestTree, defaultMain, testGroup)")
             + "spec :: TestTree\n"
             f'spec = testGroup "alpha group" [FooSpec.spec, {PAD_RUN}]\n'
             + "main :: IO ()\n"
             + "main = defaultMain spec\n"},
            GOOD_CABAL, _good_inventory(), workflows)
        expect("coretests-idiom-passes", not fails_out, repr(fails_out))

        def add_battery(root):
            p = root / "tests" / "alpha" / "FooSpec.hs"
            p.write_text("module FooSpec where\n"
                         "spec = testGroup \"foo battery\" []\n")

        fails_out, _ = run_fixture(
            tmp + "/groupdrift", mains, GOOD_CABAL, _good_inventory(),
            workflows, mutate=add_battery)
        expect("module-group-drift-fails",
               fails_out == ["MODULE-GROUPS-suite-a"], repr(fails_out))

        no_mg = _good_inventory()
        del no_mg["suites"][0]["module_groups"]
        fails_out, _ = run_fixture(
            tmp + "/nogroups", mains, GOOD_CABAL, no_mg, workflows)
        expect("module-groups-missing-fails",
               fails_out == ["MODULE-GROUPS-suite-a"], repr(fails_out))

        match_inv = _good_inventory()
        match_inv["suites"][0]["module_groups"]["FooSpec"] = [
            "foo battery"]
        fails_out, _ = run_fixture(
            tmp + "/groupmatch", mains, GOOD_CABAL, match_inv,
            workflows, mutate=add_battery)
        expect("module-groups-match-passes", not fails_out,
               repr(fails_out))

        def add_dup(root):
            (root / "tests" / "alpha" / "FooSpec.hs").write_text(
                "module FooSpec where\nspec = testGroup \"same\" []\n")
            (root / "tests" / "alpha" / "Pad00Spec.hs").write_text(
                "module Pad00Spec where\n"
                "spec = testGroup \"same\" []\n")

        dup_inv = _good_inventory()
        dup_inv["suites"][0]["module_groups"]["FooSpec"] = ["same"]
        dup_inv["suites"][0]["module_groups"]["Pad00Spec"] = ["same"]
        fails_out, _ = run_fixture(
            tmp + "/duptop", mains, GOOD_CABAL, dup_inv,
            workflows, mutate=add_dup)
        expect("duplicate-top-name-fails",
               fails_out == ["MODULE-GROUPS-suite-a"], repr(fails_out))

        def add_shadow(root):
            (root / "tests" / "alpha" / "FooSpec.hs").write_text(
                "module FooSpec where\nspec = testGroup \"top\" []\n")
            (root / "tests" / "alpha" / "Pad00Spec.hs").write_text(
                "module Pad00Spec where\n"
                "spec = testGroup \"other\" [testCase \"top\" x]\n")

        sh_inv = _good_inventory()
        sh_inv["suites"][0]["module_groups"]["FooSpec"] = ["top"]
        sh_inv["suites"][0]["module_groups"]["Pad00Spec"] = ["other"]
        fails_out, _ = run_fixture(
            tmp + "/shadowtop", mains, GOOD_CABAL, sh_inv,
            workflows, mutate=add_shadow)
        expect("shadowed-top-name-fails",
               fails_out == ["MODULE-GROUPS-suite-a"], repr(fails_out))

        def add_extend(root):
            (root / "tests" / "alpha" / "FooSpec.hs").write_text(
                "module FooSpec where\nspec = testGroup \"top\" []\n")
            (root / "tests" / "alpha" / "Pad00Spec.hs").write_text(
                "module Pad00Spec where\n"
                "spec = testGroup \"top.sub\" []\n")

        ext_inv = _good_inventory()
        ext_inv["suites"][0]["module_groups"]["FooSpec"] = ["top"]
        ext_inv["suites"][0]["module_groups"]["Pad00Spec"] = [
            "top.sub"]
        fails_out, _ = run_fixture(
            tmp + "/extendtop", mains, GOOD_CABAL, ext_inv,
            workflows, mutate=add_extend)
        expect("extended-top-name-fails",
               fails_out == ["MODULE-GROUPS-suite-a"], repr(fails_out))

        inline = dict(mains)
        inline["tests/alpha/Main.hs"] = _fixture_main(
            focus=f'[FooSpec.spec, {PAD_RUN}, testGroup "sneaky" []]')
        fails_out, _ = run_fixture(
            tmp + "/inlinemain", inline, GOOD_CABAL,
            _good_inventory(), workflows)
        expect("main-inline-battery-fails",
               fails_out == ["MAIN-NO-INLINE-suite-a"],
               repr(fails_out))

        h_head = let_head.replace(
            "import Test.Tasty (defaultMain, testGroup)",
            "import Test.Tasty (defaultMain, testGroup)\n"
            "import qualified Test.Tasty.HUnit as H")

        def inline_main(expr, bottom=""):
            return (h_head
                    + "main = defaultMain $ testGroup \"alpha group\"\n"
                    f"  [FooSpec.spec, {PAD_RUN}, {expr}\n"
                    + "  ]\n" + bottom)

        for tag, expr, bottom in (
                ("paren", 'H.testCase ("sneaky.r4") (pure ())', ""),
                ("concat",
                 'H.testCase ("sneak" ++ ".r4") (pure ())', ""),
                ("bound", "H.testCase r4Leaf (pure ())",
                 '\nr4Leaf = "sneaky.r4"\n'),
                ("computed",
                 "testGroup r4Name [H.testCase r4Case (pure ())]",
                 '\nr4Name = "sneaky"\nr4Case = "r4"\n'),
                ("splice", "$(mkTests)", "")):
            sneaky = {"tests/alpha/Main.hs": inline_main(expr,
                                                         bottom)}
            fails_out, _ = run_fixture(
                tmp + f"/inline{tag}", sneaky, GOOD_CABAL,
                _good_inventory(), workflows)
            expect(f"main-inline-{tag}-fails",
                   fails_out == ["MAIN-NO-INLINE-suite-a"],
                   repr(fails_out))

        wrapped = {"tests/alpha/Main.hs": let_head.replace(
            "import Test.Tasty (defaultMain, testGroup)",
            "import Test.Tasty\n  ( defaultMain\n  , testGroup\n  )")
            + "main = defaultMain $ testGroup \"alpha group\" "
            f"[FooSpec.spec, {PAD_RUN}]\n"}
        fails_out, _ = run_fixture(
            tmp + "/multiimport", wrapped, GOOD_CABAL,
            _good_inventory(), workflows)
        expect("main-multiline-import-passes", not fails_out,
               repr(fails_out))

        h_imports = h_head.rsplit("main :: IO ()\n", 1)[0]
        helper_eq = ("main :: IO ()\n"
                     "main = defaultMain $ testGroup "
                     "\"alpha group\"\n"
                     f"  [FooSpec.spec, {PAD_RUN}, r5Helper]\n")
        decls = [
            ("split", "r5Helper\n"
             "  = H.testCase \"sneaky.r6\" (pure ())\n", False),
            ("split-after", "r5Helper\n"
             "  = H.testCase \"sneaky.r6\" (pure ())\n", True),
            ("split-paren", "r5Helper\n"
             "  = H.testCase (\"sneaky.r6\") (pure ())\n", False),
            ("pattern-paren", "(r5Helper) = "
             "H.testCase \"sneaky.r6\" (pure ())\n", False),
            ("pattern-ctor", "Just r5Helper = "
             "Just (H.testCase \"sneaky.r6\" (pure ()))\n", False),
            ("guarded", "r5Helper\n"
             "  | True = H.testCase \"sneaky.r6\" (pure ())\n",
             False),
            ("named-qq", "r5Helper = [r5quoter| sneaky.r6 |]\n",
             False),
            ("named-qq-spaced",
             "r5Helper = [ r5quoter | sneaky.r6 |]\n", False),
            ("named-qq-qual",
             "r5Helper = [R5.quoter| sneaky.r6 |]\n", False),
            ("bare-splice", "r5Helper = $r5Splice\n", False),
            ("bare-splice-typed", "r5Helper = $$r5Splice\n", False),
            ("cpp", "#define R5SNEAKY 1\nr5Helper = 42\n", False),
        ]
        for tag, helper, after in decls:
            if after:
                text = h_imports + helper_eq + helper
            else:
                text = h_imports + helper + helper_eq
            fails_out, _ = run_fixture(
                tmp + f"/decl{tag}",
                {"tests/alpha/Main.hs": text},
                GOOD_CABAL, _good_inventory(), workflows)
            expect(f"main-decl-{tag}-fails",
                   fails_out == ["MAIN-NO-INLINE-suite-a"],
                   repr(fails_out))

        tight = {"tests/alpha/Main.hs": h_imports
                 + "main = defaultMain $testGroup \"alpha group\" "
                 f"[FooSpec.spec, {PAD_RUN}]\n"}
        fails_out, _ = run_fixture(
            tmp + "/tightapp", tight, GOOD_CABAL,
            _good_inventory(), workflows)
        expect("main-unspaced-app-passes", not fails_out,
               repr(fails_out))

        # Round-7 declaration forms, builders, and markers: every
        # shape fails on its own rule with wiring otherwise quiet.
        r7_eq = ("main :: IO ()\n"
                 "main = defaultMain $ testGroup \"alpha group\"\n"
                 f"  [FooSpec.spec, {PAD_RUN}]\n")
        r7decls = [
            ("tuple", '(r7Helper, _) = (H.testCase "s.r7" '
             "(pure ()), ())\n"),
            ("record", 'R7 { r = r7Helper } = R7 (H.testCase "s.r7" '
             "(pure ()))\n"),
            ("infix", 'r7a <#> r7b = H.testCase "s.r7" (pure ())\n'),
            ("instance", "instance R7Class R7 where\n"
             '  r7m _ = H.testCase "s.r7" (pure ())\n'),
            ("class", "class R7Class a where\n"
             "  r7m :: a -> TestTree\n"
             '  r7m _ = H.testCase "s.r7" (pure ())\n'),
            ("patguard", "r7Helper\n"
             "  | Just x <- Just () = "
             'H.testCase "s.r7" (pure ())\n'),
            ("steps", 'r7Helper = H.testCaseSteps "s.r7" '
             "(\\_ -> pure ())\n"),
            ("info", 'r7Helper = H.testCaseInfo "s.r7" (pure "")\n'),
            ("props", 'r7Helper = testProperties "s.r7" []\n'),
            ("sequential", 'r7Helper = sequentialTestGroup "s.r7" '
             "Sequential []\n"),
            ("dependent", 'r7Helper = dependentTestGroup "s.r7" '
             "Parallel []\n"),
            ("inorder", 'r7Helper = inOrderTestGroup "s.r7" []\n'),
            ("single", 'r7Helper = singleTest "s.r7" r7Inst\n'),
            ("kw-then",
             "r7Helper = if True then $g else mempty\n"),
            ("kw-else",
             "r7Helper = if False then mempty else $g\n"),
            ("kw-in", "r7Helper = let x = () in $g\n"),
            ("kw-do", "r7Helper = do\n  $g\n"),
            ("kw-of", "r7Helper = case y of $g\n"),
            ("kw-where", "r7Helper = y where $g = z\n"),
            ("opdot", "r7Helper = f.$g\n"),
            ("unicode", "r7Helper = $\u03bb\n"),
            ("qq-hidden-line",
             "r7Helper = [qq| -- payload |]\n"),
            ("qq-hidden-block",
             "r7Helper = [qq| payload {- |] -} tail\n"),
            ("cpp-spaced", "# define R7X 1\nr7Helper = 42\n"),
            ("cpp-pragma-dir",
             '#pragma GCC diagnostic ignored "-Wfoo"\n'
             "r7Helper = 42\n"),
            ("foreign",
             'foreign import ccall "g" r7Helper :: IO ()\n'),
            ("fplugin", "{-# OPTIONS_GHC -fplugin=Foo #-}\n"
             "r7Helper = 42\n"),
            ("preprocessor", "{-# OPTIONS_GHC -F -pgmF foo #-}\n"
             "r7Helper = 42\n"),
            ("rules", '{-# RULES "r" forall x. f x = x #-}\n'
             "r7Helper = 42\n"),
            ("bare", "genDecls\n"),
            ("bare-qual", "M.genDecls\n"),
        ]
        for tag, helper in r7decls:
            fails_out, _ = run_fixture(
                tmp + f"/r7decl{tag}",
                {"tests/alpha/Main.hs": h_imports + helper + r7_eq},
                GOOD_CABAL, _good_inventory(), workflows)
            expect(f"main-r7decl-{tag}-fails",
                   fails_out == ["MAIN-NO-INLINE-suite-a"],
                   repr(fails_out))

        fails_out, _ = run_fixture(
            tmp + "/r7declunterminated",
            {"tests/alpha/Main.hs": h_imports + r7_eq
             + "r7Helper = 1 {- blah\n"},
            GOOD_CABAL, _good_inventory(), workflows)
        expect("main-r7decl-unterminated-fails",
               fails_out == ["MAIN-NO-INLINE-suite-a"],
               repr(fails_out))

        semi_head = h_imports.replace(
            "import qualified FooSpec\n",
            "import qualified FooSpec; r7Helper = "
            'H.testCase "s.r7" (pure ())\n')
        fails_out, _ = run_fixture(
            tmp + "/r7semi", {"tests/alpha/Main.hs": semi_head + r7_eq},
            GOOD_CABAL, _good_inventory(), workflows)
        expect("main-import-semi-fails",
               fails_out == ["MAIN-NO-INLINE-suite-a"],
               repr(fails_out))

        cont_head = h_imports.replace(
            "import Test.Tasty (defaultMain, testGroup)\n",
            "import Test.Tasty\n  (defaultMain, testGroup) ; "
            'r7Helper = H.testCase "s.r7" (pure ())\n')
        fails_out, _ = run_fixture(
            tmp + "/r7cont", {"tests/alpha/Main.hs": cont_head + r7_eq},
            GOOD_CABAL, _good_inventory(), workflows)
        expect("main-cont-semi-fails",
               fails_out == ["MAIN-NO-INLINE-suite-a"],
               repr(fails_out))

        # Round-7 tree positions: unattributable trees fail,
        # structural idioms (wrappers, the alternate runner,
        # records) pass.
        for tag, focus, extra in (
                ("evil-elem",
                 f"[FooSpec.spec, {PAD_RUN}, Evil.evilTree]", ""),
                ("bare-elem",
                 f"[FooSpec.spec, {PAD_RUN}, mysteryTree]", ""),
                ("spec-arg-evil",
                 f"[FooSpec.spec Evil.mkTree, {PAD_RUN}]", ""),
                ("list-var-evil", "specList",
                 "specList = "
                 f"[FooSpec.spec, {PAD_RUN}, Evil.evilTree]\n"),
                ("concat-op",
                 f"[FooSpec.spec <> Evil.evilTree, {PAD_RUN}]", ""),
                ("case-elem",
                 f"[FooSpec.spec, {PAD_RUN}, "
                 "case x of _ -> Evil.evilTree]", ""),
                ("cycle", f"[FooSpec.spec, {PAD_RUN}, aaaTree]",
                 "aaaTree = bbbTree\nbbbTree = aaaTree\n"),
                ("askoption",
                 f"[FooSpec.spec, {PAD_RUN}, "
                 "askOption (\\v -> FooSpec.spec)]", ""),
                ("applied-bare",
                 f"[FooSpec.spec, {PAD_RUN}, "
                 "helper Evil.evilTree]",
                 "helper = 42\n"),
                ("brace-semi", None, "r7Helper = f { g; h }\n"),
                ("do-semi", None, "r7Helper = f; g\n")):
            fails_out, _ = run_fixture(
                tmp + f"/r7tree{tag}",
                {"tests/alpha/Main.hs": _fixture_main(
                    focus=focus, extra=extra)},
                GOOD_CABAL, _good_inventory(), workflows)
            expect(f"main-tree-{tag}-fails",
                   fails_out == ["MAIN-NO-INLINE-suite-a"],
                   repr(fails_out))

        for tag, equation in (
                ("wrapper",
                 "main = defaultMain $ localOption (mkTimeout 5) "
                 "$ testGroup \"alpha group\"\n"
                 f"  [FooSpec.spec, {PAD_RUN}]\n"),
                ("runner-alt",
                 "main = defaultMainWithIngredients "
                 "[defaultIngredients] $ testGroup \"alpha group\"\n"
                 f"  [FooSpec.spec, {PAD_RUN}]\n")):
            fails_out, _ = run_fixture(
                tmp + f"/r7idiom{tag}",
                {"tests/alpha/Main.hs": let_head + equation},
                GOOD_CABAL, _good_inventory(), workflows)
            expect(f"main-tree-{tag}-passes", not fails_out,
                   repr(fails_out))

        fails_out, _ = run_fixture(
            tmp + "/r7records",
            {"tests/alpha/Main.hs": _fixture_main(
                extra="data R7 = R7 { r7field :: Int }\n"
                "r7Helper = R7 { r7field = 1 }\n")},
            GOOD_CABAL, _good_inventory(), workflows)
        expect("main-tree-records-passes", not fails_out,
               repr(fails_out))

        # Round-7 import pins: every new module or name fails
        # until reviewed into the pin.
        for tag, main_text, inv in (
                ("new-module",
                 GOOD_MAIN.replace(
                     "import qualified FooSpec\n",
                     "import qualified FooSpec\n"
                     "import Evil (evilTree)\n"),
                 _good_inventory()),
                ("new-name",
                 GOOD_MAIN.replace(
                     "import Helper (help)\n",
                     "import Helper (help, evilTree)\n"),
                 _good_inventory()),
                ("hiding",
                 GOOD_MAIN.replace(
                     "import Test.Tasty (defaultMain, testGroup)\n",
                     "import Test.Tasty hiding (testGroup)\n"),
                 _good_inventory()),
                ("whole",
                 GOOD_MAIN.replace(
                     "import Test.Tasty (defaultMain, testGroup)\n",
                     "import Test.Tasty\n"),
                 _good_inventory()),
                ("qual-evil",
                 GOOD_MAIN.replace(
                     "import qualified FooSpec\n",
                     "import qualified FooSpec\n"
                     "import qualified Evil\n"),
                 _good_inventory()),
                ("spec-extra-name",
                 GOOD_MAIN.replace(
                     "import qualified FooSpec\n",
                     "import FooSpec (spec, evilTree)\n"),
                 _good_inventory())):
            fails_out, _ = run_fixture(
                tmp + f"/r7imp{tag}",
                {"tests/alpha/Main.hs": main_text},
                GOOD_CABAL, inv, workflows)
            expect(f"main-imports-{tag}-fails",
                   fails_out == ["MAIN-IMPORTS-suite-a"],
                   repr(fails_out))

        dot_inv = _good_inventory()
        dot_inv["suites"][0]["allowed_imports"]["Helper"] = [
            "help", "Help"]
        fails_out, _ = run_fixture(
            tmp + "/r7impdotdot",
            {"tests/alpha/Main.hs": GOOD_MAIN.replace(
                "import Helper (help)\n",
                "import Helper (Help (..))\n")},
            GOOD_CABAL, dot_inv, workflows)
        expect("main-imports-dotdot-fails",
               fails_out == ["MAIN-IMPORTS-suite-a"],
               repr(fails_out))

        nopin_inv = _good_inventory()
        del nopin_inv["suites"][0]["allowed_imports"]
        fails_out, _ = run_fixture(
            tmp + "/r7impnopin", mains, GOOD_CABAL, nopin_inv,
            workflows)
        expect("main-imports-missing-fails",
               fails_out == ["MAIN-IMPORTS-suite-a"],
               repr(fails_out))

        strpin_inv = _good_inventory()
        strpin_inv["suites"][0]["allowed_imports"] = "Test.Tasty"
        fails_out, _ = run_fixture(
            tmp + "/r7impstrpin", mains, GOOD_CABAL, strpin_inv,
            workflows)
        expect("main-imports-nondict-fails",
               fails_out == ["MAIN-IMPORTS-suite-a"],
               repr(fails_out))

        # Round-8: comments are whitespace (comment-gap imports
        # stay visible), `.spec` resolves to its owner, and
        # module sources resolve per directory.
        fails_out, _ = run_fixture(
            tmp + "/r8gap",
            {"tests/alpha/Main.hs": GOOD_MAIN.replace(
                "import qualified FooSpec\n",
                "import qualified FooSpec\n"
                "import{- -}qualified Evil\n")},
            GOOD_CABAL, _good_inventory(), workflows)
        expect("main-imports-gap-evil-fails",
               fails_out == ["MAIN-IMPORTS-suite-a"],
               repr(fails_out))

        fails_out, _ = run_fixture(
            tmp + "/r8gapspec",
            {"tests/alpha/Main.hs": GOOD_MAIN.replace(
                "import qualified FooSpec\n",
                "import{- -}qualified FooSpec\n")},
            GOOD_CABAL, _good_inventory(), workflows)
        expect("main-imports-gap-spec-passes", not fails_out,
               repr(fails_out))

        fails_out, _ = run_fixture(
            tmp + "/r8newspec",
            {"tests/alpha/Main.hs": GOOD_MAIN.replace(
                "import qualified FooSpec\n",
                "import\n  qualified FooSpec\n")},
            GOOD_CABAL, _good_inventory(), workflows)
        expect("main-imports-newline-spec-passes", not fails_out,
               repr(fails_out))

        fails_out, _ = run_fixture(
            tmp + "/r8mainspec",
            {"tests/alpha/Main.hs": _fixture_main(
                focus=f"[FooSpec.spec, {PAD_RUN}, Main.spec]",
                extra="Main.spec = unpinnedTree\n")},
            GOOD_CABAL, _good_inventory(), workflows)
        expect("main-tree-mainspec-fails",
               fails_out == ["MAIN-NO-INLINE-suite-a"],
               repr(fails_out))

        def add_shadow_dir(root):
            other = root / "tests" / "beta"
            other.mkdir(parents=True, exist_ok=True)
            (other / "FooSpec.hs").write_text(
                "module FooSpec where\n")

        run_fixture(tmp + "/r8modsrc", mains, GOOD_CABAL,
                    _good_inventory(), workflows,
                    mutate=add_shadow_dir)
        from_root = Path(tmp + "/r8modsrc")
        got = module_source(from_root, ["tests/alpha"], "FooSpec")
        expect("module-source-resolves",
               got == from_root / "tests" / "alpha" / "FooSpec.hs",
               repr(got))
        first = module_source(from_root, ["tests/alpha", "tests/beta"],
                              "FooSpec")
        expect("module-source-prefers-first-dir",
               first == from_root / "tests" / "alpha" / "FooSpec.hs"
               and first != from_root / "tests" / "beta" / "FooSpec.hs",
               repr(first))

        beta_main = ("-- REGISTRATION: suite-b\n"
                     "module Main (main) where\n"
                     "import Test.Tasty (defaultMain, testGroup)\n"
                     "import Test.Tasty.HUnit (testCase)\n"
                     "main :: IO ()\n"
                     "main = defaultMain $ testGroup \"beta\" "
                     "[testCase \"inline leaf\" (pure ())]\n")
        beta_cabal = {"suite-b": {"dirs": ["tests/beta"],
                                 "modules": [], "main": "Main.hs"}}
        beta_inv = {"schema": "haskoki-suite-inventory/1", "suites": [
            {"name": "suite-b", "main": "tests/beta/Main.hs",
             "modules": [], "required_groups": ["beta"],
             "module_groups": {},
             "allowed_imports": {
                 "Test.Tasty": ["defaultMain", "testGroup"],
                 "Test.Tasty.HUnit": ["testCase"]},
             "executed_by": [{"workflow": ".github/workflows/ci.yml",
                              "job": "haskell"}]}]}
        fails_out, _ = run_fixture(
            tmp + "/scaffold", {"tests/beta/Main.hs": beta_main},
            beta_cabal, beta_inv, workflows)
        expect("main-inline-exempts-empty-suite",
               fails_out == ["SPECS-COUNT"], repr(fails_out))

    if fails:
        print(f"test-wiring self-test: FAIL ({', '.join(fails)})")
        return 1
    print(f"test-wiring self-test: OK ({len(ran)} controls)")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description="test-wiring gate")
    ap.add_argument("--root", default=str(REPO))
    ap.add_argument("--inventory", default=None)
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args(argv)
    if args.self_test:
        return self_test()
    root = Path(args.root)
    if args.inventory:
        inv = Path(args.inventory)
    else:
        inv = root / "tests" / "suite-inventory.json"
    global failures
    failures = []
    fails, stats = check_tree(root, inv)
    if fails:
        print(f"test-wiring: FAIL ({len(fails)} rule(s))")
        return 1
    print(f"test-wiring: OK ({stats['specs']} specs wired across "
          f"{stats['suites']} suites)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
