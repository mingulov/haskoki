#!/usr/bin/env python3
"""Test-evidence linkage gate: every (artifact, case_id) pair cited in
spec/mechanisms.json `test_evidence` must resolve to a real executable
suite module AND a machine-readable acceptance token.

For each distinct pair `suite/Module` + `case_id`:

1. `suite` must be a real `test-suite` stanza in haskoki.cabal, `Module`
   must belong to that suite's declared executable module set
   (`other-modules` + `main-is` — the exact set the suite compiles),
   and `Module.hs` must exist under one of that suite's
   `hs-source-dirs`. Artifacts with absolute paths or parent-directory
   (`..`) components are rejected outright. (Per-suite wiring of each
   declared module to Main is pinned separately by
   scripts/check-test-wiring.py, which runs in the same gate step: a
   module in the suite set but unwired fails THERE.)
2. `case_id` must be accepted by that module file via a token:
     -- ACCEPTS: A42            (line comment; several ids allowed:
     -- ACCEPTS: A20, A22, A23   comma/space separated, several lines allowed)
   or the block form `{- ACCEPTS: A40 -}`. Tokens are extracted from
   Haskell comments ONLY (line comments, nesting block comments);
   string/character literals and quasiquote bodies are skipped, so a
   decoy such as `x = "ACCEPTS: A99"` mints no token. When in doubt
   the scanner emits NO token, or refuses the file outright on
   ambiguous bracket-bar spans (fail-closed: the author rewrites).
   Failures name the dangling id and exit nonzero.

Transitional registry: the pairs cited before tokens existed are
listed in TRANSITIONAL_KNOWN_PAIRS with module resolution still fully
enforced. A pair outside BOTH the tokens and the registry fails. Never
extend the registry: add the `-- ACCEPTS:` token to the spec file and
delete the entry here (the OK line counts token- vs registry-resolved
pairs so the migration is trackable). Retirement is self-enforcing: a
pair present in BOTH tokens and registry FAILS the live gate
("exemption not retired"), and the self-test pins the approved legacy
membership and fails if the live registry is not a subset of it.

STDLIB ONLY. Run on HOST python3 from anywhere:
  python3 scripts/check-test-evidence.py [--root DIR]
        [--mechanisms PATH] [--self-test]
The --root/--mechanisms overrides exist for scratch negative controls
(a typoed case_id / a deleted token must fail); --self-test runs the
repo-pattern durable controls (cf. check-actions-pinned.py).
"""

import argparse
import itertools
import json
import re
import sys
import tempfile
import unicodedata
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

RX_CASE = re.compile(r"^A[0-9]{2}$")
RX_TOKEN_LINE = re.compile(r"ACCEPTS:\s*([A-Za-z0-9][A-Za-z0-9,\s]*)")
RX_TOKEN_ID = re.compile(r"\bA[0-9]{2}\b")
RX_CHAR_LIT = re.compile(r"'([^'\\\n]|\\\^.|\\.)'")
# Haskell identifier constituents per GHC 9.10.3 (fix-3 path-3 sweep):
# segment start Ll/Lo (+Lu/Lt: conid/module position — matched as a
# uniform superset since invalid shapes never compile, so skips there
# are harmless); continue adds Nd/Nl/No/Mn/Lm + "'". Mc/Me/Cf, brackets
# (Ps/Pe/Pi/Pf), symbols (S*/Po/Pd/non-ASCII Pc), digits/Mn/Lm at start
# are rejected by GHC (lexical/parse errors) and excluded.
_ID_START_CATS = frozenset({"Ll", "Lu", "Lt", "Lo"})
_ID_CONT_CATS = frozenset({"Ll", "Lu", "Lt", "Lo", "Nd", "Nl", "No",
                            "Mn", "Lm"})
# Haskell ASCII operator constituents. Comment-vs-operator for a dash
# run is decided by the char AFTER the run (see extract_comment_text):
# symbol char -> operator (`-->`, `--+x`, `---+`); anything else ->
# line comment (`-- x`, `--x`, `---x`, haddock `-- |`/`-- ^`/`-- *`).
SYMBOL_CHARS = set("!#$%&*+./<=>?@\\^|-~:")
# Gap whitespace accepted by GHC inside string gaps (compiler-probed:
# space, tab, CR, LF, VT, FF; NBSP and other Unicode spaces rejected).
GAP_WS = " \t\n\r\v\f"
# Max bracket-bar recursion depth inside one TH span end-scan (fix 4):
# the recursive span model trips LOUDLY past this depth rather than
# mis-scan. Generous: real code nests a handful deep (3 proved
# lexically; GHC rejects un-spliced TH-in-TH outright, and even valid
# spliced nesting past a few levels never occurs), and in-tree has
# zero quasiquotes at all — the cap binds only adversarial shapes.
QQ_NEST_CAP = 32


def _is_symbol(ch):
    """Haskell operator-constituent char per GHC's lexer.

    ASCII symbols plus Unicode general categories Sm/Sc/Sk/So (fix 2)
    and Po/Pd/Pc (fix 3): GHC accepts `¡--`, `¿--`, `—--`, `‿--`,
    `＿--` as single operator lexemes. ASCII `_` (U+005F, Pc) stays an
    identifier char: the ASCII path below never consults categories,
    so the underscore exclusion is structural. Every other category
    (letters, digits, marks Mn/Mc/Me, Lm, brackets Ps/Pe/Pi/Pf,
    spaces, controls, format, private-use, unassigned) is NOT a
    symbol — each pinned by the fix-3 category sweep.
    """
    if ch in SYMBOL_CHARS:
        return True
    if ord(ch) < 128:
        return False
    return unicodedata.category(ch) in ("Sm", "Sc", "Sk", "So",
                                        "Po", "Pd", "Pc")


def _is_id_start(ch):
    """First char of a Haskell identifier segment (GHC 9.10.3)."""
    if ch == "_" or "a" <= ch <= "z" or "A" <= ch <= "Z":
        return True
    if ord(ch) < 128:
        return False
    return unicodedata.category(ch) in _ID_START_CATS


def _is_id_cont(ch):
    """Non-first char of a Haskell identifier segment (GHC 9.10.3)."""
    if ch == "_" or ch == "'" or "a" <= ch <= "z" \
            or "A" <= ch <= "Z" or "0" <= ch <= "9":
        return True
    if ord(ch) < 128:
        return False
    return unicodedata.category(ch) in _ID_CONT_CATS


def _match_qq_open(text, i):
    """`(end, is_bare_th)` for the QQ/TH opener at text[i] == "[".

    Opener = "[" + dotted identifier segments + "|" with NO spaces
    (GHC rejects every spaced variant). Segments use the full GHC
    identifier classes (ASCII varid/conid plus Unicode Ll/Lu/Lt/Lo
    start, +Nd/Nl/No/Mn/Lm/' continue); module-vs-quoter case is not
    distinguished (uniform superset — invalid shapes never compile,
    so skipping them is harmless). Returns None when text[i] opens no
    bracket-bar span (`[|`, `[||`, comprehensions with spaces, plain
    lists). `is_bare_th` = unqualified single-letter e/d/t/p bracket.
    """
    j, n = i + 1, len(text)
    segments = 0
    first = None
    while True:
        if j >= n or not _is_id_start(text[j]):
            return None
        k = j + 1
        while k < n and _is_id_cont(text[k]):
            k += 1
        segments += 1
        if segments == 1:
            first = text[j:k]
        j = k
        if j + 1 < n and text[j] == "." and _is_id_start(text[j + 1]):
            j += 1
            continue
        break
    if j >= n or text[j] != "|":
        return None
    return (j + 1, segments == 1 and first in ("e", "d", "t", "p"))

# TRANSITIONAL (F-11): pairs cited in spec/mechanisms.json before
# `-- ACCEPTS:` tokens existed in the spec files. Module resolution
# is fully enforced for these; only the token leg is deferred, one
# entry per pair, deleted as tokens land. DO NOT EXTEND: a new pair
# must ship its token in the spec file instead. Token-bearing pairs
# MUST retire their entries (live gate fails "exemption not retired"
# if a pair sits in both tokens and registry).
TRANSITIONAL_KNOWN_PAIRS = frozenset({
    ("haskoki-engine-tests/OpenSSLSpec", "A37"),
    ("haskoki-engine-tests/OpenSSLSpec", "A39"),
    ("haskoki-engine-tests/RoutingE2ESpec", "A39"),
    ("haskoki-engine-tests/SyntheticSpec", "A16"),
    ("haskoki-engine-tests/SyntheticSpec", "A37"),
    ("haskoki-model-tests/KeyManagementSpec", "A20"),
    ("haskoki-model-tests/KeyManagementSpec", "A22"),
    ("haskoki-model-tests/KeyManagementSpec", "A23"),
    ("haskoki-model-tests/KeyManagementSpec", "A37"),
    ("haskoki-model-tests/KeyManagementSpec", "A39"),
    ("haskoki-model-tests/OperationSpec", "A16"),
    ("haskoki-model-tests/RecipeByteOpsSpec", "A40"),
    ("haskoki-model-tests/RecipeCbcMacSpec", "A40"),
    ("haskoki-model-tests/RecipeCcmSpec", "A40"),
    ("haskoki-model-tests/RecipeCipherSpec", "A40"),
    ("haskoki-model-tests/RecipeCmacSpec", "A40"),
    ("haskoki-model-tests/RecipeDes3MacSpec", "A40"),
    ("haskoki-model-tests/RecipeDhSpec", "A40"),
    ("haskoki-model-tests/RecipeDsaSpec", "A40"),
    ("haskoki-model-tests/RecipeEcdhSpec", "A40"),
    ("haskoki-model-tests/RecipeEcdsaSpec", "A40"),
    ("haskoki-model-tests/RecipeEddsaSpec", "A40"),
    ("haskoki-model-tests/RecipeEncryptDataSpec", "A40"),
    ("haskoki-model-tests/RecipeGcmSpec", "A40"),
    ("haskoki-model-tests/RecipeGmacSpec", "A40"),
    ("haskoki-model-tests/RecipeIkeSpec", "A40"),
    ("haskoki-model-tests/RecipeKdfSpec", "A40"),
    ("haskoki-model-tests/RecipeMlDsaSpec", "A40"),
    ("haskoki-model-tests/RecipeOaepSpec", "A40"),
    ("haskoki-model-tests/RecipeOtpSpec", "A40"),
    ("haskoki-model-tests/RecipePbeSpec", "A40"),
    ("haskoki-model-tests/RecipePoly1305Spec", "A40"),
    ("haskoki-model-tests/RecipePssSpec", "A40"),
    ("haskoki-model-tests/RecipePubPrivSpec", "A40"),
    ("haskoki-model-tests/RecipeRsaSpec", "A40"),
    ("haskoki-model-tests/RecipeRsaX931Spec", "A40"),
    ("haskoki-model-tests/RecipeSlhDsaSpec", "A40"),
    ("haskoki-model-tests/RecipeSp800108Spec", "A40"),
    ("haskoki-model-tests/RecipeSsl3Spec", "A40"),
    ("haskoki-model-tests/RecipeTlsKdfSpec", "A40"),
    ("haskoki-model-tests/RecipeTlsKeyMatSpec", "A40"),
    ("haskoki-model-tests/RecipeTlsPrfSpec", "A40"),
    ("haskoki-model-tests/RecipeWrapCompRsaSpec", "A40"),
    ("haskoki-model-tests/RecipeWrapCompSpec", "A40"),
    ("haskoki-model-tests/RecipeX509Spec", "A40"),
    ("haskoki-model-tests/RecipeXcbcMacSpec", "A40"),
    ("haskoki-model-tests/RegistrySpec", "A40"),
})

# PINNED approved legacy membership (Low 3): the self-test fails if
# TRANSITIONAL_KNOWN_PAIRS is not a subset of this set, so any
# registry addition trips CI. Shrink-only migration (deleting entries
# as tokens land) stays green. Touching this constant to admit a new
# exemption is a shrink-only violation: review-visible by design.
PINNED_APPROVED_REGISTRY = frozenset({
    ("haskoki-engine-tests/OpenSSLSpec", "A37"),
    ("haskoki-engine-tests/OpenSSLSpec", "A39"),
    ("haskoki-engine-tests/RoutingE2ESpec", "A39"),
    ("haskoki-engine-tests/SyntheticSpec", "A16"),
    ("haskoki-engine-tests/SyntheticSpec", "A37"),
    ("haskoki-model-tests/KeyManagementSpec", "A20"),
    ("haskoki-model-tests/KeyManagementSpec", "A22"),
    ("haskoki-model-tests/KeyManagementSpec", "A23"),
    ("haskoki-model-tests/KeyManagementSpec", "A37"),
    ("haskoki-model-tests/KeyManagementSpec", "A39"),
    ("haskoki-model-tests/OperationSpec", "A16"),
    ("haskoki-model-tests/RecipeByteOpsSpec", "A40"),
    ("haskoki-model-tests/RecipeCbcMacSpec", "A40"),
    ("haskoki-model-tests/RecipeCcmSpec", "A40"),
    ("haskoki-model-tests/RecipeCipherSpec", "A40"),
    ("haskoki-model-tests/RecipeCmacSpec", "A40"),
    ("haskoki-model-tests/RecipeDes3MacSpec", "A40"),
    ("haskoki-model-tests/RecipeDhSpec", "A40"),
    ("haskoki-model-tests/RecipeDsaSpec", "A40"),
    ("haskoki-model-tests/RecipeEcdhSpec", "A40"),
    ("haskoki-model-tests/RecipeEcdsaSpec", "A40"),
    ("haskoki-model-tests/RecipeEddsaSpec", "A40"),
    ("haskoki-model-tests/RecipeEncryptDataSpec", "A40"),
    ("haskoki-model-tests/RecipeGcmSpec", "A40"),
    ("haskoki-model-tests/RecipeGmacSpec", "A40"),
    ("haskoki-model-tests/RecipeIkeSpec", "A40"),
    ("haskoki-model-tests/RecipeKdfSpec", "A40"),
    ("haskoki-model-tests/RecipeMlDsaSpec", "A40"),
    ("haskoki-model-tests/RecipeOaepSpec", "A40"),
    ("haskoki-model-tests/RecipeOtpSpec", "A40"),
    ("haskoki-model-tests/RecipePbeSpec", "A40"),
    ("haskoki-model-tests/RecipePoly1305Spec", "A40"),
    ("haskoki-model-tests/RecipePssSpec", "A40"),
    ("haskoki-model-tests/RecipePubPrivSpec", "A40"),
    ("haskoki-model-tests/RecipeRsaSpec", "A40"),
    ("haskoki-model-tests/RecipeRsaX931Spec", "A40"),
    ("haskoki-model-tests/RecipeSlhDsaSpec", "A40"),
    ("haskoki-model-tests/RecipeSp800108Spec", "A40"),
    ("haskoki-model-tests/RecipeSsl3Spec", "A40"),
    ("haskoki-model-tests/RecipeTlsKdfSpec", "A40"),
    ("haskoki-model-tests/RecipeTlsKeyMatSpec", "A40"),
    ("haskoki-model-tests/RecipeTlsPrfSpec", "A40"),
    ("haskoki-model-tests/RecipeWrapCompRsaSpec", "A40"),
    ("haskoki-model-tests/RecipeWrapCompSpec", "A40"),
    ("haskoki-model-tests/RecipeX509Spec", "A40"),
    ("haskoki-model-tests/RecipeXcbcMacSpec", "A40"),
    ("haskoki-model-tests/RegistrySpec", "A40"),
})

def parse_suites(cabal_text):
    """name -> {"dirs": [...], "modules": [...]} for every test-suite.

    "modules" is the suite's declared executable module set:
    other-modules (continuation lines and/or same-line entries) plus
    the main-is stem. Liberal where the stanza has no conditionals;
    stanzas with conditionals are out of scope (none in-tree).
    """
    suites = {}
    cur = None
    field = None
    for line in cabal_text.splitlines():
        m = re.match(r"test-suite\s+(\S+)\s*$", line)
        if m:
            cur = m.group(1)
            suites[cur] = {"dirs": [], "modules": []}
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
                stem = rest[:-3] if rest.endswith(".hs") else rest
                suites[cur]["modules"].append(stem)
            elif field == "other-modules" and rest:
                suites[cur]["modules"].extend(rest.split())
            continue
        m = re.match(r"\s+(\S+)\s*$", line)
        if m and field == "other-modules":
            suites[cur]["modules"].append(m.group(1))
    return suites


class _Refusal(Exception):
    """Loud fail-closed trip: the module holds a bracket-bar span
    whose code-vs-data extent the gate cannot bound exactly (buried
    `|]`, ambiguous TH/raw reading, or an unmodelable resume). Never
    silenced: check_tree records it as a gate failure naming the file.
    The author rewrites to disambiguate."""


def _skip_string(text, j):
    """Index just past the string closing quote opened at text[j].

    Shared escape dispatcher (fix 2, GHC-probed): `\\^X` takes 3
    chars, gaps (`\\` + GAP_WS+ + `\\`) are consumed whole with the
    string CONTINUING, every other escape takes 2; a trailing
    backslash, an unclosed gap, or a missing close swallows the tail.
    """
    n = len(text)
    j += 1
    while j < n:
        c = text[j]
        if c == "\\":
            if j + 1 >= n:
                return n
            e = text[j + 1]
            if e == "^" and j + 2 < n:
                j += 3
            elif e in GAP_WS:
                k = j + 1
                while k < n and text[k] in GAP_WS:
                    k += 1
                if k < n and text[k] == "\\":
                    j = k + 1
                else:
                    return n
            else:
                j += 2
        elif c == '"':
            return j + 1
        else:
            j += 1
    return j


def _skip_block(text, j):
    """Index just past the `-}` closing the comment at text[j]."""
    n = len(text)
    depth = 0
    while j < n:
        if text[j:j + 2] == "{-":
            depth += 1
            j += 2
        elif text[j:j + 2] == "-}":
            depth -= 1
            j += 2
            if depth == 0:
                break
        else:
            j += 1
    return j


def _dash_run_end(text, i):
    """End of the `-` run starting at text[i] (`--` seen)."""
    n = len(text)
    j = i + 2
    while j < n and text[j] == "-":
        j += 1
    return j


def _r_context(text, start, r):
    """Code-lexical context of the raw `|]` at index r.

    Lexes text[start:r] as code (strings, strict chars, `--` line and
    `{- -}` block comments skipped); returns "string", "char",
    "line", or "block" when r falls inside such a lexeme, else
    "code". An operator run covering r counts as code (runs never
    hold `]`, so r is the run's closing `|`). Depth is untracked: only
    the lexeme kind at r matters.
    """
    n = len(text)
    j = start
    while j < r:
        two = text[j:j + 2]
        if two == "--":
            k = _dash_run_end(text, j)
            nxt = text[k] if k < n else ""
            if nxt == "" or not _is_symbol(nxt):
                nl = text.find("\n", j)
                end = n if nl == -1 else nl
                if r < end:
                    return "line"
                j = end + 1
            else:
                while k < n and _is_symbol(text[k]):
                    k += 1
                j = k
        elif two == "{-":
            end = _skip_block(text, j)
            if r < end:
                return "block"
            j = end
        elif text[j] == '"':
            end = _skip_string(text, j)
            if r < end:
                return "string"
            j = end
        elif text[j] == "'":
            m = RX_CHAR_LIT.match(text, j)
            end = m.end() if m else j + 1
            if m is not None and r < end:
                return "char"
            j = end
        elif _is_symbol(text[j]):
            # Maximal-munch operator run (mirrors the main scan): a
            # `--` inside a run (x¡-- ...) never starts a comment.
            while j < r and _is_symbol(text[j]):
                j += 1
        else:
            j += 1
    return "code"


def _qq_span_end(text, start, level=1):
    """Quote-aware end of the TH `[e|d|t|p|` span opened before `start`.

    Lexes the body as Haskell code (the TH rule, GHC-nesting): strings
    via the shared dispatcher, strict chars, `--` line comments (the
    dash-run rule), nesting `{- -}` block comments, plain `[`/`]`
    depth (a bare `]` never drops below 1, so Bb11 raw bodies still
    bound), and nested bracket-bar spans resolved RECURSIVELY — on
    meeting an inner `[name|` opener the inner span's end is
    determined FIRST (raw rule for quasiquotes: the raw-first `|]`,
    quotes/comments inside raw bodies are data and never tracked;
    recursion for TH brackets) and skipped past as an opaque unit
    before the outer scan continues (fix 4: the flat scan misread
    quotes inside nested raw bodies as string opens). `level` is the
    bracket-bar recursion depth: nesting past QQ_NEST_CAP raises
    _Refusal rather than mis-scan. Returns the index of the `|]`
    terminating the span at depth 1, or None when no code-level end
    exists (every `|]` sits inside a string/char/comment, or the span
    never ends). Raw quasiquotes never consult this scan (their
    bodies are raw text); they disambiguate via _r_context instead.
    """
    n = len(text)
    depth = 1
    j = start
    while j < n:
        two = text[j:j + 2]
        if two == "--":
            k = _dash_run_end(text, j)
            nxt = text[k] if k < n else ""
            if nxt == "" or not _is_symbol(nxt):
                nl = text.find("\n", j)
                j = n if nl == -1 else nl + 1
            else:
                while k < n and _is_symbol(text[k]):
                    k += 1
                j = k
        elif two == "{-":
            j = _skip_block(text, j)
        elif text[j] == '"':
            j = _skip_string(text, j)
        elif text[j] == "'":
            m = RX_CHAR_LIT.match(text, j)
            j = m.end() if m else j + 1
        elif two == "|]":
            if depth == 1:
                return j
            depth -= 1
            j += 2
        elif text[j] == "[":
            m = _match_qq_open(text, j)
            if m is None:
                depth += 1
                j += 1
                continue
            if level + 1 > QQ_NEST_CAP:
                raise _refusal_at(
                    text, j, "bracket-bar nesting past depth "
                    f"{QQ_NEST_CAP} inside a TH bracket span: "
                    "extent ambiguous; rewrite to disambiguate")
            inner_start, inner_is_th = m
            if inner_is_th:
                e = _qq_span_end(text, inner_start, level + 1)
                if e is None:
                    return None
            else:
                # Raw inner: the raw-first |] ends it — bodies are
                # raw text, quotes/comments inside are data (fix 4).
                e = text.find("|]", inner_start)
                if e == -1:
                    return None
            j = e + 2
        elif text[j] == "]":
            if depth > 1:
                depth -= 1
            j += 1
        elif _is_symbol(text[j]):
            # Maximal-munch operator run (mirrors the main scan):
            # runs hold no brackets, quotes, or |] (a |] is matched
            # above first), so the end search skips them whole.
            while j < n and _is_symbol(text[j]):
                j += 1
        else:
            j += 1
    return None


def _region_has_opaque(text, a, b):
    """Fresh code-lex of text[a:b]: `[`/`{-` outside strings/chars?

    Resume-lexing guard for TH spans. Under the raw-quasiquote reading
    GHC ends the span at the FIRST `|]` and resumes here as code; a
    bracket or block-comment opener in the resumed region
    desynchronizes everything past it, so such spans are refused
    rather than skipped.
    """
    j = a
    while j < b:
        if text[j] == '"':
            j = _skip_string(text, j)
            if j > b:
                return False
        elif text[j] == "'":
            m = RX_CHAR_LIT.match(text, j)
            j = m.end() if m else j + 1
            if j > b:
                return False
        elif text[j:j + 2] == "{-":
            return True
        elif text[j] == "[":
            return True
        else:
            j += 1
    return False


def _line_has_comment_op(text, j):
    """Fresh code-lex to EOL: `--` comment or `{-` outside strings?

    Post-span guard for TH spans. Under the raw-quasiquote reading
    GHC resumes the span's line inside a line comment; a comment
    opener the gate would mint from is code-vs-data ambiguous, so the
    file is refused rather than skipped.
    """
    n = len(text)
    while j < n and text[j] != "\n":
        if text[j] == '"':
            j = _skip_string(text, j)
        elif text[j] == "'":
            m = RX_CHAR_LIT.match(text, j)
            j = m.end() if m else j + 1
        elif text[j:j + 2] == "--":
            k = _dash_run_end(text, j)
            nxt = text[k] if k < n else ""
            if nxt == "" or not _is_symbol(nxt):
                return True
            while k < n and _is_symbol(text[k]):
                k += 1
            j = k
        elif _is_symbol(text[j]):
            # Maximal-munch operator run (mirrors the main scan): a
            # `--` inside a run never starts a comment.
            while j < n and _is_symbol(text[j]):
                j += 1
        elif text[j:j + 2] == "{-":
            return True
        else:
            j += 1
    return False


def _refusal_at(text, pos, why):
    line = text.count("\n", 0, pos) + 1
    return _Refusal(f"line {line}: {why}")


def extract_comment_text(module_text):
    """Concatenated `--` / `{- -}` comment spans of a Haskell module.

    GHC-9.10.3-derived lexical subset (every rule compiler-probed;
    verdict tables in task-912-fix2-report.md and task-912-fix3-report.md):

    * `--` line comments: at a `-` starting a symbol run, scan the
      dash run; the char AFTER the run decides. Symbol char -> the
      run opens a maximal-munch OPERATOR (`-->`, `--+x`, `---+`,
      `--->`, `--→`, `:--`); anything else (space, letter, digit,
      EOF) -> LINE COMMENT to EOL (`-- x`, `--x`, `---x`, `----`,
      haddock `-- |`, `-- ^`, `-- *`).
    * Other operator lexemes: a symbol char (ASCII SYMBOL_CHARS or
      Unicode Sm/Sc/Sk/So/Po/Pd/Pc minus `_`) starts a maximal-munch
      run from its FIRST char; the run may contain `--` inside
      (`+--`, `+---+`, `→--`, `¡--`, `—--`, `‿--`) which must not
      misfire as a comment. Letters (incl. `α`), `_`, and digits
      never start runs.
    * `"..."` strings via an explicit escape dispatcher: `\"`, `\\`,
      single-char escapes, `\\&`, `\\^X` (3 chars), named/decimal/hex/
      octal escapes (bodies hold no quote/backslash); gaps (`\\` +
      GAP_WS+ + `\\`, newline NOT required) are consumed whole and
      the string CONTINUES — the next `"` still closes. A gap
      without its closing backslash is rejected by GHC; the scan
      then swallows the tail (fail-closed: miss, never mint).
    * `'c'` char literals in strict shape only (`\\'`, `\\\\`, `\\^X`
      included; a lone `'` is an identifier prime). GHC rejects
      gaps in chars, so none are handled.
    * `[name|...|]` quasiquotes/TH brackets: the opener is `[` +
      dotted identifier (`qq`, `Q.qq`, `A.B.qq`, `α`, `M.α`, `中`, ...)
      + `|` with NO spaces (GHC rejects every spaced variant).
      Bracket KIND decides the end rule. Raw quasiquotes end at the
      FIRST `|]` (GHC neither nests raw bodies nor sees strings
      inside them; bare `]`s are body text). TH brackets
      (unqualified `[e|`, `[d|`, `[t|`, `[p|]`, whose bodies are real
      code) end at the first `|]` OUTSIDE nested strings, chars,
      comments, and nested brackets — GHC nests bracket-bar spans —
      so a `|]` buried in a string (`[e|"|] -- ACCEPTS: A99"|]`) or
      comment never ends the span early. Nested spans resolve
      recursively: an inner `[q|...|]` ends at its raw-first `|]`
      (quotes/comments inside are data, never tracked) and is
      skipped as an opaque unit before the outer scan continues;
      nesting past QQ_NEST_CAP (32) trips loudly. Their code
      content is still skipped as data (miss-only, fail-closed).
      `[|`/`[||` (old and
      typed TH brackets) match no opener and lex as code, which is
      exact since their bodies ARE code.
    * Ambiguous bracket-bar spans are REFUSED (loud fail-closed trip
      naming the file and line — the author rewrites). Raw
      quasiquotes: the first `|]` buried in a string or block
      comment (a comprehension followed by `"|]` data, or a Bb10
      raw body with an early quote — skipping desyncs, scanning
      mints), or a line-comment-buried `|]` whose resumed line holds
      a comment opener or a quote (either desynchronizes the fresh
      lexer past the line). TH brackets: no code-level `|]` end at
      all, a code-level end inside a resumed string/char literal
      (gap-aware) or block comment, a code-level end inside a resumed
      line comment with a quote past it on the line (a quoteless
      tail resumes exactly — unconditional line refusal would trip
      valid TH shapes such as `[e| "|] ..." |]`), a nested `[`/`{-`
      in the raw-reading resume, a same-line comment past the
      code-level end, or nesting past the depth cap. With NO `|]` ahead
      at all the text is a
      no-space list comprehension (`[x|x <- xs]` — GHC ACCEPTS with
      QuasiQuotes off) and is scanned as code; an unterminated
      quasiquote is a GHC hard error, so minting there is possible
      only in uncompilable files. LOCKED (deviation from the brief's
      trip-or-skip menu, forced by GHC: both menu options would
      false-reject valid `[x|...]` comprehensions).

    CPP and other exotic forms are out of scope (neither is used
    in-tree); unknown text is scanned as code. Inputs are assumed
    compilable: an unterminated string swallows the tail, while
    comment detection only fires outside strings, chars, and
    quasiquotes — so skipped regions can only MISS a token, never
    mint one. Raises _Refusal on ambiguous spans (fail closed).
    """
    spans = []
    i, n = 0, len(module_text)
    while i < n:
        two = module_text[i:i + 2]
        if two == "--":
            # Dash run: the char AFTER the run decides (GHC rule).
            j = _dash_run_end(module_text, i)
            nxt = module_text[j] if j < n else ""
            if nxt == "" or not _is_symbol(nxt):
                k = module_text.find("\n", i)
                if k == -1:
                    k = n
                spans.append(module_text[i:k])
                i = k
            else:
                # Operator: maximal symbol run from the run start.
                while j < n and _is_symbol(module_text[j]):
                    j += 1
                i = j
        elif two == "{-":
            j = _skip_block(module_text, i)
            spans.append(module_text[i:j])
            i = j
        elif module_text[i] == '"':
            # Skipped: strings never contribute tokens.
            i = _skip_string(module_text, i)
        elif module_text[i] == "'":
            m = RX_CHAR_LIT.match(module_text, i)
            i = m.end() if m else i + 1  # strict char, else prime
        elif module_text[i] == "[":
            m = _match_qq_open(module_text, i)
            if m is None:
                i += 1
                continue
            open_end, is_bare_th = m
            r = module_text.find("|]", open_end)
            if r == -1:
                # No terminator: no-space comprehension when
                # QuasiQuotes is off (scan as code — correct on
                # every compilable input); unterminated QQ/TH when
                # on (GHC hard error — uncompilable). LOCKED (fix 2).
                i += 1
                continue
            if not is_bare_th:
                # Raw quasiquote: the TRUE end is always the raw
                # first |] (GHC ignores nesting, strings, and
                # comments in raw bodies). Only code-vs-QQ is at
                # stake, decided by R's code-lexical context.
                ctx = _r_context(module_text, open_end, r)
                if ctx == "code":
                    # R is code-level: a real QQ ends here, and pure
                    # code never holds |] (a `|` demands a following
                    # qual/guard/operand; `]` provides none — parse
                    # error). Skip either way.
                    i = r + 2
                    continue
                if ctx == "line":
                    # R sits in a line comment: a real QQ still ends
                    # at R, but the resume runs mid-comment to EOL —
                    # refuse if the gate could mint from that line (a
                    # comment opener) or desynchronize past it (a quote
                    # opens a phantom string in the fresh code-lexer
                    # regardless of openers — fix 5, same mechanism as
                    # the TH resumed-comment refusal).
                    resume_end = module_text.find("\n", r + 2)
                    resumed = module_text[r + 2:len(module_text)
                                          if resume_end == -1 else resume_end]
                    if ('"' in resumed
                            or _line_has_comment_op(module_text, r + 2)):
                        raise _refusal_at(
                            module_text, i, "quasiquote span resumes "
                            "mid-line-comment into a comment opener or "
                            "quote: code-vs-data ambiguous; rewrite to "
                            "disambiguate")
                    i = r + 2
                    continue
                # R buried in a string/char/block comment:
                # comprehension-vs-quasiquote is ambiguous (skipping
                # desynchronizes, scanning mints). Refuse.
                raise _refusal_at(
                    module_text, i, "bracket-bar opener whose first "
                    "`|]` is inside a string/block-comment: "
                    "comprehension-vs-quasiquote ambiguous; rewrite "
                    "to disambiguate")
            q = _qq_span_end(module_text, open_end)
            if q is None:
                # No code-level end: every |] is buried in a
                # string/comment. Skipping desynchronizes, scanning
                # mints. Refuse (fail closed).
                raise _refusal_at(
                    module_text, i, "TH bracket span with no "
                    "code-level `|]` end (first `|]` is inside a "
                    "string/comment): code-vs-data ambiguous; "
                    "rewrite to disambiguate")
            rctx = _r_context(module_text, r + 2, q)
            if rctx in ("string", "char"):
                # The selected end sits inside a string/char literal
                # of the raw-reading resume (gap-aware: _r_context
                # shares the main string dispatcher, so a gap
                # continuation still counts as inside). Skipping
                # desynchronizes, scanning mints. Refuse (fix 4).
                raise _refusal_at(
                    module_text, i, "TH bracket span end inside a "
                    "resumed string/character literal (raw-reading "
                    "resume, gaps included): code-vs-data ambiguous; "
                    "rewrite to disambiguate")
            if rctx == "block":
                # The selected end sits inside a block comment of the
                # raw-reading resume: the fresh lexer would restart as
                # code inside comment text whose end + nesting the gate
                # cannot bound, desynchronizing at comment quotes
                # (simple shapes already trip the opaque guard below;
                # the guard below misses comment-quote-paired resumes
                # — fix 5). Refuse.
                raise _refusal_at(
                    module_text, i, "TH bracket span end inside a "
                    "resumed block comment (raw-reading resume): "
                    "code-vs-data ambiguous; rewrite to disambiguate")
            if rctx == "line":
                # The selected end sits inside a line comment of the
                # raw-reading resume. A quote anywhere in the resumed
                # tail (rest of the line) opens a phantom string in
                # the fresh code-lexer regardless of comment openers,
                # so quotey tails refuse; a quoteless tail resumes
                # exactly (comment text without quotes or openers
                # scans to EOL with miss-only deviations). Refusing
                # all line-buried ends is infeasible: valid TH shapes
                # (f3t-e/p/t/d, f3t-blockcomment, f4-deep3) resume
                # line-buried with clean tails (fix-5 enumeration).
                tail_end = module_text.find("\n", q + 2)
                tail = module_text[q + 2:len(module_text)
                                   if tail_end == -1 else tail_end]
                if '"' in tail:
                    raise _refusal_at(
                        module_text, i, "TH bracket span end inside a "
                        "resumed line comment with a quote past the "
                        "end (raw-reading resume): code-vs-data "
                        "ambiguous; rewrite to disambiguate")
            if q == r:
                i = r + 2  # skipped: span is data
                continue
            if _region_has_opaque(module_text, r + 2, q):
                # TH span whose raw-reading resume holds a bracket
                # or block-comment opener: GHC cannot rejoin the
                # resume past the code-level end. Refuse.
                raise _refusal_at(
                    module_text, i, "TH bracket span holds a nested "
                    "bracket/block-comment between its string-buried "
                    "and code-level `|]`: extent ambiguous; rewrite "
                    "to disambiguate")
            if _line_has_comment_op(module_text, q + 2):
                # TH span whose line continues into a comment: under
                # the raw reading GHC resumes inside a comment while
                # the gate would mint. Refuse (fail closed).
                raise _refusal_at(
                    module_text, i, "TH bracket span resumes into a "
                    "same-line comment: code-vs-data ambiguous; "
                    "rewrite to disambiguate")
            i = q + 2  # skipped: span is data
        elif _is_symbol(module_text[i]):
            # Maximal-munch operator lexeme from its FIRST symbol
            # char (`+--`, `:--`, `→--`, ...): `--` inside a run is
            # operator text, never a comment.
            j = i + 1
            while j < n and _is_symbol(module_text[j]):
                j += 1
            i = j
        else:
            i += 1
    return "\n".join(spans)


def accepted_ids(module_text):
    """Case ids claimed by -- ACCEPTS: / {- ACCEPTS: -} COMMENT tokens."""
    ids = set()
    for m in RX_TOKEN_LINE.finditer(extract_comment_text(module_text)):
        ids.update(RX_TOKEN_ID.findall(m.group(1)))
    return ids


def resolve_module(root, suites, artifact):
    """(suite, module, path-or-None, error-or-None) for an artifact."""
    if artifact.startswith("/") or artifact.startswith("\\"):
        return None, None, None, (
            f"rejected artifact {artifact!r} (absolute path)")
    if any(seg == ".." for seg in re.split(r"[\\/]", artifact)):
        return None, None, None, (
            f"rejected artifact {artifact!r} "
            f"(parent-directory '..' component)")
    if "/" not in artifact:
        return None, None, None, f"malformed artifact {artifact!r} (want suite/Module)"
    suite, mod = artifact.split("/", 1)
    if suite not in suites:
        return suite, mod, None, f"unknown suite {suite!r}"
    if mod not in suites[suite]["modules"]:
        return suite, mod, None, (
            f"module {mod!r} not compiled into suite {suite!r} "
            f"(not in its other-modules/main-is set)")
    for d in suites[suite]["dirs"]:
        cand = root / d / (mod + ".hs")
        if cand.is_file():
            return suite, mod, cand, None
    return suite, mod, None, (
        f"unknown spec module {mod!r} in suite {suite!r} "
        f"(no {mod}.hs under {', '.join(suites[suite]['dirs']) or 'no dirs'})")


def check_tree(root, mech_path, registry=None):
    """Run the linkage check. Returns (failures, stats).

    `registry` defaults to TRANSITIONAL_KNOWN_PAIRS; the self-test
    passes explicit sets for the retirement/pin controls.
    """
    if registry is None:
        registry = TRANSITIONAL_KNOWN_PAIRS
    failures = []
    try:
        mechs = json.loads(Path(mech_path).read_text())["mechanisms"]
    except Exception as e:  # noqa: BLE001 - reported, not hidden
        return [f"cannot parse {mech_path}: {e}"], {}
    try:
        suites = parse_suites((root / "haskoki.cabal").read_text())
    except Exception as e:  # noqa: BLE001
        return [f"cannot parse haskoki.cabal: {e}"], {}
    cites = {}  # (artifact, case_id) -> [mechanism names]
    n_entries = 0
    for m in mechs:
        for e in m.get("test_evidence") or []:
            cites.setdefault((e.get("artifact"), e.get("case_id")), []).append(
                m.get("canonical_name", "?"))
            n_entries += 1
    token_resolved = registry_resolved = 0
    token_cache = {}
    for (artifact, case_id) in sorted(cites, key=repr):
        users = cites[(artifact, case_id)]
        where = f"(cited by {len(users)} entries, e.g. {users[0]})"
        suite, mod, path, err = resolve_module(root, suites, artifact or "")
        if err is not None:
            failures.append(f"{err} {where}")
            continue
        if not RX_CASE.match(case_id or ""):
            failures.append(
                f"malformed case_id {case_id!r} on {artifact} {where}")
            continue
        if path not in token_cache:
            try:
                token_cache[path] = accepted_ids(
                    path.read_text(encoding="utf-8"))
            except _Refusal as e:
                rel = path.relative_to(root)
                failures.append(
                    f"refused to scan {rel} for {case_id} ({e}) {where}")
                continue
        token_hit = case_id in token_cache[path]
        reg_hit = (artifact, case_id) in registry
        if token_hit and reg_hit:
            failures.append(
                f"exemption not retired for {artifact}:{case_id} — "
                f"token landed but the registry entry was retained {where}")
        elif token_hit:
            token_resolved += 1
        elif reg_hit:
            registry_resolved += 1
        else:
            rel = path.relative_to(root)
            failures.append(
                f"dangling case reference {artifact}:{case_id} — "
                f"no -- ACCEPTS: token for {case_id} in {rel} {where}")
    stats = {"entries": n_entries, "pairs": len(cites),
             "token": token_resolved, "registry": registry_resolved}
    return failures, stats


def _selftest_root(tmp, mech_entries, modules, suites, extra_modules=None):
    root = Path(tmp)
    (root / "spec").mkdir(parents=True, exist_ok=True)
    cabal = []
    for suite, dirs in suites.items():
        mods = sorted({Path(rel).stem for rel in modules
                       if any(rel == d or rel.startswith(d + "/")
                              for d in dirs)})
        mods += (extra_modules or {}).get(suite, [])
        cabal.append(f"test-suite {suite}\n"
                     f"  main-is: Main.hs\n"
                     f"  hs-source-dirs: {' '.join(dirs)}\n"
                     f"  other-modules:\n"
                     + "".join(f"    {m}\n" for m in mods))
    (root / "haskoki.cabal").write_text("".join(cabal))
    for rel, text in modules.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    mechs = {"mechanisms": [
        {"canonical_name": "CKM_SCRATCH", "test_evidence": mech_entries}]}
    (root / "spec" / "mechanisms.json").write_text(json.dumps(mechs))
    return root


# FIX-ROUND-2 (Low 4 tail) GHC-validated control corpus. Each entry is
# (full scratch-module bytes, cited case_id, resolves?): the EXACT bytes
# compiled by GHC 9.10.3 during development (oracle sweep; verdicts in
# task-912-fix2-report.md; the p3 QQ entries need the QqDef/A.B support
# files in the sweep only — the gate never compiles). resolves?=False
# entries must mint nothing (dangling); resolves?=True entries must
# token-resolve. Structural note: self-test and the oracle sweep
# consume these same literals, so the GHC-validated bytes and the
# asserted bytes cannot drift.
FIX2_CORPUS = {
    # Path 1: string gaps (RED: gap-close `\"` eaten as an escape,
    # so the real close was consumed and later string data scanned).
    "p1-gap-decoy": ("module FooSpec where\n"
                     "a = \"gap-then-close\\\n  \\\"\n"
                     "b = \"-- ACCEPTS: A99\"\n", "A99", False),
    "p1-gap-resume": ("module FooSpec where\n"
                      "a = \"gap-then-close\\\n  \\\"\n"
                      "-- ACCEPTS: A50\n", "A50", True),
    "p1-escapes": ("module FooSpec where\n"
                   "s = \"\\^A\\NUL\\65\\x42\\o101\\&\\\"q\\\"\"\n"
                   "-- ACCEPTS: A51\n", "A51", True),
    "p1-caret-char": ("module FooSpec where\n"
                      "q = '\\^A'\n"
                      "-- ACCEPTS: A52\n", "A52", True),
    # Path 2: `--` inside operator lexemes (RED: `+--`, `→--` mint).
    "p2-op-ascii": ("module FooSpec where\n"
                    "v = let (+--) a b = b in (1 :: Int) +-- \"ACCEPTS: A99\"\n",
                    "A99", False),
    "p2-op-Sm": ("module FooSpec where\n"
                 "(→--) :: Int -> String -> String\n"
                 "(→--) _ s = s\n"
                 "v = (1 :: Int) →-- \"ACCEPTS: A99\"\n", "A99", False),
    "p2-op-Sc": ("module FooSpec where\n"
                 "(€--) :: Int -> String -> String\n"
                 "(€--) _ s = s\n"
                 "v = (1 :: Int) €-- \"ACCEPTS: A99\"\n", "A99", False),
    "p2-op-Sk": ("module FooSpec where\n"
                 "(¯--) :: Int -> String -> String\n"
                 "(¯--) _ s = s\n"
                 "v = (1 :: Int) ¯-- \"ACCEPTS: A99\"\n", "A99", False),
    "p2-op-So": ("module FooSpec where\n"
                 "(☃--) :: Int -> String -> String\n"
                 "(☃--) _ s = s\n"
                 "v = (1 :: Int) ☃-- \"ACCEPTS: A99\"\n", "A99", False),
    "p2-caret-op": ("module FooSpec where\n"
                    "(--^) :: Int -> String -> String\n"
                    "(--^) _ s = s\n"
                    "x = \"ACCEPTS: A99\"\n"
                    "v = 1 --^ x\n", "A99", False),
    "p2-dashrun-comment": ("module FooSpec where\n"
                           "--- ACCEPTS: A53\n"
                           "v = 1\n", "A53", True),
    "p2-haddock-caret": ("module FooSpec where\n"
                         "v = 1 -- ^ ACCEPTS: A54\n", "A54", True),
    "p2-haddock-bar": ("module FooSpec where\n"
                       "-- | ACCEPTS: A55\n"
                       "v = 1\n", "A55", True),
    "p2-haddock-star": ("module FooSpec where\n"
                        "-- * ACCEPTS: A56\n"
                        "v = 1\n", "A56", True),
    "p2-nospace-comment": ("module FooSpec where\n"
                           "a = 1\n"
                           "f = a-- ACCEPTS: A57\n", "A57", True),
    "p2-ll-ident": ("module FooSpec where\n"
                    "α = 1\n"
                    "v = α-- ACCEPTS: A58\n", "A58", True),
    "p2-underscore": ("module FooSpec where\n"
                      "a_ = 1\n"
                      "v = a_-- ACCEPTS: A59\n", "A59", True),
    # Path 3: qualified quasiquotes (RED: `[Q.qq|...|]` mints).
    "p3-qq-qual": ("{-# LANGUAGE QuasiQuotes #-}\n"
                   "module FooSpec where\n"
                   "import qualified QqDef as Q\n"
                   "v = [Q.qq|hello -- ACCEPTS: A99|]\n", "A99", False),
    "p3-qq-qual2": ("{-# LANGUAGE QuasiQuotes #-}\n"
                    "module FooSpec where\n"
                    "import qualified A.B\n"
                    "v = [A.B.qq|hello -- ACCEPTS: A99|]\n", "A99", False),
    "p3-comprehension": ("module FooSpec where\n"
                         "v = [x|x <- [1,2::Int]] -- ACCEPTS: A60\n",
                         "A60", True),
    "p3-th-skip": ("{-# LANGUAGE TemplateHaskell #-}\n"
                   "module FooSpec where\n"
                   "import Language.Haskell.TH\n"
                   "v :: Q Exp\n"
                   "v = [e|1 {- ACCEPTS: A99 -} + 1|]\n", "A99", False),
    "p3-qq-then-token": ("{-# LANGUAGE QuasiQuotes #-}\n"
                         "module FooSpec where\n"
                         "import QqDef (qq)\n"
                         "v = [qq|data|]\n"
                         "-- ACCEPTS: A61\n", "A61", True),
}


# FIX-ROUND-3 (Low 4 tail) GHC-validated control corpus. Same structural
# contract as FIX2_CORPUS: (full scratch-module bytes, cited case_id,
# resolves?) with the EXACT bytes compiled by GHC 9.10.3 in the oracle
# sweep (verdicts in task-912-fix3-report.md). f3t-* need template-haskell
# (+ the QqDef sweep support for the nested entries); f3q-* need the
# QqUni/M/QqM.Sub sweep supports. resolves?=False entries must mint
# nothing (dangling); resolves?=True entries must token-resolve.
FIX3_CORPUS = {
    # TH brackets with string-embedded |] (RED: first-|] search ended
    # the span inside the string and minted the string data as a
    # comment). All four tags plus typed [|| ||] and old [||].
    "f3t-e": ("{-# LANGUAGE TemplateHaskell #-}\n"
              "module FooSpec where\n"
              "import Language.Haskell.TH\n"
              "v :: Q Exp\n"
              "v = [e| \"|] -- ACCEPTS: A99\" |]\n", "A99", False),
    "f3t-p": ("{-# LANGUAGE TemplateHaskell #-}\n"
              "module FooSpec where\n"
              "import Language.Haskell.TH\n"
              "v :: Q Pat\n"
              "v = [p| \"|] -- ACCEPTS: A99\" |]\n", "A99", False),
    "f3t-t": ("{-# LANGUAGE TemplateHaskell #-}\n"
              "{-# LANGUAGE DataKinds #-}\n"
              "module FooSpec where\n"
              "import Language.Haskell.TH\n"
              "v :: Q Type\n"
              "v = [t| \"|] -- ACCEPTS: A99\" |]\n", "A99", False),
    "f3t-d": ("{-# LANGUAGE TemplateHaskell #-}\n"
              "module FooSpec where\n"
              "import Language.Haskell.TH\n"
              "v :: Q [Dec]\n"
              "v = [d| x = \"|] -- ACCEPTS: A99\" |]\n", "A99", False),
    "f3t-typed": ("{-# LANGUAGE TemplateHaskell #-}\n"
                  "module FooSpec where\n"
                  "import Language.Haskell.TH\n"
                  "v :: Code IO String\n"
                  "v = [|| \"||] -- ACCEPTS: A99\" ||]\n", "A99", False),
    "f3t-oldquote": ("{-# LANGUAGE TemplateHaskell #-}\n"
                     "module FooSpec where\n"
                     "import Language.Haskell.TH\n"
                     "v :: Q Exp\n"
                     "v = [| \"|] -- ACCEPTS: A99\" |]\n", "A99", False),
    # Nested quotation inside TH (GHC nests: the inner |] never ends
    # the outer span). String / comment ACCEPTS data between the ends.
    "f3t-nestclean": ("{-# LANGUAGE TemplateHaskell #-}\n"
                      "{-# LANGUAGE QuasiQuotes #-}\n"
                      "module FooSpec where\n"
                      "import Language.Haskell.TH\n"
                      "import QqDef (q)\n"
                      "f :: String -> String -> Int -> Int\n"
                      "f _ _ n = n\n"
                      "y = 2\n"
                      "v :: Q Exp\n"
                      "v = [e| f [q| x |] \" -- ACCEPTS: A99\" y |]\n",
                      "A99", False),
    "f3t-nestcomment": ("{-# LANGUAGE TemplateHaskell #-}\n"
                        "{-# LANGUAGE QuasiQuotes #-}\n"
                        "module FooSpec where\n"
                        "import Language.Haskell.TH\n"
                        "import QqDef (q)\n"
                        "f :: String -> Int -> Int -> Int\n"
                        "f _ a b = a + b\n"
                        "y = 1\n"
                        "z = 2\n"
                        "v :: Q Exp\n"
                        "v = [e| f [q| x |] y -- ACCEPTS: A99\n z |]\n",
                        "A99", False),
    # |] buried in a TH code comment (block and line forms).
    "f3t-blockcomment": ("{-# LANGUAGE TemplateHaskell #-}\n"
                         "module FooSpec where\n"
                         "import Language.Haskell.TH\n"
                         "v :: Q Exp\n"
                         "v = [e| f {- x|]y -- ACCEPTS: A99 -} z |]\n"
                         "f a b = a\n"
                         "z = 1\n", "A99", False),
    "f3t-linecomment": ("{-# LANGUAGE TemplateHaskell #-}\n"
                        "module FooSpec where\n"
                        "import Language.Haskell.TH\n"
                        "v :: Q Exp\n"
                        "v = [e| f -- c|] -- ACCEPTS: A99\n x |]\n"
                        "f a b = a\n"
                        "x = 1\n", "A99", False),
    # Bare ] in a raw body (Bb11) with a comment-buried end: the raw
    # reading still ends at the first |]; the resume line is clean.
    "f3t-bb11": ("{-# LANGUAGE QuasiQuotes #-}\n"
                 "module FooSpec where\n"
                 "import QqDef (qq)\n"
                 "v = [qq|a]b \"x\"\n -- ACCEPTS: A99|]\n",
                 "A99", False),
    # TH skip must resume lexing for a following real token.
    "f3t-then-token": ("{-# LANGUAGE TemplateHaskell #-}\n"
                       "module FooSpec where\n"
                       "import Language.Haskell.TH\n"
                       "v :: Q Exp\n"
                       "v = [e| \"x\" |]\n"
                       "-- ACCEPTS: A68\n", "A68", True),
    # Path 2: punctuation operators (RED: Po/Pd/Pc runs misread as
    # comments, minting following string data). Prefix per added class
    # (+ round-4 blockers ¿ and ＿) and suffix (--X) per added class.
    "f3s-po-inv": ("module FooSpec where\n"
                   "v = let (¡--) a b = b in (1 :: Int) ¡-- \"ACCEPTS: A99\"\n",
                   "A99", False),
    "f3s-pd-em": ("module FooSpec where\n"
                  "v = let (—--) a b = b in (1 :: Int) —-- \"ACCEPTS: A99\"\n",
                  "A99", False),
    "f3s-pc-tie": ("module FooSpec where\n"
                   "v = let (‿--) a b = b in (1 :: Int) ‿-- \"ACCEPTS: A99\"\n",
                   "A99", False),
    "f3s-po-invq": ("module FooSpec where\n"
                    "v = let (¿--) a b = b in (1 :: Int) ¿-- \"ACCEPTS: A99\"\n",
                    "A99", False),
    "f3s-pc-full": ("module FooSpec where\n"
                    "v = let (＿--) a b = b in (1 :: Int) ＿-- \"ACCEPTS: A99\"\n",
                    "A99", False),
    "f3s-suf-po": ("module FooSpec where\n"
                   "(--¡) _ s = s\n"
                   "v = 1 --¡ \"ACCEPTS: A99\"\n", "A99", False),
    "f3s-suf-pd": ("module FooSpec where\n"
                   "(--—) _ s = s\n"
                   "v = 1 --— \"ACCEPTS: A99\"\n", "A99", False),
    "f3s-suf-pc": ("module FooSpec where\n"
                   "(--‿) _ s = s\n"
                   "v = 1 --‿ \"ACCEPTS: A99\"\n", "A99", False),
    # Path 2 boundary positives: operator lines must not swallow a
    # following real token; ASCII _ and rejected brackets stay comments.
    "f3s-op-then-token": ("module FooSpec where\n"
                          "v = let (¡--) a b = b in (1 :: Int) ¡-- \"x\"\n"
                          "-- ACCEPTS: A67\n", "A67", True),
    "f3s-uscore": ("module FooSpec where\n"
                   "w = 1 --_ ACCEPTS: A62\n"
                   "v = 1\n", "A62", True),
    "f3s-pi": ("module FooSpec where\n"
               "w = 1 --« ACCEPTS: A63\n"
               "v = 1\n", "A63", True),
    "f3s-ps": ("module FooSpec where\n"
               "w = 1 --「 ACCEPTS: A64\n"
               "v = 1\n", "A64", True),
    "f3s-pe": ("module FooSpec where\n"
               "w = 1 --」 ACCEPTS: A65\n"
               "v = 1\n", "A65", True),
    "f3s-pf": ("module FooSpec where\n"
               "w = 1 --» ACCEPTS: A66\n"
               "v = 1\n", "A66", True),
    # Path 3: Unicode quoters (RED: ASCII-only opener matcher scanned
    # quasiquote bodies as code). Single Ll/Lo, qualified, multi-part
    # qualified, and Nd/Pc/prime/Mn/Lm/Nl/No continue classes.
    "f3q-alpha": ("{-# LANGUAGE QuasiQuotes #-}\n"
                  "module FooSpec where\n"
                  "import QqUni (α)\n"
                  "v = [α|hello -- ACCEPTS: A99|]\n", "A99", False),
    "f3q-lo": ("{-# LANGUAGE QuasiQuotes #-}\n"
               "module FooSpec where\n"
               "import QqUni (中)\n"
               "v = [中|hello -- ACCEPTS: A99|]\n", "A99", False),
    "f3q-qual": ("{-# LANGUAGE QuasiQuotes #-}\n"
                 "module FooSpec where\n"
                 "import M (α)\n"
                 "v = [M.α|hello -- ACCEPTS: A99|]\n", "A99", False),
    "f3q-qual2": ("{-# LANGUAGE QuasiQuotes #-}\n"
                  "module FooSpec where\n"
                  "import QqM.Sub (α)\n"
                  "v = [QqM.Sub.α|hello -- ACCEPTS: A99|]\n", "A99", False),
    "f3q-combo": ("{-# LANGUAGE QuasiQuotes #-}\n"
                  "module FooSpec where\n"
                  "import QqUni (β2_γ')\n"
                  "v = [β2_γ'|hello -- ACCEPTS: A99|]\n", "A99", False),
    # Mn/Lm/Nl/No continues use explicit escapes (normalization-proof).
    "f3q-mn": ("{-# LANGUAGE QuasiQuotes #-}\n"
               "module FooSpec where\n"
               "import QqUni (e\u0301)\n"
               "v = [e\u0301|hello -- ACCEPTS: A99|]\n", "A99", False),
    "f3q-lm": ("{-# LANGUAGE QuasiQuotes #-}\n"
               "module FooSpec where\n"
               "import QqUni (α\u02c6)\n"
               "v = [α\u02c6|hello -- ACCEPTS: A99|]\n", "A99", False),
    "f3q-nl": ("{-# LANGUAGE QuasiQuotes #-}\n"
               "module FooSpec where\n"
               "import QqUni (α\u2167)\n"
               "v = [α\u2167|hello -- ACCEPTS: A99|]\n", "A99", False),
    "f3q-no": ("{-# LANGUAGE QuasiQuotes #-}\n"
               "module FooSpec where\n"
               "import QqUni (α\u00bd)\n"
               "v = [α\u00bd|hello -- ACCEPTS: A99|]\n", "A99", False),
    # Unicode skip must resume lexing for a following real token.
    "f3q-then-token": ("{-# LANGUAGE QuasiQuotes #-}\n"
                       "module FooSpec where\n"
                       "import QqUni (α)\n"
                       "v = [α|data|]\n"
                       "-- ACCEPTS: A69\n", "A69", True),
}

# FIX-ROUND-3 refused shapes: GHC-valid modules (same oracle sweep as
# FIX3_CORPUS) where code-vs-data is genuinely ambiguous, so the gate
# trips the file LOUDLY (fail closed) instead of minting or skipping.
# Control 13 asserts the trip (a "refused to scan" failure, never a
# token resolution and never a silent dangle).
FIX3_CORPUS_REFUSED = {
    # Comprehension followed by "|]" string data (RED-b): skipping to
    # the buried |] desynchronizes into the string; scanning mints.
    "f3r-compr": ("module FooSpec where\n"
                  "v = [x|x <- [1::Int]]\n"
                  "s = \"|] -- ACCEPTS: A99\"\n"),
    # Raw body with an early quote (Bb10 shape): the code reading
    # buries the first |] in a string while the raw reading ends
    # there; the resume is real code (second quasiquote).
    "f3r-bb10": ("{-# LANGUAGE QuasiQuotes #-}\n"
                 "module FooSpec where\n"
                 "import QqDef (qq)\n"
                 "v = [qq|say \"hi -- ACCEPTS: A99|] ++ [qq|bye|]\n"),
    # Nested quotation with a bracket in the raw-reading resume: GHC
    # cannot rejoin the resume past the code-level end.
    "f3r-nestdirty": ("{-# LANGUAGE TemplateHaskell #-}\n"
                      "{-# LANGUAGE QuasiQuotes #-}\n"
                      "module FooSpec where\n"
                      "import Language.Haskell.TH\n"
                      "import QqDef (q)\n"
                      "f :: String -> [Int] -> Int -> Int\n"
                      "f _ _ n = n\n"
                      "y = 1\n"
                      "z = 2\n"
                      "v :: Q Exp\n"
                      "v = [e| f [q| x |] [y] z |]\n"),
    # TH-letter opener with every |] buried (comprehension-shaped
    # under QuasiQuotes-off): no code-level end exists.
    "f3r-thqmiss": ("module FooSpec where\n"
                    "v = [e|e <- [1::Int]]\n"
                    "s = \"|] -- ACCEPTS: A99\"\n"),
}


# FIX-ROUND-4 (Low 4 tail) GHC-validated control corpus. Same structural
# contract as FIX2_CORPUS: (full scratch-module bytes, cited case_id,
# resolves?) with the EXACT bytes compiled by GHC 9.10.3 in the oracle
# sweep (verdicts in task-912-fix4-report.md). f4a-* need
# TemplateHaskell + QuasiQuotes (+ the QqDef sweep support); f4b-*
# need QuasiQuotes only; f4-deep3 is a valid 3-level spliced TH nest.
# resolves?=False entries must mint nothing (dangling); resolves?=True
# entries must token-resolve.
FIX4_CORPUS = {
    # Nested raw quasiquote with a quote in its body, followed by a
    # gapped string (codex-exact RED (a)): the outer TH scan must end
    # the inner raw span at ITS raw-first |] (the quote is data) and
    # skip the whole outer span, so the string data mints nothing.
    "f4a-nested-raw-quote": ("{-# LANGUAGE QuasiQuotes, TemplateHaskell #-}\n"
                             "module FooSpec where\n"
                             "import QqDef (q)\n"
                             "import Language.Haskell.TH\n"
                             "v :: Q Exp\n"
                             "v = [e| [q|raw \" |] ++ \"one |] two |] \\\n"
                             "  \\ -- ACCEPTS: A99\" |]\n", "A99", False),
    # Nested raw span followed by a gapped string inside TH: the gap
    # continuation keeps the ACCEPTS text inside string data.
    "f4a-gap-string": ("{-# LANGUAGE QuasiQuotes, TemplateHaskell #-}\n"
                       "module FooSpec where\n"
                       "import QqDef (q)\n"
                       "import Language.Haskell.TH\n"
                       "v :: Q Exp\n"
                       "v = [e| [q|raw |] ++ \"one \\\n"
                       "  \\ -- ACCEPTS: A99\" |]\n", "A99", False),
    # Comment text inside a nested RAW body is data (the -- never
    # starts a comment); the outer span still skips whole.
    "f4a-comment-body": ("{-# LANGUAGE QuasiQuotes, TemplateHaskell #-}\n"
                         "module FooSpec where\n"
                         "import QqDef (q)\n"
                         "import Language.Haskell.TH\n"
                         "f :: String -> String -> Int -> Int\n"
                         "f _ _ n = n\n"
                         "y = 2\n"
                         "v :: Q Exp\n"
                         "v = [e| f [q| -- ACCEPTS: A99 |] \"s\" y |]\n",
                         "A99", False),
    # Resume lock (TH): the (a) span skipped to the right end, so a
    # REAL comment token after it still resolves.
    "f4a-then-token": ("{-# LANGUAGE QuasiQuotes, TemplateHaskell #-}\n"
                       "module FooSpec where\n"
                       "import QqDef (q)\n"
                       "import Language.Haskell.TH\n"
                       "v :: Q Exp\n"
                       "v = [e| [q|raw \" |] ++ \"one |] two |] \\\n"
                       "  \\ -- ACCEPTS: A99\" |]\n"
                       "-- ACCEPTS: A70\n", "A70", True),
    # Raw [e| span (QuasiQuotes-only) followed by a gapped string:
    # first |] is code-level, the resume gap-skips the string data.
    "f4b-gap-resume": ("{-# LANGUAGE QuasiQuotes #-}\n"
                       "module FooSpec where\n"
                       "import QqDef (e)\n"
                       "v = [e|data|]\n"
                       "s = \"nested \\\n"
                       "  \\ -- ACCEPTS: A99\"\n", "A99", False),
    # Resume lock (QQ): raw span + gapped string skipped, so a REAL
    # comment token after them still resolves.
    "f4b-then-token": ("{-# LANGUAGE QuasiQuotes #-}\n"
                       "module FooSpec where\n"
                       "import QqDef (e)\n"
                       "v = [e|data|]\n"
                       "s = \"nested \\\n"
                       "  \\ -- ACCEPTS: A99\"\n"
                       "-- ACCEPTS: A71\n", "A71", True),
    # Valid 3-level spliced TH nest (each inner bracket whole inside
    # a splice): recursion resolves every level, string data mints
    # nothing.
    "f4-deep3": ("{-# LANGUAGE QuasiQuotes, TemplateHaskell #-}\n"
                 "module FooSpec where\n"
                 "import QqDef (q)\n"
                 "import Language.Haskell.TH\n"
                 "v :: Q Exp\n"
                 "v = [e| $([e| $([e| \"|] -- ACCEPTS: A99\" |]) |]) |]\n",
                 "A99", False),
}

# FIX-ROUND-4 refused shapes: GHC-valid modules (same oracle sweep as
# FIX4_CORPUS) where the span end is ambiguous or past the depth cap,
# so the gate trips the file LOUDLY (fail closed) instead of minting
# or skipping. Control 17b asserts the trip (a "refused to scan"
# failure, never a token resolution and never a silent dangle).
FIX4_CORPUS_REFUSED = {
    # Raw [e| span with a quote in its body, followed by a gapped
    # string (codex-exact RED (b)): the code-level end falls inside
    # the resumed (gap-continued) string. Refuse.
    "f4r-raw-e-gap": ("{-# LANGUAGE QuasiQuotes #-}\n"
                      "module FooSpec where\n"
                      "import QqDef (e)\n"
                      "v = [e|raw \" |]\n"
                      "s = \"nested |] \\\n"
                      "  \\ -- ACCEPTS: A99\"\n"),
    # Comment text inside a bare-[e| raw body (QuasiQuotes-only): no
    # code-level end exists (the only |] is comment-buried). Refuse.
    "f4r-qq-comment": ("{-# LANGUAGE QuasiQuotes #-}\n"
                       "module FooSpec where\n"
                       "import QqDef (e)\n"
                       "v = [e| -- ACCEPTS: A99 |]\n"),
    # Valid 33-level spliced TH nest (each inner bracket whole inside
    # a splice): past QQ_NEST_CAP, so the gate trips LOUDLY on valid
    # code. Built by repetition (exact by construction: 32 wraps of
    # `[e| $(` ... `) |]` around `[e| "x" |]`).
    "f4r-deep33": ("{-# LANGUAGE QuasiQuotes, TemplateHaskell #-}\n"
                   "module FooSpec where\n"
                   "import QqDef (q)\n"
                   "import Language.Haskell.TH\n"
                   "v :: Q Exp\n"
                   "v = " + "[e| $(" * 32 + "[e| \"x\" |]"
                   + ") |]" * 32 + "\n"),
}


# FIX-ROUND-5 (Low 4 tail) GHC-validated control corpus. Same structural
# contract as FIX2_CORPUS: (full scratch-module bytes, cited case_id,
# resolves?) with the EXACT bytes compiled by GHC 9.10.3 in the oracle
# sweep (verdicts in task-912-fix5-report.md). f5-op-then-token and
# f5-comment-then-token are resume-lock positives (operator runs and
# quotey comments after a clean span end resolve exactly);
# f5-raw-clean-resume locks the raw-path line-resume permit for
# quoteless resumes. resolves?=False entries must mint nothing
# (dangling); resolves?=True entries must token-resolve.
FIX5_CORPUS = {
    # Operator run (holding a dash run) after a clean raw span end,
    # then a real comment token: the run re-lexes exactly, A72 resolves.
    "f5-op-then-token": ("{-# LANGUAGE QuasiQuotes #-}\n"
                        "module FooSpec where\n"
                        "import QqDef (qq)\n"
                        "(--+) :: String -> String -> String\n"
                        "(--+) _ s = s\n"
                        "v = [qq|data|] --+ \"x\"\n"
                        "-- ACCEPTS: A72\n", "A72", True),
    # Raw-path line-resume permit lock: the first |] sits in a line
    # comment of the span body, but the resumed line is quoteless and
    # opener-free, so the gate still skips (no over-refusal); the
    # string decoy mints nothing.
    "f5-raw-clean-resume": ("{-# LANGUAGE QuasiQuotes #-}\n"
                           "module FooSpec where\n"
                           "import QqDef (qq)\n"
                           "y = \"tail\"\n"
                           "v = [qq|a -- c|] ++ y\n"
                           "s = \"-- ACCEPTS: A99\"\n", "A99", False),
    # A comment holding a quote and a |] after a clean bare-[e| end:
    # the end itself is code-level, so no refusal fires and the real
    # token after the quotey comment still resolves.
    "f5-comment-then-token": ("{-# LANGUAGE QuasiQuotes #-}\n"
                             "module FooSpec where\n"
                             "import QqDef (e)\n"
                             "v = [e|data|]\n"
                             "-- a comment with \" quote and |] bracket\n"
                             "-- ACCEPTS: A73\n", "A73", True),
}

# FIX-ROUND-5 refused shapes: GHC-valid modules (same oracle sweep as
# FIX5_CORPUS) where a span end is comment-buried with a quotey resume,
# so the gate trips the file LOUDLY (fail closed) instead of minting
# from desynchronized string data. Control 19b asserts the trip (a
# "refused to scan" failure, never a token resolution and never a
# silent dangle).
FIX5_CORPUS_REFUSED = {
    # Codex-exact RED (#4): QuasiQuotes-only e quoter; the selected
    # end is line-buried with a quote past it; GHC reads the whole as
    # raw/string data while the pre-fix gate minted A99 (exit 0).
    # Byte-identity with task-912r4-codex.jsonl item_10 checked.
    "f5r-comment-line": ("{-# LANGUAGE QuasiQuotes #-}\n"
                        "module FooSpec where\n"
                        "import QqDef (e)\n"
                        "v = [e|raw \" |] -- \" comment |] \"\n"
                        "s = \"nested \\\n"
                        "  \\ -- ACCEPTS: A99\"\n"),
    # Block-buried selected end that dodges _region_has_opaque: the "
    # after -- pairs (opaque-scan) with the " before gap1, so the {-
    # hides inside the skipped span while the resume lexes it at code
    # level (opaque=False, resume ctx block). Pre-fix minted A99.
    "f5r-comment-block": ("{-# LANGUAGE QuasiQuotes #-}\n"
                         "module FooSpec where\n"
                         "import QqDef (e)\n"
                         "v = [e|raw \" |] -- \"A tail \\\"D more\n"
                         "w = \"l\" {- m \"C gap1 |] \"P gap2 -} ++ \"ok\"\n"
                         "s = \"nested \\\n"
                         "  \\ -- ACCEPTS: A99\"\n"),
    # Simple block-buried end: already refused pre-fix by the opaque
    # guard (the {- is outside every skipped string); kept to pin the
    # simple sub-case (post-fix the comment guard trips first).
    "f5r-comment-block-simple": ("{-# LANGUAGE QuasiQuotes #-}\n"
                                "module FooSpec where\n"
                                "import QqDef (e)\n"
                                "v = [e|raw \" |] ++ {- \" c |] -} \"tail\"\n"
                                "s = \"nested \\\n"
                                "  \\ -- ACCEPTS: A99\"\n"),
    # Raw-path variant (QuasiQuotes off): a comprehension followed by
    # a comment holding a quote + buried |], resumed line quotey, then
    # a gapped string. Pre-fix minted A99 via the same phantom-string
    # mechanism through the round-3 permit.
    "f5r-raw-line-quote": ("module FooSpec where\n"
                          "qq = 0\n"
                          "v = [qq|x <- [1::Int]] -- \" tail |] junk \"\n"
                          "s = \"nested \\\n"
                          "  \\ -- ACCEPTS: A99\"\n"),
}


def self_test():
    """Durable negative controls: typo, deleted token, unknown
    suite/module, malformed id, traversal, absolute path, cross-suite
    module, decoy strings must fail; clean tree and comment tokens
    (line, block, nested) must pass. The live registry must stay a
    subset of the pinned legacy membership, and the real A42 token
    must exist with its exemptions retired (no skip-if-absent: a
    missing token or file fails loudly). Fix-round-2 adds the
    GHC-validated corpus (gaps, operators incl. Unicode, qualified
    quasiquotes) plus the A42-deletion-plus-gap-decoy regression.
    Fix-round-3 adds the GHC-validated corpus (TH brackets with
    buried terminators, punctuation operators, Unicode quoters),
    the refused-shape trips, the A42-deletion-plus-TH/comprehension
    regressions, and the symbol-table/quoter-matcher unit pins.
    Fix-round-4 adds the GHC-validated corpus (nested raw spans with
    quote/comment bodies, gapped strings, a valid 3-level TH nest,
    resume-lock positives), the refused-shape trips (resumed-literal
    end, depth-cap trip), and the A42-deletion-plus-nest/rawgap
    regressions. Fix-round-5 adds the GHC-validated corpus
    (comment-buried ends: the codex-exact line variant, block
    variants, the raw-path line+quote variant, operator/clean-resume
    locks), the A42-deletion-plus-comment regression, the
    resume-state audit unit pins (operator-run, char-impossibility),
    and the in-tree zero-opener lock."""
    fails = []
    ran = []

    def expect(name, cond, detail=""):
        ran.append(name)
        print(f"{'PASS' if cond else 'FAIL'}: self-test: {name}"
              + (f": {detail}" if detail and not cond else ""))
        if not cond:
            fails.append(name)

    suites = {"suite-a": ["tests/alpha"], "suite-b": ["tests/beta"]}
    good_modules = {
        "tests/alpha/FooSpec.hs": "-- ACCEPTS: A01, A02\nmodule FooSpec where\n",
        "tests/beta/BarSpec.hs": "{- ACCEPTS: A03 -}\nmodule BarSpec where\n",
    }
    good_entries = [
        {"artifact": "suite-a/FooSpec", "build_id": "x", "case_id": "A01"},
        {"artifact": "suite-a/FooSpec", "build_id": "x", "case_id": "A02"},
        {"artifact": "suite-b/BarSpec", "build_id": "x", "case_id": "A03"},
    ]
    with tempfile.TemporaryDirectory(prefix="f11-ev") as tmp:
        root = _selftest_root(tmp, good_entries, good_modules, suites)
        failures, stats = check_tree(root, root / "spec" / "mechanisms.json")
        expect("clean-tree-passes", not failures, "; ".join(failures))
        expect("clean-tree-token-count",
               stats.get("token") == 3 and stats.get("registry") == 0,
               repr(stats))

        # Control 1 (repro class): typoed case_id fails naming the id.
        typo = [dict(e, case_id="A99") if e["case_id"] == "A03" else e
                for e in good_entries]
        root = _selftest_root(tmp + "/t", typo, good_modules, suites)
        failures, _ = check_tree(root, root / "spec" / "mechanisms.json")
        expect("typoed-case-fails",
               len(failures) == 1 and "A99" in failures[0]
               and "dangling case reference" in failures[0],
               "; ".join(failures))

        # Control 2 (variant class): deleted token, same failure class.
        notoken = dict(good_modules)
        notoken["tests/alpha/FooSpec.hs"] = "module FooSpec where\n"
        root = _selftest_root(tmp + "/d", good_entries, notoken, suites)
        failures, _ = check_tree(root, root / "spec" / "mechanisms.json")
        expect("deleted-token-fails",
               len(failures) == 2
               and all("dangling case reference" in f for f in failures)
               and any("FooSpec:A01" in f for f in failures),
               "; ".join(failures))

        # Control 3: unknown suite fails loudly; undeclared module
        # fails membership (file existence alone no longer resolves).
        bad_entries = [{"artifact": "suite-x/FooSpec", "build_id": "x",
                        "case_id": "A01"}]
        root = _selftest_root(tmp + "/s", bad_entries, good_modules, suites)
        failures, _ = check_tree(root, root / "spec" / "mechanisms.json")
        expect("unknown-suite-fails",
               len(failures) == 1 and "unknown suite 'suite-x'" in failures[0],
               "; ".join(failures))
        bad_entries = [{"artifact": "suite-a/NopeSpec", "build_id": "x",
                        "case_id": "A01"}]
        root = _selftest_root(tmp + "/m", bad_entries, good_modules, suites)
        failures, _ = check_tree(root, root / "spec" / "mechanisms.json")
        expect("unknown-module-fails",
               len(failures) == 1
               and "not compiled into suite 'suite-a'" in failures[0],
               "; ".join(failures))

        # Control 3b: declared-but-missing file still fails loudly.
        bad_entries = [{"artifact": "suite-a/GhostSpec", "build_id": "x",
                        "case_id": "A01"}]
        root = _selftest_root(tmp + "/g", bad_entries, good_modules, suites,
                              extra_modules={"suite-a": ["GhostSpec"]})
        failures, _ = check_tree(root, root / "spec" / "mechanisms.json")
        expect("declared-module-missing-file-fails",
               len(failures) == 1
               and "unknown spec module 'GhostSpec'" in failures[0],
               "; ".join(failures))

        # Control 3c (Important 2): traversal, absolute path, and
        # cross-suite citations are rejected even though the bytes
        # exist on disk.
        bad_entries = [{"artifact": "suite-a/../beta/BarSpec",
                        "build_id": "x", "case_id": "A03"}]
        root = _selftest_root(tmp + "/p", bad_entries, good_modules, suites)
        failures, _ = check_tree(root, root / "spec" / "mechanisms.json")
        expect("traversal-artifact-rejected",
               len(failures) == 1 and "'..' component" in failures[0],
               "; ".join(failures))
        bad_entries = [{"artifact": "/x/suite-a/FooSpec",
                        "build_id": "x", "case_id": "A01"}]
        root = _selftest_root(tmp + "/a", bad_entries, good_modules, suites)
        failures, _ = check_tree(root, root / "spec" / "mechanisms.json")
        expect("absolute-artifact-rejected",
               len(failures) == 1 and "absolute path" in failures[0],
               "; ".join(failures))
        bad_entries = [{"artifact": "suite-a/BarSpec", "build_id": "x",
                        "case_id": "A03"}]
        root = _selftest_root(tmp + "/x", bad_entries, good_modules, suites)
        failures, _ = check_tree(root, root / "spec" / "mechanisms.json")
        expect("cross-suite-module-rejected",
               len(failures) == 1
               and "not compiled into suite 'suite-a'" in failures[0],
               "; ".join(failures))

        # Control 4: malformed case_id fails (shape, not silence).
        bad_entries = [{"artifact": "suite-a/FooSpec", "build_id": "x",
                        "case_id": "A1"}]
        root = _selftest_root(tmp + "/c", bad_entries, good_modules, suites)
        failures, _ = check_tree(root, root / "spec" / "mechanisms.json")
        expect("malformed-case-fails",
               len(failures) == 1 and "malformed case_id 'A1'" in failures[0],
               "; ".join(failures))

        # Control 5: transitional registry resolves without a token
        # (the real-tree path until tokens land), but never extends.
        reg_modules = {"tests/model/RegistrySpec.hs": "module RegistrySpec where\n"}
        reg_entries = [{"artifact": "haskoki-model-tests/RegistrySpec",
                        "build_id": "x", "case_id": "A40"}]
        reg_suites = {"haskoki-model-tests": ["tests/model"]}
        root = _selftest_root(tmp + "/r", reg_entries, reg_modules, reg_suites)
        failures, stats = check_tree(root, root / "spec" / "mechanisms.json")
        expect("registry-leg-resolves",
               not failures and stats.get("registry") == 1,
               "; ".join(failures) or repr(stats))
        reg_entries = [{"artifact": "haskoki-model-tests/RegistrySpec",
                        "build_id": "x", "case_id": "A41"}]
        root = _selftest_root(tmp + "/r2", reg_entries, reg_modules, reg_suites)
        failures, _ = check_tree(root, root / "spec" / "mechanisms.json")
        expect("registry-never-extends",
               len(failures) == 1 and "RegistrySpec:A41" in failures[0],
               "; ".join(failures))

        # Control 6 (Low 3): the live registry stays a subset of the
        # pinned legacy membership; any addition trips the pin.
        expect("registry-pinned-subset",
               TRANSITIONAL_KNOWN_PAIRS <= PINNED_APPROVED_REGISTRY,
               f"extra={sorted(TRANSITIONAL_KNOWN_PAIRS - PINNED_APPROVED_REGISTRY)}")
        mutant_reg = (set(TRANSITIONAL_KNOWN_PAIRS)
                      | {("haskoki-model-tests/RegistrySpec", "A99")})
        expect("registry-addition-trips-pin",
               not (mutant_reg <= PINNED_APPROVED_REGISTRY),
               "pin admits additions")

        # Control 7 (Important 1): the real A42 token exists (applied:
        # unreadable/missing fails, never skips) and both migrated A42
        # pairs retired their registry exemptions.
        try:
            real_text = (REPO / "tests/model/MechanismExhaustivenessSpec.hs"
                         ).read_text()
        except OSError as e:
            real_text = ""
            expect("real-a42-token-present", False, f"cannot read: {e}")
        else:
            expect("real-a42-token-present",
                   "A42" in accepted_ids(real_text),
                   "real A42 token missing from MechanismExhaustivenessSpec.hs")
        expect("registry-retired-a42",
               ("haskoki-core-tests/MechanismExhaustivenessSpec", "A42")
               not in TRANSITIONAL_KNOWN_PAIRS
               and ("haskoki-model-tests/MechanismExhaustivenessSpec", "A42")
               not in TRANSITIONAL_KNOWN_PAIRS,
               "migrated A42 pair still exempted")

        # Control 8 (Important 1): a scratch mini-root mirroring the
        # real A42 pair fails dangling when the token is deleted, and
        # token-resolves when intact (mutant-with-scratch, real tree
        # untouched). Catches a re-added A42 registry entry: with the
        # token deleted the mutant must NOT registry-resolve.
        a42_suites = {"haskoki-model-tests": ["tests/model"],
                      "haskoki-core-tests": ["tests/coretests", "tests/model"]}
        a42_entries = [
            {"artifact": "haskoki-model-tests/MechanismExhaustivenessSpec",
             "build_id": "x", "case_id": "A42"},
            {"artifact": "haskoki-core-tests/MechanismExhaustivenessSpec",
             "build_id": "x", "case_id": "A42"},
        ]
        stripped = "\n".join(
            l for l in real_text.split("\n")
            if not ("ACCEPTS:" in l and "A42" in RX_TOKEN_ID.findall(l)))
        a42_modules = {"tests/model/MechanismExhaustivenessSpec.hs": stripped}
        root = _selftest_root(tmp + "/a42m", a42_entries, a42_modules,
                              a42_suites)
        failures, _ = check_tree(root, root / "spec" / "mechanisms.json")
        expect("a42-token-deleted-fails",
               len(failures) == 2
               and all("dangling case reference" in f for f in failures)
               and sum("A42" in f for f in failures) == 2,
               "; ".join(failures))
        a42_modules = {"tests/model/MechanismExhaustivenessSpec.hs": real_text}
        root = _selftest_root(tmp + "/a42i", a42_entries, a42_modules,
                              a42_suites)
        failures, stats = check_tree(root, root / "spec" / "mechanisms.json")
        expect("a42-token-intact-resolves",
               not failures and stats.get("token") == 2,
               "; ".join(failures) or repr(stats))

        # Control 9 (Important 1): token-bearing + registry member
        # fails the live gate ("exemption not retired").
        root = _selftest_root(tmp + "/e", good_entries, good_modules, suites)
        failures, _ = check_tree(root, root / "spec" / "mechanisms.json",
                                 registry={("suite-a/FooSpec", "A01")})
        expect("exemption-not-retired-fails",
               len(failures) == 1
               and "exemption not retired" in failures[0]
               and "FooSpec:A01" in failures[0],
               "; ".join(failures))

        # Control 10 (Low 4): decoy ACCEPTS text in strings, chars, and
        # quasiquotes mints no token; comment tokens (incl. nested
        # blocks) still resolve, including after string/char/code that
        # must not desynchronize the scanner.
        def decoy(name, body):
            mods = {"tests/alpha/FooSpec.hs":
                    body + "\nmodule FooSpec where\n"}
            ents = [{"artifact": "suite-a/FooSpec", "build_id": "x",
                     "case_id": "A99"}]
            r = _selftest_root(f"{tmp}/{name}", ents, mods, suites)
            f, _ = check_tree(r, r / "spec" / "mechanisms.json")
            expect(f"decoy-{name}-mints-nothing",
                   len(f) == 1 and "dangling case reference" in f[0]
                   and "FooSpec:A99" in f[0],
                   "; ".join(f))

        decoy("double-string", 'reviewMetadata = "ACCEPTS: A99"')
        decoy("line-comment-in-string", 'x = "-- ACCEPTS: A99"')
        decoy("block-in-string", 'x = "{- ACCEPTS: A99 -}"')
        decoy("multiline-string", 'x = "head\nACCEPTS: A99\ntail"')
        decoy("escaped-quote", 'x = "a\\" -- ACCEPTS: A99"')
        decoy("quasiquote", "x = [qq|-- ACCEPTS: A99|]")
        # NOTE (fix2, GHC-forced): the original body `x = y ---ACCEPTS: A99`
        # is a genuine line comment per GHC (DUp2: clean compile), not an
        # operator — `---x` takes the comment leg of the dash-run rule.
        # Intent preserved with a GHC-true dash operator (`--A` would be
        # a comment too; `--->` is an operator per DOpNew/Dash3Gt).
        decoy("operator-dashes", "x = y --->ACCEPTS: A99")

        def resolves(name, body, case):
            mods = {"tests/alpha/FooSpec.hs":
                    body + "\nmodule FooSpec where\n"}
            ents = [{"artifact": "suite-a/FooSpec", "build_id": "x",
                     "case_id": case}]
            r = _selftest_root(f"{tmp}/{name}", ents, mods, suites)
            f, s = check_tree(r, r / "spec" / "mechanisms.json")
            expect(f"{name}-resolves",
                   not f and s.get("token") == 1,
                   "; ".join(f) or repr(s))

        resolves("nested-block-token", "{- outer {- ACCEPTS: A05 -} tail -}",
                 "A05")
        resolves("string-plus-real-token",
                 'x = "ACCEPTS: A99"\n-- ACCEPTS: A06', "A06")
        resolves("char-quote-resync", "q = '\"'\n-- ACCEPTS: A07", "A07")

        # Control 11 (Low 4 fix2): the GHC-validated corpus — gap,
        # operator (ASCII + Unicode Sm/Sc/Sk/So + dash-run/haddock
        # boundaries), and quasiquote shapes. Negatives mint nothing;
        # positives resolve. Each text is the exact bytes GHC 9.10.3
        # compiled in the oracle sweep.
        for key in sorted(FIX2_CORPUS):
            text, case, resolves_p = FIX2_CORPUS[key]
            mods = {"tests/alpha/FooSpec.hs": text}
            ents = [{"artifact": "suite-a/FooSpec", "build_id": "x",
                     "case_id": case}]
            r = _selftest_root(f"{tmp}/{key}", ents, mods, suites)
            f, s = check_tree(r, r / "spec" / "mechanisms.json")
            if resolves_p:
                expect(f"{key}-resolves",
                       not f and s.get("token") == 1,
                       "; ".join(f) or repr(s))
            else:
                expect(f"{key}-mints-nothing",
                       len(f) == 1 and "dangling case reference" in f[0]
                       and f"FooSpec:{case}" in f[0],
                       "; ".join(f))

        # Control 12 (Low 4 fix2): A42 token deleted + gap decoy
        # carrying "-- ACCEPTS: A42" as string data must still fail
        # dangling (pre-fix: minted from the string, exit 0).
        gap_decoy = ('gapProbe = "gap-then-close\\\n  \\"\n'
                     'decoyLabel = "-- ACCEPTS: A42"\n')
        a42_modules = {"tests/model/MechanismExhaustivenessSpec.hs":
                       stripped + "\n" + gap_decoy}
        root = _selftest_root(tmp + "/a42g", a42_entries, a42_modules,
                              a42_suites)
        failures, _ = check_tree(root, root / "spec" / "mechanisms.json")
        expect("a42-deleted-plus-gap-decoy-fails",
               len(failures) == 2
               and all("dangling case reference" in x for x in failures)
               and sum("A42" in x for x in failures) == 2,
               "; ".join(failures))

        # Control 13 (Low 4 fix3): the GHC-validated corpus — TH
        # brackets with buried |] (all four tags, typed, old-style,
        # nested, comment-buried), punctuation operators (prefix and
        # suffix per added class + boundary positives), and Unicode
        # quoters (single/qualified/multi-part/continue classes).
        # Negatives mint nothing; positives resolve.
        for key in sorted(FIX3_CORPUS):
            text, case, resolves_p = FIX3_CORPUS[key]
            mods = {"tests/alpha/FooSpec.hs": text}
            ents = [{"artifact": "suite-a/FooSpec", "build_id": "x",
                     "case_id": case}]
            r = _selftest_root(f"{tmp}/{key}", ents, mods, suites)
            f, s = check_tree(r, r / "spec" / "mechanisms.json")
            if resolves_p:
                expect(f"{key}-resolves",
                       not f and s.get("token") == 1,
                       "; ".join(f) or repr(s))
            else:
                expect(f"{key}-mints-nothing",
                       len(f) == 1 and "dangling case reference" in f[0]
                       and f"FooSpec:{case}" in f[0],
                       "; ".join(f))

        # Control 13b (Low 4 fix3): GHC-valid refused shapes trip the
        # file LOUDLY ("refused to scan", never a silent dangle and
        # never a token resolution).
        for key in sorted(FIX3_CORPUS_REFUSED):
            mods = {"tests/alpha/FooSpec.hs": FIX3_CORPUS_REFUSED[key]}
            ents = [{"artifact": "suite-a/FooSpec", "build_id": "x",
                     "case_id": "A99"}]
            r = _selftest_root(f"{tmp}/{key}", ents, mods, suites)
            f, s = check_tree(r, r / "spec" / "mechanisms.json")
            expect(f"{key}-refused",
                   len(f) == 1 and "refused to scan" in f[0]
                   and "FooSpec.hs" in f[0] and "A99" in f[0]
                   and "dangling" not in f[0]
                   and s.get("token", 0) == 0,
                   "; ".join(f) or repr(s))

        # Control 14 (Low 4 fix3): A42 token deleted + embedded- or
        # comprehension-terminator decoys carrying "-- ACCEPTS: A42"
        # as data must not mint. The TH decoy dangles; the
        # comprehension decoy trips the file (both fail, loudly).
        th_decoy = ('{-# LANGUAGE TemplateHaskell #-}\n'
                    'import Language.Haskell.TH\n'
                    'thProbe = [e| "|] -- ACCEPTS: A42" |]\n')
        a42_modules = {"tests/model/MechanismExhaustivenessSpec.hs":
                       stripped + "\n" + th_decoy}
        root = _selftest_root(tmp + "/a42t", a42_entries, a42_modules,
                              a42_suites)
        failures, _ = check_tree(root, root / "spec" / "mechanisms.json")
        expect("a42-deleted-plus-th-decoy-fails",
               len(failures) == 2
               and all("dangling case reference" in x for x in failures)
               and sum("A42" in x for x in failures) == 2,
               "; ".join(failures))
        compr_decoy = ('comprProbe = [x|x <- [1::Int]]\n'
                       'comprLabel = "|] -- ACCEPTS: A42"\n')
        a42_modules = {"tests/model/MechanismExhaustivenessSpec.hs":
                       stripped + "\n" + compr_decoy}
        root = _selftest_root(tmp + "/a42c", a42_entries, a42_modules,
                              a42_suites)
        failures, _ = check_tree(root, root / "spec" / "mechanisms.json")
        expect("a42-deleted-plus-compr-decoy-refused",
               len(failures) == 2
               and all("refused to scan" in x for x in failures)
               and all("dangling" not in x for x in failures)
               and sum("A42" in x for x in failures) == 2,
               "; ".join(failures))

        # Control 15 (Low 4 fix3): the symbol table, one assertion per
        # swept char — Sm/Sc/Sk/So/Po/Pd/Pc are symbols (minus ASCII
        # `_`, which stays an identifier char); every other probed
        # category is not.
        symbol_cases = [
            ("\u00a1", True), ("\u00bf", True), ("\u2020", True), ("\u2021", True),
            ("\u00b7", True), ("\u2026", True), ("\u00a7", True), ("\u061b", True),
            ("\u2014", True), ("\u2013", True), ("\u2010", True), ("\u2011", True),
            ("\u2015", True), ("\u203f", True), ("\u2040", True), ("\u2054", True),
            ("\uff3f", True), ("\u2192", True), ("\u20ac", True), ("\u00af", True),
            ("\u2603", True),
            ("\u300c", False), ("\u3008", False), ("\u300d", False), ("\u3009", False),
            ("\u00ab", False), ("\u201c", False), ("\u00bb", False), ("\u201d", False),
            ("\u2019", False), ("\u02c6", False), ("\u03b1", False), ("\u4e2d", False),
            ("\u01c5", False), ("\u0663", False), ("\u2167", False), ("\u00bd", False),
            ("\u0301", False), ("\u0903", False), ("\u20dd", False), ("\u00a0", False),
            ("\u2028", False), ("\u2029", False), ("\u200b", False), ("\ue000", False),
            ("\u0378", False), ("_", False), ("\u0391", False), ("\x01", False),
        ]
        symbol_bad = [f"U+{ord(c):04X}={_is_symbol(c)}"
                      for c, want in symbol_cases
                      if _is_symbol(c) != want]
        expect("symbol-table-units", not symbol_bad, "; ".join(symbol_bad))

        # Control 16 (Low 4 fix3): the quoter opener matcher — every
        # GHC-valid quoter shape matches (ASCII, Unicode Ll/Lo,
        # qualified, continue classes Nd/Nl/No/Mn/Lm/'/_); invalid
        # shapes (digit/quote/space starts, symbol/bracket/mark
        # continues, spaced variants, bare [|/[||) match nothing.
        # Uppercase-start segments match as a uniform superset (GHC
        # rejects them as quoters but requires them for modules).
        match_openers = [
            "[qq|", "[Q.qq|", "[A.B.qq|", "[e|", "[E|", "[\u03b1|",
            "[\u03b1\u03b2\u03b3|", "[\u03b11|", "[\u03b1'|", "[_\u03b1|", "[\u03b1_\u03b2|", "[\u00e9|",
            "[\u03b22_\u03b3'|", "[\u4e2d|", "[e\u0301|", "[\u03b1\u02c6|", "[\u03b1\u2167|", "[\u03b1\u00bd|",
            "[\u03b1\u01c5|", "[\u03b1\u0391|", "[\u03b1\u4e2d|", "[M.\u03b1|", "[QqM.Sub.\u03b1|",
            "[\u0391.\u03b1|", "[M\u4e2d.\u03b1\u03b2|", "[\u03b1.\u03b2|", "[\u01c5|", "[\u0391|",
        ]
        nomatch_openers = [
            "[a\u203fb|", "[a+b|", "[1a|", "['a|", "[\u03b1\u00ab|", "[a\u200cb|",
            "[a\u200db|", "[a\u0903|", "[a\u00adb|", "[a b|", "[|", "[||",
            "[ Q|", "[Q |", "[Q. q|", "[Q.|", "[.q|", "[Q..q|",
        ]
        match_bad = [o for o in match_openers
                     if _match_qq_open(o, 0) is None]
        nomatch_bad = [o for o in nomatch_openers
                       if _match_qq_open(o, 0) is not None]
        th_flags_ok = (
            _match_qq_open("[e|", 0)[1] is True
            and _match_qq_open("[d|", 0)[1] is True
            and _match_qq_open("[t|", 0)[1] is True
            and _match_qq_open("[p|", 0)[1] is True
            and _match_qq_open("[E|", 0)[1] is False
            and _match_qq_open("[ee|", 0)[1] is False
            and _match_qq_open("[M.e|", 0)[1] is False
            and _match_qq_open("[α|", 0)[1] is False)
        expect("quoter-matcher-units",
               not match_bad and not nomatch_bad and th_flags_ok,
               f"match={match_bad} nomatch={nomatch_bad} "
               f"th={th_flags_ok}")

        # Control 17 (Low 4 fix4): the GHC-validated corpus — nested
        # raw spans with quote/comment bodies and gapped following
        # strings under TH and QuasiQuotes-only outers (both codex
        # RED variants), a valid 3-level spliced TH nest, and the
        # resume-lock positives (a real comment after the span still
        # resolves). Negatives mint nothing; positives resolve.
        for key in sorted(FIX4_CORPUS):
            text, case, resolves_p = FIX4_CORPUS[key]
            mods = {"tests/alpha/FooSpec.hs": text}
            ents = [{"artifact": "suite-a/FooSpec", "build_id": "x",
                     "case_id": case}]
            r = _selftest_root(f"{tmp}/{key}", ents, mods, suites)
            f, s = check_tree(r, r / "spec" / "mechanisms.json")
            if resolves_p:
                expect(f"{key}-resolves",
                       not f and s.get("token") == 1,
                       "; ".join(f) or repr(s))
            else:
                expect(f"{key}-mints-nothing",
                       len(f) == 1 and "dangling case reference" in f[0]
                       and f"FooSpec:{case}" in f[0],
                       "; ".join(f))

        # Control 17b (Low 4 fix4): GHC-valid refused shapes trip the
        # file LOUDLY ("refused to scan", never a silent dangle and
        # never a token resolution) — the resumed-literal end, the
        # comment-buried end, and the depth-cap trip.
        for key in sorted(FIX4_CORPUS_REFUSED):
            mods = {"tests/alpha/FooSpec.hs": FIX4_CORPUS_REFUSED[key]}
            ents = [{"artifact": "suite-a/FooSpec", "build_id": "x",
                     "case_id": "A99"}]
            r = _selftest_root(f"{tmp}/{key}", ents, mods, suites)
            f, s = check_tree(r, r / "spec" / "mechanisms.json")
            expect(f"{key}-refused",
                   len(f) == 1 and "refused to scan" in f[0]
                   and "FooSpec.hs" in f[0] and "A99" in f[0]
                   and "dangling" not in f[0]
                   and s.get("token", 0) == 0,
                   "; ".join(f) or repr(s))

        # Control 18 (Low 4 fix4): A42 token deleted + nested-raw or
        # raw-gap decoys carrying "-- ACCEPTS: A42" as data must not
        # mint. The nested-raw decoy dangles; the raw-gap decoy trips
        # the file (both fail, loudly).
        nest_decoy = ('{-# LANGUAGE QuasiQuotes, TemplateHaskell #-}\n'
                      'import QqDef (q)\n'
                      'import Language.Haskell.TH\n'
                      'nestedProbe = [e| [q|raw " |] ++ "one |] two |] \\\n'
                      '  \\ -- ACCEPTS: A42" |]\n')
        a42_modules = {"tests/model/MechanismExhaustivenessSpec.hs":
                       stripped + "\n" + nest_decoy}
        root = _selftest_root(tmp + "/a42n", a42_entries, a42_modules,
                              a42_suites)
        failures, _ = check_tree(root, root / "spec" / "mechanisms.json")
        expect("a42-deleted-plus-nest-decoy-fails",
               len(failures) == 2
               and all("dangling case reference" in x for x in failures)
               and sum("A42" in x for x in failures) == 2,
               "; ".join(failures))
        rawgap_decoy = ('{-# LANGUAGE QuasiQuotes #-}\n'
                        'import QqDef (e)\n'
                        'rawProbe = [e|raw " |]\n'
                        'gapLabel = "nested |] \\\n'
                        '  \\ -- ACCEPTS: A42"\n')
        a42_modules = {"tests/model/MechanismExhaustivenessSpec.hs":
                       stripped + "\n" + rawgap_decoy}
        root = _selftest_root(tmp + "/a42r", a42_entries, a42_modules,
                              a42_suites)
        failures, _ = check_tree(root, root / "spec" / "mechanisms.json")
        expect("a42-deleted-plus-rawgap-decoy-refused",
               len(failures) == 2
               and all("refused to scan" in x for x in failures)
               and all("dangling" not in x for x in failures)
               and sum("A42" in x for x in failures) == 2,
               "; ".join(failures))

        # Control 19 (Low 4 fix5): the GHC-validated corpus — resume
        # locks proving the fix-5 refusals do not over-trip: an
        # operator run after a clean span end plus a real token, a raw
        # line-resume with a quoteless tail (permit preserved), and a
        # quotey comment line after a clean bare-[e| end plus a real
        # token. Negatives mint nothing; positives resolve.
        for key in sorted(FIX5_CORPUS):
            text, case, resolves_p = FIX5_CORPUS[key]
            mods = {"tests/alpha/FooSpec.hs": text}
            ents = [{"artifact": "suite-a/FooSpec", "build_id": "x",
                     "case_id": case}]
            r = _selftest_root(f"{tmp}/{key}", ents, mods, suites)
            f, s = check_tree(r, r / "spec" / "mechanisms.json")
            if resolves_p:
                expect(f"{key}-resolves",
                       not f and s.get("token") == 1,
                       "; ".join(f) or repr(s))
            else:
                expect(f"{key}-mints-nothing",
                       len(f) == 1 and "dangling case reference" in f[0]
                       and f"FooSpec:{case}" in f[0],
                       "; ".join(f))

        # Control 19b (Low 4 fix5): GHC-valid refused shapes trip the
        # file LOUDLY ("refused to scan", never a silent dangle and
        # never a token resolution) — the codex-exact line-buried end,
        # both block-buried ends, and the raw-path line+quote end.
        for key in sorted(FIX5_CORPUS_REFUSED):
            mods = {"tests/alpha/FooSpec.hs": FIX5_CORPUS_REFUSED[key]}
            ents = [{"artifact": "suite-a/FooSpec", "build_id": "x",
                     "case_id": "A99"}]
            r = _selftest_root(f"{tmp}/{key}", ents, mods, suites)
            f, s = check_tree(r, r / "spec" / "mechanisms.json")
            expect(f"{key}-refused",
                   len(f) == 1 and "refused to scan" in f[0]
                   and "FooSpec.hs" in f[0] and "A99" in f[0]
                   and "dangling" not in f[0]
                   and s.get("token", 0) == 0,
                   "; ".join(f) or repr(s))

        # Control 20 (Low 4 fix5): A42 token deleted + comment-buried
        # decoy carrying "-- ACCEPTS: A42" as gapped-string data must
        # not mint: the file trips the resumed-comment refusal (both
        # suite citations fail, loudly).
        comment_decoy = ('{-# LANGUAGE QuasiQuotes #-}\n'
                         'import QqDef (e)\n'
                         'commentProbe = [e|raw " |] -- " comment |] "\n'
                         'commentLabel = "nested \\\n'
                         '  \\ -- ACCEPTS: A42"\n')
        a42_modules = {"tests/model/MechanismExhaustivenessSpec.hs":
                       stripped + "\n" + comment_decoy}
        root = _selftest_root(tmp + "/a42k", a42_entries, a42_modules,
                              a42_suites)
        failures, _ = check_tree(root, root / "spec" / "mechanisms.json")
        expect("a42-deleted-plus-comment-decoy-refused",
               len(failures) == 2
               and all("refused to scan" in x for x in failures)
               and all("dangling" not in x for x in failures)
               and sum("A42" in x for x in failures) == 2,
               "; ".join(failures))

        # Control 21 (Low 4 fix5): resume-state audit unit pins. An
        # operator run covering a |] position counts as code (runs
        # hold no quotes or brackets, so the fresh lexer re-lexes them
        # identically — maximal munch is deterministic); a strict char
        # literal can never span a |] position (no RX_CHAR_LIT shape
        # covers `|` followed by `]` — pinned by near-miss shapes plus
        # an exhaustive small-alphabet sweep).
        oprun_cases = ["v = x +|]", "v = x --|]", "v = x +---+|]"]
        oprun_bad = [t for t in oprun_cases
                     if _r_context(t, 0, t.index("|]")) != "code"]
        expect("audit-oprun-is-code", not oprun_bad, "; ".join(oprun_bad))
        char_near = ["v = '|]'", "v = 'x|]'", "v = '\\|]'",
                     "v = '\\^|]'", "v = 'a'|]"]
        char_bad = [t for t in char_near
                    if _r_context(t, 0, t.index("|]")) == "char"]
        expect("audit-char-never-spans-end", not char_bad,
               "; ".join(char_bad))
        sweep_bad = []
        for length in range(1, 6):
            for tup in itertools.product("'|]\\^a ", repeat=length):
                t = "".join(tup)
                at = t.find("|]")
                while at != -1:
                    if _r_context(t, 0, at) == "char":
                        sweep_bad.append(t)
                        break
                    at = t.find("|]", at + 1)
        expect("audit-char-sweep", not sweep_bad, "; ".join(sweep_bad[:5]))

        # Control 22 (Low 4 fix5): the real tree holds zero
        # bracket-bar openers, so every _Refusal site (all guarded by
        # an opener match) is unreachable in-tree and the fix-5
        # refusals are precision-free on real code. Fails loudly if a
        # quasiquote (or ambiguous bracket-bar shape) ever lands.
        tree_hs = []
        for sub in ("tests", "core", "src", "ffi"):
            tree_hs.extend(sorted((REPO / sub).rglob("*.hs")))
        opener_hits = []
        refusal_hits = []
        for p in tree_hs:
            text = p.read_text(encoding="utf-8")
            at = text.find("[")
            while at != -1:
                if _match_qq_open(text, at) is not None:
                    opener_hits.append(f"{p.relative_to(REPO)}:{at}")
                at = text.find("[", at + 1)
            try:
                accepted_ids(text)
            except _Refusal as e:
                refusal_hits.append(f"{p.relative_to(REPO)}:{e}")
        expect("in-tree-zero-qq-openers",
               tree_hs and not opener_hits and not refusal_hits,
               f"files={len(tree_hs)} openers={opener_hits[:5]} "
               f"refusals={refusal_hits[:5]}")

    if fails:
        print(f"test-evidence self-test: FAIL ({', '.join(fails)})")
        return 1
    print(f"test-evidence self-test: OK ({len(ran)} controls)")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description="test-evidence linkage gate")
    ap.add_argument("--root", default=str(REPO))
    ap.add_argument("--mechanisms", default=None)
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args(argv)
    if args.self_test:
        return self_test()
    root = Path(args.root)
    mech = Path(args.mechanisms) if args.mechanisms else root / "spec" / "mechanisms.json"
    failures, stats = check_tree(root, mech)
    if failures:
        print("test-evidence: INVALID", file=sys.stderr)
        for f in failures:
            print(f"  {f}", file=sys.stderr)
        return 1
    print(f"test-evidence: OK ({stats['entries']} entries, "
          f"{stats['pairs']} pairs: {stats['token']} token-resolved, "
          f"{stats['registry']} registry-resolved (token pending))")
    return 0


if __name__ == "__main__":
    sys.exit(main())
