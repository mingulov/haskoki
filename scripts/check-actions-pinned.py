#!/usr/bin/env python3
"""Action-pin gate (F-4 / FINAL-30): every third-party `uses:` in the
CI workflow resolves to an immutable full commit SHA, never a mutable
tag (a moved upstream tag would otherwise execute attacker code with
the publish job's contents:write + packages:write nearby).

Fails (exit 1) when any rule fails:

* NOPIN-FLOAT: no third-party `uses:` line references a mutable tag
  (the fix-plan check: `grep -n 'uses:.*@v[0-9]'` must return zero
  hits). Implemented as the stronger positive form: every
  third-party ref is exactly 40 hex.
* TAGCOMMENT: every pinned `uses:` keeps the human-readable tag as a
  trailing `# vX` comment on the same line, so reviewers still see
  the intended version.
* USES-FORM (fail closed): every line mentioning a `uses` key must
  match the strict same-line form above; any other declaration
  shape — `uses :` (space before colon), flow mappings
  (`{uses: ...}`), a bare `uses:` key whose value continues on
  the next line (multiline scalar), single/double-quoted keys
  (`"uses": ...`), explicit mapping keys (`? uses` with the
  value on a `:` line), folded/block scalar values (`uses: >`),
  or anything else the strict parser cannot classify as
  pinned-or-local — FAILS instead of being silently skipped.
  YAML accepts all of these as real `uses` keys, so skipping
  them would let a mutable action through while the gate
  reports success.
* GRAMMAR (fail closed): the workflow stays inside a restricted
  YAML subset — plain block mappings/sequences/scalars as used by
  the real ci.yml. Any line outside the subset FAILS: quoted
  mapping keys (`"key":` / `'key':`, block or flow — every
  structural locator matches bare spellings only, so any quoted
  key fails closed instead of being silently skipped),
  `&` anchors, `*` aliases, `<<` merge keys, explicit `?` keys,
  `!` tags,
  backslashes (escape sequences like `"us\\u0065s"` decode to a
  `uses` key behind a text scan's back), quotes glued inside
  plain scalars (`a"b` desyncs comment stripping and hides the
  rest of the line), whitespace-preceded plain-scalar quotes
  (`a " b` — a quote OPENS only at a node start, i.e. with
  nothing but whitespace back to line start or to a STRUCTURAL
  `:`, `,`, `[`, `{`, `?`, or sequence dash (a `-` counts only
  when its own preceding context recursively validates as a
  boundary — `:`/`?`/`-`/compounds glued to the quote, as in
  `a:"b` or `a:- "b`, are scalar content in block AND
  flow — never boundaries); anything else is a literal that
  the naive tracker would misread, so any line where naive and
  node-start-aware tracking disagree on the `#` cut or end state
  FAILS; balanced embedded pairs such as `!= 'true'` or
  `hashFiles('...')` that change neither are explicitly
  supported), unterminated quotes (multiline quoted
  scalars), and explicit block-scalar indent indicators (`|2` —
  subset admits bare `|`/`>` plus `-`/`+` chomping only).
  Block-scalar (`run: |`) bodies are shell text tracked by the
  first-body-line indent threshold and are exempt from YAML-shape
  rules (a `uses:`-looking line there is not a key — GitHub agrees);
  every other exotic shape fails closed instead of being
  silently skipped.
* DEPENDABOT: `.github/dependabot.yml` exists and schedules
  automated SHA bumps for the github-actions ecosystem (pins rot
  without a bumper).

Scope: a `uses:` is third-party when its value names another repo
(`owner/repo[/path]@ref`); only first-party local references
(`./...` — GitHub Actions requires the `./` prefix, so bare
words are not valid local refs and fail closed) need no pin and
are excluded. Currently ci.yml has no local references — all 43
`uses:` lines are third-party.

STDLIB ONLY (PyYAML is NOT importable in the CI static-gates
container — apt python3 only — so semantic YAML parsing is out;
the USES-FORM rule above is the stdlib-only fail-closed
equivalent). Run on HOST python3 from anywhere:
  python3 scripts/check-actions-pinned.py [path/to/ci.yml]
(the optional path exists so a negative-control run can check the
pins against the pre-F-4 workflow: FAIL there, ok on the rewrite).

Self-test (durable F-4..F-8 fix-round regression, wired into the
CI static-gates step and scripts/run-gates.sh):
  python3 scripts/check-actions-pinned.py --self-test
runs the evasive-form negative controls (each must FAIL the
gate: space-before-colon, flow mapping, multiline scalar,
single/double-quoted keys, explicit `? uses` key, folded/literal
scalar values, `#`-inside-quotes, escaped keys (`\\uXXXX` /
`\\xXX`), aliased keys (merge + explicit-alias), explicit folded
keys, quote desync (glued, whitespace-preceded, colon-adjacent
AND dash-adjacent plain-scalar quotes, double- and single-quote),
one restricted-grammar unit probe per forbidden construct,
compound-prefix dash-borrowing negatives (`:-` / `--` /
repeated-dash chains, both quote styles, minimal + E2E), and
the end-to-end real-ci.yml + publish-step + colon-desync
insertion bypasses), a pinned + a local + a scalar-body-exempt
positive control (each must pass: a `uses:`-looking line inside
a `run: |` body is shell text, not a key), a real-key-after-body
negative (dedent ends the body), body-threshold negatives
(explicit `|2` / `|-2` indicators rejected, `|-` / `>+` /
trailing-comment headers catch a real key dedented below the
first body line, empty scalar catches the next key, compact
`- name: |` empty scalar + comment + key boundary in bare /
chomping / commented-header / publish-insertion / quoted-key
shapes) plus chomping/comment-header/compact-real-body/colon-heavy
positives (legitimate headed style still passes with body
exemption; legitimate `:`-heavy lines still pass), the real
ci.yml (must pass with the same pinned count), the F-6/F-7
structural asserts (every checker-stage pip install argv is
effectively wheel-only — shell + JSON exec RUN payloads parsed
in true shell order (splice-join, comment cut), supported
`sh -c` wrappers inspected recursively, heredoc / unparseable /
unsupported exec RUN refused, `$`/backquote-carrying pip argvs
refused, pip's format-control precedence applied; publish needs
the required job set, attributed strictly by job block; the
UNIQUE c-drivers timed driver step, selected by its normalized
executable run payload, selects shell: bash; every quoted
mapping key refused by GRAMMAR),
eighteen liveness probes (each non-executable substitute —
commented-out setting, flag on an echo, setting inside an env
string / publish.name / mid-line echo, same-named step in
another job, same-job shell decoy, duplicated driver commands,
added unflagged RUN, JSON exec RUN, heredoc RUN, `:none:`
clearer, env-decoy anchor + reformatted real loop x2,
decoy-only anchor, wrapped unflagged pip, unsupported exec
form — must trip exactly its own assert), two
reformatted-loop positives (env decoy + shell kept still
select the real step), the format-control branch matrix
(last-wins, `:none:` clears, no-binary interplay, RUN flags,
exec-form, wrapper/nesting/depth and refused-RUN branches),
and the fix-7 suite (quoted-key GRAMMAR refusal per locator,
wrong-job-attribution E2E + locator-direct probes, shell
comment/expansion/continuation differentials both polarities),
and the fix-8 suite (escaped-operator splitting both polarities,
command/exec/env/sudo prefix matrix, unsupported-wrapper refusal,
heredoc-spelling refusals + heredoc-free positives,
tokenization-error trips), and the fix-9 suite (pip global-option
normalization grounded in pip's real parser, attached -mpip
recognition, unrecognized-shape refusals, and
expansion-before-skip ordering with executable-substitution
refusal, plus the real-stage substitution-free enumeration),
and the fix-10 suite (CPython short-option-cluster module
resolution grounded in the 3.14 option grammar with
unrecognized-shape refusals, and pip install-option value
ownership grounded in pip 26.2.1 with effective-flags
evaluation),
and the fix-11 suite (compound-head cluster backstop: ANY
fragment carrying a `-mpip`-style module-selector cluster
trips regardless of argv[0], with re-joined/spaced forms,
`!`-negation, function-def/trap trip-on-definition decisions,
documented over-trip locks, and the real-stage zero-hit proof).
"""
import json
import re
import shlex
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DEFAULT = REPO / ".github" / "workflows" / "ci.yml"
DEPENDABOT = REPO / ".github" / "dependabot.yml"

USES_RE = re.compile(r"^\s*(?:-\s+)?uses:\s*(\S+)\s*(#.*)?$")
# Fail-closed tripwire: any mention of a `uses` key — bare,
# single/double-quoted, or explicit (`? uses`, whose value sits
# on a following `:` line) — in block or flow context, any
# pre-colon spacing, value present or not — on the
# comment-stripped line. Consulted only when USES_RE does not
# match, so strict same-line declarations never trip it.
USES_KEY_RE = re.compile(
    r"(?:^|[\s{,\-])"
    r"(?:uses\s*:|\"uses\"\s*:|'uses'\s*:"
    r"|\?\s+[\"']?uses[\"']?(?=\s|:|$))")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
FLOAT_RE = re.compile(r"@v[0-9]")

failures = []


def check(rule, cond, detail):
    print(f"{'ok' if cond else 'FAIL'}: {rule}: {detail}")
    if not cond:
        failures.append(rule)


def strip_comment(line: str) -> str:
    """Cut a YAML `#` comment: the first `#` at line start or after
    whitespace that sits OUTSIDE single/double quotes. A `#` inside
    a quoted string is data, not a comment — the naive stripper
    truncated `- {name: "a # b", uses: ...}` and hid the uses key.
    Quote state is per-line; `\"` is an escape inside "..." (YAML
    double-quoted style). `uses` mentions inside comments are
    prose, not keys."""
    quote = None
    i = 0
    while i < len(line):
        ch = line[i]
        if quote == '"' and ch == "\\":
            i += 2  # backslash escape: never a quote boundary
            continue
        if ch in "'\"":
            if quote is None:
                quote = ch
            elif quote == ch:
                quote = None
        elif ch == "#" and quote is None and (i == 0 or line[i - 1] in " \t"):
            return line[:i]
        i += 1
    return line


# A block-scalar header: `key: |` / `key: >` (optional BARE
# chomping indicator `+`/`-`, optional trailing comment already
# stripped) or a bare sequence-item scalar (`- |`). Explicit indent
# indicators (`|2`, `>-2`, `|+2`, `|2-`, ... — any `|`/`>` followed
# by a digit) are NOT headers: the restricted subset rejects them
# outright (INDENT_IND_RE via grammar_violation), removing the
# indicator-arithmetic attack surface. Anything else ending in
# `|`/`>` (mid-scalar shell pipes, `||`) is not a header.
BLOCK_HDR_RE = re.compile(
    r"^\s*(?:-\s+)?[^:#]*?:\s*[|>][+-]?\s*$"
    r"|^\s*-\s*[|>][+-]?\s*$")
INDENT_IND_RE = re.compile(
    r"^\s*(?:-\s+)?[^:#]*?:\s*[|>](?:[+-]?[0-9]+|[0-9]+[+-]?)\s*$"
    r"|^\s*-\s*[|>](?:[+-]?[0-9]+|[0-9]+[+-]?)\s*$")


def end_quote_state(code: str, start):
    """Naive quote pass over comment-stripped code; returns the quote
    (`'`/`"`/None) left open at end of line. Shared by body /
    continuation tracking; `\"` is an escape inside "..." exactly
    as in strip_comment."""
    quote = start
    i, n = 0, len(code)
    while i < n:
        ch = code[i]
        if quote == '"' and ch == "\\":
            i += 2
            continue
        if ch in "'\"":
            if quote is None:
                quote = ch
            elif quote == ch:
                quote = None
        i += 1
    return quote


def structural_lines(text: str):
    """Yield (idx0, indent, raw, code) for lines that are YAML
    structure. Skips block-scalar bodies (shell text, where
    `uses:`-looking lines are not keys) and multiline-quote
    continuations (lines consumed by a quote left open earlier —
    scalar content, never keys). `code` is comment-stripped.

    Body rule (first-body-line): after a block-scalar header the
    body threshold is the indent of the FIRST non-blank,
    non-comment following line when it is more indented than the
    header indent (the auto-detected content indent); a dedent
    below it ends the body and the ending line is structural. A
    header immediately followed by a real line at or below header
    indent is an empty scalar: no body, the next line is
    structural. Comment-only lines (like blank lines) never
    resolve `pending` nor set the threshold — only real content
    lines do; once a threshold IS set, `#` lines inside it stay
    literal body text. The header indent of a compact `- key: |`
    mapping is the KEY's column (past `- `), not the dash's —
    the scalar's parent indentation is the key's.
    (`pending` larger than the dash errs toward structural, i.e.
    fail-closed: structural lines are scanned, body lines are
    skipped.)"""
    thresh = None
    pending = None
    in_quote = None
    for idx, raw in enumerate(text.splitlines()):
        ind = len(raw) - len(raw.lstrip(" "))
        code = strip_comment(raw)
        if pending is not None:
            if code.strip() == "":
                continue
            if ind > pending:
                thresh = ind - 1
                pending = None
                continue
            pending = None
            thresh = None
        if thresh is not None:
            if raw.strip() == "" or ind > thresh:
                continue
            thresh = None
        if in_quote is not None:
            in_quote = end_quote_state(code, in_quote)
            continue
        in_quote = end_quote_state(code, None)
        if BLOCK_HDR_RE.match(code):
            m = re.match(r"^\s*-\s+", code)
            if m and not re.match(r"^\s*-\s*[|>]", code):
                pending = len(m.group(0))  # compact `- key:`: key column
            else:
                pending = ind
        yield idx, ind, raw, code


# Restricted-grammar sigils. A quote may only OPEN at a node
# start (`_node_start`); anywhere else it is glued inside a plain
# scalar and desyncs naive comment stripping. `&`/`*` / `!` / `?`
# are structural only at node start.
SAFE_QUOTE_PREV = set(" \t:,([{?-\"'")
ANCHOR_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-")
MERGE_RE = re.compile(r"(?:^|[{,])\s*(?:-\s+)?[\"']?<<")


def _node_start(code: str, pos: int) -> bool:
    """True when position `pos` starts a YAML node: only whitespace
    back to line start or to a STRUCTURAL `:`, `,`, `[`, `{`, `?`,
    or a real sequence dash. Structural is YAML-context-sensitive
    (each primitive verified against PyYAML; callers pass the index
    of a quote/sigil, so `j + 1 <= pos < len(code)` always holds):
    - `:` is a mapping colon only when followed by space/tab/EOL.
      `a:"b` is ONE plain scalar in block AND in flow (`{a:b}` is
      `{'a:b': None}`, not `{'a': 'b'}`), so a colon-glued quote is
      a literal, never an opener. The flow-only exception (`:`
      before `,`/`[`/`]`/`{`/`}`, as in `{a:, b: c}`) can never
      precede a quote: the lookback lands on `:` only when
      whitespace or the quote itself follows.
    - `?` is an explicit key only when followed by space/tab AND
      itself at a node start (recursion terminates: strictly
      smaller positions). `x? "b"` is a block scalar and a flow
      error — neither opens.
    - `-` is a sequence dash only when followed by space/tab AND
      its own preceding context recursively validates as a node
      boundary (`_dash_boundary`: line start modulo whitespace, or
      after a structural `: `/`, `/`[`/`{`/`?`/dash, each validated
      on strictly smaller positions). `-"a"` is one scalar; `- `
      inside flow is an error, so no flow gating is needed. A `-`
      that merely borrows structural appearance from adjacent
      scalar content (`a:- "b` — the `:` is followed by `-`, not
      space; `a-- "b` — the first `-` is mid-scalar) is content.
      General invariant: NO boundary char is recognized unless
      its full preceding context recursively validates (`:` is
      structural iff followed by space/tab/EOL wherever it stands
      — a compound sweep with a PyYAML oracle confirms no valid
      line lends it structure otherwise; `?`/`-` recurse;
      `,`/`[`/`{` stay unconditional, re-confirmed valid-proof
      under compound prefixes).
    - `,`/`[`/`{` stay unconditional: a quote after `,` or a
      mid-scalar bracket in BLOCK is literal but provably
      unexploitable — a block line holds a single node and plain
      scalars exclude `: `, so no valid line hides a key that way
      (PyYAML rejects every such shape: same-line hidden `uses:`,
      flow-after-scalar, scalar-after-flow); in flow all three are
      always structural. Same argument covers a line-start quote
      inside a plain-scalar continuation (`key: abc` / `  "def"`):
      literal in YAML, but the continuation cannot hide a key."""
    j = pos - 1
    while j >= 0 and code[j] in " \t":
        j -= 1
    if j < 0:
        return True
    nxt = code[j + 1] if j + 1 < len(code) else ""
    if code[j] == ":":
        return nxt in " \t" or nxt == ""
    if code[j] == "?":
        return (nxt in " \t" or nxt == "") and _node_start(code, j)
    if code[j] == "-":
        if nxt not in " \t":
            return False
        return _dash_boundary(code, j)
    return code[j] in ",[{"


def _dash_boundary(code: str, j: int) -> bool:
    """True when the `-` at `j` (already known to be followed by
    space/tab) is a real sequence dash: its own preceding context,
    skipping whitespace, must be a node boundary — line start, or a
    STRUCTURAL `: `/`, `/`[`/`{`/`?`/dash, each validated
    recursively on strictly smaller positions (terminates). A `-`
    that borrows structural appearance from adjacent scalar
    content is content: in `a:- "b` the `:` is followed by `-`,
    not space; in `a-- "b` the first `-` is mid-scalar. The
    whitespace gap between the context char and the dash decides
    `:`/`?` followed-by-space without re-reading forward:
    code[k+1:j] was skipped as whitespace, so k+1<j means
    code[k+1] is space/tab (else it is the dash itself)."""
    k = j - 1
    while k >= 0 and code[k] in " \t":
        k -= 1
    if k < 0:
        return True
    c = code[k]
    if c == ":":
        # Structural colon iff followed by space/tab: exactly when a
        # whitespace gap separates it from the dash. `a:- "b`
        # (adjacent) is a content colon, so the dash is content.
        return k + 1 < j
    if c == "?":
        # Explicit key iff followed by space/tab AND itself at a node
        # start (recursion on strictly smaller positions).
        return k + 1 < j and _node_start(code, k)
    if c == "-":
        # Nested sequence dash (`- - foo`) iff the preceding dash is
        # itself a sequence dash: it must be followed by space/tab
        # (a gap — adjacent `--` glues it into the scalar) and pass
        # this same rule (recursion on strictly smaller positions).
        return k + 1 < j and _dash_boundary(code, k)
    return c in ",[{"


def _expr_spans(code: str):
    """`${{ ... }}` spans: GitHub expression text inside a plain
    scalar, never YAML structure (`!` there is negation)."""
    spans = []
    i = 0
    while True:
        s = code.find("${{", i)
        if s < 0:
            return spans
        e = code.find("}}", s + 3)
        if e < 0:
            e = len(code)
        spans.append((s, e + 2))
        i = e + 2


def _quote_tracking_agrees(raw: str) -> bool:
    """Naive and node-start-aware quote tracking agree on this
    line's `#` cut and end state. A quote OPENS a quoted scalar
    only at a node start (`_node_start`: nothing but whitespace
    back to line start or to a STRUCTURAL `:`, `,`, `[`, `{`,
    `?`, or sequence dash — structural is context-sensitive: `:`
    / `?` / `-` glued to the quote, as in `a:"b`, are scalar
    content, never boundaries); anywhere else it is a
    plain-scalar-embedded literal (`a " b` keeps a literal quote
    in YAML) that the naive tracker would misread as a toggle. Any disagreement means
    the naive comment strip desyncs on this line — the stripped
    `code` cannot be trusted — so the line is non-subset.
    Balanced embedded pairs (`!= 'true'`, `hashFiles('...')`,
    `|| 'v0.2.1'`) toggle the naive tracker twice and cut
    nothing, so both trackers agree and the line stays admitted:
    they are explicitly supported. (The naive strip itself is
    unchanged: Dockerfile shell text NEEDS naive quote handling,
    where `echo "a # b"` really does quote the `#`.)"""
    naive_cut: int | None = None
    quote = None
    i, n = 0, len(raw)
    while i < n:
        ch = raw[i]
        if quote == '"' and ch == "\\":
            i += 2
            continue
        if ch in "'\"":
            if quote is None:
                quote = ch
            elif quote == ch:
                quote = None
        elif ch == "#" and quote is None and (i == 0 or raw[i - 1] in " \t"):
            naive_cut = i
            break
        i += 1
    naive_end = quote
    aware_cut: int | None = None
    quote = None
    i = 0
    while i < n:
        ch = raw[i]
        if quote == '"' and ch == "\\":
            i += 2
            continue
        if ch in "'\"":
            if quote is None:
                if _node_start(raw, i):
                    quote = ch
                # else: plain-scalar-embedded literal, ignored
            elif quote == ch:
                quote = None
        elif ch == "#" and quote is None and (i == 0 or raw[i - 1] in " \t"):
            aware_cut = i
            break
        i += 1
    return naive_cut == aware_cut and naive_end == quote


def _quoted_mapping_key(code: str):
    """The quoted mapping key opened on comment-stripped `code`
    (e.g. `"run"`), else None. A quote opens a KEY only at a node
    start (`_node_start`) whose matching close quote is followed by
    optional whitespace + `:` — block (`  "job":`,
    `    "needs": ...`, `      - "uses": ...`) and flow
    (`{"k": v}`, `{a: 1, "k": v}`) alike. Quoted VALUES never
    match: after `key: ` / `, ` their close quote is followed by
    EOL / `,` / `}` (never `:`), and mid-scalar quotes
    (`run: echo "a: b"`) are not node starts at all. Quote-aware:
    `\\` escapes inside "..." (a line with a backslash is refused
    by its own rule first, so this only orients the scan),
    `''` pairs inside '...', and `${{ ... }}` spans skipped
    (expression text, never key position). The restricted subset
    refuses ALL quoted keys (fail closed): every structural
    locator (`run:`/`needs:`/`shell:`/`steps:`/`jobs:` finders,
    job-id matching) matches bare spellings only, and a quoted
    spelling YAML accepts but a locator skips passes weakened
    (Low 1 `"run":`, Low 3 `"needs"` + quoted job ids)."""
    spans = _expr_spans(code)
    i, n = 0, len(code)
    while i < n:
        ch = code[i]
        if ch in "'\"":
            # A quoted KEY must open at a node start; anything else
            # is a plain-scalar-embedded literal (ignored — the
            # desync/glued-quote rules own those lines).
            if _node_start(code, i) and not any(s <= i < e for s, e in spans):
                q = ch
                j = i + 1
                closed = -1
                while j < n:
                    c = code[j]
                    if q == '"' and c == "\\":
                        j += 2
                        continue
                    if q == "'" and c == "'" and j + 1 < n and code[j + 1] == "'":
                        j += 2
                        continue
                    if c == q:
                        closed = j
                        break
                    j += 1
                if closed >= 0:
                    k = closed + 1
                    while k < n and code[k] in " \t":
                        k += 1
                    if k < n and code[k] == ":":
                        return code[i:closed + 1]
                    i = closed + 1  # quoted value: skip the span
                    continue
                # Unbalanced tail: the rest of the line sits inside
                # the quoted scalar, so no key can follow on it
                # (the unterminated rule owns the line itself).
                return None
            i += 1
            continue
        i += 1
    return None


def grammar_violation(code: str, raw: str):
    """None when comment-stripped `code` is inside the restricted
    subset, else the reason it fails closed. Every naive/reality
    divergence needs a glued quote or an unbalanced tail, so
    rejecting those keeps the naive comment strip sound: balanced
    node-start quotes behave identically under both. `raw` (the
    unstripped line) feeds the desync tripwire: stripping may
    already have cut the evidence, so naive/aware agreement is
    checked before trusting the cut."""
    if INDENT_IND_RE.match(code):
        return "explicit block-scalar indent indicator (subset: bare | > + chomping only)"
    if "\\" in code:
        return "backslash outside block scalar (no escape sequences)"
    if not _quote_tracking_agrees(raw):
        return "quote tracking desync (plain-scalar quote misread as opener)"
    qkey = _quoted_mapping_key(code)
    if qkey is not None:
        return f"quoted mapping key {qkey} (restricted subset: bare keys only)"
    spans = _expr_spans(code)
    quote = None
    i, n = 0, len(code)
    while i < n:
        ch = code[i]
        if ch in "'\"":
            if quote is None:
                prev = code[i - 1] if i else None
                if prev not in SAFE_QUOTE_PREV:
                    return "quote glued inside plain scalar (desync risk)"
                quote = ch
            elif quote == ch:
                quote = None
            i += 1
            continue
        if quote is None and not any(s <= i < e for s, e in spans):
            nxt = code[i + 1] if i + 1 < n else ""
            if ch in "&*":
                if nxt in ANCHOR_CHARS and _node_start(code, i):
                    return ("YAML anchor (restricted subset has none)"
                            if ch == "&" else
                            "YAML alias (restricted subset has none)")
            elif ch == "!":
                if _node_start(code, i):
                    return "YAML tag (restricted subset has none)"
            elif ch == "?":
                if nxt in (" ", "\t", "") and _node_start(code, i):
                    return "explicit ? key (restricted subset has none)"
        i += 1
    if quote is not None:
        return "unterminated quote (no multiline quoted scalars)"
    m = MERGE_RE.search(code)
    if m and not any(s <= m.start() < e for s, e in spans):
        return "merge key << (restricted subset has none)"
    return None


def check_text(src: str) -> int:
    del failures[:]
    third_party = []  # (lineno, ref, comment, raw)
    local = 0
    unsupported = []  # (lineno, raw): uses key the strict parser skips
    grammar = []  # (lineno, raw, reason): lines outside the subset
    for idx, _ind, line, code in structural_lines(src):
        i = idx + 1
        reason = grammar_violation(code, line)
        if reason:
            grammar.append((i, line.strip(), reason))
        m = USES_RE.match(line)
        if not m:
            if USES_KEY_RE.search(code):
                unsupported.append((i, line.strip()))
            continue
        value, comment = m.group(1), m.group(2) or ""
        if value.startswith("./"):
            local += 1
            continue
        if "@" not in value or "/" not in value.split("@")[0]:
            # Unrecognized value shape (block scalar `>`/`|`,
            # quoted string, bare word, ...): this is a uses key
            # the strict parser cannot classify — fail closed,
            # never count as local.
            unsupported.append((i, line.strip()))
            continue
        ref = value.split("@", 1)[1]
        third_party.append((i, ref, comment, line.strip()))

    floats = [(i, raw) for i, ref, _, raw in third_party
              if not SHA_RE.match(ref)]
    check("NOPIN-FLOAT", not floats,
          f"all {len(third_party)} third-party uses: pinned to 40-hex SHA "
          f"({local} local excluded)"
          if not floats else
          "mutable refs: " + "; ".join(f":{i} {raw}" for i, raw in floats[:4]))
    # The fix-plan grep, verbatim semantics: zero hits required.
    # Block-scalar bodies are shell text, not YAML, so they are out
    # of scope here exactly as for every other rule.
    grep_hits = [idx + 1 for idx, _ind, line, _code in structural_lines(src)
                 if "uses:" in line and FLOAT_RE.search(line)]
    check("NOPIN-GREP", not grep_hits,
          "plan grep `uses:.*@v[0-9]` returns zero hits"
          if not grep_hits else
          f"grep hits at lines {grep_hits[:4]}")

    untagged = [(i, raw) for i, _, c, raw in third_party
                if not re.search(r"#\s*v[0-9]", c)]
    check("TAGCOMMENT", not untagged,
          f"all {len(third_party)} pinned lines carry a trailing `# vX` comment"
          if not untagged else
          "missing tag comment: " + "; ".join(f":{i} {raw}" for i, raw in untagged[:4]))

    check("USES-FORM", not unsupported,
          "every uses key uses the strict same-line form"
          if not unsupported else
          "unsupported uses declaration (fail closed): "
          + "; ".join(f":{i} {raw}" for i, raw in unsupported[:4]))

    check("GRAMMAR", not grammar,
          "every line stays inside the restricted YAML subset"
          if not grammar else
          "non-subset YAML (fail closed): "
          + "; ".join(f":{i} {raw} [{why}]" for i, raw, why in grammar[:4]))

    dep_ok = DEPENDABOT.is_file()
    dep_text = DEPENDABOT.read_text() if dep_ok else ""
    check("DEPENDABOT", dep_ok
          and 'package-ecosystem: "github-actions"' in dep_text
          and "schedule:" in dep_text and "interval:" in dep_text,
          ".github/dependabot.yml schedules github-actions SHA bumps"
          if dep_ok else ".github/dependabot.yml missing")

    if failures:
        print(f"actions-pinned: FAIL ({', '.join(failures)})")
        return 1
    print("actions-pinned: OK (third-party uses: SHA-pinned + Dependabot wired)")
    return 0


# ---------------------------------------------------------------------------
# Self-test: durable F-4..F-8 fix-round regression. Each case is (name,
# workflow text — None for the real ci.yml, "E2E" for the real
# ci.yml plus the publish-step bypass — expected gate rc). The
# negative controls are the exact evasive forms from the fix-round
# briefs; they must FAIL the gate (rc 1). Quiet per-case: only the
# verdict line prints unless a case mismatches.
# ---------------------------------------------------------------------------


def e2e_bypass_text() -> str:
    """The end-to-end bypass demo: the real ci.yml plus one mutable
    publish-step `uses` in an evasive (quoted-key) spelling. 44 real
    refs; the gate must FAIL, not report 43 pinned."""
    t = DEFAULT.read_text()
    i = t.index("  publish:")
    j = t.index("    steps:", i)
    k = t.index("\n", j) + 1
    return t[:k] + '      - "uses": actions/checkout@main\n' + t[k:]


def e2e_compact_empty_text() -> str:
    """The real ci.yml plus a compact `- name: |` empty scalar
    (comment + mutable uses key at key indent) as the first
    publish step: empty name plus a REAL mutable action; the
    gate must FAIL, not swallow the key as scalar body."""
    t = DEFAULT.read_text()
    i = t.index("  publish:")
    j = t.index("    steps:", i)
    k = t.index("\n", j) + 1
    return (t[:k] + "      - name: |\n"
            "        # comment at indent 8\n"
            "        uses: actions/checkout@main\n" + t[k:])


def e2e_colon_text(extra: str) -> str:
    """The real ci.yml plus one colon-adjacent-quote desync step
    (codex's exact insertion point): YAML resolves 44 actions; the
    gate must FAIL, not report 43 pinned."""
    t = DEFAULT.read_text()
    anchor = "      - name: Stage draft release and verify all uploaded files\n"
    i = t.index(anchor)
    return t[:i] + extra + t[i:]


E2E_COLON_DOUBLE = ('      - {name: a:"b, env: {K: " # label"}, '
                    'uses: actions/checkout@main}\n')
E2E_COLON_SINGLE = ("      - {name: a:'b, env: {K: ' # label'}, "
                    "uses: actions/checkout@main}\n")
E2E_COMPOUND_COLONDASH_DOUBLE = ('      - {name: a:- "b, env: {K: " # label"}, '
                                 'uses: actions/checkout@main}\n')
E2E_COMPOUND_COLONDASH_SINGLE = ("      - {name: a:- 'b, env: {K: ' # label'}, "
                                 "uses: actions/checkout@main}\n")
E2E_COMPOUND_DASHDASH_DOUBLE = ('      - {name: a-- "b, env: {K: " # label"}, '
                                'uses: actions/checkout@main}\n')
E2E_COMPOUND_DASHDASH_SINGLE = ("      - {name: a-- 'b, env: {K: ' # label'}, "
                                "uses: actions/checkout@main}\n")


def e2e_quoted_run_text() -> str:
    """Low-1 codex shape: the real driver `run:` spelled `"run": |`
    with its `shell: bash` removed, plus a second Bash run holding
    the same loop header but only `echo "$d"` — the old selector
    picked the decoy and the gate passed the shell-less driver."""
    t = DEFAULT.read_text()
    timed = "      - name: PR driver subset (timed, deterministic)\n"
    t_at = t.index(timed)
    mangled = t.replace("        shell: bash\n", "", 1)
    run_at = mangled.index("        run: |\n", t_at)
    mangled = (mangled[:run_at] + '        "run": |\n'
               + mangled[run_at + len("        run: |\n"):])
    decoy = ("      - name: driver loop echo\n"
             "        shell: bash\n"
             "        run: |\n"
             "          for d in test-loader.sh test-c-abi.sh test-c-output.sh"
             "; do echo \"$d\"; done\n")
    return mangled[:t_at] + decoy + mangled[t_at:]


def e2e_quoted_needs_text() -> str:
    """Low-3 codex shape: publish's dependency key spelled `"needs"`
    (c-drivers omitted) plus an inserted quoted successor job header
    carrying the required list — the old locator skipped both
    quoted forms and attributed the successor's list to publish."""
    t = DEFAULT.read_text()
    mangled = t.replace(
        "    needs: [release-request, haskell, bundle, c-drivers, pkcs11-fast, demo-image]\n",
        '    "needs": [haskell, bundle, pkcs11-fast, demo-image]\n', 1)
    pub_at = mangled.index("  publish:\n")
    nxt = re.search(r"(?m)^  [A-Za-z0-9_-]+:\s*$", mangled[pub_at + 10:])
    succ = ('  "zzz":\n'
            '    needs: [release-request, haskell, bundle, c-drivers, pkcs11-fast, demo-image]\n')
    at = pub_at + 10 + nxt.start()
    return mangled[:at] + succ + mangled[at:]
SELF_CASES = [
    ("neg-space-before-colon",
     "jobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n"
     "      - uses : actions/checkout@v6\n",
     1),
    ("neg-flow-mapping",
     "jobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n"
     "      - {uses: actions/checkout@main, name: sneaky}\n",
     1),
    ("neg-multiline-scalar",
     "jobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n"
     "      - uses:\n          actions/checkout@main\n",
     1),
    ("neg-quoted-key-double",
     "jobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n"
     "      - \"uses\": actions/checkout@main\n",
     1),
    ("neg-quoted-key-single",
     "jobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n"
     "      - 'uses': actions/checkout@main\n",
     1),
    ("neg-explicit-key",
     "jobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n"
     "      - ? uses\n        : actions/checkout@main\n",
     1),
    ("neg-explicit-key-quoted",
     "jobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n"
     "      - ? \"uses\"\n        : actions/checkout@main\n",
     1),
    ("neg-folded-scalar",
     "jobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n"
     "      - uses: >\n          actions/checkout@main\n",
     1),
    ("neg-literal-scalar",
     "jobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n"
     "      - uses: |\n          actions/checkout@main\n",
     1),
    ("neg-hash-in-quotes",
     "jobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n"
     "      - {name: \"a # b\", uses: actions/checkout@main}\n",
     1),
    ("neg-escaped-key-u",
     "jobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n"
     "      - \"us\\u0065s\": actions/checkout@main\n",
     1),
    ("neg-escaped-key-x",
     "jobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n"
     "      - \"us\\x65s\": actions/checkout@main\n",
     1),
    ("neg-alias-merge",
     "x-anchor: &evil\n"
     "  \"us\\u0065s\": actions/checkout@main\n"
     "jobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n"
     "      - name: sneaky\n"
     "        <<: *evil\n",
     1),
    ("neg-alias-explicit-key",
     "defs:\n  k: &k uses\n"
     "jobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n"
     "      - ? *k\n"
     "        : actions/checkout@main\n",
     1),
    ("neg-explicit-folded",
     "jobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n"
     "      - ? >\n"
     "          uses\n"
     "        : actions/checkout@main\n",
     1),
    ("neg-explicit-folded-strip",
     "jobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n"
     "      - ? >-\n"
     "          uses\n"
     "        : actions/checkout@main\n",
     1),
    ("neg-quote-desync",
     "jobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n"
     "      - {name: a\"b, env: {K: \" # label\"}, "
     "uses: actions/checkout@main}\n",
     1),
    ("neg-gram-anchor",
     "jobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n"
     "      - name: x\n"
     "        data: &anchor value\n",
     1),
    ("neg-gram-alias",
     "jobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n"
     "      - name: x\n"
     "        data: *missing\n",
     1),
    ("neg-gram-merge",
     "jobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n"
     "      - name: x\n"
     "        <<: *missing\n",
     1),
    ("neg-gram-explicit",
     "jobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n"
     "      - ? foo\n"
     "        : bar\n",
     1),
    ("neg-gram-tag",
     "jobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n"
     "      - name: x\n"
     "        data: !custom value\n",
     1),
    ("neg-gram-midscalar-quote",
     "jobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n"
     "      - name: a\"b\n",
     1),
    ("neg-gram-unbalanced",
     "jobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n"
     "      - name: \"oops\n",
     1),
    ("neg-gram-backslash",
     "jobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n"
     "      - run: echo \"a\\nb\"\n",
     1),
    ("neg-real-key-after-body",
     "jobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n"
     "      - name: tricky\n"
     "        run: |\n"
     "          echo hi\n"
     "        uses: actions/checkout@main\n",
     1),
    ("neg-e2e-publish-bypass", "E2E", 1),
    ("neg-body-indicator-pipe2",
     "jobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n"
     "      - run: |2\n"
     "          echo hi\n"
     "        uses: actions/checkout@main\n",
     1),
    ("neg-body-chomp-strip",
     "jobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n"
     "      - run: |-\n"
     "          echo hi\n"
     "        uses: actions/checkout@main\n",
     1),
    ("neg-body-header-comment",
     "jobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n"
     "      - run: | # comment\n"
     "          echo hi\n"
     "        uses: actions/checkout@main\n",
     1),
    ("neg-body-chomp-keep",
     "jobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n"
     "      - run: >+\n"
     "          echo hi\n"
     "        uses: actions/checkout@main\n",
     1),
    ("neg-body-indicator-strip2",
     "jobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n"
     "      - run: |-2\n"
     "          echo hi\n"
     "        uses: actions/checkout@main\n",
     1),
    ("neg-body-empty-scalar",
     "jobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n"
     "      - name: x\n"
     "        run: |\n"
     "        uses: actions/checkout@main\n",
     1),
    ("neg-quote-desync-space-double",
     "jobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n"
     "      - {name: a \" b, env: {K: \" # label\"}, "
     "uses: actions/checkout@main}\n",
     1),
    ("neg-quote-desync-space-single",
     "jobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n"
     "      - {name: a ' b, env: {K: ' # label'}, "
     "uses: actions/checkout@main}\n",
     1),
    ("neg-body-compact-empty",
     "jobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n"
     "      - name: |\n"
     "        # comment at indent 8\n"
     "        uses: actions/checkout@main\n",
     1),
    ("neg-body-compact-empty-chomp",
     "jobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n"
     "      - name: |-\n"
     "        # comment at indent 8\n"
     "        uses: actions/checkout@main\n",
     1),
    ("neg-body-compact-empty-commented",
     "jobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n"
     "      - name: | # trailing comment\n"
     "        # comment at indent 8\n"
     "        uses: actions/checkout@main\n",
     1),
    ("neg-body-compact-empty-publish", "E2E-COMPACT", 1),
    ("neg-body-compact-quoted-key",
     "jobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n"
     "      - \"name\": |\n"
     "          echo body\n"
     "        uses: actions/checkout@main\n",
     1),
    ("pos-body-compact-real-body",
     "jobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n"
     "      - name: |\n"
     "          Some body text\n"
     "          uses: evil/not-a-key@main\n"
     "      - uses: actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803 # v6\n",
     0),
    ("pos-body-chomp-strip",
     "jobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n"
     "      - name: tricky\n"
     "        run: |-\n"
     "          echo \"uses: evil@main\"\n"
     "      - uses: actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803 # v6\n",
     0),
    ("pos-body-chomp-keep",
     "jobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n"
     "      - name: tricky\n"
     "        run: >+\n"
     "          echo \"uses: evil@main\"\n"
     "      - uses: actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803 # v6\n",
     0),
    ("pos-body-header-comment",
     "jobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n"
     "      - name: tricky\n"
     "        run: | # comment\n"
     "          echo \"uses: evil@main\" # \"quotes\" and \\ backslash\n"
     "      - uses: actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803 # v6\n",
     0),
    ("pos-pinned",
     "jobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n"
     "      - uses: actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803 # v6\n",
     0),
    ("pos-local",
     "jobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n"
     "      - uses: ./local/action\n",
     0),
    ("pos-scalar-body-exempt",
     "jobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n"
     "      - name: tricky\n"
     "        run: |\n"
     "          echo \"uses: evil@main\" # \"quotes\" and \\ backslash\n"
     "          VAR=a\"b Q=foo? A=&x S=*y << HERE\n"
     "          uses: sneaky/not-a-key@main\n"
     "      - uses: actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803 # v6\n",
     0),
    ("neg-colon-desync-double",
     "jobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n"
     "      - {name: a:\"b, env: {K: \" # label\"}, "
     "uses: actions/checkout@main}\n",
     1),
    ("neg-colon-desync-single",
     "jobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n"
     "      - {name: a:'b, env: {K: ' # label'}, "
     "uses: actions/checkout@main}\n",
     1),
    ("neg-dash-adjacent-quote",
     "jobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n"
     "      - {a: -\"b, c: {K: \" # label\"}, "
     "uses: actions/checkout@main}\n",
     1),
    ("neg-colon-desync-double-e2e", "E2E-COLON-DOUBLE", 1),
    ("neg-colon-desync-single-e2e", "E2E-COLON-SINGLE", 1),
    ("pos-colon-heavy-lines",
     "jobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n"
     "      - name: fetch https://example.com:8080/x\n"
     "        env: {A: \"x\", B: \"y\"}\n"
     "        run: echo \"https://example.com:8080/x\"\n"
     "        shell: bash\n"
     "      - uses: actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803 # v6\n",
     0),
    ("neg-compound-colondash-double",
     "jobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n"
     "      - {name: a:- \"b, env: {K: \" # label\"}, "
     "uses: actions/checkout@main}\n",
     1),
    ("neg-compound-colondash-single",
     "jobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n"
     "      - {name: a:- 'b, env: {K: ' # label'}, "
     "uses: actions/checkout@main}\n",
     1),
    ("neg-compound-dashdash-double",
     "jobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n"
     "      - {name: a-- \"b, env: {K: \" # label\"}, "
     "uses: actions/checkout@main}\n",
     1),
    ("neg-compound-dashdash-single",
     "jobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n"
     "      - {name: a-- 'b, env: {K: ' # label'}, "
     "uses: actions/checkout@main}\n",
     1),
    ("neg-compound-dashchain3-double",
     "jobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n"
     "      - {name: a--- \"b, env: {K: \" # label\"}, "
     "uses: actions/checkout@main}\n",
     1),
    ("neg-compound-dashchain3-single",
     "jobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n"
     "      - {name: a--- 'b, env: {K: ' # label'}, "
     "uses: actions/checkout@main}\n",
     1),
    ("neg-compound-dashchain4-double",
     "jobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n"
     "      - {name: a---- \"b, env: {K: \" # label\"}, "
     "uses: actions/checkout@main}\n",
     1),
    ("neg-compound-dashchain4-single",
     "jobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n"
     "      - {name: a---- 'b, env: {K: ' # label'}, "
     "uses: actions/checkout@main}\n",
     1),
    ("neg-compound-colondash-double-e2e", "E2E-COMPOUND-COLONDASH-DOUBLE", 1),
    ("neg-compound-colondash-single-e2e", "E2E-COMPOUND-COLONDASH-SINGLE", 1),
    ("neg-compound-dashdash-double-e2e", "E2E-COMPOUND-DASHDASH-DOUBLE", 1),
    ("neg-compound-dashdash-single-e2e", "E2E-COMPOUND-DASHDASH-SINGLE", 1),
    ("real-ci-yml", None, 0),
]


def self_test() -> int:
    import io
    from contextlib import redirect_stdout

    bad = 0
    for name, text, expect in SELF_CASES:
        if text == "E2E":
            src = e2e_bypass_text()
        elif text == "E2E-COMPACT":
            src = e2e_compact_empty_text()
        elif text == "E2E-COLON-DOUBLE":
            src = e2e_colon_text(E2E_COLON_DOUBLE)
        elif text == "E2E-COLON-SINGLE":
            src = e2e_colon_text(E2E_COLON_SINGLE)
        elif text == "E2E-COMPOUND-COLONDASH-DOUBLE":
            src = e2e_colon_text(E2E_COMPOUND_COLONDASH_DOUBLE)
        elif text == "E2E-COMPOUND-COLONDASH-SINGLE":
            src = e2e_colon_text(E2E_COMPOUND_COLONDASH_SINGLE)
        elif text == "E2E-COMPOUND-DASHDASH-DOUBLE":
            src = e2e_colon_text(E2E_COMPOUND_DASHDASH_DOUBLE)
        elif text == "E2E-COMPOUND-DASHDASH-SINGLE":
            src = e2e_colon_text(E2E_COMPOUND_DASHDASH_SINGLE)
        else:
            src = DEFAULT.read_text() if text is None else text
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = check_text(src)
        out = buf.getvalue()
        # The real workflow must keep its exact pinned count, not
        # merely pass: any newly rejected legitimate form shows here.
        # 43 -> 41: the pkcs11 lanes moved into the ubuntu:26.04
        # container, where setup-uv (a host-side node action) cannot
        # provision; both lanes install pinned uv 0.12.23 by
        # URL + SHA256 instead.
        # 41 -> 43: preflight checkout and immutable signed-assets checkpoint.
        count_ok = ("all 52 third-party" in out) if name == "real-ci-yml" else True
        ok = (rc == expect) and count_ok
        print(f"{'ok' if ok else 'FAIL'}: selftest-{name}: "
              f"rc={rc} (want {expect})"
              + ("" if name != "real-ci-yml" else " + 43/43 count"))
        if not ok:
            bad += 1
            print(out)
    bad += self_test_structural()
    bad += self_test_fix7()
    bad += self_test_fix8()
    bad += self_test_fix9()
    bad += self_test_fix10()
    bad += self_test_fix11()
    bad += self_test_fix12()
    bad += self_test_fix13()
    bad += self_test_fix14()
    bad += self_test_fix15()
    print(f"actions-pinned self-test: {'OK' if not bad else 'FAIL'}")
    return 1 if bad else 0


def code_text(text: str) -> str:
    """Executable content: every line comment-stripped (quote-aware).
    Commented-out settings are prose, never matches. Line structure
    is preserved, so line-anchored scans still apply."""
    return "\n".join(strip_comment(l) for l in text.splitlines())


FROM_RE = re.compile(r"^\s*FROM\s+\S+(?:\s+AS\s+(\S+))?\s*$",
                       re.IGNORECASE)


def split_shell_commands(logical: str, last: bool = False):
    """Split a logical shell line at `&&` / `||` / `;` / `&` / `|`
    (the only operators the evaluator splits on; `<`/`>`/`(`/`)`
    stay data — redirects group with their argv, parens fall to the
    pip-mention backstop). Backslash- AND quote-aware, the single
    splitter for every evaluation path: shell-form RUN payloads and
    exec `-c` scripts at every nesting depth all arrive here via
    `_scan_shell_text`, post-splice and post-comment-cut, so no path
    can split differently. Outside quotes a backslash quotes the
    next character into data (pair consumption — equivalent to the
    odd-run rule: `\\;` is data, `\\\\;` splits); inside `'...'` everything
    is literal; inside `"..."` a backslash quotes the next character
    (any of them — `\\"` never closes, `\\\\` never opens: exactly
    dash's split behavior, since operator chars are data inside
    quotes either way). Each fragment is one argv vector; flags on
    any other command — including past a mid-line `&&` — never
    satisfy the caller. A lone backslash as the last character of
    the LAST logical line (`last=True`, passed by the owner of the
    loop) is dash's literal backslash (verified: `sh -c 'echo foo\\'`
    prints `foo\\`, rc 0 — not a syntax error), so it is doubled for
    shlex (which would otherwise raise); anywhere else a
    line-final backslash is impossible (a backslash-newline would
    have spliced) and trips defensively. Returns (parts, error):
    `error` is None on success, else `"heredoc"` (an unquoted
    unescaped `<<`/`<<-` operator — its body language is unprovable,
    so the caller refuses fail-closed; `<<<` is NOT one — dash
    rejects it with rc 2, so the Dockerfile RUN would fail anyway
    and the text keeps its normal evaluation; `$((...))` arithmetic
    is NOT excluded either — `$((1<<2))` trips although dash
    accepts it, because span-skipping risks missing a real
    operator), `"quote"` (unterminated `'`/`"`, matching dash's rc-2
    syntax error), or `"backslash"` (the impossible mid-text
    line-final backslash)."""
    parts, buf = [], []
    quote = None
    i, n = 0, len(logical)
    while i < n:
        ch = logical[i]
        if quote == "'":
            buf.append(ch)
            if ch == "'":
                quote = None
            i += 1
            continue
        if quote == '"':
            if ch == "\\" and i + 1 < n:
                buf.append(ch)
                buf.append(logical[i + 1])
                i += 2
                continue
            buf.append(ch)
            if ch == '"':
                quote = None
            i += 1
            continue
        if ch == "\\":
            if i + 1 < n:
                buf.append(ch)
                buf.append(logical[i + 1])
                i += 2
                continue
            if last:
                buf.append("\\\\")
                i += 1
                continue
            return (parts, "backslash")
        if ch in "'\"":
            quote = ch
            buf.append(ch)
            i += 1
            continue
        if ch == "<" and i + 1 < n and logical[i + 1] == "<":
            if i + 2 < n and logical[i + 2] == "<":
                buf.append("<<")  # `<<<`: dash syntax error, not a heredoc
                i += 2
                continue
            return (parts, "heredoc")
        if logical[i:i + 2] in ("&&", "||"):
            parts.append("".join(buf))
            buf = []
            i += 2
            continue
        if ch in ";|&":
            parts.append("".join(buf))
            buf = []
            i += 1
            continue
        buf.append(ch)
        i += 1
    if quote is not None:
        return (parts, "quote")
    parts.append("".join(buf))
    return (parts, None)


def _apply_format_value(value: str, target: set, other: set) -> None:
    """One `--only-binary`/`--no-binary` value, pip's
    `FormatControl.handle_mutual_excludes` verbatim (pip
    26.2.1, `_internal/models/format_control.py`): `:all:`
    clears BOTH sets, claims the target, and drops everything
    before it (names after it still apply only if a `:none:`
    follows); `:none:` clears the target; a package name leaves
    the other set and joins the target. Occurrences apply in
    argv order — a later value overrides an earlier one, so
    `--only-binary=:all: --only-binary=:none:` is NOT
    wheel-only (`:none:` clears the restriction)."""
    new = value.split(",")
    while ":all:" in new:
        other.clear()
        target.clear()
        target.add(":all:")
        del new[:new.index(":all:") + 1]
        if ":none:" not in new:
            return
    for name in new:
        if name == ":none:":
            target.clear()
            continue
        if name:
            other.discard(name)
            target.add(name)


# A token "mentions pip" when it names the pip family as its own
# word: `pip`, `pip3[..]`, `pipx`, a path to one
# (`/opt/p11c/bin/pip`, `./pip`), or pip inside code/punctuation
# (`import pip`, `['pip']`, `$(pip`, `X=pip`). Bounded both sides so
# longer glued words stay silent: `python3-pip` (the apt package in
# the real checker RUN), `pipeline`, `get_pip`, `.pip`. Case-sensitive
# (Linux executables are). Checked on POST-shlex tokens, so `p"i"p`
# / `p\ip` rejoin to `pip` before the test; `uv pip ...` trips (a
# standalone `pip` word) while bare `uv`/`conda` stay out of model
# (no pip word — same as any other network-fetching non-pip tool).
_PIP_MENTION_RE = re.compile(r"(?<![A-Za-z0-9_.-])pip\d*x?(?![A-Za-z0-9_])")

# A token carries a CPython module-selector cluster for pip when it
# holds `-<letters>mpip[alphanumerics]` (`-mpip`, `-umpip`,
# `-Bumpip`, `-mpip3`, `-umpipx`, ...): the attached `-m` value has
# NO pip-word boundary (`m`/`p` glued to word chars), so the mention
# regex above cannot see it. Case-sensitive (CPython options are:
# `-M` is an unknown option, rc 2 — nothing runs). Deliberately
# broad: it also matches shapes CPython would NOT run as pip
# (`-mpip3` — no such module, rc 1; `-Wmpip` — `-W` eats `mpip` as
# its warning value and parsing continues, oracle-verified) —
# outright trip is fail-closed, and the real checker stage carries
# zero such tokens (fix-11 zero-hit control), so the over-trip
# cannot bite it.
_PIP_CLUSTER_RE = re.compile(r"-[A-Za-z]*mpip[A-Za-z0-9]*")


def _mentions_pip(tokens) -> bool:
    """True when any argv token mentions pip (`_PIP_MENTION_RE`) or
    carries a module-selector cluster (`_PIP_CLUSTER_RE`): the
    fail-closed backstop for simple commands the evaluator neither
    evaluates (pip) nor inspects (supported wrappers) — ANY head,
    including skipped compound heads (`then`/`do`/`else`/`for`/
    `(`/`{`/`!`/unknown), where module resolution never runs. A
    cluster trips outright (refusal, even behind a flagged tail):
    routing a `then`-headed fragment to evaluation would require
    locating the python argv inside it, and the real stage is
    cluster-free."""
    return any(_PIP_MENTION_RE.search(t) or _PIP_CLUSTER_RE.search(t)
               for t in tokens)


_SHELL_ASSIGN_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
_ENV_ASSIGN_RE = re.compile(r"^[^=\s-][^=]*=")
_CMD_SUBST_RE = re.compile(r"\$\((?!\()")


def _strip_command_args(args):
    """`command [-p] [-v|-V] [--] cmd...` (POSIX; dash parses `-p`
    plus getopts clusters). Returns ("skip", []) when `-v`/`-V`
    appears (it describes the command, never executes — not even
    `command -v pip ...`) or when nothing executable remains;
    ("exec", rest) otherwise — rest[0] may be another prefix (the
    outer loop re-dispatches: `command exec pip ...` really runs
    pip). An unknown flag stops the parse (real `command` errors
    there — harmless; the pip-mention backstop covers the rest)."""
    a = list(args)
    while a:
        tok = a[0]
        if tok == "--":
            return ("exec", a[1:])
        if not tok.startswith("-") or tok == "-":
            return ("exec", a)
        for ch in tok[1:]:
            if ch in ("v", "V"):
                return ("skip", [])
            if ch != "p":
                return ("exec", a)
        a = a[1:]
    return ("exec", [])


def _strip_exec_args(args):
    """`exec [-c] [-l] [-a name] [--] cmd...` (bash's flags; dash's
    exec takes NONE — consuming them over-approximates dash, which
    fails there (`exec: -c: not found`), and matches bash exactly).
    Returns ("skip", []) when nothing executable remains or `-a`
    lacks its value (real shells error — harmless); ("exec", rest)
    otherwise (rest[0] may be another prefix). Unknown flags stop
    the parse (same fail-safe as `command`)."""
    a = list(args)
    while a:
        tok = a[0]
        if tok == "--":
            return ("exec", a[1:])
        if not tok.startswith("-") or tok == "-":
            return ("exec", a)
        advanced = None
        ok = True
        j = 1
        while j < len(tok):
            ch = tok[j]
            if ch in ("c", "l"):
                j += 1
                continue
            if ch == "a":
                if j + 1 < len(tok):
                    advanced = a[1:]  # attached value: rest of token
                elif len(a) > 1:
                    advanced = a[2:]  # separate value: next token
                else:
                    return ("skip", [])
                break
            ok = False
            break
        if not ok:
            return ("exec", a)
        a = a[1:] if advanced is None else advanced
    return ("exec", [])


_ENV_NOARG_OPTS = frozenset({
    "-i", "--ignore-environment", "-0", "--null", "-", "--debug",
    "--block-signal", "--default-signal", "--ignore-signal",
    "--list-signal-handling",
})
_ENV_SIGNAL_EQ = ("--block-signal=", "--default-signal=", "--ignore-signal=")


def _env_option(tok, rest):
    """Classify one env operand while options are still open: None
    when `tok` is not an option (the caller latches option parsing
    off and handles it as an operand); ("ok", k) to consume k tokens
    (k=1, or 2 for a separate `-u`/`-C`/`-S` value); ("trip",) when
    `-S`/`--split-string`'s value mentions pip (env splits it into
    words that BECOME utility+args — the value itself can be the pip
    invocation); ("skip",) when a value is missing (real env errors
    — harmless). Unknown `-x`/`--xxx` (including long abbreviations
    like `--u`) return None: real env errors there — harmless — and
    the backstop refuses any pip text past them."""
    if tok in _ENV_NOARG_OPTS or tok.startswith(_ENV_SIGNAL_EQ):
        return ("ok", 1)
    if tok in ("--unset", "--chdir", "--split-string"):
        if not rest:
            return ("skip",)
        if tok == "--split-string" and _mentions_pip([rest[0]]):
            return ("trip",)
        return ("ok", 2)
    for long in ("--unset=", "--chdir=", "--split-string="):
        if tok.startswith(long):
            if long == "--split-string=" and _mentions_pip([tok[len(long):]]):
                return ("trip",)
            return ("ok", 1)
    if len(tok) > 1 and tok.startswith("-") and tok != "--":
        j = 1
        while j < len(tok):
            ch = tok[j]
            if ch in ("i", "0"):
                j += 1
                continue
            if ch in ("u", "C", "S"):
                if j + 1 < len(tok):
                    val, k = tok[j + 1:], 1
                elif rest:
                    val, k = rest[0], 2
                else:
                    return ("skip",)
                if ch == "S" and _mentions_pip([val]):
                    return ("trip",)
                return ("ok", k)
            return None  # unknown short: not an option
        return ("ok", 1)
    return None


def _strip_env_args(args):
    """env's operand grammar (POSIX `[-i] [name=value]... [utility]`
    plus GNU's `-u NAME` / `-C DIR` / `-S STR` value options, `-0`,
    the long spellings, lone `-` (= `-i`), and `--`). Returns
    ("trip", []) for an `-S` value mentioning pip or an operand
    assignment carrying `$(...)`/backquote (the shell expands it
    before env runs); ("skip", []) when no utility remains or an
    option value is missing (real env errors/prints — harmless);
    ("exec", rest) with the utility at rest[0] (which may be another
    prefix: `env sudo pip ...` really runs sudo). Option parsing
    latches off at the first non-option operand (verified: no
    permutation — `env FOO=x -i ...` runs `-i` as the utility) and
    at `--`; env assignments use the broad `name=value` rule (env
    passes any `=`-bearing word through), not the shell's
    identifier rule."""
    a = list(args)
    opts_done = False
    while a:
        tok = a[0]
        if not opts_done:
            if tok == "--":
                a = a[1:]
                opts_done = True
                continue
            r = _env_option(tok, a[1:])
            if r is not None:
                if r[0] == "trip":
                    return ("trip", [])
                if r[0] == "skip":
                    return ("skip", [])
                a = a[r[1]:]
                continue
            opts_done = True
        if _ENV_ASSIGN_RE.match(tok):
            if _CMD_SUBST_RE.search(tok) or "`" in tok:
                return ("trip", [])
            a = a[1:]
            continue
        return ("exec", a)
    return ("skip", [])


def _strip_command_prefixes(tokens):
    """Strip supported command prefixes to the real executable,
    chained (`sudo env -i command pip ...` — each layer genuinely
    dispatches to the next, so sequential stripping matches every
    real nesting; a shell function shadowing `sudo`/`env` can only
    make this over-approximate, never hide pip: the TEXT is still
    scanned). Supported: shell assignments (`VAR=val`, identifier
    rule — `FOO-BAR=x` is a command name under dash, correctly NOT
    stripped), bare `sudo` (plus one `--`; by basename, so
    `/usr/bin/sudo` counts — sudo WITH flags is NOT modeled: the
    parse stops and the pip-mention backstop refuses when the argv
    could conceal pip), `command` (`-p`, `--`, `-v`/`-V`),
    `exec` (`-c`, `-l`, `-a name`, `--`), and env (full operand
    grammar). Returns ("trip", []) for fail-closed refusals (an
    assignment — shell or env-operand — whose value carries
    `$(...)` (not `$((...))` arithmetic) or backquotes: the shell
    runs it before the command; env `-S` whose value mentions pip);
    ("skip", []) when the argv provably executes nothing (`command
    -v`/`-V`, bare `command`/`exec`/`env`, missing option values,
    empty remainder); ("exec", rest) otherwise, rest non-empty."""
    t = list(tokens)
    while t:
        head = t[0]
        if _SHELL_ASSIGN_RE.match(head):
            if _CMD_SUBST_RE.search(head) or "`" in head:
                return ("trip", [])
            t = t[1:]
        elif head.rsplit("/", 1)[-1] == "sudo":
            t = t[1:]
            if t and t[0] == "--":
                t = t[1:]
        elif head == "command":
            action, t = _strip_command_args(t[1:])
            if action == "skip":
                return ("skip", [])
        elif head == "exec":
            action, t = _strip_exec_args(t[1:])
            if action == "skip":
                return ("skip", [])
        elif head.rsplit("/", 1)[-1] == "env":
            action, t = _strip_env_args(t[1:])
            if action == "trip":
                return ("trip", [])
            if action == "skip":
                return ("skip", [])
        else:
            return ("exec", t)
    return ("skip", [])


# pip's GENERAL (pre-subcommand) option grammar, grounded in the
# installed pip 26.2.1 source (`pip/_internal/cli/cmdoptions.py`:
# `general_group`; `main_parser.parse_command` splits globals from
# the subcommand with optparse's `disable_interspersed_args`, so the
# FIRST non-option token is the subcommand). Value-taking vs bare
# verified per option (`takes_value()`); exit order verified by
# oracle probes against pip's real parser: `--proxy install`
# consumes `install` as the VALUE (an unknown-command error follows —
# no install runs); `--no-cache-dir` takes no value (callback,
# `=v` rejected); `--help`/`-h` exit 0 AT parse position (later
# tokens never parsed); `--version`/`-V` exit after the full parse
# (later garbage errors — still nothing installed).
# Index/format options (`--index-url`, `--no-binary`,
# `--require-hashes`, ...) are per-COMMAND, not general: pip rejects
# them before the subcommand ("no such option"), so NONE of them can
# legally appear here — and no general option affects install
# format control (verified: `format_control` is built only from the
# install group's `--no/only-binary` callbacks plus env/config).
# Skipping globals is therefore sound for the wheel-only
# evaluation; the evaluated argv is exactly the tokens after the
# located subcommand. `--isolated` ignores env/config for that
# invocation, which only shrinks the documented PIP_* residual.
# Anything else pre-subcommand — unknown `--xxx`, bad short
# clusters, unambiguous-prefix abbreviations pip would accept (e.g.
# `--iso`), dangling values — is REFUSED fail-closed.
_PIP_GENERAL_NOVALUE = frozenset({
    "--help", "--debug", "--isolated", "--require-virtualenv",
    "--require-venv", "--verbose", "--version", "--quiet", "--no-input",
    "--no-proxy-env", "--no-cache-dir", "--disable-pip-version-check",
    "--no-color", "--no-python-version-warning",
})
_PIP_GENERAL_VALUE = frozenset({
    "--python", "--log", "--log-file", "--local-log",
    "--keyring-provider", "--proxy", "--retries", "--timeout",
    "--default-timeout", "--exists-action", "--trusted-host", "--cert",
    "--client-cert", "--cache-dir", "--use-feature", "--use-deprecated",
    "--resume-retries",
})
# The general group's short flags (`-v`/`--verbose`,
# `-V`/`--version`, `-q`/`--quiet` counters, `-h`/`--help`):
# clusterable, none takes a value.
_PIP_GENERAL_SHORTS = frozenset("qvVh")


def _split_pip_globals(args):
    """Split pip argv AFTER the pip head at the subcommand, mirroring
    pip's own main parser (see the grammar note above). Returns
    ("install", argv) with argv = tokens after the subcommand;
    ("skip", []) when pip runs no install here (another/no
    subcommand — including a lone `-` or a `--`-terminated scan —
    or `-h`/`--help`/`-V`/`--version` seen: pip exits before
    dispatch, so the install never runs and must neither trip nor
    count toward `found`); ("refuse", []) for unrecognized
    global-option shapes (fail closed, never skip). A value option
    consumes the next token verbatim — even `install` (pip does the
    same, then fails to find its subcommand)."""
    saw_version = False
    i, n = 0, len(args)
    while i < n:
        tok = args[i]
        if tok == "--":
            i += 1
            break
        if tok.startswith("--"):
            name, eq, _val = tok.partition("=")
            if name in _PIP_GENERAL_NOVALUE:
                if eq:
                    return ("refuse", [])
                if name == "--help":
                    return ("skip", [])  # optparse help exits at once
                if name == "--version":
                    saw_version = True
                i += 1
                continue
            if name in _PIP_GENERAL_VALUE:
                if eq:
                    i += 1
                else:
                    i += 1
                    if i >= n:
                        return ("refuse", [])  # dangling value
                    i += 1
                continue
            return ("refuse", [])
        if len(tok) > 1 and tok.startswith("-"):
            for ch in tok[1:]:
                if ch not in _PIP_GENERAL_SHORTS:
                    return ("refuse", [])
                if ch == "h":
                    return ("skip", [])
                if ch == "V":
                    saw_version = True
            i += 1
            continue
        break  # first non-option token: the subcommand position
    if saw_version or i >= n or args[i] != "install":
        return ("skip", [])
    return ("install", args[i + 1:])


# CPython's command-line option grammar, grounded in CPython 3.14.7
# (`python3 --help` usage line plus exhaustive behavioral probes:
# every `-<ch>V` for a-z A-Z 0-9 classified by exit code/output).
# Bare shorts (cluster freely, take no value — `-R` and `-t` are
# accepted though absent from `--help`; every other letter/digit
# errors "Unknown option", rc 2): b d h i q s t u v x B E I O P R
# S V ?. Remainder-consumers (`-c`, `-m`, `-W`, `-X`): the rest of
# THAT token is the value, else the next argv token (attached and
# spaced both verified; dangling errors "Argument expected", rc 2).
# `-c`/`-m` TERMINATE the option list (usage: `[option] ... [-c cmd
# | -m mod | file | -] [arg] ...`); `-W`/`-X` values are opaque to
# the gate (a bad `-W` value is ignored with rc 0 and parsing
# continues, so opaque-continue matches CPython exactly; a bad
# `-X`/dangling value errors, where any gate verdict is sound since
# nothing runs). Longs: `--check-hash-based-pycs` takes a SPACED
# value only (the `=` form errors "Unknown option"); `--help`,
# `--version`, `--help-env`, `--help-xoptions`, `--help-all` are
# bare. No prefix abbreviations (`--check` errors). `--` ends
# options; the first non-option token (or lone `-`) is the script.
# `-h`/`-V` and the help longs print and exit WITHOUT running
# `-m`/script — the gate deliberately does NOT skip on them
# (conservative: it evaluates or refuses instead, never missing an
# install; the real stage carries no such line).
_PY_BARE_SHORTS = frozenset("bdhiqstuvxBEIOPRSV?")
_PY_VALUE_SHORTS = frozenset("cmWX")
_PY_BARE_LONGS = frozenset({
    "--help", "--version", "--help-env", "--help-xoptions", "--help-all",
})
_PY_VALUE_LONGS = frozenset({"--check-hash-based-pycs"})


def _resolve_python_module(t):
    """Resolve a `python`/`python3`-headed argv (basename match, so
    `/usr/bin/python3` counts) to its pip invocation, if any, under
    CPython's real option grammar (see the note above): a single
    left-to-right option parse over t[1:]. Returns ("pip", argv) with
    a pip head for exactly `python[3] -m pip ...` (spaced, `-m`
    first — the historical round-9 shape, including spaced `-m
    pip3` which keeps evaluating exactly as before) and for a
    FIRST-token cluster resolving the module selector to `pip`
    (`-mpip`, `-umpip`, `-Bumpip`, `-qmpip`, `-um pip`, ... — `m`
    at any cluster position, attached value or spaced next token);
    ("refuse", []) for pip-concealing shapes outside that set —
    `-m pip` past python options, `-m` clusters past the first
    token (`-u -umpip ...` — no pip word boundary, so the mention
    regex alone cannot see it; the cluster backstop trips it behind
    skipped heads, resolution still refuses it here), any other
    module value naming pip
    (`-mpip3`, `-umpip3`, `-m=pip`, `-mpipx`, `-um pip3`, spaced
    `-m pip3` past index 1 — only the exact historical `-m pip3`
    at index 1 still evaluates), unknown shorts/longs, `=` on
    longs, and dangling values; ("other", argv) otherwise — `-c`
    (its value is a COMMAND, the rest its args: never the pip CLI;
    the shell backstop still trips on any pip mention in the full
    argv), non-pip modules (historical `-m`-first payload kept:
    `python3 -m venv ...` skips exactly as before), scripts, and
    `--`-terminated scans."""
    if len(t) >= 3 and t[1] == "-m" and t[2] in ("pip", "pip3"):
        return ("pip", t[2:])
    i, n = 1, len(t)
    while i < n:
        tok = t[i]
        if tok == "--":
            break  # end of options: script + args follow
        if tok.startswith("--"):
            name, eq, _val = tok.partition("=")
            if name in _PY_BARE_LONGS:
                if eq:
                    return ("refuse", [])
                i += 1
                continue
            if name in _PY_VALUE_LONGS:
                if eq:
                    return ("refuse", [])  # CPython rejects `=` here
                i += 1
                if i >= n:
                    return ("refuse", [])  # dangling value
                i += 1  # value opaque (past here any -m is past
                # index 1, hence refused — its validity is moot)
                continue
            return ("refuse", [])  # unknown long (no abbreviations)
        if len(tok) > 1 and tok.startswith("-"):
            j = 1
            consumed_next = False
            while j < len(tok):
                ch = tok[j]
                if ch in _PY_BARE_SHORTS:
                    j += 1
                    continue
                if ch in _PY_VALUE_SHORTS:
                    if tok[j + 1:] != "":
                        val, after = tok[j + 1:], i + 1
                    else:
                        if i + 1 >= n:
                            return ("refuse", [])  # dangling value
                        val, after = t[i + 1], i + 2
                        consumed_next = True
                    if ch == "c":
                        return ("other", t)  # -c: command, not pip CLI
                    if ch == "m":
                        if val == "pip":
                            if i == 1:
                                return ("pip", ["pip"] + t[after:])
                            return ("refuse", [])
                        if "pip" in val:
                            return ("refuse", [])
                        if i == 1 and tok == "-m":
                            return ("other", t[2:])  # historical payload
                        return ("other", t)  # other module ends options
                    break  # -W/-X value opaque; next argv token
                return ("refuse", [])  # unknown short
            i += 2 if consumed_next else 1
            continue
        break  # first non-option / lone `-`: the script
    return ("other", t)


# pip install's option-value grammar, grounded in the installed pip
# 26.2.1 source (`InstallCommand.parser`: Install + Package Selection
# + Package Index + General groups; per-option `takes_value()` dumped,
# not remembered) plus optparse oracle probes. The install parser
# accepts the General options too (`--no-input`, `-q`, `--isolated`,
# ... — the real stage's `--no-input` is one), so EVERY spelling
# below is legal at install position. Walk rule (optparse verbatim):
# a value-taking option consumes the next token (or `=...` attached
# — even empty, even `--`, even another flag spelling) as DATA,
# never a flag; a bare option consumes nothing; `--` ends options
# (the rest are requirements — pip would try to install a package
# literally named e.g. `--only-binary=:all:`); short clusters walk
# char by char (bare continues, a value short takes the token rest
# or the next token). Anything else — unknown longs,
# unambiguous-prefix abbreviations pip WOULD accept (`--targ`,
# `--iso`), ambiguous ones (`--ver`), unknown shorts, `=value` on
# bare flags, dangling values — is REFUSED fail-closed (pip itself
# exits 2 there, except unambiguous abbrevs which are refused
# deliberately, same policy as round 9). Grammar pinned to pip
# 26.2.1: a newer pip's new options fail closed here as
# unrecognized. `-h`/`--help` (the optparse help action) exits 0 AT
# parse position — later tokens never parsed, nothing installs — so
# it SKIPS (neither trips nor counts); `-V`/`--version` is an
# ordinary bare flag at install position (probed: the install
# proceeds to its requirements error — unlike the main parser).
_PIP_INSTALL_VALUE_LONGS = frozenset({
    "--abi", "--all-releases", "--build-constraint", "--cache-dir",
    "--cert", "--client-cert", "--config-settings", "--constraint",
    "--default-timeout", "--editable", "--exists-action",
    "--extra-index-url", "--find-links", "--group", "--implementation",
    "--index-url", "--keyring-provider", "--local-log", "--log",
    "--log-file", "--no-binary", "--only-binary", "--only-final",
    "--platform", "--prefix", "--progress-bar", "--proxy", "--pypi-url",
    "--python", "--python-version", "--refresh-package", "--report",
    "--requirement", "--requirements-from-script", "--resume-retries",
    "--retries", "--root", "--root-user-action", "--source",
    "--source-dir", "--source-directory", "--src", "--target",
    "--timeout", "--trusted-host", "--upgrade-strategy",
    "--uploaded-prior-to", "--use-deprecated", "--use-feature",
})
_PIP_INSTALL_BARE_LONGS = frozenset({
    "--break-system-packages", "--check-build-dependencies", "--compile",
    "--debug", "--disable-pip-version-check", "--dry-run",
    "--force-reinstall", "--help", "--ignore-installed",
    "--ignore-requires-python", "--isolated", "--no-build-isolation",
    "--no-cache-dir", "--no-clean", "--no-color", "--no-compile",
    "--no-dependencies", "--no-deps", "--no-index", "--no-input",
    "--no-proxy-env", "--no-python-version-warning",
    "--no-require-hashes", "--no-user", "--no-warn-conflicts",
    "--no-warn-script-location", "--only-dependencies", "--only-deps",
    "--pre", "--prefer-binary", "--quiet", "--require-hashes",
    "--require-venv", "--require-virtualenv", "--upgrade",
    "--use-pep517", "--user", "--verbose", "--version",
})
# Value shorts (`-C -c -e -f -i -r -t`; none is format control — the
# `--only/--no-binary` pair is long-only, so short values are data)
# and bare shorts (`-I -U -V -h -q -v`, clusterable).
_PIP_INSTALL_VALUE_SHORTS = frozenset("Ccefirt")
_PIP_INSTALL_BARE_SHORTS = frozenset("IUVhqv")


def _split_install_args(args):
    """Walk install-position argv with value ownership (see the
    grammar note above). Returns ("ok", (events, req_hashes,
    no_req_hashes)) with the `--only/--no-binary` (value, which)
    events in argv order and the effective hash flags; ("skip",
    None) when `-h`/`--help` appears (pip exits 0 there — nothing
    installs, so it neither trips nor counts toward `found`);
    ("refuse", None) for unrecognized shapes (fail closed, never
    skip). A value option consumes the next token verbatim — even
    a flag spelling (pip does the same); consumed tokens are DATA."""
    events = []
    req_hashes = False
    no_req_hashes = False
    i, n = 0, len(args)
    while i < n:
        tok = args[i]
        if tok == "--":
            break  # end of options: the rest are requirements
        if tok.startswith("--"):
            name, eq, val = tok.partition("=")
            if name in _PIP_INSTALL_BARE_LONGS:
                if eq:
                    return ("refuse", None)
                if name == "--help":
                    return ("skip", None)
                if name == "--require-hashes":
                    req_hashes = True
                elif name == "--no-require-hashes":
                    no_req_hashes = True
                i += 1
                continue
            if name in _PIP_INSTALL_VALUE_LONGS:
                if eq:
                    v = val  # attached value, even empty
                else:
                    i += 1
                    if i >= n:
                        return ("refuse", None)  # dangling value
                    v = args[i]  # DATA, even when flag-shaped
                if name == "--only-binary":
                    events.append(("only", v))
                elif name == "--no-binary":
                    events.append(("no", v))
                i += 1
                continue
            return ("refuse", None)  # unknown long / abbreviation
        if len(tok) > 1 and tok.startswith("-"):
            j = 1
            while j < len(tok):
                ch = tok[j]
                if ch in _PIP_INSTALL_BARE_SHORTS:
                    if ch == "h":
                        return ("skip", None)
                    j += 1
                    continue
                if ch in _PIP_INSTALL_VALUE_SHORTS:
                    if tok[j + 1:] == "":
                        i += 1  # next token is the value (DATA)
                        if i >= n:
                            return ("refuse", None)  # dangling value
                    break  # value (attached rest or next) consumed
                return ("refuse", None)  # unknown short
            i += 1
            continue
        i += 1  # positional requirement (incl. lone `-`): data
    return ("ok", (events, req_hashes, no_req_hashes))


def _pip_install_eval(tokens) -> bool | None:
    """None when the STRIPPED argv (prefixes already removed by
    `_strip_command_prefixes`, `python -m` already resolved by the
    caller) is not a pip install invocation (pip must be the head —
    basename `pip`/`pip3` — so `echo pip install ...` cannot satisfy
    this; pip's GLOBAL options before the subcommand are skipped per
    `_split_pip_globals`, unrecognized shapes refused); else whether
    the EFFECTIVE options are wheel-only: --require-hashes present
    AND effective only_binary contains `:all:` (per pip's
    `get_allowed_formats`, `:all:` there denies every requirement
    the source format) AND effective no_binary is empty (any entry —
    `:all:` or a package — re-allows source for something).
    Install-position options are walked with VALUE OWNERSHIP first
    (`_split_install_args`: pip 26.2.1's install-parser grammar):
    a value-taking option's consumed token is DATA even when
    flag-shaped (`--target --only-binary=:all:` eats the flag —
    pip's own parser leaves only_binary empty there), `--` ends
    options, short clusters, abbreviations/unrecognized/dangling
    refused, `-h`/`--help` skipping; only the surviving effective
    options feed this evaluation, in argv order, both `--opt=value`
    and `--opt value` spellings. `--require-hashes` counts only
    AFTER the subcommand (a global `--require-hashes` is not a pip
    option at all — pip rejects it — so the globals scan refuses it
    before evaluation); `--require-hashes` together with effective
    `--no-require-hashes` refuses (pip errors: mutually exclusive),
    as does an `--only/--no-binary` value starting with `-` (pip's
    `handle_mutual_excludes` guard verbatim).
    A pip install argv containing an unexpanded shell expansion —
    any token holding `$` (`$@`, `$*`, `$1..$n`, `${...}`,
    `$(...)`) or a backquote — is REFUSED (False): a static scan
    cannot prove flags it cannot see (the expansion may supply a
    clearer or withhold the restriction).
    (pip also reads format control from env/config
    `PIP_ONLY_BINARY`/`PIP_NO_BINARY`, which a static argv scan
    cannot see — a Dockerfile `ENV PIP_NO_BINARY=...` override
    is a known residual; the gate pins argv only. Per-invocation
    `--isolated` ignores env/config and only shrinks that residual.)"""
    t = list(tokens)
    if not t or t[0].rsplit("/", 1)[-1] not in ("pip", "pip3"):
        return None
    kind, rest = _split_pip_globals(t[1:])
    if kind == "refuse":
        return False
    if kind != "install":
        return None
    if any("$" in tok or "`" in tok for tok in t):
        return False  # unexpanded expansion: statically unknowable
    status, eff = _split_install_args(rest)
    if status == "refuse":
        return False
    if status != "ok":
        return None  # -h/--help: pip exits 0, nothing installs
    events, req_hashes, no_req_hashes = eff
    if req_hashes and no_req_hashes:
        return False  # pip CommandError: mutually exclusive
    only, no = set(), set()
    for which, v in events:
        if v.startswith("-"):
            return False  # pip CommandError: a binary-control value
            # starting with `-` (handle_mutual_excludes verbatim)
        if which == "only":
            _apply_format_value(v, only, no)
        else:
            _apply_format_value(v, no, only)
    return req_hashes and ":all:" in only and not no


RUN_LEAD_RE = re.compile(r"^\s*RUN(?=\s|$)", re.IGNORECASE)
HEREDOC_RE = re.compile(r"<<-?\s*[\"']?[A-Za-z0-9_]")

# Supported exec-form shell wrappers: `[sh|bash|dash, -c, script,
# ...]` ONLY (basename match, optional path prefix, exactly `-c`
# — no combined flags like `-ec`, no `sudo`/`env` unwrapping, no
# other interpreters). Minimal and explicit: `python -c`,
# `powershell -c`, `busybox sh -c`, `sh` without `-c`, empty argv,
# and every other non-pip executable are REFUSED fail-closed, not
# skipped — a static scan cannot enumerate what an unknown
# executable does with a script argument. The real checker stage
# uses no exec-form RUN at all, so the refusal set cannot bite it.
WRAP_SHELLS = frozenset({"sh", "bash", "dash"})
# Wrapper nesting cap: each level consumes a strictly smaller
# script, but a pathological 1000-deep nest would hit Python's
# recursion limit — past this depth the scan trips fail-closed
# instead of crashing.
_WRAP_MAX_DEPTH = 10


# Go `unicode.IsSpace` (the Unicode White_Space property —
# `'\t', '\n', '\v', '\f', '\r', ' ', U+0085, U+00A0` below
# Latin-1 plus the White_Space table above it; go1.24.0 and
# go1.25.0 byte-identical, so STABLE across toolchains): the exact
# set BuildKit's Dockerfile parser skips as leading whitespace
# (`trimLeadingWhitespace` in `isComment` /
# `isEmptyContinuationLine`, v0.33.0), MINUS `\n` — Go ScanLines
# splits lines before either test, exactly as the gate splits on
# `\n` first, so `\n` never appears inside a line here. Grounded
# member-by-member in REAL `docker build` probes R1–R5/R20 (every
# class skips a `#` comment mid-continuation) and R9–R11/R21
# (ws-only lines are blank), with R6/R13 proving the boundary
# (U+001C–U+001F are NOT members — content, the builder makes a
# stage boundary). `\r` stays IN the set (BuildKit skips it too);
# a lone `\r` anywhere still refuses the whole file first (P31) —
# the refusal below runs before any mapping, so the `\r`
# membership is unobservable and exactly conservative.
_GO_WS_LEAD = ("\t\x0b\x0c\r "  # U+0009, U+000B-U+000D, U+0020
                "\x85\xa0"  # U+0085 NEL, U+00A0 NBSP
                "\u1680"  # U+1680 OGHAM SPACE MARK
                "\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007"
                "\u2008\u2009\u200a"  # U+2000-U+200A
                "\u2028\u2029"  # LINE / PARAGRAPH SEPARATOR
                "\u202f\u205f"  # NARROW NBSP, MEDIUM MATH SPACE
                "\u3000")  # IDEOGRAPHIC SPACE
_GO_WS_SET = frozenset(_GO_WS_LEAD)


def _docker_is_blank_ws(line: str) -> bool:
    """True when `line` is empty or holds only Go-IsSpace
    whitespace — BuildKit's `isEmptyContinuationLine` exactly
    (post-`\\n`-split, so `\\n` is absent by construction; a lone
    `\\r` line is the CRLF empty line and IS blank, P09). Python's
    `strip()` is a SUPERSET (it adds U+001C-U+001F, which the
    builder reads as content, R13) — never use it here."""
    return all(ch in _GO_WS_SET for ch in line)


def _join_logicals(lines):
    """Dockerfile IMAGE-BUILDER continuation rule (physical layer
    only), grounded in REAL `docker build` probes on BOTH builders
    (BuildKit + classic, Docker 29.8.1 — 15 shared shapes, zero
    disagreement; each rule below names its probe): a line whose
    rstripped form ends in EXACTLY ONE backslash (a lone-`\\` line
    counts — P17/P20; runs of 2+ NEVER splice, P07/P08/P19, the
    next line is a new instruction) splices with the next line by
    PURE concatenation — backslash-newline dropped, nothing added
    (P01; round 8's added space was WRONG), the next line appended
    verbatim (leading spaces/tabs preserved, P02/P11; trailing
    spaces/tabs/CR after the backslash stripped first, P03/P13/P09,
    but spaces BEFORE it kept, P04). Blank and whitespace-only
    lines in Go's White_Space set (P15/P29/R9–R11/R21 —
    U+001C-U+001F-only lines are CONTENT, R13) and full-line
    comments, bare or indented (P06/P25/Q3/R1–R5/R20 — full-line
    comments arrive here pre-mapped to blank by the caller; INLINE
    comments ride through verbatim, Q1/Q4/Q5), are SKIPPED with the
    continuation continuing through them; a splice consumes ANY
    next line, even another instruction (`ENV`, P05; `FROM`, P18 —
    stage attribution therefore runs on LOGICAL lines). A dangling
    backslash at EOF just drops (P14); CRLF behaves like LF (P09).
    The shell receives the joined logical line; shell text itself
    (shell-form RUN payloads, exec `-c` scripts at every nesting
    depth) is evaluated by `_shell_logical_lines` under the TRUE
    shell rule instead — one join-then-split pipeline per evaluated
    text, no drift within a layer."""
    logicals = []
    buf = ""
    for raw in lines:
        if _docker_is_blank_ws(raw):
            continue  # blank / pre-stripped comment: skipped (P15/P29/P06/P25)
        s = raw.rstrip()
        if s.endswith("\\") and not s.endswith("\\\\"):
            buf += s[:-1]
        else:
            buf += s
            logicals.append(buf)
            buf = ""
    if not _docker_is_blank_ws(buf):
        logicals.append(buf)
    return logicals


_DOCKER_DIRECTIVE_RE = re.compile(r"^\s*#\s*(escape|syntax)\s*=",
                                  re.IGNORECASE)
# BuildKit's alternate `//` directive comment form: the detector's
# second attempt (`parseDirective(anyFormat=true)`, directives.go
# L155-160) re-runs the SAME line grammar with comment marker `//`
# — no leading whitespace, same `name = value` regex, same
# case-insensitive `syntax|escape|check` names — for the `syntax`
# key only (`DetectSyntax`, the frontend-forwarding path,
# build.go L62). The gate refuses `// syntax=` and `// escape=`
# with the same anywhere-superset policy as `#` (round 12):
# `// escape=` is inert-as-directive in v0.33.0 (the main parser
# only knows `#`, parser.go L175-185; the forwarded line dies as
# an unknown instruction instead, probe P6a) but a plausible
# future builder could honor it symmetrically, and refusing agrees
# with v0.33.0's outcome (both fail) anyway. `/// name=` never
# matches (the `/` after `//` is not `\s*`-skippable — the builder
# rejects it the same way, CutPrefix leaves `/ syntax=` which
# fails the name regex). `// check=` is NOT refused: `check` is
# consumed only via `ParseDirective("check")` (anyFormat=false,
# `#`-only, convert.go L197) and is warnings-only by construction
# (linter.go `ParseLintOptions`: skip/experimental/error — it can
# only add warnings or fail the build on them, never change what
# executes); a standalone `//` line is unbuildable regardless
# (UnknownInstructionError, instructions/parse.go L161-168,
# probes P5b/P12), so passing it is the safe direction.
_DOCKER_SLASH_DIRECTIVE_RE = re.compile(r"^\s*//\s*(escape|syntax)\s*=",
                                        re.IGNORECASE)


def _docker_strip_bom(docker: str) -> str:
    """Strip EXACTLY ONE leading U+FEFF — BuildKit's `discardBOM`
    (`bytes.TrimPrefix`, directives.go L198-200), called by BOTH
    the detector (`parseDirective`, L135) and the main parser
    (first line only, parser.go L296-299). `TrimPrefix` removes at
    most one occurrence: file-leading BOM #2+ stays and kills the
    directive (the line no longer starts with `#`/`//`), and the
    surviving BOM later fails dispatch (`unknown instruction`,
    probe 2). Mid-file BOMs are never stripped (data, probe P10).
    Callers strip their own local copy exactly once; the multi-BOM
    refusal in `_docker_physical_refused` sees the survivor."""
    if docker.startswith("\ufeff"):
        return docker[1:]
    return docker


def _docker_physical_refused(docker: str):
    """Fail-closed refusals for Dockerfile physical shapes the
    probes cannot ground exactly (returns a reason, else None).
    The scan runs on BOM-normalized text (exactly one leading
    U+FEFF stripped first — the UTF-8 BOM decodes cleanly under
    the strict read, so normalization is post-decode, mirroring
    `discardBOM` in the detector AND the main parser).
    Parser directives (`# escape=` / `# syntax=` plus the
    BuildKit-recognized alternate `// escape=` / `// syntax=`
    forms, any spacing or case, anywhere in the file): BuildKit
    honors the escape switch before the first instruction
    (P10a/P21/P23/P24, BOM-prefixed too — probe 7) and it
    redefines the continuation character outright (P10b) — a
    `syntax` switch replaces the whole frontend (BOM-prefixed,
    `//`, shebang-skipped, and whole-file-JSON forms all forward,
    probes 1/3/4/9 and P14); refused everywhere, a deliberate
    superset of the honored positions (a late directive is a plain
    comment to the builder, P22 — the gate refuses it anyway).
    Multiple leading BOMs: v0.33.0 strips exactly one and then
    fails dispatch on the survivor (`unknown instruction`, probe
    2) — the gate refuses fail-closed, which agrees with that
    outcome on the cited version AND stays safe if a future
    builder strips more (the union rule is load-bearing: CI pins
    no buildkit version). `# check=` / `// check=` need no
    refusal (warnings-only by construction — convert.go L197,
    linter.go `ParseLintOptions`; probes P11/P12). A
    lone CR (`\\r` not followed by `\\n` — the builder treats it as
    data, P31, while the gate's shell layer would read it as a line
    break): refused; CRLF pairs are implemented exactly (P09).
    Exotic trailing whitespace (anything Python's rstrip removes
    beyond space/tab — re-audited in round 14 against the SAME Go
    set: the builder strips ONLY space/tab (`[ \\t]*` in its
    continuation regex, after `\\r\\n` trim), so trailing VT/FF/NEL/
    NBSP/U+2000+ DEFEAT the splice (probes R14/R15/R18/R19) — the
    gate refusing there trips where the builder makes a boundary,
    conservative-fail-closed; the wide Python rstrip comparison is
    LOAD-BEARING for trailing U+001C-U+001F, which are builder
    content the join's own rstrip would otherwise eat): refused.
    NUL needs no refusal (both builders fail the build, P32/R17 —
    nothing executes; the gate passes NUL through as data)."""
    body = _docker_strip_bom(docker)
    if body.startswith("\ufeff"):
        return "multiple leading BOMs (builder-version union)"
    for raw in body.split("\n"):
        if (_DOCKER_DIRECTIVE_RE.match(raw)
                or _DOCKER_SLASH_DIRECTIVE_RE.match(raw)):
            return "parser directive (escape/syntax switch ungrounded)"
    if re.search(r"\r(?!\n)", body):
        return "lone CR (builder-data vs gate-line-break)"
    for raw in body.split("\n"):
        core = raw[:-1] if raw.endswith("\r") else raw
        if core.rstrip(" \t") != core.rstrip():
            return "exotic trailing whitespace (strip-set gap)"
    return None


def _docker_pre_join_line(line: str) -> str:
    """Dockerfile physical-layer pre-join mapping: the BuildKit
    comment rule (grounded in REAL `docker build` probes Q1–Q10 +
    R1–R21, BuildKit v0.33.0). A FULL-LINE comment — first
    non-whitespace character is `#`, where whitespace is Go
    `unicode.IsSpace` minus `\\n` (`_GO_WS_LEAD`: space/tab/VT/FF/
    CR/NEL/NBSP/U+1680/U+2000-U+200A/U+2028/U+2029/U+202F/U+205F/
    U+3000 — quote-BLIND: the Dockerfile layer does no shell
    quoting) — maps to blank, which the join skips exactly like
    the builder skipping comment lines mid-continuation (Q3, blank
    + bare + indented chain; R1–R5/R20, exotic prefixes). EVERY
    other line passes through VERBATIM, inline `#...` text
    included: the Dockerfile layer treats inline `#` as plain
    argument text (Q2/Q9: no staging effect without a trailing
    backslash) and the splice decision is purely
    trailing-backslash, `#`-blind and quote-blind (Q1/Q4/Q5). The
    pre-round-13 mapping ran the YAML `strip_comment` here, which
    cut `RUN echo ok # \\` to `RUN echo ok ` and deleted the splice
    — the gate then saw a stage boundary where BuildKit splices,
    consumes the FROM line into the RUN logical (the build log
    shows one `RUN echo ok # FROM ...` step), and executes the rest
    in the ORIGINAL stage; the round-13 mapping's narrower
    space/tab-only prefix set had the same hole for VT/FF/NBSP
    prefixes (R1–R3). The preserved inline text is cut later, in
    the shell layer (`_shell_logical_lines`, word-start `#` rule)
    — join+attribution first, comment-strip after. A
    trailing-comment FROM (`FROM x # c`) is therefore no longer a
    boundary: the builder rejects its arity outright (Q10 — nothing
    executes, so the gate's verdict there is fail-closed on
    unbuildable)."""
    if line.lstrip(_GO_WS_LEAD).startswith("#"):
        return ""
    return line


def _docker_stage_logicals(docker: str):
    """Checker-pipeline Dockerfile parse: (logicals, refusal).
    Refusals first (fail closed — the refusal scan normalizes one
    leading BOM internally), then exactly one leading U+FEFF is
    stripped before ALL parsing (comment/blank tests, join, stage
    attribution — mirroring `discardBOM`, without which a
    BOM-prefixed first-line RUN would be builder-executed but
    gate-invisible), then the exact builder join over `\\n`-split
    lines (Go ScanLines splits on `\\n` only — `\\x0b`
    and friends are data, P30), then stage attribution on LOGICAL
    lines (a splice consumes even a FROM line, P18/Q1 — physical
    attribution would mis-stage). The pre-join mapping strips ONLY
    full-line comments (`_docker_pre_join_line`); inline comments
    ride through the join verbatim — their trailing backslash
    splices exactly as the builder's (Q1/Q4/Q5) — and are cut later
    in the shell layer."""
    why = _docker_physical_refused(docker)
    if why is not None:
        return ([], why)
    docker = _docker_strip_bom(docker)
    logicals = []  # (stage, text)
    stage = None
    for logical in _join_logicals(
            [_docker_pre_join_line(l) for l in docker.split("\n")]):
        m = FROM_RE.match(logical)
        if m:
            stage = (m.group(1) or "").lower() or None
            continue
        logicals.append((stage, logical))
    return (logicals, None)


# Chars after which `#` starts a shell word, hence a comment
# (dash-verified: `;#`, `(#`, `)#`, `|#`, `&#`, `<#`, `>#` all
# comment; `a#b`, `"a#b"`, `'a#b'`, `\#`, `FOO=#v` are data).
_SHELL_COMMENT_GAP = frozenset(" \t;()|&<>")


def _shell_logical_lines(text: str):
    """One left-to-right shell-READING pass over shell text: removes
    backslash-newline splices and `#` comments in TRUE shell order,
    yielding logical lines (newlines inside quotes preserved for
    shlex; every other newline is a command separator). A splice
    drops exactly backslash-newline (nothing added, no rstrip — trailing
    spaces defeat it, even backslash runs keep a literal) and
    applies everywhere EXCEPT inside single quotes (literal there)
    and inside comments (a comment-ending backslash does NOT
    continue the comment — dash-verified). A `#` starts a comment
    only at a word start (string start or after unquoted
    whitespace/operator); `#` glued mid-word, inside quotes, or
    backslash-escaped is data. Quote tracking mirrors the later
    split/shlex stages (`'...'` literal, `\\` escapes inside "..."
    and outside quotes). CRLF/CR normalize to LF (as splitlines
    did for the old join)."""
    chars = text.replace("\r\n", "\n").replace("\r", "\n")
    lines, buf = [], []
    quote = None
    in_comment = False
    at_word_start = True
    i, n = 0, len(chars)
    while i < n:
        ch = chars[i]
        nxt = chars[i + 1] if i + 1 < n else ""
        if in_comment:
            if ch == "\n":
                in_comment = False
                lines.append("".join(buf))
                buf = []
                at_word_start = True
            i += 1  # comment text (incl. any backslash) discarded
            continue
        if quote == "'":
            buf.append(ch)
            if ch == "'":
                quote = None
            at_word_start = False
            i += 1
            continue
        if quote == '"':
            if ch == "\\" and nxt == "\n":
                i += 2  # splice applies inside double quotes too
                continue
            if ch == "\\" and i + 1 < n:
                buf.append(ch)
                buf.append(nxt)
                i += 2
            else:
                if ch == '"':
                    quote = None
                buf.append(ch)
                i += 1
            at_word_start = False
            continue
        if ch == "\\" and nxt == "\n":
            i += 2  # line continuation: removed, nothing added
            continue
        if ch == "\\" and i + 1 < n:
            buf.append(ch)
            buf.append(nxt)  # escaped char: data (e.g. \# stays)
            at_word_start = False
            i += 2
            continue
        if ch in "'\"":
            quote = ch
            buf.append(ch)
            at_word_start = False
            i += 1
            continue
        if ch == "\n":
            lines.append("".join(buf))
            buf = []
            at_word_start = True
            i += 1
            continue
        if ch == "#" and at_word_start:
            in_comment = True
            i += 1
            continue
        buf.append(ch)
        at_word_start = ch in _SHELL_COMMENT_GAP
        i += 1
    lines.append("".join(buf))
    return lines


def _shell_wrapper_script(argv):
    """The script string when `argv` is a SUPPORTED exec-form shell
    wrapper (`[sh|bash|dash, -c, script, ...]` — extra args after
    the script become `$0`, `$1`, ... and are ignored), else None
    (the caller refuses: never skipped)."""
    if (len(argv) >= 3 and argv[0].rsplit("/", 1)[-1] in WRAP_SHELLS
            and argv[1] == "-c"):
        return argv[2]
    return None


def _scan_shell_text(text: str, depth: int):
    """Evaluate shell text exactly as a shell-form RUN payload:
    the single shell-reading pass (`_shell_logical_lines`:
    backslash-newline splices removed and `#` comments cut in
    true shell order), then per logical line the single
    backslash/quote-aware split (`split_shell_commands`), `shlex`,
    then per argv vector — FIRST an expansion pre-scan (any `$(...)`
    outside `$((...))` or backquote trips outright: the shell runs
    it before any skip/consume decision), then prefixes stripped to
    the real executable (`_strip_command_prefixes`:
    assignments/`sudo`/`command`/`exec`/`env`), `python -m`
    resolved under CPython's real option grammar (first-token
    short-option clusters like `-umpip` included; unrecognized
    pip-concealing shapes refused), a pip head evaluated (globals
    skipped to the subcommand per pip's own grammar; an install
    joins the effective-flags evaluation with install-option value
    ownership; any other pip subcommand is visible-without-install
    and skipped, never backstopped), a
    SUPPORTED `sh|bash|dash -c` wrapper recursed into (after
    prefixes, so `env -i sh -c ...` is inspected; nested wrappers
    inspected to `_WRAP_MAX_DEPTH`, past it the scan trips),
    anything else refused when it mentions pip or carries a
    `-mpip`-style module-selector cluster (`_mentions_pip` on the
    full argv — unsupported wrappers like `nice`/`timeout`/
    `xargs`, `python -c` scripts, `then`-branches, and paren groups
    cannot conceal an install, boundary-free clusters included)
    and skipped otherwise. Returns
    (tripped, found): `found` when a flagged pip install was
    evaluated anywhere inside (it counts toward the stage's
    at-least-one-pip requirement). Tokenization failures trip
    fail-closed, never skip: heredoc operators (`<<`/`<<-` — the
    body language is not provably shell, e.g. `python3 <<EOF` runs
    pip inside Python), unterminated quotes, and `shlex` errors
    (defensive — the splitter already excludes them except dash's
    literal trailing backslash, which it normalizes)."""
    if depth > _WRAP_MAX_DEPTH:
        return (True, False)
    found = False
    logicals = _shell_logical_lines(text)
    for li, logical in enumerate(logicals):
        parts, err = split_shell_commands(logical, li == len(logicals) - 1)
        if err is not None:
            return (True, found)
        for frag in parts:
            try:
                tokens = shlex.split(frag, posix=True)
            except ValueError:
                return (True, found)
            if not tokens:
                continue
            if any(_CMD_SUBST_RE.search(x) or "`" in x for x in tokens):
                # Expansion-before-skip: an executable substitution
                # (`$(...)` — not `$((...))` arithmetic — or a
                # backquote) runs while the shell builds this
                # command's argv, BEFORE any skip/consume decision
                # below could take effect (`command -v`, prefix
                # option values, non-pip heads all expand first —
                # dash-verified). Refused outright, wherever it
                # sits: the real checker stage is enumerated
                # substitution-free (fix-9 control), so the refusal
                # cannot bite it. `${...}`/bare `$x` alone never
                # execute — only data — and are not refused here
                # (a pip argv carrying any `$` is still refused at
                # evaluation as unknowable).
                return (True, found)
            action, rest = _strip_command_prefixes(tokens)
            if action == "trip":
                return (True, found)
            if action == "skip":
                continue
            t = rest
            if t and t[0].rsplit("/", 1)[-1] in ("python", "python3"):
                mkind, payload = _resolve_python_module(t)
                if mkind == "refuse":
                    return (True, found)
                t = payload
            if t and t[0].rsplit("/", 1)[-1] in ("pip", "pip3"):
                verdict = _pip_install_eval(t)
                if verdict is False:
                    return (True, found)
                if verdict is True:
                    found = True
                continue
            script = _shell_wrapper_script(t)
            if script is not None:
                tripped, inner = _scan_shell_text(script, depth + 1)
                if tripped:
                    return (True, found)
                found = found or inner
                continue
            if _mentions_pip(tokens):
                return (True, found)
    return (False, found)


def _run_payload_kind(payload: str):
    """Classify a checker-stage RUN payload (RUN word + builder
    `--flags` already stripped): ("exec", argv) for JSON exec form
    (valid Docker: `RUN ["pip", "install", ...]` — `json.loads`
    must yield a list of strings; backslash continuations inside
    the JSON were already joined into the logical line, and RUN
    `--flags` precede it); ("refuse", reason) for heredoc
    `RUN <<[−]EOF ...` (the heredoc body language is not provably
    shell — e.g. `RUN python3 <<EOF` can run pip inside Python —
    so no argv scan can clear it) and for `[`-led payloads that
    are not a JSON string list; ("shell", None) otherwise. `<<`
    inside quotes is data (naively dequoted before the heredoc
    test; mismatched quotes only over-refuse, never under-)."""
    dequoted = re.sub(r"'[^']*'|\"(?:[^\"\\\\]|\\\\.)*\"", "", payload)
    if HEREDOC_RE.search(dequoted):
        return ("refuse", "heredoc RUN (body language not provably shell)")
    s = payload.strip()
    if s.startswith("["):
        try:
            argv = json.loads(s)
        except ValueError:
            return ("refuse", "unparseable JSON RUN")
        if not isinstance(argv, list) or not all(isinstance(a, str) for a in argv):
            return ("refuse", "non-string JSON RUN argv")
        return ("exec", argv)
    return ("shell", None)


def _strip_run_payload(logical: str) -> str:
    """The shell payload of a Dockerfile logical line: a leading
    `RUN` instruction word (case-insensitive, like Docker) plus
    any `--flag`/`--flag=value` RUN options (`--mount=...`,
    `--network=...`, `--security=...`, quote-aware for values
    with spaces) are the IMAGE BUILDER's syntax, not the shell
    argv — without this an added `RUN pip install ...` line
    scans `RUN` as the executable and the real pip invocation
    evades the assert. Non-RUN lines pass through unchanged."""
    m = RUN_LEAD_RE.match(logical)
    if not m:
        return logical
    rest = logical[m.end():]
    i, n = 0, len(rest)
    while True:
        while i < n and rest[i] in " \t":
            i += 1
        if not rest.startswith("--", i):
            break
        q = None
        while i < n and (q is not None or rest[i] not in " \t"):
            c = rest[i]
            if q is not None:
                if c == q:
                    q = None
            elif c in "'\"":
                q = c
            i += 1
    return rest[i:]


def f6_only_binary_ok(docker: str) -> bool:
    """Every checker-stage `pip install` invocation is
    EFFECTIVELY wheel-only in its own argv (--require-hashes
    plus effective `:all:` with an empty no-set; a later
    `:none:` or conflicting override clears it). The leading
    `RUN` word and RUN `--flag`s are the builder's syntax and
    are stripped before locating pip commands; Dockerfile
    continuations join physical lines, then every evaluated shell
    text (shell-form payloads, wrapper scripts) is read in true
    shell order — backslash-newline splices removed, `#` comments
    cut — before backslash/quote-aware operator-splitting, and
    only the checker stage
    counts — flags on an echo (own line or past a
    mid-line `&&`), in another stage, or in a comment cannot
    satisfy this; pip argvs carrying unexpanded `$`/backquote
    expansions are refused outright. JSON exec-form RUN
    (`RUN ["pip", ...]`, valid
    Docker) is parsed with `json.loads`: prefixes strip to the real
    executable first (assignments/`sudo`/`command`/`exec`/`env`,
    the same grammar as shell text), then a direct pip argv joins
    the SAME effective-flags evaluation; a SUPPORTED shell
    wrapper (`[sh|bash|dash, -c, script, ...]` — and ONLY that
    shape, after prefixes) has its script inspected recursively
    as shell text (nested wrappers to `_WRAP_MAX_DEPTH`); every
    other exec form — other executables (even with script args),
    `sh` without `-c`, combined flags, empty argv — is REFUSED
    (fail closed, never skipped). Heredoc RUN (`RUN <<EOF`) and
    unparseable/non-string JSON RUN are likewise REFUSED (a
    heredoc body is not provably shell), as is any `<<`/`<<-`
    inside evaluated shell text (shell-form payloads and `-c`
    scripts alike); tokenization errors (unterminated quotes)
    trip too, and any other simple command mentioning pip trips
    via the unsupported-wrapper backstop. Instruction audit: SHELL
    only selects the shell for later shell-form RUNs (each RUN
    logical's pip argv is still evaluated in full, so it cannot
    hide an unflagged install); ADD/COPY never execute;
    ENTRYPOINT/CMD/HEALTHCHECK run at container runtime, not at
    build time — none of them can smuggle a build-time pip
    install past the scan. The physical layer is the probe-grounded
    builder rule exactly (exactly-one-backslash splice, pure
    concatenation, full-line-comment/blank skip in Go's White_Space
    set — inline `#` is argument text, Q1–Q10/R1–R21 — `\\n`-only
    line splits, logical-line staging) with fail-closed refusals
    for parser directives, lone CR, and exotic trailing whitespace
    (see `_docker_stage_logicals`)."""
    logicals, why = _docker_stage_logicals(docker)
    if why is not None:
        return False
    found = False
    for st, logical in logicals:
        if st != "checker":
            continue
        payload = _strip_run_payload(logical)
        if RUN_LEAD_RE.match(logical):
            kind, data = _run_payload_kind(payload)
            if kind == "refuse":
                return False
            if kind == "exec":
                action, rest = _strip_command_prefixes(data)
                if action != "exec":
                    return False  # refused prefix, or an exec form that
                    # executes nothing evaluable (existing rule: only
                    # evaluated pip installs and supported wrappers pass)
                t = rest
                if t and t[0].rsplit("/", 1)[-1] in ("python", "python3"):
                    mkind, payload = _resolve_python_module(t)
                    if mkind != "pip":
                        return False  # non-pip python exec, or an
                        # unrecognized pip-concealing shape: refuse
                    t = payload
                if t and t[0].rsplit("/", 1)[-1] in ("pip", "pip3"):
                    if _pip_install_eval(t) is not True:
                        return False  # unflagged, `$`-refused, or (existing)
                        # non-install pip exec: refuse
                    found = True
                    continue
                script = _shell_wrapper_script(t)
                if script is None:
                    return False  # unsupported exec form: refuse
                tripped, inner = _scan_shell_text(script, 0)
                if tripped:
                    return False
                found = found or inner
                continue
        tripped, inner = _scan_shell_text(payload, 0)
        if tripped:
            return False
        found = found or inner
    return found


# Publish must run only after every gating job: the direct
# `needs:` set must cover all of these. Removal weakens the gate
# (publish runs untested); addition only adds preconditions, so
# the assert is "at least" (superset), not equality.
REQUIRED_PUBLISH_NEEDS = frozenset(
    {"haskell", "bundle", "c-drivers", "pkcs11-fast", "demo-image"})

JOBS_RE = re.compile(r"^jobs:\s*$")
JOB_HDR_RE = re.compile(r"^  ([A-Za-z0-9_-]+):\s*$")
NEEDS_RE = re.compile(r"^    needs:\s*(.*?)\s*$")
NEED_ITEM_RE = re.compile(r"^      - ([A-Za-z0-9_-]+)\s*$")
# The driver-invocation anchor: first line of the timed step's `run:`
# loop over scripts/. The shell assert locates steps whose body
# contains it (not the cosmetic step name).
TIMED_DRIVER_ANCHOR = "for d in test-loader.sh test-c-abi.sh test-c-output.sh"
STEP_RE = re.compile(r"^      - ")
SHELL_RE = re.compile(r"^        shell:\s*[\"']?bash[\"']?\s*$")
RUN_KEY_RE = re.compile(r"^(?: {8}run:|      - run:)(.*)$")


def _norm_run_text(text: str) -> str:
    """Executable run text, normalized for anchor matching: comments
    stripped per line (quote-aware, as in shell), `\\`-continuations
    joined (exact shell rule on the comment-stripped line — an ODD
    count of trailing backslashes splices with the next line with no
    space added, exactly as the shell removes `\\<newline>`; no
    rstrip-first: trailing spaces after the backslash defeat the
    continuation in the shell too), then every horizontal-whitespace
    run (space/tab) collapsed to one space. Plain newlines are NOT
    joined: lines the shell runs as separate commands are a
    different program — fail closed (a loop genuinely split across
    commands does not match and trips via uniqueness, rather than
    equating two programs). Applied to BOTH the anchor and the
    searched payloads, so double-space, tab-indented, and
    `\\`-continued spellings of the same loop still match.
    Normalization can only conflate near-identical loops — which
    then trip via uniqueness or have the shell requirement enforced
    on them — never hide the loop."""
    logicals = []
    buf = ""
    for raw in text.splitlines():
        line = strip_comment(raw)
        trailing = len(line) - len(line.rstrip("\\"))
        if trailing % 2 == 1:
            buf += line[:-1]
        else:
            logicals.append(buf + line)
            buf = ""
    if buf:
        logicals.append(buf)
    return "\n".join(re.sub(r"[ \t]+", " ", logical) for logical in logicals)


def _step_run_payloads(raw_lines, struct, s: int, e: int):
    """Executable `run:` payloads of one step span [s, e): the body of
    every structural `run: |`/`>` block scalar (first-body-line
    threshold, exactly as structural_lines), the value of every
    single-line `run:`, and the continuation lines of a bare `run:`
    (a YAML multiline plain scalar folds deeper-indented lines into
    the run string). `struct` maps raw idx -> (indent,
    comment-stripped code) for structural lines only. Step names,
    env values, comments, and other keys' bodies are NOT payloads —
    an anchor there is prose, never a match."""
    payloads = []
    for idx in range(s, e):
        if idx not in struct:
            continue
        ind, code = struct[idx]
        m = RUN_KEY_RE.match(code)
        if not m:
            continue
        if BLOCK_HDR_RE.match(code):
            mh = re.match(r"^\s*-\s+", code)
            if mh and not re.match(r"^\s*-\s*[|>]", code):
                hdr_ind = len(mh.group(0))  # compact `- run:`: key column
            else:
                hdr_ind = ind
            j = idx + 1
            while j < e and strip_comment(raw_lines[j]).strip() == "":
                j += 1
            if j < e and len(raw_lines[j]) - len(raw_lines[j].lstrip(" ")) > hdr_ind:
                thresh = len(raw_lines[j]) - len(raw_lines[j].lstrip(" ")) - 1
                body = []
                while j < e and (raw_lines[j].strip() == ""
                                 or len(raw_lines[j]) - len(raw_lines[j].lstrip(" ")) > thresh):
                    body.append(raw_lines[j])
                    j += 1
                payloads.append("\n".join(body))
            # else: empty scalar — no payload
        elif m.group(1).strip() == "":
            # Bare `run:`: YAML folds deeper-indented following lines
            # into the value; capture them as the payload.
            j = idx + 1
            body = []
            while j < e and (raw_lines[j].strip() == ""
                             or len(raw_lines[j]) - len(raw_lines[j].lstrip(" ")) > ind):
                body.append(raw_lines[j])
                j += 1
            payloads.append("\n".join(body))
        else:
            payloads.append(m.group(1))
    return payloads


def f7_publish_needs(ci: str) -> set:
    """The DIRECT `needs:` set of the publish job: the `publish:`
    header at job indent (past the `jobs:` section), the `needs:`
    key at job-body indent (4 spaces), flow `[a, b]`, scalar, or
    block-sequence value. Block-scalar bodies and multiline-quote
    continuations are skipped via structural_lines, so a needs
    list inside publish.name or a comment is not a dependency.
    Attribution is strictly by job block: any other structural
    line above job-body indent ends publish's block — including
    an UNRECOGNIZED boundary such as a quoted job header — so a
    needs list past it belongs to another job and is never
    attributed to publish by proximity (defense in depth behind
    the GRAMMAR quoted-key refusal; a list the locator cannot
    attribute trips via the required-subset assert instead).
    Last duplicate key wins, as in YAML."""
    seen_jobs = False
    in_publish = False
    found = None
    collecting = False
    for _idx, ind, _raw, code in structural_lines(ci):
        if not code.strip():
            continue
        if JOBS_RE.match(code):
            seen_jobs = True
            continue
        m = JOB_HDR_RE.match(code)
        if m:
            if in_publish:
                break
            in_publish = seen_jobs and m.group(1) == "publish"
            continue
        if in_publish and ind < 4:
            break  # unrecognized job-block boundary: refuse proximity
        if not in_publish:
            continue
        if collecting:
            im = NEED_ITEM_RE.match(code)
            if im:
                found.add(im.group(1))
                continue
            collecting = False
        nm = NEEDS_RE.match(code)
        if nm:
            val = nm.group(1)
            if val == "":
                found = set()
                collecting = True
            elif val.startswith("["):
                found = set(re.findall(r"[A-Za-z0-9_-]+", val))
            else:
                w = re.match(r"^([A-Za-z0-9_-]+)\s*$", val)
                found = {w.group(1)} if w else set()
    return found if found is not None else set()


def f7_shell_bash_ok(ci: str) -> bool:
    """A real `shell: bash` step key at step-body indent (8 spaces)
    on the UNIQUE timed driver step of `jobs.c-drivers`: the step
    whose EXECUTABLE `run:` payload (block-scalar body,
    single-line value, or bare-`run:` continuations —
    `_step_run_payloads`) contains the driver invocation loop
    (`TIMED_DRIVER_ANCHOR`, `_norm_run_text` on both sides:
    comments stripped, `\\`-continuations joined, horizontal
    whitespace collapsed — reformatted spellings of the same loop
    still match). EXACTLY ONE c-drivers step may contain the
    anchor, and THAT step must carry the shell key. The step name,
    env values, and comments are not searched: a decoy anchor in
    an environment value never counts, and a decoy with the
    commands copied into a real `run:` breaks uniqueness — both
    trip. Step spans, the shell key, and the run headers come from
    structural_lines (bodies and multiline-quote continuations
    skipped), so `shell: bash` inside an env string, a comment, or
    another step — or a same-named step in another job — cannot
    satisfy this."""
    seen_jobs = False
    in_cdrv = False
    raw_lines = ci.splitlines()
    struct = {}  # raw idx -> (indent, code) for structural lines
    step_heads = []  # raw idx of each `      - ` step header in c-drivers
    shells = set()  # step headers whose block holds a real shell: bash
    job_end = len(raw_lines)
    cur = None
    for idx, ind, _raw, code in structural_lines(ci):
        struct[idx] = (ind, code)
        if not code.strip():
            continue
        if JOBS_RE.match(code):
            seen_jobs = True
            continue
        m = JOB_HDR_RE.match(code)
        if m:
            if in_cdrv:
                job_end = idx
                break
            in_cdrv = seen_jobs and m.group(1) == "c-drivers"
            continue
        if not in_cdrv:
            continue
        if STEP_RE.match(code):
            cur = idx
            step_heads.append(cur)
            continue
        if cur is not None and SHELL_RE.match(code):
            shells.add(cur)
    norm_anchor = _norm_run_text(TIMED_DRIVER_ANCHOR)
    anchored = []
    for k, s in enumerate(step_heads):
        e = step_heads[k + 1] if k + 1 < len(step_heads) else job_end
        payloads = _step_run_payloads(raw_lines, struct, s, e)
        if any(norm_anchor in _norm_run_text(p) for p in payloads):
            anchored.append(s)
    return len(anchored) == 1 and anchored[0] in shells


def _anchor_decoy_step() -> str:
    """A c-drivers step whose ENVIRONMENT value contains the driver
    anchor verbatim (plus a real `shell: bash` and an innocuous
    `run:`): prose, never executable content — the shell assert
    must not count it."""
    return ("      - name: driver notes\n"
            "        shell: bash\n"
            "        env:\n"
            f"          NOTE: \"{TIMED_DRIVER_ANCHOR}\"\n"
            "        run: echo notes\n")


def _with_env_decoy(ci: str) -> str:
    """`ci` plus the anchor decoy step as the first c-drivers step."""
    cdrv_at = ci.index("  c-drivers:\n")
    steps_at = ci.index("    steps:\n", cdrv_at)
    nl = ci.index("\n", steps_at) + 1
    return ci[:nl] + _anchor_decoy_step() + ci[nl:]


def probe_mutations(ci: str, docker: str):
    """Non-executable substitutes: (name, ci text, docker text, victim
    assert). Each must trip exactly its own assert while the others
    stay passing — proving the asserts match executable content."""
    shell_sub = ci.replace("        shell: bash\n",
                           "        # shell: bash\n", 1)
    without_shell = ci.replace("        shell: bash\n", "", 1)
    needs_sub = ci.replace(
        "    needs: [release-request, haskell, bundle, c-drivers, pkcs11-fast, demo-image]\n",
        "    needs: [haskell, bundle, pkcs11-fast, demo-image] # c-drivers\n",
        1)
    echo_sub = docker.replace(
        "         --only-binary=:all: \\\n"
        "         -r /tmp/checker-requirements.txt \\\n",
        "         -r /tmp/checker-requirements.txt \\\n"
        "    && echo --only-binary=:all: \\\n",
        1)
    shell_str = ci.replace(
        "        shell: bash\n",
        "        env:\n"
        "          NOTE: \"timing retained\n"
        "        shell: bash\n"
        "        for reference\"\n",
        1)
    needs_str = ci.replace(
        "    needs: [release-request, haskell, bundle, c-drivers, pkcs11-fast, demo-image]\n",
        "    name: \"staged release\n"
        "    needs: [release-request, haskell, bundle, c-drivers, pkcs11-fast, demo-image]\n"
        "    trailer\"\n",
        1)
    midline_echo = docker.replace(
        "    && /opt/p11c/bin/pip install --no-input --require-hashes \\\n"
        "         --only-binary=:all: \\\n"
        "         -r /tmp/checker-requirements.txt \\\n",
        "    && /opt/p11c/bin/pip install --no-input --require-hashes \\\n"
        "         -r /tmp/checker-requirements.txt"
        " && echo --only-binary=:all: \\\n",
        1)
    haskell_decoy = shell_sub.replace(
        "  c-drivers:\n",
        "      - name: PR driver subset (timed, deterministic)\n"
        "        shell: bash\n"
        "        run: echo decoy\n"
        "  c-drivers:\n",
        1)
    added_run = docker.replace(
        "    && command -v pkcs11-tool\n",
        "    && command -v pkcs11-tool\n"
        "RUN /opt/p11c/bin/pip install --no-input requests\n",
        1)
    none_clearer = docker.replace(
        "         --only-binary=:all: \\\n",
        "         --only-binary=:all: \\\n"
        "         --only-binary=:none: \\\n",
        1)
    # Same-named Bash decoy INSIDE c-drivers (codex's exact shape):
    # the real timed step loses `shell: bash` while a decoy step
    # with the name + shell but `run: echo decoy` precedes it.
    timed_name = "      - name: PR driver subset (timed, deterministic)\n"
    same_job = without_shell.replace(
        timed_name,
        timed_name + "        shell: bash\n        run: echo decoy\n"
        + timed_name,
        1)
    # Reverse direction: the real timed step keeps its shell, but a
    # second c-drivers step gains the driver loop (uniqueness
    # broken — the selector must not silently pick one).
    cdrv_at = ci.index("  c-drivers:\n")
    dup_anchor = (ci[:cdrv_at] + ci[cdrv_at:].replace(
        "        run: tar xzf ossl-cache/openssl-4.0.2.tar.gz -C /\n",
        "        run: echo for d in test-loader.sh test-c-abi.sh"
        " test-c-output.sh && tar xzf ossl-cache/openssl-4.0.2.tar.gz -C /\n",
        1))
    # Checker-stage JSON exec-form RUN invoking pip unflagged
    # (codex's exact shape): --no-binary=cffi breaks wheel-only.
    exec_run = ('RUN ["/opt/p11c/bin/pip", "install", "--no-input", '
                '"--require-hashes", "--no-binary=cffi", '
                '"--force-reinstall", "-r", '
                '"/tmp/checker-requirements.txt"]\n')
    json_run = docker.replace(
        "    && command -v pkcs11-tool\n",
        "    && command -v pkcs11-tool\n" + exec_run,
        1)
    # Checker-stage heredoc RUN: refused outright, even though the
    # visible body line is flagged (the body language is not
    # provably shell).
    heredoc_run = docker.replace(
        "    && command -v pkcs11-tool\n",
        "    && command -v pkcs11-tool\n"
        "RUN <<EOF\n"
        "/opt/p11c/bin/pip install --require-hashes --only-binary=:all: pkg\n"
        "EOF\n",
        1)
    # Env-decoy anchor + the REAL loop reformatted (codex's exact
    # substitutions): the real step loses `shell: bash`, the loop
    # gains a second space after `for d in` (sub 1) or is split
    # across `\`-continued lines (sub 2). The normalized run-only
    # match still selects the real step — shell-less, so it trips.
    decoy_dspace = _with_env_decoy(without_shell.replace(
        "          for d in test-loader.sh",
        "          for d in  test-loader.sh", 1))
    decoy_cont = _with_env_decoy(without_shell.replace(
        "          for d in test-loader.sh test-c-abi.sh test-c-output.sh \\\n",
        "          for d in test-loader.sh \\\n"
        "              test-c-abi.sh test-c-output.sh \\\n", 1))
    # Decoy-only: the real loop is gone, the anchor survives only
    # as env prose — zero anchor-bearing run payloads, trips.
    decoy_only = _with_env_decoy(ci.replace(
        "          for d in test-loader.sh test-c-abi.sh test-c-output.sh \\\n"
        "              test-c-mutexes.sh test-consumers.sh test-client.sh \\\n"
        "              test-ossl4-bounds.sh; do\n",
        "          echo loop-removed\n", 1))
    # Checker-stage exec-form SHELL WRAPPER hiding an unflagged pip
    # install (codex's exact shape): the script is inspected, the
    # `--no-binary=cffi` install without `:all:` trips.
    wrap_run = docker.replace(
        "    && command -v pkcs11-tool\n",
        "    && command -v pkcs11-tool\n"
        'RUN ["/bin/sh", "-c", "/opt/p11c/bin/pip install --require-hashes '
        '--no-binary=cffi --force-reinstall -r '
        '/tmp/checker-requirements.txt"]\n',
        1)
    # Checker-stage UNSUPPORTED exec form (`sh` without `-c`):
    # refused fail-closed, never silently skipped.
    refuse_run = docker.replace(
        "    && command -v pkcs11-tool\n",
        "    && command -v pkcs11-tool\n"
        'RUN ["/bin/sh"]\n',
        1)
    return [
        ("shell-in-comment", shell_sub, docker, "f7-driver-shell-bash"),
        ("needs-in-comment", needs_sub, docker, "f7-publish-needs-c-drivers"),
        ("flag-on-echo", ci, echo_sub, "f6-only-binary"),
        ("shell-in-env-string", shell_str, docker, "f7-driver-shell-bash"),
        ("needs-in-publish-name", needs_str, docker,
         "f7-publish-needs-c-drivers"),
        ("flags-on-midline-echo", ci, midline_echo, "f6-only-binary"),
        ("shell-in-haskell-only", haskell_decoy, docker,
         "f7-driver-shell-bash"),
        ("added-unflagged-run", ci, added_run, "f6-only-binary"),
        ("only-binary-none-clearer", ci, none_clearer, "f6-only-binary"),
        ("shell-decoy-same-job", same_job, docker,
         "f7-driver-shell-bash"),
        ("timed-commands-duplicated", dup_anchor, docker,
         "f7-driver-shell-bash"),
        ("json-run-unflagged-pip", ci, json_run, "f6-only-binary"),
        ("heredoc-run-refused", ci, heredoc_run, "f6-only-binary"),
        ("anchor-env-decoy-double-space", decoy_dspace, docker,
         "f7-driver-shell-bash"),
        ("anchor-env-decoy-continued-loop", decoy_cont, docker,
         "f7-driver-shell-bash"),
        ("anchor-env-decoy-only", decoy_only, docker,
         "f7-driver-shell-bash"),
        ("exec-wrap-unflagged-pip", ci, wrap_run, "f6-only-binary"),
        ("exec-unsupported-refused", ci, refuse_run, "f6-only-binary"),
    ]


def self_test_structural() -> int:
    """F-6/F-7 declarative asserts (stdlib-only text scans, no YAML
    parser: the CI container has no PyYAML). Single implementation;
    wired into both the CI static-gates step and run-gates.sh via
    --self-test."""
    bad = 0

    def check_struct(name, cond, detail):
        nonlocal bad
        print(f"{'ok' if cond else 'FAIL'}: selftest-{name}: {detail}")
        if not cond:
            bad += 1

    # F-6: the checker-stage pip install keeps --only-binary=:all:
    # so sdist-only resolution (wheel-withholding index) fails
    # closed instead of fetching unhashed build deps.
    docker = (REPO / "docker" / "Dockerfile.demo").read_text()
    check_struct("f6-only-binary",
                 f6_only_binary_ok(docker),
                 "checker pip install keeps --require-hashes --only-binary=:all:")

    # F-7: publish directly needs every gating job ...
    ci = DEFAULT.read_text()
    needs = f7_publish_needs(ci)
    check_struct("f7-publish-needs-c-drivers",
                 REQUIRED_PUBLISH_NEEDS <= needs,
                 f"publish needs {sorted(needs)} covers required "
                 f"{sorted(REQUIRED_PUBLISH_NEEDS)}")
    # ... and c-drivers itself must run wherever publish runs: no
    # job-level `if:`; its only permitted dependency is the unconditional
    # request preflight (else adding it to publish.needs could stall).
    cdrv = re.search(r"(?ms)^  c-drivers:\n(.*?)(?=^  [a-z0-9-]+:|\Z)",
                     code_text(ci))
    cdrv_body = cdrv.group(1) if cdrv else ""
    # Job-level keys sit at exactly 4 spaces; step-level `if:` (8
    # spaces) must not trip this — anchor at line start.
    check_struct("f7-c-drivers-unconditional",
                 bool(cdrv) and not re.search(r"(?m)^    if:", cdrv_body)
                 and not re.search(r"(?m)^    needs:(?! release-request$)", cdrv_body)
                 and ("    needs: release-request" not in cdrv_body
                      or bool(re.search(r"(?ms)^  release-request:\n(?:(?!^  [a-z0-9-]+:).)*?(?=^  [a-z0-9-]+:|\Z)", code_text(ci)))
                      and not re.search(r"(?ms)^  release-request:\n(?:(?!^  [a-z0-9-]+:).)*?^    (if|needs):", code_text(ci))),
                 "c-drivers runs on v-tags; only unconditional release-request dependency allowed")

    # F-7: the timed driver step selects bash (container default is
    # sh/dash, where `time` is exit 127).
    check_struct("f7-driver-shell-bash",
                 f7_shell_bash_ok(ci),
                 "timed driver step selects shell: bash")

    # Liveness probes: each substitute must trip exactly its own
    # assert. `applied` guards against anchor drift — a mutation
    # that no longer applies is a vacuous probe, not a pass.
    for name, pci, pdocker, victim in probe_mutations(ci, docker):
        applied = pci != ci or pdocker != docker
        results = {
            "f6-only-binary": f6_only_binary_ok(pdocker),
            "f7-publish-needs-c-drivers":
                REQUIRED_PUBLISH_NEEDS <= f7_publish_needs(pci),
            "f7-driver-shell-bash": f7_shell_bash_ok(pci),
        }
        check_struct(f"probe-{name}",
                     applied and not results[victim]
                     and all(v for k, v in results.items() if k != victim),
                     f"substitute trips exactly {victim}")

    # Anchor positives (both polarities controlled): an env decoy
    # plus a REFORMATTED real loop with its shell kept still
    # selects exactly the real step — normalization finds it, the
    # decoy is ignored.
    dspace_shell = _with_env_decoy(ci.replace(
        "          for d in test-loader.sh",
        "          for d in  test-loader.sh", 1))
    cont_shell = _with_env_decoy(ci.replace(
        "          for d in test-loader.sh test-c-abi.sh test-c-output.sh \\\n",
        "          for d in test-loader.sh \\\n"
        "              test-c-abi.sh test-c-output.sh \\\n", 1))
    check_struct("probe-anchor-double-space-pass",
                 dspace_shell != ci and f7_shell_bash_ok(dspace_shell),
                 "reformatted real loop still selected (env decoy ignored)")
    check_struct("probe-anchor-continued-loop-pass",
                 cont_shell != ci and f7_shell_bash_ok(cont_shell),
                 "continued real loop still selected (env decoy ignored)")

    # Format-control branches: effective wheel-only per pip's
    # handle_mutual_excludes/get_allowed_formats, on synthetic
    # checker stages (anchor-free). Last occurrence wins;
    # `:none:` clears; any no_binary entry re-allows source.
    syn = "FROM ubuntu:26.04 AS checker\n"
    _deep_ok = _deep_cap = "pip install --require-hashes --only-binary=:all: pkg"
    for _ in range(3):
        _deep_ok = ("sh -c \"" + _deep_ok.replace("\\", "\\\\").replace("\"", "\\\"") + "\"")
    for _ in range(12):
        _deep_cap = ("sh -c \"" + _deep_cap.replace("\\", "\\\\").replace("\"", "\\\"") + "\"")
    fmt_cases = [
        ("fmt-none-clears",
         "RUN pip install --require-hashes --only-binary=:all:"
         " --only-binary=:none: pkg\n", False),
        ("fmt-same-flag-all-none",
         "RUN pip install --require-hashes --only-binary=:all:,:none: pkg\n",
         False),
        ("fmt-none-then-all",
         "RUN pip install --require-hashes --only-binary=:none:"
         " --only-binary=:all: pkg\n", True),
        ("fmt-no-binary-all",
         "RUN pip install --require-hashes --only-binary=:all:"
         " --no-binary=:all: pkg\n", False),
        ("fmt-no-binary-pkg",
         "RUN pip install --require-hashes --only-binary=:all:"
         " --no-binary=somepkg pkg\n", False),
        ("fmt-second-only-adds",
         "RUN pip install --require-hashes --only-binary=:all:"
         " --only-binary=somepkg pkg\n", True),
        ("fmt-separate-spelling",
         "RUN pip install --require-hashes --only-binary :all: pkg\n", True),
        ("fmt-no-binary-none-ok",
         "RUN pip install --require-hashes --only-binary=:all:"
         " --no-binary=:none: pkg\n", True),
        ("fmt-run-flags",
         "RUN --mount=type=cache,target=/root/.cache pip install"
         " --require-hashes --only-binary=:all: pkg\n", True),
        ("fmt-run-unflagged",
         "RUN pip install --no-input pkg\n", False),
        ("fmt-second-run-unflagged",
         "RUN pip install --require-hashes --only-binary=:all: pkg\n"
         "RUN pip install --no-input other\n", False),
        ("fmt-exec-ok",
         'RUN ["pip", "install", "--require-hashes",'
         ' "--only-binary=:all:", "pkg"]\n', True),
        ("fmt-exec-unflagged",
         'RUN ["/opt/p11c/bin/pip", "install", "--no-input",'
         ' "--require-hashes", "--no-binary=cffi", "--force-reinstall",'
         ' "-r", "/tmp/checker-requirements.txt"]\n', False),
        ("fmt-exec-invalid-json",
         'RUN ["pip", install]\n', False),
        ("fmt-exec-nonstring-argv",
         'RUN ["pip", 42]\n', False),
        ("fmt-exec-continuation",
         'RUN ["pip", "install", \\\n'
         ' "--require-hashes", "--only-binary=:all:", "pkg"]\n', True),
        ("fmt-exec-run-flags",
         'RUN --mount=type=cache,target=/root/.cache ["pip", "install",'
         ' "--require-hashes", "--only-binary=:all:", "pkg"]\n', True),
        ("fmt-heredoc-refused",
         "RUN <<EOF\n"
         "pip install --require-hashes --only-binary=:all: pkg\n"
         "EOF\n", False),
        ("fmt-quoted-heredoc-op-ok",
         'RUN pip install --require-hashes --only-binary=:all: pkg'
         ' && echo "a << b"\n', True),
        ("fmt-exec-wrap-unflagged",
         'RUN ["/bin/sh", "-c", "/opt/p11c/bin/pip install --require-hashes '
         '--no-binary=cffi --force-reinstall -r '
         '/tmp/checker-requirements.txt"]\n', False),
        ("fmt-exec-wrap-flagged",
         'RUN ["/bin/sh", "-c", "/opt/p11c/bin/pip install --require-hashes '
         '--only-binary=:all: -r /tmp/checker-requirements.txt"]\n', True),
        ("fmt-exec-wrap-bash",
         'RUN ["bash", "-c", "pip install --require-hashes '
         '--only-binary=:all: pkg"]\n', True),
        ("fmt-exec-wrap-nested-unflagged",
         'RUN ["sh", "-c", "sh -c \\"pip install --no-input pkg\\""]\n',
         False),
        ("fmt-exec-wrap-nested-flagged",
         'RUN ["sh", "-c", "sh -c \\"pip install --require-hashes '
         '--only-binary=:all: pkg\\""]\n', True),
        ("fmt-exec-wrap-extra-args",
         'RUN ["sh", "-c", "pip install --require-hashes '
         '--only-binary=:all: pkg", "name", "x"]\n', True),
        ("fmt-exec-wrap-continuation",
         "RUN " + json.dumps(["sh", "-c",
                               "pip install --require-hashes \\\n"
                               "--only-binary=:all: pkg"]) + "\n", True),
        ("fmt-exec-wrap-deep-ok",
         "RUN " + json.dumps(["sh", "-c", _deep_ok]) + "\n", True),
        ("fmt-exec-wrap-deep-refused",
         "RUN " + json.dumps(["sh", "-c", _deep_cap]) + "\n", False),
        ("fmt-exec-refuse-sh-without-c",
         'RUN ["/bin/sh"]\n', False),
        ("fmt-exec-refuse-sh-c-without-script",
         'RUN ["sh", "-c"]\n', False),
        ("fmt-exec-refuse-empty-argv",
         'RUN []\n', False),
        ("fmt-exec-refuse-python-c",
         'RUN ["python3", "-c", "import pip"]\n', False),
        ("fmt-exec-refuse-combined-flags",
         'RUN ["sh", "-ec", "pip install --require-hashes '
         '--only-binary=:all: pkg"]\n', False),
        ("fmt-exec-refuse-plain-other",
         'RUN ["echo", "hi"]\n', False),
        ("fmt-shell-nested-wrap-unflagged",
         'RUN sh -c "pip install --no-input pkg"\n', False),
        ("fmt-shell-nested-wrap-flagged",
         'RUN sh -c "pip install --require-hashes --only-binary=:all: pkg"\n',
         True),
    ]
    for name, body, expect in fmt_cases:
        got = f6_only_binary_ok(syn + body)
        check_struct(f"f6-{name}", got == expect,
                     f"effective format control -> {got} (want {expect})")

    return bad


def self_test_fix7() -> int:
    """Fix-round-7 durable regression (codex re-review #6 Lows):
    GRAMMAR refuses every quoted mapping key (one negative per
    structural locator + flow/`''`/positive shapes), the Low-1 and
    Low-3 codex substitutions fail the gate with GRAMMAR
    attribution, the needs locator attributes strictly by job
    block (locator-direct probes), and shell-wrapper evaluation
    follows true shell order (comment cut, `$`/backquote refusal,
    backslash-newline join — each both polarities)."""
    import io
    from contextlib import redirect_stdout
    bad = 0

    def check_fix7(name, cond, detail):
        nonlocal bad
        print(f"{'ok' if cond else 'FAIL'}: selftest-{name}: {detail}")
        if not cond:
            bad += 1

    def gate_run(src):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = check_text(src)
        return rc, buf.getvalue()

    ci = DEFAULT.read_text()

    # (1) Quoted-key GRAMMAR negatives: one per structural locator
    # (run/needs/shell/steps/jobs/job-id) plus flow, `''`-escape,
    # and both quote styles — each otherwise gate-clean, so
    # GRAMMAR is the attributed catcher (spelling cited).
    qcases = [
        ("fix7-quoted-run",
         "jobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n"
         "      - name: x\n        \"run\": echo hi\n", '"run"'),
        ("fix7-quoted-run-single",
         "jobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n"
         "      - name: x\n        'run': echo hi\n", "'run'"),
        ("fix7-quoted-needs",
         "jobs:\n  publish:\n    runs-on: ubuntu-latest\n"
         "    \"needs\": [a]\n", '"needs"'),
        ("fix7-quoted-shell",
         "jobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n"
         "      - name: x\n        run: echo hi\n        \"shell\": bash\n",
         '"shell"'),
        ("fix7-quoted-steps",
         "jobs:\n  t:\n    runs-on: ubuntu-latest\n    \"steps\": []\n",
         '"steps"'),
        ("fix7-quoted-jobs",
         "\"jobs\":\n  t:\n    runs-on: ubuntu-latest\n", '"jobs"'),
        ("fix7-quoted-job-id",
         "jobs:\n  \"t\":\n    runs-on: ubuntu-latest\n", '"t"'),
        ("fix7-quoted-key-flow",
         "jobs:\n  t:\n    runs-on: ubuntu-latest\n    env: {\"K\": \"v\"}\n",
         '"K"'),
        ("fix7-quoted-key-escape",
         "jobs:\n  t:\n    runs-on: ubuntu-latest\n    'it''s': v\n",
         "'it''s'"),
    ]
    for name, text, cited in qcases:
        rc, out = gate_run(text)
        check_fix7(name,
                   rc == 1 and "FAIL: GRAMMAR" in out and cited in out,
                   f"quoted key refused by GRAMMAR ({cited} cited)")
    # Positive polarity: quoted VALUES (incl. a colon inside) pass.
    qpos = ("jobs:\n  t:\n    runs-on: ubuntu-latest\n"
            "    env: {A: \"x\", B: \"a: b\"}\n    steps:\n"
            "      - run: \"k: v\"\n")
    rc, _out = gate_run(qpos)
    check_fix7("fix7-quoted-values-pass", rc == 0,
               "quoted values (incl. inner colon) still pass")

    # (2) Codex-substitution E2Es: the gate fails each via GRAMMAR.
    m_run = e2e_quoted_run_text()
    rc, out = gate_run(m_run)
    check_fix7("fix7-e2e-quoted-run",
               m_run != ci and rc == 1 and "FAIL: GRAMMAR" in out
               and '"run"' in out,
               "Low-1 codex shape fails the gate via GRAMMAR")
    m_needs = e2e_quoted_needs_text()
    rc, out = gate_run(m_needs)
    check_fix7("fix7-e2e-quoted-needs",
               m_needs != ci and rc == 1 and "FAIL: GRAMMAR" in out
               and '"needs"' in out and '"zzz"' in out,
               "Low-3 codex shape fails the gate via GRAMMAR")

    # (3) Locator-direct probes: needs attributed strictly by job
    # block (holds even if GRAMMAR refusal were bypassed).
    check_fix7("fix7-needs-e2e-unattributed",
               not (REQUIRED_PUBLISH_NEEDS <= f7_publish_needs(m_needs)),
               "quoted successor list not attributed to publish")
    qpub = ("jobs:\n  \"publish\":\n"
            "    needs: [haskell, bundle, c-drivers, pkcs11-fast,"
            " demo-image]\n")
    check_fix7("fix7-needs-quoted-publish-unattributed",
               not (REQUIRED_PUBLISH_NEEDS <= f7_publish_needs(qpub)),
               "needs outside any recognized job block unattributed")
    early = ("jobs:\n"
             "    needs: [haskell, bundle, c-drivers, pkcs11-fast,"
             " demo-image]\n"
             "  publish:\n    runs-on: ubuntu-latest\n")
    check_fix7("fix7-needs-before-job-unattributed",
               not (REQUIRED_PUBLISH_NEEDS <= f7_publish_needs(early)),
               "needs before any job block unattributed")

    # (4) Shell-wrapper evaluation: comment cut, expansion refusal,
    # continuation join — each both polarities, on synthetic
    # checker stages (anchor-free) plus nesting depth.
    syn = "FROM ubuntu:26.04 AS checker\n"

    def wrap(script):
        return syn + "RUN " + json.dumps(["sh", "-c", script]) + "\n"

    sh_cases = [
        ("fix7-comment-flag-ignored",
         wrap("pip install --require-hashes --no-binary=cffi"
              " --force-reinstall -r /tmp/checker-requirements.txt"
              " # --only-binary=:all:"), False),
        ("fix7-comment-trailing-ok",
         wrap("pip install --require-hashes --only-binary=:all:"
              " pkg # trailing comment"), True),
        ("fix7-comment-quoted-hash-data",
         wrap('pip install --require-hashes --only-binary=:all:'
              ' "pkg#frag"'), True),
        ("fix7-comment-glued-hash-data",
         wrap("pip install --require-hashes a#b --only-binary=:all:"
              " pkg"), True),
        ("fix7-comment-shell-form-ignored",
         syn + "RUN pip install --require-hashes --only-binary=:all:"
         " pkg # comment\n", True),
        ("fix7-comment-shell-form-flag",
         syn + "RUN pip install --require-hashes --no-binary=cffi"
         " -r req.txt # --only-binary=:all:\n", False),
        ("fix7-comment-expansion-ignored",
         wrap("pip install --require-hashes --only-binary=:all:"
              " pkg # \"$@\""), True),
        ("fix7-comment-nested-ignored",
         wrap('sh -c "pip install --require-hashes --no-binary=cffi'
              ' -r req.txt # --only-binary=:all:"'), False),
        ("fix7-expand-dollar-at",
         wrap('pip install --require-hashes --only-binary=:all: "$@"'),
         False),
        ("fix7-expand-dollar-star",
         wrap('pip install --require-hashes --only-binary=:all: "$*"'),
         False),
        ("fix7-expand-dollar-1",
         wrap('pip install --require-hashes --only-binary=:all: "$1"'),
         False),
        ("fix7-expand-dollar-brace",
         wrap('pip install --require-hashes --only-binary=:all: "${X}"'),
         False),
        ("fix7-expand-dollar-paren",
         wrap("pip install --require-hashes --only-binary=:all:"
              " $(echo pkg)"), False),
        ("fix7-expand-backquote",
         wrap("pip install --require-hashes --only-binary=:all:"
              " `echo pkg`"), False),
        ("fix7-split-flag-name-hidden",
         wrap("pip install --require-hashes --only-binary=:all:"
              " --no-binar\\\ny=cffi pkg"), False),
        ("fix7-split-value-effective",
         wrap("pip install --require-hashes --only-binary=:\\\nall: pkg"),
         True),
        ("fix7-split-clearer-hidden",
         wrap("pip install --require-hashes --only-binary=:all:"
              " --only-binary=:no\\\nne: pkg"), False),
        ("fix7-split-nested-hidden",
         wrap('sh -c "pip install --require-hashes --only-binary=:all:'
              ' --no-binar\\\ny=cffi pkg"'), False),
    ]
    for name, body, expect in sh_cases:
        got = f6_only_binary_ok(body)
        check_fix7(name, got == expect,
                   f"shell evaluation -> {got} (want {expect})")

    return bad


def self_test_fix8() -> int:
    """Fix-round-8 durable regression (codex re-review #7 Low 2 tail:
    shell tokenization differentials). Backslash/quote-aware command
    splitting (escaped operators hide nothing, both layers; even
    runs still split; flagged-with-escapes passes un-split),
    supported command-prefix inspection (command/exec/env/sudo
    grammars, both polarities, shell + `-c` + exec layers),
    unsupported-wrapper refusal (unrecognized head + pip mention
    trips; pip-free stays silent), heredoc refusal in evaluated
    shell text (every delimiter spelling, nested `-c`; `<<<` /
    quoted / escaped `<<` stay evaluable), and fail-closed
    tokenization errors (unterminated quotes trip; dash's literal
    trailing backslash evaluates). Shapes: trip controls pair the
    probe with a flagged install elsewhere (False proves the trip —
    a skip would pass), pass controls evaluate the probe alone
    (True proves evaluation — a skip would starve `found`).
    Synthetic checker stages (anchor-free)."""
    bad = 0

    def check_fix8(name, cond, detail):
        nonlocal bad
        print(f"{'ok' if cond else 'FAIL'}: selftest-{name}: {detail}")
        if not cond:
            bad += 1

    syn = "FROM ubuntu:26.04 AS checker\n"
    GOOD = "pip install --require-hashes --only-binary=:all: pkg"
    BAD = "pip install --require-hashes --no-binary=cffi pkg"

    def wrap(script):
        return syn + "RUN " + json.dumps(["sh", "-c", script]) + "\n"

    def run(line):
        return syn + "RUN " + line + "\n"

    def run2(line1, line2):
        return syn + "RUN " + line1 + "\nRUN " + line2 + "\n"

    def run_wrap(line, script):
        return syn + "RUN " + line + "\nRUN " + json.dumps(["sh", "-c", script]) + "\n"

    cases = [
        ("fix8-esc-semi-c",
         run_wrap(GOOD, "LOG=/tmp/pip\\;log " + BAD), False),
        ("fix8-esc-semi-shell",
         run2(GOOD, "LOG=/tmp/pip\\;log " + BAD), False),
        ("fix8-esc-pipe-c",
         run_wrap(GOOD, "LOG=/tmp/pip\\|log " + BAD), False),
        ("fix8-esc-pipe-shell",
         run2(GOOD, "X=a\\|b " + BAD), False),
        ("fix8-esc-amp-c",
         run_wrap(GOOD, "LOG=/tmp/pip\\&log " + BAD), False),
        ("fix8-esc-amp-shell",
         run2(GOOD, "X=a\\&b " + BAD), False),
        ("fix8-esc-flagged-passes",
         run("LOG=a\\;b " + GOOD), True),
        ("fix8-esc-flagged-passes-c",
         wrap("LOG=a\\;b " + GOOD), True),
        ("fix8-esc-double-backslash-splits",
         run("echo hi \\\\; " + GOOD), True),
        ("fix8-esc-double-backslash-evaluates",
         run(GOOD + " \\\\; echo done"), True),
        ("fix8-esc-triple-data",
         run("X=a\\\\\\;b " + GOOD), True),
        ("fix8-split-quoted-semi-kept",
         run('echo "a;b" && ' + GOOD), True),
        ("fix8-split-quoted-semi-kept-sq",
         run("echo 'a;b' && " + GOOD), True),
        ("fix8-prefix-command-shell-flagged",
         run("command " + GOOD), True),
        ("fix8-prefix-command-shell-unflagged",
         run2(GOOD, "command " + BAD), False),
        ("fix8-prefix-command-c-flagged",
         wrap("command " + GOOD), True),
        ("fix8-prefix-command-c-unflagged",
         run_wrap(GOOD, "command " + BAD), False),
        ("fix8-prefix-command-p-flagged",
         run("command -p " + GOOD), True),
        ("fix8-prefix-command-p-unflagged",
         run2(GOOD, "command -p " + BAD), False),
        ("fix8-prefix-command-v-skip",
         run2(GOOD, "command -v pip install --no-input x"), True),
        ("fix8-prefix-command-bare",
         run2(GOOD, "command -p"), True),
        ("fix8-prefix-exec-shell-flagged",
         run("exec " + GOOD), True),
        ("fix8-prefix-exec-shell-unflagged",
         run2(GOOD, "exec " + BAD), False),
        ("fix8-prefix-exec-c-flagged",
         wrap("exec " + GOOD), True),
        ("fix8-prefix-exec-c-unflagged",
         run_wrap(GOOD, "exec " + BAD), False),
        ("fix8-prefix-exec-a-flagged",
         run("exec -a NAME " + GOOD), True),
        ("fix8-prefix-exec-a-unflagged",
         run2(GOOD, "exec -a NAME " + BAD), False),
        ("fix8-prefix-exec-cl-flagged",
         run("exec -c -l " + GOOD), True),
        ("fix8-prefix-exec-bare",
         run2(GOOD, "exec"), True),
        ("fix8-prefix-env-shell-flagged",
         run("env " + GOOD), True),
        ("fix8-prefix-env-shell-unflagged",
         run2(GOOD, "env " + BAD), False),
        ("fix8-prefix-env-i-flagged",
         run("env -i " + GOOD), True),
        ("fix8-prefix-env-i-unflagged",
         run2(GOOD, "env -i " + BAD), False),
        ("fix8-prefix-env-u-shell-flagged",
         run("env -u FOO " + GOOD), True),
        ("fix8-prefix-env-u-shell-unflagged",
         run2(GOOD, "env -u FOO " + BAD), False),
        ("fix8-prefix-env-u-c-flagged",
         wrap("env -u FOO " + GOOD), True),
        ("fix8-prefix-env-u-c-unflagged",
         run_wrap(GOOD, "env -u FOO " + BAD), False),
        ("fix8-prefix-env-u-attached",
         run2(GOOD, "env -uFOO " + BAD), False),
        ("fix8-prefix-env-combined-shorts",
         run("env -iuFOO " + GOOD), True),
        ("fix8-prefix-env-assign-flagged",
         run("env A=B " + GOOD), True),
        ("fix8-prefix-env-assign-unflagged",
         run2(GOOD, "env A=B " + BAD), False),
        ("fix8-prefix-env-dd-flagged",
         run("env -- " + GOOD), True),
        ("fix8-prefix-env-dd-unflagged",
         run2(GOOD, "env -- " + BAD), False),
        ("fix8-prefix-env-combined-flagged",
         run("env -i -u FOO -- A=B " + GOOD), True),
        ("fix8-prefix-env-combined-unflagged",
         run2(GOOD, "env -i -u FOO -- A=B " + BAD), False),
        ("fix8-prefix-env-S-refused",
         run2(GOOD, 'env -S"pip install --no-input pkg"'), False),
        ("fix8-prefix-env-S-clean",
         run('env -S"--foo" ' + GOOD), True),
        ("fix8-prefix-env-bare",
         run2(GOOD, "env"), True),
        ("fix8-prefix-sudo-flagged",
         run("sudo " + GOOD), True),
        ("fix8-prefix-sudo-unflagged",
         run2(GOOD, "sudo " + BAD), False),
        ("fix8-prefix-sudo-dd-flagged",
         run("sudo -- " + GOOD), True),
        ("fix8-prefix-sudo-flag-refused",
         run2(GOOD, "sudo -E " + GOOD), False),
        ("fix8-prefix-env-path-flagged",
         run("/usr/bin/env " + GOOD), True),
        ("fix8-prefix-env-path-unflagged",
         run2(GOOD, "/usr/bin/env " + BAD), False),
        ("fix8-prefix-nested-command-env",
         run("command env -i " + GOOD), True),
        ("fix8-prefix-nested-sudo-command",
         run2(GOOD, "sudo command " + BAD), False),
        ("fix8-prefix-wrap-assign",
         run2(GOOD, 'VAR=x sh -c "' + BAD + '"'), False),
        ("fix8-prefix-wrap-env",
         run('env -i sh -c "' + GOOD + '"'), True),
        ("fix8-prefix-execform-env-flagged",
         syn + "RUN " + json.dumps(["env", "-u", "X"] + GOOD.split()) + "\n",
         True),
        ("fix8-prefix-execform-env-unflagged",
         syn + "RUN " + json.dumps(["env", "-u", "X"] + BAD.split()) + "\n",
         False),
        ("fix8-prefix-assign-static",
         run("FOO=bar " + GOOD), True),
        ("fix8-backstop-nice",
         run2(GOOD, "nice -n 5 " + BAD), False),
        ("fix8-backstop-timeout",
         run2(GOOD, "timeout 10 " + BAD), False),
        ("fix8-backstop-xargs",
         run2(GOOD, "echo x | xargs " + BAD), False),
        ("fix8-backstop-find",
         run2(GOOD, "find . -exec " + BAD + " {} +"), False),
        ("fix8-backstop-python-c",
         run2(GOOD, 'python3 -c "import pip"'), False),
        ("fix8-backstop-python-c-clean",
         run2(GOOD, 'python3 -c "print(1)"'), True),
        ("fix8-backstop-clean-nice",
         run2(GOOD, "nice echo hi"), True),
        ("fix8-backstop-clean-pipeline",
         run2(GOOD, "echo pipeline"), True),
        ("fix8-backstop-then",
         run2(GOOD, "if true; then " + BAD + "; fi"), False),
        ("fix8-backstop-subshell",
         run2(GOOD, "(" + BAD + ")"), False),
        ("fix8-backstop-pipx",
         run2(GOOD, "pipx install cowsay"), False),
        ("fix8-backstop-dynassign",
         run2(GOOD, "X=$(" + BAD + ") true"), False),
        ("fix8-backstop-dynassign-harmless",
         run2(GOOD, "X=$(echo hi) " + GOOD), False),
        ("fix8-backstop-assign-arith",
         run("X=$((1+2)) " + GOOD), True),
        ("fix8-backstop-assign-backquote",
         run2(GOOD, "X=`" + BAD + "` true"), False),
        ("fix8-heredoc-c-codex",
         run_wrap(GOOD, "python3 <<'EOF'\nimport subprocess\n"
                  "subprocess.check_call(" + repr(BAD.split()) + ")\nEOF\n"),
         False),
        ("fix8-heredoc-c-unquoted",
         run_wrap(GOOD, "cat <<EOF\n" + BAD + "\nEOF\n"), False),
        ("fix8-heredoc-c-dashstrip",
         run_wrap(GOOD, "cat <<-EOF\n\t" + BAD + "\n\tEOF\n"), False),
        ("fix8-heredoc-c-dquotedelim",
         run_wrap(GOOD, 'cat <<"EOF"\n' + BAD + "\nEOF\n"), False),
        ("fix8-heredoc-c-squotedelim",
         run_wrap(GOOD, "cat <<'EOF'\n" + BAD + "\nEOF\n"), False),
        ("fix8-heredoc-c-escapedelim",
         run_wrap(GOOD, "cat <<\\EOF\n" + BAD + "\nEOF\n"), False),
        ("fix8-heredoc-c-space",
         run_wrap(GOOD, "cat << EOF\n" + BAD + "\nEOF\n"), False),
        ("fix8-heredoc-shell-escapedelim",
         run2(GOOD, "python3 <<\\EOF\nimport subprocess\nEOF"), False),
        ("fix8-heredoc-nested",
         run_wrap(GOOD, 'sh -c "python3 <<EOF\nprint(1)\nEOF\n"'), False),
        ("fix8-heredoc-free-herestring",
         wrap(GOOD + " && cat <<< hello"), True),
        ("fix8-heredoc-shell-herestring-refused",
         run(GOOD + " && cat <<< hello"), False),
        ("fix8-heredoc-free-squote",
         run(GOOD + " && echo 'a << b'"), True),
        ("fix8-heredoc-free-escape",
         run(GOOD + " && echo \\<\\<y"), True),
        ("fix8-err-unterminated-dquote",
         run2(GOOD, 'echo "oops'), False),
        ("fix8-err-unterminated-squote",
         run2(GOOD, "echo 'oops"), False),
        ("fix8-err-escaped-quote",
         run2(GOOD, 'echo "a\\"'), False),
        ("fix8-err-trailing-backslash-literal",
         wrap(GOOD + " && echo foo\\"), True),
    ]
    for name, body, expect in cases:
        got = f6_only_binary_ok(body)
        check_fix8(name, got == expect,
                   f"shell tokenization -> {got} (want {expect})")

    return bad


def self_test_fix9() -> int:
    """Fix-round-9 durable regression (codex re-review #8, 2 Lows):
    pip global-option normalization grounded in pip's real parser
    (installed pip 26.2.1 `general_group` + `parse_command` oracle
    probes) — every implemented global in both polarities
    (flagged-alone passes proving evaluation + `found`, never
    blanket refusal; unflagged-behind-globals trips), value-eats-
    subcommand skips, dangling values refused, unrecognized global
    shapes refused (per-command options in global position —
    including global `--require-hashes`/`--no-binary`, which pip
    itself rejects — plus unknown flags, abbreviations pip would
    accept, bad clusters, `=` on bare flags), `--help`/`-h`
    immediate skips and `--version`/`-V` post-parse skips (neither
    trips nor counts toward `found`); attached `-mpip` recognition
    (spaced/attached/path/`-c`/global-combination forms both
    polarities) with pip-concealing python shapes refused (options
    before `-m`, `-mpip3`, `-c`-with-args); and
    expansion-before-skip ordering (every executable substitution
    trips before ANY skip/consume decision: `command -v`/`-V`
    `$()`/backquote, bare and useful `env -u`/`-C`/`-S`/`--chdir`
    values, `exec -a` values, skipped non-pip heads — including the
    backstop-blind `-mpip` inner — nested substitutions, and
    content-blind flagged-inner refusal), with the preserved
    non-executing shapes still skipping (`-v` on plain text,
    `$HOME`/`${X}`/`$((...))` — parameter expansion and arithmetic
    never execute) and the real-stage substitution-free
    enumeration proving outright refusal cannot bite the checker
    stage. Synthetic checker stages (anchor-free)."""
    bad = 0

    def check_fix9(name, cond, detail):
        nonlocal bad
        print(f"{'ok' if cond else 'FAIL'}: selftest-{name}: {detail}")
        if not cond:
            bad += 1

    syn = "FROM ubuntu:26.04 AS checker\n"
    GOOD = "pip install --require-hashes --only-binary=:all: pkg"
    BAD = "pip install --require-hashes --no-binary=cffi pkg"
    GOODTAIL = "--require-hashes --only-binary=:all: pkg"
    BADTAIL = "--require-hashes --no-binary=cffi pkg"

    def wrap(script):
        return syn + "RUN " + json.dumps(["sh", "-c", script]) + "\n"

    def run(line):
        return syn + "RUN " + line + "\n"

    def run2(line1, line2):
        return syn + "RUN " + line1 + "\nRUN " + line2 + "\n"

    def run_wrap(line, script):
        return syn + "RUN " + line + "\nRUN " + json.dumps(["sh", "-c", script]) + "\n"

    # Every implemented general option × both polarities. Flagged
    # runs alone: True proves the install was EVALUATED (a skip
    # would starve `found`); unflagged pairs with a flagged GOOD:
    # False proves the trip (a skip would pass).
    prefixes = [
        ("q", "-q"), ("quiet", "--quiet"),
        ("v", "-v"), ("verbose", "--verbose"),
        ("qv", "-qv"), ("qqv", "-qqv"),
        ("isolated", "--isolated"), ("no-input", "--no-input"),
        ("debug", "--debug"),
        ("proxy-sp", "--proxy http://x"), ("proxy-eq", "--proxy=http://x"),
        ("retries-sp", "--retries 3"), ("retries-eq", "--retries=3"),
        ("timeout-sp", "--timeout 60"), ("timeout-eq", "--timeout=60"),
        ("default-timeout", "--default-timeout 60"),
        ("exists-action", "--exists-action w"),
        ("trusted-host", "--trusted-host h"),
        ("trusted-host-2", "--trusted-host h1 --trusted-host h2"),
        ("cert", "--cert c.pem"), ("client-cert", "--client-cert c.pem"),
        ("log-sp", "--log f.log"), ("log-file-eq", "--log-file=f"),
        ("local-log", "--local-log l"),
        ("cache-dir", "--cache-dir /tmp/c"),
        ("python", "--python /usr/bin/python3"),
        ("keyring", "--keyring-provider subprocess"),
        ("no-proxy-env", "--no-proxy-env"),
        ("no-cache-dir", "--no-cache-dir"),
        ("no-version-check", "--disable-pip-version-check"),
        ("no-color", "--no-color"),
        ("no-py-warn", "--no-python-version-warning"),
        ("use-feature", "--use-feature X"),
        ("use-deprecated", "--use-deprecated=Y"),
        ("resume-retries", "--resume-retries 2"),
        ("require-venv", "--require-virtualenv"),
        ("require-venv-short", "--require-venv"),
        ("dd", "--"),
        ("combined", "-q --isolated --proxy=http://x --retries 2"),
    ]
    cases = []
    for slug, prefix in prefixes:
        cases.append((f"fix9-global-{slug}-flagged",
                      run(f"pip {prefix} install {GOODTAIL}"), True))
        cases.append((f"fix9-global-{slug}-unflagged",
                      run2(GOOD, f"pip {prefix} install {BADTAIL}"), False))

    cases += [
        # A value option eats the next token even when it reads
        # `install` (pip's real parser does the same, then fails to
        # find its subcommand — nothing runs): skipped, never
        # tripped, never counted.
        ("fix9-global-value-eats-install",
         run2(GOOD, "pip --proxy install"), True),
        ("fix9-global-value-eats-install-starves",
         run("pip --proxy install"), False),
        ("fix9-global-value-eats-install-rest",
         run2(GOOD, "pip --proxy install pkg"), True),
        # Dangling value: pip errors; the gate refuses.
        ("fix9-global-dangling-value",
         run2(GOOD, "pip --proxy"), False),
        # Unrecognized global shapes: refused even with a flagged
        # install tail (False proves refusal, not evaluation).
        # Per-command options in global position (pip rejects every
        # one of these before the subcommand — oracle-verified),
        # unknown flags, an abbreviation pip WOULD accept (`--iso`
        # -> `--isolated`: refused fail-closed), bad short
        # clusters, and `=value` on bare flags.
        ("fix9-global-refuse-index-url",
         run2(GOOD, f"pip --index-url=https://x install {GOODTAIL}"), False),
        ("fix9-global-refuse-extra-index",
         run2(GOOD, f"pip --extra-index-url https://x install {GOODTAIL}"),
         False),
        ("fix9-global-refuse-no-index",
         run2(GOOD, f"pip --no-index install {GOODTAIL}"), False),
        ("fix9-global-refuse-find-links",
         run2(GOOD, f"pip --find-links /tmp/w install {GOODTAIL}"), False),
        ("fix9-global-refuse-require-hashes",
         run2(GOOD, f"pip --require-hashes install {GOODTAIL}"), False),
        ("fix9-global-refuse-no-binary",
         run2(GOOD, f"pip --no-binary=cffi install {GOODTAIL}"), False),
        ("fix9-global-refuse-only-binary",
         run2(GOOD, f"pip --only-binary=:all: install {GOODTAIL}"), False),
        ("fix9-global-refuse-bogus",
         run2(GOOD, f"pip --bogus install {GOODTAIL}"), False),
        ("fix9-global-refuse-abbrev",
         run2(GOOD, f"pip --iso install {GOODTAIL}"), False),
        ("fix9-global-refuse-cluster",
         run2(GOOD, f"pip -qX install {GOODTAIL}"), False),
        ("fix9-global-refuse-eq-noval",
         run2(GOOD, f"pip --isolated=x install {GOODTAIL}"), False),
        ("fix9-global-refuse-nocache-eq",
         run2(GOOD, f"pip --no-cache-dir=x install {GOODTAIL}"), False),
        # A lone `-` is a (bogus) subcommand, never an option: pip
        # errors unknown-command; the gate skips.
        ("fix9-global-lone-dash",
         run2(GOOD, f"pip - install {BADTAIL}"), True),
        # `--version`/`-V` exit after the parse, `--help`/`-h` at
        # parse position (oracle-verified): the install never runs,
        # so it neither trips (pairs True) nor counts (alone False).
        ("fix9-global-version-skip",
         run2(GOOD, f"pip --version install {BADTAIL}"), True),
        ("fix9-global-version-starves",
         run(f"pip --version install {GOODTAIL}"), False),
        ("fix9-global-V-skip",
         run2(GOOD, f"pip -V install {BADTAIL}"), True),
        ("fix9-global-V-starves",
         run(f"pip -V install {GOODTAIL}"), False),
        ("fix9-global-help-skip",
         run2(GOOD, f"pip --help install {BADTAIL}"), True),
        ("fix9-global-help-starves",
         run(f"pip --help install {GOODTAIL}"), False),
        ("fix9-global-h-skip",
         run2(GOOD, f"pip -h install {BADTAIL}"), True),
        ("fix9-global-h-starves",
         run(f"pip -h install {GOODTAIL}"), False),
        ("fix9-global-bare-version",
         run2(GOOD, "pip --version"), True),
        ("fix9-global-bare-pip",
         run2(GOOD, "pip"), True),
        ("fix9-global-other-subcommand",
         run2(GOOD, "pip download --no-binary=:all: pkg"), True),
        # Attached `-mpip`: evaluated exactly like `-m pip`, both
        # polarities, every layer.
        ("fix9-mpip-flagged",
         run(f"python3 -mpip install {GOODTAIL}"), True),
        ("fix9-mpip-unflagged",
         run2(GOOD, f"python3 -mpip install {BADTAIL}"), False),
        ("fix9-mpip-python",
         run(f"python -mpip install {GOODTAIL}"), True),
        ("fix9-mpip-path",
         run(f"/usr/bin/python3 -mpip install {GOODTAIL}"), True),
        ("fix9-mpip-globals-flagged",
         run(f"python3 -mpip -q --isolated install {GOODTAIL}"), True),
        ("fix9-mpip-globals-unflagged",
         run2(GOOD, f"python3 -mpip -q install {BADTAIL}"), False),
        ("fix9-mpip-c-flagged",
         wrap(f"python3 -mpip install {GOODTAIL}"), True),
        ("fix9-mpip-c-unflagged",
         run_wrap(GOOD, f"python3 -mpip install {BADTAIL}"), False),
        ("fix9-mpip-spaced-globals-flagged",
         run(f"python3 -m pip --isolated install {GOODTAIL}"), True),
        ("fix9-mpip-spaced-globals-unflagged",
         run2(GOOD, f"python3 -m pip -q install {BADTAIL}"), False),
        # Pip-concealing python shapes outside the modeled set are
        # refused even with flagged tails (False proves refusal).
        ("fix9-mpip-refuse-preopt",
         run2(GOOD, f"python3 -W ignore -m pip install {GOODTAIL}"), False),
        ("fix9-mpip-refuse-preopt-attached",
         run2(GOOD, f"python3 -Wignore -mpip install {GOODTAIL}"), False),
        ("fix9-mpip-refuse-mpip3",
         run2(GOOD, f"python3 -mpip3 install {GOODTAIL}"), False),
        ("fix9-mpip-refuse-preopt2",
         run2(GOOD, f"python3 -I -mpip install {GOODTAIL}"), False),
        ("fix9-mpip-refuse-c-args",
         run2(GOOD, f"python3 -c \"pass\" -m pip install {GOODTAIL}"), False),
        # Preserved non-pip / non-install python shapes.
        ("fix9-mpip-venv-skip",
         run2(GOOD, "python3 -m venv /opt/p11c"), True),
        ("fix9-mpip-pip-version-skip",
         run2(GOOD, "python3 -m pip --version"), True),
        # Exec-form layer: globals and `-mpip` evaluated, unknown
        # shapes refused.
        ("fix9-exec-global-flagged",
         syn + "RUN " + json.dumps(
             ["pip", "-q", "install", "--require-hashes",
              "--only-binary=:all:", "pkg"]) + "\n", True),
        ("fix9-exec-global-unflagged",
         syn + "RUN " + json.dumps(
             ["pip", "-q", "install", "--require-hashes",
              "--no-binary=cffi", "pkg"]) + "\n", False),
        ("fix9-exec-mpip-flagged",
         syn + "RUN " + json.dumps(
             ["python3", "-mpip", "install", "--require-hashes",
              "--only-binary=:all:", "pkg"]) + "\n", True),
        ("fix9-exec-mpip-unflagged",
         syn + "RUN " + json.dumps(
             ["python3", "-mpip", "install", "--require-hashes",
              "--no-binary=cffi", "pkg"]) + "\n", False),
        ("fix9-exec-global-refuse",
         syn + "RUN " + json.dumps(
             ["pip", "--bogus", "install", "--require-hashes",
              "--only-binary=:all:", "pkg"]) + "\n", False),
        ("fix9-exec-mpip-refuse-preopt",
         syn + "RUN " + json.dumps(
             ["python3", "-W", "ignore", "-m", "pip", "install",
              "--require-hashes", "--only-binary=:all:", "pkg"]) + "\n",
         False),
        # Expansion-before-skip: executable substitutions trip
        # before ANY skip/consume decision, wherever they sit.
        ("fix9-subst-cmd-v",
         run2(GOOD, f"command -v \"$({BAD})\"; true"), False),
        ("fix9-subst-cmd-V",
         run2(GOOD, f"command -V \"$({BAD})\"; true"), False),
        ("fix9-subst-cmd-backquote",
         run2(GOOD, f"command -v `{BAD}`; true"), False),
        ("fix9-subst-cmd-v-c",
         run_wrap(GOOD, f"command -v \"$({BAD})\""), False),
        ("fix9-subst-cmd-backquote-c",
         run_wrap(GOOD, f"command -v `{BAD}`"), False),
        ("fix9-subst-env-u-bare",
         run2(GOOD, f"env -u \"$({BAD})\""), False),
        ("fix9-subst-env-u-utility",
         run2(GOOD, f"env -u \"$({BAD})\" echo hi"), False),
        ("fix9-subst-env-u-pip",
         run2(GOOD, f"env -u \"$({BAD})\" {GOOD}"), False),
        ("fix9-subst-env-C-bare",
         run2(GOOD, f"env -C \"$({BAD})\""), False),
        ("fix9-subst-env-chdir-eq",
         run2(GOOD, f"env --chdir=\"$({BAD})\""), False),
        ("fix9-subst-env-S",
         run2(GOOD, f"env -S \"$({BAD})\""), False),
        ("fix9-subst-exec-a-bare",
         run2(GOOD, f"exec -a \"$({BAD})\""), False),
        ("fix9-subst-echo-mpip",
         run2(GOOD, "echo \"$(python3 -mpip install "
              "--require-hashes --no-binary=cffi pkg)\""), False),
        ("fix9-subst-echo-plain",
         run2(GOOD, f"echo \"$({BAD})\""), False),
        ("fix9-subst-nested",
         run2(GOOD, f"echo \"$(echo \"$({BAD})\")\""), False),
        # Refusal is content-blind: even a flagged inner trips (the
        # substitution's presence, not its flags, decides).
        ("fix9-subst-flagged-inner",
         run2(GOOD, f"command -v \"$({GOOD})\""), False),
        # The scan is quote/escape-blind fail-closed: an escaped
        # `$(` trips although dash would not execute it.
        ("fix9-subst-escaped",
         run2(GOOD, "echo \\$(echo hi)"), False),
        # Preserved non-executing shapes: `-v` on plain text, and
        # non-executable expansions (`$x`/`${x}` data, `$((...))`
        # arithmetic) still skip.
        ("fix9-subst-cmd-v-plain",
         run2(GOOD, "command -v pip"), True),
        ("fix9-subst-cmd-v-dollar",
         run2(GOOD, "command -v $HOME"), True),
        ("fix9-subst-env-u-plain",
         run2(GOOD, "env -u FOO"), True),
        ("fix9-subst-arith",
         run2(GOOD, "echo $((1+2))"), True),
        ("fix9-subst-param",
         run2(GOOD, "echo \"${X}\""), True),
    ]
    for name, body, expect in cases:
        got = f6_only_binary_ok(body)
        check_fix9(name, got == expect,
                   f"pip globals / substitution order -> {got} "
                   f"(want {expect})")

    # Real-stage enumeration: every checker-stage evaluated shell
    # text is substitution-free and no exec-form RUN exists there,
    # so outright executable-substitution refusal cannot bite the
    # real stage. (Stage split + payload strip mirror f6 exactly;
    # non-RUN lines pass through as scanned.)
    docker = (REPO / "docker" / "Dockerfile.demo").read_text()
    stage, phys = None, []
    logicals = []
    for raw in code_text(docker).splitlines():
        m = FROM_RE.match(raw)
        if m:
            for logical in _join_logicals(phys):
                logicals.append((stage, logical))
            phys = []
            stage = (m.group(1) or "").lower() or None
            continue
        phys.append(raw)
    for logical in _join_logicals(phys):
        logicals.append((stage, logical))
    shell_payloads = []
    exec_seen = False
    for _st, logical in [x for x in logicals if x[0] == "checker"]:
        payload = _strip_run_payload(logical)
        if RUN_LEAD_RE.match(logical):
            kind, _data = _run_payload_kind(payload)
            if kind != "shell":
                exec_seen = True
                continue
        shell_payloads.append(payload)
    marked = [p for p in shell_payloads
              if _CMD_SUBST_RE.search(p) or "`" in p]
    check_fix9("fix9-real-stage-subst-free",
               (not exec_seen) and not marked and len(shell_payloads) > 0,
               f"checker stage: {len(shell_payloads)} shell payloads, "
               "no exec/refused RUN, no executable-substitution markers")

    return bad


def self_test_fix10() -> int:
    """Fix-round-10 durable regression (codex re-review #9, 2 Lows):
    CPython short-option clusters resolving the module selector
    (grounded in CPython 3.14.7: `python3 --help` + exhaustive
    `-<ch>V` probes) — every bare short × attached `-mpip` in both
    polarities (flagged-alone passes proving evaluation + `found`,
    never blanket refusal; unflagged-behind-cluster trips),
    spaced-after-cluster values, pip-naming non-pip modules refused,
    unknown-short/long refusals, `-W`/`-X` opaque values, `-c`
    command-vs-CLI consistency, `--`/script termination,
    past-first-token `-m` clusters refused (the boundary-free hole
    the backstop cannot see), dangling refusals, exec-form shapes,
    and the real-stage python-line enumeration; and pip install
    option-value ownership (grounded in pip 26.2.1's install
    parser: per-option `takes_value()` dump + optparse probes) —
    EVERY value-taking install option × eats-flag trip / eats-data
    pass (separate and `=` spellings), bare flags eating nothing,
    `--` end-of-options, abbreviation refusals, `-h`/`--help`
    skips vs `-V`/`--version` evaluation, the hash-flag exclusion,
    dash-leading binary-control values refused, and the real
    install argv passing. Synthetic checker stages (anchor-free);
    every case carries its probe needle (applied-guard)."""
    bad = 0

    def check_fix10(name, cond, detail):
        nonlocal bad
        print(f"{'ok' if cond else 'FAIL'}: selftest-{name}: {detail}")
        if not cond:
            bad += 1

    syn = "FROM ubuntu:26.04 AS checker\n"
    GOOD = "pip install --require-hashes --only-binary=:all: pkg"
    BAD = "pip install --require-hashes --no-binary=cffi pkg"
    GOODTAIL = "--require-hashes --only-binary=:all: pkg"
    BADTAIL = "--require-hashes --no-binary=cffi pkg"

    def run(line):
        return syn + "RUN " + line + "\n"

    def run2(line1, line2):
        return syn + "RUN " + line1 + "\nRUN " + line2 + "\n"

    def run_wrap(line, script):
        return syn + "RUN " + line + "\nRUN " + json.dumps(["sh", "-c", script]) + "\n"

    # Pinned transcription of the pip 26.2.1 install-parser dump
    # (per-option `takes_value()`; `/tmp/sets10.txt` at fix time):
    # the behavior matrices below iterate THESE lists, and the
    # first control pins the implementation sets to them, so a
    # transcription slip fails loudly instead of going vacuous.
    VALUE_LONGS = (
        "--abi", "--all-releases", "--build-constraint", "--cache-dir",
        "--cert", "--client-cert", "--config-settings", "--constraint",
        "--default-timeout", "--editable", "--exists-action",
        "--extra-index-url", "--find-links", "--group", "--implementation",
        "--index-url", "--keyring-provider", "--local-log", "--log",
        "--log-file", "--no-binary", "--only-binary", "--only-final",
        "--platform", "--prefix", "--progress-bar", "--proxy", "--pypi-url",
        "--python", "--python-version", "--refresh-package", "--report",
        "--requirement", "--requirements-from-script", "--resume-retries",
        "--retries", "--root", "--root-user-action", "--source",
        "--source-dir", "--source-directory", "--src", "--target",
        "--timeout", "--trusted-host", "--upgrade-strategy",
        "--uploaded-prior-to", "--use-deprecated", "--use-feature",
    )
    BARE_LONGS = (
        "--break-system-packages", "--check-build-dependencies", "--compile",
        "--debug", "--disable-pip-version-check", "--dry-run",
        "--force-reinstall", "--help", "--ignore-installed",
        "--ignore-requires-python", "--isolated", "--no-build-isolation",
        "--no-cache-dir", "--no-clean", "--no-color", "--no-compile",
        "--no-dependencies", "--no-deps", "--no-index", "--no-input",
        "--no-proxy-env", "--no-python-version-warning",
        "--no-require-hashes", "--no-user", "--no-warn-conflicts",
        "--no-warn-script-location", "--only-dependencies", "--only-deps",
        "--pre", "--prefer-binary", "--quiet", "--require-hashes",
        "--require-venv", "--require-virtualenv", "--upgrade",
        "--use-pep517", "--user", "--verbose", "--version",
    )
    check_fix10("fix10-install-sets-pinned",
                 _PIP_INSTALL_VALUE_LONGS == set(VALUE_LONGS)
                 and _PIP_INSTALL_BARE_LONGS == set(BARE_LONGS)
                 and _PIP_INSTALL_VALUE_SHORTS == set("Ccefirt")
                 and _PIP_INSTALL_BARE_SHORTS == set("IUVhqv")
                 and len(VALUE_LONGS) == 49 and len(BARE_LONGS) == 39,
                 "install grammar pinned to the pip 26.2.1 dump")
    check_fix10("fix10-python-shorts-pinned",
                 _PY_BARE_SHORTS == set("bdhiqstuvxBEIOPRSV?")
                 and _PY_VALUE_SHORTS == set("cmWX"),
                 "CPython shorts pinned to the 3.14 probe classification")

    cases = []
    # Cluster matrix: every bare short × attached -mpip, both
    # polarities. Flagged runs alone: True proves the install was
    # EVALUATED (a skip would starve `found`); unflagged pairs
    # with a flagged GOOD: False proves the trip (a skip would
    # pass). (`-Vmpip`/`-hmpip`/`-?mpip` evaluate conservatively:
    # CPython would print+exit, the gate evaluates fail-closed.)
    for ch in "bdhiqstuvxBEIOPRSV?":
        cases.append((f"fix10-cluster-{ch}-flagged",
                      run(f"python3 -{ch}mpip install {GOODTAIL}"),
                      True, f"-{ch}mpip"))
        cases.append((f"fix10-cluster-{ch}-unflagged",
                      run2(GOOD, f"python3 -{ch}mpip install {BADTAIL}"),
                      False, f"-{ch}mpip"))

    cases += [
        # Spaced value after a cluster (`-um pip`, `-Bum pip`).
        ("fix10-cluster-spaced-flagged",
         run(f"python3 -um pip install {GOODTAIL}"), True, "-um pip"),
        ("fix10-cluster-spaced-unflagged",
         run2(GOOD, f"python3 -um pip install {BADTAIL}"), False, "-um pip"),
        ("fix10-cluster-spaced2-flagged",
         run(f"python3 -Bum pip install {GOODTAIL}"), True, "-Bum pip"),
        ("fix10-cluster-spaced2-unflagged",
         run2(GOOD, f"python3 -Bum pip install {BADTAIL}"),
         False, "-Bum pip"),
        # Pip-naming non-pip modules refuse (flagged tails prove
        # refusal, not evaluation).
        ("fix10-cluster-refuse-umpip3",
         run2(GOOD, f"python3 -umpip3 install {GOODTAIL}"), False, "-umpip3"),
        ("fix10-cluster-refuse-m-eq-pip",
         run2(GOOD, f"python3 -m=pip install {GOODTAIL}"), False, "-m=pip"),
        ("fix10-cluster-refuse-mpipx",
         run2(GOOD, f"python3 -mpipx install {GOODTAIL}"), False, "-mpipx"),
        ("fix10-cluster-refuse-spaced-pip3",
         run2(GOOD, f"python3 -um pip3 install {GOODTAIL}"), False, "pip3"),
        ("fix10-cluster-refuse-past-pip3",
         run2(GOOD, f"python3 -u -m pip3 install {GOODTAIL}"),
         False, "-m pip3"),
        # Historical `-m pip3` at index 1 keeps EVALUATING (round 9
        # preservation: flagged passes, unflagged trips).
        ("fix10-cluster-spaced-pip3-flagged",
         run(f"python3 -m pip3 install {GOODTAIL}"), True, "-m pip3"),
        ("fix10-cluster-spaced-pip3-unflagged",
         run2(GOOD, f"python3 -m pip3 install {BADTAIL}"), False, "-m pip3"),
        # Unknown shorts refuse — pip-concealing tails and clean.
        ("fix10-py-refuse-z",
         run2(GOOD, f"python3 -z -m pip install {GOODTAIL}"), False, "-z"),
        ("fix10-py-refuse-J",
         run2(GOOD, f"python3 -J -m pip install {GOODTAIL}"), False, "-J"),
        ("fix10-py-refuse-o",
         run2(GOOD, f"python3 -o -m pip install {GOODTAIL}"), False, "-o"),
        ("fix10-py-refuse-a",
         run2(GOOD, f"python3 -a -m pip install {GOODTAIL}"), False, "-a"),
        ("fix10-py-refuse-0",
         run2(GOOD, f"python3 -0 -m pip install {GOODTAIL}"), False, "-0"),
        ("fix10-py-refuse-z-clean",
         run2(GOOD, "python3 -z --version"), False, "-z"),
        # Unknown longs refuse (CPython takes no abbreviations).
        ("fix10-py-refuse-bogus-long",
         run2(GOOD, f"python3 --bogus -m pip install {GOODTAIL}"),
         False, "--bogus"),
        ("fix10-py-refuse-abbrev",
         run2(GOOD, f"python3 --check -m pip install {GOODTAIL}"),
         False, "--check"),
        ("fix10-py-refuse-quiet-long",
         run2(GOOD, f"python3 --quiet -m pip install {GOODTAIL}"),
         False, "--quiet"),
        ("fix10-py-refuse-version-eq",
         run2(GOOD, "python3 --version=x -V"), False, "--version=x"),
        ("fix10-py-refuse-pycs-eq",
         run2(GOOD, "python3 --check-hash-based-pycs=always -V"),
         False, "--check-hash-based-pycs="),
        ("fix10-py-pycs-spaced-clean",
         run2(GOOD, "python3 --check-hash-based-pycs always -V"),
         True, "--check-hash-based-pycs always"),
        ("fix10-py-pycs-spaced-refuse",
         run2(GOOD, "python3 --check-hash-based-pycs always"
              f" -m pip install {GOODTAIL}"), False,
         "--check-hash-based-pycs always"),
        ("fix10-py-pycs-dangling",
         run2(GOOD, "python3 --check-hash-based-pycs"), False,
         "--check-hash-based-pycs"),
        # Help longs are recognized bare (skip when pip-free).
        ("fix10-py-long-help", run2(GOOD, "python3 --help"), True, "--help"),
        ("fix10-py-long-version",
         run2(GOOD, "python3 --version"), True, "--version"),
        ("fix10-py-long-help-env",
         run2(GOOD, "python3 --help-env"), True, "--help-env"),
        ("fix10-py-long-help-xoptions",
         run2(GOOD, "python3 --help-xoptions"), True, "--help-xoptions"),
        ("fix10-py-long-help-all",
         run2(GOOD, "python3 --help-all"), True, "--help-all"),
        # -W/-X values opaque, attached and spaced.
        ("fix10-py-W-attached",
         run2(GOOD, "python3 -Wignore -V"), True, "-Wignore"),
        ("fix10-py-X-attached",
         run2(GOOD, "python3 -Xdev -V"), True, "-Xdev"),
        ("fix10-py-W-spaced",
         run2(GOOD, "python3 -W ignore -V"), True, "-W ignore"),
        ("fix10-py-X-spaced",
         run2(GOOD, "python3 -X dev -V"), True, "-X dev"),
        ("fix10-py-W-cluster",
         run2(GOOD, "python3 -uWignore -V"), True, "-uWignore"),
        ("fix10-py-X-past-m-refuse",
         run2(GOOD, f"python3 -X dev -m pip install {GOODTAIL}"),
         False, "-X dev"),
        # -c consistency: a COMMAND, never the pip CLI — the shell
        # backstop trips on a pip mention, silence skips.
        ("fix10-py-c-cluster-pip",
         run2(GOOD, 'python3 -uc "import pip"'), False, '-uc "import pip"'),
        ("fix10-py-c-cluster-clean",
         run2(GOOD, 'python3 -uc "print(1)"'), True, '-uc "print(1)"'),
        ("fix10-py-c-past-pip",
         run2(GOOD, 'python3 -u -c "import pip"'), False, '-c "import pip"'),
        ("fix10-py-c-dangling",
         run2(GOOD, "python3 -c"), False, "python3 -c"),
        # `--` ends options; a script stops parsing.
        ("fix10-py-dd-pip",
         run2(GOOD, f"python3 -- -m pip install {GOODTAIL}"), False, "-- -m"),
        ("fix10-py-dd-clean",
         run2(GOOD, "python3 -- script.py"), True, "-- script.py"),
        ("fix10-py-dd-bare", run2(GOOD, "python3 --"), True, "python3 --"),
        ("fix10-py-script-clean",
         run2(GOOD, "python3 script.py"), True, "script.py"),
        ("fix10-py-script-pip",
         run2(GOOD, f"python3 script.py -m pip install {GOODTAIL}"),
         False, "script.py -m"),
        ("fix10-py-stdin", run2(GOOD, "python3 -"), True, "python3 -"),
        # Past-first-token -m shapes refuse EVEN flagged (the
        # boundary-free hole: `-u -umpip` is invisible to the
        # mention backstop, so resolution must refuse it).
        ("fix10-py-past-cluster-flagged",
         run2(GOOD, f"python3 -u -umpip install {GOODTAIL}"),
         False, "-u -umpip"),
        ("fix10-py-past-cluster-unflagged",
         run2(GOOD, f"python3 -u -umpip install {BADTAIL}"),
         False, "-u -umpip"),
        ("fix10-py-past-cluster2",
         run2(GOOD, f"python3 -q -Bmpip install {GOODTAIL}"),
         False, "-q -Bmpip"),
        ("fix10-py-past-spaced",
         run2(GOOD, f"python3 -u -m pip install {GOODTAIL}"),
         False, "-u -m pip"),
        ("fix10-py-past-venv-skip",
         run2(GOOD, "python3 -u -m venv x"), True, "-u -m venv"),
        # Dangling remainder-consumers refuse (CPython rc 2 each).
        ("fix10-py-dangling-m", run2(GOOD, "python3 -m"), False, "python3 -m"),
        ("fix10-py-dangling-W", run2(GOOD, "python3 -W"), False, "python3 -W"),
        ("fix10-py-dangling-X", run2(GOOD, "python3 -X"), False, "python3 -X"),
        ("fix10-py-dangling-um",
         run2(GOOD, "python3 -um"), False, "python3 -um"),
        # Non-pip attached module without a pip name skips.
        ("fix10-py-mm-skip", run2(GOOD, "python3 -mm"), True, "-mm"),
        # Real-stage python lines keep their verdicts (skip).
        ("fix10-py-real-venv",
         run2(GOOD, "python3 -m venv /opt/p11c"), True, "-m venv"),
        ("fix10-py-real-version",
         run2(GOOD, "python3 --version"), True, "python3 --version"),
        # Exec-form layer: clusters evaluated, past shapes refused.
        ("fix10-exec-cluster-flagged",
         syn + "RUN " + json.dumps(
             ["python3", "-umpip", "install", "--require-hashes",
              "--only-binary=:all:", "pkg"]) + "\n", True, "-umpip"),
        ("fix10-exec-cluster-unflagged",
         syn + "RUN " + json.dumps(
             ["python3", "-umpip", "install", "--require-hashes",
              "--no-binary=cffi", "pkg"]) + "\n", False, "-umpip"),
        ("fix10-exec-past-cluster",
         syn + "RUN " + json.dumps(
             ["python3", "-u", "-umpip", "install", "--require-hashes",
              "--only-binary=:all:", "pkg"]) + "\n", False, "-umpip"),
        # -c layer: clusters evaluated there too.
        ("fix10-c-cluster-flagged",
         syn + "RUN " + json.dumps(
             ["sh", "-c", f"python3 -umpip install {GOODTAIL}"]) + "\n",
         True, "-umpip"),
        ("fix10-c-cluster-unflagged",
         run_wrap(GOOD, f"python3 -umpip install {BADTAIL}"),
         False, "-umpip"),
    ]

    # Install-ownership matrix: EVERY value-taking long × separate-
    # eats-flag trip / separate-eats-data pass / `=`-eats-flag trip.
    for opt in VALUE_LONGS:
        slug = opt[2:]
        cases.append((f"fix10-vl-{slug}-sep-trip",
                      run2(GOOD, "pip install " + opt +
                           " --only-binary=:all: --require-hashes pkg"),
                      False, opt + " --only-binary"))
        cases.append((f"fix10-vl-{slug}-sep-pass",
                      run("pip install " + opt +
                          " somedata --require-hashes --only-binary=:all:"
                          " pkg"), True, opt + " somedata"))
        cases.append((f"fix10-vl-{slug}-eq-trip",
                      run2(GOOD, "pip install " + opt +
                           "=--only-binary=:all: --require-hashes pkg"),
                      False, opt + "=--only-binary"))

    # `--opt=` empty values: data, never flags (the binary-control
    # pair's empty value is a no-op event, so the real flag still
    # decides beside it).
    for opt in ("--target", "--requirement", "--config-settings",
                "--proxy", "--index-url"):
        cases.append((f"fix10-vl-{opt[2:]}-eq-empty",
                      run("pip install " + opt +
                          "= --require-hashes --only-binary=:all: pkg"),
                      True, opt + "="))
    cases.append(("fix10-vl-only-binary-eq-empty",
                  run("pip install --only-binary= --require-hashes"
                      " --only-binary=:all: pkg"), True, "--only-binary="))
    cases.append(("fix10-vl-no-binary-eq-empty",
                  run("pip install --no-binary= --require-hashes"
                      " --only-binary=:all: pkg"), True, "--no-binary="))

    # Bare longs eat NOTHING: the following flags stay effective
    # (`--help` and `--no-require-hashes` have their own semantics
    # and are covered separately below).
    for opt in BARE_LONGS:
        if opt in ("--help", "--no-require-hashes"):
            continue
        cases.append((f"fix10-bl-{opt[2:]}-eats-nothing",
                      run("pip install " + opt + " " + GOODTAIL),
                      True, opt + " "))

    # Value shorts: separate and attached × trip / pass.
    for ch in "Ccefirt":
        data = "k=v" if ch == "C" else "somedata"
        cases.append((f"fix10-vs-{ch}-sep-trip",
                      run2(GOOD, f"pip install -{ch} --only-binary=:all:"
                           " --require-hashes pkg"), False, f"-{ch} --only"))
        cases.append((f"fix10-vs-{ch}-sep-pass",
                      run(f"pip install -{ch} {data} " + GOODTAIL),
                      True, f"-{ch} {data}"))
        cases.append((f"fix10-vs-{ch}-att-trip",
                      run2(GOOD, f"pip install -{ch}--only-binary=:all:"
                           " --require-hashes pkg"), False, f"-{ch}--only"))
        cases.append((f"fix10-vs-{ch}-att-pass",
                      run(f"pip install -{ch}{data} " + GOODTAIL),
                      True, f"-{ch}{data}"))

    # Bare shorts eat nothing (`-h` skips; covered below).
    for ch in "IUVqv":
        cases.append((f"fix10-bs-{ch}-eats-nothing",
                      run(f"pip install -{ch} " + GOODTAIL), True, f"-{ch} "))

    cases += [
        # `-r` interplay audit: at install position `-r` takes the
        # requirements FILE (the evaluator never reads its value —
        # flags-only model); `-r --only-binary=:all:` eats the flag
        # as the filename AND leaves no effective restriction, so
        # the gate trips on the missing `:all:` (pip itself would
        # then fail opening that file — fail-closed in reality too).
        ("fix10-r-eats-flag",
         run2(GOOD, "pip install -r --only-binary=:all:"
              " --require-hashes pkg"), False, "-r --only-binary"),
        # `--` ends options: everything after is a requirement.
        ("fix10-dd-eats-flag",
         run2(GOOD, "pip install --require-hashes -- --only-binary=:all:"
              " pkg"), False, "-- --only-binary"),
        ("fix10-dd-eats-all",
         run2(GOOD, "pip install -- --require-hashes --only-binary=:all:"
              " pkg"), False, "install -- --require"),
        ("fix10-dd-flags-before-count",
         run("pip install --require-hashes --only-binary=:all:"
             " -- --no-binary=:all: pkg"), True, "-- --no-binary"),
        # ... but `--` itself is consumable as a value.
        ("fix10-dd-as-value",
         run2(GOOD, "pip install --target -- pkg"), False, "--target -- "),
        # Abbreviations refuse (pip would accept the unambiguous
        # ones — same fail-closed policy as round 9).
        ("fix10-abbrev-targ",
         run2(GOOD, "pip install --targ /tmp/x " + GOODTAIL),
         False, "--targ "),
        ("fix10-abbrev-iso",
         run2(GOOD, "pip install --iso " + GOODTAIL), False, "--iso "),
        ("fix10-abbrev-req",
         run2(GOOD, "pip install --req f " + GOODTAIL), False, "--req "),
        ("fix10-abbrev-ver",
         run2(GOOD, "pip install --ver " + GOODTAIL), False, "--ver "),
        # Unrecognized install shapes refuse, even flagged.
        ("fix10-install-refuse-bogus",
         run2(GOOD, "pip install --bogus " + GOODTAIL), False, "--bogus"),
        ("fix10-install-refuse-new-pip-opt",
         run2(GOOD, "pip install --bogus-new-opt " + GOODTAIL),
         False, "--bogus-new-opt"),
        ("fix10-install-refuse-short",
         run2(GOOD, "pip install -z " + GOODTAIL), False, " -z "),
        ("fix10-install-refuse-digit",
         run2(GOOD, "pip install -1 " + GOODTAIL), False, " -1 "),
        ("fix10-install-refuse-eq-bare",
         run2(GOOD, "pip install --no-input=x " + GOODTAIL),
         False, "--no-input=x"),
        ("fix10-install-refuse-eq-bare2",
         run2(GOOD, "pip install --force-reinstall= " + GOODTAIL),
         False, "--force-reinstall="),
        ("fix10-install-refuse-eq-hashes",
         run2(GOOD, "pip install --require-hashes=x "
              "--only-binary=:all: pkg"), False, "--require-hashes=x"),
        ("fix10-install-refuse-dangling",
         run2(GOOD, "pip install --require-hashes --only-binary=:all:"
              " --target"), False, " --target"),
        ("fix10-install-refuse-dangling-r",
         run2(GOOD, "pip install --require-hashes --only-binary=:all:"
              " -r"), False, " -r"),
        ("fix10-install-refuse-dangling-only",
         run2(GOOD, "pip install --require-hashes --only-binary"),
         False, "--only-binary"),
        # `-h`/`--help` skip (pip exits 0 at parse position):
        # paired passes, alone starves.
        ("fix10-help-skip",
         run2(GOOD, "pip install --help --require-hashes"
              " --no-binary=cffi pkg"), True, "--help "),
        ("fix10-help-starves",
         run("pip install --help " + GOODTAIL), False, "--help "),
        ("fix10-h-skip",
         run2(GOOD, "pip install -h --require-hashes --no-binary=cffi"
              " pkg"), True, " -h "),
        ("fix10-h-starves",
         run("pip install -h " + GOODTAIL), False, " -h "),
        ("fix10-help-late-skip",
         run2(GOOD, "pip install pkg --help"), True, "pkg --help"),
        # `-V`/`--version` EVALUATE at install position (the
        # install proceeds — unlike the main parser).
        ("fix10-version-eval",
         run("pip install --version " + GOODTAIL), True, "--version "),
        ("fix10-version-eval-unflagged",
         run2(GOOD, "pip install --version " + BADTAIL), False, "--version "),
        ("fix10-V-eval",
         run("pip install -V " + GOODTAIL), True, " -V "),
        ("fix10-V-eval-unflagged",
         run2(GOOD, "pip install -V " + BADTAIL), False, " -V "),
        # Hash-flag exclusion: pip errors when both are effective.
        ("fix10-hash-exclusion",
         run2(GOOD, "pip install --require-hashes --no-require-hashes"
              " --only-binary=:all: pkg"), False, "--no-require-hashes"),
        ("fix10-hash-exclusion-rev",
         run2(GOOD, "pip install --no-require-hashes --require-hashes"
              " --only-binary=:all: pkg"), False, "--no-require-hashes"),
        ("fix10-hash-no-only",
         run2(GOOD, "pip install --no-require-hashes --only-binary=:all:"
              " pkg"), False, "--no-require-hashes"),
        # Dash-leading binary-control values refuse (pip's
        # handle_mutual_excludes guard: without it the first case
        # would evaluate `:all:` present and pass).
        ("fix10-dashval-only-sep",
         run2(GOOD, "pip install --require-hashes --only-binary"
              " -:all:,:all: pkg"), False, "--only-binary -:"),
        ("fix10-dashval-only-eq",
         run2(GOOD, "pip install --require-hashes"
              " --only-binary=-:all:,:all: pkg"), False, "--only-binary=-"),
        ("fix10-dashval-no",
         run2(GOOD, "pip install --require-hashes --only-binary=:all:"
              " --no-binary -x pkg"), False, "--no-binary -x"),
        # The real install argv stays passing (exact stage line).
        ("fix10-real-install-argv",
         run("/opt/p11c/bin/pip install --no-input --require-hashes "
             "--only-binary=:all: -r /tmp/checker-requirements.txt"),
         True, "--no-input --require-hashes"),
    ]

    for name, body, expect, needle in cases:
        applied = needle in body
        got = f6_only_binary_ok(body)
        check_fix10(name, applied and got == expect,
                    f"value ownership / clusters -> {got} (want {expect})")

    # Direct module-resolution units (grounding spot-checks).
    check_fix10("fix10-unit-umpip",
                 _resolve_python_module(
                     ["python3", "-umpip", "install", "x"])
                 == ("pip", ["pip", "install", "x"]),
                 "first-token cluster resolves to the pip head")
    check_fix10("fix10-unit-past-cluster",
                 _resolve_python_module(
                     ["python3", "-u", "-umpip", "install", "x"])
                 == ("refuse", []),
                 "past-first-token cluster refuses")
    check_fix10("fix10-unit-venv",
                 _resolve_python_module(
                     ["python3", "-m", "venv", "/opt/p11c"])
                 == ("other", ["venv", "/opt/p11c"]),
                 "historical -m-first payload preserved")
    check_fix10("fix10-unit-version",
                 _resolve_python_module(["python3", "--version"])
                 == ("other", ["python3", "--version"]),
                 "bare long resolves to other")

    # Real-stage enumeration: the checker stage's python-bearing
    # payloads are exactly the known two lines (venv build +
    # `--version` stamp), so the new refusals cannot bite them —
    # and the stage itself stays passing.
    docker = (REPO / "docker" / "Dockerfile.demo").read_text()
    stage, phys = None, []
    logicals = []
    for raw in code_text(docker).splitlines():
        m = FROM_RE.match(raw)
        if m:
            for logical in _join_logicals(phys):
                logicals.append((stage, logical))
            phys = []
            stage = (m.group(1) or "").lower() or None
            continue
        phys.append(raw)
    for logical in _join_logicals(phys):
        logicals.append((stage, logical))
    shell_payloads = []
    for _st, logical in [x for x in logicals if x[0] == "checker"]:
        payload = _strip_run_payload(logical)
        if RUN_LEAD_RE.match(logical):
            kind, _data = _run_payload_kind(payload)
            if kind != "shell":
                continue
        shell_payloads.append(payload)
    py_payloads = [p for p in shell_payloads if "python3" in p]
    check_fix10("fix10-real-stage-python-enum",
                 len(py_payloads) == 1
                 and "-m venv /opt/p11c" in py_payloads[0]
                 and "python3 --version" in py_payloads[0]
                 and len(shell_payloads) > 0,
                 f"checker stage: {len(shell_payloads)} shell payloads, "
                 "exactly the venv + --version python lines")
    check_fix10("fix10-real-stage-passing",
                 f6_only_binary_ok(docker),
                 "checker stage still evaluates wheel-only passing")

    return bad


def self_test_fix11() -> int:
    """Fix-round-11 durable regression (codex re-review #10, 1 Low):
    boundary-free `-mpip` clusters behind skipped compound heads.
    After `;`-splitting the fragment head is `then`/`do`/`(`/...,
    so module resolution never runs — and `-umpip` has NO pip-word
    boundary, so the mention regex missed it (both the `-umpip`
    spelling and the plain `-mpip` one). The backstop now trips on
    ANY fragment carrying a module-selector cluster regardless of
    argv[0] — outright refusal (even a flagged tail behind a
    compound head trips; the real stage is cluster-free, so the
    refusal cannot bite it). Cluster spellings x compound forms
    (each trips), flagged-behind-compound refusal polarity,
    re-joined forms behind compound heads, spaced `-m pip` still
    tripping via the mention regex, `!`-negation, function-def and
    trap trip-on-definition decisions (a definition runs nothing
    until called, but static analysis cannot know the call set —
    the real stage defines/traps nothing, so refusal is free),
    `&&`/`||` second-branch evaluation (split heads still
    evaluate, both polarities), documented over-trip locks
    (`-mpip3`/`-umpipx`/`-Wmpip`: CPython runs no pip there,
    oracle-verified — the gate trips anyway, fail closed), the
    same-hole `env -S` cluster, and the real-stage
    cluster-pattern zero-hit proof (guards future drift).
    Synthetic checker stages (anchor-free); every case carries
    its probe needle (applied-guard)."""
    bad = 0

    def check_fix11(name, cond, detail):
        nonlocal bad
        print(f"{'ok' if cond else 'FAIL'}: selftest-{name}: {detail}")
        if not cond:
            bad += 1

    syn = "FROM ubuntu:26.04 AS checker\n"
    GOOD = "pip install --require-hashes --only-binary=:all: pkg"
    BADTAIL = "--require-hashes --no-binary=cffi pkg"
    GOODTAIL = "--require-hashes --only-binary=:all: pkg"

    def run(line):
        return syn + "RUN " + line + "\n"

    def run2(line1, line2):
        return syn + "RUN " + line1 + "\nRUN " + line2 + "\n"

    # Compound forms wrapping an unsafe cluster install: each must
    # trip (False proves the backstop trip — a skip would pass).
    # Every form below was dash-probe-verified to dispatch its body.
    forms = [
        ("if-then", "if true; then %s; fi"),
        ("if-else", "if false; then echo x; else %s; fi"),
        ("if-elif", "if false; then echo x; elif true; then %s; fi"),
        ("for-do", "for i in 1; do %s; done"),
        ("while-do", "while true; do %s; break; done"),
        ("until-do", "until false; do %s; break; done"),
        ("case", "case x in a) %s;; esac"),
        ("subshell", "(%s)"),
        ("subshell-sp", "( %s )"),
        ("group", "{ %s; }"),
        ("negation", "! %s"),
        ("funcdef", "f() { %s; }"),
        ("trap", "trap '%s' EXIT"),
    ]
    cases = []
    for slug, tmpl in forms:
        for cl in ("-mpip", "-umpip", "-Bumpip"):
            cases.append((f"fix11-{slug}-{cl[1:]}",
                          run2(GOOD, tmpl % (
                              f"python3 {cl} install {BADTAIL}")),
                          False, cl))
    # One more bare-short variant (representative, not exhaustive —
    # fix-10 pins the full short set at head position).
    cases.append(("fix11-if-then-qmpip",
                  run2(GOOD, "if true; then python3 -qmpip install "
                       + BADTAIL + "; fi"), False, "-qmpip"))
    # The codex verbatim repro (absolute interpreter path + full
    # unsafe tail) trips behind `then`.
    cases.append(("fix11-codex-verbatim",
                  run2(GOOD, "if true; then /opt/p11c/bin/python3 -umpip "
                       "install --require-hashes --no-binary=cffi "
                       "--force-reinstall -r /tmp/checker-requirements.txt"
                       "; fi"), False, "-umpip"))
    # Flagged tail behind a compound head STILL trips: the cluster
    # backstop is outright refusal, not evaluation (each form one
    # representative cluster).
    for slug, tmpl in forms:
        cases.append((f"fix11-refuse-flagged-{slug}",
                      run2(GOOD, tmpl % (
                          f"python3 -umpip install {GOODTAIL}")),
                      False, "-umpip"))

    cases += [
        # Re-joined spellings behind compound heads: shlex rejoins
        # before the backstop, so the mention regex trips.
        ("fix11-rejoin-then-dquote",
         run2(GOOD, 'if true; then p"i"p install ' + BADTAIL + "; fi"),
         False, 'p"i"p'),
        ("fix11-rejoin-do-dquote",
         run2(GOOD, 'for i in 1; do p"i"p install ' + BADTAIL + "; done"),
         False, 'p"i"p'),
        ("fix11-rejoin-subshell-dquote",
         run2(GOOD, '(p"i"p install ' + BADTAIL + ")"), False, 'p"i"p'),
        ("fix11-rejoin-then-escape",
         run2(GOOD, "if true; then p\\ip install " + BADTAIL + "; fi"),
         False, "p\\ip"),
        ("fix11-rejoin-negation",
         run2(GOOD, '! p"i"p install ' + BADTAIL), False, 'p"i"p'),
        # Re-joined + flagged behind `then` still trips (mention
        # backstop refuses outright — polarity lock).
        ("fix11-rejoin-flagged-then",
         run2(GOOD, 'if true; then p"i"p install ' + GOODTAIL + "; fi"),
         False, 'p"i"p'),
        # Spaced `-m pip` / `-um pip` behind compound heads: the
        # spaced `pip` word trips via the mention regex (no cluster
        # needed) — flagged tails refuse likewise.
        ("fix11-spaced-m-pip-then",
         run2(GOOD, "if true; then python3 -m pip install "
              + BADTAIL + "; fi"), False, "-m pip"),
        ("fix11-spaced-m-pip-flagged-then",
         run2(GOOD, "if true; then python3 -m pip install "
              + GOODTAIL + "; fi"), False, "-m pip"),
        ("fix11-spaced-um-pip-do",
         run2(GOOD, "for i in 1; do python3 -um pip install "
              + BADTAIL + "; done"), False, "-um pip"),
        # `&&`/`||` split first, so a cluster in the second branch
        # keeps its python head and EVALUATES (both polarities —
        # unflagged trips, flagged-alone passes proving `found`).
        ("fix11-or-branch-unflagged",
         run2(GOOD, "false || python3 -umpip install " + BADTAIL),
         False, "|| python3 -umpip"),
        ("fix11-or-branch-flagged",
         run("true || python3 -umpip install " + GOODTAIL),
         True, "|| python3 -umpip"),
        ("fix11-and-branch-unflagged",
         run2(GOOD, "true && python3 -umpip install " + BADTAIL),
         False, "&& python3 -umpip"),
        ("fix11-and-branch-flagged",
         run("true && python3 -umpip install " + GOODTAIL),
         True, "&& python3 -umpip"),
        # `&&` inside a skipped head: the second fragment keeps its
        # own python head and evaluates (unflagged trips).
        ("fix11-and-inside-then-unflagged",
         run2(GOOD, "if true; then echo a && python3 -umpip install "
              + BADTAIL + "; fi"), False, "&& python3 -umpip"),
        # Negation of a clean command passes (the `!` head alone is
        # not refused); negation of plain pip trips via mention.
        ("fix11-negation-clean",
         run2(GOOD, "! echo hi"), True, "! echo"),
        ("fix11-negation-pip",
         run2(GOOD, "! pip install " + BADTAIL), False, "! pip"),
        # Function-def / trap of clean bodies pass (the definition
        # heads alone are not refused); the unsafe-cluster variants
        # trip per the matrix above (trip-on-definition: the body
        # runs only when called, but the call set is unknowable).
        ("fix11-funcdef-clean",
         run2(GOOD, "f() { echo hi; }"), True, "f() {"),
        ("fix11-trap-clean",
         run2(GOOD, "trap 'echo hi' EXIT"), True, "trap 'echo"),
        # Same-hole `env -S` value: env splits it into the executed
        # argv, so a cluster inside trips via `_mentions_pip` too.
        ("fix11-env-S-cluster",
         run2(GOOD, 'env -S"python3 -umpip install ' + BADTAIL + '"'),
         False, '-S"python3 -umpip'),
        # Documented over-trips (CPython oracle: `-mpip3`/`-umpipx`
        # die with "No module named", `-Wmpip` eats `mpip` as its
        # warning value and runs no pip — the gate trips anyway,
        # fail closed; flagged tails prove refusal, not evaluation).
        ("fix11-over-mpip3",
         run2(GOOD, "if true; then python3 -mpip3 install "
              + GOODTAIL + "; fi"), False, "-mpip3"),
        ("fix11-over-umpipx",
         run2(GOOD, "if true; then python3 -umpipx install "
              + GOODTAIL + "; fi"), False, "-umpipx"),
        ("fix11-over-Wmpip",
         run2(GOOD, "if true; then python3 -Wmpip install "
              + GOODTAIL + "; fi"), False, "-Wmpip"),
    ]

    for name, body, expect, needle in cases:
        applied = needle in body
        got = f6_only_binary_ok(body)
        check_fix11(name, applied and got == expect,
                    f"cluster backstop -> {got} (want {expect})")

    # Direct backstop units (grounding spot-checks).
    check_fix11("fix11-unit-cluster-then",
                 _mentions_pip(["then", "python3", "-umpip", "install", "x"]),
                 "cluster token trips behind a skipped head")
    check_fix11("fix11-unit-cluster-over",
                 _mentions_pip(["then", "python3", "-mpip3", "x"]),
                 "over-trip spelling trips too")
    check_fix11("fix11-unit-clean-group",
                 not _mentions_pip(["{", "echo", "hi"]),
                 "clean group-head fragment stays silent")
    check_fix11("fix11-unit-apt-tokens",
                 not _mentions_pip(["apt-get", "install", "-y",
                                    "python3", "python3-venv",
                                    "python3-pip", "opensc"]),
                 "apt `python3-pip` package stays silent under both patterns")

    # Real-stage proof: zero cluster-pattern hits over every
    # post-shlex token of every checker-stage shell payload, no
    # function definitions, no traps — so outright refusal and
    # trip-on-definition cannot bite the real stage — and the
    # stage itself stays passing.
    docker = (REPO / "docker" / "Dockerfile.demo").read_text()
    stage, phys = None, []
    logicals = []
    for raw in code_text(docker).splitlines():
        m = FROM_RE.match(raw)
        if m:
            for logical in _join_logicals(phys):
                logicals.append((stage, logical))
            phys = []
            stage = (m.group(1) or "").lower() or None
            continue
        phys.append(raw)
    for logical in _join_logicals(phys):
        logicals.append((stage, logical))
    cluster_hits, funcdefs, traps, npayloads = 0, 0, 0, 0
    for _st, logical in [x for x in logicals if x[0] == "checker"]:
        payload = _strip_run_payload(logical)
        if RUN_LEAD_RE.match(logical):
            kind, _data = _run_payload_kind(payload)
            if kind != "shell":
                continue
        npayloads += 1
        if re.search(r"\(\)", payload):
            funcdefs += 1
        if re.search(r"(?<![A-Za-z0-9_])trap(?![A-Za-z0-9_])", payload):
            traps += 1
        for shell_line in _shell_logical_lines(payload):
            parts, err = split_shell_commands(shell_line, True)
            if err is not None:
                continue
            for frag in parts:
                try:
                    toks = shlex.split(frag, posix=True)
                except ValueError:
                    continue
                cluster_hits += sum(1 for t in toks
                                    if _PIP_CLUSTER_RE.search(t))
    check_fix11("fix11-real-stage-zero-hit",
                 npayloads > 0 and cluster_hits == 0 and funcdefs == 0
                 and traps == 0,
                 f"checker stage: {npayloads} shell payloads, "
                 f"{cluster_hits} cluster hits, {funcdefs} funcdefs, "
                 f"{traps} traps")
    check_fix11("fix11-real-stage-passing",
                 f6_only_binary_ok(docker),
                 "checker stage still evaluates wheel-only passing")

    return bad


def self_test_fix12() -> int:
    """Fix-round-12 durable regression (codex re-review #11, 1 NEW
    Low + the P18 stage hole found while grounding it): the
    Dockerfile physical continuation join, grounded in REAL `docker
    build` probes on BOTH builders (BuildKit via the default
    docker-driver builder + the classic legacy builder, Docker
    29.8.1). Both builders agree on ALL 15 shared union shapes
    (zero disagreement, so no union-refusals): rstrip, splice iff
    EXACTLY ONE trailing backslash (runs of 2+ never splice),
    PURE concatenation (round 8's added space was wrong — the
    codex mid-word bypass), verbatim next line (leading ws kept,
    trailing ws-after-backslash stripped, ws-before kept),
    comment/blank skip-through, any-line consumption (even FROM —
    stages split on LOGICAL lines), EOF dangle drops, CRLF==LF,
    `# escape=` switches the escape char. Mid-word splits of the
    executable path, bare head, flag names and flag values (both
    polarities — flagged-alone passes prove evaluation, never
    blanket refusal); trailing-space/tab splice; multi-backslash
    non-splice (incl. locked pass-on-unbuildable where the builder
    rejects); dangling-FROM stage capture both directions; comment
    (bare/indented) and blank splits; directive/lone-CR/exotic-ws
    refusals (+ narrowness guards); CRLF evaluation; the exact-join
    sweep (27 probe oracles, string equality, zero dangerous
    direction); and the real-stage proof (passing, refusal-free,
    15/15 token-boundary continuations enumerated, old-vs-new
    token identity). Synthetic checker stages (anchor-free); every
    f6 case carries its probe needle (applied-guard)."""
    bad = 0

    def check_fix12(name, cond, detail):
        nonlocal bad
        print(f"{'ok' if cond else 'FAIL'}: selftest-{name}: {detail}")
        if not cond:
            bad += 1

    syn = "FROM ubuntu:26.04 AS checker\n"
    GOOD = "pip install --require-hashes --only-binary=:all: pkg"
    GOODRUN = "RUN " + GOOD + "\n"
    BADTAIL = "--require-hashes --no-binary=cffi pkg"
    FULLBAD = ("--require-hashes --no-binary=cffi --force-reinstall"
               " -r /tmp/checker-requirements.txt")

    def run(line):
        return syn + "RUN " + line + "\n"

    def run2(line1, line2):
        return syn + "RUN " + line1 + "\nRUN " + line2 + "\n"

    cases = [
        # The codex verbatim bypass: executable path split mid-word
        # across a continuation (P01: pure concatenation).
        ("fix12-codex-verbatim",
         syn + GOODRUN + "RUN /opt/p11c/bin/p\\\nip install "
         + FULLBAD + "\n", False, "/opt/p11c/bin/p\\\nip"),
        ("fix12-head-split-bare",
         syn + GOODRUN + "RUN p\\\nip install " + BADTAIL + "\n",
         False, "RUN p\\\nip"),
        # Flagged-alone behind a mid-word split PASSES: the gate
        # evaluates the reassembled head (found), never blanket
        # refuses (polarity proof).
        ("fix12-head-split-flagged-alone",
         syn + "RUN /opt/p11c/bin/p\\\nip install --require-hashes"
         " --only-binary=:all: pkg\n", True, "bin/p\\\nip"),
        # Indented continuation after a mid-word split keeps its gap
        # (P02): broken path, gate skips — and the builder fails the
        # build on the same bytes (no such executable). Locked pass
        # on unbuildable (safe direction, documented).
        ("fix12-head-split-indented-passes-unbuildable",
         syn + GOODRUN + "RUN /opt/p11c/bin/p\\\n    ip install "
         + BADTAIL + "\n", True, "bin/p\\\n    ip"),
        # Durable checker-stage regression (codex explicitly
        # requires it): a realistic multi-line checker RUN with the
        # pip path split mid-word and an unsafe tail trips.
        ("fix12-checker-stage-name-split",
         syn + GOODRUN
         + "RUN apt-get update && apt-get install -y python3 \\\n"
         "    && python3 -m venv /opt/p11c \\\n"
         "    && /opt/p11c/bin/p\\\n"
         "ip install " + FULLBAD + "\n", False, "bin/p\\\nip"),
        # Flag NAME split mid-word, both polarities.
        ("fix12-flagname-split-unflagged",
         run2(GOOD, "pip install --require-hashes --no-bin\\\nary=cffi"
              " pkg"), False, "--no-bin\\\nary"),
        ("fix12-flagname-split-flagged",
         run("pip install --require-hashes --only-bin\\\nary=:all:"
             " pkg"), True, "--only-bin\\\nary"),
        # Flag VALUE split mid-word, both polarities; the `:none:`
        # reassembly trip proves evaluation (a skip would pass).
        ("fix12-flagval-split-all",
         run("pip install --require-hashes --only-binary=:al\\\nl:"
             " pkg"), True, "=:al\\\nl:"),
        ("fix12-flagval-split-none",
         run2(GOOD, "pip install --require-hashes --only-binary=:all:"
              " --only-binary=:no\\\nne: pkg"), False, "=:no\\\nne:"),
        ("fix12-flagval-split-nobin",
         run2(GOOD, "pip install --require-hashes --only-binary=:all:"
              " --no-binary=cf\\\nfi pkg"), False, "=cf\\\nfi"),
        # Trailing spaces/tabs AFTER the backslash are stripped
        # first — the splice still happens (P03/P13).
        ("fix12-trailspace-splice-trip",
         syn + GOODRUN + "RUN /opt/p11c/bin/p\\   \nip install "
         + BADTAIL + "\n", False, "bin/p\\   \nip"),
        ("fix12-trailspace-splice-pass",
         syn + "RUN pip install --require-hashes --only-binary=:all:"
         " pk\\   \ng\n", True, "pk\\   \ng"),
        ("fix12-trailtab-splice-trip",
         syn + GOODRUN + "RUN /opt/p11c/bin/p\\\t\nip install "
         + BADTAIL + "\n", False, "bin/p\\\t\nip"),
        ("fix12-trailtab-splice-pass",
         syn + "RUN pip install --require-hashes --only-binary=:all:"
         " p\\\t\nkg\n", True, "p\\\t\nkg"),
        # Spaces BEFORE the backslash are kept (P04): still a token
        # boundary, flags evaluate normally.
        ("fix12-prespace-kept-trip",
         run2(GOOD, "pip install --require-hashes   \\\n"
              " --no-binary=cffi pkg"), False,
         "--require-hashes   \\\n"),
        # Multi-backslash runs NEVER splice (P07/P08/P19): the next
        # line is a new instruction and evaluates on its own.
        ("fix12-evenrun-nosplice",
         syn + GOODRUN + "RUN echo ab\\\\\nRUN pip install "
         + BADTAIL + "\n", False, "ab\\\\\nRUN"),
        ("fix12-triplerun-nosplice",
         syn + GOODRUN + "RUN echo ab\\\\\\\nRUN pip install "
         + BADTAIL + "\n", False, "ab\\\\\\\nRUN"),
        ("fix12-quadrun-nosplice",
         syn + GOODRUN + "RUN echo ab\\\\\\\\\nRUN pip install "
         + BADTAIL + "\n", False, "ab\\\\\\\\\nRUN"),
        # Odd-3 run after a head prefix: no splice, so the gate sees
        # a broken head plus a headless fragment and passes — while
        # the builder fails the build on the same bytes (argv[0]
        # ending in `\` never exists). Locked pass on unbuildable
        # (safe direction, documented).
        ("fix12-odd3-midword-nosplice-passes-unbuildable",
         syn + GOODRUN + "RUN /opt/p11c/bin/pi\\\\\\\np install "
         + BADTAIL + "\n", True, "bin/pi\\\\\\\np"),
        # A dangling backslash eats even a FROM line (P18): the
        # stage does NOT switch (logical-line staging).
        ("fix12-dangle-eats-from",
         "FROM ubuntu:26.04 AS checker\n" + GOODRUN
         + "RUN echo a \\\nFROM ubuntu:26.04 AS other\n"
         "RUN pip install " + BADTAIL + "\n", False,
         "a \\\nFROM ubuntu:26.04 AS other"),
        # ...in the other direction the checker stage never comes
        # into being, so nothing is found (trip).
        ("fix12-dangle-eats-checker-from",
         "FROM ubuntu:26.04 AS base\nRUN echo a \\\n"
         "FROM ubuntu:26.04 AS checker\nRUN " + GOOD + "\n", False,
         "a \\\nFROM ubuntu:26.04 AS checker"),
        # A dangling backslash at EOF just drops (P14).
        ("fix12-dangle-eof",
         syn + "RUN pip install --require-hashes --only-binary=:all:"
         " pkg \\\n", True, "pkg \\\n"),
        # Comment lines (bare or indented) do NOT break a
        # continuation (P06/P25) — the flags after one still join.
        ("fix12-comment-split-head",
         syn + GOODRUN + "RUN /opt/p11c/bin/p\\\n# sneaky\nip install "
         + BADTAIL + "\n", False, "# sneaky\nip"),
        ("fix12-comment-split-flags",
         run2(GOOD, "pip install --require-hashes --only-binary=:all:"
              " pkg \\\n# c\n --no-binary=cffi"), False,
         "# c\n --no-binary"),
        ("fix12-comment-indented-split",
         run2(GOOD, "pip install --require-hashes --only-binary=:all:"
              " pkg \\\n   # c\n --no-binary=cffi"), False,
         "   # c\n --no-binary"),
        ("fix12-comment-split-flagged-alone",
         syn + "RUN pip install --require-hashes \\\n# c\n"
         " --only-binary=:all: pkg\n", True, "# c\n --only-binary"),
        # Blank / whitespace-only lines likewise (P15/P29).
        ("fix12-blank-split-head",
         syn + GOODRUN + "RUN /opt/p11c/bin/p\\\n\nip install "
         + BADTAIL + "\n", False, "bin/p\\\n\nip"),
        ("fix12-blank-split-flagged-alone",
         syn + "RUN pip install --require-hashes \\\n\n"
         " --only-binary=:all: pkg\n", True,
         "--require-hashes \\\n\n"),
        ("fix12-wsonly-split",
         syn + GOODRUN + "RUN /opt/p11c/bin/p\\\n   \nip install "
         + BADTAIL + "\n", False, "\\\n   \nip"),
        # Parser-directive refusals: every honored spelling (P10a/
        # P21/P23/P24), the late position the builder ignores (P22
        # — refused anyway, documented superset), `syntax`, and a
        # backtick-continuation shape (P10a).
        ("fix12-directive-escape",
         "# escape=`\n" + syn + GOODRUN, False, "# escape=`"),
        ("fix12-directive-escape-nospace",
         "#escape=`\n" + syn + GOODRUN, False, "#escape=`"),
        ("fix12-directive-escape-upper",
         "# ESCAPE=`\n" + syn + GOODRUN, False, "# ESCAPE=`"),
        ("fix12-directive-escape-leading-ws",
         "  # escape=`\n" + syn + GOODRUN, False, "  # escape=`"),
        ("fix12-directive-escape-late",
         syn + GOODRUN + "# escape=`\n", False,
         "RUN " + GOOD + "\n# escape=`"),
        ("fix12-directive-syntax",
         "# syntax=docker/dockerfile:1\n" + syn + GOODRUN, False,
         "# syntax="),
        ("fix12-directive-backtick-shape",
         "# escape=`\nFROM ubuntu:26.04 AS checker\nRUN " + GOOD
         + "\nRUN echo a `\n echo b\n", False, "RUN echo a `"),
        # Narrowness guard: the word without `=` is a plain comment.
        ("fix12-directive-word-without-eq",
         "# the escape hatch is closed\n" + syn + GOODRUN, True,
         "escape hatch"),
        # Lone CR refused (P31); CRLF pairs evaluate exactly (P09).
        ("fix12-lone-cr-refused",
         syn + GOODRUN + "RUN echo a\rb\n", False, "a\rb"),
        ("fix12-lone-cr-eof",
         syn + GOODRUN + "RUN echo hi\r", False, "hi\r"),
        ("fix12-crlf-evaluates",
         "FROM ubuntu:26.04 AS checker\r\nRUN " + GOOD + "\r\n",
         True, "\r\nRUN"),
        ("fix12-crlf-split-reassembles",
         "FROM ubuntu:26.04 AS checker\r\nRUN " + GOOD + "\r\n"
         "RUN /opt/p11c/bin/p\\\r\nip install " + BADTAIL + "\r\n",
         False, "p\\\r\nip"),
        ("fix12-crlf-flagged-split-alone",
         "FROM ubuntu:26.04 AS checker\r\nRUN /opt/p11c/bin/p\\\r\n"
         "ip install --require-hashes --only-binary=:all: pkg\r\n",
         True, "p\\\r\nip"),
        # Exotic trailing whitespace refused (strip-set gap); inner
        # exotic whitespace stays data (narrowness guard).
        ("fix12-exotic-trailing-emspace",
         syn + "RUN " + GOOD + "\u2003\n", False, "\u2003"),
        ("fix12-exotic-nbsp-after-backslash",
         syn + GOODRUN + "RUN echo a\\u00a0\nRUN pip install "
         + BADTAIL + "\n", False, "\\u00a0\nRUN"),
        ("fix12-exotic-inner-nbsp-data",
         run2(GOOD, "echo \"a\u00a0b\""), True, "a\u00a0b"),
        # Continued exec-JSON skips comments too (P26b): flagged
        # alone passes, proving evaluation.
        ("fix12-exec-comment-join",
         syn + 'RUN ["pip", "install", \\\n# c\n "--require-hashes",'
         ' "--only-binary=:all:", "pkg"]\n', True,
         "# c\n \"--require-hashes"),
        # A continued FROM is one logical (P28): the gate scans it
        # as shell text and the pip mention trips (the builder
        # rejects its arity — agree-trip).
        ("fix12-continued-from",
         syn + GOODRUN + "FROM ubuntu:26.04 AS other \\\n"
         "RUN pip install " + BADTAIL + "\n", False,
         "AS other \\\nRUN"),
    ]
    for name, body, expect, needle in cases:
        applied = needle in body
        got = f6_only_binary_ok(body)
        check_fix12(name, applied and got == expect,
                    f"physical join -> {got} (want {expect})")

    # Differential sweep: EXACT joined text per probe oracle (the
    # harness mirrors the pipeline — comment strip, then join).
    # Builder-error shapes (P07/P08/P19/P28) join exactly too; only
    # instruction validation differs (the builder rejects — nothing
    # executes, so no dangerous direction). N = 27.
    def joined(phys):
        return _join_logicals([strip_comment(l) for l in phys])

    sweep = [
        ("sweep-p00",
         ["RUN printf 'P00:[%s]\\n' ab cd"],
         ["RUN printf 'P00:[%s]\\n' ab cd"]),
        ("sweep-p01",
         ["RUN printf 'P01:[%s]\\n' ab\\", "cd"],
         ["RUN printf 'P01:[%s]\\n' abcd"]),
        ("sweep-p02",
         ["RUN printf 'P02:[%s]\\n' ab\\", "   cd"],
         ["RUN printf 'P02:[%s]\\n' ab   cd"]),
        ("sweep-p03",
         ["RUN printf 'P03:[%s]\\n' ab\\   ", "cd"],
         ["RUN printf 'P03:[%s]\\n' abcd"]),
        ("sweep-p04",
         ["RUN printf 'P04:[%s]\\n' ab   \\", "cd"],
         ["RUN printf 'P04:[%s]\\n' ab   cd"]),
        ("sweep-p05",
         ["RUN echo P05-result:hello \\", "ENV FOO=bar"],
         ["RUN echo P05-result:hello ENV FOO=bar"]),
        ("sweep-p06",
         ["RUN echo P06a \\", "# just a comment", " echo P06b"],
         ["RUN echo P06a  echo P06b"]),
        ("sweep-p07",
         ["RUN printf 'P07:[%s]\\n' ab\\\\", "cd"],
         ["RUN printf 'P07:[%s]\\n' ab\\\\", "cd"]),
        ("sweep-p08",
         ["RUN printf 'P08:[%s]\\n' ab\\\\\\", "cd"],
         ["RUN printf 'P08:[%s]\\n' ab\\\\\\", "cd"]),
        ("sweep-p09",
         ["RUN printf 'P09:[%s]\\n' ab\\\r", "cd\r"],
         ["RUN printf 'P09:[%s]\\n' abcd"]),
        ("sweep-p11",
         ["RUN printf 'P11:[%s]\\n' ab\\", "\tcd"],
         ["RUN printf 'P11:[%s]\\n' ab\tcd"]),
        ("sweep-p12",
         ['RUN ["echo", "P12a\\', '   P12b"]'],
         ['RUN ["echo", "P12a   P12b"]']),
        ("sweep-p13",
         ["RUN printf 'P13:[%s]\\n' ab\\\t", "cd"],
         ["RUN printf 'P13:[%s]\\n' abcd"]),
        ("sweep-p14",
         ["RUN echo P14done \\"],
         ["RUN echo P14done "]),
        ("sweep-p15",
         ["RUN echo P15a \\", "", "echo P15b"],
         ["RUN echo P15a echo P15b"]),
        ("sweep-p16",
         ["RUN printf 'P16:[%s]\\n' a\\", "b\\", "c"],
         ["RUN printf 'P16:[%s]\\n' abc"]),
        ("sweep-p17",
         ["RUN echo P17a \\", "\\", "echo P17b"],
         ["RUN echo P17a echo P17b"]),
        ("sweep-p18",
         ["RUN echo P18a \\", "FROM ubuntu:26.04 AS checker"],
         ["RUN echo P18a FROM ubuntu:26.04 AS checker"]),
        ("sweep-p19",
         ["RUN printf 'P19:[%s]\\n' ab\\\\\\\\", "cd"],
         ["RUN printf 'P19:[%s]\\n' ab\\\\\\\\", "cd"]),
        ("sweep-p20",
         ["RUN echo P20a", "\\", "RUN echo P20b"],
         ["RUN echo P20a", "RUN echo P20b"]),
        ("sweep-p25",
         ["RUN echo P25a \\", "   # indented comment", " echo P25b"],
         ["RUN echo P25a  echo P25b"]),
        ("sweep-p26b",
         ['RUN ["echo", \\', "# comment", '"hi"]'],
         ['RUN ["echo", "hi"]']),
        ("sweep-p28",
         ["FROM ubuntu:26.04 AS checker \\", "RUN echo P28hi"],
         ["FROM ubuntu:26.04 AS checker RUN echo P28hi"]),
        ("sweep-p29",
         ["RUN echo P29a \\", "   ", " echo P29b"],
         ["RUN echo P29a  echo P29b"]),
        ("sweep-p30",
         ["RUN printf 'P30:[%s]\\n' ab\\\x0bcd"],
         ["RUN printf 'P30:[%s]\\n' ab\\\x0bcd"]),
        # P32: the join passes NUL through; BOTH builders fail at
        # exec (`invalid argument`) — nothing executes (documented).
        ("sweep-p32",
         ["RUN echo P32a\x00b"],
         ["RUN echo P32a\x00b"]),
        # P33: the harness pre-cuts the trailing comment (old
        # pipeline behavior, kept); the builder rejects FROM arity
        # — gate-pass on unbuildable, safe direction (documented).
        ("sweep-p33",
         ["FROM ubuntu:26.04 # hello"],
         ["FROM ubuntu:26.04"]),
    ]
    nagree = 0
    for name, phys, expected in sweep:
        got = joined(phys)
        if got == expected:
            nagree += 1
        check_fix12("fix12-" + name, got == expected,
                    f"oracle join -> {got!r}")
    check_fix12("fix12-sweep-agreement", nagree == len(sweep) == 27,
                f"{nagree}/{len(sweep)} probe oracles agree exactly")

    # Direct join / refusal / staging units.
    check_fix12("fix12-unit-join-single",
                 _join_logicals(["a\\", "b"]) == ["ab"],
                 "single backslash splices with pure concat")
    check_fix12("fix12-unit-join-lone",
                 _join_logicals(["\\", "RUN echo hi"])
                 == ["RUN echo hi"],
                 "lone-backslash line splices with empty")
    check_fix12("fix12-unit-join-even",
                 _join_logicals(["a\\\\", "b"]) == ["a\\\\", "b"],
                 "even run never splices")
    check_fix12("fix12-unit-join-odd3",
                 _join_logicals(["a\\\\\\", "b"]) == ["a\\\\\\", "b"],
                 "odd-3 run never splices (round-8 parity was wrong)")
    check_fix12("fix12-unit-refuse-escape",
                 bool(_docker_physical_refused("# escape=`\nFROM x\n")),
                 "escape directive refuses")
    check_fix12("fix12-unit-refuse-late",
                 bool(_docker_physical_refused("FROM x\n# escape=`\n")),
                 "late directive refuses too (superset lock)")
    check_fix12("fix12-unit-refuse-syntax",
                 bool(_docker_physical_refused(
                     "# syntax=docker/dockerfile:1\n")),
                 "syntax directive refuses")
    check_fix12("fix12-unit-refuse-lone-cr",
                 bool(_docker_physical_refused("RUN echo a\rb\n")),
                 "lone CR refuses")
    check_fix12("fix12-unit-clean-crlf",
                 _docker_physical_refused("FROM x\r\nRUN echo hi\r\n")
                 is None,
                 "CRLF pair stays clean")
    check_fix12("fix12-unit-clean-inner-nbsp",
                 _docker_physical_refused("RUN echo \"a\u00a0b\"\n") is None,
                 "inner NBSP stays data")
    check_fix12("fix12-unit-refuse-exotic",
                 bool(_docker_physical_refused("RUN echo hi\u2003\n")),
                 "exotic trailing ws refuses")
    check_fix12("fix12-unit-stage-logical",
                 _docker_stage_logicals(
                     "FROM x AS base\nRUN echo a \\\n"
                     "FROM x AS checker\nRUN echo hi\n")
                 == ([("base", "RUN echo a FROM x AS checker"),
                      ("base", "RUN echo hi")], None),
                 "consumed FROM does not switch stage")
    # Real-stage proof: passing, refusal-free, physical/logical FROM
    # agreement, every continuation enumerated at a token boundary
    # (a mid-word junction fails LOUDLY), and old-vs-new token
    # identity per checker logical.
    docker = (REPO / "docker" / "Dockerfile.demo").read_text()
    check_fix12("fix12-real-stage-passing",
                 f6_only_binary_ok(docker),
                 "checker stage still evaluates wheel-only passing")
    struct, why = _docker_stage_logicals(docker)
    nodirect = not any(_DOCKER_DIRECTIVE_RE.match(l)
                       for l in docker.split("\n"))
    nocr = "\r" not in docker
    noexotic = all(
        (l[:-1] if l.endswith("\r") else l).rstrip(" \t")
        == (l[:-1] if l.endswith("\r") else l).rstrip()
        for l in docker.split("\n"))
    check_fix12("fix12-real-stage-no-refusal",
                 why is None and nodirect and nocr and noexotic,
                 f"no directive/lone-CR/exotic-ws ({why})")
    raw_lines = docker.split("\n")
    stripped = [strip_comment(l) for l in raw_lines]
    phys_froms = [((m.group(1) or "").lower() or None)
                  for m in (FROM_RE.match(l) for l in stripped)
                  if m]
    log_froms = [((m.group(1) or "").lower() or None)
                 for m in (FROM_RE.match(l)
                           for l in _join_logicals(stripped))
                 if m]
    check_fix12("fix12-real-stage-from-physical",
                 phys_froms == log_froms
                 == ["proxy", "checker", "runtime"],
                 f"physical/logical FROMs agree: {log_froms}")
    # Checker physical span (valid: FROMs are single physical lines
    # per the control above — no continuation touches one).
    from_idx = [i for i, l in enumerate(stripped)
                if FROM_RE.match(l)]
    check_fix12("fix12-real-stage-three-stages",
                 len(from_idx) == 3,
                 f"three physical FROMs ({len(from_idx)})")
    checker_lines = ([(i, raw_lines[i])
                      for i in range(from_idx[1] + 1, from_idx[2])]
                     if len(from_idx) == 3 else [])
    junctions, loud, midcont_blank = [], [], []
    is_open, prev_line = False, ""
    for i, l in checker_lines:
        code = strip_comment(l)
        if not code.strip():
            if is_open:
                midcont_blank.append(i + 1)
            continue
        s = code.rstrip()
        splices = s.endswith("\\") and not s.endswith("\\\\")
        if is_open:
            junctions.append((i, prev_line, l))
            ps = prev_line.rstrip()
            if not ((len(ps) >= 2 and ps[-2] in " \t")
                    or l[:1] in " \t"):
                loud.append(i + 1)
        is_open, prev_line = splices, l
    for i, prev, nxt in junctions:
        print(f"      junction L{i}->L{i + 1}: "
              f"{prev.rstrip()[-28:]!r} + {nxt[:28]!r}")
    check_fix12("fix12-real-stage-continuation-enum",
                 len(junctions) == 15 and not loud
                 and not midcont_blank,
                 f"15/15 token-boundary junctions, mid-word={loud}, "
                 f"midcont-blank={midcont_blank}")

    def _legacy_join(lines):
        out, buf = [], ""
        for raw in lines:
            s = raw.rstrip()
            trailing = len(s) - len(s.rstrip("\\"))
            if trailing % 2 == 1:
                buf += s[:-1] + " "
            else:
                buf += s
                out.append(buf)
                buf = ""
        if buf.strip():
            out.append(buf)
        return out

    checker_codes = [strip_comment(l) for _, l in checker_lines]
    old_logs = [l for l in _legacy_join(checker_codes) if l.strip()]
    new_logs = [l for l in _join_logicals(checker_codes) if l.strip()]
    tok_bad, shlex_bad = [], []
    if len(old_logs) != len(new_logs):
        tok_bad.append(f"count {len(old_logs)}!={len(new_logs)}")
    for a, b in zip(old_logs, new_logs):
        try:
            ta, tb = shlex.split(a, posix=True), shlex.split(b, posix=True)
        except ValueError as e:
            shlex_bad.append(str(e))
            continue
        if ta != tb:
            tok_bad.append(f"{a!r:.60} vs {b!r:.60}")
    check_fix12("fix12-real-stage-join-identity",
                 not tok_bad and not shlex_bad and len(new_logs) > 0,
                 f"{len(new_logs)} checker logicals tokenize "
                 f"identically ({tok_bad + shlex_bad})")
    return bad


def self_test_fix13() -> int:
    """Fix-round-13 durable regression (codex re-review #12, 1 NEW
    Low): inline-comment continuations consuming FROM. The old
    pipeline ran the YAML `strip_comment` on Dockerfile physical
    lines BEFORE joining, deleting the trailing backslash of
    `RUN echo ok # \\` — the gate saw a stage boundary where
    BuildKit splices and consumes the FROM into the RUN logical.
    Grounded in REAL `docker build` probes Q1–Q10 (BuildKit v0.33.0,
    default docker-driver builder, base ubuntu:26.04, --no-cache;
    bad-image oracle — a stage boundary pulls
    `127.0.0.1:1/fix13-nonexistent:latest` and fails, a consumed
    FROM builds): Q1 inline `# \\` eats FROM (rc 0; the build log
    shows ONE `RUN echo ok # FROM ...` step); Q2/Q9 no-backslash
    inline `#` (plain/quoted) is a real boundary (rc 1, bad pull);
    Q3 blank + bare + indented comment chain consumed (rc 0); Q4
    quoted `"a # b" \\` splices (rc 0); Q5 glued `ok#\\` splices
    (rc 0); Q6 non-trailing `\\` is a boundary (rc 1); Q7 `\\\\`
    run never splices (rc 1); Q10 trailing-comment FROM rejected
    by the builder (`FROM requires either one or three arguments`
    — nothing executes). Codex verbatim + full-file fixture trips;
    both polarities per probe shape (unsafe-behind trips,
    flagged-alone passes proving evaluation); round-12 full-line
    shapes preserved; stage-attribution units; real-stage immunity
    (passing + per-line old-vs-new mapping identity + checker `#`
    enumeration). Synthetic checker stages (anchor-free); every f6
    case carries its probe needle (applied-guard)."""
    bad = 0

    def check_fix13(name, cond, detail):
        nonlocal bad
        print(f"{'ok' if cond else 'FAIL'}: selftest-{name}: {detail}")
        if not cond:
            bad += 1

    syn = "FROM ubuntu:26.04 AS checker\n"
    GOOD = "pip install --require-hashes --only-binary=:all: pkg"
    GOODRUN = "RUN " + GOOD + "\n"
    BADTAIL = "--require-hashes --no-binary=cffi pkg"
    OTHER = "FROM ubuntu:26.04 AS other\n"

    def run2(line1, line2):
        return syn + "RUN " + line1 + "\nRUN " + line2 + "\n"

    fullfile = (
        "# header comment\n"
        "FROM ubuntu:26.04 AS proxy\n"
        "RUN echo proxy-ok\n"
        "FROM ubuntu:26.04 AS checker\n"
        + GOODRUN +
        "RUN echo ok # \\\n"
        + OTHER +
        "RUN /opt/p11c/bin/pip install " + BADTAIL + "\n"
        "FROM ubuntu:26.04 AS runtime\n"
        "COPY --from=checker /x /y\n")

    cases = [
        # The codex verbatim bypass (Q1): the unsafe install stays
        # in checker and trips.
        ("fix13-codex-verbatim",
         syn + GOODRUN + "RUN echo ok # \\\n" + OTHER
         + "RUN /opt/p11c/bin/pip install " + BADTAIL + "\n",
         False, "echo ok # \\\nFROM"),
        # Full-file in-memory fixture variant (codex): header
        # comments, three more stages — still trips.
        ("fix13-codex-fullfile", fullfile, False,
         "echo ok # \\\nFROM ubuntu:26.04 AS other"),
        # Intervening blank + bare + indented comment chain (Q3).
        ("fix13-chain-blank-comment-from",
         syn + GOODRUN + "RUN echo ok # \\\n\n# full\n"
         "   # indented\n" + OTHER + "RUN pip install " + BADTAIL
         + "\n", False, "# indented\nFROM"),
        # ...in the other direction the checker stage never comes
        # into being, so nothing is found (trip).
        ("fix13-comment-eats-checker-from",
         "FROM ubuntu:26.04 AS base\nRUN echo ok # \\\n"
         "FROM ubuntu:26.04 AS checker\nRUN " + GOOD + "\n", False,
         "ok # \\\nFROM ubuntu:26.04 AS checker"),
        # Flagged-alone behind the splice PASSES: the install stays
        # in checker and evaluates (found) — polarity proof.
        ("fix13-flagged-alone-stays",
         syn + "RUN echo ok # \\\n" + OTHER + "RUN " + GOOD + "\n",
         True, "echo ok # \\\nFROM"),
        # Inline comment WITHOUT backslash is a genuine boundary
        # (Q2): the unsafe install is really in `other`, out of
        # scope — pass.
        ("fix13-plain-comment-is-boundary",
         syn + GOODRUN + "RUN echo ok # plain\n" + OTHER
         + "RUN pip install " + BADTAIL + "\n", True,
         "ok # plain\nFROM"),
        # Quoted `"a # b" \\` splices quote-blind (Q4), both
        # polarities.
        ("fix13-quote-splice-trip",
         syn + GOODRUN + 'RUN echo "a # b" \\\n' + OTHER
         + "RUN pip install " + BADTAIL + "\n", False,
         '"a # b" \\\nFROM'),
        ("fix13-quote-splice-flagged-alone",
         syn + 'RUN echo "a # b" \\\n' + OTHER + "RUN " + GOOD
         + "\n", True, '"a # b" \\\nFROM'),
        # Quoted `#` without backslash: real boundary (Q9).
        ("fix13-quoted-hash-no-splice",
         syn + GOODRUN + 'RUN echo "a#b"\n' + OTHER
         + "RUN pip install " + BADTAIL + "\n", True,
         '"a#b"\nFROM'),
        # Glued `ok#\\` splices `#`-blind (Q5).
        ("fix13-glued-splice-trip",
         syn + GOODRUN + "RUN echo ok#\\\n" + OTHER
         + "RUN pip install " + BADTAIL + "\n", False,
         "ok#\\\nFROM"),
        # Non-trailing backslash: no splice, real boundary (Q6).
        ("fix13-nontrailing-bs-is-boundary",
         syn + GOODRUN + "RUN echo ok # \\ foo\n" + OTHER
         + "RUN pip install " + BADTAIL + "\n", True,
         "# \\ foo\nFROM"),
        # Double-backslash run after a comment never splices (Q7).
        ("fix13-double-bs-comment-is-boundary",
         syn + GOODRUN + "RUN echo ok # \\\\\n" + OTHER
         + "RUN pip install " + BADTAIL + "\n", True,
         "# \\\\\nFROM"),
        # Round-12 full-line shapes preserved under the new
        # mapping: bare and indented comments still skip
        # mid-continuation.
        ("fix13-full-line-still-skipped",
         syn + GOODRUN + "RUN /opt/p11c/bin/p\\\n# sneaky\n"
         "ip install " + BADTAIL + "\n", False,
         "p\\\n# sneaky\nip"),
        ("fix13-indented-full-line-still-skipped",
         run2(GOOD, "pip install --require-hashes --only-binary=:all:"
              " pkg \\\n   # c\n --no-binary=cffi"), False,
         "   # c\n --no-binary"),
        # Trailing-comment FROM is no longer a boundary (Q10): the
        # builder rejects its arity outright (nothing executes), so
        # the gate keeping the stage and tripping on the unsafe
        # install is fail-closed on unbuildable (locked).
        ("fix13-trailing-comment-from-not-boundary",
         syn + GOODRUN + "FROM ubuntu:26.04 AS other # hello\n"
         "RUN pip install " + BADTAIL + "\n", False,
         "AS other # hello"),
        # Preserved inline text is cut in the shell layer
        # post-join: flagged still passes, unflagged still trips.
        ("fix13-inline-comment-mid-flags-pass",
         run2(GOOD, "pip install --require-hashes --only-binary=:all:"
              " pkg # trailing note"), True, "pkg # trailing"),
        ("fix13-inline-comment-mid-flags-trip",
         run2(GOOD, "pip install --require-hashes --no-binary=cffi"
              " pkg # trailing note"), False, "cffi pkg # trailing"),
    ]
    for name, body, expect, needle in cases:
        applied = needle in body
        got = f6_only_binary_ok(body)
        check_fix13(name, applied and got == expect,
                    f"inline-comment join -> {got} (want {expect})")

    # Pre-join mapping units.
    check_fix13("fix13-unit-prejoin-full-line",
                 _docker_pre_join_line("   # c") == ""
                 and _docker_pre_join_line("#c") == "",
                 "bare/indented full-line comments map to blank")
    check_fix13("fix13-unit-prejoin-inline-preserved",
                 _docker_pre_join_line("RUN echo ok # \\")
                 == "RUN echo ok # \\",
                 "inline comment rides through verbatim")
    check_fix13("fix13-unit-prejoin-quoted-hash",
                 _docker_pre_join_line('RUN echo "a#b"')
                 == 'RUN echo "a#b"',
                 "quoted hash preserved (as before)")
    check_fix13("fix13-unit-prejoin-label-shape",
                 _docker_pre_join_line(
                     '      org.opencontainers.image.description='
                     '"Haskoki PKCS#11 x" \\').endswith("\\"),
                 "real LABEL shape (quoted #, trailing bs) preserved")
    # Stage-attribution units: exact logicals.
    check_fix13("fix13-unit-stage-comment-eats-from",
                 _docker_stage_logicals(
                     syn + "RUN echo ok # \\\n" + OTHER
                     + "RUN echo hi\n")
                 == ([("checker",
                       "RUN echo ok # FROM ubuntu:26.04 AS other"),
                      ("checker", "RUN echo hi")], None),
                 "consumed FROM is mid-logical text, never a boundary")
    check_fix13("fix13-unit-stage-chain",
                 _docker_stage_logicals(
                     syn + "RUN echo ok # \\\n\n# full\n"
                     "   # indented\n" + OTHER + "RUN echo hi\n")
                 == ([("checker",
                       "RUN echo ok # FROM ubuntu:26.04 AS other"),
                      ("checker", "RUN echo hi")], None),
                 "blank/comment chain consumed with the FROM")
    check_fix13("fix13-unit-stage-trailing-from",
                 _docker_stage_logicals(
                     syn + "FROM x AS other # c\nRUN echo hi\n")
                 == ([("checker", "FROM x AS other # c"),
                      ("checker", "RUN echo hi")], None),
                 "trailing-comment FROM stays in its stage (Q10)")

    # Real-stage immunity: passing, per-line old-vs-new mapping
    # identity (identical join inputs => identical pipeline => zero
    # behavior change), and the checker-span `#` enumeration (every
    # `#` full-line; no trailing backslash after an inline
    # comment — the real file has no inline comments at all).
    docker = (REPO / "docker" / "Dockerfile.demo").read_text()
    check_fix13("fix13-real-stage-passing",
                 f6_only_binary_ok(docker),
                 "checker stage still evaluates wheel-only passing")
    raw_lines = docker.split("\n")
    differing = [i + 1 for i, l in enumerate(raw_lines)
                 if _docker_pre_join_line(l) != strip_comment(l)]
    nfull = sum(1 for l in raw_lines
                if _docker_pre_join_line(l) == "" and l.strip())
    check_fix13("fix13-real-prejoin-identity",
                 not differing,
                 f"old/new pre-join agree on all {len(raw_lines)} "
                 f"lines ({nfull} full-line comments blanked; "
                 f"diverging={differing})")
    from_idx = [i for i, l in enumerate(raw_lines)
                if FROM_RE.match(_docker_pre_join_line(l))]
    span = (range(from_idx[1] + 1, from_idx[2])
            if len(from_idx) == 3 else [])
    checker_hash = [(i + 1, raw_lines[i]) for i in span
                    if "#" in raw_lines[i]]
    inline = [n for n, l in checker_hash
              if not l.lstrip(" \t").startswith("#")]
    for n, l in checker_hash:
        print(f"      checker # L{n}: {l[:60]!r}")
    check_fix13("fix13-real-checker-no-inline",
                 len(from_idx) == 3 and not inline
                 and len(checker_hash) > 0,
                 f"{len(checker_hash)} `#` lines in checker span, "
                 f"all full-line (inline={inline})")
    return bad


def self_test_fix14() -> int:
    """Fix-round-14 durable regression (codex re-review #13, 1 NEW
    Low): full-line comment prefix set narrower than BuildKit/Go.
    The round-13 mapping's `lstrip(" \\t")` did not recognize a
    VT/FF/NBSP-prefixed `#` line as a comment, so it ENDED a
    continuation (spliced as content) and treated the consumed FROM
    as a stage boundary — while BuildKit (Go `unicode.IsSpace`)
    SKIPS that comment, continues the join, consumes FROM, and runs
    the unsafe install in checker. The gate now skips leading Go
    White_Space (minus `\\n`) before `#`, and the blank test uses
    the identical set. Grounded in REAL `docker build` probes
    R1–R21 (BuildKit v0.33.0, default docker-driver builder, base
    ubuntu:26.04, --no-cache; bad-image oracle — a stage boundary
    pulls `127.0.0.1:1/fix14-nonexistent:latest` and fails, a
    consumed FROM builds): R1–R5 VT/FF/NBSP/NEL/U+2003-prefixed
    comments skipped (rc 0); R6 U+001C-prefixed `#` is CONTENT
    (rc 1, boundary); R7/R8 space-comment/content controls; R9–R11
    VT/NBSP/U+2003-only lines blank (rc 0); R12/R13 empty/U+001C
    controls; R14/R15/R18/R19 trailing VT/NBSP/FF/NEL defeat the
    splice (rc 1 — the builder strips only space/tab); R16
    trailing-space control (rc 0); R17 NUL fails the build (P32
    re-verified); R20/R21 mixed-prefix/mixed-blank skipped (rc 0).
    Go `unicode.IsSpace` (Latin-1 switch + White_Space table) is
    byte-identical in go1.24.0 and go1.25.0 — STABLE. Codex shape
    per char class + flagged-alone polarity; refusal locks for
    ws-only/trailing exotics (the gate trips where the builder
    skips or bounds — conservative-fail-closed, never the reverse);
    U+001C polarity both directions; NUL passthrough lock; lone-CR
    prefix refusal (P31 kept); per-member set units; exact-logical
    stage units; real-file immunity (ASCII proof + passing +
    old-vs-new agreement on all physical lines). Synthetic checker
    stages (anchor-free); every f6 case carries its probe needle
    (applied-guard)."""
    bad = 0

    def check_fix14(name, cond, detail):
        nonlocal bad
        print(f"{'ok' if cond else 'FAIL'}: selftest-{name}: {detail}")
        if not cond:
            bad += 1

    syn = "FROM ubuntu:26.04 AS checker\n"
    GOOD = "pip install --require-hashes --only-binary=:all: pkg"
    GOODRUN = "RUN " + GOOD + "\n"
    BADTAIL = "--require-hashes --no-binary=cffi pkg"
    OTHER = "FROM ubuntu:26.04 AS other\n"
    UNSAFE = "RUN /opt/p11c/bin/pip install " + BADTAIL + "\n"
    VT, FF = "\x0b", "\x0c"
    NEL, NBSP = "\u0085", "\u00a0"
    EMSP = "\u2003"

    def contrip(mid):
        return syn + GOODRUN + "RUN echo ok # \\\n" + mid + OTHER + UNSAFE

    cases = [
        # The codex shape, one per char class (R1–R5): the comment
        # is skipped, FROM consumed, unsafe install trips.
        ("fix14-codex-vt-comment-trip",
         contrip(VT + "# sneaky\n"), False, VT + "# sneaky\nFROM"),
        ("fix14-ff-comment-trip",
         contrip(FF + "# sneaky\n"), False, FF + "# sneaky\nFROM"),
        ("fix14-nbsp-comment-trip",
         contrip(NBSP + "# sneaky\n"), False, NBSP + "# sneaky\nFROM"),
        ("fix14-nel-comment-trip",
         contrip(NEL + "# sneaky\n"), False, NEL + "# sneaky\nFROM"),
        ("fix14-emspace-comment-trip",
         contrip(EMSP + "# sneaky\n"), False, EMSP + "# sneaky\nFROM"),
        # Mixed-class prefix (R20) and ASCII+exotic mix.
        ("fix14-mixed-prefix-trip",
         contrip(VT + FF + " " + NBSP + NEL + EMSP + "# mixed\n"),
         False, EMSP + "# mixed\nFROM"),
        ("fix14-ascii-exotic-mix-trip",
         contrip(" \t" + VT + "# mixed\n"), False,
         "\t" + VT + "# mixed\nFROM"),
        # Flagged-alone behind the VT comment PASSES: the install
        # stays in checker and evaluates (found) — polarity proof.
        ("fix14-flagged-alone-vt-stays",
         syn + "RUN echo ok # \\\n" + VT + "# sneaky\n" + OTHER
         + "RUN " + GOOD + "\n", True, VT + "# sneaky\nFROM"),
        # U+001C-prefixed `#` is CONTENT (R6): spliced into the RUN
        # logical, continuation ends, FROM is a genuine boundary —
        # the unsafe install is really in `other` — pass.
        ("fix14-fs-prefixed-is-content",
         contrip("\x1c# sneaky\n"), True, "\x1c# sneaky\nFROM"),
        # Ws-only exotic lines are REFUSED whole-file (round-12
        # exotic-trailing refusal): the gate trips where the builder
        # skips (R9–R11) or bounds (R13) — conservative, locked.
        ("fix14-vt-only-line-refused",
         contrip(VT + "\n"), False, "\\\n" + VT + "\nFROM"),
        ("fix14-nbsp-only-line-refused",
         contrip(NBSP + "\n"), False, "\\\n" + NBSP + "\nFROM"),
        ("fix14-emspace-only-line-refused",
         contrip(EMSP + "\n"), False, "\\\n" + EMSP + "\nFROM"),
        ("fix14-fs-only-line-refused",
         contrip("\x1c\n"), False, "\\\n\x1c\nFROM"),
        # Trailing exotics after the backslash refuse (R14/R15/
        # R18/R19: the builder does NOT strip them — no splice,
        # genuine boundary — the gate trips fail-closed).
        ("fix14-trailing-vt-refused",
         syn + GOODRUN + "RUN echo ok \\" + VT + "\n" + OTHER
         + UNSAFE, False, "ok \\" + VT + "\nFROM"),
        ("fix14-trailing-ff-refused",
         syn + GOODRUN + "RUN echo ok \\" + FF + "\n" + OTHER
         + UNSAFE, False, "ok \\" + FF + "\nFROM"),
        ("fix14-trailing-nbsp-refused",
         syn + GOODRUN + "RUN echo ok \\" + NBSP + "\n" + OTHER
         + UNSAFE, False, "ok \\" + NBSP + "\nFROM"),
        ("fix14-trailing-nel-refused",
         syn + GOODRUN + "RUN echo ok \\" + NEL + "\n" + OTHER
         + UNSAFE, False, "ok \\" + NEL + "\nFROM"),
        # NUL passes through the gate as data (no refusal, no
        # crash); the BUILDER fails the step (R17, P32) — nothing
        # executes, so the pass is safe (locked).
        ("fix14-nul-passes-builder-fails",
         syn + GOODRUN + "RUN echo a\x00b\n", True, "a\x00b"),
        # A `\r` in the comment prefix still refuses whole-file
        # (lone CR, P31 — kept, not softened).
        ("fix14-lone-cr-prefix-still-refused",
         contrip("\r# c\n"), False, "\\\n\r# c\nFROM"),
    ]
    for name, body, expect, needle in cases:
        applied = needle in body
        got = f6_only_binary_ok(body)
        check_fix14(name, applied and got == expect,
                    f"ws-prefix join -> {got} (want {expect})")

    # Refusal reasons behind the trip locks above.
    refuse_cases = [
        ("fix14-refuse-vt-only", contrip(VT + "\n"), "exotic"),
        ("fix14-refuse-nbsp-only", contrip(NBSP + "\n"), "exotic"),
        ("fix14-refuse-emspace-only", contrip(EMSP + "\n"),
         "exotic"),
        ("fix14-refuse-fs-only", contrip("\x1c\n"), "exotic"),
        ("fix14-refuse-trailing-vt",
         syn + GOODRUN + "RUN echo ok \\" + VT + "\n", "exotic"),
        ("fix14-refuse-trailing-ff",
         syn + GOODRUN + "RUN echo ok \\" + FF + "\n", "exotic"),
        ("fix14-refuse-trailing-nbsp",
         syn + GOODRUN + "RUN echo ok \\" + NBSP + "\n", "exotic"),
        ("fix14-refuse-trailing-nel",
         syn + GOODRUN + "RUN echo ok \\" + NEL + "\n", "exotic"),
        ("fix14-refuse-trailing-emspace",
         syn + GOODRUN + "RUN echo ok \\" + EMSP + "\n", "exotic"),
        ("fix14-refuse-cr-prefix", contrip("\r# c\n"), "lone CR"),
    ]
    for name, body, want in refuse_cases:
        _log, why = _docker_stage_logicals(body)
        check_fix14(name, why is not None and want in why,
                    f"refusal -> {why!r} (want {want!r})")
    # Narrowness: space/tab after the backslash still splice
    # (P03/P13 — no refusal), and the VT-shape files above refuse
    # ONLY via trailing ws (the comment line itself is clean).
    check_fix14("fix14-refuse-narrow-space-tab",
                 _docker_physical_refused(
                     "RUN echo ok \\ \nRUN echo ok \\\t\n") is None
                 and _docker_physical_refused(
                     VT + "# sneaky\n"
                     + NBSP + "# n\n" + EMSP + "# e\n") is None,
                 "space/tab splice stays clean; exotic comment "
                 "prefixes stay clean")
    check_fix14("fix14-fs-content-no-refusal",
                 _docker_stage_logicals(contrip("\x1c# sneaky\n"))[1]
                 is None,
                 "U+001C content shape passes via boundary, not refusal")

    # Set identity: the exact 24 code points (Go IsSpace minus
    # `\n`) — typo guard on the literal.
    want_pts = ([0x09, 0x0b, 0x0c, 0x0d, 0x20, 0x85, 0xa0, 0x1680]
                + list(range(0x2000, 0x200b))
                + [0x2028, 0x2029, 0x202f, 0x205f, 0x3000])
    check_fix14("fix14-unit-gows-identity",
                 sorted(map(ord, _GO_WS_SET)) == want_pts
                 and len(_GO_WS_LEAD) == len(_GO_WS_SET) == 24,
                 f"Go set minus LF == {len(want_pts)} pts exactly")
    # Per-member comment units: EVERY set member skips a `#`
    # comment (bare and space-padded).
    all_skip = all(_docker_pre_join_line(c + "# c") == ""
                   and _docker_pre_join_line("  " + c + "# c") == ""
                   for c in _GO_WS_SET)
    check_fix14("fix14-unit-comment-each-member", all_skip,
                 "all 24 members skip `#` (bare + padded)")
    # Non-members keep the line verbatim (R6/R13 boundary):
    # U+001C-U+001F, NUL, other C0 controls, DEL, ZWSP, BOM, and a
    # plain letter.
    nonmembers = ["\x00", "\x01", "\x07", "\x1c", "\x1d", "\x1e",
                  "\x1f", "\x7f", "a", "\u200b", "\ufeff"]
    all_verbatim = all(_docker_pre_join_line(c + "# c") == c + "# c"
                       for c in nonmembers)
    check_fix14("fix14-unit-comment-nonmembers", all_verbatim,
                 f"{len(nonmembers)} non-members stay verbatim")
    # Blank units: members blank (incl. the CRLF empty line),
    # non-members content (incl. `\n`, absent by construction).
    blank_ok = (_docker_is_blank_ws("")
                and all(_docker_is_blank_ws(c) for c in _GO_WS_SET)
                and _docker_is_blank_ws("".join(sorted(_GO_WS_SET)))
                and _docker_is_blank_ws(" \t" + VT + NBSP + EMSP)
                and _docker_is_blank_ws("\r"))
    content_ok = (all(not _docker_is_blank_ws(c)
                      for c in ["\x1c", "\x1d", "\x1e", "\x1f"])
                  and not _docker_is_blank_ws(" \x1c ")
                  and not _docker_is_blank_ws("x")
                  and not _docker_is_blank_ws("\x00")
                  and not _docker_is_blank_ws("\n"))
    check_fix14("fix14-unit-blank-members", blank_ok,
                 "empty/each/all-24/mixed/CR are blank")
    check_fix14("fix14-unit-blank-nonmembers", content_ok,
                 "U+001C-U+001F/mixed/x/NUL/LF are content")
    # NUL shapes stay refusal-clean (passthrough lock).
    check_fix14("fix14-unit-nul-clean",
                 _docker_physical_refused("RUN echo a\x00b\n") is None
                 and _docker_physical_refused("# c\x00omment\n")
                 is None
                 and _docker_physical_refused("\x00\n") is None,
                 "NUL needs no refusal (P32/R17)")
    # Stage-attribution units: exact logicals, both polarities.
    check_fix14("fix14-unit-stage-vt-attribution",
                 _docker_stage_logicals(
                     syn + "RUN echo ok # \\\n" + VT + "# sneaky\n"
                     + OTHER + "RUN echo hi\n")
                 == ([("checker",
                       "RUN echo ok # FROM ubuntu:26.04 AS other"),
                      ("checker", "RUN echo hi")], None),
                 "VT comment skipped, FROM consumed into checker")
    check_fix14("fix14-unit-stage-fs-attribution",
                 _docker_stage_logicals(
                     syn + "RUN echo ok # \\\n" + "\x1c# sneaky\n"
                     + OTHER + "RUN echo hi\n")
                 == ([("checker", "RUN echo ok # \x1c# sneaky"),
                      ("other", "RUN echo hi")], None),
                 "U+001C line spliced as content, FROM is boundary")

    # Real-file immunity: UTF-8 decodes (the read encoding
    # handles the file); every exotic char (non-ASCII or C0
    # control outside tab/LF/CR) is inventoried and none is
    # whitespace-class under EITHER the old or the new test (so no
    # VT/FF/NEL/NBSP/U+2000-class char is present); stage passing;
    # and old-vs-new agreement on ALL physical lines for BOTH the
    # pre-join mapping and the blank test (identical join inputs
    # => zero behavior change).
    raw_bytes = (REPO / "docker" / "Dockerfile.demo").read_bytes()
    docker = raw_bytes.decode("utf-8")
    exotic = sorted({c for c in docker
                     if (ord(c) < 0x20 and c not in "\t\n\r")
                     or ord(c) > 0x7e})
    inv = [f"U+{ord(c):04X}" for c in exotic]
    ws_bad = [c for c in exotic
              if c in _GO_WS_SET or not c.strip()]
    check_fix14("fix14-real-no-gows-chars", not ws_bad,
                 f"{len(raw_bytes)}B UTF-8; exotic inventory={inv}, "
                 f"ws-class={ws_bad}")
    check_fix14("fix14-real-stage-passing",
                 f6_only_binary_ok(docker),
                 "checker stage still evaluates wheel-only passing")

    def _old_pre_join(line):
        return "" if line.lstrip(" \t").startswith("#") else line

    raw_lines = docker.split("\n")
    pre_diff = [i + 1 for i, l in enumerate(raw_lines)
                if _docker_pre_join_line(l) != _old_pre_join(l)]
    check_fix14("fix14-real-prejoin-agreement", not pre_diff,
                 f"old/new pre-join agree on all {len(raw_lines)} "
                 f"lines (diverging={pre_diff})")
    blank_diff = [i + 1 for i, l in enumerate(raw_lines)
                  if _docker_is_blank_ws(l) != (not l.strip())]
    check_fix14("fix14-real-blank-agreement", not blank_diff,
                 f"old/new blank test agree on all {len(raw_lines)} "
                 f"lines (diverging={blank_diff})")
    return bad


def self_test_fix15() -> int:
    """Fix-round-15 durable regression (codex re-review #14, 1 NEW
    Low): BOM-prefixed `#` directives and the BuildKit-recognized
    `//` directive forms bypassed the round-12 refusal. Grounded in
    the cited BuildKit v0.33.0 detector source
    (`frontend/dockerfile/parser/directives.go`: `discardBOM` =
    `TrimPrefix`, exactly one; `ParseLine` grammar; `DetectSyntax`
    tries `#`, then `//`, then whole-file JSON; `ParseDirective`
    is `#`-only) plus the main parser (BOM strip first line only,
    parser.go L296-299; `#`-only escape, L175-185; `//` lines are
    NOT comments — mid-continuation they splice as content, and
    standalone they die as `UnknownInstructionError`,
    instructions/parse.go L161-168), the `check` consumer
    (convert.go L197 → lint config only, linter.go
    `ParseLintOptions`: skip/experimental/error — warnings-only,
    never execution), and REAL `docker build` probes 0–14+P5b
    (BuildKit v0.33.0 via default docker-driver, client Docker
    29.8.1, base alpine:3.22, contested ref
    127.0.0.1:1/f15-nonexistent:latest — forward proves
    recognition). The suite locks: one-BOM normalization before
    ALL guards/parsing (refusals, comment/blank, join, stage
    attribution), multi-BOM fail-closed refusal, `//`
    syntax/escape refusals with the round-12 anywhere-superset,
    `//` content-vs-comment semantics, shebang agreement, the
    directive-name union audit (`check` warnings-only pass, both
    forms), the JSON-form found=False mechanism, the union-rule
    premise (CI pins no buildkit version), and real-file immunity
    (no BOM, no `//`, no directives → zero behavior change).
    Synthetic checker stages (anchor-free); every f6 case carries
    its probe needle (applied-guard)."""
    bad = 0

    def check_fix15(name, cond, detail):
        nonlocal bad
        print(f"{'ok' if cond else 'FAIL'}: selftest-{name}: {detail}")
        if not cond:
            bad += 1

    BOM = "\ufeff"
    syn = "FROM ubuntu:26.04 AS checker\n"
    GOOD = "pip install --require-hashes --only-binary=:all: pkg"
    GOODRUN = "RUN " + GOOD + "\n"
    BAD = "pip install --require-hashes --no-binary=cffi pkg"
    BADRUN = "RUN " + BAD + "\n"

    cases = [
        # The codex bypass forms: single BOM + `#` directive (probes 1/7:
        # detector/main-parser strip the BOM, then honor it).
        ("fix15-bom-syntax",
         BOM + "# syntax=docker/dockerfile:1\n" + syn + GOODRUN,
         False, BOM + "# syntax="),
        ("fix15-bom-escape",
         BOM + "# escape=`\n" + syn + GOODRUN, False, BOM + "# escape="),
        # Multi-BOM refuses fail-closed (probe 2: v0.33.0 strips one,
        # the directive dies AND dispatch fails on the survivor —
        # refusal agrees with that outcome and stays safe if a
        # future builder strips more).
        ("fix15-2bom-directive",
         BOM + BOM + "# syntax=docker/dockerfile:1\n" + syn + GOODRUN,
         False, BOM + BOM + "# syntax="),
        ("fix15-2bom-plain",
         BOM + BOM + syn + GOODRUN, False, BOM + BOM + "FROM"),
        ("fix15-2bom-slash",
         BOM + BOM + "// syntax=x\n" + syn + GOODRUN,
         False, BOM + BOM + "// syntax="),
        ("fix15-3bom",
         BOM + BOM + BOM + syn + GOODRUN, False, BOM + BOM + BOM),
        # Mid-file BOM is data, never a comment/directive (P10):
        # the BOM blocks the `#` match, the line rides through as
        # a skipped non-RUN logical. The builder fails such a file
        # later at dispatch (unknown instruction, probe-2 analog) — so
        # the gate passing is the safe direction, locked here.
        ("fix15-midfile-bom-standalone",
         syn + GOODRUN + BOM + "# sneaky\n", True, BOM + "# sneaky"),
        ("fix15-midfile-bom-nodirective",
         syn + GOODRUN + BOM + "# syntax=x\n", True, BOM + "# syntax="),
        # The `//` directive refusals (probe 3: `// syntax=` forwards).
        ("fix15-slash-syntax",
         "// syntax=docker/dockerfile:1\n" + syn + GOODRUN,
         False, "// syntax="),
        ("fix15-slash-escape",
         "// escape=`\n" + syn + GOODRUN, False, "// escape="),
        ("fix15-slash-nospace",
         "//syntax=x\n" + syn + GOODRUN, False, "//syntax="),
        ("fix15-slash-upper",
         "// SYNTAX=x\n" + syn + GOODRUN, False, "// SYNTAX="),
        ("fix15-slash-tab",
         "//\tsyntax=x\n" + syn + GOODRUN, False, "//\tsyntax="),
        ("fix15-slash-late",
         syn + GOODRUN + "// syntax=x\n", False, "// syntax=x"),
        ("fix15-slash-leading-ws",
         "  // syntax=x\n" + syn + GOODRUN, False, "  // syntax="),
        # `//` narrowness: `///` is dead in the builder too
        # (CutPrefix leaves `/ syntax=`, the name regex fails) and
        # `# //` is a plain comment to both — full agreement.
        # Standalone `//` lines die at dispatch (P5b) — the gate
        # passing them is the safe direction, locked here.
        ("fix15-triple-slash",
         "/// syntax=x\n" + syn + GOODRUN, True, "/// syntax="),
        ("fix15-hash-slashslash",
         "# // syntax=x\n" + syn + GOODRUN, True, "# // syntax="),
        ("fix15-slash-standalone",
         "// just a comment\n" + syn + GOODRUN, True, "// just a"),
        # `// check=` is never parsed (check is `#`-only,
        # convert.go L197) and warnings-only by construction; the
        # standalone line is unbuildable anyway (P12) — safe pass.
        ("fix15-slash-check",
         "// check=skip=all\n" + syn + GOODRUN, True, "// check="),
        ("fix15-slash-check-error",
         "// check=error=true\n" + syn + GOODRUN, True, "error=true"),
        # `# check=` warnings-only pass (P11): lint config can only
        # add warnings or fail the build on them — never change
        # what executes — so the gate is unaffected, late or not.
        ("fix15-check-skip",
         "# check=skip=all\n" + syn + GOODRUN, True, "# check=skip"),
        ("fix15-check-error",
         "# check=error=true\n" + syn + GOODRUN, True, "error=true"),
        ("fix15-check-late",
         syn + GOODRUN + "# check=skip=all\n", True, "# check=skip"),
        ("fix15-check-bom",
         BOM + "# check=skip=all\n" + syn + GOODRUN,
         True, BOM + "# check="),
        # Shebang agreement: `#!` is a plain comment to the main
        # parser and skipped by the detector (probe 8: builds fine).
        ("fix15-shebang-first",
         "#!/bin/sh\n" + syn + GOODRUN, True, "#!/bin/sh"),
        ("fix15-shebang-mid",
         syn + GOODRUN + "#!/bin/sh\n", True, "#!/bin/sh"),
        # `#!` + directive-looking text: the detector strips the
        # WHOLE first line as shebang, the main parser comments it
        # (P13: builds fine with an unresolvable-looking ref).
        ("fix15-shebang-directive-looking",
         "#! syntax=127.0.0.1:1/f15-nonexistent:latest\n"
         + syn + GOODRUN, True, "#! syntax="),
        ("fix15-shebang-escape-looking",
         "#! escape=`\n" + syn + GOODRUN, True, "#! escape="),
        # Shebang + a REAL directive on the next line still
        # forwards (probe 9/P14) — the anywhere-superset covers it.
        ("fix15-shebang-then-syntax",
         "#!/bin/sh\n# syntax=x\n" + syn + GOODRUN,
         False, "#!/bin/sh"),
        ("fix15-shebang-then-slash",
         "#!/bin/sh\n// syntax=x\n" + syn + GOODRUN,
         False, "// syntax="),
        # Single-BOM normalization passes: BOM + comment/blank is
        # exactly the builder's strip-then-skip (full agreement).
        ("fix15-bom-comment",
         BOM + "# plain comment\n" + syn + GOODRUN,
         True, BOM + "# plain"),
        ("fix15-bom-blank",
         BOM + "\n" + syn + GOODRUN, True, BOM + "\n"),
        ("fix15-bom-good-passes",
         BOM + syn + GOODRUN, True, BOM + "FROM"),
        # LOAD-BEARING join normalization: without the strip, the
        # BOM-prefixed FROM does not attribute, so the unflagged
        # install below it is gate-invisible while a LATER clean
        # checker stage still yields found=True — the old behavior
        # returns True (miss) where the builder (which strips, probe 7)
        # executes the unflagged install. The strip catches it.
        ("fix15-bom-run-evaluated",
         BOM + syn + BADRUN + syn + GOODRUN, False, BOM + "FROM"),
        # Whole-file JSON `{"syntax": ...}` forwards (probe 4) but can
        # never smuggle a checker install past the gate: JSON
        # strings cannot span lines, so no FROM/RUN line-start can
        # appear in detector-recognized input → found=False.
        ("fix15-json-syntax",
         '{"syntax": "docker/dockerfile:1"}\n', False, '"syntax"'),
        ("fix15-bom-only-file",
         BOM + "\n", False, BOM),
    ]
    for name, body, expect, needle in cases:
        applied = needle in body
        got = f6_only_binary_ok(body)
        check_fix15(name, applied and got == expect,
                    f"BOM/directive union -> {got} (want {expect})")

    # Exact-logical agreement units: `//` and BOM-prefixed `#`
    # lines mid-continuation splice as CONTENT (probe 5/P10), ending the
    # splice exactly like the builder's (contrast: a plain `#`
    # comment is skipped and the FROM is consumed — fix13/14).
    OTHER = "FROM ubuntu:26.04 AS other\n"
    check_fix15("fix15-unit-slash-content",
                 _docker_stage_logicals(
                     syn + "RUN echo one \\\n// two\n"
                     + OTHER + "RUN echo three\n")
                 == ([("checker", "RUN echo one // two"),
                      ("other", "RUN echo three")], None),
                 "probe 5: `// two` spliced as content, FROM is boundary")
    check_fix15("fix15-unit-midbom-content",
                 _docker_stage_logicals(
                     syn + "RUN echo ok # \\\n" + BOM + "# sneaky\n"
                     + OTHER + "RUN echo hi\n")
                 == ([("checker", "RUN echo ok # " + BOM + "# sneaky"),
                      ("other", "RUN echo hi")], None),
                 "P10: BOM-`#` spliced as content, FROM is boundary")
    # Strip-exactness units: exactly one, file-leading only.
    check_fix15("fix15-unit-strip-one",
                 _docker_strip_bom(BOM + "# x") == "# x"
                 and _docker_strip_bom(BOM + BOM + "# x")
                 == BOM + "# x"
                 and _docker_strip_bom("# x") == "# x"
                 and _docker_strip_bom("") == ""
                 and _docker_strip_bom("a\n" + BOM + "b")
                 == "a\n" + BOM + "b",
                 "single stripped, double keeps survivor, mid kept")
    # Refusal reasons behind the trip locks above.
    check_fix15("fix15-unit-refuse-bom",
                 bool(_docker_physical_refused(
                     BOM + "# syntax=x\nFROM x\n"))
                 and bool(_docker_physical_refused(
                     BOM + "# escape=`\nFROM x\n")),
                 "BOM-prefixed `#` directives refuse")
    check_fix15("fix15-unit-refuse-multibom",
                 bool(_docker_physical_refused(BOM + BOM + "FROM x\n"))
                 and _docker_physical_refused(
                     BOM + BOM + "FROM x\n").startswith("multiple"),
                 "double BOM refuses (union rule)")
    check_fix15("fix15-unit-refuse-slash",
                 bool(_docker_physical_refused(
                     "// syntax=x\nFROM x\n"))
                 and bool(_docker_physical_refused(
                     "// escape=`\nFROM x\n"))
                 and bool(_docker_physical_refused(
                     "FROM x\n// syntax=x\n")),
                 "`//` directives refuse (incl. late superset)")
    check_fix15("fix15-unit-refuse-narrow",
                 _docker_physical_refused("/// syntax=x\nFROM x\n")
                 is None
                 and _docker_physical_refused("# // syntax=x\nFROM x\n")
                 is None
                 and _docker_physical_refused(
                     "FROM x\n" + BOM + "# syntax=y\n") is None
                 and _docker_physical_refused(
                     "# check=skip=all\nFROM x\n") is None
                 and _docker_physical_refused(
                     "// check=skip=all\nFROM x\n") is None,
                 "triple-slash/hash-slash/mid-BOM/check stay clean")

    # Real-file immunity: strict UTF-8 decode (the BOM would decode
    # cleanly to U+FEFF — normalization is post-decode), zero BOM /
    # line-start-`//` / directive forms in BOTH Dockerfiles, the
    # strip is identity, refusal-free, stage passing — and the join
    # inputs are provably identical to the pre-fix path (same
    # refusal outcome + identity strip ⟹ identical downstream).
    for fname in ("docker/Dockerfile.demo", "Dockerfile"):
        raw_bytes = (REPO / fname).read_bytes()
        docker = raw_bytes.decode("utf-8")
        has_bom = "\ufeff" in docker
        slash = [i + 1 for i, l in enumerate(docker.split("\n"))
                 if _DOCKER_SLASH_DIRECTIVE_RE.match(l)
                 or (l.lstrip(" \t").startswith("//"))]
        direct = [i + 1 for i, l in enumerate(docker.split("\n"))
                  if _DOCKER_DIRECTIVE_RE.match(l)]
        tag = "demo" if fname.endswith("demo") else "root"
        check_fix15(f"fix15-real-{tag}-no-bom-slash-directive",
                     not has_bom and not slash and not direct,
                     f"{len(raw_bytes)}B strict UTF-8; BOM={has_bom}, "
                     f"slash-lines={slash}, directives={direct}")
        check_fix15(f"fix15-real-{tag}-strip-identity",
                     _docker_strip_bom(docker) == docker,
                     "strip is identity on BOM-free text")
    demo = (REPO / "docker" / "Dockerfile.demo").read_text()
    check_fix15("fix15-real-stage-passing",
                 f6_only_binary_ok(demo),
                 "checker stage still evaluates wheel-only passing")
    check_fix15("fix15-real-no-refusal",
                 _docker_physical_refused(demo) is None,
                 "refusal-free (same outcome as pre-fix path)")

    # Union-rule premise: CI pins no buildkit/builder version, so
    # the refusal must cover the union of honored forms across
    # plausible builder versions. This trips if CI ever pins (at
    # which point the union re-audits against the pinned version).
    ci = (REPO / ".github" / "workflows" / "ci.yml").read_text()
    ci_lines = ci.split("\n")
    setup_idx = next(i for i, l in enumerate(ci_lines)
                     if "setup-buildx-action" in l)
    step_tail = []
    for l in ci_lines[setup_idx + 1:]:
        if re.match(r"^(      - |    [a-zA-Z]|  [a-zA-Z])", l):
            break
        step_tail.append(l)
    pinned = [l for l in step_tail
              if re.search(r"version\s*:", l)]
    check_fix15("fix15-union-ci-unpinned",
                 not pinned,
                 f"setup-buildx step has no version pin ({step_tail})")
    return bad


def main() -> int:
    if len(sys.argv) > 1 and sys.argv[1] == "--self-test":
        return self_test()
    src = Path(sys.argv[1]).read_text() if len(sys.argv) > 1 else DEFAULT.read_text()
    return check_text(src)


if __name__ == "__main__":
    sys.exit(main())
