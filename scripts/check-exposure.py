#!/usr/bin/env python3
"""Public Haskell exposure gate: the installable API surface stays honest.

The product interface is the C ABI; Haskell libraries are
same-package implementation (R-09a). Asserts over haskoki.cabal:

  * no main (unnamed) `library` stanza exists (mains are
    always public);
  * every named library stanza is private: an explicit
    `visibility:` marker must read `private`, and unmarked
    libraries are private by default (both probed against
    cabal-install 3.12.1.0; `common` stanzas cannot carry
    visibility — Cabal parses them with build-info only);
  * no other `visibility:` marker anywhere in the file reads
    anything but `private` (conditionals included, whatever
    branch is taken).

Stanza headers are case-insensitive, may use brace syntax,
and may be indented at a stanza boundary; braces suspend
layout; duplicate fields are last-wins; NBSP counts as
indentation (all probed). Only whole-line `--` comments
exist (probed: `--` inside values reaches the compiler).
Anything the parser cannot classify fails closed (an error,
never a pass).

Known residuals (require deliberate contrivance; code review
is the backstop): a top-level `visibility:` field (Cabal
warns and ignores it, the gate flags it); quoted braces in
stanza names (fail closed); publicity markers inside nested
(ignored) sections (fail closed — un-nest to escape).

Module-size budgets (0.6.3 ratchet, same file per one-in-one-out:
no new check-*.py for this rule). Every .hs file under the lib
roots (src core tools app client examples bench) must stay at or
below 1200 lines, every .hs file under tests/ at or below 4000;
top-level ffi/ (a compiled hs-source-dir, excluded by owner
decision) and *Generated.hs are out of scope. Over-budget
files fail unless pinned in MODSIZE_ALLOW with a reason, and a
pinned file fails when it grows past its pin. Splitting a pinned
file removes its pin; growing the tree within budget needs no
gate change.

Usage: python3 scripts/check-exposure.py [--self-test]
"""

import re
import sys
import tempfile
from bisect import bisect_right
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
CABAL = REPO / "haskoki.cabal"

HEADER_RE = re.compile(r"^([A-Za-z][A-Za-z0-9-]*)(.*)$")
FIELD_RE = re.compile(r"^([A-Za-z][A-Za-z0-9-]*)\s*:(.*)$")
COND_RE = re.compile(r"^(if|elif|else)\b", re.IGNORECASE)
# Comments are WHOLE LINES only: inside field values `--` is
# literal text (probed: `--opt` flags reach the compiler; Cabal
# itself says "only whole line comments"). Section headers take
# only their first token, which ignores trailing comments.
COMMENT_RE = re.compile(r"^\s*--.*$")
# Same-line visibility scan: the value must follow on its line
# (multi-line values belong to the stanza parser). A `{` before
# the value is accepted: Cabal honors `{ private }`.
VIS_RE = re.compile(
    r"(?:^|[;{}])[ \t]*visibility[ \t]*:[ \t]*\{*[ \t]*([^\s;,{}]+)",
    re.IGNORECASE | re.MULTILINE)
EMPTY_VIS_RE = re.compile(
    r"(?:^|[;{}])[ \t]*visibility[ \t]*:[ \t]*\{*[ \t]*([};]?)[ \t]*$",
    re.IGNORECASE)
BRACED_VALUE_RE = re.compile(r"^\{\s*(.*?)\s*\}$")
STANZA_KINDS = frozenset([
    "library", "common", "executable", "test-suite", "benchmark",
    "foreign-library", "flag", "source-repository", "custom-setup",
])


def _unbrace(value):
    """Strips pairs of braces around a field value, if present."""
    text = value.strip()
    while True:
        m = BRACED_VALUE_RE.match(text)
        if not m:
            return text
        text = m.group(1)


def _records(text):
    """Significant lines as (indent, code) with comments stripped.

    UTF-8 NBSP counts as indentation (probed: the lexer accepts
    it with a warning), so it normalizes to a space first; tabs
    count one column each, exactly like the lexer.
    """
    out = []
    for raw in text.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        raw = raw.replace("\u00a0", " ")  # NBSP -> space
        code = COMMENT_RE.sub("", raw).rstrip()
        if code.strip():
            out.append((len(raw) - len(raw.lstrip(" \t")), code))
    return out


def _split_top(text):
    """Splits braced body text on ';' at brace depth zero."""
    parts, buf, depth = [], [], 0
    for ch in text:
        if ch == "{":
            depth += 1
            buf.append(ch)
        elif ch == "}":
            depth -= 1
            buf.append(ch)
        elif ch == ";" and depth == 0:
            parts.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
    parts.append("".join(buf))
    return parts


def _net_open(text):
    """Net unbalanced `{` count (clamped at zero from below)."""
    depth = 0
    for ch in text:
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth = max(0, depth - 1)
    return depth


def stanzas(text):
    """Returns ([(kind, name, fields, vidxs, cidxs)], unclosed).

    kind is 'library' or 'common' (lowercase); fields maps
    lowercase field names to value text for fields lexically
    direct to the stanza (conditional branches excluded,
    duplicates last-wins); vidxs holds the significant-line
    indices of direct `visibility:` fields and cidxs those of
    skipped conditional segments mentioning one (both consumed
    by the global pass). unclosed is true when a braced stanza
    never closes.

    Layout and braces share one loop: a header opens a stanza
    (layout, or braced when its line opens a brace); braces
    suspend layout (column-0 lines inside braces are content);
    an unbalanced value keeps consuming lines (any indent)
    until it balances. Field order per line: unbalanced-value
    append wins (braces beat structure), then conditionals,
    then continuations (deeper colon lines extend values, never
    fields), then fields.
    """
    pending = [(n, indent, code)
               for n, (indent, code) in enumerate(_records(text))]
    # Every re-scan strictly shortens its line, so iterations
    # stay linear; the cap turns any future queue bug into a
    # loud gate failure instead of a CI hang.
    cap = 10 * len(pending) + 100
    cur = None  # stanza dict, or None outside stanzas
    continuations = None  # (field-name, indent, complete?) for values
    field_indent = None  # indent of the open top-level field, if any
    cur_idx = -1
    yielded = []
    i = 0

    def new_stanza(kind, name, hdr_indent):
        return {"kind": kind, "name": name, "fields": {},
                "cond": [], "depth": 0, "vidxs": set(),
                "cidxs": set(), "hdr_braced": False,
                "hdr_indent": hdr_indent, "need": None}

    def flush():
        if cur is not None and cur["kind"] in ("library", "common"):
            yield (cur["kind"], cur["name"], cur["fields"],
                   cur["vidxs"], cur["cidxs"])

    def note(field, value):
        name = field.lower()
        cur["fields"][name] = value  # duplicates last-wins, like Cabal
        if name == "visibility":
            # Only visibility lines are attributed (the global
            # pass judges every other same-line marker itself).
            cur["vidxs"].add(cur_idx)
        if _net_open(value) > 0:
            cur["need"] = name

    def append_need(stripped):
        cur["fields"][cur["need"]] += " " + stripped
        if _net_open(cur["fields"][cur["need"]]) == 0:
            cur["need"] = None

    def region_active(line_indent):
        for kind, mark in cur["cond"]:
            if kind == "d":
                if cur["depth"] >= mark:
                    return True
            elif line_indent > mark:
                return True
        return False

    def pop_regions(line_indent):
        cur["cond"][:] = [
            (kind, mark) for kind, mark in cur["cond"]
            if not (kind == "d" and cur["depth"] < mark)
            and not (kind == "i" and line_indent <= mark)]

    def open_header(kind, rest, hdr_indent):
        """Opens a stanza; splits name from any braced rest.

        A `--` outside the braced rest starts a section-level
        comment (probed: kept inside field values, stripped
        here); quoted braces in names are unsupported and fail
        closed (documented, insane input only).
        """
        if "{" in rest:
            namepart, content = rest.split("{", 1)
        else:
            namepart, content = rest, None
        name = re.sub(r"--.*$", "", namepart).strip() or None
        fresh = new_stanza(kind, name, hdr_indent)
        if content is None:
            return fresh, ""
        fresh["hdr_braced"] = True
        return fresh, content

    def close_stanza(trailing):
        """Ends a braced stanza; re-scans text after the brace."""
        if cur["kind"] in ("library", "common"):
            yielded.append((cur["kind"], cur["name"], cur["fields"],
                            cur["vidxs"], cur["cidxs"]))
        rest = re.sub(r"^[\s}]+", "", trailing)
        return rest

    def close_layout():
        """Ends a layout stanza for reparse at top level."""
        for y in flush():
            yielded.append(y)

    while i < len(pending):
        assert i < cap, "exposure parser iteration cap exceeded"
        cur_idx, indent, line = pending[i]
        i += 1
        if cur is None and not (
                field_indent is not None and indent > field_indent):
            # Top level outside any field range: a library
            # header after a field-value close opens on the same
            # line (probed). Inside an open stanza, or inside a
            # field's continuation range, the same text is
            # nested junk or value text (ignored).
            tm = re.search(r"\}\s*(library\b.*)$", line,
                           re.IGNORECASE)
            if tm and "{" in tm.group(1):
                pending.insert(i, (cur_idx, 0,
                                   tm.group(1).strip()))
                line = line[:tm.start() + 1]
        if cur is not None and cur["need"] is not None:
            # Unbalanced value: braces win over structure; every
            # line appends (any indent, column 0 included) until
            # the value balances.
            cur["depth"] = max(0, cur["depth"] + line.count("{")
                               - line.count("}"))
            append_need(line.strip())
            continue
        if cur is not None and cur["depth"] > 0:
            # Braced content: ';' separates fields; a `}` that
            # empties a header-braced stanza ends it (anything
            # after re-scans: `} library foo` is valid).
            buf, rel, closed, cut = [], 0, False, 0
            for pos, ch in enumerate(line):
                if ch == "{":
                    rel += 1
                    buf.append(ch)
                elif ch == "}":
                    if cur["hdr_braced"] and cur["depth"] + rel == 1:
                        closed = True
                        cut = pos + 1
                        break
                    rel -= 1
                    buf.append(ch)
                else:
                    buf.append(ch)
            if not closed:
                cur["depth"] = max(0, cur["depth"] + line.count("{")
                                   - line.count("}"))
            else:
                cur["depth"] = 0
            pop_regions(indent)
            for seg in _split_top("".join(buf)):
                core = re.sub(r"^[} \t]+", "", seg.strip())
                if not core:
                    continue
                if COND_RE.match(core):
                    rest = core[COND_RE.match(core).end():]
                    if re.search(r"\{", rest) and _net_open(rest) > 0:
                        cur["cond"].append(("d", cur["depth"]))
                    elif "{" not in rest:
                        cur["cond"].append(("i", indent))
                    if re.search(r"visibility\s*:", core,
                                 re.IGNORECASE):
                        cur["cidxs"].add(cur_idx)
                    continuations = None
                    continue
                if region_active(indent):
                    continue
                f = FIELD_RE.match(core)
                if f:
                    continuations = (f.group(1).lower(), indent,
                                     False)
                    note(f.group(1), f.group(2).strip())
            if closed:
                rest = close_stanza(line[cut:])
                cur = None
                continuations = None
                field_indent = None
                if rest.strip():
                    pending.insert(i, (cur_idx, 0, rest.strip()))
            continue
        if indent == 0:
            for y in flush():
                yielded.append(y)
            cur, continuations = None, None
            m = HEADER_RE.match(line)
            kind = m.group(1).lower() if m else None
            if kind in ("library", "common"):
                cur, rest = open_header(kind, m.group(2), indent)
                field_indent = None
                if cur["hdr_braced"]:
                    cur["depth"] = 1
                    if rest.strip():
                        pending.insert(i, (cur_idx, indent, rest))
            elif kind in STANZA_KINDS:
                cur = new_stanza("other", None, indent)
                field_indent = None
                if "{" in m.group(2):
                    cur["hdr_braced"] = True
                    cur["depth"] = 1
                    rest = m.group(2).split("{", 1)[1]
                    if rest.strip():
                        pending.insert(i, (cur_idx, 1, rest))
            elif m and FIELD_RE.match(line):
                # Top-level field: a brace-balanced close leaves
                # no continuation range (probed boundary);
                # otherwise deeper lines continue its value.
                # (Same-line library headers split off above.)
                opens = line.count("{")
                closes = line.count("}")
                if "}" in line and closes >= opens:
                    field_indent = None
                else:
                    field_indent = 0
            else:
                # Garbage: a leading `}` (lone or repeated)
                # re-scans its remainder as a new line; anything
                # else is ignored (Cabal rejects it loudly).
                # Only re-scan on strict progress (a `}` was
                # consumed) so the queue cannot self-reproduce.
                field_indent = None
                if re.match(r"^[\s}]*\}", line):
                    rest = re.sub(r"^[\s}]+", "", line)
                    if rest.strip():
                        pending.insert(i, (cur_idx, 0, rest.strip()))
            continue
        if cur is None:
            # Outside a stanza, an indented header opens only at
            # top level (no open field) or dedented at or above
            # the open field (probed splits); deeper lines are
            # continuations. Fields open a continuation range
            # unless brace-completed.
            if field_indent is not None and indent > field_indent:
                continue  # continuation of a top-level field
            m = HEADER_RE.match(line.strip())
            kind = m.group(1).lower() if m else None
            if kind in ("library", "common"):
                cur, rest = open_header(kind, m.group(2), indent)
                field_indent = None
                if rest.strip() or cur["hdr_braced"]:
                    if rest.strip():
                        pending.insert(i, (cur_idx, indent, rest))
                    if not rest.strip():
                        cur["depth"] = 1
            elif kind in STANZA_KINDS:
                cur = new_stanza("other", None, indent)
                field_indent = None
                if "{" in m.group(2):
                    cur["hdr_braced"] = True
                    cur["depth"] = 1
                    rest = m.group(2).split("{", 1)[1]
                    if rest.strip():
                        pending.insert(i, (cur_idx, indent, rest))
            elif FIELD_RE.match(line.strip()):
                opens = line.count("{")
                closes = line.count("}")
                if "}" in line and closes >= opens:
                    field_indent = None
                else:
                    field_indent = indent
            continue
        # Layout body line.
        stripped = line.strip()
        if indent < cur["hdr_indent"] + 1:
            # Dedented below the body level: the stanza closes
            # (probed) and the line re-parses at top level.
            close_layout()
            cur, continuations = None, None
            field_indent = None
            pending.insert(i, (cur_idx, indent, line))
            continue
        if stripped.startswith("{"):
            # A brace group opens layout-neutrally (its depth is
            # still counted); regions and fields are unaffected.
            cur["depth"] = max(0, cur["depth"] + stripped.count("{")
                               - stripped.count("}"))
            continue
        pop_regions(indent)
        if COND_RE.match(stripped):
            if "{" not in stripped:
                cur["cond"].append(("i", indent))
            elif _net_open(stripped) > 0:
                cur["cond"].append(("d", cur["depth"]))
            continuations = None
            cur["depth"] = max(0, cur["depth"] + stripped.count("{")
                               - stripped.count("}"))
            continue
        if region_active(indent):
            continue  # inside a conditional branch: not direct
        if continuations is not None and indent > continuations[1] \
                and not continuations[2]:
            cur["fields"][continuations[0]] += " " + stripped
            if _net_open(cur["fields"][continuations[0]]) > 0:
                cur["need"] = continuations[0]
            cur["depth"] = max(0, cur["depth"] + stripped.count("{")
                               - stripped.count("}"))
            continue
        f = FIELD_RE.match(stripped)
        if f:
            # A brace-completed value takes no continuations:
            # deeper lines are new elements (probed).
            complete = "{" in f.group(2) and \
                _net_open(f.group(2)) == 0
            continuations = (f.group(1).lower(), indent, complete)
            note(f.group(1), f.group(2).strip())
            cur["depth"] = max(0, cur["depth"] + stripped.count("{")
                               - stripped.count("}"))
            continue
        cur["depth"] = max(0, cur["depth"] + stripped.count("{")
                           - stripped.count("}"))

    for y in flush():
        yielded.append(y)
    unclosed = cur is not None and cur["hdr_braced"] and cur["depth"] > 0
    return yielded, unclosed


def _lite_class(indent, stripped):
    """Structural class of one comment-stripped line.

    Returns (class, indent) with class in header0/cond/field/
    other. Boundary-indented headers classify as other
    (transparent): the walk-up passes through them to the
    boundary header, which keeps both F3a recognition and F3d
    continuation-skipping correct.
    """
    if COND_RE.match(stripped):
        return "cond", indent
    if FIELD_RE.match(stripped):
        return "field", indent
    if indent == 0 and HEADER_RE.match(stripped):
        return "header0", indent
    return "other", indent


def _walk_verdict(records, idx, indent):
    """Whether records[idx] starts a field (vs continues one).

    Walks up past transparent lines: a header, conditional
    opener, or field at shallower-or-equal indent starts a
    field; a shallower field above makes this line its
    continuation. BOF defaults to field (fail closed).
    """
    for k in range(idx - 1, -1, -1):
        cls, jind = _lite_class(records[k][0], records[k][1].strip())
        if cls == "other":
            continue
        if cls == "field":
            return "field" if indent <= jind else "continuation"
        return "field"  # header0 or cond opens a level
    return "field"


def _continued_value(records, idx, indent):
    """First value token on deeper lines below records[idx].

    Resolves multi-line values (`visibility:` with nothing
    after it): brace-only tokens are skipped, so `{` newline
    `public` still reads public. Returns "" when no deeper
    line follows (the stanza pass or Cabal rejects the file).
    """
    for k in range(idx + 1, len(records)):
        jind, code = records[k]
        if jind <= indent:
            break
        toks = code.strip().split()
        if toks:
            tok = toks[0].strip("{},;")
            if tok:
                return tok
    return ""


def _global_errors(text, direct_idxs, cond_idxs):
    """Non-private visibility values outside direct fields.

    Each `visibility:` match is judged in context: a match on
    a direct-field line (owned by the stanza pass, which
    resolves duplicates last-wins) is skipped unless the line
    also holds a skipped conditional marker; a match inside a
    layout field value (after `;` at brace depth zero, not
    after a closing brace) or on a continuation line (walk-up
    finds a shallower field above) is value text, not a
    marker. Values may continue on deeper lines. Everything
    else must read `private`.
    """
    records = _records(text)
    codes = [code for _, code in records]
    joined = "\n".join(codes)
    starts, pos = [], 0
    for code in codes:
        starts.append(pos)
        pos += len(code) + 1
    depths, depth = [], 0
    for ch in joined:
        depths.append(depth)
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth = max(0, depth - 1)
    errors = []
    for m in VIS_RE.finditer(joined):
        idx = bisect_right(starts, m.start()) - 1
        if idx in direct_idxs and idx not in cond_idxs:
            continue  # judged by the stanza pass (dup last-wins)
        indent, code = records[idx]
        pre = codes[idx][:m.start() - starts[idx]]
        own_start = pre.strip() == ""
        after_brace = joined[m.start()] == "}"
        if not own_start and not after_brace \
                and depths[m.start(1)] == 0:
            cls, _ = _lite_class(indent, code.strip())
            if cls == "field":
                continue  # layout `;` inside a field value
        verdict = _walk_verdict(records, idx, indent)
        if verdict == "field" and m.group(1).lower() != "private":
            errors.append("non-private visibility value: %s" % m.group(1))
    for idx, (indent, code) in enumerate(records):
        em = EMPTY_VIS_RE.search(code)
        if (idx in direct_idxs and idx not in cond_idxs) or not em:
            continue
        pre = code[:em.start()]
        after_brace = code[em.start()] == "}"
        if pre.strip() != "" and not after_brace \
                and depths[starts[idx]] == 0:
            cls, _ = _lite_class(indent, code.strip())
            if cls == "field":
                continue  # layout `;` inside a field value
        if _walk_verdict(records, idx, indent) != "field":
            continue
        if em.group(1):
            errors.append("empty visibility value")
            continue
        value = _continued_value(records, idx, indent)
        if not value:
            errors.append("empty visibility value")
        elif value.lower() != "private":
            errors.append("non-private visibility value: %s" % value)
    return errors


def check(cabal_text):
    """Returns error strings (empty means honest)."""
    errors = []
    yielded, unclosed = stanzas(cabal_text)
    if unclosed:
        errors.append("unclosed braced stanza in cabal file")
    libs, direct, cond = [], set(), set()
    for kind, name, fields, vidxs, cidxs in yielded:
        direct.update(vidxs)
        cond.update(cidxs)
        if kind == "library":
            libs.append((name, fields))
    for name, fields in libs:
        if name is None:
            errors.append("main library stanza exists (must be named + private)")
            continue
        if "visibility" not in fields:
            # Named libraries default to private (probed: an
            # unmarked library rejects external goals, and
            # `common` stanzas cannot carry visibility — Cabal
            # parses them with the build-info grammar only).
            continue
        vis = _unbrace(fields["visibility"]).split()[0:1]
        if not vis or vis[0].lower() != "private":
            errors.append("library %s is not private" % name)
    errors.extend(_global_errors(cabal_text, direct, cond))
    return errors


# Module-size budgets (0.6.3 ratchet): the lib/test splits must not
# regrow. Caps apply to every Haskell source file (.hs/.hsc/.lhs)
# under the source roots; over-cap files fail unless pinned below
# with a reason. Pins record pre-existing over-budget debt
# (owner-call skips, follow-up candidates).
MODSIZE_LIB_MAX = 1200
MODSIZE_TEST_MAX = 4000
# Roots track every hs-source-dirs entry in haskoki.cabal except ffi/,
# which is a compiled hs-source-dir excluded by owner decision (FFI
# binding surface).
MODSIZE_LIB_ROOTS = ("src", "core", "tools", "app", "client",
                     "examples", "bench")
MODSIZE_TEST_ROOTS = ("tests", "test")
MODSIZE_EXTS = ("*.hs", "*.hsc", "*.lhs")
MODSIZE_SKIP_SUFFIXES = ("Generated.hs",)
MODSIZE_SKIP_PARTS = ("dist-newstyle",)
# path: (lines at pinning, reason). Lines are splitlines() counts.
# Pins cover over-budget debt only (owner-call skips, follow-up
# candidates); generated code and ffi/ mirrors are excluded above,
# never pinned.
MODSIZE_ALLOW = {
    "src/Haskoki/Engine/OpenSSL4.hs":
        (2393, "owner-call skip: FFI-adjacent, weak seams"),
    "src/Haskoki/Engine/Synthetic.hs":
        (1958, "follow-up candidate, not yet split"),
    "core/Haskoki/Transition.hs":
        (1814, "owner-call skip: weak seams"),
    "core/Haskoki/Registry.hs":
        (1766, "owner-call skip: weak seams"),
    "tests/model/FfiAsyncSpec.hs":
        (4063, "out of the 0.6.3 test-split scope (3 files)"),
}


def _modsize_files(root):
    out = []
    for d, cap in [(r, MODSIZE_LIB_MAX) for r in MODSIZE_LIB_ROOTS] + \
                  [(r, MODSIZE_TEST_MAX) for r in MODSIZE_TEST_ROOTS]:
        base = root / d
        if not base.is_dir():
            continue
        for ext in MODSIZE_EXTS:
            for p in sorted(base.rglob(ext)):
                rel = p.relative_to(root).as_posix()
                if any(part in MODSIZE_SKIP_PARTS
                       for part in rel.split("/")):
                    continue
                if rel.endswith(MODSIZE_SKIP_SUFFIXES):
                    continue
                out.append((rel, p, cap))
    return out


def check_modsize(root):
    """Returns error strings for over-budget unpinned modules."""
    errors = []
    counts = {}
    unreadable = set()
    for rel, path, cap in _modsize_files(Path(root)):
        try:
            n = len(path.read_text(encoding="utf-8",
                                   errors="replace").splitlines())
        except OSError as exc:
            errors.append("modsize: cannot read %s: %s" % (rel, exc))
            unreadable.add(rel)
            continue
        counts[rel] = (n, cap)
        if n <= cap:
            continue
        if rel in MODSIZE_ALLOW:
            pinned, _why = MODSIZE_ALLOW[rel]
            if n > pinned:
                errors.append("modsize: %s grew to %d lines "
                              "(pinned at %d): split it" % (rel, n, pinned))
            continue
        errors.append("modsize: %s has %d lines (budget %d): split it "
                      "or add a (count, reason) pin in MODSIZE_ALLOW "
                      "in scripts/check-exposure.py" % (rel, n, cap))
    for rel, (pinned, _why) in sorted(MODSIZE_ALLOW.items()):
        if rel in unreadable:
            continue
        if rel not in counts:
            errors.append("modsize: stale pin %s: file is gone or out "
                          "of scope; remove the pin" % rel)
            continue
        n, cap = counts[rel]
        if n <= cap:
            errors.append("modsize: %s is %d lines (budget %d): "
                          "remove its pin" % (rel, n, cap))
        elif n < pinned:
            errors.append("modsize: %s shrank to %d lines "
                          "(pinned at %d): lower the pin"
                          % (rel, n, pinned))
    return errors


def self_test():
    good = "library foo\n  visibility: private\n  exposed-modules:\n    A\n"
    assert check(good) == [], "private named lib must pass"
    assert check("library\n  exposed-modules:\n    A\n") != [], "main lib must fail"
    assert check("library foo\n  exposed-modules:\n    A\n") == [], \
        "unmarked named lib must pass (private by default, probed)"
    assert check("library foo\n  visibility: public\n") != [], "public marker must fail"
    # Adversarial forms (finding one): every one of these exposes (or may
    # expose) modules, so each must fail.
    assert check("Library upper\n  visibility: public\n") != [], \
        "uppercase public header must fail"
    assert check("Library\n  exposed-modules:\n    A\n") != [], \
        "uppercase main lib must fail"
    assert check("library foo { visibility: public; exposed-modules: A }\n") != [], \
        "braced public lib must fail"
    assert check("library foo\n  visibility: private\n  if flag(x)\n"
                 "    visibility: public\n") != [], \
        "conditional public override must fail"
    assert check("library foo\n  if true\n    visibility: private\n") == [], \
        "conditional-only private must pass (default private; branch harmless)"
    assert check("common c\n  visibility: public\n"
                 "library foo\n  import: c\n") == [], \
        "common markers are ignored; unmarked lib is private by default"
    assert check("library foo\n  visibility: private\n  if flag(x)\n"
                 "    buildable: True\n  else\n    visibility: public\n") != [], \
        "else-branch public override must fail"
    assert check("library foo {\n  visibility: public;\n}\n") != [], \
        "multiline braced public lib must fail"
    assert check("library foo {\n  visibility: private;\n"
                 "  if flag(x) { visibility: public; }\n}\n") != [], \
        "braced nested conditional public must fail"
    # Honest variants that must keep passing.
    assert check("Library Upper\n  visibility: private\n") == [], \
        "uppercase private header must pass"
    assert check("library foo { visibility: private; exposed-modules: A }\n") == [], \
        "braced private lib must pass"
    assert check("library foo\r\n  visibility: private\r\n") == [], \
        "CRLF private lib must pass"
    assert check("library foo  \n  visibility: private  \n") == [], \
        "trailing whitespace must pass"
    assert check("common c\n  visibility: private\n"
                 "library foo\n  import: c\n") == [], \
        "common marker ignored; unmarked lib private by default"
    assert check("library foo\n  visibility: Private\n") == [], \
        "mixed-case private value must pass"
    assert check("library foo\n  visibility: private\n"
                 "Executable bar\n  main-is: B.hs\n") == [], \
        "uppercase non-library stanza must end the stanza and pass"
    assert check("library foo {\n  visibility: private;\n}\n") == [], \
        "multiline braced private lib must pass"
    # Round 2 (codex re-review): same-line remainder, indented
    # headers, quoted names, braced values, comments, dups.
    assert check("library demo { visibility: private } "
                 "library { exposed-modules: Demo }\n") != [], \
        "same-line main after braced sibling must fail"
    assert check("library demo {\n  visibility: private\n"
                 "} library { exposed-modules: Demo }\n") != [], \
        "same-line main after multiline braced sibling must fail"
    assert check("library demo { visibility: private }\n  LIBRARY\n"
                 "    exposed-modules: Demo\n") != [], \
        "indented main after closed sibling must fail"
    assert check("library demo { visibility: private }\n"
                 "  executable sneakpeek\n") == [], \
        "indented non-library header after braced must pass"
    assert check("description: blank\n\n  library sneaky\n"
                 "    visibility: public\n") == [], \
        "indented header after a field is a continuation: pass"
    assert check("description: x\n  see: also-x\n"
                 "library demo\n  visibility: private\n") == [], \
        "colon line deeper than a field is a continuation: pass"
    assert check("library \"new-lib\"\n  visibility: private\n") == [], \
        "quoted private name must pass"
    assert check("library \"new-lib\"\n  visibility: public\n") != [], \
        "quoted public name must fail"
    assert check("library demo\n  visibility: { private }\n") == [], \
        "braced private value must pass"
    assert check("library demo\n  visibility: { public }\n") != [], \
        "braced public value must fail"
    assert check("library demo\n  visibility: {{private}}\n") == [], \
        "nested braced private value must pass"
    assert check("library demo\n  visibility: {{public}}\n") != [], \
        "nested braced public value must fail"
    assert check("library demo\n  visibility: private\n"
                 "-- Reminder; visibility: public is prohibited.\n") == [], \
        "comment mentioning publicity must pass"
    assert check("library demo\n  visibility:\n    -- comment\n    private\n") == [], \
        "comment between visibility and its value must pass"
    assert check("library demo\n  visibility: private\n  visibility: public\n") != [], \
        "duplicate visibility last-wins: public must fail"
    assert check("library demo\n  visibility: public\n  visibility: private\n") == [], \
        "duplicate visibility last-wins: private must pass"
    assert check("library demo {\n  visibility: private\n  exposed-modules: A\n}\n") == [], \
        "newline-separated braced fields must pass"
    assert check("library a { visibility: private") != [], \
        "unbalanced braces must fail"
    assert check("common c\n  visibility: public\n"
                 "library foo\n  visibility: private\n") == [], \
        "unused public common ignored; direct private passes"
    assert check("common c\n  visibility: public\n"
                 "library foo\n  visibility: private\n  import: c\n") == [], \
        "imported public common loses to direct private (probed)"
    assert check("common c\n  if flag(x)\n    visibility: public\n"
                 "library foo\n  visibility: private\n  import: c\n") != [], \
        "conditional public in imported common must fail"
    assert check("library demo\n  visibility: private\n  if flag(test)\n"
                 "    ViSiBiLiTy:\n      public\n") != [], \
        "multiline conditional public must fail"
    assert check("library demo\n  visibility: private\n  if flag(test)\n"
                 "    visibility:\n      private\n") == [], \
        "multiline conditional private must pass"
    assert check("library demo\n  visibility: private\n  if flag(test)\n"
                 "    visibility: {\n      public\n    }\n") != [], \
        "multiline braced conditional public must fail"
    assert check("library demo\n  visibility: private\n  if flag(test)\n"
                 "    visibility: {\n      private\n    }\n") == [], \
        "multiline braced conditional private must pass"
    assert check("library demo\n  visibility: private\n  if flag(test)\n"
                 "    visibility:\n  exposed-modules: A\n") != [], \
        "conditional empty visibility must fail"
    # Round 3 (codex re-review): presence-based direct wins,
    # transitive imports, continuation-first, braced cond
    # regions, unbalanced-value append, other-stanza braces,
    # bracefield boundaries, scoped unclosed check.
    assert check("common c\n  visibility: private\n"
                 "library demo\n  import: c\n  visibility: public\n") != [], \
        "direct public beats imported private (probed)"
    assert check("common c\n  visibility: private\n"
                 "common d\n  import: c\n"
                 "library demo\n  import: d\n") == [], \
        "imports ignored; unmarked lib private by default"
    assert check("common c\n  visibility: private\n"
                 "common d\n  visibility: public\n"
                 "library demo\n  import: c, d\n") == [], \
        "mixed common markers ignored; default private passes"
    assert check("common a\n  import: b\ncommon b\n  import: a\n"
                 "library demo\n  import: a\n") == [], \
        "import cycles ignored for visibility (default private)"
    assert check("library demo\n  visibility:\n  exposed-modules: A\n") != [], \
        "direct empty visibility must fail"
    assert check("library demo\n  visibility: public\n  x-note: words\n"
                 "    visibility: private\n") != [], \
        "continuation cannot override direct public (probed)"
    assert check("library demo\n  visibility: private\n  x-note: words\n"
                 "    visibility: public\n") == [], \
        "continuation publicity is value text (probed)"
    assert check("library demo\n  visibility: private\n  library sneaky\n"
                 "    visibility: public\n") == [], \
        "indented header inside a layout body is ignored (probed)"
    assert check("library demo {\n  if flag(x) {\n    visibility: public\n  }\n"
                 "  visibility: private\n  exposed-modules: Demo\n}\n") != [], \
        "braced conditional public before direct must fail"
    assert check("library demo {\n  if flag(x) {\n"
                 "    visibility: private\n  }\n"
                 "  exposed-modules: Demo\n}\n") == [], \
        "braced conditional-only private must pass (default private)"
    assert check("library demo {\n  visibility: private;\n"
                 "  if flag(x) { visibility: public; }\n}\n") != [], \
        "single-line braced conditional public must fail"
    assert check("library demo {\n  visibility: private;\n"
                 "  if flag(x) { buildable: True } else "
                 "{ visibility: public }\n}\n") != [], \
        "braced else-branch public must fail"
    assert check("library demo\n  visibility: {\n    private\n  }\n"
                 "  exposed-modules: Demo\n") == [], \
        "multiline braced direct private must pass"
    assert check("library demo {\n  visibility: {\n    private\n  }\n"
                 "  exposed-modules: Demo\n}\n") == [], \
        "braced multiline braced direct private must pass"
    assert check("library demo {\n  visibility: {\n    public\n  }\n"
                 "  exposed-modules: Demo\n}\n") != [], \
        "braced multiline braced direct public must fail"
    assert check("flag extra {\n  default: { False }\n"
                 "} library { exposed-modules: Demo }\n") != [], \
        "main after braced non-library close must fail"
    assert check("flag extra {\n  default: { False }\n  }\n  library\n"
                 "    exposed-modules: Demo\n") != [], \
        "indented main after indented non-library close must fail"
    assert check("flag extra { default: False }\n  library\n"
                 "    exposed-modules: Demo\n") != [], \
        "indented main after one-line braced other must fail"
    assert check("description: { words }\n  library sneaky\n"
                 "    visibility: public\n") != [], \
        "indented header after brace-closed field is real (probed)"
    assert check("description: A literal opening brace { in prose.\n"
                 "library demo\n  visibility: private\n") == [], \
        "unbalanced brace in prose must pass (no stanza stuck)"
    assert check("library demo { visibility: private\n") != [], \
        "unclosed braced stanza must fail"
    assert check("source-repository head\n  type: git\n  location: x\n"
                 "library demo\n  visibility: private\n") == [], \
        "source-repository stanza is tracked as other"
    assert check("randomwords\nlibrary demo\n  visibility: private\n") == [], \
        "garbage lines terminate and are ignored (Cabal rejects)"
    assert check("library demo\n  visibility: {\nprivate\n}\n"
                 "  exposed-modules: Demo\n") == [], \
        "column-0 lines inside braces are value content (probed)"
    assert check("library demo\n  {\n    visibility: private\n  }\n"
                 "  exposed-modules: Demo\n") == [], \
        "bare-brace layout body keeps layout rules (probed)"
    # Round 4 (codex re-review + Cabal source): whole-line
    # comments, NBSP indent, brace transparency, same-line
    # library after field close, dedent splits, default private.
    assert check("library demo\n  visibility: private\n"
                 "  if flag(f)\n  {\n    visibility: public\n  }\n") != [], \
        "brace-group conditional public must fail (probed valid)"
    assert check("x-review: { note } library review-extra {\n"
                 "  visibility: public\n  exposed-modules: E\n}\n") != [], \
        "same-line library after field close is real (probed)"
    assert check("x-review: { note } library \"review-extra\" {\n"
                 "  visibility: public\n  exposed-modules: E\n}\n") != [], \
        "same-line quoted library after field close must fail"
    assert check("description: { words }\n\u00a0library sneaky\n"
                 "\u00a0  visibility: public\n") != [], \
        "NBSP header after bracefield is real (probed)"
    assert check("flag f { default: False }\n  library hidden\n"
                 "    visibility: private\n  library\n"
                 "    exposed-modules: E\n") != [], \
        "same-indent sibling after indented layout splits (probed)"
    assert check("flag f { default: False }\n  library hidden\n"
                 "    visibility: private\n library\n"
                 "    exposed-modules: E\n") != [], \
        "dedented sibling after indented layout splits (probed)"
    assert check("library demo\n  visibility: private -- ok\n") == [], \
        "trailing comment text ignored in values (first token)"
    assert check("library demo\n  visibility: public -- ok\n") != [], \
        "trailing comment cannot neutralize a public marker"
    assert check("library demo\n  visibility: private\n"
                 "  ghc-options: --sysroot=/ -DFLAG\n") == [], \
        "double-dash flags in values are literal (probed)"
    assert check("library demo -- comment\n  visibility: private\n") == [], \
        "header trailing comment stripped (section level)"
    assert check("library -- foo\n  exposed-modules: E\n") != [], \
        "main with trailing comment is still main"
    assert check("library \"a--b\" { visibility: private }\n") == [], \
        "quoted dashes in names are literal"
    assert check("library demo\n  visibility: private\n"
                 "  x-note: {a} visibility: public\n") != [], \
        "marker after a value close on its line must fail"
    assert check("library demo\n  import: c\n  exposed-modules: A\n") == [], \
        "imports never affect visibility (probed ignored)"
    assert check("description: blank\n\u00a0library sneaky\n"
                 "\u00a0  visibility: public\n") == [], \
        "NBSP after a plain field is a continuation (probed)"
    assert check("library held\n  { visibility: { private }\n"
                 "  } library { exposed-modules: Demo }\n") == [], \
        "header after a group close stays layout junk (F3b)"
    assert check("source-repository head\n  type: git\n"
                 "  x-note: { note } library sneaky "
                 "{ visibility: public }\n") != [], \
        "public marker in a nested section fails closed (un-nest)"
    # Module-size budgets (tmp trees, small files exercise the same code).
    # Live pins stay out: the fixture tree is judged on its own pins.
    real_allow = dict(MODSIZE_ALLOW)
    MODSIZE_ALLOW.clear()
    try:
        _self_test_modsize()
    finally:
        MODSIZE_ALLOW.update(real_allow)
    print("exposure self-test: ok")
    return 0


def _self_test_modsize():
    with tempfile.TemporaryDirectory(prefix="exposure-modsize") as tmp:
        root = Path(tmp)
        (root / "src").mkdir()
        (root / "src" / "Small.hs").write_text("module Small where\n")
        big = "module Big where\n" + "-- pad\n" * MODSIZE_LIB_MAX
        (root / "src" / "Big.hs").write_text(big)
        assert check_modsize(root) != [], \
            "over-budget lib module must fail"
        (root / "src" / "Big.hs").unlink()
        assert check_modsize(root) == [], \
            "in-budget tree must pass"
        (root / "src" / "Big.hs").write_text(big)
        MODSIZE_ALLOW["src/Big.hs"] = (MODSIZE_LIB_MAX + 1, "fixture pin")
        try:
            assert check_modsize(root) == [], \
                "pinned module at its pin must pass"
            (root / "src" / "Big.hs").write_text(big + "-- one more\n")
            assert check_modsize(root) != [], \
                "pinned module grown past its pin must fail"
        finally:
            del MODSIZE_ALLOW["src/Big.hs"]
        (root / "src" / "Big.hs").unlink()
        MODSIZE_ALLOW["src/Gone.hs"] = (MODSIZE_LIB_MAX + 5, "fixture pin")
        try:
            assert check_modsize(root) != [], \
                "pin without a file must fail"
        finally:
            del MODSIZE_ALLOW["src/Gone.hs"]
        (root / "src" / "Big.hs").write_text(big)
        MODSIZE_ALLOW["src/Big.hs"] = (MODSIZE_LIB_MAX + 5, "fixture pin")
        try:
            assert check_modsize(root) != [], \
                "pin above the file must fail (lower the pin)"
        finally:
            del MODSIZE_ALLOW["src/Big.hs"]
        small = "module Small2 where\n"
        (root / "src" / "Small2.hs").write_text(small)
        MODSIZE_ALLOW["src/Small2.hs"] = (MODSIZE_LIB_MAX + 5, "fixture pin")
        try:
            assert check_modsize(root) != [], \
                "pin on an in-budget file must fail (remove the pin)"
        finally:
            del MODSIZE_ALLOW["src/Small2.hs"]
        (root / "src" / "Small2.hs").unlink()
        (root / "src" / "Big.hs").unlink()
        (root / "ffi").mkdir()
        (root / "ffi" / "Huge.hs").write_text(big + big)
        (root / "src" / "Generated").mkdir()
        (root / "src" / "Generated" / "Foo.hs").write_text(big)
        gen = root / "src" / "WidgetGenerated.hs"
        gen.write_text(big + big)
        errs = check_modsize(root)
        assert len(errs) == 1 and "src/Generated/Foo.hs" in errs[0], \
            "a Generated/ directory must not exclude its files"
        (root / "src" / "Generated" / "Foo.hs").unlink()
        assert check_modsize(root) == [], \
            "top-level ffi/ is not walked; *Generated.hs is skipped"
        (root / "src" / "dist-newstyle").mkdir()
        (root / "src" / "dist-newstyle" / "Copy.hs").write_text(big + big)
        (root / "test").mkdir()
        (root / "test" / "Main.hs").write_text(big + big + big + big)
        errs = check_modsize(root)
        assert len(errs) == 1 and "test/Main.hs" in errs[0], \
            "test/ counts, dist-newstyle/ does not"


def main():
    if "--self-test" in sys.argv[1:]:
        return self_test()
    errors = check(CABAL.read_text())
    errors.extend(check_modsize(REPO))
    if errors:
        for e in errors:
            print("exposure: %s" % e)
        return 1
    print("exposure: ok (no public Haskell library; modules within budget)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
