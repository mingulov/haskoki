# check-ossl4-hooks.awk — the HSK_OSSL4_TEST_HOOKS macro belongs to the
# private implementation library stanza only. Prints lines OUTSIDE that
# stanza (comments stripped); the caller fails if the macro appears in
# the output. Usage:
#   awk -f scripts/check-ossl4-hooks.awk haskoki.cabal | grep -q MACRO
#
# Handles: case-insensitive stanza kinds, any blank layout, CRLF,
# braced stanzas, `}`-headers (a header after a closing brace is a
# valid stanza start), boundary-indented headers. Braces suspend
# layout (column-0 lines inside braces are content). Fail-closed:
# unrecognized structure ends the internal mode and alarms. NBSP
# indent is NOT recognized (Cabal rejects it loudly); a macro
# there alarms here too.
BEGIN {
  kinds["library"]; kinds["common"]; kinds["executable"]
  kinds["test-suite"]; kinds["benchmark"]; kinds["foreign-library"]
  kinds["flag"]; kinds["source-repository"]; kinds["custom-setup"]
  lib = 0        # inside haskoki-internal
  cur_braced = 0 # current stanza opened with an unbalanced brace
  depth = 0      # global brace depth (clamped)
  boundary = 1   # no open stanza and no open field
}
function is_header(word) {
  return (tolower(word) in kinds)
}
function head_word(seg,   w) {
  w = seg
  sub(/^[[:blank:]]+/, "", w)
  sub(/[[:blank:]].*$/, "", w)
  sub(/\{.*$/, "", w)
  return w
}
function stanza_name(seg,   rest, name) {
  rest = seg
  sub(/^[[:blank:]]*[^[:blank:]]+[[:blank:]]+/, "", rest)
  name = rest
  sub(/[[:blank:]].*$/, "", name)
  sub(/\{.*$/, "", name)
  return name
}
{
  line = $0
  sub(/\r$/, "", line)
  # Only whole-line comments exist: `--` inside values is
  # literal text (probed: `--opt` flags reach the compiler).
  sub(/^[[:blank:]]*--.*$/, "", line)
  if (line ~ /^[[:blank:]]*$/) next
  # Split `}`-headers: `} foreign-library x` starts a new stanza.
  # Each split consumes its `}` (depth + close checks); the head
  # keeps the original indent, the remainder is col-0-equivalent.
  rest = line
  n = 0
  delete parts
  delete pind
  while (match(rest, /\}[[:blank:]]*[A-Za-z][A-Za-z0-9-]*/)) {
    head = substr(rest, 1, RSTART - 1)
    word = substr(rest, RSTART + 1)
    sub(/^[[:blank:]]+/, "", word)
    sub(/[[:blank:]].*$/, "", word)
    if (!is_header(word)) break
    n++
    parts[n] = head "}"
    pind[n] = (line ~ /^[^[:blank:]]/) ? 0 : 1
    rest = substr(rest, RSTART + 1)
    sub(/^[[:blank:]]+/, "", rest)
  }
  n++
  parts[n] = rest
  pind[n] = (n == 1) ? ((line ~ /^[^[:blank:]]/) ? 0 : 1) : 0
  for (p = 1; p <= n; p++) {
    seg = parts[p]
    if (seg ~ /^[[:blank:]]*$/) continue
    seg_indent = pind[p]
    tmp = seg
    opens = gsub(/\{/, "{", tmp)
    tmp = seg
    closes = gsub(/\}/, "}", tmp)
    net = opens - closes
    entry_depth = depth
    depth += net
    if (depth < 0) depth = 0
    # A close ends the internal mode when it empties a braced
    # stanza, or when it is stray at depth zero (fail closed;
    # value-closes inside an open level never end it).
    if (lib && net < 0 && seg ~ /\}[[:blank:]]*$/ \
        && (entry_depth == 0 || (cur_braced && depth == 0))) {
      lib = 0
      cur_braced = 0
      boundary = 1
    }
    if (seg_indent == 0 && entry_depth == 0) {
      # Column 0 outside braces closes any stanza; classify it.
      word = head_word(seg)
      if (is_header(word)) {
        lib = 0
        cur_braced = (net > 0)
        boundary = 0
        if (net == 0 && opens > 0) {
          # Single-line closed: complete already.
          cur_braced = 0
          boundary = 1
        }
        if (tolower(word) == "library" \
            && stanza_name(seg) == "haskoki-internal") {
          if (boundary) continue  # closed already; own line
          lib = 1
          continue  # its own line belongs to the stanza
        }
        print seg
        continue
      }
      lib = 0
      cur_braced = 0
      if (seg ~ /^[A-Za-z][A-Za-z0-9-]*[[:blank:]]*:/) {
        # Top-level field: a brace-balanced close makes a
        # boundary (probed); otherwise continuations own the
        # following indented lines.
        boundary = (index(seg, "}") > 0 && closes >= opens) ? 1 : 0
      } else {
        # Garbage: Cabal rejects it loudly; stay loud too.
        boundary = 1
      }
      print seg
      continue
    }
    if (entry_depth == 0 && boundary && is_header(head_word(seg))) {
      # Boundary-indented header (probed valid).
      word = head_word(seg)
      lib = 0
      cur_braced = (net > 0)
      boundary = 0
      if (net == 0 && opens > 0) {
        cur_braced = 0
        boundary = 1
      }
      if (tolower(word) == "library" \
          && stanza_name(seg) == "haskoki-internal") {
        if (boundary) continue  # closed already; own line
        lib = 1
        continue  # its own line belongs to the stanza
      }
      print seg
      continue
    }
    # Content (in braces, in a stanza body, or boundary
    # garbage): visible unless inside the internal stanza.
    if (!lib) print seg
  }
}
