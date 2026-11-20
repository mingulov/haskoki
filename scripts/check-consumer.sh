#!/bin/sh
# Out-of-tree consumer check: no downstream package can depend on
# any Haskell library of this package (R-09a). Runs one fixture
# probe project per library (main + every named library); each
# probe must FAIL with a dependency-resolution error. Probes live
# in SEPARATE projects because Cabal solves a whole project
# before selecting targets (probed with the pinned toolchain):
# probes sharing one project cannot fail independently. Run from
# anywhere:
#   bash scripts/check-consumer.sh
# Needs cabal + network on first run (dependency download); the
# package store is shared with the caller's CABAL_DIR. Shell
# only (no python3): this check also runs inside the docker
# toolchain image, which has no Python.
set -u
HERE=$(dirname "$0")
ROOT="$HERE/.."
FIXTURE="$HERE/consumer-fixture"
# Coverage: every library needs its probe project. A new named
# library without a probe would leave a re-exposed facade
# undetected. Stale = loud error, never silent skip. Quoted and
# indented headers fail closed (rename/dedent, or reword the
# prose line).
STALE=0
if grep -qiE '(^|[}])[[:blank:]]*library[[:blank:]]+"' "$ROOT/haskoki.cabal"; then
  echo "consumer: FAIL - quoted library name in haskoki.cabal (rename to unquoted)"
  STALE=1
fi
if grep -qiE '^[[:blank:]]+library([[:blank:]]+[A-Za-z0-9-]+)?[[:blank:]]*(\{|$|--)' "$ROOT/haskoki.cabal"; then
  echo "consumer: FAIL - indented library header in haskoki.cabal (dedent to column 0)"
  STALE=1
fi
# exe_deps prints a probe package's build-depends block lines
# (comment-stripped, CR-stripped): dependency text anywhere else
# (synopsis, description, comments) never counts as coverage.
exe_deps() { # $1 = probe package .cabal path
  tr -d '\r' < "$1" | sed 's/--.*$//' | awk '
    /^[[:blank:]]*$/ { next }
    /^[^[:blank:]]/ { exe = (tolower($1) == "executable"); bd = 0; next }
    !exe { next }
    /build-depends[[:blank:]]*:/ { match($0, /[^[:blank:]]/); bdind = RSTART - 1; sub(/^[^:]*:/, ""); print; bd = 1; next }
    !bd { next }
    {
      match($0, /[^[:blank:]]/); ind = RSTART - 1
      if ($0 ~ /^[[:blank:]]+[A-Za-z][A-Za-z0-9-]*[[:blank:]]*:/ && ind <= bdind) { bd = 0; next }
      print
    }
  '
}
need_probe() { # $1 = probe dir, $2 = ERE for its required dep
  dir="$FIXTURE/$1"
  cabal="$dir/$1.cabal"
  if [ ! -d "$dir" ]; then
    echo "consumer: FAIL - fixture has no $1 probe project (stale)"
    STALE=1
    return
  fi
  if [ ! -f "$cabal" ] \
     || ! tr -d '\r' < "$cabal" \
        | grep -qE '^[Ee][Xx][Ee][Cc][Uu][Tt][Aa][Bb][Ll][Ee][[:blank:]]+probe([[:blank:]]|$)'; then
    echo "consumer: FAIL - $1 has no 'executable probe' (stale)"
    STALE=1
    return
  fi
  if ! exe_deps "$cabal" | grep -qE "$2"; then
    echo "consumer: FAIL - $1 does not depend on its library (stale)"
    STALE=1
  fi
}
need_probe probe-main '(^[[:blank:]]*|,[[:blank:]]*)haskoki([[:blank:]]*(,|$))'
all_libs() {
  tr -d '\r' < "$ROOT/haskoki.cabal" \
    | grep -ioE '^library[[:blank:]]+[A-Za-z0-9-]+' | awk '{print $2}'
  tr -d '\r' < "$ROOT/haskoki.cabal" \
    | grep -ioE '[}][[:blank:]]*library[[:blank:]]+[A-Za-z0-9-]+' \
    | sed 's/^[^l]*library[[:blank:]][[:blank:]]*//'
}
for lib in $(all_libs); do
  need_probe "probe-$lib" "(^[[:blank:]]*|,[[:blank:]]*)haskoki:$lib(,|[[:blank:]]|$)"
done
[ "$STALE" -eq 0 ] || exit 1
probe() { # $1 = probe dir/name, $2 = expected diagnostic
  dir="$FIXTURE/$1"
  LOG="${TMPDIR:-/tmp}/consumer-$1-$$.log"
  rm -f "$LOG"
  if (cd "$dir" && cabal build exe:probe >"$LOG" 2>&1); then
    echo "consumer: FAIL - probe $1 built: out-of-tree import still possible"
    return 1
  fi
  # The solver pretty-prints diagnostics with wrapping, so match
  # on whitespace-squashed text. Each single-goal project fails
  # with its own diagnostic; anything else (a resolution, a
  # broken toolchain, a changed message) is a loud failure. The
  # pinned toolchain (cabal-install 3.12.1.0) fixes the wording:
  # a toolchain upgrade that rewords diagnostics fails this check
  # until a human re-pins the expectations below.
  SQUASHED=$(tr -s '[:space:]' ' ' < "$LOG")
  if echo "$SQUASHED" | grep -q "will be built"; then
    echo "consumer: FAIL - probe $1 resolved (expected a resolution failure):"
    tail -n 15 "$LOG"
    return 1
  fi
  if echo "$SQUASHED" | grep -q "Could not resolve dependencies" \
     && echo "$SQUASHED" | grep -qF "$1" \
     && echo "$SQUASHED" | grep -qF "$2"; then
    return 0
  fi
  echo "consumer: FAIL - probe $1 failed for the wrong reason:"
  tail -n 15 "$LOG"
  return 1
}
FAIL=0
for d in "$FIXTURE"/probe-*/; do
  pkg=$(basename "$d")
  if [ "$pkg" = "probe-main" ]; then
    probe "$pkg" "requires library from haskoki, but the component does not exist" || FAIL=1
  else
    lib=${pkg#probe-}
    probe "$pkg" "requires library '$lib' from haskoki, but the component is private" || FAIL=1
  fi
done
if [ "$FAIL" -eq 0 ]; then
  echo "consumer: ok (no public Haskell library to depend on)"
fi
exit "$FAIL"
