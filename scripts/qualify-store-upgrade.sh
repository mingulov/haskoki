#!/usr/bin/env bash
# scripts/qualify-store-upgrade.sh -- old/new installed-binary store lane (opt-in).
#
# Drives the RELEASED v0.3.1.0 / v0.4.0.0 modules and the NEW build's
# haskoki-ctl and libhaskoki.so as installed binaries (subprocesses,
# never library calls) over disposable copies of the committed
# released-binary fixtures: check -> refused new open -> migrate ->
# new open and logins -> old-binary downgrade refusal -> restore ->
# old binary opens the restored backup -> check again, plus per-tag
# journal recovery: a planted cold journal clears through migrate
# (check names it, migrate records the clearing) and a planted hot
# journal stays refused with nothing written. Old-module digests are
# asserted against the fixture manifests; every refusal asserts its
# specific tag. A schema-3 cold journal needs nothing and stays
# untouched.
#
# Not a test-*.sh driver: it needs the downloaded, verified release
# bundles (ws/plans/2026-10-15-v050-wp05.md, Task 2), which the
# release-evidence runner does not provision. WP14 decides promotion.
#
# Usage (from haskoki/): scripts/qualify-store-upgrade.sh BUNDLES_DIR [EVIDENCE_DIR]
#   HASKOKI_CTL     new haskoki-ctl   (default: cabal list-bin haskoki-ctl)
#   HASKOKI_MODULE  new libhaskoki.so (default: the one dist-newstyle build)
set -euo pipefail
umask 022
cd "$(dirname "$0")/.."
BUNDLES=${1:?usage: qualify-store-upgrade.sh BUNDLES_DIR [EVIDENCE_DIR]}
EVID=${2:-$(mktemp -d "${TMPDIR:-/tmp}/haskoki-qualify-store-XXXXXX")}
mkdir -p "$EVID"
CTL=${HASKOKI_CTL:-$(cabal list-bin haskoki-ctl)}
if [ -z "${HASKOKI_MODULE:-}" ]; then
  mapfile -t mods < <(find dist-newstyle -name 'libhaskoki.so' -type f | sort)
  [ "${#mods[@]}" -eq 1 ] || { echo "qualify-store-upgrade: FAIL: want exactly one built libhaskoki.so, found ${#mods[@]}" >&2; exit 1; }
  HASKOKI_MODULE=${mods[0]}
fi
NEW=$HASKOKI_MODULE
PINS='58213946|69324057|12873465|23984576|34095687'
fail() { echo "qualify-store-upgrade: FAIL: $*" >&2; exit 1; }
sha() { sha256sum "$1" | cut -d' ' -f1; }
[ -d "$BUNDLES" ] || fail "bundles dir missing: $BUNDLES"
command -v pkcs11-tool >/dev/null 2>&1 || fail "pkcs11-tool missing from PATH"
command -v dpkg-query >/dev/null 2>&1 || fail "dpkg-query missing from PATH"
[ -x "$CTL" ] || fail "new haskoki-ctl missing or not executable: $CTL"
[ -f "$NEW" ] || fail "new libhaskoki.so missing: $NEW"
[ -f tests/fixtures/stores/config.toml.in ] || fail "config template missing"
for t in v0.3.1.0 v0.4.0.0; do
  [ -f "$BUNDLES/$t/haskoki-${t#v}/lib/libhaskoki.so" ] || fail "$t: old module missing"
  [ -f "tests/fixtures/stores/$t/store.sqlite" ] || fail "$t: fixture store missing"
done
{
  echo "ctl: $CTL $(sha "$CTL")"; "$CTL" --version
  echo "module: $NEW $(sha "$NEW")"
  echo "opensc: $(dpkg-query -W -f='${Version}' opensc)"
  for t in v0.3.1.0 v0.4.0.0; do
    echo "$t module: $(sha "$BUNDLES/$t/haskoki-${t#v}/lib/libhaskoki.so")"
  done
} > "$EVID/versions.txt"

run_tag() {
  local tag=$1 ver=${1#v} rc
  local old="$BUNDLES/$tag/haskoki-$ver/lib/libhaskoki.so"
  local want_lib; want_lib=$(sed -n 's/^libhaskoki-sha256: //p' "tests/fixtures/stores/$tag/manifest.txt")
  [ -n "$want_lib" ] || fail "$tag: manifest libhaskoki-sha256 missing"
  [ "$(sha "$old")" = "$want_lib" ] || fail "$tag: old module digest differs from the manifest"
  local w="$EVID/$tag"
  mkdir -p "$w/backups"
  cp "tests/fixtures/stores/$tag/store.sqlite" "$w/store.sqlite"
  chmod 600 "$w/store.sqlite"
  sed "s#@STORE@#$w/store.sqlite#" tests/fixtures/stores/config.toml.in > "$w/config.toml"
  export HASKOKI_CONFIG="$w/config.toml"
  local s0; s0=$(sha "$w/store.sqlite")

  set +e; "$CTL" store check --path "$w/store.sqlite" --config "$w/config.toml" >"$w/check1.out" 2>"$w/check1.err"; rc=$?; set -e
  [ "$rc" -eq 1 ] && grep -qx 'verdict: migration-required' "$w/check1.out" || fail "$tag: check before migrate"
  grep -q '^store-migration-required:' "$w/check1.err" || fail "$tag: check1 stderr tag"
  [ "$(sha "$w/store.sqlite")" = "$s0" ] || fail "$tag: check wrote the store"
  [ ! -e "$w/store.sqlite.lock" ] || fail "$tag: check left a lock"

  if pkcs11-tool --module "$NEW" -L >"$w/new-open-old.out" 2>&1; then fail "$tag: new module opened an old store"; fi
  grep -q 'CKR_GENERAL_ERROR' "$w/new-open-old.out" || fail "$tag: new-open-old is not the GENERAL_ERROR refusal"
  [ "$(sha "$w/store.sqlite")" = "$s0" ] || fail "$tag: refused new open wrote the store"

  "$CTL" store migrate --path "$w/store.sqlite" --config "$w/config.toml" --backup-dir "$w/backups" \
    >"$w/migrate.out" 2>"$w/migrate.err" || fail "$tag: migrate"
  grep -qx 'migrate-done' "$w/migrate.out" || fail "$tag: migrate-done missing"
  local bak; bak=$(sed -n 's/^backup: //p' "$w/migrate.out")
  [ "$(sha "$bak")" = "$s0" ] || fail "$tag: backup differs from the pre-migration store"
  grep -qx "backup-sha256: $s0" "$bak.receipt" || fail "$tag: receipt digest"
  grep -qx 'cold-journal-removed: no' "$w/migrate.out" || fail "$tag: migrate output misses cold-journal-removed no"
  grep -qx 'cold-journal-removed: no' "$bak.receipt" || fail "$tag: receipt misses cold-journal-removed no"
  if grep -qE "$PINS" "$w/check1.out" "$w/check1.err" "$w/migrate.out" "$w/migrate.err" "$bak.receipt"; then
    fail "$tag: a PIN value reached output or the receipt"
  fi

  pkcs11-tool --module "$NEW" -L >"$w/new-open.out" || fail "$tag: new module after migrate"
  pkcs11-tool --module "$NEW" --slot-index 0 --login --pin 12873465 --list-objects >"$w/objects.out" \
    || fail "$tag: frozen token-1 user PIN"
  grep -q 'fixture-ec' "$w/objects.out" || fail "$tag: fixture key lost"
  if [ "$tag" = v0.4.0.0 ]; then
    pkcs11-tool --module "$NEW" --slot-index 1 --login --pin 34095687 --list-objects >/dev/null \
      || fail "$tag: the in-band PIN row was not preserved"
    if pkcs11-tool --module "$NEW" --slot-index 1 --login --pin 23984576 --list-objects >/dev/null 2>&1; then
      fail "$tag: a config PIN replaced a durable row"
    fi
  else
    pkcs11-tool --module "$NEW" --slot-index 1 --login --pin 23984576 --list-objects >/dev/null \
      || fail "$tag: frozen token-2 user PIN"
  fi

  local s1; s1=$(sha "$w/store.sqlite")
  if pkcs11-tool --module "$old" -L >"$w/old-open-migrated.out" 2>&1; then fail "$tag: old module opened a schema-3 store"; fi
  grep -q 'CKR_GENERAL_ERROR' "$w/old-open-migrated.out" || fail "$tag: old-open-migrated is not the GENERAL_ERROR refusal"
  [ "$(sha "$w/store.sqlite")" = "$s1" ] || fail "$tag: old module wrote the migrated store"
  {
    echo "after old open of migrated store (expected refusal):"
    ls -l "$w/store.sqlite.lock" 2>&1 || echo "no sidecar lock"
  } > "$w/old-lock-migrated.txt" 2>&1

  mv "$w/store.sqlite" "$w/store.sqlite.migrated"
  cp "$bak" "$w/store.sqlite"
  pkcs11-tool --module "$old" -L >"$w/old-open-restored.out" || fail "$tag: old module cannot open the restored backup"
  pkcs11-tool --module "$old" --slot-index 0 --login --pin 12873465 --list-objects >"$w/old-objects.out" \
    || fail "$tag: old module login on the restored backup"
  {
    echo "after old open of restored backup:"
    ls -l "$w/store.sqlite.lock" 2>&1 || echo "no sidecar lock"
  } > "$w/old-lock-restored.txt" 2>&1
  set +e; "$CTL" store check --path "$w/store.sqlite" --config "$w/config.toml" >"$w/check2.out" 2>"$w/check2.err"; rc=$?; set -e
  [ "$rc" -eq 1 ] && grep -qx 'verdict: migration-required' "$w/check2.out" || fail "$tag: restored store not migration-required"
  grep -q '^store-migration-required:' "$w/check2.err" || fail "$tag: check2 stderr tag"

  local rcw="$w/recovery-cold"
  mkdir -p "$rcw/backups"
  cp "$bak" "$rcw/store.sqlite"
  chmod 600 "$rcw/store.sqlite"
  sed "s#@STORE@#$rcw/store.sqlite#" tests/fixtures/stores/config.toml.in > "$rcw/config.toml"
  local s_cold; s_cold=$(sha "$rcw/store.sqlite")
  head -c 512 /dev/zero > "$rcw/store.sqlite-journal"
  local j_cold; j_cold=$(sha "$rcw/store.sqlite-journal")
  set +e; "$CTL" store check --path "$rcw/store.sqlite" --config "$rcw/config.toml" >"$w/recovery-cold.check.out" 2>"$w/recovery-cold.check.err"; rc=$?; set -e
  [ "$rc" -eq 1 ] || fail "$tag: cold journal check exit"
  grep -q '^store-journal-cold:' "$w/recovery-cold.check.err" || fail "$tag: cold journal check tag"
  grep -q 'store migrate' "$w/recovery-cold.check.err" || fail "$tag: cold journal remedy"
  [ "$(sha "$rcw/store.sqlite")" = "$s_cold" ] || fail "$tag: cold journal check wrote the store"
  [ "$(sha "$rcw/store.sqlite-journal")" = "$j_cold" ] || fail "$tag: cold journal check wrote the journal"
  "$CTL" store migrate --path "$rcw/store.sqlite" --config "$rcw/config.toml" --backup-dir "$rcw/backups" \
    >"$w/recovery-cold.migrate.out" 2>"$w/recovery-cold.migrate.err" || fail "$tag: cold journal migrate"
  grep -qx 'migrate-done' "$w/recovery-cold.migrate.out" || fail "$tag: cold journal migrate-done missing"
  grep -qx 'cold-journal-removed: yes' "$w/recovery-cold.migrate.out" || fail "$tag: cold journal stdout line"
  local bak_cold; bak_cold=$(sed -n 's/^backup: //p' "$w/recovery-cold.migrate.out")
  [ "$(sha "$bak_cold")" = "$s_cold" ] || fail "$tag: cold journal backup differs"
  grep -qx "backup-sha256: $s_cold" "$bak_cold.receipt" || fail "$tag: cold journal receipt digest"
  grep -qx 'cold-journal-removed: yes' "$bak_cold.receipt" || fail "$tag: cold journal receipt line"
  [ ! -e "$rcw/store.sqlite-journal" ] || fail "$tag: cold journal not removed"
  if grep -qE "$PINS" "$w/recovery-cold.check.out" "$w/recovery-cold.check.err" "$w/recovery-cold.migrate.out" "$w/recovery-cold.migrate.err" "$bak_cold.receipt"; then
    fail "$tag: cold journal PIN leak"
  fi
  export HASKOKI_CONFIG="$rcw/config.toml"
  pkcs11-tool --module "$NEW" -L >"$w/recovery-cold.new-open.out" || fail "$tag: new module after cold clear"
  export HASKOKI_CONFIG="$w/config.toml"

  local rhw="$w/recovery-hot"
  mkdir -p "$rhw/backups"
  cp "$bak" "$rhw/store.sqlite"
  chmod 600 "$rhw/store.sqlite"
  sed "s#@STORE@#$rhw/store.sqlite#" tests/fixtures/stores/config.toml.in > "$rhw/config.toml"
  local s_hot; s_hot=$(sha "$rhw/store.sqlite")
  printf '\xd9\xd5\x05\xf9\x20\xa1\x63\xd7' > "$rhw/store.sqlite-journal"
  head -c 504 /dev/zero >> "$rhw/store.sqlite-journal"
  local j_hot; j_hot=$(sha "$rhw/store.sqlite-journal")
  set +e; "$CTL" store check --path "$rhw/store.sqlite" --config "$rhw/config.toml" >"$w/recovery-hot.check.out" 2>"$w/recovery-hot.check.err"; rc=$?; set -e
  [ "$rc" -eq 1 ] || fail "$tag: hot journal check exit"
  grep -q '^store-journal-present:' "$w/recovery-hot.check.err" || fail "$tag: hot journal check tag"
  [ "$(sha "$rhw/store.sqlite")" = "$s_hot" ] || fail "$tag: hot journal check wrote the store"
  [ "$(sha "$rhw/store.sqlite-journal")" = "$j_hot" ] || fail "$tag: hot journal check wrote the journal"
  set +e; "$CTL" store migrate --path "$rhw/store.sqlite" --config "$rhw/config.toml" --backup-dir "$rhw/backups" \
    >"$w/recovery-hot.migrate.out" 2>"$w/recovery-hot.migrate.err"; rc=$?; set -e
  [ "$rc" -eq 1 ] || fail "$tag: hot journal migrate exit"
  grep -q '^store-journal-present:' "$w/recovery-hot.migrate.err" || fail "$tag: hot journal migrate tag"
  [ "$(sha "$rhw/store.sqlite")" = "$s_hot" ] || fail "$tag: hot journal migrate wrote the store"
  [ "$(sha "$rhw/store.sqlite-journal")" = "$j_hot" ] || fail "$tag: hot journal migrate wrote the journal"
  [ -z "$(ls -A "$rhw/backups")" ] || fail "$tag: hot journal migrate wrote a backup"
  if grep -qE "$PINS" "$w/recovery-hot.check.out" "$w/recovery-hot.check.err" "$w/recovery-hot.migrate.out" "$w/recovery-hot.migrate.err"; then
    fail "$tag: hot journal PIN leak"
  fi

  local r3w="$w/recovery-cold-current"
  mkdir -p "$r3w/backups"
  [ -f "$w/store.sqlite.migrated" ] || fail "$tag: migrated store missing for the current cold case"
  cp "$w/store.sqlite.migrated" "$r3w/store.sqlite"
  chmod 600 "$r3w/store.sqlite"
  sed "s#@STORE@#$r3w/store.sqlite#" tests/fixtures/stores/config.toml.in > "$r3w/config.toml"
  set +e; "$CTL" store check --path "$r3w/store.sqlite" --config "$r3w/config.toml" >"$w/recovery-cold-current.pre.out" 2>"$w/recovery-cold-current.pre.err"; rc=$?; set -e
  [ "$rc" -eq 0 ] && grep -qx 'verdict: ok' "$w/recovery-cold-current.pre.out" || fail "$tag: current cold premise not openable"
  local s_r3; s_r3=$(sha "$r3w/store.sqlite")
  head -c 512 /dev/zero > "$r3w/store.sqlite-journal"
  local j_r3; j_r3=$(sha "$r3w/store.sqlite-journal")
  set +e; "$CTL" store check --path "$r3w/store.sqlite" --config "$r3w/config.toml" >"$w/recovery-cold-current.check.out" 2>"$w/recovery-cold-current.check.err"; rc=$?; set -e
  [ "$rc" -eq 0 ] || fail "$tag: current cold check exit"
  grep -qx 'verdict: ok' "$w/recovery-cold-current.check.out" || fail "$tag: current cold verdict"
  grep -qx 'journal: cold (harmless; reused by the next write)' "$w/recovery-cold-current.check.out" || fail "$tag: current cold journal line"
  [ ! -s "$w/recovery-cold-current.check.err" ] || fail "$tag: current cold stderr not empty"
  [ "$(sha "$r3w/store.sqlite")" = "$s_r3" ] || fail "$tag: current cold check wrote the store"
  [ "$(sha "$r3w/store.sqlite-journal")" = "$j_r3" ] || fail "$tag: current cold check wrote the journal"
  set +e; "$CTL" store migrate --path "$r3w/store.sqlite" --config "$r3w/config.toml" --backup-dir "$r3w/backups" \
    >"$w/recovery-cold-current.migrate.out" 2>"$w/recovery-cold-current.migrate.err"; rc=$?; set -e
  [ "$rc" -eq 0 ] || fail "$tag: current cold migrate exit"
  grep -q '^migrate-not-needed:' "$w/recovery-cold-current.migrate.out" || fail "$tag: current cold migrate tag"
  [ "$(sha "$r3w/store.sqlite")" = "$s_r3" ] || fail "$tag: current cold migrate wrote the store"
  [ "$(sha "$r3w/store.sqlite-journal")" = "$j_r3" ] || fail "$tag: current cold migrate touched the journal"
  [ -z "$(ls -A "$r3w/backups")" ] || fail "$tag: current cold migrate wrote a backup"
  if grep -qE "$PINS" "$w/recovery-cold-current.check.out" "$w/recovery-cold-current.check.err" "$w/recovery-cold-current.migrate.out" "$w/recovery-cold-current.migrate.err"; then
    fail "$tag: current cold PIN leak"
  fi

  unset HASKOKI_CONFIG
  echo "$tag: ok"
}

run_tag v0.3.1.0
run_tag v0.4.0.0
echo "PASS: qualify-store-upgrade.sh (evidence: $EVID)"
