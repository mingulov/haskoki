#!/usr/bin/env bash
# scripts/make-store-fixtures.sh -- regenerate the released-binary store fixtures.
#
# Builds tests/fixtures/stores/<tag>/store.sqlite with the RELEASED
# libhaskoki.so of v0.3.1.0 and v0.4.0.0 (driven by OpenSC pkcs11-tool)
# and records provenance in tests/fixtures/stores/<tag>/manifest.txt:
# bundle digest, module/ctl/toolchain-record digests, tool versions,
# the resulting store digest and its schema/token/credential shape.
# Fixture PINs are example-grade test values, recorded on purpose.
#
# Usage (from haskoki/): scripts/make-store-fixtures.sh BUNDLES_DIR
#   BUNDLES_DIR/<tag>/ holds the downloaded, digest-verified asset and
#   SHA256SUMS plus the extracted haskoki-<ver>/ bundle.
set -euo pipefail
umask 022
cd "$(dirname "$0")/.."
BUNDLES=${1:?usage: make-store-fixtures.sh BUNDLES_DIR}
OUT=tests/fixtures/stores
command -v pkcs11-tool >/dev/null || { echo "pkcs11-tool missing" >&2; exit 1; }
OPENSC=$(dpkg-query -W -f='${Version}' opensc)
PYSQL=$(python3 -I -c 'import sys, sqlite3; print(sys.version.split()[0], "sqlite", sqlite3.sqlite_version)')
GEN_SHA=$(sha256sum scripts/make-store-fixtures.sh | cut -d' ' -f1)
TMPL_SHA=$(sha256sum "$OUT/config.toml.in" | cut -d' ' -f1)
declare -A PINNED=(
  [v0.3.1.0]=8e77b8fdb15b68b5e0a42a63798fc6ce30a003e0163fce34728bee754aa107fa
  [v0.4.0.0]=4561b0c9df95a0ee7ed514a617faa9b8dc51262402a3b97790286262bcfe02b5
)
sha() { sha256sum "$1" | cut -d' ' -f1; }

shape() {  # read-only shape of a store: schema, tokens, credentials, objects
  python3 -I - "$1" <<'PY'
import sqlite3, sys
db = sqlite3.connect("file:" + sys.argv[1] + "?mode=ro", uri=True)
q = lambda s: [r[0] for r in db.execute(s)]
tables = q("SELECT name FROM sqlite_master WHERE type = 'table'")
print("schema-version:", q("SELECT value FROM store_meta WHERE key = 'schema_version'")[0])
print("tokens:", " ".join(q("SELECT token_id FROM tokens ORDER BY token_id")) or "none")
creds = q("SELECT token_id FROM credentials ORDER BY token_id") if "credentials" in tables else []
print("credentials:", " ".join(creds) or "none")
print("objects:", q("SELECT COUNT(*) FROM objects")[0])
PY
}

make_one() {
  local tag=$1 ver=${1#v}
  local dir="$BUNDLES/$tag" bundle="$BUNDLES/$tag/haskoki-$ver"
  local asset="haskoki-$ver-linux-x86_64.tar.gz"
  [ "$(sha "$dir/$asset")" = "${PINNED[$tag]}" ] || { echo "$tag: bundle digest mismatch" >&2; exit 1; }
  local lib="$bundle/lib/libhaskoki.so" ctl="$bundle/bin/haskoki-ctl"
  local work; work=$(mktemp -d "${TMPDIR:-/tmp}/haskoki-fixture-$tag-XXXXXX")
  sed "s#@STORE@#$work/store.sqlite#" "$OUT/config.toml.in" > "$work/config.toml"
  export HASKOKI_CONFIG="$work/config.toml"
  pkcs11-tool --module "$lib" --list-slots > "$work/slots.txt"
  pkcs11-tool --module "$lib" --slot-index 0 --login --pin 12873465 \
    --keypairgen --key-type EC:prime256v1 --label fixture-ec --id 01 > "$work/keygen.txt"
  if [ "$tag" = v0.4.0.0 ]; then
    pkcs11-tool --module "$lib" --slot-index 1 --login --pin 23984576 \
      --change-pin --new-pin 34095687 > "$work/change-pin.txt"
  fi
  unset HASKOKI_CONFIG
  [ ! -s "$work/store.sqlite-journal" ] || { echo "$tag: journal left behind" >&2; exit 1; }
  # A released module may leave its sidecar lock behind at process exit;
# that is acceptable only when the recorded owner is gone. The lock is
# never copied into the fixture.
local lock_note=none
if [ -e "$work/store.sqlite.lock" ]; then
  local owner; owner=$(tr -d '[:space:]' < "$work/store.sqlite.lock")
  if [ -d "/proc/$owner" ]; then echo "$tag: live lock owner $owner" >&2; exit 1; fi
  lock_note="stale (owner exited)"
fi
  mkdir -p "$OUT/$tag"
  cp "$work/store.sqlite" "$OUT/$tag/store.sqlite"
  chmod 0644 "$OUT/$tag/store.sqlite"
  {
    echo "fixture-format: 1"
    echo "release-tag: $tag"
    echo "bundle-asset: $asset"
    echo "bundle-sha256: ${PINNED[$tag]}"
    echo "libhaskoki-sha256: $(sha "$lib")"
    echo "haskoki-ctl-sha256: $(sha "$ctl")"
    echo "toolchain-record-sha256: $(sha "$bundle/toolchain-record.txt")"
    echo "config-template-sha256: $TMPL_SHA"
    echo "generator-sha256: $GEN_SHA"
    echo "opensc-version: $OPENSC"
    echo "python-sqlite: $PYSQL"
    echo "host: $(uname -srm)"
    echo "generated-utc: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "store-sha256: $(sha "$OUT/$tag/store.sqlite")"
    echo "sidecar-lock-after-exit: $lock_note"
    shape "$OUT/$tag/store.sqlite"
    echo "pins: so 58213946 69324057; user 12873465 23984576"
    if [ "$tag" = v0.4.0.0 ]; then echo "changed-user-pin: 0000000000000002 34095687"; fi
  } > "$OUT/$tag/manifest.txt"
  rm -rf "$work"
}

make_one v0.3.1.0
make_one v0.4.0.0
grep -H . "$OUT"/*/manifest.txt
