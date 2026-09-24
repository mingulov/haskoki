#!/usr/bin/env bash
# caseFunnel must pass when the model suite runs
# OUTSIDE the package root. Originally the funnel test read its
# sources via CWD-relative readFile, so it failed anywhere but the
# root; the hardening resolves the package root by walking up
# to haskoki.cabal. This probe runs exactly the funnel case from
# /tmp inside the pinned container and demands its pass.
#
# Logs: redirect stdout/stderr to a host path under /tmp/gates-*.
set -euo pipefail
cd "$(dirname "$0")/.."
RC=0
IMAGE="${HASKOKI_IMAGE:-haskoki-dev:ghc-9.10.3}"
OUT=$(timeout -s KILL 600 docker run --rm --network host \
  -v "$PWD:/work" -w /work "$IMAGE" \
  bash -c 'BIN=$(cabal list-bin haskoki-model-tests) && cd /tmp && "$BIN" -p "/no production bypass of the interpreter/"') || RC=$?
echo "$OUT"
if [ "$RC" -ne 0 ]; then
  echo "check-funnel-cwd: FAIL: funnel case failed outside the package root (rc=$RC)"
  exit 1
fi
if ! grep -q "All 1 tests passed" <<<"$OUT"; then
  echo "check-funnel-cwd: FAIL: pattern selected != 1 passing test"
  exit 1
fi
echo "check-funnel-cwd: ok: funnel case passes outside the package root"
