#!/usr/bin/env bash
# Gate runner: static gates + full cabal test + release evidence,
# the ONE entry point whose pass means a passing release story.
#
# Gate count: 20 static gates —
# core-boundary, mechanisms, denominators, attributes, ossl4-surface,
# version, ckr, seed-honesty, plus warnings-zero, docs,
# fork-stance, test-wiring, test-evidence, coverage-boundary,
# coverage-fresh, release-pivots, loader-norm,
# history-codes, actions-pinned
# and funnel-cwd (wired here) — then a forced `cabal build all`
# plus `cabal test all` in the pinned toolchain container, then the
# release-evidence manifest (15 drivers + release build +
# clean-container install).
#
# Order matters twice: the forced build runs BEFORE the tests (a fresh
# `cabal test all` can run haskoki-core-tests before the sibling main
# library unit registers — Cabal-9341, found by the first direct
# invocation), and check-funnel-cwd.sh runs the built
# model-test binary from /tmp, so it runs AFTER the tests build it.
# Every docker invocation honors timeout -s KILL + --network host.
#
# PR vs release/nightly driver split (F-7 / T-6): per-PR CI (the
# `c-drivers` job) runs only the TIMED DETERMINISTIC subset —
# test-loader.sh, test-c-abi.sh (+ --negative), test-c-output.sh,
# test-c-mutexes.sh, test-consumers.sh, test-client.sh,
# test-ossl4-bounds.sh. Race/threaded drivers stay on the
# release/nightly path (this manifest only): test-finalize-race.sh,
# test-sim-threaded.sh, test-async-attached.sh,
# test-async-detached.sh, test-control-events.sh, test-lifecycle.sh,
# test-crypto-routed.sh, test-proxy-parity.sh. This script always runs
# the FULL 15-driver manifest; the PR subset never replaces it.
#
#   Run (from haskoki/, on the HOST):
#     bash scripts/run-gates.sh
#   Env (passed through to the evidence manifest):
#     HASKOKI_PROXY_DIR     host dir with the canonical proxy pair
#     HASKOKI_EVIDENCE_DIR  evidence root (default ./dist-release-evidence/<utc-stamp>)
#     HASKOKI_IMAGE         toolchain image (default haskoki-dev:ghc-9.10.3)
set -euo pipefail
cd "$(dirname "$0")/.."
IMAGE="${HASKOKI_IMAGE:-haskoki-dev:ghc-9.10.3}"
export HASKOKI_IMAGE="$IMAGE"
echo "=== static gates (1-19, build-free) ==="
python3 scripts/check-core-boundary.py
python3 scripts/check-mechanisms.py
python3 scripts/check-denominators.py
python3 scripts/check-attributes.py
python3 scripts/check-ossl4-surface.py
python3 scripts/check-version.py
python3 scripts/check-ckr.py
python3 scripts/check-seed-honesty.py
python3 scripts/check-warnings-zero.py
python3 scripts/check-docs.py
python3 scripts/check-fork-stance.py
python3 scripts/check-test-wiring.py
python3 scripts/check-test-evidence.py
python3 scripts/check-test-evidence.py --self-test
python3 scripts/check-coverage-boundary.py
python3 scripts/publish-coverage.py --check
python3 scripts/check-release-pivots.py
python3 scripts/check-loader-norm.py
python3 scripts/check-history-codes.py
python3 scripts/check-actions-pinned.py
# Final-review M-1: the gate defaults to ci.yml — pin every workflow
# explicitly so hpc/prop-nightly cannot drift to a mutable tag.
python3 scripts/check-actions-pinned.py .github/workflows/hpc.yml
python3 scripts/check-actions-pinned.py .github/workflows/prop-nightly.yml
# F-4..F-8 fix-round regression (durable, stdlib-only): evasive-form
# negative controls + F-6/F-7 structural asserts. Same --self-test
# the CI static-gates step runs.
python3 scripts/check-actions-pinned.py --self-test
echo "=== forced build + cabal test all (pinned container) ==="
timeout -s KILL 2400 docker run --rm --network host -v "$PWD:/work" -w /work "$IMAGE" cabal build all --enable-tests
timeout -s KILL 2400 docker run --rm --network host -v "$PWD:/work" -w /work "$IMAGE" cabal test all
echo "=== static gate 20 (needs the built tests) ==="
bash scripts/check-funnel-cwd.sh
echo "=== release evidence (drivers + install) ==="
bash scripts/release-evidence.sh
echo "GATES: all passing (20 gates + cabal test + release evidence)"
