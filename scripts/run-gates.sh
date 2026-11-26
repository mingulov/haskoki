#!/usr/bin/env bash
# Gate runner: static gates + full cabal test + release evidence,
# the ONE entry point whose pass means a passing release story.
#
# Static region (parity-gated by check-gates-parity.py, which runs
# first): every CI `Static gates` invocation, plus three intentional
# local extras (release-evidence runner fixtures, journey engine +
# driver self-tests — those run in other CI jobs too). Then a forced
# clean build with the zero-warning norm, the hook gate, `cabal test
# all`, the benchmark self-test and an sdist build (all in the
# pinned toolchain container), the executed test-tree join,
# funnel-cwd (needs the built tests), and the release-evidence
# manifest (17 container + 2 host drivers + release build +
# clean-container install; nested children run in-parent).
#
# Known CI-only coverage (not run here): unpacked-sdist build+test
# (the sdist itself builds above; the unpacked rebuild runs in CI
# bundle on every PR).
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
# the FULL 17-driver manifest; the PR subset never replaces it.
#
#   Run (from haskoki/, on the HOST):
#     bash scripts/run-gates.sh [--static-only]
#   --static-only runs the parity gate plus the static region and
#   stops before the container build: a fast dev smoke, NOT a pass.
#   Env (passed through to the evidence manifest):
#     HASKOKI_PROXY_DIR     host dir with the canonical proxy pair
#     HASKOKI_EVIDENCE_DIR  evidence root (default ./dist-release-evidence/<utc-stamp>)
#     HASKOKI_IMAGE         toolchain image (default haskoki-dev:ghc-9.10.3)
set -euo pipefail
if [ -z "${BASH_VERSION:-}" ]; then
  echo "GATES: run-gates.sh requires bash (uses PIPESTATUS); got ${0}" >&2
  exit 2
fi
cd "$(dirname "$0")/.."
if [ -n "${1:-}" ] && [ "$1" != "--static-only" ]; then
  echo "usage: bash scripts/run-gates.sh [--static-only]" >&2
  exit 2
fi
IMAGE="${HASKOKI_IMAGE:-haskoki-dev:ghc-9.10.3}"
export HASKOKI_IMAGE="$IMAGE"
# Tree-state contract: dev runs record HEAD + tracked dirtiness and
# warn; release-evidence runs set HASKOKI_REQUIRE_CLEAN_TREE=1 and
# fail closed on tracked modifications (untracked scratch never
# qualifies or disqualifies).
echo "--- tree: $(git rev-parse HEAD 2>/dev/null || echo 'not a git checkout')"
if ! dirt="$(git status --porcelain --untracked-files=no 2>/dev/null)"; then
  echo "GATES: cannot read tree state"
  exit 2
fi
if [ -n "$dirt" ]; then
  if [ "${HASKOKI_REQUIRE_CLEAN_TREE:-0}" = "1" ]; then
    echo "GATES: refusing to qualify a dirty tree (tracked modifications present)"
    exit 2
  fi
  echo "GATES: warning: dirty tree — results are dev-only"
  printf '%s\n' "$dirt" | head -n 20 || true
fi
for tool in python3 git docker openssl cc nm strip timeout; do
  command -v "$tool" >/dev/null 2>&1 || { echo "GATES: $tool required but not found (host prerequisite)"; exit 2; }
done
echo "=== static gates (build-free; parity first) ==="
python3 scripts/check-gates-parity.py
python3 scripts/check-gates-parity.py --self-test
python3 scripts/check-core-boundary.py
python3 scripts/check-mechanisms.py
python3 scripts/check-denominators.py
python3 scripts/check-attributes.py
python3 scripts/check-ossl4-surface.py
python3 scripts/check-version.py
python3 scripts/check-compat.py
python3 scripts/check-compat.py --self-test
python3 scripts/check-ckr.py
python3 scripts/check-seed-honesty.py
python3 scripts/check-seed-honesty.py --self-test
python3 scripts/check-warnings-zero.py
python3 scripts/check-docs.py
python3 scripts/check-fork-stance.py
python3 scripts/check-test-wiring.py
python3 scripts/check-test-evidence.py
python3 scripts/check-test-evidence.py --self-test
python3 scripts/check-test-wiring.py --self-test
python3 scripts/check-test-execution.py
python3 scripts/check-test-execution.py --self-test
python3 scripts/check-coverage-boundary.py
python3 scripts/publish-coverage.py --check
python3 scripts/check-release-pivots.py
python3 scripts/check-findings-ledger.py
python3 scripts/check-findings-ledger.py --self-test
python3 scripts/check-planner-join.py
python3 scripts/check-planner-join.py --self-test
python3 scripts/check-rv-generated.py
python3 scripts/check-rv-generated.py --self-test
python3 scripts/check-exposure.py
python3 scripts/check-exposure.py --self-test
python3 scripts/check-usdt-codes.py
python3 scripts/check-usdt-codes.py --self-test
python3 scripts/check-usdt-redaction.py
python3 scripts/check-usdt-redaction.py --self-test
python3 scripts/check-qualification-wiring.py
python3 scripts/check-qualification-wiring.py --self-test
python3 scripts/check-loader-norm.py
python3 scripts/check-release-install-flags.py
python3 scripts/check-smoke-surface.py
python3 scripts/check-history-codes.py
python3 scripts/check-history-codes.py --self-test
python3 scripts/check-sealed-callwork.py
python3 scripts/check-sealed-callwork.py --self-test
python3 scripts/check-ossl4-laziness.py
python3 scripts/check-ossl4-laziness.py --self-test
python3 scripts/check-actions-pinned.py
# Final-review M-1: the gate defaults to ci.yml — pin every workflow
# explicitly so hpc/prop-nightly cannot drift to a mutable tag.
python3 scripts/check-actions-pinned.py .github/workflows/hpc.yml
python3 scripts/check-actions-pinned.py .github/workflows/prop-nightly.yml
python3 scripts/check-actions-pinned.py .github/workflows/qualification.yml
python3 scripts/check-actions-pinned.py .github/workflows/haskell-reference.yml
# F-4..F-8 fix-round regression (durable, stdlib-only): evasive-form
# negative controls + F-6/F-7 structural asserts. Same --self-test
# the CI static-gates step runs.
python3 scripts/check-actions-pinned.py --self-test
# V1: release-evidence runner fixtures (fake docker/timeout/build only).
python3 scripts/test-release-evidence.py
# Release nm gate: the hook check refuses a hooked tree and fails closed.
python3 scripts/test-release-nm-gate.py
# Shell-helper config: the generated backend.toml names the real path.
python3 scripts/test-shell-config.py
# Ownership-matrix driver controls (fake binaries, no build).
python3 scripts/test-ownership-matrix-controls.py
python3 scripts/test-release-request.py
python3 scripts/test-release-workflow.py
python3 scripts/test-demo-shards.py
# Client journeys: leg-table aggregate controls (build-free).
python3 -I tests/journeys/journeys.py --self-test
sh scripts/test-client-journeys.sh --self-test
if [ "${1:-}" = "--static-only" ]; then
  echo "GATES: static-only smoke done (NOT a full pass: build, suites, evidence skipped)"
  exit 0
fi
echo "=== forced clean build + warnings norm (pinned container) ==="
# Clean-checkout semantics mirror CI (dist-newstyle never cached):
# warnings cannot hide behind a skipped rebuild.
set +e
timeout -s KILL 2400 docker run --rm --network host -v "$PWD:/work" -w /work "$IMAGE" sh -c "cabal update && cabal clean && cabal build all --enable-tests --enable-benchmarks" 2>&1 | tee haskell-build.log
rc=("${PIPESTATUS[@]}")
set -e
test "${rc[0]}" -eq 0 || { echo "GATES: clean build failed (see haskell-build.log)"; exit 1; }
test "${rc[1]}" -eq 0 || { echo "GATES: build log write failed (log untrustworthy)"; exit 1; }
# Zero-warning norm (mirrors CI Build and test): grep exit 1 (no
# match) passes; any other grep exit fails the gate too.
rc=0
grep -F 'warning: [GHC-' haskell-build.log || rc=$?
if [ "$rc" -eq 0 ]; then echo "GATES: GHC warnings in the clean build (norm is zero)"; exit 1; elif [ "$rc" -ne 1 ]; then echo "GATES: warning scan failed (grep exit $rc)"; exit "$rc"; fi
echo "=== hook gate + cabal test all (pinned container) ==="
timeout -s KILL 2400 docker run --rm --network host -v "$PWD:/work" -w /work "$IMAGE" sh -c "scripts/make-release.sh --check-hooks-only \"\$(cabal list-bin haskoki-ctl)\" 'main|hs_main'"
set +e
timeout -s KILL 2400 docker run --rm --network host -v "$PWD:/work" -w /work "$IMAGE" cabal test all --test-show-details=direct 2>&1 | tee haskell-test.log
rc=("${PIPESTATUS[@]}")
set -e
test "${rc[0]}" -eq 0 || { echo "GATES: cabal test failed (see haskell-test.log)"; exit 1; }
test "${rc[1]}" -eq 0 || { echo "GATES: test log write failed"; exit 1; }
python3 scripts/check-test-execution.py --scan-log haskell-test.log
echo "=== out-of-tree consumer check (pinned container) ==="
timeout -s KILL 1200 docker run --rm --network host -v "$PWD:/work" -w /work "$IMAGE" bash scripts/check-consumer.sh
echo "=== benchmark self-test + sdist build (exact build above) ==="
timeout -s KILL 600 docker run --rm --network host -v "$PWD:/work" -w /work "$IMAGE" sh -c "BENCH_BIN=\$(cabal list-bin bench:buffered-updates) && test -x \"\$BENCH_BIN\" && \"\$BENCH_BIN\" --self-test"
timeout -s KILL 600 docker run --rm --network host -v "$PWD:/work" -w /work "$IMAGE" sh -c "cabal sdist"
echo "=== executed test-tree join (builder context, needs the built suites) ==="
# The container run above exited 0, so every suite passed; the join
# binds that success to the reviewed intended groups. Suite binaries
# come from the exact build above (dist-newstyle persists in the
# mounted workspace) and were built inside HASKOKI_IMAGE, so each
# --list-tests capture runs in that same builder context
# (--docker-image): the host never launches container-built binaries
# directly, and no host runtime/library compatibility is assumed.
# The join itself stays host-side (pure text over the captures).
timeout -s KILL 2400 python3 scripts/check-test-execution.py --collect --build-root dist-newstyle --dir test-trees --result pass --docker-image "$IMAGE"
echo "=== static gate 25 (needs the built tests) ==="
bash scripts/check-funnel-cwd.sh
echo "=== release evidence (drivers + install) ==="
bash scripts/release-evidence.sh
echo "GATES: all passing (25 gates + cabal test + executed join + release evidence)"
