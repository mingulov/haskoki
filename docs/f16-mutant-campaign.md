# F-16 bounded sensitivity campaign — mutant/killer record

Fix-plan item F-16 (codex rank 16), T-22 narrowed. Bounded MANUAL mutants only,
run last against the final tree with all F-1..F-15 *tracked* changes in place
(F-15 touches zero tracked files), plus the untracked files present at
snapshot time — see the manifest note below. No mutation-testing framework,
no tool-fork spike.

Method (all mutants in ONE isolated scratch tree, never the live checkout):

- Scratch: `/tmp/f16base`, rsync of the live tree excluding build/evidence
  dirs (`dist-release-evidence/`, `dist-release/`, `dist-newstyle/`, `ws/`,
  local agent scratch, `haskoki-*.jsonl`). Tracked diff identical to live:
  `git diff | sha256sum` = `16e1a566…be4b4f0` in both trees before the campaign.
- Untracked-input manifest (the tracked-diff hash cannot see these): the
  snapshot carries all F-1..F-14 untracked inputs (verified: F-13's
  `withOracleWorkDir` and F-14's `PROP_SEED` tracked changes plus
  `.github/workflows/prop-nightly.yml` present in scratch) but NOT the two
  F-15 files (`.github/workflows/hpc.yml`, `docs/hpc-triage.md` — the F-15
  wave ran in parallel and landed after the rsync) nor this record file
  itself (written after the campaign). Kill attribution is unaffected: no
  mutant touches those files and no killer reads them (the hpc lane is
  non-gating by construction; the triage is prose).
- Sequential mutants with backup/restore: each mutant applied to the scratch
  file only, killer run, file restored from backup, `git diff` sha re-verified
  equal to the pre-campaign value after every revert.
- Every killer below was run passing on the unmutated scratch first (baseline),
  then failing on the mutant, then passing again after restore (except the two
  instant python gates, re-run passing after restore where noted).
- Shell is dash; each run captured as `cmd > file 2>&1; echo "EXIT: $?"`.
- Raw logs (baseline/kill/restore per mutant) were session artifacts under
  `/tmp/f16-evidence/`; this file is the durable record.

Result: 8 mutants, 8 killed, 0 survivors. No gate or test was weakened.

## Mutant table

| ID | Area (F-item) | Mutant file | Killer | Verdict |
|----|---------------|-------------|--------|---------|
| mutant 1 | authorization (F-1) | `core/Haskoki/Object.hs` | model test `visibility: SO sessions cannot see user private objects` | KILLED |
| mutant 2 | locking (F-2) | `src/Haskoki/Runtime/Storage/SQLite.hs` | storage tests `stale lock takeable; masked proc and held flock refuse`, `unreadable proc root refuses cleanly`, `partially masked proc refuses as unknowable` | KILLED (3/3) |
| mutant 3 | retention (F-3) | `src/Haskoki/Runtime/Async.hs` | model tests `retention bound: N delivered digests keep at most cap tombstones`, `byte retention bound: N max-size digests keep bytes within budget` | KILLED (2/2) |
| mutant 4 | capability (F-9) | `cbits/mech_catalog.inc` | model test `flag correspondence: CKF_MESSAGE_* has its route and vice versa` | KILLED |
| mutant 4b | capability (F-10) | `cbits/standard_surface.c` | C consumer `consumer_derive_f10` (test-consumers.sh recipe) | KILLED |
| mutant 5a | evidence (F-11) | `spec/mechanisms.json` | gate `scripts/check-test-evidence.py` | KILLED |
| mutant 5b | evidence (F-12) | `tests/model/MechanismExhaustivenessSpec.hs` | model test `status-mutation control: flips detected and rows identified` | KILLED |
| mutant 6 | release-input (F-4) | `.github/workflows/ci.yml` | gate `scripts/check-actions-pinned.py` | KILLED |

Gates/suites that participated as killers: `haskoki-model-tests`,
`haskoki-storage-tests`, `scripts/test-consumers.sh` (single-scenario recipe:
`cc … tests/c/consumer_derive_f10.c` + run against the rebuilt `libhaskoki.so`),
`scripts/check-test-evidence.py`, `scripts/check-actions-pinned.py`.

## Mutant 1 — authorization (F-1): SO sees private objects again

Mutant (`core/Haskoki/Object.hs:380`, one line): re-admit `LoginSO` to the
same-slot private-visibility set (compiling equivalent of the pre-F-1 rule;
the literal pre-F-1 spelling `ssLogin st /= LoginPublic` no longer compiles
because F-1 removed `LoginPublic` from the import list — that non-compiling
first attempt was discarded, not counted):

```diff
-    && (not (objectPrivate ost) || ssLogin st `elem` [LoginUser, LoginContextUser])
+    && (not (objectPrivate ost) || ssLogin st `elem` [LoginUser, LoginContextUser, LoginSO])
```

Killer command (in scratch):

```sh
cabal test haskoki-model-tests --test-option='-p' \
  --test-option='/SO sessions cannot see user private objects/'
```

Killer output: `KILLER EXIT: 1`,

```text
visibility: SO sessions cannot see user private objects: FAIL (0.07s)
  tests/model/ObjectSpec.hs:858:
  private hidden from SO
```

Baseline before: `EXIT: 0`, same case `OK (0.07s)`. After restore: `EXIT: 0`.

## Mutant 2 — locking (F-2): unknowable liveness proceeds to takeover

Mutant (`src/Haskoki/Runtime/Storage/SQLite.hs`, `inspectLock`): route the
`PidUnknown` arm to `confirmTakeover` instead of failing closed:

```diff
-          PidUnknown -> pure (Left (StoreSecondWriter ("store is locked by pid " ++ show ownerN
-            ++ " but owner liveness is unknowable (/proc unreadable); refusing second writer: " ++ dbPath)))
+          PidUnknown -> confirmTakeover dbPath lockPath procRoot pid attempts
```

Killer command (in scratch):

```sh
cabal test haskoki-storage-tests --test-option='-p' --test-option='/proc/'
```

Killer output: `KILLER EXIT: 1`, all 3 matched cases fail:

```text
stale lock takeable; masked proc and held flock refuse: FAIL (0.19s)
  masked: expected unknowable-liveness refusal, got: store lock is held by a
  live owner (kernel lock held on …store.db.lock); refusing second writer: …
unreadable proc root refuses cleanly:                   FAIL (0.03s)
  noproc: takeover succeeded with liveness unknowable (state fork)
partially masked proc refuses as unknowable:            FAIL (0.10s)
  pmask: expected unknowable-liveness refusal, got: store lock is held by a
  live owner (kernel lock held on …store.db.lock); refusing second writer: …
3 out of 3 tests failed (0.32s)
```

Note the `noproc` leg: without a live holder the mutant takes over outright
(state fork), proving the fail-closed arm — not just the kernel backstop —
carries that case. Baseline before: `EXIT: 0`, all 3 `OK`. After restore:
`EXIT: 0`, 3 `OK`.

## Mutant 3 — retention (F-3): eviction never triggers

Mutant (`src/Haskoki/Runtime/Async.hs:1496`, one guard): the retention walk
always stops, so no victim is ever evicted (a head-level `enforceRetention _
jobs = jobs` first attempt was discarded: it leaves the `where` clause's `jid`
unbound and does not compile):

```diff
-      | count <= maxRetainedTombstones && bytes <= maxRetainedBytes = []
+      | True = [] -- MUTANT: eviction never triggers
```

Killer command (in scratch):

```sh
cabal test haskoki-model-tests --test-option='-p' --test-option='/retention bound/'
```

Killer output: `KILLER EXIT: 1`, both bounds fail:

```text
retention bound: N delivered digests keep at most cap tombstones:  FAIL
  tombstones bounded by the retention cap
  expected: 4096
   but got: 4160
byte retention bound: N max-size digests keep bytes within budget: FAIL
  retained bytes exceed budget: 134264576 > 67108864
```

Baseline before: `EXIT: 0`, both `OK`. After restore: `EXIT: 0`, 2 `OK`.

## Mutant 4 — capability (F-9): GCM message flags re-advertised

Mutant (`cbits/mech_catalog.inc:264`, one row): restore the withdrawn
`CKF_MESSAGE_*` flags on `CKM_AES_GCM` (F-9 revert). The battery parses this
file at test time, so no rebuild is involved:

```diff
-  { 0x00001087UL, 16UL, 32UL, (unsigned long)(CKF_DECRYPT | CKF_ENCRYPT) }, /* CKM_AES_GCM */
+  { 0x00001087UL, 16UL, 32UL, (unsigned long)(CKF_DECRYPT | CKF_ENCRYPT | CKF_MESSAGE_ENCRYPT | CKF_MESSAGE_DECRYPT) }, /* CKM_AES_GCM */
```

Killer command (in scratch):

```sh
cabal test haskoki-model-tests --test-option='-p' --test-option='/flag correspondence/'
```

Killer output: `KILLER EXIT: 1`,

```text
flag correspondence: CKF_MESSAGE_* has its route and vice versa:         FAIL (0.02s)
  flag correspondence: 2 mismatches:
  withdrawn GCM row must keep its route without its flag: got flag=True route=True
    at CKM_AES_GCM MechanismId {unMechanismId = 4231} (x2)
recover flag correspondence: …: OK
1 out of 2 tests failed
```

Baseline before: `EXIT: 0`, both `OK`. After restore: `EXIT: 0`.

## Mutant 4b — capability (F-10): PBKD2 derive row unwired

Mutant (`cbits/standard_surface.c:2807`, one case): drop `CKM_PKCS5_PBKD2`
from `derive_opaque_ok` (F-10 revert); foreign lib rebuilt in scratch via
`cabal build flib:haskoki` (`[27 of 27] Linking … libhaskoki.so
[Objects changed]`):

```diff
-  case CKM_PKCS5_PBKD2:
+  /* MUTANT: PBKD2 row unwired (F-10 revert) */
```

Killer command (in scratch; the `test-consumers.sh` compile recipe for the one
scenario, run against the mutant `.so`):

```sh
cc -std=c11 -O2 -g -Wall -Wextra -Werror -Ispec/vendor \
  -o /tmp/f16-evidence/consumers/consumer_derive_f10 \
  tests/c/consumer_derive_f10.c -ldl -lpthread
/tmp/f16-evidence/consumers/consumer_derive_f10 "$SO"
```

Killer output: `KILLER EXIT: 1`,

```text
FAIL [tests/c/consumer_derive_f10.c:366]: PBKD2 derives (rv=0x54)
FAIL [tests/c/consumer_derive_f10.c:368]: PBKD2 derive matches RFC 6070 c=1
FAIL [tests/c/consumer_derive_f10.c:373]: second PBKD2 derive deterministic, distinct handle
FAIL [tests/c/consumer_derive_f10.c:385]: PBKD2 derive with inline password refused
FAIL [tests/c/consumer_derive_f10.c:400]: PBKD2 derive with GOST PRF refused typed
FAILURES: 5
```

`rv=0x54` is the base-behavior refusal (`CKR_FUNCTION_NOT_SUPPORTED`) the F-10
consumer was written to close. Baseline before (same binary, baseline `.so`):
`RUN EXIT: 0`, `PASS: consumer_derive_f10 (five derive advertisements wired)`.
After restore + rebuild: `RESTORED-RUN EXIT: 0`, same `PASS` line, identical
derive vectors (`pbkd2=0c60c80f961f0e71f3a9b524af6012062fe037a6`).

## Mutant 5a — evidence (F-11): typoed case_id

Mutant (`spec/mechanisms.json:62`, one value): `A42` → `A42X` on the
`haskoki-model-tests/MechanismExhaustivenessSpec` exhaustiveness entry:

```diff
-          "case_id": "A42",
+          "case_id": "A42X",
```

Killer command (in scratch): `python3 scripts/check-test-evidence.py`

Killer output: `KILLER EXIT: 1`,

```text
test-evidence: INVALID
  malformed case_id 'A42X' on haskoki-model-tests/MechanismExhaustivenessSpec
  (cited by 1 entries, e.g. CKM_RSA_PKCS_KEY_PAIR_GEN)
```

Baseline before: `EXIT: 0`,
`test-evidence: OK (2040 entries, 49 pairs: 2 token-resolved, 47
registry-resolved (token pending))`. After restore: `EXIT: 0`, same OK line.

## Mutant 5b — evidence (F-12): flip logic neutered

Mutant (`tests/model/MechanismExhaustivenessSpec.hs:599`, one line): flip 1
checks the genuinely-refused row instead of the flipped one, so no mismatch
can fire:

```diff
-      let flippedInv = InvRow (mrId m) (mrName m)
+      let flippedInv = i -- MUTANT: flip neutered (genuinely-refused row)
```

Killer command (in scratch):

```sh
cabal test haskoki-model-tests --test-option='-p' \
  --test-option='/status-mutation control/'
```

Killer output: `KILLER EXIT: 1`,

```text
status-mutation control: flips detected and rows identified: FAIL (0.09s)
  status-flips mech->inv: flip NOT detected (no mismatches)
```

The control catches its own neutering. Baseline before: `EXIT: 0`, `OK
(0.08s)`. After restore: `EXIT: 0`.

## Mutant 6 — release-input (F-4): mutable action tag

Mutant (`.github/workflows/ci.yml:80`, one line): replace the SHA pin with a
mutable tag:

```diff
-        uses: actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803 # v6
+        uses: actions/checkout@v6
```

Killer command (in scratch): `python3 scripts/check-actions-pinned.py`

Killer output: `KILLER EXIT: 1`,

```text
FAIL: NOPIN-FLOAT: mutable refs: :80 uses: actions/checkout@v6
FAIL: NOPIN-GREP: grep hits at lines [80]
FAIL: TAGCOMMENT: missing tag comment: :80 uses: actions/checkout@v6
ok: USES-FORM: every uses key uses the strict same-line form
ok: GRAMMAR: every line stays inside the restricted YAML subset
ok: DEPENDABOT: .github/dependabot.yml schedules github-actions SHA bumps
actions-pinned: FAIL (NOPIN-FLOAT, NOPIN-GREP, TAGCOMMENT)
```

Baseline before: `EXIT: 0`, `actions-pinned: OK (third-party uses: SHA-pinned
+ Dependabot wired)`. Scratch file restored; gate re-verified passing on the
live tree at handoff (see below).

## Survivors

None. Every mutant was killed by its area's retained regression or gate; no
survivor justifications are owed. No gate or test was weakened to kill any
mutant — the only file states changed during the campaign were scratch copies
under `/tmp`, each restored with the pre-campaign `git diff` sha re-verified.

## Live-tree handoff check

After the campaign, the live tree holds only this record file plus the SDD
report as additions; the tracked diff is byte-identical to the pre-campaign
state (`git diff | sha256sum` unchanged). Both python killer gates re-run
passing on the live tree:

- `python3 scripts/check-test-evidence.py` → `EXIT: 0`, `test-evidence: OK …`
- `python3 scripts/check-actions-pinned.py` → `EXIT: 0`, `actions-pinned: OK …`
