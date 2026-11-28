{- | Store contract suite.

Persist token objects, close, reload from the
same store identity, and obtain the SAME logical data with FRESH
handles. Handles are minted by the live model, never resurrected
from disk: the stored encoding carries no handle field at all (the
object-document key set pins that), and the reloaded objects bind
whatever handles the new generation's counters hand out.

The suite is parameterized over the backend opener so Memory and
SQLite satisfy the SAME contract ('contractSpec'). Backend-specific
fixtures (a 'MemoryWorld' vs a SQLite file path) supply the shared
store identity across the close/reopen boundary.
-}
{-# LANGUAGE ForeignFunctionInterface #-}
module StoreSpec
  ( spec
  , contractSpec
  , Opener (..)
  , EnvScope
  , newEnvScope
  , withEnvGate
  , withOpenPause
  , withProcRoot
  , forkOpener
  , closeStoreResult
  , closeStdResult
  , closeReconciledResult
  , holderMain
  , spawnHolderEnv
  , releaseHolder
  , awaitHolderExit
  , makeTempDir
  , expectRight
  , expectJust
  , expectInspect
  , expectCreated
  , seedStore
  , demoJobPending
  , demoJobResult
  , freshObject
  ) where

import Test.Tasty (DependencyType (AllFinish), TestTree, after, testGroup)
import Test.Tasty.HUnit ( testCase)

import StoreFixtures
  ( EnvScope, awaitHolderExit
  , makeTempDir, newEnvScope
  , releaseHolder
   )
import Store.Contract
import Store.Files
import Store.UriTwins
import Store.Ownership
import Store.Seams
import Store.TokenParsing
import Store.OpenRecon
import Store.AttrCodec
import Store.Fixtures

-- | Both backends run the shared contract, plus sqlite-only cases.
--
-- The process-wide env mutators (every @withProcRoot@/@withOpenPause@
-- user below) share one atomic gate held through arming and
-- restoration: the AllFinish chain already serializes full runs, and
-- the gate additionally serializes name-filtered runs whose filter
-- drops chain links. Readers that need the real @\/proc@ use the
-- inert opener, so they are immune either way. Child processes are
-- spawned from the scope's frozen environment snapshot, never from a
-- live 'getEnvironment' that could race a concurrent restore. The
-- scope is acquired once in 'Main' and passed in.
spec :: IO EnvScope -> TestTree
spec mkScope = testGroup "store contract"
  [ contractSpec "memory" memoryOpener
  , contractSpec "sqlite" sqliteOpener
  , testGroup "sqlite-only"
      [ testCase "held lock and guard fds are close-on-exec" testHeldFdsCloexec
      , testCase "lock fds are opened close-on-exec, never set afterwards" testOpenFdSourceGate
      , testCase "garbage file is rejected without rewrite" testGarbageRejected
      , testCase "future schema version rejected without rewrite" testFutureVersionRejected
      , testCase "version-1 database refuses without writing" testV1RefusesWithoutWriting
      , testCase "version-2 database refuses without writing" testV2RefusesWithoutWriting
      , testCase "URI twin sees the same sidecars" caseUriTwinSidecar
      , testCase "URI twin sees the same lock" caseUriTwinLock
      , testCase "alias plus URI twin sees the same lock" caseUriTwinAlias
      , testCase "undecodable URI refuses cleanly" caseUriUndecodable
      , testCase "URI with query refuses" caseUriQuery
      , testCase "URI with fragment refuses" caseUriFragment
      , testCase "nested file: URI refuses" caseUriNested
      , testCase "a spelling resolving to a URI refuses" caseUriAfterResolve
      , testCase ":memory: refuses at resolve and at open" caseMemoryRefuses
      , testCase "a localhost-authority twin sees the same sidecars" caseUriAuthorityTwin
      , testCase "a non-local authority refuses" caseUriAuthorityRefuses
      , testCase "async store open refuses a version-1 store without writing" testV1AsyncRefusalWritesNothing
      , testCase "async store open seeds the home credential and reopens" testAsyncOpenSeedsHomeCredential
      , testCase "corrupt records diagnosed" testCorruptDiagnosed
      , testCase "raw columns contain no pointers or handles" testRawColumnsClean
      , testCase "live schema matches spec/storage-schema.sql" testSchemaShape
      , testCase "stale lock takeable; masked proc and held flock refuse" (withEnvGate mkScope (testOwnershipGuards mkScope))
      , testCase "ppid-0 liveness mapping" testLivenessMapping
      , testCase "lock deletion cannot fork a live owner" (testUnlinkRefuses mkScope)
      , testCase "owner close keeps a replacement lock" (testCloseKeepsReplacement mkScope)
      -- The proc-root tests mutate HASKOKI_PROC_ROOT process-wide,
      -- the pause tests mutate HASKOKI_OPEN_PAUSE process-wide, and
      -- the ownership-guards / kill-retry tests consult the real
      -- /proc (their stale-takeover phases); chain them so full
      -- (unfiltered) runs never run them concurrently. Name-filtered
      -- runs (@-p@) drop chain links, so every mutator below also
      -- registers through the atomic 'withEnvGate', which serializes
      -- them even when the chain is filtered away. (The
      -- unlink/replacement tests neither mutate the env nor consult
      -- liveness, so they stay parallel.)
      , after AllFinish "/stale lock takeable; masked proc and held flock refuse/" $
          testCase "unreadable proc root refuses cleanly" (withEnvGate mkScope (testProcUnreadableRefuses mkScope))
      , after AllFinish "/unreadable proc root refuses cleanly/" $
          testCase "partially masked proc refuses as unknowable" (withEnvGate mkScope (testProcPartialMaskRefuses mkScope))
      , after AllFinish "/partially masked proc refuses as unknowable/" $
          testCase "fresh open guards the database before init" (withEnvGate mkScope (testFreshGuardBeforeInit mkScope))
      , after AllFinish "/fresh open guards the database before init/" $
          testCase "database swapped during open aborts" (withEnvGate mkScope (testSwappedDbAborts mkScope))
      , after AllFinish "/database swapped during open aborts/" $
          testCase "cancellation during db-guard retry releases the sidecar" (testKillDuringDbRetry mkScope)
      , after AllFinish "/cancellation during db-guard retry releases the sidecar/" $
          testCase "selective owner hiding refuses safely" (withEnvGate mkScope (testSelectiveHideRefuses mkScope))
      , after AllFinish "/selective owner hiding refuses safely/" $
          testCase "pause binds to the intended opener" (withEnvGate mkScope (testPauseBindsToIntendedOpener mkScope))
      , after AllFinish "/pause binds to the intended opener/" $
          testCase "pre-existing go file releases the pause promptly" (withEnvGate mkScope (testPauseGoPresentProceeds mkScope))
      , after AllFinish "/pre-existing go file releases the pause promptly/" $
          testCase "pause waits on the loop directly" (withEnvGate mkScope (testPauseDirectWaitsOnLoop mkScope))
      -- No chain link: the poll-loop unit test touches no
      -- process-wide env, only its own scratch directory.
      , testCase "go handshake polls until the file appears" testGoHandshakePolls
      -- Ungated (no env to arm): mkScope is only for tracking the
      -- delayed writer so a failure cannot strand it.
      , testCase "go file handshake polls the filesystem" (testGoHandshakeFilePolls mkScope)
      , after AllFinish "/pre-existing go file releases the pause promptly/" $
          testCase "lock naming pid 0 refuses dead-by-rule without naming pid 0" (withEnvGate mkScope (testPidZeroTakeable mkScope))
      -- The reserve-death case takes over a SIGKILLed child's
      -- lock via the real /proc, so it joins the same chain.
      -- The new seam tests mutate HASKOKI_PROC_ROOT/HASKOKI_OPEN_PAUSE
      -- process-wide too, so they join the same chain here and
      -- register through 'withEnvGate' like every other mutator.
      , after AllFinish "/lock naming pid 0 refuses dead-by-rule without naming pid 0/" $
          testCase "env seams inert without opt-in (proc root)" (withEnvGate mkScope (testProcRootInertWithoutOptIn mkScope))
      , after AllFinish "/env seams inert without opt-in (proc root)/" $
          testCase "env seams honored with opt-in (proc root)" (withEnvGate mkScope (testProcRootHonoredWithOptIn mkScope))
      , after AllFinish "/env seams honored with opt-in (proc root)/" $
          testCase "pause seam inert without opt-in" (withEnvGate mkScope (testPauseInertWithoutOptIn mkScope))
      , after AllFinish "/pause seam inert without opt-in/" $
          testCase "serving open honors the pause seam under opt-in" (withEnvGate mkScope (testServingOpenHonorsPauseSeam mkScope))
      , after AllFinish "/serving open honors the pause seam under opt-in/" $
          testCase "serving open inert without opt-in" (withEnvGate mkScope (testServingOpenInertByDefault mkScope))
      , after AllFinish "/serving open inert without opt-in/" $
          testCase "serving open waits for the go file" (withEnvGate mkScope (testServingOpenWaitsForGo mkScope))
      , after AllFinish "/serving open waits for the go file/" $
          testCase "serving open resumes promptly on an early go" (withEnvGate mkScope (testServingOpenResumesPromptly mkScope))
      , after AllFinish "/serving open resumes promptly on an early go/" $
          testCase "cancelled open retries a faulted close" (withEnvGate mkScope (testCancelledOpenRetriesClose mkScope))
      , after AllFinish "/cancelled open retries a faulted close/" $
          testCase "kill during release still restores the env" (withEnvGate mkScope (testKillDuringReleaseRestoresEnv mkScope))
      , after AllFinish "/kill during release still restores the env/" $
          testCase "kill during release reaps the remaining workers" (withEnvGate mkScope (testKillDuringReleaseKeepsWorkers mkScope))
      , after AllFinish "/kill during release reaps the remaining workers/" $
          testCase "kill during join is not swallowed" (withEnvGate mkScope (testKillDuringJoinPropagates mkScope))
      , after AllFinish "/kill during join is not swallowed/" $
          testCase "wedged closer is abandoned within the drain bound and reported" (withEnvGate mkScope (testWedgedCloserAbandoned mkScope))
      , after AllFinish "/wedged closer is abandoned within the drain bound and reported/" $
          testCase "serving open proceeds when go never arrives" (withEnvGate mkScope (testServingOpenNoGoCompletesAtCap mkScope))
      , after AllFinish "/serving open proceeds when go never arrives/" $
          testCase "reconciliation fixture preserves the opt-in" (withEnvGate mkScope (testReconciledHonorsOptIn mkScope))
      , after AllFinish "/reconciliation fixture preserves the opt-in/" $
          testCase "death after reservation leaves a gap, never reuse" (withEnvGate mkScope (testReserveDeathGap mkScope))
      -- Stale-lock takeover consults the real /proc for pid 1
      -- (own-pid entries take the same-process shortcut straight to
      -- the flock, with no liveness probe at all), so it joins the
      -- same chain after every proc-root mutator.
      , after AllFinish "/death after reservation leaves a gap, never reuse/" $
          testStaleLockTakeoverServing
      ]
  , testGroup "token identity parsing"
      [ testCase "pinned token_ids parse and project" casePinnedIdsParse
      , testCase "duplicate token_ids refused" caseDuplicateIdsRefused
      , testCase "ragged token_ids refused" caseRaggedIdsRefused
      , testCase "malformed token_ids refused" caseMalformedIdsRefused
      , testCase "non-home slot zero id refused" caseNonHomeIdRefused
      , testCase "absent token_ids read positionally" caseAbsentIdsPositional
      , testCase "token_ids without labels refused" caseIdsWithoutLabelsRefused
      , testCase "hand-built id mismatch falls back to positional" caseMismatchFallsBack
      , testCase "duplicate desired identity refuses" caseDuplicateDesiredRefuses
      , testCase "reconciler enforces the home anchor" caseReconcilerHomeAnchor
      , testCase "token serial is the canonical 16-hex identity" caseTokenSerialCanonical
      , testCase "desired tokens project the pinned catalog" caseDesiredTokensProject
      , testCase "catalog credential follows identity, not position" caseCatalogCredentialByIdentity
      , testCase "tokens without credentials are listed ascending" caseTokensWithoutCredentials
      ]
  , testGroup "standard open reconciliation"
      [ testCase "standard open seeds a fresh file positionally" caseOpenSeedsFresh
      , testCase "a failed seed commit leaves neither tokens nor credentials" caseOpenSeedFailsAtomically
      , testCase "a credential insert failing inside the seed rolls the tokens back" caseOpenSeedCredentialFailureLeavesNoToken
      , testCase "an appended catalog token seeds one token and one credential" caseOpenAppendSeedsOne
      , testCase "standard open refuses a reorder with the actionable message" caseOpenReorderRefuses
      , testCase "standard open refuses a removal, preserving the file" caseOpenRemovalRefuses
      , testCase "standard open accepts after an explicit move" caseOpenAcceptsMoved
      , testCase "standard open refuses an interrupted move until completed" caseOpenInterruptedRefuses
      , testCase "standard open refuses a positional downgrade over a moved store" caseOpenDowngradeRefuses
      , testCase "a config PIN edit leaves the seeded credentials in force" caseOpenPinEditIgnoredAfterSeed
      , testCase "legacy tokens without credentials refuse as migration-required" caseOpenLegacyRefusesMigrationRequired
      , testCase "a mixed store names only its legacy tokens" caseOpenMixedLegacyNamesOnlyLegacy
      , testCase "identity drift refuses before missing credentials" caseOpenIdentityRefusalPrecedesMigration
      , testCase "a schema-1 legacy store refuses before any write" caseOpenSchema1LegacyRefusesWithoutWrite
      , testCase "a schema-1 identity refusal writes nothing" caseOpenSchema1IdentityRefusalWithoutWrite
      , testCase "publication resolves moved slots through the reconciled layout" caseProjectionUsesReconciledLayout
      ]
  , testGroup "attribute codec"
      [ testCase "history attributes round-trip" testHistoryAttrsRoundTrip
      , testCase "legacy map encodes to the v0.4 golden bytes" testLegacyGoldenBytes
      ]
  ]
