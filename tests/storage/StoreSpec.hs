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
{-# LANGUAGE OverloadedStrings #-}
module StoreSpec
  ( spec
  , contractSpec
  , Opener (..)
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
  ) where

import Control.Concurrent (forkFinally, forkIO, killThread, threadDelay)
import Control.Concurrent.MVar (MVar, newEmptyMVar, putMVar, readMVar, takeMVar, tryPutMVar, tryReadMVar, tryTakeMVar)
import Control.Exception (AsyncException (ThreadKilled), bracket, bracket_, fromException, mask, onException)
import Control.Monad (replicateM_, when)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BC8
import Data.Char (isSpace)
import Data.IORef (IORef, atomicModifyIORef', newIORef, readIORef)
import Data.List (isInfixOf, isPrefixOf, sort)
import Data.Maybe (mapMaybe)
import qualified Data.Map.Strict as Map
import qualified Data.Text as T
import qualified Database.SQLite3 as S
import Data.Word (Word64)
import Foreign.C.Types (CInt (..), CULong (..))
import Foreign.Marshal.Alloc (alloca)
import Foreign.Ptr (Ptr, castPtr, nullPtr)
import Foreign.StablePtr (StablePtr, castStablePtrToPtr)
import Foreign.Storable (peek, poke)
import System.Directory (createDirectory, doesDirectoryExist, doesFileExist, getTemporaryDirectory, removeDirectoryRecursive, removeFile, renameFile)
import System.Environment (getEnvironment, getExecutablePath, lookupEnv, setEnv, unsetEnv)
import System.Exit (ExitCode (..))
import System.FilePath (takeDirectory, (</>))
import System.IO.Error (catchIOError)
import System.Posix.Files (createSymbolicLink, fileExist, fileMode, getFileStatus, setFileMode)
import System.Posix.IO (OpenMode (..), closeFd, defaultFileFlags, openFd)
import System.Posix.Process (exitImmediately, getParentProcessID, getProcessID)
import System.Posix.Signals (sigKILL, signalProcess)
import System.Posix.Types (Fd, FileMode, ProcessID)
import System.Process (CreateProcess (..), ProcessHandle, createProcess, getPid, getProcessExitCode, proc)
import System.Timeout (timeout)
import Test.Tasty (DependencyType (AllFinish), TestTree, after, testGroup)
import Test.Tasty.HUnit (assertBool, assertEqual, assertFailure, testCase)

import Haskoki.Attribute (AttributeType (..), AttributeValue (..))
import Haskoki.Model
  ( HandleBinding (..)
  , Model (..)
  , ObjectState (..)
  , SessionState
  , addToken
  , emptyModel
  , lookupObject
  , lookupSession
  )
import Haskoki.Object (decodeHandle, planCreateObject)
import Haskoki.Outcome
  ( DeltaOp (..)
  , NativeOutput (..)
  , PlanResult (..)
  , PreparedCommit (..)
  , StateDelta (..)
  )
import Haskoki.Runtime.Storage
  ( CommitResult (..)
  , CredentialRecord (..)
  , DesiredToken (..)
  , IdentityRefusal (..)
  , JobBody (..)
  , JobExecState (..)
  , JobRecord (..)
  , ObjectPut (..)
  , ObjectRecord (..)
  , Reconcile (..)
  , ReconcilePlan (..)
  , SlotMoveRefusal (..)
  , Store (..)
  , StoreDelta (..)
  , StoreError (..)
  , StoredDoc (..)
  , TokenRecord (..)
  , docTopKeys
  , emptyDelta
  , encodeHexWord64
  , jobIdCounterKey
  , objectToRecord
  , planSlotMoves
  , reconcileCredentialsReload
  , reconcileIdentities
  , renderIdentityRefusal
  , renderSlotMoveRefusal
  , reserveRestoredIds
  )
import Haskoki.FFI.Standard
  ( ObjectProjection (..)
  , StdInstance
  , StdStore (..)
  , StdStoreError (..)
  , buildObjectProjection
  , haskokiStdClose
  , haskokiStdGetSessionInfo
  , haskokiStdLogin
  , haskokiStdLogout
  , haskokiStdOpenSession
  , openStdInstance
  , openStdStore
  )
import Haskoki.Runtime.Catalog (effectiveCatalog, identityCatalog)
import Haskoki.Runtime.Config
  ( Config (..)
  , ConfigError (..)
  , StorageCfg (..)
  , StorageKind (..)
  , defaultConfig
  , parseConfig
  )
import Haskoki.Runtime.Lifecycle (newEnv, rulesFromConfig)
import Haskoki.Runtime.Storage.Memory (newMemoryWorld, openMemoryStore)
import Haskoki.Runtime.Storage.SQLite (PidLiveness (..), ProcProbe (..), livenessFromProbes, openSQLiteStore)
import Haskoki.Session (ActiveLogin (..), TokenAuth (..), tokenAuthNew)
import Haskoki.Transition (publishDelta)
import Haskoki.Types
  ( ExternalHandle (..)
  , Generation (..)
  , ObjectId (..)
  , ReturnCode (..)
  , Revision (..)
  , SessionId (..)
  , SlotId (..)
  , TokenId (..)
  )

-- | How to open a store for one contract run: a label, an action
-- that opens the CURRENT identity (the same world/file across the
-- close/reopen boundary of a single test), and a release action.
data Opener = Opener
  { openerLabel :: String
  , openCurrent :: IO (Either StoreError Store)
  , openerClose :: IO ()
  }

-- | Run one case against a freshly made opener, always releasing it.
withOpener :: IO Opener -> (Opener -> IO ()) -> IO ()
withOpener mkOpener = bracket mkOpener openerClose

-- | Open the current identity, closing the handle when the body
-- exits on any path (handle hygiene: a failing assertion mid-case
-- must not leak a live handle into fixture cleanup). Explicit
-- closes inside the body stay — they are the behavior under
-- test — and the bracket close is an idempotent no-op after
-- them.
withStore :: Opener -> (Store -> IO a) -> IO a
withStore o = bracket (openCurrent o >>= either (assertFailure . show) pure) storeClose

-- | Fresh memory identity per case.
memoryOpener :: IO Opener
memoryOpener = do
  world <- newMemoryWorld
  pure (Opener "memory" (openMemoryStore world) (pure ()))

-- | Fresh SQLite file identity per case, cleaned up afterwards.
sqliteOpener :: IO Opener
sqliteOpener = do
  dir <- makeTempDir "haskoki-storage-test"
  let path = dir </> "store.db"
  pure (Opener "sqlite" (openSQLiteStore path) (removeDirectoryRecursive dir))

-- | Make a fresh scratch directory: pid-suffixed with exists-retry
-- (no new dependencies; concurrent runs cannot collide).
makeTempDir :: String -> IO FilePath
makeTempDir prefix = do
  base <- getTemporaryDirectory
  pid <- getProcessID
  tryNames base (prefix ++ "-" ++ show pid ++ "-") (0 :: Int)
  where
    tryNames :: FilePath -> String -> Int -> IO FilePath
    tryNames base stem n
      | n > 10000 = ioError (userError ("makeTempDir: exhausted names for " ++ stem))
      | otherwise = do
          let dir = base </> (stem ++ show n)
          (createDirectory dir >> pure dir) `catchIOError` \_ -> do
            exists <- doesDirectoryExist dir
            if exists then tryNames base stem (n + 1) else ioError (userError ("makeTempDir: cannot create " ++ dir))

-- | Both backends run the shared contract, plus sqlite-only cases.
spec :: TestTree
spec = testGroup "store contract"
  [ contractSpec "memory" memoryOpener
  , contractSpec "sqlite" sqliteOpener
  , testGroup "sqlite-only"
      [ testCase "garbage file is rejected without rewrite" testGarbageRejected
      , testCase "future schema version rejected without rewrite" testFutureVersionRejected
      , testCase "version-1 database migrates explicitly" testV1Migrates
      , testCase "corrupt records diagnosed" testCorruptDiagnosed
      , testCase "raw columns contain no pointers or handles" testRawColumnsClean
      , testCase "live schema matches spec/storage-schema.sql" testSchemaShape
      , testCase "stale lock takeable; masked proc and held flock refuse" testOwnershipGuards
      , testCase "ppid-0 liveness mapping" testLivenessMapping
      , testCase "lock deletion cannot fork a live owner" testUnlinkRefuses
      , testCase "owner close keeps a replacement lock" testCloseKeepsReplacement
      -- The proc-root tests mutate HASKOKI_PROC_ROOT process-wide,
      -- the pause tests mutate HASKOKI_OPEN_PAUSE process-wide, and
      -- the ownership-guards / kill-retry tests consult the real
      -- /proc (their stale-takeover phases); chain them so they
      -- never run concurrently with each other. (The
      -- unlink/replacement tests neither mutate the env nor consult
      -- liveness, so they stay parallel.)
      , after AllFinish "/stale lock takeable; masked proc and held flock refuse/" $
          testCase "unreadable proc root refuses cleanly" testProcUnreadableRefuses
      , after AllFinish "/unreadable proc root refuses cleanly/" $
          testCase "partially masked proc refuses as unknowable" testProcPartialMaskRefuses
      , after AllFinish "/partially masked proc refuses as unknowable/" $
          testCase "fresh open guards the database before init" testFreshGuardBeforeInit
      , after AllFinish "/fresh open guards the database before init/" $
          testCase "database swapped during open aborts" testSwappedDbAborts
      , after AllFinish "/database swapped during open aborts/" $
          testCase "cancellation during db-guard retry releases the sidecar" testKillDuringDbRetry
      , after AllFinish "/cancellation during db-guard retry releases the sidecar/" $
          testCase "selective owner hiding refuses safely" testSelectiveHideRefuses
      , after AllFinish "/selective owner hiding refuses safely/" $
          testCase "pause binds to the intended opener" testPauseBindsToIntendedOpener
      , after AllFinish "/pause binds to the intended opener/" $
          testCase "lock naming pid 0 is takeable without probing" testPidZeroTakeable
      -- The reserve-death case takes over a SIGKILLed child's
      -- lock via the real /proc, so it joins the same chain.
      , after AllFinish "/lock naming pid 0 is takeable without probing/" $
          testCase "death after reservation leaves a gap, never reuse" testReserveDeathGap
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
      ]
  , testGroup "standard open reconciliation"
      [ testCase "standard open seeds a fresh file positionally" caseOpenSeedsFresh
      , testCase "standard open refuses a reorder with the actionable message" caseOpenReorderRefuses
      , testCase "standard open refuses a removal, preserving the file" caseOpenRemovalRefuses
      , testCase "standard open accepts after an explicit move" caseOpenAcceptsMoved
      , testCase "standard open refuses an interrupted move until completed" caseOpenInterruptedRefuses
      , testCase "standard open refuses a positional downgrade over a moved store" caseOpenDowngradeRefuses
      , testCase "PIN edit changes the credential for the same identity" caseOpenPinEditAccepted
      , testCase "publication resolves moved slots through the reconciled layout" caseProjectionUsesReconciledLayout
      ]
  ]

-- | The shared backend contract. Every backend runs every case here.
contractSpec :: String -> IO Opener -> TestTree
contractSpec label mkOpener = testGroup label
  [ testCase "persist-close-reload keeps logical data, mints fresh handles" $
      withOpener mkOpener (testPersistReloadFresh . openCurrent)
  , testCase "second writer fails explicitly" $
      withOpener mkOpener testSecondWriter
  , testCase "stale close does not release the new owner" $
      withOpener mkOpener staleCloseDoesNotReleaseNewOwner
  , testCase "close/reopen preserves stored bytes exactly" $
      withOpener mkOpener testBytePreservation
  , testCase "empty store loads empty" $
      withOpener mkOpener testEmptyLoadsEmpty
  , testCase "revision conflict refuses the whole delta atomically" $
      withOpener mkOpener testRevisionAtomic
  , testCase "job records round-trip with recipe or result" $
      withOpener mkOpener testJobsRoundTrip
  , testCase "reset kills old generation ids" $
      withOpener mkOpener testResetKillsOldIds
  , testCase "puts referencing missing tokens refuse" $
      withOpener mkOpener testMissingTokenRefs
  , testCase "stored bytes contain no pointers or handles" $
      withOpener mkOpener testNoPointerBytes
  , testCase "second token on one slot refuses" $
      withOpener mkOpener testSlotUnique
  , testCase "ordinary token refresh preserves owned children" $
      withOpener mkOpener tokenRefreshPreservesChildren
  , testCase "byte-identical token put preserves owned children" $
      withOpener mkOpener unchangedTokenPutPreservesChildren
  , testCase "mixed token and object puts preserve other children" $
      withOpener mkOpener mixedTokenAndObjectPutPreservesOtherChildren
  , testCase "dropped token cannot resurrect children on recreate" $
      withOpener mkOpener dropRecreateCannotResurrectChildren
  , testCase "killed competing openers never strand the identity" $
      withOpener mkOpener testKilledOpener
  , testCase "token slot moves commit identically in either put order" $
      withOpener mkOpener tokenSlotMovesAreOrderIndependent
  , testCase "reservation hands out increasing durable ids" $
      withOpener mkOpener testReserveIncreasing
  , testCase "reservation reconciles with stored jobs without lowering" $
      withOpener mkOpener testReserveReconciles
  , testCase "reset and drop keep the high-water mark" $
      withOpener mkOpener testReserveSurvivesReset
  , testCase "id space refuses before wrap" $
      withOpener mkOpener testReserveExhaustion
  , testCase "corrupt counter fails closed" $
      withOpener mkOpener testReserveCorrupt
  , testCase "legacy reset before first reservation never reuses" $
      withOpener mkOpener testLegacyResetCovers
  , testCase "legacy token drop before first reservation never reuses" $
      withOpener mkOpener testLegacyDropCovers
  , testCase "legacy job drop before first reservation never reuses" $
      withOpener mkOpener testLegacyJobDropCovers
  , testCase "phantom job drop burns nothing" $
      withOpener mkOpener testPhantomDropBurnsNothing
  , testCase "corrupt mark stays failed-closed across deletes" $
      withOpener mkOpener testCorruptDeleteStaysClosed
  , testCase "identity reconciliation seeds new tokens, keeps durable ones" $
      withOpener mkOpener testIdentitySeedAppend
  , testCase "reordered catalog refuses without touching bytes" $
      withOpener mkOpener testIdentityReorderRefuses
  , testCase "middle insertion refuses, append seeds" $
      withOpener mkOpener testIdentityInsertion
  , testCase "removed entry refuses and preserves durable data" $
      withOpener mkOpener testIdentityRemovalRefuses
  , testCase "relabeled entry refuses, durable label authoritative" $
      withOpener mkOpener testIdentityLabelChangeRefuses
  , testCase "explicit slot moves reassign slots atomically" $
      withOpener mkOpener testIdentitySlotMoves
  , testCase "fresh store seeds every configured token" $
      withOpener mkOpener testIdentityFreshSeeds
  , testCase "auth commits persist counters and locks, never the login" $
      withOpener mkOpener testAuthDurableOnly
  , testCase "stored auth bytes carry no principal or session" $
      withOpener mkOpener testAuthBytesRedacted
  , testCase "credentials round-trip across close/reopen" $
      withOpener mkOpener testCredentialsRoundTrip
  , testCase "credential put for a missing token refuses" $
      withOpener mkOpener testCredentialMissingToken
  , testCase "token drop cascades the credential" $
      withOpener mkOpener testCredentialCascade
  , testCase "reset drops the credential" $
      withOpener mkOpener testResetDropsCredential
  , testCase "refused commits preserve stored bytes" $
      withOpener mkOpener testRefusedPreservesBytes
  , testCase "credential Show redacts both PINs" $
      withOpener mkOpener testCredentialShowRedacted
  ]

-- | Acceptance 1: the same logical token objects across a
-- close/reopen boundary, bound to fresh handles in the new
-- generation. The new generation provokes counter divergence the
-- way a real restart does (a transient session object binds first),
-- so identical handle values would prove resurrection.
testPersistReloadFresh :: IO (Either StoreError Store) -> IO ()
testPersistReloadFresh openCurrent = do
  eStore1 <- openCurrent
  store1 <- either (assertFailure . show) pure eStore1
  let slot = SlotId 0
      tmpl1 =
        [ (AttrClass, ValULong 3)
        , (AttrToken, ValBool True)
        , (AttrLabel, ValBytes "first")
        , (AttrValue, ValBytes "payload-one")
        ]
      tmpl2 =
        [ (AttrClass, ValULong 4)
        , (AttrToken, ValBool True)
        , (AttrLabel, ValBytes "second")
        , (AttrValue, ValBytes "payload-two")
        ]
  mSeated <- expectRight "seat+open" (publishDelta (addToken emptyModel slot)
    (StateDelta [DeltaOpenSession (SessionId 1) slot False]))
  st <- expectJust "session 1" (lookupSession mSeated (SessionId 1))
  -- Generation 1 is a lived-in process: a transient session object
  -- binds first, so the token objects take handles 2 and 3.
  (m0, hT, _) <- expectCreated mSeated st
    [(AttrClass, ValULong 3), (AttrLabel, ValBytes "gen1-transient")]
  (m1, h1, oid1) <- expectCreated m0 st tmpl1
  (m2, h2, oid2) <- expectCreated m1 st tmpl2
  assertEqual "gen-1 handle history" [ExternalHandle 1, ExternalHandle 2, ExternalHandle 3] [hT, h1, h2]
  ost1 <- expectJust "object 1" (lookupObject m2 oid1)
  ost2 <- expectJust "object 2" (lookupObject m2 oid2)
  let tok = TokenRecord
        { trId = TokenId 1
        , trSlot = slot
        , trGeneration = Generation 1
        , trLabel = "demo-token-1"
        , trAuth = tokenAuthNew
        }
      delta = emptyDelta
        { sdPutTokens = [tok]
        , sdPutObjects =
            [ ObjectPut Nothing (objectToRecord (TokenId 1) ost1)
            , ObjectPut Nothing (objectToRecord (TokenId 1) ost2)
            ]
        }
  result1 <- storeCommit store1 delta
  assertEqual "initial commit" Committed result1
  -- The stored encoding carries no handle: pin the exact key set.
  docs <- expectInspect store1
  let objDocs = [d | d <- docs, docTable d == "objects"]
  assertEqual "two object docs" 2 (length objDocs)
  mapM_ assertObjectDocKeys objDocs
  mapM_ (assertBool "no handle leakage in stored bytes" . noHandleBytes . docJson) docs
  storeClose store1
  -- Generation 2: a fresh model (as after finalize/reinit) whose
  -- counters provably diverge, then reload and rebind.
  eStore2 <- openCurrent
  store2 <- either (assertFailure . show) pure eStore2
  eLoaded <- storeLoadTokens store2
  loaded <- either (assertFailure . show) pure eLoaded
  case loaded of
    [(tok2, objs2)] -> do
      assertEqual "token label survives" "demo-token-1" (trLabel tok2)
      assertEqual "token generation survives" (Generation 1) (trGeneration tok2)
      assertEqual "both objects survive" 2 (length objs2)
      let attrs2 = map orAttrs objs2
      assertBool "first attrs survive" (osAttrs ost1 `elem` attrs2)
      assertBool "second attrs survive" (osAttrs ost2 `elem` attrs2)
      assertEqual "object ids stable" [oid1, oid2] (map orId objs2)
      -- Generation 2 re-seats at init (before serving calls), so
      -- the live counters mint handles 1 and 2 for the restored
      -- objects: pairwise distinct from generation 1's 2 and 3.
      -- Object ids stay stable; handles never do.
      mNew <- expectRight "reseat+open" (publishDelta (addToken emptyModel slot)
        (StateDelta [DeltaOpenSession (SessionId 1) slot False]))
      let hNew = [ExternalHandle (mNextHandle mNew), ExternalHandle (mNextHandle mNew + 1)]
          rebinds = zipWith DeltaBindHandle hNew (map orId objs2)
          creates =
            [ DeltaCreateObjectFull (orId o) (orAttrs o) Nothing slot
            | o <- objs2
            ]
      assertEqual "live counters mint 1,2" [ExternalHandle 1, ExternalHandle 2] hNew
      mBound <- expectRight "rebind" (publishDelta mNew (StateDelta (creates ++ rebinds)))
      assertBool "handles are fresh, not resurrected"
        (and (zipWith (/=) [h1, h2] hNew))
      assertBool "rebound objects resolve"
        (all (resolves mBound) hNew)
      -- The restored id space is reserved, so later allocations
      -- never collide with it.
      stNew <- expectJust "new session 1" (lookupSession mBound (SessionId 1))
      let mReserved = reserveRestoredIds (map orId objs2) mBound
      (mFinal, hAfter, oidAfter) <- expectCreated mReserved stNew
        [(AttrClass, ValULong 3), (AttrLabel, ValBytes "post-reseat")]
      assertEqual "post-reseat object id advances" (ObjectId 4) oidAfter
      assertEqual "post-reseat handle advances" (ExternalHandle 3) hAfter
      assertBool "post-reseat object resolves" (resolves mFinal hAfter)
    _ -> assertFailure ("expected one token, got: " ++ show (length loaded))
  storeClose store2

-- | Unwrap an 'Either' or fail the test with context.
expectRight :: Show e => String -> Either e a -> IO a
expectRight ctx = either (\e -> assertFailure (ctx ++ ": " ++ show e)) pure

-- | Unwrap a 'Maybe' or fail the test with context.
expectJust :: String -> Maybe a -> IO a
expectJust ctx = maybe (assertFailure ("missing: " ++ ctx)) pure

-- | Inspect a store, failing the case on an inspection error:
-- inspection is fallible, so every happy-path use unwraps here.
expectInspect :: Store -> IO [StoredDoc]
expectInspect s = storeInspect s >>= expectRight "inspect"

-- | Acceptance 2 (ownership): a second concurrent open of the same
-- identity fails with an explicit second-writer diagnosis — never
-- a stale-cache shadow. Closing releases ownership.
testSecondWriter :: Opener -> IO ()
testSecondWriter o = do
  e1 <- openCurrent o
  s1 <- either (\e -> assertFailure ("first open: " ++ show e)) pure e1
  e2 <- openCurrent o
  case e2 of
    Right s2 -> do
      storeClose s2
      storeClose s1
      assertFailure "second concurrent open succeeded"
    Left (StoreSecondWriter _) -> pure ()
    Left other -> do
      storeClose s1
      assertFailure ("wrong error for second writer: " ++ show other)
  storeClose s1
  e3 <- openCurrent o
  s3 <- either (\e -> assertFailure ("reopen after close: " ++ show e)) pure e3
  storeClose s3

-- | A stale close never releases the new owner. Open A, close
-- A, open B, then close A again: B must still own the identity
-- (a third open is refused and B stays usable), and only B's own
-- close releases it.
staleCloseDoesNotReleaseNewOwner :: Opener -> IO ()
staleCloseDoesNotReleaseNewOwner o =
  withStore o $ \sA -> do
    _ <- seedStore sA
    storeClose sA
    withStore o $ \sB -> do
      storeClose sA
      eC <- openCurrent o
      case eC of
        Right sC -> do
          storeClose sC
          assertFailure "stale close released the new owner"
        Left (StoreSecondWriter _) -> pure ()
        Left other ->
          assertFailure ("wrong error while new owner holds: " ++ show other)
      docs <- expectInspect sB
      assertBool "new owner still inspects seeded docs" (not (null docs))
      r <- storeCommit sB emptyDelta { sdPutMeta = [("m4-stale-probe", "1")] }
      assertEqual "new owner usable after stale close" Committed r
      eMeta <- storeLoadMeta sB
      meta <- either (assertFailure . show) pure eMeta
      assertEqual "probe durable" (Just "1") (lookup "m4-stale-probe" meta)
      storeClose sB
      withStore o $ \sD -> do
        eMeta2 <- storeLoadMeta sD
        meta2 <- either (assertFailure . show) pure eMeta2
        assertEqual "probe survives owner close" (Just "1") (lookup "m4-stale-probe" meta2)
        storeClose sD

-- | A kill racing a competing open never strands the identity. Each
-- round kills one opener twice — once on the refusal path while an
-- owner holds the identity, once on the claim path with the identity
-- unowned — then the owner still closes under a bounded wait and the
-- identity reopens and closes cleanly. A stranded owner cell would
-- refuse the reopen (or hang the close past the guard) instead.
testKilledOpener :: Opener -> IO ()
testKilledOpener o = replicateM_ openerKillRounds $ do
  eOwner <- openCurrent o
  owner <- expectRight "open owner" eOwner
  raceRefusal o
  closeObserved owner "owner close completes after killed competing open"
  raceClaim o
  eFinal <- openCurrent o
  final <- expectRight "reopen after killed claim" eFinal
  closeObserved final "reopened close completes after killed racing claim"

-- | Opener-kill race rounds per case: repeated kills, so a
-- regression stranding the owner cell is near-certain to refuse
-- (or hang past the guard) at least once.
openerKillRounds :: Int
openerKillRounds = 50

-- | Refusal-race opens the spinner provably runs before the kill
-- lands (the handshake proves each round raced live opens).
refusalSpinIters :: Int
refusalSpinIters = 20

-- | Bounded waits in the opener-kill races (5 seconds, matching
-- the multi-session suite's guards).
killGuard :: Int
killGuard = 5000000

-- | Race a kill against opens on the refusal path: the owner holds
-- the identity throughout, so no open can claim (nothing can leak)
-- while the kill may land inside any of them. The spinner signals
-- once it has run 'refusalSpinIters' opens, proving the round raced
-- live opens; the kill then races the opens past the handshake.
raceRefusal :: Opener -> IO ()
raceRefusal o = do
  spunVar <- newEmptyMVar
  outcomeVar <- newEmptyMVar
  tid <- forkFinally (refusalSpin o spunVar) (putMVar outcomeVar)
  mSpun <- timeout killGuard (takeMVar spunVar)
  case mSpun of
    Nothing -> assertFailure "refusal spinner never ran its opens (5s guard)"
    Just () -> pure ()
  killThread tid
  mOut <- timeout killGuard (takeMVar outcomeVar)
  case mOut of
    Nothing -> assertFailure "killed refusal spinner join timed out (5s guard)"
    Just (Left e) -> case fromException e of
      Just ThreadKilled -> pure ()
      _ -> assertFailure ("refusal spinner died: " ++ show e)
    Just (Right ()) -> pure ()

-- | Spin opens that cannot claim (the caller holds the identity),
-- signaling after 'refusalSpinIters' of them. Each open runs
-- restored (killable no matter the ambient mask); the loop holds
-- no claim across iterations, so a kill can neither leak a handle
-- nor strand the worker past the join.
refusalSpin :: Opener -> MVar () -> IO ()
refusalSpin o spunVar = go (0 :: Int)
  where
    go n = do
      e <- mask (\restore -> restore (openCurrent o))
      case e of
        -- Impossible while the owner holds; closed for totality
        -- (a foreign token releases nothing).
        Right stray -> storeClose stray >> go (n + 1)
        Left _ -> do
          when (n + 1 == refusalSpinIters) $ do
            _ <- tryPutMVar spunVar ()
            pure ()
          go (n + 1)

-- | Race a kill against one opening claim with the identity unowned.
-- The opener signals entry before opening, so the kill provably races
-- a started worker — but not provably a started open: a kill already
-- pending when the worker enters its restored open is delivered
-- before the open begins, so no report can exist on that schedule.
-- The drain therefore distinguishes the pre-begin kill (no report;
-- a probe open asserts nothing leaked, stranded, or wedged the owner
-- cell) from the post-begin kill (the open completed first, so the
-- self-report is required and the completed claim is drained, never
-- leaked). Either way the identity is unowned on return.
raceClaim :: Opener -> IO ()
raceClaim o = do
  enteredVar <- newEmptyMVar
  reportVar <- newEmptyMVar
  outcomeVar <- newEmptyMVar
  tid <- forkFinally (claimOnce o enteredVar reportVar) (putMVar outcomeVar)
  mEntered <- timeout killGuard (takeMVar enteredVar)
  case mEntered of
    Nothing -> assertFailure "racing opener never started (5s guard)"
    Just () -> pure ()
  killThread tid
  mOut <- timeout killGuard (takeMVar outcomeVar)
  killed <- case mOut of
    Nothing -> assertFailure "killed opener join timed out (5s guard)"
    Just (Left e) -> case fromException e of
      Just ThreadKilled -> pure True
      _ -> assertFailure ("opener worker died: " ++ show e)
    Just (Right ()) -> pure False
  -- The worker is dead, so its self-report (if any) is final.
  mRep <- tryTakeMVar reportVar
  case mRep of
    -- Pre-begin kill: the pending kill was delivered at 'restore'
    -- entry, before the open began (or aborted a backend open section
    -- whose cleanup keeps the identity unowned), so no completed open
    -- exists to drain and no report can be required. The probe asserts
    -- the regression postcondition directly: the identity reopens
    -- (nothing leaked, nothing stranded, the owner cell intact) and
    -- closes cleanly.
    Nothing
      | killed -> do
          eProbe <- openCurrent o
          probe <- expectRight "identity opens after pre-begin kill" eProbe
          storeClose probe
      | otherwise ->
          assertFailure "racing opener exited without reporting its open"
    -- Post-begin kill (or a kill that missed entirely): the open
    -- completed before the kill landed, so the self-report is
    -- required — drain the completed claim, and fail on a completed
    -- refusal (impossible on the unowned identity).
    Just (Left err) ->
      assertFailure ("racing opener refused on unowned identity: " ++ show err)
    Just (Right stray) -> storeClose stray

-- | Signal entry, then run one open, restored (killable no matter
-- the ambient mask), and self-report the attempt under the same
-- mask — acquisition through registration is atomic w.r.t. async
-- exceptions, so a completed claim always reaches the drain. The
-- caller drains the report after joining the worker; a kill landing
-- before the restored open begins leaves no report, which the caller
-- ('raceClaim') covers with its pre-begin probe instead.
claimOnce :: Opener -> MVar () -> MVar (Either StoreError Store) -> IO ()
claimOnce o enteredVar reportVar = mask $ \restore -> do
  putMVar enteredVar ()
  e <- restore (openCurrent o)
  putMVar reportVar e

-- | Close a handle in a worker, observing the outcome under a
-- bounded wait. A close hung past the guard fails the case instead
-- of hanging the suite; the stuck worker (if any) is contained —
-- every case runs on a fresh identity.
closeObserved :: Store -> String -> IO ()
closeObserved s ctx = do
  outcomeVar <- newEmptyMVar
  _ <- forkFinally (storeClose s) (putMVar outcomeVar)
  mOut <- timeout killGuard (takeMVar outcomeVar)
  case mOut of
    Just (Right ()) -> pure ()
    Just (Left e) -> assertFailure (ctx ++ ": close threw: " ++ show e)
    Nothing -> assertFailure (ctx ++ " (5s guard)")

-- | Acceptance 2 (no silent refixture): the stored bytes before and
-- after a close/reopen boundary are identical.
testBytePreservation :: Opener -> IO ()
testBytePreservation o = do
  e1 <- openCurrent o
  s1 <- either (\e -> assertFailure ("open: " ++ show e)) pure e1
  _ <- seedStore s1
  docsBefore <- expectInspect s1
  assertBool "seeded docs are non-empty" (not (null docsBefore))
  storeClose s1
  e2 <- openCurrent o
  s2 <- either (\e -> assertFailure ("reopen: " ++ show e)) pure e2
  docsAfter <- expectInspect s2
  storeClose s2
  assertEqual "stored bytes survive close/reopen"
    (map show docsBefore) (map show docsAfter)

-- | Acceptance 2 (empty init): a fresh identity opens and loads
-- empty (SQLite initializes its schema transactionally).
testEmptyLoadsEmpty :: Opener -> IO ()
testEmptyLoadsEmpty o = do
  eStore <- openCurrent o
  s <- either (\e -> assertFailure ("open: " ++ show e)) pure eStore
  eLoaded <- storeLoadTokens s
  loaded <- either (\e -> assertFailure ("load: " ++ show e)) pure eLoaded
  assertEqual "fresh store is empty" [] loaded
  storeClose s

-- | Acceptance 4 (atomic multi-object transaction): a delta with
-- one stale expected revision refuses ENTIRELY — the innocent
-- put does not land either. The control (correct expectations)
-- commits both.
testRevisionAtomic :: Opener -> IO ()
testRevisionAtomic o = do
  eStore <- openCurrent o
  s <- either (\e -> assertFailure ("open: " ++ show e)) pure eStore
  (tok, recs) <- seedStore s
  recB <- case recs of
    [_, b] -> pure b
    _ -> assertFailure "seed must hold two objects"
  recC <- freshObject (trId tok)
  let badDelta = emptyDelta
        { sdPutObjects =
            [ ObjectPut Nothing recC
            , ObjectPut (Just (Revision 424242)) recB
            ]
        }
  bad <- storeCommit s badDelta
  case bad of
    NotCommitted (StoreRevisionConflict _) -> pure ()
    other -> assertFailure ("expected revision conflict, got: " ++ show other)
  eLoaded <- storeLoadTokens s
  loaded <- either (\e -> assertFailure ("load: " ++ show e)) pure eLoaded
  let objs = concatMap snd loaded
  assertEqual "nothing landed" recs objs
  let goodDelta = emptyDelta
        { sdPutObjects =
            [ ObjectPut Nothing recC
            , ObjectPut (Just (orRevision recB)) recB
            ]
        }
  good <- storeCommit s goodDelta
  assertEqual "correct expectations commit" Committed good
  eLoaded2 <- storeLoadTokens s
  loaded2 <- either (\e -> assertFailure ("load: " ++ show e)) pure eLoaded2
  assertEqual "both land" 3 (length (concatMap snd loaded2))
  storeClose s

-- | Build a fresh object record (naturally 'ObjectId 3': two
-- dummies consumed first) via a scratch model.
freshObject :: TokenId -> IO ObjectRecord
freshObject tok = do
  let slot = SlotId 0
      dummy = [(AttrClass, ValULong 3), (AttrLabel, ValBytes "dummy")]
      tmplC =
        [ (AttrClass, ValULong 3)
        , (AttrToken, ValBool True)
        , (AttrLabel, ValBytes "third")
        , (AttrValue, ValBytes "third-bytes")
        ]
  mSeated <- expectRight "seat+open" (publishDelta (addToken emptyModel slot)
    (StateDelta [DeltaOpenSession (SessionId 1) slot False]))
  st <- expectJust "session" (lookupSession mSeated (SessionId 1))
  (m1, _, _) <- expectCreated mSeated st dummy
  (m2, _, _) <- expectCreated m1 st dummy
  (m3, _, oidC) <- expectCreated m2 st tmplC
  assertEqual "fresh id" (ObjectId 3) oidC
  ostC <- expectJust "fresh object" (lookupObject m3 oidC)
  pure (objectToRecord tok ostC)

-- | SQLite-only: a garbage file is rejected with a diagnosis and
-- its bytes are left untouched (never silently replaced).
testGarbageRejected :: IO ()
testGarbageRejected = do
  bracket (makeTempDir "haskoki-storage-garbage") removeDirectoryRecursive $ \dir -> do
    let path = dir </> "store.db"
    BS.writeFile path (BS.pack [116, 104, 105, 115, 32, 110, 111, 116, 32, 97, 32, 100, 98, 0, 1, 2])
    before <- BS.readFile path
    eStore <- openSQLiteStore path
    case eStore of
      Right s -> do
        storeClose s
        assertFailure "garbage file opened as a store"
      Left _ -> pure ()
    bytesAfter <- BS.readFile path
    assertEqual "garbage bytes untouched" before bytesAfter

-- | Acceptance 4 (wrong schema): a future schema version is
-- rejected with its versions diagnosed, the bytes untouched, and
-- no lock stranded.
testFutureVersionRejected :: IO ()
testFutureVersionRejected =
  bracket (makeTempDir "haskoki-storage-version") removeDirectoryRecursive $ \dir -> do
    let path = dir </> "store.db"
    e0 <- openSQLiteStore path
    s0 <- either (\e -> assertFailure ("seed open: " ++ show e)) pure e0
    _ <- seedStore s0
    storeClose s0
    rawExec path (T.pack "UPDATE store_meta SET value = '999' WHERE key = 'schema_version'")
    before <- BS.readFile path
    e1 <- openSQLiteStore path
    case e1 of
      Right s -> do
        storeClose s
        assertFailure "future schema version opened"
      Left (StoreSchemaVersion expected found) -> do
        assertEqual "expected version" 2 expected
        assertEqual "found version" "999" found
      Left other -> assertFailure ("wrong error: " ++ show other)
    bytesAfter <- BS.readFile path
    assertEqual "bytes untouched" before bytesAfter
    lockLeft <- doesFileExist (path ++ ".lock")
    assertBool "no stranded lock" (not lockLeft)

-- | Acceptance (explicit migration): a version-1 database opens
-- by migrating to version 2 — the empty @credentials@ table is
-- created and the marker advances, in one transaction — while
-- no existing row is rewritten or reinterpreted (a marker meta
-- row survives byte-identical). Afterwards the store serves
-- credentials and reopens cleanly at version 2. The version-1
-- DDL below is frozen history (copied from the
-- pre-provisioning @spec/storage-schema.sql@), not a live
-- reference: it must never track the current schema.
testV1Migrates :: IO ()
testV1Migrates =
  bracket (makeTempDir "haskoki-storage-migrate") removeDirectoryRecursive $ \dir -> do
    let path = dir </> "store.db"
        v1 =
          [ "CREATE TABLE store_meta (key TEXT PRIMARY KEY NOT NULL, value TEXT NOT NULL)"
          , "CREATE TABLE tokens (token_id TEXT PRIMARY KEY NOT NULL, slot_key BLOB NOT NULL CHECK (typeof(slot_key) = 'blob' AND length(slot_key) = 8), generation_key BLOB NOT NULL CHECK (typeof(generation_key) = 'blob' AND length(generation_key) = 8), record_json TEXT NOT NULL, format_version INTEGER NOT NULL CHECK (format_version = 1), UNIQUE(slot_key))"
          , "CREATE TABLE objects (object_id TEXT PRIMARY KEY NOT NULL, token_id TEXT NOT NULL REFERENCES tokens(token_id) ON DELETE CASCADE, class_key BLOB NOT NULL CHECK (typeof(class_key) = 'blob' AND length(class_key) = 8), key_type_key BLOB CHECK (key_type_key IS NULL OR (typeof(key_type_key) = 'blob' AND length(key_type_key) = 8)), attributes_json TEXT NOT NULL, material_encoding TEXT NOT NULL, material_blob BLOB, revision INTEGER NOT NULL CHECK (revision > 0), format_version INTEGER NOT NULL CHECK (format_version = 1))"
          , "CREATE INDEX objects_by_token ON objects(token_id)"
          , "CREATE TABLE detached_jobs (persistent_id_key BLOB PRIMARY KEY NOT NULL CHECK (typeof(persistent_id_key) = 'blob' AND length(persistent_id_key) = 8), token_id TEXT NOT NULL REFERENCES tokens(token_id) ON DELETE CASCADE, token_generation_key BLOB NOT NULL CHECK (typeof(token_generation_key) = 'blob' AND length(token_generation_key) = 8), function_name TEXT NOT NULL, execution_state TEXT NOT NULL CHECK (execution_state IN ('queued','ready','failed','canceled','delivered')), record_json TEXT NOT NULL, format_version INTEGER NOT NULL CHECK (format_version = 1))"
          , "CREATE INDEX jobs_by_token ON detached_jobs(token_id)"
          , "INSERT INTO store_meta(key, value) VALUES ('store_format', 'haskoki-demo-v1')"
          , "INSERT INTO store_meta(key, value) VALUES ('schema_version', '1')"
          , "INSERT INTO store_meta(key, value) VALUES ('next_persistent_job_id', '0000000000000001')"
          , "INSERT INTO store_meta(key, value) VALUES ('p6-migration-marker', 'kept')"
          ]
    mapM_ (rawExec path . T.pack) v1
    eStore <- openSQLiteStore path
    s <- either (\e -> assertFailure ("migrating open: " ++ show e)) pure eStore
    eMeta <- storeLoadMeta s
    meta <- either (\e -> assertFailure ("load meta: " ++ show e)) pure eMeta
    assertEqual "marker survives migration" (Just "kept") (lookup "p6-migration-marker" meta)
    storeClose s
    db <- S.open (T.pack path)
    ver <- rawTexts db (T.pack "SELECT value FROM store_meta WHERE key = 'schema_version'")
    tables <- rawTexts db (T.pack "SELECT name FROM sqlite_master WHERE type = 'table'")
    S.close db
    assertEqual "version advanced to 2" ["2"] ver
    assertBool "credentials table migrated" ("credentials" `elem` tables)
    -- The migrated store serves credentials and reopens cleanly.
    eStore2 <- openSQLiteStore path
    s2 <- either (\e -> assertFailure ("post-migration open: " ++ show e)) pure eStore2
    let tok = TokenRecord (TokenId 7) (SlotId 0) (Generation 1) "migrated" tokenAuthNew
        cred = CredentialRecord (TokenId 7) "so-pin-1" (Just "user-pin-1")
    r <- storeCommit s2 emptyDelta { sdPutTokens = [tok], sdPutCredentials = [cred] }
    assertEqual "credential commits on migrated store" Committed r
    storeClose s2
    eStore3 <- openSQLiteStore path
    s3 <- either (\e -> assertFailure ("reopen: " ++ show e)) pure eStore3
    eCreds <- storeLoadCredentials s3
    creds <- either (\e -> assertFailure ("load credentials: " ++ show e)) pure eCreds
    assertEqual "credential survives reopen" [cred] creds
    storeClose s3

-- | Acceptance 4 (corrupt records): garbage in each decodable
-- surface diagnoses 'StoreCorrupt' at load (open itself stays
-- lazy and succeeds).
testCorruptDiagnosed :: IO ()
testCorruptDiagnosed = do
  mapM_ runSurface
    [ ("token doc", "UPDATE tokens SET record_json = '{broken'")
    , ("attrs doc", "UPDATE objects SET attributes_json = 'nope' WHERE object_id = '0000000000000001'")
    , ("object id", "UPDATE objects SET object_id = 'zzz' WHERE object_id = '0000000000000001'")
    , ("material encoding", "UPDATE objects SET material_encoding = 'evil/v9' WHERE object_id = '0000000000000002'")
    ]
  where
    runSurface :: (String, String) -> IO ()
    runSurface (label, sql) =
      bracket (makeTempDir "haskoki-storage-corrupt") removeDirectoryRecursive $ \dir -> do
        let path = dir </> "store.db"
        e0 <- openSQLiteStore path
        s0 <- either (\e -> assertFailure ("seed open: " ++ show e)) pure e0
        _ <- seedStore s0
        storeClose s0
        rawExec path (T.pack sql)
        e1 <- openSQLiteStore path
        s1 <- either (\e -> assertFailure (label ++ " open: " ++ show e)) pure e1
        eLoaded <- storeLoadTokens s1
        case eLoaded of
          Left (StoreCorrupt _) -> pure ()
          Left other -> assertFailure (label ++ ": wrong error: " ++ show other)
          Right _ -> assertFailure (label ++ ": corrupt record loaded")
        storeClose s1

-- | Run one raw statement against a closed database file.
rawExec :: FilePath -> T.Text -> IO ()
rawExec path sql = do
  db <- S.open (T.pack path)
  S.exec db sql
  S.close db

-- | Acceptance 5 (detached-job records): a pending recipe and a
-- prepared result both round-trip byte-exact across close/reopen.
testJobsRoundTrip :: Opener -> IO ()
testJobsRoundTrip o = do
  eStore <- openCurrent o
  s <- either (\e -> assertFailure ("open: " ++ show e)) pure eStore
  (tok, _) <- seedStore s
  let j1 = demoJobPending 1 (trId tok) (trGeneration tok)
      j2 = demoJobResult 2 (trId tok) (trGeneration tok)
  r <- storeCommit s emptyDelta { sdPutJobs = [j1, j2] }
  assertEqual "jobs commit" Committed r
  docs <- expectInspect s
  let jobDocs = [d | d <- docs, docTable d == "detached_jobs"]
  assertEqual "two job docs" 2 (length jobDocs)
  mapM_ assertJobDocKeys jobDocs
  storeClose s
  eStore2 <- openCurrent o
  s2 <- either (\e -> assertFailure ("reopen: " ++ show e)) pure eStore2
  eJobs <- storeLoadJobs s2
  jobs <- either (\e -> assertFailure ("load jobs: " ++ show e)) pure eJobs
  assertEqual "jobs round-trip" [j1, j2] jobs
  storeClose s2

-- | The exact canonical key set of a job document.
assertJobDocKeys :: StoredDoc -> IO ()
assertJobDocKeys d =
  assertEqual ("job doc keys: " ++ docKey d)
    [ "body"
    , "format_version"
    , "function"
    , "persistent_id"
    , "state"
    , "token_generation"
    , "token_id"
    ]
    (docTopKeys (docJson d))

-- | Acceptance 5 (generation validation, record side): reset
-- replaces the token, removes its objects AND jobs atomically,
-- and kills the old generation's ids — while the new generation
-- stays writable.
testResetKillsOldIds :: Opener -> IO ()
testResetKillsOldIds o = do
  eStore <- openCurrent o
  s <- either (\e -> assertFailure ("open: " ++ show e)) pure eStore
  (tok, _) <- seedStore s
  let gen1 = trGeneration tok
  rJobs <- storeCommit s emptyDelta
    { sdPutJobs =
        [ demoJobPending 10 (trId tok) gen1
        , demoJobResult 11 (trId tok) gen1
        ]
    }
  assertEqual "jobs seed" Committed rJobs
  let replacement = tok { trGeneration = Generation 2, trLabel = "seed-token-gen2" }
  rr <- storeResetToken s (trId tok) gen1 replacement
  assertEqual "reset commits" Committed rr
  eLoaded <- storeLoadTokens s
  loaded <- either (\e -> assertFailure ("load: " ++ show e)) pure eLoaded
  case loaded of
    [(tok2, objs2)] -> do
      assertEqual "generation bumped" (Generation 2) (trGeneration tok2)
      assertEqual "objects removed" [] objs2
    _ -> assertFailure ("expected one token, got: " ++ show (length loaded))
  eJobs <- storeLoadJobs s
  jobs <- either (\e -> assertFailure ("load jobs: " ++ show e)) pure eJobs
  assertEqual "jobs removed" [] jobs
  -- Old generation ids are dead.
  stale <- storeCommit s emptyDelta
    { sdPutJobs = [demoJobPending 12 (trId tok) gen1] }
  case stale of
    NotCommitted (StoreRevisionConflict _) -> pure ()
    other -> assertFailure ("expected generation refusal, got: " ++ show other)
  -- Current generation works.
  fresh <- storeCommit s emptyDelta
    { sdPutJobs = [demoJobPending 12 (trId tok) (Generation 2)] }
  assertEqual "new generation writable" Committed fresh
  -- Reset with a stale expectation refuses.
  rr2 <- storeResetToken s (trId tok) gen1 replacement
  case rr2 of
    NotCommitted (StoreRevisionConflict _) -> pure ()
    other -> assertFailure ("expected stale reset refusal, got: " ++ show other)
  -- Reset of a missing token refuses.
  rr3 <- storeResetToken s (TokenId 99) (Generation 1) replacement
  case rr3 of
    NotCommitted (StoreRevisionConflict _) -> pure ()
    other -> assertFailure ("expected missing reset refusal, got: " ++ show other)
  storeClose s

-- | Read the durable job-id mark ('Nothing' = the key is absent).
loadCounter :: Store -> IO (Maybe String)
loadCounter s = do
  eMeta <- storeLoadMeta s
  meta <- either (\e -> assertFailure ("loadMeta: " ++ show e)) pure eMeta
  pure (lookup jobIdCounterKey meta)

-- | Reservation hands out increasing durable ids: 1, 2, then 3
-- after a close/reopen boundary, with the mark persisted.
testReserveIncreasing :: Opener -> IO ()
testReserveIncreasing o = withStore o $ \s -> do
  r1 <- storeReserveJobId s >>= expectRight "reserve 1"
  r2 <- storeReserveJobId s >>= expectRight "reserve 2"
  assertEqual "increasing" [1, 2] [r1, r2]
  storeClose s
  eStore2 <- openCurrent o
  s2 <- either (\e -> assertFailure ("reopen: " ++ show e)) pure eStore2
  r3 <- storeReserveJobId s2 >>= expectRight "reserve 3"
  assertEqual "durable across reopen" 3 r3
  mark <- loadCounter s2
  assertEqual "mark persisted" (Just (encodeHexWord64 4)) mark
  storeClose s2

-- | A store with hand-seated jobs reconciles the mark with the
-- stored maximum — without ever lowering a higher mark.
testReserveReconciles :: Opener -> IO ()
testReserveReconciles o = withStore o $ \s -> do
  (tok, _) <- seedStore s
  rJobs <- storeCommit s emptyDelta
    { sdPutJobs = [demoJobPending 41 (trId tok) (trGeneration tok)] }
  assertEqual "jobs seed" Committed rJobs
  r1 <- storeReserveJobId s >>= expectRight "reserve past jobs"
  assertEqual "reconciles with max job + 1" 42 r1
  rMeta <- storeCommit s emptyDelta
    { sdPutMeta = [(jobIdCounterKey, encodeHexWord64 100)] }
  assertEqual "mark seed" Committed rMeta
  r2 <- storeReserveJobId s >>= expectRight "reserve past mark"
  assertEqual "never lowers the mark" 100 r2
  mark <- loadCounter s
  assertEqual "mark advanced" (Just (encodeHexWord64 101)) mark

-- | Reset and token drop remove job rows but keep the
-- high-water mark: later reservations never reuse ids.
testReserveSurvivesReset :: Opener -> IO ()
testReserveSurvivesReset o = withStore o $ \s -> do
  (tok, _) <- seedStore s
  let gen1 = trGeneration tok
  r1 <- storeReserveJobId s >>= expectRight "reserve 1"
  assertEqual "first id" 1 r1
  rJobs <- storeCommit s emptyDelta
    { sdPutJobs = [demoJobPending r1 (trId tok) gen1] }
  assertEqual "job insert" Committed rJobs
  let replacement = tok { trGeneration = Generation 2, trLabel = "seed-token-gen2" }
  rr <- storeResetToken s (trId tok) gen1 replacement
  assertEqual "reset commits" Committed rr
  eJobs <- storeLoadJobs s
  jobs <- either (\e -> assertFailure ("load jobs: " ++ show e)) pure eJobs
  assertEqual "reset drops job rows" [] jobs
  r2 <- storeReserveJobId s >>= expectRight "reserve after reset"
  assertEqual "mark kept across reset" 2 r2
  rDrop <- storeCommit s emptyDelta { sdDropTokens = [trId tok] }
  assertEqual "drop commits" Committed rDrop
  r3 <- storeReserveJobId s >>= expectRight "reserve after drop"
  assertEqual "mark kept across drop" 3 r3

-- | The id space refuses before the 'Word64' domain can wrap:
-- the next-to-last id hands out once, then reservation fails
-- with the mark parked (never wrapped to zero).
testReserveExhaustion :: Opener -> IO ()
testReserveExhaustion o = withStore o $ \s -> do
  _ <- seedStore s
  let nearMax = maxBound - 1 :: Word64
  rMeta <- storeCommit s emptyDelta
    { sdPutMeta = [(jobIdCounterKey, encodeHexWord64 nearMax)] }
  assertEqual "mark seed" Committed rMeta
  r1 <- storeReserveJobId s >>= expectRight "reserve next-to-last"
  assertEqual "next-to-last hands out" nearMax r1
  eFull <- storeReserveJobId s
  case eFull of
    Left (StoreFull _) -> pure ()
    other -> assertFailure ("expected StoreFull, got: " ++ show other)
  mark <- loadCounter s
  assertEqual "mark parked, never wrapped" (Just (encodeHexWord64 maxBound)) mark
  eJobs <- storeLoadJobs s
  jobs <- either (\e -> assertFailure ("load jobs: " ++ show e)) pure eJobs
  assertEqual "no phantom records" [] jobs

-- | A corrupt counter fails closed (never a guessed id) and
-- the store serves again once the mark is repaired.
testReserveCorrupt :: Opener -> IO ()
testReserveCorrupt o = withStore o $ \s -> do
  _ <- seedStore s
  rMeta <- storeCommit s emptyDelta
    { sdPutMeta = [(jobIdCounterKey, "not-a-counter")] }
  assertEqual "mark seed" Committed rMeta
  eBad <- storeReserveJobId s
  case eBad of
    Left (StoreCorrupt _) -> pure ()
    other -> assertFailure ("expected StoreCorrupt, got: " ++ show other)
  rFix <- storeCommit s emptyDelta
    { sdPutMeta = [(jobIdCounterKey, encodeHexWord64 5)] }
  assertEqual "mark repair" Committed rFix
  r1 <- storeReserveJobId s >>= expectRight "reserve after repair"
  assertEqual "repaired mark serves" 5 r1

-- | Seed the legacy shape: a token with a hand-minted job id 1
-- while the durable mark still reads 1 (the pre-reservation
-- allocator never advanced it). Return the token record.
seedLegacy :: Store -> IO TokenRecord
seedLegacy s = do
  (tok, _) <- seedStore s
  rJobs <- storeCommit s emptyDelta
    { sdPutJobs = [demoJobPending 1 (trId tok) (trGeneration tok)] }
  assertEqual "legacy job seed" Committed rJobs
  rMeta <- storeCommit s emptyDelta
    { sdPutMeta = [(jobIdCounterKey, encodeHexWord64 1)] }
  assertEqual "legacy mark seed" Committed rMeta
  pure tok

-- | A legacy store reset before its first reservation still
-- cannot re-mint the deleted id: the deleting commit folds the
-- doomed pid into the mark.
testLegacyResetCovers :: Opener -> IO ()
testLegacyResetCovers o = withStore o $ \s -> do
  tok <- seedLegacy s
  let gen1 = trGeneration tok
      replacement = tok { trGeneration = Generation 2, trLabel = "seed-token-gen2" }
  rr <- storeResetToken s (trId tok) gen1 replacement
  assertEqual "reset commits" Committed rr
  eJobs <- storeLoadJobs s
  jobs <- either (\e -> assertFailure ("load jobs: " ++ show e)) pure eJobs
  assertEqual "reset drops job rows" [] jobs
  r1 <- storeReserveJobId s >>= expectRight "first reservation after reset"
  assertEqual "deleted id never re-minted" 2 r1

-- | A legacy store whose token is dropped before its first
-- reservation still cannot re-mint the cascade-deleted id.
testLegacyDropCovers :: Opener -> IO ()
testLegacyDropCovers o = withStore o $ \s -> do
  tok <- seedLegacy s
  rDrop <- storeCommit s emptyDelta { sdDropTokens = [trId tok] }
  assertEqual "drop commits" Committed rDrop
  eJobs <- storeLoadJobs s
  jobs <- either (\e -> assertFailure ("load jobs: " ++ show e)) pure eJobs
  assertEqual "drop cascades to jobs" [] jobs
  r1 <- storeReserveJobId s >>= expectRight "first reservation after drop"
  assertEqual "deleted id never re-minted" 2 r1

-- | A legacy store whose job row is dropped explicitly before
-- its first reservation still cannot re-mint the deleted id.
testLegacyJobDropCovers :: Opener -> IO ()
testLegacyJobDropCovers o = withStore o $ \s -> do
  _ <- seedLegacy s
  rDrop <- storeCommit s emptyDelta { sdDropJobs = [1] }
  assertEqual "job drop commits" Committed rDrop
  r1 <- storeReserveJobId s >>= expectRight "first reservation after job drop"
  assertEqual "deleted id never re-minted" 2 r1

-- | Dropping an unknown job id is a silent no-op that burns
-- nothing: the next reservation still hands out 1.
testPhantomDropBurnsNothing :: Opener -> IO ()
testPhantomDropBurnsNothing o = withStore o $ \s -> do
  _ <- seedStore s
  rDrop <- storeCommit s emptyDelta { sdDropJobs = [9999] }
  assertEqual "phantom drop commits" Committed rDrop
  r1 <- storeReserveJobId s >>= expectRight "reserve after phantom drop"
  assertEqual "nothing burned" 1 r1

-- | A corrupt mark stays failed-closed across deletes and
-- reset: removing rows never derives a reusable small counter
-- from partial history (a previously returned higher id whose
-- row is gone must not become mintable again).
testCorruptDeleteStaysClosed :: Opener -> IO ()
testCorruptDeleteStaysClosed o = withStore o $ \s -> do
  (tok, _) <- seedStore s
  let gen = trGeneration tok
  r1 <- storeReserveJobId s >>= expectRight "reserve 1"
  r2 <- storeReserveJobId s >>= expectRight "reserve 2"
  r3 <- storeReserveJobId s >>= expectRight "reserve 3"
  assertEqual "increasing" [1, 2, 3] [r1, r2, r3]
  rJobs <- storeCommit s emptyDelta
    { sdPutJobs =
        [ demoJobPending r1 (trId tok) gen
        , demoJobPending r2 (trId tok) gen
        , demoJobPending r3 (trId tok) gen
        ]
    }
  assertEqual "jobs seed" Committed rJobs
  rDrop <- storeCommit s emptyDelta { sdDropJobs = [r3] }
  assertEqual "drop commits" Committed rDrop
  markBefore <- loadCounter s
  assertEqual "healthy cover keeps the mark" (Just (encodeHexWord64 4)) markBefore
  rMeta <- storeCommit s emptyDelta
    { sdPutMeta = [(jobIdCounterKey, "not-a-counter")] }
  assertEqual "mark corrupt" Committed rMeta
  eBad <- storeReserveJobId s
  case eBad of
    Left (StoreCorrupt _) -> pure ()
    other -> assertFailure ("expected StoreCorrupt, got: " ++ show other)
  rDrop2 <- storeCommit s emptyDelta { sdDropJobs = [r2] }
  assertEqual "delete under corruption commits" Committed rDrop2
  markMid <- loadCounter s
  assertEqual "delete never heals the mark" (Just "not-a-counter") markMid
  eBad2 <- storeReserveJobId s
  case eBad2 of
    Left (StoreCorrupt _) -> pure ()
    other -> assertFailure ("expected StoreCorrupt after delete, got: " ++ show other)
  let replacement = tok { trGeneration = Generation 2, trLabel = "seed-token-gen2" }
  rr <- storeResetToken s (trId tok) gen replacement
  assertEqual "reset under corruption commits" Committed rr
  eJobs <- storeLoadJobs s
  jobs <- either (\e -> assertFailure ("load jobs: " ++ show e)) pure eJobs
  assertEqual "reset drops job rows" [] jobs
  markAfter <- loadCounter s
  assertEqual "reset never heals the mark" (Just "not-a-counter") markAfter
  eBad3 <- storeReserveJobId s
  case eBad3 of
    Left (StoreCorrupt _) -> pure ()
    other -> assertFailure ("expected StoreCorrupt after reset, got: " ++ show other)

-- | Referential validation: object and job puts naming a missing
-- token refuse; a token created in the SAME delta satisfies refs.
testMissingTokenRefs :: Opener -> IO ()
testMissingTokenRefs o = do
  eStore <- openCurrent o
  s <- either (\e -> assertFailure ("open: " ++ show e)) pure eStore
  _ <- seedStore s
  recGhost <- freshObject (TokenId 99)
  bad <- storeCommit s emptyDelta
    { sdPutObjects = [ObjectPut Nothing recGhost] }
  case bad of
    NotCommitted (StoreRevisionConflict _) -> pure ()
    other -> assertFailure ("expected object refusal, got: " ++ show other)
  badJ <- storeCommit s emptyDelta
    { sdPutJobs = [demoJobPending 20 (TokenId 99) (Generation 1)] }
  case badJ of
    NotCommitted (StoreRevisionConflict _) -> pure ()
    other -> assertFailure ("expected job refusal, got: " ++ show other)
  let newTok = TokenRecord
        { trId = TokenId 100
        , trSlot = SlotId 1
        , trGeneration = Generation 1
        , trLabel = "late-token"
        , trAuth = tokenAuthNew
        }
  recNew <- freshObject (TokenId 100)
  ok <- storeCommit s emptyDelta
    { sdPutTokens = [newTok]
    , sdPutObjects = [ObjectPut Nothing recNew]
    , sdPutJobs = [demoJobPending 21 (TokenId 100) (Generation 1)]
    }
  assertEqual "same-delta refs commit" Committed ok
  storeClose s

-- | Acceptance 5 (encoding fixtures): no stored document mentions
-- pointers, handles, callbacks, or native contexts, and the only
-- bare JSON number is @format_version@.
testNoPointerBytes :: Opener -> IO ()
testNoPointerBytes o = do
  eStore <- openCurrent o
  s <- either (\e -> assertFailure ("open: " ++ show e)) pure eStore
  (tok, _) <- seedStore s
  r <- storeCommit s emptyDelta
    { sdPutJobs =
        [ demoJobPending 30 (trId tok) (trGeneration tok)
        , demoJobResult 31 (trId tok) (trGeneration tok)
        ]
    }
  assertEqual "jobs commit" Committed r
  docs <- expectInspect s
  assertBool "docs non-empty" (not (null docs))
  mapM_ checkDoc docs
  storeClose s
  where
    checkDoc d = do
      assertBool ("clean bytes: " ++ docTable d ++ "/" ++ docKey d)
        (cleanBytes (docJson d))
      assertBool ("numbers only as format_version: " ++ docKey d)
        (numbersClean (docJson d))

-- | SQLite-only: the same fixture scan over the RAW column values
-- read through an independent driver session (not our inspect).
testRawColumnsClean :: IO ()
testRawColumnsClean =
  bracket (makeTempDir "haskoki-storage-rawscan") removeDirectoryRecursive $ \dir -> do
    let path = dir </> "store.db"
    eStore <- openSQLiteStore path
    s <- either (\e -> assertFailure ("open: " ++ show e)) pure eStore
    (tok, _) <- seedStore s
    r <- storeCommit s emptyDelta
      { sdPutJobs =
          [ demoJobPending 40 (trId tok) (trGeneration tok)
          , demoJobResult 41 (trId tok) (trGeneration tok)
          ]
      }
    assertEqual "jobs commit" Committed r
    storeClose s
    db <- S.open (T.pack path)
    tokDocs <- rawTexts db (T.pack "SELECT record_json FROM tokens")
    attrDocs <- rawTexts db (T.pack "SELECT attributes_json FROM objects")
    matDocs <- rawTexts db (T.pack "SELECT material_encoding FROM objects")
    jobDocs <- rawTexts db (T.pack "SELECT record_json FROM detached_jobs")
    blobs <- rawBlobs db (T.pack "SELECT material_blob FROM objects WHERE material_blob IS NOT NULL")
    S.close db
    let texts = tokDocs ++ attrDocs ++ matDocs ++ jobDocs ++ blobs
    assertBool "raw columns non-empty" (not (null texts))
    mapM_ (\t -> assertBool ("raw clean: " ++ take 40 t) (cleanBytes t)) texts
    mapM_ (\t -> assertBool ("raw numbers: " ++ take 40 t) (numbersClean t))
      (tokDocs ++ attrDocs ++ jobDocs)

-- | Read one text column from every row of a raw query.
rawTexts :: S.Database -> T.Text -> IO [String]
rawTexts db sql =
  bracket (S.prepare db sql) S.finalize collect
  where
    collect stmt = do
      r <- S.step stmt
      case r of
        S.Done -> pure []
        S.Row -> do
          cols <- S.columns stmt
          rest <- collect stmt
          pure ([T.unpack t | S.SQLText t <- cols] ++ rest)

-- | Read one blob column from every row of a raw query.
rawBlobs :: S.Database -> T.Text -> IO [String]
rawBlobs db sql =
  bracket (S.prepare db sql) S.finalize collect
  where
    collect stmt = do
      r <- S.step stmt
      case r of
        S.Done -> pure []
        S.Row -> do
          cols <- S.columns stmt
          rest <- collect stmt
          pure ([BC8.unpack b | S.SQLBlob b <- cols] ++ rest)

-- | The package root, resolved CWD-independently (same
-- funnel-cwd hardening as the model suite: walk up from the test
-- binary's own directory to haskoki.cabal).
storePackageRoot :: IO FilePath
storePackageRoot = do
  exeDir <- takeDirectory <$> getExecutablePath
  ascend exeDir
  where
    ascend dir = do
      here <- doesFileExist (dir </> "haskoki.cabal")
      if here
        then pure dir
        else let parent = takeDirectory dir
             in if parent == dir
                  then assertFailure "schema-shape: haskoki.cabal not found"
                  else ascend parent

-- | Normalize DDL for comparison: collapse whitespace runs and
-- drop spaces adjacent to parens/commas. Sound here because no
-- quoted literal in either schema text contains a space (pinned
-- implicitly: any such literal would break the equality below).
normDDL :: String -> String
normDDL s = [c | (prev, c, next) <- triples (' ' : collapsed ++ " "), keep prev c next]
  where
    collapsed = unwords (words s)
    triples (a : b : c : rest) = (a, b, c) : triples (b : c : rest)
    triples _ = []
    keep prev c next = c /= ' ' || not (prev `elem` punct || next `elem` punct)
    punct = "()," :: String

-- | Split spec SQL text into statements: drop `--` comment lines,
-- split on `;`, drop empties.
specStatements :: String -> [String]
specStatements text =
  [ t
  | chunk <- splitOn ';' noComments
  , let t = trim chunk
  , not (null t)
  ]
  where
    noComments = unlines
      [l | l <- lines text, not ("--" `isPrefixOf` dropWhile isSpace l)]
    trim = reverse . dropWhile isSpace . reverse . dropWhile isSpace
    splitOn _ [] = [[]]
    splitOn d (c : cs)
      | c == d = [] : splitOn d cs
      | otherwise = case splitOn d cs of
          [] -> [[c]]
          (h : t) -> (c : h) : t

-- | The live SQLite schema (tables + indexes, read back
-- from sqlite_master of a fresh store) equals the readable
-- reference spec/storage-schema.sql modulo whitespace.
testSchemaShape :: IO ()
testSchemaShape = do
  mOut <- timeout (120 * 1000000) $ do
    root <- storePackageRoot
    specText <- readFile (root </> "spec/storage-schema.sql")
    let specDDLs = sort
          [ normDDL s
          | s <- specStatements specText
          , "CREATE TABLE" `isPrefixOf` s || "CREATE INDEX" `isPrefixOf` s
          ]
        specPragmas =
          [ s
          | s <- specStatements specText
          , "PRAGMA" `isPrefixOf` s
          ]
    assertEqual "spec table+index count" 7 (length specDDLs)
    assertEqual "spec pragma count" 4 (length specPragmas)
    bracket (makeTempDir "haskoki-storage-schema") removeDirectoryRecursive $ \dir -> do
      let path = dir </> "store.db"
      eStore <- openSQLiteStore path
      s <- either (\e -> assertFailure ("open: " ++ show e)) pure eStore
      storeClose s
      db <- S.open (T.pack path)
      liveDDLs <- sort . map normDDL <$> rawTexts db
        (T.pack "SELECT sql FROM sqlite_master WHERE sql IS NOT NULL")
      S.close db
      assertEqual "live schema equals spec/storage-schema.sql" specDDLs liveDDLs
  case mOut of
    Just () -> pure ()
    Nothing -> assertFailure "schema-shape wedged (120s timeout)"

-- | Ownership guards (one case, sequential phases — the masked-proc
-- phase mutates @HASKOKI_PROC_ROOT@ process-wide, so the phases must
-- not run concurrently with each other): a stale-pid lock with no
-- holder is still takeable and the taken-over store keeps its data
-- (no fail-closed overreach); a second open with owner liveness
-- unknowable is refused; and a stale-pid lock whose kernel lock is
-- held is refused until the holder goes away.
testOwnershipGuards :: IO ()
testOwnershipGuards = do
  staleTakeable
  heldFlockRefuses
  maskedProcRefuses

-- | Variant guard: a lock naming a provably-dead pid, with no
-- kernel-lock holder, is taken over; the lock is re-owned and the
-- seeded data survives the takeover.
staleTakeable :: IO ()
staleTakeable =
  bracket (makeTempDir "haskoki-storage-stale") removeDirectoryRecursive $ \dir -> do
    let path = dir </> "store.db"
    e0 <- openSQLiteStore path
    s0 <- either (\e -> assertFailure ("stale seed open: " ++ show e)) pure e0
    _ <- seedStore s0
    storeClose s0
    deadPid <- reapedPid
    writeFile (path ++ ".lock") (show deadPid ++ "\n")
    e1 <- openSQLiteStore path
    s1 <- either (\e -> assertFailure ("stale takeover failed: " ++ show e)) pure e1
    me <- getProcessID
    content <- readFile (path ++ ".lock")
    assertEqual "stale: lock re-owned by taker" (show me ++ "\n") content
    eLoaded <- storeLoadTokens s1
    loaded <- either (\e -> assertFailure ("stale load after takeover: " ++ show e)) pure eLoaded
    assertEqual "stale: seeded token survives takeover" 1 (length loaded)
    storeClose s1

-- | Kernel guard: a stale-pid lock whose file is @flock@-held (a
-- live-but-hidden owner from the store's point of view) refuses the
-- takeover with 'StoreSecondWriter'; once the holder goes away the
-- same lock is takeable.
heldFlockRefuses :: IO ()
heldFlockRefuses =
  bracket (makeTempDir "haskoki-storage-held") removeDirectoryRecursive $ \dir -> do
    let path = dir </> "store.db"
    e0 <- openSQLiteStore path
    s0 <- either (\e -> assertFailure ("held seed open: " ++ show e)) pure e0
    storeClose s0
    deadPid <- reapedPid
    writeFile (path ++ ".lock") (show deadPid ++ "\n")
    bracket (openFd (path ++ ".lock") ReadOnly defaultFileFlags) closeFd $ \holderFd -> do
      held <- testTryFlock holderFd
      assertBool "held: test holder took the kernel lock" held
      e1 <- openSQLiteStore path
      case e1 of
        Right s1 -> do
          storeClose s1
          assertFailure "held: takeover succeeded despite held kernel lock (state fork)"
        Left (StoreSecondWriter _) -> pure ()
        Left other -> assertFailure ("held: wrong error for held lock: " ++ show other)
    e2 <- openSQLiteStore path
    s2 <- either (\e -> assertFailure ("held: takeover after release failed: " ++ show e)) pure e2
    storeClose s2

-- | Fail-closed guard: with @\/proc@ masked (via @HASKOKI_PROC_ROOT@,
-- deterministically empty), a second open against a live owner in
-- ANOTHER process is refused with the unknowable-liveness
-- 'StoreSecondWriter' instead of forking. The owner must be a
-- separate process: a same-process second open is refused by the
-- same-process guard before liveness is ever consulted, so it can
-- never pin the fail-closed path (and its message carries no
-- "unknowable" on either base or patch).
maskedProcRefuses :: IO ()
maskedProcRefuses =
  bracket (makeTempDir "haskoki-storage-masked") removeDirectoryRecursive $ \dir ->
    bracket (makeTempDir "haskoki-storage-emptyproc") removeDirectoryRecursive $ \emptyProc -> do
      reaped <- newIORef False
      let path = dir </> "store.db"
          doneFile = dir </> "holder.done"
          readyFile = dir </> "holder.ready"
      bracket (spawnHolder path doneFile readyFile) (releaseHolder reaped) $ \ph -> do
        holderPid <- spawnedPid ph "masked"
        awaitLockOwner path holderPid
        awaitDone readyFile (6000 :: Int)
        withProcRoot emptyProc $ do
          e2 <- openSQLiteStore path
          case e2 of
            Right s2 -> do
              storeClose s2
              assertFailure "masked: second open succeeded with liveness unknowable (state fork)"
            Left (StoreSecondWriter msg) ->
              assertBool ("masked: expected unknowable-liveness refusal, got: " ++ msg)
                ("unknowable" `isInfixOf` msg)
            Left other ->
              assertFailure ("masked: wrong error for unknowable liveness: " ++ show other)
        writeFile doneFile "done\n"
        awaitHolderExit reaped ph "masked"
        e3 <- openSQLiteStore path
        s3 <- either (\e -> assertFailure ("masked reopen after close: " ++ show e)) pure e3
        storeClose s3

-- | The lock holder: runs in a spawned child process (see
-- 'spawnHolder'), opens the store (becoming its live owner),
-- signals readiness only once the open has fully completed (the
-- pid names the lock before schema init finishes, so the lock
-- alone cannot gate a racing second open), waits for the parent's
-- done file, then closes and exits. Never returns to test code;
-- uses 'exitImmediately' to avoid flushing the parent's stdio
-- buffers.
--
-- Reserve mode (@HASKOKI_HOLDER_MODE=reserve@, passed only via
-- the child's spawn environment): after opening, the child
-- reserves one job id, records it at @HASKOKI_HOLDER_PIDFILE@,
-- signals ready, then parks in the reserve/insert window
-- without inserting, closing, or exiting — the parent kills it
-- there to observe true process death between the two commits.
--
-- Auth-probe mode (@HASKOKI_HOLDER_MODE=auth-probe@, likewise
-- environment-only): the child opens a full serving instance
-- over the path instead of the raw store and runs the
-- @HASKOKI_AUTH_SCRIPT@ login ops (see 'authProbeMain').
holderMain :: FilePath -> FilePath -> FilePath -> IO ()
holderMain path doneFile readyFile = do
  mode <- lookupEnv "HASKOKI_HOLDER_MODE"
  case mode of
    -- The auth probe opens a full serving instance, never the
    -- raw store: it must not become a bare store owner first
    -- (the instance open would then refuse as a second writer).
    Just "auth-probe" -> authProbeMain path
    _ -> holderStoreMain path doneFile readyFile mode

-- | The store-owner holder: open the raw store, optionally run
-- the reserve window, handshake on the ready/done files, then
-- close and exit.
holderStoreMain :: FilePath -> FilePath -> FilePath -> Maybe String -> IO ()
holderStoreMain path doneFile readyFile mode = do
  e <- openSQLiteStore path
  case e of
    Left _ -> exitImmediately (ExitFailure 1)
    Right s -> case mode of
      Just "reserve" -> do
        ePid <- storeReserveJobId s
        case ePid of
          Left _ -> exitImmediately (ExitFailure 2)
          Right pid -> do
            mPidFile <- lookupEnv "HASKOKI_HOLDER_PIDFILE"
            case mPidFile of
              Just pidFile -> writeFile pidFile (show pid ++ "\n")
              Nothing -> pure ()
            writeFile readyFile "ready\n"
            awaitDone doneFile (6000 :: Int)
            -- Crash simulation: never close, never insert.
            exitImmediately ExitSuccess
      _ -> do
        writeFile readyFile "ready\n"
        awaitDone doneFile (6000 :: Int)
        storeClose s
        exitImmediately ExitSuccess

-- | Auth-probe holder (@HASKOKI_HOLDER_MODE=auth-probe@): the
-- second-process leg of the durable-login suite. Opens a full
-- serving instance over the database path (home catalog, SQLite
-- store), opens one read/write session on slot 0, runs the
-- comma-separated @HASKOKI_AUTH_SCRIPT@ login ops, writes one
-- @op=decimal@ line per op to @HASKOKI_AUTH_RESULT@, closes, and
-- exits. Ops: @u-bad@\/@u-good@ (user login with a wrong\/home
-- PIN), @s-bad@\/@s-good@ (SO login likewise), @logout@, and
-- @info@ (the session login code). Any failure exits nonzero
-- without writing further lines; the parent joins with
-- 'awaitHolderExit' and asserts the exact lines.
authProbeMain :: FilePath -> IO ()
authProbeMain path = do
  mScript <- lookupEnv "HASKOKI_AUTH_SCRIPT"
  mResult <- lookupEnv "HASKOKI_AUTH_RESULT"
  case (mScript, mResult) of
    (Just script, Just result) -> do
      ctx <- openStdInstance sqliteCfg
      if castStablePtrToPtr ctx == nullPtr
        then exitImmediately (ExitFailure 2)
        else do
          h <- openProbeSession ctx
          case h of
            Nothing -> exitImmediately (ExitFailure 3)
            Just session -> do
              outs <- mapM (runProbeOp ctx session) (splitScript script)
              case sequence outs of
                Nothing -> exitImmediately (ExitFailure 4)
                Just rendered -> do
                  writeFile result (unlines rendered)
                  haskokiStdClose ctx
                  exitImmediately ExitSuccess
    _ -> exitImmediately (ExitFailure 5)
  where
    sqliteCfg = defaultConfig
      { cfgStorage = StorageCfg StorageSQLite (Just path) 5000 True }

-- | Open one read/write session on slot 0 for the probe.
openProbeSession :: StablePtr StdInstance -> IO (Maybe CULong)
openProbeSession ctx =
  alloca $ \(phSession :: Ptr CULong) -> do
    poke phSession (CULong 0)
    rv <- haskokiStdOpenSession ctx (CULong 0) (CULong 0) phSession
    if rv /= CULong 0
      then pure Nothing
      else Just <$> peek phSession

-- | Run one probe op, rendering its @op=decimal@ line ('Nothing'
-- on an unknown op).
runProbeOp :: StablePtr StdInstance -> CULong -> String -> IO (Maybe String)
runProbeOp ctx h op = case op of
  "u-bad" -> Just . render <$> probeLogin ctx h 1 "0000"
  "u-good" -> Just . render <$> probeLogin ctx h 1 "1234"
  "s-bad" -> Just . render <$> probeLogin ctx h 0 "0000"
  "s-good" -> Just . render <$> probeLogin ctx h 0 "5678"
  "logout" -> Just . render <$> haskokiStdLogout ctx h
  "info" -> fmap (fmap render) (probeLoginCode ctx h)
  _ -> pure Nothing
  where
    render (CULong n) = op ++ "=" ++ show n

-- | Log in with literal PIN bytes.
probeLogin :: StablePtr StdInstance -> CULong -> CULong -> String -> IO CULong
probeLogin ctx h userType pinStr =
  BS.useAsCStringLen (BC8.pack pinStr) $ \(cstr, len) ->
    haskokiStdLogin ctx h userType (castPtr cstr) (fromIntegral len)

-- | Read the session login code ('Nothing' unless the info call is OK).
probeLoginCode :: StablePtr StdInstance -> CULong -> IO (Maybe CULong)
probeLoginCode ctx h =
  alloca $ \(pSlot :: Ptr CULong) ->
  alloca $ \(pRO :: Ptr CULong) ->
  alloca $ \(pLogin :: Ptr CULong) ->
  alloca $ \(pDevErr :: Ptr CULong) -> do
    rv <- haskokiStdGetSessionInfo ctx h pSlot pRO pLogin pDevErr
    if rv /= CULong 0
      then pure Nothing
      else Just <$> peek pLogin

-- | Split a comma-separated probe script.
splitScript :: String -> [String]
splitScript = go
  where
    go [] = []
    go s = case break (== ',') s of
      (op, []) -> [op]
      (op, _ : rest) -> op : go rest

-- | Poll for the done file (10ms steps, bounded so a stuck parent
-- cannot wedge the suite past the tasty timeout).
awaitDone :: FilePath -> Int -> IO ()
awaitDone _ 0 = pure ()
awaitDone doneFile n = do
  done <- fileExist doneFile
  if done then pure () else threadDelay 10000 >> awaitDone doneFile (n - 1)

-- | Poll until the lock names the holder child (10s cap); the
-- holder is live from then on.
awaitLockOwner :: FilePath -> ProcessID -> IO ()
awaitLockOwner path holderPid = do
  let want = BC8.pack (show holderPid ++ "\n")
      go = do
        content <- catchIOError (BS.readFile (path ++ ".lock")) (\_ -> pure BS.empty)
        if content == want then pure () else threadDelay 10000 >> go
  mOk <- timeout 10000000 go
  case mOk of
    Just () -> pure ()
    Nothing -> assertFailure "masked: holder child did not take the lock"

-- | Spawn a holder child as a FRESH OS process (the test binary
-- re-invoked with @--holder@), never 'forkProcess': a forked child
-- would inherit the parent's open guard fds (the same open file
-- description — the parent's close then cannot release the kernel
-- locks while the child lives, poisoning concurrent tests with
-- spurious refusals) and forking a multithreaded RTS while another
-- thread is inside SQLite can wedge the child forever. The spawned
-- child starts with only stdio fds (@close_fds@) and a clean
-- address space.
spawnHolder :: FilePath -> FilePath -> FilePath -> IO ProcessHandle
spawnHolder path doneFile readyFile = do
  exe <- getExecutablePath
  (_, _, _, ph) <- createProcess ((proc exe ["--holder", path, doneFile, readyFile]) { close_fds = True })
  pure ph

-- | Spawn a holder child with extra environment entries (merged
-- over the parent's environment for the child only): mode
-- switches travel here so concurrent holders never observe a
-- process-wide mutation.
spawnHolderEnv :: [(String, String)] -> FilePath -> FilePath -> FilePath -> IO ProcessHandle
spawnHolderEnv extra path doneFile readyFile = do
  exe <- getExecutablePath
  parentEnv <- getEnvironment
  let merged = extra ++ [(k, v) | (k, v) <- parentEnv, k `notElem` map fst extra]
  (_, _, _, ph) <- createProcess
    ((proc exe ["--holder", path, doneFile, readyFile])
      { close_fds = True, env = Just merged })
  pure ph

-- | The spawned child's pid for the lock-ownership handshake;
-- fails fast when the child already exited before handshaking.
spawnedPid :: ProcessHandle -> String -> IO ProcessID
spawnedPid ph tag = do
  mPid <- getPid ph
  case mPid of
    Just pid -> pure pid
    Nothing -> assertFailure (tag ++ ": holder child exited before handshake")

-- | Claim the exactly-once right to reap a holder child: True
-- for the first claimer (it owns signal+reap), False once the
-- child has been reaped. A reaped numeric pid may be recycled by
-- an unrelated process, so it must never be signaled again.
claimReap :: IORef Bool -> IO Bool
claimReap ref = atomicModifyIORef' ref (\done -> (True, not done))

-- | Bounded wait on a holder child (10ms non-blocking polls), so
-- a wedged child cannot hang the suite. Nothing on timeout; every
-- error is swallowed on the release path.
waitBounded :: ProcessHandle -> Int -> IO (Maybe ExitCode)
waitBounded _ 0 = pure Nothing
waitBounded ph n = do
  mSt <- catchIOError (getProcessExitCode ph) (\_ -> pure Nothing)
  case mSt of
    Just st -> pure (Just st)
    Nothing -> threadDelay 10000 >> waitBounded ph (n - 1)

-- | Bracket release for a holder child: exactly-once SIGKILL plus
-- a bounded wait. A no-op when the body already reaped the child.
-- The kill targets only our own unreaped child (its pid cannot be
-- recycled before we reap it), never a recycled numeric pid.
-- Every failure is swallowed: the release must not mask the test
-- verdict.
releaseHolder :: IORef Bool -> ProcessHandle -> IO ()
releaseHolder reaped ph = do
  ours <- claimReap reaped
  when ours $ do
    catchIOError (getPid ph >>= maybe (pure ()) (signalProcess sigKILL)) (\_ -> pure ())
    _ <- waitBounded ph 500
    pure ()

-- | Bounded join on a holder child (10s cap) with checked exit
-- status; marks the child reaped so the bracket release skips it.
awaitHolderExit :: IORef Bool -> ProcessHandle -> String -> IO ()
awaitHolderExit reaped ph tag = do
  mSt <- waitBounded ph 1000
  case mSt of
    Nothing -> assertFailure (tag ++ ": holder child did not exit within 10s")
    Just st -> do
      _ <- claimReap reaped
      case st of
        ExitSuccess -> pure ()
        other -> assertFailure (tag ++ ": holder child failed: " ++ show other)

-- | Run with a path's mode overridden, restoring it afterwards
-- (a denied mode must never strand an undeletable fixture, even
-- when the action throws).
withFileMode :: FilePath -> FileMode -> IO a -> IO a
withFileMode p mode action = do
  st <- getFileStatus p
  bracket_ (setFileMode p mode) (setFileMode p (fileMode st)) action

-- | Run with @HASKOKI_PROC_ROOT@ overridden, restoring it afterwards.
withProcRoot :: FilePath -> IO a -> IO a
withProcRoot root action =
  bracket (lookupEnv "HASKOKI_PROC_ROOT")
          (\prev -> maybe (unsetEnv "HASKOKI_PROC_ROOT") (setEnv "HASKOKI_PROC_ROOT") prev)
          (\_ -> setEnv "HASKOKI_PROC_ROOT" root >> action)

-- | Run with @HASKOKI_OPEN_PAUSE@ (pause directory) and
-- @HASKOKI_OPEN_PAUSE_PATH@ (intended opener's database path)
-- overridden, restoring both afterwards. The path binding keeps
-- unrelated parallel SQLite creators from pausing on our handshake.
withOpenPause :: FilePath -> FilePath -> IO a -> IO a
withOpenPause dir want action =
  bracket (lookupEnv "HASKOKI_OPEN_PAUSE")
          (\prev -> maybe (unsetEnv "HASKOKI_OPEN_PAUSE") (setEnv "HASKOKI_OPEN_PAUSE") prev)
          (\_ -> setEnv "HASKOKI_OPEN_PAUSE" dir >> inner)
  where
    inner =
      bracket (lookupEnv "HASKOKI_OPEN_PAUSE_PATH")
              (\prev -> maybe (unsetEnv "HASKOKI_OPEN_PAUSE_PATH") (setEnv "HASKOKI_OPEN_PAUSE_PATH") prev)
              (\_ -> setEnv "HASKOKI_OPEN_PAUSE_PATH" want >> action)

-- | Unlink guard: deleting a live owner's lock path must not let
-- a second opener take over by creating and flocking a different
-- inode — exclusion is anchored to the database identity as well
-- as the sidecar, so the replacement lock's sidecar flock
-- succeeding still refuses at the database guard.
testUnlinkRefuses :: IO ()
testUnlinkRefuses =
  bracket (makeTempDir "haskoki-storage-unlink") removeDirectoryRecursive $ \dir -> do
    reaped <- newIORef False
    let path = dir </> "store.db"
        lockPath = path ++ ".lock"
        doneFile = dir </> "holder.done"
        readyFile = dir </> "holder.ready"
    bracket (spawnHolder path doneFile readyFile) (releaseHolder reaped) $ \ph -> do
      holderPid <- spawnedPid ph "unlink"
      awaitLockOwner path holderPid
      awaitDone readyFile (6000 :: Int)
      removeFile lockPath
      e2 <- openSQLiteStore path
      case e2 of
        Right s2 -> do
          storeClose s2
          assertFailure "unlink: second open took over after lock deletion (state fork)"
        Left (StoreSecondWriter msg) ->
          assertBool ("unlink: expected database-anchored refusal, got: " ++ msg)
            ("database" `isInfixOf` msg)
        Left other ->
          assertFailure ("unlink: wrong error after lock deletion: " ++ show other)
      writeFile doneFile "done\n"
      awaitHolderExit reaped ph "unlink"

-- | Owned-inode release: a replacement lock planted at the path
-- after a live owner's lock was deleted is NOT the owner's, so
-- the owner's close must leave it byte-identical (unlink only the
-- owned inode).
testCloseKeepsReplacement :: IO ()
testCloseKeepsReplacement =
  bracket (makeTempDir "haskoki-storage-replace") removeDirectoryRecursive $ \dir -> do
    reaped <- newIORef False
    let path = dir </> "store.db"
        lockPath = path ++ ".lock"
        doneFile = dir </> "holder.done"
        readyFile = dir </> "holder.ready"
    bracket (spawnHolder path doneFile readyFile) (releaseHolder reaped) $ \ph -> do
      holderPid <- spawnedPid ph "replace"
      awaitLockOwner path holderPid
      awaitDone readyFile (6000 :: Int)
      removeFile lockPath
      writeFile lockPath "replacement-marker\n"
      writeFile doneFile "done\n"
      awaitHolderExit reaped ph "replace"
      content <- readFile lockPath
      assertEqual "replace: owner close deleted a replacement lock"
        "replacement-marker\n" content

-- | Probe-error guard: a @\/proc@ root the opener cannot read
-- (@EACCES@) fails closed with a clean 'StoreSecondWriter', never
-- an uncaught 'IOException' — even when the named owner is dead
-- (death cannot be proven, so no takeover).
testProcUnreadableRefuses :: IO ()
testProcUnreadableRefuses =
  bracket (makeTempDir "haskoki-storage-noproc") removeDirectoryRecursive $ \dir ->
    bracket (makeTempDir "haskoki-storage-denied") removeDirectoryRecursive $ \denied -> do
      let path = dir </> "store.db"
      e0 <- openSQLiteStore path
      s0 <- either (\e -> assertFailure ("noproc seed open: " ++ show e)) pure e0
      storeClose s0
      deadPid <- reapedPid
      writeFile (path ++ ".lock") (show deadPid ++ "\n")
      withFileMode denied 0o000 $
        withProcRoot denied $ do
          e1 <- openSQLiteStore path
          case e1 of
            Right s1 -> do
              storeClose s1
              assertFailure "noproc: takeover succeeded with liveness unknowable (state fork)"
            Left (StoreSecondWriter msg) ->
              assertBool ("noproc: expected unknowable-liveness refusal, got: " ++ msg)
                ("unknowable" `isInfixOf` msg)
            Left other ->
              assertFailure ("noproc: wrong error for unreadable proc: " ++ show other)

-- | Partial-mask guard: a @\/proc@ view that shows @self@ but
-- hides our own pid, or whose owner entry ERRORS on stat (a
-- self-loop symlink: ELOOP for every runner, root included),
-- cannot prove death — so a second open against a live owner is
-- refused as unknowable, never misread as dead.
testProcPartialMaskRefuses :: IO ()
testProcPartialMaskRefuses =
  bracket (makeTempDir "haskoki-storage-pmask") removeDirectoryRecursive $ \dir ->
    bracket (makeTempDir "haskoki-storage-fakeproc") removeDirectoryRecursive $ \fakeProc -> do
      reaped <- newIORef False
      me <- getProcessID
      ppid <- getParentProcessID
      let path = dir </> "store.db"
          doneFile = dir </> "holder.done"
          readyFile = dir </> "holder.ready"
      bracket (spawnHolder path doneFile readyFile) (releaseHolder reaped) $ \ph -> do
        holderPid <- spawnedPid ph "pmask"
        awaitLockOwner path holderPid
        awaitDone readyFile (6000 :: Int)
        writeFile (fakeProc </> "self") ""
        withProcRoot fakeProc $ do
          e1 <- openSQLiteStore path
          case e1 of
            Right s1 -> do
              storeClose s1
              assertFailure "pmask: second open succeeded with a partial proc view (state fork)"
            Left (StoreSecondWriter msg) ->
              assertBool ("pmask: expected unknowable-liveness refusal, got: " ++ msg)
                ("unknowable" `isInfixOf` msg)
            Left other ->
              assertFailure ("pmask: wrong error for partial proc view: " ++ show other)
        writeFile (fakeProc </> show me) ""
        -- The parent witness must be present so phase 2 still pins
        -- the owner-entry error (not the parent's absence).
        writeFile (fakeProc </> show ppid) ""
        -- The owner entry must ERROR on stat (not merely be absent)
        -- while self+own-pid stay visible. A self-loop symlink stats
        -- as ELOOP for every runner; a chmod-000 construction would
        -- be bypassed as root (CI runs as root), misreading the live
        -- owner as dead.
        createSymbolicLink (show holderPid) (fakeProc </> show holderPid)
        withProcRoot fakeProc $ do
          e2 <- openSQLiteStore path
          case e2 of
            Right s2 -> do
              storeClose s2
              assertFailure "pmask: second open succeeded with owner entry denied (state fork)"
            Left (StoreSecondWriter msg) ->
              assertBool ("pmask: expected unknowable-liveness refusal, got: " ++ msg)
                ("unknowable" `isInfixOf` msg)
            Left other ->
              assertFailure ("pmask: wrong error for denied owner entry: " ++ show other)
        writeFile doneFile "done\n"
        awaitHolderExit reaped ph "pmask"
        e3 <- openSQLiteStore path
        s3 <- either (\e -> assertFailure ("pmask reopen after close: " ++ show e)) pure e3
        storeClose s3

-- | Fresh-guard test (finding 1): the database guard is held before
-- any SQLite work on the fresh-create path. A is forked and pauses
-- after creating+guarding the database (via @HASKOKI_OPEN_PAUSE@);
-- its sidecar is deleted (the finding's interleaving); B's open
-- must refuse at the database guard — never take over — and A's
-- resume must complete harmlessly. Then A owns alone and the store
-- reopens cleanly. In-process threads contend on @flock@ exactly
-- like processes (separate opens), so no spawn is needed.
testFreshGuardBeforeInit :: IO ()
testFreshGuardBeforeInit =
  bracket (makeTempDir "haskoki-storage-freshg") removeDirectoryRecursive $ \dir ->
    bracket (makeTempDir "haskoki-storage-pause") removeDirectoryRecursive $ \pauseDir -> do
      let path = dir </> "store.db"
          lockPath = path ++ ".lock"
          pausedFile = pauseDir </> "paused"
          goFile = pauseDir </> "go"
      withOpenPause pauseDir path $ do
        resVar <- newEmptyMVar
        _ <- forkIO $ do
          e <- openSQLiteStore path
          _ <- tryPutMVar resVar e
          pure ()
        awaitDone pausedFile (300 :: Int)
        paused <- doesFileExist pausedFile
        assertBool "freshg: opener did not pause (seam not honored?)" paused
        -- The interleaving: A loses its sidecar while paused.
        removeFile lockPath
        e2 <- openSQLiteStore path
        case e2 of
          Right s2 -> do
            storeClose s2
            assertFailure "freshg: second open took over a paused fresh init (state fork)"
          Left (StoreSecondWriter msg) ->
            assertBool ("freshg: expected database-anchored refusal, got: " ++ msg)
              ("database" `isInfixOf` msg)
          Left other ->
            assertFailure ("freshg: wrong error during paused fresh init: " ++ show other)
        writeFile goFile "go\n"
        mA <- timeout (30 * 1000000) (takeMVar resVar)
        eA <- case mA of
          Nothing -> assertFailure "freshg: paused opener wedged after release"
          Just e -> pure e
        sA <- either (\e -> assertFailure ("freshg: paused opener failed: " ++ show e)) pure eA
        storeClose sA
        e3 <- openSQLiteStore path
        s3 <- either (\e -> assertFailure ("freshg reopen after close: " ++ show e)) pure e3
        eLoaded <- storeLoadTokens s3
        _ <- either (\e -> assertFailure ("freshg load after close: " ++ show e)) pure eLoaded
        storeClose s3

-- | Swap-abort test (finding 1): if the database path no longer
-- names the guarded inode when SQLite opens it, the open aborts
-- with "replaced" instead of initializing another file — and the
-- planted file is left byte-identical. (The planted store is
-- created outside the pause env: it must not pause itself.)
testSwappedDbAborts :: IO ()
testSwappedDbAborts =
  bracket (makeTempDir "haskoki-storage-swap") removeDirectoryRecursive $ \dir ->
    bracket (makeTempDir "haskoki-storage-pause") removeDirectoryRecursive $ \pauseDir -> do
      let path = dir </> "store.db"
          plantSrc = dir </> "plant.db"
          movedAside = dir </> "moved-aside.db"
          pausedFile = pauseDir </> "paused"
          goFile = pauseDir </> "go"
      ePlant <- openSQLiteStore plantSrc
      plant <- either (\e -> assertFailure ("swap plant open: " ++ show e)) pure ePlant
      _ <- seedStore plant
      storeClose plant
      plantBytes <- BS.readFile plantSrc
      withOpenPause pauseDir path $ do
        resVar <- newEmptyMVar
        _ <- forkIO $ do
          e <- openSQLiteStore path
          _ <- tryPutMVar resVar e
          pure ()
        awaitDone pausedFile (300 :: Int)
        paused <- doesFileExist pausedFile
        assertBool "swap: opener did not pause (seam not honored?)" paused
        renameFile path movedAside
        renameFile plantSrc path
        writeFile goFile "go\n"
        mA <- timeout (30 * 1000000) (takeMVar resVar)
        eA <- case mA of
          Nothing -> assertFailure "swap: paused opener wedged after release"
          Just e -> pure e
        case eA of
          Right sA -> do
            storeClose sA
            assertFailure "swap: opener initialized a swapped-in database"
          Left (StoreIO msg) ->
            assertBool ("swap: expected replaced-database refusal, got: " ++ msg)
              ("replaced" `isInfixOf` msg)
          Left other ->
            assertFailure ("swap: wrong error for swapped database: " ++ show other)
        afterBytes <- BS.readFile path
        assertEqual "swap: planted database modified" plantBytes afterBytes
        aside <- doesFileExist movedAside
        assertBool "swap: paused opener's file went missing" aside
        e3 <- openSQLiteStore path
        s3 <- either (\e -> assertFailure ("swap reopen planted: " ++ show e)) pure e3
        eLoaded <- storeLoadTokens s3
        loaded <- either (\e -> assertFailure ("swap load planted: " ++ show e)) pure eLoaded
        assertEqual "swap: planted token survives" 1 (length loaded)
        storeClose s3

-- | Async-cleanup test (finding 2): killing a thread blocked in the
-- database-guard retry (flock-retry delays are interruptible even
-- under mask) must release the already-owned sidecar — never
-- strand a live-pid lock that wedges later opens. The parent holds
-- the database flock, so the opener retries over ~45ms; a kill is
-- attempted ~10ms after observing ownership. The observer also
-- checks completion, since scheduling can hide the short-lived
-- sidecar. A missed kill still asserts the clean end-state; the
-- hit counter requires at least one actual ThreadKilled outcome.
testKillDuringDbRetry :: IO ()
testKillDuringDbRetry =
  bracket (makeTempDir "haskoki-storage-killr") removeDirectoryRecursive $ \dir -> do
    let path = dir </> "store.db"
        lockPath = path ++ ".lock"
    e0 <- openSQLiteStore path
    s0 <- either (\e -> assertFailure ("killr seed open: " ++ show e)) pure e0
    storeClose s0
    me <- getProcessID
    hits <- newIORef (0 :: Int)
    let awaitOwnPid resVar = do
          let want = BC8.pack (show me ++ "\n")
              go = do
                completed <- tryReadMVar resVar
                case completed of
                  Just _ -> pure False
                  Nothing -> do
                    content <- catchIOError (BS.readFile lockPath) (\_ -> pure BS.empty)
                    if content == want then pure True else threadDelay 1000 >> go
          mOk <- timeout 10000000 go
          case mOk of
            Just observed -> pure observed
            Nothing -> assertFailure "killr: opener neither published ownership nor completed"
        loop 0 = pure ()
        loop n = do
          deadPid <- reapedPid
          writeFile lockPath (show deadPid ++ "\n")
          bracket (openFd path ReadOnly defaultFileFlags) closeFd $ \holdFd -> do
            held <- testTryFlock holdFd
            assertBool "killr: parent could not hold the database flock" held
            resVar <- newEmptyMVar
            bracket
              (forkFinally
                (do e <- openSQLiteStore path
                    case e of
                      Right s -> storeClose s
                      Left _ -> pure ())
                (putMVar resVar))
              (\tid -> do
                  stopped <- timeout (5 * 1000000) (killThread tid >> readMVar resVar)
                  case stopped of
                    Just _ -> pure ()
                    Nothing -> assertFailure "killr: retry worker did not finish during cleanup")
              $ \tid -> do
                observed <- awaitOwnPid resVar
                when observed $ do
                  threadDelay 10000
                  killThread tid
                mOut <- timeout (5 * 1000000) (readMVar resVar)
                case mOut of
                  Nothing -> assertFailure "killr: opener wedged after kill"
                  Just (Left err)
                    | observed && fromException err == Just ThreadKilled ->
                        atomicModifyIORef' hits (\h -> (h + 1, ()))
                    | otherwise -> assertFailure ("killr: unexpected opener exception: " ++ show err)
                  Just (Right ()) -> pure ()
          absent <- not <$> doesFileExist lockPath
          assertBool "killr: kill stranded the sidecar lock" absent
          eRe <- openSQLiteStore path
          sRe <- either (\e -> assertFailure ("killr: reopen wedged after kill: " ++ show e)) pure eRe
          storeClose sRe
          loop (n - 1)
    loop (20 :: Int)
    nHits <- readIORef hits
    assertBool "killr: no mid-window kill observed (vacuous?)" (nHits >= 1)

-- | Selective-hiding test (finding 3): a @\/proc@ view showing
-- @self@ and our own pid but hiding the live owner's entry with
-- @ENOENT@ cannot prove death — the parent witness (always a live
-- process) is absent, so the open refuses as unknowable. A
-- surgical filter hiding ONLY the owner is
-- @\/proc@-indistinguishable from a dead owner and falls through
-- to the kernel-lock backstop, which still refuses.
testSelectiveHideRefuses :: IO ()
testSelectiveHideRefuses =
  bracket (makeTempDir "haskoki-storage-selhide") removeDirectoryRecursive $ \dir ->
    bracket (makeTempDir "haskoki-storage-fakeproc") removeDirectoryRecursive $ \fakeProc -> do
      reaped <- newIORef False
      me <- getProcessID
      ppid <- getParentProcessID
      let path = dir </> "store.db"
          doneFile = dir </> "holder.done"
          readyFile = dir </> "holder.ready"
      bracket (spawnHolder path doneFile readyFile) (releaseHolder reaped) $ \ph -> do
        holderPid <- spawnedPid ph "selhide"
        awaitLockOwner path holderPid
        awaitDone readyFile (6000 :: Int)
        -- Phase A: self + own pid visible, live owner hidden
        -- (ENOENT), parent witness absent -> unknowable.
        writeFile (fakeProc </> "self") ""
        writeFile (fakeProc </> show me) ""
        withProcRoot fakeProc $ do
          e1 <- openSQLiteStore path
          case e1 of
            Right s1 -> do
              storeClose s1
              assertFailure "selhide: second open succeeded with owner hidden (state fork)"
            Left (StoreSecondWriter msg) ->
              assertBool ("selhide: expected unknowable-liveness refusal, got: " ++ msg)
                ("unknowable" `isInfixOf` msg)
            Left other ->
              assertFailure ("selhide: wrong error for hidden owner: " ++ show other)
        -- Phase B: the surgical residual — parent witness present,
        -- only the live owner hidden -> takeover attempted, kernel
        -- lock backstop refuses.
        writeFile (fakeProc </> show ppid) ""
        withProcRoot fakeProc $ do
          e2 <- openSQLiteStore path
          case e2 of
            Right s2 -> do
              storeClose s2
              assertFailure "selhide: second open took over a live owner (state fork)"
            Left (StoreSecondWriter msg) ->
              assertBool ("selhide: expected kernel-lock refusal, got: " ++ msg)
                ("kernel lock held" `isInfixOf` msg)
            Left other ->
              assertFailure ("selhide: wrong error for surgical hiding: " ++ show other)
        writeFile doneFile "done\n"
        awaitHolderExit reaped ph "selhide"
        e3 <- openSQLiteStore path
        s3 <- either (\e -> assertFailure ("selhide reopen after close: " ++ show e)) pure e3
        storeClose s3

-- | Pause-isolation test (finding 3): with the pause seam armed
-- for one intended database path, a fresh-create open of a
-- DIFFERENT path must not pause. (Before path binding, any parallel
-- SQLite creator — contract/commit tests, inherited-env holders —
-- paused on the same handshake file and could satisfy the
-- controller's handshake before the intended opener paused.)
testPauseBindsToIntendedOpener :: IO ()
testPauseBindsToIntendedOpener =
  bracket (makeTempDir "haskoki-storage-pausebind") removeDirectoryRecursive $ \dir ->
    bracket (makeTempDir "haskoki-storage-pause") removeDirectoryRecursive $ \pauseDir -> do
      let intended = dir </> "intended.db"
          other = dir </> "other.db"
      withOpenPause pauseDir intended $ do
        resVar <- newEmptyMVar
        _ <- forkIO $ do
          e <- openSQLiteStore other
          _ <- tryPutMVar resVar e
          pure ()
        mDone <- timeout (5 * 1000000) (takeMVar resVar)
        eOther <- case mDone of
          Nothing -> assertFailure "pausebind: unrelated fresh open paused (seam leaked across openers)"
          Just e -> pure e
        sOther <- either (\e -> assertFailure ("pausebind: unrelated open failed: " ++ show e)) pure eOther
        storeClose sOther
        pausedExists <- doesFileExist (pauseDir </> "paused")
        assertBool "pausebind: pause seam fired for an unintended opener" (not pausedExists)

-- | Pid-0 test (finding 2): a lock naming pid 0 is takeable WITHOUT
-- probing @\/proc\/0@ — pid 0 is never a userspace owner (owners
-- write @getProcessID@), so the entry is dead by rule while the
-- kernel backstop still confirms. The fake proc root even contains
-- a @0@ entry: any probe would read Present (alive) and refuse, so
-- success proves no probe happened.
testPidZeroTakeable :: IO ()
testPidZeroTakeable =
  bracket (makeTempDir "haskoki-storage-pidzero") removeDirectoryRecursive $ \dir ->
    bracket (makeTempDir "haskoki-storage-fakeproc") removeDirectoryRecursive $ \fakeProc -> do
      me <- getProcessID
      ppid <- getParentProcessID
      let path = dir </> "store.db"
      e0 <- openSQLiteStore path
      s0 <- either (\e -> assertFailure ("pidzero seed open: " ++ show e)) pure e0
      _ <- seedStore s0
      storeClose s0
      writeFile (path ++ ".lock") "0\n"
      writeFile (fakeProc </> "self") ""
      writeFile (fakeProc </> show me) ""
      writeFile (fakeProc </> show ppid) ""
      writeFile (fakeProc </> "0") ""
      withProcRoot fakeProc $ do
        e1 <- openSQLiteStore path
        s1 <- either (\e -> assertFailure ("pidzero takeover failed: " ++ show e)) pure e1
        content <- readFile (path ++ ".lock")
        assertEqual "pidzero: lock re-owned by taker" (show me ++ "\n") content
        eLoaded <- storeLoadTokens s1
        loaded <- either (\e -> assertFailure ("pidzero load after takeover: " ++ show e)) pure eLoaded
        assertEqual "pidzero: seeded token survives takeover" 1 (length loaded)
        storeClose s1

-- | Death between reservation and insertion: a holder child in
-- reserve mode opens the store, durably reserves one id,
-- records it, and parks; the parent SIGKILLs it there (no
-- close, no insert), takes over the stale lock via the real
-- /proc, and proves the burned id is absent and never reused.
testReserveDeathGap :: IO ()
testReserveDeathGap =
  bracket (makeTempDir "haskoki-storage-reservedeath") removeDirectoryRecursive $ \dir -> do
    reaped <- newIORef False
    let path = dir </> "store.db"
        doneFile = dir </> "holder.done"
        readyFile = dir </> "holder.ready"
        pidFile = dir </> "holder.pid"
    e0 <- openSQLiteStore path
    s0 <- either (\e -> assertFailure ("reserve-death seed open: " ++ show e)) pure e0
    (tok, _) <- seedStore s0
    storeClose s0
    let childEnv =
          [ ("HASKOKI_HOLDER_MODE", "reserve")
          , ("HASKOKI_HOLDER_PIDFILE", pidFile)
          ]
    bracket (spawnHolderEnv childEnv path doneFile readyFile) (releaseHolder reaped) $ \ph -> do
      holderPid <- spawnedPid ph "reserve-death"
      awaitLockOwner path holderPid
      awaitDone readyFile (6000 :: Int)
      pidText <- readFile pidFile
      burned <- case reads pidText of
        [(n, _)] -> pure (n :: Word64)
        _ -> assertFailure "reserve-death: child recorded no id"
      -- True process death in the reserve/insert window.
      signalProcess sigKILL holderPid
      mSt <- waitBounded ph 1000
      case mSt of
        Nothing -> assertFailure "reserve-death: child survived SIGKILL"
        Just _ -> do
          _ <- claimReap reaped
          pure ()
      -- Stale takeover, then the gap proof.
      e1 <- openSQLiteStore path
      s1 <- either (\e -> assertFailure ("reserve-death takeover failed: " ++ show e)) pure e1
      eJobs <- storeLoadJobs s1
      jobs <- either (\e -> assertFailure ("reserve-death load jobs: " ++ show e)) pure eJobs
      assertEqual "burned id names no record" [] jobs
      next <- storeReserveJobId s1 >>= expectRight "reserve-death next"
      assertEqual "gap, never a reuse" (burned + 1) next
      landed <- storeCommit s1 emptyDelta
        { sdPutJobs = [demoJobPending next (trId tok) (trGeneration tok)] }
      assertEqual "insert lands" Committed landed
      eJobs2 <- storeLoadJobs s1
      jobs2 <- either (\e -> assertFailure ("reserve-death reload jobs: " ++ show e)) pure eJobs2
      assertEqual "only the new record exists" [next] (map jrPersistentId jobs2)
      storeClose s1

-- | Liveness-mapping unit test (finding 2): the pure verdict
-- table over synthetic probe results, pinning the namespace-local
-- ppid-0 rule (parent witness inapplicable, stale recovery works)
-- without forking into a PID namespace — plus the fail-closed rows
-- the @\/proc@-fixture tests rely on.
testLivenessMapping :: IO ()
testLivenessMapping = do
  let t = assertEqual "liveness mapping"
  -- The ppid-0 rule (parent probe Nothing: no /proc/0 probe taken).
  t PidDead $ livenessFromProbes ProbePresent ProbePresent Nothing ProbeAbsent
  t PidAlive $ livenessFromProbes ProbePresent ProbePresent Nothing ProbePresent
  t PidUnknown $ livenessFromProbes ProbePresent ProbePresent Nothing ProbeUnknown
  -- The parent witness still gates when the ppid is namespace-local.
  t PidDead $ livenessFromProbes ProbePresent ProbePresent (Just ProbePresent) ProbeAbsent
  t PidAlive $ livenessFromProbes ProbePresent ProbePresent (Just ProbePresent) ProbePresent
  t PidUnknown $ livenessFromProbes ProbePresent ProbePresent (Just ProbePresent) ProbeUnknown
  t PidUnknown $ livenessFromProbes ProbePresent ProbePresent (Just ProbeAbsent) ProbeAbsent
  t PidUnknown $ livenessFromProbes ProbePresent ProbePresent (Just ProbeUnknown) ProbeAbsent
  -- Self/own gating fails closed regardless of the parent row.
  t PidUnknown $ livenessFromProbes ProbeAbsent ProbePresent Nothing ProbeAbsent
  t PidUnknown $ livenessFromProbes ProbeUnknown ProbePresent (Just ProbePresent) ProbeAbsent
  t PidUnknown $ livenessFromProbes ProbePresent ProbeAbsent Nothing ProbeAbsent
  t PidUnknown $ livenessFromProbes ProbePresent ProbeUnknown (Just ProbePresent) ProbeAbsent

-- | A provably-dead pid: spawn a fresh process with no inherited
-- store descriptors, reap it, and confirm @\/proc@ has no entry
-- (a reused pid is retried). A raw fork can keep another parallel
-- test's database guard locked after that test closes its store.
reapedPid :: IO Int
reapedPid = go (0 :: Int)
  where
    go n
      | n > 50 = assertFailure "could not reap a dead pid"
      | otherwise = do
          reaped <- newIORef False
          bracket spawnReaper (releaseHolder reaped) $ \ph -> do
            pid <- spawnedPid ph "dead-pid"
            awaitHolderExit reaped ph "dead-pid"
            alive <- fileExist ("/proc/" ++ show (fromIntegral pid :: Int))
            if alive then go (n + 1) else pure (fromIntegral pid)
    spawnReaper :: IO ProcessHandle
    spawnReaper = do
      (_, _, _, ph) <- createProcess ((proc "/bin/true" []) { close_fds = True })
      pure ph

foreign import ccall unsafe "sys/file.h flock" test_c_flock :: CInt -> CInt -> IO CInt

-- | The test's own kernel-lock hold: an independent @flock@ import
-- (not the library's), so the held-lock phase proves the guard
-- interacts at the kernel level. @6 = LOCK_EX|LOCK_NB@ (Linux ABI).
testTryFlock :: Fd -> IO Bool
testTryFlock fd = (== 0) <$> test_c_flock (fromIntegral fd) 6

-- | Reject any bytes mentioning pointers, handles, callbacks, or
-- native crypto contexts.
cleanBytes :: String -> Bool
cleanBytes s = not (any (`isInfixOf` s) banned)
  where
    banned =
      [ "Ptr"
      , "callback"
      , "Callback"
      , "CALLBACK"
      , "EVP_"
      , "evp_"
      , "FunPtr"
      , "nullFunPtr"
      , "handle"
      , "Handle"
      , "HANDLE"
      , "struct"
      , "0x7f"
      , "0x55"
      , "0X"
      ]

-- | The only bare JSON number permitted is @\"format_version\":1@;
-- every other digit must sit inside a string.
numbersClean :: String -> Bool
numbersClean s = go False False (stripFmt s)
  where
    stripFmt [] = []
    stripFmt t@(c : cs)
      | "\"format_version\":1" `isPrefixOf` t = stripFmt (drop 18 t)
      | otherwise = c : stripFmt cs
    go _ _ [] = True
    go inStr esc (c : cs)
      | inStr && esc = go True False cs
      | inStr && c == '\\' = go True True cs
      | inStr && c == '"' = go False False cs
      | inStr = go True False cs
      | c == '"' = go True False cs
      | c >= '0' && c <= '9' = False
      | otherwise = go False False cs

-- | Schema parity: at most one token per slot (the SQLite
-- @UNIQUE(slot_key)@, mirrored by the memory backend).
testSlotUnique :: Opener -> IO ()
testSlotUnique o = do
  eStore <- openCurrent o
  s <- either (\e -> assertFailure ("open: " ++ show e)) pure eStore
  _ <- seedStore s
  let twin = TokenRecord
        { trId = TokenId 8
        , trSlot = SlotId 0
        , trGeneration = Generation 1
        , trLabel = "twin"
        , trAuth = tokenAuthNew
        }
  bad <- storeCommit s emptyDelta { sdPutTokens = [twin] }
  case bad of
    NotCommitted (StoreRevisionConflict _) -> pure ()
    other -> assertFailure ("expected slot refusal, got: " ++ show other)
  ok <- storeCommit s emptyDelta { sdPutTokens = [twin { trSlot = SlotId 1 }] }
  assertEqual "free slot commits" Committed ok
  storeClose s

-- | Token slot moves apply order-independently: shifting two tokens
-- up one slot commits identically whether the leader or the trailer
-- comes first (no transient slot refusal), a direct slot swap
-- commits, children ride along untouched, and the moved layout
-- survives close/reopen. The final projected uniqueness check still
-- refuses genuine conflicts (see 'testSlotUnique').
tokenSlotMovesAreOrderIndependent :: Opener -> IO ()
tokenSlotMovesAreOrderIndependent o = do
  eStore <- openCurrent o
  s <- either (assertFailure . show) pure eStore
  (seedA, seedB) <- seedTwoTokens s
  let tokA = tsToken seedA
      tokB = tsToken seedB
      fwdA = tokA { trSlot = SlotId 1 }
      fwdB = tokB { trSlot = SlotId 2 }
  rFwd <- storeCommit s emptyDelta { sdPutTokens = [fwdA, fwdB] }
  assertEqual "leader-first shift commits" Committed rFwd
  assertSlotProjection s [(trId tokA, SlotId 1), (trId tokB, SlotId 2)]
  assertSeedRecords s (seedA { tsToken = fwdA }) (seedB { tsToken = fwdB })
  let backA = tokA { trSlot = SlotId 0 }
      backB = tokB { trSlot = SlotId 1 }
  rBack <- storeCommit s emptyDelta { sdPutTokens = [backB, backA] }
  assertEqual "trailer-first shift commits" Committed rBack
  assertSlotProjection s [(trId tokA, SlotId 0), (trId tokB, SlotId 1)]
  assertSeedRecords s (seedA { tsToken = backA }) (seedB { tsToken = backB })
  let swapA = tokA { trSlot = SlotId 1 }
      swapB = tokB { trSlot = SlotId 0 }
  rSwap <- storeCommit s emptyDelta { sdPutTokens = [swapA, swapB] }
  assertEqual "slot swap commits" Committed rSwap
  assertSlotProjection s [(trId tokA, SlotId 1), (trId tokB, SlotId 0)]
  assertSeedRecords s (seedA { tsToken = swapA }) (seedB { tsToken = swapB })
  -- Boundary: a target slot near the top of the range commits in
  -- either put order as well (staging must not rely on space
  -- above the maximum).
  let homeA = tokA { trSlot = SlotId 0 }
      topB = tokB { trSlot = SlotId (maxBound - 1) }
  rTop <- storeCommit s emptyDelta { sdPutTokens = [homeA, topB] }
  assertEqual "near-limit shift commits" Committed rTop
  assertSlotProjection s [(trId tokA, SlotId 0), (trId tokB, SlotId (maxBound - 1))]
  assertSeedRecords s (seedA { tsToken = homeA }) (seedB { tsToken = topB })
  rTopBack <- storeCommit s emptyDelta { sdPutTokens = [swapB, swapA] }
  assertEqual "near-limit shift returns in reversed order" Committed rTopBack
  assertSlotProjection s [(trId tokA, SlotId 1), (trId tokB, SlotId 0)]
  assertSeedRecords s (seedA { tsToken = swapA }) (seedB { tsToken = swapB })
  storeClose s
  eStore2 <- openCurrent o
  s2 <- either (assertFailure . show) pure eStore2
  assertSlotProjection s2 [(trId tokA, SlotId 1), (trId tokB, SlotId 0)]
  assertSeedRecords s2 (seedA { tsToken = swapA }) (seedB { tsToken = swapB })
  storeClose s2

-- | Assert the store holds exactly the given token/slot pairs.
assertSlotProjection :: Store -> [(TokenId, SlotId)] -> IO ()
assertSlotProjection s want = do
  eLoaded <- storeLoadTokens s
  loaded <- either (assertFailure . show) pure eLoaded
  assertEqual "slot projection"
    (sort want) (sort [(trId t, trSlot t) | (t, _) <- loaded])

-- | One seeded token subtree: the token with its objects and jobs.
data TokenSeed = TokenSeed
  { tsToken :: !TokenRecord
  , tsObjects :: ![ObjectRecord]
  , tsJobs :: ![JobRecord]
  }

-- | Seed two tokens (slots 0 and 1), each with two objects and a
-- queued plus a ready job; return the exact seeded subtrees.
seedTwoTokens :: Store -> IO (TokenSeed, TokenSeed)
seedTwoTokens store = do
  let slotA = SlotId 0
      slotB = SlotId 1
      tmplA1 =
        [ (AttrClass, ValULong 3)
        , (AttrToken, ValBool True)
        , (AttrLabel, ValBytes "seed2-a1")
        , (AttrValue, ValBytes "seed2-bytes-a1")
        ]
      tmplA2 =
        [ (AttrClass, ValULong 4)
        , (AttrToken, ValBool True)
        , (AttrLabel, ValBytes "seed2-a2")
        ]
      tmplB1 =
        [ (AttrClass, ValULong 3)
        , (AttrToken, ValBool True)
        , (AttrLabel, ValBytes "seed2-b1")
        , (AttrValue, ValBytes "seed2-bytes-b1")
        ]
      tmplB2 =
        [ (AttrClass, ValULong 4)
        , (AttrToken, ValBool True)
        , (AttrLabel, ValBytes "seed2-b2")
        ]
  mSeated <- expectRight "seed2 seat+open" (publishDelta (addToken emptyModel slotA)
    (StateDelta [DeltaOpenSession (SessionId 1) slotA False]))
  st <- expectJust "seed2 session" (lookupSession mSeated (SessionId 1))
  (m1, _, oid1) <- expectCreated mSeated st tmplA1
  (m2, _, oid2) <- expectCreated m1 st tmplA2
  (m3, _, oid3) <- expectCreated m2 st tmplB1
  (m4, _, oid4) <- expectCreated m3 st tmplB2
  assertEqual "seed2 ids" [ObjectId 1, ObjectId 2, ObjectId 3, ObjectId 4] [oid1, oid2, oid3, oid4]
  ost1 <- expectJust "seed2 object 1" (lookupObject m4 oid1)
  ost2 <- expectJust "seed2 object 2" (lookupObject m4 oid2)
  ost3 <- expectJust "seed2 object 3" (lookupObject m4 oid3)
  ost4 <- expectJust "seed2 object 4" (lookupObject m4 oid4)
  let tokA = TokenRecord
        { trId = TokenId 7
        , trSlot = slotA
        , trGeneration = Generation 1
        , trLabel = "seed2-token-a"
        , trAuth = tokenAuthNew
        }
      tokB = TokenRecord
        { trId = TokenId 8
        , trSlot = slotB
        , trGeneration = Generation 1
        , trLabel = "seed2-token-b"
        , trAuth = tokenAuthNew
        }
      recA1 = objectToRecord (TokenId 7) ost1
      recA2 = objectToRecord (TokenId 7) ost2
      recB1 = objectToRecord (TokenId 8) ost3
      recB2 = objectToRecord (TokenId 8) ost4
      jobsA =
        [ demoJobPending 70 (TokenId 7) (Generation 1)
        , demoJobResult 71 (TokenId 7) (Generation 1)
        ]
      jobsB =
        [ demoJobPending 80 (TokenId 8) (Generation 1)
        , demoJobResult 81 (TokenId 8) (Generation 1)
        ]
  result <- storeCommit store emptyDelta
    { sdPutTokens = [tokA, tokB]
    , sdPutObjects =
        [ ObjectPut Nothing recA1
        , ObjectPut Nothing recA2
        , ObjectPut Nothing recB1
        , ObjectPut Nothing recB2
        ]
    , sdPutJobs = jobsA ++ jobsB
    }
  assertEqual "seed2 commit" Committed result
  pure (TokenSeed tokA [recA1, recA2] jobsA, TokenSeed tokB [recB1, recB2] jobsB)

-- | Assert both seeded subtrees load exactly: full token, object
-- and job records, nothing more and nothing less.
assertSeedRecords :: Store -> TokenSeed -> TokenSeed -> IO ()
assertSeedRecords s seedA seedB = do
  eLoaded <- storeLoadTokens s
  loaded <- either (assertFailure . show) pure eLoaded
  assertEqual "two tokens" 2 (length loaded)
  assertLoadedSeed loaded seedA
  assertLoadedSeed loaded seedB
  eJobs <- storeLoadJobs s
  jobs <- either (assertFailure . show) pure eJobs
  assertEqual "jobs exact" (tsJobs seedA ++ tsJobs seedB) jobs

-- | Assert one seeded subtree loads with its exact token and objects.
assertLoadedSeed :: [(TokenRecord, [ObjectRecord])] -> TokenSeed -> IO ()
assertLoadedSeed loaded seed =
  case lookup (trId (tsToken seed)) [(trId t, (t, os)) | (t, os) <- loaded] of
    Nothing -> assertFailure ("token missing: " ++ show (trId (tsToken seed)))
    Just (t, os) -> do
      assertEqual ("token exact: " ++ show (trId t)) (tsToken seed) t
      assertEqual ("objects exact: " ++ show (trId t)) (tsObjects seed) os

-- | Assert a token loads with its exact row and no objects.
assertChildless :: [(TokenRecord, [ObjectRecord])] -> TokenRecord -> IO ()
assertChildless loaded tok =
  case lookup (trId tok) [(trId t, (t, os)) | (t, os) <- loaded] of
    Nothing -> assertFailure ("token missing: " ++ show (trId tok))
    Just (t, os) -> do
      assertEqual "token exact" tok t
      assertEqual "token childless" [] os

-- | Child (non-token) stored bytes, in inspection order.
childJson :: [StoredDoc] -> [String]
childJson = map docJson . filter ((/= "tokens") . docTable)

-- | C2: an ordinary same-id token update (label plus auth metadata,
-- same slot and generation) preserves every owned object and job
-- byte-exact, leaves the unrelated token untouched, and survives
-- close/reopen.
tokenRefreshPreservesChildren :: Opener -> IO ()
tokenRefreshPreservesChildren o = do
  eStore <- openCurrent o
  s <- either (assertFailure . show) pure eStore
  (seedA, seedB) <- seedTwoTokens s
  docsBefore <- expectInspect s
  let tokA = tsToken seedA
      tokA' = tokA { trLabel = "seed2-token-a-relabeled"
                   , trAuth = (trAuth tokA) { taUserAttempts = 1 }
                   }
      seedA' = seedA { tsToken = tokA' }
  r <- storeCommit s emptyDelta { sdPutTokens = [tokA'] }
  assertEqual "refresh commits" Committed r
  assertSeedRecords s seedA' seedB
  docsAfter <- expectInspect s
  assertEqual "child bytes exact" (childJson docsBefore) (childJson docsAfter)
  storeClose s
  eStore2 <- openCurrent o
  s2 <- either (assertFailure . show) pure eStore2
  assertSeedRecords s2 seedA' seedB
  storeClose s2

-- | C2: a byte-identical token put preserves every child and every
-- stored byte, across close/reopen.
unchangedTokenPutPreservesChildren :: Opener -> IO ()
unchangedTokenPutPreservesChildren o = do
  eStore <- openCurrent o
  s <- either (assertFailure . show) pure eStore
  (seedA, seedB) <- seedTwoTokens s
  docsBefore <- expectInspect s
  r <- storeCommit s emptyDelta { sdPutTokens = [tsToken seedA] }
  assertEqual "identical put commits" Committed r
  assertSeedRecords s seedA seedB
  docsAfter <- expectInspect s
  assertEqual "stored bytes unchanged" (map docJson docsBefore) (map docJson docsAfter)
  storeClose s
  eStore2 <- openCurrent o
  s2 <- either (assertFailure . show) pure eStore2
  assertSeedRecords s2 seedA seedB
  storeClose s2

-- | C2: a token refresh commuting with one object update lands both
-- and preserves every other child byte-exact, across close/reopen.
mixedTokenAndObjectPutPreservesOtherChildren :: Opener -> IO ()
mixedTokenAndObjectPutPreservesOtherChildren o = do
  eStore <- openCurrent o
  s <- either (assertFailure . show) pure eStore
  (seedA, seedB) <- seedTwoTokens s
  docsBefore <- expectInspect s
  (firstA, restA) <- case tsObjects seedA of
    (x : xs) -> pure (x, xs)
    [] -> assertFailure "seed A has no objects"
  let tokA' = (tsToken seedA) { trLabel = "seed2-token-a-mixed" }
      updA = firstA { orAttrs = Map.insert AttrLabel (ValBytes "relabeled-a1") (orAttrs firstA) }
      seedA' = seedA { tsToken = tokA', tsObjects = updA : restA }
      keyA = show (unObjectId (orId updA))
      keyTokA = show (unTokenId (trId tokA'))
      otherJson = map docJson . filter (\d ->
        not (docTable d == "objects" && docKey d == keyA)
          && not (docTable d == "tokens" && docKey d == keyTokA))
  r <- storeCommit s emptyDelta
    { sdPutTokens = [tokA']
    , sdPutObjects = [ObjectPut Nothing updA]
    }
  assertEqual "mixed put commits" Committed r
  assertSeedRecords s seedA' seedB
  docsAfter <- expectInspect s
  assertEqual "other child bytes exact" (otherJson docsBefore) (otherJson docsAfter)
  storeClose s
  eStore2 <- openCurrent o
  s2 <- either (assertFailure . show) pure eStore2
  assertSeedRecords s2 seedA' seedB
  storeClose s2

-- | C2: dropping a token removes its owned children on both
-- backends, and recreating the token cannot resurrect them —
-- across close/reopen.
dropRecreateCannotResurrectChildren :: Opener -> IO ()
dropRecreateCannotResurrectChildren o = do
  eStore <- openCurrent o
  s <- either (assertFailure . show) pure eStore
  (seedA, seedB) <- seedTwoTokens s
  rDrop <- storeCommit s emptyDelta { sdDropTokens = [trId (tsToken seedA)] }
  assertEqual "drop commits" Committed rDrop
  eLoaded <- storeLoadTokens s
  loaded <- either (assertFailure . show) pure eLoaded
  assertEqual "only token B remains" [tsToken seedB] (map fst loaded)
  assertEqual "only B objects remain" (tsObjects seedB) (concatMap snd loaded)
  eJobs <- storeLoadJobs s
  jobs <- either (assertFailure . show) pure eJobs
  assertEqual "only B jobs remain" (tsJobs seedB) jobs
  rPut <- storeCommit s emptyDelta { sdPutTokens = [tsToken seedA] }
  assertEqual "recreate commits" Committed rPut
  eLoaded2 <- storeLoadTokens s
  loaded2 <- either (assertFailure . show) pure eLoaded2
  assertChildless loaded2 (tsToken seedA)
  assertLoadedSeed loaded2 seedB
  eJobs2 <- storeLoadJobs s
  jobs2 <- either (assertFailure . show) pure eJobs2
  assertEqual "no resurrected jobs" (tsJobs seedB) jobs2
  storeClose s
  eStore2 <- openCurrent o
  s2 <- either (assertFailure . show) pure eStore2
  eLoaded3 <- storeLoadTokens s2
  loaded3 <- either (assertFailure . show) pure eLoaded3
  assertChildless loaded3 (tsToken seedA)
  assertLoadedSeed loaded3 seedB
  eJobs3 <- storeLoadJobs s2
  jobs3 <- either (assertFailure . show) pure eJobs3
  assertEqual "no resurrected jobs after reopen" (tsJobs seedB) jobs3
  storeClose s2

-- | A pending-recipe job fixture: deterministic recipe plus owned
-- parameter bytes (replayable after restart, no live context).
demoJobPending :: Word64 -> TokenId -> Generation -> JobRecord
demoJobPending pid tok gen = JobRecord
  { jrPersistentId = pid
  , jrToken = tok
  , jrTokenGeneration = gen
  , jrFunction = "C_Digest"
  , jrState = JobQueued
  , jrBody = JobPending "sha256-owned-input/v1" (BS.pack (map fromIntegral [1 .. 32 :: Int]))
  }

-- | A prepared-result job fixture: verdict plus fully owned
-- result bytes (deliverable without any live context).
demoJobResult :: Word64 -> TokenId -> Generation -> JobRecord
demoJobResult pid tok gen = JobRecord
  { jrPersistentId = pid
  , jrToken = tok
  , jrTokenGeneration = gen
  , jrFunction = "C_Sign"
  , jrState = JobReady
  , jrBody = JobResult CKR_OK (BS.pack (map fromIntegral [101 .. 140 :: Int]))
  }

-- | Seed one token with two token objects; return the records.
seedStore :: Store -> IO (TokenRecord, [ObjectRecord])
seedStore store = do
  let slot = SlotId 0
      tmplA =
        [ (AttrClass, ValULong 3)
        , (AttrToken, ValBool True)
        , (AttrLabel, ValBytes "seed-a")
        , (AttrValue, ValBytes "seed-bytes-a")
        ]
      tmplB =
        [ (AttrClass, ValULong 4)
        , (AttrToken, ValBool True)
        , (AttrLabel, ValBytes "seed-b")
        ]
  mSeated <- expectRight "seed seat+open" (publishDelta (addToken emptyModel slot)
    (StateDelta [DeltaOpenSession (SessionId 1) slot False]))
  st <- expectJust "seed session" (lookupSession mSeated (SessionId 1))
  (m1, _, oid1) <- expectCreated mSeated st tmplA
  (m2, _, oid2) <- expectCreated m1 st tmplB
  ost1 <- expectJust "seed object 1" (lookupObject m2 oid1)
  ost2 <- expectJust "seed object 2" (lookupObject m2 oid2)
  let tok = TokenRecord
        { trId = TokenId 7
        , trSlot = slot
        , trGeneration = Generation 1
        , trLabel = "seed-token"
        , trAuth = tokenAuthNew
        }
  result <- storeCommit store emptyDelta
    { sdPutTokens = [tok]
    , sdPutObjects =
        [ ObjectPut Nothing (objectToRecord (TokenId 7) ost1)
        , ObjectPut Nothing (objectToRecord (TokenId 7) ost2)
        ]
    }
  assertEqual "seed commit" Committed result
  pure (tok, [objectToRecord (TokenId 7) ost1, objectToRecord (TokenId 7) ost2])

-- | Plan + publish one creation; return the model, handle, and id.
expectCreated
  :: Model -> SessionState -> [(AttributeType, AttributeValue)]
  -> IO (Model, ExternalHandle, ObjectId)
expectCreated m st tmpl = case planCreateObject m st tmpl of
  Immediate pc -> case publishDelta m (pcDelta pc) of
    Left fault -> assertFailure ("publish failed: " ++ show fault)
    Right m' -> case mapMaybe (decodeHandle . outBytes) (pcOutputs pc) of
      [h] -> pure (m', h, ObjectId (mNextObject' m))
      _ -> assertFailure "expected exactly one handle output"
  _ -> assertFailure "expected Immediate creation plan"

-- | Read the model's next-object counter (the id just allocated).
mNextObject' :: Model -> Int
mNextObject' = mNextObject

-- | The exact canonical key set of an object document. No handle,
-- no pointer, no out-of-band field may appear.
assertObjectDocKeys :: StoredDoc -> IO ()
assertObjectDocKeys d =
  assertEqual ("object doc keys: " ++ docKey d)
    [ "attrs"
    , "class"
    , "format_version"
    , "key_type"
    , "material"
    , "material_encoding"
    , "object_id"
    , "revision"
    , "token_id"
    ]
    (docTopKeys (docJson d))

-- | Reject any stored bytes mentioning handles/pointers.
noHandleBytes :: String -> Bool
noHandleBytes s =
  not (any (`isInfixOf` s) ["handle", "Handle", "HANDLE", "Ptr", "0x7f", "0x55"])

-- | A handle resolves when its binding names a live object.
resolves :: Model -> ExternalHandle -> Bool
resolves m h = case Map.lookup h (mHandles m) of
  Nothing -> False
  Just b -> case lookupObject m (hbObject b) of
    Nothing -> False
    Just ost -> hbGeneration b == osGeneration ost

-- ---------------------------------------------------------------------------
-- Durable token identity
-- ---------------------------------------------------------------------------

-- | The three-token fixture catalog (demo/ops/audit).
threeLabels :: [String]
threeLabels = ["haskoki-demo", "haskoki-ops", "haskoki-audit"]

threeSo :: [String]
threeSo = ["5678", "6789", "7890"]

threeUser :: [String]
threeUser = ["1234", "2345", "3456"]

-- | A @[tokens]@ document with the given parallel arrays (an
-- empty id list omits the @token_ids@ key: the legacy
-- positional reading).
catalogDoc :: [String] -> [String] -> [String] -> [String] -> String
catalogDoc labels soPins userPins ids = unlines $
  [ "schema_version = 1"
  , "[tokens]"
  , "labels = " ++ show labels
  , "so_pins = " ++ show soPins
  , "user_pins = " ++ show userPins
  ] ++ ["token_ids = " ++ show ids | not (null ids)]

-- | The legacy positional three-token document.
positionalDoc :: String
positionalDoc = catalogDoc threeLabels threeSo threeUser []

-- | The swapped pinned document: audit moves to slot 1 with
-- its own PINs, ops moves to slot 2 with its own PINs.
swappedDoc :: String
swappedDoc = catalogDoc
  ["haskoki-demo", "haskoki-audit", "haskoki-ops"]
  ["5678", "7890", "6789"]
  ["1234", "3456", "2345"]
  ["1", "3", "2"]

-- | Parse a catalog document or fail the case.
parseCatalog :: String -> IO Config
parseCatalog body = case parseConfig body of
  Left err -> assertFailure ("catalog must parse: " ++ show err)
  Right cfg -> pure cfg

-- | A catalog document must refuse as 'CfgInvalid'.
expectInvalid :: String -> String -> IO ()
expectInvalid ctx body = case parseConfig body of
  Left (CfgInvalid _) -> pure ()
  Left err -> assertFailure (ctx ++ ": wrong refusal: " ++ show err)
  Right _ -> assertFailure (ctx ++ ": bad catalog parsed")

-- | Desired tokens from a config, in slot order.
desiredOf :: Config -> [DesiredToken]
desiredOf cfg =
  [ DesiredToken slot tid label
  | (slot, (tid, label)) <- Map.toAscList (identityCatalog cfg)
  ]

-- | Which credential reaches which objects: per slot, the
-- configured user PIN, the durable identity seated there, and
-- its owned object ids. Call only on aligned layouts (after an
-- accepted reconciliation); refused layouts keep the previous
-- mapping.
credentialReach :: Config -> [(TokenRecord, [ObjectRecord])] -> [(String, TokenId, [ObjectId])]
credentialReach cfg loaded =
  [ (userPin, tid, sort [orId o | o <- objs])
  | (slot, (tid, _)) <- Map.toAscList (identityCatalog cfg)
  , Just (t, objs) <- [lookup tid byId]
  , trSlot t == slot
  , Just (_, _, userPin) <- [Map.lookup slot (effectiveCatalog cfg)]
  ]
  where
    byId = [(trId t, (t, os)) | (t, os) <- loaded]

-- | Exact stored bytes: table, key, and full document per row.
snapshotBytes :: Store -> IO [(String, String, String)]
snapshotBytes s = do
  docs <- expectInspect s
  pure [(docTable d, docKey d, docJson d) | d <- docs]

-- | Load every token with its objects or fail the case.
expectLoaded :: Store -> IO [(TokenRecord, [ObjectRecord])]
expectLoaded s = storeLoadTokens s >>= expectRight "load tokens"

-- | Token-object template with a distinct label.
idTmpl :: BS.ByteString -> [(AttributeType, AttributeValue)]
idTmpl label =
  [ (AttrClass, ValULong 3)
  , (AttrToken, ValBool True)
  , (AttrLabel, ValBytes label)
  , (AttrValue, ValBytes "id3-bytes")
  ]

-- | Seed three positional tokens (demo/ops/audit at slots 0/1/2
-- with ids 1/2/3), each owning one labeled object; return the
-- token records in slot order.
seedThreeTokens :: Store -> IO [TokenRecord]
seedThreeTokens store = do
  let s0 = SlotId 0
      s1 = SlotId 1
      s2 = SlotId 2
  mSeated <- expectRight "id3 seat+open" (publishDelta
    (addToken (addToken (addToken emptyModel s0) s1) s2)
    (StateDelta [ DeltaOpenSession (SessionId 1) s0 False
                , DeltaOpenSession (SessionId 2) s1 False
                , DeltaOpenSession (SessionId 3) s2 False
                ]))
  st0 <- expectJust "id3 session 0" (lookupSession mSeated (SessionId 1))
  st1 <- expectJust "id3 session 1" (lookupSession mSeated (SessionId 2))
  st2 <- expectJust "id3 session 2" (lookupSession mSeated (SessionId 3))
  (m1, _, oid1) <- expectCreated mSeated st0 (idTmpl "id3-demo")
  (m2, _, oid2) <- expectCreated m1 st1 (idTmpl "id3-ops")
  (m3, _, oid3) <- expectCreated m2 st2 (idTmpl "id3-audit")
  ost1 <- expectJust "id3 object 1" (lookupObject m3 oid1)
  ost2 <- expectJust "id3 object 2" (lookupObject m3 oid2)
  ost3 <- expectJust "id3 object 3" (lookupObject m3 oid3)
  let toks =
        [ TokenRecord (TokenId 1) s0 (Generation 1) "haskoki-demo" tokenAuthNew
        , TokenRecord (TokenId 2) s1 (Generation 1) "haskoki-ops" tokenAuthNew
        , TokenRecord (TokenId 3) s2 (Generation 1) "haskoki-audit" tokenAuthNew
        ]
  result <- storeCommit store emptyDelta
    { sdPutTokens = toks
    , sdPutObjects =
        [ ObjectPut Nothing (objectToRecord (TokenId 1) ost1)
        , ObjectPut Nothing (objectToRecord (TokenId 2) ost2)
        , ObjectPut Nothing (objectToRecord (TokenId 3) ost3)
        ]
    }
  assertEqual "id3 seed commit" Committed result
  pure toks

-- | Reconciliation seeds new identities and keeps durable ones:
-- a matching catalog plans nothing (steady state, zero
-- writes); an appended token seeds with generation zero and
-- fresh auth while every existing token, object, and
-- credential mapping survives untouched.
testIdentitySeedAppend :: Opener -> IO ()
testIdentitySeedAppend o = withStore o $ \s -> do
  toks <- seedThreeTokens s
  assertEqual "three seeded" 3 (length toks)
  loaded <- expectLoaded s
  cfg <- parseCatalog positionalDoc
  snapBefore <- snapshotBytes s
  case reconcileIdentities (desiredOf cfg) [t | (t, _) <- loaded] of
    Left refusal ->
      assertFailure ("matching catalog refused: " ++ renderIdentityRefusal refusal)
    Right plan -> assertEqual "steady state seeds nothing" [] (planSeeds plan)
  snapSteady <- snapshotBytes s
  assertEqual "steady reconcile writes nothing" snapBefore snapSteady
  let reachBefore = credentialReach cfg loaded
  assertEqual "three credentials served" 3 (length reachBefore)
  cfgAppend <- parseCatalog (catalogDoc
    (threeLabels ++ ["haskoki-vault"]) (threeSo ++ ["8901"]) (threeUser ++ ["4567"]) [])
  plan <- case reconcileIdentities (desiredOf cfgAppend) [t | (t, _) <- loaded] of
    Left refusal -> assertFailure ("append refused: " ++ renderIdentityRefusal refusal)
    Right p -> pure p
  case planSeeds plan of
    [seed] -> do
      assertEqual "seed identity" (TokenId 4) (trId seed)
      assertEqual "seed slot" (SlotId 3) (trSlot seed)
      assertEqual "seed label" "haskoki-vault" (trLabel seed)
      assertEqual "seed generation" (Generation 0) (trGeneration seed)
      assertEqual "seed auth" tokenAuthNew (trAuth seed)
    other -> assertFailure ("append must seed exactly one token: " ++ show other)
  rSeed <- storeCommit s emptyDelta { sdPutTokens = planSeeds plan }
  assertEqual "seed commit" Committed rSeed
  loadedAfter <- expectLoaded s
  assertEqual "old credentials keep their objects"
    (reachBefore ++ [( "4567", TokenId 4, [])])
    (credentialReach cfgAppend loadedAfter)

-- | A reordered catalog reopens refused: swapping two entries
-- changes which credential would reach which token's objects,
-- so the reconciler names the first drifted token and the
-- durable bytes survive exactly.
testIdentityReorderRefuses :: Opener -> IO ()
testIdentityReorderRefuses o = withStore o $ \s -> do
  _ <- seedThreeTokens s
  loaded <- expectLoaded s
  cfg <- parseCatalog positionalDoc
  let reachBefore = credentialReach cfg loaded
  bytesBefore <- snapshotBytes s
  cfgSwap <- parseCatalog swappedDoc
  case reconcileIdentities (desiredOf cfgSwap) [t | (t, _) <- loaded] of
    Left refusal@(RefuseSlotChanged tid _ _ _) -> do
      assertEqual "first drifted token" (TokenId 2) tid
      assertBool "refusal names the explicit move"
        ("planSlotMoves" `isInfixOf` renderIdentityRefusal refusal)
    Left refusal ->
      assertFailure ("reorder refused for the wrong reason: " ++ show refusal)
    Right plan -> assertFailure ("reorder accepted: " ++ show (planSeeds plan))
  bytesAfter <- snapshotBytes s
  assertEqual "refused reorder preserves bytes exactly" bytesBefore bytesAfter
  loadedAfter <- expectLoaded s
  assertEqual "refused reorder keeps the mapping"
    reachBefore (credentialReach cfg loadedAfter)

-- | Insertion in the middle refuses under both readings (the
-- legacy positional layout sees a label change; the pinned
-- layout sees a slot shift). Neither refusal writes a byte.
testIdentityInsertion :: Opener -> IO ()
testIdentityInsertion o = withStore o $ \s -> do
  _ <- seedThreeTokens s
  loaded <- expectLoaded s
  let stored = [t | (t, _) <- loaded]
  bytesBefore <- snapshotBytes s
  cfgLegacyMid <- parseCatalog (catalogDoc
    ["haskoki-demo", "haskoki-new", "haskoki-ops", "haskoki-audit"]
    ["5678", "1111", "6789", "7890"]
    ["1234", "2222", "2345", "3456"] [])
  case reconcileIdentities (desiredOf cfgLegacyMid) stored of
    Left (RefuseLabelChanged tid _ _ _) ->
      assertEqual "legacy insert hits id 2" (TokenId 2) tid
    other -> assertFailure
      ("legacy middle insert must refuse as a label change: " ++ show other)
  cfgPinnedMid <- parseCatalog (catalogDoc
    ["haskoki-demo", "haskoki-new", "haskoki-ops", "haskoki-audit"]
    ["5678", "1111", "6789", "7890"]
    ["1234", "2222", "2345", "3456"]
    ["1", "9", "2", "3"])
  case reconcileIdentities (desiredOf cfgPinnedMid) stored of
    Left (RefuseSlotChanged tid _ _ _) ->
      assertEqual "pinned insert hits id 2" (TokenId 2) tid
    other -> assertFailure
      ("pinned middle insert must refuse as a slot change: " ++ show other)
  bytesAfter <- snapshotBytes s
  assertEqual "refused insertions preserve bytes exactly" bytesBefore bytesAfter

-- | A removed entry reopens refused: the durable token stays
-- authoritative, its objects survive, and the bytes are exact.
testIdentityRemovalRefuses :: Opener -> IO ()
testIdentityRemovalRefuses o = withStore o $ \s -> do
  _ <- seedThreeTokens s
  loaded <- expectLoaded s
  bytesBefore <- snapshotBytes s
  cfgShrunk <- parseCatalog (catalogDoc
    ["haskoki-demo", "haskoki-ops"] ["5678", "6789"] ["1234", "2345"] [])
  case reconcileIdentities (desiredOf cfgShrunk) [t | (t, _) <- loaded] of
    Left refusal@(RefuseStoredUnconfigured tid _ _) -> do
      assertEqual "unconfigured token" (TokenId 3) tid
      assertBool "refusal rules out pruning"
        ("never pruned" `isInfixOf` renderIdentityRefusal refusal)
    Left refusal ->
      assertFailure ("removal refused for the wrong reason: " ++ show refusal)
    Right plan -> assertFailure ("removal accepted: " ++ show (planSeeds plan))
  bytesAfter <- snapshotBytes s
  assertEqual "refused removal preserves bytes exactly" bytesBefore bytesAfter
  reloaded <- expectLoaded s
  case [os | (t, os) <- reloaded, trId t == TokenId 3] of
    [objs] -> assertEqual "audit keeps its object" 1 (length objs)
    _ -> assertFailure "audit token missing after refused removal"

-- | A relabeled entry reopens refused: the durable label is
-- authoritative and labels never identify, so the catalog does
-- not rename the token silently.
testIdentityLabelChangeRefuses :: Opener -> IO ()
testIdentityLabelChangeRefuses o = withStore o $ \s -> do
  _ <- seedThreeTokens s
  loaded <- expectLoaded s
  bytesBefore <- snapshotBytes s
  cfgRenamed <- parseCatalog (catalogDoc
    ["haskoki-demo", "haskoki-ops-renamed", "haskoki-audit"]
    threeSo threeUser [])
  case reconcileIdentities (desiredOf cfgRenamed) [t | (t, _) <- loaded] of
    Left refusal@(RefuseLabelChanged tid _ durable desired) -> do
      assertEqual "renamed token" (TokenId 2) tid
      assertEqual "durable label" "haskoki-ops" durable
      assertEqual "desired label" "haskoki-ops-renamed" desired
      assertBool "refusal rules out silent rename"
        ("labels never" `isInfixOf` renderIdentityRefusal refusal)
    Left refusal ->
      assertFailure ("relabel refused for the wrong reason: " ++ show refusal)
    Right plan -> assertFailure ("relabel accepted: " ++ show (planSeeds plan))
  bytesAfter <- snapshotBytes s
  assertEqual "refused relabel preserves bytes exactly" bytesBefore bytesAfter
  reloaded <- expectLoaded s
  case [trLabel t | (t, _) <- reloaded, trId t == TokenId 2] of
    ["haskoki-ops"] -> pure ()
    other -> assertFailure ("durable label drifted: " ++ show other)

-- | The explicit slot move is the only path between serving
-- layouts: a swap commits atomically in one plan; occupied
-- targets, unknown tokens, the home anchor, clashing targets,
-- duplicated movers, and negative slots all refuse; settled
-- plans are the empty delta. Objects ride along under their
-- durable identity
-- throughout, and the reconciler accepts the matching pinned
-- catalog afterwards with the credentials following the
-- identities.
testIdentitySlotMoves :: Opener -> IO ()
testIdentitySlotMoves o = withStore o $ \s -> do
  _ <- seedThreeTokens s
  loaded0 <- expectLoaded s
  let stored0 = [t | (t, _) <- loaded0]
      owned m = sort [(orToken oo, orId oo, orRevision oo) | (_, os) <- m, oo <- os]
  case planSlotMoves [(TokenId 2, SlotId 2)] stored0 of
    Left refusal@(MoveSlotOccupied slot holder) -> do
      assertEqual "occupied slot" (SlotId 2) slot
      assertEqual "holder named" (TokenId 3) holder
      assertBool "refusal reroutes through a free slot"
        ("free slot" `isInfixOf` renderSlotMoveRefusal refusal)
    other -> assertFailure
      ("lone move onto an occupied slot must refuse: " ++ show other)
  case planSlotMoves [(TokenId 1, SlotId 1)] stored0 of
    Left (MoveHomeAnchored tid slot) -> do
      assertEqual "home token" (TokenId 1) tid
      assertEqual "home target" (SlotId 1) slot
    other -> assertFailure ("home move must refuse: " ++ show other)
  case planSlotMoves [(TokenId 2, SlotId 0)] stored0 of
    Left (MoveHomeAnchored _ _) -> pure ()
    other -> assertFailure ("move into slot 0 must refuse: " ++ show other)
  case planSlotMoves [(TokenId 9, SlotId 5)] stored0 of
    Left (MoveUnknownToken tid) -> assertEqual "unknown token" (TokenId 9) tid
    other -> assertFailure ("unknown move must refuse: " ++ show other)
  case planSlotMoves [(TokenId 2, SlotId 5), (TokenId 3, SlotId 5)] stored0 of
    Left (MoveTargetClash slot) -> assertEqual "clashing slot" (SlotId 5) slot
    other -> assertFailure ("clashing plan must refuse: " ++ show other)
  case planSlotMoves [(TokenId 2, SlotId 5), (TokenId 2, SlotId 6)] stored0 of
    Left (MoveDuplicateMover tid) -> assertEqual "duplicated mover" (TokenId 2) tid
    other -> assertFailure ("duplicated mover must refuse: " ++ show other)
  case planSlotMoves [(TokenId 2, SlotId (-1))] stored0 of
    Left (MoveBadSlot slot) -> assertEqual "bad slot" (SlotId (-1)) slot
    other -> assertFailure ("negative target must refuse: " ++ show other)
  case planSlotMoves [(TokenId 2, SlotId 1)] stored0 of
    Right delta -> assertEqual "settled plan is empty" emptyDelta delta
    Left refusal -> assertFailure ("settled plan must be empty: " ++ show refusal)
  swap <- case planSlotMoves [(TokenId 2, SlotId 2), (TokenId 3, SlotId 1)] stored0 of
    Left refusal -> assertFailure ("atomic swap must plan: " ++ show refusal)
    Right delta -> pure delta
  rSwap <- storeCommit s swap
  assertEqual "atomic swap commits" Committed rSwap
  assertSlotProjection s [(TokenId 1, SlotId 0), (TokenId 2, SlotId 2), (TokenId 3, SlotId 1)]
  loaded1 <- expectLoaded s
  assertEqual "objects ride along under their identities" (owned loaded0) (owned loaded1)
  cfgSwap <- parseCatalog swappedDoc
  case reconcileIdentities (desiredOf cfgSwap) [t | (t, _) <- loaded1] of
    Left refusal ->
      assertFailure ("post-swap catalog refused: " ++ renderIdentityRefusal refusal)
    Right planAfter ->
      assertEqual "post-swap layout is steady" [] (planSeeds planAfter)
  let objsOf tid = sort [orId oo | (_, os) <- loaded1, oo <- os, orToken oo == tid]
  assertEqual "credentials follow identities"
    [ ("1234", TokenId 1, objsOf (TokenId 1))
    , ("3456", TokenId 3, objsOf (TokenId 3))
    , ("2345", TokenId 2, objsOf (TokenId 2))
    ]
    (credentialReach cfgSwap loaded1)
  spare <- case planSlotMoves [(TokenId 2, SlotId 7)] [t | (t, _) <- loaded1] of
    Left refusal -> assertFailure ("spare move must plan: " ++ show refusal)
    Right delta -> pure delta
  rSpare <- storeCommit s spare
  assertEqual "spare move commits" Committed rSpare
  assertSlotProjection s [(TokenId 1, SlotId 0), (TokenId 2, SlotId 7), (TokenId 3, SlotId 1)]
  loadedSpare <- expectLoaded s
  back <- case planSlotMoves [(TokenId 2, SlotId 2)] [t | (t, _) <- loadedSpare] of
    Left refusal -> assertFailure ("return move must plan: " ++ show refusal)
    Right delta -> pure delta
  rBack <- storeCommit s back
  assertEqual "return move commits" Committed rBack
  assertSlotProjection s [(TokenId 1, SlotId 0), (TokenId 2, SlotId 2), (TokenId 3, SlotId 1)]

-- | A fresh store seeds every configured token: each seed
-- carries its pinned identity, slot, and label with generation
-- zero and fresh auth.
testIdentityFreshSeeds :: Opener -> IO ()
testIdentityFreshSeeds o = withStore o $ \s -> do
  loaded <- expectLoaded s
  assertEqual "fresh store loads empty" [] loaded
  cfg <- parseCatalog (catalogDoc threeLabels threeSo threeUser ["1", "2", "3"])
  case reconcileIdentities (desiredOf cfg) [] of
    Left refusal -> assertFailure ("fresh seeds refused: " ++ renderIdentityRefusal refusal)
    Right plan -> do
      let seeds = planSeeds plan
      assertEqual "three seeds" 3 (length seeds)
      assertEqual "seed layout"
        [(TokenId 1, SlotId 0), (TokenId 2, SlotId 1), (TokenId 3, SlotId 2)]
        [(trId t, trSlot t) | t <- seeds]
      assertEqual "seed labels" threeLabels [trLabel t | t <- seeds]
      assertEqual "seed generations" [Generation 0, Generation 0, Generation 0]
        [trGeneration t | t <- seeds]
      assertEqual "seed auths" [tokenAuthNew, tokenAuthNew, tokenAuthNew]
        [trAuth t | t <- seeds]

-- ---------------------------------------------------------------------------
-- Durable authentication state
-- ---------------------------------------------------------------------------

-- | A token put carrying a fully populated auth (logged in with
-- a principal, epoch, counters, and a lock) persists the
-- durable half only: loads and close/reopen boundaries show
-- the counters and locks with the transient half cleared, so
-- reopening never restores an authenticated application session.
testAuthDurableOnly :: Opener -> IO ()
testAuthDurableOnly o = withStore o $ \s -> do
  let full = tokenAuthNew
        { taLogin = Just AuthUser
        , taPrincipal = Just "alice"
        , taAuthEpoch = 7
        , taUserAttempts = 2
        , taSoAttempts = 1
        , taUserLocked = True
        }
      tok = TokenRecord
        { trId = TokenId 7
        , trSlot = SlotId 0
        , trGeneration = Generation 1
        , trLabel = "auth-token"
        , trAuth = full
        }
      want = tokenAuthNew
        { taUserAttempts = 2
        , taSoAttempts = 1
        , taUserLocked = True
        }
  r <- storeCommit s emptyDelta { sdPutTokens = [tok] }
  assertEqual "auth put commits" Committed r
  auth1 <- loadTokenAuth s (TokenId 7)
  assertEqual "load clears transient, keeps durable" want auth1
  storeClose s
  eStore2 <- openCurrent o
  s2 <- either (assertFailure . show) pure eStore2
  auth2 <- loadTokenAuth s2 (TokenId 7)
  assertEqual "reopen keeps durable, never the login" want auth2
  storeClose s2

-- | Read one token's loaded auth (fails unless exactly one row).
loadTokenAuth :: Store -> TokenId -> IO TokenAuth
loadTokenAuth s tid = do
  eLoaded <- storeLoadTokens s
  loaded <- either (assertFailure . show) pure eLoaded
  case [trAuth t | (t, _) <- loaded, trId t == tid] of
    [a] -> pure a
    _ -> assertFailure "auth token row missing"

-- | The stored token bytes carry retry counters and lock flags
-- only: no login key, no principal key or bytes, no epoch key.
-- The token-document top-level key set stays pinned, and the
-- 'Show' rendering leaks nothing either (it redacts the body).
testAuthBytesRedacted :: Opener -> IO ()
testAuthBytesRedacted o = withStore o $ \s -> do
  let full = tokenAuthNew
        { taLogin = Just AuthSO
        , taPrincipal = Just "mallory"
        , taAuthEpoch = 9
        , taUserAttempts = 1
        , taSoLocked = True
        }
      tok = TokenRecord
        { trId = TokenId 7
        , trSlot = SlotId 0
        , trGeneration = Generation 1
        , trLabel = "auth-token"
        , trAuth = full
        }
  r <- storeCommit s emptyDelta { sdPutTokens = [tok] }
  assertEqual "auth put commits" Committed r
  docs <- expectInspect s
  case [d | d <- docs, docTable d == "tokens"] of
    [tokDoc] -> do
      let body = docJson tokDoc
      assertEqual "token doc top keys pinned"
        ["auth", "format_version", "generation", "label", "slot", "token_id"]
        (docTopKeys body)
      assertBool "no login key" (not ("\"login\"" `isInfixOf` body))
      assertBool "no principal key" (not ("principal" `isInfixOf` body))
      assertBool "no epoch key" (not ("auth_epoch" `isInfixOf` body))
      assertBool "no principal bytes" (not ("mallory" `isInfixOf` body))
      assertBool "counters present"
        ("user_attempts" `isInfixOf` body && "so_locked" `isInfixOf` body)
      assertBool "show redacts the body"
        (not ("mallory" `isInfixOf` show tokDoc))
    other -> assertFailure ("expected one token doc, got: " ++ show (length other))

-- | Provisioned credentials round-trip byte-exact across
-- close/reopen, for both the set user PIN and the
-- uninitialized (null) user PIN. The credential document key
-- set pins exactly, and the ambiguous-commit reconciliation
-- covers the credential table (a put present reloads
-- present).
testCredentialsRoundTrip :: Opener -> IO ()
testCredentialsRoundTrip o = do
  eStore <- openCurrent o
  s <- either (\e -> assertFailure ("open: " ++ show e)) pure eStore
  (tok, _) <- seedStore s
  let tid = trId tok
      setCred = CredentialRecord tid "so-pin-1" (Just "user-pin-1")
  r <- storeCommit s emptyDelta { sdPutCredentials = [setCred] }
  assertEqual "credential put commits" Committed r
  docs <- expectInspect s
  case [d | d <- docs, docTable d == "credentials"] of
    [credDoc] -> assertEqual "credential doc top keys pinned"
      ["format_version", "so_pin", "token_id", "user_pin"]
      (docTopKeys (docJson credDoc))
    ds -> assertFailure ("expected one credential doc, got " ++ show (length ds))
  storeClose s
  eStore2 <- openCurrent o
  s2 <- either (\e -> assertFailure ("reopen: " ++ show e)) pure eStore2
  eCreds <- storeLoadCredentials s2
  creds <- either (\e -> assertFailure ("load credentials: " ++ show e)) pure eCreds
  assertEqual "credential round-trips" [setCred] creds
  assertEqual "credential put reconciles present" ReconciledPresent
    (reconcileCredentialsReload emptyDelta { sdPutCredentials = [setCred] } creds)
  let unsetCred = CredentialRecord tid "so-pin-2" Nothing
  r2 <- storeCommit s2 emptyDelta { sdPutCredentials = [unsetCred] }
  assertEqual "uninitialized user PIN commits" Committed r2
  storeClose s2
  eStore3 <- openCurrent o
  s3 <- either (\e -> assertFailure ("reopen2: " ++ show e)) pure eStore3
  eCreds3 <- storeLoadCredentials s3
  creds3 <- either (\e -> assertFailure ("load credentials2: " ++ show e)) pure eCreds3
  assertEqual "uninitialized credential round-trips" [unsetCred] creds3
  storeClose s3

-- | A credential put naming a token outside the projected set
-- refuses the whole delta (no orphan credentials), and the
-- store loads empty afterwards.
testCredentialMissingToken :: Opener -> IO ()
testCredentialMissingToken o = withStore o $ \s -> do
  let orphan = CredentialRecord (TokenId 99) "so-pin-1" (Just "user-pin-1")
  r <- storeCommit s emptyDelta { sdPutCredentials = [orphan] }
  case r of
    NotCommitted (StoreRevisionConflict _) -> pure ()
    other -> assertFailure ("expected revision conflict, got " ++ show other)
  eCreds <- storeLoadCredentials s
  creds <- either (\e -> assertFailure ("load credentials: " ++ show e)) pure eCreds
  assertEqual "no credential stored" [] creds

-- | Dropping a token removes its owned credential alongside
-- its objects and jobs (the ownership cascade).
testCredentialCascade :: Opener -> IO ()
testCredentialCascade o = withStore o $ \s -> do
  (tok, _) <- seedStore s
  let tid = trId tok
      cred = CredentialRecord tid "so-pin-1" (Just "user-pin-1")
  r <- storeCommit s emptyDelta { sdPutCredentials = [cred] }
  assertEqual "credential put commits" Committed r
  r2 <- storeCommit s emptyDelta { sdDropTokens = [tid] }
  assertEqual "token drop commits" Committed r2
  eCreds <- storeLoadCredentials s
  creds <- either (\e -> assertFailure ("load credentials: " ++ show e)) pure eCreds
  assertEqual "credential cascaded away" [] creds

-- | Reset drops the token's credential with its objects and
-- jobs: the replacement token serves catalog PINs until it is
-- provisioned again.
testResetDropsCredential :: Opener -> IO ()
testResetDropsCredential o = withStore o $ \s -> do
  (tok, _) <- seedStore s
  let tid = trId tok
      cred = CredentialRecord tid "so-pin-1" (Just "user-pin-1")
  r <- storeCommit s emptyDelta { sdPutCredentials = [cred] }
  assertEqual "credential put commits" Committed r
  let replacement = tok { trGeneration = Generation 2, trAuth = tokenAuthNew }
  rr <- storeResetToken s tid (trGeneration tok) replacement
  assertEqual "reset commits" Committed rr
  eCreds <- storeLoadCredentials s
  creds <- either (\e -> assertFailure ("load credentials: " ++ show e)) pure eCreds
  assertEqual "reset drops the credential" [] creds
  eLoaded <- storeLoadTokens s
  loaded <- either (\e -> assertFailure ("load tokens: " ++ show e)) pure eLoaded
  assertEqual "replacement token present" [replacement] (map fst loaded)

-- | A refused commit changes nothing: the inspected bytes and
-- the loaded records are identical before and after (the
-- refused-change leg of the provisioning lifecycle).
testRefusedPreservesBytes :: Opener -> IO ()
testRefusedPreservesBytes o = withStore o $ \s -> do
  (tok, _) <- seedStore s
  let tid = trId tok
      cred = CredentialRecord tid "so-pin-1" (Just "user-pin-1")
  r <- storeCommit s emptyDelta { sdPutCredentials = [cred] }
  assertEqual "credential put commits" Committed r
  docsBefore <- expectInspect s
  let badCred = CredentialRecord (TokenId 99) "so-x" (Just "user-x")
  r2 <- storeCommit s emptyDelta { sdPutCredentials = [badCred] }
  case r2 of
    NotCommitted (StoreRevisionConflict _) -> pure ()
    other -> assertFailure ("expected revision conflict, got " ++ show other)
  docsAfter <- expectInspect s
  assertEqual "refused commit preserves bytes"
    (map show docsBefore) (map show docsAfter)
  eCreds <- storeLoadCredentials s
  creds <- either (\e -> assertFailure ("load credentials: " ++ show e)) pure eCreds
  assertEqual "credential untouched" [cred] creds

-- | 'Show' on a credential redacts both PINs (kind and length
-- only); the home token renders normally.
testCredentialShowRedacted :: Opener -> IO ()
testCredentialShowRedacted _ = do
  let cred = CredentialRecord (TokenId 7) "so-pin-1" (Just "user-pin-1")
      redacted :: Int -> String
      redacted n = "{\"redacted\":true,\"kind\":\"pin\",\"length\":" ++ show n ++ "}"
  assertEqual "credential Show redacted"
    ("CredentialRecord {crToken = TokenId 7, crSoPin = " ++ redacted 8
      ++ ", crUserPin = Just " ++ redacted 10 ++ "}")
    (show cred)
  assertEqual "uninitialized Show"
    ("CredentialRecord {crToken = TokenId 7, crSoPin = " ++ redacted 8
      ++ ", crUserPin = Nothing}")
    (show (cred { crUserPin = Nothing }))

-- | Pinned @token_ids@ parse and project onto both catalogs:
-- identities pin per entry while the serving triples stay
-- positional.
casePinnedIdsParse :: IO ()
casePinnedIdsParse = do
  cfg <- parseCatalog (catalogDoc threeLabels threeSo threeUser ["1", "2", "3"])
  assertEqual "pinned ids" (Just [TokenId 1, TokenId 2, TokenId 3]) (cfgTokenIds cfg)
  assertEqual "identity projection"
    [ (SlotId 0, (TokenId 1, "haskoki-demo"))
    , (SlotId 1, (TokenId 2, "haskoki-ops"))
    , (SlotId 2, (TokenId 3, "haskoki-audit"))
    ]
    (Map.toAscList (identityCatalog cfg))
  assertEqual "serving triples stay positional"
    (zip3 threeLabels threeSo threeUser)
    [triple | (_, triple) <- Map.toAscList (effectiveCatalog cfg)]

-- | A duplicate pinned identity refuses the whole config.
caseDuplicateIdsRefused :: IO ()
caseDuplicateIdsRefused =
  expectInvalid "duplicate ids" (catalogDoc threeLabels threeSo threeUser ["1", "2", "2"])

-- | Pinned ids ragged against the labels refuse.
caseRaggedIdsRefused :: IO ()
caseRaggedIdsRefused =
  expectInvalid "ragged ids" (catalogDoc threeLabels threeSo threeUser ["1", "2"])

-- | Non-decimal, zero, and out-of-range ids refuse.
caseMalformedIdsRefused :: IO ()
caseMalformedIdsRefused = do
  expectInvalid "non-decimal id"
    (catalogDoc threeLabels threeSo threeUser ["1", "two", "3"])
  expectInvalid "zero id"
    (catalogDoc threeLabels threeSo threeUser ["1", "0", "3"])
  expectInvalid "oversized id"
    (catalogDoc threeLabels threeSo threeUser ["1", "4294967296", "3"])

-- | Slot 0 must carry @TokenId 1@: a pinned catalog that seats
-- anything else at slot 0 refuses.
caseNonHomeIdRefused :: IO ()
caseNonHomeIdRefused =
  expectInvalid "non-home slot zero" (catalogDoc threeLabels threeSo threeUser ["2", "1", "3"])

-- | Without @token_ids@ the catalog reads positionally.
caseAbsentIdsPositional :: IO ()
caseAbsentIdsPositional = do
  cfg <- parseCatalog positionalDoc
  assertEqual "no pinned ids" Nothing (cfgTokenIds cfg)
  assertEqual "positional projection" [TokenId 1, TokenId 2, TokenId 3]
    [tid | (_, (tid, _)) <- Map.toAscList (identityCatalog cfg)]

-- | Pinned ids without any labeled entry refuse.
caseIdsWithoutLabelsRefused :: IO ()
caseIdsWithoutLabelsRefused =
  expectInvalid "ids without labels" (unlines
    [ "schema_version = 1"
    , "[tokens]"
    , "token_ids = [\"1\"]"
    ])

-- | A hand-built config whose pinned list mismatches the
-- entries falls back to positional for every slot (total,
-- never a silent mix).
caseMismatchFallsBack :: IO ()
caseMismatchFallsBack = do
  cfg <- parseCatalog (catalogDoc threeLabels threeSo threeUser ["1", "2", "3"])
  let short = cfg { cfgTokenIds = Just [TokenId 1] }
      dropped = cfg { cfgTokenIds = Nothing }
      positional = [TokenId 1, TokenId 2, TokenId 3]
      project c = [tid | (_, (tid, _)) <- Map.toAscList (identityCatalog c)]
  assertEqual "short list falls back" positional (project short)
  assertEqual "dropped list falls back" positional (project dropped)

-- | The reconciler refuses duplicate desired identities even
-- for hand-built inputs (defense behind the parser check).
caseDuplicateDesiredRefuses :: IO ()
caseDuplicateDesiredRefuses =
  case reconcileIdentities
    [ DesiredToken (SlotId 1) (TokenId 2) "haskoki-ops"
    , DesiredToken (SlotId 2) (TokenId 2) "haskoki-dup"
    ] [] of
    Left (RefuseDuplicateDesired tid) -> assertEqual "duplicate id" (TokenId 2) tid
    other -> assertFailure ("duplicate desired identity must refuse: " ++ show other)

-- | The reconciler enforces the home anchor in both
-- directions: @TokenId 1@ sits at @SlotId 0@ only, and
-- @SlotId 0@ holds @TokenId 1@ only.
caseReconcilerHomeAnchor :: IO ()
caseReconcilerHomeAnchor = do
  case reconcileIdentities [DesiredToken (SlotId 2) (TokenId 1) "haskoki-demo"] [] of
    Left (RefuseHomeAnchor tid slot) -> do
      assertEqual "home token" (TokenId 1) tid
      assertEqual "home slot" (SlotId 2) slot
    other -> assertFailure ("home token away from slot 0 must refuse: " ++ show other)
  case reconcileIdentities [DesiredToken (SlotId 0) (TokenId 5) "haskoki-demo"] [] of
    Left (RefuseHomeAnchor tid slot) -> do
      assertEqual "intruder token" (TokenId 5) tid
      assertEqual "intruder slot" (SlotId 0) slot
    other -> assertFailure ("intruder at slot 0 must refuse: " ++ show other)

-- ---------------------------------------------------------------------------
-- Standard open reconciliation
-- ---------------------------------------------------------------------------

-- | Run a case against a scratch SQLite file, cleaned up
-- afterwards.
withOpenFile :: (FilePath -> IO a) -> IO a
withOpenFile use =
  bracket (makeTempDir "haskoki-open-reconcile") removeDirectoryRecursive $ \dir ->
    use (dir </> "store.db")

-- | Open the store file at the path through the production
-- acquisition (the same 'openStdStore' the instance open
-- threads): typed reconciliation errors, no assembly.
openReconciled :: FilePath -> Config -> IO (Either StdStoreError (Maybe StdStore))
openReconciled path cfg = do
  env <- newEnv (rulesFromConfig cfg)
  openStdStore env cfg { cfgStorage = StorageCfg StorageSQLite (Just path) 5000 True }

-- | Close an acquired store handle, if any.
closeAcquired :: Maybe StdStore -> IO ()
closeAcquired Nothing = pure ()
closeAcquired (Just ss) = storeClose (stdStore ss)

-- | Hand-built object fixture: one minimal token object
-- shape per token (attributes stay minimal; ownership is what
-- the open cases pin).
openObject :: TokenId -> ObjectId -> ObjectRecord
openObject tok oid = ObjectRecord
  { orId = oid
  , orToken = tok
  , orClass = 3
  , orKeyType = Nothing
  , orAttrs = Map.fromList [(AttrClass, ValULong 3)]
  , orMaterialEncoding = "none"
  , orMaterial = Nothing
  , orRevision = Revision 1
  }

-- | Seed a three-token file: tokens through the production
-- open itself (fresh-file seeding path), then one object per
-- token through a backend commit.
seedOpenSeeded :: FilePath -> IO ()
seedOpenSeeded path = do
  cfg <- parseCatalog positionalDoc
  eAcq <- openReconciled path cfg
  case eAcq of
    Left err -> assertFailure ("fresh open must seed: " ++ show err)
    Right mAcq -> closeAcquired mAcq
  eStore <- openSQLiteStore path
  s <- either (assertFailure . show) pure eStore
  result <- storeCommit s emptyDelta
    { sdPutObjects =
        [ ObjectPut Nothing (openObject (TokenId 1) (ObjectId 1))
        , ObjectPut Nothing (openObject (TokenId 2) (ObjectId 2))
        , ObjectPut Nothing (openObject (TokenId 3) (ObjectId 3))
        ]
    }
  storeClose s
  assertEqual "open seed objects commit" Committed result

-- | Commit one backend delta against a closed file.
commitFile :: FilePath -> StoreDelta -> IO CommitResult
commitFile path delta = do
  eStore <- openSQLiteStore path
  s <- either (assertFailure . show) pure eStore
  result <- storeCommit s delta
  storeClose s
  pure result

-- | Inspect the exact bytes of a closed file.
fileBytes :: FilePath -> IO [(String, String, String)]
fileBytes path = do
  eStore <- openSQLiteStore path
  s <- either (assertFailure . show) pure eStore
  docs <- expectInspect s
  storeClose s
  pure [(docTable d, docKey d, docJson d) | d <- docs]

-- | Load every token with its objects from a closed file.
fileLoaded :: FilePath -> IO [(TokenRecord, [ObjectRecord])]
fileLoaded path = do
  eStore <- openSQLiteStore path
  s <- either (assertFailure . show) pure eStore
  loaded <- expectLoaded s
  storeClose s
  pure loaded

-- | A fresh file seeds positionally through the production
-- open: three tokens with generation zero and fresh auth,
-- and the reconciled layout the instance would publish
-- through.
caseOpenSeedsFresh :: IO ()
caseOpenSeedsFresh = withOpenFile $ \path -> do
  cfg <- parseCatalog positionalDoc
  eAcq <- openReconciled path cfg
  acquired <- case eAcq of
    Left err -> assertFailure ("fresh open must seed: " ++ show err)
    Right mAcq -> pure mAcq
  case acquired of
    Nothing -> assertFailure "sqlite open must acquire a store"
    Just ss -> do
      assertEqual "reconciled layout is positional"
        [(SlotId 0, TokenId 1), (SlotId 1, TokenId 2), (SlotId 2, TokenId 3)]
        (Map.toAscList (stdTokenIds ss))
      closeAcquired acquired
  loaded <- fileLoaded path
  assertEqual "three tokens seeded" 3 (length loaded)
  assertEqual "seeded labels" threeLabels [trLabel t | (t, _) <- loaded]
  assertEqual "seed generations" [Generation 0, Generation 0, Generation 0]
    [trGeneration t | (t, _) <- loaded]
  assertEqual "seed auths" [tokenAuthNew, tokenAuthNew, tokenAuthNew]
    [trAuth t | (t, _) <- loaded]

-- | A reordered catalog refuses at the production open with
-- the actionable message; the file survives byte-exact and
-- the original catalog still opens afterwards.
caseOpenReorderRefuses :: IO ()
caseOpenReorderRefuses = withOpenFile $ \path -> do
  seedOpenSeeded path
  cfgSteady <- parseCatalog positionalDoc
  loadedSteady <- fileLoaded path
  let reachBefore = credentialReach cfgSteady loadedSteady
  bytesBefore <- fileBytes path
  cfgSwap <- parseCatalog swappedDoc
  eAcq <- openReconciled path cfgSwap
  case eAcq of
    Left (StdStoreIdentityRefusal msg) ->
      assertBool "refusal names the explicit move"
        ("planSlotMoves" `isInfixOf` msg)
    Left err -> assertFailure ("reorder refused for the wrong reason: " ++ show err)
    Right mAcq -> do
      closeAcquired mAcq
      assertFailure "reordered open accepted"
  bytesAfter <- fileBytes path
  assertEqual "refused open preserves bytes exactly" bytesBefore bytesAfter
  eAgain <- openReconciled path cfgSteady
  case eAgain of
    Left err -> assertFailure ("steady reopen refused after refusal: " ++ show err)
    Right mAcq -> closeAcquired mAcq
  loadedAgain <- fileLoaded path
  assertEqual "mapping intact after refused open"
    reachBefore (credentialReach cfgSteady loadedAgain)

-- | A removed entry refuses at the production open: the
-- durable token is never pruned, its objects survive, and
-- the file survives byte-exact.
caseOpenRemovalRefuses :: IO ()
caseOpenRemovalRefuses = withOpenFile $ \path -> do
  seedOpenSeeded path
  bytesBefore <- fileBytes path
  cfgShrunk <- parseCatalog (catalogDoc
    ["haskoki-demo", "haskoki-ops"] ["5678", "6789"] ["1234", "2345"] [])
  eAcq <- openReconciled path cfgShrunk
  case eAcq of
    Left (StdStoreIdentityRefusal msg) ->
      assertBool "refusal rules out pruning" ("never pruned" `isInfixOf` msg)
    Left err -> assertFailure ("removal refused for the wrong reason: " ++ show err)
    Right mAcq -> do
      closeAcquired mAcq
      assertFailure "removal open accepted"
  bytesAfter <- fileBytes path
  assertEqual "refused removal preserves bytes exactly" bytesBefore bytesAfter
  reloaded <- fileLoaded path
  case [os | (t, os) <- reloaded, trId t == TokenId 3] of
    [objs] -> assertEqual "audit keeps its object" 1 (length objs)
    _ -> assertFailure "audit token missing after refused removal"

-- | After an explicit swap committed underneath, the
-- production open accepts the matching pinned catalog and
-- hands the instance the moved layout, with the credentials
-- following the identities to their objects.
caseOpenAcceptsMoved :: IO ()
caseOpenAcceptsMoved = withOpenFile $ \path -> do
  seedOpenSeeded path
  loaded <- fileLoaded path
  swap <- case planSlotMoves [(TokenId 2, SlotId 2), (TokenId 3, SlotId 1)] [t | (t, _) <- loaded] of
    Left refusal -> assertFailure ("swap must plan: " ++ show refusal)
    Right delta -> pure delta
  rSwap <- commitFile path swap
  assertEqual "swap commits" Committed rSwap
  cfgSwap <- parseCatalog swappedDoc
  eAcq <- openReconciled path cfgSwap
  acquired <- case eAcq of
    Left err -> assertFailure ("moved open refused: " ++ show err)
    Right mAcq -> pure mAcq
  case acquired of
    Nothing -> assertFailure "sqlite open must acquire a store"
    Just ss -> do
      assertEqual "reconciled layout follows the move"
        [(SlotId 0, TokenId 1), (SlotId 1, TokenId 3), (SlotId 2, TokenId 2)]
        (Map.toAscList (stdTokenIds ss))
      closeAcquired acquired
  loadedAfter <- fileLoaded path
  let reach = credentialReach cfgSwap loadedAfter
      objsOf tid = sort [orId o | (_, os) <- loadedAfter, o <- os, orToken o == tid]
  assertEqual "credentials follow identities through the open"
    [ ("1234", TokenId 1, objsOf (TokenId 1))
    , ("3456", TokenId 3, objsOf (TokenId 3))
    , ("2345", TokenId 2, objsOf (TokenId 2))
    ]
    reach

-- | An interrupted move refuses at the production open under
-- both the old and the target catalog; completing the
-- remaining legs explicitly lets the target catalog open.
caseOpenInterruptedRefuses :: IO ()
caseOpenInterruptedRefuses = withOpenFile $ \path -> do
  seedOpenSeeded path
  loaded <- fileLoaded path
  move <- case planSlotMoves [(TokenId 2, SlotId 7)] [t | (t, _) <- loaded] of
    Left refusal -> assertFailure ("first leg must plan: " ++ show refusal)
    Right delta -> pure delta
  rMove <- commitFile path move
  assertEqual "first leg commits" Committed rMove
  bytesMid <- fileBytes path
  cfgOld <- parseCatalog positionalDoc
  eOld <- openReconciled path cfgOld
  case eOld of
    Left (StdStoreIdentityRefusal msg) ->
      assertBool "old open names the drifted slot" ("SlotId 7" `isInfixOf` msg)
    Left err -> assertFailure ("interrupted state misrefused the old catalog: " ++ show err)
    Right mAcq -> do
      closeAcquired mAcq
      assertFailure "interrupted state opened under the old catalog"
  cfgTarget <- parseCatalog swappedDoc
  eTarget <- openReconciled path cfgTarget
  case eTarget of
    Left (StdStoreIdentityRefusal _) -> pure ()
    Left err -> assertFailure ("interrupted state misrefused the target catalog: " ++ show err)
    Right mAcq -> do
      closeAcquired mAcq
      assertFailure "interrupted state opened under the target catalog"
  bytesRefused <- fileBytes path
  assertEqual "refused opens preserve the mid-state exactly" bytesMid bytesRefused
  loadedMid <- fileLoaded path
  rest <- case planSlotMoves [(TokenId 3, SlotId 1), (TokenId 2, SlotId 2)] [t | (t, _) <- loadedMid] of
    Left refusal -> assertFailure ("remaining legs must plan: " ++ show refusal)
    Right delta -> pure delta
  rRest <- commitFile path rest
  assertEqual "remaining legs commit" Committed rRest
  eDone <- openReconciled path cfgTarget
  case eDone of
    Left err -> assertFailure ("completed layout refused: " ++ show err)
    Right mAcq -> closeAcquired mAcq

-- | A positional downgrade over a moved store refuses at the
-- production open; the matching pinned catalog still opens.
caseOpenDowngradeRefuses :: IO ()
caseOpenDowngradeRefuses = withOpenFile $ \path -> do
  seedOpenSeeded path
  loaded <- fileLoaded path
  swap <- case planSlotMoves [(TokenId 2, SlotId 2), (TokenId 3, SlotId 1)] [t | (t, _) <- loaded] of
    Left refusal -> assertFailure ("swap must plan: " ++ show refusal)
    Right delta -> pure delta
  rSwap <- commitFile path swap
  assertEqual "swap commits" Committed rSwap
  bytesBefore <- fileBytes path
  cfgLegacy <- parseCatalog positionalDoc
  eLegacy <- openReconciled path cfgLegacy
  case eLegacy of
    Left (StdStoreIdentityRefusal _) -> pure ()
    Left err -> assertFailure ("downgrade refused for the wrong reason: " ++ show err)
    Right mAcq -> do
      closeAcquired mAcq
      assertFailure "positional downgrade opened over a moved store"
  bytesAfter <- fileBytes path
  assertEqual "refused downgrade preserves bytes exactly" bytesBefore bytesAfter
  cfgPinned <- parseCatalog swappedDoc
  ePinned <- openReconciled path cfgPinned
  case ePinned of
    Left err -> assertFailure ("pinned catalog refused after downgrade refusal: " ++ show err)
    Right mAcq -> closeAcquired mAcq

-- | A PIN edit reopens accepted: PINs are not identity, so
-- the changed credential reaches the same durable identity
-- and the same objects, and nothing else moves.
caseOpenPinEditAccepted :: IO ()
caseOpenPinEditAccepted = withOpenFile $ \path -> do
  seedOpenSeeded path
  loaded <- fileLoaded path
  cfg <- parseCatalog positionalDoc
  let reachBefore = credentialReach cfg loaded
  assertEqual "three credentials served" 3 (length reachBefore)
  cfgRotated <- parseCatalog (catalogDoc threeLabels threeSo ["1234", "9999", "3456"] [])
  bytesBefore <- fileBytes path
  eAcq <- openReconciled path cfgRotated
  case eAcq of
    Left err -> assertFailure ("PIN edit refused: " ++ show err)
    Right mAcq -> closeAcquired mAcq
  bytesAfter <- fileBytes path
  assertEqual "accepted PIN edit writes nothing" bytesBefore bytesAfter
  loadedAfter <- fileLoaded path
  let reachAfter = credentialReach cfgRotated loadedAfter
      pinsOf reach = [pin | (pin, _, _) <- reach]
      ownersOf reach = [(tid, objs) | (_, tid, objs) <- reach]
  assertEqual "PINs before" ["1234", "2345", "3456"] (pinsOf reachBefore)
  assertEqual "only the ops PIN changed" ["1234", "9999", "3456"] (pinsOf reachAfter)
  assertEqual "owners untouched by PIN edit" (ownersOf reachBefore) (ownersOf reachAfter)

-- | The durable publication path resolves serving slots
-- through the reconciled layout: a real creation delta for a
-- slot-1 object projects under the moved identity with the
-- swapped map and under the legacy identity with the
-- positional map. Reverting the projection to slot-plus-one
-- fails the first assertion.
caseProjectionUsesReconciledLayout :: IO ()
caseProjectionUsesReconciledLayout = do
  mSeated <- expectRight "proj seat+open" (publishDelta
    (addToken (addToken emptyModel (SlotId 0)) (SlotId 1))
    (StateDelta [DeltaOpenSession (SessionId 1) (SlotId 1) False]))
  st <- expectJust "proj session" (lookupSession mSeated (SessionId 1))
  pc <- case planCreateObject mSeated st (idTmpl "proj-moved") of
    Immediate p -> pure p
    _ -> assertFailure "expected Immediate creation plan"
  mAfter <- expectRight "proj publish" (publishDelta mSeated (pcDelta pc))
  let oid = ObjectId (mNextObject' mSeated)
  ost <- expectJust "proj object" (lookupObject mAfter oid)
  assertEqual "object created on slot 1" (SlotId 1) (osSlot ost)
  let swapped = Map.fromList [(SlotId 0, TokenId 1), (SlotId 1, TokenId 3)]
      positional = Map.fromList [(SlotId 0, TokenId 1), (SlotId 1, TokenId 2)]
      tokensOf proj = [orToken (opRecord p) | p <- sdPutObjects (projDelta proj)]
  assertEqual "reconciled layout attributes the moved identity"
    [TokenId 3] (tokensOf (buildObjectProjection swapped mSeated mAfter (pcDelta pc)))
  assertEqual "positional layout attributes the legacy identity"
    [TokenId 2] (tokensOf (buildObjectProjection positional mSeated mAfter (pcDelta pc)))
