{- | Store contract cases.
-}
{-# LANGUAGE OverloadedStrings #-}
module Store.Contract
  ( Opener (..)
  , contractSpec
  , expectInspect
  , expectLoaded
  , freshObject
  , idTmpl
  , memoryOpener
  , sqliteOpener
  ) where

import Control.Concurrent (forkFinally, killThread)
import Control.Concurrent.MVar (MVar, newEmptyMVar, putMVar, takeMVar, tryPutMVar, tryTakeMVar)
import Control.Exception (AsyncException (ThreadKilled), bracket, fromException, mask)
import Control.Monad (replicateM_, when)
import qualified Data.ByteString as BS
import Data.List (isInfixOf, sort)
import qualified Data.Map.Strict as Map
import Data.Word (Word64)
import System.Directory (removeDirectoryRecursive)
import System.FilePath ( (</>))
import System.Timeout (timeout)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertBool, assertEqual, assertFailure, testCase)
import Haskoki.Attribute (AttributeType (..), AttributeValue (..))
import Haskoki.Model
  ( HandleBinding (..)
  , Model (..)
  , ObjectState (..)
  , addToken
  , emptyModel
  , lookupObject
  , lookupSession
  )
import Haskoki.Attribute.Generated (mustClassId, mustKeyTypeId)
import Haskoki.Object (effectiveAttrs, planFindObjects, planGetAttributes)
import Haskoki.Operation.KeyManagement (KeyDeny (..), KeyPlan (..), aesKwMech, planWrapKey)
import Haskoki.Outcome
  ( DeltaOp (..)
  , PlanResult (..)
  , PreparedCommit (..)
  , Rejection (..)
  , StateDelta (..)
  )
import Haskoki.Request (OutputIntent (..))
import Haskoki.Runtime.Storage
  ( CommitResult (..)
  , CredentialRecord (..)
  , IdentityRefusal (..)
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
  , claimCensus
  , docTopKeys
  , emptyDelta
  , encodeHexWord64
  , jobIdCounterKey
  , markCensus
  , objectToRecord
  , planSlotMoves
  , reconcileCredentialsReload
  , reconcileIdentities
  , renderIdentityRefusal
  , renderSlotMoveRefusal
  , reserveRestoredIds
  )
import StoreFixtures (makeTempDir)
import Haskoki.Runtime.Async (newAsyncTable)
import Haskoki.Runtime.Catalog (desiredTokens, effectiveCatalog, identityCatalog)
import Haskoki.Runtime.Detached (markJobOpaque, openDetached)
import Haskoki.Runtime.Config
  ( Config (..)
  )
import Haskoki.Runtime.Storage.Memory (newMemoryWorld, openMemoryStore)
import Haskoki.Runtime.Storage.SQLite (openSQLiteStore)
import Haskoki.Session (ActiveLogin (..), TokenAuth (..), tokenAuthNew)
import Haskoki.Transition (publishDelta)
import Haskoki.Types
  ( ExternalHandle (..)
  , Generation (..)
  , JobId (..)
  , ObjectId (..)
  , ReturnCode (..)
  , Revision (..)
  , SessionId (..)
  , SlotId (..)
  , TokenId (..)
  )
import Store.Fixtures

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
  , testCase "legacy rows reload verbatim and report the key defaults" $
      withOpener mkOpener testLegacyReloadVerbatim
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
  , testCase "claim authority is handle-scoped" $
      withOpener mkOpener testClaimAuthorityHandleScoped
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
  , testCase "token refresh preserves the credential" $
      withOpener mkOpener testTokenRefreshPreservesCredential
  , testCase "reset keeps the credential" $
      withOpener mkOpener testResetKeepsCredential
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

-- | Legacy, partial and stamped rows reload verbatim and report the
-- key defaults: v0.4 maps lacking the six attributes, maps with
-- explicit protection but no history, partially stamped maps, fully
-- stamped maps, public halves and a non-key control all survive
-- close/reopen byte-identical on both backends, and the effective
-- view fills absent rows from the class defaults without unsealing
-- sealed material or overstating history. Read-only reopen writes
-- nothing. Hand-built records bypass the planner so the stored bytes
-- are exactly the legacy shapes (the encoder is untouched by this
-- lane, so these bytes are byte-identical to what the old base wrote
-- for the same shapes). The reloaded flag-less PQC and RSA rows are
-- then seated into a model exactly as stored and exercised through
-- read, find and wrap, which must all treat them as sealed.
testLegacyReloadVerbatim :: Opener -> IO ()
testLegacyReloadVerbatim o = do
  e1 <- openCurrent o
  s1 <- either (\e -> assertFailure ("open: " ++ show e)) pure e1
  let slot = SlotId 0
      tok = TokenRecord
        { trId = TokenId 7
        , trSlot = slot
        , trGeneration = Generation 1
        , trLabel = "legacy-token"
        , trAuth = tokenAuthNew
        }
      cSecret = mustClassId "CKO_SECRET_KEY"
      cPrivate = mustClassId "CKO_PRIVATE_KEY"
      cPublic = mustClassId "CKO_PUBLIC_KEY"
      cData = mustClassId "CKO_DATA"
      kAes = mustKeyTypeId "CKK_AES"
      kGeneric = mustKeyTypeId "CKK_GENERIC_SECRET"
      kRsa = mustKeyTypeId "CKK_RSA"
      kMldsa = mustKeyTypeId "CKK_ML_DSA"
      keyBase c k lab val =
        [ (AttrClass, ValULong c)
        , (AttrKeyType, ValULong k)
        , (AttrToken, ValBool True)
        , (AttrLabel, ValBytes lab)
        , (AttrValue, ValBytes val)
        , (AttrValueLen, ValULong (fromIntegral (BS.length val)))
        ]
      -- (tag, stored map, expected effective six as (present, value);
      -- Nothing means the effective view carries no such row)
      cases :: [(String, [(AttributeType, AttributeValue)], [(AttributeType, Maybe AttributeValue)])]
      cases =
        [ ("legacy-empty", keyBase cSecret kAes "legacy-empty" (BS.replicate 16 1),
            eff False False False False False maxBound)
        , ("legacy-sealed", keyBase cSecret kAes "legacy-sealed" (BS.replicate 16 2)
            ++ [(AttrSensitive, ValBool True), (AttrExtractable, ValBool False)],
            eff True False False False False maxBound)
        , ("legacy-open", keyBase cSecret kGeneric "legacy-open" (BS.replicate 32 3)
            ++ [(AttrSensitive, ValBool False), (AttrExtractable, ValBool True)],
            eff False True False False False maxBound)
        , ("partial-sens-only", keyBase cSecret kAes "partial-sens-only" (BS.replicate 16 4)
            ++ [(AttrSensitive, ValBool True)],
            eff True False False False False maxBound)
        , ("partial-ext-only", keyBase cSecret kAes "partial-ext-only" (BS.replicate 16 5)
            ++ [(AttrExtractable, ValBool True)],
            eff False True False False False maxBound)
        , ("partial-local", keyBase cSecret kAes "partial-local" (BS.replicate 16 6)
            ++ [(AttrSensitive, ValBool False), (AttrExtractable, ValBool False), (AttrLocal, ValBool False)],
            eff False False False False False maxBound)
        , ("partial-almost", keyBase cSecret kAes "partial-almost" (BS.replicate 16 7)
            ++ [(AttrSensitive, ValBool True), (AttrExtractable, ValBool False)
               , (AttrAlwaysSensitive, ValBool False), (AttrNeverExtractable, ValBool False)
               , (AttrLocal, ValBool False)],
            eff True False False False False maxBound)
        , ("stamped-generated", keyBase cSecret kAes "stamped-generated" (BS.replicate 16 8)
            ++ [(AttrSensitive, ValBool True), (AttrExtractable, ValBool False)
               , (AttrAlwaysSensitive, ValBool True), (AttrNeverExtractable, ValBool True)
               , (AttrLocal, ValBool True), (AttrKeyGenMechanism, ValULong 0x1080)],
            [ (AttrSensitive, Just (ValBool True)), (AttrExtractable, Just (ValBool False))
            , (AttrAlwaysSensitive, Just (ValBool True)), (AttrNeverExtractable, Just (ValBool True))
            , (AttrLocal, Just (ValBool True)), (AttrKeyGenMechanism, Just (ValULong 0x1080)) ])
        , ("stamped-import", keyBase cSecret kAes "stamped-import" (BS.replicate 16 9)
            ++ [(AttrSensitive, ValBool False), (AttrExtractable, ValBool False)
               , (AttrAlwaysSensitive, ValBool False), (AttrNeverExtractable, ValBool False)
               , (AttrLocal, ValBool False), (AttrKeyGenMechanism, ValULong maxBound)],
            eff False False False False False maxBound)
        , ("private-legacy", keyBase cPrivate kRsa "private-legacy" (BS.replicate 32 10),
            eff False False False False False maxBound)
        , ("mldsa-legacy",
            [ (AttrClass, ValULong cPrivate)
            , (AttrKeyType, ValULong kMldsa)
            , (AttrToken, ValBool True)
            , (AttrLabel, ValBytes "mldsa-legacy")
            , (AttrValue, ValBytes (BS.replicate 64 0x11))
            , (AttrSeed, ValBytes (BS.replicate 32 0x22))
            , (AttrParameterSet, ValULong 44)
            ],
            eff False False False False False maxBound)
        , ("rsa-legacy",
            [ (AttrClass, ValULong cPrivate)
            , (AttrKeyType, ValULong kRsa)
            , (AttrToken, ValBool True)
            , (AttrLabel, ValBytes "rsa-legacy")
            , (AttrModulus, ValBytes "legacy-modulus")
            , (AttrPublicExponent, ValBytes "legacy-pubexp")
            , (AttrPrivateExponent, ValBytes "legacy-privexp")
            , (AttrPrime1, ValBytes "legacy-prime1")
            , (AttrPrime2, ValBytes "legacy-prime2")
            , (AttrExponent1, ValBytes "legacy-exp1")
            , (AttrExponent2, ValBytes "legacy-exp2")
            , (AttrCoefficient, ValBytes "legacy-coeff")
            ],
            eff False False False False False maxBound)
        , ("public-legacy", keyBase cPublic kRsa "public-legacy" (BS.replicate 32 11),
            [ (AttrSensitive, Just (ValBool False)), (AttrExtractable, Just (ValBool True))
            , (AttrAlwaysSensitive, Nothing), (AttrNeverExtractable, Nothing)
            , (AttrLocal, Just (ValBool False)), (AttrKeyGenMechanism, Just (ValULong maxBound)) ])
        , ("public-stamped", keyBase cPublic kRsa "public-stamped" (BS.replicate 32 12)
            ++ [(AttrSensitive, ValBool False), (AttrExtractable, ValBool True)
               , (AttrLocal, ValBool False), (AttrKeyGenMechanism, ValULong maxBound)],
            [ (AttrSensitive, Just (ValBool False)), (AttrExtractable, Just (ValBool True))
            , (AttrAlwaysSensitive, Nothing), (AttrNeverExtractable, Nothing)
            , (AttrLocal, Just (ValBool False)), (AttrKeyGenMechanism, Just (ValULong maxBound)) ])
        , ("data-control",
            [ (AttrClass, ValULong cData)
            , (AttrToken, ValBool True)
            , (AttrLabel, ValBytes "data-control")
            , (AttrValue, ValBytes "plain-bytes")
            ],
            [ (AttrSensitive, Nothing), (AttrExtractable, Nothing)
            , (AttrAlwaysSensitive, Nothing), (AttrNeverExtractable, Nothing)
            , (AttrLocal, Nothing), (AttrKeyGenMechanism, Nothing) ])
        ]
      eff sens ext alw nev loc kgm =
        [ (AttrSensitive, Just (ValBool sens)), (AttrExtractable, Just (ValBool ext))
        , (AttrAlwaysSensitive, Just (ValBool alw)), (AttrNeverExtractable, Just (ValBool nev))
        , (AttrLocal, Just (ValBool loc)), (AttrKeyGenMechanism, Just (ValULong kgm)) ]
      mkOst n attrs = ObjectState
        { osId = ObjectId n
        , osRevision = Revision 1
        , osGeneration = Generation 1
        , osAttrs = Map.fromList attrs
        , osOwner = Nothing
        , osSlot = slot
        }
      osts = zipWith (\n (_, m, _) -> mkOst n m) [1 ..] cases
      recs = [objectToRecord (TokenId 7) ost | ost <- osts]
  result <- storeCommit s1 emptyDelta
    { sdPutTokens = [tok]
    , sdPutObjects = [ObjectPut Nothing r | r <- recs]
    }
  assertEqual "legacy commit" Committed result
  docsBefore <- expectInspect s1
  assertBool "seeded docs are non-empty" (not (null docsBefore))
  storeClose s1
  e2 <- openCurrent o
  s2 <- either (\e -> assertFailure ("reopen: " ++ show e)) pure e2
  eLoaded <- storeLoadTokens s2
  loaded <- either (\e -> assertFailure ("load: " ++ show e)) pure eLoaded
  case loaded of
    [(tok2, objs2)] -> do
      assertEqual "token label survives" "legacy-token" (trLabel tok2)
      assertEqual "all objects survive" (length cases) (length objs2)
      mapM_ (checkOne objs2) cases
      docsAfter <- expectInspect s2
      assertEqual "read-only reopen writes nothing"
        (map show docsBefore) (map show docsAfter)
      enforceReloadedAbsentProtections slot objs2
    _ -> assertFailure ("expected one token, got: " ++ show (length loaded))
  storeClose s2
  where
    checkOne objs2 (tag, origList, effExpect) = do
      let orig = Map.fromList origList
          label = case Map.lookup AttrLabel orig of
            Just (ValBytes b) -> b
            _ -> error ("case without label: " ++ tag)
          found = [rec | rec <- objs2, Map.lookup AttrLabel (orAttrs rec) == Just (ValBytes label)]
      case found of
        [rec] -> do
          assertEqual (tag ++ ": stored map untouched") orig (orAttrs rec)
          let eff = effectiveAttrs (orAttrs rec)
          mapM_ (\(t, want) -> assertEqual (tag ++ ": effective " ++ show t) want (Map.lookup t eff)) effExpect
        _ -> assertFailure (tag ++ ": expected one object, got " ++ show (length found))

-- | Enforcement over reloaded flag-less rows: the reloaded records
-- seat into a fresh model exactly as stored (a raw reseat, never
-- through creation, which would stamp them), and the PQC seed plus
-- the RSA private components must then refuse reads with no output
-- bytes, match no find, and refuse wrap as unextractable. Positive
-- controls (a public-component read, a label find) show the
-- session observes the objects, so the refusals are enforcement
-- rather than an empty model.
enforceReloadedAbsentProtections :: SlotId -> [ObjectRecord] -> IO ()
enforceReloadedAbsentProtections slot objs2 = do
  mNew <- expectRight "reseat+open" (publishDelta (addToken emptyModel slot)
    (StateDelta [DeltaOpenSession (SessionId 1) slot False]))
  let wrapOid = ObjectId (1 + maximum (0 : [unObjectId (orId o) | o <- objs2]))
      wrapAttrs = Map.fromList
        [ (AttrClass, ValULong (mustClassId "CKO_SECRET_KEY"))
        , (AttrKeyType, ValULong (mustKeyTypeId "CKK_AES"))
        , (AttrToken, ValBool True)
        , (AttrLabel, ValBytes "kw-wrap")
        , (AttrValue, ValBytes (BS.replicate 16 0xA5))
        , (AttrValueLen, ValULong 16)
        , (AttrSensitive, ValBool False)
        , (AttrExtractable, ValBool True)
        , (AttrWrap, ValBool True)
        ]
      oids = map orId objs2 ++ [wrapOid]
      creates =
        [ DeltaCreateObjectFull (orId o) (orAttrs o) Nothing slot | o <- objs2 ]
        ++ [DeltaCreateObjectFull wrapOid wrapAttrs Nothing slot]
      hNew = [ExternalHandle n | n <- [mNextHandle mNew ..]]
      binds = zipWith DeltaBindHandle hNew oids
  mBound <- expectRight "rebind" (publishDelta mNew (StateDelta (creates ++ binds)))
  st <- expectJust "session 1" (lookupSession mBound (SessionId 1))
  let rowOf lab =
        case [o | o <- objs2
              , Map.lookup AttrLabel (orAttrs o) == Just (ValBytes lab)] of
          [o] -> pure (orId o, orAttrs o)
          _ -> assertFailure ("missing reloaded row: " ++ show lab)
      handleOf oid =
        case [h | (h, b) <- Map.toList (mHandles mBound), hbObject b == oid] of
          [h] -> pure h
          hs -> assertFailure
            ("expected one handle, got " ++ show (length hs))
  (mldsaOid, mldsaAttrs) <- rowOf "mldsa-legacy"
  (rsaOid, rsaAttrs) <- rowOf "rsa-legacy"
  hMldsa <- handleOf mldsaOid
  hRsa <- handleOf rsaOid
  hWrap <- handleOf wrapOid
  let expectSealed tag h wants = case planGetAttributes mBound st h wants of
        Reject rej -> do
          assertEqual (tag ++ " code") CKR_ATTRIBUTE_SENSITIVE (rejCode rej)
          assertEqual (tag ++ " emits no bytes") [] (rejOutputs rej)
        _ -> assertFailure (tag ++ ": sealed read was served")
  expectSealed "mldsa seed" hMldsa [AttrSeed]
  expectSealed "mldsa value" hMldsa [AttrValue]
  expectSealed "rsa private exponent" hRsa [AttrPrivateExponent]
  seedVal <- expectJust "seed stored" (Map.lookup AttrSeed mldsaAttrs)
  expVal <- expectJust "private exponent stored"
    (Map.lookup AttrPrivateExponent rsaAttrs)
  valVal <- expectJust "mldsa value stored" (Map.lookup AttrValue mldsaAttrs)
  let expectNoMatch tag tmpl = case planFindObjects mBound st tmpl of
        Immediate pc -> assertEqual (tag ++ " matches nothing") [] (pcOutputs pc)
        _ -> assertFailure (tag ++ ": find refused")
  expectNoMatch "seed oracle" [(AttrSeed, seedVal)]
  expectNoMatch "value oracle" [(AttrValue, valVal)]
  expectNoMatch "private-exponent oracle" [(AttrPrivateExponent, expVal)]
  let expectUnextractable tag hT =
        case planWrapKey mBound st aesKwMech BS.empty hWrap hT IntentNull of
          KeyDenied deny ->
            assertEqual (tag ++ " code") CKR_KEY_UNEXTRACTABLE (kdCode deny)
          _ -> assertFailure (tag ++ ": wrap planned over a flag-less key")
  expectUnextractable "mldsa wrap" hMldsa
  expectUnextractable "rsa wrap" hRsa
  case planGetAttributes mBound st hRsa [AttrModulus] of
    Immediate pc -> assertEqual "modulus reads" 1 (length (pcOutputs pc))
    _ -> assertFailure "modulus read refused"
  case planFindObjects mBound st [(AttrLabel, ValBytes "mldsa-legacy")] of
    Immediate pc -> assertEqual "label finds the key" 1 (length (pcOutputs pc))
    _ -> assertFailure "label find refused"

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

-- | The detached-job claim authority is a live-handle property:
-- a record-update wrapper of a handle (the fault-injection idiom)
-- shares the handle's authority, while a close and reopen of the
-- same identity mints a fresh, empty one — the authority is never
-- world- or file-scoped and never durable. The authority is filled
-- (through a detach context over the wrapper) before the close, so
-- the reopened handle's emptiness is observed, not assumed.
testClaimAuthorityHandleScoped :: Opener -> IO ()
testClaimAuthorityHandleScoped o = withStore o $ \s -> do
  (tok, _) <- seedStore s
  let wrapped = s { storeCommit = storeCommit s, storeReload = storeReload s }
      tid = trId tok
  assertBool "record-update wrapper shares the authority"
    (storeClaims wrapped == storeClaims s)
  marks0 <- markCensus (storeClaims s) tid
  assertEqual "a fresh handle's authority holds no marks" 0 marks0
  dc <- openDetached wrapped tid
    >>= either (\e -> assertFailure ("open detached: " ++ show e)) pure
  table <- newAsyncTable 8
  markJobOpaque dc table (JobId 0) "fill before close"
  marks1 <- markCensus (storeClaims s) tid
  assertEqual "a mark through the wrapper lands in the handle's authority" 1 marks1
  storeClose s
  s2 <- openCurrent o >>= either (\e -> assertFailure ("reopen: " ++ show e)) pure
  assertBool "reopen mints a fresh authority"
    (storeClaims s2 /= storeClaims s)
  marks2 <- markCensus (storeClaims s2) tid
  assertEqual "the reopened authority holds no marks" 0 marks2
  census2 <- claimCensus (storeClaims s2) tid
  assertEqual "the reopened authority holds no attachments" (0, 0, 0) census2
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
  case reconcileIdentities (desiredTokens cfg) [t | (t, _) <- loaded] of
    Left refusal ->
      assertFailure ("matching catalog refused: " ++ renderIdentityRefusal refusal)
    Right plan -> assertEqual "steady state seeds nothing" [] (planSeeds plan)
  snapSteady <- snapshotBytes s
  assertEqual "steady reconcile writes nothing" snapBefore snapSteady
  let reachBefore = credentialReach cfg loaded
  assertEqual "three credentials served" 3 (length reachBefore)
  cfgAppend <- parseCatalog (catalogDoc
    (threeLabels ++ ["haskoki-vault"]) (threeSo ++ ["8901"]) (threeUser ++ ["4567"]) [])
  plan <- case reconcileIdentities (desiredTokens cfgAppend) [t | (t, _) <- loaded] of
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
  case reconcileIdentities (desiredTokens cfgSwap) [t | (t, _) <- loaded] of
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
  case reconcileIdentities (desiredTokens cfgLegacyMid) stored of
    Left (RefuseLabelChanged tid _ _ _) ->
      assertEqual "legacy insert hits id 2" (TokenId 2) tid
    other -> assertFailure
      ("legacy middle insert must refuse as a label change: " ++ show other)
  cfgPinnedMid <- parseCatalog (catalogDoc
    ["haskoki-demo", "haskoki-new", "haskoki-ops", "haskoki-audit"]
    ["5678", "1111", "6789", "7890"]
    ["1234", "2222", "2345", "3456"]
    ["1", "9", "2", "3"])
  case reconcileIdentities (desiredTokens cfgPinnedMid) stored of
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
  case reconcileIdentities (desiredTokens cfgShrunk) [t | (t, _) <- loaded] of
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
  case reconcileIdentities (desiredTokens cfgRenamed) [t | (t, _) <- loaded] of
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
  case reconcileIdentities (desiredTokens cfgSwap) [t | (t, _) <- loaded1] of
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
  case reconcileIdentities (desiredTokens cfg) [] of
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

-- | Reset drops the token's objects and jobs but keeps its
-- credential row: an existing durable credential always wins
-- over the catalog PINs.
testResetKeepsCredential :: Opener -> IO ()
testResetKeepsCredential o = withStore o $ \s -> do
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
  assertEqual "reset keeps the credential" [cred] creds
  eLoaded <- storeLoadTokens s
  loaded <- either (\e -> assertFailure ("load tokens: " ++ show e)) pure eLoaded
  assertEqual "replacement token present" [replacement] (map fst loaded)

-- | C2x: an ordinary same-id token refresh preserves the stored
-- credential, across close/reopen. The ownership rule covers
-- objects, jobs, AND credentials; the C2 cases pin objects and
-- jobs, the cascade case pins the drop half — this pins the
-- refresh half.
testTokenRefreshPreservesCredential :: Opener -> IO ()
testTokenRefreshPreservesCredential o =
  withStore o $ \s -> do
    (tok, _) <- seedStore s
    let tid = trId tok
        cred = CredentialRecord tid "so-pin-1" (Just "user-pin-1")
        tok' = tok { trLabel = "seed-token-relabeled" }
    r <- storeCommit s emptyDelta { sdPutCredentials = [cred] }
    assertEqual "credential put commits" Committed r
    r2 <- storeCommit s emptyDelta { sdPutTokens = [tok'] }
    assertEqual "refresh commits" Committed r2
    eCreds <- storeLoadCredentials s
    creds <- either (assertFailure . show) pure eCreds
    assertEqual "refresh preserves the credential" [cred] creds
    storeClose s
    withStore o $ \s2 -> do
      eCreds2 <- storeLoadCredentials s2
      creds2 <- either (assertFailure . show) pure eCreds2
      assertEqual "credential survives reopen after refresh" [cred] creds2

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
    ("CredentialRecord {crToken = " ++ show (TokenId 7) ++ ", crSoPin = "
      ++ redacted 8 ++ ", crUserPin = Just " ++ redacted 10 ++ "}")
    (show cred)
  assertEqual "uninitialized Show"
    ("CredentialRecord {crToken = " ++ show (TokenId 7) ++ ", crSoPin = "
      ++ redacted 8 ++ ", crUserPin = Nothing}")
    (show (cred { crUserPin = Nothing }))

-- | Token-object template with a distinct label.
idTmpl :: BS.ByteString -> [(AttributeType, AttributeValue)]
idTmpl label =
  [ (AttrClass, ValULong 3)
  , (AttrToken, ValBool True)
  , (AttrLabel, ValBytes label)
  , (AttrValue, ValBytes "id3-bytes")
  ]
