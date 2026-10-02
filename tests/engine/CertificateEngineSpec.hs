{- | Certificate durability engine tests (T-C02).

T-C03 adds the numeric-admission case (numeric CKA 0x86 modeled
end to end).

T-C05 adds the identity interop cases (CKA_ID linkage across the
component-imported RSA pair plus an X.509 certificate, and a real
sign/verify over the certificate VALUE bytes).

Gate-held store-first publication of public (token) objects: token
X.509 certificates and DATA survive engine restart with exact
attribute readback, session objects stay volatile, copy/set/destroy
effects are durable, read-only open/find/close cycles never alias
handles, injected commit failures reconcile gate-held without
reissue, racing publishers serialize to success/conflict with zero
lost update, and pre-commit interruption performs zero store IO.

Every case prints DURABILITY lines (case/seq-tagged, flushed per
line) for check-durability.py: startup reservation notes plus the
live ledger event stream and case markers.
-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
module CertificateEngineSpec (spec) where

import Control.Concurrent
  ( MVar
  , ThreadId
  , forkIO
  , killThread
  , newEmptyMVar
  , putMVar
  , takeMVar
  , threadDelay
  )
import Control.Exception (SomeException, bracket, catch, finally)
import Control.Monad (forM_, guard, unless, when)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BC8
import Data.ByteString (ByteString)
import Data.Char (digitToInt, isHexDigit)
import Data.IORef (IORef, modifyIORef', newIORef, readIORef, writeIORef)
import Data.List (nub)
import qualified Data.Map.Strict as Map
import Data.Maybe (listToMaybe, mapMaybe)
import Data.Word (Word64, Word8)
import Foreign.C.Types (CULong (..))
import Foreign.Marshal.Alloc (alloca, allocaBytes)
import Foreign.Marshal.Array (allocaArray, peekArray, pokeArray)
import Foreign.Ptr (Ptr, castPtr, nullPtr)
import Foreign.StablePtr
  ( StablePtr
  , castStablePtrToPtr
  , deRefStablePtr
  , newStablePtr
  )
import Foreign.Storable (peek, poke)
import GHC.Conc (BlockReason (..), ThreadStatus (..), threadStatus)
import System.Directory (doesFileExist, getTemporaryDirectory, removeFile)
import System.IO (BufferMode (..), hFlush, hSetBuffering, stdout)
import Text.Read (readMaybe)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertBool, assertEqual, assertFailure, testCase)

import EnvLock (withEnvLock)
import Haskoki.Attribute
  ( AttributeType (..)
  , AttributeValue (..)
  , attributeTypeByName
  )
import Haskoki.Attribute.Generated (attributeNameById)
import Haskoki.Engine.Backend
  ( CryptoBackend (..)
  , DigestAlg (..)
  , EngineResult (..)
  , KeyMaterial (..)
  , SigSpec (..)
  )
import Haskoki.Engine.OpenSSL4 (OpenSSL4 (..))
import Haskoki.FFI.Standard
  ( LedgerEvent
  , StdAcquisition (..)
  , StdInstance (..)
  , StdStore (..)
  , haskokiStdClose
  , haskokiStdCopyObject
  , haskokiStdCreateObject
  , haskokiStdDestroyObject
  , haskokiStdFind
  , haskokiStdFindFinal
  , haskokiStdFindInit
  , haskokiStdGetOneAttr
  , haskokiStdOpenSession
  , haskokiStdSetAttributeValue
  , openStdInstanceWithSlots
  , renderLedgerEvent
  , stdAcquisition
  , tokenIdForSlot
  )
import Haskoki.Model
  ( Model (..)
  , ObjectState (..)
  , SessionState
  , addToken
  , emptyModel
  , lookupSession
  )
import Haskoki.Object
  ( decodeHandle
  , planCreateObject
  , planFindObjects
  , planSetAttributes
  , resolveHandle
  )
import Haskoki.Operation.KeyManagement (ckoPrivateKey, ckoPublicKey, ckkRsa)
import Haskoki.Outcome
  ( DeltaOp (..)
  , ModelFault (..)
  , NativeOutput (..)
  , PlanResult (..)
  , PreparedCommit (..)
  , Rejection (..)
  , StateDelta (..)
  )
import Haskoki.Runtime.Catalog (effectiveCatalog)
import Haskoki.Runtime.Config
  ( Config (..)
  , ControlCfg (..)
  , Limits (..)
  , StorageCfg (..)
  , StorageKind (..)
  , defaultConfig
  )
import Haskoki.Runtime.Lifecycle (envGate, snapshotModel, withGate)
import Haskoki.Runtime.SlotEvents
  ( SlotDefinition (..)
  , SlotEvents
  , closeSlotEvents
  , newSlotEvents
  )
import Haskoki.Runtime.Storage
  ( CommitResult (..)
  , ObjectPut (..)
  , Store (..)
  , StoreDelta (..)
  , StoreError (..)
  , emptyDelta
  , objectToRecord
  )
import Haskoki.Runtime.Storage.SQLite (openSQLiteStore)
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

spec :: MVar () -> TestTree
spec envLock = testGroup "Certificates"
  [ testGroup "T-C02"
    [ testCase "caseCertTokenRestart" (caseCertTokenRestart envLock)
    , testCase "caseCertSessionVolatile" (caseCertSessionVolatile envLock)
    , testCase "caseCertDurableMutations" (caseCertDurableMutations envLock)
    , testCase "caseReadOnlyCycles" (caseReadOnlyCycles envLock)
    , testCase "caseDurabilityFaults" (caseDurabilityFaults envLock)
    , testCase "caseDurabilityConflict" (caseDurabilityConflict envLock)
    , testCase "caseDurabilityInterrupt" (caseDurabilityInterrupt envLock)
    , testCase "caseKeylessHighWater" (caseKeylessHighWater envLock)
    ]
  , testGroup "T-C03"
    [ testCase "caseTrustedNumericModeled" (caseTrustedNumericModeled envLock)
    ]
  , testGroup "T-C05"
    [ testCase "caseIdLinkage" (caseIdLinkage envLock)
    , testCase "caseRealSignature" (caseRealSignature envLock)
    ]
  , testGroup "T-C06"
    [ testCase "caseTrustNumericPinned" (caseTrustNumericPinned envLock)
    , testCase "caseValidationNumericPinned" (caseValidationNumericPinned envLock)
    ]
  ]

-- ---------------------------------------------------------------------------
-- Cases
-- ---------------------------------------------------------------------------

caseCertTokenRestart :: MVar () -> IO ()
caseCertTokenRestart envLock = do
  rep <- newReporter "caseCertTokenRestart"
  der <- fixtureDer
  subj <- derSubject der
  dbPath <- certDbPath "restart"
  probe <- newCertProbe
  let labelA = "tc02-restart-a"
      labelB = "tc02-restart-b"
  staleA <- newIORef (CULong 0)
  staleB <- newIORef (CULong 0)
  withCertInstance envLock dbPath probe $ \ctx inst -> do
    noteOpen rep inst 0
    h <- openRwSession ctx
    ha <- createObject ctx h (certTemplate True labelA der subj)
    hb <- createObject ctx h (certTemplate True labelB der subj)
    writeIORef staleA ha
    writeIORef staleB hb
    _ <- drainLedger rep probe
    pure ()
  withCertInstance envLock dbPath probe $ \ctx inst -> do
    noteOpen rep inst 1
    h <- openRwSession ctx
    foundA <- findByLabel ctx h labelA
    say rep ("phase=live kind=find label=" ++ BC8.unpack labelA ++ " hits=" ++ show (length foundA))
    assertEqual "exactly one fresh handle for A" 1 (length foundA)
    foundB <- findByLabel ctx h labelB
    say rep ("phase=live kind=find label=" ++ BC8.unpack labelB ++ " hits=" ++ show (length foundB))
    assertEqual "exactly one fresh handle for B" 1 (length foundB)
    freshA <- only "fresh A" foundA
    freshB <- only "fresh B" foundB
    assertBool "fresh handles differ" (freshA /= freshB)
    say rep ("phase=live kind=fresh-issue handle=" ++ showH freshA ++ " label=" ++ BC8.unpack labelA ++ " gen=1")
    say rep ("phase=live kind=fresh-issue handle=" ++ showH freshB ++ " label=" ++ BC8.unpack labelB ++ " gen=1")
    valA <- getAttrOk ctx h freshA ckaValue
    assertEqual "VALUE readback A" der valA
    subjA <- getAttrOk ctx h freshA ckaSubject
    assertEqual "SUBJECT readback A" subj subjA
    valB <- getAttrOk ctx h freshB ckaValue
    assertEqual "VALUE readback B" der valB
    subjB <- getAttrOk ctx h freshB ckaSubject
    assertEqual "SUBJECT readback B" subj subjB
    oldA <- readIORef staleA
    oldB <- readIORef staleB
    (rvA, _) <- getAttrBytes ctx h oldA ckaValue
    say rep ("phase=live kind=stale-fault handle=" ++ showH oldA ++ " rv=" ++ showH rvA)
    assertEqual "stale A faults" rvHandleInvalid rvA
    (rvB, _) <- getAttrBytes ctx h oldB ckaValue
    say rep ("phase=live kind=stale-fault handle=" ++ showH oldB ++ " rv=" ++ showH rvB)
    assertEqual "stale B faults" rvHandleInvalid rvB
    _ <- drainLedger rep probe
    pure ()
  noteCommitLog rep probe

caseCertSessionVolatile :: MVar () -> IO ()
caseCertSessionVolatile envLock = do
  rep <- newReporter "caseCertSessionVolatile"
  der <- fixtureDer
  subj <- derSubject der
  dbPath <- certDbPath "volatile"
  probe <- newCertProbe
  let sesCert = "tc02-vol-sescert"
      sesData = "tc02-vol-sesdata"
      tokData = "tc02-vol-tokdata"
      tokBytes = "tc02 durable token payload"
  withCertInstance envLock dbPath probe $ \ctx inst -> do
    noteOpen rep inst 0
    h <- openRwSession ctx
    _ <- createObject ctx h (certTemplate False sesCert der subj)
    _ <- createObject ctx h (dataTemplate False sesData "session payload")
    _ <- createObject ctx h (dataTemplate True tokData tokBytes)
    _ <- drainLedger rep probe
    pure ()
  withCertInstance envLock dbPath probe $ \ctx inst -> do
    noteOpen rep inst 1
    h <- openRwSession ctx
    goneCert <- findByLabel ctx h sesCert
    say rep ("phase=live kind=find label=" ++ BC8.unpack sesCert ++ " hits=" ++ show (length goneCert))
    assertEqual "session cert volatile" 0 (length goneCert)
    goneData <- findByLabel ctx h sesData
    say rep ("phase=live kind=find label=" ++ BC8.unpack sesData ++ " hits=" ++ show (length goneData))
    assertEqual "session data volatile" 0 (length goneData)
    foundTok <- findByLabel ctx h tokData
    say rep ("phase=live kind=find label=" ++ BC8.unpack tokData ++ " hits=" ++ show (length foundTok))
    tokH <- only "token data refind" foundTok
    say rep ("phase=live kind=fresh-issue handle=" ++ showH tokH ++ " label=" ++ BC8.unpack tokData ++ " gen=1")
    back <- getAttrOk ctx h tokH ckaValue
    assertEqual "token DATA value survives" tokBytes back
    _ <- drainLedger rep probe
    pure ()
  noteCommitLog rep probe

caseCertDurableMutations :: MVar () -> IO ()
caseCertDurableMutations envLock = do
  rep <- newReporter "caseCertDurableMutations"
  der <- fixtureDer
  subj <- derSubject der
  dbPath <- certDbPath "mutations"
  probe <- newCertProbe
  let labelC = "tc02-mut-c"
      labelC2 = "tc02-mut-c-v2"
      labelCopy = "tc02-mut-copy"
      labelSes = "tc02-mut-ses"
      labelX = "tc02-mut-doomed"
  highWater <- newIORef (0 :: Int)
  doomedOid <- newIORef (ObjectId 0)
  withCertInstance envLock dbPath probe $ \ctx inst -> do
    noteOpen rep inst 0
    h <- openRwSession ctx
    hc <- createObject ctx h (certTemplate True labelC der subj)
    _ <- copyObject ctx h hc (buildFrame [(ckaLabel, labelCopy)])
    setAttrs ctx h hc (buildFrame [(ckaLabel, labelC2)])
    back2 <- getAttrOk ctx h hc ckaLabel
    assertEqual "in-gen set readback" labelC2 back2
    hs <- createObject ctx h (certTemplate False labelSes der subj)
    setAttrs ctx h hs (buildFrame [(ckaToken, uBool True)])
    _ <- createObject ctx h (dataTemplate True labelX "doomed")
    copyFound <- findByLabel ctx h labelCopy
    say rep ("phase=live kind=find label=" ++ BC8.unpack labelCopy ++ " hits=" ++ show (length copyFound))
    assertEqual "copy visible in-gen" 1 (length copyFound)
    (topLabel, topRev) <- highestLabel inst
    writeIORef highWater topRev
    say rep ("phase=live kind=high-water rev=" ++ show topRev)
    assertEqual "highest is the doomed object" labelX topLabel
    topFound <- findByLabel ctx h topLabel
    say rep ("phase=live kind=find label=top hits=" ++ show (length topFound))
    hTop <- only "highest refind" topFound
    ostTop <- objectStateOfLabel inst topLabel
    writeIORef doomedOid (osId ostTop)
    destroyObject ctx h hTop
    say rep ("phase=live kind=destroy-highest rev=" ++ show topRev
      ++ " oid=" ++ show (unObjectId (osId ostTop)))
    _ <- drainLedger rep probe
    pure ()
  withCertInstance envLock dbPath probe $ \ctx inst -> do
    noteOpen rep inst 1
    -- The reserved revision, BEFORE session allocation (opening a
    -- session mints a revision and would mask a broken
    -- reservation): it must already sit past the deleted
    -- high-water. This is the value noteOpen prints as next_rev.
    mRes <- snapshotModel (siEnv inst)
    hw <- readIORef highWater
    let reserved = mNextRevision mRes
    say rep ("phase=startup kind=reserved-rev rev=" ++ show reserved)
    assertBool "reserved revision past the deleted high-water" (reserved > hw)
    h <- openRwSession ctx
    foundC <- findByLabel ctx h labelC2
    say rep ("phase=live kind=find label=" ++ BC8.unpack labelC2 ++ " hits=" ++ show (length foundC))
    hC <- only "set survivor refind" foundC
    say rep ("phase=live kind=fresh-issue handle=" ++ showH hC ++ " label=" ++ BC8.unpack labelC2 ++ " gen=1")
    keptC <- getAttrOk ctx h hC ckaLabel
    assertEqual "set value kept" labelC2 keptC
    foundE <- findByLabel ctx h labelCopy
    say rep ("phase=live kind=find label=" ++ BC8.unpack labelCopy ++ " hits=" ++ show (length foundE))
    hE <- only "copy refind" foundE
    say rep ("phase=live kind=fresh-issue handle=" ++ showH hE ++ " label=" ++ BC8.unpack labelCopy ++ " gen=1")
    foundS <- findByLabel ctx h labelSes
    say rep ("phase=live kind=find label=" ++ BC8.unpack labelSes ++ " hits=" ++ show (length foundS))
    hS <- only "promoted refind" foundS
    say rep ("phase=live kind=fresh-issue handle=" ++ showH hS ++ " label=" ++ BC8.unpack labelSes ++ " gen=1")
    foundX <- findByLabel ctx h labelX
    say rep ("phase=live kind=find label=" ++ BC8.unpack labelX ++ " hits=" ++ show (length foundX))
    assertEqual "destroyed stays destroyed" 0 (length foundX)
    -- Recreate the deleted highest ID, then issue the stale CAS
    -- against the RECREATED id with the pre-restart revision.
    hX <- createObject ctx h (dataTemplate True labelX "doomed")
    say rep ("phase=live kind=fresh-issue handle=" ++ showH hX ++ " label=" ++ BC8.unpack labelX ++ " gen=1")
    ostX <- objectStateOfLabel inst labelX
    wantOid <- readIORef doomedOid
    say rep ("phase=live kind=recreate rev=" ++ show (unRevision (osRevision ostX))
      ++ " oid=" ++ show (unObjectId (osId ostX)))
    assertEqual "recreated ID reuses the deleted ID" wantOid (osId ostX)
    store <- liveStore inst
    let staleRec = objectToRecord (tokenIdForSlot (SlotId 0)) ostX
    resCas <- storeCommit store (emptyDelta { sdPutObjects = [ObjectPut (Just (Revision hw)) staleRec] })
    case resCas of
      NotCommitted (StoreRevisionConflict _) ->
        say rep "phase=live kind=stale-cas result=conflict target=recreated"
      _ -> do
        say rep "phase=live kind=stale-cas result=other target=recreated"
        assertFailure "stale pre-restart CAS landed"
    _ <- drainLedger rep probe
    pure ()
  noteCommitLog rep probe

caseReadOnlyCycles :: MVar () -> IO ()
caseReadOnlyCycles envLock = do
  rep <- newReporter "caseReadOnlyCycles"
  der <- fixtureDer
  subj <- derSubject der
  dbPath <- certDbPath "readonly"
  probe <- newCertProbe
  let labelA = "tc02-ro-a"
      labelB = "tc02-ro-b"
  genHandles <- newIORef ([] :: [[CULong]])
  let runGen :: Int -> IO ()
      runGen gen = do
        tapeBefore <- length <$> readIORef (cpCommits probe)
        withCertInstance envLock dbPath probe $ \ctx inst -> do
          noteOpen rep inst gen
          h <- openRwSession ctx
          when (gen == 0) $ do
            _ <- createObject ctx h (certTemplate True labelA der subj)
            _ <- createObject ctx h (certTemplate True labelB der subj)
            pure ()
          foundA <- findByLabel ctx h labelA
          foundB <- findByLabel ctx h labelB
          say rep ("phase=live kind=gen-handles gen=" ++ show gen
            ++ " handles=" ++ showHList (foundA ++ foundB))
          assertEqual ("gen handles A " ++ show gen) 1 (length foundA)
          assertEqual ("gen handles B " ++ show gen) 1 (length foundB)
          modifyIORef' genHandles (++ [foundA ++ foundB])
          when (gen == 3) $ do
            sets <- readIORef genHandles
            forM_ (concat (take 3 sets)) $ \old -> do
              (rv, _) <- getAttrBytes ctx h old ckaValue
              say rep ("phase=live kind=stale-fault handle=" ++ showH old ++ " rv=" ++ showH rv)
              assertEqual "stale faults" rvHandleInvalid rv
          _ <- drainLedger rep probe
          pure ()
        tapeAfter <- newCommits probe tapeBefore
        let flushTags = [tag | (isF, tag) <- tapeAfter, isF]
        forM_ flushTags $ \tag ->
          say rep ("phase=live kind=flush gen=" ++ show gen ++ " result=" ++ tag)
        -- Conditional flush (T-C02f): gen 0's creates are covered by
        -- live upserts (no close commit); gens 1-3 finds mint fresh
        -- handles, so the handle high-water flush fires (this is
        -- what keeps the generations disjoint below).
        assertEqual ("flush committed gen " ++ show gen)
          (if gen == 0 then [] else ["committed"]) flushTags
  forM_ [0, 1, 2, 3] runGen
  sets <- readIORef genHandles
  assertDisjoint "readonly cycles" sets
  noteCommitLog rep probe

caseDurabilityFaults :: MVar () -> IO ()
caseDurabilityFaults envLock = do
  rep <- newReporter "caseDurabilityFaults"
  der <- fixtureDer
  subj <- derSubject der
  dbPath <- certDbPath "faults"
  probe <- newCertProbe
  let labelF = "tc02-flt-base"
      labelF2 = "tc02-flt-base-v2"
      labelB = "tc02-flt-blocked"
      labelC = "tc02-flt-landed"
      labelD = "tc02-flt-absent"
      labelE = "tc02-flt-unread"
      disarm = writeIORef (cpFault probe) (\delta backing -> backing delta)
  preRev <- newIORef (0 :: Int)
  preHandle <- newIORef (0 :: Int)
  preObjHW <- newIORef (0 :: Int)
  withCertInstance envLock dbPath probe $ \ctx inst -> do
    noteOpen rep inst 0
    h <- openRwSession ctx
    _ <- createObject ctx h (certTemplate True labelF der subj)
    writeIORef preRev =<< revisionOfLabel inst labelF
    -- (a) before-commit refusal: no backing call, model unchanged, zero publish.
    (_, objsBefore) <- modelRevisions inst
    backingBefore <- readIORef (cpBacking probe)
    writeIORef (cpFault probe)
      (\_delta _backing -> pure (NotCommitted (StoreIO "t-c02 injected pre-commit")))
    (rvA, _) <- rawCreate ctx h (certTemplate True labelB der subj)
    disarm
    backingAfter <- readIORef (cpBacking probe)
    (_, objsAfter) <- modelRevisions inst
    say rep ("phase=live kind=fault-a rv=" ++ showH rvA
      ++ " backing_delta=" ++ show (backingAfter - backingBefore)
      ++ " objs_before=" ++ show objsBefore ++ " objs_after=" ++ show objsAfter)
    assertEqual "before-commit rv" rvGeneral rvA
    assertEqual "before-commit zero backing" backingBefore backingAfter
    assertEqual "before-commit model unchanged" objsBefore objsAfter
    blockedFound <- findByLabel ctx h labelB
    say rep ("phase=live kind=find label=" ++ BC8.unpack labelB ++ " hits=" ++ show (length blockedFound))
    assertEqual "blocked absent" 0 (length blockedFound)
    _ <- drainLedger rep probe
    -- (b1) ambiguity that landed: publish proceeds, never reissued.
    writeIORef (cpFault probe)
      (\delta backing -> backing delta >> pure (CommitUnknown (StoreIO "t-c02 injected ambiguity")))
    backingB1 <- readIORef (cpBacking probe)
    _ <- createObject ctx h (certTemplate True labelC der subj)
    disarm
    backingB1' <- readIORef (cpBacking probe)
    say rep ("phase=live kind=fault-b1 backing_delta=" ++ show (backingB1' - backingB1))
    assertEqual "landed single backing" 1 (backingB1' - backingB1)
    foundC <- findByLabel ctx h labelC
    say rep ("phase=live kind=find label=" ++ BC8.unpack labelC ++ " hits=" ++ show (length foundC))
    assertEqual "landed present" 1 (length foundC)
    _ <- drainLedger rep probe
    -- (b2) ambiguity that never landed: fault, model kept, zero publish.
    writeIORef (cpFault probe)
      (\_delta _backing -> pure (CommitUnknown (StoreIO "t-c02 injected ambiguity")))
    backingB2 <- readIORef (cpBacking probe)
    (rvD, _) <- rawCreate ctx h (certTemplate True labelD der subj)
    disarm
    backingB2' <- readIORef (cpBacking probe)
    say rep ("phase=live kind=fault-b2 rv=" ++ showH rvD ++ " backing_delta=" ++ show (backingB2' - backingB2))
    assertEqual "absent rv" rvGeneral rvD
    assertEqual "absent zero backing" backingB2 backingB2'
    foundD <- findByLabel ctx h labelD
    say rep ("phase=live kind=find label=" ++ BC8.unpack labelD ++ " hits=" ++ show (length foundD))
    assertEqual "absent missing" 0 (length foundD)
    _ <- drainLedger rep probe
    -- (unreadable) same ledger shape as absent, failed closed.
    writeIORef (cpFault probe)
      (\_delta _backing -> pure (CommitUnknown (StoreIO "t-c02 injected ambiguity")))
    writeIORef (cpLoadFail probe) True
    (rvE, _) <- rawCreate ctx h (certTemplate True labelE der subj)
    writeIORef (cpLoadFail probe) False
    disarm
    say rep ("phase=live kind=fault-unread rv=" ++ showH rvE)
    assertEqual "unreadable rv" rvGeneral rvE
    foundE <- findByLabel ctx h labelE
    say rep ("phase=live kind=find label=" ++ BC8.unpack labelE ++ " hits=" ++ show (length foundE))
    assertEqual "unreadable missing" 0 (length foundE)
    _ <- drainLedger rep probe
    -- An extra session, so the close flush carries counters strictly
    -- past every restored object revision (meta-landing inference).
    _ <- openRwSession ctx
    mPre <- snapshotModel (siEnv inst)
    writeIORef preHandle (mNextHandle mPre)
    writeIORef preObjHW (mObjectRevHW mPre)
    say rep ("phase=live kind=preclose next_handle=" ++ show (mNextHandle mPre)
      ++ " next_rev=" ++ show (mNextRevision mPre))
    -- (c) the close flush itself goes ambiguous: best-effort close
    -- still succeeds, and the meta it wrote still lands.
    writeIORef (cpFault probe) $ \delta backing ->
      if isFlushDelta delta
        then backing delta >> pure (CommitUnknown (StoreIO "t-c02 injected flush ambiguity"))
        else backing delta
    pure ()
  tape0 <- readIORef (cpCommits probe)
  let flush0 = [(isF, tag) | (isF, tag) <- tape0, isF]
  forM_ flush0 $ \(_, tag) -> say rep ("phase=live kind=flush gen=0 result=" ++ tag)
  assertEqual "gen0 no close-flush commit" [] flush0
  eStore0 <- openSQLiteStore dbPath
  store0 <- case eStore0 of
    Left err -> assertFailure ("gen0 meta setup open: " ++ show err) >> fail "unreachable"
    Right store -> pure store
  eMeta0 <- storeLoadMeta store0
  meta0 <- case eMeta0 of
    Left err -> assertFailure ("gen0 meta setup meta: " ++ show err) >> fail "unreachable"
    Right meta -> pure meta
  storeClose store0
  assertEqual "gen0 persisted handle counter" (Just "3") (lookup "handle_counter" meta0)
  assertEqual "gen0 persisted revision counter" (Just "4") (lookup "revision_counter" meta0)
  writeIORef (cpFault probe) (\delta backing -> backing delta)
  withCertInstance envLock dbPath probe $ \ctx inst -> do
    noteOpen rep inst 1
    m1 <- snapshotModel (siEnv inst)
    wantH <- readIORef preHandle
    wantR <- readIORef preObjHW
    say rep ("phase=live kind=meta-landed next_handle=" ++ show (mNextHandle m1)
      ++ " next_rev=" ++ show (mNextRevision m1))
    assertBool "flushed handle high-water restored" (mNextHandle m1 >= wantH)
    assertBool "flushed revision high-water restored" (mNextRevision m1 >= wantR)
    h <- openRwSession ctx
    -- (d) post-restart stale CAS with a pre-restart expected revision.
    foundF <- findByLabel ctx h labelF
    say rep ("phase=live kind=find label=" ++ BC8.unpack labelF ++ " hits=" ++ show (length foundF))
    hF <- only "base refind" foundF
    setAttrs ctx h hF (buildFrame [(ckaLabel, labelF2)])
    ost <- objectStateOfLabel inst labelF2
    store <- liveStore inst
    staleRev <- readIORef preRev
    let staleRec = objectToRecord (tokenIdForSlot (SlotId 0)) ost
    resCas <- storeCommit store (emptyDelta { sdPutObjects = [ObjectPut (Just (Revision staleRev)) staleRec] })
    case resCas of
      NotCommitted (StoreRevisionConflict _) -> say rep "phase=live kind=stale-cas result=conflict"
      _ -> do
        say rep "phase=live kind=stale-cas result=other"
        assertFailure "stale pre-restart CAS landed"
    _ <- drainLedger rep probe
    pure ()
  -- (e) poisoned durable counters refuse the open (C02-01): an
  -- unparsable revision counter, then (revision restored) a
  -- nonpositive handle counter. Absent keys still fall back (every
  -- gen-0 open proves it); corrupt keys never open.
  refusalDb <- certDbPath "refusal"
  probeR <- newCertProbe
  withCertInstance envLock refusalDb probeR $ \ctxR _instR -> do
    hR <- openRwSession ctxR
    _ <- createObject ctxR hR (dataTemplate True "tc02-ref-a" "ref")
    pure ()
  eStoreR <- openSQLiteStore refusalDb
  storeR <- case eStoreR of
    Left err -> assertFailure ("poison setup open: " ++ show err) >> fail "unreachable"
    Right store -> pure store
  eMetaR <- storeLoadMeta storeR
  metaR <- case eMetaR of
    Left err -> assertFailure ("poison setup meta: " ++ show err) >> fail "unreachable"
    Right meta -> pure meta
  revGood <- case lookup "revision_counter" metaR of
    Just v -> pure v
    Nothing -> assertFailure "close flush wrote no revision counter" >> fail "unreachable"
  resP1 <- storeCommit storeR (emptyDelta { sdPutMeta = [("revision_counter", "bogus")] })
  assertEqual "poison write lands" Committed resP1
  storeClose storeR
  refused1 <- tryOpenRefused envLock refusalDb
  say rep ("phase=live kind=refusal key=revision_counter poison=unparsable result=" ++ if refused1 then "refused" else "opened")
  assertBool "unparsable revision counter refuses open" refused1
  eStoreR2 <- openSQLiteStore refusalDb
  storeR2 <- case eStoreR2 of
    Left err -> assertFailure ("re-poison open: " ++ show err) >> fail "unreachable"
    Right store -> pure store
  resP2 <- storeCommit storeR2
    (emptyDelta { sdPutMeta = [("revision_counter", revGood), ("handle_counter", "0")] })
  assertEqual "re-poison write lands" Committed resP2
  storeClose storeR2
  refused2 <- tryOpenRefused envLock refusalDb
  say rep ("phase=live kind=refusal key=handle_counter poison=nonpositive result=" ++ if refused2 then "refused" else "opened")
  assertBool "nonpositive handle counter refuses open" refused2
  -- (f) positive backstop: on a fresh keyless DB the close flush
  -- MUST fire (absent counters count as dirty), and flush
  -- ambiguity is tolerated (close succeeds, tag recorded).
  backstopDb <- certDbPath "backstop"
  probeB <- newCertProbe
  withCertInstance envLock backstopDb probeB $ \ctxB instB -> do
    noteOpen rep instB 0
    hB <- openRwSession ctxB
    foundB <- findByLabel ctxB hB "tc02-backstop-absent"
    say rep ("phase=live kind=find label=tc02-backstop-absent hits=" ++ show (length foundB))
    assertEqual "backstop empty find" 0 (length foundB)
    writeIORef (cpFault probeB) $ \delta backing ->
      if isFlushDelta delta
        then backing delta >> pure (CommitUnknown (StoreIO "t-c02 injected flush ambiguity"))
        else backing delta
    pure ()
  tapeB <- readIORef (cpCommits probeB)
  let flushB = [(isF, tag) | (isF, tag) <- tapeB, isF]
  forM_ flushB $ \(_, tag) -> say rep ("phase=live kind=flush gen=backstop result=" ++ tag)
  assertEqual "backstop flush fires ambiguous" [(True, "commit-unknown")] flushB
  tape1 <- newCommits probe (length tape0)
  forM_ tape1 $ \(isF, tag) ->
    when isF (say rep ("phase=live kind=flush gen=1 result=" ++ tag))
  noteCommitLog rep probe

caseDurabilityConflict :: MVar () -> IO ()
caseDurabilityConflict envLock = do
  rep <- newReporter "caseDurabilityConflict"
  der <- fixtureDer
  subj <- derSubject der
  dbPath <- certDbPath "conflict"
  probe <- newCertProbe
  let labelW = "tc02-race-w"
  withCertInstance envLock dbPath probe $ \ctx inst -> do
    noteOpen rep inst 0
    h <- openRwSession ctx
    m0 <- snapshotModel (siEnv inst)
    let oid0 = ObjectId (mNextObject m0)
        h0 = ExternalHandle (mNextHandle m0)
    (_, objsBefore) <- modelRevisions inst
    backingBefore <- readIORef (cpBacking probe)
    r1 <- newEmptyMVar
    r2 <- newEmptyMVar
    -- Both racers plan from the one frozen snapshot, then block
    -- acquiring the gate; releasing it races exactly one win.
    withGate (envGate (siEnv inst)) $ do
      let frame = certTemplate True labelW der subj
      t1 <- forkIO (rawCreate ctx h frame >>= putMVar r1)
      t2 <- forkIO (rawCreate ctx h frame >>= putMVar r2)
      waitBlockedOnGate [t1, t2]
      pure ()
    (rv1, out1) <- takeMVar r1
    (rv2, out2) <- takeMVar r2
    let oks = length (filter (== rvOK) [rv1, rv2])
        gens = length (filter (== rvGeneral) [rv1, rv2])
    assertEqual "exactly one winner" 1 oks
    assertEqual "exactly one loser" 1 gens
    let (winRv, winOut, loseRv, loseOut) =
          if rv1 == rvOK then (rv1, out1, rv2, out2) else (rv2, out2, rv1, out1)
    say rep ("phase=live kind=race role=winner rv=" ++ showH winRv ++ " handle=" ++ showH winOut)
    say rep ("phase=live kind=race role=loser rv=" ++ showH loseRv
      ++ " canary=" ++ if loseOut == CULong 0xA5A5A5A5 then "ok" else "touched")
    assertEqual "loser canary untouched" (CULong 0xA5A5A5A5) loseOut
    assertEqual "winner handle predicted" (CULong (fromIntegral (unExternalHandle h0))) winOut
    found <- findByLabel ctx h labelW
    say rep ("phase=live kind=find label=" ++ BC8.unpack labelW ++ " hits=" ++ show (length found))
    assertEqual "winner object present" 1 (length found)
    (_, objsAfter) <- modelRevisions inst
    assertEqual "zero lost update" (objsBefore + 1) objsAfter
    backingAfter <- readIORef (cpBacking probe)
    say rep ("phase=live kind=race backing_delta=" ++ show (backingAfter - backingBefore))
    assertEqual "winner committed once" 1 (backingAfter - backingBefore)
    -- Pin the duplicate fault value (pure, ledger-silent).
    m1 <- snapshotModel (siEnv inst)
    let pinDelta = StateDelta
          [ DeltaCreateObjectFull oid0 Map.empty Nothing (SlotId 0)
          , DeltaBindHandle h0 oid0
          ]
    case publishDelta m1 pinDelta of
      Left (FaultDuplicateObject got) -> do
        assertEqual "duplicate oid" oid0 got
        say rep "phase=live kind=pin-fault fault=FaultDuplicateObject"
      _ -> assertFailure "expected the duplicate fault"
    _ <- drainLedger rep probe
    pure ()
  noteCommitLog rep probe

caseDurabilityInterrupt :: MVar () -> IO ()
caseDurabilityInterrupt envLock = do
  rep <- newReporter "caseDurabilityInterrupt"
  der <- fixtureDer
  subj <- derSubject der
  dbPath <- certDbPath "interrupt"
  probe <- newCertProbe
  let labelV = "tc02-vic-a"
      labelW = "tc02-vic-b"
  withCertInstance envLock dbPath probe $ \ctx inst -> do
    noteOpen rep inst 0
    h <- openRwSession ctx
    _ <- createObject ctx h (certTemplate True labelV der subj)
    _ <- drainLedger rep probe
    pure ()
  withCertInstance envLock dbPath probe $ \ctx inst -> do
    noteOpen rep inst 1
    h <- openRwSession ctx
    foundV <- findByLabel ctx h labelV
    say rep ("phase=live kind=find label=" ++ BC8.unpack labelV ++ " hits=" ++ show (length foundV))
    assertEqual "sanity refind" 1 (length foundV)
    _ <- drainLedger rep probe
    -- Victim phase: async kill while blocked acquiring the gate.
    started <- newEmptyMVar
    killed <- newEmptyMVar
    tapeBefore <- length <$> readIORef (cpCommits probe)
    backingBefore <- readIORef (cpBacking probe)
    say rep "phase=live kind=victim-start"
    withGate (envGate (siEnv inst)) $ do
      victim <- forkIO
        ((putMVar started () >> rawCreate ctx h (certTemplate True labelW der subj) >> pure ())
          `finally` putMVar killed ())
      takeMVar started
      waitBlockedOnGate [victim]
      killThread victim
      takeMVar killed
      pure ()
    say rep "phase=live kind=victim-end"
    victimEvents <- drainLedger rep probe
    assertEqual "victim emitted nothing" [] victimEvents
    tapeAfter <- newCommits probe tapeBefore
    assertEqual "victim zero store IO" [] tapeAfter
    backingAfter <- readIORef (cpBacking probe)
    assertEqual "victim zero backing" backingBefore backingAfter
    pure ()
  noteCommitLog rep probe

-- | Restored revisions feed the object high-water (C02f-01): on a
-- populated keyless store the reservation must cover the highest
-- restored revision, or a handle-dirty close persists a
-- revision_counter BELOW a live revision and a recreated id
-- re-mints its pre-restart revision (satisfying a stale CAS).
-- Gen 0 builds the keyless DB (meta-stripping fault, objects at
-- rev 2 and 4); gen 1 deletes the rev-4 id and binds the rev-2
-- id (handle-dirty close); gen 2 recreates and stale-CASes.
caseKeylessHighWater :: MVar () -> IO ()
caseKeylessHighWater envLock = do
  rep <- newReporter "caseKeylessHighWater"
  der <- fixtureDer
  subj <- derSubject der
  dbPath <- certDbPath "keyless-hw"
  let labelA = "tc02-hw-a"
      labelB = "tc02-hw-b"
      labelB2 = "tc02-hw-b-v2"
      deletedRev = 4
  doomedOid <- newIORef (ObjectId 0)
  -- Gen 0: populate WITHOUT meta counters (old keyless store
  -- shape). Session rev 1, A rev 2, B rev 3, label set rev 4.
  -- The stripping fault also covers the close flush, so the DB
  -- keeps objects but no counters.
  probe0 <- newCertProbe
  writeIORef (cpFault probe0) (\delta backing -> backing (delta { sdPutMeta = [] }))
  withCertInstance envLock dbPath probe0 $ \ctx inst -> do
    noteOpen rep inst 0
    h <- openRwSession ctx
    _ <- createObject ctx h (certTemplate True labelA der subj)
    hB <- createObject ctx h (dataTemplate True labelB "hw-b")
    setAttrs ctx h hB (buildFrame [(ckaLabel, labelB2)])
    revA <- revisionOfLabel inst labelA
    revB <- revisionOfLabel inst labelB2
    say rep ("phase=live kind=seed rev-a=" ++ show revA ++ " rev-b=" ++ show revB)
    assertEqual "seeded A revision" 2 revA
    assertEqual "seeded B revision" 4 revB
    _ <- drainLedger rep probe0
    pure ()
  eStoreK <- openSQLiteStore dbPath
  storeK <- case eStoreK of
    Left err -> assertFailure ("keyless setup open: " ++ show err) >> fail "unreachable"
    Right store -> pure store
  eMetaK <- storeLoadMeta storeK
  metaK <- case eMetaK of
    Left err -> assertFailure ("keyless setup meta: " ++ show err) >> fail "unreachable"
    Right meta -> pure meta
  storeClose storeK
  assertEqual "keyless has no handle counter" Nothing (lookup "handle_counter" metaK)
  assertEqual "keyless has no revision counter" Nothing (lookup "revision_counter" metaK)
  -- Gen 1: keyless open (restored-fallback) -> session ->
  -- find+delete the rev-4 id -> find the previously unbound
  -- rev-2 id (fresh handle binds make the close handle-dirty).
  probe <- newCertProbe
  withCertInstance envLock dbPath probe $ \ctx inst -> do
    noteOpen rep inst 1
    preB <- revisionOfLabel inst labelB2
    assertEqual "doomed pre-restart revision" deletedRev preB
    ostB <- objectStateOfLabel inst labelB2
    writeIORef doomedOid (osId ostB)
    h <- openRwSession ctx
    foundB <- findByLabel ctx h labelB2
    say rep ("phase=live kind=find label=" ++ BC8.unpack labelB2 ++ " hits=" ++ show (length foundB))
    hDel <- only "doomed refind" foundB
    destroyObject ctx h hDel
    say rep ("phase=live kind=destroy-highest rev=" ++ show deletedRev
      ++ " oid=" ++ show (unObjectId (osId ostB)))
    foundA <- findByLabel ctx h labelA
    say rep ("phase=live kind=find label=" ++ BC8.unpack labelA ++ " hits=" ++ show (length foundA))
    assertEqual "survivor refind" 1 (length foundA)
    _ <- drainLedger rep probe
    pure ()
  eStore1 <- openSQLiteStore dbPath
  store1 <- case eStore1 of
    Left err -> assertFailure ("gen1 meta setup open: " ++ show err) >> fail "unreachable"
    Right store -> pure store
  eMeta1 <- storeLoadMeta store1
  meta1 <- case eMeta1 of
    Left err -> assertFailure ("gen1 meta setup meta: " ++ show err) >> fail "unreachable"
    Right meta -> pure meta
  storeClose store1
  let hCtr1 = lookup "handle_counter" meta1
      rCtr1 = lookup "revision_counter" meta1
  say rep ("phase=live kind=gen1-meta handle=" ++ show hCtr1 ++ " revision=" ++ show rCtr1)
  assertBool "handle-dirty close persisted a handle counter" (hCtr1 /= Nothing)
  assertEqual "close persisted the restored high-water" (Just "5") rCtr1
  -- Gen 2: the reservation must already exceed the deleted
  -- revision BEFORE the session burn; the recreated id mints
  -- fresh (rev 6, not the deleted 4); a stale CAS at rev 4
  -- refuses.
  withCertInstance envLock dbPath probe $ \ctx inst -> do
    noteOpen rep inst 2
    mRes <- snapshotModel (siEnv inst)
    let reserved = mNextRevision mRes
    say rep ("phase=startup kind=reserved-rev rev=" ++ show reserved
      ++ " obj-hw=" ++ show (mObjectRevHW mRes))
    assertBool "reserved revision past the deleted revision" (reserved > deletedRev)
    assertEqual "reserved object high-water" 5 (mObjectRevHW mRes)
    h <- openRwSession ctx
    foundA <- findByLabel ctx h labelA
    say rep ("phase=live kind=find label=" ++ BC8.unpack labelA ++ " hits=" ++ show (length foundA))
    assertEqual "survivor kept" 1 (length foundA)
    foundB <- findByLabel ctx h labelB2
    say rep ("phase=live kind=find label=" ++ BC8.unpack labelB2 ++ " hits=" ++ show (length foundB))
    assertEqual "destroyed stays destroyed" 0 (length foundB)
    hB2 <- createObject ctx h (dataTemplate True labelB2 "hw-b")
    say rep ("phase=live kind=fresh-issue handle=" ++ showH hB2 ++ " label=" ++ BC8.unpack labelB2 ++ " gen=2")
    ostX <- objectStateOfLabel inst labelB2
    wantOid <- readIORef doomedOid
    say rep ("phase=live kind=recreate rev=" ++ show (unRevision (osRevision ostX))
      ++ " oid=" ++ show (unObjectId (osId ostX)))
    assertEqual "recreated ID reuses the deleted ID" wantOid (osId ostX)
    assertEqual "recreated revision is fresh" 6 (unRevision (osRevision ostX))
    store <- liveStore inst
    let staleRec = objectToRecord (tokenIdForSlot (SlotId 0)) ostX
    resCas <- storeCommit store (emptyDelta { sdPutObjects = [ObjectPut (Just (Revision deletedRev)) staleRec] })
    case resCas of
      NotCommitted (StoreRevisionConflict _) ->
        say rep "phase=live kind=stale-cas result=conflict target=recreated"
      _ -> do
        say rep "phase=live kind=stale-cas result=other target=recreated"
        assertFailure "stale pre-restart CAS landed"
    _ <- drainLedger rep probe
    pure ()
  noteCommitLog rep probe

-- ---------------------------------------------------------------------------
-- T-C03 cases
-- ---------------------------------------------------------------------------

-- | Numeric CKA 0x86 (TRUSTED) is modeled: a raw FFI frame carrying
-- it as false is admitted on a public session and reads back. Before
-- the T-C03 inventory the same assertion fails with
-- CKR_ATTRIBUTE_TYPE_INVALID at frame decode.
caseTrustedNumericModeled :: MVar () -> IO ()
caseTrustedNumericModeled envLock = do
  der <- fixtureDer
  subj <- derSubject der
  dbPath <- certDbPath "trusted-numeric"
  probe <- newCertProbe
  withCertInstance envLock dbPath probe $ \ctx _inst -> do
    h <- openRwSession ctx
    let frame = buildFrame
          [ (ckaClass, le64 ckoCert)
          , (ckaCertType, le64 ckcX509)
          , (ckaToken, uBool False)
          , (ckaLabel, "tc03-trusted-numeric")
          , (ckaValue, der)
          , (ckaSubject, subj)
          , (ckaTrusted, uBool False)
          ]
    obj <- createObject ctx h frame
    back <- getAttrOk ctx h obj ckaTrusted
    assertEqual "TRUSTED=false readback" (uBool False) back

-- ---------------------------------------------------------------------------
-- T-C05 cases
-- ---------------------------------------------------------------------------

-- | CKA_ID linkage across the component-imported RSA pair and an
-- X.509 certificate carrying the fixture DER: all three objects get
-- CKA_ID "link", find-by-ID returns exactly those three handles,
-- and the ID reads back on each. A fourth X.509 object carrying
-- CKA_ID "other" proves the find filters on the ID value (it is
-- excluded from the "link" find, returned alone by the "other"
-- find), and a find for an absent ID returns no handles.
caseIdLinkage :: MVar () -> IO ()
caseIdLinkage _envLock = do
  der <- fixtureDer
  subj <- derSubject der
  m0 <- seedModel
  st <- getSession m0
  (m1, hPriv, _) <- doCreate m0 st rsaPrivTmpl
  (m2, hPub, _) <- doCreate m1 st rsaPubTmpl
  (m3, hCert, _) <- doCreate m2 st (linkCertTmpl der subj)
  (m4, hOther, _) <- doCreate m3 st (linkCertTmpl der subj)
  let link = [(AttrId, ValBytes "link")]
      other = [(AttrId, ValBytes "other")]
      absent = [(AttrId, ValBytes "absent")]
  m5 <- doSet m4 st hPriv link
  m6 <- doSet m5 st hPub link
  m7 <- doSet m6 st hCert link
  m8 <- doSet m7 st hOther other
  (m9, found) <- doFind m8 st link
  assertEqual "find-by-ID returns exactly the three linked handles"
    [hPriv, hPub, hCert] found
  (m10, foundOther) <- doFind m9 st other
  assertEqual "find-by-other-ID returns exactly the distractor handle"
    [hOther] foundOther
  (m11, foundAbsent) <- doFind m10 st absent
  assertEqual "find-by-absent-ID returns no handles"
    [] foundAbsent
  forM_ [hPriv, hPub, hCert] $ \h -> case resolveHandle m11 h of
    Nothing -> assertFailure "linked handle does not resolve"
    Just ost -> assertEqual "ID readback"
      (Just (ValBytes "link")) (Map.lookup AttrId (osAttrs ost))

-- | Real sign/verify over the certificate VALUE bytes: the message
-- is the VALUE read back from a created X.509 certificate object
-- (the fixture DER), signed with the component-imported private
-- DER and verified with the public DER to a real EngineOk ().
caseRealSignature :: MVar () -> IO ()
caseRealSignature _envLock = withRealEnv $ \env -> do
  der <- fixtureDer
  subj <- derSubject der
  m0 <- seedModel
  st <- getSession m0
  (m1, _, privAttrs) <- doCreate m0 st rsaPrivTmpl
  privDer <- storedValue privAttrs
  (m2, _, pubAttrs) <- doCreate m1 st rsaPubTmpl
  pubDer <- storedValue pubAttrs
  (_, _, certAttrs) <- doCreate m2 st (linkCertTmpl der subj)
  certValue <- storedValue certAttrs
  assertEqual "certificate VALUE is the fixture DER" der certValue
  let rsaSpec = SigRSA_PKCS1v15 D_SHA256
  sres <- sign env rsaSpec (KeyDer privDer) certValue
  sig <- case sres of
    EngineOk s -> pure s
    EngineFail err -> assertFailure ("identity RSA sign failed: " ++ show err) >> undefined
  vres <- verify env rsaSpec (KeyDer pubDer) certValue sig
  case vres of
    EngineOk () -> pure ()
    EngineFail err -> assertFailure ("identity RSA verify failed: " ++ show err)

-- | X.509 create template over caller-supplied VALUE/SUBJECT.
linkCertTmpl :: ByteString -> ByteString -> [(AttributeType, AttributeValue)]
linkCertTmpl der subj =
  [ (AttrClass, ValULong ckoCert)
  , (AttrCertificateType, ValULong ckcX509)
  , (AttrValue, ValBytes der)
  , (AttrSubject, ValBytes subj)
  ]

-- | Set attributes, publish, and return the model (doCreate-shaped).
doSet :: Model -> SessionState -> ExternalHandle -> [(AttributeType, AttributeValue)] -> IO Model
doSet m st h tmpl = case planSetAttributes m st h tmpl of
  Immediate c -> expectRight (publishDelta m (pcDelta c))
  Reject rej -> assertFailure ("must set, got: " ++ show (rejCode rej)) >> undefined
  Execute _ _ -> assertFailure "set must not execute" >> undefined

-- | One-shot find returning the bound handles (doCreate-shaped).
doFind :: Model -> SessionState -> [(AttributeType, AttributeValue)] -> IO (Model, [ExternalHandle])
doFind m st tmpl = case planFindObjects m st tmpl of
  Immediate c -> do
    m' <- expectRight (publishDelta m (pcDelta c))
    hs <- mapM handleOf (pcOutputs c)
    pure (m', hs)
  Reject rej -> assertFailure ("must find, got: " ++ show (rejCode rej)) >> undefined
  Execute _ _ -> assertFailure "find must not execute" >> undefined

-- ---------------------------------------------------------------------------
-- T-C06 cases
-- ---------------------------------------------------------------------------

-- | CKO_TRUST / CKO_VALIDATION numeric class ids (pinned header
-- spec/vendor/pkcs11.h:1034-1035).
ckoTrust, ckoValidation :: Word64
ckoTrust = 0xb
ckoValidation = 0xa

-- | Generic-attribute numeric ids for the trust/validation create
-- frames (pinned header: CKA_ISSUER 0x81, CKA_SERIAL_NUMBER 0x82).
ckaIssuer, ckaSerialNumber :: Word64
ckaIssuer = 0x81
ckaSerialNumber = 0x82

-- | CKR_ATTRIBUTE_TYPE_INVALID (pinned: ckrAttrTypeInvalid in
-- Standard.hs is CULong 0x12).
rvAttrTypeInvalid :: CULong
rvAttrTypeInvalid = CULong 0x12

-- | Unmodeled trust numerics: CKA_TRUST_* 0x62c-0x632 plus
-- CKA_HASH_OF_CERTIFICATE 0x635 (pinned header).
trustNumerics :: [Word64]
trustNumerics = [0x62c .. 0x632] ++ [0x635]

-- | Unmodeled validation numerics: CKA_OBJECT_VALIDATION_FLAGS
-- 0x61e plus CKA_VALIDATION_* 0x61f-0x629 (pinned header).
validationNumerics :: [Word64]
validationNumerics = [0x61e .. 0x629]

-- | The deferral proof for one unmodeled numeric attribute id:
-- the generated name exists (attributeNameById returns Just) AND
-- attributeTypeByName returns Nothing — proving the id takes the
-- unknown-id path in haskokiStdGetOneAttr (Standard.hs:2299-2302),
-- not the modeled-but-missing rejection arm (Standard.hs:2332)
-- which emits the same response triple — plus the deferral triple
-- read through the scalar FFI getter: RV
-- CKR_ATTRIBUTE_TYPE_INVALID, pLen CK_UNAVAILABLE_INFORMATION
-- (maxBound), and the value buffer byte-identical to its pre-call
-- canary fill. The unknown-id path pokes only pLen and never
-- touches the value buffer.
assertNumericPinned :: StablePtr StdInstance -> CULong -> CULong -> Word64 -> IO ()
assertNumericPinned ctx h obj cka = do
  case attributeNameById cka of
    Nothing -> assertFailure ("generated name missing for " ++ show cka)
    Just name ->
      assertEqual ("typed mapping " ++ show cka) Nothing (attributeTypeByName name)
  allocaBytes canaryLen $ \(buf :: Ptr Word8) ->
    alloca $ \(pLen :: Ptr CULong) -> do
      pokeArray buf canary
      poke pLen (CULong (fromIntegral canaryLen))
      rv <- haskokiStdGetOneAttr ctx h obj (CULong cka) buf pLen
      assertEqual ("rv " ++ show cka) rvAttrTypeInvalid rv
      CULong n <- peek pLen
      assertEqual ("pLen " ++ show cka) maxBound n
      after <- peekArray canaryLen buf
      assertEqual ("buffer " ++ show cka) canary after
  where
    canaryLen = 64
    canary = replicate canaryLen 0xA5

-- | CKO_TRUST numeric pins: a trust object created through the
-- generic FFI path carries generic attributes only (LABEL reads
-- back); every unmodeled trust numeric id refuses with the
-- deferral triple. This pins absence; it must NOT be "fixed" into
-- service.
caseTrustNumericPinned :: MVar () -> IO ()
caseTrustNumericPinned envLock = do
  dbPath <- certDbPath "trust-numeric"
  probe <- newCertProbe
  withCertInstance envLock dbPath probe $ \ctx _inst -> do
    h <- openRwSession ctx
    let frame = buildFrame
          [ (ckaClass, le64 ckoTrust)
          , (ckaToken, uBool False)
          , (ckaLabel, "tc06-trust-numeric")
          , (ckaIssuer, "tc06-trust-issuer")
          , (ckaSerialNumber, "tc06-trust-serial")
          ]
    obj <- createObject ctx h frame
    back <- getAttrOk ctx h obj ckaLabel
    assertEqual "LABEL readback" "tc06-trust-numeric" back
    forM_ trustNumerics (assertNumericPinned ctx h obj)

-- | CKO_VALIDATION numeric pins: a validation object created
-- through the generic FFI path carries generic attributes only
-- (LABEL reads back); every unmodeled validation numeric id
-- refuses with the deferral triple. This pins absence; it must NOT
-- be "fixed" into service.
caseValidationNumericPinned :: MVar () -> IO ()
caseValidationNumericPinned envLock = do
  dbPath <- certDbPath "validation-numeric"
  probe <- newCertProbe
  withCertInstance envLock dbPath probe $ \ctx _inst -> do
    h <- openRwSession ctx
    let frame = buildFrame
          [ (ckaClass, le64 ckoValidation)
          , (ckaToken, uBool False)
          , (ckaLabel, "tc06-validation-numeric")
          , (ckaIssuer, "tc06-validation-issuer")
          , (ckaSerialNumber, "tc06-validation-serial")
          ]
    obj <- createObject ctx h frame
    back <- getAttrOk ctx h obj ckaLabel
    assertEqual "LABEL readback" "tc06-validation-numeric" back
    forM_ validationNumerics (assertNumericPinned ctx h obj)

-- ---------------------------------------------------------------------------
-- T-C05 KeyImportSpec local copies
-- ---------------------------------------------------------------------------

-- The blocks below are copied from tests/model/KeyImportSpec.hs
-- (which exports only spec and lives outside the engine source
-- directory, so the T-C05 cases carry local copies). Each span was
-- asserted to hold exactly the briefed names before copying.

-- KeyImportSpec.hs:105-131 (slot0, sid1, hex, seedModel,
-- getSession, expectRight).
slot0 :: SlotId
slot0 = SlotId 0

sid1 :: SessionId
sid1 = SessionId 1

-- | Decode a hex string (whitespace-tolerant).
hex :: String -> ByteString
hex s = BS.pack (go (filter isHexDigit s))
  where
    go [] = []
    go (a : b : rest) = fromIntegral (digitToInt a * 16 + digitToInt b) : go rest
    go [_] = error "hex: odd digit count"

seedModel :: IO Model
seedModel = do
  let m0 = addToken emptyModel slot0
  expectRight (publishDelta m0 (StateDelta [DeltaOpenSession sid1 slot0 False]))

getSession :: Model -> IO SessionState
getSession m = case lookupSession m sid1 of
  Nothing -> assertFailure "seed session missing" >> undefined
  Just st -> pure st

expectRight :: Show e => Either e a -> IO a
expectRight (Right a) = pure a
expectRight (Left e) = assertFailure ("expected Right, got: " ++ show e) >> undefined

-- KeyImportSpec.hs:134-168 (withRealEnv, doCreate, handleOf,
-- expectReject with full body).
withRealEnv :: (BackendEnv OpenSSL4 -> IO a) -> IO a
withRealEnv action = do
  opened <- openBackend "provider=default" :: IO (EngineResult (BackendEnv OpenSSL4))
  case opened of
    EngineFail err -> assertFailure ("openssl4 open failed: " ++ show err) >> undefined
    EngineOk env -> do
      r <- action env
      closeBackend env
      pure r

-- | Create one object, publish it, and return the stored attributes.
doCreate :: Model -> SessionState -> [(AttributeType, AttributeValue)]
  -> IO (Model, ExternalHandle, Map.Map AttributeType AttributeValue)
doCreate m st tmpl = case planCreateObject m st tmpl of
  Immediate c -> do
    m' <- expectRight (publishDelta m (pcDelta c))
    h <- case pcOutputs c of
      [o] -> handleOf o
      _ -> assertFailure "create outputs arity" >> undefined
    case resolveHandle m' h of
      Nothing -> assertFailure "created object unresolvable" >> undefined
      Just ost -> pure (m', h, osAttrs ost)
  Reject rej -> assertFailure ("must create, got: " ++ show (rejCode rej)) >> undefined
  Execute _ _ -> assertFailure "create must not execute" >> undefined

handleOf :: NativeOutput -> IO ExternalHandle
handleOf o = case decodeHandle (outBytes o) of
  Just h -> pure h
  Nothing -> assertFailure "handle output undecodable" >> undefined

expectReject :: ReturnCode -> PlanResult -> IO ()
expectReject want res = case res of
  Reject rej -> assertEqual "reject code" want (rejCode rej)
  Immediate _ -> assertFailure "must reject, created"
  Execute _ _ -> assertFailure "must reject, executed"

-- KeyImportSpec.hs:170-192 (rsaPrivTmpl, rsaPubTmpl).
rsaPrivTmpl :: [(AttributeType, AttributeValue)]
rsaPrivTmpl =
  [ (AttrClass, ValULong ckoPrivateKey)
  , (AttrKeyType, ValULong ckkRsa)
  , (AttrToken, ValBool False)
  , (AttrModulus, ValBytes rsaN)
  , (AttrPublicExponent, ValBytes rsaE)
  , (AttrPrivateExponent, ValBytes rsaD)
  , (AttrPrime1, ValBytes rsaP)
  , (AttrPrime2, ValBytes rsaQ)
  , (AttrExponent1, ValBytes rsaDp)
  , (AttrExponent2, ValBytes rsaDq)
  , (AttrCoefficient, ValBytes rsaQinv)
  ]

rsaPubTmpl :: [(AttributeType, AttributeValue)]
rsaPubTmpl =
  [ (AttrClass, ValULong ckoPublicKey)
  , (AttrKeyType, ValULong ckkRsa)
  , (AttrToken, ValBool False)
  , (AttrModulus, ValBytes rsaN)
  , (AttrPublicExponent, ValBytes rsaE)
  ]

-- KeyImportSpec.hs:489-492 (storedValue).
storedValue :: Map.Map AttributeType AttributeValue -> IO ByteString
storedValue attrs = case Map.lookup AttrValue attrs of
  Just (ValBytes bs) -> pure bs
  _ -> assertFailure "stored value missing" >> undefined

-- KeyImportSpec.hs:1101-1169 (rsaN/E/D/P/Q/Dp/Dq/Qinv blobs).
rsaN :: ByteString
rsaN = hex $ concat
    [ "bf249542389ea0de381c11c04c7777e6c56106165ec581cc378e6f9022cd2b4f"
    , "efd66e575e7043004afef1e4916177cea097cef02d4f09de587d869840cd75ec"
    , "a6adb70c19824f9a8a573c9ac337876cd2c490e6c5d69a686386009d54d13f1b"
    , "1be0a71055f23717d81bdc060c29d0ec7a6d8280a677ab92d65c9b64981300e4"
    , "a4eb60e4180189362c964ba3d55ca2db2d2998331ea0e87ab44d577fe8533717"
    , "9f02cf8d71404b4f8bd99e4e3e636c45ceea91e7660165f35451ee15fd44b42a"
    , "5eee7552aaccc25737be7f3d43542a43cc46b39fb127608c5a055327d339855e"
    , "838995295160067a417cc8c3095ee012bf078da33c71becae36b9805c174f357"
    ]

rsaE :: ByteString
rsaE = hex $ concat
    [ "010001"
    ]

rsaD :: ByteString
rsaD = hex $ concat
    [ "02147aaaa8fabcedbe219165e22478ac626079befb92b2fa0f1960886a8088b9"
    , "f5765966b4fde16a1ae6d1a8b6eb9f1b4e0468e43f31f97daf167fef9f363d29"
    , "7144e4558adf855092b47bfc83d1a7b51cf40ba449e9d9c34cb5f4181788b162"
    , "f0f78db4854d934b91f6a25079ddbdf5722847ea70cff8e62a540152e3bec287"
    , "3598079bf1965083cca686d500ab2867c43db553dd2894a3014fa30814f58966"
    , "b7f91e71b9c6928f41d22587daa3a939b409b9aeac3765404b0b3a890000c2e3"
    , "480d90950529f73df1340f69cc8be3c69def997524a3883cc618f51a81130842"
    , "f094b95699d093acb3e8c59a9a65b968101f6220638265e398f8f65ba6363ca5"
    ]

rsaP :: ByteString
rsaP = hex $ concat
    [ "f38edb79d7c425b930bee769f17aa3cc565f6e0a72b7fd0c734a0257960213f5"
    , "c5c5d16887e80d0d8c9136daa855e26e38319f7cd5f454b875e9eff1c9a6dc88"
    , "753a65d825d079d1fd9b8d1843e250793279877e1db7bd932b09473a1973ce71"
    , "0f5179baf192a17052a66c5247205bdad49fb48938b6590d5f2154820337498b"
    ]

rsaQ :: ByteString
rsaQ = hex $ concat
    [ "c8e8439d64764eaff4f6bf45bc56df3280d3c5aeedae00f0099f3d169db75f3a"
    , "0105900eef944f120f0d49d63d623e07b6feafa043914bf8e4ae243a9f82b853"
    , "dc1e347b262a250423d1f53f097cdce6677813a277f8eca15b5a61acb08bbdc2"
    , "042a0457492f09488ab22936aa8e098798484a230f3c4d27294589d4c8a1bee5"
    ]

rsaDp :: ByteString
rsaDp = hex $ concat
    [ "17e28b9d804e6910a73a21819f3fd2ae684e05819acc76517140f1c7db1b2b0f"
    , "f02c3d240e27f097c2903f1be4643fc765556079a295ca7528831f97cb99c488"
    , "d14e3fcc99b0bf319bb85476ebb95700fbb5355765dcae07afb1c23d6d5f9100"
    , "3f6b530fc53f06fbf7ef0032756d33f4dae32a96466c83812f321a9281743b8f"
    ]

rsaDq :: ByteString
rsaDq = hex $ concat
    [ "80b900096a02bb2bd5e1fa6f2ddae32ab28bfd0eb54e555f766ac673251e062f"
    , "5dd43896b93de6e3852d586fa1e8be21a747cb32fdd7ac3b8e195d310a5e70c7"
    , "9a32e8213734ad7ed78c807ba112955e325127136396e3d606780438e6ecc1e9"
    , "fb4d0876fc76dc95d3f78e9c6dee8f80873b59f4d8a02436c124c2c8c8bb8959"
    ]

rsaQinv :: ByteString
rsaQinv = hex $ concat
    [ "3cefd2574cbb2056d55f71c3fe82090a9797c6c038d1ef045e0373081801f4e4"
    , "68f7822b9580bcd21aac3c601a330ca745978cd01761cbccf29201086defab1f"
    , "08ec5024b60b79ed839dbf43c9c35a07da5cf8163fc4c57a1e06b20378077dab"
    , "fb54e39d56bf2a4d478187829ec00236001f1503a903482246a21aac1c04ae4f"
    ]

-- ---------------------------------------------------------------------------
-- DURABILITY reporting
-- ---------------------------------------------------------------------------

-- | One case's DURABILITY line reporter: case-fixed, seq-numbered,
-- line-buffered and flushed per line so parallel tasty threads can
-- only interleave whole lines (the checker reorders by seq).
data Reporter = Reporter
  { repCase :: !String
  , repSeq :: !(IORef Int)
  }

newReporter :: String -> IO Reporter
newReporter name = do
  hSetBuffering stdout LineBuffering
  Reporter name <$> newIORef 1

say :: Reporter -> String -> IO ()
say rep rest = do
  n <- readIORef (repSeq rep)
  writeIORef (repSeq rep) (n + 1)
  putStrLn ("DURABILITY case=" ++ repCase rep ++ " seq=" ++ show n ++ " " ++ rest)
  hFlush stdout

-- ---------------------------------------------------------------------------
-- Store/ledger probe
-- ---------------------------------------------------------------------------

-- | One case's store/ledger probe: the ledger ref injected through
-- the @saAssemble@ override, the commit/result tape wrapped around
-- the opened store's commit, the backing-call count
-- (reissue/IO accounting), the reset-call count (always zero), and
-- the fault override (delta + backing -> result).
data CertProbe = CertProbe
  { cpLedger :: !(IORef [LedgerEvent])
  , cpCommits :: !(IORef [(Bool, String)])
  , cpBacking :: !(IORef Int)
  , cpResets :: !(IORef Int)
  , cpFault :: !(IORef (StoreDelta -> (StoreDelta -> IO CommitResult) -> IO CommitResult))
  , cpLoadFail :: !(IORef Bool)
  }

newCertProbe :: IO CertProbe
newCertProbe = CertProbe
  <$> newIORef []
  <*> newIORef []
  <*> newIORef 0
  <*> newIORef 0
  <*> newIORef (\delta backing -> backing delta)
  <*> newIORef False

tagResult :: CommitResult -> String
tagResult Committed = "committed"
tagResult (NotCommitted _) = "not-committed"
tagResult (CommitUnknown _) = "commit-unknown"

-- | A flush is the only commit with every pre-T-C02 delta list
-- empty (live commits always carry puts or drops; the seat commit
-- carries token puts). Detected without naming @sdPutMeta@ so this
-- fixture also compiles against the behavior-neutral scaffold.
isFlushDelta :: StoreDelta -> Bool
isFlushDelta d = null (sdPutTokens d) && null (sdDropTokens d)
  && null (sdPutObjects d) && null (sdDropObjects d)
  && null (sdPutJobs d) && null (sdDropJobs d)

certAcquisition :: CertProbe -> StdAcquisition
certAcquisition probe = stdAcquisition
  { saOpenStore = \env cfg -> do
      eStore <- saOpenStore stdAcquisition env cfg
      case eStore of
        Left err -> pure (Left err)
        Right mStore -> pure (Right (fmap wrapStd mStore))
  , saAssemble = \inst -> newStablePtr (inst { siLedger = Just (cpLedger probe) })
  }
  where
    wrapStd ss = ss { stdStore = (stdStore ss)
      { storeCommit = wrappedCommit (storeCommit (stdStore ss))
      , storeLoadTokens = do
          bad <- readIORef (cpLoadFail probe)
          if bad
            then pure (Left (StoreIO "t-c02 injected unreadable"))
            else storeLoadTokens (stdStore ss)
      , storeResetToken = \_tid _gen _rec ->
          modifyIORef' (cpResets probe) (+ 1)
            >> storeResetToken (stdStore ss) _tid _gen _rec
      } }
    wrappedCommit backing delta = do
      fault <- readIORef (cpFault probe)
      result <- fault delta countedBacking
      modifyIORef' (cpCommits probe) (++ [(isFlushDelta delta, tagResult result)])
      pure result
      where
        countedBacking d = modifyIORef' (cpBacking probe) (+ 1) >> backing d

-- | Print every buffered ledger event (phase=live) and clear the buffer.
drainLedger :: Reporter -> CertProbe -> IO [String]
drainLedger rep probe = do
  events <- readIORef (cpLedger probe)
  writeIORef (cpLedger probe) []
  let names = map renderLedgerEvent events
  forM_ names $ \name -> say rep ("phase=live kind=event name=" ++ name)
  pure names

noteOpen :: Reporter -> StdInstance -> Int -> IO ()
noteOpen rep inst gen = do
  m <- snapshotModel (siEnv inst)
  say rep ("phase=startup kind=open gen=" ++ show gen
    ++ " next_handle=" ++ show (mNextHandle m)
    ++ " next_rev=" ++ show (mNextRevision m))
  -- C02-06 fallback note (brief:73): the reservation runs before
  -- the ledger probe exists, so no production ledger event can
  -- observe the open path. The test re-reads storeLoadMeta
  -- post-open and prints meta-key presence plus the implied
  -- fallback decision; the checker requires this note on every
  -- open and cross-checks the counters against the implied
  -- branch. Corrupt/unreadable meta post-open is impossible (the
  -- open would have refused): fail loudly if ever observed.
  store <- liveStore inst
  eMeta <- storeLoadMeta store
  case eMeta of
    Left err -> do
      say rep ("phase=startup kind=fallback gen=" ++ show gen ++ " status=unreadable")
      assertFailure ("store meta unreadable post-open: " ++ show err) >> fail "unreachable"
    Right meta -> do
      let hCtr = lookup "handle_counter" meta
          rCtr = lookup "revision_counter" meta
          hVal = hCtr >>= readCounter
          rVal = rCtr >>= readCounter
          badKey = case (hCtr, hVal) of
            (Just _, Nothing) -> Just "handle_counter"
            _ -> case (rCtr, rVal) of
              (Just _, Nothing) -> Just "revision_counter"
              _ -> Nothing
          liveMaxH = maximum (0 : [unExternalHandle h | h <- Map.keys (mHandles m)])
          restMaxR = maximum (0 : [unRevision (osRevision o) | o <- Map.elems (mObjects m)])
          showCtr = maybe "absent" show
          decision
            | hVal /= Nothing && rVal /= Nothing = "meta"
            | hCtr == Nothing && rCtr == Nothing = "restored-fallback"
            | otherwise = "partial"
      case badKey of
        Just key -> do
          say rep ("phase=startup kind=fallback gen=" ++ show gen ++ " status=corrupt key=" ++ key)
          assertFailure ("store meta corrupt post-open: " ++ key) >> fail "unreachable"
        Nothing ->
          say rep ("phase=startup kind=fallback gen=" ++ show gen
            ++ " handle_ctr=" ++ showCtr hVal
            ++ " revision_ctr=" ++ showCtr rVal
            ++ " live_max_handle=" ++ show liveMaxH
            ++ " restored_max_rev=" ++ show restMaxR
            ++ " decision=" ++ decision)

-- | Positive-int counter parse (mirrors the production gate).
readCounter :: String -> Maybe Int
readCounter s = case readMaybe s of
  Just n | n >= 1 -> Just n
  _ -> Nothing

noteCommitLog :: Reporter -> CertProbe -> IO ()
noteCommitLog rep probe = do
  commits <- readIORef (cpCommits probe)
  backing <- readIORef (cpBacking probe)
  resets <- readIORef (cpResets probe)
  let flushes = length (filter fst commits)
  say rep ("phase=live kind=commit-log commits=" ++ show (length commits)
    ++ " flushes=" ++ show flushes
    ++ " backing=" ++ show backing
    ++ " resets=" ++ show resets)

-- | New commit-tape entries since a recorded length.
newCommits :: CertProbe -> Int -> IO [(Bool, String)]
newCommits probe before = drop before <$> readIORef (cpCommits probe)

-- ---------------------------------------------------------------------------
-- Temp-directory SQLite opens
-- ---------------------------------------------------------------------------

certDbPath :: String -> IO FilePath
certDbPath tag = do
  base <- getTemporaryDirectory
  let path = base ++ "/haskoki-cert-" ++ tag ++ ".db"
  removeIfExists path
  removeIfExists (path ++ ".lock")
  pure path

removeIfExists :: FilePath -> IO ()
removeIfExists path = do
  exists <- doesFileExist path
  when exists (removeFile path)

certConfig :: FilePath -> Config
certConfig path = defaultConfig
  { cfgStorage = (cfgStorage defaultConfig) { scKind = StorageSQLite, scPath = Just path } }

-- | SlotEvents mirroring openStdInstanceWith's construction.
certSlots :: Config -> IO SlotEvents
certSlots cfg = do
  let catalog = effectiveCatalog cfg
  eSlots <- newSlotEvents (limEvents (cfgLimits cfg))
    [SlotDefinition slot (ccTestEnabled (cfgControl cfg)) | slot <- Map.keys catalog]
  case eSlots of
    Left err -> assertFailure ("slot events: " ++ show err) >> fail "unreachable"
    Right slots -> pure slots

withCertInstance :: MVar () -> FilePath -> CertProbe
  -> (StablePtr StdInstance -> StdInstance -> IO a) -> IO a
withCertInstance envLock dbPath probe action = do
  let cfg = certConfig dbPath
  slots <- certSlots cfg
  bracket (openHere cfg slots)
    (\(ctx, _) -> haskokiStdClose ctx >> closeSlotEvents slots)
    (\(ctx, inst) -> action ctx inst)
  where
    openHere cfg slots = do
      ctx <- withEnvLock envLock (openStdInstanceWithSlots (certAcquisition probe) cfg slots)
      assertBool ("SQLite open: " ++ dbPath) (castStablePtrToPtr ctx /= nullPtr)
      inst <- deRefStablePtr ctx
      pure (ctx, inst)

-- | Attempt an open that must refuse (C02-01): @True@ iff the open
-- returns NULL. A NULL open already closed its slots; a
-- non-NULL (unexpected) open is closed before reporting.
tryOpenRefused :: MVar () -> FilePath -> IO Bool
tryOpenRefused envLock dbPath = do
  let cfg = certConfig dbPath
  slots <- certSlots cfg
  probe <- newCertProbe
  ctx <- withEnvLock envLock (openStdInstanceWithSlots (certAcquisition probe) cfg slots)
  if castStablePtrToPtr ctx == nullPtr
    then pure True
    else haskokiStdClose ctx >> closeSlotEvents slots >> pure False

liveStore :: StdInstance -> IO Store
liveStore inst = case siStore inst of
  Just ss -> pure (stdStore ss)
  Nothing -> assertFailure "missing owned store" >> fail "unreachable"

-- ---------------------------------------------------------------------------
-- Template frames and object FFI
-- ---------------------------------------------------------------------------

rvOK, rvHandleInvalid, rvGeneral :: CULong
rvOK = CULong 0
rvHandleInvalid = CULong 0x82
rvGeneral = CULong 5

le64 :: Word64 -> ByteString
le64 w = BS.pack [fromIntegral ((w `div` (256 ^ s)) `mod` 256) | s <- [0 .. 7 :: Int]]

buildFrame :: [(Word64, ByteString)] -> ByteString
buildFrame attrs = le64 (fromIntegral (length attrs))
  <> mconcat [le64 t <> le64 (fromIntegral (BS.length v)) <> v | (t, v) <- attrs]

uBool :: Bool -> ByteString
uBool False = BS.singleton 0
uBool True = BS.singleton 1

ckaClass, ckaToken, ckaLabel, ckaValue, ckaCertType, ckaSubject :: Word64
ckaClass = 0x0
ckaToken = 0x1
ckaLabel = 0x3
ckaValue = 0x11
ckaCertType = 0x80
ckaSubject = 0x101

ckaTrusted :: Word64
ckaTrusted = 0x86

ckoData, ckoCert, ckcX509 :: Word64
ckoData = 0x0
ckoCert = 0x1
ckcX509 = 0x0

certTemplate :: Bool -> ByteString -> ByteString -> ByteString -> ByteString
certTemplate isToken label der subj = buildFrame
  [ (ckaClass, le64 ckoCert)
  , (ckaCertType, le64 ckcX509)
  , (ckaToken, uBool isToken)
  , (ckaLabel, label)
  , (ckaValue, der)
  , (ckaSubject, subj)
  ]

dataTemplate :: Bool -> ByteString -> ByteString -> ByteString
dataTemplate isToken label bytes = buildFrame
  [ (ckaClass, le64 ckoData)
  , (ckaToken, uBool isToken)
  , (ckaLabel, label)
  , (ckaValue, bytes)
  ]

openRwSession :: StablePtr StdInstance -> IO CULong
openRwSession ctx = alloca $ \(phSession :: Ptr CULong) -> do
  poke phSession (CULong 0)
  rv <- haskokiStdOpenSession ctx (CULong 0) (CULong 0) phSession
  assertEqual "open session rv" rvOK rv
  peek phSession

-- | Raw create: canary-poked output, no assertions (the conflict
-- loser keeps its canary).
rawCreate :: StablePtr StdInstance -> CULong -> ByteString -> IO (CULong, CULong)
rawCreate ctx h frame =
  BS.useAsCStringLen frame $ \(cstr, len) ->
    alloca $ \(phObject :: Ptr CULong) -> do
      poke phObject (CULong 0xA5A5A5A5)
      rv <- haskokiStdCreateObject ctx h (castPtr cstr) (fromIntegral len) phObject
      out <- peek phObject
      pure (rv, out)

createObject :: StablePtr StdInstance -> CULong -> ByteString -> IO CULong
createObject ctx h frame = do
  (rv, out) <- rawCreate ctx h frame
  assertEqual "create rv" rvOK rv
  pure out

findByTemplate :: StablePtr StdInstance -> CULong -> ByteString -> IO [CULong]
findByTemplate ctx h frame =
  BS.useAsCStringLen frame $ \(cstr, len) -> do
    rvInit <- haskokiStdFindInit ctx h (castPtr cstr) (fromIntegral len)
    assertEqual "find-init rv" rvOK rvInit
    hits <- allocaArray 16 $ \(pHandles :: Ptr CULong) ->
      alloca $ \(pCount :: Ptr CULong) -> do
        poke pCount (CULong 0)
        rvFind <- haskokiStdFind ctx h 16 pHandles pCount
        assertEqual "find rv" rvOK rvFind
        CULong n <- peek pCount
        peekArray (fromIntegral n) pHandles
    rvFinal <- haskokiStdFindFinal ctx h
    assertEqual "find-final rv" rvOK rvFinal
    pure hits

findByLabel :: StablePtr StdInstance -> CULong -> ByteString -> IO [CULong]
findByLabel ctx h label = findByTemplate ctx h (buildFrame [(ckaLabel, label)])

getAttrBytes :: StablePtr StdInstance -> CULong -> CULong -> Word64 -> IO (CULong, ByteString)
getAttrBytes ctx h obj cka =
  allocaBytes 8192 $ \(buf :: Ptr Word8) ->
    alloca $ \(pLen :: Ptr CULong) -> do
      poke pLen (CULong 8192)
      rv <- haskokiStdGetOneAttr ctx h obj (CULong cka) buf pLen
      if rv == rvOK
        then do
          CULong n <- peek pLen
          bytes <- BS.packCStringLen (castPtr buf, fromIntegral n)
          pure (rv, bytes)
        else pure (rv, BS.empty)

getAttrOk :: StablePtr StdInstance -> CULong -> CULong -> Word64 -> IO ByteString
getAttrOk ctx h obj cka = do
  (rv, bytes) <- getAttrBytes ctx h obj cka
  assertEqual ("getattr rv " ++ show cka) rvOK rv
  pure bytes

setAttrs :: StablePtr StdInstance -> CULong -> CULong -> ByteString -> IO ()
setAttrs ctx h obj frame =
  BS.useAsCStringLen frame $ \(cstr, len) -> do
    rv <- haskokiStdSetAttributeValue ctx h obj (castPtr cstr) (fromIntegral len)
    assertEqual "set-attr rv" rvOK rv

copyObject :: StablePtr StdInstance -> CULong -> CULong -> ByteString -> IO CULong
copyObject ctx h obj frame =
  BS.useAsCStringLen frame $ \(cstr, len) ->
    alloca $ \(phNew :: Ptr CULong) -> do
      poke phNew (CULong 0)
      rv <- haskokiStdCopyObject ctx h obj (castPtr cstr) (fromIntegral len) phNew
      assertEqual "copy rv" rvOK rv
      peek phNew

destroyObject :: StablePtr StdInstance -> CULong -> CULong -> IO ()
destroyObject ctx h obj = do
  rv <- haskokiStdDestroyObject ctx h obj
  assertEqual "destroy rv" rvOK rv

-- ---------------------------------------------------------------------------
-- Fixture DER and its real subject bytes
-- ---------------------------------------------------------------------------

fixturePath :: FilePath
fixturePath = "tests/fixtures/cert-selfsigned.der"

fixtureDer :: IO ByteString
fixtureDer = do
  bytes <- BS.readFile fixturePath `catch` \(_ :: SomeException) -> pure BS.empty
  when (BS.null bytes)
    (assertFailure ("fixture unreadable: " ++ fixturePath) >> fail "unreachable")
  pure bytes

byteAt :: ByteString -> Int -> Maybe Word8
byteAt bs off
  | off < 0 || off >= BS.length bs = Nothing
  | otherwise = Just (BS.index bs off)

takeBytes :: ByteString -> Int -> Int -> Maybe ByteString
takeBytes bs off n
  | off < 0 || n < 0 || off + n > BS.length bs = Nothing
  | otherwise = Just (BS.take n (BS.drop off bs))

-- | One TLV header at an offset: (tag, valueOffset, valueLen).
tlvHeader :: ByteString -> Int -> Maybe (Word8, Int, Int)
tlvHeader bs off = do
  tag <- byteAt bs off
  b1 <- byteAt bs (off + 1)
  if b1 < 0x80
    then pure (tag, off + 2, fromIntegral b1)
    else do
      let n = fromIntegral (b1 - 0x80)
      guard (n >= 1 && n <= 4)
      lenBytes <- takeBytes bs (off + 2) n
      let len = BS.foldl' (\acc b -> acc * 256 + fromIntegral b) 0 lenBytes
      pure (tag, off + 2 + n, len)

-- | Split a constructed value into child full-TLV slices.
childSlices :: ByteString -> Maybe [ByteString]
childSlices val = go 0
  where
    go off
      | off == BS.length val = Just []
      | off > BS.length val = Nothing
      | otherwise = do
          (_, vOff, vLen) <- tlvHeader val off
          let end = vOff + vLen
          guard (end <= BS.length val)
          rest <- go end
          Just (BS.take (end - off) (BS.drop off val) : rest)

orSetupFail :: String -> Maybe a -> IO a
orSetupFail _ (Just x) = pure x
orSetupFail why Nothing = assertFailure ("fixture setup: " ++ why) >> fail "unreachable"

-- | The fixture's real subject Name bytes: Certificate[0][5]'s full
-- TLV (tag+length+value). Fails setup on any shape surprise.
derSubject :: ByteString -> IO ByteString
derSubject der = do
  (tag0, vOff0, vLen0) <- orSetupFail "outer header" (tlvHeader der 0)
  unless (tag0 == 0x30) (assertFailure "fixture is not a DER SEQUENCE" >> fail "unreachable")
  certVal <- orSetupFail "outer length" (takeBytes der vOff0 vLen0)
  kids <- orSetupFail "cert children" (childSlices certVal)
  tbs <- orSetupFail "tbs child" (listToMaybe kids)
  (tagT, tOff, tLen) <- orSetupFail "tbs header" (tlvHeader tbs 0)
  unless (tagT == 0x30) (assertFailure "tbs is not a SEQUENCE" >> fail "unreachable")
  tVal <- orSetupFail "tbs length" (takeBytes tbs tOff tLen)
  tKids <- orSetupFail "tbs children" (childSlices tVal)
  subj <- orSetupFail "subject child" (listToMaybe (drop 5 tKids))
  (tagS, _, _) <- orSetupFail "subject header" (tlvHeader subj 0)
  unless (tagS == 0x30) (assertFailure "subject is not a Name" >> fail "unreachable")
  pure subj

-- ---------------------------------------------------------------------------
-- Model inspection
-- ---------------------------------------------------------------------------

-- | Max live object revision + live object count.
modelRevisions :: StdInstance -> IO (Int, Int)
modelRevisions inst = do
  m <- snapshotModel (siEnv inst)
  let revs = [unRevision (osRevision o) | o <- Map.elems (mObjects m)]
  pure (maximum (0 : revs), Map.size (mObjects m))

-- | The label and revision of the highest-revision labeled object.
highestLabel :: StdInstance -> IO (ByteString, Int)
highestLabel inst = do
  m <- snapshotModel (siEnv inst)
  let labeled = mapMaybe labelRev (Map.elems (mObjects m))
      labelRev o = case Map.lookup AttrLabel (osAttrs o) of
        Just (ValBytes lbl) -> Just (lbl, unRevision (osRevision o))
        _ -> Nothing
  case labeled of
    [] -> assertFailure "no labeled objects" >> fail "unreachable"
    _ -> pure (foldr1 pick labeled)
      where
        pick x acc = if snd x >= snd acc then x else acc

revisionOfLabel :: StdInstance -> ByteString -> IO Int
revisionOfLabel inst label = do
  m <- snapshotModel (siEnv inst)
  let revs = [ unRevision (osRevision o)
             | o <- Map.elems (mObjects m)
             , Map.lookup AttrLabel (osAttrs o) == Just (ValBytes label) ]
  case revs of
    [r] -> pure r
    _ -> assertFailure ("label revision not unique: " ++ show (length revs)) >> fail "unreachable"

objectStateOfLabel :: StdInstance -> ByteString -> IO ObjectState
objectStateOfLabel inst label = do
  m <- snapshotModel (siEnv inst)
  let found = [ o
              | o <- Map.elems (mObjects m)
              , Map.lookup AttrLabel (osAttrs o) == Just (ValBytes label) ]
  case found of
    [o] -> pure o
    _ -> assertFailure ("label object not unique: " ++ show (length found)) >> fail "unreachable"

-- | Block until every thread waits on an MVar (with the gate held by
-- the test, the only contended MVar is the gate itself).
waitBlockedOnGate :: [ThreadId] -> IO ()
waitBlockedOnGate tids = go (0 :: Int)
  where
    go n
      | n > 5000 = assertFailure "racers did not block on the gate" >> fail "unreachable"
      | otherwise = do
          states <- mapM threadStatus tids
          if all isGateBlock states then pure () else threadDelay 1000 >> go (n + 1)
    isGateBlock (ThreadBlocked BlockedOnMVar) = True
    isGateBlock _ = False

assertDisjoint :: String -> [[CULong]] -> IO ()
assertDisjoint label sets = do
  let flat = concat sets
  assertEqual (label ++ ": generations never alias") (length flat) (length (nub flat))

showH :: CULong -> String
showH (CULong n) = show n

showHList :: [CULong] -> String
showHList [] = ""
showHList [x] = showH x
showHList (x : xs) = showH x ++ "," ++ showHList xs

only :: String -> [a] -> IO a
only _ [x] = pure x
only label xs = assertFailure (label ++ ": expected one, got " ++ show (length xs)) >> fail "unreachable"
