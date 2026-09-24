{- | Runtime lifecycle tests: init/finalize validation, the mutation
gate with explicit invalidation, and the callback-lock adapter.

The conflict case proves the architecture rule: a call pinned to
invalidated state gets its source-defined rejection while an
unrelated session's reservation still holds.
-}
{-# LANGUAGE OverloadedStrings #-}
module LifecycleSpec (spec) where

import Control.Exception (SomeException, try)
import Data.IORef (atomicModifyIORef', newIORef)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertBool, assertEqual, testCase)

import Haskoki.Model (Model (..), addToken, emptyModel)
import Haskoki.Outcome
  ( DeltaOp (..)
  , EngineResult (..)
  , ModelFault (..)
  , PlanResult (..)
  , PreparedCommit (..)
  , Rejection (..)
  , Reservation (..)
  , RevisionDep (..)
  , StateDelta (..)
  )
import Haskoki.Request (FunctionId (..), Request (..))
import Haskoki.Rules (defaultRules)
import Haskoki.Runtime.Lifecycle
  ( CallbackSet (..)
  , InitArgs (..)
  , MutexCounts (..)
  , MutexHooks (..)
  , adapterCounts
  , adapterLive
  , checkReservation
  , createCounted
  , defaultInitArgs
  , destroyCounted
  , finalize
  , initialize
  , invalidateSession
  , newEnv
  , newMutexAdapter
  , publish
  , referenceHooks
  , seatToken
  , withAdapterLock
  , withInitLocks
  )
import Haskoki.Transition (finishEffect, planCall, publishDelta)
import Haskoki.Types
  ( Generation (..)
  , Outcome (..)
  , Pkcs11Version (..)
  , ReturnCode (..)
  , Revision (..)
  , SessionId (..)
  , SlotId (..)
  )

spec :: TestTree
spec = testGroup "runtime lifecycle"
  [ testCase "init validation table" caseInitTable
  , testCase "finalize needs init and zero sessions" caseFinalize
  , testCase "conflict rejects; unrelated session proceeds" caseConflict
  , testCase "publish faults leave the model unchanged" casePublishFault
  , testCase "adapter counts create/use/destroy" caseAdapterCounts
  , testCase "init locks clean up on throw" caseInitLockCleanup
  , testCase "init locks clean up on setup throw" caseInitLockSetupThrow
  ]

slot0 :: SlotId
slot0 = SlotId 0

openReq :: Request
openReq = Request
  { reqVersion = Pkcs11_3_2
  , reqFunction = F_OpenSession
  , reqSession = Nothing
  , reqHandle = Nothing
  , reqInput = "slot=0,rw"
  , reqRegions = []
  }

-- | Open a session through plan+publish and return its id and model.
openOne :: Model -> IO (SessionId, Model)
openOne model = case planCall defaultRules model openReq of
  Immediate pc -> case publishDelta model (pcDelta pc) of
    Left fault -> fail ("open fault: " ++ show fault)
    Right m' -> pure (SessionId (mNextSession model), m')
  other -> fail ("open did not commit: " ++ show other)

caseInitTable :: IO ()
caseInitTable = do
  env <- newEnv defaultRules
  -- Fresh + default args initializes.
  r1 <- initialize env defaultInitArgs
  assertEqual "init ok" (OutcomeOk ()) r1
  -- Double init is denied.
  r2 <- initialize env defaultInitArgs
  assertEqual "double init" (OutcomeErr CKR_CRYPTOKI_ALREADY_INITIALIZED) r2
  -- Bad args are denied even when the table row changes: finalize
  -- first, then retry with reserved flags and partial callbacks.
  r3 <- finalize env
  assertEqual "finalize ok" (OutcomeOk ()) r3
  r4 <- initialize env (defaultInitArgs { iaReservedFlags = True })
  assertEqual "reserved flags" (OutcomeErr CKR_ARGUMENTS_BAD) r4
  r5 <- initialize env (defaultInitArgs { iaCallbacks = PartialCallbacks })
  assertEqual "partial callbacks" (OutcomeErr CKR_ARGUMENTS_BAD) r5
  r6 <- initialize env (defaultInitArgs { iaCallbacks = FullCallbacks })
  assertEqual "full callbacks" (OutcomeOk ()) r6

caseFinalize :: IO ()
caseFinalize = do
  env <- newEnv defaultRules
  r0 <- finalize env
  assertEqual "finalize while fresh" (OutcomeErr CKR_CRYPTOKI_NOT_INITIALIZED) r0
  _ <- initialize env defaultInitArgs
  seatToken env slot0 >>= assertEqual "seat ok" (Right ())
  -- Publish an open through the runtime gate.
  (sid, _) <- openOne (addToken emptyModel slot0)
  _ <- publish env (StateDelta [DeltaOpenSession sid slot0 False])
  r1 <- finalize env
  assertEqual "finalize with open session denied"
    (OutcomeErr CKR_GENERAL_ERROR) r1
  _ <- publish env (StateDelta [DeltaCloseSession sid])
  r2 <- finalize env
  assertEqual "finalize after close" (OutcomeOk ()) r2
  -- And the provider can be initialized again.
  r3 <- initialize env defaultInitArgs
  assertEqual "re-init ok" (OutcomeOk ()) r3

caseConflict :: IO ()
caseConflict = do
  env <- newEnv defaultRules
  _ <- initialize env defaultInitArgs
  seatToken env slot0 >>= assertEqual "seat ok" (Right ())
  -- Open A and B through the runtime; opens allocate rev 1, 2.
  _ <- publish env (StateDelta [DeltaOpenSession (SessionId 1) slot0 False])
  _ <- publish env (StateDelta [DeltaOpenSession (SessionId 2) slot0 False])
  let resA = Reservation "digest"
        [DepSession (SessionId 1) (Revision 1) (Generation 1)]
        Nothing Nothing
      resB = Reservation "digest"
        [DepSession (SessionId 2) (Revision 2) (Generation 1)]
        Nothing Nothing
  -- Both hold before invalidation.
  staleA0 <- checkReservation env resA
  staleB0 <- checkReservation env resB
  assertEqual "A holds" Nothing staleA0
  assertEqual "B holds" Nothing staleB0
  -- Invalidate A: its reservation goes stale, B's still holds.
  invalidateSession env (SessionId 1)
  staleA1 <- checkReservation env resA
  staleB1 <- checkReservation env resB
  assertBool "A stale" (staleA1 /= Nothing)
  assertEqual "B still holds" Nothing staleB1
  -- The conflicting call gets the source-defined rejection while the
  -- unrelated session's reservation still commits.
  model <- case publishDelta (addToken emptyModel slot0)
    (StateDelta [ DeltaOpenSession (SessionId 1) slot0 False
                , DeltaOpenSession (SessionId 2) slot0 False
                , DeltaBumpGeneration (SessionId 1) (Generation 2)
                ]) of
    Left fault -> fail ("setup fault: " ++ show fault)
    Right m -> pure m
  case finishEffect defaultRules model resA (EngineOkBytes "x") of
    Left rej -> assertEqual "stale code" CKR_GENERAL_ERROR (rejCode rej)
    Right _ -> fail "stale reservation must not commit"
  case finishEffect defaultRules model resB (EngineOkBytes "y") of
    Left rej -> fail ("unrelated session must proceed: " ++ show (rejCode rej))
    Right _ -> pure ()

casePublishFault :: IO ()
casePublishFault = do
  env <- newEnv defaultRules
  _ <- initialize env defaultInitArgs
  seatToken env slot0 >>= assertEqual "seat ok" (Right ())
  r <- publish env (StateDelta [DeltaCloseSession (SessionId 99)])
  case r of
    Left (FaultUnknownSession (SessionId 99)) -> pure ()
    other -> fail ("expected unknown-session fault, got: " ++ show other)
  -- Model unchanged: a real open still lands on session 1.
  r2 <- publish env (StateDelta [DeltaOpenSession (SessionId 1) slot0 False])
  assertEqual "open after fault" (Right ()) r2

caseAdapterCounts :: IO ()
caseAdapterCounts = do
  ma <- newMutexAdapter =<< referenceHooks
  m1 <- createCounted ma
  m2 <- createCounted ma
  withAdapterLock ma m1 (pure ())
  withAdapterLock ma m1 (pure ())
  withAdapterLock ma m2 (pure ())
  destroyCounted ma m1
  counts <- adapterCounts ma
  assertEqual "counts" (MutexCounts 2 1 3 3) counts
  live <- adapterLive ma
  assertEqual "one live" 1 live
  destroyCounted ma m2
  live2 <- adapterLive ma
  assertEqual "none live" 0 live2

caseInitLockCleanup :: IO ()
caseInitLockCleanup = do
  ma <- newMutexAdapter =<< referenceHooks
  -- Clean path: 3 created, 3 destroyed, none live.
  withInitLocks ma 3 (pure ())
  c1 <- adapterCounts ma
  assertEqual "clean created" 3 (mcCreated c1)
  assertEqual "clean destroyed" 3 (mcDestroyed c1)
  l1 <- adapterLive ma
  assertEqual "clean live" 0 l1
  -- Throwing path: cleanup still destroys everything created.
  _ <- try (withInitLocks ma 2 (fail "boom")) :: IO (Either SomeException ())
  c2 <- adapterCounts ma
  assertEqual "throw created" 5 (mcCreated c2)
  assertEqual "throw destroyed" 5 (mcDestroyed c2)
  l2 <- adapterLive ma
  assertEqual "throw live" 0 l2

caseInitLockSetupThrow :: IO ()
caseInitLockSetupThrow = do
  -- Host hooks that fail the 3rd creation: setup itself throws, the
  -- exact path `bracket`-around-`mapM` would leak.
  serial <- newIORef (0 :: Int)
  base <- referenceHooks
  let failing = base
        { hookCreate = do
            n <- atomicModifyIORef' serial (\c -> (c + 1, c + 1))
            if n == 3 then fail "boom-create" else hookCreate base
        }
  ma <- newMutexAdapter failing
  r <- try (withInitLocks ma 4 (pure ())) :: IO (Either SomeException ())
  case r of
    Left _ -> pure ()
    Right _ -> fail "setup failure must propagate"
  counts <- adapterCounts ma
  assertEqual "created before failure" 2 (mcCreated counts)
  assertEqual "partial destroys exactly once" 2 (mcDestroyed counts)
  live <- adapterLive ma
  assertEqual "none live after setup throw" 0 live
