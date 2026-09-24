{- | Multi-session reservation proofs.

Closing a session invalidates its reservations (through the runtime
'checkReservation' seam); closing an UNRELATED session invalidates
nothing (reservations are recorded narrowly).
-}
module MultiSessionSpec (spec) where

import Data.List (isInfixOf)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertEqual, assertFailure, testCase)

import Haskoki.Model (SessionState (..), lookupSession)
import Haskoki.Outcome
  ( DeltaOp (..)
  , Reservation (..)
  , RevisionDep (..)
  , StateDelta (..)
  )
import Haskoki.Rules (defaultRules)
import Haskoki.Runtime.Lifecycle
  ( checkReservation
  , newEnv
  , publish
  , seatToken
  , snapshotModel
  )
import Haskoki.Types (SessionId (..), SlotId (..))

spec :: TestTree
spec = testGroup "Multi-session reservations"
  [ testCase "session close invalidates its reservations" testCloseInvalidates
  , testCase "unrelated close invalidates nothing" testNarrowness
  , testCase "event waiter tests are sleep-free" caseNoSleeps
  ]

-- | A reservation pinned to an open session holds; after the session
-- closes, 'checkReservation' reports the stale 'DepSession'.
testCloseInvalidates :: IO ()
testCloseInvalidates = do
  env <- newEnv defaultRules
  eSeat <- seatToken env (SlotId 0)
  case eSeat of
    Left deny -> assertFailure ("seat refused: " ++ show deny)
    Right () -> pure ()
  eOpen <- publish env (StateDelta [DeltaOpenSession (SessionId 1) (SlotId 0) False])
  case eOpen of
    Left fault -> assertFailure ("open failed: " ++ show fault)
    Right () -> pure ()
  m <- snapshotModel env
  st <- expectJust "session 1" (lookupSession m (SessionId 1))
  let res = Reservation "close-invalidates"
        [DepSession (SessionId 1) (ssRevision st) (ssGeneration st)]
        Nothing Nothing
  held <- checkReservation env res
  assertEqual "holds while open" Nothing held
  eClose <- publish env (StateDelta [DeltaCloseSession (SessionId 1)])
  case eClose of
    Left fault -> assertFailure ("close failed: " ++ show fault)
    Right () -> pure ()
  stale <- checkReservation env res
  case stale of
    Just (DepSession (SessionId 1) _ _) -> pure ()
    other -> assertFailure ("expected stale DepSession, got: " ++ show other)

-- | Closing session 2 leaves session 1's reservation held (and vice
-- versa): invalidation is per-session, never global.
testNarrowness :: IO ()
testNarrowness = do
  env <- newEnv defaultRules
  eSeat <- seatToken env (SlotId 0)
  case eSeat of
    Left deny -> assertFailure ("seat refused: " ++ show deny)
    Right () -> pure ()
  eOpen <- publish env (StateDelta
    [ DeltaOpenSession (SessionId 1) (SlotId 0) False
    , DeltaOpenSession (SessionId 2) (SlotId 0) False
    ])
  case eOpen of
    Left fault -> assertFailure ("open failed: " ++ show fault)
    Right () -> pure ()
  m <- snapshotModel env
  st1 <- expectJust "session 1" (lookupSession m (SessionId 1))
  st2 <- expectJust "session 2" (lookupSession m (SessionId 2))
  let res1 = Reservation "narrow-1"
        [DepSession (SessionId 1) (ssRevision st1) (ssGeneration st1)]
        Nothing Nothing
      res2 = Reservation "narrow-2"
        [DepSession (SessionId 2) (ssRevision st2) (ssGeneration st2)]
        Nothing Nothing
  eClose <- publish env (StateDelta [DeltaCloseSession (SessionId 2)])
  case eClose of
    Left fault -> assertFailure ("close failed: " ++ show fault)
    Right () -> pure ()
  held1 <- checkReservation env res1
  assertEqual "session 1 reservation survives" Nothing held1
  stale2 <- checkReservation env res2
  case stale2 of
    Just (DepSession (SessionId 2) _ _) -> pure ()
    other -> assertFailure ("expected stale DepSession 2, got: " ++ show other)

-- | The slot-event waiter cases must synchronize through deterministic
-- handshakes, never fixed 'threadDelay' sleeps (hope, not proof:
-- under load the waiter thread may not even be scheduled in 50ms).
caseNoSleeps :: IO ()
caseNoSleeps = do
  body <- readFile "tests/model/EventsSpec.hs"
  let hits =
        [n | (n, ln) <- zip [1 :: Int ..] (lines body), "threadDelay" `isInfixOf` ln]
  case hits of
    [] -> pure ()
    _ -> assertFailure ("EventsSpec still sleeps on lines: " ++ show hits)

-- | Unwrap a 'Maybe' or fail the test with context.
expectJust :: String -> Maybe a -> IO a
expectJust ctx = maybe (assertFailure ("missing: " ++ ctx)) pure
