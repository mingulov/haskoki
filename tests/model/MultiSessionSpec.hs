{- | Multi-session reservation proofs.

Closing a session invalidates its reservations (through the runtime
'checkReservation' seam); closing an UNRELATED session invalidates
nothing (reservations are recorded narrowly).

Key-mutation contract (H1 decision, pinned below): an effect runner
observes key material as of effect START — the snapshot its resolver
closes over ('stdResolver') or the owned bytes the job already holds.
A key destroyed or revoked mid-flight does not fail the in-flight
effect; later calls (fresh plans) observe the destruction or
revocation. The four blocked-runner cases prove both halves: the
runner acquires the bound key's bytes before blocking, the mutation
lands in the model AND the key store mid-flight, the in-flight
delivery still carries the pre-mutation bytes, and a fresh sign init
on the second session refuses after destruction or a permitted-use
change while still admitting after an unrelated label change or a
change to a different key.
-}
module MultiSessionSpec (spec) where

import Control.Concurrent (forkIO, newEmptyMVar, putMVar, takeMVar)
import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import Data.IORef (IORef, modifyIORef', newIORef, readIORef, writeIORef)
import Data.List (isInfixOf)
import qualified Data.Map.Strict as Map
import Data.Word (Word64)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertBool, assertEqual, assertFailure, testCase)

import Haskoki.Attribute (AttributeType (..), AttributeValue (..))
import Haskoki.Model (SessionState (..), lookupSession)
import Haskoki.Operation (CryptoEffect (..), CryptoResult (..))
import Haskoki.Operation.Codec (encodeInitInput)
import Haskoki.Outcome
  ( DeltaOp (..)
  , EffectRequest (..)
  , PlanResult (..)
  , PreparedCommit (..)
  , Rejection (..)
  , Reservation (..)
  , RevisionDep (..)
  , StateDelta (..)
  )
import Haskoki.Registry (MechanismId (..), Operation (..))
import Haskoki.Request
  ( DecodedRequest (..)
  , FunctionId (..)
  , OutputIntent (..)
  , OutputRegion (..)
  , Request (..)
  )
import Haskoki.Rules (defaultRules)
import Haskoki.Runtime.Async
  ( AsyncWork (..)
  , CompleteOutcome (..)
  , Completion (..)
  , Delivery (..)
  , JobFunction (..)
  , JobRequest (..)
  , PollOutcome (..)
  , completeJob
  , enableAsyncSession
  , encodeCompletion
  , newAsyncTable
  , pollJob
  , startJob
  )
import Haskoki.Runtime.Lifecycle
  ( Env
  , checkReservation
  , newEnv
  , publish
  , seatToken
  , snapshotModel
  )
import Haskoki.Transition (planCall, planDecoded)
import Haskoki.Types
  ( ExternalHandle (..)
  , ObjectId (..)
  , Pkcs11Version (..)
  , ReturnCode (..)
  , SessionId (..)
  , SlotId (..)
  )

spec :: TestTree
spec = testGroup "Multi-session reservations"
  [ testCase "session close invalidates its reservations" testCloseInvalidates
  , testCase "unrelated close invalidates nothing" testNarrowness
  , testCase "event waiter tests are sleep-free" caseNoSleeps
  , testCase "key destruction meets start-time validity"
      (caseKeyMutation MutDestroy)
  , testCase "permitted-use change meets start-time validity"
      (caseKeyMutation MutUsage)
  , testCase "unrelated label change stays invisible"
      (caseKeyMutation MutLabel)
  , testCase "different-key change stays invisible"
      (caseKeyMutation MutOtherKey)
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

-- ---------------------------------------------------------------------------
-- Key-mutation contract: start-time validity, observed destruction
-- ---------------------------------------------------------------------------

-- | The mid-flight key mutation each variant lands.
data KeyMutation
  = MutDestroy
  | MutUsage
  | MutLabel
  | MutOtherKey
  deriving (Eq, Show)

sidA, sidB :: SessionId
sidA = SessionId 1
sidB = SessionId 2

slot0 :: SlotId
slot0 = SlotId 0

keyOid1, keyOid2 :: ObjectId
keyOid1 = ObjectId 10
keyOid2 = ObjectId 11

keyHandle1, keyHandle2 :: ExternalHandle
keyHandle1 = ExternalHandle 70
keyHandle2 = ExternalHandle 71

hmacMech :: MechanismId
hmacMech = MechanismId 0x251

-- | The two keys' material, as the key store holds it: the blocked
-- runner acquires these bytes at effect start, and the delivery
-- must carry them even after the store loses the key.
matKey1, matKey2 :: ByteString
matKey1 = BS.replicate 20 0x0b
matKey2 = BS.replicate 20 0x0d

-- | Token sign-key attributes: public, signing, HMAC-sized material.
-- Usage permission comes from the OBJECT ('policyFromObject'), so a
-- later 'AttrSign' flip changes what fresh inits admit.
signKeyAttrs :: [(AttributeType, AttributeValue)]
signKeyAttrs =
  [ (AttrClass, ValULong 4)
  , (AttrToken, ValBool True)
  , (AttrPrivate, ValBool False)
  , (AttrSign, ValBool True)
  , (AttrValue, ValBytes matKey1)
  ]

-- | The key object one planned effect binds, if it binds one.
effectKey :: CryptoEffect -> Maybe ObjectId
effectKey (FxSign _ key _ _) = key
effectKey _ = Nothing

-- | Publish a delta or fail the test.
expectPublish :: Env -> StateDelta -> IO ()
expectPublish env delta = do
  r <- publish env delta
  case r of
    Left fault -> assertFailure ("publish fault: " ++ show fault)
    Right () -> pure ()

-- | Publish an 'Immediate' plan's delta or fail the test.
expectImmediate :: Env -> String -> PlanResult -> IO PreparedCommit
expectImmediate env ctx pr = case pr of
  Immediate pc -> expectPublish env (pcDelta pc) >> pure pc
  other -> assertFailure (ctx ++ " is not Immediate: " ++ show other)

-- | Open two read-write sessions and two token sign keys.
setupTwoSessions :: IO Env
setupTwoSessions = do
  env <- newEnv defaultRules
  eSeat <- seatToken env slot0
  case eSeat of
    Left deny -> assertFailure ("seat refused: " ++ show deny)
    Right () -> pure ()
  expectPublish env (StateDelta
    [ DeltaOpenSession sidA slot0 False
    , DeltaOpenSession sidB slot0 False
    , DeltaCreateObjectFull keyOid1 (Map.fromList signKeyAttrs) Nothing slot0
    , DeltaBindHandle keyHandle1 keyOid1
    , DeltaCreateObjectFull keyOid2 (Map.fromList signKeyAttrs) Nothing slot0
    , DeltaBindHandle keyHandle2 keyOid2
    ])
  pure env

-- | A session-scoped request skeleton.
mkReq :: FunctionId -> SessionId -> Maybe ExternalHandle -> ByteString -> Request
mkReq fid sid mh input = Request
  { reqVersion = Pkcs11_3_2
  , reqFunction = fid
  , reqSession = Just sid
  , reqHandle = mh
  , reqInput = input
  , reqRegions = []
  }

-- | Initialize a sign operation on a session and publish the commit.
initSignOn :: Env -> SessionId -> ExternalHandle -> IO ()
initSignOn env sid h = do
  m <- snapshotModel env
  let req = mkReq F_SignInit sid (Just h)
        (encodeInitInput hmacMech [OpSign] False BS.empty)
  _ <- expectImmediate env "sign init" (planCall defaultRules m req)
  pure ()

-- | Plan a sign one-shot on a session; the plan must execute.
planSignShot :: Env -> SessionId -> IO (Reservation, CryptoEffect)
planSignShot env sid = do
  m <- snapshotModel env
  let req = (mkReq F_Sign sid Nothing "hello")
        { reqRegions = [RegionBytes "sig" (IntentBuffer 64)] }
  case planCall defaultRules m req of
    Execute res (EffectCrypto fx) -> pure (res, fx)
    other -> assertFailure ("sign one-shot did not execute: " ++ show other)

-- | Land one key mutation through session B, planned and published
-- against the model and mirrored into the key store a resolver
-- would read: destruction and revocation withdraw the key (a
-- revoked key is modeled as unresolvable, so the test is
-- sensitive to acquisition timing — resolving after the
-- handshake would find nothing); label and other-key changes
-- leave the first key's material alone.
mutateViaB :: Env -> KeyMutation -> IORef (Map.Map ObjectId ByteString) -> IO ()
mutateViaB env mut store = do
  m <- snapshotModel env
  let pr = case mut of
        MutDestroy ->
          planCall defaultRules m (mkReq F_DestroyObject sidB (Just keyHandle1) BS.empty)
        MutUsage ->
          planDecoded defaultRules m
            (DRSetAttributeValue sidB keyHandle1 [(AttrSign, ValBool False)])
        MutLabel ->
          planDecoded defaultRules m
            (DRSetAttributeValue sidB keyHandle1 [(AttrLabel, ValBytes "renamed")])
        MutOtherKey ->
          planDecoded defaultRules m
            (DRSetAttributeValue sidB keyHandle2 [(AttrLabel, ValBytes "other")])
  _ <- expectImmediate env ("mutation " ++ show mut) pr
  modifyIORef' store $ case mut of
    MutDestroy -> Map.delete keyOid1
    MutUsage -> Map.delete keyOid1
    MutLabel -> id
    MutOtherKey -> Map.delete keyOid2

-- | A fresh sign init on session B after the mutation: destruction
-- and revocation refuse typed; unrelated changes still admit.
observeViaB :: Env -> KeyMutation -> IO ()
observeViaB env mut = do
  m <- snapshotModel env
  let req = mkReq F_SignInit sidB (Just keyHandle1)
        (encodeInitInput hmacMech [OpSign] False BS.empty)
  case (mut, planCall defaultRules m req) of
    (MutDestroy, Reject rej) ->
      assertEqual "destroyed key refuses" CKR_OBJECT_HANDLE_INVALID (rejCode rej)
    (MutUsage, Reject rej) ->
      assertEqual "revoked use refuses" CKR_KEY_FUNCTION_NOT_PERMITTED (rejCode rej)
    (MutLabel, Immediate pc) ->
      expectPublish env (pcDelta pc)
    (MutOtherKey, Immediate pc) ->
      expectPublish env (pcDelta pc)
    (_, other) ->
      assertFailure ("unexpected fresh-init plan for " ++ show mut ++ ": " ++ show other)

-- | One blocked-runner variant: session A submits a real planned sign
-- job whose runner acquires the bound key's bytes from the key
-- store at effect START and then blocks; the mutation lands in the
-- model and the store mid-flight through session B; the runner is
-- released and the delivery must still carry the pre-mutation
-- bytes (start-time validity), while a fresh call on B observes
-- the mutation. Handshakes only — no sleeps.
caseKeyMutation :: KeyMutation -> IO ()
caseKeyMutation mut = do
  env <- setupTwoSessions
  initSignOn env sidA keyHandle1
  (res, fx) <- planSignShot env sidA
  table <- newAsyncTable 8
  enableAsyncSession table sidA
  started <- startJob table JobRequest
    { jrSession = sidA
    , jrFunction = JobSign
    , jrWork = WorkCall res (EffectCrypto fx)
    , jrTicks = 1
    , jrCapacity = 64
    }
  jid <- case started of
    Left deny -> assertFailure ("coherent submit refused: " ++ show deny)
    Right j -> pure j
  gate <- newEmptyMVar
  invoked <- newEmptyMVar
  pollBox <- newEmptyMVar
  keyStore <- newIORef (Map.fromList [(keyOid1, matKey1), (keyOid2, matKey2)])
  seen <- newIORef (Nothing :: Maybe (CryptoEffect, ByteString))
  writes <- newIORef ([] :: [ByteString])
  needed <- newIORef ([] :: [Word64])
  let run effect = do
        -- Acquire-then-block: the owned key material is fixed at
        -- effect START, before the handshake; whatever session B
        -- does next cannot change what this invocation holds. A
        -- runner that resolved after unblocking would find the
        -- destroyed or revoked key gone.
        store <- readIORef keyStore
        mat <- case effectKey effect of
          Just oid -> case Map.lookup oid store of
            Just m -> pure m
            Nothing -> assertFailure "key withdrawn before effect start"
          Nothing -> assertFailure "planned effect binds no key"
        writeIORef seen (Just (effect, mat))
        putMVar invoked ()
        takeMVar gate
        pure (GotBytes mat)
      del = Delivery
        { dCapacity = 64
        , dWrite = \bs -> do
            prior <- readIORef writes
            writeIORef writes (prior ++ [bs])
        , dReportNeeded = \n -> do
            prior <- readIORef needed
            writeIORef needed (prior ++ [n])
        }
  _ <- forkIO (pollJob run env table JobSign jid >>= putMVar pollBox)
  takeMVar invoked
  mutateViaB env mut keyStore
  held <- checkReservation env res
  assertEqual "reservation survives the key mutation" Nothing held
  -- The mutation really landed in the store before release (the
  -- destroy/revoke variants would starve a late resolver).
  storeAfter <- readIORef keyStore
  case mut of
    MutDestroy ->
      assertBool "destroyed key left the store" (Map.notMember keyOid1 storeAfter)
    MutUsage ->
      assertBool "revoked key left the store" (Map.notMember keyOid1 storeAfter)
    MutLabel ->
      assertEqual "label change keeps material"
        (Just matKey1) (Map.lookup keyOid1 storeAfter)
    MutOtherKey -> do
      assertEqual "other-key change keeps material"
        (Just matKey1) (Map.lookup keyOid1 storeAfter)
      assertBool "other key left the store" (Map.notMember keyOid2 storeAfter)
  putMVar gate ()
  pollOut <- takeMVar pollBox
  assertEqual "drive lands after the mutation" PollReady pollOut
  captured <- readIORef seen
  assertEqual "runner acquired pre-mutation material" (Just (fx, matKey1)) captured
  cout <- completeJob env table JobSign jid del (\_ -> pure ())
  case cout of
    CompleteDelivered (CompBytes bs) ->
      assertEqual "delivery carries start-time bytes" matKey1 bs
    other -> assertFailure ("in-flight completion lost: " ++ show other)
  frames <- readIORef writes
  assertEqual "exact delivery frame" [encodeCompletion (CompBytes matKey1)] frames
  reports <- readIORef needed
  assertBool "no sizing report on delivery" (null reports)
  observeViaB env mut

-- | Unwrap a 'Maybe' or fail the test with context.
expectJust :: String -> Maybe a -> IO a
expectJust ctx = maybe (assertFailure ("missing: " ++ ctx)) pure
