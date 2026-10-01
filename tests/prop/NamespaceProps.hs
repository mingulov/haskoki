{- | Namespace laws: session ops never create\/destroy objects
and object ops never touch sessions — the TransitionSpec
caseNamespaces precedent generalized to all lengths 0..12 plus
constant (all-duplicates) sequences. Every side publishes on the
seeded 'seedBase' (sessions 1..3 open, objects\/handles 9..10
present, slots 0..1 seated) so success-path side effects are
observable, and the OTHER namespaces are asserted UNCHANGED vs
the base — never merely empty (the empty-model shape
faulted every non-empty session side before any assertion ran).
-}
module NamespaceProps (spec) where

import qualified Data.Map.Strict as Map
import Data.Word (Word64)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertEqual, testCase)

import Gen (genSeq, lcgNext)
import Haskoki.Attribute (AttributeType (..), AttributeValue (..))
import Haskoki.Model (Model (..), addToken, emptyModel)
import Haskoki.Operation (emptySessionOps)
import Haskoki.Outcome (DeltaOp (..), StateDelta (..))
import Haskoki.Session
  ( ActiveLogin (..)
  , SessionLogin (..)
  , TokenAuth (..)
  )
import Haskoki.Transition (publishDelta)
import Haskoki.Types
  ( ExternalHandle (..)
  , Generation (..)
  , ObjectId (..)
  , SessionId (..)
  , SlotId (..)
  )

spec :: Int -> TestTree
spec count =
  testGroup
    "namespace laws"
    [ testCase "namespaces stay separate" (caseNamespaces count)
    , testCase "namespaces over constant seqs" caseConstNamespaces
    , testCase "full namespace partition" (caseFull count)
    , testCase "unbind preserves session and token namespaces" caseUnbind
    ]

isSessionOp :: DeltaOp -> Bool
isSessionOp op = case op of
  DeltaCreateObject _ -> False
  DeltaDestroyObject _ -> False
  DeltaBindHandle _ _ -> False
  DeltaUnbindHandle _ -> False
  _ -> True

checkSeparation :: [DeltaOp] -> IO ()
checkSeparation ops = do
  let sessionOnly = [op | op <- ops, isSessionOp op]
      objectOnly = [op | op <- ops, not (isSessionOp op)]
  case publishDelta seedBase (StateDelta sessionOnly) of
    Left _ -> pure ()
    Right m -> do
      assertEqual "session ops leave objects unchanged"
        (mObjects seedBase) (mObjects m)
      assertEqual "session ops leave handles unchanged"
        (mHandles seedBase) (mHandles m)
      assertEqual "session ops leave token-auth unchanged"
        (mTokenAuth seedBase) (mTokenAuth m)
  case publishDelta seedBase (StateDelta objectOnly) of
    Left _ -> pure ()
    Right m -> do
      assertEqual "object ops leave sessions unchanged"
        (mSessions seedBase) (mSessions m)
      assertEqual "object ops leave token-auth unchanged"
        (mTokenAuth seedBase) (mTokenAuth m)

caseNamespaces :: Int -> IO ()
caseNamespaces count =
  mapM_ check [(seed, len) | seed <- seeds, len <- [0 .. 12]]
  where
    seeds :: [Word64]
    seeds = [1 .. fromIntegral count]
    check :: (Word64, Int) -> IO ()
    check (seed, len) = checkSeparation (genSeq seed len)

constOps :: [DeltaOp]
constOps =
  [ DeltaTouchSession (SessionId 1)
  , DeltaCloseSession (SessionId 1)
  , DeltaBumpGeneration (SessionId 1) (Generation 2)
  , DeltaCreateObject (ObjectId 1)
  , DeltaDestroyObject (ObjectId 1)
  , DeltaUnbindHandle (ExternalHandle 9)
  ]

caseConstNamespaces :: IO ()
caseConstNamespaces =
  mapM_ check [(op, len) | op <- constOps, len <- [0 .. 12]]
  where
    check :: (DeltaOp, Int) -> IO ()
    check (op, len) = checkSeparation (replicate len op)

-- ---------------------------------------------------------------------------
-- Full 12-constructor partition
-- ---------------------------------------------------------------------------

-- | Namespace class: object ops touch objects/handles only, session
-- ops touch sessions only, token ops touch token-auth only
-- (verified against every applyOp branch in Transition.hs).
data OpClass = OCObject | OCSession | OCToken
  deriving (Eq, Show)

opClass :: DeltaOp -> OpClass
opClass op = case op of
  DeltaCreateObject _ -> OCObject
  DeltaDestroyObject _ -> OCObject
  DeltaCreateObjectFull _ _ _ _ -> OCObject
  DeltaBindHandle _ _ -> OCObject
  DeltaBumpHandle _ -> OCObject
  DeltaUnbindHandle _ -> OCObject
  DeltaSetTokenAuth _ _ -> OCToken
  _ -> OCSession

-- | One full delta op drawn from the generator state over small id
-- spaces (covers all 12 constructors).
genOpFull :: Word64 -> (DeltaOp, Word64)
genOpFull s0 =
  let s1 = lcgNext s0
      s2 = lcgNext s1
      s3 = lcgNext s2
      pick = fromIntegral (s1 `mod` 12) :: Int
      sid = SessionId (1 + fromIntegral (s2 `mod` 3))
      sid2 = SessionId (1 + fromIntegral ((s2 `div` 3) `mod` 3))
      oid = ObjectId (1 + fromIntegral ((s2 `div` 9) `mod` 5))
      hdl = ExternalHandle (1 + fromIntegral ((s2 `div` 45) `mod` 5))
      slotV = SlotId (fromIntegral ((s2 `div` 225) `mod` 2))
      genV = Generation (1 + fromIntegral ((s2 `div` 450) `mod` 4))
      readOnly = s3 `mod` 2 == 1
      attrs =
        if s3 `div` 2 `mod` 2 == 0
          then Map.empty
          else Map.singleton AttrClass (ValULong (fromIntegral (s3 `mod` 7)))
      owner =
        if s3 `div` 4 `mod` 2 == 0
          then Nothing
          else Just sid2
      loginV = case s3 `div` 8 `mod` 3 of
        0 -> LoginPublic
        1 -> LoginUser
        _ -> LoginSO
      authV =
        TokenAuth
          (if s3 `div` 24 `mod` 2 == 0 then Nothing else Just AuthUser)
          (if s3 `div` 48 `mod` 2 == 0 then Nothing else Just "test-user")
          (fromIntegral (s3 `div` 96 `mod` 5))
          (fromIntegral (s3 `div` 480 `mod` 4))
          (fromIntegral (s3 `div` 1920 `mod` 4))
          (s3 `div` 7680 `mod` 2 == 1)
          (s3 `div` 15360 `mod` 2 == 1)
  in case pick of
    0 -> (DeltaTouchSession sid, s3)
    1 -> (DeltaCloseSession sid, s3)
    2 -> (DeltaBumpGeneration sid genV, s3)
    3 -> (DeltaCreateObject oid, s3)
    4 -> (DeltaDestroyObject oid, s3)
    5 -> (DeltaCreateObjectFull oid attrs owner slotV, s3)
    6 -> (DeltaBindHandle hdl oid, s3)
    7 -> (DeltaBumpHandle hdl, s3)
    8 -> (DeltaOpenSession sid slotV readOnly, s3)
    9 -> (DeltaSetSessionLogin sid loginV, s3)
    10 -> (DeltaSetTokenAuth slotV authV, s3)
    _ -> (DeltaSetSessionOps sid emptySessionOps, s3)

-- | A deterministic full op sequence of the requested length.
genSeqFull :: Word64 -> Int -> [DeltaOp]
genSeqFull seed n = go seed n []
  where
    go :: Word64 -> Int -> [DeltaOp] -> [DeltaOp]
    go _ 0 acc = reverse acc
    go s k acc = let (op, s') = genOpFull s in go s' (k - 1) (op : acc)

-- | Model seating slot 0, so token ops can succeed (on the empty
-- model they fault on the unknown slot and the law would be
-- vacuous).
tokenModel :: Model
tokenModel = addToken emptyModel (SlotId 0)

-- | The seeded base every namespace side publishes on:
-- slots 0..1 seated, sessions 1..3 pre-opened via OpenSession on
-- slot 0, objects\/handles 9..10 present. Generator ids live in
-- 1..5 (sessions 1..3), so the seeded objects\/handles sit outside
-- the generated range: creates can still succeed while the base
-- already holds observable other-namespace state. A seed failure
-- is a loud construction error, never a silent pass.
seedBase :: Model
seedBase = case publishDelta seated (StateDelta seedOps) of
  Left fault -> error ("seedBase construction failed: " ++ show fault)
  Right m -> m
  where
    seated = addToken tokenModel (SlotId 1)
    seedOps =
      [ DeltaOpenSession (SessionId 1) (SlotId 0) False
      , DeltaOpenSession (SessionId 2) (SlotId 0) False
      , DeltaOpenSession (SessionId 3) (SlotId 0) False
      , DeltaCreateObjectFull (ObjectId 9) Map.empty Nothing (SlotId 0)
      , DeltaCreateObjectFull (ObjectId 10) Map.empty Nothing (SlotId 0)
      , DeltaBindHandle (ExternalHandle 9) (ObjectId 9)
      , DeltaBindHandle (ExternalHandle 10) (ObjectId 10)
      ]

-- | One representative per full constructor.
constOpsFull :: [DeltaOp]
constOpsFull =
  [ DeltaTouchSession (SessionId 1)
  , DeltaCloseSession (SessionId 1)
  , DeltaBumpGeneration (SessionId 1) (Generation 2)
  , DeltaCreateObject (ObjectId 1)
  , DeltaDestroyObject (ObjectId 1)
  , DeltaCreateObjectFull (ObjectId 1) Map.empty Nothing (SlotId 0)
  , DeltaBindHandle (ExternalHandle 1) (ObjectId 1)
  , DeltaBumpHandle (ExternalHandle 1)
  , DeltaUnbindHandle (ExternalHandle 9)
  , DeltaOpenSession (SessionId 1) (SlotId 0) False
  , DeltaSetSessionLogin (SessionId 1) LoginUser
  , DeltaSetTokenAuth (SlotId 0) tokenAuth0
  , DeltaSetSessionOps (SessionId 1) emptySessionOps
  ]
  where
    tokenAuth0 :: TokenAuth
    tokenAuth0 = TokenAuth (Just AuthUser) (Just "test-user") 1 0 0 False False

-- | The three separations on the seeded base: object-only leaves
-- sessions+token-auth UNCHANGED; session-only leaves
-- objects+handles+token-auth UNCHANGED; token-only leaves
-- sessions+objects+handles UNCHANGED. A failing side passes
-- (fault atomicity is the delta law's domain) — but
-- on the seeded base every class has succeeding sides, so the
-- assertions execute (no vacuous arms).
checkPartition :: [DeltaOp] -> IO ()
checkPartition ops = do
  let objectOnly = [op | op <- ops, opClass op == OCObject]
      sessionOnly = [op | op <- ops, opClass op == OCSession]
      tokenOnly = [op | op <- ops, opClass op == OCToken]
  case publishDelta seedBase (StateDelta objectOnly) of
    Left _ -> pure ()
    Right m -> do
      assertEqual "object ops leave sessions unchanged"
        (mSessions seedBase) (mSessions m)
      assertEqual "object ops leave token-auth unchanged"
        (mTokenAuth seedBase) (mTokenAuth m)
  case publishDelta seedBase (StateDelta sessionOnly) of
    Left _ -> pure ()
    Right m -> do
      assertEqual "session ops leave objects unchanged"
        (mObjects seedBase) (mObjects m)
      assertEqual "session ops leave handles unchanged"
        (mHandles seedBase) (mHandles m)
      assertEqual "session ops leave token-auth unchanged"
        (mTokenAuth seedBase) (mTokenAuth m)
  case publishDelta seedBase (StateDelta tokenOnly) of
    Left _ -> pure ()
    Right m -> do
      assertEqual "token ops leave sessions unchanged"
        (mSessions seedBase) (mSessions m)
      assertEqual "token ops leave objects unchanged"
        (mObjects seedBase) (mObjects m)
      assertEqual "token ops leave handles unchanged"
        (mHandles seedBase) (mHandles m)

caseFull :: Int -> IO ()
caseFull count = do
  mapM_ checkGen [(seed, len) | seed <- seeds, len <- [0 .. 12]]
  mapM_ checkConst [(op, len) | op <- constOpsFull, len <- [0 .. 12]]
  where
    seeds :: [Word64]
    seeds = [1 .. fromIntegral count]
    checkGen :: (Word64, Int) -> IO ()
    checkGen (seed, len) = checkPartition (genSeqFull seed len)
    checkConst :: (DeltaOp, Int) -> IO ()
    checkConst (op, len) = checkPartition (replicate len op)

-- Keep the original LCG and all of its seeds/traces intact. These named
-- success/failure traces add permanent retirement without diluting that corpus.
caseUnbind :: IO ()
caseUnbind = mapM_ check
  [ [DeltaUnbindHandle (ExternalHandle 9)]
  , [DeltaUnbindHandle (ExternalHandle 9), DeltaUnbindHandle (ExternalHandle 9)]
  , [DeltaUnbindHandle (ExternalHandle 9), DeltaBindHandle (ExternalHandle 11) (ObjectId 9)]
  , [DeltaUnbindHandle (ExternalHandle 9), DeltaDestroyObject (ObjectId 404)]
  ]
  where
    check ops = do
      checkSeparation ops
      checkPartition ops
      case publishDelta seedBase (StateDelta ops) of
        Left _ -> pure ()
        Right m -> do
          assertEqual "old binding deleted" Nothing (Map.lookup (ExternalHandle 9) (mHandles m))
          assertEqual "parked objects retained" (mObjects seedBase) (mObjects m)
