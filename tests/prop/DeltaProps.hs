{- | Delta laws: split-application equivalence generalized to ALL
split points, all lengths 0..12, and constant (all-duplicates)
sequences — extending the TransitionSpec corpus precedent.
-}
module DeltaProps (spec) where

import Data.Word (Word64)
import qualified Data.Map.Strict as Map
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertBool, assertEqual, assertFailure, testCase)
import Test.Tasty.QuickCheck (Property, forAllShrink)

import Gen
  ( constructorHits
  , freshSeeds
  , genDeltaSeq
  , genSeq
  , genSeqFull14
  , hitSummary
  , propSeedOverride
  , propWith
  , shrinkDeltaSeq
  )
import Haskoki.Attribute (AttributeType (..), AttributeValue (..))
import Haskoki.Model (Model (..), emptyModel)
import Haskoki.Operation (emptySessionOps)
import Haskoki.Outcome (DeltaOp (..), ModelFault (..), StateDelta (..))
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
import NamespaceProps (seedBase)

spec :: Int -> TestTree
spec count =
  testGroup
    "delta laws"
    [ testCase "split equivalence all splits" (caseSplit count)
    , testCase "split equivalence constant seqs" caseConst
    , testCase "unbind split and fault traces" caseUnbind
    , testCase "split equivalence from populated state"
        (caseSplitSeeded count)
    , testCase "split equivalence over lifecycle traces" caseLifecycle
    , testCase "seeded corpus hits every constructor"
        (caseSeededHits count)
    , propWith Nothing "seeded split law" 401 count pSplitSeeded
    ]

-- | Publishing a++b at once equals publishing a then b, for EVERY
-- split point of every corpus sequence.
caseSplit :: Int -> IO ()
caseSplit count = do
  seedOv <- propSeedOverride
  mapM_ check [(seed, len) | seed <- freshSeeds seedOv count, len <- [0 .. 12]]
  where
    check :: (Word64, Int) -> IO ()
    check (seed, len) = do
      let ops = genSeq seed len
          whole = publishDelta emptyModel (StateDelta ops)
      mapM_ (checkK ops whole seed len) [0 .. len]
    checkK :: [DeltaOp] -> Either ModelFault Model -> Word64 -> Int -> Int -> IO ()
    checkK ops whole seed len k = do
      let (a, b) = splitAt k ops
          split =
            publishDelta emptyModel (StateDelta a) >>= \m ->
              publishDelta m (StateDelta b)
      assertEqual
        ("split seed=" ++ show seed ++ " len=" ++ show len
          ++ " k=" ++ show k)
        whole
        split

-- | One representative op per DeltaOp constructor.
constOps :: [DeltaOp]
constOps =
  [ DeltaTouchSession (SessionId 1)
  , DeltaCloseSession (SessionId 1)
  , DeltaBumpGeneration (SessionId 1) (Generation 2)
  , DeltaCreateObject (ObjectId 1)
  , DeltaDestroyObject (ObjectId 1)
  , DeltaUnbindHandle (ExternalHandle 1)
  ]

-- | The split law over constant sequences (incl. empty, single, and
-- sequences that fault — both sides must agree exactly).
caseConst :: IO ()
caseConst = mapM_ check [(op, len) | op <- constOps, len <- [0 .. 12]]
  where
    check :: (DeltaOp, Int) -> IO ()
    check (op, len) = do
      let ops = replicate len op
          whole = publishDelta emptyModel (StateDelta ops)
      mapM_ (checkK ops whole op len) [0 .. len]
    checkK :: [DeltaOp] -> Either ModelFault Model -> DeltaOp -> Int -> Int -> IO ()
    checkK ops whole op len k = do
      let (a, b) = splitAt k ops
          split =
            publishDelta emptyModel (StateDelta a) >>= \m ->
              publishDelta m (StateDelta b)
      assertEqual
        ("const op=" ++ show op ++ " len=" ++ show len
          ++ " k=" ++ show k)
        whole
        split

-- Explicit unbind traces supplement, rather than reseed or change, genSeq.
-- Include successful deletion, repeated missing deletion, and a later fault.
caseUnbind :: IO ()
caseUnbind = mapM_ check
  [ [DeltaUnbindHandle h]
  , [DeltaCreateObject oid, DeltaBindHandle h oid, DeltaUnbindHandle h]
  , [DeltaCreateObject oid, DeltaBindHandle h oid, DeltaUnbindHandle h, DeltaUnbindHandle h]
  , [DeltaCreateObject oid, DeltaBindHandle h oid, DeltaUnbindHandle h, DeltaDestroyObject (ObjectId 99)]
  ]
  where
    h = ExternalHandle 7
    oid = ObjectId 9
    check ops = do
      let whole = publishDelta emptyModel (StateDelta ops)
      mapM_ (\k -> let (a,b) = splitAt k ops in
        assertEqual ("unbind split " ++ show k) whole
          (publishDelta emptyModel (StateDelta a) >>= \m -> publishDelta m (StateDelta b))) [0 .. length ops]
      case whole of
        Left _ -> pure ()
        Right m -> assertEqual "permanent binding removal" Nothing (Map.lookup h (mHandles m))

-- ---------------------------------------------------------------------------
-- Populated-state composition + lifecycle traces + hits
-- ---------------------------------------------------------------------------

-- | The split law over full-constructor sequences published on the
-- seeded base (sessions open, objects and handles parked): every
-- split point must agree exactly, faults included.
caseSplitSeeded :: Int -> IO ()
caseSplitSeeded count = do
  seedOv <- propSeedOverride
  mapM_ check [(seed, len) | seed <- freshSeeds seedOv count, len <- [0 .. 12]]
  where
    check :: (Word64, Int) -> IO ()
    check (seed, len) = do
      let ops = genSeqFull14 seed len
          whole = publishDelta seedBase (StateDelta ops)
      mapM_ (checkK ops whole seed len) [0 .. len]
    checkK :: [DeltaOp] -> Either ModelFault Model -> Word64 -> Int -> Int -> IO ()
    checkK ops whole seed len k = do
      let (a, b) = splitAt k ops
          split =
            publishDelta seedBase (StateDelta a) >>= \m ->
              publishDelta m (StateDelta b)
      assertEqual
        ("seeded split seed=" ++ show seed ++ " len=" ++ show len
          ++ " k=" ++ show k)
        whole
        split

-- | Representative token auth for the token lifecycle trace.
tokenAuthWitness :: TokenAuth
tokenAuthWitness =
  TokenAuth (Just AuthUser) (Just "witness-user") 1 0 0 False False

-- | Deterministic lifecycles over fresh ids: a session login
-- lifecycle, an object attribute lifecycle
-- (create/update/bind/destroy), and a token-auth lifecycle. Each
-- trace is designed to succeed end to end; a fault is a loud
-- regression, never a skip.
loginTrace :: [DeltaOp]
loginTrace =
  [ DeltaOpenSession (SessionId 4) (SlotId 0) False
  , DeltaSetSessionLogin (SessionId 4) LoginUser
  , DeltaSetSessionOps (SessionId 4) emptySessionOps
  , DeltaTouchSession (SessionId 4)
  , DeltaBumpGeneration (SessionId 4) (Generation 2)
  , DeltaCloseSession (SessionId 4)
  ]

attrTrace :: [DeltaOp]
attrTrace =
  [ DeltaCreateObjectFull (ObjectId 11) Map.empty Nothing (SlotId 0)
  , DeltaSetAttributes (ObjectId 11)
      (Map.singleton AttrClass (ValULong 1))
  , DeltaBindHandle (ExternalHandle 11) (ObjectId 11)
  , DeltaBumpHandle (ExternalHandle 11)
  , DeltaSetAttributes (ObjectId 11)
      (Map.singleton AttrToken (ValBool True))
  , DeltaUnbindHandle (ExternalHandle 11)
  , DeltaDestroyObject (ObjectId 11)
  ]

tokenTrace :: [DeltaOp]
tokenTrace =
  [ DeltaSetTokenAuth (SlotId 1) tokenAuthWitness
  , DeltaOpenSession (SessionId 5) (SlotId 1) True
  , DeltaCloseSession (SessionId 5)
  ]

-- | Split equivalence at every point of each lifecycle trace,
-- plus each trace's end-state effects.
caseLifecycle :: IO ()
caseLifecycle = do
  checkTrace "login" loginTrace $ \m ->
    assertEqual "login retires its session" True
      (not (Map.member (SessionId 4) (mSessions m)))
  checkTrace "attr" attrTrace $ \m -> do
    assertEqual "attr retires its object" True
      (not (Map.member (ObjectId 11) (mObjects m)))
    assertEqual "attr retires its handle" True
      (not (Map.member (ExternalHandle 11) (mHandles m)))
  checkTrace "token" tokenTrace $ \m -> do
    assertEqual "token retires its session" True
      (not (Map.member (SessionId 5) (mSessions m)))
    assertEqual "token pins slot auth" (Just tokenAuthWitness)
      (Map.lookup (SlotId 1) (mTokenAuth m))
  where
    checkTrace :: String -> [DeltaOp] -> (Model -> IO ()) -> IO ()
    checkTrace label ops effects = do
      let whole = publishDelta seedBase (StateDelta ops)
      mapM_ (\k -> let (a, b) = splitAt k ops in
        assertEqual (label ++ " split " ++ show k) whole
          (publishDelta seedBase (StateDelta a) >>= \m ->
            publishDelta m (StateDelta b))) [0 .. length ops]
      case whole of
        Left fault ->
          assertFailure (label ++ " trace faulted: " ++ show fault)
        Right m -> effects m

-- | Hit obligations over the seeded generated corpus: all 14
-- constructors appear, so the populated-state split law exercises
-- every op shape. The corpus size is fixed (PROP_SEED shifts it,
-- never shrinks it) so tiny case counts cannot starve an arm.
caseSeededHits :: Int -> IO ()
caseSeededHits _count = do
  seedOv <- propSeedOverride
  let corpus =
        [ op
        | seed <- freshSeeds seedOv 50
        , len <- [0 .. 12]
        , op <- genSeqFull14 seed len
        ]
      hits = constructorHits corpus
  putStrLn ("delta seeded corpus: " ++ hitSummary hits)
  assertEqual "seeded corpus covers all constructors" 14 (Map.size hits)
  assertBool "every constructor hit" (all (>= 1) (Map.elems hits))

-- | The seeded split law as a shrinking QuickCheck property:
-- counterexamples minimize through dependency-preserving
-- single removals. Replay-fixed (the deterministic loops above
-- carry fresh-seed exploration).
pSplitSeeded :: Property
pSplitSeeded = forAllShrink genDeltaSeq shrinkDeltaSeq $ \ops ->
  let whole = publishDelta seedBase (StateDelta ops)
      splits =
        [ publishDelta seedBase (StateDelta a) >>= \m ->
            publishDelta m (StateDelta b)
        | k <- [0 .. length ops]
        , let (a, b) = splitAt k ops
        ]
  in all (== whole) splits
