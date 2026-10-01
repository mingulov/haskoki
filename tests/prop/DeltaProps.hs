{- | Delta laws: split-application equivalence generalized to ALL
split points, all lengths 0..12, and constant (all-duplicates)
sequences — extending the TransitionSpec corpus precedent.
-}
module DeltaProps (spec) where

import Data.Word (Word64)
import qualified Data.Map.Strict as Map
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertEqual, testCase)

import Gen (genSeq)
import Haskoki.Model (Model (..), emptyModel)
import Haskoki.Outcome (DeltaOp (..), ModelFault (..), StateDelta (..))
import Haskoki.Transition (publishDelta)
import Haskoki.Types (Generation (..), ObjectId (..), SessionId (..), ExternalHandle (..))

spec :: Int -> TestTree
spec count =
  testGroup
    "delta laws"
    [ testCase "split equivalence all splits" (caseSplit count)
    , testCase "split equivalence constant seqs" caseConst
    , testCase "unbind split and fault traces" caseUnbind
    ]

-- | Publishing a++b at once equals publishing a then b, for EVERY
-- split point of every corpus sequence.
caseSplit :: Int -> IO ()
caseSplit count =
  mapM_ check [(seed, len) | seed <- seeds, len <- [0 .. 12]]
  where
    seeds :: [Word64]
    seeds = [1 .. fromIntegral count]
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
