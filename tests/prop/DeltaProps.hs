{- | Delta laws: split-application equivalence generalized to ALL
split points, all lengths 0..12, and constant (all-duplicates)
sequences — extending the TransitionSpec corpus precedent.
-}
module DeltaProps (spec) where

import Data.Word (Word64)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertEqual, testCase)

import Gen (genSeq)
import Haskoki.Model (Model, emptyModel)
import Haskoki.Outcome (DeltaOp (..), ModelFault (..), StateDelta (..))
import Haskoki.Transition (publishDelta)
import Haskoki.Types (Generation (..), ObjectId (..), SessionId (..))

spec :: Int -> TestTree
spec count =
  testGroup
    "delta laws"
    [ testCase "split equivalence all splits" (caseSplit count)
    , testCase "split equivalence constant seqs" caseConst
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
