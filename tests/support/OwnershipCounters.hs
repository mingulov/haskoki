-- | Ownership counter lines for the private-RTS matrix
-- (scripts/test-ownership-matrix.sh). A test is wrapped in 'counted'
-- with its matrix case id and a distinct label; every
-- 'assertZero' / 'assertCensusZero' inside it prints one
-- @OWNERSHIP-COUNTERS case=<id> test=<label> k=v@ line and then
-- asserts the value is 0. Lines print only when
-- HASKOKI_OWNERSHIP_COUNTERS=1 (precedent: DURABILITY lines).
--
-- The tag rides the test thread's own GHC label (no process
-- global), so parallel tasty workers (-j N) never share a tag; an
-- assertion outside 'counted' (or on a thread the test forked)
-- still asserts, it just prints nothing.
module OwnershipCounters
  ( counted
  , emitCounters
  , assertZero
  , assertCensusZero
  ) where

import Control.Concurrent (myThreadId)
import Control.Exception (finally)
import Control.Monad (when)
import Data.List (stripPrefix)
import GHC.Conc (labelThread)
import GHC.Conc.Sync (threadLabel)
import System.Environment (lookupEnv)
import System.IO (hFlush, stdout)
import Test.Tasty.HUnit (assertEqual)

-- | Thread-label prefix that marks a counted test; the case id and
-- the test label follow, tab-separated (neither contains a tab).
tagPrefix :: String
tagPrefix = "haskoki-ownership-counters\t"

-- | Run a test body under (case id, test label). The thread's
-- previous label comes back afterwards.
counted :: String -> String -> IO a -> IO a
counted c t act = do
  me <- myThreadId
  before <- threadLabel me
  labelThread me (tagPrefix ++ c ++ "\t" ++ t)
  act `finally` labelThread me (maybe "" id before)

-- | The (case id, test label) of the current thread, if counted.
currentTag :: IO (Maybe (String, String))
currentTag = do
  me <- myThreadId
  lbl <- threadLabel me
  pure $ case lbl >>= stripPrefix tagPrefix of
    Just rest -> case break (== '\t') rest of
      (c, '\t' : t) -> Just (c, t)
      _ -> Nothing
    Nothing -> Nothing

-- | Print one counter line for the current test (no-op unless
-- HASKOKI_OWNERSHIP_COUNTERS=1 and the thread is under 'counted').
-- One flushed 'putStr' so parallel threads interleave whole lines.
emitCounters :: [(String, String)] -> IO ()
emitCounters kvs = do
  on <- lookupEnv "HASKOKI_OWNERSHIP_COUNTERS"
  when (on == Just "1") $ do
    tag <- currentTag
    case tag of
      Nothing -> pure ()
      Just (c, t) -> do
        putStr ("OWNERSHIP-COUNTERS case=" ++ c ++ " test=" ++ t
                ++ concatMap (\(k, v) -> " " ++ k ++ "=" ++ v) kvs ++ "\n")
        hFlush stdout

-- | Print @key=<v>@, then assert the value is 0.
assertZero :: (Integral a, Show a) => String -> String -> a -> IO ()
assertZero key label v = do
  emitCounters [(key, show v)]
  assertEqual label 0 v

-- | Same for a (live, tombstones, next-id) census that must be all 0.
assertCensusZero :: (Integral a, Show a) => String -> (a, a, a) -> IO ()
assertCensusZero label c@(a, b, n) = do
  emitCounters [("census_live", show a), ("census_tomb", show b), ("census_next", show n)]
  assertEqual label (0, 0, 0) c
