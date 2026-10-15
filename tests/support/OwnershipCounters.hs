-- | Ownership counter lines for the private-RTS matrix
-- (scripts/test-ownership-matrix.sh). A test is wrapped in 'counted'
-- with its matrix case id and a distinct label; every
-- 'assertZero' / 'assertCensusZero' inside it prints one
-- @OWNERSHIP-COUNTERS case=<id> test=<label> k=v@ line and then
-- asserts the value is 0. Lines print only when
-- HASKOKI_OWNERSHIP_COUNTERS=1 (precedent: DURABILITY lines).
--
-- The tag is keyed by the test's own thread, so parallel tasty
-- workers (-j N) never share a tag; an assertion outside 'counted'
-- still asserts, it just prints nothing.
module OwnershipCounters
  ( counted
  , emitCounters
  , assertZero
  , assertCensusZero
  ) where

import Control.Concurrent (ThreadId, myThreadId)
import Control.Exception (finally)
import Control.Monad (when)
import Data.IORef (IORef, atomicModifyIORef', newIORef, readIORef)
import qualified Data.Map.Strict as Map
import System.Environment (lookupEnv)
import System.IO (hFlush, stdout)
import System.IO.Unsafe (unsafePerformIO)
import Test.Tasty.HUnit (assertEqual)

tags :: IORef (Map.Map ThreadId (String, String))
tags = unsafePerformIO (newIORef Map.empty)
{-# NOINLINE tags #-}

-- | Run a test body under (case id, test label).
counted :: String -> String -> IO a -> IO a
counted c t act = do
  me <- myThreadId
  atomicModifyIORef' tags (\m -> (Map.insert me (c, t) m, ()))
  act `finally` atomicModifyIORef' tags (\m -> (Map.delete me m, ()))

-- | Print one counter line for the current test (no-op unless
-- HASKOKI_OWNERSHIP_COUNTERS=1 and the thread is under 'counted').
-- One flushed 'putStr' so parallel threads interleave whole lines.
emitCounters :: [(String, String)] -> IO ()
emitCounters kvs = do
  on <- lookupEnv "HASKOKI_OWNERSHIP_COUNTERS"
  when (on == Just "1") $ do
    me <- myThreadId
    m <- readIORef tags
    case Map.lookup me m of
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
