{- | FfiAsync Open: std open/config NULL pins and the async-kill probe.
-}
{-# LANGUAGE OverloadedStrings #-}
module FfiAsync.Open
  ( caseStdSuccess
  , caseStdBadSqlite
  , caseStdZeroSlots
  , caseStdOversize
  , caseStdNonPoison
  , caseStdAsyncSlow
  ) where


import Control.Concurrent
  ( forkIO
  , killThread
  , newEmptyMVar
  , putMVar
  , takeMVar
  , tryPutMVar
  )
import Control.Exception
  ( SomeException
  , try
  )
import Foreign.StablePtr
  ( StablePtr
  )
import System.Timeout (timeout)
import Test.Tasty.HUnit (assertBool, assertFailure)

import FfiAsync.Fixtures
import Haskoki.FFI.Standard
  ( StdAcquisition (..)
  , StdInstance (..)
  , haskokiStdClose
  , openStdInstance
  , openStdInstanceWith
  , stdAcquisition
  )
import Haskoki.Runtime.Config
  ( defaultConfig
  )


caseStdSuccess :: IO ()
caseStdSuccess = do
  sp <- openStdInstance defaultConfig
  assertBool "memory open succeeds" (not (isNull sp))
  haskokiStdClose sp

caseStdBadSqlite :: IO ()
caseStdBadSqlite = do
  sp <- openStdInstance badSqliteCfg
  assertBool "bad sqlite path is NULL" (isNull sp)

caseStdZeroSlots :: IO ()
caseStdZeroSlots = do
  sp <- openStdInstance zeroSlotCfg
  assertBool "zero-slot seating refusal is NULL" (isNull sp)

caseStdOversize :: IO ()
caseStdOversize = do
  sp <- openStdInstance oversizeCatalogCfg
  assertBool "oversize catalog refusal is NULL" (isNull sp)

caseStdNonPoison :: IO ()
caseStdNonPoison = do
  bad <- openStdInstance badSqliteCfg
  assertBool "bad open is NULL" (isNull bad)
  good <- openStdInstance defaultConfig
  assertBool "next open succeeds" (not (isNull good))
  haskokiStdClose good

-- Async injection (the kill aborts the open; previously it was
-- swallowed and the open completed)

-- | A kill delivered while the open is provably in flight: the
-- victim opens through injected acquisition steps whose backend
-- step signals @entered@ and then parks on @proceed@, so the
-- victim is blocked inside the open (past the store acquire, in
-- the restored backend step) when the single 'killThread' lands.
-- No timing margin: however late the kill arrives, the victim
-- cannot have completed the open, so the outcome is always
-- 'Left'. After the kill the main thread releases @proceed@, so
-- a missed kill (a real defect) would surface as a completed
-- open instead of a wedge.
caseStdAsyncSlow :: IO ()
caseStdAsyncSlow = do
  entered <- newEmptyMVar
  proceed <- newEmptyMVar
  outcome <- newEmptyMVar
  let sa = stdAcquisition
        { saOpenBackend = putMVar entered () >> takeMVar proceed
            >> saOpenBackend stdAcquisition
        }
  victimTid <- forkIO $ do
    r <- try $ openStdInstanceWith sa defaultConfig
    putMVar outcome (r :: Either SomeException (StablePtr StdInstance))
  mEntered <- timeout 10000000 (takeMVar entered)
  case mEntered of
    Nothing -> assertFailure "wedge detected: victim never entered the open"
    Just () -> pure ()
  -- Single kill: the victim is parked at the backend gate inside
  -- the open (it cannot proceed until released below), so this is
  -- delivered mid-open and returns (no spray, no exit race).
  killThread victimTid
  _ <- tryPutMVar proceed ()
  mOut <- timeout 10000000 (takeMVar outcome)
  case mOut of
    Nothing -> assertFailure "wedge detected: open never reported after kill"
    Just (Left _) -> pure ()
    Just (Right sp) -> do
      if isNull sp then pure () else haskokiStdClose sp
      assertFailure "async swallowed: kill mid-open did not abort the open"
