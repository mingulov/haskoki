{- | Dense-rain detach-lease wedge probe.

The @beginDetach@ take-to-handoff is masked (no window):
previously (@src/Haskoki/Runtime/Async.hs@, @restore (takeMVar ...)@
returning unmasked before the handoff recorded) it stranded
@jbLock@ under dense async-exception rain.

Shape mirrors the independent verifier's burst\/quiesce probe
(@wedge-verify.hs@ v4, same discipline, fewer
rounds for suite time): free-running victim acquire\/release loop,
30ms mixed killThread\/throwTo rain per round, spray-off timed
probes, confirm-by-elimination (triple spaced 500ms probes, then
victim termination, then a final quiet probe with no live holder).
Only victim-dead + spray-off + probe-timeout counts as a strand;
a lone timeout that recovers is transient (victim restarted).

Every wait carries a 'System.Timeout' backstop; the case always
terminates (120s overall cap).
-}
{-# LANGUAGE NumericUnderscores #-}
{-# LANGUAGE OverloadedStrings #-}
module LeaseWedgeDenseSpec (spec) where

import Control.Concurrent
  ( ThreadId
  , forkIO
  , killThread
  , newEmptyMVar
  , putMVar
  , takeMVar
  , threadDelay
  )
import Control.Exception
  ( Exception
  , SomeException
  , catch
  , mask
  , throwTo
  , try
  )
import Control.Monad (unless)
import Data.IORef (modifyIORef', newIORef, readIORef, writeIORef)
import System.Timeout (timeout)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertFailure, testCase)

import Haskoki.Operation (CryptoEffect (..))
import Haskoki.Outcome (EffectRequest (..), Reservation (..))
import Haskoki.Registry (MechanismId (..))
import Haskoki.Runtime.Async
  ( AsyncWork (..)
  , DetachLease
  , JobFunction (..)
  , JobRequest (..)
  , abortDetach
  , beginDetach
  , enableAsyncSession
  , newAsyncTable
  , startJob
  )
import Haskoki.Types (SessionId (..))

spec :: TestTree
spec = testGroup "Dense-rain detach wedge"
  [ testCase "beginDetach never strands under dense rain"
      caseDenseNeverWedges
  ]

-- | Custom fault, distinct from ThreadKilled: the rain alternates
-- the two, so the victim faces a mixed async-exception stream.
data ProbeEx = ProbeEx deriving (Show)

instance Exception ProbeEx

nRounds :: Int
nRounds = 20

rainUs :: Int
rainUs = 30_000

rainDelayUs :: Int
rainDelayUs = 1

quiesceProbeUs :: Int
quiesceProbeUs = 500_000

settleUs :: Int
settleUs = 100_000

joinUs :: Int
joinUs = 5_000_000

overallUs :: Int
overallUs = 120_000_000

caseDenseNeverWedges :: IO ()
caseDenseNeverWedges = do
  mRes <- timeout overallUs runDense
  case mRes of
    Nothing -> assertFailure "dense probe overall timeout (120s)"
    Just True -> assertFailure "CONFIRMED-STRAND under dense rain"
    Just False -> pure ()

runDense :: IO Bool
runDense = do
  table <- newAsyncTable 2048
  let sid = SessionId 1
  enableAsyncSession table sid
  ej <- startJob table JobRequest
    { jrSession = sid
    , jrFunction = JobDigest
    , jrWork = WorkCall
        (Reservation "dense-rain" [] Nothing Nothing)
        (EffectCrypto (FxDigest (MechanismId 0x250) "abc"))
    , jrTicks = 2
    , jrCapacity = 64
    }
  jid <- case ej of
    Left deny -> assertFailure ("job submit refused: " ++ show deny)
    Right j -> pure j
  completes <- newIORef (0 :: Int)
  let startVictim = do
        stopVictim <- newIORef False
        victimDone <- newEmptyMVar
        let victimLoop = mask $ \restore -> do
              let go :: IO ()
                  go = do
                    stop <- readIORef stopVictim
                    if stop
                      then putMVar victimDone ()
                      else do
                        r <- try (restore (beginDetach table jid))
                          :: IO (Either SomeException (Maybe DetachLease))
                        case r of
                          Right (Just l) -> do
                            abortDetach l
                            modifyIORef' completes (+ 1)
                          _ -> pure ()
                        go
              go `catch` \(e :: SomeException) -> do
                putStrLn ("VICTIM-ESCAPED: " ++ show e)
                putMVar victimDone ()
        tid <- forkIO victimLoop
        pure (tid, stopVictim, victimDone)
  victimVar <- startVictim >>= newIORef
  let rainLoop :: ThreadId -> Int -> IO ()
      rainLoop victimTid i = do
        (if even i then killThread victimTid else throwTo victimTid ProbeEx)
          `catch` \(_ :: SomeException) -> pure ()
        threadDelay rainDelayUs
        rainLoop victimTid (i + 1)
      probeOnce :: IO Bool
      probeOnce = do
        r <- timeout quiesceProbeUs (beginDetach table jid)
        case r of
          Nothing -> pure False
          Just Nothing -> pure True
          Just (Just l) -> abortDetach l >> pure True
      confirm :: Int -> IO Bool
      confirm n = do
        c0 <- readIORef completes
        p1 <- probeOnce
        c1 <- readIORef completes
        putStrLn ("CONFIRM r" ++ show n
          ++ " p1=" ++ show p1
          ++ " completes-delta=" ++ show (c1 - c0))
        if p1
          then pure False
          else do
            threadDelay settleUs
            p2 <- probeOnce
            c2 <- readIORef completes
            putStrLn ("CONFIRM r" ++ show n
              ++ " p2=" ++ show p2
              ++ " completes-delta=" ++ show (c2 - c1))
            if p2
              then pure False
              else do
                threadDelay settleUs
                p3 <- probeOnce
                putStrLn ("CONFIRM r" ++ show n ++ " p3=" ++ show p3)
                if p3
                  then pure False
                  else do
                    putStrLn ("CONFIRM r" ++ show n
                      ++ ": terminating victim for quiet probe")
                    (tid, stopRef, doneMv) <- readIORef victimVar
                    writeIORef stopRef True
                    j <- timeout joinUs (takeMVar doneMv)
                    case j of
                      Just () -> pure ()
                      Nothing ->
                        killThread tid
                          `catch` \(_ :: SomeException) -> pure ()
                    _ <- timeout joinUs (takeMVar doneMv)
                    threadDelay settleUs
                    p4 <- probeOnce
                    putStrLn ("CONFIRM r" ++ show n
                      ++ " p4-quiet=" ++ show p4)
                    if p4
                      then do
                        putStrLn ("ROUND " ++ show n
                          ++ ": TRANSIENT (quiet probe answered)")
                        nv <- startVictim
                        writeIORef victimVar nv
                        pure False
                      else do
                        putStrLn ("ROUND " ++ show n
                          ++ ": CONFIRMED-STRAND"
                          ++ " (victim dead, system quiet,"
                          ++ " lock still held)")
                        pure True
      loop :: Int -> IO Bool
      loop n
        | n > nRounds = do
            (tid2, stopRef2, doneMv2) <- readIORef victimVar
            writeIORef stopRef2 True
            _ <- timeout joinUs (takeMVar doneMv2)
            killThread tid2 `catch` \(_ :: SomeException) -> pure ()
            c <- readIORef completes
            putStrLn ("DENSE-RESULT: ROUNDS=" ++ show nRounds
              ++ " COMPLETES=" ++ show c ++ " ALL-CLEAN")
            pure False
        | otherwise = do
            (vtid, _, _) <- readIORef victimVar
            killerTid <- forkIO (rainLoop vtid n)
            threadDelay rainUs
            killThread killerTid `catch` \(_ :: SomeException) -> pure ()
            threadDelay 2_000
            c0 <- readIORef completes
            ok <- probeOnce
            c1 <- readIORef completes
            unless ok $ putStrLn ("ROUND " ++ show n
              ++ ": quiesce probe timed out (completes-delta="
              ++ show (c1 - c0) ++ "), confirming...")
            wedge <- if ok then pure False else confirm n
            if wedge
              then do
                c <- readIORef completes
                putStrLn ("DENSE-RESULT: ROUNDS=" ++ show n
                  ++ " COMPLETES=" ++ show c ++ " CONFIRMED-STRAND")
                pure True
              else loop (n + 1)
  loop 1
