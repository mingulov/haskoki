{- | Detach-lease wedge-window probe, behavioral half.

'caseBeginNeverWedges': 'beginDetach' is self-cleaning
("raises implies holds nothing": masked handoff, killable wait,
catch-release-rethrow) — previously it took the job lock unmasked
and read the table before handing the lease to its owner, so an
async exception landing in the take-to-handoff window stranded the
lock forever. A kill can now only clean-abort or be deferred past
the probe's own masked release, deterministically.

Probe shape (statistical but honest): a victim loops over 1000
fresh jobs; per iteration it rendezvouses (@ready@), runs one
'beginDetach' inside @try (restore ...)@, releases an acquired
lease across a MASKED gap (so a kill can never strand the probe's
own pairing — no false positives), and reports (@done@). Main
fires ONE 'killThread' per iteration and then probes the lock with
a 100ms 'beginDetach' (healthy: instant; wedged: timeout). Both
rendezvous carry a 10s 'System.Timeout' backstop ('assertFailure'
on expiry) per the no-wedge rule, and every victim-side 'MVar'
put is kill-retried, so the victim can neither die silently (the
spray failure mode) nor overrun by more than one iteration
(@ready@ fullness backpressures). Kills landing pre-take abort
cleanly (dilution, not signal); the window itself is closed,
so no iteration wedges.

Ordering discipline: 'try' sits OUTSIDE 'restore'. The reversed
order lets a kill that is already pending when the victim unmasks
escape past the handler and kill the victim outright — a probe
bug (@outcome=Just "died: thread killed"@). With
'try' outside, every delivery point is guarded and the victim
cannot die from the probe's kills.

The commit-window half is NOT runnable hook-free:
a kill between the revoke STM and the lock release orphans a
lock on an already-revoked job, which no hook-free observable
can distinguish from a clean commit (the orphan is unreachable
— the job is gone from the table). The commit fix rides with
the begin fix (same uninterruptible-handoff pattern, fixed by
construction), and its regression probe lives in the model
suite ('LeaseScopeSpec', over the 'leaseLockHeld' seam).

This module uses only the long-exported raw lease API.
-}
{-# LANGUAGE OverloadedStrings #-}
module LeaseWedgeSpec (spec) where

import Control.Concurrent
  ( MVar
  , forkIO
  , killThread
  , newEmptyMVar
  , putMVar
  , takeMVar
  )
import Control.Exception (SomeException, mask, try)
import Control.Monad (forM_)
import Data.IORef (modifyIORef', newIORef, readIORef)
import System.Timeout (timeout)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertEqual, assertFailure, testCase)

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
spec = testGroup "Detach-lease wedge windows"
  [ testCase "beginDetach take-to-handoff never wedges under kill"
      caseBeginNeverWedges
  ]

sid1 :: SessionId
sid1 = SessionId 1

digestRequest :: SessionId -> Int -> JobRequest
digestRequest sid ticks = JobRequest
  { jrSession = sid
  , jrFunction = JobDigest
  , jrWork = WorkCall
      (Reservation "lease-wedge" [] Nothing Nothing)
      (EffectCrypto (FxDigest (MechanismId 0x250) "abc"))
  , jrTicks = ticks
  , jrCapacity = 64
  }

-- | Victim-side put that survives a kill landing while blocked:
-- a killed put is retried (main's kills are bounded, one per
-- iteration, so retries terminate; main always drains).
putRetry :: MVar a -> a -> IO ()
putRetry mv x = do
  e <- try (putMVar mv x)
  case (e :: Either SomeException ()) of
    Left _ -> putRetry mv x
    Right () -> pure ()

-- | Iterations (fresh job each).
nJobs :: Int
nJobs = 1000

caseBeginNeverWedges :: IO ()
caseBeginNeverWedges = do
  table <- newAsyncTable 2048
  enableAsyncSession table sid1
  jids <- mapM
    (\_ -> do
      ej <- startJob table (digestRequest sid1 2)
      case ej of
        Left deny -> assertFailure ("job submit refused: " ++ show deny)
        Right j -> pure j
    )
    [1 .. nJobs :: Int]
  ready <- newEmptyMVar
  done <- newEmptyMVar
  let victimLoop = mask $ \restore -> forM_ jids $ \jid -> do
        putRetry ready jid
        -- 'try' OUTSIDE 'restore': a pending kill is always caught.
        mL <- try (restore (beginDetach table jid))
          :: IO (Either SomeException (Maybe DetachLease))
        case mL of
          -- Masked gap: the probe's own pairing never strands.
          Right (Just l) -> abortDetach l
          _ -> pure ()
        putRetry done ()
  victimTid <- forkIO victimLoop
  wedged <- newIORef (0 :: Int)
  forM_ jids $ \jid -> do
    mReady <- timeout 10000000 (takeMVar ready)
    -- No order is asserted here: a kill landing in 'try''s return
    -- path can double-put a ghost token, skewing one rendezvous by
    -- an iteration. Ghosts self-heal (MVars drain) and never touch
    -- the wedge count — only a >100ms held lock counts — so the
    -- rendezvous stays loose on purpose.
    case mReady of
      Nothing -> assertFailure "wedge detected: victim stalled before begin"
      Just _ -> pure ()
    killThread victimTid
    mDone <- timeout 10000000 (takeMVar done)
    case mDone of
      Nothing -> assertFailure "wedge detected: iteration never reported"
      Just () -> pure ()
    mProbe <- timeout 100000 (beginDetach table jid)
    case mProbe of
      Nothing -> modifyIORef' wedged (+ 1)
      Just Nothing -> assertFailure "job vanished mid-probe"
      Just (Just l) -> abortDetach l
  nW <- readIORef wedged
  assertEqual "no beginDetach window wedged" 0 nW
