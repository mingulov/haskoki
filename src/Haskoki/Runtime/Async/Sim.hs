{- | Async simulation bridge.
-}
module Haskoki.Runtime.Async.Sim
  ( advanceTicks
  ) where

import Control.Concurrent.STM
  ( atomically
  , readTVar
  , writeTVar
  )
import qualified Data.Map.Strict as Map
import Data.Maybe (listToMaybe)
import qualified Data.Text as T
import Data.Word (Word64)
import Haskoki.Operation.Effect
  ( CryptoEffect (..)
  )
import Haskoki.Registry.Generated (generatedInventory)
import Haskoki.Registry.Types (MechanismId (..))
import Haskoki.Runtime.Async.Jobs
import Haskoki.Runtime.Async.Table

-- ---------------------------------------------------------------------------
-- Simulation bridge (scheduler advance)
-- ---------------------------------------------------------------------------

-- | Decrement every pending job's ticks by the base advance plus its
-- schedule boost, saturating at 1: the last tick ALWAYS drives
-- through the poll path — advance never executes effects, checks
-- reservations, delivers, or fails a job. Unconfigured runs (empty
-- schedule) apply the base advance only; the poll path itself is
-- untouched. Returns @(advanced, saturated-at-1)@.
advanceTicks :: AsyncTable -> Int -> [(String, Int)] -> IO (Int, Int)
advanceTicks table base sched = atomically $ do
  jobs <- readTVar (atJobs table)
  let (counts, jobs') = Map.mapAccum step (0, 0) jobs
  -- Forced: see the forcing invariant on @commitStep@.
  jobs' `seq` writeTVar (atJobs table) jobs'
  pure counts
  where
    step :: (Int, Int) -> Job -> ((Int, Int), Job)
    step (adv, sat) job = case jbState job of
      JobPending t
        | t > 1 ->
            let t' = max 1 (t - base - scheduleBoost sched job)
                dec = t - t'
                -- Countdowns tick through 'stepJob' one tick at a
                -- time; a zero or negative advance is not a
                -- countdown (the caller guards base >= 1 and boosts
                -- >= 0, so this arm only fires on direct misuse) and
                -- writes the saturated target exactly as before.
                (st', e') = if dec > 0
                  then applyTicks dec (JobPending t) (jbEpoch job)
                  else (JobPending t', jbEpoch job)
            in ((adv + 1, if t' == 1 then sat + 1 else sat)
               , job { jbState = st', jbEpoch = e' })
      _ -> ((adv, sat), job)

-- | Apply @n@ countdown ticks through 'stepJob', stopping early if
-- a tick rejects (defensive: the countdown vocabulary keeps the
-- epoch, and callers only tick pending jobs with ticks left, so
-- the loop always runs to completion and the epoch never moves).
applyTicks :: Int -> JobState -> Word64 -> (JobState, Word64)
applyTicks n st e
  | n <= 0 = (st, e)
  | otherwise = case stepJob EvTick st e of
      Right s -> applyTicks (n - 1) (stepState s) (stepEpoch s)
      Left _ -> (st, e)

-- | Extra ticks a job earns from the delay schedule. Precedence:
-- exact CKM mechanism name wins over the job-function tag, which
-- wins over the @"*"@ wildcard; within one key the LAST file entry
-- wins. Unknown names match nothing.
scheduleBoost :: [(String, Int)] -> Job -> Int
scheduleBoost sched job =
  case (byMech, byFunc, byWild) of
    (Just t, _, _) -> t
    (_, Just t, _) -> t
    (_, _, Just t) -> t
    _ -> 0
  where
    look key = listToMaybe [t | (k, t) <- reverse sched, k == key]
    byMech = effectMech (workEffect (jbWork job)) >>= mechNameOf >>= look
    byFunc = look (funcTag (jbFunction job))
    byWild = look "*"

-- | The mechanism an effect names, if any. Stream feed/consume
-- steps name a backend context instead of a mechanism.
effectMech :: CryptoEffect -> Maybe MechanismId
effectMech fx = case fx of
  FxDigest m _ -> Just m
  FxDigestInit m -> Just m
  FxDigestFeed {} -> Nothing
  FxDigestConsume {} -> Nothing
  FxCipher _ m _ _ _ -> Just m
  FxSign m _ _ _ -> Just m
  FxVerify m _ _ _ _ -> Just m
  FxSignRecover m _ _ _ _ -> Just m
  FxVerifyRecover m _ _ _ _ -> Just m
  FxMessageCipher _ m _ _ _ _ -> Just m
  FxMessageSign m _ _ _ -> Just m
  FxMessageVerify m _ _ _ _ -> Just m
  FxGenerateKey m _ _ -> Just m
  FxWrap m _ _ _ -> Just m
  FxUnwrap m _ _ _ -> Just m
  FxAuthWrap m _ _ _ -> Just m
  FxAuthUnwrap m _ _ _ -> Just m
  FxDerive m _ _ _ _ _ -> Just m
  FxKemEncaps m _ _ _ -> Just m
  FxKemDecaps m _ _ _ -> Just m

-- | The schedule key for a job function family.
funcTag :: JobFunction -> String
funcTag JobSign = "sign"
funcTag JobDigest = "digest"
funcTag JobGenKey = "genkey"
funcTag JobGenKeyPair = "genkeypair"

-- | Canonical CKM name for a mechanism id, if it is one.
mechNameOf :: MechanismId -> Maybe String
mechNameOf (MechanismId w) =
  listToMaybe [T.unpack name | (i, name, _) <- generatedInventory, i == w]
