{- | Async jobs and functions.
-}
module Haskoki.Runtime.Async.Jobs
  ( JobFunction (..)
  , jobExactFid
  , AsyncWork (..)
  , workEffect
  , workReservation
  , JobRequest (..)
  , StartDeny (..)
  , effectHoldable
  , Job (..)
  , JobState (..)
  , TerminalState (..)
  ) where

import Control.Concurrent.MVar
  (MVar)
import Data.Word (Word64)
import Haskoki.CallWork
  ( CallWork
  , callWorkEffect
  , callWorkReservation
  )
import Haskoki.Operation.Effect
  ( CryptoEffect (..)
  , CryptoResult (..)
  )
import Haskoki.Operation.KeyManagement
  ( PendingWork (..)
  , workFunction
  )
import Haskoki.Outcome
  ( CryptoStep (..)
  , EffectRequest (..)
  , Reservation (..)
  )
import Haskoki.Request (FunctionId (..))
import Haskoki.Runtime.Usdt (
  UsdtOpId
  )
import Haskoki.Types
  ( ReturnCode (..)
  , SessionId
  )
import Haskoki.Runtime.Async.Completion

-- ---------------------------------------------------------------------------
-- Jobs and functions
-- ---------------------------------------------------------------------------

-- | Which function family a job belongs to. Pollers name the family
-- they serve; a mismatch is a typed refusal and the job is left
-- intact. Constructor order is stable (the FFI code mapping keys
-- off it): append, never reorder.
data JobFunction
  = JobSign
  | JobDigest
  | JobGenKey
  | JobGenKeyPair
  deriving (Eq, Ord, Show, Enum, Bounded)

-- | Family representative for async error attribution: the
-- fallback when a job carries no checked inner work (unstepped
-- call work reaches the drive on unchecked submit paths).
-- Checked jobs attribute exactly through 'jobExactFid'. If the
-- per-function error cells ever distinguish within a family, this
-- mapping (not the call sites) is the place that records the call.
jobFunctionToFid :: JobFunction -> FunctionId
jobFunctionToFid func = case func of
  JobSign -> F_Sign
  JobDigest -> F_Digest
  JobGenKey -> F_GenerateKey
  JobGenKeyPair -> F_GenerateKeyPair

-- | Exact error attribution for a job: checked call work carries
-- its pinned step (phase-exact function, e.g. a final step
-- attributes as the final entry, not the family head); key work
-- carries its 'PendingWork' shape. Unstepped call work (possible
-- on unchecked submit paths) falls back to the family head.
jobExactFid :: Job -> FunctionId
jobExactFid job = case jbWork job of
  WorkCall w -> case resStep (callWorkReservation w) of
    Just step -> csFunction step
    Nothing -> jobFunctionToFid (jbFunction job)
  WorkKey _ pw _ -> workFunction pw

-- | One planned unit of async work: the reservation that guards its
-- commit plus the effect the drive step runs. 'WorkCall' finishes
-- through the call finisher; 'WorkKey' through the key finisher.
data AsyncWork
  = WorkCall !CallWork
  | WorkKey !Reservation !PendingWork !CryptoEffect
  deriving (Eq, Show)

-- | The effect a drive step runs for a job.
workEffect :: AsyncWork -> CryptoEffect
workEffect (WorkCall w) = case callWorkEffect w of EffectCrypto fx -> fx
workEffect (WorkKey _ _ fx) = fx

-- | The reservation that guards a job's commit. The drive step
-- refuses to run against stale revisions; the complete step
-- re-validates through its finisher before publishing.
workReservation :: AsyncWork -> Reservation
workReservation (WorkCall w) = callWorkReservation w
workReservation (WorkKey res _ _) = res

-- | A submit request: session, function, planned work, polls before
-- runnable, and attached byte-payload capacity (bounds byte
-- results; handle results carry no byte payload).
data JobRequest = JobRequest
  { jrSession :: !SessionId
  , jrFunction :: !JobFunction
  , jrWork :: !AsyncWork
  , jrTicks :: !Int
  , jrCapacity :: !Word64
  } deriving (Eq, Show)

-- | Why submission was refused. Refusals allocate nothing: no job
-- id is consumed and the table is unchanged.
data StartDeny
  = StartSessionNotAsync
  | StartOverCapacity
  | StartBadCapacity
  | StartIncompatibleWork
  deriving (Eq, Show)

-- | Whether an effect can produce an answer the job can hold:
-- the work/result compatibility rule. Every completion
-- gates on bytes-like holdings (@isBytesLike@), so only
-- bytes- and unit-producing effects hold; resource-producing
-- allocation ('FxDigestInit') and verdict-producing verification
-- ('FxVerify', 'FxMessageVerify') never can. Recovery effects
-- hold by their natural bytes shape (a driver that cannot run
-- them refuses loudly at drive time — defense in depth,
-- unchanged). @startJobChecked@ refuses unholdable work at submit.
effectHoldable :: CryptoEffect -> Bool
-- Exhaustive, not fail-open — every constructor has an
-- explicit arm (no wildcard). A new effect fails validation via
-- -Werror=incomplete-patterns, forcing an explicit
-- holdability verdict here; the holdability battery pins every
-- verdict against silent flips.
effectHoldable (FxDigestInit _) = False
effectHoldable (FxVerify _ _ _ _ _) = False
effectHoldable (FxMessageVerify _ _ _ _ _) = False
effectHoldable (FxDigest _ _) = True
effectHoldable (FxDigestFeed _ _) = True
effectHoldable (FxDigestConsume _) = True
effectHoldable (FxCipher _ _ _ _ _) = True
effectHoldable (FxSign _ _ _ _) = True
effectHoldable (FxSignRecover _ _ _ _ _) = True
effectHoldable (FxVerifyRecover _ _ _ _ _) = True
effectHoldable (FxMessageCipher _ _ _ _ _ _) = True
effectHoldable (FxMessageSign _ _ _ _) = True
effectHoldable (FxGenerateKey _ _ _) = True
effectHoldable (FxWrap _ _ _ _) = True
effectHoldable (FxUnwrap _ _ _ _) = True
effectHoldable (FxAuthWrap _ _ _ _) = True
effectHoldable (FxAuthUnwrap _ _ _ _) = True
effectHoldable (FxDerive _ _ _ _ _ _) = True
effectHoldable (FxKemEncaps _ _ _ _) = True
effectHoldable (FxKemDecaps _ _ _ _) = True

-- | Live execution state. Terminal jobs stay in the map as
-- tombstones so late polls\/completions observe the winner.
data JobState
  = JobPending !Int
  | JobRunning
  | JobReady !CryptoResult
  | JobTerminal !TerminalState
  deriving (Eq, Show)

-- | One attached job: identity, plan, schedule, live state,
-- cancellation epoch, and the delivery lease. The lease is
-- 'MVar'-held outside STM; every transaction below touches only
-- the table @TVar@s.
data Job = Job
  { jbSession :: !SessionId
  , jbFunction :: !JobFunction
  , jbWork :: !AsyncWork
  , jbCapacity :: !Word64
  , jbState :: !JobState
  , jbEpoch :: !Word64
  , jbLock :: !(MVar ())
  , jbUsdt :: !(Maybe UsdtOpId)
  }

-- | A job's terminal state. Losers observe this (never partial
-- output): delivered completions, cancellation, or a coded failure.
data TerminalState
  = TermDelivered !Completion
  | TermCanceled
  | TermFailed !ReturnCode !String
  deriving (Eq, Show)
