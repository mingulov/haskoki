{- | Async poll/complete/cancel/reap outcomes.
-}
module Haskoki.Runtime.Async.Outcomes
  ( PollOutcome (..)
  , CompleteOutcome (..)
  , CancelOutcome (..)
  , ReapOutcome (..)
  , Delivery (..)
  , EffectRunner
  ) where

import Data.ByteString (ByteString)
import Data.Word (Word64)
import Haskoki.Operation.Effect
  ( CryptoEffect (..)
  , CryptoResult (..)
  )
import Haskoki.Runtime.Async.Jobs
import Haskoki.Runtime.Async.Completion

-- ---------------------------------------------------------------------------
-- Outcomes
-- ---------------------------------------------------------------------------

-- | One poll's outcome. Pending polls (and the drive that turns the
-- last poll ready) never touch the result sink.
data PollOutcome
  = PollPending { poTicksLeft :: !Int }
  | PollReady
  | PollTerminal !TerminalState
  | PollUnknown
  | PollWrongFunction { pwExpected :: !JobFunction, pwGot :: !JobFunction }
  deriving (Eq, Show)

-- | One complete's outcome. Delivery happens only on the winning
-- 'CompleteDelivered'; every other outcome writes nothing (short
-- buffers report their sizing through 'dReportNeeded').
data CompleteOutcome
  = CompletePending { coTicksLeft :: !Int }
  | CompleteDelivered { coCompletion :: !Completion }
  | CompleteAlready !TerminalState
  | CompleteUnknown
  | CompleteWrongFunction { cwExpected :: !JobFunction, cwGot :: !JobFunction }
  | CompleteShort { coNeeded :: !Word64 }
  deriving (Eq, Show)

-- | One cancel's outcome. Cancel wins only out of a live state;
-- otherwise the caller observes the winner's terminal state.
data CancelOutcome
  = CancelOk
  | CancelAlready !TerminalState
  | CancelUnknown
  deriving (Eq, Show)

-- | One reap's outcome: terminal tombstones drop, live jobs and
-- unknown ids report without touching the table.
data ReapOutcome
  = Reaped
  | ReapLive
  | ReapUnknown
  deriving (Eq, Show)

-- | The attached delivery sink: caller byte-payload capacity, the
-- exact-frame write (fires at most once, on the winning complete),
-- and the sizing report for short buffers.
data Delivery = Delivery
  { dCapacity :: !Word64
  , dWrite :: !(ByteString -> IO ())
  , dReportNeeded :: !(Word64 -> IO ())
  }

-- | The effect interpreter a drive step runs through. Model tests
-- pass stubs; engine and FFI layers pass the production driver.
type EffectRunner = CryptoEffect -> IO CryptoResult
