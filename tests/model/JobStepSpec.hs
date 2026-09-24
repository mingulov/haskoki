{- | Closed job-transition pins.

Every job-state change routes through the single total 'stepJob':
a 'JobEvent' plus the current 'JobState' and epoch either steps
to a committable verdict or rejects with a 'JobReject' naming
the event and the offending state (previously each operation
site ran its own @case@ analysis).

The table pins every event against every state: legal steps with
their exact target state and epoch, illegal pairs with their
exact rejection. Epoch policy is part of the contract: countdown
and claim steps keep the epoch, every terminal or hold step bumps
it by one.
-}
{-# LANGUAGE OverloadedStrings #-}
module JobStepSpec (spec) where

import Data.Word (Word64)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertEqual, testCase)

import Haskoki.Operation.Effect (CryptoResult (..))
import Haskoki.Runtime.Async
  ( Completion (..)
  , JobEvent (..)
  , JobReject (..)
  , JobState (..)
  , TerminalState (..)
  , stepEpoch
  , stepJob
  , stepState
  )
import Haskoki.Types (ReturnCode (..))

spec :: TestTree
spec = testGroup "Closed job transition"
  [ testGroup "transition table" (map toCase table)
  ]

-- | One table row: name, event, starting state, expected verdict.
toCase :: (String, JobEvent, JobState, Expect) -> TestTree
toCase (name, ev, st, want) =
  testCase name (assertEqual "verdict" want (runStep ev st epochIn))

-- | Run 'stepJob' and project the verdict onto plain data (the
-- 'JobStep' verdict constructor stays private: only 'stepJob'
-- builds committable steps).
runStep :: JobEvent -> JobState -> Word64 -> Expect
runStep ev st e = case stepJob ev st e of
  Left rej -> Left rej
  Right s -> Right (stepState s, stepEpoch s)

-- | The epoch every row starts from.
epochIn :: Word64
epochIn = 7

-- | A table expectation: rejection, or the target state and epoch.
type Expect = Either JobReject (JobState, Word64)

-- | Expect a legal step to its target state and epoch.
ok :: JobState -> Word64 -> Expect
ok st e = Right (st, e)

-- | Expect a rejection naming the event and the state.
no :: JobEvent -> JobState -> Expect
no ev st = Left (JobReject ev st)

-- | Sample states.
p3 :: JobState
p3 = JobPending 3

p1 :: JobState
p1 = JobPending 1

p0 :: JobState
p0 = JobPending 0

running :: JobState
running = JobRunning

ready :: JobState
ready = JobReady (GotBytes "held")

tDelivered :: JobState
tDelivered = JobTerminal (TermDelivered (CompBytes "done"))

tCanceled :: JobState
tCanceled = JobTerminal TermCanceled

tFailed :: JobState
tFailed = JobTerminal (TermFailed CKR_GENERAL_ERROR "boom")

-- | Sample events.
eTick :: JobEvent
eTick = EvTick

eClaim :: JobEvent
eClaim = EvClaim

eHold :: JobEvent
eHold = EvHold (GotBytes "answer")

eDeliver :: JobEvent
eDeliver = EvDeliver (CompBytes "out")

eFail :: JobEvent
eFail = EvFail CKR_GENERAL_ERROR "fail"

eCancel :: JobEvent
eCancel = EvCancel

-- | Every event against every state.
table :: [(String, JobEvent, JobState, Expect)]
table =
  [ ("tick counts down a pending job with ticks left", eTick, p3, ok (JobPending 2) 7)
  , ("tick on the last tick is not a countdown", eTick, p1, no eTick p1)
  , ("tick on a runnable job is not a countdown", eTick, p0, no eTick p0)
  , ("tick on a running job rejects", eTick, running, no eTick running)
  , ("tick on a ready job rejects", eTick, ready, no eTick ready)
  , ("tick on a delivered job rejects", eTick, tDelivered, no eTick tDelivered)
  , ("tick on a canceled job rejects", eTick, tCanceled, no eTick tCanceled)
  , ("tick on a failed job rejects", eTick, tFailed, no eTick tFailed)
  , ("claim takes a waiting job running", eClaim, p3, ok JobRunning 7)
  , ("claim takes a last-tick job running", eClaim, p1, ok JobRunning 7)
  , ("claim takes a runnable job running", eClaim, p0, ok JobRunning 7)
  , ("claim on a running job rejects", eClaim, running, no eClaim running)
  , ("claim on a ready job rejects", eClaim, ready, no eClaim ready)
  , ("claim on a delivered job rejects", eClaim, tDelivered, no eClaim tDelivered)
  , ("claim on a canceled job rejects", eClaim, tCanceled, no eClaim tCanceled)
  , ("claim on a failed job rejects", eClaim, tFailed, no eClaim tFailed)
  , ("hold on a pending job rejects", eHold, p3, no eHold p3)
  , ("hold on a last-tick job rejects", eHold, p1, no eHold p1)
  , ("hold on a runnable job rejects", eHold, p0, no eHold p0)
  , ("hold takes a running job ready", eHold, running, ok (JobReady (GotBytes "answer")) 8)
  , ("hold on a ready job rejects", eHold, ready, no eHold ready)
  , ("hold on a delivered job rejects", eHold, tDelivered, no eHold tDelivered)
  , ("hold on a canceled job rejects", eHold, tCanceled, no eHold tCanceled)
  , ("hold on a failed job rejects", eHold, tFailed, no eHold tFailed)
  , ("deliver on a pending job rejects", eDeliver, p3, no eDeliver p3)
  , ("deliver on a last-tick job rejects", eDeliver, p1, no eDeliver p1)
  , ("deliver on a runnable job rejects", eDeliver, p0, no eDeliver p0)
  , ("deliver on a running job rejects", eDeliver, running, no eDeliver running)
  , ("deliver takes a ready job delivered", eDeliver, ready, ok (JobTerminal (TermDelivered (CompBytes "out"))) 8)
  , ("deliver on a delivered job rejects", eDeliver, tDelivered, no eDeliver tDelivered)
  , ("deliver on a canceled job rejects", eDeliver, tCanceled, no eDeliver tCanceled)
  , ("deliver on a failed job rejects", eDeliver, tFailed, no eDeliver tFailed)
  , ("fail takes a pending job failed", eFail, p3, ok (JobTerminal (TermFailed CKR_GENERAL_ERROR "fail")) 8)
  , ("fail takes a last-tick job failed", eFail, p1, ok (JobTerminal (TermFailed CKR_GENERAL_ERROR "fail")) 8)
  , ("fail takes a runnable job failed", eFail, p0, ok (JobTerminal (TermFailed CKR_GENERAL_ERROR "fail")) 8)
  , ("fail takes a running job failed", eFail, running, ok (JobTerminal (TermFailed CKR_GENERAL_ERROR "fail")) 8)
  , ("fail takes a ready job failed", eFail, ready, ok (JobTerminal (TermFailed CKR_GENERAL_ERROR "fail")) 8)
  , ("fail on a delivered job rejects", eFail, tDelivered, no eFail tDelivered)
  , ("fail on a canceled job rejects", eFail, tCanceled, no eFail tCanceled)
  , ("fail on a failed job rejects", eFail, tFailed, no eFail tFailed)
  , ("cancel takes a pending job canceled", eCancel, p3, ok (JobTerminal TermCanceled) 8)
  , ("cancel takes a last-tick job canceled", eCancel, p1, ok (JobTerminal TermCanceled) 8)
  , ("cancel takes a runnable job canceled", eCancel, p0, ok (JobTerminal TermCanceled) 8)
  , ("cancel takes a running job canceled", eCancel, running, ok (JobTerminal TermCanceled) 8)
  , ("cancel takes a ready job canceled", eCancel, ready, ok (JobTerminal TermCanceled) 8)
  , ("cancel on a delivered job rejects", eCancel, tDelivered, no eCancel tDelivered)
  , ("cancel on a canceled job rejects", eCancel, tCanceled, no eCancel tCanceled)
  , ("cancel on a failed job rejects", eCancel, tFailed, no eCancel tFailed)
  ]
