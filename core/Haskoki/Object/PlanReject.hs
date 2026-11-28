{- | Object plan rejection constructors.
-}
{-# LANGUAGE OverloadedStrings #-}
module Haskoki.Object.PlanReject
  ( templateReject
  , invalidHandle
  ) where

import Haskoki.Outcome
  ( PlanResult (..)
  , Rejection (..)
  , StateDelta (..)
  )
import Haskoki.Types
  ( ReturnCode (..)
  )

-- | A template rejection: no outputs, no delta, no partial object.
templateReject :: ReturnCode -> String -> PlanResult
templateReject code why = Reject Rejection
  { rejCode = code
  , rejOutputs = []
  , rejDelta = StateDelta []
  , rejReleases = []
  , rejReasons = [why]
  , rejCause = Nothing
  }

-- | An unresolvable-handle rejection.
invalidHandle :: String -> PlanResult
invalidHandle why = Reject Rejection
  { rejCode = CKR_OBJECT_HANDLE_INVALID
  , rejOutputs = []
  , rejDelta = StateDelta []
  , rejReleases = []
  , rejReasons = [why]
  , rejCause = Nothing
  }
