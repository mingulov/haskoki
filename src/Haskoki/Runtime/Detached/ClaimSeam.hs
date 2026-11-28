{- | Detached join-claim test seam.
-}
module Haskoki.Runtime.Detached.ClaimSeam
  ( setJoinTestHook
  ) where

import Control.Concurrent.STM
  ( atomically
  , writeTVar
  )
import Haskoki.Runtime.Detached.Context

-- ---------------------------------------------------------------------------
-- Join-claim test seam
-- ---------------------------------------------------------------------------

-- | TEST-ONLY: set the action a claimed join runs between its live
-- start and its attachment commit — the interruption window the
-- transfer must survive. Production leaves the default no-op, so
-- normal joins pay one @TVar@ read and no hook call. Tests set a
-- rendezvous here to land a kill deterministically inside the
-- window, then assert the claim rolled back and the fresh
-- unregistered job retired.
setJoinTestHook :: DetachCtx -> IO () -> IO ()
setJoinTestHook dc hook = atomically (writeTVar (dcJoinHook dc) hook)
