{- | Detached saveability checks.
-}
module Haskoki.Runtime.Detached.Saveability
  ( markJobOpaque
  , readOpaque
  , clearOpaque
  ) where

import Control.Concurrent.STM
  ( atomically
  , readTVar
  , writeTVar
  )
import qualified Data.Map.Strict as Map
import qualified Data.Set as Set
import Haskoki.Runtime.Async
  ( AsyncTable
  , asyncTableId
  )
import Haskoki.Runtime.Attach
  ( TokenClaims (..)
  )
import Haskoki.Types
  ( JobId (..)
  )
import Haskoki.Runtime.Detached.Context

-- ---------------------------------------------------------------------------
-- Saveability
-- ---------------------------------------------------------------------------

-- | Flag a live job as native-opaque (an explicit fault-injection
-- API for adapters and tests): its workflow holds a live native
-- context (a real adapter's un-checkpointable state) that has no
-- pointer-free record. The mark is keyed by table and job
-- identity on the store handle's shared claim authority, so two
-- tables' job zero never share a mark and every context over the
-- handle sees it. Detach of a non-terminal (pending, ready,
-- running or held) job then reports the permitted typed
-- unsaveable outcome with the job preserved, every time: the
-- mark is not consumed by a refusal. It clears when the job
-- detaches successfully, and when the table is retired through a
-- context that marked or served it (this context records the
-- table in its marked set, in the same STM step, so its own
-- retirement of the table drops the mark even if no context ever
-- joined through it). Terminal jobs ignore marks.
markJobOpaque :: DetachCtx -> AsyncTable -> JobId -> String -> IO ()
markJobOpaque dc table jid reason = atomically $ do
  let tid = asyncTableId table
  tc <- readClaims dc
  writeClaims dc tc
    { tcOpaque = Map.insert (tid, jid) reason (tcOpaque tc) }
  marked <- readTVar (dcMarked dc)
  writeTVar (dcMarked dc) (Set.insert tid marked)

-- | Read (without consuming) a job's opaque mark, if any.
readOpaque :: DetachCtx -> AsyncTable -> JobId -> IO (Maybe String)
readOpaque dc table jid =
  Map.lookup (asyncTableId table, jid) . tcOpaque
    <$> atomically (readClaims dc)

-- | Drop a job's opaque mark (after a successful detach).
clearOpaque :: DetachCtx -> AsyncTable -> JobId -> IO ()
clearOpaque dc table jid = atomically $ do
  tc <- readClaims dc
  writeClaims dc tc
    { tcOpaque = Map.delete (asyncTableId table, jid) (tcOpaque tc) }
