{-# OPTIONS_GHC -fno-hpc #-}
{- | Heap walker shared by the engine tests: finds lazy closures
reachable from a value, so a test can assert that a published
structure holds no thunk another thread could race on (GHC #27272).

Under @-fhpc@ the call itself wraps the argument in a tick box: a
counting tick is not trivial, so GHC allocates a fresh thunk around
the walked value at the call site, and the walk would report that
one root thunk on an evaluated value. 'lazyClosures' therefore
forces only the root to WHNF first, which strips the tick thunk;
every caller already passes a WHNF root, so no detection is lost.
This module opts out of HPC so the walk adds no new tick of its
own (helper modules never enter the coverage reports, which pass
only the two library mix dirs, so coverage numbers do not change).

The entry-tracking oracle ('trackedTail', 'trackedInt',
'TrackerFired') measures the complementary "every field entered"
property without reading the heap: a tracked position throws when
entered, on any flags.
-}
module LazyWalk
  ( lazyClosures
  , TrackerFired (..)
  , trackedTail
  , trackedInt
  ) where

import Control.Exception (Exception, evaluate, throw)
import GHC.Exts.Heap (Box, GenClosure (..), asBox, getBoxedClosureData)

-- | Lazy heap objects reachable from a value (unevaluated thunks,
-- partial applications of thunks, black holes under evaluation),
-- named by closure constructor. Follows constructor fields and
-- evaluated indirections; functions and byte arrays are values.
-- The root is forced to WHNF first (see the module header):
-- callers pass evaluated values, so this strips an instrumentation
-- tick, never a product thunk.
lazyClosures :: a -> IO [String]
lazyClosures x0 = do
  x <- evaluate x0
  go (asBox x)
  where
    go :: Box -> IO [String]
    go b = do
      c <- getBoxedClosureData b
      case c of
        ConstrClosure {ptrArgs = ps} -> concat <$> mapM go ps
        IndClosure {indirectee = i} -> go i
        BlackholeClosure {indirectee = i} -> go i
        FunClosure {} -> pure []
        PAPClosure {} -> pure []
        ArrWordsClosure {} -> pure []
        other -> pure [takeWhile (/= ' ') (show other)]

-- | Thrown by a tracked position when it is entered. The tag names
-- the position (field or set element), so a test can assert that
-- forcing reached exactly the armed spot.
data TrackerFired = TrackerFired String deriving (Show)

instance Exception TrackerFired

-- | A string whose tail end throws 'TrackerFired' when entered. The
-- prefix keeps its outward shape (including WHNF), so strict record
-- fields and set-insertion comparisons stay quiet; only a deep fold
-- that reaches the end fires the tracker.
trackedTail :: String -> String -> String
trackedTail prefix tag = prefix ++ throw (TrackerFired tag)

-- | An 'Int' that throws 'TrackerFired' when entered.
trackedInt :: String -> Int
trackedInt tag = throw (TrackerFired tag)
