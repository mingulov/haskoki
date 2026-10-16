{- | Heap walker shared by the engine tests: finds lazy closures
reachable from a value, so a test can assert that a published
structure holds no thunk another thread could race on (GHC #27272).
-}
module LazyWalk (lazyClosures) where

import GHC.Exts.Heap (Box, GenClosure (..), asBox, getBoxedClosureData)

-- | Lazy heap objects reachable from a value (unevaluated thunks,
-- partial applications of thunks, black holes under evaluation),
-- named by closure constructor. Follows constructor fields and
-- evaluated indirections; functions and byte arrays are values.
lazyClosures :: a -> IO [String]
lazyClosures x = go (asBox x)
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
