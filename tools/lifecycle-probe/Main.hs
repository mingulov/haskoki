{- | Stale-handle injection probe (SUBPROCESS-ISOLATED).
 -
 - The resolve-then-enter race (plain @g_haskoki_instance@ resolved
 - lock-free in C while @C_Finalize@ closes it, ending in
 - @freeStablePtr@) has a narrow window: a hammer may run clean
 - without proving anything (the race probe went 50\/50 clean). This probe
 - injects the losing interleaving DETERMINISTICALLY instead: open an
 - instance, close it (frees the @StablePtr@), open a FRESH interval
 - (likely reuses the freed table slot — the RTS says so itself in
 - 'DetachedEngineSpec'), then use the STALE handle.
 -
 - Without the liveness cell the stale use would be
 - @deRefStablePtr@-after-@freeStablePtr@ (undefined: a crash, or a
 - cross-generation success against the fresh instance — either is a
 - failure). With the cell (single-shot, never freed) every stale
 - use reads a taken cell and answers @CKR_CRYPTOKI_NOT_INITIALIZED@
 - (0x190).
 -
 - Exit 0 with @STALE-USE-RESULT all-not-initialized@ iff EVERY stale
 - wait and stale control over all iterations answered 0x190.
 - Anything else (signal death, wrong code, failed open) fails.
 - Run ONLY through scripts\/test-lifecycle.sh (with timeout),
 - never in-process in a test suite (a stale-use crash would take the
 - suite binary down with it).
 -}
module Main (main) where

import Foreign.C.Types (CULong (..))
import Foreign.Marshal.Alloc (alloca)
import Foreign.Ptr (Ptr, nullPtr)
import Foreign.StablePtr (StablePtr, castStablePtrToPtr)
import Numeric (showHex)
import System.Exit (exitFailure)
import System.IO (hPutStrLn, stderr)

import Haskoki.FFI.Instance
  ( haskokiControl
  , haskokiInstanceClose
  , haskokiInstanceOpen
  , haskokiWaitForSlotEvent
  )

-- | @CKR_CRYPTOKI_NOT_INITIALIZED@, pinned v2.40.
ckrNotInitialized :: CULong
ckrNotInitialized = CULong 0x190

-- | @CKF_DONT_BLOCK@ for @C_WaitForSlotEvent@: 1.
ckfDontBlock :: CULong
ckfDontBlock = CULong 0x00000001

-- | @CKR_NO_EVENT@ (0x08), pinned v2.40: what a live
-- @DON'T_BLOCK@ wait on an empty queue answers (the freshness guard
-- below).
ckrNoEvent :: CULong
ckrNoEvent = CULong 0x08

-- | Stale-use iterations: each iteration must answer 0x190 on BOTH
-- the wait and the control path. A single iteration can only
-- spuriously pass by returning 0x190 from freed memory, so 25 clean
-- iterations admit no flake (and a crash fails closed).
iterations :: Int
iterations = 25

isLive :: StablePtr a -> Bool
isLive p = castStablePtrToPtr p /= nullPtr

showRv :: CULong -> String
showRv (CULong w) = "0x" ++ showHex w ""

-- | One stale-use iteration: open, close, re-open (fresh
-- generation), then use the STALE handle on both entries. Returns
-- the two stale codes plus a freshness probe on the live handle
-- (which must keep serving: the fix must not break live use).
oneIteration :: IO (CULong, CULong, CULong)
oneIteration = do
  stale <- haskokiInstanceOpen
  if not (isLive stale)
    then do
      hPutStrLn stderr "STALE-USE-RESULT open1-null"
      exitFailure
    else pure ()
  haskokiInstanceClose stale
  fresh <- haskokiInstanceOpen
  if not (isLive fresh)
    then do
      hPutStrLn stderr "STALE-USE-RESULT open2-null"
      exitFailure
    else pure ()
  rvW <- alloca $ \(slotPtr :: Ptr CULong) ->
    haskokiWaitForSlotEvent stale ckfDontBlock slotPtr
  rvC <- alloca $ \(lenPtr :: Ptr CULong) ->
    haskokiControl stale nullPtr (CULong 0) nullPtr lenPtr
  rvF <- alloca $ \(slotPtr :: Ptr CULong) ->
    haskokiWaitForSlotEvent fresh ckfDontBlock slotPtr
  haskokiInstanceClose fresh
  pure (rvW, rvC, rvF)

go :: Int -> IO Bool
go 0 = pure True
go n = do
  (rvW, rvC, rvF) <- oneIteration
  if rvW == ckrNotInitialized && rvC == ckrNotInitialized
      && rvF == ckrNoEvent
    then go (n - 1)
    else do
      putStrLn ("STALE-USE-RESULT wrong-code wait=" ++ showRv rvW
        ++ " control=" ++ showRv rvC ++ " fresh=" ++ showRv rvF)
      pure False

main :: IO ()
main = do
  clean <- go iterations
  if clean
    then putStrLn "STALE-USE-RESULT all-not-initialized"
    else exitFailure
