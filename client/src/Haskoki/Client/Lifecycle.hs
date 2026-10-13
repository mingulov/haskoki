-- | Init-interval brackets and bounded retry for the test client.
--
-- Every entry that touches the token must run inside one init interval
-- (@C_Initialize@ ... @C_Finalize@). 'withInitialized' brackets that
-- interval so @C_Finalize@ runs even when the body throws: without the
-- bracket an exception leaks an open interval and the next
-- @C_Initialize@ answers @CKR_CRYPTOKI_ALREADY_INITIALIZED@ instead of
-- serving. 'withLifecycleRetry' re-runs an interval-scoped action in a
-- fresh interval when the token refuses. Test-only.
module Haskoki.Client.Lifecycle
  ( P11Error (..)
  , check
  , withInitialized
  , RetryPolicy (..)
  , defaultRetryPolicy
  , shouldRetry
  , withLifecycleRetry
  ) where

import Control.Exception (Exception, bracket_, throwIO, try)
import Foreign.Ptr (nullPtr)

import Haskoki.Client.Raw (CK_RV, Functions (..), ckrOk)

-- ---------------------------------------------------------------------------
-- Errors
-- ---------------------------------------------------------------------------

data P11Error = P11Error
  { p11Call :: !String
  , p11Rv :: !CK_RV
  } deriving (Show)

instance Exception P11Error

check :: Functions -> String -> IO CK_RV -> IO ()
check _fun call act = do
  rv <- act
  if rv == ckrOk then pure () else throwIO (P11Error call rv)

-- ---------------------------------------------------------------------------
-- Init intervals
-- ---------------------------------------------------------------------------

-- | Call labels for the interval edges, shared by the bracket and the
-- retry policy so the two cannot drift apart.
initCall, finCall :: String
initCall = "C_Initialize"
finCall = "C_Finalize"

-- | Run the body inside one init interval: initialize, run, finalize.
-- The finalize runs even when the body throws, so a mid-interval
-- failure never leaks an open interval into the next attempt.
withInitialized :: Functions -> IO a -> IO a
withInitialized funs body =
  bracket_ acquire release body
  where
    acquire = check funs initCall (fInitialize funs nullPtr)
    release = check funs finCall (fFinalize funs nullPtr)

-- ---------------------------------------------------------------------------
-- Bounded retry across fresh intervals
-- ---------------------------------------------------------------------------

-- | How many times an interval-scoped action may be retried after a
-- token refusal. Each attempt runs in its own interval (the caller
-- wraps the attempt in 'withInitialized', directly or via @withToken@),
-- so a refusal never retries inside a poisoned interval.
data RetryPolicy = RetryPolicy
  { maxRetries :: !Int
  } deriving (Show, Eq)

-- | One retry: two attempts total. Enough to ride out a single
-- mid-interval refusal; bounded so a permanently refusing token fails
-- fast instead of spinning.
defaultRetryPolicy :: RetryPolicy
defaultRetryPolicy = RetryPolicy { maxRetries = 1 }

-- | Whether a refusal merits another attempt. @failures@ counts
-- failures so far (1 after the first failure); attempts are bounded by
-- 'maxRetries', so the total never exceeds @1 + maxRetries@. Only body
-- refusals retry: init/finalize failures fail fast, so a broken
-- interval is reported instead of ridden out.
shouldRetry :: RetryPolicy -> Int -> P11Error -> Bool
shouldRetry pol failures err =
  failures <= maxRetries pol && isBodyRefusal err
  where
    isBodyRefusal e = p11Call e /= initCall && p11Call e /= finCall

-- | 'try' pinned to token refusals, so the retry loop names the
-- exception type it handles.
tryP11 :: IO a -> IO (Either P11Error a)
tryP11 = try

-- | Run an interval-scoped action, retrying body refusals in a fresh
-- interval per 'shouldRetry'. Anything that is not a token refusal,
-- and any init/finalize failure, propagates immediately without
-- consuming a retry. Retries run outside the handler: 'catch' handlers
-- execute masked, so recursing inside one would mask every later
-- attempt; 'tryP11' returns the refusal as a value and the retry runs
-- unmasked.
withLifecycleRetry :: RetryPolicy -> IO a -> IO a
withLifecycleRetry pol = go 0
  where
    go :: Int -> IO a -> IO a
    go failures act = do
      res <- tryP11 act
      case res of
        Right a -> pure a
        Left err ->
          if shouldRetry pol (failures + 1) err
            then go (failures + 1) act
            else throwIO err
