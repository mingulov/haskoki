-- | Native CK_NOTIFY values. Application pointers remain borrowed native values;
-- the private String callback API and persistent storage are not involved.
{-# LANGUAGE ForeignFunctionInterface #-}
module Haskoki.FFI.Notify
  ( NativeNotify, SessionNotify (..), NotifyDecision (..), NotifyInvoker
  , invokeNativeNotify, dispatchSessionNotifyWith
  ) where

import Control.Concurrent (runInBoundThread)
import Control.Exception (SomeException, try)
import Foreign.C.Types (CULong (..))
import Foreign.Ptr (FunPtr, Ptr, nullFunPtr)
import Haskoki.Types (SessionId (..))

type NativeNotify = CULong -> CULong -> Ptr () -> IO CULong

data SessionNotify = SessionNotify
  { snFunction :: !(FunPtr NativeNotify)
  , snApplication :: !(Ptr ())
  } deriving (Eq, Show)

data NotifyDecision = NotifyContinue | NotifyCancel | NotifyFailed
  deriving (Eq, Show)

type NotifyInvoker = FunPtr NativeNotify -> CULong -> CULong -> Ptr () -> IO CULong

-- Safe: application code may call the guarded C surface. A bound caller keeps
-- that reentry on the same OS thread and therefore in the same TLS context.
foreign import ccall safe "haskoki_invoke_notify"
  invokeNativeNotify :: FunPtr NativeNotify -> CULong -> CULong -> Ptr () -> IO CULong

-- | Called after releasing model/registry/store locks and async leases. The
-- serving C state lock remains the lifetime lease. Tests can throw from an
-- injected Haskell invoker BEFORE entering C; native callbacks must themselves
-- return normally. No Haskell exception is sent through a C callback wrapper.
dispatchSessionNotifyWith :: NotifyInvoker -> SessionId -> SessionNotify -> IO NotifyDecision
dispatchSessionNotifyWith invoke (SessionId sid) notification
  | snFunction notification == nullFunPtr = pure NotifyContinue
  | otherwise = do
      result <- try (runInBoundThread (invoke (snFunction notification)
        (fromIntegral sid) 0 (snApplication notification))) :: IO (Either SomeException CULong)
      pure $ case result of
        Right 0 -> NotifyContinue
        Right 1 -> NotifyCancel
        _ -> NotifyFailed
