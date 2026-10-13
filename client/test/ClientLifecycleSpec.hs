-- | Tasty pins for the client lifecycle bracket and retry policy.
--
-- 'withInitialized' is exercised against a stub 'Functions' record
-- (plain Haskell functions logging init/finalize order): no @dlopen@,
-- no token, yet the bracket order under success, body exceptions, init
-- refusal, finalize failure, and async interruption is pinned exactly.
-- 'withLifecycleRetry' is exercised against 'P11Error' throws counted
-- with an 'IORef', including the masking state of each attempt.
module ClientLifecycleSpec (spec) where

import Control.Concurrent (forkIO, killThread, newEmptyMVar, putMVar, takeMVar)
import Control.Exception
  ( IOException
  , MaskingState (..)
  , SomeException
  , catch
  , getMaskingState
  , throwIO
  , try
  )
import Data.IORef (IORef, modifyIORef', newIORef, readIORef, writeIORef)
import System.Timeout (timeout)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertFailure, testCase, (@?=))

import Haskoki.Client
  ( P11Error (..)
  , RetryPolicy (..)
  , defaultRetryPolicy
  , shouldRetry
  , withInitialized
  , withLifecycleRetry
  )
import Haskoki.Client.Raw (CK_RV, Functions (..), ckrOk)

spec :: TestTree
spec = testGroup "client lifecycle"
  [ testGroup "retry policy"
    [ testCase "first failure retries under the default policy" $
        shouldRetry defaultRetryPolicy 1 err @?= True
    , testCase "second failure exhausts the default policy" $
        shouldRetry defaultRetryPolicy 2 err @?= False
    , testCase "zero policy never retries" $
        shouldRetry (RetryPolicy 0) 1 err @?= False
    , testCase "retry then success runs the action twice" $ do
        attempts <- newIORef (0 :: Int)
        out <- withLifecycleRetry defaultRetryPolicy $ do
          n <- readIORef attempts
          writeIORef attempts (n + 1)
          if n == 0 then throwIO err else pure "served"
        out @?= "served"
        count <- readIORef attempts
        count @?= 2
    , testCase "permanent refusal fails after 1 + maxRetries attempts" $ do
        attempts <- newIORef (0 :: Int)
        res <- try (withLifecycleRetry defaultRetryPolicy $ do
          n <- readIORef attempts
          writeIORef attempts (n + 1)
          throwIO err) :: IO (Either P11Error ())
        case res of
          Left e -> p11Call e @?= "C_Body"
          Right _ -> assertFailure "permanent refusal unexpectedly passed"
        count <- readIORef attempts
        count @?= 2
    , testCase "retries run outside the masked handler" $ do
        attempts <- newIORef (0 :: Int)
        states <- newIORef []
        out <- withLifecycleRetry defaultRetryPolicy $ do
          st <- getMaskingState
          modifyIORef' states (st :)
          n <- readIORef attempts
          writeIORef attempts (n + 1)
          if n == 0 then throwIO err else pure "served"
        out @?= "served"
        statesSeen <- readIORef states
        statesSeen @?= [Unmasked, Unmasked]
    , testCase "init failure is not retried" $ do
        attempts <- newIORef (0 :: Int)
        res <- try (withLifecycleRetry defaultRetryPolicy $ do
          n <- readIORef attempts
          writeIORef attempts (n + 1)
          throwIO (P11Error "C_Initialize" 1)) :: IO (Either P11Error ())
        case res of
          Left e -> p11Call e @?= "C_Initialize"
          Right _ -> assertFailure "init failure unexpectedly passed"
        count <- readIORef attempts
        count @?= 1
    , testCase "finalize failure is not retried" $ do
        attempts <- newIORef (0 :: Int)
        res <- try (withLifecycleRetry defaultRetryPolicy $ do
          n <- readIORef attempts
          writeIORef attempts (n + 1)
          throwIO (P11Error "C_Finalize" 1)) :: IO (Either P11Error ())
        case res of
          Left e -> p11Call e @?= "C_Finalize"
          Right _ -> assertFailure "finalize failure unexpectedly passed"
        count <- readIORef attempts
        count @?= 1
    , testCase "retry runs each attempt in its own interval" $ do
        logRef <- newIORef []
        attempts <- newIORef (0 :: Int)
        let funs = stubFunctions logRef ckrOk ckrOk
        out <- withLifecycleRetry defaultRetryPolicy $ withInitialized funs $ do
          modifyIORef' logRef ("body" :)
          n <- readIORef attempts
          writeIORef attempts (n + 1)
          if n == 0 then throwIO err else pure "served"
        out @?= "served"
        order <- readIORef logRef
        reverse order @?= ["init", "body", "finalize", "init", "body", "finalize"]
    , testCase "non-token errors propagate without retry" $ do
        attempts <- newIORef (0 :: Int)
        res <- try (withLifecycleRetry defaultRetryPolicy $ do
          n <- readIORef attempts
          writeIORef attempts (n + 1)
          throwIO (userError "simulated host failure")) :: IO (Either IOException ())
        case res of
          Left _ -> pure ()
          Right _ -> assertFailure "host error unexpectedly passed"
        count <- readIORef attempts
        count @?= 1
    ]
  , testGroup "init intervals"
    [ testCase "success finalizes after the body" $ do
        logRef <- newIORef []
        let funs = stubFunctions logRef ckrOk ckrOk
        withInitialized funs (modifyIORef' logRef ("body" :))
        order <- readIORef logRef
        reverse order @?= ["init", "body", "finalize"]
    , testCase "body exception still finalizes, then propagates" $ do
        logRef <- newIORef []
        let funs = stubFunctions logRef ckrOk ckrOk
        res <- try (withInitialized funs $ do
          modifyIORef' logRef ("body" :)
          throwIO err) :: IO (Either P11Error ())
        case res of
          Left e -> p11Call e @?= "C_Body"
          Right _ -> assertFailure "body exception was swallowed"
        order <- readIORef logRef
        reverse order @?= ["init", "body", "finalize"]
    , testCase "init refusal runs neither body nor finalize" $ do
        logRef <- newIORef []
        let funs = stubFunctions logRef 1 ckrOk
        res <- try (withInitialized funs
          (modifyIORef' logRef ("body" :))) :: IO (Either P11Error ())
        case res of
          Left e -> p11Call e @?= "C_Initialize"
          Right _ -> assertFailure "init refusal unexpectedly passed"
        order <- readIORef logRef
        reverse order @?= ["init"]
    , testCase "finalize failure surfaces after a clean body" $ do
        logRef <- newIORef []
        let funs = stubFunctions logRef ckrOk 1
        res <- try (withInitialized funs
          (modifyIORef' logRef ("body" :))) :: IO (Either P11Error ())
        case res of
          Left e -> p11Call e @?= "C_Finalize"
          Right _ -> assertFailure "finalize failure unexpectedly passed"
        order <- readIORef logRef
        reverse order @?= ["init", "body", "finalize"]
    , testCase "joint body and finalize failure reports finalize" $ do
        logRef <- newIORef []
        let funs = stubFunctions logRef ckrOk 1
        res <- try (withInitialized funs $ do
          modifyIORef' logRef ("body" :)
          throwIO err) :: IO (Either P11Error ())
        case res of
          Left e -> p11Call e @?= "C_Finalize"
          Right _ -> assertFailure "joint failure unexpectedly passed"
        order <- readIORef logRef
        reverse order @?= ["init", "body", "finalize"]
    , testCase "async interruption finalizes and kills the worker" $ do
        logRef <- newIORef []
        entered <- newEmptyMVar
        released <- newEmptyMVar
        finalized <- newEmptyMVar
        outcome <- newEmptyMVar
        let funs = (stubFunctions logRef ckrOk ckrOk)
              { fFinalize = \_ -> do
                  modifyIORef' logRef ("finalize" :)
                  putMVar finalized ()
                  pure ckrOk
              }
        tid <- forkIO $
          (withInitialized funs (putMVar entered () >> takeMVar released)
            >> putMVar outcome "survived")
          `catch` (\e -> putMVar outcome (show (e :: SomeException)))
        takeMVar entered
        killThread tid
        done <- timeout 5000000 (takeMVar finalized)
        case done of
          Nothing -> assertFailure "finalize did not run after interruption"
          Just () -> pure ()
        out <- timeout 5000000 (takeMVar outcome)
        out @?= Just "thread killed"
        order <- readIORef logRef
        reverse order @?= ["init", "finalize"]
    ]
  ]
  where
    -- A body refusal: the policy counts attempts, and retries every
    -- call except the interval edges.
    err :: P11Error
    err = P11Error "C_Body" 7

-- | A stub function list logging init/finalize order. Every other
-- entry answers 'ckrOk'; nothing here touches FFI.
stubFunctions :: IORef [String] -> CK_RV -> CK_RV -> Functions
stubFunctions logRef initRv finRv = Functions
  { fInitialize = \_ -> logCall "init" >> pure initRv
  , fFinalize = \_ -> logCall "finalize" >> pure finRv
  , fGetInfo = \_ -> pure ckrOk
  , fGetSlotList = \_ _ _ -> pure ckrOk
  , fGetSlotInfo = \_ _ -> pure ckrOk
  , fGetTokenInfo = \_ _ -> pure ckrOk
  , fGetMechanismList = \_ _ _ -> pure ckrOk
  , fGetMechanismInfo = \_ _ _ -> pure ckrOk
  , fOpenSession = \_ _ _ -> pure ckrOk
  , fCloseSession = \_ -> pure ckrOk
  , fGetSessionInfo = \_ _ -> pure ckrOk
  , fLogin = \_ _ _ _ -> pure ckrOk
  , fLogout = \_ -> pure ckrOk
  , fCreateObject = \_ _ _ _ -> pure ckrOk
  , fDestroyObject = \_ _ -> pure ckrOk
  , fGetAttributeValue = \_ _ _ _ -> pure ckrOk
  , fFindObjectsInit = \_ _ _ -> pure ckrOk
  , fFindObjects = \_ _ _ _ -> pure ckrOk
  , fFindObjectsFinal = \_ -> pure ckrOk
  , fDigestInit = \_ _ -> pure ckrOk
  , fDigest = \_ _ _ _ _ -> pure ckrOk
  , fDigestUpdate = \_ _ _ -> pure ckrOk
  , fDigestFinal = \_ _ _ -> pure ckrOk
  , fEncryptInit = \_ _ _ -> pure ckrOk
  , fEncrypt = \_ _ _ _ _ -> pure ckrOk
  , fEncryptUpdate = \_ _ _ _ _ -> pure ckrOk
  , fEncryptFinal = \_ _ _ -> pure ckrOk
  , fDecryptInit = \_ _ _ -> pure ckrOk
  , fDecrypt = \_ _ _ _ _ -> pure ckrOk
  , fDecryptUpdate = \_ _ _ _ _ -> pure ckrOk
  , fDecryptFinal = \_ _ _ -> pure ckrOk
  , fSignInit = \_ _ _ -> pure ckrOk
  , fSign = \_ _ _ _ _ -> pure ckrOk
  , fSignUpdate = \_ _ _ -> pure ckrOk
  , fSignFinal = \_ _ _ -> pure ckrOk
  , fVerifyInit = \_ _ _ -> pure ckrOk
  , fVerify = \_ _ _ _ _ -> pure ckrOk
  , fVerifyUpdate = \_ _ _ -> pure ckrOk
  , fVerifyFinal = \_ _ _ -> pure ckrOk
  , fGenerateKey = \_ _ _ _ _ -> pure ckrOk
  , fGenerateKeyPair = \_ _ _ _ _ _ _ _ -> pure ckrOk
  , fDeriveKey = \_ _ _ _ _ _ -> pure ckrOk
  , fSeedRandom = \_ _ _ -> pure ckrOk
  , fGenerateRandom = \_ _ _ -> pure ckrOk
  }
  where
    logCall :: String -> IO ()
    logCall s = modifyIORef' logRef (s :)
