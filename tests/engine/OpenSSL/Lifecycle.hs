{- | OpenSSL isolation and lifecycle cases.
-}
{-# LANGUAGE OverloadedStrings #-}
module OpenSSL.Lifecycle
  ( caseFinalConsumesOnce
  , caseInvalidInputs
  , caseIsolation
  , caseLifetimeGateSequential
  , caseLifetimeGateSimultaneous
  , caseShimHygiene
  ) where

import Control.Concurrent (forkIO, newEmptyMVar, putMVar, takeMVar)
import Control.Monad (replicateM_)
import qualified Data.ByteString as BS
import Data.List (isInfixOf, stripPrefix, tails)
import System.Directory (doesFileExist)
import Test.Tasty.HUnit (assertBool, assertEqual, assertFailure)
import Data.Word (Word32)
import Haskoki.Engine.Backend
  ( BackendCaps (..)
  , BackendEnv
  , BackendError (..)
  , CryptoBackend (..)
  , DigestAlg (..)
  , EngineResult (..)
  , KeyMaterial (..)
  , ResourceSaveability (..)
  , UnsaveableReason (..)
  , SigSpec (..)
  )
import Haskoki.Engine.OpenSSL4 (OpenSSL4 (..))
import Haskoki.Types (EngineResourceId (..))
import OpenSSL.Fixtures

expectInvalidState :: Show a => String -> EngineResult a -> IO ()
expectInvalidState label r = case r of
  EngineFail (BackendInvalidState _ _) -> pure ()
  other -> assertFailure (label ++ ": expected BackendInvalidState, got " ++ show other)

-- ---------------------------------------------------------------------------
-- Known-answer fixtures (independent oracles, see module header)
-- ---------------------------------------------------------------------------

caseIsolation :: IO ()
caseIsolation = do
  r1 <- openBackend "provider=default" :: IO (EngineResult (BackendEnv OpenSSL4))
  r2 <- openBackend "provider=default" :: IO (EngineResult (BackendEnv OpenSSL4))
  (e1, e2) <- case (r1, r2) of
    (EngineOk a, EngineOk b) -> pure (a, b)
    _ -> assertFailure "could not open two backends"
  d1 <- expectOk "ctx1 digest" =<< digestOneShot e1 D_SHA256 "abc"
  closeBackend e1
  -- Closing one private context leaves the other fully usable.
  d2 <- expectOk "ctx2 digest after close" =<< digestOneShot e2 D_SHA256 "abc"
  assertEqual "same vector" d1 d2
  assertEqual "still correct" sha256Abc d2
  closeBackend e2

caseShimHygiene :: IO ()
caseShimHygiene = do
  src <- findShim ["cbits/ossl4_ctx.c", "../cbits/ossl4_ctx.c", "haskoki/cbits/ossl4_ctx.c"]
  let low = lower src
  -- A provider *string* (quoted literal or header include), not a prose
  -- mention in a comment, would load a token-backed provider.
  assertBool "no pkcs11 provider string in shim"
    (not ("\"pkcs11\"" `isInfixOf` low || "pkcs11.h" `isInfixOf` low))
  -- A *reference* (call or address-of), not a prose mention, would run
  -- process-global teardown.
  assertBool "no OPENSSL_cleanup reference in shim" (not (hasRef low "openssl_cleanup"))
  assertBool "no OPENSSL_atexit reference in shim" (not (hasRef low "openssl_atexit"))
  where
    lower = map (\c -> if c >= 'A' && c <= 'Z' then toEnum (fromEnum c + 32) else c)
    hasRef src name = any match (tails src)
      where
        match s = case stripPrefix name s of
          Just rest -> case dropWhile (== ' ') rest of
            ('(' : _) -> True
            _ -> False
          Nothing -> case s of
            ('&' : rest) -> case stripPrefix name (dropWhile (== ' ') rest) of
              Just _ -> True
              Nothing -> False
            _ -> False
    findShim [] = assertFailure "cbits/ossl4_ctx.c not found from test cwd"
    findShim (p:ps) = do
      exists <- doesFileExist p
      if exists then readFile p else findShim ps

caseInvalidInputs :: IO ()
caseInvalidInputs = withBackend $ \env -> do
  -- Garbage key DER is a typed BadKey, never a crash.
  let badKey = KeyDer "not-der-at-all"
      spec' = SigECDSA { sigEc = mkEc "P-256" "DER", sigEcDigest = Just D_SHA256 }
  r1 <- verify env spec' badKey ecMsg ecSigDer
  case r1 of
    EngineFail (BackendBadKey _ _) -> pure ()
    EngineFail (BackendBadParam _ _) -> pure ()
    other -> assertFailure ("garbage key must be BadKey/BadParam, got " ++ show other)
  -- Unknown multipart resource is ResourceGone.
  r2 <- digestFinal env (mkResId 0xdeadbeef)
  case r2 of
    EngineFail (BackendResourceGone _ _) -> pure ()
    other -> assertFailure ("unknown resource must be ResourceGone, got " ++ show other)
  -- Double-final is ResourceGone (final releases).
  rid <- expectOk "init" =<< digestInit env D_SHA256
  _ <- expectOk "final" =<< digestFinal env rid
  r3 <- digestFinal env rid
  case r3 of
    EngineFail (BackendResourceGone _ _) -> pure ()
    other -> assertFailure ("second final must be ResourceGone, got " ++ show other)

-- | Behavioral pin: the final consumes the multipart handle, so
-- every later use of the id answers ResourceGone, and a release of
-- the consumed id is a no-op that must not throw or free again. The
-- exception-window proof (a fault at the copy boundary after C
-- consumes the handle) lives in OwnershipSpec's gated battery, which
-- is the suite that can observe native ownership counts.
caseFinalConsumesOnce :: IO ()
caseFinalConsumesOnce = withBackend $ \env -> do
  rid <- expectOk "init" =<< digestInit env D_SHA256
  expectOk "update" =<< digestUpdate env rid "hello"
  d1 <- expectOk "final" =<< digestFinal env rid
  assertEqual "sha256 hello" (hex "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824") d1
  r2 <- digestFinal env rid
  case r2 of
    EngineFail (BackendResourceGone _ _) -> pure ()
    other -> assertFailure ("second final must be Gone, got " ++ show other)
  u2 <- digestUpdate env rid "hello"
  case u2 of
    EngineFail (BackendResourceGone _ _) -> pure ()
    other -> assertFailure ("update-after-final must be Gone, got " ++ show other)
  releaseResource env rid
  r3 <- digestFinal env rid
  case r3 of
    EngineFail (BackendResourceGone _ _) -> pure ()
    other -> assertFailure ("final after release must be Gone, got " ++ show other)

-- | Lifetime gate, sequential half: after close every supported
-- execute path answers InvalidState (never touches freed native
-- state), while capability guards still answer first (the
-- guard-before-gate law) and lifecycle releases stay total
-- no-ops. Cached reads keep their characterization: caps still
-- answer, drained resources report gone.
caseLifetimeGateSequential :: IO ()
caseLifetimeGateSequential = do
  r <- openBackend "provider=default" :: IO (EngineResult (BackendEnv OpenSSL4))
  env <- case r of
    EngineFail err -> assertFailure ("openBackend failed: " ++ show err)
    EngineOk e -> pure e
  rid <- expectOk "init" =<< digestInit env D_SHA256
  ref <- expectOk "import" =<< importKey env (KeyBytes (BS.replicate 32 0x17))
  closeBackend env
  expectUnsupported "guard before gate" =<< digestOneShot env D_SHAKE128 "abc"
  expectInvalidState "one-shot post-close" =<< digestOneShot env D_SHA256 "abc"
  expectInvalidState "init post-close" =<< digestInit env D_SHA256
  expectInvalidState "update post-close" =<< digestUpdate env rid "hello"
  expectInvalidState "final post-close" =<< digestFinal env rid
  expectInvalidState "import post-close" =<< importKey env (KeyBytes "x")
  expectInvalidState "export post-close" =<< exportKey env ref
  -- A reference is already imported: the pure passthrough stays
  -- total (no state, no lease) even post-close.
  same <- expectOk "ref passthrough post-close" =<< importKey env (KeyRefMaterial ref)
  assertEqual "passthrough identity" ref same
  releaseResource env rid
  destroyKey env ref
  closeBackend env
  caps <- queryCapabilities env
  assertEqual "backend name post-close" "openssl4" (bcName caps)
  save <- resourceSaveability env rid
  case save of
    ResourceUnsaveable (UnsaveableGone _) -> pure ()
    other -> assertFailure ("expected Gone post-close, got " ++ show other)

-- | Lifetime gate, simultaneous close: concurrent closes serialize
-- into one drain — every closer returns and the backend reads
-- closed after. (The race battery — each execute path vs close,
-- plus cancel-while-closing — lives in OwnershipSpec's lifetime
-- gate group, the suite with the MVar rendezvous helpers.)
caseLifetimeGateSimultaneous :: IO ()
caseLifetimeGateSimultaneous = do
  r <- openBackend "provider=default" :: IO (EngineResult (BackendEnv OpenSSL4))
  env <- case r of
    EngineFail err -> assertFailure ("openBackend failed: " ++ show err)
    EngineOk e -> pure e
  done <- newEmptyMVar
  let closer = closeBackend env >> putMVar done ()
  replicateM_ 8 (forkIO closer)
  replicateM_ 8 (takeMVar done)
  expectInvalidState "post-close one-shot" =<< digestOneShot env D_SHA256 "abc"

mkResId :: Word32 -> EngineResourceId
mkResId = EngineResourceId
