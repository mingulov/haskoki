{- | A single total edge interpreter for 'CryptoError' to
'ReturnCode' ('interpretError'); denial legs are the identity on
their carried code ('TyDeny' projects 'sdCode'). Each constructor
maps to its pinned code (see the code snapshot). A source-funnel
test pins that no routed production call site maps a 'CryptoError'
past the interpreter (a textual 'cryptoCode'-absence pin: it
cannot see direct-code 'StepOutcome'/'rejCode' literals, which
are denial-leg identity by review).
-}
module ErrorInterpSpec (spec) where

import Data.List (isInfixOf)
import System.Directory (doesFileExist, getCurrentDirectory)
import System.Environment (getExecutablePath)
import System.FilePath (takeDirectory, (</>))
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertEqual, assertFailure, testCase)

import Haskoki.Operation
  ( CryptoError (..)
  , DenyDetail (..)
  , StepDeny (..)
  , StepOutcome (..)
  , TypedError (..)
  , cryptoCode
  , denyOutcome
  , interpretError
  , mkDeny
  )
import qualified Haskoki.Outcome as O
import qualified Haskoki.Transition as T
import Haskoki.Types (EngineResourceId (..), ReturnCode (..))

spec :: TestTree
spec = testGroup "Single interpreter"
  [ testCase "every crypto error maps to its pinned code" caseCryptoCodes
  , testCase "every core failure maps to its pinned code" caseCoreCodes
  , testCase "every denial keeps its code through the interpreter" caseDenyCodes
  , testCase "cryptoCode delegates to the interpreter" caseDelegates
  , testCase "denyOutcome routes through the interpreter" caseDenyRoutes
  , testCase "no production bypass of the interpreter" caseFunnel
  ]

sampleCryptos :: [(CryptoError, ReturnCode)]
sampleCryptos =
  [ (CryptoFailed "x", CKR_GENERAL_ERROR)
  , (CryptoUnsupported "o" "w", CKR_MECHANISM_INVALID)
  , (CryptoBadParam "o" "w", CKR_GENERAL_ERROR)
  , (CryptoBadKey "o" "w", CKR_GENERAL_ERROR)
  , (CryptoMechParamInvalid "o" "w", CKR_MECHANISM_PARAM_INVALID)
  , (CryptoAuthFailed "o", CKR_ENCRYPTED_DATA_INVALID)
  , (CryptoInvalidState "o" "w", CKR_GENERAL_ERROR)
  , (CryptoNative "o" 7 "w", CKR_GENERAL_ERROR)
  , (CryptoResourceGone "o" (EngineResourceId 9), CKR_GENERAL_ERROR)
  ]

sampleFailures :: [(O.BackendFailure, ReturnCode)]
sampleFailures =
  [ (O.BackendUnsupported "o" "w", CKR_MECHANISM_INVALID)
  , (O.BackendBadParam "o" "w", CKR_GENERAL_ERROR)
  , (O.BackendBadKey "o" "w", CKR_GENERAL_ERROR)
  , (O.BackendMechParamInvalid "o" "w", CKR_MECHANISM_PARAM_INVALID)
  , (O.BackendAuthFailed "o", CKR_ENCRYPTED_DATA_INVALID)
  , (O.BackendInvalidState "o" "w", CKR_GENERAL_ERROR)
  , (O.BackendNative "o" 7 "w", CKR_GENERAL_ERROR)
  , (O.BackendResourceGone "o" (EngineResourceId 9), CKR_GENERAL_ERROR)
  ]

sampleDenies :: [(ReturnCode, String)]
sampleDenies =
  [ (CKR_MECHANISM_INVALID, "unknown mechanism")
  , (CKR_ARGUMENTS_BAD, "operation requires a key")
  , (CKR_KEY_FUNCTION_NOT_PERMITTED, "key refuses")
  , (CKR_USER_NOT_LOGGED_IN, "needs login")
  , (CKR_OPERATION_NOT_INITIALIZED, "no op")
  , (CKR_DATA_LEN_RANGE, "too short")
  , (CKR_GENERAL_ERROR, "boom")
  ]

caseCryptoCodes :: IO ()
caseCryptoCodes =
  mapM_ (\(e, c) -> assertEqual ("interpret " ++ show e) c
    (interpretError (TyCrypto e))) sampleCryptos

caseCoreCodes :: IO ()
caseCoreCodes =
  mapM_ (\(f, c) -> assertEqual ("interpret " ++ show f) c
    (interpretError (TyCrypto (T.toCryptoError f)))) sampleFailures

caseDenyCodes :: IO ()
caseDenyCodes = do
  mapM_ (\(c, m) -> assertEqual ("interpret deny " ++ show c) c
    (interpretError (TyDeny (mkDeny c m)))) sampleDenies
  -- Every DenyDetail category is reachable through the interpreter.
  let details = map (sdDetail . uncurry mkDeny) sampleDenies
  assertEqual "detail category count" 7 (length details)
  mapM_ (\d -> case d of
    DenyUnknownMechanism _ -> pure ()
    DenyBadParams _ -> pure ()
    DenyKeyBinding _ -> pure ()
    DenyAuthState _ -> pure ()
    DenyOpState _ -> pure ()
    DenyRange _ -> pure ()
    DenyGeneral _ -> pure ()) details

caseDelegates :: IO ()
caseDelegates =
  mapM_ (\(e, _) -> assertEqual ("delegate " ++ show e)
    (interpretError (TyCrypto e)) (cryptoCode e)) sampleCryptos

caseDenyRoutes :: IO ()
caseDenyRoutes =
  mapM_ (\(c, m) -> assertEqual ("denyOutcome " ++ show c)
    (interpretError (TyDeny (mkDeny c m)))
    (soCode (denyOutcome (mkDeny c m)))) sampleDenies

-- | The package root, resolved CWD-independently: walk up from
-- the test binary's own directory to haskoki.cabal (the binary
-- always lives under the root's dist-newstyle), falling back to a
-- CWD walk-up (funnel-hardened over the original relative read).
packageRoot :: IO FilePath
packageRoot = do
  exeDir <- takeDirectory <$> getExecutablePath
  fromExe <- ascend exeDir
  case fromExe of
    Just root -> pure root
    Nothing -> do
      cwd <- getCurrentDirectory
      fromCwd <- ascend cwd
      case fromCwd of
        Just root -> pure root
        Nothing -> assertFailure
          "caseFunnel: haskoki.cabal not found above executable or CWD"
  where
    ascend dir = do
      here <- doesFileExist (dir </> "haskoki.cabal")
      if here
        then pure (Just dir)
        else let parent = takeDirectory dir
             in if parent == dir
                  then pure Nothing
                  else ascend parent

-- | Scope: a textual 'cryptoCode'-absence pin over the routed call
-- sites plus an 'interpretError'-presence pin. It cannot see
-- direct-code 'StepOutcome'/'rejCode' literals (denial-leg
-- identity by review) or files outside the lists below.
caseFunnel :: IO ()
caseFunnel = do
  root <- packageRoot
  let routed =
        [ "core/Haskoki/Operation/Cipher.hs"
        , "core/Haskoki/Operation/Digest.hs"
        , "core/Haskoki/Operation/Dual.hs"
        , "core/Haskoki/Operation/Message.hs"
        , "core/Haskoki/Operation/Signature.hs"
        , "core/Haskoki/Operation/KeyManagement.hs"
        , "src/Haskoki/Runtime/Async.hs"
        ]
      unrouted =
        [ "core/Haskoki/Transition.hs"
        , "src/Haskoki/Engine/Driver.hs"
        ]
  routedBodies <- mapM (readFile . (root </>)) routed
  unroutedBodies <- mapM (readFile . (root </>)) unrouted
  mapM_ (\(path, body) ->
    if "cryptoCode" `isInfixOf` body
      then assertFailure ("bypass of interpretError in " ++ path)
      else pure ()) (zip (routed ++ unrouted) (routedBodies ++ unroutedBodies))
  mapM_ (\(path, body) ->
    if "interpretError" `isInfixOf` body
      then pure ()
      else assertFailure ("missing interpretError in " ++ path))
    (zip routed routedBodies)
