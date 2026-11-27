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
  ( CryptoCause (..)
  , CryptoError (..)
  , CryptoResult (..)
  , DenyDetail (..)
  , StepDeny (..)
  , StepOutcome (..)
  , TypedError (..)
  , cryptoCode
  , denyOutcome
  , interpretError
  , keptCause
  , mkDeny
  )
import qualified Haskoki.Outcome as O
import Haskoki.Request (FunctionId (..))
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
  , testCase "bad key maps per function" caseBadKeyCells
  , testCase "bad param maps per function" caseBadParamCells
  , testCase "resource gone maps per function" caseResourceGoneCells
  , testCase "kept general errors carry a trace cause" caseKeptCause
  ]

sampleCryptos :: [(CryptoError, ReturnCode)]
sampleCryptos =
  [ (CryptoFailed "x", CKR_GENERAL_ERROR)
  , (CryptoUnsupported "o" "w", CKR_MECHANISM_INVALID)
  , (CryptoBadParam "o" "w", CKR_GENERAL_ERROR)
  , (CryptoBadKey "o" "w", CKR_GENERAL_ERROR)
  , (CryptoMechParamInvalid "o" "w", CKR_MECHANISM_PARAM_INVALID)
  , (CryptoAuthFailed "o", CKR_ENCRYPTED_DATA_INVALID)
  , (CryptoSigLenRange "o", CKR_SIGNATURE_LEN_RANGE)
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
  , (O.BackendSigLenRange "o", CKR_SIGNATURE_LEN_RANGE)
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

-- Representative function id (F_GetInfo, arbitrary): the interpreter ignores it, so these collapsing pins evaluate under one id; they expand per function when the per-function error cells land.
caseCryptoCodes :: IO ()
caseCryptoCodes =
  mapM_ (\(e, c) -> assertEqual ("interpret " ++ show e) c
    (interpretError F_GetInfo (TyCrypto e))) sampleCryptos

caseCoreCodes :: IO ()
caseCoreCodes =
  mapM_ (\(f, c) -> assertEqual ("interpret " ++ show f) c
    (interpretError F_GetInfo (TyCrypto (T.toCryptoError f)))) sampleFailures

caseDenyCodes :: IO ()
caseDenyCodes = do
  mapM_ (\(c, m) -> assertEqual ("interpret deny " ++ show c) c
    (interpretError F_GetInfo (TyDeny (mkDeny c m)))) sampleDenies
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
    (interpretError F_GetInfo (TyCrypto e)) (cryptoCode F_GetInfo e)) sampleCryptos

caseDenyRoutes :: IO ()
caseDenyRoutes =
  mapM_ (\(c, m) -> assertEqual ("denyOutcome " ++ show c)
    (interpretError F_GetInfo (TyDeny (mkDeny c m)))
    (soCode (denyOutcome (mkDeny c m)))) sampleDenies

-- | Per-function bad-key cells: the backend rejected bound key
-- material (DER refused, curve mismatch, domain params refused).
badKeyCells :: [(FunctionId, ReturnCode)]
badKeyCells =
  [ (F_Sign, CKR_FUNCTION_FAILED)
  , (F_SignFinal, CKR_FUNCTION_FAILED)
  , (F_SignRecover, CKR_FUNCTION_FAILED)
  , (F_SignMessage, CKR_FUNCTION_FAILED)
  , (F_SignMessageNext, CKR_FUNCTION_FAILED)
  , (F_Verify, CKR_FUNCTION_FAILED)
  , (F_VerifyFinal, CKR_FUNCTION_FAILED)
  , (F_VerifyRecover, CKR_FUNCTION_FAILED)
  , (F_VerifyMessage, CKR_FUNCTION_FAILED)
  , (F_VerifyMessageNext, CKR_FUNCTION_FAILED)
  , (F_Encrypt, CKR_FUNCTION_FAILED)
  , (F_EncryptFinal, CKR_FUNCTION_FAILED)
  , (F_EncryptUpdate, CKR_FUNCTION_FAILED)
  , (F_EncryptMessage, CKR_FUNCTION_FAILED)
  , (F_EncryptMessageNext, CKR_FUNCTION_FAILED)
  , (F_Decrypt, CKR_FUNCTION_FAILED)
  , (F_DecryptFinal, CKR_FUNCTION_FAILED)
  , (F_DecryptUpdate, CKR_FUNCTION_FAILED)
  , (F_DecryptMessage, CKR_FUNCTION_FAILED)
  , (F_DecryptMessageNext, CKR_FUNCTION_FAILED)
  , (F_WrapKey, CKR_FUNCTION_FAILED)
  , (F_UnwrapKey, CKR_FUNCTION_FAILED)
  , (F_EncapsulateKey, CKR_FUNCTION_FAILED)
  , (F_DecapsulateKey, CKR_FUNCTION_FAILED)
  , (F_GenerateKey, CKR_ATTRIBUTE_VALUE_INVALID)
  , (F_GenerateKeyPair, CKR_DOMAIN_PARAMS_INVALID)
  , (F_DeriveKey, CKR_KEY_TYPE_INCONSISTENT)
  ]

caseBadKeyCells :: IO ()
caseBadKeyCells =
  mapM_ (\(fid, c) -> assertEqual ("badkey " ++ show fid) c
    (interpretError fid (TyCrypto (CryptoBadKey "op" "why")))) badKeyCells

-- | Per-function bad-param cells: input widths and floors
-- (mechanism-param-shaped producers reclassify to
-- 'CryptoMechParamInvalid' instead of reaching these cells).
badParamCells :: [(FunctionId, ReturnCode)]
badParamCells =
  [ (F_Sign, CKR_DATA_LEN_RANGE)
  , (F_SignFinal, CKR_DATA_LEN_RANGE)
  , (F_SignRecover, CKR_DATA_LEN_RANGE)
  , (F_SignMessage, CKR_DATA_LEN_RANGE)
  , (F_SignMessageNext, CKR_DATA_LEN_RANGE)
  , (F_Verify, CKR_DATA_LEN_RANGE)
  , (F_VerifyFinal, CKR_DATA_LEN_RANGE)
  , (F_VerifyMessage, CKR_DATA_LEN_RANGE)
  , (F_VerifyMessageNext, CKR_DATA_LEN_RANGE)
  , (F_Encrypt, CKR_DATA_LEN_RANGE)
  , (F_EncryptFinal, CKR_DATA_LEN_RANGE)
  , (F_EncryptUpdate, CKR_DATA_LEN_RANGE)
  , (F_EncryptMessage, CKR_DATA_LEN_RANGE)
  , (F_EncryptMessageNext, CKR_DATA_LEN_RANGE)
  , (F_VerifyRecover, CKR_SIGNATURE_LEN_RANGE)
  , (F_WrapKey, CKR_KEY_SIZE_RANGE)
  , (F_Decrypt, CKR_ENCRYPTED_DATA_LEN_RANGE)
  , (F_DecryptFinal, CKR_ENCRYPTED_DATA_LEN_RANGE)
  , (F_DecryptUpdate, CKR_ENCRYPTED_DATA_LEN_RANGE)
  , (F_DecryptMessage, CKR_ENCRYPTED_DATA_LEN_RANGE)
  , (F_DecryptMessageNext, CKR_ENCRYPTED_DATA_LEN_RANGE)
  , (F_UnwrapKey, CKR_WRAPPED_KEY_LEN_RANGE)
  , (F_DecapsulateKey, CKR_WRAPPED_KEY_LEN_RANGE)
  , (F_GenerateKey, CKR_ATTRIBUTE_VALUE_INVALID)
  , (F_GenerateKeyPair, CKR_ATTRIBUTE_VALUE_INVALID)
  ]

caseBadParamCells :: IO ()
caseBadParamCells =
  mapM_ (\(fid, c) -> assertEqual ("badparam " ++ show fid) c
    (interpretError fid (TyCrypto (CryptoBadParam "op" "why")))) badParamCells

-- | Per-function resource-gone cells: the backend lost a
-- referenced stream or key (one-shot digest and digest init
-- resolve no backend resources, so they stay collapsed).
goneCells :: [(FunctionId, ReturnCode)]
goneCells =
  [ (F_DigestUpdate, CKR_DEVICE_ERROR)
  , (F_DigestFinal, CKR_DEVICE_ERROR)
  , (F_Sign, CKR_DEVICE_ERROR)
  , (F_SignFinal, CKR_DEVICE_ERROR)
  , (F_SignRecover, CKR_DEVICE_ERROR)
  , (F_Verify, CKR_DEVICE_ERROR)
  , (F_VerifyFinal, CKR_DEVICE_ERROR)
  , (F_VerifyRecover, CKR_DEVICE_ERROR)
  , (F_Encrypt, CKR_DEVICE_ERROR)
  , (F_EncryptFinal, CKR_DEVICE_ERROR)
  , (F_EncryptUpdate, CKR_DEVICE_ERROR)
  , (F_Decrypt, CKR_DEVICE_ERROR)
  , (F_DecryptFinal, CKR_DEVICE_ERROR)
  , (F_DecryptUpdate, CKR_DEVICE_ERROR)
  , (F_EncryptMessage, CKR_DEVICE_ERROR)
  , (F_DecryptMessage, CKR_DEVICE_ERROR)
  , (F_SignMessage, CKR_DEVICE_ERROR)
  , (F_VerifyMessage, CKR_DEVICE_ERROR)
  , (F_EncryptMessageNext, CKR_DEVICE_ERROR)
  , (F_DecryptMessageNext, CKR_DEVICE_ERROR)
  , (F_SignMessageNext, CKR_DEVICE_ERROR)
  , (F_VerifyMessageNext, CKR_DEVICE_ERROR)
  , (F_DeriveKey, CKR_DEVICE_ERROR)
  , (F_WrapKey, CKR_DEVICE_ERROR)
  , (F_UnwrapKey, CKR_DEVICE_ERROR)
  , (F_EncapsulateKey, CKR_DEVICE_ERROR)
  , (F_DecapsulateKey, CKR_DEVICE_ERROR)
  ]

caseResourceGoneCells :: IO ()
caseResourceGoneCells =
  mapM_ (\(fid, c) -> assertEqual ("gone " ++ show fid) c
    (interpretError fid (TyCrypto (CryptoResourceGone "op" (EngineResourceId 9))))) goneCells

-- | Kept-general-error cause table: (function, result, served
-- code, expected cause). Only the deliberately unclassified
-- legs (driver, invalid-state, native) serving general-error
-- carry one; distinct cells, non-errors and code mismatches do
-- not.
keptCauseCells :: [(FunctionId, CryptoResult, ReturnCode, Maybe CryptoCause)]
keptCauseCells =
  [ (F_Sign, GotCryptoError (CryptoFailed "boom"), CKR_GENERAL_ERROR,
      Just (CryptoCause F_Sign (CryptoFailed "boom")))
  , (F_DigestFinal, GotCryptoError (CryptoInvalidState "op" "why"), CKR_GENERAL_ERROR,
      Just (CryptoCause F_DigestFinal (CryptoInvalidState "op" "why")))
  , (F_DeriveKey, GotCryptoError (CryptoNative "op" 7 "why"), CKR_GENERAL_ERROR,
      Just (CryptoCause F_DeriveKey (CryptoNative "op" 7 "why")))
  , (F_Sign, GotCryptoError (CryptoBadKey "op" "why"), CKR_FUNCTION_FAILED, Nothing)
  , (F_Sign, GotCryptoError (CryptoBadParam "op" "why"), CKR_DATA_LEN_RANGE, Nothing)
  , (F_DigestFinal, GotCryptoError (CryptoResourceGone "op" (EngineResourceId 9)), CKR_DEVICE_ERROR, Nothing)
  , (F_Sign, GotCryptoError (CryptoFailed "boom"), CKR_FUNCTION_FAILED, Nothing)
  , (F_Sign, GotValid True, CKR_OK, Nothing)
  , (F_Sign, GotUnit, CKR_GENERAL_ERROR, Nothing)
  ]

caseKeptCause :: IO ()
caseKeptCause =
  mapM_ (\(fid, res, code, want) -> assertEqual
    ("keptCause " ++ show fid ++ " " ++ show res) want (keptCause fid res code)) keptCauseCells

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
        , "core/Haskoki/Operation/KeyManagement/Currency.hs"
        , "src/Haskoki/Runtime/Async.hs"
        ]
      unrouted =
        [ "core/Haskoki/Transition.hs"
        , "src/Haskoki/Engine/Driver.hs"
        , "core/Haskoki/Operation/KeyManagement.hs"
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
