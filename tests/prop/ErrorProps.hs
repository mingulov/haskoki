{- | Error laws: 'interpretError' exhaustiveness over every
'TypedError' constructor, pinned to the code snapshot.
-}
module ErrorProps (spec) where

import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertEqual, testCase)
import Test.Tasty.QuickCheck (Gen, Property, elements, forAll)

import Gen (propWith)
import Haskoki.Operation.Effect
  ( CryptoError (..)
  , DenyDetail (..)
  , StepDeny (..)
  , TypedError (..)
  , interpretError
  , mkDeny
  , sdCode
  )
import Haskoki.Types (EngineResourceId (..), ReturnCode (..))

spec :: Int -> TestTree
spec count =
  testGroup
    "error laws"
    [ propWith "deny passthrough" 201 count pDenyPassthrough
    , testCase "deny passthrough exhaustive" caseDenyExhaustive
    , testCase "crypto exhaustiveness" caseCrypto
    , testCase "mkDeny preserves code" caseMkDeny
    ]

-- | All 38 return codes (Types.hs), enumerated.
allCodes :: [ReturnCode]
allCodes =
  [ CKR_OK
  , CKR_HOST_MEMORY
  , CKR_FUNCTION_CANCELED
  , CKR_PENDING
  , CKR_SESSION_ASYNC_NOT_SUPPORTED
  , CKR_GENERAL_ERROR
  , CKR_ARGUMENTS_BAD
  , CKR_BUFFER_TOO_SMALL
  , CKR_SESSION_HANDLE_INVALID
  , CKR_SESSION_COUNT
  , CKR_SESSION_READ_ONLY_EXISTS
  , CKR_SESSION_READ_ONLY
  , CKR_TOKEN_NOT_PRESENT
  , CKR_USER_ALREADY_LOGGED_IN
  , CKR_USER_ANOTHER_ALREADY_LOGGED_IN
  , CKR_USER_NOT_LOGGED_IN
  , CKR_PIN_INCORRECT
  , CKR_PIN_LOCKED
  , CKR_CRYPTOKI_NOT_INITIALIZED
  , CKR_CRYPTOKI_ALREADY_INITIALIZED
  , CKR_OBJECT_HANDLE_INVALID
  , CKR_ATTRIBUTE_SENSITIVE
  , CKR_ATTRIBUTE_TYPE_INVALID
  , CKR_TEMPLATE_INCOMPLETE
  , CKR_TEMPLATE_INCONSISTENT
  , CKR_MECHANISM_INVALID
  , CKR_MECHANISM_PARAM_INVALID
  , CKR_OPERATION_ACTIVE
  , CKR_OPERATION_NOT_INITIALIZED
  , CKR_SIGNATURE_INVALID
  , CKR_KEY_FUNCTION_NOT_PERMITTED
  , CKR_DATA_LEN_RANGE
  , CKR_ENCRYPTED_DATA_INVALID
  , CKR_ENCRYPTED_DATA_LEN_RANGE
  , CKR_KEY_UNEXTRACTABLE
  , CKR_KEY_NOT_WRAPPABLE
  , CKR_STATE_UNSAVEABLE
  , CKR_SAVED_STATE_INVALID
  ]

-- | One representative per denial category (detail is irrelevant to
-- the interpreter; the code is what the law pins).
allDetails :: [DenyDetail]
allDetails =
  [ DenyUnknownMechanism "m"
  , DenyBadParams "m"
  , DenyKeyBinding "m"
  , DenyAuthState "m"
  , DenyOpState "m"
  , DenyRange "m"
  , DenyGeneral "m"
  ]

genDeny :: Gen StepDeny
genDeny = StepDeny <$> elements allCodes <*> elements allDetails

-- | Denials keep their pinned code through the interpreter.
pDenyPassthrough :: Property
pDenyPassthrough = forAll genDeny $ \d ->
  interpretError (TyDeny d) == sdCode d

-- | The full 38x7=266 (code,detail) space, enumerated
-- deterministically: the QC sampler above can miss codes
-- at default counts, so the strongest available property — every
-- pair keeps its code — runs as a seed-independent testCase.
caseDenyExhaustive :: IO ()
caseDenyExhaustive =
  mapM_ check [(code, det) | code <- allCodes, det <- allDetails]
  where
    check :: (ReturnCode, DenyDetail) -> IO ()
    check (code, det) =
      assertEqual ("interpret (TyDeny " ++ show code ++ " " ++ show det ++ ")")
        code
        (interpretError (TyDeny (StepDeny code det)))

-- | Every crypto failure maps to its pinned code. Four rows
-- (Failed, Unsupported, BadKey, AuthFailed) cross-check
-- tests/fixtures/code-snapshot.txt; the other four pin the
-- Effect.hs interpreter table.
cryptoPins :: [(CryptoError, ReturnCode)]
cryptoPins =
  [ (CryptoFailed "f", CKR_GENERAL_ERROR)
  , (CryptoUnsupported "o" "w", CKR_MECHANISM_INVALID)
  , (CryptoBadParam "o" "w", CKR_GENERAL_ERROR)
  , (CryptoBadKey "o" "w", CKR_GENERAL_ERROR)
  , (CryptoAuthFailed "d", CKR_ENCRYPTED_DATA_INVALID)
  , (CryptoInvalidState "o" "w", CKR_GENERAL_ERROR)
  , (CryptoNative "n" (-1) "m", CKR_GENERAL_ERROR)
  , (CryptoResourceGone "r" (EngineResourceId 7), CKR_GENERAL_ERROR)
  ]

caseCrypto :: IO ()
caseCrypto = mapM_ checkPin cryptoPins
  where
    checkPin :: (CryptoError, ReturnCode) -> IO ()
    checkPin (err, want) =
      assertEqual ("interpret " ++ show err) want
        (interpretError (TyCrypto err))

caseMkDeny :: IO ()
caseMkDeny = mapM_ checkCode allCodes
  where
    checkCode :: ReturnCode -> IO ()
    checkCode code =
      assertEqual ("mkDeny " ++ show code) code
        (sdCode (mkDeny code "why"))
