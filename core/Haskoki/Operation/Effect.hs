{- | Planned-crypto currency between planners and drivers (pure).

'CryptoEffect' is one planned unit of crypto, 'CryptoResult' the
driver's answer, 'CryptoError' the typed failure. Split from
'Haskoki.Operation': 'Haskoki.Outcome' carries effects on
'EffectCrypto', and importing the whole planner there would cycle
(@Object -> Outcome -> Operation -> Object@). This leaf imports only
'Haskoki.Operation.State' and 'Haskoki.Registry'; 'Haskoki.Operation'
re-exports it, so existing importers are unaffected.

The denial vocabulary ('StepDeny', 'DenyDetail') and the single edge
interpreter ('TypedError', 'interpretError') live here too:
every planner submodule and the key manager import this leaf, so the
funnel has no import cycle.
-}
module Haskoki.Operation.Effect
  ( CryptoError (..)
  , cryptoCode
  , CryptoEffect (..)
  , CryptoResult (..)
  , DenyDetail (..)
  , StepDeny (..)
  , mkDeny
  , prettyDeny
  , sdReason
  , TypedError (..)
  , interpretError
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS

import Haskoki.Operation.State (CipherDir (..))
import Haskoki.Registry (MechanismId)
import Haskoki.Types
  ( EngineResourceId
  , ObjectId
  , ReturnCode (..)
  , redactShown
  )

-- | A typed crypto failure reported by a driver. The eight structured
-- cases mirror the backend failure taxonomy one-to-one, so
-- adapters preserve every category with its fields instead of
-- concatenating strings; 'CryptoFailed' is the unclassified
-- driver-malfunction bucket only. Finishers map failures onto return
-- codes ('cryptoCode').
data CryptoError
  = CryptoFailed !String
  | CryptoUnsupported !String !String
  | CryptoBadParam !String !String
  | CryptoBadKey !String !String
  | CryptoMechParamInvalid !String !String
  | CryptoAuthFailed !String
  | CryptoInvalidState !String !String
  | CryptoNative !String !Int !String
  | CryptoResourceGone !String !EngineResourceId
  deriving (Eq, Show)

-- | Return code for a reported crypto failure: the crypto leg of
-- the single edge interpreter ('interpretError').
cryptoCode :: CryptoError -> ReturnCode
cryptoCode e = interpretError (TyCrypto e)

-- | Typed denial detail: the matchable category behind a
-- denial, carrying the diagnostic message. Every producer classifies
-- by its pinned return code ('mkDeny'); the edge matches the
-- constructor instead of parsing English text.
data DenyDetail
  = DenyUnknownMechanism !String
  | DenyBadParams !String
  | DenyKeyBinding !String
  | DenyAuthState !String
  | DenyOpState !String
  | DenyRange !String
  | DenyGeneral !String
  deriving (Eq, Show)

-- | Build a denial: the pinned code plus the category it names. The
-- code is the producer's unchanged choice (see
-- tests/fixtures/error-code-snapshot.txt); the category is a pure
-- function of that code.
mkDeny :: ReturnCode -> String -> StepDeny
mkDeny code why = StepDeny code (detailFor code why)

-- | The single code->category table. Total: codes no producer denies
-- with (including 'CKR_OK') classify as 'DenyGeneral'.
detailFor :: ReturnCode -> String -> DenyDetail
detailFor code why = case code of
  CKR_MECHANISM_INVALID -> DenyUnknownMechanism why
  CKR_MECHANISM_PARAM_INVALID -> DenyBadParams why
  CKR_ARGUMENTS_BAD -> DenyBadParams why
  CKR_TEMPLATE_INCOMPLETE -> DenyBadParams why
  CKR_TEMPLATE_INCONSISTENT -> DenyBadParams why
  CKR_ATTRIBUTE_SENSITIVE -> DenyBadParams why
  CKR_ATTRIBUTE_TYPE_INVALID -> DenyBadParams why
  CKR_ATTRIBUTE_READ_ONLY -> DenyBadParams why
  CKR_ATTRIBUTE_VALUE_INVALID -> DenyBadParams why
  CKR_ACTION_PROHIBITED -> DenyKeyBinding why
  CKR_OBJECT_HANDLE_INVALID -> DenyBadParams why
  CKR_KEY_HANDLE_INVALID -> DenyBadParams why
  CKR_KEY_FUNCTION_NOT_PERMITTED -> DenyKeyBinding why
  CKR_KEY_UNEXTRACTABLE -> DenyKeyBinding why
  CKR_KEY_NOT_WRAPPABLE -> DenyKeyBinding why
  CKR_KEY_TYPE_INCONSISTENT -> DenyKeyBinding why
  CKR_WRAPPING_KEY_TYPE_INCONSISTENT -> DenyKeyBinding why
  CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT -> DenyKeyBinding why
  CKR_CURVE_NOT_SUPPORTED -> DenyKeyBinding why
  CKR_USER_NOT_LOGGED_IN -> DenyAuthState why
  CKR_USER_ALREADY_LOGGED_IN -> DenyAuthState why
  CKR_USER_ANOTHER_ALREADY_LOGGED_IN -> DenyAuthState why
  CKR_PIN_INCORRECT -> DenyAuthState why
  CKR_PIN_LOCKED -> DenyAuthState why
  CKR_SIGNATURE_INVALID -> DenyAuthState why
  CKR_ENCRYPTED_DATA_INVALID -> DenyAuthState why
  CKR_OPERATION_ACTIVE -> DenyOpState why
  CKR_OPERATION_NOT_INITIALIZED -> DenyOpState why
  CKR_SESSION_HANDLE_INVALID -> DenyOpState why
  CKR_SESSION_COUNT -> DenyOpState why
  CKR_SESSION_READ_ONLY_EXISTS -> DenyOpState why
  CKR_SESSION_READ_ONLY -> DenyOpState why
  CKR_TOKEN_NOT_PRESENT -> DenyOpState why
  CKR_CRYPTOKI_NOT_INITIALIZED -> DenyOpState why
  CKR_CRYPTOKI_ALREADY_INITIALIZED -> DenyOpState why
  CKR_STATE_UNSAVEABLE -> DenyOpState why
  CKR_SAVED_STATE_INVALID -> DenyOpState why
  CKR_KEY_SIZE_RANGE -> DenyRange why
  CKR_DATA_LEN_RANGE -> DenyRange why
  CKR_ENCRYPTED_DATA_LEN_RANGE -> DenyRange why
  CKR_BUFFER_TOO_SMALL -> DenyRange why
  _ -> DenyGeneral why

-- | Render a typed denial at the boundary. The single renderer:
-- every denial message in reasons text comes from here, and the
-- payload is the producer's unchanged text.
prettyDeny :: DenyDetail -> String
prettyDeny detail = case detail of
  DenyUnknownMechanism m -> m
  DenyBadParams m -> m
  DenyKeyBinding m -> m
  DenyAuthState m -> m
  DenyOpState m -> m
  DenyRange m -> m
  DenyGeneral m -> m

-- | Why a data call was denied: the pinned code plus the typed
-- detail. Render with 'prettyDeny' ('sdReason') at the boundary.
data StepDeny = StepDeny
  { sdCode :: !ReturnCode
  , sdDetail :: !DenyDetail
  } deriving (Eq, Show)

-- | The rendered denial reason: the boundary rendering of the typed
-- detail. Kept so rejection paths keep their exact text.
sdReason :: StepDeny -> String
sdReason = prettyDeny . sdDetail

-- | The unified typed error: every failure the core reports
-- reaches the edge as one of these and is interpreted exactly once.
data TypedError
  = TyDeny !StepDeny
  | TyCrypto !CryptoError
  deriving (Eq, Show)

-- | The single total 'CryptoError' interpreter: the ONLY production
-- mapping from crypto failures to return codes. Denials keep their
-- pinned code by identity ('TyDeny' projects 'sdCode'), including
-- the closings that bypass textually ('rejectDeny', 'rejectOf',
-- 'rejCode'/'StepOutcome' literals — semantic identity by review);
-- crypto failures map here: unsupported stays
-- mechanism-invalid (never a silent substitution); a bytes-shaped
-- authentication failure (rejected KEM ciphertext or wrap tag) is
-- encrypted-data-invalid; anything else is a general failure.
-- Verify-shaped calls report authentication as a verdict ('GotValid
-- False'), never through an error. Backend failures normalize
-- through the adapters first ('toCryptoError' in either layer, then
-- 'TyCrypto'). Every crypto-to-code leg routes through here
-- (pinned by the funnel test). Every case maps to the code its
-- collapse produced (see tests/fixtures/error-code-snapshot.txt).
interpretError :: TypedError -> ReturnCode
interpretError terr = case terr of
  TyDeny d -> sdCode d
  TyCrypto e -> case e of
    CryptoFailed _ -> CKR_GENERAL_ERROR
    CryptoUnsupported _ _ -> CKR_MECHANISM_INVALID
    CryptoBadParam _ _ -> CKR_GENERAL_ERROR
    CryptoBadKey _ _ -> CKR_GENERAL_ERROR
    CryptoMechParamInvalid _ _ -> CKR_MECHANISM_PARAM_INVALID
    CryptoAuthFailed _ -> CKR_ENCRYPTED_DATA_INVALID
    CryptoInvalidState _ _ -> CKR_GENERAL_ERROR
    CryptoNative _ _ _ -> CKR_GENERAL_ERROR
    CryptoResourceGone _ _ -> CKR_GENERAL_ERROR

-- | One planned unit of crypto: the family, mechanism, bound key
-- object, opaque parameters, and the full input the driver executes
-- over. Buffered updates plan no effects; finals and one-shots plan
-- exactly one. Key-management planners likewise plan exactly
-- one effect per call; their finishers publish the pending key
-- objects. Digest multipart streams instead: the init
-- allocates a backend context ('FxDigestInit'), each update feeds
-- it ('FxDigestFeed'), and the final consumes it ('FxDigestConsume').
data CryptoEffect
  = FxDigest
      { fxMech :: !MechanismId
      , fxInput :: !ByteString
      }
  | FxDigestInit
      { fxMech :: !MechanismId
      }
  | FxDigestFeed
      { fxResource :: !EngineResourceId
      , fxInput :: !ByteString
      }
  | FxDigestConsume
      { fxResource :: !EngineResourceId
      }
  | FxCipher
      { fxDir :: !CipherDir
      , fxMech :: !MechanismId
      , fxKey :: !(Maybe ObjectId)
      , fxParams :: !ByteString
      , fxInput :: !ByteString
      }
  | FxSign
      { fxMech :: !MechanismId
      , fxKey :: !(Maybe ObjectId)
      , fxParams :: !ByteString
      , fxInput :: !ByteString
      }
  | FxVerify
      { fxMech :: !MechanismId
      , fxKey :: !(Maybe ObjectId)
      , fxParams :: !ByteString
      , fxInput :: !ByteString
      , fxSig :: !ByteString
      }
  | FxSignRecover
      { fxMech :: !MechanismId
      , fxKey :: !(Maybe ObjectId)
      , fxParams :: !ByteString
      , fxInput :: !ByteString
      , fxTagLen :: !Int
      }
  | FxVerifyRecover
      { fxMech :: !MechanismId
      , fxKey :: !(Maybe ObjectId)
      , fxParams :: !ByteString
      , fxSig :: !ByteString
      , fxTagLen :: !Int
      }
  | FxMessageCipher
      { fxDir :: !CipherDir
      , fxMech :: !MechanismId
      , fxKey :: !(Maybe ObjectId)
      , fxParams :: !ByteString
      , fxAad :: !ByteString
      , fxInput :: !ByteString
      }
  | FxMessageSign
      { fxMech :: !MechanismId
      , fxKey :: !(Maybe ObjectId)
      , fxParams :: !ByteString
      , fxInput :: !ByteString
      }
  | FxMessageVerify
      { fxMech :: !MechanismId
      , fxKey :: !(Maybe ObjectId)
      , fxParams :: !ByteString
      , fxInput :: !ByteString
      , fxSig :: !ByteString
      }
  | FxGenerateKey
      { fxMech :: !MechanismId
      , fxParams :: !ByteString
      , fxInput :: !ByteString
      }
  | FxWrap
      { fxMech :: !MechanismId
      , fxKey :: !(Maybe ObjectId)
      , fxParams :: !ByteString
      , fxInput :: !ByteString
      }
  | FxUnwrap
      { fxMech :: !MechanismId
      , fxKey :: !(Maybe ObjectId)
      , fxParams :: !ByteString
      , fxInput :: !ByteString
      }
  | FxAuthWrap
      { fxMech :: !MechanismId
      , fxKey :: !(Maybe ObjectId)
      , fxParams :: !ByteString
      , fxInput :: !ByteString
      }
  | FxAuthUnwrap
      { fxMech :: !MechanismId
      , fxKey :: !(Maybe ObjectId)
      , fxParams :: !ByteString
      , fxInput :: !ByteString
      }
  | FxDerive
      { fxMech :: !MechanismId
      , fxKey :: !(Maybe ObjectId)
      , fxParams :: !ByteString
      , fxInput :: !ByteString
      , fxLen :: !Int
      }
  | FxKemEncaps
      { fxMech :: !MechanismId
      , fxKey :: !(Maybe ObjectId)
      , fxParams :: !ByteString
      , fxInput :: !ByteString
      }
  | FxKemDecaps
      { fxMech :: !MechanismId
      , fxKey :: !(Maybe ObjectId)
      , fxParams :: !ByteString
      , fxInput :: !ByteString
      }
  deriving (Eq)

-- | 'Show' redacts exactly the wrap inputs: 'FxWrap' and
-- 'FxAuthWrap' carry padded target key material in 'fxInput', so
-- that field renders its kind and length only ('redactShown').
-- Every other variant carries operation data (plaintext,
-- ciphertexts, signatures, parameters), which renders normally:
-- secrets are distinguished from ordinary data, not blanket
-- hidden. Explicit inspection pattern-matches the exported
-- constructors (never 'Show').
instance Show CryptoEffect where
  show (FxDigest mech input) =
    showFx "FxDigest" [("fxMech", show mech), ("fxInput", show input)]
  show (FxDigestInit mech) =
    showFx "FxDigestInit" [("fxMech", show mech)]
  show (FxDigestFeed res input) =
    showFx "FxDigestFeed" [("fxResource", show res), ("fxInput", show input)]
  show (FxDigestConsume res) =
    showFx "FxDigestConsume" [("fxResource", show res)]
  show (FxCipher dir mech key params input) = showFx "FxCipher"
    [ ("fxDir", show dir), ("fxMech", show mech), ("fxKey", show key)
    , ("fxParams", show params), ("fxInput", show input)
    ]
  show (FxSign mech key params input) = showFx "FxSign"
    [ ("fxMech", show mech), ("fxKey", show key)
    , ("fxParams", show params), ("fxInput", show input)
    ]
  show (FxVerify mech key params input sig) = showFx "FxVerify"
    [ ("fxMech", show mech), ("fxKey", show key)
    , ("fxParams", show params), ("fxInput", show input)
    , ("fxSig", show sig)
    ]
  show (FxSignRecover mech key params input tagLen) = showFx "FxSignRecover"
    [ ("fxMech", show mech), ("fxKey", show key)
    , ("fxParams", show params), ("fxInput", show input)
    , ("fxTagLen", show tagLen)
    ]
  show (FxVerifyRecover mech key params sig tagLen) = showFx "FxVerifyRecover"
    [ ("fxMech", show mech), ("fxKey", show key)
    , ("fxParams", show params), ("fxSig", show sig)
    , ("fxTagLen", show tagLen)
    ]
  show (FxMessageCipher dir mech key params aad input) = showFx "FxMessageCipher"
    [ ("fxDir", show dir), ("fxMech", show mech), ("fxKey", show key)
    , ("fxParams", show params), ("fxAad", show aad), ("fxInput", show input)
    ]
  show (FxMessageSign mech key params input) = showFx "FxMessageSign"
    [ ("fxMech", show mech), ("fxKey", show key)
    , ("fxParams", show params), ("fxInput", show input)
    ]
  show (FxMessageVerify mech key params input sig) = showFx "FxMessageVerify"
    [ ("fxMech", show mech), ("fxKey", show key)
    , ("fxParams", show params), ("fxInput", show input)
    , ("fxSig", show sig)
    ]
  show (FxGenerateKey mech params input) = showFx "FxGenerateKey"
    [ ("fxMech", show mech), ("fxParams", show params)
    , ("fxInput", show input)
    ]
  show (FxWrap mech key params input) = showFx "FxWrap"
    [ ("fxMech", show mech), ("fxKey", show key)
    , ("fxParams", show params)
    , ("fxInput", redactShown "key" (BS.length input))
    ]
  show (FxUnwrap mech key params input) = showFx "FxUnwrap"
    [ ("fxMech", show mech), ("fxKey", show key)
    , ("fxParams", show params), ("fxInput", show input)
    ]
  show (FxAuthWrap mech key params input) = showFx "FxAuthWrap"
    [ ("fxMech", show mech), ("fxKey", show key)
    , ("fxParams", show params)
    , ("fxInput", redactShown "key" (BS.length input))
    ]
  show (FxAuthUnwrap mech key params input) = showFx "FxAuthUnwrap"
    [ ("fxMech", show mech), ("fxKey", show key)
    , ("fxParams", show params), ("fxInput", show input)
    ]
  show (FxDerive mech key params input len) = showFx "FxDerive"
    [ ("fxMech", show mech), ("fxKey", show key)
    , ("fxParams", show params), ("fxInput", show input)
    , ("fxLen", show len)
    ]
  show (FxKemEncaps mech key params input) = showFx "FxKemEncaps"
    [ ("fxMech", show mech), ("fxKey", show key)
    , ("fxParams", show params), ("fxInput", show input)
    ]
  show (FxKemDecaps mech key params input) = showFx "FxKemDecaps"
    [ ("fxMech", show mech), ("fxKey", show key)
    , ("fxParams", show params), ("fxInput", show input)
    ]

-- | Record-style rendering for one effect variant.
showFx :: String -> [(String, String)] -> String
showFx name fields =
  name ++ " {" ++ join ", " [k ++ " = " ++ v | (k, v) <- fields] ++ "}"
  where
    join _ [] = ""
    join _ [x] = x
    join sep (x : xs) = x ++ sep ++ join sep xs

-- | The driver's answer to one planned effect: output bytes, a
-- verification verdict, an allocated backend resource, a unit feed
-- acknowledgment, or a typed failure. A resource answer belongs
-- only to allocation finishers; a unit answer belongs only to feed
-- steps — anywhere else they are driver-protocol violations. 'GotUnit'
-- keeps feed answers unit-typed through the driver
-- helpers, distinct from empty bytes, until 'encodeResult'.
data CryptoResult
  = GotBytes !ByteString
  | GotValid !Bool
  | GotResource !EngineResourceId
  | GotUnit
  | GotCryptoError !CryptoError
  deriving (Eq)

-- | 'Show' redacts answer bytes: 'GotBytes' carries fresh
-- key material on key-management answers (and operation outputs
-- elsewhere), and the value does not say which, so it renders its
-- kind and length only ('redactShown'). Verdicts, resources, unit
-- acknowledgments, and typed failures render normally. Explicit
-- inspection pattern-matches the exported constructors (never 'Show').
instance Show CryptoResult where
  show (GotBytes bs) = "GotBytes " ++ redactShown "bytes" (BS.length bs)
  show (GotValid b) = "GotValid " ++ show b
  show (GotResource r) = "GotResource " ++ show r
  show GotUnit = "GotUnit"
  show (GotCryptoError e) = "GotCryptoError " ++ show e
