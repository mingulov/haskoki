{- | Detached job documents.
-}
module Haskoki.Runtime.Storage.JobDocs
  ( execStateName
  , nameExecState
  , encodeReturnCode
  , decodeReturnCode
  , encodeJobRecord
  , encodeJobBody
  , decodeJobRecord
  , decodeJobBody
  ) where

import Haskoki.Runtime.Attach ( JobExecState (..))
import Haskoki.Types
  ( Generation (..)
  , ReturnCode (..)
  , TokenId (..)
  )
import Haskoki.Runtime.Storage.Base64
import Haskoki.Runtime.Storage.Encoding
import Haskoki.Runtime.Storage.FixedHex
import Haskoki.Runtime.Storage.Records
import Haskoki.Runtime.Storage.Word64Hex

-- ---------------------------------------------------------------------------
-- Job documents
-- ---------------------------------------------------------------------------

-- | Canonical execution-state names (matching the schema's
-- @CHECK@ constraint).
execStateName :: JobExecState -> String
execStateName s = case s of
  JobQueued -> "queued"
  JobReady -> "ready"
  JobFailed -> "failed"
  JobCanceled -> "canceled"
  JobDelivered -> "delivered"

-- | State name back to state; unknown names fail.
nameExecState :: String -> Maybe JobExecState
nameExecState s = case s of
  "queued" -> Just JobQueued
  "ready" -> Just JobReady
  "failed" -> Just JobFailed
  "canceled" -> Just JobCanceled
  "delivered" -> Just JobDelivered
  _ -> Nothing

-- | Canonical return-code names in stored documents. An explicit
-- table (not 'Show'-derived at decode time): unknown names reject
-- rather than decoding speculatively.
encodeReturnCode :: ReturnCode -> String
encodeReturnCode c = case c of
  CKR_OK -> "CKR_OK"
  CKR_HOST_MEMORY -> "CKR_HOST_MEMORY"
  CKR_FUNCTION_CANCELED -> "CKR_FUNCTION_CANCELED"
  CKR_PENDING -> "CKR_PENDING"
  CKR_SESSION_ASYNC_NOT_SUPPORTED -> "CKR_SESSION_ASYNC_NOT_SUPPORTED"
  CKR_GENERAL_ERROR -> "CKR_GENERAL_ERROR"
  CKR_ARGUMENTS_BAD -> "CKR_ARGUMENTS_BAD"
  CKR_BUFFER_TOO_SMALL -> "CKR_BUFFER_TOO_SMALL"
  CKR_SESSION_HANDLE_INVALID -> "CKR_SESSION_HANDLE_INVALID"
  CKR_SESSION_COUNT -> "CKR_SESSION_COUNT"
  CKR_SESSION_READ_ONLY_EXISTS -> "CKR_SESSION_READ_ONLY_EXISTS"
  CKR_SESSION_READ_ONLY -> "CKR_SESSION_READ_ONLY"
  CKR_TOKEN_NOT_PRESENT -> "CKR_TOKEN_NOT_PRESENT"
  CKR_USER_ALREADY_LOGGED_IN -> "CKR_USER_ALREADY_LOGGED_IN"
  CKR_USER_ANOTHER_ALREADY_LOGGED_IN -> "CKR_USER_ANOTHER_ALREADY_LOGGED_IN"
  CKR_USER_NOT_LOGGED_IN -> "CKR_USER_NOT_LOGGED_IN"
  CKR_PIN_INCORRECT -> "CKR_PIN_INCORRECT"
  CKR_PIN_LOCKED -> "CKR_PIN_LOCKED"
  CKR_CRYPTOKI_NOT_INITIALIZED -> "CKR_CRYPTOKI_NOT_INITIALIZED"
  CKR_CRYPTOKI_ALREADY_INITIALIZED -> "CKR_CRYPTOKI_ALREADY_INITIALIZED"
  CKR_OBJECT_HANDLE_INVALID -> "CKR_OBJECT_HANDLE_INVALID"
  CKR_KEY_HANDLE_INVALID -> "CKR_KEY_HANDLE_INVALID"
  CKR_ATTRIBUTE_SENSITIVE -> "CKR_ATTRIBUTE_SENSITIVE"
  CKR_ATTRIBUTE_TYPE_INVALID -> "CKR_ATTRIBUTE_TYPE_INVALID"
  CKR_ATTRIBUTE_READ_ONLY -> "CKR_ATTRIBUTE_READ_ONLY"
  CKR_ATTRIBUTE_VALUE_INVALID -> "CKR_ATTRIBUTE_VALUE_INVALID"
  CKR_ACTION_PROHIBITED -> "CKR_ACTION_PROHIBITED"
  CKR_TEMPLATE_INCOMPLETE -> "CKR_TEMPLATE_INCOMPLETE"
  CKR_TEMPLATE_INCONSISTENT -> "CKR_TEMPLATE_INCONSISTENT"
  CKR_MECHANISM_INVALID -> "CKR_MECHANISM_INVALID"
  CKR_MECHANISM_PARAM_INVALID -> "CKR_MECHANISM_PARAM_INVALID"
  CKR_OPERATION_ACTIVE -> "CKR_OPERATION_ACTIVE"
  CKR_OPERATION_NOT_INITIALIZED -> "CKR_OPERATION_NOT_INITIALIZED"
  CKR_SIGNATURE_INVALID -> "CKR_SIGNATURE_INVALID"
  CKR_SIGNATURE_LEN_RANGE -> "CKR_SIGNATURE_LEN_RANGE"
  CKR_KEY_FUNCTION_NOT_PERMITTED -> "CKR_KEY_FUNCTION_NOT_PERMITTED"
  CKR_KEY_TYPE_INCONSISTENT -> "CKR_KEY_TYPE_INCONSISTENT"
  CKR_WRAPPING_KEY_TYPE_INCONSISTENT -> "CKR_WRAPPING_KEY_TYPE_INCONSISTENT"
  CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT -> "CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT"
  CKR_CURVE_NOT_SUPPORTED -> "CKR_CURVE_NOT_SUPPORTED"
  CKR_KEY_SIZE_RANGE -> "CKR_KEY_SIZE_RANGE"
  CKR_DATA_LEN_RANGE -> "CKR_DATA_LEN_RANGE"
  CKR_ENCRYPTED_DATA_INVALID -> "CKR_ENCRYPTED_DATA_INVALID"
  CKR_ENCRYPTED_DATA_LEN_RANGE -> "CKR_ENCRYPTED_DATA_LEN_RANGE"
  CKR_KEY_UNEXTRACTABLE -> "CKR_KEY_UNEXTRACTABLE"
  CKR_KEY_NOT_WRAPPABLE -> "CKR_KEY_NOT_WRAPPABLE"
  CKR_STATE_UNSAVEABLE -> "CKR_STATE_UNSAVEABLE"
  CKR_SAVED_STATE_INVALID -> "CKR_SAVED_STATE_INVALID"
  CKR_CANT_LOCK -> "CKR_CANT_LOCK"
  CKR_FUNCTION_FAILED -> "CKR_FUNCTION_FAILED"
  CKR_FUNCTION_NOT_PARALLEL -> "CKR_FUNCTION_NOT_PARALLEL"
  CKR_FUNCTION_NOT_SUPPORTED -> "CKR_FUNCTION_NOT_SUPPORTED"
  CKR_NEED_TO_CREATE_THREADS -> "CKR_NEED_TO_CREATE_THREADS"
  CKR_PIN_LEN_RANGE -> "CKR_PIN_LEN_RANGE"
  CKR_SESSION_EXISTS -> "CKR_SESSION_EXISTS"
  CKR_SESSION_PARALLEL_NOT_SUPPORTED -> "CKR_SESSION_PARALLEL_NOT_SUPPORTED"
  CKR_SLOT_ID_INVALID -> "CKR_SLOT_ID_INVALID"
  CKR_USER_PIN_NOT_INITIALIZED -> "CKR_USER_PIN_NOT_INITIALIZED"
  CKR_USER_TYPE_INVALID -> "CKR_USER_TYPE_INVALID"
  CKR_NO_EVENT -> "CKR_NO_EVENT"
  CKR_DEVICE_ERROR -> "CKR_DEVICE_ERROR"
  CKR_DOMAIN_PARAMS_INVALID -> "CKR_DOMAIN_PARAMS_INVALID"
  CKR_WRAPPED_KEY_LEN_RANGE -> "CKR_WRAPPED_KEY_LEN_RANGE"

-- | Code name back to code; unknown names fail.
decodeReturnCode :: String -> Maybe ReturnCode
decodeReturnCode s = case s of
  "CKR_OK" -> Just CKR_OK
  "CKR_HOST_MEMORY" -> Just CKR_HOST_MEMORY
  "CKR_FUNCTION_CANCELED" -> Just CKR_FUNCTION_CANCELED
  "CKR_PENDING" -> Just CKR_PENDING
  "CKR_SESSION_ASYNC_NOT_SUPPORTED" -> Just CKR_SESSION_ASYNC_NOT_SUPPORTED
  "CKR_GENERAL_ERROR" -> Just CKR_GENERAL_ERROR
  "CKR_ARGUMENTS_BAD" -> Just CKR_ARGUMENTS_BAD
  "CKR_BUFFER_TOO_SMALL" -> Just CKR_BUFFER_TOO_SMALL
  "CKR_SESSION_HANDLE_INVALID" -> Just CKR_SESSION_HANDLE_INVALID
  "CKR_SESSION_COUNT" -> Just CKR_SESSION_COUNT
  "CKR_SESSION_READ_ONLY_EXISTS" -> Just CKR_SESSION_READ_ONLY_EXISTS
  "CKR_SESSION_READ_ONLY" -> Just CKR_SESSION_READ_ONLY
  "CKR_TOKEN_NOT_PRESENT" -> Just CKR_TOKEN_NOT_PRESENT
  "CKR_USER_ALREADY_LOGGED_IN" -> Just CKR_USER_ALREADY_LOGGED_IN
  "CKR_USER_ANOTHER_ALREADY_LOGGED_IN" -> Just CKR_USER_ANOTHER_ALREADY_LOGGED_IN
  "CKR_USER_NOT_LOGGED_IN" -> Just CKR_USER_NOT_LOGGED_IN
  "CKR_PIN_INCORRECT" -> Just CKR_PIN_INCORRECT
  "CKR_PIN_LOCKED" -> Just CKR_PIN_LOCKED
  "CKR_CRYPTOKI_NOT_INITIALIZED" -> Just CKR_CRYPTOKI_NOT_INITIALIZED
  "CKR_CRYPTOKI_ALREADY_INITIALIZED" -> Just CKR_CRYPTOKI_ALREADY_INITIALIZED
  "CKR_OBJECT_HANDLE_INVALID" -> Just CKR_OBJECT_HANDLE_INVALID
  "CKR_KEY_HANDLE_INVALID" -> Just CKR_KEY_HANDLE_INVALID
  "CKR_ATTRIBUTE_SENSITIVE" -> Just CKR_ATTRIBUTE_SENSITIVE
  "CKR_ATTRIBUTE_TYPE_INVALID" -> Just CKR_ATTRIBUTE_TYPE_INVALID
  "CKR_ATTRIBUTE_READ_ONLY" -> Just CKR_ATTRIBUTE_READ_ONLY
  "CKR_ATTRIBUTE_VALUE_INVALID" -> Just CKR_ATTRIBUTE_VALUE_INVALID
  "CKR_ACTION_PROHIBITED" -> Just CKR_ACTION_PROHIBITED
  "CKR_TEMPLATE_INCOMPLETE" -> Just CKR_TEMPLATE_INCOMPLETE
  "CKR_TEMPLATE_INCONSISTENT" -> Just CKR_TEMPLATE_INCONSISTENT
  "CKR_MECHANISM_INVALID" -> Just CKR_MECHANISM_INVALID
  "CKR_MECHANISM_PARAM_INVALID" -> Just CKR_MECHANISM_PARAM_INVALID
  "CKR_OPERATION_ACTIVE" -> Just CKR_OPERATION_ACTIVE
  "CKR_OPERATION_NOT_INITIALIZED" -> Just CKR_OPERATION_NOT_INITIALIZED
  "CKR_SIGNATURE_INVALID" -> Just CKR_SIGNATURE_INVALID
  "CKR_SIGNATURE_LEN_RANGE" -> Just CKR_SIGNATURE_LEN_RANGE
  "CKR_KEY_FUNCTION_NOT_PERMITTED" -> Just CKR_KEY_FUNCTION_NOT_PERMITTED
  "CKR_KEY_TYPE_INCONSISTENT" -> Just CKR_KEY_TYPE_INCONSISTENT
  "CKR_WRAPPING_KEY_TYPE_INCONSISTENT" -> Just CKR_WRAPPING_KEY_TYPE_INCONSISTENT
  "CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT" -> Just CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT
  "CKR_CURVE_NOT_SUPPORTED" -> Just CKR_CURVE_NOT_SUPPORTED
  "CKR_KEY_SIZE_RANGE" -> Just CKR_KEY_SIZE_RANGE
  "CKR_DATA_LEN_RANGE" -> Just CKR_DATA_LEN_RANGE
  "CKR_ENCRYPTED_DATA_INVALID" -> Just CKR_ENCRYPTED_DATA_INVALID
  "CKR_ENCRYPTED_DATA_LEN_RANGE" -> Just CKR_ENCRYPTED_DATA_LEN_RANGE
  "CKR_KEY_UNEXTRACTABLE" -> Just CKR_KEY_UNEXTRACTABLE
  "CKR_KEY_NOT_WRAPPABLE" -> Just CKR_KEY_NOT_WRAPPABLE
  "CKR_STATE_UNSAVEABLE" -> Just CKR_STATE_UNSAVEABLE
  "CKR_SAVED_STATE_INVALID" -> Just CKR_SAVED_STATE_INVALID
  "CKR_CANT_LOCK" -> Just CKR_CANT_LOCK
  "CKR_FUNCTION_FAILED" -> Just CKR_FUNCTION_FAILED
  "CKR_FUNCTION_NOT_PARALLEL" -> Just CKR_FUNCTION_NOT_PARALLEL
  "CKR_FUNCTION_NOT_SUPPORTED" -> Just CKR_FUNCTION_NOT_SUPPORTED
  "CKR_NEED_TO_CREATE_THREADS" -> Just CKR_NEED_TO_CREATE_THREADS
  "CKR_PIN_LEN_RANGE" -> Just CKR_PIN_LEN_RANGE
  "CKR_SESSION_EXISTS" -> Just CKR_SESSION_EXISTS
  "CKR_SESSION_PARALLEL_NOT_SUPPORTED" -> Just CKR_SESSION_PARALLEL_NOT_SUPPORTED
  "CKR_SLOT_ID_INVALID" -> Just CKR_SLOT_ID_INVALID
  "CKR_USER_PIN_NOT_INITIALIZED" -> Just CKR_USER_PIN_NOT_INITIALIZED
  "CKR_USER_TYPE_INVALID" -> Just CKR_USER_TYPE_INVALID
  "CKR_NO_EVENT" -> Just CKR_NO_EVENT
  "CKR_DEVICE_ERROR" -> Just CKR_DEVICE_ERROR
  "CKR_DOMAIN_PARAMS_INVALID" -> Just CKR_DOMAIN_PARAMS_INVALID
  "CKR_WRAPPED_KEY_LEN_RANGE" -> Just CKR_WRAPPED_KEY_LEN_RANGE
  _ -> Nothing

-- | Canonical job document bytes.
encodeJobRecord :: JobRecord -> String
encodeJobRecord j = renderJson $ JObject
  [ ("format_version", JNumber (fromIntegral recordFormatVersion))
  , ("persistent_id", JString (encodeHexWord64 (jrPersistentId j)))
  , ("token_id", JString (encodeHex16 (unTokenId (jrToken j))))
  , ("token_generation", JString (encodeHex16 (unGeneration (jrTokenGeneration j))))
  , ("function", JString (jrFunction j))
  , ("state", JString (execStateName (jrState j)))
  , ("body", encodeJobBody (jrBody j))
  ]

-- | Canonical job-body sub-document.
encodeJobBody :: JobBody -> Json
encodeJobBody b = case b of
  JobPending recipe params -> JObject
    [ ("kind", JString "recipe")
    , ("recipe", JString recipe)
    , ("params", JString (encodeBase64 params))
    ]
  JobResult code bytes -> JObject
    [ ("kind", JString "result")
    , ("code", JString (encodeReturnCode code))
    , ("bytes", JString (encodeBase64 bytes))
    ]

-- | Decode a job document; unknown format versions, states, body
-- kinds, and codes all fail.
decodeJobRecord :: String -> Maybe JobRecord
decodeJobRecord s = do
  JObject kvs <- parseJson s
  JNumber v <- lookupField "format_version" kvs
  if v /= fromIntegral recordFormatVersion then Nothing else do
    pid <- lookupField "persistent_id" kvs >>= asString >>= decodeHexWord64
    tid <- lookupField "token_id" kvs >>= asString >>= decodeHex16
    gen <- lookupField "token_generation" kvs >>= asString >>= decodeHex16
    fun <- lookupField "function" kvs >>= asString
    stName <- lookupField "state" kvs >>= asString
    st <- nameExecState stName
    bodyJson <- lookupField "body" kvs >>= asObject
    body <- decodeJobBody bodyJson
    pure JobRecord
      { jrPersistentId = pid
      , jrToken = TokenId tid
      , jrTokenGeneration = Generation gen
      , jrFunction = fun
      , jrState = st
      , jrBody = body
      }

-- | Decode a job-body sub-document.
decodeJobBody :: [(String, Json)] -> Maybe JobBody
decodeJobBody kvs = do
  kind <- lookupField "kind" kvs >>= asString
  case kind of
    "recipe" -> do
      recipe <- lookupField "recipe" kvs >>= asString
      params <- lookupField "params" kvs >>= asString >>= decodeBase64
      pure (JobPending recipe params)
    "result" -> do
      codeName <- lookupField "code" kvs >>= asString
      code <- decodeReturnCode codeName
      bytes <- lookupField "bytes" kvs >>= asString >>= decodeBase64
      pure (JobResult code bytes)
    _ -> Nothing
