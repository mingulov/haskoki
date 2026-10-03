{- | Core owned-value types for the soft token.

Strict records, ordinary algebraic data types, and distinct identifiers.
Native pointers, callbacks, foreign crypto contexts, and SQL connections
must never appear in this module (enforced by
@scripts/check-core-boundary.py@).
-}
module Haskoki.Types
  ( -- * Identifiers
    SlotId (..)
  , TokenId (..)
  , SessionId (..)
  , ObjectId (..)
  , ExternalHandle (..)
  , JobId (..)
  , BindingId (..)
  , EngineResourceId (..)
  , Revision (..)
  , Generation (..)
    -- * Versions and results
  , Pkcs11Version (..)
  , ReturnCode (..)
    -- * One-shot liveness
  , OpState (..)
  , Consumption (..)
    -- * Outcomes
  , Outcome (..)
    -- * Redacted rendering
  , redactShown
  ) where

import Data.Word (Word32)

-- | Identifies a token slot. Distinct from session and object identifiers
-- by construction.
newtype SlotId = SlotId { unSlotId :: Int }
  deriving (Eq, Ord, Show)

-- | Identifies a token instance within a slot.
newtype TokenId = TokenId { unTokenId :: Int }
  deriving (Eq, Ord, Show)

-- | Identifies an open session.
newtype SessionId = SessionId { unSessionId :: Int }
  deriving (Eq, Ord, Show)

-- | Identifies a token or session object.
newtype ObjectId = ObjectId { unObjectId :: Int }
  deriving (Eq, Ord, Show)

-- | Opaque handle value handed to the caller. Never dereferenced inside
-- the model; resolved through the external-handle map.
newtype ExternalHandle = ExternalHandle { unExternalHandle :: Int }
  deriving (Eq, Ord, Show)

-- | Identifies a logical asynchronous job.
newtype JobId = JobId { unJobId :: Int }
  deriving (Eq, Ord, Show)

-- | Identifies a native output binding for async completion delivery.
newtype BindingId = BindingId { unBindingId :: Int }
  deriving (Eq, Ord, Show)

-- | Opaque handle into the runtime-owned effect-resource registry.
-- The model stores this id; the registry owns the native context.
-- Unified: the single definition, 'Word32'-backed to match
-- native handles; @Haskoki.Engine.Backend@ uses this type.
newtype EngineResourceId = EngineResourceId { unEngineResourceId :: Word32 }
  deriving (Eq, Ord, Show)

-- | Per-entity revision for reservation dependency checks.
newtype Revision = Revision { unRevision :: Int }
  deriving (Eq, Ord, Show)

-- | Per-entity generation, bumped on invalidation events (close, logout,
-- destroy). A stale generation rejects dependent reservations.
newtype Generation = Generation { unGeneration :: Int }
  deriving (Eq, Ord, Show)

-- | Supported PKCS#11 interface versions.
data Pkcs11Version
  = Pkcs11_2_40
  | Pkcs11_3_0
  | Pkcs11_3_1
  | Pkcs11_3_2
  deriving (Eq, Ord, Show, Enum, Bounded)

-- | Call return codes needed by the pure core. The full @CK_RV@
-- enumeration is generated from byte-pinned headers; this type only
-- carries what core planning can produce. Later work extends it.
--
-- Async codes: 'CKR_HOST_MEMORY' and 'CKR_FUNCTION_CANCELED' are
-- pinned in all four vendored headers; 'CKR_PENDING' and
-- 'CKR_SESSION_ASYNC_NOT_SUPPORTED' are PKCS#11 3.2 codes, pinned
-- in @spec\/vendor\/pkcs11.h@ only (the async facility
-- is itself 3.2).
data ReturnCode
  = CKR_OK
  | CKR_HOST_MEMORY
  | CKR_FUNCTION_CANCELED
  | CKR_PENDING
  | CKR_SESSION_ASYNC_NOT_SUPPORTED
  | CKR_GENERAL_ERROR
  | CKR_ARGUMENTS_BAD
  | CKR_BUFFER_TOO_SMALL
  | CKR_SESSION_HANDLE_INVALID
  | CKR_SESSION_COUNT
  | CKR_SESSION_READ_ONLY_EXISTS
  | CKR_SESSION_READ_ONLY
  | CKR_TOKEN_NOT_PRESENT
  | CKR_USER_ALREADY_LOGGED_IN
  | CKR_USER_ANOTHER_ALREADY_LOGGED_IN
  | CKR_USER_NOT_LOGGED_IN
  | CKR_PIN_INCORRECT
  | CKR_PIN_LOCKED
  | CKR_CRYPTOKI_NOT_INITIALIZED
  | CKR_CRYPTOKI_ALREADY_INITIALIZED
  | CKR_OBJECT_HANDLE_INVALID
  | CKR_KEY_HANDLE_INVALID
  | CKR_ATTRIBUTE_SENSITIVE
  | CKR_ATTRIBUTE_TYPE_INVALID
  | CKR_ATTRIBUTE_READ_ONLY
  | CKR_ATTRIBUTE_VALUE_INVALID
  | CKR_ACTION_PROHIBITED
  | CKR_TEMPLATE_INCOMPLETE
  | CKR_TEMPLATE_INCONSISTENT
  | CKR_MECHANISM_INVALID
  | CKR_MECHANISM_PARAM_INVALID
  | CKR_OPERATION_ACTIVE
  | CKR_OPERATION_NOT_INITIALIZED
  | CKR_SIGNATURE_INVALID
  | CKR_SIGNATURE_LEN_RANGE
  | CKR_KEY_FUNCTION_NOT_PERMITTED
  | CKR_KEY_TYPE_INCONSISTENT
  | CKR_WRAPPING_KEY_TYPE_INCONSISTENT
  | CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT
  | CKR_CURVE_NOT_SUPPORTED
  | CKR_KEY_SIZE_RANGE
  | CKR_DATA_LEN_RANGE
  | CKR_ENCRYPTED_DATA_INVALID
  | CKR_ENCRYPTED_DATA_LEN_RANGE
  | CKR_KEY_UNEXTRACTABLE
  | CKR_KEY_NOT_WRAPPABLE
  | CKR_STATE_UNSAVEABLE
  | CKR_SAVED_STATE_INVALID
  deriving (Eq, Show)

-- | How many times a one-shot operation consumed its input.
-- (Moved from 'Haskoki.Output': operation staging shares this
-- liveness, and the state leaf cannot import the output planner.)
newtype Consumption = Consumption { consCount :: Int }
  deriving (Eq, Show)

-- | One-shot liveness: live with its consumption count, or
-- terminated (a retry after termination fails cleanly).
data OpState
  = OpLive !Consumption
  | OpDead
  deriving (Eq, Show)

-- | Explicit call outcome placeholder. Per @06-call-and-output-contracts.md@,
-- return values, partial outputs, and error-dependent state changes form one
-- explicit outcome; implementations must not collapse that to @Either@ of a
-- bare return code.
data Outcome a
  = OutcomeOk a
  | OutcomeErr ReturnCode
  deriving (Eq, Show)

-- | Trace-shaped redaction marker: the payload class plus
-- its length, never the payload bytes. Shared by every redacted
-- 'Show' instance (key material, attribute bytes, PINs, secrets)
-- so the shape cannot drift; mirrors the
-- @{"redacted":true,"kind":...,"length":N}@ rendering of
-- 'Haskoki.Runtime.Trace.renderJSONL'.
redactShown :: String -> Int -> String
redactShown kind len =
  "{\"redacted\":true,\"kind\":\"" ++ kind ++ "\",\"length\":"
    ++ show len ++ "}"
