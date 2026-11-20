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
    -- * Retained-size accounting
  , retainedStringBytes
  ) where

import Data.Word (Word32)

-- Re-exported: the type lives generated in
-- Haskoki.ReturnCode.Generated (single authority).
import Haskoki.ReturnCode.Generated (ReturnCode (..))

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

-- | Heap upper bound for a retained 'String' (a @[Char]@ list):
-- 48 bytes per character. A cons cell is 3 words and a boxed
-- 'Char' is 2 words, so 40 bytes per character on 64-bit
-- architectures (+8 margin); 32-bit heaps are smaller, so the
-- bound holds there too. Used by retention accounting (the
-- 'Haskoki.Runtime.Async.retainedBytes' contract), where short
-- trust-boundary texts (operation names,
-- region names, failure renders) are the only 'String's pinned
-- per record.
retainedStringBytes :: String -> Int
retainedStringBytes = (48 *) . length
