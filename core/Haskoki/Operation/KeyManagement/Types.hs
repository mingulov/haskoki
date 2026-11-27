{- | KeyManagement plan-currency types: denials, plans, and the
pending objects/work the finishers publish.

Leaf module: data only, shared by Template, the planners, and the
shell (re-exported).
-}
module Haskoki.Operation.KeyManagement.Types
  ( KeyDeny (..)
  , KeyPlan (..)
  , PendingObject (..)
  , PendingWork (..)
  , KeygenLens (..)
  ) where

import Data.Map.Strict (Map)
import Data.Word (Word64)

import Haskoki.Attribute (AttributeType, AttributeValue)
import Haskoki.Operation.Effect (CryptoEffect)
import Haskoki.Outcome (PlanResult)
import Haskoki.Types (ReturnCode, SessionId, SlotId)

-- | Why a key-management call was denied.
data KeyDeny = KeyDeny
  { kdCode :: !ReturnCode
  , kdReason :: !String
  } deriving (Eq, Show)

-- | One key-management plan: a denial (no objects, no outputs), an
-- immediate outcome (length queries and short buffers, likewise
-- object-free), or exactly one effect plus the pending work its
-- answer completes.
data KeyPlan
  = KeyDenied !KeyDeny
  | KeyImmediate !PlanResult
  | KeyEffect !PendingWork !CryptoEffect
  deriving (Eq, Show)

-- | One object awaiting publication: its full attributes, its
-- lifetime owner ('Nothing' = token object) and its home slot.
data PendingObject = PendingObject
  { poAttrs :: !(Map AttributeType AttributeValue)
  , poOwner :: !(Maybe SessionId)
  , poSlot :: !SlotId
  } deriving (Eq, Show)

-- | The pending work one driver answer completes. Every variant
-- carries fully validated templates; 'finishWork' only adds the
-- driver-supplied material and publishes.
data PendingWork
  = PwGeneratePair
      { pwPub :: !PendingObject
      , pwPriv :: !PendingObject
      }
  | PwGenerateKey
      { pwKey :: !PendingObject
      }
  | PwGenerateKeyIv
      { pwKey :: !PendingObject
      , pwKeyLen :: !Int
      }
  | PwEncaps
      { pwSecret :: !PendingObject
      , pwCtLen :: !Int
      , pwSsLen :: !Int
      }
  | PwDecaps
      { pwSecret :: !PendingObject
      }
  | PwBlobOut
      { pwRegion :: !String
      }
  | PwUnwrap
      { pwKey :: !PendingObject
      }
  | PwUnwrapRaw
      { pwKey :: !PendingObject
      }
  | PwUnwrapPad8
      { pwKey :: !PendingObject
      }
  | PwUnwrapTail
      { pwKey :: !PendingObject
      , pwWidth :: !Int
      , pwLen :: !Int
      }
  | PwDerive
      { pwKeys :: ![PendingObject]
      , pwLens :: ![Int]
      }
  | PwDeriveIv
      { pwKeys :: ![PendingObject]
      , pwLens :: ![Int]
      , pwIvLens :: !(Int, Int)
      }
  | PwDerivePub
      { pwKey :: !PendingObject
      , pwPubKty :: !Word64
      }
  deriving (Eq, Show)

-- | Sweep length shapes: fixed sizes mint the headline length when
-- @CKA_VALUE_LEN@ is absent; discrete and ranged shapes require it.
data KeygenLens
  = KeygenFixed !Int
  | KeygenDiscrete ![Int]
  | KeygenRange !Int !Int
  deriving (Eq, Show)
