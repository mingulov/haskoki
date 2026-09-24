{- | Pure model: provider/token/session/operation state skeletons.

Revision and generation tracking live here so reservation checks
and lifecycle rules share one representation; this module only
needs coherent shapes plus lookup and delta-application helpers.
-}
module Haskoki.Model
  ( SessionState (..)
  , ObjectState (..)
  , HandleBinding (..)
  , Model (..)
  , emptyModel
  , addToken
  , lookupSession
  , lookupObject
  , lookupHandle
  , lookupTokenAuth
  , sessionsOnSlot
  , nextRevision
  ) where

import Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map

import Haskoki.Attribute (AttributeType, AttributeValue)
import Haskoki.Operation.State (SessionOps)
import Haskoki.Session (SessionLogin (..), TokenAuth (..), tokenAuthNew)
import Haskoki.Types
  ( ExternalHandle
  , Generation (..)
  , ObjectId
  , Revision (..)
  , SessionId
  , SlotId
  )

-- | Session state: identity, slot binding, revision, generation,
-- read-only flag, observed login, and the active operation slots.
-- Token-level auth lives in 'TokenAuth', keyed by slot in the model.
data SessionState = SessionState
  { ssId :: !SessionId
  , ssSlot :: !SlotId
  , ssRevision :: !Revision
  , ssGeneration :: !Generation
  , ssReadOnly :: !Bool
  , ssLogin :: !SessionLogin
  , ssOps :: !SessionOps
  } deriving (Eq, Show)

-- | Object state: identity, revision, handle-map generation,
-- attributes, lifetime owner ('Nothing' = token object, 'Just'
-- creator = session object), and home slot. Token/private-ness
-- derives from the stored 'AttrToken'/'AttrPrivate' flags (absent or
-- wrongly shaped = false); see 'Haskoki.Object.objectToken'.
data ObjectState = ObjectState
  { osId :: !ObjectId
  , osRevision :: !Revision
  , osGeneration :: !Generation
  , osAttrs :: !(Map AttributeType AttributeValue)
  , osOwner :: !(Maybe SessionId)
  , osSlot :: !SlotId
  } deriving (Eq, Show)

-- | One external-handle binding: the object it names plus the object
-- generation observed at bind time. Resolution succeeds only while
-- the generations still match. Bindings are retained stale (never
-- deleted, never reused), so a destroyed handle faults forever.
data HandleBinding = HandleBinding
  { hbObject :: !ObjectId
  , hbGeneration :: !Generation
  } deriving (Eq, Show)

-- | The pure model: sessions, objects, the external-handle map,
-- per-slot token auth, and allocation counters. Counters make id and
-- handle allocation deterministic under test seeds. A slot holds a
-- token exactly when it has a 'TokenAuth' entry.
data Model = Model
  { mSessions :: !(Map SessionId SessionState)
  , mObjects :: !(Map ObjectId ObjectState)
  , mHandles :: !(Map ExternalHandle HandleBinding)
  , mTokenAuth :: !(Map SlotId TokenAuth)
  , mNextSession :: !Int
  , mNextObject :: !Int
  , mNextHandle :: !Int
  , mNextRevision :: !Int
  } deriving (Eq, Show)

-- | The empty model: no sessions, no objects, no handles, no tokens,
-- counters at one so the value zero stays reserved for "no id"
-- sentinels at the FFI layer.
emptyModel :: Model
emptyModel = Model
  { mSessions = Map.empty
  , mObjects = Map.empty
  , mHandles = Map.empty
  , mTokenAuth = Map.empty
  , mNextSession = 1
  , mNextObject = 1
  , mNextHandle = 1
  , mNextRevision = 1
  }

-- | Seat a fresh token in a slot. Seating an already-seated slot
-- leaves the model unchanged (presence, not reset).
addToken :: Model -> SlotId -> Model
addToken m slot
  | Map.member slot (mTokenAuth m) = m
  | otherwise = m { mTokenAuth = Map.insert slot tokenAuthNew (mTokenAuth m) }

-- | Look up a session by id.
lookupSession :: Model -> SessionId -> Maybe SessionState
lookupSession m sid = Map.lookup sid (mSessions m)

-- | Look up an object by id.
lookupObject :: Model -> ObjectId -> Maybe ObjectState
lookupObject m oid = Map.lookup oid (mObjects m)

-- | Look up a handle binding by handle. A present binding may still
-- be stale (generation mismatch or object gone); use
-- 'Haskoki.Object.resolveHandle' for guarded resolution.
lookupHandle :: Model -> ExternalHandle -> Maybe HandleBinding
lookupHandle m h = Map.lookup h (mHandles m)

-- | Look up a slot's token auth ('Nothing' = no token present).
lookupTokenAuth :: Model -> SlotId -> Maybe TokenAuth
lookupTokenAuth m slot = Map.lookup slot (mTokenAuth m)

-- | All sessions bound to a slot, in session-id order.
sessionsOnSlot :: Model -> SlotId -> [SessionState]
sessionsOnSlot m slot =
  filter ((== slot) . ssSlot) (Map.elems (mSessions m))

-- | Allocate a fresh revision number, returning the revision and the
-- updated model.
nextRevision :: Model -> (Revision, Model)
nextRevision m =
  let r = mNextRevision m
  in (Revision r, m { mNextRevision = r + 1 })
