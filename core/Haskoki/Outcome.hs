{- | Explicit plan and outcome contracts for the pure core.

'PlanResult' is one of 'Reject', 'Immediate', or 'Execute'. A rejection
may still carry source-required output updates and state termination, so
a bare @Either ReturnCode@ is not an acceptable substitute.
-}
module Haskoki.Outcome
  ( PlanResult (..)
  , Rejection (..)
  , PreparedCommit (..)
  , StateDelta (..)
  , DeltaOp (..)
  , Reservation (..)
  , CryptoStep (..)
  , RevisionDep (..)
  , EngineResult (..)
  , BackendFailure (..)
  , EffectRequest (..)
  , EngineEnv (..)
  , ModelFault (..)
  , NativeOutput (..)
  , PersistOp (..)
  , ResourceRelease (..)
  ) where

import Data.ByteString (ByteString)
import Data.Map.Strict (Map)

import Haskoki.Attribute (AttributeType, AttributeValue)
import Haskoki.Model (SessionState)
import Haskoki.Operation.Effect (CryptoEffect)
import Haskoki.Operation.State (SessionOps, SlotKind)
import Haskoki.Request (FunctionId, OutputIntent, OutputRegion)
import Haskoki.Session (SessionLogin, TokenAuth)
import Haskoki.Types
  ( EngineResourceId
  , ExternalHandle
  , Generation
  , ObjectId
  , ReturnCode
  , Revision
  , SessionId
  , SlotId
  )

-- | The plan for one call: reject outright, commit immediately, or
-- reserve resources and execute an effect outside the model gate.
data PlanResult
  = Reject !Rejection
  | Immediate !PreparedCommit
  | Execute !Reservation !EffectRequest
  deriving (Eq, Show)

-- | A rejected plan. Rejections still perform their required output
-- writes (e.g. size-query answers on a failing call) and state
-- termination (e.g. operation teardown) instead of silently doing
-- nothing. A rejection may also release backend resources: when a
-- reservation goes stale after its effect already allocated one
-- (streamed digest), the orphan drains through 'rejReleases' instead of
-- leaking. Plan-time rejections carry none.
data Rejection = Rejection
  { rejCode :: !ReturnCode
  , rejOutputs :: ![NativeOutput]
  , rejDelta :: !StateDelta
  , rejReleases :: ![ResourceRelease]
  , rejReasons :: ![String]
  } deriving (Eq, Show)

-- | A fully determined commit: API outcome, typed state delta,
-- persistent mutations, native output values, resource releases, and
-- structured diagnostic reasons. Never contains a captured caller
-- pointer or an unevaluated IO action.
data PreparedCommit = PreparedCommit
  { pcCode :: !ReturnCode
  , pcDelta :: !StateDelta
  , pcPersist :: ![PersistOp]
  , pcOutputs :: ![NativeOutput]
  , pcReleases :: ![ResourceRelease]
  , pcReasons :: ![String]
  } deriving (Eq, Show)

-- | Typed state-delta operations applied atomically by 'publishDelta'.
data DeltaOp
  = DeltaTouchSession !SessionId
  | DeltaCloseSession !SessionId
  | DeltaBumpGeneration !SessionId !Generation
  | DeltaCreateObject !ObjectId
  | DeltaDestroyObject !ObjectId
  | DeltaCreateObjectFull !ObjectId !(Map AttributeType AttributeValue) !(Maybe SessionId) !SlotId
  | DeltaBindHandle !ExternalHandle !ObjectId
  | DeltaBumpHandle !ExternalHandle
  | DeltaOpenSession !SessionId !SlotId !Bool
  | DeltaSetSessionLogin !SessionId !SessionLogin
  | DeltaSetTokenAuth !SlotId !TokenAuth
  | DeltaSetSessionOps !SessionId !SessionOps
  deriving (Eq, Show)

-- | An ordered list of delta operations. Order is significant and
-- preserved through planning, persistence, and publication.
newtype StateDelta = StateDelta { unStateDelta :: [DeltaOp] }
  deriving (Eq, Show)

-- | One revision dependency: the entity revisions that must remain
-- valid for a reservation to commit.
data RevisionDep
  = DepSession !SessionId !Revision !Generation
  | DepObject !ObjectId !Revision
  deriving (Eq, Show)

-- | Identifies the affected operation and the revisions that must
-- remain valid. Recorded narrowly so unrelated activity does not
-- invalidate a plan.
data Reservation = Reservation
  { resOperation :: !String
  , resDeps :: ![RevisionDep]
  , resResource :: !(Maybe EngineResourceId)
  , resStep :: !(Maybe CryptoStep)
  } deriving (Eq, Show)

-- | One planned crypto step pinned to a reservation: the finishing
-- function, the slot, the output region name and caller intent, and
-- the post-plan operation/session snapshot the finisher runs over.
-- The revision dependencies on the reservation guard the snapshot:
-- any concurrent session-ops change goes stale instead of clobbering.
data CryptoStep = CryptoStep
  { csFunction :: !FunctionId
  , csKind :: !SlotKind
  , csName :: !String
  , csIntent :: !OutputIntent
  , csOps :: !SessionOps
  , csSession :: !SessionState
  } deriving (Eq, Show)

-- | Typed backend failure. Native error codes are preserved for traces;
-- translation to 'ReturnCode' follows the calling function's policy.
-- Mirrors 'Haskoki.Engine.Backend.BackendError' constructor for
-- constructor, so the adapter between the layers is total
-- and lossless both ways.
data BackendFailure
  = BackendUnsupported !String !String
  | BackendBadParam !String !String
  | BackendBadKey !String !String
  | BackendAuthFailed !String
  | BackendInvalidState !String !String
  | BackendNative !String !Int !String
  | BackendResourceGone !String !EngineResourceId
  deriving (Eq, Show)

-- | Effect outcome: owned bytes, a verification verdict, key
-- material, resource references, or a typed backend failure. Never
-- a pointer, never an unevaluated IO.
data EngineResult
  = EngineOkBytes !ByteString
  | EngineOkValid !Bool
  | EngineOkResource !EngineResourceId
  | EngineFail !BackendFailure
  deriving (Eq, Show)

-- | A request for effect execution outside the model gate (crypto,
-- callbacks, persistence IO). This converges the engine-facing
-- abstractions on one: planned crypto ('EffectCrypto'); earlier stub
-- constructors retired with the original record.
data EffectRequest
  = EffectCrypto !CryptoEffect
  deriving (Eq, Show)

-- | Opaque engine environment handle for effect execution. The pure
-- core names it but never inspects it; only the runtime holds one.
data EngineEnv = EngineEnv
  { envBackend :: !String
  } deriving (Eq, Show)

-- | A model-level fault: the delta could not be published against the
-- current model (missing entity, generation mismatch, internal
-- inconsistency). Distinct from call rejections.
data ModelFault
  = FaultUnknownSession !SessionId
  | FaultUnknownObject !ObjectId
  | FaultDuplicateObject !ObjectId
  | FaultDuplicateSession !SessionId
  | FaultDuplicateHandle !ExternalHandle
  | FaultUnknownHandle !ExternalHandle
  | FaultUnknownSlot !SlotId
  | FaultGenerationMismatch !SessionId !Generation !Generation
  | FaultInternal !String
  deriving (Eq, Show)

-- | One permitted native write: region + owned bytes. Length
-- conversions and capacity checks happen before this value exists.
data NativeOutput = NativeOutput
  { outRegion :: !OutputRegion
  , outBytes :: !ByteString
  } deriving (Eq, Show)

-- | One persistent mutation request for the storage backend.
data PersistOp
  = PersistStoreObject !ObjectId !ByteString
  | PersistDropObject !ObjectId
  deriving (Eq, Show)

-- | One runtime resource release to run after the native call returns.
data ResourceRelease
  = ReleaseEngineResource !EngineResourceId
  deriving (Eq, Show)
