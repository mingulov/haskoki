{- | Per-session operation state: slots, active operations, accessors.

Split from 'Haskoki.Operation' so 'Haskoki.Model' can host
'SessionOps' without an import cycle: this module imports only
'Haskoki.Registry' and 'Haskoki.Types'. Planners, effects, and the
init policy stay in 'Haskoki.Operation', which re-exports this
module, so existing importers are unaffected.
-}
module Haskoki.Operation.State
  ( -- * Slots and states
    SlotKind (..)
  , slotOf
  , CipherDir (..)
  , cipherDirOf
  , RecoverRole (..)
  , recoverRoleOf
  , MsgFamily (..)
  , msgFamilyOp
  , msgFamilyKind
  , msgOperation
  , CipherSpec (..)
  , RecoverSpec (..)
  , OpAuth (..)
  , DigestStream (..)
  -- The three state representations are abstract outside
  -- this module — no @(..)@. Clients build through the smart
  -- constructors, observe through the projectors/readers, and
  -- transition through 'insertOp'/'insertChecked'/'setStaged' and
  -- the writers below; internal states are unforgeable.
  , SlotCommon
  , SlotPhase (..)
  , ActiveOp
  , MsgInner (..)
  , MsgState (..)
  , DualState (..)
  , DualStaged (..)
  , StagedOutput (..)
  , SessionOps
  , emptySessionOps
  , activeSlots
  , hasDual
  , opsActive
  , dirKind
  , kindOccupied
  , slotAuth
  , bufferedLength
    -- * Slot accessors for the per-kind lifecycles
  , lookupSingle
  , removeSingle
  , cancelOps
    -- * Validated insertion (the kind is derived from the op)
  , slotOfActive
  , SlotMismatch (..)
  , insertOp
  , insertChecked
    -- * Slot phases (live and staged are mutually exclusive)
  , stagedOf
  , streamOf
  , setStaged
  , commonOf
  , setCommon
    -- * Validated constructors (the only way to build states)
  , mkSlotCommon
  , mkActiveDigest
  , mkActiveSign
  , mkActiveVerify
  , mkActiveRecover
  , mkActiveCipher
  , mkActiveMessage
    -- * Shape projectors (total kind dispatch)
  , activeDigest
  , activeSign
  , activeVerify
  , activeRecover
  , activeCipher
  , activeMessage
    -- * Shared-state readers and writers
  , commonMech
  , commonOp
  , commonKey
  , commonParams
  , commonAuth
  , setCommonAuth
  , dualLinkOf
  , setDualLink
  , slotLinkFresh
  , multipartActiveOf
  , setMultipartActive
  , bufferedOf
  , setBuffered
  , chainIvOf
  , setChainIv
  , hasStreamed
  , phaseOf
  , setLive
  , resetToBuffered
    -- * Dual-operation access
  , dualOf
  , setDual
  ) where

import Data.Bits ((.&.), (.|.))
import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import Data.List (sort)
import Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map
import Data.Maybe (isJust, isNothing)
import Data.Word (Word32)

import Haskoki.Registry
  ( MechanismId
  , Operation (..)
  )
import Haskoki.Types
  ( EngineResourceId
  , ObjectId
  , OpState
  )

-- | Per-session operation slots. Sign and sign-recover share
-- 'SlotSign'; verify and verify-recover share 'SlotVerify'.
data SlotKind
  = SlotDigest
  | SlotSign
  | SlotVerify
  | SlotEncrypt
  | SlotDecrypt
  deriving (Eq, Ord, Show, Enum, Bounded)

-- | The slot an operation occupies, if it is a classic operation.
slotOf :: Operation -> Maybe SlotKind
slotOf op = case op of
  OpDigest -> Just SlotDigest
  OpSign -> Just SlotSign
  OpSignRecover -> Just SlotSign
  OpVerify -> Just SlotVerify
  OpVerifyRecover -> Just SlotVerify
  OpEncrypt -> Just SlotEncrypt
  OpDecrypt -> Just SlotDecrypt
  _ -> Nothing

-- | Cipher direction.
data CipherDir = DirEncrypt | DirDecrypt
  deriving (Eq, Show)

-- | The cipher direction of an operation, if it is a cipher op.
cipherDirOf :: Operation -> Maybe CipherDir
cipherDirOf op = case op of
  OpEncrypt -> Just DirEncrypt
  OpDecrypt -> Just DirDecrypt
  _ -> Nothing

-- | Recovery role.
data RecoverRole = RoleSignRecover | RoleVerifyRecover
  deriving (Eq, Show)

-- | The recovery role of an operation, if it is a recovery op.
recoverRoleOf :: Operation -> Maybe RecoverRole
recoverRoleOf op = case op of
  OpSignRecover -> Just RoleSignRecover
  OpVerifyRecover -> Just RoleVerifyRecover
  _ -> Nothing

-- | Message family: the four PKCS#11 v3 message operation families.
-- There is no digest family: v3 message APIs cover only
-- encrypt/decrypt/sign/verify.
data MsgFamily
  = MsgEncrypt
  | MsgDecrypt
  | MsgSign
  | MsgVerify
  deriving (Eq, Ord, Show, Enum, Bounded)

-- | The classic operation counterpart of a message family.
-- Message-init legality (source routes, engine capabilities, key
-- policy, shape) keys off the classic counterpart: a
-- message-encrypt init IS an encrypt operation on the mechanism,
-- used in message mode. The @CKF_MESSAGE_*@ mechanism-info flags
-- are future @C_GetMechanismInfo@ scope, not init scope.
msgFamilyOp :: MsgFamily -> Operation
msgFamilyOp fam = case fam of
  MsgEncrypt -> OpEncrypt
  MsgDecrypt -> OpDecrypt
  MsgSign -> OpSign
  MsgVerify -> OpVerify

-- | The message operation tag recorded on an initialized outer
-- context.
msgOperation :: MsgFamily -> Operation
msgOperation fam = case fam of
  MsgEncrypt -> OpMessageEncrypt
  MsgDecrypt -> OpMessageDecrypt
  MsgSign -> OpMessageSign
  MsgVerify -> OpMessageVerify

-- | The slot a message family occupies, shared with its classic
-- counterpart: a message init conflicts with a classic init in the
-- same slot and vice versa.
msgFamilyKind :: MsgFamily -> SlotKind
msgFamilyKind fam = case fam of
  MsgEncrypt -> SlotEncrypt
  MsgDecrypt -> SlotDecrypt
  MsgSign -> SlotSign
  MsgVerify -> SlotVerify

-- | Cipher shape fixed at init: block width in bytes and whether the
-- final block carries PKCS#7 padding.
data CipherSpec = CipherSpec
  { csBlock :: !Int
  , csPad :: !Bool
  } deriving (Eq, Show)

-- | Recovery shape fixed at init: signature-block capacity in bytes
-- and the trailing tag width of the model @data \|\| tag@ embedding.
data RecoverSpec = RecoverSpec
  { rsCapacity :: !Int
  , rsTagLen :: !Int
  } deriving (Eq, Show)

-- | Context-auth state of one slot: no requirement, an
-- always-authenticate requirement awaiting its first data call, or a
-- consumed grant.
data OpAuth
  = AuthNone
  | AuthPending
  | AuthSatisfied
  deriving (Eq, Show)

-- | A live streamed-digest backend context: the
-- 'EngineResourceId' the init allocated plus whether any update
-- fed it yet. Only the classic digest slot carries one; buffered
-- operations (sign\/verify\/cipher\/dual\/message) leave it empty.
data DigestStream = DigestStream
  { dsResource :: !EngineResourceId
  , dsFed :: !Bool
  } deriving (Eq, Show)

-- | The lifecycle phase of one slot: buffering multipart input,
-- streaming a live digest backend context, or holding a staged
-- final output. Live and staged are mutually exclusive by
-- construction: the phase is one field, so a slot can never be
-- both. The multipart buffer ('scBuffered') is retained across
-- staging — snapshot bytes carry it — and simply stays empty on
-- slots that never accumulate.
data SlotPhase
  = PhaseBuffered
  | PhaseLive !DigestStream
  | PhaseStaged !StagedOutput
  deriving (Eq, Show)

-- | State shared by every active single operation: mechanism,
-- operation, bound key object, opaque parameters, auth state,
-- multipart accumulation, the lifecycle phase, and the decrypt-dual
-- peer link (unrelated slots leave it empty).
data SlotCommon = SlotCommon
  { scMech :: !MechanismId
  , scOp :: !Operation
  , scKey :: !(Maybe ObjectId)
  , scParams :: !ByteString
  , scAuth :: !OpAuth
  , scBuffered :: !ByteString
  , scPhase :: !SlotPhase
  , scChainIv :: !(Maybe ByteString)
  -- | The decrypt-dual peer link: @Just peer@ on a decrypt slot
  -- means the peer slot's buffered bytes came from this slot's
  -- cipher output through combined updates (so the peer final
  -- reads its buffer, not a backend stream). The decrypt final
  -- drops the link WITHOUT feeding the peer: §5.17.2/§5.17.4
  -- leave the recovered tail to an explicit peer update. Set ONLY
  -- by the combined-update path; cleared on final, completion,
  -- init-change (fresh slots start unlinked), peer removal
  -- ('clearLinksTo'), and any separate cipher data call. Never
  -- serialized: restored slots start unlinked.
  , scDualLink :: !(Maybe SlotKind)
  -- | Multipart update activity for combined flows: set by the
  -- combined digest-update path even when the part carries no
  -- bytes, so a zero-output dual update closes the one-shot
  -- window exactly like a streamed empty update. Never
  -- serialized: restored slots start inactive (the same corner
  -- as the dual link).
  , scMultipartActive :: !Bool
  } deriving (Eq, Show)

-- | One active single operation: its kind plus its shared state and,
-- for cipher and recovery slots, the shape fixed at init.
data ActiveOp
  = ActiveDigest !SlotCommon
  | ActiveSign !SlotCommon
  | ActiveVerify !SlotCommon
  | ActiveRecover !RecoverRole !SlotCommon !RecoverSpec
  | ActiveCipher !CipherDir !SlotCommon !CipherSpec
  | ActiveMessage !MsgState
  deriving (Eq, Show)

-- | Inner per-message state: idle between messages, or one open
-- message with its per-message parameters, AAD, and buffered input.
-- A short-buffered message output is staged on the OUTER common
-- ('PhaseStaged'); while staged, the inner message stays open so only
-- the message retry can conclude it.
data MsgInner
  = MsgIdle
  | MsgOpen
      { miParams :: !ByteString
      , miAad :: !ByteString
      , miBuffered :: !ByteString
      } deriving (Eq, Show)

-- | One active outer message context: the family, the shared outer
-- state (mechanism, key, auth, staged message output), the inner
-- per-message state, the cipher shape for cipher families, and the
-- count of fully delivered messages.
data MsgState = MsgState
  { msFamily :: !MsgFamily
  , msCommon :: !SlotCommon
  , msInner :: !MsgInner
  , msCipher :: !(Maybe CipherSpec)
  , msMessages :: !Int
  } deriving (Eq, Show)

-- | One active dual operation: the digest side and the cipher side
-- accumulate the same update stream; the cipher side carries the
-- direction, the padding shape, and the auth requirement (the digest
-- side is unkeyed, hence never auth-gated). At most one staged dual
-- final is retained for retries.
data DualState = DualState
  { duDigest :: !SlotCommon
  , duCipher :: !SlotCommon
  , duDir :: !CipherDir
  , duCipherSpec :: !CipherSpec
  , duStaged :: !(Maybe DualStaged)
  } deriving (Eq, Show)

-- | A staged dual final: both sides' outputs with per-side delivery
-- flags, so a retry replays only the sides still pending.
data DualStaged = DualStaged
  { dsDigest :: !StagedOutput
  , dsCipher :: !StagedOutput
  , dsDigestDone :: !Bool
  , dsCipherDone :: !Bool
  } deriving (Eq, Show)

-- | One staged final output: the region name, the full bytes, and the
-- output-planner liveness for short-buffer retries.
data StagedOutput = StagedOutput
  { stName :: !String
  , stBytes :: !ByteString
  , stState :: !OpState
  } deriving (Eq, Show)

-- | Per-session operation state: the active singles by slot plus at
-- most one dual operation. A dual occupies its digest slot and its
-- cipher-direction slot: singles and duals conflict on either.
data SessionOps = SessionOps
  { soSingles :: !(Map SlotKind ActiveOp)
  , soDual :: !(Maybe DualState)
  } deriving (Eq, Show)

-- | No active operations.
emptySessionOps :: SessionOps
emptySessionOps = SessionOps Map.empty Nothing

-- | The slot a cipher direction occupies.
dirKind :: CipherDir -> SlotKind
dirKind dir = case dir of
  DirEncrypt -> SlotEncrypt
  DirDecrypt -> SlotDecrypt

-- | Active slots, ascending: single slots plus the slots a dual
-- occupies, if any.
activeSlots :: SessionOps -> [SlotKind]
activeSlots ops =
  sort (Map.keys (soSingles ops) ++ dualKinds)
  where
    dualKinds = case soDual ops of
      Nothing -> []
      Just du -> [SlotDigest, dirKind (duDir du)]

-- | Whether a dual operation is active.
hasDual :: SessionOps -> Bool
hasDual = isJust . soDual

-- | Whether any operation is active (any single slot or the dual).
-- Context-specific login requires one: there must be an operation
-- to re-authenticate.
opsActive :: SessionOps -> Bool
opsActive = not . null . activeSlots

-- | Whether a slot is occupied by a single or by the dual.
kindOccupied :: SessionOps -> SlotKind -> Bool
kindOccupied ops kind =
  Map.member kind (soSingles ops) || dualOccupies
  where
    dualOccupies = case soDual ops of
      Nothing -> False
      Just du -> kind == SlotDigest || kind == dirKind (duDir du)

-- | Auth state of one slot, if active.
slotAuth :: SessionOps -> SlotKind -> Maybe OpAuth
slotAuth ops kind = scAuth . commonOf <$> lookupSingle ops kind

-- | Buffered multipart bytes of one slot, if active.
bufferedLength :: SessionOps -> SlotKind -> Maybe Int
bufferedLength ops kind =
  BS.length . scBuffered . commonOf <$> lookupSingle ops kind

-- | Look up the active operation in one slot.
lookupSingle :: SessionOps -> SlotKind -> Maybe ActiveOp
lookupSingle ops kind = Map.lookup kind (soSingles ops)

-- | Free one slot. A removed peer ends every combined flow
-- pointing at it ('clearLinksTo'): conclusion, termination, and
-- the removal preceding any replacement all pass through here, so
-- a replacement peer never inherits the old combined-flow link.
removeSingle :: SlotKind -> SessionOps -> SessionOps
removeSingle kind ops =
  clearLinksTo kind (ops { soSingles = Map.delete kind (soSingles ops) })

-- | Clear the decrypt-dual peer links that reference a concluded
-- slot. A no-op when no slot links to it (every single flow).
clearLinksTo :: SlotKind -> SessionOps -> SessionOps
clearLinksTo kind ops =
  ops { soSingles = Map.map clear (soSingles ops) }
  where
    clear active
      | dualLinkOf (commonOf active) == Just kind =
          setCommon active (setDualLink Nothing (commonOf active))
      | otherwise = active

-- | The CKF_* selector bits addressing one slot: the pinned-header
-- mechanism-flag values (spec/vendor/pkcs11.h), reused as the
-- C_SessionCancel operation-class mask. Recovery bits select their
-- shared slot (sign-recover shares 'SlotSign', verify-recover
-- shares 'SlotVerify').
slotCancelBits :: SlotKind -> Word32
slotCancelBits kind = case kind of
  SlotEncrypt -> 0x100
  SlotDecrypt -> 0x200
  SlotDigest -> 0x400
  SlotSign -> 0x800 .|. 0x1000
  SlotVerify -> 0x2000 .|. 0x4000

-- | The slots a cancel mask selects. A zero mask selects every
-- slot: with no class selected the whole session operation set is
-- cancelled (the recovery semantic — a caller passing no selection
-- wants a clean session, not a no-op). Unknown bits select
-- nothing: teardown stays lenient so a future flag cannot strand a
-- session behind an un-clearable operation.
cancelSlots :: Word32 -> [SlotKind]
cancelSlots 0 = [minBound .. maxBound]
cancelSlots flags =
  [ kind | kind <- [minBound .. maxBound], flags .&. slotCancelBits kind /= 0 ]

-- | Drop the operations a cancel mask selects. Selected singles
-- are freed; the dual drops when the mask covers either side it
-- occupies (a dual is one operation: half-cancelling it is
-- unrepresentable). Idempotent: cancelling an idle selection is a
-- no-op.
cancelOps :: Word32 -> SessionOps -> SessionOps
cancelOps flags ops =
  let kinds = cancelSlots flags
      singles' = foldr Map.delete (soSingles ops) kinds
      dual' = case soDual ops of
        Nothing -> Nothing
        Just du
          | SlotDigest `elem` kinds || dirKind (duDir du) `elem` kinds -> Nothing
          | otherwise -> Just du
  -- A cancelled peer ends the combined flows pointing at it, like
  -- any other removal ('removeSingle' shares 'clearLinksTo').
  in foldr clearLinksTo (SessionOps singles' dual') kinds

-- | The slot one active operation truly occupies: the kind side of
-- the validated insertion pair. Total: every constructor names its
-- slot (recovery by role, cipher by direction, message by family).
slotOfActive :: ActiveOp -> SlotKind
slotOfActive active = case active of
  ActiveDigest _ -> SlotDigest
  ActiveSign _ -> SlotSign
  ActiveVerify _ -> SlotVerify
  ActiveRecover RoleSignRecover _ _ -> SlotSign
  ActiveRecover RoleVerifyRecover _ _ -> SlotVerify
  ActiveCipher dir _ _ -> dirKind dir
  ActiveMessage ms -> msgFamilyKind (msFamily ms)

-- | A rejected insertion claim: the slot the caller named plus the
-- slot the operation truly occupies.
data SlotMismatch = SlotMismatch
  { smExpected :: !SlotKind
  , smActual :: !SlotKind
  } deriving (Eq, Show)

-- | Install the active operation under its derived slot, replacing
-- whatever that slot holds. Total: a mismatched kind/operation
-- pair is unbuildable — there is no kind parameter to mismatch.
insertOp :: ActiveOp -> SessionOps -> SessionOps
insertOp active ops =
  ops { soSingles = Map.insert (slotOfActive active) active (soSingles ops) }

-- | Install the active operation under a claimed slot, rejecting a
-- claim that mismatches the operation's true slot. The only
-- validating entry: external kind claims (snapshot restore) route
-- through here.
insertChecked
  :: SlotKind -> ActiveOp -> SessionOps -> Either SlotMismatch SessionOps
insertChecked kind active ops
  | slotOfActive active == kind = Right (insertOp active ops)
  | otherwise = Left (SlotMismatch kind (slotOfActive active))

-- | The staged final output a slot holds, if it is staged.
stagedOf :: SlotCommon -> Maybe StagedOutput
stagedOf sc = case scPhase sc of
  PhaseBuffered -> Nothing
  PhaseLive _ -> Nothing
  PhaseStaged s -> Just s

-- | The live digest stream a slot holds, if it is streaming.
streamOf :: SlotCommon -> Maybe DigestStream
streamOf sc = case scPhase sc of
  PhaseBuffered -> Nothing
  PhaseLive ds -> Just ds
  PhaseStaged _ -> Nothing

-- | Record the byte stager's 'Maybe' packaging on a slot.
-- 'Nothing' is the freed shape: staging arms never see it
-- ('stageBytes' pairs it with @freed=True@), so it leaves the slot
-- untouched. 'Just' moves the slot to 'PhaseStaged', structurally
-- clearing any live stream — the old explicit stream-clearing
-- assignment, now unrepresentable otherwise. Callers hold the
-- stream's release separately.
setStaged :: Maybe StagedOutput -> SlotCommon -> SlotCommon
setStaged Nothing sc = sc
setStaged (Just s) sc = sc { scPhase = PhaseStaged s }

-- | The shared state of any active operation.
commonOf :: ActiveOp -> SlotCommon
commonOf active = case active of
  ActiveDigest sc -> sc
  ActiveSign sc -> sc
  ActiveVerify sc -> sc
  ActiveRecover _ sc _ -> sc
  ActiveCipher _ sc _ -> sc
  ActiveMessage ms -> msCommon ms

-- | Replace the shared state of an active operation, keeping its
-- kind and shape.
setCommon :: ActiveOp -> SlotCommon -> ActiveOp
setCommon active sc = case active of
  ActiveDigest _ -> ActiveDigest sc
  ActiveSign _ -> ActiveSign sc
  ActiveVerify _ -> ActiveVerify sc
  ActiveRecover role _ spec -> ActiveRecover role sc spec
  ActiveCipher dir _ spec -> ActiveCipher dir sc spec
  ActiveMessage ms -> ActiveMessage (ms { msCommon = sc })

-- | Build shared slot state: every init path starts buffered with
-- no bytes staged, so the phase and buffer are fixed here, not
-- caller-chosen.
mkSlotCommon
  :: MechanismId -> Operation -> Maybe ObjectId -> ByteString -> OpAuth
  -> SlotCommon
mkSlotCommon mech op key params auth = SlotCommon
  { scMech = mech
  , scOp = op
  , scKey = key
  , scParams = params
  , scAuth = auth
  , scBuffered = BS.empty
  , scPhase = PhaseBuffered
  , scChainIv = Nothing
  , scDualLink = Nothing
  , scMultipartActive = False
  }

-- | Build single-shape active operations.
mkActiveDigest :: SlotCommon -> ActiveOp
mkActiveDigest = ActiveDigest

-- | Build single-shape active operations.
mkActiveSign :: SlotCommon -> ActiveOp
mkActiveSign = ActiveSign

-- | Build single-shape active operations.
mkActiveVerify :: SlotCommon -> ActiveOp
mkActiveVerify = ActiveVerify

-- | Build a recovery active operation.
mkActiveRecover :: RecoverRole -> SlotCommon -> RecoverSpec -> ActiveOp
mkActiveRecover = ActiveRecover

-- | Build a cipher active operation.
mkActiveCipher :: CipherDir -> SlotCommon -> CipherSpec -> ActiveOp
mkActiveCipher = ActiveCipher

-- | Build a message active operation.
mkActiveMessage :: MsgState -> ActiveOp
mkActiveMessage = ActiveMessage

-- | Project the digest shape, if this is a digest operation.
activeDigest :: ActiveOp -> Maybe SlotCommon
activeDigest active = case active of
  ActiveDigest sc -> Just sc
  _ -> Nothing

-- | Project the sign shape, if this is a sign operation.
activeSign :: ActiveOp -> Maybe SlotCommon
activeSign active = case active of
  ActiveSign sc -> Just sc
  _ -> Nothing

-- | Project the verify shape, if this is a verify operation.
activeVerify :: ActiveOp -> Maybe SlotCommon
activeVerify active = case active of
  ActiveVerify sc -> Just sc
  _ -> Nothing

-- | Project the recovery shape, if this is a recovery operation.
activeRecover :: ActiveOp -> Maybe (RecoverRole, SlotCommon, RecoverSpec)
activeRecover active = case active of
  ActiveRecover role sc spec -> Just (role, sc, spec)
  _ -> Nothing

-- | Project the cipher shape, if this is a cipher operation.
activeCipher :: ActiveOp -> Maybe (CipherDir, SlotCommon, CipherSpec)
activeCipher active = case active of
  ActiveCipher dir sc spec -> Just (dir, sc, spec)
  _ -> Nothing

-- | Project the message state, if this is a message operation.
activeMessage :: ActiveOp -> Maybe MsgState
activeMessage active = case active of
  ActiveMessage ms -> Just ms
  _ -> Nothing

-- | The mechanism of shared slot state.
commonMech :: SlotCommon -> MechanismId
commonMech = scMech

-- | The operation of shared slot state.
commonOp :: SlotCommon -> Operation
commonOp = scOp

-- | The key of shared slot state, if any.
commonKey :: SlotCommon -> Maybe ObjectId
commonKey = scKey

-- | The init parameters of shared slot state.
commonParams :: SlotCommon -> ByteString
commonParams = scParams

-- | The auth state of shared slot state.
commonAuth :: SlotCommon -> OpAuth
commonAuth = scAuth

-- | Replace the auth state of shared slot state.
setCommonAuth :: OpAuth -> SlotCommon -> SlotCommon
setCommonAuth auth sc = sc { scAuth = auth }

-- | The decrypt-dual peer link of shared slot state, if linked.
dualLinkOf :: SlotCommon -> Maybe SlotKind
dualLinkOf = scDualLink

-- | Replace the decrypt-dual peer link of shared slot state.
setDualLink :: Maybe SlotKind -> SlotCommon -> SlotCommon
setDualLink link sc = sc { scDualLink = link }

-- | Whether a slot is byte-fresh: no buffered bytes, no chaining
-- value, no staged output, and no fed digest stream. The
-- combined-update path links only fresh pairs, so a broken link
-- never re-forms over bytes the peer missed.
slotLinkFresh :: SlotCommon -> Bool
slotLinkFresh sc =
  BS.null (scBuffered sc)
    && isNothing (scChainIv sc)
    && isNothing (stagedOf sc)
    && case streamOf sc of
      Nothing -> True
      Just ds -> not (dsFed ds)

-- | Whether a combined-flow update reached shared slot state (set
-- even for parts carrying no bytes).
multipartActiveOf :: SlotCommon -> Bool
multipartActiveOf = scMultipartActive

-- | Record combined-flow update activity on shared slot state.
-- Activity never clears on a live slot; only a fresh slot starts
-- without it.
setMultipartActive :: SlotCommon -> SlotCommon
setMultipartActive sc = sc { scMultipartActive = True }

-- | The buffered multipart bytes of shared slot state.
bufferedOf :: SlotCommon -> ByteString
bufferedOf = scBuffered

-- | Replace the buffered multipart bytes of shared slot state.
setBuffered :: ByteString -> SlotCommon -> SlotCommon
setBuffered buf sc = sc { scBuffered = buf }

-- | The running CBC chaining value once a cipher slot has streamed
-- an update ('Nothing' before the first streamed chunk, when the
-- init IV in 'scParams' still chains). ECB slots record 'Just'
-- empty after their first streamed chunk: chaining is vacuous
-- there, but the marker still proves multipart input exists (a
-- one-shot after any update is 'CKR_OPERATION_ACTIVE' even when
-- the buffer drained). Slots that never stream (digests, signs,
-- unframed AEAD/asymmetric ciphers, dual/message inners) keep
-- 'Nothing'.
chainIvOf :: SlotCommon -> Maybe ByteString
chainIvOf = scChainIv

-- | Replace the running chaining value of shared slot state.
setChainIv :: Maybe ByteString -> SlotCommon -> SlotCommon
setChainIv iv sc = sc { scChainIv = iv }

-- | Whether the slot has streamed an update chunk.
hasStreamed :: SlotCommon -> Bool
hasStreamed = isJust . scChainIv

-- | The phase of shared slot state.
phaseOf :: SlotCommon -> SlotPhase
phaseOf = scPhase

-- | Move a slot to the live-streaming phase with the given stream.
setLive :: DigestStream -> SlotCommon -> SlotCommon
setLive ds sc = sc { scPhase = PhaseLive ds }

-- | Move a slot back to the buffered phase, keeping its bytes.
resetToBuffered :: SlotCommon -> SlotCommon
resetToBuffered sc = sc { scPhase = PhaseBuffered }

-- | The dual operation a session holds, if any.
dualOf :: SessionOps -> Maybe DualState
dualOf = soDual

-- | Replace the dual operation a session holds.
setDual :: Maybe DualState -> SessionOps -> SessionOps
setDual du ops = ops { soDual = du }
