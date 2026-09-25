{- | Portable operation snapshots: bounded versioned export/import codecs (pure).

Save a multipart operation ('saveOperation'), restore it into a
compatible session ('restoreOperation'). The bytes carry logical
state only — mechanism, operation, parameters, buffered input,
staged output, shape specs, auth marks, and canonical key
identities — never resource ids, pointers, or native handles, so a
fixture scan can pin their absence.

Byte format (all integers big-endian; @len32@ is a u32 length plus
that many bytes; @u8@ tags reject any other value):

> MAGIC    8 bytes "HKSNAP02" (schema id plus format version "02")
> PROFILE  u8: 0 = 2.40, 1 = 3.0, 2 = 3.1, 3 = 3.2
> SLOT     u32: token SlotId (< 2^31)
> BODY     SINGLE | DUAL
>
> SINGLE   0x00 KIND OPTAG COMMON EXTRA
> KIND     u8 SlotKind tag (must match the reconstructed operation)
> OPTAG    u8: 0 digest, 1 sign, 2 verify, 3 recover, 4 cipher, 5 message
> COMMON   MECH OP PARAMS AUTH BUFFERED CHAINIV STAGED KEYSECT
>   MECH     u64 MechanismId
>   OP       u8 Operation tag (must cohere with OPTAG)
>   PARAMS   len32 bytes
>   AUTH     u8: 0 none, 1 pending, 2 satisfied
>   BUFFERED len32 bytes
>   CHAINIV u8 0 (never streamed), or 0x01 IV (len32 running
>            chaining value; empty for ECB, which chains vacuously)
>   STAGED   u8 0, or 0x01 NAME STBYTES STSTATE
>     NAME     len32 UTF-8 bytes
>     STBYTES  len32 bytes
>     STSTATE  u8 0 + u32 consumption (live), or u8 1 (dead)
>   KEYSECT  u8 0, or 0x01 CLASS KEYTYPE FPR
>     CLASS    u32 CKO_* (< 2^31)
>     KEYTYPE  u32 CKK_* (< 2^31), or 0xFFFFFFFF when absent
>     FPR      u64 FNV-1a over the stored material bytes
> EXTRA (by OPTAG):
>   digest\/sign\/verify: empty
>   recover: ROLE CAP TAGLEN (u8 0\/1, u32, u32)
>   cipher:  DIR BLOCK PAD (u8 0\/1, u32, u8 0\/1)
>   message: FAM INNER MCSPEC COUNT
>     FAM    u8: 0 encrypt, 1 decrypt, 2 sign, 3 verify
>     INNER  u8 0 (idle), or 0x01 MPARAMS AAD MBUF (each len32)
>     MCSPEC u8 0, or 0x01 BLOCK PAD (u32, u8)
>     COUNT  u32 delivered messages
>
> DUAL     0x01 DCOMMON CCOMMON DIR SPEC DSTAGED
>   DCOMMON, CCOMMON: COMMON each
>   DIR      u8 0\/1
>   SPEC     u32 block width, u8 pad flag
>   DSTAGED  u8 0, or 0x01 DSTAGE DSTAGE DDONE CDONE
>     DSTAGE   NAME STBYTES STSTATE (as above)
>     DDONE, CDONE: u8 0\/1

Decoding is strict: truncated input, trailing bytes, unknown tags,
out-of-range values, incoherent kind\/operation pairs, and quota
violations all reject. Restore checks run in documented order:
decode, quotas, profile, token, slot occupancy, then key binding —
and any failure returns the target session untouched.
-}
{-# LANGUAGE OverloadedStrings #-}
module Haskoki.Snapshot
  ( -- * Format
    snapshotMagic
  , snapshotFormatVersion
    -- * Quotas
  , SnapshotQuotas (..)
  , defaultQuotas
    -- * Canonical key identities
  , KeyIdentity (..)
  , keyIdentityOf
  , fingerprintKey
    -- * Save
  , SaveTarget (..)
  , SaveError (..)
  , saveCode
  , saveOperation
    -- * Restore
  , RestoreKeys (..)
  , RestoreError (..)
  , restoreCode
  , restoreOperation
  ) where

import Data.Bits (shiftR, xor)
import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import qualified Data.Map.Strict as Map
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import Data.Word (Word8, Word64)

import Haskoki.Attribute (AttributeType (..), AttributeValue (..))
import Haskoki.Model (Model (..), ObjectState (..), SessionState (..))
import Haskoki.Object (objectVisible, resolveHandle)
import Haskoki.Operation (maxBuffered)
import Haskoki.Operation.State
  ( ActiveOp
  , CipherDir (..)
  , CipherSpec (..)
  , DualStaged (..)
  , DualState (..)
  , MsgFamily (..)
  , MsgInner (..)
  , MsgState (..)
  , OpAuth (..)
  , RecoverRole (..)
  , RecoverSpec (..)
  , SessionOps
  , SlotCommon
  , SlotKind (..)
  , SlotPhase (..)
  , StagedOutput (..)
  , activeCipher
  , activeDigest
  , activeMessage
  , activeRecover
  , activeSign
  , activeVerify
  , bufferedOf
  , commonAuth
  , commonKey
  , commonMech
  , commonOf
  , commonOp
  , commonParams
  , dirKind
  , dualOf
  , hasDual
  , insertChecked
  , kindOccupied
  , lookupSingle
  , mkActiveCipher
  , mkActiveDigest
  , mkActiveMessage
  , mkActiveRecover
  , mkActiveSign
  , mkActiveVerify
  , mkSlotCommon
  , msgFamilyKind
  , msgOperation
  , phaseOf
  , setBuffered
  , setDual
  , setStaged
  , setChainIv
  , slotOfActive
  , stagedOf
  , chainIvOf
  )
import Haskoki.Registry (MechanismId (..), Operation (..))
import Haskoki.Types
  ( Consumption (..)
  , ExternalHandle
  , ObjectId (..)
  , OpState (..)
  , Pkcs11Version (..)
  , ReturnCode (..)
  , SlotId (..)
  )

-- ---------------------------------------------------------------------------
-- Format identity and quotas
-- ---------------------------------------------------------------------------

-- | Snapshot magic: schema id plus format version.
snapshotMagic :: ByteString
snapshotMagic = "HKSNAP02"

-- | Snapshot format version carried in the magic.
snapshotFormatVersion :: Word8
snapshotFormatVersion = 2

-- | Snapshot size policy: the total-bytes bound plus the per-staged-output
-- bound. Restore enforces the same quotas, so hostile bytes cannot stage
-- unbounded output through a compliant restorer.
data SnapshotQuotas = SnapshotQuotas
  { sqMaxTotal :: !Int
  , sqMaxStaged :: !Int
  } deriving (Eq, Show)

-- | Default quotas: staged outputs admit anything the output planner can
-- stage ('maxBuffered'); the total admits the worst-case dual state (two
-- buffer-bound sides plus two staged finals) with 64 KiB of header slack.
defaultQuotas :: SnapshotQuotas
defaultQuotas = SnapshotQuotas
  { sqMaxTotal = 4 * maxBuffered + 65536
  , sqMaxStaged = maxBuffered
  }

-- ---------------------------------------------------------------------------
-- Canonical key identities
-- ---------------------------------------------------------------------------

-- | The portable identity of a key object: its class, its key type (absent
-- on legacy objects), and a fingerprint over the stored material bytes.
-- Object ids and handles are session-local and never cross the wire.
data KeyIdentity = KeyIdentity
  { kiClass :: !Int
  , kiKeyType :: !(Maybe Int)
  , kiFingerprint :: !Word64
  } deriving (Eq, Show)

-- | FNV-1a 64-bit fingerprint over key material bytes. A
-- non-cryptographic consistency check (same bytes, same identity), not a
-- security boundary: it binds a snapshot to its key, nothing more.
fingerprintKey :: ByteString -> Word64
fingerprintKey = BS.foldl' step 14695981039346656037
  where
    step :: Word64 -> Word8 -> Word64
    step h b = (h `xor` fromIntegral b) * 1099511628211

-- | Read the canonical identity off a key object: 'Nothing' when the
-- class is missing or malformed, the key type is malformed, or no
-- material is stored — such a key cannot anchor a portable snapshot.
keyIdentityOf :: ObjectState -> Maybe KeyIdentity
keyIdentityOf ost = do
  cls <- case lookupAttr AttrClass of
    Just (ValULong c) | c < 0x7FFFFFFF -> Just (fromIntegral c)
    _ -> Nothing
  kty <- case lookupAttr AttrKeyType of
    Nothing -> Just Nothing
    Just (ValULong k) | k < 0x7FFFFFFF -> Just (Just (fromIntegral k))
    _ -> Nothing
  mat <- case lookupAttr AttrValue of
    Just (ValBytes bs) | not (BS.null bs) -> Just bs
    _ -> Nothing
  Just (KeyIdentity cls kty (fingerprintKey mat))
  where
    lookupAttr t = Map.lookup t (osAttrs ost)

-- ---------------------------------------------------------------------------
-- Save
-- ---------------------------------------------------------------------------

-- | Which operation state to save: one slot, or the dual operation.
data SaveTarget
  = SaveSlot !SlotKind
  | SaveDual
  deriving (Eq, Show)

-- | Why a save was refused. Quota failures name the measured size and the
-- bound that rejected it.
data SaveError
  = SaveEmpty !SlotKind
  | SaveNoDual
  | SaveCorrupt !SlotKind
  | SaveKeyGone !ObjectId
  | SaveKeyNoIdentity !ObjectId
  | SaveBadField !String
  | SaveOverQuota !Int !Int
  | SaveStagedOverQuota !Int !Int
  | SaveStreamLive !SlotKind
  deriving (Eq, Show)

-- | Source-defined return code for each save failure.
saveCode :: SaveError -> ReturnCode
saveCode e = case e of
  SaveEmpty _ -> CKR_OPERATION_NOT_INITIALIZED
  SaveNoDual -> CKR_OPERATION_NOT_INITIALIZED
  SaveCorrupt _ -> CKR_GENERAL_ERROR
  SaveKeyGone _ -> CKR_OBJECT_HANDLE_INVALID
  SaveKeyNoIdentity _ -> CKR_STATE_UNSAVEABLE
  SaveBadField _ -> CKR_STATE_UNSAVEABLE
  SaveOverQuota _ _ -> CKR_STATE_UNSAVEABLE
  SaveStagedOverQuota _ _ -> CKR_STATE_UNSAVEABLE
  SaveStreamLive _ -> CKR_STATE_UNSAVEABLE

-- | Save one slot's operation, or the dual operation, to portable bytes.
-- The session supplies the token identity; the model resolves bound keys
-- to canonical identities. Quota checks run staged-first (the specific
-- bound) then total, so a failure names the tightest violated bound.
saveOperation
  :: SnapshotQuotas -> Model -> SessionState -> Pkcs11Version -> SaveTarget
  -> Either SaveError ByteString
saveOperation quotas model st profile target = case target of
  SaveSlot kind -> case lookupSingle (ssOps st) kind of
    Nothing -> Left (SaveEmpty kind)
    Just active
      | slotOfActive active /= kind -> Left (SaveCorrupt kind)
      | otherwise -> do
          checkSaveStaged quotas (stagedMaxSingle active)
          common <- encodeActive model active
          slot <- encodeSlot (ssSlot st)
          let bytes = snapshotMagic <> encodeProfile profile <> slot
                <> BS.singleton 0x00 <> BS.singleton (encodeKind kind)
                <> common
          checkSaveTotal quotas bytes
          pure bytes
  SaveDual -> case dualOf (ssOps st) of
    Nothing -> Left SaveNoDual
    Just du -> do
      checkSaveStaged quotas (stagedMaxDual du)
      body <- encodeDual model du
      slot <- encodeSlot (ssSlot st)
      let bytes = snapshotMagic <> encodeProfile profile <> slot
            <> BS.singleton 0x01 <> body
      checkSaveTotal quotas bytes
      pure bytes

-- | Reject a staged output past the staged bound.
checkSaveStaged :: SnapshotQuotas -> Int -> Either SaveError ()
checkSaveStaged quotas n
  | n <= sqMaxStaged quotas = Right ()
  | otherwise = Left (SaveStagedOverQuota n (sqMaxStaged quotas))

-- | Reject encoded bytes past the total bound.
checkSaveTotal :: SnapshotQuotas -> ByteString -> Either SaveError ()
checkSaveTotal quotas bytes
  | BS.length bytes <= sqMaxTotal quotas = Right ()
  | otherwise = Left (SaveOverQuota (BS.length bytes) (sqMaxTotal quotas))

-- | The largest staged output held by one live single operation (zero
-- when nothing is staged).
stagedMaxSingle :: ActiveOp -> Int
stagedMaxSingle active = case stagedOf (commonOf active) of
  Nothing -> 0
  Just s -> BS.length (stBytes s)

-- | The largest staged output held by one live dual operation.
stagedMaxDual :: DualState -> Int
stagedMaxDual du = case duStaged du of
  Nothing -> 0
  Just ds -> max (BS.length (stBytes (dsDigest ds)))
    (BS.length (stBytes (dsCipher ds)))

-- ---------------------------------------------------------------------------
-- Restore
-- ---------------------------------------------------------------------------

-- | The key arguments a restore binds: one handle for a single operation,
-- one per side for a dual (digest side, cipher side).
data RestoreKeys
  = RestoreSingle !(Maybe ExternalHandle)
  | RestoreDual !(Maybe ExternalHandle) !(Maybe ExternalHandle)
  deriving (Eq, Show)

-- | Why a restore was refused. 'RestoreMalformed' carries the exact
-- structural complaint; quota failures name the measured size and bound.
data RestoreError
  = RestoreMalformed !String
  | RestoreProfileMismatch
  | RestoreTokenMismatch
  | RestoreSlotBusy !SlotKind
  | RestoreDualBusy
  | RestoreKeyMissing
  | RestoreKeyUnexpected
  | RestoreKeyGone
  | RestoreKeyNotVisible
  | RestoreKeyMismatch
  | RestoreOverQuota !Int !Int
  | RestoreStagedOverQuota !Int !Int
  deriving (Eq, Show)

-- | Source-defined return code for each restore failure.
restoreCode :: RestoreError -> ReturnCode
restoreCode e = case e of
  RestoreMalformed _ -> CKR_SAVED_STATE_INVALID
  RestoreProfileMismatch -> CKR_SAVED_STATE_INVALID
  RestoreTokenMismatch -> CKR_SAVED_STATE_INVALID
  RestoreSlotBusy _ -> CKR_OPERATION_ACTIVE
  RestoreDualBusy -> CKR_OPERATION_ACTIVE
  RestoreKeyMissing -> CKR_SAVED_STATE_INVALID
  RestoreKeyUnexpected -> CKR_SAVED_STATE_INVALID
  RestoreKeyGone -> CKR_OBJECT_HANDLE_INVALID
  RestoreKeyNotVisible -> CKR_OBJECT_HANDLE_INVALID
  RestoreKeyMismatch -> CKR_SAVED_STATE_INVALID
  RestoreOverQuota _ _ -> CKR_SAVED_STATE_INVALID
  RestoreStagedOverQuota _ _ -> CKR_SAVED_STATE_INVALID

-- | Restore snapshot bytes into the target session. Check order: decode,
-- quotas, profile, token, slot occupancy, then key binding. Any failure
-- returns 'Left' and the session is untouched.
restoreOperation
  :: SnapshotQuotas -> Model -> SessionState -> Pkcs11Version -> RestoreKeys
  -> ByteString -> Either RestoreError SessionState
restoreOperation quotas model st profile keys bytes = do
  Decoded bodyProfile bodySlot body <- decodeSnapshot bytes
  checkRestoreTotal quotas bytes
  checkRestoreStaged quotas
    (either stagedMaxDecodedSingle stagedMaxDecodedDual body)
  if bodyProfile /= profile
    then Left RestoreProfileMismatch
    else if bodySlot /= ssSlot st
      then Left RestoreTokenMismatch
      else pure ()
  case (body, keys) of
    (Left ds, RestoreSingle mh) -> do
      checkSingleFree (ssOps st) (dsKind ds)
      active <- buildSingle model st mh ds
      case insertChecked (dsKind ds) active (ssOps st) of
        Left mm -> Left (RestoreMalformed
          ("slot tag mismatches the restored operation: " ++ show mm))
        Right ops' -> pure st { ssOps = ops' }
    (Right dd, RestoreDual mhd mhc) -> do
      checkDualFree (ssOps st) (ddDir dd)
      du <- buildDual model st mhd mhc dd
      pure st { ssOps = setDual (Just du) (ssOps st) }
    (Left _, RestoreDual _ _) ->
      Left (RestoreMalformed "dual key arguments for a single snapshot")
    (Right _, RestoreSingle _) ->
      Left (RestoreMalformed "single key arguments for a dual snapshot")

-- | Reject snapshot bytes past the total bound.
checkRestoreTotal :: SnapshotQuotas -> ByteString -> Either RestoreError ()
checkRestoreTotal quotas bytes
  | BS.length bytes <= sqMaxTotal quotas = Right ()
  | otherwise = Left (RestoreOverQuota (BS.length bytes) (sqMaxTotal quotas))

-- | Reject a decoded staged output past the staged bound.
checkRestoreStaged :: SnapshotQuotas -> Int -> Either RestoreError ()
checkRestoreStaged quotas n
  | n <= sqMaxStaged quotas = Right ()
  | otherwise = Left (RestoreStagedOverQuota n (sqMaxStaged quotas))

-- | The largest staged output claimed by one decoded single.
stagedMaxDecodedSingle :: DecodedSingle -> Int
stagedMaxDecodedSingle ds = case bcStaged (dsCommon ds) of
  Nothing -> 0
  Just s -> BS.length (stBytes s)

-- | The largest staged output claimed by one decoded dual.
stagedMaxDecodedDual :: DecodedDual -> Int
stagedMaxDecodedDual dd = case ddStaged dd of
  Nothing -> 0
  Just ds -> max (BS.length (stBytes (dsDigest ds)))
    (BS.length (stBytes (dsCipher ds)))

-- | The target slot must be free of singles and of any dual overlap.
checkSingleFree :: SessionOps -> SlotKind -> Either RestoreError ()
checkSingleFree ops kind
  | kindOccupied ops kind = Left (RestoreSlotBusy kind)
  | otherwise = Right ()

-- | A dual restore needs both of its slots free and no dual active.
checkDualFree :: SessionOps -> CipherDir -> Either RestoreError ()
checkDualFree ops dir
  | hasDual ops = Left RestoreDualBusy
  | kindOccupied ops SlotDigest = Left (RestoreSlotBusy SlotDigest)
  | kindOccupied ops ck = Left (RestoreSlotBusy ck)
  | otherwise = Right ()
  where
    ck = dirKind dir

-- | Bind one decoded key section against its handle argument: the handle
-- must resolve to a visible object whose canonical identity equals the
-- recorded one. Anything else rejects with the target untouched.
bindKey
  :: Model -> SessionState -> Maybe KeyIdentity -> Maybe ExternalHandle
  -> Either RestoreError (Maybe ObjectId)
bindKey model st mIdent mh = case (mIdent, mh) of
  (Nothing, Nothing) -> Right Nothing
  (Nothing, Just _) -> Left RestoreKeyUnexpected
  (Just _, Nothing) -> Left RestoreKeyMissing
  (Just want, Just h) -> case resolveHandle model h of
    Nothing -> Left RestoreKeyGone
    Just ost
      | not (objectVisible st ost) -> Left RestoreKeyNotVisible
      | keyIdentityOf ost /= Just want -> Left RestoreKeyMismatch
      | otherwise -> Right (Just (osId ost))

-- | Build the restored single operation from its decoded shape.
buildSingle
  :: Model -> SessionState -> Maybe ExternalHandle -> DecodedSingle
  -> Either RestoreError ActiveOp
buildSingle model st mh ds = do
  mkey <- bindKey model st (bcKey (dsCommon ds)) mh
  let sc = toCommon (dsCommon ds) mkey
  case dsTag ds of
    0 -> pure (mkActiveDigest sc)
    1 -> pure (mkActiveSign sc)
    2 -> pure (mkActiveVerify sc)
    3 -> case dsRecoverShape ds of
      Just (role, spec) -> pure (mkActiveRecover role sc spec)
      Nothing -> Left (RestoreMalformed "recover shape missing")
    4 -> case dsCipherShape ds of
      Just (dir, spec) -> pure (mkActiveCipher dir sc spec)
      Nothing -> Left (RestoreMalformed "cipher shape missing")
    5 -> case dsMessageShape ds of
      Just (fam, inner, mspec, count) ->
        pure (mkActiveMessage (MsgState fam sc inner mspec count))
      Nothing -> Left (RestoreMalformed "message shape missing")
    t -> Left (RestoreMalformed ("operation tag out of range: " ++ show t))

-- | Build the restored dual operation from its decoded shape.
buildDual
  :: Model -> SessionState -> Maybe ExternalHandle -> Maybe ExternalHandle
  -> DecodedDual -> Either RestoreError DualState
buildDual model st mhd mhc dd = do
  dk <- bindKey model st (bcKey (ddDigest dd)) mhd
  ck <- bindKey model st (bcKey (ddCipher dd)) mhc
  pure (DualState (toCommon (ddDigest dd) dk) (toCommon (ddCipher dd) ck)
    (ddDir dd) (ddSpec dd) (ddStaged dd))

-- ---------------------------------------------------------------------------
-- Slot kinds and profiles
-- ---------------------------------------------------------------------------

-- | SlotKind tag: the 'Enum' order (digest, sign, verify, encrypt, decrypt).
encodeKind :: SlotKind -> Word8
encodeKind = fromIntegral . fromEnum

-- | Baseline profile tag.
encodeProfile :: Pkcs11Version -> ByteString
encodeProfile v = BS.singleton $ case v of
  Pkcs11_2_40 -> 0
  Pkcs11_3_0 -> 1
  Pkcs11_3_1 -> 2
  Pkcs11_3_2 -> 3

-- | Token slot encoding; rejects out-of-range ids instead of truncating.
encodeSlot :: SlotId -> Either SaveError ByteString
encodeSlot (SlotId s)
  | 0 <= s && s < 0x7FFFFFFF = Right (putU32 s)
  | otherwise = Left (SaveBadField ("slot id out of range: " ++ show s))

-- ---------------------------------------------------------------------------
-- Put helpers
-- ---------------------------------------------------------------------------

-- | Big-endian u32; the caller guarantees @0 <= n < 2^32@.
putU32 :: Int -> ByteString
putU32 n = BS.pack
  [ fromIntegral (n `shiftR` 24)
  , fromIntegral (n `shiftR` 16)
  , fromIntegral (n `shiftR` 8)
  , fromIntegral n
  ]

-- | Big-endian u64.
putU64 :: Word64 -> ByteString
putU64 w = BS.pack [fromIntegral (w `shiftR` s) | s <- [56, 48 .. 0]]

-- | Length-prefixed bytes; lengths past 2^31 - 1 refuse to encode.
putLen :: ByteString -> Either SaveError ByteString
putLen bs
  | BS.length bs < 0x7FFFFFFF = Right (putU32 (BS.length bs) <> bs)
  | otherwise = Left (SaveBadField "field exceeds the 2^31 - 1 encode bound")

-- ---------------------------------------------------------------------------
-- Encode
-- ---------------------------------------------------------------------------

-- | Encode one shared slot state, resolving its bound key to a canonical
-- identity. The 'ObjectId' itself is never serialized.
encodeCommon :: Model -> SlotCommon -> Either SaveError ByteString
encodeCommon model sc = do
  params <- putLen (commonParams sc)
  buffered <- putLen (bufferedOf sc)
  streamIv <- encodeChainIv (chainIvOf sc)
  staged <- encodeStaged (stagedOf sc)
  key <- encodeKeySection model (commonKey sc)
  pure (putU64 (unMechanismId (commonMech sc))
    <> BS.singleton (fromIntegral (fromEnum (commonOp sc)))
    <> params
    <> BS.singleton (encodeAuth (commonAuth sc))
    <> buffered
    <> streamIv
    <> staged
    <> key)

-- | Chaining-value section: absent before the first streamed chunk.
encodeChainIv :: Maybe ByteString -> Either SaveError ByteString
encodeChainIv Nothing = Right (BS.singleton 0x00)
encodeChainIv (Just iv) = (BS.singleton 0x01 <>) <$> putLen iv

-- | Auth mark tag.
encodeAuth :: OpAuth -> Word8
encodeAuth a = case a of
  AuthNone -> 0
  AuthPending -> 1
  AuthSatisfied -> 2

-- | Staged-output section.
encodeStaged :: Maybe StagedOutput -> Either SaveError ByteString
encodeStaged Nothing = Right (BS.singleton 0x00)
encodeStaged (Just s) = do
  name <- putLen (TE.encodeUtf8 (T.pack (stName s)))
  out <- putLen (stBytes s)
  lst <- encodeLiveness (stState s)
  pure (BS.singleton 0x01 <> name <> out <> lst)

-- | One-shot liveness: live carries its consumption count, dead is bare.
encodeLiveness :: OpState -> Either SaveError ByteString
encodeLiveness st = case st of
  OpLive (Consumption n)
    | 0 <= n && n < 0x7FFFFFFF ->
        Right (BS.singleton 0x00 <> putU32 n)
    | otherwise -> Left (SaveBadField ("consumption out of range: " ++ show n))
  OpDead -> Right (BS.singleton 0x01)

-- | Key section: absent for unkeyed operations, otherwise the canonical
-- identity of the resolved key object.
encodeKeySection :: Model -> Maybe ObjectId -> Either SaveError ByteString
encodeKeySection _ Nothing = Right (BS.singleton 0x00)
encodeKeySection model (Just oid) = case Map.lookup oid (mObjects model) of
  Nothing -> Left (SaveKeyGone oid)
  Just ost -> case keyIdentityOf ost of
    Nothing -> Left (SaveKeyNoIdentity oid)
    Just ki -> Right (BS.singleton 0x01 <> putU32 (kiClass ki)
      <> putU32 (maybe 0xFFFFFFFF id (kiKeyType ki))
      <> putU64 (kiFingerprint ki))

-- | Operation tag plus shape extras for one active operation.
encodeActive :: Model -> ActiveOp -> Either SaveError ByteString
encodeActive model active
  -- A live digest stream holds backend-native context the portable
  -- bytes cannot capture: refuse honestly instead of saving an
  -- empty buffer that would silently drop the fed bytes. Consumed
  -- (staged) and buffered slots save normally. Each phase is
  -- handled explicitly: no catch-all. The final arm is dead over
  -- the six current shapes (exactly one projector hits) and
  -- degrades to honest refusal if a shape is ever added without
  -- updating this dispatch.
  | Just sc <- activeDigest active = case phaseOf sc of
      PhaseLive _ -> Left (SaveStreamLive SlotDigest)
      PhaseBuffered -> plain 0 sc
      PhaseStaged _ -> plain 0 sc
  | Just sc <- activeSign active = plain 1 sc
  | Just sc <- activeVerify active = plain 2 sc
  | Just (role, sc, spec) <- activeRecover active = do
    scBs <- encodeCommon model sc
    let roleB = case role of
          RoleSignRecover -> 0x00
          RoleVerifyRecover -> 0x01
    pure (BS.singleton 3 <> scBs <> BS.singleton roleB
      <> putU32 (rsCapacity spec) <> putU32 (rsTagLen spec))
  | Just (dir, sc, spec) <- activeCipher active = do
    scBs <- encodeCommon model sc
    let dirB = case dir of
          DirEncrypt -> 0x00
          DirDecrypt -> 0x01
        padB = if csPad spec then 0x01 else 0x00
    pure (BS.singleton 4 <> scBs <> BS.singleton dirB
      <> putU32 (csBlock spec) <> BS.singleton padB)
  | Just ms <- activeMessage active = do
    scBs <- encodeCommon model (msCommon ms)
    inner <- encodeInner (msInner ms)
    let famB = case msFamily ms of
          MsgEncrypt -> 0x00
          MsgDecrypt -> 0x01
          MsgSign -> 0x02
          MsgVerify -> 0x03
        specB = case msCipher ms of
          Nothing -> BS.singleton 0x00
          Just spec -> BS.singleton 0x01 <> putU32 (csBlock spec)
            <> BS.singleton (if csPad spec then 0x01 else 0x00)
    pure (BS.singleton 5 <> scBs <> BS.singleton famB <> inner
      <> specB <> putU32 (msMessages ms))
  | otherwise = Left (SaveCorrupt (slotOfActive active))
  where
    plain tag sc = (BS.singleton tag <>) <$> encodeCommon model sc

-- | Inner per-message state.
encodeInner :: MsgInner -> Either SaveError ByteString
encodeInner MsgIdle = Right (BS.singleton 0x00)
encodeInner (MsgOpen p a b) = do
  pBs <- putLen p
  aBs <- putLen a
  bBs <- putLen b
  pure (BS.singleton 0x01 <> pBs <> aBs <> bBs)

-- | Dual-operation body: both sides plus direction, shape, and staging.
encodeDual :: Model -> DualState -> Either SaveError ByteString
encodeDual model du = do
  dBs <- encodeCommon model (duDigest du)
  cBs <- encodeCommon model (duCipher du)
  staged <- encodeDualStaged (duStaged du)
  let dirB = case duDir du of
        DirEncrypt -> 0x00
        DirDecrypt -> 0x01
      spec = duCipherSpec du
  pure (dBs <> cBs <> BS.singleton dirB <> putU32 (csBlock spec)
    <> BS.singleton (if csPad spec then 0x01 else 0x00) <> staged)

-- | Dual staging: both sides' outputs with per-side delivery flags.
encodeDualStaged :: Maybe DualStaged -> Either SaveError ByteString
encodeDualStaged Nothing = Right (BS.singleton 0x00)
encodeDualStaged (Just ds) = do
  dBs <- encodeStagedOutput (dsDigest ds)
  cBs <- encodeStagedOutput (dsCipher ds)
  pure (BS.singleton 0x01 <> dBs <> cBs
    <> flag (dsDigestDone ds) <> flag (dsCipherDone ds))
  where
    flag True = BS.singleton 0x01
    flag False = BS.singleton 0x00

-- | One staged output without the presence flag (dual sides are bare).
encodeStagedOutput :: StagedOutput -> Either SaveError ByteString
encodeStagedOutput s = do
  name <- putLen (TE.encodeUtf8 (T.pack (stName s)))
  out <- putLen (stBytes s)
  lst <- encodeLiveness (stState s)
  pure (name <> out <> lst)

-- ---------------------------------------------------------------------------
-- Decode
-- ---------------------------------------------------------------------------

-- | A decoded shared slot state: everything but the bound object id, which
-- the restore key arguments supply.
data BareCommon = BareCommon
  { bcMech :: !MechanismId
  , bcOp :: !Operation
  , bcParams :: !ByteString
  , bcAuth :: !OpAuth
  , bcBuffered :: !ByteString
  , bcChainIv :: !(Maybe ByteString)
  , bcStaged :: !(Maybe StagedOutput)
  , bcKey :: !(Maybe KeyIdentity)
  } deriving (Eq, Show)

-- | Reattach the resolved key to a decoded common. Restored
-- slots are always streamless: live streams refuse to save, so no
-- snapshot can name one. Each decoded shape maps to its phase
-- explicitly: staged output restores staged, anything else restores
-- buffered. The chaining value restores verbatim, so a mid-stream
-- cipher save resumes chaining exactly.
toCommon :: BareCommon -> Maybe ObjectId -> SlotCommon
toCommon bc mkey =
  setStaged (bcStaged bc)
    (setChainIv (bcChainIv bc)
      (setBuffered (bcBuffered bc)
        (mkSlotCommon (bcMech bc) (bcOp bc) mkey (bcParams bc) (bcAuth bc))))

-- | A decoded single-operation body.
data DecodedSingle = DecodedSingle
  { dsKind :: !SlotKind
  , dsTag :: !Word8
  , dsCommon :: !BareCommon
  , dsRecoverShape :: !(Maybe (RecoverRole, RecoverSpec))
  , dsCipherShape :: !(Maybe (CipherDir, CipherSpec))
  , dsMessageShape :: !(Maybe (MsgFamily, MsgInner, Maybe CipherSpec, Int))
  } deriving (Eq, Show)

-- | A decoded dual-operation body.
data DecodedDual = DecodedDual
  { ddDigest :: !BareCommon
  , ddCipher :: !BareCommon
  , ddDir :: !CipherDir
  , ddSpec :: !CipherSpec
  , ddStaged :: !(Maybe DualStaged)
  } deriving (Eq, Show)

-- | A fully decoded snapshot.
data Decoded = Decoded
  { decProfile :: !Pkcs11Version
  , decSlot :: !SlotId
  , decBody :: !(Either DecodedSingle DecodedDual)
  } deriving (Eq, Show)

-- | Strict cursor decoder with exact complaints.
newtype Get a = Get { runGet :: ByteString -> Either String (a, ByteString) }

instance Functor Get where
  fmap f (Get g) = Get $ \bs -> case g bs of
    Left e -> Left e
    Right (a, rest) -> Right (f a, rest)

instance Applicative Get where
  pure a = Get $ \bs -> Right (a, bs)
  Get gf <*> Get ga = Get $ \bs -> case gf bs of
    Left e -> Left e
    Right (f, rest) -> case ga rest of
      Left e -> Left e
      Right (a, rest') -> Right (f a, rest')

instance Monad Get where
  Get ga >>= f = Get $ \bs -> case ga bs of
    Left e -> Left e
    Right (a, rest) -> runGet (f a) rest

-- | Fail with a structural complaint.
getFail :: String -> Get a
getFail why = Get $ \_ -> Left why

-- | One byte, or truncation.
getU8 :: Get Word8
getU8 = Get $ \bs -> case BS.uncons bs of
  Nothing -> Left "truncated snapshot"
  Just (b, rest) -> Right (b, rest)

-- | Big-endian u32 as an 'Int'.
getU32 :: Get Int
getU32 = Get $ \bs ->
  let (h, rest) = BS.splitAt 4 bs
  in if BS.length h /= 4
    then Left "truncated snapshot"
    else Right (BS.foldl' (\a b -> a * 256 + fromIntegral b) 0 h, rest)

-- | Big-endian u64.
getU64 :: Get Word64
getU64 = Get $ \bs ->
  let (h, rest) = BS.splitAt 8 bs
  in if BS.length h /= 8
    then Left "truncated snapshot"
    else Right (BS.foldl' (\a b -> a * 256 + fromIntegral b) 0 h, rest)

-- | Exactly @n@ bytes, or truncation.
getBytes :: Int -> Get ByteString
getBytes n = Get $ \bs ->
  let (h, rest) = BS.splitAt n bs
  in if BS.length h /= n
    then Left "truncated snapshot"
    else Right (h, rest)

-- | Length-prefixed bytes.
getLenBytes :: Get ByteString
getLenBytes = getU32 >>= getBytes

-- | Decode a full snapshot, rejecting trailing bytes.
decodeSnapshot :: ByteString -> Either RestoreError Decoded
decodeSnapshot bytes = case runGet getSnapshot bytes of
  Left why -> Left (RestoreMalformed why)
  Right (dec, rest)
    | BS.null rest -> Right dec
    | otherwise -> Left (RestoreMalformed
        ("trailing bytes: " ++ show (BS.length rest)))

-- | Top-level snapshot decoder.
getSnapshot :: Get Decoded
getSnapshot = do
  magic <- getBytes 8
  if magic /= snapshotMagic
    then getFail "bad magic: not a haskoki snapshot"
    else do
      profile <- getProfile
      slot <- getSlot
      tag <- getU8
      case tag of
        0x00 -> Decoded profile slot . Left <$> getSingle
        0x01 -> Decoded profile slot . Right <$> getDual
        t -> getFail ("body tag out of range: " ++ show t)

-- | Baseline profile tag.
getProfile :: Get Pkcs11Version
getProfile = do
  t <- getU8
  case t of
    0 -> pure Pkcs11_2_40
    1 -> pure Pkcs11_3_0
    2 -> pure Pkcs11_3_1
    3 -> pure Pkcs11_3_2
    _ -> getFail ("profile tag out of range: " ++ show t)

-- | Token slot; values past 2^31 - 1 never encode, so they never decode.
getSlot :: Get SlotId
getSlot = do
  n <- getU32
  if 0 <= n && n < 0x7FFFFFFF
    then pure (SlotId n)
    else getFail ("slot id out of range: " ++ show n)

-- | SlotKind tag.
getKind :: Get SlotKind
getKind = do
  t <- getU8
  if t <= fromIntegral (fromEnum (maxBound :: SlotKind))
    then pure (toEnum (fromIntegral t))
    else getFail ("slot tag out of range: " ++ show t)

-- | Single-operation body with kind/operation coherence checks.
getSingle :: Get DecodedSingle
getSingle = do
  kind <- getKind
  tag <- getU8
  common <- getCommon
  ds <- case tag of
    0 -> checkOp common OpDigest >> pure (bare kind tag common)
    1 -> checkOp common OpSign >> pure (bare kind tag common)
    2 -> checkOp common OpVerify >> pure (bare kind tag common)
    3 -> do
      role <- getRecoverRole
      cap <- getU32
      tagLen <- getU32
      checkOp common (recoverOp role)
      pure ((bare kind tag common)
        { dsRecoverShape = Just (role, RecoverSpec cap tagLen) })
    4 -> do
      dir <- getCipherDir
      block <- getU32
      pad <- getFlag "pad"
      checkOp common (cipherOp dir)
      pure ((bare kind tag common)
        { dsCipherShape = Just (dir, CipherSpec block (pad == 1)) })
    5 -> do
      fam <- getMsgFamily
      inner <- getInner
      mspec <- getMaybeCipherSpec
      count <- getU32
      checkOp common (msgOperation fam)
      pure ((bare kind tag common)
        { dsMessageShape = Just (fam, inner, mspec, count) })
    t -> getFail ("operation tag out of range: " ++ show t)
  -- The recorded slot must be the slot the operation truly occupies.
  let want = kindOfDecoded ds
  if want == kind
    then pure ds
    else getFail "slot tag mismatches the decoded operation"
  where
    bare k t c = DecodedSingle k t c Nothing Nothing Nothing
    checkOp c op
      | bcOp c == op = pure ()
      | otherwise = getFail "operation field mismatches the operation tag"
    recoverOp RoleSignRecover = OpSignRecover
    recoverOp RoleVerifyRecover = OpVerifyRecover
    cipherOp DirEncrypt = OpEncrypt
    cipherOp DirDecrypt = OpDecrypt

-- | The slot a decoded single truly occupies.
kindOfDecoded :: DecodedSingle -> SlotKind
kindOfDecoded ds = case dsTag ds of
  0 -> SlotDigest
  1 -> SlotSign
  2 -> SlotVerify
  3 -> case dsRecoverShape ds of
    Just (RoleSignRecover, _) -> SlotSign
    _ -> SlotVerify
  4 -> case dsCipherShape ds of
    Just (dir, _) -> dirKind dir
    _ -> SlotEncrypt
  _ -> case dsMessageShape ds of
    Just (fam, _, _, _) -> msgFamilyKind fam
    _ -> SlotEncrypt

-- | Recovery role tag.
getRecoverRole :: Get RecoverRole
getRecoverRole = do
  t <- getU8
  case t of
    0 -> pure RoleSignRecover
    1 -> pure RoleVerifyRecover
    _ -> getFail ("recover role out of range: " ++ show t)

-- | Cipher direction tag.
getCipherDir :: Get CipherDir
getCipherDir = do
  t <- getU8
  case t of
    0 -> pure DirEncrypt
    1 -> pure DirDecrypt
    _ -> getFail ("cipher direction out of range: " ++ show t)

-- | A 0/1 flag byte.
getFlag :: String -> Get Word8
getFlag what = do
  t <- getU8
  case t of
    0 -> pure 0
    1 -> pure 1
    _ -> getFail (what ++ " flag out of range: " ++ show t)

-- | Message family tag.
getMsgFamily :: Get MsgFamily
getMsgFamily = do
  t <- getU8
  case t of
    0 -> pure MsgEncrypt
    1 -> pure MsgDecrypt
    2 -> pure MsgSign
    3 -> pure MsgVerify
    _ -> getFail ("message family out of range: " ++ show t)

-- | Inner per-message state.
getInner :: Get MsgInner
getInner = do
  t <- getU8
  case t of
    0 -> pure MsgIdle
    1 -> MsgOpen <$> getLenBytes <*> getLenBytes <*> getLenBytes
    _ -> getFail ("inner tag out of range: " ++ show t)

-- | Optional cipher shape.
getMaybeCipherSpec :: Get (Maybe CipherSpec)
getMaybeCipherSpec = do
  t <- getU8
  case t of
    0 -> pure Nothing
    1 -> do
      block <- getU32
      pad <- getFlag "pad"
      pure (Just (CipherSpec block (pad == 1)))
    _ -> getFail ("cipher-spec tag out of range: " ++ show t)

-- | Dual-operation body.
getDual :: Get DecodedDual
getDual = do
  d <- getCommon
  c <- getCommon
  dir <- getCipherDir
  block <- getU32
  pad <- getFlag "pad"
  staged <- getDualStaged
  pure (DecodedDual d c dir (CipherSpec block (pad == 1)) staged)

-- | Dual staging section.
getDualStaged :: Get (Maybe DualStaged)
getDualStaged = do
  t <- getU8
  case t of
    0 -> pure Nothing
    1 -> do
      d <- getStagedOutput
      c <- getStagedOutput
      dd <- getFlag "digest-done"
      cd <- getFlag "cipher-done"
      pure (Just (DualStaged d c (dd == 1) (cd == 1)))
    _ -> getFail ("dual-staged tag out of range: " ++ show t)

-- | One shared slot state.
getCommon :: Get BareCommon
getCommon = do
  mech <- MechanismId <$> getU64
  op <- getOperation
  params <- getLenBytes
  auth <- getAuth
  buffered <- getLenBytes
  streamIv <- getChainIv
  staged <- getStaged
  key <- getKeySection
  pure (BareCommon mech op params auth buffered streamIv staged key)

-- | Chaining-value section.
getChainIv :: Get (Maybe ByteString)
getChainIv = do
  t <- getU8
  case t of
    0 -> pure Nothing
    1 -> Just <$> getLenBytes
    _ -> getFail ("chain-iv tag out of range: " ++ show t)

-- | Operation tag; bounded by the 'Operation' enumeration.
getOperation :: Get Operation
getOperation = do
  t <- getU8
  let lo = fromEnum (minBound :: Operation)
      hi = fromEnum (maxBound :: Operation)
  if fromIntegral t >= lo && fromIntegral t <= hi
    then pure (toEnum (fromIntegral t))
    else getFail ("operation field out of range: " ++ show t)

-- | Auth mark tag.
getAuth :: Get OpAuth
getAuth = do
  t <- getU8
  case t of
    0 -> pure AuthNone
    1 -> pure AuthPending
    2 -> pure AuthSatisfied
    _ -> getFail ("auth tag out of range: " ++ show t)

-- | Staged-output section.
getStaged :: Get (Maybe StagedOutput)
getStaged = do
  t <- getU8
  case t of
    0 -> pure Nothing
    1 -> Just <$> getStagedOutput
    _ -> getFail ("staged tag out of range: " ++ show t)

-- | One staged output: name, bytes, liveness.
getStagedOutput :: Get StagedOutput
getStagedOutput = do
  nameBs <- getLenBytes
  out <- getLenBytes
  lst <- getLiveness
  case TE.decodeUtf8' nameBs of
    Left _ -> getFail "staged name is not UTF-8"
    Right name -> pure (StagedOutput (T.unpack name) out lst)

-- | One-shot liveness.
getLiveness :: Get OpState
getLiveness = do
  t <- getU8
  case t of
    0 -> OpLive . Consumption <$> getU32
    1 -> pure OpDead
    _ -> getFail ("liveness tag out of range: " ++ show t)

-- | Key section: absent, or a canonical identity.
getKeySection :: Get (Maybe KeyIdentity)
getKeySection = do
  t <- getU8
  case t of
    0 -> pure Nothing
    1 -> do
      cls <- getU32
      ktyRaw <- getU32
      fpr <- getU64
      if 0 <= cls && cls < 0x7FFFFFFF
        then case ktyRaw of
          0xFFFFFFFF -> pure (Just (KeyIdentity cls Nothing fpr))
          k | 0 <= k && k < 0x7FFFFFFF ->
            pure (Just (KeyIdentity cls (Just k) fpr))
          k -> getFail ("key type out of range: " ++ show k)
        else getFail ("key class out of range: " ++ show cls)
    _ -> getFail ("key-section tag out of range: " ++ show t)
