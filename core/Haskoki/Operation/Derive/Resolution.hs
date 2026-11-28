{- | Haskoki.Operation.Derive.Resolution: base/aux key resolution and derive-time key checks.
-}
module Haskoki.Operation.Derive.Resolution
  ( auxAttrsOf
  , LenDefault (..)
  , resolveBase
  , resolveBaseAnyMark
  , ikeBaseOk
  , resolveAuxKey
  , byteOpsBaseOkState
  , ikeCeiling
  , curvesDiffer
  , isMontgomery
  , xdhPeerMismatched
  ) where


import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import qualified Data.Map.Strict as Map
import Data.Word (Word64, Word8)

import Haskoki.Attribute (AttributeType (..), AttributeValue (..))
import Haskoki.Model (Model (..), ObjectState (..), SessionState)
import Haskoki.Object (objectVisible, resolveHandle)
import Haskoki.Operation.KeyManagement
  ( KeyDeny (..)
  , ckkEcMontgomery
  , keyBytesOf
  , mechAllowed
  )
import Haskoki.Recipe.Ecdh
  ( xdhSecretWidth
  )
import Haskoki.Recipe.Ecdsa (ecdsaCurveOfDer)
import Haskoki.Recipe.Kdf
  ( kdfCodeDigest
  , kdfDigestWidth
  )
import Haskoki.Recipe.Ike
  ( IkeKind (..)
  , ikeBaseKeyOk
  , maxIkeOutput
  )
import Haskoki.Recipe.ByteOps
  ( byteOpsBaseKeyOk
  )
import Haskoki.Registry (MechanismId (..))
import Haskoki.Types (ExternalHandle (..), ObjectId, ReturnCode (..))

-- | Project aux-key attributes out of the model: 'Nothing' when
-- the mechanism takes no aux key. A resolved aux always looks up
-- (same model); 'Nothing' on a 'Just' handle is
-- unreachable-defensive and denies at the call site.
auxAttrsOf :: Model -> Maybe ObjectId -> Maybe (Maybe (Map.Map AttributeType AttributeValue))
auxAttrsOf _ Nothing = Just Nothing
auxAttrsOf model (Just oid) = Just <$> (osAttrs <$> Map.lookup oid (mObjects model))

-- | How a derive family fills an omitted @CKA_VALUE_LEN@.
data LenDefault
  = NoLenDefault
    -- ^ the length is required (INCOMPLETE when absent)
  | GenericLenDefault !Int
    -- ^ generic-secret targets default to this width; typed
    -- targets need a length
  | SpecLenDefault !Int !Bool
    -- ^ the PKCS#11 hash-KDF and concat\/XOR rule: an untyped
    -- target defaults to this width, a typed target to its type's
    -- single defined length, otherwise INCOMPLETE. The flag keeps
    -- the byte-op rows' pinned default for an explicit generic
    -- type (hash KDF: an explicit generic secret has no defined
    -- length, so it stays INCOMPLETE)

-- | Resolve the base key: known handle, session-visible, derive
-- mark set, the derive mechanism in the allowed mechanisms,
-- stored material present. Shared by the derive families that
-- resolve a marked base (identical denials, one
-- implementation).
--
-- Refusal order: the handle resolves first, then session
-- visibility (both deny @CKR_KEY_HANDLE_INVALID@), then the
-- derive mark, then the allowed-mechanism list (both deny
-- @CKR_KEY_FUNCTION_NOT_PERMITTED@), then stored material
-- (@CKR_GENERAL_ERROR@), and only then the family key type and
-- the object class (both deny @CKR_KEY_TYPE_INCONSISTENT@,
-- decided by the family arm after this returns). A wrong-type
-- base without the mark therefore answers
-- @CKR_KEY_FUNCTION_NOT_PERMITTED@; operation init orders the
-- same checks type, class, allowed list, usage.
resolveBase
  :: Model -> SessionState -> MechanismId -> ExternalHandle
  -> Either KeyDeny (ObjectState, ByteString)
resolveBase model st dMech baseH = case resolveHandle model baseH of
  Nothing -> Left (KeyDeny CKR_KEY_HANDLE_INVALID
    "unknown or destroyed base-key handle")
  Just ost
    | not (objectVisible st ost) -> Left (KeyDeny CKR_KEY_HANDLE_INVALID
        "base key not visible in this session")
    | Map.lookup AttrDerive (osAttrs ost) /= Just (ValBool True) ->
        Left (KeyDeny CKR_KEY_FUNCTION_NOT_PERMITTED
          "base key does not permit derivation")
    | not (mechAllowed dMech ost) -> Left (KeyDeny CKR_KEY_FUNCTION_NOT_PERMITTED
        "mechanism is not in the key's allowed list")
    | otherwise -> case keyBytesOf ost of
        Nothing -> Left (KeyDeny CKR_GENERAL_ERROR
          "base key lacks material")
        Just mat -> Right (ost, mat)

-- | Resolve the base key ignoring CKA_DERIVE: known handle,
-- session-visible, stored material present. The pub-from-priv
-- row is the only derive allowed to skip the mark (same
-- denials otherwise, one implementation shape with
-- 'resolveBase').
resolveBaseAnyMark
  :: Model -> SessionState -> ExternalHandle
  -> Either KeyDeny (ObjectState, ByteString)
resolveBaseAnyMark model st baseH = case resolveHandle model baseH of
  Nothing -> Left (KeyDeny CKR_KEY_HANDLE_INVALID
    "unknown or destroyed base-key handle")
  Just ost
    | not (objectVisible st ost) -> Left (KeyDeny CKR_KEY_HANDLE_INVALID
        "base key not visible in this session")
    | otherwise -> case keyBytesOf ost of
        Nothing -> Left (KeyDeny CKR_GENERAL_ERROR
          "base key lacks material")
        Just mat -> Right (ost, mat)

-- | An IKE base\/aux object: generic-secret or HMAC type (the
-- recipe rule; a missing or mistyped key type denies).
ikeBaseOk :: ObjectState -> Bool
ikeBaseOk ost = case Map.lookup AttrKeyType (osAttrs ost) of
  Just (ValULong kty) -> ikeBaseKeyOk kty
  _ -> False

-- | Resolve a params-carried aux handle (0 = absent),
-- held to the same visibility, type, permission, allowed
-- mechanisms, and material rules as the base key; the type
-- check and its label ride per family (IKE: generic or HMAC;
-- byte-ops: generic only).
resolveAuxKey
  :: (ObjectState -> Bool) -> String
  -> Model -> SessionState -> MechanismId -> Word64
  -> Either KeyDeny (Maybe ObjectId)
resolveAuxKey _ _ _ _ _ 0 = Right Nothing
resolveAuxKey typeOk label model st dMech auxN =
  case resolveHandle model (ExternalHandle (fromIntegral auxN)) of
    Nothing -> Left (KeyDeny CKR_KEY_HANDLE_INVALID
      "unknown or destroyed aux-key handle")
    Just ost
      | not (objectVisible st ost) -> Left (KeyDeny CKR_KEY_HANDLE_INVALID
          "aux key not visible in this session")
      | not (typeOk ost) -> Left (KeyDeny CKR_KEY_TYPE_INCONSISTENT
          (label ++ " aux key has the wrong key type"))
      | Map.lookup AttrDerive (osAttrs ost) /= Just (ValBool True) ->
          Left (KeyDeny CKR_KEY_FUNCTION_NOT_PERMITTED
            "aux key does not permit derivation")
      | not (mechAllowed dMech ost) -> Left (KeyDeny CKR_KEY_FUNCTION_NOT_PERMITTED
          "mechanism is not in the key's allowed list")
      | otherwise -> case keyBytesOf ost of
          Nothing -> Left (KeyDeny CKR_GENERAL_ERROR
            "aux key lacks material")
          Just _ -> Right (Just (osId ost))

-- | Byte-op base\/aux type check over object state.
byteOpsBaseOkState :: ObjectState -> Bool
byteOpsBaseOkState ost = case Map.lookup AttrKeyType (osAttrs ost) of
  Just (ValULong kty) -> byteOpsBaseKeyOk kty
  _ -> False

-- | The output ceiling by kind: the single-shot rows cap at
-- their PRF width (truncation serves the AES legs); the
-- iterating rows cap at the prf+ counter capacity.
ikeCeiling :: IkeKind -> Word8 -> Maybe Int
ikeCeiling kind prf = case kind of
  Ike2PrfPlus -> blockCeiling
  Ike1Extended -> Just maxIkeOutput
  IkePrf -> digestWidth
  Ike1Prf -> digestWidth
  where
    digestWidth = do
      stem <- kdfCodeDigest (fromIntegral prf)
      kdfDigestWidth stem
    -- prf+ runs a single-byte counter: 255 blocks of the hash
    -- width. The flat cap over-admits small hashes (SHA-256
    -- tops out at 8160, not 16320); the backend refuses past
    -- the counter capacity, so the planner must too.
    blockCeiling = do
      stem <- kdfCodeDigest (fromIntegral prf)
      hLen <- kdfDigestWidth stem
      pure (255 * hLen)

-- | Base/peer curve agreement: a mismatch denies only when BOTH
-- sides scan as DER EC keys on different curves. Unscannable sides
-- (synthetic opaque bytes) pass — the backends enforce key shape.
curvesDiffer :: ByteString -> ByteString -> Bool
curvesDiffer base peer = case (ecdsaCurveOfDer base, ecdsaCurveOfDer peer) of
  (Just a, Just b) -> a /= b
  _ -> False

-- | A Montgomery base key (the XDH agreement shape).
isMontgomery :: ObjectState -> Bool
isMontgomery ost =
  Map.lookup AttrKeyType (osAttrs ost) == Just (ValULong ckkEcMontgomery)

-- | A Montgomery base whose scanned curve width disagrees with the
-- raw peer length (the XDH peer is the bare RFC 7748 coordinate,
-- never a wrapped point). Unscannable bases (synthetic opaque
-- doubles) cannot be checked here — the backend arbitrates, the
-- Weierstrass opaque precedent.
xdhPeerMismatched :: ObjectState -> ByteString -> ByteString -> Bool
xdhPeerMismatched ost mat peer =
  isMontgomery ost && case xdhSecretWidth mat of
    Just w -> BS.length peer /= w
    Nothing -> False
