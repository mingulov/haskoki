{- | KEM encapsulation planning (pure).

ML-KEM encapsulation over the shared pending-object publication:
a length query ('IntentNull') answers the mechanism's ciphertext
length and creates nothing; a short buffer likewise reports the
length and creates nothing; a sufficient buffer plans exactly one
'FxKemEncaps' effect whose answer completes the pending shared-secret
object. The delivery call returns the ciphertext bytes plus exactly
one handle. Decapsulation recovers the shared secret as exactly one
handle; a rejected ciphertext fails closed with zero objects.
-}
{-# LANGUAGE OverloadedStrings #-}
module Haskoki.Operation.Kem
  ( KemAlg (..)
  , kemCtLen
  , kemSsLen
  , kemAlgNum
  , kemAlgName
  , kemAlgFromName
  , mlKemMech
  , mlKemKeyPairGenMech
  , planKemEncaps
  , planKemDecaps
  ) where

import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BC8
import Data.ByteString (ByteString)
import qualified Data.Map.Strict as Map

import Haskoki.Attribute (AttributeType (..), AttributeValue (..), encodeValue)
import Haskoki.Model (Model, ObjectState (..), SessionState)
import Haskoki.Object (objectVisible, resolveHandle)
import Haskoki.Operation.Effect (CryptoEffect (..))
import Haskoki.Operation.KeyManagement
  ( KeyDeny (..)
  , KeyPlan (..)
  , PendingWork (..)
  , checkKeyTemplate
  , ckkGenericSecret
  , ckkMlKem
  , ckoSecretKey
  , pendingFromAttrs
  )
import Haskoki.Outcome
  ( NativeOutput (..)
  , PlanResult (..)
  , PreparedCommit (..)
  , Rejection (..)
  , StateDelta (..)
  )
import Haskoki.Registry (MechanismId (..))
import Haskoki.Registry.Generated (ckm_ML_KEM, ckm_ML_KEM_KEY_PAIR_GEN)
import Haskoki.Request (OutputIntent (..), OutputRegion (..))
import Haskoki.Types (ExternalHandle, ReturnCode (..))

-- | The ML-KEM parameter sets. Ciphertext lengths are the standard
-- 768\/1088\/1568 bytes; every shared secret is 32 bytes.
data KemAlg
  = KemMl512
  | KemMl768
  | KemMl1024
  deriving (Eq, Ord, Show, Enum, Bounded)

-- | Ciphertext length in bytes.
kemCtLen :: KemAlg -> Int
kemCtLen alg = case alg of
  KemMl512 -> 768
  KemMl768 -> 1088
  KemMl1024 -> 1568

-- | Shared-secret length in bytes.
kemSsLen :: KemAlg -> Int
kemSsLen _ = 32

-- | The parameter-set number carried on key objects ('AttrKemAlg').
kemAlgNum :: KemAlg -> Int
kemAlgNum alg = case alg of
  KemMl512 -> 512
  KemMl768 -> 768
  KemMl1024 -> 1024

-- | The mechanism-parameter name carried on 'FxKemEncaps'.
kemAlgName :: KemAlg -> ByteString
kemAlgName alg = case alg of
  KemMl512 -> "ML-KEM-512"
  KemMl768 -> "ML-KEM-768"
  KemMl1024 -> "ML-KEM-1024"

-- | Parse a mechanism-parameter name back to its set.
kemAlgFromName :: ByteString -> Maybe KemAlg
kemAlgFromName bs = case BC8.unpack bs of
  "ML-KEM-512" -> Just KemMl512
  "ML-KEM-768" -> Just KemMl768
  "ML-KEM-1024" -> Just KemMl1024
  _ -> Nothing

-- | @CKM_ML_KEM@ (generated id, resolved by name).
mlKemMech :: MechanismId
mlKemMech = MechanismId (ckm_ML_KEM)

-- | @CKM_ML_KEM_KEY_PAIR_GEN@ (generated id, resolved by name).
mlKemKeyPairGenMech :: MechanismId
mlKemKeyPairGenMech = MechanismId (ckm_ML_KEM_KEY_PAIR_GEN)

-- | Plan one encapsulation against a peer public key: the mechanism
-- must be ML-KEM, the handle must resolve to a visible ML-KEM key
-- of this parameter set carrying the encapsulate mark, and the
-- secret template must describe a 32-byte generic secret. Check
-- order is documented and tested: mechanism, handle, key kind and
-- parameter set, usage mark, template, then the output intent.
planKemEncaps
  :: Model -> SessionState -> MechanismId -> ExternalHandle -> KemAlg
  -> [(AttributeType, AttributeValue)] -> OutputIntent
  -> KeyPlan
planKemEncaps model st mech h alg tmpl intent
  | mech /= mlKemMech =
      KeyDenied (KeyDeny CKR_MECHANISM_INVALID
        ("not a KEM mechanism: " ++ show mech))
  | otherwise = case resolveHandle model h of
      Nothing -> KeyDenied (KeyDeny CKR_OBJECT_HANDLE_INVALID
        "unknown or destroyed key handle")
      Just ost
        | not (objectVisible st ost) -> KeyDenied (KeyDeny CKR_OBJECT_HANDLE_INVALID
            "object not visible in this session")
        | Map.lookup AttrKeyType (osAttrs ost) /= Just (ValULong ckkMlKem) ->
            KeyDenied (KeyDeny CKR_KEY_FUNCTION_NOT_PERMITTED
              "peer key is not an ML-KEM key")
        | Map.lookup AttrKemAlg (osAttrs ost) /= Just (ValULong (fromIntegral (kemAlgNum alg))) ->
            KeyDenied (KeyDeny CKR_KEY_FUNCTION_NOT_PERMITTED
              "peer key names a different KEM parameter set")
        | Map.lookup AttrEncapsulate (osAttrs ost) /= Just (ValBool True) ->
            KeyDenied (KeyDeny CKR_KEY_FUNCTION_NOT_PERMITTED
              "peer key does not permit encapsulation")
        | otherwise -> case checkKeyTemplate ckoSecretKey ckkGenericSecret tmpl of
            Left deny -> KeyDenied deny
            Right attrs -> case checkSecretLen attrs of
              Left deny -> KeyDenied deny
              Right attrs' ->
                let po = pendingFromAttrs st attrs'
                    ctLen = kemCtLen alg
                    lenOut = NativeOutput (RegionBytes "ciphertext" intent)
                      (encodeValue (ValULong (fromIntegral ctLen)))
                in case intent of
                  IntentNull -> KeyImmediate (Immediate PreparedCommit
                    { pcCode = CKR_OK
                    , pcDelta = StateDelta []
                    , pcPersist = []
                    , pcOutputs = [lenOut]
                    , pcReleases = []
                    , pcReasons = ["encapsulation length query; no key created"]
                    })
                  IntentBuffer cap
                    | cap < fromIntegral ctLen -> KeyImmediate (Reject Rejection
                        { rejCode = CKR_BUFFER_TOO_SMALL
                        , rejOutputs = [lenOut]
                        , rejDelta = StateDelta []
                        , rejReleases = []
                        , rejReasons = ["short buffer; no key created"]
                        })
                    | otherwise -> KeyEffect
                        (PwEncaps po ctLen (kemSsLen alg))
                        (FxKemEncaps mech (Just (osId ost)) (kemAlgName alg) mempty)

-- | The secret template must ask for a 32-byte secret: absent
-- defaults to 32, anything else is inconsistent.
checkSecretLen
  :: Map.Map AttributeType AttributeValue
  -> Either KeyDeny (Map.Map AttributeType AttributeValue)
checkSecretLen attrs = case Map.lookup AttrValueLen attrs of
  Nothing -> Right (Map.insert AttrValueLen (ValULong 32) attrs)
  Just (ValULong 32) -> Right attrs
  _ -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
    "KEM shared secrets are 32 bytes")

-- | Plan one decapsulation against a private KEM key: the ciphertext
-- must be exactly the mechanism's length (checked purely, before any
-- effect), the handle must resolve to a visible ML-KEM key of this
-- parameter set carrying the decapsulate mark, and the secret
-- template must describe a 32-byte generic secret. The answer
-- completes exactly one pending secret object.
planKemDecaps
  :: Model -> SessionState -> MechanismId -> ExternalHandle -> KemAlg
  -> ByteString -> [(AttributeType, AttributeValue)]
  -> KeyPlan
planKemDecaps model st mech h alg ct tmpl
  | mech /= mlKemMech =
      KeyDenied (KeyDeny CKR_MECHANISM_INVALID
        ("not a KEM mechanism: " ++ show mech))
  | BS.length ct /= kemCtLen alg =
      KeyDenied (KeyDeny CKR_ARGUMENTS_BAD
        ("ciphertext length " ++ show (BS.length ct)
          ++ " mismatches " ++ show (kemCtLen alg)))
  | otherwise = case resolveHandle model h of
      Nothing -> KeyDenied (KeyDeny CKR_OBJECT_HANDLE_INVALID
        "unknown or destroyed key handle")
      Just ost
        | not (objectVisible st ost) -> KeyDenied (KeyDeny CKR_OBJECT_HANDLE_INVALID
            "object not visible in this session")
        | Map.lookup AttrKeyType (osAttrs ost) /= Just (ValULong ckkMlKem) ->
            KeyDenied (KeyDeny CKR_KEY_FUNCTION_NOT_PERMITTED
              "key is not an ML-KEM key")
        | Map.lookup AttrKemAlg (osAttrs ost) /= Just (ValULong (fromIntegral (kemAlgNum alg))) ->
            KeyDenied (KeyDeny CKR_KEY_FUNCTION_NOT_PERMITTED
              "key names a different KEM parameter set")
        | Map.lookup AttrDecapsulate (osAttrs ost) /= Just (ValBool True) ->
            KeyDenied (KeyDeny CKR_KEY_FUNCTION_NOT_PERMITTED
              "key does not permit decapsulation")
        | otherwise -> case checkKeyTemplate ckoSecretKey ckkGenericSecret tmpl of
            Left deny -> KeyDenied deny
            Right attrs -> case checkSecretLen attrs of
              Left deny -> KeyDenied deny
              Right attrs' ->
                KeyEffect (PwDecaps (pendingFromAttrs st attrs'))
                  (FxKemDecaps mech (Just (osId ost)) (kemAlgName alg) ct)
