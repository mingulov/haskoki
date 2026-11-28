{- | Key-derivation planning: one multi-key codec (pure).

A derive call frames its context string plus one or more key
templates ('encodeDeriveParams'); 'planDerive' decodes the frame,
validates EVERY template before planning, and emits one 'FxDerive'
effect whose concatenated answer 'finishWork' splits across the
pending objects. Any invalid template — or a malformed frame —
denies with zero objects published.

Key derivation offers HKDF with HMAC-SHA-256 (RFC 5869):
expand-only over the base key bytes, or extract-then-expand with
an explicit salt (empty salt extracts against HashLen zeros).
The same base, salt, context and lengths replay the same bytes
on every backend offering HMAC-SHA-256. Extract-only is refused:
combine extract and expand.
ECDH agreement (plain or cofactor, per the mechanism row) runs
between the base EC key and the peer public key
carried in the frame's info segment: the raw x-coordinate secret,
truncated across the pending objects (leading bytes dropped per
PKCS#11 v3.2; a missing CKA_VALUE_LEN takes the full secret).
Derived totals are capped by
the construction's ceiling (the HKDF-Expand ceiling for HKDF, the
base curve's coordinate width for ECDH). The hash and PBKDF2
constructions are the SHA key-derivations (hash the base value,
truncate to the
digest width; empty info) and PBKDF2 (HMAC-PRF iterations over
salt and block index, truncated to the planned length; the
@pbkd2-params\/1@ frame travels in the info segment), capped by
the digest width and the shared ceiling respectively.
-}
{-# LANGUAGE OverloadedStrings #-}
module Haskoki.Operation.Derive
  ( hkdfDeriveMech
  , hkdfDataMech
  , pubPrivMech
  , maxDerivedTotal
  , maxXofTotal
  , maxDeriveKeys
  , maxDeriveInfo
  , encodeDeriveParams
  , decodeDeriveParams
  , encodeHkdfInfo
  , decodeHkdfInfo
  , planDerive
  ) where


import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import qualified Data.Map.Strict as Map

import Haskoki.Attribute (AttributeType (..), AttributeValue (..), payloadSealed)
import Haskoki.Model (Model (..), ObjectState (..), SessionState)
import Haskoki.Object (effectiveAttrs, effectiveExtractable, effectiveSensitive)
import Haskoki.Operation.Derive.Framing
import Haskoki.Operation.Derive.Resolution
import Haskoki.Operation.Derive.Stamping
import Haskoki.Operation.Effect (CryptoEffect (..))
import Haskoki.Operation.KeyManagement
  ( KeyDeny (..)
  , KeyPlan (..)
  , PendingWork (..)
  , byteOpsProtectionOf
  , checkDataTemplate
  , checkDerivedTarget
  , checkKeyTemplateAny
  , DerivedDomain (..)
  , ckkEc
  , ckkEcMontgomery
  , ckkGenericSecret
  , ckoData
  , ckoPrivateKey
  , ckoPublicKey
  , ckoSecretKey
  , derivedObjectDomain
  , keyBytesOf
  , pendingFromAttrs
  , resolveByteOpsProtection
  , sealedByteOpChildOk
  )
import Haskoki.Attribute.Generated (mustKeyTypeId)
import Haskoki.Recipe.Dh
  ( DhRecipe (..)
  , decodeDhParams
  , dhParamsValid
  , dhRecipeFor
  , dhSecretWidth
  )
import Haskoki.Recipe.EncryptData
  ( EncryptDataRecipe (..)
  , encryptDataOutputLen
  , encryptDataParamsValid
  , encryptDataRecipeFor
  )
import Haskoki.Recipe.Ecdh
  ( EcdhRecipe (..)
  , decodeEcdhParams
  , ecdhParamsValid
  , ecdhRecipeFor
  , ecdhSecretWidth
  )
import Haskoki.Recipe.Kdf
  ( KdfRecipe (..)
  , kdfParamsValid
  , kdfRecipeFor
  , kdfShaWidth
  , kdfXofStem
  )
import Haskoki.Recipe.PubPriv
  ( pubPrivBaseKeyOk
  , pubPrivBaseMatOk
  , pubPrivMapAttrs
  , pubPrivParamsValid
  , pubPrivRecipeFor
  )
import Haskoki.Recipe.Sp800108
  ( Sp800Params (..)
  , Sp800Recipe (..)
  , decodeSp800Params
  , maxSp800Total
  , sp800ParamsValid
  , sp800RecipeFor
  )
import Haskoki.Recipe.Ike
  ( IkeKind (..)
  , IkeRecipe (..)
  , decodeIkeParams
  , ikeParamsValid
  , ikeRecipeFor
  )
import Haskoki.Recipe.ByteOps
  ( ByteOpsKind (..)
  , ByteOpsRecipe (..)
  , byteOpsParamsValid
  , byteOpsRecipeFor
  , decodeByteOpsParams
  , maxByteOpsOutput
  )
import Haskoki.Recipe.TlsKdf
  ( maxTlsKdfOutput
  , tlsKdfParamsValid
  , tlsKdfRecipeFor
  )
import Haskoki.Recipe.Ssl3
  ( Ssl3KeyMatRole (..)
  , Ssl3Kind (..)
  , Ssl3Recipe (..)
  , decodeSsl3KeyMatParams
  , ssl3KeyMatLayout
  , ssl3ParamsValid
  , ssl3RecipeFor
  )
import Haskoki.Recipe.TlsKeyMat
  ( TlsKeyMatKind (..)
  , TlsKeyMatRecipe (..)
  , TlsKeyMatRole (..)
  , decodeTlsKeyMatParams
  , tlsKeyMatLayout
  , tlsKeyMatParamsValid
  , tlsKeyMatRecipeFor
  )
import Haskoki.Recipe.TlsPrf
  ( maxTlsPrfOutput
  , tlsPrfParamsValid
  , tlsPrfRecipeFor
  )
import Haskoki.Registry (MechanismId (..))
import Haskoki.Rules (Rules)
import Haskoki.Session (admitCode, admitObjects)
import Haskoki.Types (ExternalHandle (..), ReturnCode (..))

-- | Plan one (possibly multi-key) derivation: the mechanism must be
-- a derive mechanism (HKDF, ECDH, or KDF), the base handle must
-- resolve to a visible key carrying the derive mark and stored
-- material, and EVERY template must describe a secret key with a
-- positive length — except ECDH templates, where a missing
-- CKA_VALUE_LEN defaults to the full agreement secret (PKCS#11
-- v3.2: truncation applies "if it has one" a length), and
-- HKDF-DATA templates, which describe data objects (CKO_DATA
-- with CKA_VALUE_LEN, never keys). Check
-- order: mechanism, frame, base, then templates in order; the
-- first failure denies with zero objects.
-- ECDH arms resolve the base and require an EC or Montgomery
-- key type before examining parameters, and SHA-KDF arms require
-- a generic-secret
-- base (a key-type contradiction outranks parameter shape); ECDH
-- frames carry the agreement parameters ('ecdh-params/1') in the
-- info segment and the derived total is capped by the base
-- curve's coordinate width; HKDF frames carry the
-- prf/mode/salt/context segment ('encodeHkdfInfo'), capped by the
-- PRF's HKDF-Expand ceiling (255 x HashLen).
-- Extract-only refuses; admission gates with the
-- EXACT validated template count (post-validation: an
-- unvalidated count could over-refuse).
planDerive
  :: Rules -> Model -> SessionState -> MechanismId -> ExternalHandle
  -> ByteString -> KeyPlan
planDerive rules model st mech baseH blob
  | mech == hkdfDataMech = case decodeDeriveParams blob of
      Nothing -> KeyDenied (KeyDeny CKR_ARGUMENTS_BAD
        "malformed derive arguments")
      -- The same KDF as 'hkdfDeriveMech' (same base acceptance:
      -- any visible key with the derive mark and stored
      -- material); only the output class differs (data objects,
      -- never keys) and data templates take no length default.
      Just (infoSeg, tmpls) -> case decodeHkdfInfo infoSeg of
        Nothing -> KeyDenied (KeyDeny CKR_ARGUMENTS_BAD
          "malformed HKDF info segment")
        Just (prf, mode, salt, info)
          | mode == 0x01 -> KeyDenied (KeyDeny CKR_MECHANISM_PARAM_INVALID
              "HKDF extract-only is not served; combine extract and expand")
          | otherwise -> case prfHashLen prf of
              Nothing -> KeyDenied (KeyDeny CKR_MECHANISM_PARAM_INVALID
                "HKDF PRF has no servable hash length")
              Just hashLen -> case resolveBase model st mech baseH of
                Left deny -> KeyDenied deny
                Right (ost, _) -> finishData tmpls (255 * hashLen)
                  "derived total exceeds the HKDF-Expand ceiling"
                  (FxDerive mech (Just (osId ost)) Nothing
                    (BS.singleton prf <> BS.singleton mode <> salt) info)
                  CKR_ARGUMENTS_BAD
  | mech == hkdfDeriveMech = case decodeDeriveParams blob of
      Nothing -> KeyDenied (KeyDeny CKR_ARGUMENTS_BAD
        "malformed derive arguments")
      Just (infoSeg, tmpls) -> case decodeHkdfInfo infoSeg of
        Nothing -> KeyDenied (KeyDeny CKR_ARGUMENTS_BAD
          "malformed HKDF info segment")
        Just (prf, mode, salt, info)
          | mode == 0x01 -> KeyDenied (KeyDeny CKR_MECHANISM_PARAM_INVALID
              "HKDF extract-only is not served; combine extract and expand")
          | otherwise -> case prfHashLen prf of
              Nothing -> KeyDenied (KeyDeny CKR_MECHANISM_PARAM_INVALID
                "HKDF PRF has no servable hash length")
              Just hashLen -> case resolveBase model st mech baseH of
                Left deny -> KeyDenied deny
                Right (ost, _) -> finish (osAttrs ost) Nothing tmpls (255 * hashLen)
                  "derived total exceeds the HKDF-Expand ceiling"
                  (FxDerive mech (Just (osId ost)) Nothing
                    (BS.singleton prf <> BS.singleton mode <> salt) info)
                  -- A missing length defaults to the PRF hash
                  -- length: the mechanism doc says VALUE_LEN "should
                  -- be set" (non-mandatory), like the ECDH default.
                  (Just hashLen)
                  CKR_ARGUMENTS_BAD
  | Just r <- pubPrivRecipeFor mech = case decodeDeriveParams blob of
      Nothing -> KeyDenied (KeyDeny CKR_ARGUMENTS_BAD
        "malformed derive arguments")
      -- The base resolves WITHOUT the derive-mark check (the
      -- only row allowed to ignore it); class, type and
      -- material contradictions outrank parameter shape (the
      -- Init-matrix ordering, shared with the ECDH arm).
      Just (infoSeg, tmpls) -> case resolveBaseAnyMark model st baseH of
        Left deny -> KeyDenied deny
        Right (ost, mat)
          | Map.lookup AttrClass (osAttrs ost) /= Just (ValULong ckoPrivateKey) ->
              -- Unified with the agreement arms (ECDH/DH refuse a
              -- non-private base the same way): §5.18.5.
              KeyDenied (KeyDeny CKR_KEY_TYPE_INCONSISTENT
                "pub-from-priv base is not a private key")
          | otherwise -> case Map.lookup AttrKeyType (osAttrs ost) of
              Just (ValULong kty)
                | not (pubPrivBaseKeyOk kty) -> KeyDenied (KeyDeny CKR_KEY_TYPE_INCONSISTENT
                    "pub-from-priv base key type is not served")
                | not (pubPrivBaseMatOk kty mat) -> KeyDenied (KeyDeny CKR_TEMPLATE_INCOMPLETE
                    "EC base lacks an embedded public point")
                | not (pubPrivParamsValid r infoSeg) -> KeyDenied (KeyDeny CKR_ARGUMENTS_BAD
                    "pub-from-priv takes empty parameters")
                | otherwise -> case tmpls of
                    [tmpl] -> case checkKeyTemplateAny ckoPublicKey kty tmpl of
                      Left deny -> KeyDenied deny
                      Right caller -> case Map.lookup AttrKeyType caller of
                        Just (ValULong k)
                          | k == kty -> finishPub ost kty caller
                          | otherwise -> KeyDenied (KeyDeny CKR_TEMPLATE_INCONSISTENT
                              "derived key type differs from the base key")
                        _ -> KeyDenied (KeyDeny CKR_TEMPLATE_INCONSISTENT
                          "derived key type is malformed")
                    _ -> KeyDenied (KeyDeny CKR_ARGUMENTS_BAD
                      "pub-from-priv derives exactly one key")
              _ -> KeyDenied (KeyDeny CKR_KEY_TYPE_INCONSISTENT
                "pub-from-priv base key type is not served")
  | Just r <- ecdhRecipeFor mech = case decodeDeriveParams blob of
      Nothing -> KeyDenied (KeyDeny CKR_ARGUMENTS_BAD
        "malformed derive arguments")
      -- Key-type and class contradictions outrank parameter
      -- shape (the Init-matrix ordering): the base resolves and
      -- must be a private EC key before params are examined.
      -- The class arm is stricter than init's coherence check:
      -- the agreement needs the private half, so a secret- or
      -- public-class object with a matching key type (a row
      -- stored before the creation gate) still refuses here,
      -- with the same return code.
      Just (ecdhBlob, tmpls) -> case resolveBase model st mech baseH of
        Left deny -> KeyDenied deny
        Right (ost, mat)
          | Map.lookup AttrKeyType (osAttrs ost) /= Just (ValULong ckkEc)
          , Map.lookup AttrKeyType (osAttrs ost) /= Just (ValULong ckkEcMontgomery) ->
              KeyDenied (KeyDeny CKR_KEY_TYPE_INCONSISTENT
                "ECDH base key is not an EC or Montgomery key")
          | Map.lookup AttrClass (osAttrs ost) /= Just (ValULong ckoPrivateKey) ->
              KeyDenied (KeyDeny CKR_KEY_TYPE_INCONSISTENT
                "ECDH base key is not a private key")
          | not (ecdhParamsValid r ecdhBlob) -> KeyDenied (KeyDeny CKR_MECHANISM_PARAM_INVALID
              "ECDH mechanism parameters rejected by the recipe")
          | rhCofactor r && isMontgomery ost -> KeyDenied (KeyDeny CKR_MECHANISM_PARAM_INVALID
              "cofactor derive is not served over Montgomery curves")
          | otherwise -> case decodeEcdhParams ecdhBlob of
              Just (_, _, peer)
                | curvesDiffer mat peer -> KeyDenied (KeyDeny CKR_MECHANISM_PARAM_INVALID
                    "ECDH base/peer curve mismatch")
                | xdhPeerMismatched ost mat peer -> KeyDenied (KeyDeny CKR_MECHANISM_PARAM_INVALID
                    "ECDH Montgomery peer length mismatch")
                | otherwise -> finish (osAttrs ost) Nothing tmpls (ecdhSecretWidth mat)
                    "derived total exceeds the ECDH secret width"
                    (FxDerive mech (Just (osId ost)) Nothing ecdhBlob BS.empty)
                    (Just (ecdhSecretWidth mat))
                    CKR_ARGUMENTS_BAD
              _ -> KeyDenied (KeyDeny CKR_MECHANISM_PARAM_INVALID
                "ECDH mechanism parameters rejected by the recipe")
  | Just r <- dhRecipeFor mech = case decodeDeriveParams blob of
      Nothing -> KeyDenied (KeyDeny CKR_ARGUMENTS_BAD
        "malformed derive arguments")
      -- Same ordering as ECDH: the base resolves and must carry
      -- the row's key type (CKK_DH vs CKK_X9_42_DH) on a private
      -- object before params are examined. The peer is bare
      -- bytes (no domain framing to compare), so range
      -- membership is enforced by the executing backend, which
      -- owns the prime.
      Just (dhBlob, tmpls) -> case resolveBase model st mech baseH of
        Left deny -> KeyDenied deny
        Right (ost, mat)
          | Map.lookup AttrKeyType (osAttrs ost) /= Just (ValULong (dhKeyType r)) ->
              KeyDenied (KeyDeny CKR_KEY_TYPE_INCONSISTENT
                "DH base key type mismatch for the mechanism row")
          | Map.lookup AttrClass (osAttrs ost) /= Just (ValULong ckoPrivateKey) ->
              KeyDenied (KeyDeny CKR_KEY_TYPE_INCONSISTENT
                "DH base key is not a private key")
          | not (dhParamsValid r dhBlob) -> KeyDenied (KeyDeny CKR_MECHANISM_PARAM_INVALID
              "DH mechanism parameters rejected by the recipe")
          | otherwise -> case decodeDhParams dhBlob of
              Just _ -> finish (osAttrs ost) Nothing tmpls (dhSecretWidth mat)
                "derived total exceeds the DH secret width"
                (FxDerive mech (Just (osId ost)) Nothing dhBlob BS.empty)
                (Just (dhSecretWidth mat))
                CKR_ARGUMENTS_BAD
              _ -> KeyDenied (KeyDeny CKR_MECHANISM_PARAM_INVALID
                "DH mechanism parameters rejected by the recipe")
  | Just r <- kdfRecipeFor mech = case decodeDeriveParams blob of
      Nothing -> KeyDenied (KeyDeny CKR_ARGUMENTS_BAD
        "malformed derive arguments")
      Just (info, tmpls) -> case resolveBase model st mech baseH of
        Left deny -> KeyDenied deny
        Right (ost, _)
          -- SHA-KDF rows derive from generic-secret bases only;
          -- the key-type contradiction outranks parameter shape
          -- (the Init-matrix ordering, shared with the ECDH arm).
          | not (rkPbkd2 r)
          , Map.lookup AttrKeyType (osAttrs ost) /= Just (ValULong ckkGenericSecret) ->
              KeyDenied (KeyDeny CKR_KEY_TYPE_INCONSISTENT
                "SHA-KDF base key is not a generic secret")
          | rkPbkd2 r, not (kdfParamsValid r info) -> KeyDenied (KeyDeny CKR_ARGUMENTS_BAD
              "PBKDF2 mechanism parameters rejected by the recipe")
          | not (rkPbkd2 r), not (BS.null info) -> KeyDenied (KeyDeny CKR_ARGUMENTS_BAD
              "SHA key derivation takes empty info")
          | rkPbkd2 r -> finish (osAttrs ost) Nothing tmpls maxDerivedTotal
              "derived total exceeds the derive ceiling"
              (FxDerive mech (Just (osId ost)) Nothing info BS.empty)
              Nothing
              CKR_ARGUMENTS_BAD
          -- Hash-KDF length rules (PKCS#11 SHA-1\/SHA-2\/SHA-3
          -- key derivation): no type and no length gives a generic
          -- secret of the digest width; a typed target without a
          -- length takes its type's single defined length (DES3
          -- 24) or refuses INCOMPLETE (AES has none); a length past
          -- the digest width is a capacity error.
          | otherwise -> case kdfShaWidth r of
              Just w -> finishMerged (Right . stampDerived (osAttrs ost) Nothing) tmpls w
                "derived total exceeds the digest width"
                (FxDerive mech (Just (osId ost)) Nothing BS.empty BS.empty)
                (SpecLenDefault w False)
                CKR_KEY_SIZE_RANGE
                Nothing
              -- SHAKE XOF rows: no fixed width — the output
              -- length rides the template lengths, capped by
              -- 'maxXofTotal'; a missing length stays
              -- INCOMPLETE (no natural width to default to).
              Nothing -> case kdfXofStem r of
                Just _ -> finish (osAttrs ost) Nothing tmpls maxXofTotal
                  "derived total exceeds the XOF output ceiling"
                  (FxDerive mech (Just (osId ost)) Nothing BS.empty BS.empty)
                  Nothing
                  CKR_KEY_SIZE_RANGE
                Nothing -> KeyDenied (KeyDeny CKR_GENERAL_ERROR
                  "KDF row without a digest width")
  | Just r <- tlsPrfRecipeFor mech = case decodeDeriveParams blob of
      Nothing -> KeyDenied (KeyDeny CKR_ARGUMENTS_BAD
        "malformed derive arguments")
      Just (prfBlob, tmpls) -> case resolveBase model st mech baseH of
        Left deny -> KeyDenied deny
        Right (ost, _)
          -- TLS-PRF derives from generic-secret bases only; the
          -- key-type contradiction outranks parameter shape (the
          -- Init-matrix ordering, shared with the ECDH and SHA-KDF
          -- arms).
          | Map.lookup AttrKeyType (osAttrs ost) /= Just (ValULong ckkGenericSecret) ->
              KeyDenied (KeyDeny CKR_KEY_TYPE_INCONSISTENT
                "TLS-PRF base key is not a generic secret")
          | not (tlsPrfParamsValid r prfBlob) -> KeyDenied (KeyDeny CKR_ARGUMENTS_BAD
              "TLS-PRF mechanism parameters rejected by the recipe")
          | otherwise -> finish (osAttrs ost) Nothing tmpls maxTlsPrfOutput
              "derived total exceeds the TLS-PRF ceiling"
              (FxDerive mech (Just (osId ost)) Nothing prfBlob BS.empty)
              Nothing
              CKR_ARGUMENTS_BAD
  | Just r <- tlsKdfRecipeFor mech = case decodeDeriveParams blob of
      Nothing -> KeyDenied (KeyDeny CKR_ARGUMENTS_BAD
        "malformed derive arguments")
      Just (kdfBlob, tmpls) -> case resolveBase model st mech baseH of
        Left deny -> KeyDenied deny
        Right (ost, _)
          -- TLS-KDF rows derive from generic-secret bases only;
          -- the key-type contradiction outranks parameter shape
          -- (the Init-matrix ordering, shared with the TLS-PRF
          -- arm).
          | Map.lookup AttrKeyType (osAttrs ost) /= Just (ValULong ckkGenericSecret) ->
              KeyDenied (KeyDeny CKR_KEY_TYPE_INCONSISTENT
                "TLS-KDF base key is not a generic secret")
          | not (tlsKdfParamsValid r kdfBlob) -> KeyDenied (KeyDeny CKR_ARGUMENTS_BAD
              "TLS-KDF mechanism parameters rejected by the recipe")
          | otherwise -> finish (osAttrs ost) Nothing tmpls maxTlsKdfOutput
              "derived total exceeds the TLS-KDF ceiling"
              (FxDerive mech (Just (osId ost)) Nothing kdfBlob BS.empty)
              Nothing
              CKR_ARGUMENTS_BAD
  | Just r <- tlsKeyMatRecipeFor mech = case decodeDeriveParams blob of
      Nothing -> KeyDenied (KeyDeny CKR_ARGUMENTS_BAD
        "malformed derive arguments")
      Just (kmBlob, tmpls) -> case resolveBase model st mech baseH of
        Left deny -> KeyDenied deny
        Right (ost, _)
          -- Key-material rows derive from generic-secret bases
          -- only; the key-type contradiction outranks parameter
          -- shape (the Init-matrix ordering, shared with the
          -- TLS-KDF arm).
          | Map.lookup AttrKeyType (osAttrs ost) /= Just (ValULong ckkGenericSecret) ->
              KeyDenied (KeyDeny CKR_KEY_TYPE_INCONSISTENT
                "key-material base key is not a generic secret")
          | not (tlsKeyMatParamsValid r kmBlob) -> KeyDenied (KeyDeny CKR_ARGUMENTS_BAD
              "key-material mechanism parameters rejected by the recipe")
          | otherwise -> case decodeTlsKeyMatParams kmBlob of
              -- Unreachable post-validation; typed, never a crash.
              Nothing -> KeyDenied (KeyDeny CKR_GENERAL_ERROR
                "key-material frame rejected after validation")
              Just (_, mac, key, iv, _, _) -> keyMatFinish r ost tmpls
                mech kmBlob mac key iv
  | Just r <- ssl3RecipeFor mech
  , ssl3Kind r == Ssl3Master || ssl3Kind r == Ssl3MasterDh =
      case decodeDeriveParams blob of
        Nothing -> KeyDenied (KeyDeny CKR_ARGUMENTS_BAD
          "malformed derive arguments")
        Just (mBlob, tmpls) -> case resolveBase model st mech baseH of
          Left deny -> KeyDenied deny
          Right (ost, _)
            -- SSL3 master rows derive from generic-secret
            -- bases only; the key-type contradiction outranks
            -- parameter shape (the Init-matrix ordering,
            -- shared with the TLS-KDF arm).
            | Map.lookup AttrKeyType (osAttrs ost) /= Just (ValULong ckkGenericSecret) ->
                KeyDenied (KeyDeny CKR_KEY_TYPE_INCONSISTENT
                  "SSL3 master base key is not a generic secret")
            | not (ssl3ParamsValid r mBlob) -> KeyDenied (KeyDeny CKR_ARGUMENTS_BAD
                "SSL3 master mechanism parameters rejected by the recipe")
            | otherwise -> finish (osAttrs ost) Nothing tmpls 48
                "derived total exceeds the 48-byte SSL3 master width"
                (FxDerive mech (Just (osId ost)) Nothing mBlob BS.empty)
                Nothing
                CKR_ARGUMENTS_BAD
  | Just r <- ssl3RecipeFor mech
  , ssl3Kind r == Ssl3KeyMat = case decodeDeriveParams blob of
      Nothing -> KeyDenied (KeyDeny CKR_ARGUMENTS_BAD
        "malformed derive arguments")
      Just (kmBlob, tmpls) -> case resolveBase model st mech baseH of
        Left deny -> KeyDenied deny
        Right (ost, _)
          -- The SSL3 keymat row derives from generic-secret
          -- bases only; the key-type contradiction outranks
          -- parameter shape (the Init-matrix ordering,
          -- shared with the TLS-KDF arm).
          | Map.lookup AttrKeyType (osAttrs ost) /= Just (ValULong ckkGenericSecret) ->
              KeyDenied (KeyDeny CKR_KEY_TYPE_INCONSISTENT
                "SSL3 key-material base key is not a generic secret")
          | not (ssl3ParamsValid r kmBlob) -> KeyDenied (KeyDeny CKR_ARGUMENTS_BAD
              "SSL3 key-material mechanism parameters rejected by the recipe")
          | otherwise -> case decodeSsl3KeyMatParams kmBlob of
              -- Unreachable post-validation; typed, never a crash.
              Nothing -> KeyDenied (KeyDeny CKR_GENERAL_ERROR
                "SSL3 key-material frame rejected after validation")
              Just (mac, key, iv, _, _) -> ssl3KeyMatFinish ost tmpls
                mech kmBlob mac key iv
  | Just r <- ikeRecipeFor mech = case decodeDeriveParams blob of
      Nothing -> KeyDenied (KeyDeny CKR_ARGUMENTS_BAD
        "malformed derive arguments")
      Just (ikeBlob, tmpls) -> case resolveBase model st mech baseH of
        Left deny -> KeyDenied deny
        Right (ost, _)
          -- IKE rows derive from generic-secret or HMAC bases;
          -- the key-type contradiction outranks parameter shape
          -- (the Init-matrix ordering, shared with the TLS-KDF
          -- arm).
          | not (ikeBaseOk ost) ->
              KeyDenied (KeyDeny CKR_KEY_TYPE_INCONSISTENT
                "IKE base key is not a generic secret or HMAC key")
          | not (ikeParamsValid r ikeBlob) -> KeyDenied (KeyDeny CKR_ARGUMENTS_BAD
              "IKE mechanism parameters rejected by the recipe")
          | otherwise -> case decodeIkeParams ikeBlob of
              -- Unreachable post-validation; typed, never a crash.
              Nothing -> KeyDenied (KeyDeny CKR_GENERAL_ERROR
                "IKE frame rejected after validation")
              Just (prf, _, _, auxN, extra, _)
                -- IKEv1 extended without aux key or extra data
                -- truncates the base (raw base bytes out, the PRF
                -- never runs): a sealed base refuses with the
                -- EXTRACT code, before the PRF-validity check.
                | ikKind r == Ike1Extended && auxN == 0 && BS.null extra
                  && payloadSealed (effectiveAttrs (osAttrs ost)) ->
                    KeyDenied (KeyDeny CKR_KEY_FUNCTION_NOT_PERMITTED
                      "IKEv1-extended truncation on a sealed base")
                -- The reserved code marks an unmapped PRF
                -- selector: the spec-exact denial (the oracle's
                -- invalid-PRF legs accept it).
                | prf == 0 -> KeyDenied (KeyDeny CKR_MECHANISM_PARAM_INVALID
                    "IKE PRF mechanism is not a served HMAC")
                | otherwise -> case resolveAuxKey ikeBaseOk "IKE" model st mech auxN of
                    Left deny -> KeyDenied deny
                    Right mAux -> case ikeCeiling (ikKind r) prf of
                      -- Unreachable post-validation (codes 1..13
                      -- map); typed, never a crash.
                      Nothing -> KeyDenied (KeyDeny CKR_GENERAL_ERROR
                        "IKE PRF code without a digest width")
                      Just ceilingN -> case auxAttrsOf model mAux of
                        -- Unreachable: the aux resolved above, in
                        -- this same model.
                        Nothing -> KeyDenied (KeyDeny CKR_GENERAL_ERROR
                          "IKE aux lost after resolution")
                        Just mAuxAttrs -> finish (osAttrs ost) mAuxAttrs tmpls ceilingN
                          "derived total exceeds the IKE ceiling"
                          (FxDerive mech (Just (osId ost)) mAux ikeBlob BS.empty)
                          Nothing
                          CKR_KEY_SIZE_RANGE
  | Just r <- byteOpsRecipeFor mech = case decodeDeriveParams blob of
      Nothing -> KeyDenied (KeyDeny CKR_ARGUMENTS_BAD
        "malformed derive arguments")
      Just (boBlob, tmpls) -> case resolveBase model st mech baseH of
        Left deny -> KeyDenied deny
        Right (ost, mat)
          -- Byte-op rows derive from generic-secret bases only;
          -- the key-type contradiction outranks parameter shape
          -- (the Init-matrix ordering, shared with the TLS-KDF
          -- arm).
          | Map.lookup AttrKeyType (osAttrs ost) /= Just (ValULong ckkGenericSecret) ->
              KeyDenied (KeyDeny CKR_KEY_TYPE_INCONSISTENT
                "byte-op base key is not a generic secret")
          | not (byteOpsParamsValid r boBlob) -> KeyDenied (KeyDeny CKR_ARGUMENTS_BAD
              "byte-op mechanism parameters rejected by the recipe")
          | otherwise -> case decodeByteOpsParams boBlob of
              -- Unreachable post-validation; typed, never a crash.
              Nothing -> KeyDenied (KeyDeny CKR_GENERAL_ERROR
                "byte-op frame rejected after validation")
              Just (auxN, offN, payBlob) ->
                case resolveAuxKey byteOpsBaseOkState "byte-op" model st mech auxN of
                  Left deny -> KeyDenied deny
                  Right mAux -> byteOpsFinish r mat mAux offN payBlob
                    mech ost boBlob tmpls
  | Just r <- sp800RecipeFor mech = case decodeDeriveParams blob of
      Nothing -> KeyDenied (KeyDeny CKR_ARGUMENTS_BAD
        "malformed derive arguments")
      Just (spBlob, tmpls) -> case resolveBase model st mech baseH of
        Left deny -> KeyDenied deny
        Right (ost, _)
          -- SP 800-108 derives from generic-secret bases only;
          -- the key-type contradiction outranks parameter shape
          -- (the Init-matrix ordering, shared with the ECDH,
          -- SHA-KDF, and TLS-PRF arms).
          | Map.lookup AttrKeyType (osAttrs ost) /= Just (ValULong ckkGenericSecret) ->
              KeyDenied (KeyDeny CKR_KEY_TYPE_INCONSISTENT
                "SP800-108 base key is not a generic secret")
          | not (sp800ParamsValid r spBlob) -> KeyDenied (KeyDeny CKR_ARGUMENTS_BAD
              "SP800-108 mechanism parameters rejected by the recipe")
          | otherwise -> case decodeSp800Params spBlob of
              -- Unreachable post-validation (the recipe just
              -- accepted); typed, never a crash.
              Nothing -> KeyDenied (KeyDeny CKR_GENERAL_ERROR
                "SP800-108 frame rejected after validation")
              -- The DKM length L is the derived bit-length, so
              -- it must fit its width, and counter mode must
              -- fit its iterations in @2^r - 1@; malformed or
              -- missing lengths fall through to 'finish' (which
              -- reports them).
              Just p -> case sp800HashLen (spPrf p) of
                -- Unreachable post-validation (the frame's PRF
                -- code maps by construction); typed, never a
                -- crash.
                Nothing -> KeyDenied (KeyDeny CKR_GENERAL_ERROR
                  "SP800-108 PRF has no servable hash length")
                Just h
                  | sp800LengthFits (rsMode r) (spLengthBits p)
                      (spCounterBits p) h tmpls -> finish (osAttrs ost) Nothing tmpls maxSp800Total
                      "derived total exceeds the SP800-108 ceiling"
                      (FxDerive mech (Just (osId ost)) Nothing spBlob BS.empty)
                      Nothing
                      CKR_ARGUMENTS_BAD
                  | otherwise -> KeyDenied (KeyDeny CKR_KEY_SIZE_RANGE
                      "derived length does not fit the counter/length widths")
  | Just r <- encryptDataRecipeFor mech = case decodeDeriveParams blob of
      Nothing -> KeyDenied (KeyDeny CKR_ARGUMENTS_BAD
        "malformed derive arguments")
      -- Same ordering as ECDH: the base resolves and must carry
      -- the row's cipher key type before params are examined.
      Just (edBlob, tmpls) -> case resolveBase model st mech baseH of
        Left deny -> KeyDenied deny
        Right (ost, _)
          | Map.lookup AttrKeyType (osAttrs ost)
              /= Just (ValULong (mustKeyTypeId (erKeyType r))) ->
              KeyDenied (KeyDeny CKR_KEY_TYPE_INCONSISTENT
                "encrypt-data base key type mismatch for the mechanism row")
          | not (encryptDataParamsValid r edBlob) -> KeyDenied (KeyDeny CKR_MECHANISM_PARAM_INVALID
              "encrypt-data mechanism parameters rejected by the recipe")
          | otherwise -> case encryptDataOutputLen r edBlob of
              Just w -> finish (osAttrs ost) Nothing tmpls w
                "derived total exceeds the encrypted data width"
                (FxDerive mech (Just (osId ost)) Nothing edBlob BS.empty)
                (Just w)
                CKR_KEY_SIZE_RANGE
              Nothing -> KeyDenied (KeyDeny CKR_GENERAL_ERROR
                "encrypt-data frame without an output width")
  | otherwise =
      KeyDenied (KeyDeny CKR_MECHANISM_INVALID
        ("not a derive mechanism: " ++ show mech))
  where
    finish baseAttrs mAuxAttrs tmpls ceilingN ceilingMsg fx defLen ceilingCode =
      finishMerged (Right . stampDerived baseAttrs mAuxAttrs) tmpls ceilingN ceilingMsg fx
        (maybe NoLenDefault GenericLenDefault defLen) ceilingCode Nothing
    -- | 'finish' with a per-template merge over the validated
    -- attributes: source inheritance plus history for every
    -- family (the byte operations additionally refuse §6.43
    -- downgrades in their merge). The merge runs before ceiling,
    -- admission and effect construction, so the merged flags
    -- retain through finish/publication. The optional seal floor
    -- is the family's natural width on sealed inputs: any
    -- resolved child length below it — explicit or filled from
    -- the template key type — refuses inconsistent, as does a
    -- child key type outside the allow-list.
    finishMerged merge tmpls ceilingN ceilingMsg fx defLen ceilingCode mSealFloor =
      case checkAllMerged defLen merge tmpls of
        Left deny -> KeyDenied deny
        Right keyed
          | null keyed -> KeyDenied (KeyDeny CKR_ARGUMENTS_BAD
              "derive needs at least one template")
          -- A sealed input cannot mint a shorter child: the
          -- resolved length below the natural width refuses
          -- inconsistent, before the ceiling comparison.
          | Just n <- mSealFloor, any ((< n) . snd) keyed ->
              KeyDenied (KeyDeny CKR_TEMPLATE_INCONSISTENT
                "sealed byte-op child length is below the natural width")
          -- A sealed input cannot mint a leak-prone child either:
          -- the resolved key type outside the allow-list refuses
          -- inconsistent even at full width, before the ceiling
          -- comparison (a missing or malformed type refuses
          -- closed; the template check above leaves it present).
          | Just _ <- mSealFloor, any (not . childTypeOk . fst) keyed ->
              KeyDenied (KeyDeny CKR_TEMPLATE_INCONSISTENT
                "sealed byte-op child key type is outside the allow-list")
          -- Ceiling before domain (recorded v0.4 ruling, the AC-16
          -- family-specific exception): a request past the
          -- mechanism's maximum output is a capacity error with the
          -- family code (SHA-256 AES/33: CKR_KEY_SIZE_RANGE); the
          -- type\/length domain (CKR_TEMPLATE_INCONSISTENT) governs
          -- lengths within that capacity.
          | sum (map snd keyed) > ceilingN ->
              KeyDenied (KeyDeny ceilingCode ceilingMsg)
          -- Key domain: every destination's type admits its length
          -- (the shared validator), before admission or any
          -- effect; one invalid template refuses the batch.
          | Left deny <- mapM_ (uncurry checkDerivedTarget) keyed ->
              KeyDenied deny
          | Left deny <- admitObjects rules (Map.size (mObjects model))
              (length keyed) ->
              KeyDenied (KeyDeny (admitCode deny)
                ("admission denied: " ++ show deny))
          | otherwise ->
              let (pos, lens) = unzip
                    [(pendingFromAttrs st attrs, n) | (attrs, n) <- keyed]
              in KeyEffect (PwDerive pos lens) (fx (sum lens))
    -- | Pub-from-priv admission: the caller template wins over
    -- the mapped base defaults; curve params copy from the base
    -- when the caller omits them. The effect carries no
    -- parameters and a zero length (the SPKI length rides the
    -- answer, which the finisher parses per key type).
    finishPub ost kty caller =
      case admitObjects rules (Map.size (mObjects model)) 1 of
        Left deny -> KeyDenied (KeyDeny (admitCode deny)
          ("admission denied: " ++ show deny))
        Right () ->
          let merged = Map.union caller (pubPrivMapAttrs (osAttrs ost))
              withParams = case Map.lookup AttrEcParams (osAttrs ost) of
                Just p | not (Map.member AttrEcParams merged) ->
                  Map.insert AttrEcParams p merged
                _ -> merged
              po = pendingFromAttrs st withParams
          in KeyEffect (PwDerivePub po kty)
            (FxDerive mech (Just (osId ost)) Nothing BS.empty BS.empty 0)
    -- | Byte-op admission after the frame and aux resolve: the
    -- natural output width per kind drives 'finish' (concat
    -- and XOR default a missing template length to the full
    -- width, ECDH-style; EXTRACT has no natural width so a
    -- missing length stays INCOMPLETE). Over-width requests
    -- refuse @CKR_KEY_SIZE_RANGE@ (the SHA-KDF\/encrypt-data
    -- ceiling code), including an XOR length past
    -- min(base, data) (spec 6.43.6); an EXTRACT overrun refuses
    -- @CKR_ARGUMENTS_BAD@. A sealed input (the base, or the
    -- concat-key aux, sealed on the effective view) cannot mint
    -- a shorter child: EXTRACT refuses
    -- @CKR_KEY_FUNCTION_NOT_PERMITTED@, short-data XOR refuses
    -- the same way, and a resolved child length below the
    -- natural width — an explicit @CKA_VALUE_LEN@ or a length
    -- the template key type fills in — refuses
    -- @CKR_TEMPLATE_INCONSISTENT@ on the concatenate and XOR
    -- rows, as does a child key type outside the allow-list at
    -- any width. Full-width allow-listed sealed derives still
    -- plan; unsealed inputs keep every row.
    byteOpsFinish r mat mAux offN payBlob dMech ost boBlob tmpls =
      let baseSealed = payloadSealed (effectiveAttrs (osAttrs ost))
      in case boKind r of
        ConcatBaseAndKey -> case mAux of
          -- Unreachable: validation forces a nonzero aux
          -- handle, which resolves or denies above.
          Nothing -> KeyDenied (KeyDeny CKR_GENERAL_ERROR
            "concat-key aux vanished after resolution")
          Just auxOid -> case Map.lookup auxOid (mObjects model) of
            -- Unreachable: the aux resolved with material
            -- above.
            Nothing -> KeyDenied (KeyDeny CKR_GENERAL_ERROR
              "concat-key aux lost its material")
            Just auxOst -> case keyBytesOf auxOst of
              -- Unreachable: the aux carried material at
              -- resolution.
              Nothing -> KeyDenied (KeyDeny CKR_GENERAL_ERROR
                "concat-key aux lost its material")
              Just auxMat -> natural (Just (osAttrs auxOst))
                (baseSealed || payloadSealed (effectiveAttrs (osAttrs auxOst)))
                (BS.length mat + BS.length auxMat)
        ConcatBaseAndData -> natural Nothing baseSealed
          (BS.length mat + BS.length payBlob)
        ConcatDataAndBase -> natural Nothing baseSealed
          (BS.length payBlob + BS.length mat)
        -- PKCS#11 §6.43.6: the result covers the shorter of the
        -- base and the data (an empty side leaves nothing and
        -- refuses as an empty natural output).
        XorBaseAndData
          | baseSealed && BS.length payBlob < BS.length mat ->
              KeyDenied (KeyDeny CKR_KEY_FUNCTION_NOT_PERMITTED
                "XOR data shorter than a sealed base")
          | otherwise -> natural Nothing baseSealed
              (min (BS.length mat) (BS.length payBlob))
        ExtractKeyFromKey
          | baseSealed ->
              KeyDenied (KeyDeny CKR_KEY_FUNCTION_NOT_PERMITTED
                "EXTRACT_KEY_FROM_KEY on a sealed base")
          | otherwise ->
              let baseBits = toInteger (BS.length mat) * 8
                  remaining = (baseBits - toInteger offN) `div` 8
                  -- The whole-byte window at the offset, capped by
                  -- the byte-ops ceiling; a past-the-end offset
                  -- leaves no window, so every positive request
                  -- overruns.
                  window = max 0 (min (toInteger maxByteOpsOutput) remaining)
              in finishMerged (byteOpsMerge Nothing) tmpls (fromInteger window)
                "EXTRACT window exceeds the base key"
                (FxDerive dMech (Just (osId ost)) mAux boBlob BS.empty)
                NoLenDefault
                CKR_ARGUMENTS_BAD
                Nothing
      where
        fx = FxDerive dMech (Just (osId ost)) mAux boBlob BS.empty
        -- | The §6.43 merge for one validated caller template:
        -- base protection plus the aux key's where the row takes
        -- one (concat-key only; the data/offset rows pass
        -- 'Nothing'), then the source-derived stamp (inherited
        -- protection for the omitted rows, derived history).
        byteOpsMerge mAuxAttrs =
          fmap (stampDerived (osAttrs ost) mAuxAttrs)
            . resolveByteOpsProtection (byteOpsProtectionOf (osAttrs ost) mAuxAttrs)
        natural mAuxAttrs sealed n
          | n < 1 = KeyDenied (KeyDeny CKR_KEY_SIZE_RANGE
              "byte-op natural output is empty")
          | n > maxByteOpsOutput = KeyDenied (KeyDeny CKR_ARGUMENTS_BAD
              "byte-op natural output exceeds the ceiling")
          -- A sealed input cannot mint a shorter child: any
          -- positive template length below the natural width
          -- refuses inconsistent up front (zero and malformed
          -- shapes still fall through to the shared validator
          -- below); the resolved floor in 'finishMerged'
          -- additionally catches lengths the template key type
          -- fills in.
          | sealed && any (shorterThan n) tmpls =
              KeyDenied (KeyDeny CKR_TEMPLATE_INCONSISTENT
                "sealed byte-op template length is below the natural width")
          -- Concat\/XOR length rules (PKCS#11 v3.2 §6.43): no
          -- type and no length gives a generic secret of the
          -- natural width; a typed target without a length takes
          -- its type's single defined length or refuses INCOMPLETE.
          | otherwise = finishMerged (byteOpsMerge mAuxAttrs) tmpls n
              "derived total exceeds the byte-op natural width"
              fx (SpecLenDefault n True)
              CKR_KEY_SIZE_RANGE
              (if sealed then Just n else Nothing)
        shorterThan n tmpl = case lookup AttrValueLen tmpl of
          Just (ValULong want) -> want >= 1 && toInteger want < toInteger n
          _ -> False
    -- | Key-material admission after the frame validates: the
    -- single template applies to every output (v3.2 §6.39.6\/
    -- §6.40.6). Per-output lengths come from params, so a
    -- template @CKA_VALUE_LEN@ refuses @CKR_TEMPLATE_INCONSISTENT@
    -- (like the @CKA_VALUE@ rule); protection attributes present
    -- in the template must match the base key's
    -- (@CKR_TEMPLATE_INCONSISTENT@ on conflict — the oracle's
    -- template-conflict leg). MAC outputs force
    -- @CKK_GENERIC_SECRET@; cipher keys keep the template type.
    -- KEY_SAFE suppresses IVs (v3.2 §6.40.7: the size is
    -- treated as 0).
    keyMatFinish r ost tmpls dMech kmBlob mac key iv = case tmpls of
      [tmpl] -> case checkKeyTemplateAny ckoSecretKey ckkGenericSecret tmpl of
        Left deny -> KeyDenied deny
        Right attrs
          | Map.member AttrValue attrs -> KeyDenied (KeyDeny CKR_TEMPLATE_INCONSISTENT
              "derived template must not supply CKA_VALUE")
          | Map.member AttrValueLen attrs -> KeyDenied (KeyDeny CKR_TEMPLATE_INCONSISTENT
              "key-material lengths come from params, not CKA_VALUE_LEN")
          -- Key domain: each key output (template type, params
          -- length; MAC outputs generic) fits its domain.
          | Left deny <- mapM_ (\(outAttrs, n) -> checkDerivedTarget outAttrs n)
              (outsFor attrs) -> KeyDenied deny
          | Just msg <- protectionMismatch (osAttrs ost) attrs ->
              KeyDenied (KeyDeny CKR_TEMPLATE_INCONSISTENT msg)
          | Left deny <- admitObjects rules (Map.size (mObjects model))
              (length (outsFor attrs)) ->
              KeyDenied (KeyDeny (admitCode deny)
                ("admission denied: " ++ show deny))
          | otherwise ->
              let (pos, lens) = unzip
                    [(pendingFromAttrs st outAttrs, n) | (outAttrs, n) <- outsFor attrs]
              in KeyEffect (PwDeriveIv pos lens (ivEff, ivEff))
                (FxDerive dMech (Just (osId ost)) Nothing kmBlob BS.empty total)
      _ -> KeyDenied (KeyDeny CKR_ARGUMENTS_BAD
        "key-material derive needs exactly one template")
      where
        ivEff = case tkmKind r of KeyMatTls12Safe -> 0; _ -> iv
        total = 2 * mac + 2 * key + 2 * ivEff
        outsFor attrs =
          [ ( stampDerived (osAttrs ost) Nothing
                (Map.insert AttrValueLen (ValULong (fromIntegral n))
                  (Map.insert AttrKeyType (ValULong (outType role)) attrs))
            , n
            )
          | (role, n) <- tlsKeyMatLayout mac key ivEff
          , isKeyRole role
          ]
          where
            outType role
              | role == KeyMatMacClient || role == KeyMatMacServer = ckkGenericSecret
              | otherwise = case Map.lookup AttrKeyType attrs of
                  Just (ValULong k) -> k
                  -- Unreachable: the template check defaults the
                  -- key type.
                  _ -> ckkGenericSecret
        isKeyRole KeyMatIvClient = False
        isKeyRole KeyMatIvServer = False
        isKeyRole _ = True
    -- | SSL3 key-material admission after the frame validates:
    -- the single template applies to every output (v3.2
    -- §6.36.3). Per-output lengths come from params, so a
    -- template @CKA_VALUE_LEN@ refuses @CKR_TEMPLATE_INCONSISTENT@
    -- (like the @CKA_VALUE@ rule); protection attributes present
    -- in the template must match the base key's
    -- (@CKR_TEMPLATE_INCONSISTENT@ on conflict — the oracle's
    -- template-conflict leg). MAC outputs force
    -- @CKK_GENERIC_SECRET@; cipher keys keep the template type.
    ssl3KeyMatFinish ost tmpls dMech kmBlob mac key iv = case tmpls of
      [tmpl] -> case checkKeyTemplateAny ckoSecretKey ckkGenericSecret tmpl of
        Left deny -> KeyDenied deny
        Right attrs
          | Map.member AttrValue attrs -> KeyDenied (KeyDeny CKR_TEMPLATE_INCONSISTENT
              "derived template must not supply CKA_VALUE")
          | Map.member AttrValueLen attrs -> KeyDenied (KeyDeny CKR_TEMPLATE_INCONSISTENT
              "SSL3 key-material lengths come from params, not CKA_VALUE_LEN")
          -- Key domain: each key output (template type, params
          -- length; MAC outputs generic) fits its domain.
          | Left deny <- mapM_ (\(outAttrs, n) -> checkDerivedTarget outAttrs n)
              (outsFor attrs) -> KeyDenied deny
          | Just msg <- protectionMismatch (osAttrs ost) attrs ->
              KeyDenied (KeyDeny CKR_TEMPLATE_INCONSISTENT msg)
          | Left deny <- admitObjects rules (Map.size (mObjects model))
              (length (outsFor attrs)) ->
              KeyDenied (KeyDeny (admitCode deny)
                ("admission denied: " ++ show deny))
          | otherwise ->
              let (pos, lens) = unzip
                    [(pendingFromAttrs st outAttrs, n) | (outAttrs, n) <- outsFor attrs]
              in KeyEffect (PwDeriveIv pos lens (iv, iv))
                (FxDerive dMech (Just (osId ost)) Nothing kmBlob BS.empty total)
      _ -> KeyDenied (KeyDeny CKR_ARGUMENTS_BAD
        "SSL3 key-material derive needs exactly one template")
      where
        total = 2 * mac + 2 * key + 2 * iv
        outsFor attrs =
          [ ( stampDerived (osAttrs ost) Nothing
                (Map.insert AttrValueLen (ValULong (fromIntegral n))
                  (Map.insert AttrKeyType (ValULong (outType role)) attrs))
            , n
            )
          | (role, n) <- ssl3KeyMatLayout mac key iv
          , isKeyRole role
          ]
          where
            outType role
              | role == Ssl3MacClient || role == Ssl3MacServer = ckkGenericSecret
              | otherwise = case Map.lookup AttrKeyType attrs of
                  Just (ValULong k) -> k
                  -- Unreachable: the template check defaults the
                  -- key type.
                  _ -> ckkGenericSecret
        isKeyRole Ssl3IvClient = False
        isKeyRole Ssl3IvServer = False
        isKeyRole _ = True
    protectionMismatch baseAttrs attrs =
      mismatch AttrSensitive "CKA_SENSITIVE" baseAttrs attrs
        `orElse` mismatch AttrExtractable "CKA_EXTRACTABLE" baseAttrs attrs
      where
        orElse (Just m) _ = Just m
        orElse Nothing x = x
        mismatch at label b a = case Map.lookup at a of
          Just (ValBool t)
            | t /= baseBool at b -> Just
                ("template " ++ label ++ " differs from the base key")
          _ -> Nothing
        baseBool AttrSensitive b = effectiveSensitive b
        baseBool AttrExtractable b = effectiveExtractable b
        baseBool _ _ = False
    checkAllMerged
      :: LenDefault
      -> (Map.Map AttributeType AttributeValue
          -> Either KeyDeny (Map.Map AttributeType AttributeValue))
      -> [[(AttributeType, AttributeValue)]]
      -> Either KeyDeny [(Map.Map AttributeType AttributeValue, Int)]
    checkAllMerged defLen merge = mapM $ \tmpl -> do
      (attrs, n) <- checkOne defLen tmpl
      (, n) <$> merge attrs
    -- | Stamp a defaulted length so readback matches an explicit
    -- template.
    stampLen attrs n =
      Right (Map.insert AttrValueLen (ValULong (fromIntegral n)) attrs, n)
    -- | A derive template targets a generic secret when the key
    -- type is absent (the mechanism default) or explicitly generic.
    targetGeneric :: [(AttributeType, AttributeValue)] -> Bool
    targetGeneric t = case lookup AttrKeyType t of
      Nothing -> True
      Just (ValULong k) -> k == ckkGenericSecret
      Just _ -> False
    -- | A resolved child key type on a sealed byte-op input: inside
    -- the allow-list only (fail closed on a missing or malformed
    -- entry; the template check leaves the type present).
    childTypeOk :: Map.Map AttributeType AttributeValue -> Bool
    childTypeOk attrs = case Map.lookup AttrKeyType attrs of
      Just (ValULong k) -> sealedByteOpChildOk k
      _ -> False
    -- | One secret-key destination: shape ('checkKeyTemplateAny'),
    -- then the destination type (asymmetric, vendor and
    -- unserved types refuse before any length rule), then the
    -- length (explicit or the family default). The type\/length
    -- domain itself ('checkDerivedTarget') runs in 'finishMerged'
    -- after the family ceiling, so over-ceiling requests keep
    -- their family code.
    checkOne
      :: LenDefault -> [(AttributeType, AttributeValue)]
      -> Either KeyDeny (Map.Map AttributeType AttributeValue, Int)
    checkOne defLen tmpl = case checkKeyTemplateAny ckoSecretKey ckkGenericSecret tmpl of
      Left deny -> Left deny
      Right attrs
        | Map.member AttrValue attrs -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
            "derived template must not supply CKA_VALUE")
        | Left deny <- derivedObjectDomain attrs -> Left deny
        | otherwise -> case Map.lookup AttrValueLen attrs of
        Just (ValULong n)
          | n < 1 -> Left (KeyDeny CKR_KEY_SIZE_RANGE
              "derived length must be positive")
          | n > fromIntegral (maxBound :: Int) -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
              "derived length exceeds the platform range")
          | otherwise -> Right (attrs, fromIntegral n)
        Just _ -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
          "derived length is malformed")
        -- Constructions with a natural output width (ECDH: the
        -- agreement secret; HKDF: the hash length, mechanism doc:
        -- VALUE_LEN "should be set") default a missing length to
        -- that width for generic-secret targets only (absent or
        -- generic key type); an explicit typed target without a
        -- length stays INCOMPLETE. The hash-KDF and concat\/XOR
        -- rows follow their PKCS#11 rule ('SpecLenDefault'): a
        -- typed target takes its type's single defined length
        -- (DES 8, DES2 16, DES3 24) and a type without one (AES,
        -- HMAC) stays INCOMPLETE. Open-ended PBKDF2, EXTRACT and
        -- the other families keep INCOMPLETE. Every default is
        -- stamped so readback matches an explicit template.
        Nothing -> case defLen of
          NoLenDefault -> Left (KeyDeny CKR_TEMPLATE_INCOMPLETE
            "derived template needs CKA_VALUE_LEN")
          GenericLenDefault n
            | targetGeneric tmpl -> stampLen attrs n
            | otherwise -> Left (KeyDeny CKR_TEMPLATE_INCOMPLETE
                "variable-length target needs CKA_VALUE_LEN")
          SpecLenDefault n genericToo
            | typeAbsent || (genericToo && targetGeneric tmpl) -> stampLen attrs n
            | Right (DomainLengths [d]) <- derivedObjectDomain attrs -> stampLen attrs d
            | otherwise -> Left (KeyDeny CKR_TEMPLATE_INCOMPLETE
                "target type has no single defined length; needs CKA_VALUE_LEN")
            where
              typeAbsent = lookup AttrKeyType tmpl == Nothing
    -- | 'finish' for data-output derivations: every template must
    -- describe a data object with a positive length (no
    -- length default — data objects have no natural width).
    finishData tmpls ceilingN ceilingMsg fx ceilingCode =
      case mapM checkDataOne tmpls of
        Left deny -> KeyDenied deny
        Right keyed
          | null keyed -> KeyDenied (KeyDeny CKR_ARGUMENTS_BAD
              "derive needs at least one template")
          | sum (map snd keyed) > ceilingN ->
              KeyDenied (KeyDeny ceilingCode ceilingMsg)
          | Left deny <- admitObjects rules (Map.size (mObjects model))
              (length keyed) ->
              KeyDenied (KeyDeny (admitCode deny)
                ("admission denied: " ++ show deny))
          | otherwise ->
              let (pos, lens) = unzip
                    [(pendingFromAttrs st attrs, n) | (attrs, n) <- keyed]
              in KeyEffect (PwDerive pos lens) (fx (sum lens))
    checkDataOne
      :: [(AttributeType, AttributeValue)]
      -> Either KeyDeny (Map.Map AttributeType AttributeValue, Int)
    checkDataOne tmpl = case checkDataTemplate ckoData tmpl of
      Left deny -> Left deny
      Right attrs
        | Map.member AttrValue attrs -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
            "derived template must not supply CKA_VALUE")
        | otherwise -> case Map.lookup AttrValueLen attrs of
        Just (ValULong n)
          | n < 1 -> Left (KeyDeny CKR_KEY_SIZE_RANGE
              "derived length must be positive")
          | n > fromIntegral (maxBound :: Int) -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
              "derived length exceeds the platform range")
          | otherwise -> Right (attrs, fromIntegral n)
        Just _ -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
          "derived length is malformed")
        Nothing -> Left (KeyDeny CKR_TEMPLATE_INCOMPLETE
          "derived data template needs CKA_VALUE_LEN")
