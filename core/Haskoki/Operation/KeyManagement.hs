{- | Key-management planning: generation, wrap\/unwrap, derivation
and KEM finishers over one shared pending-object publication (pure).

Every planner here returns a 'KeyPlan': a denial, an immediate
'PlanResult' (length queries and short buffers, which create no
objects), or exactly one 'CryptoEffect' plus the 'PendingWork' its
answer completes. 'finishWork' runs the driver's answer against the
pending work and publishes through 'publishPending' — the ONE
atomic-publish mechanism every key, pair, unwrap, derive and
encapsulation funnels through. All templates validate before any id
or handle is allocated, and 'Haskoki.Transition.publishDelta' applies
the resulting delta atomically, so a failed call leaves zero objects.

Key material arrives in driver answers and is stored on the new
objects' 'AttrValue' ('storeMaterial'); 'keyBytesOf' reads it back
for the driver resolver. The seal ('payloadSealed') governs the
attribute READ path only: sealed keys stay usable for crypto, per
PKCS#11.

Creation stamps explicit values: a missing class is incomplete,
a missing key type defaults to the mechanism's key, usage flags
default to true on the strict key-template path (except
CKA_DERIVE, which defaults to false per the PKCS#11 common key
attributes table), and the
protection pair stamps per class (non-sensitive and unextractable
on private and secret keys, non-sensitive and extractable on
public keys; unwrapped keys stamp extractable). Generated keys
additionally take birth history (always-sensitive at the birth
sensitive mark, never-extractable at the negated birth
extractable mark, local true, the generating mechanism);
unwrapped keys take false history and origin. The planners
enforce the effective (reported) values strictly.

Class, key-type and mechanism ids resolve through the
generated tables ('Haskoki.Attribute.Generated',
'Haskoki.Registry.Generated') by name; no numeric ids are hand-typed
here. Strict template paths additionally enforce the generated
template rules ('Haskoki.Object.checkRules').
-}
{-# LANGUAGE OverloadedStrings #-}
module Haskoki.Operation.KeyManagement
  ( -- * Plan currency
    KeyDeny (..)
  , KeyPlan (..)
  , PendingObject (..)
  , PendingWork (..)
  , publishPending
  , finishWork
  , storeDerivedMaterial
  , derivedNeedsParity
  , workFunction
  , stampPairComponents
  , stampParamsObject
  , keyPairCompatible
    -- * Object reading
  , keyBytesOf
  , policyFromObject
  , keyTypeCompatible
  , keyClassCompatible
  , mechAllowed
    -- * Class and key-type codes (spec\/vendor\/pkcs11.h)
  , ckoData
  , ckoSecretKey
  , ckoPublicKey
  , ckoPrivateKey
  , ckoDomainParameters
  , ckkRsa
  , ckkEc
  , ckkDsa
  , ckkDh
  , ckkX9_42Dh
  , ckkEcEdwards
  , ckkEcMontgomery
  , ckkGenericSecret
  , ckkAes
  , ckkAesXts
  , ckkDes3
  , ckkHotp
  , ckkBlake2b512Hmac
  , ckkChacha20
  , ckkMlKem
  , ckkMlDsa
  , ckkSlhDsa
  , ckkDes
  , ckkDes2
  , ckkCdmf
  , ckkCast
  , ckkCast3
  , ckkCast128
  , ckkRc2
  , ckkRc4
  , ckkRc5
  , ckkIdea
  , ckkSkipjack
  , ckkBaton
  , ckkJuniper
  , ckkBlowfish
  , ckkTwofish
  , ckkGost28147
  , ckkSeed
  , ckkAria
  , ckkCamellia
  , ckkSalsa20
  , ckkPoly1305
  , ckkHkdf
  , ckkSha1Hmac
  , ckkSha224Hmac
  , ckkSha256Hmac
  , ckkSha384Hmac
  , ckkSha512Hmac
  , ckkSha512_224Hmac
  , ckkSha512_256Hmac
  , ckkSha512THmac
  , ckkSha3_224Hmac
  , ckkSha3_256Hmac
  , ckkSha3_384Hmac
  , ckkSha3_512Hmac
  , ckkBlake2b160Hmac
  , ckkBlake2b256Hmac
  , ckkBlake2b384Hmac
    -- * Mechanism ids (spec\/vendor\/pkcs11.h)
  , aesKeyGenMech
  , des3KeyGenMech
  , hotpKeyGenMech
  , blake2b512KeyGenMech
  , chacha20KeyGenMech
  , genericSecretKeyGenMech
  , desKeyGenMech
  , des2KeyGenMech
  , cdmfKeyGenMech
  , castKeyGenMech
  , cast3KeyGenMech
  , cast128KeyGenMech
  , rc2KeyGenMech
  , rc4KeyGenMech
  , rc5KeyGenMech
  , ideaKeyGenMech
  , skipjackKeyGenMech
  , batonKeyGenMech
  , juniperKeyGenMech
  , blowfishKeyGenMech
  , twofishKeyGenMech
  , gost28147KeyGenMech
  , seedKeyGenMech
  , ariaKeyGenMech
  , camelliaKeyGenMech
  , salsa20KeyGenMech
  , poly1305KeyGenMech
  , aesXtsKeyGenMech
  , hkdfKeyGenMech
  , sha1KeyGenMech
  , sha224KeyGenMech
  , sha256KeyGenMech
  , sha384KeyGenMech
  , sha512KeyGenMech
  , sha512_224KeyGenMech
  , sha512_256KeyGenMech
  , sha512TKeyGenMech
  , sha3_224KeyGenMech
  , sha3_256KeyGenMech
  , sha3_384KeyGenMech
  , sha3_512KeyGenMech
  , blake2b160KeyGenMech
  , blake2b256KeyGenMech
  , blake2b384KeyGenMech
  , ssl3PremasterKeyGenMech
  , tlsPremasterKeyGenMech
  , wtlsPremasterKeyGenMech
  , pbkd2KeyGenMech
  , pbeDes3KeyGenMech
  , pbeDes2KeyGenMech
  , pbeSha1Cast128KeyGenMech
  , pbeSha1Rc4_128KeyGenMech
  , pbeSha1Rc4_40KeyGenMech
  , pbeSha1Rc2_128KeyGenMech
  , pbeSha1Rc2_40KeyGenMech
  , pbeMd5DesKeyGenMech
  , pbeMd5CastKeyGenMech
  , pbeMd5Cast3KeyGenMech
  , pbeMd5Cast128KeyGenMech
  , pbkd2KeygenMaxBytes
  , genericSecretKeygenMinBytes
  , genericSecretKeygenMaxBytes
  , ecKeyPairGenMech
  , ecExtraBitsKeyPairGenMech
  , rsaKeyPairGenMech
  , dsaKeyPairGenMech
  , dsaParameterGenMech
  , dhKeyPairGenMech
  , dhPkcsParameterGenMech
  , x9_42DhKeyPairGenMech
  , x9_42DhParameterGenMech
  , edwardsKeyPairGenMech
  , montgomeryKeyPairGenMech
  , mldsaKeyPairGenMech
  , slhdsaKeyPairGenMech
  , aesCbcMech
  , aesKwMech
  , aesKwPadMech
  , aesKwpMech
  , aesKwp7Mech
  , ecdhAesKwMech
  , ecdhCofAesKwMech
  , ecdhXAesKwMech
  , rsaAesKwMech
  , rsaPkcsMech
  , rsaOaepMech
  , rsaX509Mech
    -- * Shared template checks
  , checkKeyTemplate
  , checkKeyTemplateAny
  , checkDataTemplate
  , DerivedDomain (..)
  , derivedObjectDomain
  , checkDerivedTarget
  , sealedByteOpChildOk
  , pendingFromAttrs
  , ByteOpsProtection (..)
  , byteOpsProtectionOf
  , resolveByteOpsProtection
    -- * Generation frames (planner \<-\> driver contract)
  , GenArgs (..)
  , encodeGenArgs
  , decodeGenArgs
  , encodeKeyPair
  , decodeKeyPair
  , encodeWrapParams
  , decodeWrapParams
    -- * Wrap padding (mirrors Haskoki.Operation.Cipher)
  , padPkcs7
  , unpadPkcs7
    -- * Planners
  , planGenerateKeyPair
  , planGenerateKey
  , planWrapKey
  , planUnwrapKey
  , planAuthWrapKey
  , planAuthUnwrapKey
    -- * Writability admission
  , admitPending
  ) where

import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import qualified Data.Map.Strict as Map
import Data.Word (Word64)

import Haskoki.Attribute
  ( AttributeType (..)
  , AttributeValue (..)
  , encodeValue
  )
import Haskoki.Der (RsaCrt (..), parseRsaPrivate, parseRsaPublic)
import Haskoki.Model (Model (..), ObjectState (..), SessionState (..))
import Haskoki.Object
  ( effectiveAttrs
  , objectVisible
  , resolveHandle
  )
import Haskoki.Operation.Effect (CryptoEffect (..))
import Haskoki.Operation.KeyManagement.Codes
import Haskoki.Operation.KeyManagement.MechIds
import Haskoki.Operation.KeyManagement.Codec
import Haskoki.Operation.KeyManagement.Currency
import Haskoki.Operation.KeyManagement.Keygen
import Haskoki.Operation.KeyManagement.Template
import Haskoki.Operation.KeyManagement.Types
import Haskoki.Outcome
  ( NativeOutput (..)
  , PlanResult (..)
  , PreparedCommit (..)
  , Rejection (..)
  , StateDelta (..)
  )
import Haskoki.Recipe.Ecdh (ecdhSecretWidth)
import Haskoki.Recipe.RsaOaep
  ( decodeOaepParams
  , oaepDigestWidth
  , rsaOaepParamsValid
  , rsaOaepRecipeFor
  )
import Haskoki.Recipe.RsaPkcs1 (rsaPkcs1ParamsValid, rsaPkcs1RecipeFor)
import Haskoki.Recipe.RsaX509 (rsaX509ParamsValid, rsaX509RecipeFor)
import Haskoki.Recipe.WrapCompRsa
  ( wrapCompRsaAesBytes
  , wrapCompRsaKekFits
  , wrapCompRsaOaep
  , wrapCompRsaParamsValid
  , wrapCompRsaRecipeFor
  , wrapCompRsaSplitBlob
  )
import Haskoki.Recipe.WrapComp
  ( WrapCompDomain
  , WrapCompEcdhRecipe
  , wrapCompAesBytes
  , wrapCompDomain
  , wrapCompEcdhKdfServed
  , wrapCompEcdhKeyOk
  , wrapCompEcdhParamsWellFormed
  , wrapCompEcdhRecipeFor
  , wrapCompSplitBlob
  , wrapCompTransportLen
  )
import Haskoki.Registry (MechanismId (..))
import Haskoki.Request (OutputIntent (..), OutputRegion (..))
import Haskoki.Rules (Rules)
import Haskoki.Session (admitCode, admitObjects)
import Haskoki.Types
  ( ExternalHandle (..)
  , ObjectId (..)
  , ReturnCode (..)
  )

-- ---------------------------------------------------------------------------
-- Plan currency
-- ---------------------------------------------------------------------------

-- ---------------------------------------------------------------------------
-- Shared template checks
-- ---------------------------------------------------------------------------

-- ---------------------------------------------------------------------------
-- Generation frames (planner <-> driver contract)
-- ---------------------------------------------------------------------------

-- ---------------------------------------------------------------------------
-- Wrap padding
-- ---------------------------------------------------------------------------

-- ---------------------------------------------------------------------------
-- Key-pair generation
-- ---------------------------------------------------------------------------

-- ---------------------------------------------------------------------------
-- Table-driven single-key generation (slice 11a sweep)
-- ---------------------------------------------------------------------------



-- ---------------------------------------------------------------------------
-- Single-key generation
-- ---------------------------------------------------------------------------

-- ---------------------------------------------------------------------------
-- Wrap and unwrap
-- ---------------------------------------------------------------------------

-- | Resolve a wrapping key: the handle resolves to a visible object
-- carrying the required usage mark, listing the wrap mechanism in
-- its allowed mechanisms, and stored material. Every
-- caller is an AES-CBC wrap/unwrap path, so the key must be an AES
-- secret key; anything else (EC/RSA halves, generic secrets) is a
-- key-type refusal, never a silent coercion of foreign material.
-- Check order is usage, allowed list, then class\/type — unlike
-- operation init (type, class, allowed list, usage) — so an
-- unlisted mechanism on a wrong-type key reports
-- @CKR_KEY_FUNCTION_NOT_PERMITTED@ here. The RSA and EC-composition
-- helpers share this order.
withWrappingKey
  :: Model -> SessionState -> AttributeType -> String -> MechanismId -> ExternalHandle
  -> Either KeyDeny (ObjectId, ByteString)
withWrappingKey model st usage label dMech h = case resolveHandle model h of
  Nothing -> Left (KeyDeny CKR_OBJECT_HANDLE_INVALID
    "unknown or destroyed wrapping-key handle")
  Just ost
    | not (objectVisible st ost) -> Left (KeyDeny CKR_OBJECT_HANDLE_INVALID
        "wrapping key not visible in this session")
    | Map.lookup usage (osAttrs ost) /= Just (ValBool True) ->
        Left (KeyDeny CKR_KEY_FUNCTION_NOT_PERMITTED
          ("wrapping key does not permit " ++ label))
    | not (mechAllowed dMech ost) -> Left (KeyDeny CKR_KEY_FUNCTION_NOT_PERMITTED
        "mechanism is not in the key's allowed list")
    | Map.lookup AttrClass (osAttrs ost) /= Just (ValULong ckoSecretKey) ||
      Map.lookup AttrKeyType (osAttrs ost) /= Just (ValULong ckkAes) ->
        Left (KeyDeny (if usage == AttrWrap
                        then CKR_WRAPPING_KEY_TYPE_INCONSISTENT
                        else CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT)
          ("wrapping key is not an AES secret key: " ++ label))
    | otherwise -> case keyBytesOf ost of
        Just mat -> Right (osId ost, mat)
        Nothing -> Left (KeyDeny CKR_GENERAL_ERROR
          "wrapping key lacks material")

-- | Modulus byte width of an RSA wrapping key: the stored DER
-- parses first (authoritative — the same parser that stamps
-- keygen components), the stamped @CKA_MODULUS@ second. The DER
-- integers parse minimal, and a real modulus always sets its top
-- bit, so the parsed length is the modulus width.
rsaModulusBytes :: ObjectState -> Maybe Int
rsaModulusBytes ost =
  case keyBytesOf ost of
    Just der -> case parseRsaPublic der of
      Just (n, _) -> Just (BS.length n)
      Nothing -> case parseRsaPrivate der of
        Just crt -> Just (BS.length (crtN crt))
        Nothing -> fromAttr
    Nothing -> fromAttr
  where
    fromAttr = case Map.lookup AttrModulus (osAttrs ost) of
      Just (ValBytes n) ->
        let stripped = BS.dropWhile (== 0) n
        in if BS.null stripped then Nothing else Just (BS.length stripped)
      _ -> Nothing

-- | Resolve an RSA wrapping key: the handle resolves to a visible
-- RSA object of the required half (public for wrapping, private
-- for unwrapping) carrying the required usage mark, listing the
-- wrap mechanism in its allowed mechanisms, and modulus
-- material. Answers the object id and the modulus byte width the
-- length checks and the blob length derive from. Anything else is
-- a key-type refusal, never a silent coercion.
withRsaWrappingKey
  :: Model -> SessionState -> AttributeType -> String -> MechanismId -> Word64 -> ExternalHandle
  -> Either KeyDeny (ObjectId, Int)
withRsaWrappingKey model st usage label dMech wantClass h =
  case resolveHandle model h of
    Nothing -> Left (KeyDeny CKR_OBJECT_HANDLE_INVALID
      "unknown or destroyed wrapping-key handle")
    Just ost
      | not (objectVisible st ost) -> Left (KeyDeny CKR_OBJECT_HANDLE_INVALID
          "wrapping key not visible in this session")
      | Map.lookup usage (osAttrs ost) /= Just (ValBool True) ->
          Left (KeyDeny CKR_KEY_FUNCTION_NOT_PERMITTED
            ("wrapping key does not permit " ++ label))
      | not (mechAllowed dMech ost) -> Left (KeyDeny CKR_KEY_FUNCTION_NOT_PERMITTED
          "mechanism is not in the key's allowed list")
      | Map.lookup AttrClass (osAttrs ost) /= Just (ValULong wantClass) ||
        Map.lookup AttrKeyType (osAttrs ost) /= Just (ValULong ckkRsa) ->
          Left (KeyDeny (if usage == AttrWrap
                          then CKR_WRAPPING_KEY_TYPE_INCONSISTENT
                          else CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT)
            ("wrapping key is not an RSA key half: " ++ label))
      | otherwise -> case rsaModulusBytes ost of
          Just k -> Right (osId ost, k)
          Nothing -> Left (KeyDeny CKR_GENERAL_ERROR
            "wrapping key lacks modulus material")

-- | Resolve an ECDH-composition wrapping key: the handle resolves
-- to a visible key carrying the usage mark, listing the wrap
-- mechanism in its allowed mechanisms, whose class matches
-- the direction (wrap takes the recipient PUBLIC key — the
-- agreement runs against an ephemeral transport pair; unwrap
-- takes the PRIVATE key) and whose key type the composition row
-- admits (plain: EC or Montgomery; cofactor: EC; X:
-- Montgomery). Answers the object id, the key material, and its
-- transport domain.
withEcCompWrappingKey
  :: Model -> SessionState -> AttributeType -> String -> MechanismId -> WrapCompEcdhRecipe
  -> ExternalHandle -> Either KeyDeny (ObjectId, ByteString, WrapCompDomain)
withEcCompWrappingKey model st usage label dMech r h =
  case resolveHandle model h of
    Nothing -> Left (KeyDeny CKR_OBJECT_HANDLE_INVALID
      "unknown or destroyed wrapping-key handle")
    Just ost
      | not (objectVisible st ost) -> Left (KeyDeny CKR_OBJECT_HANDLE_INVALID
          "wrapping key not visible in this session")
      | Map.lookup usage (osAttrs ost) /= Just (ValBool True) ->
          Left (KeyDeny CKR_KEY_FUNCTION_NOT_PERMITTED
            ("wrapping key does not permit " ++ label))
      | not (mechAllowed dMech ost) -> Left (KeyDeny CKR_KEY_FUNCTION_NOT_PERMITTED
          "mechanism is not in the key's allowed list")
      | Map.lookup AttrClass (osAttrs ost) /= Just (ValULong wantClass) ->
          Left (KeyDeny typeCode
            ("wrapping key has the wrong class for " ++ label))
      | otherwise -> case Map.lookup AttrKeyType (osAttrs ost) of
          Just (ValULong kty)
            | wrapCompEcdhKeyOk r kty -> case keyBytesOf ost of
                Just mat -> Right (osId ost, mat, wrapCompDomain mat)
                Nothing -> Left (KeyDeny CKR_GENERAL_ERROR
                  "wrapping key lacks material")
          _ -> Left (KeyDeny typeCode
            ("wrapping key type rejected by the composition row: " ++ label))
  where
    (wantClass, typeCode)
      | usage == AttrWrap = (ckoPublicKey, CKR_WRAPPING_KEY_TYPE_INCONSISTENT)
      | otherwise = (ckoPrivateKey, CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT)

-- | Resolve a wrap target: the handle resolves to a visible
-- extractable object carrying stored material.
withWrapTarget
  :: Model -> SessionState -> ExternalHandle
  -> Either KeyDeny ByteString
withWrapTarget model st h = case resolveHandle model h of
  Nothing -> Left (KeyDeny CKR_OBJECT_HANDLE_INVALID
    "unknown or destroyed target handle")
  Just ost
    | not (objectVisible st ost) -> Left (KeyDeny CKR_OBJECT_HANDLE_INVALID
        "target not visible in this session")
    | Map.lookup AttrExtractable (effectiveAttrs (osAttrs ost))
        /= Just (ValBool True) ->
        Left (KeyDeny CKR_KEY_UNEXTRACTABLE "target is not extractable")
    | otherwise -> case keyBytesOf ost of
        Just mat -> Right mat
        Nothing -> Left (KeyDeny CKR_KEY_NOT_WRAPPABLE
          "target carries no key material")

-- | Plan one wrap: AES-CBC pads through 'planAesWrapKey', the
-- AES key-wrap rows expand through 'planAesKwWrapKey', KW-PKCS7
-- pads plus wraps through 'planAesKwPkcs7WrapKey', the ECDH
-- compositions frame through 'planEcdhCompWrapKey', the RSA
-- mechanisms travel raw through 'planRsaWrapKey'.
planWrapKey
  :: Model -> SessionState -> MechanismId -> ByteString
  -> ExternalHandle -> ExternalHandle -> OutputIntent
  -> KeyPlan
planWrapKey model st mech params wrapH targetH intent
  | mech == aesCbcMech = planAesWrapKey model st mech params wrapH targetH intent
  | mech == aesKwMech || mech == aesKwPadMech || mech == aesKwpMech =
      planAesKwWrapKey model st mech params wrapH targetH intent
  | mech == aesKwp7Mech =
      planAesKwPkcs7WrapKey model st mech params wrapH targetH intent
  | mech == ecdhAesKwMech || mech == ecdhCofAesKwMech || mech == ecdhXAesKwMech =
      planEcdhCompWrapKey model st mech params wrapH targetH intent
  | mech == rsaAesKwMech =
      planRsaCompWrapKey model st mech params wrapH targetH intent
  | mech == rsaPkcsMech || mech == rsaOaepMech || mech == rsaX509Mech =
      planRsaWrapKey model st mech params wrapH targetH intent
  | otherwise =
      KeyDenied (KeyDeny CKR_MECHANISM_INVALID
        ("not a wrap mechanism: " ++ show mech))

-- | Padding overhead per RSA wrap mechanism: v1.5 takes empty
-- parameters and 11 bytes; OAEP takes the labeled
-- @oaep-params\/1@ parameters and 2*hLen+2 over the main hash
-- width; X.509 takes empty parameters and zero overhead (raw
-- block). Rejected shapes are argument errors (parse-first).
rsaWrapOverhead :: MechanismId -> ByteString -> Either KeyDeny Int
rsaWrapOverhead mech params
  | mech == rsaPkcsMech = case rsaPkcs1RecipeFor mech of
      Just r | rsaPkcs1ParamsValid r params -> Right 11
      _ -> Left (KeyDeny CKR_ARGUMENTS_BAD
        "RSA v1.5 wrap takes empty mechanism parameters")
  | mech == rsaX509Mech = case rsaX509RecipeFor mech of
      Just r | rsaX509ParamsValid r params -> Right 0
      _ -> Left (KeyDeny CKR_ARGUMENTS_BAD
        "RSA-X.509 wrap takes empty mechanism parameters")
  | otherwise = case rsaOaepRecipeFor mech of
      Just r | rsaOaepParamsValid r params ->
        case decodeOaepParams params of
          Just (d, _, _) -> case oaepDigestWidth d of
            Just h -> Right (2 * h + 2)
            -- Unreachable post-validation (the width table covers
            -- every code the codec admits); typed, never a crash.
            Nothing -> Left (KeyDeny CKR_ARGUMENTS_BAD
              "RSA-OAEP hash width is unknown")
          Nothing -> Left (KeyDeny CKR_ARGUMENTS_BAD
            "RSA-OAEP mechanism parameters rejected by the recipe")
      _ -> Left (KeyDeny CKR_ARGUMENTS_BAD
        "RSA-OAEP mechanism parameters rejected by the recipe")

-- | Plan one RSA wrap: the public wrapping key needs the wrap
-- mark, the target must be extractable, and the raw material must
-- fit the padding input bound (over the wrapping key's modulus
-- width). Length queries and short buffers answer the
-- modulus-wide blob length and plan no crypto; a sufficient
-- buffer plans one wrap effect over the raw material.
planRsaWrapKey
  :: Model -> SessionState -> MechanismId -> ByteString
  -> ExternalHandle -> ExternalHandle -> OutputIntent
  -> KeyPlan
planRsaWrapKey model st mech params wrapH targetH intent =
  case rsaWrapOverhead mech params of
    Left deny -> KeyDenied deny
    Right over ->
      case withRsaWrappingKey model st AttrWrap "wrapping" mech ckoPublicKey wrapH of
        Left deny -> KeyDenied deny
        Right (wrapOid, k) -> case withWrapTarget model st targetH of
          Left deny -> KeyDenied deny
          Right mat
            | BS.length mat > k - over -> KeyDenied (KeyDeny CKR_DATA_LEN_RANGE
                "wrap payload escapes the RSA input bound")
            | otherwise ->
                let blobLen = k
                    lenOut = NativeOutput (RegionBytes "wrapped" intent)
                      (encodeValue (ValULong (fromIntegral blobLen)))
                in case intent of
                  IntentNull -> KeyImmediate (Immediate PreparedCommit
                    { pcCode = CKR_OK
                    , pcDelta = StateDelta []
                    , pcPersist = []
                    , pcOutputs = [lenOut]
                    , pcReleases = []
                    , pcReasons = ["wrap length query"]
                    })
                  IntentBuffer cap
                    | cap < fromIntegral blobLen -> KeyImmediate (Reject Rejection
                        { rejCode = CKR_BUFFER_TOO_SMALL
                        , rejOutputs = [lenOut]
                        , rejDelta = StateDelta []
                        , rejReleases = []
                        , rejReasons = ["short buffer"]
                        , rejCause = Nothing
                        })
                    | otherwise -> KeyEffect (PwBlobOut "wrapped")
                        (FxWrap mech (Just wrapOid) params mat)

-- | Plan one AES-CBC wrap: the wrapping key needs the wrap mark,
-- the target must be extractable. Length queries and short
-- buffers answer the padded length and plan no crypto; a
-- sufficient buffer plans one wrap effect over the padded
-- material.
planAesWrapKey
  :: Model -> SessionState -> MechanismId -> ByteString
  -> ExternalHandle -> ExternalHandle -> OutputIntent
  -> KeyPlan
planAesWrapKey model st mech iv wrapH targetH intent
  | BS.length iv /= 16 =
      KeyDenied (KeyDeny CKR_ARGUMENTS_BAD "AES-CBC wrap needs a 16-byte IV")
  | otherwise = case withWrappingKey model st AttrWrap "wrapping" mech wrapH of
      Left deny -> KeyDenied deny
      Right (wrapOid, _) -> case withWrapTarget model st targetH of
        Left deny -> KeyDenied deny
        Right mat -> case padPkcs7 16 mat of
          Nothing -> KeyDenied (KeyDeny CKR_GENERAL_ERROR
            "wrap payload escapes the PKCS#7 range")
          Just padded ->
            let blobLen = BS.length padded
                lenOut = NativeOutput (RegionBytes "wrapped" intent)
                  (encodeValue (ValULong (fromIntegral blobLen)))
            in case intent of
              IntentNull -> KeyImmediate (Immediate PreparedCommit
                { pcCode = CKR_OK
                , pcDelta = StateDelta []
                , pcPersist = []
                , pcOutputs = [lenOut]
                , pcReleases = []
                , pcReasons = ["wrap length query"]
                })
              IntentBuffer cap
                | cap < fromIntegral blobLen -> KeyImmediate (Reject Rejection
                    { rejCode = CKR_BUFFER_TOO_SMALL
                    , rejOutputs = [lenOut]
                    , rejDelta = StateDelta []
                    , rejReleases = []
                    , rejReasons = ["short buffer"]
                    , rejCause = Nothing
                    })
                | otherwise -> KeyEffect (PwBlobOut "wrapped")
                    (FxWrap mech (Just wrapOid) iv padded)

-- | Plan one unwrap: AES-CBC aligns through 'planAesUnwrapKey',
-- the AES key-wrap rows frame through 'planAesKwUnwrapKey',
-- KW-PKCS7 frames plus strips through
-- 'planAesKwPkcs7UnwrapKey', the ECDH compositions split through
-- 'planEcdhCompUnwrapKey', the RSA composition splits through
-- 'planRsaCompUnwrapKey', the RSA mechanisms measure
-- modulus-wide through 'planRsaUnwrapKey'.
planUnwrapKey
  :: Rules -> Model -> SessionState -> MechanismId -> ByteString
  -> ExternalHandle -> ByteString -> [(AttributeType, AttributeValue)]
  -> KeyPlan
planUnwrapKey rules model st mech params wrapH blob tmpl
  | mech == aesCbcMech = planAesUnwrapKey rules model st mech params wrapH blob tmpl
  | mech == aesKwMech || mech == aesKwPadMech || mech == aesKwpMech =
      planAesKwUnwrapKey rules model st mech params wrapH blob tmpl
  | mech == aesKwp7Mech =
      planAesKwPkcs7UnwrapKey rules model st mech params wrapH blob tmpl
  | mech == ecdhAesKwMech || mech == ecdhCofAesKwMech || mech == ecdhXAesKwMech =
      planEcdhCompUnwrapKey rules model st mech params wrapH blob tmpl
  | mech == rsaAesKwMech =
      planRsaCompUnwrapKey rules model st mech params wrapH blob tmpl
  | mech == rsaPkcsMech || mech == rsaOaepMech || mech == rsaX509Mech =
      planRsaUnwrapKey rules model st mech params wrapH blob tmpl
  | otherwise =
      KeyDenied (KeyDeny CKR_MECHANISM_INVALID
        ("not a wrap mechanism: " ++ show mech))

-- | Plan one RSA unwrap: the private wrapping key needs the
-- unwrap mark, the blob must be exactly modulus-wide, and the
-- template must name the new key's class and key type explicitly
-- (the blob carries no header). Admission gates last
-- (parse-first): mechanism, parameters, key, blob, template,
-- then admission just before the effect. The pending work is raw
-- (no PKCS#7 framing to strip).
planRsaUnwrapKey
  :: Rules -> Model -> SessionState -> MechanismId -> ByteString
  -> ExternalHandle -> ByteString -> [(AttributeType, AttributeValue)]
  -> KeyPlan
planRsaUnwrapKey rules model st mech params wrapH blob tmpl =
  case validated of
    Left deny -> KeyDenied deny
    Right (pw, fx) ->
      case admitObjects rules (Map.size (mObjects model)) 1 of
        Left deny -> KeyDenied (KeyDeny (admitCode deny)
          ("admission denied: " ++ show deny))
        Right () -> KeyEffect pw fx
  where
    validated =
      case rsaWrapOverhead mech params of
        Left deny -> Left deny
        Right _ -> case withRsaWrappingKey model st AttrUnwrap "unwrapping" mech ckoPrivateKey wrapH of
          Left deny -> Left deny
          Right (wrapOid, k)
            | BS.length blob /= k ->
                Left (KeyDeny CKR_ARGUMENTS_BAD
                  "wrapped blob length mismatches the RSA modulus")
            | not (any ((== AttrKeyType) . fst) tmpl) ->
                Left (KeyDeny CKR_TEMPLATE_INCOMPLETE
                  "unwrap template must name the key type")
            | otherwise -> case checkKeyTemplateAny ckoSecretKey ckkGenericSecret tmpl of
                Left deny -> Left deny
                Right attrs
                  | mech == rsaX509Mech -> case Map.lookup AttrValueLen attrs of
                      Just (ValULong n)
                        | n >= 1 && fromIntegral n <= k -> Right
                            ( PwUnwrapTail (pendingFromAttrs st (stampUnwrapped attrs)) k (fromIntegral n)
                            , FxUnwrap mech (Just wrapOid) params blob
                            )
                        | otherwise -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
                            ("X.509 unwrap length escapes the modulus width: " ++ show n))
                      Just _ -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
                        "X.509 unwrap value length is malformed")
                      Nothing -> Left (KeyDeny CKR_TEMPLATE_INCOMPLETE
                        "X.509 unwrap needs CKA_VALUE_LEN")
                  | otherwise -> Right
                      ( PwUnwrapRaw (pendingFromAttrs st (stampUnwrapped attrs))
                      , FxUnwrap mech (Just wrapOid) params blob
                      )

-- | Plan one AES key-wrap wrap: the wrapping key needs the wrap
-- mark (AES secret: 'withWrappingKey'), the target must be
-- extractable, parameters are empty (ECB shape). KW needs
-- multiple-of-8 material >= 16 bytes and answers len + 8; KWP
-- (both names) needs non-empty material and answers ceil8 + 8.
-- Length queries and short buffers answer the expanded length and
-- plan no crypto; a sufficient buffer plans one wrap effect over
-- the raw material.
planAesKwWrapKey
  :: Model -> SessionState -> MechanismId -> ByteString
  -> ExternalHandle -> ExternalHandle -> OutputIntent
  -> KeyPlan
planAesKwWrapKey model st mech params wrapH targetH intent
  | not (BS.null params) =
      KeyDenied (KeyDeny CKR_ARGUMENTS_BAD
        "AES key wrap takes empty mechanism parameters")
  | otherwise = case withWrappingKey model st AttrWrap "wrapping" mech wrapH of
      Left deny -> KeyDenied deny
      Right (wrapOid, _) -> case withWrapTarget model st targetH of
        Left deny -> KeyDenied deny
        Right mat -> case kwBlobLen mech (BS.length mat) of
          Nothing -> KeyDenied (KeyDeny CKR_DATA_LEN_RANGE
            "wrap payload escapes the key-wrap length rules")
          Just blobLen ->
            let lenOut = NativeOutput (RegionBytes "wrapped" intent)
                  (encodeValue (ValULong (fromIntegral blobLen)))
            in case intent of
              IntentNull -> KeyImmediate (Immediate PreparedCommit
                { pcCode = CKR_OK
                , pcDelta = StateDelta []
                , pcPersist = []
                , pcOutputs = [lenOut]
                , pcReleases = []
                , pcReasons = ["wrap length query"]
                })
              IntentBuffer cap
                | cap < fromIntegral blobLen -> KeyImmediate (Reject Rejection
                    { rejCode = CKR_BUFFER_TOO_SMALL
                    , rejOutputs = [lenOut]
                    , rejDelta = StateDelta []
                    , rejReleases = []
                    , rejReasons = ["short buffer"]
                    , rejCause = Nothing
                    })
                | otherwise -> KeyEffect (PwBlobOut "wrapped")
                    (FxWrap mech (Just wrapOid) params mat)

-- | Wrapped-blob length for a payload length, or 'Nothing' when
-- the payload violates the row's floor (KW: multiple-of-8 >= 16;
-- KWP under either name: >= 1). Non-wrap mechanisms answer
-- 'Nothing' (the dispatch guards first; total anyway).
kwBlobLen :: MechanismId -> Int -> Maybe Int
kwBlobLen mech n
  | mech == aesKwMech
  , n >= 16 && n `mod` 8 == 0 = Just (n + 8)
  | (mech == aesKwPadMech || mech == aesKwpMech)
  , n >= 1 = Just (n + (8 - n `mod` 8) `mod` 8 + 8)
  | otherwise = Nothing

-- | Plan one AES-CBC unwrap: the wrapping key needs the unwrap
-- mark, the blob must be block-aligned, and the template must
-- name the new key's class and key type explicitly (the blob
-- carries no header). Admission gates last (parse-first):
-- mechanism, IV, blob, key, template, then the bound check just
-- before the effect.
planAesUnwrapKey
  :: Rules -> Model -> SessionState -> MechanismId -> ByteString
  -> ExternalHandle -> ByteString -> [(AttributeType, AttributeValue)]
  -> KeyPlan
planAesUnwrapKey rules model st mech iv wrapH blob tmpl =
  case validated of
    Left deny -> KeyDenied deny
    Right (pw, fx) ->
      case admitObjects rules (Map.size (mObjects model)) 1 of
        Left deny -> KeyDenied (KeyDeny (admitCode deny)
          ("admission denied: " ++ show deny))
        Right () -> KeyEffect pw fx
  where
    validated
      | BS.length iv /= 16 =
          Left (KeyDeny CKR_ARGUMENTS_BAD "AES-CBC unwrap needs a 16-byte IV")
      | BS.null blob || BS.length blob `mod` 16 /= 0 =
          Left (KeyDeny CKR_ARGUMENTS_BAD "wrapped blob is not block-aligned")
      | not (any ((== AttrKeyType) . fst) tmpl) =
          Left (KeyDeny CKR_TEMPLATE_INCOMPLETE
            "unwrap template must name the key type")
      | otherwise = case withWrappingKey model st AttrUnwrap "unwrapping" mech wrapH of
          Left deny -> Left deny
          Right (wrapOid, _) -> case checkKeyTemplateAny ckoSecretKey ckkGenericSecret tmpl of
            Left deny -> Left deny
            Right attrs -> Right
              ( PwUnwrap (pendingFromAttrs st (stampUnwrapped attrs))
              , FxUnwrap mech (Just wrapOid) iv blob
              )

-- | Plan one AES key-wrap unwrap: parameters are empty, the blob
-- must satisfy the row's framing (KW: multiple-of-8 >= 24; KWP
-- under either name: multiple-of-8 >= 16), the wrapping key needs
-- the unwrap mark (AES secret), and the template must name the
-- new key's class and key type explicitly (the blob carries no
-- header). Admission gates last (parse-first). The pending work
-- is raw (the backend answers exact plaintext, consumed framing).
planAesKwUnwrapKey
  :: Rules -> Model -> SessionState -> MechanismId -> ByteString
  -> ExternalHandle -> ByteString -> [(AttributeType, AttributeValue)]
  -> KeyPlan
planAesKwUnwrapKey rules model st mech params wrapH blob tmpl =
  case validated of
    Left deny -> KeyDenied deny
    Right (pw, fx) ->
      case admitObjects rules (Map.size (mObjects model)) 1 of
        Left deny -> KeyDenied (KeyDeny (admitCode deny)
          ("admission denied: " ++ show deny))
        Right () -> KeyEffect pw fx
  where
    validated
      | not (BS.null params) =
          Left (KeyDeny CKR_ARGUMENTS_BAD
            "AES key unwrap takes empty mechanism parameters")
      | not (kwBlobFramed mech (BS.length blob)) =
          Left (KeyDeny CKR_ARGUMENTS_BAD
            "wrapped blob violates key-wrap framing")
      | not (any ((== AttrKeyType) . fst) tmpl) =
          Left (KeyDeny CKR_TEMPLATE_INCOMPLETE
            "unwrap template must name the key type")
      | otherwise = case withWrappingKey model st AttrUnwrap "unwrapping" mech wrapH of
          Left deny -> Left deny
          Right (wrapOid, _) -> case checkKeyTemplateAny ckoSecretKey ckkGenericSecret tmpl of
            Left deny -> Left deny
            Right attrs -> Right
              ( PwUnwrapRaw (pendingFromAttrs st (stampUnwrapped attrs))
              , FxUnwrap mech (Just wrapOid) params blob
              )

-- | Wrapped-blob framing check: KW blobs are multiple-of-8 >= 24
-- (16-byte minimum plaintext plus IV); KWP blobs under either
-- name are multiple-of-8 >= 16; KW-PKCS7 frames like KW (the
-- padded image is the KW plaintext).
kwBlobFramed :: MechanismId -> Int -> Bool
kwBlobFramed mech n
  | mech == aesKwMech = n >= 24 && n `mod` 8 == 0
  | mech == aesKwp7Mech = n >= 24 && n `mod` 8 == 0
  | mech == aesKwPadMech || mech == aesKwpMech =
      n >= 16 && n `mod` 8 == 0
  | otherwise = False

-- | Plan one KW-PKCS7 wrap: the wrapping key needs the wrap mark
-- (AES secret), parameters are empty (default AIV) or the 8-byte
-- alternate IV, the target must be extractable, and the raw
-- material needs >= 8 bytes (shorter pads below the 16-byte KW
-- minimum). Length queries and short buffers answer the padded
-- length plus 8 and plan no crypto; a sufficient buffer plans one
-- wrap effect over the padded material.
planAesKwPkcs7WrapKey
  :: Model -> SessionState -> MechanismId -> ByteString
  -> ExternalHandle -> ExternalHandle -> OutputIntent
  -> KeyPlan
planAesKwPkcs7WrapKey model st mech params wrapH targetH intent
  | not (BS.null params) && BS.length params /= 8 =
      KeyDenied (KeyDeny CKR_ARGUMENTS_BAD
        "AES-KW-PKCS7 wrap takes empty or 8-byte-IV mechanism parameters")
  | otherwise = case withWrappingKey model st AttrWrap "wrapping" mech wrapH of
      Left deny -> KeyDenied deny
      Right (wrapOid, _) -> case withWrapTarget model st targetH of
        Left deny -> KeyDenied deny
        Right mat -> case padPkcs7 8 mat of
          Nothing -> KeyDenied (KeyDeny CKR_GENERAL_ERROR
            "wrap payload escapes the PKCS#7 range")
          Just padded
            | BS.length padded < 16 -> KeyDenied (KeyDeny CKR_DATA_LEN_RANGE
                "wrap payload pads below the 16-byte key-wrap minimum")
            | otherwise ->
                let blobLen = BS.length padded + 8
                    lenOut = NativeOutput (RegionBytes "wrapped" intent)
                      (encodeValue (ValULong (fromIntegral blobLen)))
                in case intent of
                  IntentNull -> KeyImmediate (Immediate PreparedCommit
                    { pcCode = CKR_OK
                    , pcDelta = StateDelta []
                    , pcPersist = []
                    , pcOutputs = [lenOut]
                    , pcReleases = []
                    , pcReasons = ["wrap length query"]
                    })
                  IntentBuffer cap
                    | cap < fromIntegral blobLen -> KeyImmediate (Reject Rejection
                        { rejCode = CKR_BUFFER_TOO_SMALL
                        , rejOutputs = [lenOut]
                        , rejDelta = StateDelta []
                        , rejReleases = []
                        , rejReasons = ["short buffer"]
                        , rejCause = Nothing
                        })
                    | otherwise -> KeyEffect (PwBlobOut "wrapped")
                        (FxWrap mech (Just wrapOid) params padded)

-- | Plan one KW-PKCS7 unwrap: parameters are empty (default AIV)
-- or the 8-byte alternate IV, the blob frames like KW
-- (multiple-of-8 >= 24), the wrapping key needs the unwrap mark
-- (AES secret), and the template must name the new key's class
-- and key type explicitly (the blob carries no header). Admission
-- gates last (parse-first). The pending work strips the 8-quantum
-- PKCS#7 framing ('PwUnwrapPad8').
planAesKwPkcs7UnwrapKey
  :: Rules -> Model -> SessionState -> MechanismId -> ByteString
  -> ExternalHandle -> ByteString -> [(AttributeType, AttributeValue)]
  -> KeyPlan
planAesKwPkcs7UnwrapKey rules model st mech params wrapH blob tmpl =
  case validated of
    Left deny -> KeyDenied deny
    Right (pw, fx) ->
      case admitObjects rules (Map.size (mObjects model)) 1 of
        Left deny -> KeyDenied (KeyDeny (admitCode deny)
          ("admission denied: " ++ show deny))
        Right () -> KeyEffect pw fx
  where
    validated
      | not (BS.null params) && BS.length params /= 8 =
          Left (KeyDeny CKR_ARGUMENTS_BAD
            "AES-KW-PKCS7 unwrap takes empty or 8-byte-IV mechanism parameters")
      | not (kwBlobFramed mech (BS.length blob)) =
          Left (KeyDeny CKR_ARGUMENTS_BAD
            "wrapped blob violates key-wrap framing")
      | not (any ((== AttrKeyType) . fst) tmpl) =
          Left (KeyDeny CKR_TEMPLATE_INCOMPLETE
            "unwrap template must name the key type")
      | otherwise = case withWrappingKey model st AttrUnwrap "unwrapping" mech wrapH of
          Left deny -> Left deny
          Right (wrapOid, _) -> case checkKeyTemplateAny ckoSecretKey ckkGenericSecret tmpl of
            Left deny -> Left deny
            Right attrs -> Right
              ( PwUnwrapPad8 (pendingFromAttrs st (stampUnwrapped attrs))
              , FxUnwrap mech (Just wrapOid) params blob
              )

-- | Plan one ECDH-composition wrap: parameters validate against
-- the composition recipe (malformed frames refuse argument-bad;
-- well-formed frames with an unserved KDF refuse parameter-invalid
-- — the KDF enum is open), the wrapping key is the recipient
-- PUBLIC EC\/Montgomery key admitted by the row, the target must
-- be extractable, the agreement secret must cover the KEK (short
-- curves refuse the wide strengths), and the answered length is
-- the transport prefix plus the KWP expansion over the target
-- material. Length queries and short buffers answer that length
-- and plan no crypto; a sufficient buffer plans one wrap effect
-- over the raw material (the driver mints the ephemeral
-- transport pair, derives the KEK, and KWP-seals).
planEcdhCompWrapKey
  :: Model -> SessionState -> MechanismId -> ByteString
  -> ExternalHandle -> ExternalHandle -> OutputIntent
  -> KeyPlan
planEcdhCompWrapKey model st mech params wrapH targetH intent =
  case wrapCompEcdhRecipeFor mech of
    Nothing -> KeyDenied (KeyDeny CKR_MECHANISM_INVALID
      ("not a wrap mechanism: " ++ show mech))
    Just r
      | not (wrapCompEcdhParamsWellFormed params) ->
          KeyDenied (KeyDeny CKR_ARGUMENTS_BAD
            "ECDH wrap takes framed parameters with a served AES strength")
      | not (wrapCompEcdhKdfServed params) ->
          KeyDenied (KeyDeny CKR_MECHANISM_PARAM_INVALID
            "ECDH wrap serves the null KDF only")
      | otherwise -> case withEcCompWrappingKey model st AttrWrap "wrapping" mech r wrapH of
          Left deny -> KeyDenied deny
          Right (wrapOid, mat, dom) -> case withWrapTarget model st targetH of
            Left deny -> KeyDenied deny
            Right tmat -> case (wrapCompAesBytes params, wrapCompTransportLen r dom) of
              (Just aesBytes, Just preLen)
                | ecdhSecretWidth mat < aesBytes ->
                    KeyDenied (KeyDeny CKR_MECHANISM_PARAM_INVALID
                      "agreement secret is shorter than the requested AES strength")
                | otherwise -> case kwBlobLen aesKwpMech (BS.length tmat) of
                    Nothing -> KeyDenied (KeyDeny CKR_DATA_LEN_RANGE
                      "wrap payload escapes the key-wrap length rules")
                    Just kwpLen ->
                      let blobLen = preLen + kwpLen
                          lenOut = NativeOutput (RegionBytes "wrapped" intent)
                            (encodeValue (ValULong (fromIntegral blobLen)))
                      in case intent of
                        IntentNull -> KeyImmediate (Immediate PreparedCommit
                          { pcCode = CKR_OK
                          , pcDelta = StateDelta []
                          , pcPersist = []
                          , pcOutputs = [lenOut]
                          , pcReleases = []
                          , pcReasons = ["wrap length query"]
                          })
                        IntentBuffer cap
                          | cap < fromIntegral blobLen -> KeyImmediate (Reject Rejection
                              { rejCode = CKR_BUFFER_TOO_SMALL
                              , rejOutputs = [lenOut]
                              , rejDelta = StateDelta []
                              , rejReleases = []
                              , rejReasons = ["short buffer"]
                              , rejCause = Nothing
                              })
                          | otherwise -> KeyEffect (PwBlobOut "wrapped")
                              (FxWrap mech (Just wrapOid) params tmat)
              _ -> KeyDenied (KeyDeny CKR_WRAPPING_KEY_TYPE_INCONSISTENT
                "wrapping key domain contradicts the composition row")

-- | Plan one ECDH-composition unwrap: parameters validate against
-- the composition recipe (malformed frames refuse argument-bad;
-- unserved KDFs refuse parameter-invalid), the blob splits into a
-- transport prefix plus a KWP-shaped tail, the unwrapping key is
-- the recipient PRIVATE EC\/Montgomery key admitted by the row
-- whose agreement secret covers the KEK, and the template must
-- name the new key's class and key type explicitly (the blob
-- carries no header). Admission gates last (parse-first). The
-- pending work is raw (the backend answers exact target
-- plaintext, consumed framing).
planEcdhCompUnwrapKey
  :: Rules -> Model -> SessionState -> MechanismId -> ByteString
  -> ExternalHandle -> ByteString -> [(AttributeType, AttributeValue)]
  -> KeyPlan
planEcdhCompUnwrapKey rules model st mech params wrapH blob tmpl =
  case validated of
    Left deny -> KeyDenied deny
    Right (pw, fx) ->
      case admitObjects rules (Map.size (mObjects model)) 1 of
        Left deny -> KeyDenied (KeyDeny (admitCode deny)
          ("admission denied: " ++ show deny))
        Right () -> KeyEffect pw fx
  where
    validated = case wrapCompEcdhRecipeFor mech of
      Nothing -> Left (KeyDeny CKR_MECHANISM_INVALID
        ("not a wrap mechanism: " ++ show mech))
      Just r
        | not (wrapCompEcdhParamsWellFormed params) ->
            Left (KeyDeny CKR_ARGUMENTS_BAD
              "ECDH unwrap takes framed parameters with a served AES strength")
        | not (wrapCompEcdhKdfServed params) ->
            Left (KeyDeny CKR_MECHANISM_PARAM_INVALID
              "ECDH unwrap serves the null KDF only")
        | not (any ((== AttrKeyType) . fst) tmpl) ->
            Left (KeyDeny CKR_TEMPLATE_INCOMPLETE
              "unwrap template must name the key type")
        | otherwise -> case withEcCompWrappingKey model st AttrUnwrap "unwrapping" mech r wrapH of
            Left deny -> Left deny
            Right (wrapOid, mat, dom) -> case wrapCompAesBytes params of
              Just aesBytes
                | ecdhSecretWidth mat < aesBytes ->
                    Left (KeyDeny CKR_MECHANISM_PARAM_INVALID
                      "agreement secret is shorter than the requested AES strength")
                | otherwise -> case wrapCompSplitBlob r dom blob of
                    Nothing -> Left (KeyDeny CKR_ARGUMENTS_BAD
                      "wrapped blob violates composition framing")
                    Just _ -> case checkKeyTemplateAny ckoSecretKey ckkGenericSecret tmpl of
                      Left deny -> Left deny
                      Right attrs -> Right
                        ( PwUnwrapRaw (pendingFromAttrs st (stampUnwrapped attrs))
                        , FxUnwrap mech (Just wrapOid) params blob
                        )
              _ -> Left (KeyDeny CKR_ARGUMENTS_BAD
                "ECDH unwrap takes null-KDF parameters with a served AES strength")

-- | Plan one RSA-composition wrap: parameters validate against
-- the composition recipe (framed OAEP plus a served AES
-- strength), the wrapping key is the recipient PUBLIC RSA key,
-- the target must be extractable, the temp KEK must fit the
-- OAEP input bound over the modulus (short moduli refuse the
-- wide strengths with the length range), and the answered
-- length is the modulus width plus the KWP expansion over the
-- target material. Length queries and short buffers answer
-- that length and plan no crypto; a sufficient buffer plans
-- one wrap effect over the raw material (the driver mints the
-- random temp KEK, OAEP-seals it, and KWP-seals the target).
planRsaCompWrapKey
  :: Model -> SessionState -> MechanismId -> ByteString
  -> ExternalHandle -> ExternalHandle -> OutputIntent
  -> KeyPlan
planRsaCompWrapKey model st mech params wrapH targetH intent =
  case wrapCompRsaRecipeFor mech of
    Nothing -> KeyDenied (KeyDeny CKR_MECHANISM_INVALID
      ("not a wrap mechanism: " ++ show mech))
    Just r
      | not (wrapCompRsaParamsValid r params) ->
          KeyDenied (KeyDeny CKR_ARGUMENTS_BAD
            "RSA wrap takes framed OAEP parameters with a served AES strength")
      | otherwise -> case withRsaWrappingKey model st AttrWrap "wrapping" mech ckoPublicKey wrapH of
          Left deny -> KeyDenied deny
          Right (wrapOid, k) -> case withWrapTarget model st targetH of
            Left deny -> KeyDenied deny
            Right tmat -> case (wrapCompRsaOaep params, wrapCompRsaAesBytes params) of
              (Just (d, _, _), Just aesBytes)
                | not (wrapCompRsaKekFits k d aesBytes) ->
                    KeyDenied (KeyDeny CKR_DATA_LEN_RANGE
                      "temp KEK escapes the OAEP input bound")
                | otherwise -> case kwBlobLen aesKwpMech (BS.length tmat) of
                    Nothing -> KeyDenied (KeyDeny CKR_DATA_LEN_RANGE
                      "wrap payload escapes the key-wrap length rules")
                    Just kwpLen ->
                      let blobLen = k + kwpLen
                          lenOut = NativeOutput (RegionBytes "wrapped" intent)
                            (encodeValue (ValULong (fromIntegral blobLen)))
                      in case intent of
                        IntentNull -> KeyImmediate (Immediate PreparedCommit
                          { pcCode = CKR_OK
                          , pcDelta = StateDelta []
                          , pcPersist = []
                          , pcOutputs = [lenOut]
                          , pcReleases = []
                          , pcReasons = ["wrap length query"]
                          })
                        IntentBuffer cap
                          | cap < fromIntegral blobLen -> KeyImmediate (Reject Rejection
                              { rejCode = CKR_BUFFER_TOO_SMALL
                              , rejOutputs = [lenOut]
                              , rejDelta = StateDelta []
                              , rejReleases = []
                              , rejReasons = ["short buffer"]
                              , rejCause = Nothing
                              })
                          | otherwise -> KeyEffect (PwBlobOut "wrapped")
                              (FxWrap mech (Just wrapOid) params tmat)
              -- Unreachable post-validation (both projections are
              -- 'Just' exactly when the recipe validates); typed,
              -- never a crash.
              _ -> KeyDenied (KeyDeny CKR_ARGUMENTS_BAD
                "RSA wrap takes framed OAEP parameters with a served AES strength")

-- | Plan one RSA-composition unwrap: parameters validate against
-- the composition recipe, the blob splits into a modulus-wide
-- OAEP head plus a KWP-shaped tail, the unwrapping key is the
-- recipient PRIVATE RSA key whose modulus fits the temp KEK,
-- and the template must name the new key's class and key type
-- explicitly (the blob carries no header). Admission gates
-- last (parse-first). The pending work is raw (the backend
-- answers exact target plaintext, consumed framing).
planRsaCompUnwrapKey
  :: Rules -> Model -> SessionState -> MechanismId -> ByteString
  -> ExternalHandle -> ByteString -> [(AttributeType, AttributeValue)]
  -> KeyPlan
planRsaCompUnwrapKey rules model st mech params wrapH blob tmpl =
  case validated of
    Left deny -> KeyDenied deny
    Right (pw, fx) ->
      case admitObjects rules (Map.size (mObjects model)) 1 of
        Left deny -> KeyDenied (KeyDeny (admitCode deny)
          ("admission denied: " ++ show deny))
        Right () -> KeyEffect pw fx
  where
    validated = case wrapCompRsaRecipeFor mech of
      Nothing -> Left (KeyDeny CKR_MECHANISM_INVALID
        ("not a wrap mechanism: " ++ show mech))
      Just r
        | not (wrapCompRsaParamsValid r params) ->
            Left (KeyDeny CKR_ARGUMENTS_BAD
              "RSA unwrap takes framed OAEP parameters with a served AES strength")
        | not (any ((== AttrKeyType) . fst) tmpl) ->
            Left (KeyDeny CKR_TEMPLATE_INCOMPLETE
              "unwrap template must name the key type")
        | otherwise -> case withRsaWrappingKey model st AttrUnwrap "unwrapping" mech ckoPrivateKey wrapH of
            Left deny -> Left deny
            Right (wrapOid, k) -> case (wrapCompRsaOaep params, wrapCompRsaAesBytes params) of
              (Just (d, _, _), Just aesBytes)
                | not (wrapCompRsaKekFits k d aesBytes) ->
                    Left (KeyDeny CKR_DATA_LEN_RANGE
                      "temp KEK escapes the OAEP input bound")
                | otherwise -> case wrapCompRsaSplitBlob k blob of
                    Nothing -> Left (KeyDeny CKR_ARGUMENTS_BAD
                      "wrapped blob violates composition framing")
                    Just _ -> case checkKeyTemplateAny ckoSecretKey ckkGenericSecret tmpl of
                      Left deny -> Left deny
                      Right attrs -> Right
                        ( PwUnwrapRaw (pendingFromAttrs st (stampUnwrapped attrs))
                        , FxUnwrap mech (Just wrapOid) params blob
                        )
              -- Unreachable post-validation; typed, never a crash.
              _ -> Left (KeyDeny CKR_ARGUMENTS_BAD
                "RSA unwrap takes framed OAEP parameters with a served AES strength")

-- | Plan one authenticated wrap: like 'planWrapKey', but the blob
-- binds associated data under a 32-byte tag, so the answered length
-- is the padded length plus 32.
planAuthWrapKey
  :: Model -> SessionState -> MechanismId -> ByteString
  -> ExternalHandle -> ExternalHandle -> ByteString -> OutputIntent
  -> KeyPlan
planAuthWrapKey model st mech iv wrapH targetH aad intent
  | mech /= aesCbcMech =
      KeyDenied (KeyDeny CKR_MECHANISM_INVALID
        ("not a wrap mechanism: " ++ show mech))
  | BS.length iv /= 16 =
      KeyDenied (KeyDeny CKR_ARGUMENTS_BAD "AES-CBC wrap needs a 16-byte IV")
  | otherwise = case withWrappingKey model st AttrWrap "wrapping" mech wrapH of
      Left deny -> KeyDenied deny
      Right (wrapOid, _) -> case withWrapTarget model st targetH of
        Left deny -> KeyDenied deny
        Right mat -> case padPkcs7 16 mat of
          Nothing -> KeyDenied (KeyDeny CKR_GENERAL_ERROR
            "wrap payload escapes the PKCS#7 range")
          Just padded ->
            let blobLen = BS.length padded + 32
                lenOut = NativeOutput (RegionBytes "wrapped" intent)
                  (encodeValue (ValULong (fromIntegral blobLen)))
            in case intent of
              IntentNull -> KeyImmediate (Immediate PreparedCommit
                { pcCode = CKR_OK
                , pcDelta = StateDelta []
                , pcPersist = []
                , pcOutputs = [lenOut]
                , pcReleases = []
                , pcReasons = ["authenticated-wrap length query"]
                })
              IntentBuffer cap
                | cap < fromIntegral blobLen -> KeyImmediate (Reject Rejection
                    { rejCode = CKR_BUFFER_TOO_SMALL
                    , rejOutputs = [lenOut]
                    , rejDelta = StateDelta []
                    , rejReleases = []
                    , rejReasons = ["short buffer"]
                    , rejCause = Nothing
                    })
                | otherwise -> KeyEffect (PwBlobOut "wrapped")
                    (FxAuthWrap mech (Just wrapOid) (encodeWrapParams iv aad) padded)

-- | Plan one authenticated unwrap: like 'planUnwrapKey', with the
-- associated data the tag is verified against. Admission gates
-- last (parse-first): mechanism, IV, blob, key, template,
-- then the bound check just before the effect.
planAuthUnwrapKey
  :: Rules -> Model -> SessionState -> MechanismId -> ByteString
  -> ExternalHandle -> ByteString -> ByteString -> [(AttributeType, AttributeValue)]
  -> KeyPlan
planAuthUnwrapKey rules model st mech iv wrapH blob aad tmpl =
  case validated of
    Left deny -> KeyDenied deny
    Right (pw, fx) ->
      case admitObjects rules (Map.size (mObjects model)) 1 of
        Left deny -> KeyDenied (KeyDeny (admitCode deny)
          ("admission denied: " ++ show deny))
        Right () -> KeyEffect pw fx
  where
    validated
      | mech /= aesCbcMech =
          Left (KeyDeny CKR_MECHANISM_INVALID
            ("not a wrap mechanism: " ++ show mech))
      | BS.length iv /= 16 =
          Left (KeyDeny CKR_ARGUMENTS_BAD "AES-CBC unwrap needs a 16-byte IV")
      | BS.length blob < 32 || (BS.length blob - 32) `mod` 16 /= 0 =
          Left (KeyDeny CKR_ARGUMENTS_BAD "authenticated blob has a bad length")
      | not (any ((== AttrKeyType) . fst) tmpl) =
          Left (KeyDeny CKR_TEMPLATE_INCOMPLETE
            "unwrap template must name the key type")
      | otherwise = case withWrappingKey model st AttrUnwrap "unwrapping" mech wrapH of
          Left deny -> Left deny
          Right (wrapOid, _) -> case checkKeyTemplateAny ckoSecretKey ckkGenericSecret tmpl of
            Left deny -> Left deny
            Right attrs -> Right
              ( PwUnwrap (pendingFromAttrs st (stampUnwrapped attrs))
              , FxAuthUnwrap mech (Just wrapOid) (encodeWrapParams iv aad) blob
              )
