{- | KeyManagement wrap planners: RSA/AES/KW wrap and unwrap
plus the wrapping-key readers and blob geometry behind them.

Imports the Types/Template/Codec/Codes/MechIds leaves only.
Imported by WrapComp and the shell dispatchers. The dispatchers
('planWrapKey', 'planUnwrapKey') stay in the shell: they fan out
across Wrap and WrapComp, so moving them would cycle.
-}
{-# LANGUAGE OverloadedStrings #-}
module Haskoki.Operation.KeyManagement.Wrap
  ( withWrappingKey
  , withRsaWrappingKey
  , withEcCompWrappingKey
  , withWrapTarget
  , planRsaWrapKey
  , planAesWrapKey
  , planRsaUnwrapKey
  , planAesKwWrapKey
  , kwBlobLen
  , planAesUnwrapKey
  , planAesKwUnwrapKey
  , kwBlobFramed
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
import Haskoki.Operation.KeyManagement.Codec
import Haskoki.Operation.KeyManagement.Codes
import Haskoki.Operation.KeyManagement.MechIds
import Haskoki.Operation.KeyManagement.Template
import Haskoki.Operation.KeyManagement.Types
import Haskoki.Outcome
  ( NativeOutput (..)
  , PlanResult (..)
  , PreparedCommit (..)
  , Rejection (..)
  , StateDelta (..)
  )
import Haskoki.Recipe.RsaOaep
  ( decodeOaepParams
  , oaepDigestWidth
  , rsaOaepParamsValid
  , rsaOaepRecipeFor
  )
import Haskoki.Recipe.RsaPkcs1 (rsaPkcs1ParamsValid, rsaPkcs1RecipeFor)
import Haskoki.Recipe.RsaX509 (rsaX509ParamsValid, rsaX509RecipeFor)
import Haskoki.Recipe.WrapComp
  ( WrapCompDomain
  , WrapCompEcdhRecipe
  , wrapCompDomain
  , wrapCompEcdhKeyOk
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
