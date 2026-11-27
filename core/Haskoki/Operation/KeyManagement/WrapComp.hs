{- | KeyManagement composition wrap planners: KWP-PKCS7, ECDH
and RSA composition, and authenticated wrap/unwrap.

Imports Wrap (key readers, blob geometry) and the leaves.
Imported by the shell dispatchers; the auth planners are
re-exported via the shell.
-}
{-# LANGUAGE OverloadedStrings #-}
module Haskoki.Operation.KeyManagement.WrapComp
  ( planAesKwPkcs7WrapKey
  , planAesKwPkcs7UnwrapKey
  , planEcdhCompWrapKey
  , planEcdhCompUnwrapKey
  , planRsaCompWrapKey
  , planRsaCompUnwrapKey
  , planAuthWrapKey
  , planAuthUnwrapKey
  ) where

import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import qualified Data.Map.Strict as Map
import Haskoki.Attribute
  ( AttributeType (..)
  , AttributeValue (..)
  , encodeValue
  )
import Haskoki.Model (Model (..), SessionState (..))
import Haskoki.Operation.Effect (CryptoEffect (..))
import Haskoki.Operation.KeyManagement.Codec
import Haskoki.Operation.KeyManagement.Codes
import Haskoki.Operation.KeyManagement.MechIds
import Haskoki.Operation.KeyManagement.Template
import Haskoki.Operation.KeyManagement.Types
import Haskoki.Operation.KeyManagement.Wrap
import Haskoki.Outcome
  ( NativeOutput (..)
  , PlanResult (..)
  , PreparedCommit (..)
  , Rejection (..)
  , StateDelta (..)
  )
import Haskoki.Recipe.Ecdh (ecdhSecretWidth)
import Haskoki.Recipe.WrapCompRsa
  ( wrapCompRsaAesBytes
  , wrapCompRsaKekFits
  , wrapCompRsaOaep
  , wrapCompRsaParamsValid
  , wrapCompRsaRecipeFor
  , wrapCompRsaSplitBlob
  )
import Haskoki.Recipe.WrapComp
  ( wrapCompAesBytes
  , wrapCompEcdhKdfServed
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
  , ReturnCode (..)
  )


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
