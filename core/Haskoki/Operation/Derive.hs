{- | Key-derivation planning: one multi-key codec (pure).

A derive call frames its context string plus one or more key
templates ('encodeDeriveParams'); 'planDerive' decodes the frame,
validates EVERY template before planning, and emits one 'FxDerive'
effect whose concatenated answer 'finishWork' splits across the
pending objects. Any invalid template — or a malformed frame —
denies with zero objects published.

Key derivation offers HKDF-Expand with HMAC-SHA-256 over the base
key bytes (salt fixed empty, PRF fixed): the same base, context and
lengths replay the same bytes on every backend offering HMAC-SHA-256.
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
  , maxDerivedTotal
  , maxDeriveKeys
  , maxDeriveInfo
  , encodeDeriveParams
  , decodeDeriveParams
  , planDerive
  ) where

import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import qualified Data.Map.Strict as Map

import Haskoki.Attribute (AttributeType (..), AttributeValue (..))
import Haskoki.Model (Model (..), ObjectState (..), SessionState)
import Haskoki.Object (encodeTemplate, objectVisible, parseTemplate, resolveHandle)
import Haskoki.Operation.Effect (CryptoEffect (..))
import Haskoki.Operation.KeyManagement
  ( KeyDeny (..)
  , KeyPlan (..)
  , PendingWork (..)
  , checkKeyTemplateAny
  , ckkEc
  , ckkGenericSecret
  , ckoSecretKey
  , keyBytesOf
  , pendingFromAttrs
  )
import Haskoki.Recipe.Ecdh
  ( decodeEcdhParams
  , ecdhParamsValid
  , ecdhRecipeFor
  , ecdhSecretWidth
  )
import Haskoki.Recipe.Ecdsa (ecdsaCurveOfDer)
import Haskoki.Recipe.Kdf
  ( KdfRecipe (..)
  , kdfParamsValid
  , kdfRecipeFor
  , kdfShaWidth
  )
import Haskoki.Registry (MechanismId (..))
import Haskoki.Registry.Generated (ckm_HKDF_DERIVE)
import Haskoki.Rules (Rules)
import Haskoki.Session (admitCode, admitObjects)
import Haskoki.Types (ExternalHandle, ReturnCode (..))

-- | @CKM_HKDF_DERIVE@ (generated id, resolved by name).
hkdfDeriveMech :: MechanismId
hkdfDeriveMech = MechanismId (ckm_HKDF_DERIVE)

-- | HKDF-Expand-SHA256 output ceiling: 255 blocks of 32 bytes.
maxDerivedTotal :: Int
maxDerivedTotal = 255 * 32

-- | Bounded fan-out: at most 16 keys per derive call.
maxDeriveKeys :: Int
maxDeriveKeys = 16

-- | Context-string ceiling: 64 KiB.
maxDeriveInfo :: Int
maxDeriveInfo = 65536

-- | Frame derive arguments: @infoLen:u32be info count:u16be
-- (tmplLen:u32be tmpl)*@, each template in 'encodeTemplate' form.
encodeDeriveParams :: ByteString -> [[(AttributeType, AttributeValue)]] -> ByteString
encodeDeriveParams info tmpls =
  u32be (BS.length info) <> info <> u16be (length tmpls) <> BS.concat
    [ u32be (BS.length t) <> t | t <- map encodeTemplate tmpls ]
  where
    u32be n = BS.pack
      [ fromIntegral (n `div` 16777216 `mod` 256)
      , fromIntegral (n `div` 65536 `mod` 256)
      , fromIntegral (n `div` 256 `mod` 256)
      , fromIntegral (n `mod` 256)
      ]
    u16be n = BS.pack
      [ fromIntegral (n `div` 256 `mod` 256)
      , fromIntegral (n `mod` 256)
      ]

-- | Parse framed derive arguments. Truncation, overrun lengths,
-- context past 'maxDeriveInfo', more than 'maxDeriveKeys'
-- templates, oversized templates and trailing bytes all fail.
decodeDeriveParams :: ByteString -> Maybe (ByteString, [[(AttributeType, AttributeValue)]])
decodeDeriveParams bs = do
  (infoLen, r0) <- takeU32 bs
  let infoN = fromIntegral infoLen
  if infoN > maxDeriveInfo
    then Nothing
    else do
      (info, r1) <- takeN infoN r0
      (count, r2) <- takeU16 r1
      let n = fromIntegral count
      if n > maxDeriveKeys
        then Nothing
        else do
          (tmpls, rest) <- takeTmpls n r2
          if BS.null rest then Just (info, tmpls) else Nothing
  where
    takeN :: Int -> ByteString -> Maybe (ByteString, ByteString)
    takeN n b
      | BS.length b < n = Nothing
      | otherwise = Just (BS.splitAt n b)
    takeU32 :: ByteString -> Maybe (Int, ByteString)
    takeU32 b = do
      (h, r) <- takeN 4 b
      pure (BS.foldl' (\acc x -> acc * 256 + fromIntegral x) 0 h, r)
    takeU16 :: ByteString -> Maybe (Int, ByteString)
    takeU16 b = do
      (h, r) <- takeN 2 b
      pure (BS.foldl' (\acc x -> acc * 256 + fromIntegral x) 0 h, r)
    takeTmpls :: Int -> ByteString -> Maybe ([[(AttributeType, AttributeValue)]], ByteString)
    takeTmpls 0 b = Just ([], b)
    takeTmpls k b = do
      (tLen, r0) <- takeU32 b
      (tBs, r1) <- takeN tLen r0
      tmpl <- parseTemplate tBs
      (rest, r2) <- takeTmpls (k - 1) r1
      pure (tmpl : rest, r2)

-- | Plan one (possibly multi-key) derivation: the mechanism must be
-- a derive mechanism (HKDF, ECDH, or KDF), the base handle must
-- resolve to a visible key carrying the derive mark and stored
-- material, and EVERY template must describe a secret key with a
-- positive length — except ECDH templates, where a missing
-- CKA_VALUE_LEN defaults to the full agreement secret (PKCS#11
-- v3.2: truncation applies "if it has one" a length). Check
-- order: mechanism, frame, base, then templates in order; the
-- first failure denies with zero objects.
-- ECDH arms resolve the base and require an EC key type before
-- examining parameters, and SHA-KDF arms require a generic-secret
-- base (a key-type contradiction outranks parameter shape); ECDH
-- frames carry the agreement parameters ('ecdh-params/1') in the
-- info segment and the derived total is capped by the base
-- curve's coordinate width; HKDF frames carry the context string,
-- capped by the HKDF-Expand ceiling. Admission gates with the
-- EXACT validated template count (post-validation: an
-- unvalidated count could over-refuse).
planDerive
  :: Rules -> Model -> SessionState -> MechanismId -> ExternalHandle
  -> ByteString -> KeyPlan
planDerive rules model st mech baseH blob
  | mech == hkdfDeriveMech = case decodeDeriveParams blob of
      Nothing -> KeyDenied (KeyDeny CKR_ARGUMENTS_BAD
        "malformed derive arguments")
      Just (info, tmpls) -> case resolveBase model st baseH of
        Left deny -> KeyDenied deny
        Right (ost, _) -> finish tmpls maxDerivedTotal
          "derived total exceeds the HKDF-Expand ceiling"
          (FxDerive mech (Just (osId ost)) BS.empty info)
          Nothing
  | Just r <- ecdhRecipeFor mech = case decodeDeriveParams blob of
      Nothing -> KeyDenied (KeyDeny CKR_ARGUMENTS_BAD
        "malformed derive arguments")
      -- Key-type contradiction outranks parameter shape (the
      -- Init-matrix ordering): the base resolves and must be EC
      -- before params are examined.
      Just (ecdhBlob, tmpls) -> case resolveBase model st baseH of
        Left deny -> KeyDenied deny
        Right (ost, mat)
          | Map.lookup AttrKeyType (osAttrs ost) /= Just (ValULong ckkEc) ->
              KeyDenied (KeyDeny CKR_KEY_TYPE_INCONSISTENT
                "ECDH base key is not an EC key")
          | not (ecdhParamsValid r ecdhBlob) -> KeyDenied (KeyDeny CKR_MECHANISM_PARAM_INVALID
              "ECDH mechanism parameters rejected by the recipe")
          | otherwise -> case decodeEcdhParams ecdhBlob of
              Just (_, _, peer)
                | curvesDiffer mat peer -> KeyDenied (KeyDeny CKR_MECHANISM_PARAM_INVALID
                    "ECDH base/peer curve mismatch")
                | otherwise -> finish tmpls (ecdhSecretWidth mat)
                    "derived total exceeds the ECDH secret width"
                    (FxDerive mech (Just (osId ost)) ecdhBlob BS.empty)
                    (Just (ecdhSecretWidth mat))
              _ -> KeyDenied (KeyDeny CKR_MECHANISM_PARAM_INVALID
                "ECDH mechanism parameters rejected by the recipe")
  | Just r <- kdfRecipeFor mech = case decodeDeriveParams blob of
      Nothing -> KeyDenied (KeyDeny CKR_ARGUMENTS_BAD
        "malformed derive arguments")
      Just (info, tmpls) -> case resolveBase model st baseH of
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
          | rkPbkd2 r -> finish tmpls maxDerivedTotal
              "derived total exceeds the derive ceiling"
              (FxDerive mech (Just (osId ost)) info BS.empty)
              Nothing
          | otherwise -> case kdfShaWidth r of
              Just w -> finish tmpls w
                "derived total exceeds the digest width"
                (FxDerive mech (Just (osId ost)) BS.empty BS.empty)
                Nothing
              Nothing -> KeyDenied (KeyDeny CKR_GENERAL_ERROR
                "KDF row without a digest width")
  | otherwise =
      KeyDenied (KeyDeny CKR_MECHANISM_INVALID
        ("not a derive mechanism: " ++ show mech))
  where
    finish tmpls ceilingN ceilingMsg fx defLen =
      case checkAll defLen tmpls of
        Left deny -> KeyDenied deny
        Right keyed
          | null keyed -> KeyDenied (KeyDeny CKR_ARGUMENTS_BAD
              "derive needs at least one template")
          | sum (map snd keyed) > ceilingN ->
              KeyDenied (KeyDeny CKR_ARGUMENTS_BAD ceilingMsg)
          | Left deny <- admitObjects rules (Map.size (mObjects model))
              (length keyed) ->
              KeyDenied (KeyDeny (admitCode deny)
                ("admission denied: " ++ show deny))
          | otherwise ->
              let (pos, lens) = unzip
                    [(pendingFromAttrs st attrs, n) | (attrs, n) <- keyed]
              in KeyEffect (PwDerive pos lens) (fx (sum lens))
    checkAll
      :: Maybe Int -> [[(AttributeType, AttributeValue)]]
      -> Either KeyDeny [(Map.Map AttributeType AttributeValue, Int)]
    checkAll defLen = mapM (checkOne defLen)
    checkOne
      :: Maybe Int -> [(AttributeType, AttributeValue)]
      -> Either KeyDeny (Map.Map AttributeType AttributeValue, Int)
    checkOne defLen tmpl = case checkKeyTemplateAny ckoSecretKey ckkGenericSecret tmpl of
      Left deny -> Left deny
      Right attrs -> case Map.lookup AttrValueLen attrs of
        Just (ValULong n)
          | n < 1 -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
              "derived length must be positive")
          | n > fromIntegral (maxBound :: Int) -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
              "derived length exceeds the platform range")
          | otherwise -> Right (attrs, fromIntegral n)
        Just _ -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
          "derived length is malformed")
        -- Constructions with a natural output width (ECDH: the
        -- agreement secret) default a missing length to that width
        -- (PKCS#11 v3.2 ECDH: "if it has one ... CKA_VALUE_LEN");
        -- the default is stamped so readback matches an explicit
        -- template. Open-ended constructions (HKDF-Expand, PBKDF2)
        -- and SHA-KDF over generic secrets keep INCOMPLETE (v3.2
        -- SHA-KDF: generic secrets have no well-defined length).
        Nothing -> case defLen of
          Just n -> Right
            ( Map.insert AttrValueLen (ValULong (fromIntegral n)) attrs
            , n
            )
          Nothing -> Left (KeyDeny CKR_TEMPLATE_INCOMPLETE
            "derived template needs CKA_VALUE_LEN")

-- | Resolve the base key: known handle, session-visible, derive
-- mark set, stored material present. Shared by the HKDF and ECDH
-- constructions (identical denials, one implementation).
resolveBase
  :: Model -> SessionState -> ExternalHandle
  -> Either KeyDeny (ObjectState, ByteString)
resolveBase model st baseH = case resolveHandle model baseH of
  Nothing -> Left (KeyDeny CKR_KEY_HANDLE_INVALID
    "unknown or destroyed base-key handle")
  Just ost
    | not (objectVisible st ost) -> Left (KeyDeny CKR_KEY_HANDLE_INVALID
        "base key not visible in this session")
    | Map.lookup AttrDerive (osAttrs ost) /= Just (ValBool True) ->
        Left (KeyDeny CKR_KEY_FUNCTION_NOT_PERMITTED
          "base key does not permit derivation")
    | otherwise -> case keyBytesOf ost of
        Nothing -> Left (KeyDeny CKR_GENERAL_ERROR
          "base key lacks material")
        Just mat -> Right (ost, mat)

-- | Base/peer curve agreement: a mismatch denies only when BOTH
-- sides scan as DER EC keys on different curves. Unscannable sides
-- (synthetic opaque bytes) pass — the backends enforce key shape.
curvesDiffer :: ByteString -> ByteString -> Bool
curvesDiffer base peer = case (ecdsaCurveOfDer base, ecdsaCurveOfDer peer) of
  (Just a, Just b) -> a /= b
  _ -> False
