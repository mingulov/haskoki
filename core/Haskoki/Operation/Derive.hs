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
import Data.Word (Word8)

import Haskoki.Attribute (AttributeType (..), AttributeValue (..))
import Haskoki.Model (Model (..), ObjectState (..), SessionState)
import Haskoki.Object (encodeTemplate, objectVisible, parseTemplate, resolveHandle)
import Haskoki.Operation.Effect (CryptoEffect (..))
import Haskoki.Operation.KeyManagement
  ( KeyDeny (..)
  , KeyPlan (..)
  , PendingWork (..)
  , checkDataTemplate
  , checkKeyTemplateAny
  , ckkEc
  , ckkEcMontgomery
  , ckkGenericSecret
  , ckoData
  , ckoSecretKey
  , keyBytesOf
  , pendingFromAttrs
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
  , xdhSecretWidth
  )
import Haskoki.Recipe.Ecdsa (ecdsaCurveOfDer)
import Haskoki.Recipe.Kdf
  ( KdfRecipe (..)
  , kdfCodeDigest
  , kdfDigestWidth
  , kdfParamsValid
  , kdfRecipeFor
  , kdfShaWidth
  , kdfXofStem
  )
import Haskoki.Recipe.TlsPrf
  ( maxTlsPrfOutput
  , tlsPrfParamsValid
  , tlsPrfRecipeFor
  )
import Haskoki.Registry (MechanismId (..))
import Haskoki.Registry.Generated (ckm_HKDF_DATA, ckm_HKDF_DERIVE)
import Haskoki.Rules (Rules)
import Haskoki.Session (admitCode, admitObjects)
import Haskoki.Types (ExternalHandle, ReturnCode (..))

-- | @CKM_HKDF_DERIVE@ (generated id, resolved by name).
hkdfDeriveMech :: MechanismId
hkdfDeriveMech = MechanismId (ckm_HKDF_DERIVE)

-- | @CKM_HKDF_DATA@ (generated id, resolved by name): the same KDF
-- as 'hkdfDeriveMech' with raw-byte output into @CKO_DATA@
-- objects (any derive-marked base; key-class templates deny).
hkdfDataMech :: MechanismId
hkdfDataMech = MechanismId (ckm_HKDF_DATA)

-- | SHAKE XOF output ceiling in bytes: 64 KiB bounds the largest
-- sane derived object while template lengths below it pass through.
maxXofTotal :: Int
maxXofTotal = 65536

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

-- | HKDF info segment: @prf:u8 mode:u8 saltLen:u16be salt
-- context@. The PRF is an engine-local digest code
-- ('kdfCodeDigest'); mode bit 0 selects extract, bit 1 selects
-- expand; decoding fails closed on an unknown PRF, an empty
-- stage set, and on reserved bits.
encodeHkdfInfo :: Word8 -> Word8 -> ByteString -> ByteString -> ByteString
encodeHkdfInfo prf mode salt info =
  BS.singleton prf <> BS.singleton mode
    <> u16be (BS.length salt) <> salt <> info
  where
    u16be n = BS.pack
      [ fromIntegral (n `div` 256 `mod` 256)
      , fromIntegral (n `mod` 256)
      ]

-- | Parse an HKDF info segment. An unknown PRF, truncation, an
-- overrun salt length, a missing stage and reserved mode bits
-- all fail.
decodeHkdfInfo :: ByteString -> Maybe (Word8, Word8, ByteString, ByteString)
decodeHkdfInfo bs = do
  (prfBs, r0) <- takeN 1 bs
  (modeBs, r1) <- takeN 1 r0
  (lenBs, r2) <- takeN 2 r1
  let prf = BS.head prfBs
      mode = BS.head modeBs
      saltN = BS.foldl' (\acc x -> acc * 256 + fromIntegral x) 0 lenBs
  case kdfCodeDigest (fromIntegral prf) of
    Nothing -> Nothing
    Just _ ->
      if mode /= 0x01 && mode /= 0x02 && mode /= 0x03
        then Nothing
        else takeN saltN r2 >>= \(salt, ctx) -> Just (prf, mode, salt, ctx)
  where
    takeN :: Int -> ByteString -> Maybe (ByteString, ByteString)
    takeN n b
      | BS.length b < n = Nothing
      | otherwise = Just (BS.splitAt n b)

-- | PRF code onto its hash length: the decode-validated code
-- resolves through 'kdfCodeDigest' and the width through
-- 'kdfDigestWidth' (the two tables share their domain, so this
-- is total on decoded frames; 'Nothing' is defense in depth).
prfHashLen :: Word8 -> Maybe Int
prfHashLen prf =
  kdfCodeDigest (fromIntegral prf) >>= kdfDigestWidth

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
              Just hashLen -> case resolveBase model st baseH of
                Left deny -> KeyDenied deny
                Right (ost, _) -> finishData tmpls (255 * hashLen)
                  "derived total exceeds the HKDF-Expand ceiling"
                  (FxDerive mech (Just (osId ost))
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
              Just hashLen -> case resolveBase model st baseH of
                Left deny -> KeyDenied deny
                Right (ost, _) -> finish tmpls (255 * hashLen)
                  "derived total exceeds the HKDF-Expand ceiling"
                  (FxDerive mech (Just (osId ost))
                    (BS.singleton prf <> BS.singleton mode <> salt) info)
                  -- A missing length defaults to the PRF hash
                  -- length: the mechanism doc says VALUE_LEN "should
                  -- be set" (non-mandatory), like the ECDH default.
                  (Just hashLen)
                  CKR_ARGUMENTS_BAD
  | Just r <- ecdhRecipeFor mech = case decodeDeriveParams blob of
      Nothing -> KeyDenied (KeyDeny CKR_ARGUMENTS_BAD
        "malformed derive arguments")
      -- Key-type contradiction outranks parameter shape (the
      -- Init-matrix ordering): the base resolves and must be EC
      -- before params are examined.
      Just (ecdhBlob, tmpls) -> case resolveBase model st baseH of
        Left deny -> KeyDenied deny
        Right (ost, mat)
          | Map.lookup AttrKeyType (osAttrs ost) /= Just (ValULong ckkEc)
          , Map.lookup AttrKeyType (osAttrs ost) /= Just (ValULong ckkEcMontgomery) ->
              KeyDenied (KeyDeny CKR_KEY_TYPE_INCONSISTENT
                "ECDH base key is not an EC or Montgomery key")
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
                | otherwise -> finish tmpls (ecdhSecretWidth mat)
                    "derived total exceeds the ECDH secret width"
                    (FxDerive mech (Just (osId ost)) ecdhBlob BS.empty)
                    (Just (ecdhSecretWidth mat))
                    CKR_ARGUMENTS_BAD
              _ -> KeyDenied (KeyDeny CKR_MECHANISM_PARAM_INVALID
                "ECDH mechanism parameters rejected by the recipe")
  | Just r <- dhRecipeFor mech = case decodeDeriveParams blob of
      Nothing -> KeyDenied (KeyDeny CKR_ARGUMENTS_BAD
        "malformed derive arguments")
      -- Same ordering as ECDH: the base resolves and must carry
      -- the row's key type (CKK_DH vs CKK_X9_42_DH) before params
      -- are examined. The peer is bare bytes (no domain framing
      -- to compare), so range membership is enforced by the
      -- executing backend, which owns the prime.
      Just (dhBlob, tmpls) -> case resolveBase model st baseH of
        Left deny -> KeyDenied deny
        Right (ost, mat)
          | Map.lookup AttrKeyType (osAttrs ost) /= Just (ValULong (dhKeyType r)) ->
              KeyDenied (KeyDeny CKR_KEY_TYPE_INCONSISTENT
                "DH base key type mismatch for the mechanism row")
          | not (dhParamsValid r dhBlob) -> KeyDenied (KeyDeny CKR_MECHANISM_PARAM_INVALID
              "DH mechanism parameters rejected by the recipe")
          | otherwise -> case decodeDhParams dhBlob of
              Just _ -> finish tmpls (dhSecretWidth mat)
                "derived total exceeds the DH secret width"
                (FxDerive mech (Just (osId ost)) dhBlob BS.empty)
                (Just (dhSecretWidth mat))
                CKR_ARGUMENTS_BAD
              _ -> KeyDenied (KeyDeny CKR_MECHANISM_PARAM_INVALID
                "DH mechanism parameters rejected by the recipe")
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
              CKR_ARGUMENTS_BAD
          | otherwise -> case kdfShaWidth r of
              Just w -> finish tmpls w
                "derived total exceeds the digest width"
                (FxDerive mech (Just (osId ost)) BS.empty BS.empty)
                (blakeDefaultLen r w)
                CKR_KEY_SIZE_RANGE
              -- SHAKE XOF rows: no fixed width — the output
              -- length rides the template lengths, capped by
              -- 'maxXofTotal'; a missing length stays
              -- INCOMPLETE (no natural width to default to).
              Nothing -> case kdfXofStem r of
                Just _ -> finish tmpls maxXofTotal
                  "derived total exceeds the XOF output ceiling"
                  (FxDerive mech (Just (osId ost)) BS.empty BS.empty)
                  Nothing
                  CKR_KEY_SIZE_RANGE
                Nothing -> KeyDenied (KeyDeny CKR_GENERAL_ERROR
                  "KDF row without a digest width")
  | Just r <- tlsPrfRecipeFor mech = case decodeDeriveParams blob of
      Nothing -> KeyDenied (KeyDeny CKR_ARGUMENTS_BAD
        "malformed derive arguments")
      Just (prfBlob, tmpls) -> case resolveBase model st baseH of
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
          | otherwise -> finish tmpls maxTlsPrfOutput
              "derived total exceeds the TLS-PRF ceiling"
              (FxDerive mech (Just (osId ost)) prfBlob BS.empty)
              Nothing
              CKR_ARGUMENTS_BAD
  | Just r <- encryptDataRecipeFor mech = case decodeDeriveParams blob of
      Nothing -> KeyDenied (KeyDeny CKR_ARGUMENTS_BAD
        "malformed derive arguments")
      -- Same ordering as ECDH: the base resolves and must carry
      -- the row's cipher key type before params are examined.
      Just (edBlob, tmpls) -> case resolveBase model st baseH of
        Left deny -> KeyDenied deny
        Right (ost, _)
          | Map.lookup AttrKeyType (osAttrs ost)
              /= Just (ValULong (mustKeyTypeId (erKeyType r))) ->
              KeyDenied (KeyDeny CKR_KEY_TYPE_INCONSISTENT
                "encrypt-data base key type mismatch for the mechanism row")
          | not (encryptDataParamsValid r edBlob) -> KeyDenied (KeyDeny CKR_MECHANISM_PARAM_INVALID
              "encrypt-data mechanism parameters rejected by the recipe")
          | otherwise -> case encryptDataOutputLen r edBlob of
              Just w -> finish tmpls w
                "derived total exceeds the encrypted data width"
                (FxDerive mech (Just (osId ost)) edBlob BS.empty)
                (Just w)
                CKR_KEY_SIZE_RANGE
              Nothing -> KeyDenied (KeyDeny CKR_GENERAL_ERROR
                "encrypt-data frame without an output width")
  | otherwise =
      KeyDenied (KeyDeny CKR_MECHANISM_INVALID
        ("not a derive mechanism: " ++ show mech))
  where
    finish tmpls ceilingN ceilingMsg fx defLen ceilingCode =
      case checkAll defLen tmpls of
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
    checkAll
      :: Maybe Int -> [[(AttributeType, AttributeValue)]]
      -> Either KeyDeny [(Map.Map AttributeType AttributeValue, Int)]
    checkAll defLen = mapM (checkOne defLen)
    -- | BLAKE2B-KDF rows default a missing length to the digest
    -- width (the lane's default-template legs derive full-width
    -- generic secrets); SHA rows keep INCOMPLETE (v3.2 SHA-KDF:
    -- generic secrets have no well-defined length).
    blakeDefaultLen :: KdfRecipe -> Int -> Maybe Int
    blakeDefaultLen r w = case rkDigestStem r of
      Just s
        | s == "BLAKE2B_160" || s == "BLAKE2B_256"
        || s == "BLAKE2B_384" || s == "BLAKE2B_512" -> Just w
      _ -> Nothing
    -- | A derive template targets a generic secret when the key
    -- type is absent (the mechanism default) or explicitly generic.
    targetGeneric :: [(AttributeType, AttributeValue)] -> Bool
    targetGeneric t = case lookup AttrKeyType t of
      Nothing -> True
      Just (ValULong k) -> k == ckkGenericSecret
      Just _ -> False
    checkOne
      :: Maybe Int -> [(AttributeType, AttributeValue)]
      -> Either KeyDeny (Map.Map AttributeType AttributeValue, Int)
    checkOne defLen tmpl = case checkKeyTemplateAny ckoSecretKey ckkGenericSecret tmpl of
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
        -- Constructions with a natural output width (ECDH: the
        -- agreement secret; BLAKE2B-KDF: the digest width) default
        -- a missing length to that width (PKCS#11 v3.2 ECDH: "if
        -- it has one ... CKA_VALUE_LEN"); the default is stamped
        -- so readback matches an explicit template. The default
        -- covers generic-secret targets only (absent or generic
        -- key type): an explicit variable-length target (AES)
        -- without a length stays INCOMPLETE. Open-ended PBKDF2
        -- and SHA-KDF over generic secrets keep INCOMPLETE
        -- (v3.2 SHA-KDF: generic secrets have no well-defined
        -- length); HKDF defaults to the hash length (mechanism
        -- doc: VALUE_LEN "should be set").
        Nothing -> case defLen of
          Just n
            | targetGeneric tmpl -> Right
                ( Map.insert AttrValueLen (ValULong (fromIntegral n)) attrs
                , n
                )
            | otherwise -> Left (KeyDeny CKR_TEMPLATE_INCOMPLETE
                "variable-length target needs CKA_VALUE_LEN")
          Nothing -> Left (KeyDeny CKR_TEMPLATE_INCOMPLETE
            "derived template needs CKA_VALUE_LEN")
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
