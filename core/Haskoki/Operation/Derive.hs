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
import Data.Word (Word64, Word8)

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
  , ckoPrivateKey
  , ckoPublicKey
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
import Haskoki.Recipe.PubPriv
  ( pubPrivBaseKeyOk
  , pubPrivBaseMatOk
  , pubPrivMapAttrs
  , pubPrivParamsValid
  , pubPrivRecipeFor
  )
import Haskoki.Recipe.Sp800108
  ( Sp800Mode (..)
  , Sp800Params (..)
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
  , ikeBaseKeyOk
  , ikeParamsValid
  , ikeRecipeFor
  , maxIkeOutput
  )
import Haskoki.Recipe.ByteOps
  ( ByteOpsKind (..)
  , ByteOpsRecipe (..)
  , byteOpsBaseKeyOk
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
import Haskoki.Registry.Generated (ckm_HKDF_DATA, ckm_HKDF_DERIVE, ckm_PUB_KEY_FROM_PRIV_KEY)
import Haskoki.Rules (Rules)
import Haskoki.Session (admitCode, admitObjects)
import Haskoki.Types (ExternalHandle (..), ObjectId, ReturnCode (..))

-- | @CKM_HKDF_DERIVE@ (generated id, resolved by name).
hkdfDeriveMech :: MechanismId
hkdfDeriveMech = MechanismId (ckm_HKDF_DERIVE)

-- | @CKM_PUB_KEY_FROM_PRIV_KEY@ (generated id, resolved by
-- name): the single derive row that ignores CKA_DERIVE and
-- yields a public key object.
pubPrivMech :: MechanismId
pubPrivMech = MechanismId (ckm_PUB_KEY_FROM_PRIV_KEY)

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

-- | SP 800-108 hash length for a frame PRF code (the
-- 'kdfCodeDigest' space onto 'kdfDigestWidth').
sp800HashLen :: Word8 -> Maybe Int
sp800HashLen code = do
  stem <- kdfCodeDigest (fromIntegral code)
  kdfDigestWidth stem

-- | SP 800-108 width pre-check: the planned total's bit-length
-- must fit the DKM-length width, and counter mode must fit its
-- iterations in @2^r - 1@ (never wraps). Only well-formed
-- lengths contribute; malformed or missing lengths fall
-- through to 'finish', which reports them with the precise
-- code.
sp800LengthFits :: Sp800Mode -> Int -> Int -> Int -> [[(AttributeType, AttributeValue)]] -> Bool
sp800LengthFits mode lBits rBits hashLen tmpls =
  let total = sum [fromIntegral m | t <- tmpls, (AttrValueLen, ValULong m) <- t] :: Integer
      n = (total + toInteger hashLen - 1) `div` toInteger hashLen
  in total * 8 < 2 ^ lBits
    && (mode /= Sp800Counter || n <= 2 ^ rBits - 1)

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
              Just hashLen -> case resolveBase model st baseH of
                Left deny -> KeyDenied deny
                Right (ost, _) -> finish tmpls (255 * hashLen)
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
              KeyDenied (KeyDeny CKR_TEMPLATE_INCONSISTENT
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
                    (FxDerive mech (Just (osId ost)) Nothing ecdhBlob BS.empty)
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
                (FxDerive mech (Just (osId ost)) Nothing dhBlob BS.empty)
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
              (FxDerive mech (Just (osId ost)) Nothing info BS.empty)
              Nothing
              CKR_ARGUMENTS_BAD
          | otherwise -> case kdfShaWidth r of
              Just w -> finish tmpls w
                "derived total exceeds the digest width"
                (FxDerive mech (Just (osId ost)) Nothing BS.empty BS.empty)
                (blakeDefaultLen r w)
                CKR_KEY_SIZE_RANGE
              -- SHAKE XOF rows: no fixed width — the output
              -- length rides the template lengths, capped by
              -- 'maxXofTotal'; a missing length stays
              -- INCOMPLETE (no natural width to default to).
              Nothing -> case kdfXofStem r of
                Just _ -> finish tmpls maxXofTotal
                  "derived total exceeds the XOF output ceiling"
                  (FxDerive mech (Just (osId ost)) Nothing BS.empty BS.empty)
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
              (FxDerive mech (Just (osId ost)) Nothing prfBlob BS.empty)
              Nothing
              CKR_ARGUMENTS_BAD
  | Just r <- tlsKdfRecipeFor mech = case decodeDeriveParams blob of
      Nothing -> KeyDenied (KeyDeny CKR_ARGUMENTS_BAD
        "malformed derive arguments")
      Just (kdfBlob, tmpls) -> case resolveBase model st baseH of
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
          | otherwise -> finish tmpls maxTlsKdfOutput
              "derived total exceeds the TLS-KDF ceiling"
              (FxDerive mech (Just (osId ost)) Nothing kdfBlob BS.empty)
              Nothing
              CKR_ARGUMENTS_BAD
  | Just r <- tlsKeyMatRecipeFor mech = case decodeDeriveParams blob of
      Nothing -> KeyDenied (KeyDeny CKR_ARGUMENTS_BAD
        "malformed derive arguments")
      Just (kmBlob, tmpls) -> case resolveBase model st baseH of
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
        Just (mBlob, tmpls) -> case resolveBase model st baseH of
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
            | otherwise -> finish tmpls 48
                "derived total exceeds the 48-byte SSL3 master width"
                (FxDerive mech (Just (osId ost)) Nothing mBlob BS.empty)
                Nothing
                CKR_ARGUMENTS_BAD
  | Just r <- ssl3RecipeFor mech
  , ssl3Kind r == Ssl3KeyMat = case decodeDeriveParams blob of
      Nothing -> KeyDenied (KeyDeny CKR_ARGUMENTS_BAD
        "malformed derive arguments")
      Just (kmBlob, tmpls) -> case resolveBase model st baseH of
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
      Just (ikeBlob, tmpls) -> case resolveBase model st baseH of
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
              Just (prf, _, _, auxN, _, _)
                -- The reserved code marks an unmapped PRF
                -- selector: the spec-exact denial (the oracle's
                -- invalid-PRF legs accept it).
                | prf == 0 -> KeyDenied (KeyDeny CKR_MECHANISM_PARAM_INVALID
                    "IKE PRF mechanism is not a served HMAC")
                | otherwise -> case resolveAuxKey ikeBaseOk "IKE" model st auxN of
                    Left deny -> KeyDenied deny
                    Right mAux -> case ikeCeiling (ikKind r) prf of
                      -- Unreachable post-validation (codes 1..13
                      -- map); typed, never a crash.
                      Nothing -> KeyDenied (KeyDeny CKR_GENERAL_ERROR
                        "IKE PRF code without a digest width")
                      Just ceilingN -> finish tmpls ceilingN
                        "derived total exceeds the IKE ceiling"
                        (FxDerive mech (Just (osId ost)) mAux ikeBlob BS.empty)
                        Nothing
                        CKR_ARGUMENTS_BAD
  | Just r <- byteOpsRecipeFor mech = case decodeDeriveParams blob of
      Nothing -> KeyDenied (KeyDeny CKR_ARGUMENTS_BAD
        "malformed derive arguments")
      Just (boBlob, tmpls) -> case resolveBase model st baseH of
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
                case resolveAuxKey byteOpsBaseOkState "byte-op" model st auxN of
                  Left deny -> KeyDenied deny
                  Right mAux -> byteOpsFinish r mat mAux offN payBlob
                    mech ost boBlob tmpls
  | Just r <- sp800RecipeFor mech = case decodeDeriveParams blob of
      Nothing -> KeyDenied (KeyDeny CKR_ARGUMENTS_BAD
        "malformed derive arguments")
      Just (spBlob, tmpls) -> case resolveBase model st baseH of
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
                      (spCounterBits p) h tmpls -> finish tmpls maxSp800Total
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
                (FxDerive mech (Just (osId ost)) Nothing edBlob BS.empty)
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
    -- ceiling code); an XOR length mismatch refuses
    -- @CKR_DATA_LEN_RANGE@; an EXTRACT overrun refuses
    -- @CKR_ARGUMENTS_BAD@.
    byteOpsFinish r mat mAux offN payBlob dMech ost boBlob tmpls =
      case boKind r of
        ConcatBaseAndKey -> case mAux of
          -- Unreachable: validation forces a nonzero aux
          -- handle, which resolves or denies above.
          Nothing -> KeyDenied (KeyDeny CKR_GENERAL_ERROR
            "concat-key aux vanished after resolution")
          Just auxOid -> case Map.lookup auxOid (mObjects model) >>= keyBytesOf of
            -- Unreachable: the aux carried material at
            -- resolution.
            Nothing -> KeyDenied (KeyDeny CKR_GENERAL_ERROR
              "concat-key aux lost its material")
            Just auxMat -> natural (BS.length mat + BS.length auxMat)
        ConcatBaseAndData -> natural (BS.length mat + BS.length payBlob)
        ConcatDataAndBase -> natural (BS.length payBlob + BS.length mat)
        XorBaseAndData
          | BS.length mat /= BS.length payBlob -> KeyDenied (KeyDeny CKR_DATA_LEN_RANGE
              "XOR data length differs from the base length")
          | otherwise -> natural (BS.length mat)
        ExtractKeyFromKey ->
          let baseBits = toInteger (BS.length mat) * 8
              remaining = (baseBits - toInteger offN) `div` 8
              -- The whole-byte window at the offset, capped by
              -- the byte-ops ceiling; a past-the-end offset
              -- leaves no window, so every positive request
              -- overruns.
              window = max 0 (min (toInteger maxByteOpsOutput) remaining)
          in finish tmpls (fromInteger window)
            "EXTRACT window exceeds the base key"
            (FxDerive dMech (Just (osId ost)) mAux boBlob BS.empty)
            Nothing
            CKR_ARGUMENTS_BAD
      where
        fx = FxDerive dMech (Just (osId ost)) mAux boBlob BS.empty
        natural n
          | n < 1 = KeyDenied (KeyDeny CKR_KEY_SIZE_RANGE
              "byte-op natural output is empty")
          | n > maxByteOpsOutput = KeyDenied (KeyDeny CKR_ARGUMENTS_BAD
              "byte-op natural output exceeds the ceiling")
          | otherwise = finish tmpls n
              "derived total exceeds the byte-op natural width"
              fx (Just n)
              CKR_KEY_SIZE_RANGE
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
          [ ( Map.insert AttrValueLen (ValULong (fromIntegral n))
                (Map.insert AttrKeyType (ValULong (outType role)) attrs)
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
          [ ( Map.insert AttrValueLen (ValULong (fromIntegral n))
                (Map.insert AttrKeyType (ValULong (outType role)) attrs)
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
        baseBool at b = case Map.lookup at b of
          Just (ValBool x) -> x
          _ -> False
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
-- held to the same visibility, type, permission, and
-- material rules as the base key; the type check and its
-- label ride per family (IKE: generic or HMAC; byte-ops:
-- generic only).
resolveAuxKey
  :: (ObjectState -> Bool) -> String
  -> Model -> SessionState -> Word64
  -> Either KeyDeny (Maybe ObjectId)
resolveAuxKey _ _ _ _ 0 = Right Nothing
resolveAuxKey typeOk label model st auxN =
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
  Ike2PrfPlus -> Just maxIkeOutput
  Ike1Extended -> Just maxIkeOutput
  IkePrf -> digestWidth
  Ike1Prf -> digestWidth
  where
    digestWidth = do
      stem <- kdfCodeDigest (fromIntegral prf)
      kdfDigestWidth stem

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
