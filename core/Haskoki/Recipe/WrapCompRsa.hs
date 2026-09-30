{- | The wrap-composition RSA recipe: the single header mechanism
@CKM_RSA_AES_KEY_WRAP@ (0x1054) and its canonical parameters.

The construction (OASIS PKCS#11 v3.2 §2: RSA-AES key wrap): the
caller names an AES strength plus an OAEP frame; wrap mints a
random temp KEK at that strength, RSA-OAEP-seals it under the
recipient PUBLIC key, KWP-seals the target under the KEK, and
answers the modulus-wide OAEP head plus the KWP tail. Unwrap
splits the head, OAEP-opens the KEK with the PRIVATE key, and
KWP-opens the tail.

The canonical @wrapcomp-rsa-params\/1@ image is
@digest:u64be mgf:u64be labelLen:u64be label aesBits:u64be@
(the OAEP digest codes shared with @oaep-params\/1@). Served
AES strengths are 128\/192\/256; labels ride to the backend
exactly like the @CKM_RSA_PKCS_OAEP@ row. The KEK-fit bound is
the OAEP input bound over the main hash width
(mLen <= k - 2*hLen - 2).
-}
{-# LANGUAGE OverloadedStrings #-}
module Haskoki.Recipe.WrapCompRsa
  ( WrapCompRsaRecipe (..)
  , wrapCompRsaRecipes
  , wrapCompRsaRecipeFor
  , wrapCompRsaCodec
  , wrapCompRsaCodecFor
  , encodeWrapCompRsaParams
  , decodeWrapCompRsaParams
  , wrapCompRsaParamsValid
  , wrapCompRsaAesBitsSet
  , wrapCompRsaAesBytes
  , wrapCompRsaOaep
  , wrapCompRsaKeyOk
  , wrapCompRsaKekFits
  , wrapCompRsaSplitBlob
  , wrapCompRsaModulusBytes
  , wrapCompRsaFrameHead
  , wrapCompRsaUnframeHead
  ) where

import Data.Bits (shiftL, shiftR, (.&.))
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Text (Text)
import Data.Word (Word64, Word8)

import Haskoki.Attribute.Generated (mustKeyTypeId)
import Haskoki.Der (RsaCrt (..), parseRsaPrivate, parseRsaPublic)
import Haskoki.Recipe.RsaOaep (oaepCodeDigest, oaepDigestCode, oaepDigestWidth)
import Haskoki.Registry.Generated (mustGeneratedId)
import Haskoki.Registry.Types (MechanismId (..), MechanismName, ParameterCodec (..))

-- | The single RSA composition recipe row.
data WrapCompRsaRecipe = WrapCompRsaRecipe
  { wcrName :: !MechanismName
  } deriving (Eq, Show)

-- | The recipe table (one row).
wrapCompRsaRecipes :: [WrapCompRsaRecipe]
wrapCompRsaRecipes = [WrapCompRsaRecipe "CKM_RSA_AES_KEY_WRAP"]

-- | The row for a mechanism id ('Nothing' off-row).
wrapCompRsaRecipeFor :: MechanismId -> Maybe WrapCompRsaRecipe
wrapCompRsaRecipeFor (MechanismId m)
  | m == mustGeneratedId "CKM_RSA_AES_KEY_WRAP" =
      Just (WrapCompRsaRecipe "CKM_RSA_AES_KEY_WRAP")
  | otherwise = Nothing

-- | The group's canonical parameter codec.
wrapCompRsaCodec :: ParameterCodec
wrapCompRsaCodec = ParameterCodec "wrapcomp-rsa-params" 1

-- | The codec for one recipe row (uniform across the group).
wrapCompRsaCodecFor :: WrapCompRsaRecipe -> ParameterCodec
wrapCompRsaCodecFor _ = wrapCompRsaCodec

-- | Encode one 8-byte big-endian word.
encodeWord64 :: Int -> ByteString
encodeWord64 n = BS.pack [byte s | s <- [56, 48 .. 0]]
  where
    byte :: Int -> Word8
    byte s = fromIntegral ((n `shiftR` s) .&. 0xff)

-- | Decode one 8-byte big-endian word.
decodeWord64 :: ByteString -> Maybe Int
decodeWord64 bs
  | BS.length bs /= 8 = Nothing
  | otherwise = Just (BS.foldl' (\a b -> a `shiftL` 8 + fromIntegral b) 0 bs)

-- | Encode wrap-composition RSA parameters (total; unknown
-- stems encode as code 0, which never validates).
encodeWrapCompRsaParams :: Text -> Text -> ByteString -> Int -> ByteString
encodeWrapCompRsaParams digest mgf label aesBits =
  encodeWord64 (code digest)
    <> encodeWord64 (code mgf)
    <> encodeWord64 (BS.length label) <> label
    <> encodeWord64 aesBits
  where
    code stem = case oaepDigestCode stem of
      Just c -> c
      Nothing -> 0

-- | Strict decode: table codes only, the label length must land
-- exactly, no trailing bytes.
decodeWrapCompRsaParams :: ByteString -> Maybe (Text, Text, ByteString, Int)
decodeWrapCompRsaParams bs = do
  let (w0, r0) = BS.splitAt 8 bs
      (w1, r1) = BS.splitAt 8 r0
      (w2, r2) = BS.splitAt 8 r1
  c1 <- decodeWord64 w0
  c2 <- decodeWord64 w1
  sLen <- decodeWord64 w2
  d <- oaepCodeDigest c1
  m <- oaepCodeDigest c2
  let (label, r3) = BS.splitAt sLen r2
  if BS.length label /= sLen
    then Nothing
    else do
      let (w4, rest) = BS.splitAt 8 r3
      aesBits <- decodeWord64 w4
      if BS.null rest
        then pure (d, m, label, aesBits)
        else Nothing

-- | Served AES strengths in bits.
wrapCompRsaAesBitsSet :: [Int]
wrapCompRsaAesBitsSet = [128, 192, 256]

-- | Parameter validation: strict decoding with a served AES
-- strength. Labels are served (they ride the OAEP frame).
wrapCompRsaParamsValid :: WrapCompRsaRecipe -> ByteString -> Bool
wrapCompRsaParamsValid _ params = case decodeWrapCompRsaParams params of
  Just (_, _, _, bits) -> bits `elem` wrapCompRsaAesBitsSet
  _ -> False

-- | The KEK length in bytes for validated parameters ('Nothing'
-- for anything the recipe refuses).
wrapCompRsaAesBytes :: ByteString -> Maybe Int
wrapCompRsaAesBytes params = case decodeWrapCompRsaParams params of
  Just (_, _, _, bits)
    | bits `elem` wrapCompRsaAesBitsSet -> Just (bits `div` 8)
  _ -> Nothing

-- | The OAEP frame for validated parameters (digest stem, MGF
-- stem, label).
wrapCompRsaOaep :: ByteString -> Maybe (Text, Text, ByteString)
wrapCompRsaOaep params = case decodeWrapCompRsaParams params of
  Just (d, m, label, bits)
    | bits `elem` wrapCompRsaAesBitsSet -> Just (d, m, label)
  _ -> Nothing

-- | The row's wrapping-key type gate over a numeric @CKK_*@ id:
-- RSA only.
wrapCompRsaKeyOk :: WrapCompRsaRecipe -> Word64 -> Bool
wrapCompRsaKeyOk _ kty = kty == mustKeyTypeId "CKK_RSA"

-- | The KEK-fit bound: the KEK (bytes) fits the modulus (bytes)
-- under the OAEP input bound over the main hash width
-- (mLen <= k - 2*hLen - 2).
wrapCompRsaKekFits :: Int -> Text -> Int -> Bool
wrapCompRsaKekFits k digest aesBytes = case oaepDigestWidth digest of
  Just h -> aesBytes <= k - 2 * h - 2
  Nothing -> False

-- | Split one wrapped blob into (OAEP head, KWP blob): the
-- modulus-wide head plus a KWP-shaped tail (a multiple of 8,
-- at least 16). Short blobs and ragged tails answer 'Nothing'.
wrapCompRsaSplitBlob :: Int -> ByteString -> Maybe (ByteString, ByteString)
wrapCompRsaSplitBlob k blob
  | BS.length blob >= k + 16
  , let rest = BS.drop k blob
  , BS.length rest >= 16
  , BS.length rest `mod` 8 == 0 =
      Just (BS.splitAt k blob)
  | otherwise = Nothing

-- | Scan the modulus width in bytes from RSA key material: the
-- SPKI modulus, else the PKCS#8 CRT modulus, else 'Nothing'
-- (opaque halves carry no modulus — the planner falls back to
-- the @CKA_MODULUS@ attribute there).
wrapCompRsaModulusBytes :: ByteString -> Maybe Int
wrapCompRsaModulusBytes mat = case parseRsaPublic mat of
  Just (n, _) -> Just (BS.length n)
  Nothing -> case parseRsaPrivate mat of
    Just crt -> Just (BS.length (crtN crt))
    Nothing -> Nothing

-- | Frame one OAEP seal as the modulus-wide head: exact-k
-- seals pass through (the real backend); seals at exactly the
-- expected seal width zero-pad to k (the tag-sized synthetic
-- backend — the structural agreement with the driver, like the
-- ECDH opaque transport length); anything else refuses (an
-- over-wide or wrong-short seal would strip to a wrong head).
wrapCompRsaFrameHead :: Int -> Int -> ByteString -> Maybe ByteString
wrapCompRsaFrameHead k sealLen raw
  | BS.length raw == k = Just raw
  | BS.length raw == sealLen && sealLen < k =
      Just (raw <> BS.replicate (k - sealLen) 0)
  | otherwise = Nothing

-- | Recover the inner seal from a modulus-wide head: a k-wide
-- head whose trailing (k - sealLen) bytes are all zero strips
-- to the seal (the padded synthetic framing); anything else
-- passes through whole (real seals, whose random tails never
-- match the zero run — and a mismatch fails closed at the
-- OAEP tag check or the backend length gate, never silently).
wrapCompRsaUnframeHead :: Int -> Int -> ByteString -> ByteString
wrapCompRsaUnframeHead k sealLen blob
  | BS.length blob == k
  , sealLen < k
  , BS.all (== 0) (BS.drop sealLen blob) =
      BS.take sealLen blob
  | otherwise = blob
