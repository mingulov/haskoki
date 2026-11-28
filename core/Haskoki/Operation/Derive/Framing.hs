{- | Haskoki.Operation.Derive.Framing: derive mechanism ids, ceilings, and the derive-arguments / HKDF-info frames with their length helpers.
-}
module Haskoki.Operation.Derive.Framing
  ( hkdfDeriveMech
  , pubPrivMech
  , hkdfDataMech
  , maxXofTotal
  , maxDerivedTotal
  , maxDeriveKeys
  , maxDeriveInfo
  , encodeDeriveParams
  , decodeDeriveParams
  , encodeHkdfInfo
  , decodeHkdfInfo
  , prfHashLen
  , sp800HashLen
  , sp800LengthFits
  ) where


import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import Data.Word (Word8)

import Haskoki.Attribute (AttributeType (..), AttributeValue (..))
import Haskoki.Bytes (u16be, u32be)
import Haskoki.Object (encodeTemplate, parseTemplate)
import Haskoki.Recipe.Kdf
  ( kdfCodeDigest
  , kdfDigestWidth
  )
import Haskoki.Recipe.Sp800108
  ( Sp800Mode (..)
  )
import Haskoki.Registry (MechanismId (..))
import Haskoki.Registry.Generated (ckm_HKDF_DATA, ckm_HKDF_DERIVE, ckm_PUB_KEY_FROM_PRIV_KEY)

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
