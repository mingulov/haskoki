{- | Haskoki.Engine.Synthetic.Codecs: digest-context codecs.
-}
module Haskoki.Engine.Synthetic.Codecs
  ( encodeDigestCtx
  , decodeDigestCtx
  , digestAlgByte
  , digestAlgFromByte
  ) where


import Control.Monad (guard)
import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import Data.Word (Word8)

import Haskoki.Engine.Backend
  ( DigestAlg (..)
  )
import Haskoki.Engine.Synthetic.Framing


-- | Digest snapshot layout: @0x02 || algByte(1) || accLen BE(4) || acc@.
-- Key snapshots are @0x01@-versioned; the leading byte keeps the
-- two registries' encodings disjoint. @algByte 1@ is SHA-256 forever
-- (legacy snapshots restore); the recipe table assigns the rest (see
-- 'digestAlgByte' — the mapping is append-only and pinned by
-- SyntheticSpec).
encodeDigestCtx :: DigestAlg -> ByteString -> ByteString
encodeDigestCtx alg acc =
  BS.singleton 2 <> BS.singleton (digestAlgByte alg)
    <> word32BE (BS.length acc) <> acc

-- | Strict parse: version skew, unknown algorithm, truncation, or any
-- trailing byte rejects.
decodeDigestCtx :: ByteString -> Maybe (DigestAlg, ByteString)
decodeDigestCtx bs = case BS.uncons bs of
  Just (2, r1) -> case BS.uncons r1 of
    Just (b, r2) -> do
      alg <- digestAlgFromByte b
      let (lenBs, r3) = BS.splitAt 4 r2
      guard (BS.length lenBs == 4)
      let n = getWord32BE lenBs
          (acc, rest) = BS.splitAt n r3
      guard (BS.length acc == n && BS.null rest)
      Just (alg, acc)
    _ -> Nothing
  _ -> Nothing

-- | Stable snapshot algorithm bytes. 1 is SHA-256 (legacy
-- compat); 2-15 assigned by the recipe table. Never reuse or reorder.
digestAlgByte :: DigestAlg -> Word8
digestAlgByte alg = case alg of
  D_SHA256 -> 1
  D_MD5 -> 2
  D_SHA1 -> 3
  D_SHA224 -> 4
  D_SHA384 -> 5
  D_SHA512 -> 6
  D_SHA512_224 -> 7
  D_SHA512_256 -> 8
  D_SHA3_224 -> 9
  D_SHA3_256 -> 10
  D_SHA3_384 -> 11
  D_SHA3_512 -> 12
  D_RIPEMD160 -> 13
  D_SHAKE128 -> 14
  D_SHAKE256 -> 15
  D_BLAKE2B512 -> 16
  D_BLAKE2B160 -> 17
  D_BLAKE2B256 -> 18
  D_BLAKE2B384 -> 19

digestAlgFromByte :: Word8 -> Maybe DigestAlg
digestAlgFromByte b = case b of
  1 -> Just D_SHA256
  2 -> Just D_MD5
  3 -> Just D_SHA1
  4 -> Just D_SHA224
  5 -> Just D_SHA384
  6 -> Just D_SHA512
  7 -> Just D_SHA512_224
  8 -> Just D_SHA512_256
  9 -> Just D_SHA3_224
  10 -> Just D_SHA3_256
  11 -> Just D_SHA3_384
  12 -> Just D_SHA3_512
  13 -> Just D_RIPEMD160
  14 -> Just D_SHAKE128
  15 -> Just D_SHAKE256
  16 -> Just D_BLAKE2B512
  17 -> Just D_BLAKE2B160
  18 -> Just D_BLAKE2B256
  19 -> Just D_BLAKE2B384
  _ -> Nothing
