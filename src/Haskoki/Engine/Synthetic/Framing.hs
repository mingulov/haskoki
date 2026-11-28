{- | Haskoki.Engine.Synthetic.Framing: shape contracts, deterministic FNV/splitmix core, versioned RNG streams and fixtures.
-}
{-# LANGUAGE OverloadedStrings #-}
module Haskoki.Engine.Synthetic.Framing
  ( synthDigestLength
  , synthDigestLengthFor
  , synthMacLength
  , synthSigLength
  , synthEcdhWidth
  , synthDhWidth
  , synthKeyContextVersion
  , fnv1a64
  , mix64
  , word64BE
  , word64LE
  , word32BE
  , getWord32BE
  , frame
  , prfBytes
  , encodeMech
  , Seed (..)
  , OpNumber (..)
  , RngStream (..)
  , deriveStream
  , nextBytes
  , streamKeyBytes
  , FixtureMaterial (..)
  , fixtureIdentity
  , fixturePairIdentity
  , fixtureKey
  , fixtureKeyPair
  , unword32BE
  ) where


import Data.Bits ((.|.), shiftL, shiftR, xor)
import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import Data.Text (Text)
import qualified Data.Text.Encoding as TE
import Data.Word (Word8, Word64)

import Haskoki.Engine.Backend
  ( DigestAlg (..)
  )
import Haskoki.Recipe.Dh (dhSecretWidthMax)
import Haskoki.Recipe.Ecdh (ecdhSecretWidthMax)
import Haskoki.Registry (MechanismId (..))


-- Shape contracts

-- | Synthetic digest output length (bytes): the SHA-256 width, kept
-- as the historical alias. Prefer 'synthDigestLengthFor'.
synthDigestLength :: Int
synthDigestLength = 32

-- | Synthetic digest output length per algorithm (bytes), matching
-- the real digest widths ('Haskoki.Recipe.Digest' pins the same
-- table; SyntheticSpec executes it).
synthDigestLengthFor :: DigestAlg -> Int
synthDigestLengthFor alg = case alg of
  D_MD5 -> 16
  D_SHA1 -> 20
  D_SHA224 -> 28
  D_SHA256 -> 32
  D_SHA384 -> 48
  D_SHA512 -> 64
  D_SHA512_224 -> 28
  D_SHA512_256 -> 32
  D_SHA3_224 -> 28
  D_SHA3_256 -> 32
  D_SHA3_384 -> 48
  D_SHA3_512 -> 64
  D_RIPEMD160 -> 20
  D_SHAKE128 -> 32
  D_SHAKE256 -> 64
  D_BLAKE2B512 -> 64
  D_BLAKE2B160 -> 20
  D_BLAKE2B256 -> 32
  D_BLAKE2B384 -> 48

-- | Synthetic MAC output length (bytes).
synthMacLength :: Int
synthMacLength = 32

-- | Synthetic signature output length (bytes).
synthSigLength :: Int
synthSigLength = 64

-- | Synthetic ECDH secret width (bytes): the maximum over the
-- covered curves (the recipe's 'ecdhSecretWidthMax'). Synthetic
-- keys are opaque bytes with no scannable curve, so agreements
-- always emit the max width and the driver truncates to the
-- planned length.
synthEcdhWidth :: Int
synthEcdhWidth = ecdhSecretWidthMax

-- | Synthetic DH secret width (bytes): the maximum served prime
-- width (the recipe's 'dhSecretWidthMax'). Synthetic keys are
-- opaque bytes with no scannable prime, so agreements always
-- emit the max width and the driver truncates to the planned
-- length.
synthDhWidth :: Int
synthDhWidth = dhSecretWidthMax

-- | Synthetic key-context format version (first context byte).
synthKeyContextVersion :: Word8
synthKeyContextVersion = 1

-- Deterministic core: FNV-1a accumulation, splitmix64 expansion

-- | FNV-1a 64-bit accumulation over domain-framed input.
fnv1a64 :: ByteString -> Word64
fnv1a64 = BS.foldl' step 14695981039346656037
  where
    step :: Word64 -> Word8 -> Word64
    step h b = (h `xor` fromIntegral b) * 1099511628211

-- | splitmix64 finalizer: good avalanche for nearby inputs.
mix64 :: Word64 -> Word64
mix64 z0 =
  let z1 = (z0 `xor` (z0 `shiftR` 30)) * 0xBF58476D1CE4E5B9
      z2 = (z1 `xor` (z1 `shiftR` 27)) * 0x94D049BB133111EB
  in z2 `xor` (z2 `shiftR` 31)

word64BE :: Word64 -> ByteString
word64BE w = BS.pack [byte s | s <- [56, 48 .. 0]]
  where byte s = fromIntegral (w `shiftR` s)

word64LE :: Word64 -> ByteString
word64LE w = BS.pack [byte s | s <- [0, 8 .. 56]]
  where byte s = fromIntegral (w `shiftR` s)

word32BE :: Int -> ByteString
word32BE n = BS.pack
  [ fromIntegral (n `shiftR` 24)
  , fromIntegral (n `shiftR` 16)
  , fromIntegral (n `shiftR` 8)
  , fromIntegral n
  ]

getWord32BE :: ByteString -> Int
getWord32BE = BS.foldl' (\a b -> a * 256 + fromIntegral b) 0

-- | Length-prefixed framing so concatenated domains stay unambiguous.
frame :: [ByteString] -> ByteString
frame = BS.concat . map (\p -> word32BE (BS.length p) <> p)

-- | Domain-separated expansion to exactly @n@ bytes.
prfBytes :: ByteString -> Int -> ByteString
prfBytes domain n
  | n <= 0 = BS.empty
  | otherwise =
      let seed = fnv1a64 domain
          need = (n + 7) `div` 8
      in BS.take n (BS.concat [word64LE (mix64 (seed + fromIntegral i)) | i <- [0 .. need - 1]])

encodeMech :: MechanismId -> ByteString
encodeMech (MechanismId w) = word64BE w

-- Versioned RNG streams

-- | Fixture seed.
newtype Seed = Seed { unSeed :: Word64 }
  deriving (Eq, Show)

-- | Logical operation number within a schedule. Backends derive
-- independent randomness streams from (seed, operation) so that
-- schedule order and thread interleaving do not move an operation's
-- results; only the same seed plus the same schedule replays.
-- (Moved here from the retired original record: it keys synthetic
-- RNG streams, nothing else.)
newtype OpNumber = OpNumber { unOpNumber :: Word64 }
  deriving (Eq, Ord, Show)

-- | Independent per-operation stream: @(seed, operation, counter)@.
data RngStream = RngStream
  { rsSeed :: !Word64
  , rsStream :: !Word64
  , rsCounter :: !Word64
  } deriving (Eq, Show)

-- | Derive the independent stream for one logical operation.
deriveStream :: Seed -> OpNumber -> RngStream
deriveStream (Seed s) (OpNumber n) = RngStream s n 0

-- | Draw exactly @n@ bytes, advancing the counter by words consumed.
nextBytes :: Int -> RngStream -> (ByteString, RngStream)
nextBytes n rs@(RngStream seed stream ctr)
  | n <= 0 = (BS.empty, rs)
  | otherwise =
      let base = seed + stream * 0x9E3779B97F4A7C15 + ctr
          need = (n + 7) `div` 8
          out = BS.take n (BS.concat
            [word64LE (mix64 (base + fromIntegral i)) | i <- [0 .. need - 1]])
      in (out, rs { rsCounter = ctr + fromIntegral need })

-- Seeded keygen streams

-- | Keygen bytes from the backend seed folded with the derivation
-- domain, drawn from the generation counter's independent stream, so
-- the same seed plus the same call sequence replays.
streamKeyBytes :: Word64 -> OpNumber -> ByteString -> Int -> ByteString
streamKeyBytes seed op extra n =
  fst (nextBytes n (deriveStream (Seed (seed `xor` fnv1a64 extra)) op))

-- Fixtures

-- | Deterministic fixture material: owned bytes, the 32-byte object
-- identity, and the shared pair identity for halves. Byte-identical
-- to the retired record's fixtures (same domains, new home).
data FixtureMaterial = FixtureMaterial
  { fmBytes :: !ByteString
  , fmIdentity :: !ByteString
  , fmPair :: !(Maybe ByteString)
  } deriving (Eq, Show)

-- | Object identity: the same @keyid/v1@ expansion the retired
-- record used, over owned bytes.
fixtureIdentity :: ByteString -> ByteString
fixtureIdentity mat =
  prfBytes (frame ["haskoki-synth/keyid/v1", mat]) 32

-- | Pair identity over two halves, as the retired record built it.
fixturePairIdentity :: ByteString -> ByteString -> ByteString
fixturePairIdentity pubBytes privBytes = fixtureIdentity
  (frame ["haskoki-synth/pair/v1", pubBytes, privBytes])

-- | Deterministic fixture key: same @(mechanism, seed, label) gives
-- the same material. Fixed 32-byte documented test shape.
fixtureKey :: MechanismId -> Seed -> Text -> FixtureMaterial
fixtureKey mech (Seed s) label =
  FixtureMaterial bytes (fixtureIdentity bytes) Nothing
  where
    bytes = prfBytes
      (frame ["haskoki-synth/fixture/v1", encodeMech mech, word64BE s, TE.encodeUtf8 label])
      32

-- | Deterministic fixture key pair sharing one pair identity.
fixtureKeyPair :: MechanismId -> Seed -> Text -> (FixtureMaterial, FixtureMaterial)
fixtureKeyPair mech (Seed s) label =
  let pair = fixturePairIdentity pubBytes privBytes
  in ( FixtureMaterial pubBytes (fixtureIdentity pubBytes) (Just pair)
     , FixtureMaterial privBytes (fixtureIdentity privBytes) (Just pair)
     )
  where
    pubBytes = prfBytes (frame
      ["haskoki-synth/fixture-pub/v1", encodeMech mech, word64BE s, TE.encodeUtf8 label]) 32
    privBytes = prfBytes (frame
      ["haskoki-synth/fixture-priv/v1", encodeMech mech, word64BE s, TE.encodeUtf8 label]) 32

-- | Decode the 'word32BE' encoding (short input decodes 0; the
-- caller bounds the result against the body length).
unword32BE :: ByteString -> Int
unword32BE bs = case BS.unpack (BS.take 4 (bs <> BS.replicate 4 0)) of
  [a, b, c, d] ->
    fromIntegral a `shiftL` 24 .|. fromIntegral b `shiftL` 16
      .|. fromIntegral c `shiftL` 8 .|. fromIntegral d
  _ -> 0
