{- | SP 800-108 recipe: the eleventh shape-group recipe.

Three header mechanisms — @CKM_SP800_108_COUNTER_KDF@,
@CKM_SP800_108_FEEDBACK_KDF@, @CKM_SP800_108_DOUBLE_PIPELINE_KDF@
(NIST SP 800-108 §5.1\/5.2\/5.3 over an HMAC PRF) — share the
derive shape with a canonical parameter frame (@sp800-params\/1@:
@prf:u8 rWidth:u8 lWidth:u8 ivLen:u64be iv fixedLen:u64be
fixed@). The mode rides the mechanism (never the frame); the
frame carries the engine-local PRF code (the 'kdfCodeDigest'
space), the counter width @r@ and DKM-length width @l@ (each in
bits, one of 8\/16\/24\/32), the feedback IV (empty unless
feedback mode), and the flattened fixed input (byte arrays in
parameter order, separators included; the DKM length @L@ itself
is computed at execution from the derived length, so it always
equals it by construction).

The served profile is the canonical one: big-endian counter and
length, iteration variable first, DKM length last, single output.
Profile rules (parameter order, PRF family, endianness,
additional-keys refusal) live in the FFI struct decoder; this
module owns the canonical codec, the frame grammar, and the
ceilings ('maxSp800Total', 'maxSp800Fixed'). Pure core only.

Consumers:

* 'Haskoki.Registry' builds the behavior descriptors from
  'sp800CodecFor' (never a re-typed codec literal);
* 'Haskoki.Operation.Derive.planDerive' accepts SP 800-108
  frames via 'sp800RecipeFor' + 'sp800ParamsValid', capped by
  'maxSp800Total' with the L-width fit check;
* 'Haskoki.Engine.Driver.sp800ParamsFor' maps frames to the
  execution tuple; RecipeSp800108Spec pins the mapping against
  this table;
* the driver composes the three modes over the HMAC route
  (real digests on the real backend, test constructions on
  synthetic) — pinned by RoutingE2ESpec vectors and
  SyntheticSpec constructions.
-}
{-# LANGUAGE OverloadedStrings #-}
module Haskoki.Recipe.Sp800108
  ( Sp800Mode (..)
  , Sp800Recipe (..)
  , Sp800Params (..)
  , sp800Recipes
  , sp800RecipeFor
  , sp800Codec
  , sp800CodecFor
  , encodeSp800Params
  , decodeSp800Params
  , sp800ParamsValid
  , maxSp800Total
  , maxSp800Fixed
  , sp800PrfCodeFor
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Word (Word8)

import Haskoki.Recipe.Hmac (HmacRecipe (..), hmacRecipeFor)
import Haskoki.Recipe.Kdf (kdfCodeDigest)
import Haskoki.Registry.Generated (mustGeneratedId)
import Haskoki.Registry.Types (MechanismId (..), MechanismName, ParameterCodec (..))

-- | The SP 800-108 mode: counter (§5.1), feedback (§5.2), or
-- double-pipeline (§5.3). Rides the mechanism, never the frame.
data Sp800Mode = Sp800Counter | Sp800Feedback | Sp800DoublePipeline
  deriving (Eq, Show)

-- | One SP 800-108 recipe: the mechanism name plus its mode.
data Sp800Recipe = Sp800Recipe
  { rsName :: !MechanismName
  , rsMode :: !Sp800Mode
  } deriving (Eq, Show)

-- | Decoded parameters: the engine-local PRF code (the
-- 'Haskoki.Recipe.Kdf.kdfCodeDigest' space), the counter width
-- @r@ and DKM-length width @l@ in bits, the feedback IV, and
-- the flattened fixed input.
data Sp800Params = Sp800Params
  { spPrf :: !Word8
  , spCounterBits :: !Int
  , spLengthBits :: !Int
  , spIv :: !ByteString
  , spFixed :: !ByteString
  } deriving (Eq, Show)

-- | SP 800-108 takes the canonical parameter frame.
sp800Codec :: ParameterCodec
sp800Codec = ParameterCodec "sp800-params" 1

-- | Output ceiling in bytes (the largest sane derived object;
-- the XOF precedent): larger derivations refuse typed.
maxSp800Total :: Int
maxSp800Total = 65536

-- | Fixed-input + IV ceiling in bytes (the derive info
-- ceiling): larger frames refuse typed.
maxSp800Fixed :: Int
maxSp800Fixed = 65536

-- | The served counter/length widths in bits.
sp800Widths :: [Int]
sp800Widths = [8, 16, 24, 32]

encodeWord64 :: Int -> ByteString
encodeWord64 n =
  BS.pack [ fromIntegral ((n `div` 2 ^ (8 * i)) `mod` 256) | i <- [7, 6 .. 0] ]

decodeWord64 :: ByteString -> Maybe (Int, ByteString)
decodeWord64 bs
  | BS.length bs < 8 = Nothing
  | otherwise =
      let (w, rest) = BS.splitAt 8 bs
      in Just (BS.foldl' (\a b -> a * 256 + fromIntegral b) 0 w, rest)

-- | Encode the canonical parameter frame.
encodeSp800Params :: Word8 -> Int -> Int -> ByteString -> ByteString -> ByteString
encodeSp800Params prf r l iv fixed =
  BS.singleton prf <> BS.singleton (fromIntegral r) <> BS.singleton (fromIntegral l)
    <> encodeWord64 (BS.length iv) <> iv
    <> encodeWord64 (BS.length fixed) <> fixed

-- | Decode the canonical parameter frame ('Nothing' on an
-- unmapped PRF code, a width outside 8\/16\/24\/32, an
-- over-ceiling input, truncation, or trailing bytes).
decodeSp800Params :: ByteString -> Maybe Sp800Params
decodeSp800Params bs = do
  (prf, r1) <- BS.uncons bs
  (rw, r2) <- BS.uncons r1
  (lw, r3) <- BS.uncons r2
  _ <- kdfCodeDigest (fromIntegral prf)
  let r = fromIntegral rw
      l = fromIntegral lw
  if r `notElem` sp800Widths || l `notElem` sp800Widths
    then Nothing
    else do
      (il, r4) <- decodeWord64 r3
      (iv, r5) <- Just (BS.splitAt il r4)
      (fl, r6) <- decodeWord64 r5
      (fixed, rest) <- Just (BS.splitAt fl r6)
      if BS.length iv /= il || BS.length fixed /= fl || not (BS.null rest)
        then Nothing
        else if il + fl > maxSp800Fixed then Nothing
          else Just (Sp800Params prf r l iv fixed)

-- | Parameter validation: the frame decodes and the IV matches
-- the mode (feedback rows alone take an IV).
sp800ParamsValid :: Sp800Recipe -> ByteString -> Bool
sp800ParamsValid r params = case decodeSp800Params params of
  Just p -> case rsMode r of
    Sp800Feedback -> True
    _ -> BS.null (spIv p)
  Nothing -> False

-- | The codec rides every recipe row.
sp800CodecFor :: Sp800Recipe -> ParameterCodec
sp800CodecFor _ = sp800Codec

-- | The three covered mechanisms.
sp800Recipes :: [Sp800Recipe]
sp800Recipes =
  [ Sp800Recipe "CKM_SP800_108_COUNTER_KDF" Sp800Counter
  , Sp800Recipe "CKM_SP800_108_FEEDBACK_KDF" Sp800Feedback
  , Sp800Recipe "CKM_SP800_108_DOUBLE_PIPELINE_KDF" Sp800DoublePipeline
  ]

-- | Resolve a mechanism id to its SP 800-108 recipe, if covered.
sp800RecipeFor :: MechanismId -> Maybe Sp800Recipe
sp800RecipeFor mid =
  case [ r | r <- sp800Recipes
           , MechanismId (mustGeneratedId (rsName r)) == mid ] of
    (r : _) -> Just r
    [] -> Nothing

-- | A PRF mechanism id onto its frame code: the mechanism must
-- resolve to a served HMAC row whose stem sits in the
-- 'kdfCodeDigest' space (BLAKE2B HMACs are served HMACs but
-- have no PRF code — a named gap). 'Nothing' means unserved
-- (non-HMAC mechanism, unserved HMAC, or GENERAL/tag-length
-- rows, which name the same PRF — the tag length is not a KDF
-- input, so GENERAL rows map too).
sp800PrfCodeFor :: MechanismId -> Maybe Word8
sp800PrfCodeFor mid = do
  r <- hmacRecipeFor mid
  let n = hrName r
      match code = case kdfCodeDigest (fromIntegral code) of
        Just stem
          | n == "CKM_" <> stem <> "_HMAC"
          || n == "CKM_" <> stem <> "_HMAC_GENERAL" -> Just code
        _ -> Nothing
  foldr (\c acc -> case match c of Just k -> Just k; Nothing -> acc) Nothing [1 .. 13]
