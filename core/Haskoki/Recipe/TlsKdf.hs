{- | TLS KDF recipe: the TLS 1.0\/1.1\/1.2 derive rows.

Eight header mechanisms in four parameter shapes:

* @CKM_TLS_MASTER_KEY_DERIVE@ \/ @CKM_TLS_MASTER_KEY_DERIVE_DH@
  (0x375\/0x377): @PRF(pms, "master secret", client_random ++
  server_random)@ over the legacy MD5\/SHA-1 construction (RFC
  2246 §5 — the same construction 'Haskoki.Recipe.TlsPrf'
  serves, with the label fixed by the mechanism);
* @CKM_TLS12_MASTER_KEY_DERIVE@ \/
  @CKM_TLS12_MASTER_KEY_DERIVE_DH@ (0x3e0\/0x3e2): @P_hash@
  with a selected hash over @"master secret" ++ client_random
  ++ server_random@ (RFC 5246 §5);
* @CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE@ \/
  @CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE_DH@ (0x56\/0x57):
  @P_hash@ over @"extended master secret" ++ session_hash@
  (RFC 7627);
* @CKM_TLS12_KDF@ (0x3d9) \/ @CKM_TLS_KDF@ (0x3e5): @P_hash@
  (or the legacy PRF when the selector names @CKM_TLS_PRF@)
  over @label ++ client_random ++ server_random@ plus optional
  RFC 5705 context data.

Parameters are the canonical frame (@tls-kdf-params\/1@:
@prf:u8 labLen:u64be lab seedLen:u64be seed ctxLen:u64be
ctx@). The PRF selector is 0 for the legacy construction,
else a 'Haskoki.Recipe.Kdf.kdfCodeDigest' hash code. The
native structs decode in the FFI (canonical profile only:
exact-32-byte randoms, NULL-or-live version which is never
written back — the oracle never asserts it — hash PRFs from
the served HMAC space, context on the free-label rows only);
fixed labels are injected by the row kind, never by the
caller. The output length arrives via the derived template's
@CKA_VALUE_LEN@, capped by 'maxTlsKdfOutput'.

This module owns the canonical codec and parameter validation.
Pure core only.

Consumers:

* 'Haskoki.Registry' builds behavior descriptors from
  'tlsKdfCodecFor' (never a re-typed codec literal);
* 'Haskoki.Operation.Derive.planDerive' accepts TLS-KDF
  frames via 'tlsKdfRecipeFor' + 'tlsKdfParamsValid', capped
  by 'maxTlsKdfOutput';
* 'Haskoki.Engine.Driver.tlsKdfParamsFor' maps params to the
  execution tuple; RecipeTlsKdfSpec pins the mapping against
  this table;
* the driver executes the legacy construction or @P_hash@
  over the HMAC routes (real digests on the real backend,
  test constructions on synthetic) — pinned by
  RoutingE2ESpec vectors and SyntheticSpec constructions.
-}
{-# LANGUAGE OverloadedStrings #-}
module Haskoki.Recipe.TlsKdf
  ( TlsKdfKind (..)
  , TlsKdfRecipe (..)
  , tlsKdfRecipes
  , tlsKdfRecipeFor
  , tlsKdfCodec
  , tlsKdfCodecFor
  , encodeTlsKdfParams
  , decodeTlsKdfParams
  , tlsKdfParamsValid
  , tlsKdfPrfCodeFor
  , maxTlsKdfOutput
  , maxTlsKdfMaterial
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Word (Word8)

import Haskoki.Recipe.Kdf (kdfCodeDigest)
import Haskoki.Registry.Generated (mustGeneratedId)
import Haskoki.Registry.Types (MechanismId (..), MechanismName, ParameterCodec (..))

-- | The four TLS-KDF parameter shapes.
data TlsKdfKind
  = TlsMaster10
  | TlsMaster12
  | TlsExtended12
  | TlsKdfFree
  deriving (Eq, Show)

-- | One TLS-KDF recipe: the mechanism name and its shape.
data TlsKdfRecipe = TlsKdfRecipe
  { tkName :: !MechanismName
  , tkKind :: !TlsKdfKind
  } deriving (Eq, Show)

-- | The TLS-KDF frame codec.
tlsKdfCodec :: ParameterCodec
tlsKdfCodec = ParameterCodec "tls-kdf-params" 1

-- | Output ceiling in bytes (the shared 255-block construction
-- ceiling): larger derivations refuse typed.
maxTlsKdfOutput :: Int
maxTlsKdfOutput = 255 * 32

-- | Label + seed + context ceiling in bytes.
maxTlsKdfMaterial :: Int
maxTlsKdfMaterial = 65536

encodeWord64 :: Int -> ByteString
encodeWord64 n =
  BS.pack [ fromIntegral ((n `div` 2 ^ (8 * i)) `mod` 256) | i <- ([7, 6 .. 0] :: [Int]) ]

decodeWord64 :: ByteString -> Maybe (Int, ByteString)
decodeWord64 bs
  | BS.length bs < 8 = Nothing
  | otherwise =
      let (w, rest) = BS.splitAt 8 bs
      in Just (BS.foldl' (\a b -> a * 256 + fromIntegral b) 0 w, rest)

decodeSized :: ByteString -> Maybe (ByteString, ByteString)
decodeSized bs = do
  (n, r1) <- decodeWord64 bs
  let (v, r2) = BS.splitAt n r1
  if BS.length v /= n then Nothing else Just (v, r2)

-- | Encode the canonical frame.
encodeTlsKdfParams :: Word8 -> ByteString -> ByteString -> ByteString -> ByteString
encodeTlsKdfParams prf lab seed ctx =
  BS.singleton prf
    <> encodeWord64 (BS.length lab) <> lab
    <> encodeWord64 (BS.length seed) <> seed
    <> encodeWord64 (BS.length ctx) <> ctx

-- | Decode the canonical frame ('Nothing' on truncation,
-- trailing bytes, or over-ceiling material).
decodeTlsKdfParams :: ByteString -> Maybe (Word8, ByteString, ByteString, ByteString)
decodeTlsKdfParams bs = case BS.uncons bs of
  Nothing -> Nothing
  Just (prf, r0) -> do
    (lab, r1) <- decodeSized r0
    (seed, r2) <- decodeSized r1
    (ctx, rest) <- decodeSized r2
    if not (BS.null rest) then Nothing
      else if BS.length lab + BS.length seed + BS.length ctx > maxTlsKdfMaterial
        then Nothing
        else Just (prf, lab, seed, ctx)

-- | Fixed labels by kind ('Nothing' = caller label, must be
-- non-empty).
tlsKdfFixedLabel :: TlsKdfKind -> Maybe ByteString
tlsKdfFixedLabel TlsMaster10 = Just "master secret"
tlsKdfFixedLabel TlsMaster12 = Just "master secret"
tlsKdfFixedLabel TlsExtended12 = Just "extended master secret"
tlsKdfFixedLabel TlsKdfFree = Nothing

-- | Seed width rule by kind: master and free rows carry the
-- 32+32 randoms; extended rows carry the session hash
-- (16..64 bytes — a real hash output, MD5 to SHA-512).
tlsKdfSeedOk :: TlsKdfKind -> ByteString -> Bool
tlsKdfSeedOk TlsExtended12 seed =
  let n = BS.length seed in n >= 16 && n <= 64
tlsKdfSeedOk _ seed = BS.length seed == 64

-- | PRF rule by kind: the TLS 1.0 rows are legacy-only, the
-- TLS 1.2 master\/extended rows are hash-only, the free rows
-- take either.
tlsKdfPrfOk :: TlsKdfKind -> Word8 -> Bool
tlsKdfPrfOk TlsMaster10 prf = prf == 0
tlsKdfPrfOk TlsKdfFree prf = prf == 0 || prf `elem` [1 .. 13]
tlsKdfPrfOk _ prf = prf `elem` [1 .. 13]

-- | Parameter validation: the frame decodes and matches the
-- row kind (fixed labels, seed widths, PRF range, context
-- rules — context rides the free rows with a hash PRF only;
-- the legacy construction has no context input).
tlsKdfParamsValid :: TlsKdfRecipe -> ByteString -> Bool
tlsKdfParamsValid r params = case decodeTlsKdfParams params of
  Nothing -> False
  Just (prf, lab, seed, ctx) ->
    let kind = tkKind r
        labelOk = case tlsKdfFixedLabel kind of
          Just want -> lab == want
          Nothing -> not (BS.null lab)
        ctxOk = case kind of
          TlsKdfFree -> prf /= 0 || BS.null ctx
          _ -> BS.null ctx
    in labelOk && tlsKdfSeedOk kind seed && tlsKdfPrfOk kind prf && ctxOk

-- | A PRF mechanism id onto its frame code: 0 for
-- @CKM_TLS_PRF@ (legacy), else the hash code when the id is a
-- served digest mechanism in the 'kdfCodeDigest' space.
-- 'Nothing' means unserved.
tlsKdfPrfCodeFor :: MechanismId -> Maybe Word8
tlsKdfPrfCodeFor (MechanismId mid)
  | mid == mustGeneratedId "CKM_TLS_PRF" = Just 0
  | otherwise =
      let match code = case kdfCodeDigest (fromIntegral code) of
            Just stem
              | mid == mustGeneratedId ("CKM_" <> stem) -> Just code
            _ -> Nothing
      in foldr (\c acc -> case match c of Just k -> Just k; Nothing -> acc) Nothing [1 .. 13]

-- | The codec rides every recipe row.
tlsKdfCodecFor :: TlsKdfRecipe -> ParameterCodec
tlsKdfCodecFor _ = tlsKdfCodec

-- | The eight covered mechanisms.
tlsKdfRecipes :: [TlsKdfRecipe]
tlsKdfRecipes =
  [ TlsKdfRecipe "CKM_TLS_MASTER_KEY_DERIVE" TlsMaster10
  , TlsKdfRecipe "CKM_TLS_MASTER_KEY_DERIVE_DH" TlsMaster10
  , TlsKdfRecipe "CKM_TLS12_MASTER_KEY_DERIVE" TlsMaster12
  , TlsKdfRecipe "CKM_TLS12_MASTER_KEY_DERIVE_DH" TlsMaster12
  , TlsKdfRecipe "CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE" TlsExtended12
  , TlsKdfRecipe "CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE_DH" TlsExtended12
  , TlsKdfRecipe "CKM_TLS12_KDF" TlsKdfFree
  , TlsKdfRecipe "CKM_TLS_KDF" TlsKdfFree
  ]

-- | Resolve a mechanism id to its TLS-KDF recipe, if covered.
tlsKdfRecipeFor :: MechanismId -> Maybe TlsKdfRecipe
tlsKdfRecipeFor mid =
  case [ r | r <- tlsKdfRecipes
           , MechanismId (mustGeneratedId (tkName r)) == mid ] of
    (r : _) -> Just r
    [] -> Nothing
