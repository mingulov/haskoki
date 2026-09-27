{- | Finite-field Diffie-Hellman recipe: the agreement shape-group recipe.

Two header mechanisms share the agreement parameter shape —
@dh-params\/1@: @kdf:u64be peerLen:u64be peer@. Only the null-KDF
selector (code 0, @CKD_NULL@ semantics: the raw shared secret at
the prime's byte width) is served; every other KDF selector names
a deferred dimension and is refused, never silently downgraded.
The peer arrives as the bare big-endian public value (no DER
framing); range membership (@1 < y < p - 1@) is enforced by the
executing backend, which owns the prime.

This module owns the group's canonical codec, parameter
validation, secret-width rule, and mechanism table. Pure core only.

Consumers:

* 'Haskoki.Registry' builds the group's behavior descriptors from
  'dhCodecFor' (never a re-typed codec literal);
* 'Haskoki.Operation.Derive.planDerive' accepts DH frames via
  'dhRecipeFor' + 'dhParamsValid', capped by
  'dhSecretWidth';
* 'Haskoki.Engine.Driver.dhParamsFor' maps covered (mechanism,
  params) pairs to the backend 'DhSpec' plus the peer key;
  RecipeDhSpec pins the mapping against this table;
* the synthetic backend's per-agreement constructions and the
  libcrypto interop vectors execute the bindings pinned here
  (SyntheticSpec, OpenSSLSpec).

Deferred family members (not recipes, named gaps):
@CKM_X9_42_DH_HYBRID_DERIVE@ and @CKM_X9_42_MQV_DERIVE@
(multi-key agreements, no planner shape), the two
@*_PARAMETER_GEN@ rows (safe-prime policy, a later slice), and
every non-null DH KDF selector — see mechanisms.json honesty
notes.
-}
{-# LANGUAGE OverloadedStrings #-}
module Haskoki.Recipe.Dh
  ( DhRecipe (..)
  , dhRecipes
  , dhRecipeFor
  , dhCodec
  , dhCodecFor
  , encodeDhParams
  , decodeDhParams
  , dhParamsValid
  , dhSecretWidth
  , dhSecretWidthMax
  , dhPrimeWidthOfDer
  ) where

import Data.Bits ((.&.), shiftL, shiftR)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Word (Word64, Word8)

import Haskoki.Attribute.Generated (mustKeyTypeId)
import Haskoki.Registry.Generated (mustGeneratedId)
import Haskoki.Registry.Types (MechanismId (..), MechanismName, ParameterCodec (..))

-- | One DH recipe: the mechanism name and its base key-type id
-- (@CKK_DH@ for the PKCS#3 row, @CKK_X9_42_DH@ for X9.42).
data DhRecipe = DhRecipe
  { dhName :: !MechanismName
  , dhKeyType :: !Word64
  } deriving (Eq, Show)

-- | The group's canonical parameter codec: the agreement frame
-- (KDF selector, peer public value).
dhCodec :: ParameterCodec
dhCodec = ParameterCodec "dh-params" 1

-- | The codec for one recipe row (uniform across the group).
dhCodecFor :: DhRecipe -> ParameterCodec
dhCodecFor _ = dhCodec

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

-- | Encode DH parameters (total; validation is strict).
encodeDhParams :: Int -> ByteString -> ByteString
encodeDhParams kdf peer =
  encodeWord64 kdf <> encodeWord64 (BS.length peer) <> peer

-- | Decode DH parameters: truncation, overrun lengths, and
-- trailing bytes all fail (never a crash, never a partial read).
decodeDhParams :: ByteString -> Maybe (Int, ByteString)
decodeDhParams bs = do
  let (w0, r0) = BS.splitAt 8 bs
      (w1, r1) = BS.splitAt 8 r0
  kdf <- decodeWord64 w0
  pLen <- decodeWord64 w1
  let (peer, rest) = BS.splitAt pLen r1
  if BS.length peer /= pLen || not (BS.null rest)
    then Nothing
    else pure (kdf, peer)

-- | DH parameter validation: the null-KDF selector (code 0) with
-- a non-empty peer public value. Every nonzero KDF selector is
-- refused (deferred dimension, named in the mechanisms.json
-- honesty notes).
dhParamsValid :: DhRecipe -> ByteString -> Bool
dhParamsValid _ params = case decodeDhParams params of
  Just (0, peer) -> not (BS.null peer)
  _ -> False

-- | The DH public-key OIDs (DER-encoded): @dhpublicnumber@
-- (1.2.840.10046.2.1, X9.42 keys) and @dhKeyAgreement@
-- (1.2.840.113549.1.3.1, PKCS#3 keys — what OpenSSL emits).
-- The scan gate that keeps EC/RSA/DSA DER from misreading as
-- DH domain parameters.
dhOidDers :: [ByteString]
dhOidDers =
  [ BS.pack [0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3e, 0x02, 0x01]
  , BS.pack [0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x03, 0x01]
  ]

-- | Take one DER TLV: @(tag, content, rest)@. 'Nothing' on
-- truncation or an indefinite length (never a partial read).
takeTlv :: ByteString -> Maybe (Word8, ByteString, ByteString)
takeTlv bs = do
  (tag, r0) <- BS.uncons bs
  (loct, r1) <- BS.uncons r0
  if loct < 0x80
    then do
      let (content, rest) = BS.splitAt (fromIntegral loct) r1
      if BS.length content /= fromIntegral loct then Nothing
        else pure (tag, content, rest)
    else do
      let n = fromIntegral (loct .&. 0x7f)
      if n == 0 || n > 4 then Nothing else do
        let (lenBs, r2) = BS.splitAt n r1
        if BS.length lenBs /= n then Nothing else do
          let ln = BS.foldl' (\a b -> a `shiftL` 8 + fromIntegral b) 0 lenBs
              (content, rest) = BS.splitAt ln r2
          if BS.length content /= ln then Nothing
            else pure (tag, content, rest)

-- | Prime byte width from DH key DER (PKCS#8 or SPKI): the
-- normalized length of the @p@ INTEGER in the algorithm
-- parameters (one sign pad at most), 'Nothing' unless the OID
-- gate passes and the shape is exact. Serves the planner's width
-- cap; the backend re-parses authoritatively at execution.
dhPrimeWidthOfDer :: ByteString -> Maybe Int
dhPrimeWidthOfDer der = do
  (outerTag, outer, _) <- takeTlv der
  if outerTag /= 0x30 then Nothing else do
    (_, first, rest0) <- takeTlv outer
    algId <- algWithDhOid first
      `orElse` (do (_, second, _) <- takeTlv rest0; algWithDhOid second)
    (_, params, _) <- takeTlv algId
    (pTag, pBs, _) <- takeTlv params
    if pTag /= 0x02 then Nothing
      else pure (BS.length (stripSignPad pBs))
  where
    orElse :: Maybe a -> Maybe a -> Maybe a
    orElse (Just x) _ = Just x
    orElse Nothing y = y
    -- An AlgorithmIdentifier body whose OID is a DH OID:
    -- PKCS#8 carries it as outer[1], SPKI as outer[0].
    algWithDhOid :: ByteString -> Maybe ByteString
    algWithDhOid body = do
      (oidTag, _, oidRest) <- takeTlv body
      -- Rebuild the candidate: the OID TLV must equal a gate
      -- OID exactly (tag + length + value).
      let oidTlv = BS.take (BS.length body - BS.length oidRest) body
      if oidTag /= 0x06 || oidTlv `notElem` dhOidDers then Nothing
        else Just oidRest
    stripSignPad :: ByteString -> ByteString
    stripSignPad b = case BS.uncons b of
      Just (0x00, rest) | not (BS.null rest) -> rest
      _ -> b

-- | The maximum served prime width in bytes (4096 bits): the
-- planner cap for unscannable base material (synthetic opaque
-- bytes), so the planner never caps it lower; the real backend
-- refuses out-of-window primes itself.
dhSecretWidthMax :: Int
dhSecretWidthMax = 512

-- | Raw-secret width in bytes for a base-key material: the prime
-- width when the DER parameters scan, else the maximum (see
-- 'dhSecretWidthMax').
dhSecretWidth :: ByteString -> Int
dhSecretWidth mat = case dhPrimeWidthOfDer mat of
  Just w -> w
  Nothing -> dhSecretWidthMax

-- | Both covered mechanisms with their base key types.
dhRecipes :: [DhRecipe]
dhRecipes =
  [ DhRecipe "CKM_DH_PKCS_DERIVE" (mustKeyTypeId "CKK_DH")
  , DhRecipe "CKM_X9_42_DH_DERIVE" (mustKeyTypeId "CKK_X9_42_DH")
  ]

-- | Resolve a mechanism id to its DH recipe, if covered.
dhRecipeFor :: MechanismId -> Maybe DhRecipe
dhRecipeFor mid =
  case [ r | r <- dhRecipes
           , MechanismId (mustGeneratedId (dhName r)) == mid ] of
    (r : _) -> Just r
    [] -> Nothing
