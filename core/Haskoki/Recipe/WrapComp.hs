{- | Wrap-composition recipes: ECDH+KDF+AES-KW compositions.

Three header mechanisms share the agreement-then-wrap parameter
shape — @wrapcomp-ecdh-params\/1@: @kdf:u64be sharedLen:u64be
shared aesBits:u64be@. There is no peer field: the transport
keypair is generated ephemerally at wrap time on the wrapping
key's domain, and the transport public half rides as the blob
prefix at unwrap time.

Only the null-KDF selector (code 0, @CKD_NULL@ semantics) is
served, mirroring the served @CKM_ECDH1_DERIVE@ stance
('Haskoki.Recipe.Ecdh' models no KDF); shared data is accepted
and ignored under the null KDF exactly like the ECDH1 recipe.
@ulAESKeyBits@ is one of 128\/192\/256; curves whose raw secret
is shorter than @ulAESKeyBits\/8@ refuse at the planner (pinned:
P-192 x AES-256).

Key-type gates come from the mechanism row, not the parameters:

* @CKM_ECDH_AES_KEY_WRAP@ (0x1053, plain): @CKK_EC@ or
  @CKK_EC_MONTGOMERY@. Deprecated in PKCS#11 v3.2 but still
  in the catalog.
* @CKM_ECDH_COF_AES_KEY_WRAP@ (0x4039, cofactor): @CKK_EC@
  only.
* @CKM_ECDH_X_AES_KEY_WRAP@ (0x4038, plain): @CKK_EC_MONTGOMERY@
  only.

Transport framing (blob = transport-pub \|\| kwp-blob):

* plain over Weierstrass: the bare X9.62 point (@0x04 \|\| X \|\| Y@,
  1+2w bytes); the unwrap split measures the unwrapping key's
  domain width.
* cofactor: the DER OCTET STRING of the X9.62 point (the
  @CKA_EC_POINT@ encoding); the unwrap split parses the
  length octets (self-delimiting).
* plain\/X over Montgomery: the raw RFC 7748 u-coordinate
  (curve-width bytes); the unwrap split measures the
  unwrapping key's domain width.
* opaque test doubles (unscannable material): the 69-byte
  synthetic pair half passes through raw on every row; no DER
  framing applies. Real keys always scan (DER with curve OID),
  so this arm fires for synthetic doubles only.

The KEK is the FIRST @ulAESKeyBits@ bits (leading bytes) of the
raw agreement secret — NOT the derive truncation, which drops
leading bytes. KDF scope stays null-only: no KDF math runs.

This module owns the ECDH half of the group (canonical codec,
parameter validation, key-type gates, domain scan, transport
framing, blob split). The RSA half (@CKM_RSA_AES_KEY_WRAP@)
extends this module in its own slice. Pure core only.
-}
{-# LANGUAGE OverloadedStrings #-}
module Haskoki.Recipe.WrapComp
  ( WrapCompEcdhRecipe (..)
  , WrapCompDomain (..)
  , wrapCompEcdhRecipes
  , wrapCompEcdhRecipeFor
  , wrapCompEcdhCodec
  , wrapCompEcdhCodecFor
  , encodeWrapCompEcdhParams
  , decodeWrapCompEcdhParams
  , wrapCompEcdhParamsValid
  , wrapCompEcdhParamsWellFormed
  , wrapCompEcdhKdfServed
  , wrapCompEcdhKeyOk
  , wrapCompAesBytes
  , wrapCompDomain
  , wrapCompTransportLen
  , wrapCompTransportPrefix
  , wrapCompSplitBlob
  , wrapCompAgreePeer
  , wrapCompPubPeer
  , opaqueTransportLen
  ) where

import Data.Bits ((.&.), shiftL, shiftR)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Text (Text)
import Data.Word (Word8, Word64)

import Haskoki.Attribute.Generated (mustKeyTypeId)
import Haskoki.Der (derOctet, montgomerySpkiFields, spkiPoint, unwrapEcPoint)
import Haskoki.Recipe.Ecdh (curveWidthOfName, xdhCurveOfDer, xdhSecretWidth)
import Haskoki.Recipe.Ecdsa (ecdsaCurveOfDer)
import Haskoki.Registry.Generated (mustGeneratedId)
import Haskoki.Registry.Types (MechanismId (..), MechanismName, ParameterCodec (..))

-- | One ECDH wrap-composition recipe: the mechanism name, the
-- cofactor flag, and the allowed wrapping-key type names.
data WrapCompEcdhRecipe = WrapCompEcdhRecipe
  { wceName :: !MechanismName
  , wceCofactor :: !Bool
  , wceKeyTypes :: ![Text]
  } deriving (Eq, Show)

-- | The transport domain scanned from key material: a named
-- Weierstrass or Montgomery curve with its coordinate width, or
-- an opaque test double (unscannable material).
data WrapCompDomain
  = DomainWeierstrass !Text !Int
  | DomainMontgomery !Text !Int
  | DomainOpaque
  deriving (Eq, Show)

-- | The three served rows.
wrapCompEcdhRecipes :: [WrapCompEcdhRecipe]
wrapCompEcdhRecipes =
  [ WrapCompEcdhRecipe "CKM_ECDH_AES_KEY_WRAP" False ["CKK_EC", "CKK_EC_MONTGOMERY"]
  , WrapCompEcdhRecipe "CKM_ECDH_COF_AES_KEY_WRAP" True ["CKK_EC"]
  , WrapCompEcdhRecipe "CKM_ECDH_X_AES_KEY_WRAP" False ["CKK_EC_MONTGOMERY"]
  ]

-- | Resolve a mechanism id to its wrap-composition recipe, if covered.
wrapCompEcdhRecipeFor :: MechanismId -> Maybe WrapCompEcdhRecipe
wrapCompEcdhRecipeFor mid =
  case [ r | r <- wrapCompEcdhRecipes
           , MechanismId (mustGeneratedId (wceName r)) == mid ] of
    (r : _) -> Just r
    [] -> Nothing

-- | The group's canonical parameter codec: the agreement frame
-- (KDF selector, shared data) plus the AES strength word. No
-- peer field: the transport keypair is ephemeral.
wrapCompEcdhCodec :: ParameterCodec
wrapCompEcdhCodec = ParameterCodec "wrapcomp-ecdh-params" 1

-- | The codec for one recipe row (uniform across the group).
wrapCompEcdhCodecFor :: WrapCompEcdhRecipe -> ParameterCodec
wrapCompEcdhCodecFor _ = wrapCompEcdhCodec

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

-- | Encode wrap-composition ECDH parameters (total; validation is strict).
encodeWrapCompEcdhParams :: Int -> ByteString -> Int -> ByteString
encodeWrapCompEcdhParams kdf shared aesBits =
  encodeWord64 kdf
    <> encodeWord64 (BS.length shared) <> shared
    <> encodeWord64 aesBits

-- | Decode wrap-composition ECDH parameters: truncation, overrun
-- lengths, and trailing bytes all fail (never a crash, never a
-- partial read).
decodeWrapCompEcdhParams :: ByteString -> Maybe (Int, ByteString, Int)
decodeWrapCompEcdhParams bs = do
  let (w0, r0) = BS.splitAt 8 bs
      (w1, r1) = BS.splitAt 8 r0
  kdf <- decodeWord64 w0
  sLen <- decodeWord64 w1
  let (shared, r2) = BS.splitAt sLen r1
  if BS.length shared /= sLen
    then Nothing
    else do
      let (w3, rest) = BS.splitAt 8 r2
      aesBits <- decodeWord64 w3
      if BS.null rest
        then pure (kdf, shared, aesBits)
        else Nothing

-- | Served AES strengths in bits.
wrapCompAesBitsSet :: [Int]
wrapCompAesBitsSet = [128, 192, 256]

-- | Parameter validation: the null-KDF selector (code 0) with a
-- served AES strength. Shared data is accepted and ignored under
-- the null KDF (the ECDH1 rule). Every nonzero KDF selector and
-- every off-set strength is refused, never silently downgraded.
wrapCompEcdhParamsValid :: WrapCompEcdhRecipe -> ByteString -> Bool
wrapCompEcdhParamsValid _ params =
  wrapCompEcdhParamsWellFormed params && wrapCompEcdhKdfServed params

-- | Structural well-formedness: decodable with a served AES
-- strength (any KDF selector). Malformed frames refuse as
-- argument errors; well-formed frames with an unserved KDF
-- refuse as parameter errors (the KDF enum is open — a nonzero
-- selector is an unserved feature, not a malformed struct).
wrapCompEcdhParamsWellFormed :: ByteString -> Bool
wrapCompEcdhParamsWellFormed params = case decodeWrapCompEcdhParams params of
  Just (_, _, bits) -> bits `elem` wrapCompAesBitsSet
  _ -> False

-- | The null-KDF selector (code 0) is the only served KDF,
-- mirroring the served @CKM_ECDH1_DERIVE@ stance.
wrapCompEcdhKdfServed :: ByteString -> Bool
wrapCompEcdhKdfServed params = case decodeWrapCompEcdhParams params of
  Just (0, _, _) -> True
  _ -> False

-- | The KEK length in bytes for validated parameters ('Nothing'
-- for anything the recipe refuses).
wrapCompAesBytes :: ByteString -> Maybe Int
wrapCompAesBytes params = case decodeWrapCompEcdhParams params of
  Just (0, _, bits)
    | bits `elem` wrapCompAesBitsSet -> Just (bits `div` 8)
  _ -> Nothing

-- | The row's wrapping-key type gate over a numeric @CKK_*@ id.
wrapCompEcdhKeyOk :: WrapCompEcdhRecipe -> Word64 -> Bool
wrapCompEcdhKeyOk r kty = kty `elem` map mustKeyTypeId (wceKeyTypes r)

-- | Scan the transport domain from key material: a Montgomery OID
-- resolves the Montgomery curve, else a Weierstrass OID resolves
-- the EC curve, else the material is an opaque test double.
wrapCompDomain :: ByteString -> WrapCompDomain
wrapCompDomain mat = case xdhCurveOfDer mat of
  Just name -> case xdhSecretWidth mat of
    Just w -> DomainMontgomery name w
    Nothing -> DomainOpaque
  Nothing -> case ecdsaCurveOfDer mat of
    Just name -> case curveWidthOfName name of
      Just w -> DomainWeierstrass name w
      Nothing -> DomainOpaque
    Nothing -> DomainOpaque

-- | Opaque transport prefix length: the synthetic pair-half layout
-- @"HKS1" \|\| pairId(32) \|\| role(1) \|\| mat(32)@. The planner
-- and the driver pin this constant together (structural
-- agreement); the driver tripwires the actual length.
opaqueTransportLen :: Int
opaqueTransportLen = 69

-- | Transport prefix length for a (row, domain) pair: the bare
-- point over Weierstrass-plain, the OCTET STRING image over
-- cofactor, the raw coordinate over Montgomery, the opaque half
-- over doubles. Row/domain contradictions answer 'Nothing'.
wrapCompTransportLen :: WrapCompEcdhRecipe -> WrapCompDomain -> Maybe Int
wrapCompTransportLen r dom = case (wceName r, dom) of
  ("CKM_ECDH_AES_KEY_WRAP", DomainWeierstrass _ w) -> Just (1 + 2 * w)
  ("CKM_ECDH_AES_KEY_WRAP", DomainMontgomery _ w) -> Just w
  ("CKM_ECDH_COF_AES_KEY_WRAP", DomainWeierstrass _ w) ->
    Just (BS.length (derOctet (BS.replicate (1 + 2 * w) 0)))
  ("CKM_ECDH_X_AES_KEY_WRAP", DomainMontgomery _ w) -> Just w
  (_, DomainOpaque) -> Just opaqueTransportLen
  _ -> Nothing

-- | Frame the transport prefix from freshly generated transport
-- public material: the bare point (Weierstrass-plain), its OCTET
-- STRING image (cofactor), the raw coordinate (Montgomery), or
-- the opaque half verbatim (doubles, length-tripwired). 'Nothing'
-- covers framing failures and row/domain contradictions.
wrapCompTransportPrefix
  :: WrapCompEcdhRecipe -> WrapCompDomain -> ByteString -> Maybe ByteString
wrapCompTransportPrefix r dom pub = case (wceName r, dom) of
  ("CKM_ECDH_AES_KEY_WRAP", DomainWeierstrass _ _) -> spkiPoint pub
  ("CKM_ECDH_AES_KEY_WRAP", DomainMontgomery _ _) ->
    snd <$> montgomerySpkiFields pub
  ("CKM_ECDH_COF_AES_KEY_WRAP", DomainWeierstrass _ _) ->
    derOctet <$> spkiPoint pub
  ("CKM_ECDH_X_AES_KEY_WRAP", DomainMontgomery _ _) ->
    snd <$> montgomerySpkiFields pub
  (_, DomainOpaque)
    | BS.length pub == opaqueTransportLen -> Just pub
    | otherwise -> Nothing
  _ -> Nothing

-- | Split one wrapped blob into (transport-pub, kwp-blob): fixed
-- splits over raw framings, an OCTET-STRING prefix parse over
-- cofactor, the opaque length over doubles. Short blobs,
-- non-KWP-shaped tails (the KWP half is a multiple of 8, at
-- least 16), and row/domain contradictions answer 'Nothing'.
wrapCompSplitBlob
  :: WrapCompEcdhRecipe -> WrapCompDomain -> ByteString -> Maybe (ByteString, ByteString)
wrapCompSplitBlob r dom blob = case (wceName r, dom) of
  ("CKM_ECDH_COF_AES_KEY_WRAP", DomainWeierstrass _ w) -> do
    (img, rest) <- splitOctetPrefix w blob
    if kwpTailOk rest then Just (img, rest) else Nothing
  _ -> case wrapCompTransportLen r dom of
    Just n
      | BS.length blob >= n + 16
      , let rest = BS.drop n blob
      , kwpTailOk rest -> Just (BS.splitAt n blob)
    _ -> Nothing
  where
    kwpTailOk rest = BS.length rest >= 16 && BS.length rest `mod` 8 == 0

-- | The agreement peer for a split transport prefix: the inner
-- X9.62 point out of a cofactor OCTET image, the prefix itself
-- everywhere else (bare points, raw coordinates, opaque halves).
wrapCompAgreePeer
  :: WrapCompEcdhRecipe -> WrapCompDomain -> ByteString -> Maybe ByteString
wrapCompAgreePeer r dom prefix = case (wceName r, dom) of
  ("CKM_ECDH_COF_AES_KEY_WRAP", DomainWeierstrass _ w) ->
    unwrapEcPoint w prefix
  _ -> Just prefix

-- | The wrap-side agreement peer from wrapping PUBLIC key
-- material: the raw u-coordinate out of a Montgomery SPKI (the
-- XDH entry takes raw coordinates), the material itself
-- everywhere else (Weierstrass SPKI scans at the backend,
-- opaque halves pass through).
wrapCompPubPeer :: WrapCompDomain -> ByteString -> Maybe ByteString
wrapCompPubPeer (DomainMontgomery _ _) pub =
  snd <$> montgomerySpkiFields pub
wrapCompPubPeer _ pub = Just pub

-- | Parse one DER OCTET STRING prefix holding an uncompressed
-- X9.62 point at the expected coordinate width: answers the
-- (consumed image, rest of blob). The agreement peer comes out
-- of the image via 'unwrapEcPoint'. Short headers, length lies,
-- short bodies, and non-point contents all fail.
splitOctetPrefix :: Int -> ByteString -> Maybe (ByteString, ByteString)
splitOctetPrefix w bs = case BS.uncons bs of
  Just (0x04, rest) -> do
    (n, body) <- splitLen rest
    let hdrLen = BS.length bs - BS.length body
        point = BS.take n body
    if BS.length body >= n
       && n == 2 * w + 1
       && not (BS.null point)
       && BS.index point 0 == 0x04
      then Just (BS.take (hdrLen + n) bs, BS.drop (hdrLen + n) bs)
      else Nothing
  _ -> Nothing
  where
    splitLen :: ByteString -> Maybe (Int, ByteString)
    splitLen s = case BS.uncons s of
      Just (h, r)
        | h < 0x80 -> Just (fromIntegral h, r)
        | h == 0x81 -> case BS.uncons r of
            Just (b, r') -> Just (fromIntegral b, r')
            Nothing -> Nothing
        | h == 0x82 -> case BS.unpack (BS.take 2 r) of
            [b1, b2] -> Just (fromIntegral b1 * 256 + fromIntegral b2, BS.drop 2 r)
            _ -> Nothing
        | otherwise -> Nothing
      Nothing -> Nothing
