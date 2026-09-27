{- | Caller-native mechanism structs into the recipe canonical codecs.

The Init and Derive planners validate mechanism parameters against
the recipe canonical codecs ('Haskoki.Recipe.RsaPss',
'Haskoki.Recipe.RsaOaep', 'Haskoki.Recipe.Ecdh'): big-endian words
over small digest tables. Real PKCS#11 callers pass native C
structs instead (@CK_RSA_PKCS_PSS_PARAMS@,
@CK_RSA_PKCS_OAEP_PARAMS@, @CK_ECDH1_DERIVE_PARAMS@): host-order
words, real @CKM_*@/@CKG_*@/@CKD_*@ ids, and (for OAEP/ECDH) data
pointers the pure core can never chase. 'normalizeMechParams' and
'normalizeEcdhParams' translate at the FFI boundary, where the
caller's memory is still live.

Covered structs (caller-native layout, offsets derived from
'Foreign.Storable' so LP64 and ILP32 both work; words read with
'Foreign.Storable.peekByteOff' so the host endianness is honored):

* PSS (@CK_RSA_PKCS_PSS_PARAMS@: hashAlg, mgf, sLen — three
  @CK_ULONG@, no pointers): the @CKM_*@ hash id maps onto a digest
  stem through the generated vocabulary, the @CKG_MGF1_*@ id onto an
  MGF stem through header-cited constants (@spec/vendor/pkcs11.h@,
  @CKG_*@ has no generated vocabulary), and the salt length carries
  over; the triple re-encodes with 'encodePssParams'.
* OAEP (@CK_RSA_PKCS_OAEP_PARAMS@: hashAlg, mgf, source, pSourceData,
  ulSourceDataLen): the ids map as for PSS; @source@ must be
  @CKZ_DATA_SPECIFIED@ (0x01); the label chases @pSourceData@ under
  'maxInputBytes' with the 'decodeInputBytes' null conventions
  (null-with-zero is the empty label, null-with-length rejects).
* ECDH (@CK_ECDH1_DERIVE_PARAMS@: kdf, shared length, shared
  pointer, public length, public pointer): @kdf@ must be @CKD_NULL@
  (0x01, the only served selector — every other KDF is a deferred
  recipe dimension); both byte strings chase under 'maxInputBytes'
  with the same null conventions, and the triple re-encodes with
  'encodeEcdhParams' (canonical null-KDF code 0).
* EdDSA (@CK_EDDSA_PARAMS@: phFlag, context length, context
  pointer): flags 0/1 translate (anything else passes through);
  the context chases under 'maxInputBytes' with the same null
  conventions, and the pair re-encodes with 'encodeEddsaParams'
  (non-pure combinations refuse downstream at the recipe).
* ML-DSA (@CK_SIGN_ADDITIONAL_CONTEXT@: hedge word, context
  pointer, context length): hedge words 0/1/2 translate
  (anything else passes through); the context chases under
  'maxInputBytes' with the same null conventions, and the pair
  re-encodes with 'encodeMldsaParams' (overlong contexts refuse
  downstream at the recipe).
* ChaCha20 (@CK_CHACHA20_PARAMS@: counter pointer, counter bits,
  nonce pointer, nonce bits): the counter chases
  counter-bits/8 bytes (whole bytes only) and decodes
  little-endian — the OASIS text pins no byte order, so the
  IETF/RFC 8439 state-word order is the documented
  interpretation — and the nonce chases nonce-bits/8 bytes;
  the pair re-encodes with 'encodeChachaStreamParams'
  (non-IETF widths translate and refuse downstream at the
  recipe, never a malformed struct).
* ChaCha20-Poly1305 (@CK_SALSA20_CHACHA20_POLY1305_PARAMS@:
  nonce pointer, nonce length, AAD pointer, AAD length): both
  byte strings chase under 'maxInputBytes' with the same null
  conventions and re-encode with 'encodeChachaPolyParams' at
  the fixed 16-byte tag (the struct carries no tag width;
  off-12 nonces refuse downstream at the recipe).

Anything unmappable — wrong length, unknown ids, a bad source tag,
a null-with-length or over-bound chase — passes the input bytes
through untouched, so the recipe refusal (and its @CKR@) is
exactly today's: the normalizer only ever turns a would-be refusal
into an acceptance when the native struct is fully understood. In
particular the historical canonical byte images still validate,
since their words never parse as mapped native ids. Non-null
chased pointers must be readable for the stated length (the usual
PKCS#11 caller contract, shared with 'decodeInputBytes'): a wild
pointer is undefined behavior, not a refusal.
-}
{-# LANGUAGE OverloadedStrings #-}
module Haskoki.FFI.NativeParams
  ( normalizeMechParams
  , normalizeEcdhParams
  , normalizeTlsPrfParams
  , tlsPrfStructToCanonical
  , tlsPrfNativeSize
  , pssStructToCanonical
  , oaepStructToCanonical
  , ecdhStructToCanonical
  , gcmStructToCanonical
  , ccmStructToCanonical
  , ctrStructToCanonical
  , eddsaStructToCanonical
  , mldsaStructToCanonical
  , slhdsaStructToCanonical
  , chachaStreamStructToCanonical
  , chachaPolyStructToCanonical
  , digestStemByCkm
  , mgfStemByCkg
  , pssNativeSize
  , oaepNativeSize
  , ecdhNativeSize
  , gcmNativeSize
  , ccmNativeSize
  , ctrNativeSize
  , eddsaNativeSize
  , mldsaNativeSize
  , slhdsaNativeSize
  , chachaStreamNativeSize
  , chachaPolyNativeSize
  ) where

import Control.Monad (guard)
import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map
import Data.Maybe (fromMaybe, isJust)
import Data.Text (Text)
import Data.Word (Word64, Word8)
import Foreign.C.String (CStringLen)
import Foreign.C.Types (CULong (..))
import Foreign.Ptr (Ptr, castPtr, nullPtr, plusPtr)
import Foreign.Storable (alignment, peekByteOff, sizeOf)

import Haskoki.FFI.Decode (maxInputBytes)
import Haskoki.Recipe.Ccm (ccmRecipeFor, encodeCcmParams)
import Haskoki.Recipe.Chacha20
  ( chachaName
  , chachaPolyTagLen
  , chachaRecipeFor
  , encodeChachaPolyParams
  , encodeChachaStreamParams
  )
import Haskoki.Recipe.Cipher (ctrRecipeFor, encodeCtrParams)
import Haskoki.Recipe.Ecdh (encodeEcdhParams)
import Haskoki.Recipe.Eddsa (eddsaRecipeFor, encodeEddsaParams)
import Haskoki.Recipe.Gcm (encodeGcmParams, gcmRecipeFor)
import Haskoki.Recipe.MlDsa (encodeMldsaParams, hedgeOfWord, mldsaRecipeFor)
import Haskoki.Recipe.SlhDsa (encodeSlhdsaParams, slhdsaRecipeFor)
import qualified Haskoki.Recipe.SlhDsa as SlhDsa
import Haskoki.Recipe.RsaOaep (encodeOaepParams, rsaOaepRecipeFor)
import Haskoki.Recipe.RsaPss (encodePssParams, rsaPssRecipeFor)
import Haskoki.Recipe.TlsPrf (encodeTlsPrfParams)
import Haskoki.Registry.Generated (mustGeneratedId)
import Haskoki.Registry.Types (MechanismId)

-- | Width of one @CK_ULONG@ word on this build.
wordSize :: Int
wordSize = sizeOf (undefined :: CULong)

-- | Width of one pointer on this build.
ptrSize :: Int
ptrSize = sizeOf (undefined :: Ptr Word8)

-- | Native @CK_RSA_PKCS_PSS_PARAMS@ image size: three words.
pssNativeSize :: Int
pssNativeSize = 3 * wordSize

-- | Native @CK_RSA_PKCS_OAEP_PARAMS@ image size: three words, one
-- pointer, one length.
oaepNativeSize :: Int
oaepNativeSize = 4 * wordSize + ptrSize

-- | Native @CK_ECDH1_DERIVE_PARAMS@ image size: one KDF word, then
-- (length, pointer) twice (shared data, peer public key).
ecdhNativeSize :: Int
ecdhNativeSize = 3 * wordSize + 2 * ptrSize

-- | Native @CK_TLS_PRF_PARAMS@ image size: (pointer, length) for
-- the seed, (pointer, length) for the label, then the output
-- pointer pair (ignored on the derive path — the output lands in
-- the derived object).
tlsPrfNativeSize :: Int
tlsPrfNativeSize = 2 * wordSize + 4 * ptrSize

-- | Native @CK_GCM_PARAMS@ image size: (pointer, length, bits) for
-- the IV, then (pointer, length) for the AAD, then the tag-bits
-- word.
gcmNativeSize :: Int
gcmNativeSize = 4 * wordSize + 2 * ptrSize

-- | Native @CK_AES_CCM_PARAMS@ (layout-identical to
-- @CK_CCM_PARAMS@) image size: the data-length word, (pointer,
-- length) for the nonce, (pointer, length) for the AAD, then the
-- MAC-length word. All lengths are BYTES (unlike GCM bits).
ccmNativeSize :: Int
ccmNativeSize = 4 * wordSize + 2 * ptrSize

-- | Native @CK_CHACHA20_PARAMS@ image size: (pointer, bits) for
-- the block counter, (pointer, bits) for the nonce. Both widths
-- are BITS (the GCM convention, unlike CCM bytes).
chachaStreamNativeSize :: Int
chachaStreamNativeSize = 2 * wordSize + 2 * ptrSize

-- | Native @CK_SALSA20_CHACHA20_POLY1305_PARAMS@ image size:
-- (pointer, length) for the nonce, (pointer, length) for the
-- AAD. Both lengths are BYTES (the CCM convention).
chachaPolyNativeSize :: Int
chachaPolyNativeSize = 2 * wordSize + 2 * ptrSize

-- | Native @CK_AES_CTR_PARAMS@ image size: one counter-bits word
-- plus the inline 16-byte counter block.
ctrNativeSize :: Int
ctrNativeSize = wordSize + 16

-- | Offset of @ulContextDataLen@ in a native @CK_EDDSA_PARAMS@
-- image: the @CK_BBOOL@ flag byte plus padding to the word
-- alignment. The header order is flag, length, pointer (the
-- pointer follows at @eddsaLenOff + wordSize@).
eddsaLenOff :: Int
eddsaLenOff = ((1 + wordAlign - 1) `div` wordAlign) * wordAlign
  where
    wordAlign = alignment (undefined :: CULong)

-- | Native @CK_EDDSA_PARAMS@ image size: the flag byte (plus
-- padding), one length word, one pointer.
eddsaNativeSize :: Int
eddsaNativeSize = eddsaLenOff + wordSize + ptrSize

-- | Native @CK_SIGN_ADDITIONAL_CONTEXT@ image size: the hedge
-- word, one pointer, one length word — all-word, 24 bytes on
-- LP64 (no padding traps; the header order is hedge, pointer,
-- length).
mldsaNativeSize :: Int
mldsaNativeSize = 2 * wordSize + ptrSize

-- | Native @CK_SIGN_ADDITIONAL_CONTEXT@ size for CKM_SLH_DSA:
-- same struct shape as ML-DSA (the header order is hedge,
-- pointer, length).
slhdsaNativeSize :: Int
slhdsaNativeSize = 2 * wordSize + ptrSize

-- | Native @CKM_*@ hash ids onto recipe digest stems. Ids come from
-- the generated vocabulary, so a header drift breaks the build
-- instead of mistranslating.
digestStemByCkm :: Map Word64 Text
digestStemByCkm = Map.fromList
  [ (mustGeneratedId "CKM_MD5", "MD5")
  , (mustGeneratedId "CKM_SHA_1", "SHA_1")
  , (mustGeneratedId "CKM_SHA224", "SHA224")
  , (mustGeneratedId "CKM_SHA256", "SHA256")
  , (mustGeneratedId "CKM_SHA384", "SHA384")
  , (mustGeneratedId "CKM_SHA512", "SHA512")
  , (mustGeneratedId "CKM_SHA3_224", "SHA3_224")
  , (mustGeneratedId "CKM_SHA3_256", "SHA3_256")
  , (mustGeneratedId "CKM_SHA3_384", "SHA3_384")
  , (mustGeneratedId "CKM_SHA3_512", "SHA3_512")
  , (mustGeneratedId "CKM_RIPEMD160", "RIPEMD160")
  ]

-- | Native @CKG_MGF1_*@ ids onto recipe digest stems. @CKG_*@ has no
-- generated vocabulary; the ids are numeric literals cited to
-- @spec/vendor/pkcs11.h:439-447@. There are no MGF1 ids for MD5 or
-- RIPEMD160, so those stems are unreachable here (correctly: no
-- caller can name them).
mgfStemByCkg :: Map Word64 Text
mgfStemByCkg = Map.fromList
  [ (0x01, "SHA_1")
  , (0x02, "SHA256")
  , (0x03, "SHA384")
  , (0x04, "SHA512")
  , (0x05, "SHA224")
  , (0x06, "SHA3_224")
  , (0x07, "SHA3_256")
  , (0x08, "SHA3_384")
  , (0x09, "SHA3_512")
  ]

-- | @CKZ_DATA_SPECIFIED@ (@spec/vendor/pkcs11.h:1224@): the only
-- OAEP label source with pointed-to bytes.
ckzDataSpecified :: Word64
ckzDataSpecified = 0x01

-- | @CKD_NULL@ (@spec/vendor/pkcs11.h:306@): the only served ECDH
-- KDF selector (canonical code 0).
ckdNull :: Word64
ckdNull = 0x01

-- | Pure PSS translation: native (hashAlg, mgf, sLen) words onto the
-- canonical @pss-params/1@ image. Unknown ids and unrepresentable
-- salt lengths refuse ('Nothing'); the recipe bounds the rest.
pssStructToCanonical :: Word64 -> Word64 -> Word64 -> Maybe ByteString
pssStructToCanonical hashId mgfId salt = do
  d <- Map.lookup hashId digestStemByCkm
  m <- Map.lookup mgfId mgfStemByCkg
  if salt > fromIntegral (maxBound :: Int)
    then Nothing
    else Just (encodePssParams d m (fromIntegral salt))

-- | Pure OAEP translation: native (hashAlg, mgf) words plus the
-- chased label onto the canonical @oaep-params/1@ image. Unknown ids
-- refuse ('Nothing').
oaepStructToCanonical :: Word64 -> Word64 -> ByteString -> Maybe ByteString
oaepStructToCanonical hashId mgfId label = do
  d <- Map.lookup hashId digestStemByCkm
  m <- Map.lookup mgfId mgfStemByCkg
  Just (encodeOaepParams d m label)

-- | Pure ECDH translation: the native KDF selector plus the chased
-- shared-data and peer-key bytes onto the canonical
-- @ecdh-params/1@ image. Only @CKD_NULL@ translates (canonical
-- code 0); every other selector refuses ('Nothing'). An empty peer
-- key translates and is refused downstream by the recipe
-- (invalid parameters, not a malformed struct).
ecdhStructToCanonical :: Word64 -> ByteString -> ByteString -> Maybe ByteString
ecdhStructToCanonical kdf shared peer
  | kdf /= ckdNull = Nothing
  | otherwise = Just (encodeEcdhParams 0 shared peer)

-- | Pure TLS-PRF translation: the chased label and seed onto the
-- canonical @tls-prf-params\/1@ image. The over-ceiling refusal
-- lives downstream (the recipe validation in 'planDerive'); the
-- chase bounds plus that check fail the shape closed.
tlsPrfStructToCanonical :: ByteString -> ByteString -> Maybe ByteString
tlsPrfStructToCanonical lab seed = Just (encodeTlsPrfParams lab seed)

-- | Pure GCM translation: the chased IV and AAD plus the native
-- bit/tag widths onto the canonical @gcm-params/1@ image. The bit
-- width must agree with the chased IV length and the tag width
-- must be whole bytes; the IV must be caller-supplied, so the
-- provider-generated-IV convention (empty IV) never translates and
-- passes through to the recipe refusal downstream.
gcmStructToCanonical :: ByteString -> ByteString -> Word64 -> Word64 -> Maybe ByteString
gcmStructToCanonical iv aad ivBits tagBits = do
  guard (fromIntegral (BS.length iv) * 8 == ivBits)
  guard (tagBits `mod` 8 == 0)
  let tagLen = fromIntegral (tagBits `div` 8)
  guard (not (BS.null iv))
  pure (encodeGcmParams iv aad tagLen)

-- | Pure CCM translation: the chased nonce and AAD plus the
-- native byte lengths onto the canonical @ccm-params/1@ image.
-- The nonce length must agree with the chased nonce bytes; any
-- width translates (even unserved ones: the recipe refuses
-- downstream with the parameter CKR, never a malformed struct);
-- only an unrepresentable width refuses here.
ccmStructToCanonical :: ByteString -> ByteString -> Word64 -> Word64 -> Word64 -> Maybe ByteString
ccmStructToCanonical nonce aad dataLen nonceLen macLen = do
  guard (fromIntegral (BS.length nonce) == nonceLen)
  tagLen <- word64ToInt macLen
  dLen <- word64ToInt dataLen
  pure (encodeCcmParams nonce aad tagLen dLen)

-- | Pure ChaCha20 translation: the chased counter and nonce plus
-- the native bit widths onto the canonical @chacha20-params/1@
-- image. Both widths must agree with the chased bytes; the
-- counter decodes little-endian (the documented OASIS-gap
-- interpretation — RFC 8439 state-word order) and must fit an
-- 'Int'. Any width translates (even non-IETF ones: the recipe
-- refuses downstream with the parameter CKR, never a malformed
-- struct); only disagreement or an unrepresentable counter
-- refuses here.
chachaStreamStructToCanonical :: ByteString -> Word64 -> ByteString -> Word64 -> Maybe ByteString
chachaStreamStructToCanonical ctr ctrBits nonce nonceBits = do
  guard (fromIntegral (BS.length ctr) * 8 == ctrBits)
  guard (fromIntegral (BS.length nonce) * 8 == nonceBits)
  counter <- leWordToInt ctr
  pure (encodeChachaStreamParams counter nonce)

-- | Pure ChaCha20-Poly1305 translation: the chased nonce and AAD
-- plus the native byte lengths onto the canonical
-- @chacha20poly1305-params/1@ image at the fixed 16-byte tag.
-- Both lengths must agree with the chased bytes; any width
-- translates (off-12 nonces refuse downstream at the recipe).
chachaPolyStructToCanonical :: ByteString -> Word64 -> ByteString -> Word64 -> Maybe ByteString
chachaPolyStructToCanonical nonce nonceLen aad aadLen = do
  guard (fromIntegral (BS.length nonce) == nonceLen)
  guard (fromIntegral (BS.length aad) == aadLen)
  pure (encodeChachaPolyParams nonce aad chachaPolyTagLen)

-- | Decode a little-endian byte string (at most 8 bytes) onto an
-- 'Int'; 'Nothing' on over-width or overflow (mirrors the
-- recipe's LE IV framing, 'decodeChachaIv', generalized past 4
-- bytes for the 64-bit counter width).
leWordToInt :: ByteString -> Maybe Int
leWordToInt bs
  | BS.length bs > 8 = Nothing
  | otherwise = word64ToInt (BS.foldr (\b a -> a * 256 + fromIntegral b) 0 bs)

-- | Narrow a native bit width onto whole bytes; 'Nothing' on a
-- ragged width (the struct cannot name a sub-byte chase).
bitsToBytes :: Word64 -> Maybe Word64
bitsToBytes b
  | b `mod` 8 == 0 = Just (b `div` 8)
  | otherwise = Nothing

-- | Narrow one native word onto 'Int'; 'Nothing' when it does not
-- fit (which cannot encode downstream).
word64ToInt :: Word64 -> Maybe Int
word64ToInt w
  | w > fromIntegral (maxBound :: Int) = Nothing
  | otherwise = Just (fromIntegral w)

-- | Pure CTR translation: the native counter-bits word plus the
-- inline counter block onto the canonical @ctr-params/1@ image.
-- Any width translates (even unserved ones: the recipe refuses
-- downstream with the parameter CKR, never a malformed struct);
-- only an unrepresentable width refuses here.
ctrStructToCanonical :: Word64 -> ByteString -> Maybe ByteString
ctrStructToCanonical bits cb
  | bits > fromIntegral (maxBound :: Int) = Nothing
  | BS.length cb /= 16 = Nothing
  | otherwise = Just (encodeCtrParams (fromIntegral bits) cb)

-- | Pure EdDSA translation: the native @CK_BBOOL@ prehash flag
-- plus the chased context bytes onto the canonical
-- @eddsa-params/1@ image. Only flags 0/1 translate; anything
-- else refuses ('Nothing'). Non-pure combinations translate and
-- are refused downstream by the recipe (invalid parameters, not
-- a malformed struct).
eddsaStructToCanonical :: Word8 -> ByteString -> Maybe ByteString
eddsaStructToCanonical flag ctx
  | flag == 0 = Just (encodeEddsaParams False ctx)
  | flag == 1 = Just (encodeEddsaParams True ctx)
  | otherwise = Nothing

-- | ML-DSA translation: the native @CK_HEDGE_TYPE@ word plus the
-- chased context onto the canonical @mldsa-params/1@ image. Only
-- words 0/1/2 translate (the bound check runs on the 'Word64'
-- before narrowing, so no wrap-around can smuggle a hedge);
-- anything else passes through.
mldsaStructToCanonical :: Word64 -> ByteString -> Maybe ByteString
mldsaStructToCanonical hedge ctx
  | hedge > 2 = Nothing
  | otherwise = case hedgeOfWord (fromIntegral hedge) of
      Just h -> Just (encodeMldsaParams h ctx)
      Nothing -> Nothing

-- | SLH-DSA translation: the native @CK_HEDGE_TYPE@ word plus the
-- chased context onto the canonical @slhdsa-params/1@ image
-- (same struct shape as ML-DSA — @CK_SIGN_ADDITIONAL_CONTEXT@
-- is shared). Only words 0/1/2 translate; anything else passes
-- through.
slhdsaStructToCanonical :: Word64 -> ByteString -> Maybe ByteString
slhdsaStructToCanonical hedge ctx
  | hedge > 2 = Nothing
  | otherwise = case SlhDsa.hedgeOfWord (fromIntegral hedge) of
      Just h -> Just (encodeSlhdsaParams h ctx)
      Nothing -> Nothing

-- | Chase one bounded byte string from caller memory under the
-- 'decodeInputBytes' null conventions: zero length never
-- dereferences, null-with-length and over-bound lengths refuse.
chaseBytes :: Ptr Word8 -> Word64 -> IO (Maybe ByteString)
chaseBytes ptr len
  | len == 0 = pure (Just BS.empty)
  | ptr == nullPtr = pure Nothing
  | len > maxInputBytes = pure Nothing
  | otherwise = do
      let cstr :: CStringLen
          cstr = (castPtr ptr, fromIntegral len)
      Just <$> BS.packCStringLen cstr

-- | Normalize one ECDH agreement struct: the native
-- @CK_ECDH1_DERIVE_PARAMS@ image at @pParams@/@paramsLen@ onto the
-- canonical @ecdh-params/1@ image. Wrong-sized images, non-null KDF
-- selectors, and null-with-length or over-bound shared/peer chases
-- refuse ('Nothing').
normalizeEcdhParams :: Ptr Word8 -> Word64 -> IO (Maybe ByteString)
normalizeEcdhParams pParams paramsLen
  | paramsLen /= fromIntegral ecdhNativeSize = pure Nothing
  | otherwise = do
      CULong kdf <- peekByteOff pParams 0
      CULong sharedLen <- peekByteOff pParams wordSize
      pShared <- peekByteOff pParams (2 * wordSize)
      CULong pubLen <- peekByteOff pParams (2 * wordSize + ptrSize)
      pPub <- peekByteOff pParams (3 * wordSize + ptrSize)
      mShared <- chaseBytes pShared sharedLen
      mPub <- chaseBytes pPub pubLen
      pure (mShared >>= \shared -> mPub >>= ecdhStructToCanonical kdf shared)

-- | Normalize one TLS-PRF struct: the native @CK_TLS_PRF_PARAMS@
-- image at @pParams@/@paramsLen@ onto the canonical
-- @tls-prf-params\/1@ image. Wrong-sized images and null-with-length
-- or over-bound seed\/label chases refuse ('Nothing'). The output
-- pointer pair is ignored (the derive path publishes objects, not
-- caller buffers).
normalizeTlsPrfParams :: Ptr Word8 -> Word64 -> IO (Maybe ByteString)
normalizeTlsPrfParams pParams paramsLen
  | paramsLen /= fromIntegral tlsPrfNativeSize = pure Nothing
  | otherwise = do
      pSeed <- peekByteOff pParams 0
      CULong seedLen <- peekByteOff pParams ptrSize
      pLabel <- peekByteOff pParams (ptrSize + wordSize)
      CULong labelLen <- peekByteOff pParams (2 * ptrSize + wordSize)
      mSeed <- chaseBytes pSeed seedLen
      mLabel <- chaseBytes pLabel labelLen
      pure (mSeed >>= \seed -> mLabel >>= \lab -> tlsPrfStructToCanonical lab seed)

-- | Normalize one call's mechanism parameters: struct mechanisms
-- translate from the live caller image at @pParams@/@paramsLen@
-- (already length-checked by 'decodeInputBytes', whose copy is
-- @raw@); every other mechanism passes @raw@ through. Unmappable
-- struct images also pass through, preserving today's recipe
-- refusal.
normalizeMechParams
  :: MechanismId -> Ptr Word8 -> Word64 -> ByteString -> IO ByteString
normalizeMechParams mid pParams paramsLen raw
  | isJust (rsaPssRecipeFor mid) = fromMaybe raw <$> decodePssNative
  | isJust (rsaOaepRecipeFor mid) = fromMaybe raw <$> decodeOaepNative
  | isJust (gcmRecipeFor mid) = fromMaybe raw <$> decodeGcmNative
  | isJust (ccmRecipeFor mid) = fromMaybe raw <$> decodeCcmNative
  | isJust (ctrRecipeFor mid) = fromMaybe raw <$> decodeCtrNative
  | isJust (eddsaRecipeFor mid) = fromMaybe raw <$> decodeEddsaNative
  | isJust (mldsaRecipeFor mid) = fromMaybe raw <$> decodeMldsaNative
  | isJust (slhdsaRecipeFor mid) = fromMaybe raw <$> decodeSlhdsaNative
  | Just r <- chachaRecipeFor mid, chachaName r == "CKM_CHACHA20" =
      fromMaybe raw <$> decodeChachaStreamNative
  | Just r <- chachaRecipeFor mid, chachaName r == "CKM_CHACHA20_POLY1305" =
      fromMaybe raw <$> decodeChachaPolyNative
  | otherwise = pure raw
  where
    decodePssNative :: IO (Maybe ByteString)
    decodePssNative
      | paramsLen /= fromIntegral pssNativeSize = pure Nothing
      | otherwise = do
          CULong hashId <- peekByteOff pParams 0
          CULong mgfId <- peekByteOff pParams wordSize
          CULong salt <- peekByteOff pParams (2 * wordSize)
          pure (pssStructToCanonical hashId mgfId salt)
    decodeOaepNative :: IO (Maybe ByteString)
    decodeOaepNative
      | paramsLen /= fromIntegral oaepNativeSize = pure Nothing
      | otherwise = do
          CULong hashId <- peekByteOff pParams 0
          CULong mgfId <- peekByteOff pParams wordSize
          CULong source <- peekByteOff pParams (2 * wordSize)
          pLabel <- peekByteOff pParams (3 * wordSize)
          CULong labelLen <- peekByteOff pParams (3 * wordSize + ptrSize)
          if source /= ckzDataSpecified
            then pure Nothing
            else do
              mLabel <- chaseBytes pLabel labelLen
              pure (mLabel >>= oaepStructToCanonical hashId mgfId)
    decodeGcmNative :: IO (Maybe ByteString)
    decodeGcmNative
      | paramsLen /= fromIntegral gcmNativeSize = pure Nothing
      | otherwise = do
          pIv <- peekByteOff pParams 0
          CULong ivLen <- peekByteOff pParams ptrSize
          CULong ivBits <- peekByteOff pParams (ptrSize + wordSize)
          pAad <- peekByteOff pParams (ptrSize + 2 * wordSize)
          CULong aadLen <- peekByteOff pParams (2 * ptrSize + 2 * wordSize)
          CULong tagBits <- peekByteOff pParams (2 * ptrSize + 3 * wordSize)
          mIv <- chaseBytes pIv ivLen
          mAad <- chaseBytes pAad aadLen
          pure (mIv >>= \iv -> mAad >>= \aad -> gcmStructToCanonical iv aad ivBits tagBits)
    decodeCcmNative :: IO (Maybe ByteString)
    decodeCcmNative
      | paramsLen /= fromIntegral ccmNativeSize = pure Nothing
      | otherwise = do
          CULong dataLen <- peekByteOff pParams 0
          pNonce <- peekByteOff pParams wordSize
          CULong nonceLen <- peekByteOff pParams (wordSize + ptrSize)
          pAad <- peekByteOff pParams (2 * wordSize + ptrSize)
          CULong aadLen <- peekByteOff pParams (2 * wordSize + 2 * ptrSize)
          CULong macLen <- peekByteOff pParams (3 * wordSize + 2 * ptrSize)
          mNonce <- chaseBytes pNonce nonceLen
          mAad <- chaseBytes pAad aadLen
          pure (mNonce >>= \nonce -> mAad >>= \aad -> ccmStructToCanonical nonce aad dataLen nonceLen macLen)
    decodeCtrNative :: IO (Maybe ByteString)
    decodeCtrNative
      | paramsLen /= fromIntegral ctrNativeSize = pure Nothing
      | otherwise = do
          CULong bits <- peekByteOff pParams 0
          cb <- BS.packCStringLen (castPtr (pParams `plusPtr` wordSize), 16)
          pure (ctrStructToCanonical bits cb)
    decodeEddsaNative :: IO (Maybe ByteString)
    decodeEddsaNative
      | paramsLen /= fromIntegral eddsaNativeSize = pure Nothing
      | otherwise = do
          flag <- peekByteOff pParams 0
          CULong ctxLen <- peekByteOff pParams eddsaLenOff
          pCtx <- peekByteOff pParams (eddsaLenOff + wordSize)
          mCtx <- chaseBytes pCtx ctxLen
          pure (mCtx >>= eddsaStructToCanonical flag)
    decodeMldsaNative :: IO (Maybe ByteString)
    decodeMldsaNative
      | paramsLen /= fromIntegral mldsaNativeSize = pure Nothing
      | otherwise = do
          CULong hedge <- peekByteOff pParams 0
          pCtx <- peekByteOff pParams wordSize
          CULong ctxLen <- peekByteOff pParams (wordSize + ptrSize)
          mCtx <- chaseBytes pCtx ctxLen
          pure (mCtx >>= mldsaStructToCanonical hedge)
    decodeSlhdsaNative :: IO (Maybe ByteString)
    decodeSlhdsaNative
      | paramsLen /= fromIntegral slhdsaNativeSize = pure Nothing
      | otherwise = do
          CULong hedge <- peekByteOff pParams 0
          pCtx <- peekByteOff pParams wordSize
          CULong ctxLen <- peekByteOff pParams (wordSize + ptrSize)
          mCtx <- chaseBytes pCtx ctxLen
          pure (mCtx >>= slhdsaStructToCanonical hedge)
    decodeChachaStreamNative :: IO (Maybe ByteString)
    decodeChachaStreamNative
      | paramsLen /= fromIntegral chachaStreamNativeSize = pure Nothing
      | otherwise = do
          pCtr <- peekByteOff pParams 0
          CULong ctrBits <- peekByteOff pParams ptrSize
          pNonce <- peekByteOff pParams (ptrSize + wordSize)
          CULong nonceBits <- peekByteOff pParams (2 * ptrSize + wordSize)
          case (bitsToBytes ctrBits, bitsToBytes nonceBits) of
            (Just ctrLen, Just nonceLen) -> do
              mCtr <- chaseBytes pCtr ctrLen
              mNonce <- chaseBytes pNonce nonceLen
              pure (mCtr >>= \ctr -> mNonce >>= \nonce ->
                chachaStreamStructToCanonical ctr ctrBits nonce nonceBits)
            _ -> pure Nothing
    decodeChachaPolyNative :: IO (Maybe ByteString)
    decodeChachaPolyNative
      | paramsLen /= fromIntegral chachaPolyNativeSize = pure Nothing
      | otherwise = do
          pNonce <- peekByteOff pParams 0
          CULong nonceLen <- peekByteOff pParams ptrSize
          pAad <- peekByteOff pParams (ptrSize + wordSize)
          CULong aadLen <- peekByteOff pParams (2 * ptrSize + wordSize)
          mNonce <- chaseBytes pNonce nonceLen
          mAad <- chaseBytes pAad aadLen
          pure (mNonce >>= \nonce -> mAad >>= \aad ->
            chachaPolyStructToCanonical nonce nonceLen aad aadLen)
