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

Anything unmappable — wrong length, unknown ids, a bad source tag,
an unreadable label — passes the input bytes through untouched, so
the recipe refusal (and its @CKR@) is exactly today's: the
normalizer only ever turns a would-be refusal into an acceptance
when the native struct is fully understood. In particular the
historical canonical byte images still validate, since their words
never parse as mapped native ids.
-}
{-# LANGUAGE OverloadedStrings #-}
module Haskoki.FFI.NativeParams
  ( normalizeMechParams
  , normalizeEcdhParams
  , pssStructToCanonical
  , oaepStructToCanonical
  , ecdhStructToCanonical
  , gcmStructToCanonical
  , digestStemByCkm
  , mgfStemByCkg
  , pssNativeSize
  , oaepNativeSize
  , ecdhNativeSize
  , gcmNativeSize
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
import Foreign.Ptr (Ptr, castPtr, nullPtr)
import Foreign.Storable (peekByteOff, sizeOf)

import Haskoki.FFI.Decode (maxInputBytes)
import Haskoki.Recipe.Ecdh (encodeEcdhParams)
import Haskoki.Recipe.Gcm (encodeGcmParams, gcmRecipeFor)
import Haskoki.Recipe.RsaOaep (encodeOaepParams, rsaOaepRecipeFor)
import Haskoki.Recipe.RsaPss (encodePssParams, rsaPssRecipeFor)
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

-- | Native @CK_GCM_PARAMS@ image size: (pointer, length, bits) for
-- the IV, then (pointer, length) for the AAD, then the tag-bits
-- word.
gcmNativeSize :: Int
gcmNativeSize = 4 * wordSize + 2 * ptrSize

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
-- selectors, and unreadable shared/peer bytes refuse ('Nothing').
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
