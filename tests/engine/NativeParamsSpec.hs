{- | Caller-native mechanism structs into the recipe canonical codecs.

Exercises 'Haskoki.FFI.NativeParams.normalizeMechParams' against
real native struct images built with 'Foreign.Storable' (host order,
'Storable'-derived widths — the same layout a C caller produces):
PSS structs translate to @pss-params/1@, OAEP structs chase the
label pointer into @oaep-params/1@, and anything unmappable passes
through byte-identical so the recipe refusal is unchanged. The
translated images must validate under the owning recipes; C-ABI
execution (sign/verify, encrypt/decrypt round-trips) is pinned by
the consumer suite.
-}
{-# LANGUAGE OverloadedStrings #-}
module NativeParamsSpec (spec) where

import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import Data.Word (Word8)
import Foreign.C.Types (CULong (..))
import Foreign.Marshal.Alloc (allocaBytes)
import Foreign.Ptr (Ptr, castPtr, nullPtr)
import Foreign.Storable (pokeByteOff, sizeOf)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertEqual, testCase)

import Haskoki.FFI.NativeParams
  ( digestStemByCkm
  , ecdhNativeSize
  , gcmNativeSize
  , mgfStemByCkg
  , normalizeEcdhParams
  , normalizeMechParams
  , oaepNativeSize
  , pssNativeSize
  )
import Haskoki.Recipe.Ecdh (ecdhParamsValid, ecdhRecipeFor, encodeEcdhParams)
import Haskoki.Recipe.Gcm (encodeGcmParams, gcmParamsValid, gcmRecipeFor)
import Haskoki.Recipe.RsaOaep
  ( encodeOaepParams
  , rsaOaepParamsValid
  , rsaOaepRecipeFor
  )
import Haskoki.Recipe.RsaPss
  ( encodePssParams
  , rsaPssParamsValid
  , rsaPssRecipeFor
  )
import Haskoki.Registry.Generated (mustGeneratedId)
import Haskoki.Registry.Types (MechanismId (..))

spec :: TestTree
spec = testGroup "native mechanism params"
  [ testCase "pss native struct translates to canonical" $ do
      let mid = MechanismId (mustGeneratedId "CKM_RSA_PKCS_PSS")
          hash = mustGeneratedId "CKM_SHA256"
          w = sizeOf (undefined :: CULong)
      out <- allocaBytes pssNativeSize $ \p -> do
        pokeByteOff p 0 (CULong hash)
        pokeByteOff p w (CULong 0x02)
        pokeByteOff p (2 * w) (CULong 32)
        raw <- BS.packCStringLen (castPtr p, pssNativeSize)
        normalizeMechParams mid p (fromIntegral pssNativeSize) raw
      let want = encodePssParams "SHA256" "SHA256" 32
      assertEqual "canonical pss image" want out
      case rsaPssRecipeFor mid of
        Nothing -> fail "pss recipe missing"
        Just r -> assertEqual "recipe accepts" True (rsaPssParamsValid r out)
  , testCase "pss digest-bound row keeps its binding" $ do
      let mid = MechanismId (mustGeneratedId "CKM_SHA384_RSA_PKCS_PSS")
          hash = mustGeneratedId "CKM_SHA384"
          w = sizeOf (undefined :: CULong)
      out <- allocaBytes pssNativeSize $ \p -> do
        pokeByteOff p 0 (CULong hash)
        pokeByteOff p w (CULong 0x03)
        pokeByteOff p (2 * w) (CULong 48)
        raw <- BS.packCStringLen (castPtr p, pssNativeSize)
        normalizeMechParams mid p (fromIntegral pssNativeSize) raw
      assertEqual "canonical pss image"
        (encodePssParams "SHA384" "SHA384" 48) out
  , testCase "pss unknown hash id passes through" $ do
      let mid = MechanismId (mustGeneratedId "CKM_RSA_PKCS_PSS")
          w = sizeOf (undefined :: CULong)
      (raw, out) <- allocaBytes pssNativeSize $ \p -> do
        pokeByteOff p 0 (CULong 0xDEAD)
        pokeByteOff p w (CULong 0x02)
        pokeByteOff p (2 * w) (CULong 32)
        raw <- BS.packCStringLen (castPtr p, pssNativeSize)
        out <- normalizeMechParams mid p (fromIntegral pssNativeSize) raw
        pure (raw, out)
      assertEqual "passthrough" raw out
  , testCase "pss short image passes through" $ do
      let mid = MechanismId (mustGeneratedId "CKM_RSA_PKCS_PSS")
          raw = BS.replicate 8 0
      out <- allocaBytes 8 $ \p -> do
        pokeByteOff p 0 (CULong 0x250 :: CULong)
        normalizeMechParams mid p 8 raw
      assertEqual "passthrough" raw out
  , testCase "gcm native struct chases iv and aad" $ do
      let mid = MechanismId (mustGeneratedId "CKM_AES_GCM")
          iv = "0123456789ab" :: ByteString
          aad = "AD" :: ByteString
          w = sizeOf (undefined :: CULong)
          pw = sizeOf (undefined :: Ptr Word8)
      out <- BS.useAsCStringLen iv $ \(ivp, ivlen) ->
        BS.useAsCStringLen aad $ \(aadp, aadlen) ->
          allocaBytes gcmNativeSize $ \p -> do
            pokeByteOff p 0 (castPtr ivp)
            pokeByteOff p pw (CULong (fromIntegral ivlen))
            pokeByteOff p (pw + w) (CULong (fromIntegral (ivlen * 8)))
            pokeByteOff p (pw + 2 * w) (castPtr aadp)
            pokeByteOff p (2 * pw + 2 * w) (CULong (fromIntegral aadlen))
            pokeByteOff p (2 * pw + 3 * w) (CULong 128)
            raw <- BS.packCStringLen (castPtr p, gcmNativeSize)
            normalizeMechParams mid p (fromIntegral gcmNativeSize) raw
      let want = encodeGcmParams iv aad 16
      assertEqual "canonical gcm image" want out
      case gcmRecipeFor mid of
        Nothing -> fail "gcm recipe missing"
        Just r -> assertEqual "recipe accepts" True (gcmParamsValid r out)
  , testCase "gcm generated-iv convention passes through" $ do
      let mid = MechanismId (mustGeneratedId "CKM_AES_GCM")
          w = sizeOf (undefined :: CULong)
          pw = sizeOf (undefined :: Ptr Word8)
      (raw, out) <- allocaBytes gcmNativeSize $ \p -> do
        pokeByteOff p 0 (nullPtr :: Ptr Word8)
        pokeByteOff p pw (CULong 0)
        pokeByteOff p (pw + w) (CULong 96)
        pokeByteOff p (pw + 2 * w) (nullPtr :: Ptr Word8)
        pokeByteOff p (2 * pw + 2 * w) (CULong 0)
        pokeByteOff p (2 * pw + 3 * w) (CULong 128)
        raw <- BS.packCStringLen (castPtr p, gcmNativeSize)
        out <- normalizeMechParams mid p (fromIntegral gcmNativeSize) raw
        pure (raw, out)
      assertEqual "passthrough" raw out
  , testCase "oaep native struct chases the label" $ do
      let mid = MechanismId (mustGeneratedId "CKM_RSA_PKCS_OAEP")
          hash = mustGeneratedId "CKM_SHA256"
          label = "mylabel" :: ByteString
          w = sizeOf (undefined :: CULong)
          pw = sizeOf (undefined :: Ptr Word8)
      out <- BS.useAsCStringLen label $ \(lp, llen) ->
        allocaBytes oaepNativeSize $ \p -> do
          pokeByteOff p 0 (CULong hash)
          pokeByteOff p w (CULong 0x02)
          pokeByteOff p (2 * w) (CULong 0x01)
          pokeByteOff p (3 * w) (castPtr lp)
          pokeByteOff p (3 * w + pw) (CULong (fromIntegral llen))
          raw <- BS.packCStringLen (castPtr p, oaepNativeSize)
          normalizeMechParams mid p (fromIntegral oaepNativeSize) raw
      let want = encodeOaepParams "SHA256" "SHA256" label
      assertEqual "canonical oaep image" want out
      case rsaOaepRecipeFor mid of
        Nothing -> fail "oaep recipe missing"
        Just r -> assertEqual "recipe accepts" True (rsaOaepParamsValid r out)
  , testCase "oaep empty label skips the pointer" $ do
      let mid = MechanismId (mustGeneratedId "CKM_RSA_PKCS_OAEP")
          hash = mustGeneratedId "CKM_SHA_1"
          w = sizeOf (undefined :: CULong)
          pw = sizeOf (undefined :: Ptr Word8)
      out <- allocaBytes oaepNativeSize $ \p -> do
        pokeByteOff p 0 (CULong hash)
        pokeByteOff p w (CULong 0x01)
        pokeByteOff p (2 * w) (CULong 0x01)
        pokeByteOff p (3 * w) (nullPtr :: Ptr Word8)
        pokeByteOff p (3 * w + pw) (CULong 0)
        raw <- BS.packCStringLen (castPtr p, oaepNativeSize)
        normalizeMechParams mid p (fromIntegral oaepNativeSize) raw
      assertEqual "canonical oaep image"
        (encodeOaepParams "SHA_1" "SHA_1" BS.empty) out
  , testCase "oaep null label with length passes through" $ do
      let mid = MechanismId (mustGeneratedId "CKM_RSA_PKCS_OAEP")
          hash = mustGeneratedId "CKM_SHA256"
          w = sizeOf (undefined :: CULong)
          pw = sizeOf (undefined :: Ptr Word8)
      (raw, out) <- allocaBytes oaepNativeSize $ \p -> do
        pokeByteOff p 0 (CULong hash)
        pokeByteOff p w (CULong 0x02)
        pokeByteOff p (2 * w) (CULong 0x01)
        pokeByteOff p (3 * w) (nullPtr :: Ptr Word8)
        pokeByteOff p (3 * w + pw) (CULong 7)
        raw <- BS.packCStringLen (castPtr p, oaepNativeSize)
        out <- normalizeMechParams mid p (fromIntegral oaepNativeSize) raw
        pure (raw, out)
      assertEqual "passthrough" raw out
  , testCase "oaep non-data source passes through" $ do
      let mid = MechanismId (mustGeneratedId "CKM_RSA_PKCS_OAEP")
          hash = mustGeneratedId "CKM_SHA256"
          w = sizeOf (undefined :: CULong)
          pw = sizeOf (undefined :: Ptr Word8)
      (raw, out) <- allocaBytes oaepNativeSize $ \p -> do
        pokeByteOff p 0 (CULong hash)
        pokeByteOff p w (CULong 0x02)
        pokeByteOff p (2 * w) (CULong 0x00)
        pokeByteOff p (3 * w) (nullPtr :: Ptr Word8)
        pokeByteOff p (3 * w + pw) (CULong 0)
        raw <- BS.packCStringLen (castPtr p, oaepNativeSize)
        out <- normalizeMechParams mid p (fromIntegral oaepNativeSize) raw
        pure (raw, out)
      assertEqual "passthrough" raw out
  , testCase "non-struct mechanism is identity" $ do
      let mid = MechanismId (mustGeneratedId "CKM_SHA256_HMAC")
          raw = BS.pack [1, 2, 3, 4, 5, 6, 7, 8]
      out <- BS.useAsCStringLen raw $ \(p, _) ->
        normalizeMechParams mid (castPtr p) (fromIntegral (BS.length raw)) raw
      assertEqual "identity" raw out
  , testCase "id tables cover the recipe stems" $ do
      assertEqual "ckm table size" 11 (length digestStemByCkm)
      assertEqual "ckg table size" 9 (length mgfStemByCkg)
  , testCase "ecdh native struct chases shared and peer" $ do
      let mid = MechanismId (mustGeneratedId "CKM_ECDH1_DERIVE")
          shared = "shared-info" :: ByteString
          peer = BS.replicate 65 0x04
          w = sizeOf (undefined :: CULong)
          pw = sizeOf (undefined :: Ptr Word8)
      out <- BS.useAsCStringLen shared $ \(sp, slen) ->
        BS.useAsCStringLen peer $ \(pp, plen) ->
          allocaBytes ecdhNativeSize $ \p -> do
            pokeByteOff p 0 (CULong 0x01)
            pokeByteOff p w (CULong (fromIntegral slen))
            pokeByteOff p (2 * w) (castPtr sp)
            pokeByteOff p (2 * w + pw) (CULong (fromIntegral plen))
            pokeByteOff p (3 * w + pw) (castPtr pp)
            normalizeEcdhParams p (fromIntegral ecdhNativeSize)
      let want = encodeEcdhParams 0 shared peer
      assertEqual "canonical ecdh image" (Just want) out
      case (out, ecdhRecipeFor mid) of
        (Just canon, Just r) ->
          assertEqual "recipe accepts" True (ecdhParamsValid r canon)
        _ -> fail "ecdh recipe or image missing"
  , testCase "ecdh non-null kdf refuses" $ do
      let w = sizeOf (undefined :: CULong)
          pw = sizeOf (undefined :: Ptr Word8)
          peer = BS.replicate 65 0x04
      out <- BS.useAsCStringLen peer $ \(pp, plen) ->
        allocaBytes ecdhNativeSize $ \p -> do
          pokeByteOff p 0 (CULong 0x02)
          pokeByteOff p w (CULong 0)
          pokeByteOff p (2 * w) (nullPtr :: Ptr Word8)
          pokeByteOff p (2 * w + pw) (CULong (fromIntegral plen))
          pokeByteOff p (3 * w + pw) (castPtr pp)
          normalizeEcdhParams p (fromIntegral ecdhNativeSize)
      assertEqual "refused" Nothing out
  , testCase "ecdh null peer with length refuses" $ do
      let w = sizeOf (undefined :: CULong)
          pw = sizeOf (undefined :: Ptr Word8)
      out <- allocaBytes ecdhNativeSize $ \p -> do
        pokeByteOff p 0 (CULong 0x01)
        pokeByteOff p w (CULong 0)
        pokeByteOff p (2 * w) (nullPtr :: Ptr Word8)
        pokeByteOff p (2 * w + pw) (CULong 65)
        pokeByteOff p (3 * w + pw) (nullPtr :: Ptr Word8)
        normalizeEcdhParams p (fromIntegral ecdhNativeSize)
      assertEqual "refused" Nothing out
  , testCase "ecdh short image refuses" $ do
      out <- allocaBytes 8 $ \p -> do
        pokeByteOff p 0 (CULong 0x01 :: CULong)
        normalizeEcdhParams p 8
      assertEqual "refused" Nothing out
  ]
