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
import Foreign.Marshal.Utils (copyBytes)
import Foreign.Ptr (Ptr, castPtr, nullPtr, plusPtr)
import Foreign.Storable (alignment, pokeByteOff, sizeOf)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertBool, assertEqual, testCase)

import Haskoki.FFI.NativeParams
  ( chachaPolyNativeSize
  , chachaStreamNativeSize
  , dhX942NativeSize
  , digestStemByCkm
  , ecdhNativeSize
  , eddsaNativeSize
  , gcmNativeSize
  , mgfStemByCkg
  , mldsaNativeSize
  , normalizeDhPkcsParams
  , normalizeDhX942Params
  , normalizeEcdhParams
  , encryptDataCbcNativeSize
  , encryptDataEcbNativeSize
  , normalizeEncryptDataCbcParams
  , normalizeEncryptDataEcbParams
  , normalizeMechParams
  , normalizeByteOpsConcatKeyParams
  , normalizeByteOpsStringDataParams
  , normalizeByteOpsExtractParams
  , byteOpsUlongNativeSize
  , byteOpsStringDataNativeSize
  , normalizeSp800KdfParams
  , normalizeTlsKeyMatParams
  , normalizeTls12KeyMatParams
  , normalizeTls12KeySafeParams
  , normalizePbeParams
  , pbeParamsNativeSize
  , tlsKeyMatNativeSize
  , tls12KeyMatNativeSize
  , KeyMatSlots (..)
  , DerivedKeySlot (..)
  , normalizeIke1ExtParams
  , normalizeIke1PrfParams
  , normalizeIkePrfParams
  , normalizeIkePrfPlusParams
  , ike1ExtNativeSize
  , ike1PrfNativeSize
  , ikePrfNativeSize
  , ikePrfPlusNativeSize
  , oaepNativeSize
  , pssNativeSize
  )
import Haskoki.Recipe.Chacha20
  ( chachaParamsValid
  , chachaRecipeFor
  , encodeChachaPolyParams
  , encodeChachaStreamParams
  )
import Haskoki.Recipe.Dh (dhParamsValid, dhRecipeFor, encodeDhParams)
import Haskoki.Recipe.Ecdh (ecdhParamsValid, ecdhRecipeFor, encodeEcdhParams)
import Haskoki.Recipe.EncryptData (encryptDataParamsValid, encryptDataRecipeFor)
import Haskoki.Recipe.Eddsa
  ( eddsaParamsValid
  , eddsaRecipeFor
  , encodeEddsaParams
  )
import Haskoki.Recipe.Gcm (encodeGcmParams, gcmParamsValid, gcmRecipeFor)
import Haskoki.Recipe.ByteOps (encodeByteOpsParams, byteOpsParamsValid, byteOpsRecipeFor)
import Haskoki.Recipe.Ike (encodeIkeParams, ikeParamsValid, ikeRecipeFor)
import Haskoki.Recipe.Sp800108 (Sp800Mode (..), decodeSp800Params)
import Haskoki.Recipe.TlsKeyMat (encodeTlsKeyMatParams, tlsKeyMatParamsValid, tlsKeyMatRecipeFor)
import Haskoki.Recipe.Pbe (encodePbeParams, pbeParamsValid, pbeRecipeFor)
import Haskoki.Attribute (AttributeType (..), AttributeValue (..))
import Haskoki.Recipe.Gmac (gmacParamsValid, gmacRecipeFor)
import Haskoki.Recipe.MlDsa
  ( MldsaHedge (..)
  , encodeMldsaParams
  , mldsaParamsValid
  , mldsaRecipeFor
  )
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
  , testCase "gmac native struct shares the gcm chase" $ do
      let mid = MechanismId (mustGeneratedId "CKM_AES_GMAC")
          iv = "0123456789ab" :: ByteString
          w = sizeOf (undefined :: CULong)
          pw = sizeOf (undefined :: Ptr Word8)
      out <- BS.useAsCStringLen iv $ \(ivp, ivlen) ->
          allocaBytes gcmNativeSize $ \p -> do
            pokeByteOff p 0 (castPtr ivp)
            pokeByteOff p pw (CULong (fromIntegral ivlen))
            pokeByteOff p (pw + w) (CULong (fromIntegral (ivlen * 8)))
            pokeByteOff p (pw + 2 * w) (nullPtr :: Ptr Word8)
            pokeByteOff p (2 * pw + 2 * w) (CULong 0)
            pokeByteOff p (2 * pw + 3 * w) (CULong 128)
            raw <- BS.packCStringLen (castPtr p, gcmNativeSize)
            normalizeMechParams mid p (fromIntegral gcmNativeSize) raw
      let want = encodeGcmParams iv BS.empty 16
      assertEqual "canonical gmac image" want out
      case gmacRecipeFor mid of
        Nothing -> fail "gmac recipe missing"
        Just r -> assertEqual "recipe accepts" True (gmacParamsValid r out)
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
  , testCase "encrypt-data cbc-16 struct chases iv and data" $ do
      let mid = MechanismId (mustGeneratedId "CKM_AES_CBC_ENCRYPT_DATA")
          iv = BS.replicate 16 0xcb
          dat = BS.replicate 32 0xda
          pw = sizeOf (undefined :: Ptr Word8)
      out <- BS.useAsCStringLen dat $ \(dp, dlen) ->
        BS.useAsCStringLen iv $ \(ip, _) ->
          allocaBytes (encryptDataCbcNativeSize 16) $ \p -> do
            copyBytes p ip 16
            pokeByteOff p 16 (castPtr dp :: Ptr Word8)
            pokeByteOff p (16 + pw) (CULong (fromIntegral dlen))
            normalizeEncryptDataCbcParams 16 (castPtr p)
              (fromIntegral (encryptDataCbcNativeSize 16))
      assertEqual "canonical frame" (Just (iv <> dat)) out
      case (out, encryptDataRecipeFor mid) of
        (Just canon, Just r) ->
          assertEqual "recipe accepts" True (encryptDataParamsValid r canon)
        _ -> fail "encrypt-data recipe or frame missing"
  , testCase "encrypt-data cbc-8 struct chases iv and data" $ do
      let iv = BS.replicate 8 0xcb
          dat = BS.replicate 16 0xda
          pw = sizeOf (undefined :: Ptr Word8)
      out <- BS.useAsCStringLen dat $ \(dp, dlen) ->
        BS.useAsCStringLen iv $ \(ip, _) ->
          allocaBytes (encryptDataCbcNativeSize 8) $ \p -> do
            copyBytes p ip 8
            pokeByteOff p 8 (castPtr dp :: Ptr Word8)
            pokeByteOff p (8 + pw) (CULong (fromIntegral dlen))
            normalizeEncryptDataCbcParams 8 (castPtr p)
              (fromIntegral (encryptDataCbcNativeSize 8))
      assertEqual "canonical frame" (Just (iv <> dat)) out
  , testCase "encrypt-data null data with length refuses" $ do
      let pw = sizeOf (undefined :: Ptr Word8)
      out <- allocaBytes (encryptDataCbcNativeSize 16) $ \p -> do
        pokeByteOff p 16 (nullPtr :: Ptr Word8)
        pokeByteOff p (16 + pw) (CULong 32)
        normalizeEncryptDataCbcParams 16 (castPtr p)
          (fromIntegral (encryptDataCbcNativeSize 16))
      assertEqual "refused" Nothing out
  , testCase "encrypt-data short image refuses" $ do
      out <- allocaBytes 8 $ \p -> do
        pokeByteOff p 0 (CULong 0x01 :: CULong)
        normalizeEncryptDataCbcParams 16 (castPtr p) 8
      assertEqual "refused" Nothing out
  , testCase "encrypt-data ecb struct chases the data" $ do
      let mid = MechanismId (mustGeneratedId "CKM_AES_ECB_ENCRYPT_DATA")
          dat = BS.replicate 32 0xda
          pw = sizeOf (undefined :: Ptr Word8)
      out <- BS.useAsCStringLen dat $ \(dp, dlen) ->
        allocaBytes encryptDataEcbNativeSize $ \p -> do
          pokeByteOff p 0 (castPtr dp :: Ptr Word8)
          pokeByteOff p pw (CULong (fromIntegral dlen))
          normalizeEncryptDataEcbParams (castPtr p)
            (fromIntegral encryptDataEcbNativeSize)
      assertEqual "canonical data" (Just dat) out
      case (out, encryptDataRecipeFor mid) of
        (Just canon, Just r) ->
          assertEqual "recipe accepts" True (encryptDataParamsValid r canon)
        _ -> fail "encrypt-data recipe or data missing"
  , testCase "encrypt-data ecb null data with length refuses" $ do
      let pw = sizeOf (undefined :: Ptr Word8)
      out <- allocaBytes encryptDataEcbNativeSize $ \p -> do
        pokeByteOff p 0 (nullPtr :: Ptr Word8)
        pokeByteOff p pw (CULong 32)
        normalizeEncryptDataEcbParams (castPtr p)
          (fromIntegral encryptDataEcbNativeSize)
      assertEqual "refused" Nothing out
  , testCase "encrypt-data ecb short image refuses" $ do
      out <- allocaBytes 8 $ \p -> do
        pokeByteOff p 0 (CULong 0x01 :: CULong)
        normalizeEncryptDataEcbParams (castPtr p) 8
      assertEqual "refused" Nothing out
  , testCase "dh pkcs bare peer wraps canonical" $ do
      let mid = MechanismId (mustGeneratedId "CKM_DH_PKCS_DERIVE")
          peer = BS.replicate 256 0x09
          out = normalizeDhPkcsParams peer
      assertEqual "canonical dh image" (Just (encodeDhParams 0 peer)) out
      case (out, dhRecipeFor mid) of
        (Just canon, Just r) ->
          assertEqual "recipe accepts" True (dhParamsValid r canon)
        _ -> fail "dh recipe or image missing"
  , testCase "dh pkcs canonical image is idempotent" $ do
      let canon = encodeDhParams 0 (BS.replicate 32 0x07)
      assertEqual "idempotent" (Just canon) (normalizeDhPkcsParams canon)
  , testCase "dh pkcs empty and overlong refuse" $ do
      assertEqual "empty refused" Nothing (normalizeDhPkcsParams BS.empty)
      assertEqual "overlong refused" Nothing
        (normalizeDhPkcsParams (BS.replicate 4097 0x01))
  , testCase "dh x942 native struct chases empty shared and peer" $ do
      let mid = MechanismId (mustGeneratedId "CKM_X9_42_DH_DERIVE")
          peer = BS.replicate 128 0x04
          w = sizeOf (undefined :: CULong)
          pw = sizeOf (undefined :: Ptr Word8)
      out <- BS.useAsCStringLen peer $ \(pp, plen) ->
        allocaBytes dhX942NativeSize $ \p -> do
          pokeByteOff p 0 (CULong 0x01)
          pokeByteOff p w (CULong 0)
          pokeByteOff p (2 * w) (nullPtr :: Ptr Word8)
          pokeByteOff p (2 * w + pw) (CULong (fromIntegral plen))
          pokeByteOff p (3 * w + pw) (castPtr pp)
          normalizeDhX942Params p (fromIntegral dhX942NativeSize)
      let want = encodeDhParams 0 peer
      assertEqual "canonical dh image" (Just want) out
      case (out, dhRecipeFor mid) of
        (Just canon, Just r) ->
          assertEqual "recipe accepts" True (dhParamsValid r canon)
        _ -> fail "dh recipe or image missing"
  , testCase "dh x942 non-null kdf refuses" $ do
      let w = sizeOf (undefined :: CULong)
          pw = sizeOf (undefined :: Ptr Word8)
          peer = BS.replicate 128 0x04
      out <- BS.useAsCStringLen peer $ \(pp, plen) ->
        allocaBytes dhX942NativeSize $ \p -> do
          pokeByteOff p 0 (CULong 0x02)
          pokeByteOff p w (CULong 0)
          pokeByteOff p (2 * w) (nullPtr :: Ptr Word8)
          pokeByteOff p (2 * w + pw) (CULong (fromIntegral plen))
          pokeByteOff p (3 * w + pw) (castPtr pp)
          normalizeDhX942Params p (fromIntegral dhX942NativeSize)
      assertEqual "refused" Nothing out
  , testCase "dh x942 non-empty shared refuses" $ do
      let w = sizeOf (undefined :: CULong)
          pw = sizeOf (undefined :: Ptr Word8)
          shared = "shared-info" :: ByteString
          peer = BS.replicate 128 0x04
      out <- BS.useAsCStringLen shared $ \(sp, slen) ->
        BS.useAsCStringLen peer $ \(pp, plen) ->
          allocaBytes dhX942NativeSize $ \p -> do
            pokeByteOff p 0 (CULong 0x01)
            pokeByteOff p w (CULong (fromIntegral slen))
            pokeByteOff p (2 * w) (castPtr sp)
            pokeByteOff p (2 * w + pw) (CULong (fromIntegral plen))
            pokeByteOff p (3 * w + pw) (castPtr pp)
            normalizeDhX942Params p (fromIntegral dhX942NativeSize)
      assertEqual "refused" Nothing out
  , testCase "dh x942 null peer with length refuses" $ do
      let w = sizeOf (undefined :: CULong)
          pw = sizeOf (undefined :: Ptr Word8)
      out <- allocaBytes dhX942NativeSize $ \p -> do
        pokeByteOff p 0 (CULong 0x01)
        pokeByteOff p w (CULong 0)
        pokeByteOff p (2 * w) (nullPtr :: Ptr Word8)
        pokeByteOff p (2 * w + pw) (CULong 128)
        pokeByteOff p (3 * w + pw) (nullPtr :: Ptr Word8)
        normalizeDhX942Params p (fromIntegral dhX942NativeSize)
      assertEqual "refused" Nothing out
  , testCase "dh x942 short image refuses" $ do
      out <- allocaBytes 8 $ \p -> do
        pokeByteOff p 0 (CULong 0x01 :: CULong)
        normalizeDhX942Params p 8
      assertEqual "refused" Nothing out
  , testCase "eddsa pure native struct translates to canonical" $ do
      let mid = MechanismId (mustGeneratedId "CKM_EDDSA")
          w = sizeOf (undefined :: CULong)
          wa = alignment (undefined :: CULong)
          lenOff = ((1 + wa - 1) `div` wa) * wa
      out <- allocaBytes eddsaNativeSize $ \p -> do
        pokeByteOff p 0 (0 :: Word8)
        pokeByteOff p lenOff (CULong 0)
        pokeByteOff p (lenOff + w) (nullPtr :: Ptr Word8)
        raw <- BS.packCStringLen (castPtr p, eddsaNativeSize)
        normalizeMechParams mid p (fromIntegral eddsaNativeSize) raw
      let want = encodeEddsaParams False BS.empty
      assertEqual "canonical eddsa image" want out
      case eddsaRecipeFor mid of
        Nothing -> fail "eddsa recipe missing"
        Just r -> assertEqual "recipe accepts" True (eddsaParamsValid r out)
      assertEqual "native size" (lenOff + w + sizeOf (undefined :: Ptr Word8)) eddsaNativeSize
  , testCase "eddsa context struct translates, recipe refuses" $ do
      let mid = MechanismId (mustGeneratedId "CKM_EDDSA")
          ctx = "CTX" :: ByteString
          w = sizeOf (undefined :: CULong)
          wa = alignment (undefined :: CULong)
          lenOff = ((1 + wa - 1) `div` wa) * wa
      out <- BS.useAsCStringLen ctx $ \(cp, clen) ->
        allocaBytes eddsaNativeSize $ \p -> do
          pokeByteOff p 0 (0 :: Word8)
          pokeByteOff p lenOff (CULong (fromIntegral clen))
          pokeByteOff p (lenOff + w) (castPtr cp)
          raw <- BS.packCStringLen (castPtr p, eddsaNativeSize)
          normalizeMechParams mid p (fromIntegral eddsaNativeSize) raw
      assertEqual "canonical eddsa image" (encodeEddsaParams False ctx) out
      case eddsaRecipeFor mid of
        Nothing -> fail "eddsa recipe missing"
        Just r -> assertEqual "recipe refuses" False (eddsaParamsValid r out)
  , testCase "eddsa prehash struct translates, recipe refuses" $ do
      let mid = MechanismId (mustGeneratedId "CKM_EDDSA")
          w = sizeOf (undefined :: CULong)
          wa = alignment (undefined :: CULong)
          lenOff = ((1 + wa - 1) `div` wa) * wa
      out <- allocaBytes eddsaNativeSize $ \p -> do
        pokeByteOff p 0 (1 :: Word8)
        pokeByteOff p lenOff (CULong 0)
        pokeByteOff p (lenOff + w) (nullPtr :: Ptr Word8)
        raw <- BS.packCStringLen (castPtr p, eddsaNativeSize)
        normalizeMechParams mid p (fromIntegral eddsaNativeSize) raw
      assertEqual "canonical eddsa image"
        (encodeEddsaParams True BS.empty) out
      case eddsaRecipeFor mid of
        Nothing -> fail "eddsa recipe missing"
        Just r -> assertEqual "recipe refuses" False (eddsaParamsValid r out)
  , testCase "eddsa null context with length passes through" $ do
      let mid = MechanismId (mustGeneratedId "CKM_EDDSA")
          w = sizeOf (undefined :: CULong)
          wa = alignment (undefined :: CULong)
          lenOff = ((1 + wa - 1) `div` wa) * wa
      (raw, out) <- allocaBytes eddsaNativeSize $ \p -> do
        pokeByteOff p 0 (0 :: Word8)
        pokeByteOff p lenOff (CULong 7)
        pokeByteOff p (lenOff + w) (nullPtr :: Ptr Word8)
        raw <- BS.packCStringLen (castPtr p, eddsaNativeSize)
        out <- normalizeMechParams mid p (fromIntegral eddsaNativeSize) raw
        pure (raw, out)
      assertEqual "passthrough" raw out
  , testCase "eddsa bad flag passes through" $ do
      let mid = MechanismId (mustGeneratedId "CKM_EDDSA")
          w = sizeOf (undefined :: CULong)
          wa = alignment (undefined :: CULong)
          lenOff = ((1 + wa - 1) `div` wa) * wa
      (raw, out) <- allocaBytes eddsaNativeSize $ \p -> do
        pokeByteOff p 0 (2 :: Word8)
        pokeByteOff p lenOff (CULong 0)
        pokeByteOff p (lenOff + w) (nullPtr :: Ptr Word8)
        raw <- BS.packCStringLen (castPtr p, eddsaNativeSize)
        out <- normalizeMechParams mid p (fromIntegral eddsaNativeSize) raw
        pure (raw, out)
      assertEqual "passthrough" raw out
  , testCase "eddsa short image passes through" $ do
      let mid = MechanismId (mustGeneratedId "CKM_EDDSA")
          raw = BS.replicate 8 0
      out <- allocaBytes 8 $ \p -> do
        pokeByteOff p 0 (0 :: Word8)
        normalizeMechParams mid p 8 raw
      assertEqual "passthrough" raw out
  , testCase "mldsa pure native struct translates to canonical" $ do
      let mid = MechanismId (mustGeneratedId "CKM_ML_DSA")
          w = sizeOf (undefined :: CULong)
          pw = sizeOf (undefined :: Ptr Word8)
      out <- allocaBytes mldsaNativeSize $ \p -> do
        pokeByteOff p 0 (CULong 0)
        pokeByteOff p w (nullPtr :: Ptr Word8)
        pokeByteOff p (w + pw) (CULong 0)
        raw <- BS.packCStringLen (castPtr p, mldsaNativeSize)
        normalizeMechParams mid p (fromIntegral mldsaNativeSize) raw
      let want = encodeMldsaParams HedgePreferred BS.empty
      assertEqual "canonical mldsa image" want out
      case mldsaRecipeFor mid of
        Nothing -> fail "mldsa recipe missing"
        Just r -> assertEqual "recipe accepts" True (mldsaParamsValid r out)
      assertEqual "native size" (2 * w + pw) mldsaNativeSize
  , testCase "mldsa context struct translates, recipe accepts" $ do
      let mid = MechanismId (mustGeneratedId "CKM_ML_DSA")
          ctx = "CTX" :: ByteString
          w = sizeOf (undefined :: CULong)
          pw = sizeOf (undefined :: Ptr Word8)
      out <- BS.useAsCStringLen ctx $ \(cp, clen) ->
        allocaBytes mldsaNativeSize $ \p -> do
          pokeByteOff p 0 (CULong 0)
          pokeByteOff p w (castPtr cp)
          pokeByteOff p (w + pw) (CULong (fromIntegral clen))
          raw <- BS.packCStringLen (castPtr p, mldsaNativeSize)
          normalizeMechParams mid p (fromIntegral mldsaNativeSize) raw
      assertEqual "canonical mldsa image" (encodeMldsaParams HedgePreferred ctx) out
      case mldsaRecipeFor mid of
        Nothing -> fail "mldsa recipe missing"
        Just r -> assertEqual "recipe accepts" True (mldsaParamsValid r out)
  , testCase "mldsa deterministic struct translates, recipe accepts" $ do
      let mid = MechanismId (mustGeneratedId "CKM_ML_DSA")
          w = sizeOf (undefined :: CULong)
          pw = sizeOf (undefined :: Ptr Word8)
      out <- allocaBytes mldsaNativeSize $ \p -> do
        pokeByteOff p 0 (CULong 2)
        pokeByteOff p w (nullPtr :: Ptr Word8)
        pokeByteOff p (w + pw) (CULong 0)
        raw <- BS.packCStringLen (castPtr p, mldsaNativeSize)
        normalizeMechParams mid p (fromIntegral mldsaNativeSize) raw
      assertEqual "canonical mldsa image"
        (encodeMldsaParams HedgeDeterministic BS.empty) out
      case mldsaRecipeFor mid of
        Nothing -> fail "mldsa recipe missing"
        Just r -> assertEqual "recipe accepts" True (mldsaParamsValid r out)
  , testCase "mldsa overlong context translates, recipe refuses" $ do
      let mid = MechanismId (mustGeneratedId "CKM_ML_DSA")
          ctx = BS.replicate 256 0x41
          w = sizeOf (undefined :: CULong)
          pw = sizeOf (undefined :: Ptr Word8)
      out <- BS.useAsCStringLen ctx $ \(cp, clen) ->
        allocaBytes mldsaNativeSize $ \p -> do
          pokeByteOff p 0 (CULong 0)
          pokeByteOff p w (castPtr cp)
          pokeByteOff p (w + pw) (CULong (fromIntegral clen))
          raw <- BS.packCStringLen (castPtr p, mldsaNativeSize)
          normalizeMechParams mid p (fromIntegral mldsaNativeSize) raw
      assertEqual "canonical mldsa image" (encodeMldsaParams HedgePreferred ctx) out
      case mldsaRecipeFor mid of
        Nothing -> fail "mldsa recipe missing"
        Just r -> assertEqual "recipe refuses" False (mldsaParamsValid r out)
  , testCase "mldsa null context with length passes through" $ do
      let mid = MechanismId (mustGeneratedId "CKM_ML_DSA")
          w = sizeOf (undefined :: CULong)
          pw = sizeOf (undefined :: Ptr Word8)
      (raw, out) <- allocaBytes mldsaNativeSize $ \p -> do
        pokeByteOff p 0 (CULong 0)
        pokeByteOff p w (nullPtr :: Ptr Word8)
        pokeByteOff p (w + pw) (CULong 7)
        raw <- BS.packCStringLen (castPtr p, mldsaNativeSize)
        out <- normalizeMechParams mid p (fromIntegral mldsaNativeSize) raw
        pure (raw, out)
      assertEqual "passthrough" raw out
  , testCase "mldsa bad hedge passes through" $ do
      let mid = MechanismId (mustGeneratedId "CKM_ML_DSA")
          w = sizeOf (undefined :: CULong)
          pw = sizeOf (undefined :: Ptr Word8)
      (raw, out) <- allocaBytes mldsaNativeSize $ \p -> do
        pokeByteOff p 0 (CULong 3)
        pokeByteOff p w (nullPtr :: Ptr Word8)
        pokeByteOff p (w + pw) (CULong 0)
        raw <- BS.packCStringLen (castPtr p, mldsaNativeSize)
        out <- normalizeMechParams mid p (fromIntegral mldsaNativeSize) raw
        pure (raw, out)
      assertEqual "passthrough" raw out
  , testCase "mldsa short image passes through" $ do
      let mid = MechanismId (mustGeneratedId "CKM_ML_DSA")
          raw = BS.replicate 8 0
      out <- allocaBytes 8 $ \p -> do
        pokeByteOff p 0 (CULong 0 :: CULong)
        normalizeMechParams mid p 8 raw
      assertEqual "passthrough" raw out
  , testCase "chacha stream struct chases counter and nonce" $ do
      let mid = MechanismId (mustGeneratedId "CKM_CHACHA20")
          ctr = BS.pack [0x01, 0x00, 0x00, 0x00]
          nonce = "0123456789ab" :: ByteString
          w = sizeOf (undefined :: CULong)
          pw = sizeOf (undefined :: Ptr Word8)
      out <- BS.useAsCStringLen ctr $ \(cp, _) ->
        BS.useAsCStringLen nonce $ \(np, _) ->
          allocaBytes chachaStreamNativeSize $ \p -> do
            pokeByteOff p 0 (castPtr cp)
            pokeByteOff p pw (CULong 32)
            pokeByteOff p (pw + w) (castPtr np)
            pokeByteOff p (2 * pw + w) (CULong 96)
            raw <- BS.packCStringLen (castPtr p, chachaStreamNativeSize)
            normalizeMechParams mid p (fromIntegral chachaStreamNativeSize) raw
      assertEqual "canonical stream image"
        (encodeChachaStreamParams 1 nonce) out
      case chachaRecipeFor mid of
        Nothing -> fail "chacha recipe missing"
        Just r -> assertEqual "recipe accepts" True (chachaParamsValid r out)
  , testCase "chacha stream ragged bits pass through" $ do
      let mid = MechanismId (mustGeneratedId "CKM_CHACHA20")
          w = sizeOf (undefined :: CULong)
          pw = sizeOf (undefined :: Ptr Word8)
      (raw, out) <- allocaBytes chachaStreamNativeSize $ \p -> do
        pokeByteOff p 0 (nullPtr :: Ptr Word8)
        pokeByteOff p pw (CULong 20)
        pokeByteOff p (pw + w) (nullPtr :: Ptr Word8)
        pokeByteOff p (2 * pw + w) (CULong 96)
        raw <- BS.packCStringLen (castPtr p, chachaStreamNativeSize)
        out <- normalizeMechParams mid p (fromIntegral chachaStreamNativeSize) raw
        pure (raw, out)
      assertEqual "passthrough" raw out
  , testCase "chacha poly struct chases nonce and aad" $ do
      let mid = MechanismId (mustGeneratedId "CKM_CHACHA20_POLY1305")
          nonce = "0123456789ab" :: ByteString
          aad = "AD" :: ByteString
          w = sizeOf (undefined :: CULong)
          pw = sizeOf (undefined :: Ptr Word8)
      out <- BS.useAsCStringLen nonce $ \(np, nlen) ->
        BS.useAsCStringLen aad $ \(ap, alen) ->
          allocaBytes chachaPolyNativeSize $ \p -> do
            pokeByteOff p 0 (castPtr np)
            pokeByteOff p pw (CULong (fromIntegral nlen))
            pokeByteOff p (pw + w) (castPtr ap)
            pokeByteOff p (2 * pw + w) (CULong (fromIntegral alen))
            raw <- BS.packCStringLen (castPtr p, chachaPolyNativeSize)
            normalizeMechParams mid p (fromIntegral chachaPolyNativeSize) raw
      assertEqual "canonical poly image"
        (encodeChachaPolyParams nonce aad 16) out
      case chachaRecipeFor mid of
        Nothing -> fail "chacha recipe missing"
        Just r -> assertEqual "recipe accepts" True (chachaParamsValid r out)
  , testCase "chacha poly off-12 nonce translates, recipe refuses" $ do
      let mid = MechanismId (mustGeneratedId "CKM_CHACHA20_POLY1305")
          nonce = "12345678" :: ByteString
          aad = "AD" :: ByteString
          w = sizeOf (undefined :: CULong)
          pw = sizeOf (undefined :: Ptr Word8)
      out <- BS.useAsCStringLen nonce $ \(np, nlen) ->
        BS.useAsCStringLen aad $ \(ap, alen) ->
          allocaBytes chachaPolyNativeSize $ \p -> do
            pokeByteOff p 0 (castPtr np)
            pokeByteOff p pw (CULong (fromIntegral nlen))
            pokeByteOff p (pw + w) (castPtr ap)
            pokeByteOff p (2 * pw + w) (CULong (fromIntegral alen))
            raw <- BS.packCStringLen (castPtr p, chachaPolyNativeSize)
            normalizeMechParams mid p (fromIntegral chachaPolyNativeSize) raw
      assertEqual "canonical poly image"
        (encodeChachaPolyParams nonce aad 16) out
      case chachaRecipeFor mid of
        Nothing -> fail "chacha recipe missing"
        Just r -> assertEqual "recipe refuses" False (chachaParamsValid r out)
  , testCase "chacha short image passes through" $ do
      let mid = MechanismId (mustGeneratedId "CKM_CHACHA20")
          raw = BS.replicate 8 0
      out <- allocaBytes 8 $ \p -> do
        pokeByteOff p 0 (nullPtr :: Ptr Word8)
        normalizeMechParams mid p 8 raw
      assertEqual "passthrough" raw out
  , testCase "ike native structs translate to canonical" $ do
      let w = sizeOf (undefined :: CULong)
          pw = sizeOf (undefined :: Ptr Word8)
          prf = mustGeneratedId "CKM_SHA256_HMAC"
          seed = BS.pack [1 .. 32]
          ni = BS.replicate 16 1
          nr = BS.replicate 16 2
          ckyi = BS.replicate 8 3
          ckyr = BS.replicate 8 4
          extra = BS.pack [5 .. 20]
          check name mid got want = do
            assertEqual ("canonical " ++ name) (Just want) got
            case (got, ikeRecipeFor mid) of
              (Just canon, Just r) ->
                assertEqual ("recipe accepts " ++ name) True (ikeParamsValid r canon)
              _ -> fail ("ike recipe or image missing: " ++ name)
          plusMid = MechanismId (mustGeneratedId "CKM_IKE2_PRF_PLUS_DERIVE")
          prfMid = MechanismId (mustGeneratedId "CKM_IKE_PRF_DERIVE")
          ike1Mid = MechanismId (mustGeneratedId "CKM_IKE1_PRF_DERIVE")
          extMid = MechanismId (mustGeneratedId "CKM_IKE1_EXTENDED_DERIVE")
      outPlus <- BS.useAsCStringLen seed $ \(sp, slen) ->
        allocaBytes ikePrfPlusNativeSize $ \p -> do
          pokeByteOff p 0 (CULong prf)
          pokeByteOff p w (0 :: Word8)
          pokeByteOff p (2 * w) (CULong 0)
          pokeByteOff p (3 * w) (castPtr sp)
          pokeByteOff p (3 * w + pw) (CULong (fromIntegral slen))
          normalizeIkePrfPlusParams p (fromIntegral ikePrfPlusNativeSize)
      check "prf+" plusMid outPlus (encodeIkeParams 4 0 0 0 seed BS.empty)
      outPrf <- BS.useAsCStringLen ni $ \(ip, ilen) ->
        BS.useAsCStringLen nr $ \(rp, rlen) ->
          allocaBytes ikePrfNativeSize $ \p -> do
            pokeByteOff p 0 (CULong prf)
            pokeByteOff p w (1 :: Word8)
            pokeByteOff p (w + 1) (0 :: Word8)
            pokeByteOff p (2 * w) (castPtr ip)
            pokeByteOff p (3 * w) (CULong (fromIntegral ilen))
            pokeByteOff p (3 * w + pw) (castPtr rp)
            pokeByteOff p (4 * w + pw) (CULong (fromIntegral rlen))
            pokeByteOff p (5 * w + pw) (CULong 0)
            normalizeIkePrfParams p (fromIntegral ikePrfNativeSize)
      check "prf" prfMid outPrf (encodeIkeParams 4 1 0 0 ni nr)
      outIke1 <- BS.useAsCStringLen ckyi $ \(ip, ilen) ->
        BS.useAsCStringLen ckyr $ \(rp, rlen) ->
          allocaBytes ike1PrfNativeSize $ \p -> do
            pokeByteOff p 0 (CULong prf)
            pokeByteOff p w (0 :: Word8)
            pokeByteOff p (2 * w) (CULong 405)
            pokeByteOff p (3 * w) (CULong 0)
            pokeByteOff p (4 * w) (castPtr ip)
            pokeByteOff p (5 * w) (CULong (fromIntegral ilen))
            pokeByteOff p (5 * w + pw) (castPtr rp)
            pokeByteOff p (6 * w + pw) (CULong (fromIntegral rlen))
            pokeByteOff p (8 * w) (7 :: Word8)
            normalizeIke1PrfParams p (fromIntegral ike1PrfNativeSize)
      check "ike1" ike1Mid outIke1 (encodeIkeParams 4 0 7 405 ckyi ckyr)
      outExt <- BS.useAsCStringLen extra $ \(ep, elen) ->
        allocaBytes ike1ExtNativeSize $ \p -> do
          pokeByteOff p 0 (CULong prf)
          pokeByteOff p w (1 :: Word8)
          pokeByteOff p (2 * w) (CULong 405)
          pokeByteOff p (3 * w) (castPtr ep)
          pokeByteOff p (3 * w + pw) (CULong (fromIntegral elen))
          normalizeIke1ExtParams p (fromIntegral ike1ExtNativeSize)
      check "ext" extMid outExt (encodeIkeParams 4 0 0 405 extra BS.empty)
  , testCase "ike key-carrying legs refuse" $ do
      let w = sizeOf (undefined :: CULong)
          pw = sizeOf (undefined :: Ptr Word8)
          prf = mustGeneratedId "CKM_SHA256_HMAC"
          seed = BS.pack [1 .. 32]
          lbl name got = assertEqual ("refused " ++ name) Nothing got
      seedKey <- BS.useAsCStringLen seed $ \(sp, slen) ->
        allocaBytes ikePrfPlusNativeSize $ \p -> do
          pokeByteOff p 0 (CULong prf)
          pokeByteOff p w (1 :: Word8)
          pokeByteOff p (2 * w) (CULong 9)
          pokeByteOff p (3 * w) (castPtr sp)
          pokeByteOff p (3 * w + pw) (CULong (fromIntegral slen))
          normalizeIkePrfPlusParams p (fromIntegral ikePrfPlusNativeSize)
      lbl "seed-key" seedKey
      rekey <- BS.useAsCStringLen seed $ \(sp, slen) ->
        allocaBytes ikePrfNativeSize $ \p -> do
          pokeByteOff p 0 (CULong prf)
          pokeByteOff p w (0 :: Word8)
          pokeByteOff p (w + 1) (1 :: Word8)
          pokeByteOff p (2 * w) (castPtr sp)
          pokeByteOff p (3 * w) (CULong (fromIntegral slen))
          pokeByteOff p (3 * w + pw) (castPtr sp)
          pokeByteOff p (4 * w + pw) (CULong (fromIntegral slen))
          pokeByteOff p (5 * w + pw) (CULong 7)
          normalizeIkePrfParams p (fromIntegral ikePrfNativeSize)
      lbl "rekey" rekey
      prev <- BS.useAsCStringLen seed $ \(sp, slen) ->
        allocaBytes ike1PrfNativeSize $ \p -> do
          pokeByteOff p 0 (CULong prf)
          pokeByteOff p w (1 :: Word8)
          pokeByteOff p (2 * w) (CULong 405)
          pokeByteOff p (3 * w) (CULong 9)
          pokeByteOff p (4 * w) (castPtr sp)
          pokeByteOff p (5 * w) (CULong (fromIntegral slen))
          pokeByteOff p (5 * w + pw) (castPtr sp)
          pokeByteOff p (6 * w + pw) (CULong (fromIntegral slen))
          pokeByteOff p (8 * w) (1 :: Word8)
          normalizeIke1PrfParams p (fromIntegral ike1PrfNativeSize)
      lbl "prevkey" prev
      noKeygxy <- BS.useAsCStringLen seed $ \(sp, slen) ->
        allocaBytes ike1PrfNativeSize $ \p -> do
          pokeByteOff p 0 (CULong prf)
          pokeByteOff p w (0 :: Word8)
          pokeByteOff p (2 * w) (CULong 0)
          pokeByteOff p (3 * w) (CULong 0)
          pokeByteOff p (4 * w) (castPtr sp)
          pokeByteOff p (5 * w) (CULong (fromIntegral slen))
          pokeByteOff p (5 * w + pw) (castPtr sp)
          pokeByteOff p (6 * w + pw) (CULong (fromIntegral slen))
          pokeByteOff p (8 * w) (1 :: Word8)
          normalizeIke1PrfParams p (fromIntegral ike1PrfNativeSize)
      lbl "missing-keygxy" noKeygxy
      mismatch <- BS.useAsCStringLen seed $ \(sp, slen) ->
        allocaBytes ike1ExtNativeSize $ \p -> do
          pokeByteOff p 0 (CULong prf)
          pokeByteOff p w (0 :: Word8)
          pokeByteOff p (2 * w) (CULong 405)
          pokeByteOff p (3 * w) (castPtr sp)
          pokeByteOff p (3 * w + pw) (CULong (fromIntegral slen))
          normalizeIke1ExtParams p (fromIntegral ike1ExtNativeSize)
      lbl "flag-handle-mismatch" mismatch
  , testCase "ike non-0/1 flag byte refuses" $ do
      let w = sizeOf (undefined :: CULong)
          pw = sizeOf (undefined :: Ptr Word8)
          prf = mustGeneratedId "CKM_SHA256_HMAC"
          seed = BS.pack [1 .. 32]
      out <- BS.useAsCStringLen seed $ \(sp, slen) ->
        allocaBytes ikePrfPlusNativeSize $ \p -> do
          pokeByteOff p 0 (CULong prf)
          pokeByteOff p w (2 :: Word8)
          pokeByteOff p (2 * w) (CULong 0)
          pokeByteOff p (3 * w) (castPtr sp)
          pokeByteOff p (3 * w + pw) (CULong (fromIntegral slen))
          normalizeIkePrfPlusParams p (fromIntegral ikePrfPlusNativeSize)
      assertEqual "refused" Nothing out
  , testCase "ike short image refuses" $ do
      out <- allocaBytes 8 $ \p -> do
        pokeByteOff p 0 (CULong 0x251 :: CULong)
        normalizeIkePrfPlusParams p 8
      assertEqual "refused" Nothing out
  , testCase "byte-op native params translate to canonical" $ do
      let pw = sizeOf (undefined :: Ptr Word8)
          blob = BS.pack [1 .. 16]
          check name mid got want = do
            assertEqual ("canonical " ++ name) (Just want) got
            case (got, byteOpsRecipeFor mid) of
              (Just canon, Just r) ->
                assertEqual ("recipe accepts " ++ name) True (byteOpsParamsValid r canon)
              _ -> fail ("byte-op recipe or image missing: " ++ name)
          keyMid = MechanismId (mustGeneratedId "CKM_CONCATENATE_BASE_AND_KEY")
          bdMid = MechanismId (mustGeneratedId "CKM_CONCATENATE_BASE_AND_DATA")
          extMid = MechanismId (mustGeneratedId "CKM_EXTRACT_KEY_FROM_KEY")
      outKey <- allocaBytes byteOpsUlongNativeSize $ \p -> do
        pokeByteOff p 0 (CULong 405)
        normalizeByteOpsConcatKeyParams p (fromIntegral byteOpsUlongNativeSize)
      check "concat-key" keyMid outKey (encodeByteOpsParams 405 0 BS.empty)
      outBD <- BS.useAsCStringLen blob $ \(dp, dlen) ->
        allocaBytes byteOpsStringDataNativeSize $ \p -> do
          pokeByteOff p 0 (castPtr dp)
          pokeByteOff p pw (CULong (fromIntegral dlen))
          normalizeByteOpsStringDataParams p (fromIntegral byteOpsStringDataNativeSize)
      check "concat-data" bdMid outBD (encodeByteOpsParams 0 0 blob)
      outExt <- allocaBytes byteOpsUlongNativeSize $ \p -> do
        pokeByteOff p 0 (CULong 128)
        normalizeByteOpsExtractParams p (fromIntegral byteOpsUlongNativeSize)
      check "extract" extMid outExt (encodeByteOpsParams 0 128 BS.empty)
  , testCase "byte-op bad native params refuse" $ do
      let pw = sizeOf (undefined :: Ptr Word8)
          blob = BS.pack [1 .. 16]
      zeroKey <- allocaBytes byteOpsUlongNativeSize $ \p -> do
        pokeByteOff p 0 (CULong 0)
        normalizeByteOpsConcatKeyParams p (fromIntegral byteOpsUlongNativeSize)
      assertEqual "zero handle refused" Nothing zeroKey
      shortKey <- allocaBytes 4 $ \p -> do
        pokeByteOff p 0 (CULong 405)
        normalizeByteOpsConcatKeyParams p 4
      assertEqual "short handle refused" Nothing shortKey
      shortSD <- BS.useAsCStringLen blob $ \(dp, dlen) ->
        allocaBytes byteOpsStringDataNativeSize $ \p -> do
          pokeByteOff p 0 (castPtr dp)
          pokeByteOff p pw (CULong (fromIntegral dlen))
          normalizeByteOpsStringDataParams p 8
      assertEqual "short struct refused" Nothing shortSD
      nullSD <- allocaBytes byteOpsStringDataNativeSize $ \p -> do
        pokeByteOff p 0 (nullPtr :: Ptr Word8)
        pokeByteOff p pw (CULong 16)
        normalizeByteOpsStringDataParams p (fromIntegral byteOpsStringDataNativeSize)
      assertEqual "null data refused" Nothing nullSD
      shortExt <- allocaBytes 4 $ \p -> do
        pokeByteOff p 0 (CULong 0)
        normalizeByteOpsExtractParams p 4
      assertEqual "short offset refused" Nothing shortExt
  , testCase "key-material native structs translate to canonical" $ do
      let w = sizeOf (undefined :: CULong)
          cr = BS.pack [0 .. 31]
          sr = BS.pack [32 .. 63]
          sha256 = mustGeneratedId "CKM_SHA256"
          k10 = MechanismId (mustGeneratedId "CKM_TLS_KEY_AND_MAC_DERIVE")
          k12 = MechanismId (mustGeneratedId "CKM_TLS12_KEY_AND_MAC_DERIVE")
          check name mid got want nHandles ivLen = case got of
            Just (canon, slots) -> do
              assertEqual ("canonical " ++ name) want canon
              case tlsKeyMatRecipeFor mid of
                Just r -> assertEqual ("recipe accepts " ++ name) True
                  (tlsKeyMatParamsValid r canon)
                Nothing -> fail ("keymat recipe missing: " ++ name)
              assertEqual ("handles " ++ name) nHandles (length (kmsHandles slots))
              assertEqual ("ivc " ++ name) ivLen (kmsIvCLen slots)
              assertEqual ("ivs " ++ name) ivLen (kmsIvSLen slots)
            Nothing -> fail ("keymat struct refused: " ++ name)
          withOut ivLen action =
            allocaBytes 48 $ \out ->
              allocaBytes ivLen $ \ivc ->
                allocaBytes ivLen $ \ivs -> do
                  pokeByteOff out 0 (CULong 0)
                  pokeByteOff out w (CULong 0)
                  pokeByteOff out (2 * w) (CULong 0)
                  pokeByteOff out (3 * w) (CULong 0)
                  pokeByteOff out (4 * w) (castPtr ivc :: Ptr Word8)
                  pokeByteOff out (5 * w) (castPtr ivs :: Ptr Word8)
                  action out
      out10 <- BS.useAsCStringLen cr $ \(cp, _) ->
        BS.useAsCStringLen sr $ \(sp, _) ->
          withOut 16 $ \out ->
            allocaBytes tlsKeyMatNativeSize $ \p -> do
              pokeByteOff p 0 (CULong 0)
              pokeByteOff p w (CULong 128)
              pokeByteOff p (2 * w) (CULong 128)
              pokeByteOff p (3 * w) (0 :: Word8)
              pokeByteOff p (4 * w) (castPtr cp :: Ptr Word8)
              pokeByteOff p (5 * w) (CULong 32)
              pokeByteOff p (6 * w) (castPtr sp :: Ptr Word8)
              pokeByteOff p (7 * w) (CULong 32)
              pokeByteOff p (8 * w) (castPtr out :: Ptr Word8)
              normalizeTlsKeyMatParams p (fromIntegral tlsKeyMatNativeSize)
      check "tls10" k10 out10 (encodeTlsKeyMatParams 0 0 16 16 cr sr) 2 16
      out12 <- BS.useAsCStringLen cr $ \(cp, _) ->
        BS.useAsCStringLen sr $ \(sp, _) ->
          withOut 16 $ \out ->
            allocaBytes tls12KeyMatNativeSize $ \p -> do
              pokeByteOff p 0 (CULong 160)
              pokeByteOff p w (CULong 128)
              pokeByteOff p (2 * w) (CULong 128)
              pokeByteOff p (3 * w) (0 :: Word8)
              pokeByteOff p (4 * w) (castPtr cp :: Ptr Word8)
              pokeByteOff p (5 * w) (CULong 32)
              pokeByteOff p (6 * w) (castPtr sp :: Ptr Word8)
              pokeByteOff p (7 * w) (CULong 32)
              pokeByteOff p (8 * w) (castPtr out :: Ptr Word8)
              pokeByteOff p tlsKeyMatNativeSize (CULong sha256)
              normalizeTls12KeyMatParams p (fromIntegral tls12KeyMatNativeSize)
      check "tls12" k12 out12 (encodeTlsKeyMatParams 4 20 16 16 cr sr) 4 16
  , testCase "key-material bad native structs refuse" $ do
      let w = sizeOf (undefined :: CULong)
          cr = BS.pack [0 .. 31]
          sr = BS.pack [32 .. 63]
          sha256 = mustGeneratedId "CKM_SHA256"
          build action =
            BS.useAsCStringLen cr $ \(cp, _) ->
              BS.useAsCStringLen sr $ \(sp, _) ->
                allocaBytes 48 $ \out ->
                  allocaBytes 16 $ \ivc ->
                    allocaBytes 16 $ \ivs -> do
                      pokeByteOff out (4 * w) (castPtr ivc :: Ptr Word8)
                      pokeByteOff out (5 * w) (castPtr ivs :: Ptr Word8)
                      allocaBytes tls12KeyMatNativeSize $ \p -> do
                        pokeByteOff p 0 (CULong 0)
                        pokeByteOff p w (CULong 128)
                        pokeByteOff p (2 * w) (CULong 128)
                        pokeByteOff p (3 * w) (0 :: Word8)
                        pokeByteOff p (4 * w) (castPtr cp :: Ptr Word8)
                        pokeByteOff p (5 * w) (CULong 32)
                        pokeByteOff p (6 * w) (castPtr sp :: Ptr Word8)
                        pokeByteOff p (7 * w) (CULong 32)
                        pokeByteOff p (8 * w) (castPtr out :: Ptr Word8)
                        pokeByteOff p tlsKeyMatNativeSize (CULong sha256)
                        action p out
      short <- build $ \p _ -> normalizeTls12KeyMatParams p 40
      assertEqual "short image refused" Nothing short
      nullOut <- build $ \p _ -> do
        pokeByteOff p (8 * w) (nullPtr :: Ptr Word8)
        normalizeTls12KeyMatParams p (fromIntegral tls12KeyMatNativeSize)
      assertEqual "null out refused" Nothing nullOut
      nullIv <- build $ \p out -> do
        pokeByteOff out (4 * w) (nullPtr :: Ptr Word8)
        normalizeTls12KeyMatParams p (fromIntegral tls12KeyMatNativeSize)
      assertEqual "null iv refused" Nothing nullIv
      exp <- build $ \p _ -> do
        pokeByteOff p (3 * w) (1 :: Word8)
        normalizeTls12KeyMatParams p (fromIntegral tls12KeyMatNativeSize)
      assertEqual "export refused" Nothing exp
      ragged <- build $ \p _ -> do
        pokeByteOff p (2 * w) (CULong 127)
        normalizeTls12KeyMatParams p (fromIntegral tls12KeyMatNativeSize)
      assertEqual "ragged size refused" Nothing ragged
      wildPrf <- build $ \p _ -> do
        pokeByteOff p tlsKeyMatNativeSize (CULong 0x999)
        normalizeTls12KeyMatParams p (fromIntegral tls12KeyMatNativeSize)
      assertEqual "wild prf refused" Nothing wildPrf
  , testCase "key-safe native struct ignores the IV size" $ do
      let w = sizeOf (undefined :: CULong)
          cr = BS.pack [0 .. 31]
          sr = BS.pack [32 .. 63]
          sha256 = mustGeneratedId "CKM_SHA256"
          kSafe = MechanismId (mustGeneratedId "CKM_TLS12_KEY_SAFE_DERIVE")
          build action =
            BS.useAsCStringLen cr $ \(cp, _) ->
              BS.useAsCStringLen sr $ \(sp, _) ->
                allocaBytes 48 $ \out ->
                  allocaBytes 16 $ \ivc ->
                    allocaBytes 16 $ \ivs -> do
                      pokeByteOff out (4 * w) (castPtr ivc :: Ptr Word8)
                      pokeByteOff out (5 * w) (castPtr ivs :: Ptr Word8)
                      allocaBytes tls12KeyMatNativeSize $ \p -> do
                        pokeByteOff p 0 (CULong 0)
                        pokeByteOff p w (CULong 128)
                        pokeByteOff p (2 * w) (CULong 128)
                        pokeByteOff p (3 * w) (0 :: Word8)
                        pokeByteOff p (4 * w) (castPtr cp :: Ptr Word8)
                        pokeByteOff p (5 * w) (CULong 32)
                        pokeByteOff p (6 * w) (castPtr sp :: Ptr Word8)
                        pokeByteOff p (7 * w) (CULong 32)
                        pokeByteOff p (8 * w) (castPtr out :: Ptr Word8)
                        pokeByteOff p tlsKeyMatNativeSize (CULong sha256)
                        action p out
          check name got = case got of
            Just (canon, slots) -> do
              assertEqual ("canonical " ++ name)
                (encodeTlsKeyMatParams 4 0 16 16 cr sr) canon
              case tlsKeyMatRecipeFor kSafe of
                Just r -> assertEqual ("recipe accepts " ++ name) True
                  (tlsKeyMatParamsValid r canon)
                Nothing -> fail "key-safe recipe missing"
              assertEqual ("ivc " ++ name) 0 (kmsIvCLen slots)
              assertEqual ("ivs " ++ name) 0 (kmsIvSLen slots)
            Nothing -> fail ("key-safe struct refused: " ++ name)
      buffered <- build $ \p _ ->
        normalizeTls12KeySafeParams p (fromIntegral tls12KeyMatNativeSize)
      check "buffered iv128" buffered
      unbuffered <- build $ \p out -> do
        pokeByteOff out (4 * w) (nullPtr :: Ptr Word8)
        pokeByteOff out (5 * w) (nullPtr :: Ptr Word8)
        normalizeTls12KeySafeParams p (fromIntegral tls12KeyMatNativeSize)
      check "null iv128" unbuffered
  , testCase "pbe native struct translates to canonical plus iv slot" $ do
      let w = sizeOf (undefined :: CULong)
          psz = sizeOf (undefined :: Ptr Word8)
          pw = "TestPassword123!" :: BS.ByteString
          salt = BS.pack [0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe]
          mid = MechanismId (mustGeneratedId "CKM_PBE_SHA1_DES3_EDE_CBC")
      got <- BS.useAsCStringLen pw $ \(pp, _) ->
        BS.useAsCStringLen salt $ \(sp, _) ->
          allocaBytes 8 $ \iv ->
            allocaBytes pbeParamsNativeSize $ \p -> do
              pokeByteOff p 0 (castPtr iv :: Ptr Word8)
              pokeByteOff p psz (castPtr pp :: Ptr Word8)
              pokeByteOff p (psz + w) (CULong 16)
              pokeByteOff p (psz + 2 * w) (castPtr sp :: Ptr Word8)
              pokeByteOff p (psz + 3 * w) (CULong 8)
              pokeByteOff p (psz + 4 * w) (CULong 1024)
              normalizePbeParams p (fromIntegral pbeParamsNativeSize)
      case got of
        Just (canon, slot) -> do
          assertEqual "canonical" (encodePbeParams 1024 pw salt) canon
          case pbeRecipeFor mid of
            Just r -> assertEqual "recipe accepts" True (pbeParamsValid r canon)
            Nothing -> fail "pbe recipe missing"
          assertBool "iv slot live" (slot /= nullPtr)
        Nothing -> fail "pbe struct refused"
  , testCase "pbe bad native structs refuse" $ do
      let w = sizeOf (undefined :: CULong)
          psz = sizeOf (undefined :: Ptr Word8)
          pw = "TestPassword123!" :: BS.ByteString
          salt = BS.pack [0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe]
          build action =
            BS.useAsCStringLen pw $ \(pp, _) ->
              BS.useAsCStringLen salt $ \(sp, _) ->
                allocaBytes 8 $ \iv ->
                  allocaBytes pbeParamsNativeSize $ \p -> do
                    pokeByteOff p 0 (castPtr iv :: Ptr Word8)
                    pokeByteOff p psz (castPtr pp :: Ptr Word8)
                    pokeByteOff p (psz + w) (CULong 16)
                    pokeByteOff p (psz + 2 * w) (castPtr sp :: Ptr Word8)
                    pokeByteOff p (psz + 3 * w) (CULong 8)
                    pokeByteOff p (psz + 4 * w) (CULong 1024)
                    action p
      short <- build $ \p -> normalizePbeParams p 40
      assertEqual "short image refused" Nothing short
      nullIv <- build $ \p -> do
        pokeByteOff p 0 (nullPtr :: Ptr Word8)
        normalizePbeParams p (fromIntegral pbeParamsNativeSize)
      assertEqual "null iv refused" Nothing nullIv
      nullPw <- build $ \p -> do
        pokeByteOff p psz (nullPtr :: Ptr Word8)
        normalizePbeParams p (fromIntegral pbeParamsNativeSize)
      assertEqual "null password refused" Nothing nullPw
  , testCase "sp800 additional-keys chase feeds templates plus slots" $ do
      let w = sizeOf (undefined :: CULong)
          pw = sizeOf (undefined :: Ptr Word8)
          prf = mustGeneratedId "CKM_SHA256_HMAC"
          attrSize = 3 * w
          dkSize = 2 * pw + w
          dpSize = 2 * w + pw
          -- CLASS=secret, KEY_TYPE=generic, VALUE_LEN=16.
          pokeAttr base vp i typ val = do
            pokeByteOff vp 0 (CULong val)
            let el = base `plusPtr` (i * attrSize)
            pokeByteOff el 0 (CULong typ)
            pokeByteOff el pw (castPtr vp :: Ptr Word8)
            pokeByteOff el (2 * w) (CULong (fromIntegral w))
          -- The minimal counter profile: an 8-bit counter plus
          -- the sum-of-keys DKM length (the chase needs at
          -- least the iteration/DKM-length pair).
          withProfile action =
            allocaBytes 16 $ \cfmt ->
              allocaBytes 24 $ \lfmt ->
                allocaBytes (2 * dpSize) $ \dps -> do
                  pokeByteOff cfmt 0 (0 :: Word8)
                  pokeByteOff cfmt 8 (CULong 8)
                  pokeByteOff lfmt 0 (CULong 1)
                  pokeByteOff lfmt 8 (0 :: Word8)
                  pokeByteOff lfmt 16 (CULong 32)
                  pokeByteOff dps 0 (CULong 1)
                  pokeByteOff dps w (castPtr cfmt :: Ptr Word8)
                  pokeByteOff dps (w + pw) (CULong 16)
                  let el1 = dps `plusPtr` dpSize
                  pokeByteOff el1 0 (CULong 3)
                  pokeByteOff el1 w (castPtr lfmt :: Ptr Word8)
                  pokeByteOff el1 (w + pw) (CULong 24)
                  action dps
      got <- allocaBytes w $ \v0 ->
        allocaBytes w $ \v1 ->
          allocaBytes w $ \v2 ->
            allocaBytes (3 * attrSize) $ \attrs ->
              allocaBytes dkSize $ \dk ->
                allocaBytes w $ \phKey ->
                  withProfile $ \dps ->
                    allocaBytes 40 $ \p -> do
                      pokeAttr attrs v0 0 0x0 0x4
                      pokeAttr attrs v1 1 0x100 0x10
                      pokeAttr attrs v2 2 0x161 16
                      pokeByteOff dk 0 (castPtr attrs :: Ptr Word8)
                      pokeByteOff dk pw (CULong 3)
                      pokeByteOff dk (pw + w) (castPtr phKey :: Ptr CULong)
                      pokeByteOff p 0 (CULong prf)
                      pokeByteOff p w (CULong 2)
                      pokeByteOff p (2 * w) (castPtr dps :: Ptr Word8)
                      pokeByteOff p (2 * w + pw) (CULong 1)
                      pokeByteOff p (3 * w + pw) (castPtr dk :: Ptr Word8)
                      normalizeSp800KdfParams Sp800Counter p 40
      case got of
        Just (blob, [slot]) -> do
          assertEqual "frame decodes" True
            (case decodeSp800Params blob of Just _ -> True; Nothing -> False)
          assertEqual "template" [(AttrClass, ValULong 0x4), (AttrKeyType, ValULong 0x10), (AttrValueLen, ValULong 16)]
            (dksTemplate slot)
        other -> fail ("additional chase refused: " ++ show (fmap (const ()) other))
      -- Zero count with a dangling pointer refuses (spec: NULL).
      dangling <- withProfile $ \dps ->
        allocaBytes dkSize $ \dk ->
          allocaBytes 40 $ \p -> do
            pokeByteOff p 0 (CULong prf)
            pokeByteOff p w (CULong 2)
            pokeByteOff p (2 * w) (castPtr dps :: Ptr Word8)
            pokeByteOff p (2 * w + pw) (CULong 0)
            pokeByteOff p (3 * w + pw) (castPtr dk :: Ptr Word8)
            normalizeSp800KdfParams Sp800Counter p 40
      assertEqual "dangling refused" Nothing dangling
      -- Zero count with NULL chases clean with no slots.
      clean <- withProfile $ \dps ->
        allocaBytes 40 $ \p -> do
          pokeByteOff p 0 (CULong prf)
          pokeByteOff p w (CULong 2)
          pokeByteOff p (2 * w) (castPtr dps :: Ptr Word8)
          pokeByteOff p (2 * w + pw) (CULong 0)
          pokeByteOff p (3 * w + pw) (nullPtr :: Ptr Word8)
          normalizeSp800KdfParams Sp800Counter p 40
      case clean of
        Just (_, []) -> pure ()
        other -> fail ("clean chase off-shape: " ++ show (fmap (const ()) other))
  ]
