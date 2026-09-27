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
import Foreign.Storable (alignment, pokeByteOff, sizeOf)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertEqual, testCase)

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
  , normalizeMechParams
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
import Haskoki.Recipe.Eddsa
  ( eddsaParamsValid
  , eddsaRecipeFor
  , encodeEddsaParams
  )
import Haskoki.Recipe.Gcm (encodeGcmParams, gcmParamsValid, gcmRecipeFor)
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
  ]
