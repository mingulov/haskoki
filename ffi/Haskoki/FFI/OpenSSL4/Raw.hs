{- | Private OpenSSL 4 foreign imports for the Haskoki backend.

This module is the ONLY Haskell module (besides 'Haskoki.Engine.OpenSSL4',
which owns the resulting 'ForeignPtr's) allowed to import @Foreign.*@ for
the engine. It binds the narrow @cbits/ossl4_ctx.*@ shim -- a
provider-only surface -- and converts shim results into owned strict
'ByteString's, clearing native buffers with @hsk_ossl4_free@ after each
copy. Nothing here is exported from the @haskoki@ package publicly.
-}
{-# LANGUAGE ForeignFunctionInterface #-}
module Haskoki.FFI.OpenSSL4.Raw
  ( -- * Opaque native types
    OsslEnv
  , OsslLibCtx
  , DigestHandle
    -- * Error codes
  , errNative
  , errBadParam
  , errBadKey
  , errNoMem
  , errAuthFail
  , errBadPeer
    -- * Lifecycle
  , envNew
  , envLoad
  , envCtx
  , envFree
  , envFreeFinalizer
  , digestFreeFinalizer
  , libVersion
  , lastError
  , probe
    -- * Fetch+run helpers (owned outputs)
  , digest
  , digestSized
  , digestXof
  , digestInit
  , digestInitSized
  , digestUpdate
  , digestFinal
  , digestFree
  , hmac
  , hmacSized
  , cipherCbc
  , cipherCts
  , cipherWrap
  , cipherXts
  , aeadEncrypt
  , aeadDecrypt
  , aeadCcmEncrypt
  , aeadCcmDecrypt
  , ecGen
  , rsaGen
  , randBytes
  , randSeed
  , ecdsaSign
  , ecdsaVerify
  , dsaSign
  , dsaVerify
  , dsaGenParams
  , dsaGenKeypair
  , eddsaSign
  , eddsaVerify
  , edwardsGen
  , montgomeryGen
  , mldsaSign
  , mldsaVerify
  , mldsaGen
  , slhdsaSign
  , slhdsaVerify
  , slhdsaGen
  , mlkemEncaps
  , mlkemDecaps
  , mlkemGen
  , ecdhDerive
  , xdhDerive
  , dhDerive
  , dhGenKeypair
  , rsaSign
  , rsaVerify
  , rsaPssSign
  , rsaPssVerify
  , rsaOaepEncrypt
  , rsaOaepDecrypt
  , rsaPkcs1Encrypt
  , rsaPkcs1Decrypt
  , rsaX509Encrypt
  , rsaX509Decrypt
  , rsaX509Sign
  , rsaX509Verify
  ) where

import qualified Data.ByteString as BS
import qualified Data.ByteString.Unsafe as BSU
import Data.ByteString (ByteString)
import Foreign.C.String (CString, peekCString, withCString)
import Foreign.C.Types (CChar (..), CInt (..), CLong (..), CSize (..), CUChar (..))
import Foreign.Marshal.Alloc (alloca, allocaBytes)
import Foreign.Ptr (FunPtr, Ptr, castPtr, nullPtr)
import Foreign.Storable (peek)

-- Opaque native types (never constructed in Haskell).

data OsslEnv
data OsslLibCtx
data DigestHandle

-- Shim error codes (mirror cbits/ossl4_ctx.h).

errNative, errBadParam, errBadKey, errNoMem, errAuthFail, errBadPeer :: Int
errNative = -1
errBadParam = -2
errBadKey = -3
errNoMem = -4
errAuthFail = -5
errBadPeer = -6

-- Foreign imports: the hsk_ossl4_* shim only.

foreign import ccall safe "ossl4_ctx.h hsk_ossl4_env_new"
  c_env_new :: IO (Ptr OsslEnv)

foreign import ccall safe "ossl4_ctx.h hsk_ossl4_env_load"
  c_env_load :: Ptr OsslEnv -> CString -> IO CInt

foreign import ccall unsafe "ossl4_ctx.h hsk_ossl4_env_ctx"
  c_env_ctx :: Ptr OsslEnv -> IO (Ptr OsslLibCtx)

foreign import ccall safe "ossl4_ctx.h &hsk_ossl4_env_free"
  c_env_free_finalizer :: FunPtr (Ptr OsslEnv -> IO ())

-- manual call (closeBackend runs ordered teardown eagerly)
foreign import ccall safe "ossl4_ctx.h hsk_ossl4_env_free"
  c_env_free :: Ptr OsslEnv -> IO ()

foreign import ccall unsafe "ossl4_ctx.h hsk_ossl4_version"
  c_version :: IO CString

foreign import ccall unsafe "ossl4_ctx.h hsk_ossl4_free"
  c_free :: Ptr () -> CSize -> IO ()

foreign import ccall safe "ossl4_ctx.h hsk_ossl4_last_error"
  c_last_error :: Ptr CChar -> CSize -> IO CSize

foreign import ccall safe "ossl4_ctx.h hsk_ossl4_probe"
  c_probe :: Ptr OsslLibCtx -> CString -> CString -> CString -> IO CInt

foreign import ccall safe "ossl4_ctx.h hsk_ossl4_digest"
  c_digest :: Ptr OsslLibCtx -> CString -> CString -> Ptr CUChar -> CSize -> Ptr (Ptr CUChar) -> IO CLong

foreign import ccall safe "ossl4_ctx.h hsk_ossl4_digest_sized"
  c_digest_sized :: Ptr OsslLibCtx -> CString -> CString -> Ptr CUChar -> CSize -> CInt -> Ptr (Ptr CUChar) -> IO CLong

foreign import ccall safe "ossl4_ctx.h hsk_ossl4_digest_xof"
  c_digest_xof :: Ptr OsslLibCtx -> CString -> CString -> Ptr CUChar -> CSize -> CInt -> Ptr (Ptr CUChar) -> IO CLong

foreign import ccall safe "ossl4_ctx.h hsk_ossl4_digest_init"
  c_digest_init :: Ptr OsslLibCtx -> CString -> CString -> IO (Ptr DigestHandle)

foreign import ccall safe "ossl4_ctx.h hsk_ossl4_digest_init_sized"
  c_digest_init_sized :: Ptr OsslLibCtx -> CString -> CString -> CInt -> IO (Ptr DigestHandle)

foreign import ccall safe "ossl4_ctx.h hsk_ossl4_digest_update"
  c_digest_update :: Ptr DigestHandle -> Ptr CUChar -> CSize -> IO CInt

foreign import ccall safe "ossl4_ctx.h hsk_ossl4_digest_final"
  c_digest_final :: Ptr DigestHandle -> Ptr (Ptr CUChar) -> IO CLong

foreign import ccall safe "ossl4_ctx.h hsk_ossl4_digest_free"
  c_digest_free :: Ptr DigestHandle -> IO ()

foreign import ccall safe "ossl4_ctx.h &hsk_ossl4_digest_free"
  c_digest_free_finalizer :: FunPtr (Ptr DigestHandle -> IO ())

foreign import ccall safe "ossl4_ctx.h hsk_ossl4_hmac"
  c_hmac :: Ptr OsslLibCtx -> CString -> CString -> Ptr CUChar -> CSize -> Ptr CUChar -> CSize -> Ptr (Ptr CUChar) -> IO CLong

foreign import ccall safe "ossl4_ctx.h hsk_ossl4_hmac_sized"
  c_hmac_sized :: Ptr OsslLibCtx -> CString -> CString -> Ptr CUChar -> CSize -> Ptr CUChar -> CSize -> CInt -> Ptr (Ptr CUChar) -> IO CLong

foreign import ccall safe "ossl4_ctx.h hsk_ossl4_cipher_cbc"
  c_cipher_cbc :: Ptr OsslLibCtx -> CString -> CString -> CInt -> Ptr CUChar -> CSize -> Ptr CUChar -> CSize -> Ptr CUChar -> CSize -> Ptr (Ptr CUChar) -> IO CLong

foreign import ccall safe "ossl4_ctx.h hsk_ossl4_cipher_cts"
  c_cipher_cts :: Ptr OsslLibCtx -> CString -> CString -> CInt -> Ptr CUChar -> CSize -> Ptr CUChar -> CSize -> Ptr CUChar -> CSize -> Ptr (Ptr CUChar) -> IO CLong

foreign import ccall safe "ossl4_ctx.h hsk_ossl4_cipher_wrap"
  c_cipher_wrap :: Ptr OsslLibCtx -> CString -> CString -> CInt -> CInt -> Ptr CUChar -> CSize -> Ptr CUChar -> CSize -> Ptr (Ptr CUChar) -> IO CLong
foreign import ccall safe "ossl4_ctx.h hsk_ossl4_cipher_xts"
  c_cipher_xts :: Ptr OsslLibCtx -> CString -> CString -> CInt -> Ptr CUChar -> CSize -> Ptr CUChar -> CSize -> Ptr CUChar -> CSize -> Ptr (Ptr CUChar) -> IO CLong

foreign import ccall safe "ossl4_ctx.h hsk_ossl4_aead_encrypt"
  c_aead_encrypt :: Ptr OsslLibCtx -> CString -> CString -> Ptr CUChar -> CSize -> Ptr CUChar -> CSize -> Ptr CUChar -> CSize -> Ptr CUChar -> CSize -> CSize -> Ptr (Ptr CUChar) -> IO CLong
foreign import ccall safe "ossl4_ctx.h hsk_ossl4_aead_decrypt"
  c_aead_decrypt :: Ptr OsslLibCtx -> CString -> CString -> Ptr CUChar -> CSize -> Ptr CUChar -> CSize -> Ptr CUChar -> CSize -> Ptr CUChar -> CSize -> Ptr CUChar -> CSize -> Ptr (Ptr CUChar) -> IO CLong
foreign import ccall safe "ossl4_ctx.h hsk_ossl4_aead_ccm_encrypt"
  c_aead_ccm_encrypt :: Ptr OsslLibCtx -> CString -> CString -> Ptr CUChar -> CSize -> Ptr CUChar -> CSize -> Ptr CUChar -> CSize -> Ptr CUChar -> CSize -> CSize -> Ptr (Ptr CUChar) -> IO CLong
foreign import ccall safe "ossl4_ctx.h hsk_ossl4_aead_ccm_decrypt"
  c_aead_ccm_decrypt :: Ptr OsslLibCtx -> CString -> CString -> Ptr CUChar -> CSize -> Ptr CUChar -> CSize -> Ptr CUChar -> CSize -> Ptr CUChar -> CSize -> Ptr CUChar -> CSize -> Ptr (Ptr CUChar) -> IO CLong

foreign import ccall safe "ossl4_ctx.h hsk_ossl4_ec_gen"
  c_ec_gen :: Ptr OsslLibCtx -> CString -> CString -> Ptr (Ptr CUChar) -> Ptr CSize -> Ptr (Ptr CUChar) -> Ptr CSize -> IO CInt

foreign import ccall safe "ossl4_ctx.h hsk_ossl4_rsa_gen_keypair"
  c_rsa_gen :: Ptr OsslLibCtx -> CInt -> Ptr CUChar -> CSize -> CString -> Ptr (Ptr CUChar) -> Ptr CSize -> Ptr (Ptr CUChar) -> Ptr CSize -> IO CInt

foreign import ccall safe "ossl4_ctx.h hsk_ossl4_rand_bytes"
  c_rand_bytes :: Ptr OsslLibCtx -> CSize -> Ptr (Ptr CUChar) -> IO CLong

-- Safe, per the module's audited split (only the ctx getter,
-- version string, and free are unsafe; every entry that runs crypto
-- work is a safe call).
foreign import ccall safe "ossl4_ctx.h hsk_ossl4_rand_seed"
  c_rand_seed :: Ptr OsslLibCtx -> Ptr CUChar -> CSize -> IO CLong

foreign import ccall safe "ossl4_ctx.h hsk_ossl4_ecdsa_sign"
  c_ecdsa_sign :: Ptr OsslLibCtx -> CString -> CString -> Ptr CUChar -> CSize -> Ptr CUChar -> CSize -> CInt -> CInt -> Ptr (Ptr CUChar) -> IO CLong

foreign import ccall safe "ossl4_ctx.h hsk_ossl4_ecdsa_verify"
  c_ecdsa_verify :: Ptr OsslLibCtx -> CString -> CString -> Ptr CUChar -> CSize -> Ptr CUChar -> CSize -> Ptr CUChar -> CSize -> CInt -> CInt -> IO CInt

foreign import ccall safe "ossl4_ctx.h hsk_ossl4_dsa_sign"
  c_dsa_sign :: Ptr OsslLibCtx -> CString -> CString -> Ptr CUChar -> CSize -> Ptr CUChar -> CSize -> CInt -> CInt -> Ptr (Ptr CUChar) -> IO CLong

foreign import ccall safe "ossl4_ctx.h hsk_ossl4_dsa_verify"
  c_dsa_verify :: Ptr OsslLibCtx -> CString -> CString -> Ptr CUChar -> CSize -> Ptr CUChar -> CSize -> Ptr CUChar -> CSize -> CInt -> CInt -> IO CInt

foreign import ccall safe "ossl4_ctx.h hsk_ossl4_dsa_gen_params"
  c_dsa_gen_params :: Ptr OsslLibCtx -> CString -> CInt -> CInt -> Ptr (Ptr CUChar) -> IO CLong

foreign import ccall safe "ossl4_ctx.h hsk_ossl4_dsa_gen_keypair"
  c_dsa_gen_keypair :: Ptr OsslLibCtx -> CString -> Ptr CUChar -> CSize -> Ptr (Ptr CUChar) -> Ptr CSize -> Ptr (Ptr CUChar) -> Ptr CSize -> IO CInt

foreign import ccall safe "ossl4_ctx.h hsk_ossl4_eddsa_sign"
  c_eddsa_sign :: Ptr OsslLibCtx -> CString -> CString -> Ptr CUChar -> CSize -> Ptr CUChar -> CSize -> Ptr (Ptr CUChar) -> IO CLong

foreign import ccall safe "ossl4_ctx.h hsk_ossl4_eddsa_verify"
  c_eddsa_verify :: Ptr OsslLibCtx -> CString -> CString -> Ptr CUChar -> CSize -> Ptr CUChar -> CSize -> Ptr CUChar -> CSize -> IO CInt

foreign import ccall safe "ossl4_ctx.h hsk_ossl4_edwards_gen"
  c_edwards_gen :: Ptr OsslLibCtx -> CString -> CString -> Ptr (Ptr CUChar) -> Ptr CSize -> Ptr (Ptr CUChar) -> Ptr CSize -> IO CInt

foreign import ccall safe "ossl4_ctx.h hsk_ossl4_montgomery_gen"
  c_montgomery_gen :: Ptr OsslLibCtx -> CString -> CString -> Ptr (Ptr CUChar) -> Ptr CSize -> Ptr (Ptr CUChar) -> Ptr CSize -> IO CInt

foreign import ccall safe "ossl4_ctx.h hsk_ossl4_mldsa_sign"
  c_mldsa_sign :: Ptr OsslLibCtx -> CString -> CString -> Ptr CUChar -> CSize -> Ptr CUChar -> CSize -> Ptr CUChar -> CSize -> CInt -> Ptr (Ptr CUChar) -> IO CLong

foreign import ccall safe "ossl4_ctx.h hsk_ossl4_mldsa_verify"
  c_mldsa_verify :: Ptr OsslLibCtx -> CString -> CString -> Ptr CUChar -> CSize -> Ptr CUChar -> CSize -> Ptr CUChar -> CSize -> Ptr CUChar -> CSize -> IO CInt

foreign import ccall safe "ossl4_ctx.h hsk_ossl4_mldsa_gen"
  c_mldsa_gen :: Ptr OsslLibCtx -> CString -> CString -> Ptr (Ptr CUChar) -> Ptr CSize -> Ptr (Ptr CUChar) -> Ptr CSize -> IO CInt

foreign import ccall safe "ossl4_ctx.h hsk_ossl4_slhdsa_sign"
  c_slhdsa_sign :: Ptr OsslLibCtx -> CString -> CString -> Ptr CUChar -> CSize -> Ptr CUChar -> CSize -> Ptr CUChar -> CSize -> CInt -> Ptr (Ptr CUChar) -> IO CLong

foreign import ccall safe "ossl4_ctx.h hsk_ossl4_slhdsa_verify"
  c_slhdsa_verify :: Ptr OsslLibCtx -> CString -> CString -> Ptr CUChar -> CSize -> Ptr CUChar -> CSize -> Ptr CUChar -> CSize -> Ptr CUChar -> CSize -> IO CInt

foreign import ccall safe "ossl4_ctx.h hsk_ossl4_slhdsa_gen"
  c_slhdsa_gen :: Ptr OsslLibCtx -> CString -> CString -> Ptr (Ptr CUChar) -> Ptr CSize -> Ptr (Ptr CUChar) -> Ptr CSize -> IO CInt

foreign import ccall safe "ossl4_ctx.h hsk_ossl4_mlkem_encaps"
  c_mlkem_encaps :: Ptr OsslLibCtx -> CString -> CString -> Ptr CUChar -> CSize -> Ptr (Ptr CUChar) -> IO CLong

foreign import ccall safe "ossl4_ctx.h hsk_ossl4_mlkem_decaps"
  c_mlkem_decaps :: Ptr OsslLibCtx -> CString -> CString -> Ptr CUChar -> CSize -> Ptr CUChar -> CSize -> Ptr (Ptr CUChar) -> IO CLong

foreign import ccall safe "ossl4_ctx.h hsk_ossl4_mlkem_gen"
  c_mlkem_gen :: Ptr OsslLibCtx -> CString -> CString -> Ptr (Ptr CUChar) -> Ptr CSize -> Ptr (Ptr CUChar) -> Ptr CSize -> IO CInt

foreign import ccall safe "ossl4_ctx.h hsk_ossl4_ecdh_derive"
  c_ecdh_derive :: Ptr OsslLibCtx -> CString -> Ptr CUChar -> CSize -> Ptr CUChar -> CSize -> CInt -> Ptr (Ptr CUChar) -> IO CLong

foreign import ccall safe "ossl4_ctx.h hsk_ossl4_xdh_derive"
  c_xdh_derive :: Ptr OsslLibCtx -> CString -> Ptr CUChar -> CSize -> Ptr CUChar -> CSize -> Ptr (Ptr CUChar) -> IO CLong

foreign import ccall safe "ossl4_ctx.h hsk_ossl4_dh_derive"
  c_dh_derive :: Ptr OsslLibCtx -> CString -> Ptr CUChar -> CSize -> Ptr CUChar -> CSize -> Ptr (Ptr CUChar) -> IO CLong
foreign import ccall safe "ossl4_ctx.h hsk_ossl4_dh_gen_keypair"
  c_dh_gen_keypair :: Ptr OsslLibCtx -> CString -> Ptr CUChar -> CSize -> Ptr (Ptr CUChar) -> Ptr CSize -> Ptr (Ptr CUChar) -> Ptr CSize -> IO CInt

foreign import ccall safe "ossl4_ctx.h hsk_ossl4_rsa_sign"
  c_rsa_sign :: Ptr OsslLibCtx -> CString -> CString -> Ptr CUChar -> CSize -> Ptr CUChar -> CSize -> CInt -> Ptr (Ptr CUChar) -> IO CLong

foreign import ccall safe "ossl4_ctx.h hsk_ossl4_rsa_verify"
  c_rsa_verify :: Ptr OsslLibCtx -> CString -> CString -> Ptr CUChar -> CSize -> Ptr CUChar -> CSize -> Ptr CUChar -> CSize -> CInt -> IO CInt

foreign import ccall safe "ossl4_ctx.h hsk_ossl4_rsa_pss_sign"
  c_rsa_pss_sign :: Ptr OsslLibCtx -> CString -> CString -> CInt -> CString -> Ptr CUChar -> CSize -> Ptr CUChar -> CSize -> Ptr (Ptr CUChar) -> IO CLong

foreign import ccall safe "ossl4_ctx.h hsk_ossl4_rsa_pss_verify"
  c_rsa_pss_verify :: Ptr OsslLibCtx -> CString -> CString -> CInt -> CString -> Ptr CUChar -> CSize -> Ptr CUChar -> CSize -> Ptr CUChar -> CSize -> IO CInt

foreign import ccall safe "ossl4_ctx.h hsk_ossl4_rsa_oaep_encrypt"
  c_rsa_oaep_encrypt :: Ptr OsslLibCtx -> CString -> CString -> Ptr CUChar -> CSize -> CString -> Ptr CUChar -> CSize -> Ptr CUChar -> CSize -> Ptr (Ptr CUChar) -> IO CLong

foreign import ccall safe "ossl4_ctx.h hsk_ossl4_rsa_oaep_decrypt"
  c_rsa_oaep_decrypt :: Ptr OsslLibCtx -> CString -> CString -> Ptr CUChar -> CSize -> CString -> Ptr CUChar -> CSize -> Ptr CUChar -> CSize -> Ptr (Ptr CUChar) -> IO CLong

foreign import ccall safe "ossl4_ctx.h hsk_ossl4_rsa_pkcs1_encrypt"
  c_rsa_pkcs1_encrypt :: Ptr OsslLibCtx -> CString -> Ptr CUChar -> CSize -> Ptr CUChar -> CSize -> Ptr (Ptr CUChar) -> IO CLong

foreign import ccall safe "ossl4_ctx.h hsk_ossl4_rsa_pkcs1_decrypt"
  c_rsa_pkcs1_decrypt :: Ptr OsslLibCtx -> CString -> Ptr CUChar -> CSize -> Ptr CUChar -> CSize -> Ptr (Ptr CUChar) -> IO CLong

foreign import ccall safe "ossl4_ctx.h hsk_ossl4_rsa_x509_encrypt"
  c_rsa_x509_encrypt :: Ptr OsslLibCtx -> CString -> Ptr CUChar -> CSize -> Ptr CUChar -> CSize -> Ptr (Ptr CUChar) -> IO CLong

foreign import ccall safe "ossl4_ctx.h hsk_ossl4_rsa_x509_decrypt"
  c_rsa_x509_decrypt :: Ptr OsslLibCtx -> CString -> Ptr CUChar -> CSize -> Ptr CUChar -> CSize -> Ptr (Ptr CUChar) -> IO CLong

foreign import ccall safe "ossl4_ctx.h hsk_ossl4_rsa_x509_sign"
  c_rsa_x509_sign :: Ptr OsslLibCtx -> CString -> Ptr CUChar -> CSize -> Ptr CUChar -> CSize -> Ptr (Ptr CUChar) -> IO CLong

foreign import ccall safe "ossl4_ctx.h hsk_ossl4_rsa_x509_verify"
  c_rsa_x509_verify :: Ptr OsslLibCtx -> CString -> Ptr CUChar -> CSize -> Ptr CUChar -> CSize -> Ptr CUChar -> CSize -> IO CInt

-- Managed wrappers.

-- | Use a 'ByteString' as @(ptr, len)@. The empty string uses a
-- throwaway non-NULL pointer with length 0.
withBytes :: ByteString -> ((Ptr CUChar, CSize) -> IO a) -> IO a
withBytes bs action
  | BS.null bs = allocaBytes 1 $ \p -> action (p, 0)
  | otherwise = BSU.unsafeUseAsCStringLen bs $ \(p, n) ->
      action (castPtr p, fromIntegral n)

-- | 'Nothing' is @(NULL, 0)@ (parameter absent); @Just@ uses
-- 'withBytes', so @Just ""@ is a present-but-empty buffer —
-- distinct from absent for shims that branch on NULL (ML-DSA
-- context: absent means pure, present means the context-string
-- param is set, even when empty).
withOptBytes :: Maybe ByteString -> ((Ptr CUChar, CSize) -> IO a) -> IO a
withOptBytes Nothing action = action (nullPtr, 0)
withOptBytes (Just bs) action = withBytes bs action

-- | Take ownership of a shim output buffer: copy @len@ bytes into an
-- owned 'ByteString', then clear+free the native buffer.
takeOwned :: Ptr CUChar -> Int -> IO ByteString
takeOwned p n = do
  bs <- BS.packCStringLen (castPtr p, n)
  c_free (castPtr p) (fromIntegral n)
  pure bs

-- | Run a shim call that reports a @long@ length-or-negative-code and
-- an out-pointer; copy the output on success.
withOut :: (Ptr (Ptr CUChar) -> IO CLong) -> IO (Either Int ByteString)
withOut call = alloca $ \outp -> do
  rc <- call outp
  if rc < 0
    then pure (Left (fromIntegral rc))
    else do
      p <- peek outp
      if p == nullPtr
        then pure (Left errNative)
        else Right <$> takeOwned p (fromIntegral rc)

-- | Current oldest queued native error string (clears the queue).
lastError :: IO String
lastError = allocaBytes 256 $ \buf -> do
  _ <- c_last_error buf 256
  peekCString (castPtr buf)

-- | Static libcrypto version string.
libVersion :: IO String
libVersion = c_version >>= peekCString

envNew :: IO (Ptr OsslEnv)
envNew = c_env_new

envLoad :: Ptr OsslEnv -> String -> IO Int
envLoad env name = withCString name $ \cname ->
  fromIntegral <$> c_env_load env cname

envCtx :: Ptr OsslEnv -> IO (Ptr OsslLibCtx)
envCtx = c_env_ctx

envFree :: Ptr OsslEnv -> IO ()
envFree = c_env_free

envFreeFinalizer :: FunPtr (Ptr OsslEnv -> IO ())
envFreeFinalizer = c_env_free_finalizer

digestFreeFinalizer :: FunPtr (Ptr DigestHandle -> IO ())
digestFreeFinalizer = c_digest_free_finalizer

probe :: Ptr OsslLibCtx -> String -> String -> String -> IO Int
probe ctx kind name propq =
  withCString kind $ \ck ->
    withCString name $ \cn ->
      withCString propq $ \cp ->
        fromIntegral <$> c_probe ctx ck cn cp

digest :: Ptr OsslLibCtx -> String -> String -> ByteString -> IO (Either Int ByteString)
digest ctx mdname propq msg =
  withCString mdname $ \cmd ->
    withCString propq $ \cpq ->
      withBytes msg $ \(pmsg, nmsg) ->
        withOut (c_digest ctx cmd cpq pmsg nmsg)

digestSized :: Ptr OsslLibCtx -> String -> String -> ByteString -> Int -> IO (Either Int ByteString)
digestSized ctx mdname propq msg outsize =
  withCString mdname $ \cmd ->
    withCString propq $ \cpq ->
      withBytes msg $ \(pmsg, nmsg) ->
        withOut (c_digest_sized ctx cmd cpq pmsg nmsg (fromIntegral outsize))

digestXof :: Ptr OsslLibCtx -> String -> String -> ByteString -> Int -> IO (Either Int ByteString)
digestXof ctx mdname propq msg outsize =
  withCString mdname $ \cmd ->
    withCString propq $ \cpq ->
      withBytes msg $ \(pmsg, nmsg) ->
        withOut (c_digest_xof ctx cmd cpq pmsg nmsg (fromIntegral outsize))

digestInit :: Ptr OsslLibCtx -> String -> String -> IO (Ptr DigestHandle)
digestInit ctx mdname propq =
  withCString mdname $ \cmd ->
    withCString propq $ \cpq ->
      c_digest_init ctx cmd cpq

digestInitSized :: Ptr OsslLibCtx -> String -> String -> Int -> IO (Ptr DigestHandle)
digestInitSized ctx mdname propq outsize =
  withCString mdname $ \cmd ->
    withCString propq $ \cpq ->
      c_digest_init_sized ctx cmd cpq (fromIntegral outsize)

digestUpdate :: Ptr DigestHandle -> ByteString -> IO Int
digestUpdate h msg =
  withBytes msg $ \(pmsg, nmsg) ->
    fromIntegral <$> c_digest_update h pmsg nmsg

digestFinal :: Ptr DigestHandle -> IO (Either Int ByteString)
digestFinal h = withOut (c_digest_final h)

digestFree :: Ptr DigestHandle -> IO ()
digestFree = c_digest_free

hmac :: Ptr OsslLibCtx -> String -> String -> ByteString -> ByteString -> IO (Either Int ByteString)
hmac ctx mdname propq key msg =
  withCString mdname $ \cmd ->
    withCString propq $ \cpq ->
      withBytes key $ \(pkey, nkey) ->
        withBytes msg $ \(pmsg, nmsg) ->
          withOut (c_hmac ctx cmd cpq pkey nkey pmsg nmsg)

hmacSized :: Ptr OsslLibCtx -> String -> String -> ByteString -> ByteString -> Int -> IO (Either Int ByteString)
hmacSized ctx mdname propq key msg outsize =
  withCString mdname $ \cmd ->
    withCString propq $ \cpq ->
      withBytes key $ \(pkey, nkey) ->
        withBytes msg $ \(pmsg, nmsg) ->
          withOut (c_hmac_sized ctx cmd cpq pkey nkey pmsg nmsg (fromIntegral outsize))

cipherCbc :: Ptr OsslLibCtx -> String -> String -> Bool -> ByteString -> ByteString -> ByteString -> IO (Either Int ByteString)
cipherCbc ctx ciphername propq enc key iv input =
  withCString ciphername $ \cc ->
    withCString propq $ \cpq ->
      withBytes key $ \(pkey, nkey) ->
        withBytes iv $ \(piv, niv) ->
          withBytes input $ \(pin, nin) ->
            withOut (c_cipher_cbc ctx cc cpq (if enc then 1 else 0) pkey nkey piv niv pin nin)

-- | AES-CTS (CBC-CS1): @ecbname@ is the fetched ECB primitive the
-- shim builds the stealing construction over. Output length always
-- equals input length; input shorter than one block answers
-- 'errBadParam'.
cipherCts :: Ptr OsslLibCtx -> String -> String -> Bool -> ByteString -> ByteString -> ByteString -> IO (Either Int ByteString)
cipherCts ctx ecbname propq enc key iv input =
  withCString ecbname $ \cc ->
    withCString propq $ \cpq ->
      withBytes key $ \(pkey, nkey) ->
        withBytes iv $ \(piv, niv) ->
          withBytes input $ \(pin, nin) ->
            withOut (c_cipher_cts ctx cc cpq (if enc then 1 else 0) pkey nkey piv niv pin nin)

-- | AES key wrap: @ciphername@ is the fetched wrap cipher
-- (@AES-\{128,192,256\}-WRAP@ for @kwp == False@,
-- @AES-\{128,192,256\}-WRAP-PAD@ for @kwp == True@); no IV.
-- Output expands (KW: inlen + 8; KWP: ceil8(inlen) + 8).
-- Geometry violations answer 'errBadParam'; a decrypt-side
-- integrity failure answers 'errAuthFail'.
cipherWrap :: Ptr OsslLibCtx -> String -> String -> Bool -> Bool -> ByteString -> ByteString -> IO (Either Int ByteString)
cipherWrap ctx ciphername propq enc kwp key input =
  withCString ciphername $ \cc ->
    withCString propq $ \cpq ->
      withBytes key $ \(pkey, nkey) ->
        withBytes input $ \(pin, nin) ->
          withOut (c_cipher_wrap ctx cc cpq (if enc then 1 else 0) (if kwp then 1 else 0) pkey nkey pin nin)

-- | AES-XTS: @ciphername@ is the fetched XTS cipher
-- (@AES-\\{128,256\\}-XTS@); @tweak@ is the 16-byte data-unit
-- tweak (rides as the IV). Length-preserving over inputs >= 16
-- bytes. Short input answers 'errBadParam'; an equal-halves
-- weak key answers 'errBadKey'.
cipherXts :: Ptr OsslLibCtx -> String -> String -> Bool -> ByteString -> ByteString -> ByteString -> IO (Either Int ByteString)
cipherXts ctx ciphername propq enc key tweak input =
  withCString ciphername $ \cc ->
    withCString propq $ \cpq ->
      withBytes key $ \(pkey, nkey) ->
        withBytes tweak $ \(ptweak, ntweak) ->
          withBytes input $ \(pin, nin) ->
            withOut (c_cipher_xts ctx cc cpq (if enc then 1 else 0) pkey nkey ptweak ntweak pin nin)

-- | AEAD encrypt: returns @ct || tag@ (tag length known to the caller).
aeadEncrypt :: Ptr OsslLibCtx -> String -> String -> ByteString -> ByteString -> ByteString -> ByteString -> Int -> IO (Either Int ByteString)
aeadEncrypt ctx ciphername propq key iv aad input tagLen =
  withCString ciphername $ \cc ->
    withCString propq $ \cpq ->
      withBytes key $ \(pkey, nkey) ->
        withBytes iv $ \(piv, niv) ->
          withBytes aad $ \(paad, naad) ->
            withBytes input $ \(pin, nin) ->
              withOut (c_aead_encrypt ctx cc cpq pkey nkey piv niv paad naad pin nin (fromIntegral tagLen))

-- | AEAD decrypt: takes ct and the expected tag separately.
aeadDecrypt :: Ptr OsslLibCtx -> String -> String -> ByteString -> ByteString -> ByteString -> ByteString -> ByteString -> IO (Either Int ByteString)
aeadDecrypt ctx ciphername propq key iv aad input tag =
  withCString ciphername $ \cc ->
    withCString propq $ \cpq ->
      withBytes key $ \(pkey, nkey) ->
        withBytes iv $ \(piv, niv) ->
          withBytes aad $ \(paad, naad) ->
            withBytes input $ \(pin, nin) ->
              withBytes tag $ \(ptag, ntag) ->
                withOut (c_aead_decrypt ctx cc cpq pkey nkey piv niv paad naad pin nin ptag ntag)

-- | CCM AEAD encrypt: returns @ct || tag@ (tag length known to the caller).
aeadCcmEncrypt :: Ptr OsslLibCtx -> String -> String -> ByteString -> ByteString -> ByteString -> ByteString -> Int -> IO (Either Int ByteString)
aeadCcmEncrypt ctx ciphername propq key iv aad input tagLen =
  withCString ciphername $ \cc ->
    withCString propq $ \cpq ->
      withBytes key $ \(pkey, nkey) ->
        withBytes iv $ \(piv, niv) ->
          withBytes aad $ \(paad, naad) ->
            withBytes input $ \(pin, nin) ->
              withOut (c_aead_ccm_encrypt ctx cc cpq pkey nkey piv niv paad naad pin nin (fromIntegral tagLen))

-- | CCM AEAD decrypt: takes ct and the expected tag separately.
aeadCcmDecrypt :: Ptr OsslLibCtx -> String -> String -> ByteString -> ByteString -> ByteString -> ByteString -> ByteString -> IO (Either Int ByteString)
aeadCcmDecrypt ctx ciphername propq key iv aad input tag =
  withCString ciphername $ \cc ->
    withCString propq $ \cpq ->
      withBytes key $ \(pkey, nkey) ->
        withBytes iv $ \(piv, niv) ->
          withBytes aad $ \(paad, naad) ->
            withBytes input $ \(pin, nin) ->
              withBytes tag $ \(ptag, ntag) ->
                withOut (c_aead_ccm_decrypt ctx cc cpq pkey nkey piv niv paad naad pin nin ptag ntag)

ecGen :: Ptr OsslLibCtx -> String -> String -> IO (Either Int (ByteString, ByteString))
ecGen ctx group propq =
  withCString group $ \cg ->
    withCString propq $ \cpq ->
      alloca $ \ppriv -> alloca $ \npriv -> alloca $ \ppub -> alloca $ \npub -> do
        rc <- c_ec_gen ctx cg cpq ppriv npriv ppub npub
        if rc /= 0
          then pure (Left (fromIntegral rc))
          else do
            privp <- peek ppriv
            privn <- peek npriv
            pubp <- peek ppub
            pubn <- peek npub
            if privp == nullPtr || pubp == nullPtr
              then pure (Left errNative)
              else do
                priv <- takeOwned privp (fromIntegral privn)
                pub <- takeOwned pubp (fromIntegral pubn)
                pure (Right (priv, pub))

randBytes :: Ptr OsslLibCtx -> Int -> IO (Either Int ByteString)
randBytes ctx n =
  withOut (c_rand_bytes ctx (fromIntegral n))

rsaGen :: Ptr OsslLibCtx -> Int -> ByteString -> String -> IO (Either Int (ByteString, ByteString))
rsaGen ctx bits eBe propq =
  withBytes eBe $ \(pe, ne) ->
    withCString propq $ \cpq ->
      alloca $ \ppriv -> alloca $ \npriv -> alloca $ \ppub -> alloca $ \npub -> do
        rc <- c_rsa_gen ctx (fromIntegral bits) pe ne cpq ppriv npriv ppub npub
        if rc /= 0
          then pure (Left (fromIntegral rc))
          else do
            privp <- peek ppriv
            privn <- peek npriv
            pubp <- peek ppub
            pubn <- peek npub
            if privp == nullPtr || pubp == nullPtr
              then pure (Left errNative)
              else do
                priv <- takeOwned privp (fromIntegral privn)
                pub <- takeOwned pubp (fromIntegral pubn)
                pure (Right (priv, pub))

-- | Mix seed bytes via the shim's @RAND_add@ entry: 0 is
-- success, a negative shim code is the @Left@ (mirrors 'withOut').
randSeed :: Ptr OsslLibCtx -> ByteString -> IO (Either Int ())
randSeed ctx seed =
  withBytes seed $ \(pseed, nseed) -> do
    rc <- c_rand_seed ctx pseed nseed
    if rc == 0
      then pure (Right ())
      else pure (Left (fromIntegral rc))

ecdsaSign :: Ptr OsslLibCtx -> String -> String -> ByteString -> ByteString -> Bool -> Bool -> IO (Either Int ByteString)
ecdsaSign ctx mdname propq privDer msg wantRaw noHash =
  withCString mdname $ \cmd ->
    withCString propq $ \cpq ->
      withBytes privDer $ \(ppriv, npriv) ->
        withBytes msg $ \(pmsg, nmsg) ->
          withOut (c_ecdsa_sign ctx cmd cpq ppriv npriv pmsg nmsg (if wantRaw then 1 else 0) (if noHash then 1 else 0))

ecdsaVerify :: Ptr OsslLibCtx -> String -> String -> ByteString -> ByteString -> ByteString -> Bool -> Bool -> IO Int
ecdsaVerify ctx mdname propq pubDer msg sig isRaw noHash =
  withCString mdname $ \cmd ->
    withCString propq $ \cpq ->
      withBytes pubDer $ \(ppub, npub) ->
        withBytes msg $ \(pmsg, nmsg) ->
          withBytes sig $ \(psig, nsig) ->
            fromIntegral <$> c_ecdsa_verify ctx cmd cpq ppub npub pmsg nmsg psig nsig (if isRaw then 1 else 0) (if noHash then 1 else 0)

dsaSign :: Ptr OsslLibCtx -> String -> String -> ByteString -> ByteString -> Bool -> Bool -> IO (Either Int ByteString)
dsaSign ctx mdname propq privDer msg wantRaw noHash =
  withCString mdname $ \cmd ->
    withCString propq $ \cpq ->
      withBytes privDer $ \(ppriv, npriv) ->
        withBytes msg $ \(pmsg, nmsg) ->
          withOut (c_dsa_sign ctx cmd cpq ppriv npriv pmsg nmsg (if wantRaw then 1 else 0) (if noHash then 1 else 0))

dsaVerify :: Ptr OsslLibCtx -> String -> String -> ByteString -> ByteString -> ByteString -> Bool -> Bool -> IO Int
dsaVerify ctx mdname propq pubDer msg sig isRaw noHash =
  withCString mdname $ \cmd ->
    withCString propq $ \cpq ->
      withBytes pubDer $ \(ppub, npub) ->
        withBytes msg $ \(pmsg, nmsg) ->
          withBytes sig $ \(psig, nsig) ->
            fromIntegral <$> c_dsa_verify ctx cmd cpq ppub npub pmsg nmsg psig nsig (if isRaw then 1 else 0) (if noHash then 1 else 0)

-- | DSA domain parameters: DER DSS-Parms for an approved (L, N) pair.
dsaGenParams :: Ptr OsslLibCtx -> String -> Int -> Int -> IO (Either Int ByteString)
dsaGenParams ctx propq pbits qbits =
  withCString propq $ \cpq ->
    withOut (c_dsa_gen_params ctx cpq (fromIntegral pbits) (fromIntegral qbits))

-- | DSA keypair from DER domain parameters: PKCS#8 + SPKI halves.
dsaGenKeypair :: Ptr OsslLibCtx -> String -> ByteString -> IO (Either Int (ByteString, ByteString))
dsaGenKeypair ctx propq paramsDer =
  withCString propq $ \cpq ->
    withBytes paramsDer $ \(pparams, nparams) ->
      alloca $ \ppriv -> alloca $ \npriv -> alloca $ \ppub -> alloca $ \npub -> do
        rc <- c_dsa_gen_keypair ctx cpq pparams nparams ppriv npriv ppub npub
        if rc /= 0
          then pure (Left (fromIntegral rc))
          else do
            privp <- peek ppriv
            privn <- peek npriv
            pubp <- peek ppub
            pubn <- peek npub
            if privp == nullPtr || pubp == nullPtr
              then pure (Left errNative)
              else do
                priv <- takeOwned privp (fromIntegral privn)
                pub <- takeOwned pubp (fromIntegral pubn)
                pure (Right (priv, pub))

-- | Pure EdDSA sign: the raw signature for (curve name, PKCS#8,
-- message); empty messages serve.
eddsaSign :: Ptr OsslLibCtx -> String -> String -> ByteString -> ByteString -> IO (Either Int ByteString)
eddsaSign ctx curvename propq privDer msg =
  withCString curvename $ \ccurve ->
    withCString propq $ \cpq ->
      withBytes privDer $ \(ppriv, npriv) ->
        withBytes msg $ \(pmsg, nmsg) ->
          withOut (c_eddsa_sign ctx ccurve cpq ppriv npriv pmsg nmsg)

-- | Pure EdDSA verify: 1 valid, 0 mismatch, negative shim code.
eddsaVerify :: Ptr OsslLibCtx -> String -> String -> ByteString -> ByteString -> ByteString -> IO Int
eddsaVerify ctx curvename propq pubDer msg sig =
  withCString curvename $ \ccurve ->
    withCString propq $ \cpq ->
      withBytes pubDer $ \(ppub, npub) ->
        withBytes msg $ \(pmsg, nmsg) ->
          withBytes sig $ \(psig, nsig) ->
            fromIntegral <$> c_eddsa_verify ctx ccurve cpq ppub npub pmsg nmsg psig nsig

-- | Edwards keypair for a curve name: PKCS#8 + SPKI halves.
edwardsGen :: Ptr OsslLibCtx -> String -> String -> IO (Either Int (ByteString, ByteString))
edwardsGen ctx propq curvename =
  withCString propq $ \cpq ->
    withCString curvename $ \ccurve ->
      alloca $ \ppriv -> alloca $ \npriv -> alloca $ \ppub -> alloca $ \npub -> do
        rc <- c_edwards_gen ctx cpq ccurve ppriv npriv ppub npub
        if rc /= 0
          then pure (Left (fromIntegral rc))
          else do
            privp <- peek ppriv
            privn <- peek npriv
            pubp <- peek ppub
            pubn <- peek npub
            if privp == nullPtr || pubp == nullPtr
              then pure (Left errNative)
              else do
                priv <- takeOwned privp (fromIntegral privn)
                pub <- takeOwned pubp (fromIntegral pubn)
                pure (Right (priv, pub))

-- | Montgomery keypair for a curve name: PKCS#8 + SPKI halves.
montgomeryGen :: Ptr OsslLibCtx -> String -> String -> IO (Either Int (ByteString, ByteString))
montgomeryGen ctx propq curvename =
  withCString propq $ \cpq ->
    withCString curvename $ \ccurve ->
      alloca $ \ppriv -> alloca $ \npriv -> alloca $ \ppub -> alloca $ \npub -> do
        rc <- c_montgomery_gen ctx cpq ccurve ppriv npriv ppub npub
        if rc /= 0
          then pure (Left (fromIntegral rc))
          else do
            privp <- peek ppriv
            privn <- peek npriv
            pubp <- peek ppub
            pubn <- peek npub
            if privp == nullPtr || pubp == nullPtr
              then pure (Left errNative)
              else do
                priv <- takeOwned privp (fromIntegral privn)
                pub <- takeOwned pubp (fromIntegral pubn)
                pure (Right (priv, pub))

-- | ML-DSA sign: the raw signature for (level name, PKCS#8,
-- message, optional context, deterministic flag); @Nothing@
-- context is pure mode. @True@ selects FIPS 204 deterministic
-- signing (@CKH_DETERMINISTIC_REQUIRED@); @False@ is the
-- provider default (proven hedged). Empty messages serve.
mldsaSign :: Ptr OsslLibCtx -> String -> String -> ByteString -> ByteString -> Maybe ByteString -> Bool -> IO (Either Int ByteString)
mldsaSign ctx algname propq privDer msg mctx deterministic =
  withCString algname $ \calg ->
    withCString propq $ \cpq ->
      withBytes privDer $ \(ppriv, npriv) ->
        withBytes msg $ \(pmsg, nmsg) ->
          withOptBytes mctx $ \(pctx, nctx) ->
            withOut (c_mldsa_sign ctx calg cpq ppriv npriv pmsg nmsg pctx nctx (if deterministic then 1 else 0))

-- | ML-DSA verify: 1 valid, 0 mismatch, negative shim code.
-- The context must match the signing call ('Nothing' = pure).
mldsaVerify :: Ptr OsslLibCtx -> String -> String -> ByteString -> ByteString -> Maybe ByteString -> ByteString -> IO Int
mldsaVerify ctx algname propq pubDer msg mctx sig =
  withCString algname $ \calg ->
    withCString propq $ \cpq ->
      withBytes pubDer $ \(ppub, npub) ->
        withBytes msg $ \(pmsg, nmsg) ->
          withOptBytes mctx $ \(pctx, nctx) ->
            withBytes sig $ \(psig, nsig) ->
              fromIntegral <$> c_mldsa_verify ctx calg cpq ppub npub pmsg nmsg pctx nctx psig nsig

-- | ML-DSA keypair for a level name: PKCS#8 + SPKI halves.
mldsaGen :: Ptr OsslLibCtx -> String -> String -> IO (Either Int (ByteString, ByteString))
mldsaGen ctx propq algname =
  withCString propq $ \cpq ->
    withCString algname $ \calg ->
      alloca $ \ppriv -> alloca $ \npriv -> alloca $ \ppub -> alloca $ \npub -> do
        rc <- c_mldsa_gen ctx cpq calg ppriv npriv ppub npub
        if rc /= 0
          then pure (Left (fromIntegral rc))
          else do
            privp <- peek ppriv
            privn <- peek npriv
            pubp <- peek ppub
            pubn <- peek npub
            if privp == nullPtr || pubp == nullPtr
              then pure (Left errNative)
              else do
                priv <- takeOwned privp (fromIntegral privn)
                pub <- takeOwned pubp (fromIntegral pubn)
                pure (Right (priv, pub))

-- | SLH-DSA sign: the raw signature for (set name, PKCS#8,
-- message, optional context, deterministic flag); @Nothing@
-- context is pure mode. @True@ selects FIPS 205 deterministic
-- signing (@CKH_DETERMINISTIC_REQUIRED@); @False@ is the
-- provider default (proven hedged). Empty messages serve.
slhdsaSign :: Ptr OsslLibCtx -> String -> String -> ByteString -> ByteString -> Maybe ByteString -> Bool -> IO (Either Int ByteString)
slhdsaSign ctx algname propq privDer msg mctx deterministic =
  withCString algname $ \calg ->
    withCString propq $ \cpq ->
      withBytes privDer $ \(ppriv, npriv) ->
        withBytes msg $ \(pmsg, nmsg) ->
          withOptBytes mctx $ \(pctx, nctx) ->
            withOut (c_slhdsa_sign ctx calg cpq ppriv npriv pmsg nmsg pctx nctx (if deterministic then 1 else 0))

-- | SLH-DSA verify: 1 valid, 0 mismatch, negative shim code.
-- The context must match the signing call ('Nothing' = pure).
slhdsaVerify :: Ptr OsslLibCtx -> String -> String -> ByteString -> ByteString -> Maybe ByteString -> ByteString -> IO Int
slhdsaVerify ctx algname propq pubDer msg mctx sig =
  withCString algname $ \calg ->
    withCString propq $ \cpq ->
      withBytes pubDer $ \(ppub, npub) ->
        withBytes msg $ \(pmsg, nmsg) ->
          withOptBytes mctx $ \(pctx, nctx) ->
            withBytes sig $ \(psig, nsig) ->
              fromIntegral <$> c_slhdsa_verify ctx calg cpq ppub npub pmsg nmsg pctx nctx psig nsig

-- | SLH-DSA keypair for a set name: PKCS#8 + SPKI halves.
slhdsaGen :: Ptr OsslLibCtx -> String -> String -> IO (Either Int (ByteString, ByteString))
slhdsaGen ctx propq algname =
  withCString propq $ \cpq ->
    withCString algname $ \calg ->
      alloca $ \ppriv -> alloca $ \npriv -> alloca $ \ppub -> alloca $ \npub -> do
        rc <- c_slhdsa_gen ctx cpq calg ppriv npriv ppub npub
        if rc /= 0
          then pure (Left (fromIntegral rc))
          else do
            privp <- peek ppriv
            privn <- peek npriv
            pubp <- peek ppub
            pubn <- peek npub
            if privp == nullPtr || pubp == nullPtr
              then pure (Left errNative)
              else do
                priv <- takeOwned privp (fromIntegral privn)
                pub <- takeOwned pubp (fromIntegral pubn)
                pure (Right (priv, pub))

-- | ML-KEM encapsulate: ct||ss for (set name, SPKI DER or raw
-- ek); the shim splits nothing — the caller frames by the
-- set's ciphertext width (768/1088/1568, secret always 32).
mlkemEncaps :: Ptr OsslLibCtx -> String -> String -> ByteString -> IO (Either Int ByteString)
mlkemEncaps ctx algname propq pub =
  withCString algname $ \calg ->
    withCString propq $ \cpq ->
      withBytes pub $ \(ppub, npub) ->
        withOut (c_mlkem_encaps ctx calg cpq ppub npub)

-- | ML-KEM decapsulate: the 32-byte shared secret for (set
-- name, provider-form PKCS#8 DER or raw dk, exact-width
-- ciphertext). Off-width ciphertexts refuse at the shim.
mlkemDecaps :: Ptr OsslLibCtx -> String -> String -> ByteString -> ByteString -> IO (Either Int ByteString)
mlkemDecaps ctx algname propq priv ct =
  withCString algname $ \calg ->
    withCString propq $ \cpq ->
      withBytes priv $ \(ppriv, npriv) ->
        withBytes ct $ \(pct, nct) ->
          withOut (c_mlkem_decaps ctx calg cpq ppriv npriv pct nct)

-- | ML-KEM keypair for a set name: provider-form PKCS#8 +
-- SPKI halves.
mlkemGen :: Ptr OsslLibCtx -> String -> String -> IO (Either Int (ByteString, ByteString))
mlkemGen ctx propq algname =
  withCString propq $ \cpq ->
    withCString algname $ \calg ->
      alloca $ \ppriv -> alloca $ \npriv -> alloca $ \ppub -> alloca $ \npub -> do
        rc <- c_mlkem_gen ctx cpq calg ppriv npriv ppub npub
        if rc /= 0
          then pure (Left (fromIntegral rc))
          else do
            privp <- peek ppriv
            privn <- peek npriv
            pubp <- peek ppub
            pubn <- peek npub
            if privp == nullPtr || pubp == nullPtr
              then pure (Left errNative)
              else do
                priv <- takeOwned privp (fromIntegral privn)
                pub <- takeOwned pubp (fromIntegral pubn)
                pure (Right (priv, pub))

-- | ECDH agreement: the raw secret for (PKCS#8 base, SPKI peer);
-- @cofactor@ selects cofactor multiplication.
ecdhDerive :: Ptr OsslLibCtx -> String -> ByteString -> ByteString -> Bool -> IO (Either Int ByteString)
ecdhDerive ctx propq privDer peerDer cofactor =
  withCString propq $ \cpq ->
    withBytes privDer $ \(ppriv, npriv) ->
      withBytes peerDer $ \(ppeer, npeer) ->
        withOut (c_ecdh_derive ctx cpq ppriv npriv ppeer npeer (if cofactor then 1 else 0))

-- | XDH agreement (X25519/X448): the raw secret for (PKCS#8
-- Montgomery base, bare peer u-coordinate). The shim gates the
-- peer width on the base type and attributes low-order peers as
-- 'errBadPeer'.
xdhDerive :: Ptr OsslLibCtx -> String -> ByteString -> ByteString -> IO (Either Int ByteString)
xdhDerive ctx propq privDer peerRaw =
  withCString propq $ \cpq ->
    withBytes privDer $ \(ppriv, npriv) ->
      withBytes peerRaw $ \(ppeer, npeer) ->
        withOut (c_xdh_derive ctx cpq ppriv npriv ppeer npeer)

-- | Finite-field DH agreement: the raw secret for (PKCS#8 base,
-- bare peer public value). The shim range-checks the peer
-- natively (@1 < y < p - 1@).
dhDerive :: Ptr OsslLibCtx -> String -> ByteString -> ByteString -> IO (Either Int ByteString)
dhDerive ctx propq privDer peerVal =
  withCString propq $ \cpq ->
    withBytes privDer $ \(ppriv, npriv) ->
      withBytes peerVal $ \(ppeer, npeer) ->
        withOut (c_dh_derive ctx cpq ppriv npriv ppeer npeer)

-- | DH keypair from DER domain parameters (PKCS#3 or X9.42):
-- PKCS#8 + SPKI halves.
dhGenKeypair :: Ptr OsslLibCtx -> String -> ByteString -> IO (Either Int (ByteString, ByteString))
dhGenKeypair ctx propq paramsDer =
  withCString propq $ \cpq ->
    withBytes paramsDer $ \(pparams, nparams) ->
      alloca $ \ppriv -> alloca $ \npriv -> alloca $ \ppub -> alloca $ \npub -> do
        rc <- c_dh_gen_keypair ctx cpq pparams nparams ppriv npriv ppub npub
        if rc /= 0
          then pure (Left (fromIntegral rc))
          else do
            privp <- peek ppriv
            privn <- peek npriv
            pubp <- peek ppub
            pubn <- peek npub
            if privp == nullPtr || pubp == nullPtr
              then pure (Left errNative)
              else do
                priv <- takeOwned privp (fromIntegral privn)
                pub <- takeOwned pubp (fromIntegral pubn)
                pure (Right (priv, pub))

-- | RSA PKCS#1 v1.5 sign: digested hash-and-sign under @mdname@, or
-- the raw block-type-1 operation when @isRaw@ (mdname ignored).
rsaSign :: Ptr OsslLibCtx -> String -> String -> ByteString -> ByteString -> Bool -> IO (Either Int ByteString)
rsaSign ctx mdname propq privDer msg isRaw =
  withCString mdname $ \cmd ->
    withCString propq $ \cpq ->
      withBytes privDer $ \(ppriv, npriv) ->
        withBytes msg $ \(pmsg, nmsg) ->
          withOut (c_rsa_sign ctx cmd cpq ppriv npriv pmsg nmsg (if isRaw then 1 else 0))

rsaVerify :: Ptr OsslLibCtx -> String -> String -> ByteString -> ByteString -> ByteString -> Bool -> IO Int
rsaVerify ctx mdname propq pubDer msg sig isRaw =
  withCString mdname $ \cmd ->
    withCString propq $ \cpq ->
      withBytes pubDer $ \(ppub, npub) ->
        withBytes msg $ \(pmsg, nmsg) ->
          withBytes sig $ \(psig, nsig) ->
            fromIntegral <$> c_rsa_verify ctx cmd cpq ppub npub pmsg nmsg psig nsig (if isRaw then 1 else 0)

-- | RSA-PSS sign/verify with explicit MGF1 digest and salt length.
rsaPssSign :: Ptr OsslLibCtx -> String -> String -> Int -> String -> ByteString -> ByteString -> IO (Either Int ByteString)
rsaPssSign ctx mdname mgfname saltlen propq privDer msg =
  withCString mdname $ \cmd ->
    withCString mgfname $ \cmgf ->
      withCString propq $ \cpq ->
        withBytes privDer $ \(ppriv, npriv) ->
          withBytes msg $ \(pmsg, nmsg) ->
            withOut (c_rsa_pss_sign ctx cmd cmgf (fromIntegral saltlen) cpq ppriv npriv pmsg nmsg)

rsaPssVerify :: Ptr OsslLibCtx -> String -> String -> Int -> String -> ByteString -> ByteString -> ByteString -> IO Int
rsaPssVerify ctx mdname mgfname saltlen propq pubDer msg sig =
  withCString mdname $ \cmd ->
    withCString mgfname $ \cmgf ->
      withCString propq $ \cpq ->
        withBytes pubDer $ \(ppub, npub) ->
          withBytes msg $ \(pmsg, nmsg) ->
            withBytes sig $ \(psig, nsig) ->
              fromIntegral <$> c_rsa_pss_verify ctx cmd cmgf (fromIntegral saltlen) cpq ppub npub pmsg nmsg psig nsig

-- | RSA-OAEP encrypt/decrypt with explicit hash, MGF1 digest, and
-- label (empty label selects the default).
rsaOaepEncrypt :: Ptr OsslLibCtx -> String -> String -> ByteString -> String -> ByteString -> ByteString -> IO (Either Int ByteString)
rsaOaepEncrypt ctx mdname mgfname label propq pubDer input =
  withCString mdname $ \cmd ->
    withCString mgfname $ \cmgf ->
      withCString propq $ \cpq ->
        withBytes label $ \(plabel, nlabel) ->
          withBytes pubDer $ \(ppub, npub) ->
            withBytes input $ \(pin, nin) ->
              withOut (c_rsa_oaep_encrypt ctx cmd cmgf plabel nlabel cpq ppub npub pin nin)

rsaOaepDecrypt :: Ptr OsslLibCtx -> String -> String -> ByteString -> String -> ByteString -> ByteString -> IO (Either Int ByteString)
rsaOaepDecrypt ctx mdname mgfname label propq privDer input =
  withCString mdname $ \cmd ->
    withCString mgfname $ \cmgf ->
      withCString propq $ \cpq ->
        withBytes label $ \(plabel, nlabel) ->
          withBytes privDer $ \(ppriv, npriv) ->
            withBytes input $ \(pin, nin) ->
              withOut (c_rsa_oaep_decrypt ctx cmd cmgf plabel nlabel cpq ppriv npriv pin nin)

rsaPkcs1Encrypt :: Ptr OsslLibCtx -> String -> ByteString -> ByteString -> IO (Either Int ByteString)
rsaPkcs1Encrypt ctx propq pubDer input =
  withCString propq $ \cpq ->
    withBytes pubDer $ \(ppub, npub) ->
      withBytes input $ \(pin, nin) ->
        withOut (c_rsa_pkcs1_encrypt ctx cpq ppub npub pin nin)

rsaPkcs1Decrypt :: Ptr OsslLibCtx -> String -> ByteString -> ByteString -> IO (Either Int ByteString)
rsaPkcs1Decrypt ctx propq privDer input =
  withCString propq $ \cpq ->
    withBytes privDer $ \(ppriv, npriv) ->
      withBytes input $ \(pin, nin) ->
        withOut (c_rsa_pkcs1_decrypt ctx cpq ppriv npriv pin nin)

rsaX509Encrypt :: Ptr OsslLibCtx -> String -> ByteString -> ByteString -> IO (Either Int ByteString)
rsaX509Encrypt ctx propq pubDer input =
  withCString propq $ \cpq ->
    withBytes pubDer $ \(ppub, npub) ->
      withBytes input $ \(pin, nin) ->
        withOut (c_rsa_x509_encrypt ctx cpq ppub npub pin nin)

rsaX509Decrypt :: Ptr OsslLibCtx -> String -> ByteString -> ByteString -> IO (Either Int ByteString)
rsaX509Decrypt ctx propq privDer input =
  withCString propq $ \cpq ->
    withBytes privDer $ \(ppriv, npriv) ->
      withBytes input $ \(pin, nin) ->
        withOut (c_rsa_x509_decrypt ctx cpq ppriv npriv pin nin)

rsaX509Sign :: Ptr OsslLibCtx -> String -> ByteString -> ByteString -> IO (Either Int ByteString)
rsaX509Sign ctx propq privDer input =
  withCString propq $ \cpq ->
    withBytes privDer $ \(ppriv, npriv) ->
      withBytes input $ \(pin, nin) ->
        withOut (c_rsa_x509_sign ctx cpq ppriv npriv pin nin)

rsaX509Verify :: Ptr OsslLibCtx -> String -> ByteString -> ByteString -> ByteString -> IO Int
rsaX509Verify ctx propq pubDer msg sig =
  withCString propq $ \cpq ->
    withBytes pubDer $ \(ppub, npub) ->
      withBytes msg $ \(pmsg, nmsg) ->
        withBytes sig $ \(psig, nsig) ->
          fromIntegral <$> c_rsa_x509_verify ctx cpq ppub npub pmsg nmsg psig nsig
