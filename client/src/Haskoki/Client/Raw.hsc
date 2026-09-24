{-# LANGUAGE CApiFFI #-}
{-# LANGUAGE ForeignFunctionInterface #-}

-- | Raw PKCS#11 client bindings: @dlopen@ a module, fetch its function
-- list, and call through it. Every offset and constant comes from the
-- single verbatim @spec/vendor/pkcs11.h@ via hsc2hs; nothing is
-- hand-copied. Test-only: this module exists to prove the C ABI is
-- drivable by a genuine foreign client.
module Haskoki.Client.Raw
  ( -- * Handles and codes
    CK_RV
  , ckrOk
  , rvName
    -- * Constants from the header
  , ckaClass, ckaKeyType, ckaToken, ckaPrivate, ckaLabel
  , ckaEncrypt, ckaDecrypt, ckaSign, ckaVerify, ckaDerive
  , ckaExtractable, ckaValue, ckaValueLen, ckaEcParams
  , ckoSecretKey, ckoPublicKey, ckoPrivateKey
  , ckkAes, ckkGenericSecret, ckkEc
  , ckmSha256, ckmAesKeyGen, ckmAesCbcPad, ckmGenericSecretKeyGen
  , ckmSha256Hmac, ckmEcKeyPairGen, ckmEcdsa, ckmSha256KeyDerivation
  , ckuUser, ckfSerialSession, ckfRwSession, ckTrue, ckFalse
    -- * Structs
  , CKMechanism (..)
  , CKAttribute (..)
  , CKInfo (..)
  , CKSlotInfo (..)
  , CKTokenInfo (..)
  , CKMechanismInfo (..)
  , CKSessionInfo (..)
  , peekInfo, peekSlotInfo, peekTokenInfo, peekMechInfo, peekSessionInfo
  , infoSize, slotInfoSize, tokenInfoSize, mechInfoSize, sessionInfoSize
    -- * Function list
  , Functions (..)
  , loadFunctions
  , functionListVersion
    -- * Module loading
  , withModule
  ) where

#include "pkcs11.h"

import Control.Exception (bracket)
import Data.Word (Word8, Word64)
import Foreign.C.String (peekCStringLen)
import Foreign.Marshal.Alloc (alloca)
import Foreign.Ptr (FunPtr, Ptr, castFunPtr, castPtr, nullPtr, plusPtr)
import Foreign.Storable (Storable (..))
import System.Posix.DynamicLinker (RTLDFlags (..), dlclose, dlopen, dlsym)

-- ---------------------------------------------------------------------------
-- Codes
-- ---------------------------------------------------------------------------

type CK_RV = Word64

ckrOk :: CK_RV
ckrOk = #{const CKR_OK}

-- | Short names for the codes a client smoke test meets. Anything else
-- renders as hex; the mapping is diagnostic only.
rvName :: CK_RV -> String
rvName rv = case rv of
  #{const CKR_OK} -> "CKR_OK"
  #{const CKR_ARGUMENTS_BAD} -> "CKR_ARGUMENTS_BAD"
  #{const CKR_ATTRIBUTE_READ_ONLY} -> "CKR_ATTRIBUTE_READ_ONLY"
  #{const CKR_ATTRIBUTE_SENSITIVE} -> "CKR_ATTRIBUTE_SENSITIVE"
  #{const CKR_ATTRIBUTE_TYPE_INVALID} -> "CKR_ATTRIBUTE_TYPE_INVALID"
  #{const CKR_ATTRIBUTE_VALUE_INVALID} -> "CKR_ATTRIBUTE_VALUE_INVALID"
  #{const CKR_BUFFER_TOO_SMALL} -> "CKR_BUFFER_TOO_SMALL"
  #{const CKR_CRYPTOKI_ALREADY_INITIALIZED} -> "CKR_CRYPTOKI_ALREADY_INITIALIZED"
  #{const CKR_CRYPTOKI_NOT_INITIALIZED} -> "CKR_CRYPTOKI_NOT_INITIALIZED"
  #{const CKR_DATA_LEN_RANGE} -> "CKR_DATA_LEN_RANGE"
  #{const CKR_DEVICE_ERROR} -> "CKR_DEVICE_ERROR"
  #{const CKR_ENCRYPTED_DATA_LEN_RANGE} -> "CKR_ENCRYPTED_DATA_LEN_RANGE"
  #{const CKR_FUNCTION_NOT_SUPPORTED} -> "CKR_FUNCTION_NOT_SUPPORTED"
  #{const CKR_GENERAL_ERROR} -> "CKR_GENERAL_ERROR"
  #{const CKR_KEY_HANDLE_INVALID} -> "CKR_KEY_HANDLE_INVALID"
  #{const CKR_KEY_SIZE_RANGE} -> "CKR_KEY_SIZE_RANGE"
  #{const CKR_KEY_TYPE_INCONSISTENT} -> "CKR_KEY_TYPE_INCONSISTENT"
  #{const CKR_KEY_FUNCTION_NOT_PERMITTED} -> "CKR_KEY_FUNCTION_NOT_PERMITTED"
  #{const CKR_KEY_NOT_WRAPPABLE} -> "CKR_KEY_NOT_WRAPPABLE"
  #{const CKR_KEY_UNEXTRACTABLE} -> "CKR_KEY_UNEXTRACTABLE"
  #{const CKR_MECHANISM_INVALID} -> "CKR_MECHANISM_INVALID"
  #{const CKR_MECHANISM_PARAM_INVALID} -> "CKR_MECHANISM_PARAM_INVALID"
  #{const CKR_OBJECT_HANDLE_INVALID} -> "CKR_OBJECT_HANDLE_INVALID"
  #{const CKR_OPERATION_ACTIVE} -> "CKR_OPERATION_ACTIVE"
  #{const CKR_OPERATION_NOT_INITIALIZED} -> "CKR_OPERATION_NOT_INITIALIZED"
  #{const CKR_PIN_INCORRECT} -> "CKR_PIN_INCORRECT"
  #{const CKR_SESSION_CLOSED} -> "CKR_SESSION_CLOSED"
  #{const CKR_SESSION_HANDLE_INVALID} -> "CKR_SESSION_HANDLE_INVALID"
  #{const CKR_SIGNATURE_INVALID} -> "CKR_SIGNATURE_INVALID"
  #{const CKR_SLOT_ID_INVALID} -> "CKR_SLOT_ID_INVALID"
  #{const CKR_TEMPLATE_INCOMPLETE} -> "CKR_TEMPLATE_INCOMPLETE"
  #{const CKR_TEMPLATE_INCONSISTENT} -> "CKR_TEMPLATE_INCONSISTENT"
  #{const CKR_TOKEN_NOT_PRESENT} -> "CKR_TOKEN_NOT_PRESENT"
  #{const CKR_USER_NOT_LOGGED_IN} -> "CKR_USER_NOT_LOGGED_IN"
  _ -> "CKR_<0x" ++ showHex rv ++ ">"
  where
    showHex 0 = "0"
    showHex n = reverse (go n)
    go 0 = []
    go x = "0123456789abcdef" !! fromIntegral (x `mod` 16) : go (x `div` 16)

-- ---------------------------------------------------------------------------
-- Header constants
-- ---------------------------------------------------------------------------

ckaClass, ckaKeyType, ckaToken, ckaPrivate, ckaLabel :: Word64
ckaClass = #{const CKA_CLASS}
ckaKeyType = #{const CKA_KEY_TYPE}
ckaToken = #{const CKA_TOKEN}
ckaPrivate = #{const CKA_PRIVATE}
ckaLabel = #{const CKA_LABEL}

ckaEncrypt, ckaDecrypt, ckaSign, ckaVerify, ckaDerive :: Word64
ckaEncrypt = #{const CKA_ENCRYPT}
ckaDecrypt = #{const CKA_DECRYPT}
ckaSign = #{const CKA_SIGN}
ckaVerify = #{const CKA_VERIFY}
ckaDerive = #{const CKA_DERIVE}

ckaExtractable, ckaValue, ckaValueLen, ckaEcParams :: Word64
ckaExtractable = #{const CKA_EXTRACTABLE}
ckaValue = #{const CKA_VALUE}
ckaValueLen = #{const CKA_VALUE_LEN}
ckaEcParams = #{const CKA_EC_PARAMS}

ckoSecretKey, ckoPublicKey, ckoPrivateKey :: Word64
ckoSecretKey = #{const CKO_SECRET_KEY}
ckoPublicKey = #{const CKO_PUBLIC_KEY}
ckoPrivateKey = #{const CKO_PRIVATE_KEY}

ckkAes, ckkGenericSecret, ckkEc :: Word64
ckkAes = #{const CKK_AES}
ckkGenericSecret = #{const CKK_GENERIC_SECRET}
ckkEc = #{const CKK_EC}

ckmSha256, ckmAesKeyGen, ckmAesCbcPad, ckmGenericSecretKeyGen :: Word64
ckmSha256 = #{const CKM_SHA256}
ckmAesKeyGen = #{const CKM_AES_KEY_GEN}
ckmAesCbcPad = #{const CKM_AES_CBC_PAD}
ckmGenericSecretKeyGen = #{const CKM_GENERIC_SECRET_KEY_GEN}

ckmSha256Hmac, ckmEcKeyPairGen, ckmEcdsa, ckmSha256KeyDerivation :: Word64
ckmSha256Hmac = #{const CKM_SHA256_HMAC}
ckmEcKeyPairGen = #{const CKM_EC_KEY_PAIR_GEN}
ckmEcdsa = #{const CKM_ECDSA}
ckmSha256KeyDerivation = #{const CKM_SHA256_KEY_DERIVATION}

ckuUser, ckfSerialSession, ckfRwSession :: Word64
ckuUser = #{const CKU_USER}
ckfSerialSession = #{const CKF_SERIAL_SESSION}
ckfRwSession = #{const CKF_RW_SESSION}

ckTrue, ckFalse :: Word8
ckTrue = #{const CK_TRUE}
ckFalse = #{const CK_FALSE}

-- ---------------------------------------------------------------------------
-- Structs
-- ---------------------------------------------------------------------------

data CKMechanism = CKMechanism
  { cmType :: !Word64
  , cmParam :: !(Ptr ())
  , cmParamLen :: !Word64
  } deriving (Show)

instance Storable CKMechanism where
  sizeOf _ = #{size CK_MECHANISM}
  alignment _ = alignment (0 :: Word64)
  peek p = CKMechanism
    <$> #{peek CK_MECHANISM, mechanism} p
    <*> #{peek CK_MECHANISM, pParameter} p
    <*> #{peek CK_MECHANISM, ulParameterLen} p
  poke p m = do
    #{poke CK_MECHANISM, mechanism} p (cmType m)
    #{poke CK_MECHANISM, pParameter} p (cmParam m)
    #{poke CK_MECHANISM, ulParameterLen} p (cmParamLen m)

data CKAttribute = CKAttribute
  { caType :: !Word64
  , caValue :: !(Ptr ())
  , caLen :: !Word64
  } deriving (Show)

instance Storable CKAttribute where
  sizeOf _ = #{size CK_ATTRIBUTE}
  alignment _ = alignment (0 :: Word64)
  peek p = CKAttribute
    <$> #{peek CK_ATTRIBUTE, type} p
    <*> #{peek CK_ATTRIBUTE, pValue} p
    <*> #{peek CK_ATTRIBUTE, ulValueLen} p
  poke p a = do
    #{poke CK_ATTRIBUTE, type} p (caType a)
    #{poke CK_ATTRIBUTE, pValue} p (caValue a)
    #{poke CK_ATTRIBUTE, ulValueLen} p (caLen a)

data CKInfo = CKInfo
  { ciCryptoki :: !(Word8, Word8)
  , ciManufacturer :: !String
  , ciFlags :: !Word64
  , ciLibrary :: !String
  , ciVersion :: !(Word8, Word8)
  } deriving (Show)

data CKSlotInfo = CKSlotInfo
  { csiDescription :: !String
  , csiManufacturer :: !String
  , csiFlags :: !Word64
  } deriving (Show)

data CKTokenInfo = CKTokenInfo
  { ctiLabel :: !String
  , ctiManufacturer :: !String
  , ctiModel :: !String
  , ctiSerial :: !String
  , ctiFlags :: !Word64
  , ctiMaxSession :: !Word64
  , ctiSessionCount :: !Word64
  } deriving (Show)

data CKMechanismInfo = CKMechanismInfo
  { cmiMinKey :: !Word64
  , cmiMaxKey :: !Word64
  , cmiFlags :: !Word64
  } deriving (Show)

data CKSessionInfo = CKSessionInfo
  { csiSlot :: !Word64
  , csiState :: !Word64
  , csiSessionFlags :: !Word64
  , csiDeviceError :: !Word64
  } deriving (Show)

trimPad :: String -> String
trimPad = reverse . dropWhile (`elem` (" \0" :: String)) . reverse

peekFixed :: Ptr a -> Int -> Int -> IO String
peekFixed base off len =
  trimPad <$> peekCStringLen (castPtr (base `plusPtr` off), len)

peekVersion :: Ptr a -> Int -> IO (Word8, Word8)
peekVersion base off = do
  maj <- peekByteOff base off
  mnr <- peekByteOff base (off + 1)
  pure (maj, mnr)

peekInfo :: Ptr () -> IO CKInfo
peekInfo p = CKInfo
  <$> peekVersion p #{offset CK_INFO, cryptokiVersion}
  <*> peekFixed p #{offset CK_INFO, manufacturerID} 32
  <*> #{peek CK_INFO, flags} p
  <*> peekFixed p #{offset CK_INFO, libraryDescription} 32
  <*> peekVersion p #{offset CK_INFO, libraryVersion}

peekSlotInfo :: Ptr () -> IO CKSlotInfo
peekSlotInfo p = CKSlotInfo
  <$> peekFixed p #{offset CK_SLOT_INFO, slotDescription} 64
  <*> peekFixed p #{offset CK_SLOT_INFO, manufacturerID} 32
  <*> #{peek CK_SLOT_INFO, flags} p

peekTokenInfo :: Ptr () -> IO CKTokenInfo
peekTokenInfo p = CKTokenInfo
  <$> peekFixed p #{offset CK_TOKEN_INFO, label} 32
  <*> peekFixed p #{offset CK_TOKEN_INFO, manufacturerID} 32
  <*> peekFixed p #{offset CK_TOKEN_INFO, model} 16
  <*> peekFixed p #{offset CK_TOKEN_INFO, serialNumber} 16
  <*> #{peek CK_TOKEN_INFO, flags} p
  <*> #{peek CK_TOKEN_INFO, ulMaxSessionCount} p
  <*> #{peek CK_TOKEN_INFO, ulSessionCount} p

peekMechInfo :: Ptr () -> IO CKMechanismInfo
peekMechInfo p = CKMechanismInfo
  <$> #{peek CK_MECHANISM_INFO, ulMinKeySize} p
  <*> #{peek CK_MECHANISM_INFO, ulMaxKeySize} p
  <*> #{peek CK_MECHANISM_INFO, flags} p

peekSessionInfo :: Ptr () -> IO CKSessionInfo
peekSessionInfo p = CKSessionInfo
  <$> #{peek CK_SESSION_INFO, slotID} p
  <*> #{peek CK_SESSION_INFO, state} p
  <*> #{peek CK_SESSION_INFO, flags} p
  <*> #{peek CK_SESSION_INFO, ulDeviceError} p

infoSize, slotInfoSize, tokenInfoSize, mechInfoSize, sessionInfoSize :: Int
infoSize = #{size CK_INFO}
slotInfoSize = #{size CK_SLOT_INFO}
tokenInfoSize = #{size CK_TOKEN_INFO}
mechInfoSize = #{size CK_MECHANISM_INFO}
sessionInfoSize = #{size CK_SESSION_INFO}

-- ---------------------------------------------------------------------------
-- Dynamic call wrappers, one per C-level call shape
-- ---------------------------------------------------------------------------

foreign import ccall "dynamic" dynVP
  :: FunPtr (Ptr () -> IO Word64) -> Ptr () -> IO Word64
foreign import ccall "dynamic" dynBWW
  :: FunPtr (Word8 -> Ptr Word64 -> Ptr Word64 -> IO Word64)
  -> Word8 -> Ptr Word64 -> Ptr Word64 -> IO Word64
foreign import ccall "dynamic" dynWP
  :: FunPtr (Word64 -> Ptr () -> IO Word64) -> Word64 -> Ptr () -> IO Word64
foreign import ccall "dynamic" dynWWW
  :: FunPtr (Word64 -> Ptr Word64 -> Ptr Word64 -> IO Word64)
  -> Word64 -> Ptr Word64 -> Ptr Word64 -> IO Word64
foreign import ccall "dynamic" dynWWWW
  :: FunPtr (Word64 -> Ptr Word64 -> Word64 -> Ptr Word64 -> IO Word64)
  -> Word64 -> Ptr Word64 -> Word64 -> Ptr Word64 -> IO Word64
foreign import ccall "dynamic" dynWWP
  :: FunPtr (Word64 -> Word64 -> Ptr () -> IO Word64)
  -> Word64 -> Word64 -> Ptr () -> IO Word64
foreign import ccall "dynamic" dynOpenSession
  :: FunPtr (Word64 -> Word64 -> Ptr () -> Ptr () -> Ptr Word64 -> IO Word64)
  -> Word64 -> Word64 -> Ptr () -> Ptr () -> Ptr Word64 -> IO Word64
foreign import ccall "dynamic" dynW
  :: FunPtr (Word64 -> IO Word64) -> Word64 -> IO Word64
foreign import ccall "dynamic" dynWW
  :: FunPtr (Word64 -> Word64 -> IO Word64) -> Word64 -> Word64 -> IO Word64
foreign import ccall "dynamic" dynWPW
  :: FunPtr (Word64 -> Ptr () -> Word64 -> IO Word64)
  -> Word64 -> Ptr () -> Word64 -> IO Word64
foreign import ccall "dynamic" dynWPWW
  :: FunPtr (Word64 -> Ptr () -> Word64 -> Ptr Word64 -> IO Word64)
  -> Word64 -> Ptr () -> Word64 -> Ptr Word64 -> IO Word64
foreign import ccall "dynamic" dynWWPW
  :: FunPtr (Word64 -> Word64 -> Ptr () -> Word64 -> IO Word64)
  -> Word64 -> Word64 -> Ptr () -> Word64 -> IO Word64
foreign import ccall "dynamic" dynWBuf
  :: FunPtr (Word64 -> Ptr Word8 -> Word64 -> Ptr Word8 -> Ptr Word64 -> IO Word64)
  -> Word64 -> Ptr Word8 -> Word64 -> Ptr Word8 -> Ptr Word64 -> IO Word64
foreign import ccall "dynamic" dynWIn
  :: FunPtr (Word64 -> Ptr Word8 -> Word64 -> IO Word64)
  -> Word64 -> Ptr Word8 -> Word64 -> IO Word64
foreign import ccall "dynamic" dynWOut
  :: FunPtr (Word64 -> Ptr Word8 -> Ptr Word64 -> IO Word64)
  -> Word64 -> Ptr Word8 -> Ptr Word64 -> IO Word64
foreign import ccall "dynamic" dynWVerify
  :: FunPtr (Word64 -> Ptr Word8 -> Word64 -> Ptr Word8 -> Word64 -> IO Word64)
  -> Word64 -> Ptr Word8 -> Word64 -> Ptr Word8 -> Word64 -> IO Word64
foreign import ccall "dynamic" dynWLogin
  :: FunPtr (Word64 -> Word64 -> Ptr Word8 -> Word64 -> IO Word64)
  -> Word64 -> Word64 -> Ptr Word8 -> Word64 -> IO Word64
foreign import ccall "dynamic" dynGenKeyPair
  :: FunPtr (Word64 -> Ptr () -> Ptr () -> Word64 -> Ptr () -> Word64
              -> Ptr Word64 -> Ptr Word64 -> IO Word64)
  -> Word64 -> Ptr () -> Ptr () -> Word64 -> Ptr () -> Word64
  -> Ptr Word64 -> Ptr Word64 -> IO Word64
foreign import ccall "dynamic" dynGenKey
  :: FunPtr (Word64 -> Ptr () -> Ptr () -> Word64 -> Ptr Word64 -> IO Word64)
  -> Word64 -> Ptr () -> Ptr () -> Word64 -> Ptr Word64 -> IO Word64
foreign import ccall "dynamic" dynDerive
  :: FunPtr (Word64 -> Ptr () -> Word64 -> Ptr () -> Word64 -> Ptr Word64 -> IO Word64)
  -> Word64 -> Ptr () -> Word64 -> Ptr () -> Word64 -> Ptr Word64 -> IO Word64
foreign import ccall "dynamic" dynGetFunctionList
  :: FunPtr (Ptr (Ptr ()) -> IO Word64) -> Ptr (Ptr ()) -> IO Word64

-- ---------------------------------------------------------------------------
-- Resolved function list
-- ---------------------------------------------------------------------------

-- | The 2.x calls a client smoke test needs, resolved once from the
-- module's function list.
data Functions = Functions
  { fInitialize :: Ptr () -> IO Word64
  , fFinalize :: Ptr () -> IO Word64
  , fGetInfo :: Ptr () -> IO Word64
  , fGetSlotList :: Word8 -> Ptr Word64 -> Ptr Word64 -> IO Word64
  , fGetSlotInfo :: Word64 -> Ptr () -> IO Word64
  , fGetTokenInfo :: Word64 -> Ptr () -> IO Word64
  , fGetMechanismList :: Word64 -> Ptr Word64 -> Ptr Word64 -> IO Word64
  , fGetMechanismInfo :: Word64 -> Word64 -> Ptr () -> IO Word64
  , fOpenSession :: Word64 -> Word64 -> Ptr Word64 -> IO Word64
  , fCloseSession :: Word64 -> IO Word64
  , fGetSessionInfo :: Word64 -> Ptr () -> IO Word64
  , fLogin :: Word64 -> Word64 -> Ptr Word8 -> Word64 -> IO Word64
  , fLogout :: Word64 -> IO Word64
  , fCreateObject :: Word64 -> Ptr () -> Word64 -> Ptr Word64 -> IO Word64
  , fDestroyObject :: Word64 -> Word64 -> IO Word64
  , fGetAttributeValue :: Word64 -> Word64 -> Ptr () -> Word64 -> IO Word64
  , fFindObjectsInit :: Word64 -> Ptr () -> Word64 -> IO Word64
  , fFindObjects :: Word64 -> Ptr Word64 -> Word64 -> Ptr Word64 -> IO Word64
  , fFindObjectsFinal :: Word64 -> IO Word64
  , fDigestInit :: Word64 -> Ptr () -> IO Word64
  , fDigest :: Word64 -> Ptr Word8 -> Word64 -> Ptr Word8 -> Ptr Word64 -> IO Word64
  , fDigestUpdate :: Word64 -> Ptr Word8 -> Word64 -> IO Word64
  , fDigestFinal :: Word64 -> Ptr Word8 -> Ptr Word64 -> IO Word64
  , fEncryptInit :: Word64 -> Ptr () -> Word64 -> IO Word64
  , fEncrypt :: Word64 -> Ptr Word8 -> Word64 -> Ptr Word8 -> Ptr Word64 -> IO Word64
  , fEncryptUpdate :: Word64 -> Ptr Word8 -> Word64 -> Ptr Word8 -> Ptr Word64 -> IO Word64
  , fEncryptFinal :: Word64 -> Ptr Word8 -> Ptr Word64 -> IO Word64
  , fDecryptInit :: Word64 -> Ptr () -> Word64 -> IO Word64
  , fDecrypt :: Word64 -> Ptr Word8 -> Word64 -> Ptr Word8 -> Ptr Word64 -> IO Word64
  , fDecryptUpdate :: Word64 -> Ptr Word8 -> Word64 -> Ptr Word8 -> Ptr Word64 -> IO Word64
  , fDecryptFinal :: Word64 -> Ptr Word8 -> Ptr Word64 -> IO Word64
  , fSignInit :: Word64 -> Ptr () -> Word64 -> IO Word64
  , fSign :: Word64 -> Ptr Word8 -> Word64 -> Ptr Word8 -> Ptr Word64 -> IO Word64
  , fSignUpdate :: Word64 -> Ptr Word8 -> Word64 -> IO Word64
  , fSignFinal :: Word64 -> Ptr Word8 -> Ptr Word64 -> IO Word64
  , fVerifyInit :: Word64 -> Ptr () -> Word64 -> IO Word64
  , fVerify :: Word64 -> Ptr Word8 -> Word64 -> Ptr Word8 -> Word64 -> IO Word64
  , fVerifyUpdate :: Word64 -> Ptr Word8 -> Word64 -> IO Word64
  , fVerifyFinal :: Word64 -> Ptr Word8 -> Word64 -> IO Word64
  , fGenerateKey :: Word64 -> Ptr () -> Ptr () -> Word64 -> Ptr Word64 -> IO Word64
  , fGenerateKeyPair :: Word64 -> Ptr () -> Ptr () -> Word64 -> Ptr () -> Word64
                    -> Ptr Word64 -> Ptr Word64 -> IO Word64
  , fDeriveKey :: Word64 -> Ptr () -> Word64 -> Ptr () -> Word64 -> Ptr Word64 -> IO Word64
  , fSeedRandom :: Word64 -> Ptr Word8 -> Word64 -> IO Word64
  , fGenerateRandom :: Word64 -> Ptr Word8 -> Word64 -> IO Word64
  }

entry :: Ptr a -> Int -> IO (FunPtr b)
entry base off = castFunPtr <$> peekByteOff base off

loadFunctions :: Ptr () -> IO Functions
loadFunctions fl = do
  cInitialize <- entry fl #{offset CK_FUNCTION_LIST, C_Initialize}
  cFinalize <- entry fl #{offset CK_FUNCTION_LIST, C_Finalize}
  cGetInfo <- entry fl #{offset CK_FUNCTION_LIST, C_GetInfo}
  cGetSlotList <- entry fl #{offset CK_FUNCTION_LIST, C_GetSlotList}
  cGetSlotInfo <- entry fl #{offset CK_FUNCTION_LIST, C_GetSlotInfo}
  cGetTokenInfo <- entry fl #{offset CK_FUNCTION_LIST, C_GetTokenInfo}
  cGetMechanismList <- entry fl #{offset CK_FUNCTION_LIST, C_GetMechanismList}
  cGetMechanismInfo <- entry fl #{offset CK_FUNCTION_LIST, C_GetMechanismInfo}
  cOpenSession <- entry fl #{offset CK_FUNCTION_LIST, C_OpenSession}
  cCloseSession <- entry fl #{offset CK_FUNCTION_LIST, C_CloseSession}
  cGetSessionInfo <- entry fl #{offset CK_FUNCTION_LIST, C_GetSessionInfo}
  cLogin <- entry fl #{offset CK_FUNCTION_LIST, C_Login}
  cLogout <- entry fl #{offset CK_FUNCTION_LIST, C_Logout}
  cCreateObject <- entry fl #{offset CK_FUNCTION_LIST, C_CreateObject}
  cDestroyObject <- entry fl #{offset CK_FUNCTION_LIST, C_DestroyObject}
  cGetAttributeValue <- entry fl #{offset CK_FUNCTION_LIST, C_GetAttributeValue}
  cFindObjectsInit <- entry fl #{offset CK_FUNCTION_LIST, C_FindObjectsInit}
  cFindObjects <- entry fl #{offset CK_FUNCTION_LIST, C_FindObjects}
  cFindObjectsFinal <- entry fl #{offset CK_FUNCTION_LIST, C_FindObjectsFinal}
  cDigestInit <- entry fl #{offset CK_FUNCTION_LIST, C_DigestInit}
  cDigest <- entry fl #{offset CK_FUNCTION_LIST, C_Digest}
  cDigestUpdate <- entry fl #{offset CK_FUNCTION_LIST, C_DigestUpdate}
  cDigestFinal <- entry fl #{offset CK_FUNCTION_LIST, C_DigestFinal}
  cEncryptInit <- entry fl #{offset CK_FUNCTION_LIST, C_EncryptInit}
  cEncrypt <- entry fl #{offset CK_FUNCTION_LIST, C_Encrypt}
  cEncryptUpdate <- entry fl #{offset CK_FUNCTION_LIST, C_EncryptUpdate}
  cEncryptFinal <- entry fl #{offset CK_FUNCTION_LIST, C_EncryptFinal}
  cDecryptInit <- entry fl #{offset CK_FUNCTION_LIST, C_DecryptInit}
  cDecrypt <- entry fl #{offset CK_FUNCTION_LIST, C_Decrypt}
  cDecryptUpdate <- entry fl #{offset CK_FUNCTION_LIST, C_DecryptUpdate}
  cDecryptFinal <- entry fl #{offset CK_FUNCTION_LIST, C_DecryptFinal}
  cSignInit <- entry fl #{offset CK_FUNCTION_LIST, C_SignInit}
  cSign <- entry fl #{offset CK_FUNCTION_LIST, C_Sign}
  cSignUpdate <- entry fl #{offset CK_FUNCTION_LIST, C_SignUpdate}
  cSignFinal <- entry fl #{offset CK_FUNCTION_LIST, C_SignFinal}
  cVerifyInit <- entry fl #{offset CK_FUNCTION_LIST, C_VerifyInit}
  cVerify <- entry fl #{offset CK_FUNCTION_LIST, C_Verify}
  cVerifyUpdate <- entry fl #{offset CK_FUNCTION_LIST, C_VerifyUpdate}
  cVerifyFinal <- entry fl #{offset CK_FUNCTION_LIST, C_VerifyFinal}
  cGenerateKey <- entry fl #{offset CK_FUNCTION_LIST, C_GenerateKey}
  cGenerateKeyPair <- entry fl #{offset CK_FUNCTION_LIST, C_GenerateKeyPair}
  cDeriveKey <- entry fl #{offset CK_FUNCTION_LIST, C_DeriveKey}
  cSeedRandom <- entry fl #{offset CK_FUNCTION_LIST, C_SeedRandom}
  cGenerateRandom <- entry fl #{offset CK_FUNCTION_LIST, C_GenerateRandom}
  pure Functions
    { fInitialize = dynVP cInitialize
    , fFinalize = dynVP cFinalize
    , fGetInfo = dynVP cGetInfo
    , fGetSlotList = dynBWW cGetSlotList
    , fGetSlotInfo = dynWP cGetSlotInfo
    , fGetTokenInfo = dynWP cGetTokenInfo
    , fGetMechanismList = dynWWW cGetMechanismList
    , fGetMechanismInfo = dynWWP cGetMechanismInfo
    , fOpenSession = \slot flags out ->
        dynOpenSession cOpenSession slot flags nullPtr nullPtr out
    , fCloseSession = dynW cCloseSession
    , fGetSessionInfo = dynWP cGetSessionInfo
    , fLogin = dynWLogin cLogin
    , fLogout = dynW cLogout
    , fCreateObject = dynWPWW cCreateObject
    , fDestroyObject = dynWW cDestroyObject
    , fGetAttributeValue = dynWWPW cGetAttributeValue
    , fFindObjectsInit = dynWPW cFindObjectsInit
    , fFindObjects = dynWWWW cFindObjects
    , fFindObjectsFinal = dynW cFindObjectsFinal
    , fDigestInit = dynWP cDigestInit
    , fDigest = dynWBuf cDigest
    , fDigestUpdate = dynWIn cDigestUpdate
    , fDigestFinal = dynWOut cDigestFinal
    , fEncryptInit = dynWPW cEncryptInit
    , fEncrypt = dynWBuf cEncrypt
    , fEncryptUpdate = dynWBuf cEncryptUpdate
    , fEncryptFinal = dynWOut cEncryptFinal
    , fDecryptInit = dynWPW cDecryptInit
    , fDecrypt = dynWBuf cDecrypt
    , fDecryptUpdate = dynWBuf cDecryptUpdate
    , fDecryptFinal = dynWOut cDecryptFinal
    , fSignInit = dynWPW cSignInit
    , fSign = dynWBuf cSign
    , fSignUpdate = dynWIn cSignUpdate
    , fSignFinal = dynWOut cSignFinal
    , fVerifyInit = dynWPW cVerifyInit
    , fVerify = dynWVerify cVerify
    , fVerifyUpdate = dynWIn cVerifyUpdate
    , fVerifyFinal = dynWVerifyFinalShim cVerifyFinal
    , fGenerateKey = dynGenKey cGenerateKey
    , fGenerateKeyPair = dynGenKeyPair cGenerateKeyPair
    , fDeriveKey = dynDerive cDeriveKey
    , fSeedRandom = dynWIn cSeedRandom
    , fGenerateRandom = dynWIn cGenerateRandom
    }
  where
    -- C_VerifyFinal(h, sig, sigLen) shares the 3-arg input shape.
    dynWVerifyFinalShim
      :: FunPtr (Word64 -> Ptr Word8 -> Word64 -> IO Word64)
      -> Word64 -> Ptr Word8 -> Word64 -> IO Word64
    dynWVerifyFinalShim = dynWIn

-- | Major/minor of the module's function list (offset 0).
functionListVersion :: Ptr () -> IO (Word8, Word8)
functionListVersion = (`peekVersion` 0)

-- ---------------------------------------------------------------------------
-- Loading
-- ---------------------------------------------------------------------------

-- | @dlopen@ the module, resolve @C_GetFunctionList@, fetch the list,
-- and run the client. The handle closes on exit.
withModule :: FilePath -> (Functions -> IO a) -> IO a
withModule path body =
  bracket (dlopen path [RTLD_NOW]) dlclose $ \dl -> do
    sym <- dlsym dl "C_GetFunctionList"
    fl <- alloca $ \pp -> do
      rv <- dynGetFunctionList (castFunPtr sym) pp
      if rv /= ckrOk
        then fail ("C_GetFunctionList failed: " ++ rvName rv)
        else peek pp
    loadFunctions fl >>= body
