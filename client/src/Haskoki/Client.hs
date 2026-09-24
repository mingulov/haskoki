-- | Small bracketed PKCS#11 client over 'Raw.Functions': sessions,
-- login, attributes, and the single-part crypto calls a smoke test
-- needs. Errors raise 'P11Error' with the failing call and the @CK_RV@
-- name. Test-only.
module Haskoki.Client
  ( P11Error (..)
  , Session (..)
  , withToken
  , openSession
  , withSession
  , loginUser
  , logout
  , getInfo
  , getSlotList
  , getTokenInfo
  , getMechanismList
  , Attr (..)
  , attrBool, attrULong, attrBytes
  , withTemplate
  , withMechanism
  , generateKey
  , generateKeyPair
  , deriveKey
  , createObject
  , destroyObject
  , getAttrBytes
  , digest
  , digestMultipart
  , encryptSingle
  , decryptSingle
  , signSingle
  , verifySingle
  , signMultipart
  , generateRandom
  , hex
  , unhex
  ) where

import Control.Exception (Exception, bracket, throwIO)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Unsafe as BSU
import Data.Word (Word8, Word64)
import Foreign.Marshal.Alloc (alloca, allocaBytes)
import Foreign.Marshal.Array (allocaArray, peekArray, pokeArray)
import Foreign.Ptr (Ptr, castPtr, nullPtr, plusPtr)
import Foreign.Storable (peek, poke, sizeOf)

import Haskoki.Client.Raw

-- ---------------------------------------------------------------------------
-- Errors
-- ---------------------------------------------------------------------------

data P11Error = P11Error
  { p11Call :: !String
  , p11Rv :: !CK_RV
  } deriving (Show)

instance Exception P11Error

check :: Functions -> String -> IO CK_RV -> IO ()
check _fun call act = do
  rv <- act
  if rv == ckrOk then pure () else throwIO (P11Error call rv)

-- ---------------------------------------------------------------------------
-- Sessions
-- ---------------------------------------------------------------------------

data Session = Session
  { sessFuns :: !Functions
  , sessHandle :: !Word64
  , sessSlot :: !Word64
  }

-- | Load the module, initialize, run, finalize. @C_Initialize@ with NULL
-- args (no custom mutexes, no @CKF_OS_LOCKING_OK@ claim needed here).
withToken :: FilePath -> (Functions -> IO a) -> IO a
withToken path body = withModule path $ \funs -> do
  check funs "C_Initialize" (fInitialize funs nullPtr)
  out <- body funs
  check funs "C_Finalize" (fFinalize funs nullPtr)
  pure out

openSession :: Functions -> Word64 -> Bool -> IO Session
openSession funs slot rw = alloca $ \ph -> do
  let flags = ckfSerialSession + if rw then ckfRwSession else 0
  check funs "C_OpenSession" (fOpenSession funs slot flags ph)
  h <- peek ph
  pure (Session funs h slot)

closeSession :: Session -> IO ()
closeSession (Session funs h _) =
  check funs "C_CloseSession" (fCloseSession funs h)

withSession :: Functions -> Word64 -> Bool -> (Session -> IO a) -> IO a
withSession funs slot rw = bracket (openSession funs slot rw) closeSession

loginUser :: Session -> BS.ByteString -> IO ()
loginUser (Session funs h _) pin =
  BSU.unsafeUseAsCStringLen pin $ \(ptr, len) ->
    check funs "C_Login"
      (fLogin funs h ckuUser (castPtr ptr) (fromIntegral len))

logout :: Session -> IO ()
logout (Session funs h _) = check funs "C_Logout" (fLogout funs h)

-- ---------------------------------------------------------------------------
-- Discovery
-- ---------------------------------------------------------------------------

getInfo :: Functions -> IO CKInfo
getInfo funs = allocaBytes infoSize $ \p -> do
  check funs "C_GetInfo" (fGetInfo funs p)
  peekInfo p

-- | All slots (@tokenPresent@ FALSE: every slot with a token or not —
-- the smoke CLI filters by token presence via 'getTokenInfo').
getSlotList :: Functions -> Bool -> IO [Word64]
getSlotList funs present = alloca $ \pn -> do
  let flag = if present then ckTrue else ckFalse
  check funs "C_GetSlotList(count)"
    (fGetSlotList funs flag nullPtr pn)
  n <- peek pn
  allocaArray (fromIntegral n) $ \ps -> do
    check funs "C_GetSlotList" (fGetSlotList funs flag ps pn)
    n2 <- peek pn
    peekArray (fromIntegral n2) ps

getTokenInfo :: Functions -> Word64 -> IO CKTokenInfo
getTokenInfo funs slot = allocaBytes tokenInfoSize $ \p -> do
  check funs "C_GetTokenInfo" (fGetTokenInfo funs slot p)
  peekTokenInfo p

getMechanismList :: Functions -> Word64 -> IO [Word64]
getMechanismList funs slot = alloca $ \pn -> do
  check funs "C_GetMechanismList(count)"
    (fGetMechanismList funs slot nullPtr pn)
  n <- peek pn
  allocaArray (fromIntegral n) $ \ps -> do
    check funs "C_GetMechanismList" (fGetMechanismList funs slot ps pn)
    n2 <- peek pn
    peekArray (fromIntegral n2) ps

-- ---------------------------------------------------------------------------
-- Templates and mechanisms
-- ---------------------------------------------------------------------------

-- | One template attribute: type plus owned value bytes (bool/ulong are
-- pre-encoded by the smart constructors).
data Attr = Attr !Word64 !BS.ByteString

attrBool :: Word64 -> Bool -> Attr
attrBool t b = Attr t (BS.singleton (if b then ckTrue else ckFalse))

attrULong :: Word64 -> Word64 -> Attr
attrULong t w = Attr t (BS.pack
  [ fromIntegral w, fromIntegral (w `div` 256), fromIntegral (w `div` 65536)
  , fromIntegral (w `div` 16777216), fromIntegral (w `div` 4294967296)
  , fromIntegral (w `div` 1099511627776), fromIntegral (w `div` 281474976710656)
  , fromIntegral (w `div` 72057594037927936) ])

attrBytes :: Word64 -> BS.ByteString -> Attr
attrBytes = Attr

-- | Marshal a template: value bytes are copied into one block whose
-- lifetime covers the call.
withTemplate :: [Attr] -> (Ptr () -> Word64 -> IO a) -> IO a
withTemplate attrs body = do
  let blob = BS.concat [bs | Attr _ bs <- attrs]
      offs = scanl (+) 0 [BS.length bs | Attr _ bs <- attrs]
  BSU.unsafeUseAsCStringLen blob $ \(vptr, _) ->
    allocaArray (length attrs) $ \aptr -> do
      let mk :: Int -> Attr -> IO ()
          mk i (Attr t bs) =
            poke (advance aptr i)
              (CKAttribute t (vptr `plusPtr` (offs !! i) `asVoid`) (fromIntegral (BS.length bs)))
          advance :: Ptr CKAttribute -> Int -> Ptr CKAttribute
          advance p j = p `plusPtr` (j * sizeOf (undefined :: CKAttribute))
      mapM_ (uncurry mk) (zip [0 ..] attrs)
      body (castPtr aptr) (fromIntegral (length attrs))
  where
    asVoid :: Ptr a -> Ptr ()
    asVoid = castPtr

withMechanism :: Word64 -> BS.ByteString -> (Ptr () -> IO a) -> IO a
withMechanism typ params body =
  BSU.unsafeUseAsCStringLen params $ \(pptr, plen) ->
    alloca $ \mptr -> do
      poke mptr (CKMechanism typ (castPtr pptr) (fromIntegral plen))
      body (castPtr mptr)

-- ---------------------------------------------------------------------------
-- Objects
-- ---------------------------------------------------------------------------

generateKey :: Session -> Word64 -> BS.ByteString -> [Attr] -> IO Word64
generateKey (Session funs h _) mech params tmpl =
  withMechanism mech params $ \mp ->
    withTemplate tmpl $ \tp n ->
      alloca $ \ph -> do
        check funs "C_GenerateKey" (fGenerateKey funs h mp tp n ph)
        peek ph

generateKeyPair
  :: Session -> Word64 -> BS.ByteString -> [Attr] -> [Attr]
  -> IO (Word64, Word64)
generateKeyPair (Session funs h _) mech params pub priv =
  withMechanism mech params $ \mp ->
    withTemplate pub $ \tpub npub ->
      withTemplate priv $ \tpriv npriv ->
        alloca $ \phpub -> alloca $ \phpriv -> do
          check funs "C_GenerateKeyPair"
            (fGenerateKeyPair funs h mp tpub npub tpriv npriv phpub phpriv)
          pubH <- peek phpub
          privH <- peek phpriv
          pure (pubH, privH)

deriveKey
  :: Session -> Word64 -> BS.ByteString -> Word64 -> [Attr] -> IO Word64
deriveKey (Session funs h _) mech params base tmpl =
  withMechanism mech params $ \mp ->
    withTemplate tmpl $ \tp n ->
      alloca $ \ph -> do
        check funs "C_DeriveKey" (fDeriveKey funs h mp base tp n ph)
        peek ph

createObject :: Session -> [Attr] -> IO Word64
createObject (Session funs h _) tmpl =
  withTemplate tmpl $ \tp n ->
    alloca $ \ph -> do
      check funs "C_CreateObject" (fCreateObject funs h tp n ph)
      peek ph

destroyObject :: Session -> Word64 -> IO ()
destroyObject (Session funs h _) o =
  check funs "C_DestroyObject" (fDestroyObject funs h o)

-- | Query one attribute's value with the two-phase length call.
getAttrBytes :: Session -> Word64 -> Word64 -> IO BS.ByteString
getAttrBytes (Session funs h _) obj typ =
  allocaArray 1 $ \aptr -> do
    poke aptr (CKAttribute typ nullPtr 0)
    check funs "C_GetAttributeValue(len)"
      (fGetAttributeValue funs h obj (castPtr aptr) 1)
    CKAttribute _ _ len <- peek aptr
    allocaBytes (fromIntegral len) $ \out -> do
      poke aptr (CKAttribute typ out len)
      check funs "C_GetAttributeValue"
        (fGetAttributeValue funs h obj (castPtr aptr) 1)
      BS.packCStringLen (castPtr out, fromIntegral len)

-- ---------------------------------------------------------------------------
-- Crypto helpers
-- ---------------------------------------------------------------------------

-- | Two-phase single-part call: length query with NULL out, then fill.
singleOut
  :: Functions -> String
  -> (Ptr Word8 -> Ptr Word64 -> IO CK_RV) -> IO BS.ByteString
singleOut funs call act = alloca $ \pn -> do
  check funs (call ++ "(len)") (act nullPtr pn)
  n <- peek pn
  allocaBytes (fromIntegral n) $ \pout -> do
    check funs call (act pout pn)
    n2 <- peek pn
    BS.packCStringLen (castPtr pout, fromIntegral n2)

withInput :: BS.ByteString -> (Ptr Word8 -> Word64 -> IO a) -> IO a
withInput bs body =
  BSU.unsafeUseAsCStringLen bs $ \(p, n) ->
    body (castPtr p) (fromIntegral n)

digest :: Session -> Word64 -> BS.ByteString -> IO BS.ByteString
digest (Session funs h _) mech msg =
  withMechanism mech BS.empty $ \mp -> do
    check funs "C_DigestInit" (fDigestInit funs h mp)
    withInput msg $ \p n ->
      singleOut funs "C_Digest" (fDigest funs h p n)

digestMultipart
  :: Session -> Word64 -> [BS.ByteString] -> IO BS.ByteString
digestMultipart (Session funs h _) mech parts =
  withMechanism mech BS.empty $ \mp -> do
    check funs "C_DigestInit" (fDigestInit funs h mp)
    mapM_ (\bs -> withInput bs $ \p n ->
      check funs "C_DigestUpdate" (fDigestUpdate funs h p n)) parts
    singleOut funs "C_DigestFinal" (fDigestFinal funs h)

encryptSingle
  :: Session -> Word64 -> BS.ByteString -> Word64 -> BS.ByteString
  -> IO BS.ByteString
encryptSingle (Session funs h _) mech params key msg =
  withMechanism mech params $ \mp -> do
    check funs "C_EncryptInit" (fEncryptInit funs h mp key)
    withInput msg $ \p n ->
      singleOut funs "C_Encrypt" (fEncrypt funs h p n)

decryptSingle
  :: Session -> Word64 -> BS.ByteString -> Word64 -> BS.ByteString
  -> IO BS.ByteString
decryptSingle (Session funs h _) mech params key ct =
  withMechanism mech params $ \mp -> do
    check funs "C_DecryptInit" (fDecryptInit funs h mp key)
    withInput ct $ \p n ->
      singleOut funs "C_Decrypt" (fDecrypt funs h p n)

signSingle
  :: Session -> Word64 -> BS.ByteString -> Word64 -> BS.ByteString
  -> IO BS.ByteString
signSingle (Session funs h _) mech params key msg =
  withMechanism mech params $ \mp -> do
    check funs "C_SignInit" (fSignInit funs h mp key)
    withInput msg $ \p n ->
      singleOut funs "C_Sign" (fSign funs h p n)

verifySingle
  :: Session -> Word64 -> BS.ByteString -> Word64 -> BS.ByteString
  -> BS.ByteString -> IO ()
verifySingle (Session funs h _) mech params key msg sig =
  withMechanism mech params $ \mp -> do
    check funs "C_VerifyInit" (fVerifyInit funs h mp key)
    withInput msg $ \pm nm ->
      withInput sig $ \ps ns ->
        check funs "C_Verify" (fVerify funs h pm nm ps ns)

signMultipart
  :: Session -> Word64 -> BS.ByteString -> Word64 -> [BS.ByteString]
  -> IO BS.ByteString
signMultipart (Session funs h _) mech params key parts =
  withMechanism mech params $ \mp -> do
    check funs "C_SignInit" (fSignInit funs h mp key)
    mapM_ (\bs -> withInput bs $ \p n ->
      check funs "C_SignUpdate" (fSignUpdate funs h p n)) parts
    singleOut funs "C_SignFinal" (fSignFinal funs h)

generateRandom :: Session -> Int -> IO BS.ByteString
generateRandom (Session funs h _) n =
  allocaBytes n $ \p -> do
    check funs "C_GenerateRandom"
      (fGenerateRandom funs h p (fromIntegral n))
    BS.packCStringLen (castPtr p, n)

-- ---------------------------------------------------------------------------
-- Hex
-- ---------------------------------------------------------------------------

hex :: BS.ByteString -> String
hex = concatMap byte . BS.unpack
  where
    byte b = [digits !! fromIntegral (b `div` 16), digits !! fromIntegral (b `mod` 16)]
    digits = "0123456789abcdef"

unhex :: String -> BS.ByteString
unhex [] = BS.empty
unhex (a : b : rest) =
  BS.cons (fromIntegral (val a * 16 + val b)) (unhex rest)
  where
    val c
      | c >= '0' && c <= '9' = fromEnum c - fromEnum '0'
      | c >= 'a' && c <= 'f' = fromEnum c - fromEnum 'a' + 10
      | c >= 'A' && c <= 'F' = fromEnum c - fromEnum 'A' + 10
      | otherwise = error ("unhex: bad digit " ++ [c])
unhex [_] = error "unhex: odd length"
