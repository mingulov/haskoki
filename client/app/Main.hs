-- | @haskoki-client@: test-only CLI driving a PKCS#11 module through
-- the in-repo Haskell client. Every subcommand takes the module path
-- first. Exit nonzero (with the @CK_RV@ name on stderr) on any token
-- refusal.
module Main (main) where

import Control.Exception (catch)
import Data.Bits (xor)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BSC
import Data.Word (Word64, Word8)
import System.Environment (getArgs)
import System.Exit (exitFailure)
import System.IO (hPutStrLn, stderr)

import Haskoki.Client
import Haskoki.Client.Raw

main :: IO ()
main = do
  args <- getArgs
  (run args >>= putStr) `catch` \(P11Error call rv) -> do
    hPutStrLn stderr ("token refused " ++ call ++ ": " ++ rvName rv)
    exitFailure

run :: [String] -> IO String
run (modPath : cmd : rest) = withToken modPath $ \funs -> case cmd of
  "slots" -> cmdSlots funs
  "mechs" -> cmdMechs funs rest
  "digest" -> cmdDigest funs rest
  "rand" -> cmdRand funs rest
  "hmac" -> cmdHmac funs rest
  "aes" -> cmdAes funs
  "ec" -> cmdEc funs
  "kdf" -> cmdKdf funs
  "roundtrip" -> cmdRoundtrip funs
  _ -> fail ("unknown command: " ++ cmd)
run _ = fail "usage: haskoki-client <module.so> <slots|mechs|digest|rand|hmac|aes|ec|kdf|roundtrip> [args...]"

firstSlot :: Functions -> IO Word64
firstSlot funs = do
  slots <- getSlotList funs True
  case slots of
    [] -> fail "no slots with a token present"
    (s : _) -> pure s

cmdSlots :: Functions -> IO String
cmdSlots funs = do
  info <- getInfo funs
  slots <- getSlotList funs False
  rows <- mapM (slotRow funs) slots
  pure (unlines
    (("library: " ++ ciLibrary info ++ " (" ++ ciManufacturer info ++ ")")
      : ("slots: " ++ show (length slots)) : rows))
  where
    slotRow f s = do
      ti <- (Just <$> getTokenInfo f s)
        `catch` \(P11Error _ _) -> pure Nothing
      pure ("  slot " ++ show s ++ maybe " (empty)" tokenRow ti)
    tokenRow ti = " label=" ++ show (ctiLabel ti)
      ++ " model=" ++ show (ctiModel ti)
      ++ " sessions=" ++ show (ctiSessionCount ti)

cmdMechs :: Functions -> [String] -> IO String
cmdMechs funs rest = do
  slot <- case rest of
    (s : _) -> pure (read s)
    [] -> firstSlot funs
  mechs <- getMechanismList funs slot
  pure (unlines
    (("mechanisms on slot " ++ show slot ++ ": " ++ show (length mechs))
      : map (("  0x" ++) . hexWord) mechs))

hexWord :: Word64 -> String
hexWord 0 = "0"
hexWord n = reverse (go n)
  where
    go 0 = []
    go x = "0123456789abcdef" !! fromIntegral (x `mod` 16) : go (x `div` 16)

cmdDigest :: Functions -> [String] -> IO String
cmdDigest funs rest = do
  path <- case rest of
    (p : _) -> pure p
    [] -> fail "usage: haskoki-client <mod> digest <file>"
  msg <- BS.readFile path
  slot <- firstSlot funs
  withSession funs slot False $ \sess -> do
    d1 <- digest sess ckmSha256 msg
    -- Multipart over two halves must agree with single-part.
    let (a, b) = BS.splitAt (BS.length msg `div` 2) msg
    d2 <- digestMultipart sess ckmSha256 [a, b]
    if d1 /= d2
      then fail "single-part and multipart digests disagree"
      else pure ("SHA256(" ++ path ++ ") = " ++ hex d1 ++ "\n")

cmdRand :: Functions -> [String] -> IO String
cmdRand funs rest = do
  let n = case rest of
        (s : _) -> read s
        [] -> 32
  slot <- firstSlot funs
  withSession funs slot False $ \sess -> do
    bs <- generateRandom sess n
    if BS.length bs /= n
      then fail "short random read"
      else pure (hex bs ++ "\n")

-- | RFC 4231 test case 1: key = 0x0b x 20, data = "Hi There".
cmdHmac :: Functions -> [String] -> IO String
cmdHmac funs _rest = do
  let keyBytes = BS.replicate 20 0x0b
      msg = BSC.pack "Hi There"
      expect = "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
  slot <- firstSlot funs
  withSession funs slot True $ \sess -> do
    key <- createObject sess
      [ attrULong ckaClass ckoSecretKey
      , attrULong ckaKeyType ckkGenericSecret
      , attrBool ckaToken False
      , attrBool ckaSign True
      , attrBool ckaVerify True
      , attrBytes ckaValue keyBytes
      ]
    mac <- signSingle sess ckmSha256Hmac BS.empty key msg
    mac2 <- signMultipart sess ckmSha256Hmac BS.empty key [BSC.pack "Hi ", BSC.pack "There"]
    verifySingle sess ckmSha256Hmac BS.empty key msg mac
    -- Using the key after destroy must refuse.
    destroyObject sess key
    usedAfterDestroy <-
      (verifySingle sess ckmSha256Hmac BS.empty key msg mac >> pure True)
        `catch` \(P11Error _ _) -> pure False
    if usedAfterDestroy
      then fail "verify after destroy unexpectedly passed"
      else if hex mac /= expect
      then fail ("HMAC mismatch: got " ++ hex mac)
      else if mac /= mac2
        then fail "single-part and multipart HMACs disagree"
        else pure ("HMAC-SHA256(RFC4231#1) = " ++ hex mac ++ " OK\n")

cmdAes :: Functions -> IO String
cmdAes funs = do
  slot <- firstSlot funs
  withSession funs slot True $ \sess -> do
    key <- generateKey sess ckmAesKeyGen BS.empty
      [ attrULong ckaClass ckoSecretKey
      , attrULong ckaKeyType ckkAes
      , attrBool ckaToken False
      , attrBool ckaEncrypt True
      , attrBool ckaDecrypt True
      , attrULong ckaValueLen 16
      ]
    let iv = BS.replicate 16 0
        msg = BSC.pack "AES-CBC-PAD roundtrip, 29 bytes!!"
    ct <- encryptSingle sess ckmAesCbcPad iv key msg
    pt <- decryptSingle sess ckmAesCbcPad iv key ct
    destroyObject sess key
    if pt /= msg
      then fail "AES-CBC-PAD roundtrip mismatch"
      else pure ("AES-CBC-PAD roundtrip OK (" ++ show (BS.length ct) ++ " ct bytes)\n")

p256Params :: BS.ByteString
p256Params = BS.pack [0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07]

cmdEc :: Functions -> IO String
cmdEc funs = do
  slot <- firstSlot funs
  withSession funs slot True $ \sess -> do
    (pub, priv) <- generateKeyPair sess ckmEcKeyPairGen BS.empty
      [ attrULong ckaClass ckoPublicKey
      , attrULong ckaKeyType ckkEc
      , attrBytes ckaEcParams p256Params
      , attrBool ckaToken False
      , attrBool ckaVerify True
      ]
      [ attrULong ckaClass ckoPrivateKey
      , attrULong ckaKeyType ckkEc
      , attrBool ckaToken False
      , attrBool ckaSign True
      ]
    let msg = BSC.pack "ECDSA P-256 roundtrip"
    sig <- signSingle sess ckmEcdsa BS.empty priv msg
    verifySingle sess ckmEcdsa BS.empty pub msg sig
    -- A flipped bit must NOT verify.
    let bad = BS.map (`xor` (1 :: Word8)) sig
    badOk <- (verifySingle sess ckmEcdsa BS.empty pub msg bad >> pure True)
      `catch` \(P11Error _ _) -> pure False
    destroyObject sess pub
    destroyObject sess priv
    if badOk
      then fail "corrupt ECDSA signature verified"
      else pure ("ECDSA P-256 sign/verify OK (" ++ show (BS.length sig) ++ " sig bytes)\n")

cmdKdf :: Functions -> IO String
cmdKdf funs = do
  slot <- firstSlot funs
  withSession funs slot True $ \sess -> do
    base <- generateKey sess ckmGenericSecretKeyGen BS.empty
      [ attrULong ckaClass ckoSecretKey
      , attrULong ckaKeyType ckkGenericSecret
      , attrBool ckaToken False
      , attrBool ckaDerive True
      , attrULong ckaValueLen 32
      ]
    derived <- deriveKey sess ckmSha256KeyDerivation BS.empty base
      [ attrULong ckaClass ckoSecretKey
      , attrULong ckaKeyType ckkGenericSecret
      , attrBool ckaToken False
      , attrBool ckaSign True
      , attrULong ckaValueLen 16
      ]
    val <- getAttrBytes sess derived ckaValue
    destroyObject sess derived
    destroyObject sess base
    if BS.length val /= 16
      then fail "derived key has the wrong width"
      else pure "SHA256-KDF derive OK (16 bytes)\n"

cmdRoundtrip :: Functions -> IO String
cmdRoundtrip funs = do
  a <- cmdAes funs
  h <- cmdHmac funs []
  e <- cmdEc funs
  k <- cmdKdf funs
  pure (a ++ h ++ e ++ k)
