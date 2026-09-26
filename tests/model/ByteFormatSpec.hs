{- | Byte-format goldens.

Exact-bytes pins proving @docs/byte-formats.md@ §1–§3 match the
code: every golden below is hand-derived from the documented
layout (not copied from encoder output), so a passing run proves
doc and code agree. Round-trip and malformed-input coverage
already lives in @RoutingSpec@; snapshot goldens in
@SnapshotSpec@; storage schema + JSON docs in @StoreSpec@ and
@BytesSpec@ — this spec pins the remaining frame layouts.

Shared with @haskoki-core-tests@ (pure-core imports only).
-}
{-# LANGUAGE OverloadedStrings #-}
module ByteFormatSpec (spec) where

import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import Data.Word (Word64, Word8)
import System.Timeout (timeout)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertEqual, assertFailure, testCase)

import Haskoki.Attribute
  ( AttributeType (..)
  , AttributeValue (..)
  , decodeValue
  , encodeValue
  , maxAttributeBytes
  )
import Haskoki.Object
  ( decodeHandle
  , encodeHandle
  , encodeTemplate
  , encodeWanted
  , parseTemplate
  , parseWanted
  )
import Haskoki.Operation.Codec
  ( decodeInitInput
  , decodeMsgBegin
  , decodeMsgNext
  , decodeMsgOneShot
  , decodeVerifyInput
  , encodeInitInput
  , encodeMsgBegin
  , encodeMsgNext
  , encodeMsgOneShot
  , encodeVerifyInput
  )
import Haskoki.Operation.Message
  ( MsgBegin (..)
  , MsgNext (..)
  , MsgOneShot (..)
  )
import Haskoki.Operation.State (MsgFamily (..))
import Haskoki.Recipe.Cipher
  ( BlockCipherRecipe (..)
  , cipherParamsValid
  , cipherRecipeFor
  )
import Haskoki.Recipe.Ecdsa (ecdsaEncodingOf)
import Haskoki.Recipe.Gcm
  ( decodeGcmParams
  , encodeGcmParams
  , gcmParamsValid
  , gcmRecipeFor
  )
import Haskoki.Recipe.Hmac (encodeMacGeneral)
import Haskoki.Recipe.Otp (encodeHotpParams)
import Haskoki.Recipe.RsaOaep (encodeOaepParams)
import Haskoki.Recipe.RsaPss (encodePssParams)
import Haskoki.Registry (MechanismId (..), Operation (..))
import Haskoki.Registry.Generated (ckm_AES_CBC, ckm_AES_GCM)
import Haskoki.Types (ExternalHandle (..))

spec :: TestTree
spec = testGroup "byte-format goldens"
  [ testCase "init frame golden + layout" caseInit
  , testCase "verify one-shot golden" caseVerify
  , testCase "message frames goldens + family gates" caseMessage
  , testCase "template + wanted + handle goldens" caseTemplate
  , testCase "value codec layout" caseValue
  , testCase "recipe params goldens" caseParams
  ]

-- | Run a case under a 30s wedge guard (pure codecs; generous).
guarded :: String -> IO () -> IO ()
guarded label act = do
  m <- timeout (30 * 1000000) act
  case m of
    Just () -> pure ()
    Nothing -> assertFailure (label ++ " wedged (30s timeout)")

-- | One 8-byte big-endian word (the test-side renderer; the
-- goldens below spell every byte literally through this).
w64 :: Word64 -> ByteString
w64 n = BS.pack
  [fromIntegral ((n `div` (256 ^ s)) `mod` 256) | s <- ([7, 6 .. 0] :: [Int])]

w64le :: Word64 -> ByteString
w64le n = BS.pack
  [fromIntegral ((n `div` (256 ^ s)) `mod` 256) | s <- ([0 .. 7] :: [Int])]

-- | One 4-byte big-endian word.
w32 :: Word64 -> ByteString
w32 n = BS.pack
  [fromIntegral ((n `div` (256 ^ s)) `mod` 256) | s <- ([3, 2 .. 0] :: [Int])]

u8 :: Word8 -> ByteString
u8 = BS.singleton

caseInit :: IO ()
caseInit = guarded "init" $ do
  -- mech:u64 permits:u16 flags:u8 params:bytes — sign bit 0,
  -- decrypt bit 3, always-authenticate set.
  let blob = encodeInitInput (MechanismId 0x250) [OpSign, OpDecrypt] True "params"
      golden = w64 0x250 <> BS.pack [0, 9] <> u8 1 <> "params"
  assertEqual "init golden" golden blob
  assertEqual "init length" 17 (BS.length blob)
  -- Layout offsets from the doc.
  assertEqual "mech cell" (w64 0x250) (BS.take 8 blob)
  assertEqual "permits cell" (BS.pack [0, 9]) (BS.take 2 (BS.drop 8 blob))
  assertEqual "flags cell" (u8 1) (BS.take 1 (BS.drop 10 blob))
  assertEqual "params tail" "params" (BS.drop 11 blob)
  -- Permits decode in canonical ascending order.
  assertEqual "permits canonical"
    (Just (MechanismId 0x250, [OpSign, OpDecrypt], True, "params"))
    (decodeInitInput blob)
  -- Reserved bits reject.
  let badPerms = w64 0x250 <> BS.pack [0xFF, 0xC0] <> u8 0
      badFlags = w64 0x250 <> BS.pack [0, 0] <> u8 0xFE
  assertEqual "reserved permit bits" Nothing (decodeInitInput badPerms)
  assertEqual "reserved flag bits" Nothing (decodeInitInput badFlags)
  assertEqual "truncated" Nothing (decodeInitInput (BS.take 10 blob))

caseVerify :: IO ()
caseVerify = guarded "verify" $ do
  -- dlen:u32 data:dlen sig:bytes.
  let blob = encodeVerifyInput "data" "sig"
  assertEqual "verify golden" (w32 4 <> "datasig") blob
  assertEqual "verify round-trip" (Just ("data", "sig")) (decodeVerifyInput blob)
  assertEqual "verify truncated" Nothing (decodeVerifyInput "xx")
  assertEqual "verify short data" Nothing
    (decodeVerifyInput (w32 9 <> "short"))

caseMessage :: IO ()
caseMessage = guarded "message" $ do
  -- begin: plen:u32 params:plen aad:bytes.
  let begin = encodeMsgBegin (MsgBegin "nonce" "aad")
  assertEqual "begin golden" (w32 5 <> "nonceaad") begin
  assertEqual "begin round-trip" (Just (MsgBegin "nonce" "aad")) (decodeMsgBegin begin)
  -- next, cipher + sign: tag plen params end part.
  let nextC = encodeMsgNext (MsgNextCipher "p" "part" True)
      nextS = encodeMsgNext (MsgNextSign "p" "part" False)
  assertEqual "next cipher golden" (u8 0 <> w32 1 <> "p" <> u8 1 <> "part") nextC
  assertEqual "next sign golden" (u8 1 <> w32 1 <> "p" <> u8 0 <> "part") nextS
  -- next, verify without/with witness.
  let nextV0 = encodeMsgNext (MsgNextVerify "p" "part" Nothing)
      nextV1 = encodeMsgNext (MsgNextVerify "p" "part" (Just "w"))
  assertEqual "next verify golden" (u8 2 <> w32 1 <> "p" <> u8 0 <> "part") nextV0
  assertEqual "next witness golden"
    (u8 2 <> w32 1 <> "p" <> u8 1 <> w32 1 <> "w" <> "part") nextV1
  -- one-shot: tag + len-prefixed cells + input tail.
  let oneC = encodeMsgOneShot (MsgOneShotCipher "p" "aad" "in")
      oneS = encodeMsgOneShot (MsgOneShotSign "p" "in")
      oneV = encodeMsgOneShot (MsgOneShotVerify "p" "in" "wit")
  assertEqual "oneshot cipher golden"
    (u8 0 <> w32 1 <> "p" <> w32 3 <> "aad" <> "in") oneC
  assertEqual "oneshot sign golden" (u8 1 <> w32 1 <> "p" <> "in") oneS
  assertEqual "oneshot verify golden"
    (u8 2 <> w32 1 <> "p" <> w32 3 <> "wit" <> "in") oneV
  -- Family gates: cross-family blobs reject.
  assertEqual "next cipher under sign" Nothing (decodeMsgNext MsgSign nextC)
  assertEqual "next sign under encrypt" Nothing (decodeMsgNext MsgEncrypt nextS)
  assertEqual "next cipher under verify" Nothing (decodeMsgNext MsgVerify nextC)
  assertEqual "next verify under decrypt" Nothing (decodeMsgNext MsgDecrypt nextV1)
  assertEqual "oneshot cipher under sign" Nothing (decodeMsgOneShot MsgSign oneC)
  assertEqual "oneshot verify under encrypt" Nothing
    (decodeMsgOneShot MsgEncrypt oneV)
  -- Same-family decodes accept (cipher tag under either cipher family).
  assertEqual "next cipher under decrypt"
    (Just (MsgNextCipher "p" "part" True)) (decodeMsgNext MsgDecrypt nextC)
  assertEqual "oneshot cipher under decrypt"
    (Just (MsgOneShotCipher "p" "aad" "in")) (decodeMsgOneShot MsgDecrypt oneC)
  -- Bad tags and flags reject.
  assertEqual "bad next tag" Nothing (decodeMsgNext MsgSign (u8 9 <> "x"))
  assertEqual "bad end flag" Nothing
    (decodeMsgNext MsgEncrypt (u8 0 <> w32 1 <> "p" <> u8 7 <> "x"))
  assertEqual "bad witness flag" Nothing
    (decodeMsgNext MsgVerify (u8 2 <> w32 1 <> "p" <> u8 7 <> "x"))

caseTemplate :: IO ()
caseTemplate = guarded "template" $ do
  -- Tag order is the AttributeType enumerant order, pinned stable.
  let tags = [minBound .. maxBound] :: [AttributeType]
  assertEqual "tag count" 51 (length tags)
  assertEqual "tag order" [0 .. 50] (map fromEnum tags)
  assertEqual "class tag" 0 (fromEnum AttrClass)
  assertEqual "label tag" 3 (fromEnum AttrLabel)
  assertEqual "value tag" 5 (fromEnum AttrValue)
  assertEqual "modulus tag" 25 (fromEnum AttrModulus)
  assertEqual "ecpoint tag" 32 (fromEnum AttrEcPoint)
  assertEqual "allowed-mechanisms tag" 33 (fromEnum AttrAllowedMechanisms)
  assertEqual "copyable tag" 34 (fromEnum AttrCopyable)
  assertEqual "destroyable tag" 35 (fromEnum AttrDestroyable)
  assertEqual "certificate-type tag" 36 (fromEnum AttrCertificateType)
  assertEqual "subject tag" 37 (fromEnum AttrSubject)
  assertEqual "issuer tag" 38 (fromEnum AttrIssuer)
  assertEqual "serial-number tag" 39 (fromEnum AttrSerialNumber)
  assertEqual "public-key-info tag" 40 (fromEnum AttrPublicKeyInfo)
  assertEqual "hash-of-subject-public-key tag" 41
    (fromEnum AttrHashOfSubjectPublicKey)
  assertEqual "hash-of-issuer-public-key tag" 42
    (fromEnum AttrHashOfIssuerPublicKey)
  assertEqual "modifiable tag" 43 (fromEnum AttrModifiable)
  assertEqual "prime tag" 44 (fromEnum AttrPrime)
  assertEqual "subprime tag" 45 (fromEnum AttrSubprime)
  assertEqual "base tag" 46 (fromEnum AttrBase)
  assertEqual "prime-bits tag" 47 (fromEnum AttrPrimeBits)
  assertEqual "subprime-bits tag" 48 (fromEnum AttrSubprimeBits)
  assertEqual "parameter-set tag" 49 (fromEnum AttrParameterSet)
  assertEqual "seed tag" 50 (fromEnum AttrSeed)
  -- entry: tag:u8 vlen:u32 value:vlen.
  let tmpl = [(AttrClass, ValULong 4), (AttrLabel, ValBytes "ab")]
      blob = encodeTemplate tmpl
      golden = u8 0 <> w32 8 <> w64 4 <> u8 3 <> w32 2 <> "ab"
  assertEqual "template golden" golden blob
  assertEqual "template round-trip" (Just tmpl) (parseTemplate blob)
  assertEqual "template truncated" Nothing (parseTemplate (BS.take 9 blob))
  assertEqual "template unknown tag" Nothing
    (parseTemplate (u8 99 <> w32 1 <> "x"))
  -- Past-bound entry counts refuse (65 > maxTemplateEntries 64).
  let big = encodeTemplate (replicate 65 (AttrClass, ValULong 1))
  assertEqual "template over bound" Nothing (parseTemplate big)
  -- Wanted lists are bare tag bytes.
  assertEqual "wanted golden" (BS.pack [0, 5])
    (encodeWanted [AttrClass, AttrValue])
  assertEqual "wanted round-trip" (Just [AttrClass, AttrValue])
    (parseWanted (BS.pack [0, 5]))
  assertEqual "wanted unknown tag" Nothing (parseWanted (BS.pack [0, 99]))
  -- Handles are 8-byte big-endian words.
  assertEqual "handle golden" (w64 3) (encodeHandle (ExternalHandle 3))
  assertEqual "handle round-trip" (Just (ExternalHandle 3))
    (decodeHandle (w64 3))
  assertEqual "handle short" Nothing (decodeHandle (w64 3 <> "x"))
  assertEqual "handle truncated" Nothing (decodeHandle "short")

caseValue :: IO ()
caseValue = guarded "value" $ do
  assertEqual "bool true" (u8 1) (encodeValue (ValBool True))
  assertEqual "bool false" (u8 0) (encodeValue (ValBool False))
  assertEqual "ulong" (BS.pack [1, 2, 3, 4, 5, 6, 7, 8])
    (encodeValue (ValULong 0x0102030405060708))
  assertEqual "ulong zero" (w64 0) (encodeValue (ValULong 0))
  assertEqual "ulong max" (w64 maxBound) (encodeValue (ValULong maxBound))
  assertEqual "bytes identity" "raw" (encodeValue (ValBytes "raw"))
  -- Cross-shape bytes never decode.
  assertEqual "bool as ulong" Nothing (decodeValue AttrClass (u8 1))
  assertEqual "ulong as bool" Nothing
    (decodeValue AttrToken (encodeValue (ValULong 1)))
  assertEqual "bad bool byte" Nothing (decodeValue AttrToken (u8 7))
  assertEqual "short ulong" Nothing (decodeValue AttrClass "short")
  -- Byte arrays bound at 4 MiB.
  assertEqual "bound value" 4194304 maxAttributeBytes
  assertEqual "at bound" (Just (ValBytes (BS.replicate 4194304 0)))
    (decodeValue AttrValue (BS.replicate 4194304 0))
  assertEqual "over bound" Nothing
    (decodeValue AttrValue (BS.replicate 4194305 0))

caseParams :: IO ()
caseParams = guarded "params" $ do
  -- pss-params: digest code, MGF code, salt (SHA256=4, SHA_1=2).
  assertEqual "pss golden" (w64 4 <> w64 2 <> w64 20)
    (encodePssParams "SHA256" "SHA_1" 20)
  -- mac-general: 8-byte caller-native little-endian tag length.
  assertEqual "mac-general golden" (w64le 8) (encodeMacGeneral 8)
  -- hotp-params: counter, digit count.
  assertEqual "hotp golden" (w64 0 <> w64 6) (encodeHotpParams 0 6)
  -- oaep-params: digest code, MGF code, label.
  assertEqual "oaep golden" (w64 2 <> w64 2)
    (encodeOaepParams "SHA_1" "SHA_1" "")
  assertEqual "oaep label golden" (w64 2 <> w64 2 <> "L")
    (encodeOaepParams "SHA_1" "SHA_1" "L")
  -- gcm-params: tag length, IV length, IV, AAD.
  assertEqual "gcm golden" (w64 16 <> w64 12 <> "0123456789ab" <> "AD")
    (encodeGcmParams "0123456789ab" "AD" 16)
  assertEqual "gcm roundtrip"
    (Just ("0123456789ab", "AD", 16))
    (decodeGcmParams (encodeGcmParams "0123456789ab" "AD" 16))
  assertEqual "gcm truncated" Nothing
    (decodeGcmParams (w64 16 <> w64 12 <> "short"))
  case gcmRecipeFor (MechanismId ckm_AES_GCM) of
    Nothing -> assertFailure "no AES-GCM recipe"
    Just r -> do
      assertEqual "gcm valid" True
        (gcmParamsValid r (encodeGcmParams "0123456789ab" "AD" 16))
      assertEqual "gcm empty iv" False
        (gcmParamsValid r (encodeGcmParams "" "AD" 16))
      assertEqual "gcm bad tag" False
        (gcmParamsValid r (encodeGcmParams "0123456789ab" "AD" 7))
      assertEqual "gcm garbage" False (gcmParamsValid r "nope")
  -- sig-encoding: RAW, DER, or empty (DER default).
  assertEqual "ecdsa empty" (Just "RAW") (ecdsaEncodingOf "")
  assertEqual "ecdsa raw" (Just "RAW") (ecdsaEncodingOf "RAW")
  assertEqual "ecdsa der" (Just "DER") (ecdsaEncodingOf "DER")
  assertEqual "ecdsa bogus" Nothing (ecdsaEncodingOf "XX")
  -- iv-bytes: exactly the recipe width (AES-CBC: one 16-byte block).
  case cipherRecipeFor (MechanismId ckm_AES_CBC) of
    Nothing -> assertFailure "no AES-CBC cipher recipe"
    Just r -> do
      assertEqual "aes-cbc iv width" 16 (crIvBytes r)
      assertEqual "iv exact" True
        (cipherParamsValid r (BS.replicate 16 0))
      assertEqual "iv short" False
        (cipherParamsValid r (BS.replicate 15 0))
