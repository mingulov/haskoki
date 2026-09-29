{- | OpenSSL 4 engine tests.

Known-answer vectors for SHA-256 (FIPS 180-4),
HMAC-SHA-256 (RFC 4231 case 1), AES-256-CBC (NIST SP 800-38A F.2.5),
and ECDSA P-256/SHA-256 (fixed vector generated with the system
openssl CLI, verified there before embedding). All oracles are
independent of synthetic-engine outputs.

Also: capability-miss rejection without silent fallback (including a
guard-before-native probe on a closed backend), explicit RAW-vs-DER
signature encodings with no silent conversion, private-context
isolation, and shim-hygiene assertions.
-}
{-# LANGUAGE OverloadedStrings #-}
module OpenSSLSpec (spec) where

import Data.Bits ((.&.), shiftL, xor)
import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import Data.Char (digitToInt, isHexDigit)
import Data.List (isInfixOf, stripPrefix, tails)
import qualified Data.Set as Set
import System.Directory (doesFileExist)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertBool, assertEqual, assertFailure, testCase)

import Data.Word (Word32)
import Haskoki.Engine.Backend
  ( AeadSpec (..)
  , BackendCaps (..)
  , BackendEnv
  , BackendError (..)
  , CipherCaps (..)
  , CipherSpec (..)
  , CryptoBackend (..)
  , DigestAlg (..)
  , DigestCaps (..)
  , EcdhSpec (..)
  , DhSpec (..)
  , EcSpec (..)
  , EngineResult (..)
  , KemCaps (..)
  , KemSpec (..)
  , KeyGenSpec (..)
  , KeyMaterial (..)
  , KdfCaps (..)
  , MacCaps (..)
  , MacSpec (..)
  , OaepParams (..)
  , PqcKemAlg (..)
  , PqcSigAlg (..)
  , RsaCipherParams (..)
  , PssParams (..)
  , SigCaps (..)
  , SigSpec (..)
  , generateRandomMaxBytes
  , seedRandomMaxBytes
  )
import Haskoki.Der (dhParamsDer, dhParamsDerQ, dhPkcs8Fields, dhSpkiFields, integerToBE, mldsaPkcs8Fields, mldsaPrivateDer, mldsaSpkiFields, mlkemOidOfCkp, mlkemPkcs8Fields, mlkemPublicDer, mlkemSpkiFields, montgomeryPkcs8Fields, montgomeryPrivateDer, montgomerySpkiFields, rsaSpkiFields, slhdsaPkcs8Fields, slhdsaSpkiFields)
import Haskoki.Engine.Driver (cipherSpecFor)
import Haskoki.Engine.OpenSSL4 (OpenSSL4 (..))
import Haskoki.Recipe.Cipher (encodeCtrParams)
import Haskoki.Registry (MechanismId (..))
import Haskoki.Types (EngineResourceId (..))

spec :: TestTree
spec = testGroup "openssl4 engine"
  [ testCase "sha256 known answers (FIPS 180-4)" caseSha256Kat
  , testCase "sha256 multipart equals one-shot" caseSha256Multipart
  , testCase "Digest KATs (FIPS/RFC/RIPEMD)" caseDigestKats
  , testCase "Digest multipart equals one-shot" caseSha384Multipart
  , testCase "hmac-sha256 known answer (RFC 4231)" caseHmacKat
  , testCase "HMAC KATs (RFC/hashlib)" caseHmacKats
  , testCase "HMAC-GENERAL truncation (real)" caseHmacGeneral
  , testCase "hmac verify roundtrip and tamper" caseHmacVerify
  , testCase "aes-256-cbc known answer (SP 800-38A)" caseAesKat
  , testCase "aes-256-cbc roundtrip and bad lengths" caseAesRoundtrip
  , testCase "Block-cipher KATs (NIST/RFC/CLI)" caseCipherKats
  , testCase "aes-cts known answers (ACVP CBC-CS1)" caseAesCts
  , testCase "aes cfb/ofb known answers (ACVP)" caseAesCfbOfb
  , testCase "aes-kw/kwp known answers (ACVP)" caseAesWrapKwp
  , testCase "aes-xts known answers (ACVP)" caseAesXts
  , testCase "RSA v1.5 KATs (CLI vectors)" caseRsaKats
  , testCase "RSA-PSS interop (CLI vector)" caseRsaPssVectors
  , testCase "RSA-OAEP interop (CLI vectors)" caseRsaOaepVectors
  , testCase "RSA PKCS#1 v1.5 interop (CLI vector)" caseRsaPkcs1Vectors
  , testCase "RSA-X.509 interop (CLI vectors)" caseRsaX509Vectors
  , testCase "RSA-X9.31 interop (CLI vectors)" caseRsaX931Vectors
  , testCase "Poly1305 KAT (CLI + pyca vector)" casePoly1305Vector
  , testCase "ecdsa fixed-vector verify (DER and RAW)" caseEcdsaKat
  , testCase "ecdsa sign/verify roundtrip, both encodings" caseEcdsaRoundtrip
  , testCase "ECDSA curves/digests/raw (CLI vectors)" caseEcdsaCurvesVectors
  , testCase "ECDSA raw truncates overlong digests (SEC1)" caseEcdsaRawTruncate
  , testCase "ECDSA point-at-infinity rejects as mismatch" caseEcdsaInfinity
  , testCase "ECDSA odd-length raw sig mismatches" caseEcdsaOddSig
  , testCase "ECDSA off-curve keys refused typed" caseEcdsaOffCurve
  , testCase "DSA wycheproof KAT + roundtrips (q224/q256)" caseDsa
  , testCase "DSA paramgen + keygen mint usable pairs" caseDsaKeygen
  , testCase "EdDSA wycheproof KAT + roundtrips (Ed25519/Ed448)" caseEddsa
  , testCase "EdDSA keygen mints usable pairs" caseRealEddsaKeygen
  , testCase "ML-DSA wycheproof KAT + roundtrips (44/65/87)" caseMldsa
  , testCase "ML-DSA keygen mints usable pairs" caseRealMldsaKeygen
  , testCase "SLH-DSA ACVP KAT + roundtrips (12 sets)" caseSlhdsa
  , testCase "SLH-DSA keygen mints usable pairs" caseRealSlhdsaKeygen
  , testCase "ML-KEM wycheproof KAT + roundtrips (512/768/1024)" caseMlkem
  , testCase "ML-KEM keygen mints usable pairs" caseRealMlkemKeygen
  , testCase "ECDH agreement KATs (CLI vectors)" caseEcdhVectors
  , testCase "XDH agreement KATs (CLI + wycheproof tc1)" caseXdhVectors
  , testCase "Montgomery keygen mints agreeing pairs" caseRealMontgomeryKeygen
  , testCase "DH agreement KAT (CLI vectors)" caseDhAgree
  , testCase "DH keygen mints agreeing pairs" caseDhKeygen
  , testCase "raw-vs-der encodings never convert silently" caseRawVsDer
  , testCase "Symmetric keygen (fresh random bytes)" caseSymKeygen
  , testCase "RSA keygen mints DER halves in bounds" caseRsaKeygen
  , testCase "AES-GCM matches the pinned vector and round-trips" caseAeadReal
  , testCase "AES-GCM empty plaintext with AAD round-trips (tc92)" caseAeadEmptyPlaintext
  , testCase "AES-CCM wycheproof KATs seal and open" caseAeadCcmReal
  , testCase "ChaCha20 matches RFC 8439 2.4.2 (counter 1)" caseChachaReal
  , testCase "ChaCha20-Poly1305 matches RFC 8439 2.8.2" caseChachaPolyReal
  , testCase "Random bytes (fresh DRBG output)" caseRandomBytes
  , testCase "seedRandom mixes, randomBytes unaffected" caseSeedRandomMix
  , testCase "Seed entropy estimate pinned at 0.0" caseSeedEntropyHonesty
  , testCase "OpenSSL reseed never replays (scope pin)" caseSeedNoReplay
  , testCase "unsupported algs rejected without fallback" caseUnsupported
  , testCase "guard runs before any native call" caseGuardBeforeNative
  , testCase "capability report is exactly the supported set" caseCaps
  , testCase "private contexts are isolated" caseIsolation
  , testCase "shim has no pkcs11 provider or global cleanup" caseShimHygiene
  , testCase "invalid inputs fail typed, never crash" caseInvalidInputs
  ]

-- ---------------------------------------------------------------------------
-- Helpers
-- ---------------------------------------------------------------------------

-- | Decode a hex string (whitespace-tolerant).
hex :: String -> ByteString
hex s =
  let h = filter isHexDigit s
  in BS.pack (go h)
  where
    go [] = []
    go (a:b:rest) =
      fromIntegral (digitToInt a * 16 + digitToInt b) : go rest
    go [_] = error "hex: odd digit count"

withBackend :: (BackendEnv OpenSSL4 -> IO ()) -> IO ()
withBackend action = do
  r <- openBackend "provider=default" :: IO (EngineResult (BackendEnv OpenSSL4))
  case r of
    EngineFail err -> assertFailure ("openBackend failed: " ++ show err)
    EngineOk env -> action env >> closeBackend env

expectOk :: (Eq a, Show a) => String -> EngineResult a -> IO a
expectOk label r = case r of
  EngineOk a -> pure a
  EngineFail err -> assertFailure (label ++ ": expected EngineOk, got " ++ show err)

expectUnsupported :: Show a => String -> EngineResult a -> IO ()
expectUnsupported label r = case r of
  EngineFail (BackendUnsupported _ _) -> pure ()
  other -> assertFailure (label ++ ": expected BackendUnsupported, got " ++ show other)

expectAuthFailed :: Show a => String -> EngineResult a -> IO ()
expectAuthFailed label r = case r of
  EngineFail (BackendAuthFailed _) -> pure ()
  other -> assertFailure (label ++ ": expected BackendAuthFailed, got " ++ show other)

expectBadParam :: Show a => String -> EngineResult a -> IO ()
expectBadParam label r = case r of
  EngineFail (BackendBadParam _ _) -> pure ()
  other -> assertFailure (label ++ ": expected BackendBadParam, got " ++ show other)

expectBadKey :: Show a => String -> EngineResult a -> IO ()
expectBadKey label r = case r of
  EngineFail (BackendBadKey _ _) -> pure ()
  other -> assertFailure (label ++ ": expected BackendBadKey, got " ++ show other)

expectMechParamInvalid :: Show a => String -> EngineResult a -> IO ()
expectMechParamInvalid label r = case r of
  EngineFail (BackendMechParamInvalid _ _) -> pure ()
  other -> assertFailure (label ++ ": expected BackendMechParamInvalid, got " ++ show other)

expectNative :: Show a => String -> EngineResult a -> IO ()
expectNative label r = case r of
  EngineFail (BackendNative _ _ _) -> pure ()
  other -> assertFailure (label ++ ": expected BackendNative, got " ++ show other)

-- ---------------------------------------------------------------------------
-- Known-answer fixtures (independent oracles, see module header)
-- ---------------------------------------------------------------------------

-- ACVP-AES-CBC-CS1-1.0 encrypt vectors (prompt + expectedResults).
-- PKCS#11 names no CS variant for CKM_AES_CTS, so the module
-- implements CS1 (NIST SP 800-38A canonical first variant) and the
-- oracle auto-detects it; CS2/CS3 legs skip by detector design.
cts128Key64, cts128Iv64, cts128Pt64, cts128Ct64 :: ByteString
cts128Key64 = hex "D08FF477651FE9C084F20B2FFE50849B"
cts128Iv64 = hex "5A2623FC47B3F0D88C641AFC0DE45967"
cts128Pt64 = hex $ concat
  [ "28DE99791E5BA3329AF0C1E66DE07E1CE117A6211390F0F49F4157EBE58BC94"
  , "E4A88DD8B003A7E77B1070855138902DBDDF1BBC79FCF23056A9AB49DD25539A2"
  ]
cts128Ct64 = hex $ concat
  [ "247D046CBEA8A6A76CC9EFA0564559C19BC39869BDAFB9350ED5995469B705C13"
  , "177B7397625FD1A5B2FDFABCC9AEC131C7766F0081024F9718E781B491580E9"
  ]
cts128Key156, cts128Iv156, cts128Pt156, cts128Ct156 :: ByteString
cts128Key156 = hex "D616101E6BA31CF80E62A6EC8FC74F6F"
cts128Iv156 = hex "7E1E4E5E1A29465BF5987E5020DDE649"
cts128Pt156 = hex $ concat
  [ "25E5E1339994FD97A82CFE9B3297E52A64EE0D8914EA206052E7F217C0EF88F3"
  , "33B1E705074B38E4A025098B036EE0017A66DB17BA82210DEAE97ED1789DBCB2B"
  , "8020A12985F914006C80C35F70B4AD1B96BB47DA140F63DC48065998B3FACAC5A"
  , "01964D40996C2FE47D58B1C0E58D50830A11244917B34F504AAC058F75BD5E79CC"
  , "1B855BCDDBCA90FE94548F46877186F40F499E25797686F21B1B"
  ]
cts128Ct156 = hex $ concat
  [ "D751512C2C7548A71DAA70FDABA2A30F15EB09DF75D398A03E8CDE6F80FBE3335D"
  , "B3C98EF4188692E03BF99FF3BFFBF6FA256EE4C06B936DCE72A553FD2D6358DC39"
  , "392CD84A84F057CF77F834DD157F98F97A79187C883F6C020EE2EEA495A91EB272C"
  , "1308C19ED7402198E6FD02384F53DDDA839D55C902E8E5C01FF3B66A0FED0987D2"
  , "1834A7F36A49BC32452B2DBEF92EF40FA4BD25122B39E58"
  ]
cts192Key32, cts192Iv32, cts192Pt32, cts192Ct32 :: ByteString
cts192Key32 = hex "851ADF39D5CA81EB5ABD6043766DA706C42E3ABB74ED754E"
cts192Iv32 = hex "877FA72ED20AE32EE57BE60E86F5B5C6"
cts192Pt32 = hex $ concat
  [ "87EAA4FEAEC9803DA1B7D4F39B4146C23A1C1C47596A198A7994D80732567E59" ]
cts192Ct32 = hex $ concat
  [ "678D222A3E661C726C54B0877115921B319D2639AB00A23CC03B6A9D034EC225" ]
cts192Key57, cts192Iv57, cts192Pt57, cts192Ct57 :: ByteString
cts192Key57 = hex "000000000000000000000000000000000000000000000000"
cts192Iv57 = hex "00000000000000000000000000000000"
cts192Pt57 = hex $ concat
  [ "1B077A6AF4B7F98229DE786D7516B63900000000000000000000000000000000"
  , "00000000000000000000000000000000000000000000000000"
  ]
cts192Ct57 = hex $ concat
  [ "275CFC0413D8CCB70513C3859B1D0F729F88A422F49262C8B0B54CFD7C95DD5E2"
  , "4137195A73064E6EDB3EC9A5446C99351A26B06CF7DC930E7"
  ]
cts256Key66, cts256Iv66, cts256Pt66, cts256Ct66 :: ByteString
cts256Key66 = hex "8E6635BB59960919CDD8BAA3DEF14D7AC38D86882539A5CCAF9FE27B3B6D9C78"
cts256Iv66 = hex "BFBD702277C2FC416FB27656A011B6A2"
cts256Pt66 = hex $ concat
  [ "8E1B6C9FCCCCC84546955C1C8FACE0522DB2C43D8A44BEFA06028722DC50AF29F4"
  , "494FBE437A2D87CA10CDE334ABCE36C1BECBEA9791C2DDDAB01AFA539355137890"
  ]
cts256Ct66 = hex $ concat
  [ "3CEA9005FCA1DEEFDC800A271C06868A2068B0145084B8C1F400B8418C2AC38E20C"
  , "B26B674FB629DF542EC152CA36998494514902C77AB5E620C0517B0E53E7210F1"
  ]
cts256Key19, cts256Iv19, cts256Pt19, cts256Ct19 :: ByteString
cts256Key19 = hex "2A88FED687FF2FC5E920DD98100DB031057A847758A12FF5D1E63579CE21C0A4"
cts256Iv19 = hex "460D42F6C44BF495DFCB7D6855C60F0A"
cts256Pt19 = hex "E325A505A54F7CCB859B98F440C67B14444B89"
cts256Ct19 = hex "8752AD80462421DC5E5ECA1EFAA9790E4B398A"

-- ACVP-AES-KW-1.0 / ACVP-AES-KWP-1.0 encrypt vectors
-- (internalProjection.json, kwCipher=cipher, direction=encrypt).
-- KW legs: 16B minimal + 72B multiblock per width; KWP legs: 1B
-- minimal + 269B ragged per width. No IV (empty-IV, ECB shape);
-- output expands by the 8-byte wrap IV.
kw128_16_key, kw128_16_pt, kw128_16_ct :: ByteString
kw128_16_key = hex "8F684992A8BCB568DDA90ECF82D0EDE7"
kw128_16_pt = hex "E41B0CC0CB58B9A4EDBCC6057748A1CF"
kw128_16_ct = hex "CA31B1B6FA7C9C1152524421924555EDB25AC702D73037CD"
kw128_72_key, kw128_72_pt, kw128_72_ct :: ByteString
kw128_72_key = hex "A51BFEF0E23F74C6EE45E50E52D52159"
kw128_72_pt = hex $ concat
  [ "604A42E9A00001C004351C1BF84BBB35D1C47416E6B0DA4C47D8C2F9C0DEE578"
  , "3536D11AE5957582EA8D6FB98C08BA439DE12EE0A7E8093165277E1683EC4E73EFA924B28E591700"
  ]
kw128_72_ct = hex $ concat
  [ "F83C0E64F45E609F399DD66A31F830BC6DFBCBF60CBC30507AB370EA64D371B1"
  , "493C3F1329DFBBA05FF7DA4D920A56B2340B5C92301B15E103717A6FE674654376336FBAC0C563CF1FB6CDC02353E7D7"
  ]
kw192_16_key, kw192_16_pt, kw192_16_ct :: ByteString
kw192_16_key = hex "DAA150E331CA487709620A9E62E06FFD16905801B99028E6"
kw192_16_pt = hex "0F369E5B9D2DD76F9457813DB1E76DFB"
kw192_16_ct = hex "319A65CE21EECE1325955A27191C917EB806EF0D1D6B8FE1"
kw192_72_key, kw192_72_pt, kw192_72_ct :: ByteString
kw192_72_key = hex "D616A4FA0FAAB6C8180F2C608173B897EDF98668B502D45C"
kw192_72_pt = hex $ concat
  [ "1FE4625EBDE2E2F36A9BC9E0845D38184619EC67BCD3DF26912F6F923BFD1A000A1B1CE72DD82CBEB83119BDEDAD4D7F662396BC293D3D3BCB8F36E9A09A258359B78DD1DD9F3BDD"
  ]
kw192_72_ct = hex $ concat
  [ "4482CD60BA9F9AA30B60897E2F3E821284F4E3971C9B72E4DB2B445576D25EF815E1B4BA3914EFDC55AA31A41878DBB3CE8F4776BB5371ECF6BE5C9EC80B2E4C9177DE28F202F811B0788E10E8C47299"
  ]
kw256_16_key, kw256_16_pt, kw256_16_ct :: ByteString
kw256_16_key = hex "CEC66703B9DEC70887BE1C30D4DB1CCFA7A0B24906280B87FA078BAB1DB4B097"
kw256_16_pt = hex "5207914442601FEDD22F274C17975B27"
kw256_16_ct = hex "C949844B62EA0B68250687291E4EBA6E3FA2693B7018E3B6"
kw256_72_key, kw256_72_pt, kw256_72_ct :: ByteString
kw256_72_key = hex "D6CAEB95C7DFC07392DB74BD6E37433B9DE1ECF68192B58678BB020C709C391E"
kw256_72_pt = hex $ concat
  [ "9D918A3A7D3F629DFAC5EA0ED8590A31C7F90F5EFD00165C2758B0773C7F4F0E30BA2937D911BCEB9AE3F3224BFC0A5EA9EAA7DCBA8D97C7C9644B392AFD81EEE8350BE2B7B41C6F"
  ]
kw256_72_ct = hex $ concat
  [ "6115034CC3CCC8ADE9C88BB32887144F21D5E7B72F32A8E891D734D29901FC9E4F1A8AA2B4C91EFA4A3D4D6DB798DC5902774A8E2A5AC5ED664C08BA1F55FAA02BCC15C681A12CD078D2AA409C9B6E74"
  ]
kwp128_1_key, kwp128_1_pt, kwp128_1_ct :: ByteString
kwp128_1_key = hex "045779F345ECF100480481C9A2FB7219"
kwp128_1_pt = hex "f0"
kwp128_1_ct = hex "867E3EDFC4B327C6E01072E95DA7E071"
kwp128_269_key, kwp128_269_pt, kwp128_269_ct :: ByteString
kwp128_269_key = hex "D953348EC9BDB24EF56DFE62C3C10750"
kwp128_269_pt = hex $ concat
  [ "4B69C751243B1F9AABEDCD94552644F35F66525CF58DE694B7F93E64C8D21ABA9DC7413E4C53EDC4524738F74C40B14871E94140B9EC598DA714A5110071E2E3E519D5076EB6DCA1A70B484F1A8DA85C0B3ED6ABB5FFD472CFB0F429F494D09A965385F49CBC864794F7408D5F283E9C3E99A6D00C78376A0E71C4F5FE7198E799A7775829E7F6B10FE224ED6AE2E493A5F39B8D7C69420EACAFDB926E962AB8E4AA6F43BBE38FD926223A4F87E319E904328B292A7D9108EB333CB9C01CD44931ABD183CBE9C6311CC60A0D722E42E9689CAF42DF5C64B52E3B2C8215ACA03030AC7DC9CC8286B4756B858F32C04417B55165614D04F5AF759D06529D3B9DA2553DCEB645F73ACEFEFD46D50B"
  ]
kwp128_269_ct = hex $ concat
  [ "3EC7F5257C7BA8EDFC13CBEB3468226B94471C50F5C7B0DDB565209D3F3A81EA6D6A7C53074C3CEA94FAD159B2C1F6AE736D1853377F67135EFEF4A08E882FAC9F4846B31E92709D4D10E69F7CF9B9C8057C1ED4E758EFFE0C76EA85658EC1CC29C13682F194937083C60C5F9E72154089735E19AFB8CAB86E4232ACB4D1C91C54AEACDE5AFB1A9FDB0537FC6FF968227B9BA23BACC7813C9D40032A40908577A3C33550A7E20BEC9F85F5836936A1ED6F9AFB99813E035898A6D14146956697256A2B1DD4AE90B9D496C44DC848D5364C180CDC160C2A047B479C4D320912D64D8578C2EDA56A01CD05DB3C2137D19C30293526BE90230FF5546B560F9C62D541C75B8D78BDF4B1E4985452067259D4B92600EBC68814C0"
  ]
kwp192_1_key, kwp192_1_pt, kwp192_1_ct :: ByteString
kwp192_1_key = hex "50037744E6DC3F21729497550A0D277858188AD5584AC489"
kwp192_1_pt = hex "1D"
kwp192_1_ct = hex "B3EAC3B55425309A94EDBB4D9AF45894"
kwp192_269_key, kwp192_269_pt, kwp192_269_ct :: ByteString
kwp192_269_key = hex "5165C133705476947523330CDE4C734561E9AD3387D0F599"
kwp192_269_pt = hex $ concat
  [ "A220A41F0E30A7193A272C6065AA21BCEAFE1C39981288403C0BF255938231BA226562089B3F155ED6201E5A577003DAF9700218D60EC104293F5E238F7D39598283D169841B2DEC16F2485A17B17F9A2F81D3CCDBB33EF3CFE624C82B2C511E7A350CD70B335BCD3DDECB140290EB4D088A50E09CB38F8E5ADC9CE0E86BCAE2074AEA02FE88257F626F806A4199D06BC70C33F60E586864380B5F30B2BE3CBD480DADD2FCB2593C805E390517C899BA0D4F9E252813EFB51DE6B558C4A5DE9B749832DB53DDBB65325C09FE0E864BEE6324D69159B1567BE801B0B7188B998A5C478B63B6FDDEE3E0F7D67F8FD8B6CD9ECEE45E2F3BE2FFFBE9D832C09C5D08DC99D6C453E9BD478205CC3BB1"
  ]
kwp192_269_ct = hex $ concat
  [ "3CEA6ED129FEEAF73E6BCA72D914B2C7D9397CD8A365DCB890115471C2FDE98DA527DA23D4860FE7D3F90EC2CA19AADFCAB53AAADD33B8A87750E995FAF90431227C912651D7FC2F462A893075909D57C453060EBC91E8DB5BC8F9745316CFEA184E3BB915C169992CE0C80D98805B02605199B29D3FB7FBDF2518D47FBA6EE8F194CE24224F2385D06CC94A1F72A1DBB0B2FFE4B2CA825021E781F7EF523FCB0BC98F8101AAC53FE50AB6E2B7A62D0F1F977948A048FF0712CCC425EFD41BAFBEBF7818A06A9E238F93B8D43B5012CD2976A6A5C188047D4D6A50E6B12DED906D9BCC5A4F9D3FFAFA0AD3DF0CD7AFCA4E113B9D7355437D38B40D5C1823C677DACDD1562F24F64ABDA4C5B38D0164C15FBB91A5BFEA4E0A"
  ]
kwp256_1_key, kwp256_1_pt, kwp256_1_ct :: ByteString
kwp256_1_key = hex "CBACADE82EFC97AD2EE38B19F955DBCB1178ADE01E78C30676FD27AAAAE9D8AE"
kwp256_1_pt = hex "C0"
kwp256_1_ct = hex "462A7E8D992594F6163BD7A24C0FE4E5"
kwp256_269_key, kwp256_269_pt, kwp256_269_ct :: ByteString
kwp256_269_key = hex "CE53CBA5CCF56762F664D3487D46CE30C88B14242E084173900C4189774FBB29"
kwp256_269_pt = hex $ concat
  [ "65A836920C1345356B77330B7A3F9D516CB801AB8E268B4CB32DBBB6DC7A5BECFB9F8D47E76DE387A383719306201EB4A35CB105AD6548F2EF1E00F09AE9B8DC0B3A2B99F341AD1DBEAF11D6197B6BB41D569F9456662727398188958BA236B5598A0F72D43C0A43F0086CD58C817378B48B92D19E12661AACFFD5FE849E252A849E588CF41F3FB0273DA7BD81D4260E7F0D33B1CDBA53B217039113ED328097C5EEA9B390F286E83D5F8BF2C47E1E3E13C3300536EB192E52E87F7A077C10B32F6B3CA0123AD2AF136A9DE6E9A59B977E9890FDE5B003028EBCEE62A29952DA4574985F159DD6A4C015B539EDA7EA404B211459565528C7CB513DE9DE93C5C9A38A8ED3E5E6B893F1E7530E78"
  ]
kwp256_269_ct = hex $ concat
  [ "9CF90C5CF0364383D94748245C6D727D058BD18CF35BFF30EF9249A6990526B83328EAA9E0462396EAEDF905696853A21909294C52D34DAD0DD9D49363B9082289DC15FF6D3AD9814877492BE56F292CF640FD85CFBD2D6D311942E2049126A6366E0E9303730B5537962372E8C66827B67F2CFA4995871320541A694E0F5DB3D4DA897023DBA6B9BAF289368339ECC56536E865BBF0AF059B88EA4D758F4F4AC758B3A2120C03A98F2E73DD29AD4436D8055FF596F46412CC9DE54245C0269BB9082D2017CC9672340AEEB4C74949B6C7112BC58242DF18B527DF7A12C5F3E32A7F6A382B022F1270FC76234D4BA1D0269378ED51D9A896437DF2F709EF285AF432D2DB047A202A4D087C4D96689D08333C240737B03D62"
  ]

-- ACVP-AES-XTS-2.0 encrypt vectors (prompt + expectedResults,
-- each cross-checked against the `cryptography` oracle before
-- hardcoding). One aligned (16B) + one ragged leg per width;
-- keys are double-width (data + tweak halves), tweak is the
-- 16-byte data-unit sequence number.
xts128_key, xts128_tweak, xts128_pt, xts128_ct :: ByteString
xts128_key = hex "8ACB99D1D215612314D6B262147343F23F1B1E8F34F1DCBD6D57200FAE54E8C4"
xts128_tweak = hex "bf0d3404d7bce2b4132d02e90a256ebf"
xts128_pt = hex "EA29098CB827A1DE9D69F5B47A500C34"
xts128_ct = hex "7A4CC60DE7997471AAB765348F08D935"
xts128_rag_key, xts128_rag_tweak, xts128_rag_pt, xts128_rag_ct :: ByteString
xts128_rag_key = hex "6FA0AE27860CB658B40A3D95666954442E418EE3E4565657DD08EDC69E20E5D2"
xts128_rag_tweak = hex "c7c71ac8a3f858145b9ba0e658491af7"
xts128_rag_pt = hex "316F416DD8828155AAFE1EFA50361D48613E073E1B4B66B00D86A908626157D3058DCB83B1B6833580AA2F4A0663DE87115027F5F4EB60FCF2F2235BB801"
xts128_rag_ct = hex "74FCCB3C6FA20BAE9D1FBA9525519A5AEBB0BD4F2803A40C4EC0D80FBE3D5ECF53EA3D8C7456D23B4FD7772C4BC44B06C0C7A533E53747A4CB94927D4572"
xts256_key, xts256_tweak, xts256_pt, xts256_ct :: ByteString
xts256_key = hex "9D9674635844373FBAC65EA8FEFCCF4BEDB7B1845C89DC1B28B343FDCD5DF7AF1C0A96EDEEAD069C6666B741153FA3F367AD7538F9615C348462115FE09DA571"
xts256_tweak = hex "eae1092e65f917efaf69e01740494551"
xts256_pt = hex "0873E8A1EF36F962EFAAE5B9BD617D39"
xts256_ct = hex "6EA0F22583C4C6397ADCAF702A08C27D"
xts256_rag_key, xts256_rag_tweak, xts256_rag_pt, xts256_rag_ct :: ByteString
xts256_rag_key = hex "DCF8C5F5AC2FF90719DF2DCBBEE159C53C44E80BCFA95C718C659C4E8F6FC0A4C85A9E3C16527E66BDD924C13EC8314987F0F3E89089007B34DC472B95B7E03E"
xts256_rag_tweak = hex "7eb2097b64cc3bccad39608427ecc1a5"
xts256_rag_pt = hex "A06B93F02AE1B52F2D7995D024914DD490320670AD610F5B4BC91E"
xts256_rag_ct = hex "87E96FCD94D73BA5E2CFE45A96BE469C2A13CE2F621CD76FC1C875"

-- ACVP-AES-CFB128/CFB8/CFB1/OFB-1.0 encrypt vectors (prompt +
-- expectedResults). One leg per mode x width; CFB1 adds sub-byte
-- payloadLen-10 legs with oracle-defined top-bits masking.
cfb128_128_key, cfb128_128_iv, cfb128_128_pt, cfb128_128_ct :: ByteString
cfb128_128_key = hex "8E5D75D976DB6983954B54C1A714E135"
cfb128_128_iv = hex "A610F1879CDD7B3D1267E51D55ACFE87"
cfb128_128_pt = hex $ concat
  [ "531F2B906CFFE6541BDDE16F267D7481A62DA1A6462525D1A05E878332971BF4D"
  , "60C9ACA2DA5B42F04BCFF9CAC0AE21D"
  ]
cfb128_128_ct = hex $ concat
  [ "04F436D93655427BB495029F789F72B597CCEBEC6FE927BF1B08FE29AC05CCCDE5"
  , "AED842AE89C8D858736C1772760FD2"
  ]
cfb128_192_key, cfb128_192_iv, cfb128_192_pt, cfb128_192_ct :: ByteString
cfb128_192_key = hex "D86D60ABA397596E00FC643E5CA178679F92127470514715"
cfb128_192_iv = hex "4B82C289E366F05F5F23E4D2B8E48ED2"
cfb128_192_pt = hex $ concat
  [ "31DA4A73E7BF25ADAB8778AD607F1B5DF733DB2A7C213AAA97CB91DD913A5A501A"
  , "C12ABEF450A2DB27E060964B103230"
  ]
cfb128_192_ct = hex $ concat
  [ "5325ED26C6695717E7813790CAB764F43C60C3B8882AC1F3DEB2FA5A4E1E784DFD"
  , "E4CB4BDAA8F500DD470AB08F71C312"
  ]
cfb128_256_key, cfb128_256_iv, cfb128_256_pt, cfb128_256_ct :: ByteString
cfb128_256_key = hex "193477C335697BA0FA61FDA15AE1E4BA9D0D76EE5EA4552EE5DD22759FFA2EEE"
cfb128_256_iv = hex "B335E95FCD2983A349165581C1A8E9A6"
cfb128_256_pt = hex $ concat
  [ "0F98CBBE70A5EB2A244703235869816B8CF57CF097F93EE4F2E8692193A0E8FE84"
  , "550ADC4C70B01AFD0EE79D8848164F"
  ]
cfb128_256_ct = hex $ concat
  [ "37D20635E92B613C7A36FFE827B4C74D75D5E2A92965C8850380F5E1340D8C17CF"
  , "98B53D98372AABA4C286D956DEC1F7"
  ]
cfb8_128_key, cfb8_128_iv, cfb8_128_pt, cfb8_128_ct :: ByteString
cfb8_128_key = hex "D8B5B55196BC7BA12C1A3F383D53055E"
cfb8_128_iv = hex "59866908DB5E9CBD8188E5BB11228E91"
cfb8_128_pt = hex "746C1B57DA68713B3826094A9FE85DC2680AC7C696457074DD44704D99D5E48B"
cfb8_128_ct = hex "4EE17694BBFC7EF4CE603CD14D5E8EBDF1AB7BD84F2A7C4E4E1577B81205DEDB"
cfb8_192_key, cfb8_192_iv, cfb8_192_pt, cfb8_192_ct :: ByteString
cfb8_192_key = hex "9A3E3FCE8BC21CCBE4893470234F48845BD1B4AE23B3BCF8"
cfb8_192_iv = hex "0419D52672D4C61B4924E09A5347C0EF"
cfb8_192_pt = hex "602562FEFB49745E2A185A3651AB98B9C8F8D92FCC2741AB23DCE4C7A6EB08F5"
cfb8_192_ct = hex "C5D1E776F3F428D592A3116A6993C10E0DB63737775D2A77200262A1EF8DDD21"
cfb8_256_key, cfb8_256_iv, cfb8_256_pt, cfb8_256_ct :: ByteString
cfb8_256_key = hex "880B1086E6326896D02DCE97C04DB55A10BD17F97F257374265FA3A1AED8495E"
cfb8_256_iv = hex "2306207DE21D456E1B4E2DD21419BC54"
cfb8_256_pt = hex "25E3EDD024537E3B009FA356926CCDBEEFDBAA5E77E23775DB34D9646D683673"
cfb8_256_ct = hex "267A52D8B3C6BE04FC16412A99682089CDD17328126A5DF6B3E78C4DE8F2B3CF"
cfb1_128_key, cfb1_128_iv :: ByteString
cfb1_128_key = hex "5ACB11FB4A72B089C492D6C8B3636E95"
cfb1_128_iv = hex "0E9BCCA0A1F1A840D0C9F6FB6FCD4B6E"
cfb1_192_key, cfb1_192_iv :: ByteString
cfb1_192_key = hex "5E763B08CE4A24E9059E134F8DB68A6500C847B4A1876ADE"
cfb1_192_iv = hex "F2AB1305D9D681A02DE6D6C0D9CC3E53"
cfb1_256_key, cfb1_256_iv :: ByteString
cfb1_256_key = hex "A2C614B71BE9F438C472A9DACB49865DE2516AE353AD0E7453E8731799DFC0A1"
cfb1_256_iv = hex "9FD31916DEC92DB8CBB390ABD3ADDA05"
cfb1_128b_key, cfb1_128b_iv :: ByteString
cfb1_128b_key = hex "CA8838F0F0E94106A9FED0120A79C2B3"
cfb1_128b_iv = hex "A6070E04A2DD5C1CA26B279E2EB5183C"
cfb1_192b_key, cfb1_192b_iv :: ByteString
cfb1_192b_key = hex "B33C80CCCB7E2D9C272E3052D7A1D300661A33357670403B"
cfb1_192b_iv = hex "52F67B2D4A2C21E9AB33BC8BF6E2D07C"
cfb1_256b_key, cfb1_256b_iv :: ByteString
cfb1_256b_key = hex "01416CB918CAD2CEF6AC40B2E2CACC0B976A91EC40902F9185B5622055FD9B3F"
cfb1_256b_iv = hex "1B263E429DA5F706A62DB54AC45CE040"
ofb_128_key, ofb_128_iv, ofb_128_pt, ofb_128_ct :: ByteString
ofb_128_key = hex "055B701A06741E45FF8F9A0AB72AD4C8"
ofb_128_iv = hex "D3B99DB990F923FF0C46A41D810B2763"
ofb_128_pt = hex $ concat
  [ "CD49B6830E22C3C08B5965175C21885F47C62E3A67CC558A3DABDB54BAAE58715D"
  , "003F096A6E293395D8E75BFE5BF1DAE455B80F9C32C90C5321F23755599872"
  ]
ofb_128_ct = hex $ concat
  [ "D0C883857DC4DE820D76E115A74274EFFBF3DD364E27EE57050BF161F5AAE2F498"
  , "31DCAD7F1E464728B59A9E59C655552D5D91219D8D88F320F4681925B8CAA8"
  ]
ofb_192_key, ofb_192_iv, ofb_192_pt, ofb_192_ct :: ByteString
ofb_192_key = hex "1737AC3C014C74E20F6254A71C9165D311AE21D2DDCF8F74"
ofb_192_iv = hex "F4BFF3A113C0C63732BEB6E77216EB9F"
ofb_192_pt = hex $ concat
  [ "18ADD7BF57AA00844759AFA1B468C81592D170A335DFE50A7D0D91729B32F8C7D8"
  , "60A5C96206B480058987019BE2E0A220BD04D69668D5BE773AC60B2A050ECE"
  ]
ofb_192_ct = hex $ concat
  [ "E7765838AF94B62C494C6E0C5D43E6D1BD6DCA82E8C90BCED23AA2FFF3B250E5F"
  , "9D86CE055EABD6951EED2B2E6901D1D0DDE9329F4ADC66D3B48906476713A34"
  ]
ofb_256_key, ofb_256_iv, ofb_256_pt, ofb_256_ct :: ByteString
ofb_256_key = hex "FAA7B060B20C10D6700D13718CA610223688BFD4D49C5CF5CA10992CD93F6494"
ofb_256_iv = hex "83922A2CC59B353517FE3965DAA9BBCF"
ofb_256_pt = hex $ concat
  [ "1355175F24941D4367FFC922900045B12A13A43E3ECE241206D5F4CF5078D5392F"
  , "A471D2573A35DAC7FDA3F8AF62CBBFE0E9A4AF79933984276F99596FE5410B"
  ]
ofb_256_ct = hex $ concat
  [ "56A0EAA8290D0DE9EF6C382E33327D108D04793AE3FE97933E5AF1F0A617C28E0"
  , "0C07BD84A498EF39C6C33668F044FB7C10C2F4383BE61F20212210025B90666"
  ]

-- FIPS 180-4 §B.1 / §B.2.
sha256Abc :: ByteString
sha256Abc = hex "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

sha256Empty :: ByteString
sha256Empty = hex "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

sha256Long :: ByteString
sha256Long = hex "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"

longMsg :: ByteString
longMsg = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"

-- RFC 4231 test case 1: key = 0x0b * 20, data = "Hi There".
hmacKey1 :: ByteString
hmacKey1 = BS.replicate 20 0x0b

hmacMsg1 :: ByteString
hmacMsg1 = "Hi There"

hmacOut1 :: ByteString
hmacOut1 = hex "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"

-- NIST SP 800-38A F.2.5 AES-256-CBC, first block.
aes256Key :: ByteString
aes256Key = hex "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"

aes256Iv :: ByteString
aes256Iv = hex "000102030405060708090a0b0c0d0e0f"

aes256Pt :: ByteString
aes256Pt = hex "6bc1bee22e409f96e93d7e117393172a"

aes256Ct :: ByteString
aes256Ct = hex "f58c4c04d6e5f1ba779eabfb5f7bfbd6"

-- NIST SP 800-38A F.1/F.2 AES rows (128/192 CBC+ECB, 256
-- ECB; 256 CBC is caseAesKat). Generated on the pinned 4.0.2 CLI,
-- cross-checked byte-identical on the system 3.5.5 CLI.
aes128Key :: ByteString
aes128Key = hex "2b7e151628aed2a6abf7158809cf4f3c"

aes192Key :: ByteString
aes192Key = hex "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"

aes128CbcCt, aes128EcbCt, aes192CbcCt, aes192EcbCt, aes256EcbCt :: ByteString
aes128CbcCt = hex "7649abac8119b246cee98e9b12e9197d"
aes128EcbCt = hex "3ad77bb40d7a3660a89ecaf32466ef97"
aes192CbcCt = hex "4f021db243bc633d7178183a9fa071e8"
aes192EcbCt = hex "bd334f1d6e45f25ff712a214571fa5cc"
aes256EcbCt = hex "f3eed1bdb5d2a03c064b5a7e3db181f8"

-- NIST SP 800-38A F.5 CTR rows (128/192/256): the shared
-- four-block plaintext and initial counter plus the per-width
-- ciphertexts, transcribed from the PDF and cross-checked with
-- Python cryptography.
ctrPt, ctrIcb :: ByteString
ctrPt = hex $ "6bc1bee22e409f96e93d7e117393172a"
  <> "ae2d8a571e03ac9c9eb76fac45af8e51"
  <> "30c81c46a35ce411e5fbc1191a0a52ef"
  <> "f69f2445df4f9b17ad2b417be66c3710"
ctrIcb = hex "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"

aes128CtrCt, aes192CtrCt, aes256CtrCt :: ByteString
aes128CtrCt = hex $ "874d6191b620e3261bef6864990db6ce"
  <> "9806f66b7970fdff8617187bb9fffdff"
  <> "5ae4df3edbd5d35e5b4f09020db03eab"
  <> "1e031dda2fbe03d1792170a0f3009cee"
aes192CtrCt = hex $ "1abc932417521ca24f2b0459fe7e6e0b"
  <> "090339ec0aa6faefd5ccc2c6f4ce8e94"
  <> "1e36b26bd1ebc670d1bd1d665620abf7"
  <> "4f78a7f6d29809585a97daec58c6b050"
aes256CtrCt = hex $ "601ec313775789a5b7a7f504bbf3d228"
  <> "f443e3ca4d62b59aca84e990cacaf5c5"
  <> "2b0930daa23de94ce87017ba2d84988d"
  <> "dfc9c58db67aada613c2dd08457941a6"

-- Triple-DES MMT row (K1 = K3, so the 24-byte key doubles
-- as the two-key expansion target): zero block -> 08d7b4fb629d0885;
-- CBC with the zero IV equals ECB. Agreed on both CLIs.
des3Key24 :: ByteString
des3Key24 = hex "0123456789abcdeffedcba98765432100123456789abcdef"

des3Key16 :: ByteString
des3Key16 = hex "0123456789abcdeffedcba9876543210"

des3Pt, des3Iv, des3Ct :: ByteString
des3Pt = hex "0000000000000000"
des3Iv = hex "0000000000000000"
des3Ct = hex "08d7b4fb629d0885"

-- ARIA/CAMELLIA rows (sequential key bytes, RFC-style
-- plaintext). Pinned 4.0.2 CLI, cross-checked byte-identical on the
-- system 3.5.5 CLI.
ariaPt, ariaIv :: ByteString
ariaPt = hex "00112233445566778899aabbccddeeff"
ariaIv = hex "000102030405060708090a0b0c0d0e0f"

ariaKey128, ariaKey192, ariaKey256 :: ByteString
ariaKey128 = hex "000102030405060708090a0b0c0d0e0f"
ariaKey192 = hex "000102030405060708090a0b0c0d0e0f1011121314151617"
ariaKey256 = hex "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"

aria128CbcCt, aria128EcbCt, aria192CbcCt, aria192EcbCt, aria256CbcCt, aria256EcbCt :: ByteString
aria128CbcCt = hex "d87ae512c018266fcd74ddf801efabf9"
aria128EcbCt = hex "d718fbd6ab644c739da95f3be6451778"
aria192CbcCt = hex "b22cdd3ca4ee4d8da19777c93d930eb9"
aria192EcbCt = hex "26449c1805dbe7aa25a468ce263a9e79"
aria256CbcCt = hex "06ad7356394a53e875c70ba8ab0d49d5"
aria256EcbCt = hex "f92bd7c79fb72e2f2b8f80c1972d24fc"

cam128CbcCt, cam128EcbCt, cam192CbcCt, cam192EcbCt, cam256CbcCt, cam256EcbCt :: ByteString
cam128CbcCt = hex "94887caa8b90cd132d9aa972db3e52bb"
cam128EcbCt = hex "77cf412067af8270613529149919546f"
cam192CbcCt = hex "a0a022e9de176eaaec0bcab1ad5f6e9d"
cam192EcbCt = hex "b22f3c36b72d31329eee8addc2906c68"
cam256CbcCt = hex "cd3f05325b834e2bd83510993ca53afb"
cam256EcbCt = hex "2edf1f3418d53b88841fc8985fb1ecf2"

-- CAMELLIA-CTR rows: RFC 5528 TV#1/#4/#7 (single block each;
-- counter block drives the 16-byte IV directly), verified under
-- the pinned 4.0.2 CLI before embedding; independent of this
-- backend's fetch path.
camCtrPt :: ByteString
camCtrPt = hex "53696e676c6520626c6f636b206d7367"

camCtr128Key, camCtr128Icb, camCtr128Ct :: ByteString
camCtr128Key = hex "ae6852f8121067cc4bf7a5765577f39e"
camCtr128Icb = hex "00000030000000000000000000000001"
camCtr128Ct = hex "d09dc29a8214619a20877c76db1f0b3f"

camCtr192Key, camCtr192Icb, camCtr192Ct :: ByteString
camCtr192Key = hex "16af5b145fc9f579c175f93e3bfb0eed863d06ccfdb78515"
camCtr192Icb = hex "0000004836733c147d6d93cb00000001"
camCtr192Ct = hex "2379399e8a8d2b2b16702fc78b9e9696"

camCtr256Key, camCtr256Icb, camCtr256Ct :: ByteString
camCtr256Key = hex "776beff2851db06f4c8a0542c8696f6c6a81af1eec96b4d37fc1d689e6c1c104"
camCtr256Icb = hex "00000060db5672c97aa8f0b200000001"
camCtr256Ct = hex "3401f9c8247effcebd6994714c1bbb11"

-- ECDSA P-256/SHA-256 fixed vector (system openssl CLI 3.5.5, Verified OK
-- there before embedding; independent of this backend).
ecMsg :: ByteString
ecMsg = hex "543037206563647361206b6174206d657373616765"

ecPrivDer :: ByteString
ecPrivDer = hex "308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b0201010420e9032e4f06ee6b5397252cfb48e73a8d3f7717d4024dd4cc5b98bbf041c11bb3a14403420004a348bab88ded75858acef31e9afa0ef8680ad8ec1196227b10083a630f029ecfc5503e37b76e2538f9ec2ceb6aa766cc7948071e6c39b9a93f0c54d5f7b12086"

ecPubDer :: ByteString
ecPubDer = hex "3059301306072a8648ce3d020106082a8648ce3d03010703420004a348bab88ded75858acef31e9afa0ef8680ad8ec1196227b10083a630f029ecfc5503e37b76e2538f9ec2ceb6aa766cc7948071e6c39b9a93f0c54d5f7b12086"

ecSigDer :: ByteString
ecSigDer = hex "3045022100debdbb00072c928d38bf43791d32f0eefe8a562d8444869adabdf77820cbed49022063cc0a678a74c3e006c7387907210825f12920ff5f15b96709291e48b84ddc21"

ecSigRaw :: ByteString
ecSigRaw = hex "debdbb00072c928d38bf43791d32f0eefe8a562d8444869adabdf77820cbed4963cc0a678a74c3e006c7387907210825f12920ff5f15b96709291e48b84ddc21"

-- RSA-2048 fixed vector (pinned 4.0.2 CLI genpkey; PKCS#8 +
-- SPKI DER). The SHA-256 signature is `dgst -sha256 -sign` output and
-- the raw signature is `pkeyutl -sign` (PKCS#1 block type 1) output,
-- both Verified OK on the CLI before embedding; independent of this
-- backend.
rsaPrivDer :: ByteString
rsaPrivDer = hex $ concat
  [ "308204bc020100300d06092a864886f70d0101010500048204a6308204a20201"
  , "000282010100c926e2edfdfd3886e1b3cc75c224421b0fc2deeb1f780943d23a"
  , "39698d4f6944cffda2957fb8aa9f70e410231e4fb89dfe370fce96515fcb2093"
  , "d512c4603632a6b83d2c42144a53138113ba96442c63311f8b8fc6b2b4424831"
  , "979b94f5e2929a0c2c9f2b4b17f713b394546faaa1c0e65cb87911cb244af772"
  , "5b894f6f27d059d6e9e9c761032577912bfc1eccac593d0df649ec03e2fc13fe"
  , "723c268c1ecfa63c80b3dcf04ee18c758189567f753fa6f936f926347632f18e"
  , "4d4b1252539235ae4929f72b990ebb78db7159f6779cffe23e96ca1908babc51"
  , "34c424688d37eadaf126bd94fd108ac4415e4503ff2e6d125cd5c762a3fbe6ec"
  , "ae8e2a76011102030100010282010009c28c237bcdc9ecba7e0ebb3e7da3a2fc"
  , "416a6f4a5e38c5dc891470cf89553c6062a83d3c7e9d71c1c8a1135124d15a82"
  , "23920de62b81dc416306e54397befd776b2c55adc99dff18accc4423072107b9"
  , "9214239862a29e2e3250cebcdc2edf89dfb2191180d1e37c465bf9ba56d34520"
  , "b04a479e92469b2815398588b006248edc33d6ca1867543f7ae188e38c2d6b05"
  , "34711b1320e3ba0bba97d39b36a581927deb148d0deef6ea2627a2a91fe8b408"
  , "1062e726ed764788eec572b38bc86ad158a1d04b1c35aca6ae1270e05c137c2d"
  , "38d9762cbe4b06d07c87f038608a96b9efac090a08175207eaf2393cd0a2d301"
  , "9dd5102bb1a21554dd416f6a316f0102818100fa935980bc731d39e87d225964"
  , "017bfefcd827a3d43126fa1426efb9dcfb8e693030dd4aadeaa9b977611b747e"
  , "7993f5b78e9358e58b2442cdb8f038d466cfc28d0af579e12adc781abdbedc97"
  , "7d1b5a2bd547506441e622ff73bba38c7097d464adf8169e8df412a7a5d65c4b"
  , "405884590388ee4625c3f2e2e7679b963cb48102818100cd81a378890e9c224c"
  , "660acd28f0edd17b17f1cf0068a6185d13bbef2383e303258ccb79ad37899344"
  , "7126397e57e8e19e26ed0b6e20d338ab4d092548374b5e3e909dcf59416e46eb"
  , "0f7e1e5efe01cd4ae55f49856430cdb230bb9861b9fdd72b5f6c265da17a6f78"
  , "f3f5acd3b9a30cdd46bc279b7fa72679a4b4b1b361c49102818048d9fa55b174"
  , "8e74bda154114540213adb6c44ea1ed14391c5b62450976d13d4854c4faa5cb2"
  , "3332570106a871f50b0d8f9686447c485dfc862f54b85118ab22d73aee6fc705"
  , "5d201636407d8615bb9415d6666b7b1aa5bc5b24dcd30a0bda38c824c4525f3a"
  , "ca517a287f104a58a4e3a5b59f641744f799705af3068b418f0102818015a7c5"
  , "8c1c15380abd363b8926f94c76389c6b54bedc4834650a81514fd2c4073edbb9"
  , "4d571d7517d9ac7ab4b0459f3ab729aeecf76bea161ca6ff81b83c6b6ac0f908"
  , "482345abd3394de6a258ac379064860b267a31f69a965e60464c7606f3b79454"
  , "972e62a7be3b66a9cace7ccf5bb9ad8c8237f699ac8a40faf186cf94a1028180"
  , "4a51ff546c065beff7c5e653db4011aa3989470826473c6afb0eca603fd4109a"
  , "6d731fac84d8d1c0647f1a2d8e68246449eb18ef6ef433f654785f9713798c85"
  , "4a10352d4db6aa28fb9ec13d0772dec7ebd1b1c3faa5979672bad3c6be7c45e0"
  , "82b79fcbc58b7d39abed53870ec5efb62b66c52da906950afcd7117007b99f7d"
  ]

rsaPubDer :: ByteString
rsaPubDer = hex $ concat
  [ "30820122300d06092a864886f70d01010105000382010f003082010a02820101"
  , "00c926e2edfdfd3886e1b3cc75c224421b0fc2deeb1f780943d23a39698d4f69"
  , "44cffda2957fb8aa9f70e410231e4fb89dfe370fce96515fcb2093d512c46036"
  , "32a6b83d2c42144a53138113ba96442c63311f8b8fc6b2b4424831979b94f5e2"
  , "929a0c2c9f2b4b17f713b394546faaa1c0e65cb87911cb244af7725b894f6f27"
  , "d059d6e9e9c761032577912bfc1eccac593d0df649ec03e2fc13fe723c268c1e"
  , "cfa63c80b3dcf04ee18c758189567f753fa6f936f926347632f18e4d4b125253"
  , "9235ae4929f72b990ebb78db7159f6779cffe23e96ca1908babc5134c424688d"
  , "37eadaf126bd94fd108ac4415e4503ff2e6d125cd5c762a3fbe6ecae8e2a7601"
  , "110203010001"
  ]

rsaMsg :: ByteString
rsaMsg = "T16 S7 RSA PKCS#1 v1.5 KAT message"

rsaSig256 :: ByteString
rsaSig256 = hex $ concat
  [ "1a688970cd06fcbd04ca437952ea041cb952a0022698c4d77358cafccaf2490f"
  , "ddaf1b854bc40d854710d203e689b1f1422ae7669ea9ae8b5bac74e8762e3eae"
  , "bc916f66b052e369753b7fa27f44d0f5a762481a19ad4c078b11fecc66ce5b70"
  , "28152c1fbc4d750f81e58d3c9763f000b2a7cd10291127c2e85a8aa5ae6b31cf"
  , "286197885eea82b768e12588e2e386aa7ff1ecdcf3746480d73335e716ca779b"
  , "3bf45729506c742d3b860d5f6473f54a2afa6e0c6dae9bebeed2874e3f7c698a"
  , "c997d4af99317d4361e5e80d538a7551ada520d9ec4f8a90ecbc88f87866888c"
  , "cac430db724c03347f2470b65f9db3dcd42bdbd3bf00fce8dd311f0230e5ca96"
  ]

rsaRawMsg :: ByteString
rsaRawMsg = "raw-rsa-pkcs1-input"

rsaRawSig :: ByteString
rsaRawSig = hex $ concat
  [ "28d1e96dee36cacc910b992a1205c1c6328e224e15cde51a2e5c48f96f2549a0"
  , "8702edd609d00f5597b35b81a9edfa67f7a2177e79b8785f046773e22c9b613b"
  , "9073a0ca88888dacd83486660c370b513810d0e262a2ece08bcd7f47be2fcd76"
  , "2231e521dd5adde4668143c5151b7d38c4ee2f4360c62c76d1d2c787a7eca502"
  , "3f991c6cd81d36778ec1d57006f6be5f08782559cc6b2bd35ae784d0742521b7"
  , "8a90020f082b07be789468f2861660053f2c2026dfb84ce193b6f53d2e67d040"
  , "dfe9a1cc352af6c8449daa5d0bd83e201e622bcb663cf3cb84bf491a45974142"
  , "6159d1f203f89db9f9e790b16837254f81f87bf59c4e55bdea4ac6de3b8a5ffc"
  ]

-- PSS/OAEP interop vectors (pinned 4.0.2 CLI, same RSA-2048
-- key as the v1.5 vectors). PSS is randomized, so the suite verifies
-- the CLI's bytes (proving interop) and roundtrips its own; OAEP
-- likewise. All three vectors were CLI-verified before embedding.
pssMsg :: ByteString
pssMsg = "T16 S8 RSA-PSS KAT message"

pssSig256 :: ByteString
pssSig256 = hex $ concat
  [ "a485e83b8a92370e6b770164476f3f8154f59aa95616100eb0d79d333d080a18"
  , "e346d063dc2600f91bad8ec68c55de62e6b4cce8478284ef8f6822d9f3e40355"
  , "2c658e40a67f6dc68e1d7075c4ee42fc021851809b264a6811859a462347f060"
  , "b219b7b4e42065146008062e78684d4dff08ba80c46b9243c6ed47bca6c8d766"
  , "bd97dd87577410690fd98bbef29c07a5a6f90044b967e04a736bb18b500ece12"
  , "1d175ebae0e64927af63753ff906df57cf99609794483f054b4e12874df6cbde"
  , "243e1cbb4796c1dc338686695aab96ca6f48015af476da7482055e2c969dfc46"
  , "7538fdffa5ed548c66ebd18413b565c967ea033a79fb8ca4fd69233851d5d3d7"
  ]

oaepMsg :: ByteString
oaepMsg = "oaep-secret-32-bytes-payload!!!!"

oaepCt256 :: ByteString
oaepCt256 = hex $ concat
  [ "c8487aa483b4807c96df59d7d7cba952026c0af0ae9b1e34bb2df9cf86990866"
  , "de54bed6a552bc48d9fc3460f3e72666206b154c1dd213a94cb9810cf2861f1b"
  , "413c03124cc51f3f049154887e9d704ebb1d3aebbd508529ce91c9a73eef04e0"
  , "0e701e7bad72f97714ecde22bcc491228f8ca831e7fb22a570747362eea7a204"
  , "054315fc13a1074c3221c8c125e2a8cd6f2c1636b7e012c0afbbef48681f076d"
  , "cbe2c2a894afe2a0a16bc7d4f0df9a329c395aee38cd05b771748b3647c2ded7"
  , "cce302721f6a674ef9c864682dfc3c7b0ab92ef00347435c7b2a55173fbae7c2"
  , "087096ad95fb3c77b495699fb8d8a51b212cd9197265f684eb834302ac09a8ea"
  ]

oaepCtLabel :: ByteString
oaepCtLabel = hex $ concat
  [ "8731edc179823659994212b26301adfff66b3f2371d79640d2b9ec4100d47e9c"
  , "e4c047373deefa92d8cca0000c26259d7471441b966e9e85d78215e96324e5ca"
  , "372639a789c4162108dcaa177ff26760f3f0b19dd0ae05fb2824819576eadc77"
  , "8219912a2cb5f4ee76ba2ad27a68b6f283636f1b04ca7dc87b2009ea41e4247a"
  , "48ba0615ce5f5fb6932bcca6aaed9ebd79d9b0ba7d40c4128bfcda1ee60fb718"
  , "da7c783d3d1bf59391eef1a6f30cd5be6c7d0e1fd32d7fbf57629e60ea43a250"
  , "de38228fb7cb7d016cd64710c4b9485cbb336abca3699e0f11ebde8c57889940"
  , "20a2a3e03dfb241ff23d76351f9bbdd6e7e292e02fdd6c19d967b4f904187e73"
  ]

-- PKCS#1 v1.5 interop vector (pinned 4.0.2 CLI, same RSA-2048 key
-- as the OAEP vectors): @pkeyutl -encrypt -pkeyopt
-- rsa_padding_mode:pkcs1@ over 'pkcs1Msg'. The CLI decrypted the
-- same bytes back before embedding.
pkcs1Msg :: ByteString
pkcs1Msg = "pkcs1-v15-secret-payload"

pkcs1Ct :: ByteString
pkcs1Ct = hex $ concat
  [ "95c544fce5a8a92aa7ce3e2cd4c3b8f1f73ef2bab790f7b47bd68b0f852e6390"
  , "59beca2d3d9c755880b5665f0b86384bd8fd993516f09a19e2ef47d526d781dc"
  , "a9f28eac278cb5ac6cd4582013f0b48e415a5ce8a8f1d4f6374fcd755a9c8239"
  , "f9c3df96be044a3fb21de404b0b4dae2981bfad77af50b763e290f5e4308e7ff"
  , "cc9e950f9d1cff829df9ca2d9a21b01472b7eaab505cf05771c5f22a2823690b"
  , "1c2c70892cb74fab75f105b83ff22f36a39023a41dd916190f8b3df30b9caf90"
  , "e7827d13d4672a3315f854598b385cdcceac5d1c0b486d5c6010d74489858a06"
  , "eeeeefebddf38af708eb71fbec554aa5c8f5f0163c6a9f470f8d8af53f7f7bf4"
  ]

-- X.509 raw-RSA interop vectors (host 3.5.5 CLI, same RSA-2048 key
-- as the v1.5 vectors; raw RSA is deterministic modular
-- exponentiation, so the bytes are version-independent). The
-- 32-byte message left-pads to the 256-byte block; the ciphertext
-- is `pkeyutl -encrypt -pkeyopt rsa_padding_mode:none` output and
-- the signature is the private-op output (`pkeyutl -decrypt` with
-- rsa_padding_mode:none — the CLI sign path refuses padding none).
-- Both were CLI roundtripped before embedding.
x509Msg :: ByteString
x509Msg = "x509-secret-32-bytes-payload!!!!"
x509Ct :: ByteString
x509Ct = hex $ concat
  [ "a7f6abc64915f4386b2e119279cd401812c50abef4e3793b73274b4ac45c1e38"
  , "57d58688cde8de2175138d9d93514d5f42f3ca44ee46ebafdac354d130deeaa4"
  , "d78986ee865932e3c83820ee94300c06d0e235ad244dbcc35ca2b938ec6a6291"
  , "7d931b784c6f0e801de6076e704ac4b71ab685f84875d5b9b2155a36f704621f"
  , "f9758a41629a99be36b66fea0c98509571ec902f6ec018e4ce5fe9d22657192f"
  , "f6ede732ce8f7acdd38781ce7250f17b8e2757d929650dd69de55ad2f46f0727"
  , "81357a7f2952d9f739feba0021a4168041f4ebea0cce69f1eb18de1a82e77910"
  , "5ac7565685b880b4b008a350e52ceb90ac9c7b6d48d621a1f7c238db0c43b76a"
  ]
x509Sig :: ByteString
x509Sig = hex $ concat
  [ "7b62d8db852ec3c1ff4b3c5b61abe1db40e29f17a778888a88e7aa69087a6304"
  , "2976e27207d690a66f5becc18562f95ffabe90429ed817a4ff02b1662dafb24c"
  , "1ea340bc7df8cc8aaedd568d417238653f5916ae0aaa1961a27501dde8aead57"
  , "4565f396f80b77050476e7192069e4fc08ae65ad826b64219e5a34030786ea90"
  , "062b5721f2f502758891f68587762f48c94617db402062b5bbb7461f3229b4ae"
  , "348d871d7f8f2e6d65110a3378d444c409ad2e92dc35b7c844616fc4641dec01"
  , "d2b287d34a706b196c8b21f3d8a421360b4e811e5a399ab5b994b426a5bc9d8a"
  , "8627519be535674cb4a09d02eede177143a5e7fde37b1ecdb2a9efd1ac20048a"
  ]

-- X9.31 interop vectors (pinned 4.0.2 CLI, same RSA-2048 key as the
-- v1.5 vectors; X9.31 is deterministic, so the backend replays the
-- CLI's bytes). The digest is SHA-256 over "T16 S7 X9.31 KAT
-- digest input"; the signature is `pkeyutl -sign -pkeyopt
-- digest:sha256 -pkeyopt rsa_padding_mode:x931` output, CLI-verified
-- before embedding.
x931Digest :: ByteString
x931Digest = hex "0281e0bf4eddce53c3ebe418aaef70f85fdbd3fbb7b736683ea4b6acdbdeb0c0"

x931Sig :: ByteString
x931Sig = hex $ concat
  [ "456576fa9624988d3210f3fa2ef1d859e469e742852f0861caddaed79eda5b10"
  , "099db855968d2a894e79b8260ed42d3da606a383fe88579b31d41dae5d258d18"
  , "1a62811e34250f9a0c25ae65ae760948b829cab8fbc054472f91ed02b9f8c1fd"
  , "cfaf68ade709d3f3a1312bf8cf4b9e35f9f2d0e15cf0cb84cc8e1ad40800b619"
  , "185dd6e9749f157e2e4a5ef666633a5e4d31ee60cae1941205c1e8deed18494d"
  , "c17dd63f0dac58fdc03863a900a568b877f9693e689d6649285419d34fbc6ca1"
  , "ecd808dd9f404e38da6275905867f80f7fc08c2b35ee6c3717426e48bf28c3c5"
  , "0b1cb683efa07322a713d1e7a0371ae78450c1390df6f95760c9e50fd225e400"
  ]

-- Poly1305 KAT (pinned 4.0.2 CLI `openssl mac POLY1305` and
-- python-cryptography agreeing byte for byte, independent of this
-- backend).
polyKey :: ByteString
polyKey = hex "60ae20bd9302aea34cafbc620011e17b7774e97764b9bb6e035ffb2b8b63be9f"

polyMsg :: ByteString
polyMsg = "Poly1305 KAT message, second vector"

polyTag :: ByteString
polyTag = hex "f70a350ed794a7e0660bba7638f5a6d2"

-- P-384/SHA-384, P-521/SHA-512, and raw-P-256 interop
-- vectors (pinned 4.0.2 CLI; the raw vector reuses the P-256 key from
-- the fixtures above), plus one vector per new curve family
-- (Koblitz secp256k1, brainpoolP256r1, binary sect283r1).
-- ECDSA is randomized, so the suite verifies the CLI's bytes
-- (proving interop) and roundtrips its own. All vectors were
-- CLI-verified before embedding.
ecMsgK256 :: ByteString
ecMsgK256 = "T16 curves ECDSA secp256k1 message"

ecK256Pub :: ByteString
ecK256Pub = hex $ concat
  [ "3056301006072a8648ce3d020106052b8104000a03420004e352f674324827b1f8"
  , "37300d5895a22acc9525bbe6870870be10da08c1a86564d459a356f3c940fbc11f"
  , "dc99b1c14b1fd066cc5b70c0ce2f5da36c98cc21302d"
  ]

ecSigK256 :: ByteString
ecSigK256 = hex $ concat
  [ "3045022100a090d3cf9830d5119cbb22ad47643819af723a45b140be25f65bb324"
  , "3d1c927402207e2d68f4e8c18d57964f8fcc6613f4f8882653b1661db1abf3fb62"
  , "18b308f745"
  ]

ecMsgBp256 :: ByteString
ecMsgBp256 = "T16 curves ECDSA brainpoolP256r1 message"

ecBp256Pub :: ByteString
ecBp256Pub = hex $ concat
  [ "305a301406072a8648ce3d020106092b2403030208010107034200040bd5b550aad"
  , "747b0cc578ac7b16b0def74c510abaad293e37782316101d9bb5d6f22ed582fd49b"
  , "5624c612eeb556710ebd8cbf479748d717ee3af83e7956cf6a"
  ]

ecSigBp256 :: ByteString
ecSigBp256 = hex $ concat
  [ "304402207462de59f25d911fef3f6fa57abe9476583c61b6fccbaa25a5fb88ea27c"
  , "c18cd02203750f9012d446286c257337fc1bc6a5d43d27a1913eab536eb78c828fb"
  , "79d3ed"
  ]

ecMsgT283 :: ByteString
ecMsgT283 = "T16 curves ECDSA sect283r1 message"

ecT283Pub :: ByteString
ecT283Pub = hex $ concat
  [ "305e301006072a8648ce3d020106052b81040011034a00040776c09667a56b6f058"
  , "5fd97a89be7cf0210f279264f8e3a4429835000951148fbed79ec03ca63c04605c1"
  , "dbac6efc38b97d99af003eafe001febbefbdbce33d5b9ea34f2d8a5d6b"
  ]

ecSigT283 :: ByteString
ecSigT283 = hex $ concat
  [ "304c0224027d44ac97d49f193cf0ffee770a5a7a1e2e046ddb3452276fabb32d9fe"
  , "7fcfc3fbd014202240371cf18faf7654c4b0a5a6d902295e72859d9fadee6498084"
  , "8236a12832177883e388c6"
  ]
ecMsg384 :: ByteString
ecMsg384 = "T16 S9 ECDSA P-384/SHA384 message"

ecP384Pub :: ByteString
ecP384Pub = hex $ concat
  [ "3076301006072a8648ce3d020106052b8104002203620004467ab2e9c927f143"
  , "e9f6151006e492da4d11c9e079e339f6086dfd988bd0cac51e25adf31d504a7c"
  , "730a94c1c4b3bb880cffcceaf56ebc0c1a42e04051e8d11e409440f6a4924c1c"
  , "fea44e8858601cd2a041d7340fe670712e91ca3ec5389a0c"
  ]

ecSig384 :: ByteString
ecSig384 = hex $ concat
  [ "306502301745214d2dd601618123d12577281adfd877401da97434930c6be638"
  , "71069f00aa881a2c7552d1a6cd11964d962d35ec0231009aa7912604646cd498"
  , "08da3a73f279d55a4000bc3ab2f60ee9fc84be326142d18e50efadccac7a38a7"
  , "90846dda3abddd"
  ]

-- | CLI ECDSA P-256/BLAKE2b-512 interop bytes ('openssl pkeyutl
-- -sign -rawin -digest blake2b512', verified back through the CLI).
ecMsgB2 :: ByteString
ecMsgB2 = "ecdsa-blake2b-test-message"

ecB2Pub :: ByteString
ecB2Pub = hex $ concat
  [ "3059301306072a8648ce3d020106082a8648ce3d03010703420004cd49ef94a0"
  , "69a3e45c179d5dcfa51271c9c61b04e94838067cbfd351a1056b0c07d2690f20"
  , "51acf535a3d672ae17613067c32f64517f84eb8ab6ca9a4eb7669d"
  ]

ecSigB2 :: ByteString
ecSigB2 = hex $ concat
  [ "3044022005f2b419c99f1dcd0f0ddd0982b8d643517b51002a169ad91641328ca"
  , "c12253302207d5ca1f3b3d58bfeb3482238e0db956ea750a241e5da3ea3a76ab0"
  , "0650d3fd00"
  ]

ecMsg521 :: ByteString
ecMsg521 = "T16 S9 ECDSA P-521/SHA512 message"

ecP521Pub :: ByteString
ecP521Pub = hex $ concat
  [ "30819b301006072a8648ce3d020106052b810400230381860004019eed1a84c8"
  , "46d69d26a869d864b0d1bf557cc7320ce1d8018f22f3b963f6b4c136b38d44c8"
  , "cb2e21218e96f93aa82459dfb186d80fe06db19cc3c49989e1da9c1701a68897"
  , "45283941b46bb94ab6f59ad10786191c910aa0183b702b25cd18de9afa573180"
  , "5cab4f7e3309226b19e397fbaed8b54a03e2e9e1e79ec3862f0ca47a1fc9"
  ]

ecSig521 :: ByteString
ecSig521 = hex $ concat
  [ "30818702410b6ed9ef58252d7628e1da101ce8d563ee4958740c9420407bdeaa"
  , "2d9ebe7b3e8fc7d32c21fe434dfde0975955dd86d1175a7e8aeb0bc4f5cc42ef"
  , "5bd3ccdce926024201650e92bc9c37d7b2a71309cad43ab170ecc530ab1696d8"
  , "b674246e5275205b60c260f59c00ca96a0dadbd9e180d76a2592ffeb2eb6d8eb"
  , "d43f0e6def4440fe9a46"
  ]

ecRaw32 :: ByteString
ecRaw32 = hex "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

ecRawSig :: ByteString
ecRawSig = hex $ concat
  [ "304502200c0b980a724edb395232d3fe7434d0ff85c10ee8db983fc5ca245d67"
  , "5d6337c7022100f446a1b647aa0fc78ed12dab16076692a4128980fdbba6f874"
  , "997a935c1219b3"
  ]

-- | Point-at-infinity fixture: Wycheproof
-- @ecdsa_brainpoolP224r1_sha224_test.json@ tc360 (invalid,
-- PointDuplication/ArithmeticError), PKCS#11-shaped exactly as the
-- lane sends it — 28-byte SHA-224 digest, 56-byte raw r||s with
-- both halves in range. The verification math lands on the point
-- at infinity, which X9.62 §7.4.2 says REJECTS; OpenSSL reports
-- it as an internal error (rc -1), so the shim must map that one
-- degenerate-math reason to a mismatch verdict.
ecInf224Pub, ecInf224Digest, ecInf224Sig :: ByteString
ecInf224Pub = hex $ concat
  [ "3052301406072a8648ce3d020106092b2403030208010105033a0004d4b6e51"
  , "12406fb743b6bb55f49ea2030d904420831ebddacd67bba89652265384b75d85"
  , "0e7c27f4e33ed6c576df0ff969470a9ef25ffafcd"
  ]
ecInf224Digest = hex "753bb40078934081d7bd113ec49b19ef09d1ba33498690516d4d122c"
ecInf224Sig = hex $ concat
  [ "6be09a551321b343150c1812bae87dcc688b5e25b6ef5e51d2d3c9cf47eb11"
  , "8e0cc1222cb8b2bab72745a932f05ce96e79f4e98be1e2868a"
  ]

-- | Off-set-curve fixtures: a well-formed brainpoolP160r1 key
-- pair (CLI genpkey; curve OID @1.3.36.3.3.2.8.1.1.1@ — real but
-- uncollected, so outside the covered set). The real backend must
-- refuse these with 'BackendBadKey' — never execute past the
-- advertised cap set.
ecBp160Priv, ecBp160Pub :: ByteString
ecBp160Priv = hex $ concat
  [ "305402010104148b826497e301a31d83e16a10c7ba9070fd6e5bf6a00b0609"
  , "2b2403030208010101a12c032a0004e471b91d45036f84037b7e2c3804348be"
  , "1455d93662b6814bfeb22a8acb58b5ae6f583f2a0de1081"
  ]
ecBp160Pub = hex $ concat
  [ "3042301406072a8648ce3d020106092b2403030208010101032a0004e471b91d"
  , "45036f84037b7e2c3804348be1455d93662b6814bfeb22a8acb58b5ae6f583f2"
  , "a0de1081"
  ]

-- | S10 ECDH KAT fixtures: two fresh P-256 pairs plus one P-384 pair
-- (pinned-CLI genpkey); the secrets are pinned-CLI @pkeyutl -derive@
-- output (A->B and B->A agree; cofactor mode agrees on P-256, h=1).
ecdhPrivA, ecdhPubA, ecdhPrivB, ecdhPubB :: ByteString
ecdhPrivA = hex $ concat
  [ "308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b02"
  , "01010420311c1de45b711a6ba76e060470e0db863ac2b9ff60a44db447fc70360"
  , "eaa5ef6a1440342000448ac633084fc453d57a59703893c48f26d1eefd067c1f8"
  , "e69382565b21bf3a2e6dc574e35285f5dd6028eb00471de54d74e3de18a1f9a8a"
  , "280081e7ccec47e98"
  ]
ecdhPubA = hex $ concat
  [ "3059301306072a8648ce3d020106082a8648ce3d0301070342000448ac633084"
  , "fc453d57a59703893c48f26d1eefd067c1f8e69382565b21bf3a2e6dc574e35285"
  , "f5dd6028eb00471de54d74e3de18a1f9a8a280081e7ccec47e98"
  ]
ecdhPrivB = hex $ concat
  [ "308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b02"
  , "0101042087762e6a31210036b5e0cf9af7e2703f31c84916b9df67b4f062f3021"
  , "991d835a144034200043bb6f938a377952e614445d9933c97d15a76d94d1ef9d8"
  , "bafb02ac3cda56ee209e5d0221a899cf628c9cef305fe1a14f3af46e0c7ac2be8"
  , "b68e0e2707d9225e1"
  ]
ecdhPubB = hex $ concat
  [ "3059301306072a8648ce3d020106082a8648ce3d030107034200043bb6f938a3"
  , "77952e614445d9933c97d15a76d94d1ef9d8bafb02ac3cda56ee209e5d0221a89"
  , "9cf628c9cef305fe1a14f3af46e0c7ac2be8b68e0e2707d9225e1"
  ]
ecdhPrivC, ecdhPubC, ecdhSecretAB, ecdhSecretCC :: ByteString
ecdhPrivC = hex $ concat
  [ "3081b6020100301006072a8648ce3d020106052b8104002204819e30819b02010"
  , "104302adb33390dd6fbfc9522bade688cb1ef2960f2bd7fe0c29a87153357e7f7"
  , "aaf44c2efda7eccd10cca7a8d117f49de506a16403620004adce07c5ce4996c1c"
  , "3b5561a7e2ef688d0c046d473ab6676a2e472c096e24d923304f955b099b1ca6d"
  , "9fd414a536e90b6f30acb85c0f74e539ee2905d574ac7b7a918172d8f7c075e833"
  , "3883b626a7a74649dda234ed7694f4332d4be4f227cf"
  ]
ecdhPubC = hex $ concat
  [ "3076301006072a8648ce3d020106052b8104002203620004adce07c5ce4996c1"
  , "c3b5561a7e2ef688d0c046d473ab6676a2e472c096e24d923304f955b099b1ca6d"
  , "9fd414a536e90b6f30acb85c0f74e539ee2905d574ac7b7a918172d8f7c075e833"
  , "3883b626a7a74649dda234ed7694f4332d4be4f227cf"
  ]
ecdhSecretAB = hex "9671ac43cbf5d68893022679b588483c63cdd6e370ae62c81d4ce95d9eae7b05"
ecdhSecretCC = hex "6c0636f7c3858a26c97f7215f27f7a5a952ac99513c70ee3ea54386dad9ff3e50f9eb0004242035779c505284316e9c0"

-- | XDH KAT fixtures: two fresh CLI pairs per curve (pinned-CLI
-- genpkey; the A halves are the KeyImportSpec goldens) with
-- pinned-CLI @pkeyutl -derive@ secrets (A->B and B->A agree),
-- plus the wycheproof tc1 exchange vectors per curve (external
-- KATs; the tc1 bases assemble through 'montgomeryPrivateDer',
-- whose framing the import goldens pin independently).
xdhPrivA, xdhPrivB, xdhSecretAB :: ByteString
xdhPrivA = hex "302e020100300506032b656e04220420107c0296168df7ef1da8bf471f5ac2d793788e84eb8b34d86a2605b2424d0847"
xdhPrivB = hex "302e020100300506032b656e04220420202ea3672e47f763457157ae6915e4ac327f6120a8c1551ae73813d3b3c92175"
xdhSecretAB = hex "a52e5f55676e562a916a32f95cfc05671e85f17bd5975647dcb09eec6418073c"

xdhPointA, xdhPointB :: ByteString
xdhPointA = hex "684cd5fbe3473e3cb8dc7263ec9f0a837d770e5c9e2db619c8e9b0294b0e991d"
xdhPointB = hex "67d790586fcaf48d1628ec7ea2be1281c6cf1e599fffbd059ece5c521143ab7c"

xdh48PrivA, xdh48PrivB, xdh48SecretAB :: ByteString
xdh48PrivA = hex $ concat
  ["3046020100300506032b656f043a0438f0b746caef9d715d94ecf3cc83b6b5caf0140402"
  ,"ff06b3043a56f2904b1594350ce4b7523116d8422a97365bb37c3f11f746e4765e71efad"
  ]
xdh48PrivB = hex $ concat
  ["3046020100300506032b656f043a0438d89fb4cb38f9a4196b39873961f8349f729865ac"
  ,"74ab6f4fee94ed46a668c8b19f38cb4b936dcb68253ebec18a7a4a16565f60b86e5d18cf"
  ]
xdh48SecretAB = hex "d361d60928257b80eb3709a87502c6b5a1d0959533690a29d3af730824a55f3bfb749afe176ca5e4c62dd16a0c17f283dc46ace3047aee2a"

xdh48PointA, xdh48PointB :: ByteString
xdh48PointA = hex $ concat
  ["a661ed99e0dfbb6c4985d6affe9247682f0a809ffab3e351e1142820c636c30c6947fb4c"
  ,"69833ba7e4ec2ec0638016f5ddbcd72e77ebf670"
  ]
xdh48PointB = hex "20ae62a605737b5568b8423ebc0f1479b088c8bb1c2d10de702ea71b179e694d1e87c51ca1b2817e05387e4ca918ae13499e64493bb99c27"

xdhTc1Priv, xdhTc1Pub, xdhTc1Shared :: ByteString
xdhTc1Priv = hex "c8a9d5a91091ad851c668b0736c1c9a02936c0d3ad62670858088047ba057475"
xdhTc1Pub = hex "504a36999f489cd2fdbc08baff3d88fa00569ba986cba22548ffde80f9806829"
xdhTc1Shared = hex "436a2c040cf45fea9b29a0cb81b1f41458f863d0d61b453d0a982720d6d61320"

xdh48Tc1Priv, xdh48Tc1Pub, xdh48Tc1Shared :: ByteString
xdh48Tc1Priv = hex $ concat
  ["e41c63d5159c89de12163fde9d04cf1f430f346b8b2c1f2a4b1f5aee63d17aec29d4b1de"
  ,"bf8b6457e7809d2b15ff9779c97becb04b824efa"
  ]
xdh48Tc1Pub = hex $ concat
  ["f8073fc01c8358362c08740c914b419847ef1e409f4e40d9440febc26f00551adb1c37c6c"
  ,"2a87d8283b8cb453e928a0d42793f72894e0f81"
  ]
xdh48Tc1Shared = hex $ concat
  ["acd496ceb5f68bf9c267196b405f59701a40ec88744b7e5e60bf8f81e8b13df448efe4020"
  ,"01750edb0b695a0512f08c572a2e356493d170b"
  ]

-- | sect283k1 ECDH KAT (pinned CLI): plain and cofactor (h=2, so
-- the two secrets differ) plus the bare peer point.
ecdhPrivD, ecdhPubD, ecdhPrivE, ecdhPubE :: ByteString
ecdhPrivD = hex $ concat
  [ "308180020101042400d5930db9e585af6e5ea746c0fd932202771cbcd2e4acd91"
  , "4ca94a95ef95c2eab736beca00706052b81040010a14c034a000400a519b87152d"
  , "fcb842c7ba62870f3c910db05aaf690bb790c2226822005de24e118e64e0731b30"
  , "b4a66a4a86ebaa58b5b0a23673ab13bcb46421ab42a4710f24c578cbbc94c7a38"
  ]
ecdhPubD = hex $ concat
  [ "305e301006072a8648ce3d020106052b81040010034a000400a519b87152dfcb84"
  , "2c7ba62870f3c910db05aaf690bb790c2226822005de24e118e64e0731b30b4a66"
  , "a4a86ebaa58b5b0a23673ab13bcb46421ab42a4710f24c578cbbc94c7a38"
  ]
ecdhPrivE = hex $ concat
  [ "3081800201010424000b81e39e6ef5ccc92df1b207beb8cd71b246ff4e57c1494d"
  , "4221f5fa91d00b01dd2f40a00706052b81040010a14c034a000407277db5580914a"
  , "8be1b6752a4abbe5e329d63243632155bd04174a611af790852d57a16079ed448d"
  , "e40bb0c7d01f3a882bf0aa01e3278b8f537397cc606b7323ef57eeb134d022a"
  ]
ecdhPubE = hex $ concat
  [ "305e301006072a8648ce3d020106052b81040010034a000407277db5580914a8be1"
  , "b6752a4abbe5e329d63243632155bd04174a611af790852d57a16079ed448de40bb"
  , "0c7d01f3a882bf0aa01e3278b8f537397cc606b7323ef57eeb134d022a"
  ]
ecdhPointE :: ByteString
ecdhPointE = hex $ concat
  [ "0407277db5580914a8be1b6752a4abbe5e329d63243632155bd04174a611af7908"
  , "52d57a16079ed448de40bb0c7d01f3a882bf0aa01e3278b8f537397cc606b7323ef"
  , "57eeb134d022a"
  ]
ecdhSecretDE, ecdhSecretDEcof :: ByteString
ecdhSecretDE = hex "01d8b812087d09360c6db7f56ebc9c9799348bf951571db0390a8fd5e696c1369aedb255"
ecdhSecretDEcof = hex "07e629aca2075197a2a88ca5e4dc2c870bb32ae36a070c84bde114af867386b2a58879e4"

-- | S10e DH KAT fixtures: two ffdhe2048 pairs (pinned-CLI genpkey);
-- the secret is pinned-CLI @pkeyutl -derive@ output (A->B and B->A agree).
dhPrivA, dhPrivB, dhPeerA, dhPeerB, dhSecretAB, dhPrime2048 :: ByteString
dhPrivA = hex $ concat
  [ "3082013f0201003082011706092a864886f70d010301308201080282010100ff"
  , "ffffffffffffffadf85458a2bb4a9aafdc5620273d3cf1d8b9c583ce2d3695a9"
  , "e13641146433fbcc939dce249b3ef97d2fe363630c75d8f681b202aec4617ad3"
  , "df1ed5d5fd65612433f51f5f066ed0856365553ded1af3b557135e7f57c93598"
  , "4f0c70e0e68b77e2a689daf3efe8721df158a136ade73530acca4f483a797abc"
  , "0ab182b324fb61d108a94bb2c8e3fbb96adab760d7f4681d4f42a3de394df4ae"
  , "56ede76372bb190b07a7c8ee0a6d709e02fce1cdf7e2ecc03404cd28342f6191"
  , "72fe9ce98583ff8e4f1232eef28183c3fe3b1b4c6fad733bb5fcbc2ec22005c5"
  , "8ef1837d1683b2c6f34a26c1b2effa886b423861285c97ffffffffffffffff02"
  , "0102041f021d009fa3ef2b4c8dfa3c47df391c7a7bc8018609291f24a761a569"
  , "699de1"
  ]
dhPrivB = hex $ concat
  [ "3082013f0201003082011706092a864886f70d010301308201080282010100ff"
  , "ffffffffffffffadf85458a2bb4a9aafdc5620273d3cf1d8b9c583ce2d3695a9"
  , "e13641146433fbcc939dce249b3ef97d2fe363630c75d8f681b202aec4617ad3"
  , "df1ed5d5fd65612433f51f5f066ed0856365553ded1af3b557135e7f57c93598"
  , "4f0c70e0e68b77e2a689daf3efe8721df158a136ade73530acca4f483a797abc"
  , "0ab182b324fb61d108a94bb2c8e3fbb96adab760d7f4681d4f42a3de394df4ae"
  , "56ede76372bb190b07a7c8ee0a6d709e02fce1cdf7e2ecc03404cd28342f6191"
  , "72fe9ce98583ff8e4f1232eef28183c3fe3b1b4c6fad733bb5fcbc2ec22005c5"
  , "8ef1837d1683b2c6f34a26c1b2effa886b423861285c97ffffffffffffffff02"
  , "0102041f021d0147586245374ff5bc320cfe03ca2049b8b46f5eb702c9c3b1e0"
  , "5a5ca0"
  ]
dhPeerA = hex $ concat
  [ "f738b2ecbdd1d53faa936e55572f1d5304d2a1b983454250848e463dbb125727"
  , "c865d36944cd303ae8daf3855df44cedfc5352c47d090c96efeaed6f70e17bf3"
  , "60aa2248c4c6664c8713d3aa7a53d711c883f7c1493cb69e8a72068af1ab5705"
  , "097e538536523384cf237c576cc3d9acc47c26768162c1290687a596a7a6aa87"
  , "33e04354594fabad2eb42797518dcc5220194a5106195bbdba6e9e7025dd33bf"
  , "cfd1c95e8ad1efc97c0884b31079b794fba0d583fcb93096c76a17b4f8b3c067"
  , "0477c56f1ff367b1ecdfeb90fc25f7b1dae5ebc377d059a3d7b7e66e9bc26c26"
  , "5caee6fd5528c97b892eeb89842d666299c02e1344620662148952a1cc103fa2"
  ]
dhPeerB = hex $ concat
  [ "c75ae3465dfd93b6a1b50841c679448a34ef087b30edfe7c25bd9d897d105e6d"
  , "d943419867a2009eea2f0e931b1925e134468889a06d92c3a5251af1b39a4092"
  , "ba99e124f795852a9de46f85b421f4d5232d73b0b2ba42f033609789f0ca2bc3"
  , "16f79b7a64ad04f410dfb0443ebac1e8844485e9e1c3772ef0558623a9ef3476"
  , "ff8549d3a259511e0490a7b4af4f8f0b73582e1cf2bafdc43486141631972039"
  , "38e4c95ecbddf0bc638d09a12d473e5b1cc576831e43a0cb35f8561e40f5c264"
  , "d66a58f3fcc14ed3bf9a71ac134810fca2da8a98c47c3db55f05d228a9efd4a3"
  , "de7db7d1e45b79a0636fc3f6885efce43b24900b2341ef074543d54120dcd700"
  ]
dhSecretAB = hex $ concat
  [ "96cbacbfc6da3d06a280605284b5729ccce84f1896870ece31468d38f3463c90"
  , "98c303e4abc67edacbb6a78a074a869ea32e293f621ac0546214310932a024e9"
  , "1f0f9f60ff8b329cf655734012a67fb37cc03a281522b56c52944f0332810ad2"
  , "a7c4680ce64db5c13155153dfa9ece121622c9338b605441097d4a5c83da8d8d"
  , "528ceb3b2550eb6b2dfdb2f76ffa8fbcb6aabf7e93495c84c395c9e2d2a2442b"
  , "617f2af65ef63436ee5df3634b530b9373f3c985a91d4930995e1b05db29d82d"
  , "95762e42025f58f59e08c805e65be03c131016f05c1cfec08c94a046ec053048"
  , "5d3d8516e9de0a331e6ec041cc354c7b44950f1811dfe063242781d7a7fe0cc4"
  ]
dhPrime2048 = hex $ concat
  [ "ffffffffffffffffadf85458a2bb4a9aafdc5620273d3cf1d8b9c583ce2d3695"
  , "a9e13641146433fbcc939dce249b3ef97d2fe363630c75d8f681b202aec4617a"
  , "d3df1ed5d5fd65612433f51f5f066ed0856365553ded1af3b557135e7f57c935"
  , "984f0c70e0e68b77e2a689daf3efe8721df158a136ade73530acca4f483a797a"
  , "bc0ab182b324fb61d108a94bb2c8e3fbb96adab760d7f4681d4f42a3de394df4"
  , "ae56ede76372bb190b07a7c8ee0a6d709e02fce1cdf7e2ecc03404cd28342f61"
  , "9172fe9ce98583ff8e4f1232eef28183c3fe3b1b4c6fad733bb5fcbc2ec22005"
  , "c58ef1837d1683b2c6f34a26c1b2effa886b423861285c97ffffffffffffffff"
  ]

-- | X9.42 domain triple (1024-bit DSA paramgen output
-- re-encoded as SEQ{p, g, q}; sign pads stripped).
dhX942P, dhX942G, dhX942Q :: ByteString
dhX942P = hex $ concat
  [ "ddc17b058e1ec15b51996f85eae0b678ea9bb72444159fe2fcd0f44f7be7e7"
  , "37eeebe94c47e751bcd826c53960d7e1af0f0f421f4f31104d07b13af401ed76"
  , "567b31d2ebf1eaac37c626698e60dff128c671f9055600740581508c10081444"
  , "4ffa21fada6af011260c1bc070a3d58f9a098607d92a938eff5a16fdc388e41e"
  , "09"
  ]
dhX942G = hex $ concat
  [ "d1a4428b2e04060534ad2a284a7039276bf6306a88bfde2d92332a824da217"
  , "82e30b3642625f08ca00c5997626d6733d00eafcc206afbbdafb0086ddf1d06d"
  , "4887ff77e549937bdde181e6955cec0b29e710168d891687515c1ad3e03eee3f"
  , "60f96a9063d540b7907cdb24b99dfd490e3cc447be9d47cdefde5aa30c857a9c"
  , "fa"
  ]
dhX942Q = hex "fcbd52881b3c3975a661ce18c867832617b49b0dc2c467c10c264a67"

-- | Tiny DER ECDSA-signature parser: SEQUENCE { INTEGER r, INTEGER s }.
-- Independent of the backend's own conversion; used to cross-check
-- RAW (r || s) against DER on the same signature bytes.
-- | Minimal DER ECDSA-signature parser for cross-checks: the
-- coordinate length is the caller's curve half-width (any covered
-- width). Wider curves use long-form lengths, so both length forms
-- parse.
parseDerEcdsa :: Int -> ByteString -> Maybe (ByteString, ByteString)
parseDerEcdsa coordLen der = do
  (seqBody, rest0) <- takeTLV 0x30 der
  if not (BS.null rest0) then Nothing else do
    (r, rest1) <- takeTLV 0x02 seqBody
    (s, rest2) <- takeTLV 0x02 rest1
    if not (BS.null rest2) then Nothing else pure (stripInt r, stripInt s)
  where
    takeTLV :: Int -> ByteString -> Maybe (ByteString, ByteString)
    takeTLV tag bs = case BS.uncons bs of
      Just (t, r0)
        | fromIntegral t == tag -> case BS.uncons r0 of
            Just (l0, r1)
              | l0 < 0x80 ->
                  let n = fromIntegral l0
                  in Just (BS.take n r1, BS.drop n r1)
              | l0 == 0x81 -> case BS.uncons r1 of
                  Just (n, r2) ->
                    let k = fromIntegral n
                    in Just (BS.take k r2, BS.drop k r2)
                  _ -> Nothing
              | l0 == 0x82 -> case (BS.uncons r1 >>= \(h, tl) -> BS.uncons tl >>= \(l, u) -> Just (h, l, u)) of
                  Just (h, l, r2) ->
                    let k = fromIntegral h * 256 + fromIntegral l
                    in Just (BS.take k r2, BS.drop k r2)
                  _ -> Nothing
              | otherwise -> Nothing
            _ -> Nothing
      _ -> Nothing
    stripInt bs =
      let s = BS.dropWhile (== 0) bs
      in BS.dropWhile (== 0) (if BS.length s > coordLen then BS.drop (BS.length s - coordLen) s else s)

pad32 :: ByteString -> ByteString
pad32 bs = BS.replicate (32 - BS.length bs) 0 <> bs

-- ---------------------------------------------------------------------------
-- Cases
-- ---------------------------------------------------------------------------

caseSha256Kat :: IO ()
caseSha256Kat = withBackend $ \env -> do
  d1 <- expectOk "sha256(abc)" =<< digestOneShot env D_SHA256 "abc"
  assertEqual "sha256(abc)" sha256Abc d1
  d2 <- expectOk "sha256(empty)" =<< digestOneShot env D_SHA256 BS.empty
  assertEqual "sha256(empty)" sha256Empty d2
  d3 <- expectOk "sha256(long)" =<< digestOneShot env D_SHA256 longMsg
  assertEqual "sha256(long)" sha256Long d3
  -- Independent of synthetic outputs: synthetic digest is 32 bytes but
  -- never these values (spot-check the first vector differs from the
  -- synthetic construction only by trusting the FIPS oracle here).
  assertBool "non-empty digest" (BS.length d1 == 32)

-- | Digest "abc" vectors, each independently verified against
-- the pinned @/opt/openssl-4.0.2/bin/openssl dgst@ CLI on 2026-09-21
-- and citing its standard: FIPS 180-4 (SHA-1/SHA-2), FIPS 202
-- (SHA-3), RFC 1321 A.5 (MD5), the RIPEMD-160 test suite.
digestKats :: [(DigestAlg, String, ByteString)]
digestKats =
  [ (D_MD5, "RFC1321", hex "900150983cd24fb0d6963f7d28e17f72")
  , (D_SHA1, "FIPS180-4", hex "a9993e364706816aba3e25717850c26c9cd0d89d")
  , (D_SHA224, "FIPS180-4", hex "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7")
  , (D_SHA384, "FIPS180-4", hex "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7")
  , (D_SHA512, "FIPS180-4", hex "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f")
  , (D_SHA512_224, "FIPS180-4", hex "4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa")
  , (D_SHA512_256, "FIPS180-4", hex "53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23")
  , (D_SHA3_224, "FIPS202", hex "e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf")
  , (D_SHA3_256, "FIPS202", hex "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532")
  , (D_SHA3_384, "FIPS202", hex "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25")
  , (D_SHA3_512, "FIPS202", hex "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0")
  , (D_RIPEMD160, "RIPEMD160", hex "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc")
  , (D_BLAKE2B512, "RFC7693", hex "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923")
  , (D_BLAKE2B160, "hashlib-nn20", hex "384264f676f39536840523f284921cdc68b6846b")
  , (D_BLAKE2B256, "hashlib-nn32", hex "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319")
  , (D_BLAKE2B384, "hashlib-nn48", hex "6f56a82c8e7ef526dfe182eb5212f7db9df1317e57815dbda46083fc30f54ee6c66ba83be64b302d7cba6ce15bb556f4")
  ]

caseDigestKats :: IO ()
caseDigestKats = withBackend $ \env -> do
  -- SHA-256 KATs live in caseSha256Kat; every other recipe alg here.
  mapM_ (\(alg, src, want) -> do
    d <- expectOk (show alg ++ " abc") =<< digestOneShot env alg "abc"
    assertEqual (show alg ++ " KAT " ++ src) want d
    assertEqual (show alg ++ " width") (BS.length want) (BS.length d)) digestKats

caseSha384Multipart :: IO ()
caseSha384Multipart = withBackend $ \env -> do
  -- Multipart honors the init alg for every recipe alg: multipart
  -- output equals one-shot output (KAT equality per alg lives in
  -- caseDigestKats; SHA-256 multipart in caseSha256Multipart).
  mapM_ (checkAlg env)
    [ D_MD5, D_SHA1, D_SHA224, D_SHA384, D_SHA512
    , D_SHA512_224, D_SHA512_256
    , D_SHA3_224, D_SHA3_256, D_SHA3_384, D_SHA3_512
    , D_RIPEMD160
    , D_BLAKE2B512
    , D_BLAKE2B160
    , D_BLAKE2B256
    , D_BLAKE2B384
    ]
  where
    checkAlg e alg = do
      rid <- expectOk ("init " ++ show alg) =<< digestInit e alg
      expectOk "update(a)" =<< digestUpdate e rid "a"
      expectOk "update(bc)" =<< digestUpdate e rid "bc"
      d <- expectOk "final" =<< digestFinal e rid
      one <- expectOk "one-shot" =<< digestOneShot e alg "abc"
      assertEqual ("multipart == one-shot " ++ show alg) one d

caseSha256Multipart :: IO ()
caseSha256Multipart = withBackend $ \env -> do
  rid <- expectOk "digestInit" =<< digestInit env D_SHA256
  expectOk "update(a)" =<< digestUpdate env rid "a"
  expectOk "update(bc)" =<< digestUpdate env rid "bc"
  d <- expectOk "digestFinal" =<< digestFinal env rid
  assertEqual "multipart == one-shot" sha256Abc d
  one <- expectOk "one-shot" =<< digestOneShot env D_SHA256 "abc"
  assertEqual "multipart matches one-shot" one d

caseHmacKat :: IO ()
caseHmacKat = withBackend $ \env -> do
  let spec' = MacHMAC { macDigest = D_SHA256, macTruncLen = Nothing }
  t <- expectOk "hmac kat" =<< macSign env spec' (KeyBytes hmacKey1) hmacMsg1
  assertEqual "rfc4231 case 1" hmacOut1 t

-- | HMAC known answers over the shared RFC 4231 case-1 key
-- ('hmacKey1', 20x0x0b) and message ('hmacMsg1', "Hi There").
-- SHA-1/SHA-2 tags coincide with the RFC 2202/4231 TC1 vectors; MD5
-- (RFC 2202 TC1 uses a 16-byte key), RIPEMD160, and the SHA-3 rows
-- are pinned against the CPython hashlib reference (computed
-- 2026-09-21) and independently cross-checked against the container
-- openssl CLI (3.5.5 mac); the suite itself executes them against
-- the pinned 4.0.2 libcrypto.
hmacKats :: [(DigestAlg, String, ByteString)]
hmacKats =
  [ (D_MD5, "hashlib", hex "5ccec34ea9656392457fa1ac27f08fbc")
  , (D_SHA1, "RFC2202-TC1", hex "b617318655057264e28bc0b6fb378c8ef146be00")
  , (D_SHA224, "RFC4231-TC1", hex "896fb1128abbdf196832107cd49df33f47b4b1169912ba4f53684b22")
  , (D_SHA384, "RFC4231-TC1", hex "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6")
  , (D_SHA512, "RFC4231-TC1", hex "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854")
  , (D_SHA512_224, "RFC4231-TC1", hex "b244ba01307c0e7a8ccaad13b1067a4cf6b961fe0c6a20bda3d92039")
  , (D_SHA512_256, "RFC4231-TC1", hex "9f9126c3d9c3c330d760425ca8a217e31feae31bfe70196ff81642b868402eab")
  , (D_SHA3_224, "hashlib", hex "3b16546bbc7be2706a031dcafd56373d9884367641d8c59af3c860f7")
  , (D_SHA3_256, "hashlib", hex "ba85192310dffa96e2a3a40e69774351140bb7185e1202cdcc917589f95e16bb")
  , (D_SHA3_384, "hashlib", hex "68d2dcf7fd4ddd0a2240c8a437305f61fb7334cfb5d0226e1bc27dc10a2e723a20d370b47743130e26ac7e3d532886bd")
  , (D_SHA3_512, "hashlib", hex "eb3fbd4b2eaab8f5c504bd3a41465aacec15770a7cabac531e482f860b5ec7ba47ccb2c6f2afce8f88d22b6dc61380f23a668fd3888bb80537c0a0b86407689e")
  , (D_RIPEMD160, "hashlib", hex "24cb4bd67d20fc1a5d2ed7732dcc39377f0a5668")
  , (D_BLAKE2B512, "CLI-TC1", hex "358a6a184924894fc34bee5680eedf57d84a37bb38832f288e3b27dc63a98cc8c91e76da476b508bc6b2d408a248857452906e4a20b48c6b4b55d2df0fe1dd24")
  , (D_BLAKE2B160, "hashlib-TC1-nn20", hex "8e52620843a0942dc68ff03ef437d379a361175e")
  , (D_BLAKE2B256, "hashlib-TC1-nn32", hex "b6996ecae165cdb17a02becfbf442b5dee41c5075ded9a5763185cd68bd261d0")
  , (D_BLAKE2B384, "hashlib-TC1-nn48", hex "948364b074f4739bb1be6e7f8c918405f1f06c7a18a125534618269d57e337b67750ba54bd3d6456a59b6b9bb39a7601")
  ]

caseHmacKats :: IO ()
caseHmacKats = withBackend $ \env -> do
  -- SHA-256 KAT lives in caseHmacKat; every other recipe alg here.
  mapM_ (\(alg, src, want) -> do
    t <- expectOk (show alg ++ " hmac") =<< macSign env (MacHMAC alg Nothing) (KeyBytes hmacKey1) hmacMsg1
    assertEqual (show alg ++ " KAT " ++ src) want t
    assertEqual (show alg ++ " width") (BS.length want) (BS.length t)) hmacKats

caseHmacGeneral :: IO ()
caseHmacGeneral = withBackend $ \env -> do
  let key = KeyBytes hmacKey1
  full <- expectOk "full sha256" =<< macSign env (MacHMAC D_SHA256 Nothing) key hmacMsg1
  trunc16 <- expectOk "truncated sha256" =<< macSign env (MacHMAC D_SHA256 (Just 16)) key hmacMsg1
  assertEqual "truncation slices the KAT" (BS.take 16 hmacOut1) trunc16
  assertEqual "full == KAT" hmacOut1 full
  ok <- expectOk "truncated verifies" =<< macVerify env (MacHMAC D_SHA256 (Just 16)) key hmacMsg1 trunc16
  assertBool "truncated roundtrip" ok
  trunc48 <- expectOk "ceiling sha384" =<< macSign env (MacHMAC D_SHA384 (Just 48)) key hmacMsg1
  f48 <- expectOk "full sha384" =<< macSign env (MacHMAC D_SHA384 Nothing) key hmacMsg1
  assertEqual "ceiling == full" f48 trunc48
  b2full <- expectOk "full blake2b512" =<< macSign env (MacHMAC D_BLAKE2B512 Nothing) key hmacMsg1
  b2t32 <- expectOk "truncated blake2b512" =<< macSign env (MacHMAC D_BLAKE2B512 (Just 32)) key hmacMsg1
  assertEqual "blake2b truncation slices the KAT" (BS.take 32 b2full) b2t32
  s2full <- expectOk "full blake2b256" =<< macSign env (MacHMAC D_BLAKE2B256 Nothing) key hmacMsg1
  s2t12 <- expectOk "truncated blake2b256" =<< macSign env (MacHMAC D_BLAKE2B256 (Just 12)) key hmacMsg1
  assertEqual "sized truncation slices the KAT" (BS.take 12 s2full) s2t12
  -- Out-of-range lengths refuse without fallback.
  expectUnsupported "zero refused" =<< macSign env (MacHMAC D_SHA256 (Just 0)) key hmacMsg1
  expectUnsupported "over-width refused" =<< macSign env (MacHMAC D_SHA256 (Just 33)) key hmacMsg1
  expectUnsupported "shake hmac refused" =<< macSign env (MacHMAC D_SHAKE128 Nothing) key hmacMsg1

caseHmacVerify :: IO ()
caseHmacVerify = withBackend $ \env -> do
  let spec' = MacHMAC { macDigest = D_SHA256, macTruncLen = Nothing }
      key = KeyBytes hmacKey1
  ok <- expectOk "verify good" =<< macVerify env spec' key hmacMsg1 hmacOut1
  assertBool "good tag verifies" ok
  let bad = BS.init hmacOut1 <> BS.singleton (BS.last hmacOut1 + 1)
  expectAuthFailed "verify tampered" =<< macVerify env spec' key hmacMsg1 bad
  expectAuthFailed "verify truncated" =<< macVerify env spec' key hmacMsg1 (BS.take 16 hmacOut1)

caseAesKat :: IO ()
caseAesKat = withBackend $ \env -> do
  let key = KeyBytes aes256Key
  ct <- expectOk "aes encrypt kat"
    =<< cipherEncrypt env C_AES256_CBC key aes256Iv aes256Pt
  assertEqual "sp800-38a f.2.5" aes256Ct ct
  pt <- expectOk "aes decrypt kat"
    =<< cipherDecrypt env C_AES256_CBC key aes256Iv aes256Ct
  assertEqual "decrypt inverts" aes256Pt pt

caseAesRoundtrip :: IO ()
caseAesRoundtrip = withBackend $ \env -> do
  let key = KeyBytes aes256Key
      pt2 = aes256Pt <> aes256Pt -- two blocks
  ct <- expectOk "encrypt 2 blocks" =<< cipherEncrypt env C_AES256_CBC key aes256Iv pt2
  assertEqual "no padding: length preserved" (BS.length pt2) (BS.length ct)
  pt <- expectOk "decrypt 2 blocks" =<< cipherDecrypt env C_AES256_CBC key aes256Iv ct
  assertEqual "roundtrip" pt2 pt
  -- Non-block-aligned input is rejected (padding is never implicit).
  expectBadParam "encrypt misaligned" =<< cipherEncrypt env C_AES256_CBC key aes256Iv "short"
  expectBadParam "decrypt misaligned" =<< cipherDecrypt env C_AES256_CBC key aes256Iv "short!!"
  expectBadParam "bad key length" =<< cipherEncrypt env C_AES256_CBC (KeyBytes "short") aes256Iv aes256Pt
  expectBadParam "bad iv length" =<< cipherEncrypt env C_AES256_CBC key "short" aes256Pt

caseCipherKats :: IO ()
caseCipherKats = withBackend $ \env -> do
  -- AES widths: NIST rows (CBC shares the F.2 IV/PT; ECB is empty-IV).
  katCbc env "aes-128-cbc" C_AES128_CBC aes128Key aes256Iv aes256Pt aes128CbcCt
  katEcb env "aes-128-ecb" C_AES128_ECB aes128Key aes256Pt aes128EcbCt
  katCbc env "aes-192-cbc" C_AES192_CBC aes192Key aes256Iv aes256Pt aes192CbcCt
  katEcb env "aes-192-ecb" C_AES192_ECB aes192Key aes256Pt aes192EcbCt
  katEcb env "aes-256-ecb" C_AES256_ECB aes256Key aes256Pt aes256EcbCt
  -- AES-CTR: the F.5 rows at all widths, plus unaligned stream input.
  katCtr env "aes-128-ctr" C_AES128_CTR aes128Key ctrIcb ctrPt aes128CtrCt
  katCtr env "aes-192-ctr" C_AES192_CTR aes192Key ctrIcb ctrPt aes192CtrCt
  katCtr env "aes-256-ctr" C_AES256_CTR aes256Key ctrIcb ctrPt aes256CtrCt
  ragged <- expectOk "ctr unaligned encrypt" =<<
    cipherEncrypt env C_AES128_CTR (KeyBytes aes128Key) ctrIcb "twenty bytes exactly!!"
  assertEqual "ctr length preserved" 22 (BS.length ragged)
  raggedPt <- expectOk "ctr unaligned decrypt" =<<
    cipherDecrypt env C_AES128_CTR (KeyBytes aes128Key) ctrIcb ragged
  assertEqual "ctr unaligned inverts" "twenty bytes exactly!!" raggedPt
  -- Triple-DES: three-key and two-key (K1 = K3, so both agree).
  katCbc env "des3-cbc" C_DES3_CBC des3Key24 des3Iv des3Pt des3Ct
  katEcb env "des3-ecb" C_DES3_ECB des3Key24 des3Pt des3Ct
  ct16 <- expectOk "des3-cbc two-key encrypt"
    =<< cipherEncrypt env C_DES3_CBC (KeyBytes des3Key16) des3Iv des3Pt
  assertEqual "des3 two-key expands to K1||K2||K1" des3Ct ct16
  -- ARIA/CAMELLIA widths share the key/PT/IV fixtures.
  katCbc env "aria-128-cbc" C_ARIA128_CBC ariaKey128 ariaIv ariaPt aria128CbcCt
  katEcb env "aria-128-ecb" C_ARIA128_ECB ariaKey128 ariaPt aria128EcbCt
  katCbc env "aria-192-cbc" C_ARIA192_CBC ariaKey192 ariaIv ariaPt aria192CbcCt
  katEcb env "aria-192-ecb" C_ARIA192_ECB ariaKey192 ariaPt aria192EcbCt
  katCbc env "aria-256-cbc" C_ARIA256_CBC ariaKey256 ariaIv ariaPt aria256CbcCt
  katEcb env "aria-256-ecb" C_ARIA256_ECB ariaKey256 ariaPt aria256EcbCt
  katCbc env "camellia-128-cbc" C_CAMELLIA128_CBC ariaKey128 ariaIv ariaPt cam128CbcCt
  katEcb env "camellia-128-ecb" C_CAMELLIA128_ECB ariaKey128 ariaPt cam128EcbCt
  katCbc env "camellia-192-cbc" C_CAMELLIA192_CBC ariaKey192 ariaIv ariaPt cam192CbcCt
  katEcb env "camellia-192-ecb" C_CAMELLIA192_ECB ariaKey192 ariaPt cam192EcbCt
  katCbc env "camellia-256-cbc" C_CAMELLIA256_CBC ariaKey256 ariaIv ariaPt cam256CbcCt
  katEcb env "camellia-256-ecb" C_CAMELLIA256_ECB ariaKey256 ariaPt cam256EcbCt
  -- CAMELLIA-CTR: the RFC 5528 rows at all widths, resolved through
  -- the driver map (the spec constructors land with the backend
  -- slice; the map-plus-fetch agreement stays pinned here).
  katCtrMapped env "camellia-128-ctr" 16 camCtr128Key camCtr128Icb camCtrPt camCtr128Ct
  katCtrMapped env "camellia-192-ctr" 24 camCtr192Key camCtr192Icb camCtrPt camCtr192Ct
  katCtrMapped env "camellia-256-ctr" 32 camCtr256Key camCtr256Icb camCtrPt camCtr256Ct
  -- Geometry refusals stay typed on the new specs.
  expectBadParam "ecb rejects iv" =<<
    cipherEncrypt env C_AES128_ECB (KeyBytes aes128Key) aes256Iv aes256Pt
  expectBadParam "des3 rejects 16-byte iv" =<<
    cipherEncrypt env C_DES3_CBC (KeyBytes des3Key24) aes256Iv des3Pt
  expectBadParam "des3 rejects 8-byte key" =<<
    cipherEncrypt env C_DES3_CBC (KeyBytes "12345678") des3Iv des3Pt
  where
    katCbc env label cipher key iv pt want = do
      ct <- expectOk (label ++ " encrypt")
        =<< cipherEncrypt env cipher (KeyBytes key) iv pt
      assertEqual (label ++ " kat") want ct
      pt' <- expectOk (label ++ " decrypt")
        =<< cipherDecrypt env cipher (KeyBytes key) iv want
      assertEqual (label ++ " inverts") pt pt'
    katEcb env label cipher key pt want = do
      ct <- expectOk (label ++ " encrypt")
        =<< cipherEncrypt env cipher (KeyBytes key) BS.empty pt
      assertEqual (label ++ " kat") want ct
      pt' <- expectOk (label ++ " decrypt")
        =<< cipherDecrypt env cipher (KeyBytes key) BS.empty want
      assertEqual (label ++ " inverts") pt pt'
    katCtr env label cipher key icb pt want = do
      ct <- expectOk (label ++ " encrypt")
        =<< cipherEncrypt env cipher (KeyBytes key) icb pt
      assertEqual (label ++ " kat") want ct
      pt' <- expectOk (label ++ " decrypt")
        =<< cipherDecrypt env cipher (KeyBytes key) icb want
      assertEqual (label ++ " inverts") pt pt'
    katCtrMapped env label keyLen key icb pt want =
      case cipherSpecFor (MechanismId 0x558) keyLen (encodeCtrParams 128 icb) of
        Nothing -> assertFailure (label ++ " unmapped")
        Just cipher -> katCtr env label cipher key icb pt want

-- AES-CTS (CBC-CS1): ACVP encrypt vectors plus geometry/KAT-edge negatives.
caseAesCts :: IO ()
caseAesCts = withBackend $ \env -> do
  -- 6 legs: 128/192/256 x (exactly-2-blocks, multi-block, ragged, short).
  katCts env "aes-128-cts-64" C_AES128_CTS cts128Key64 cts128Iv64 cts128Pt64 cts128Ct64
  katCts env "aes-128-cts-156" C_AES128_CTS cts128Key156 cts128Iv156 cts128Pt156 cts128Ct156
  katCts env "aes-192-cts-32" C_AES192_CTS cts192Key32 cts192Iv32 cts192Pt32 cts192Ct32
  katCts env "aes-192-cts-57" C_AES192_CTS cts192Key57 cts192Iv57 cts192Pt57 cts192Ct57
  katCts env "aes-256-cts-66" C_AES256_CTS cts256Key66 cts256Iv66 cts256Pt66 cts256Ct66
  katCts env "aes-256-cts-19" C_AES256_CTS cts256Key19 cts256Iv19 cts256Pt19 cts256Ct19
  -- CTS needs >= 1 full block; sub-block input is a typed refusal.
  expectBadParam "cts encrypt sub-block" =<<
    cipherEncrypt env C_AES128_CTS (KeyBytes cts128Key64) cts128Iv64 "short"
  expectBadParam "cts decrypt sub-block" =<<
    cipherDecrypt env C_AES128_CTS (KeyBytes cts128Key64) cts128Iv64 "short!!"
  expectBadParam "cts bad key length" =<<
    cipherEncrypt env C_AES128_CTS (KeyBytes "short") cts128Iv64 cts128Pt64
  expectBadParam "cts bad iv length" =<<
    cipherEncrypt env C_AES128_CTS (KeyBytes cts128Key64) "short" cts128Pt64
  -- CS1 degenerates to plain CBC at exactly one block: cross-check.
  oneBlock <- expectOk "cts 1-block encrypt" =<<
    cipherEncrypt env C_AES256_CTS (KeyBytes aes256Key) aes256Iv aes256Pt
  oneBlockCbc <- expectOk "cbc 1-block encrypt" =<<
    cipherEncrypt env C_AES256_CBC (KeyBytes aes256Key) aes256Iv aes256Pt
  assertEqual "cts==cbc at 16 bytes" oneBlockCbc oneBlock
  where
    katCts env label cipher key iv pt want = do
      ct <- expectOk (label ++ " encrypt")
        =<< cipherEncrypt env cipher (KeyBytes key) iv pt
      assertEqual (label ++ " kat") want ct
      pt' <- expectOk (label ++ " decrypt")
        =<< cipherDecrypt env cipher (KeyBytes key) iv want
      assertEqual (label ++ " inverts") pt pt'

-- AES CFB128/CFB8/CFB1/OFB: ACVP encrypt vectors (enc+dec) plus
-- ragged roundtrips (length-preserving, self-inverse) and geometry
-- negatives. CFB1 sub-byte legs mask to the payload bits per the
-- oracle's _cfb1_mask rule (top payloadLen bits compared).
caseAesCfbOfb :: IO ()
caseAesCfbOfb = withBackend $ \env -> do
  kat env "aes-128-cfb128-48" C_AES128_CFB128 cfb128_128_key cfb128_128_iv cfb128_128_pt cfb128_128_ct
  kat env "aes-192-cfb128-48" C_AES192_CFB128 cfb128_192_key cfb128_192_iv cfb128_192_pt cfb128_192_ct
  kat env "aes-256-cfb128-48" C_AES256_CFB128 cfb128_256_key cfb128_256_iv cfb128_256_pt cfb128_256_ct
  kat env "aes-128-cfb8-32" C_AES128_CFB8 cfb8_128_key cfb8_128_iv cfb8_128_pt cfb8_128_ct
  kat env "aes-192-cfb8-32" C_AES192_CFB8 cfb8_192_key cfb8_192_iv cfb8_192_pt cfb8_192_ct
  kat env "aes-256-cfb8-32" C_AES256_CFB8 cfb8_256_key cfb8_256_iv cfb8_256_pt cfb8_256_ct
  kat env "aes-128-cfb1-8b" C_AES128_CFB1 cfb1_128_key cfb1_128_iv (hex "93") (hex "75")
  kat env "aes-192-cfb1-8b" C_AES192_CFB1 cfb1_192_key cfb1_192_iv (hex "5C") (hex "76")
  kat env "aes-256-cfb1-8b" C_AES256_CFB1 cfb1_256_key cfb1_256_iv (hex "51") (hex "D2")
  katMasked env "aes-128-cfb1-10b" C_AES128_CFB1 cfb1_128b_key cfb1_128b_iv (hex "CDC0") (hex "6B00") 10
  katMasked env "aes-192-cfb1-10b" C_AES192_CFB1 cfb1_192b_key cfb1_192b_iv (hex "3480") (hex "F740") 10
  katMasked env "aes-256-cfb1-10b" C_AES256_CFB1 cfb1_256b_key cfb1_256b_iv (hex "1280") (hex "2F00") 10
  kat env "aes-128-ofb-64" C_AES128_OFB ofb_128_key ofb_128_iv ofb_128_pt ofb_128_ct
  kat env "aes-192-ofb-64" C_AES192_OFB ofb_192_key ofb_192_iv ofb_192_pt ofb_192_ct
  kat env "aes-256-ofb-64" C_AES256_OFB ofb_256_key ofb_256_iv ofb_256_pt ofb_256_ct
  -- Ragged roundtrips (no ACVP ragged vectors exist; these pin
  -- length preservation + inversion, not oracle bytes).
  roundtrip env "cfb128 ragged 20" C_AES128_CFB128 cfb128_128_key cfb128_128_iv 20
  roundtrip env "cfb8 ragged 20" C_AES128_CFB8 cfb8_128_key cfb8_128_iv 20
  roundtrip env "cfb1 ragged 3" C_AES128_CFB1 cfb1_128_key cfb1_128_iv 3
  roundtrip env "ofb ragged 20" C_AES128_OFB ofb_128_key ofb_128_iv 20
  -- Geometry negatives.
  expectBadParam "cfb128 bad key" =<<
    cipherEncrypt env C_AES128_CFB128 (KeyBytes "short") cfb128_128_iv cfb128_128_pt
  expectBadParam "cfb128 bad iv" =<<
    cipherEncrypt env C_AES128_CFB128 (KeyBytes cfb128_128_key) "short" cfb128_128_pt
  expectBadParam "cfb8 bad key" =<<
    cipherEncrypt env C_AES128_CFB8 (KeyBytes "short") cfb8_128_iv cfb8_128_pt
  expectBadParam "cfb8 bad iv" =<<
    cipherEncrypt env C_AES128_CFB8 (KeyBytes cfb8_128_key) "short" cfb8_128_pt
  expectBadParam "cfb1 bad key" =<<
    cipherEncrypt env C_AES128_CFB1 (KeyBytes "short") cfb1_128_iv (hex "93")
  expectBadParam "cfb1 bad iv" =<<
    cipherEncrypt env C_AES128_CFB1 (KeyBytes cfb1_128_key) "short" (hex "93")
  expectBadParam "ofb bad key" =<<
    cipherEncrypt env C_AES128_OFB (KeyBytes "short") ofb_128_iv ofb_128_pt
  expectBadParam "ofb bad iv" =<<
    cipherEncrypt env C_AES128_OFB (KeyBytes ofb_128_key) "short" ofb_128_pt
  where
    kat env label cipher key iv pt want = do
      ct <- expectOk (label ++ " encrypt")
        =<< cipherEncrypt env cipher (KeyBytes key) iv pt
      assertEqual (label ++ " kat") want ct
      pt' <- expectOk (label ++ " decrypt")
        =<< cipherDecrypt env cipher (KeyBytes key) iv want
      assertEqual (label ++ " inverts") pt pt'
    katMasked env label cipher key iv pt want bits = do
      ct <- expectOk (label ++ " encrypt")
        =<< cipherEncrypt env cipher (KeyBytes key) iv pt
      assertEqual (label ++ " kat") (maskTopBits bits want) (maskTopBits bits ct)
      pt' <- expectOk (label ++ " decrypt")
        =<< cipherDecrypt env cipher (KeyBytes key) iv want
      assertEqual (label ++ " inverts") (maskTopBits bits pt) (maskTopBits bits pt')
    roundtrip env label cipher key iv n = do
      let pt = BS.take n "ragged-input-bytes-0123456789ABCDEF"
      ct <- expectOk (label ++ " encrypt")
        =<< cipherEncrypt env cipher (KeyBytes key) iv pt
      assertEqual (label ++ " length preserved") n (BS.length ct)
      pt' <- expectOk (label ++ " decrypt")
        =<< cipherDecrypt env cipher (KeyBytes key) iv ct
      assertEqual (label ++ " inverts") pt pt'
    -- Keep the first n bits (oracle _cfb1_mask rule); the engine
    -- always returns full bytes.
    maskTopBits bits bs
      | BS.length bs * 8 <= bits = bs
      | rest == 0 = hd
      | otherwise = hd <> BS.take 1 (BS.map (.&. mask) tl)
      where
        (full, rest) = bits `divMod` 8
        (hd, tl) = BS.splitAt full bs
        mask = fromIntegral (0xFF `shiftL` (8 - rest) .&. 0xFF :: Int)

-- AES-KW (RFC 3394) / AES-KWP (RFC 5649): ACVP vectors, empty-IV
-- (ECB shape), output expands by the 8-byte wrap IV.
caseAesWrapKwp :: IO ()
caseAesWrapKwp = withBackend $ \env -> do
  -- 12 legs: KW/KWP x 128/192/256 x (minimal, multiblock/ragged).
  katKw env "aes-128-kw-16" C_AES128_KW kw128_16_key kw128_16_pt kw128_16_ct
  katKw env "aes-128-kw-72" C_AES128_KW kw128_72_key kw128_72_pt kw128_72_ct
  katKw env "aes-192-kw-16" C_AES192_KW kw192_16_key kw192_16_pt kw192_16_ct
  katKw env "aes-192-kw-72" C_AES192_KW kw192_72_key kw192_72_pt kw192_72_ct
  katKw env "aes-256-kw-16" C_AES256_KW kw256_16_key kw256_16_pt kw256_16_ct
  katKw env "aes-256-kw-72" C_AES256_KW kw256_72_key kw256_72_pt kw256_72_ct
  katKwp env "aes-128-kwp-1" C_AES128_KWP kwp128_1_key kwp128_1_pt kwp128_1_ct
  katKwp env "aes-128-kwp-269" C_AES128_KWP kwp128_269_key kwp128_269_pt kwp128_269_ct
  katKwp env "aes-192-kwp-1" C_AES192_KWP kwp192_1_key kwp192_1_pt kwp192_1_ct
  katKwp env "aes-192-kwp-269" C_AES192_KWP kwp192_269_key kwp192_269_pt kwp192_269_ct
  katKwp env "aes-256-kwp-1" C_AES256_KWP kwp256_1_key kwp256_1_pt kwp256_1_ct
  katKwp env "aes-256-kwp-269" C_AES256_KWP kwp256_269_key kwp256_269_pt kwp256_269_ct
  -- Geometry negatives (provider-proven: KW minimum is 16 bytes,
  -- multiple-of-8; KWP refuses empty rather than emitting the
  -- provider's vacuous 0-byte success).
  expectBadParam "kw rejects 8-byte input" =<<
    cipherEncrypt env C_AES128_KW (KeyBytes kw128_16_key) BS.empty "12345678"
  expectBadParam "kw rejects non-multiple-of-8" =<<
    cipherEncrypt env C_AES128_KW (KeyBytes kw128_16_key) BS.empty "twenty bytes exactly!!"
  expectBadParam "kw rejects iv" =<<
    cipherEncrypt env C_AES128_KW (KeyBytes kw128_16_key) aes256Iv kw128_16_pt
  expectBadParam "kw bad key length" =<<
    cipherEncrypt env C_AES128_KW (KeyBytes "short") BS.empty kw128_16_pt
  expectBadParam "kwp rejects empty input" =<<
    cipherEncrypt env C_AES128_KWP (KeyBytes kwp128_1_key) BS.empty BS.empty
  expectBadParam "kwp rejects iv" =<<
    cipherEncrypt env C_AES128_KWP (KeyBytes kwp128_1_key) aes256Iv kwp128_1_pt
  expectBadParam "kwp bad key length" =<<
    cipherEncrypt env C_AES128_KWP (KeyBytes "short") BS.empty kwp128_1_pt
  -- Integrity negatives: decrypt failures are authentication
  -- failures (GCM-tag-failure precedent), never wrong plaintext.
  expectAuthFailed "kw corrupt ct" =<<
    cipherDecrypt env C_AES128_KW (KeyBytes kw128_16_key) BS.empty (corrupt kw128_16_ct)
  expectAuthFailed "kwp corrupt ct" =<<
    cipherDecrypt env C_AES128_KWP (KeyBytes kwp128_1_key) BS.empty (corrupt kwp128_1_ct)
  where
    katKw env label cipher key pt want =
      kat env label cipher key pt want (+ 8)
    katKwp env label cipher key pt want =
      kat env label cipher key pt want (\n -> n + (8 - n `mod` 8) `mod` 8 + 8)
    kat env label cipher key pt want expand = do
      ct <- expectOk (label ++ " encrypt")
        =<< cipherEncrypt env cipher (KeyBytes key) BS.empty pt
      assertEqual (label ++ " kat") want ct
      assertEqual (label ++ " expands") (expand (BS.length pt)) (BS.length ct)
      pt' <- expectOk (label ++ " decrypt")
        =<< cipherDecrypt env cipher (KeyBytes key) BS.empty want
      assertEqual (label ++ " inverts") pt pt'
    corrupt bs = case BS.uncons bs of
      Nothing -> bs
      Just (b, rest) -> BS.cons (b `xor` 0x01) rest

-- AES-XTS (IEEE 1619): ACVP vectors, 16-byte tweak as the IV,
-- double-width keys (data + tweak halves), length-preserving
-- over data units >= 16 bytes (stealing covers ragged tails).
caseAesXts :: IO ()
caseAesXts = withBackend $ \env -> do
  -- 4 legs: 128/256 x (aligned 16B, ragged).
  kat env "aes-128-xts-16" C_AES128_XTS xts128_key xts128_tweak xts128_pt xts128_ct
  kat env "aes-128-xts-62" C_AES128_XTS xts128_rag_key xts128_rag_tweak xts128_rag_pt xts128_rag_ct
  kat env "aes-256-xts-16" C_AES256_XTS xts256_key xts256_tweak xts256_pt xts256_ct
  kat env "aes-256-xts-27" C_AES256_XTS xts256_rag_key xts256_rag_tweak xts256_rag_pt xts256_rag_ct
  -- Geometry negatives (provider-proven: input floor is 16
  -- bytes; equal-halves keys refused at init as bad keys).
  expectBadParam "xts rejects 15-byte input" =<<
    cipherEncrypt env C_AES128_XTS (KeyBytes xts128_key) xts128_tweak (BS.take 15 xts128_pt)
  expectBadParam "xts bad key length" =<<
    cipherEncrypt env C_AES128_XTS (KeyBytes "short") xts128_tweak xts128_pt
  expectBadParam "xts bad tweak length" =<<
    cipherEncrypt env C_AES128_XTS (KeyBytes xts128_key) "short" xts128_pt
  expectBadKey "xts rejects equal-halves key" =<<
    cipherEncrypt env C_AES128_XTS (KeyBytes (BS.take 16 xts128_key <> BS.take 16 xts128_key)) xts128_tweak xts128_pt
  where
    kat env label cipher key tweak pt want = do
      ct <- expectOk (label ++ " encrypt")
        =<< cipherEncrypt env cipher (KeyBytes key) tweak pt
      assertEqual (label ++ " kat") want ct
      assertEqual (label ++ " length preserved") (BS.length pt) (BS.length ct)
      pt' <- expectOk (label ++ " decrypt")
        =<< cipherDecrypt env cipher (KeyBytes key) tweak want
      assertEqual (label ++ " inverts") pt pt'

caseRsaKats :: IO ()
caseRsaKats = withBackend $ \env -> do
  let priv = KeyDer rsaPrivDer
      pub = KeyDer rsaPubDer
      sha256 = SigRSA_PKCS1v15 D_SHA256
  -- SHA-256 KAT: the backend signs the CLI's exact bytes
  -- (deterministic v1.5) and verifies the CLI's vector.
  sig <- expectOk "rsa-sha256 sign kat" =<< sign env sha256 priv rsaMsg
  assertEqual "rsa-sha256 kat" rsaSig256 sig
  expectOk "rsa-sha256 verify kat" =<< verify env sha256 pub rsaMsg rsaSig256
  expectAuthFailed "rsa-sha256 tampered" =<<
    verify env sha256 pub rsaMsg (BS.init rsaSig256 <> "X")
  expectAuthFailed "rsa-sha256 wrong msg" =<<
    verify env sha256 pub "wrong message" rsaSig256
  -- Raw KAT: block-type-1 over the input, no hashing.
  rsig <- expectOk "rsa-raw sign kat" =<< sign env SigRSA_Raw priv rsaRawMsg
  assertEqual "rsa-raw kat" rsaRawSig rsig
  expectOk "rsa-raw verify kat" =<< verify env SigRSA_Raw pub rsaRawMsg rsaRawSig
  expectAuthFailed "rsa-raw tampered" =<<
    verify env SigRSA_Raw pub rsaRawMsg (BS.init rsaRawSig <> "X")
  -- Every other bound digest roundtrips (sign is deterministic:
  -- signing twice agrees, and cross-digest verifies fail).
  mapM_ (roundtrip env priv pub)
    [ D_MD5, D_SHA1, D_SHA224, D_SHA384, D_SHA512
    , D_SHA3_224, D_SHA3_256, D_SHA3_384, D_SHA3_512
    , D_RIPEMD160
    ]
  cross <- expectOk "rsa-sha512 sign" =<<
    sign env (SigRSA_PKCS1v15 D_SHA512) priv rsaMsg
  expectAuthFailed "sha512 sig under sha256 rejected" =<<
    verify env sha256 pub rsaMsg cross
  -- Typed key refusals: garbage DER is a bad key, never native.
  expectBadKey "rsa sign garbage priv" =<< sign env sha256 (KeyDer "bogus") rsaMsg
  expectBadKey "rsa verify garbage pub" =<<
    verify env sha256 (KeyDer "bogus") rsaMsg rsaSig256
  where
    roundtrip env priv pub alg = do
      let spec' = SigRSA_PKCS1v15 alg
          label = show alg
      s1 <- expectOk ("sign " ++ label) =<< sign env spec' priv rsaMsg
      assertEqual ("sig length " ++ label) 256 (BS.length s1)
      s2 <- expectOk ("resign " ++ label) =<< sign env spec' priv rsaMsg
      assertEqual ("deterministic " ++ label) s1 s2
      expectOk ("verify " ++ label) =<< verify env spec' pub rsaMsg s1

caseRsaPssVectors :: IO ()
caseRsaPssVectors = withBackend $ \env -> do
  let priv = KeyDer rsaPrivDer
      pub = KeyDer rsaPubDer
      sha256 = SigRSA_PSS (PssParams D_SHA256 D_SHA256 32)
  -- Interop: the backend verifies the CLI's signature bytes.
  expectOk "pss-sha256 verify cli vector" =<<
    verify env sha256 pub pssMsg pssSig256
  expectAuthFailed "pss-sha256 tampered" =<<
    verify env sha256 pub pssMsg (BS.init pssSig256 <> "X")
  expectAuthFailed "pss-sha256 wrong msg" =<<
    verify env sha256 pub "wrong message" pssSig256
  expectAuthFailed "pss-sha256 wrong salt rejected" =<<
    verify env (SigRSA_PSS (PssParams D_SHA256 D_SHA256 20)) pub pssMsg pssSig256
  -- Roundtrips: the backend signs (fresh randomness each call) and
  -- verifies its own output across salts and digests.
  mapM_ (roundtrip env priv pub)
    [ PssParams D_SHA256 D_SHA256 0
    , PssParams D_SHA256 D_SHA256 20
    , PssParams D_SHA256 D_SHA256 32
    , PssParams D_SHA256 D_SHA256 64
    , PssParams D_SHA256 D_SHA512 32
    , PssParams D_SHA512 D_SHA512 64
    , PssParams D_SHA1 D_SHA1 20
    , PssParams D_SHA3_256 D_SHA3_256 32
    ]
  -- Typed key refusals: garbage DER is a bad key, never native.
  expectBadKey "pss sign garbage priv" =<< sign env sha256 (KeyDer "bogus") pssMsg
  expectBadKey "pss verify garbage pub" =<<
    verify env sha256 (KeyDer "bogus") pssMsg pssSig256
  where
    roundtrip env priv pub p = do
      let spec' = SigRSA_PSS p
          label = show p
      s1 <- expectOk ("sign " ++ label) =<< sign env spec' priv pssMsg
      assertEqual ("sig length " ++ label) 256 (BS.length s1)
      s2 <- expectOk ("resign " ++ label) =<< sign env spec' priv pssMsg
      -- Positive salts randomize; salt 0 is deterministic by design.
      if pssSaltLen p > 0
        then assertBool ("randomized " ++ label) (s1 /= s2)
        else assertEqual ("salt-0 deterministic " ++ label) s1 s2
      expectOk ("verify own " ++ label) =<< verify env spec' pub pssMsg s1
      expectOk ("verify own2 " ++ label) =<< verify env spec' pub pssMsg s2

caseRsaOaepVectors :: IO ()
caseRsaOaepVectors = withBackend $ \env -> do
  let priv = KeyDer rsaPrivDer
      pub = KeyDer rsaPubDer
      sha256 = RsaOaep (OaepParams D_SHA256 D_SHA256 BS.empty)
      sha1Label = RsaOaep (OaepParams D_SHA1 D_SHA1 "label")
  -- Interop: the backend decrypts the CLI's ciphertexts.
  pt <- expectOk "oaep-sha256 decrypt cli vector" =<<
    pkeyDecrypt env sha256 priv oaepCt256
  assertEqual "oaep-sha256 interop" oaepMsg pt
  ptL <- expectOk "oaep-sha1-label decrypt cli vector" =<<
    pkeyDecrypt env sha1Label priv oaepCtLabel
  assertEqual "oaep-sha1-label interop" oaepMsg ptL
  -- Wrong label, tampering, and wrong keys are verdicts.
  expectAuthFailed "oaep wrong label rejected" =<<
    pkeyDecrypt env sha256 priv oaepCtLabel
  expectAuthFailed "oaep tampered rejected" =<<
    pkeyDecrypt env sha256 priv (BS.init oaepCt256 <> "X")
  -- Uniformity (Manger 2001): every modulus-wide invalid
  -- ciphertext is the same AuthFailed verdict — no reason-code
  -- partition across padding-failure shapes.
  let badBlobs = [ BS.replicate 256 0x00
                 , BS.replicate 256 0xFF
                 , BS.pack [0x00, 0x02] <> BS.replicate 254 0x00
                 , BS.reverse oaepCt256
                 ]
  mapM_ (\(i, bad) -> expectAuthFailed ("oaep uniform " ++ show (i :: Int)) =<<
    pkeyDecrypt env sha256 priv bad) (zip [1 ..] badBlobs)
  expectBadParam "oaep wrong-length refused" =<<
    pkeyDecrypt env sha256 priv "short"
  -- Roundtrips: fresh randomness each call, label binding holds.
  mapM_ (roundtrip env priv pub) [sha256, sha1Label]
  -- Typed bounds: overlong input is BadParam (k-2*hLen-2 = 190 for
  -- SHA-256 on this key), garbage DER is a bad key.
  expectBadParam "oaep overlong refused" =<<
    pkeyEncrypt env sha256 pub (BS.replicate 191 0x41)
  ct190 <- expectOk "oaep boundary seals" =<<
    pkeyEncrypt env sha256 pub (BS.replicate 190 0x41)
  pt190 <- expectOk "oaep boundary opens" =<<
    pkeyDecrypt env sha256 priv ct190
  assertEqual "oaep boundary reversible" (BS.replicate 190 0x41) pt190
  expectBadKey "oaep encrypt garbage pub" =<<
    pkeyEncrypt env sha256 (KeyDer "bogus") oaepMsg
  expectBadKey "oaep decrypt garbage priv" =<<
    pkeyDecrypt env sha256 (KeyDer "bogus") oaepCt256
  where
    roundtrip env priv pub params = do
      let label = show params
      c1 <- expectOk ("seal " ++ label) =<< pkeyEncrypt env params pub oaepMsg
      assertEqual ("ct length " ++ label) 256 (BS.length c1)
      c2 <- expectOk ("reseal " ++ label) =<< pkeyEncrypt env params pub oaepMsg
      assertBool ("randomized " ++ label) (c1 /= c2)
      p1 <- expectOk ("open " ++ label) =<< pkeyDecrypt env params priv c1
      assertEqual ("reversible " ++ label) oaepMsg p1

caseRsaPkcs1Vectors :: IO ()
caseRsaPkcs1Vectors = withBackend $ \env -> do
  let priv = KeyDer rsaPrivDer
      pub = KeyDer rsaPubDer
  -- Interop: the backend decrypts the CLI's ciphertext.
  pt <- expectOk "pkcs1 decrypt cli vector" =<<
    pkeyDecrypt env RsaPkcs1 priv pkcs1Ct
  assertEqual "pkcs1 interop" pkcs1Msg pt
  -- Header tampering is a verdict. (A last-byte flip is NOT
  -- tested: v1.5 carries no integrity check, so it still opens to
  -- garbage — that is correct padding behavior, not a bypass.)
  expectAuthFailed "pkcs1 tampered rejected" =<<
    pkeyDecrypt env RsaPkcs1 priv ("\xFF\xFF" <> BS.drop 2 pkcs1Ct)
  -- Uniformity (Manger 2001): every modulus-wide invalid
  -- ciphertext is the same AuthFailed verdict — no reason-code
  -- partition across padding-failure shapes.
  let badBlobs = [ BS.replicate 256 0x00
                 , BS.replicate 256 0xFF
                 , BS.pack [0x00, 0x02] <> BS.replicate 254 0x00
                 , BS.pack [0x00, 0x01] <> BS.replicate 254 0xFF
                 , BS.reverse pkcs1Ct
                 ]
  mapM_ (\(i, bad) -> expectAuthFailed ("pkcs1 uniform " ++ show (i :: Int)) =<<
    pkeyDecrypt env RsaPkcs1 priv bad) (zip [1 ..] badBlobs)
  expectBadParam "pkcs1 wrong-length refused" =<<
    pkeyDecrypt env RsaPkcs1 priv "short"
  -- Roundtrip: fresh randomness each call, own output opens.
  c1 <- expectOk "pkcs1 seal" =<< pkeyEncrypt env RsaPkcs1 pub pkcs1Msg
  assertEqual "pkcs1 ct length" 256 (BS.length c1)
  c2 <- expectOk "pkcs1 reseal" =<< pkeyEncrypt env RsaPkcs1 pub pkcs1Msg
  assertBool "pkcs1 randomized" (c1 /= c2)
  p1 <- expectOk "pkcs1 open" =<< pkeyDecrypt env RsaPkcs1 priv c1
  assertEqual "pkcs1 reversible" pkcs1Msg p1
  -- Typed bounds: overlong input is BadParam (k-11 = 245 on this
  -- key), garbage DER is a bad key.
  expectBadParam "pkcs1 overlong refused" =<<
    pkeyEncrypt env RsaPkcs1 pub (BS.replicate 246 0x41)
  ct245 <- expectOk "pkcs1 boundary seals" =<<
    pkeyEncrypt env RsaPkcs1 pub (BS.replicate 245 0x41)
  pt245 <- expectOk "pkcs1 boundary opens" =<<
    pkeyDecrypt env RsaPkcs1 priv ct245
  assertEqual "pkcs1 boundary reversible" (BS.replicate 245 0x41) pt245
  expectBadKey "pkcs1 encrypt garbage pub" =<<
    pkeyEncrypt env RsaPkcs1 (KeyDer "bogus") pkcs1Msg
  expectBadKey "pkcs1 decrypt garbage priv" =<<
    pkeyDecrypt env RsaPkcs1 (KeyDer "bogus") pkcs1Ct

caseRsaX509Vectors :: IO ()
caseRsaX509Vectors = withBackend $ \env -> do
  let priv = KeyDer rsaPrivDer
      pub = KeyDer rsaPubDer
      padded = BS.replicate (256 - BS.length x509Msg) 0 <> x509Msg
  -- Interop: the backend decrypts the CLI's ciphertext and verifies
  -- the CLI's raw signature (same RSA-2048 key as the v1.5 vectors).
  pt <- expectOk "x509 decrypt cli vector" =<<
    pkeyDecrypt env RsaX509 priv x509Ct
  assertEqual "x509 interop" padded pt
  expectOk "x509 verify cli vector" =<<
    verify env SigRSA_X509 pub x509Msg x509Sig
  -- Raw RSA has no integrity: tampered blocks open to garbage and
  -- mismatched messages verify to a verdict; the zero block is
  -- the identity.
  garbled <- expectOk "x509 tampered opens" =<<
    pkeyDecrypt env RsaX509 priv (BS.init x509Ct <> "X")
  assertBool "x509 tamper garbles" (garbled /= padded)
  expectAuthFailed "x509 tampered sig rejected" =<<
    verify env SigRSA_X509 pub x509Msg (BS.init x509Sig <> "X")
  expectAuthFailed "x509 wrong msg rejected" =<<
    verify env SigRSA_X509 pub "tampered-data-32-bytes-payload!!!" x509Sig
  zeroPt <- expectOk "x509 zero opens" =<<
    pkeyDecrypt env RsaX509 priv (BS.replicate 256 0)
  assertEqual "x509 zero identity" (BS.replicate 256 0) zeroPt
  -- Above-modulus blocks are verdicts (uniform invalid-block shape).
  expectAuthFailed "x509 above-n rejected" =<<
    pkeyDecrypt env RsaX509 priv (BS.replicate 256 0xFF)
  expectBadParam "x509 wrong-length refused" =<<
    pkeyDecrypt env RsaX509 priv "short"
  -- Roundtrips: raw RSA is deterministic — seals replay the CLI
  -- vector byte for byte.
  c1 <- expectOk "x509 seal" =<< pkeyEncrypt env RsaX509 pub x509Msg
  assertEqual "x509 ct length" 256 (BS.length c1)
  assertEqual "x509 matches cli vector" x509Ct c1
  c2 <- expectOk "x509 reseal" =<< pkeyEncrypt env RsaX509 pub x509Msg
  assertEqual "x509 deterministic" c1 c2
  p1 <- expectOk "x509 open" =<< pkeyDecrypt env RsaX509 priv c1
  assertEqual "x509 reversible" padded p1
  s1 <- expectOk "x509 sign" =<< sign env SigRSA_X509 priv x509Msg
  assertEqual "x509 sig length" 256 (BS.length s1)
  assertEqual "x509 sig matches cli vector" x509Sig s1
  expectOk "x509 self-verify" =<< verify env SigRSA_X509 pub x509Msg s1
  -- Typed bounds: empty and over-wide inputs refuse (k = 256 on
  -- this key), garbage DER is a bad key.
  expectBadParam "x509 empty encrypt refused" =<<
    pkeyEncrypt env RsaX509 pub BS.empty
  expectBadParam "x509 overlong encrypt refused" =<<
    pkeyEncrypt env RsaX509 pub (BS.replicate 257 0x41)
  full <- expectOk "x509 full-width seals" =<<
    pkeyEncrypt env RsaX509 pub (BS.replicate 256 0x41)
  assertEqual "x509 full-width length" 256 (BS.length full)
  expectBadParam "x509 empty sign refused" =<< sign env SigRSA_X509 priv BS.empty
  expectBadParam "x509 overlong sign refused" =<<
    sign env SigRSA_X509 priv (BS.replicate 257 0x41)
  expectBadKey "x509 encrypt garbage pub" =<<
    pkeyEncrypt env RsaX509 (KeyDer "bogus") x509Msg
  expectBadKey "x509 decrypt garbage priv" =<<
    pkeyDecrypt env RsaX509 (KeyDer "bogus") x509Ct
  expectBadKey "x509 sign garbage priv" =<<
    sign env SigRSA_X509 (KeyDer "bogus") x509Msg
  expectBadKey "x509 verify garbage pub" =<<
    verify env SigRSA_X509 (KeyDer "bogus") x509Msg x509Sig

caseRsaX931Vectors :: IO ()
caseRsaX931Vectors = withBackend $ \env -> do
  let priv = KeyDer rsaPrivDer
      pub = KeyDer rsaPubDer
      raw = SigRSA_X931 Nothing
      sha1 = SigRSA_X931 (Just D_SHA1)
  -- Interop: the backend replays the CLI's deterministic bytes and
  -- verifies the CLI's vector (same RSA-2048 key as v1.5).
  s1 <- expectOk "x931 sign kat" =<< sign env raw priv x931Digest
  assertEqual "x931 kat" x931Sig s1
  s2 <- expectOk "x931 resign" =<< sign env raw priv x931Digest
  assertEqual "x931 deterministic" s1 s2
  expectOk "x931 verify kat" =<< verify env raw pub x931Digest x931Sig
  expectAuthFailed "x931 tampered sig rejected" =<<
    verify env raw pub x931Digest (BS.init x931Sig <> "X")
  expectAuthFailed "x931 wrong digest rejected" =<<
    verify env raw pub (BS.replicate 32 0x55) x931Sig
  -- Every other hash-id length roundtrips (20/48/64 bytes).
  mapM_ (rawRoundtrip env priv pub) [20, 48, 64]
  -- Off-rule lengths refuse typed (28-byte SHA-224 has no X9.31
  -- hash id — the provider rejects it, proven by probe).
  expectUnsupported "x931 28-byte refused" =<<
    sign env raw priv (BS.replicate 28 0xAA)
  expectUnsupported "x931 16-byte refused" =<<
    sign env raw priv (BS.replicate 16 0xAA)
  expectUnsupported "x931 empty refused" =<< sign env raw priv BS.empty
  -- The SHA-1 row hashes inside the backend and roundtrips.
  msig <- expectOk "x931-sha1 sign" =<< sign env sha1 priv "SHA1 X9.31 interop message"
  assertEqual "x931-sha1 sig length" 256 (BS.length msig)
  expectOk "x931-sha1 verify" =<< verify env sha1 pub "SHA1 X9.31 interop message" msig
  expectAuthFailed "x931-sha1 wrong msg rejected" =<<
    verify env sha1 pub "tampered message" msig
  -- Off-rule digested rows refuse; garbage DER is a bad key.
  expectUnsupported "x931-sha224 digested refused" =<<
    sign env (SigRSA_X931 (Just D_SHA224)) priv "message"
  expectBadKey "x931 sign garbage priv" =<< sign env raw (KeyDer "bogus") x931Digest
  expectBadKey "x931 verify garbage pub" =<<
    verify env raw (KeyDer "bogus") x931Digest x931Sig
  where
    rawRoundtrip env priv pub n = do
      let d = BS.pack (take n (cycle [0x31, 0xA7, 0xE2, 0x09]))
          label = show n ++ "-byte"
      s <- expectOk ("x931 sign " ++ label) =<< sign env (SigRSA_X931 Nothing) priv d
      assertEqual ("x931 sig length " ++ label) 256 (BS.length s)
      expectOk ("x931 verify " ++ label) =<< verify env (SigRSA_X931 Nothing) pub d s

casePoly1305Vector :: IO ()
casePoly1305Vector = withBackend $ \env -> do
  let key = KeyBytes polyKey
  -- KAT: the backend tags the CLI/pyca bytes exactly.
  tag <- expectOk "poly1305 kat" =<< macSign env MacPoly1305 key polyMsg
  assertEqual "poly1305 tag" polyTag tag
  assertEqual "poly1305 tag length" 16 (BS.length tag)
  expectOk "poly1305 verify kat" =<< macVerify env MacPoly1305 key polyMsg polyTag
  expectAuthFailed "poly1305 tampered rejected" =<<
    macVerify env MacPoly1305 key polyMsg (BS.init polyTag <> "X")
  expectAuthFailed "poly1305 wrong msg rejected" =<<
    macVerify env MacPoly1305 key "tampered message" polyTag
  -- Key independence: a second key tags differently.
  tag2 <- expectOk "poly1305 second key" =<<
    macSign env MacPoly1305 (KeyBytes (BS.replicate 32 0x11)) polyMsg
  assertBool "poly1305 keys differ" (tag2 /= tag)
  -- Off-length keys refuse at the provider (native error, never a tag).
  expectNative "poly1305 short key refused" =<<
    macSign env MacPoly1305 (KeyBytes (BS.replicate 16 0x11)) polyMsg
  expectNative "poly1305 long key refused" =<<
    macSign env MacPoly1305 (KeyBytes (BS.replicate 64 0x11)) polyMsg

caseEcdsaKat :: IO ()
caseEcdsaKat = withBackend $ \env -> do
  let pub = KeyDer ecPubDer
      derSpec = SigECDSA { sigEc = p256der, sigEcDigest = Just D_SHA256 }
      rawSpec = SigECDSA { sigEc = p256raw, sigEcDigest = Just D_SHA256 }
  expectOk "verify fixed DER" =<< verify env derSpec pub ecMsg ecSigDer
  expectOk "verify fixed RAW" =<< verify env rawSpec pub ecMsg ecSigRaw
  -- Cross-check: the test's own DER parser recovers the same r || s.
  case parseDerEcdsa 32 ecSigDer of
    Nothing -> assertFailure "test DER parser rejected the fixed signature"
    Just (r, s) -> assertEqual "raw == parsed der" ecSigRaw (pad32 r <> pad32 s)
  where
    p256der = mkEc "P-256" "DER"
    p256raw = mkEc "P-256" "RAW"

caseEcdsaRoundtrip :: IO ()
caseEcdsaRoundtrip = withBackend $ \env -> do
  (priv, Just pub) <- expectOk "gen p-256" =<< generateKey env (GenEC (mkEc "P-256" "DER"))
  let derSpec = SigECDSA { sigEc = mkEc "P-256" "DER", sigEcDigest = Just D_SHA256 }
      rawSpec = SigECDSA { sigEc = mkEc "P-256" "RAW", sigEcDigest = Just D_SHA256 }
  sigD <- expectOk "sign DER" =<< sign env derSpec priv ecMsg
  assertBool "der parses" (parseDerEcdsa 32 sigD /= Nothing)
  expectOk "verify DER" =<< verify env derSpec pub ecMsg sigD
  sigR <- expectOk "sign RAW" =<< sign env rawSpec priv ecMsg
  assertEqual "raw is exactly r||s" 64 (BS.length sigR)
  expectOk "verify RAW" =<< verify env rawSpec pub ecMsg sigR
  -- Tampered signatures fail authentication, never verify.
  let tamper bs = BS.init bs <> BS.singleton (BS.last bs + 1)
  expectAuthFailed "tampered DER" =<< verify env derSpec pub ecMsg (tamper sigD)
  expectAuthFailed "tampered RAW" =<< verify env rawSpec pub ecMsg (tamper sigR)

caseEcdsaCurvesVectors :: IO ()
caseEcdsaCurvesVectors = withBackend $ \env -> do
  -- Interop: the CLI's P-384/SHA-384 and P-521/SHA-512 bytes verify.
  let s384 = SigECDSA (mkEc "P-384" "DER") (Just D_SHA384)
      s521 = SigECDSA (mkEc "P-521" "DER") (Just D_SHA512)
  expectOk "verify cli p384" =<<
    verify env s384 (KeyDer ecP384Pub) ecMsg384 ecSig384
  expectOk "verify cli p521" =<<
    verify env s521 (KeyDer ecP521Pub) ecMsg521 ecSig521
  -- Interop on the new families: Koblitz, brainpool, binary.
  let sK256 = SigECDSA (mkEc "secp256k1" "DER") (Just D_SHA256)
      sBp256 = SigECDSA (mkEc "brainpoolP256r1" "DER") (Just D_SHA256)
      sT283 = SigECDSA (mkEc "sect283r1" "DER") (Just D_SHA256)
  expectOk "verify cli k256" =<<
    verify env sK256 (KeyDer ecK256Pub) ecMsgK256 ecSigK256
  expectOk "verify cli bp256" =<<
    verify env sBp256 (KeyDer ecBp256Pub) ecMsgBp256 ecSigBp256
  expectOk "verify cli t283" =<<
    verify env sT283 (KeyDer ecT283Pub) ecMsgT283 ecSigT283
  expectAuthFailed "p384 tampered" =<<
    verify env s384 (KeyDer ecP384Pub) ecMsg384 (BS.init ecSig384 <> "X")
  -- Interop on BLAKE2B-512: the CLI's P-256 bytes verify.
  let sB2 = SigECDSA (mkEc "P-256" "DER") (Just D_BLAKE2B512)
  expectOk "verify cli blake2b512" =<<
    verify env sB2 (KeyDer ecB2Pub) ecMsgB2 ecSigB2
  expectAuthFailed "blake2b512 tampered" =<<
    verify env sB2 (KeyDer ecB2Pub) ecMsgB2 (BS.init ecSigB2 <> "X")
  expectAuthFailed "t283 tampered" =<<
    verify env sT283 (KeyDer ecT283Pub) ecMsgT283 (BS.init ecSigT283 <> "X")
  -- Raw interop: the CLI's raw P-256 bytes verify under the raw row.
  let sraw = SigECDSA (mkEc "P-256" "DER") Nothing
  expectOk "verify cli raw" =<<
    verify env sraw (KeyDer ecPubDer) ecRaw32 ecRawSig
  expectAuthFailed "raw tampered" =<<
    verify env sraw (KeyDer ecPubDer) ecRaw32 (BS.init ecRawSig <> "X")
  -- Raw input bounds follow SEC1: 33 bytes on P-256 truncates
  -- to the leftmost 256 bits (a verdict input, never a refusal).
  sig33 <- expectOk "raw overlong sign truncates" =<<
    sign env sraw (KeyDer ecPrivDer) (BS.replicate 33 0)
  expectOk "raw overlong verify truncates" =<<
    verify env sraw (KeyDer ecPubDer) (BS.replicate 33 0) sig33
  -- Roundtrips: every (curve, digest-or-raw, encoding) signs and
  -- verifies its own output (fresh randomness each call).
  (p384, Just q384) <- expectOk "gen p384" =<<
    generateKey env (GenEC (mkEc "P-384" "DER"))
  (p521, Just q521) <- expectOk "gen p521" =<<
    generateKey env (GenEC (mkEc "P-521" "DER"))
  (p256, Just q256) <- expectOk "gen p256" =<<
    generateKey env (GenEC (mkEc "P-256" "DER"))
  mapM_ (roundtrip env p384 q384 "P-384" 96)
    (Nothing : map Just
      [ D_MD5, D_SHA1, D_SHA224, D_SHA256, D_SHA384, D_SHA512
      , D_SHA512_224, D_SHA512_256
      , D_SHA3_224, D_SHA3_256, D_SHA3_384, D_SHA3_512
      , D_RIPEMD160
      , D_BLAKE2B512
      ])
  mapM_ (roundtrip env p521 q521 "P-521" 132)
    [Nothing, Just D_SHA256, Just D_SHA512, Just D_SHA3_512]
  mapM_ (roundtrip env p256 q256 "P-256" 64)
    [Nothing, Just D_SHA1, Just D_SHA256, Just D_SHA512, Just D_SHA3_256]
  -- Roundtrips on every new curve (real keygen each): the raw
  -- length pins the coordinate width end to end.
  mapM_ (\(curve, rawLen) -> do
    (p, Just q) <- expectOk ("gen " ++ curve) =<<
      generateKey env (GenEC (mkEc curve "DER"))
    mapM_ (roundtrip env p q curve rawLen)
      [Nothing, Just D_SHA256, Just D_SHA512]
    ) newCurveLens
  where
    newCurveLens :: [(String, Int)]
    newCurveLens =
      [ ("secp160r1", 40), ("secp160r2", 40), ("secp160k1", 40)
      , ("secp192r1", 48), ("secp192k1", 48)
      , ("secp224r1", 56), ("secp224k1", 56), ("secp256k1", 64)
      , ("brainpoolP224r1", 56), ("brainpoolP256r1", 64)
      , ("brainpoolP320r1", 80), ("brainpoolP384r1", 96)
      , ("brainpoolP512r1", 128)
      , ("sect283k1", 72), ("sect283r1", 72)
      , ("sect409k1", 104), ("sect409r1", 104)
      , ("sect571k1", 144), ("sect571r1", 144)
      ]
    roundtrip env priv pub curve rawLen digest = do
      let derSpec = SigECDSA (mkEc curve "DER") digest
          rawSpec = SigECDSA (mkEc curve "RAW") digest
          label = curve ++ "/" ++ show digest
          input = if digest == Nothing then BS.replicate (rawLen `div` 2) 0x5a else ecMsg
      sigD <- expectOk ("sign DER " ++ label) =<< sign env derSpec priv input
      assertBool ("der parses " ++ label) (parseDerEcdsa (rawLen `div` 2) sigD /= Nothing)
      expectOk ("verify DER " ++ label) =<< verify env derSpec pub input sigD
      sigR <- expectOk ("sign RAW " ++ label) =<< sign env rawSpec priv input
      assertEqual ("raw length " ++ label) rawLen (BS.length sigR)
      expectOk ("verify RAW " ++ label) =<< verify env rawSpec pub input sigR

-- | SEC1 truncation on the raw row: PKCS#11 §2.3.1 / SEC1
-- §4.1.3 sign and verify the leftmost min(N, n) bits when the
-- input is longer than the group order — overlong input is a
-- verdict input, never a parameter refusal.
caseEcdsaRawTruncate :: IO ()
caseEcdsaRawTruncate = withBackend $ \env -> do
  let sraw = SigECDSA (mkEc "P-256" "RAW") Nothing
      long = ecRaw32 <> BS.replicate 32 0xA5
  sigL <- expectOk "sign 64B on P-256 truncates" =<<
    sign env sraw (KeyDer ecPrivDer) long
  assertEqual "truncated sign is r||s" 64 (BS.length sigL)
  expectOk "verify 64B with its own sig" =<<
    verify env sraw (KeyDer ecPubDer) long sigL
  -- Cross: a signature over the 32-byte prefix verifies against
  -- the 64-byte input (same leftmost 256 bits).
  sigP <- expectOk "sign 32B prefix" =<<
    sign env sraw (KeyDer ecPrivDer) ecRaw32
  expectOk "verify truncates to the prefix" =<<
    verify env sraw (KeyDer ecPubDer) long sigP
  -- Negative: a wrong prefix still mismatches after truncation.
  expectAuthFailed "verify wrong prefix mismatches" =<<
    verify env sraw (KeyDer ecPubDer)
      (BS.replicate 32 0x5A <> BS.replicate 32 0xA5) sigP
  -- Non-aligned order (P-521: 521 bits): a 66-byte input keeps
  -- the leftmost 521 bits — the low 7 bits of the last byte are
  -- masked away, so inputs differing only there are identical.
  (p521, Just q521) <- expectOk "gen p521" =<<
    generateKey env (GenEC (mkEc "P-521" "DER"))
  let sraw521 = SigECDSA (mkEc "P-521" "RAW") Nothing
      hi = BS.replicate 65 0x33 <> BS.singleton 0x80
      lo = BS.replicate 65 0x33 <> BS.singleton 0xFF
  sig521 <- expectOk "sign 66B on P-521 truncates" =<<
    sign env sraw521 p521 hi
  assertEqual "p521 truncated sign is r||s" 132 (BS.length sig521)
  expectOk "verify masked-away bits ignored" =<<
    verify env sraw521 q521 lo sig521

-- | Degenerate-math verdict: the point-at-infinity fixture
-- verifies as a mismatch (X9.62 §7.4.2 rejects), never a native
-- malfunction — even though OpenSSL reports rc -1.
caseEcdsaInfinity :: IO ()
caseEcdsaInfinity = withBackend $ \env -> do
  let sraw = SigECDSA (mkEc "brainpoolP224r1" "RAW") Nothing
  assertEqual "fixture sig is r||s" 56 (BS.length ecInf224Sig)
  expectAuthFailed "infinity fixture mismatches" =<<
    verify env sraw (KeyDer ecInf224Pub) ecInf224Digest ecInf224Sig

-- | An odd-length raw signature cannot split into halves and can
-- never be valid: a mismatch verdict, like malformed DER — not a
-- parameter refusal.
caseEcdsaOddSig :: IO ()
caseEcdsaOddSig = withBackend $ \env -> do
  let sraw = SigECDSA (mkEc "P-256" "RAW") Nothing
  expectAuthFailed "63-byte raw sig mismatches" =<<
    verify env sraw (KeyDer ecPubDer) ecRaw32 (BS.replicate 63 1)

-- | The curve allowlist: a well-formed brainpoolP160r1 key (real
-- but uncollected) refuses typed on both sign and verify (the
-- driver only hints the curve label, so the backend re-checks
-- before any native call). Garbage DER refuses the same way.
caseEcdsaOffCurve :: IO ()
caseEcdsaOffCurve = withBackend $ \env -> do
  let ecdsaSpec = SigECDSA (mkEc "P-256" "DER") (Just D_SHA256)
  expectBadKey "bp160 sign refused" =<<
    sign env ecdsaSpec (KeyDer ecBp160Priv) ecMsg
  expectBadKey "bp160 verify refused" =<<
    verify env ecdsaSpec (KeyDer ecBp160Pub) ecMsg ecSigDer
  expectBadKey "garbage sign refused" =<<
    sign env ecdsaSpec (KeyDer "bogus") ecMsg
  expectBadKey "garbage verify refused" =<<
    verify env ecdsaSpec (KeyDer "bogus") ecMsg ecSigDer

-- | DSA fixtures: CLI-generated (2048,224) keypair (pinned
-- @openssl dsaparam/gendsa@, PKCS#8 private half) plus a CLI
-- SHA-256 signature over 'dsaCliMsg' (cross-implementation KAT),
-- and the wycheproof (2048,256) group-0 SPKI with tc59 (valid)
-- and tc1 (invalid: r+q) P1363 vectors from
-- @dsa_2048_256_sha256_p1363_test.json@.
dsaCliPub :: ByteString
dsaCliPub = hex $ concat
  ["308203423082023506072a8648ce380401308202280282010100887ba402e537402944fc0b99930fe8dc2cf648f063ca5c40e7d8679f3c58"
  , "4d93125abf9d8e21daba7f1b64c8ed6e11ace9bb78ad66d71c71cdc2f3c0ea4341c174006c80f5833311dfd6dd7e902dc806ce1e470e9dfa"
  , "4fb7581b744b9412c42948d9f5c98cd2a9b3dabb058a6eb9d4adaa11ebf79cc665acaea98729ff6bab6172db75ef22dc55a440f0f89c4a0d"
  , "018756eb9077b6bad92500238caefe7bb42080a3f071340b8cf8c4ec8128dbad5352fec210030d649a172802d2f92763c02d051c97114d01"
  , "562cc82c8a40d5de28cab2e311a3e6842eaf990d3cb26096ed7a495b81e82472f770b0201a8aea0c27ecf5f6e711f2356f8f262d71cf4c6f"
  , "91fb021d00f9db1760fb0a352f4fed24e43fb2905f7156d7d425fb3a392468cc4102820100122cdd506b17ee6999e5874f3426a4540ba2be"
  , "d03c654b69149cad7cac01bbc0124f3881ea856b420eb5ec1d9d4a77b6c364d00161d711a32bc8edcc900233dce8814a56758f6e7caba971"
  , "e135b82d9b37a77e01cae0f7f38249578fec4f78dfaf64f372dd3bbd64ca8448199b30fbf44551f2a13b48c2e9a890cb715d87ea7a8060cc"
  , "8eb36afaa5b9cc89f7947b6345d482bff613b12cadf1cfa006b5694a6bb501ae76c9e759667a53f635757a5db97f50acf4447962b18ac91c"
  , "e966ed96cf0d6b52c9d5eeb049c634917cd450b24627ec12f2d8818f179b4df221d999e75e6835147abf4b0b68956b4db9d85fab096bdf9a"
  , "fac381c367ed0f1143f0ea87c303820105000282010060b8ba1b907936a778f3eb7027a6a6fdecc1ee0ae417fcec01aefbedb60e48bb4999"
  , "e10d49efcb2db0ada5c429212c8b52f59ecf71982c619a573b42ad63a94dcce71166ee4a9575a0c9188311194f7207f5fb91ff89ac8b11a0"
  , "b2119f6a0b67da8c5e073f0ad05da9c36a7b1bb7d731b91960d65e361c5e5d2d001d46586b54bbc40a3fa1d1a80db188b5b8deea97ac53e1"
  , "76972607ecf8c4dd96a3ed2d7d2817b32ac62c3899470ae8e30412eef07098ab75be9269570d3dfb4bc9db68df75398aee11f2218bcf7dca"
  , "414048a25ac59f8df695e435d0fb0e4a327063fc86bada9db51cc7b1f176f35ce11a985ae2e5a7b2e61bb55af290866fe2099f1050a9"
  ]

dsaCliPriv :: ByteString
dsaCliPriv = hex $ concat
  ["3082025b0201003082023506072a8648ce380401308202280282010100887ba402e537402944fc0b99930fe8dc2cf648f063ca5c40e7d867"
  , "9f3c584d93125abf9d8e21daba7f1b64c8ed6e11ace9bb78ad66d71c71cdc2f3c0ea4341c174006c80f5833311dfd6dd7e902dc806ce1e47"
  , "0e9dfa4fb7581b744b9412c42948d9f5c98cd2a9b3dabb058a6eb9d4adaa11ebf79cc665acaea98729ff6bab6172db75ef22dc55a440f0f8"
  , "9c4a0d018756eb9077b6bad92500238caefe7bb42080a3f071340b8cf8c4ec8128dbad5352fec210030d649a172802d2f92763c02d051c97"
  , "114d01562cc82c8a40d5de28cab2e311a3e6842eaf990d3cb26096ed7a495b81e82472f770b0201a8aea0c27ecf5f6e711f2356f8f262d71"
  , "cf4c6f91fb021d00f9db1760fb0a352f4fed24e43fb2905f7156d7d425fb3a392468cc4102820100122cdd506b17ee6999e5874f3426a454"
  , "0ba2bed03c654b69149cad7cac01bbc0124f3881ea856b420eb5ec1d9d4a77b6c364d00161d711a32bc8edcc900233dce8814a56758f6e7c"
  , "aba971e135b82d9b37a77e01cae0f7f38249578fec4f78dfaf64f372dd3bbd64ca8448199b30fbf44551f2a13b48c2e9a890cb715d87ea7a"
  , "8060cc8eb36afaa5b9cc89f7947b6345d482bff613b12cadf1cfa006b5694a6bb501ae76c9e759667a53f635757a5db97f50acf4447962b1"
  , "8ac91ce966ed96cf0d6b52c9d5eeb049c634917cd450b24627ec12f2d8818f179b4df221d999e75e6835147abf4b0b68956b4db9d85fab09"
  , "6bdf9afac381c367ed0f1143f0ea87c3041d021b17d4566d451940d21d58ac3059302cb8dabcdf2a80adaf36f21bd0"
  ]

dsaCliMsg :: ByteString
dsaCliMsg = hex "4453412066697874757265206d657373616765"

dsaCliSigDer :: ByteString
dsaCliSigDer = hex "303d021c2cf49ba16d76c738ce1d586bc5d5c24d24b5278f66167cd432b72e75021d009d247ced58ddc6591799508425029b03f145a3a9dff66d77ef68c2ce"

-- | EdDSA fixtures: Wycheproof ed25519 vectors (TEST 1 tcId 80,
-- group0 tc1 valid + tc10 invalid) copied from
-- @testvectors_v1/ed25519_test.json@ (SPKI-wrapped here for the
-- backend's KeyDer shape); a CLI cross-implementation KAT (pinned
-- @openssl pkeyutl@ over the KeyImportSpec Ed25519 key); and a
-- pinned-CLI Ed448 keypair for roundtrips.
edWyT1Pub :: ByteString
edWyT1Pub = hex $ concat
  ["302a300506032b6570032100d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
  ]

edWyT1Msg :: ByteString
edWyT1Msg = hex ""

edWyT1Sig :: ByteString
edWyT1Sig = hex $ concat
  ["e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46b"
  ,"d25bf5f0595bbe24655141438e7a100b"
  ]

edWyG0Pub :: ByteString
edWyG0Pub = hex $ concat
  ["302a300506032b65700321007d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa"
  ]

edWyG0Msg :: ByteString
edWyG0Msg = hex ""

edWyG0Sig :: ByteString
edWyG0Sig = hex $ concat
  ["d4fbdb52bfa726b44d1786a8c0d171c3e62ca83c9e5bbe63de0bb2483f8fd6cc1429ab72cafc41ab56af02ff8fcc43b9"
  ,"9bfe4c7ae940f60f38ebaa9d311c4007"
  ]

edWyBadMsg :: ByteString
edWyBadMsg = hex "3f"

edWyBadSig :: ByteString
edWyBadSig = hex $ concat
  ["000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
  ,"00000000000000000000000000000000"
  ]

edCliPriv :: ByteString
edCliPriv = hex $ concat
  ["302e020100300506032b657004220420e48c12f6fd3bd16c24e972eab3910d1053a23f9db0113d10d0835223f638dd05"
  ]

edCliPub :: ByteString
edCliPub = hex $ concat
  ["302a300506032b6570032100e3066819aa9f7d91c3c4ebad5584adeef588d8a1cbf2a09a8081d41cc5183402"
  ]

edCliMsg :: ByteString
edCliMsg = "eddsa cli kat message"

edCliSig :: ByteString
edCliSig = hex $ concat
  ["6b88ff1978856a802dd75dc694a6435d3df4da2909d43a00e5ec3718a7cce79cdeafacceabe5a05eb676f8315e9ca793"
  ,"0a9b1d6497562a3d650cb07cc20ce30e"
  ]

ed48Priv :: ByteString
ed48Priv = hex $ concat
  ["3047020100300506032b6571043b04398217a8d0ea3724199e10d866da9b2f582ce7c9a8aa37ad7763df96d48c210c1c"
  ,"3ef3fe87ad7ce40306f70747dfee39a799cd1a0ecb1481f9e1"
  ]

ed48Pub :: ByteString
ed48Pub = hex $ concat
  ["3043300506032b6571033a0086328bf04c3d241a0f05968cee630c68cdd2e2378a2f63e01ec215a661c7f83dddfddc78"
  ,"8c1102a2529c68b8d3c0155ec9e263561e2545d280"
  ]

dsaWyPub :: ByteString
dsaWyPub = hex $ concat
  ["308203463082023906072a8648ce3804013082022c0282010100faa45850a6f185cff01790524f60c6867461578fcb013cf340fe495b43b4"
  , "6acc759c0d2f61bfaef901f510274298876f3048f41d13697ccb77fb540ed0b3fbc7a60a3c97297310fa929d90837eeb6ed0ee82a36c5f4c"
  , "9dc4e2ea07d20f27675c48152abdf6f6dba66cfd8f58aed85d77ae8bb367b1348a5f46099d511507ad6575bbf8ec6ba48baa620cdcf1bd2e"
  , "c7aaafeae6d98d235921203af64814163cdd11424968f5ab77fad662306eea7ee69792f2b5d39d658ab9d927f368e68363ac18178e304096"
  , "33c4d488fb1fb92d22bca9214a4dfb720f28f4511f9be42e53e7f907d2d41f92bac9ca5e87580082390bbd0c229b2dc7e899aed654f7df06"
  , "2cf9022100fefbe4917b5ea7dbb3d5c62dc15bf430d8464813d2431819fe556832c3889d2f0282010038971fbfad52d9e8a84a2c17ed90cc"
  , "ff311648100e962c3269be255cab1471507ba40f457f5fb7990f6591b72b146e65213c619275b9b58d7597f41b42c55535592301e35b3a46"
  , "9dd5b204d70ccdd3cd477f65bd0f52eae53578fee143a43ae68b725c3c324fc91a84ecb7489dc67346ad11f3a0afdea009ce53201fa12207"
  , "aea5b4461ab0ffaa801beab94f648797aa1192be18345b270435ccb4678ce663c7bf35f7a7a3c98fc4907bd12701230469a18e3ae6327aca"
  , "d29dac259bc5f5e912e64fe7ad0364af74ecace858cbf7a36a1dac9f9ddc7665fb7c639019971cc2691e2b586666691914b4f3785ef0d1a8"
  , "3f34a8130ed29724ce443493fceee25aa7038201050002820100669300e7128ef31a126fb015c525596a21bbd43082f8ca6d6f7a9974e482"
  , "5085d1a50092956cd02016206c572d43eb90146f384454ac7f185f85af8855efcd3b9116c14e4ff859e07b2dad84f91fe23d7c09945368db"
  , "0ab30fff942741fcfa40f39ea82596370149bf168b79ef3067ba883ee3af6025465a79e96de11bd2f7f6eda740398ef4347ee4551b857128"
  , "1272f5cb83b0356f37e3ed5a19b084dff5156a3c78f8fdc3ccb5b3db431aa08a280c4a9da780aa4eeca8fb74ed7135b1370121c15328f17e"
  , "0504ea2e2c68e2e53268f875f17ce3cabd34e77866711c68c711a8ea4fa136a685cd07f5fff584d6c813cf3bffd0d705795998562b9235e6"
  , "1430"
  ]

dsaWyMsg :: ByteString
dsaWyMsg = hex "313233343030"

dsaWySig :: ByteString
dsaWySig = hex "3be2ad698f533f614e3a51d78516e1351c3290f3804f5a9f71e91957c3cddbe2be73fbe8557f552300c7419f25c44e7f0f9fd1e46bd4f3425e1618d320fd5ae6"

dsaWyBadSig :: ByteString
dsaWyBadSig = hex "01aace8c171d789060b16c9f594c85ae5c412aeea77ddf626fd7e20a7da13b0edc005bf17d17a8d9172cab83df9e56cccce8f282e35bbdbe99eadf8bc20ae9722c6f"

-- | ML-DSA fixtures: wycheproof group-0 SPKIs (publicKeyDer) with
-- tc1 (valid, pure, "Hello world") and the ML-DSA-44 tc3
-- (valid, context "Context") signatures, embedded verbatim.
mldsaWyPub44 :: ByteString
mldsaWyPub44 = hex $ concat
  ["30820532300b06096086480165030403110382052100db9ac67708f2ba0fac1f92bd802f9be89ecab966feef59872a1a9ac9"
  ,"0b1111170a561290ae86b13968f2506023c014ba09fa449a26e4e9d35595e73986506cc8790e4d07a94d6c736f7ae78cc5e3"
  ,"e3cf025ce06a09252bef97fe92e94cbd107b1844d1a7c690d88bff9e9336f8f58e0bd5ee384de9c7ffbb149a6fcd87c77288"
  ,"601d8843e28e0c7a60149d02ebc57b183c39888d98b61cd8ad48135ddb8a1666743bb689f44c1a92d52017b6a8fa493eeb83"
  ,"9dffb086a9a6c399b194a52f0e4164c96ff8a2a54337de24350a866b5fe4195257778e72511221778f1eae5fa93ed3532f69"
  ,"6b9b0767aded85f62ea311027c7f5fc4182dcd2864b1c26bd6dcf72ebdedf70471327be0ea1c2ae53e46489c6dbefa512a78"
  ,"fdd7be0ad3ada16a7f7b1ece49817b44868a2cc234bfdba556c32cc92ec2c5e8a5d206f2e4ee372d41681e67d1b7e7b00618"
  ,"70c57f600fafca85f98aed8ce4ba76bba961f9ed56e563220d3ced853b6b28e7527da0e0912bc932a23c8bab811429bbb4d4"
  ,"9b2770bcda44abb932b11c0a5866409fce39fed2b459c86c8f6e1ab0aefc5879503f4b21a49b4b2de6760c9b6aaf041144a6"
  ,"56a26af39f4578e1d482ddc1360ef751d9784b860ec373d415360fe99f32e126a2ac1243430e8bed1bc90b19b3d219c2712e"
  ,"dcf81c44b4331f6421088e662b695e1fd8fa5091f616ab60af70f159b63368f1ac60d77b279ed47ef7f24ec2044bb6c2bc76"
  ,"d933ecd568f7e663392afc1d335abac6c03670adf87747dde90052f5cd45f7d30f43a4dc3c500ceb658fce235c171240baca"
  ,"1b5a14733d774b9416c540f53eb83481afc98344b12a4309e6222b08d978430467497010314c6f6b8caf65361c2161063952"
  ,"75a67d7500dbc120f7918c6f8db7aa63fa965b4a22c70dc88f727d768ce2bfc7597fd470184e1c59a6b2e1204cc8c3d052c5"
  ,"94d5771e0ccc8cfb191f47038b1c0672f07caf4747562d3d76a9816fb1def1391cf0f05fcdbf2a0eb6c21ac24b26e74ee403"
  ,"133e80a79313ddb02c1fa386c6dd1d420195343e3a104aff6d60887f7304fa9e3bb59bb55f820dd85b1445c54e9a38dc1c7f"
  ,"3b88eb36a9f48d13455e51c934825ff3cd8bedb2b5422344120399eef83a360b83440ebdd8ea6e01c95159e3735bb4408500"
  ,"caa785ca4049891c7331c4ea31ad9060ece768fd339e6904f88e27bad3b28845687be2cc9314f300fda56fe3ff2508e54c59"
  ,"123b068f86fe00213d5af8da1b1735423ed688f097c306dbc121b81f532fcaf872d9f80596642295d6e4bead478644081618"
  ,"ab903b39e9b5e7cc0b5f2742d8337b18d4ad4788db7443e946cafc1762a5da84070e8c2fd86d6c633f0b44ee234ba11b9e14"
  ,"40c94a08d0437015279690405353059020fd2f58f15dab18754177244adfb81ceab79c7840bf3884a3d364afc8c453a425fd"
  ,"8c5378eaa7445f8c6256bfbd03a66c53e8cf27e2c52f14ef3294afe79cda408f5dff933ca0211a78a4e3be3d9a932558ed71"
  ,"ed19bbb57f87937fa3d4a78128491ff096a261045bdd186325c42caa8c7564195a4d2499a1c17d21a52d1aacd221d9c8a186"
  ,"6963a20390f2fd43dcf56b308a1c01c38091fd3e04c12b695de497d48bcc268d50cb0bed793b8e6937e8d533afd568521f1c"
  ,"9377a3804d38e785674d7ce868d289938e33dda6edc76d25b15fcb38852b7803cfe62f08d9fbd070957c4e6f134973964c9d"
  ,"c009985c8501e7d8f72e7ec285d5289fdd07f64d62acaa9737b039efa7a9d1d175577c6bcf9dddcf692877af38e75263bebe"
  ,"2453155be61f0723c274388a532abe29dd7023e327085f4c9dda41839b7b3357ab9d"
  ]

mldsaWySig44 :: ByteString
mldsaWySig44 = hex $ concat
  ["1aa69cb5ed35204534f25f40a17eb0d767f8981f5e7cec46d3bf3252bfc78e09d02ef0c82da6dde973611c84947289010615"
  ,"8cb15ffa6ca891615e888efa0d2d8a121b75ca440228ad32991be34249620f158ffd6f74d7b03bf919218ce259b500808ec1"
  ,"57ead67b56b79e9e6607eafb9227b8a30adbec087d35bc1aec2f1a0c4dd126dfcfb9fbf0bd74fb1e092495fa994ab5a7cd13"
  ,"33281aafe834694a6dc11e889c762b5645638e172dfab3060031ebcdc1fd455d5de6050bf71b074a4dd34af5ebf15487651f"
  ,"0f13e5d3cee231b9b347810bfc418196df9d7231780c09171b9aae732bea27a1649d8c03220f417e30a016b08ccb1d55c933"
  ,"7b4812e20e04523f5d29a760a01b3a80d76285521206481ee1e44df09a76913ba54ae50c8eb973a3ced73950fbf39c4c0c12"
  ,"62a216821a442072c10cc82839ac57b898411be9e810f893272a2546ff7d1d920f146210efc2b4528bc98a099a398302d301"
  ,"fc1dea31b3d8ff78246a66f690ef536b68e02bd7ea23a5378930dde7f1beb51749896a7944e5a40e6fbbb1f76c3fda09e32e"
  ,"0a58062c24cac7ddb8c1d2cbb352a81e336425c5f551246db45ecd0ab29dac88cdebf51c60bebc2e27c974f56da12c1fec4f"
  ,"5745850429b607f5ed7cd821f2c91fc2dda8c2c8e8ec278d1b2a5bf50ec70c5623fc681b4d1dccff96b324cb53ff97470f9d"
  ,"e177c2006a89af8f18603a6d4ea2625794695fe79cd30318a1e76307a4c2a353db1e076ad9b609a2489b94cb6dd821c3af31"
  ,"046bb7a5d43d190e09fce4969fe4e93c8393975e64cb2d9c2294fc427ef5191c40937929b3b0e1b037e6b84cc0299d5af2b5"
  ,"410118bfd88ef6491af6f21233390ca7a19f1576e6c5a10a673796905562075047896e3a2379f64dfbbc12b9bfe64939c2d0"
  ,"5efbc5f6e4b5ca69ce1ed4b7d25e8c835b0612b33e13ed7a8a7233b4b3d58eead0bc4c841acb65a5ec0ed45e2584c23c2a16"
  ,"2392b5789c62358e4038864e20c10e10c67d940ce78993178dbeb3de1fea1e50e7c29f4d7d938c3bfe50229ea040102f30d5"
  ,"b3a64cb8e13420065d54a1ac50a77383bdff3cae2340ebf15a1557fde897007c1b67d04f19431ca00cb0f08db87e90e166e0"
  ,"f4ce6fd69c6ecef1b3f70d9eb601b57a7bf931057c2afe2d3567b6bbec7891c664713385122fdd789c1d5a8a9cfd491f407c"
  ,"16d0b0c5dfc53a6862208e264b981bf2ddbdd1d7db9729b5265c4c3868a947c982880bc55b786153b89ef3324067b35a928c"
  ,"51236bcbe9f860ad9eee5644478f894a9fe78d26a5a17d482612f1cb9983b864e6fba84591c0f73b7b27918819d2121d4af6"
  ,"40f533e2939d3da0f0aa6b9df80837a80165ae8b7579715192eb0f6cca78a43d8ad8d7abb56d816e3af2de59b88bfdcf6767"
  ,"abfb043d3ae24223d05001953faa292671c57ade1fe28988075ab8d14ac98363412bd694c40ae85b1f104afcd0f25aa590f5"
  ,"7ba4f5dfdf613bf8594e3f54baadfdf50c0881af2475590758a23b7eee725513e4d1ea9f4630159c424a289f18a9879e5e17"
  ,"3390f8e630f6ee2a6043d82a1983dc97c7acfea3b0c03e27e865d810d012daeec28dc454f59334edf24627d435701d329ff5"
  ,"e68d19bbdca5ef7d5e00204fa947d08f81cb6484cabe60989d2f61fbe70940f7e4f449b3fcb103a89143d74b15d72e7913dc"
  ,"e9193a0b9c5a7b2a97bde6d7f396ae80b4b566f9f2e7345bc42ce3b002818e19f0f16416b850832cd02279ee8d58a381deaa"
  ,"c09b1b4d4613f4d066805d2faea6716e015fe361c0526c6e4617a389ffdf930213c1dc0c4c905c3106a7517dce7abea7a934"
  ,"1132f8ad98de3e42f6b75809fff38f6eeafb97398e79d50a5622338763c4e45a88ddda7fb87ab7f5cec61109fdc1c5d4a163"
  ,"10275241fc34178028a49fd79581a05c3b6984eecd6cb9bd60a44da72600f8f2604a4ff4578126194fb2269c8e6e71447445"
  ,"e8e80bf8c6063dbbf29c7ded58abbc0d2eed347bf495b6a9cbe68585a594aa0e65834bfbcccc3f6bf42fe4ef42d86232c3fb"
  ,"1412dd0b5f8a0489958f5c3b883bf7851337a35b13dd2b6517626ff2d1064cd189beb402497dd6b8893d414dde7d1d51018c"
  ,"7a83766a2d8a29b80e8f428237732f7ee5ba878163f0aa8af5b60533b4d4621a38fdc54383acb3325b5e876e21483eddcc64"
  ,"c419596e656d1557be31b530ea66054f79d4f4a755f9ee33c84fed5d552ec5e2eccd061cf4c4b5c3c16a70a7baecccfc208d"
  ,"2430e78621c9ae5b0d080973b4e1df0a1f5c0415db6d3c85f9ea9041e9a9abdde71d6776a522aa957f708b14a33eda10ebba"
  ,"b93bb8ec2b7a04679f38eb44fc558ee698d3c6937e0e647dce898d7599fef6de32ae4d52adc722443610b2126559756aa36f"
  ,"3c79696b99be3d908f780fcbaef33b215693634d63ce2a0777dfbbc899d2be72efdbafbc10aefb26a1a63cdcfda00235b34d"
  ,"b723c91624ee5f939024dfedba0863ad08f648767d41fc7fd6b317c51f4b1b87e21e07d488c9423581f9bbdae43e4d32b37e"
  ,"8283960524f9a601ab69f5cd7fb01c9a8a5c64fe863519a1e9f3426398f691a96e1748491b4e209fca2ab29481a674621c79"
  ,"7614ba16fbfdfd1a4184e7f84667e720e6bcd9debef32c2b9e891a6e3c0423158f539838d8413e9fc707d5c65b23368b6edc"
  ,"95d9c3f8e20bbb844499311614945606c1487ef4015d1e260fa8239abaa071be572163132bdb06ef21e31be0f9d4b6747134"
  ,"e4842bedcd3bf53b0d6f054693bc428e9a715d5a32a79e6a3cb8b81faf2c04087d8816752637a2fe11eacb38341e02484856"
  ,"2a29d4585e4ee56552ce9b1fad43b965a37bff8558921790ef0f4ac55bcac4327d1783f5e1e79bf01e96934bb4a8f5dd06c8"
  ,"3bb70b2377189d622a106100f0cbdd38e34c0565900c616561161b3261859133f83893feb22b0bafc82cf4f0dbafde0648e2"
  ,"f86260e6e747034e5cb3ece98087fbf74179c6306f0c460b5d609b9b3a66761472ee0b9dabb5dfa872d5c6bc9b33461a27b5"
  ,"427bd8833f874f479ecc5f0a20304b9a75aacc82420a87af6469daaef53391ae8a25468e717dc47f464fce45a31147c0c4e1"
  ,"2ac2f834567e4005b0827d13b3ec80cd8b7a907436e6624c6c8ac6a80add35cfa1a28872fb65cb3fa46894d116a052f19b5f"
  ,"e20c7ead10bd24d27ad2b5683f299d1193ec6d9ff3379f3b3e39cb9991831f194af2041085508da4dcb7b8785cbdc4e04cf4"
  ,"d826d1ef4a11036e4c5803c3aaa7669b4dd3bc12ff888984e9bbdace0e772ab59332b47300334757677578808e90929697a9"
  ,"cecfd6ed1b303d4250738a97a0aabac6d91e283a4b696f7181828493aec8cdcfe1eaecfc0227484957595badbcbfc8fa0000"
  ,"00000000000000000000000000000000121f323e"
  ]

mldsaWyPub65 :: ByteString
mldsaWyPub65 = hex $ concat
  ["308207b2300b0609608648016503040312038207a100f5408337d0fee65c28851226a5fa81b58464632c78e2a9bef70d330f"
  ,"2e3a5f74d9cf676aedd1067c91a5dd5d4edc46f868a93ffec9f44e254e44f682a153aeadf228e8db7c5fcfed30cc3408e261"
  ,"ab896876bee56660d2a7c1d7eac20c5754255206a178f7156295065ce7876f90c48f44bc37f3a00e32eefd3a4bb1e298fe28"
  ,"3d106eaef92a33a594253a2a0790976a1d04636f8672d28c06c852ea8bb43b84bff512996e7616963d5b9a2906466a152c7e"
  ,"a9be178be35405683b44367af85d2daad87630c1e21ba5490154f0141780f5ed0407cb0b975dd56d5930f9b26413b843b83f"
  ,"3693304b0038bd3e4bb398868060ea18c9c67099376470a50deb052e4056743fbcdf0341b192663bd1c21ba3b3d5666e0d0e"
  ,"29c4e1ed0759ab0bd9d1d355011b94e0ff0c049b03ddb7138640667144fcacd7265f55a07e5387f1abd30c037cf14d436aa8"
  ,"55f827049215440d8007f61460500d943f57ffb6bfee6fedd2fcec52882d7d8da1aab29e892c8beac3df3234b4a7d2eca3a4"
  ,"5c6623c52bbdd07c1c94314b706988a52029f8f8b06e874b741d72926652c78c6ace2cfd8864eadb2e4b39cafe6e03e4edba"
  ,"fa2747db9bc42f92af8b031e3e380846b1bfd15ade88c285d6a6fffe91eafc8b17de6cbc68575f323cc09fc20e49e8efd76f"
  ,"9568bec486b78df4245428d8d0d5f53873e11de65fda4c770b521a8c67f5c51d48cc26358954514447881fd9a42e5891dac7"
  ,"e1db5249d7861b322111e5fb929bee9ff5e9d5a2667ba93e63fc03040d2e82648f89e89dec1d1d2dfb9efeceb7940f7dcbeb"
  ,"eb5a239cc1c54d8f7d52cba220d0634e15df46a58280bc5a48840bd39274cfde150f9ad9a40f6398d715350925f0e0501944"
  ,"409f32331a362bdaaafb3d8ce71c964332d6afb7e684f99951246d88081c86744ae68133f22c53a4b5ae258f230a98491d2d"
  ,"43a79a6d0f4d54a3b62013965ac7c82d0507125a38a0277f81cbc1d46cef2a131c6f51b88ec0baae0c82a6a0e72831cb06f9"
  ,"116cff5111d597e01057d32805a008f52c9aec3311139bfb35982789ff83bdd0c31e9f1080e8ed8eb99fde66bafb29e33573"
  ,"89fe3785b60c78e229ef073e1b65e34d848bd4d8a4f251551e2d38d2546afbc205d3c6dab34d2b962b1afb44f1d22fc10c67"
  ,"44fcd6b636afd3cb414b16c2e0d708fe9f51ff19120bde693b028b6d1e6dbe37b4b8b3bc7c6f7a842701603869d3ded57250"
  ,"0f085502efc8d3cc62b30e5cdbcb5e86d9c0d42973bf755df539cc0aea58f9148386db67bd2bf70cd12ccd96d5c66fb27141"
  ,"6b772465228dc44b079178f9b766370b66a79b871faca246ca6f8f63be9f0668297ac446cad5cf4a83318b1b00ecbd283f0e"
  ,"ecee60a9a37a27abdbdbe382e307970002837dfc0bd3934ebd008918fd4bd383c02c9d37f694996e989a49075767ebc4a298"
  ,"1ef5275455e026cb0bd70946cdd1fadaf251381d324f9efbb860d1b280c29685bab97d010676273b45cca12ac3966aae342c"
  ,"84e2357eccf252577743b8787967b40b07ef2d3d9e6c1a3bcb059cba0fdb7f0d4f815c242b8e14acd3375e608e9230ba3cf8"
  ,"718f43882a3e1e661a2bbe81830d34741f33473e263b3790abe67acf29f5df44865b2ffbc96975fd62738a64112deda5a253"
  ,"4fb0a23b3b3024df986391badf9041c593c313a7ca1e1fcffcb65b07b9a99337b4a4acf616cbe1553eb9541f38aa62473429"
  ,"05995233a28172ca13396b2a9662970120f82b92a213f43de7a232ccca3268265c9ce042d50915430a6c455f32277da42f99"
  ,"62fb9163b623231ebc080fa7b8e9f9021fcf85b98f9c483e4d2226b9326a5bcb2e7449ef029ae142d3a0f0c28bd4f7e9c51a"
  ,"12e1336f24dfacbc3f808a8f7dd683027bc948763b808fb0037394b8b41bc9b2ec7887e67584e03d11b15ca203b2bcb43f88"
  ,"81638c4e4eee7f846d09c7f89b7739df22b2c3acc235032ba8f7ae27b5b9d25733143e80a4cdde6770719c1e66ec2ce68361"
  ,"2233e88fafff84c0745a98aa1254c8219c6c556348c2b5d1beeb61532d6bf7bde153271dc647460beb65fe0055b33fd6480d"
  ,"cbb9d7d471952cfa5be260c39721a8c5c89b9e966ae2dc9036451ec9f2c49433b2225e13f23e20c2bfba81a7b3a555883449"
  ,"238f7d48213e9f10ce19e76f1bdcfc73ee5524bd7d8be0a4b46784e238233c04fb99383ec7726f9717e1179dd14fba9ad6c2"
  ,"ebd1699f0ab0e57e6cad23875b029e89cfda06f51266ecd2eed4edafb51e82f2a506d57ba74da611774ca5fa2fff4a976519"
  ,"de425885e7d09219cf815b1767d4fc5a72c18918991a285086a6a766614a4d245387da50f28dd778fb33ab88c0918feba376"
  ,"8c55bb1f07aec33cfeed33d6faa4d34fd7227b365533c1e67dbc89f0b20195cf1cbd480d333ade1c9bb28308085b72ced430"
  ,"268c1492a27050c43668adc9cf8b8509447cfcd3c8f8d8eb554f704101786aa9ebca86991d250776a37a1f56fbf7d08e591f"
  ,"978da49c3870625879f70e2418aec5cba32fa8c346fa9038baebc35ad0068a4d03537aee14c2e71570a87490377fa8dd66f9"
  ,"95aa044a522f0c7025a7ab2dd5ad30a64268dc112b7f9fa156df64d631f55f1d6edc55cec570a9c7372e29e02c8d4867bae2"
  ,"49431dcf6ed2794a0183f0f7501201feca4a81d334c642fc8d38e9a90fa77429665e09e214797dfa455ff47c4f219d3a2cb0"
  ,"176bc2236455123c1c5da714ad29d580fb194f87173a18dc"
  ]

mldsaWySig65 :: ByteString
mldsaWySig65 = hex $ concat
  ["69da5aec6d5f58fbf29439c520bd68b966e3dd2ca633b68351c2862344713a1e9c086a44f9a870a3ccc14de62d6c12b278c3"
  ,"54d7197c4d6d7f83d1422b29b250f5ee3fec118311d905e5db2b4b8b23b8d542202d6652f6dc3f9d7ed51f2463082d3f145c"
  ,"fd0fa7ac548a47e91c1ccb1a55b215e90ab355bfc6d67154287b1dfae0fb530264dbb841a7684b396e5ca0459d795216416a"
  ,"9d232bc89b32e0f9461f53107c78e66c8e876554e8ddd501867b55dcfc1fb33f102e03373cdd192640f1027a08ce277b468f"
  ,"6ed0fe80a9d6cd2d6b2f7a3738c8325d95b0ccc6e7b9fb000c923b92298e0867d4a9f6dd5513e8001033c633bb1641ee6634"
  ,"9487224dd43386c7fcc29916332066a868100d46e2c5b8354c28f087a024cba27694afc4c1665e0d72b37686919ad55052cc"
  ,"63a144febe4e2a0c9ae416e064e289f9f69cbb883665d1130826b7b74e30c94a2b98b67b471663e3d66326db3b43bebf958e"
  ,"8665b68eda90e8c5d9494b0c7c9ec48800910dd6d906b1fcd47a0aac462ac87b126d21b5ba150df61f752257ddf5a063b4a5"
  ,"b150371d625535e3b2874b9fe548960ff67931cd6c12496e8213e2ace6fff48e6bdc60310e49389f62579db26b92ad73e9d3"
  ,"f23942cab51784f48b3660b6450caecbb0df2aa4c8e56577f5ea450d2f7f51aacc0b304a62250bf2cae7b99dcd955b659662"
  ,"5d06da1c67f730b706fdba630f00fd891830d251484640b7258ab364d6fd9986878fffa69b7c44b92e43143affae8b098e1d"
  ,"27716850f37553bf266cdfb561abbcdbfeb80752b364434e64b80429b54cc88693ce03dc0fa147f0741b215f0728499bdc25"
  ,"140aafc976ac99e910ba8a8a50d21b7bddaa28626b3b90a93fd44077068357c81d36e735eda4362930adead4951a0baa104f"
  ,"384fc70e842a9f329e1868b07b455e9cc3fecd54805c9052e70f88c3b92fe0fc6a4d7dda18cf5694e5398860e439a1e19d5a"
  ,"66f2fbc0aacdd1a498711bb16054796c015a715395ef6174e37b04eda589b673c4d5dda737817fb52f392caf7a72d7a3e84b"
  ,"2180cb5b75bc8af065bdc05c3e4040435a1b160081352ac43e09cbf2ead6e09c2b0be0e37894888fe2812f68806f957c13fc"
  ,"e6ff167bcee21d4f412ec95a4847f3db7bf441223a4d4ca9ed69adb4de8a4b5b01c775f2721226e6c59ff26fc38e1bb78a38"
  ,"4b30e7b55f082e264d8f25e31518619ddd6b6a9faf8aa6cdb5eab75ed59a33825d5ef8b93bde5d120ada773fcc0852b918f4"
  ,"f03e2d2a543b15363adb823eb1f6c533b98d940411e1f5c1cf521f9f63d5454697608326625fffe01bf87f44187dad631df2"
  ,"898effd2c291d98222e564abe3b042b75e90c9c54667842fa8ebb68a1244bf8e0c3ae3ee5f97d5ddeefd986c4bd3f99d877c"
  ,"2cc2381a89abdc61713d38cee58bf69805a485c288d21b15843147066b4a74c69dc25de878e21d35fdfe6746feb4c166606b"
  ,"f3219e42cf63581e7e6bd6570f40f8fae590cedf5106fe57037ccb2324b74fca6500f6ed3d0736cdcc67d04f8fa9e80054a5"
  ,"bd7c8459fc1abb1c4c78677d7f6b325af94a0e5c9c7db0a748e12c5265e8724947d9b5c4bab1a8b6faec827cc41ec115ef3c"
  ,"2d7348cddabddfbc8436f3b41765e13f3762b3b45ed23156f085831e726a55d4b83848b3d1d3352aab9edcc0ac2388f2383f"
  ,"6301ad813b917ee3f23734e057832ae4cf65e668c9ddd0bdd0f9d8b6693254649668aa91a1fa5eb7c59859bb6ddd36c25f4a"
  ,"2223f5d688b480d0388fa307ea69298f9bf7737f6b3dbfda87b331affd75cd8d88f0460e98ebc2890b217bd6d11000a3a088"
  ,"cd837f4f8859a43f76afaaab05a0c3007a149d4d6b9155cadc2c9b55003efdec5012b6272b87183694c505f0446ede55f35b"
  ,"8ab201f9eda974ff840eccb0f004fa3acf753acd0613f66e2a6ac82e322199d37b4af83cbb3d98371c31be79bb42331e8196"
  ,"44cbad2ce27a04e4c517998692cd8331552892e199a01a6922bda4d38ac4c01f708809e529c3216eaab399ef25b350ea213b"
  ,"a47126f278140e17391ca7139bd13c56f415e6b74aed8dbfbf38c95dc6db366fd72aa863a27fa1ebf198716400b978a3709e"
  ,"35039731930406588ebdffd35fa230a9b75fce41d7acd214ca4f0029896c137495eade0cf4d10fe621c73f01061acb077de7"
  ,"2177ff5dbc6f0c5bec681aa34668ca4fcdd727525068b0b0e9072971b84ef6ce11d5c3c6024da40966703dcc2b33ae04f677"
  ,"677635a55db508f34f1403cdbe37960c8577dac3d848b29f3b5c5c6c56fb74f34c8f4634c04b8cce9b218f1760ca00e6de87"
  ,"efd14087c633469c892bf3e319443336733bb60cfb44941bfa25229aa24384d812db90fe74e0f93fda005eea87400736cabc"
  ,"036f71421b6657b1674d4a8f76cbbf3a8b1c0af82f72973927752257c532db439d96762ad64f102551a9d03f9ce3d8cc850c"
  ,"393c128bf8054bb55bb92ea31ec0706f083a9cf90424c617f8ad2a21225d1913c30e8f47a6b7131304d536a85596ebfd987b"
  ,"64b6bf3c51638d6c839214b53c3c10aa52bd9c6eb77fcf80b5e3b724dec1381d0e02207a6adc73ff53d9d1ffcee1c4a28fa5"
  ,"445ce518eee937074ff7a402f5bbcb362ff090415f9dbd93b62ee56dc8c50e4d2e34c6c621650c0dffe311484e95d68de771"
  ,"70c909c815828946aeeec7ede56bcf433e22fc63a33f764ced1f9242f3d26dc7558686e471f30fbe9304d3d56af8b23e72a4"
  ,"088970b24b2f7e968c1d0392eeeb0b0f0ac8c176547a5383d948ed15484b79e21314a1f28ed624f61e5aaecf2269e5b027e1"
  ,"910ffddede52fad4e8da224e8a10b079548fa7cd44172f4991adfd7623d13e5a19c812824bcf990c07c9721ded9093be6ce7"
  ,"bc7da3ac8c932133a64396b822be92b088844991596df893625a4ef24543bf75a10d7d17ff70350ef62ce3a7758aebbf9b39"
  ,"77b08becb9ea28376082f607965f2cded28bbdb39dab7e00833b0488370d221742b66e27d9ee2d9dd07f401bc22a62c8a9d8"
  ,"d3a290c63804991496aafa47a32578f583cfb53d0c2199055973440d7535e0da6cb2957f4e04002ecea68f9c3ff76cade27e"
  ,"d15fd7835989d0abb197fe32f68636139a42710644bb25860ff33f539200e3ccb8a7738422ca0fa0c744b4c19d15c5d4a3cb"
  ,"082e20a78e20b5a4965b043595cbcacad500b5adbb6cd597e6a4b9c5ea6a1f2e653b5474da277f1818048094ac9e0e1e0b20"
  ,"068d1c1ce5a114a4db7195057a6ce4d221c336fdc29190fee8ff855cae8b7f7c02eec21f972c827066d9c6dcc4a4179bc44e"
  ,"a9b88abe5124bf78b071e09e9af43f739a6e1030091fc091e73edc447f25c68bf84b8df7aa8f091ab42662b93e02c27003af"
  ,"c7b0ca69efcfa60bd53d4d78ceb7c4d2c8fd5ed7e8b35024de849e06400ad145fdb28348d22b317ccec704c401f88db1af2a"
  ,"5348223f5cefd914e404c9d73805d0de77211881486f1bf4aadacadd3ae2588f0db7b5e6957fed50a374f541cfe5e4e923c8"
  ,"2ec47e5b3d2c70ad6760c79cd5080b490bdc75f9ef5e1d17f0978b1e8770775f902b9463e6980e1683b2454751ba2dad4a2e"
  ,"6460924bd60ff49b03230cb11fcd04a0388e60874c35d3f6cfc4dd487665e1b16578751eaea89e126bf58044596e3188c7a9"
  ,"631017be1f2dcd7d612331832ff8755460dc496aa99a61ea053c78e72607a18213ff9ef4bb880903b91e9a43e0b1f0ed1511"
  ,"b2eca2f4253fcfbd7d0faebf3680fbf0a45df231544882c9c46505c726d56905d02fd046c1652d8fd06d15286a1a8f8b69fb"
  ,"d825ca421fd80f5e9ba1a23f924937ad049adeec60c78fea1adf9b1ef7e8ac4d1ded18f1a801b0bda8fe9a88098825ff3eef"
  ,"5c1fc68cbea143310b39543293f3f5fbcf4773b02054c0bc79f00554947c7604b36389c0c45f597a88f3713456b4cfd83b30"
  ,"cb6520b624aa09c812066a8cd542dc67e19e4c92b562b4e0f6799fe57d9d4f4f3e0b6fabff4b1fc190bf1e78775ebcbe3655"
  ,"d370ca6c08f48decf6153a4989eeab6921f8475f85197f51d651e563994257df57977e5f219b4879751de57ab0374b407a21"
  ,"adb4ba520bb35e7b7508675bf49f4e432190451423cbd529fc79b22baae9cb1d8660c3a49c456ac03bc06c0ef3b02f7d8acd"
  ,"40919315206fb38e715139c9bd6f89a58634fe683df03f5bda719764f6c38131bc5ba1c53244472ef73834ade04b86ca08dd"
  ,"753141ac0a9a230e246735060a044018bc9b75d50134b20e6219c13f8325b5a0201e9453f6f012fe72e829ee1c637fe30037"
  ,"a9212a31c6e713726a6cd4cf2dd66ffdba77f1e2800e717940f231d04aa2e4e88dea084754947d848c0271856bfe65992240"
  ,"8449858a81fa6583f062d96898d18ec53664f0067eb9b9c40ad2579ba9802abd8d1bf287e49d94ae397e784db14b5f7010ee"
  ,"4fc42e6e3c8ba80370afc188fcecaf466ea830d7b16362e5c9329980b981decc7174f3ff70a35d8a180ee12ed0cbffd4e8d1"
  ,"4eb503387e4959f702d4293109e922eb561371f9ab21475821f8555d92f0aa1c3d841a6f1eabd4e663993636c754ce2b3c3f"
  ,"6a6b6d0b161e777b8296d7dce7fd162970496494d4f60716244a5a7fb7cee40e1d565e6566697e8f93000000000000000000"
  ,"00000005101318212b"
  ]

mldsaWyPub87 :: ByteString
mldsaWyPub87 = hex $ concat
  ["30820a32300b060960864801650304031303820a210017a508179b35057099111733da28fd1a2265de7d8ab22d5279f13bca"
  ,"84cc42a5b8c9644c121e7e1b81723c5295be288fb6c36bfa188b6e08d913a152350947fa2c8ccc3fd01b319f65a2058a1dff"
  ,"54133946cfeb408d0b6dfde6bbebd7e0591cfe83b8b5452ceef6c855f7d33e06a0d269345089ed0d3ad67d84d8a4a34d1683"
  ,"6004cff125469e8c3387abd788b620e30c1fc23909117a0e34c42a6631d9791347b1b2a3c9ab3082416211afb7bc3f6ce630"
  ,"a7019af19f736cdfacb1e7db66b65ef56844d2a2b0753d09283a7a0b66f77596384e95f7ceddd1c4ba20edc11f1eaab695bb"
  ,"963f6eda1c383754aa372a0d7729bfa6e0f142131c2367ba3f89ce3de6c357f9a7225b7cb85f6b3e8a3a122e8501fd1446b8"
  ,"152a415c19dda1d2e4590cd994f6664b4d1abd7381468c3a085abe2741a0cfbb81880664b271677245c4a471bf8bb8e0192e"
  ,"b32e4fb5e8560f3c50d6b19a353e486d0fcc2a35ac046286e707e095f61786d92212686a65d39b6863e0f8cec1e1997f2f84"
  ,"5e4878ca9df650c746765296790863e51d012d32dffcbd746aa2276d04c0a57cd1b3d6ed06c0d66a0897aae5c49c97b6f19a"
  ,"e829baaafbfed28a52c05963c6eea9eff69528294207f8cda75280f7c486e6848791c8e37015479f2e13c28a9fe654dbde11"
  ,"689875203aaec51be3da7cab1cf31e4ec476c0c830cbdd04ac02167c0a6fbfdd6548b1fa525d235c7e3fca8d63e6427503b0"
  ,"a45c0bfddb428b837c32e8755441077bfe1c0142bac357b012a46545bf4148d465472dcf89c9d73b62357087e229f53a450d"
  ,"3cce41c8ee21a9d54b61e34a794f5b1406a70724ab0c3712c49df231ef30a956075e907c51b63dd1f9453dbe60e25b0f3cc0"
  ,"354dfd7c9119313919e77cb2c92f544d3e5302b8827603e936b567e99bfe9904932585a9f01a5a1b5bce07565f1d84c6b1c5"
  ,"c86259e1fefcff18cd06861122be6836be21e40be4eaf6bcabee8f634f95520aa914bb51c54dbd67d1b9dc5e38831e786c28"
  ,"3979a963a3206b98e339edec4128b0502d4d47813869713e431a529a03c7f54b50123680f2b7f256f5d2b40642203259b9e8"
  ,"5c62253d5670ce372193f28b5aa48ddd643c54756a2cff808c109f74772961d8db6bb8a17547c8f29c7f5ff3ea06740b867d"
  ,"84917e07f3978ad0281a20689eef58467e768b6178a9b36a567289fd39762bb3e4254031b2798a4550857f6af369d484392c"
  ,"ddd7b48eaa2942e2cbfe754d5ee2da2b7fa71222e4a525ff5224d551a778ebd828e4e0499adc74ff0d59a5abc78ad6a8abaf"
  ,"eedb3c99045a14423507f85597b1a7f540982f7d72ea13449110b442d54b78029b4c7fe3b49396dc6c3b7d58792538fa9079"
  ,"63de10a4b724548142541cdf1512e0f7ff1b10a93de63541b8cc3268b4de20ed26739ee8973b6507ebe48965602c35fa3f7d"
  ,"4278146b598d7d7044e16e97e9351f7c51ac25573b7232ae2432638e9166190e7f7a7dcb5096ecb5d10017cdea2a82b4f56c"
  ,"7385041c6919a7e36e11beac77ec3f25df44e7b596c1542c1e376de3667c0e903fe25b57c338e9d93c5570c484f0ddab4f57"
  ,"d38f292b23599d9efc7a9fd9e078aaddca0acb1a196d6c45d3c8be6f39e8cdbe3299e370b262e0bf6fb5f005cae2b1287928"
  ,"9d00bd8039de6a571c310d87557f5c9a4f64a0bde7177a8464722a04bf87fa2cb0e312d4fa6e536c61d65dc2c1baf144b0d1"
  ,"d1d75f4c860626ff773933efa9941d105c53a1d92c4f7c7bba4aa969590acef1e50901870f59715ac14d9846d83871a77367"
  ,"be57c63f88bc2c02eabafe678f44925a3e605979282fcd3f284736a1d346c033cb782dd615e886683fc37cd87a9142285777"
  ,"4c63c6659096eba393c56225ed8c3485b4f89ecb07d53526281a6426ae7d67cda52fec5ac32320caae9b96000bcbe9e8782b"
  ,"e88cb1ca6dcaffb74ef04c77e03a994bea2c89e4fcfa44cd0c9f4e30705a8b7b20df8c76b05a4479400e07db03d243e9fe4c"
  ,"90d34e9245f1e574be9a388f5355482077e4e98b919de024e666fdd7d51ed2a0d58a823e7497eb07303cf1d6d5f10a536be9"
  ,"80220de5856727e5c13981839cfa19740988e7771a2b984f53ae3a5916ed881a4a90fe524f0bb3778355882864f8961fade3"
  ,"2e656fcf9f524e748c8196a1f1bbc57bf8da7b36de9b0080f0c7bb8487a2b7bb7a81a8ff43a2539b367c9a48c70041520f05"
  ,"ca3dae316dbbe3118218216f52b7bcdba7557c4c9d861803a5e2ee01d3682e1261d7cae0a99fb8de909eb2bc1e112aa43cc2"
  ,"fa9c76a222bd85faaaba5d9ec2198ac45a295181a324a0592632b89e2752582cd5e01e1a610e7563faee10b76d853109e257"
  ,"e7c0c248a9fb7933f514b07b4f4e3a4a3d2cd22e8cc45ebda3bef5948aa050f01eff85ae98d19f69c51e67ff89f2df0c5268"
  ,"acfdd325e84591317e05cab4f9e6358f249c4ddf4019fbc8f511549a733898a50efa9e0793083de0b15b5bf78d9f63d8df83"
  ,"0d42df2fefa27b89e0ede2a702eb9467118fc0ed44edc63ad1b1935877c34843fea06fdf388bbf83e501723a13cc6cc2efbb"
  ,"9691fe28fc1d45270591e5bdf7aa1c82673544ee29d9e6c9da3328f21e9729bffd7f4e56de585909679a74037105fdac3f51"
  ,"ae35f69d9763d2e4cfeb1d4a8fdce99bf1aa21f866a9f523b2a9549e12258a4d19900cf5db37b67da19b23563bd1d701c610"
  ,"6fccb28e4689c62e1a6cf1abd763d7239c2258b765610d4478be9f1650cb8d18923592ad0024076e52f9bd0a3894fe97bc0a"
  ,"1646b4c37f62c27f32d0df270260f47c49a5caf110e4cf80168a7d54b1c70bed9bd5d9a143ce869a05cd44ee266aecd6bfed"
  ,"b39be79e7c7d5c11a99575ebc0f389cc55a4fe1469a2d61b70bfe4b74e3e27521a037d2b9f4fdb377231e2ceb214ba90f695"
  ,"3865c683215203ce963875c6524c01b789e0389a9f0c386eb236f0dfba6c95df4f28ccc7ae7cd473f9dcd20817cccdd211bc"
  ,"bc78b064e936e4ba2813df531128428ddf410e6ca07044aeb4cfcc0a16c995ec51c8af16a541ce18dbeb69a26635632dcc24"
  ,"ee52a5eedce38c502cd0e356ec31341c893f92e6063c3a160a53d34b85e92357a8ebaaad8f206771be43ee48cc409825a709"
  ,"4bda529ee18776d9e67f1fa1c1419514309d70ba2443be2f63b6943478d6c0f56dd058731e53de4c30bfc7d915e9284a5624"
  ,"8e81944392881666680d4991f04269ec9a83b24b458ed59a6c274de452ab3013c103a4920543e6a7d22dadfd764f6ea39d49"
  ,"b910ee0dc216e547aa5fb4382a72a568ebe83ec00416fb5830dc21c24ae72416602870cb52c3a8a1c4c12a4b287b9b800d31"
  ,"c287ca161f404a9e598a5358d28b3aae43e534846bcd0d7a9c7652ae01e6698c79e315aca8198f36de45af7084b1cb21ca2b"
  ,"a0ee3a547a7343a10ef9e3fd17b0a4060badd1409a0562cba25b84fd578268fac53cfbca08e6cf6e5419f57262eb5813c1d1"
  ,"324e0df1d483ade08d8f6c62498e262485ac7c2872b11b42e5c1b797fc12e838b38a711d364d45cd1ed35f7faffdf4b0fb0e"
  ,"aa312fc3d5af77909b0649cbbacea10c9831273922b5b05172face9ce6cf324edf6e2f5f5fa0a9f0463eee938b30adf3e556"
  ,"64f94d274cd87dea901a7e08e805"
  ]

mldsaWySig87 :: ByteString
mldsaWySig87 = hex $ concat
  ["ba4275ff54c22d2d09ea1937a0667362acd44925c6d6965fad350b111d1cbcce68ddbd0e576d1a8810eb4e71623781f32f74"
  ,"7d44c8e693749df191682f588906949d97617a4b0ec54ad966818dee88b95f0f28ca24bfc5bfe0c316140b0662c43093ae48"
  ,"b899cc71e5739e9d67095ed987a79b6a0e7aac960c3c4125f0e92bc9435d10bfffae34bb3af05e977ebe0bafcbeb2381c5af"
  ,"e3379667b4c201aebf162dbd0a4bd1baa88fb2f88fa970499a848737d3cf94cc8ce278880a169cad91f304e4e8f1091d4cf3"
  ,"9d9a3ab9f88dcc6f3bc4df311a5be0cba290365b3e879527e2a77f0cb6eccc9d85a5e592fb00f3a2e925a26d295a6b82746d"
  ,"7f534c83c35bc4826ee4910216b9a2867032698996fb0e1669b539ccd2ec74d181f4844e8f4d28f9c174316c12dadb54cb1d"
  ,"de7338238a20731c2565bb959f8e3086273ed03abc7ac515728750633083c0b397b29d385d13f5afd2529b32f00dce66c9dc"
  ,"8ea93d99c8b61c5e0ab2fc70de2a8dabdcaf290d53e8fca7561bda8c516ad475e4ec6c7cd2603aa3c8a71d9fa5dc7efc33cf"
  ,"318bebc1f1594e6ea25c69b8f9ce34a65b8ab0ae8dd3538bd267d86c584b8f354d7e4776ed4dd59a73f9e70a1df572f033b6"
  ,"9b3eafa5a901e02515472e37258608875ca469de07db71cd6b8dc7edeb3d866ed2d219e44fcb133a066e89d8e3013569ca6f"
  ,"1fee7bf4ae56a6d32a5f3e5a530819c31aadabc8a88503edbea9cdfa3171762e1e8bcebaf9bb6af7e540102d5fc810bbcf1e"
  ,"02ae564e04d9dc55dab0a9392d6c95a317730d9793954da2cb16544d15403d0db01e85881e2d4f1b9b98458e1af0985f98b0"
  ,"14f08f200558f2fed7a70c352a27423bedeebb3775c0a1ede9d461d2aea303c09c8b1f73fc37a5b3a01fb24a131574f7eac9"
  ,"0c78baa38cebe81e2335dafda20299f76d6a0ba77d2954d11381674f4069f45e133886d64222d92583d5908e3ab6eb6a72cf"
  ,"b41f7dc3e71c1383888f61624bdcaf12fb716de98232ee329af1dd045f30d377234db7bfd11ddab0b3108329e16ce568c8ba"
  ,"da39a98df5a5f72a72f063fa4253313a806013f61ce5adbe54cf42180ebf6e496bd4b42aeacf069aaa8e1c231fd037b394d7"
  ,"8a69d1742b45bc5784ab8593a198077423c4c357d734f9899cfe9b3b62b6b9c3f4d781b8484a3fd0eea7e8d6945f4ba2b046"
  ,"fee079b7f032bebbc402918daa2aa1c9433dc3bcfbd7f49a5d7a293833c21c1bade3e8a7ec3c83d485529de51b5993cdffe2"
  ,"3b770e25acab0ab9fb3059f14952d9464ebfa36a6274d8da317a7b07c2afe38ba28ca942cf7bfaee4020e59911c047b2aa24"
  ,"d1787baae1bc3546364b782358676d75c7698769f1d4a0d5dccade7fcf80e308437f7fc24fdfbf72625abf1b0f534da62cf8"
  ,"60da1efd986950e3e19a085999f4d008fce38459c673befcdf2287c1766e106beb4f3175e97812da141330dcb2beb3265e38"
  ,"c8423c19dd50a655c9e8dc969f6367f3383b644d53a26875d53cea26de429266b506e70e7e6832886ed06d81738b0b482bd2"
  ,"3bda396eb674ddfdb64803d6c4fae2f040170b5a28923279838b7b876220d02dc7478666f7c3287b1ba4a2f8228e8c491a55"
  ,"ba459805c601b986caea27ee9436f63383351c74d673643b15f6007fc6dc49e337a65a8a96ecd7eef4ad730bf3dc1972fc39"
  ,"6703ee26af1156dc4beb46c47d99bb69ebdaf81c2d738d0f70e57a2c7162f5a55242255675f22082aa43f5b3dd862b535b2a"
  ,"15bb815b4e9faf16a302552cd6098d40930dfad7a7c609d6aeade814242a8bf0721c1c26d0d3daa7a638880a6411c6538d80"
  ,"c259d31b639aadaea49563a8d7f5ddb64291d6b086c80d72bfe7d26802cbd20fd6ba5495011e42da1c82483cbe8e37838e73"
  ,"c48f79f65b205476bee600399feda6aaaa939eee12cb34be4e6bdbd18032c85b54a2713551de677a16ca0142ff97b77bc963"
  ,"e8f3c57d91df9b49474b01ca514641842893abc3181caee3f49b635d17daf41bcc4aeb1116ec4b3e78ff1480cf3a5d9c6a15"
  ,"4384b88516834d19196976e2ba97cee91f7a0d73f7f8146e58dc0fc8f510511d39d82a7ba531a4abcce6b624035d753a37c5"
  ,"980343cfc7724cf83efb0c33fc4abb5b002241bf57a46b67cb5a4cbd637b2f19bc93b368d97e13c6a62c8443c8222e0a90c3"
  ,"ed1972cc739b824fdf729ed8eca02ad96bd78bf6d2b3d2853e24fa93199ff41635176b31aab2207013d0a9317fa49668dfeb"
  ,"672b8129e6175a2998642ab8e74f0823e3b5480ae80180ca395f5348744a3c7b344891f008aab65914760b5fe852615ad642"
  ,"5216b1c5e777db1a46517cd01a77b277cfa2c6f250c2d68c495fef28feee6e0716817d6b30716f5ca48001805042133eca17"
  ,"a41c2219784ce0f12858ccfd371c77b90966ea04c3996851edf31aef962946628007de5531b06fddf3449f6c552eaf6e16b3"
  ,"e9160e265900b8c8e414732505e02660e123d45a3d6f1b15e56fd759d38e821e27e84967e95c4b0d2a48e008897e655d1b65"
  ,"b76299f1e3074209abe44b37f8786b02df23aa4dcebe512e6312f1a3d6d781d749635247aca897626f5ee688f517df6cfe94"
  ,"7ddead820f07fed4bcbe7f1bee3f19117b5666dc123d528f2bf03db346d6afb53804b0681aea98a9479fc6de5ae974d2c0d2"
  ,"055f07ba8a1d2d8b6a7e08a6805bd8634cc190c4988b502f475c36d78c7b3dda0057c818835bbf21c5a7c13bb6fd91cd3cfd"
  ,"76abe4c2ff908a08a3000b9021500ff94b297cec0fb3e51b1cae7026ab4347bfd5b6a641a3d347f45a2a2aacd22e521e00da"
  ,"0c3986c67672c5d7d7e61e7edafc15d42aa42cb37fa8621f79e9096b092efe853ab318b3e4bbd90f20165a1be1d3aa5b3de4"
  ,"3751b65abbd952599869778393c4351ab8f534fd49e16547df01c40bfaf56de60b4fb0019bc34177cc8e2236d219fb3c0b84"
  ,"dedae6b88e134280eabd1823420cd1afe6d929774967fd7d885fbad33d89ed9dc5e0eb978eab5d96c50bed5887aa8277880c"
  ,"7b06bf2780cee82ce639a1e3344c88a25102edcc17a4cb48989c4ad6a998726ede31deb0b98107f40858bad7864983f6ecdf"
  ,"0c9761a42751b19d5360daa7fddbbd2e2292638b95c763ca1e747eedef0dd387e9d9ec9e5afee207d8c45703c5befc2de387"
  ,"8d313655ce85ad984250cdf054360f33d41dc193060d42cf9528b1fb91d6ca3395199e25a1a7739eba9a6a4ac2c417ae6159"
  ,"40b3eb1b746dd0ecc7b2f7acdff887110115629f70877dafcd7a6625fa1b9e256bc8fe1d66005dbcf12fde0a5fcda5d4f23d"
  ,"58ece91d60eb91274df8d9d17d4a39e63533acf1b317db979b04ca3ab9a0bcba652d0010ca3fcd33ed8f8a62faf42f78b379"
  ,"12d3adb410f20bf16b31359cacc25fb783083a3f065f0a2dd6fe58b8f594e11a87bf0f4c5f5493f334c18b03ebdefebce502"
  ,"28937ec13a8c221b617450486291071f3c14f64f66c927dd4bd623c214ac35433b8a6875cdf00916476eac0f196858aa1484"
  ,"bc1cd45b726d33a965619829b8deaa9d9fa0c3c210f23967ce26a4bdd939cff8aa662f70fb0af97ee44bcb9e2755000a1957"
  ,"41d8919e4dcb1a5caae21009f686fa1489c72f16f9fee76b5410ece7f406947f4a19f394a5121da79f3216777b0fee542332"
  ,"8156ecf0b4548dbd5b3f7b526d6b9cfd57576f67dd521c314c2d37474ed0cf732c3b073a101c735a4c4e6b33c9aaa12c91d1"
  ,"47ad1075a20287d36c388657614a9c648d8e49cce8cfa282b2a2e8e9da6e4444e4b6aed1bd0ada5009a335cd0500bdae9a01"
  ,"b97f7e8cfe8372398e750de92ee4a524393a19826d19de5e762fb53a88b9b4657e9c6d7d01a4124e3e39532f614aec5cb88d"
  ,"982b78b2ff568017c92f6a1ce5298b5f323b5ee61695038ef0c3a7a339cfac31cf7875a4563046a40e7b35cef1d37d811b34"
  ,"2fcbb5373122415befc23cb656a619f7c262c443403b23ba20e341a079918dec6f4f801b92781179ad7ac1951f39ddb0b1f1"
  ,"fb95b28c0f4593a04486f0e0e86bb3b014674879aad10f41e0bad34d40bc817b6fd43c1dde8547882d82e5111e208107e9c9"
  ,"736d16ca77ac7453d7b6c7976a7dd6a4c6c0252185bc9948660a07b66151b09b980d8572ae829ab2f6d900cc63066c4ecb3a"
  ,"0317e8a9acaa8e22a216721f3d69c67843df2fbedd88bc424f761cdf420de4ff2c55b6925b1826c1c4134090d2aae82a7f64"
  ,"a8d428efe1b21097a6fdbc9b8a31c4d46c7b32d478bf5b9181bef8af4d3486958d7c198c46a5ad771090bb64e7fc2bd7677a"
  ,"e7618b861c83c13177075063517eff40cfd52ae56650e9e7035f783bfe8920c754e98470b327909ac2a407e07864710544b8"
  ,"adbc075502c75b5f0fdbca0cde5d94b013141c96b55ae1b60ab63f9e792641690af41b05a78233935fd7f82852ebb2602a10"
  ,"459a709256c41d108c2aeb71925089cc79b121eabd5edc54f3f7c8929685b88ab29700c7fb2f247cd7962c8ce6dc9f79f935"
  ,"8d6a7989d24ccc17d0dbaa0b7fbe73479164181ae7d6b6a02678cce46f74ea2bd387ecb73041817b429a0220e1c3635fe492"
  ,"f5f3a8e2b65c086fe24c375563d7220856dd8f970716d548492964a156554dc88810c3c4f81dcc3ae80243e19679a3be9c9b"
  ,"1b8c707b416e9166c54a568bb9d84728c1a283d9231a12b13688ce2362901342652d66bf44cec223f561d2735d977c6adcf5"
  ,"7e9066220d0770fc77fdf6ff367a2f36ae20062887beb88d1b453f267aef9bc763ab716bacb9214c38b95f4f2f3f6c236aa7"
  ,"1aef83c1ae4b26133678884476c1d7c6d3e7b99f13e028ac6cebddfae4793f9ae975f3d66b725b500e7c7d2f664eaa0c358d"
  ,"eb91cb2d6173394b306749d2bfb2684b985769bdb682e922b75555d38dad1899057a64ef6ea361e4712244d02d0dfec8c3d4"
  ,"0770122770c2538d6a14a8462ef18eb705c16e5ba30aa5366447c94869060e4df155f7d01ffda04c1ced0ad5fbe5fdd85856"
  ,"e1e49320319687d31a6e4c7145479f45f43a9b8e9ffe4cbacfad4a21e5445e119df2996cce8b11d0f224efb4f18b544d456e"
  ,"2fb1d96fcd99fc319dbd86720621ac25b490f3611f7e5655bb3940a503c07dbf41f4b87593595a66008808744668371a54ce"
  ,"1b9dfdaa16f90415e57470bc23898d13d8351ba34369e96347da13d012b4eab32ada90668654c5ed2b433716b1b4170f640c"
  ,"f4b40659efcf4150237bbc25f72b248be85cd482b55ce2f5f73e8f02efd2465805b37d12487465ec1085bc6602b71862771a"
  ,"f13e13baece4916b1ddef9ce016c92db9fb9e82aee5e1c4e22c45090ad1c19801ce1c541ff3902baea7a12dbcac6ec2d128a"
  ,"c7acb203463921ca6ce1d182d60d553ddecc4a3175eec2e924e9191e0d69aa49ca0b653495b8c62b802e443e669220f2a404"
  ,"7a56ed5cb7431a3387a435070795e6e63d242a74555e97371989c6d0040748e89ac316618d5d6eb7bff8d91e953afbe00464"
  ,"df4e4f6380c273b7ac5934cacb6c3be4da6649c8a5ea12bdf9afa1ec1e5053db7668c10ae2df75c4b3b14525369bf3374152"
  ,"5a7630158aca3d3c7da5c1d71d3f63c0c2948a43236968d623c6c163eb757f0c78d6ae682ff4e4b673be07193e8d6c106c92"
  ,"851b393f0523491d5152e06de675fa22ae7bded329836a8ca0b955a59cb575395952c6ea0cb1644f2cada196b96b44ee1211"
  ,"5ff9668e32886103d8f8109fac4a2287738ee1d2d4c1c19dab94eaa2757ea32016df60d7286099eb010ba570b5791ce4c54d"
  ,"860b15d56c53a5ddb543b0b602b3a87ca5213aa9647e51b1cb1736697506081240f4f7163a646f2be30e62c617d7572d820a"
  ,"113f96320834a2f43842160511923bd1ef4f723a2ab9b242fffe97cf0199c9f2ebca266a63beea0af279f2d18651b2ea9789"
  ,"d03025857c8aefc5f8bc6ee92ab7c6ffed2606f9c7ef25cb6c96140256a08cc58218869c52f3e5074fe5ace87a86057cc29f"
  ,"c845ff275f1b2dbc5991cbebe4c556b29ce3da3415958f0c9c68a5c664a1da60365ce56b9a4df24ec5d69c6f5a2e685885f6"
  ,"973c0ccd4caf7e000346bdea502b1418c8819e05bb7bee31bbd235819b49c892f7dadade576cb8ca68bda916a598c32ec03c"
  ,"ceba2d01a7960f38680facccdaaf05e254dd8c3631a7222d1561c998c54b16f17a425f3247232dca035d545202e1b1803402"
  ,"19ce31c66987bc86f983240e7fd2c926e8af77e6ea9f4139ff1edc0c323b67ceadead8f64a8004164d942f6aa65a28544d72"
  ,"05d41aafe62c5bfc6fd9fc322e2a8b620532d00d1add7a0d25a9dbaff90e19de14ac2ca97e83a2d77e63888ba0f7eaf9b18a"
  ,"7f2e5f148d16887580e55e894ae79024385f439acd071494e6469b77d07e763553652a470f3b4bd8bb7968052f3a969dacce"
  ,"d51572bd125870849ce3e55359b2e17eabc3153b5f62868ea0ca1f40738488dbe0020c103f53678b9eb1c100000000000000"
  ,"00000000000000000000000000000000000000070a111518202731"
  ]

mldsaWySig44Ctx :: ByteString
mldsaWySig44Ctx = hex $ concat
  ["e11d24772c24efc107ae3abb0149817436f11684d3548748cba19fc0b373ddcb7c8f68f00407d964570c155a9a34823d5b33"
  ,"345a2bb4dfc43d2e178331bc6573f39d634239230cfc160bf03f41d176854dfee5be915ed6c3f4112fff50d8effcc4577082"
  ,"61e715fdf0676831989a15cbd16b92fc97bec06c75919c114c167d2bfae8d7dfa384068c0d96a8e6039e755f9b90cb57b4b0"
  ,"e678854a88a8fada69b91bbbea873f81a7489c0e3612774e8a00370b9b9650331bd2184b9037ce340d82b39436dab990f0c1"
  ,"76b90421e71fd182bc07ed70e54587bf2b92c038e8794aded666a6c9cdb29d8747c223967c5a283d3be2946584202a021c52"
  ,"64e04587b3c60bb5ec7a73e2d4d7caf4619e388d1beff4ec4bf7d104fee34765ab6a51108660f052a05d16aa46efc49d46ff"
  ,"42d65bbc6521d8a18c8cbe104de453367bae5c72b43854def8222480746003fc8ec4efa2d122965ef9e0e5b3d68c9069af54"
  ,"ef4511036a079d9bb67a43eabec138d37eeaa918bf14815159b0216352a354110d5c835ea9631075317ba617085f2d86215c"
  ,"09c288a584add2809bcc7f50f9071fee5ea2fc08020f2a106fad222155155018f67162855ce624328724b659c645cc30c638"
  ,"2c6fdf48e1c9e8499bf6f8ccd63f06113e3262efd0800d2619d59cd8966d847c2de3854634f3b5e83f84e66cac84e1013b93"
  ,"fe3869f270380ccf8c26591a2635cfa048d1955516560c95ce0c39b0cd7c12c3234b13939386adcf557118f21811c3595151"
  ,"919da2bce155f9c6300703a7209fcd893305486df90a828bc551f23878b72f04fe471ed75982175b74ce135fbdf0c786acde"
  ,"fb09829afdaf7eab308cd8c181345e8f713afd5b433a6be59a4e70b421c216a02a16bf0e927630992211d48d71ac0aec3d06"
  ,"26d84456303c3f35c132571eeafa0106cc7ff333e0d2dcd9352b3cdf36a8fec2a750e5c8ebfeed52a94e5f41c1d295ddc01d"
  ,"e6ddbf9df9970460f33fb362b0b94fac9b496459c6ca989e90d53ec8944d1518d7fcc21f1adca0bac93df266820dfbe9c7cb"
  ,"ce4b762340ef8ea6464d26c5fd4f2b67b9776548b567d7426511aa9c2fdd19d85206130ab6cf6d7f5115dcb7f53b628b99ed"
  ,"8fa1bd6055764f950deeabae276b419370c4700cd37ca2a34b387d644d4e0ef6a380a5e2d2f32376b4b8752bfc3003c2b671"
  ,"11105b775fd21c3e5ae678f79975097e6c63e759eae6b14d60c9778b4bc31aaa4c9f4fa4911688dc390047aa11f9a998baa6"
  ,"52eb9be561cb4039bd9801fd62eedb6f568ff4189dffa4c9a7bc11d9faf26499285098043fe699b565545a930d9ce8f5247e"
  ,"ea4c5f6df27f3e050b8d01eee5dd1058efe65190eebeaa0742515d9f8f36bd29e6d84e56d9e41c1a551d3ce6ad7e8967872a"
  ,"bd60488d4172c56006eb2db95cb25743287a1d73fb3a36ca4d7f7dce22fd2baf10ad47aeacf82b37dafad7c06a6795be40bd"
  ,"6abfc8f998219f2a0e58531c8ccd1bf3ce66b960741a2da9d36971bad67ee4d75e660e0805e889eab0f0be62b38439476ec2"
  ,"89e77176341461b474f66f44120f784de5490529a1f6f013eac2dfbdea11275733f1b1723357740a903085e09e8d61a2e2c8"
  ,"4f26ddf95fe630a398329e48cd58cbf358b98b839c7f17893b6e913ee286c976bea3a0bbc58177ce0a35a28c5bb4ac6d9d5f"
  ,"fdb9dc626555a55bea17386237d8ccf2ef60a31393b1f49a37329598f706eeeca9c2d0b02ef13dfa6bb9f1e84517aa51d7d7"
  ,"e85ffbdacf23892962d231f67c142df49d6236630bdb50dad047bc84fec4f517758c3f54c77f5f25fe78a12db9e4dd766198"
  ,"d6014b35cdbab0257cc50c7f9dfa5ac0a88c7d107c8f6bb50dee4d7a3e35cc54fb12572d901f02f4e8bf15cb6fef1910fcd5"
  ,"d54530dbca4046bd9ba3039c4ff97bcbfb6d00a16c1f902a25005c30d3d0d96a9d7116b15f81699614afe0aa448973b6da55"
  ,"c18f20395a15d2ac53c5725e45711f9b3050ca8f409d4776b568afa8d6657668e7d6d3553d23bdbe09cd1957fc5c76fb733b"
  ,"237e60073dfff5d64ad3f03d3116fe1db0ee27c36b9671b0efa079cb0ae0558023ac6a0aa36f1f2d887805658131398f78b4"
  ,"c2fb2e0bfc4a37e444015879f0db10abd5b56d5993a3ccc0798651c0b85b658285cd00e898be4406a431e29d861379c26ed2"
  ,"6cee7f23c05fba0519fa6d0336120dffd6d441d7de14233ff6c345425b852e1cbef6ac4d442e6f121975b912b9e60538b5ef"
  ,"e74c3df3861671b54d96d1d512725fe63b511c4d90261577f8a992746cfe6a4e1426a3d9fcbdb3098a626681ed5c41c31586"
  ,"67708c321a515a978c47c337b1d9cdf6be83fae368d57843baaea2b8b7a94398a8fcdb3b3e39c55a8feceae53f4b2b8967f5"
  ,"a7f671d7cff584596682ed7436979ee9e8610bdcdd0c065b39e22b3fefdb8ebbe7ea59ddb2058980f8c186ec95428a8cea2c"
  ,"41376312a073543283f2c8a970b11f1f31dc531748292cf198c63b2f21996f2bf769d397083f5f7c2da8952b38a199a2fa26"
  ,"98e156cc5550f123d99d4f65852fab97e184f0f615ac419af60c236f4e1c3c209b4eda22ec47c963d6b5318031cda0b1ce9d"
  ,"d0876b0a011d9d1a8a1233c38538581401dcb8766c4c9147d257828a0068a91e458e3a312e398c2b1affcbd7a702efdcb3f7"
  ,"9a28d131667545f2ac3d04fefee0228f257e689a85fb92f528d901768a2dfda51f65ad31e1b781759cde2a44adf0a4b84639"
  ,"a8160bf863445f94a04ab7885fa247fe057c161246f1202bad84345aea9e34b77ef93fe01d090f49e1ba3e214acfea26bc04"
  ,"e4bb2ef2f4fa2af4751a873573ee273d8ab7f1d59aad74c8da98232e2562966b6816f01c1db37c0b5a55710011656ff76f8e"
  ,"b4bbba1e5875e954f1dc43bbd0d77b09cfbc57890acedf796507d31fee63305cc97209964cc7897befd20db3d6203a317bc8"
  ,"769b8b0081016f2180eb3b40d24ac1458d0afb8034b8babe87c91ead17f25715104be58a526409e8f5053b67e48d7de17a2f"
  ,"81f68a679a6d9192120eda7564c7970c88d4aa266f7063d6b24de7b402c69d9d14f8d51b3bdff45e952c45ead4e729d195f9"
  ,"30870fda380f64085011fff63caca5e79d1dae0b2b0dad7e01c4b7b2714b20d3bb69dcee4fe9e0412420b55abba95bacbc1b"
  ,"1fe498474d8d3a5396968b057b8b5081ddb57eaae581da0a1b482879cdc1bda82fe83d4007375831cf06bcd334ac42c780cb"
  ,"91121eb4021f39f9292a6a023b1010b35d378a798601cd4a6cfebc0f45b1e7879a8f884e3d465a6680a0b8cbd5e0f210111a"
  ,"40464a586184859299a5e329384751b5c5c6eceef1ff1d3864879398a1b5b7cbd80000000000000000000000000000000000"
  ,"000000000000000000000000000000000b19242f"
  ]

mldsaWyMsg :: ByteString
mldsaWyMsg = hex "48656c6c6f20776f726c64"

mldsaWyCtx :: ByteString
mldsaWyCtx = hex "436f6e74657874"
-- | DSA sign/verify: wycheproof KAT (tc59 valid verifies, tc1
-- r+q invalid mismatches), CLI cross-implementation DER KAT,
-- roundtrips over all 9 digests x RAW/DER plus the raw row, the
-- raw 20-byte floor, and typed key refusals.
caseDsa :: IO ()
caseDsa = withBackend $ \env -> do
  let wyRaw = SigDSA "RAW" (Just D_SHA256)
      wyDer = SigDSA "DER" (Just D_SHA256)
      cliPub = KeyDer dsaCliPub
      cliPriv = KeyDer dsaCliPriv
      wyPub = KeyDer dsaWyPub
      tamper bs = BS.init bs <> BS.singleton (BS.last bs + 1)
  -- Wycheproof KAT: tc59 (valid) verifies, tc1 (r+q) mismatches.
  expectOk "wycheproof tc59 valid" =<< verify env wyRaw wyPub dsaWyMsg dsaWySig
  expectAuthFailed "wycheproof tc1 invalid" =<< verify env wyRaw wyPub dsaWyMsg dsaWyBadSig
  expectAuthFailed "wycheproof tampered" =<< verify env wyRaw wyPub dsaWyMsg (tamper dsaWySig)
  -- CLI cross-implementation KAT (DER signature over dsaCliMsg).
  let cliDer = SigDSA "DER" (Just D_SHA256)
  expectOk "cli DER verifies" =<< verify env cliDer cliPub dsaCliMsg dsaCliSigDer
  expectAuthFailed "cli DER tampered" =<<
    verify env cliDer cliPub dsaCliMsg (tamper dsaCliSigDer)
  -- Roundtrips: every recipe digest x both encodings signs and
  -- verifies its own output (q=224: raw sigs are exactly 56 bytes).
  mapM_ (roundtrip env cliPriv cliPub tamper)
    [ D_SHA1, D_SHA224, D_SHA256, D_SHA384, D_SHA512
    , D_SHA3_224, D_SHA3_256, D_SHA3_384, D_SHA3_512
    ]
  -- Raw row: a 20-byte digest roundtrips; 7 bytes refuse typed.
  let raw = SigDSA "RAW" Nothing
      rawDer = SigDSA "DER" Nothing
      dgst20 = BS.replicate 20 0xA5
  sigRaw <- expectOk "raw sign" =<< sign env raw cliPriv dgst20
  assertEqual "raw sig is r||s" 56 (BS.length sigRaw)
  expectOk "raw verify" =<< verify env raw cliPub dgst20 sigRaw
  sigRawDer <- expectOk "raw DER sign" =<< sign env rawDer cliPriv dgst20
  assertBool "raw DER parses" (BS.take 1 sigRawDer == "\x30")
  expectOk "raw DER verify" =<< verify env rawDer cliPub dgst20 sigRawDer
  expectBadParam "raw short sign refuses" =<< sign env raw cliPriv (BS.replicate 7 0)
  expectBadParam "raw short verify refuses" =<< verify env raw cliPub (BS.replicate 7 0) sigRaw
  -- Wrong-length raw signatures mismatch, never verify.
  expectAuthFailed "truncated raw mismatches" =<<
    verify env wyRaw wyPub dsaWyMsg (BS.init dsaWySig)
  expectAuthFailed "overlong raw mismatches" =<<
    verify env wyRaw wyPub dsaWyMsg (dsaWySig <> "\x00")
  -- Garbage keys refuse typed.
  expectBadKey "garbage sign refused" =<< sign env wyRaw (KeyDer "bogus") dsaWyMsg
  expectBadKey "garbage verify refused" =<< verify env wyRaw (KeyDer "bogus") dsaWyMsg dsaWySig
  where
    roundtrip env priv pub tamper alg = do
      let raw = SigDSA "RAW" (Just alg)
          der = SigDSA "DER" (Just alg)
          label = show alg
      sigR <- expectOk ("sign RAW " ++ label) =<< sign env raw priv dsaCliMsg
      assertEqual ("raw width " ++ label) 56 (BS.length sigR)
      expectOk ("verify RAW " ++ label) =<< verify env raw pub dsaCliMsg sigR
      sigD <- expectOk ("sign DER " ++ label) =<< sign env der priv dsaCliMsg
      expectOk ("verify DER " ++ label) =<< verify env der pub dsaCliMsg sigD
      expectAuthFailed ("tampered " ++ label) =<< verify env raw pub dsaCliMsg (tamper sigR)

-- | DSA generation: paramgen mints parseable (L,N) params, keygen
-- mints a usable pair from them, and garbage params refuse typed.
caseDsaKeygen :: IO ()
caseDsaKeygen = withBackend $ \env -> do
  (paramsM, Nothing) <- expectOk "paramgen 2048/256" =<<
    generateKey env (GenDSAParams 2048 256)
  paramsDer <- case paramsM of
    KeyDer der -> pure der
    other -> assertFailure ("paramgen answer is not DER: " ++ show other)
  (priv, Just pub) <- expectOk "keygen from params" =<<
    generateKey env (GenDSAKeypair paramsDer)
  let spec = SigDSA "RAW" (Just D_SHA256)
  sig <- expectOk "genkey sign" =<< sign env spec priv dsaCliMsg
  assertEqual "genkey raw width q256" 64 (BS.length sig)
  expectOk "genkey verify" =<< verify env spec pub dsaCliMsg sig
  expectBadKey "garbage params refused" =<<
    generateKey env (GenDSAKeypair "bogus")

-- | EdDSA: Wycheproof KATs (TEST 1 tcId 80 + group0 tc1 verify,
-- group0 tc10 invalid mismatches), a CLI cross-implementation KAT,
-- and roundtrips on both curves (fixed widths, determinism, empty
-- messages, typed key-shape refusals, cross-curve refusal).
caseEddsa :: IO ()
caseEddsa = withBackend $ \env -> do
  let ed19 = SigEdDSA (EcSpec "Ed25519" "RAW") ""
      ed48 = SigEdDSA (EcSpec "Ed448" "RAW") ""
      tamper bs = BS.init bs <> BS.singleton (BS.last bs + 1)
  -- Wycheproof KATs: TEST 1 + group0 tc1 verify; tc10 invalid
  -- and tampered vectors mismatch.
  expectOk "wycheproof TEST 1" =<<
    verify env ed19 (KeyDer edWyT1Pub) edWyT1Msg edWyT1Sig
  expectOk "wycheproof group0 tc1" =<<
    verify env ed19 (KeyDer edWyG0Pub) edWyG0Msg edWyG0Sig
  expectAuthFailed "wycheproof group0 tc10 invalid" =<<
    verify env ed19 (KeyDer edWyG0Pub) edWyBadMsg edWyBadSig
  expectAuthFailed "wycheproof TEST 1 tampered" =<<
    verify env ed19 (KeyDer edWyT1Pub) edWyT1Msg (tamper edWyT1Sig)
  -- CLI cross-implementation KAT (pkeyutl signature over edCliMsg).
  expectOk "cli verifies" =<<
    verify env ed19 (KeyDer edCliPub) edCliMsg edCliSig
  expectAuthFailed "cli tampered" =<<
    verify env ed19 (KeyDer edCliPub) edCliMsg (tamper edCliSig)
  -- Roundtrips: Ed25519 sigs are exactly 64 bytes, Ed448 114;
  -- signing is deterministic; empty messages serve.
  sig19 <- expectOk "sign Ed25519" =<<
    sign env ed19 (KeyDer edCliPriv) edCliMsg
  assertEqual "Ed25519 width" 64 (BS.length sig19)
  expectOk "verify Ed25519" =<<
    verify env ed19 (KeyDer edCliPub) edCliMsg sig19
  sig19b <- expectOk "resign Ed25519" =<<
    sign env ed19 (KeyDer edCliPriv) edCliMsg
  assertEqual "Ed25519 deterministic" sig19 sig19b
  expectAuthFailed "Ed25519 tampered" =<<
    verify env ed19 (KeyDer edCliPub) edCliMsg (tamper sig19)
  sigE <- expectOk "sign empty" =<<
    sign env ed19 (KeyDer edCliPriv) BS.empty
  expectOk "verify empty" =<<
    verify env ed19 (KeyDer edCliPub) BS.empty sigE
  sig48 <- expectOk "sign Ed448" =<<
    sign env ed48 (KeyDer ed48Priv) edCliMsg
  assertEqual "Ed448 width" 114 (BS.length sig48)
  expectOk "verify Ed448" =<<
    verify env ed48 (KeyDer ed48Pub) edCliMsg sig48
  expectAuthFailed "Ed448 tampered" =<<
    verify env ed48 (KeyDer ed48Pub) edCliMsg (tamper sig48)
  -- Wrong-length signatures mismatch, never verify.
  expectAuthFailed "truncated mismatches" =<<
    verify env ed19 (KeyDer edCliPub) edCliMsg (BS.init sig19)
  expectAuthFailed "overlong mismatches" =<<
    verify env ed19 (KeyDer edCliPub) edCliMsg (sig19 <> "\x00")
  -- Garbage keys refuse typed.
  expectBadKey "garbage sign refused" =<<
    sign env ed19 (KeyDer "bogus") edCliMsg
  expectBadKey "garbage verify refused" =<<
    verify env ed19 (KeyDer "bogus") edCliMsg sig19
  -- Cross-curve execution refuses typed (the label is a hint;
  -- the shim checks the key's actual algorithm).
  expectBadKey "Ed448 key under Ed25519 refused" =<<
    sign env ed19 (KeyDer ed48Priv) edCliMsg
  expectBadKey "Ed25519 key under Ed448 refused" =<<
    sign env ed48 (KeyDer edCliPriv) edCliMsg
  -- Non-pure specs (context) stay unsupported.
  expectUnsupported "context unsupported" =<<
    sign env (SigEdDSA (EcSpec "Ed25519" "RAW") "CTX") (KeyDer edCliPriv) edCliMsg

-- | EdDSA generation: keygen mints usable pairs on both curves,
-- and unknown curves refuse typed.
caseRealEddsaKeygen :: IO ()
caseRealEddsaKeygen = withBackend $ \env -> do
  (priv19, Just pub19) <- expectOk "keygen Ed25519" =<<
    generateKey env (GenEdDSAKeypair "Ed25519")
  let spec19 = SigEdDSA (EcSpec "Ed25519" "RAW") ""
  sig19 <- expectOk "genkey sign Ed25519" =<< sign env spec19 priv19 edCliMsg
  assertEqual "genkey Ed25519 width" 64 (BS.length sig19)
  expectOk "genkey verify Ed25519" =<< verify env spec19 pub19 edCliMsg sig19
  (priv48, Just pub48) <- expectOk "keygen Ed448" =<<
    generateKey env (GenEdDSAKeypair "Ed448")
  let spec48 = SigEdDSA (EcSpec "Ed448" "RAW") ""
  sig48 <- expectOk "genkey sign Ed448" =<< sign env spec48 priv48 edCliMsg
  assertEqual "genkey Ed448 width" 114 (BS.length sig48)
  expectOk "genkey verify Ed448" =<< verify env spec48 pub48 edCliMsg sig48
  expectUnsupported "unknown curve refused" =<<
    generateKey env (GenEdDSAKeypair "P-256")

-- | Fixture DER keys (pinned-CLI genpkey halves under
-- tests/fixtures/), located cwd-tolerantly like the shim reads.
loadMldsaFixture :: String -> IO ByteString
loadMldsaFixture name = findFixture
  [ "tests/fixtures/" ++ name
  , "../tests/fixtures/" ++ name
  , "haskoki/tests/fixtures/" ++ name
  ]
  where
    findFixture [] = assertFailure ("fixture not found from test cwd: " ++ name)
    findFixture (p : ps) = do
      exists <- doesFileExist p
      if exists then BS.readFile p else findFixture ps

-- | SLH-DSA fixture halves share the ML-DSA fixture loader (same
-- directory, same cwd tolerance).
loadSlhdsaFixture :: String -> IO ByteString
loadSlhdsaFixture = loadMldsaFixture

-- ACVP SLH-DSA-sigVer-FIPS205 tcId 266 (SLH-DSA-SHA2-128s, external,
-- 24-byte message, 255-byte context): SPKI-wrapped public key, message,
-- context, and signature, embedded verbatim.
slhAcvpPub266 :: ByteString
slhAcvpPub266 = hex $ concat
  ["3030300b0609608648016503040314032100cf5339f7b748f3b48c0bbf22392e6f4254aeaa7d529078de7c056d3e71973df5"
  ]
slhAcvpMsg266 :: ByteString
slhAcvpMsg266 = hex $ concat
  ["4B81F0CD1F79CB8524D12233592474236B6B9EF279E53B38"
  ]
slhAcvpCtx266 :: ByteString
slhAcvpCtx266 = hex $ concat
  ["159F52B2492F1DFE8C3EAC8E5A05EDC7F098351F168A8FE18B50322DC24385AA0080BA72B3C0B07687A56BE544B2AFB19AACB440642AD8CF110572FAA6A5A3F7"
  ,"24F1400AB78873A4D99A4AEF59A1E7FE4AD8D2653AAA9B418B71FA26658910D194C5872BB0FA8A6D12EFEB006B63410C2CD884B67737BDAB1DF10542F58594C4"
  ,"9AB5529BAD13D6CF8F4A9DF855B83290B3F0ACF94EAA87E760353F87CA19B7AFE740B89EF4F5FCD8D2D261FF1E1DE05C78D05BAD357C0453544790AAEBA9A1F0"
  ,"49BC163515AB600F9DE17652FDDB2EF0DF2B306C09006BFE76CE4955049AB948255FDA4D0EBF87A83C65ADA07A7A219D9C9444A5F1C74F230925F59D549D74"
  ]
slhAcvpSig266 :: ByteString
slhAcvpSig266 = hex $ concat
  ["C78372208C5608819464A302A035902DF784D04CD83C4806F28F92FAB15270A36ECE71C6930FF09D8761CF4D4E41916BC2A4597F9102116B3B3625939400C5DE"
  ,"A5E654CA0AD2373C8DF2FD38AACC14074F8DBB4FB63ACE4F719B7C835272E361CF7FF9E1ED02D083EE3621E01C5FC08417FBBE5DA5D378322E2BE29ADF2A5A17"
  ,"924E31DB3BD1B6677A33B008FB3A8BA8BBB09FE64E0D5ECB9F0E8EFAC8B891ADAC83FD7FB02E986734794617136133275FE5C5359815F9B56772C30040C213F0"
  ,"27AE5B6A477F3267F0DA7B0F76B1D9F09C7BCEB3A37B1D37CD4648333EBF87907613FB9A25EC20191CE5B1CE36372ED29FC2546B056A6A56F29FAAA141FD8065"
  ,"E576D17582580F157D6CEDEFC61EE3E24E21F29778E9CEA21C6E8A16EFB04B841071C2E628A951AFB0872D425813A672191E589B68B582C33D5B095B90A29954"
  ,"F3F3452A4CA04ED90461D23BF8678E698EE1AF6FCB5274E3CBB2859F4A19D98DD96D5B9B4E0353D16167A71C92CECA77AF2F9B9DC7858C0B1213AC6006234A06"
  ,"5C1CA7A861F5E729B3CC9E5BD40FB9448111CFF60E7A88C15EC838FFF35C199BC274175779FD9D8EE821E66302D84FE787037C6B31536EA204B8059487E96D10"
  ,"DFC0953FAD29D9D3509716FAD11FAB5877B66562139A8B8C71B1C730DA416BE33CABD29A524BAB6752E240F65B9A5CC71D8754B253C5122F75CBC169EB665578"
  ,"D0D0200EEB57BE15C8745BB03218E7C69CF92A938BA827722D24D664F32448260473C76E0F541B842FCB7BB18733D618536D56E79D1B6913D05545CF77F32803"
  ,"EF1E53AB891B7B1D64492F2B5862127B4ED0DED51C49BE0E4C7748F384A031DD3A275677568746537963602FBCC2C9F4A81EEC8A481BB4AAA1901998FE11E223"
  ,"C00B72ACFB7ECAA4E09F1CC9889B04D441E4022AC91DC6164B813CC6E094BFC5453D35EAA6C2B0A5D492B95AA014BA0FFF5524000426D457355CAD555E8107A8"
  ,"3E844136AC8C772EE550227E04FBE7E0169210C7857BB21D2322F9EFBEF2D2909601A6009236E945E02940FDDACA4FF4B88A48842CEA97A16C4EC1961534598F"
  ,"F50EEA24ABFFA2DDA27B1F5F33082EA38C111B0DF14B5976BEBD4DBA3F73EA7342D09DDB21CA2260AF7F82BD6AB5ACDFE987E416C87AF9798407AFE3D5979379"
  ,"48B988040BD0FDCA59E301A3537753E0D0259DECF9C36E96ABEF8701974667DA05D98CC03CF449718BE0D5E974BBAD373B5077F3303716053D549B8259192E50"
  ,"D0E6047D1436DF010BA9C0E154D4AE048094DBE1D3A380E4CC9984A48666FAFFFC5794B50547F83CCF75DDBC7041CBD854FD61D1B94882B2ACC244AFD487B74E"
  ,"67CC5943C9C86CB5C811DCD4D0F988525F58C4344A5DB88F5F6AE49A24FED9319E60AF40FC249515857932827960C7A2831FF860D4F875D7516590FB40ABCC55"
  ,"6DCA3C21B9E78DFFBBFA6786E2169483497B080402F6E3A0C3FD4DEABA5D6D2ED8D47ED4E6B355653CD1B98600259D870EB868F524676D7C69FC9A3770813F13"
  ,"24B61485C9AC028FFB6904DB1D8253B8E8E05DB8D7E202B6CBBD4B504D2B9C55F07C0073A3B876C566B1251B654A022DEF289BF09E65DEDE3C54E33BA3292C59"
  ,"90215BECEA26FC3471EA11EC2EA694B66C358C6F9341F7501C1E0B598F0559FB282078EE4635C89205D9E3AA403E4223CD7E740C6D8DF080B65916C12700BE39"
  ,"6BEED89FFDA4CAF20328E459E669E9514DB6094BC0BDA0198C67CE96C11ADA4F437776B6454656EDC58B763F55FAA3BC19FEEDA4033403D5E7E6C4D619C0A727"
  ,"0AFB2266554FFA5678D34FEADFA2228B39E469F383E72F06D937E48128901F2295A3AB4AD593BC49F18D21A2D9423F1AEFB34D6B0C46348F759AF67D715EB24B"
  ,"9D32B45061876924C25F55C5DCF28EB7CFB16595E18184892183DB87E36C22A264A3A3705D29BD9018C0E000B5B8D79454E7091BC4193E1423E910FAD5EC6492"
  ,"5BE63885DFF6AC46375F873426812E6AFEAAB8B938AED8FC91CED8E7F7C7B9E0FEB36E9111877A3EC3F082A9E98345726B2FEEBF05B0656D055129A1C8E8F857"
  ,"77FF56E81824C60B9F3D68BDA53AB79DA9DE956BE91DC36406F27B2FB0B740887AB3510636463C29C76FFD4E3EFE0C1D5BEBDA8258D54E47414497BA3A3D901A"
  ,"EB8E7B388929C65EBFC14E05BADEA008FBAE199C93D3B6F655A07FF5E99C52B9E30EB1375F3A46FEBC78E8AE6619DEA8DF25C0644E25CA2534AFD1C3A443F2F3"
  ,"C8178E927F49D54F509C14A93C357E7CF4C1C102255C3ED0406DA7B86D5D623CD81A11C48C4F43587F1F106C75DA042E6918580CAA1408C7C1741152726953E9"
  ,"0F053A968B73C6AD5995D34B7F6B4BBB0154D3F7A05282DB6D9356FA97D8871B358E17675F83DA09ED16E299601FE0EC182667688A59D7C41D181437C31A98AD"
  ,"777936CA95D2AA4DEDC8A866DC0C2492CDD7016CC3258AEA4D5811FD367F7749D7481F4966765BA256D2535F5F81F0591048A04B4A113A5ABB7153BBAA707769"
  ,"F4774FDDF473BD2BB5B43DBC1CDFB39E3F23F2738153AAE6F1745A48ACBB3A0AA59B53B60FA575F85ED0E3B415831F4D734513D857CF94818623AD636D6E2224"
  ,"4DCE401E0816AEC85540D118B63600BAB3E7F11AFC23397EDD2CAEE2F739AE9890A21F6BFF804B21B50FD3533C9C1A5CF410238B784B21A9C6018E11243A859A"
  ,"E2A5C7A07629C901BE7ADE94F3009627163BB5837AA8680ED52E74F8B7E2FA73F1A9A77E698946A344B6F54E5DCDCFEC8381A1354B40CC2EE850B4EE2D2A8DF6"
  ,"048EF06551643FA0011DF364CC16949ACCC588090B914CB5F9DED9449C7959FAA750872A96B4678AD392F0B0E87610BEE3FB9E9537E06F06D6CDFCC3E6B3160A"
  ,"17DAA96ADB2916CA3C18708B56E629A34007C8A20CC0B49FB12EB57C6A39DFF9C37CB3EF80BF53E5DFE4AF9F66F0659CB527B1B3A39312DA5CCE8669A4F9C592"
  ,"5E9746DB533A990BEAB1686E765996B2EA8F164F33DDFC3561F67D04928D335A818C5AC4940336129F05A54BFC257D467672A013A9937784081E705EDF139D4F"
  ,"B931895F51A577CB1265E4A6E6C781605D0B62D57D220BE4A7507CF5613C56DC656F257E6E40C2EEEC35A39D2C019D6940B0511E9C989F6A5F92BC1BD189CAE8"
  ,"38350A3B8EA1E3FB27C93BF0D8631BDB1905DE73FCAB9EE148E44B444959F5048B02F048F7C01FDCCE86954BDDF3FB8697598CF808038238F61B309445EEC998"
  ,"12450BEA0B7085E03938AF7AB6D3C0157D560376A040596A4C451E61F65EDC078DBAD3FCB5156FA9075413DA3E6227316ED25F4CF1017B3C594873D00DCD6ACF"
  ,"E3F788054649F4BD09B82D9CF994BB1DA072A0D704905F313F212DADC6DC7BD53C870C304DA69FA4591BC174A97D6410E229D8CFFCFF6BD80616839BE409FF7D"
  ,"C67CB9780F1BECA59C80C1B78F0B90E138D90F058162D5045AEB5533142EAFE0EB654AC62940664C428F7EF45E6B4C45049B8F1CB2533B2DE646A138ABA1B922"
  ,"1FE1066CA2FCBE1C110F5CA5B7353E7877DD774859467679573EE98A6A8DA1A14D0807258F0FA4F215781B0E611362B603019FBE14F697F18A84EADDEDFEEA9F"
  ,"AD313B51134342CD6C847BB027FA23677C0A59B85E910FF26270BA6F6D6C6B7D3E8560E2ADCF52984A9EE675A15D0165F1667AE941B1B76C35CB06A730FF8575"
  ,"3581771FC6E23FF116F98A880B3F359FB985797DC12F95D0E1421754C2C7FC001123C1ACF96B6E4631A9A2B81D0C5988318EC821618443A08EA4D7225434499E"
  ,"1353D135741E3C7AEDB769341A9B05C2D1E3315511DE0ACF23F7D8DC845EE47A6B5C353397EA7E6401F82F71E1031F8E0BC5555A5527F331F0B76C9C76925D9F"
  ,"AA84469BA49D42CB33C4B66252552A2192B58C5C03F6E12DFCBCE0713AAD83030FFFD9251DF079F5DACF29961D49BDEBF647683EE8B32B55579D79BD510E4ED3"
  ,"323A4966EE62B771509DCC8714194B8E0072720A711B4A4BEE7154565E75D3C2F9937D1163572B00FD7433E3F7A80850EBD4A2D4A79C2BE621BF91FF9B32D869"
  ,"B4665236C28BDF15EA92F507418F70B6264F8FDC30B631358BA42C8D7E112B85486E0A293A91C957455E815225EA64649853554668164F56457DC928D690F99E"
  ,"99839C5D2FD8C74FA476CD44D886B1E410E037CC7F54665FCB86999CFC50AC2954C59371B6225BBD87C8F1A41253DAC39DDB234446E2CF1AC2607B29F2929192"
  ,"04DEB65157217A0DE2DE894586B37BED4CAA3CE3A120E10ACD9D04D7F34BEA0CB9769534276C41C8320A3217060CC673DA96DD2C948C323B8927292F4356FAA0"
  ,"3EEE1D5B2511B5ADA4150C840FC8B569825F43B9E08CE868CEA0F2369A5CBD96771F9F4576FB853606CBCC46FEDCA0BA8DBC0B4791D4D42974E83E3835C7BA01"
  ,"FFB1B71A8E4FD48DD438BFAD899D83400A80F18CEDFEA5902A879E53B63CC51F9777F4ED9D978F07D5D52D9A5CFFBB85EF7070BE5367D032D91E3BEAE812AFB8"
  ,"16E603FD73EEC182D59C2DB88DF06575BA3450707B200CBBA018FA84385693674B1C29FC40B9FB335BAF3A0861D33DE94440C3BD275F59DB596047A015C2F435"
  ,"64BF9572CBB44D85981A866B32B4A9C4AE0DC9EEA234C2A407DCFCB35E8A877D07E932D63213856A00D4890C3BBD7A33CE50EEF5DBCBF0CA796DB2A54FD038BD"
  ,"5E55DDDEDF15F9AFF37233ED407001FF39FFC2A09CC5959399B5127FF343B8BA2A0B599E99E77C81D6877F7034DA4EE864B9F773E3694BFA3CFD00993CAD7AAE"
  ,"59A4FEB2987B0C5E104A5F0A36C0D670D708BB7B37DD9CC5A56F3BF4EA92C3DA444ADC49887C5B36CEE627C42D71885D115E8762DA890A0CFAFCCF80D368CFF2"
  ,"E3523DD44ECFE652959C07FE6D08F24A53687F86A0F53B0FB8A7C91E1F54E4B8C13838649D9F0339216A6271F2A591B3D712A1521BC284FD27AE236C50857423"
  ,"516725D5420E50FFD514CCFC61C1934C51E7B3C70159BE5ED25B68E14B01ED69F9C0929D828B9CBE2EBA9E8B15E2FB89064627C3485E002F92E36213CECCC1A4"
  ,"855F7726BD1F8FF541DFEB9824DCDD7123876B9EA57AF9D0A18BF97CF93A3DB2F145D4DD9D7F4F6FF897AA8F166B3949874FBC12B2C338F53FCEEE62B8EE26A4"
  ,"4923E84D8AE8B6AADA6123CC4F030B58C6C571675A35C4725E8950F7F6A7E5AEEB3FB7C82674E3EA57E4C8B8A1D2A81C7442F494C99F06413CA380CA44EF0C54"
  ,"D2837EBE9A7AB46043CE83A2CDE39D68A7413FF4E7F0BFAF65564A8E4FE1054091D30F1C2392FB57F6DF770618D66DEBABEADB90465020807C3DCA6D4F0CE6ED"
  ,"CA9138F209EA30E8242BEFEEA4C477C720F6026D61FBE4FB25C4D7E24714AE8EED81D857B27C07B8815C1AC28D87ABE38A6CCAE76F308E2D71BCF0BA7E37B439"
  ,"7C6C5173931E068AB4592999F52C4711A18CFD290417C3274EF786F6210DFE548D3AF7C2D62077AD8AF1667B678085927120679BBFA2FD3C5F863024F95A86FD"
  ,"9039C4819E713F2B2FDDA5C19530EAF3AE422E4E72A119B6D0CCF0FD9A81E3A5C028C3174727F1C147ED3D09B69C9049B595283D1CD6EFD9589D0CE25029C55A"
  ,"BA3298697739313AA4A0D4CD5D50ECD8EC63EFA66751CEF4BD67AA517640C39F6E040AC187F52F4E93C3A3219D41D5E2F02A2E4D0368778D866F89D7220C1AA5"
  ,"39448C577E769B3F934E98A7154B2D5AF0A3486468785BF5692854D015B4C1ADB949E2BC5E4A5C7A177EF74BF5419C9646E32C8B874972638752AA57990C2FE7"
  ,"34E4AC8BAA856B437C469AD62A2319379BB4BC3576F35AC8B8F7D02727666887872656AA5359ADEF7166E7DE26013DD760F52821026AC2AF6868CCCD5E0A5D5A"
  ,"5753CF8D38E86718E61D5D92F538B451C98B2B5C020E7FEF3C19F0E7C14FF51A2BD730AC1851671357953A11C71AA68043A8C9FEECFC8016927D18179C3127CC"
  ,"50559FA47D532EB9772A28821FC2B25488FD12A687DBE6B405B9DE8520B7C971A6F51BEA108363C122262AFBCB02440C35DEF291B18807B83816981A621AB8BA"
  ,"08EB78E94ACC5E27CF0E8C0FF78D217E5DA2A27056F0AF0D52BBEA0E73D258F0B16E3237A64D958540011828055B7679B777AEC869E0028C3D948A01751ED734"
  ,"84B0E80B104B803ABE5BEE3B0651B4D9AD698A5DF59B4A71D1632A7DE72D807FF4810B201A31AB3B1D3ACB7672DDB4BB75B56A5623579AB35416614BBBFA119F"
  ,"F2FDDF7715CFF06B116DDF22DB90F14AEF3D2F6D4E7A2129497F7BF2675891F4D4A1360008035B52BE64D8299F2601890011511159438BFC6C04BD7B7FCE4F2C"
  ,"62A0EB0E1B1E038662580FFFA6B3D4BF08561AECE0B368799B31DFB3DD8B598E56B952DE01252C4A38674AEF90757C0B1B1E2CAC61632DAF9F8A932F6F732A5C"
  ,"0432A2C23853C6EBAED0601219FE4A248A9352683B2FE23383778231FD72578C22668921639C9C052F0F3A4F6F701347420630EED591CE81F6DC9AEB401AD2F5"
  ,"A2C1E19BA4795909AB3ED0DB810306E0E578DE97F923EEF13ECC4B397050D06FEE07A75F296770216D8A78CBEC016CB7519E629C7B27358CC90F8C4BEA8298C1"
  ,"6F33196F89F47C7D7E71582D6D396247BB0EAED76CECFBB19897F34261C5F72157E5B930A4B30D6FEBF653B8B7B4650BDC7B3365013137EA0459CDB13349C967"
  ,"5062CF72BC5959C7EB6FDE873C9FFCEA1F6FC167C5EE595A67594C00C5077971EE153B8625082A8C2AAC2F4BB9734D15928CEC6C6655A6AF70550EB5AF11BC20"
  ,"38107CECFE31CC16714AA7B63CFB496A48045B90848F17A412308DED6F7CC3998A2448356AD22B34619CEA5C130F3E729EE130EEC0950F502A60739D622C67D7"
  ,"B5840D9C2CAB6ACBDC34B2CE8669987BEF284F40A68B213480E56E93AD89E7B5C120B207DB50E1E48AFBB703471948D5348C35F5522BA00758680479882E62DF"
  ,"2037CC6C42D9089FB3F4C66BD8CAFDDBB166FB82E14AE691A30AB261E86BA3EDD3ADC1EEBBE092FC42E03C50C1158E24F4A214F2464A68BA703346ABFBC5F400"
  ,"DC15BA5FC20C1A73304AAA57166BA0DAEFAA0D84899EE378080AE6C3480363FF6D6DC94E8107CDB4086447DDB388B7C67CD994E81001836C60133F7AAEE5F006"
  ,"2EA7CB17385E2EAEE9EDAE5C796F91A1C0565C5FAC6C713F3FC2DF2369E4C05913CF7878DD609F542063833CF498FE336FBC0DF547BB3718B38B064355CC55C1"
  ,"32BA46D3BE8FD64484D3D9E136033E6381DD988F2AF6A8C22D189038D309196FF338D010E3558028364535A271FAB6DA41D7B66A4D6AF4A6D4091ECB48F20936"
  ,"F4111FFCCDD0F32348FFAB263328D8652E573F944877913CB6F3DED223606D6BD77FF7FE7A70617FE5358B8EB83FCB3E34E88859848FE7030A1BB9112126D5E6"
  ,"2D6E557564792A0AF36ECBC451FA0264F76457B31F176366D270CDF8834360FFE47B9ADE364AE4C44360BA9FBFF03058B94A5F8595A161D2361D90F719CA0C48"
  ,"5B64C284D980AEE322F1B3597A54B4667F7175E8B185D61A7378AA66EDD208B10B150D5CB328632FB524F4C12411E5109BF7275C6F9899FB9E396AC321D6456A"
  ,"E676E8ECE8A6EECC9684880EC47F788791471D7F38F6BAD33C1CB695DCDFA6C03FE9FD0E9239810C496A7A3B58F554F7AED485081C92FF7639D32B3A38B521E6"
  ,"BDD3DA99A92BE99FC690D47792F942E95FEA9375C4D8DA7089F27F61FF984FD3D74E3753C8C6C40E9011ACED177732DA830970059235FD5AF13834B6E867FBC4"
  ,"AF0B5C6AEC6425B37E432CC9B12B1209B922E33774FD8DB59C2F4841CF79811BD9ADC4FAA5446A03895E4E91E0C009AE25D9FB7FDA336E7F46EE30B7E483DAF0"
  ,"F2BB4197EE98AB238C8972A92D8B2F7150007DB75E1F26A40CCB95E9449815B28BDF63957FA66A2775528B14D5D9F06E46AE81BE07A01D938305E5DD9835A372"
  ,"6397DD511006915D51F6E3DD87A22716B6BD99808066671785500C208F6B34B40D211A232B365A69FD4E84D06E8EEFD431C4C12B623FE2CBF9859D1682E9F6E1"
  ,"7ADCA153C621A88979642FB7314046AEEB6BF2C54BD8C69A1F473497DF4CEF5442B6D656D5D4D4BFFB57B4DE2320823BD5CB6003561494F5BF5CE8D6089AFF42"
  ,"DCAA03CE3C70C9AADDC6E08B04C210728910E8B6F7344778EBAD69CC7D70E2C3C5B58E1D60A49EE96F46E03A063B4EACB8D3FE4355628A17909EFE8D938F2CCC"
  ,"6A96AC5C0212508B5FFA8113A431273DCB0728B6963440241B5EBB9CDE155E36C9D10F983B15052619C2444CBF885AA1B4371E2C793DC8DAF442C38FFF1EABB3"
  ,"9FCB998A107A854CD6DA6D1019FBE93F8C4869D484234B537AC97D76F8C1C83C2478B659A7098489D2D98528A9BFE07F1772FC6F3873BD103930408614407837"
  ,"F2A388FCBECB0C3BB571CB28410B777F4483D68B0073307E59A8C20E1ED610A24DDF27EDE241E4E03D0346DFBDB34D170768B98EBFA9EF012F1D3ADAF1D2B57E"
  ,"6AE85EAD0113B34801A42714A4271C9128B5A4D5A686E50323F63A783210B04DD4647FA41D3AFCB71AC024C11ED6A11B18DCE7F5EC0A24F8A061DBD440B3462B"
  ,"19A309ECC4DD7660ED106DB67D6E12E079A6670F0FB94C94E4D677E784002A8DF3CF8528F6F0F8C5DE118864A8570932C7F03DB3A28FBFA5FFC397A9C24B1802"
  ,"A25A54CE655A3CBF34BA35EF40A2A68CEF3E42042855FB836ED1B91F179E7B2E6F42E7C27F61B5E3A5CC40F88AD5EAAA75128E08BF14E95508DB560632B9CAA4"
  ,"FA118BB8CA7155AC5E71DBFC24507099D375B35982357D344E458EBC10DE380245C4307DA9CC1984B1AD622E9707BED31741CD61A6FB15360A5E8DBE868CD9A7"
  ,"A805AB4471E7247FA1A5A7F0237E5B1E72B0CCE541B6A4D91BBD1B1026BC105DAE94E8941EBCAE4C82232F0DE675E941829D191D84E58FCF6B7D4A59BAEB8F91"
  ,"8CB8096E7FA737FF4AE61E6B2A679ADA2D8293093C9E44968D3F411785EE446FD46AE86DD059D00B80E384ECCBB06918F811240F2EC92AF3B8A0D2C12E734C9D"
  ,"18F2B45D6FF931C579669DA6D3FA2681C4B8C97B209A814D5CB18540528F73F196F1121C0AED955D5673C707521BF26D4ECA528C9EE7662600FDDF13912206B8"
  ,"98B5AB4A8BCB187E7303C523E20D951EA63AF592AEBE7EE6F9631A8F5DD3E8A4E362ED1FBDBF9C12CC2F6CE78275F4D354639B7095619DF4BF02FB2FD1578DDF"
  ,"02E26FA9B3458F20E1E949575744BF98A9544845985ABB66FB1D6F1B09B523D2D8E78FF3374240FD2952267AC5BF6BD29C635C0D04D72FA82C1FA37E8C32B35C"
  ,"43614FAA33BC9011628CA49B8EA3048DE739AD16DA93F9B790FAB89E879156FD4BB8776E1DA8222794862ABD5BF2E0A08AD4F900E2B84AE05CC124D9D24FCF43"
  ,"EFAEF337B0F9B34314CE1EBE852F9FFA285D3081E16C6B237B7FD8EB44CB46F341FDCD83AAB920597DF464A97A486B33407653A8F3A2803ABD9B9BE5D8ABA718"
  ,"DCF856ED19164A0EAC9BA873BB15459F4586F7E47C3096F2D3019682733A3468830A808800E1C7B1EBA549C6C3EC289C017961A0BAE828D8E492A29C2418B585"
  ,"50AD02D586E4ECD67C9DB5079510446301B6C23A4E489BB298C89B5409D4748B5C2689223DCB660838076C79B41E7E4DB59EB81427E7686D013BDFFB29A5BEAF"
  ,"EA59CD097B9CAEB9F97B9856EA050DA3B67CEC60785A140C440693A30EE862D7CFA1FA31A073EF124D21B1DDF336D450FE55D3DB62E40339001B678E087C35BE"
  ,"5E9EBE4391B5990F5C198E46112745E0B1A90C58E46023F0B4801776300D8E375CE8605B58406F3377FE1165D5FEA41418BEE47763B6E6811FF44D7EE1B8247A"
  ,"F24893568B3780511447788B6E4CAD8C1CF622E37390813E8261464C048D790B4FDE09F3EC0B8176E77E0E7FC3FEC5C83BDA548A43BD05E607AB79308DAFF238"
  ,"BB20320CE9B93304FD904B629A7B08C4E7E0CD9B12C3FF524F981D9FF02C7BC1FCBC5AF41CC7C8D510879AB005B8B54D4C76F0EEA50A4D888564EA3856D1E82B"
  ,"DE18F673CEF82A74B4C7FCEBC7D7C6E4C27A57173FE8614B7523808C6F922585622CF02F70353D35719DBB42DBBEC75ECF111BC8866FD57AB1A9C8CFA33FC215"
  ,"C6923D7D4296CE7E71005C67B205D722C85AD10FB70CAD11873F339F1A28061FE91FCBC69FEBEE8664F7D8FA2E75A7DFF2D617A2F966183F61AB04CE53F6D0DE"
  ,"77E539CF0BA4B03286569E417FD1873B646EABEB2FCADDEFCA9D47E14D00FABCBC51D5BBDE194A059F4DEBF5984D6E9722DCDF76A3B235F172A84297BC256E4A"
  ,"4F7D041889A7A95FB3111CDA6D8589F43C974FC1B250D1899061DB1F69E530EFC3BAA3F074244902DC3CD9C3F697E89E73CBBAEBC310F116CD7761E34AD8EF95"
  ,"45DAE1A1720E702EFAE51D074D68E4B2CEB2356236A22836E6850BC1E04AAAD6D92C2525AA93F4149B5C620EE5FA33B00C9E61F1ED39FBB023E76F72B678EE4D"
  ,"C5FE6FB65F42F2E4196A367A3DC1FF0F025C02A43FC373CE6781FF471ED05C3DA5A9D97E18ADC946C6F25E2DA69EBFA2206CCC12D2B71A05278361B54C4086C5"
  ,"C7DA31BE5004D4A1A0EC3193E0983DCAFBFA8100E3D50B1618081FB784A61D3CCD9F52EF53FEF4292C6C90ABAF0C96E7947D2B76B10B868938D3B8E6CFD8BD06"
  ,"83B16A67C6D8C23A01ABEA7E2665D82BE67C8F4476E9C3EF460C61413AE21AAD4228A41B3852A25ED71CD7F0B791B7B98C190F1F0E76500DBFCBF0500EFBC526"
  ,"CE95F5B60BDAA736C98350D2FE53E971C90E16CA0CBC55ADDD6CFDA1D5E32B5B43191F728B94133D1D06F35F4CF5C8B4431C4F2BB59A02D60064EF05512C8AFC"
  ,"DCE061215FB5C379290AF5299B818A6440606CB691FEFAE83E961B363C486151A875020BF5515D3B5DCB754457DAB13C5E03DE9F718A95295AF556997A09BEE2"
  ,"7B3CDF6588398C2D5372C4699079906231DBE9FAD35C620359C072E878E5D74B04F861F6CEF805B41B452599B84D758EE095355104013575D2E67CDB9B0E3F9C"
  ,"C46C8AE02C2273F4E2B7C133F441D138B1BC222CF6F0C3A15CC81F70E575BF1257EFC3B0EB75954284C4B0BAB281E990"
  ]
-- ACVP SLH-DSA-sigVer-FIPS205 tcId 343 (SLH-DSA-SHAKE-128s, external,
-- pure, empty context): SPKI-wrapped public key, message, signature.
slhAcvpPub343 :: ByteString
slhAcvpPub343 = hex $ concat
  ["3030300b060960864801650304031a0321005153524d8622042426e76b4b818f0c45d57c602301a55955cf898c0fd2f3a7fe"
  ]
slhAcvpMsg343 :: ByteString
slhAcvpMsg343 = hex $ concat
  ["8D37BEB2B152ADEC9F29C7E9469A15DE59BDA1BB46E2987C25C7E36774A0A7D703A7CE73203AFDEF5A61F3153365F37B0A9F3FA3077CC25BABDEEDAF42084E93"
  ,"3EFA4F3A16207E9861A937093D445A1376256FC234E6D252E2E4949ED25F99926B31598E786AA17A62738AD9CFA4403F7CBF0FDB9AB9C49788C7A5B79AE00BEB"
  ,"8306AE7E83D7D28601097CF97E5A1A879C2F7EDE4A1D9819B0DD654BF0A383DE6C0834E92CDD6FFA9D59F933D27475ED13965B1EBE77F3B8F0DA5CF2D170DFFA"
  ,"3C4F6DF3482D1DF84D3D553ED589F30CD037BBD09EC02DDAFB7C1749D6BC37F398CEBCC6814524CF66FADFEC51EF34072332AF096378C9F815EE396CFC84F22C"
  ,"29A72E0A91173E80401F4967B943C834E914CDC8E9619BC6D84DDEBFC565EEAF61982F1A241D1CF1FA996BFE3EA146F4AEFED2EB3454C558C25228AD093919AC"
  ,"1E8809FF377733BBFF011DAFBA5D1800FBE8F8DF110C376B98679257D91BF31748255C57A241DCA7DDE4F86CC05DBF54A901C9FD5162D17ADFAC41141E119FF7"
  ,"6DDD0C7AB2C202C4E54941E3871717D97BB068791361F5559F0E19A406C1F01FC77F83D7373B05127ADD5E46B77089F95047D60F306677F1B543B5B7D47DA144"
  ,"90F9531111682151BF99E08B53AA9954C6ED21A70680181A919440598CC4AB5B68B2F050C550E772EFDC9049810986F59D417C7FD80AF6804A1962F8DB112D4F"
  ,"E26194D9A03696426DFAB1FC016333F38D1C6ABA148DBDFD8B91875B93546DA1D991ACB5FD131207FC910D95078211D174F54D48B206E18E1792ECB23E92D47A"
  ,"8FB97F1334A8E9DA641DC1F61CD48F7843C5EE67CFFC5A58A5E05EE6ED7725BD87296A97FB5596635D1C450D5F876F7679DA2963505BA4F9507A69CB0C46F6AA"
  ,"2B207D8C4A08536D283FC373F6ABD20EAC6A2DE42150DE05B6B5A04EC2BFA3208F3BB932961CE1A6BE4AB32F615BAEF1C82B8BAF6786E5E45313A92CAF12B7DB"
  ,"6E24CEA59C9B3A371A956A073431195FE150607A9B11455EE056CED054FB3B2952E8617ABA8F4129A626C1ACE5C63A21E4FD27EB3B0AC3CF9F8934DEC5E05DDB"
  ,"414FCD6F52FD5D083B9C845FE1E4E8153493B0B2D67D792057B37818987DC52A85A291CDDC6FB494AFFD69B42A1B8317A1CC5B8A0AE37ED21DAADE07910C06A4"
  ,"50AE7A65FC8AE28F1EBB95545096CA36BB0A249E2116D9FF088D57BEFED34F4452B94AF4523F22C66B7DA1E4E286607468DDDAE151595E9BA3CCA41E514D0CBF"
  ,"9F78DBB00A321496EB76F780B17CCCADABA80B0B92EFBC2E6A552766D50D3D62FD5360AF330C1D74E96DD00E87C8F0CA337A2C8EB0091300270FBD27A7FD03BC"
  ,"847F48A246FF27D836BC15A5EFE43D277DCE63D9CAC2E245F5A7AF5BE45430FE13BFF3C5EF6E989653F750924F09A7D66AA17CD7FB177C77453710DE967ACF87"
  ,"4E64AF96BBA8C9F9A55FF0473A277D068645D6B4DB7F62C256AE6EB8673DF6433E8ABACD0F2D1C405557575ED9D326B3F0781C8CBE0D110932BEC4D8E81E50FC"
  ,"BDC91A60DA6E7FA3D294C1ED8895811B8656D7B83AB30D59EB943B8FD0EED51744DFF35BEEAD0AC7305740CC66FD9D6D4D95C7BD3695DCB125090EE435AFFA12"
  ,"6028EA2602CFB04E140D4D17643262F979713ECB01353F2F05F62A9FFB1ED57E6EA5FEC9F617DE8C60C8F376C4E2A74FA90A030B2E69B75FF1E13DE15C111608"
  ,"8412F90C820B037D7D6D34B995311043D786B11227599167B180D4FA945CF9958288A7D4257ED65A1C2B65BFD169E0C6DBD23D56A799912BE71F8A586520A8E2"
  ,"2C052375F7EB1615DD58ABB88578873CD93A1A3D3E269BA5FE9EC03C93B3B3C8E3EA3858A5B900F60F7B7C423E8FCAA85B1E0C19E88CCC655DC82FF7E1259059"
  ,"9BEA484F21E25BE55303C90A8BF86E2D96A262240D4EB22B3A593A019F54F9D986083BACBD614BBD4319679AB806BE98C9CF4CDBFF1762D69605B16C9F9FFFBB"
  ,"9D81114A9138FCE27D613C6F244931EBC6DAA09F0F975A9752CCE4B944C91E7F898CE4E9F285736A6E5B7259AFB4A37BBEF535BE1E8847816A03CF04A26B3EF0"
  ,"BAEB24C8C5EFE1FB99BF275619C59B22D1872482B9D96BAD54A9D9D3800C2996B18B1E4AD77403E378EE988A359B2B43D65010CB01EF7BD935FB3CC8D359EA31"
  ,"495DF244087273E153267234B3A0A99071AC2C6B3D72F4A3CF27BC4A555609EA234B2ADF2C9CF003BC4E3EF5934A01F246921EDD430D7C743D1EE0F8752F3091"
  ,"1B057FB493EF2390896F79BAE631C2B020317985E725F0A2FFBECF4F2D79733508252656FB2124C018060333B07C320C6E0D72E86438B6425C7AD5B7B03B978D"
  ,"A32A36183D31BE921ADEBE9E684C1DD4757F8AC407165F3F3E6487B9B43E9FD6A46B7FCE50A78CF9D279FEC377F4A7E43389F54F123BF823F887C0C92A900C19"
  ,"A236920F30515E6BCF9DFFFF3957C6FE2EB249C057410D377BB020AF135B96D279381B3EF3D5977D494D901F7374D31836D425C1628651BD7486E5C7CEA8B860"
  ,"BC73740D70FCD35374AB46A8FE81BD6078EF57CCBB5245ED468C3AC6280B2890F68FA031D54C078DA0E114A7749749AF4C0DD3F738AFF05DA44959788A733488"
  ,"53BA4048300A6E4BE7907BACB0EA379F04C4395C947C4B36D8D13B4397EE1D1B8DC491AB374E74866A677484E6C82EDF8DF167A78FC14DE5667797A490D9B35B"
  ,"146174DEC9C4906C6CC91EE261B1AE6F76CB1C4A4A317D01A35B70C7BAE04F8949D5369437A5ABAA3BB1D90CC3F040D63F5185E062FD304AF6AC83756FCC1D46"
  ,"D6E2D2A288EEC1FCAB7F477A7C73AE27D1DF94D826256B1C77BF82F8A15729832C5680711812B6D329AC05CD19A70979A525CC984F499C5753EBB43FC1EAA8B1"
  ,"4D612286EC534C9D78E422C37CBF082BFE44E3490876E54EDC6DC464AF2FB74C6F828C22D308BD896ED50F359878C41850646F79371734DA83F58EAADCBB7388"
  ,"19BA3B41D7588F6EBD1A613D5068436A18A12022B8D006AAC4647A62767BA4D012609EDBE3DCB97086274A3DC2F83EFD570525808C85E9B7951E1E91C8169608"
  ,"5824368F669B703D21ACA8A1889CC9E2F542780C83FCF548EF0476541ADB1C2FC9D2D98CDB3340D012A97C81CED8BC0C72396CE5455FDA32B112C3A76B83E69E"
  ,"2D767A44A83C1C6127BE6C5D2EA65AB2ACE2D701794AA5431682C9F895688F7E06AB27288B68EE4A3AE52FEBA2F0B47A0A580FFA"
  ]
slhAcvpSig343 :: ByteString
slhAcvpSig343 = hex $ concat
  ["E82C1E1828F2A3076BEB5C0AB5E90C74E61529E3194B636E4D4C9C0A6837F308DD13D3295AF14A6F0EA38822C82E3735327347A483F1A7A2B9F64C8E1B1ABA12"
  ,"52AC10C3C82C1F3BDF5698D4CA317D5A2C996B234AFB128A416627B89EE40316B194B948ABFDE37C4BF60676D6FAA985E05C20BA63C5B4B39D6B76831B6AA6E0"
  ,"49564B11E3BF2092A29E4342E6084562A16F7EB4E1EAB1DFBB5376009B15309A9D5AD774435BB28B4FF59BF7CDAF708BE9DC443D60B1C86B3BAC16EBCA6FB8D5"
  ,"3B17757489C0D2B027EAE9F9BA361CD05C9BEDB7CD37556569B11E8CAC6673E2F6FBF61FE0EADCA435401BECE535F8D9FD3836BF65D8B15AE3874524B6F6282E"
  ,"E5FB80BD1174ED1AD764DBDD33989854F3D2746A850F1AC5A9C3BE18467B178F4EF59F19F44AB72B6532C74FE8F6C81D5EE29496F538B8B1A212E41F756879A9"
  ,"9651FB7E8DD8A85DE3B67F400B657AEFB8AB01C8836599971A56E6112966BC4493B29885CB85E67C8504FFC74DBC4D0179EBED747A9C98CD856E15EE34563B2E"
  ,"22D3BB634F612AC177F4695E49B50E1E1F14F673FB26DE99F4F04B55D62332FC554953B35A2D548054EB6A1E8A14B5CB526A0DB290A0B63A47F49138B45CF712"
  ,"DD9914D9469F13790FABBFBBDC9B2409A7E3C951B836AD9633D1AF1F98DADCEB6AA468D415712631D81D47E8289829A57F457EC3729747616BD41DF72EFF650F"
  ,"3EC2D4A37960F8CD03C7F98CE474C70A9E9E4133889A607C97BB6C8628094EE06814CDB220BCA6A4A2188F7D56CD3AF3213552722437593333180F8EBA467373"
  ,"FD0F5BBA74165745885CE78DF23FA95EBB405D0B207B41A88246D08D5D45FC9F0FDBA4E45BA07F30E8152A419CE47C61726A98C5AEBE3F236489AD008BD03AC2"
  ,"081E1B5F230064A12FEFC929696BED2542B62FE728E8AAF8D26A0423A4D29CD7B7E468F04BA04D9C87B0275540925A4E0967580FAD31D68A379249A2B3EDDC23"
  ,"09F24EA1900ECE3099C5CB51CB87380226267DB2744A0C46DF9A6EB7C7064E949B5ED0CF7E193527A57E0D8A25049E58A76CB0DCD09CED49B366707207A2653D"
  ,"1A322510501CA3194556C4FC0D5FB6091583CDD77E4D802F1A6371BDE4F323D97D7A6B000926E7F8DB0571BEB3F387EE5686893AB32E71FAD17C01B48A9A616E"
  ,"C4F27FF7E998957CDDF7629B321A6465FD86A62925D64D29E39E1A38A42AA3765ABBE840AD2AFCB5F542DC069B49C03F34CD0D79B8A7C07C4E52C4489A1717CA"
  ,"D52A4E441ADBD7C3BC0FAB9A939C546C82CF4B9AAAB239CDDCCDED21B95F547F484A482A1CE553F612E39C04BE9AF0D6294F14E86447B2AF4008653E034332B2"
  ,"B23855138E66DBA3E2449E0E3459B876B06C5F06CA6A53B4D683996C5141294DFE6604769E3576B48625A82D093EBEA6F6D78368999BA34CAB502DD519132225"
  ,"7D798FF3CA65E1B788F840C20E19389A27D7F05D4612395D1F23F55C7CC5F180B6D7A02610B76775BB44B5D674A7999058BA142F5FC16E2A5698C626641B5CDC"
  ,"0CE5043C0E8851898C1F06D49F6C7DBE56ECA8414E29CAE1519E2127AF222BDFB105560AEF75A3717263D5152108D6FA8235CC4FB0C2855F47E9949977BE8868"
  ,"A1CE8F9C40C2B56DDE135B56BB97BDE5CCFC03C522966E6CF7F98849C10935E51C27422E2C19DE423C674CAF5B105C7D82C3A6C943509321A9ABBDF8B6596946"
  ,"A454E4EC4F13114608466E22B81F83C463022C12CA9234FF75EEE82D7400DB5DEFC3B1210C415410C22AFC3839634D52F71E29F514CD5410E990EC83D742A3F3"
  ,"33909A38FAC9934C72F3C19477515692F949C0C4B17E4E7EF052B200AEB99464BA27F349A5DBD1F57013446BA29B504CA4BB663D81A74CB4FC6B5A5F7C47ED07"
  ,"CD2BC54B0C73441794CCE2835F323CB5755CC3509AC9B844441C03456AA9A3509BC9B96E7518358EEA40D456C208F49246FC7208EF6CFBC18EE8B0E38EA77590"
  ,"918F2FBD49E2146413537CEA1812178CACB3C009D3B777A9DCD3434F0E5367BA2F1775B47889466B65A4656B46FB9A2B310AAA148BD033B39C66533A90E14490"
  ,"298DFAB0F9A0B374AF2030363935AA9C986E1B98F405C28B25145D068BB30F2018C1B6673776C4AE015B34E0A1DC589AFD8B201579A89127DD9F9CFE1274C073"
  ,"29FB1C2313C94770BD9C8A49AB2429B5DE14DDE9177D8B304AA992E2B82032A224258AE8D56C7C5829940F2BABC730CB1C9D865256788EE8E5034DB4E8F71277"
  ,"7C3D15540E5534678BFB40B350049B7BA5920F4EE6A1674792D49CBCA2BE5D0C13E6726213315DA3112A665E8ABBB98C138E5052867AD018D70367448EF64012"
  ,"98D0FD213A9BA6AAB44B4291230C32DF477932333E5526492CEDCA9EFFF5E6C81C30DF4A74EF9BE9EE69ED124C13888159AF6FAD378F37084B89B2897E3026B1"
  ,"6547FEB371ADE0D5290B43F3A91AC6756D254761C006C1DF897E78435B46FDEF562373EBA7913AB53E8E9862F86EFFA0A2C3B3B9C3D9D4DC49A148B72CF6777F"
  ,"13513E0E548F5DD188BC67EA858FEAB104117274C9C4AA671768877D949FBFCA77BEC21FF0AB73963383750BD20CB01D504DCD774673182C6FF934C698ACE62A"
  ,"E4D6B95F8DAB09C376E81218A18DCD0FCC9C0EB46B96EF93AEF913826BBD10C74B3DAD813ED999C36954E73D1E7958817BA13ED06EA025A6502E6CAE210CDA6C"
  ,"6640C95992A006195F21F6E9DAD04ADD8F802BC07F86A33A314CD7834DA063CFF7A33AC63CA49B07293947415F0EC2650F12134C301A8D5A916A6C1380398406"
  ,"D9BF499B52E0AD317F12D378CFFD44E4A2E27B68B93F8C560611275546EF9E98B7F49283D70FD53EF388B494F24CB0A26ADDFF20FAA0ED2ABCC885A8709D902E"
  ,"608271A62161CFE7E4BE4864328EE7DD5748416684D8BFF7706266BB2FE87754A9D5000D1A56D1160D54CDD9E58884669838F6D1DAB69CBC1A870A21BE96D1C4"
  ,"83270DBE7148E023ECEEE4C2776E185582E874437B6789CC922D337B0F6C1BF962125B676471D335F2BD61A69FB535E59E3C03ADED04E2866C8F141043D0EE20"
  ,"80F8906E4AB53CE5ECFFBADED0EA866AA741144E1B758FC49798B2EAE97D0DB15F23277BA2E42607FA5848475153A1CDDC86C4C10B56181710244A23AD8C2FA7"
  ,"A77C55A899B5880942C4B7671A6F998216C0BCA8BB9314A7BA34A38D56B5810FCF928FFD5CC43271D947944DFB416C19E75EF43B36E6C5B8B3FE6023963B5197"
  ,"2EF523ED84250405511464C2F4D65774E083F705E5A02920EFB61177889A5DBF3C32455D0F97DCF33EA11C971297234C4A1F6B1F549FF5654AE7D11D9F35C1CF"
  ,"3EC1479C5844E71895349B233E12D9B771DB3BB5BD1C670F14722A8B98E6A447341F7B4F3E831819532EDC4E62CD3026EC177BB4C6BCBEE0E3EA0CE5DDFBFA1F"
  ,"C1ED0089F2894B6E37EFA5F572EBFAA2E62CC1678378A22EE8D472D730EEDE1F1EA1A124FCA1DCDAB936E06FD8E20211578F776659F8D7BC5D737D3AD828A0C6"
  ,"5EA50F31570B757CF957BB1A5CEBA48C9442D2C598BCCB9CE5A5962D0D6EFD7BE9D5F0919FE510B90C09A731C978A187C3F7220E3EE2E96C1DBC4940D095D42F"
  ,"5EA58F0EEBF502229E24738EABCF24B9A1BBE3EBAB354DA68072460670A2521D8C4DC955B17F322665A0AFB1D30F7785DAF36BBFFF0E0AB63B2C032D34E6DB8E"
  ,"560A70C95BC09CD08B5333276E0C9144A98EF5164A4598205C44EFAA1A48A4A175F72367767AE0520C908A679DBFBC77CDE06D8F668C142C1B3BBF7F801F5346"
  ,"195F54E8CF42BD5D267E9B647091276821503604ABDD1F9EB0D48E5401A4650A37B703E2FB61D3EE6AF4EE278FAC49F04810AFF99229F77A3B73DFBC040B23E6"
  ,"B822C2D04C39C47179958AFBC6D1867A07BDB4D84FF10141F47CC601DF8F0CCDE43D41B407A5287CC5BDF63496003C3E516EA4D74C190826E0B1EC9B16F13FCE"
  ,"39AC9F9F0CBC0850B94423F5881860AB81A836F26491FE2B566C70CB244FA221395B61D94BE54D003801350D9653E6714612A1623B639942209AC339D37D8466"
  ,"045D16726C9B6225104C6B5CC33CEC618C8AD13E6695C30CDB5885A73526C5CA648F512D4FF8708758C75BDE72258127FDABC7449550F9780552E8C7DBE93FD8"
  ,"D95A5D6A455E1F6BB8A1DAC7850A9E5FF41F58C4793E24B020C085B7A01C1FF62B8AB5F57F6756E8F5836A5EF0FAE354256FE59C55E4925967AE0CED8753BA35"
  ,"65B28A17F0F059C96CEBFB00841EE9140C991133184F51B41AC61BB6D0A348AA021F2168FEB358FB1663EB13D96801CB519809165E893505DF44C8565314675B"
  ,"5BB29ABC6BB9A816CA3F40BDEAF30842C512D7D2D0738EB3D90A835EB138D2D19174577138BBD1B3A0078232EFCCFA6FE6835F4F546EDBEC8D4675B610F5CA07"
  ,"4CD05A8FD8C507C9318E8687E0B6F141DE2D0569EECD5DFED0F1FFC83F2A5887D89871898242BFDC4664A9A0A9160F446F5CEB0C27CD75EF34F59F69E74B310F"
  ,"E20A0E7307B54C05A87170DCAC1ACFFD927FE082FD54A365F1D1DB9480E09398793F42844C7DD7E33C2B31278963145ECB8C74A55D852360FCE573F993120752"
  ,"F758338BD35DA231C0C062571AA4DF5D634D79AC681EF52516972C465F19F5D52D49E1CD0155F623FCF111CED256D5220E5E7165A9F260272BC4D63833E118B7"
  ,"6725313580EFF7E5E4B6CC8D2DABD4D31A9C435880F3EEB60B5EE7F92169BE76BE08B04BFD5B8F8419F8AD4703D7883354789A372F2F17F37226B4C36D1A7A93"
  ,"FC02E0A4C70A0A504B5B69998EF458FDBDFB160DB6E4890976BFE79F256244DFA5B1B0197FF5ED156BE6481F7EEE904787877650223C570719FAB31A0490611D"
  ,"F6A07238221EE54CDCD3D8D4D93805EA48F4C6495AC59A7C0BA59CD90AA03D526F431363431250505AF50940CFF28404B466A6B649E2A31BC6F455CEE3E41FB8"
  ,"EC8DD257C5ED717D7B7B85FDFD56C69110379093333905E9ADD16290D13EDA793EF28330D29D74F8A7086C2C66BAEA39BF230B3782B924262F3E95C6B121A784"
  ,"6C7339821745C05A8FECC525D21C6E18ADCA6BC7514786B2D3D9EEA7A0C8677A32E692404E4BE062F84DABE6E4886A397298BC9D0ADDE4135043EAB813E8C969"
  ,"E5B8C64C33317B3DEB31ACCBECAA19C0B46DC8EAC08E204B2F6B49D7656C1E80C94FFEF8CA41265C80EA9F6FE499FD37B7CB11E7537B46877EF07584183D7DFE"
  ,"838C0854195C334B70B74C113C23F5BBCF4563D122AA2BEB10E53801257CF6C776D45483BBC36065BE386E8021D9E5D7B036517B00175FCB33B7EDF7B28264E9"
  ,"D851E8EDA3584C74DB34030A7E2512FCA924F4F7F3D48F085890F30AE68B86E99176AEB6769178524A7A7C43AA62B51ECA618A36493C9DA51661CEBF5034AB86"
  ,"6EBFA70B5A2E531145BF77BF281E9486FAA53EA2B5B89A1F0A564279CA1840CB39FF6F8DECB1FB0A2D5D4FEEC4F890B0A211159CAD67E795CF1A3F29D87593B9"
  ,"353D6B789D680F073C10C557828FAFE15F0AD36C9BD4CDFC32A900040C162248759913CA69408F427CF12B564453A3397162F008A17D9FC061DEC529882BA30A"
  ,"FD057AF082A5AC473BC4CE0C0FCE840291DA51388B0C023A0F99D5922418AD2A1B71ECAFBE10571681C660C8302174F89D20961F7D785B3AC4D0C4B6C35D5500"
  ,"CFD40D1C9ED1E261B40A14DE273F550B9FD0DB152E0DA804EA9C354E8321A525D76373891C0695CF28421743AC80AD68A9E36BFD32B9820B58C1A83D9AA7B5AD"
  ,"249304AE567A50C8F5E70E6FD05A39D2169DE54924141B7D34D41D0C236FF9DAC57E2640B0F6E8AF4080514B6CAE9AEFCCA142439CD7549DCD67F5BA06919035"
  ,"9A70C98D18C3AF1895A459ACFAAD3FD3E1169A80162B4F6A8A6EE269F38B64326C739D2160BFD85A485C74AF7E542F08C5C6AE04B318F7EB9B82925B8A1B4310"
  ,"855EF853BFA18F8CF0D453D5E7231D5A8BBEAC2FF784A7BFC08CDEF0E795724A8078557970A3B4439DDCBEA70F5A8401D04C9BB414F01DFB96519041F1F28639"
  ,"01490FDADD50EC5F8C3DC2D988D4DA81F24F29AA4FAA73069C2393DDF026B750629CAF83F0C3BEC3664927AEB666C5C0AE10F9D2B1DBEFCBC27896F66C4AB481"
  ,"6ACEA46D56F3CDD153487526B2A7ED756F404C2754145E8378B5248A3202DF894689D0823C0F95CCC9A9B97EC2353C142580EE442E19E0CD665355FD892462BF"
  ,"B1EDED17477B88072F2E68BFDA3FD8A3F1002D08C68F268E3B145394187F302C21B47EA5376A6DC13BEE0DD7600920BE8205CB34FD3F0E559B01417E47C1BFE2"
  ,"7384929231A1F162CEE8C440BB46CA740E2A20986C487D0DAA4B8D5A7D9541B5759E6111E8CD9ADBB8B206800DE56BBF28DD33CB309E9AAA33BED44A2C632820"
  ,"A5DD77404ABD0AD7A81D94712BB9C88B1ED5681580930617D7F3AD6425FB2077D9ECC7467E671AAE446547A399091E308548D10B5B1C0D071C8DD95B43199FDB"
  ,"07682D642418B86D290E6A30B81F1EA49DBC1A15B26F1498E6418F616A26494FC3EB4AA92A497A30353359EF91B06604331BC5205FA327E68952CF841BBCC39B"
  ,"42892E339D7524E4C939BCAF4A102341B8FDF7E18A50A98D39B6BAF05A23324F06C93B231AB6285E99183415FB9BE3A8EE2B9C554D80C919643BB571914AD632"
  ,"DE346C4E291D5E49B309EA857961AA7E7078584C974DA70D3AFB9E3AFD7154A1B1A6F31939AA396571E1EF20B95DC31224375FC044C3014B5709D290842C26A5"
  ,"23090AAC3D222AAB1D900292D69E49E01ABE2D239F238DB6BE75BBB95061C3CC8BF424486100CD43ECDD1D62D179D48576E511886126D52BD60542484BD81401"
  ,"FC134157A20C50BC901646D5BEB598CE9D9670FB71403B89B1A2DC42D13928744B2F4E708FA37D484CD7330ECD48B3B672355E6DA3ED1AE7569037927453A701"
  ,"3B0BFD204EF4D549267863543A5F7C9795BB8E673711B4F2454A7C522433C86D8FB28C882674AE82C4F0C86FAA7B30025396AA81AF12B450E890BAA9AC03E779"
  ,"D3E5F7F571496F808B9D2604086C292FC949751A3A63C85036373A7A97DAFDE9A800962EA2BD54B5497D2A8451C55F907616504F471F123D94A1091153980B7E"
  ,"E990D6C330DCAD0881FB98B1C085B4BE7F80FFF6A44DE88DDEF308BCDF6CBFF8F86FFB0CBFBE7D7F33EED6E530AD001B75445805CA3247EA7DE7D3E7D0E3C9F9"
  ,"489D2D2DFD178DE6D8E8FE5EDEA8554323F131794A964DFC04BCE61A6CDC9FC4F8EA80370C09DCC1D29B7D9229BDD861B8DFA879C4C3B0B7741C2F76FE63C93E"
  ,"88FB5BEC82D5B129DE166BBEA81D17926F7045E05E8E8967840AB06F317D9D4D20B55507A82EEB320A2BCDA24FDF68B533E8B62DF8C8782356F30FA0C23D3E6F"
  ,"CD046C9C98B1FB1B7035AE102081881CDC70CCADA649B71012CE819E80A7DB3C52A93B86EA6A9CC3FBADB53F025BBC836DBDBC8E2AF153EA8B308528E5DE9B24"
  ,"230D6675F66CCB893ECAF328A20A558B2C81DFB73361E1455F2D173F8608A6458D03AD94E521FC5175025E8AE29990C0043EF207BDDD3875DD3FB6AD6432A5E6"
  ,"1A364E8B2D7CC4E9AC1D421F4E4F01B6FB96581C68A68EFE488E4902B6669EBBC463BE84783F59008ECF5166B31AD3BDBE24711CFBC7EF8210A08B7FD5F62A99"
  ,"6647BF60F6626D5632A81E5E01A11FE5CB971B2DE55669900E9AAF2B348E9FE46F934C0ED09E88E08618034DFEF39EE3FA3E625A90273974A9A0D5529257C77E"
  ,"0D0634D1AD65251892ABF35400DA4E1FA0A5515F3400B4F38C1ECCF2E602B15E1C300AF95318D12FE7DB50663AA2F543CD11BFC2E4F49BE4173A5B31515A3248"
  ,"81DA9E64C2E43AAFD966C991CB0255C2C3FA45F6F2690E3083ECF784BD61246B066BFE30765B0A8F888723BB9B6FFAB4715F76F7FE16A46E11D11B65A925D2F8"
  ,"D4C9F849A7D3CB7ED28BD2E686E70FD6B7BB6481DFE83915F11B6EEC5A7098895B0577E9BEC3864E4942AA2A1A44122A5C8177DE0F543EA5DE5CA8ED00290EEA"
  ,"BDF9DABB79C1EFF6000964B67852E01ED1E6F79C0442017C4C4DCDC7287D9FF46AFB202B61EC2813EB87580B632FB8F0FC1B7691C7F49477BCE82DF763F17A64"
  ,"AE79A556EE2E00090F08844AE01D691CC80C1B0C332AA75390F6EE39F1959C126CF30886621346FDFA1ECD2D64300C7DFAD882D9301CAEC3601D5F5AB7275CDF"
  ,"AA862F08E8B8FE1CD061DF48C94A397B4CE5C5AF8F1AD1D1B114FF0FC3511CDEAAAF65BCB1D3EFB0A541B33671B76A14CA1778D85F967ECFFE20A8046BEE34D4"
  ,"F97B23B219ADADF3EF8C78A7C569B476190076F50865510972BB2B4B60BDDA1902A529750FAC5649275A5F721796F7D6761932F6B45F53E67BDCA883086BB01E"
  ,"A48C1B4C1A4620CC066C31D30AEDCDEDF55F1ED4C69D64C8085861F29FF756101B542ABAB08DFA608479DA9547843490F36764855A15CEF4D469F3F0A27E5B1F"
  ,"1AF445F9FE2AACA921B16D4ABD3A7E2875AC7C3F3AB52FC75650B86361EF9FE25239C6081F8B65F9653698567B3BBEEA2D345E64764773E2F9BF7FDCBF8FFB09"
  ,"288D851841AA65D5B5D5B967163EE24271A0C34F2D1475186DEA879CC282B3D6C32295A0733D32D1A09D814807A6FD49150B130B91682ECB3535D434CA231505"
  ,"214EED33824CEC8F4B92FA8023F2355E29998AEE59A507880C74D500E8639E7FC326A1EA2F571AF80C0D05BB5C2CA2B766FCE8325AC7DFDD74A0304AA999FB66"
  ,"744DC30EDEAE6C618BA43AFDA3BFAC1EB7CC7E6D436B740D544C6CF4D99D8FEAF98639600583904CDFDD05D1D5FC658BAC5544FF618B316CE5C3DBF46DEBDF46"
  ,"51E632603C2D6EF2AC54A6FD863ABEAA0F94221BF64920924BE86B20BE66C0813980AE513A34B5E1DE85444990C82338242AAF81DB393AA48DD3BD8686B4AA50"
  ,"F9740046FCF1FB9A26203213DD88F6C4643F13812AAE91C3772F7F5A35A57CC3643A0D02D98629A27CC5093971AE3C4488F69391AFF5A8213E6B2BC0F2DFAE39"
  ,"B0D796F0C674EB5546EB20FE4CED256E606FB35AD213382860D20D56168F46B45378AB3B2E29E7C98EBC4656EC53D29BBABCD7BC0F22D959E8946A77A3E251D3"
  ,"4B96BD9D3E43847E0B2658209CCCAE83BDCF0607A671D893EBD57F7134E3C3F0CBB2A32BF3E2878ED3BA06DFA4799F7F08B4DA721084DB8B4A39A2D689D8E81F"
  ,"50D3D380913EC7AD5CF33412EB7FFC7B4A8B8A84A2BFFB523C96BB4ECC6A4A943E2BC86A070204A45A9BEF4DB113190254D99757B99E966CEB99D32A74982FD7"
  ,"46092BC8FBD57B1C54EE8AE0F581E06451D6AC33CF259D9F9A5709AE676AACBEEE14473827125570F3E5C99B902DA3732BDC3CBB74696626D6BA0B4C83F959C1"
  ,"F1ED6C94CB74882B0B05EBB28957EAE08CD8CA12F7B71DB61702656E5A9910335D99F42FE9DB93DE844AD3B0C259E09C67D9D7D51DE63C500EA0D612BD67BA04"
  ,"D9B817B48DF542FBC7C82E12C3AFEE6F424370B992B85D186072DA711A1EC063A070B58FA7E73EC3F31B85B979B17175E6E2A19810DAD5D2CE9BFE30D482AC4E"
  ,"F0639C296E5FFCEF5380D345B236434397A1E770BD2C8E0E098E7FBA56C102E1196843A416AE5C31C8E24DBD6D808FB3482EE968DE042DB755152AC73790E6C2"
  ,"BCD2D45A2D3A2A95A2CADB822587F7B7CB06E4624048B521D6C98F77A9F419A69AD083051FBCC7125397B9AB950AFAD86DC0741024902EE8354648E74D1876D3"
  ,"1DEA591AD7CB103B7CB1FCF058DF56CB08DF98190FBC333056881AD419A290D770563D23790DFEB9190D7EBB5B68189137E59C0137E501923AF1A7989A2D9EDF"
  ,"07D97CA54A92C1056C902418DF04FF9E67FE2C06C13CA661468D9379324D8729289B2BD1E81ADE063881C73726AF35036E1EB7B70964A3BDD5201FDBD4EE919D"
  ,"7CBDEE1E35146A0864EA8682F5EC7EE9DEBC1B92E8219D2FBFE8CCEEA62387D808E35D9F2F65B50706BBCC1188DD0E09FA4C399500E92DCDEEC4010837506EDF"
  ,"3A6295E4F826329BF88EB125EF189A078461CCDC39F718157A6B76D0A5197F138834E7DFF91B58ADAA64B83DE4F8012C55673F210F51815B8728B6A5FD425E98"
  ,"11839A2F32F7B29E32D0A158832336CB1C3EB4EF6A0827249AB2206660B024862076A1DADA7F4DF45007640304798AD74DDBAC9836C10A18E8D08B70AA7F5787"
  ,"2D8C31E88683F2B965B11256DCF6A73690880AC88DF115D758EE67CE304B57BDA2C0E06DAC0AF8F169623F72392D7A78A7EC33572CEC729FE20E5D7652B382DF"
  ,"9D3671E3D34D5160EBB501CA1E295434CE092D39319A3E98C1B1DEBB699A043AB5D131662CB8141D2EFB4292F637B65CDC7B6849A8679073B887645FE39FAEB5"
  ,"DF86AB502D02F1F913E40703885ECA030C520BF71EEA8B0D2A854BCA89BBFA083A11C2887DA063DE41795F7334993C4DD62F8C287CE74AAB4812ACC3AA7B7B05"
  ,"2D30B61125A9060FAEE0C43B5CC7E3513D3180F7FEE6EFBA7275E09A3BAC1794E66D49525F0E40AE6B7D5803CD7A3CE31F76A742E1E66C6CC81EB25469DD8A4A"
  ,"3A0D0DD6F5965E6773B25700A3EE4BFB73FBE908484F7B76DEE7008177EE9C5DDAC01694095D6914F10544682BB1D9E9497F6EE8B5060A7AFBB8CB993E416D29"
  ,"F880D6FAB44FB7B1A0587324AE4DD1026A2FAA793514B5E073A3783560D46CEEF79E55FBBB47F8EDC4391B52DB43B6726AA021DD5303BA5FA347FC0C11D388B5"
  ,"DF9912C8D4A9498492CC68B21ED05A5AF4091C97A10FB46AFDB7BCCADD945C0B40C99E0F657927BB922B7FB6C53D9C6832A5B45D7961168AE78335FCB7DA49E1"
  ,"A5056CAFA3A110BC729BC7D889D05A54EE3414833029BB0B8558FDCAB4635FAB48068F7F0F8DC54C8528BB9A2ADD8F90A4FD0F8A95F340876B873A5C072BC32D"
  ,"D548F0C70D81A4D376380DF13B553C8E2CFA6555D9D6023F95E331F29B972F6879B1306FAE6AF53CCD8042190110F59305B704B14C83EE4AAA79F9611BBCF02E"
  ,"DD7E4B456B50068A87D4DDAEDB9CF33FE55B3973DA3DFD7A2B07A1DB58205529E586D89A8290E2C714B6D9E6C2D90A81"
  ]

-- | ML-DSA sign/verify: wycheproof KATs (group-0 tc1 valid pure
-- per level, ML-DSA-44 tc3 valid under its "Context"),
-- roundtrips over all three levels x hedged/deterministic x
-- pure/context (widths 2420/3309/4627), deterministic
-- reproducibility, hedged randomization, empty messages, the
-- flat-expanded import form executing end to end, and typed
-- refusals (garbage keys, cross-level execution, external-mu
-- mode, overlong contexts).
caseMldsa :: IO ()
caseMldsa = withBackend $ \env -> do
  let tamper bs = BS.init bs <> BS.singleton (BS.last bs + 1)
  -- Wycheproof KATs: tc1 valid pure per level; tampered,
  -- truncated, and overlong sigs mismatch.
  expectOk "wycheproof 44 tc1" =<<
    verify env mldsa44 (KeyDer mldsaWyPub44) mldsaWyMsg mldsaWySig44
  expectOk "wycheproof 65 tc1" =<<
    verify env mldsa65 (KeyDer mldsaWyPub65) mldsaWyMsg mldsaWySig65
  expectOk "wycheproof 87 tc1" =<<
    verify env mldsa87 (KeyDer mldsaWyPub87) mldsaWyMsg mldsaWySig87
  expectAuthFailed "wycheproof 44 tampered" =<<
    verify env mldsa44 (KeyDer mldsaWyPub44) mldsaWyMsg (tamper mldsaWySig44)
  expectAuthFailed "wycheproof 44 truncated" =<<
    verify env mldsa44 (KeyDer mldsaWyPub44) mldsaWyMsg (BS.init mldsaWySig44)
  expectAuthFailed "wycheproof 44 overlong" =<<
    verify env mldsa44 (KeyDer mldsaWyPub44) mldsaWyMsg (mldsaWySig44 <> "\x00")
  -- Wycheproof tc3: the context signature verifies under its
  -- context and mismatches under pure (domain separation).
  let ctx44 = SigMLDSA ML_DSA_44 False mldsaWyCtx True
  expectOk "wycheproof 44 tc3 context" =<<
    verify env ctx44 (KeyDer mldsaWyPub44) mldsaWyMsg mldsaWySig44Ctx
  expectAuthFailed "wycheproof 44 tc3 under pure" =<<
    verify env mldsa44 (KeyDer mldsaWyPub44) mldsaWyMsg mldsaWySig44Ctx
  expectAuthFailed "wycheproof 44 tc1 under context" =<<
    verify env ctx44 (KeyDer mldsaWyPub44) mldsaWyMsg mldsaWySig44
  -- Overlong contexts (wycheproof tc5 shape) refuse
  -- unsupported at the backend guard, never execute.
  let longCtx = SigMLDSA ML_DSA_44 False (BS.replicate 256 0x41) True
  priv44 <- KeyDer <$> loadMldsaFixture "mldsa44-priv.der"
  expectUnsupported "overlong context sign refused" =<<
    sign env longCtx priv44 mldsaWyMsg
  expectUnsupported "overlong context verify refused" =<<
    verify env longCtx (KeyDer mldsaWyPub44) mldsaWyMsg mldsaWySig44
  -- External-mu mode refuses unsupported.
  expectUnsupported "external-mu refused" =<<
    sign env (SigMLDSA ML_DSA_44 True "" True) priv44 mldsaWyMsg
  -- Garbage keys refuse typed.
  expectBadKey "garbage sign refused" =<<
    sign env mldsa44 (KeyDer "bogus") mldsaWyMsg
  expectBadKey "garbage verify refused" =<<
    verify env mldsa44 (KeyDer "bogus") mldsaWyMsg mldsaWySig44
  -- Cross-level execution refuses typed (the label is a hint;
  -- the shim checks the key's actual keymgmt type name).
  expectBadKey "65 key under 44 refused" =<< do
    priv65 <- KeyDer <$> loadMldsaFixture "mldsa65-priv.der"
    sign env mldsa44 priv65 mldsaWyMsg
  -- Roundtrips per level with fixture keys.
  mapM_ (roundtrip env tamper)
    [ (ML_DSA_44, "44", 2420)
    , (ML_DSA_65, "65", 3309)
    , (ML_DSA_87, "87", 4627)
    ]
  where
    mldsa44 = SigMLDSA ML_DSA_44 False "" True
    mldsa65 = SigMLDSA ML_DSA_65 False "" True
    mldsa87 = SigMLDSA ML_DSA_87 False "" True
    roundtrip env tamper (alg, tag, width) = do
      let label = show alg
          hedged = SigMLDSA alg False "" True
          det = SigMLDSA alg False "" False
          ctx = SigMLDSA alg False "CTX" True
      privDer <- loadMldsaFixture ("mldsa" ++ tag ++ "-priv.der")
      pubDer <- loadMldsaFixture ("mldsa" ++ tag ++ "-pub.der")
      let priv = KeyDer privDer
          pub = KeyDer pubDer
      -- Hedged roundtrip; hedged signs randomize.
      sigH <- expectOk ("sign hedged " ++ label) =<< sign env hedged priv mldsaWyMsg
      assertEqual ("hedged width " ++ label) width (BS.length sigH)
      expectOk ("verify hedged " ++ label) =<< verify env hedged pub mldsaWyMsg sigH
      sigH2 <- expectOk ("resign hedged " ++ label) =<< sign env hedged priv mldsaWyMsg
      assertBool ("hedged randomizes " ++ label) (sigH /= sigH2)
      expectAuthFailed ("tampered " ++ label) =<< verify env hedged pub mldsaWyMsg (tamper sigH)
      -- Deterministic roundtrip; deterministic signs reproduce.
      sigD <- expectOk ("sign det " ++ label) =<< sign env det priv mldsaWyMsg
      assertEqual ("det width " ++ label) width (BS.length sigD)
      expectOk ("verify det " ++ label) =<< verify env det pub mldsaWyMsg sigD
      sigD2 <- expectOk ("resign det " ++ label) =<< sign env det priv mldsaWyMsg
      assertEqual ("det reproduces " ++ label) sigD sigD2
      -- Context roundtrip; empty messages serve.
      sigC <- expectOk ("sign ctx " ++ label) =<< sign env ctx priv mldsaWyMsg
      expectOk ("verify ctx " ++ label) =<< verify env ctx pub mldsaWyMsg sigC
      expectAuthFailed ("ctx sig under pure " ++ label) =<<
        verify env hedged pub mldsaWyMsg sigC
      sigE <- expectOk ("sign empty " ++ label) =<< sign env hedged priv BS.empty
      expectOk ("verify empty " ++ label) =<< verify env hedged pub BS.empty sigE
      -- Flat-expanded import form executes: reassemble the
      -- provider PKCS#8's expanded key as flat PKCS#8 and sign.
      case mldsaPkcs8Fields privDer of
        Just (oid, _seed, expanded) -> do
          let flat = KeyDer (mldsaPrivateDer oid expanded)
          sigF <- expectOk ("sign flat " ++ label) =<< sign env hedged flat mldsaWyMsg
          expectOk ("verify flat " ++ label) =<< verify env hedged pub mldsaWyMsg sigF
        Nothing -> assertFailure ("fixture priv does not parse: " ++ label)

-- | ML-DSA generation: keygen mints usable pairs on all three
-- levels (provider PKCS#8 halves with a 32-byte seed, SPKI
-- halves, agreeing OIDs), and unknown levels refuse typed.
caseRealMldsaKeygen :: IO ()
caseRealMldsaKeygen = withBackend $ \env -> do
  mapM_ (genPair env)
    [ (ML_DSA_44, 2420), (ML_DSA_65, 3309), (ML_DSA_87, 4627) ]
  expectUnsupported "unknown level refused" =<<
    generateKey env (GenMLDSA SLH_DSA_SHA2_128s)
  where
    genPair env (alg, width) = do
      let label = show alg
          spec = SigMLDSA alg False "" True
      (privM, mPubM) <- expectOk ("keygen " ++ label) =<< generateKey env (GenMLDSA alg)
      (privDer, pubDer) <- case (privM, mPubM) of
        (KeyDer priv, Just (KeyDer pub)) -> pure (priv, pub)
        other -> assertFailure ("keygen halves are not DER: " ++ show other)
      case (mldsaSpkiFields pubDer, mldsaPkcs8Fields privDer) of
        (Just (pubOid, _), Just (privOid, seed, _))
          | pubOid == privOid -> assertEqual ("seed width " ++ label) 32 (BS.length seed)
        _ -> assertFailure ("keygen halves disagree or do not parse: " ++ label)
      sig <- expectOk ("genkey sign " ++ label) =<< sign env spec privM mldsaWyMsg
      assertEqual ("genkey width " ++ label) width (BS.length sig)
      case mPubM of
        Just pubM -> expectOk ("genkey verify " ++ label) =<<
          verify env spec pubM mldsaWyMsg sig
        Nothing -> assertFailure ("keygen missing public half: " ++ label)

-- | SLH-DSA sign/verify: ACVP sigVer KATs (tcId 266 SHA2-128s
-- under its 255-byte context, tcId 343 SHAKE-128s pure),
-- roundtrips over all twelve sets x hedged/deterministic x
-- pure/context (widths 7856/17088/16224/35664/29792/49856),
-- deterministic reproducibility, hedged randomization, empty
-- messages, and typed refusals (garbage keys, cross-set
-- execution, overlong contexts).
caseSlhdsa :: IO ()
caseSlhdsa = withBackend $ \env -> do
  let tamper bs = BS.init bs <> BS.singleton (BS.last bs + 1)
  -- ACVP KATs: tcId 266 verifies under its 255-byte context
  -- and mismatches under pure; tampered, truncated, and
  -- overlong sigs mismatch.
  let ctx266 = SigSLHDSA SLH_DSA_SHA2_128s slhAcvpCtx266 True
      pure128s = SigSLHDSA SLH_DSA_SHA2_128s "" True
  expectOk "acvp 266 context" =<<
    verify env ctx266 (KeyDer slhAcvpPub266) slhAcvpMsg266 slhAcvpSig266
  expectAuthFailed "acvp 266 tampered" =<<
    verify env ctx266 (KeyDer slhAcvpPub266) slhAcvpMsg266 (tamper slhAcvpSig266)
  expectAuthFailed "acvp 266 truncated" =<<
    verify env ctx266 (KeyDer slhAcvpPub266) slhAcvpMsg266 (BS.init slhAcvpSig266)
  expectAuthFailed "acvp 266 overlong" =<<
    verify env ctx266 (KeyDer slhAcvpPub266) slhAcvpMsg266 (slhAcvpSig266 <> "\x00")
  expectAuthFailed "acvp 266 under pure" =<<
    verify env pure128s (KeyDer slhAcvpPub266) slhAcvpMsg266 slhAcvpSig266
  -- ACVP tcId 343: pure SHAKE-128s verifies, tampering
  -- mismatches.
  let pureShake128s = SigSLHDSA SLH_DSA_SHAKE_128s "" True
  expectOk "acvp 343 pure" =<<
    verify env pureShake128s (KeyDer slhAcvpPub343) slhAcvpMsg343 slhAcvpSig343
  expectAuthFailed "acvp 343 tampered" =<<
    verify env pureShake128s (KeyDer slhAcvpPub343) slhAcvpMsg343 (tamper slhAcvpSig343)
  -- Overlong contexts refuse unsupported at the backend
  -- guard, never execute.
  let longCtx = SigSLHDSA SLH_DSA_SHA2_128s (BS.replicate 256 0x41) True
  priv128s <- KeyDer <$> loadSlhdsaFixture "slhdsa-sha2-128s-priv.der"
  expectUnsupported "overlong context sign refused" =<<
    sign env longCtx priv128s slhAcvpMsg266
  expectUnsupported "overlong context verify refused" =<<
    verify env longCtx (KeyDer slhAcvpPub266) slhAcvpMsg266 slhAcvpSig266
  -- Garbage keys refuse typed.
  expectBadKey "garbage sign refused" =<<
    sign env pure128s (KeyDer "bogus") slhAcvpMsg266
  expectBadKey "garbage verify refused" =<<
    verify env pure128s (KeyDer "bogus") slhAcvpMsg266 slhAcvpSig266
  -- Cross-set execution refuses typed (the label is a hint;
  -- the shim checks the key's actual keymgmt type name).
  expectBadKey "shake key under sha2 refused" =<< do
    privShake <- KeyDer <$> loadSlhdsaFixture "slhdsa-shake-128s-priv.der"
    sign env pure128s privShake slhAcvpMsg266
  -- Roundtrips per set with fixture keys.
  mapM_ (roundtrip env tamper)
    [ (SLH_DSA_SHA2_128s, "sha2-128s", 7856)
    , (SLH_DSA_SHA2_128f, "sha2-128f", 17088)
    , (SLH_DSA_SHA2_192s, "sha2-192s", 16224)
    , (SLH_DSA_SHA2_192f, "sha2-192f", 35664)
    , (SLH_DSA_SHA2_256s, "sha2-256s", 29792)
    , (SLH_DSA_SHA2_256f, "sha2-256f", 49856)
    , (SLH_DSA_SHAKE_128s, "shake-128s", 7856)
    , (SLH_DSA_SHAKE_128f, "shake-128f", 17088)
    , (SLH_DSA_SHAKE_192s, "shake-192s", 16224)
    , (SLH_DSA_SHAKE_192f, "shake-192f", 35664)
    , (SLH_DSA_SHAKE_256s, "shake-256s", 29792)
    , (SLH_DSA_SHAKE_256f, "shake-256f", 49856)
    ]
  where
    roundtrip env tamper (alg, tag, width) = do
      let label = show alg
          hedged = SigSLHDSA alg "" True
          det = SigSLHDSA alg "" False
          ctx = SigSLHDSA alg "CTX" True
      privDer <- loadSlhdsaFixture ("slhdsa-" ++ tag ++ "-priv.der")
      pubDer <- loadSlhdsaFixture ("slhdsa-" ++ tag ++ "-pub.der")
      let priv = KeyDer privDer
          pub = KeyDer pubDer
      -- Hedged roundtrip; hedged signs randomize.
      sigH <- expectOk ("sign hedged " ++ label) =<< sign env hedged priv slhAcvpMsg266
      assertEqual ("hedged width " ++ label) width (BS.length sigH)
      expectOk ("verify hedged " ++ label) =<< verify env hedged pub slhAcvpMsg266 sigH
      sigH2 <- expectOk ("resign hedged " ++ label) =<< sign env hedged priv slhAcvpMsg266
      assertBool ("hedged randomizes " ++ label) (sigH /= sigH2)
      expectAuthFailed ("tampered " ++ label) =<< verify env hedged pub slhAcvpMsg266 (tamper sigH)
      -- Deterministic roundtrip; deterministic signs reproduce.
      sigD <- expectOk ("sign det " ++ label) =<< sign env det priv slhAcvpMsg266
      assertEqual ("det width " ++ label) width (BS.length sigD)
      expectOk ("verify det " ++ label) =<< verify env det pub slhAcvpMsg266 sigD
      sigD2 <- expectOk ("resign det " ++ label) =<< sign env det priv slhAcvpMsg266
      assertEqual ("det reproduces " ++ label) sigD sigD2
      -- Context roundtrip; empty messages serve.
      sigC <- expectOk ("sign ctx " ++ label) =<< sign env ctx priv slhAcvpMsg266
      expectOk ("verify ctx " ++ label) =<< verify env ctx pub slhAcvpMsg266 sigC
      expectAuthFailed ("ctx sig under pure " ++ label) =<<
        verify env hedged pub slhAcvpMsg266 sigC
      sigE <- expectOk ("sign empty " ++ label) =<< sign env hedged priv BS.empty
      expectOk ("verify empty " ++ label) =<< verify env hedged pub BS.empty sigE

-- | SLH-DSA generation: keygen mints usable pairs on all twelve
-- sets (provider PKCS#8 halves with a 4n-byte secret, SPKI
-- halves, agreeing OIDs), and unknown sets refuse typed.
caseRealSlhdsaKeygen :: IO ()
caseRealSlhdsaKeygen = withBackend $ \env -> do
  mapM_ (genPair env)
    [ (SLH_DSA_SHA2_128s, 64, 7856), (SLH_DSA_SHA2_128f, 64, 17088)
    , (SLH_DSA_SHA2_192s, 96, 16224), (SLH_DSA_SHA2_192f, 96, 35664)
    , (SLH_DSA_SHA2_256s, 128, 29792), (SLH_DSA_SHA2_256f, 128, 49856)
    , (SLH_DSA_SHAKE_128s, 64, 7856), (SLH_DSA_SHAKE_128f, 64, 17088)
    , (SLH_DSA_SHAKE_192s, 96, 16224), (SLH_DSA_SHAKE_192f, 96, 35664)
    , (SLH_DSA_SHAKE_256s, 128, 29792), (SLH_DSA_SHAKE_256f, 128, 49856)
    ]
  expectUnsupported "unknown set refused" =<<
    generateKey env (GenSLHDSA ML_DSA_44)
  where
    genPair env (alg, secW, width) = do
      let label = show alg
          spec = SigSLHDSA alg "" True
      (privM, mPubM) <- expectOk ("keygen " ++ label) =<< generateKey env (GenSLHDSA alg)
      (privDer, pubDer) <- case (privM, mPubM) of
        (KeyDer priv, Just (KeyDer pub)) -> pure (priv, pub)
        other -> assertFailure ("keygen halves are not DER: " ++ show other)
      case (slhdsaSpkiFields pubDer, slhdsaPkcs8Fields privDer) of
        (Just (pubOid, _), Just (privOid, secret))
          | pubOid == privOid -> assertEqual ("secret width " ++ label) secW (BS.length secret)
        _ -> assertFailure ("keygen halves disagree or do not parse: " ++ label)
      sig <- expectOk ("genkey sign " ++ label) =<< sign env spec privM slhAcvpMsg266
      assertEqual ("genkey width " ++ label) width (BS.length sig)
      case mPubM of
        Just pubM -> expectOk ("genkey verify " ++ label) =<<
          verify env spec pubM slhAcvpMsg266 sig
        Nothing -> assertFailure ("keygen missing public half: " ++ label)

-- | ML-KEM fixtures: wycheproof decaps tc1 (valid) per set
-- (seed, ek, c, K verbatim from mlkem_*_test.json) with the dk
-- derived by seeded keygen against the pinned provider (the
-- files carry the seed, not the dk; derivation replays byte-
-- exact under the "seed" keygen param, proven by probe).
mlkemWySeed512 :: ByteString
mlkemWySeed512 = hex $ concat
  ["a3896e30892230a6c1dff667f8caee759ff84a08e3462ae484fcbca9971d7959cdc6c5ec65f10a5a24b5145aac863232ee3b2229ca3a6c4b9c8a2dafc315d9d4"
  ]

mlkemWyEk512 :: ByteString
mlkemWyEk512 = hex $ concat
  ["871b108fd980108768612345f2fc7317216f55576f914c3ede67878ea89046d636572ca78fd67a4efc9b68e462853b2ae8dab001b6059c390916fccf45bba50b"
  ,"85b7e12504ef931c52030a4efb31ce978866ea0bece660b16700d9ca4fb8eca335cb2395478e6bf845eba6161765c479e0a3c0b64773b0a8f9191789e0b939cb"
  ,"bce7f80317e569a96c7c3ba2596aabca4298c2383ab539a05232f990af03b936d18cb6378363523ccdb75ef237ccf9774776ba0e219c97726c6f82b3168e4908"
  ,"1d7b358f6c2dda287796a99775e60de716ae28385b8270451b3a2b8dbb267a8a37266c70718ac30303cad7e5908d0b09897bbfb18c25975bc9f46909df4b3451"
  ,"dbca7a3498eb253bb4246721685b762086b903b6f6a86b2db894cd59567ac9b18a82c5fa67306ef3cd7aa5c82d46aa73111f837c2eadca7b1bf6ba81f769e053"
  ,"0d44b21f5ab161a159014c14ad7292b638b86e548a5c0de9300df1416e619afbb01a77588cd3e1a17546be6af108f8d3ad87429f6dba298d8119a4594310f874"
  ,"def0a9f3f5a20748cde73218e91b428a629e6cb24e611300d9155f6d16c6398b7d2615a0bf486b9ac1c32be69b2212baff1c5ccbb0c247075536f2bc28caa954"
  ,"064bf5f3963060ada289ab5a58628959347356a7ba4c84051a65547a3b56a738eb9acc0d62213cf1291006a502ec7296b42e989905a08393278480290887958c"
  ,"4155a975d37194d25b146344b012318a3aa98060c64946191a871408f6a0917cab9227b956e4dc8081c96b50927944381631237302a0c960a33678a268f2139c"
  ,"a0b5b44203863cba6d2ab37c78b369a4ba5256e173a274567b536cb0d5b6d47b3d8ad738fc022792112a4ca09389b9c1317b2342a5c4a444c73f364685298068"
  ,"42b5297482fb001ceb28b1be8299e612985957bf7ac16cf7e609fe532a33f25690186616762c680b1cb1e986c5f55c37a49bc32219faa8ada839937ac56f7587"
  ,"ac51a12abfc8be413a9b915b4c455ab1e2dba776dc8633083646f7cd95437b129095e75510dff58fa4cc6c3f4531211a3a161418b7da4e6ec8388b0197993898"
  ,"783d963d109590d4ac0092189baabef63fcc3df15b0ab3099078c9580b198e11"
  ]

mlkemWyDk512 :: ByteString
mlkemWyDk512 = hex $ concat
  ["05ec05532c8ce40953543356cc791b6d9ba20638221a5370fdda26780018f10b697ddca386f657c54660f9a84e14658c5e3015cc9c0a8452326779c11955c767"
  ,"581a0b02900220c26af75e53cca04b3667f1b313e3a81a413c6c5c62c0101284a7d4738af090855965ca6690f0841bee40606fd17886a48b3823656ea0751182"
  ,"691a0ad0e286023b0208cc80a2f3780b625651f3b34ce0d8991bb1a0a4f589976a68ed10a9a1d54afe93a62f061c84e25d6d1ccf38243b52cb2fb3ea983a627b"
  ,"9db48acf7546951067a704918f617d1bd27a7797bbb5ea339981b48450b49d63c5a5f84280023507056fcd22a378428cc312556c07189a90cc4dc2c570e2748e"
  ,"c76be374779c68561b4b308c4b19e4145e9ea4abac17afd3586507c2780b227ac24810cea7839510b34ac59882f3a4b116a9bbd3395e301bb3bc5b9bf32341a4"
  ,"642f4622369912ddd174699a09d4689c4212076b5a5ede19ae8108b597c269b65b084b5138a7e1444da7bc1ec24953f31566400d28c34c3992cfb5fb317749b4"
  ,"600c6855153e38558e30d1c4baf241e8b5458831258b80c02038a01d1967a441660618a8fdf3723cf53e6b506532c331eada98958a417a1aa786f44beb628f6f"
  ,"239a3e7bca7db334520445c946463b502fc830aab8aaaee47ba1ce5296329c758d312364f69b0429b4b88955cdc8bba5dc0a98b47a599923ae2795a2d1af92f0"
  ,"278447a6a806c7f4c26e428c3e41c249b61842bdbc497fe61ee3746217e4a18b8b9c97769abbf9958beb396601253dec885e93028428acff030ff56a257f1343"
  ,"a2449453c23421f127f2602d9a1348e7c62775444d1a4c606632a83cfa9b958843163a4115ac9a9e20021e2a7a190aa374f3550a9841958cada5c99fae53144b"
  ,"fccc0f92c1f8e1530cf7985e866f8fc68c72c463bc99356b6991c2bb43ffb532615669cbb927874ab98e580c7f525f47eb1eeb5056cd1ab906c69e338232c34c"
  ,"77e426a7fb65c3799b2b473a58b845c384a873ac595ea2a8caea058212d13185b57ea824be8f7886fe7c0cf1991d01273f33a1a220f548ec86cade844f80b06f"
  ,"871b108fd980108768612345f2fc7317216f55576f914c3ede67878ea89046d636572ca78fd67a4efc9b68e462853b2ae8dab001b6059c390916fccf45bba50b"
  ,"85b7e12504ef931c52030a4efb31ce978866ea0bece660b16700d9ca4fb8eca335cb2395478e6bf845eba6161765c479e0a3c0b64773b0a8f9191789e0b939cb"
  ,"bce7f80317e569a96c7c3ba2596aabca4298c2383ab539a05232f990af03b936d18cb6378363523ccdb75ef237ccf9774776ba0e219c97726c6f82b3168e4908"
  ,"1d7b358f6c2dda287796a99775e60de716ae28385b8270451b3a2b8dbb267a8a37266c70718ac30303cad7e5908d0b09897bbfb18c25975bc9f46909df4b3451"
  ,"dbca7a3498eb253bb4246721685b762086b903b6f6a86b2db894cd59567ac9b18a82c5fa67306ef3cd7aa5c82d46aa73111f837c2eadca7b1bf6ba81f769e053"
  ,"0d44b21f5ab161a159014c14ad7292b638b86e548a5c0de9300df1416e619afbb01a77588cd3e1a17546be6af108f8d3ad87429f6dba298d8119a4594310f874"
  ,"def0a9f3f5a20748cde73218e91b428a629e6cb24e611300d9155f6d16c6398b7d2615a0bf486b9ac1c32be69b2212baff1c5ccbb0c247075536f2bc28caa954"
  ,"064bf5f3963060ada289ab5a58628959347356a7ba4c84051a65547a3b56a738eb9acc0d62213cf1291006a502ec7296b42e989905a08393278480290887958c"
  ,"4155a975d37194d25b146344b012318a3aa98060c64946191a871408f6a0917cab9227b956e4dc8081c96b50927944381631237302a0c960a33678a268f2139c"
  ,"a0b5b44203863cba6d2ab37c78b369a4ba5256e173a274567b536cb0d5b6d47b3d8ad738fc022792112a4ca09389b9c1317b2342a5c4a444c73f364685298068"
  ,"42b5297482fb001ceb28b1be8299e612985957bf7ac16cf7e609fe532a33f25690186616762c680b1cb1e986c5f55c37a49bc32219faa8ada839937ac56f7587"
  ,"ac51a12abfc8be413a9b915b4c455ab1e2dba776dc8633083646f7cd95437b129095e75510dff58fa4cc6c3f4531211a3a161418b7da4e6ec8388b0197993898"
  ,"783d963d109590d4ac0092189baabef63fcc3df15b0ab3099078c9580b198e1143225a95c345d2cc5b9ae9563200d124cba30b8c1bd5cc30118b553011e76364"
  ,"cdc6c5ec65f10a5a24b5145aac863232ee3b2229ca3a6c4b9c8a2dafc315d9d4"
  ]

mlkemWyCt512 :: ByteString
mlkemWyCt512 = hex $ concat
  ["00ec7fcdb617629fead7f43cf59a7d3a0b946b5c5f472407812c15c44249e52974483eb31fb6ce5e15728708ef24f78bb61bb5c8b6ebb4e8a96e5b898e069c49"
  ,"9c44a57efb0907234597e810f4de40d85d6eacd775b83400937ac863cfe5d406469b8d3ca4f6dbe0aced60fbecb32588f1ddaaa08ba5c5b177ab51b548d8ae22"
  ,"18eb2d9b02b31cb4bb6e7754b6a74856316ad3e0394025f750412023a74ab851fc03171cada993c6469fa254b5d384edab1efe8f2efb6eba37c7ba7434bb2433"
  ,"31938849114ad398cf91038fb96c30a712f47e1c7183956838d487016f023bd9900a94c606edaa42bf0e67f2aedd03f5a581e55af29e24af061ba73da64c3869"
  ,"d7598a0c95c3c8330ecb4481cab2c85ccaaa366f99f3bafc980362f4d701a233d0967ded78e4f1874b42cda774b888d31f1671d6567d1636d5b2bcc117e2a256"
  ,"f343541c3e173e900b6d6c71bcd55479d23dee6b54e2fe32303c7955fa5f567894605ed75e65e54858222c0d065ba9231fcd82ab86af63c242d10d1d30b4176e"
  ,"2bb8169fbd7f03cfa044098853382083284ef8cecf05f9d0bd3d9af84f6df551e3d11e9281794d36a619f61e47901ea0dd695782241250f0b5c2a20d76d3afef"
  ,"cb11d015179d6a9a74121c448e315f507cb29add40da4eb05cae27320c4b18a25d7af24ac7b0bdf7382143d4d02db3e7d016f9ff5638e0df7968f785ac8000c7"
  ,"545a1a70d6fd43cc3ba28d82e9eb6ccb391e094ba85a49ad6e9f8fd8faa9954062a5df13c69847bee485bc6624b40b8128fe911231b4ef9b4a22ced4f8140df6"
  ,"5a5b8180665128273fde02955a65921f0d1be139fbe1edf0ac01db1d2a5ffd95d63d33b0a7627cab4bcd37647238c80197d4fa88a7e34d4caa066dba2ae6feff"
  ,"f6a1e804a72d49ed443c29b2db313fdf25d98d0dee992befc4572f8b1eee0db7227b6e202ef69ea8340ae3690fc064d3edfd8d067934db3061767e4857e805e8"
  ,"88294efa7248743fcaa1e01acdaf491de408c58869bc9624c951103c079793be1edfa9442df4dece40eabb99e9b01410fc0108b26a13cd424cd9a9de5bafa1fc"
  ]

mlkemWyK512 :: ByteString
mlkemWyK512 = hex $ concat
  ["cf3bcfeb2679cb43658fcdcd01aa1505bcea1e72a165ccac7bfb66d9dc0c0e90"
  ]

mlkemWySeed768 :: ByteString
mlkemWySeed768 = hex $ concat
  ["cbfc4405d1b2a3a386c94c25e0f2d5f5ee92cb0388ff4d6aa04223086d51c3fd24752da14c9fc3b8ae0d9e4a8b1016b8d8fc69e229c03ea2ef08a4ae0cffc37f"
  ]

mlkemWyEk768 :: ByteString
mlkemWyEk768 = hex $ concat
  ["8b9a7354e8c1c17a9898f96caf99bba1c625ae0983c4d26e60c12f59bc25d756182b17979e713fff129e6c336a2317770380858129cb91a902ea5455ca076c20"
  ,"e4158f393aa2783053d8acf92c3286a10436d72af3e8903ce22f8cbab18b1309aca205aa8a3da45807e5b60e6967a640a713a5b81b0d82bc406934e3c88910cc"
  ,"06f09a68bce991009bb56ae233296218ff5baf1f475390b8b7494a4e083645985437f2495a073222fea058e1672034151a2e14c2cbcb4ad9068c8e7bcb02886c"
  ,"4087c14bd8823ec66393fb2e12326b38e655dcab1c13cb2931358715c8be5153293229cc994a5702b7295a6a4a73249ac5a30a32a6b91dca768c177d8fa59054"
  ,"e548bee40257db6962a83b64ec6de0d3be7b1812c5d99e7a38cf54eaa8413aa0bd02bf374461f29c2b6aea56f7d33e10dbbc75bb1bf6b555213aac33e652443a"
  ,"186a618b6e9a293919693f1673ea159d0ee52c92d53e9a5cbd5f4c44419b5493f0286efcb9b5a2ad56a713c4f61ed431aa987805a90475391ccd4c7a28d884bf"
  ,"1a926b7675b9208897a89a6384c154acca3521c32a994949b2e80b2ff2518c0bbd34184cda443de498a05dfba9ce701bb914179a0188be0bcda6fbc2cd93afb0"
  ,"42481b4a84d821160a1b0ade8bcb97dbaf681547cce0bca674151a261a21aa04fda318c921c38425b775b995cd7b4eb6369f0b211da186594de815fa3b53a680"
  ,"43e1946468a5899b90578ad49397306f71acab67c258fa17a31893b72d22151ce1afee150fe550bffde8a24fe4740dd43f387c7ad20b5cca5997879536c30715"
  ,"74901147727341c1a6fc8043e6454903e88217f0c92b9a4ac54a86e7909390878a35ba18c1e26b13049f41c522bc049d74db6f76caba39f23d8f07abc26a07a1"
  ,"caba71cb5c12fbc20a715450b2228d17b2ba985cfe2496b033b55f300baf992964388a5422298f627ba567730ddb03a195806a5c23a1d315481c52814b0681ea"
  ,"3c804b02c90688c2fbbce9b17d230a42f8b865417c9e93347f5ff624879962747c7eed886acd48a994b22064ca499c69aa4825be60260d12f63102799828b3cc"
  ,"ebaa4340b749605017eb4598ff13a634500a48470de9078a34106267d25a0b144d8cdb1a4d527692153da013c0ab27ae2ca955e7c66238746022d50630892933"
  ,"a05c283a9f4c00c9f984646f75471081722ed3404ce60fed4a06702b8728b62d920b3224206ab0a4694f9c18e3162b529c16af04b87b4a61cd53a757906d67a1"
  ,"39629585d423a3b0986f29c95984e2095ea4608784b0b31c20cbc36cfd60b773389fe5a8c0958211a35b2c45f21f51a08693c19bfc388c2d677a214ccc5a7cb0"
  ,"b67030fd6987503c91b0f2646985a9048489dd882bd4141f5419554eb738fa7333c5c57a4ce5541fd6b8ad454c2dea67ad1c6f848c0a44a1872e40a17d987075"
  ,"d762ba5aaa21d435dd079b989a8ee21a2ce898934a98a02d5b381c302a2d76948fa65de15666f57750d580ae1a541c700692dd0b0a6799b5cdb893413bb89bb6"
  ,"5182f219a4bc3c80b43bb591bcd05ac6e9a366552558ed5c5fbe7b4acfc7b23372094f6a87f26c0c46646c55a888871324fea7536e586a5149b9b707c86ea076"
  ,"486a6822b9bbf59fbfcaedc13284b9813cabdd526e326a6832d3b36efc3102ef"
  ]

mlkemWyDk768 :: ByteString
mlkemWyDk768 = hex $ concat
  ["3f1cc26ba8bf924776f0064faad848b466256f00bbb3c27e44823e3d264b45190c0e966af8e73e8dc51333470dbc986541116a8de357c8a87d6d0216758b00d1"
  ,"c365071c73e7eb668dd22ee180c6703ac6b031a401915ff2e58a5a2c58c06327c64300f04a48229372165c60db2248207c6cb339330242488dbb0c6db0b65b3a"
  ,"2dd821699e6aa453c48bcaa799499c845496accd529599844d4826cdcee14e4e28b3d661b76d851141515badfa351b694bf710a4355433603b0729264f0ad95e"
  ,"354c43b025cd3370ae6cd3a4622c7eb46901b1f8cb0e5c8777eac40fa7768dd37606c664e5acc0f9abae62d1392da30fa0479483f08a103b81c5d9768cac0e95"
  ,"2c47b5a46a26aa70a4e2b7173a5bf2b743085a1736e33b1db9b497c88ed265638a2136691b78a6bccca1f4666d2a768655486af7c3914503a692903df83b7133"
  ,"7432115dedaa3f319a07ea9984760187e7265d367314dc237f29260045cb2d0bb7b4ebb714198b97b6dbade78b53a24391fa3112cae04589b37fc1abb252c810"
  ,"685371a7ec77b877223ae35d12171bded8002419887c2c92d869328f1b7ffd094c6e7990f9b18d17ba872523b70d849175a35f9b4b438452038730cc50c024c9"
  ,"96c815231b7560aa854766f1988a032733aa267dfe4763041b0d96a6320339684a06326de5b6518972e9e526d4c91e5a4b0408435c3dc4559ee0741218a00766"
  ,"611ca7b11f9bcdffa93a2fd1c86a7b556dd45ef5eb3fe63c6173328f56a4429fa98611209c22c3c901452b32990091e302acd62af8a6bab5ba6499c43b9aa11a"
  ,"ddc1a2a6334f1cc03ad57004915a4bea93a641a493c4aa042a1147b42ac9ca09a161a81567bac1ae84bfc4330d9c261ced243e9682410f5ab6b9c2067367aa0b"
  ,"bb39c9b57d3e7cc9ee5c7ac448ce5bd38c901289be874ab7f74a44c06a3f118b0a2bcd5de8426d78452a51b7d8ba4059543c778619bfacbcbb996d743162ca0b"
  ,"ca0e04b6c784217ccccc2634127ba2b623277fb94076e51abefa7cc87696ca258bcbaf716a429c673f646b0ef88a5a1cc59a748e630375617530a1ec1e6c7b35"
  ,"9df7b62992a5eb65c490668829f386da538492c4530b205f33f5cb8233040211b3aa42c5ccdcaf25126d10a5c16af788e93c98432b564f7c4ff975817fb9a812"
  ,"55588a77510df30f88121e94aa1c0de7b8e4540ac79bb3ce1cb48136aee6c2a41d0a7dcba333827814c298ba1aeaa5a19a0d04d43a3584a34f1602b27874886a"
  ,"808a494a00dd9ab411412deb550cd166c3399887966cfca703aff90baceb7386206c35db6f42872be7c5b569648367c24771c48e97ea64db34616f0bb92a9877"
  ,"72a999587a1ca3680b3fb19bfba5cd7e9901967503ff17baea624e02a0055c7bbc2fa545eb421cf2f3a55579a22e924cffe979eb597e58c9bcbd39adaaf3ca94"
  ,"f33a9e3c9d968ca27be5790fd781e90b29db38480816a2957927c3d027f795b014b8281f9625473434890a01414110708a59752a3d5b0ab71ab68b328b685dca"
  ,"64be563a0f262b00c467ec215eb713a977ec95077593cc17c0bbf68c02f4bb1e12483414c7aa4c9ea3c50c67b8442bbc8fdfa84b6483a70d0c95b6f972002860"
  ,"8b9a7354e8c1c17a9898f96caf99bba1c625ae0983c4d26e60c12f59bc25d756182b17979e713fff129e6c336a2317770380858129cb91a902ea5455ca076c20"
  ,"e4158f393aa2783053d8acf92c3286a10436d72af3e8903ce22f8cbab18b1309aca205aa8a3da45807e5b60e6967a640a713a5b81b0d82bc406934e3c88910cc"
  ,"06f09a68bce991009bb56ae233296218ff5baf1f475390b8b7494a4e083645985437f2495a073222fea058e1672034151a2e14c2cbcb4ad9068c8e7bcb02886c"
  ,"4087c14bd8823ec66393fb2e12326b38e655dcab1c13cb2931358715c8be5153293229cc994a5702b7295a6a4a73249ac5a30a32a6b91dca768c177d8fa59054"
  ,"e548bee40257db6962a83b64ec6de0d3be7b1812c5d99e7a38cf54eaa8413aa0bd02bf374461f29c2b6aea56f7d33e10dbbc75bb1bf6b555213aac33e652443a"
  ,"186a618b6e9a293919693f1673ea159d0ee52c92d53e9a5cbd5f4c44419b5493f0286efcb9b5a2ad56a713c4f61ed431aa987805a90475391ccd4c7a28d884bf"
  ,"1a926b7675b9208897a89a6384c154acca3521c32a994949b2e80b2ff2518c0bbd34184cda443de498a05dfba9ce701bb914179a0188be0bcda6fbc2cd93afb0"
  ,"42481b4a84d821160a1b0ade8bcb97dbaf681547cce0bca674151a261a21aa04fda318c921c38425b775b995cd7b4eb6369f0b211da186594de815fa3b53a680"
  ,"43e1946468a5899b90578ad49397306f71acab67c258fa17a31893b72d22151ce1afee150fe550bffde8a24fe4740dd43f387c7ad20b5cca5997879536c30715"
  ,"74901147727341c1a6fc8043e6454903e88217f0c92b9a4ac54a86e7909390878a35ba18c1e26b13049f41c522bc049d74db6f76caba39f23d8f07abc26a07a1"
  ,"caba71cb5c12fbc20a715450b2228d17b2ba985cfe2496b033b55f300baf992964388a5422298f627ba567730ddb03a195806a5c23a1d315481c52814b0681ea"
  ,"3c804b02c90688c2fbbce9b17d230a42f8b865417c9e93347f5ff624879962747c7eed886acd48a994b22064ca499c69aa4825be60260d12f63102799828b3cc"
  ,"ebaa4340b749605017eb4598ff13a634500a48470de9078a34106267d25a0b144d8cdb1a4d527692153da013c0ab27ae2ca955e7c66238746022d50630892933"
  ,"a05c283a9f4c00c9f984646f75471081722ed3404ce60fed4a06702b8728b62d920b3224206ab0a4694f9c18e3162b529c16af04b87b4a61cd53a757906d67a1"
  ,"39629585d423a3b0986f29c95984e2095ea4608784b0b31c20cbc36cfd60b773389fe5a8c0958211a35b2c45f21f51a08693c19bfc388c2d677a214ccc5a7cb0"
  ,"b67030fd6987503c91b0f2646985a9048489dd882bd4141f5419554eb738fa7333c5c57a4ce5541fd6b8ad454c2dea67ad1c6f848c0a44a1872e40a17d987075"
  ,"d762ba5aaa21d435dd079b989a8ee21a2ce898934a98a02d5b381c302a2d76948fa65de15666f57750d580ae1a541c700692dd0b0a6799b5cdb893413bb89bb6"
  ,"5182f219a4bc3c80b43bb591bcd05ac6e9a366552558ed5c5fbe7b4acfc7b23372094f6a87f26c0c46646c55a888871324fea7536e586a5149b9b707c86ea076"
  ,"486a6822b9bbf59fbfcaedc13284b9813cabdd526e326a6832d3b36efc3102ef1369c4700afc1f4462f21bb71a2c07a74a3fa2e8822577588d6140aa692cff71"
  ,"24752da14c9fc3b8ae0d9e4a8b1016b8d8fc69e229c03ea2ef08a4ae0cffc37f"
  ]

mlkemWyCt768 :: ByteString
mlkemWyCt768 = hex $ concat
  ["00e96c44eb5f5380d80b4cb05d608971a28fbe838b912b558bf9676c6c67c9692ed6ea063fc47b70d5d6004825c269b9cb8e68b5728d67f44844d97686a11154"
  ,"e3cbd4a6f9e47524d93d851bdce480d7762ded09be53d17cce3ee28dc5a06911c062b99b218355dd5822108c55e2c67f7ea0b74b6189b33b4589d8ff9d0c867d"
  ,"13edaaf1c5f724675320beda3e6acc673c048fa04a1b30f899227d5a555e08a412a47b7db75eb118a8844a71b186880426f6bb6e77186d18e753cbcce93c9fb7"
  ,"6c729875b4d473eeca8dab9941969faef04df9ce3178e7341eab416d28bb7aee12bfb8f4c3df814eff45a0187329079acfc41a8e8dba7b08d111f02e37a1d2b6"
  ,"9e57eef808fcc6ae23385534a420a93dfb6a95c73e2f1016177c4fe9d3ced769e277293aaceded6d07efc7890eaa885bd1e73f9e5da2b9cfda0d44cbc9090705"
  ,"ac2ce3e7bcd7775b593c706e45ddc97d3a65d9b7e73673f9473df5bfec689671f73e7f6ee77c730a8ebda1f0b2c112a71904d6f28a51d8d479f8323fb485e722"
  ,"f5c4d5857e95989a9cbaf273efd04fc3cbde98baa9969e095e88accecfbd12ef2155497a5b15fe91a70d1106b91a568363bfc2d6736cc8138cbc41ddf1e54fd4"
  ,"0511e27d89e2c26c027b63c156e2bbb998faaed3d72186f0cc626dad39a782dcda2087fd13a9498e10b41b685646a227ea1166a5632c195983f4aba2b718b407"
  ,"4030d57126d34c38349892007acbea9e393b967dc3146b270f080a1f0bee90d65a095a6352a7718ed1717a8025a2bd38c66d120baf4247676a1fe044a57ce268"
  ,"c078f8ff46cc26fe4f9c7a03d6467adacb8418d26273662bce1f7bc00b906e0088e95dc0fb419e2232e85aac77b9e7cd563e604de5e1d3e9693dcd3b19865cf4"
  ,"250773691e7e0af9c2755cd31f49d1f96708f3ba2f0b98184525abb869e12d5cea0ac1740181a875035300b05a54b8d42ee3b4ae92b06e43cd807e2b096c977f"
  ,"23c61ef8c989c52ed83754076dea1323f639250bef61bdf903bf7961cec89ba6942d9d0647ac9c8195d93ed8abcedf25754644035719a5a0a1c8c0798912726a"
  ,"9a8258e4c10ae7485322ed9ba331f6f090c4b492a4fcf53d753cd34f28ec0443fce0724f43c89a3942169d5099a8f7430f38691ebce2e3fe4f600d82c7ccedf6"
  ,"0673f8e5d4c1a9f84b8b5b23f5ed63defb6a7205e0a8b105bdc6ff4568fc78cb4456b02fedb7f4c48f6fd6b69216a3319821039db40e19a31a0b0c9d471d5a7a"
  ,"73865d26f8be3595525b1ec4a8579efd07ea98e2602e2bffdfd8febc5c7b4c736d326b5030ccc6faf9420a9c156a8f4516b9fff675459dfdcd4ef85d7adbdffd"
  ,"60f4a39628e399cc752c2e99ab2f431dc765e7c9d206bfe32649fbef4ef48b1d7936fc74766d724350ee2245a8d5f23fbc6c7ed8b57168ce1e864e49d7f8c475"
  ,"dcda140bd42473825b3c72eb8c54780188813011e1962a503f9b516e13226de6375b204733b0192183c8f55e870e61cf8947c3191790bc0b657bc43aebc9d86c"
  ]

mlkemWyK768 :: ByteString
mlkemWyK768 = hex $ concat
  ["76c10bb1d86d96d7eb18e298363e51f7728e113f455df7d15017940ed3541451"
  ]

mlkemWySeed1024 :: ByteString
mlkemWySeed1024 = hex $ concat
  ["8247c17686a8bc0b3afebe6bed1df1dc3ff7fa07c3670f624930235f20aecb4353ece11faa61f47d946ee501abb9a48029096de63b243a1794c4a760f98cc157"
  ]

mlkemWyEk1024 :: ByteString
mlkemWyEk1024 = hex $ concat
  ["a22bc758f65682632313e5c786952a5a144e9747791a4a382c74618b879e6fd8584dc42fb103c6537384906108ece36734510ab6fb5fc68baba2eb9cdb893ef0"
  ,"bccc0e1a90287213ebf25b4455056055993516439af9b45fb441187b2b0169734809497e24821a888b3502469af74023b376f62b03e3e00259f0540bd1163b67"
  ,"750f8a75eb127bec50031619c1bc362d2ab844baab68925884be574ea5d2cc8f694a37503592d2107ab47ba4258b9b3ab0eddc9c4d1402785665d783b298004f"
  ,"eb196c48228cc3a684d6950ae688054f5acb35b09c3f290a76470f548674ddaa92ff808d7a091f7795cd75503d5d6982275c01581c1d22d491d2222e97e17280"
  ,"9bc9d9c8c6c3875302a03901914017326440faced5bac1dcd2a9014b426f764335f31fd41a05dce58a731bb6e362a61d712303ba1ca4eb0998e507304b6f8c88"
  ,"7254261ab4fbca4a198bac4792894a974dd203cf7c9ab58b9402f515aac64641aba6ee133572835f31b4ab6178ccf5c2a9ca875d8d9866bf8a282c49cf3174a8"
  ,"9c415926f5155516baa34aa4c3b47af49ac7c6dc9323c45e69a47d79045d66181041da3cef619449c004bf314ef8a6a02a0819a6511dd2eb88e7336a01b947a1"
  ,"b5618e02865d8a9db031be34c1259fc09230f43d294baab64c5cd348563309564cc30912e672d7eb0ec43a7c8f94c89ab99bf4fb852fe661b4c37d6058312c9a"
  ,"7f3b33ce9103625d886869d79f98c6047555310ce6904ddc050d37b8bc872d93951b703b961773696238b890a0971e90c005cc2e75628746b599f878355df2b3"
  ,"55153b282b4dcf7b7c3167cfb48bc6002861f5d000a373239166449a67718a1b9dbb43ce6c18a5be227e23f999c8bbb1de6441a6e1193b5176bba03c4f8c71fd"
  ,"da29ee18c336d120d0c331a0a622c1827166c1aa351bb7dca69d84bb9ec692ca62812fbe4a5f89a65ec5b6a6eb976658585f5a63541a23242f31022c4c44db40"
  ,"0dd292227b3976cb741e708369370c9555297433b67da83992b1e06d791aa6faa34a040332cbac151576a51c794e2b791dc3740e0f0136fb2137685ca71b3626"
  ,"fb6a51d8417df2408346929685371dc1532093d38176fb8c670b7a7236bb9035923280016afb5070bb559e78a89bd6c5fc36c87e0a5443587c879aa94368ae6f"
  ,"a6690d38bc18274bab0b4b0f01accd95c0af0ba048a76880b8c842430c4541bdbdb267d39498fdd35907a58faab500a710742a63179d5c15fad0bace8bba3019"
  ,"35e7b195794597a206a9ad83ca73b66c18f1a25d6813a242a4d082b646d488bc63852df5b69ef08510a657d3ba5954b6a4df752237d8c5d0a429baa14be2f824"
  ,"e16ca19e694de9c6251cb90958a03159914243dc5e272438e2a6500970b55390b02c3b5e52ccb7ebb2099f646f9518376417896e837c16f783ce568d59e6c6e2"
  ,"068892936b6e584a6d2233e7d98506b740008b6d14e29cc878170c966f80f3c76cb96d3e7665eba6067d996bdb16a45c094d8563958a1015ce833b3cac29d4bb"
  ,"3e970c0d7ae654451b378a1027340b5471790ea68575d200c8af88777e28a203c4b36b0512de6607436a34d83a6691882aa5f81c83649f0370be6b743140fc62"
  ,"db1527d220cf6b66870dc674660b5856a34766fcc66f7480c383c904fc124bc608a38246ebe835b3834487611b8d262578364f5849c94437937fa47341a31848"
  ,"7a23129c3636f050a0d693a7cb89f36c78502487a691142ca88d8975b4a92417bed59efea73fe3892a062ba384d404887c498909212a5c913e8953c4d50d87fa"
  ,"a6bb9c3536582e39b69cfa59240dc881fed2b9450aa1715b88805966b5e52505341f98f728ef939f7917083057a42c40ce9f364117d6b9752179f8d22c4ba3b0"
  ,"0de31363d56ad69b92db30ae809036b93a5437598abf115496126dae81875d633e47d49c27911892a885efd78122b90712d3576d864701a469a25b34d9041136"
  ,"29a3231b20cdd5a2ede1188e0c411e619162820ea6f1009bf17f32e36fd716098b384013e60a85572d217aa1239507efdc0604379592f66de032372589404952"
  ,"c87552b5c3326d4cac0172c74254b792463ca428d334ee419994eb501b07789349b1d0c16a352ac8fef45d30da79cfa53147529149bc69b594745ff86e2ba862"
  ,"d128410ed993d5e6b3f011342518beb7be48573d1adb2b712ebe6f7b79802ff3"
  ]

mlkemWyDk1024 :: ByteString
mlkemWyDk1024 = hex $ concat
  ["bec150848288ec475764626e004d8b6f055918b00a235a2cb1965dc3235800cc7a392cc93146cfd2b74ac2bc684cd38e7f3c6c23e7c585e09106d2b358224e9a"
  ,"4bcb1aa93319ab1cc09068da6853e302c4e4824fe8366d98917b11caae2ab793306625ea1697b222016821c626b1432df00f1c982c6362bfa8c03cdb69397081"
  ,"8cab00ba92dca2ea145677b025c9034b2af10f4d20b3e0b289fcdbadda45a5e171ac73fc71ed3b8c1227541452519fd2216e97b3d7c8b1077677055571b1f487"
  ,"3c35c949a808fc038827faa6adf921526067f9bb183f746666318c19f75f708238cd072d97e3cea2b00b0d43a4bbb27e7bc0588200a1a0f572cb474f30259516"
  ,"a874eb53c78a42cda447b3fd771ab5641f3b367b0f297e47a00cf8a28fe5e09bc5d33e0bb19de3868daae15f7eea1383725db09422cf683ac3b12457d93ee5a4"
  ,"35b0f488e2b339207a028654bfe57933931bcb7b33573efac0606a9014f924bcb66349a2297c8c9442343e013b7c9617588cdb2037b4bab6d482b9087973d3a3"
  ,"5d5c8d9e481969a4bc2a1b19b596541f848e50c19a95b74ca2571ce50438e4d8954430356baacdee160612aa2c80385dcd9457cb7589487497d3906c4577a3c7"
  ,"238c5f4cb5aff20819176b73f36f72a0587c370bf23917a4e04a447cb71d4612d1488e8de511630c99c8800758097d8584668fe6208d1352d47193cc61934458"
  ,"839925a114516ab4c2c3135b43c8702862328327abadb4d887affc6e342c7e72691f243b3abb215e59b82782e13b70b86794159c0fb69c551a9bb196a118f216"
  ,"b19bca98aacf3b764ee4cb9714a29cc8c879391ca6f3a6cbff81b242082d66800a8b85ac09ca81d6751ffad25df07871408122aa46cac28913e74c65923a8471"
  ,"b97b12c74905a59e2e8a4773e0160a3a8e7028bcba1c7f917a5a8be793fa1181a40a66ea1baf23f709325410178ab394b189750b4beaf91b2755604dac50d2d2"
  ,"31117c3d07150b6b64b4a9f1328a035bff9c05bb3a2f4e8839b7f3485cfcaf58c2c4d94c472f5ab4096a7548423e45bb51bab56340e70eefa83daaf13476e4ba"
  ,"c28b1c0b528673768f2f1bcb9cc23173f766d4e56abaf2693be62992759e45a68d7a33636da95bb552462c697ac79cba104b6bb958b17d740fd3a56a37ba4ce4"
  ,"101a1c5ace12727f99066c6bf00c3f39785c9b0785a31294b26faeb7c27b472a38b0339d93286343068ca2a461e61a00b390ae6ba5d909261ec781f80b8f48a3"
  ,"6d7c849424c780e37a886247af9df317690870f470981bc3a913307f9da076c7460511f5c50fa7b09ec2cbee7b2f98f44972a53f631491afea4bb6975ff5c50d"
  ,"241c2573d50aff69b685f08ab64798ddfca65f286391a27aed1517afd65a84d842b07096fada197c2a7aca06cbc3525f80c121cfc25e94249d57479d146890e8"
  ,"323f07e3a94ff5354dbc520923ce60c747aaf19610a00b50cb5f8bab8ca8dc37f33621832b659c098115d334f38236cc74ce2d8974b2d8bac674b4d81ab65b40"
  ,"cbf22b1ed72854a7f43f85090c665c69b2da9c63b6a4aaf583ce132f18d4a52ce313262ca271d76e16468d45c40c5ee50620ba078686147527ace27953bb9a87"
  ,"173388e0909beedac3ba925607e1a7dec0871817429e4a1844306c5f37411df38d54057577c099f858ae14114047fb5c3bc05628a8686f65a3c0352d479cc27c"
  ,"768b8bab4464d0c1d12c7fa4721474332b6dbc6951021d98220db313c3d0a0aaca7589e5789d460b4849d20e08c519409277174bad182b47b824c9ab96b77f26"
  ,"410e161bd94c6e03f51a6f2c1ebec0135588b4f5696e5a28632f43299a77937c518ea9c7250281b6b7f370a579ab52ecbdf98466a9a69b34f09b97cc486260c8"
  ,"15b969cbe4b6a4b8597035c6377913140314f4c685d9720f0891740cb257cccac531447750ecb1ee360cacf9800d706d4b17128cb537a019999bc900de43233f"
  ,"71aff5c8a32c979a7de1789f7a1bd4d03f47e9a541199d37ba8b7ce3b8f99b232e9b8344f06d5c1c2b8a85a1f6051d6b779dea8a0b6cac4fb2a689e00616a559"
  ,"595bc5b4c1cb00c261020f16702967c72d8cabb6b5a60a65a6c92907c439152cd78a64305f087c357ad891f9e597c57163a79b99e74403f24201350005fe21b9"
  ,"a22bc758f65682632313e5c786952a5a144e9747791a4a382c74618b879e6fd8584dc42fb103c6537384906108ece36734510ab6fb5fc68baba2eb9cdb893ef0"
  ,"bccc0e1a90287213ebf25b4455056055993516439af9b45fb441187b2b0169734809497e24821a888b3502469af74023b376f62b03e3e00259f0540bd1163b67"
  ,"750f8a75eb127bec50031619c1bc362d2ab844baab68925884be574ea5d2cc8f694a37503592d2107ab47ba4258b9b3ab0eddc9c4d1402785665d783b298004f"
  ,"eb196c48228cc3a684d6950ae688054f5acb35b09c3f290a76470f548674ddaa92ff808d7a091f7795cd75503d5d6982275c01581c1d22d491d2222e97e17280"
  ,"9bc9d9c8c6c3875302a03901914017326440faced5bac1dcd2a9014b426f764335f31fd41a05dce58a731bb6e362a61d712303ba1ca4eb0998e507304b6f8c88"
  ,"7254261ab4fbca4a198bac4792894a974dd203cf7c9ab58b9402f515aac64641aba6ee133572835f31b4ab6178ccf5c2a9ca875d8d9866bf8a282c49cf3174a8"
  ,"9c415926f5155516baa34aa4c3b47af49ac7c6dc9323c45e69a47d79045d66181041da3cef619449c004bf314ef8a6a02a0819a6511dd2eb88e7336a01b947a1"
  ,"b5618e02865d8a9db031be34c1259fc09230f43d294baab64c5cd348563309564cc30912e672d7eb0ec43a7c8f94c89ab99bf4fb852fe661b4c37d6058312c9a"
  ,"7f3b33ce9103625d886869d79f98c6047555310ce6904ddc050d37b8bc872d93951b703b961773696238b890a0971e90c005cc2e75628746b599f878355df2b3"
  ,"55153b282b4dcf7b7c3167cfb48bc6002861f5d000a373239166449a67718a1b9dbb43ce6c18a5be227e23f999c8bbb1de6441a6e1193b5176bba03c4f8c71fd"
  ,"da29ee18c336d120d0c331a0a622c1827166c1aa351bb7dca69d84bb9ec692ca62812fbe4a5f89a65ec5b6a6eb976658585f5a63541a23242f31022c4c44db40"
  ,"0dd292227b3976cb741e708369370c9555297433b67da83992b1e06d791aa6faa34a040332cbac151576a51c794e2b791dc3740e0f0136fb2137685ca71b3626"
  ,"fb6a51d8417df2408346929685371dc1532093d38176fb8c670b7a7236bb9035923280016afb5070bb559e78a89bd6c5fc36c87e0a5443587c879aa94368ae6f"
  ,"a6690d38bc18274bab0b4b0f01accd95c0af0ba048a76880b8c842430c4541bdbdb267d39498fdd35907a58faab500a710742a63179d5c15fad0bace8bba3019"
  ,"35e7b195794597a206a9ad83ca73b66c18f1a25d6813a242a4d082b646d488bc63852df5b69ef08510a657d3ba5954b6a4df752237d8c5d0a429baa14be2f824"
  ,"e16ca19e694de9c6251cb90958a03159914243dc5e272438e2a6500970b55390b02c3b5e52ccb7ebb2099f646f9518376417896e837c16f783ce568d59e6c6e2"
  ,"068892936b6e584a6d2233e7d98506b740008b6d14e29cc878170c966f80f3c76cb96d3e7665eba6067d996bdb16a45c094d8563958a1015ce833b3cac29d4bb"
  ,"3e970c0d7ae654451b378a1027340b5471790ea68575d200c8af88777e28a203c4b36b0512de6607436a34d83a6691882aa5f81c83649f0370be6b743140fc62"
  ,"db1527d220cf6b66870dc674660b5856a34766fcc66f7480c383c904fc124bc608a38246ebe835b3834487611b8d262578364f5849c94437937fa47341a31848"
  ,"7a23129c3636f050a0d693a7cb89f36c78502487a691142ca88d8975b4a92417bed59efea73fe3892a062ba384d404887c498909212a5c913e8953c4d50d87fa"
  ,"a6bb9c3536582e39b69cfa59240dc881fed2b9450aa1715b88805966b5e52505341f98f728ef939f7917083057a42c40ce9f364117d6b9752179f8d22c4ba3b0"
  ,"0de31363d56ad69b92db30ae809036b93a5437598abf115496126dae81875d633e47d49c27911892a885efd78122b90712d3576d864701a469a25b34d9041136"
  ,"29a3231b20cdd5a2ede1188e0c411e619162820ea6f1009bf17f32e36fd716098b384013e60a85572d217aa1239507efdc0604379592f66de032372589404952"
  ,"c87552b5c3326d4cac0172c74254b792463ca428d334ee419994eb501b07789349b1d0c16a352ac8fef45d30da79cfa53147529149bc69b594745ff86e2ba862"
  ,"d128410ed993d5e6b3f011342518beb7be48573d1adb2b712ebe6f7b79802ff3b955809aaedf3b1e2988832123519721ba6c3b5030096bd358e4a82b53eb0985"
  ,"53ece11faa61f47d946ee501abb9a48029096de63b243a1794c4a760f98cc157"
  ]

mlkemWyCt1024 :: ByteString
mlkemWyCt1024 = hex $ concat
  ["001d80376f40a555c9590838e4dd953cfb9a30edf7768f0f35b298c69eb459a42e081f79b419391b14347254849f1ddeac6d03975f22c9bd0e7a27cef18432e1"
  ,"d42b75d3845130cec8cd2387007116f7b21f69d196eb3340a44d4b3d92b2acfa420ce4654063d0e739ffb9238990c117454ed017d33bd63bc1c2da9adc52cb0f"
  ,"a2dc90f6f7482e3072f4d620d65afab8e908943dd7a4e91ed4e12b9147656a8fe758abdfa2d5d2d810edb4409ab09332b9dddccdc6cabf8d89633c609a0a005a"
  ,"f2f4fac6baf70315103825531f513f9fc9f6d088cf28b54ff6fba4725e6ee291131b778058a45ed49bea10c1aa0aed05796a3bc88a1a45bc63a01b3646521e79"
  ,"68bdb0eab72758a6f025411814013e123fe354484f4380a218f6f0b6876bf4a225766890ab191b6ffdf84fc19521533b58cc518a5f40d7e2861e9a51c297e3ab"
  ,"fe8b36674a066bdbb52390b6e2c91d0a6e1ae66210f3e700344d1a75978945ac9ef7fe72a7c1f6939690cd33e11ef3a9efbb9dc3285254af07121758aad87d34"
  ,"a85231b63f23a6b81a2e5bd232c0138ff574417d2b1fcbde45b686ed6348da7bb2cef151285ee52f4e0e214139f812a68df69459706baf85e31a0073623c7fae"
  ,"c1c0b99d86d34fd3a7145210c1870f37687f8d4c94849a22dd1099cd8c730969fcf8e1cc4c1af623f89bb0f2e3b6e4a4c37b6d4d7c8f66df8c384c66264e7a4b"
  ,"35e893cf7424642db20a844aef74a12f1dd244bd331101486babee54b326440f9f9b97e1f1a603146b42b8266a05781ec8bfff57bab186973a9b7bffa60ff246"
  ,"a01d2c9259950e94e9df25dca30c59890280636dee43f83510ddf7de2a5f77a78854cde70ead0943bac7895ee10d363a9334a1d502c282671161a2355f1d4be9"
  ,"9a1f9f67e687b9851caf8a3db107940b1ab4481084f8a96053c6205a207ca19043f8d20090ef245557c6b7c1bd2065d2db7f8343acdcd9f7341491c665a8842c"
  ,"19e19d12ab36b01ec68c95bfd9226aa10370ea1b71f08b326f7817a96c53132d7b5004fa00ecf1d6204198fc785b05438bc687cba235e5c2211d8e1e1f211664"
  ,"f240c3c2e4f4a1990943ec83ad80141beceba6e31384c0aa148783872593c0ce9e002cb2af6de35845dc1fcd6e7d5da96b6e8cf3a4cab1d6490ad18203cdac1a"
  ,"77f608c8460d21230ac8470f841c6c17f5a1faff871c27c5a9e0e93a20b5c1e17d8f7a5c74065ab192c33d08d0c603226a01b9f5976e0f06625baa7f90554ee8"
  ,"05d7ee242cb54d3183758bf948ea31024fa3aa368cfc8ba7df1474a4388e84e3f79617080a96ce3af88ce5e1b9ba02871c2e6a54d0fc05050295f5f9a638a63c"
  ,"51428bc935c7f539cdd90a5501b8832a3bea490657f026ec6745d4b30f518e6f4b2bee0afb65b34df1d81a4751aed0865b9cb01f4cdc65cab3ee1b3e988b23c0"
  ,"f2c63cb16e305d4c7b69a2ebac8471d6d61412004bbbd4550debbf64c49f5975df1f4bef53281fbadda4a5fb7dfa63e7261499a74c7f3af2026a997c1fdcde6c"
  ,"07fb3ce720a450f9de6970d6121706245e4cd2332247c6cce84085afbf7fab4f7f1fa98626646630e48e2dab8cb21661c306a22ebd7243beb7fc3c6cf57088a4"
  ,"0d05c2381fef655c42817f1bb95de7d20f38d02fc1e3b2d6852b2a8f3a4dd4a262ada59f48482e44468c10c0506368c305ee4efc93d60adac26c132587396408"
  ,"90762077e771ecb57c01efbb895c65a9eb1a2c479f1ad7434377331738a2034840682de3ae673ce47e3e54172556a3a543066fd5e30473c33641ffe90144bbe1"
  ,"5d68b5e8ab9c063f48edb3a4480356e7a7ddef32c60f0edffcf1c5fef4eb488476794f42af7b66eb01b19bfba59cacd157d485037b2c383add0cf2ff727c1056"
  ,"a466930e46e3f081af429a45e5ccdfe8e0f3c210474eb0156744c7d5486f761910083b6a8fba1898a52b112b96b4b3387f2f3e4000aa0854781b029e8c01f3f0"
  ,"9f0cd361eaaa56a89b2a054a1805248e89ddc32dc8a3e53333595686e4e7b076340076a29c1c0f4f1232af35527e8d35f887e7fe524991b5b74da3b02dc26f72"
  ,"27595c096fd40541b86e7f0705cebd4c2a134c14e8f9eef94fa609a305e6a429f290404f1043c1666387df4bafc2308dc4eb2539c01dedc23d9c2018a9c5cdec"
  ,"50475a8f8ee32d9d13d79b304dcf69b949be7877fab4752b45b9ee04622123db"
  ]

mlkemWyK1024 :: ByteString
mlkemWyK1024 = hex $ concat
  ["c6338bf92f3930b95f81d87fe669fabc42aaa549e8fecfbfdbe237d739fe4d96"
  ]


caseMlkem :: IO ()
caseMlkem = withBackend $ \env -> do
  let tamper bs = BS.init bs <> BS.singleton (BS.last bs + 1)
  -- Wycheproof KATs: tc1 decapsulates to K on every set, from
  -- raw dk bytes (the dk-only import shape).
  assertEqual "wycheproof 512 K" mlkemWyK512 =<<
    expectOk "wycheproof 512 decaps" =<<
      kemDecapsulate env (mkKem ML_KEM_512) (KeyBytes mlkemWyDk512) mlkemWyCt512
  assertEqual "wycheproof 768 K" mlkemWyK768 =<<
    expectOk "wycheproof 768 decaps" =<<
      kemDecapsulate env (mkKem ML_KEM_768) (KeyBytes mlkemWyDk768) mlkemWyCt768
  assertEqual "wycheproof 1024 K" mlkemWyK1024 =<<
    expectOk "wycheproof 1024 decaps" =<<
      kemDecapsulate env (mkKem ML_KEM_1024) (KeyBytes mlkemWyDk1024) mlkemWyCt1024
  -- Tampered ciphertexts decapsulate to a DIFFERENT secret
  -- (FIPS 203 implicit rejection: never an error, never K).
  ssBad <- expectOk "tampered decaps" =<<
    kemDecapsulate env (mkKem ML_KEM_768) (KeyBytes mlkemWyDk768) (tamper mlkemWyCt768)
  assertBool "tampered secret differs" (ssBad /= mlkemWyK768)
  -- Off-width ciphertexts refuse typed (the model layer
  -- enforces this first; the shim repeats the check).
  expectBadParam "truncated ct refused" =<<
    kemDecapsulate env (mkKem ML_KEM_768) (KeyBytes mlkemWyDk768) (BS.init mlkemWyCt768)
  expectBadParam "overlong ct refused" =<<
    kemDecapsulate env (mkKem ML_KEM_768) (KeyBytes mlkemWyDk768) (mlkemWyCt768 <> "\x00")
  -- Garbage keys refuse typed on both entries.
  expectBadKey "garbage encaps refused" =<<
    kemEncapsulate env (mkKem ML_KEM_768) (KeyBytes "bogus")
  expectBadKey "garbage decaps refused" =<<
    kemDecapsulate env (mkKem ML_KEM_768) (KeyBytes "bogus") mlkemWyCt768
  -- Cross-set execution refuses typed on both key shapes
  -- (the shim checks the key's actual keymgmt type name for
  -- DER, the width gate for raw).
  pub512 <- KeyDer <$> loadMlkemFixture "mlkem512-pub.der"
  expectBadKey "512 SPKI under 768 refused" =<<
    kemEncapsulate env (mkKem ML_KEM_768) pub512
  expectBadKey "512 raw dk under 768 refused" =<<
    kemDecapsulate env (mkKem ML_KEM_768) (KeyBytes mlkemWyDk512) mlkemWyCt768
  -- Roundtrips per set against the KAT keys: encapsulate to
  -- the file's ek (both SPKI and raw shapes), decapsulate
  -- with the file's dk; encapsulation randomizes.
  mapM_ (roundtrip env)
    [ (ML_KEM_512, 1, mlkemWyEk512, mlkemWyDk512, 768)
    , (ML_KEM_768, 2, mlkemWyEk768, mlkemWyDk768, 1088)
    , (ML_KEM_1024, 3, mlkemWyEk1024, mlkemWyDk1024, 1568)
    ]
  where
    roundtrip env (alg, ckp, ek, dk, ctW) = do
      let label = show alg
          spec = mkKem alg
      oid <- case mlkemOidOfCkp ckp of
        Just o -> pure o
        Nothing -> assertFailure ("no OID for CKP: " ++ show ckp)
      let pubDer = KeyDer (mlkemPublicDer oid ek)
          pubRaw = KeyBytes ek
          priv = KeyBytes dk
      (ct1, ss1) <- expectOk ("encaps SPKI " ++ label) =<< kemEncapsulate env spec pubDer
      assertEqual ("ct width " ++ label) ctW (BS.length ct1)
      assertEqual ("ss width " ++ label) 32 (BS.length ss1)
      assertEqual ("roundtrip SPKI " ++ label) ss1 =<<
        expectOk ("decaps SPKI " ++ label) =<< kemDecapsulate env spec priv ct1
      (ct2, ss2) <- expectOk ("encaps raw " ++ label) =<< kemEncapsulate env spec pubRaw
      assertEqual ("roundtrip raw " ++ label) ss2 =<<
        expectOk ("decaps raw " ++ label) =<< kemDecapsulate env spec priv ct2
      assertBool ("encaps randomizes " ++ label) (ct1 /= ct2)
      -- A non-canonical raw ek refuses at the backend
      -- (fromdata re-validates the modulus even though import
      -- already refused it).
      let badEk = BS.pack [0xFF, 0xFF, 0xFF] <> BS.drop 3 ek
      expectBadKey ("non-canonical ek refused " ++ label) =<<
        kemEncapsulate env spec (KeyBytes badEk)

-- | ML-KEM generation: keygen mints usable pairs on all three
-- sets (provider PKCS#8 halves with a 64-byte seed, SPKI
-- halves, agreeing OIDs), and fresh pairs roundtrip.
caseRealMlkemKeygen :: IO ()
caseRealMlkemKeygen = withBackend $ \env -> do
  mapM_ (genPair env)
    [ (ML_KEM_512, 768), (ML_KEM_768, 1088), (ML_KEM_1024, 1568) ]
  where
    genPair env (alg, ctW) = do
      let label = show alg
          spec = mkKem alg
      (privM, mPubM) <- expectOk ("keygen " ++ label) =<< generateKey env (GenMLKEM alg)
      (privDer, pubDer) <- case (privM, mPubM) of
        (KeyDer priv, Just (KeyDer pub)) -> pure (priv, pub)
        other -> assertFailure ("keygen halves are not DER: " ++ show other)
      case (mlkemSpkiFields pubDer, mlkemPkcs8Fields privDer) of
        (Just (pubOid, _), Just (privOid, seed, _))
          | pubOid == privOid -> assertEqual ("seed width " ++ label) 64 (BS.length seed)
        _ -> assertFailure ("keygen halves disagree or do not parse: " ++ label)
      pubM <- case mPubM of
        Just pub -> pure pub
        Nothing -> assertFailure ("keygen missing public half: " ++ label)
      (ct, ss1) <- expectOk ("genkey encaps " ++ label) =<< kemEncapsulate env spec pubM
      assertEqual ("genkey ct width " ++ label) ctW (BS.length ct)
      assertEqual ("genkey roundtrip " ++ label) ss1 =<<
        expectOk ("genkey decaps " ++ label) =<< kemDecapsulate env spec privM ct

loadMlkemFixture :: String -> IO ByteString
loadMlkemFixture name = findFixture
  [ "tests/fixtures/" ++ name
  , "../tests/fixtures/" ++ name
  , "haskoki/tests/fixtures/" ++ name
  ]
  where
    findFixture [] = assertFailure ("fixture not found from test cwd: " ++ name)
    findFixture (p : ps) = do
      exists <- doesFileExist p
      if exists then BS.readFile p else findFixture ps

-- | S10 ECDH agreement: CLI cross-checked KATs in both
-- directions, cofactor-equals-plain on P-256 (h=1), the P-384
-- width, and typed key-shape refusals (garbage, off-set curve,
-- base/peer curve mismatch).
caseEcdhVectors :: IO ()
caseEcdhVectors = withBackend $ \env -> do
  let pA = KeyDer ecdhPrivA
      qA = KeyDer ecdhPubA
      pB = KeyDer ecdhPrivB
      qB = KeyDer ecdhPubB
      pC = KeyDer ecdhPrivC
      qC = KeyDer ecdhPubC
  sAB <- expectOk "derive A->B" =<< ecdhDerive env EcdhPlain pA qB
  assertEqual "KAT A->B" ecdhSecretAB sAB
  sBA <- expectOk "derive B->A" =<< ecdhDerive env EcdhPlain pB qA
  assertEqual "commute" ecdhSecretAB sBA
  sCof <- expectOk "derive cofactor" =<< ecdhDerive env EcdhCofactor pA qB
  assertEqual "cofactor == plain (h=1)" ecdhSecretAB sCof
  sCC <- expectOk "derive P-384" =<< ecdhDerive env EcdhPlain pC qC
  assertEqual "KAT P-384" ecdhSecretCC sCC
  assertEqual "P-384 width" 48 (BS.length sCC)
  -- sect283k1 KAT: plain + cofactor (h=2, so they differ), SPKI and
  -- bare-point peers agree, commute holds.
  let pD = KeyDer ecdhPrivD
      qE = KeyDer ecdhPubE
      bE = KeyDer ecdhPointE
  sDE <- expectOk "derive t283k1" =<< ecdhDerive env EcdhPlain pD qE
  assertEqual "KAT t283k1" ecdhSecretDE sDE
  assertEqual "t283k1 width" 36 (BS.length sDE)
  sDEb <- expectOk "derive t283k1 bare peer" =<< ecdhDerive env EcdhPlain pD bE
  assertEqual "bare peer agrees" ecdhSecretDE sDEb
  sED <- expectOk "derive t283k1 commute" =<<
    ecdhDerive env EcdhPlain (KeyDer ecdhPrivE) (KeyDer ecdhPubD)
  assertEqual "commute t283k1" ecdhSecretDE sED
  sDEcof <- expectOk "derive t283k1 cofactor" =<< ecdhDerive env EcdhCofactor pD qE
  assertEqual "KAT t283k1 cofactor" ecdhSecretDEcof sDEcof
  assertBool "cofactor differs (h=2)" (sDEcof /= ecdhSecretDE)
  expectBadKey "garbage priv refused" =<< ecdhDerive env EcdhPlain (KeyDer "bogus") qB
  expectMechParamInvalid "garbage peer refused" =<< ecdhDerive env EcdhPlain pA (KeyDer "bogus")
  expectBadKey "off-curve priv refused" =<< ecdhDerive env EcdhPlain (KeyDer ecBp160Priv) qB
  expectMechParamInvalid "curve mismatch refused" =<< ecdhDerive env EcdhPlain pA qC

-- | XDH agreement: CLI cross-checked KATs in both directions per
-- curve, wycheproof tc1 exchange KATs, and typed peer refusals
-- (low-order, off-width, cofactor spec).
caseXdhVectors :: IO ()
caseXdhVectors = withBackend $ \env -> do
  let pA = KeyDer xdhPrivA
      pB = KeyDer xdhPrivB
      qA = KeyBytes xdhPointA
      qB = KeyBytes xdhPointB
  sAB <- expectOk "derive X25519 A->B" =<< ecdhDerive env EcdhPlain pA qB
  assertEqual "KAT X25519" xdhSecretAB sAB
  assertEqual "X25519 width" 32 (BS.length sAB)
  sBA <- expectOk "derive X25519 B->A" =<< ecdhDerive env EcdhPlain pB qA
  assertEqual "commute X25519" xdhSecretAB sBA
  let p48A = KeyDer xdh48PrivA
      p48B = KeyDer xdh48PrivB
      q48A = KeyBytes xdh48PointA
      q48B = KeyBytes xdh48PointB
  s48AB <- expectOk "derive X448 A->B" =<< ecdhDerive env EcdhPlain p48A q48B
  assertEqual "KAT X448" xdh48SecretAB s48AB
  assertEqual "X448 width" 56 (BS.length s48AB)
  s48BA <- expectOk "derive X448 B->A" =<< ecdhDerive env EcdhPlain p48B q48A
  assertEqual "commute X448" xdh48SecretAB s48BA
  -- Wycheproof tc1 exchange KATs (external vectors).
  let t19 = KeyDer (montgomeryPrivateDer (hex "06032b656e") xdhTc1Priv)
  sT19 <- expectOk "derive wycheproof X25519 tc1" =<< ecdhDerive env EcdhPlain t19 (KeyBytes xdhTc1Pub)
  assertEqual "KAT wycheproof X25519 tc1" xdhTc1Shared sT19
  let t48 = KeyDer (montgomeryPrivateDer (hex "06032b656f") xdh48Tc1Priv)
  sT48 <- expectOk "derive wycheproof X448 tc1" =<< ecdhDerive env EcdhPlain t48 (KeyBytes xdh48Tc1Pub)
  assertEqual "KAT wycheproof X448 tc1" xdh48Tc1Shared sT48
  -- Low-order peers (u=0, the wycheproof tc32 shape) refuse as
  -- mechanism-param-invalid: the pinned provider fails
  -- zero-output derives and the shim attributes the peer.
  expectMechParamInvalid "low-order X25519 peer refused" =<<
    ecdhDerive env EcdhPlain pA (KeyBytes (BS.replicate 32 0))
  expectMechParamInvalid "low-order X448 peer refused" =<<
    ecdhDerive env EcdhPlain p48A (KeyBytes (BS.replicate 56 0))
  -- Off-width peers refuse before any native call.
  expectMechParamInvalid "short peer refused" =<<
    ecdhDerive env EcdhPlain pA (KeyBytes (BS.take 31 xdhPointB))
  expectMechParamInvalid "long peer refused" =<<
    ecdhDerive env EcdhPlain pA (KeyBytes (xdhPointB <> BS.singleton 0))
  expectMechParamInvalid "cross-curve peer refused" =<<
    ecdhDerive env EcdhPlain pA (KeyBytes xdh48PointB)
  -- Cofactor derive over Montgomery curves is unserved (named gap).
  expectMechParamInvalid "cofactor over montgomery refused" =<<
    ecdhDerive env EcdhCofactor pA qB

-- | Montgomery keygen: both curves mint parseable DER halves
-- whose halves agree both directions at the curve width (no KAT
-- possible for randomized generation). Off-set curves refuse
-- unsupported.
caseRealMontgomeryKeygen :: IO ()
caseRealMontgomeryKeygen = withBackend $ \env -> do
  let mint label curve = do
        (priv, mpub) <- expectOk label =<< generateKey env (GenXDHKeypair curve)
        case (priv, mpub) of
          (KeyDer privB, Just (KeyDer pubB)) -> pure (privB, pubB)
          other -> assertFailure (label ++ ": halves are not DER: " ++ show other)
      agree label w privA pubA privB pubB = do
        pointA <- case montgomerySpkiFields pubA of
          Just (_, pt) -> pure pt
          Nothing -> assertFailure (label ++ ": SPKI A failed to parse") >> undefined
        pointB <- case montgomerySpkiFields pubB of
          Just (_, pt) -> pure pt
          Nothing -> assertFailure (label ++ ": SPKI B failed to parse") >> undefined
        case montgomeryPkcs8Fields privA of
          Just _ -> pure ()
          Nothing -> assertFailure (label ++ ": PKCS#8 A failed to parse")
        sAB <- expectOk (label ++ " A->B") =<<
          ecdhDerive env EcdhPlain (KeyDer privA) (KeyBytes pointB)
        sBA <- expectOk (label ++ " B->A") =<<
          ecdhDerive env EcdhPlain (KeyDer privB) (KeyBytes pointA)
        assertEqual (label ++ " commutes") sAB sBA
        assertEqual (label ++ " width") w (BS.length sAB)
  (privA, pubA) <- mint "x25519 mint A" "X25519"
  (privB, pubB) <- mint "x25519 mint B" "X25519"
  assertBool "x25519 halves differ" (privA /= pubA && privB /= pubB)
  agree "x25519" 32 privA pubA privB pubB
  (privC, pubC) <- mint "x448 mint A" "X448"
  (privD, pubD) <- mint "x448 mint B" "X448"
  agree "x448" 56 privC pubC privD pubD
  expectUnsupported "unknown curve refused" =<<
    generateKey env (GenXDHKeypair "P-256")

caseDhAgree :: IO ()
caseDhAgree = withBackend $ \env -> do
  let pA = KeyDer dhPrivA
      pB = KeyDer dhPrivB
      qA = KeyDer dhPeerA
      qB = KeyDer dhPeerB
  -- Both directions agree with the pinned CLI secret at the
  -- prime's byte width; the peer rides as bare bytes.
  sAB <- expectOk "derive A->B" =<< dhDerive env DhPlain pA qB
  assertEqual "KAT A->B" dhSecretAB sAB
  assertEqual "prime width" 256 (BS.length sAB)
  sBA <- expectOk "derive B->A" =<< dhDerive env DhPlain pB qA
  assertEqual "commute" dhSecretAB sBA
  -- Fault attribution mirrors ECDH: the base is the caller's
  -- key (bad base stays a bad key) while the peer rides in
  -- the mechanism parameters.
  expectBadKey "garbage base refused" =<< dhDerive env DhPlain (KeyDer "bogus") qB
  -- Any in-range integer is a legitimate DH peer (a short
  -- "bogus" value derives); only structural violations refuse.
  expectMechParamInvalid "over-max peer refused" =<<
    dhDerive env DhPlain pA (KeyDer (BS.replicate 4097 1))
  expectMechParamInvalid "peer 0 refused" =<< dhDerive env DhPlain pA (KeyDer (BS.replicate 256 0))
  expectMechParamInvalid "peer 1 refused" =<<
    dhDerive env DhPlain pA (KeyDer (BS.replicate 255 0 <> BS.singleton 1))
  expectMechParamInvalid "peer p refused" =<< dhDerive env DhPlain pA (KeyDer dhPrime2048)
  expectMechParamInvalid "peer over p refused" =<<
    dhDerive env DhPlain pA (KeyDer (BS.replicate 257 0xff))
  expectMechParamInvalid "empty peer refused" =<< dhDerive env DhPlain pA (KeyDer BS.empty)
  -- A tampered peer still derives (in range) but to a
  -- different secret — no silent KAT match.
  sTam <- expectOk "derive tampered peer" =<<
    dhDerive env DhPlain pA (KeyDer (BS.singleton 0x00 <> BS.drop 1 dhPeerB))
  assertBool "tamper diverges" (sTam /= dhSecretAB)

-- | DH keygen: PKCS#3 and X9.42 params mint parseable pairs
-- whose halves carry the domain, and minted pairs on the same
-- domain agree both directions at the prime width. Garbage
-- params refuse as a bad key (DSA mirror).
caseDhKeygen :: IO ()
caseDhKeygen = withBackend $ \env -> do
  let mint label params = do
        (priv, mpub) <- expectOk label =<< generateKey env (GenDHKeypair params)
        case (priv, mpub) of
          (KeyDer privB, Just (KeyDer pubB)) -> pure (privB, pubB)
          other -> assertFailure (label ++ ": halves are not DER: " ++ show other)
      agree label w privA pubA privB pubB = do
        yA <- case dhSpkiFields pubA of
          Just (_, _, _, y) -> pure y
          Nothing -> assertFailure (label ++ ": SPKI A failed to parse") >> undefined
        yB <- case dhSpkiFields pubB of
          Just (_, _, _, y) -> pure y
          Nothing -> assertFailure (label ++ ": SPKI B failed to parse") >> undefined
        sAB <- expectOk (label ++ " A->B") =<< dhDerive env DhPlain (KeyDer privA) (KeyDer yB)
        sBA <- expectOk (label ++ " B->A") =<< dhDerive env DhPlain (KeyDer privB) (KeyDer yA)
        assertEqual (label ++ " commutes") sAB sBA
        assertEqual (label ++ " width") w (BS.length sAB)
  -- PKCS#3 on ffdhe2048.
  (privA, pubA) <- mint "pkcs mint A" (dhParamsDer dhPrime2048 (BS.singleton 2))
  (privB, pubB) <- mint "pkcs mint B" (dhParamsDer dhPrime2048 (BS.singleton 2))
  assertBool "pkcs halves differ" (privA /= pubA && privB /= pubB)
  case dhSpkiFields pubA of
    Just (p, g, q, _) -> do
      assertEqual "pkcs p" dhPrime2048 p
      assertEqual "pkcs g" (BS.singleton 2) g
      assertEqual "pkcs no q" Nothing q
    Nothing -> assertFailure "pkcs SPKI failed to parse"
  case dhPkcs8Fields privA of
    Just (p, g, q, _) -> do
      assertEqual "pkcs8 p" dhPrime2048 p
      assertEqual "pkcs8 g" (BS.singleton 2) g
      assertEqual "pkcs8 no q" Nothing q
    Nothing -> assertFailure "pkcs PKCS#8 failed to parse"
  agree "pkcs" 256 privA pubA privB pubB
  -- X9.42 on the embedded (p, g, q) domain.
  let x942 = dhParamsDerQ dhX942P dhX942G dhX942Q
  (privC, pubC) <- mint "x942 mint A" x942
  (privD, pubD) <- mint "x942 mint B" x942
  case dhSpkiFields pubC of
    Just (p, g, q, _) -> do
      assertEqual "x942 p" dhX942P p
      assertEqual "x942 g" dhX942G g
      assertEqual "x942 q" (Just dhX942Q) q
    Nothing -> assertFailure "x942 SPKI failed to parse"
  agree "x942" 128 privC pubC privD pubD
  expectBadKey "garbage params refused" =<<
    generateKey env (GenDHKeypair "bogus")

caseRawVsDer :: IO ()
caseRawVsDer = withBackend $ \env -> do
  let pub = KeyDer ecPubDer
      derSpec = SigECDSA { sigEc = mkEc "P-256" "DER", sigEcDigest = Just D_SHA256 }
      rawSpec = SigECDSA { sigEc = mkEc "P-256" "RAW", sigEcDigest = Just D_SHA256 }
  -- Same bytes under the wrong encoding are rejected: the backend never
  -- sniffs or converts encodings silently.
  r1 <- verify env derSpec pub ecMsg ecSigRaw
  case r1 of
    EngineFail (BackendAuthFailed _) -> pure ()
    EngineFail (BackendBadParam _ _) -> pure ()
    other -> assertFailure ("raw-as-der must be rejected, got " ++ show other)
  r2 <- verify env rawSpec pub ecMsg ecSigDer
  case r2 of
    EngineFail (BackendAuthFailed _) -> pure ()
    EngineFail (BackendBadParam _ _) -> pure ()
    other -> assertFailure ("der-as-raw must be rejected, got " ++ show other)
  -- RSA v1.5 is supported (see caseRsaKats); the XOF
  -- digest never makes a servable RSA spec.
  expectUnsupported "rsa xof never servable"
    =<< sign env (SigRSA_PKCS1v15 D_SHAKE128) (KeyDer ecPrivDer) ecMsg
  -- The NIST prime curves, every fixed-width digest, and the
  -- raw row are supported (see caseEcdsaCurvesVectors); off-set
  -- curves and XOF digests stay out, never coerced.
  expectUnsupported "ecdsa p-224 never servable"
    =<< sign env (SigECDSA (mkEc "P-224" "DER") (Just D_SHA256)) (KeyDer ecPrivDer) ecMsg
  expectUnsupported "ecdsa xof never servable"
    =<< sign env (SigECDSA (mkEc "P-256" "DER") (Just D_SHAKE128)) (KeyDer ecPrivDer) ecMsg

caseSymKeygen :: IO ()
caseSymKeygen = withBackend $ \env -> do
  -- AES lengths land as lone raw bytes; two generations differ
  -- (fresh randomness every call; no KAT is possible).
  (KeyBytes k16, Nothing) <- expectOk "gen aes-16" =<< generateKey env (GenSym "AES" 16)
  assertEqual "aes-16 length" 16 (BS.length k16)
  (KeyBytes k16b, Nothing) <- expectOk "gen aes-16 again" =<< generateKey env (GenSym "AES" 16)
  assertBool "aes-16 fresh" (k16 /= k16b)
  (KeyBytes k24, Nothing) <- expectOk "gen aes-24" =<< generateKey env (GenSym "AES" 24)
  assertEqual "aes-24 length" 24 (BS.length k24)
  (KeyBytes k32, Nothing) <- expectOk "gen aes-32" =<< generateKey env (GenSym "AES" 32)
  assertEqual "aes-32 length" 32 (BS.length k32)
  (KeyBytes kh, Nothing) <- expectOk "gen hotp-20" =<< generateKey env (GenSym "HOTP" 20)
  assertEqual "hotp-20 length" 20 (BS.length kh)
  (KeyBytes kg, Nothing) <- expectOk "gen generic-32" =<< generateKey env (GenSym "GENERIC" 32)
  assertEqual "generic-32 length" 32 (BS.length kg)
  (KeyBytes kd, Nothing) <- expectOk "gen des3-24" =<< generateKey env (GenSym "DES3" 24)
  assertEqual "des3-24 length" 24 (BS.length kd)
  (KeyBytes kd2, Nothing) <- expectOk "gen des3-16" =<< generateKey env (GenSym "DES3" 16)
  assertEqual "des3-16 length" 16 (BS.length kd2)
  (KeyBytes kc, Nothing) <- expectOk "gen chacha20-32" =<< generateKey env (GenSym "ChaCha20" 32)
  assertEqual "chacha20-32 length" 32 (BS.length kc)
  (KeyBytes kc2, Nothing) <- expectOk "gen chacha20-32 again" =<< generateKey env (GenSym "ChaCha20" 32)
  assertBool "chacha20-32 fresh" (kc /= kc2)
  -- Bounds are typed: off-window lengths are bad params, unknown
  -- algorithms are unsupported (never silent bytes).
  expectBadParam "aes-15 refused" =<< generateKey env (GenSym "AES" 15)
  expectBadParam "aes-0 refused" =<< generateKey env (GenSym "AES" 0)
  expectBadParam "des3-15 refused" =<< generateKey env (GenSym "DES3" 15)
  expectBadParam "des3-32 refused" =<< generateKey env (GenSym "DES3" 32)
  expectBadParam "hotp-15 refused" =<< generateKey env (GenSym "HOTP" 15)
  expectBadParam "hotp-65 refused" =<< generateKey env (GenSym "HOTP" 65)
  expectBadParam "generic-0 refused" =<< generateKey env (GenSym "GENERIC" 0)
  expectBadParam "generic-256 refused" =<< generateKey env (GenSym "GENERIC" 256)
  expectBadParam "chacha20-16 refused" =<< generateKey env (GenSym "ChaCha20" 16)
  expectBadParam "chacha20-0 refused" =<< generateKey env (GenSym "ChaCha20" 0)
  -- BLAKE2B-512-HMAC widened to VALUE_LEN sizes (slice 11a).
  (KeyBytes kb2, Nothing) <- expectOk "gen blake2b512-32" =<< generateKey env (GenSym "BLAKE2B-512-HMAC" 32)
  assertEqual "blake2b512-32 length" 32 (BS.length kb2)
  expectBadParam "blake2b512-0 refused" =<< generateKey env (GenSym "BLAKE2B-512-HMAC" 0)
  -- Sweep labels mint with planner-mirrored bounds (slice 11a).
  mapM_ (checkSweepLabel env) sweepLabelBounds
  -- Unknown labels stay unsupported (never silent bytes).
  expectUnsupported "unknown keygen out" =<< generateKey env (GenSym "NOPE-NOT-A-LABEL" 8)
  -- ML-KEM keygen is served (see caseRealMlkemKeygen).

-- | (label, good lengths, bad lengths) for the sweep keygens.
sweepLabelBounds :: [(String, [Int], [Int])]
sweepLabelBounds =
  [ ("DES", [8], [0, 7, 9])
  , ("DES2", [16], [0, 15, 17])
  , ("CDMF", [8], [0, 7, 9])
  , ("IDEA", [16], [0, 15, 17])
  , ("SEED", [16], [0, 15, 17])
  , ("SKIPJACK", [12], [0, 10, 13])
  , ("BATON", [40], [0, 32, 41])
  , ("JUNIPER", [40], [0, 32, 41])
  , ("GOST28147", [32], [0, 16, 33])
  , ("SALSA20", [32], [0, 16, 33])
  , ("POLY1305", [32], [0, 16, 33])
  , ("ARIA", [16, 24, 32], [0, 8, 20, 40])
  , ("CAMELLIA", [16, 24, 32], [0, 8, 20, 40])
  , ("TWOFISH", [16, 24, 32], [0, 8, 20, 40])
  , ("AES-XTS", [32, 64], [0, 16, 48, 65])
  , ("CAST", [1, 4, 8], [0, 9])
  , ("CAST3", [1, 4, 8], [0, 9])
  , ("CAST128", [1, 8, 16], [0, 17])
  , ("RC2", [1, 64, 128], [0, 129])
  , ("RC4", [1, 128, 255], [0, 256])
  , ("RC5", [1, 128, 255], [0, 256])
  , ("BLOWFISH", [4, 32, 56], [0, 3, 57])
  , ("HKDF", [1, 128, 255], [0, 256])
  , ("SHA-1-HMAC", [1, 32, 255], [0, 256])
  , ("SHA224-HMAC", [1, 32, 255], [0, 256])
  , ("SHA256-HMAC", [1, 32, 255], [0, 256])
  , ("SHA384-HMAC", [1, 48, 255], [0, 256])
  , ("SHA512-HMAC", [1, 64, 255], [0, 256])
  , ("SHA512-224-HMAC", [1, 28, 255], [0, 256])
  , ("SHA512-256-HMAC", [1, 32, 255], [0, 256])
  , ("SHA512-T-HMAC", [1, 32, 255], [0, 256])
  , ("SHA3-224-HMAC", [1, 28, 255], [0, 256])
  , ("SHA3-256-HMAC", [1, 32, 255], [0, 256])
  , ("SHA3-384-HMAC", [1, 48, 255], [0, 256])
  , ("SHA3-512-HMAC", [1, 64, 255], [0, 256])
  , ("BLAKE2B-160-HMAC", [1, 20, 255], [0, 256])
  , ("BLAKE2B-256-HMAC", [1, 32, 255], [0, 256])
  , ("BLAKE2B-384-HMAC", [1, 48, 255], [0, 256])
  , ("TLS-PRE-MASTER", [46], [0, 45, 47])
  , ("WTLS-PRE-MASTER", [19, 128, 254], [0, 18, 255])
  ]

checkSweepLabel :: BackendEnv OpenSSL4 -> (String, [Int], [Int]) -> IO ()
checkSweepLabel env (label, good, bad) = do
  mapM_ mint good
  mapM_ refuse bad
  where
    mint n = do
      (KeyBytes ks, Nothing) <- expectOk ("gen " ++ label) =<< generateKey env (GenSym label n)
      assertEqual (label ++ " length") n (BS.length ks)
    refuse n = expectBadParam (label ++ "-" ++ show n ++ " refused")
      =<< generateKey env (GenSym label n)

caseAeadReal :: IO ()
caseAeadReal = withBackend $ \env -> do
  -- Pinned vector (Python cryptography AESGCM, the oracle's own
  -- cross-check root): key 00..0f, nonce 00..0b, aad "aad-data",
  -- pt "Hello GCM world!".
  let key = KeyBytes (hex "000102030405060708090a0b0c0d0e0f")
      nonce = hex "000102030405060708090a0b"
      aad = "aad-data"
      pt = "Hello GCM world!"
      spec = AeadSpec "AES-128-GCM" 12 16
  (ct, tag) <- expectOk "gcm vector" =<<
    aeadEncrypt env spec key nonce aad pt
  assertEqual "vector ct" (hex "db09cba2093bb01706f216e544cf1429") ct
  assertEqual "vector tag" (hex "39f0385041afdfd3a2d5a8e8ed69a2e6") tag
  pt' <- expectOk "gcm vector decrypt" =<<
    aeadDecrypt env spec key nonce aad ct tag
  assertEqual "vector roundtrip" pt pt'
  -- Tampering anywhere fails closed.
  let badTag = BS.pack [BS.head tag `xor` 1] <> BS.tail tag
  expectAuthFailed "tag tamper" =<<
    aeadDecrypt env spec key nonce aad ct badTag
  let badCt = BS.pack [BS.head ct `xor` 1] <> BS.tail ct
  expectAuthFailed "ct tamper" =<<
    aeadDecrypt env spec key nonce aad badCt tag
  expectAuthFailed "aad tamper" =<<
    aeadDecrypt env spec key nonce "aad-datX" ct tag
  -- Bounds: wrong key/nonce/tag widths refuse as bad params.
  expectBadParam "short key" =<<
    aeadEncrypt env spec (KeyBytes "short") nonce aad pt
  expectBadParam "short nonce" =<<
    aeadEncrypt env (AeadSpec "AES-128-GCM" 12 16) key "short" aad pt
  expectBadParam "bad alg" =<<
    aeadEncrypt env (AeadSpec "NOPE" 12 16) key nonce aad pt

-- | Empty plaintext must seal to ct="" plus the pinned tag and open back
-- to "". The AAD Update call used to clobber the shared output-length
-- accumulator, so empty-message seals wrote the tag out of bounds (lane
-- crash) and opens returned aad-length garbage (Wycheproof tc92).
caseAeadEmptyPlaintext :: IO ()
caseAeadEmptyPlaintext = withBackend $ \env -> do
  -- Pinned tags from Python cryptography AESGCM (same oracle root as
  -- caseAeadReal): key 00..0f, nonce 00..0b.
  let key = KeyBytes (hex "000102030405060708090a0b0c0d0e0f")
      nonce = hex "000102030405060708090a0b"
      spec = AeadSpec "AES-128-GCM" 12 16
  (ct1, tag1) <- expectOk "empty-pt seal with aad" =<<
    aeadEncrypt env spec key nonce "aad-data" ""
  assertEqual "empty-pt ct with aad" "" ct1
  assertEqual "empty-pt tag with aad" (hex "e01312146176abd643fcee9d4a640184") tag1
  pt1 <- expectOk "empty-pt open with aad" =<<
    aeadDecrypt env spec key nonce "aad-data" ct1 tag1
  assertEqual "empty-pt roundtrip with aad" "" pt1
  (ct0, tag0) <- expectOk "empty-pt seal without aad" =<<
    aeadEncrypt env spec key nonce "" ""
  assertEqual "empty-pt ct without aad" "" ct0
  assertEqual "empty-pt tag without aad" (hex "435b9ba12d75a4be8a977ea3cd011890") tag0
  pt0 <- expectOk "empty-pt open without aad" =<<
    aeadDecrypt env spec key nonce "" ct0 tag0
  assertEqual "empty-pt roundtrip without aad" "" pt0

caseAeadCcmReal :: IO ()
caseAeadCcmReal = withBackend $ \env -> do
  -- Wycheproof aes_ccm_test.json group 0 (AES-128, 128-bit tag).
  -- tcId 1: empty message, the CCM analogue of the GCM tc92 shape.
  let key1 = KeyBytes (hex "bedcfb5a011ebc84600fcb296c15af0d")
      nonce1 = hex "438a547a94ea88dce46c6c85"
      cspec = AeadSpec "AES-128-CCM" 12 16
  (ct1, tag1) <- expectOk "ccm tcId 1 seal" =<<
    aeadEncrypt env cspec key1 nonce1 "" ""
  assertEqual "ccm tcId 1 ct" "" ct1
  assertEqual "ccm tcId 1 tag" (hex "25d1a38495a7dea45bda049705627d10") tag1
  pt1 <- expectOk "ccm tcId 1 open" =<<
    aeadDecrypt env cspec key1 nonce1 "" ct1 tag1
  assertEqual "ccm tcId 1 roundtrip" "" pt1
  -- tcId 2: single-byte message.
  let key2 = KeyBytes (hex "384ea416ac3c2f51a76e7d8226346d4e")
      nonce2 = hex "b30c084727ad1c592ac21d12"
  (ct2, tag2) <- expectOk "ccm tcId 2 seal" =<<
    aeadEncrypt env cspec key2 nonce2 "" (hex "35")
  assertEqual "ccm tcId 2 ct" (hex "d7") ct2
  assertEqual "ccm tcId 2 tag" (hex "6be3fd13b7065afc19e3b8a3b96b39fb") tag2
  pt2 <- expectOk "ccm tcId 2 open" =<<
    aeadDecrypt env cspec key2 nonce2 "" ct2 tag2
  assertEqual "ccm tcId 2 roundtrip" (hex "35") pt2
  -- tcId 52 "Flipped bit 0 in tag" (result invalid): must fail closed.
  let key52 = KeyBytes (hex "000102030405060708090a0b0c0d0e0f")
      nonce52 = hex "505152535455565758595a5b"
      ct52 = hex "3ee9f3430f3e803c0a46b7a84cd803de"
      badTag52 = hex "3d6d5f66430ad65bb034077297f0929a"
  expectAuthFailed "ccm tcId 52 flipped tag" =<<
    aeadDecrypt env cspec key52 nonce52 "" ct52 badTag52
  -- Bounds: CCM-only widths refuse as bad params.
  expectBadParam "ccm 6-byte tag" =<<
    aeadEncrypt env (AeadSpec "AES-128-CCM" 12 5) key2 nonce2 "" (hex "35")
  expectBadParam "ccm 6-byte nonce" =<<
    aeadEncrypt env (AeadSpec "AES-128-CCM" 6 16) key2 (BS.take 6 nonce2) "" (hex "35")

caseRsaKeygen :: IO ()
caseRsaKeygen = withBackend $ \env -> do
  -- The real backend mints PKCS#8/SPKI DER halves (no KAT
  -- possible for randomized generation; lengths pin the shape).
  (KeyDer priv, Just (KeyDer pub)) <- expectOk "rsa-2048 mints" =<<
    generateKey env (GenRSA 2048 65537)
  assertBool "priv PKCS#8 length" (BS.length priv >= 1180 && BS.length priv <= 1250)
  assertBool "pub SPKI length" (BS.length pub >= 280 && BS.length pub <= 310)
  assertBool "halves differ" (priv /= pub)
  assertEqual "priv framing" (BS.singleton 0x30) (BS.take 1 priv)
  assertEqual "pub framing" (BS.singleton 0x30) (BS.take 1 pub)
  -- Bounds mirror the key planner (bad params, never silent).
  expectBadParam "rsa-1024 refused" =<< generateKey env (GenRSA 1024 65537)
  expectBadParam "rsa even exponent refused" =<< generateKey env (GenRSA 2048 4)
  -- A non-palindromic exponent round-trips exactly: OSSL_PARAM
  -- BN import reads native-endian, and the stock 65537 masked a
  -- big-endian pass-through that minted mirrored exponents.
  (KeyDer _, Just (KeyDer pub3)) <- expectOk "rsa odd-e mints" =<<
    generateKey env (GenRSA 2048 65539)
  case rsaSpkiFields pub3 of
    Just (_, e3) -> assertEqual "minted exponent" (integerToBE 65539) e3
    Nothing -> assertFailure "rsa odd-e SPKI failed to parse"

-- | RFC 8439 section 2.4.2: key 00..1f, nonce
-- 000000000000004a00000000, initial counter 1, the 114-byte
-- Sunscreen plaintext. The counter rides the IV natively (4-byte
-- LE counter plus the 12-byte nonce, the exact IV layout
-- @EVP_chacha20@ takes).
caseChachaReal :: IO ()
caseChachaReal = withBackend $ \env -> do
  let key = KeyBytes (hex "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
      nonce = hex "000000000000004a00000000"
      pt = chachaSunscreen
      iv1 = hex "01000000" <> nonce
      ct = hex $ concat
        [ "6e2e359a2568f98041ba0728dd0d6981"
        , "e97e7aec1d4360c20a27afccfd9fae0b"
        , "f91b65c5524733ab8f593dabcd62b357"
        , "1639d624e65152ab8f530c359f0861d8"
        , "07ca0dbf500d6a6156a38e088a22b65e"
        , "52bc514d16ccf806818ce91ab7793736"
        , "5af90bbf74a35be6b40b8eedf2785e42"
        , "874d"
        ]
  got <- expectOk "rfc 2.4.2 encrypt" =<<
    cipherEncrypt env C_CHACHA20 key iv1 pt
  assertEqual "rfc 2.4.2 ct" ct got
  back <- expectOk "rfc 2.4.2 decrypt" =<<
    cipherDecrypt env C_CHACHA20 key iv1 got
  assertEqual "rfc 2.4.2 roundtrip" pt back
  -- Counter 0 differs (the framework's block-counter
  -- independence leg); unaligned input preserves length.
  let iv0 = hex "00000000" <> nonce
  got0 <- expectOk "counter 0 encrypt" =<<
    cipherEncrypt env C_CHACHA20 key iv0 pt
  assertBool "counters differentiate" (got0 /= got)
  ragged <- expectOk "unaligned encrypt" =<<
    cipherEncrypt env C_CHACHA20 key iv0 "twenty bytes exactly!!"
  assertEqual "length preserved" 22 (BS.length ragged)
  -- Bounds: key exactly 32, framing exactly 20.
  expectBadParam "short key" =<<
    cipherEncrypt env C_CHACHA20 (KeyBytes "short") iv0 pt
  expectBadParam "bare nonce" =<<
    cipherEncrypt env C_CHACHA20 key nonce pt

-- | RFC 8439 section 2.8.2: key 80..9f, nonce
-- 070000004041424344454647, the 12-byte AAD, the Sunscreen
-- plaintext, fixed 16-byte tag.
caseChachaPolyReal :: IO ()
caseChachaPolyReal = withBackend $ \env -> do
  let key = KeyBytes (hex "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
      nonce = hex "070000004041424344454647"
      aad = hex "50515253c0c1c2c3c4c5c6c7"
      pt = chachaSunscreen
      spec = AeadSpec "ChaCha20-Poly1305" 12 16
      ct = hex $ concat
        [ "d31a8d34648e60db7b86afbc53ef7ec2"
        , "a4aded51296e08fea9e2b5a736ee62d6"
        , "3dbea45e8ca9671282fafb69da92728b"
        , "1a71de0a9e060b2905d6a5b67ecd3b36"
        , "92ddbd7f2d778b8c9803aee328091b58"
        , "fab324e4fad675945585808b4831d7bc"
        , "3ff4def08e4b7a9de576d26586cec64b"
        , "6116"
        ]
      tag = hex "1ae10b594f09e26a7e902ecbd0600691"
  (got, gotTag) <- expectOk "rfc 2.8.2 seal" =<<
    aeadEncrypt env spec key nonce aad pt
  assertEqual "rfc 2.8.2 ct" ct got
  assertEqual "rfc 2.8.2 tag" tag gotTag
  back <- expectOk "rfc 2.8.2 open" =<<
    aeadDecrypt env spec key nonce aad got gotTag
  assertEqual "rfc 2.8.2 roundtrip" pt back
  -- Tampering anywhere fails closed.
  let badTag = BS.pack [BS.head gotTag `xor` 1] <> BS.tail gotTag
  expectAuthFailed "tag tamper" =<<
    aeadDecrypt env spec key nonce aad got badTag
  expectAuthFailed "aad tamper" =<<
    aeadDecrypt env spec key nonce "tampered-aad!" got gotTag
  -- Bounds: key exactly 32, tag exactly 16.
  expectBadParam "short key" =<<
    aeadEncrypt env spec (KeyBytes "short") nonce aad pt
  expectBadParam "short tag" =<<
    aeadEncrypt env (AeadSpec "ChaCha20-Poly1305" 12 8) key nonce aad pt

-- | The RFC 8439 Sunscreen plaintext (114 bytes).
chachaSunscreen :: ByteString
chachaSunscreen =
  "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."

caseRandomBytes :: IO ()
caseRandomBytes = withBackend $ \env -> do
  -- Fresh DRBG bytes every call; zero length is a bad param; the
  -- 1 MiB window serves exactly; past it refuses (no transparent
  -- chunking: unbounded requests amplify into OOM kills).
  r1 <- expectOk "random 32" =<< randomBytes env 32
  assertEqual "random length" 32 (BS.length r1)
  r2 <- expectOk "random 32 again" =<< randomBytes env 32
  assertBool "random fresh" (r1 /= r2)
  expectBadParam "random 0 refused" =<< randomBytes env 0
  full <- expectOk "random 1MiB" =<< randomBytes env generateRandomMaxBytes
  assertEqual "window length" generateRandomMaxBytes (BS.length full)
  expectBadParam "random 1MiB+1 refused" =<< randomBytes env (generateRandomMaxBytes + 1)

caseSeedRandomMix :: IO ()
caseSeedRandomMix = withBackend $ \env -> do
  -- Seeding mixes additional input (never replacing the DRBG
  -- state); post-seed randomBytes works normally, empty seeds are
  -- a vacuous OK, oversize seeds are refused.
  expectOk "seed ok" =<< seedRandom env "test-seed"
  r <- expectOk "random after seed" =<< randomBytes env 32
  assertEqual "random length" 32 (BS.length r)
  expectOk "empty seed ok" =<< seedRandom env BS.empty
  r2 <- expectOk "random after empty seed" =<< randomBytes env 32
  assertEqual "random length again" 32 (BS.length r2)
  expectBadParam "oversize seed refused"
    =<< seedRandom env (BS.replicate (seedRandomMaxBytes + 1) 0)

caseSeedEntropyHonesty :: IO ()
caseSeedEntropyHonesty = do
  -- The seed path never claims entropy it doesn't have. The
  -- 0.0 estimate lives in ONE named home in the shim, and the
  -- single RAND_add call site passes that name (never a literal,
  -- never RAND_seed). Mirrors the caseShimHygiene read-the-shim
  -- idiom (cwd-tolerant lookup included).
  src <- findShim ["cbits/ossl4_ctx.c", "../cbits/ossl4_ctx.c", "haskoki/cbits/ossl4_ctx.c"]
  assertEqual "single entropy-estimate home" 1
    (count "#define HSK_OSSL4_SEED_ENTROPY_ESTIMATE 0.0" src)
  let calls = filter ("RAND_add(" `isInfixOf`) (lines src)
  assertEqual "single RAND_add call site" 1 (length calls)
  case calls of
    [c] -> assertBool "call site passes the named estimate"
             ("HSK_OSSL4_SEED_ENTROPY_ESTIMATE" `isInfixOf` c)
    _ -> assertFailure ("expected one RAND_add call site, saw " ++ show (length calls))
  assertEqual "no RAND_seed anywhere" 0 (count "RAND_seed" src)
  where
    count needle hay = length (filter (hasPrefix needle) (tails hay))
    hasPrefix needle s = case stripPrefix needle s of
      Just _ -> True
      Nothing -> False
    findShim [] = assertFailure "cbits/ossl4_ctx.c not found from test cwd"
    findShim (p:ps) = do
      exists <- doesFileExist p
      if exists then readFile p else findShim ps

caseSeedNoReplay :: IO ()
caseSeedNoReplay = withBackend $ \env -> do
  -- Scope pin: the OpenSSL seed path mixes (RAND_add) and never
  -- replaces DRBG state, so identical reseeds do NOT replay --
  -- freshness is preserved across them. C-table determinism is
  -- therefore NOT asserted anywhere (the served C path is
  -- OpenSSL-typed end to end: siBackend :: BackendEnv OpenSSL4);
  -- the determinism contract lives in SyntheticSpec
  -- caseSeedRandomReplay.
  expectOk "seed S ok" =<< seedRandom env "scope-S"
  a <- expectOk "bytes after seed" =<< randomBytes env 32
  expectOk "reseed S ok" =<< seedRandom env "scope-S"
  b <- expectOk "bytes after reseed" =<< randomBytes env 32
  assertBool "reseed does not replay" (a /= b)

caseUnsupported :: IO ()
caseUnsupported = withBackend $ \env -> do
  -- Fixed-length digests are supported; XOF stays out.
  expectUnsupported "shake128 digest" =<< digestOneShot env D_SHAKE128 "abc"
  expectUnsupported "shake256 digest" =<< digestOneShot env D_SHAKE256 "abc"
  -- The 23-spec CBC/CTR/ECB set is supported (see
  -- caseCipherKats, which pins the CTR stream specs too).
  expectUnsupported "cmac" =<< macSign env (MacCMAC C_AES256_CBC) (KeyBytes hmacKey1) hmacMsg1
  -- In-range truncation is supported (see caseHmacGeneral);
  -- out-of-range lengths and XOFs stay out.
  expectUnsupported "zero-length hmac" =<< macSign env (MacHMAC D_SHA256 (Just 0)) (KeyBytes hmacKey1) hmacMsg1
  expectUnsupported "over-width hmac" =<< macSign env (MacHMAC D_SHA256 (Just 33)) (KeyBytes hmacKey1) hmacMsg1
  expectUnsupported "shake hmac" =<< macSign env (MacHMAC D_SHAKE128 Nothing) (KeyBytes hmacKey1) hmacMsg1
  -- OAEP is supported (see caseRsaOaepVectors); XOF
  -- hashes stay out.
  expectUnsupported "rsa oaep xof" =<< pkeyEncrypt env (mkOaep D_SHAKE128) (KeyDer ecPubDer) "x"
  -- ML-KEM is served (see caseMlkem); a foreign key under it
  -- refuses typed, never unsupported, never silent.
  expectBadKey "ml-kem encaps cross-key" =<< kemEncapsulate env (mkKem ML_KEM_768) (KeyDer ecPubDer)

caseGuardBeforeNative :: IO ()
caseGuardBeforeNative = do
  -- On a closed backend the capability guard still answers Unsupported
  -- (not a native crash): the check precedes any native call. Every
  -- cipher spec is served, so the cipher leg pins the closed check
  -- instead: a supported cipher answers InvalidState, never a crash.
  r <- openBackend "provider=default" :: IO (EngineResult (BackendEnv OpenSSL4))
  env <- case r of
    EngineFail err -> assertFailure ("openBackend failed: " ++ show err)
    EngineOk e -> pure e
  closeBackend env
  expectUnsupported "unsupported on closed backend" =<< digestOneShot env D_SHAKE128 "abc"
  closed <- cipherEncrypt env C_AES128_CTR (KeyBytes aes128Key) aes256Iv aes256Pt
  case closed of
    EngineFail (BackendInvalidState _ _) -> pure ()
    other -> assertFailure ("expected InvalidState, got: " ++ show other)

caseCaps :: IO ()
caseCaps = withBackend $ \env -> do
  caps <- queryCapabilities env
  assertEqual "backend name" "openssl4" (bcName caps)
  assertBool ("version pins 4.0.2, got " ++ bcVersion caps)
    ("4.0.2" `isInfixOf` bcVersion caps)
  assertEqual "digest set" (Set.fromList
    [ D_MD5, D_SHA1, D_SHA224, D_SHA256, D_SHA384, D_SHA512
    , D_SHA512_224, D_SHA512_256
    , D_SHA3_224, D_SHA3_256, D_SHA3_384, D_SHA3_512
    , D_RIPEMD160
    , D_BLAKE2B512
    , D_BLAKE2B160
    , D_BLAKE2B256
    , D_BLAKE2B384
    ]) (dcAlgs (bcDigests caps))
  assertEqual "cipher set" (Set.fromList
    [ C_AES128_CBC, C_AES192_CBC, C_AES256_CBC
    , C_AES128_CTR, C_AES192_CTR, C_AES256_CTR
    , C_AES128_ECB, C_AES192_ECB, C_AES256_ECB
    , C_AES128_CTS, C_AES192_CTS, C_AES256_CTS
    , C_AES128_CFB128, C_AES192_CFB128, C_AES256_CFB128
    , C_AES128_CFB8, C_AES192_CFB8, C_AES256_CFB8
    , C_AES128_CFB1, C_AES192_CFB1, C_AES256_CFB1
    , C_AES128_OFB, C_AES192_OFB, C_AES256_OFB
    , C_AES128_KW, C_AES192_KW, C_AES256_KW
    , C_AES128_KWP, C_AES192_KWP, C_AES256_KWP
    , C_AES128_XTS, C_AES256_XTS
    , C_DES3_CBC, C_DES3_ECB
    , C_ARIA128_CBC, C_ARIA192_CBC, C_ARIA256_CBC
    , C_ARIA128_ECB, C_ARIA192_ECB, C_ARIA256_ECB
    , C_CAMELLIA128_CBC, C_CAMELLIA192_CBC, C_CAMELLIA256_CBC
    , C_CAMELLIA128_ECB, C_CAMELLIA192_ECB, C_CAMELLIA256_ECB
    , C_CAMELLIA128_CTR, C_CAMELLIA192_CTR, C_CAMELLIA256_CTR
    , C_CHACHA20
    ]) (ccCiphers (bcCiphers caps))
  assertEqual "cipher set size" 50 (Set.size (ccCiphers (bcCiphers caps)))
  assertEqual "aead set" (Set.fromList
    [ "AES-128-GCM", "AES-192-GCM", "AES-256-GCM"
    , "AES-128-CCM", "AES-192-CCM", "AES-256-CCM"
    , "ChaCha20-Poly1305"
    ]) (ccAead (bcCiphers caps))
  assertEqual "mac set" (Set.fromList
    [ "HMAC-MD5", "HMAC-SHA1"
    , "HMAC-SHA224", "HMAC-SHA256", "HMAC-SHA384", "HMAC-SHA512"
    , "HMAC-SHA512-224", "HMAC-SHA512-256"
    , "HMAC-SHA3-224", "HMAC-SHA3-256", "HMAC-SHA3-384", "HMAC-SHA3-512"
    , "HMAC-RIPEMD160"
    , "HMAC-BLAKE2B-512"
    , "HMAC-BLAKE2B-160", "HMAC-BLAKE2B-256", "HMAC-BLAKE2B-384"
    , "HMAC-MD5-GENERAL", "HMAC-SHA1-GENERAL"
    , "HMAC-SHA224-GENERAL", "HMAC-SHA256-GENERAL"
    , "HMAC-SHA384-GENERAL", "HMAC-SHA512-GENERAL"
    , "HMAC-SHA512-224-GENERAL", "HMAC-SHA512-256-GENERAL"
    , "HMAC-SHA3-224-GENERAL", "HMAC-SHA3-256-GENERAL"
    , "HMAC-SHA3-384-GENERAL", "HMAC-SHA3-512-GENERAL"
    , "HMAC-RIPEMD160-GENERAL"
    , "HMAC-BLAKE2B-512-GENERAL"
    , "HMAC-BLAKE2B-160-GENERAL", "HMAC-BLAKE2B-256-GENERAL", "HMAC-BLAKE2B-384-GENERAL"
    , "POLY1305"
    ]) (mcSpecs (bcMacs caps))
  assertBool "ecdsa-p256-sha256 advertised"
    (Set.member "ECDSA-P-256-SHA256" (scSpecs (bcSigs caps)))
  -- The RSA v1.5 names join the signature set (probe-narrowed
  -- over the same probed digests as the digest set, so all 11 land).
  -- The ECDSA names (22 curves x 13 digests + 22 raw), generated
  -- over explicit dimensions so a dropped curve or digest fails.
  let dsaCurves =
        [ "P-256", "P-384", "P-521", "secp224r1", "secp224k1"
        , "secp256k1", "secp192r1", "secp192k1", "secp160r1"
        , "secp160r2", "secp160k1", "brainpoolP224r1"
        , "brainpoolP256r1", "brainpoolP320r1", "brainpoolP384r1"
        , "brainpoolP512r1", "sect283k1", "sect283r1", "sect409k1"
        , "sect409r1", "sect571k1", "sect571r1"
        ]
      dsaStems =
        [ "MD5", "SHA1", "SHA224", "SHA256", "SHA384", "SHA512"
        , "SHA512-224", "SHA512-256", "SHA3-224", "SHA3-256"
        , "SHA3-384", "SHA3-512", "RIPEMD160", "BLAKE2B-512"
        ]
      dsaNames =
        ["ECDSA-" ++ c ++ "-RAW" | c <- dsaCurves]
          ++ ["ECDSA-" ++ c ++ "-" ++ s | c <- dsaCurves, s <- dsaStems]
      fipsDsaNames =
        ["DSA-RAW"]
          ++ ["DSA-" ++ s | s <- fipsDsaStems]
      fipsDsaStems =
        [ "SHA1", "SHA224", "SHA256", "SHA384", "SHA512"
        , "SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512"
        ]
      eddsaNames = ["EDDSA-Ed25519", "EDDSA-Ed448"]
      mldsaNames = ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]
      slhdsaNames =
        [ "SLH-DSA-SHA2-128s", "SLH-DSA-SHA2-128f"
        , "SLH-DSA-SHA2-192s", "SLH-DSA-SHA2-192f"
        , "SLH-DSA-SHA2-256s", "SLH-DSA-SHA2-256f"
        , "SLH-DSA-SHAKE-128s", "SLH-DSA-SHAKE-128f"
        , "SLH-DSA-SHAKE-192s", "SLH-DSA-SHAKE-192f"
        , "SLH-DSA-SHAKE-256s", "SLH-DSA-SHAKE-256f"
        ]
  assertEqual "sig set" (Set.fromList
    ([ "RSA-PSS"
    , "RSA-RAW"
    , "RSA-X509"
    , "RSA-X931"
    , "RSA-PKCS1v15-MD5", "RSA-PKCS1v15-SHA1"
    , "RSA-PKCS1v15-SHA224", "RSA-PKCS1v15-SHA256"
    , "RSA-PKCS1v15-SHA384", "RSA-PKCS1v15-SHA512"
    , "RSA-PKCS1v15-SHA3-224", "RSA-PKCS1v15-SHA3-256"
    , "RSA-PKCS1v15-SHA3-384", "RSA-PKCS1v15-SHA3-512"
    , "RSA-PKCS1v15-RIPEMD160"
    ] ++ dsaNames ++ fipsDsaNames ++ eddsaNames ++ mldsaNames ++ slhdsaNames)) (scSpecs (bcSigs caps))
  assertEqual "curves" (Set.fromList dsaCurves) (scCurves (bcSigs caps))
  assertEqual "kem set" (Set.fromList [ML_KEM_512, ML_KEM_768, ML_KEM_1024]) (kcAlgs (bcKems caps))
  assertEqual "kdf set" (Set.fromList ["DH", "ECDH", "ECDH-COFACTOR"]) (kcKdfs (bcKdfs caps))

caseIsolation :: IO ()
caseIsolation = do
  r1 <- openBackend "provider=default" :: IO (EngineResult (BackendEnv OpenSSL4))
  r2 <- openBackend "provider=default" :: IO (EngineResult (BackendEnv OpenSSL4))
  (e1, e2) <- case (r1, r2) of
    (EngineOk a, EngineOk b) -> pure (a, b)
    _ -> assertFailure "could not open two backends"
  d1 <- expectOk "ctx1 digest" =<< digestOneShot e1 D_SHA256 "abc"
  closeBackend e1
  -- Closing one private context leaves the other fully usable.
  d2 <- expectOk "ctx2 digest after close" =<< digestOneShot e2 D_SHA256 "abc"
  assertEqual "same vector" d1 d2
  assertEqual "still correct" sha256Abc d2
  closeBackend e2

caseShimHygiene :: IO ()
caseShimHygiene = do
  src <- findShim ["cbits/ossl4_ctx.c", "../cbits/ossl4_ctx.c", "haskoki/cbits/ossl4_ctx.c"]
  let low = lower src
  -- A provider *string* (quoted literal or header include), not a prose
  -- mention in a comment, would load a token-backed provider.
  assertBool "no pkcs11 provider string in shim"
    (not ("\"pkcs11\"" `isInfixOf` low || "pkcs11.h" `isInfixOf` low))
  -- A *reference* (call or address-of), not a prose mention, would run
  -- process-global teardown.
  assertBool "no OPENSSL_cleanup reference in shim" (not (hasRef low "openssl_cleanup"))
  assertBool "no OPENSSL_atexit reference in shim" (not (hasRef low "openssl_atexit"))
  where
    lower = map (\c -> if c >= 'A' && c <= 'Z' then toEnum (fromEnum c + 32) else c)
    hasRef src name = any match (tails src)
      where
        match s = case stripPrefix name s of
          Just rest -> case dropWhile (== ' ') rest of
            ('(' : _) -> True
            _ -> False
          Nothing -> case s of
            ('&' : rest) -> case stripPrefix name (dropWhile (== ' ') rest) of
              Just _ -> True
              Nothing -> False
            _ -> False
    findShim [] = assertFailure "cbits/ossl4_ctx.c not found from test cwd"
    findShim (p:ps) = do
      exists <- doesFileExist p
      if exists then readFile p else findShim ps

caseInvalidInputs :: IO ()
caseInvalidInputs = withBackend $ \env -> do
  -- Garbage key DER is a typed BadKey, never a crash.
  let badKey = KeyDer "not-der-at-all"
      spec' = SigECDSA { sigEc = mkEc "P-256" "DER", sigEcDigest = Just D_SHA256 }
  r1 <- verify env spec' badKey ecMsg ecSigDer
  case r1 of
    EngineFail (BackendBadKey _ _) -> pure ()
    EngineFail (BackendBadParam _ _) -> pure ()
    other -> assertFailure ("garbage key must be BadKey/BadParam, got " ++ show other)
  -- Unknown multipart resource is ResourceGone.
  r2 <- digestFinal env (mkResId 0xdeadbeef)
  case r2 of
    EngineFail (BackendResourceGone _ _) -> pure ()
    other -> assertFailure ("unknown resource must be ResourceGone, got " ++ show other)
  -- Double-final is ResourceGone (final releases).
  rid <- expectOk "init" =<< digestInit env D_SHA256
  _ <- expectOk "final" =<< digestFinal env rid
  r3 <- digestFinal env rid
  case r3 of
    EngineFail (BackendResourceGone _ _) -> pure ()
    other -> assertFailure ("second final must be ResourceGone, got " ++ show other)

-- ---------------------------------------------------------------------------
-- Small constructors used above
-- ---------------------------------------------------------------------------

mkEc :: String -> String -> EcSpec
mkEc curve enc = EcSpec { ecCurve = curve, ecEncoding = enc }

mkOaep :: DigestAlg -> RsaCipherParams
mkOaep d = RsaOaep (OaepParams { oaepHash = d, oaepMgf = d, oaepLabel = BS.empty })

mkKem :: PqcKemAlg -> KemSpec
mkKem a = KemSpec { kemAlg = a }

mkResId :: Word32 -> EngineResourceId
mkResId = EngineResourceId
