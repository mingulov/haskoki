{- | Key-import coverage: RSA/EC component templates create objects
whose stored value is the PKCS#8/SPKI DER the engine consumes
(the same shape key generation stores), with the components kept
verbatim for reads.

Fixtures are pinned OpenSSL 4.0.2 vectors (an RSA-2048 key and a
P-256 key, generated once); the DER goldens are openssl-emitted
bytes, so golden equality is an independent cross-check of the
assembly, not self-agreement.
-}
{-# LANGUAGE OverloadedStrings #-}
module KeyImportSpec (spec) where

import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import qualified Data.ByteString.Char8 as BS8
import Data.Char (digitToInt, isHexDigit)
import qualified Data.Map.Strict as Map
import Data.Word (Word64)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit
  (assertBool, assertEqual, assertFailure, testCase)

import Haskoki.Attribute
  (AttributeResult (..), AttributeType (..), AttributeValue (..),
   PartialReads (..), decodeValue, getAttributes)
import Haskoki.Der (curveCoordLen, curveOidOfParams, dhPkcs8Fields, dhSpkiFields, dsaPkcs8Fields, dsaSpkiFields, eddsaPkcs8Fields, eddsaPrivateDer, eddsaPublicDer, eddsaSpkiFields, edwardsNameOfOid, edwardsOidOfParams, edwardsTable, edwardsWidthsOfParams, mldsaOidOfCkp, mldsaPkcs8Fields, mldsaPrivateDer, mldsaPublicDer, mldsaSpkiFields, mldsaTable, mldsaWidthsOfOid, mlkemEkWellFormed, mlkemOidOfCkp, mlkemPkcs8Fields, mlkemPrivateDer, mlkemPublicDer, mlkemSpkiFields, mlkemTable, mlkemWidthsOfOid, parseDsaParams, unwrapEcPoint, unwrapEdwardsPoint)
import Haskoki.Engine.Backend
  (CryptoBackend (..), DhSpec (..), DigestAlg (..), EcSpec (..),
   EngineResult (..), KemSpec (..), KeyMaterial (..), PqcKemAlg (..), PqcSigAlg (..), SigSpec (..))
import Haskoki.Engine.OpenSSL4 (OpenSSL4 (..))
import Haskoki.FFI.Standard (ecParamsFromWire, ecParamsToWire)
import Haskoki.Model
  (Model, ObjectState (..), SessionState, addToken, emptyModel,
   lookupSession)
import Haskoki.Object (decodeHandle, planCreateObject, planGetAttributes, resolveHandle)
import Haskoki.Operation.KeyManagement
  (ckoPrivateKey, ckoPublicKey, ckkDh, ckkDsa, ckkEc, ckkEcEdwards, ckkMlDsa, ckkMlKem, ckkRsa, ckkX9_42Dh)
import Haskoki.Outcome
  (DeltaOp (..), NativeOutput (..), PlanResult (..),
   PreparedCommit (..), Rejection (..), StateDelta (..))
import Haskoki.Transition (publishDelta)
import Haskoki.Types
  (ExternalHandle, ReturnCode (..), SessionId (..), SlotId (..))

spec :: TestTree
spec = testGroup "key import"
  [ testCase "RSA private import assembles PKCS#8" caseRsaPrivate
  , testCase "RSA public import assembles SPKI" caseRsaPublic
  , testCase "EC private import assembles PKCS#8" caseEcPrivate
  , testCase "EC public import assembles SPKI" caseEcPublic
  , testCase "DSA private import assembles PKCS#8" caseDsaPrivate
  , testCase "DSA public import assembles SPKI" caseDsaPublic
  , testCase "DSA DER readers parse openssl goldens" caseDsaDerReaders
  , testCase "DH private import assembles PKCS#8" caseDhPrivate
  , testCase "DH public import assembles SPKI" caseDhPublic
  , testCase "X9.42 DH import assembles both halves" caseDhX942
  , testCase "DH DER readers parse openssl goldens" caseDhDerReaders
  , testCase "partial DH import is incomplete" casePartialDh
  , testCase "PKCS#3 subprime refuses inconsistent" caseBadDhSubprime
  , testCase "public DH/DSA reads project the value" casePublicValueReads
  , testCase "imported DH key agrees through the real backend" caseDhExecutes
  , testCase "EdDSA assembly matches openssl goldens" caseEddsaDerGoldens
  , testCase "EdDSA DER readers parse openssl goldens" caseEddsaDerReaders
  , testCase "EdDSA private import assembles PKCS#8" caseEddsaPrivate
  , testCase "EdDSA public import assembles SPKI" caseEddsaPublic
  , testCase "partial EdDSA import is incomplete" casePartialEddsa
  , testCase "bad EdDSA value refuses inconsistent" caseBadEddsaValue
  , testCase "Edwards OID table agrees with the FFI" caseEdwardsTableAgreement
  , testCase "partial RSA import is incomplete" casePartialRsa
  , testCase "partial DSA import is incomplete" casePartialDsa
  , testCase "empty DSA component refuses inconsistent" caseBadDsaValue
  , testCase "foreign curve refuses CURVE_NOT_SUPPORTED" caseForeignCurve
  , testCase "malformed point refuses inconsistent" caseBadPoint
  , testCase "explicit value with components contradicts" caseValueConflict
  , testCase "private components seal with the payload" caseSealedComponents
  , testCase "curve OID table agrees with the FFI" caseCurveTableAgreement
  , testCase "imported EC key signs through the real backend" caseEcExecutes
  , testCase "imported RSA key signs through the real backend" caseRsaExecutes
  , testCase "imported DSA key signs through the real backend" caseDsaExecutes
  , testCase "ML-DSA assembly matches openssl-emitted SPKIs" caseMldsaDerGoldens
  , testCase "ML-DSA DER readers parse openssl halves" caseMldsaDerReaders
  , testCase "ML-DSA private import assembles flat PKCS#8" caseMldsaPrivate
  , testCase "ML-DSA public import assembles SPKI" caseMldsaPublic
  , testCase "partial ML-DSA import is incomplete" casePartialMldsa
  , testCase "bad ML-DSA value refuses inconsistent" caseBadMldsaValue
  , testCase "imported ML-DSA key signs through the real backend" caseMldsaExecutes
  , testCase "ML-KEM assembly matches openssl-emitted SPKIs" caseMlkemDerGoldens
  , testCase "ML-KEM DER readers parse openssl halves" caseMlkemDerReaders
  , testCase "ML-KEM private import stores raw dk, seed+dk assembles" caseMlkemPrivate
  , testCase "ML-KEM public import assembles SPKI" caseMlkemPublic
  , testCase "partial ML-KEM import is incomplete" casePartialMlkem
  , testCase "bad ML-KEM value refuses inconsistent" caseBadMlkemValue
  , testCase "non-canonical ML-KEM ek refuses value-invalid" caseMlkemModulus
  , testCase "imported ML-KEM keys encapsulate through the real backend" caseMlkemExecutes
  ]

slot0 :: SlotId
slot0 = SlotId 0

sid1 :: SessionId
sid1 = SessionId 1

-- | Decode a hex string (whitespace-tolerant).
hex :: String -> ByteString
hex s = BS.pack (go (filter isHexDigit s))
  where
    go [] = []
    go (a : b : rest) = fromIntegral (digitToInt a * 16 + digitToInt b) : go rest
    go [_] = error "hex: odd digit count"

seedModel :: IO Model
seedModel = do
  let m0 = addToken emptyModel slot0
  expectRight (publishDelta m0 (StateDelta [DeltaOpenSession sid1 slot0 False]))

getSession :: Model -> IO SessionState
getSession m = case lookupSession m sid1 of
  Nothing -> assertFailure "seed session missing" >> undefined
  Just st -> pure st

expectRight :: Show e => Either e a -> IO a
expectRight (Right a) = pure a
expectRight (Left e) = assertFailure ("expected Right, got: " ++ show e) >> undefined

-- | Answer effects against the real OpenSSL4 backend.
withRealEnv :: (BackendEnv OpenSSL4 -> IO a) -> IO a
withRealEnv action = do
  opened <- openBackend "provider=default" :: IO (EngineResult (BackendEnv OpenSSL4))
  case opened of
    EngineFail err -> assertFailure ("openssl4 open failed: " ++ show err) >> undefined
    EngineOk env -> do
      r <- action env
      closeBackend env
      pure r

-- | Create one object, publish it, and return the stored attributes.
doCreate :: Model -> SessionState -> [(AttributeType, AttributeValue)]
  -> IO (Model, ExternalHandle, Map.Map AttributeType AttributeValue)
doCreate m st tmpl = case planCreateObject m st tmpl of
  Immediate c -> do
    m' <- expectRight (publishDelta m (pcDelta c))
    h <- case pcOutputs c of
      [o] -> handleOf o
      _ -> assertFailure "create outputs arity" >> undefined
    case resolveHandle m' h of
      Nothing -> assertFailure "created object unresolvable" >> undefined
      Just ost -> pure (m', h, osAttrs ost)
  Reject rej -> assertFailure ("must create, got: " ++ show (rejCode rej)) >> undefined
  Execute _ _ -> assertFailure "create must not execute" >> undefined

handleOf :: NativeOutput -> IO ExternalHandle
handleOf o = case decodeHandle (outBytes o) of
  Just h -> pure h
  Nothing -> assertFailure "handle output undecodable" >> undefined

expectReject :: ReturnCode -> PlanResult -> IO ()
expectReject want res = case res of
  Reject rej -> assertEqual "reject code" want (rejCode rej)
  Immediate _ -> assertFailure "must reject, created"
  Execute _ _ -> assertFailure "must reject, executed"

rsaPrivTmpl :: [(AttributeType, AttributeValue)]
rsaPrivTmpl =
  [ (AttrClass, ValULong ckoPrivateKey)
  , (AttrKeyType, ValULong ckkRsa)
  , (AttrToken, ValBool False)
  , (AttrModulus, ValBytes rsaN)
  , (AttrPublicExponent, ValBytes rsaE)
  , (AttrPrivateExponent, ValBytes rsaD)
  , (AttrPrime1, ValBytes rsaP)
  , (AttrPrime2, ValBytes rsaQ)
  , (AttrExponent1, ValBytes rsaDp)
  , (AttrExponent2, ValBytes rsaDq)
  , (AttrCoefficient, ValBytes rsaQinv)
  ]

rsaPubTmpl :: [(AttributeType, AttributeValue)]
rsaPubTmpl =
  [ (AttrClass, ValULong ckoPublicKey)
  , (AttrKeyType, ValULong ckkRsa)
  , (AttrToken, ValBool False)
  , (AttrModulus, ValBytes rsaN)
  , (AttrPublicExponent, ValBytes rsaE)
  ]

ecParamsP256 :: ByteString
ecParamsP256 = hex "06082a8648ce3d030107"

ecPrivTmpl :: [(AttributeType, AttributeValue)]
ecPrivTmpl =
  [ (AttrClass, ValULong ckoPrivateKey)
  , (AttrKeyType, ValULong ckkEc)
  , (AttrToken, ValBool False)
  , (AttrEcParams, ValBytes ecParamsP256)
  , (AttrValue, ValBytes ecScalar)
  ]

ecPubTmpl :: [(AttributeType, AttributeValue)]
ecPubTmpl =
  [ (AttrClass, ValULong ckoPublicKey)
  , (AttrKeyType, ValULong ckkEc)
  , (AttrToken, ValBool False)
  , (AttrEcParams, ValBytes ecParamsP256)
  , (AttrEcPoint, ValBytes ecPointWrapped)
  ]

-- | DSA fixtures: a CLI-generated (2048,224) key (pinned
-- @openssl dsaparam/gendsa@); the DER goldens are openssl-emitted
-- bytes, so golden equality is an independent cross-check of the
-- assembly, not self-agreement.
dsaP :: ByteString
dsaP = hex $ concat
  ["887ba402e537402944fc0b99930fe8dc2cf648f063ca5c40e7d8679f3c584d93125abf9d8e21daba7f1b64c8ed6e11ace9bb"
  , "78ad66d71c71cdc2f3c0ea4341c174006c80f5833311dfd6dd7e902dc806ce1e470e9dfa4fb7581b744b9412c42948d9f5c9"
  , "8cd2a9b3dabb058a6eb9d4adaa11ebf79cc665acaea98729ff6bab6172db75ef22dc55a440f0f89c4a0d018756eb9077b6ba"
  , "d92500238caefe7bb42080a3f071340b8cf8c4ec8128dbad5352fec210030d649a172802d2f92763c02d051c97114d01562c"
  , "c82c8a40d5de28cab2e311a3e6842eaf990d3cb26096ed7a495b81e82472f770b0201a8aea0c27ecf5f6e711f2356f8f262d"
  , "71cf4c6f91fb"
  ]

dsaQ :: ByteString
dsaQ = hex "f9db1760fb0a352f4fed24e43fb2905f7156d7d425fb3a392468cc41"

dsaG :: ByteString
dsaG = hex $ concat
  ["122cdd506b17ee6999e5874f3426a4540ba2bed03c654b69149cad7cac01bbc0124f3881ea856b420eb5ec1d9d4a77b6c364"
  , "d00161d711a32bc8edcc900233dce8814a56758f6e7caba971e135b82d9b37a77e01cae0f7f38249578fec4f78dfaf64f372"
  , "dd3bbd64ca8448199b30fbf44551f2a13b48c2e9a890cb715d87ea7a8060cc8eb36afaa5b9cc89f7947b6345d482bff613b1"
  , "2cadf1cfa006b5694a6bb501ae76c9e759667a53f635757a5db97f50acf4447962b18ac91ce966ed96cf0d6b52c9d5eeb049"
  , "c634917cd450b24627ec12f2d8818f179b4df221d999e75e6835147abf4b0b68956b4db9d85fab096bdf9afac381c367ed0f"
  , "1143f0ea87c3"
  ]

dsaX :: ByteString
dsaX = hex "0017d4566d451940d21d58ac3059302cb8dabcdf2a80adaf36f21bd0"

dsaY :: ByteString
dsaY = hex $ concat
  ["60b8ba1b907936a778f3eb7027a6a6fdecc1ee0ae417fcec01aefbedb60e48bb4999e10d49efcb2db0ada5c429212c8b52f5"
  , "9ecf71982c619a573b42ad63a94dcce71166ee4a9575a0c9188311194f7207f5fb91ff89ac8b11a0b2119f6a0b67da8c5e07"
  , "3f0ad05da9c36a7b1bb7d731b91960d65e361c5e5d2d001d46586b54bbc40a3fa1d1a80db188b5b8deea97ac53e176972607"
  , "ecf8c4dd96a3ed2d7d2817b32ac62c3899470ae8e30412eef07098ab75be9269570d3dfb4bc9db68df75398aee11f2218bcf"
  , "7dca414048a25ac59f8df695e435d0fb0e4a327063fc86bada9db51cc7b1f176f35ce11a985ae2e5a7b2e61bb55af290866f"
  , "e2099f1050a9"
  ]

dsaP8Gold :: ByteString
dsaP8Gold = hex $ concat
  ["3082025b0201003082023506072a8648ce380401308202280282010100887ba402e537402944fc0b99930fe8dc2cf648f063"
  , "ca5c40e7d8679f3c584d93125abf9d8e21daba7f1b64c8ed6e11ace9bb78ad66d71c71cdc2f3c0ea4341c174006c80f58333"
  , "11dfd6dd7e902dc806ce1e470e9dfa4fb7581b744b9412c42948d9f5c98cd2a9b3dabb058a6eb9d4adaa11ebf79cc665acae"
  , "a98729ff6bab6172db75ef22dc55a440f0f89c4a0d018756eb9077b6bad92500238caefe7bb42080a3f071340b8cf8c4ec81"
  , "28dbad5352fec210030d649a172802d2f92763c02d051c97114d01562cc82c8a40d5de28cab2e311a3e6842eaf990d3cb260"
  , "96ed7a495b81e82472f770b0201a8aea0c27ecf5f6e711f2356f8f262d71cf4c6f91fb021d00f9db1760fb0a352f4fed24e4"
  , "3fb2905f7156d7d425fb3a392468cc4102820100122cdd506b17ee6999e5874f3426a4540ba2bed03c654b69149cad7cac01"
  , "bbc0124f3881ea856b420eb5ec1d9d4a77b6c364d00161d711a32bc8edcc900233dce8814a56758f6e7caba971e135b82d9b"
  , "37a77e01cae0f7f38249578fec4f78dfaf64f372dd3bbd64ca8448199b30fbf44551f2a13b48c2e9a890cb715d87ea7a8060"
  , "cc8eb36afaa5b9cc89f7947b6345d482bff613b12cadf1cfa006b5694a6bb501ae76c9e759667a53f635757a5db97f50acf4"
  , "447962b18ac91ce966ed96cf0d6b52c9d5eeb049c634917cd450b24627ec12f2d8818f179b4df221d999e75e6835147abf4b"
  , "0b68956b4db9d85fab096bdf9afac381c367ed0f1143f0ea87c3041d021b17d4566d451940d21d58ac3059302cb8dabcdf2a"
  , "80adaf36f21bd0"
  ]

dsaSpkiGold :: ByteString
dsaSpkiGold = hex $ concat
  ["308203423082023506072a8648ce380401308202280282010100887ba402e537402944fc0b99930fe8dc2cf648f063ca5c40"
  , "e7d8679f3c584d93125abf9d8e21daba7f1b64c8ed6e11ace9bb78ad66d71c71cdc2f3c0ea4341c174006c80f5833311dfd6"
  , "dd7e902dc806ce1e470e9dfa4fb7581b744b9412c42948d9f5c98cd2a9b3dabb058a6eb9d4adaa11ebf79cc665acaea98729"
  , "ff6bab6172db75ef22dc55a440f0f89c4a0d018756eb9077b6bad92500238caefe7bb42080a3f071340b8cf8c4ec8128dbad"
  , "5352fec210030d649a172802d2f92763c02d051c97114d01562cc82c8a40d5de28cab2e311a3e6842eaf990d3cb26096ed7a"
  , "495b81e82472f770b0201a8aea0c27ecf5f6e711f2356f8f262d71cf4c6f91fb021d00f9db1760fb0a352f4fed24e43fb290"
  , "5f7156d7d425fb3a392468cc4102820100122cdd506b17ee6999e5874f3426a4540ba2bed03c654b69149cad7cac01bbc012"
  , "4f3881ea856b420eb5ec1d9d4a77b6c364d00161d711a32bc8edcc900233dce8814a56758f6e7caba971e135b82d9b37a77e"
  , "01cae0f7f38249578fec4f78dfaf64f372dd3bbd64ca8448199b30fbf44551f2a13b48c2e9a890cb715d87ea7a8060cc8eb3"
  , "6afaa5b9cc89f7947b6345d482bff613b12cadf1cfa006b5694a6bb501ae76c9e759667a53f635757a5db97f50acf4447962"
  , "b18ac91ce966ed96cf0d6b52c9d5eeb049c634917cd450b24627ec12f2d8818f179b4df221d999e75e6835147abf4b0b6895"
  , "6b4db9d85fab096bdf9afac381c367ed0f1143f0ea87c303820105000282010060b8ba1b907936a778f3eb7027a6a6fdecc1"
  , "ee0ae417fcec01aefbedb60e48bb4999e10d49efcb2db0ada5c429212c8b52f59ecf71982c619a573b42ad63a94dcce71166"
  , "ee4a9575a0c9188311194f7207f5fb91ff89ac8b11a0b2119f6a0b67da8c5e073f0ad05da9c36a7b1bb7d731b91960d65e36"
  , "1c5e5d2d001d46586b54bbc40a3fa1d1a80db188b5b8deea97ac53e176972607ecf8c4dd96a3ed2d7d2817b32ac62c389947"
  , "0ae8e30412eef07098ab75be9269570d3dfb4bc9db68df75398aee11f2218bcf7dca414048a25ac59f8df695e435d0fb0e4a"
  , "327063fc86bada9db51cc7b1f176f35ce11a985ae2e5a7b2e61bb55af290866fe2099f1050a9"
  ]

dsaPrivTmpl :: [(AttributeType, AttributeValue)]
dsaPrivTmpl =
  [ (AttrClass, ValULong ckoPrivateKey)
  , (AttrKeyType, ValULong ckkDsa)
  , (AttrToken, ValBool False)
  , (AttrPrime, ValBytes dsaP)
  , (AttrSubprime, ValBytes dsaQ)
  , (AttrBase, ValBytes dsaG)
  , (AttrValue, ValBytes dsaX)
  ]

dsaPubTmpl :: [(AttributeType, AttributeValue)]
dsaPubTmpl =
  [ (AttrClass, ValULong ckoPublicKey)
  , (AttrKeyType, ValULong ckkDsa)
  , (AttrToken, ValBool False)
  , (AttrPrime, ValBytes dsaP)
  , (AttrSubprime, ValBytes dsaQ)
  , (AttrBase, ValBytes dsaG)
  , (AttrValue, ValBytes dsaY)
  ]

-- | DH fixtures: one shim-minted 1024-bit PKCS#3 pair plus one
-- X9.42 pair (openssl-emitted DER goldens, so golden equality is
-- an independent cross-check of the assembly, not self-agreement).
dhP :: ByteString
dhP = hex $ concat
  [ "ce7843fa444ba3e33dd4b2b08ab55fab98da8169a4fa0a685aec06862189bf58"
  , "baf06dab132fe922953c8f86ed63595b3db745ddbc4a8a68669cdc3c4711ec67"
  , "6a99de245bf5edd6a2367727e84f36a8defc2bc7b932e6619786b8853647aeb4"
  , "f8bf6d2e4fee84be8e0a0ce60dfe6316b5e58c155cc85e3c7c2b78bf96f06e37"
  ]

dhG :: ByteString
dhG = hex "02"

dhY :: ByteString
dhY = hex $ concat
  [ "923db54b4889a8d61bf61df12e01179a81c035baf29061008e924b2268b71096"
  , "f80c8df6a4f4defcf7eaf635f105531c8cae13c3581738f1f157d08069251d2a"
  , "14ab389dec1a1dd32e6c46960ffbcef653c48b3181b0b060e7beaec98c7952a0"
  , "e35e2481495ba65ddf617aa262a4a4fcb2d07fd8a260f7c83b4b59968843db1b"
  ]

dhX :: ByteString
dhX = hex $ concat
  [ "287b9f838bd97cca9580063359a16b18465c5cee4a09d49ba9d619d10c00d109"
  , "d97fb09afaf33ec36948c8904730472aa91fbdb4c70ea232f1eaad9d5e67c4f5"
  , "1920efc410bb73aa547494ee24b5151d1f736edaa4c7a10807d15d5125b7c7c9"
  , "f625883a981b9e1b4ce47e92039646b5f70bccafcde06564c3fa58ac400f950f"
  ]

dhSpkiGold :: ByteString
dhSpkiGold = hex $ concat
  [ "3082012030819506092a864886f70d01030130818702818100ce7843fa444ba3"
  , "e33dd4b2b08ab55fab98da8169a4fa0a685aec06862189bf58baf06dab132fe9"
  , "22953c8f86ed63595b3db745ddbc4a8a68669cdc3c4711ec676a99de245bf5ed"
  , "d6a2367727e84f36a8defc2bc7b932e6619786b8853647aeb4f8bf6d2e4fee84"
  , "be8e0a0ce60dfe6316b5e58c155cc85e3c7c2b78bf96f06e3702010203818500"
  , "02818100923db54b4889a8d61bf61df12e01179a81c035baf29061008e924b22"
  , "68b71096f80c8df6a4f4defcf7eaf635f105531c8cae13c3581738f1f157d080"
  , "69251d2a14ab389dec1a1dd32e6c46960ffbcef653c48b3181b0b060e7beaec9"
  , "8c7952a0e35e2481495ba65ddf617aa262a4a4fcb2d07fd8a260f7c83b4b5996"
  , "8843db1b"
  ]

dhP8Gold :: ByteString
dhP8Gold = hex $ concat
  [ "3082012102010030819506092a864886f70d01030130818702818100ce7843fa"
  , "444ba3e33dd4b2b08ab55fab98da8169a4fa0a685aec06862189bf58baf06dab"
  , "132fe922953c8f86ed63595b3db745ddbc4a8a68669cdc3c4711ec676a99de24"
  , "5bf5edd6a2367727e84f36a8defc2bc7b932e6619786b8853647aeb4f8bf6d2e"
  , "4fee84be8e0a0ce60dfe6316b5e58c155cc85e3c7c2b78bf96f06e3702010204"
  , "8183028180287b9f838bd97cca9580063359a16b18465c5cee4a09d49ba9d619"
  , "d10c00d109d97fb09afaf33ec36948c8904730472aa91fbdb4c70ea232f1eaad"
  , "9d5e67c4f51920efc410bb73aa547494ee24b5151d1f736edaa4c7a10807d15d"
  , "5125b7c7c9f625883a981b9e1b4ce47e92039646b5f70bccafcde06564c3fa58"
  , "ac400f950f"
  ]

-- | Self-agreement KAT for the golden pair (pow dhY dhX dhP,
-- computed independently in Python).
dhSelfGold :: ByteString
dhSelfGold = hex $ concat
  [ "94e0da51ab4315a6904aca2317a288abb9e3905328f4dea72f901a6a7b04ab66"
  , "b51e4a9ca1a460a800be3a811a8607d851e578dab29f6ce6af9bc1e8aa075e0f"
  , "373d322fa5d73e5f95f83b8ab6e5d3b5a3e107179dc2774f2424b044767af5e1"
  , "36cb3216ba5e4f072fd146aea7eabaccb9db57d943ed677c36c2b8b43d4258d9"
  ]

dhQP :: ByteString
dhQP = hex $ concat
  [ "ddc17b058e1ec15b51996f85eae0b678ea9bb72444159fe2fcd0f44f7be7e737"
  , "eeebe94c47e751bcd826c53960d7e1af0f0f421f4f31104d07b13af401ed7656"
  , "7b31d2ebf1eaac37c626698e60dff128c671f9055600740581508c100814444f"
  , "fa21fada6af011260c1bc070a3d58f9a098607d92a938eff5a16fdc388e41e09"
  ]

dhQG :: ByteString
dhQG = hex $ concat
  [ "d1a4428b2e04060534ad2a284a7039276bf6306a88bfde2d92332a824da21782"
  , "e30b3642625f08ca00c5997626d6733d00eafcc206afbbdafb0086ddf1d06d48"
  , "87ff77e549937bdde181e6955cec0b29e710168d891687515c1ad3e03eee3f60"
  , "f96a9063d540b7907cdb24b99dfd490e3cc447be9d47cdefde5aa30c857a9cfa"
  ]

dhQQ :: ByteString
dhQQ = hex "fcbd52881b3c3975a661ce18c867832617b49b0dc2c467c10c264a67"

dhQY :: ByteString
dhQY = hex $ concat
  [ "368c5da062e25de6b141f5dbebb9c92e89245d9450fcd298342cc5c19d605615"
  , "5f5cee5b15d9d06828cbf6b1c67229c5264c32ce9db210e4453ee989ef2adf16"
  , "a5c447d1b565a18eb79d815f0c13da8bf4f9b2f7771d1ffd7a2212ff577a07fc"
  , "8f9b14759cc55e85dcc9c824aec6bf1b05edb5bb8eb4fb6e966fee1d35f0c075"
  ]

dhQX :: ByteString
dhQX = hex "0d6273388a45982a65d5e8231c0f0bd12a410d2594fac66990f81a15"

dhQSpkiGold :: ByteString
dhQSpkiGold = hex $ concat
  [ "308201bf3082013406072a8648ce3e02013082012702818100ddc17b058e1ec1"
  , "5b51996f85eae0b678ea9bb72444159fe2fcd0f44f7be7e737eeebe94c47e751"
  , "bcd826c53960d7e1af0f0f421f4f31104d07b13af401ed76567b31d2ebf1eaac"
  , "37c626698e60dff128c671f9055600740581508c100814444ffa21fada6af011"
  , "260c1bc070a3d58f9a098607d92a938eff5a16fdc388e41e0902818100d1a442"
  , "8b2e04060534ad2a284a7039276bf6306a88bfde2d92332a824da21782e30b36"
  , "42625f08ca00c5997626d6733d00eafcc206afbbdafb0086ddf1d06d4887ff77"
  , "e549937bdde181e6955cec0b29e710168d891687515c1ad3e03eee3f60f96a90"
  , "63d540b7907cdb24b99dfd490e3cc447be9d47cdefde5aa30c857a9cfa021d00"
  , "fcbd52881b3c3975a661ce18c867832617b49b0dc2c467c10c264a6703818400"
  , "028180368c5da062e25de6b141f5dbebb9c92e89245d9450fcd298342cc5c19d"
  , "6056155f5cee5b15d9d06828cbf6b1c67229c5264c32ce9db210e4453ee989ef"
  , "2adf16a5c447d1b565a18eb79d815f0c13da8bf4f9b2f7771d1ffd7a2212ff57"
  , "7a07fc8f9b14759cc55e85dcc9c824aec6bf1b05edb5bb8eb4fb6e966fee1d35"
  , "f0c075"
  ]

dhQP8Gold :: ByteString
dhQP8Gold = hex $ concat
  [ "3082015b0201003082013406072a8648ce3e02013082012702818100ddc17b05"
  , "8e1ec15b51996f85eae0b678ea9bb72444159fe2fcd0f44f7be7e737eeebe94c"
  , "47e751bcd826c53960d7e1af0f0f421f4f31104d07b13af401ed76567b31d2eb"
  , "f1eaac37c626698e60dff128c671f9055600740581508c100814444ffa21fada"
  , "6af011260c1bc070a3d58f9a098607d92a938eff5a16fdc388e41e0902818100"
  , "d1a4428b2e04060534ad2a284a7039276bf6306a88bfde2d92332a824da21782"
  , "e30b3642625f08ca00c5997626d6733d00eafcc206afbbdafb0086ddf1d06d48"
  , "87ff77e549937bdde181e6955cec0b29e710168d891687515c1ad3e03eee3f60"
  , "f96a9063d540b7907cdb24b99dfd490e3cc447be9d47cdefde5aa30c857a9cfa"
  , "021d00fcbd52881b3c3975a661ce18c867832617b49b0dc2c467c10c264a6704"
  , "1e021c0d6273388a45982a65d5e8231c0f0bd12a410d2594fac66990f81a15"
  ]

dhPrivTmpl :: [(AttributeType, AttributeValue)]
dhPrivTmpl =
  [ (AttrClass, ValULong ckoPrivateKey)
  , (AttrKeyType, ValULong ckkDh)
  , (AttrToken, ValBool False)
  , (AttrPrime, ValBytes dhP)
  , (AttrBase, ValBytes dhG)
  , (AttrValue, ValBytes dhX)
  ]

dhPubTmpl :: [(AttributeType, AttributeValue)]
dhPubTmpl =
  [ (AttrClass, ValULong ckoPublicKey)
  , (AttrKeyType, ValULong ckkDh)
  , (AttrToken, ValBool False)
  , (AttrPrime, ValBytes dhP)
  , (AttrBase, ValBytes dhG)
  , (AttrValue, ValBytes dhY)
  ]

dhX942PrivTmpl :: [(AttributeType, AttributeValue)]
dhX942PrivTmpl =
  [ (AttrClass, ValULong ckoPrivateKey)
  , (AttrKeyType, ValULong ckkX9_42Dh)
  , (AttrToken, ValBool False)
  , (AttrPrime, ValBytes dhQP)
  , (AttrSubprime, ValBytes dhQQ)
  , (AttrBase, ValBytes dhQG)
  , (AttrValue, ValBytes dhQX)
  ]

dhX942PubTmpl :: [(AttributeType, AttributeValue)]
dhX942PubTmpl =
  [ (AttrClass, ValULong ckoPublicKey)
  , (AttrKeyType, ValULong ckkX9_42Dh)
  , (AttrToken, ValBool False)
  , (AttrPrime, ValBytes dhQP)
  , (AttrSubprime, ValBytes dhQQ)
  , (AttrBase, ValBytes dhQG)
  , (AttrValue, ValBytes dhQY)
  ]

storedValue :: Map.Map AttributeType AttributeValue -> IO ByteString
storedValue attrs = case Map.lookup AttrValue attrs of
  Just (ValBytes bs) -> pure bs
  _ -> assertFailure "stored value missing" >> undefined

caseRsaPrivate :: IO ()
caseRsaPrivate = do
  m0 <- seedModel
  st <- getSession m0
  (_, _, attrs) <- doCreate m0 st rsaPrivTmpl
  der <- storedValue attrs
  assertEqual "PKCS#8 golden" rsaP8Gold der
  assertEqual "modulus kept" (Just (ValBytes rsaN)) (Map.lookup AttrModulus attrs)
  assertEqual "coefficient kept" (Just (ValBytes rsaQinv)) (Map.lookup AttrCoefficient attrs)

caseRsaPublic :: IO ()
caseRsaPublic = do
  m0 <- seedModel
  st <- getSession m0
  (_, _, attrs) <- doCreate m0 st rsaPubTmpl
  der <- storedValue attrs
  assertEqual "SPKI golden" rsaSpkiGold der

caseEcPrivate :: IO ()
caseEcPrivate = do
  m0 <- seedModel
  st <- getSession m0
  (_, _, attrs) <- doCreate m0 st ecPrivTmpl
  der <- storedValue attrs
  assertEqual "no-pub PKCS#8 golden" ecP8NoPubGold der

caseEcPublic :: IO ()
caseEcPublic = do
  m0 <- seedModel
  st <- getSession m0
  (_, _, attrs) <- doCreate m0 st ecPubTmpl
  der <- storedValue attrs
  assertEqual "SPKI golden" ecSpkiGold der
  assertEqual "point kept" (Just (ValBytes ecPointWrapped)) (Map.lookup AttrEcPoint attrs)

caseDsaPrivate :: IO ()
caseDsaPrivate = do
  m0 <- seedModel
  st <- getSession m0
  (_, _, attrs) <- doCreate m0 st dsaPrivTmpl
  der <- storedValue attrs
  assertEqual "PKCS#8 golden" dsaP8Gold der
  assertEqual "prime kept" (Just (ValBytes dsaP)) (Map.lookup AttrPrime attrs)
  assertEqual "subprime kept" (Just (ValBytes dsaQ)) (Map.lookup AttrSubprime attrs)
  assertEqual "base kept" (Just (ValBytes dsaG)) (Map.lookup AttrBase attrs)

caseDsaPublic :: IO ()
caseDsaPublic = do
  m0 <- seedModel
  st <- getSession m0
  (_, _, attrs) <- doCreate m0 st dsaPubTmpl
  der <- storedValue attrs
  assertEqual "SPKI golden" dsaSpkiGold der
  assertEqual "prime kept" (Just (ValBytes dsaP)) (Map.lookup AttrPrime attrs)
  assertEqual "subprime kept" (Just (ValBytes dsaQ)) (Map.lookup AttrSubprime attrs)
  assertEqual "base kept" (Just (ValBytes dsaG)) (Map.lookup AttrBase attrs)

caseDhPrivate :: IO ()
caseDhPrivate = do
  m0 <- seedModel
  st <- getSession m0
  (_, _, attrs) <- doCreate m0 st dhPrivTmpl
  der <- storedValue attrs
  assertEqual "PKCS#8 golden" dhP8Gold der
  assertEqual "prime kept" (Just (ValBytes dhP)) (Map.lookup AttrPrime attrs)
  assertEqual "base kept" (Just (ValBytes dhG)) (Map.lookup AttrBase attrs)

caseDhPublic :: IO ()
caseDhPublic = do
  m0 <- seedModel
  st <- getSession m0
  (_, _, attrs) <- doCreate m0 st dhPubTmpl
  der <- storedValue attrs
  assertEqual "SPKI golden" dhSpkiGold der
  assertEqual "prime kept" (Just (ValBytes dhP)) (Map.lookup AttrPrime attrs)
  assertEqual "base kept" (Just (ValBytes dhG)) (Map.lookup AttrBase attrs)

caseDhX942 :: IO ()
caseDhX942 = do
  m0 <- seedModel
  st <- getSession m0
  (_, _, privAttrs) <- doCreate m0 st dhX942PrivTmpl
  privDer <- storedValue privAttrs
  assertEqual "X9.42 PKCS#8 golden" dhQP8Gold privDer
  (m1, _, _) <- doCreate m0 st dhX942PrivTmpl
  (_, _, pubAttrs) <- doCreate m1 st dhX942PubTmpl
  pubDer <- storedValue pubAttrs
  assertEqual "X9.42 SPKI golden" dhQSpkiGold pubDer
  assertEqual "subprime kept" (Just (ValBytes dhQQ)) (Map.lookup AttrSubprime pubAttrs)

caseDhDerReaders :: IO ()
caseDhDerReaders = do
  case dhSpkiFields dhSpkiGold of
    Just (p, g, q, y) -> do
      assertEqual "spki p" dhP p
      assertEqual "spki g" dhG g
      assertEqual "spki q" Nothing q
      assertEqual "spki y" dhY y
    Nothing -> assertFailure "SPKI golden failed to parse"
  case dhPkcs8Fields dhP8Gold of
    Just (p, g, q, x) -> do
      assertEqual "p8 p" dhP p
      assertEqual "p8 g" dhG g
      assertEqual "p8 q" Nothing q
      assertEqual "p8 x" dhX x
    Nothing -> assertFailure "PKCS#8 golden failed to parse"
  case dhSpkiFields dhQSpkiGold of
    Just (p, g, q, y) -> do
      assertEqual "x942 spki p" dhQP p
      assertEqual "x942 spki g" dhQG g
      assertEqual "x942 spki q" (Just dhQQ) q
      assertEqual "x942 spki y" dhQY y
    Nothing -> assertFailure "X9.42 SPKI golden failed to parse"
  case dhPkcs8Fields dhQP8Gold of
    Just (p, g, q, x) -> do
      assertEqual "x942 p8 p" dhQP p
      assertEqual "x942 p8 g" dhQG g
      assertEqual "x942 p8 q" (Just dhQQ) q
      assertEqual "x942 p8 x" dhQX x
    Nothing -> assertFailure "X9.42 PKCS#8 golden failed to parse"

casePartialDh :: IO ()
casePartialDh = do
  m0 <- seedModel
  st <- getSession m0
  let noG = filter ((/= AttrBase) . fst) dhPrivTmpl
  expectReject CKR_TEMPLATE_INCOMPLETE (planCreateObject m0 st noG)
  let noY = filter ((/= AttrValue) . fst) dhPubTmpl
  expectReject CKR_TEMPLATE_INCOMPLETE (planCreateObject m0 st noY)
  let noQ = filter ((/= AttrSubprime) . fst) dhX942PubTmpl
  expectReject CKR_TEMPLATE_INCOMPLETE (planCreateObject m0 st noQ)

caseBadDhSubprime :: IO ()
caseBadDhSubprime = do
  m0 <- seedModel
  st <- getSession m0
  let withQ = dhPubTmpl ++ [(AttrSubprime, ValBytes dhQQ)]
  expectReject CKR_TEMPLATE_INCONSISTENT (planCreateObject m0 st withQ)

casePublicValueReads :: IO ()
casePublicValueReads = do
  m0 <- seedModel
  st <- getSession m0
  let readValue m h = case planGetAttributes m st h [AttrValue] of
        Immediate c -> case pcOutputs c of
          [o] -> pure (decodeValue AttrValue (outBytes o))
          _ -> assertFailure "read outputs arity" >> undefined
        Reject rej -> assertFailure ("read rejected: " ++ show (rejCode rej)) >> undefined
        Execute _ _ -> assertFailure "read must not execute" >> undefined
  (m1, hDh, _) <- doCreate m0 st dhPubTmpl
  vDh <- readValue m1 hDh
  assertEqual "DH pub reads y" (Just (ValBytes dhY)) vDh
  (m2, hDsa, _) <- doCreate m1 st dsaPubTmpl
  vDsa <- readValue m2 hDsa
  assertEqual "DSA pub reads y" (Just (ValBytes dsaY)) vDsa
  (m3, hPriv, _) <- doCreate m2 st dhPrivTmpl
  vPriv <- readValue m3 hPriv
  assertEqual "DH priv reads DER" (Just (ValBytes dhP8Gold)) vPriv

caseDhExecutes :: IO ()
caseDhExecutes = withRealEnv $ \env -> do
  m0 <- seedModel
  st <- getSession m0
  (m1, _, privAttrs) <- doCreate m0 st dhPrivTmpl
  privDer <- storedValue privAttrs
  (_, _, pubAttrs) <- doCreate m1 st dhPubTmpl
  pubDer <- storedValue pubAttrs
  y <- case dhSpkiFields pubDer of
    Just (_, _, _, y') -> pure y'
    Nothing -> assertFailure "imported SPKI failed to parse" >> undefined
  rres <- dhDerive env DhPlain (KeyDer privDer) (KeyDer y)
  case rres of
    EngineOk s -> assertEqual "self-agreement KAT" dhSelfGold s
    EngineFail err -> assertFailure ("imported DH agree failed: " ++ show err)

-- | Edwards fixtures: CLI-generated Ed25519/Ed448 keys (pinned
-- @openssl genpkey@); the DER goldens are openssl-emitted bytes,
-- so golden equality is an independent cross-check of the
-- assembly, not self-agreement.
ed19Oid :: ByteString
ed19Oid = hex "06032b6570"

ed19Point :: ByteString
ed19Point = hex $ concat
  ["e3066819aa9f7d91c3c4ebad5584adeef588d8a1cbf2a09a8081d41cc5183402"
  ]

ed19Seed :: ByteString
ed19Seed = hex $ concat
  ["e48c12f6fd3bd16c24e972eab3910d1053a23f9db0113d10d0835223f638dd05"
  ]

ed19SpkiGold :: ByteString
ed19SpkiGold = hex $ concat
  ["302a300506032b6570032100e3066819aa9f7d91c3c4ebad5584adeef588d8a1cbf2a09a8081d41cc5183402"
  ]

ed19P8Gold :: ByteString
ed19P8Gold = hex $ concat
  ["302e020100300506032b657004220420e48c12f6fd3bd16c24e972eab3910d1053a23f9db0113d10d0835223f638dd05"
  ]

ed48Oid :: ByteString
ed48Oid = hex "06032b6571"

ed48Point :: ByteString
ed48Point = hex $ concat
  ["86328bf04c3d241a0f05968cee630c68cdd2e2378a2f63e01ec215a661c7f83dddfddc788c1102a2529c68b8d3c0155e"
  ,"c9e263561e2545d280"
  ]

ed48Seed :: ByteString
ed48Seed = hex $ concat
  ["8217a8d0ea3724199e10d866da9b2f582ce7c9a8aa37ad7763df96d48c210c1c3ef3fe87ad7ce40306f70747dfee39a7"
  ,"99cd1a0ecb1481f9e1"
  ]

ed48SpkiGold :: ByteString
ed48SpkiGold = hex $ concat
  ["3043300506032b6571033a0086328bf04c3d241a0f05968cee630c68cdd2e2378a2f63e01ec215a661c7f83dddfddc78"
  ,"8c1102a2529c68b8d3c0155ec9e263561e2545d280"
  ]

ed48P8Gold :: ByteString
ed48P8Gold = hex $ concat
  ["3047020100300506032b6571043b04398217a8d0ea3724199e10d866da9b2f582ce7c9a8aa37ad7763df96d48c210c1c"
  ,"3ef3fe87ad7ce40306f70747dfee39a799cd1a0ecb1481f9e1"
  ]

eddsaPrivTmpl :: [(AttributeType, AttributeValue)]
eddsaPrivTmpl =
  [ (AttrClass, ValULong ckoPrivateKey)
  , (AttrKeyType, ValULong ckkEcEdwards)
  , (AttrToken, ValBool False)
  , (AttrEcParams, ValBytes ed19Oid)
  , (AttrValue, ValBytes ed19Seed)
  ]

eddsaPubTmpl :: [(AttributeType, AttributeValue)]
eddsaPubTmpl =
  [ (AttrClass, ValULong ckoPublicKey)
  , (AttrKeyType, ValULong ckkEcEdwards)
  , (AttrToken, ValBool False)
  , (AttrEcParams, ValBytes ed19Oid)
  , (AttrEcPoint, ValBytes ed19Point)
  ]

caseEddsaDerGoldens :: IO ()
caseEddsaDerGoldens = do
  assertEqual "Ed25519 SPKI golden" ed19SpkiGold
    (eddsaPublicDer ed19Oid ed19Point)
  assertEqual "Ed448 SPKI golden" ed48SpkiGold
    (eddsaPublicDer ed48Oid ed48Point)
  assertEqual "Ed25519 PKCS#8 golden" ed19P8Gold
    (eddsaPrivateDer ed19Oid ed19Seed)
  assertEqual "Ed448 PKCS#8 golden" ed48P8Gold
    (eddsaPrivateDer ed48Oid ed48Seed)
  assertEqual "table rows" [("Ed25519", ed19Oid, 32, 64), ("Ed448", ed48Oid, 57, 114)]
    edwardsTable
  assertEqual "Ed25519 widths" (Just (32, 64)) (edwardsWidthsOfParams ed19Oid)
  assertEqual "Ed448 widths" (Just (57, 114)) (edwardsWidthsOfParams ed48Oid)
  assertEqual "P-256 has no Edwards widths" Nothing
    (edwardsWidthsOfParams (hex "06082a8648ce3d030107"))
  assertEqual "garbage has no Edwards widths" Nothing
    (edwardsWidthsOfParams "nope")
  -- Point unwrap: raw RFC 8032 bytes pass through; a DER OCTET
  -- STRING wrapper unwraps; widths are enforced either way.
  assertEqual "raw point passes" (Just ed19Point)
    (unwrapEdwardsPoint 32 ed19Point)
  assertEqual "wrapped point unwraps" (Just ed19Point)
    (unwrapEdwardsPoint 32 (BS.pack [0x04, 0x20] <> ed19Point))
  assertEqual "wrapped Ed448 unwraps" (Just ed48Point)
    (unwrapEdwardsPoint 57 (BS.pack [0x04, 0x39] <> ed48Point))
  assertEqual "short raw refuses" Nothing
    (unwrapEdwardsPoint 32 (BS.take 31 ed19Point))
  assertEqual "long raw refuses" Nothing
    (unwrapEdwardsPoint 32 (ed19Point <> BS.singleton 0x00))
  assertEqual "wrong-width wrap refuses" Nothing
    (unwrapEdwardsPoint 32 (BS.pack [0x04, 0x39] <> ed48Point))
  assertEqual "truncated wrap refuses" Nothing
    (unwrapEdwardsPoint 32 (BS.pack [0x04, 0x20] <> BS.take 31 ed19Point))
  assertEqual "garbage refuses" Nothing
    (unwrapEdwardsPoint 32 "nope")

caseEddsaDerReaders :: IO ()
caseEddsaDerReaders = do
  -- The openssl-emitted goldens parse back to the fixture
  -- components (independent cross-check of the
  -- keygen-stamping readers).
  assertEqual "Ed25519 SPKI fields" (Just (ed19Oid, ed19Point))
    (eddsaSpkiFields ed19SpkiGold)
  assertEqual "Ed448 SPKI fields" (Just (ed48Oid, ed48Point))
    (eddsaSpkiFields ed48SpkiGold)
  assertEqual "Ed25519 PKCS#8 fields" (Just (ed19Oid, ed19Seed))
    (eddsaPkcs8Fields ed19P8Gold)
  assertEqual "Ed448 PKCS#8 fields" (Just (ed48Oid, ed48Seed))
    (eddsaPkcs8Fields ed48P8Gold)
  -- Malformed input refuses.
  assertEqual "truncated SPKI" Nothing
    (eddsaSpkiFields (BS.take (BS.length ed19SpkiGold - 1) ed19SpkiGold))
  assertEqual "truncated PKCS#8" Nothing
    (eddsaPkcs8Fields (BS.take 10 ed19P8Gold))
  assertEqual "garbage SPKI" Nothing (eddsaSpkiFields "nope")
  assertEqual "garbage PKCS#8" Nothing (eddsaPkcs8Fields "nope")
  assertEqual "wrong tag" Nothing
    (eddsaSpkiFields (BS.cons 0x31 (BS.drop 1 ed19SpkiGold)))
  -- Foreign algorithms refuse (OID membership, not shape).
  assertEqual "EC SPKI refuses" Nothing (eddsaSpkiFields ecSpkiGold)
  assertEqual "DSA SPKI refuses" Nothing (eddsaSpkiFields dsaSpkiGold)

caseEddsaPrivate :: IO ()
caseEddsaPrivate = do
  m0 <- seedModel
  st <- getSession m0
  (_, _, attrs) <- doCreate m0 st eddsaPrivTmpl
  der <- storedValue attrs
  assertEqual "PKCS#8 golden" ed19P8Gold der
  assertEqual "params kept" (Just (ValBytes ed19Oid)) (Map.lookup AttrEcParams attrs)
  -- Engine-name params (the post-wire form) assemble identically.
  let named = map (\(t, v) -> if t == AttrEcParams then (t, ValBytes "Ed25519") else (t, v)) eddsaPrivTmpl
  (_, _, attrsN) <- doCreate m0 st named
  derN <- storedValue attrsN
  assertEqual "named-params PKCS#8 golden" ed19P8Gold derN

caseEddsaPublic :: IO ()
caseEddsaPublic = do
  m0 <- seedModel
  st <- getSession m0
  (_, _, attrs) <- doCreate m0 st eddsaPubTmpl
  der <- storedValue attrs
  assertEqual "SPKI golden" ed19SpkiGold der
  assertEqual "point kept" (Just (ValBytes ed19Point)) (Map.lookup AttrEcPoint attrs)
  -- A DER OCTET STRING wrapper around the point unwraps to the
  -- same golden (maximal coverage: some providers emit it).
  let wrapped = map (\(t, v) -> if t == AttrEcPoint
        then (t, ValBytes (BS.pack [0x04, 0x20] <> ed19Point)) else (t, v)) eddsaPubTmpl
  (_, _, attrsW) <- doCreate m0 st wrapped
  derW <- storedValue attrsW
  assertEqual "wrapped-point SPKI golden" ed19SpkiGold derW

casePartialEddsa :: IO ()
casePartialEddsa = do
  m0 <- seedModel
  st <- getSession m0
  let noParams = filter ((/= AttrEcParams) . fst) eddsaPrivTmpl
  expectReject CKR_TEMPLATE_INCOMPLETE (planCreateObject m0 st noParams)
  let noSeed = filter ((/= AttrValue) . fst) eddsaPrivTmpl
  expectReject CKR_TEMPLATE_INCOMPLETE (planCreateObject m0 st noSeed)
  let noPoint = filter ((/= AttrEcPoint) . fst) eddsaPubTmpl
  expectReject CKR_TEMPLATE_INCOMPLETE (planCreateObject m0 st noPoint)

caseBadEddsaValue :: IO ()
caseBadEddsaValue = do
  m0 <- seedModel
  st <- getSession m0
  let setT tmpl t v = (t, v) : filter ((/= t) . fst) tmpl
      p256 = hex "06082a8648ce3d030107"
  -- Off-width seed/point refuse inconsistent.
  expectReject CKR_TEMPLATE_INCONSISTENT (planCreateObject m0 st
    (setT eddsaPrivTmpl AttrValue (ValBytes (BS.take 31 ed19Seed))))
  expectReject CKR_TEMPLATE_INCONSISTENT (planCreateObject m0 st
    (setT eddsaPrivTmpl AttrValue (ValBytes (ed19Seed <> BS.singleton 0))))
  expectReject CKR_TEMPLATE_INCONSISTENT (planCreateObject m0 st
    (setT eddsaPubTmpl AttrEcPoint (ValBytes (BS.take 31 ed19Point))))
  -- A foreign curve refuses CURVE_NOT_SUPPORTED (the EC precedent).
  expectReject CKR_CURVE_NOT_SUPPORTED (planCreateObject m0 st
    (setT eddsaPrivTmpl AttrEcParams (ValBytes p256)))
  expectReject CKR_CURVE_NOT_SUPPORTED (planCreateObject m0 st
    (setT eddsaPubTmpl AttrEcParams (ValBytes p256)))
  -- An explicit value next to public components contradicts.
  expectReject CKR_TEMPLATE_INCONSISTENT (planCreateObject m0 st
    (eddsaPubTmpl ++ [(AttrValue, ValBytes "x")]))

caseEdwardsTableAgreement :: IO ()
caseEdwardsTableAgreement = do
  -- The core Edwards table and the FFI wire mapping agree both
  -- ways (the EC agreement precedent); anything else passes
  -- through untouched.
  let curves =
        [ ("Ed25519", "06032b6570", 32, 64)
        , ("Ed448", "06032b6571", 57, 114)
        ]
  mapM_ (\(name, oid, seedW, sigW) -> do
    assertEqual ("core resolves " ++ name) (Just (hex oid)) (edwardsOidOfParams (BS8.pack name))
    assertEqual ("core resolves DER " ++ name) (Just (hex oid)) (edwardsOidOfParams (hex oid))
    assertEqual ("core names " ++ name) (Just (BS8.pack name)) (edwardsNameOfOid (hex oid))
    assertEqual ("core widths " ++ name) (Just (seedW, sigW)) (edwardsWidthsOfParams (hex oid))
    assertEqual ("ffi emits " ++ name) (hex oid) (ecParamsToWire (BS8.pack name))
    assertEqual ("ffi parses " ++ name) (BS8.pack name) (ecParamsFromWire (hex oid))
    ) curves

caseDsaDerReaders :: IO ()
caseDsaDerReaders = do
  -- The openssl-emitted goldens parse back to the fixture components
  -- (independent cross-check of the keygen-stamping readers).
  -- Note: dsaX carries a leading zero octet on the wire; readers
  -- return minimal unsigned bytes.
  assertEqual "SPKI fields" (Just (dsaP, dsaQ, dsaG, dsaY))
    (dsaSpkiFields dsaSpkiGold)
  assertEqual "PKCS#8 fields" (Just (dsaP, dsaQ, dsaG, BS.drop 1 dsaX))
    (dsaPkcs8Fields dsaP8Gold)
  -- DSS-Parms extraction from the SPKI algorithm parameters.
  case dsaSpkiFields dsaSpkiGold of
    Just (p, q, g, _) -> do
      assertEqual "params p" dsaP p
      assertEqual "params q" dsaQ q
      assertEqual "params g" dsaG g
    Nothing -> assertFailure "SPKI golden must parse"
  -- Malformed input refuses.
  assertEqual "truncated SPKI" Nothing
    (dsaSpkiFields (BS.take (BS.length dsaSpkiGold - 1) dsaSpkiGold))
  assertEqual "truncated PKCS#8" Nothing
    (dsaPkcs8Fields (BS.take 10 dsaP8Gold))
  assertEqual "garbage params" Nothing (parseDsaParams "nope")
  assertEqual "wrong tag" Nothing
    (parseDsaParams (BS.cons 0x31 (BS.drop 1 dsaSpkiGold)))

casePartialDsa :: IO ()
casePartialDsa = do
  m0 <- seedModel
  st <- getSession m0
  let noQ = filter ((/= AttrSubprime) . fst) dsaPrivTmpl
  expectReject CKR_TEMPLATE_INCOMPLETE (planCreateObject m0 st noQ)
  let noY = filter ((/= AttrValue) . fst) dsaPubTmpl
  expectReject CKR_TEMPLATE_INCOMPLETE (planCreateObject m0 st noY)

caseBadDsaValue :: IO ()
caseBadDsaValue = do
  m0 <- seedModel
  st <- getSession m0
  let bads =
        [ ("empty value", (AttrValue, ValBytes BS.empty), dsaPrivTmpl)
        , ("empty prime", (AttrPrime, ValBytes BS.empty), dsaPubTmpl)
        , ("empty subprime", (AttrSubprime, ValBytes BS.empty), dsaPubTmpl)
        , ("empty base", (AttrBase, ValBytes BS.empty), dsaPubTmpl)
        ]
  mapM_ (\(label, (t, v), tmpl) -> do
    let tmpl' = (t, v) : filter ((/= t) . fst) tmpl
    case planCreateObject m0 st tmpl' of
      Reject rej -> assertEqual ("bad DSA " ++ label) CKR_TEMPLATE_INCONSISTENT (rejCode rej)
      Immediate _ -> assertFailure ("bad DSA accepted: " ++ label)
      Execute _ _ -> assertFailure ("bad DSA executed: " ++ label)
    ) bads

casePartialRsa :: IO ()
casePartialRsa = do
  m0 <- seedModel
  st <- getSession m0
  let tmpl = filter ((/= AttrPrime1) . fst) rsaPrivTmpl
  expectReject CKR_TEMPLATE_INCOMPLETE (planCreateObject m0 st tmpl)

caseForeignCurve :: IO ()
caseForeignCurve = do
  m0 <- seedModel
  st <- getSession m0
  -- brainpoolP160r1 OID (DER): a real curve we do not execute
  -- (uncollected by the oracle, so outside the covered set).
  let foreignOid = hex "06092b2403030208010101"
      tmpl = (AttrEcParams, ValBytes foreignOid)
        : filter ((/= AttrEcParams) . fst) ecPubTmpl
  expectReject CKR_CURVE_NOT_SUPPORTED (planCreateObject m0 st tmpl)

caseBadPoint :: IO ()
caseBadPoint = do
  m0 <- seedModel
  st <- getSession m0
  let raw = BS.drop 2 ecPointWrapped
      bads =
        [ ("unwrapped", raw)
        , ("trailing garbage", ecPointWrapped <> "zz")
        , ("compressed", BS.pack [0x04, 0x22] <> BS.pack [0x02] <> BS.replicate 32 0x11)
        , ("empty", BS.empty)
        ]
  mapM_ (\(label, point) -> do
    let tmpl = (AttrEcPoint, ValBytes point)
          : filter ((/= AttrEcPoint) . fst) ecPubTmpl
    case planCreateObject m0 st tmpl of
      Reject rej -> assertEqual ("bad point " ++ label) CKR_TEMPLATE_INCONSISTENT (rejCode rej)
      Immediate _ -> assertFailure ("bad point accepted: " ++ label)
      Execute _ _ -> assertFailure ("bad point executed: " ++ label)
    ) bads
  -- The unwrapper agrees directly: garbage in, Nothing out.
  assertBool "unwrap rejects garbage" (unwrapEcPoint 32 "zz" == Nothing)
  assertBool "curve rejects garbage" (curveOidOfParams "P-999" == Nothing)

caseValueConflict :: IO ()
caseValueConflict = do
  m0 <- seedModel
  st <- getSession m0
  let tmpl = (AttrValue, ValBytes "opaque") : rsaPrivTmpl
  expectReject CKR_TEMPLATE_INCONSISTENT (planCreateObject m0 st tmpl)

caseSealedComponents :: IO ()
caseSealedComponents = do
  let attrs = Map.fromList
        [ (AttrSensitive, ValBool True)
        , (AttrModulus, ValBytes rsaN)
        , (AttrPrivateExponent, ValBytes rsaD)
        , (AttrPrime1, ValBytes rsaP)
        , (AttrValue, ValBytes rsaP8Gold)
        ]
      PartialReads code results = getAttributes attrs
        [AttrModulus, AttrPrivateExponent, AttrPrime1, AttrValue]
  assertEqual "sealed code" CKR_ATTRIBUTE_SENSITIVE code
  assertEqual "modulus readable"
    (Just (ResOk (ValBytes rsaN))) (lookup AttrModulus results)
  assertEqual "private exponent sealed"
    (Just ResSensitive) (lookup AttrPrivateExponent results)
  assertEqual "prime sealed"
    (Just ResSensitive) (lookup AttrPrime1 results)
  assertEqual "value sealed"
    (Just ResSensitive) (lookup AttrValue results)

caseCurveTableAgreement :: IO ()
caseCurveTableAgreement = do
  -- The core OID table and the FFI wire mapping agree both ways on
  -- all 22 oracle-collected curves (OID bytes verified against the
  -- oracle's own table); anything else passes through untouched.
  -- (name, DER OID hex, coordinate width)
  let curves =
        [ ("P-256", "06082a8648ce3d030107", 32)
        , ("P-384", "06052b81040022", 48)
        , ("P-521", "06052b81040023", 66)
        , ("secp160r1", "06052b81040008", 20)
        , ("secp160r2", "06052b8104001e", 20)
        , ("secp160k1", "06052b81040009", 20)
        , ("secp192k1", "06052b8104001f", 24)
        , ("secp192r1", "06082a8648ce3d030101", 24)
        , ("secp224k1", "06052b81040020", 28)
        , ("secp224r1", "06052b81040021", 28)
        , ("secp256k1", "06052b8104000a", 32)
        , ("brainpoolP224r1", "06092b2403030208010105", 28)
        , ("brainpoolP256r1", "06092b2403030208010107", 32)
        , ("brainpoolP320r1", "06092b2403030208010109", 40)
        , ("brainpoolP384r1", "06092b240303020801010b", 48)
        , ("brainpoolP512r1", "06092b240303020801010d", 64)
        , ("sect283k1", "06052b81040010", 36)
        , ("sect283r1", "06052b81040011", 36)
        , ("sect409k1", "06052b81040024", 52)
        , ("sect409r1", "06052b81040025", 52)
        , ("sect571k1", "06052b81040026", 72)
        , ("sect571r1", "06052b81040027", 72)
        ]
  mapM_ (\(name, oid, width) -> do
    assertEqual ("core resolves " ++ name) (Just (hex oid)) (curveOidOfParams (BS8.pack name))
    assertEqual ("core resolves DER " ++ name) (Just (hex oid)) (curveOidOfParams (hex oid))
    assertEqual ("core width " ++ name) (Just width) (curveCoordLen (hex oid))
    assertEqual ("ffi emits " ++ name) (hex oid) (ecParamsToWire (BS8.pack name))
    assertEqual ("ffi parses " ++ name) (BS8.pack name) (ecParamsFromWire (hex oid))
    ) curves

caseEcExecutes :: IO ()
caseEcExecutes = withRealEnv $ \env -> do
  m0 <- seedModel
  st <- getSession m0
  (m1, _, privAttrs) <- doCreate m0 st ecPrivTmpl
  privDer <- storedValue privAttrs
  (_, _, pubAttrs) <- doCreate m1 st ecPubTmpl
  pubDer <- storedValue pubAttrs
  let spec = SigECDSA (EcSpec "P-256" "RAW") (Just D_SHA256)
  sres <- sign env spec (KeyDer privDer) "import-msg"
  sig <- case sres of
    EngineOk s -> pure s
    EngineFail err -> assertFailure ("imported EC sign failed: " ++ show err) >> undefined
  assertEqual "raw signature length" 64 (BS.length sig)
  vres <- verify env spec (KeyDer pubDer) "import-msg" sig
  case vres of
    EngineOk () -> pure ()
    EngineFail err -> assertFailure ("imported EC verify failed: " ++ show err)

caseDsaExecutes :: IO ()
caseDsaExecutes = withRealEnv $ \env -> do
  m0 <- seedModel
  st <- getSession m0
  (m1, _, privAttrs) <- doCreate m0 st dsaPrivTmpl
  privDer <- storedValue privAttrs
  (_, _, pubAttrs) <- doCreate m1 st dsaPubTmpl
  pubDer <- storedValue pubAttrs
  let spec = SigDSA "RAW" (Just D_SHA256)
  sres <- sign env spec (KeyDer privDer) "import-msg"
  sig <- case sres of
    EngineOk s -> pure s
    EngineFail err -> assertFailure ("imported DSA sign failed: " ++ show err) >> undefined
  assertEqual "raw signature length" 56 (BS.length sig)
  vres <- verify env spec (KeyDer pubDer) "import-msg" sig
  case vres of
    EngineOk () -> pure ()
    EngineFail err -> assertFailure ("imported DSA verify failed: " ++ show err)

caseRsaExecutes :: IO ()
caseRsaExecutes = withRealEnv $ \env -> do
  m0 <- seedModel
  st <- getSession m0
  (m1, _, privAttrs) <- doCreate m0 st rsaPrivTmpl
  privDer <- storedValue privAttrs
  (_, _, pubAttrs) <- doCreate m1 st rsaPubTmpl
  pubDer <- storedValue pubAttrs
  let spec = SigRSA_PKCS1v15 D_SHA256
  sres <- sign env spec (KeyDer privDer) "import-msg"
  sig <- case sres of
    EngineOk s -> pure s
    EngineFail err -> assertFailure ("imported RSA sign failed: " ++ show err) >> undefined
  vres <- verify env spec (KeyDer pubDer) "import-msg" sig
  case vres of
    EngineOk () -> pure ()
    EngineFail err -> assertFailure ("imported RSA verify failed: " ++ show err)

rsaN :: ByteString
rsaN = hex $ concat
    [ "bf249542389ea0de381c11c04c7777e6c56106165ec581cc378e6f9022cd2b4f"
    , "efd66e575e7043004afef1e4916177cea097cef02d4f09de587d869840cd75ec"
    , "a6adb70c19824f9a8a573c9ac337876cd2c490e6c5d69a686386009d54d13f1b"
    , "1be0a71055f23717d81bdc060c29d0ec7a6d8280a677ab92d65c9b64981300e4"
    , "a4eb60e4180189362c964ba3d55ca2db2d2998331ea0e87ab44d577fe8533717"
    , "9f02cf8d71404b4f8bd99e4e3e636c45ceea91e7660165f35451ee15fd44b42a"
    , "5eee7552aaccc25737be7f3d43542a43cc46b39fb127608c5a055327d339855e"
    , "838995295160067a417cc8c3095ee012bf078da33c71becae36b9805c174f357"
    ]

rsaE :: ByteString
rsaE = hex $ concat
    [ "010001"
    ]

rsaD :: ByteString
rsaD = hex $ concat
    [ "02147aaaa8fabcedbe219165e22478ac626079befb92b2fa0f1960886a8088b9"
    , "f5765966b4fde16a1ae6d1a8b6eb9f1b4e0468e43f31f97daf167fef9f363d29"
    , "7144e4558adf855092b47bfc83d1a7b51cf40ba449e9d9c34cb5f4181788b162"
    , "f0f78db4854d934b91f6a25079ddbdf5722847ea70cff8e62a540152e3bec287"
    , "3598079bf1965083cca686d500ab2867c43db553dd2894a3014fa30814f58966"
    , "b7f91e71b9c6928f41d22587daa3a939b409b9aeac3765404b0b3a890000c2e3"
    , "480d90950529f73df1340f69cc8be3c69def997524a3883cc618f51a81130842"
    , "f094b95699d093acb3e8c59a9a65b968101f6220638265e398f8f65ba6363ca5"
    ]

rsaP :: ByteString
rsaP = hex $ concat
    [ "f38edb79d7c425b930bee769f17aa3cc565f6e0a72b7fd0c734a0257960213f5"
    , "c5c5d16887e80d0d8c9136daa855e26e38319f7cd5f454b875e9eff1c9a6dc88"
    , "753a65d825d079d1fd9b8d1843e250793279877e1db7bd932b09473a1973ce71"
    , "0f5179baf192a17052a66c5247205bdad49fb48938b6590d5f2154820337498b"
    ]

rsaQ :: ByteString
rsaQ = hex $ concat
    [ "c8e8439d64764eaff4f6bf45bc56df3280d3c5aeedae00f0099f3d169db75f3a"
    , "0105900eef944f120f0d49d63d623e07b6feafa043914bf8e4ae243a9f82b853"
    , "dc1e347b262a250423d1f53f097cdce6677813a277f8eca15b5a61acb08bbdc2"
    , "042a0457492f09488ab22936aa8e098798484a230f3c4d27294589d4c8a1bee5"
    ]

rsaDp :: ByteString
rsaDp = hex $ concat
    [ "17e28b9d804e6910a73a21819f3fd2ae684e05819acc76517140f1c7db1b2b0f"
    , "f02c3d240e27f097c2903f1be4643fc765556079a295ca7528831f97cb99c488"
    , "d14e3fcc99b0bf319bb85476ebb95700fbb5355765dcae07afb1c23d6d5f9100"
    , "3f6b530fc53f06fbf7ef0032756d33f4dae32a96466c83812f321a9281743b8f"
    ]

rsaDq :: ByteString
rsaDq = hex $ concat
    [ "80b900096a02bb2bd5e1fa6f2ddae32ab28bfd0eb54e555f766ac673251e062f"
    , "5dd43896b93de6e3852d586fa1e8be21a747cb32fdd7ac3b8e195d310a5e70c7"
    , "9a32e8213734ad7ed78c807ba112955e325127136396e3d606780438e6ecc1e9"
    , "fb4d0876fc76dc95d3f78e9c6dee8f80873b59f4d8a02436c124c2c8c8bb8959"
    ]

rsaQinv :: ByteString
rsaQinv = hex $ concat
    [ "3cefd2574cbb2056d55f71c3fe82090a9797c6c038d1ef045e0373081801f4e4"
    , "68f7822b9580bcd21aac3c601a330ca745978cd01761cbccf29201086defab1f"
    , "08ec5024b60b79ed839dbf43c9c35a07da5cf8163fc4c57a1e06b20378077dab"
    , "fb54e39d56bf2a4d478187829ec00236001f1503a903482246a21aac1c04ae4f"
    ]

ecScalar :: ByteString
ecScalar = hex $ concat
    [ "5bc5fc2e1cb344d11de202ea057cbfd5da5f9a9a54a83fda363e5742b044366c"
    ]

ecPointWrapped :: ByteString
ecPointWrapped = hex $ concat
    [ "044104a113ffac941b89a293f5bb308496c60f74732c92b5724a97191ba3f76d"
    , "afa9b00ba279852742b80f7e8bc51f7fd41b368d1c611c391a4abd0559ddf16b"
    , "63ee01"
    ]

rsaP8Gold :: ByteString
rsaP8Gold = hex $ concat
    [ "308204bd020100300d06092a864886f70d0101010500048204a7308204a30201"
    , "000282010100bf249542389ea0de381c11c04c7777e6c56106165ec581cc378e"
    , "6f9022cd2b4fefd66e575e7043004afef1e4916177cea097cef02d4f09de587d"
    , "869840cd75eca6adb70c19824f9a8a573c9ac337876cd2c490e6c5d69a686386"
    , "009d54d13f1b1be0a71055f23717d81bdc060c29d0ec7a6d8280a677ab92d65c"
    , "9b64981300e4a4eb60e4180189362c964ba3d55ca2db2d2998331ea0e87ab44d"
    , "577fe85337179f02cf8d71404b4f8bd99e4e3e636c45ceea91e7660165f35451"
    , "ee15fd44b42a5eee7552aaccc25737be7f3d43542a43cc46b39fb127608c5a05"
    , "5327d339855e838995295160067a417cc8c3095ee012bf078da33c71becae36b"
    , "9805c174f35702030100010282010002147aaaa8fabcedbe219165e22478ac62"
    , "6079befb92b2fa0f1960886a8088b9f5765966b4fde16a1ae6d1a8b6eb9f1b4e"
    , "0468e43f31f97daf167fef9f363d297144e4558adf855092b47bfc83d1a7b51c"
    , "f40ba449e9d9c34cb5f4181788b162f0f78db4854d934b91f6a25079ddbdf572"
    , "2847ea70cff8e62a540152e3bec2873598079bf1965083cca686d500ab2867c4"
    , "3db553dd2894a3014fa30814f58966b7f91e71b9c6928f41d22587daa3a939b4"
    , "09b9aeac3765404b0b3a890000c2e3480d90950529f73df1340f69cc8be3c69d"
    , "ef997524a3883cc618f51a81130842f094b95699d093acb3e8c59a9a65b96810"
    , "1f6220638265e398f8f65ba6363ca502818100f38edb79d7c425b930bee769f1"
    , "7aa3cc565f6e0a72b7fd0c734a0257960213f5c5c5d16887e80d0d8c9136daa8"
    , "55e26e38319f7cd5f454b875e9eff1c9a6dc88753a65d825d079d1fd9b8d1843"
    , "e250793279877e1db7bd932b09473a1973ce710f5179baf192a17052a66c5247"
    , "205bdad49fb48938b6590d5f2154820337498b02818100c8e8439d64764eaff4"
    , "f6bf45bc56df3280d3c5aeedae00f0099f3d169db75f3a0105900eef944f120f"
    , "0d49d63d623e07b6feafa043914bf8e4ae243a9f82b853dc1e347b262a250423"
    , "d1f53f097cdce6677813a277f8eca15b5a61acb08bbdc2042a0457492f09488a"
    , "b22936aa8e098798484a230f3c4d27294589d4c8a1bee502818017e28b9d804e"
    , "6910a73a21819f3fd2ae684e05819acc76517140f1c7db1b2b0ff02c3d240e27"
    , "f097c2903f1be4643fc765556079a295ca7528831f97cb99c488d14e3fcc99b0"
    , "bf319bb85476ebb95700fbb5355765dcae07afb1c23d6d5f91003f6b530fc53f"
    , "06fbf7ef0032756d33f4dae32a96466c83812f321a9281743b8f0281810080b9"
    , "00096a02bb2bd5e1fa6f2ddae32ab28bfd0eb54e555f766ac673251e062f5dd4"
    , "3896b93de6e3852d586fa1e8be21a747cb32fdd7ac3b8e195d310a5e70c79a32"
    , "e8213734ad7ed78c807ba112955e325127136396e3d606780438e6ecc1e9fb4d"
    , "0876fc76dc95d3f78e9c6dee8f80873b59f4d8a02436c124c2c8c8bb89590281"
    , "803cefd2574cbb2056d55f71c3fe82090a9797c6c038d1ef045e0373081801f4"
    , "e468f7822b9580bcd21aac3c601a330ca745978cd01761cbccf29201086defab"
    , "1f08ec5024b60b79ed839dbf43c9c35a07da5cf8163fc4c57a1e06b20378077d"
    , "abfb54e39d56bf2a4d478187829ec00236001f1503a903482246a21aac1c04ae"
    , "4f"
    ]

rsaSpkiGold :: ByteString
rsaSpkiGold = hex $ concat
    [ "30820122300d06092a864886f70d01010105000382010f003082010a02820101"
    , "00bf249542389ea0de381c11c04c7777e6c56106165ec581cc378e6f9022cd2b"
    , "4fefd66e575e7043004afef1e4916177cea097cef02d4f09de587d869840cd75"
    , "eca6adb70c19824f9a8a573c9ac337876cd2c490e6c5d69a686386009d54d13f"
    , "1b1be0a71055f23717d81bdc060c29d0ec7a6d8280a677ab92d65c9b64981300"
    , "e4a4eb60e4180189362c964ba3d55ca2db2d2998331ea0e87ab44d577fe85337"
    , "179f02cf8d71404b4f8bd99e4e3e636c45ceea91e7660165f35451ee15fd44b4"
    , "2a5eee7552aaccc25737be7f3d43542a43cc46b39fb127608c5a055327d33985"
    , "5e838995295160067a417cc8c3095ee012bf078da33c71becae36b9805c174f3"
    , "570203010001"
    ]

ecSpkiGold :: ByteString
ecSpkiGold = hex $ concat
    [ "3059301306072a8648ce3d020106082a8648ce3d03010703420004a113ffac94"
    , "1b89a293f5bb308496c60f74732c92b5724a97191ba3f76dafa9b00ba2798527"
    , "42b80f7e8bc51f7fd41b368d1c611c391a4abd0559ddf16b63ee01"
    ]

ecP8NoPubGold :: ByteString
ecP8NoPubGold = hex $ concat
    [ "3041020100301306072a8648ce3d020106082a8648ce3d030107042730250201"
    , "0104205bc5fc2e1cb344d11de202ea057cbfd5da5f9a9a54a83fda363e5742b0"
    , "44366c"
    ]

-- | ML-DSA fixtures: CLI-generated halves per level (pinned
-- @openssl genpkey@, read from tests/fixtures/); the DER files
-- are openssl-emitted bytes, so golden equality is an
-- independent cross-check of the assembly, not self-agreement.
loadMldsaHalves :: String -> IO (ByteString, ByteString, ByteString, ByteString, ByteString)
loadMldsaHalves tag = do
  pubDer <- BS.readFile ("tests/fixtures/mldsa" ++ tag ++ "-pub.der")
  privDer <- BS.readFile ("tests/fixtures/mldsa" ++ tag ++ "-priv.der")
  case (mldsaSpkiFields pubDer, mldsaPkcs8Fields privDer) of
    (Just (pubOid, raw), Just (privOid, seed, expanded))
      | pubOid == privOid -> pure (pubOid, raw, seed, expanded, pubDer)
    _ -> assertFailure ("ML-DSA fixture halves disagree: " ++ tag) >> undefined

mldsaOids :: [(String, Int, ByteString)]
mldsaOids =
  [ ("44", 1, hex "0609608648016503040311")
  , ("65", 2, hex "0609608648016503040312")
  , ("87", 3, hex "0609608648016503040313")
  ]

mldsaCkp :: ByteString -> Word64
mldsaCkp o
  | o == hex "0609608648016503040311" = 1
  | o == hex "0609608648016503040312" = 2
  | otherwise = 3

mldsaPrivTmpl :: ByteString -> ByteString -> [(AttributeType, AttributeValue)]
mldsaPrivTmpl oid expanded =
  [ (AttrClass, ValULong ckoPrivateKey)
  , (AttrKeyType, ValULong ckkMlDsa)
  , (AttrToken, ValBool False)
  , (AttrParameterSet, ValULong (mldsaCkp oid))
  , (AttrValue, ValBytes expanded)
  ]

mldsaPubTmpl :: ByteString -> ByteString -> [(AttributeType, AttributeValue)]
mldsaPubTmpl oid raw =
  [ (AttrClass, ValULong ckoPublicKey)
  , (AttrKeyType, ValULong ckkMlDsa)
  , (AttrToken, ValBool False)
  , (AttrParameterSet, ValULong (mldsaCkp oid))
  , (AttrValue, ValBytes raw)
  ]

caseMldsaDerGoldens :: IO ()
caseMldsaDerGoldens = do
  -- Every served level: SPKI assembly from the parsed raw key
  -- reproduces the openssl-emitted fixture bytes exactly.
  mapM_ golden ["44", "65", "87"]
  -- The table rows pin names, OIDs, widths, and CKP ids.
  assertEqual "table rows"
    [ ("ML-DSA-44", hex "0609608648016503040311", 1312, 2560, 2420, 1)
    , ("ML-DSA-65", hex "0609608648016503040312", 1952, 4032, 3309, 2)
    , ("ML-DSA-87", hex "0609608648016503040313", 2592, 4896, 4627, 3)
    ]
    mldsaTable
  mapM_ (\(tag, ckp, oid) ->
    assertEqual ("OID " ++ tag) (Just oid) (mldsaOidOfCkp ckp)) mldsaOids
  assertEqual "unknown CKP" Nothing (mldsaOidOfCkp 7)
  assertEqual "44 widths" (Just (1312, 2560, 2420))
    (mldsaWidthsOfOid (hex "0609608648016503040311"))
  assertEqual "P-256 has no ML-DSA widths" Nothing
    (mldsaWidthsOfOid (hex "06082a8648ce3d030107"))
  assertEqual "garbage has no ML-DSA widths" Nothing
    (mldsaWidthsOfOid "nope")
  where
    golden tag = do
      (oid, raw, _, _, pubDer) <- loadMldsaHalves tag
      assertEqual ("SPKI golden " ++ tag) pubDer (mldsaPublicDer oid raw)

caseMldsaDerReaders :: IO ()
caseMldsaDerReaders = do
  (oid44, raw44, seed44, exp44, pub44) <- loadMldsaHalves "44"
  priv44 <- BS.readFile "tests/fixtures/mldsa44-priv.der"
  assertEqual "44 SPKI fields" (Just (oid44, raw44)) (mldsaSpkiFields pub44)
  assertEqual "44 PKCS#8 fields" (Just (oid44, seed44, exp44)) (mldsaPkcs8Fields priv44)
  assertEqual "44 seed width" 32 (BS.length seed44)
  -- Malformed input refuses.
  assertEqual "truncated SPKI" Nothing
    (mldsaSpkiFields (BS.take (BS.length pub44 - 1) pub44))
  assertEqual "truncated PKCS#8" Nothing (mldsaPkcs8Fields (BS.take 10 priv44))
  assertEqual "garbage SPKI" Nothing (mldsaSpkiFields "nope")
  assertEqual "garbage PKCS#8" Nothing (mldsaPkcs8Fields "nope")
  -- Foreign algorithms refuse (OID membership, not shape).
  assertEqual "EC SPKI refuses" Nothing (mldsaSpkiFields ecSpkiGold)
  assertEqual "Ed25519 SPKI refuses" Nothing (mldsaSpkiFields ed19SpkiGold)
  -- The flat import form is deliberately NOT provider-form: the
  -- provider reader refuses it (import and keygen shapes differ
  -- by design).
  assertEqual "provider reader refuses flat" Nothing
    (mldsaPkcs8Fields (mldsaPrivateDer oid44 exp44))

caseMldsaPrivate :: IO ()
caseMldsaPrivate = do
  m0 <- seedModel
  st <- getSession m0
  (oid, _, _, expanded, _) <- loadMldsaHalves "44"
  (_, _, attrs) <- doCreate m0 st (mldsaPrivTmpl oid expanded)
  der <- storedValue attrs
  assertEqual "flat PKCS#8 golden" (mldsaPrivateDer oid expanded) der
  assertBool "flat framing" (BS.isPrefixOf (hex "30820a14020100300b060960864801650304031104820a00") der)
  assertEqual "flat carries expanded" expanded (BS.drop (BS.length der - 2560) der)
  assertEqual "set kept" (Just (ValULong 1)) (Map.lookup AttrParameterSet attrs)

caseMldsaPublic :: IO ()
caseMldsaPublic = do
  m0 <- seedModel
  st <- getSession m0
  (oid, raw, _, _, pubDer) <- loadMldsaHalves "65"
  (_, _, attrs) <- doCreate m0 st (mldsaPubTmpl oid raw)
  der <- storedValue attrs
  assertEqual "SPKI golden" pubDer der
  assertEqual "set kept" (Just (ValULong 2)) (Map.lookup AttrParameterSet attrs)

casePartialMldsa :: IO ()
casePartialMldsa = do
  m0 <- seedModel
  st <- getSession m0
  (oid, raw, _, expanded, _) <- loadMldsaHalves "44"
  let noSet = filter ((/= AttrParameterSet) . fst) (mldsaPrivTmpl oid expanded)
  expectReject CKR_TEMPLATE_INCOMPLETE (planCreateObject m0 st noSet)
  let noValue = filter ((/= AttrValue) . fst) (mldsaPrivTmpl oid expanded)
  expectReject CKR_TEMPLATE_INCOMPLETE (planCreateObject m0 st noValue)
  let noSetPub = filter ((/= AttrParameterSet) . fst) (mldsaPubTmpl oid raw)
  expectReject CKR_TEMPLATE_INCOMPLETE (planCreateObject m0 st noSetPub)
  let noRaw = filter ((/= AttrValue) . fst) (mldsaPubTmpl oid raw)
  expectReject CKR_TEMPLATE_INCOMPLETE (planCreateObject m0 st noRaw)

caseBadMldsaValue :: IO ()
caseBadMldsaValue = do
  m0 <- seedModel
  st <- getSession m0
  (oid, raw, seed, expanded, _) <- loadMldsaHalves "44"
  let setT tmpl t v = (t, v) : filter ((/= t) . fst) tmpl
      priv = mldsaPrivTmpl oid expanded
      pub = mldsaPubTmpl oid raw
  -- Off-width values refuse inconsistent.
  expectReject CKR_TEMPLATE_INCONSISTENT (planCreateObject m0 st
    (setT priv AttrValue (ValBytes (BS.take 2559 expanded))))
  expectReject CKR_TEMPLATE_INCONSISTENT (planCreateObject m0 st
    (setT priv AttrValue (ValBytes (expanded <> BS.singleton 0))))
  expectReject CKR_TEMPLATE_INCONSISTENT (planCreateObject m0 st
    (setT pub AttrValue (ValBytes (BS.take 1311 raw))))
  -- An unknown set refuses inconsistent.
  expectReject CKR_TEMPLATE_INCONSISTENT (planCreateObject m0 st
    (setT priv AttrParameterSet (ValULong 7)))
  -- A seed-only private template refuses inconsistent (the
  -- provider cannot expand a lone seed); seed plus value
  -- imports fine (the seed rides verbatim).
  let seedOnly = setT (filter ((/= AttrValue) . fst) priv) AttrSeed (ValBytes seed)
  expectReject CKR_TEMPLATE_INCONSISTENT (planCreateObject m0 st seedOnly)
  (_, _, bothAttrs) <- doCreate m0 st (priv ++ [(AttrSeed, ValBytes seed)])
  assertEqual "seed kept verbatim" (Just (ValBytes seed)) (Map.lookup AttrSeed bothAttrs)

caseMldsaExecutes :: IO ()
caseMldsaExecutes = withRealEnv $ \env -> do
  m0 <- seedModel
  st <- getSession m0
  (oid, raw, _, expanded, _) <- loadMldsaHalves "44"
  (m1, _, privAttrs) <- doCreate m0 st (mldsaPrivTmpl oid expanded)
  privDer <- storedValue privAttrs
  (_, _, pubAttrs) <- doCreate m1 st (mldsaPubTmpl oid raw)
  pubDer <- storedValue pubAttrs
  let spec = SigMLDSA ML_DSA_44 False "" True
  sres <- sign env spec (KeyDer privDer) "import-msg"
  sig <- case sres of
    EngineOk s -> pure s
    EngineFail err -> assertFailure ("imported ML-DSA sign failed: " ++ show err) >> undefined
  assertEqual "raw signature length" 2420 (BS.length sig)
  vres <- verify env spec (KeyDer pubDer) "import-msg" sig
  case vres of
    EngineOk () -> pure ()
    EngineFail err -> assertFailure ("imported ML-DSA verify failed: " ++ show err)

loadMlkemHalves :: String -> IO (ByteString, ByteString, ByteString, ByteString, ByteString)
loadMlkemHalves tag = do
  pubDer <- BS.readFile ("tests/fixtures/mlkem" ++ tag ++ "-pub.der")
  privDer <- BS.readFile ("tests/fixtures/mlkem" ++ tag ++ "-priv.der")
  case (mlkemSpkiFields pubDer, mlkemPkcs8Fields privDer) of
    (Just (pubOid, ek), Just (privOid, seed, dk))
      | pubOid == privOid -> pure (pubOid, ek, seed, dk, pubDer)
    _ -> assertFailure ("ML-KEM fixture halves disagree: " ++ tag) >> undefined

mlkemOids :: [(String, Int, ByteString)]
mlkemOids =
  [ ("512", 1, hex "0609608648016503040401")
  , ("768", 2, hex "0609608648016503040402")
  , ("1024", 3, hex "0609608648016503040403")
  ]

mlkemCkp :: ByteString -> Word64
mlkemCkp o
  | o == hex "0609608648016503040401" = 1
  | o == hex "0609608648016503040402" = 2
  | otherwise = 3

mlkemAlgNum :: ByteString -> Word64
mlkemAlgNum o
  | o == hex "0609608648016503040401" = 512
  | o == hex "0609608648016503040402" = 768
  | otherwise = 1024

mlkemPrivTmpl :: ByteString -> ByteString -> [(AttributeType, AttributeValue)]
mlkemPrivTmpl oid dk =
  [ (AttrClass, ValULong ckoPrivateKey)
  , (AttrKeyType, ValULong ckkMlKem)
  , (AttrToken, ValBool False)
  , (AttrParameterSet, ValULong (mlkemCkp oid))
  , (AttrValue, ValBytes dk)
  ]

mlkemPubTmpl :: ByteString -> ByteString -> [(AttributeType, AttributeValue)]
mlkemPubTmpl oid ek =
  [ (AttrClass, ValULong ckoPublicKey)
  , (AttrKeyType, ValULong ckkMlKem)
  , (AttrToken, ValBool False)
  , (AttrParameterSet, ValULong (mlkemCkp oid))
  , (AttrValue, ValBytes ek)
  ]

caseMlkemDerGoldens :: IO ()
caseMlkemDerGoldens = do
  -- Every served set: SPKI assembly from the parsed ek
  -- reproduces the openssl-emitted fixture bytes exactly.
  mapM_ golden ["512", "768", "1024"]
  -- The table rows pin names, OIDs, widths, and CKP ids.
  assertEqual "table rows"
    [ ("ML-KEM-512", hex "0609608648016503040401", 800, 1632, 768, 1)
    , ("ML-KEM-768", hex "0609608648016503040402", 1184, 2400, 1088, 2)
    , ("ML-KEM-1024", hex "0609608648016503040403", 1568, 3168, 1568, 3)
    ]
    mlkemTable
  mapM_ (\(tag, ckp, oid) ->
    assertEqual ("OID " ++ tag) (Just oid) (mlkemOidOfCkp ckp)) mlkemOids
  assertEqual "unknown CKP" Nothing (mlkemOidOfCkp 7)
  assertEqual "768 widths" (Just (1184, 2400, 1088))
    (mlkemWidthsOfOid (hex "0609608648016503040402"))
  assertEqual "ML-DSA OID has no ML-KEM widths" Nothing
    (mlkemWidthsOfOid (hex "0609608648016503040311"))
  assertEqual "garbage has no ML-KEM widths" Nothing
    (mlkemWidthsOfOid "nope")
  where
    golden tag = do
      (oid, ek, _, _, pubDer) <- loadMlkemHalves tag
      assertEqual ("SPKI golden " ++ tag) pubDer (mlkemPublicDer oid ek)

caseMlkemDerReaders :: IO ()
caseMlkemDerReaders = do
  (oid768, ek768, seed768, dk768, pub768) <- loadMlkemHalves "768"
  priv768 <- BS.readFile "tests/fixtures/mlkem768-priv.der"
  assertEqual "768 SPKI fields" (Just (oid768, ek768)) (mlkemSpkiFields pub768)
  assertEqual "768 PKCS#8 fields" (Just (oid768, seed768, dk768)) (mlkemPkcs8Fields priv768)
  assertEqual "768 seed width" 64 (BS.length seed768)
  assertEqual "768 ek width" 1184 (BS.length ek768)
  assertEqual "768 dk width" 2400 (BS.length dk768)
  -- Malformed input refuses.
  assertEqual "truncated SPKI" Nothing
    (mlkemSpkiFields (BS.take (BS.length pub768 - 1) pub768))
  assertEqual "truncated PKCS#8" Nothing (mlkemPkcs8Fields (BS.take 10 priv768))
  assertEqual "garbage SPKI" Nothing (mlkemSpkiFields "nope")
  assertEqual "garbage PKCS#8" Nothing (mlkemPkcs8Fields "nope")
  -- Foreign algorithms refuse (OID membership, not shape).
  assertEqual "EC SPKI refuses" Nothing (mlkemSpkiFields ecSpkiGold)
  assertEqual "ML-DSA SPKI refuses" Nothing
    (mlkemSpkiFields (mldsaPublicDer (hex "0609608648016503040311") (BS.replicate 1312 0)))
  -- The provider reader refuses a flat-dk PKCS#8 (import and
  -- keygen shapes differ by design: the provider's own form is
  -- SEQ{seed64, dk}, while dk-only import stores raw bytes).
  assertEqual "provider reader refuses flat" Nothing
    (mlkemPkcs8Fields (mlkemFlatPriv oid768 dk768))
  -- Seed+dk assembly reproduces the provider form exactly.
  assertEqual "seed+dk assembles provider form" priv768
    (mlkemPrivateDer oid768 seed768 dk768)

-- | A flat OCTET(dk) PKCS#8 (the shape the provider decoder
-- refuses): test-local assembly the production reader must
-- reject, proving import/keygen shape separation.
mlkemFlatPriv :: ByteString -> ByteString -> ByteString
mlkemFlatPriv oid dk =
  derSeqLocal [derIntLocal 0, derSeqLocal [oid], derOctetLocal dk]
  where
    derLen n
      | n < 128 = BS.singleton (fromIntegral n)
      | n < 256 = BS.pack [0x81, fromIntegral n]
      | otherwise = BS.pack [0x82, fromIntegral (n `div` 256), fromIntegral (n `mod` 256)]
    derTlv t body = BS.singleton t <> derLen (BS.length body) <> body
    derSeqLocal parts = derTlv 0x30 (mconcat parts)
    derIntLocal 0 = BS.pack [0x02, 0x01, 0x00]
    derIntLocal _ = error "mlkemFlatPriv: version only"
    derOctetLocal = derTlv 0x04

caseMlkemPrivate :: IO ()
caseMlkemPrivate = do
  m0 <- seedModel
  st <- getSession m0
  (oid, _, seed, dk, _) <- loadMlkemHalves "768"
  priv768 <- BS.readFile "tests/fixtures/mlkem768-priv.der"
  -- dk-only import: no decodable DER exists without the seed
  -- (the provider refuses flat-dk PKCS#8), so the raw dk
  -- stores verbatim and the set tags AttrKemAlg for dispatch.
  (_, _, dkAttrs) <- doCreate m0 st (mlkemPrivTmpl oid dk)
  dkStored <- storedValue dkAttrs
  assertEqual "dk stored verbatim" dk dkStored
  assertEqual "set kept" (Just (ValULong 2)) (Map.lookup AttrParameterSet dkAttrs)
  assertEqual "alg tagged" (Just (ValULong 768)) (Map.lookup AttrKemAlg dkAttrs)
  -- Seed+dk import assembles the provider-form PKCS#8 (the
  -- decoder accepts SEQ{seed64, dk}); the seed rides verbatim.
  (m1, _, bothAttrs) <- doCreate m0 st (mlkemPrivTmpl oid dk ++ [(AttrSeed, ValBytes seed)])
  bothStored <- storedValue bothAttrs
  assertEqual "provider-form PKCS#8 golden" priv768 bothStored
  assertEqual "seed kept verbatim" (Just (ValBytes seed)) (Map.lookup AttrSeed bothAttrs)
  assertEqual "alg tagged" (Just (ValULong 768)) (Map.lookup AttrKemAlg bothAttrs)
  -- A wrong-width seed with a good dk refuses inconsistent.
  expectReject CKR_TEMPLATE_INCONSISTENT (planCreateObject m1 st
    (mlkemPrivTmpl oid dk ++ [(AttrSeed, ValBytes (BS.take 63 seed))]))

caseMlkemPublic :: IO ()
caseMlkemPublic = do
  m0 <- seedModel
  st <- getSession m0
  (oid, ek, _, _, pubDer) <- loadMlkemHalves "512"
  (_, _, attrs) <- doCreate m0 st (mlkemPubTmpl oid ek)
  der <- storedValue attrs
  assertEqual "SPKI golden" pubDer der
  assertEqual "set kept" (Just (ValULong 1)) (Map.lookup AttrParameterSet attrs)
  assertEqual "alg tagged" (Just (ValULong 512)) (Map.lookup AttrKemAlg attrs)

casePartialMlkem :: IO ()
casePartialMlkem = do
  m0 <- seedModel
  st <- getSession m0
  (oid, ek, _, dk, _) <- loadMlkemHalves "768"
  let noSet = filter ((/= AttrParameterSet) . fst) (mlkemPrivTmpl oid dk)
  expectReject CKR_TEMPLATE_INCOMPLETE (planCreateObject m0 st noSet)
  let noValue = filter ((/= AttrValue) . fst) (mlkemPrivTmpl oid dk)
  expectReject CKR_TEMPLATE_INCOMPLETE (planCreateObject m0 st noValue)
  let noSetPub = filter ((/= AttrParameterSet) . fst) (mlkemPubTmpl oid ek)
  expectReject CKR_TEMPLATE_INCOMPLETE (planCreateObject m0 st noSetPub)
  let noRaw = filter ((/= AttrValue) . fst) (mlkemPubTmpl oid ek)
  expectReject CKR_TEMPLATE_INCOMPLETE (planCreateObject m0 st noRaw)

caseBadMlkemValue :: IO ()
caseBadMlkemValue = do
  m0 <- seedModel
  st <- getSession m0
  (oid, ek, _, dk, _) <- loadMlkemHalves "768"
  let setT tmpl t v = (t, v) : filter ((/= t) . fst) tmpl
      priv = mlkemPrivTmpl oid dk
      pub = mlkemPubTmpl oid ek
  -- Off-width values refuse inconsistent.
  expectReject CKR_TEMPLATE_INCONSISTENT (planCreateObject m0 st
    (setT priv AttrValue (ValBytes (BS.take 2399 dk))))
  expectReject CKR_TEMPLATE_INCONSISTENT (planCreateObject m0 st
    (setT priv AttrValue (ValBytes (dk <> BS.singleton 0))))
  expectReject CKR_TEMPLATE_INCONSISTENT (planCreateObject m0 st
    (setT pub AttrValue (ValBytes (BS.take 1183 ek))))
  -- An unknown set refuses inconsistent.
  expectReject CKR_TEMPLATE_INCONSISTENT (planCreateObject m0 st
    (setT priv AttrParameterSet (ValULong 7)))

caseMlkemModulus :: IO ()
caseMlkemModulus = do
  m0 <- seedModel
  st <- getSession m0
  (oid512, ek512, _, _, _) <- loadMlkemHalves "512"
  (oid768, ek768, _, _, _) <- loadMlkemHalves "768"
  (oid1024, ek1024, _, _, _) <- loadMlkemHalves "1024"
  -- Positive controls: honestly generated eks are canonical
  -- (this also pins the 12-bit unpacking against real keys).
  assertBool "512 ek canonical" (mlkemEkWellFormed oid512 ek512)
  assertBool "768 ek canonical" (mlkemEkWellFormed oid768 ek768)
  assertBool "1024 ek canonical" (mlkemEkWellFormed oid1024 ek1024)
  -- Forcing the first coefficient pair to 0xFFF (above
  -- q = 3329) breaks canonicity on every set.
  let bad ek = BS.pack [0xFF, 0xFF, 0xFF] <> BS.drop 3 ek
  assertBool "512 ek non-canonical" (not (mlkemEkWellFormed oid512 (bad ek512)))
  assertBool "768 ek non-canonical" (not (mlkemEkWellFormed oid768 (bad ek768)))
  assertBool "1024 ek non-canonical" (not (mlkemEkWellFormed oid1024 (bad ek1024)))
  -- A corrupted trailing seed (rho) still passes: the modulus
  -- check covers the packed coefficients only (FIPS 203 7.2).
  let badRho ek = BS.take (BS.length ek - 1) ek <> BS.singleton 0xFF
  assertBool "rho corruption passes" (mlkemEkWellFormed oid768 (badRho ek768))
  -- Import refuses a non-canonical ek with the spec-correct
  -- code (the oracle's encaps-modulus pass condition).
  let badTmpl = mlkemPubTmpl oid768 (bad ek768)
  expectReject CKR_ATTRIBUTE_VALUE_INVALID (planCreateObject m0 st badTmpl)

caseMlkemExecutes :: IO ()
caseMlkemExecutes = withRealEnv $ \env -> do
  m0 <- seedModel
  st <- getSession m0
  (oid, ek, _, dk, _) <- loadMlkemHalves "768"
  (m1, _, privAttrs) <- doCreate m0 st (mlkemPrivTmpl oid dk)
  dkStored <- storedValue privAttrs
  (_, _, pubAttrs) <- doCreate m1 st (mlkemPubTmpl oid ek)
  pubStored <- storedValue pubAttrs
  let spec = KemSpec ML_KEM_768
  eres <- kemEncapsulate env spec (KeyBytes pubStored)
  (ct, ss1) <- case eres of
    EngineOk pair -> pure pair
    EngineFail err -> assertFailure ("imported ML-KEM encaps failed: " ++ show err) >> undefined
  assertEqual "ciphertext length" 1088 (BS.length ct)
  assertEqual "shared secret length" 32 (BS.length ss1)
  dres <- kemDecapsulate env spec (KeyBytes dkStored) ct
  ss2 <- case dres of
    EngineOk ss -> pure ss
    EngineFail err -> assertFailure ("imported ML-KEM decaps failed: " ++ show err) >> undefined
  assertEqual "roundtrip secret agrees" ss1 ss2

