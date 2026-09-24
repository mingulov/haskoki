{- | ECDSA recipe tests.

The ECDSA group: 10 header mechanisms sharing the encoding
parameter shape — @sig-encoding\/1@: @"RAW"@, @"DER"@, or empty
(our engine convention selecting the signature encoding; empty
defaults to DER). Nine rows bind a digest (hash-and-sign);
@CKM_ECDSA@ is the raw row (the input is signed directly, no
hashing — the old driver hashed under this id, which this
recipe corrects).
'Haskoki.Recipe.Ecdsa' owns the group's canonical codec, parameter
validation, digest bindings, and mechanism table; these tests pin
the recipe and its three consumers:

* the model init path enforces ECDSA parameters ('validateInit',
  'CKR_ARGUMENTS_BAD');
* the driver maps every covered (mechanism, params, key) triple to
  its backend 'SigSpec' ('ecdsaSpecFor' agrees with the recipe
  table; the curve label hints from the DER key's curve OID
  ('ecCurveOfKey'), defaulting to P-256 — the driver checks
  (mechanism, params), key shape is the backend's call);
* engines execute the pinned specs across P-256\/P-384\/P-521
  (SyntheticSpec roundtrips, OpenSSLSpec interop vectors against
  the pinned libcrypto).
-}
{-# LANGUAGE OverloadedStrings #-}
module RecipeEcdsaSpec (spec) where

import qualified Data.ByteString as BS
import Data.Char (digitToInt, isHexDigit)
import Data.Text (Text)
import qualified Data.Text as T
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertBool, assertEqual, assertFailure, testCase)

import Haskoki.Engine.Backend
  ( DigestAlg (..)
  , EcSpec (..)
  , KeyMaterial (..)
  , SigSpec (..)
  )
import Haskoki.Engine.Driver (ecCurveOfKey, ecdsaSpecFor)
import Haskoki.Model (SessionState (..), emptyModel)
import Haskoki.Operation
  ( InitArgs (..)
  , InitOutcome (..)
  , KeyPolicy (..)
  , OpEnv (..)
  , emptySessionOps
  , initOperation
  )
import Haskoki.Recipe.Ecdsa
  ( EcdsaRecipe (..)
  , ecdsaCodec
  , ecdsaCodecFor
  , ecdsaEncodingOf
  , ecdsaParamsValid
  , ecdsaRecipeFor
  , ecdsaRecipes
  )
import Haskoki.Registry
  ( MechanismId (..)
  , Operation (..)
  , ParameterCodec (..)
  , curatedRegistry
  , mkCapabilities
  )
import Haskoki.Registry.Generated
  ( mustGeneratedId
  , ckm_ECDH1_DERIVE
  , ckm_ECDSA
  , ckm_ECDSA_SHA256
  , ckm_EDDSA
  , ckm_SHA256_RSA_PKCS
  )
import Haskoki.Session (SessionLogin (..))
import Haskoki.Types
  ( ExternalHandle (..)
  , Generation (..)
  , ReturnCode (..)
  , Revision (..)
  , SessionId (..)
  , SlotId (..)
  )

spec :: TestTree
spec = testGroup "ECDSA recipe"
  [ testCase "recipe table covers 10 mechanisms with digests" caseTable
  , testCase "recipe lookup resolves by id" caseLookup
  , testCase "codec is sig-encoding/1" caseCodec
  , testCase "params: RAW/DER/empty only" caseParams
  , testCase "init enforces ECDSA params" caseInitParams
  , testCase "curve sniffing reads the DER curve OID" caseCurveSniff
  , testCase "driver maps every triple to its SigSpec" caseDriverMap
  ]

-- | (Name suffix, digest stem or Nothing for the raw row, backend alg).
groupShape :: [(Text, Maybe Text, Maybe DigestAlg)]
groupShape =
  [ ("ECDSA", Nothing, Nothing)
  , ("ECDSA_SHA1", Just "SHA_1", Just D_SHA1)
  , ("ECDSA_SHA224", Just "SHA224", Just D_SHA224)
  , ("ECDSA_SHA256", Just "SHA256", Just D_SHA256)
  , ("ECDSA_SHA384", Just "SHA384", Just D_SHA384)
  , ("ECDSA_SHA512", Just "SHA512", Just D_SHA512)
  , ("ECDSA_SHA3_224", Just "SHA3_224", Just D_SHA3_224)
  , ("ECDSA_SHA3_256", Just "SHA3_256", Just D_SHA3_256)
  , ("ECDSA_SHA3_384", Just "SHA3_384", Just D_SHA3_384)
  , ("ECDSA_SHA3_512", Just "SHA3_512", Just D_SHA3_512)
  ]

mechName :: Text -> Text
mechName suffix = "CKM_" <> suffix

caseTable :: IO ()
caseTable = do
  assertEqual "recipe count" 10 (length ecdsaRecipes)
  mapM_ (\(suffix, stem, _alg) -> do
    let name = mechName suffix
        found = [ r | r <- ecdsaRecipes, reName r == name ]
    case found of
      [r] -> assertEqual ("digest " ++ T.unpack name) stem (reDigestStem r)
      rs -> assertFailure ("rows " ++ T.unpack name ++ ": " ++ show (length rs))
    ) groupShape

caseLookup :: IO ()
caseLookup = do
  mapM_ (\(suffix, _, _) -> do
    let name = mechName suffix
    case ecdsaRecipeFor (MechanismId (mustGeneratedId name)) of
      Nothing -> assertFailure ("unresolved " ++ T.unpack name)
      Just r -> assertEqual ("lookup " ++ T.unpack name) name (reName r)
    ) groupShape
  assertEqual "unknown id has no recipe" Nothing
    (ecdsaRecipeFor (MechanismId 0x4712))
  assertEqual "ECDH has no ECDSA recipe" Nothing
    (ecdsaRecipeFor (MechanismId (ckm_ECDH1_DERIVE)))
  assertEqual "EdDSA has no ECDSA recipe" Nothing
    (ecdsaRecipeFor (MechanismId (ckm_EDDSA)))

caseCodec :: IO ()
caseCodec = do
  assertEqual "ecdsa codec" (ParameterCodec "sig-encoding" 1) ecdsaCodec
  mapM_ (\(suffix, _, _) -> do
    let name = mechName suffix
    case ecdsaRecipeFor (MechanismId (mustGeneratedId name)) of
      Nothing -> assertFailure ("unresolved " ++ T.unpack name)
      Just r -> assertEqual ("codec " ++ T.unpack name) ecdsaCodec
        (ecdsaCodecFor r)
    ) groupShape
  assertEqual "RAW encodes" (Just "RAW") (ecdsaEncodingOf "RAW")
  assertEqual "DER encodes" (Just "DER") (ecdsaEncodingOf "DER")
  assertEqual "empty defaults DER" (Just "DER") (ecdsaEncodingOf BS.empty)
  assertEqual "PEM refused" Nothing (ecdsaEncodingOf "PEM")
  assertEqual "lowercase refused" Nothing (ecdsaEncodingOf "der")

recipeOf :: Text -> EcdsaRecipe
recipeOf name =
  case ecdsaRecipeFor (MechanismId (mustGeneratedId name)) of
    Just r -> r
    Nothing -> error ("test recipe missing: " ++ T.unpack name)

caseParams :: IO ()
caseParams = do
  let r = recipeOf "CKM_ECDSA_SHA256"
  assertBool "RAW valid" (ecdsaParamsValid r "RAW")
  assertBool "DER valid" (ecdsaParamsValid r "DER")
  assertBool "empty valid" (ecdsaParamsValid r BS.empty)
  assertBool "PEM refused" (not (ecdsaParamsValid r "PEM"))
  assertBool "lowercase refused" (not (ecdsaParamsValid r "der"))
  let raw = recipeOf "CKM_ECDSA"
  assertBool "raw RAW valid" (ecdsaParamsValid raw "RAW")
  assertBool "raw empty valid" (ecdsaParamsValid raw BS.empty)
  assertBool "raw PEM refused" (not (ecdsaParamsValid raw "PEM"))
  mapM_ (\(suffix, _, _) -> do
    let rr = recipeOf (mechName suffix)
    mapM_ (\p -> assertBool ("valid " ++ T.unpack suffix ++ "/" ++ show p)
      (ecdsaParamsValid rr p)) ["RAW", "DER", BS.empty]
    assertBool ("refused " ++ T.unpack suffix)
      (not (ecdsaParamsValid rr "PEM"))
    ) groupShape

testSession :: SessionState
testSession = SessionState
  { ssId = SessionId 1
  , ssSlot = SlotId 7
  , ssRevision = Revision 1
  , ssGeneration = Generation 1
  , ssReadOnly = False
  , ssLogin = LoginPublic
  , ssOps = emptySessionOps
  }

ecdsaMech, rawMech :: MechanismId
ecdsaMech = MechanismId (ckm_ECDSA_SHA256)
rawMech = MechanismId (ckm_ECDSA)

testEnv :: OpEnv
testEnv = OpEnv
  { oeRegistry = curatedRegistry
  , oeCaps = mkCapabilities [(ecdsaMech, OpSign), (rawMech, OpSign)]
  , oeModel = emptyModel
  }

-- | Unknown handle: valid parameters proceed PAST the parameter check
-- to key resolution (proving acceptance); bad parameters stop at
-- 'CKR_ARGUMENTS_BAD'.
badKey :: KeyPolicy
badKey = KeyPolicy (ExternalHandle 999) [OpSign] False

runInit :: InitArgs -> ReturnCode
runInit args = ioCode (snd (initOperation testEnv emptySessionOps testSession args))

caseInitParams :: IO ()
caseInitParams = do
  assertEqual "PEM refused" CKR_ARGUMENTS_BAD
    (runInit (InitArgs OpSign ecdsaMech "PEM" (Just badKey) Nothing Nothing))
  assertEqual "DER passes params" CKR_OBJECT_HANDLE_INVALID
    (runInit (InitArgs OpSign ecdsaMech "DER" (Just badKey) Nothing Nothing))
  assertEqual "empty passes params" CKR_OBJECT_HANDLE_INVALID
    (runInit (InitArgs OpSign ecdsaMech BS.empty (Just badKey) Nothing Nothing))
  assertEqual "raw PEM refused" CKR_ARGUMENTS_BAD
    (runInit (InitArgs OpSign rawMech "PEM" (Just badKey) Nothing Nothing))
  assertEqual "raw RAW passes params" CKR_OBJECT_HANDLE_INVALID
    (runInit (InitArgs OpSign rawMech "RAW" (Just badKey) Nothing Nothing))

hex :: String -> BS.ByteString
hex s = BS.pack (go (filter isHexDigit s))
  where
    go [] = []
    go (a : b : rest) = fromIntegral (digitToInt a * 16 + digitToInt b) : go rest
    go [_] = error "hex: odd digit count"

-- | Real key bytes: the P-256 SPKI + PKCS#8 from the OpenSSLSpec
-- fixtures and the P-384/P-521 SPKIs (pinned-CLI genpkey).
p256Pub, p256Priv, p384Pub, p521Pub :: KeyMaterial
p256Pub = KeyDer (hex "3059301306072a8648ce3d020106082a8648ce3d03010703420004a348bab88ded75858acef31e9afa0ef8680ad8ec1196227b10083a630f029ecfc5503e37b76e2538f9ec2ceb6aa766cc7948071e6c39b9a93f0c54d5f7b12086")
p256Priv = KeyDer (hex "308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b0201010420e9032e4f06ee6b5397252cfb48e73a8d3f7717d4024dd4cc5b98bbf041c11bb3a14403420004a348bab88ded75858acef31e9afa0ef8680ad8ec1196227b10083a630f029ecfc5503e37b76e2538f9ec2ceb6aa766cc7948071e6c39b9a93f0c54d5f7b12086")
p384Pub = KeyDer (hex "3076301006072a8648ce3d020106052b8104002203620004467ab2e9c927f143e9f6151006e492da4d11c9e079e339f6086dfd988bd0cac51e25adf31d504a7c730a94c1c4b3bb880cffcceaf56ebc0c1a42e04051e8d11e409440f6a4924c1cfea44e8858601cd2a041d7340fe670712e91ca3ec5389a0c")
p521Pub = KeyDer (hex "30819b301006072a8648ce3d020106052b810400230381860004019eed1a84c846d69d26a869d864b0d1bf557cc7320ce1d8018f22f3b963f6b4c136b38d44c8cb2e21218e96f93aa82459dfb186d80fe06db19cc3c49989e1da9c1701a6889745283941b46bb94ab6f59ad10786191c910aa0183b702b25cd18de9afa5731805cab4f7e3309226b19e397fbaed8b54a03e2e9e1e79ec3862f0ca47a1fc9")

caseCurveSniff :: IO ()
caseCurveSniff = do
  assertEqual "P-256 SPKI" (Just "P-256") (ecCurveOfKey p256Pub)
  assertEqual "P-256 PKCS#8" (Just "P-256") (ecCurveOfKey p256Priv)
  assertEqual "P-384 SPKI" (Just "P-384") (ecCurveOfKey p384Pub)
  assertEqual "P-521 SPKI" (Just "P-521") (ecCurveOfKey p521Pub)
  assertEqual "raw bytes unscannable" Nothing
    (ecCurveOfKey (KeyBytes (BS.replicate 32 0)))
  assertEqual "garbage unscannable" Nothing
    (ecCurveOfKey (KeyDer "bogus"))
  assertEqual "RSA SPKI unscannable" Nothing
    (ecCurveOfKey (KeyDer (hex "30820122300d06092a864886f70d01010105000382010f00")))

caseDriverMap :: IO ()
caseDriverMap = do
  let sha256 = MechanismId (ckm_ECDSA_SHA256)
  assertEqual "sha256 DER P-256"
    (Just (SigECDSA (EcSpec "P-256" "DER") (Just D_SHA256)))
    (ecdsaSpecFor sha256 "DER" p256Pub)
  assertEqual "sha256 empty defaults DER"
    (Just (SigECDSA (EcSpec "P-256" "DER") (Just D_SHA256)))
    (ecdsaSpecFor sha256 BS.empty p256Priv)
  assertEqual "sha256 RAW P-384"
    (Just (SigECDSA (EcSpec "P-384" "RAW") (Just D_SHA256)))
    (ecdsaSpecFor sha256 "RAW" p384Pub)
  assertEqual "sha256 P-521"
    (Just (SigECDSA (EcSpec "P-521" "DER") (Just D_SHA256)))
    (ecdsaSpecFor sha256 "DER" p521Pub)
  assertEqual "raw row, no digest"
    (Just (SigECDSA (EcSpec "P-256" "DER") Nothing))
    (ecdsaSpecFor rawMech "DER" p256Pub)
  assertEqual "PEM refused" Nothing
    (ecdsaSpecFor sha256 "PEM" p256Pub)
  assertEqual "raw key falls back to the P-256 label (key shape is the backend's call)"
    (Just (SigECDSA (EcSpec "P-256" "DER") (Just D_SHA256)))
    (ecdsaSpecFor sha256 "DER" (KeyBytes (BS.replicate 32 0)))
  assertEqual "non-ECDSA uncovered" Nothing
    (ecdsaSpecFor (MechanismId (ckm_SHA256_RSA_PKCS)) "DER" p256Pub)
  -- Whole-table agreement: every (recipe, encoding, curve) triple maps.
  mapM_ (\(suffix, _stem, alg) -> do
    let mech = MechanismId (mustGeneratedId (mechName suffix))
    mapM_ (\(key, curve) ->
      mapM_ (\enc ->
        assertEqual ("map " ++ T.unpack suffix ++ "/" ++ curve ++ "/" ++ enc)
          (Just (SigECDSA (EcSpec curve enc) alg))
          (ecdsaSpecFor mech (if enc == "DER" then "DER" else "RAW") key)
        ) ["DER", "RAW"]
      ) [(p256Pub, "P-256"), (p384Pub, "P-384"), (p521Pub, "P-521")]
    ) groupShape
