{- | ECDSA recipe tests.

The ECDSA group: 10 header mechanisms sharing the encoding
parameter shape — @sig-encoding\/1@: @"RAW"@, @"DER"@, or empty
(our engine convention selecting the signature encoding; empty
defaults to RAW per PKCS#11). Nine rows bind a digest (hash-and-sign);
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
import Data.Maybe (isJust)
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
  assertEqual "empty defaults RAW" (Just "RAW") (ecdsaEncodingOf BS.empty)
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
  -- Malformed sweep: validity agrees with the decoder on every
  -- input (the two entry points cannot drift apart).
  let bogus = ["raw", "Raw", " RAW", "RAW ", "DER ", "D", "R", "RA",
               "DERX", "RAWX", "DER\0", "RAW\0", "PEM", "der", "ber",
               BS.replicate 64 0x41, BS.singleton 0x00]
  mapM_ (\(suffix, _, _) -> do
    let rr = recipeOf (mechName suffix)
    mapM_ (\p -> do
      assertBool ("bogus refused " ++ T.unpack suffix ++ "/" ++ show p)
        (not (ecdsaParamsValid rr p))
      assertEqual ("validity agrees " ++ T.unpack suffix ++ "/" ++ show p)
        (isJust (ecdsaEncodingOf p)) (ecdsaParamsValid rr p)
      ) bogus
    mapM_ (\p ->
      assertEqual ("validity agrees " ++ T.unpack suffix ++ "/" ++ show p)
        (isJust (ecdsaEncodingOf p)) (ecdsaParamsValid rr p)
      ) ["RAW", "DER", BS.empty]
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

-- | SPKI fixtures for the 19 newly covered curves (openssl genpkey,
-- independent bytes; each embeds its curve OID from the Der table).
newCurvePubs :: [(KeyMaterial, String)]
newCurvePubs =
  [(KeyDer (hex "303e301006072a8648ce3d020106052b81040008032a000416a0827105f5da461c6b8456551c96479e221ddbdfc348e8ad4cd9282bfed43ba343eb0c58e3c13f"), "secp160r1")
  , (KeyDer (hex "303e301006072a8648ce3d020106052b8104001e032a000451d0439b8a834c8de2dd845c023986a40d838c07afaaaf97975116258713bcce59fe7ff3e52df162"), "secp160r2")
  , (KeyDer (hex "303e301006072a8648ce3d020106052b81040009032a00043f285fa190c82036ab6c9b31c1e995e3447d3d7f91ffe285144d8729ff7aecb6ab447a98dbc18c56"), "secp160k1")
  , (KeyDer (hex "3049301306072a8648ce3d020106082a8648ce3d030101033200041a6c9c7c9a3bef4d26ab08ad0439a924841cb41db7181c86fcb2cbdfe654511e249399b4b6dd8292da6f3d0146d2d75d"), "secp192r1")
  , (KeyDer (hex "3046301006072a8648ce3d020106052b8104001f033200048083f4b8bd6a82c6b64081a2ead9a197e85958918592427cb6d2fa400c05c9e5c571acfbe388bfbd1cf57ab92094b203"), "secp192k1")
  , (KeyDer (hex "304e301006072a8648ce3d020106052b81040021033a00045cfa6e7345d6ae0bfc5f4b3229f6600a5baaa4685a00f204494ef1baff5953ef78c89cb3f7666e07e689570b837d65591a5c05ac306de2d4"), "secp224r1")
  , (KeyDer (hex "304e301006072a8648ce3d020106052b81040020033a0004e793fa30dc75c0f8d619b2aaa9185918ee450fc2345fb9eaf4d34856e3e97d2beea7b12df9573b9e28bb78f2712eea349d3e0492121e9681"), "secp224k1")
  , (KeyDer (hex "3056301006072a8648ce3d020106052b8104000a034200044901fb30f1a13e9b49098d42da10e1c469c01b0d59768b57369d9130bbdcb9327b7f9a93d50924f654432becbaba0997e95010f78ae2bd79b4a82ea9ff5da937"), "secp256k1")
  , (KeyDer (hex "3052301406072a8648ce3d020106092b2403030208010105033a00041df1b6bd3135745a609e99d365532c06d196f4b22a0d8b4b2c5c2c0f618f7e497a1b11c122c9733264e465963f2c523488186d13f8241852"), "brainpoolP224r1")
  , (KeyDer (hex "305a301406072a8648ce3d020106092b2403030208010107034200040925ae97a86782195a4c24b62611fbda7eca5336866ea093d79ba4cdd2bf027367aface6d083476f6f73dfaa8cb7f1664b46883efb985e7870059f4e3ae37705"), "brainpoolP256r1")
  , (KeyDer (hex "306a301406072a8648ce3d020106092b2403030208010109035200044c77a0aad77ec23fce0cd5e3a721119bd774b48666d87fa6c5bb557e68923cee95472b42b778b2fe47ba502d4e431c8d72ad79c9745ec268756363e72fbd8eea67641f52a4c142fefd7e4c4e7e3b206b"), "brainpoolP320r1")
  , (KeyDer (hex "307a301406072a8648ce3d020106092b240303020801010b03620004229cedc4008f2a8770a12ed6b1e1769d3cbea8c10f75a7f2bec9b1b7ad9b7cd0c9c806c66a816bb0a7f8fe0da11c87b10de5a29857102238a3623b350166976565f476ff5ca6d3af8c4df8f945997c7420807a83ee84fbca873bf2fd6e0cc06a"), "brainpoolP384r1")
  , (KeyDer (hex "30819b301406072a8648ce3d020106092b240303020801010d03818200044ee5c6e894709f6e8f25c8442beff044eedf055f914c84a919e21a561266aaa8c988c0344c59e5c234f5a9a9afe2e15396ad1fa07e43300a386bbc347a01bca34912f5e30e498cf4b94d56cec741865d5c6e325ef753729c5b947a664733c2482b61a655fad69fe2fa7724520ab8a0b32074e0610e2171e34dee13ac54faa155"), "brainpoolP512r1")
  , (KeyDer (hex "305e301006072a8648ce3d020106052b81040010034a000406fa898b7c2c7ae0ce053712077903bba81ebdf164af68e5183a01a2b1c5667d389b94030068b86c84aa350b1589445ddd75f1181ec1aa900c9dd07810fa6ea26ded2c9414f31239"), "sect283k1")
  , (KeyDer (hex "305e301006072a8648ce3d020106052b81040011034a000403320369f42dee383178d8c14f902caae96044ba56d49403600e0a79616cc230b1b1b8db00c4152f325e2443d8fb18c8c42bc496cf8c311bdb1117d04fa3fb54c5120605c388366c"), "sect283r1")
  , (KeyDer (hex "307e301006072a8648ce3d020106052b81040024036a00040108d450cd3b86f9d69cec6fffd09071aec73675139eb732b1d55efd23b354f4ec1e906e8e1abf6ec23668833f3401d9068420da01e9d7c9537b6fd885735d825d5f8a74daa7f66a56a3df18c055e2ac219c8c9e057c9b75a302960bf4f17f5a13f7333a81b0512d"), "sect409k1")
  , (KeyDer (hex "307e301006072a8648ce3d020106052b81040025036a0004004f433cb18afcf0df9281e9ca5d62e2408f83f84e71f2179986235d3a18e5285cc300bc41a775ecde168b41745b14e85a63b66700db6ace1e67325ae7d42664c5b5f5b1c81e766f6a109e9417981d693feb37065da4c94ba498a25af0dd21c4e6421a1344c78262"), "sect409r1")
  , (KeyDer (hex "3081a7301006072a8648ce3d020106052b81040026038192000403dfef325f04e373e19e339efe02d26f138f3240ca8273f33ba7e1f4f1082557903e880de0165f584bd7cd1dc4e1a0aafba35a4deb12adf17668c7ce2d41be8d2631668d681d29a400989c94d0af458ba7290e927e42733b466de9ee41dbcbdd1d1866719bef6e17f96c01b8bad9b8d3218ac544f595a86e9dd91cd043b656a896c1e12811668e725ba7b58d0ef39bf3"), "sect571k1")
  , (KeyDer (hex "3081a7301006072a8648ce3d020106052b8104002703819200040325f6a9960286d997cd126f35463619027296d7bedf2190f7e5d92f8e48e8b2055e903c65dd091ba96f771e071745eeab97aa67f655f213ebb2e3f06ecbbcbd891e8c3a03ca55360674b9878ee51d97c19d73a8903bdcda8be3b80097c75ddf57a4022062f5a100f97aa9dd857ddbca706808883fec5a3ec107636be4c2b1ce4abd471edd4c354b7ea547575508778e"), "sect571r1")
  ]

caseCurveSniff :: IO ()
caseCurveSniff = do
  assertEqual "P-256 SPKI" (Just "P-256") (ecCurveOfKey p256Pub)
  assertEqual "P-256 PKCS#8" (Just "P-256") (ecCurveOfKey p256Priv)
  assertEqual "P-384 SPKI" (Just "P-384") (ecCurveOfKey p384Pub)
  assertEqual "P-521 SPKI" (Just "P-521") (ecCurveOfKey p521Pub)
  mapM_ (\(key, curve) ->
    assertEqual ("new curve SPKI " ++ curve)
      (Just (T.pack curve)) (ecCurveOfKey key)) newCurvePubs
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
  assertEqual "sha256 empty defaults RAW"
    (Just (SigECDSA (EcSpec "P-256" "RAW") (Just D_SHA256)))
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
    mapM_ (\(key, curve) -> do
      mapM_ (\enc ->
        assertEqual ("map " ++ T.unpack suffix ++ "/" ++ curve ++ "/" ++ enc)
          (Just (SigECDSA (EcSpec curve enc) alg))
          (ecdsaSpecFor mech (if enc == "DER" then "DER" else "RAW") key)
        ) ["DER", "RAW"]
      -- Empty parameters (the only shape PKCS#11 callers send)
      -- default to RAW on every row and curve.
      assertEqual ("empty defaults RAW " ++ T.unpack suffix ++ "/" ++ curve)
        (Just (SigECDSA (EcSpec curve "RAW") alg))
        (ecdsaSpecFor mech BS.empty key)
      ) ([(p256Pub, "P-256"), (p384Pub, "P-384"), (p521Pub, "P-521")] ++ newCurvePubs)
    ) groupShape
