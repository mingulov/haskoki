{- | EdDSA recipe tests.

The EdDSA group: one header mechanism, @CKM_EDDSA@, with the
pure-EdDSA parameter shape — @eddsa-params\/1@: a prehash flag
plus a context string (our engine convention; empty defaults to
pure: phFlag clear, empty context — the only combination the
pinned provider serves). Non-pure combinations (prehash set or
non-empty context) translate to the canonical image and refuse
at the recipe; @CKM_XEDDSA@ stays an honest named gap (no
provider equivalent).
'Haskoki.Recipe.Eddsa' owns the group's canonical codec,
parameter validation, and mechanism table; these tests pin the
recipe and its consumers:

* the model init path enforces EdDSA parameters ('validateInit',
  'CKR_ARGUMENTS_BAD');
* the driver maps the covered (mechanism, params, key) triple
  to its backend 'SigSpec' ('eddsaSpecFor' agrees with the
  recipe table; the curve label comes from the key's SPKI OID,
  the ECDSA precedent — key shape is the backend's call);
* engines execute the pinned specs on both served curves
  (SyntheticSpec roundtrips, OpenSSLSpec interop vectors
  against the pinned libcrypto).
-}
{-# LANGUAGE OverloadedStrings #-}
module RecipeEddsaSpec (spec) where

import qualified Data.ByteString as BS
import Data.Char (digitToInt, isHexDigit)
import Data.Maybe (isJust)
import Data.Text (Text)
import qualified Data.Text as T
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertBool, assertEqual, assertFailure, testCase)

import Haskoki.Engine.Backend
  ( EcSpec (..)
  , KeyMaterial (..)
  , SigSpec (..)
  )
import Haskoki.Engine.Driver (eddsaCurveOfKey, eddsaSpecFor)
import Haskoki.Model (SessionState (..), emptyModel)
import Haskoki.Operation
  ( InitArgs (..)
  , InitOutcome (..)
  , KeyPolicy (..)
  , OpEnv (..)
  , emptySessionOps
  , initOperation
  )
import Haskoki.Recipe.Eddsa
  ( EddsaRecipe (..)
  , decodeEddsaParams
  , eddsaCodec
  , eddsaCodecFor
  , eddsaParamsValid
  , eddsaRecipeFor
  , eddsaRecipes
  , encodeEddsaParams
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
  , ckm_DSA
  , ckm_ECDSA
  , ckm_EDDSA
  , ckm_ML_DSA
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
spec = testGroup "EdDSA recipe"
  [ testCase "recipe table covers CKM_EDDSA" caseTable
  , testCase "recipe lookup resolves by id" caseLookup
  , testCase "codec is eddsa-params/1" caseCodec
  , testCase "params: pure only" caseParams
  , testCase "init enforces EdDSA params" caseInitParams
  , testCase "driver maps the triple to its SigSpec" caseDriverMap
  , testCase "curve sniff reads the SPKI OID" caseCurveSniff
  ]

caseTable :: IO ()
caseTable = do
  assertEqual "recipe count" 1 (length eddsaRecipes)
  case eddsaRecipes of
    [r] -> assertEqual "row name" "CKM_EDDSA" (redName r)
    rs -> assertFailure ("rows: " ++ show (length rs))

caseLookup :: IO ()
caseLookup = do
  case eddsaRecipeFor (MechanismId (mustGeneratedId "CKM_EDDSA")) of
    Nothing -> assertFailure "CKM_EDDSA unresolved"
    Just r -> assertEqual "lookup CKM_EDDSA" "CKM_EDDSA" (redName r)
  assertEqual "unknown id has no recipe" Nothing
    (eddsaRecipeFor (MechanismId 0x4712))
  assertEqual "ECDSA has no EdDSA recipe" Nothing
    (eddsaRecipeFor (MechanismId (ckm_ECDSA)))
  assertEqual "DSA has no EdDSA recipe" Nothing
    (eddsaRecipeFor (MechanismId (ckm_DSA)))
  assertEqual "ML-DSA has no EdDSA recipe" Nothing
    (eddsaRecipeFor (MechanismId (ckm_ML_DSA)))
  assertEqual "raw id resolves" (Just "CKM_EDDSA")
    (redName <$> eddsaRecipeFor (MechanismId (ckm_EDDSA)))

-- | Canonical pure-params image: two zero words (flag, length).
pureImage :: BS.ByteString
pureImage = BS.replicate 16 0x00

caseCodec :: IO ()
caseCodec = do
  assertEqual "eddsa codec" (ParameterCodec "eddsa-params" 1) eddsaCodec
  case eddsaRecipeFor (MechanismId (ckm_EDDSA)) of
    Nothing -> assertFailure "CKM_EDDSA unresolved"
    Just r -> assertEqual "codec row" eddsaCodec (eddsaCodecFor r)
  assertEqual "pure encodes to two zero words" pureImage
    (encodeEddsaParams False BS.empty)
  assertEqual "empty decodes to pure (NULL means pure)" (Just (False, BS.empty))
    (decodeEddsaParams BS.empty)
  assertEqual "pure image decodes" (Just (False, BS.empty))
    (decodeEddsaParams pureImage)
  assertEqual "context roundtrips" (Just (True, "CTX"))
    (decodeEddsaParams (encodeEddsaParams True "CTX"))
  assertEqual "pure context roundtrips" (Just (False, "CTX"))
    (decodeEddsaParams (encodeEddsaParams False "CTX"))

recipeOf :: Text -> EddsaRecipe
recipeOf name =
  case eddsaRecipeFor (MechanismId (mustGeneratedId name)) of
    Just r -> r
    Nothing -> error ("test recipe missing: " ++ T.unpack name)

-- | Big-endian u64 word (canonical codec byte order).
word64 :: Int -> BS.ByteString
word64 n = BS.pack [fromIntegral ((n `div` (256 ^ s)) `mod` 256) | s <- [7, 6 .. 0]]

caseParams :: IO ()
caseParams = do
  let r = recipeOf "CKM_EDDSA"
  assertBool "empty valid (NULL means pure)" (eddsaParamsValid r BS.empty)
  assertBool "pure image valid" (eddsaParamsValid r pureImage)
  assertBool "encoded pure valid"
    (eddsaParamsValid r (encodeEddsaParams False BS.empty))
  assertBool "prehash refused"
    (not (eddsaParamsValid r (encodeEddsaParams True BS.empty)))
  assertBool "context refused"
    (not (eddsaParamsValid r (encodeEddsaParams False "CTX")))
  assertBool "prehash+context refused"
    (not (eddsaParamsValid r (encodeEddsaParams True "CTX")))
  -- Malformed sweep: validity agrees with the decoder on every
  -- input (the two entry points cannot drift apart).
  let bogus =
        [ "RAW", "PEM", BS.singleton 0x00, BS.replicate 8 0x00
        , BS.replicate 15 0x00, BS.replicate 17 0x00
        , word64 2 <> word64 0
        , word64 0 <> word64 5 <> "AB"
        , pureImage <> BS.singleton 0x00
        , encodeEddsaParams False BS.empty <> "trailing"
        , BS.replicate 64 0x41
        ]
  mapM_ (\p -> do
    assertBool ("bogus refused " ++ show p) (not (eddsaParamsValid r p))
    assertEqual ("validity agrees " ++ show p)
      (decodeEddsaParams p == Just (False, BS.empty)) (eddsaParamsValid r p)
    ) bogus
  mapM_ (\p ->
    assertEqual ("validity agrees " ++ show p)
      (decodeEddsaParams p == Just (False, BS.empty)) (eddsaParamsValid r p)
    ) [BS.empty, pureImage, encodeEddsaParams True "CTX"]

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

eddsaMech :: MechanismId
eddsaMech = MechanismId (ckm_EDDSA)

testEnv :: OpEnv
testEnv = OpEnv
  { oeRegistry = curatedRegistry
  , oeCaps = mkCapabilities [(eddsaMech, OpSign)]
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
  assertEqual "prehash refused" CKR_ARGUMENTS_BAD
    (runInit (InitArgs OpSign eddsaMech (encodeEddsaParams True BS.empty) (Just badKey) Nothing Nothing))
  assertEqual "context refused" CKR_ARGUMENTS_BAD
    (runInit (InitArgs OpSign eddsaMech (encodeEddsaParams False "CTX") (Just badKey) Nothing Nothing))
  assertEqual "malformed refused" CKR_ARGUMENTS_BAD
    (runInit (InitArgs OpSign eddsaMech "PEM" (Just badKey) Nothing Nothing))
  assertEqual "pure passes params" CKR_OBJECT_HANDLE_INVALID
    (runInit (InitArgs OpSign eddsaMech pureImage (Just badKey) Nothing Nothing))
  assertEqual "empty passes params" CKR_OBJECT_HANDLE_INVALID
    (runInit (InitArgs OpSign eddsaMech BS.empty (Just badKey) Nothing Nothing))

hex :: String -> BS.ByteString
hex s = BS.pack (go (filter isHexDigit s))
  where
    go [] = []
    go (a : b : rest) = fromIntegral (digitToInt a * 16 + digitToInt b) : go rest
    go [_] = error "hex: odd digit count"

-- | Real key bytes: Ed25519/Ed448 SPKI + PKCS#8 (pinned-CLI
-- genpkey, the KeyImportSpec goldens).
ed19Pub, ed19Priv, ed48Pub, ed48Priv :: KeyMaterial
ed19Pub = KeyDer (hex "302a300506032b6570032100e3066819aa9f7d91c3c4ebad5584adeef588d8a1cbf2a09a8081d41cc5183402")
ed19Priv = KeyDer (hex "302e020100300506032b657004220420e48c12f6fd3bd16c24e972eab3910d1053a23f9db0113d10d0835223f638dd05")
ed48Pub = KeyDer (hex "3043300506032b6571033a0086328bf04c3d241a0f05968cee630c68cdd2e2378a2f63e01ec215a661c7f83dddfddc788c1102a2529c68b8d3c0155ec9e263561e2545d280")
ed48Priv = KeyDer (hex "3047020100300506032b6571043b04398217a8d0ea3724199e10d866da9b2f582ce7c9a8aa37ad7763df96d48c210c1c3ef3fe87ad7ce40306f70747dfee39a799cd1a0ecb1481f9e1")

-- | A Weierstrass key the Edwards sniff must never claim (the
-- RecipeEcdsaSpec P-256 SPKI).
p256Pub :: KeyMaterial
p256Pub = KeyDer (hex "3059301306072a8648ce3d020106082a8648ce3d03010703420004a348bab88ded75858acef31e9afa0ef8680ad8ec1196227b10083a630f029ecfc5503e37b76e2538f9ec2ceb6aa766cc7948071e6c39b9a93f0c54d5f7b12086")

caseDriverMap :: IO ()
caseDriverMap = do
  let eddsa = MechanismId (ckm_EDDSA)
  assertEqual "Ed25519 pure image"
    (Just (SigEdDSA (EcSpec "Ed25519" "RAW") ""))
    (eddsaSpecFor eddsa pureImage ed19Pub)
  assertEqual "Ed448 pure image"
    (Just (SigEdDSA (EcSpec "Ed448" "RAW") ""))
    (eddsaSpecFor eddsa pureImage ed48Priv)
  assertEqual "Ed25519 PKCS#8"
    (Just (SigEdDSA (EcSpec "Ed25519" "RAW") ""))
    (eddsaSpecFor eddsa pureImage ed19Priv)
  assertEqual "empty maps to pure" (Just (SigEdDSA (EcSpec "Ed25519" "RAW") ""))
    (eddsaSpecFor eddsa BS.empty ed19Pub)
  assertEqual "prehash refused" Nothing
    (eddsaSpecFor eddsa (encodeEddsaParams True BS.empty) ed19Pub)
  assertEqual "context refused" Nothing
    (eddsaSpecFor eddsa (encodeEddsaParams False "CTX") ed19Pub)
  assertEqual "malformed refused" Nothing
    (eddsaSpecFor eddsa "PEM" ed19Pub)
  assertEqual "non-EdDSA uncovered" Nothing
    (eddsaSpecFor (MechanismId (ckm_SHA256_RSA_PKCS)) BS.empty ed19Pub)
  assertEqual "ECDSA uncovered" Nothing
    (eddsaSpecFor (MechanismId (ckm_ECDSA)) BS.empty ed19Pub)
  assertEqual "unscannable key defaults Ed25519"
    (Just (SigEdDSA (EcSpec "Ed25519" "RAW") ""))
    (eddsaSpecFor eddsa pureImage (KeyBytes (BS.replicate 32 0)))
  -- Production shape: stored keys resolve as KeyBytes carrying
  -- DER (stdResolver); the sniff must still find Ed448, or the
  -- shim's base-id check refuses every production Ed448 op.
  case ed48Pub of
    KeyDer der -> assertEqual "Ed448 KeyBytes sniffs Ed448"
      (Just (SigEdDSA (EcSpec "Ed448" "RAW") ""))
      (eddsaSpecFor eddsa pureImage (KeyBytes der))
    _ -> assertFailure "Ed448 fixture not DER"

caseCurveSniff :: IO ()
caseCurveSniff = do
  assertEqual "Ed25519 SPKI" (Just "Ed25519") (eddsaCurveOfKey ed19Pub)
  assertEqual "Ed25519 PKCS#8" (Just "Ed25519") (eddsaCurveOfKey ed19Priv)
  assertEqual "Ed448 SPKI" (Just "Ed448") (eddsaCurveOfKey ed48Pub)
  assertEqual "Ed448 PKCS#8" (Just "Ed448") (eddsaCurveOfKey ed48Priv)
  assertEqual "raw bytes unscannable" Nothing
    (eddsaCurveOfKey (KeyBytes (BS.replicate 32 0)))
  assertEqual "garbage unscannable" Nothing
    (eddsaCurveOfKey (KeyDer "bogus"))
  assertEqual "P-256 SPKI unscannable" Nothing
    (eddsaCurveOfKey p256Pub)
  case ed48Pub of
    KeyDer der -> assertEqual "Ed448 SPKI as KeyBytes" (Just "Ed448")
      (eddsaCurveOfKey (KeyBytes der))
    _ -> assertFailure "Ed448 fixture not DER"
