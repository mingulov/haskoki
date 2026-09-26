{- | ML-DSA recipe tests.

The ML-DSA group: one header mechanism, @CKM_ML_DSA@, with the
optional @CK_SIGN_ADDITIONAL_CONTEXT@ parameter shape —
@mldsa-params\/1@: a hedge word plus a context string (our
engine convention). The struct is OPTIONAL (OASIS v3.2
§ML-DSA Signature: no parameter means hedge-preferred with an
empty context — the opposite of EdDSA): missing parameters
decode to the default and validate. All three hedge variants
serve (preferred/required ride the provider default, proven
hedged; deterministic sets the provider @deterministic@ param),
context 0..255 serves (the FIPS 204 bound); hedge words past 2
and longer contexts refuse at the recipe. The level label
comes from the key's SPKI OID. @CKM_HASH_ML_DSA@ and its
10 hash-specific variants stay catalog-only (the pinned
provider refuses an explicit digest — no DIY domain
separation), and @CKM_ML_DSA_EXTERNAL_MU[_GEN]@ are out of
scope (absent from the OASIS 3.2 header).
'Haskoki.Recipe.MlDsa' owns the group's canonical codec,
parameter validation, and mechanism table; these tests pin the
recipe and its consumers:

* the model init path enforces ML-DSA parameters
  ('validateInit', 'CKR_ARGUMENTS_BAD'; empty passes);
* the driver maps the covered (mechanism, params, key) triple
  to its backend 'SigSpec' ('mldsaSpecFor' agrees with the
  recipe table; the level label comes from the key's SPKI OID,
  defaulting to ML-DSA-44 — key shape is the backend's call);
* engines execute the pinned specs on all three levels
  (SyntheticSpec roundtrips, OpenSSLSpec interop vectors
  against the pinned libcrypto).
-}
{-# LANGUAGE OverloadedStrings #-}
module RecipeMlDsaSpec (spec) where

import qualified Data.ByteString as BS
import Data.Char (digitToInt, isHexDigit)
import Data.Text (Text)
import qualified Data.Text as T
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertBool, assertEqual, assertFailure, testCase)

import Haskoki.Engine.Backend
  ( KeyMaterial (..)
  , PqcSigAlg (..)
  , SigSpec (..)
  )
import Haskoki.Engine.Driver (mldsaLevelOfKey, mldsaSpecFor)
import Haskoki.Model (SessionState (..), emptyModel)
import Haskoki.Operation
  ( InitArgs (..)
  , InitOutcome (..)
  , KeyPolicy (..)
  , OpEnv (..)
  , emptySessionOps
  , initOperation
  )
import Haskoki.Recipe.MlDsa
  ( MldsaHedge (..)
  , MldsaRecipe (..)
  , decodeMldsaParams
  , encodeMldsaParams
  , mldsaCodec
  , mldsaCodecFor
  , mldsaLevelOfDer
  , mldsaParamsValid
  , mldsaRecipeFor
  , mldsaRecipes
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
spec = testGroup "ML-DSA recipe"
  [ testCase "recipe table covers CKM_ML_DSA" caseTable
  , testCase "recipe lookup resolves by id" caseLookup
  , testCase "codec is mldsa-params/1" caseCodec
  , testCase "params: all hedges plus short contexts" caseParams
  , testCase "init enforces ML-DSA params" caseInitParams
  , testCase "driver maps the triple to its SigSpec" caseDriverMap
  , testCase "level sniff reads the SPKI OID" caseLevelSniff
  ]

caseTable :: IO ()
caseTable = do
  assertEqual "recipe count" 1 (length mldsaRecipes)
  case mldsaRecipes of
    [r] -> assertEqual "row name" "CKM_ML_DSA" (rmlName r)
    rs -> assertFailure ("rows: " ++ show (length rs))

caseLookup :: IO ()
caseLookup = do
  case mldsaRecipeFor (MechanismId (mustGeneratedId "CKM_ML_DSA")) of
    Nothing -> assertFailure "CKM_ML_DSA unresolved"
    Just r -> assertEqual "lookup CKM_ML_DSA" "CKM_ML_DSA" (rmlName r)
  assertEqual "unknown id has no recipe" Nothing
    (mldsaRecipeFor (MechanismId 0x4712))
  assertEqual "ECDSA has no ML-DSA recipe" Nothing
    (mldsaRecipeFor (MechanismId (ckm_ECDSA)))
  assertEqual "DSA has no ML-DSA recipe" Nothing
    (mldsaRecipeFor (MechanismId (ckm_DSA)))
  assertEqual "EdDSA has no ML-DSA recipe" Nothing
    (mldsaRecipeFor (MechanismId (ckm_EDDSA)))
  assertEqual "raw id resolves" (Just "CKM_ML_DSA")
    (rmlName <$> mldsaRecipeFor (MechanismId (ckm_ML_DSA)))

-- | Canonical default-params image: two zero words (hedge 0 =
-- preferred, length 0).
defaultImage :: BS.ByteString
defaultImage = BS.replicate 16 0x00

caseCodec :: IO ()
caseCodec = do
  assertEqual "mldsa codec" (ParameterCodec "mldsa-params" 1) mldsaCodec
  case mldsaRecipeFor (MechanismId (ckm_ML_DSA)) of
    Nothing -> assertFailure "CKM_ML_DSA unresolved"
    Just r -> assertEqual "codec row" mldsaCodec (mldsaCodecFor r)
  assertEqual "default encodes to two zero words" defaultImage
    (encodeMldsaParams HedgePreferred BS.empty)
  assertEqual "empty decodes to the default (struct optional)" (Just (HedgePreferred, BS.empty))
    (decodeMldsaParams BS.empty)
  assertEqual "default image decodes" (Just (HedgePreferred, BS.empty))
    (decodeMldsaParams defaultImage)
  assertEqual "hedge roundtrips" (Just (HedgeRequired, BS.empty))
    (decodeMldsaParams (encodeMldsaParams HedgeRequired BS.empty))
  assertEqual "deterministic roundtrips" (Just (HedgeDeterministic, BS.empty))
    (decodeMldsaParams (encodeMldsaParams HedgeDeterministic BS.empty))
  assertEqual "context roundtrips" (Just (HedgePreferred, "CTX"))
    (decodeMldsaParams (encodeMldsaParams HedgePreferred "CTX"))
  assertEqual "deterministic context roundtrips" (Just (HedgeDeterministic, "CTX"))
    (decodeMldsaParams (encodeMldsaParams HedgeDeterministic "CTX"))

recipeOf :: Text -> MldsaRecipe
recipeOf name =
  case mldsaRecipeFor (MechanismId (mustGeneratedId name)) of
    Just r -> r
    Nothing -> error ("test recipe missing: " ++ T.unpack name)

-- | Big-endian u64 word (canonical codec byte order).
word64 :: Int -> BS.ByteString
word64 n = BS.pack [fromIntegral ((n `div` (256 ^ s)) `mod` 256) | s <- [7, 6 .. 0]]

caseParams :: IO ()
caseParams = do
  let r = recipeOf "CKM_ML_DSA"
  assertBool "empty valid (struct optional)" (mldsaParamsValid r BS.empty)
  assertBool "default image valid" (mldsaParamsValid r defaultImage)
  assertBool "preferred valid"
    (mldsaParamsValid r (encodeMldsaParams HedgePreferred BS.empty))
  assertBool "required valid"
    (mldsaParamsValid r (encodeMldsaParams HedgeRequired BS.empty))
  assertBool "deterministic valid"
    (mldsaParamsValid r (encodeMldsaParams HedgeDeterministic BS.empty))
  assertBool "context valid"
    (mldsaParamsValid r (encodeMldsaParams HedgePreferred "CTX"))
  assertBool "255-byte context valid"
    (mldsaParamsValid r (encodeMldsaParams HedgePreferred (BS.replicate 255 0x41)))
  assertBool "256-byte context refused"
    (not (mldsaParamsValid r (encodeMldsaParams HedgePreferred (BS.replicate 256 0x41))))
  assertBool "hedge word 3 refused"
    (not (mldsaParamsValid r (word64 3 <> word64 0)))
  -- Malformed sweep: validity agrees with (decoder + FIPS
  -- context bound) on every input (the two entry points cannot
  -- drift apart).
  let bogus =
        [ "RAW", "PEM", BS.singleton 0x00, BS.replicate 8 0x00
        , BS.replicate 15 0x00, BS.replicate 17 0x00
        , word64 3 <> word64 0
        , word64 0 <> word64 5 <> "AB"
        , defaultImage <> BS.singleton 0x00
        , encodeMldsaParams HedgePreferred BS.empty <> "trailing"
        , encodeMldsaParams HedgePreferred (BS.replicate 256 0x41)
        , BS.replicate 64 0x41
        ]
      expect p = case decodeMldsaParams p of
        Just (_, ctx) -> BS.length ctx <= 255
        Nothing -> False
  mapM_ (\p -> do
    assertBool ("bogus refused " ++ show p) (not (mldsaParamsValid r p))
    assertEqual ("validity agrees " ++ show p) (expect p) (mldsaParamsValid r p)
    ) bogus
  mapM_ (\p ->
    assertEqual ("validity agrees " ++ show p) (expect p) (mldsaParamsValid r p)
    ) [BS.empty, defaultImage, encodeMldsaParams HedgeDeterministic "CTX"]

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

mldsaMech :: MechanismId
mldsaMech = MechanismId (ckm_ML_DSA)

testEnv :: OpEnv
testEnv = OpEnv
  { oeRegistry = curatedRegistry
  , oeCaps = mkCapabilities [(mldsaMech, OpSign)]
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
  assertEqual "empty passes params (struct optional)" CKR_OBJECT_HANDLE_INVALID
    (runInit (InitArgs OpSign mldsaMech BS.empty (Just badKey) Nothing Nothing))
  assertEqual "default passes params" CKR_OBJECT_HANDLE_INVALID
    (runInit (InitArgs OpSign mldsaMech defaultImage (Just badKey) Nothing Nothing))
  assertEqual "context passes params" CKR_OBJECT_HANDLE_INVALID
    (runInit (InitArgs OpSign mldsaMech (encodeMldsaParams HedgePreferred "CTX") (Just badKey) Nothing Nothing))
  assertEqual "deterministic passes params" CKR_OBJECT_HANDLE_INVALID
    (runInit (InitArgs OpSign mldsaMech (encodeMldsaParams HedgeDeterministic BS.empty) (Just badKey) Nothing Nothing))
  assertEqual "hedge word 3 refused" CKR_ARGUMENTS_BAD
    (runInit (InitArgs OpSign mldsaMech (word64 3 <> word64 0) (Just badKey) Nothing Nothing))
  assertEqual "overlong context refused" CKR_ARGUMENTS_BAD
    (runInit (InitArgs OpSign mldsaMech (encodeMldsaParams HedgePreferred (BS.replicate 256 0x41)) (Just badKey) Nothing Nothing))
  assertEqual "malformed refused" CKR_ARGUMENTS_BAD
    (runInit (InitArgs OpSign mldsaMech "PEM" (Just badKey) Nothing Nothing))

-- | Real key bytes: ML-DSA SPKI + PKCS#8 per level (pinned-CLI
-- genpkey fixtures under tests/fixtures/).
loadKeys :: IO [(PqcSigAlg, KeyMaterial, KeyMaterial)]
loadKeys = mapM load
  [ (ML_DSA_44, "44"), (ML_DSA_65, "65"), (ML_DSA_87, "87") ]
  where
    load (alg, tag) = do
      pub <- BS.readFile ("tests/fixtures/mldsa" ++ tag ++ "-pub.der")
      priv <- BS.readFile ("tests/fixtures/mldsa" ++ tag ++ "-priv.der")
      pure (alg, KeyDer pub, KeyDer priv)

caseDriverMap :: IO ()
caseDriverMap = do
  keys <- loadKeys
  let mldsa = MechanismId (ckm_ML_DSA)
  mapM_ (\(alg, pub, priv) -> do
    assertEqual ("SPKI maps, level " ++ show alg)
      (Just (SigMLDSA alg False BS.empty True))
      (mldsaSpecFor mldsa defaultImage pub)
    assertEqual ("PKCS#8 maps, level " ++ show alg)
      (Just (SigMLDSA alg False BS.empty True))
      (mldsaSpecFor mldsa BS.empty priv)
    assertEqual ("context rides, level " ++ show alg)
      (Just (SigMLDSA alg False "CTX" True))
      (mldsaSpecFor mldsa (encodeMldsaParams HedgePreferred "CTX") pub)
    assertEqual ("required rides hedged, level " ++ show alg)
      (Just (SigMLDSA alg False BS.empty True))
      (mldsaSpecFor mldsa (encodeMldsaParams HedgeRequired BS.empty) pub)
    assertEqual ("deterministic clears hedge, level " ++ show alg)
      (Just (SigMLDSA alg False BS.empty False))
      (mldsaSpecFor mldsa (encodeMldsaParams HedgeDeterministic BS.empty) pub)
    -- Production shape: stored keys resolve as KeyBytes carrying
    -- DER (stdResolver); both constructors must sniff (the
    -- EdDSA lesson).
    case pub of
      KeyDer der -> assertEqual ("KeyBytes sniffs, level " ++ show alg)
        (Just (SigMLDSA alg False BS.empty True))
        (mldsaSpecFor mldsa defaultImage (KeyBytes der))
      _ -> assertFailure "fixture not DER"
    ) keys
  (_, pub44, _) <- headOf keys
  assertEqual "hedge word 3 refused" Nothing
    (mldsaSpecFor mldsa (word64 3 <> word64 0) pub44)
  assertEqual "overlong context refused" Nothing
    (mldsaSpecFor mldsa (encodeMldsaParams HedgePreferred (BS.replicate 256 0x41)) pub44)
  assertEqual "malformed refused" Nothing
    (mldsaSpecFor mldsa "PEM" pub44)
  assertEqual "non-ML-DSA uncovered" Nothing
    (mldsaSpecFor (MechanismId (ckm_EDDSA)) BS.empty pub44)
  assertEqual "ECDSA uncovered" Nothing
    (mldsaSpecFor (MechanismId (ckm_ECDSA)) BS.empty pub44)
  assertEqual "unscannable key defaults ML-DSA-44"
    (Just (SigMLDSA ML_DSA_44 False BS.empty True))
    (mldsaSpecFor mldsa defaultImage (KeyBytes (BS.replicate 32 0)))
  where
    headOf (x : _) = pure x
    headOf [] = assertFailure "no fixtures" >> undefined

caseLevelSniff :: IO ()
caseLevelSniff = do
  keys <- loadKeys
  mapM_ (\(alg, pub, priv) -> do
    assertEqual ("SPKI sniffs " ++ show alg) (Just alg) (mldsaLevelOfKey pub)
    assertEqual ("PKCS#8 sniffs " ++ show alg) (Just alg) (mldsaLevelOfKey priv)
    case pub of
      KeyDer der -> assertEqual ("SPKI as KeyBytes " ++ show alg) (Just alg)
        (mldsaLevelOfKey (KeyBytes der))
      _ -> assertFailure "fixture not DER"
    ) keys
  assertEqual "raw bytes unscannable" Nothing
    (mldsaLevelOfKey (KeyBytes (BS.replicate 32 0)))
  assertEqual "garbage unscannable" Nothing
    (mldsaLevelOfKey (KeyDer "bogus"))
  assertEqual "Ed25519 SPKI unscannable" Nothing
    (mldsaLevelOfKey (KeyDer ed19Pub))
  assertEqual "P-256 SPKI unscannable" Nothing
    (mldsaLevelOfKey (KeyDer p256Pub))

-- | Foreign keys the ML-DSA sniff must never claim (the
-- RecipeEddsaSpec Ed25519 SPKI and the RecipeEcdsaSpec P-256
-- SPKI).
ed19Pub, p256Pub :: BS.ByteString
ed19Pub = hex "302a300506032b6570032100e3066819aa9f7d91c3c4ebad5584adeef588d8a1cbf2a09a8081d41cc5183402"
p256Pub = hex "3059301306072a8648ce3d020106082a8648ce3d03010703420004a348bab88ded75858acef31e9afa0ef8680ad8ec1196227b10083a630f029ecfc5503e37b76e2538f9ec2ceb6aa766cc7948071e6c39b9a93f0c54d5f7b12086"

hex :: String -> BS.ByteString
hex s = BS.pack (go (filter isHexDigit s))
  where
    go [] = []
    go (a : b : rest) = fromIntegral (digitToInt a * 16 + digitToInt b) : go rest
    go [_] = error "hex: odd digit count"
