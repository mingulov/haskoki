{- | SLH-DSA recipe tests.

The SLH-DSA group: one header mechanism, @CKM_SLH_DSA@, with the
optional @CK_SIGN_ADDITIONAL_CONTEXT@ parameter shape —
@slhdsa-params\/1@: a hedge word plus a context string (our
engine convention, the ML-DSA mirror). The struct is OPTIONAL
(OASIS v3.2 §SLH-DSA Signature: no parameter means
hedge-preferred with an empty context): missing parameters
decode to the default and validate. All three hedge variants
serve (preferred/required ride the provider default, proven
hedged; deterministic sets the provider @deterministic@ param),
context 0..255 serves (the FIPS 205 bound); hedge words past 2
and longer contexts refuse at the recipe. The parameter set
rides the key (@CKA_PARAMETER_SET@ on the object, the
algorithm OID in the DER), and keygen
(@CKM_SLH_DSA_KEY_PAIR_GEN@) takes no parameter — the set
comes from the public-key template. @CKM_HASH_SLH_DSA@ and its
11 hash-specific variants stay catalog-only (the pinned
provider refuses an explicit digest — no DIY domain
separation).
'Haskoki.Recipe.SlhDsa' owns the group's canonical codec,
parameter validation, and mechanism table; these tests pin the
recipe and its consumers:

* the model init path enforces SLH-DSA parameters
  ('validateInit', 'CKR_ARGUMENTS_BAD'; empty passes);
* the driver maps the covered (mechanism, params, key) triple
  to its backend 'SigSpec' ('slhdsaSpecFor' agrees with the
  recipe table; the set label comes from the key's SPKI OID,
  defaulting to SLH-DSA-SHA2-128s — key shape is the backend's
  call);
* engines execute the pinned specs on all twelve sets
  (SyntheticSpec roundtrips, OpenSSLSpec interop vectors
  against the pinned libcrypto).
-}
{-# LANGUAGE OverloadedStrings #-}
module RecipeSlhDsaSpec (spec) where

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
import Haskoki.Engine.Driver (slhdsaLevelOfKey, slhdsaSpecFor)
import Haskoki.Model (SessionState (..), emptyModel)
import Haskoki.Operation
  ( InitArgs (..)
  , InitOutcome (..)
  , KeyPolicy (..)
  , OpEnv (..)
  , emptySessionOps
  , initOperation
  )
import Haskoki.Recipe.SlhDsa
  ( SlhdsaHedge (..)
  , SlhdsaRecipe (..)
  , decodeSlhdsaParams
  , encodeSlhdsaParams
  , slhdsaCodec
  , slhdsaCodecFor
  , slhdsaParamsValid
  , slhdsaRecipeFor
  , slhdsaRecipes
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
  , ckm_SLH_DSA
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
spec = testGroup "SLH-DSA recipe"
  [ testCase "recipe table covers CKM_SLH_DSA" caseTable
  , testCase "recipe lookup resolves by id" caseLookup
  , testCase "codec is slhdsa-params/1" caseCodec
  , testCase "params: all hedges plus short contexts" caseParams
  , testCase "init enforces SLH-DSA params" caseInitParams
  , testCase "driver maps the triple to its SigSpec" caseDriverMap
  , testCase "level sniff reads the SPKI OID" caseLevelSniff
  ]

caseTable :: IO ()
caseTable = do
  assertEqual "recipe count" 1 (length slhdsaRecipes)
  case slhdsaRecipes of
    [r] -> assertEqual "row name" "CKM_SLH_DSA" (rslName r)
    rs -> assertFailure ("rows: " ++ show (length rs))

caseLookup :: IO ()
caseLookup = do
  case slhdsaRecipeFor (MechanismId (mustGeneratedId "CKM_SLH_DSA")) of
    Nothing -> assertFailure "CKM_SLH_DSA unresolved"
    Just r -> assertEqual "lookup CKM_SLH_DSA" "CKM_SLH_DSA" (rslName r)
  assertEqual "unknown id has no recipe" Nothing
    (slhdsaRecipeFor (MechanismId 0x4712))
  assertEqual "ECDSA has no SLH-DSA recipe" Nothing
    (slhdsaRecipeFor (MechanismId (ckm_ECDSA)))
  assertEqual "DSA has no SLH-DSA recipe" Nothing
    (slhdsaRecipeFor (MechanismId (ckm_DSA)))
  assertEqual "EdDSA has no SLH-DSA recipe" Nothing
    (slhdsaRecipeFor (MechanismId (ckm_EDDSA)))
  assertEqual "ML-DSA has no SLH-DSA recipe" Nothing
    (slhdsaRecipeFor (MechanismId (ckm_ML_DSA)))
  assertEqual "raw id resolves" (Just "CKM_SLH_DSA")
    (rslName <$> slhdsaRecipeFor (MechanismId (ckm_SLH_DSA)))

-- | Canonical default-params image: two zero words (hedge 0 =
-- preferred, length 0).
defaultImage :: BS.ByteString
defaultImage = BS.replicate 16 0x00

caseCodec :: IO ()
caseCodec = do
  assertEqual "slhdsa codec" (ParameterCodec "slhdsa-params" 1) slhdsaCodec
  case slhdsaRecipeFor (MechanismId (ckm_SLH_DSA)) of
    Nothing -> assertFailure "CKM_SLH_DSA unresolved"
    Just r -> assertEqual "codec row" slhdsaCodec (slhdsaCodecFor r)
  assertEqual "default encodes to two zero words" defaultImage
    (encodeSlhdsaParams SlhPreferred BS.empty)
  assertEqual "empty decodes to the default (struct optional)" (Just (SlhPreferred, BS.empty))
    (decodeSlhdsaParams BS.empty)
  assertEqual "default image decodes" (Just (SlhPreferred, BS.empty))
    (decodeSlhdsaParams defaultImage)
  assertEqual "hedge roundtrips" (Just (SlhRequired, BS.empty))
    (decodeSlhdsaParams (encodeSlhdsaParams SlhRequired BS.empty))
  assertEqual "deterministic roundtrips" (Just (SlhDeterministic, BS.empty))
    (decodeSlhdsaParams (encodeSlhdsaParams SlhDeterministic BS.empty))
  assertEqual "context roundtrips" (Just (SlhPreferred, "CTX"))
    (decodeSlhdsaParams (encodeSlhdsaParams SlhPreferred "CTX"))
  assertEqual "deterministic context roundtrips" (Just (SlhDeterministic, "CTX"))
    (decodeSlhdsaParams (encodeSlhdsaParams SlhDeterministic "CTX"))

recipeOf :: Text -> SlhdsaRecipe
recipeOf name =
  case slhdsaRecipeFor (MechanismId (mustGeneratedId name)) of
    Just r -> r
    Nothing -> error ("test recipe missing: " ++ T.unpack name)

-- | Big-endian u64 word (canonical codec byte order).
word64 :: Int -> BS.ByteString
word64 n = BS.pack [fromIntegral ((n `div` (256 ^ s)) `mod` 256) | s <- ([7, 6 .. 0] :: [Int])]

caseParams :: IO ()
caseParams = do
  let r = recipeOf "CKM_SLH_DSA"
  assertBool "empty valid (struct optional)" (slhdsaParamsValid r BS.empty)
  assertBool "default image valid" (slhdsaParamsValid r defaultImage)
  assertBool "preferred valid"
    (slhdsaParamsValid r (encodeSlhdsaParams SlhPreferred BS.empty))
  assertBool "required valid"
    (slhdsaParamsValid r (encodeSlhdsaParams SlhRequired BS.empty))
  assertBool "deterministic valid"
    (slhdsaParamsValid r (encodeSlhdsaParams SlhDeterministic BS.empty))
  assertBool "context valid"
    (slhdsaParamsValid r (encodeSlhdsaParams SlhPreferred "CTX"))
  assertBool "255-byte context valid"
    (slhdsaParamsValid r (encodeSlhdsaParams SlhPreferred (BS.replicate 255 0x41)))
  assertBool "256-byte context refused"
    (not (slhdsaParamsValid r (encodeSlhdsaParams SlhPreferred (BS.replicate 256 0x41))))
  assertBool "hedge word 3 refused"
    (not (slhdsaParamsValid r (word64 3 <> word64 0)))
  -- Malformed sweep: validity agrees with (decoder + FIPS
  -- context bound) on every input (the two entry points cannot
  -- drift apart).
  let bogus =
        [ "RAW", "PEM", BS.singleton 0x00, BS.replicate 8 0x00
        , BS.replicate 15 0x00, BS.replicate 17 0x00
        , word64 3 <> word64 0
        , word64 0 <> word64 5 <> "AB"
        , defaultImage <> BS.singleton 0x00
        , encodeSlhdsaParams SlhPreferred BS.empty <> "trailing"
        , encodeSlhdsaParams SlhPreferred (BS.replicate 256 0x41)
        , BS.replicate 64 0x41
        ]
      expect p = case decodeSlhdsaParams p of
        Just (_, ctx) -> BS.length ctx <= 255
        Nothing -> False
  mapM_ (\p -> do
    assertBool ("bogus refused " ++ show p) (not (slhdsaParamsValid r p))
    assertEqual ("validity agrees " ++ show p) (expect p) (slhdsaParamsValid r p)
    ) bogus
  mapM_ (\p ->
    assertEqual ("validity agrees " ++ show p) (expect p) (slhdsaParamsValid r p)
    ) [BS.empty, defaultImage, encodeSlhdsaParams SlhDeterministic "CTX"]

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

slhdsaMech :: MechanismId
slhdsaMech = MechanismId (ckm_SLH_DSA)

testEnv :: OpEnv
testEnv = OpEnv
  { oeRegistry = curatedRegistry
  , oeCaps = mkCapabilities [(slhdsaMech, OpSign)]
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
    (runInit (InitArgs OpSign slhdsaMech BS.empty (Just badKey) Nothing Nothing))
  assertEqual "default passes params" CKR_OBJECT_HANDLE_INVALID
    (runInit (InitArgs OpSign slhdsaMech defaultImage (Just badKey) Nothing Nothing))
  assertEqual "context passes params" CKR_OBJECT_HANDLE_INVALID
    (runInit (InitArgs OpSign slhdsaMech (encodeSlhdsaParams SlhPreferred "CTX") (Just badKey) Nothing Nothing))
  assertEqual "deterministic passes params" CKR_OBJECT_HANDLE_INVALID
    (runInit (InitArgs OpSign slhdsaMech (encodeSlhdsaParams SlhDeterministic BS.empty) (Just badKey) Nothing Nothing))
  assertEqual "hedge word 3 refused" CKR_ARGUMENTS_BAD
    (runInit (InitArgs OpSign slhdsaMech (word64 3 <> word64 0) (Just badKey) Nothing Nothing))
  assertEqual "overlong context refused" CKR_ARGUMENTS_BAD
    (runInit (InitArgs OpSign slhdsaMech (encodeSlhdsaParams SlhPreferred (BS.replicate 256 0x41)) (Just badKey) Nothing Nothing))
  assertEqual "malformed refused" CKR_ARGUMENTS_BAD
    (runInit (InitArgs OpSign slhdsaMech "PEM" (Just badKey) Nothing Nothing))

-- | All twelve parameter sets: backend algorithm plus the
-- fixture tag (pinned-CLI genpkey fixtures under
-- tests/fixtures/).
slhSets :: [(PqcSigAlg, String)]
slhSets =
  [ (SLH_DSA_SHA2_128s, "sha2-128s"), (SLH_DSA_SHA2_128f, "sha2-128f")
  , (SLH_DSA_SHA2_192s, "sha2-192s"), (SLH_DSA_SHA2_192f, "sha2-192f")
  , (SLH_DSA_SHA2_256s, "sha2-256s"), (SLH_DSA_SHA2_256f, "sha2-256f")
  , (SLH_DSA_SHAKE_128s, "shake-128s"), (SLH_DSA_SHAKE_128f, "shake-128f")
  , (SLH_DSA_SHAKE_192s, "shake-192s"), (SLH_DSA_SHAKE_192f, "shake-192f")
  , (SLH_DSA_SHAKE_256s, "shake-256s"), (SLH_DSA_SHAKE_256f, "shake-256f")
  ]

-- | Real key bytes: SLH-DSA SPKI + PKCS#8 per set (pinned-CLI
-- genpkey fixtures under tests/fixtures/).
loadKeys :: IO [(PqcSigAlg, KeyMaterial, KeyMaterial)]
loadKeys = mapM load slhSets
  where
    load (alg, tag) = do
      pub <- BS.readFile ("tests/fixtures/slhdsa-" ++ tag ++ "-pub.der")
      priv <- BS.readFile ("tests/fixtures/slhdsa-" ++ tag ++ "-priv.der")
      pure (alg, KeyDer pub, KeyDer priv)

caseDriverMap :: IO ()
caseDriverMap = do
  keys <- loadKeys
  let slhdsa = MechanismId (ckm_SLH_DSA)
  mapM_ (\(alg, pub, priv) -> do
    assertEqual ("SPKI maps, set " ++ show alg)
      (Just (SigSLHDSA alg BS.empty True))
      (slhdsaSpecFor slhdsa defaultImage pub)
    assertEqual ("PKCS#8 maps, set " ++ show alg)
      (Just (SigSLHDSA alg BS.empty True))
      (slhdsaSpecFor slhdsa BS.empty priv)
    assertEqual ("context rides, set " ++ show alg)
      (Just (SigSLHDSA alg "CTX" True))
      (slhdsaSpecFor slhdsa (encodeSlhdsaParams SlhPreferred "CTX") pub)
    assertEqual ("required rides hedged, set " ++ show alg)
      (Just (SigSLHDSA alg BS.empty True))
      (slhdsaSpecFor slhdsa (encodeSlhdsaParams SlhRequired BS.empty) pub)
    assertEqual ("deterministic clears hedge, set " ++ show alg)
      (Just (SigSLHDSA alg BS.empty False))
      (slhdsaSpecFor slhdsa (encodeSlhdsaParams SlhDeterministic BS.empty) pub)
    -- Production shape: stored keys resolve as KeyBytes carrying
    -- DER (stdResolver); both constructors must sniff (the
    -- EdDSA lesson).
    case pub of
      KeyDer der -> assertEqual ("KeyBytes sniffs, set " ++ show alg)
        (Just (SigSLHDSA alg BS.empty True))
        (slhdsaSpecFor slhdsa defaultImage (KeyBytes der))
      _ -> assertFailure "fixture not DER"
    ) keys
  (_, pub128s, _) <- headOf keys
  assertEqual "hedge word 3 refused" Nothing
    (slhdsaSpecFor slhdsa (word64 3 <> word64 0) pub128s)
  assertEqual "overlong context refused" Nothing
    (slhdsaSpecFor slhdsa (encodeSlhdsaParams SlhPreferred (BS.replicate 256 0x41)) pub128s)
  assertEqual "malformed refused" Nothing
    (slhdsaSpecFor slhdsa "PEM" pub128s)
  assertEqual "non-SLH-DSA uncovered" Nothing
    (slhdsaSpecFor (MechanismId (ckm_EDDSA)) BS.empty pub128s)
  assertEqual "ECDSA uncovered" Nothing
    (slhdsaSpecFor (MechanismId (ckm_ECDSA)) BS.empty pub128s)
  assertEqual "unscannable key defaults SLH-DSA-SHA2-128s"
    (Just (SigSLHDSA SLH_DSA_SHA2_128s BS.empty True))
    (slhdsaSpecFor slhdsa defaultImage (KeyBytes (BS.replicate 32 0)))
  where
    headOf (x : _) = pure x
    headOf [] = assertFailure "no fixtures" >> undefined

caseLevelSniff :: IO ()
caseLevelSniff = do
  keys <- loadKeys
  mapM_ (\(alg, pub, priv) -> do
    assertEqual ("SPKI sniffs " ++ show alg) (Just alg) (slhdsaLevelOfKey pub)
    assertEqual ("PKCS#8 sniffs " ++ show alg) (Just alg) (slhdsaLevelOfKey priv)
    case pub of
      KeyDer der -> assertEqual ("SPKI as KeyBytes " ++ show alg) (Just alg)
        (slhdsaLevelOfKey (KeyBytes der))
      _ -> assertFailure "fixture not DER"
    ) keys
  assertEqual "raw bytes unscannable" Nothing
    (slhdsaLevelOfKey (KeyBytes (BS.replicate 32 0)))
  assertEqual "garbage unscannable" Nothing
    (slhdsaLevelOfKey (KeyDer "bogus"))
  assertEqual "Ed25519 SPKI unscannable" Nothing
    (slhdsaLevelOfKey (KeyDer ed19Pub))
  assertEqual "P-256 SPKI unscannable" Nothing
    (slhdsaLevelOfKey (KeyDer p256Pub))
  assertEqual "ML-DSA-44 SPKI unscannable" Nothing
    (slhdsaLevelOfKey (KeyDer mldsa44Pub))

-- | Foreign keys the SLH-DSA sniff must never claim (the
-- RecipeEddsaSpec Ed25519 SPKI, the RecipeEcdsaSpec P-256
-- SPKI, and the tests/fixtures ML-DSA-44 SPKI head).
ed19Pub, p256Pub, mldsa44Pub :: BS.ByteString
ed19Pub = hex "302a300506032b6570032100e3066819aa9f7d91c3c4ebad5584adeef588d8a1cbf2a09a8081d41cc5183402"
p256Pub = hex "3059301306072a8648ce3d020106082a8648ce3d03010703420004a348bab88ded75858acef31e9afa0ef8680ad8ec1196227b10083a630f029ecfc5503e37b76e2538f9ec2ceb6aa766cc7948071e6c39b9a93f0c54d5f7b12086"
mldsa44Pub = hex "3082020230200d06096086480165030403113000"

hex :: String -> BS.ByteString
hex s = BS.pack (go (filter isHexDigit s))
  where
    go [] = []
    go (a : b : rest) = fromIntegral (digitToInt a * 16 + digitToInt b) : go rest
    go [_] = error "hex: odd digit count"
