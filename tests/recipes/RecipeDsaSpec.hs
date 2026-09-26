{- | DSA recipe tests.

The DSA group: 10 header mechanisms sharing the encoding
parameter shape — @sig-encoding\/1@: @"RAW"@, @"DER"@, or empty
(our engine convention selecting the signature encoding; empty
defaults to RAW per PKCS#11 — DSA signatures on the wire are the
raw r||s concatenation). Nine rows bind a digest (hash-and-sign);
@CKM_DSA@ is the raw row (the input is a caller-supplied digest
of at least 20 bytes, signed directly, no hashing).
'Haskoki.Recipe.Dsa' owns the group's canonical codec, parameter
validation, digest bindings, and mechanism table; these tests pin
the recipe and its three consumers:

* the model init path enforces DSA parameters ('validateInit',
  'CKR_ARGUMENTS_BAD');
* the driver maps every covered (mechanism, params) pair to its
  backend 'SigSpec' ('dsaSpecFor' agrees with the recipe table;
  unlike ECDSA there is no curve label to hint — key shape is
  the backend's call);
* engines execute the pinned specs across the served (L, N)
  pairs (SyntheticSpec roundtrips, OpenSSLSpec interop vectors
  against the pinned libcrypto).
-}
{-# LANGUAGE OverloadedStrings #-}
module RecipeDsaSpec (spec) where

import qualified Data.ByteString as BS
import Data.Maybe (isJust)
import Data.Text (Text)
import qualified Data.Text as T
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertBool, assertEqual, assertFailure, testCase)

import Haskoki.Engine.Backend
  ( DigestAlg (..)
  , SigSpec (..)
  )
import Haskoki.Engine.Driver (dsaSpecFor)
import Haskoki.Model (SessionState (..), emptyModel)
import Haskoki.Operation
  ( InitArgs (..)
  , InitOutcome (..)
  , KeyPolicy (..)
  , OpEnv (..)
  , emptySessionOps
  , initOperation
  )
import Haskoki.Recipe.Dsa
  ( DsaRecipe (..)
  , dsaCodec
  , dsaCodecFor
  , dsaEncodingOf
  , dsaParamsValid
  , dsaRawDigestFloor
  , dsaRawFloorFor
  , dsaRecipeFor
  , dsaRecipes
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
  , ckm_DSA_SHA256
  , ckm_ECDSA
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
spec = testGroup "DSA recipe"
  [ testCase "recipe table covers 10 mechanisms with digests" caseTable
  , testCase "recipe lookup resolves by id" caseLookup
  , testCase "codec is sig-encoding/1" caseCodec
  , testCase "params: RAW/DER/empty only" caseParams
  , testCase "init enforces DSA params" caseInitParams
  , testCase "driver maps every pair to its SigSpec" caseDriverMap
  , testCase "raw floor pins the digest minimum" caseRawFloor
  ]

-- | (Name suffix, digest stem or Nothing for the raw row, backend alg).
groupShape :: [(Text, Maybe Text, Maybe DigestAlg)]
groupShape =
  [ ("DSA", Nothing, Nothing)
  , ("DSA_SHA1", Just "SHA_1", Just D_SHA1)
  , ("DSA_SHA224", Just "SHA224", Just D_SHA224)
  , ("DSA_SHA256", Just "SHA256", Just D_SHA256)
  , ("DSA_SHA384", Just "SHA384", Just D_SHA384)
  , ("DSA_SHA512", Just "SHA512", Just D_SHA512)
  , ("DSA_SHA3_224", Just "SHA3_224", Just D_SHA3_224)
  , ("DSA_SHA3_256", Just "SHA3_256", Just D_SHA3_256)
  , ("DSA_SHA3_384", Just "SHA3_384", Just D_SHA3_384)
  , ("DSA_SHA3_512", Just "SHA3_512", Just D_SHA3_512)
  ]

mechName :: Text -> Text
mechName suffix = "CKM_" <> suffix

caseTable :: IO ()
caseTable = do
  assertEqual "recipe count" 10 (length dsaRecipes)
  mapM_ (\(suffix, stem, _alg) -> do
    let name = mechName suffix
        found = [ r | r <- dsaRecipes, rdName r == name ]
    case found of
      [r] -> assertEqual ("digest " ++ T.unpack name) stem (rdDigestStem r)
      rs -> assertFailure ("rows " ++ T.unpack name ++ ": " ++ show (length rs))
    ) groupShape

caseLookup :: IO ()
caseLookup = do
  mapM_ (\(suffix, _, _alg) -> do
    let name = mechName suffix
    case dsaRecipeFor (MechanismId (mustGeneratedId name)) of
      Nothing -> assertFailure ("unresolved " ++ T.unpack name)
      Just r -> assertEqual ("lookup " ++ T.unpack name) name (rdName r)
    ) groupShape
  assertEqual "unknown id has no recipe" Nothing
    (dsaRecipeFor (MechanismId 0x4712))
  assertEqual "ECDSA has no DSA recipe" Nothing
    (dsaRecipeFor (MechanismId (ckm_ECDSA)))
  assertEqual "ML-DSA has no DSA recipe" Nothing
    (dsaRecipeFor (MechanismId (ckm_ML_DSA)))
  assertEqual "raw row resolves" (Just "CKM_DSA")
    (rdName <$> dsaRecipeFor (MechanismId (ckm_DSA)))
  assertEqual "sha256 row resolves" (Just "CKM_DSA_SHA256")
    (rdName <$> dsaRecipeFor (MechanismId (ckm_DSA_SHA256)))

caseCodec :: IO ()
caseCodec = do
  assertEqual "dsa codec" (ParameterCodec "sig-encoding" 1) dsaCodec
  mapM_ (\(suffix, _, _alg) -> do
    let name = mechName suffix
    case dsaRecipeFor (MechanismId (mustGeneratedId name)) of
      Nothing -> assertFailure ("unresolved " ++ T.unpack name)
      Just r -> assertEqual ("codec " ++ T.unpack name) dsaCodec
        (dsaCodecFor r)
    ) groupShape
  assertEqual "RAW encodes" (Just "RAW") (dsaEncodingOf "RAW")
  assertEqual "DER encodes" (Just "DER") (dsaEncodingOf "DER")
  assertEqual "empty defaults RAW" (Just "RAW") (dsaEncodingOf BS.empty)
  assertEqual "PEM refused" Nothing (dsaEncodingOf "PEM")
  assertEqual "lowercase refused" Nothing (dsaEncodingOf "der")

recipeOf :: Text -> DsaRecipe
recipeOf name =
  case dsaRecipeFor (MechanismId (mustGeneratedId name)) of
    Just r -> r
    Nothing -> error ("test recipe missing: " ++ T.unpack name)

caseParams :: IO ()
caseParams = do
  let r = recipeOf "CKM_DSA_SHA256"
  assertBool "RAW valid" (dsaParamsValid r "RAW")
  assertBool "DER valid" (dsaParamsValid r "DER")
  assertBool "empty valid" (dsaParamsValid r BS.empty)
  assertBool "PEM refused" (not (dsaParamsValid r "PEM"))
  assertBool "lowercase refused" (not (dsaParamsValid r "der"))
  let raw = recipeOf "CKM_DSA"
  assertBool "raw RAW valid" (dsaParamsValid raw "RAW")
  assertBool "raw empty valid" (dsaParamsValid raw BS.empty)
  assertBool "raw PEM refused" (not (dsaParamsValid raw "PEM"))
  mapM_ (\(suffix, _, _alg) -> do
    let rr = recipeOf (mechName suffix)
    mapM_ (\p -> assertBool ("valid " ++ T.unpack suffix ++ "/" ++ show p)
      (dsaParamsValid rr p)) ["RAW", "DER", BS.empty]
    assertBool ("refused " ++ T.unpack suffix)
      (not (dsaParamsValid rr "PEM"))
    ) groupShape
  -- Malformed sweep: validity agrees with the decoder on every
  -- input (the two entry points cannot drift apart).
  let bogus = ["raw", "Raw", " RAW", "RAW ", "DER ", "D", "R", "RA",
               "DERX", "RAWX", "DER\0", "RAW\0", "PEM", "der", "ber",
               BS.replicate 64 0x41, BS.singleton 0x00]
  mapM_ (\(suffix, _, _alg) -> do
    let rr = recipeOf (mechName suffix)
    mapM_ (\p -> do
      assertBool ("bogus refused " ++ T.unpack suffix ++ "/" ++ show p)
        (not (dsaParamsValid rr p))
      assertEqual ("validity agrees " ++ T.unpack suffix ++ "/" ++ show p)
        (isJust (dsaEncodingOf p)) (dsaParamsValid rr p)
      ) bogus
    mapM_ (\p ->
      assertEqual ("validity agrees " ++ T.unpack suffix ++ "/" ++ show p)
        (isJust (dsaEncodingOf p)) (dsaParamsValid rr p)
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

dsaMech, rawMech :: MechanismId
dsaMech = MechanismId (ckm_DSA_SHA256)
rawMech = MechanismId (ckm_DSA)

testEnv :: OpEnv
testEnv = OpEnv
  { oeRegistry = curatedRegistry
  , oeCaps = mkCapabilities [(dsaMech, OpSign), (rawMech, OpSign)]
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
    (runInit (InitArgs OpSign dsaMech "PEM" (Just badKey) Nothing Nothing))
  assertEqual "DER passes params" CKR_OBJECT_HANDLE_INVALID
    (runInit (InitArgs OpSign dsaMech "DER" (Just badKey) Nothing Nothing))
  assertEqual "empty passes params" CKR_OBJECT_HANDLE_INVALID
    (runInit (InitArgs OpSign dsaMech BS.empty (Just badKey) Nothing Nothing))
  assertEqual "raw PEM refused" CKR_ARGUMENTS_BAD
    (runInit (InitArgs OpSign rawMech "PEM" (Just badKey) Nothing Nothing))
  assertEqual "raw RAW passes params" CKR_OBJECT_HANDLE_INVALID
    (runInit (InitArgs OpSign rawMech "RAW" (Just badKey) Nothing Nothing))

caseDriverMap :: IO ()
caseDriverMap = do
  let sha256 = MechanismId (ckm_DSA_SHA256)
  assertEqual "sha256 DER"
    (Just (SigDSA "DER" (Just D_SHA256)))
    (dsaSpecFor sha256 "DER")
  assertEqual "sha256 empty defaults RAW"
    (Just (SigDSA "RAW" (Just D_SHA256)))
    (dsaSpecFor sha256 BS.empty)
  assertEqual "sha256 RAW"
    (Just (SigDSA "RAW" (Just D_SHA256)))
    (dsaSpecFor sha256 "RAW")
  assertEqual "raw row, no digest"
    (Just (SigDSA "DER" Nothing))
    (dsaSpecFor rawMech "DER")
  assertEqual "PEM refused" Nothing
    (dsaSpecFor sha256 "PEM")
  assertEqual "non-DSA uncovered" Nothing
    (dsaSpecFor (MechanismId (ckm_SHA256_RSA_PKCS)) "DER")
  assertEqual "ECDSA uncovered" Nothing
    (dsaSpecFor (MechanismId (ckm_ECDSA)) "DER")
  -- Whole-table agreement: every (recipe, encoding) pair maps.
  mapM_ (\(suffix, _stem, alg) -> do
    let mech = MechanismId (mustGeneratedId (mechName suffix))
    mapM_ (\enc ->
      assertEqual ("map " ++ T.unpack suffix ++ "/" ++ show enc)
        (Just (SigDSA (if enc == "DER" then "DER" else "RAW") alg))
        (dsaSpecFor mech enc)
      ) ["DER", "RAW"]
    -- Empty parameters (the only shape PKCS#11 callers send)
    -- default to RAW on every row.
    assertEqual ("empty defaults RAW " ++ T.unpack suffix)
      (Just (SigDSA "RAW" alg))
      (dsaSpecFor mech BS.empty)
    ) groupShape

caseRawFloor :: IO ()
caseRawFloor = do
  assertEqual "floor is 20 bytes" 20 dsaRawDigestFloor
  assertEqual "raw row carries the floor" (Just 20)
    (dsaRawFloorFor (MechanismId (ckm_DSA)))
  -- Every hash-and-sign row accepts arbitrary message lengths.
  mapM_ (\(suffix, stem, _alg) -> case stem of
    Nothing -> pure ()
    Just _ -> assertEqual ("no floor " ++ T.unpack suffix) Nothing
      (dsaRawFloorFor (MechanismId (mustGeneratedId (mechName suffix))))
    ) groupShape
  assertEqual "unknown id has no floor" Nothing
    (dsaRawFloorFor (MechanismId 0x4712))
  assertEqual "ECDSA has no DSA floor" Nothing
    (dsaRawFloorFor (MechanismId (ckm_ECDSA)))
