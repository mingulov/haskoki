{- | RSA PKCS#1 v1.5 recipe tests.

The RSA v1.5 group: 12 header mechanisms sharing one parameter
shape — empty mechanism parameters, one-shot sign\/verify. Eleven
rows bind a digest (@CKM_*_RSA_PKCS@: the backend hashes and signs
in one @EVP_DigestSign@ step); @CKM_RSA_PKCS@ is the raw row (the
input is signed directly with block-type-1 padding, no hashing).
'Haskoki.Recipe.RsaPkcs1' owns the group's canonical codec,
parameter validation, digest bindings, and mechanism table; these
tests pin the recipe and its three consumers:

* the model init path enforces empty RSA parameters
  ('validateInit', 'CKR_ARGUMENTS_BAD');
* the driver maps every covered (mechanism, params) pair to its
  backend 'SigSpec' ('rsaPkcs1SpecFor' agrees with the recipe
  table);
* engines execute the pinned specs (SyntheticSpec roundtrips,
  OpenSSLSpec KATs against the pinned libcrypto).
-}
{-# LANGUAGE OverloadedStrings #-}
module RecipeRsaSpec (spec) where

import qualified Data.ByteString as BS
import Data.Text (Text)
import qualified Data.Text as T
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertBool, assertEqual, assertFailure, testCase)

import Haskoki.Engine.Backend (DigestAlg (..), RsaCipherParams (..), SigSpec (..))
import Haskoki.Engine.Driver
  ( recoverType1Pad
  , recoverType1Strip
  , rsaPkcs1SpecFor
  , rsaRecoverCipherFor
  )
import Haskoki.Model (SessionState (..), emptyModel)
import Haskoki.Operation
  ( InitArgs (..)
  , InitOutcome (..)
  , KeyPolicy (..)
  , OpEnv (..)
  , RecoverSpec (..)
  , emptySessionOps
  , initOperation
  )
import Haskoki.Recipe.RsaPkcs1
  ( RsaPkcs1Recipe (..)
  , rsaPkcs1Codec
  , rsaPkcs1CodecFor
  , rsaPkcs1ParamsValid
  , rsaPkcs1RecipeFor
  , rsaPkcs1Recipes
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
  , ckm_RSA_PKCS
  , ckm_RSA_PKCS_OAEP
  , ckm_RSA_PKCS_PSS
  , ckm_SHA256
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
spec = testGroup "RSA PKCS#1 v1.5 recipe"
  [ testCase "recipe table covers 12 mechanisms with digests" caseTable
  , testCase "recipe lookup resolves by id" caseLookup
  , testCase "codec is no-params/1 for every row" caseCodec
  , testCase "params: empty-only" caseParams
  , testCase "init enforces empty RSA params" caseInitParams
  , testCase "driver maps every recipe to its SigSpec" caseDriverMap
  , testCase "recover init accepts the raw row, refuses digest rows" caseRecoverInit
  , testCase "recover driver maps the raw row onto raw RSA" caseRecoverDriver
  , testCase "recover type-1 framing round-trips" caseRecoverFraming
  ]

-- | (Name suffix, digest stem or Nothing for the raw row, backend alg).
groupShape :: [(Text, Maybe Text, Maybe DigestAlg)]
groupShape =
  [ ("RSA_PKCS", Nothing, Nothing)
  , ("MD5_RSA_PKCS", Just "MD5", Just D_MD5)
  , ("RIPEMD160_RSA_PKCS", Just "RIPEMD160", Just D_RIPEMD160)
  , ("SHA1_RSA_PKCS", Just "SHA_1", Just D_SHA1)
  , ("SHA224_RSA_PKCS", Just "SHA224", Just D_SHA224)
  , ("SHA256_RSA_PKCS", Just "SHA256", Just D_SHA256)
  , ("SHA384_RSA_PKCS", Just "SHA384", Just D_SHA384)
  , ("SHA512_RSA_PKCS", Just "SHA512", Just D_SHA512)
  , ("SHA3_224_RSA_PKCS", Just "SHA3_224", Just D_SHA3_224)
  , ("SHA3_256_RSA_PKCS", Just "SHA3_256", Just D_SHA3_256)
  , ("SHA3_384_RSA_PKCS", Just "SHA3_384", Just D_SHA3_384)
  , ("SHA3_512_RSA_PKCS", Just "SHA3_512", Just D_SHA3_512)
  ]

mechName :: Text -> Text
mechName suffix = "CKM_" <> suffix

caseTable :: IO ()
caseTable = do
  assertEqual "recipe count" 12 (length rsaPkcs1Recipes)
  mapM_ (\(suffix, stem, _alg) -> do
    let name = mechName suffix
        found = [ r | r <- rsaPkcs1Recipes, rrName r == name ]
    case found of
      [r] -> assertEqual ("digest " ++ T.unpack name) stem (rrDigestStem r)
      rs -> assertFailure ("rows " ++ T.unpack name ++ ": " ++ show (length rs))
    ) groupShape

caseLookup :: IO ()
caseLookup = do
  mapM_ (\(suffix, _, _) -> do
    let name = mechName suffix
    case rsaPkcs1RecipeFor (MechanismId (mustGeneratedId name)) of
      Nothing -> assertFailure ("unresolved " ++ T.unpack name)
      Just r -> assertEqual ("lookup " ++ T.unpack name) name (rrName r)
    ) groupShape
  assertEqual "unknown id has no recipe" Nothing
    (rsaPkcs1RecipeFor (MechanismId 0x4712))
  assertEqual "digest mech has no RSA recipe" Nothing
    (rsaPkcs1RecipeFor (MechanismId (ckm_SHA256)))
  assertEqual "PSS has no v1.5 recipe" Nothing
    (rsaPkcs1RecipeFor (MechanismId (ckm_RSA_PKCS_PSS)))
  assertEqual "OAEP has no v1.5 recipe" Nothing
    (rsaPkcs1RecipeFor (MechanismId (ckm_RSA_PKCS_OAEP)))

caseCodec :: IO ()
caseCodec = do
  assertEqual "rsa codec" (ParameterCodec "no-params" 1) rsaPkcs1Codec
  mapM_ (\(suffix, _, _) -> do
    let name = mechName suffix
    case rsaPkcs1RecipeFor (MechanismId (mustGeneratedId name)) of
      Nothing -> assertFailure ("unresolved " ++ T.unpack name)
      Just r -> assertEqual ("codec " ++ T.unpack name) rsaPkcs1Codec
        (rsaPkcs1CodecFor r)
    ) groupShape

recipeOf :: Text -> RsaPkcs1Recipe
recipeOf name =
  case rsaPkcs1RecipeFor (MechanismId (mustGeneratedId name)) of
    Just r -> r
    Nothing -> error ("test recipe missing: " ++ T.unpack name)

caseParams :: IO ()
caseParams = do
  let r = recipeOf "CKM_SHA256_RSA_PKCS"
  assertBool "empty valid" (rsaPkcs1ParamsValid r BS.empty)
  assertBool "non-empty refused" (not (rsaPkcs1ParamsValid r "x"))
  let raw = recipeOf "CKM_RSA_PKCS"
  assertBool "raw empty valid" (rsaPkcs1ParamsValid raw BS.empty)
  assertBool "raw non-empty refused"
    (not (rsaPkcs1ParamsValid raw (BS.replicate 8 0)))
  mapM_ (\(suffix, _, _) -> do
    let rr = recipeOf (mechName suffix)
    assertBool ("empty ok " ++ T.unpack suffix)
      (rsaPkcs1ParamsValid rr BS.empty)
    assertBool ("byte refused " ++ T.unpack suffix)
      (not (rsaPkcs1ParamsValid rr "x"))
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

rsaMech, rawMech :: MechanismId
rsaMech = MechanismId (ckm_SHA256_RSA_PKCS)
rawMech = MechanismId (ckm_RSA_PKCS)

testEnv :: OpEnv
testEnv = OpEnv
  { oeRegistry = curatedRegistry
  , oeCaps = mkCapabilities [(rsaMech, OpSign), (rawMech, OpSign)]
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
  assertEqual "digested non-empty refused" CKR_ARGUMENTS_BAD
    (runInit (InitArgs OpSign rsaMech "x" (Just badKey) Nothing Nothing))
  assertEqual "digested empty passes params" CKR_OBJECT_HANDLE_INVALID
    (runInit (InitArgs OpSign rsaMech BS.empty (Just badKey) Nothing Nothing))
  assertEqual "raw non-empty refused" CKR_ARGUMENTS_BAD
    (runInit (InitArgs OpSign rawMech "x" (Just badKey) Nothing Nothing))
  assertEqual "raw empty passes params" CKR_OBJECT_HANDLE_INVALID
    (runInit (InitArgs OpSign rawMech BS.empty (Just badKey) Nothing Nothing))

caseDriverMap :: IO ()
caseDriverMap =
  mapM_ (\(suffix, _stem, alg) -> do
    let mech = MechanismId (mustGeneratedId (mechName suffix))
        want = case alg of
          Nothing -> SigRSA_Raw
          Just a -> SigRSA_PKCS1v15 a
    assertEqual ("driver " ++ T.unpack suffix) (Just want)
      (rsaPkcs1SpecFor mech BS.empty)
    assertEqual ("driver rejects params " ++ T.unpack suffix) Nothing
      (rsaPkcs1SpecFor mech "x")
    ) groupShape

-- | The recover shape for a 2048-bit RSA key: capacity and tag
-- width both fix the modulus width (the driver block stages
-- directly, never split).
recSpec :: RecoverSpec
recSpec = RecoverSpec 256 256

recEnv :: OpEnv
recEnv = testEnv
  { oeCaps = mkCapabilities
      [(rawMech, OpSignRecover), (rawMech, OpVerifyRecover)]
  }

runRecInit :: InitArgs -> ReturnCode
runRecInit args =
  ioCode (snd (initOperation recEnv emptySessionOps testSession args))

caseRecoverInit :: IO ()
caseRecoverInit = do
  assertEqual "raw sign-recover non-empty refused" CKR_ARGUMENTS_BAD
    (runRecInit (InitArgs OpSignRecover rawMech "x"
      (Just badKey) Nothing (Just recSpec)))
  assertEqual "raw sign-recover empty passes params"
    CKR_OBJECT_HANDLE_INVALID
    (runRecInit (InitArgs OpSignRecover rawMech BS.empty
      (Just badKey) Nothing (Just recSpec)))
  assertEqual "raw verify-recover empty passes params"
    CKR_OBJECT_HANDLE_INVALID
    (runRecInit (InitArgs OpVerifyRecover rawMech BS.empty
      (Just badKey) Nothing (Just recSpec)))
  assertEqual "digest sign-recover route miss" CKR_MECHANISM_INVALID
    (runRecInit (InitArgs OpSignRecover rsaMech BS.empty
      (Just badKey) Nothing (Just recSpec)))
  -- Granted caps do not help: the digest rows carry no recover
  -- routes, so the refusal is registry-driven.
  let capped = recEnv
        { oeCaps = mkCapabilities [(rsaMech, OpSignRecover)] }
      got = ioCode (snd (initOperation capped emptySessionOps
        testSession (InitArgs OpSignRecover rsaMech BS.empty
          (Just badKey) Nothing (Just recSpec))))
  assertEqual "digest miss stands under caps" CKR_MECHANISM_INVALID got

caseRecoverDriver :: IO ()
caseRecoverDriver = do
  let x509 = MechanismId (mustGeneratedId "CKM_RSA_X_509")
      pss = MechanismId ckm_RSA_PKCS_PSS
      oaep = MechanismId ckm_RSA_PKCS_OAEP
  assertEqual "raw maps" (Just RsaX509)
    (rsaRecoverCipherFor rawMech BS.empty)
  assertEqual "raw rejects params" Nothing
    (rsaRecoverCipherFor rawMech "x")
  assertEqual "digest row unmapped" Nothing
    (rsaRecoverCipherFor rsaMech BS.empty)
  assertEqual "x509 pair row maps" (Just RsaX509)
    (rsaRecoverCipherFor x509 BS.empty)
  assertEqual "pss unmapped" Nothing
    (rsaRecoverCipherFor pss BS.empty)
  assertEqual "oaep unmapped" Nothing
    (rsaRecoverCipherFor oaep BS.empty)

caseRecoverFraming :: IO ()
caseRecoverFraming = do
  assertEqual "pad shape"
    (Just (BS.pack [0x00, 0x01] <> BS.replicate 250 0xff
      <> BS.pack [0x00] <> "abc"))
    (recoverType1Pad 256 "abc")
  mapM_ (\payload ->
    assertEqual ("round-trip " ++ show (BS.length payload)) (Just payload)
      (recoverType1Strip =<< recoverType1Pad 256 payload))
    [BS.empty, "a", "abc", BS.replicate 245 7]
  assertEqual "pad refuses the 246th byte" Nothing
    (recoverType1Pad 256 (BS.replicate 246 7))
  assertEqual "strip accepts empty data" (Just BS.empty)
    (recoverType1Strip (BS.pack [0x00, 0x01] <> BS.replicate 8 0xff
      <> BS.pack [0x00]))
  mapM_ (\(label, raw) ->
    assertEqual ("strip refuses " ++ label) Nothing
      (recoverType1Strip raw))
    [ ("empty", BS.empty)
    , ("type-2", BS.pack [0x00, 0x02] <> BS.replicate 8 0xff
        <> BS.pack [0x00] <> "abc")
    , ("short filler", BS.pack [0x00, 0x01] <> BS.replicate 7 0xff
        <> BS.pack [0x00] <> "abc")
    , ("missing separator", BS.pack [0x00, 0x01] <> BS.replicate 8 0xff
        <> "abc")
    , ("missing leading zero", BS.pack [0x01] <> BS.replicate 8 0xff
        <> BS.pack [0x00] <> "abc")
    ]
