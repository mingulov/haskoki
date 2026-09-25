{- | AES-CCM AEAD recipe tests.

The single-row CCM group: caller-supplied nonce (7..13 bytes per
NIST SP 800-38C), even tag widths 4..16 bytes, AAD bound at seal
('ccm-params/1': tag length, nonce length, data length, nonce,
AAD). 'Haskoki.Recipe.Ccm' owns the canonical codec and parameter
validation; these tests pin the recipe and its two consumers:

* the model init path enforces CCM parameters ('validateInit',
  'CKR_MECHANISM_PARAM_INVALID');
* the driver maps every covered (mechanism, key length, params)
  triple to its backend 'AeadSpec' ('aeadSpecFor' agrees with
  the recipe table: key length selects the AES width, the nonce
  length is the nonce length, the tag width crosses intact).
-}
{-# LANGUAGE OverloadedStrings #-}
module RecipeCcmSpec (spec) where

import qualified Data.ByteString as BS
import Data.Maybe (isJust, isNothing)
import Data.Text (Text)
import Data.Word (Word64)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertBool, assertEqual, assertFailure, testCase)

import Haskoki.Engine.Backend (AeadSpec (..))
import Haskoki.Engine.Driver (aeadSpecFor)
import Haskoki.FFI.NativeParams (ccmStructToCanonical)
import Haskoki.Model (SessionState (..), emptyModel)
import Haskoki.Operation
  ( CipherSpec (..)
  , InitArgs (..)
  , InitOutcome (..)
  , KeyPolicy (..)
  , OpEnv (..)
  , emptySessionOps
  , initOperation
  )
import Haskoki.Operation.Codec (cipherShapeFor)
import Haskoki.Recipe.Ccm
  ( CcmRecipe (..)
  , ccmCodec
  , ccmCodecFor
  , ccmParamsValid
  , ccmRecipeFor
  , ccmRecipes
  , decodeCcmParams
  , encodeCcmParams
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
  , ckm_AES_CBC
  , ckm_AES_CCM
  , ckm_SHA256
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
spec = testGroup "AES-CCM recipe"
  [ testCase "recipe table covers AES-CCM alone" caseTable
  , testCase "recipe lookup resolves by id" caseLookup
  , testCase "codec is ccm-params/1" caseCodec
  , testCase "ccm-params roundtrip" caseRoundtrip
  , testCase "params: caller nonce, approved tag widths" caseParams
  , testCase "ccm native translation agrees on lengths" caseNative
  , testCase "init enforces CCM params" caseInitParams
  , testCase "driver maps every triple to its AeadSpec" caseDriverMap
  , testCase "planner resolves a CCM cipher shape" caseCipherShape
  ]

caseTable :: IO ()
caseTable = do
  assertEqual "recipe count" 1 (length ccmRecipes)
  case ccmRecipes of
    [r] -> assertEqual "row" ("CKM_AES_CCM" :: Text) (ccmName r)
    rs -> assertFailure ("rows: " ++ show (length rs))

caseLookup :: IO ()
caseLookup = do
  case ccmRecipeFor (MechanismId ckm_AES_CCM) of
    Nothing -> assertFailure "unresolved CKM_AES_CCM"
    Just r -> assertEqual "lookup" ("CKM_AES_CCM" :: Text) (ccmName r)
  assertEqual "unknown id has no recipe" Nothing
    (ccmRecipeFor (MechanismId 0x4712))
  assertEqual "digest mech has no CCM recipe" Nothing
    (ccmRecipeFor (MechanismId ckm_SHA256))
  assertEqual "CBC has no CCM recipe" Nothing
    (ccmRecipeFor (MechanismId ckm_AES_CBC))

caseCodec :: IO ()
caseCodec = do
  assertEqual "group codec" (ParameterCodec "ccm-params" 1) ccmCodec
  case ccmRecipeFor (MechanismId ckm_AES_CCM) of
    Nothing -> assertFailure "unresolved CKM_AES_CCM"
    Just r -> assertEqual "row codec" ccmCodec (ccmCodecFor r)

recipeOf :: Text -> CcmRecipe
recipeOf name =
  case ccmRecipeFor (MechanismId (mustGeneratedId name)) of
    Just r -> r
    Nothing -> error ("test recipe missing: " ++ show name)

nonce12 :: BS.ByteString
nonce12 = "0123456789ab"

caseRoundtrip :: IO ()
caseRoundtrip = do
  let aad = BS.pack [0x02, 0x03]
      img = encodeCcmParams nonce12 aad 16 2
  case decodeCcmParams img of
    Nothing -> assertFailure "valid image refused"
    Just (n, a, t, d) -> do
      assertEqual "nonce" nonce12 n
      assertEqual "aad" aad a
      assertEqual "taglen" 16 t
      assertEqual "datalen" 2 d

caseParams :: IO ()
caseParams = do
  let ccm = recipeOf "CKM_AES_CCM"
      good tag nonce = encodeCcmParams nonce "AD" tag 2
  -- Every approved tag width validates at the standard nonce.
  mapM_ (\t -> assertBool ("tag " ++ show t)
    (ccmParamsValid ccm (good t nonce12))) [4, 6, 8, 10, 12, 14, 16]
  -- Unapproved widths refuse.
  mapM_ (\t -> assertBool ("tag refused " ++ show t)
    (not (ccmParamsValid ccm (good t nonce12)))) [0, 1, 5, 7, 11, 13, 15, 17, 32]
  -- Nonce bounds: 7..13 bytes.
  assertBool "nonce 7 valid"
    (ccmParamsValid ccm (good 16 (BS.replicate 7 0)))
  assertBool "nonce 13 valid"
    (ccmParamsValid ccm (good 16 (BS.replicate 13 0)))
  assertBool "nonce 6 refused"
    (not (ccmParamsValid ccm (good 16 (BS.replicate 6 0))))
  assertBool "nonce 14 refused"
    (not (ccmParamsValid ccm (good 16 (BS.replicate 14 0))))
  -- AAD is free-form (including empty); garbage never validates.
  assertBool "empty aad valid"
    (ccmParamsValid ccm (encodeCcmParams nonce12 BS.empty 16 0))
  assertBool "garbage refused" (not (ccmParamsValid ccm "nope"))
  assertBool "truncated refused"
    (not (ccmParamsValid ccm (BS.take 28 (good 16 nonce12))))

caseNative :: IO ()
caseNative = do
  let aad = BS.pack [0x02, 0x03]
      good = ccmStructToCanonical nonce12 aad 2 12 16
  assertBool "valid translates" (isJust good)
  case good >>= decodeCcmParams of
    Just (n, a, t, d) -> do
      assertEqual "nonce" nonce12 n
      assertEqual "aad" aad a
      assertEqual "taglen" 16 t
      assertEqual "datalen" 2 d
    Nothing -> assertFailure "translated image undecodable"
  assertBool "nonceLen mismatch refuses"
    (isNothing (ccmStructToCanonical nonce12 aad 2 11 16))
  assertBool "unrepresentable macLen refuses"
    (isNothing (ccmStructToCanonical nonce12 aad 2 12 (maxBound :: Word64)))

ccmMech :: MechanismId
ccmMech = MechanismId ckm_AES_CCM

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

testEnv :: OpEnv
testEnv = OpEnv
  { oeRegistry = curatedRegistry
  , oeCaps = mkCapabilities [(ccmMech, OpEncrypt)]
  , oeModel = emptyModel
  }

-- | Unknown handle: valid parameters proceed PAST the parameter check
-- to key resolution (proving acceptance); bad parameters stop at
-- 'CKR_MECHANISM_PARAM_INVALID'.
badKey :: KeyPolicy
badKey = KeyPolicy (ExternalHandle 999) [OpEncrypt] False

runInit :: InitArgs -> ReturnCode
runInit args = ioCode (snd (initOperation testEnv emptySessionOps testSession args))

mkArgs :: MechanismId -> BS.ByteString -> InitArgs
mkArgs mech params = InitArgs OpEncrypt mech params (Just badKey)
  (Just (CipherSpec 1 False)) Nothing

caseInitParams :: IO ()
caseInitParams = do
  let good = encodeCcmParams nonce12 "AD" 16 2
  assertEqual "short nonce refused" CKR_MECHANISM_PARAM_INVALID
    (runInit (mkArgs ccmMech (encodeCcmParams (BS.replicate 6 0) "AD" 16 2)))
  assertEqual "bad tag refused" CKR_MECHANISM_PARAM_INVALID
    (runInit (mkArgs ccmMech (encodeCcmParams nonce12 "AD" 5 2)))
  assertEqual "garbage refused" CKR_MECHANISM_PARAM_INVALID
    (runInit (mkArgs ccmMech "nope"))
  assertEqual "valid params pass to key resolution" CKR_OBJECT_HANDLE_INVALID
    (runInit (mkArgs ccmMech good))

caseDriverMap :: IO ()
caseDriverMap = do
  let params tag nonce = encodeCcmParams nonce "AD" tag 2
      p12 = params 16 nonce12
  assertEqual "ccm-128" (Just (AeadSpec "AES-128-CCM" 12 16))
    (aeadSpecFor ccmMech 16 p12)
  assertEqual "ccm-192" (Just (AeadSpec "AES-192-CCM" 12 16))
    (aeadSpecFor ccmMech 24 p12)
  assertEqual "ccm-256" (Just (AeadSpec "AES-256-CCM" 12 16))
    (aeadSpecFor ccmMech 32 p12)
  -- The nonce length follows the nonce; the tag width crosses intact.
  assertEqual "ccm-256 short nonce/narrow tag"
    (Just (AeadSpec "AES-256-CCM" 7 8))
    (aeadSpecFor ccmMech 32 (params 8 "1234567"))
  assertEqual "ccm rejects bad keylen" Nothing
    (aeadSpecFor ccmMech 15 p12)

caseCipherShape :: IO ()
caseCipherShape = do
  -- The planner gates classic inits on this shape; without it init
  -- refuses CKR_MECHANISM_INVALID before the driver is reached.
  assertEqual "ccm cipher shape" (Just (CipherSpec 1 False))
    (cipherShapeFor ccmMech)
