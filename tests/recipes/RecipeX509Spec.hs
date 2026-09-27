{- | RSA-X.509 recipe tests.

The X.509 group: one header mechanism (@CKM_RSA_X_509@) with the
empty parameter shape — @no-params\/1@: raw modular
exponentiation, no padding. Short inputs are left-padded with zero
bytes to the modulus width (@k@); outputs are full @k@-blocks;
unwrap derives the key from the trailing bytes of the decrypted
block (the length comes from @CKA_VALUE_LEN@). 'Haskoki.Recipe.RsaX509'
owns the group's canonical codec, parameter validation, block
framing, and mechanism table; these tests pin the recipe and its
consumers:

* the model init path enforces empty X.509 parameters and refuses
  padded cipher specs for the RSA row ('validateInit',
  'CKR_ARGUMENTS_BAD': the block-cipher planner's PKCS#7 framing
  must never cover an asymmetric operation);
* the driver maps the covered (mechanism, params) pair to its
  backend 'SigSpec' ('rsaX509SigFor') and cipher params
  ('rsaX509CipherFor') and routes X.509 cipher effects to the
  asymmetric backend entry points;
* engines execute the pinned framing (SyntheticSpec roundtrips,
  OpenSSLSpec interop vectors against the pinned libcrypto).
-}
{-# LANGUAGE OverloadedStrings #-}
module RecipeX509Spec (spec) where

import qualified Data.ByteString as BS
import Data.Text (Text)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertBool, assertEqual, assertFailure, testCase)

import Haskoki.Engine.Backend (RsaCipherParams (..), SigSpec (..))
import Haskoki.Engine.Driver (rsaX509CipherFor, rsaX509SigFor)
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
import Haskoki.Recipe.RsaX509
  ( RsaX509Recipe (..)
  , rsaX509Codec
  , rsaX509CodecFor
  , rsaX509ParamsValid
  , rsaX509RecipeFor
  , rsaX509Recipes
  , x509PadBlock
  , x509Tail
  )
import Haskoki.Registry
  ( MechanismId (..)
  , Operation (..)
  , ParameterCodec (..)
  , curatedRegistry
  , mkCapabilities
  )
import Haskoki.Registry.Generated (mustGeneratedId, ckm_RSA_PKCS, ckm_RSA_PKCS_OAEP)
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
spec = testGroup "RSA-X.509 recipe"
  [ testCase "recipe table covers CKM_RSA_X_509" caseTable
  , testCase "recipe lookup resolves by id" caseLookup
  , testCase "codec is no-params/1" caseCodec
  , testCase "params: empty-only" caseParams
  , testCase "block framing pads left, tails right" caseFraming
  , testCase "init enforces X.509 params, refuses padding" caseInitParams
  , testCase "driver maps to raw RSA specs" caseDriverMap
  ]

x509Name :: Text
x509Name = "CKM_RSA_X_509"

caseTable :: IO ()
caseTable = do
  assertEqual "recipe count" 1 (length rsaX509Recipes)
  case rsaX509Recipes of
    [r] -> assertEqual "row name" x509Name (rxName r)
    rs -> assertFailure ("rows: " ++ show (length rs))

caseLookup :: IO ()
caseLookup = do
  case rsaX509RecipeFor (MechanismId (mustGeneratedId x509Name)) of
    Nothing -> assertFailure "unresolved CKM_RSA_X_509"
    Just r -> assertEqual "lookup" x509Name (rxName r)
  assertEqual "unknown id has no recipe" Nothing
    (rsaX509RecipeFor (MechanismId 0x4712))
  assertEqual "v1.5 has no X.509 recipe" Nothing
    (rsaX509RecipeFor (MechanismId (ckm_RSA_PKCS)))
  assertEqual "OAEP has no X.509 recipe" Nothing
    (rsaX509RecipeFor (MechanismId (ckm_RSA_PKCS_OAEP)))

caseCodec :: IO ()
caseCodec = do
  assertEqual "x509 codec" (ParameterCodec "no-params" 1) rsaX509Codec
  case rsaX509Recipes of
    [r] -> assertEqual "row codec" rsaX509Codec (rsaX509CodecFor r)
    _ -> assertFailure "row count"

recipeOf :: Text -> RsaX509Recipe
recipeOf name =
  case rsaX509RecipeFor (MechanismId (mustGeneratedId name)) of
    Just r -> r
    Nothing -> error ("test recipe missing: " ++ show name)

caseParams :: IO ()
caseParams = do
  let r = recipeOf x509Name
  assertBool "empty valid" (rsaX509ParamsValid r BS.empty)
  assertBool "non-empty refused"
    (not (rsaX509ParamsValid r (BS.pack [0])))

caseFraming :: IO ()
caseFraming = do
  assertEqual "short left-pads"
    (Just (BS.replicate 253 0 <> "abc"))
    (x509PadBlock 256 "abc")
  assertEqual "exact passes through"
    (Just (BS.replicate 256 7))
    (x509PadBlock 256 (BS.replicate 256 7))
  assertEqual "empty refused" Nothing (x509PadBlock 256 BS.empty)
  assertEqual "oversize refused" Nothing
    (x509PadBlock 256 (BS.replicate 257 1))
  assertEqual "non-positive width refused" Nothing (x509PadBlock 0 "a")
  let block = BS.replicate 240 0 <> "0123456789abcdef"
  assertEqual "tail takes trailing bytes"
    (Just "0123456789abcdef")
    (x509Tail 256 16 block)
  assertEqual "tail refuses short block" Nothing
    (x509Tail 256 16 (BS.replicate 255 0))
  assertEqual "tail refuses long block" Nothing
    (x509Tail 256 16 (BS.replicate 257 0))
  assertEqual "tail refuses zero length" Nothing (x509Tail 256 0 block)
  assertEqual "tail refuses overlong length" Nothing (x509Tail 256 257 block)

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

x509Mech :: MechanismId
x509Mech = MechanismId (mustGeneratedId x509Name)

testEnv :: OpEnv
testEnv = OpEnv
  { oeRegistry = curatedRegistry
  , oeCaps = mkCapabilities [(x509Mech, OpEncrypt)]
  , oeModel = emptyModel
  }

-- | Unknown handle: valid parameters proceed PAST the parameter check
-- to key resolution (proving acceptance); bad parameters stop at
-- 'CKR_ARGUMENTS_BAD'.
badKey :: KeyPolicy
badKey = KeyPolicy (ExternalHandle 999) [OpEncrypt] False

runInit :: InitArgs -> ReturnCode
runInit args = ioCode (snd (initOperation testEnv emptySessionOps testSession args))

caseInitParams :: IO ()
caseInitParams = do
  assertEqual "non-empty params refused" CKR_ARGUMENTS_BAD
    (runInit (InitArgs OpEncrypt x509Mech (BS.pack [0])
      (Just badKey) (Just (CipherSpec 256 False)) Nothing))
  assertEqual "padded spec refused" CKR_ARGUMENTS_BAD
    (runInit (InitArgs OpEncrypt x509Mech BS.empty
      (Just badKey) (Just (CipherSpec 256 True)) Nothing))
  assertEqual "valid passes params" CKR_OBJECT_HANDLE_INVALID
    (runInit (InitArgs OpEncrypt x509Mech BS.empty
      (Just badKey) (Just (CipherSpec 256 False)) Nothing))

caseDriverMap :: IO ()
caseDriverMap = do
  assertEqual "driver sig" (Just SigRSA_X509)
    (rsaX509SigFor x509Mech BS.empty)
  assertEqual "driver sig rejects params" Nothing
    (rsaX509SigFor x509Mech (BS.pack [0]))
  assertEqual "driver cipher" (Just RsaX509)
    (rsaX509CipherFor x509Mech BS.empty)
  assertEqual "driver cipher rejects params" Nothing
    (rsaX509CipherFor x509Mech (BS.pack [0]))
  assertEqual "non-x509 sig uncovered" Nothing
    (rsaX509SigFor (MechanismId (ckm_RSA_PKCS)) BS.empty)
  assertEqual "non-x509 cipher uncovered" Nothing
    (rsaX509CipherFor (MechanismId (ckm_RSA_PKCS_OAEP)) BS.empty)
