{- | ChaCha20 stream + ChaCha20-Poly1305 AEAD recipe tests.

Two rows: the AEAD row takes the fixed 16-byte tag and the IETF
12-byte nonce plus free-form AAD
('chacha20poly1305-params/1': tag length, nonce length, nonce,
AAD); the raw-stream row takes a bounded initial block counter
plus the 12-byte nonce ('chacha20-params/1': counter, nonce
length, nonce — exact-length). 'Haskoki.Recipe.Chacha20' owns
the canonical codecs and parameter validation; these tests pin
the recipe and its two consumers:

* the model init path enforces both parameter shapes
  ('validateInit', 'CKR_ARGUMENTS_BAD');
* the driver maps the AEAD triple to its backend 'AeadSpec'
  and the stream triple to its backend 'CipherSpec'
  ('aeadSpecFor'/'cipherSpecFor' agree with the recipe table:
  256-bit keys only, the nonce length crosses intact, the
  counter bound refuses).
-}
{-# LANGUAGE OverloadedStrings #-}
module RecipeChacha20Spec (spec) where

import qualified Data.ByteString as BS
import Data.Maybe (isJust, isNothing)
import Data.Text (Text)
import Data.Word (Word64)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertBool, assertEqual, assertFailure, testCase)

import Haskoki.Engine.Backend (AeadSpec (..), CipherSpec (..))
import Haskoki.Engine.Driver (aeadSpecFor, cipherSpecFor)
import Haskoki.FFI.NativeParams
  ( chachaPolyStructToCanonical
  , chachaStreamStructToCanonical
  )
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
import Haskoki.Recipe.Chacha20
  ( Chacha20Recipe (..)
  , chachaCodecFor
  , chachaMaxCounter
  , chachaParamsValid
  , chachaPolyCodec
  , chachaRecipeFor
  , chachaRecipes
  , chachaStreamCodec
  , decodeChachaPolyParams
  , decodeChachaStreamParams
  , encodeChachaPolyParams
  , encodeChachaStreamParams
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
  , ckm_CHACHA20
  , ckm_CHACHA20_POLY1305
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
spec = testGroup "ChaCha20 recipe"
  [ testCase "recipe table covers both rows" caseTable
  , testCase "recipe lookup resolves by id" caseLookup
  , testCase "codecs are row-specific" caseCodec
  , testCase "AEAD params: fixed tag, IETF nonce" casePolyParams
  , testCase "stream params: bounded counter, IETF nonce" caseStreamParams
  , testCase "init enforces both param shapes" caseInitParams
  , testCase "driver maps the AEAD triple" caseDriverAead
  , testCase "driver maps the stream triple" caseDriverStream
  , testCase "native structs translate to canonical" caseNative
  , testCase "planner cipher shapes" caseCipherShape
  ]

caseTable :: IO ()
caseTable = do
  assertEqual "recipe count" 2 (length chachaRecipes)
  case chachaRecipes of
    [a, s] -> do
      assertEqual "aead row" ("CKM_CHACHA20_POLY1305" :: Text) (chachaName a)
      assertEqual "stream row" ("CKM_CHACHA20" :: Text) (chachaName s)
    rs -> assertFailure ("rows: " ++ show (length rs))

caseLookup :: IO ()
caseLookup = do
  case chachaRecipeFor (MechanismId ckm_CHACHA20_POLY1305) of
    Nothing -> assertFailure "unresolved CKM_CHACHA20_POLY1305"
    Just r -> assertEqual "aead lookup" ("CKM_CHACHA20_POLY1305" :: Text) (chachaName r)
  case chachaRecipeFor (MechanismId ckm_CHACHA20) of
    Nothing -> assertFailure "unresolved CKM_CHACHA20"
    Just r -> assertEqual "stream lookup" ("CKM_CHACHA20" :: Text) (chachaName r)
  assertEqual "unknown id has no recipe" Nothing
    (chachaRecipeFor (MechanismId 0x4712))
  assertEqual "digest mech has no ChaCha recipe" Nothing
    (chachaRecipeFor (MechanismId ckm_SHA256))
  assertEqual "CBC has no ChaCha recipe" Nothing
    (chachaRecipeFor (MechanismId ckm_AES_CBC))

caseCodec :: IO ()
caseCodec = do
  assertEqual "poly codec"
    (ParameterCodec "chacha20poly1305-params" 1) chachaPolyCodec
  assertEqual "stream codec"
    (ParameterCodec "chacha20-params" 1) chachaStreamCodec
  assertEqual "aead row codec" chachaPolyCodec
    (chachaCodecFor (recipeOf "CKM_CHACHA20_POLY1305"))
  assertEqual "stream row codec" chachaStreamCodec
    (chachaCodecFor (recipeOf "CKM_CHACHA20"))

recipeOf :: Text -> Chacha20Recipe
recipeOf name =
  case chachaRecipeFor (MechanismId (mustGeneratedId name)) of
    Just r -> r
    Nothing -> error ("test recipe missing: " ++ show name)

nonce12 :: BS.ByteString
nonce12 = "0123456789ab"

casePolyParams :: IO ()
casePolyParams = do
  let poly = recipeOf "CKM_CHACHA20_POLY1305"
      good tag nonce = encodeChachaPolyParams nonce "AD" tag
  -- The fixed tag validates at the IETF nonce.
  assertBool "tag 16 valid" (chachaParamsValid poly (good 16 nonce12))
  -- Any other tag width refuses (the Poly1305 tag is fixed).
  mapM_ (\t -> assertBool ("tag refused " ++ show t)
    (not (chachaParamsValid poly (good t nonce12)))) [0, 4, 8, 12, 15, 17, 32]
  -- Nonce is exactly the IETF 12.
  assertBool "nonce 8 refused"
    (not (chachaParamsValid poly (good 16 "12345678")))
  assertBool "nonce 16 refused"
    (not (chachaParamsValid poly (good 16 "0123456789abcdef")))
  assertBool "nonce empty refused"
    (not (chachaParamsValid poly (good 16 BS.empty)))
  -- AAD is free-form (including empty); garbage never validates.
  assertBool "empty aad valid"
    (chachaParamsValid poly (encodeChachaPolyParams nonce12 BS.empty 16))
  assertBool "garbage refused" (not (chachaParamsValid poly "nope"))
  assertBool "truncated refused"
    (not (chachaParamsValid poly (BS.take 20 (good 16 nonce12))))

caseStreamParams :: IO ()
caseStreamParams = do
  let stream = recipeOf "CKM_CHACHA20"
      good c n = encodeChachaStreamParams c n
  -- Counters 0..bound validate at the IETF nonce.
  mapM_ (\c -> assertBool ("counter " ++ show c)
    (chachaParamsValid stream (good c nonce12)))
    [0, 1, 2, chachaMaxCounter]
  -- Past the bound refuses.
  assertBool "counter bound+1 refused"
    (not (chachaParamsValid stream (good (chachaMaxCounter + 1) nonce12)))
  -- Nonce is exactly the IETF 12.
  assertBool "nonce 8 refused"
    (not (chachaParamsValid stream (good 0 "12345678")))
  assertBool "nonce empty refused"
    (not (chachaParamsValid stream (good 0 BS.empty)))
  -- The stream image is exact-length: trailing garbage refuses.
  assertBool "trailing garbage refused"
    (not (chachaParamsValid stream (good 0 nonce12 <> "x")))
  assertBool "garbage refused" (not (chachaParamsValid stream "nope"))

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

polyMech :: MechanismId
polyMech = MechanismId ckm_CHACHA20_POLY1305

streamMech :: MechanismId
streamMech = MechanismId ckm_CHACHA20

testEnv :: OpEnv
testEnv = OpEnv
  { oeRegistry = curatedRegistry
  , oeCaps = mkCapabilities [(polyMech, OpEncrypt), (streamMech, OpEncrypt)]
  , oeModel = emptyModel
  }

-- | Unknown handle: valid parameters proceed PAST the parameter check
-- to key resolution (proving acceptance); bad parameters stop at
-- 'CKR_ARGUMENTS_BAD'.
badKey :: KeyPolicy
badKey = KeyPolicy (ExternalHandle 999) [OpEncrypt] False

runInit :: InitArgs -> ReturnCode
runInit args = ioCode (snd (initOperation testEnv emptySessionOps testSession args))

mkArgs :: MechanismId -> BS.ByteString -> InitArgs
mkArgs mech params = InitArgs OpEncrypt mech params (Just badKey)
  (Just (CipherSpec 1 False)) Nothing

caseInitParams :: IO ()
caseInitParams = do
  let goodPoly = encodeChachaPolyParams nonce12 "AD" 16
      goodStream = encodeChachaStreamParams 0 nonce12
  assertEqual "poly bad tag refused" CKR_ARGUMENTS_BAD
    (runInit (mkArgs polyMech (encodeChachaPolyParams nonce12 "AD" 8)))
  assertEqual "poly bad nonce refused" CKR_ARGUMENTS_BAD
    (runInit (mkArgs polyMech (encodeChachaPolyParams "12345678" "AD" 16)))
  assertEqual "poly garbage refused" CKR_ARGUMENTS_BAD
    (runInit (mkArgs polyMech "nope"))
  assertEqual "poly valid params pass to key resolution" CKR_OBJECT_HANDLE_INVALID
    (runInit (mkArgs polyMech goodPoly))
  assertEqual "stream past-bound counter refused" CKR_ARGUMENTS_BAD
    (runInit (mkArgs streamMech (encodeChachaStreamParams (chachaMaxCounter + 1) nonce12)))
  assertEqual "stream bad nonce refused" CKR_ARGUMENTS_BAD
    (runInit (mkArgs streamMech (encodeChachaStreamParams 0 "12345678")))
  assertEqual "stream garbage refused" CKR_ARGUMENTS_BAD
    (runInit (mkArgs streamMech "nope"))
  assertEqual "stream valid params pass to key resolution" CKR_OBJECT_HANDLE_INVALID
    (runInit (mkArgs streamMech goodStream))

caseDriverAead :: IO ()
caseDriverAead = do
  let p = encodeChachaPolyParams nonce12 "AD" 16
  assertEqual "poly-256" (Just (AeadSpec "ChaCha20-Poly1305" 12 16))
    (aeadSpecFor polyMech 32 p)
  assertEqual "poly rejects short key" Nothing
    (aeadSpecFor polyMech 16 p)
  assertEqual "poly rejects bad tag" Nothing
    (aeadSpecFor polyMech 32 (encodeChachaPolyParams nonce12 "AD" 8))
  assertEqual "poly rejects bad nonce" Nothing
    (aeadSpecFor polyMech 32 (encodeChachaPolyParams "12345678" "AD" 16))
  assertEqual "non-poly uncovered" Nothing
    (aeadSpecFor (MechanismId ckm_SHA256) 32 p)

caseDriverStream :: IO ()
caseDriverStream = do
  let p = encodeChachaStreamParams 0 nonce12
  assertEqual "stream-256" (Just C_CHACHA20)
    (cipherSpecFor streamMech 32 p)
  assertEqual "stream counter 1 maps" (Just C_CHACHA20)
    (cipherSpecFor streamMech 32 (encodeChachaStreamParams 1 nonce12))
  assertEqual "stream rejects short key" Nothing
    (cipherSpecFor streamMech 16 p)
  assertEqual "stream rejects past-bound counter" Nothing
    (cipherSpecFor streamMech 32
      (encodeChachaStreamParams (chachaMaxCounter + 1) nonce12))
  assertEqual "stream rejects bad nonce" Nothing
    (cipherSpecFor streamMech 32 (encodeChachaStreamParams 0 "12345678"))
  assertEqual "non-stream uncovered" Nothing
    (cipherSpecFor (MechanismId ckm_SHA256) 32 p)

caseNative :: IO ()
caseNative = do
  let stream = recipeOf "CKM_CHACHA20"
      poly = recipeOf "CKM_CHACHA20_POLY1305"
      aad = BS.pack [0x02, 0x03]
      ctr1 = BS.pack [0x01, 0x00, 0x00, 0x00]
  -- Stream: (counter LE bytes, 32 bits, IETF nonce, 96 bits).
  case chachaStreamStructToCanonical ctr1 32 nonce12 96 of
    Just img -> case decodeChachaStreamParams img of
      Just (c, n) -> do
        assertEqual "counter" 1 c
        assertEqual "nonce" nonce12 n
        assertBool "recipe accepts" (chachaParamsValid stream img)
      Nothing -> assertFailure "translated stream image undecodable"
    Nothing -> assertFailure "valid stream struct refused"
  -- The counter is little-endian (RFC 8439 state-word order):
  -- 34 12 00 00 is 0x1234, not 0x34120000.
  case chachaStreamStructToCanonical (BS.pack [0x34, 0x12, 0x00, 0x00]) 32 nonce12 96
    >>= decodeChachaStreamParams of
    Just (c, _) -> assertEqual "LE counter" 0x1234 c
    Nothing -> assertFailure "LE counter undecodable"
  -- The 64-bit counter width translates (value 1 serves as the
  -- IETF counter 1); the 64-bit max overflows Int and refuses.
  assertBool "64-bit counter translates" (isJust
    (chachaStreamStructToCanonical (BS.pack [0x01, 0, 0, 0, 0, 0, 0, 0]) 64 nonce12 96))
  assertBool "counter overflow refuses" (isNothing
    (chachaStreamStructToCanonical (BS.replicate 8 0xff) 64 nonce12 96))
  assertBool "over-wide counter refuses" (isNothing
    (chachaStreamStructToCanonical (BS.replicate 9 0) 72 nonce12 96))
  -- Width/bytes disagreement refuses (never a misread chase).
  assertBool "counter bits mismatch refuses" (isNothing
    (chachaStreamStructToCanonical ctr1 24 nonce12 96))
  assertBool "nonce bits mismatch refuses" (isNothing
    (chachaStreamStructToCanonical ctr1 32 nonce12 64))
  -- Non-IETF widths translate and refuse downstream, never here.
  case chachaStreamStructToCanonical ctr1 32 "12345678" 64 of
    Just img -> assertBool "64-bit nonce refused downstream"
      (not (chachaParamsValid stream img))
    Nothing -> assertFailure "non-IETF width refused at translation"
  -- Poly: (nonce, byte length, AAD, byte length) at the fixed tag.
  case chachaPolyStructToCanonical nonce12 12 aad 2 of
    Just img -> case decodeChachaPolyParams img of
      Just (n, a, t) -> do
        assertEqual "nonce" nonce12 n
        assertEqual "aad" aad a
        assertEqual "tag fixed 16" 16 t
        assertBool "recipe accepts" (chachaParamsValid poly img)
      Nothing -> assertFailure "translated poly image undecodable"
    Nothing -> assertFailure "valid poly struct refused"
  assertBool "poly nonceLen mismatch refuses" (isNothing
    (chachaPolyStructToCanonical nonce12 11 aad 2))
  assertBool "poly aadLen mismatch refuses" (isNothing
    (chachaPolyStructToCanonical nonce12 12 aad 3))
  case chachaPolyStructToCanonical "12345678" 8 aad 2 of
    Just img -> assertBool "off-12 nonce refused downstream"
      (not (chachaParamsValid poly img))
    Nothing -> assertFailure "non-IETF width refused at translation"
  assertBool "unrepresentable width refuses" (isNothing
    (chachaStreamStructToCanonical ctr1 32 nonce12 (maxBound :: Word64)))

caseCipherShape :: IO ()
caseCipherShape = do
  -- The planner gates classic inits on this shape; without it init
  -- refuses before the driver is reached.
  assertEqual "stream cipher shape" (Just (CipherSpec 1 False))
    (cipherShapeFor streamMech)
  assertEqual "poly cipher shape" (Just (CipherSpec 1 False))
    (cipherShapeFor polyMech)
