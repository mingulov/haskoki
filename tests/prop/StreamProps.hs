{- | Streaming laws: digest init-feed*-final equals the one-shot
over random chunkings on both backends, and illegal backend orders
(feed/final without init, double final) reject with the pinned
resource-gone failure.
-}
{-# LANGUAGE OverloadedStrings #-}
module StreamProps (spec) where

import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import Data.Word (Word64)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertEqual, assertFailure, testCase)

import Gen (chunking, lcgBytes, maxChunks)
import Haskoki.Engine.Backend
  ( BackendEnv
  , BackendError (..)
  , CryptoBackend (..)
  , DigestAlg (..)
  , EngineResult (..)
  )
import Haskoki.Engine.Driver (runEffect)
import Haskoki.Engine.OpenSSL4 (OpenSSL4)
import Haskoki.Engine.Synthetic (Synthetic)
import Haskoki.Operation
  ( CryptoEffect (..)
  , CryptoError (..)
  , CryptoResult (..)
  )
import Haskoki.Registry (MechanismId (..))
import Haskoki.Types (EngineResourceId (..), ObjectId)

sha256Mech :: MechanismId
sha256Mech = MechanismId 0x250

-- | Digests bind no key.
noKeys :: ObjectId -> Maybe a
noKeys _ = Nothing

openSynth :: IO (BackendEnv Synthetic)
openSynth = do
  res <- openBackend "0" :: IO (EngineResult (BackendEnv Synthetic))
  case res of
    EngineOk env -> pure env
    EngineFail err -> assertFailure ("synth open: " ++ show err) >> undefined

openOssl :: IO (BackendEnv OpenSSL4)
openOssl = do
  res <- openBackend "provider=default" :: IO (EngineResult (BackendEnv OpenSSL4))
  case res of
    EngineOk env -> pure env
    EngineFail err -> assertFailure ("ossl4 open: " ++ show err) >> undefined

withBackends :: (BackendEnv Synthetic -> BackendEnv OpenSSL4 -> IO ()) -> IO ()
withBackends action = do
  synth <- openSynth
  ossl <- openOssl
  action synth ossl
  closeBackend synth
  closeBackend ossl

spec :: Int -> TestTree
spec count =
  testGroup
    "streaming laws"
    [ testCase "streamed equals one-shot" (caseStreamed count)
    , testCase "feed/final without init reject" caseUnknown
    , testCase "double final rejects" caseDoubleFinal
    , testCase "driver consume without init rejects" caseConsumeGhost
    ]

expectBytes :: String -> CryptoResult -> IO ByteString
expectBytes label res = case res of
  GotBytes b -> pure b
  other -> assertFailure (label ++ ": wanted bytes, got " ++ show other) >> undefined

expectResource :: String -> CryptoResult -> IO EngineResourceId
expectResource label res = case res of
  GotResource rid -> pure rid
  other -> assertFailure (label ++ ": wanted resource, got " ++ show other) >> undefined

-- | Feed answers keep their unit shape through the driver
-- helpers (no longer collapsing to empty bytes at 'toUnit').
expectUnit :: String -> CryptoResult -> IO ()
expectUnit label res = case res of
  GotUnit -> pure ()
  other -> assertFailure (label ++ ": wanted unit, got " ++ show other) >> undefined

-- | Stream one input through init-feed*-consume; the bytes must equal
-- the one-shot over the same input.
streamEqualsOneShot
  :: CryptoBackend b => BackendEnv b -> ByteString -> [ByteString] -> IO ()
streamEqualsOneShot be input chunks = do
  one <- runEffect be noKeys (FxDigest sha256Mech input) >>= expectBytes "one-shot"
  rid <- runEffect be noKeys (FxDigestInit sha256Mech) >>= expectResource "init"
  mapM_ (feed rid) chunks
  multi <- runEffect be noKeys (FxDigestConsume rid) >>= expectBytes "consume"
  assertEqual "streamed == one-shot" one multi
  where
    feed :: EngineResourceId -> ByteString -> IO ()
    feed rid part = do
      _ <- runEffect be noKeys (FxDigestFeed rid part) >>= expectUnit "feed"
      pure ()

-- | Generated inputs (sizes 0..128 cycling) plus explicit empty and
-- single-byte edges, each over every chunk count 1..maxChunks.
caseStreamed :: Int -> IO ()
caseStreamed count = withBackends $ \synth ossl ->
  mapM_ (checkInput synth ossl) (edgeInputs ++ genInputs)
  where
    genInputs :: [(Word64, ByteString)]
    genInputs =
      [ (s, lcgBytes s (fromIntegral (s `mod` 129)))
      | s <- [1 .. fromIntegral count]
      ]
    edgeInputs :: [(Word64, ByteString)]
    edgeInputs = [(100001, BS.empty), (100002, BS.singleton 0x00)]
    checkInput
      :: BackendEnv Synthetic -> BackendEnv OpenSSL4 -> (Word64, ByteString) -> IO ()
    checkInput synth ossl (seed, input) =
      mapM_ (checkCount synth ossl seed input) [1 .. maxChunks]
    checkCount
      :: BackendEnv Synthetic
      -> BackendEnv OpenSSL4
      -> Word64
      -> ByteString
      -> Int
      -> IO ()
    checkCount synth ossl seed input j = do
      let chunks = chunking seed j input
      streamEqualsOneShot synth input chunks
      streamEqualsOneShot ossl input chunks

ghostRid :: EngineResourceId
ghostRid = EngineResourceId 9999

assertGone :: Show a => String -> EngineResult a -> IO ()
assertGone op res = case res of
  EngineFail (BackendResourceGone gotOp gotRid) -> do
    assertEqual "gone op" op gotOp
    assertEqual "gone rid" ghostRid gotRid
  other -> assertFailure (op ++ ": wanted ResourceGone, got " ++ show other)

-- | Feed/final on a never-allocated stream reject on both backends.
caseUnknown :: IO ()
caseUnknown = withBackends $ \synth ossl -> do
  digestUpdate synth ghostRid "x" >>= assertGone "digestUpdate"
  digestFinal synth ghostRid >>= assertGone "digestFinal"
  digestUpdate ossl ghostRid "x" >>= assertGone "digestUpdate"
  digestFinal ossl ghostRid >>= assertGone "digestFinal"

-- | A second final on a consumed stream rejects on both backends.
caseDoubleFinal :: IO ()
caseDoubleFinal = withBackends $ \synth ossl -> do
  checkBackend synth
  checkBackend ossl
  where
    checkBackend :: CryptoBackend b => BackendEnv b -> IO ()
    checkBackend be = do
      rid <- digestInit be D_SHA256 >>= expectInit
      _ <- digestFinal be rid >>= expectFinal
      digestFinal be rid >>= assertGoneFinal rid
    expectInit :: EngineResult EngineResourceId -> IO EngineResourceId
    expectInit res = case res of
      EngineOk rid -> pure rid
      other -> assertFailure ("init: " ++ show other) >> undefined
    expectFinal :: EngineResult ByteString -> IO ByteString
    expectFinal res = case res of
      EngineOk b -> pure b
      other -> assertFailure ("final: " ++ show other) >> undefined
    assertGoneFinal :: EngineResourceId -> EngineResult ByteString -> IO ()
    assertGoneFinal rid res = case res of
      EngineFail (BackendResourceGone gotOp gotRid) -> do
        assertEqual "gone op" "digestFinal" gotOp
        assertEqual "gone rid" rid gotRid
      other -> assertFailure ("refinal: wanted ResourceGone, got " ++ show other)

-- | The driver maps a consume without init to the typed
-- resource-gone failure on both backends.
caseConsumeGhost :: IO ()
caseConsumeGhost = withBackends $ \synth ossl -> do
  checkBackend synth
  checkBackend ossl
  where
    checkBackend :: CryptoBackend b => BackendEnv b -> IO ()
    checkBackend be = do
      res <- runEffect be noKeys (FxDigestConsume ghostRid)
      case res of
        GotCryptoError (CryptoResourceGone _ gotRid) ->
          assertEqual "gone rid" ghostRid gotRid
        other -> assertFailure ("consume ghost: wanted CryptoResourceGone, got " ++ show other)
