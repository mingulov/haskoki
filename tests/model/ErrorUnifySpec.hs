{- | Backend failure vocabulary unification. A backend
'BackendAuthFailed'/'BackendInvalidState'/'BackendResourceGone' must
arrive at the finisher with its category intact (a matchable
constructor, never 'CryptoFailed' string soup); the three parallel
vocabularies convert losslessly both ways (round-trip pins); every
error still maps to its pinned code (see ErrorPinSpec).
-}
module ErrorUnifySpec (spec) where

import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertEqual, testCase)

import Haskoki.Engine.Backend (BackendError (..))
import Haskoki.Engine.Driver
  ( cryptoToCore
  , encodeResult
  , fromCoreFailure
  , toCoreFailure
  , toCryptoError
  )
import Haskoki.Operation (CryptoError (..), CryptoResult (..), cryptoCode)
import qualified Haskoki.Outcome as O
import qualified Haskoki.Transition as T
import Haskoki.Types (EngineResourceId (..), ReturnCode (..))

spec :: TestTree
spec = testGroup "Failure unification"
  [ testCase "backend error round-trips through core failure" caseRoundTripBackend
  , testCase "core failure round-trips through backend error" caseRoundTripCore
  , testCase "core mapping preserves every category" caseCoreMap
  , testCase "driver mapping preserves every category" caseDriverMap
  , testCase "auth failure reaches the edge typed" caseAuthTyped
  , testCase "new crypto codes match pinned collapse" caseNewCodes
  , testCase "crypto round-trips through core failure" caseRoundTripCrypto
  , testCase "unclassified bucket stays pinned" caseBucket
  ]

sampleErrors :: [BackendError]
sampleErrors =
  [ BackendUnsupported "op" "why"
  , BackendBadParam "op" "why"
  , BackendBadKey "op" "why"
  , BackendAuthFailed "op"
  , BackendInvalidState "op" "why"
  , BackendNative "op" 7 "why"
  , BackendResourceGone "op" (EngineResourceId 9)
  ]

sampleFailures :: [O.BackendFailure]
sampleFailures =
  [ O.BackendUnsupported "op" "why"
  , O.BackendBadParam "op" "why"
  , O.BackendBadKey "op" "why"
  , O.BackendAuthFailed "op"
  , O.BackendInvalidState "op" "why"
  , O.BackendNative "op" 7 "why"
  , O.BackendResourceGone "op" (EngineResourceId 9)
  ]

sampleCryptos :: [CryptoError]
sampleCryptos =
  [ CryptoUnsupported "op" "why"
  , CryptoBadParam "op" "why"
  , CryptoBadKey "op" "why"
  , CryptoAuthFailed "op"
  , CryptoInvalidState "op" "why"
  , CryptoNative "op" 7 "why"
  , CryptoResourceGone "op" (EngineResourceId 9)
  ]

caseRoundTripBackend :: IO ()
caseRoundTripBackend =
  mapM_ (\be -> assertEqual ("round-trip " ++ show be) be
    (fromCoreFailure (toCoreFailure be))) sampleErrors

caseRoundTripCore :: IO ()
caseRoundTripCore =
  mapM_ (\f -> assertEqual ("round-trip " ++ show f) f
    (toCoreFailure (fromCoreFailure f))) sampleFailures

cryptoTag :: CryptoError -> String
cryptoTag err = case err of
  CryptoFailed _ -> "CryptoFailed"
  CryptoUnsupported _ _ -> "CryptoUnsupported"
  CryptoBadParam _ _ -> "CryptoBadParam"
  CryptoBadKey _ _ -> "CryptoBadKey"
  CryptoAuthFailed _ -> "CryptoAuthFailed"
  CryptoInvalidState _ _ -> "CryptoInvalidState"
  CryptoNative _ _ _ -> "CryptoNative"
  CryptoResourceGone _ _ -> "CryptoResourceGone"

caseCoreMap :: IO ()
caseCoreMap = do
  let got = map (cryptoTag . T.toCryptoError) sampleFailures
  assertEqual "core 1:1 categories"
    [ "CryptoUnsupported"
    , "CryptoBadParam"
    , "CryptoBadKey"
    , "CryptoAuthFailed"
    , "CryptoInvalidState"
    , "CryptoNative"
    , "CryptoResourceGone"
    ] got
  -- No collapse into the unclassified bucket.
  mapM_ (\f -> assertEqual ("no collapse for " ++ show f) False
    (cryptoTag (T.toCryptoError f) == "CryptoFailed")) sampleFailures

caseDriverMap :: IO ()
caseDriverMap = do
  let got = map (cryptoTag . toCryptoError) sampleErrors
  assertEqual "driver 1:1 categories"
    [ "CryptoUnsupported"
    , "CryptoBadParam"
    , "CryptoBadKey"
    , "CryptoAuthFailed"
    , "CryptoInvalidState"
    , "CryptoNative"
    , "CryptoResourceGone"
    ] got

caseAuthTyped :: IO ()
caseAuthTyped =
  assertEqual "auth survives encodeResult"
    (O.EngineFail (O.BackendAuthFailed "tag-op"))
    (encodeResult (GotCryptoError (CryptoAuthFailed "tag-op")))

caseNewCodes :: IO ()
caseNewCodes = do
  assertEqual "bad param code" CKR_GENERAL_ERROR
    (cryptoCode (CryptoBadParam "op" "why"))
  assertEqual "invalid state code" CKR_GENERAL_ERROR
    (cryptoCode (CryptoInvalidState "op" "why"))
  assertEqual "native code" CKR_GENERAL_ERROR
    (cryptoCode (CryptoNative "op" 7 "why"))
  assertEqual "resource gone code" CKR_GENERAL_ERROR
    (cryptoCode (CryptoResourceGone "op" (EngineResourceId 9)))

caseRoundTripCrypto :: IO ()
caseRoundTripCrypto = do
  mapM_ (\c -> assertEqual ("crypto round-trip " ++ show c) c
    (T.toCryptoError (cryptoToCore c))) sampleCryptos
  mapM_ (\f -> assertEqual ("core round-trip " ++ show f) f
    (cryptoToCore (T.toCryptoError f))) sampleFailures

caseBucket :: IO ()
caseBucket = do
  assertEqual "bucket to core"
    (O.BackendNative "driver" (-1) "f")
    (cryptoToCore (CryptoFailed "f"))
  assertEqual "bucket through encode"
    (O.EngineFail (O.BackendNative "driver" (-1) "f"))
    (encodeResult (GotCryptoError (CryptoFailed "f")))
