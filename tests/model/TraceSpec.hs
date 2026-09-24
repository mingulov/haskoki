{- | Trace contract suite.

§7 JSONL fields, redaction by default, bounded queue + dropped
counter, sink failure never changes the CKR, drops-as-failure mode.
-}
module TraceSpec (spec) where

import qualified Data.ByteString.Char8 as BC8
import Data.IORef (newIORef, readIORef, modifyIORef')
import Data.List (isInfixOf)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertBool, assertEqual, testCase)

import Haskoki.Runtime.Trace

spec :: TestTree
spec = testGroup "Trace"
  [ testCase "JSONL carries every §7 field" caseFields
  , testCase "PINs, key material and bodies redacted" caseRedaction
  , testCase "bounded queue + dropped counter under flood" caseFlood
  , testCase "sink failure leaves the CKR unchanged" caseSinkFailure
  , testCase "drops-as-failure fails the harness run" caseDropsAsFailure
  ]

ids :: TraceIds
ids = TraceIds "trace/1" "haskoki-test" "trace-spec" "demo-maximal" "run-1"

ev :: TraceEvent
ev = TraceEvent
  { teFunction = "C_Sign"
  , teInterface = "3.2"
  , teMechanism = Just "CKM_RSA_PKCS"
  , teSession = Just "s1"
  , teObject = Just "demo-signing-key"
  , teJob = Nothing
  , teInputLen = 12
  , teOutputLen = 256
  , teCkr = 0
  , teDisposition = "delivered"
  , teReason = "rule:none"
  , teMode = "sync"
  , teSecret = Nothing
  }

caseFields :: IO ()
caseFields = do
  let line = BC8.unpack (renderJSONL ids 7 ev)
  mapM_ (\k -> assertBool ("field present: " ++ k) (k `isInfixOf` line))
    [ "\"schema\":\"trace/1\"", "\"build\":\"haskoki-test\""
    , "\"source\":\"trace-spec\"", "\"profile\":\"demo-maximal\""
    , "\"run\":\"run-1\"", "\"seq\":7", "\"function\":\"C_Sign\""
    , "\"interface\":\"3.2\"", "\"mechanism\":\"CKM_RSA_PKCS\""
    , "\"session\":\"s1\"", "\"object\":\"demo-signing-key\""
    , "\"input_len\":12", "\"output_len\":256", "\"ckr\":0"
    , "\"disposition\":\"delivered\"", "\"reason\":\"rule:none\""
    , "\"mode\":\"sync\""
    ]

caseRedaction :: IO ()
caseRedaction = do
  let withPin = ev { teSecret = Just (TracePin "1234") }
      withKey = ev { teSecret = Just (TraceKeyMaterial "AAECAwQFBg==") }
      withBody = ev { teSecret = Just (TraceBody "super-secret-bytes") }
      rendered = map (BC8.unpack . renderJSONL ids 1) [withPin, withKey, withBody]
  mapM_ (\line -> assertBool "redaction marker" ("\"redacted\":true" `isInfixOf` line)) rendered
  assertBool "no PIN leak" (not ("1234" `isInfixOf` concat rendered))
  assertBool "no key leak" (not ("AAECAwQFBg==" `isInfixOf` concat rendered))
  assertBool "no body leak" (not ("super-secret-bytes" `isInfixOf` concat rendered))
  -- Lengths survive (reproducibility via lengths, not secrets).
  case rendered of
    (first : _) -> assertBool "pin length kept" ("\"length\":4" `isInfixOf` first)
    [] -> fail "redaction cases vanished"

caseFlood :: IO ()
caseFlood = do
  kept <- newIORef (0 :: Int)
  tr <- newTracer 100 (\_ -> modifyIORef' kept (+ 1) >> pure (Right ())) False
  mapM_ (\_ -> emitTrace tr ev 0 >> pure ()) [1 .. 500 :: Int]
  d <- droppedTraces tr
  assertEqual "drops counted" 400 d
  rep <- drainTracer tr
  assertEqual "bounded drain" 100 (drWritten rep)
  assertEqual "no sink failures" 0 (drFailed rep)
  k <- readIORef kept
  assertEqual "sink saw the bound" 100 k

caseSinkFailure :: IO ()
caseSinkFailure = do
  tr <- newTracer 16 (\_ -> pure (Left "EIO")) False
  -- The CKR on the way in is the CKR on the way out, always.
  c1 <- emitTrace tr ev 0
  c2 <- emitTrace tr ev { teCkr = 5 } 5
  assertEqual "ok preserved" 0 c1
  assertEqual "error preserved" 5 c2
  rep <- drainTracer tr
  assertEqual "failures reported, not thrown" 2 (drFailed rep)
  assertEqual "nothing written" 0 (drWritten rep)

caseDropsAsFailure :: IO ()
caseDropsAsFailure = do
  tr <- newTracer 4 (\_ -> pure (Right ())) True
  mapM_ (\_ -> emitTrace tr ev 0 >> pure ()) [1 .. 10 :: Int]
  ok <- runHarnessChecked tr
  assertBool "drops fail the harness run" (not ok)
  tr2 <- newTracer 64 (\_ -> pure (Right ())) True
  mapM_ (\_ -> emitTrace tr2 ev 0 >> pure ()) [1 .. 10 :: Int]
  ok2 <- runHarnessChecked tr2
  assertBool "no drops keeps the run passing" ok2
  -- Same flood without the mode: harness stays passing (loss counted, not fatal).
  tr3 <- newTracer 4 (\_ -> pure (Right ())) False
  mapM_ (\_ -> emitTrace tr3 ev 0 >> pure ()) [1 .. 10 :: Int]
  ok3 <- runHarnessChecked tr3
  assertBool "non-strict mode tolerates counted drops" ok3
