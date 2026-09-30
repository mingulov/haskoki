{- | Control ABI contract suite.

64 KiB budget rule, pure budget query, too-small executes nothing,
unknown/malformed without mutation, generation checks, test-gated
mutations, paginated in-budget responses.
-}
module ControlSpec (spec) where

import qualified Data.ByteString.Char8 as BC8
import Data.List (isInfixOf)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertBool, assertEqual, testCase)

import Haskoki.Runtime.Async (newAsyncTable)
import Haskoki.Runtime.Config (defaultConfig)
import Haskoki.Runtime.Control
import Haskoki.Runtime.Events (OverflowPolicy (DropOldest), newEventQueue, newTokenRegistry)
import Haskoki.Types (ReturnCode (..), SlotId (..))

spec :: TestTree
spec = testGroup "Control"
  [ testCase "null capacity is a pure budget query" caseBudgetQuery
  , testCase "short capacity: too-small + required + no mutation" caseTooSmall
  , testCase "sufficient capacity executes exactly once" caseExecuteOnce
  , testCase "unknown command: argument error, no mutation" caseUnknown
  , testCase "malformed JSON: argument error, no mutation" caseMalformed
  , testCase "generation mismatch refuses" caseGeneration
  , testCase "mutations need a test-enabled instance" caseTestGate
  , testCase "responses fit the budget (paginated)" casePaginated
  , testCase "unsafe-debug gates test key/PIN material" caseUnsafeDebug
  ]

mkState :: Bool -> Bool -> IO ControlState
mkState testEnabled unsafeDebug = do
  eq <- newEventQueue 64 DropOldest
  at <- newAsyncTable 16
  reg <- newTokenRegistry eq at
  st <- newControlState defaultConfig reg at testEnabled unsafeDebug
  bindPrivatePresenceOwner st reg
  pure st

statusReq :: BC8.ByteString
statusReq = BC8.pack "{\"schema_version\":1,\"command\":\"status\",\"arguments\":{}}"

insertReq :: Int -> BC8.ByteString
insertReq slot = BC8.pack
  ("{\"schema_version\":1,\"command\":\"token.insert\",\"arguments\":{\"slot\":" ++ show slot ++ "}}")

genOf :: ControlState -> IO BC8.ByteString
genOf st = do
  (_, body, _) <- dispatchControl st statusReq (Just 65536)
  pure body

caseBudgetQuery :: IO ()
caseBudgetQuery = do
  st <- mkState True False
  before <- genOf st
  (code, body, required) <- dispatchControl st (insertReq 0) Nothing
  after <- genOf st
  assertEqual "query ok" CKR_OK code
  assertEqual "empty body" BC8.empty body
  assertEqual "required is the budget" 65536 required
  assertEqual "executed nothing" before after

caseTooSmall :: IO ()
caseTooSmall = do
  st <- mkState True False
  before <- genOf st
  (code, body, required) <- dispatchControl st (insertReq 0) (Just 100)
  after <- genOf st
  assertEqual "too small" CKR_BUFFER_TOO_SMALL code
  assertEqual "empty body" BC8.empty body
  assertEqual "required is the budget" 65536 required
  assertEqual "executed nothing" before after

caseExecuteOnce :: IO ()
caseExecuteOnce = do
  st <- mkState True False
  (code, body, actual) <- dispatchControl st (insertReq 0) (Just 65536)
  assertEqual "insert ok" CKR_OK code
  assertBool "actual length honest" (fromIntegral (BC8.length body) == actual)
  assertBool "response names the slot" ("\"slot\":0" `isInfixOf` BC8.unpack body)
  present <- controlTokenPresent st (SlotId 0)
  assertBool "token seated" present
  -- A repeat insert is idempotent, not a second mutation row.
  (code2, _, _) <- dispatchControl st (insertReq 0) (Just 65536)
  assertEqual "re-insert ok" CKR_OK code2

caseUnknown :: IO ()
caseUnknown = do
  st <- mkState True False
  before <- genOf st
  let bad = BC8.pack "{\"schema_version\":1,\"command\":\"token.selfdestruct\",\"arguments\":{}}"
  (code, body, _) <- dispatchControl st bad (Just 65536)
  after <- genOf st
  assertEqual "argument error" CKR_ARGUMENTS_BAD code
  assertBool "error tagged" ("\"error\"" `isInfixOf` BC8.unpack body)
  assertEqual "no mutation" before after

caseMalformed :: IO ()
caseMalformed = do
  st <- mkState True False
  before <- genOf st
  (code, _, _) <- dispatchControl st (BC8.pack "{\"schema_version\":") (Just 65536)
  after <- genOf st
  assertEqual "argument error" CKR_ARGUMENTS_BAD code
  assertEqual "no mutation" before after

caseGeneration :: IO ()
caseGeneration = do
  st <- mkState True False
  _ <- dispatchControl st (insertReq 0) (Just 65536)
  g <- controlGeneration st
  let stale = BC8.pack ("{\"schema_version\":1,\"command\":\"token.remove\","
        ++ "\"arguments\":{\"slot\":0,\"expected_generation\":" ++ show (g + 99) ++ "}}")
  (code, _, _) <- dispatchControl st stale (Just 65536)
  assertEqual "stale generation refuses" CKR_ARGUMENTS_BAD code
  present <- controlTokenPresent st (SlotId 0)
  assertBool "token still seated" present
  let fresh = BC8.pack ("{\"schema_version\":1,\"command\":\"token.remove\","
        ++ "\"arguments\":{\"slot\":0,\"expected_generation\":" ++ show g ++ "}}")
  (code2, _, _) <- dispatchControl st fresh (Just 65536)
  assertEqual "fresh generation proceeds" CKR_OK code2

caseTestGate :: IO ()
caseTestGate = do
  st <- mkState False False
  (codeS, _, _) <- dispatchControl st statusReq (Just 65536)
  assertEqual "status needs no test instance" CKR_OK codeS
  (codeI, bodyI, _) <- dispatchControl st (insertReq 0) (Just 65536)
  assertEqual "insert refused" CKR_ARGUMENTS_BAD codeI
  assertBool "refusal names the gate" ("test_instance_required" `isInfixOf` BC8.unpack bodyI)
  present <- controlTokenPresent st (SlotId 0)
  assertBool "nothing seated" (not present)

casePaginated :: IO ()
casePaginated = do
  st <- mkState True False
  let paged = BC8.pack ("{\"schema_version\":1,\"command\":\"status\","
        ++ "\"arguments\":{\"offset\":0,\"limit\":4}}")
  (code, body, actual) <- dispatchControl st paged (Just 65536)
  assertEqual "paged status ok" CKR_OK code
  assertBool "fits budget" (actual <= 65536)
  assertBool "page marker" ("\"paginated\":true" `isInfixOf` BC8.unpack body)

caseUnsafeDebug :: IO ()
caseUnsafeDebug = do
  stSafe <- mkState True False
  (_, safeBody, _) <- dispatchControl stSafe statusReq (Just 65536)
  assertBool "safe status hides fixture PIN" (not ("1234" `isInfixOf` BC8.unpack safeBody))
  stDbg <- mkState True True
  (_, dbgBody, _) <- dispatchControl stDbg statusReq (Just 65536)
  assertBool "unsafe-debug reveals fixture marker" ("fixture_pin" `isInfixOf` BC8.unpack dbgBody)
