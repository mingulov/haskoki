{- | Typed denials until the edge. Every 'StepDeny' producer must
carry a matchable 'DenyDetail' (not just a code plus English text)
through 'denyOutcome' and the init rejection path to the edge, with a
single 'prettyDeny' renderer at the boundary. Codes and rendered
messages are unchanged (see ErrorPinSpec).
-}
{-# LANGUAGE OverloadedStrings #-}
module ErrorDetailSpec (spec) where

import qualified Data.ByteString as BS
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertEqual, assertFailure, testCase)

import Haskoki.Model (SessionState (..), emptyModel)
import Haskoki.Operation
  ( CipherSpec (..)
  , CryptoResult (..)
  , DenyDetail (..)
  , InitArgs (..)
  , InitOutcome (..)
  , OpEnv (..)
  , SlotKind (..)
  , StepDeny (..)
  , StepOutcome (..)
  , denyOutcome
  , emptySessionOps
  , initOperation
  , mkDeny
  , prettyDeny
  , sdReason
  )
import Haskoki.Operation.Cipher (finishCipher)
import Haskoki.Registry (MechanismId (..), Operation (..), curatedRegistry, mkCapabilities)
import Haskoki.Request (OutputIntent (..))
import Haskoki.Session (SessionLogin (..))
import Haskoki.Types
  ( Generation (..)
  , Revision (..)
  , ReturnCode (..)
  , SessionId (..)
  , SlotId (..)
  )

spec :: TestTree
spec = testGroup "Typed denials"
  [ testCase "unknown mechanism denial is typed" caseMech
  , testCase "bad params denial is typed" caseParams
  , testCase "key binding denial is typed" caseKey
  , testCase "auth/state denial is typed" caseAuth
  , testCase "op-state denial is typed" caseOpState
  , testCase "range denial is typed" caseRange
  , testCase "general denial is typed" caseGeneral
  , testCase "code and message survive typing" caseStable
  , testCase "denyOutcome carries the detail" caseCarry
  , testCase "init rejection carries the detail" caseInitCarry
  , testCase "data-call denial carries the detail" caseDataCarry
  ]

detailOf :: StepDeny -> DenyDetail
detailOf = sdDetail

caseMech :: IO ()
caseMech = case detailOf (mkDeny CKR_MECHANISM_INVALID "unknown mechanism") of
  DenyUnknownMechanism _ -> pure ()
  other -> assertFailure ("expected DenyUnknownMechanism, got " ++ show other)

caseParams :: IO ()
caseParams = case detailOf (mkDeny CKR_ARGUMENTS_BAD "operation requires a key") of
  DenyBadParams _ -> pure ()
  other -> assertFailure ("expected DenyBadParams, got " ++ show other)

caseKey :: IO ()
caseKey = case detailOf (mkDeny CKR_KEY_FUNCTION_NOT_PERMITTED "key refuses") of
  DenyKeyBinding _ -> pure ()
  other -> assertFailure ("expected DenyKeyBinding, got " ++ show other)

caseAuth :: IO ()
caseAuth = case detailOf (mkDeny CKR_USER_NOT_LOGGED_IN "needs login") of
  DenyAuthState _ -> pure ()
  other -> assertFailure ("expected DenyAuthState, got " ++ show other)

caseOpState :: IO ()
caseOpState = case detailOf (mkDeny CKR_OPERATION_NOT_INITIALIZED "no op") of
  DenyOpState _ -> pure ()
  other -> assertFailure ("expected DenyOpState, got " ++ show other)

caseRange :: IO ()
caseRange = case detailOf (mkDeny CKR_DATA_LEN_RANGE "too short") of
  DenyRange _ -> pure ()
  other -> assertFailure ("expected DenyRange, got " ++ show other)

caseGeneral :: IO ()
caseGeneral = case detailOf (mkDeny CKR_GENERAL_ERROR "boom") of
  DenyGeneral _ -> pure ()
  other -> assertFailure ("expected DenyGeneral, got " ++ show other)

caseStable :: IO ()
caseStable = do
  let d = mkDeny CKR_ARGUMENTS_BAD "operation requires a key"
  assertEqual "code preserved" CKR_ARGUMENTS_BAD (sdCode d)
  assertEqual "rendered message preserved" "operation requires a key" (prettyDeny (sdDetail d))
  assertEqual "legacy reason preserved" "operation requires a key" (sdReason d)

caseCarry :: IO ()
caseCarry = do
  let d = mkDeny CKR_MECHANISM_INVALID "unknown mechanism"
      o = denyOutcome d
  assertEqual "deny code" CKR_MECHANISM_INVALID (soCode o)
  assertEqual "deny reasons" ["unknown mechanism"] (soReasons o)
  case soDeny o of
    Just (DenyUnknownMechanism _) -> pure ()
    other -> assertFailure ("denyOutcome dropped the detail: " ++ show other)

caseInitCarry :: IO ()
caseInitCarry = do
  let badMech = digestArgs { iaMech = MechanismId 0x9999 }
      (_, o1) = initOperation pinEnv emptySessionOps pinSession badMech
  assertEqual "init deny code" CKR_MECHANISM_INVALID (ioCode o1)
  case ioDeny o1 of
    Just (DenyUnknownMechanism _) -> pure ()
    other -> assertFailure ("init rejection dropped the detail: " ++ show other)
  let (ops1, _) = initOperation pinEnv emptySessionOps pinSession digestArgs
      (_, o2) = initOperation pinEnv ops1 pinSession digestArgs
  case ioDeny o2 of
    Just (DenyOpState _) -> pure ()
    other -> assertFailure ("conflict rejection dropped the detail: " ++ show other)
  let (_, o3) = initOperation pinEnv emptySessionOps pinSession encryptArgs
  case ioDeny o3 of
    Just (DenyBadParams _) -> pure ()
    other -> assertFailure ("key-required rejection dropped the detail: " ++ show other)
  -- Success carries no denial.
  let (_, ok) = initOperation pinEnv emptySessionOps pinSession digestArgs
  assertEqual "success has no denial" Nothing (ioDeny ok)

caseDataCarry :: IO ()
caseDataCarry = do
  -- A cipher final with no active slot denies through the finisher.
  let (_, o) = finishCipher emptySessionOps SlotEncrypt "probe"
        (GotBytes "junk") (IntentBuffer 128)
  assertEqual "data-call deny code" CKR_OPERATION_NOT_INITIALIZED (soCode o)
  case soDeny o of
    Just (DenyOpState _) -> pure ()
    other -> assertFailure ("data-call denial dropped the detail: " ++ show other)

sha256Mech :: MechanismId
sha256Mech = MechanismId 0x250

aesCbcMech :: MechanismId
aesCbcMech = MechanismId 0x1082

pinEnv :: OpEnv
pinEnv = OpEnv
  { oeRegistry = curatedRegistry
  , oeCaps = mkCapabilities [(sha256Mech, OpDigest), (aesCbcMech, OpEncrypt)]
  , oeModel = emptyModel
  }

pinSession :: SessionState
pinSession = SessionState
  { ssId = SessionId 1
  , ssSlot = SlotId 7
  , ssRevision = Revision 1
  , ssGeneration = Generation 1
  , ssReadOnly = False
  , ssLogin = LoginPublic
  , ssOps = emptySessionOps
  }

digestArgs :: InitArgs
digestArgs = InitArgs
  { iaOp = OpDigest
  , iaMech = sha256Mech
  , iaParams = BS.empty
  , iaKey = Nothing
  , iaCipher = Nothing
  , iaRecover = Nothing
  }

encryptArgs :: InitArgs
encryptArgs = InitArgs
  { iaOp = OpEncrypt
  , iaMech = aesCbcMech
  , iaParams = BS.replicate 16 0
  , iaKey = Nothing
  , iaCipher = Just (CipherSpec 16 True)
  , iaRecover = Nothing
  }
