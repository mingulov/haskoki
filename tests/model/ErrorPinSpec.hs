{- | Code-snapshot pins: error->code mappings that the error
unification must preserve exactly. Reads
@tests/fixtures/code-snapshot.txt@ and asserts current behavior
matches every line (the IRON INVARIANT: no ReturnCode change on
any path).
-}
module ErrorPinSpec (spec) where

import qualified Data.ByteString as BS
import qualified Data.Map.Strict as Map
import Data.Map.Strict (Map)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertEqual, assertFailure, testCase)

import Haskoki.Engine.Driver (encodeResult)
import Haskoki.Model (SessionState (..), emptyModel)
import Haskoki.Operation
  ( CipherSpec (..)
  , CryptoError (..)
  , CryptoResult (..)
  , InitArgs (..)
  , InitOutcome (..)
  , KeyPolicy (..)
  , OpEnv (..)
  , cryptoCode
  , emptySessionOps
  , initOperation
  )
import qualified Haskoki.Outcome as O
import Haskoki.Registry (MechanismId (..), Operation (..), curatedRegistry, mkCapabilities)
import Haskoki.Session (SessionLogin (..))
import Haskoki.Types
  ( ExternalHandle (..)
  , Generation (..)
  , Revision (..)
  , SessionId (..)
  , SlotId (..)
  )

spec :: TestTree
spec = testGroup "Code snapshot pins"
  [ testCase "cryptoCode table matches snapshot" caseCryptoCode
  , testCase "encodeResult taxonomy matches snapshot" caseEncode
  , testCase "init deny codes match snapshot" caseDenyInit
  , testCase "init deny reasons match snapshot" caseDenyReason
  ]

snapshotPaths :: [FilePath]
snapshotPaths =
  [ "tests/fixtures/code-snapshot.txt"
  , "tests/fixtures/taxonomy.txt"
  ]

loadSnapshot :: IO (Map String String)
loadSnapshot = do
  bodies <- mapM readFile snapshotPaths
  pure (Map.unions (map (parseSnapshot . lines) bodies))

-- | Minimal @[section]@ / @key = value@ parser. Malformed lines fail
-- loudly: a silent skip would weaken the pin.
parseSnapshot :: [String] -> Map String String
parseSnapshot = go "" Map.empty
  where
    go :: String -> Map String String -> [String] -> Map String String
    go _ acc [] = acc
    go sec acc (raw : rest) =
      case trim raw of
        "" -> go sec acc rest
        ('#' : _) -> go sec acc rest
        ('[' : xs) -> case span (/= ']') xs of
          (name, ']' : _) -> go name acc rest
          _ -> error ("ErrorPinSpec: bad section line: " ++ raw)
        kv -> case break (== '=') kv of
          (k, '=' : v) -> go sec (Map.insert (sec ++ "." ++ trim k) (trim v) acc) rest
          _ -> error ("ErrorPinSpec: bad snapshot line: " ++ raw)

    trim :: String -> String
    trim = reverse . dropWhile (== ' ') . reverse . dropWhile (== ' ')

expect :: Map String String -> String -> String -> IO ()
expect snap key actual = case Map.lookup key snap of
  Nothing -> assertFailure ("snapshot lacks key: " ++ key)
  Just want -> assertEqual ("snapshot " ++ key) want actual

cryptoTag :: CryptoError -> String
cryptoTag err = case err of
  CryptoFailed _ -> "CryptoFailed"
  CryptoUnsupported _ _ -> "CryptoUnsupported"
  CryptoBadParam _ _ -> "CryptoBadParam"
  CryptoBadKey _ _ -> "CryptoBadKey"
  CryptoMechParamInvalid _ _ -> "CryptoMechParamInvalid"
  CryptoAuthFailed _ -> "CryptoAuthFailed"
  CryptoInvalidState _ _ -> "CryptoInvalidState"
  CryptoNative _ _ _ -> "CryptoNative"
  CryptoResourceGone _ _ -> "CryptoResourceGone"

failureTag :: O.BackendFailure -> String
failureTag f = case f of
  O.BackendUnsupported _ _ -> "BackendUnsupported"
  O.BackendBadParam _ _ -> "BackendBadParam"
  O.BackendBadKey _ _ -> "BackendBadKey"
  O.BackendMechParamInvalid _ _ -> "BackendMechParamInvalid"
  O.BackendAuthFailed _ -> "BackendAuthFailed"
  O.BackendInvalidState _ _ -> "BackendInvalidState"
  O.BackendNative _ _ _ -> "BackendNative"
  O.BackendResourceGone _ _ -> "BackendResourceGone"

encodeTag :: CryptoError -> String
encodeTag err = case encodeResult (GotCryptoError err) of
  O.EngineFail f -> failureTag f
  _ -> "unexpected-success"

caseCryptoCode :: IO ()
caseCryptoCode = do
  snap <- loadSnapshot
  let errs =
        [ CryptoFailed "x"
        , CryptoUnsupported "o" "x"
        , CryptoBadKey "o" "x"
        , CryptoAuthFailed "x"
        ]
  mapM_ (\e -> expect snap ("cryptoCode." ++ cryptoTag e) (show (cryptoCode e))) errs
  -- The snapshot must pin exactly these four original ctors.
  assertEqual "cryptoCode row count" 4
    (length (filter ("cryptoCode." `isPrefixOfStr`) (Map.keys snap)))

caseEncode :: IO ()
caseEncode = do
  snap <- loadSnapshot
  let errs =
        [ CryptoUnsupported "o" "x"
        , CryptoBadKey "o" "x"
        , CryptoAuthFailed "x"
        , CryptoFailed "x"
        ]
  mapM_ (\e -> expect snap ("encode." ++ cryptoTag e) (encodeTag e)) errs

caseDenyInit :: IO ()
caseDenyInit = do
  snap <- loadSnapshot
  let badMech = digestArgs { iaMech = unknownMech }
      (_, o1) = initOperation pinEnv emptySessionOps pinSession badMech
  expect snap "denyInit.unknown-mech" (show (ioCode o1))
  let (ops1, _) = initOperation pinEnv emptySessionOps pinSession digestArgs
      (_, o2) = initOperation pinEnv ops1 pinSession digestArgs
  expect snap "denyInit.conflict" (show (ioCode o2))
  let (_, o3) = initOperation pinEnv emptySessionOps pinSession encryptArgs
  expect snap "denyInit.key-required" (show (ioCode o3))
  let badKey = encryptArgs { iaKey = Just (KeyPolicy (ExternalHandle 0xbeef) [OpEncrypt] False) }
      (_, o4) = initOperation pinEnv emptySessionOps pinSession badKey
  expect snap "denyInit.bad-handle" (show (ioCode o4))

caseDenyReason :: IO ()
caseDenyReason = do
  snap <- loadSnapshot
  let badMech = digestArgs { iaMech = unknownMech }
      (_, o1) = initOperation pinEnv emptySessionOps pinSession badMech
  expect snap "denyReason.unknown-mech" (firstReason o1)
  let (ops1, _) = initOperation pinEnv emptySessionOps pinSession digestArgs
      (_, o2) = initOperation pinEnv ops1 pinSession digestArgs
  expect snap "denyReason.conflict" (firstReason o2)
  let (_, o3) = initOperation pinEnv emptySessionOps pinSession encryptArgs
  expect snap "denyReason.key-required" (firstReason o3)
  let badKey = encryptArgs { iaKey = Just (KeyPolicy (ExternalHandle 0xbeef) [OpEncrypt] False) }
      (_, o4) = initOperation pinEnv emptySessionOps pinSession badKey
  expect snap "denyReason.bad-handle" (firstReason o4)

firstReason :: InitOutcome -> String
firstReason o = case ioReasons o of
  (r : _) -> r
  [] -> "<no reason>"

isPrefixOfStr :: String -> String -> Bool
isPrefixOfStr [] _ = True
isPrefixOfStr _ [] = False
isPrefixOfStr (x : xs) (y : ys) = x == y && isPrefixOfStr xs ys

-- | Local fixtures mirroring OperationSpec (unknown mechanism,
-- SHA-256 digest, AES-CBC encrypt).
sha256Mech :: MechanismId
sha256Mech = MechanismId 0x250

aesCbcMech :: MechanismId
aesCbcMech = MechanismId 0x1082

unknownMech :: MechanismId
unknownMech = MechanismId 0x9999

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
