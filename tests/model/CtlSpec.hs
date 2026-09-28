{- | CLI contract suite (hermetic).

@config check@, @capabilities@, @scenario run@ against an owned
instance, and help text that never claims live control. Store
subcommands live in the storage suite (needs file/SQLite deps).
-}
module CtlSpec (spec) where

import Data.List (isInfixOf)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertBool, assertEqual, testCase)

import Haskoki.Ctl (CtlExit (..), ctlHelp, runCtl)

spec :: TestTree
spec = testGroup "Haskoki-ctl"
  [ testCase "config check accepts the example TOMLs" caseConfigAccept
  , testCase "config check rejects a bad key" caseConfigReject
  , testCase "capabilities reports catalog + gaps" caseCapabilities
  , testCase "capabilities scopes the native engine binding" caseNativeScope
  , testCase "scenario run executes deterministically" caseScenario
  , testCase "help never claims live control" caseHelpHonest
  , testCase "openssl catalog serves CKM_SHA256" caseSha256Served
  ]

fixture :: FilePath -> FilePath
fixture name = "tests/ops/fixtures/" ++ name

caseConfigAccept :: IO ()
caseConfigAccept = do
  r1 <- runCtl ["config", "check", "--config", fixture "maximal-demo.toml"]
  r2 <- runCtl ["config", "check", "--config", fixture "persistent-demo.toml"]
  r3 <- runCtl ["config", "check", "--config", fixture "real-crypto.toml"]
  assertEqual "maximal ok" 0 (ceCode r1)
  assertEqual "persistent ok" 0 (ceCode r2)
  assertEqual "real-crypto ok" 0 (ceCode r3)

caseConfigReject :: IO ()
caseConfigReject = do
  r <- runCtl ["config", "check", "--config", fixture "scenario.json"]
  assertBool "scenario.json is not a config" (ceCode r /= 0)

caseCapabilities :: IO ()
caseCapabilities = do
  r <- runCtl ["capabilities", "--config", fixture "real-crypto.toml"]
  assertEqual "exit 0" 0 (ceCode r)
  let out = ceOut r
  assertBool "names the profile" ("real-crypto" `isInfixOf` out)
  assertBool "reports the active catalog" ("active-catalog" `isInfixOf` out)
  assertBool "reports the gap set" ("gap-set" `isInfixOf` out)
  r2 <- runCtl ["capabilities", "--config", fixture "maximal-demo.toml"]
  assertBool "demo-maximal labeled as target" ("target-profile" `isInfixOf` ceOut r2)
  -- The catalogs derive from the registry (no stale gaps,
  -- no phantom routes). Both engines serve all 154 tested
  -- behaviors (OpenSSL included: every behavior runs on real
  -- libcrypto since the KEM pair went real); both cover the
  -- 464-mechanism baseline exactly once.
  checkCatalog (ceOut r2) 250 214 "synthetic"
  checkCatalog out 250 214 "openssl"
  where
    reportLine prefix text =
      case [drop (length prefix) ln | ln <- lines text, prefix `isInfixOf` ln] of
        (l : _) -> words l
        [] -> []
    checkCatalog text wantActive wantGaps engine = do
      let active = reportLine "active-catalog:" text
          gaps = reportLine "gap-set:" text
      assertEqual (engine ++ " active count") wantActive (length active)
      assertEqual (engine ++ " gap count") wantGaps (length gaps)
      assertEqual (engine ++ " covers baseline") 464 (length active + length gaps)
      assertBool (engine ++ " active/gaps disjoint")
        (null [n | n <- active, n `elem` gaps])
      assertBool (engine ++ " serves HOTP") ("CKM_HOTP" `elem` active)
      assertBool (engine ++ " serves raw RSA") ("CKM_RSA_PKCS" `elem` active)
      assertBool (engine ++ " serves GCM") ("CKM_AES_GCM" `elem` active)
      assertBool (engine ++ " gaps XMSS") ("CKM_XMSS" `elem` gaps)
      assertBool (engine ++ " no bare HMAC phantom")
        (not ("CKM_HMAC " `isInfixOf` text))
      case engine of
        "synthetic" -> assertBool "synthetic mints HOTP keys"
          ("CKM_HOTP_KEY_GEN" `elem` active)
        _ -> do
          assertBool "real mints HOTP keys"
            ("CKM_HOTP_KEY_GEN" `elem` active)
          assertBool "real mints AES keys"
            ("CKM_AES_KEY_GEN" `elem` active)
          assertBool "real serves KEM"
            ("CKM_ML_KEM" `elem` active)
          assertBool "real mints KEM pairs"
            ("CKM_ML_KEM_KEY_PAIR_GEN" `elem` active)

-- | The report pins the native binding scope. All four
-- native opens ('haskoki_std_open', 'haskokiCryptoOpen',
-- 'haskokiAsyncOpen', 'haskokiAsyncOpenOn') bind @BackendEnv
-- OpenSSL4@ regardless of @engine.kind@; the exact scope sentence
-- below must appear for BOTH engine selections.
caseNativeScope :: IO ()
caseNativeScope = do
  r <- runCtl ["capabilities", "--config", fixture "maximal-demo.toml"]
  assertEqual "exit 0 (synthetic)" 0 (ceCode r)
  assertBool "synthetic config states the native binding"
    (nativeScopeLine `isInfixOf` ceOut r)
  r2 <- runCtl ["capabilities", "--config", fixture "real-crypto.toml"]
  assertEqual "exit 0 (openssl)" 0 (ceCode r2)
  assertBool "openssl config states the same binding"
    (nativeScopeLine `isInfixOf` ceOut r2)
  where
    nativeScopeLine = "native-engine: EngineOpenSSL (native paths always run OpenSSL4; engine/active-catalog describe the configured engine)"

caseScenario :: IO ()
caseScenario = do
  r1 <- runCtl ["scenario", "run", "--config", fixture "maximal-demo.toml"
               , "--scenario", fixture "scenario.json"]
  r2 <- runCtl ["scenario", "run", "--config", fixture "maximal-demo.toml"
               , "--scenario", fixture "scenario.json"]
  assertEqual "first run exits 0" 0 (ceCode r1)
  assertEqual "deterministic rerun" (ceOut r1) (ceOut r2)
  assertBool "steps executed" ("steps-executed" `isInfixOf` ceOut r1)
  assertBool "pending honored for async" ("CKR_PENDING" `isInfixOf` ceOut r1)

-- | Mirrors the install smoke's membership leg in-process.
-- The smoke asserts CKM_SHA256 over the C-served catalog; this case
-- asserts the same name over the configured-engine catalog behind
-- @capabilities@ (guard pin: serving already provides it).
caseSha256Served :: IO ()
caseSha256Served = do
  r <- runCtl ["capabilities", "--config", fixture "real-crypto.toml"]
  assertEqual "exit 0" 0 (ceCode r)
  let active = case [words (drop (length prefix) ln)
                    | ln <- lines (ceOut r), prefix `isInfixOf` ln] of
        (l : _) -> l
        [] -> []
      prefix = "active-catalog:"
  assertBool "CKM_SHA256 served" ("CKM_SHA256" `elem` active)

caseHelpHonest :: IO ()
caseHelpHonest = do
  r <- runCtl ["--help"]
  assertEqual "help exits 0" 0 (ceCode r)
  let h = ctlHelp ++ ceOut r
  assertBool "mentions owned instance" ("owned" `isInfixOf` h)
  assertBool "no remote-control claim" (not ("remote live control" `isInfixOf` h))
  assertBool "no live-control claim" (not ("live control" `isInfixOf` h))
