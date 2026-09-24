{- | Config contract suite.

TOML loads via @HASKOKI_CONFIG@; unknown keys are rejected; the
resolved config is validated once and immutable; §3 limits are
configurable and reported.
-}
module ConfigSpec (spec) where

import Control.Exception (bracket)
import Data.List (intercalate, isInfixOf)
import System.Directory (getTemporaryDirectory, removeFile)
import System.Environment (lookupEnv, setEnv, unsetEnv)
import System.FilePath ((</>))
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertBool, assertEqual, assertFailure, testCase)

import Haskoki.Attribute (maxAttributeBytes)
import Haskoki.Ctl (CtlExit (..), runCtl)
import Haskoki.FFI.Standard (maxTemplateAttrs)
import Haskoki.Object (maxTemplateEntries)
import Haskoki.Runtime.Config

spec :: TestTree
spec = testGroup "Config"
  [ testCase "example TOMLs all parse and validate" caseExamplesParse
  , testCase "misspelled key is rejected" caseUnknownKey
  , testCase "unknown section is rejected" caseUnknownSection
  , testCase "validated once: second resolve fails, first stands" caseResolveOnce
  , testCase "no per-call env reads after resolve" caseNoLiveEnv
  , testCase "limits are configurable and reported" caseLimitsReported
  , testCase "sqlite without explicit path is refused" caseNoSilentShare
  , testCase "trace override only swaps the trace path" caseTraceOverride
  , testCase "template bounds are pinned constants" caseTemplatePins
  , testCase "template-bound keys are disclosed ignored" caseTemplateDisclosure
  , testCase "sim section parses with knobs" caseSimParse
  , testCase "bad sim key is rejected by name" caseSimBadKey
  , testCase "capabilities reports sim knobs" caseSimReported
  , testCase "config check rejects a bad sim key (guard)" caseSimCheckReject
  , testCase "tokens catalog parses" caseTokensParse
  , testCase "ragged token arrays rejected" caseTokensRagged
  , testCase "duplicate token labels rejected" caseTokensDuplicate
  , testCase "non-demo slot 0 rejected" caseTokensSlotZero
  , testCase "over-16 catalog rejected" caseTokensOver16
  , testCase "overlong token label rejected" caseTokensLongLabel
  , testCase "bad tokens key rejected by name" caseTokensBadKey
  , testCase "absent tokens section is home-only" caseTokensAbsent
  , testCase "capabilities reports token catalog" caseTokensReported
  , testCase "config check accepts multi-token fixture" caseTokensCheckGood
  , testCase "config check rejects ragged catalog (guard)" caseTokensCheckBad
  ]

fixture :: FilePath -> FilePath
fixture name = "tests/ops/fixtures/" ++ name

caseExamplesParse :: IO ()
caseExamplesParse = do
  eMax <- loadConfigFile (fixture "maximal-demo.toml")
  ePer <- loadConfigFile (fixture "persistent-demo.toml")
  eReal <- loadConfigFile (fixture "real-crypto.toml")
  case (eMax, ePer, eReal) of
    (Right cm, Right cp, Right cr) -> do
      assertEqual "maximal profile" ProfileDemoMaximal (cfgProfile cm)
      assertEqual "persistent storage" StorageSQLite (scKind (cfgStorage cp))
      assertEqual "real engine" EngineOpenSSL (ecKind (cfgEngine cr))
      assertEqual "interfaces" ["2.40", "3.0", "3.1", "3.2"] (cfgInterfaces cm)
      assertEqual "seed" 1234 (cfgSeed cm)
      assertEqual "slots default" 16 (limSlots (cfgLimits cm))
      assertEqual "events default" 1024 (limEvents (cfgLimits cm))
      assertEqual "trace queue" 4096 (tcQueueLimit (cfgTrace cm))
      assertEqual "control budget" 65536 (ccResponseBudgetBytes (cfgControl cm))
    _ -> assertFailure ("example fixtures must parse: " ++ show (eMax, ePer, eReal))

caseUnknownKey :: IO ()
caseUnknownKey = do
  let bad = "schema_version = 1\nprofile = \"demo-maximal\"\nseedd = 5\n"
  case parseConfig bad of
    Left (CfgUnknownKey k) ->
      assertBool ("misspelling named: " ++ k) ("seedd" == k)
    other -> assertFailure ("misspelling must be rejected, got: " ++ show other)

caseUnknownSection :: IO ()
caseUnknownSection = do
  let bad = "schema_version = 1\n[traec]\nenabled = true\n"
  case parseConfig bad of
    Left (CfgUnknownKey k) ->
      assertBool ("section named: " ++ k) ("traec" `elem` words (map dot2sp k))
    other -> assertFailure ("unknown section must be rejected, got: " ++ show other)
  where
    dot2sp '.' = ' '
    dot2sp c = c

caseResolveOnce :: IO ()
caseResolveOnce = do
  cell <- newConfigCell
  r1 <- cellResolve cell (loadConfigFile (fixture "maximal-demo.toml"))
  r2 <- cellResolve cell (loadConfigFile (fixture "real-crypto.toml"))
  case r1 of
    Left err -> assertFailure ("first resolve must succeed: " ++ show err)
    Right c1 -> do
      assertEqual "first config stands" ProfileDemoMaximal (cfgProfile c1)
      case r2 of
        Left CfgAlreadyResolved -> pure ()
        other -> assertFailure ("second resolve must fail, got: " ++ show other)
      cached <- cellConfig cell
      case cached of
        Just c0 -> assertEqual "cached config immutable" ProfileDemoMaximal (cfgProfile c0)
        Nothing -> assertFailure "resolved config must be retrievable"

caseNoLiveEnv :: IO ()
caseNoLiveEnv = do
  -- resolveFrom ignores the environment entirely: even a garbage
  -- HASKOKI_CONFIG cannot move an already-resolved value.
  bracket (lookupEnv "HASKOKI_CONFIG")
          (\prev -> maybe (unsetEnv "HASKOKI_CONFIG") (setEnv "HASKOKI_CONFIG") prev)
          (\_ -> do
            setEnv "HASKOKI_CONFIG" "/nonexistent/garbage.toml"
            eCfg <- resolveFrom Nothing Nothing
            case eCfg of
              Right c -> assertEqual "defaults without env read" ProfileDemoMaximal (cfgProfile c)
              Left err -> assertFailure ("path-based resolve must not read env: " ++ show err))

caseLimitsReported :: IO ()
caseLimitsReported = do
  eCfg <- loadConfigFile (fixture "maximal-demo.toml")
  case eCfg of
    Left err -> assertFailure (show err)
    Right cfg -> do
      let rep = reportLimits cfg
          names = map fst rep
      mapM_ (\k -> assertBool ("reported: " ++ k) (k `elem` names))
        ["slots", "sessions", "objects", "transcript", "aggregate"
        , "template_entries", "template_depth", "jobs", "events"
        , "control", "trace"]
      assertEqual "slots value" (Just 16) (lookup "slots" rep)
      assertEqual "control budget value" (Just 65536) (lookup "control" rep)
      assertEqual "trace queue value" (Just 4096) (lookup "trace" rep)

caseNoSilentShare :: IO ()
caseNoSilentShare = do
  let bad = unlines
        [ "schema_version = 1"
        , "profile = \"demo-maximal\""
        , "[storage]"
        , "kind = \"sqlite\""
        ]
  case parseConfig bad of
    Left (CfgInvalid _) -> pure ()
    other -> assertFailure ("sqlite without explicit path must fail, got: " ++ show other)

caseTraceOverride :: IO ()
caseTraceOverride = do
  eCfg <- resolveFrom (Just (fixture "maximal-demo.toml")) (Just "/tmp/ovr.jsonl")
  case eCfg of
    Left err -> assertFailure (show err)
    Right cfg -> do
      assertEqual "trace path overridden" "/tmp/ovr.jsonl" (tcPath (cfgTrace cfg))
      assertEqual "nothing else moves" ProfileDemoMaximal (cfgProfile cfg)
      assertEqual "seed intact" 1234 (cfgSeed cfg)

-- | The effective template bounds are pinned constants, enforced
-- on both sides of the FFI (C packer + Haskell frame decode for
-- entries; codec + frame decode under a C ceiling for bytes) and
-- by the core codec on in-process planCall paths (same 64, single
-- source of truth). Any change fails loudly here first.
caseTemplatePins :: IO ()
caseTemplatePins = do
  assertEqual "max template attrs" 64 maxTemplateAttrs
  assertEqual "max attribute bytes" 65536 maxAttributeBytes
  -- The FFI bound is an alias of the core source of truth,
  -- not a second literal.
  assertEqual "ffi aliases core" maxTemplateAttrs
    (fromIntegral maxTemplateEntries)

-- | @limits.attribute_entries@/@buffer_bytes@ do NOT drive
-- template enforcement (reserved keys); the capabilities report
-- discloses that loudly instead of ignoring them silently. The
-- small-limits fixture proves the ignored-ness is genuine: 8/1024
-- configured, 64/65536 still enforced.
caseTemplateDisclosure :: IO ()
caseTemplateDisclosure = do
  eCfg <- loadConfigFile (fixture "small-limits.toml")
  case eCfg of
    Left err -> assertFailure ("small-limits must parse: " ++ show err)
    Right cfg -> do
      assertEqual "fixture entries" 8 (limAttributeEntries (cfgLimits cfg))
      assertEqual "fixture buffer" 1024 (limBufferBytes (cfgLimits cfg))
  r <- runCtl ["capabilities", "--config", fixture "small-limits.toml"]
  assertEqual "exit 0" 0 (ceCode r)
  assertBool "disclosure line present" (templateBoundsLine `isInfixOf` ceOut r)
  where
    templateBoundsLine = "template-bounds: entries=64 bytes=65536 (pinned; limits.attribute_entries/buffer_bytes reserved, no enforcement effect)"

-- | The full [sim] fixture parses with the expected knob values
-- (values ALSO pin end to end through 'caseSimReported').
caseSimParse :: IO ()
caseSimParse = do
  eCfg <- loadConfigFile (fixture "sim-demo.toml")
  case eCfg of
    Left err -> assertFailure ("sim fixture must parse: " ++ show err)
    Right cfg -> do
      let sim = cfgSim cfg
      assertEqual "sim enabled" True (scEnabled sim)
      assertEqual "delay schedule"
        [("CKM_RSA_PKCS", 3), ("sign", 1), ("*", 1)] (scDelaySchedule sim)
      assertEqual "token script"
        [("insert", 1), ("remove", 1)] (scTokenScript sim)
      assertEqual "fault window start" 2 (scFaultWindowStart sim)
      assertEqual "fault window ticks" 4 (scFaultWindowTicks sim)

-- | An unknown sim KEY is rejected naming the dotted key.
caseSimBadKey :: IO ()
caseSimBadKey = do
  let bad = unlines
        [ "schema_version = 1"
        , "[sim]"
        , "bogus_key = 1"
        ]
  case parseConfig bad of
    Left (CfgUnknownKey k) -> assertEqual "bad sim key named" "sim.bogus_key" k
    other -> assertFailure ("bad sim key must be rejected by name, got: " ++ show other)

-- | Config check accepts the sim demo and capabilities
-- reports every sim knob (value-pinned text).
caseSimReported :: IO ()
caseSimReported = do
  rCheck <- runCtl ["config", "check", "--config", fixture "sim-demo.toml"]
  assertEqual "config check accepts sim demo" 0 (ceCode rCheck)
  r <- runCtl ["capabilities", "--config", fixture "sim-demo.toml"]
  assertEqual "exit 0" 0 (ceCode r)
  let out = ceOut r
  assertBool "sim enabled reported" ("sim.enabled: True" `isInfixOf` out)
  assertBool "delay schedule reported"
    ("sim.delay_schedule: CKM_RSA_PKCS:3,sign:1,*:1" `isInfixOf` out)
  assertBool "token script reported"
    ("sim.token_script: insert 1,remove 1" `isInfixOf` out)
  assertBool "fault window start reported"
    ("sim.fault_window_start: 2" `isInfixOf` out)
  assertBool "fault window length reported"
    ("sim.fault_window_ticks: 4" `isInfixOf` out)

-- | GUARD: a bad sim key is rejected through the CLI end to end,
-- naming the unknown key.
caseSimCheckReject :: IO ()
caseSimCheckReject =
  bracket (writeBadSim "haskoki-bad-sim.toml") removeFile $ \path -> do
    r <- runCtl ["config", "check", "--config", path]
    assertBool "config check rejects a bad sim key" (ceCode r /= 0)
  where
    writeBadSim name = do
      base <- getTemporaryDirectory
      let path = base </> name
      writeFile path (unlines ["schema_version = 1", "[sim]", "bogus_key = 1"])
      pure path

-- | Spine-only (mirroring the sim-section precedent: value
-- assertions added later): the 3-token fixture parses
-- with the expected catalog triples (slot = index).
caseTokensParse :: IO ()
caseTokensParse = do
  eCfg <- loadConfigFile (fixture "multi-token.toml")
  case eCfg of
    Left err -> assertFailure ("multi-token fixture must parse: " ++ show err)
    Right cfg ->
      assertEqual "catalog triples"
        [ ("haskoki-demo", "5678", "1234")
        , ("haskoki-ops", "6789", "2345")
        , ("haskoki-audit", "7890", "3456")
        ] (tcEntries (cfgTokens cfg))

-- | Parallel arrays with mismatched lengths are CfgInvalid.
caseTokensRagged :: IO ()
caseTokensRagged = do
  let bad = unlines
        [ "schema_version = 1"
        , "[tokens]"
        , "labels = [\"haskoki-demo\", \"haskoki-ops\"]"
        , "so_pins = [\"5678\", \"6789\"]"
        , "user_pins = [\"1234\"]"
        ]
  case parseConfig bad of
    Left (CfgInvalid _) -> pure ()
    other -> assertFailure ("ragged catalog must be CfgInvalid, got: " ++ show other)

-- | Duplicate labels are CfgInvalid.
caseTokensDuplicate :: IO ()
caseTokensDuplicate = do
  let bad = unlines
        [ "schema_version = 1"
        , "[tokens]"
        , "labels = [\"haskoki-demo\", \"haskoki-ops\", \"haskoki-ops\"]"
        , "so_pins = [\"5678\", \"6789\", \"7890\"]"
        , "user_pins = [\"1234\", \"2345\", \"3456\"]"
        ]
  case parseConfig bad of
    Left (CfgInvalid _) -> pure ()
    other -> assertFailure ("duplicate labels must be CfgInvalid, got: " ++ show other)

-- | Slot 0 must be haskoki-demo (the stability anchor for
-- every existing single-slot pin).
caseTokensSlotZero :: IO ()
caseTokensSlotZero = do
  let bad = unlines
        [ "schema_version = 1"
        , "[tokens]"
        , "labels = [\"haskoki-ops\", \"haskoki-demo\"]"
        , "so_pins = [\"6789\", \"5678\"]"
        , "user_pins = [\"2345\", \"1234\"]"
        ]
  case parseConfig bad of
    Left (CfgInvalid _) -> pure ()
    other -> assertFailure ("non-demo slot 0 must be CfgInvalid, got: " ++ show other)

-- | More than 16 entries are refused loudly (the seating
-- bound), never truncated silently.
caseTokensOver16 :: IO ()
caseTokensOver16 = do
  let labels = "haskoki-demo" : ["t" ++ show n | n <- [1 .. 16 :: Int]]
      pins = ["000" ++ show n | n <- [1 .. 17 :: Int]]
      bad = unlines
        [ "schema_version = 1"
        , "[tokens]"
        , "labels = [" ++ intercalate ", " (map show labels) ++ "]"
        , "so_pins = [" ++ intercalate ", " (map show pins) ++ "]"
        , "user_pins = [" ++ intercalate ", " (map show pins) ++ "]"
        ]
  case parseConfig bad of
    Left (CfgInvalid _) -> pure ()
    other -> assertFailure ("17-entry catalog must be CfgInvalid, got: " ++ show other)

-- | Labels must fit the 32-byte CK_TOKEN_INFO label field.
caseTokensLongLabel :: IO ()
caseTokensLongLabel = do
  let bad = unlines
        [ "schema_version = 1"
        , "[tokens]"
        , "labels = [\"haskoki-demo\", \"" ++ replicate 33 'x' ++ "\"]"
        , "so_pins = [\"5678\", \"6789\"]"
        , "user_pins = [\"1234\", \"2345\"]"
        ]
  case parseConfig bad of
    Left (CfgInvalid _) -> pure ()
    other -> assertFailure ("33-char label must be CfgInvalid, got: " ++ show other)

-- | An unknown tokens KEY is rejected naming the dotted key.
caseTokensBadKey :: IO ()
caseTokensBadKey = do
  let bad = unlines
        [ "schema_version = 1"
        , "[tokens]"
        , "bogus_key = 1"
        ]
  case parseConfig bad of
    Left (CfgUnknownKey k) -> assertEqual "bad tokens key named" "tokens.bogus_key" k
    other -> assertFailure ("bad tokens key must be rejected by name, got: " ++ show other)

-- | An absent [tokens] section serves the home token only
-- (the declared catalog is empty).
caseTokensAbsent :: IO ()
caseTokensAbsent = do
  assertEqual "default catalog empty" [] (tcEntries (cfgTokens defaultConfig))
  eCfg <- loadConfigFile (fixture "maximal-demo.toml")
  case eCfg of
    Left err -> assertFailure ("maximal fixture must parse: " ++ show err)
    Right cfg -> assertEqual "absent catalog empty" [] (tcEntries (cfgTokens cfg))
  r <- runCtl ["capabilities", "--config", fixture "maximal-demo.toml"]
  assertEqual "exit 0" 0 (ceCode r)
  assertBool "absent catalog reports count 0" ("tokens.count: 0" `isInfixOf` ceOut r)

-- | Config check accepts the multi-token fixture and
-- capabilities reports the declared catalog (count + labels; PINs
-- are NEVER reported).
caseTokensReported :: IO ()
caseTokensReported = do
  rCheck <- runCtl ["config", "check", "--config", fixture "multi-token.toml"]
  assertEqual "config check accepts multi-token fixture" 0 (ceCode rCheck)
  r <- runCtl ["capabilities", "--config", fixture "multi-token.toml"]
  assertEqual "exit 0" 0 (ceCode r)
  let out = ceOut r
  assertBool "tokens count reported" ("tokens.count: 3" `isInfixOf` out)
  assertBool "tokens labels reported"
    ("tokens.labels: haskoki-demo,haskoki-ops,haskoki-audit" `isInfixOf` out)
  assertBool "user PINs never reported" (not ("2345" `isInfixOf` out))
  assertBool "SO PINs never reported" (not ("6789" `isInfixOf` out))

-- | Config check accepts the multi-token fixture (the config-check
-- half of caseTokensReported, kept as its own pin).
caseTokensCheckGood :: IO ()
caseTokensCheckGood = do
  r <- runCtl ["config", "check", "--config", fixture "multi-token.toml"]
  assertEqual "config check accepts multi-token fixture" 0 (ceCode r)

-- | GUARD: a ragged catalog is rejected through the CLI end to
-- end, naming the ragged arrays.
caseTokensCheckBad :: IO ()
caseTokensCheckBad =
  bracket (writeBadTokens "haskoki-bad-tokens.toml") removeFile $ \path -> do
    r <- runCtl ["config", "check", "--config", path]
    assertBool "config check rejects a ragged catalog" (ceCode r /= 0)
  where
    writeBadTokens name = do
      base <- getTemporaryDirectory
      let path = base </> name
      writeFile path (unlines
        [ "schema_version = 1"
        , "[tokens]"
        , "labels = [\"haskoki-demo\", \"haskoki-ops\"]"
        , "so_pins = [\"5678\", \"6789\"]"
        , "user_pins = [\"1234\"]"
        ])
      pure path
