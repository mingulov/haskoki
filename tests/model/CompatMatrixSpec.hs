{- | Compatibility-matrix contract suite.

@docs/compatibility.md@ is generated (see @scripts/generate_compat.py@),
never hand-edited. This spec pins what the checked-in doc must say:
its Versions agree with the tree's constants, its table is total
over binary x store x config x interface with every cell resolving
to works/migrate/refuse, and the pinned behaviors behind the
headline cells hold. Store-dimension pins live in the storage suite
(@testV1RefusesWithoutWriting@, the v2 refusal pin,
@caseOpenLegacyRefusesMigrationRequired@,
@caseOpenReorderRefuses@) and are cited here by name, not duplicated.
-}
module CompatMatrixSpec (spec) where

import Data.Char (isSpace)
import Data.List (isInfixOf, isPrefixOf, sort)
import System.Directory (doesFileExist)
import System.Environment (getExecutablePath)
import System.FilePath (takeDirectory, (</>))
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertBool, assertEqual, assertFailure, testCase)

import Haskoki.Runtime.Config (cfgInterfaces, cfgSchemaVersion, defaultConfig, parseConfig, ConfigError (..))
import Haskoki.Runtime.Storage.SQLite (sqliteSchemaVersion)

spec :: TestTree
spec = testGroup "Compatibility matrix"
  [ testCase "matrix doc exists" caseDocExists
  , testCase "doc versions match the tree constants" caseVersionsMatch
  , testCase "every cell resolves works/migrate/refuse" caseCellsResolve
  , testCase "matrix is total over all four dimensions" caseMatrixTotal
  , testCase "memory fixture parses (works-cell config leg)" caseMemoryParses
  , testCase "unknown config schema refuses (refuse cell)" caseSchemaRefuses
  , testCase "unknown interface refuses (refuse cell)" caseInterfaceRefuses
  ]

-- | The package root, resolved CWD-independently: walk up from the
-- test binary's own directory to haskoki.cabal (falling back to a
-- CWD walk-up). Same shape as ErrorInterpSpec's funnel-hardened
-- resolver; kept local so this spec stands alone.
packageRoot :: IO FilePath
packageRoot = do
  exeDir <- takeDirectory <$> getExecutablePath
  fromExe <- ascend exeDir
  case fromExe of
    Just root -> pure root
    Nothing -> do
      fromCwd <- ascend "."
      case fromCwd of
        Just root -> pure root
        Nothing -> assertFailure
          "matrix: haskoki.cabal not found above executable or CWD"
  where
    ascend dir = do
      here <- doesFileExist (dir </> "haskoki.cabal")
      if here
        then pure (Just dir)
        else let parent = takeDirectory dir
             in if parent == dir
                then pure Nothing
                else ascend parent

readDoc :: IO String
readDoc = do
  root <- packageRoot
  let doc = root </> "docs/compatibility.md"
  exists <- doesFileExist doc
  if exists then readFile doc
    else assertFailure "docs/compatibility.md is missing (run scripts/generate_compat.py)"

cabalVersion :: IO String
cabalVersion = do
  root <- packageRoot
  content <- readFile (root </> "haskoki.cabal")
  case [v | l <- lines content, "version:" `isPrefixOf` l,
            let v = trim (drop (length "version:") l), not (null v)] of
    (v : _) -> pure v
    [] -> assertFailure "haskoki.cabal carries no version line"

trim :: String -> String
trim = reverse . dropWhile isSpace . reverse . dropWhile isSpace

-- | Table rows: @| binary | store | config | iface | verdict |@.
tableRows :: String -> [[String]]
tableRows doc =
  [cells | l <- lines doc, isRow l, let cells = parseRow l, length cells == 5]
  where
    isRow l = "|" `isPrefixOf` trim l && "Binary" `notElem` words l && "---" `notElem` words l
    parseRow l = map trim (splitOn '|' (stripPipes (trim l)))
    stripPipes = reverse . dropWhile (== '|') . reverse . dropWhile (== '|')
    splitOn _ [] = [""]
    splitOn c (x : xs)
      | x == c = "" : splitOn c xs
      | otherwise = case splitOn c xs of
          [] -> [[x]]
          (h : t) -> (x : h) : t

versionBullet :: String -> String -> Maybe String
versionBullet key doc =
  case [l | l <- lines doc, ("- " ++ key) `isPrefixOf` l] of
    (l : _) -> Just l
    [] -> Nothing

caseDocExists :: IO ()
caseDocExists = do
  _ <- readDoc
  pure ()

caseVersionsMatch :: IO ()
caseVersionsMatch = do
  doc <- readDoc
  binary <- cabalVersion
  let want =
        [ ("Binary: `" ++ binary ++ "`", "binary version")
        , ("Store schema served: `" ++ show sqliteSchemaVersion ++ "`", "store schema")
        , ("Config schema accepted: `" ++ show (cfgSchemaVersion defaultConfig) ++ "`", "config schema")
        ]
  mapM_ (\(needle, what) ->
    assertBool ("doc " ++ what ++ " matches the tree: " ++ needle)
      (needle `isInfixOf` doc)) want
  let ifaces = cfgInterfaces defaultConfig
  case versionBullet "Interfaces:" doc of
    Nothing -> assertFailure "doc lacks an Interfaces bullet"
    Just l -> mapM_ (\i ->
      assertBool ("doc interfaces list " ++ i) (("`" ++ i ++ "`") `isInfixOf` l)) ifaces

caseCellsResolve :: IO ()
caseCellsResolve = do
  doc <- readDoc
  rows <- pure (tableRows doc)
  assertBool "matrix table is non-empty" (not (null rows))
  mapM_ check rows
  where
    check cells@[_, _, _, _, v] =
      assertBool ("cell resolves: " ++ show cells) (v `elem` ["works", "migrate", "refuse"])
    check cells = assertFailure ("malformed row: " ++ show cells)

caseMatrixTotal :: IO ()
caseMatrixTotal = do
  doc <- readDoc
  binary <- cabalVersion
  rows <- pure (tableRows doc)
  let ifaces = cfgInterfaces defaultConfig
      want =
        [ [binary, s, c, i]
        | s <- ["memory", "1", "2", "3", "other"]
        , c <- [show (cfgSchemaVersion defaultConfig), "other"]
        , i <- ifaces ++ ["other"]
        ]
      have = sort [[b, s, c, i] | [b, s, c, i, _] <- rows]
  assertEqual "every combination present exactly once" (sort want) have

caseMemoryParses :: IO ()
caseMemoryParses = do
  root <- packageRoot
  body <- readFile (root </> "tests/ops/fixtures/maximal-demo.toml")
  case parseConfig body of
    Left err -> assertFailure ("memory fixture must parse: " ++ show err)
    Right _ -> pure ()

caseSchemaRefuses :: IO ()
caseSchemaRefuses =
  case parseConfig "schema_version = 2\n" of
    Left (CfgInvalid _) -> pure ()
    other -> assertFailure ("unknown schema must refuse, got: " ++ show other)

caseInterfaceRefuses :: IO ()
caseInterfaceRefuses =
  case parseConfig "schema_version = 1\ninterfaces = [\"9.9\"]\n" of
    Left (CfgInvalid _) -> pure ()
    other -> assertFailure ("unknown interface must refuse, got: " ++ show other)
