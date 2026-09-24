{- | Mechanism exhaustiveness battery (acceptance case A42).

A42: every catalog id in @spec/mechanisms-canonical.txt@ (the
'check-mechanisms.py' projection of @spec/mechanisms.json@, the
source of truth) routes through 'initOperation' — the classic-init
planning funnel — to its cataloged disposition:

* allowed ids (the 106 @mech|@ rows): the curated descriptor
  matches the cataloged name and routes exactly, every cataloged
  classic route initializes to @CKR_OK@ under full caps with
  valid parameters, and every cataloged NON-classic route
  (generate-key, derive, wrap families, encapsulate) refuses with
  the exact @(CKR_MECHANISM_INVALID, "not a classic
  operation")@ — that refusal is this funnel's honest routing:
  those operations plan through their own dedicated planners
  ('Haskoki.Operation.KeyManagement' for generate\/wrap,
  the derive\/KEM paths for derive\/encapsulate), pinned by
  @KeyManagementSpec@ (A20\/A22\/A23) and the engine suites,
  not through classic init;
* refused ids (the 358 @inv|@ rows): @StatusCatalogOnly@, no
  behavior descriptor, and init refuses with the exact
  @(CKR_MECHANISM_INVALID, "unknown mechanism")@ even under
  fully granted caps (the refusal is registry-driven, never a
  silent or bare unsupported).

Catalog coupling is structural: the battery parses the generated
projection at test time, so any catalog/code drift (a status flip,
a route change, an id rename) fails loudly here. A scratch
catalog mutation that flips one row's status must fail this
battery (proven per run, scratch discarded, log kept).

Shared with @haskoki-core-tests@ (pure-core imports only): the
core suite is in this battery's reporting closure.
-}
{-# LANGUAGE OverloadedStrings #-}
module MechanismExhaustivenessSpec (spec) where

import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import Data.List (sort)
import qualified Data.Map.Strict as Map
import Data.Map.Strict (Map)
import Data.Maybe (fromMaybe, isJust, isNothing)
import qualified Data.Text as T
import Data.Text (Text)
import qualified Data.Text.IO as TIO
import Data.Word (Word64)
import System.Directory (doesFileExist, getCurrentDirectory)
import System.Environment (getExecutablePath)
import System.FilePath (takeDirectory, (</>))
import System.Timeout (timeout)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertFailure, testCase)

import Haskoki.Attribute (AttributeType (..), AttributeValue (..))
import Haskoki.Model
  ( HandleBinding (..)
  , Model (..)
  , ObjectState (..)
  , SessionState (..)
  , emptyModel
  )
import Haskoki.Operation
  ( CipherSpec (..)
  , InitArgs (..)
  , InitOutcome (..)
  , KeyPolicy (..)
  , OpEnv (..)
  , RecoverSpec (..)
  , cipherDirOf
  , emptySessionOps
  , initOperation
  , recoverRoleOf
  , slotOf
  )
import Haskoki.Recipe.Cipher (BlockCipherRecipe (..), cipherRecipeFor)
import Haskoki.Recipe.Hmac (encodeMacGeneral)
import Haskoki.Recipe.Otp (encodeHotpParams)
import Haskoki.Recipe.RsaOaep (encodeOaepParams, rsaOaepRecipeFor)
import Haskoki.Recipe.RsaPss
  ( RsaPssRecipe (..)
  , encodePssParams
  , rsaPssRecipeFor
  )
import Haskoki.Registry
  ( Descriptor (..)
  , MechanismId (..)
  , MechanismStatus (..)
  , Operation (..)
  , behaviorRoutes
  , curatedRegistry
  , descRoutes
  , describeStatus
  , lookupBehavior
  , mkCapabilities
  , operationName
  , routeOperation
  )
import Haskoki.Session (SessionLogin (..))
import Haskoki.Types
  ( ExternalHandle (..)
  , Generation (..)
  , ObjectId (..)
  , ReturnCode (..)
  , Revision (..)
  , SessionId (..)
  , SlotId (..)
  )

spec :: TestTree
spec = testGroup "mechanism exhaustiveness (A42)"
  [ testCase "catalog coverage: 464 ids, 106 allowed + 358 refused" caseCoverage
  , testCase "allowed ids: descriptors match catalog routes" caseDescriptors
  , testCase "allowed routes: classic init OK, non-classic exact refusal" caseInitRouting
  , testCase "allowed classic routes: caps miss refuses exactly" caseCapsStage
  , testCase "refused ids: exact code + reason under granted caps" caseRefusals
  ]

-- ---------------------------------------------------------------------------
-- Canonical projection parsing
-- ---------------------------------------------------------------------------

-- | One allowed row: @mech|id|name|aliases|family|codec|bounds|routes@.
data MechRow = MechRow
  { mrId :: !Word64
  , mrName :: !Text
  , mrCodec :: !Text
  , mrOps :: ![Operation]
  } deriving (Eq, Show)

-- | One refused row: @inv|id|name|aliases|catalog-only@.
data InvRow = InvRow
  { irId :: !Word64
  , irName :: !Text
  } deriving (Eq, Show)

-- | Operation labels are the canonical 'operationName' spellings.
opByLabel :: Map Text Operation
opByLabel = Map.fromList
  [(operationName op, op) | op <- [minBound .. maxBound]]

-- | The package root, resolved CWD-independently (same funnel-cwd
-- hardening as ErrorInterpSpec: the test binary always lives under
-- the root's dist-newstyle, with a CWD walk-up fallback).
packageRoot :: IO FilePath
packageRoot = do
  exeDir <- takeDirectory <$> getExecutablePath
  fromExe <- ascend exeDir
  case fromExe of
    Just root -> pure root
    Nothing -> do
      fromCwd <- ascend =<< getCurrentDirectory
      case fromCwd of
        Just root -> pure root
        Nothing -> assertFailure
          "exhaustiveness: haskoki.cabal not found above executable or CWD"
  where
    ascend dir = do
      here <- doesFileExist (dir </> "haskoki.cabal")
      if here
        then pure (Just dir)
        else let parent = takeDirectory dir
             in if parent == dir
                  then pure Nothing
                  else ascend parent

-- | Load and parse the canonical projection. Parse failures are
-- returned as mismatches (a malformed projection fails loudly,
-- never silently skips rows).
loadCatalog :: IO ([String], [MechRow], [InvRow], [Word64])
loadCatalog = do
  root <- packageRoot
  content <- TIO.readFile (root </> "spec/mechanisms-canonical.txt")
  let ls = T.lines (T.strip content)
      header = take 1 ls
      rest = drop 1 ls
      hdrBad = ["bad projection header: " ++ show header
               | header /= ["schema 1"]]
      catLines = [l | l <- rest, "catalog|" `T.isPrefixOf` l]
      (catBad, catIds) = case catLines of
        [c] -> parseCatalogLine c
        _ -> (["want exactly one catalog| line, got "
               ++ show (length catLines)], [])
      mechLines = [l | l <- rest, "mech|" `T.isPrefixOf` l]
      invLines = [l | l <- rest, "inv|" `T.isPrefixOf` l]
      (mBad, mechs) = foldMap parseMechLine mechLines
      (iBad, invs) = foldMap parseInvLine invLines
      -- Every non-header line must be classified: nothing silently skipped.
      stray =
        ["unclassified projection line: " ++ T.unpack l
        | l <- rest
        , not ("catalog|" `T.isPrefixOf` l)
        , not ("mech|" `T.isPrefixOf` l)
        , not ("inv|" `T.isPrefixOf` l)]
  pure (hdrBad ++ catBad ++ mBad ++ iBad ++ stray, mechs, invs, catIds)
  where
    parseCatalogLine c =
      let cells = T.splitOn "," (T.drop (T.length "catalog|") c)
          ids = map parseHex cells
      in ([ "bad catalog id: " ++ T.unpack w
          | (w, Nothing) <- zip cells ids ]
         , [n | Just n <- ids])
    parseMechLine l = case T.splitOn "|" l of
      ["mech", wid, name, _aliases, _family, codec, _bounds, routes]
        | Just n <- parseHex wid
        , ops <- map (T.takeWhile (/= ':')) (T.splitOn ";" routes)
        , badOps <- [o | o <- ops, Map.notMember o opByLabel] ->
            if null badOps
              then ([], [MechRow n name codec
                         [opByLabel Map.! o | o <- ops]])
              else (["bad route ops " ++ show badOps ++ " in: " ++ T.unpack l], [])
      _ -> (["bad mech line: " ++ T.unpack l], [])
    parseInvLine l = case T.splitOn "|" l of
      ["inv", wid, name, _aliases, st]
        | Just n <- parseHex wid
        , st == "catalog-only" -> ([], [InvRow n name])
      _ -> (["bad inv line: " ++ T.unpack l], [])

-- | Parse a @0x%08X@ id cell.
parseHex :: Text -> Maybe Word64
parseHex w = case reads (T.unpack w) :: [(Word, String)] of
  [(n, "")] -> Just (fromIntegral n)
  _ -> Nothing

-- ---------------------------------------------------------------------------
-- Shared fixtures (mirroring OperationSpec: one public key object)
-- ---------------------------------------------------------------------------

fixtureSlot :: SlotId
fixtureSlot = SlotId 7

fixtureSession :: SessionState
fixtureSession = SessionState
  { ssId = SessionId 1
  , ssSlot = fixtureSlot
  , ssRevision = Revision 1
  , ssGeneration = Generation 1
  , ssReadOnly = False
  , ssLogin = LoginPublic
  , ssOps = emptySessionOps
  }

-- | Model holding one public key object bound to handle 3. The
-- object carries no key-policy attributes, so 'policyFromObject'
-- yields 'Nothing' and the caller 'KeyPolicy' permits govern —
-- exactly the OperationSpec seam, with all classic ops permitted.
modelWithKey :: Model
modelWithKey =
  let ost = ObjectState
        { osId = ObjectId 9
        , osRevision = Revision 1
        , osGeneration = Generation 1
        , osAttrs = Map.fromList
            [ (AttrClass, ValULong 4)
            , (AttrPrivate, ValBool False)
            ]
        , osOwner = Nothing
        , osSlot = fixtureSlot
        }
  in emptyModel
    { mObjects = Map.singleton (ObjectId 9) ost
    , mHandles = Map.singleton (ExternalHandle 3)
        (HandleBinding (ObjectId 9) (Generation 1))
    }

-- | Every classic operation (the 'slotOf' set): the fixture key
-- permits each, so key binding never decides a battery outcome.
classicOps :: [Operation]
classicOps = [op | op <- [minBound .. maxBound], isJust (slotOf op)]

fixtureKey :: KeyPolicy
fixtureKey = KeyPolicy
  { kpHandle = ExternalHandle 3
  , kpPermits = classicOps
  , kpAlwaysAuth = False
  }

-- | Full engine: every behavior-backed pair executable.
fullEnv :: OpEnv
fullEnv = OpEnv
  { oeRegistry = curatedRegistry
  , oeCaps = mkCapabilities (behaviorRoutes curatedRegistry)
  , oeModel = modelWithKey
  }

-- | Empty engine: every mechanism-stage pass reaches the caps miss.
noCapsEnv :: OpEnv
noCapsEnv = fullEnv { oeCaps = mkCapabilities [] }

-- ---------------------------------------------------------------------------
-- Per-codec valid parameters (recipe encoders, validity-driven)
-- ---------------------------------------------------------------------------

-- | Valid mechanism parameters for one cataloged (codec, id). 'Left'
-- is a battery mismatch (no constructor for a classic route's
-- codec), never a silent default: unknown codecs fail loudly.
paramsFor :: Text -> MechanismId -> Either String ByteString
paramsFor codec mid = case codec of
  "no-params/1" -> Right BS.empty
  "sig-encoding/1" -> Right BS.empty
  "mac-general/1" -> Right (encodeMacGeneral 8)
  "pss-params/1" -> case rsaPssRecipeFor mid of
    Just r ->
      let stem = fromMaybe "SHA256" (rpDigestStem r)
      in Right (encodePssParams stem stem 20)
    Nothing -> Left ("no PSS recipe for " ++ show mid)
  "iv-bytes/1" -> case cipherRecipeFor mid of
    Just r -> Right (BS.replicate (crIvBytes r) 0)
    Nothing -> Left ("no cipher recipe for " ++ show mid)
  "oaep-params/1" -> Right (encodeOaepParams "SHA_1" "SHA_1" BS.empty)
  "hotp-params/1" -> Right (encodeHotpParams 0 6)
  _ -> Left ("no params constructor for codec "
             ++ T.unpack codec ++ " at " ++ show mid)

-- | Whether an operation takes a key. Mirrors 'Haskoki.Operation'
-- 'opKeyed' (unexported; only digest is unkeyed): any drift fails
-- loudly below as a key-shape mismatch, never silently.
isKeyed :: Operation -> Bool
isKeyed OpDigest = False
isKeyed _ = True

-- | Init arguments for one cataloged route: the fixture key for
-- keyed ops, an unpadded cipher spec on OAEP rows (the planner
-- forbids padded specs there) and a padded one elsewhere, and a
-- recover spec on recovery ops.
argsFor :: Operation -> MechanismId -> ByteString -> InitArgs
argsFor op mid params = InitArgs
  { iaOp = op
  , iaMech = mid
  , iaParams = params
  , iaKey = if isKeyed op then Just fixtureKey else Nothing
  , iaCipher = case cipherDirOf op of
      Nothing -> Nothing
      Just _
        | isJust (rsaOaepRecipeFor mid) -> Just (CipherSpec 16 False)
        | otherwise -> Just (CipherSpec 16 True)
  , iaRecover = case recoverRoleOf op of
      Nothing -> Nothing
      Just _ -> Just (RecoverSpec 64 32)
  }

-- ---------------------------------------------------------------------------
-- Mismatch reporting
-- ---------------------------------------------------------------------------

-- | Fail with the full mismatch list (truncated display, exact
-- count): every row is checked, nothing aborts early.
assertNoMismatches :: String -> [String] -> IO ()
assertNoMismatches label mm
  | null mm = pure ()
  | otherwise = assertFailure
      (label ++ ": " ++ show (length mm) ++ " mismatches:\n"
       ++ unlines (take 40 mm))

-- | Run a case under a 60s wedge guard (pure planning; generous).
guarded :: String -> IO () -> IO ()
guarded label act = do
  m <- timeout (60 * 1000000) act
  case m of
    Just () -> pure ()
    Nothing -> assertFailure (label ++ " wedged (60s timeout)")

-- ---------------------------------------------------------------------------
-- The battery
-- ---------------------------------------------------------------------------

caseCoverage :: IO ()
caseCoverage = guarded "coverage" $ do
  (parseBad, mechs, invs, catIds) <- loadCatalog
  let mechIds = sort (map mrId mechs)
      invIds = sort (map irId invs)
      allIds = sort (mechIds ++ invIds)
      mm =
        parseBad
        ++ ["allowed count: want 106, got " ++ show (length mechs)
           | length mechs /= 106]
        ++ ["refused count: want 358, got " ++ show (length invs)
           | length invs /= 358]
        ++ ["catalog count: want 464, got " ++ show (length catIds)
           | length catIds /= 464]
        ++ ["mech/inv overlap: "
            ++ show (length [i | i <- mechIds, i `elem` invIds])
            ++ " ids in both"
           | any (`elem` invIds) mechIds]
        ++ ["mech+inv != catalog line"
           | allIds /= sort catIds]
  assertNoMismatches "coverage" mm

caseDescriptors :: IO ()
caseDescriptors = guarded "descriptors" $ do
  (parseBad, mechs, _invs, _cat) <- loadCatalog
  let reg = curatedRegistry
      mm = parseBad ++ concatMap checkOne mechs
      checkOne row =
        let mid = MechanismId (mrId row)
            tag = T.unpack (mrName row) ++ " " ++ show mid
        in case lookupBehavior reg mid of
          Nothing ->
            ["allowed row without behavior: " ++ tag]
          Just d ->
            ["status: want StatusSupported, got "
             ++ show (describeStatus reg mid) ++ " at " ++ tag
            | describeStatus reg mid /= StatusSupported]
            ++ ["name: want " ++ T.unpack (mrName row) ++ ", got "
                ++ show (descCanonical d) ++ " at " ++ tag
               | descCanonical d /= mrName row]
            ++ ["routes: want " ++ show (sort (mrOps row)) ++ ", got "
                ++ show (sort (map routeOperation (descRoutes d)))
                ++ " at " ++ tag
               | sort (map routeOperation (descRoutes d))
                 /= sort (mrOps row)]
  assertNoMismatches "descriptors" mm

caseInitRouting :: IO ()
caseInitRouting = guarded "init-routing" $ do
  (parseBad, mechs, _invs, _cat) <- loadCatalog
  let mm = parseBad ++ concatMap checkOne mechs
      checkOne row = concatMap (checkRoute row) (mrOps row)
      checkRoute row op =
        let mid = MechanismId (mrId row)
            tag = T.unpack (mrName row) ++ " " ++ show mid
                  ++ " " ++ show op
            -- Non-classic routes never reach the params check
            -- ('slotOf' rejects first), so their codecs need no
            -- constructor; classic routes must have one.
            eParams
              | isJust (slotOf op) = paramsFor (mrCodec row) mid
              | otherwise = Right BS.empty
        in case eParams of
          Left err -> ["params: " ++ err ++ " at " ++ tag]
          Right params ->
            let (_, out) = initOperation fullEnv emptySessionOps
                  fixtureSession (argsFor op mid params)
                got = (ioCode out, ioReasons out)
            in if isJust (slotOf op)
               then let want = (CKR_OK, ["initialized " ++ show op])
                    in ["init: want " ++ show want ++ ", got "
                        ++ show got ++ " at " ++ tag
                       | got /= want]
               else let want = (CKR_MECHANISM_INVALID
                               , ["not a classic operation"])
                    in ["non-classic: want " ++ show want ++ ", got "
                        ++ show got ++ " at " ++ tag
                       | got /= want]
                    ++ ["non-classic: untyped denial at " ++ tag
                       | isNothing (ioDeny out)]
  assertNoMismatches "init-routing" mm

caseCapsStage :: IO ()
caseCapsStage = guarded "caps-stage" $ do
  (parseBad, mechs, _invs, _cat) <- loadCatalog
  let want = (CKR_MECHANISM_INVALID
             , ["engine lacks this (mechanism, operation)"])
      classicRows =
        [(row, op) | row <- mechs, op <- mrOps row
        , isJust (slotOf op)]
      mm = parseBad ++ concatMap checkOne classicRows
      checkOne (row, op) =
        let mid = MechanismId (mrId row)
            tag = T.unpack (mrName row) ++ " " ++ show mid
                  ++ " " ++ show op
        in case paramsFor (mrCodec row) mid of
          Left err -> ["params: " ++ err ++ " at " ++ tag]
          Right params ->
            let (_, out) = initOperation noCapsEnv emptySessionOps
                  fixtureSession (argsFor op mid params)
                got = (ioCode out, ioReasons out)
            in ["caps: want " ++ show want ++ ", got "
                ++ show got ++ " at " ++ tag
               | got /= want]
  assertNoMismatches "caps-stage" mm

caseRefusals :: IO ()
caseRefusals = guarded "refusals" $ do
  (parseBad, _mechs, invs, _cat) <- loadCatalog
  let reg = curatedRegistry
      want = (CKR_MECHANISM_INVALID, ["unknown mechanism"])
      mm = parseBad ++ concatMap checkOne invs
      checkOne row =
        let mid = MechanismId (irId row)
            tag = T.unpack (irName row) ++ " " ++ show mid
            statusBad =
              ["status: want StatusCatalogOnly, got "
               ++ show (describeStatus reg mid) ++ " at " ++ tag
              | describeStatus reg mid /= StatusCatalogOnly]
            behavBad =
              ["refused row carries behavior at " ++ tag
              | isJust (lookupBehavior reg mid)]
            -- Fully granted caps: the refusal must be
            -- registry-driven, never a caps artifact.
            caps = mkCapabilities [(mid, op) | op <- classicOps]
            env = fullEnv { oeCaps = caps }
            args = InitArgs
              { iaOp = OpDigest
              , iaMech = mid
              , iaParams = BS.empty
              , iaKey = Nothing
              , iaCipher = Nothing
              , iaRecover = Nothing
              }
            (_, out) = initOperation env emptySessionOps
              fixtureSession args
            got = (ioCode out, ioReasons out)
            routeBad =
              ["refusal: want " ++ show want ++ ", got "
               ++ show got ++ " at " ++ tag
              | got /= want]
              ++ ["refusal: untyped denial at " ++ tag
                 | isNothing (ioDeny out)]
        in statusBad ++ behavBad ++ routeBad
  assertNoMismatches "refusals" mm
