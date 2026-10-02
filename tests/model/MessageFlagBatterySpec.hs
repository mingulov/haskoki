{- | Message route/flag battery (acceptance case T-M01).

DG1: a tested row gains a @message-*@ route iff (a) its classic
counterpart route is tested, (b) the driver @FxMessage*@ arm serves
the mechanism (@src/Haskoki/Engine/Driver.hs:1944-2072@, never the
@unsupported fx@ fallthrough), and (c) 'initMessageOperation'
returns @CKR_OK@ under full caps with valid parameters. The
@CKF_MESSAGE_*@ flags match the routes; @CKF_MULTI_MESSAGE@ stays
unadvertised.

Legs (each a named tasty case):

* route rule: for every tested row and message family, the
  @message-*@ route is present iff the DG1 rule holds (missing and
  unearned routes both fail loudly);
* route init: every cataloged @message-*@ route initializes @CKR_OK@
  via 'initMessageOperation' under full caps;
* flag correspondence: every @CKF_MESSAGE_*@ flag (parsed from the
  generated @cbits/mech_catalog.inc@, the exact
  @C_GetMechanismInfo@ source) has its route and vice versa;
* no multi: @CKF_MULTI_MESSAGE@ is advertised nowhere;
* scratch mutation: an in-memory catalog copy with one flipped
  route and one flipped flag must fail the rule/flag checks (the
  battery proves per run it is not blind; scratch discarded).

Rule (b) mirrors the driver arms exactly through the same recipe
tables the driver's @is*Mech@ predicates wrap ('isJust'
@XRecipeFor@): message-cipher is GCM/cipher/(chacha-stream)/OAEP/X.509
(the classic CCM and ChaCha20-Poly1305 arms have no @FxMessageCipher@
counterpart, so those rows earn no route); message-sign/verify is the
17-family MAC/signature disjunction (the classic SSL3-MAC arm has no
@FxMessage*@ counterpart, so those two rows earn no route). Any
driver-arm drift fails loudly here as an unearned/missing route.
-}
{-# LANGUAGE OverloadedStrings #-}
module MessageFlagBatterySpec (spec) where

import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import Data.List (isInfixOf, sort)
import qualified Data.Map.Strict as Map
import Data.Map.Strict (Map)
import Data.Maybe (fromMaybe, isJust)
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
  , MsgFamily (..)
  , OpEnv (..)
  , RecoverSpec (..)
  , cipherDirOf
  , emptySessionOps
  , initMessageOperation
  , msgFamilyOp
  , msgOperation
  , recoverRoleOf
  )
import Haskoki.Recipe.CbcMac (cbcmacRecipeFor)
import Haskoki.Recipe.Ccm (ccmRecipeFor, encodeCcmParams)
import Haskoki.Recipe.Chacha20
  ( Chacha20Recipe (..)
  , chachaRecipeFor
  , encodeChachaPolyParams
  , encodeChachaStreamParams
  )
import Haskoki.Recipe.Cipher (BlockCipherRecipe (..), cipherRecipeFor, encodeCtrParams, encodeRc2CbcParams)
import Haskoki.Recipe.Cmac (cmacRecipeFor)
import Haskoki.Recipe.Des3Mac (des3macRecipeFor)
import Haskoki.Recipe.Dsa (dsaRecipeFor)
import Haskoki.Recipe.Ecdsa (ecdsaRecipeFor)
import Haskoki.Recipe.Eddsa (eddsaRecipeFor, encodeEddsaParams)
import Haskoki.Recipe.Gcm (encodeGcmParams, gcmRecipeFor)
import Haskoki.Recipe.Gmac (gmacRecipeFor)
import Haskoki.Recipe.Hmac (encodeMacGeneral, hmacRecipeFor)
import Haskoki.Recipe.MlDsa (MldsaHedge (..), encodeMldsaParams, mldsaRecipeFor)
import Haskoki.Recipe.Otp (encodeHotpParams, hotpRecipeFor)
import Haskoki.Recipe.Poly1305 (poly1305RecipeFor)
import Haskoki.Recipe.RsaOaep (encodeOaepParams, rsaOaepRecipeFor)
import Haskoki.Recipe.RsaPkcs1 (rsaPkcs1RecipeFor)
import Haskoki.Recipe.RsaX509 (rsaX509RecipeFor)
import Haskoki.Recipe.RsaX931 (rsaX931RecipeFor)
import Haskoki.Recipe.RsaPss
  ( RsaPssRecipe (..)
  , encodePssParams
  , rsaPssRecipeFor
  )
import Haskoki.Recipe.SlhDsa (SlhdsaHedge (..), encodeSlhdsaParams, slhdsaRecipeFor)
import Haskoki.Recipe.XcbcMac (xcbcRecipeFor)
import Haskoki.Registry
  ( MechanismId (..)
  , Operation (..)
  , behaviorRoutes
  , curatedRegistry
  , mkCapabilities
  , operationName
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
spec = testGroup "message flag battery (T-M01)"
  [ testCase "route rule: message route iff DG1 holds" caseRouteRule
  , testCase "route init: every message route initializes CKR_OK" caseRouteInit
  , testCase "flag correspondence: CKF_MESSAGE_* has its route and vice versa" caseFlags
  , testCase "no CKF_MULTI_MESSAGE advertised" caseNoMulti
  , testCase "scratch mutation: flipped route/flag fails per run" caseMutation
  ]

-- ---------------------------------------------------------------------------
-- Canonical projection + catalog include parsing
-- ---------------------------------------------------------------------------

-- | One allowed row: @mech|id|name|aliases|family|codec|bounds|routes@.
data MechRow = MechRow
  { mrId :: !Word64
  , mrName :: !Text
  , mrCodec :: !Text
  , mrOps :: ![Operation]
  } deriving (Eq, Show)

-- | Operation labels are the canonical 'operationName' spellings.
opByLabel :: Map Text Operation
opByLabel = Map.fromList
  [(operationName op, op) | op <- [minBound .. maxBound]]

-- | The package root, resolved CWD-independently (same funnel-cwd
-- hardening as the A42 battery: the test binary always lives under
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
          "message battery: haskoki.cabal not found above executable or CWD"
  where
    ascend dir = do
      here <- doesFileExist (dir </> "haskoki.cabal")
      if here
        then pure (Just dir)
        else let parent = takeDirectory dir
             in if parent == dir
                  then pure Nothing
                  else ascend parent

-- | Load and parse the canonical projection's @mech|@ rows. Parse
-- failures are returned as mismatches (a malformed projection fails
-- loudly, never silently skips rows).
loadCatalog :: IO ([String], [MechRow])
loadCatalog = do
  root <- packageRoot
  content <- TIO.readFile (root </> "spec/mechanisms-canonical.txt")
  let ls = T.lines (T.strip content)
      hdrBad = ["bad projection header" | take 1 ls /= ["schema 1"]]
      mechLines = [l | l <- drop 1 ls, "mech|" `T.isPrefixOf` l]
      (mBad, mechs) = foldMap parseMechLine mechLines
  pure (hdrBad ++ mBad, mechs)
  where
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

-- | Parse a @0x%08X@ id cell.
parseHex :: Text -> Maybe Word64
parseHex w = case reads (T.unpack w) :: [(Word, String)] of
  [(n, "")] -> Just (fromIntegral n)
  _ -> Nothing

-- | Flags per mechanism id, parsed from the generated
-- @cbits/mech_catalog.inc@ (the exact @C_GetMechanismInfo@ source:
-- one @  { 0x..UL, minUL, maxUL, (unsigned long)(F | G) }, \/* NAME *\/ @
-- row per real-tested mechanism, or @0UL@ for the flag cell when the
-- row carries no flags).
loadFlags :: IO ([String], Map Word64 [Text], Text)
loadFlags = do
  root <- packageRoot
  content <- TIO.readFile (root </> "cbits/mech_catalog.inc")
  let rows = [l | l <- T.lines content, "  { 0x" `T.isPrefixOf` l]
      parsed = map parseIncLine rows
      bad = [e | Left e <- parsed]
      good = [g | Right g <- parsed]
  pure (bad, Map.fromList [(i, fs) | (i, fs, _) <- good], content)
  where
    parseIncLine l =
      case T.stripPrefix "  { " l of
        Nothing -> Left ("bad inc row: " ++ T.unpack l)
        Just rest -> case T.splitOn "UL," rest of
          [wid, _min, _max, flagCell] ->
            case parseHex (T.strip wid) of
              Nothing -> Left ("bad inc id: " ++ T.unpack l)
              Just n ->
                let cell = T.strip (T.takeWhile (/= '}') flagCell)
                in if cell == "0UL"
                   then Right (n, [], ())
                   else case T.stripPrefix "(unsigned long)(" cell of
                     Nothing -> Left ("bad inc flags: " ++ T.unpack l)
                     Just inner ->
                       let flags = [ T.strip f
                                   | f <- T.splitOn "|" (T.dropEnd 1 inner) ]
                       in if any (not . ("CKF_" `T.isPrefixOf`)) flags
                          then Left ("bad inc flags: " ++ T.unpack l)
                          else Right (n, flags, ())
          _ -> Left ("bad inc row cells: " ++ T.unpack l)

-- ---------------------------------------------------------------------------
-- Shared fixtures (mirroring A42: one public key object)
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

fixtureKey :: KeyPolicy
fixtureKey = KeyPolicy
  { kpHandle = ExternalHandle 3
  , kpPermits = [minBound .. maxBound]
  , kpAlwaysAuth = False
  }

-- | Full engine: every behavior-backed pair executable.
fullEnv :: OpEnv
fullEnv = OpEnv
  { oeRegistry = curatedRegistry
  , oeCaps = mkCapabilities (behaviorRoutes curatedRegistry)
  , oeModel = modelWithKey
  }

-- ---------------------------------------------------------------------------
-- Per-codec valid parameters (A42's constructors, validity-driven)
-- ---------------------------------------------------------------------------

-- | Valid mechanism parameters for one cataloged (codec, id). 'Left'
-- is a battery mismatch (no constructor for a route's codec), never
-- a silent default: unknown codecs fail loudly.
paramsFor :: Text -> MechanismId -> Either String ByteString
paramsFor codec mid = case codec of
  "no-params/1" -> Right BS.empty
  "sig-encoding/1" -> Right BS.empty
  "eddsa-params/1" -> Right (encodeEddsaParams False BS.empty)
  "mldsa-params/1" -> Right (encodeMldsaParams HedgePreferred BS.empty)
  "slhdsa-params/1" -> Right (encodeSlhdsaParams SlhPreferred BS.empty)
  "mac-general/1" -> Right (encodeMacGeneral 8)
  "pss-params/1" -> case rsaPssRecipeFor mid of
    Just r ->
      let stem = fromMaybe "SHA256" (rpDigestStem r)
      in Right (encodePssParams stem stem 20)
    Nothing -> Left ("no PSS recipe for " ++ show mid)
  "iv-bytes/1" -> case cipherRecipeFor mid of
    Just r -> Right (BS.replicate (crIvBytes r) 0)
    Nothing -> Left ("no cipher recipe for " ++ show mid)
  "ctr-params/1" -> case cipherRecipeFor mid of
    Just r -> Right (encodeCtrParams 128 (BS.replicate (crIvBytes r) 0))
    Nothing -> Left ("no cipher recipe for " ++ show mid)
  "rc2-params/1" -> case cipherRecipeFor mid of
    Just r -> Right (encodeRc2CbcParams 128 (BS.replicate (crIvBytes r) 0))
    Nothing -> Left ("no cipher recipe for " ++ show mid)
  "optional-wrap-iv/1" -> Right BS.empty
  "oaep-params/1" -> Right (encodeOaepParams "SHA_1" "SHA_1" BS.empty)
  "hotp-params/1" -> Right (encodeHotpParams 0 6)
  "gcm-params/1" -> Right (encodeGcmParams "0123456789ab" "AD" 16)
  "ccm-params/1" -> case ccmRecipeFor mid of
    Just _ -> Right (encodeCcmParams "0123456789ab" "AD" 16 0)
    Nothing -> Left ("no CCM recipe for " ++ show mid)
  "chacha20poly1305-params/1" -> case chachaRecipeFor mid of
    Just _ -> Right (encodeChachaPolyParams "0123456789ab" "AD" 16)
    Nothing -> Left ("no ChaCha recipe for " ++ show mid)
  "chacha20-params/1" -> case chachaRecipeFor mid of
    Just _ -> Right (encodeChachaStreamParams 0 "0123456789ab")
    Nothing -> Left ("no ChaCha recipe for " ++ show mid)
  _ -> Left ("no params constructor for codec "
             ++ T.unpack codec ++ " at " ++ show mid)

isKeyed :: Operation -> Bool
isKeyed OpDigest = False
isKeyed _ = True

-- | Init arguments for one cataloged classic route (A42's
-- constructor, unchanged semantics).
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
        | isJust (rsaX509RecipeFor mid) -> Just (CipherSpec 16 False)
        | isJust (gcmRecipeFor mid) -> Just (CipherSpec 1 False)
        | isJust (ccmRecipeFor mid) -> Just (CipherSpec 1 False)
        | isJust (chachaRecipeFor mid) -> Just (CipherSpec 1 False)
        | otherwise -> Just (CipherSpec 16 True)
  , iaRecover = case recoverRoleOf op of
      Nothing -> Nothing
      Just _ -> Just (RecoverSpec 64 32)
  }

-- ---------------------------------------------------------------------------
-- DG1 rule (b): the driver FxMessage* arm serves the mechanism
-- ---------------------------------------------------------------------------

-- | Message-cipher service: the exact @FxMessageCipher@ mechanism
-- dispatch (@Driver.hs:1944-1956@) through the same recipe tables
-- the driver's predicates wrap. GCM takes the AEAD arm; block
-- ciphers, the raw ChaCha20 stream row, RSA-OAEP and RSA-X.509 take
-- the cipher arms; CCM and ChaCha20-Poly1305 have no message arm
-- and fall through to @unsupported fx@.
msgCipherServed :: MechanismId -> Bool
msgCipherServed mid =
  isJust (gcmRecipeFor mid)
  || isJust (cipherRecipeFor mid)
  || isChachaStreamMech mid
  || isJust (rsaOaepRecipeFor mid)
  || isJust (rsaX509RecipeFor mid)
  where
    isChachaStreamMech m = case chachaRecipeFor m of
      Just r -> chachaName r == "CKM_CHACHA20"
      Nothing -> False

-- | Message-sign/verify service: the exact @FxMessageSign@ /
-- @FxMessageVerify@ mechanism dispatch (@Driver.hs:1957-2072@)
-- through the same recipe tables. The classic SSL3-MAC arm has no
-- message counterpart: those two rows fall through to @unsupported
-- fx@.
msgSignServed :: MechanismId -> Bool
msgSignServed mid =
  isJust (hmacRecipeFor mid)
  || isJust (cmacRecipeFor mid)
  || isJust (des3macRecipeFor mid)
  || isJust (cbcmacRecipeFor mid)
  || isJust (xcbcRecipeFor mid)
  || isJust (gmacRecipeFor mid)
  || isJust (hotpRecipeFor mid)
  || isJust (poly1305RecipeFor mid)
  || isJust (rsaPkcs1RecipeFor mid)
  || isJust (rsaPssRecipeFor mid)
  || isJust (rsaX509RecipeFor mid)
  || isJust (rsaX931RecipeFor mid)
  || isJust (ecdsaRecipeFor mid)
  || isJust (dsaRecipeFor mid)
  || isJust (eddsaRecipeFor mid)
  || isJust (mldsaRecipeFor mid)
  || isJust (slhdsaRecipeFor mid)

-- | Rule (b) by family.
msgServed :: MsgFamily -> MechanismId -> Bool
msgServed MsgEncrypt = msgCipherServed
msgServed MsgDecrypt = msgCipherServed
msgServed MsgSign = msgSignServed
msgServed MsgVerify = msgSignServed

-- | Rule (c): 'initMessageOperation' returns @CKR_OK@ under full
-- caps with valid parameters.
msgInitOk :: MsgFamily -> MechanismId -> ByteString -> Bool
msgInitOk fam mid params =
  let (_, out) = initMessageOperation fam fullEnv emptySessionOps
        fixtureSession (argsFor (msgFamilyOp fam) mid params)
  in ioCode out == CKR_OK

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

-- | Run a case under a 120s wedge guard (pure planning over the
-- full catalog; generous).
guarded :: String -> IO () -> IO ()
guarded label act = do
  m <- timeout (120 * 1000000) act
  case m of
    Just () -> pure ()
    Nothing -> assertFailure (label ++ " wedged (120s timeout)")

-- ---------------------------------------------------------------------------
-- The battery
-- ---------------------------------------------------------------------------

-- | The DG1 rule per (row, family): present iff (a) classic tested
-- and (b) driver-served and (c) message-init OK.
checkRouteRule :: [MechRow] -> [String]
checkRouteRule mechs = concatMap checkOne mechs
  where
    checkOne row = concatMap (checkFam row) [minBound .. maxBound]
    checkFam row fam =
      let mid = MechanismId (mrId row)
          classic = msgFamilyOp fam
          msgOp = msgOperation fam
          tag = T.unpack (mrName row) ++ " " ++ show mid
                ++ " " ++ T.unpack (operationName msgOp)
          hasClassic = classic `elem` mrOps row
          served = msgServed fam mid
      in case paramsFor (mrCodec row) mid of
        Left err
          | hasClassic -> ["params: " ++ err ++ " at " ++ tag]
          | otherwise -> []
        Right params ->
          let ok = hasClassic && served && msgInitOk fam mid params
              present = msgOp `elem` mrOps row
          in case (ok, present) of
            (True, False) ->
              ["missing " ++ T.unpack (operationName msgOp)
               ++ " route at " ++ tag]
            (False, True) ->
              ["unearned " ++ T.unpack (operationName msgOp)
               ++ " route at " ++ tag
               ++ " (classic=" ++ show hasClassic
               ++ " served=" ++ show served ++ ")"]
            _ -> []

caseRouteRule :: IO ()
caseRouteRule = guarded "route-rule" $ do
  (parseBad, mechs) <- loadCatalog
  assertNoMismatches "route rule" (parseBad ++ checkRouteRule mechs)

-- | Every cataloged @message-*@ route initializes @CKR_OK@ through
-- the message funnel under full caps.
checkRouteInit :: [MechRow] -> [String]
checkRouteInit mechs = concatMap checkOne mechs
  where
    checkOne row = concatMap (checkFam row) [minBound .. maxBound]
    checkFam row fam =
      let mid = MechanismId (mrId row)
          msgOp = msgOperation fam
          tag = T.unpack (mrName row) ++ " " ++ show mid
                ++ " " ++ T.unpack (operationName msgOp)
      in if msgOp `notElem` mrOps row
         then []
         else case paramsFor (mrCodec row) mid of
           Left err -> ["params: " ++ err ++ " at " ++ tag]
           Right params ->
             let (_, out) = initMessageOperation fam fullEnv emptySessionOps
                   fixtureSession (argsFor (msgFamilyOp fam) mid params)
                 want = (CKR_OK, ["initialized message " ++ show fam])
                 got = (ioCode out, ioReasons out)
             in ["init: want " ++ show want ++ ", got "
                 ++ show got ++ " at " ++ tag
                | got /= want]

caseRouteInit :: IO ()
caseRouteInit = guarded "route-init" $ do
  (parseBad, mechs) <- loadCatalog
  assertNoMismatches "route init" (parseBad ++ checkRouteInit mechs)

-- | Flag/route correspondence per (row, family): the
-- @CKF_MESSAGE_*@ flag is present iff the @message-*@ route is.
flagFor :: MsgFamily -> Text
flagFor MsgEncrypt = "CKF_MESSAGE_ENCRYPT"
flagFor MsgDecrypt = "CKF_MESSAGE_DECRYPT"
flagFor MsgSign = "CKF_MESSAGE_SIGN"
flagFor MsgVerify = "CKF_MESSAGE_VERIFY"

checkFlags :: [MechRow] -> Map Word64 [Text] -> [String]
checkFlags mechs flagMap =
  coverage ++ concatMap checkOne mechs
  where
    coverage =
      ["flag coverage: want 316 mech rows, got " ++ show (length mechs)
      | length mechs /= 316]
      ++ ["flag coverage: want 316 inc rows, got " ++ show (Map.size flagMap)
         | Map.size flagMap /= 316]
      ++ ["flag coverage: inc ids differ from catalog ids"
         | sort (map mrId mechs) /= sort (Map.keys flagMap)]
    checkOne row = concatMap (checkFam row) [minBound .. maxBound]
    checkFam row fam =
      let flags = fromMaybe [] (Map.lookup (mrId row) flagMap)
          msgOp = msgOperation fam
          tag = T.unpack (mrName row) ++ " " ++ show (MechanismId (mrId row))
          hasFlag = flagFor fam `elem` flags
          hasRoute = msgOp `elem` mrOps row
      in case (hasFlag, hasRoute) of
        (True, False) ->
          ["flag without route: " ++ T.unpack (flagFor fam)
           ++ " at " ++ tag]
        (False, True) ->
          ["route without flag: " ++ T.unpack (operationName msgOp)
           ++ " at " ++ tag]
        _ -> []

caseFlags :: IO ()
caseFlags = guarded "flags" $ do
  (parseBad, mechs) <- loadCatalog
  (flagBad, flagMap, _) <- loadFlags
  assertNoMismatches "flag correspondence"
    (parseBad ++ flagBad ++ checkFlags mechs flagMap)

caseNoMulti :: IO ()
caseNoMulti = guarded "no-multi" $ do
  (flagBad, flagMap, content) <- loadFlags
  let mm = flagBad
        ++ ["CKF_MULTI_MESSAGE on " ++ show mid
           | (mid, flags) <- Map.toList flagMap
           , "CKF_MULTI_MESSAGE" `elem` flags]
        ++ ["CKF_MULTI_MESSAGE in catalog include text"
           | "CKF_MULTI_MESSAGE" `T.isInfixOf` content]
  assertNoMismatches "no multi-message" mm

-- | Scratch mutation: flip one route and one flag on an in-memory
-- catalog copy; the rule/flag checks must fail on the mutated copy
-- (the battery proves per run it is not blind; scratch discarded).
caseMutation :: IO ()
caseMutation = guarded "mutation" $ do
  (parseBad, mechs) <- loadCatalog
  (flagBad, flagMap, _) <- loadFlags
  assertNoMismatches "mutation inputs" (parseBad ++ flagBad)
  -- Flip one route where the rule cannot hold (the RSA keypair
  -- generator has no classic cipher route): adding
  -- @message-encrypt@ there must read as unearned.
  case [row | row <- mechs, mrName row == "CKM_RSA_PKCS_KEY_PAIR_GEN"] of
    [] -> assertFailure "mutation: keygen row missing from catalog"
    (keygen : _) -> do
      let mutatedRoutes =
            [ if mrId row == mrId keygen
              then row { mrOps = OpMessageEncrypt : mrOps row }
              else row
            | row <- mechs ]
          routeHits = checkRouteRule mutatedRoutes
      -- Flip one flag where no route exists (same row): a
      -- @CKF_MESSAGE_SIGN@ without its @message-sign@ route must
      -- fail the correspondence check.
          mutatedFlags = Map.insert (mrId keygen) ["CKF_MESSAGE_SIGN"] flagMap
          flagHits = checkFlags mechs mutatedFlags
          -- Detection must name the flipped row: on a failing tree the
          -- re-check also reports the live catalog's own gaps.
          rowHit hits = any ("CKM_RSA_PKCS_KEY_PAIR_GEN" `isInfixOf`) hits
      assertNoMismatches "mutation detection"
        (["route flip undetected: battery is blind" | not (rowHit routeHits)]
         ++ ["flag flip undetected: battery is blind" | not (rowHit flagHits)])
