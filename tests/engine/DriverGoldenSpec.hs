-- | Driver golden sweep: behavior-identity anchor for the 0.6.3 refactor.
--
-- Every header mechanism ('generatedInventory') is driven through
-- every stateless 'CryptoEffect' constructor (plus a digest
-- init\/feed\/consume chain and sign→verify \/ enc→dec chained
-- rows) over a fresh deterministic Synthetic backend per mechanism,
-- across parameter validity (empty vs malformed) and key presence
-- (no key slot, missing key, present 'KeyBytes', present 'KeyDer').
-- 'KeyRefMaterial' is out of scope (needs a backend-imported
-- 'KeyRef'; covered by the import tests, not by dispatch).
--
-- Outcomes render via 'Show' with two stabilizations: 'GotBytes'
-- renders length plus an FNV-1a-64 digest of the bytes (never the
-- raw bytes — the sweep must pin outputs without leaking key
-- material into the repo), and a @CryptoUnsupported \"driver\"@
-- refusal whose message equals @show fx@ renders as the
-- @CryptoUnsupported<=fx>@ placeholder (verified in code, so a
-- record-field rename cannot churn sixty thousand rows). A driver
-- throw renders as @EXN ...@.
--
-- The whole sweep must match
-- @tests\/engine\/golden\/driver-sweep.txt@ byte for byte. On
-- mismatch the test writes @driver-sweep.txt.new@ next to the
-- golden and fails: inspect with @diff@, and accept ONLY when the
-- delta is an intended behavior change (@cp@ the @.new@ over the
-- golden). A pure refactor must never change this file.
{-# LANGUAGE OverloadedStrings #-}
module DriverGoldenSpec (spec) where

import Control.Exception (SomeException, bracket, try)
import Data.Bits (xor)
import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import qualified Data.ByteString.Builder as BB
import Data.ByteString.Builder (Builder)
import qualified Data.ByteString.Lazy as BL
import qualified Data.Text.Encoding as TE
import Data.Text (Text)
import Data.Word (Word64)
import Numeric (showHex)
import System.Directory (doesDirectoryExist, doesFileExist, removeFile)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertFailure, testCase)

import Haskoki.Engine.Backend
  ( BackendEnv
  , CryptoBackend (..)
  , EngineResult (..)
  , KeyMaterial (..)
  )
import Haskoki.Engine.Driver (KeyResolver, runEffect)
import Haskoki.Engine.Synthetic (Synthetic)
import Haskoki.Operation.Effect (CryptoEffect (..), CryptoError (..), CryptoResult (..))
import Haskoki.Operation.State (CipherDir (..))
import Haskoki.Registry (MechanismId (..))
import Haskoki.Registry.Generated (generatedInventory)
import Haskoki.Types (EngineResourceId (..), ObjectId (..))

spec :: TestTree
spec = testGroup "driver golden sweep"
  [ testCase "sweep matches golden" caseSweep
  ]

-- | Golden candidates, cwd-tolerant like the fixture reads: cabal
-- runs suites from the package root, direct binary runs from anywhere.
goldenCandidates :: [FilePath]
goldenCandidates = [primaryGolden, "golden/driver-sweep.txt"]

-- | The canonical golden path (also where @.new@ output lands when
-- its directory exists).
primaryGolden :: FilePath
primaryGolden = "tests/engine/golden/driver-sweep.txt"

fixedKey :: ByteString
fixedKey = BS.pack [1 .. 32]

-- | Fixed garbage DER: pins 'KeyDer' dispatch deterministically
-- (parse failure or success, whatever the driver does — the golden
-- records it, identity is what matters).
fixedDer :: ByteString
fixedDer = BS.pack [0x30, 0x82, 0x01, 0x00, 0x02, 0x03, 0x04, 0x05]

fixedInput :: ByteString
fixedInput = "sweep-input-bytes"

fixedAad :: ByteString
fixedAad = "sweep-aad"

fixedSig :: ByteString
fixedSig = BS.replicate 64 0

malformedParams :: ByteString
malformedParams = "not-valid-params!!!"

sweepOid :: ObjectId
sweepOid = ObjectId 7

sweepOid2 :: ObjectId
sweepOid2 = ObjectId 9

-- | A resource id no real digest init can produce (counter ids start
-- low): exercises the invalid-resource path when init already failed.
bogusResource :: EngineResourceId
bogusResource = EngineResourceId maxBound

resolvePresent :: KeyResolver
resolvePresent _ = Just (KeyBytes fixedKey)

resolveDer :: KeyResolver
resolveDer _ = Just (KeyDer fixedDer)

resolveMissing :: KeyResolver
resolveMissing _ = Nothing

openSynth :: String -> IO (BackendEnv Synthetic)
openSynth seed = do
  r <- openBackend seed :: IO (EngineResult (BackendEnv Synthetic))
  case r of
    EngineFail err -> assertFailure ("open " ++ show seed ++ " failed: " ++ show err)
    EngineOk e -> pure e

-- | FNV-1a-64 over the bytes (local, no new dependency): pins output
-- bytes without storing them.
fnv1a64 :: ByteString -> Word64
fnv1a64 = BS.foldl' step 14695981039346656037
  where
    step h b = (h `xor` fromIntegral b) * 1099511628211

hex16 :: Word64 -> String
hex16 w = let s = showHex w "" in replicate (16 - length s) '0' ++ s

-- | One sweep dimension: key slot, resolver, and row tag.
keyVariants :: [(String, Maybe ObjectId, KeyResolver)]
keyVariants =
  [ ("nokey", Nothing, resolvePresent)
  , ("missing", Just sweepOid, resolveMissing)
  , ("present", Just sweepOid, resolvePresent)
  , ("present-der", Just sweepOid, resolveDer)
  ]

paramVariants :: [(String, ByteString)]
paramVariants =
  [ ("empty", BS.empty)
  , ("malformed", malformedParams)
  ]

-- | The stateless effects: tag, whether the key dimension applies
-- (keyless effects run once — the resolver is never consulted), and
-- a constructor over (mechanism, key slot, params).
effectTemplates :: [(String, Bool, MechanismId -> Maybe ObjectId -> ByteString -> CryptoEffect)]
effectTemplates =
  [ ("digest", False, \m _ _ -> FxDigest m fixedInput)
  , ("digest-init", False, \m _ _ -> FxDigestInit m)
  , ("generate-key", False, \m _ p -> FxGenerateKey m p fixedInput)
  , ("cipher-enc", True, \m k p -> FxCipher DirEncrypt m k p fixedInput)
  , ("cipher-dec", True, \m k p -> FxCipher DirDecrypt m k p fixedInput)
  , ("sign", True, \m k p -> FxSign m k p fixedInput)
  , ("verify", True, \m k p -> FxVerify m k p fixedInput fixedSig)
  , ("sign-recover", True, \m k p -> FxSignRecover m k p fixedInput 32)
  , ("verify-recover", True, \m k p -> FxVerifyRecover m k p fixedSig 32)
  , ("msg-cipher-enc", True, \m k p -> FxMessageCipher DirEncrypt m k p fixedAad fixedInput)
  , ("msg-cipher-dec", True, \m k p -> FxMessageCipher DirDecrypt m k p fixedAad fixedInput)
  , ("msg-sign", True, \m k p -> FxMessageSign m k p fixedInput)
  , ("msg-verify", True, \m k p -> FxMessageVerify m k p fixedInput fixedSig)
  , ("wrap", True, \m k p -> FxWrap m k p fixedInput)
  , ("unwrap", True, \m k p -> FxUnwrap m k p fixedInput)
  , ("auth-wrap", True, \m k p -> FxAuthWrap m k p fixedInput)
  , ("auth-unwrap", True, \m k p -> FxAuthUnwrap m k p fixedInput)
  , ("derive", True, \m k p -> FxDerive m k Nothing p fixedInput 32)
  , ("kem-encaps", True, \m k p -> FxKemEncaps m k p fixedInput)
  , ("kem-decaps", True, \m k p -> FxKemDecaps m k p fixedInput)
  ]

-- | Render one outcome. 'GotBytes' renders length plus digest (never
-- raw bytes); a @CryptoUnsupported \"driver\"@ refusal that echoes
-- @show fx@ collapses to a placeholder (verified here, so the echo
-- cannot drift silently); throws render as @EXN ...@.
renderOutcome :: CryptoEffect -> Either SomeException CryptoResult -> String
renderOutcome fx r = case r of
  Left ex -> "EXN " ++ show ex
  Right (GotBytes bs) ->
    "GotBytes len=" ++ show (BS.length bs) ++ " fnv=" ++ hex16 (fnv1a64 bs)
  Right (GotCryptoError (CryptoUnsupported who msg))
    | who == "driver" && msg == show fx -> "CryptoUnsupported<=fx>"
  Right other -> show other

sweepRun
  :: BackendEnv Synthetic -> KeyResolver -> CryptoEffect -> IO (Either SomeException CryptoResult)
sweepRun env resolve fx = try (runEffect env resolve fx)

row :: Text -> String -> String -> String -> String -> Builder
row name eTag pTag kTag outcome =
  BB.byteString (TE.encodeUtf8 name)
    <> BB.char8 '|' <> BB.string8 eTag
    <> BB.char8 '|' <> BB.string8 pTag
    <> BB.char8 '|' <> BB.string8 kTag
    <> BB.char8 '|' <> BB.string8 outcome
    <> BB.char8 '\n'

sweepTemplate
  :: BackendEnv Synthetic
  -> Text -> MechanismId
  -> (String, Bool, MechanismId -> Maybe ObjectId -> ByteString -> CryptoEffect)
  -> IO [Builder]
sweepTemplate env name mech (eTag, usesKey, mkFx) =
  sequence
    [ do
        let fx = mkFx mech mKey params
        r <- sweepRun env resolve fx
        pure (row name eTag pTag kTag (renderOutcome fx r))
    | (pTag, params) <- paramVariants
    , (kTag, mKey, resolve) <- if usesKey then keyVariants else [("keyless", Nothing, resolvePresent)]
    ]

-- | Digest init\/feed\/consume chain with the present key and empty
-- params; when init fails there is no live resource, so feed\/consume
-- run against the bogus id (invalid-resource path, still deterministic).
sweepChain :: BackendEnv Synthetic -> Text -> MechanismId -> IO [Builder]
sweepChain env name mech = do
  let fxInit = FxDigestInit mech
  rInit <- sweepRun env resolvePresent fxInit
  let res = case rInit of
        Right (GotResource r) -> r
        _ -> bogusResource
      fxFeed = FxDigestFeed res fixedInput
      fxConsume = FxDigestConsume res
  rFeed <- sweepRun env resolvePresent fxFeed
  rConsume <- sweepRun env resolvePresent fxConsume
  pure
    [ row name "digest-chain" "init" "present" (renderOutcome fxInit rInit)
    , row name "digest-chain" "feed" "present" (renderOutcome fxFeed rFeed)
    , row name "digest-chain" "consume" "present" (renderOutcome fxConsume rConsume)
    ]

-- | Chained success rows (present key): the sign output feeds verify,
-- the encrypt output feeds decrypt. Emitted only when the producer
-- yields bytes — otherwise the chain has nothing to pin beyond the
-- unchained rows. Note @verify-recover-chained@ is currently empty:
-- sign-recover never yields bytes on Synthetic with these keys (its
-- own rows still trip the golden if that ever changes).
sweepChained :: BackendEnv Synthetic -> Text -> MechanismId -> ByteString -> IO [Builder]
sweepChained env name mech params = do
  let pTag = if BS.null params then "empty" else "malformed"
  signRows <- do
    let fxSign = FxSign mech (Just sweepOid) params fixedInput
    rSign <- sweepRun env resolvePresent fxSign
    case rSign of
      Right (GotBytes sig) -> do
        let fxVerify = FxVerify mech (Just sweepOid) params fixedInput sig
        rVerify <- sweepRun env resolvePresent fxVerify
        pure [row name "verify-chained" pTag "present" (renderOutcome fxVerify rVerify)]
      _ -> pure []
  signRecRows <- do
    let fxSign = FxSignRecover mech (Just sweepOid) params fixedInput 32
    rSign <- sweepRun env resolvePresent fxSign
    case rSign of
      Right (GotBytes sig) -> do
        let fxVerify = FxVerifyRecover mech (Just sweepOid) params sig 32
        rVerify <- sweepRun env resolvePresent fxVerify
        pure [row name "verify-recover-chained" pTag "present" (renderOutcome fxVerify rVerify)]
      _ -> pure []
  cipherRows <- do
    let fxEnc = FxCipher DirEncrypt mech (Just sweepOid) params fixedInput
    rEnc <- sweepRun env resolvePresent fxEnc
    case rEnc of
      Right (GotBytes ct) -> do
        let fxDec = FxCipher DirDecrypt mech (Just sweepOid) params ct
        rDec <- sweepRun env resolvePresent fxDec
        pure [row name "cipher-dec-chained" pTag "present" (renderOutcome fxDec rDec)]
      _ -> pure []
  pure (signRows ++ signRecRows ++ cipherRows)

-- | Single two-key derive row (present keys, empty params): 'fxKey2'
-- is 'Nothing' on every matrix row, so this one pins the aux-key path.
sweepDerive2 :: BackendEnv Synthetic -> Text -> MechanismId -> IO [Builder]
sweepDerive2 env name mech = do
  let fx = FxDerive mech (Just sweepOid) (Just sweepOid2) BS.empty fixedInput 32
  r <- sweepRun env resolvePresent fx
  pure [row name "derive-2key" "empty" "present" (renderOutcome fx r)]

-- | The whole inventory, each mechanism over a FRESH backend:
-- resource ids restart per mechanism, so one extra or missing
-- allocation cannot shift every later 'GotResource' row.
sweepAll :: IO [Builder]
sweepAll = concat <$> mapM sweepRow generatedInventory
  where
    sweepRow (wid, name, _aliases) =
      bracket (openSynth "63063") closeBackend $ \env -> do
        let mech = MechanismId wid
        arrivals <- concat <$> mapM (sweepTemplate env name mech) effectTemplates
        chain <- sweepChain env name mech
        chainedEmpty <- sweepChained env name mech BS.empty
        chainedMalformed <- sweepChained env name mech malformedParams
        d2 <- sweepDerive2 env name mech
        pure (arrivals ++ chain ++ chainedEmpty ++ chainedMalformed ++ d2)

-- | Parent directory of a candidate (no filepath dependency: manual).
parentDir :: FilePath -> FilePath
parentDir p = case break (== '/') (reverse p) of
  (_, []) -> "."
  (_, '/' : rest) -> reverse rest
  _ -> "."

-- | Where a @.new@ file can actually be written: the first candidate
-- whose directory exists.
writableNew :: IO (Maybe FilePath)
writableNew = findM hasDir goldenCandidates
  where
    hasDir p = doesDirectoryExist (parentDir p)

caseSweep :: IO ()
caseSweep = do
  rows <- sweepAll
  let actual = BB.toLazyByteString (mconcat rows)
  found <- findM doesFileExist goldenCandidates
  case found of
    Nothing -> do
      mNew <- writableNew
      case mNew of
        Nothing -> assertFailure "golden missing and no writable candidate dir; cannot bootstrap"
        Just path -> do
          BL.writeFile (path ++ ".new") actual
          assertFailure "golden missing: wrote driver-sweep.txt.new; inspect and move into place"
    Just path -> do
      expected <- BL.readFile path
      if expected == actual
        then do
          staleExists <- doesFileExist (path ++ ".new")
          if staleExists then removeFile (path ++ ".new") else pure ()
        else do
          BL.writeFile (path ++ ".new") actual
          assertFailure
            ("sweep drifted: wrote " ++ path ++ ".new"
              ++ "; diff against " ++ path
              ++ " and accept ONLY for an intended behavior change")

findM :: Monad m => (a -> m Bool) -> [a] -> m (Maybe a)
findM _ [] = pure Nothing
findM p (x : xs) = do
  ok <- p x
  if ok then pure (Just x) else findM p xs
