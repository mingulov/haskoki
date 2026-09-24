{- | Slot phase specialization pins.

A slot is never live AND staged at once: the phase type
('SlotPhase' with 'PhaseBuffered', 'PhaseLive', 'PhaseStaged'),
its projections ('stagedOf', 'streamOf'), and the stager bridge
('setStaged') replaced the coexisting 'scStaged'/'scStream'
fields.

'caseNoRawPhaseFields' is the removal pin: it scans @core/@,
@src/@, @ffi/@, @tests/@ (and @app/@ when present) for any
remaining 'scStaged'/'scStream' token and fails with file:line
evidence.
-}
{-# LANGUAGE OverloadedStrings #-}
module SlotPhaseSpec (spec) where

import Control.Monad (forM)
import qualified Data.ByteString as BS
import Data.List (isInfixOf)
import System.Directory (doesDirectoryExist, listDirectory)
import System.FilePath ((</>), takeExtension)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertEqual, assertFailure, testCase)

import Haskoki.Model (SessionState (..), emptyModel)
import Haskoki.Operation
  ( CryptoResult (..)
  , DigestStream (..)
  , OpAuth (..)
  , SlotCommon
  , SlotKind (..)
  , SlotPhase (..)
  , StagedOutput (..)
  , StepOutcome (..)
  , activeDigest
  , bufferedOf
  , emptySessionOps
  , insertOp
  , lookupSingle
  , mkActiveDigest
  , mkSlotCommon
  , phaseOf
  , setBuffered
  , setLive
  , setStaged
  , stagedOf
  , streamOf
  )
import Haskoki.Operation.Digest (finishDigestInit)
import Haskoki.Registry (MechanismId (..), Operation (..))
import Haskoki.Request (OutputIntent (..))
import Haskoki.Session (SessionLogin (..))
import Haskoki.Snapshot
  ( RestoreKeys (..)
  , SaveError (..)
  , SaveTarget (..)
  , defaultQuotas
  , restoreOperation
  , saveOperation
  )
import Haskoki.Types
  ( Consumption (..)
  , EngineResourceId (..)
  , Generation (..)
  , OpState (..)
  , Pkcs11Version (..)
  , ReturnCode (..)
  , Revision (..)
  , SessionId (..)
  , SlotId (..)
  )

spec :: TestTree
spec = testGroup "Slot phases"
  [ testGroup "phase projections are exclusive"
    [ testCase "buffered projects empty" $ do
        assertEqual "no staged" Nothing (stagedOf sampleCommon)
        assertEqual "no stream" Nothing (streamOf sampleCommon)
    , testCase "live carries the stream only" $ do
        let sc = setLive sampleStream sampleCommon
        assertEqual "stream held" (Just sampleStream) (streamOf sc)
        assertEqual "no staged" Nothing (stagedOf sc)
    , testCase "staged carries the output only" $ do
        let sc = setStaged (Just sampleStaged) sampleCommon
        assertEqual "staged held" (Just sampleStaged) (stagedOf sc)
        assertEqual "no stream" Nothing (streamOf sc)
    ]
  , testGroup "setStaged transitions"
    [ testCase "stages a buffered slot, keeping the buffer" $ do
        let sc = setBuffered "kept" sampleCommon
            sc' = setStaged (Just sampleStaged) sc
        assertEqual "phase staged" (PhaseStaged sampleStaged) (phaseOf sc')
        assertEqual "staged held" (Just sampleStaged) (stagedOf sc')
        assertEqual "buffer retained" ("kept") (bufferedOf sc')
    , testCase "stages a live slot, clearing the stream" $ do
        let sc = setLive sampleStream sampleCommon
            sc' = setStaged (Just sampleStaged) sc
        assertEqual "phase staged" (PhaseStaged sampleStaged) (phaseOf sc')
        assertEqual "stream cleared" Nothing (streamOf sc')
    , testCase "nothing leaves the slot untouched" $
        assertEqual "identity" sampleCommon (setStaged Nothing sampleCommon)
    ]
  , testGroup "save and restore handle each phase"
    [ testCase "live phase refuses save" caseLiveRefuses
    , testCase "buffered phase roundtrips" caseBufferedRoundtrip
    , testCase "staged phase roundtrips byte-identically" caseStagedRoundtrip
    ]
  , testGroup "re-finish on a staged slot"
    [ testCase "keeps the staged conclusion" caseRefinishStaged
    ]
  , testCase "raw scStaged/scStream fields are gone" caseNoRawPhaseFields
  ]

-- | A live digest stream refuses to save: the portable bytes
-- cannot capture backend-native context.
caseLiveRefuses :: IO ()
caseLiveRefuses = do
  let sc = setLive sampleStream sampleCommon
      st = (mkSession (SessionId 1))
        { ssOps = insertOp (mkActiveDigest sc) emptySessionOps }
  assertEqual "live error"
    (Left (SaveStreamLive SlotDigest))
    (saveOperation defaultQuotas emptyModel st Pkcs11_3_2 (SaveSlot SlotDigest))

-- | A buffered (legacy-shaped) digest slot saves and restores
-- exactly.
caseBufferedRoundtrip :: IO ()
caseBufferedRoundtrip = do
  let sc = setBuffered "hello" sampleCommon
      stA = (mkSession (SessionId 1))
        { ssOps = insertOp (mkActiveDigest sc) emptySessionOps }
  bytes <- case saveOperation defaultQuotas emptyModel stA
    Pkcs11_3_2 (SaveSlot SlotDigest) of
    Left err -> assertFailure ("save failed: " ++ show err) >> undefined
    Right b -> pure b
  stB <- case restoreOperation defaultQuotas emptyModel
    (mkSession (SessionId 2)) Pkcs11_3_2 (RestoreSingle Nothing) bytes of
    Left err -> assertFailure ("restore failed: " ++ show err) >> undefined
    Right s -> pure s
  assertEqual "restored slot equals saved slot"
    (lookupSingle (ssOps stA) SlotDigest)
    (lookupSingle (ssOps stB) SlotDigest)

-- | A staged slot keeps its retained buffer and its staged output
-- through restore, and re-save is byte-identical.
caseStagedRoundtrip :: IO ()
caseStagedRoundtrip = do
  let sc = setStaged (Just sampleStaged)
            (setBuffered "retained-input" sampleCommon)
      stA = (mkSession (SessionId 1))
        { ssOps = insertOp (mkActiveDigest sc) emptySessionOps }
  bytes1 <- case saveOperation defaultQuotas emptyModel stA
    Pkcs11_3_2 (SaveSlot SlotDigest) of
    Left err -> assertFailure ("save failed: " ++ show err) >> undefined
    Right b -> pure b
  stB <- case restoreOperation defaultQuotas emptyModel
    (mkSession (SessionId 2)) Pkcs11_3_2 (RestoreSingle Nothing) bytes1 of
    Left err -> assertFailure ("restore failed: " ++ show err) >> undefined
    Right s -> pure s
  assertEqual "restored slot equals saved slot"
    (lookupSingle (ssOps stA) SlotDigest)
    (lookupSingle (ssOps stB) SlotDigest)
  bytes2 <- case saveOperation defaultQuotas emptyModel stB
    Pkcs11_3_2 (SaveSlot SlotDigest) of
    Left err -> assertFailure ("re-save failed: " ++ show err) >> undefined
    Right b -> pure b
  assertEqual "re-save is byte-identical" bytes1 bytes2

-- | A re-finish-init on a staged slot acknowledges the spurious
-- alloc answer but keeps the staged conclusion (a regression pin): the
-- slot stays staged and streamless, with its buffer intact.
caseRefinishStaged :: IO ()
caseRefinishStaged = do
  let sc = setStaged (Just sampleStaged)
            (setBuffered "kept" sampleCommon)
      ops0 = insertOp (mkActiveDigest sc) emptySessionOps
      (ops1, step) = finishDigestInit ops0 SlotDigest "digest"
        (GotResource (EngineResourceId 9)) IntentNull
  assertEqual "ack code" CKR_OK (soCode step)
  case lookupSingle ops1 SlotDigest of
    Just active -> case activeDigest active of
      Just sc' -> do
        assertEqual "still staged" (Just sampleStaged) (stagedOf sc')
        assertEqual "no stream" Nothing (streamOf sc')
        assertEqual "buffer kept" "kept" (bufferedOf sc')
      Nothing -> assertFailure ("slot lost: " ++ show active)
    Nothing -> assertFailure "slot lost: Nothing"

-- | A sample shared slot state: unbuffered, buffered-phase.
sampleCommon :: SlotCommon
sampleCommon = mkSlotCommon (MechanismId 0x250) OpDigest Nothing BS.empty AuthNone

-- | A sample live digest stream: fed, over resource 7.
sampleStream :: DigestStream
sampleStream = DigestStream (EngineResourceId 7) True

-- | A sample staged final output.
sampleStaged :: StagedOutput
sampleStaged = StagedOutput "digest" ("out") (OpLive (Consumption 0))

-- | A sample session over slot 7.
mkSession :: SessionId -> SessionState
mkSession sid = SessionState
  { ssId = sid
  , ssSlot = SlotId 7
  , ssRevision = Revision 1
  , ssGeneration = Generation 1
  , ssReadOnly = False
  , ssLogin = LoginPublic
  , ssOps = emptySessionOps
  }

-- | The raw phase fields must be gone from every Haskell source
-- file (this probe exempts its own file, auditable here).
caseNoRawPhaseFields :: IO ()
caseNoRawPhaseFields = do
  files <- filter (/= "tests/model/SlotPhaseSpec.hs")
    . concat <$> mapM walkHs ["core", "src", "ffi", "tests", "app"]
  hits <- fmap concat $ forM files $ \fp -> do
    body <- readFile fp
    pure
      [ (fp, n)
      | (n, ln) <- zip [1 :: Int ..] (lines body)
      , "scStaged" `isInfixOf` ln || "scStream" `isInfixOf` ln
      ]
  case hits of
    [] -> pure ()
    _ -> assertFailure ("raw phase-field uses: " ++ show hits)

-- | All @.hs@ files under a root (@[]@ when the root is absent).
walkHs :: FilePath -> IO [FilePath]
walkHs root = do
  ok <- doesDirectoryExist root
  if not ok then pure [] else go root
  where
    go dir = do
      ents <- listDirectory dir
      fmap concat $ forM ents $ \e -> do
        let p = dir </> e
        isDir <- doesDirectoryExist p
        if isDir then go p else pure [p | takeExtension p == ".hs"]
