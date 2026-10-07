{- | Command laws: digest command sequences over the pure planners
checked against an independent reference model (accept\/reject +
slot occupancy at every step), plus pinned illegal-order scripts.
-}
{-# LANGUAGE OverloadedStrings #-}
module DigestCmdProps (spec) where

import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import Data.Maybe (isJust)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertEqual, assertFailure, testCase)
import Test.Tasty.QuickCheck
  ( Gen
  , Property
  , arbitrary
  , choose
  , conjoin
  , counterexample
  , forAll
  , oneof
  , property
  , vectorOf
  )

import Gen (propWith, qcBytes)
import Haskoki.Model (SessionState (..), emptyModel)
import Haskoki.Operation
  ( CryptoError (..)
  , CryptoResult (..)
  , InitArgs (..)
  , InitOutcome (..)
  , OpEnv (..)
  , SessionOps
  , SlotKind (..)
  , StepOutcome (..)
  , emptySessionOps
  , initOperation
  , lookupSingle
  , retryStaged
  )
import Haskoki.Operation.Digest
  ( finishDigest
  , finishDigestFeed
  , finishDigestInit
  , planDigestFinal
  , planDigestOneShot
  , planDigestUpdate
  )
import Haskoki.Registry
  ( MechanismId (..)
  , Operation (..)
  , curatedRegistry
  , mkCapabilities
  )
import Haskoki.Request (OutputIntent (..))
import Haskoki.Session (SessionLogin (..))
import Haskoki.Types
  ( EngineResourceId (..)
  , Generation (..)
  , ReturnCode (..)
  , Revision (..)
  , SessionId (..)
  , SlotId (..)
  )

spec :: Maybe Int -> Int -> TestTree
spec seedOv count =
  testGroup
    "digest command laws"
    [ propWith seedOv "reference model agreement" 301 count pCommands
    , propWith seedOv "staged transitions reject" 302 count pStagedRejects
    , propWith seedOv "freed transitions reject" 303 count pFreedRejects
    , testCase "illegal orders reject" caseIllegal
    , testCase "valid scripts succeed" (caseValid count)
    ]

-- ---------------------------------------------------------------------------
-- Fixtures
-- ---------------------------------------------------------------------------

sha256Mech :: MechanismId
sha256Mech = MechanismId 0x250

digestEnv :: OpEnv
digestEnv =
  OpEnv
    { oeRegistry = curatedRegistry
    , oeCaps = mkCapabilities [(sha256Mech, OpDigest)]
    , oeModel = emptyModel
    }

digestArgs :: InitArgs
digestArgs =
  InitArgs
    { iaOp = OpDigest
    , iaMech = sha256Mech
    , iaParams = BS.empty
    , iaKey = Nothing
    , iaCipher = Nothing
    , iaRecover = Nothing
    }

freshSession :: SessionState
freshSession =
  SessionState
    { ssId = SessionId 1
    , ssSlot = SlotId 0
    , ssRevision = Revision 1
    , ssGeneration = Generation 1
    , ssReadOnly = False
    , ssLogin = LoginPublic
    , ssOps = emptySessionOps
    }

-- ---------------------------------------------------------------------------
-- Command DSL + reference model
-- ---------------------------------------------------------------------------

data DigestCmd
  = DCInit
  | DCUpdate !ByteString
  | DCOneShot !ByteString
  | DCFinal
  | DCFinishInit !EngineResourceId
  | DCFinishFeed !Bool
  | DCFinish !ByteString !OutputIntent
  | DCRetry !OutputIntent
  deriving (Eq, Show)

-- | Model phase: no operation, an active slot (stream allocated?
-- fed?), or a staged final holding its byte length.
data Phase
  = PhAbsent
  | PhActive !Bool !Bool
  | PhStaged !Int
  deriving (Eq, Show)

-- | The output-planner fit rule (Output.hs planOneShot): a null
-- intent is a size query (always OK); a buffer must cover the bytes.
fitsLen :: OutputIntent -> Int -> Bool
fitsLen intent len = case intent of
  IntentNull -> True
  IntentBuffer cap -> cap >= fromIntegral len

fits :: OutputIntent -> ByteString -> Bool
fits intent bs = fitsLen intent (BS.length bs)

isQuery :: OutputIntent -> Bool
isQuery IntentNull = True
isQuery _ = False

type StepRes = (ReturnCode, Bool)

-- | The reference model: predicted (code, occupied-after) plus the
-- next phase, from the documented planner contract.
modelStep :: Phase -> DigestCmd -> (StepRes, Phase)
modelStep phase cmd = case cmd of
  DCInit -> case phase of
    PhAbsent -> ((CKR_OK, True), PhActive False False)
    _ -> ((CKR_OPERATION_ACTIVE, True), phase)
  DCUpdate _ -> case phase of
    PhAbsent -> ((CKR_OPERATION_NOT_INITIALIZED, False), PhAbsent)
    PhStaged _ -> ((CKR_OPERATION_NOT_INITIALIZED, True), phase)
    PhActive False _ -> ((CKR_GENERAL_ERROR, False), PhAbsent)
    PhActive True _ -> ((CKR_OK, True), PhActive True True)
  DCOneShot _ -> case phase of
    PhAbsent -> ((CKR_OPERATION_NOT_INITIALIZED, False), PhAbsent)
    PhStaged _ -> ((CKR_OPERATION_NOT_INITIALIZED, True), phase)
    -- One-shot over fed input denies ACTIVE and terminates (spec:
    -- every error other than BUFFER_TOO_SMALL terminates).
    PhActive _ True -> ((CKR_OPERATION_ACTIVE, False), PhAbsent)
    PhActive alloc False -> ((CKR_OK, True), PhActive alloc False)
  DCFinal -> case phase of
    PhAbsent -> ((CKR_OPERATION_NOT_INITIALIZED, False), PhAbsent)
    PhStaged _ -> ((CKR_OPERATION_NOT_INITIALIZED, True), phase)
    PhActive False _ -> ((CKR_GENERAL_ERROR, False), PhAbsent)
    PhActive True fed -> ((CKR_OK, True), PhActive True fed)
  DCFinishInit _ -> case phase of
    PhAbsent -> ((CKR_OPERATION_NOT_INITIALIZED, False), PhAbsent)
    -- A re-finish on an active slot replaces the stream with a
    -- fresh unfed one; on a staged slot the conclusion stands (the
    -- spurious alloc is acknowledged, not recorded). Unreachable
    -- in real flows (one init plans one alloc, re-init conflicts),
    -- but the model pins the implementation's behavior exactly.
    PhActive _ _ -> ((CKR_OK, True), PhActive True False)
    PhStaged _ -> ((CKR_OK, True), phase)
  DCFinishFeed ok -> case phase of
    PhAbsent -> ((CKR_OPERATION_NOT_INITIALIZED, False), PhAbsent)
    _ | ok -> ((CKR_OK, True), phase)
      | otherwise -> ((CKR_GENERAL_ERROR, False), PhAbsent)
  DCFinish bs intent -> case phase of
    PhAbsent -> ((CKR_OPERATION_NOT_INITIALIZED, False), PhAbsent)
    PhStaged _ -> ((CKR_GENERAL_ERROR, True), phase)
    PhActive _ _
      -- A size query always stages (even an empty output) and keeps
      -- the slot for the recall; only a fitting buffer frees it.
      | isQuery intent -> ((CKR_BUFFER_TOO_SMALL, True), PhStaged (BS.length bs))
      | fits intent bs -> ((CKR_OK, False), PhAbsent)
      | otherwise -> ((CKR_BUFFER_TOO_SMALL, True), PhStaged (BS.length bs))
  DCRetry intent -> case phase of
    PhStaged len
      | isQuery intent -> ((CKR_BUFFER_TOO_SMALL, True), phase)
      | fitsLen intent len -> ((CKR_OK, False), PhAbsent)
      | otherwise -> ((CKR_BUFFER_TOO_SMALL, True), phase)
    PhAbsent -> ((CKR_OPERATION_NOT_INITIALIZED, False), PhAbsent)
    PhActive _ _ -> ((CKR_OPERATION_NOT_INITIALIZED, True), phase)

-- ---------------------------------------------------------------------------
-- Interpreter
-- ---------------------------------------------------------------------------

occupied :: SessionOps -> Bool
occupied ops = isJust (lookupSingle ops SlotDigest)

feedResult :: Bool -> CryptoResult
feedResult True = GotBytes "fed"
feedResult False = GotCryptoError (CryptoFailed "boom")

runCmd
  :: (SessionOps, SessionState) -> DigestCmd -> (StepRes, (SessionOps, SessionState))
runCmd (ops, st) cmd = case cmd of
  DCInit ->
    let (ops', out) = initOperation digestEnv ops st digestArgs
    in ((ioCode out, occupied ops'), (ops', st))
  DCUpdate bs ->
    let (ops', st', step) = planDigestUpdate ops st bs
    in ((soCode step, occupied ops'), (ops', st'))
  DCOneShot bs ->
    let (ops', st', step) = planDigestOneShot ops st "digest" bs
    in ((soCode step, occupied ops'), (ops', st'))
  DCFinal ->
    let (ops', st', step) = planDigestFinal ops st "digest"
    in ((soCode step, occupied ops'), (ops', st'))
  DCFinishInit rid ->
    let (ops', step) =
          finishDigestInit ops SlotDigest "digest" (GotResource rid) (IntentBuffer 64)
    in ((soCode step, occupied ops'), (ops', st))
  DCFinishFeed ok ->
    let (ops', step) =
          finishDigestFeed ops SlotDigest "digest" (feedResult ok) (IntentBuffer 64)
    in ((soCode step, occupied ops'), (ops', st))
  DCFinish bs intent ->
    let (ops', step) = finishDigest ops SlotDigest "digest" (GotBytes bs) intent
    in ((soCode step, occupied ops'), (ops', st))
  DCRetry intent ->
    let (ops', step) = retryStaged ops SlotDigest intent
    in ((soCode step, occupied ops'), (ops', st))

-- | Thread a script through model and planners; per-step
-- (predicted, actual).
runBoth :: [DigestCmd] -> [(StepRes, StepRes)]
runBoth cmds = go PhAbsent (emptySessionOps, freshSession) cmds
  where
    go :: Phase -> (SessionOps, SessionState) -> [DigestCmd] -> [(StepRes, StepRes)]
    go _ _ [] = []
    go phase st (c : rest) =
      let (predRes, phase') = modelStep phase c
          (actRes, st') = runCmd st c
      in (predRes, actRes) : go phase' st' rest

-- ---------------------------------------------------------------------------
-- Properties
-- ---------------------------------------------------------------------------

genIntent :: Gen OutputIntent
genIntent = oneof [pure IntentNull, IntentBuffer <$> choose (0, 64)]

genRid :: Gen EngineResourceId
genRid = EngineResourceId . fromIntegral <$> (choose (1, 50) :: Gen Int)

genCmd :: Gen DigestCmd
genCmd =
  oneof
    [ pure DCInit
    , DCUpdate <$> qcBytes 48
    , DCOneShot <$> qcBytes 48
    , pure DCFinal
    , DCFinishInit <$> genRid
    , DCFinishFeed <$> arbitrary
    , DCFinish <$> qcBytes 48 <*> genIntent
    , DCRetry <$> genIntent
    ]

genScript :: Gen [DigestCmd]
genScript = do
  k <- choose (1, 12)
  vectorOf k genCmd

showStep :: Int -> (DigestCmd, (StepRes, StepRes)) -> String
showStep i (cmd, (predRes, actRes)) =
  "  " ++ show i ++ " " ++ show cmd
    ++ " pred=" ++ show predRes
    ++ " actual=" ++ show actRes

pCommands :: Property
pCommands = forAll genScript $ \cmds ->
  let steps = runBoth cmds
      bad =
        [ i
        | (i, (predRes, actRes)) <- zip [0 ..] steps
        , predRes /= actRes
        ] :: [Int]
  in counterexample
        ("script:\n" ++ unlines (zipWith showStep [0 ..] (zip cmds steps)))
        (null bad)

-- ---------------------------------------------------------------------------
-- Targeted staged/freed transition properties (FI5 showed
-- uniform scripts structurally under-cover staged/freed states, so
-- these drive those states with generated bytes+intents directly).
-- ---------------------------------------------------------------------------

-- | Exact-length generated bytes.
qcBytesN :: Int -> Gen ByteString
qcBytesN n = BS.pack <$> vectorOf n arbitrary

-- | A script that stages by construction: canned length 1..48 with a
-- strictly smaller buffer, then a transition suffix.
genStagedScript :: Gen [DigestCmd]
genStagedScript = do
  cannedLen <- choose (1, 48)
  canned <- qcBytesN cannedLen
  cap <- choose (0, cannedLen - 1)
  k <- choose (0, 2)
  ups <- vectorOf k (qcBytes 32)
  rid <- genRid
  suffix <- stagedSuffix
  let prefix =
        [DCInit, DCFinishInit rid]
          ++ concatMap (\p -> [DCUpdate p, DCFinishFeed True]) ups
          ++ [DCFinal, DCFinish canned (IntentBuffer (fromIntegral cap))]
  pure (prefix ++ [suffix])
  where
    stagedSuffix :: Gen DigestCmd
    stagedSuffix =
      oneof
        [ DCUpdate <$> qcBytes 32
        , pure DCFinal
        , DCOneShot <$> qcBytes 32
        , DCFinish <$> qcBytes 32 <*> genIntent
        ]

-- | A script that frees by construction: canned bytes with a
-- covering buffer, then a transition suffix.
genFreedScript :: Gen [DigestCmd]
genFreedScript = do
  cannedLen <- choose (0, 48)
  canned <- qcBytesN cannedLen
  slack <- choose (0, 16)
  k <- choose (0, 2)
  ups <- vectorOf k (qcBytes 32)
  rid <- genRid
  suffix <- freedSuffix
  let prefix =
        [DCInit, DCFinishInit rid]
          ++ concatMap (\p -> [DCUpdate p, DCFinishFeed True]) ups
          ++ [DCFinal, DCFinish canned (IntentBuffer (fromIntegral (cannedLen + slack)))]
  pure (prefix ++ [suffix])
  where
    freedSuffix :: Gen DigestCmd
    freedSuffix =
      oneof
        [ DCUpdate <$> qcBytes 32
        , pure DCFinal
        , DCOneShot <$> qcBytes 32
        , DCFinish <$> qcBytes 32 <*> genIntent
        , DCRetry <$> genIntent
        ]

traceStr :: [DigestCmd] -> String
traceStr script =
  unlines (zipWith showStep [0 ..] (zip script (runBoth script)))

-- | The actual trace, newest first (total).
revTrace :: [DigestCmd] -> [StepRes]
revTrace script = reverse (actualTrace script)

-- | No model/implementation mismatch on any step.
modelAgrees :: [DigestCmd] -> Bool
modelAgrees script =
  all (\(predRes, actRes) -> predRes == actRes) (runBoth script)

stagedSuffixCode :: DigestCmd -> Maybe ReturnCode
stagedSuffixCode suffix = case suffix of
  DCUpdate _ -> Just CKR_OPERATION_NOT_INITIALIZED
  DCFinal -> Just CKR_OPERATION_NOT_INITIALIZED
  DCOneShot _ -> Just CKR_OPERATION_NOT_INITIALIZED
  DCFinish _ _ -> Just CKR_GENERAL_ERROR
  _ -> Nothing

pStagedRejects :: Property
pStagedRejects = forAll genStagedScript $ \script ->
  counterexample ("staged script:\n" ++ traceStr script) $
    conjoin
      [ counterexample "prefix stages" (property (prefixStaged script))
      , counterexample "suffix pinned" (property (suffixPinned script))
      , counterexample "model agrees" (property (modelAgrees script))
      ]
  where
    prefixStaged :: [DigestCmd] -> Bool
    prefixStaged script = case revTrace script of
      _ : (finCode, finOcc) : _ ->
        finCode == CKR_BUFFER_TOO_SMALL && finOcc
      _ -> False
    suffixPinned :: [DigestCmd] -> Bool
    suffixPinned script = case (reverse script, revTrace script) of
      (suffix : _, (lastCode, _) : _) ->
        stagedSuffixCode suffix == Just lastCode
      _ -> False

pFreedRejects :: Property
pFreedRejects = forAll genFreedScript $ \script ->
  counterexample ("freed script:\n" ++ traceStr script) $
    conjoin
      [ counterexample "prefix frees" (property (prefixFreed script))
      , counterexample "suffix pinned" (property (suffixPinned script))
      , counterexample "model agrees" (property (modelAgrees script))
      ]
  where
    prefixFreed :: [DigestCmd] -> Bool
    prefixFreed script = case revTrace script of
      _ : (finCode, finOcc) : _ -> finCode == CKR_OK && not finOcc
      _ -> False
    suffixPinned :: [DigestCmd] -> Bool
    suffixPinned script = case revTrace script of
      (lastCode, _) : _ -> lastCode == CKR_OPERATION_NOT_INITIALIZED
      _ -> False

-- ---------------------------------------------------------------------------
-- Pinned scripts
-- ---------------------------------------------------------------------------

rid7 :: EngineResourceId
rid7 = EngineResourceId 7

canned32 :: ByteString
canned32 = BS.replicate 32 0xAB

shortIntent :: OutputIntent
shortIntent = IntentBuffer 2

bigIntent :: OutputIntent
bigIntent = IntentBuffer 64

stagedPrefix :: [DigestCmd]
stagedPrefix = [DCInit, DCFinishInit rid7, DCFinal, DCFinish canned32 shortIntent]

freedPrefix :: [DigestCmd]
freedPrefix = [DCInit, DCFinishInit rid7, DCFinal, DCFinish canned32 bigIntent]

-- | (label, script, full expected code trace).
illegalScripts :: [(String, [DigestCmd], [ReturnCode])]
illegalScripts =
  [ ("update without init", [DCUpdate "x"], [CKR_OPERATION_NOT_INITIALIZED])
  , ("final without init", [DCFinal], [CKR_OPERATION_NOT_INITIALIZED])
  , ("oneshot without init", [DCOneShot "x"], [CKR_OPERATION_NOT_INITIALIZED])
  , ("finish-init without init", [DCFinishInit rid7], [CKR_OPERATION_NOT_INITIALIZED])
  , ("finish-feed without init", [DCFinishFeed True], [CKR_OPERATION_NOT_INITIALIZED])
  , ("finish without init", [DCFinish "d" bigIntent], [CKR_OPERATION_NOT_INITIALIZED])
  , ("retry without init", [DCRetry bigIntent], [CKR_OPERATION_NOT_INITIALIZED])
  , ( "update on unallocated stream"
    , [DCInit, DCUpdate "x"]
    , [CKR_OK, CKR_GENERAL_ERROR]
    )
  , ( "final on unallocated stream"
    , [DCInit, DCFinal]
    , [CKR_OK, CKR_GENERAL_ERROR]
    )
  , ( "oneshot after fed"
    , [DCInit, DCFinishInit rid7, DCUpdate "x", DCFinishFeed True, DCOneShot "y"]
    , [CKR_OK, CKR_OK, CKR_OK, CKR_OK, CKR_OPERATION_ACTIVE]
    )
  , ( "update after staged"
    , stagedPrefix ++ [DCUpdate "x"]
    , [CKR_OK, CKR_OK, CKR_OK, CKR_BUFFER_TOO_SMALL, CKR_OPERATION_NOT_INITIALIZED]
    )
  , ( "final after staged"
    , stagedPrefix ++ [DCFinal]
    , [CKR_OK, CKR_OK, CKR_OK, CKR_BUFFER_TOO_SMALL, CKR_OPERATION_NOT_INITIALIZED]
    )
  , ( "oneshot after staged"
    , stagedPrefix ++ [DCOneShot "x"]
    , [CKR_OK, CKR_OK, CKR_OK, CKR_BUFFER_TOO_SMALL, CKR_OPERATION_NOT_INITIALIZED]
    )
  , ( "finish after staged"
    , stagedPrefix ++ [DCFinish "d" bigIntent]
    , [CKR_OK, CKR_OK, CKR_OK, CKR_BUFFER_TOO_SMALL, CKR_GENERAL_ERROR]
    )
  , ( "double final after freed"
    , freedPrefix ++ [DCFinal]
    , [CKR_OK, CKR_OK, CKR_OK, CKR_OK, CKR_OPERATION_NOT_INITIALIZED]
    )
  , ( "update after freed"
    , freedPrefix ++ [DCUpdate "x"]
    , [CKR_OK, CKR_OK, CKR_OK, CKR_OK, CKR_OPERATION_NOT_INITIALIZED]
    )
  , ( "double finish after freed"
    , freedPrefix ++ [DCFinish "d" bigIntent]
    , [CKR_OK, CKR_OK, CKR_OK, CKR_OK, CKR_OPERATION_NOT_INITIALIZED]
    )
  ]

-- | Actual (code, occupied) trace of a script through the planners.
actualTrace :: [DigestCmd] -> [StepRes]
actualTrace cmds = map snd (runBoth cmds)

-- | The final occupancy of a trace (scripts here are never empty).
finalOccupied :: String -> [(StepRes, StepRes)] -> IO Bool
finalOccupied label steps = case reverse steps of
  [] -> assertFailure (label ++ ": empty trace")
  (_, (_, occ)) : _ -> pure occ

caseIllegal :: IO ()
caseIllegal = mapM_ check illegalScripts
  where
    check :: (String, [DigestCmd], [ReturnCode]) -> IO ()
    check (label, cmds, want) =
      assertEqual label want (map fst (actualTrace cmds))

-- | Full valid scripts over generated parts succeed and free the slot.
caseValid :: Int -> IO ()
caseValid count = mapM_ check [1 .. count]
  where
    check :: Int -> IO ()
    check i = do
      let parts = [BS.replicate ((i * 7) `mod` 33) (fromIntegral i), "mid", BS.empty]
          script =
            [DCInit, DCFinishInit rid7]
              ++ concatMap (\p -> [DCUpdate p, DCFinishFeed True]) parts
              ++ [DCFinal, DCFinish canned32 bigIntent]
          steps = runBoth script
      assertEqual ("valid codes " ++ show i)
        (replicate (length script) CKR_OK)
        (map fst (actualTrace script))
      occ <- finalOccupied ("valid freed " ++ show i) steps
      assertEqual ("valid freed " ++ show i) False occ
      -- Staged then retried: the retry delivers and frees.
      let stagedScript = [DCInit, DCFinishInit rid7, DCFinal, DCFinish canned32 shortIntent]
          retryScript = stagedScript ++ [DCRetry bigIntent]
          retrySteps = runBoth retryScript
      assertEqual ("retry codes " ++ show i)
        [CKR_OK, CKR_OK, CKR_OK, CKR_BUFFER_TOO_SMALL, CKR_OK]
        (map fst (actualTrace retryScript))
      retryOcc <- finalOccupied ("retry freed " ++ show i) retrySteps
      assertEqual ("retry freed " ++ show i) False retryOcc
