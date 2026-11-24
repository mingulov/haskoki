{- | Trace contract suite.

§7 JSONL fields, redaction by default, bounded queue + dropped
counter, sink failure never changes the CKR, drops-as-failure mode.
-}
module TraceSpec (spec) where

import qualified Data.ByteString.Char8 as BC8
import Control.Concurrent (myThreadId, throwTo)
import Control.Exception (AsyncException (..), IOException, SomeException, bracket, fromException, try)
import Data.IORef (newIORef, readIORef, modifyIORef')
import Data.List (isInfixOf)
import GHC.Clock (getMonotonicTimeNSec)
import System.Directory (createDirectory, getTemporaryDirectory, removeDirectoryRecursive)
import System.FilePath ((</>))
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertBool, assertEqual, testCase)

import Haskoki.Operation (CryptoCause (..), CryptoError (..), functionCName)
import Haskoki.Outcome (Rejection (..), StateDelta (..))
import Haskoki.Request (FunctionId (..))
import Haskoki.Runtime.Config (TraceCfg (..))
import Haskoki.Runtime.Trace
import Haskoki.Types (JobId (..), ReturnCode (..))

spec :: TestTree
spec = testGroup "Trace"
  [ testCase "JSONL carries every §7 field" caseFields
  , testCase "PINs, key material and bodies redacted" caseRedaction
  , testCase "bounded queue + dropped counter under flood" caseFlood
  , testCase "sink failure leaves the CKR unchanged" caseSinkFailure
  , testCase "drops-as-failure fails the harness run" caseDropsAsFailure
  , testCase "kept failure emits one cause row" caseKeptRow
  , testCase "kept job failure tags mode and job" caseKeptJobRow
  , testCase "causeless rejection emits nothing" caseNoCauseNoRow
  , testCase "function identities name their C entries" caseCNames
  , testCase "sync-try never swallows cancellation" caseTrySyncAsync
  , testCase "store spellings decode once or refuse" caseSpellingTable
  , testCase "resolved spellings re-check URI and :memory:" caseRecheckTable
  , testCase "guard: a URI twin resolving away still guards the decoded target" caseGuardTwinSymlink
  , testCase "guard: a URI spelling aliasing the target drops" caseGuardUriAlias
  , testCase "guard: a distinct trace file proceeds" caseGuardDistinct
  , testCase "guard: an undecodable URI drops" caseGuardUndecodable
  , testCase "guard: a URI spelling with a distinct trace file proceeds" caseGuardUriDistinct
  , testCase "guard: a trace aimed at the twin's target proceeds" caseGuardTwinTraceProceeds
  , testCase "guard: a resolved URI strips its authority" caseGuardResolvedUriAuthority
  ]

ids :: TraceIds
ids = TraceIds "trace/1" "haskoki-test" "trace-spec" "demo-maximal" "run-1"

ev :: TraceEvent
ev = TraceEvent
  { teFunction = "C_Sign"
  , teInterface = "3.2"
  , teMechanism = Just "CKM_RSA_PKCS"
  , teSession = Just "s1"
  , teObject = Just "demo-signing-key"
  , teJob = Nothing
  , teInputLen = 12
  , teOutputLen = 256
  , teCkr = 0
  , teDisposition = "delivered"
  , teReason = "rule:none"
  , teMode = "sync"
  , teSecret = Nothing
  }

caseFields :: IO ()
caseFields = do
  let line = BC8.unpack (renderJSONL ids 7 ev)
  mapM_ (\k -> assertBool ("field present: " ++ k) (k `isInfixOf` line))
    [ "\"schema\":\"trace/1\"", "\"build\":\"haskoki-test\""
    , "\"source\":\"trace-spec\"", "\"profile\":\"demo-maximal\""
    , "\"run\":\"run-1\"", "\"seq\":7", "\"function\":\"C_Sign\""
    , "\"interface\":\"3.2\"", "\"mechanism\":\"CKM_RSA_PKCS\""
    , "\"session\":\"s1\"", "\"object\":\"demo-signing-key\""
    , "\"input_len\":12", "\"output_len\":256", "\"ckr\":0"
    , "\"disposition\":\"delivered\"", "\"reason\":\"rule:none\""
    , "\"mode\":\"sync\""
    ]

caseRedaction :: IO ()
caseRedaction = do
  let withPin = ev { teSecret = Just (TracePin "1234") }
      withKey = ev { teSecret = Just (TraceKeyMaterial "AAECAwQFBg==") }
      withBody = ev { teSecret = Just (TraceBody "super-secret-bytes") }
      rendered = map (BC8.unpack . renderJSONL ids 1) [withPin, withKey, withBody]
  mapM_ (\line -> assertBool "redaction marker" ("\"redacted\":true" `isInfixOf` line)) rendered
  assertBool "no PIN leak" (not ("1234" `isInfixOf` concat rendered))
  assertBool "no key leak" (not ("AAECAwQFBg==" `isInfixOf` concat rendered))
  assertBool "no body leak" (not ("super-secret-bytes" `isInfixOf` concat rendered))
  -- Lengths survive (reproducibility via lengths, not secrets).
  case rendered of
    (first : _) -> assertBool "pin length kept" ("\"length\":4" `isInfixOf` first)
    [] -> fail "redaction cases vanished"

caseFlood :: IO ()
caseFlood = do
  kept <- newIORef (0 :: Int)
  tr <- newTracer 100 (\_ -> modifyIORef' kept (+ 1) >> pure (Right ())) False
  mapM_ (\_ -> emitTrace tr ev 0 >> pure ()) [1 .. 500 :: Int]
  d <- droppedTraces tr
  assertEqual "drops counted" 400 d
  rep <- drainTracer tr
  assertEqual "bounded drain" 100 (drWritten rep)
  assertEqual "no sink failures" 0 (drFailed rep)
  k <- readIORef kept
  assertEqual "sink saw the bound" 100 k

caseSinkFailure :: IO ()
caseSinkFailure = do
  tr <- newTracer 16 (\_ -> pure (Left "EIO")) False
  -- The CKR on the way in is the CKR on the way out, always.
  c1 <- emitTrace tr ev 0
  c2 <- emitTrace tr ev { teCkr = 5 } 5
  assertEqual "ok preserved" 0 c1
  assertEqual "error preserved" 5 c2
  rep <- drainTracer tr
  assertEqual "failures reported, not thrown" 2 (drFailed rep)
  assertEqual "nothing written" 0 (drWritten rep)

caseDropsAsFailure :: IO ()
caseDropsAsFailure = do
  tr <- newTracer 4 (\_ -> pure (Right ())) True
  mapM_ (\_ -> emitTrace tr ev 0 >> pure ()) [1 .. 10 :: Int]
  ok <- runHarnessChecked tr
  assertBool "drops fail the harness run" (not ok)
  tr2 <- newTracer 64 (\_ -> pure (Right ())) True
  mapM_ (\_ -> emitTrace tr2 ev 0 >> pure ()) [1 .. 10 :: Int]
  ok2 <- runHarnessChecked tr2
  assertBool "no drops keeps the run passing" ok2
  -- Same flood without the mode: harness stays passing (loss counted, not fatal).
  tr3 <- newTracer 4 (\_ -> pure (Right ())) False
  mapM_ (\_ -> emitTrace tr3 ev 0 >> pure ()) [1 .. 10 :: Int]
  ok3 <- runHarnessChecked tr3
  assertBool "non-strict mode tolerates counted drops" ok3

collectingTracer :: IO (Tracer, IO [String])
collectingTracer = do
  ref <- newIORef []
  tr <- newTracer 64 (\l -> modifyIORef' ref (BC8.unpack l :) >> pure (Right ())) False
  pure (tr, reverse <$> readIORef ref)

caseKeptRow :: IO ()
caseKeptRow = do
  (tr, rows) <- collectingTracer
  emitKeptFailure tr (CryptoCause F_SignFinal (CryptoNative "op" 7 "why"))
  rep <- drainTracer tr
  assertEqual "one row written" 1 (drWritten rep)
  ls <- rows
  case ls of
    [line] -> do
      mapM_ (\k -> assertBool ("row carries " ++ k) (k `isInfixOf` line))
        [ "\"function\":\"C_SignFinal\"", "\"ckr\":5"
        , "\"reason\":\"CryptoNative(op,7,why)\""
        , "\"disposition\":\"rejected\"", "\"mode\":\"sync\""
        , "\"job\":null"
        ]
    other -> fail ("expected exactly one row, got: " ++ show (length other))

caseKeptJobRow :: IO ()
caseKeptJobRow = do
  (tr, rows) <- collectingTracer
  emitKeptJobFailure tr (AsyncTableId 2) (JobId 9) (CryptoCause F_DigestFinal (CryptoFailed "boom"))
  rep <- drainTracer tr
  assertEqual "one row written" 1 (drWritten rep)
  ls <- rows
  case ls of
    [line] -> do
      mapM_ (\k -> assertBool ("row carries " ++ k) (k `isInfixOf` line))
        [ "\"function\":\"C_DigestFinal\"", "\"mode\":\"async\""
        , "\"job\":\"j9@t2\"", "CryptoFailed"
        ]
    other -> fail ("expected exactly one row, got: " ++ show (length other))

caseNoCauseNoRow :: IO ()
caseNoCauseNoRow = do
  (tr, rows) <- collectingTracer
  let rej = Rejection
        { rejCode = CKR_FUNCTION_FAILED
        , rejOutputs = []
        , rejDelta = StateDelta []
        , rejReleases = []
        , rejReasons = ["distinct cell"]
        , rejCause = Nothing
        }
  emitRejectionCause tr rej
  rep <- drainTracer tr
  assertEqual "nothing written" 0 (drWritten rep)
  ls <- rows
  assertEqual "no rows collected" [] ls

caseCNames :: IO ()
caseCNames = do
  assertEqual "sign final" "C_SignFinal" (functionCName F_SignFinal)
  assertEqual "digest" "C_Digest" (functionCName F_Digest)
  assertEqual "dual" "C_DigestEncryptUpdate" (functionCName F_DigestEncryptUpdate)
  assertEqual "encapsulate" "C_EncapsulateKey" (functionCName F_EncapsulateKey)
  assertEqual "get info" "C_GetInfo" (functionCName F_GetInfo)
  -- Every identity mirrors its C entry: a future non-F_ ctor
  -- breaks this sweep and forces a naming decision here.
  mapM_ (\fid -> case functionCName fid of
    'C' : '_' : _ -> pure ()
    other -> fail ("non-C name for " ++ show fid ++ ": " ++ other))
    [minBound .. maxBound]

caseTrySyncAsync :: IO ()
caseTrySyncAsync = do
  r1 <- trySync (ioError (userError "boom") >> pure ())
  case r1 of
    Left _ -> pure ()
    Right _ -> fail "sync failure must return Left"
  r2 <- trySync (pure (42 :: Int))
  case r2 of
    Right 42 -> pure ()
    _ -> fail "success must return Right"
  r3 <- try (trySync (myThreadId >>= \t -> throwTo t ThreadKilled >> pure ()))
    :: IO (Either SomeException (Either SomeException ()))
  case r3 of
    Left ex -> case (fromException ex :: Maybe AsyncException) of
      Just _ -> pure ()
      Nothing -> fail ("expected async, got sync: " ++ show ex)
    Right _ -> fail "cancellation was swallowed"

-- | Store-spelling rule table: POSIX spellings pass through
-- for the existing resolution to handle; bare file: URIs decode
-- once; query/fragment, undecodable, nested, and empty
-- spellings refuse so guards and SQLite can never diverge.
caseSpellingTable :: IO ()
caseSpellingTable = mapM_ check
  [ ("/tmp/x.db", Right "/tmp/x.db")
  , ("rel/path.db", Right "rel/path.db")
  , ("", Left SpellingEmpty)
  , ("file:/tmp/a%2edb", Right "/tmp/a.db")
  , ("file:/tmp/x/%2e%2e/a.db", Right "/tmp/x/../a.db")
  , ("file:/tmp/a%3F.db", Right "/tmp/a?.db")
  , ("file:/tmp/a.db?mode=memory", Left UriQueryOrFragment)
  , ("file:/tmp/a.db#frag", Left UriQueryOrFragment)
  , ("file:/tmp/a%00.db", Left UriUndecodable)
  , ("file:/tmp/a%FF.db", Left UriUndecodable)
  , ("file:/tmp/a%.db", Left UriUndecodable)
  , ("file:", Left SpellingEmpty)
  , ("file:file%3Ax", Left UriNested)
  -- :memory: is NOT special at decode (no file: prefix): the
  -- resolve stage refuses it, where SQLite would act on it.
  , (":memory:", Right ":memory:")
  -- Authority: SQLite opens the path after an empty or
  -- localhost authority (matched exactly, before decoding)
  -- and refuses anything else, so decoding agrees.
  , ("file:///tmp/x.db", Right "/tmp/x.db")
  , ("file://localhost/tmp/x.db", Right "/tmp/x.db")
  , ("file://other/tmp/x.db", Left UriAuthority)
  , ("file://LOCALHOST/tmp/x.db", Left UriAuthority)
  , ("file://%6cocalhost/tmp/x.db", Left UriAuthority)
  , ("file://", Left SpellingEmpty)
  , ("file://localhost/file:x", Right "/file:x")
  ]
  where
    check (input, want) =
      assertEqual ("spelling " ++ show input) want (effectiveStorePath input)

caseRecheckTable :: IO ()
caseRecheckTable = mapM_ check
  [ ("", Left SpellingEmpty)
  , (":memory:", Left SpellingIsMemory)
  , ("file:x.db", Left UriAfterResolve)
  , ("file:/abs/x.db", Left UriAfterResolve)
  , ("/abs/x.db", Right "/abs/x.db")
  , ("rel/x.db", Right "rel/x.db")
  , ("xfile:y.db", Right "xfile:y.db")
  ]
  where
    check (input, want) =
      assertEqual ("recheck " ++ show input) want (recheckResolved input)

-- | Two real files under a scratch dir: the guard's alias legs
-- stat for real while the resolver is injected (a literal
-- twin needs a relative URI, which would couple the test to
-- the process working directory under parallel suites).
withTokenDecoy :: (FilePath -> FilePath -> IO a) -> IO a
withTokenDecoy act =
  bracket create tryRemove $ \dir -> do
    let token = dir </> "token.db"
        decoy = dir </> "decoy.db"
    writeFile token "store-bytes"
    writeFile decoy "decoy-bytes"
    act token decoy
  where
    create = do
      base <- getTemporaryDirectory
      let go :: Int -> IO FilePath
          go n = do
            t <- getMonotonicTimeNSec
            let d = base </> ("haskoki-trace-guard-" ++ show t ++ "-" ++ show n)
            r <- try (createDirectory d)
            case r of
              Right () -> pure d
              Left (e :: IOException)
                | n < 100 -> go (n + 1)
                | otherwise -> ioError e
      go 0
    tryRemove d = do
      _ <- (try (removeDirectoryRecursive d) :: IO (Either IOException ()))
      pure ()

-- | A literal "file:..." symlink beside the store resolves the
-- RAW spelling away while the opener decodes to the target the
-- trace file names: the row must drop (proceeding would emit
-- into the store).
caseGuardTwinSymlink :: IO ()
caseGuardTwinSymlink = withTokenDecoy $ \token decoy -> do
  tr <- newFileTracer (TraceCfg True token True 64)
  let twinResolve p
        | p == "file:" ++ token = pure decoy
        | otherwise = pure p
  skip <- tracerSkipsStoreWith (pure True) twinResolve tr ("file:" ++ token)
  assertEqual "twin resolving away still guards the decoded target" True skip

-- | Control: without a twin, a URI spelling aliasing the trace
-- target drops.
caseGuardUriAlias :: IO ()
caseGuardUriAlias = withTokenDecoy $ \token _decoy -> do
  tr <- newFileTracer (TraceCfg True token True 64)
  skip <- tracerSkipsStoreWith (pure True) pure tr ("file:" ++ token)
  assertEqual "URI alias drops" True skip

-- | Control: a distinct trace file proceeds (the guard must not
-- mute everything).
caseGuardDistinct :: IO ()
caseGuardDistinct = withTokenDecoy $ \token decoy -> do
  tr <- newFileTracer (TraceCfg True decoy True 64)
  skip <- tracerSkipsStoreWith (pure True) pure tr token
  assertEqual "distinct trace proceeds" False skip

-- | An undecodable URI drops: the guard cannot place the store.
caseGuardUndecodable :: IO ()
caseGuardUndecodable = withTokenDecoy $ \token _decoy -> do
  tr <- newFileTracer (TraceCfg True token True 64)
  skip <- tracerSkipsStoreWith (pure True) pure tr "file:%zz"
  assertEqual "undecodable URI drops" True skip

-- | A URI spelling per se does not drop: with a distinct trace
-- file the row proceeds.
caseGuardUriDistinct :: IO ()
caseGuardUriDistinct = withTokenDecoy $ \token decoy -> do
  tr <- newFileTracer (TraceCfg True decoy True 64)
  skip <- tracerSkipsStoreWith (pure True) pure tr ("file:" ++ token)
  assertEqual "URI with distinct trace proceeds" False skip

-- | The twin correction's other direction: the trace file aimed
-- at the twin's resolution target (the decoy stands in for
-- where the literal twin points) must PROCEED, since the store
-- opens the decoded target, not the twin. Resolving the raw
-- spelling would drop here (false conservative).
caseGuardTwinTraceProceeds :: IO ()
caseGuardTwinTraceProceeds = withTokenDecoy $ \token decoy -> do
  tr <- newFileTracer (TraceCfg True decoy True 64)
  let twinResolve p
        | p == "file:" ++ token = pure decoy
        | otherwise = pure p
  skip <- tracerSkipsStoreWith (pure True) twinResolve tr ("file:" ++ token)
  assertEqual "trace at the twin target proceeds" False skip

-- | The resolved-URI leg strips authorities like the opener: a
-- POSIX spelling resolving (via a symlink hop) to a localhost
-- URI guards the stripped target.
caseGuardResolvedUriAuthority :: IO ()
caseGuardResolvedUriAuthority = withTokenDecoy $ \token _decoy -> do
  tr <- newFileTracer (TraceCfg True token True 64)
  let hopResolve p
        | p == "mystore" = pure ("file://localhost" ++ token)
        | otherwise = pure p
  skip <- tracerSkipsStoreWith (pure True) hopResolve tr "mystore"
  assertEqual "resolved URI authority strips to the target" True skip
