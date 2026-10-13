{-# LANGUAGE OverloadedStrings #-}
module Main (main) where

import Control.Exception (Exception, SomeException, bracket, fromException, throwIO, try)
import Control.Monad (unless)
import qualified Data.Map.Strict as Map
import Data.List (sortOn)
import System.Directory (createDirectory, doesDirectoryExist, getTemporaryDirectory, removeDirectoryRecursive)
import System.Environment (getArgs)
import System.Exit (ExitCode (..), exitWith)
import System.FilePath ((</>))
import System.IO (BufferMode (LineBuffering), hSetBuffering, stdout)
import System.IO.Error (catchIOError)
import System.Posix.Process (getProcessID)

import Haskoki.Attribute (AttributeType (..), AttributeValue (..))
import Haskoki.Runtime.Storage
  ( CommitResult (..), JobBody (..), JobExecState (..), JobRecord (..)
  , ObjectPut (..), ObjectRecord (..), Store (..), StoreDelta (..)
  , StoreError (..), StoredDoc (..), TokenRecord (..), emptyDelta
  )
import Haskoki.Runtime.Storage.Memory (newMemoryWorld, openMemoryStore)
import Haskoki.Runtime.Storage.SQLite (openSQLiteStore)
import Haskoki.Session (tokenAuthNew)
import Haskoki.Types (Generation (..), ObjectId (..), ReturnCode (..), Revision (..), SlotId (..), TokenId (..))

-- Diagnostic-only cases: no fault injection, production changes, or shared data.
-- A setup error is distinct from an observed contract violation.
data SetupFailure = SetupFailure String deriving (Show)
instance Exception SetupFailure

data Result = Passed | Violated | SetupError deriving (Eq)

main :: IO ()
main = do
  hSetBuffering stdout LineBuffering
  args <- getArgs
  backends <- case args of
    [] -> pure ["memory", "sqlite"]
    ["memory"] -> pure ["memory"]
    ["sqlite"] -> pure ["sqlite"]
    _ -> do
      putStrLn "SETUP_ERROR usage: haskoki-review-probes [memory|sqlite]"
      exitWith (ExitFailure 2)
  results <- mapM runCase
    [ (backend ++ "/" ++ name, withBackend backend probe)
    | backend <- backends
    , (name, probe) <-
        [ ("token-refresh-preserves-children", tokenRefresh)
        , ("stale-close-preserves-current-owner", staleClose)
        ]
    ]
  putStrLn ("SUMMARY cases=" ++ show (length results)
    ++ " passed=" ++ show (count Passed results)
    ++ " violations=" ++ show (count Violated results)
    ++ " setup_errors=" ++ show (count SetupError results))
  exitWith $ if SetupError `elem` results then ExitFailure 2
    else if Violated `elem` results then ExitFailure 1 else ExitSuccess
  where
    count result = length . filter (== result)

runCase :: (String, IO [String]) -> IO Result
runCase (name, action) = do
  putStrLn ("CASE " ++ name)
  result <- try action :: IO (Either SomeException [String])
  case result of
    Left err -> do
      let detail = case fromException err of
            Just (SetupFailure message) -> message
            Nothing -> "unexpected exception: " ++ show err
      putStrLn ("SETUP_ERROR " ++ name ++ " " ++ detail)
      pure SetupError
    Right [] -> putStrLn ("PASS " ++ name) >> pure Passed
    Right failures -> do
      mapM_ (putStrLn . (("VIOLATION " ++ name ++ " ") ++)) failures
      pure Violated

-- Each case gets a fresh identity. SQLite's entire directory (DB and sidecars)
-- is removed after the case, even when its assertions fail.
withBackend :: String -> (IO (Either StoreError Store) -> IO a) -> IO a
withBackend "memory" action = do
  world <- newMemoryWorld
  action (openMemoryStore world)
withBackend "sqlite" action = bracket makeTempDir removeDirectoryRecursive $ \dir ->
  action (openSQLiteStore (dir </> "store.db"))
withBackend other _ = throwIO (SetupFailure ("unknown backend: " ++ other))

-- Same dependency-free allocation pattern as tests/storage/StoreSpec.hs.
-- Only a directory successfully created by this process is removed.
makeTempDir :: IO FilePath
makeTempDir = do
  base <- getTemporaryDirectory
  pid <- getProcessID
  let next n
        | n > (10000 :: Int) = throwIO (SetupFailure "temporary directory names exhausted")
        | otherwise = do
            let path = base </> ("haskoki-review-runtime-" ++ show pid ++ "-" ++ show n)
            (createDirectory path >> pure path) `catchIOError` \err -> do
              exists <- doesDirectoryExist path
              if exists then next (n + 1) else throwIO err
  next 0

opened :: String -> IO (Either StoreError Store) -> IO Store
opened phase opener = opener >>= required phase

required :: Show e => String -> Either e a -> IO a
required phase = either (throwIO . SetupFailure . ((phase ++ ": ") ++) . show) pure

seedToken :: TokenRecord
seedToken = TokenRecord
  { trId = TokenId 7
  , trSlot = SlotId 0
  , trGeneration = Generation 1
  , trLabel = "review-seed-token"
  , trAuth = tokenAuthNew
  }

seedObject :: ObjectRecord
seedObject = ObjectRecord
  { orId = ObjectId 11
  , orToken = trId seedToken
  , orClass = 0
  , orKeyType = Nothing
  , orAttrs = Map.fromList
      [ (AttrClass, ValULong 0)
      , (AttrToken, ValBool True)
      , (AttrLabel, ValBytes "review-object")
      , (AttrValue, ValBytes "ephemeral-review-payload")
      ]
  , orMaterialEncoding = "none"
  , orMaterial = Nothing
  , orRevision = Revision 1
  }

seedJob :: JobRecord
seedJob = JobRecord
  { jrPersistentId = 21
  , jrToken = trId seedToken
  , jrTokenGeneration = trGeneration seedToken
  , jrFunction = "C_Digest"
  , jrState = JobQueued
  , jrBody = JobPending "sha256-owned-input/v1" "ephemeral-review-job-input"
  }

-- This is a record-side Store contract test; the queued recipe is deliberately
-- never executed, replayed, or passed to Detached's recipe decoder.
tokenRefresh :: IO (Either StoreError Store) -> IO [String]
tokenRefresh opener = do
  (immediate, before) <- bracket (opened "initial open" opener) storeClose $ \store -> do
    seeded <- storeCommit store emptyDelta
      { sdPutTokens = [seedToken]
      , sdPutObjects = [ObjectPut Nothing seedObject]
      , sdPutJobs = [seedJob]
      }
    unless (seeded == Committed) $
      throwIO (SetupFailure ("seed commit: " ++ show seeded))
    before <- childDocs <$> storeInspect store
    tokens <- storeLoadTokens store >>= required "seed token load"
    jobs <- storeLoadJobs store >>= required "seed job load"
    unless (tokens == [(seedToken, [seedObject])] && jobs == [seedJob]
      && length before == 2) $
      throwIO (SetupFailure "seed failed exact round-trip or canonical child document count")
    committed <- storeCommit store emptyDelta { sdPutTokens = [refreshedToken] }
    putStrLn ("OBSERVED refresh_commit=" ++ show committed)
    failures <- observeRefresh "immediate" store before
    pure (failedUnless (committed == Committed) "token-only refresh did not commit" ++ failures, before)
  reopened <- bracket (opened "reopen after refresh" opener) storeClose $ \store ->
    observeRefresh "reopened" store before
  pure (immediate ++ reopened)

refreshedToken :: TokenRecord
refreshedToken = seedToken { trLabel = "review-refreshed-token" }

childDocs :: [StoredDoc] -> [StoredDoc]
childDocs = sortOn (\doc -> (docTable doc, docKey doc))
  . filter (\doc -> docTable doc `elem` ["objects", "detached_jobs"])

observeRefresh :: String -> Store -> [StoredDoc] -> IO [String]
observeRefresh phase store before = do
  tokenResult <- storeLoadTokens store
  jobResult <- storeLoadJobs store
  docs <- childDocs <$> storeInspect store
  let tokenCount = either (const (-1)) length tokenResult
      objectCount = either (const (-1)) (sum . map (length . snd)) tokenResult
      jobCount = either (const (-1)) length jobResult
      tokensExact = tokenResult == Right [(refreshedToken, [seedObject])]
      jobsExact = jobResult == Right [seedJob]
      bytesExact = docs == before
  putStrLn ("OBSERVED " ++ phase ++ " tokens=" ++ show tokenCount
    ++ " objects=" ++ show objectCount ++ " jobs=" ++ show jobCount
    ++ " token_and_object_exact=" ++ show tokensExact
    ++ " job_exact=" ++ show jobsExact ++ " child_documents_exact=" ++ show bytesExact)
  pure (failedUnless tokensExact (phase ++ ": refreshed token and original object differ")
    ++ failedUnless jobsExact (phase ++ ": original detached job differs")
    ++ failedUnless bytesExact (phase ++ ": canonical child documents differ"))

staleClose :: IO (Either StoreError Store) -> IO [String]
staleClose opener = bracket (opened "owner A open" opener) storeClose $ \ownerA -> do
  -- The outer finalizer runs only after B and any unexpectedly opened C close.
  -- It therefore cannot revoke a later live owner during cleanup.
  storeClose ownerA
  verdict <- bracket (opened "owner B open after A close" opener) storeClose $ \_ownerB -> do
    storeClose ownerA
    contender <- opener
    case contender of
      Left (StoreSecondWriter _) -> do
        putStrLn "OBSERVED C_after_stale_A_close=refused_second_writer"
        pure []
      Left err -> do
        putStrLn ("OBSERVED C_after_stale_A_close=other_refusal " ++ show err)
        pure ["C must refuse specifically as StoreSecondWriter while B owns the identity"]
      Right ownerC -> bracket (pure ownerC) storeClose $ \_ -> do
        putStrLn "OBSERVED C_after_stale_A_close=opened_while_B_live"
        pure ["stale A close released B's exclusive ownership"]
  -- Confirm legitimate release still permits a later opener; its handle is
  -- also closed before the old A handle's outer finalizer runs.
  bracket (opened "open after B and C cleanup" opener) storeClose $ \_ ->
    putStrLn "OBSERVED after_owner_cleanup=reopened"
  pure verdict

failedUnless :: Bool -> String -> [String]
failedUnless condition message = [message | not condition]
