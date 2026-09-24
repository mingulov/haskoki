{- | CLI store subcommands (hermetic temp dirs).

@store inspect@ reads a SQLite store offline; @store reset@ refuses a
live (lock-held) store and resets an offline one only with the
confirm flag. Never mutates a live store.
-}
module StoreCtlSpec (spec) where

import Control.Exception (bracket)
import System.Directory (doesFileExist)
import System.FilePath ((</>))
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertBool, assertEqual, testCase)

import Haskoki.Ctl (CtlExit (..), runCtl)
import Haskoki.Runtime.Storage (storeClose, storeCommit, emptyDelta)
import Haskoki.Runtime.Storage.SQLite (openSQLiteStore)

import StoreSpec (makeTempDir)

spec :: TestTree
spec = testGroup "Store commands"
  [ testCase "inspect reads an offline store" caseInspect
  , testCase "reset refuses a live store" caseResetLive
  , testCase "reset needs the confirm flag" caseResetConfirm
  , testCase "reset clears an offline store with the flag" caseResetOffline
  ]

withStoreFile :: (FilePath -> IO a) -> IO a
withStoreFile = bracket (makeTempDir "store-ctl") dropDir
  where
    dropDir _ = pure ()

seedDb :: FilePath -> IO FilePath
seedDb dir = do
  let db = dir </> "demo-token.sqlite"
  eSt <- openSQLiteStore db
  case eSt of
    Left err -> fail ("seed open failed: " ++ show err)
    Right st -> do
      _ <- storeCommit st emptyDelta
      storeClose st
      pure db

caseInspect :: IO ()
caseInspect = withStoreFile $ \dir -> do
  db <- seedDb dir
  r <- runCtl ["store", "inspect", "--path", db]
  assertEqual "inspect exits 0" 0 (ceCode r)
  assertBool "reports offline" ("offline" `elem` words (ceOut r))

caseResetLive :: IO ()
caseResetLive = withStoreFile $ \dir -> do
  let db = dir </> "live.sqlite"
  eSt <- openSQLiteStore db
  case eSt of
    Left err -> fail ("open failed: " ++ show err)
    Right st -> do
      r <- runCtl ["store", "reset", "--path", db, "--confirm-demo-reset"]
      storeClose st
      assertBool "live store refused" (ceCode r /= 0)
      assertBool "names the lock" ("live" `elem` words (ceOut r ++ ceErr r))
      stillThere <- doesFileExist db
      assertBool "live db untouched" stillThere

caseResetConfirm :: IO ()
caseResetConfirm = withStoreFile $ \dir -> do
  db <- seedDb dir
  r <- runCtl ["store", "reset", "--path", db]
  assertBool "no flag, no reset" (ceCode r /= 0)
  stillThere <- doesFileExist db
  assertBool "db untouched" stillThere

caseResetOffline :: IO ()
caseResetOffline = withStoreFile $ \dir -> do
  db <- seedDb dir
  r <- runCtl ["store", "reset", "--path", db, "--confirm-demo-reset"]
  assertEqual "reset exits 0" 0 (ceCode r)
  gone <- doesFileExist db
  assertBool "offline db removed" (not gone)
