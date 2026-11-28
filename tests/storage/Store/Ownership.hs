{- | Store lock ownership cases.
-}
{-# LANGUAGE OverloadedStrings #-}
module Store.Ownership
  ( testCloseKeepsReplacement
  , testOwnershipGuards
  , testStaleLockTakeoverServing
  , testUnlinkRefuses
  ) where

import Control.Exception (bracket)
import Control.Monad (when)
import Data.IORef (newIORef)
import Data.List (isInfixOf)
import System.Directory (removeDirectoryRecursive, removeFile)
import System.FilePath ( (</>))
import System.Posix.IO (OpenMode (..), closeFd, defaultFileFlags, openFd)
import System.Posix.Process (getProcessID)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertBool, assertEqual, assertFailure, testCase)
import Haskoki.Runtime.Storage
  ( CommitResult (..)
  , Store (..)
  , StoreError (..)
  , defaultLimits
  , emptyDelta
  , noFaults
  )
import StoreFixtures
  ( EnvScope, awaitHolderExit
  , makeTempDir
  , reapedPid, releaseHolder, spawnedPid
   )
import Haskoki.Runtime.Storage.SQLite (openSQLiteStore, openSQLiteStoreWith)
import Store.Fixtures

-- | Ownership guards (one case, sequential phases — the masked-proc
-- phase mutates @HASKOKI_PROC_ROOT@ process-wide, so the phases must
-- not run concurrently with each other): a stale-pid lock with no
-- holder is still takeable and the taken-over store keeps its data
-- (no fail-closed overreach); a second open with owner liveness
-- unknowable is refused; and a stale-pid lock whose kernel lock is
-- held is refused until the holder goes away.
testOwnershipGuards :: IO EnvScope -> IO ()
testOwnershipGuards mkScope = do
  (staleTakeable mkScope)
  (heldFlockRefuses mkScope)
  (maskedProcRefuses mkScope)

-- | Variant guard: a lock naming a provably-dead pid, with no
-- kernel-lock holder, is taken over; the lock is re-owned and the
-- seeded data survives the takeover.
staleTakeable :: IO EnvScope -> IO ()
staleTakeable mkScope =
  bracket (makeTempDir "haskoki-storage-stale") removeDirectoryRecursive $ \dir -> do
    let path = dir </> "store.db"
    e0 <- openSQLiteStore path
    s0 <- either (\e -> assertFailure ("stale seed open: " ++ show e)) pure e0
    _ <- seedStore s0
    storeClose s0
    deadPid <- reapedPid mkScope
    writeFile (path ++ ".lock") (show deadPid ++ "\n")
    e1 <- openSQLiteStore path
    s1 <- either (\e -> assertFailure ("stale takeover failed: " ++ show e)) pure e1
    me <- getProcessID
    content <- readFile (path ++ ".lock")
    assertEqual "stale: lock re-owned by taker" (show me ++ "\n") content
    eLoaded <- storeLoadTokens s1
    loaded <- either (\e -> assertFailure ("stale load after takeover: " ++ show e)) pure eLoaded
    assertEqual "stale: seeded token survives takeover" 1 (length loaded)
    storeClose s1

-- | Kernel guard: a stale-pid lock whose file is @flock@-held (a
-- live-but-hidden owner from the store's point of view) refuses the
-- takeover with 'StoreSecondWriter'; once the holder goes away the
-- same lock is takeable.
heldFlockRefuses :: IO EnvScope -> IO ()
heldFlockRefuses mkScope =
  bracket (makeTempDir "haskoki-storage-held") removeDirectoryRecursive $ \dir -> do
    let path = dir </> "store.db"
    e0 <- openSQLiteStore path
    s0 <- either (\e -> assertFailure ("held seed open: " ++ show e)) pure e0
    storeClose s0
    deadPid <- reapedPid mkScope
    writeFile (path ++ ".lock") (show deadPid ++ "\n")
    bracket (openFd (path ++ ".lock") ReadOnly defaultFileFlags) closeFd $ \holderFd -> do
      held <- testTryFlock holderFd
      assertBool "held: test holder took the kernel lock" held
      e1 <- openSQLiteStore path
      case e1 of
        Right s1 -> do
          storeClose s1
          assertFailure "held: takeover succeeded despite held kernel lock (state fork)"
        Left (StoreSecondWriter _) -> pure ()
        Left other -> assertFailure ("held: wrong error for held lock: " ++ show other)
    e2 <- openSQLiteStore path
    s2 <- either (\e -> assertFailure ("held: takeover after release failed: " ++ show e)) pure e2
    storeClose s2

-- | Stale-lock takeover through the serving open, one case per
-- lock content: a lock naming the opener's own pid, a live pid
-- (1), an empty file, garbage with or without a trailing newline,
-- or NUL bytes is taken over when no fd holds the kernel flock,
-- and refused while another fd holds it. A genuine second open in
-- the same process still refuses: flock is per open file
-- description, so the second open's takeover attempt meets the
-- first open's held lock. All cases use the default (inert) opener,
-- so the verdicts come from the real @\/proc@ and the kernel lock,
-- never the env seams — a concurrent fake-root arming in a
-- filtered run cannot reclassify them.
testStaleLockTakeoverServing :: TestTree
testStaleLockTakeoverServing = testGroup "stale locks take over when no holder keeps them; second open still refuses"
  [ testCase "own pid, free lock is taken over" $
      withOwnPid (\content -> testFree "own-pid" content)
  , testCase "own pid, held lock still refuses" $
      withOwnPid (\content -> testHeld "own-pid" content "already open in this process")
  , testCase "pid-1, free lock is taken over" $ testFree "pid-1" "1\n"
  , testCase "pid-1, held lock still refuses" $ testHeld "pid-1" "1\n" "already open by pid 1"
  , testCase "empty, free lock is taken over" $ testFree "empty" ""
  , testCase "empty, held lock still refuses" $ testHeld "empty" "" "empty"
  , testCase "garbage with newline, free lock is taken over" $ testFree "garbage-nl" "garbage\n"
  , testCase "garbage with newline, held lock still refuses" $ testHeld "garbage-nl" "garbage\n" "unknown owner"
  , testCase "garbage without newline, free lock is taken over" $ testFree "garbage" "garbage"
  , testCase "garbage without newline, held lock still refuses" $ testHeld "garbage" "garbage" "unknown owner"
  , testCase "NUL bytes, free lock is taken over" $ testFree "nuls" "\0\0\0\0\0"
  , testCase "NUL bytes, held lock still refuses" $ testHeld "nuls" "\0\0\0\0\0" "unknown owner"
  , testCase "second open in the same process still refuses" testGenuineSecondOpen
  ]
  where
    withOwnPid act = do
      me <- getProcessID
      act (show me ++ "\n")
    testFree tag content =
      bracket (makeTempDir ("haskoki-storage-takeover-" ++ tag)) removeDirectoryRecursive $ \dir -> do
        let path = dir </> "store.db"
        e0 <- openSQLiteStore path
        s0 <- either (\e -> assertFailure (tag ++ " seed open: " ++ show e)) pure e0
        _ <- seedStore s0
        storeClose s0
        writeFile (path ++ ".lock") content
        e1 <- openSQLiteStore path
        s1 <- either (\e -> assertFailure (tag ++ " takeover failed (stale lock not taken): " ++ show e)) pure e1
        mine <- getProcessID
        lockContent <- readFile (path ++ ".lock")
        assertEqual (tag ++ ": lock re-owned by taker") (show mine ++ "\n") lockContent
        eLoaded <- storeLoadTokens s1
        loaded <- either (\e -> assertFailure (tag ++ " load after takeover: " ++ show e)) pure eLoaded
        assertEqual (tag ++ ": seeded token survives takeover") 1 (length loaded)
        storeClose s1
    testHeld tag content expectHeld =
      bracket (makeTempDir ("haskoki-storage-held-" ++ tag)) removeDirectoryRecursive $ \dir -> do
        let path = dir </> "store.db"
        e0 <- openSQLiteStore path
        s0 <- either (\e -> assertFailure (tag ++ " seed open: " ++ show e)) pure e0
        storeClose s0
        writeFile (path ++ ".lock") content
        bracket (openFd (path ++ ".lock") ReadOnly defaultFileFlags) closeFd $ \holderFd -> do
          held <- testTryFlock holderFd
          assertBool (tag ++ ": test holder took the kernel lock") held
          e1 <- openSQLiteStore path
          case e1 of
            Right s1 -> do
              storeClose s1
              assertFailure (tag ++ ": takeover succeeded despite held kernel lock (state fork)")
            Left (StoreSecondWriter msg) -> do
              assertBool (tag ++ ": held refusal names " ++ expectHeld ++ ", got: " ++ msg)
                (expectHeld `isInfixOf` msg)
              when (tag == "empty") $
                assertBool ("empty held must not say unreadable, got: " ++ msg)
                  (not ("unreadable" `isInfixOf` msg))
            Left other -> assertFailure (tag ++ ": wrong error for held lock: " ++ show other)
        e2 <- openSQLiteStore path
        s2 <- either (\e -> assertFailure (tag ++ ": takeover after release failed: " ++ show e)) pure e2
        storeClose s2
    testGenuineSecondOpen =
      bracket (makeTempDir "haskoki-storage-second-open") removeDirectoryRecursive $ \dir -> do
        let path = dir </> "store.db"
        e0 <- openSQLiteStore path
        s0 <- either (\e -> assertFailure ("second-open seed: " ++ show e)) pure e0
        e1 <- openSQLiteStore path
        case e1 of
          Right s1 -> do
            storeClose s1
            storeClose s0
            assertFailure "second open in the same process succeeded (state fork)"
          Left (StoreSecondWriter msg) ->
            assertBool ("second open refusal names same process, got: " ++ msg)
              ("already open in this process" `isInfixOf` msg)
          Left other -> do
            storeClose s0
            assertFailure ("second open wrong error: " ++ show other)
        r <- storeCommit s0 emptyDelta
        assertEqual "first owner keeps serving" Committed r
        storeClose s0
        e2 <- openSQLiteStore path
        s2 <- either (\e -> assertFailure ("reopen after close: " ++ show e)) pure e2
        storeClose s2

-- | Fail-closed guard: with @\/proc@ masked (via @HASKOKI_PROC_ROOT@,
-- deterministically empty), a second open against a live owner in
-- ANOTHER process is refused with the unknowable-liveness
-- 'StoreSecondWriter' instead of forking. The owner must be a
-- separate process: a same-process second open is refused by the
-- same-process guard before liveness is ever consulted, so it can
-- never pin the fail-closed path (and its message carries no
-- "unknowable" on either base or patch).
maskedProcRefuses :: IO EnvScope -> IO ()
maskedProcRefuses mkScope =
  bracket (makeTempDir "haskoki-storage-masked") removeDirectoryRecursive $ \dir ->
    bracket (makeTempDir "haskoki-storage-emptyproc") removeDirectoryRecursive $ \emptyProc -> do
      reaped <- newIORef False
      let path = dir </> "store.db"
          doneFile = dir </> "holder.done"
          readyFile = dir </> "holder.ready"
      bracket (spawnHolder mkScope path doneFile readyFile) (releaseHolder reaped) $ \ph -> do
        holderPid <- spawnedPid ph "masked"
        awaitLockOwner path holderPid
        awaitDone readyFile (6000 :: Int)
        withProcRoot mkScope emptyProc $ do
          e2 <- openSQLiteStoreWith True path defaultLimits noFaults
          case e2 of
            Right s2 -> do
              storeClose s2
              assertFailure "masked: second open succeeded with liveness unknowable (state fork)"
            Left (StoreSecondWriter msg) ->
              assertBool ("masked: expected unknowable-liveness refusal, got: " ++ msg)
                ("unknowable" `isInfixOf` msg)
            Left other ->
              assertFailure ("masked: wrong error for unknowable liveness: " ++ show other)
        writeFile doneFile "done\n"
        awaitHolderExit reaped ph "masked"
        e3 <- openSQLiteStore path
        s3 <- either (\e -> assertFailure ("masked reopen after close: " ++ show e)) pure e3
        storeClose s3

-- | Unlink guard: deleting a live owner's lock path must not let
-- a second opener take over by creating and flocking a different
-- inode — exclusion is anchored to the database identity as well
-- as the sidecar, so the replacement lock's sidecar flock
-- succeeding still refuses at the database guard.
testUnlinkRefuses :: IO EnvScope -> IO ()
testUnlinkRefuses mkScope =
  bracket (makeTempDir "haskoki-storage-unlink") removeDirectoryRecursive $ \dir -> do
    reaped <- newIORef False
    let path = dir </> "store.db"
        lockPath = path ++ ".lock"
        doneFile = dir </> "holder.done"
        readyFile = dir </> "holder.ready"
    bracket (spawnHolder mkScope path doneFile readyFile) (releaseHolder reaped) $ \ph -> do
      holderPid <- spawnedPid ph "unlink"
      awaitLockOwner path holderPid
      awaitDone readyFile (6000 :: Int)
      removeFile lockPath
      e2 <- openSQLiteStore path
      case e2 of
        Right s2 -> do
          storeClose s2
          assertFailure "unlink: second open took over after lock deletion (state fork)"
        Left (StoreSecondWriter msg) ->
          assertBool ("unlink: expected database-anchored refusal, got: " ++ msg)
            ("database" `isInfixOf` msg)
        Left other ->
          assertFailure ("unlink: wrong error after lock deletion: " ++ show other)
      writeFile doneFile "done\n"
      awaitHolderExit reaped ph "unlink"

-- | Owned-inode release: a replacement lock planted at the path
-- after a live owner's lock was deleted is NOT the owner's, so
-- the owner's close must leave it byte-identical (unlink only the
-- owned inode).
testCloseKeepsReplacement :: IO EnvScope -> IO ()
testCloseKeepsReplacement mkScope =
  bracket (makeTempDir "haskoki-storage-replace") removeDirectoryRecursive $ \dir -> do
    reaped <- newIORef False
    let path = dir </> "store.db"
        lockPath = path ++ ".lock"
        doneFile = dir </> "holder.done"
        readyFile = dir </> "holder.ready"
    bracket (spawnHolder mkScope path doneFile readyFile) (releaseHolder reaped) $ \ph -> do
      holderPid <- spawnedPid ph "replace"
      awaitLockOwner path holderPid
      awaitDone readyFile (6000 :: Int)
      removeFile lockPath
      writeFile lockPath "replacement-marker\n"
      writeFile doneFile "done\n"
      awaitHolderExit reaped ph "replace"
      content <- readFile lockPath
      assertEqual "replace: owner close deleted a replacement lock"
        "replacement-marker\n" content
