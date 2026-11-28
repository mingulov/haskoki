{- | Store proc and pause seam cases.
-}
{-# LANGUAGE OverloadedStrings #-}
module Store.Seams
  ( closeReconciledResult
  , closeStdResult
  , closeStoreResult
  , forkOpener
  , spawnHolderEnv
  , testCancelledOpenRetriesClose
  , testFreshGuardBeforeInit
  , testGoHandshakeFilePolls
  , testGoHandshakePolls
  , testKillDuringDbRetry
  , testKillDuringJoinPropagates
  , testKillDuringReleaseKeepsWorkers
  , testKillDuringReleaseRestoresEnv
  , testLivenessMapping
  , testPauseBindsToIntendedOpener
  , testPauseDirectWaitsOnLoop
  , testPauseGoPresentProceeds
  , testPauseInertWithoutOptIn
  , testPidZeroTakeable
  , testProcPartialMaskRefuses
  , testProcRootHonoredWithOptIn
  , testProcRootInertWithoutOptIn
  , testProcUnreadableRefuses
  , testReconciledHonorsOptIn
  , testReserveDeathGap
  , testSelectiveHideRefuses
  , testServingOpenHonorsPauseSeam
  , testServingOpenInertByDefault
  , testServingOpenNoGoCompletesAtCap
  , testServingOpenResumesPromptly
  , testServingOpenWaitsForGo
  , testSwappedDbAborts
  , testWedgedCloserAbandoned
  , withOpenPause
  ) where

import Control.Concurrent (forkFinally, forkIO, killThread, myThreadId, threadDelay)
import Control.Concurrent.MVar (MVar, newEmptyMVar, putMVar, readMVar, takeMVar, tryPutMVar, tryReadMVar, tryTakeMVar)
import Control.Exception (AsyncException (ThreadKilled), SomeException, bracket, bracket_, finally, fromException, mask_, onException, try, uninterruptibleMask_)
import Control.Monad (unless, when)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BC8
import Data.IORef (atomicModifyIORef', modifyIORef', newIORef, readIORef, writeIORef)
import GHC.Clock (getMonotonicTime)
import Data.List (isInfixOf)
import Data.Word (Word64)
import System.Directory (createDirectoryIfMissing, doesFileExist, removeDirectoryRecursive, removeFile, renameFile)
import System.Environment (getExecutablePath, lookupEnv, setEnv)
import System.FilePath ( (</>))
import System.IO.Error (catchIOError)
import System.Posix.Files (createSymbolicLink)
import System.Posix.IO (OpenMode (..), closeFd, defaultFileFlags, openFd)
import System.Posix.Process (getParentProcessID, getProcessID)
import System.Posix.Signals (sigKILL, signalProcess)
import System.Process (CreateProcess (..), ProcessHandle, createProcess, proc)
import System.Timeout (timeout)
import Test.Tasty.HUnit (assertBool, assertEqual, assertFailure)
import Haskoki.Runtime.Storage
  ( CommitResult (..)
  , FaultInjector (..)
  , FaultPoint (..)
  , JobRecord (..)
  , Store (..)
  , StoreDelta (..)
  , StoreError (..)
  , TokenRecord (..)
  , defaultLimits
  , emptyDelta
  , noFaults
  , scriptedFaults
  )
import StoreFixtures
  ( EnvScope, awaitHolderExit, claimReap, closeAcquired
  , makeTempDir, openReconciled
  , reapedPid, releaseHolder, spawnedPid, waitBounded, withFileMode
  )
import Haskoki.FFI.Standard
  ( StdStore (..)
  , StdStoreError (..)
  , openStdStore
  , openStdStoreWith
  )
import Haskoki.Runtime.Config
  ( Config (..)
  , StorageCfg (..)
  , StorageKind (..)
  , defaultConfig
  )
import Haskoki.Runtime.Lifecycle (newEnv, rulesFromConfig)
import Haskoki.Runtime.Storage.SQLite (PidLiveness (..), ProcProbe (..), livenessFromProbes, openSQLiteStore, openSQLiteStoreWith, pauseForFreshCreate, waitForGoFile, waitForPoll)
import Store.Fixtures

-- | Spawn a holder child with extra environment entries (merged
-- over the suite's frozen environment snapshot for the child only):
-- mode switches travel here so concurrent holders never observe a
-- process-wide mutation, and the snapshot (taken once before any
-- test runs) never races a concurrent restore the way a live
-- 'getEnvironment' would.
spawnHolderEnv :: IO EnvScope -> [(String, String)] -> FilePath -> FilePath -> FilePath -> IO ProcessHandle
spawnHolderEnv mkScope extra path doneFile readyFile = do
  (_, _, frozenEnv) <- mkScope
  exe <- getExecutablePath
  let merged = extra ++ [(k, v) | (k, v) <- frozenEnv, k `notElem` map fst extra]
  (_, _, _, ph) <- createProcess
    ((proc exe ["--holder", path, doneFile, readyFile])
      { close_fds = True, env = Just merged })
  pure ph

-- | Fork a one-shot opener worker tracked in the scope's registry.
-- The worker's result lands in the returned 'MVar' exactly as with
-- a raw fork; the difference is lifetime: the arming helpers reap
-- every tracked worker (kill, bounded join, drain of an unconsumed
-- successful open through @closer@) before restoring the env, so a
-- timed-out test never leaves an orphaned opener behind to read the
-- next test's armed variables — and never leaks an unconsumed open.
forkOpener :: IO EnvScope -> (e -> IO ()) -> IO e -> IO (MVar e)
forkOpener mkScope closer open = do
  (_, reg, _) <- mkScope
  resVar <- newEmptyMVar
  doneVar <- newEmptyMVar
  mask_ $ do
    me <- myThreadId
    tid <- forkIO ((open >>= \e -> tryPutMVar resVar e >> pure ()) `finally` putMVar doneVar ())
    atomicModifyIORef' reg (\w -> ((me, tid, doneVar, drain resVar) : w, ()))
  pure resVar
  where
    -- A closer failure puts the result back so a later reap can
    -- retry the close (SQLite retries a failed close for real);
    -- without the put-back a failed close would silently drop a
    -- handle the backend deliberately retained.
    drain var = do
      mRes <- tryTakeMVar var
      case mRes of
        Just e -> closer e `onException` (tryPutMVar var e >> pure ())
        Nothing -> pure ()

-- | Closer for a raw store open result: releases a successful
-- open, ignores failures (nothing to release).
closeStoreResult :: Either StoreError Store -> IO ()
closeStoreResult (Right s) = storeClose s
closeStoreResult (Left _) = pure ()

-- | Closer for a serving-open result: releases the acquired store,
-- ignores failures (nothing to release).
closeStdResult :: Either StdStoreError (Maybe StdStore) -> IO ()
closeStdResult (Right mss) = closeAcquired mss
closeStdResult (Left _) = pure ()

-- | Closer for a reconciliation-fixture open result.
closeReconciledResult :: Either StdStoreError (Maybe StdStore) -> IO ()
closeReconciledResult (Right mss) = closeAcquired mss
closeReconciledResult (Left _) = pure ()

-- | Reap the calling test's tracked workers, failing on problems.
reapOwnWorkers :: IO EnvScope -> IO ()
reapOwnWorkers mkScope = do
  (_, reg, _) <- mkScope
  me <- myThreadId
  problems <- reapSelected (Just me) reg
  unless (null problems) (assertFailure (unlines problems))

-- | Run with @HASKOKI_OPEN_PAUSE@ (pause directory) and
-- @HASKOKI_OPEN_PAUSE_PATH@ (intended opener's database path)
-- overridden, restoring both afterwards. The path binding keeps
-- unrelated parallel SQLite creators from pausing on our handshake.
-- Inherited values are saved and restored like above; mutual
-- exclusion comes from 'withEnvGate' at registration. Both
-- variables are acquired up front so the release reaps workers
-- before restoring EITHER variable — no worker is ever resumed
-- between the two restores.
withOpenPause :: IO EnvScope -> FilePath -> FilePath -> IO a -> IO a
withOpenPause mkScope dir want action =
  bracket
    (do prevDir <- lookupEnv "HASKOKI_OPEN_PAUSE"
        prevWant <- lookupEnv "HASKOKI_OPEN_PAUSE_PATH"
        setEnv "HASKOKI_OPEN_PAUSE" dir
        -- A throwing second setter must not leave the first half
        -- installed (bracket release would never run for it).
        setEnv "HASKOKI_OPEN_PAUSE_PATH" want `onException` restoreEnv "HASKOKI_OPEN_PAUSE" prevDir
        pure (prevDir, prevWant))
    (\(prevDir, prevWant) -> reapThenRestore mkScope $ do
        restoreEnv "HASKOKI_OPEN_PAUSE" prevDir
        restoreEnv "HASKOKI_OPEN_PAUSE_PATH" prevWant)
    (\_ -> action)

-- | Probe-error guard: a @\/proc@ root the opener cannot read
-- (@EACCES@) defers to the kernel lock — a held lock fails closed
-- with a clean 'StoreSecondWriter' (never an uncaught
-- 'IOException'), while a free lock is taken over (no holder to
-- fork with, even though death cannot be proven).
testProcUnreadableRefuses :: IO EnvScope -> IO ()
testProcUnreadableRefuses mkScope =
  bracket (makeTempDir "haskoki-storage-noproc") removeDirectoryRecursive $ \dir ->
    bracket (makeTempDir "haskoki-storage-denied") removeDirectoryRecursive $ \denied -> do
      let path = dir </> "store.db"
      e0 <- openSQLiteStoreWith True path defaultLimits noFaults
      s0 <- either (\e -> assertFailure ("noproc seed open: " ++ show e)) pure e0
      storeClose s0
      deadPid <- reapedPid mkScope
      writeFile (path ++ ".lock") (show deadPid ++ "\n")
      withFileMode denied 0o000 $
        withProcRoot mkScope denied $ do
          bracket (openFd (path ++ ".lock") ReadOnly defaultFileFlags) closeFd $ \holderFd -> do
            held <- testTryFlock holderFd
            assertBool "noproc: test holder took the kernel lock" held
            e1 <- openSQLiteStoreWith True path defaultLimits noFaults
            case e1 of
              Right s1 -> do
                storeClose s1
                assertFailure "noproc: takeover succeeded with liveness unknowable and the lock held (state fork)"
              Left (StoreSecondWriter msg) ->
                assertBool ("noproc: expected unknowable-liveness refusal, got: " ++ msg)
                  ("unknowable" `isInfixOf` msg)
              Left other ->
                assertFailure ("noproc: wrong error for unreadable proc: " ++ show other)
          e2 <- openSQLiteStoreWith True path defaultLimits noFaults
          s2 <- either (\e -> assertFailure ("noproc: takeover with free lock failed: " ++ show e)) pure e2
          me <- getProcessID
          readFile (path ++ ".lock") >>= assertEqual "noproc: lock re-owned" (show me ++ "\n")
          storeClose s2
          e3 <- openSQLiteStoreWith True path defaultLimits noFaults
          s3 <- either (\e -> assertFailure ("noproc: reopen after close: " ++ show e)) pure e3
          storeClose s3

-- | Partial-mask guard: a @\/proc@ view that shows @self@ but
-- hides our own pid, or whose owner entry ERRORS on stat (a
-- self-loop symlink: ELOOP for every runner, root included),
-- cannot prove death — so a second open against a live owner is
-- refused as unknowable, never misread as dead.
testProcPartialMaskRefuses :: IO EnvScope -> IO ()
testProcPartialMaskRefuses mkScope =
  bracket (makeTempDir "haskoki-storage-pmask") removeDirectoryRecursive $ \dir ->
    bracket (makeTempDir "haskoki-storage-fakeproc") removeDirectoryRecursive $ \fakeProc -> do
      reaped <- newIORef False
      me <- getProcessID
      ppid <- getParentProcessID
      let path = dir </> "store.db"
          doneFile = dir </> "holder.done"
          readyFile = dir </> "holder.ready"
      bracket (spawnHolder mkScope path doneFile readyFile) (releaseHolder reaped) $ \ph -> do
        holderPid <- spawnedPid ph "pmask"
        awaitLockOwner path holderPid
        awaitDone readyFile (6000 :: Int)
        writeFile (fakeProc </> "self") ""
        withProcRoot mkScope fakeProc $ do
          e1 <- openSQLiteStoreWith True path defaultLimits noFaults
          case e1 of
            Right s1 -> do
              storeClose s1
              assertFailure "pmask: second open succeeded with a partial proc view (state fork)"
            Left (StoreSecondWriter msg) ->
              assertBool ("pmask: expected unknowable-liveness refusal, got: " ++ msg)
                ("unknowable" `isInfixOf` msg)
            Left other ->
              assertFailure ("pmask: wrong error for partial proc view: " ++ show other)
        writeFile (fakeProc </> show me) ""
        -- The parent witness must be present so phase 2 still pins
        -- the owner-entry error (not the parent's absence).
        writeFile (fakeProc </> show ppid) ""
        -- The owner entry must ERROR on stat (not merely be absent)
        -- while self+own-pid stay visible. A self-loop symlink stats
        -- as ELOOP for every runner; a chmod-000 construction would
        -- be bypassed as root (CI runs as root), misreading the live
        -- owner as dead.
        createSymbolicLink (show holderPid) (fakeProc </> show holderPid)
        withProcRoot mkScope fakeProc $ do
          e2 <- openSQLiteStoreWith True path defaultLimits noFaults
          case e2 of
            Right s2 -> do
              storeClose s2
              assertFailure "pmask: second open succeeded with owner entry denied (state fork)"
            Left (StoreSecondWriter msg) ->
              assertBool ("pmask: expected unknowable-liveness refusal, got: " ++ msg)
                ("unknowable" `isInfixOf` msg)
            Left other ->
              assertFailure ("pmask: wrong error for denied owner entry: " ++ show other)
        writeFile doneFile "done\n"
        awaitHolderExit reaped ph "pmask"
        e3 <- openSQLiteStoreWith True path defaultLimits noFaults
        s3 <- either (\e -> assertFailure ("pmask reopen after close: " ++ show e)) pure e3
        storeClose s3

-- | Fresh-guard test (finding 1): the database guard is held before
-- any SQLite work on the fresh-create path. A is forked and pauses
-- after creating+guarding the database (via @HASKOKI_OPEN_PAUSE@);
-- its sidecar is deleted (the finding's interleaving); B's open
-- must refuse at the database guard — never take over — and A's
-- resume must complete harmlessly. Then A owns alone and the store
-- reopens cleanly. In-process threads contend on @flock@ exactly
-- like processes (separate opens), so no spawn is needed.
testFreshGuardBeforeInit :: IO EnvScope -> IO ()
testFreshGuardBeforeInit mkScope =
  bracket (makeTempDir "haskoki-storage-freshg") removeDirectoryRecursive $ \dir ->
    bracket (makeTempDir "haskoki-storage-pause") removeDirectoryRecursive $ \pauseDir -> do
      let path = dir </> "store.db"
          lockPath = path ++ ".lock"
          pausedFile = pauseDir </> "paused"
          goFile = pauseDir </> "go"
      withOpenPause mkScope pauseDir path $ do
        resVar <- forkOpener mkScope closeStoreResult (openSQLiteStoreWith True path defaultLimits noFaults)
        awaitDone pausedFile (300 :: Int)
        paused <- doesFileExist pausedFile
        assertBool "freshg: opener did not pause (seam not honored?)" paused
        -- The interleaving: A loses its sidecar while paused.
        removeFile lockPath
        e2 <- openSQLiteStoreWith True path defaultLimits noFaults
        case e2 of
          Right s2 -> do
            storeClose s2
            assertFailure "freshg: second open took over a paused fresh init (state fork)"
          Left (StoreSecondWriter msg) ->
            assertBool ("freshg: expected database-anchored refusal, got: " ++ msg)
              ("database" `isInfixOf` msg)
          Left other ->
            assertFailure ("freshg: wrong error during paused fresh init: " ++ show other)
        writeFile goFile "go\n"
        -- Peek, don't take: the result stays registered for the
        -- reap drain, which owns the single close. The eager close
        -- below is still needed (the reopen requires the lock
        -- released); the drain's later close of the same handle is
        -- a no-op on the closed handle.
        mA <- timeout (30 * 1000000) (readMVar resVar)
        eA <- case mA of
          Nothing -> assertFailure "freshg: paused opener wedged after release"
          Just e -> pure e
        sA <- either (\e -> assertFailure ("freshg: paused opener failed: " ++ show e)) pure eA
        storeClose sA
        e3 <- openSQLiteStoreWith True path defaultLimits noFaults
        s3 <- either (\e -> assertFailure ("freshg reopen after close: " ++ show e)) pure e3
        eLoaded <- storeLoadTokens s3
        _ <- either (\e -> assertFailure ("freshg load after close: " ++ show e)) pure eLoaded
        storeClose s3

-- | Swap-abort test (finding 1): if the database path no longer
-- names the guarded inode when SQLite opens it, the open aborts
-- with "replaced" instead of initializing another file — and the
-- planted file is left byte-identical. (The planted store is
-- created outside the pause env: it must not pause itself.)
testSwappedDbAborts :: IO EnvScope -> IO ()
testSwappedDbAborts mkScope =
  bracket (makeTempDir "haskoki-storage-swap") removeDirectoryRecursive $ \dir ->
    bracket (makeTempDir "haskoki-storage-pause") removeDirectoryRecursive $ \pauseDir -> do
      let path = dir </> "store.db"
          plantSrc = dir </> "plant.db"
          movedAside = dir </> "moved-aside.db"
          pausedFile = pauseDir </> "paused"
          goFile = pauseDir </> "go"
      ePlant <- openSQLiteStore plantSrc
      plant <- either (\e -> assertFailure ("swap plant open: " ++ show e)) pure ePlant
      _ <- seedStore plant
      storeClose plant
      plantBytes <- BS.readFile plantSrc
      withOpenPause mkScope pauseDir path $ do
        resVar <- forkOpener mkScope closeStoreResult (openSQLiteStoreWith True path defaultLimits noFaults)
        awaitDone pausedFile (300 :: Int)
        paused <- doesFileExist pausedFile
        assertBool "swap: opener did not pause (seam not honored?)" paused
        renameFile path movedAside
        renameFile plantSrc path
        writeFile goFile "go\n"
        mA <- timeout (30 * 1000000) (readMVar resVar)
        eA <- case mA of
          Nothing -> assertFailure "swap: paused opener wedged after release"
          Just e -> pure e
        case eA of
          Right _ -> assertFailure "swap: opener initialized a swapped-in database"
          Left (StoreIO msg) ->
            assertBool ("swap: expected replaced-database refusal, got: " ++ msg)
              ("replaced" `isInfixOf` msg)
          Left other ->
            assertFailure ("swap: wrong error for swapped database: " ++ show other)
        afterBytes <- BS.readFile path
        assertEqual "swap: planted database modified" plantBytes afterBytes
        aside <- doesFileExist movedAside
        assertBool "swap: paused opener's file went missing" aside
        e3 <- openSQLiteStoreWith True path defaultLimits noFaults
        s3 <- either (\e -> assertFailure ("swap reopen planted: " ++ show e)) pure e3
        eLoaded <- storeLoadTokens s3
        loaded <- either (\e -> assertFailure ("swap load planted: " ++ show e)) pure eLoaded
        assertEqual "swap: planted token survives" 1 (length loaded)
        storeClose s3

-- | Async-cleanup test (finding 2): killing a thread blocked in the
-- database-guard retry (flock-retry delays are interruptible even
-- under mask) must release the already-owned sidecar — never
-- strand a live-pid lock that wedges later opens. The parent holds
-- the database flock, so the opener retries over ~45ms; a kill is
-- attempted ~10ms after observing ownership. The observer also
-- checks completion, since scheduling can hide the short-lived
-- sidecar. A missed kill still asserts the clean end-state; the
-- hit counter requires at least one actual ThreadKilled outcome.
testKillDuringDbRetry :: IO EnvScope -> IO ()
testKillDuringDbRetry mkScope =
  bracket (makeTempDir "haskoki-storage-killr") removeDirectoryRecursive $ \dir -> do
    let path = dir </> "store.db"
        lockPath = path ++ ".lock"
    e0 <- openSQLiteStore path
    s0 <- either (\e -> assertFailure ("killr seed open: " ++ show e)) pure e0
    storeClose s0
    me <- getProcessID
    hits <- newIORef (0 :: Int)
    let awaitOwnPid resVar = do
          let want = BC8.pack (show me ++ "\n")
              go = do
                completed <- tryReadMVar resVar
                case completed of
                  Just _ -> pure False
                  Nothing -> do
                    content <- catchIOError (BS.readFile lockPath) (\_ -> pure BS.empty)
                    if content == want then pure True else threadDelay 1000 >> go
          mOk <- timeout 10000000 go
          case mOk of
            Just observed -> pure observed
            Nothing -> assertFailure "killr: opener neither published ownership nor completed"
        loop 0 = pure ()
        loop n = do
          deadPid <- reapedPid mkScope
          writeFile lockPath (show deadPid ++ "\n")
          bracket (openFd path ReadOnly defaultFileFlags) closeFd $ \holdFd -> do
            held <- testTryFlock holdFd
            assertBool "killr: parent could not hold the database flock" held
            resVar <- newEmptyMVar
            bracket
              (forkFinally
                (do e <- openSQLiteStore path
                    case e of
                      Right s -> storeClose s
                      Left _ -> pure ())
                (putMVar resVar))
              (\tid -> do
                  stopped <- timeout (5 * 1000000) (killThread tid >> readMVar resVar)
                  case stopped of
                    Just _ -> pure ()
                    Nothing -> assertFailure "killr: retry worker did not finish during cleanup")
              $ \tid -> do
                observed <- awaitOwnPid resVar
                when observed $ do
                  threadDelay 10000
                  killThread tid
                mOut <- timeout (5 * 1000000) (readMVar resVar)
                case mOut of
                  Nothing -> assertFailure "killr: opener wedged after kill"
                  Just (Left err)
                    | observed && fromException err == Just ThreadKilled ->
                        atomicModifyIORef' hits (\h -> (h + 1, ()))
                    | otherwise -> assertFailure ("killr: unexpected opener exception: " ++ show err)
                  Just (Right ()) -> pure ()
          absent <- not <$> doesFileExist lockPath
          assertBool "killr: kill stranded the sidecar lock" absent
          eRe <- openSQLiteStore path
          sRe <- either (\e -> assertFailure ("killr: reopen wedged after kill: " ++ show e)) pure eRe
          storeClose sRe
          loop (n - 1)
    loop (20 :: Int)
    nHits <- readIORef hits
    assertBool "killr: no mid-window kill observed (vacuous?)" (nHits >= 1)

-- | Selective-hiding test (finding 3): a @\/proc@ view showing
-- @self@ and our own pid but hiding the live owner's entry with
-- @ENOENT@ cannot prove death — the parent witness (always a live
-- process) is absent, so the open refuses as unknowable. A
-- surgical filter hiding ONLY the owner is
-- @\/proc@-indistinguishable from a dead owner and falls through
-- to the kernel-lock backstop, which still refuses.
testSelectiveHideRefuses :: IO EnvScope -> IO ()
testSelectiveHideRefuses mkScope =
  bracket (makeTempDir "haskoki-storage-selhide") removeDirectoryRecursive $ \dir ->
    bracket (makeTempDir "haskoki-storage-fakeproc") removeDirectoryRecursive $ \fakeProc -> do
      reaped <- newIORef False
      me <- getProcessID
      ppid <- getParentProcessID
      let path = dir </> "store.db"
          doneFile = dir </> "holder.done"
          readyFile = dir </> "holder.ready"
      bracket (spawnHolder mkScope path doneFile readyFile) (releaseHolder reaped) $ \ph -> do
        holderPid <- spawnedPid ph "selhide"
        awaitLockOwner path holderPid
        awaitDone readyFile (6000 :: Int)
        -- Phase A: self + own pid visible, live owner hidden
        -- (ENOENT), parent witness absent -> unknowable.
        writeFile (fakeProc </> "self") ""
        writeFile (fakeProc </> show me) ""
        withProcRoot mkScope fakeProc $ do
          e1 <- openSQLiteStoreWith True path defaultLimits noFaults
          case e1 of
            Right s1 -> do
              storeClose s1
              assertFailure "selhide: second open succeeded with owner hidden (state fork)"
            Left (StoreSecondWriter msg) ->
              assertBool ("selhide: expected unknowable-liveness refusal, got: " ++ msg)
                ("unknowable" `isInfixOf` msg)
            Left other ->
              assertFailure ("selhide: wrong error for hidden owner: " ++ show other)
        -- Phase B: the surgical residual — parent witness present,
        -- only the live owner hidden -> takeover attempted, kernel
        -- lock backstop refuses.
        writeFile (fakeProc </> show ppid) ""
        withProcRoot mkScope fakeProc $ do
          e2 <- openSQLiteStoreWith True path defaultLimits noFaults
          case e2 of
            Right s2 -> do
              storeClose s2
              assertFailure "selhide: second open took over a live owner (state fork)"
            Left (StoreSecondWriter msg) ->
              assertBool ("selhide: expected kernel-lock refusal, got: " ++ msg)
                ("kernel lock held" `isInfixOf` msg)
            Left other ->
              assertFailure ("selhide: wrong error for surgical hiding: " ++ show other)
        writeFile doneFile "done\n"
        awaitHolderExit reaped ph "selhide"
        e3 <- openSQLiteStore path
        s3 <- either (\e -> assertFailure ("selhide reopen after close: " ++ show e)) pure e3
        storeClose s3

-- | Pause-isolation test (finding 3): with the pause seam armed
-- for one intended database path, a fresh-create open of a
-- DIFFERENT path must not pause. (Before path binding, any parallel
-- SQLite creator — contract/commit tests, inherited-env holders —
-- paused on the same handshake file and could satisfy the
-- controller's handshake before the intended opener paused.)
testPauseBindsToIntendedOpener :: IO EnvScope -> IO ()
testPauseBindsToIntendedOpener mkScope =
  bracket (makeTempDir "haskoki-storage-pausebind") removeDirectoryRecursive $ \dir ->
    bracket (makeTempDir "haskoki-storage-pause") removeDirectoryRecursive $ \pauseDir -> do
      let intended = dir </> "intended.db"
          other = dir </> "other.db"
      withOpenPause mkScope pauseDir intended $ do
        resVar <- forkOpener mkScope closeStoreResult (openSQLiteStoreWith True other defaultLimits noFaults)
        mDone <- timeout (5 * 1000000) (readMVar resVar)
        eOther <- case mDone of
          Nothing -> assertFailure "pausebind: unrelated fresh open paused (seam leaked across openers)"
          Just e -> pure e
        case eOther of
          Left e -> assertFailure ("pausebind: unrelated open failed: " ++ show e)
          Right _ -> pure ()
        pausedExists <- doesFileExist (pauseDir </> "paused")
        assertBool "pausebind: pause seam fired for an unintended opener" (not pausedExists)
        resVar2 <- forkOpener mkScope closeStoreResult (openSQLiteStoreWith True intended defaultLimits noFaults)
        let awaitPaused 0 = assertFailure "pausebind: intended open did not pause (binding broken)"
            awaitPaused n = do
              here <- doesFileExist (pauseDir </> "paused")
              if here then pure () else threadDelay 100000 >> awaitPaused (n - 1 :: Int)
        awaitPaused (50 :: Int)
        -- Blocked proof: the opener must still be waiting at 0.5s,
        -- 1.5s and 2.5s with no go file present. (A seam that wrote
        -- `paused` and returned on any shorter idle — including a
        -- three-second unconditional delay in place of the go loop —
        -- would have published by the fourth sample.) The go handshake
        -- must then release it within 5s: the production seam polls
        -- every 10ms, so an ignored or missing go file reads as a
        -- poll-cap timeout instead.
        -- A completed open here means the seam never fired: fail
        -- without consuming it (a peek, not a take), so the reap
        -- drain still owns the single close at teardown.
        let stillWaiting tag = do
              early <- tryReadMVar resVar2
              case early of
                Just _ -> assertFailure ("pausebind: intended open completed without the go file (" ++ tag ++ ")")
                Nothing -> pure ()
        threadDelay 500000 >> stillWaiting "0.5s sample"
        threadDelay 1000000 >> stillWaiting "1.5s sample"
        threadDelay 1000000 >> stillWaiting "2.5s sample"
        threadDelay 1000000 >> stillWaiting "3.5s sample"
        writeFile (pauseDir </> "go") "go\n"
        mIntended <- timeout (5 * 1000000) (readMVar resVar2)
        eIntended <- case mIntended of
          Nothing -> assertFailure "pausebind: intended open did not resume on go file"
          Just e -> pure e
        case eIntended of
          Left e -> assertFailure ("pausebind: intended open failed: " ++ show e)
          Right _ -> pure ()

-- | Go-handshake unit test: 'waitForPoll' against a scripted probe
-- (no clock, no filesystem, no process-wide env — parallel-safe
-- outside the chain). A probe firing on its third poll returns True
-- after exactly 3 probes, proving the loop keeps polling past its
-- first check: a check-once-then-sleep seam returns False here,
-- while the timing tests alone would pass it. A never-firing probe
-- returns False after exactly the budgeted polls, and a nonpositive
-- budget probes nothing at all.
testGoHandshakePolls :: IO ()
testGoHandshakePolls = do
  scripted <- newIORef [False, False, True]
  scriptedCalls <- newIORef (0 :: Int)
  let scriptedProbe = do
        modifyIORef' scriptedCalls (+1)
        xs <- readIORef scripted
        case xs of
          [] -> pure True
          (b : bs) -> writeIORef scripted bs >> pure b
  (found, nReported) <- waitForPoll scriptedProbe 10
  assertBool "probe firing on third poll not observed (seam stopped polling)" found
  assertEqual "loop reports the firing poll" 3 nReported
  nFired <- readIORef scriptedCalls
  assertEqual "firing probe polled exactly to the firing poll" 3 nFired
  quietCalls <- newIORef (0 :: Int)
  (missing, nQuietReported) <- waitForPoll (modifyIORef' quietCalls (+1) >> pure False) 5
  assertBool "never-firing probe reported present" (not missing)
  assertEqual "loop reports the exhausted budget" 5 nQuietReported
  nQuiet <- readIORef quietCalls
  assertEqual "quiet probe polled exactly the budget" 5 nQuiet
  staleCalls <- newIORef (0 :: Int)
  (exhausted, nStaleReported) <- waitForPoll (modifyIORef' staleCalls (+1) >> pure True) 0
  assertBool "nonpositive budget reported present" (not exhausted)
  assertEqual "nonpositive budget reports zero polls" 0 nStaleReported
  nStale <- readIORef staleCalls
  assertEqual "nonpositive budget probes nothing" 0 nStale
  negCalls <- newIORef (0 :: Int)
  (negExhausted, nNegReported) <- waitForPoll (modifyIORef' negCalls (+1) >> pure True) (-1)
  assertBool "negative budget reported present" (not negExhausted)
  assertEqual "negative budget reports zero polls" 0 nNegReported
  nNeg <- readIORef negCalls
  assertEqual "negative budget probes nothing" 0 nNeg

-- | Go-file composition test: 'waitForGoFile' polls the real
-- filesystem through 'waitForPoll', and the poll count is part of
-- the verdict. A go file landing mid-wait must report (True, n)
-- with n >= 2: a single-check reimplementation reports a count of
-- one and fails here no matter how the test thread is scheduled
-- (it cannot fabricate a second poll it never ran). An absent file
-- must report exactly the budget. The writer announces itself
-- through a @ready@ file and only then sleeps, so the validity
-- gate below (fail loudly on a pre-existing go file) plus the
-- count assertion leave a timing-only adversary no silent pass:
-- any scheduling anomaly fails loudly instead. No process-wide
-- env, so parallel-safe outside the chain.
testGoHandshakeFilePolls :: IO EnvScope -> IO ()
testGoHandshakeFilePolls mkScope =
  bracket (makeTempDir "haskoki-storage-gofilepoll") removeDirectoryRecursive $ \dir ->
    bracket_ (pure ()) (reapOwnWorkers mkScope) $ do
      let goFile = dir </> "go"
          readyFile = dir </> "ready"
      -- Tracked in the shared registry and reaped by the bracket
      -- (a no-op once the writer has fired) so a failing run cannot
      -- strand it writing into the removed scratch directory. It
      -- reads no env and the release only reaps this test's own
      -- entries, so no other test can be affected either way; the
      -- test itself stays ungated as it arms nothing.
      _ <- forkOpener mkScope (\_ -> pure ()) $ do
        writeFile readyFile "ready\n"
        threadDelay 100000
        writeFile goFile "go\n"
      awaitFile readyFile
      -- Validity gate: go must not exist yet. A pre-existing go
      -- file means the environment, not the implementation, is at
      -- fault: fail loudly as a broken test environment instead of
      -- letting a one-shot implementation pass vacuously.
      early <- doesFileExist goFile
      when early (assertFailure "composition: go file already present before the waiter started (scheduling anomaly)")
      (found, nPolls) <- waitForGoFile goFile 100
      assertBool "delayed go file not observed through waitForGoFile" found
      assertBool ("handshake took a single poll: " ++ show nPolls) (nPolls >= 2)
      (missing, nAbsent) <- waitForGoFile (dir </> "absent") 5
      assertBool "absent go file reported present" (not missing)
      assertEqual "absent go file polled exactly the budget" 5 nAbsent
  where
    awaitFile f = do
      mOk <- timeout (5 * 1000000) (awaitFileGo f)
      case mOk of
        Just () -> pure ()
        Nothing -> assertFailure "handshake writer never announced readiness"
    awaitFileGo f = do
      here <- doesFileExist f
      if here then pure () else threadDelay 10000 >> awaitFileGo f

-- | Go-present release: with the @go@ file already in place, an
-- opted-in fresh-create open must still write the @paused@ marker
-- (the seam fires) but complete promptly (within 3s) instead of
-- waiting out the poll cap. A seam that ignores the handshake and
-- idles unconditionally fails here for any idle longer than the
-- bound — the complement of the still-waiting tests, which catch
-- short idles. Together they leave an unconditional-delay seam no
-- delay that passes both.
testPauseGoPresentProceeds :: IO EnvScope -> IO ()
testPauseGoPresentProceeds mkScope =
  bracket (makeTempDir "haskoki-storage-gopresent") removeDirectoryRecursive $ \dir ->
    bracket (makeTempDir "haskoki-storage-gopresentdir") removeDirectoryRecursive $ \pauseDir -> do
      let path = dir </> "store.db"
          pausedFile = pauseDir </> "paused"
      writeFile (pauseDir </> "go") "go\n"
      withOpenPause mkScope pauseDir path $ do
        resVar <- forkOpener mkScope closeStoreResult (openSQLiteStoreWith True path defaultLimits noFaults)
        mDone <- timeout (3 * 1000000) (readMVar resVar)
        eOpen <- case mDone of
          Nothing -> assertFailure "gopresent: open with pre-existing go file did not complete promptly (handshake ignored)"
          Just e -> pure e
        case eOpen of
          Left e -> assertFailure ("gopresent: open failed: " ++ show e)
          Right _ -> pure ()
        paused <- doesFileExist pausedFile
        assertBool "gopresent: pause marker missing (seam never fired)" paused

-- | Direct seam test: 'pauseForFreshCreate' itself waits on the
-- polling loop. A @go@ file landing 0.1s in releases it promptly
-- (within 1s): a seam that checked once and then slept a fixed
-- delay fails here for any sleep longer than the bound, while the
-- still-waiting tests catch shorter sleeps — together they leave a
-- fixed-sleep seam no delay that passes both. No opener thread is
-- involved; the forked writer exits on its own in 0.1s.
testPauseDirectWaitsOnLoop :: IO EnvScope -> IO ()
testPauseDirectWaitsOnLoop mkScope =
  bracket (makeTempDir "haskoki-storage-directpause") removeDirectoryRecursive $ \dir ->
    bracket (makeTempDir "haskoki-storage-directpausedir") removeDirectoryRecursive $ \pauseDir -> do
      let path = dir </> "store.db"
      withOpenPause mkScope pauseDir path $ do
        -- Tracked so a failing run cannot leave it writing into the
        -- removed scratch directory (reaped before restore).
        _ <- forkOpener mkScope (\_ -> pure ()) (threadDelay 100000 >> writeFile (pauseDir </> "go") "go\n")
        mDone <- timeout (1000000) (pauseForFreshCreate True path)
        case mDone of
          Nothing -> assertFailure "directpause: pause did not release on go file within 1s (not waiting on the loop)"
          Just () -> pure ()

-- | Env seams are inert without the explicit opt-in (finding: ambient
-- @HASKOKI_PROC_ROOT@ must not change liveness verdicts). A live
-- holder's lock refuses with the live-owner verdict, never the
-- unknowable one: the real @/proc@ (which reports the holder live)
-- decides, not the env var. (Outside the same-process shortcut —
-- which skips the liveness probe and lets the flock decide: a lock
-- our own open holds refuses as already-open-in-this-process, a free
-- lock naming our pid is taken over (both halves pinned by the
-- stale-lock takeover cases) — liveness is still probed for other
-- named pids; a free, writable lock is taken over (an unwritable
-- sidecar refuses as untakeoverable instead) and the verdict
-- survives only in the refusal message — the flock arbitrates.)
testProcRootInertWithoutOptIn :: IO EnvScope -> IO ()
testProcRootInertWithoutOptIn mkScope =
  bracket (makeTempDir "haskoki-storage-seamoff") removeDirectoryRecursive $ \dir -> do
    reaped <- newIORef False
    let path = dir </> "store.db"
        doneFile = dir </> "holder.done"
        readyFile = dir </> "holder.ready"
        pidFile = dir </> "holder.pid"
    e0 <- openSQLiteStore path
    s0 <- either (\e -> assertFailure ("seamoff seed open: " ++ show e)) pure e0
    _ <- seedStore s0
    storeClose s0
    let childEnv =
          [ ("HASKOKI_HOLDER_MODE", "reserve")
          , ("HASKOKI_HOLDER_PIDFILE", pidFile)
          ]
    bracket (spawnHolderEnv mkScope childEnv path doneFile readyFile) (releaseHolder reaped) $ \ph -> do
      holderPid <- spawnedPid ph "seamoff"
      awaitLockOwner path holderPid
      awaitDone readyFile (6000 :: Int)
      withProcRoot mkScope "/nonexistent-proc-haskoki-test" $ do
        -- The production default surface (the no-Bool wrapper), then
        -- the explicit opt-out: both must refuse with the live-owner
        -- verdict. Going through the wrapper pins the default itself —
        -- flipping the wrapper's default would refuse as unknowable
        -- here and fail this test.
        e1 <- openSQLiteStore path
        case e1 of
          Right s1 -> do
            storeClose s1
            assertFailure "seamoff: default second open succeeded against a live holder (state fork)"
          Left (StoreSecondWriter msg) ->
            assertBool ("seamoff: expected live-owner refusal, got: " ++ msg)
              (("already open by pid " ++ show holderPid) `isInfixOf` msg
               && not ("unknowable" `isInfixOf` msg))
          Left other -> assertFailure ("seamoff: wrong error with bogus proc root: " ++ show other)
        e2 <- openSQLiteStoreWith False path defaultLimits noFaults
        case e2 of
          Right s2 -> do
            storeClose s2
            assertFailure "seamoff: explicit opt-out second open succeeded against a live holder (state fork)"
          Left (StoreSecondWriter msg) ->
            assertBool ("seamoff: expected live-owner refusal, got: " ++ msg)
              (("already open by pid " ++ show holderPid) `isInfixOf` msg
               && not ("unknowable" `isInfixOf` msg))
          Left other -> assertFailure ("seamoff: wrong error with bogus proc root: " ++ show other)
      writeFile doneFile "done\n"
      awaitHolderExit reaped ph "seamoff"

-- | The opt-in restores the seam: same live holder and bogus proc
-- root, but @allowEnvSeams@ on refuses as unknowable.
testProcRootHonoredWithOptIn :: IO EnvScope -> IO ()
testProcRootHonoredWithOptIn mkScope =
  bracket (makeTempDir "haskoki-storage-seamon") removeDirectoryRecursive $ \dir -> do
    reaped <- newIORef False
    let path = dir </> "store.db"
        doneFile = dir </> "holder.done"
        readyFile = dir </> "holder.ready"
        pidFile = dir </> "holder.pid"
    e0 <- openSQLiteStore path
    s0 <- either (\e -> assertFailure ("seamon seed open: " ++ show e)) pure e0
    _ <- seedStore s0
    storeClose s0
    let childEnv =
          [ ("HASKOKI_HOLDER_MODE", "reserve")
          , ("HASKOKI_HOLDER_PIDFILE", pidFile)
          ]
    bracket (spawnHolderEnv mkScope childEnv path doneFile readyFile) (releaseHolder reaped) $ \ph -> do
      holderPid <- spawnedPid ph "seamon"
      awaitLockOwner path holderPid
      awaitDone readyFile (6000 :: Int)
      withProcRoot mkScope "/nonexistent-proc-haskoki-test" $ do
        e1 <- openSQLiteStoreWith True path defaultLimits noFaults
        case e1 of
          Right s1 -> do
            storeClose s1
            assertFailure "seamon: second open succeeded with a bogus proc root under opt-in (expected unknowable refusal)"
          Left (StoreSecondWriter msg) ->
            assertBool ("seamon: expected unknowable-liveness refusal, got: " ++ msg)
              ("unknowable" `isInfixOf` msg)
          Left other -> assertFailure ("seamon: wrong error with bogus proc root under opt-in: " ++ show other)
      writeFile doneFile "done\n"
      awaitHolderExit reaped ph "seamon"

-- | The pause seam is inert without the opt-in: @HASKOKI_OPEN_PAUSE@
-- set, but the default open returns promptly and writes no @paused@
-- file. Both the production default surface (the no-Bool wrapper)
-- and the explicit opt-out are pinned: flipping the wrapper's
-- default would block here and fail this test. (The honored
-- direction is covered by testPauseBindsToIntendedOpener with the
-- opt-in on.)
testPauseInertWithoutOptIn :: IO EnvScope -> IO ()
testPauseInertWithoutOptIn mkScope =
  bracket (makeTempDir "haskoki-storage-seamnopause") removeDirectoryRecursive $ \dir ->
    bracket (makeTempDir "haskoki-storage-seamnopausedir") removeDirectoryRecursive $ \pauseDir -> do
      let pathA = dir </> "store-a.db"
          pathB = dir </> "store-b.db"
          pausedFile = pauseDir </> "paused"
          openPrompt tag open = do
            resVar <- forkOpener mkScope closeStoreResult open
            mDone <- timeout (10 * 1000000) (readMVar resVar)
            eOpen <- case mDone of
              Nothing -> assertFailure (tag ++ ": open blocked without opt-in (pause seam leaked)")
              Just e -> pure e
            case eOpen of
              Left e -> assertFailure (tag ++ ": open failed: " ++ show e)
              Right _ -> pure ()
            paused <- doesFileExist pausedFile
            assertBool (tag ++ ": pause file written without opt-in (seam leaked)") (not paused)
      withOpenPause mkScope pauseDir pathA (openPrompt "seamnopause-default" (openSQLiteStore pathA))
      withOpenPause mkScope pauseDir pathB
        (openPrompt "seamnopause-explicit" (openSQLiteStoreWith False pathB defaultLimits noFaults))

-- | Serving open honors the pause seam under the opt-in: the
-- config-driven serving open (not just the backend direct call)
-- pauses a fresh creation until the @go@ file appears. Dropping
-- the opt-in threading in 'openStdStore' (hardcoding the inert
-- open) fails this test: the open would complete without pausing.
testServingOpenHonorsPauseSeam :: IO EnvScope -> IO ()
testServingOpenHonorsPauseSeam mkScope =
  bracket (makeTempDir "haskoki-storage-servingpause") removeDirectoryRecursive $ \dir ->
    bracket (makeTempDir "haskoki-storage-servingpausedir") removeDirectoryRecursive $ \pauseDir -> do
      let path = dir </> "store.db"
          pausedFile = pauseDir </> "paused"
          goFile = pauseDir </> "go"
          cfg = defaultConfig
            { cfgStorage = StorageCfg StorageSQLite (Just path) 5000 True True
            }
      env <- newEnv (rulesFromConfig cfg)
      withOpenPause mkScope pauseDir path $ do
        resVar <- forkOpener mkScope closeStdResult (openStdStore env cfg)
        let awaitPaused 0 = assertFailure "servingpause: serving open did not pause under opt-in"
            awaitPaused n = do
              here <- doesFileExist pausedFile
              if here then pure () else threadDelay 100000 >> awaitPaused (n - 1 :: Int)
        awaitPaused (100 :: Int)
        -- Still blocked at 0.5s, 1.5s and 2.5s with no go file: a
        -- seam that only wrote `paused` (even after a three-second
        -- unconditional delay in place of the go loop) publishes by
        -- the fourth sample. The go handshake must then release the
        -- serving open within 5s (the seam polls every 10ms);
        -- without the handshake the poll cap, not the go file, would
        -- release it.
        -- A completed open here means the seam never fired: fail
        -- without consuming it (a peek, not a take), so the reap
        -- drain still owns the single close at teardown.
        let stillWaiting tag = do
              early <- tryReadMVar resVar
              case early of
                Just _ -> assertFailure ("servingpause: serving open completed without the go file (" ++ tag ++ ")")
                Nothing -> pure ()
        threadDelay 500000 >> stillWaiting "0.5s sample"
        threadDelay 1000000 >> stillWaiting "1.5s sample"
        threadDelay 1000000 >> stillWaiting "2.5s sample"
        threadDelay 1000000 >> stillWaiting "3.5s sample"
        writeFile goFile "go\n"
        mDone <- timeout (5 * 1000000) (readMVar resVar)
        eAcq <- case mDone of
          Nothing -> assertFailure "servingpause: serving open did not resume on go file"
          Just e -> pure e
        case eAcq of
          Left err -> assertFailure ("servingpause: serving open failed: " ++ show err)
          Right Nothing -> assertFailure "servingpause: serving open returned no store"
          Right (Just _) -> pure ()

-- | Serving open is inert without the opt-in: the pause variables
-- armed, but the config-driven open with 'defaultConfig' (only the
-- kind and path pointed at the scratch sqlite file; the seam flag
-- keeps its default) returns promptly and writes no @paused@ file.
-- Flipping defaultConfig's flag, or hardcoding the opt-in inside
-- 'openStdStore', blocks here and fails this test.
testServingOpenInertByDefault :: IO EnvScope -> IO ()
testServingOpenInertByDefault mkScope =
  bracket (makeTempDir "haskoki-storage-servingoff") removeDirectoryRecursive $ \dir ->
    bracket (makeTempDir "haskoki-storage-servingoffdir") removeDirectoryRecursive $ \pauseDir -> do
      let path = dir </> "store.db"
          pausedFile = pauseDir </> "paused"
          cfg = defaultConfig
            { cfgStorage = (cfgStorage defaultConfig)
              { scKind = StorageSQLite, scPath = Just path }
            }
      env <- newEnv (rulesFromConfig cfg)
      withOpenPause mkScope pauseDir path $ do
        resVar <- forkOpener mkScope closeStdResult (openStdStore env cfg)
        mDone <- timeout (10 * 1000000) (readMVar resVar)
        eAcq <- case mDone of
          Nothing -> assertFailure "servingoff: serving open blocked without opt-in (pause seam leaked)"
          Just e -> pure e
        case eAcq of
          Left err -> assertFailure ("servingoff: serving open failed: " ++ show err)
          Right Nothing -> assertFailure "servingoff: serving open returned no store"
          Right (Just _) -> pure ()
        paused <- doesFileExist pausedFile
        assertBool "servingoff: pause file written without opt-in (seam leaked)" (not paused)

-- | Serving open waits for the go file (finding 4): with the opt-in
-- armed, the open must stay blocked through ~21s of samples with
-- no go file, then resume promptly once go lands at ~22s (within
-- 2s). Sampling this late pins that the seam is STILL POLLING
-- deep into the budget: a call site that stopped polling early
-- (to sleep, then proceed) publishes early or ignores the late
-- go and fails here. Together with the early-go run the pair
-- admits no fixed-sleep seam (disjoint survivor sets — see the
-- companion), and together with the no-go cap run it pins
-- late-budget activity as well as the total budget. Residual:
-- give-up cutoffs past ~22s need a go written even later to
-- catch; each such probe moves the band without closing it —
-- full exactness would need the poll count exposed at the
-- serving level (offered, not built).
testServingOpenWaitsForGo :: IO EnvScope -> IO ()
testServingOpenWaitsForGo mkScope =
  bracket (makeTempDir "haskoki-storage-servingwait") removeDirectoryRecursive $ \dir ->
    bracket (makeTempDir "haskoki-storage-servingwaitdir") removeDirectoryRecursive $ \pauseDir -> do
      let path = dir </> "store.db"
          pausedFile = pauseDir </> "paused"
          goFile = pauseDir </> "go"
          cfg = defaultConfig
            { cfgStorage = StorageCfg StorageSQLite (Just path) 5000 True True
            }
      env <- newEnv (rulesFromConfig cfg)
      withOpenPause mkScope pauseDir path $ do
        resVar <- forkOpener mkScope closeStdResult (openStdStore env cfg)
        let awaitPaused 0 = assertFailure "servingwait: serving open did not pause under opt-in"
            awaitPaused n = do
              here <- doesFileExist pausedFile
              if here then pure () else threadDelay 100000 >> awaitPaused (n - 1 :: Int)
        awaitPaused (100 :: Int)
        -- No go file until ~22s: the uniform 1s samples prove the
        -- seam is still blocked (hence still polling) deep into
        -- the budget — a call site that stopped polling early
        -- publishes early here, and one that went quiet ignores
        -- the late go below and fails the resume. Peek, never
        -- consume: the reap drain still owns the single close at
        -- teardown.
        let stillWaiting tag = do
              early <- tryReadMVar resVar
              case early of
                Just _ -> assertFailure ("servingwait: serving open completed without the go file (" ++ tag ++ ")")
                Nothing -> pure ()
        threadDelay 500000 >> stillWaiting "0.5s sample"
        threadDelay 1000000 >> stillWaiting "1.5s sample"
        threadDelay 1000000 >> stillWaiting "2.5s sample"
        threadDelay 1000000 >> stillWaiting "3.5s sample"
        threadDelay 1000000 >> stillWaiting "4.5s sample"
        threadDelay 1000000 >> stillWaiting "5.5s sample"
        threadDelay 1000000 >> stillWaiting "6.5s sample"
        threadDelay 1000000 >> stillWaiting "7.5s sample"
        threadDelay 1000000 >> stillWaiting "8.5s sample"
        threadDelay 1000000 >> stillWaiting "9.5s sample"
        threadDelay 1000000 >> stillWaiting "10.5s sample"
        threadDelay 1000000 >> stillWaiting "11.5s sample"
        threadDelay 1000000 >> stillWaiting "12.5s sample"
        threadDelay 1000000 >> stillWaiting "13.5s sample"
        threadDelay 1000000 >> stillWaiting "14.5s sample"
        threadDelay 1000000 >> stillWaiting "15.5s sample"
        threadDelay 1000000 >> stillWaiting "16.5s sample"
        threadDelay 1000000 >> stillWaiting "17.5s sample"
        threadDelay 1000000 >> stillWaiting "18.5s sample"
        threadDelay 1000000 >> stillWaiting "19.5s sample"
        threadDelay 1000000 >> stillWaiting "20.5s sample"
        threadDelay 1000000 >> stillWaiting "21.5s sample"
        writeFile goFile "go\n"
        -- Prompt resume after the late go (the poll loop resumes
        -- within ~50ms; 2s is 40x slop for scheduling): a seam
        -- that stopped polling before the go completes late and
        -- fails here.
        mDone <- timeout (2 * 1000000) (readMVar resVar)
        eAcq <- case mDone of
          Nothing -> assertFailure "servingwait: serving open did not resume promptly on late go file"
          Just e -> pure e
        case eAcq of
          Left err -> assertFailure ("servingwait: serving open failed: " ++ show err)
          Right Nothing -> assertFailure "servingwait: serving open returned no store"
          Right (Just _) -> pure ()

-- | Serving open resumes promptly on an early go (finding 4,
-- companion to the waits-for-go run): with the opt-in armed, the
-- go file lands at 0.5s and the open must complete by 2.5s. The
-- two runs' survivor sets are disjoint — a fixed sleep short
-- enough to pass here (<= ~2.4s) fails the late run's 21.5s
-- still-blocked samples, and one long enough to pass there
-- (> ~21.4s) fails here — so together they admit no fixed-sleep
-- seam at all, only implementations that resume promptly on go.
testServingOpenResumesPromptly :: IO EnvScope -> IO ()
testServingOpenResumesPromptly mkScope =
  bracket (makeTempDir "haskoki-storage-servingearly") removeDirectoryRecursive $ \dir ->
    bracket (makeTempDir "haskoki-storage-servingearlydir") removeDirectoryRecursive $ \pauseDir -> do
      let path = dir </> "store.db"
          pausedFile = pauseDir </> "paused"
          goFile = pauseDir </> "go"
          cfg = defaultConfig
            { cfgStorage = StorageCfg StorageSQLite (Just path) 5000 True True
            }
      env <- newEnv (rulesFromConfig cfg)
      withOpenPause mkScope pauseDir path $ do
        resVar <- forkOpener mkScope closeStdResult (openStdStore env cfg)
        let awaitPaused 0 = assertFailure "servingearly: serving open did not pause under opt-in"
            awaitPaused n = do
              here <- doesFileExist pausedFile
              if here then pure () else threadDelay 100000 >> awaitPaused (n - 1 :: Int)
        awaitPaused (100 :: Int)
        threadDelay 500000
        writeFile goFile "go\n"
        -- The poll loop resumes within ~50ms of the go file; 2s is
        -- 40x slop for scheduling. A seam that slept a fixed span
        -- instead of polling completes late and fails here.
        mDone <- timeout (2 * 1000000) (readMVar resVar)
        eAcq <- case mDone of
          Nothing -> assertFailure "servingearly: serving open did not resume promptly on early go file"
          Just e -> pure e
        case eAcq of
          Left err -> assertFailure ("servingearly: serving open failed: " ++ show err)
          Right Nothing -> assertFailure "servingearly: serving open returned no store"
          Right (Just _) -> pure ()

-- | Cancelled open retries a faulted close (finding 2): killing a
-- serving open blocked mid-body (post-acquire) with a one-shot
-- 'FaultClose' armed must still propagate the kill (not the
-- injected close failure), attempt the close exactly twice (the
-- fault spends on the first attempt, the retry closes for real),
-- and release the lock. The block comes from a 'FaultBeforeCommit'
-- probe that signals entry and parks (the commit runs after the
-- store is acquired, so the cleanup owns a live handle); the kill
-- lands there deterministically. The close count pins the retry:
-- a fault that never fired, or a missing retry, reports a count
-- other than two and fails here. Without the real second close
-- the reopen below would see a second writer. The worker runs on
-- a raw fork (not the registry) so the thrown kill is observable;
-- it is joined before the assertions, and no tracked workers remain.
testCancelledOpenRetriesClose :: IO EnvScope -> IO ()
testCancelledOpenRetriesClose _mkScope =
  bracket (makeTempDir "haskoki-storage-cancelretry") removeDirectoryRecursive $ \dir -> do
    let path = dir </> "store.db"
        cfg = defaultConfig
          { cfgStorage = StorageCfg StorageSQLite (Just path) 5000 True False
          }
    env <- newEnv (rulesFromConfig cfg)
    base <- scriptedFaults [FaultClose]
    entered <- newEmptyMVar
    closeCount <- newIORef (0 :: Int)
    never <- newEmptyMVar :: IO (MVar ())
    let inj = base { fiFire = fire }
        fire FaultClose = do
          modifyIORef' closeCount (+1)
          fiFire base FaultClose
        fire FaultBeforeCommit = do
          _ <- tryPutMVar entered ()
          takeMVar never
          pure True
        fire p = fiFire base p
    resVar <- newEmptyMVar :: IO (MVar (Either SomeException (Either StdStoreError (Maybe StdStore))))
    tid <- forkIO (do
      eOpen <- try (openStdStoreWith (\p -> openSQLiteStoreWith False p defaultLimits inj) env cfg)
      putMVar resVar eOpen)
    -- The commit block is post-acquire by construction (the fault
    -- fires inside the seed commit on a live handle); killing
    -- before entry is impossible — entry precedes the kill.
    mEntered <- timeout (15 * 1000000) (takeMVar entered)
    case mEntered of
      Nothing -> assertFailure "cancelretry: open never reached the commit block"
      Just () -> pure ()
    killThread tid
    -- 15s guard: the supervisor bounds cleanup at 10s, so a
    -- correct run joins in milliseconds; only a true hang
    -- trips this.
    mDone <- timeout (15 * 1000000) (takeMVar resVar)
    eOpen <- case mDone of
      Nothing -> assertFailure "cancelretry: killed open never completed its cleanup"
      Just e -> pure e
    case eOpen of
      Left e -> case fromException e of
        Just ThreadKilled -> pure ()
        _ -> assertFailure ("cancelretry: kill replaced by cleanup failure: " ++ show e)
      Right _ -> assertFailure "cancelretry: killed open returned a value"
    nCloses <- readIORef closeCount
    assertEqual "cancelretry: cleanup did not attempt the close twice (retry missing or fault never fired)" 2 nCloses
    -- The retry closed for real: the lock is free for a reopen.
    eRe <- openSQLiteStore path
    case eRe of
      Left err -> assertFailure ("cancelretry: lock still held after retried close: " ++ show err)
      Right sRe -> storeClose sRe

-- | Kill-during-release test (finding 3): a kill landing in the
-- release reap's interruptible join must still restore the armed
-- variables (via 'reapThenRestore') and must still propagate. The
-- controller kills the test thread the moment the gated closer
-- signals entry — at that point the test thread is parked in the
-- drain join (or a microstep before it; both paths run the
-- shielded restore and rethrow identically, so the test is
-- race-free by construction, with no timing assertions). The gate
-- fill runs in 'finally' and the closer's exit is observed, so no
-- path strands the waiter.
testKillDuringReleaseRestoresEnv :: IO EnvScope -> IO ()
testKillDuringReleaseRestoresEnv mkScope =
  bracket (makeTempDir "haskoki-storage-killrelease") removeDirectoryRecursive $ \dir -> do
    let pauseDir = dir </> "pause"
        path = dir </> "store.db"
    createDirectoryIfMissing True pauseDir
    me <- myThreadId
    gate <- newEmptyMVar
    entered <- newEmptyMVar
    exited <- newEmptyMVar
    _resVar <- forkOpener mkScope
      (\(_ :: ()) -> putMVar entered () >> takeMVar gate >> putMVar exited ())
      (pure ())
    _ <- forkIO (takeMVar entered >> killThread me)
    prevDir <- lookupEnv "HASKOKI_OPEN_PAUSE"
    prevWant <- lookupEnv "HASKOKI_OPEN_PAUSE_PATH"
    flip finally (putMVar gate ()) $ do
      eOut <- try (withOpenPause mkScope pauseDir path (pure ()))
      case eOut of
        Left e -> case fromException e of
          Just ThreadKilled -> pure ()
          _ -> assertFailure ("killrelease: release threw instead of rethrowing the kill: " ++ show e)
        Right _ -> assertFailure "killrelease: kill during release did not propagate"
      afterDir <- lookupEnv "HASKOKI_OPEN_PAUSE"
      assertEqual "killrelease: HASKOKI_OPEN_PAUSE left armed by a killed release"
        prevDir afterDir
      afterWant <- lookupEnv "HASKOKI_OPEN_PAUSE_PATH"
      assertEqual "killrelease: HASKOKI_OPEN_PAUSE_PATH left armed by a killed release"
        prevWant afterWant
    mExited <- timeout (5 * 1000000) (takeMVar exited)
    case mExited of
      Nothing -> assertFailure "killrelease: abandoned closer did not exit after the gate fill"
      Just () -> pure ()

-- | Serving open proceeds when go never arrives (finding 4): the
-- documented no-go fallback is "10ms poll, 3000 polls — about 30s
-- wall-clock — then proceed regardless". With the opt-in armed and
-- no go file ever written, the open must stay blocked at 5s (no
-- instant skip, no short sleep), then complete on its own — within
-- 35s of fork (a 3000 -> 30000 typo at the call site would need
-- ~300s and trips the guard), having waited out the budget (over
-- 25s of it: threadDelay never fires early, so the floor proves
-- polling happened. The 3000 lives at the 'pauseForFreshCreate' call
-- site, not in the count-tested helper — this is the only test
-- that pins the call-site value behaviorally. Clock and guard both
-- start at fork (a guard started after the peek would grant ~5s
-- extra and admit a 4000 cap), so the bracket is the full ~30s
-- budget: floor 25 and guard 35 admit the documented value with
-- slop but reject a 2000 cap below and a 4000 cap above.
-- All intervals use the monotonic clock (immune to wall-clock
-- steps).
testServingOpenNoGoCompletesAtCap :: IO EnvScope -> IO ()
testServingOpenNoGoCompletesAtCap mkScope =
  bracket (makeTempDir "haskoki-storage-servingnocap") removeDirectoryRecursive $ \dir ->
    bracket (makeTempDir "haskoki-storage-servingnocapdir") removeDirectoryRecursive $ \pauseDir -> do
      let path = dir </> "store.db"
          pausedFile = pauseDir </> "paused"
          cfg = defaultConfig
            { cfgStorage = StorageCfg StorageSQLite (Just path) 5000 True True
            }
      env <- newEnv (rulesFromConfig cfg)
      withOpenPause mkScope pauseDir path $ do
        -- Clock and guard both start at fork: the 5s peek below
        -- runs concurrently with the first seconds of the poll
        -- budget, so a guard started after the peek would grant
        -- ~5s extra and admit a 4000 cap. The correct ~30s
        -- budget clears 35s with slop; floor 25 rejects a 2000
        -- cap, guard 35 rejects 4000 and above.
        start <- getMonotonicTime
        resVar <- forkOpener mkScope closeStdResult (openStdStore env cfg)
        mDone <- timeout (35 * 1000000) $ do
          let awaitPaused 0 = assertFailure "servingnocap: serving open did not pause under opt-in"
              awaitPaused n = do
                here <- doesFileExist pausedFile
                if here then pure () else threadDelay 100000 >> awaitPaused (n - 1 :: Int)
          awaitPaused (100 :: Int)
          -- Still blocked at 5s with no go file (peek, not take).
          threadDelay 5000000
          early <- tryReadMVar resVar
          case early of
            Just _ -> assertFailure "servingnocap: serving open completed without any go file or cap wait"
            Nothing -> readMVar resVar
        end <- getMonotonicTime
        eAcq <- case mDone of
          Nothing -> assertFailure "servingnocap: serving open buried the no-go fallback (cap larger than documented?)"
          Just e -> pure e
        case eAcq of
          Left err -> assertFailure ("servingnocap: serving open failed after the cap wait: " ++ show err)
          Right Nothing -> assertFailure "servingnocap: serving open returned no store after the cap wait"
          Right (Just _) -> pure ()
        assertBool ("servingnocap: open returned without waiting the cap budget: " ++ show (end - start))
          (end - start > 25)
        -- Exact poll count: the seam must have polled 3000 times,
        -- not fewer with sleeps or backoff in place of polls. Any
        -- structural reworking reports a different total here.
        ePolls <- catchIOError (Right <$> readFile (pauseDir </> "polls")) (pure . Left . show)
        case ePolls of
          Left err -> assertFailure ("servingnocap: polls file unreadable: " ++ err)
          Right raw -> assertEqual "servingnocap: seam did not poll exactly 3000 times"
            "3000" (filter (/= '\n') raw)

-- | Kill-during-release test, multi-worker (finding 3): a kill
-- landing in one worker's drain must not orphan the remaining
-- workers as untracked live handles. Worker A holds a successful
-- SQLite open (result unread); worker B's gated closer signals
-- entry and blocks. Killing the release on entry must still
-- drain A's store (via the abort sweep) before restoring the env
-- and rethrowing: reopening A's database must succeed. A release
-- that drops the unreaped remainder leaves A's lock held and the
-- reopen sees a second writer. The gate fill runs in 'finally'
-- and the abandoned closer's exit is observed, so no path
-- strands the waiter. B's closer first peeks A's result, so the
-- kill provably lands after A completed — a slow A delays the
-- whole choreography instead of passing vacuously (reopen would
-- succeed merely because A never opened).
testKillDuringReleaseKeepsWorkers :: IO EnvScope -> IO ()
testKillDuringReleaseKeepsWorkers mkScope =
  bracket (makeTempDir "haskoki-storage-killrelease2") removeDirectoryRecursive $ \dir -> do
    let pauseDir = dir </> "pause"
        pathA = dir </> "a.db"
        pathB = dir </> "b.db"
    createDirectoryIfMissing True pauseDir
    me <- myThreadId
    gate <- newEmptyMVar
    entered <- newEmptyMVar
    exited <- newEmptyMVar
    resVarA <- forkOpener mkScope closeStoreResult (openSQLiteStore pathA)
    aOk <- newIORef False
    _resB <- forkOpener mkScope
      (\(_ :: ()) -> do
          -- Record whether A actually opened: the kill choreography
          -- below is only meaningful if it did. A failed A must
          -- fail this test loudly, not pass vacuously (reopen would
          -- succeed merely because nothing was ever held).
          eA <- readMVar resVarA
          case eA of
            Right _ -> writeIORef aOk True
            Left _ -> pure ()
          putMVar entered () >> takeMVar gate >> putMVar exited ())
      (pure ())
    _ <- forkIO (takeMVar entered >> killThread me)
    prevDir <- lookupEnv "HASKOKI_OPEN_PAUSE"
    prevWant <- lookupEnv "HASKOKI_OPEN_PAUSE_PATH"
    flip finally (putMVar gate ()) $ do
      eOut <- try (withOpenPause mkScope pauseDir pathB (pure ()))
      case eOut of
        Left e -> case fromException e of
          Just ThreadKilled -> pure ()
          _ -> assertFailure ("killrelease2: release threw instead of rethrowing the kill: " ++ show e)
        Right _ -> assertFailure "killrelease2: kill during release did not propagate"
      ok <- readIORef aOk
      assertBool "killrelease2: worker A never opened (choreography untested)" ok
      afterDir <- lookupEnv "HASKOKI_OPEN_PAUSE"
      assertEqual "killrelease2: HASKOKI_OPEN_PAUSE left armed by a killed release"
        prevDir afterDir
      afterWant <- lookupEnv "HASKOKI_OPEN_PAUSE_PATH"
      assertEqual "killrelease2: HASKOKI_OPEN_PAUSE_PATH left armed by a killed release"
        prevWant afterWant
      -- The abort sweep must have drained worker A: reopening its
      -- database succeeds. A dropped remainder leaves the lock
      -- held and this sees a second writer.
      eRe <- openSQLiteStore pathA
      case eRe of
        Left err -> assertFailure ("killrelease2: first worker orphaned (lock still held): " ++ show err)
        Right sRe -> storeClose sRe
    mExited <- timeout (5 * 1000000) (takeMVar exited)
    case mExited of
      Nothing -> assertFailure "killrelease2: abandoned closer did not exit after the gate fill"
      Just () -> pure ()

-- | Kill-during-join test (finding 3): a kill landing in the
-- release's interruptible join must propagate, not degrade into
-- a retried round — a retry that later succeeds would swallow
-- the kill and return normally. The worker's cancellation
-- finalizer signals entry and parks on a gate; killing the
-- release on entry must surface ThreadKilled (not a normal
-- return) while still restoring the env. The gate is opened
-- after the kill so no path strands the worker.
testKillDuringJoinPropagates :: IO EnvScope -> IO ()
testKillDuringJoinPropagates mkScope =
  bracket (makeTempDir "haskoki-storage-killjoin") removeDirectoryRecursive $ \dir -> do
    let pauseDir = dir </> "pause"
        path = dir </> "b.db"
    createDirectoryIfMissing True pauseDir
    me <- myThreadId
    entered <- newEmptyMVar
    gate <- newEmptyMVar
    opengate <- newEmptyMVar
    _resVar <- forkOpener mkScope (\(_ :: ()) -> pure ())
      (takeMVar opengate `finally` (putMVar entered () >> takeMVar gate))
    _ <- forkIO (takeMVar entered >> killThread me >> putMVar gate ())
    prevDir <- lookupEnv "HASKOKI_OPEN_PAUSE"
    prevWant <- lookupEnv "HASKOKI_OPEN_PAUSE_PATH"
    -- tryPutMVar: the controller normally opens the gate itself;
    -- this only releases a worker stranded by an early failure.
    flip finally (tryPutMVar gate () >> pure ()) $ do
      eOut <- try (withOpenPause mkScope pauseDir path (pure ()))
      case eOut of
        Left e -> case fromException e of
          Just ThreadKilled -> pure ()
          _ -> assertFailure ("killjoin: release threw instead of rethrowing the kill: " ++ show e)
        Right _ -> assertFailure "killjoin: kill during join was swallowed (release returned normally)"
      afterDir <- lookupEnv "HASKOKI_OPEN_PAUSE"
      assertEqual "killjoin: HASKOKI_OPEN_PAUSE left armed by a killed release"
        prevDir afterDir
      afterWant <- lookupEnv "HASKOKI_OPEN_PAUSE_PATH"
      assertEqual "killjoin: HASKOKI_OPEN_PAUSE_PATH left armed by a killed release"
        prevWant afterWant

-- | Wedged-closer test (finding 3): a closer that blocks on a gate
-- the controller never fills must not stall the release past the
-- 10s drain bound — and the abandonment must be reported loudly,
-- not swallowed. The closer waits UNINTERRUPTIBLY: an inline
-- @timeout@-around-@drain@ reimplementation cannot cancel it and
-- hangs into the 60s guard, so this test distinguishes the
-- fork+abandon drain from that weaker shape. The opener completes
-- immediately so the drain really invokes the closer (an empty
-- result would take the no-op path and the report assertion below
-- would fail). Without any bound the reap would hang forever and
-- the 60s guard would fire; with fork+abandon the reap returns in
-- ~10s carrying the timeout report. The report string is only
-- produced by the timeout's 'Nothing' branch, so its presence
-- proves the full bound was waited, not skipped; the 5s elapsed
-- floor pins the constant against a regress to a zero bound, and
-- the 20s ceiling pins it from above (a 30s-timeout regress would
-- return at ~30s and fail here — the 60s guard alone cannot catch
-- it). The gate fill wraps the reap itself in 'finally': a kill
-- landing after the closer parks but before the drain returns
-- still releases the waiter instead of stranding it (a kill before
-- the reap starts strand nothing — the closer was never invoked).
-- The closer's exit is then observed, proving the abandoned waiter
-- reaped — and a post-abandon throw would have to come from
-- nowhere (the waiter's thread id is discarded, unreachable by
-- 'throwTo'; the gate fill returns normally, so no put-back
-- fires).
testWedgedCloserAbandoned :: IO EnvScope -> IO ()
testWedgedCloserAbandoned mkScope = do
  (_, reg, _) <- mkScope
  me <- myThreadId
  gate <- newEmptyMVar
  exited <- newEmptyMVar
  _resVar <- forkOpener mkScope
    (\(_ :: ()) -> uninterruptibleMask_ (takeMVar gate >> putMVar exited ()))
    (pure ())
  -- A wall-clock step between the readings would corrupt the
  -- interval, so the floor and ceiling use the monotonic clock.
  start <- getMonotonicTime
  (mProblems, end) <- flip finally (putMVar gate ()) $ do
    mPs <- timeout (60 * 1000000) (reapSelected (Just me) reg)
    endNow <- getMonotonicTime
    pure (mPs, endNow)
  problems <- case mProblems of
    Nothing -> assertFailure "wedgedrain: reap hung past 60s on a wedged closer (no drain bound)"
    Just ps -> pure ps
  assertBool ("wedgedrain: wedged-closer abandonment not reported: " ++ show problems)
    (any ("drain timed out" `isInfixOf`) problems)
  assertBool ("wedgedrain: reap returned without waiting the drain bound: " ++ show (end - start))
    (end - start > 5)
  assertBool ("wedgedrain: reap returned past twice the drain bound: " ++ show (end - start))
    (end - start < 20)
  mExited <- timeout (5 * 1000000) (takeMVar exited)
  case mExited of
    Nothing -> assertFailure "wedgedrain: abandoned closer did not exit after the gate fill"
    Just () -> pure ()

-- | The reconciliation fixture preserves the caller's opt-in: an
-- opted-in config through 'openReconciled' pauses a fresh creation
-- until the @go@ file appears, exactly like the direct serving
-- open. (The fixture used to force the flag off; that version never
-- writes the marker here and fails this test.)
testReconciledHonorsOptIn :: IO EnvScope -> IO ()
testReconciledHonorsOptIn mkScope =
  bracket (makeTempDir "haskoki-storage-reconpause") removeDirectoryRecursive $ \dir ->
    bracket (makeTempDir "haskoki-storage-reconpausedir") removeDirectoryRecursive $ \pauseDir -> do
      let path = dir </> "store.db"
          pausedFile = pauseDir </> "paused"
          goFile = pauseDir </> "go"
          cfg = defaultConfig
            { cfgStorage = (cfgStorage defaultConfig)
              { scKind = StorageSQLite, scPath = Just path, scAllowEnvSeams = True }
            }
      withOpenPause mkScope pauseDir path $ do
        resVar <- forkOpener mkScope closeReconciledResult (openReconciled path cfg)
        let awaitPaused 0 = assertFailure "reconpause: reconciled open did not pause under opt-in"
            awaitPaused n = do
              here <- doesFileExist pausedFile
              if here then pure () else threadDelay 100000 >> awaitPaused (n - 1 :: Int)
        awaitPaused (100 :: Int)
        -- Still blocked at 0.5s, 1.5s and 2.5s with no go file (same
        -- bar as the direct serving-open test: a marker-only seam
        -- publishes by the fourth sample); the go handshake must then
        -- release it within 5s.
        -- A completed open here means the seam never fired: fail
        -- without consuming it (a peek, not a take), so the reap
        -- drain still owns the single close at teardown.
        let stillWaiting tag = do
              early <- tryReadMVar resVar
              case early of
                Just _ -> assertFailure ("reconpause: reconciled open completed without the go file (" ++ tag ++ ")")
                Nothing -> pure ()
        threadDelay 500000 >> stillWaiting "0.5s sample"
        threadDelay 1000000 >> stillWaiting "1.5s sample"
        threadDelay 1000000 >> stillWaiting "2.5s sample"
        threadDelay 1000000 >> stillWaiting "3.5s sample"
        writeFile goFile "go\n"
        mDone <- timeout (5 * 1000000) (readMVar resVar)
        eAcq <- case mDone of
          Nothing -> assertFailure "reconpause: reconciled open did not resume on go file"
          Just e -> pure e
        case eAcq of
          Left err -> assertFailure ("reconpause: reconciled open failed: " ++ show err)
          Right Nothing -> assertFailure "reconpause: reconciled open returned no store"
          Right _ -> pure ()

-- | Pid-0 test: a lock naming pid 0 takes no @\/proc\/0@ probe — pid 0
-- is never a userspace owner (owners write @getProcessID@), so the
-- entry is dead by rule while the kernel backstop still confirms.
-- A free, writable lock would take over regardless of the pid
-- verdict (the flock arbitrates; an unwritable sidecar refuses
-- instead), so this test holds the lock instead: with a live holder
-- behind the
-- stale @0@ entry and a fake proc root, the dead-by-rule path takes
-- the generic kernel-held refusal, which names no pid. The assertion
-- pins that path positively (and excludes every pid-0 phrasing):
-- probing @\/proc\/0@ would read Present (alive) and refuse as
-- "already open by pid 0", while a missing @self@ witness would
-- refuse as unknowable "locked by pid 0". Both controls fail it.
testPidZeroTakeable :: IO EnvScope -> IO ()
testPidZeroTakeable mkScope =
  bracket (makeTempDir "haskoki-storage-pidzero") removeDirectoryRecursive $ \dir ->
    bracket (makeTempDir "haskoki-storage-fakeproc") removeDirectoryRecursive $ \fakeProc -> do
      me <- getProcessID
      ppid <- getParentProcessID
      reaped <- newIORef False
      let path = dir </> "store.db"
          doneFile = dir </> "holder.done"
          readyFile = dir </> "holder.ready"
          pidFile = dir </> "holder.pid"
      e0 <- openSQLiteStore path
      s0 <- either (\e -> assertFailure ("pidzero seed open: " ++ show e)) pure e0
      _ <- seedStore s0
      storeClose s0
      let childEnv =
            [ ("HASKOKI_HOLDER_MODE", "reserve")
            , ("HASKOKI_HOLDER_PIDFILE", pidFile)
            ]
      bracket (spawnHolderEnv mkScope childEnv path doneFile readyFile) (releaseHolder reaped) $ \ph -> do
        holderPid <- spawnedPid ph "pidzero"
        awaitLockOwner path holderPid
        awaitDone readyFile (6000 :: Int)
        -- The holder keeps the flock; rewrite the entry to pid 0.
        writeFile (path ++ ".lock") "0\n"
        writeFile (fakeProc </> "self") ""
        writeFile (fakeProc </> show me) ""
        writeFile (fakeProc </> show ppid) ""
        writeFile (fakeProc </> "0") ""
        withProcRoot mkScope fakeProc $ do
          e1 <- openSQLiteStoreWith True path defaultLimits noFaults
          case e1 of
            Right s1 -> do
              storeClose s1
              assertFailure "pidzero: second open succeeded against a held lock (state fork)"
            Left (StoreSecondWriter msg) ->
              assertBool ("pidzero: expected dead-by-rule kernel-held refusal naming no pid 0, got: " ++ msg)
                (("kernel lock held" `isInfixOf` msg) && not ("pid 0" `isInfixOf` msg))
            Left other -> assertFailure ("pidzero: wrong error with bogus proc root: " ++ show other)
        writeFile doneFile "done\n"
        awaitHolderExit reaped ph "pidzero"

-- | Death between reservation and insertion: a holder child in
-- reserve mode opens the store, durably reserves one id,
-- records it, and parks; the parent SIGKILLs it there (no
-- close, no insert), takes over the stale lock via the real
-- /proc, and proves the burned id is absent and never reused.
testReserveDeathGap :: IO EnvScope -> IO ()
testReserveDeathGap mkScope =
  bracket (makeTempDir "haskoki-storage-reservedeath") removeDirectoryRecursive $ \dir -> do
    reaped <- newIORef False
    let path = dir </> "store.db"
        doneFile = dir </> "holder.done"
        readyFile = dir </> "holder.ready"
        pidFile = dir </> "holder.pid"
    e0 <- openSQLiteStore path
    s0 <- either (\e -> assertFailure ("reserve-death seed open: " ++ show e)) pure e0
    (tok, _) <- seedStore s0
    storeClose s0
    let childEnv =
          [ ("HASKOKI_HOLDER_MODE", "reserve")
          , ("HASKOKI_HOLDER_PIDFILE", pidFile)
          ]
    bracket (spawnHolderEnv mkScope childEnv path doneFile readyFile) (releaseHolder reaped) $ \ph -> do
      holderPid <- spawnedPid ph "reserve-death"
      awaitLockOwner path holderPid
      awaitDone readyFile (6000 :: Int)
      pidText <- readFile pidFile
      burned <- case reads pidText of
        [(n, _)] -> pure (n :: Word64)
        _ -> assertFailure "reserve-death: child recorded no id"
      -- True process death in the reserve/insert window.
      signalProcess sigKILL holderPid
      mSt <- waitBounded ph 1000
      case mSt of
        Nothing -> assertFailure "reserve-death: child survived SIGKILL"
        Just _ -> do
          _ <- claimReap reaped
          pure ()
      -- Stale takeover, then the gap proof.
      e1 <- openSQLiteStore path
      s1 <- either (\e -> assertFailure ("reserve-death takeover failed: " ++ show e)) pure e1
      eJobs <- storeLoadJobs s1
      jobs <- either (\e -> assertFailure ("reserve-death load jobs: " ++ show e)) pure eJobs
      assertEqual "burned id names no record" [] jobs
      next <- storeReserveJobId s1 >>= expectRight "reserve-death next"
      assertEqual "gap, never a reuse" (burned + 1) next
      landed <- storeCommit s1 emptyDelta
        { sdPutJobs = [demoJobPending next (trId tok) (trGeneration tok)] }
      assertEqual "insert lands" Committed landed
      eJobs2 <- storeLoadJobs s1
      jobs2 <- either (\e -> assertFailure ("reserve-death reload jobs: " ++ show e)) pure eJobs2
      assertEqual "only the new record exists" [next] (map jrPersistentId jobs2)
      storeClose s1

-- | Liveness-mapping unit test (finding 2): the pure verdict
-- table over synthetic probe results, pinning the namespace-local
-- ppid-0 rule (parent witness inapplicable, stale recovery works)
-- without forking into a PID namespace — plus the fail-closed rows
-- the @\/proc@-fixture tests rely on.
testLivenessMapping :: IO ()
testLivenessMapping = do
  let t = assertEqual "liveness mapping"
  -- The ppid-0 rule (parent probe Nothing: no /proc/0 probe taken).
  t PidDead $ livenessFromProbes ProbePresent ProbePresent Nothing ProbeAbsent
  t PidAlive $ livenessFromProbes ProbePresent ProbePresent Nothing ProbePresent
  t PidUnknown $ livenessFromProbes ProbePresent ProbePresent Nothing ProbeUnknown
  -- The parent witness still gates when the ppid is namespace-local.
  t PidDead $ livenessFromProbes ProbePresent ProbePresent (Just ProbePresent) ProbeAbsent
  t PidAlive $ livenessFromProbes ProbePresent ProbePresent (Just ProbePresent) ProbePresent
  t PidUnknown $ livenessFromProbes ProbePresent ProbePresent (Just ProbePresent) ProbeUnknown
  t PidUnknown $ livenessFromProbes ProbePresent ProbePresent (Just ProbeAbsent) ProbeAbsent
  t PidUnknown $ livenessFromProbes ProbePresent ProbePresent (Just ProbeUnknown) ProbeAbsent
  -- Self/own gating fails closed regardless of the parent row.
  t PidUnknown $ livenessFromProbes ProbeAbsent ProbePresent Nothing ProbeAbsent
  t PidUnknown $ livenessFromProbes ProbeUnknown ProbePresent (Just ProbePresent) ProbeAbsent
  t PidUnknown $ livenessFromProbes ProbePresent ProbeAbsent Nothing ProbeAbsent
  t PidUnknown $ livenessFromProbes ProbePresent ProbeUnknown (Just ProbePresent) ProbeAbsent
