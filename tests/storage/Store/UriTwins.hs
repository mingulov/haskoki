{- | Store URI twin cases.
-}
{-# LANGUAGE OverloadedStrings #-}
module Store.UriTwins
  ( caseMemoryRefuses
  , caseUriAfterResolve
  , caseUriAuthorityRefuses
  , caseUriAuthorityTwin
  , caseUriFragment
  , caseUriNested
  , caseUriQuery
  , caseUriTwinAlias
  , caseUriTwinLock
  , caseUriTwinSidecar
  , caseUriUndecodable
  ) where

import Control.Exception (bracket, finally)
import Control.Monad (filterM)
import qualified Data.ByteString as BS
import Data.List (isInfixOf, sort)
import System.Directory (createDirectoryIfMissing, doesFileExist, removeDirectoryRecursive, removeFile)
import System.FilePath ( (</>))
import System.IO.Error (catchIOError)
import System.Posix.Files (createSymbolicLink)
import Test.Tasty.HUnit (assertEqual, assertFailure)
import Haskoki.Runtime.Storage
  ( Store (..)
  , StoreError (..)
  )
import StoreFixtures (makeTempDir)
import Haskoki.Runtime.Storage.SQLite (openSQLiteStore, resolveStoreSpelling)
import Haskoki.Runtime.Trace (SpellingRefusal (..))

-- | URI twin sees the same sidecars: a store plus a -wal
-- sibling opened through a %2e%2e twin spelling refuses exactly
-- like the POSIX spelling (guards and SQLite agree on the
-- decoded file).
caseUriTwinSidecar :: IO ()
caseUriTwinSidecar =
  bracket (makeTempDir "haskoki-storage-uri-twin") removeDirectoryRecursive $ \dir -> do
    let db = dir </> "a.db"
    bracket (either (assertFailure . show) pure =<< openSQLiteStore db) storeClose $ \_ -> pure ()
    BS.writeFile (db ++ "-wal") "foreign frames"
    ePosix <- openSQLiteStore db
    case ePosix of
      Left (StoreForeignSidecar p) -> assertEqual "posix sidecar path" (db ++ "-wal") p
      Left other -> assertFailure ("posix spelling must see the sidecar, got: " ++ show other)
      Right s -> storeClose s >> assertFailure "posix spelling missed the sidecar"
    let twin = "file:" ++ dir ++ "/x/%2e%2e/a.db"
    eTwin <- openSQLiteStore twin
    case eTwin of
      Left (StoreForeignSidecar p) -> assertEqual "twin sidecar path" (db ++ "-wal") p
      Left other -> assertFailure ("twin must refuse by sidecar, got: " ++ show other)
      Right s -> storeClose s >> assertFailure "twin spelling missed the sidecar"

-- | URI twin sees the same lock: a POSIX open holds the lock,
-- so the %2e%2e twin must refuse StoreSecondWriter (same
-- identity, not a shadow open); after close the twin opens fine.
caseUriTwinLock :: IO ()
caseUriTwinLock =
  bracket (makeTempDir "haskoki-storage-uri-lock") removeDirectoryRecursive $ \dir -> do
    let db = dir </> "a.db"
        twin = "file:" ++ dir ++ "/x/%2e%2e/a.db"
    bracket (either (assertFailure . show) pure =<< openSQLiteStore db) storeClose $ \_ -> do
      eTwin <- openSQLiteStore twin
      -- Either lock-file verdict proves the twin resolved to the
      -- same lock identity; the kernel guard or a decode break
      -- must not fire. In-test both opens share a pid, so the
      -- exercised arm is the same-pid read-back; the held-lock
      -- arm documents the dead-owner-with-held-lock verdict.
      case eTwin of
        Left (StoreSecondWriter m)
          | "store lock is held" `isInfixOf` m -> pure ()
          | "already open in this process" `isInfixOf` m -> pure ()
          | otherwise -> assertFailure ("twin refused by the wrong guard: " ++ m)
        Left other -> assertFailure ("twin must refuse by lock, got: " ++ show other)
        Right s -> storeClose s >> assertFailure "twin spelling shadowed the lock"
    eRe <- openSQLiteStore twin
    case eRe of
      Left err -> assertFailure ("twin must open after close, got: " ++ show err)
      Right s -> storeClose s

-- | Alias (symlink) plus URI decoding agree: a store under a
-- symlinked directory, opened through the link, holds the lock
-- on the real file; a %2e%2e twin traversing the same link must
-- refuse StoreSecondWriter (same identity).
caseUriTwinAlias :: IO ()
caseUriTwinAlias =
  bracket (makeTempDir "haskoki-storage-uri-alias") removeDirectoryRecursive $ \dir -> do
    createDirectoryIfMissing True (dir </> "real")
    createSymbolicLink (dir </> "real") (dir </> "link")
    let via = dir </> "link" </> "a.db"
        twin = "file:" ++ dir ++ "/link/x/%2e%2e/a.db"
    bracket (either (assertFailure . show) pure =<< openSQLiteStore via) storeClose $ \_ -> do
      eTwin <- openSQLiteStore twin
      case eTwin of
        Left (StoreSecondWriter m)
          | "store lock is held" `isInfixOf` m -> pure ()
          | "already open in this process" `isInfixOf` m -> pure ()
          | otherwise -> assertFailure ("alias twin refused by the wrong guard: " ++ m)
        Left other -> assertFailure ("alias twin must refuse by lock, got: " ++ show other)
        Right s -> storeClose s >> assertFailure "alias twin spelling shadowed the lock"
    eRe <- openSQLiteStore twin
    case eRe of
      Left err -> assertFailure ("alias twin must open after close, got: " ++ show err)
      Right s -> storeClose s

-- | Undecodable URIs refuse cleanly (never reach SQLite).
caseUriUndecodable :: IO ()
caseUriUndecodable =
  bracket (makeTempDir "haskoki-storage-uri-bad") removeDirectoryRecursive $ \dir -> do
    let bad0 = "file:" ++ dir ++ "/a%00.db"
        badFF = "file:" ++ dir ++ "/a%FF.db"
    e0 <- openSQLiteStore bad0
    case e0 of
      Left (StoreIO msg) -> assertEqual "exact refusal"
        ("file: URI does not decode: " ++ bad0) msg
      Left other -> assertFailure ("NUL URI must refuse cleanly, got: " ++ show other)
      Right st -> storeClose st >> assertFailure "NUL URI opened"
    eFF <- openSQLiteStore badFF
    case eFF of
      Left (StoreIO msg) -> assertEqual "exact refusal"
        ("file: URI does not decode: " ++ badFF) msg
      Left other -> assertFailure ("non-UTF8 URI must refuse cleanly, got: " ++ show other)
      Right st -> storeClose st >> assertFailure "non-UTF8 URI opened"

-- | URIs with query strings refuse (their semantics —
-- mode=memory, shared cache — are invisible to the guards).
caseUriQuery :: IO ()
caseUriQuery =
  bracket (makeTempDir "haskoki-storage-uri-query") removeDirectoryRecursive $ \dir -> do
    let q = "file:" ++ dir ++ "/missing.db?mode=memory"
    eQ <- openSQLiteStore q
    case eQ of
      Left (StoreIO msg) -> assertEqual "exact refusal"
        ("file: URI with query/fragment refused (bare paths only): " ++ q) msg
      Left other -> assertFailure ("query URI must refuse by spelling, got: " ++ show other)
      Right st -> storeClose st >> assertFailure "query URI opened"

-- | URIs with fragments refuse (same invisibility as query).
caseUriFragment :: IO ()
caseUriFragment =
  bracket (makeTempDir "haskoki-storage-uri-fragment") removeDirectoryRecursive $ \dir -> do
    let f = "file:" ++ dir ++ "/missing.db#frag"
    eF <- openSQLiteStore f
    case eF of
      Left (StoreIO msg) -> assertEqual "exact refusal"
        ("file: URI with query/fragment refused (bare paths only): " ++ f) msg
      Left other -> assertFailure ("fragment URI must refuse by spelling, got: " ++ show other)
      Right st -> storeClose st >> assertFailure "fragment URI opened"

-- | A nested file: URI refuses (decoding it would re-enter
-- URI interpretation in SQLite).
caseUriNested :: IO ()
caseUriNested =
  bracket (makeTempDir "haskoki-storage-uri-nested") removeDirectoryRecursive $ \_dir -> do
    let nested = "file:file%3Ax"
    eN <- openSQLiteStore nested
    case eN of
      Left (StoreIO msg) -> assertEqual "exact refusal"
        ("nested file: URI refused: " ++ nested) msg
      Left other -> assertFailure ("nested URI must refuse by spelling, got: " ++ show other)
      Right s -> storeClose s >> assertFailure "nested URI opened"
    -- Refusal precedes all I/O: no lock, sidecar, or database may
    -- appear under the working directory.
    litter <- filterM doesFileExist ["file:x", "file:x.lock"]
    assertEqual "no refusal litter" [] litter

-- | Resolution can CREATE a URI the decode stage never sees
-- (@./file:x@ resolves to @file:x@): SQLite would re-enter URI
-- interpretation while the guards stat the spelling literally,
-- so the resolved spelling re-checks and refuses. (The relative
-- spelling needs no fixture: refusal precedes all I/O. The probe
-- name is distinctive so no checkout file can shadow it. The
-- litter check snapshots the working directory BEFORE the open
-- and compares after: scrubbing first would let a regression
-- that writes-then-refuses pass, and the teardown removes only
-- files the open created, never pre-existing ones.)
caseUriAfterResolve :: IO ()
caseUriAfterResolve = do
  eSp <- resolveStoreSpelling rel
  assertEqual "resolve refuses the produced URI" (Left UriAfterResolve) eSp
  before <- sort <$> filterM doesFileExist litterNames
  (do
    eU <- openSQLiteStore rel
    case eU of
      Left (StoreIO msg) -> do
        assertEqual "exact refusal"
          ("store path resolves to a file: URI, refusing: " ++ rel) msg
        litter <- sort <$> filterM doesFileExist litterNames
        assertEqual "refusal writes nothing new" before litter
      Left other -> assertFailure ("resolved-URI spelling must refuse by spelling, got: " ++ show other)
      Right st -> do
        storeClose st
        assertFailure "resolved-URI spelling opened"
    ) `finally` do
      present <- filterM doesFileExist litterNames
      mapM_ scrub (filter (`notElem` before) present)
  where
    rel = "./file:spelling-recheck-060probe.sqlite"
    decoded = "spelling-recheck-060probe.sqlite"
    literal = "file:spelling-recheck-060probe.sqlite"
    sidecars b = [b, b ++ ".lock", b ++ "-journal", b ++ "-wal", b ++ "-shm"]
    litterNames = sidecars decoded ++ sidecars literal
    scrub f = catchIOError (removeFile f) (\_ -> pure ())

-- | @:memory:@ names SQLite's in-memory database, which the file
-- guards cannot see: it refuses at resolve and at open, writing
-- nothing (not even a lock beside it). Same before/after litter
-- discipline as 'caseUriAfterResolve'.
caseMemoryRefuses :: IO ()
caseMemoryRefuses = do
  eSp <- resolveStoreSpelling ":memory:"
  assertEqual "resolve refuses :memory:" (Left SpellingIsMemory) eSp
  before <- sort <$> filterM doesFileExist litterNames
  (do
    eM <- openSQLiteStore ":memory:"
    case eM of
      Left (StoreIO msg) -> do
        assertEqual "exact refusal"
          "store path names the :memory: database, refusing (file stores only): :memory:" msg
        litter <- sort <$> filterM doesFileExist litterNames
        assertEqual "refusal writes nothing new" before litter
      Left other -> assertFailure (":memory: must refuse by spelling, got: " ++ show other)
      Right st -> do
        storeClose st
        assertFailure ":memory: opened"
    ) `finally` do
      present <- filterM doesFileExist litterNames
      mapM_ scrub (filter (`notElem` before) present)
  where
    litterNames =
      [ ":memory:"
      , ":memory:.lock"
      , ":memory:-journal"
      , ":memory:-wal"
      , ":memory:-shm"
      ]
    scrub f = catchIOError (removeFile f) (\_ -> pure ())

-- | A localhost-authority URI twin sees the same sidecars:
-- SQLite strips the authority, so decoding agrees and the twin
-- refuses exactly like the POSIX spelling.
caseUriAuthorityTwin :: IO ()
caseUriAuthorityTwin =
  bracket (makeTempDir "haskoki-storage-uri-authtwin") removeDirectoryRecursive $ \dir -> do
    let db = dir </> "a.db"
    bracket (either (assertFailure . show) pure =<< openSQLiteStore db) storeClose $ \_ -> pure ()
    BS.writeFile (db ++ "-wal") "foreign frames"
    let twin = "file://localhost" ++ dir ++ "/x/%2e%2e/a.db"
    eTwin <- openSQLiteStore twin
    case eTwin of
      Left (StoreForeignSidecar p) -> assertEqual "twin sidecar path" (db ++ "-wal") p
      Left other -> assertFailure ("authority twin must refuse by sidecar, got: " ++ show other)
      Right s -> storeClose s >> assertFailure "authority twin spelling missed the sidecar"

-- | A non-local authority refuses with its own reason (SQLite
-- refuses it too, so decoding the authority into a path
-- component would diverge from the opener).
caseUriAuthorityRefuses :: IO ()
caseUriAuthorityRefuses =
  bracket (makeTempDir "haskoki-storage-uri-authbad") removeDirectoryRecursive $ \dir -> do
    let bad = "file://other" ++ dir ++ "/a.db"
    eB <- openSQLiteStore bad
    case eB of
      Left (StoreIO msg) -> assertEqual "exact refusal"
        ("file: URI has a non-local authority, refusing: " ++ bad) msg
      Left other -> assertFailure ("authority URI must refuse by spelling, got: " ++ show other)
      Right st -> storeClose st >> assertFailure "authority URI opened"
