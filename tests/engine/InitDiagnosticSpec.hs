{- | C_Initialize diagnostic contract (R-09c): a standard-surface
open refused with a typed store error best-effort emits one JSONL
cause row through the acquisition tracer before returning NULL, so
the C caller — who only sees CKR_GENERAL_ERROR — can read the typed
refusal from the drained trace when tracing is enabled and the row
survives the queue and the sink. Only the store step reports: the
initialization and backend failure arms return NULL with no row.

Row shape: function @C_Initialize@, disposition @rejected@, ckr 5,
mode @sync@, reason @\<tag\>: \<remedy\>@ with trace-safe fixed
remedy text (no store payload bytes; @store check@ reports the
detail it can see — never the serving open's counter validation or
seed write). Tags reuse the CLI vocabulary where it applies, so one
doc table covers both surfaces.

* behavioral probes: injected @saOpenStore@ refusals (seating,
  SQLite, identity, migration, lock-branch) each emit exactly one
  row with the pinned fields; a tracer-less refused open still
  returns NULL without throwing; a successful open emits no
  @C_Initialize@ row; a real instance over a directory-as-store
  proves the rollback close drains the exact row to the trace file;
* renderer pins: 'renderInitRefusal' maps every 'StdStoreError'
  constructor (and every 'StoreError' constructor through the
  SQLite arm, both 'StoreIO' branches included) to its exact
  @(tag, remedy)@ pair;
* tag agreement: the SQLite arm reuses 'renderStoreRefusal' tags
  verbatim, pinned equal per constructor;
* doc pin: every cell of the init-refusal table in
  @docs/operations-notes.md@ is compared against its tag's expected
  content (tag set, surfaces, reachability, renderer-sourced remedy
  wordings).
- best-effort delivery: tracing disabled, queue overflow, or sink
  failure loses the row (the NULL is returned either way).
-}
module InitDiagnosticSpec (spec) where

import Control.Concurrent (forkIO, killThread, newEmptyMVar, putMVar, takeMVar, threadDelay, threadWaitRead, tryTakeMVar)
import Control.Exception (IOException, bracket, finally, mask, throwIO, try, uninterruptibleMask_)
import Control.Monad (replicateM, replicateM_, when)
import Data.Either (isLeft, isRight)
import Data.Char (isAlphaNum, isAscii, ord)
import Data.IORef (IORef, modifyIORef', newIORef, readIORef, writeIORef)
import Data.List (isInfixOf, isPrefixOf, sort)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BC8
import Data.Maybe (listToMaybe)
import Foreign.C.Error (Errno (..), eCHILD, eNXIO)
import Foreign.Marshal.Alloc (allocaBytes)
import Foreign.Ptr (minusPtr, nullPtr)
import GHC.IO.Exception (ioe_errno)
import GHC.IO.Encoding (getFileSystemEncoding, textEncodingName)
import System.Info (os)
import Foreign.StablePtr (StablePtr, castStablePtrToPtr)
import GHC.Clock (getMonotonicTimeNSec)
import System.Directory
  ( canonicalizePath
  , createDirectory
  , doesDirectoryExist
  , doesFileExist
  , getCurrentDirectory
  , getTemporaryDirectory
  , listDirectory
  , removeDirectoryRecursive
  , removeFile
  )
import System.Environment (lookupEnv)
import System.IO (IOMode (..), hClose, hFileSize, openFile, withFile)
import System.IO.Error (isEOFError)
import System.Posix.Files (FileStatus, createLink, createNamedPipe, createSymbolicLink, deviceID, fileID, getFileStatus, readSymbolicLink, setFileMode)
import qualified System.Posix.Directory.ByteString as BDir
import System.Posix.IO (FdOption (CloseOnExec), OpenFileFlags (..), OpenMode (..), closeFd, createPipe, defaultFileFlags, dupTo, openFd, setFdOption, stdOutput)
import qualified System.Posix.IO.ByteString as BIO
import System.Posix.Process (ProcessStatus, executeFile, forkProcess, getProcessStatus)
import System.Posix.Signals (Handler (..), installHandler, sigCONT, sigKILL, sigPIPE, sigSTOP, signalProcess)
import System.Posix.Types (CPid (..), Fd (..))
import System.Posix.User (getEffectiveUserID)
import System.Timeout (timeout)
import Test.Tasty (TestTree, inOrderTestGroup, testGroup)
import Test.Tasty.HUnit (HUnitFailure (..), assertBool, assertEqual, assertFailure, testCase)

import Haskoki.FFI.Instance
  ( buildInstance
  , haskokiInstanceClose
  , newInstanceCell
  )
import Haskoki.FFI.Standard
  ( StdAcquisition (..)
  , StdStoreError (..)
  , haskokiStdClose
  , haskokiStdOpen
  , openStdInstanceWith
  , renderInitRefusal
  , stdAcquisition
  )
import Haskoki.Runtime.Config
  ( Config (..)
  , StorageCfg (..)
  , StorageKind (..)
  , TraceCfg (..)
  , defaultConfig
  )
import Haskoki.Runtime.Storage (StoreError (..))
import Haskoki.Runtime.Storage.Preflight (renderStoreRefusal)
import Haskoki.Runtime.Trace
  ( DrainReport (..)
  , TraceEvent (..)
  , TraceIds (..)
  , Tracer
  , drainTracer
  , droppedTraces
  , fileSink
  , newFileTracer
  , newTracer
  , isUtf8EncodingName
  , renderJSONL
  , shouldDropForEncoding
  , spellingDropsWith
  , tracerAliasesStoreWith
  , withReaderHeld
  , writeFully
  )
import Haskoki.Session (AdmitDeny (..))
import Haskoki.Types (TokenId (..))

spec :: TestTree
spec = testGroup "C_Initialize diagnostics"
  [ testCase "seating refusal emits one cause row" caseSeatingRow
  , testCase "SQLite refusal emits one cause row" caseSQLiteRow
  , testCase "lock-branch refusal tags store-lock-unwritable" caseLockRow
  , testCase "identity refusal emits one cause row" caseIdentityRow
  , testCase "migration refusal emits one cause row" caseMigrationRow
  , testCase "tracer-less refusal is NULL without throwing" caseNoTracerNull
  , testCase "successful open emits no C_Initialize row" caseSuccessSilent
  , testCase "rollback close drains the cause row" caseRollbackCloseDrainsRow
  , testCase "renderer pins every constructor" caseRendererPins
  , testCase "SQLite arm reuses CLI tags" caseTagAgreement
  , testCase "reasons are single-line tag-safe text" caseReasonShape
  , testCase "doc table cells match per tag" caseDocCells
  , testCase "trace file aliasing the store is skipped" caseAliasSkipped
  , testCase "distinct trace file keeps the row" caseDistinctWrites
  , testCase "trace file symlinked to the store is skipped" caseSymlinkSkipped
  , testCase "trace file hardlinked to the store is skipped" caseHardlinkSkipped
  , testCase "store path with missing interior resolves like the opener" caseDotDotSkipped
  , testCase "unproven store side fails closed" caseUnprovenSkipped
  , testCase "missing store parent keeps the row" caseMissingParentEmits
  , testCase "bind-mounted journal alias is skipped" caseBindMountSkipped
  , testCase "dangling trace link to a shadow is skipped" caseDanglingSkipped
  , testCase "case-variant trace spelling fails closed" caseVariantSkipped
  , testCase "URI store guards the decoded spelling" caseUriDecodedSkipped
  , testCase "short writes retry to completion" caseShortWriteRetries
  , testCase "percent-escapes decode as UTF-8" caseUriPercentDecoded
  , testCase "decoded dot-dot normalizes like the opener" caseUriDotDotSkipped
  , testCase "undecodable file: URI fails closed" caseUriUndecodableSkipped
  , testCase "dot-slash file: URI tests the resolved spelling" caseUriDotSlashSkipped
  , testCase "NUL escape in a URI fails closed" caseUriNulSkipped
  , testCase "procfs magic link identity matches" caseMagicLinkSkipped
  , testCase "casefold twins match" caseCasefoldSkipped
  , testCase "dangling sidecar link target is skipped" caseShadowDanglingSkipped
  , testCase "bind-mounted dangling target is skipped" caseBindMountDanglingSkipped
  , testCase "surrogate-escape spelling is skipped" caseSurrogatePathSkipped
  , testCase "encoding names classify UTF-8" caseEncodingNames
  , testCase "non-ASCII drops without UTF-8" caseEncodingDropQuadrants
  , testCase "guard drops non-ASCII under simulated latin1" caseLatin1Drop
  , testCase "pre-resolve spelling drops" caseSpellingDrops
  , testCase "unresolved surrogate spelling is skipped" caseRawSurrogateLinkSkipped
  , testCase "forty-link chain resolves" caseFortyLinksResolve
  , testCase "forty-one-link chain drops" caseFortyOneLinksDrop
  , testCase "spawn-flake retry spans five attempts" caseRetryDepth
  -- FIFO/fd-count assertions race fork+exec children: tasty runs
  -- tests in parallel by default, and a child forked mid-test
  -- inherits every open descriptor — a pre-exec child still holds
  -- each with cloexec pending, so it counts as a live reader and
  -- breaks ENXIO/EOF expectations in a concurrently running case.
  -- These nine never overlap each other; every descriptor they open
  -- is close-on-exec, so nothing unintended survives past exec —
  -- the sync-pin test asserts the single deliberate survivor (the
  -- exec'd child's stdout dup).
  , inOrderTestGroup "FIFO and fork-sensitive"
    [ testCase "drain to a readerless FIFO returns" caseFifoDrainReturns
    , testCase "drain to a connected full FIFO returns" caseFifoFullReturns
    , testCase "disconnected FIFO fails, never terminates" caseFifoEpipeMasked
    , testCase "holder is close-on-exec" caseFifoHolderCloexec
    , testCase "exec'd children keep no sync fds" caseSyncPipeCloexec
    , testCase "stopped child cannot hang the sync read" caseSyncReadTimeouts
    , testCase "EOF with live child reaps without hanging" caseSyncEofReapsLive
    , testCase "timed-out read reaps and closes before failing" caseSyncTimeoutCleansUp
    , testCase "write-only FIFO fails the row" caseFifoWriteOnlyFails
    ]
  ]

isNull :: StablePtr a -> Bool
isNull sp = castStablePtrToPtr sp == nullPtr

-- | Run a refused open with a collecting tracer: inject the store
-- failure, assert NULL, drain, and return the rows oldest-first.
refusedRows :: StdStoreError -> IO [String]
refusedRows refusal = do
  rows <- newIORef []
  tr <- newTracer 64 (\l -> modifyIORef' rows (BC8.unpack l :) >> pure (Right ())) False
  let sa = stdAcquisition
        { saTracer = Just tr
        , saOpenStore = \_ _ -> pure (Left refusal)
        }
  sp <- openStdInstanceWith sa defaultConfig
  assertBool "refused open is NULL" (isNull sp)
  _ <- drainTracer tr
  reverse <$> readIORef rows

-- | The row carries the exact field values (comma-terminated, so
-- @\"ckr\":5,@ cannot match a hypothetical @\"ckr\":50@) and the
-- exact full reason — never a tag prefix with arbitrary text after
-- it. Reasons are pinned literally here (the wiring level); the
-- renderer pins below hold the same literals (the mapping level).
assertCauseRow :: String -> String -> [String] -> IO ()
assertCauseRow tag reason [line] = do
  assertBool "names the entry" ("\"function\":\"C_Initialize\"," `isInfixOf` line)
  assertBool "rejected" ("\"disposition\":\"rejected\"," `isInfixOf` line)
  assertBool "keeps the code" ("\"ckr\":5," `isInfixOf` line)
  assertBool "sync mode" ("\"mode\":\"sync\"," `isInfixOf` line)
  assertBool ("exact reason for " ++ tag)
    (("\"reason\":\"" ++ tag ++ ": " ++ reason ++ "\",") `isInfixOf` line)
assertCauseRow tag _ other =
  assertFailure ("expected exactly one cause row for " ++ tag ++ ", got: " ++ show other)

caseSeatingRow :: IO ()
caseSeatingRow = do
  ls <- refusedRows (StdStoreSeating AdmitTokensFull)
  assertCauseRow "store-seating-refused"
    "token seating refused (AdmitTokensFull): the catalog exceeds serving limits; shrink the configured token catalog and retry" ls

caseSQLiteRow :: IO ()
caseSQLiteRow = do
  ls <- refusedRows (StdStoreSQLite (StoreSecondWriter "store is in use (pid 1): /tmp/x"))
  assertCauseRow "store-live"
    ("the store lock could not be acquired (run haskoki-ctl store check to see the lock state):"
      ++ " if a store owner holds it, stop the owner and retry;"
      ++ " otherwise inspect the lock file and retry") ls

caseLockRow :: IO ()
caseLockRow = do
  ls <- refusedRows (StdStoreSQLite (StoreIO "store lock cannot be created: /tmp/x.lock: denied"))
  assertCauseRow "store-lock-unwritable"
    "the store lock cannot be created: fix the directory permissions or free space and retry" ls

caseIdentityRow :: IO ()
caseIdentityRow = do
  ls <- refusedRows (StdStoreIdentityRefusal "stored token 2 relabeled (ignored payload)")
  assertCauseRow "store-identity-refused"
    "stored token identity drifted from the catalog: run haskoki-ctl store check for the reconciler's report" ls

caseMigrationRow :: IO ()
caseMigrationRow = do
  ls <- refusedRows (StdStoreMigrationRequired [TokenId 1, TokenId 2])
  assertCauseRow "store-migration-required"
    "stored tokens lack credential rows: run haskoki-ctl store migrate" ls

caseNoTracerNull :: IO ()
caseNoTracerNull = do
  let sa = stdAcquisition
        { saTracer = Nothing
        , saOpenStore = \_ _ -> pure (Left (StdStoreSeating AdmitTokensFull))
        }
  sp <- openStdInstanceWith sa defaultConfig
  assertBool "refused open is NULL" (isNull sp)

caseSuccessSilent :: IO ()
caseSuccessSilent = do
  rows <- newIORef []
  tr <- newTracer 64 (\l -> modifyIORef' rows (BC8.unpack l :) >> pure (Right ())) False
  let sa = stdAcquisition { saTracer = Just tr }
  sp <- openStdInstanceWith sa defaultConfig
  assertBool "open succeeds" (not (isNull sp))
  haskokiStdClose sp
  _ <- drainTracer tr
  ls <- reverse <$> readIORef rows
  mapM_ (\l -> assertBool ("no C_Initialize row, got: " ++ l)
    (not ("C_Initialize" `isInfixOf` l))) ls

-- | End-to-end delivery through the production close path (no
-- injected opener, no manual drain): a real instance over a
-- directory-as-store refuses the standard open with NULL, the trace
-- file does not exist yet, and after the rollback close it carries
-- the exact cause row.
caseRollbackCloseDrainsRow :: IO ()
caseRollbackCloseDrainsRow =
  bracket acquire release $ \(dir, tracePath) -> do
    let cfg = defaultConfig
          { cfgStorage = (cfgStorage defaultConfig)
              { scKind = StorageSQLite
              , scPath = Just dir
              }
          , cfgTrace = TraceCfg True tracePath True 64
          }
    inst <- buildInstance cfg
    cell <- newInstanceCell inst
    std <- haskokiStdOpen cell
    assertBool "refused std open is NULL" (isNull std)
    assertBool "no trace file before the rollback close" . not
      =<< doesFileExist tracePath
    haskokiInstanceClose cell
    content <- readFile tracePath
    -- The delivered file holds exactly one row with the exact
    -- fields and the exact full reason (a file-wide substring
    -- would also accept duplicate rows or the fields scattered
    -- across lines).
    assertCauseRow "store-unreadable"
      ("the store cannot be opened (I/O, SQLite, or format failure):"
        ++ " run haskoki-ctl store check for detail and retry;"
        ++ " if check reports ok, inspect the store with SQLite tooling")
      (lines content)
  where
    acquire = do
      base <- getTemporaryDirectory
      t <- getMonotonicTimeNSec
      let dir = base ++ "/haskoki-initdiag-" ++ show t
      createDirectory dir
      pure (dir, dir ++ "/trace.jsonl")
    release (dir, _) = do
      _ <- try (removeFile (dir ++ ".lock")) :: IO (Either IOException ())
      _ <- try (removeDirectoryRecursive dir) :: IO (Either IOException ())
      pure ()

-- ---------------------------------------------------------------------------
-- Store-alias guard: a file tracer aimed at the store must not write it.
-- ---------------------------------------------------------------------------

-- | A scratch dir with a missing store path and a trace path: the
-- store file never exists (the open is refused before touching
-- it), so any file the drain creates is the test's signal.
withAliasScratch :: (FilePath -> FilePath -> FilePath -> IO ()) -> IO ()
withAliasScratch act = bracket acquire release (\(dir, store, trace) -> act dir store trace)
  where
    acquire = do
      base <- getTemporaryDirectory
      t <- getMonotonicTimeNSec
      let dir = base ++ "/haskoki-initdiag-alias-" ++ show t
      createDirectory dir
      pure (dir, dir ++ "/store.sqlite", dir ++ "/trace.jsonl")
    release (dir, _, _) = do
      _ <- try (removeDirectoryRecursive dir) :: IO (Either IOException ())
      pure ()

-- | A file tracer aimed at the store file itself: the refusal row
-- is skipped (fail closed) — after the drain the store path still
-- does not exist and the drop is counted. Without the guard the
-- drain would create it with the row.
caseAliasSkipped :: IO ()
caseAliasSkipped =
  withAliasScratch $ \_dir store _trace -> do
    tr <- newFileTracer (TraceCfg True store True 64)
    let cfg = defaultConfig
          { cfgStorage = (cfgStorage defaultConfig)
              { scKind = StorageSQLite
              , scPath = Just store
              }
          }
        sa = stdAcquisition
          { saTracer = Just tr
          , saOpenStore = \_ _ -> pure (Left (StdStoreSeating AdmitTokensFull))
          }
    sp <- openStdInstanceWith sa cfg
    assertBool "refused open is NULL" (isNull sp)
    _ <- drainTracer tr
    exists <- doesFileExist store
    assertBool "no trace file created at the store path" (not exists)
    drops <- droppedTraces tr
    assertEqual "the skipped row is counted" 1 drops

-- | Control: a distinct trace file still receives the refusal row
-- (the guard must not mute everything).
caseDistinctWrites :: IO ()
caseDistinctWrites =
  withAliasScratch $ \_dir store trace -> do
    tr <- newFileTracer (TraceCfg True trace True 64)
    let cfg = defaultConfig
          { cfgStorage = (cfgStorage defaultConfig)
              { scKind = StorageSQLite
              , scPath = Just store
              }
          }
        sa = stdAcquisition
          { saTracer = Just tr
          , saOpenStore = \_ _ -> pure (Left (StdStoreSeating AdmitTokensFull))
          }
    sp <- openStdInstanceWith sa cfg
    assertBool "refused open is NULL" (isNull sp)
    _ <- drainTracer tr
    content <- readFile trace
    assertBool "row names the entry" ("\"function\":\"C_Initialize\"," `isInfixOf` content)
    drops <- droppedTraces tr
    assertEqual "no drops" 0 drops

-- | A file tracer symlinked to the store file: the sink would
-- follow the link, so the guard must catch the resolved target —
-- after the drain the target bytes are unchanged and the drop is
-- counted.
caseSymlinkSkipped :: IO ()
caseSymlinkSkipped =
  withAliasScratch $ \_dir store trace -> do
    BC8.writeFile store (BC8.replicate 64 's')
    createSymbolicLink store trace
    prologue <- BC8.readFile trace
    assertEqual "link aims at the store" (BC8.replicate 64 's') prologue
    tr <- newFileTracer (TraceCfg True trace True 64)
    let cfg = defaultConfig
          { cfgStorage = (cfgStorage defaultConfig)
              { scKind = StorageSQLite
              , scPath = Just store
              }
          }
        sa = stdAcquisition
          { saTracer = Just tr
          , saOpenStore = \_ _ -> pure (Left (StdStoreSeating AdmitTokensFull))
          }
    sp <- openStdInstanceWith sa cfg
    assertBool "refused open is NULL" (isNull sp)
    _ <- drainTracer tr
    bytes <- BC8.readFile store
    assertEqual "target bytes unchanged" 64 (BC8.length bytes)
    drops <- droppedTraces tr
    assertEqual "the skipped row is counted" 1 drops

-- | A file tracer hardlinked to the store file: same inode under a
-- different name must still match — bytes unchanged, drop counted.
caseHardlinkSkipped :: IO ()
caseHardlinkSkipped =
  withAliasScratch $ \_dir store trace -> do
    BC8.writeFile store (BC8.replicate 64 's')
    createLink store trace
    prologue <- BC8.readFile trace
    assertEqual "link aims at the store" (BC8.replicate 64 's') prologue
    tr <- newFileTracer (TraceCfg True trace True 64)
    let cfg = defaultConfig
          { cfgStorage = (cfgStorage defaultConfig)
              { scKind = StorageSQLite
              , scPath = Just store
              }
          }
        sa = stdAcquisition
          { saTracer = Just tr
          , saOpenStore = \_ _ -> pure (Left (StdStoreSeating AdmitTokensFull))
          }
    sp <- openStdInstanceWith sa cfg
    assertBool "refused open is NULL" (isNull sp)
    _ <- drainTracer tr
    bytes <- BC8.readFile store
    assertEqual "target bytes unchanged" 64 (BC8.length bytes)
    drops <- droppedTraces tr
    assertEqual "the skipped row is counted" 1 drops

-- | A store path with a missing interior component resolves the way
-- the opener resolves it ("missing/.." drops): a trace destination
-- at the normalized location must match — bytes unchanged, drop
-- counted. (Characterization: both spellings skip; the URI twin
-- below pins that the second resolution does the work.)
caseDotDotSkipped :: IO ()
caseDotDotSkipped =
  withAliasScratch $ \dir store _trace -> do
    BC8.writeFile store (BC8.replicate 64 's')
    tr <- newFileTracer (TraceCfg True store True 64)
    let cfg = defaultConfig
          { cfgStorage = (cfgStorage defaultConfig)
              { scKind = StorageSQLite
              , scPath = Just (dir ++ "/missing/../store.sqlite")
              }
          }
        sa = stdAcquisition
          { saTracer = Just tr
          , saOpenStore = \_ _ -> pure (Left (StdStoreSeating AdmitTokensFull))
          }
    sp <- openStdInstanceWith sa cfg
    assertBool "refused open is NULL" (isNull sp)
    _ <- drainTracer tr
    bytes <- BC8.readFile store
    assertEqual "target bytes unchanged" 64 (BC8.length bytes)
    drops <- droppedTraces tr
    assertEqual "the skipped row is counted" 1 drops

-- | A store path the guard cannot resolve for non-absence reasons
-- (here ENOTDIR through a regular file) fails closed: no trace
-- file appears and the drop is counted.
caseUnprovenSkipped :: IO ()
caseUnprovenSkipped =
  withAliasScratch $ \_dir store trace -> do
    BC8.writeFile store (BC8.replicate 64 's')
    tr <- newFileTracer (TraceCfg True trace True 64)
    let cfg = defaultConfig
          { cfgStorage = (cfgStorage defaultConfig)
              { scKind = StorageSQLite
              , scPath = Just (store ++ "/child.sqlite")
              }
          }
        sa = stdAcquisition
          { saTracer = Just tr
          , saOpenStore = \_ _ -> pure (Left (StdStoreSeating AdmitTokensFull))
          }
    sp <- openStdInstanceWith sa cfg
    assertBool "refused open is NULL" (isNull sp)
    _ <- drainTracer tr
    exists <- doesFileExist trace
    assertBool "no trace file created" (not exists)
    drops <- droppedTraces tr
    assertEqual "the skipped row is counted" 1 drops

-- | A store whose parent is missing (pure absence, no unproven
-- leg) keeps a distinct row: the missing files are evidence of
-- distinct destinations, not a reason to drop.
caseMissingParentEmits :: IO ()
caseMissingParentEmits =
  withAliasScratch $ \dir _store trace -> do
    tr <- newFileTracer (TraceCfg True trace True 64)
    let cfg = defaultConfig
          { cfgStorage = (cfgStorage defaultConfig)
              { scKind = StorageSQLite
              , scPath = Just (dir ++ "/nodir/store.sqlite")
              }
          }
        sa = stdAcquisition
          { saTracer = Just tr
          , saOpenStore = \_ _ -> pure (Left (StdStoreSeating AdmitTokensFull))
          }
    sp <- openStdInstanceWith sa cfg
    assertBool "refused open is NULL" (isNull sp)
    _ <- drainTracer tr
    content <- readFile trace
    assertBool "row names the entry" ("\"function\":\"C_Initialize\"," `isInfixOf` content)
    drops <- droppedTraces tr
    assertEqual "no drops" 0 drops

-- | Bind-mounted alias: two names for one directory, journal absent
-- under both spellings. String resolution cannot see the shared
-- directory object, but the parent-identity leg matches — no
-- journal appears and the drop is counted. Needs
-- HASKOKI_ALIAS_BIND_SRC (an existing store file) and
-- HASKOKI_ALIAS_BIND_DST (the missing journal path through the
-- other mount); vacuous otherwise. Exercise under e.g.
-- `unshare -rm` with `mount --bind`.
caseBindMountSkipped :: IO ()
caseBindMountSkipped = do
  mSrc <- lookupEnv "HASKOKI_ALIAS_BIND_SRC"
  mDst <- lookupEnv "HASKOKI_ALIAS_BIND_DST"
  case (mSrc, mDst) of
    (Just store, Just journal) -> do
      tr <- newFileTracer (TraceCfg True journal True 64)
      let cfg = defaultConfig
            { cfgStorage = (cfgStorage defaultConfig)
                { scKind = StorageSQLite
                , scPath = Just store
                }
            }
          sa = stdAcquisition
            { saTracer = Just tr
            , saOpenStore = \_ _ -> pure (Left (StdStoreSeating AdmitTokensFull))
            }
      sp <- openStdInstanceWith sa cfg
      assertBool "refused open is NULL" (isNull sp)
      _ <- drainTracer tr
      exists <- doesFileExist journal
      assertBool "no journal created through the bind" (not exists)
      drops <- droppedTraces tr
      assertEqual "the skipped row is counted" 1 drops
    _ -> assertBool "bind-mount test needs HASKOKI_ALIAS_BIND_SRC/DST (not exercised)" True

-- | A trace path dangling through a symlink at a shadow: the sink
-- would follow the link and create the store's journal, so the
-- guard resolves the link first — nothing appears and the drop
-- is counted.
caseDanglingSkipped :: IO ()
caseDanglingSkipped =
  withAliasScratch $ \dir store _trace -> do
    let link = dir ++ "/link.jsonl"
        journal = store ++ "-journal"
    createSymbolicLink journal link
    tr <- newFileTracer (TraceCfg True link True 64)
    let cfg = defaultConfig
          { cfgStorage = (cfgStorage defaultConfig)
              { scKind = StorageSQLite
              , scPath = Just store
              }
          }
        sa = stdAcquisition
          { saTracer = Just tr
          , saOpenStore = \_ _ -> pure (Left (StdStoreSeating AdmitTokensFull))
          }
    sp <- openStdInstanceWith sa cfg
    assertBool "refused open is NULL" (isNull sp)
    _ <- drainTracer tr
    exists <- doesFileExist journal
    assertBool "no journal created through the link" (not exists)
    drops <- droppedTraces tr
    assertEqual "the skipped row is counted" 1 drops

-- | A trace leaf differing only by case: casefolded filesystems
-- would alias it, so the guard matches case-insensitively (and
-- over-blocks on sensitive filesystems by design) — nothing
-- appears and the drop is counted.
caseVariantSkipped :: IO ()
caseVariantSkipped =
  withAliasScratch $ \dir store _trace -> do
    let upper = dir ++ "/STORE.SQLITE"
    tr <- newFileTracer (TraceCfg True upper True 64)
    let cfg = defaultConfig
          { cfgStorage = (cfgStorage defaultConfig)
              { scKind = StorageSQLite
              , scPath = Just store
              }
          }
        sa = stdAcquisition
          { saTracer = Just tr
          , saOpenStore = \_ _ -> pure (Left (StdStoreSeating AdmitTokensFull))
          }
    sp <- openStdInstanceWith sa cfg
    assertBool "refused open is NULL" (isNull sp)
    _ <- drainTracer tr
    exists <- doesFileExist upper
    assertBool "no trace file created" (not exists)
    drops <- droppedTraces tr
    assertEqual "the skipped row is counted" 1 drops

-- | A @file:@ URI store guards the decoded spelling SQLite opens,
-- not just the literal: a trace at the decoded path must skip.
caseUriDecodedSkipped :: IO ()
caseUriDecodedSkipped =
  withAliasScratch $ \_dir store _trace -> do
    tr <- newFileTracer (TraceCfg True store True 64)
    let cfg = defaultConfig
          { cfgStorage = (cfgStorage defaultConfig)
              { scKind = StorageSQLite
              , scPath = Just ("file:" ++ store)
              }
          }
        sa = stdAcquisition
          { saTracer = Just tr
          , saOpenStore = \_ _ -> pure (Left (StdStoreSeating AdmitTokensFull))
          }
    sp <- openStdInstanceWith sa cfg
    assertBool "refused open is NULL" (isNull sp)
    _ <- drainTracer tr
    exists <- doesFileExist store
    assertBool "no trace file created at the decoded path" (not exists)
    drops <- droppedTraces tr
    assertEqual "the skipped row is counted" 1 drops

-- | Drain with the deadline enforced outside the sink's failure
-- handler: 'timeout' delivers asynchronously, but 'Timeout' is
-- not an 'AsyncException' subtype, so 'trySync' would catch it
-- as a sink failure, masking a hang as an expected report.
drainTimed :: Tracer -> IO (Maybe DrainReport)
drainTimed tr = do
  repVar <- newEmptyMVar
  bracket (forkIO (drainTracer tr >>= putMVar repVar)) killThread $ \_ ->
    timeout 5000000 (takeMVar repVar)

-- | Draining to a readerless FIFO returns (fail-fast) instead of
-- stalling the caller: the refusal drain runs synchronously
-- under the initialization lock. Both sinks fail here (no
-- reader is an immediate error); the connected-full case below
-- is the one that discriminates the non-blocking sink.
caseFifoDrainReturns :: IO ()
caseFifoDrainReturns =
  withAliasScratch $ \_dir store trace -> do
    createNamedPipe trace 0o644
    tr <- newFileTracer (TraceCfg True trace True 64)
    let cfg = defaultConfig
          { cfgStorage = (cfgStorage defaultConfig)
              { scKind = StorageSQLite
              , scPath = Just store
              }
          }
        sa = stdAcquisition
          { saTracer = Just tr
          , saOpenStore = \_ _ -> pure (Left (StdStoreSeating AdmitTokensFull))
          }
    sp <- openStdInstanceWith sa cfg
    assertBool "refused open is NULL" (isNull sp)
    mRep <- drainTimed tr
    case mRep of
      Nothing -> assertFailure "drain blocked on a readerless FIFO"
      Just rep -> assertEqual "failed write counted" (DrainReport 0 1) rep

-- | Draining to a connected-but-full FIFO returns instead of
-- stalling on pipe capacity: the reader holds the pipe open
-- without draining, so a blocking sink would wait forever.
-- Every row resolves (written or counted) and backpressure
-- shows as failures.
caseFifoFullReturns :: IO ()
caseFifoFullReturns =
  withAliasScratch $ \_dir store trace -> do
    createNamedPipe trace 0o644
    bracket (openFd trace ReadOnly (defaultFileFlags { nonBlock = True, cloexec = True })) closeFd $ \_reader -> do
      tr <- newFileTracer (TraceCfg True trace True 8192)
      let cfg = defaultConfig
            { cfgStorage = (cfgStorage defaultConfig)
                { scKind = StorageSQLite
                , scPath = Just store
                }
            }
          sa = stdAcquisition
            { saTracer = Just tr
            , saOpenStore = \_ _ -> pure (Left (StdStoreSeating AdmitTokensFull))
            }
      replicateM_ 800 $ do
        sp <- openStdInstanceWith sa cfg
        assertBool "refused open is NULL" (isNull sp)
      mRep <- drainTimed tr
      case mRep of
        Nothing -> assertFailure "drain blocked on a full FIFO"
        Just rep -> do
          assertEqual "every row resolved" 800 (drWritten rep + drFailed rep)
          assertBool "pipe filled before failing" (drWritten rep >= 1)
          assertBool "backpressure observed" (drFailed rep >= 1)
      drops <- droppedTraces tr
      assertEqual "no guard drops" 0 drops

-- | Short writes retry to completion with advancing offsets: a
-- scripted prim returning partial counts still moves every byte
-- exactly once, in order. Errors fail; a zero return fails after
-- exactly one call, without spinning. The zero case runs on a
-- worker thread with the timeout bounding only the outer wait,
-- so no Timeout can land inside the prim: a swallowed Timeout
-- cannot explain the False.
caseShortWriteRetries :: IO ()
caseShortWriteRetries = do
  allocaBytes 8 $ \p0 -> do
    srcRef <- newIORef "abcdefgh"
    dstRef <- newIORef ""
    offRef <- newIORef ([] :: [Int])
    scriptRef <- newIORef [3, 2, 3]
    let prim p n = do
          modifyIORef' offRef ((p `minusPtr` p0) :)
          ks <- readIORef scriptRef
          case ks of
            [] -> pure n
            (k : rest) -> do
              writeIORef scriptRef rest
              src <- readIORef srcRef
              let (move, keep) = splitAt k src
              writeIORef srcRef keep
              modifyIORef' dstRef (++ move)
              pure k
    ok <- writeFully prim p0 8
    assertBool "scripted shorts complete" ok
    dst <- readIORef dstRef
    assertEqual "every byte moved once, in order" "abcdefgh" dst
    offs <- readIORef offRef
    assertEqual "offsets advance" [0, 3, 5] (reverse offs)
  allocaBytes 4 $ \p0 -> do
    okErr <- writeFully (\_ _ -> ioError (userError "boom")) p0 4
    assertBool "errors fail" (not okErr)
    zeroCalls <- newIORef (0 :: Int)
    spinless <- newEmptyMVar
    let prim _ _ = modifyIORef' zeroCalls (+ 1) >> pure 0
    worker <- forkIO (writeFully prim p0 4 >>= putMVar spinless)
    mZero <- timeout 5000000 (takeMVar spinless)
    case mZero of
      Nothing -> killThread worker >> assertFailure "zero return spun instead of failing"
      Just okZero -> do
        assertBool "zero return fails" (not okZero)
        calls <- readIORef zeroCalls
        assertEqual "zero return calls the prim exactly once" 1 calls

-- | Percent-escapes decode as UTF-8 bytes (what SQLite opens), not
-- per byte into Latin-1: `%C3%A9` must match a literal é in the
-- trace path — nothing appears and the drop is counted.
caseUriPercentDecoded :: IO ()
caseUriPercentDecoded =
  withAliasScratch $ \dir _store _trace -> do
    let trace = dir ++ "/café.sqlite"
    tr <- newFileTracer (TraceCfg True trace True 64)
    let cfg = defaultConfig
          { cfgStorage = (cfgStorage defaultConfig)
              { scKind = StorageSQLite
              , scPath = Just ("file:" ++ dir ++ "/caf%C3%A9.sqlite")
              }
          }
        sa = stdAcquisition
          { saTracer = Just tr
          , saOpenStore = \_ _ -> pure (Left (StdStoreSeating AdmitTokensFull))
          }
    sp <- openStdInstanceWith sa cfg
    assertBool "refused open is NULL" (isNull sp)
    _ <- drainTracer tr
    exists <- doesFileExist trace
    assertBool "no trace file created" (not exists)
    drops <- droppedTraces tr
    assertEqual "the skipped row is counted" 1 drops

-- | A decoded escape introducing dot-dot components normalizes the
-- way the opener normalizes: the guard compares the normalized
-- spelling, not the raw decoded text. Uses %2E%2E (not plain
-- ..) so decoding introduces the component — plain .. would
-- already normalize in the first resolution.
caseUriDotDotSkipped :: IO ()
caseUriDotDotSkipped =
  withAliasScratch $ \dir store _trace -> do
    tr <- newFileTracer (TraceCfg True store True 64)
    let cfg = defaultConfig
          { cfgStorage = (cfgStorage defaultConfig)
              { scKind = StorageSQLite
              , scPath = Just ("file:" ++ dir ++ "/missing/%2E%2E/store.sqlite")
              }
          }
        sa = stdAcquisition
          { saTracer = Just tr
          , saOpenStore = \_ _ -> pure (Left (StdStoreSeating AdmitTokensFull))
          }
    sp <- openStdInstanceWith sa cfg
    assertBool "refused open is NULL" (isNull sp)
    _ <- drainTracer tr
    exists <- doesFileExist store
    assertBool "no trace file created at the normalized path" (not exists)
    drops <- droppedTraces tr
    assertEqual "the skipped row is counted" 1 drops

-- | A NUL escape in a URI store drops: SQLite truncates at NUL
-- while pure string processing would keep the suffix, so no
-- decoded spelling is trustworthy — the existing target (what
-- SQLite opens) keeps its bytes and the drop is counted.
caseUriNulSkipped :: IO ()
caseUriNulSkipped =
  withAliasScratch $ \dir _store _trace -> do
    let target = dir ++ "/x"
    BC8.writeFile target (BC8.replicate 64 's')
    tr <- newFileTracer (TraceCfg True target True 64)
    let cfg = defaultConfig
          { cfgStorage = (cfgStorage defaultConfig)
              { scKind = StorageSQLite
              , scPath = Just ("file:" ++ dir ++ "/x%00")
              }
          }
        sa = stdAcquisition
          { saTracer = Just tr
          , saOpenStore = \_ _ -> pure (Left (StdStoreSeating AdmitTokensFull))
          }
    sp <- openStdInstanceWith sa cfg
    assertBool "refused open is NULL" (isNull sp)
    _ <- drainTracer tr
    bytes <- BC8.readFile target
    assertEqual "target bytes unchanged" 64 (BC8.length bytes)
    drops <- droppedTraces tr
    assertEqual "the skipped row is counted" 1 drops

-- | An undecodable file: URI (SQLite keeps a bare % literally)
-- fails closed: the guard cannot place the effective file, so
-- the row is skipped and counted instead of risking the
-- literal-kept location.
caseUriUndecodableSkipped :: IO ()
caseUriUndecodableSkipped =
  withAliasScratch $ \_dir store _trace -> do
    let kept = store ++ "-kept%ger"
    tr <- newFileTracer (TraceCfg True kept True 64)
    let cfg = defaultConfig
          { cfgStorage = (cfgStorage defaultConfig)
              { scKind = StorageSQLite
              , scPath = Just ("file:" ++ kept)
              }
          }
        sa = stdAcquisition
          { saTracer = Just tr
          , saOpenStore = \_ _ -> pure (Left (StdStoreSeating AdmitTokensFull))
          }
    sp <- openStdInstanceWith sa cfg
    assertBool "refused open is NULL" (isNull sp)
    _ <- drainTracer tr
    exists <- doesFileExist kept
    assertBool "no trace file created at the kept-literal path" (not exists)
    drops <- droppedTraces tr
    assertEqual "the skipped row is counted" 1 drops

-- | A @./file:@ spelling has no URI prefix until resolution drops
-- the dot: the guard tests the RESOLVED spelling (what SQLite
-- receives), so the decoded location matches — nothing appears
-- and the drop is counted. (Unique names in the runner's
-- directory, removed afterwards either way.)
caseUriDotSlashSkipped :: IO ()
caseUriDotSlashSkipped = do
  cwd <- getCurrentDirectory
  t <- getMonotonicTimeNSec
  let name = "y1-" ++ show t ++ "-store"
      trace = cwd ++ "/" ++ name
      cleanup = do
        _ <- try (removeFile trace) :: IO (Either IOException ())
        pure ()
  bracket (pure ()) (const cleanup) $ \_ -> do
    tr <- newFileTracer (TraceCfg True trace True 64)
    let cfg = defaultConfig
          { cfgStorage = (cfgStorage defaultConfig)
              { scKind = StorageSQLite
              , scPath = Just ("./file:" ++ name)
              }
          }
        sa = stdAcquisition
          { saTracer = Just tr
          , saOpenStore = \_ _ -> pure (Left (StdStoreSeating AdmitTokensFull))
          }
    sp <- openStdInstanceWith sa cfg
    assertBool "refused open is NULL" (isNull sp)
    _ <- drainTracer tr
    exists <- doesFileExist trace
    assertBool "no trace file created at the decoded path" (not exists)
    drops <- droppedTraces tr
    assertEqual "the skipped row is counted" 1 drops

-- | A procfs descriptor link keeps the store inode reachable after
-- its name is gone: the identity leg reads the ORIGINAL trace
-- path (which follows the magic link), not the resolved text
-- (which stats missing). The survivor hardlink's bytes stay
-- put and the drop is counted. Linux-only; vacuous elsewhere.
caseMagicLinkSkipped :: IO ()
caseMagicLinkSkipped = do
  hasProc <- doesDirectoryExist "/proc/self/fd"
  if not hasProc
    then assertBool "no /proc/self/fd (not exercised)" True
    else withAliasScratch $ \dir store _trace -> do
      let survivor = store ++ ".live"
      BC8.writeFile store (BC8.replicate 64 's')
      createLink store survivor
      cDir <- canonicalizePath dir
      bracket (openFile store ReadMode) hClose $ \_h -> do
        removeFile store
        mLink <- findProcFd (cDir ++ "/store.sqlite")
        case mLink of
          Nothing -> assertFailure "test setup lost the descriptor link"
          Just link -> do
            tr <- newFileTracer (TraceCfg True link True 64)
            let cfg = defaultConfig
                  { cfgStorage = (cfgStorage defaultConfig)
                      { scKind = StorageSQLite
                      , scPath = Just survivor
                      }
                  }
                sa = stdAcquisition
                  { saTracer = Just tr
                  , saOpenStore = \_ _ -> pure (Left (StdStoreSeating AdmitTokensFull))
                  }
            sp <- openStdInstanceWith sa cfg
            assertBool "refused open is NULL" (isNull sp)
            _ <- drainTracer tr
            bytes <- BC8.readFile survivor
            assertEqual "survivor bytes unchanged" 64 (BC8.length bytes)
            drops <- droppedTraces tr
            assertEqual "the skipped row is counted" 1 drops
  where
    findProcFd want = do
      fds <- listDirectory "/proc/self/fd"
      found <- mapM (tryReadlink want) fds
      pure (listToMaybe ["/proc/self/fd/" ++ fd | (fd, True) <- zip fds found])
    tryReadlink want fd = do
      r <- try (readSymbolicLink ("/proc/self/fd/" ++ fd)) :: IO (Either IOException FilePath)
      pure $ case r of
        Right dest -> want `isPrefixOf` dest
        Left _ -> False

-- | Casefold twins (ß vs SS) match on the leaf leg: nothing
-- appears and the drop is counted. (On a case-sensitive
-- filesystem this over-blocks by design.)
caseCasefoldSkipped :: IO ()
caseCasefoldSkipped =
  withAliasScratch $ \dir _store _trace -> do
    let trace = dir ++ "/STRASSE.SQLITE"
    tr <- newFileTracer (TraceCfg True trace True 64)
    let cfg = defaultConfig
          { cfgStorage = (cfgStorage defaultConfig)
              { scKind = StorageSQLite
              , scPath = Just (dir ++ "/straße.sqlite")
              }
          }
        sa = stdAcquisition
          { saTracer = Just tr
          , saOpenStore = \_ _ -> pure (Left (StdStoreSeating AdmitTokensFull))
          }
    sp <- openStdInstanceWith sa cfg
    assertBool "refused open is NULL" (isNull sp)
    _ <- drainTracer tr
    exists <- doesFileExist trace
    assertBool "no trace file created" (not exists)
    drops <- droppedTraces tr
    assertEqual "the skipped row is counted" 1 drops

-- | A trace destination naming a dangling sidecar link's missing
-- target through a differently-resolved spelling (here a
-- case variant; the bind-mount shape is the env-gated twin
-- below): the full-identity legs cannot see the alias, so the
-- guard resolves sidecar links and the parent-identity leg
-- matches the target — nothing appears and the drop is counted.
-- (On a case-sensitive filesystem this over-blocks by design,
-- like 'caseVariantSkipped': the variant would be a distinct
-- file, but on a folding filesystem it IS the target.)
caseShadowDanglingSkipped :: IO ()
caseShadowDanglingSkipped =
  withAliasScratch $ \dir store _trace -> do
    let wal = store ++ "-wal"
        ghost = dir ++ "/GHOST.JSONL"
    createSymbolicLink (dir ++ "/ghost.jsonl") wal
    tr <- newFileTracer (TraceCfg True ghost True 64)
    let cfg = defaultConfig
          { cfgStorage = (cfgStorage defaultConfig)
              { scKind = StorageSQLite
              , scPath = Just store
              }
          }
        sa = stdAcquisition
          { saTracer = Just tr
          , saOpenStore = \_ _ -> pure (Left (StdStoreSeating AdmitTokensFull))
          }
    sp <- openStdInstanceWith sa cfg
    assertBool "refused open is NULL" (isNull sp)
    _ <- drainTracer tr
    exists <- doesFileExist ghost
    assertBool "no trace file created at the variant spelling" (not exists)
    drops <- droppedTraces tr
    assertEqual "the skipped row is counted" 1 drops

-- | The G2 shape through a bind mount: the trace names the
-- dangling target through the other mount, so only the
-- parent-identity leg (on the resolved sidecar target) can match.
-- Needs HASKOKI_ALIAS_BIND_DANGLING_STORE (a store whose -wal is
-- a dangling symlink to the ghost) and
-- HASKOKI_ALIAS_BIND_DANGLING_GHOST (the ghost through the other
-- mount); vacuous otherwise. Exercise under e.g. `unshare -rm`
-- with `mount --bind`.
caseBindMountDanglingSkipped :: IO ()
caseBindMountDanglingSkipped = do
  mStore <- lookupEnv "HASKOKI_ALIAS_BIND_DANGLING_STORE"
  mGhost <- lookupEnv "HASKOKI_ALIAS_BIND_DANGLING_GHOST"
  case (mStore, mGhost) of
    (Just store, Just ghost) -> do
      tr <- newFileTracer (TraceCfg True ghost True 64)
      let cfg = defaultConfig
            { cfgStorage = (cfgStorage defaultConfig)
                { scKind = StorageSQLite
                , scPath = Just store
                }
            }
          sa = stdAcquisition
            { saTracer = Just tr
            , saOpenStore = \_ _ -> pure (Left (StdStoreSeating AdmitTokensFull))
            }
      sp <- openStdInstanceWith sa cfg
      assertBool "refused open is NULL" (isNull sp)
      _ <- drainTracer tr
      exists <- doesFileExist ghost
      assertBool "no ghost created through either mount" (not exists)
      drops <- droppedTraces tr
      assertEqual "the skipped row is counted" 1 drops
    _ -> assertBool "bind-mount dangling test needs HASKOKI_ALIAS_BIND_DANGLING_STORE/GHOST (not exercised)" True

-- | A store under an undecodable directory name, spelled with
-- surrogate escapes (as argv/readdir produce): POSIX lookups
-- round-trip them to the true bytes while the SQLite opener's
-- Text round-trip replaces them, so the guard cannot compare
-- what SQLite opens — the row drops, the true bytes stay put,
-- and nothing appears at the mangled spelling.
caseSurrogatePathSkipped :: IO ()
caseSurrogatePathSkipped =
  withAliasScratch $ \dir _store _trace -> do
    let rawSub = BC8.pack (dir ++ "/d") <> BS.singleton 0xFF
        mangledSub = dir ++ "/d\xFFFD"
        rawStore = rawSub <> BC8.pack "/store.sqlite"
        storeArg = dir ++ "/d\xDCFF/store.sqlite"
        traceArg = mangledSub ++ "/trace.jsonl"
    BDir.createDirectory rawSub 0o700
    createDirectory mangledSub
    bracket (BIO.openFd rawStore WriteOnly defaultFileFlags { creat = Just 0o600 })
      closeFd
      (\fd -> BIO.fdWrite fd (BC8.replicate 64 's') >> pure ())
    tr <- newFileTracer (TraceCfg True traceArg True 64)
    let cfg = defaultConfig
          { cfgStorage = (cfgStorage defaultConfig)
              { scKind = StorageSQLite
              , scPath = Just storeArg
              }
          }
        sa = stdAcquisition
          { saTracer = Just tr
          , saOpenStore = \_ _ -> pure (Left (StdStoreSeating AdmitTokensFull))
          }
    sp <- openStdInstanceWith sa cfg
    assertBool "refused open is NULL" (isNull sp)
    _ <- drainTracer tr
    size <- withFile storeArg ReadMode hFileSize
    assertEqual "true store bytes unchanged" 64 size
    exists <- doesFileExist traceArg
    assertBool "nothing created at the mangled spelling" (not exists)
    drops <- droppedTraces tr
    assertEqual "the skipped row is counted" 1 drops

-- | Filesystem-encoding names classify UTF-8 (verified names:
-- utf8/latin1/char8/ASCII probed live; matching is
-- case-insensitive over alphanumerics).
caseEncodingNames :: IO ()
caseEncodingNames = do
  assertBool "UTF-8 counts" (isUtf8EncodingName "UTF-8")
  assertBool "utf8 counts" (isUtf8EncodingName "utf8")
  assertBool "latin1 does not" (not (isUtf8EncodingName "ISO-8859-1"))
  assertBool "ASCII does not" (not (isUtf8EncodingName "ASCII"))

-- | The drop quadrants: ASCII-only spellings never drop (they
-- encode identically on ASCII-compatible filesystem encodings);
-- non-ASCII spellings drop exactly when the filesystem encoding
-- is not UTF-8.
caseEncodingDropQuadrants :: IO ()
caseEncodingDropQuadrants = do
  assertBool "ascii+utf8 proceeds" (not (shouldDropForEncoding True "/a" "/b"))
  assertBool "ascii+latin1 proceeds" (not (shouldDropForEncoding False "/a" "/b"))
  assertBool "non-ascii+utf8 proceeds" (not (shouldDropForEncoding True "/caf\xe9" "/b"))
  assertBool "non-ascii trace+latin1 drops" (shouldDropForEncoding False "/b" "/caf\xe9/x")
  assertBool "non-ascii store+latin1 drops" (shouldDropForEncoding False "/caf\xe9" "/b")

-- | The guard with a simulated non-UTF-8 filesystem drops
-- non-ASCII spellings (direct-sqlite would open different
-- bytes), and proceeds when UTF-8 is simulated: the probe is
-- injected because it reads process-global state. Uses real
-- UTF-8-byte files under the ambient encoding.
caseLatin1Drop :: IO ()
caseLatin1Drop =
  withAliasScratch $ \dir _store _trace -> do
    let rawSub = BC8.pack (dir ++ "/d") <> BS.pack [0xC3, 0xA9]
        storeBytes = rawSub <> BC8.pack "/store.sqlite"
        storeArg = dir ++ "/d\xe9/store.sqlite"
        traceArg = dir ++ "/d\xe9/trace.jsonl"
    BDir.createDirectory rawSub 0o700
    bracket (BIO.openFd storeBytes WriteOnly defaultFileFlags { creat = Just 0o600 })
      closeFd
      (\fd -> BIO.fdWrite fd (BC8.replicate 64 's') >> pure ())
    tr <- newFileTracer (TraceCfg True traceArg True 64)
    dropIt <- tracerAliasesStoreWith (pure False) tr storeArg
    assertBool "simulated latin1 drops" dropIt
    enc <- getFileSystemEncoding
    if isUtf8EncodingName (textEncodingName enc)
      then do
        keepIt <- tracerAliasesStoreWith (pure True) tr storeArg
        assertBool "simulated UTF-8 proceeds" (not keepIt)
      else assertBool "proceed control needs a UTF-8 filesystem (not exercised)" True

-- | Pre-resolve spelling drops: surrogates always drop (either
-- probe); non-ASCII drops exactly without UTF-8; ASCII proceeds
-- under both probes.
caseSpellingDrops :: IO ()
caseSpellingDrops = do
  surrogateUtf8 <- spellingDropsWith (pure True) "/d\xDCFF/x"
  assertBool "surrogate drops under UTF-8" surrogateUtf8
  surrogateLatin <- spellingDropsWith (pure False) "/d\xDCFF/x"
  assertBool "surrogate drops under latin1" surrogateLatin
  uniUtf8 <- spellingDropsWith (pure True) "/caf\xe9/x"
  assertBool "non-ASCII proceeds under UTF-8" (not uniUtf8)
  uniLatin <- spellingDropsWith (pure False) "/caf\xe9/x"
  assertBool "non-ASCII drops under latin1" uniLatin
  asciiLatin <- spellingDropsWith (pure False) "/plain/x"
  assertBool "ASCII proceeds under latin1" (not asciiLatin)

-- | A surrogate spelling resolving through a symlink to clean
-- ASCII: the guard would only see the resolved spelling, so the
-- caller checks the raw spelling first — the row drops and
-- nothing is created.
caseRawSurrogateLinkSkipped :: IO ()
caseRawSurrogateLinkSkipped =
  withAliasScratch $ \dir store trace -> do
    let rawSub = BC8.pack (dir ++ "/d") <> BS.singleton 0xFF
        storeArg = dir ++ "/d\xDCFF/link.sqlite"
    BDir.createDirectory rawSub 0o700
    createSymbolicLink store storeArg
    tr <- newFileTracer (TraceCfg True trace True 64)
    let cfg = defaultConfig
          { cfgStorage = (cfgStorage defaultConfig)
              { scKind = StorageSQLite
              , scPath = Just storeArg
              }
          }
        sa = stdAcquisition
          { saTracer = Just tr
          , saOpenStore = \_ _ -> pure (Left (StdStoreSeating AdmitTokensFull))
          }
    sp <- openStdInstanceWith sa cfg
    assertBool "refused open is NULL" (isNull sp)
    _ <- drainTracer tr
    exists <- doesFileExist trace
    assertBool "no trace file created" (not exists)
    drops <- droppedTraces tr
    assertEqual "the skipped row is counted" 1 drops

-- | Readers flapping while rows sink through a FIFO: a held
-- reader writes all rows, no reader fails all rows fast at open,
-- and flapping resolves every row — none lost to termination —
-- even with SIG_DFL installed (as a host may restore after RTS
-- startup), because the sink holds its own reader across each
-- open and its writes. The host disposition is never touched,
-- so foreign C handlers survive. (Pre-fix termination with
-- signal 13 was reproduced at the syscall level during review;
-- masking alone cannot fix it — a blocked SIGPIPE stays pending
-- and delivers on unmask.)
caseFifoEpipeMasked :: IO ()
caseFifoEpipeMasked =
  withAliasScratch $ \dir _store _trace -> do
    let fifo = dir ++ "/pipe"
        row = BC8.pack "{\"r\":1}"
        sink = fileSink (TraceCfg True fifo True 64) row
    createNamedPipe fifo 0o644
    oldH <- installHandler sigPIPE Default Nothing
    finally
      (do
        held <- openFd fifo ReadOnly defaultFileFlags { nonBlock = True, cloexec = True }
        r1 <- replicateM 10 sink
        closeFd held
        assertBool "held reader writes all" (all isRight r1)
        r2 <- replicateM 10 sink
        assertBool "readerless fails all" (all isLeft r2)
        stopVar <- newEmptyMVar
        let flap = do
              stopped <- tryTakeMVar stopVar
              case stopped of
                Just () -> pure ()
                Nothing -> do
                  r <- openFd fifo ReadOnly defaultFileFlags { nonBlock = True, cloexec = True }
                  closeFd r
                  flap
        flapper <- forkIO flap
        r3 <- replicateM 200 sink
        putMVar stopVar ()
        killThread flapper
        assertEqual "every flapping row resolved" 200 (length r3)
        h2 <- installHandler sigPIPE Default Nothing
        case h2 of
          Default -> pure ()
          _ -> assertFailure "host disposition was touched")
      (installHandler sigPIPE oldH Nothing >> pure ())

-- | The held reader is close-on-exec: a child forked+exec'd
-- mid-hold must not retain it (a retained reader would let
-- later writes succeed after the collector is gone). The child
-- signals twice (before and after its own exec), so liveness at
-- check time proves an exec'd sleeper rather than a dying shell;
-- the parent closes its own writer first, so a child that fails
-- before signaling ends the read at EOF instead of hanging it;
-- and the sync pipe itself is close-on-exec, so unrelated
-- children cannot wedge the read. Only ENXIO proves no reader
-- remains (any other open failure fails the case), and the
-- fixture mode is pinned against umask surprises.
caseFifoHolderCloexec :: IO ()
caseFifoHolderCloexec =
  retryOnSpawnFlake $ withAliasScratch $ \dir _store _trace -> do
    let fifo = dir ++ "/pipe"
    createNamedPipe fifo 0o644
    setFileMode fifo 0o600
    -- Outer mask + nested finallys + late restore: the
    -- reader/child finally installs immediately after createPipe
    -- (a setFdOption throw must not strand the fresh pipe), and a
    -- nested finally around setup+fork closes the writer exactly
    -- once — on success (same point as an explicit close, O2
    -- preserved) and on any setup failure (fork EAGAIN,
    -- holder-close EIO) — before restore runs the reads and
    -- assertions. The shared release runs its cleanup
    -- uninterruptibly (bounded: microseconds naturally, 200
    -- attempts with 5 ms delays worst-case fault-only) with the
    -- reader close in its own nested finally, so a cancel landing
    -- mid-cleanup cannot strand the reader. No stdout I/O happens
    -- anywhere on this path (even a buffered diagnostic would
    -- wedge the exit-time flush). The pid is recorded inside the
    -- held callback while masked, so even a holder-close throw
    -- finds it for cleanup. Zero descriptor leaks on every path,
    -- fault-injected throws included; exactly one close per fd
    -- per attempt, and nothing else closes them.
    mask $ \restore -> do
      (rSync, wSync) <- createPipe
      pidRef <- newIORef Nothing
      flip finally (releaseForkTest pidRef rSync) $ do
        p <- flip finally (closeFd wSync) $ do
          _ <- setFdOption rSync CloseOnExec True
          _ <- setFdOption wSync CloseOnExec True
          withReaderHeld True fifo $ do
            q <- forkProcess $ do
              _ <- dupTo wSync stdOutput
              -- Unlike the sync-pin test (which must keep its writer open
              -- pre-exec so the count pins that flag too), this child
              -- drops the duplicate: only the holder's absence is probed
              -- here, and fewer inherited writers is strictly safer.
              closeFd wSync
              executeFile "sh" True ["-c", "echo READY; exec sh -c \"echo ALIVE; exec sleep 30\""] Nothing
            writeIORef pidRef (Just q)
            pure q
        restore $ do
          ready <- readSyncFirst p rSync 6
          assertEqual "child exec'd" (BC8.pack "READY\n") ready
          alive <- readSyncFirst p rSync 6
          assertEqual "child re-exec'd" (BC8.pack "ALIVE\n") alive
          -- ALIVE is written pre-sleep-exec, so wait until the child IS
          -- sleep: liveness-then-probe on a still-starting shell could
          -- pass with sleep missing from PATH (ALIVE arrives, the check
          -- wins the race, the exec fails after). A dead child fails
          -- here loudly instead of probing a zombie.
          waitForComm p "sleep"
          eWriter <- try (openFd fifo WriteOnly defaultFileFlags { nonBlock = True, cloexec = True }) :: IO (Either IOException Fd)
          st <- getProcessStatus False False p
          assertBool "child alive at check" (st == Nothing)
          case eWriter of
            Left io -> assertBool "no reader remains (ENXIO)" (isEnxio io)
            Right w -> closeFd w >> assertFailure "exec'd child retained the holder"
          cleanupChild p
          assertReaped p
  where
    isEnxio io = case ioe_errno io of
      Just n -> Errno n == eNXIO
      Nothing -> False

-- | Retry a fork+exec case on the spawn-flake signature only:
-- under full-suite parallel load the fork child can fail before
-- signaling ("failed to create OS thread", exit 1) when the
-- machine is out of threads, which surfaces as EOF on the sync
-- read. The RETRY COUNT is bounded (5 attempts 100ms apart, logged);
-- the read wait itself is bounded separately by 'readSyncFirst'.
-- Assertion failures are not IOExceptions and propagate on first
-- attempt. EOF arrives with its zombie already reaped and our
-- reader already closed (see 'readSyncFirst'), so a retry leaks
-- nothing and starts from a fresh scratch. Depth 5 covers
-- multi-hundred-ms pressure windows: a 3-exhaustion (three
-- consecutive failed children) was observed live under full-suite
-- load; see 'caseRetryDepth'.
retryOnSpawnFlake :: IO a -> IO a
retryOnSpawnFlake = retryOnSpawnFlakeWith putStrLn

-- | 'retryOnSpawnFlake' with an injected diagnostic sink. Production
-- callers log to stdout (flake forensics); the depth test collects
-- the lines instead, so it never touches stdout itself.
retryOnSpawnFlakeWith :: (String -> IO ()) -> IO a -> IO a
retryOnSpawnFlakeWith logLine act = go (5 :: Int)
  where
    go n = do
      e <- try act
      case e of
        Left io | isEOFError io && n > 1 -> do
          logLine ("spawn-flake retry (" ++ show (6 - n) ++ "/5, EOF)")
          threadDelay 100000
          go (n - 1)
        Left io -> ioError io
        Right v -> pure v

-- | The spawn-flake retry absorbs sustained thread-pressure windows:
-- a persistently-EOF action is attempted exactly five times (100ms
-- apart) before the EOF propagates; anything else propagates on the
-- first attempt. Regression test for a 3-exhaustion observed live
-- (three consecutive "failed to create OS thread" children under
-- full-suite load). Deterministic: EOF comes from /dev/null, which
-- has no writers by construction — no pipe, no fork interaction, no
-- create-then-flag window for a concurrent foreign fork to exploit.
-- The retry diagnostics go to a collecting logger (zero stdout —
-- the test must not stall on a full pipe). The null fd is opened
-- O_CLOEXEC-atomically under plain bracket (masked acquire,
-- guaranteed close, cancel-safe body).
caseRetryDepth :: IO ()
caseRetryDepth =
  bracket (openFd "/dev/null" ReadOnly defaultFileFlags { cloexec = True }) closeFd $ \nullFd -> do
    logLines <- newIORef ([] :: [String])
    count <- newIORef (0 :: Int)
    let quiet = retryOnSpawnFlakeWith (\line -> modifyIORef' logLines (line :))
    eEof <- try (quiet (do
      modifyIORef' count (+ 1)
      _ <- BIO.fdRead nullFd 6
      pure ())) :: IO (Either IOException ())
    n <- readIORef count
    assertEqual "EOF retried to exhaustion" 5 n
    ls <- readIORef logLines
    assertEqual "four retry labels"
      [ "spawn-flake retry (1/5, EOF)"
      , "spawn-flake retry (2/5, EOF)"
      , "spawn-flake retry (3/5, EOF)"
      , "spawn-flake retry (4/5, EOF)"
      ] (reverse ls)
    case eEof of
      Left io | isEOFError io -> pure ()
      _ -> assertFailure ("expected EOF after exhaustion, got: " ++ show eEof)
    count2 <- newIORef (0 :: Int)
    eOther <- try (retryOnSpawnFlake (do
      modifyIORef' count2 (+ 1)
      ioError (userError "boom"))) :: IO (Either IOException ())
    n2 <- readIORef count2
    assertEqual "non-EOF never retried" 1 n2
    case eOther of
      Left io | not (isEOFError io) -> pure ()
      _ -> assertFailure ("expected non-EOF passthrough, got: " ++ show eOther)

-- | Outcome of one bounded sync-pipe read (testable core behind
-- 'readSyncFirst').
data SyncReadOutcome
  = SyncGot BC8.ByteString
  | SyncError IOException
  | SyncTimeout
  deriving (Show)

-- | One sync-pipe read with a deadline (microseconds): a child
-- that is stopped (or otherwise stuck) while holding the sync
-- writer would hang an unbounded 'fdRead' forever — no data, no
-- EOF — so the deadline fails the read instead. The deadline
-- bounds a readability wait, NOT the read itself: unix issues
-- 'read' via @safe@ (not @interruptible@) FFI, so 'timeout'
-- cannot abort a blocked 'fdRead' (proven live: a STOPPED holder
-- wedged the suite 15min). 'threadWaitRead' parks on STM (which
-- the timeout can abort); the follow-up 'fdRead' then returns
-- at once — this test is the sole reader, and EOF also signals
-- readability, so the read never blocks. On EOF (usually the
-- spawn-flake signature: the child died pre-signal) the child is
-- SIGKILLed first — a no-op if already dead — because EOF means
-- only "no writers": a live child that closed its writers and
-- stopped itself would hang the blocking reap below. SIGKILL is
-- unblockable even when stopped, so the reap after it is
-- instant; then the ORIGINAL error is returned for the retry
-- to match on. This layer never closes: every caller owns its
-- reader through exactly one finally (a second close could steal
-- a recycled fd number from another thread). Production uses
-- 2s (ops take about a millisecond; tolerates 100x CI slowdown
-- with room to spare).
tryReadSyncFirst :: Int -> CPid -> Fd -> Int -> IO SyncReadOutcome
tryReadSyncFirst deadlineUs pid fd n = do
  m <- timeout deadlineUs (threadWaitRead fd)
  case m of
    Nothing -> pure SyncTimeout
    Just () -> do
      e <- try (BIO.fdRead fd (fromIntegral n)) :: IO (Either IOException BC8.ByteString)
      case e of
        Right bs -> pure (SyncGot bs)
        Left io
          | isEOFError io -> do
              signalProcess sigKILL pid
              _ <- getProcessStatus True False pid
              pure (SyncError io)
          | otherwise -> pure (SyncError io)

-- | Retry a case whose child may RTS-panic before exec under
-- full-suite thread pressure ("failed to create OS thread",
-- exit 1): 'waitForComm' then fails with "died before exec",
-- which is the same rare class the pin tests retry on via EOF.
-- Matches ONLY that message (3 attempts, logged, delayed); every
-- other failure propagates on first attempt. NOTE: message-coupled
-- to waitForComm's death branch — renaming that message silently
-- disables this retry (the flake would return visibly). A retried
-- attempt leaks nothing: the zombie is reaped by the wait itself
-- and the reader by each test's finally.
retryOnDeadSpawn :: IO () -> IO ()
retryOnDeadSpawn act = go (3 :: Int)
  where
    go n = do
      e <- try act :: IO (Either HUnitFailure ())
      case e of
        Right () -> pure ()
        Left err@(HUnitFailure _ reason)
          | "died before exec" `isInfixOf` reason && n > 1 -> do
              putStrLn ("dead-spawn retry (" ++ show (4 - n) ++ "/3)")
              threadDelay 50000
              go (n - 1)
          | otherwise -> throwIO err

-- | Throwing wrapper: bytes pass through, read errors rethrow
-- the original error (EOF feeds 'retryOnSpawnFlake'; anything
-- else propagates past it). Timeout best-effort cleans the stuck
-- child up before failing loud (a refused kill leaves it live
-- for the harness); like the EOF path it never closes (the
-- caller's finally release owns the reader — one close exists).
readSyncFirst :: CPid -> Fd -> Int -> IO BC8.ByteString
readSyncFirst pid fd n = do
  o <- tryReadSyncFirst 2000000 pid fd n
  case o of
    SyncGot bs -> pure bs
    SyncError io -> ioError io
    SyncTimeout -> do
      cleanupChild pid
      assertFailure "sync read timed out (child stuck holding the writer?)"

-- | Wait until a forked child has exec'd into the expected
-- image (compared by /proc comm prefix): a pre-exec child still
-- holds every inherited descriptor with cloexec pending, so any
-- fd-table inspection must wait past the exec. Fails (instead of
-- hanging) when the child dies first or the deadline passes.
waitForComm :: CPid -> String -> IO ()
waitForComm pid want = go (200 :: Int)
  where
    go 0 = assertFailure ("child never exec'd into " ++ want)
    go n = do
      -- NB: zombies keep a readable comm, so liveness is checked
      -- first: a comm poll alone would watch a dead sh (failed
      -- exec) until the deadline instead of failing on death.
      st <- getProcessStatus False False pid
      case st of
        -- NB: waitpid reaps even non-blocking, so the Just branch
        -- leaves no zombie behind (a second wait would throw ECHILD
        -- and lose this message, which the retry matches on).
        Just _ -> assertFailure ("child died before exec into " ++ want)
        Nothing -> do
          eComm <- try (BS.readFile ("/proc/" ++ show pid ++ "/comm")) :: IO (Either IOException BS.ByteString)
          case eComm of
            Right bs | want `isPrefixOf` BC8.unpack bs -> pure ()
            _ -> threadDelay 5000 >> go (n - 1)

-- | Wait until a forked child is STOPPED (state T): T proves alive
-- (zombies show Z), so reaching it proves the child ran far enough
-- to stop itself — the shape the EOF-with-live-child pin needs.
-- A dead child fails loud (message matches 'retryOnDeadSpawn'):
-- with no shell in PATH the pin fails instead of passing on an
-- EOF from a child that never lived. Deadline instead of hanging.
waitForStop :: CPid -> IO ()
waitForStop pid = go (200 :: Int)
  where
    go 0 = assertFailure "child never stopped itself"
    go n = do
      eStat <- try (BS.readFile ("/proc/" ++ show pid ++ "/stat")) :: IO (Either IOException BS.ByteString)
      case eStat of
        Right bs -> case words (BC8.unpack bs) of
          (_ : _ : state : _) | state == "T" -> pure ()
          (_ : _ : state : _) | state == "Z" -> do
            _ <- getProcessStatus True False pid
            assertFailure "child died before exec into stopped-state"
          _ -> threadDelay 5000 >> go (n - 1)
        Left _ -> do
          st <- getProcessStatus False False pid
          case st of
            Just _ -> assertFailure "child died before exec into stopped-state"
            Nothing -> threadDelay 5000 >> go (n - 1)

-- | Best-effort stuck-child cleanup for finally releases. Ownership
-- is checked FIRST (non-blocking wait): already-reaped
-- (ECHILD) or zombie (reaped by this very call) means hands off
-- — signals only go to a live unwaited-for child, which must be
-- ours: pid reuse needs a competing waiter (a dead child stays a
-- reserved zombie until its own reap), and every test here reaps
-- only its own children, so no competing waiter exists and the
-- window is empty — POSIX offers no atomic check-and-signal.
-- The reap after the kill is POLLED, never blocking-forever: if
-- the kill itself failed the loop gives up after 200 attempts
-- with 5 ms delays, leaving a live child for the harness (by
-- necessity — retrying a refused kill is pointless, throwing
-- would mask the original failure). The give-up is SILENT: no
-- stdout diagnostic exists anywhere on this path, because even a
-- buffered write would wedge GHC's exit-time flush on a full
-- pipe. A surviving child still surfaces loudly in every body
-- that reaches its reaping check — each test asserts ECHILD
-- after the cleanup that must have reaped (the pins after their
-- reads, the rest explicitly in-body). A body cancelled first
-- reports its cancellation instead (the release backstop stays
-- silent by design).
-- Never throws synchronously: every step is tried, so cleanup
-- adds no failure of its own. Under cancel, an in-body call can
-- still be interrupted mid-reap — only release-path calls run
-- uninterruptibly, and the release backstop then takes over instead.
cleanupChild :: CPid -> IO ()
cleanupChild pid = do
  eSt <- try (getProcessStatus False False pid) :: IO (Either IOException (Maybe ProcessStatus))
  case eSt of
    Left _ -> pure ()
    Right (Just _) -> pure ()
    Right Nothing -> do
      _ <- try (signalProcess sigCONT pid) :: IO (Either IOException ())
      _ <- try (signalProcess sigKILL pid) :: IO (Either IOException ())
      reapBounded (200 :: Int)
  where
    reapBounded 0 = pure ()
    reapBounded n = do
      e <- try (getProcessStatus False False pid) :: IO (Either IOException (Maybe ProcessStatus))
      case e of
        Left _ -> pure ()
        Right (Just _) -> pure ()
        Right Nothing -> threadDelay 5000 >> reapBounded (n - 1)

-- | Release shared by all five fork tests: child cleanup runs
-- uninterruptibly (bounded: microseconds naturally, 200 attempts
-- with 5 ms delays worst-case fault-only) with the reader close
-- in its own nested finally. The release performs no stdout I/O
-- at all (a buffered diagnostic would wedge the exit-time flush).
releaseForkTest :: IORef (Maybe CPid) -> Fd -> IO ()
releaseForkTest pidRef rSync =
  uninterruptibleMask_ $
    flip finally (closeFd rSync) $ do
      mPid <- readIORef pidRef
      case mPid of
        Nothing -> pure ()
        Just p -> cleanupChild p

-- | Assert a child is reaped (no unwaited-for status remains for
-- our pid): ECHILD either way — reaped by us, or its number since
-- recycled past us (waitpid only sees our own children, so both
-- mean no unwaited child of ours). Fails loudly naming the
-- survivor status otherwise. Called explicitly in-body by the
-- three non-pin tests after their cleanup (the two pins assert
-- the identical shape inline after their reads).
assertReaped :: CPid -> IO ()
assertReaped p = do
  eSt <- try (getProcessStatus False False p) :: IO (Either IOException (Maybe ProcessStatus))
  case eSt of
    Left err | ioe_errno err == Just (errnoOf eCHILD) -> pure ()
    _ -> assertFailure ("child not reaped: " ++ show eSt)
  where
    errnoOf (Errno n) = n

-- | Sync pipes are close-on-exec: an exec'd sleeper keeps none
-- of their descriptors except the deliberate stdout dup, so no
-- unrelated party can wedge a later EOF read. Proved by
-- inspecting the child's /proc fd table after it signals past
-- its own exec (Linux; vacuous elsewhere).
caseSyncPipeCloexec :: IO ()
caseSyncPipeCloexec
  | os /= "linux" = assertBool "sync cloexec needs /proc (not exercised)" True
  | otherwise = retryOnSpawnFlake $
      -- Outer mask + nested finallys + late restore: the
      -- reader/child finally installs immediately after createPipe
      -- (a setFdOption throw must not strand the fresh pipe), and a
      -- nested finally around setup+fork closes the writer exactly
      -- once — on success (same point as an explicit close, O2
      -- preserved) and on any setup failure (fork EAGAIN, injected
      -- EIO) — before restore runs the reads and assertions. The
      -- shared release runs its cleanup uninterruptibly (bounded:
      -- microseconds naturally, 200 attempts with 5 ms delays
      -- worst-case fault-only) with the reader close in its own
      -- nested finally, so a cancel landing mid-cleanup cannot
      -- strand the reader. No stdout I/O happens anywhere on this
      -- path (even a buffered diagnostic would wedge the
      -- exit-time flush). Zero descriptor leaks on every path,
      -- fault-injected throws
      -- included; exactly one close per fd per attempt, and
      -- nothing else closes them.
      mask $ \restore -> do
        (rSync, wSync) <- createPipe
        pidRef <- newIORef Nothing
        flip finally (releaseForkTest pidRef rSync) $ do
          p <- flip finally (closeFd wSync) $ do
            _ <- setFdOption rSync CloseOnExec True
            _ <- setFdOption wSync CloseOnExec True
            q <- forkProcess $ do
              _ <- dupTo wSync stdOutput
              -- Deliberately no closeFd wSync here: the pin below counts
              -- every survivor, so a missing flag on EITHER end shows as
              -- count >= 2 (writer and reader both present pre-exec;
              -- cloexec must close both at exec). Only the parent closes
              -- its writer (EOF-on-death, O2 — a dead child closes all
              -- of its own descriptors anyway).
              executeFile "sh" True ["-c", "echo READY; exec sleep 30"] Nothing
            writeIORef pidRef (Just q)
            pure q
          pipeId <- fileIdOfFd rSync
          restore $ do
            ready <- readSyncFirst p rSync 6
            assertEqual "child exec'd" (BC8.pack "READY\n") ready
            -- READY is written pre-exec, so wait until the child has
            -- exec'd past sh (else its pre-exec self still holds the
            -- sync reader with cloexec pending, flaking the count).
            waitForComm p "sleep"
            held <- childHoldsPipe p pipeId
            assertEqual "exec'd child keeps one sync fd (its stdout)" 1 held
            cleanupChild p
            assertReaped p
  where
    fileIdOfFd fd = do
      st <- getFileStatus ("/proc/self/fd/" ++ showFd fd)
      pure (deviceID st, fileID st)
    showFd (Fd n) = show n
    childHoldsPipe pid pipeId = do
      let fddir = "/proc/" ++ show pid ++ "/fd"
      eNames <- try (listDirectory fddir) :: IO (Either IOException [FilePath])
      case eNames of
        Left _ -> assertFailure "child died before inspect" >> pure 0
        Right names -> do
          ids <- mapM (\f -> try (getFileStatus (fddir ++ "/" ++ f)) :: IO (Either IOException FileStatus)) names
          pure (length [() | Right st <- ids, (deviceID st, fileID st) == pipeId])

-- | A child stopped (SIGSTOP) while holding the sync writer
-- must time the read out instead of hanging it: no data, no EOF,
-- so only the deadline distinguishes stuck from slow. The child
-- never signals; it is resumed and reaped after. The 200ms
-- deadline here proves the mechanism (hang-vs-fail is
-- value-independent); production reads use 2s. A spawn-flake
-- RTS panic before exec fails waitForComm instead, so the whole
-- case retries on that message (same rare class the pin tests
-- retry on via EOF).
caseSyncReadTimeouts :: IO ()
caseSyncReadTimeouts = retryOnDeadSpawn $
  -- Outer mask + nested finallys + late restore: the
  -- reader/child finally installs immediately after createPipe
  -- (a setFdOption throw must not strand the fresh pipe), and a
  -- nested finally around setup+fork closes the writer exactly
  -- once — on success (same point as an explicit close, O2
  -- preserved) and on any setup failure (fork EAGAIN, injected
  -- EIO) — before restore runs the reads and assertions. The
  -- shared release runs its cleanup uninterruptibly (bounded:
  -- microseconds naturally, 200 attempts with 5 ms delays
  -- worst-case fault-only) with the reader close in its own
  -- nested finally, so a cancel landing mid-cleanup cannot strand
  -- the reader. No stdout I/O happens anywhere on this path (even
  -- a buffered diagnostic would wedge the exit-time flush). Zero
  -- descriptor leaks on every path, fault-injected throws
  -- included; exactly one close per fd per attempt, and nothing
  -- else closes them.
  mask $ \restore -> do
    (rSync, wSync) <- createPipe
    pidRef <- newIORef Nothing
    flip finally (releaseForkTest pidRef rSync) $ do
      p <- flip finally (closeFd wSync) $ do
        _ <- setFdOption rSync CloseOnExec True
        _ <- setFdOption wSync CloseOnExec True
        q <- forkProcess $ do
          _ <- dupTo wSync stdOutput
          executeFile "sh" True ["-c", "exec sleep 30"] Nothing
        writeIORef pidRef (Just q)
        pure q
      restore $ do
        waitForComm p "sleep"
        signalProcess sigSTOP p
        o <- tryReadSyncFirst 200000 p rSync 6
        case o of
          SyncTimeout -> do
            cleanupChild p
            assertReaped p
          other -> assertFailure ("expected timeout, got: " ++ show other)

-- | EOF with a LIVE child still reaps promptly: a child that
-- closes its writers and stops itself delivers EOF without dying,
-- and a blocking reap of that stopped child would hang. The read
-- kills first (unblockable even when stopped), so the reap after
-- it is instant. Liveness is established up front (STOPPED state
-- proves the child ran and stopped itself — a dead child fails
-- here instead of passing vacuously on death-EOF). The outer 5s
-- bound turns a hang regression into a loud failure instead of
-- wedging the suite. The outer finally release owns the child
-- cleanup and the reader, and a nested setup finally owns the
-- writer (exactly one close per fd exists — nothing else closes
-- them).
caseSyncEofReapsLive :: IO ()
caseSyncEofReapsLive = retryOnDeadSpawn $
  -- Outer mask + nested finallys + late restore: the
  -- reader/child finally installs immediately after createPipe
  -- (a setFdOption throw must not strand the fresh pipe), and a
  -- nested finally around setup+fork closes the writer exactly
  -- once — on success (same point as an explicit close, O2
  -- preserved) and on any setup failure (fork EAGAIN, injected
  -- EIO) — before restore runs the reads and assertions. The
  -- shared release runs its cleanup uninterruptibly (bounded:
  -- microseconds naturally, 200 attempts with 5 ms delays
  -- worst-case fault-only) with the reader close in its own
  -- nested finally, so a cancel landing mid-cleanup cannot strand
  -- the reader. No stdout I/O happens anywhere on this path (even
  -- a buffered diagnostic would wedge the exit-time flush). Zero
  -- descriptor leaks on every path, fault-injected throws
  -- included; exactly one close per fd per attempt, and nothing
  -- else closes them.
  mask $ \restore -> do
    (rSync, wSync) <- createPipe
    pidRef <- newIORef Nothing
    flip finally (releaseForkTest pidRef rSync) $ do
      p <- flip finally (closeFd wSync) $ do
        _ <- setFdOption rSync CloseOnExec True
        _ <- setFdOption wSync CloseOnExec True
        q <- forkProcess $ do
          _ <- dupTo wSync stdOutput
          closeFd wSync
          executeFile "sh" True ["-c", "exec 1>&-; kill -STOP $$"] Nothing
        writeIORef pidRef (Just q)
        pure q
      restore $ do
        waitForStop p
        m <- timeout 5000000 (tryReadSyncFirst 2000000 p rSync 6)
        case m of
          Nothing ->
            assertFailure "EOF with live child hung (kill-before-reap missing?)"
          Just o -> case o of
            SyncError io | isEOFError io -> do
              eSt <- try (getProcessStatus False False p) :: IO (Either IOException (Maybe ProcessStatus))
              case eSt of
                Left err | ioe_errno err == Just (errnoOf eCHILD) -> pure ()
                _ -> assertFailure ("child not reaped: " ++ show eSt)
            other -> assertFailure ("expected EOF, got: " ++ show other)
  where
    errnoOf (Errno n) = n

-- | A timed-out throwing read best-effort cleans the stuck child
-- up before failing loud (on the normal path the ECHILD check
-- below observes an already reaped child); the nested setup
-- finally already closed our writer before the reads, and the
-- outer finally closes our reader after (exactly one close per
-- fd exists — nothing else closes them). Reaping
-- is proven (the pid is unwaitable — ECHILD either way,
-- race-free); the close is code-reviewed, NOT re-probed:
-- re-closing the number to observe EBADF would race fd-number
-- reuse (another thread's open landing on the recycled number
-- gets closed by the probe), and every number-based re-check
-- (/proc existence, fcntl, dup-observation) goes stale the same
-- way under parallel opens.
caseSyncTimeoutCleansUp :: IO ()
caseSyncTimeoutCleansUp = retryOnDeadSpawn $
  -- Outer mask + nested finallys + late restore: the
  -- reader/child finally installs immediately after createPipe
  -- (a setFdOption throw must not strand the fresh pipe), and a
  -- nested finally around setup+fork closes the writer exactly
  -- once — on success (same point as an explicit close, O2
  -- preserved) and on any setup failure (fork EAGAIN, injected
  -- EIO) — before restore runs the reads and assertions. The
  -- shared release runs its cleanup uninterruptibly (bounded:
  -- microseconds naturally, 200 attempts with 5 ms delays
  -- worst-case fault-only) with the reader close in its own
  -- nested finally, so a cancel landing mid-cleanup cannot strand
  -- the reader. No stdout I/O happens anywhere on this path (even
  -- a buffered diagnostic would wedge the exit-time flush). Zero
  -- descriptor leaks on every path, fault-injected throws
  -- included; exactly one close per fd per attempt, and nothing
  -- else closes them.
  mask $ \restore -> do
    (rSync, wSync) <- createPipe
    pidRef <- newIORef Nothing
    flip finally (releaseForkTest pidRef rSync) $ do
      p <- flip finally (closeFd wSync) $ do
        _ <- setFdOption rSync CloseOnExec True
        _ <- setFdOption wSync CloseOnExec True
        q <- forkProcess $ do
          _ <- dupTo wSync stdOutput
          executeFile "sh" True ["-c", "exec sleep 30"] Nothing
        writeIORef pidRef (Just q)
        pure q
      restore $ do
        waitForComm p "sleep"
        signalProcess sigSTOP p
        e <- try (readSyncFirst p rSync 6) :: IO (Either HUnitFailure BC8.ByteString)
        case e of
          Left (HUnitFailure _ reason)
            | "timed out" `isInfixOf` reason -> do
                eSt <- try (getProcessStatus False False p) :: IO (Either IOException (Maybe ProcessStatus))
                case eSt of
                  Left err | ioe_errno err == Just (errnoOf eCHILD) -> pure ()
                  _ -> assertFailure ("child not reaped: " ++ show eSt)
          other -> assertFailure ("expected timeout failure, got: " ++ show other)
  where
    errnoOf (Errno n) = n

-- | Write-only FIFOs (mode 0200) fail rows instead of risking
-- termination: the holder needs read permission. A reader is
-- connected (opened before the chmod), so the failure is the
-- holder's EACCES, not a missing reader. (At the C layer the
-- loss is silent — the rollback discards the drain report.)
caseFifoWriteOnlyFails :: IO ()
caseFifoWriteOnlyFails = do
  euid <- getEffectiveUserID
  if euid == 0
    then assertBool "write-only test needs non-root (not exercised)" True
    else withAliasScratch $ \dir _store _trace -> do
      let fifo = dir ++ "/pipe"
          row = BC8.pack "{\"r\":1}"
          sink = fileSink (TraceCfg True fifo True 64) row
      createNamedPipe fifo 0o644
      reader <- openFd fifo ReadWrite defaultFileFlags { cloexec = True }
      setFileMode fifo 0o200
      r <- sink
      closeFd reader
      setFileMode fifo 0o644
      case r of
        Left _ -> pure ()
        Right () -> assertFailure "write-only FIFO must fail the row"

-- | Forty final-component symlinks resolve (Linux allows 40
-- traversals): a trace destination through such a chain emits
-- instead of dropping. Content presence is Linux-gated (other
-- kernels refuse the open past 32); the guard verdict (no drop)
-- holds everywhere. The scratch is canonicalized so a symlinked
-- TMPDIR cannot add a traversal.
caseFortyLinksResolve :: IO ()
caseFortyLinksResolve =
  withAliasScratch $ \dir0 _store0 _trace -> do
    dir <- canonicalizePath dir0
    let store = dir ++ "/store.sqlite"
    end <- buildLinkChain dir 40
    let trace = dir ++ "/chain-l0"
    BC8.writeFile end (BC8.replicate 64 't')
    tr <- newFileTracer (TraceCfg True trace True 64)
    let cfg = defaultConfig
          { cfgStorage = (cfgStorage defaultConfig)
              { scKind = StorageSQLite
              , scPath = Just store
              }
          }
        sa = stdAcquisition
          { saTracer = Just tr
          , saOpenStore = \_ _ -> pure (Left (StdStoreSeating AdmitTokensFull))
          }
    sp <- openStdInstanceWith sa cfg
    assertBool "refused open is NULL" (isNull sp)
    rep <- drainTracer tr
    drops <- droppedTraces tr
    assertEqual "forty links do not drop" 0 drops
    when (os == "linux") $ do
      assertBool "row written through forty links" (drWritten rep >= 1)
      bytes <- BC8.readFile end
      assertBool "target grew" (BC8.length bytes > 64)

-- | Forty-one links exceed every supported kernel: the guard
-- drops without opening, the target keeps its bytes, and the
-- drop is counted — on every platform.
caseFortyOneLinksDrop :: IO ()
caseFortyOneLinksDrop =
  withAliasScratch $ \dir0 _store0 _trace -> do
    dir <- canonicalizePath dir0
    let store = dir ++ "/store.sqlite"
    end <- buildLinkChain dir 41
    let trace = dir ++ "/chain-l0"
    BC8.writeFile end (BC8.replicate 64 't')
    tr <- newFileTracer (TraceCfg True trace True 64)
    let cfg = defaultConfig
          { cfgStorage = (cfgStorage defaultConfig)
              { scKind = StorageSQLite
              , scPath = Just store
              }
          }
        sa = stdAcquisition
          { saTracer = Just tr
          , saOpenStore = \_ _ -> pure (Left (StdStoreSeating AdmitTokensFull))
          }
    sp <- openStdInstanceWith sa cfg
    assertBool "refused open is NULL" (isNull sp)
    _ <- drainTracer tr
    bytes <- BC8.readFile end
    assertEqual "target bytes unchanged" 64 (BC8.length bytes)
    drops <- droppedTraces tr
    assertEqual "the skipped row is counted" 1 drops

-- | Build a chain of N final-component symlinks, l0 -> l1 -> ...
-- -> l(N-1) -> end, and return the end path. Resolving l0
-- traverses exactly N links.
buildLinkChain :: FilePath -> Int -> IO FilePath
buildLinkChain dir n = do
  let end = dir ++ "/chain-end"
      link i = dir ++ "/chain-l" ++ show i
  mapM_ (\i -> createSymbolicLink (if i + 1 >= n then end else link (i + 1)) (link i)) [0 .. n - 1]
  pure end

-- ---------------------------------------------------------------------------
-- Renderer pins: the exact (tag, remedy) contract per constructor.
-- ---------------------------------------------------------------------------

allDenials :: [AdmitDeny]
allDenials =
  [ AdmitTokenAbsent, AdmitSessionsFull, AdmitReadOnlyWhileSO
  , AdmitObjectsFull, AdmitTokensFull, AdmitReadOnly
  , AdmitLoginRequired
  ]

-- | Every 'StoreError' constructor, both 'StoreIO' branches included.
storeBattery :: [StoreError]
storeBattery =
  [ StoreIO "boom"
  , StoreIO "store lock cannot be created: /tmp/x.lock: denied"
  , StoreSecondWriter "store is in use (pid 1): /tmp/x"
  , StoreSchemaVersion 3 "9"
  , StoreQuarantined (TokenId 1) "prior failure"
  , StoreCorrupt "bad row"
  , StoreLimit "too big"
  , StoreFull "no space"
  , StoreRevisionConflict "tx 5 vs 7"
  , StoreNeedsMigration 1 3
  , StoreJournalPresent "/tmp/x-wal"
  , StoreJournalCold "/tmp/x-wal"
  , StoreForeignSidecar "/tmp/x-wal"
  ]

caseRendererPins :: IO ()
caseRendererPins = do
  assertEqual "no-path" ("store-no-path"
    , "SQLite storage is configured without a store path: set storage.path to the store file")
    (renderInitRefusal StdStoreNoPath)
  assertEqual "commit" ("store-commit-failed"
    , "the open's seed commit failed (rejected or outcome unknown): retry the open;"
      ++ " if it persists, check disk space and run haskoki-ctl store check for store state")
    (renderInitRefusal StdStoreCommit)
  assertEqual "catalog-mismatch" ("store-catalog-mismatch"
    , "retained refusal (no longer produced): catalog/store drift reports as store-identity-refused")
    (renderInitRefusal StdStoreCatalogMismatch)
  assertEqual "identity" ("store-identity-refused"
    , "stored token identity drifted from the catalog: run haskoki-ctl store check for the reconciler's report")
    (renderInitRefusal (StdStoreIdentityRefusal "ignored payload"))
  assertEqual "migration" ("store-migration-required"
    , "stored tokens lack credential rows: run haskoki-ctl store migrate")
    (renderInitRefusal (StdStoreMigrationRequired [TokenId 7]))
  mapM_ pinSeating allDenials
  mapM_ pinReload allDenials
  mapM_ pinSQLite storeBattery
  where
    pinSeating deny =
      assertEqual ("seating " ++ show deny)
        ("store-seating-refused"
        , "token seating refused (" ++ show deny
          ++ "): the catalog exceeds serving limits; shrink the configured token catalog and retry")
        (renderInitRefusal (StdStoreSeating deny))
    pinReload deny =
      assertEqual ("reload " ++ show deny)
        ("store-reload-refused"
        , "stored token state refused (" ++ show deny
          ++ "): the store exceeds serving limits; shrink the store and retry")
        (renderInitRefusal (StdStoreReload deny))
    pinSQLite err = case err of
      StoreSecondWriter _ -> pin ("store-live"
        , "the store lock could not be acquired (run haskoki-ctl store check to see the lock state):"
          ++ " if a store owner holds it, stop the owner and retry;"
          ++ " otherwise inspect the lock file and retry")
      StoreJournalPresent _ -> pin ("store-journal-present"
        , "a hot or unrecognized rollback journal is present: do not delete it;"
          ++ " see docs/operations-notes.md, Interrupted migration")
      StoreJournalCold _ -> pin ("store-journal-cold"
        , "a cold rollback journal is present, or migration found the store busy:"
          ++ " stop any process that holds the store, run haskoki-ctl store check,"
          ++ " and retry store migrate with a valid backup directory unless check names another blocker;"
          ++ " if migrate keeps reporting cold, stop and investigate: wait for a persistent"
          ++ " SQLite lock holder to release once identified, or retry migrate once for a cold"
          ++ " journal that appeared with no holder left")
      StoreForeignSidecar _ -> pin ("store-foreign-sidecar"
        , "a foreign WAL sidecar is present: do not start the service;"
          ++ " when the sidecars are confirmed stray, move the -wal/-shm pair aside (keep both files)"
          ++ " and run store check again; otherwise keep them with the database;"
          ++ " see docs/operations-notes.md, Upgrade, backup and recovery")
      StoreNeedsMigration _ _ -> pin ("store-migration-required"
        , "the store schema needs haskoki-ctl store migrate to reach the current schema")
      StoreSchemaVersion _ _ -> pin ("store-unsupported-version"
        , "the store's schema marker is not one this build opens or migrates:"
          ++ " inspect the schema marker with SQLite tooling;"
          ++ " reopen with the writing build if a newer haskoki wrote it,"
          ++ " or restore a backup if the marker itself is damaged")
      StoreCorrupt _ -> pin ("store-corrupt"
        , "the store content is damaged or inconsistent: restore a backup;"
          ++ " see docs/operations-notes.md, Upgrade, backup and recovery")
      StoreFull _ -> pin ("store-full"
        , "the store cannot grow: free disk space and retry")
      StoreIO m | "store lock cannot be created: " `isPrefixOf` m -> pin ("store-lock-unwritable"
        , "the store lock cannot be created: fix the directory permissions or free space and retry")
      StoreIO _ -> pin ("store-unreadable"
        , "the store cannot be opened (I/O, SQLite, or format failure):"
          ++ " run haskoki-ctl store check for detail and retry;"
          ++ " if check reports ok, inspect the store with SQLite tooling")
      StoreQuarantined _ _ -> pin ("store-unreadable"
        , "a prior failure quarantined the store connection: restart the service")
      StoreLimit _ -> pin ("store-unreadable"
        , "a store quota refused the write: shrink the payload and retry")
      StoreRevisionConflict _ -> pin ("store-unreadable"
        , "a commit conflict was detected between the request and current store state"
          ++ " (examples: stale revision, dangling reference, duplicate slot use):"
          ++ " re-read state and retry; if it persists, correct the request")
      where pin want = assertEqual ("sqlite " ++ show err) want (renderInitRefusal (StdStoreSQLite err))

caseTagAgreement :: IO ()
caseTagAgreement =
  mapM_ (\e -> assertEqual ("tag agrees: " ++ show e)
    (fst (renderStoreRefusal e))
    (fst (renderInitRefusal (StdStoreSQLite e)))) storeBattery

caseReasonShape :: IO ()
caseReasonShape = do
  let reasons =
        [ snd (renderInitRefusal r)
        | r <- StdStoreNoPath : StdStoreCommit : StdStoreCatalogMismatch
            : StdStoreIdentityRefusal "x" : StdStoreMigrationRequired [TokenId 1]
            : map StdStoreSeating allDenials ++ map StdStoreReload allDenials
            ++ map StdStoreSQLite storeBattery
        ]
      tags = map (fst . renderInitRefusal)
        [ StdStoreNoPath, StdStoreCommit, StdStoreCatalogMismatch
        , StdStoreIdentityRefusal "x", StdStoreMigrationRequired [TokenId 1]
        , StdStoreSeating AdmitTokensFull, StdStoreReload AdmitTokensFull
        ] ++ map (fst . renderInitRefusal . StdStoreSQLite) storeBattery
  mapM_ (\t -> assertBool ("tag charset: " ++ t) (all (\c -> isAlphaNum c || c == '-') t)) tags
  mapM_ (\r -> assertBool ("single line: " ++ r) (not ('\n' `elem` r || '\r' `elem` r))) reasons
  -- ASCII-only reasons: the JSONL renderer latin1-packs without
  -- escaping non-ASCII, so a non-ASCII byte (an em dash truncated
  -- to a control byte, caught here before) would emit invalid
  -- JSONL. The serialized check below pins the actual bytes.
  mapM_ (\r -> assertBool ("ascii only: " ++ r) (all isAscii r)) reasons
  mapM_ (\r -> assertBool ("clean bytes: " ++ take 48 r)
    (all (\c -> ord c >= 0x20) (BC8.unpack (renderJSONL testIds 0 (causeRow r))))) reasons
  where
    testIds = TraceIds "trace/1" "haskoki" "provider" "demo-maximal" "run-0"
    -- Mirrors the emission-site construction with each remedy in
    -- the reason field (tags are pinned ASCII separately, so the
    -- remedy is the only byte-varying input under test).
    causeRow reason = TraceEvent
      { teFunction = "C_Initialize"
      , teInterface = "3.2"
      , teMechanism = Nothing
      , teSession = Nothing
      , teObject = Nothing
      , teJob = Nothing
      , teInputLen = 0
      , teOutputLen = 0
      , teCkr = 5
      , teDisposition = "rejected"
      , teReason = reason
      , teMode = "sync"
      , teSecret = Nothing
      }

-- ---------------------------------------------------------------------------
-- Doc pin: every row of the init-refusal table in
-- docs/operations-notes.md is parsed strictly and every one of its
-- cells is compared against its tag's expected content — tag set,
-- surfaces, reachability, and the full remedy cell. The remedy cell
-- is compared whole (wordings drawn from the renderer, multi-wording
-- labels literal prose): a substring check would pass appended
-- contradictory text, and a lenient parser would skip an unquoted
-- extra row — both fail here.
-- ---------------------------------------------------------------------------

-- | One parsed table row: tag, surfaces, remedy, reachability.
data DocRow = DocRow
  { drTag :: String
  , drSurfaces :: String
  , drRemedy :: String
  , drReach :: String
  }

splitCells :: String -> [String]
splitCells = go ""
  where
    go acc [] = [reverse acc]
    go acc ('|' : cs) = reverse acc : go "" cs
    go acc (c : cs) = go (c : acc) cs

trim :: String -> String
trim = reverse . dropWhile (== ' ') . reverse . dropWhile (== ' ')

tableHeader :: String
tableHeader = "| Tag | Surfaces | Trace remedy | Reachability |"

-- | Every body row of the target table, parsed strictly: the
-- header and the validated separator open the block, every
-- following @|@-led line must split into exactly the four cells
-- with a tag cell that is exactly a backticked @store-*@ tag
-- (nothing before the opening or after the closing backtick), the
-- block must end at a blank line or end of file (an appended row
-- without a leading pipe fails instead of slipping through), and
-- anything else fails loudly (never silently skipped).
parseDocRows :: String -> IO [DocRow]
parseDocRows doc = case dropWhile (/= tableHeader) (lines doc) of
  (_header : sep : rest)
    | trim sep == "|---|---|---|---|" -> do
        let (body, after) = span ("|" `isPrefixOf`) rest
        case after of
          [] -> pure ()
          (next : _) | all (== ' ') next -> pure ()
          (next : _) -> assertFailure ("non-table line inside the table block: " ++ next)
        mapM parseRow body
    | otherwise -> assertFailure "init-refusal table separator malformed" >> pure []
  _ -> assertFailure "init-refusal table header not found" >> pure []
  where
    parseRow line = case splitCells line of
      ["", tagCell, surf, remedy, reach, ""] -> case trim tagCell of
        '`' : rest
          | "store-" `isPrefixOf` rest
          , (tag, closing) <- break (== '`') rest
          , closing == "`" ->
            pure (DocRow tag (trim surf) (trim remedy) (trim reach))
        _ -> assertFailure ("tag cell not exactly a backticked store tag: " ++ line)
          >> pure badRow
      _ -> assertFailure ("table row does not split into four cells: " ++ line) >> pure badRow
    badRow = DocRow "" "" "" ""

readDoc :: IO String
readDoc = readFile "docs/operations-notes.md"

-- | Expected (tag, surfaces, reachability, full remedy cell) per
-- table row. Remedy wordings come from 'renderInitRefusal' (the
-- literals live in the renderer pins); multi-wording labels and the
-- seating/reload @\<deny\>@ templates plus the hand-written
-- @store-missing@ guidance are literal prose.
docCells :: [(String, String, String, String)]
docCells =
  [ ("store-seating-refused", "trace", "Haskell/fixture opens only"
    , "token seating refused (<deny>): the catalog exceeds serving limits; shrink the configured token catalog and retry")
  , ("store-no-path", "trace", "Haskell/fixture opens only"
    , snd (renderInitRefusal StdStoreNoPath))
  , ("store-live", "trace, cli", "serving init + CLI"
    , snd (renderInitRefusal (StdStoreSQLite (StoreSecondWriter "x"))))
  , ("store-journal-present", "cli", "CLI only (mapped for totality)"
    , snd (renderInitRefusal (StdStoreSQLite (StoreJournalPresent "x"))))
  , ("store-journal-cold", "cli", "CLI only (mapped for totality)"
    , snd (renderInitRefusal (StdStoreSQLite (StoreJournalCold "x"))))
  , ("store-foreign-sidecar", "trace, cli", "serving init + CLI"
    , snd (renderInitRefusal (StdStoreSQLite (StoreForeignSidecar "x"))))
  , ("store-migration-required", "trace, cli", "serving init + CLI"
    , "Schema case: " ++ snd (renderInitRefusal (StdStoreSQLite (StoreNeedsMigration 1 3)))
      ++ ". Stored-token case: " ++ snd (renderInitRefusal (StdStoreMigrationRequired [TokenId 1])))
  , ("store-unsupported-version", "trace, cli", "serving init + CLI"
    , snd (renderInitRefusal (StdStoreSQLite (StoreSchemaVersion 3 "9"))))
  , ("store-corrupt", "trace, cli", "serving init + CLI"
    , snd (renderInitRefusal (StdStoreSQLite (StoreCorrupt "x"))))
  , ("store-full", "trace, cli", "serving init + CLI"
    , snd (renderInitRefusal (StdStoreSQLite (StoreFull "x"))))
  , ("store-lock-unwritable", "trace, cli", "serving init + CLI"
    , snd (renderInitRefusal (StdStoreSQLite (StoreIO "store lock cannot be created: x"))))
  , ("store-unreadable", "trace, cli", "serving init + CLI (other wordings mapped for totality)"
    , "Unopenable store: " ++ snd (renderInitRefusal (StdStoreSQLite (StoreIO "x")))
      ++ ". Quarantined connection: " ++ snd (renderInitRefusal (StdStoreSQLite (StoreQuarantined (TokenId 1) "x")))
      ++ ". Over quota: " ++ snd (renderInitRefusal (StdStoreSQLite (StoreLimit "x")))
      ++ ". Write conflict: " ++ snd (renderInitRefusal (StdStoreSQLite (StoreRevisionConflict "x"))))
  , ("store-reload-refused", "trace", "serving init"
    , "stored token state refused (<deny>): the store exceeds serving limits; shrink the store and retry")
  , ("store-commit-failed", "trace", "serving init"
    , snd (renderInitRefusal StdStoreCommit))
  , ("store-catalog-mismatch", "none", "none (retained)"
    , snd (renderInitRefusal StdStoreCatalogMismatch))
  , ("store-identity-refused", "trace, cli", "serving init + CLI"
    , snd (renderInitRefusal (StdStoreIdentityRefusal "x")))
  , ("store-missing", "cli", "CLI only"
    , "no store file at the path: for an ordinarily missing path, start the service once to initialize"
      ++ " a fresh store; for a dangling link, remove the link and serve the real path, recreate"
      ++ " the target, or restore a backup")
  ]

docTags :: [String]
docTags = sort [t | (t, _, _, _) <- docCells]

caseDocCells :: IO ()
caseDocCells = do
  doc <- readDoc
  rows <- parseDocRows doc
  assertEqual "table tags 1:1" docTags (sort (map drTag rows))
  mapM_ (pinRow rows) docCells
  where
    pinRow rows (tag, surf, reach, remedy) = case [r | r <- rows, drTag r == tag] of
      [r] -> do
        assertEqual ("surfaces " ++ tag) surf (drSurfaces r)
        assertEqual ("reachability " ++ tag) reach (drReach r)
        assertEqual ("remedy " ++ tag) remedy (drRemedy r)
      other -> assertFailure ("tag " ++ tag ++ " parses to "
        ++ show (length other) ++ " rows, want exactly one")
