{- | Store sqlite file behaviors.
-}
{-# LANGUAGE OverloadedStrings #-}
module Store.Files
  ( testAsyncOpenSeedsHomeCredential
  , testCorruptDiagnosed
  , testFutureVersionRejected
  , testGarbageRejected
  , testHeldFdsCloexec
  , testOpenFdSourceGate
  , testRawColumnsClean
  , testSchemaShape
  , testV1AsyncRefusalWritesNothing
  , testV1RefusesWithoutWriting
  , testV2RefusesWithoutWriting
  ) where

import Control.Exception (bracket, bracket_, evaluate)
import Control.Monad (when)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BC8
import Data.Char (isAlphaNum, isSpace)
import Data.List (isInfixOf, isPrefixOf, sort)
import qualified Data.Text as T
import qualified Database.SQLite3 as S
import Foreign.C.String (withCString)
import Foreign.Marshal.Alloc (alloca)
import Foreign.Ptr (nullPtr)
import Foreign.StablePtr (castStablePtrToPtr)
import Foreign.Storable (poke)
import System.Directory (canonicalizePath, doesDirectoryExist, doesFileExist, listDirectory, removeDirectoryRecursive)
import System.FilePath (takeExtension, (</>))
import System.IO.Error (catchIOError)
import System.Posix.Files (readSymbolicLink)
import System.Timeout (timeout)
import Test.Tasty.HUnit (assertBool, assertEqual, assertFailure)
import Haskoki.Runtime.Storage
  ( CommitResult (..)
  , CredentialRecord (..)
  , Store (..)
  , StoreDelta (..)
  , StoreError (..)
  , TokenRecord (..)
  , emptyDelta
  )
import Haskoki.FFI.Async (haskokiAsyncStoreClose, haskokiAsyncStoreOpen)
import StoreFixtures
  ( StoreState (..), assertUnchanged, captureState, closeAcquired
  , loadConfigOrFail, makeTempDir, openReconciled, rawExec, rawTexts
  , storePackageRoot
  , writeStoreConfig )
import Haskoki.FFI.Standard
  ( StdStoreError (..)
  )
import Haskoki.Runtime.Catalog (homeCatalogEntry)
import Haskoki.Runtime.Storage.SQLite (openSQLiteStore)
import Haskoki.Session (tokenAuthNew)
import Haskoki.Types
  ( Generation (..)
  , SlotId (..)
  , TokenId (..)
  )
import Store.Fixtures

-- | Every fd the open store holds on its database and sidecar lock
-- carries FD_CLOEXEC. Without it a concurrent fork+exec (any thread,
-- or the host application spawning a child) inherits the fd and keeps
-- the flock alive past 'storeClose'. Reads the live fd table (Linux
-- @\/proc@, like the backend itself; skipped with a note elsewhere),
-- so it checks the store's real fds, not a copy of the flags.
-- Expected set: one sidecar lock fd, plus on the database path the
-- guard fd and SQLite's own main-database fd.
testHeldFdsCloexec :: IO ()
testHeldFdsCloexec = do
  haveProc <- doesDirectoryExist "/proc/self/fd"
  if not haveProc
    then putStrLn "SKIP: /proc/self/fd unavailable; cannot inspect fd flags"
    else do
      dir <- makeTempDir "haskoki-cloexec"
      bracket_ (pure ()) (removeDirectoryRecursive dir) $ do
        realDir <- canonicalizePath dir
        let path = realDir </> "store.db"
        bracket (either (assertFailure . show) pure =<< openSQLiteStore (dir </> "store.db"))
                storeClose $ \_ -> do
          fds <- listDirectory "/proc/self/fd"
          held <- fmap concat $ mapM (\n -> do
            tgt <- readSymbolicLink ("/proc/self/fd" </> n) `catchIOError` \_ -> pure ""
            pure [(n, tgt) | tgt == path || tgt == path ++ ".lock"]) fds
          flagsOf <- mapM (\(n, tgt) -> do
            info <- readFile ("/proc/self/fdinfo" </> n)
            let fl = [w | l <- lines info, ("flags:" : w : _) <- [words l]]
            case fl of
              [w] -> pure (n, tgt, read ("0o" ++ w) :: Int)
              _ -> assertFailure ("no flags in fdinfo of fd " ++ n)) held
          let count t = length [() | (_, g) <- held, g == t]
          assertEqual "sidecar lock fds held" 1 (count (path ++ ".lock"))
          assertEqual "database fds held (guard + SQLite main)" 2 (count path)
          let o_cloexec = 0o2000000 :: Int
          assertEqual "fds lacking close-on-exec" []
            [(n, tgt) | (n, tgt, fl) <- flagsOf, fl `div` o_cloexec `mod` 2 == (0 :: Int)]

-- | Source gate for the two-step open. A deterministic test cannot
-- observe the fork window, so this is a best-effort tripwire that
-- pins the shape that closes it (it is textual and line-based: it
-- does not parse block comments or follow indirection). Rules:
--   1. every @openFd@ in the SQLite backend (the shell plus every
--      Storage\/SQLite\/ module) takes @guardFlags@
--      (on its own or the next line), and @guardFlags@ sets
--      @cloexec = True@;
--   2. no @setFdOption@, @F_SETFD@ or @cloexec = False@ in code
--      under src\/ or ffi\/ (a later close-on-exec step, or an
--      opt-out, reopens the window);
--   3. the offline preflight (Storage\/Preflight.hs), which opens the
--      store and its backups, follows rule 1 with the same @guardFlags@;
--   4. neither module reads a file through a GHC 'Handle' open
--      (@readFile@ and its ByteString form do not set O_CLOEXEC); they
--      read through the backend's close-on-exec reader.
-- If a legitimate refactor trips it, update the rule here.
testOpenFdSourceGate :: IO ()
testOpenFdSourceGate = do
  root <- findPackageRoot "."
  let backendDir = root </> "src/Haskoki/Runtime/Storage/SQLite"
      preflight = root </> "src/Haskoki/Runtime/Storage/Preflight.hs"
  modFiles <- sourceFilesUnder [backendDir]
  let fdFiles = (root </> "src/Haskoki/Runtime/Storage/SQLite.hs") : modFiles
  bodies <- mapM readFile fdFiles
  pbody <- readFile preflight
  obody <- readFile (backendDir </> "Ownership.hs")
  files <- sourceFilesUnder [root </> "src", root </> "ffi"]
  let stripComment l = go l
        where go ('-' : '-' : _) = ""
              go (c : cs) = c : go cs
              go [] = []
      codeLines txt = [(n, stripComment l, l) | (n, l) <- zip [1 :: Int ..] (lines txt)
                      , not ("--" `isPrefixOf` dropWhile isSpace l)
                      , not ("//" `isPrefixOf` dropWhile isSpace l)]
      callsIn txt = [n | (n, c, _) <- codeLines txt, "openFd " `isInfixOf` c, not ("import " `isPrefixOf` c)]
      unguarded txt =
        let ls = zip [1 :: Int ..] (lines txt)
            nextTwo n = unwords [l | (m, l) <- ls, m == n || m == n + 1]
        in [(n, l) | n <- callsIn txt, let l = nextTwo n, not ("guardFlags" `isInfixOf` l)]
      handleReads txt = [(n, l) | (n, c, l) <- codeLines txt, not ("import " `isPrefixOf` c)
                        , any (`elem` ["readFile", "BS.readFile", "BC8.readFile"]) (identifiers c)]
      identifiers = words . map (\ch -> if isAlphaNum ch || ch `elem` ("_'." :: String) then ch else ' ')
  assertBool "rule 1: found the backend's openFd calls (gate may need updating)" (sum (map (length . callsIn) bodies) >= 10)
  mapM_ (\(f, txt) -> assertEqual ("rule 1: openFd call not using guardFlags in " ++ f) [] (unguarded txt)) (zip fdFiles bodies)
  assertBool "rule 3: found the preflight's openFd calls (gate may need updating)" (length (callsIn pbody) >= 2)
  assertEqual "rule 3: preflight openFd call not using guardFlags (line, text)" [] (unguarded pbody)
  mapM_ (\(f, txt) -> assertEqual ("rule 4: Handle read in " ++ f) [] (handleReads txt)) (zip fdFiles bodies)
  assertEqual "rule 4: preflight Handle read (line, text)" [] (handleReads pbody)
  assertBool "rule 1: guardFlags must be defined with cloexec = True on one line"
    (any (\(_, c, _) -> "guardFlags = " `isInfixOf` c && "cloexec = True" `isInfixOf` c) (codeLines obody))
  forbidden <- fmap concat $ mapM (\f -> do
    -- Strict read (see SlotInsertSpec): never hold the whole slurp open.
    txt <- readFile f
    _ <- evaluate (length txt)
    pure [(f, n, l) | (n, c, l) <- codeLines txt
         , any (`isInfixOf` c) ["setFdOption", "F_SETFD", "cloexec = False"]]) files
  assertEqual "rule 2: setFdOption / F_SETFD / cloexec = False (file, line, text)" [] forbidden
  where
    findPackageRoot d = do
      ok <- doesFileExist (d </> "haskoki.cabal")
      if ok then pure d
        else if length d > 40 then assertFailure "haskoki.cabal not found above the working directory; run the suite from the package tree"
        else findPackageRoot (d </> "..")
    sourceFilesUnder = fmap concat . mapM walk
    walk d = do
      isDir <- doesDirectoryExist d
      if not isDir then pure [] else do
        es <- listDirectory d
        fmap concat $ mapM (\e -> do
          let f = d </> e
          sub <- doesDirectoryExist f
          if sub then walk f
            else pure [f | takeExtension f `elem` [".hs", ".c", ".h"]]) es

-- | SQLite-only: a garbage file is rejected with a diagnosis and
-- its bytes are left untouched (never silently replaced).
testGarbageRejected :: IO ()
testGarbageRejected = do
  bracket (makeTempDir "haskoki-storage-garbage") removeDirectoryRecursive $ \dir -> do
    let path = dir </> "store.db"
    BS.writeFile path (BS.pack [116, 104, 105, 115, 32, 110, 111, 116, 32, 97, 32, 100, 98, 0, 1, 2])
    before <- BS.readFile path
    eStore <- openSQLiteStore path
    case eStore of
      Right s -> do
        storeClose s
        assertFailure "garbage file opened as a store"
      Left _ -> pure ()
    bytesAfter <- BS.readFile path
    assertEqual "garbage bytes untouched" before bytesAfter

-- | Acceptance 4 (wrong schema): a future schema version is
-- rejected with its versions diagnosed, the bytes untouched, and
-- no lock stranded.
testFutureVersionRejected :: IO ()
testFutureVersionRejected =
  bracket (makeTempDir "haskoki-storage-version") removeDirectoryRecursive $ \dir -> do
    let path = dir </> "store.db"
    e0 <- openSQLiteStore path
    s0 <- either (\e -> assertFailure ("seed open: " ++ show e)) pure e0
    _ <- seedStore s0
    storeClose s0
    rawExec path (T.pack "UPDATE store_meta SET value = '999' WHERE key = 'schema_version'")
    before <- BS.readFile path
    e1 <- openSQLiteStore path
    case e1 of
      Right s -> do
        storeClose s
        assertFailure "future schema version opened"
      Left (StoreSchemaVersion expected found) -> do
        assertEqual "expected version" 3 expected
        assertEqual "found version" "999" found
      Left other -> assertFailure ("wrong error: " ++ show other)
    bytesAfter <- BS.readFile path
    assertEqual "bytes untouched" before bytesAfter
    lockLeft <- doesFileExist (path ++ ".lock")
    assertBool "no stranded lock" (not lockLeft)

-- | Acceptance (ordinary open never migrates): a version-1
-- database refuses as migration-required through every reader and
-- the open writes nothing: not a byte of the file, not the schema
-- marker, not a table, and no lock or journal is left behind. A
-- marker meta row stands for rows the open must not reinterpret.
testV1RefusesWithoutWriting :: IO ()
testV1RefusesWithoutWriting =
  bracket (makeTempDir "haskoki-storage-v1-refuse") removeDirectoryRecursive $ \dir -> do
    let path = dir </> "store.db"
    mapM_ (rawExec path . T.pack)
      (v1SchemaDdl ++ ["INSERT INTO store_meta(key, value) VALUES ('p6-migration-marker', 'kept')"])
    before <- captureState path
    eStore <- openSQLiteStore path
    case eStore of
      Left (StoreNeedsMigration 1 3) -> pure ()
      Left other -> assertFailure ("wrong refusal: " ++ show other)
      Right s -> storeClose s >> assertFailure "a version-1 database opened"
    assertUnchanged "version-1 database after a refused open" before path

-- | The v2 half of the migratable set: a version-2 database
-- refuses as migration-required and the refused open writes
-- nothing (same bar as v1: marker row, bytes, and sidecars
-- untouched). v1 is pinned by testV1RefusesWithoutWriting.
testV2RefusesWithoutWriting :: IO ()
testV2RefusesWithoutWriting =
  bracket (makeTempDir "haskoki-storage-v2-refuse") removeDirectoryRecursive $ \dir -> do
    let path = dir </> "store.db"
    mapM_ (rawExec path . T.pack)
      (v2SchemaDdl ++ ["INSERT INTO store_meta(key, value) VALUES ('p6-migration-marker', 'kept')"])
    before <- captureState path
    eStore <- openSQLiteStore path
    case eStore of
      Left (StoreNeedsMigration 2 3) -> pure ()
      Left other -> assertFailure ("wrong refusal: " ++ show other)
      Right s -> storeClose s >> assertFailure "a version-2 database opened"
    assertUnchanged "version-2 database after a refused open" before path

-- | The version-2 schema. Frozen history (v1 tables plus the
-- credentials table, @schema_version@ 2 — the credential-seeding
-- shape), not a live reference: it must never track the current
-- schema.
v2SchemaDdl :: [String]
v2SchemaDdl =
  [ "CREATE TABLE store_meta (key TEXT PRIMARY KEY NOT NULL, value TEXT NOT NULL)"
  , "CREATE TABLE tokens (token_id TEXT PRIMARY KEY NOT NULL, slot_key BLOB NOT NULL CHECK (typeof(slot_key) = 'blob' AND length(slot_key) = 8), generation_key BLOB NOT NULL CHECK (typeof(generation_key) = 'blob' AND length(generation_key) = 8), record_json TEXT NOT NULL, format_version INTEGER NOT NULL CHECK (format_version = 1), UNIQUE(slot_key))"
  , "CREATE TABLE objects (object_id TEXT PRIMARY KEY NOT NULL, token_id TEXT NOT NULL REFERENCES tokens(token_id) ON DELETE CASCADE, class_key BLOB NOT NULL CHECK (typeof(class_key) = 'blob' AND length(class_key) = 8), key_type_key BLOB CHECK (key_type_key IS NULL OR (typeof(key_type_key) = 'blob' AND length(key_type_key) = 8)), attributes_json TEXT NOT NULL, material_encoding TEXT NOT NULL, material_blob BLOB, revision INTEGER NOT NULL CHECK (revision > 0), format_version INTEGER NOT NULL CHECK (format_version = 1))"
  , "CREATE INDEX objects_by_token ON objects(token_id)"
  , "CREATE TABLE detached_jobs (persistent_id_key BLOB PRIMARY KEY NOT NULL CHECK (typeof(persistent_id_key) = 'blob' AND length(persistent_id_key) = 8), token_id TEXT NOT NULL REFERENCES tokens(token_id) ON DELETE CASCADE, token_generation_key BLOB NOT NULL CHECK (typeof(token_generation_key) = 'blob' AND length(token_generation_key) = 8), function_name TEXT NOT NULL, execution_state TEXT NOT NULL CHECK (execution_state IN ('queued','ready','failed','canceled','delivered')), record_json TEXT NOT NULL, format_version INTEGER NOT NULL CHECK (format_version = 1))"
  , "CREATE INDEX jobs_by_token ON detached_jobs(token_id)"
  , "CREATE TABLE credentials (token_id TEXT PRIMARY KEY NOT NULL REFERENCES tokens(token_id) ON DELETE CASCADE, record_json TEXT NOT NULL, format_version INTEGER NOT NULL CHECK (format_version = 1))"
  , "INSERT INTO store_meta(key, value) VALUES ('store_format', 'haskoki-demo-v1')"
  , "INSERT INTO store_meta(key, value) VALUES ('schema_version', '2')"
  , "INSERT INTO store_meta(key, value) VALUES ('next_persistent_job_id', '0000000000000001')"
  ]

-- | The async process-level store open refuses a version-1 store:
-- the SQLite open rejects the old schema before the home-token
-- check is reached, and the refusal writes nothing.
testV1AsyncRefusalWritesNothing :: IO ()
testV1AsyncRefusalWritesNothing =
  bracket (makeTempDir "haskoki-storage-v1-async") removeDirectoryRecursive $ \dir -> do
    let path = dir </> "store.db"
        tok = TokenRecord (TokenId 2) (SlotId 1) (Generation 0) "haskoki-ops" tokenAuthNew
    seedSchema1 path [tok]
    before <- captureState path
    box <- withCString path haskokiAsyncStoreOpen
    when (castStablePtrToPtr box /= nullPtr) $ do
      alloca $ \slot -> poke slot box >> haskokiAsyncStoreClose slot
      assertFailure "async open accepted a version-1 store"
    assertUnchanged "refused async open" before path
    state <- rawSchemaState path
    assertEqual "still schema 1 without a credentials table" ("1", False) state

-- | The async open creates a complete schema-3 store: the home
-- token's credential row (the home catalog entry's PINs) is
-- committed in the same transaction as the token, the store
-- reopens through the async surface unchanged, and the standard
-- open never classifies it as migration-required (a label verdict
-- against the standard catalog is an identity refusal, not a
-- legacy one).
testAsyncOpenSeedsHomeCredential :: IO ()
testAsyncOpenSeedsHomeCredential =
  bracket (makeTempDir "haskoki-storage-async-home") removeDirectoryRecursive $ \dir -> do
    let path = dir </> "store.db"
        (_, soPin, userPin) = homeCatalogEntry
        closeBox box = alloca $ \slot -> poke slot box >> haskokiAsyncStoreClose slot
    box <- withCString path haskokiAsyncStoreOpen
    when (castStablePtrToPtr box == nullPtr) $ assertFailure "async open of a fresh path refused"
    closeBox box
    created <- captureState path
    assertEqual "schema 3" ["3"] (ssSchema created)
    assertEqual "exactly one credential row" 1 (length (ssCredentials created))
    s <- openSQLiteStore path >>= either (\e -> assertFailure ("reopen: " ++ show e)) pure
    creds <- storeLoadCredentials s >>= either (\e -> assertFailure ("load credentials: " ++ show e)) pure
    storeClose s
    assertEqual "the credential is the home catalog entry's PINs"
      [CredentialRecord (TokenId 1) (BC8.pack soPin) (Just (BC8.pack userPin))] creds
    -- Reopen through the async surface: serves, writes nothing.
    box2 <- withCString path haskokiAsyncStoreOpen
    when (castStablePtrToPtr box2 == nullPtr) $ assertFailure "async reopen refused"
    closeBox box2
    assertUnchanged "async reopen" created path
    -- The standard open's verdict is never a legacy one.
    cfgPath <- writeStoreConfig (dir </> "c.toml") path [homeLabel] [soPin] [userPin]
    cfg <- loadConfigOrFail cfgPath
    r <- openReconciled path cfg
    case r of
      Left (StdStoreSQLite (StoreNeedsMigration _ _)) -> assertFailure "async-created store needs migration"
      Left (StdStoreMigrationRequired ids) -> assertFailure ("async-created store is rowless: " ++ show ids)
      Left (StdStoreIdentityRefusal _) -> pure ()
      Left other -> assertFailure ("unexpected refusal: " ++ show other)
      Right acq -> closeAcquired acq
    assertUnchanged "standard open of an async-created store" created path
  where
    (homeLabel, _, _) = homeCatalogEntry

-- | Acceptance 4 (corrupt records): garbage in each decodable
-- surface diagnoses 'StoreCorrupt' at load (open itself stays
-- lazy and succeeds).
testCorruptDiagnosed :: IO ()
testCorruptDiagnosed = do
  mapM_ runSurface
    [ ("token doc", "UPDATE tokens SET record_json = '{broken'")
    , ("attrs doc", "UPDATE objects SET attributes_json = 'nope' WHERE object_id = '0000000000000001'")
    , ("object id", "UPDATE objects SET object_id = 'zzz' WHERE object_id = '0000000000000001'")
    , ("material encoding", "UPDATE objects SET material_encoding = 'evil/v9' WHERE object_id = '0000000000000002'")
    ]
  where
    runSurface :: (String, String) -> IO ()
    runSurface (label, sql) =
      bracket (makeTempDir "haskoki-storage-corrupt") removeDirectoryRecursive $ \dir -> do
        let path = dir </> "store.db"
        e0 <- openSQLiteStore path
        s0 <- either (\e -> assertFailure ("seed open: " ++ show e)) pure e0
        _ <- seedStore s0
        storeClose s0
        rawExec path (T.pack sql)
        e1 <- openSQLiteStore path
        s1 <- either (\e -> assertFailure (label ++ " open: " ++ show e)) pure e1
        eLoaded <- storeLoadTokens s1
        case eLoaded of
          Left (StoreCorrupt _) -> pure ()
          Left other -> assertFailure (label ++ ": wrong error: " ++ show other)
          Right _ -> assertFailure (label ++ ": corrupt record loaded")
        storeClose s1

-- | SQLite-only: the same fixture scan over the RAW column values
-- read through an independent driver session (not our inspect).
testRawColumnsClean :: IO ()
testRawColumnsClean =
  bracket (makeTempDir "haskoki-storage-rawscan") removeDirectoryRecursive $ \dir -> do
    let path = dir </> "store.db"
    eStore <- openSQLiteStore path
    s <- either (\e -> assertFailure ("open: " ++ show e)) pure eStore
    (tok, _) <- seedStore s
    r <- storeCommit s emptyDelta
      { sdPutJobs =
          [ demoJobPending 40 (trId tok) (trGeneration tok)
          , demoJobResult 41 (trId tok) (trGeneration tok)
          ]
      }
    assertEqual "jobs commit" Committed r
    storeClose s
    db <- S.open (T.pack path)
    tokDocs <- rawTexts db (T.pack "SELECT record_json FROM tokens")
    attrDocs <- rawTexts db (T.pack "SELECT attributes_json FROM objects")
    matDocs <- rawTexts db (T.pack "SELECT material_encoding FROM objects")
    jobDocs <- rawTexts db (T.pack "SELECT record_json FROM detached_jobs")
    blobs <- rawBlobs db (T.pack "SELECT material_blob FROM objects WHERE material_blob IS NOT NULL")
    S.close db
    let texts = tokDocs ++ attrDocs ++ matDocs ++ jobDocs ++ blobs
    assertBool "raw columns non-empty" (not (null texts))
    mapM_ (\t -> assertBool ("raw clean: " ++ take 40 t) (cleanBytes t)) texts
    mapM_ (\t -> assertBool ("raw numbers: " ++ take 40 t) (numbersClean t))
      (tokDocs ++ attrDocs ++ jobDocs)

-- | Read one blob column from every row of a raw query.
rawBlobs :: S.Database -> T.Text -> IO [String]
rawBlobs db sql =
  bracket (S.prepare db sql) S.finalize collect
  where
    collect stmt = do
      r <- S.step stmt
      case r of
        S.Done -> pure []
        S.Row -> do
          cols <- S.columns stmt
          rest <- collect stmt
          pure ([BC8.unpack b | S.SQLBlob b <- cols] ++ rest)

-- | Normalize DDL for comparison: collapse whitespace runs and
-- drop spaces adjacent to parens/commas. Sound here because no
-- quoted literal in either schema text contains a space (pinned
-- implicitly: any such literal would break the equality below).
normDDL :: String -> String
normDDL s = [c | (prev, c, next) <- triples (' ' : collapsed ++ " "), keep prev c next]
  where
    collapsed = unwords (words s)
    triples (a : b : c : rest) = (a, b, c) : triples (b : c : rest)
    triples _ = []
    keep prev c next = c /= ' ' || not (prev `elem` punct || next `elem` punct)
    punct = "()," :: String

-- | Split spec SQL text into statements: drop `--` comment lines,
-- split on `;`, drop empties.
specStatements :: String -> [String]
specStatements text =
  [ t
  | chunk <- splitOn ';' noComments
  , let t = trim chunk
  , not (null t)
  ]
  where
    noComments = unlines
      [l | l <- lines text, not ("--" `isPrefixOf` dropWhile isSpace l)]
    trim = reverse . dropWhile isSpace . reverse . dropWhile isSpace
    splitOn _ [] = [[]]
    splitOn d (c : cs)
      | c == d = [] : splitOn d cs
      | otherwise = case splitOn d cs of
          [] -> [[c]]
          (h : t) -> (c : h) : t

-- | The live SQLite schema (tables + indexes, read back
-- from sqlite_master of a fresh store) equals the readable
-- reference spec/storage-schema.sql modulo whitespace.
testSchemaShape :: IO ()
testSchemaShape = do
  mOut <- timeout (120 * 1000000) $ do
    root <- storePackageRoot
    specText <- readFile (root </> "spec/storage-schema.sql")
    let specDDLs = sort
          [ normDDL s
          | s <- specStatements specText
          , "CREATE TABLE" `isPrefixOf` s || "CREATE INDEX" `isPrefixOf` s
          ]
        specPragmas =
          [ s
          | s <- specStatements specText
          , "PRAGMA" `isPrefixOf` s
          ]
    assertEqual "spec table+index count" 7 (length specDDLs)
    assertEqual "spec pragma count" 4 (length specPragmas)
    bracket (makeTempDir "haskoki-storage-schema") removeDirectoryRecursive $ \dir -> do
      let path = dir </> "store.db"
      eStore <- openSQLiteStore path
      s <- either (\e -> assertFailure ("open: " ++ show e)) pure eStore
      storeClose s
      db <- S.open (T.pack path)
      liveDDLs <- sort . map normDDL <$> rawTexts db
        (T.pack "SELECT sql FROM sqlite_master WHERE sql IS NOT NULL")
      S.close db
      assertEqual "live schema equals spec/storage-schema.sql" specDDLs liveDDLs
  case mOut of
    Just () -> pure ()
    Nothing -> assertFailure "schema-shape wedged (120s timeout)"
