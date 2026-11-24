{-# LANGUAGE ForeignFunctionInterface #-}
{- | Offline store preflight and explicit migration (AC-05). Read-only
diagnosis, the owned migration and their redacted renderings. Not
re-exported from "Haskoki"; the serving open does not import this module.
-}
module Haskoki.Runtime.Storage.Preflight
  ( sha256Hex
  , PreflightRefusal (..)
  , configSelectsStore
  , renderPreflightRefusal
  , MigrationOp (..)
  , PlanVerdict (..)
  , StoreOpenPlan (..)
  , planStoreOpen
  , planVerdict
  , checkStoreOpen
  , checkStoreOpenAllowCold
  , renderPlan
  , renderStoreRefusal
  , MigrateHooks (..)
  , noMigrateHooks
  , MigrationReceipt (..)
  , MigrateOutcome (..)
  , MigrateError (..)
  , migrateStore
  , migrateStoreWith
  , backupCandidates
  , renderReceipt
  , renderMigrateError
  , renderMigrateErrorAfterClear
  ) where

import Control.Exception (IOException, bracket, finally, fromException, mask, throwIO, try)
import Control.Monad (forM_)
import Data.Bifunctor (first)
import Data.Bits (shiftR, (.&.))
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BC8
import Data.ByteString (ByteString)
import Data.List (intercalate, isInfixOf, isPrefixOf, isSuffixOf)
import Data.Word (Word8)
import Foreign.C.Error (Errno (..), eNOTSUP, eOPNOTSUPP, ePERM, eXDEV)
import Foreign.C.String (CString, withCString)
import Foreign.C.Types (CInt (..), CSize (..), CUChar (..))
import Foreign.Marshal.Alloc (alloca, allocaBytes)
import Foreign.Ptr (Ptr, castPtr, nullPtr)
import Foreign.Storable (peek)
import GHC.IO.Exception (ioe_errno)
import System.IO.Error (isAlreadyExistsError, tryIOError)
import System.Posix.Directory (closeDirStream, openDirStream, readDirStream)
import System.Posix.Files
  ( createLink, deviceID, fileAccess, fileID, getFileStatus, getSymbolicLinkStatus, isDirectory
  , isSymbolicLink, removeLink )
import System.Posix.IO (OpenFileFlags (..), OpenMode (..), closeFd, fdWriteBuf, openFd)
import System.Posix.Process (getProcessID)
import System.Posix.Time (epochTime)
import System.Posix.Types (Fd)
import System.Posix.Unistd (fileSynchronise)

import Haskoki.Runtime.Catalog (catalogCredential, desiredTokens, tokenSerial)
import Haskoki.Runtime.Config (Config (..), StorageCfg (..), StorageKind (..))
import Haskoki.Runtime.Storage
  ( CredentialRecord (..), IdentityRefusal (..), ReconcilePlan (..), StoreError (..), TokenRecord (..)
  , reconcileIdentities, renderIdentityRefusal, tokensWithoutCredentials )
import Haskoki.Runtime.Storage.SQLite
  ( MigrateTxnError (..), MigrationHooks, OwnedStoreFile, OwnerState (..), SQLiteMigration (..), StoreSnapshot (..)
  , clearColdJournalOwned, guardFlags, migrateOwned, noMigrationHooks, pidIsDead, probeOwner, readFileCloexec
  , readStoreSnapshot, readStoreSnapshotAllowCold, requireRegularStore, resolveStoreSpelling, sqliteSchemaVersion
  , withOwnedStoreFile, withStoreSpelling )
import Haskoki.Runtime.Trace (renderSpellingRefusal)
import Haskoki.Types (TokenId)

-- | One-shot digest from the pinned libcrypto (see @openssl/evp.h@):
-- @EVP_Q_digest(NULL, "SHA256", NULL, data, datalen, md, &mdlen)@.
-- The default library context needs no setup: the first fetch
-- initialises it and the default provider lives in libcrypto itself.
-- A safe call, like every crypto entry in the engine's raw bindings.
foreign import ccall safe "openssl/evp.h EVP_Q_digest"
  c_EVP_Q_digest :: Ptr () -> CString -> CString -> Ptr CUChar -> CSize
                 -> Ptr CUChar -> Ptr CSize -> IO CInt

-- | SHA-256 of a byte string as 64 lowercase hex digits, computed by
-- a direct one-shot call into the pinned libcrypto (never a
-- synthetic stand-in, never through the engine: this module must not
-- pull the engine's test-hooked shim object into haskoki-ctl). Any
-- failure is a 'Left' the caller treats as a refusal.
sha256Hex :: ByteString -> IO (Either String String)
sha256Hex bytes =
  withInputBytes bytes $ \(p, len) ->
    allocaBytes 64 $ \md -> alloca $ \mdLen -> do
      rc <- withCString "SHA256" $ \name ->
        c_EVP_Q_digest nullPtr name nullPtr p len md mdLen
      if rc /= 1
        then pure (Left "SHA-256 failed: libcrypto refused the digest")
        else do
          n <- peek mdLen
          if n /= 32
            then pure (Left ("SHA-256 returned " ++ show n ++ " bytes"))
            else do
              d <- BS.packCStringLen (castPtr md, 32)
              pure (Right (concatMap hexByte (BS.unpack d)))
  where
    -- The output buffer holds EVP_MAX_MD_SIZE (64) bytes; SHA-256
    -- writes 32. The input of an empty string is a throwaway
    -- non-NULL pointer with length 0.
    withInputBytes :: ByteString -> ((Ptr CUChar, CSize) -> IO a) -> IO a
    withInputBytes bs action
      | BS.null bs = allocaBytes 1 $ \p -> action (p, 0)
      | otherwise = BS.useAsCStringLen bs (\(p, n) -> action (castPtr p, fromIntegral n))
    hexByte :: Word8 -> String
    hexByte w = [digit (w `shiftR` 4), digit (w .&. 15)]
    digit n = "0123456789abcdef" !! fromIntegral n

-- | Why a config cannot drive a check or migration of this file.
data PreflightRefusal
  = ConfigNotSQLite
  | ConfigNoPath
  | ConfigPathMismatch !FilePath !FilePath   -- ^ config path, --path
  deriving (Eq, Show)

-- | The config must select the same sqlite file (by name or inode).
configSelectsStore :: FilePath -> Config -> IO (Either PreflightRefusal ())
configSelectsStore path cfg = case (scKind (cfgStorage cfg), scPath (cfgStorage cfg)) of
  (StorageMemory, _) -> pure (Left ConfigNotSQLite)
  (StorageSQLite, Nothing) -> pure (Left ConfigNoPath)
  (StorageSQLite, Just p)
    | p == path -> pure (Right ())
    | otherwise -> do
        a <- tryIOError (getFileStatus p)
        b <- tryIOError (getFileStatus path)
        pure $ case (a, b) of
          (Right sa, Right sb)
            | deviceID sa == deviceID sb && fileID sa == fileID sb -> Right ()
          _ -> Left (ConfigPathMismatch p path)

renderPreflightRefusal :: PreflightRefusal -> String
renderPreflightRefusal r = case r of
  ConfigNotSQLite -> "the config does not select a sqlite store ([storage] kind)"
  ConfigNoPath -> "the config names no [storage] path"
  ConfigPathMismatch cfgP argP ->
    "the config's [storage] path " ++ cfgP ++ " is not --path " ++ argP
      ++ "; pass the config written for this store (for a copy, a config whose path names the copy)"

-- | One step an upgrade would perform.
data MigrationOp
  = OpCreateCredentialsTable
  | OpFreezeCredentials ![TokenId]
  | OpSetSchemaVersion !Int !Int
  deriving (Eq, Show)

data PlanVerdict
  = VerdictOpenable
  | VerdictMigrationRequired
  | VerdictIdentityRefused !IdentityRefusal
  deriving (Eq, Show)

-- | What an open of this store under this config would need. Carries
-- ids, versions and counts only, never credentials.
data StoreOpenPlan = StoreOpenPlan
  { sopPath :: !FilePath
  , sopOwner :: !OwnerState
  , sopSchema :: !Int
  , sopStoredTokens :: ![TokenId]
  , sopCredentialTokens :: ![TokenId]
  , sopAbsentCredentials :: ![TokenId]
  , sopIdentity :: !(Either IdentityRefusal [TokenId])  -- ^ Right: ids the open would seed
  , sopOps :: ![MigrationOp]
  , sopSnapshot :: !StoreSnapshot   -- ^ the observed state; migrate rechecks against it
  } deriving (Eq, Show)

planStoreOpen :: FilePath -> OwnerState -> Config -> StoreSnapshot -> StoreOpenPlan
planStoreOpen path owner cfg snap = StoreOpenPlan
  { sopPath = path
  , sopOwner = owner
  , sopSchema = snapSchema snap
  , sopStoredTokens = map trId (snapTokens snap)
  , sopCredentialTokens = snapCredentialTokens snap
  , sopAbsentCredentials = absent
  , sopIdentity = map trId . planSeeds <$> reconcileIdentities (desiredTokens cfg) (snapTokens snap)
  , sopOps =
      [OpCreateCredentialsTable | snapSchema snap == 1]
      ++ [OpFreezeCredentials absent | not (null absent)]
      ++ [OpSetSchemaVersion (snapSchema snap) sqliteSchemaVersion | snapSchema snap /= sqliteSchemaVersion]
  , sopSnapshot = snap
  }
  where
    absent = tokensWithoutCredentials (snapTokens snap) (snapCredentialTokens snap)

planVerdict :: StoreOpenPlan -> PlanVerdict
planVerdict p = case sopIdentity p of
  Left r -> VerdictIdentityRefused r
  Right _
    | null (sopOps p) -> VerdictOpenable
    | otherwise -> VerdictMigrationRequired

-- | Diagnose a store for this config WITHOUT writing the database:
-- refuses a live owner, then reads a read-only snapshot and
-- plans (a WAL-format store can gain sidecars from the snapshot
-- open; see 'readStoreSnapshot'). The result names ids, versions
-- and reasons only. The path is resolved once up front: every
-- sidecar and every open below derives from the real file —
-- under a UTF-8 filesystem encoding (other locales may
-- double-encode non-ASCII names). Bare @file:@ URIs decode once
-- up front, so guards and SQLite agree on the decoded file;
-- query/fragment, undecodable, nested, and empty spellings
-- refuse. Spellings that do not round-trip through UTF-8 are out
-- of scope (POSIX uses the original bytes while SQLite opens the
-- replacement spelling).
checkStoreOpen :: FilePath -> Config -> IO (Either StoreError StoreOpenPlan)
checkStoreOpen path0 cfg = withStoreSpelling path0 $ \path -> do
  eReg <- requireRegularStore path
  case eReg of
    Left err -> pure (Left err)
    Right () -> do
      owner <- probeOwner (scAllowEnvSeams (cfgStorage cfg)) path
      case owner of
        OwnerLive why -> pure (Left (StoreSecondWriter ("store is in use (" ++ why ++ "): " ++ path)))
        _ -> fmap (planStoreOpen path owner cfg) <$> readStoreSnapshot path

-- | Like 'checkStoreOpen' but a cold journal does not refuse: used
-- by the migration to learn its verdict before deciding whether the
-- cold journal may be cleared, and by @store check@ to accept a
-- current store whose only blocker is the cold journal.
checkStoreOpenAllowCold :: FilePath -> Config -> IO (Either StoreError StoreOpenPlan)
checkStoreOpenAllowCold path0 cfg = withStoreSpelling path0 $ \path -> do
  eReg <- requireRegularStore path
  case eReg of
    Left err -> pure (Left err)
    Right () -> do
      owner <- probeOwner (scAllowEnvSeams (cfgStorage cfg)) path
      case owner of
        OwnerLive why -> pure (Left (StoreSecondWriter ("store is in use (" ++ why ++ "): " ++ path)))
        _ -> fmap (planStoreOpen path owner cfg) <$> readStoreSnapshotAllowCold path

renderPlan :: StoreOpenPlan -> String
renderPlan p = unlines
  [ "store: " ++ sopPath p
  , "lock: " ++ ownerWord (sopOwner p)
  , "schema: " ++ show (sopSchema p) ++ " (this build: " ++ show sqliteSchemaVersion ++ ")"
  , "tokens: " ++ ids (sopStoredTokens p)
  , "credentials: " ++ ids (sopCredentialTokens p)
  , "credentials-absent: " ++ ids (sopAbsentCredentials p)
  , "identity: " ++ either (("refused: " ++) . renderIdentityRefusal) (const "ok") (sopIdentity p)
  , "seeds: " ++ either (const "none") ids (sopIdentity p)
  , "actions: " ++ ops (sopOps p)
  , "verdict: " ++ verdictWord (planVerdict p)
  ]
  where
    ids [] = "none"
    ids ts = unwords (map tokenSerial ts)
    ops [] = "none"
    ops os = intercalate "; " (map op os)
    op OpCreateCredentialsTable = "create-credentials-table"
    op (OpFreezeCredentials ts) = "freeze-credentials " ++ ids ts
    op (OpSetSchemaVersion a b) = "set-schema-version " ++ show a ++ "->" ++ show b
    ownerWord OwnerAbsent = "offline"
    ownerWord (OwnerStale n) = "offline (stale lock, pid " ++ show n ++ " dead; left in place)"
    ownerWord (OwnerLive why) = "live (" ++ why ++ ")"
    verdictWord VerdictOpenable = "ok"
    verdictWord VerdictMigrationRequired = "migration-required"
    verdictWord (VerdictIdentityRefused _) = "identity-refused"

-- | Operator tag and detail for a store-level refusal. Messages carry
-- paths, ids, versions and reasons only.
renderStoreRefusal :: StoreError -> (String, String)
renderStoreRefusal e = case e of
  StoreSecondWriter m -> ("store-live", m
    ++ "; stop any store owner and retry; if none holds it, inspect the lock file and retry")
  StoreJournalPresent j -> ("store-journal-present", "a hot or unrecognized rollback journal is present (" ++ j
    ++ "); do not delete it. See docs/operations-notes.md, Interrupted migration:"
    ++ " only a hot journal with a complete header on a writable store rolls back under the serving open;"
    ++ " an unrecognized header needs the verified backup")
  StoreJournalCold j -> ("store-journal-cold", "a cold rollback journal is present (" ++ j
    ++ "), or migration found the store busy: stop any process that holds the store,"
    ++ " run haskoki-ctl store check, and retry store migrate with a valid backup directory"
    ++ " unless check names another blocker;"
    ++ " if migrate keeps reporting cold, stop and investigate: wait for a persistent"
    ++ " SQLite lock holder to release once identified, or retry migrate once for a cold"
    ++ " journal that appeared with no holder left;"
    ++ " see docs/operations-notes.md, Interrupted migration")
  StoreForeignSidecar p -> ("store-foreign-sidecar",
    "unexpected WAL sidecar files were detected (" ++ p ++ ");"
    ++ " do not start the service. When the sidecars are confirmed stray,"
    ++ " move " ++ wal ++ " and " ++ shm
    ++ " aside (keep both files) and run store check again;"
    ++ " otherwise keep them with the database;"
    ++ " see docs/operations-notes.md, Upgrade, backup and recovery")
    where (wal, shm) = walShmPair p
  StoreNeedsMigration f t -> ("store-migration-required", "schema " ++ show f
    ++ " needs haskoki-ctl store migrate to reach schema " ++ show t)
  StoreSchemaVersion want found -> ("store-unsupported-version", "store schema " ++ found
    ++ " is not one this build opens or migrates (this build: " ++ show want
    ++ "); inspect the schema marker with SQLite tooling: reopen with the writing build"
    ++ " if a newer haskoki wrote it, or restore a backup if the marker itself is damaged")
  StoreCorrupt m -> ("store-corrupt", m)
  StoreFull m -> ("store-full", m)
  -- A sidecar the owner probe cannot create (see 'takeOwnership':
  -- read-only directory or mount, no space) names the lock, never
  -- a live owner. Same prefix-match shape as the store-missing tag.
  StoreIO m | "store lock cannot be created: " `isPrefixOf` m ->
    ("store-lock-unwritable", m)
  StoreIO m -> ("store-unreadable", m)
  other -> ("store-unreadable", show other)

-- | The @(-wal, -shm)@ pair for a foreign sidecar path: whichever of
-- the two was found, the remedy moves both aside.
walShmPair :: FilePath -> (FilePath, FilePath)
walShmPair p
  | "-wal" `isSuffixOf` p = (p, take (length p - 4) p ++ "-shm")
  | "-shm" `isSuffixOf` p = (take (length p - 4) p ++ "-wal", p)
  | otherwise = (p, p)  -- unreachable: finders only return the two suffixes

-- ---------------------------------------------------------------------------
-- Explicit migration
-- ---------------------------------------------------------------------------

-- | Test seams of 'migrateStoreWith'. 'noMigrateHooks' is production.
data MigrateHooks = MigrateHooks
  { mhAfterPlan :: IO ()
    -- ^ after the unowned plan, before taking ownership
  , mhOnColdClear :: IO ()
    -- ^ once the cold journal is cleared, already vanished, or
    -- classified absent on recheck (an empty or unstatable file
    -- can remain); reporting after the flag is set is the CLI
    -- wrapper's job (the default hook is a no-op, and the error
    -- value itself carries no clear status)
  , mhAfterBackup :: IO ()
    -- ^ after the verified backup, before the transaction
  , mhOnBackupVerified :: FilePath -> Int -> String -> IO ()
    -- ^ with the backup path, byte count and SHA-256 hex the moment
    -- verification passes, before the transaction begins: the
    -- pre-BEGIN record, so a backup outlives a killed run with its
    -- digest already reported
  , mhClock :: IO Integer
    -- ^ epoch seconds (default: 'epochTime'), read twice: once for the
    -- backup name and 'mrEpoch', once at completion for 'mrCompleted'
  , mhDigest :: ByteString -> IO (Either String String)
    -- ^ SHA-256 of the backup bytes (default: 'sha256Hex'); a 'Left'
    -- refuses before any file is written
  , mhAfterCreate :: FilePath -> IO ()
    -- ^ after a backup or receipt file is created, before its bytes
    -- are written (a failure here is a failure after the create)
  , mhLink :: FilePath -> FilePath -> IO ()
    -- ^ move the receipt temporary into place (default: 'createLink');
    -- a seam so tests can fail the link with a chosen errno
  , mhSQLite :: MigrationHooks
  }

noMigrateHooks :: MigrateHooks
noMigrateHooks = MigrateHooks
  { mhAfterPlan = pure ()
  , mhOnColdClear = pure ()
  , mhAfterBackup = pure ()
  , mhOnBackupVerified = \_ _ _ -> pure ()
  , mhClock = truncate . toRational <$> epochTime
  , mhDigest = sha256Hex
  , mhAfterCreate = \_ -> pure ()
  , mhLink = createLink
  , mhSQLite = noMigrationHooks
  }

-- | What a completed migration did. Ids, versions, paths and the
-- backup digest only: no credential byte.
data MigrationReceipt = MigrationReceipt
  { mrStore :: !FilePath, mrFrom :: !Int, mrTo :: !Int
  , mrFrozen :: ![TokenId], mrPreserved :: ![TokenId]
  , mrBackup :: !FilePath, mrBackupBytes :: !Int, mrBackupSha256 :: !String
  , mrReceipt :: !FilePath
  , mrEpoch :: !Integer      -- ^ the clock reading in the backup name
  , mrCompleted :: !Integer  -- ^ read after the commit and its read-back
  , mrColdJournalRemoved :: !Bool  -- ^ a cold journal was cleared before migrating
  } deriving (Eq, Show)

data MigrateOutcome = MigrateNotNeeded | Migrated !MigrationReceipt deriving (Eq, Show)

-- | Why a migration did not complete. Every constructor before
-- 'MigrateTxnFailed' is a refusal that leaves no trusted artifact
-- behind: a failed backup may leave a file when its cleanup
-- fails, but no digest is recorded for it, so restore cannot
-- trust it; mutations from the clear step — a removed journal,
-- possible recovery replay — surface as 'MigrateStore' with the
-- clearing reported separately;
-- 'MigrateTxnFailed' failed before committing with no uniform
-- rollback account (a COMMIT failure with an open transaction
-- attempts a rollback, and is classified as rolled-back only
-- when the rollback succeeds, autocommit is restored, and the
-- journal reads absent — already-ended transactions go directly
-- to unknown, and an unstatable journal reads absent without
-- certifying unchanged bytes; a body failure attempts rollback
-- best-effort with errors discarded; setup failures never begin
-- one — run @store check@ to establish state), while
-- 'MigrateCommitUnknown' may already have committed (run @store
-- check@ before retrying). A stored rowless token without a
-- catalog credential is reported as the identity refusal it is
-- ('RefuseStoredUnconfigured').
data MigrateError
  = MigrateConfig !PreflightRefusal
  | MigrateUnsafeBackupDir !FilePath !String
  | MigrateStore !StoreError
  | MigrateIdentityRefused !IdentityRefusal
  | MigrateStoreChanged
  | MigrateBackupExists !FilePath
  | MigrateBackupFailed !String
  | MigrateTxnFailed !FilePath !StoreError       -- ^ backup path; failed before committing (setup, begin, body, or a rolled-back COMMIT — no blanket rollback claim; the report names store check)
  | MigrateCommitUnknown !FilePath !StoreError   -- ^ backup path; COMMIT failed, outcome unknown (run check)
  | MigrateVerifyFailed !FilePath !String        -- ^ committed; post-check failed
  | MigrateReceiptFailed !FilePath !String       -- ^ committed; receipt finalization failed
  deriving (Eq, Show)

migrateStore :: FilePath -> Config -> FilePath -> IO (Either MigrateError MigrateOutcome)
migrateStore = migrateStoreWith noMigrateHooks

(>>?) :: IO (Either e a) -> (a -> IO (Either e b)) -> IO (Either e b)
m >>? k = m >>= either (pure . Left) k
infixl 1 >>?

-- | The explicit migration (AC-05). Refusals before the planning
-- snapshot touch nothing but stats and a lock probe: config
-- selection, backup-dir safety, a non-regular store, and a live
-- owner. The snapshot read itself (a read-only connection with a
-- journal/sidecar blocker run before and after the SELECTs, plus
-- a file-identity comparison) refuses hot and unknown journals
-- and foreign -wal/-shm siblings (cold journals refuse in the
-- strict read; the migration plans through them with the
-- cold-tolerant read). On a WAL-format database the read-only
-- open itself can create -shm/-wal sidecars when the directory
-- is writable (observed: a 32KiB -shm), which the post-read
-- check then reports as foreign when the snapshot itself
-- succeeded (a snapshot error or a vanished file takes
-- precedence); the identity comparison notices replacement,
-- resizing, or modification across a second boundary mid-read
-- (same-size same-second rewrites are invisible to the
-- device/inode/size/second-mtime identity).
-- The handle changes no database bytes. Identity drift and a
-- current store are decided by the plan AFTER the snapshot:
-- drift refuses (MigrateIdentityRefused) while a current store
-- succeeds (MigrateNotNeeded). A cold
-- journal is cleared only after the plan says the migration
-- proceeds: the verdict is taken first through a read-only snapshot
-- that tolerates the cold journal, and any other outcome leaves the
-- journal untouched. Under the single ownership window: a fresh
-- snapshot must equal the planned one, then the cold journal is
-- cleared (if any; a vanished one counts as cleared), then a new
-- verified backup, then ONE transaction, then a read-back check,
-- then a non-overwriting receipt. Every outcome after the flag
-- is set reports it through the CLI wrapper's print and flag
-- (the default hook is a no-op; the error value itself carries
-- no clear status).
migrateStoreWith :: MigrateHooks -> FilePath -> Config -> FilePath -> IO (Either MigrateError MigrateOutcome)
migrateStoreWith hooks path0 cfg backupDir = do
  -- Spelling refusal first (precise diagnosis); the config check
  -- then runs on the operator's spelling as before (a URI twin
  -- of the configured path mismatches conservatively).
  ePath <- resolveStoreSpelling path0
  case ePath of
    Left r -> pure (Left (MigrateStore (StoreIO (renderSpellingRefusal r path0))))
    Right path ->
      (first MigrateConfig <$> configSelectsStore path0 cfg) >>? \() ->
        checkBackupDir path backupDir >>? \() ->
          migrateResolved hooks path cfg backupDir

-- | 'migrateStoreWith' on an already-resolved path: the config check
-- ran on the operator's spelling, the backup-directory guard ran on
-- the resolved path (a link must not smuggle backups beside the
-- real file), and every sidecar and every open below derives from
-- the real file — under a UTF-8 filesystem encoding (other
-- locales may double-encode non-ASCII names). Bare @file:@ URIs
-- decode once up front (see the spelling rule); anything that
-- would split guards from the opener refuses instead.
-- Spellings that do not round-trip through UTF-8 are out of
-- scope (POSIX uses the original bytes while SQLite opens the
-- replacement spelling).
migrateResolved :: MigrateHooks -> FilePath -> Config -> FilePath -> IO (Either MigrateError MigrateOutcome)
migrateResolved hooks path cfg backupDir = do
  ePlan <- first MigrateStore <$> checkStoreOpen path cfg
  case ePlan of
    Left (MigrateStore (StoreJournalCold _)) -> handleCold
    Left err -> pure (Left err)
    Right plan -> runPlan False plan
  where
    -- Plan despite the cold journal, without touching it, to learn
    -- the verdict. Only a migration-required verdict proceeds to
    -- ownership, where the journal is cleared after the snapshot
    -- comparison; any other outcome leaves it untouched.
    handleCold :: IO (Either MigrateError MigrateOutcome)
    handleCold = do
      eSnap <- first MigrateStore <$> checkStoreOpenAllowCold path cfg
      case eSnap of
        Left err -> pure (Left err)
        Right plan -> case planVerdict plan of
          VerdictMigrationRequired -> runPlan True plan
          VerdictIdentityRefused r -> pure (Left (MigrateIdentityRefused r))
          VerdictOpenable -> pure (Right MigrateNotNeeded)
    runPlan :: Bool -> StoreOpenPlan -> IO (Either MigrateError MigrateOutcome)
    runPlan needsClear plan = case planVerdict plan of
      VerdictIdentityRefused r -> pure (Left (MigrateIdentityRefused r))
      VerdictOpenable -> pure (Right MigrateNotNeeded)
      VerdictMigrationRequired ->
        pure (traverse freezeOne (rowless plan)) >>? \freeze -> do
          mhAfterPlan hooks
          owned <- withOwnedStoreFile (scAllowEnvSeams (cfgStorage cfg)) path (\o -> underOwnership needsClear o plan freeze)
          pure (either (Left . MigrateStore) id owned)
    -- The owned re-read tolerates the cold journal exactly when
    -- the unowned plan did, so the comparison is like-for-like.
    readUnderOwnership needsClear
      | needsClear = readStoreSnapshotAllowCold path
      | otherwise = readStoreSnapshot path
    rowless plan =
      [t | t <- snapTokens (sopSnapshot plan), trId t `elem` sopAbsentCredentials plan]
    -- Unreachable after an accepted reconciliation (every stored
    -- token is configured exactly once); kept fail-closed.
    freezeOne t = maybe
      (Left (MigrateIdentityRefused (RefuseStoredUnconfigured (trId t) (trSlot t) (trLabel t))))
      Right (catalogCredential cfg (trId t))
    underOwnership :: Bool -> OwnedStoreFile -> StoreOpenPlan -> [CredentialRecord]
                   -> IO (Either MigrateError MigrateOutcome)
    underOwnership needsClear o plan freeze =
      (first MigrateStore <$> readUnderOwnership needsClear) >>? \snap ->
      if snap /= sopSnapshot plan then pure (Left MigrateStoreChanged) else do
      eClear <- if needsClear
        then clearColdJournalOwned (mhOnColdClear hooks) path
        else pure (Right ())
      case eClear of
        Left err -> pure (Left (MigrateStore err))
        Right () -> do
          now <- mhClock hooks
          writeVerifiedBackup hooks path backupDir (sopSchema plan) now snap >>? \(bak, nBytes, sha) -> do
            mhOnBackupVerified hooks bak nBytes sha
            mhAfterBackup hooks
            eTx <- migrateOwned o (SQLiteMigration (sopSchema plan) freeze) (mhSQLite hooks)
            case eTx of
              Left (MigrateTxnUnchanged err) -> pure (Left (MigrateTxnFailed bak err))
              Left (MigrateTxnCommitUnknown err) -> pure (Left (MigrateCommitUnknown bak err))
              Right () ->
                verifyMigrated plan bak >>? \() -> do
                  done <- mhClock hooks
                  let rc = MigrationReceipt
                        { mrStore = path, mrFrom = sopSchema plan, mrTo = sqliteSchemaVersion
                        , mrFrozen = map crToken freeze, mrPreserved = sopCredentialTokens plan
                        , mrBackup = bak, mrBackupBytes = nBytes, mrBackupSha256 = sha
                        , mrReceipt = bak ++ ".receipt", mrEpoch = now, mrCompleted = done
                        , mrColdJournalRemoved = needsClear }
                  w <- writeReceipt (mhAfterCreate hooks) (mhLink hooks) (mrReceipt rc) (BC8.pack (renderReceipt rc)) backupDir
                  pure $ case w of
                    Written -> Right (Migrated rc)
                    NameTaken -> Left (MigrateReceiptFailed bak (mrReceipt rc ++ " appeared during the migration"))
                    WriteFailed why -> Left (MigrateReceiptFailed bak why)
    verifyMigrated plan bak = do
      e <- readStoreSnapshot path
      pure $ case e of
        Left err -> Left (MigrateVerifyFailed bak ("read-back failed: " ++ show err))
        Right s
          | snapSchema s /= sqliteSchemaVersion -> Left (MigrateVerifyFailed bak "schema marker not advanced")
          | not (null (tokensWithoutCredentials (snapTokens s) (snapCredentialTokens s))) ->
              Left (MigrateVerifyFailed bak "a token still has no credential row")
          | map trId (snapTokens s) /= sopStoredTokens plan -> Left (MigrateVerifyFailed bak "token set changed")
          | snapObjectCount s /= snapObjectCount (sopSnapshot plan)
              || snapJobCount s /= snapJobCount (sopSnapshot plan) ->
              Left (MigrateVerifyFailed bak "object or job count changed")
          | otherwise -> Right ()

baseName, dirName :: FilePath -> FilePath
baseName = reverse . takeWhile (/= '/') . reverse
dirName p = case dropWhile (/= '/') (reverse p) of
  [] -> "."
  [_] -> "/"
  (_ : rest) -> reverse rest

-- | The 100 backup names tried in order for a store, directory,
-- source schema and epoch:
-- @<dir>/<store-basename>.pre-migrate.schema<N>.<epoch>[-k].bak@.
backupCandidates :: FilePath -> FilePath -> Int -> Integer -> [FilePath]
backupCandidates store dir from epoch =
  [ dir ++ "/" ++ stem ++ suffix ++ ".bak" | suffix <- "" : ["-" ++ show k | k <- [1 .. 99 :: Int]] ]
  where stem = baseName store ++ ".pre-migrate.schema" ++ show from ++ "." ++ show epoch

-- | The backup directory must exist, be a real directory (not a
-- symlink), be writable, and not be the store's own directory.
checkBackupDir :: FilePath -> FilePath -> IO (Either MigrateError ())
checkBackupDir store dir = do
  eL <- tryIOError (getSymbolicLinkStatus dir)
  case eL of
    Left _ -> unsafe "does not exist"
    Right st
      | isSymbolicLink st -> unsafe "is a symbolic link; pass the real directory"
      | not (isDirectory st) -> unsafe "is not a directory"
      | otherwise -> do
          w <- tryIOError (fileAccess dir False True True)
          if w /= Right True then unsafe "is not writable" else do
            eS <- tryIOError (getFileStatus (dirName store))
            case eS of
              Right sd | deviceID sd == deviceID st && fileID sd == fileID st ->
                unsafe "is the store's own directory; keep backups apart from the store"
              _ -> pure (Right ())
  where unsafe why = pure (Left (MigrateUnsafeBackupDir dir why))

data ExclusiveWrite = Written | NameTaken | WriteFailed !String

-- | Create a NEW file (O_EXCL, 0600, 'guardFlags'), write all bytes,
-- fsync it and its directory. Never overwrites: an existing name is
-- 'NameTaken'. Any failure after the create, or an asynchronous
-- exception (re-thrown), attempts to remove the file; the message
-- says whether that removal succeeded. The create, the
-- descriptor release and the cleanup run masked -- the release is
-- registered before the write is unmasked, so no window leaks the
-- descriptor; only the byte writing is interruptible.
writeExclusive :: (FilePath -> IO ()) -> FilePath -> ByteString -> FilePath -> IO ExclusiveWrite
writeExclusive afterCreate path bytes dir = mask $ \restore -> do
  eFd <- tryIOError (openFd path WriteOnly guardFlags { creat = Just 0o600, exclusive = True })
  case eFd of
    Left e
      | isAlreadyExistsError e -> pure NameTaken
      | otherwise -> pure (WriteFailed ("cannot create " ++ path ++ ": " ++ show e))
    Right fd -> do
      r <- try (((restore (fill fd) `finally` closeFd fd) >> syncDir dir))
      case r of
        Right () -> pure Written
        Left e -> do
          eRm <- tryIOError (removeLink path)
          case fromException e of
            Just (io :: IOException) ->
              pure (WriteFailed ("cannot write " ++ path ++ " (" ++ rmWord eRm ++ "): " ++ show io))
            Nothing -> throwIO e
  where
    rmWord (Right ()) = "incomplete file removed"
    rmWord (Left _) = "incomplete file may remain"
    fill fd = afterCreate path >> writeAll fd bytes >> fileSynchronise fd
    writeAll :: Fd -> ByteString -> IO ()
    writeAll fd bs
      | BS.null bs = pure ()
      | otherwise = do
          n <- BS.useAsCStringLen bs (\(p, len) -> fdWriteBuf fd (castPtr p) (fromIntegral len))
          writeAll fd (BS.drop (fromIntegral n) bs)

-- | fsync a directory, so a create, link or unlink in it is durable.
syncDir :: FilePath -> IO ()
syncDir dir = bracket (openFd dir ReadOnly guardFlags) closeFd fileSynchronise

-- | Write a receipt so that its name never holds a truncated file on
-- the link path: the bytes go to a new temporary with a unique name
-- (the final name plus the process id and a per-attempt counter, so
-- a stale temporary from a crashed run is ignored, never fatal by
-- itself — fatal only if every candidate name is occupied and the
-- bounded search exhausts),
-- written and fsynced by 'writeExclusive'; it is then moved into
-- place by link(2) plus unlink (unlike rename(2), link never
-- replaces an existing name), and the directory is fsynced; a
-- link-successful but sync-failed run still reports
-- 'MigrateReceiptFailed' with the final name already visible. Our
-- temporary's removal is attempted on every path after its write
-- (best-effort; failures strand it until a later dead-owner
-- sweep). Stale temporaries from provably-dead owners are swept
-- before writing (see 'sweepStaleReceiptTemps'). On filesystems
-- without hard links (the link fails with EPERM, ENOTSUP, EOPNOTSUPP
-- or EXDEV) it falls back to an O_EXCL create-and-write of the final
-- name, which still never overwrites — but unlike the link path, a
-- kill -9 mid-write there can strand a truncated final name; any
-- other link failure stays a receipt failure.
writeReceipt :: (FilePath -> IO ()) -> (FilePath -> FilePath -> IO ()) -> FilePath -> ByteString -> FilePath -> IO ExclusiveWrite
writeReceipt afterCreate link final bytes dir = mask $ \restore -> do
  pid <- getProcessID
  sweepStaleReceiptTemps dir (fromIntegral pid)
  attempt restore pid 0
  where
    attempt restore pid nonce
      | nonce > maxReceiptTmpAttempts =
          pure (WriteFailed ("cannot find a free temporary receipt name for " ++ final))
      | otherwise = do
          let tmp = final ++ ".tmp." ++ show pid ++ "." ++ show nonce
          w <- restore (writeExclusive afterCreate tmp bytes dir)
          case w of
            NameTaken -> attempt restore pid (nonce + 1)
            WriteFailed why -> pure (WriteFailed why)
            Written -> do
              eLink <- tryIOError (link tmp final)
              case eLink of
                Right () -> do
                  _ <- tryIOError (removeLink tmp)
                  eSync <- tryIOError (syncDir dir)
                  pure $ case eSync of
                    Left e -> WriteFailed ("cannot sync " ++ dir ++ ": " ++ show e)
                    Right () -> Written
                Left e
                  | isAlreadyExistsError e -> do
                      _ <- tryIOError (removeLink tmp)
                      _ <- tryIOError (syncDir dir)
                      pure NameTaken
                  | isLinkUnsupported e -> do
                      _ <- tryIOError (removeLink tmp)
                      restore (writeExclusive afterCreate final bytes dir)
                  | otherwise -> do
                      _ <- tryIOError (removeLink tmp)
                      _ <- tryIOError (syncDir dir)
                      pure (WriteFailed ("cannot move " ++ tmp ++ " to " ++ final ++ ": " ++ show e))

-- | Remove stale receipt temporaries from provably-dead owners:
-- files named @<receipt>.tmp.\<pid\>.\<nonce\>@ in the backup
-- directory whose pid is dead ('pidIsDead') and is not ours. Files
-- that do not parse, live owners, unknowable liveness and our own
-- pid are all left alone. Best-effort: every failure is ignored, so
-- a sweep that cannot complete only leaves files for the next run.
-- | Directory entries streamed over a POSIX directory handle (no
-- @directory@ dependency in the library). Unlike 'listDirectory',
-- @.@ and @..@ are included; callers filter them.
listDirEntries :: FilePath -> IO [String]
listDirEntries dir =
  bracket (openDirStream dir) closeDirStream $ \s -> collect s []
  where
    collect s acc = do
      e <- readDirStream s
      if null e then pure (reverse acc) else collect s (e : acc)

-- The sweep always reads the real @\/proc@, even under the env-seam
-- opt-in: deleting another live owner's receipt temporary on the
-- strength of a masked root would turn a correct migration into a
-- spurious receipt failure. Liveness masking stays scoped to
-- ownership decisions (probeOwner/takeOwnership), never janitorial
-- deletion.
sweepStaleReceiptTemps :: FilePath -> Int -> IO ()
sweepStaleReceiptTemps dir self = do
  eNames <- tryIOError (listDirEntries dir)
  case eNames of
    Left _ -> pure ()
    Right names -> forM_ (filter (\n -> n /= "." && n /= "..") names) $ \name ->
      case stalePid name of
        Just pid | pid /= self -> do
          dead <- pidIsDead False pid
          whenDead dead (dir ++ "/" ++ name)
        _ -> pure ()
  where
    whenDead True p = do
      _ <- tryIOError (removeLink p)
      pure ()
    whenDead False _ = pure ()
    stalePid :: String -> Maybe Int
    stalePid name
      | ".receipt.tmp." `isInfixOf` name = case breakOn ".tmp." name of
          Just rest -> case span (/= '.') rest of
            (pidTxt@(_ : _), '.' : nonceTxt) -> case (reads pidTxt, reads nonceTxt) of
              ([(pid, "")], [(nonce, "")]) | pid > 0 && nonce >= (0 :: Int) -> Just pid
              _ -> Nothing
            _ -> Nothing
          Nothing -> Nothing
      | otherwise = Nothing
    breakOn :: String -> String -> Maybe String
    breakOn pat str = case str of
      [] -> Nothing
      _ | pat `isPrefixOf` str -> Just (drop (length pat) str)
      (_ : t) -> breakOn pat t

-- | How many unique temporary receipt names are tried before the
-- receipt write gives up (a stale temporary only costs one attempt).
maxReceiptTmpAttempts :: Int
maxReceiptTmpAttempts = 128

-- | Errnos that mean the filesystem cannot make hard links at all, as
-- opposed to a conflict on this name (EEXIST, handled before this) or
-- any other failure: EPERM, ENOTSUP, EOPNOTSUPP, EXDEV. Only these
-- take the receipt's direct-write fallback; anything else, including
-- a missing errno, fails closed with no fallback.
isLinkUnsupported :: IOException -> Bool
isLinkUnsupported e = case ioe_errno e of
  Just n -> Errno n `elem` [ePERM, eNOTSUP, eOPNOTSUPP, eXDEV]
  Nothing -> False

-- | Hash, then copy the owned store into the first free candidate
-- name, then verify by byte readback and by a read-only snapshot
-- equal to the store's (file identity aside). A hashing failure
-- refuses before any file exists. A backup that fails verification
-- is removed again (best effort, directory synced), never left for
-- a later restore to trust: only our own O_EXCL create can be at
-- this path.
writeVerifiedBackup :: MigrateHooks -> FilePath -> FilePath -> Int -> Integer -> StoreSnapshot
                    -> IO (Either MigrateError (FilePath, Int, String))
writeVerifiedBackup hooks store dir from now snap =
  readOrFail ("cannot read the store " ++ store) store >>? \bytes ->
  (first MigrateBackupFailed <$> mhDigest hooks bytes) >>? \sha ->
  pickAndWrite bytes candidates >>? \bak -> do
    eBack <- tryIOError (readFileCloexec bak)
    case eBack of
      Left e -> discard bak ("cannot read back the backup " ++ bak ++ ": " ++ show e)
      Right back -> do
        eSnap <- readStoreSnapshot bak
        case eSnap of
          _ | back /= bytes -> discard bak ("backup readback differs: " ++ bak)
          Right b | b { snapFile = snapFile snap } == snap -> pure (Right (bak, BS.length bytes, sha))
          Right _ -> discard bak ("backup does not read as the same store: " ++ bak)
          Left err -> discard bak ("backup does not open read-only: " ++ bak ++ ": " ++ show err)
  where
    discard bak why = do
      _ <- tryIOError (removeLink bak)
      _ <- tryIOError (syncDir dir)
      pure (Left (MigrateBackupFailed why))
    candidates = backupCandidates store dir from now
    readOrFail what p = first (\e -> MigrateBackupFailed (what ++ ": " ++ show e)) <$> tryIOError (readFileCloexec p)
    pickAndWrite _ [] = pure (Left (MigrateBackupExists firstName))
    pickAndWrite bytes (c : cs) = do
      receiptTaken <- exists (c ++ ".receipt")
      if receiptTaken then pickAndWrite bytes cs else do
        r <- writeExclusive (mhAfterCreate hooks) c bytes dir
        case r of
          Written -> pure (Right c)
          NameTaken -> pickAndWrite bytes cs
          WriteFailed why -> pure (Left (MigrateBackupFailed why))
    firstName = case candidates of
      (c : _) -> c
      [] -> dir
    exists p = either (const False) (const True) <$> tryIOError (getSymbolicLinkStatus p)

renderReceipt :: MigrationReceipt -> String
renderReceipt rc = unlines
  [ "haskoki-store-migration-receipt: 1"
  , "store: " ++ mrStore rc
  , "schema-from: " ++ show (mrFrom rc)
  , "schema-to: " ++ show (mrTo rc)
  , "frozen-credentials: " ++ ids (mrFrozen rc)
  , "preserved-credentials: " ++ ids (mrPreserved rc)
  , "backup: " ++ mrBackup rc
  , "backup-bytes: " ++ show (mrBackupBytes rc)
  , "backup-sha256: " ++ mrBackupSha256 rc
  , "backup-epoch-seconds: " ++ show (mrEpoch rc)
  , "completed-epoch-seconds: " ++ show (mrCompleted rc)
  , "cold-journal-removed: " ++ if mrColdJournalRemoved rc then "yes" else "no"
  ]
  where ids [] = "none"; ids ts = unwords (map tokenSerial ts)

-- | Operator tag and detail. Paths, ids, versions and reasons only.
renderMigrateError :: MigrateError -> (String, String)
renderMigrateError e = case e of
  MigrateConfig r -> ("config-mismatch", renderPreflightRefusal r)
  MigrateUnsafeBackupDir d why -> ("migrate-unsafe-backup-dir", d ++ " " ++ why ++ "; nothing was written")
  MigrateStore se -> renderStoreRefusal se
  MigrateIdentityRefused r -> ("store-identity-refused", renderIdentityRefusal r)
  MigrateStoreChanged -> ("migrate-store-changed", "the store snapshot no longer matches the plan"
    ++ " (schema, token records, counts, credential coverage, metadata, or file identity);"
    ++ " this run did not change the store database. Run store check again")
  MigrateBackupExists p -> ("migrate-backup-exists", "every backup name is taken (first: " ++ p
    ++ "); the store database was not changed")
  MigrateBackupFailed why -> ("migrate-backup-failed", why ++ "; the store was not changed")
  MigrateTxnFailed bak se -> ("migrate-failed", "the migration transaction failed ("
    ++ snd (renderStoreRefusal se) ++ ") before committing;"
    ++ " run store check to establish the store state, restoring the verified backup on inconsistency."
    ++ " Backup kept at " ++ bak)
  MigrateCommitUnknown bak se -> ("migrate-commit-unknown", "the migration COMMIT failed and its outcome is unknown ("
    ++ snd (renderStoreRefusal se) ++ "); the store may already be at schema 3 -- run store check before retrying. Backup kept at " ++ bak)
  MigrateVerifyFailed bak why -> ("migrate-verify-failed", "the migration committed but its "
    ++ "read-back failed: " ++ why ++ ". Stop the rollout; restore from " ++ bak
    ++ " (docs/operations-notes.md, Upgrade, backup and recovery)")
  MigrateReceiptFailed bak why -> ("migrate-receipt-failed", "the migration committed; "
    ++ "receipt finalization failed (" ++ why ++ "). Backup at " ++ bak)

-- | Like 'renderMigrateError', but for a migration run that already
-- cleared a cold journal: the post-clear refusals must not claim
-- nothing was written or the store was unchanged. Even "the
-- database was not changed" is unclaimable: SQLite recovery
-- during the clear's BEGIN IMMEDIATE can roll back a hot journal
-- that appeared after the owned snapshot, rewriting database
-- pages before any backup is made. The tags are unchanged;
-- anything that can only fail before the clear renders exactly
-- as before.
renderMigrateErrorAfterClear :: MigrateError -> (String, String)
renderMigrateErrorAfterClear e = case e of
  MigrateBackupExists p -> ("migrate-backup-exists",
    "every backup name is taken (first: " ++ p
      ++ "); no backup was written (a cold journal was unlinked or treated as absent when rechecked; see above)")
  MigrateBackupFailed why -> ("migrate-backup-failed", why
    ++ "; the backup was not completed (a cold journal was unlinked or treated as absent when rechecked; see above)")
  MigrateTxnFailed bak se -> ("migrate-failed", "the migration transaction failed ("
    ++ snd (renderStoreRefusal se)
    ++ ") before committing (a cold journal was unlinked or treated as absent when rechecked; see above);"
    ++ " run store check to establish the store state, restoring the verified backup on inconsistency."
    ++ " Backup kept at "
    ++ bak)
  MigrateCommitUnknown bak se -> ("migrate-commit-unknown", "the migration COMMIT failed and its outcome is unknown ("
    ++ snd (renderStoreRefusal se)
    ++ "); the store may already be at schema 3 -- run store check before retrying (a cold journal was unlinked or treated as absent when rechecked; see above). Backup kept at "
    ++ bak)
  _ -> renderMigrateError e
