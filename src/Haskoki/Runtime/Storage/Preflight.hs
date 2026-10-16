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
  ) where

import Control.Exception (IOException, bracket, finally, fromException, mask, throwIO, try)
import Data.Bifunctor (first)
import Data.Bits (shiftR, (.&.))
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BC8
import Data.ByteString (ByteString)
import Data.List (intercalate)
import Data.Word (Word8)
import Foreign.Ptr (castPtr)
import System.IO.Error (isAlreadyExistsError, tryIOError)
import System.Posix.Files
  ( createLink, deviceID, fileAccess, fileID, getFileStatus, getSymbolicLinkStatus, isDirectory
  , isSymbolicLink, removeLink )
import System.Posix.IO (OpenFileFlags (..), OpenMode (..), closeFd, fdWriteBuf, openFd)
import System.Posix.Time (epochTime)
import System.Posix.Types (Fd)
import System.Posix.Unistd (fileSynchronise)

import Haskoki.Engine.Backend (CryptoBackend (..), DigestAlg (D_SHA256), EngineResult (..))
import Haskoki.Engine.OpenSSL4 (OpenSSL4)
import Haskoki.Runtime.Catalog (catalogCredential, desiredTokens, tokenSerial)
import Haskoki.Runtime.Config (Config (..), StorageCfg (..), StorageKind (..))
import Haskoki.Runtime.Storage
  ( CredentialRecord (..), IdentityRefusal (..), ReconcilePlan (..), StoreError (..), TokenRecord (..)
  , reconcileIdentities, renderIdentityRefusal, tokensWithoutCredentials )
import Haskoki.Runtime.Storage.SQLite
  ( MigrationHooks, OwnedStoreFile, OwnerState (..), SQLiteMigration (..), StoreSnapshot (..)
  , guardFlags, migrateOwned, noMigrationHooks, probeOwner, readFileCloexec, readStoreSnapshot
  , sqliteSchemaVersion, withOwnedStoreFile )
import Haskoki.Types (TokenId)

-- | SHA-256 of a byte string as 64 lowercase hex digits, computed by
-- the OpenSSL4 engine (never a synthetic stand-in). Any engine
-- failure is a 'Left' the caller treats as a refusal.
sha256Hex :: ByteString -> IO (Either String String)
sha256Hex bytes = do
  opened <- openBackend "provider=default" :: IO (EngineResult (BackendEnv OpenSSL4))
  case opened of
    EngineFail err -> pure (Left ("SHA-256 engine unavailable: " ++ show err))
    EngineOk be -> do
      r <- digestOneShot be D_SHA256 bytes `finally` closeBackend be
      pure $ case r of
        EngineOk d | BS.length d == 32 -> Right (concatMap hexByte (BS.unpack d))
        EngineOk d -> Left ("SHA-256 returned " ++ show (BS.length d) ++ " bytes")
        EngineFail err -> Left ("SHA-256 failed: " ++ show err)
  where
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

-- | Diagnose a store for this config WITHOUT writing it: refuses a
-- live owner, then reads a read-only snapshot and plans. The result
-- names ids, versions and reasons only.
checkStoreOpen :: FilePath -> Config -> IO (Either StoreError StoreOpenPlan)
checkStoreOpen path cfg = do
  owner <- probeOwner path
  case owner of
    OwnerLive why -> pure (Left (StoreSecondWriter ("store is in use (" ++ why ++ "): " ++ path)))
    _ -> fmap (planStoreOpen path owner cfg) <$> readStoreSnapshot path

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
  StoreSecondWriter m -> ("store-live", m ++ "; stop the store owner and retry")
  StoreJournalPresent j -> ("store-journal-present", "an interrupted write left " ++ j
    ++ "; do not delete it. Start the serving haskoki once (its open rolls the write back),"
    ++ " or restore a backup with the store and journal moved aside together;"
    ++ " see docs/operations-notes.md, Upgrade, backup and recovery")
  StoreNeedsMigration f t -> ("store-migration-required", "schema " ++ show f
    ++ " needs haskoki-ctl store migrate to reach schema " ++ show t)
  StoreSchemaVersion want found -> ("store-unsupported-version", "store schema " ++ found
    ++ " is not one this build opens or migrates (this build: " ++ show want
    ++ "); a newer haskoki wrote it, or it is not a haskoki store")
  StoreCorrupt m -> ("store-corrupt", m)
  StoreFull m -> ("store-full", m)
  StoreIO m -> ("store-unreadable", m)
  other -> ("store-unreadable", show other)

-- ---------------------------------------------------------------------------
-- Explicit migration
-- ---------------------------------------------------------------------------

-- | Test seams of 'migrateStoreWith'. 'noMigrateHooks' is production.
data MigrateHooks = MigrateHooks
  { mhAfterPlan :: IO ()
    -- ^ after the unowned plan, before taking ownership
  , mhAfterBackup :: IO ()
    -- ^ after the verified backup, before the transaction
  , mhClock :: IO Integer
    -- ^ epoch seconds (default: 'epochTime'), read twice: once for the
    -- backup name and 'mrEpoch', once at completion for 'mrCompleted'
  , mhDigest :: ByteString -> IO (Either String String)
    -- ^ SHA-256 of the backup bytes (default: 'sha256Hex'); a 'Left'
    -- refuses before any file is written
  , mhAfterCreate :: FilePath -> IO ()
    -- ^ after a backup or receipt file is created, before its bytes
    -- are written (a failure here is a failure after the create)
  , mhSQLite :: MigrationHooks
  }

noMigrateHooks :: MigrateHooks
noMigrateHooks = MigrateHooks
  { mhAfterPlan = pure ()
  , mhAfterBackup = pure ()
  , mhClock = truncate . toRational <$> epochTime
  , mhDigest = sha256Hex
  , mhAfterCreate = \_ -> pure ()
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
  } deriving (Eq, Show)

data MigrateOutcome = MigrateNotNeeded | Migrated !MigrationReceipt deriving (Eq, Show)

-- | Why a migration did not complete. Every constructor before
-- 'MigrateTxnFailed' is a refusal that wrote nothing to the store or
-- the backup directory. A stored rowless token without a catalog
-- credential is reported as the identity refusal it is
-- ('RefuseStoredUnconfigured').
data MigrateError
  = MigrateConfig !PreflightRefusal
  | MigrateUnsafeBackupDir !FilePath !String
  | MigrateStore !StoreError
  | MigrateIdentityRefused !IdentityRefusal
  | MigrateStoreChanged
  | MigrateBackupExists !FilePath
  | MigrateBackupFailed !String
  | MigrateTxnFailed !FilePath !StoreError       -- ^ backup path; store rolled back, unchanged
  | MigrateVerifyFailed !FilePath !String        -- ^ committed; post-check failed
  | MigrateReceiptFailed !FilePath !String       -- ^ committed; receipt not written
  deriving (Eq, Show)

migrateStore :: FilePath -> Config -> FilePath -> IO (Either MigrateError MigrateOutcome)
migrateStore = migrateStoreWith noMigrateHooks

(>>?) :: IO (Either e a) -> (a -> IO (Either e b)) -> IO (Either e b)
m >>? k = m >>= either (pure . Left) k
infixl 1 >>?

-- | The explicit migration (AC-05). Refusals before ownership write
-- nothing: config selection, backup-dir safety, a live owner or hot
-- journal (via the read-only check), identity drift. Under ownership:
-- a fresh snapshot must equal the planned one, then a new verified
-- backup, then ONE transaction, then a read-back check, then a
-- non-overwriting receipt.
migrateStoreWith :: MigrateHooks -> FilePath -> Config -> FilePath -> IO (Either MigrateError MigrateOutcome)
migrateStoreWith hooks path cfg backupDir =
  (first MigrateConfig <$> configSelectsStore path cfg) >>? \() ->
  checkBackupDir path backupDir >>? \() ->
  (first MigrateStore <$> checkStoreOpen path cfg) >>? \plan ->
  case planVerdict plan of
    VerdictIdentityRefused r -> pure (Left (MigrateIdentityRefused r))
    VerdictOpenable -> pure (Right MigrateNotNeeded)
    VerdictMigrationRequired ->
      pure (traverse freezeOne (rowless plan)) >>? \freeze -> do
        mhAfterPlan hooks
        owned <- withOwnedStoreFile path (\o -> underOwnership o plan freeze)
        pure (either (Left . MigrateStore) id owned)
  where
    rowless plan =
      [t | t <- snapTokens (sopSnapshot plan), trId t `elem` sopAbsentCredentials plan]
    -- Unreachable after an accepted reconciliation (every stored
    -- token is configured exactly once); kept fail-closed.
    freezeOne t = maybe
      (Left (MigrateIdentityRefused (RefuseStoredUnconfigured (trId t) (trSlot t) (trLabel t))))
      Right (catalogCredential cfg (trId t))
    underOwnership :: OwnedStoreFile -> StoreOpenPlan -> [CredentialRecord]
                   -> IO (Either MigrateError MigrateOutcome)
    underOwnership o plan freeze =
      (first MigrateStore <$> readStoreSnapshot path) >>? \snap ->
      if snap /= sopSnapshot plan then pure (Left MigrateStoreChanged) else do
      now <- mhClock hooks
      writeVerifiedBackup hooks path backupDir (sopSchema plan) now snap >>? \(bak, nBytes, sha) -> do
        mhAfterBackup hooks
        eTx <- migrateOwned o (SQLiteMigration (sopSchema plan) freeze) (mhSQLite hooks)
        case eTx of
          Left err -> pure (Left (MigrateTxnFailed bak err))
          Right () ->
            verifyMigrated plan bak >>? \() -> do
              done <- mhClock hooks
              let rc = MigrationReceipt
                    { mrStore = path, mrFrom = sopSchema plan, mrTo = sqliteSchemaVersion
                    , mrFrozen = map crToken freeze, mrPreserved = sopCredentialTokens plan
                    , mrBackup = bak, mrBackupBytes = nBytes, mrBackupSha256 = sha
                    , mrReceipt = bak ++ ".receipt", mrEpoch = now, mrCompleted = done }
              w <- writeReceipt (mhAfterCreate hooks) (mrReceipt rc) (BC8.pack (renderReceipt rc)) backupDir
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
-- exception (re-thrown), removes the file: the create and the cleanup
-- run masked, only the writing is interruptible.
writeExclusive :: (FilePath -> IO ()) -> FilePath -> ByteString -> FilePath -> IO ExclusiveWrite
writeExclusive afterCreate path bytes dir = mask $ \restore -> do
  eFd <- tryIOError (openFd path WriteOnly guardFlags { creat = Just 0o600, exclusive = True })
  case eFd of
    Left e
      | isAlreadyExistsError e -> pure NameTaken
      | otherwise -> pure (WriteFailed ("cannot create " ++ path ++ ": " ++ show e))
    Right fd -> do
      r <- try (restore ((fill fd `finally` closeFd fd) >> syncDir dir))
      case r of
        Right () -> pure Written
        Left e -> do
          _ <- tryIOError (removeLink path)
          case fromException e of
            Just (io :: IOException) ->
              pure (WriteFailed ("cannot write " ++ path ++ " (incomplete file removed): " ++ show io))
            Nothing -> throwIO e
  where
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

-- | Write a receipt so that its name never holds a truncated file: the
-- bytes go to a new temporary (written and fsynced by 'writeExclusive'),
-- which is then moved into place by link(2) plus unlink (unlike
-- rename(2), link never replaces an existing name), and the directory
-- is fsynced.
writeReceipt :: (FilePath -> IO ()) -> FilePath -> ByteString -> FilePath -> IO ExclusiveWrite
writeReceipt afterCreate final bytes dir = mask $ \restore -> do
  let tmp = final ++ ".tmp"
  w <- restore (writeExclusive afterCreate tmp bytes dir)
  case w of
    NameTaken -> pure (WriteFailed ("the temporary receipt name is taken: " ++ tmp))
    WriteFailed why -> pure (WriteFailed why)
    Written -> do
      eLink <- tryIOError (createLink tmp final)
      _ <- tryIOError (removeLink tmp)
      eSync <- tryIOError (syncDir dir)
      pure $ case (eLink, eSync) of
        (Left e, _)
          | isAlreadyExistsError e -> NameTaken
          | otherwise -> WriteFailed ("cannot move " ++ tmp ++ " to " ++ final ++ ": " ++ show e)
        (Right (), Left e) -> WriteFailed ("cannot sync " ++ dir ++ ": " ++ show e)
        (Right (), Right ()) -> Written

-- | Hash, then copy the owned store into the first free candidate
-- name, then verify by byte readback and by a read-only snapshot
-- equal to the store's (file identity aside). A hashing failure
-- refuses before any file exists.
writeVerifiedBackup :: MigrateHooks -> FilePath -> FilePath -> Int -> Integer -> StoreSnapshot
                    -> IO (Either MigrateError (FilePath, Int, String))
writeVerifiedBackup hooks store dir from now snap =
  readOrFail ("cannot read the store " ++ store) store >>? \bytes ->
  (first MigrateBackupFailed <$> mhDigest hooks bytes) >>? \sha ->
  pickAndWrite bytes candidates >>? \bak ->
  readOrFail ("cannot read back the backup " ++ bak) bak >>? \back -> do
    eSnap <- readStoreSnapshot bak
    pure $ case eSnap of
      _ | back /= bytes -> Left (MigrateBackupFailed ("backup readback differs: " ++ bak))
      Right b | b { snapFile = snapFile snap } == snap -> Right (bak, BS.length bytes, sha)
      Right _ -> Left (MigrateBackupFailed ("backup does not read as the same store: " ++ bak))
      Left err -> Left (MigrateBackupFailed ("backup does not open read-only: " ++ bak ++ ": " ++ show err))
  where
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
  ]
  where ids [] = "none"; ids ts = unwords (map tokenSerial ts)

-- | Operator tag and detail. Paths, ids, versions and reasons only.
renderMigrateError :: MigrateError -> (String, String)
renderMigrateError e = case e of
  MigrateConfig r -> ("config-mismatch", renderPreflightRefusal r)
  MigrateUnsafeBackupDir d why -> ("migrate-unsafe-backup-dir", d ++ " " ++ why ++ "; nothing was written")
  MigrateStore se -> renderStoreRefusal se
  MigrateIdentityRefused r -> ("store-identity-refused", renderIdentityRefusal r)
  MigrateStoreChanged -> ("migrate-store-changed", "the store changed between the check and "
    ++ "taking ownership; nothing was written. Run store check again")
  MigrateBackupExists p -> ("migrate-backup-exists", "every backup name is taken (first: " ++ p
    ++ "); nothing was written")
  MigrateBackupFailed why -> ("migrate-backup-failed", why ++ "; the store was not changed")
  MigrateTxnFailed bak se -> ("migrate-failed", "the migration transaction rolled back ("
    ++ snd (renderStoreRefusal se) ++ "); the store was not changed. Backup kept at " ++ bak)
  MigrateVerifyFailed bak why -> ("migrate-verify-failed", "the migration committed but its "
    ++ "read-back failed: " ++ why ++ ". Stop the rollout; restore from " ++ bak
    ++ " (docs/operations-notes.md, Upgrade, backup and recovery)")
  MigrateReceiptFailed bak why -> ("migrate-receipt-failed", "the migration committed; the "
    ++ "receipt was not written (" ++ why ++ "). Backup at " ++ bak)
