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
  ) where

import Control.Exception (finally)
import Data.Bits (shiftR, (.&.))
import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import Data.List (intercalate)
import Data.Word (Word8)
import System.IO.Error (tryIOError)
import System.Posix.Files (deviceID, fileID, getFileStatus)

import Haskoki.Engine.Backend (CryptoBackend (..), DigestAlg (D_SHA256), EngineResult (..))
import Haskoki.Engine.OpenSSL4 (OpenSSL4)
import Haskoki.Runtime.Catalog (desiredTokens, tokenSerial)
import Haskoki.Runtime.Config (Config (..), StorageCfg (..), StorageKind (..))
import Haskoki.Runtime.Storage
  ( IdentityRefusal, ReconcilePlan (..), StoreError (..), TokenRecord (..)
  , reconcileIdentities, renderIdentityRefusal, tokensWithoutCredentials )
import Haskoki.Runtime.Storage.SQLite
  ( OwnerState (..), StoreSnapshot (..), probeOwner, readStoreSnapshot, sqliteSchemaVersion )
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
