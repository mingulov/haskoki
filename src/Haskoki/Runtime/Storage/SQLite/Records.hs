{- | SQLite store record loaders, decoders, and counters.
-}
{-# LANGUAGE OverloadedStrings #-}
module Haskoki.Runtime.Storage.SQLite.Records
  ( readCounterDb
  , readMaxJobDb
  , readDoomedPids
  , coverDeletedMeta
  , allTokenIds
  , loadTokens
  , decodeObjectRow
  , note
  , loadJobs
  , decodeJobRow
  , noteJob
  , loadCredentials
  , decodeCredentialRow
  , noteCred
  , loadMeta
  , checkRevisionsDb
  , reconcileMetaReload
  , quarantineTokens
  ) where

import Control.Concurrent.MVar (MVar, modifyMVar_)
import Data.IORef (IORef)
import qualified Data.Map.Strict as Map
import Data.Maybe (fromMaybe)
import qualified Data.Text as T
import Data.Word (Word64)
import qualified Database.SQLite3 as S
import Haskoki.Runtime.Storage
  ( CredentialRecord (..)
  , JobRecord (..)
  , ObjectPut (..)
  , ObjectRecord (..)
  , Reconcile (..)
  , StoreDelta (..)
  , StoreError (..)
  , StoreStats (..)
  , TokenRecord (..)
  , checkExpectedRevisions
  , coverDeletedJobIds
  , decodeAttrsDoc
  , decodeCredentialRecord
  , decodeHex16
  , decodeJobRecord
  , decodeTokenRecord
  , execStateName
  , jobIdCounterKey
  , knownMaterialEncodings
  )
import Haskoki.Runtime.Storage.SQLite.Statements
import Haskoki.Runtime.Storage.SQLite.Stats
import Haskoki.Types (Generation (..), ObjectId (..), Revision (..), TokenId (..))

-- | Read the job-id counter row ('Nothing' = the key is
-- absent, as in a hand-built database: reservation treats it
-- as 1 and reconciles with the stored maximum).
readCounterDb :: S.Database -> IO (Either StoreError (Maybe String))
readCounterDb db = do
  eRows <- queryRows db "SELECT value FROM store_meta WHERE key = ?"
    [S.SQLText (T.pack jobIdCounterKey)]
  case eRows of
    Left err -> pure (Left err)
    Right [] -> pure (Right Nothing)
    Right [[S.SQLText v]] -> pure (Right (Just (T.unpack v)))
    Right _ -> pure (Left (StoreCorrupt "corrupt store_meta counter row shape"))

-- | Read the maximum stored persistent job id, if any. The
-- fixed-width big-endian blob keys order numerically, so one
-- descending row suffices.
readMaxJobDb :: S.Database -> IO (Either StoreError (Maybe Word64))
readMaxJobDb db = do
  eRows <- queryRows db
    "SELECT persistent_id_key FROM detached_jobs ORDER BY persistent_id_key DESC LIMIT 1" []
  case eRows of
    Left err -> pure (Left err)
    Right [] -> pure (Right Nothing)
    Right [[S.SQLBlob b]] -> case decodeBlobW64 b of
      Just w -> pure (Right (Just w))
      Nothing -> pure (Left (StoreCorrupt "corrupt persistent_id_key on max job"))
    Right _ -> pure (Left (StoreCorrupt "corrupt max-job row shape"))

-- | Pids whose records a delta deletes, read inside the
-- deleting transaction before the drops run: stored jobs
-- named by an explicit drop or owned by a dropped token,
-- minus same-delta job puts (a drop\/put pair replaces, so
-- the id survives). Drops naming unknown pids cover nothing,
-- matching the memory backend exactly.
readDoomedPids :: S.Database -> StoreDelta -> IO (Either StoreError [Word64])
readDoomedPids db d
  | null (sdDropJobs d) && null (sdDropTokens d) = pure (Right [])
  | otherwise = do
      eJobs <- loadJobs db
      pure (fmap doomedOf eJobs)
  where
    doomedOf jobs =
      [ jrPersistentId j
      | j <- jobs
      , jrToken j `elem` sdDropTokens d || jrPersistentId j `elem` sdDropJobs d
      , jrPersistentId j `notElem` map jrPersistentId (sdPutJobs d)
      ]

-- | Fold deleted pids into the job-id mark (same transaction,
-- after the caller's own meta puts): reset/drop keeps
-- coverage of legacy ids even when the mark never advanced
-- before. An empty doomed set writes nothing.
coverDeletedMeta :: S.Database -> [Word64] -> IO (Either StoreError ())
coverDeletedMeta _ [] = pure (Right ())
coverDeletedMeta db doomed = do
  eMark <- readCounterDb db
  case eMark of
    Left err -> pure (Left err)
    Right old -> case coverDeletedJobIds old doomed of
      Nothing -> pure (Right ())
      Just v -> let (sql, params) = putMetaStmt (jobIdCounterKey, v)
                in execParams db sql params

-- | Every stored token id, best-effort ('[]' when the list is
-- unreadable: callers fail closed regardless).
allTokenIds :: S.Database -> IO [TokenId]
allTokenIds db = do
  eRows <- queryRows db "SELECT token_id FROM tokens" []
  pure (case eRows of
    Left _ -> []
    Right rows -> fromMaybe [] (mapM parseTid rows))
  where
    parseTid [S.SQLText tidT] = TokenId <$> decodeHex16 (T.unpack tidT)
    parseTid _ = Nothing

-- | Load every token with its home objects, token-id ascending,
-- object-id ascending within each token.
loadTokens :: S.Database -> IO (Either StoreError [(TokenRecord, [ObjectRecord])])
loadTokens db = do
  eToks <- queryRows db "SELECT token_id, record_json FROM tokens ORDER BY token_id" []
  case eToks of
    Left err -> pure (Left err)
    Right rows -> do
      rs <- mapM loadOne rows
      pure (sequence rs)
  where
    loadOne :: [S.SQLData] -> IO (Either StoreError (TokenRecord, [ObjectRecord]))
    loadOne [S.SQLText tid, S.SQLText doc] = case decodeTokenRecord (T.unpack doc) of
      Nothing -> pure (Left (StoreCorrupt ("corrupt token record: " ++ T.unpack tid)))
      Just tok -> do
        eObjs <- queryRows db
          "SELECT object_id, token_id, class_key, key_type_key, attributes_json, material_encoding, material_blob, revision FROM objects WHERE token_id = ? ORDER BY object_id"
          [S.SQLText tid]
        case eObjs of
          Left err -> pure (Left err)
          Right orows -> pure (mapM decodeObjectRow orows >>= \objs -> Right (tok, objs))
    loadOne _ = pure (Left (StoreCorrupt "corrupt token row shape"))

-- | Decode one object row; every quantity range-checks (no blind
-- casts from the SQLite domain into 'Int').
decodeObjectRow :: [S.SQLData] -> Either StoreError ObjectRecord
decodeObjectRow [S.SQLText oidT, S.SQLText tidT, S.SQLBlob clsB, ktyD, S.SQLText attrT, S.SQLText mencT, matD, S.SQLInteger revN] = do
  oid <- note "object_id" (decodeHex16 (T.unpack oidT))
  tid <- note "token_id" (decodeHex16 (T.unpack tidT))
  cls <- note "class_key" (decodeBlobW64 clsB)
  kty <- case ktyD of
    S.SQLNull -> Right Nothing
    S.SQLBlob b -> Just <$> note "key_type_key" (decodeBlobW64 b)
    _ -> Left (StoreCorrupt "corrupt key_type_key shape")
  attrs <- note "attributes_json" (decodeAttrsDoc (T.unpack attrT))
  let menc = T.unpack mencT
  _ <- if menc `elem` knownMaterialEncodings
    then Right ()
    else Left (StoreCorrupt ("corrupt object record: unknown material encoding " ++ menc))
  mat <- case matD of
    S.SQLNull -> Right Nothing
    S.SQLBlob b -> Right (Just b)
    _ -> Left (StoreCorrupt "corrupt material_blob shape")
  rev <- note "revision" (decodeRevision revN)
  Right ObjectRecord
    { orId = ObjectId oid
    , orToken = TokenId tid
    , orClass = cls
    , orKeyType = kty
    , orAttrs = attrs
    , orMaterialEncoding = menc
    , orMaterial = mat
    , orRevision = Revision rev
    }
decodeObjectRow _ = Left (StoreCorrupt "corrupt object row shape")

-- | Tag a 'Maybe' decode with its column for the diagnosis.
note :: String -> Maybe a -> Either StoreError a
note col = maybe (Left (StoreCorrupt ("corrupt object record: bad " ++ col))) Right

-- | Load every detached job, persistent-id ascending. The full
-- document decodes the record; the key columns cross-check it.
loadJobs :: S.Database -> IO (Either StoreError [JobRecord])
loadJobs db = do
  eRows <- queryRows db
    "SELECT persistent_id_key, token_id, token_generation_key, function_name, execution_state, record_json FROM detached_jobs ORDER BY persistent_id_key" []
  case eRows of
    Left err -> pure (Left err)
    Right rows -> pure (mapM decodeJobRow rows)

-- | Decode one job row: the document first, then the redundant
-- key columns must agree with it (any mismatch is corruption).
decodeJobRow :: [S.SQLData] -> Either StoreError JobRecord
decodeJobRow [S.SQLBlob pidB, S.SQLText tidT, S.SQLBlob genB, S.SQLText funT, S.SQLText stT, S.SQLText doc] = do
  pid <- noteJob "persistent_id_key" (decodeBlobW64 pidB)
  tid <- noteJob "token_id" (decodeHex16 (T.unpack tidT))
  gen <- noteJob "token_generation_key" (decodeBlob8 genB)
  rec <- noteJob "record_json" (decodeJobRecord (T.unpack doc))
  _ <- if jrPersistentId rec == pid
    then Right ()
    else Left (StoreCorrupt "corrupt job record: key/doc id mismatch")
  _ <- if jrToken rec == TokenId tid
    then Right ()
    else Left (StoreCorrupt "corrupt job record: key/doc token mismatch")
  _ <- if jrTokenGeneration rec == Generation gen
    then Right ()
    else Left (StoreCorrupt "corrupt job record: key/doc generation mismatch")
  _ <- if jrFunction rec == T.unpack funT
    then Right ()
    else Left (StoreCorrupt "corrupt job record: key/doc function mismatch")
  _ <- if execStateName (jrState rec) == T.unpack stT
    then Right ()
    else Left (StoreCorrupt "corrupt job record: key/doc state mismatch")
  Right rec
decodeJobRow _ = Left (StoreCorrupt "corrupt job row shape")

-- | Tag a 'Maybe' job decode with its column.
noteJob :: String -> Maybe a -> Either StoreError a
noteJob col = maybe (Left (StoreCorrupt ("corrupt job record: bad " ++ col))) Right

-- | Load every provisioned credential, home-token ascending. The
-- full document decodes the record; the key column cross-checks
-- it (the job-row precedent).
loadCredentials :: S.Database -> IO (Either StoreError [CredentialRecord])
loadCredentials db = do
  eRows <- queryRows db
    "SELECT token_id, record_json FROM credentials ORDER BY token_id" []
  case eRows of
    Left err -> pure (Left err)
    Right rows -> pure (mapM decodeCredentialRow rows)

-- | Decode one credential row: the document first, then the
-- redundant key column must agree with it (any mismatch is
-- corruption).
decodeCredentialRow :: [S.SQLData] -> Either StoreError CredentialRecord
decodeCredentialRow [S.SQLText tidT, S.SQLText doc] = do
  tid <- noteCred "token_id" (decodeHex16 (T.unpack tidT))
  rec <- noteCred "record_json" (decodeCredentialRecord (T.unpack doc))
  _ <- if crToken rec == TokenId tid
    then Right ()
    else Left (StoreCorrupt "corrupt credential record: key/doc token mismatch")
  Right rec
decodeCredentialRow _ = Left (StoreCorrupt "corrupt credential row shape")

-- | Tag a 'Maybe' credential decode with its column.
noteCred :: String -> Maybe a -> Either StoreError a
noteCred col = maybe (Left (StoreCorrupt ("corrupt credential record: bad " ++ col))) Right

-- | Load every @store_meta@ row as key/value pairs.
loadMeta :: S.Database -> IO (Either StoreError [(String, String)])
loadMeta db = do
  eRows <- queryRows db "SELECT key, value FROM store_meta" []
  case eRows of
    Left err -> pure (Left err)
    Right rows -> pure (mapM decodeMetaRow rows)
  where
    decodeMetaRow [S.SQLText k, S.SQLText v] = Right (T.unpack k, T.unpack v)
    decodeMetaRow _ = Left (StoreCorrupt "corrupt store_meta row shape")

-- | Enforce expected revisions from one revision-map scan,
-- reusing the shared pure guard.
checkRevisionsDb :: S.Database -> StoreDelta -> IO (Either StoreError ())
checkRevisionsDb db delta
  | null [() | ObjectPut (Just _) _ <- sdPutObjects delta] = pure (Right ())
  | otherwise = do
      eRows <- queryRows db "SELECT object_id, revision FROM objects" []
      case eRows of
        Left err -> pure (Left err)
        Right rows -> case mapM parseRev rows of
          Nothing -> pure (Left (StoreCorrupt "corrupt revision row"))
          Just pairs -> pure (maybe (Right ()) Left
            (checkExpectedRevisions (`Map.lookup` Map.fromList pairs) delta))
  where
    parseRev :: [S.SQLData] -> Maybe (ObjectId, Revision)
    parseRev [S.SQLText oidT, S.SQLInteger n] = do
      oid <- decodeHex16 (T.unpack oidT)
      rev <- decodeRevision n
      pure (ObjectId oid, Revision rev)
    parseRev _ = Nothing

-- | Compare a delta's expected meta rows against reloaded meta
-- with full key/value equality. Every expected row must be
-- present; extra loaded rows (schema bookkeeping) are fine. A
-- metadata-only delta reconciles against meta alone.
reconcileMetaReload :: StoreDelta -> [(String, String)] -> Reconcile
reconcileMetaReload delta loaded
  | all (\(k, v) -> lookup k loaded == Just v) (sdPutMeta delta) = ReconciledPresent
  | otherwise = ReconciledAbsent

-- | Quarantine tokens with a reason, counting one event per token.
quarantineTokens :: MVar [(TokenId, String)] -> IORef StoreStats -> [TokenId] -> String -> IO ()
quarantineTokens qVar sVar tids why = do
  modifyMVar_ qVar (\q -> pure (foldr insertOne q tids))
  bumpQuarantines sVar (length tids)
  where
    insertOne tid q = (tid, why) : filter ((/= tid) . fst) q
