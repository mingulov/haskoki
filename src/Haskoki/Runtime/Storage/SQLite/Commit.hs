{- | SQLite store commit path and connection assembly.
-}
{-# LANGUAGE OverloadedStrings #-}
module Haskoki.Runtime.Storage.SQLite.Commit
  ( mkStore
  ) where

import Control.Concurrent.MVar (MVar, modifyMVar_, readMVar)
import Control.Exception (mask_)
import Data.IORef (IORef, readIORef, writeIORef)
import Data.List (nub)
import qualified Data.Map.Strict as Map
import Data.Maybe (listToMaybe)
import qualified Data.Text as T
import Data.Text (Text)
import Data.Word (Word64)
import qualified Database.SQLite3 as S
import Database.SQLite3.Direct (getAutoCommit)
import Haskoki.Runtime.Storage
  ( CommitResult (..)
  , CredentialRecord (..)
  , FaultInjector (..)
  , FaultPoint (..)
  , JobRecord (..)
  , LoadedState (..)
  , ObjectPut (..)
  , ObjectRecord (..)
  , Reconcile (..)
  , Store (..)
  , StoreDelta (..)
  , StoreError (..)
  , StoreLimits
  , StoreStats (..)
  , StoredDoc (..)
  , TokenRecord (..)
  , checkLimits
  , checkSlotUnique
  , checkTokenRefs
  , coverDeletedJobIds
  , decodeHex16
  , decodeTokenRecord
  , encodeCredentialRecord
  , encodeHex16
  , encodeHexWord64
  , encodeJobRecord
  , encodeObjectRecord
  , encodeTokenRecord
  , jobIdCounterKey
  , reconcileCredentialsReload
  , reconcileJobsReload
  , reconcileReload
  , scrubDeltaAuth
  , storeClosed
  )
import Haskoki.Runtime.Storage.SQLite.Conn
import Haskoki.Runtime.Storage.SQLite.Records
import Haskoki.Runtime.Storage.SQLite.Statements
import Haskoki.Runtime.Storage.SQLite.Stats
import Haskoki.Runtime.Storage.SQLite.Txn
import Haskoki.Runtime.Storage.SQLite.Types
import Haskoki.Types (Generation (..), ObjectId (..), SlotId (..), TokenId (..))

-- ---------------------------------------------------------------------------
-- Store operations
-- ---------------------------------------------------------------------------
-- | Build the 'Store' record over an open connection. Every
-- world-touching operation runs under the connection guard and
-- reports the closed handle unless open; quarantine and stats
-- stay readable (live-handle properties that never touch the
-- database).
mkStore :: SQLiteConn -> Store
mkStore conn = Store
  { storeLoadTokens = withLive conn Left loadTokens
  , storeLoadJobs = withLive conn Left loadJobs
  , storeLoadCredentials = withLive conn Left (loadCredentials)
  , storeCommit = protocolDelta conn
  , storeResetToken = resetTokenConn conn
  , storeReserveJobId = reserveJobIdConn conn
  , storeClose = closeConn conn
  , storeInspect = withLive conn Left inspectConn
  , storeQuarantined = readMVar (sqQuarantine conn)
  , storeReload = reloadConn conn
  , storeStats = readIORef (sqStats conn)
  , storeLoadMeta = withLive conn Left loadMeta
  , storeClaims = sqClaims conn
  }

-- | The commit protocol: closed-handle refusal, quarantine
-- refusal, pre-commit validation (limits, expected revisions),
-- pre-commit fault rollback, then the masked durable section (one
-- @BEGIN IMMEDIATE@ transaction, ambiguous verification,
-- post-commit quarantine). The whole flow holds the connection
-- guard, so one commit runs at a time per handle and the close
-- (which takes the same guard first) can never strand it
-- mid-flight.
protocolDelta :: SQLiteConn -> StoreDelta -> IO CommitResult
protocolDelta conn delta =
  withLive conn NotCommitted (\db -> protocolLocked conn db delta)

-- | Token reset: the expected generation must match the current
-- one, then the replacement plus the removal of every owned
-- object and job run as one ordinary protocol flow
-- (closed-handle refusal, quarantine, validation, faults, masking
-- all apply).
resetTokenConn :: SQLiteConn -> TokenId -> Generation -> TokenRecord -> IO CommitResult
resetTokenConn conn tid wantGen replacement =
  withLive conn NotCommitted $ \db -> do
    eEff <- resetEffectiveDb db tid wantGen replacement
    case eEff of
      Left err -> pure (NotCommitted err)
      Right eff -> protocolLocked conn db eff

-- | Build the reset's effective delta from one consistent read
-- (runs under the connection guard, so the generation check is
-- exact). Owned objects and jobs are dropped explicitly (the
-- foreign-key cascades backstop the same outcome); the credential
-- row stays with the token.
resetEffectiveDb :: S.Database -> TokenId -> Generation -> TokenRecord -> IO (Either StoreError StoreDelta)
resetEffectiveDb db tid wantGen replacement = do
  eToks <- queryRows db "SELECT record_json FROM tokens WHERE token_id = ?"
    [S.SQLText (T.pack (encodeHex16 (unTokenId tid)))]
  case eToks of
    Left err -> pure (Left err)
    Right [] -> pure (Left (StoreRevisionConflict ("reset of missing token " ++ show tid)))
    Right [[S.SQLText doc]] -> case decodeTokenRecord (T.unpack doc) of
      Nothing -> pure (Left (StoreCorrupt "corrupt token record on reset"))
      Just cur
        | trId replacement /= tid ->
            pure (Left (StoreRevisionConflict "reset replacement names a different token"))
        | trGeneration cur /= wantGen ->
            pure (Left (StoreRevisionConflict ("reset expected generation " ++ show wantGen
              ++ " but token " ++ show tid ++ " is at " ++ show (trGeneration cur))))
        | otherwise -> do
            eObjs <- queryRows db "SELECT object_id FROM objects WHERE token_id = ?"
              [S.SQLText (T.pack (encodeHex16 (unTokenId tid)))]
            eJobs <- queryRows db "SELECT persistent_id_key FROM detached_jobs WHERE token_id = ?"
              [S.SQLText (T.pack (encodeHex16 (unTokenId tid)))]
            case (eObjs, eJobs) of
              (Right orows, Right jrows) ->
                case (mapM parseOid orows, mapM parsePid jrows) of
                  (Just oids, Just pids) -> pure (Right StoreDelta
                    { sdPutTokens = [replacement]
                    , sdDropTokens = []
                    , sdPutObjects = []
                    , sdDropObjects = oids
                    , sdPutJobs = []
                    , sdDropJobs = pids
                    , sdPutMeta = []
                    , sdPutCredentials = []
                    , sdDropCredentials = []
                    })
                  _ -> pure (Left (StoreCorrupt "corrupt reset ownership rows"))
              (Left err, _) -> pure (Left err)
              (_, Left err) -> pure (Left err)
    Right _ -> pure (Left (StoreCorrupt "corrupt token row on reset"))
  where
    parseOid [S.SQLText oidT] = ObjectId <$> decodeHex16 (T.unpack oidT)
    parseOid _ = Nothing
    parsePid [S.SQLBlob b] = decodeBlobW64 b
    parsePid _ = Nothing

-- | The commit flow with the connection guard already held. The
-- delta is scrubbed first ('scrubDeltaAuth'): token puts persist
-- the durable authentication half only, so validation, the
-- staged upserts, and ambiguous-commit verification all observe
-- scrubbed rows and agree with every later load.
protocolLocked :: SQLiteConn -> S.Database -> StoreDelta -> IO CommitResult
protocolLocked conn db delta0 = do
  let delta = scrubDeltaAuth delta0
      inj = sqInjector conn
      qVar = sqQuarantine conn
      sVar = sqStats conn
  eAffected <- tokensForDelta db delta
  case eAffected of
    Left err -> pure (NotCommitted err)
    Right affected -> do
      q <- readMVar qVar
      case firstQuarantined q affected of
        Just (tid, why) -> pure (NotCommitted (StoreQuarantined tid why))
        Nothing -> do
          eValid <- validateDelta db (sqLimits conn) delta
          case eValid of
            Left err -> pure (NotCommitted err)
            Right () -> do
              preFailed <- fiFire inj FaultBeforeCommit
              if preFailed
                then pure (NotCommitted (StoreIO "injected pre-commit failure"))
                else mask_ $ do
                  fiOnMasked inj
                  fullDisk <- fiFire inj FaultFullDisk
                  eTxn <-
                    if fullDisk
                      then pure (Left (TxnRolledBack (StoreFull "disk full (injected)")))
                      else runTxn delta
                  result <- case eTxn of
                    Left failure -> settleTxnFailure conn db (Just affected) failure
                    Right doomed -> do
                      ambiguous <- fiFire inj FaultAmbiguousCommit
                      if ambiguous
                        then resolveAmbiguous inj qVar sVar (effectiveDelta doomed delta) affected
                        else do
                          bumpCommits sVar
                          postCommitTail inj qVar sVar affected
                  fiOnResult inj result
                  pure result
  where
    -- One transaction. The body stops at its first failed
    -- statement ('runBody'), so after a body or COMMIT failure
    -- the only statement left is the cleanup, which follows the
    -- native transaction state ('endFailedTxn'): no ROLLBACK at
    -- all once SQLite has rolled the whole transaction back
    -- itself (e.g. SQLITE_FULL during a page split, or a
    -- trigger's RAISE(ROLLBACK)) — the connection is then in
    -- autocommit mode, where any further statement would commit
    -- on its own — and a surfaced, classified ROLLBACK otherwise.
    -- A COMMIT that fails with the transaction still active
    -- (SQLITE_BUSY) did not take effect; one that fails after the
    -- transaction ended has an unknown outcome.
    runTxn :: StoreDelta -> IO (Either TxnFailure [Word64])
    runTxn d = do
      sthBeforeBegin (sqHooks conn) db
      eBegin <- trySQLite (S.exec db "BEGIN IMMEDIATE")
      case eBegin of
        Left err -> pure (Left (TxnRolledBack err))
        Right () -> do
          eBody <- runBody d
          case eBody of
            Left err -> Left <$> endFailedTxn conn db AtBody err
            Right doomed -> do
              eCommit <- trySQLite (S.exec db "COMMIT")
              case eCommit of
                Left err -> Left <$> endFailedTxn conn db AtCommit err
                Right () -> pure (Right doomed)
    -- The observed outcome is discarded; a reload decides. Present
    -- verifies committed (every table). Anything else — a failed
    -- reload, or a reload that does not hold the whole delta —
    -- quarantines with 'CommitUnknown': a mismatch is not proof
    -- of absence (a partial reload would be labelled "absent"
    -- while part of the delta is durable), and no pre-state is
    -- recorded to prove one. Nothing reissues. The expectation is
    -- the effective delta: the stored effect, not the raw
    -- request.
    resolveAmbiguous
      :: FaultInjector -> MVar [(TokenId, String)] -> IORef StoreStats
      -> StoreDelta -> [TokenId] -> IO CommitResult
    resolveAmbiguous inj qVar sVar d affected = do
      bumpVerifyReloads sVar
      verifyFailed <- fiFire inj FaultVerifyReload
      if verifyFailed
        then do
          quarantineTokens qVar sVar affected "commit verification failed"
          pure (CommitUnknown (StoreIO "injected verification failure"))
        else do
          eLoaded <- loadTokens db
          eJobs <- loadJobs db
          eMeta <- loadMeta db
          eCreds <- loadCredentials db
          case (eLoaded, eJobs, eMeta, eCreds) of
            (Right loaded, Right jobs, Right meta, Right creds)
              | reconcileReload d loaded == ReconciledPresent
              , reconcileJobsReload d jobs == ReconciledPresent
              , reconcileMetaReload d meta == ReconciledPresent
              , reconcileCredentialsReload d creds == ReconciledPresent -> do
                  bumpCommits sVar
                  postCommitTail inj qVar sVar affected
            (Right _, Right _, Right _, Right _) -> do
              let err = StoreIO "ambiguous commit unresolved: the reload does not hold the whole delta"
              quarantineTokens qVar sVar affected (show err)
              pure (CommitUnknown err)
            (Left err, _, _, _) -> do
              quarantineTokens qVar sVar affected ("reload failed: " ++ show err)
              pure (CommitUnknown err)
            (_, Left err, _, _) -> do
              quarantineTokens qVar sVar affected ("reload failed: " ++ show err)
              pure (CommitUnknown err)
            (_, _, Left err, _) -> do
              quarantineTokens qVar sVar affected ("reload failed: " ++ show err)
              pure (CommitUnknown err)
            (_, _, _, Left err) -> do
              quarantineTokens qVar sVar affected ("reload failed: " ++ show err)
              pure (CommitUnknown err)
    -- After a confirmed commit, a post-commit failure quarantines
    -- the affected tokens; durable truth stays 'Committed'.
    postCommitTail
      :: FaultInjector -> MVar [(TokenId, String)] -> IORef StoreStats
      -> [TokenId] -> IO CommitResult
    postCommitTail inj qVar sVar affected = do
      postFailed <- fiFire inj FaultAfterCommit
      if postFailed
        then do
          quarantineTokens qVar sVar affected "post-commit failure"
          pure Committed
        else pure Committed
    -- Drops before puts; tokens before the objects, jobs, and
    -- credentials that reference them (foreign keys stay
    -- satisfied throughout). The groups run fail-fast
    -- ('firstFailure'): the first failed statement stops the
    -- body, and no later group (nor later statement of the same
    -- group) executes. Token puts run staged (two phases
    -- within this transaction); credential puts dedupe
    -- first-wins (the token-row precedent). The doomed pids are
    -- read before the drops, then folded into the job-id mark
    -- after the caller's meta puts, so a legacy store whose
    -- mark never advanced still cannot re-mint deleted ids once
    -- the records are gone.
    runBody :: StoreDelta -> IO (Either StoreError [Word64])
    runBody d = do
      eDoomed <- readDoomedPids db d
      case eDoomed of
        Left err -> pure (Left err)
        Right doomed -> do
          eGroups <- firstFailure
            [ runAll (map dropObjectStmt (sdDropObjects d))
            , runAll (map dropJobStmt (sdDropJobs d))
            , runAll (map dropCredentialStmt (sdDropCredentials d))
            , runAll (map dropTokenStmt (sdDropTokens d))
            , runTokenPuts (sdPutTokens d)
            , runAll (map putObjectStmt (sdPutObjects d))
            , runAll (map putJobStmt (sdPutJobs d))
            , runAll (map putCredentialStmt (firstByCredential (sdPutCredentials d)))
            , runAll (map putMetaStmt (sdPutMeta d))
            , coverDeletedMeta db doomed
            ]
          pure (eGroups >> Right doomed)
      where
        runAll :: [(Text, [S.SQLData])] -> IO (Either StoreError ())
        runAll stmts = firstFailure [execParams db sql params | (sql, params) <- stmts]
        -- Token puts apply in two phases. Sequential upserts would
        -- observe transient @UNIQUE(slot_key)@ conflicts whenever
        -- one put's target slot is still held by a token a later
        -- put moves (list order would decide the outcome, and a
        -- slot swap could never land) — while the validated final
        -- projection is unique and the memory backend applies it
        -- atomically. Staging first parks every put token on a
        -- temporary slot that collides with neither a current nor
        -- a final slot, so the subsequent upserts land in any
        -- order with the same result. Staging touches only
        -- @slot_key@: the @token_id@ row — and therefore every
        -- owned object and job — is preserved throughout.
        runTokenPuts :: [TokenRecord] -> IO (Either StoreError ())
        runTokenPuts [] = pure (Right ())
        runTokenPuts puts = do
          eRows <- queryRows db "SELECT slot_key FROM tokens" []
          case eRows of
            Left err -> pure (Left err)
            Right rows -> case mapM parseSlotKey rows of
              Nothing -> pure (Left (StoreCorrupt "corrupt slot_key row"))
              Just current -> do
                let uniq = firstByToken puts
                    temps = pickTempSlots
                      (current ++ map (unSlotId . trSlot) uniq) (length uniq)
                eStage <- runAll (zipWith stageTokenStmt temps uniq)
                case eStage of
                  Left err -> pure (Left err)
                  Right () -> runAll (map putTokenStmt uniq)

-- | Tokens a delta touches: named tokens plus the home tokens of
-- named objects and jobs (drop owners resolved from current
-- state; unknown drops contribute nothing).
tokensForDelta :: S.Database -> StoreDelta -> IO (Either StoreError [TokenId])
tokensForDelta db delta = do
  eOwners <- mapM ownerOf (sdDropObjects delta)
  eJobOwners <- mapM jobOwnerOf (sdDropJobs delta)
  pure (sequence eOwners >>= \owners -> sequence eJobOwners >>= \jobOwners ->
    Right (nub (explicit ++ [t | Just t <- owners] ++ [t | Just t <- jobOwners])))
  where
    explicit =
      map trId (sdPutTokens delta)
        ++ sdDropTokens delta
        ++ map (orToken . opRecord) (sdPutObjects delta)
        ++ map jrToken (sdPutJobs delta)
        ++ map crToken (sdPutCredentials delta)
        ++ sdDropCredentials delta
    -- Drops of unknown objects stay silent no-ops;
    -- only genuine query failures refuse the commit.
    ownerOf :: ObjectId -> IO (Either StoreError (Maybe TokenId))
    ownerOf (ObjectId n) = do
      eRows <- queryRows db "SELECT token_id FROM objects WHERE object_id = ?"
        [S.SQLText (T.pack (encodeHex16 n))]
      case eRows of
        Left err -> pure (Left err)
        Right [] -> pure (Right Nothing)
        Right [[S.SQLText tid]] -> case decodeHex16 (T.unpack tid) of
          Just t -> pure (Right (Just (TokenId t)))
          Nothing -> pure (Left (StoreCorrupt "corrupt token_id on dropped object"))
        Right _ -> pure (Left (StoreCorrupt "corrupt drop-owner row shape"))
    jobOwnerOf :: Word64 -> IO (Either StoreError (Maybe TokenId))
    jobOwnerOf pid = do
      eRows <- queryRows db "SELECT token_id FROM detached_jobs WHERE persistent_id_key = ?"
        [S.SQLBlob (encodeBlobW64 pid)]
      case eRows of
        Left err -> pure (Left err)
        Right [] -> pure (Right Nothing)
        Right [[S.SQLText tid]] -> case decodeHex16 (T.unpack tid) of
          Just t -> pure (Right (Just (TokenId t)))
          Nothing -> pure (Left (StoreCorrupt "corrupt token_id on dropped job"))
        Right _ -> pure (Left (StoreCorrupt "corrupt job drop-owner row shape"))

-- | Pre-commit validation: limits against a decoded load, then
-- token references, slot uniqueness, then expected revisions
-- against the stored revision map. Runs under the connection
-- guard, so the validated state is the committed-against state.
validateDelta :: S.Database -> StoreLimits -> StoreDelta -> IO (Either StoreError ())
validateDelta db limits delta = do
  eLoaded <- loadTokens db
  eJobs <- loadJobs db
  eCreds <- loadCredentials db
  case (eLoaded, eJobs, eCreds) of
    (Left err, _, _) -> pure (Left err)
    (_, Left err, _) -> pure (Left err)
    (_, _, Left err) -> pure (Left err)
    (Right loaded, Right jobs, Right creds) ->
      let state = LoadedState loaded jobs creds
          toks = [(trId t, t) | (t, _) <- loaded]
      in case checkLimits limits delta state of
        Just err -> pure (Left err)
        Nothing -> case checkTokenRefs toks delta of
          Just err -> pure (Left err)
          Nothing -> case checkSlotUnique toks delta of
            Just err -> pure (Left err)
            Nothing -> checkRevisionsDb db delta

-- | The delta as durably applied: requested meta rows replayed
-- through the backend's own put order (sequential upserts, so
-- the last put wins, matching 'runBody'), with the requested
-- job-id counter row advanced by the generated deletion
-- coverage — so the stored effect, not the raw request, joins
-- the reconciliation expectation.
effectiveDelta :: [Word64] -> StoreDelta -> StoreDelta
effectiveDelta doomed delta =
  delta { sdPutMeta = expected }
  where
    stored = foldl (\m (k, v) -> Map.insert k v m) Map.empty (sdPutMeta delta)
    covered = case Map.lookup jobIdCounterKey stored of
      Nothing -> stored
      Just v -> case coverDeletedJobIds (Just v) doomed of
        Just c -> Map.insert jobIdCounterKey c stored
        Nothing -> stored
    expected =
      [ (k, v)
      | (k, _) <- sdPutMeta delta
      , Just v <- [Map.lookup k covered]
      ]

-- | The first touched token that is quarantined, if any.
firstQuarantined :: [(TokenId, String)] -> [TokenId] -> Maybe (TokenId, String)
firstQuarantined q tids =
  listToMaybe [(tid, why) | tid <- tids, Just why <- [lookup tid q]]

-- | Authoritative reload: a clean load clears the quarantine; a
-- failed load keeps it and reports the error. Reloads never
-- consult the fault script. A closed handle reports closed
-- without touching the quarantine. Credentials load alongside
-- tokens: a corrupt credential row keeps the quarantine like a
-- corrupt token row. A connection-wide quarantine (a write
-- transaction left open by a failed ROLLBACK) resolves first:
-- the ROLLBACK is retried, and only once SQLite reports the
-- transaction ended does the reload read — durable state, never
-- the open transaction's writes. Until then the reload refuses
-- and every quarantine stays.
reloadConn :: SQLiteConn -> IO (Either StoreError ())
reloadConn conn = withConn conn (pure (Left storeClosed)) $ \db -> do
  eOpen <- resolveOpenTxn conn db
  case eOpen of
    Left err -> pure (Left err)
    Right () -> do
      eLoaded <- loadTokens db
      eCreds <- loadCredentials db
      case (eLoaded, eCreds) of
        (Right _, Right _) ->
          modifyMVar_ (sqQuarantine conn) (\_ -> pure []) >> pure (Right ())
        (Left err, _) -> pure (Left err)
        (_, Left err) -> pure (Left err)

-- | Retry the ROLLBACK of a write transaction left open
-- ('sqOpenTxn'); clear the connection-wide quarantine only when
-- SQLite reports the transaction ended.
resolveOpenTxn :: SQLiteConn -> S.Database -> IO (Either StoreError ())
resolveOpenTxn conn db = do
  openTxn <- readIORef (sqOpenTxn conn)
  case openTxn of
    Nothing -> pure (Right ())
    Just why -> do
      ended <- getAutoCommit db
      eRollback <- if ended then pure (Right ()) else trySQLite (S.exec db "ROLLBACK")
      endedNow <- getAutoCommit db
      if endedNow
        then writeIORef (sqOpenTxn conn) Nothing >> pure (Right ())
        else pure (Left (connectionQuarantined (why ++ either (\e -> "; retried ROLLBACK failed: " ++ show e) (const "") eRollback)))

-- | Render every stored record through its canonical bytes (load,
-- then re-encode, so inspection always shows canonical form). A
-- failed load reports the error instead of a silent empty
-- list, so corruption stays diagnosed.
inspectConn :: S.Database -> IO (Either StoreError [StoredDoc])
inspectConn db = do
  eLoaded <- loadTokens db
  eJobs <- loadJobs db
  eCreds <- loadCredentials db
  case (eLoaded, eJobs, eCreds) of
    (Right toks, Right jobs, Right creds) -> pure $ Right $
      [ StoredDoc "tokens" (show (unTokenId (trId t))) (encodeTokenRecord t)
      | (t, _) <- toks
      ]
      ++
      [ StoredDoc "objects" (show (unObjectId (orId o))) (encodeObjectRecord o)
      | (_, objs) <- toks, o <- objs
      ]
      ++
      [ StoredDoc "detached_jobs" (encodeHexWord64 (jrPersistentId j)) (encodeJobRecord j)
      | j <- jobs
      ]
      ++
      [ StoredDoc "credentials" (show (unTokenId (crToken c))) (encodeCredentialRecord c)
      | c <- creds
      ]
    (Left err, _, _) -> pure (Left err)
    (_, Left err, _) -> pure (Left err)
    (_, _, Left err) -> pure (Left err)
