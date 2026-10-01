{- | In-memory store backend (the default).

A 'MemoryWorld' is the shared store identity (the analogue of one
SQLite file): exactly one open 'Store' owns it at a time, and
closing releases ownership so a later generation can reopen the
same durable state. State lives in an 'MVar'-guarded map pair;
every 'storeCommit' applies its 'StoreDelta' atomically under the
one lock, so multi-object transactions are all-or-nothing by
construction.

This backend runs the shared commit protocol: quarantine refusal,
pre-commit fault rollback, a masked durable section with
ambiguous-commit verification and post-commit quarantine, plus
per-handle stats. Quarantine and stats are live-handle properties
(fresh handles start clean); the world carries only the records.
-}
module Haskoki.Runtime.Storage.Memory
  ( MemoryWorld
  , newMemoryWorld
  , openMemoryStore
  , openMemoryStoreWith
  ) where

import Control.Concurrent.MVar
  ( MVar
  , modifyMVar_
  , newMVar
  , putMVar
  , readMVar
  , takeMVar
  , tryTakeMVar
  , withMVar
  )
import Control.Exception (bracket_, mask_)
import Data.IORef (IORef, atomicModifyIORef', newIORef, readIORef)
import Data.List (nub, sortOn)
import Data.Word (Word64)
import Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map
import Data.Maybe (listToMaybe)

import Haskoki.Runtime.Storage
  ( CommitResult (..)
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
  , checkExpectedRevisions
  , checkLimits
  , checkSlotUnique
  , checkTokenRefs
  , decodeJobRecord
  , decodeObjectRecord
  , decodeTokenRecord
  , defaultLimits
  , encodeHexWord64
  , encodeJobRecord
  , encodeObjectRecord
  , encodeTokenRecord
  , noFaults
  , reconcileJobsReload
  , reconcileReload
  , zeroStats
  )
import Haskoki.Types (Generation (..), ObjectId (..), Revision, TokenId (..))

-- | The durable state behind one memory store identity.
data WorldState = WorldState
  { wsTokens :: !(Map TokenId TokenRecord)
  , wsObjects :: !(Map ObjectId ObjectRecord)
  , wsJobs :: !(Map Word64 JobRecord)
  , wsMeta :: !(Map String String)
  }

-- | One memory store identity: the state plus the single-writer
-- ownership flag ('True' = currently owned).
data MemoryWorld = MemoryWorld
  { mwState :: !(MVar WorldState)
  , mwOwner :: !(MVar Bool)
  }

-- | A fresh empty world with no owner.
newMemoryWorld :: IO MemoryWorld
newMemoryWorld = MemoryWorld
  <$> newMVar (WorldState Map.empty Map.empty Map.empty Map.empty)
  <*> newMVar False

-- | Open the world with default limits and no fault injection.
openMemoryStore :: MemoryWorld -> IO (Either StoreError Store)
openMemoryStore world = openMemoryStoreWith world defaultLimits noFaults

-- | Open the world with explicit limits (always enforced)
-- and an explicit fault injector.
openMemoryStoreWith :: MemoryWorld -> StoreLimits -> FaultInjector -> IO (Either StoreError Store)
openMemoryStoreWith world limits inj = do
  mPrev <- tryTakeMVar (mwOwner world)
  case mPrev of
    Nothing -> pure (Left alreadyOpen)
    Just True -> do
      putMVar (mwOwner world) True
      pure (Left alreadyOpen)
    Just False -> do
      putMVar (mwOwner world) True
      qVar <- newMVar []
      sVar <- newIORef zeroStats
      cVar <- newMVar ()
      pure (Right (mkStore world limits inj qVar sVar cVar))
  where
    alreadyOpen = StoreSecondWriter "memory store is already open (single writer)"

-- | Build the 'Store' record over an owned world.
mkStore :: MemoryWorld -> StoreLimits -> FaultInjector -> MVar [(TokenId, String)] -> IORef StoreStats -> MVar () -> Store
mkStore world limits inj qVar sVar cVar = Store
  { storeLoadTokens = loadTokens world
  , storeLoadJobs = loadJobs world
  , storeCommit = protocolDelta world limits inj qVar sVar cVar
  , storeResetToken = resetTokenWorld world limits inj qVar sVar cVar
  , storeClose = releaseOwner (mwOwner world)
  , storeInspect = inspectWorld world
  , storeQuarantined = readMVar qVar
  , storeReload = reloadWorld world qVar
  , storeStats = readIORef sVar
  , storeLoadMeta = loadMeta world
  }

-- | Release ownership. Idempotent: a double close leaves the flag
-- released and never reports an error.
releaseOwner :: MVar Bool -> IO ()
releaseOwner v = mask_ $ do
  _ <- takeMVar v
  putMVar v False

-- | Load every token with its home objects, token-id ascending,
-- object-id ascending within each token. Decode round-trips every
-- record through its canonical bytes so a memory backend can never
-- harbor an unserializable value. Loads never consult quarantine:
-- reloading is the resolution path.
loadTokens :: MemoryWorld -> IO (Either StoreError [(TokenRecord, [ObjectRecord])])
loadTokens world = withMVar (mwState world) $ \st ->
  pure (mapM (loadOne st) (sortOn trId (Map.elems (wsTokens st))))
  where
    loadOne :: WorldState -> TokenRecord -> Either StoreError (TokenRecord, [ObjectRecord])
    loadOne st tok = case decodeTokenRecord (encodeTokenRecord tok) of
      Nothing -> Left (StoreCorrupt ("corrupt token record: " ++ show (trId tok)))
      Just tok' ->
        let ours = sortOn orId
              [ o | o <- Map.elems (wsObjects st), orToken o == trId tok ]
        in case mapM (decodeObjectRecord . encodeObjectRecord) ours of
          Nothing -> Left (StoreCorrupt ("corrupt object record on token " ++ show (trId tok)))
          Just objs -> Right (tok', objs)

-- | The commit protocol: quarantine refusal, pre-commit
-- validation (limits, expected revisions), pre-commit fault
-- rollback, then the masked durable section (swap, ambiguous
-- verification, post-commit quarantine). One commit runs at a
-- time per handle.
protocolDelta
  :: MemoryWorld
  -> StoreLimits
  -> FaultInjector
  -> MVar [(TokenId, String)]
  -> IORef StoreStats
  -> MVar ()
  -> StoreDelta
  -> IO CommitResult
protocolDelta world limits inj qVar sVar cVar delta =
  bracket_ (takeMVar cVar) (putMVar cVar ())
    (protocolLocked world limits inj qVar sVar delta)

-- | Token reset: the expected generation must match the current
-- one, then the replacement plus the removal of every owned
-- object and job run as one ordinary protocol flow (quarantine,
-- validation, faults, masking all apply).
resetTokenWorld
  :: MemoryWorld
  -> StoreLimits
  -> FaultInjector
  -> MVar [(TokenId, String)]
  -> IORef StoreStats
  -> MVar ()
  -> TokenId
  -> Generation
  -> TokenRecord
  -> IO CommitResult
resetTokenWorld world limits inj qVar sVar cVar tid wantGen replacement =
  bracket_ (takeMVar cVar) (putMVar cVar ()) $ do
    eEff <- resetEffective world tid wantGen replacement
    case eEff of
      Left err -> pure (NotCommitted err)
      Right eff -> protocolLocked world limits inj qVar sVar eff

-- | Build the reset's effective delta under one state read (runs
-- under the commit lock, so the generation check is exact).
resetEffective :: MemoryWorld -> TokenId -> Generation -> TokenRecord -> IO (Either StoreError StoreDelta)
resetEffective world tid wantGen replacement = withMVar (mwState world) $ \st ->
  pure (case Map.lookup tid (wsTokens st) of
    Nothing -> Left (StoreRevisionConflict ("reset of missing token " ++ show tid))
    Just cur
      | trId replacement /= tid ->
          Left (StoreRevisionConflict "reset replacement names a different token")
      | trGeneration cur /= wantGen ->
          Left (StoreRevisionConflict ("reset expected generation " ++ show wantGen
            ++ " but token " ++ show tid ++ " is at " ++ show (trGeneration cur)))
      | otherwise -> Right StoreDelta
          { sdPutTokens = [replacement]
          , sdDropTokens = []
          , sdPutObjects = []
          , sdDropObjects = [orId o | o <- Map.elems (wsObjects st), orToken o == tid]
          , sdPutJobs = []
          , sdDropJobs = [jrPersistentId j | j <- Map.elems (wsJobs st), jrToken j == tid]
          , sdPutMeta = []
          })

-- | The commit flow with the commit lock already held.
protocolLocked
  :: MemoryWorld
  -> StoreLimits
  -> FaultInjector
  -> MVar [(TokenId, String)]
  -> IORef StoreStats
  -> StoreDelta
  -> IO CommitResult
protocolLocked world limits inj qVar sVar delta = do
  affected <- affectedTokens world delta
  q <- readMVar qVar
  case firstQuarantined q affected of
    Just (tid, why) -> pure (NotCommitted (StoreQuarantined tid why))
    Nothing -> do
      eValid <- validateDelta world limits delta
      case eValid of
        Left err -> pure (NotCommitted err)
        Right () -> do
          preFailed <- fiFire inj FaultBeforeCommit
          if preFailed
            then pure (NotCommitted (StoreIO "injected pre-commit failure"))
            else mask_ $ do
              fiOnMasked inj
              st <- takeMVar (mwState world)
              fullDisk <- fiFire inj FaultFullDisk
              if fullDisk
                then do
                  putMVar (mwState world) st
                  let result = NotCommitted (StoreFull "disk full (injected)")
                  fiOnResult inj result
                  pure result
                else do
                  putMVar (mwState world) (applyDelta st delta)
                  ambiguous <- fiFire inj FaultAmbiguousCommit
                  result <-
                    if ambiguous
                      then resolveAmbiguous affected
                      else do
                        bumpCommits sVar
                        postCommitTail affected
                  fiOnResult inj result
                  pure result
  where
    -- The observed outcome is discarded; a reload decides. Present
    -- verifies committed (every table), absent verifies rolled
    -- back, and a failed reload quarantines with 'CommitUnknown'.
    -- Nothing reissues.
    resolveAmbiguous :: [TokenId] -> IO CommitResult
    resolveAmbiguous affected = do
      bumpVerifyReloads sVar
      verifyFailed <- fiFire inj FaultVerifyReload
      if verifyFailed
        then do
          quarantineTokens qVar sVar affected "commit verification failed"
          pure (CommitUnknown (StoreIO "injected verification failure"))
        else do
          eLoaded <- loadTokens world
          eJobs <- loadJobs world
          eMeta <- loadMeta world
          case (eLoaded, eJobs, eMeta) of
            (Right loaded, Right jobs, Right meta)
              | reconcileReload delta loaded == ReconciledPresent
              , reconcileJobsReload delta jobs == ReconciledPresent
              , reconcileMetaReload delta meta == ReconciledPresent -> do
                  bumpCommits sVar
                  postCommitTail affected
            (Right _, Right _, Right _) ->
              pure (NotCommitted (StoreIO "ambiguous commit resolved: delta absent"))
            (Left err, _, _) -> do
              quarantineTokens qVar sVar affected ("reload failed: " ++ show err)
              pure (CommitUnknown err)
            (_, Left err, _) -> do
              quarantineTokens qVar sVar affected ("reload failed: " ++ show err)
              pure (CommitUnknown err)
            (_, _, Left err) -> do
              quarantineTokens qVar sVar affected ("reload failed: " ++ show err)
              pure (CommitUnknown err)
    -- After a confirmed commit, a post-commit failure quarantines
    -- the affected tokens; durable truth stays 'Committed'.
    postCommitTail :: [TokenId] -> IO CommitResult
    postCommitTail affected = do
      postFailed <- fiFire inj FaultAfterCommit
      if postFailed
        then do
          quarantineTokens qVar sVar affected "post-commit failure"
          pure Committed
        else pure Committed

-- | Pre-commit validation against one state read: limits, token
-- references, slot uniqueness, then expected revisions. Runs
-- under the commit lock, so the validated state is the
-- committed-against state.
validateDelta :: MemoryWorld -> StoreLimits -> StoreDelta -> IO (Either StoreError ())
validateDelta world limits delta = withMVar (mwState world) $ \st ->
  pure (case checkLimits limits delta (currentLoaded st) of
    Just err -> Left err
    Nothing -> case checkTokenRefs (Map.toList (wsTokens st)) delta of
      Just err -> Left err
      Nothing -> case checkSlotUnique (Map.toList (wsTokens st)) delta of
        Just err -> Left err
        Nothing -> case checkExpectedRevisions (revOf st) delta of
          Just err -> Left err
          Nothing -> Right ())
  where
    revOf :: WorldState -> ObjectId -> Maybe Revision
    revOf st oid = orRevision <$> Map.lookup oid (wsObjects st)

-- | The current state as loaded associations (no decode
-- round-trip: validation reads the raw state).
currentLoaded :: WorldState -> LoadedState
currentLoaded st = LoadedState
  { lsTokens =
      [ (t, sortOn orId [o | o <- Map.elems (wsObjects st), orToken o == trId t])
      | t <- sortOn trId (Map.elems (wsTokens st))
      ]
  , lsJobs = sortOn jrPersistentId (Map.elems (wsJobs st))
  }

-- | Tokens a delta touches: named tokens plus the home tokens of
-- named objects and jobs (drop owners resolved from current
-- state; unknown drops contribute nothing).
affectedTokens :: MemoryWorld -> StoreDelta -> IO [TokenId]
affectedTokens world delta = withMVar (mwState world) $ \st ->
  pure (nub (explicit ++ resolvedObjs st ++ resolvedJobs st))
  where
    explicit =
      map trId (sdPutTokens delta)
        ++ sdDropTokens delta
        ++ map (orToken . opRecord) (sdPutObjects delta)
        ++ map jrToken (sdPutJobs delta)
    resolvedObjs st =
      [ orToken o
      | oid <- sdDropObjects delta
      , Just o <- [Map.lookup oid (wsObjects st)]
      ]
    resolvedJobs st =
      [ jrToken j
      | pid <- sdDropJobs delta
      , Just j <- [Map.lookup pid (wsJobs st)]
      ]

-- | The first touched token that is quarantined, if any.
firstQuarantined :: [(TokenId, String)] -> [TokenId] -> Maybe (TokenId, String)
firstQuarantined q tids =
  listToMaybe [(tid, why) | tid <- tids, Just why <- [lookup tid q]]

-- | Quarantine tokens with a reason, counting one event per token.
quarantineTokens :: MVar [(TokenId, String)] -> IORef StoreStats -> [TokenId] -> String -> IO ()
quarantineTokens qVar sVar tids why = do
  modifyMVar_ qVar (\q -> pure (foldr insertOne q tids))
  bumpQuarantines sVar (length tids)
  where
    insertOne tid q = (tid, why) : filter ((/= tid) . fst) q

-- | Authoritative reload: a clean load clears the quarantine; a
-- failed load keeps it and reports the error. Reloads never
-- consult the fault script.
reloadWorld :: MemoryWorld -> MVar [(TokenId, String)] -> IO (Either StoreError ())
reloadWorld world qVar = do
  eLoaded <- loadTokens world
  case eLoaded of
    Left err -> pure (Left err)
    Right _ -> modifyMVar_ qVar (\_ -> pure []) >> pure (Right ())

-- | Compare a delta's expected meta rows against reloaded meta
-- with full key/value equality. Every expected row must be
-- present; extra loaded rows are fine. A metadata-only delta
-- reconciles against meta alone.
reconcileMetaReload :: StoreDelta -> [(String, String)] -> Reconcile
reconcileMetaReload delta loaded
  | all (\(k, v) -> lookup k loaded == Just v) (sdPutMeta delta) = ReconciledPresent
  | otherwise = ReconciledAbsent

-- | Pure delta application (shared shape with the SQLite backend's
-- statement plan).
applyDelta :: WorldState -> StoreDelta -> WorldState
applyDelta st delta =
  let toks1 = foldr Map.delete (wsTokens st) (sdDropTokens delta)
      objs1 = foldr Map.delete (wsObjects st) (sdDropObjects delta)
      jobs1 = foldr Map.delete (wsJobs st) (sdDropJobs delta)
  in WorldState
    { wsTokens = foldr (\t m -> Map.insert (trId t) t m) toks1 (sdPutTokens delta)
    , wsObjects = foldr (\p m -> Map.insert (orId (opRecord p)) (opRecord p) m)
        objs1 (sdPutObjects delta)
    , wsJobs = foldr (\j m -> Map.insert (jrPersistentId j) j m)
        jobs1 (sdPutJobs delta)
    , wsMeta = foldr (\(k, v) m -> Map.insert k v m) (wsMeta st) (sdPutMeta delta)
    }

-- | Load every meta row as key/value pairs.
loadMeta :: MemoryWorld -> IO (Either StoreError [(String, String)])
loadMeta world = withMVar (mwState world) $ \st ->
  pure (Right (Map.toList (wsMeta st)))

-- | Load every detached job, persistent-id ascending. Decodes
-- round-trip through the canonical bytes.
loadJobs :: MemoryWorld -> IO (Either StoreError [JobRecord])
loadJobs world = withMVar (mwState world) $ \st ->
  pure (mapM decodeOne (sortOn jrPersistentId (Map.elems (wsJobs st))))
  where
    decodeOne :: JobRecord -> Either StoreError JobRecord
    decodeOne j = case decodeJobRecord (encodeJobRecord j) of
      Nothing -> Left (StoreCorrupt ("corrupt job record: " ++ show (jrPersistentId j)))
      Just j' -> Right j'

-- | Render every stored record through its canonical bytes.
inspectWorld :: MemoryWorld -> IO [StoredDoc]
inspectWorld world = do
  st <- readMVar (mwState world)
  let tokDocs =
        [ StoredDoc "tokens" (show (unTokenId (trId t))) (encodeTokenRecord t)
        | t <- sortOn trId (Map.elems (wsTokens st))
        ]
      objDocs =
        [ StoredDoc "objects" (show (unObjectId (orId o))) (encodeObjectRecord o)
        | o <- sortOn orId (Map.elems (wsObjects st))
        ]
      jobDocs =
        [ StoredDoc "detached_jobs" (encodeHexWord64 (jrPersistentId j)) (encodeJobRecord j)
        | j <- sortOn jrPersistentId (Map.elems (wsJobs st))
        ]
  pure (tokDocs ++ objDocs ++ jobDocs)

-- Identifier projections ('unTokenId', 'unObjectId') come from 'Haskoki.Types'.

-- ---------------------------------------------------------------------------
-- Stats
-- ---------------------------------------------------------------------------

bumpCommits :: IORef StoreStats -> IO ()
bumpCommits v = atomicModifyIORef' v (\s -> (s { ssCommits = ssCommits s + 1 }, ()))

bumpVerifyReloads :: IORef StoreStats -> IO ()
bumpVerifyReloads v = atomicModifyIORef' v (\s -> (s { ssVerifyReloads = ssVerifyReloads s + 1 }, ()))

bumpQuarantines :: IORef StoreStats -> Int -> IO ()
bumpQuarantines v n = atomicModifyIORef' v (\s -> (s { ssQuarantines = ssQuarantines s + n }, ()))
