{- | Provider lifecycle runtime: init/finalize validation, session
admission, the mutation gate, short STM publication, explicit
reservation invalidation, and the callback-lock adapter.

Discipline (architecture sections 6-8):

* Exactly one mutation holds the 'Gate' at a time. Planning
  ('planCall') runs on a snapshot; only publication takes the gate.
* STM transactions coordinate @TVar@ state only. 'publishDelta' is
  pure; no crypto, SQLite, pointer, callback, or logging IO runs
  inside 'atomically' (checked by inspection: this module performs
  all IO outside STM, and the transactions below touch only
  @TVar@s).
* Invalidation is explicit: 'invalidateSession' bumps a generation
  so dependent reservations go stale instead of committing against
  moved state.
-}
module Haskoki.Runtime.Lifecycle
  ( -- * Provider state and init/finalize validation
    ProviderState (..)
  , CallbackSet (..)
  , InitArgs (..)
  , defaultInitArgs
  , InitDeny (..)
  , initDenyCode
  , validateInit
  , FinalizeDeny (..)
  , finalizeDenyCode
  , validateFinalize
    -- * Environment
  , Env
  , newEnv
  , newEnvWith
  , envRules
  , rulesFromConfig
  , envGate
  , envAdapter
  , initialize
  , finalize
  , seatToken
  , snapshotModel
  , restoreStoreState
    -- * Mutation gate and publication
  , Gate
  , newGate
  , withGate
  , gateBusy
  , publish
  , invalidateSession
  , checkReservation
  , commitAndDeliver
    -- * Callback-lock adapter
  , NativeMutex (..)
  , MutexHooks (..)
  , referenceHooks
  , MutexCounts (..)
  , MutexAdapter (..)
  , newMutexAdapter
  , adapterCounts
  , adapterLive
  , createCounted
  , destroyCounted
  , withAdapterLock
  , withInitLocks
  ) where

import Control.Concurrent.MVar (MVar, newMVar, takeMVar, putMVar, tryTakeMVar)
import Control.Concurrent.STM
  ( TVar
  , atomically
  , newTVarIO
  , readTVar
  , readTVarIO
  , writeTVar
  )
import Control.Exception (bracket, bracket_, mask, mask_, onException)
import Control.Monad (forM_)
import Data.IORef (IORef, atomicModifyIORef', newIORef, readIORef)
import qualified Data.Map.Strict as Map

import Haskoki.Model
  ( Model (..)
  , ObjectState (..)
  , SessionState (..)
  , addToken
  , emptyModel
  , lookupSession
  )
import Haskoki.Outcome
  ( ModelFault (..)
  , Reservation (..)
  , ResourceRelease
  , RevisionDep
  , StateDelta (..)
  )
import Haskoki.Rules (Rules (..), defaultRules)
import Haskoki.Runtime.Config
  ( Config (..)
  , Limits (..)
  )
import Haskoki.Runtime.Storage
  ( ObjectRecord (..)
  , TokenRecord (..)
  , reserveRestoredIds
  )
import Haskoki.Session (AdmitDeny (..), admitToken)
import Haskoki.Transition (publishDelta, reservationStale)
import Haskoki.Types
  ( Generation (..)
  , Outcome (..)
  , ReturnCode (..)
  , SessionId (..)
  , SlotId
  , TokenId
  )

-- ---------------------------------------------------------------------------
-- Provider state and the init/finalize validation table
-- ---------------------------------------------------------------------------

-- | Provider liveness. Sessions may exist only while initialized.
data ProviderState
  = ProviderFresh
  | ProviderInitialized !InitArgs
  deriving (Eq, Show)

-- | Which mutex callbacks the host supplied. PKCS#11 requires the
-- full set or none; a partial set is rejected, never silently
-- completed.
data CallbackSet
  = NoCallbacks
  | FullCallbacks
  | PartialCallbacks
  deriving (Eq, Show)

-- | Normalized C_Initialize arguments: OS-locking request, whether
-- any reserved flag bits were set, and the callback set shape.
data InitArgs = InitArgs
  { iaOsLocking :: !Bool
  , iaReservedFlags :: !Bool
  , iaCallbacks :: !CallbackSet
  } deriving (Eq, Show)

-- | The default init: NULL @pInitArgs@ equivalent (no OS locking
-- request, no flags, no callbacks).
defaultInitArgs :: InitArgs
defaultInitArgs = InitArgs
  { iaOsLocking = False
  , iaReservedFlags = False
  , iaCallbacks = NoCallbacks
  }

-- | Why initialization was denied.
data InitDeny
  = InitAlreadyInitialized
  | InitBadArgs
  deriving (Eq, Show)

-- | Source-defined code for each init denial.
initDenyCode :: InitDeny -> ReturnCode
initDenyCode d = case d of
  InitAlreadyInitialized -> CKR_CRYPTOKI_ALREADY_INITIALIZED
  InitBadArgs -> CKR_ARGUMENTS_BAD

-- | Initialization validation table:
--
-- @
-- state               reserved?  callbacks   result
-- Initialized         _          _           deny (already)
-- Fresh               True       _           deny (bad args)
-- Fresh               _          Partial     deny (bad args)
-- Fresh               False      None|Full   accept
-- @
validateInit :: ProviderState -> InitArgs -> Either InitDeny InitArgs
validateInit ProviderFresh args
  | iaReservedFlags args = Left InitBadArgs
  | iaCallbacks args == PartialCallbacks = Left InitBadArgs
  | otherwise = Right args
validateInit (ProviderInitialized _) _ = Left InitAlreadyInitialized

-- | Why finalization was denied.
data FinalizeDeny
  = FinalizeNotInitialized
  | FinalizeSessionsOpen
  deriving (Eq, Show)

-- | Code for each finalize denial. Sessions must be closed
-- explicitly first (demonstrator policy: finalization never
-- silently drops sessions).
finalizeDenyCode :: FinalizeDeny -> ReturnCode
finalizeDenyCode d = case d of
  FinalizeNotInitialized -> CKR_CRYPTOKI_NOT_INITIALIZED
  FinalizeSessionsOpen -> CKR_GENERAL_ERROR

-- | Finalization validation: initialized with zero open sessions.
validateFinalize :: ProviderState -> Int -> Either FinalizeDeny ()
validateFinalize ProviderFresh _ = Left FinalizeNotInitialized
validateFinalize (ProviderInitialized _) nOpen
  | nOpen > 0 = Left FinalizeSessionsOpen
  | otherwise = Right ()

-- ---------------------------------------------------------------------------
-- Environment
-- ---------------------------------------------------------------------------

-- | The runtime environment: policy, mutation gate, model and
-- provider state cells, and the callback-lock adapter.
data Env = Env
  { envRules :: !Rules
  , envGate :: !Gate
  , envModel :: !(TVar Model)
  , envProvider :: !(TVar ProviderState)
  , envAdapter :: !MutexAdapter
  }

-- | Build a fresh environment: default provider state, empty model,
-- and a reference callback-lock adapter.
newEnv :: Rules -> IO Env
newEnv rules = newEnvWith rules =<< referenceHooks

-- | Build a fresh environment over host-supplied mutex hooks: a real
-- host passes its OS mutex wrappers here, and tests pass tracking
-- hooks to assert callback discipline (A05).
newEnvWith :: Rules -> MutexHooks -> IO Env
newEnvWith rules hooks = do
  gate <- newGate
  model <- newTVarIO emptyModel
  provider <- newTVarIO ProviderFresh
  adapter <- newMutexAdapter hooks
  pure Env
    { envRules = rules
    , envGate = gate
    , envModel = model
    , envProvider = provider
    , envAdapter = adapter
    }

-- | Derive instance policy from a resolved config: the @[limits]@
-- admission bounds become the 'Rules' bounds (sessions, objects,
-- slots); every other knob stays at 'defaultRules'. This is the
-- single source of truth for the bounds on native paths: operators
-- tune @limits.*@ and enforcement tracks it. On 'defaultConfig' this
-- equals 'defaultRules' (pinned by the admission spec).
rulesFromConfig :: Config -> Rules
rulesFromConfig cfg = defaultRules
  { rulesMaxSessions = limSessions lims
  , rulesMaxObjects = limObjects lims
  , rulesMaxTokens = limSlots lims
  }
  where
    lims = cfgLimits cfg

-- | Initialize the provider under the gate. The STM transaction
-- reads and writes the provider cell only.
initialize :: Env -> InitArgs -> IO (Outcome ())
initialize env args = withGate (envGate env) $ do
  verdict <- atomically $ do
    st <- readTVar (envProvider env)
    case validateInit st args of
      Left deny -> pure (Left deny)
      Right ok -> writeTVar (envProvider env) (ProviderInitialized ok) >> pure (Right ())
  pure $ case verdict of
    Left deny -> OutcomeErr (initDenyCode deny)
    Right () -> OutcomeOk ()

-- | Finalize the provider under the gate. Denied while sessions are
-- open; on success the provider returns to fresh.
finalize :: Env -> IO (Outcome ())
finalize env = withGate (envGate env) $ do
  verdict <- atomically $ do
    st <- readTVar (envProvider env)
    m <- readTVar (envModel env)
    case validateFinalize st (Map.size (mSessions m)) of
      Left deny -> pure (Left deny)
      Right () -> writeTVar (envProvider env) ProviderFresh >> pure (Right ())
  pure $ case verdict of
    Left deny -> OutcomeErr (finalizeDenyCode deny)
    Right () -> OutcomeOk ()

-- | Seat a token in a slot (host setup path). Runs under the gate
-- with a single-cell STM update. Reseating an already-seated slot
-- succeeds idempotently; seating past 'rulesMaxTokens' distinct
-- slots is refused with 'AdmitTokensFull' and seats nothing.
seatToken :: Env -> SlotId -> IO (Either AdmitDeny ())
seatToken env slot = withGate (envGate env) $
  atomically $ do
    m <- readTVar (envModel env)
    case Map.lookup slot (mTokenAuth m) of
      Just _ -> pure (Right ())
      Nothing -> case admitToken (envRules env) (Map.size (mTokenAuth m)) of
        Left deny -> pure (Left deny)
        Right () -> do
          writeTVar (envModel env) (addToken m slot)
          pure (Right ())

-- | Snapshot the current model. Read-only; takes no gate. Callers
-- plan against the snapshot and persist through 'publish', so
-- per-session operation state survives across calls in the model cell.
snapshotModel :: Env -> IO Model
snapshotModel env = readTVarIO (envModel env)

-- | Reload token metadata and token objects from the durable store
-- into a fresh model (provider-reinit path). Each stored token
-- seats its slot with its stored auth; each stored object lands
-- under its stable id with its stored attributes and revision, owned
-- by its token (stored objects are always token objects); the id
-- space reserves past the restored maximum. Sessions, handles, and
-- native bindings are NEVER reloaded — those belong to the old
-- provider generation alone. Objects naming an unknown token are
-- skipped (unreachable through validated stores, which enforce token
-- references on commit). Runs under the gate with a single-cell STM
-- update. All-or-nothing on BOTH bounds: when the stored tokens
-- would seat past 'rulesMaxTokens' distinct slots, nothing is
-- written and 'AdmitTokensFull' is returned; when the stored
-- objects would seat past 'rulesMaxObjects', nothing is written and
-- 'AdmitObjectsFull' is returned (the caller fails the open
-- loudly); otherwise the full reload commits.
restoreStoreState
  :: Env -> [(TokenRecord, [ObjectRecord])] -> IO (Either AdmitDeny ())
restoreStoreState env loaded = withGate (envGate env) $
  atomically $ do
    m <- readTVar (envModel env)
    let newSlots = filter (`Map.notMember` mTokenAuth m)
          [trSlot t | (t, _) <- loaded]
        total = Map.size (mTokenAuth m) + length newSlots
    -- Bulk form of 'admitToken': the post-reload seated count must
    -- fit the slot bound, else nothing is written.
    if total > rulesMaxTokens (envRules env)
      then pure (Left AdmitTokensFull)
      else
        let slots = Map.fromList [(trId t, trSlot t) | (t, _) <- loaded]
            m1 = foldr seatTokenRecord m loaded
            m2 = foldr (insertRestored slots) m1
              [o | (_, os) <- loaded, o <- os]
        -- Bulk form of 'admitObjects': the would-be object count
        -- (exact: id collisions and unknown-token skips are already
        -- folded into the map) must fit the object bound, else
        -- nothing is written.
        in if Map.size (mObjects m2) > rulesMaxObjects (envRules env)
          then pure (Left AdmitObjectsFull)
          else do
            writeTVar (envModel env)
              (reserveRestoredIds [orId o | (_, os) <- loaded, o <- os] m2)
            pure (Right ())
  where
    seatTokenRecord :: (TokenRecord, [ObjectRecord]) -> Model -> Model
    seatTokenRecord (trec, _) acc =
      let acc1 = addToken acc (trSlot trec)
      in acc1 { mTokenAuth = Map.insert (trSlot trec) (trAuth trec)
          (mTokenAuth acc1) }
    insertRestored
      :: Map.Map TokenId SlotId -> ObjectRecord -> Model -> Model
    insertRestored slots orec acc = case Map.lookup (orToken orec) slots of
      Nothing -> acc
      Just slot -> acc
        { mObjects = Map.insert (orId orec)
            ObjectState
              { osId = orId orec
              , osRevision = orRevision orec
              , osGeneration = Generation 1
              , osAttrs = orAttrs orec
              , osOwner = Nothing
              , osSlot = slot
              }
            (mObjects acc)
        }

-- ---------------------------------------------------------------------------
-- Mutation gate and publication
-- ---------------------------------------------------------------------------

-- | The mutation gate: at most one publisher at a time. Planning
-- stays outside; only the short publication transaction holds this.
newtype Gate = Gate (MVar ())

-- | A free gate.
newGate :: IO Gate
newGate = Gate <$> newMVar ()

-- | Run an action holding the gate (exception-safe).
withGate :: Gate -> IO a -> IO a
withGate (Gate g) action = bracket_ (takeMVar g) (putMVar g ()) action

-- | Non-blocking gate probe (diagnostic affordance for A05):
-- 'True' while the gate is held. The gate 'MVar' is
-- non-reentrant, so a callback invoked by the holding thread
-- observes 'True'. The take\/put pair runs masked so the token
-- cannot leak; a racing publisher only waits out the probe.
gateBusy :: Gate -> IO Bool
gateBusy (Gate g) = mask_ $ do
  m <- tryTakeMVar g
  case m of
    Nothing -> pure True
    Just () -> putMVar g () >> pure False

-- | Publish a delta: take the gate, then run one short STM
-- transaction that reads the model, applies the pure 'publishDelta',
-- and writes the result back. The transaction performs no IO.
publish :: Env -> StateDelta -> IO (Either ModelFault ())
publish env delta = withGate (envGate env) $
  atomically $ do
    m <- readTVar (envModel env)
    case publishDelta m delta of
      Left fault -> pure (Left fault)
      Right m' -> writeTVar (envModel env) m' >> pure (Right ())

-- | Explicit reservation invalidation: bump a session's generation
-- so every dependency pinned to the old generation goes stale. A
-- missing session is a no-op (closing already invalidated it).
invalidateSession :: Env -> SessionId -> IO ()
invalidateSession env sid = withGate (envGate env) $
  atomically $ do
    m <- readTVar (envModel env)
    case lookupSession m sid of
      Nothing -> pure ()
      Just st ->
        let Generation g = ssGeneration st
            st' = st { ssGeneration = Generation (g + 1) }
        in writeTVar (envModel env)
             m { mSessions = Map.insert sid st' (mSessions m) }

-- | Check a reservation against the current model snapshot:
-- 'Nothing' when every dependency still holds, else the first stale
-- dependency. Read-only; takes no gate.
checkReservation :: Env -> Reservation -> IO (Maybe RevisionDep)
checkReservation env res = do
  m <- readTVarIO (envModel env)
  pure (reservationStale m res)

-- ---------------------------------------------------------------------------
-- Callback-lock adapter
-- ---------------------------------------------------------------------------

-- | A host mutex handle. The reference hooks below back these with
-- an 'MVar'; a real host passes its own OS mutex wrappers in
-- 'MutexHooks'.
newtype NativeMutex = NativeMutex (MVar ())
  deriving (Eq)

instance Show NativeMutex where
  show _ = "NativeMutex"

-- | Host mutex callbacks (the C_CreateMutex/C_DestroyMutex/C_LockMutex/
-- C_UnlockMutex set), modeled as Haskell functions returning
-- host-style integer codes on creation only; lock operations on a
-- live mutex cannot fail in this model.
data MutexHooks = MutexHooks
  { hookCreate :: IO NativeMutex
  , hookDestroy :: NativeMutex -> IO ()
  , hookLock :: NativeMutex -> IO ()
  , hookUnlock :: NativeMutex -> IO ()
  }

-- | Reference hooks: MVar-backed mutexes. This is the adapter's
-- default host and the oracle for the C canary's counting test.
referenceHooks :: IO MutexHooks
referenceHooks = pure MutexHooks
  { hookCreate = NativeMutex <$> newMVar ()
  , hookDestroy = \(NativeMutex _) -> pure ()
  , hookLock = \(NativeMutex m) -> takeMVar m
  , hookUnlock = \(NativeMutex m) -> putMVar m ()
  }

-- | Lifecycle counts: creations, destructions, lock and unlock uses.
-- Every field counts adapter /calls/, not successful host operations:
-- a destroy of an unknown or already-destroyed handle still runs the
-- host hook (the host decides validity) and still increments
-- 'mcDestroyed'. Use 'adapterLive' (the live set) to prove
-- exactly-once destruction, not @mcCreated - mcDestroyed@.
data MutexCounts = MutexCounts
  { mcCreated :: !Int
  , mcDestroyed :: !Int
  , mcLocks :: !Int
  , mcUnlocks :: !Int
  } deriving (Eq, Show)

-- | A counting adapter over host hooks: every create/use/destroy
-- runs the host hook and records it, so partial-initialization
-- cleanup paths stay observable.
data MutexAdapter = MutexAdapter
  { maHooks :: !MutexHooks
  , maCounts :: !(IORef MutexCounts)
  , maLive :: !(IORef [NativeMutex])
  }

-- | Wrap host hooks in a counting adapter.
newMutexAdapter :: MutexHooks -> IO MutexAdapter
newMutexAdapter hooks = do
  counts <- newIORef (MutexCounts 0 0 0 0)
  live <- newIORef []
  pure MutexAdapter
    { maHooks = hooks
    , maCounts = counts
    , maLive = live
    }

-- | Current lifecycle counts.
adapterCounts :: MutexAdapter -> IO MutexCounts
adapterCounts = readIORef . maCounts

-- | Number of created-but-not-destroyed mutexes.
adapterLive :: MutexAdapter -> IO Int
adapterLive ma = length <$> readIORef (maLive ma)

-- | Create one mutex through the host hook and count it.
createCounted :: MutexAdapter -> IO NativeMutex
createCounted ma = mask $ \restore -> do
  m <- restore (hookCreate (maHooks ma))
    `onException` pure ()
  atomicModifyIORef' (maCounts ma) $ \c ->
    (c { mcCreated = mcCreated c + 1 }, ())
  atomicModifyIORef' (maLive ma) $ \live -> (m : live, ())
  pure m

-- | Destroy one mutex through the host hook and count the call.
-- Unknown or double-destroyed handles still run the host hook (the
-- host decides validity) and still increment the destroy count, but
-- do not disturb the live set.
destroyCounted :: MutexAdapter -> NativeMutex -> IO ()
destroyCounted ma m = do
  hookDestroy (maHooks ma) m
  atomicModifyIORef' (maCounts ma) $ \c ->
    (c { mcDestroyed = mcDestroyed c + 1 }, ())
  atomicModifyIORef' (maLive ma) $ \live ->
    (filter (/= m) live, ())

-- | Run an action holding a mutex, counting one lock and one unlock.
withAdapterLock :: MutexAdapter -> NativeMutex -> IO a -> IO a
withAdapterLock ma m action = bracket_
  (hookLock (maHooks ma) m >> bump mcLocks (\c n -> c { mcLocks = n }))
  (hookUnlock (maHooks ma) m >> bump mcUnlocks (\c n -> c { mcUnlocks = n }))
  action
  where
    bump :: (MutexCounts -> Int) -> (MutexCounts -> Int -> MutexCounts) -> IO ()
    bump get set = atomicModifyIORef' (maCounts ma) $ \c ->
      (set c (get c + 1), ())

-- | Create @n@ mutexes, run an action, then destroy all of them —
-- even when setup or the action throws. Models init-time lock
-- provisioning with guaranteed partial-cleanup: acquisition runs
-- incrementally, so a setup failure partway through still destroys
-- every already-created mutex exactly once before the exception
-- propagates (@bracket@ alone would skip the release when its own
-- acquire throws).
withInitLocks :: MutexAdapter -> Int -> IO a -> IO a
withInitLocks ma n action = bracket
  (acquireInitLocks ma n)
  (\ms -> forM_ ms (destroyCounted ma))
  (const action)

-- | Acquire @n@ mutexes one by one; if creation @k@ throws, destroy
-- the @k-1@ already-created mutexes (newest first) and rethrow, so
-- no partial acquire ever leaks.
acquireInitLocks :: MutexAdapter -> Int -> IO [NativeMutex]
acquireInitLocks ma n = go n []
  where
    go :: Int -> [NativeMutex] -> IO [NativeMutex]
    go 0 acc = pure (reverse acc)
    go k acc =
      let cleanup = forM_ acc (destroyCounted ma)
      in do
        m <- createCounted ma `onException` cleanup
        go (k - 1) (m : acc)

-- ---------------------------------------------------------------------------
-- Commit-then-deliver (output path)
-- ---------------------------------------------------------------------------

-- | Publish a delta, then deliver outputs to native buffers. The
-- gate is held only for the short 'publish'; delivery runs after
-- the gate is released, under a host mutex provisioned through the
-- callback-lock adapter (A05: no host callback ever fires while
-- the model gate is held). A faulted publish delivers nothing and
-- provisions no mutex.
--
-- The commit's releases drain through the caller-supplied
-- interpreter after a successful publish, so releases are
-- impossible to forget (the fold over an empty list is a no-op).
-- A faulted publish drains nothing: the commit never landed.
commitAndDeliver
  :: Env -> StateDelta -> [ResourceRelease] -> [a] -> (a -> IO ())
  -> (ResourceRelease -> IO ()) -> IO (Either ModelFault ())
commitAndDeliver env delta releases outs encodeOne releaseOne = do
  verdict <- publish env delta
  case verdict of
    Left fault -> pure (Left fault)
    Right () -> do
      let ad = envAdapter env
      bracket (createCounted ad) (destroyCounted ad) $ \m ->
        withAdapterLock ad m (mapM_ encodeOne outs)
      mapM_ releaseOne releases
      pure (Right ())

