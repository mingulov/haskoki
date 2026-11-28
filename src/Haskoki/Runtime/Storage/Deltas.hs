{- | Detached deltas and results.
-}
module Haskoki.Runtime.Storage.Deltas
  ( StoreDelta (..)
  , emptyDelta
  , StoreDeltaClass (..)
  , deltaClasses
  , scrubTokenAuth
  , scrubDeltaAuth
  , CommitResult (..)
  , StoreError (..)
  ) where

import Data.Word (Word64)
import Control.Exception (Exception)
import Haskoki.Session
  ( clearTransientAuth
  )
import Haskoki.Types
  ( ObjectId (..)
  , TokenId (..)
  )
import Haskoki.Runtime.Storage.Records

-- ---------------------------------------------------------------------------
-- Deltas and results
-- ---------------------------------------------------------------------------

-- | Bounded inserts, updates, and deletes applied as one atomic
-- transaction. A combined key-pair or multi-key derivation is a
-- single 'StoreDelta'; partial application is a backend bug.
--
-- Ownership rule, enforced identically by both backends: an
-- ordinary same-id token put updates the token row and preserves
-- every owned object, job, and credential; dropping a token
-- removes its owned objects, jobs, and credential;
-- @storeResetToken@ is the generation-guarded
-- replacement-plus-removal path for objects and jobs. The
-- credential row stays: an existing durable credential always
-- wins over the catalog PINs.
--
-- Duplicate credential puts for one token resolve first-wins in
-- both backends (the token-row precedent): the validated
-- projection and the memory map agree with the staged SQLite
-- upserts.
data StoreDelta = StoreDelta
  { sdPutTokens :: ![TokenRecord]
  , sdDropTokens :: ![TokenId]
  , sdPutObjects :: ![ObjectPut]
  , sdDropObjects :: ![ObjectId]
  , sdPutJobs :: ![JobRecord]
  , sdDropJobs :: ![Word64]
  , sdPutMeta :: ![(String, String)]
  , sdPutCredentials :: ![CredentialRecord]
  , sdDropCredentials :: ![TokenId]
  } deriving (Eq, Show)

-- | The empty delta: commits nothing.
emptyDelta :: StoreDelta
emptyDelta = StoreDelta
  { sdPutTokens = []
  , sdDropTokens = []
  , sdPutObjects = []
  , sdDropObjects = []
  , sdPutJobs = []
  , sdDropJobs = []
  , sdPutMeta = []
  , sdPutCredentials = []
  , sdDropCredentials = []
  }

-- | The durable write classes of a delta: one per delta list.
-- An auth-only change (a token put carrying moved retry/lock
-- state) is 'DeltaTokensPut': a real write, never a bypass.
data StoreDeltaClass
  = DeltaTokensPut
  | DeltaTokensDrop
  | DeltaObjectsPut
  | DeltaObjectsDrop
  | DeltaJobsPut
  | DeltaJobsDrop
  | DeltaMetaPut
  | DeltaCredentialsPut
  | DeltaCredentialsDrop
  deriving (Eq, Show, Enum, Bounded)

-- | Classify a delta by its nonempty lists, in field order. The
-- empty delta classifies to @[]@. The match is on the record
-- constructor itself (not field selectors), so a new delta list
-- is a compile error here until it gets its own explicit arm;
-- and the classification test pins the full delta against
-- @[minBound .. maxBound]@, so a new class without an arm fails
-- loudly. No catch-all stands between a new durable write and
-- its classification.
deltaClasses :: StoreDelta -> [StoreDeltaClass]
deltaClasses (StoreDelta putToks dropToks putObjs dropObjs putJobs dropJobs putMeta putCreds dropCreds) = concat
  [ [DeltaTokensPut | not (null putToks)]
  , [DeltaTokensDrop | not (null dropToks)]
  , [DeltaObjectsPut | not (null putObjs)]
  , [DeltaObjectsDrop | not (null dropObjs)]
  , [DeltaJobsPut | not (null putJobs)]
  , [DeltaJobsDrop | not (null dropJobs)]
  , [DeltaMetaPut | not (null putMeta)]
  , [DeltaCredentialsPut | not (null putCreds)]
  , [DeltaCredentialsDrop | not (null dropCreds)]
  ]

-- | Clear the transient authentication half of a token record
-- ('clearTransientAuth'): the active application login, the
-- named-user principal, and the session epoch never reach the
-- store. Retry counters and lock flags pass through: they are
-- the durable authentication state.
scrubTokenAuth :: TokenRecord -> TokenRecord
scrubTokenAuth t = t { trAuth = clearTransientAuth (trAuth t) }

-- | Scrub every token put of a delta. Backends apply this at the
-- commit boundary (commits and resets alike), so whatever auth a
-- caller hands over, loads and ambiguous-commit reconciliation
-- observe the durable half only, and reopening never restores an
-- authenticated application session.
scrubDeltaAuth :: StoreDelta -> StoreDelta
scrubDeltaAuth d = d { sdPutTokens = map scrubTokenAuth (sdPutTokens d) }

-- | Commit outcome classification (design 08, section 5).
--
-- * 'Committed': the delta is durable; the caller may publish its
--   in-memory delta.
-- * 'NotCommitted': nothing was written (pre-commit failure, limit
--   hit, revision conflict); the caller publishes nothing.
-- * 'CommitUnknown': the outcome could not be established (a
--   COMMIT failed after the transaction ended, a cleanup ROLLBACK
--   failed, or a verification reload did not settle it); the
--   affected tokens — or, while a transaction stays open, the
--   whole connection — are quarantined. The caller must reload and
--   reconcile, and must NEVER blindly reissue the PKCS#11 operation.
--   Quarantine is process-local state of the live handle: a clean
--   @storeReload@ or a reopen (fresh handle) clears it. A
--   connection-wide quarantine (SQLite: a write transaction left
--   open by a failed ROLLBACK) refuses every load, commit, reset
--   and reservation; only a @storeReload@ whose retried ROLLBACK
--   ends the transaction, or the close (C_Finalize closes the
--   store; SQLite rolls the open transaction back), resolves it.
--   No 'publishStd' path (object creation, derive, provisioning,
--   login-counter writes) reloads after an unresolved commit, so
--   for them it holds until close; only the detached-job path
--   reloads after every unknown result, and its reconcile retries
--   the ROLLBACK, so only there does a connection quarantine lift
--   immediately.
data CommitResult
  = Committed
  | NotCommitted !StoreError
  | CommitUnknown !StoreError
  deriving (Eq, Show)

-- | Diagnosed store failures. Every constructor carries enough
-- context to report; silent replace\/wipe is never an option.
data StoreError
  = StoreIO !String
  | StoreSecondWriter !String
  | StoreQuarantined !TokenId !String
  | StoreSchemaVersion { sevExpected :: !Int, sevFound :: !String }
  | StoreCorrupt !String
  | StoreLimit !String
  | StoreFull !String
  | StoreRevisionConflict !String
  | StoreNeedsMigration !Int !Int
    -- ^ Found and target schema: an older store that only the
    -- explicit @haskoki-ctl store migrate@ upgrades. The open wrote
    -- nothing.
  | StoreJournalPresent !FilePath
    -- ^ An interrupted write left this rollback journal; read-only
    -- tools refuse rather than recover it (see the recovery guide).
    -- Never a @-wal@ or @-shm@ file: those are 'StoreForeignSidecar'.
  | StoreJournalCold !FilePath
    -- ^ An interrupted write left this rollback journal cold
    -- (SQLite itself treats it as not hot, so the database already
    -- reads as committed state). The check refuses it distinctly;
    -- only the explicit migration clears it, under exclusive locks.
  | StoreForeignSidecar !FilePath
    -- ^ A non-empty @-wal@ or @-shm@ sibling: haskoki never writes
    -- one, so it can only come from foreign tooling. Refused
    -- before any SQLite connection opens, by check, migrate and
    -- the serving open alike; the remedy moves both files aside
    -- (keeping them) and never starts the service.
  deriving (Eq, Show)

-- | Store failures throw as exceptions on the paths with no
-- 'Either' channel (a failed @storeClose@ reports by
-- throwing the failure instead of returning silently).
instance Exception StoreError
