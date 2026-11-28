{- | Storage backend contract.
-}
module Haskoki.Runtime.Storage.Contract
  ( Store (..)
  , StoredDoc (..)
  , HandleState (..)
  , storeClosed
  ) where

import Data.Word (Word64)
import Haskoki.Runtime.Attach (ClaimAuthority)
import Haskoki.Types
  ( Generation (..)
  , TokenId (..)
  , redactShown
  )
import Haskoki.Runtime.Storage.Commit
import Haskoki.Runtime.Storage.Deltas
import Haskoki.Runtime.Storage.Records

-- | The narrow backend contract: load, commit, close, and
-- raw-document inspection (the fixture hook for encoding scans),
-- quarantine listing, authoritative reload, commit counters, job
-- loads, durable job-id reservation, and token reset:
-- 'storeResetToken' replaces the token (expected-generation
-- guarded) and atomically removes its objects and jobs, keeping
-- its credential row.
--
-- Quarantine is a live-handle property: it guards a handle whose
-- view may have diverged from durable truth. A fresh handle loads
-- the authoritative bytes and starts clean.
--
-- Ownership is handle-scoped: every open mints a fresh owner
-- token and a handle is closed exactly as its own owner. A close
-- releases ownership only while its handle is still the current
-- owner; a stale close (a second close after the identity
-- reopened under a new handle) is a silent no-op that never
-- releases the new owner.
--
-- Close serializes with use: 'storeClose' waits for any
-- in-flight operation on its handle (commit, reset, load,
-- inspect, reload), then marks the handle closed. After a close
-- returns, every world-touching operation on that handle fails
-- closed instead of touching released state — loads, inspect,
-- reload, and meta loads report 'Left' 'storeClosed', commits
-- and resets report 'NotCommitted' 'storeClosed' — while
-- 'storeQuarantined' and 'storeStats'
-- stay readable (live-handle properties that never touch the
-- world). 'storeInspect' is fallible for the same reason: a
-- closed handle or an unloadable world reports 'Left', never a
-- silent empty list.
--
-- A failed close retains everything and refuses onward use:
-- when the close itself cannot complete (an injected
-- 'FaultClose', or a SQLite close error), ownership and kernel
-- guards stay held, the handle stops serving new operations
-- (every world-touching operation reports 'storeClosed', exactly
-- as after a clean close), the close reports the failure by
-- throwing it, and a later close retries for real. A failed close
-- never half-releases, and the next owner can never enter around
-- the surviving connection.
--
-- The detached-job claim authority is handle-scoped too
-- ('storeClaims'): each open mints one fresh, empty authority;
-- every detach context over the handle (and every record-update
-- wrapper of it, which copies the field) shares it, so two
-- contexts over one handle cannot both hold a live binding for
-- one persistent job id. It is process-local and never durable:
-- a reopened handle starts with no attachments, exactly like
-- quarantine, so live attachments must be retired before the
-- close (close does not drain them).
data Store = Store
  { storeLoadTokens :: IO (Either StoreError [(TokenRecord, [ObjectRecord])])
  , storeLoadJobs :: IO (Either StoreError [JobRecord])
  , storeLoadCredentials :: IO (Either StoreError [CredentialRecord])
  , storeCommit :: StoreDelta -> IO CommitResult
  , storeResetToken :: TokenId -> Generation -> TokenRecord -> IO CommitResult
  -- | Reserve one store-wide persistent job id: the
  -- 'jobIdCounterKey' high-water mark advances DURABLY before
  -- the id is returned, under the same store-wide ownership
  -- serialization as commits, so two contexts (or two tokens)
  -- on one store never mint the same id. The caller then
  -- inserts the job record with an ordinary 'storeCommit' (a
  -- failed insert leaves a gap, never a reuse). An ambiguous
  -- reservation reconciles before any id is returned: resolved
  -- present returns the durable id, resolved absent fails with
  -- nothing written, and an unresolvable verification failure
  -- quarantines and fails — never a shared id. Reset and drop
  -- keep the mark and fold deleted ids into it (a stale
  -- pre-reset id can never name new work, even on a legacy
  -- store whose mark never advanced); exhaustion refuses
  -- before the 'Word64' domain can wrap; a closed handle
  -- reports 'Left' 'storeClosed'.
  , storeReserveJobId :: IO (Either StoreError Word64)
  , storeClose :: IO ()
  , storeInspect :: IO (Either StoreError [StoredDoc])
  , storeQuarantined :: IO [(TokenId, String)]
  , storeReload :: IO (Either StoreError ())
  , storeStats :: IO StoreStats
  , storeLoadMeta :: IO (Either StoreError [(String, String)])
  -- | The handle-owned detached-job claim authority (see above).
  , storeClaims :: !ClaimAuthority
  }

-- | One raw stored document: the table, the stable key, and the
-- canonical JSON bytes. The storage suite scans these for encoding
-- violations (handles, pointers, bare numbers).
data StoredDoc = StoredDoc
  { docTable :: !String
  , docKey :: !String
  , docJson :: !String
  } deriving (Eq)

-- | 'Show' redacts the document body: object documents
-- embed base64 key material, so 'docJson' renders its kind and
-- length only ('redactShown'). Table and key render normally.
-- Explicit inspection reads the exported 'docJson' field (never
-- 'Show').
instance Show StoredDoc where
  show d = "StoredDoc {docTable = " ++ show (docTable d)
    ++ ", docKey = " ++ show (docKey d)
    ++ ", docJson = " ++ redactShown "doc" (length (docJson d)) ++ "}"

-- | Per-handle lifecycle state, owned by the backend's
-- close gate. 'HandleOpen' serves; 'HandleClosed' (a clean close)
-- refuses new operations and ignores further closes;
-- 'HandleCloseFailed' (a close that could not complete) refuses
-- new operations like a closed handle but still owns the
-- identity, and the next close retries for real.
data HandleState
  = HandleOpen
  | HandleCloseFailed
  | HandleClosed
  deriving (Eq, Show)

-- | The use-after-close diagnosis, shared by both backends and by
-- both refusing states: every error-returning operation reports
-- exactly this on a closed or close-failed handle (commits wrap
-- it in 'NotCommitted').
storeClosed :: StoreError
storeClosed = StoreIO "store is closed"
