{- | The detached-job claim authority: one per open 'Store' handle.

Attachment state for persistent detached jobs (who holds a live
binding, who is mid-join, which ids resolved terminally) lives
here, NOT in a detach context. Every 'Haskoki.Runtime.Storage.Store'
handle owns exactly one 'ClaimAuthority', minted by the backend
constructor at open; every detach context opened over that handle
(and every record-update wrapper of it) reads and writes the same
authority, so two contexts over one handle cannot both hold a live
binding for one persistent job id. A fresh handle (a reopen after
close) starts with a fresh, empty authority, like quarantine.

The authority is keyed by 'TokenId', then by persistent id: one
handle can serve several tokens, and a token never sees another
token's attachments (a cross-token join of a live row keeps
answering unknown through the token check instead of an
attachment refusal).

This is a private leaf module (no Store, Async, or Lifecycle
import), so both the storage layer and the async runtime can
depend on it without a module cycle. It also homes
'AsyncTableId' (re-exported abstractly by
"Haskoki.Runtime.Async", whose mint is the only constructor
call) and 'JobExecState' (re-exported unchanged by
"Haskoki.Runtime.Storage"). Transitions are plain STM over one
'TVar': no Store IO ever runs inside them.
-}
module Haskoki.Runtime.Attach
  ( -- * Table identity
    AsyncTableId (..)
    -- * Durable execution states
  , JobExecState (..)
    -- * Attachment state
  , Attachment (..)
  , ClaimPrior (..)
  , TokenClaims (..)
  , emptyTokenClaims
    -- * The authority
  , ClaimAuthority
  , newClaimAuthority
  , readTokenClaims
  , writeTokenClaims
  , claimCensus
  , markCensus
  ) where

import Control.Concurrent.STM
  ( STM
  , TVar
  , atomically
  , newTVarIO
  , readTVar
  , writeTVar
  )
import Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map
import Data.Set (Set)
import qualified Data.Set as Set
import Data.Unique (Unique)
import Data.Word (Word64)

import Haskoki.Types (JobId, SessionId, TokenId)

-- | Opaque process-local identity of one async job table,
-- minted uniquely per table. Job ids are table-local counters
-- (every fresh table starts at 0), so detached attachments key
-- their live bindings by @('AsyncTableId', 'JobId')@ instead of
-- the bare job id: two tables sharing a detach context never
-- confuse each other's job zero. The constructor is private to
-- the library — identities come only from the async runtime's
-- mint ('Haskoki.Runtime.Async.asyncTableId') — and values are
-- meaningless across processes (never persisted, never on the
-- wire; persistent job ids are unchanged).
newtype AsyncTableId = AsyncTableId Int
  deriving (Eq, Ord, Show)

-- | Durable detached-job execution states (matching the schema's
-- @CHECK@ constraint). The store owns the record side; the
-- detach\/rejoin lifecycle moves jobs between these.
data JobExecState
  = JobQueued
  | JobReady
  | JobFailed
  | JobCanceled
  | JobDelivered
  deriving (Eq, Show)

-- | Internal attachment state of one persistent job: actively
-- bound to a live job (owned by one table), detached-awaiting-
-- join, terminally resolved, or an in-progress join claim
-- carrying the claiming table and session identity plus a fresh
-- per-attempt token. Actives and claims name their table so two
-- tables never resolve each other's local job ids; the attempt
-- token makes commit and rollback exact — a retry's later claim
-- is never mistaken for the older one it follows. Claims also
-- record what they replaced (idle or absent) so a racing
-- retirement rolls exactly them back. (No 'Show': 'Unique' has
-- none, and this state is never rendered.)
data Attachment
  = AttActive !AsyncTableId !JobId
  | AttIdle
  | AttTerminal !JobExecState
  | AttClaim !AsyncTableId !SessionId !Unique !ClaimPrior
  deriving (Eq)

-- | What a join claim replaced: the rollback target. Claims only
-- ever replace an idle entry or an absent one. Recorded in the
-- claim itself, so both the claimant and a racing retirement
-- roll exactly it back.
data ClaimPrior
  = ClaimHadIdle
  | ClaimHadNone
  deriving (Eq, Show)

-- | One token's claim state on one store handle: the attachment
-- registry (persistent id to state), the live-job reverse map
-- keyed by table and job identity, the opaque\/saveability marks
-- keyed by table and job identity, and the retired-table set
-- (a retired table's late claims and commits are refused).
data TokenClaims = TokenClaims
  { tcAttach :: !(Map Word64 Attachment)
  , tcReverse :: !(Map (AsyncTableId, JobId) Word64)
  , tcOpaque :: !(Map (AsyncTableId, JobId) String)
  , tcRetired :: !(Set AsyncTableId)
  }

-- | No attachments, no marks, nothing retired.
emptyTokenClaims :: TokenClaims
emptyTokenClaims = TokenClaims Map.empty Map.empty Map.empty Set.empty

-- | The store-handle-owned claim authority. 'Eq' is identity of
-- the underlying 'TVar': two values are equal exactly when they
-- are the same authority (a record-update wrapper of a handle
-- shares its authority; a reopened handle never does).
newtype ClaimAuthority = ClaimAuthority (TVar (Map TokenId TokenClaims))
  deriving (Eq)

-- | A fresh, empty authority (one per store open).
newClaimAuthority :: IO ClaimAuthority
newClaimAuthority = ClaimAuthority <$> newTVarIO Map.empty

-- | One token's claim state (empty when the token has none).
readTokenClaims :: ClaimAuthority -> TokenId -> STM TokenClaims
readTokenClaims (ClaimAuthority var) tok =
  Map.findWithDefault emptyTokenClaims tok <$> readTVar var

-- | Replace one token's claim state; other tokens are untouched.
writeTokenClaims :: ClaimAuthority -> TokenId -> TokenClaims -> STM ()
writeTokenClaims (ClaimAuthority var) tok tc = do
  m <- readTVar var
  writeTVar var (Map.insert tok tc m)

-- | Attachment census for one token: @(active, idle, terminal)@,
-- where in-progress join claims count as idle (no live binding
-- exists yet: the job is still detached-awaiting-join).
claimCensus :: ClaimAuthority -> TokenId -> IO (Int, Int, Int)
claimCensus auth tok = do
  tc <- atomically (readTokenClaims auth tok)
  let atts = Map.elems (tcAttach tc)
      active = length [() | AttActive _ _ <- atts]
      terminal = length [() | AttTerminal _ <- atts]
  pure (active, length atts - active - terminal, terminal)

-- | Opaque-mark census for one token: how many native-opaque
-- marks the authority holds (every table, every job).
markCensus :: ClaimAuthority -> TokenId -> IO Int
markCensus auth tok =
  Map.size . tcOpaque <$> atomically (readTokenClaims auth tok)
