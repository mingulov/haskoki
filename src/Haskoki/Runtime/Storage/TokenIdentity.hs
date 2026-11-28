{- | Detached durable token identity.
-}
module Haskoki.Runtime.Storage.TokenIdentity
  ( DesiredToken (..)
  , IdentityRefusal (..)
  , ReconcilePlan (..)
  , tokensWithoutCredentials
  , reconcileIdentities
  , dupIds
  , renderIdentityRefusal
  , SlotMoveRefusal (..)
  , planSlotMoves
  , dupSlots
  , renderSlotMoveRefusal
  , Store (..)
  , StoredDoc (..)
  , HandleState (..)
  , storeClosed
  ) where

import Data.List ( sort, sortOn)
import qualified Data.Set as Set
import Data.Word ( Word64)
import Haskoki.Runtime.Attach (ClaimAuthority)
import Haskoki.Session
  ( tokenAuthNew
  )
import Haskoki.Types
  ( Generation (..)
  , SlotId (..)
  , TokenId (..)
  , redactShown
  )
import Haskoki.Runtime.Storage.Commit
import Haskoki.Runtime.Storage.Deltas
import Haskoki.Runtime.Storage.Records

-- ---------------------------------------------------------------------------
-- Durable token identity (configuration reconciliation contract)
-- ---------------------------------------------------------------------------
--
-- A token's durable identity is its 'TokenId'; the serving slot is a
-- separate assignment ('trSlot'). Configuration seeds a NEW token;
-- an EXISTING durable token is authoritative over its identity,
-- label, slot, objects, jobs, and auth counters. Labels alone
-- never identify a token.
--
-- 'reconcileIdentities' compares the configured catalog against the
-- stored tokens at open. Matches proceed; new identities seed;
-- every ambiguous identity-changing reconfiguration REFUSES with
-- an 'IdentityRefusal' carrying an actionable message
-- ('renderIdentityRefusal'). There are no automatic migrations:
-- a reorder, an insertion that shifts slots, a
-- removal, or a label change reopens refused, with the durable
-- bytes untouched, until the operator either restores the
-- matching catalog or performs the explicit slot move
-- ('planSlotMoves'). PINs are not part of identity: a token's
-- PINs are its durable credential row (seeded from the catalog
-- when the token is created), so a later catalog PIN edit is
-- accepted here and changes nothing durable. The credential
-- lifecycle itself stays outside this contract.
--
-- The home anchor is unconditional: 'TokenId' 1 sits at 'SlotId'
-- 0 and 'SlotId' 0 holds 'TokenId' 1. The configuration parser,
-- the reconciler, and the move planner each enforce it, so no
-- layer can silently relocate the home token.
--
-- Version and refusal policy, one layer at a time:
--
-- * Configuration keeps @schema_version = 1@: the @token_ids@
--   key is optional and additive, so older files parse
--   unchanged (legacy positional reading: slot @n@ owns
--   @TokenId (n+1)@). Dropping @token_ids@ from a file is a
--   downgrade to that positional reading: it reopens only when
--   the positional layout still matches the durable one, and
--   otherwise refuses (never silently reassigns).
-- * Durable documents keep @format_version = 1@ with no new
--   fields: 'TokenRecord' already separates identity
--   (@token_id@) from assignment (@slot@). Unknown format
--   versions keep refusing on decode, as before.
-- * The SQLite schema marker is @schema_version = 3@: versions 1
--   and 2 refuse at open as migration-required without writing a
--   byte (only the explicit @store migrate@ upgrades them), and
--   any other version refuses as unsupported. The durable
--   documents keep @format_version = 1@.
-- * An interrupted multi-step move sequence reopens refused:
--   the mid-state matches neither endpoint, the reconciler
--   names the first drifted token, and the operator completes
--   the remaining moves explicitly. Nothing auto-repairs and
--   nothing rolls back on its own.
-- * Binary rollback sits outside this contract: a moved store
--   keeps versions every predecessor accepts, but
--   predecessors predate reconciliation and would serve the
--   moved layout positionally (the wrong credential over
--   moved objects). Operators upgrade every serving binary
--   before moving tokens and never roll one back across a
--   move; a future format bump is the mechanism that would
--   make such rollback refuse loudly.

-- | One configured token as the reconciler sees it: serving
-- slot, stable identity, and label. PINs are not part of
-- identity (see the section note above).
data DesiredToken = DesiredToken
  { dtSlot :: !SlotId
  , dtId :: !TokenId
  , dtLabel :: !String
  } deriving (Eq, Show)

-- | Why the configured catalog cannot serve the durable store.
-- Every constructor renders through 'renderIdentityRefusal' to
-- an actionable operator message; the open then fails without
-- writing.
data IdentityRefusal
  = RefuseDuplicateDesired !TokenId
  | RefuseHomeAnchor !TokenId !SlotId
  | RefuseStoredUnconfigured !TokenId !SlotId !String
  | RefuseLabelChanged !TokenId !SlotId !String !String
  | RefuseSlotChanged !TokenId !SlotId !SlotId !String
  deriving (Eq, Show)

-- | The accepted reconciliation outcome: the tokens to seed
-- (identities the configuration names and the store does not
-- hold yet). An empty plan is the steady state: the open
-- proceeds and commits nothing.
data ReconcilePlan = ReconcilePlan
  { planSeeds :: ![TokenRecord]
  } deriving (Eq, Show)

-- | The stored tokens with no credential row, ascending by id: the
-- set a legacy store must freeze before it serves.
tokensWithoutCredentials :: [TokenRecord] -> [TokenId] -> [TokenId]
tokensWithoutCredentials tokens holders =
  sort [trId t | t <- tokens, trId t `Set.notMember` withRow]
  where
    withRow = Set.fromList holders

-- | Compare the configured catalog against the stored tokens.
-- Shape checks (home anchor, duplicate identities) run first;
-- then each stored token, in identity order, must be
-- configured under its durable label at its durable slot;
-- then every configured-but-unknown identity becomes a seed
-- (generation zero, fresh auth). The first mismatch wins, so
-- the refusal is deterministic for a given pair of inputs.
reconcileIdentities :: [DesiredToken] -> [TokenRecord] -> Either IdentityRefusal ReconcilePlan
reconcileIdentities desired stored = do
  mapM_ checkAnchor desired
  checkDuplicates desired
  mapM_ checkStored (sortOn (unTokenId . trId) stored)
  pure (ReconcilePlan seeds)
  where
    byId = [(dtId d, d) | d <- desired]
    storedIds = [trId t | t <- stored]
    checkAnchor d
      | dtId d == TokenId 1 && dtSlot d /= SlotId 0 =
          Left (RefuseHomeAnchor (dtId d) (dtSlot d))
      | dtSlot d == SlotId 0 && dtId d /= TokenId 1 =
          Left (RefuseHomeAnchor (dtId d) (dtSlot d))
      | otherwise = Right ()
    checkDuplicates ds = case dupIds (sort (map dtId ds)) of
      (tid : _) -> Left (RefuseDuplicateDesired tid)
      [] -> Right ()
    checkStored t = case lookup (trId t) byId of
      Nothing ->
        Left (RefuseStoredUnconfigured (trId t) (trSlot t) (trLabel t))
      Just d
        | trLabel t /= dtLabel d ->
            Left (RefuseLabelChanged (trId t) (trSlot t) (trLabel t) (dtLabel d))
        | trSlot t /= dtSlot d ->
            Left (RefuseSlotChanged (trId t) (trSlot t) (dtSlot d) (trLabel t))
        | otherwise -> Right ()
    seeds =
      [ TokenRecord tid slot (Generation 0) label tokenAuthNew
      | d <- desired
      , let tid = dtId d
      , let slot = dtSlot d
      , let label = dtLabel d
      , tid `notElem` storedIds
      ]

-- | First repeated identity in a sorted list ('[]' when unique).
dupIds :: [TokenId] -> [TokenId]
dupIds (x : y : rest)
  | x == y = x : dupIds (y : rest)
  | otherwise = dupIds (y : rest)
dupIds _ = []

-- | Render the operator message for a refusal: what drifted,
-- why the open refuses instead of migrating silently, and the
-- concrete next action (restore the entry, pin @token_ids@, or
-- run the explicit slot move).
renderIdentityRefusal :: IdentityRefusal -> String
renderIdentityRefusal r = case r of
  RefuseDuplicateDesired tid ->
    "the token catalog lists " ++ show tid ++ " twice: stable identities "
      ++ "must be unique. Give each [tokens] entry its own token_ids value "
      ++ "and reopen."
  RefuseHomeAnchor tid slot ->
    "the token catalog seats " ++ show tid ++ " at " ++ show slot ++ ": "
      ++ "slot 0 is the home token TokenId 1, unconditionally. Restore "
      ++ "[tokens] so slot 0 carries token_ids 1 and reopen."
  RefuseStoredUnconfigured tid slot label ->
    "stored token " ++ show tid ++ " (\"" ++ label ++ "\" at " ++ show slot
      ++ ") has no catalog entry: the durable token is authoritative and "
      ++ "is never pruned automatically, so its objects and auth state "
      ++ "stay exactly as stored. Restore its [tokens] entry (with its "
      ++ "pinned token_ids value) and reopen; "
      ++ "a token cannot be removed by editing the catalog."
  RefuseLabelChanged tid slot durableLabel desiredLabel ->
    "stored token " ++ show tid ++ " at " ++ show slot ++ " is labeled \""
      ++ durableLabel ++ "\" but the catalog says \"" ++ desiredLabel
      ++ "\": the durable label is authoritative and labels never "
      ++ "identify a token, so the catalog is not renamed silently. "
      ++ "Restore the durable label in [tokens] and reopen. "
      ++ "There is no relabel command; an in-band C_InitToken relabel "
      ++ "changes the durable label, so update the catalog to match."
  RefuseSlotChanged tid durableSlot desiredSlot label ->
    "stored token " ++ show tid ++ " (\"" ++ label ++ "\") sits at "
      ++ show durableSlot ++ " but the catalog seats it at " ++ show desiredSlot
      ++ ": slot assignment is separate from token identity and never "
      ++ "moves automatically, so the wrong credential cannot silently "
      ++ "reach this token's objects. Either restore the durable slot "
      ++ "in [tokens], or move the token with the Haskell library "
      ++ "operation planSlotMoves (committed before reopening; there is "
      ++ "no installed command for it) and then reopen with the new layout."

-- | Why an explicit slot move cannot run. Every constructor
-- renders through 'renderSlotMoveRefusal'.
data SlotMoveRefusal
  = MoveUnknownToken !TokenId
  | MoveHomeAnchored !TokenId !SlotId
  | MoveTargetClash !SlotId
  | MoveDuplicateMover !TokenId
  | MoveSlotOccupied !SlotId !TokenId
  | MoveBadSlot !SlotId
  deriving (Eq, Show)

-- | Plan the explicit slot-move operation: the ONLY path by
-- which a served token changes slots. The plan is one atomic
-- delta, validated against the projected layout before
-- anything commits:
--
-- * every moved token must exist ('MoveUnknownToken');
-- * no target may be negative ('MoveBadSlot');
-- * the home anchor holds in the projection: 'TokenId' 1
--   stays at 'SlotId' 0 and nothing else enters 'SlotId' 0
--   ('MoveHomeAnchored');
-- * two moves in one plan must not claim the same target
--   ('MoveTargetClash');
-- * a token must appear at most once per plan
--   ('MoveDuplicateMover'): list each moved token once with
--   its final target, never two legs for one token;
-- * a target held by a token outside the plan stays put
--   ('MoveSlotOccupied', naming the holder); a holder that
--   itself moves away vacates, so swaps and rotation chains
--   commit atomically in one plan, while a lone move onto an
--   occupied slot reroutes through a free slot first.
--
-- Moves that change nothing filter out, so a fully settled
-- plan is the empty delta (idempotent, commits nothing).
-- Objects, jobs, labels, generations, and auth counters ride
-- along untouched: only the serving slot changes, and only
-- this operation changes it.
planSlotMoves :: [(TokenId, SlotId)] -> [TokenRecord] -> Either SlotMoveRefusal StoreDelta
planSlotMoves moves stored = do
  mapM_ checkTarget moves
  mapM_ checkKnown moves
  checkMovers moving
  checkClash moving
  mapM_ checkAnchor moving
  mapM_ (checkVacated (map fst moving)) moving
  pure emptyDelta { sdPutTokens = puts }
  where
    byId = [(trId t, t) | t <- stored]
    current = [(trId t, trSlot t) | t <- stored]
    moving = [(tid, slot) | (tid, slot) <- moves, lookup tid current /= Just slot]
    checkTarget (_, slot)
      | unSlotId slot < 0 = Left (MoveBadSlot slot)
      | otherwise = Right ()
    checkKnown (tid, _)
      | tid `elem` map fst current = Right ()
      | otherwise = Left (MoveUnknownToken tid)
    checkMovers ms = case dupIds (sort (map fst ms)) of
      (tid : _) -> Left (MoveDuplicateMover tid)
      [] -> Right ()
    checkClash ms = case dupSlots (sort (map snd ms)) of
      (slot : _) -> Left (MoveTargetClash slot)
      [] -> Right ()
    checkAnchor (tid, slot)
      | tid == TokenId 1 && slot /= SlotId 0 = Left (MoveHomeAnchored tid slot)
      | slot == SlotId 0 && tid /= TokenId 1 = Left (MoveHomeAnchored tid slot)
      | otherwise = Right ()
    checkVacated movers (_, target) = case lookup target holders of
      Nothing -> Right ()
      Just holder
        | holder `elem` movers -> Right ()
        | otherwise -> Left (MoveSlotOccupied target holder)
      where
        holders = [(slot, tid) | (tid, slot) <- current]
    puts = [t { trSlot = target } | (tid, target) <- moving, Just t <- [lookup tid byId]]

-- | First repeated slot in a sorted list ('[]' when unique).
dupSlots :: [SlotId] -> [SlotId]
dupSlots (x : y : rest)
  | x == y = x : dupSlots (y : rest)
  | otherwise = dupSlots (y : rest)
dupSlots _ = []

-- | Render the operator message for a refused move plan.
renderSlotMoveRefusal :: SlotMoveRefusal -> String
renderSlotMoveRefusal r = case r of
  MoveUnknownToken tid ->
    "cannot move " ++ show tid ++ ": no stored token carries that "
      ++ "identity. List the stored token ids and move one of them."
  MoveHomeAnchored tid slot ->
    "cannot move " ++ show tid ++ " to " ++ show slot ++ ": slot 0 is "
      ++ "the home token TokenId 1, unconditionally. The home token "
      ++ "never moves and no other token enters slot 0."
  MoveTargetClash slot ->
    "two moves in one plan claim " ++ show slot ++ ": each target "
      ++ "slot takes exactly one token. Split the plan so every "
      ++ "target is distinct."
  MoveDuplicateMover tid ->
    show tid ++ " is listed twice in one move plan: list each "
      ++ "moved token once with its final target slot."
  MoveSlotOccupied slot holder ->
    show slot ++ " is held by " ++ show holder ++ ", which this plan "
      ++ "does not move: a lone move never displaces another token. "
      ++ "Either include " ++ show holder ++ " in the same plan "
      ++ "(swaps and rotation chains commit atomically) or reroute "
      ++ "through a free slot first."
  MoveBadSlot slot ->
    "cannot move a token to " ++ show slot ++ ": slot numbers start "
      ++ "at 0. Pick a non-negative target slot."

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
