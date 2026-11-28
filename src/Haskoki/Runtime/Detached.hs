{- | Detached jobs: GetID (detach) + Join (rejoin) over the
attached-job table and the durable store.

Execution state and attachment state are independent dimensions
(design 07, section 3): a job can be complete but detached, or
pending with no valid old client buffer. This module owns the
attachment dimension:

@
live attached job --GetID--> detached (durable record, no binding)
detached --Join--> live attached job (fresh binding, fresh table)
@

Detach protocol (design 07, section 6), in order:

1. Validate the job\/function and take the attachment-change lease
   ('beginDetach'): no poll\/complete\/cancel can run on the job
   while the lease is held.
2. Prepare a pointer-free record: a deterministic pending recipe
   ('Recipe', replayable after restart) or a prepared owned result.
   Native-opaque work (flagged via 'markJobOpaque' by the adapter
   path that holds a live native context) takes the permitted
   typed unsaveable outcome instead — never a crash, never a
   serialized address.
3. Reserve the persistent id from the store
   (@storeReserveJobId@: the store-wide mark advances durably
   first) and make the record durable (@storeCommit@). The id is
   returned ONLY after the insert and revocation both succeed.
   Re-detaching a joined job retires its superseded id in the same
   atomic delta (the old record canceled, recipe bytes unchanged).
4. Revoke the old binding ('commitDetachRevoke'): the live table
   forgets the job, so no admitted completion can still write
   through the old attachment.
5. On ANY failure the old live attachment is preserved
   ('abortDetach') and no id is returned.

Rejoin validates persistent id, function, token identity\/
generation, recipe\/format version, target-session compatibility
and auth, and capacity — before attaching new storage. One active
attachment per persistent job ('joinPolicyName'); delivery-vs-cancel
arbitration is the job lease, reused, not reimplemented: joined
jobs complete through @completeJob@ via @completeJoined@, which
additionally marks the durable record with the observed fate
(delivered on delivery; failed or canceled when an already-terminal
job is observed), and poll through @pollJob@ via @pollJoined@,
which marks the observed terminal fate the same way.

Join claims (concurrency): after validation, a join takes an
in-progress claim on the persistent id in one STM step — carrying
the claiming table and session identity — before the effectful
replan\/start, then commits only that claim to the live
attachment (or rolls only it back on refusal or interruption).
Claim state is not per context: it lives in the store handle's
claim authority (@storeClaims@, keyed by token, then persistent
id), so every detach context over one open store sees and
arbitrates the same attachments — two contexts cannot both join
one persistent id. Live bindings key by
@('AsyncTableId', 'JobId')@, so two tables never confuse each
other's local job ids, and a retiring table retires only its own
attachments; a context retires only tables it claimed through
(and drops the opaque marks of tables it marked).
Claim transactions touch the authority's @TVar@ (and the
context's own served, refused and marked table sets) only: no
Store IO runs in STM on any path.
-}
module Haskoki.Runtime.Detached
  ( -- * Context
    DetachCtx
  , OpenDeny (..)
  , openDetached
  , detachToken
  , detachSlot
  , sameDetachCtx
    -- * Saveability
  , markJobOpaque
    -- * Recipes (pointer-free pending records)
  , Recipe (..)
  , recipeNameCall
  , recipeNameGenKey
  , recipeNameGenKeyPair
  , encodeRecipe
  , decodeRecipe
  , jobFunctionName
  , nameJobFunction
  , functionCode
  , codeFunction
    -- * Detach (GetID)
  , DetachOutcome (..)
  , detachJob
  , detachCode
    -- * Join (rejoin)
  , JoinRequest (..)
  , JoinOutcome (..)
  , joinPolicyName
  , joinJob
  , joinCode
    -- * Joined completion and cancellation
  , JoinedComplete (..)
  , completeJoined
  , cancelJoined
  , pollJoined
  , retireLiveTable
  , retireLiveTableFor
    -- * Attachments
  , AttachmentView (..)
  , inspectAttachment
  , inspectReverse
  , detachStats
    -- * Join-claim test seam
  , setJoinTestHook
  ) where

import Haskoki.Runtime.Detached.Context
import Haskoki.Runtime.Detached.Saveability
import Haskoki.Runtime.Detached.Recipes
import Haskoki.Runtime.Detached.Detach
import Haskoki.Runtime.Detached.Attachments
import Haskoki.Runtime.Detached.Join
import Haskoki.Runtime.Detached.JoinComplete
import Haskoki.Runtime.Detached.ClaimSeam
