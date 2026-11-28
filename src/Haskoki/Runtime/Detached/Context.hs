{- | Detached context handles.
-}
module Haskoki.Runtime.Detached.Context
  ( DetachCtx
  , OpenDeny (..)
  , openDetached
  , detachToken
  , detachSlot
  , sameDetachCtx
  , readClaims
  , writeClaims
  , lookupAttachment
  , putAttachment
  , dcStore
  , dcToken
  , dcSlot
  , dcClaims
  , dcServed
  , dcRefused
  , dcMarked
  , dcJoinHook
  ) where

import Control.Concurrent.STM
  ( STM
  , TVar
  , atomically
  , newTVarIO
  )
import qualified Data.Map.Strict as Map
import Data.Set (Set)
import qualified Data.Set as Set
import Data.Word (Word64)
import Haskoki.Runtime.Async (AsyncTableId)
import Haskoki.Runtime.Attach
  ( Attachment (..)
  , ClaimAuthority
  , TokenClaims (..)
  , readTokenClaims
  , writeTokenClaims
  )
import Haskoki.Runtime.Storage
  ( Store (..)
  , StoreError (..)
  , TokenRecord (..)
  )
import Haskoki.Types
  ( SlotId (..)
  , TokenId (..)
  )

-- ---------------------------------------------------------------------------
-- Context
-- ---------------------------------------------------------------------------

-- | A detach view over one open store handle and one home token
-- (NOT bound to one provider generation). The attachment
-- registry, the live-job reverse map keyed by table and job
-- identity, and the retired-table set are NOT held here: they
-- live in the store handle's claim authority ('storeClaims'),
-- shared by every context over that handle (and every
-- record-update wrapper of it), so two contexts over one store
-- arbitrate one persistent id through one claim. The context
-- itself holds only the set of tables it claimed through (the
-- scope of its retirement: a context never retires a table it
-- did not serve), the context-local refused set (tables retired
-- through this context before it ever claimed through them: its
-- own later claims through them are refused, while the shared
-- authority and sibling contexts are untouched), the set of
-- tables it marked opaque through (retiring one of them drops
-- that table's marks, and only its marks), and the TEST-ONLY
-- join-transfer hook (a no-op unless a test sets it).
-- Persistent ids are NOT minted here: every detach reserves its
-- id from the store ('storeReserveJobId'), so two contexts on
-- one store never share an id. One context may serve several
-- live tables at once (two FFI contexts on one store box); a
-- restart reopens the store and calls 'openDetached' again;
-- durable records survive, live attachments do not (a reopened
-- handle has a fresh, empty authority, so close must retire
-- them first). A table that retires records its identity: its
-- in-progress claims roll back, and its late claims and commits
-- are refused, so no join publishes a live binding after its
-- table closed.
-- Boundaries: closing the store while attachments are live is
-- unsupported (reopen after the owner is fully retired; nothing is
-- exactly-once across process death); a stale active claim held by
-- another context that never retires is not reclaimed; and a
-- table retired through a context that neither served nor marked
-- it keeps its opaque marks until a context that did retires it
-- (or the store handle closes).
data DetachCtx = DetachCtx
  { dcStore :: !Store
  , dcToken :: !TokenId
  , dcSlot :: !SlotId
  , dcClaims :: !ClaimAuthority
  , dcServed :: !(TVar (Set AsyncTableId))
  , dcRefused :: !(TVar (Set AsyncTableId))
  , dcMarked :: !(TVar (Set AsyncTableId))
  , dcJoinHook :: !(TVar (IO ()))
  }

-- | Why a detach context failed to open.
data OpenDeny
  = OpenNoToken
  | OpenStore !StoreError
  | OpenJobs !StoreError
  deriving (Eq, Show)

-- | Open a detach view over a store homed to one token. The token
-- record must exist (it carries the slot and the generation jobs
-- are stamped with); the stored jobs must load (a corrupt job
-- table refuses the context rather than serving half a view).
-- The view binds the store handle's claim authority: contexts
-- opened over one handle share every attachment and claim.
-- The store owns id allocation ('storeReserveJobId'), so ids
-- are never recycled — not across restarts, not across detach
-- failures, not across sibling contexts (allocation gaps are
-- fine).
openDetached :: Store -> TokenId -> IO (Either OpenDeny DetachCtx)
openDetached store tok = do
  eToks <- storeLoadTokens store
  case eToks of
    Left err -> pure (Left (OpenStore err))
    Right toks -> case [t | (t, _) <- toks, trId t == tok] of
      [] -> pure (Left OpenNoToken)
      (trec : _) -> do
        eJobs <- storeLoadJobs store
        case eJobs of
          Left err -> pure (Left (OpenJobs err))
          Right _ -> do
            servedVar <- newTVarIO Set.empty
            refusedVar <- newTVarIO Set.empty
            markedVar <- newTVarIO Set.empty
            hookVar <- newTVarIO (pure ())
            pure (Right DetachCtx
              { dcStore = store
              , dcToken = tok
              , dcSlot = trSlot trec
              , dcClaims = storeClaims store
              , dcServed = servedVar
              , dcRefused = refusedVar
              , dcMarked = markedVar
              , dcJoinHook = hookVar
              })

-- | The home token jobs are stamped with.
detachToken :: DetachCtx -> TokenId
detachToken = dcToken

-- | The home token's slot (target-session compatibility).
detachSlot :: DetachCtx -> SlotId
detachSlot = dcSlot

-- | Detach-context identity: whether two handles borrow the same context.
sameDetachCtx :: DetachCtx -> DetachCtx -> Bool
sameDetachCtx a b =
  dcServed a == dcServed b
    && dcRefused a == dcRefused b
    && dcMarked a == dcMarked b
    && dcJoinHook a == dcJoinHook b

-- | This context's token's claim state on the shared authority.
readClaims :: DetachCtx -> STM TokenClaims
readClaims dc = readTokenClaims (dcClaims dc) (dcToken dc)

-- | Replace this context's token's claim state.
writeClaims :: DetachCtx -> TokenClaims -> STM ()
writeClaims dc = writeTokenClaims (dcClaims dc) (dcToken dc)

-- | One persistent id's current attachment on the shared authority.
lookupAttachment :: DetachCtx -> Word64 -> IO (Maybe Attachment)
lookupAttachment dc pid =
  Map.lookup pid . tcAttach <$> atomically (readClaims dc)

-- | Record one attachment state for a persistent id.
putAttachment :: DetachCtx -> Word64 -> Attachment -> IO ()
putAttachment dc pid att = atomically $ do
  tc <- readClaims dc
  writeClaims dc tc { tcAttach = Map.insert pid att (tcAttach tc) }
