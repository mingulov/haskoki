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
   ('storeReserveJobId': the store-wide mark advances durably
   first) and make the record durable ('storeCommit'). The id is
   returned ONLY after the insert and revocation both succeed.
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
jobs complete through 'completeJob' via 'completeJoined', which
additionally marks the durable record delivered.

Join claims (concurrency): after validation, a join takes an
in-progress claim on the persistent id in one STM step — carrying
the claiming table and session identity — before the effectful
replan\/start, then commits only that claim to the live
attachment (or rolls only it back on refusal or interruption).
Live bindings key by @('AsyncTableId', 'JobId')@, so two tables
sharing this context never confuse each other's local job ids,
and a retiring table retires only its own attachments. Claim
transactions touch attachment @TVar@s only: no Store IO runs in
STM on any path.
-}
module Haskoki.Runtime.Detached
  ( -- * Context
    DetachCtx
  , OpenDeny (..)
  , openDetached
  , detachToken
  , detachSlot
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

import Control.Concurrent.STM
  ( TVar
  , atomically
  , newTVarIO
  , readTVar
  , readTVarIO
  , writeTVar
  )
import Control.Exception (mask, mask_, onException)
import Data.Bits (shiftR, (.&.))
import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import qualified Data.ByteString.Char8 as BC8
import Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map
import Data.Unique (Unique, newUnique)
import Data.Word (Word64, Word8)

import Haskoki.Attribute (AttributeType, AttributeValue)
import Haskoki.Model (Model, SessionState (..), lookupSession)
import Haskoki.Operation.Effect (CryptoEffect (..))
import Haskoki.Operation.KeyManagement
  ( KeyDeny (..)
  , KeyPlan (..)
  , PendingObject (..)
  , PendingWork (..)
  , planGenerateKey
  , planGenerateKeyPair
  )
import Haskoki.Outcome
  ( EffectRequest (..)
  , PlanResult (..)
  , Rejection (..)
  , Reservation (..)
  , ResourceRelease
  , RevisionDep (..)
  )
import Haskoki.Output (maxOutputBytes)
import Haskoki.Registry (MechanismId (..))
import Haskoki.Request
  ( FunctionId (..)
  , OutputIntent (..)
  , OutputRegion (..)
  , Request (..)
  )
import Haskoki.Runtime.Async
  ( AsyncTable
  , AsyncTableId
  , AsyncWork (..)
  , CancelOutcome (..)
  , CompleteOutcome (..)
  , Delivery (..)
  , JobFunction (..)
  , JobRequest (..)
  , JobSnapState (..)
  , JobSnapshot
  , LeaseView (..)
  , StartDeny (..)
  , TerminalState (..)
  , asyncTableId
  , cancelJob
  , completeJob
  , isAsyncSession
  , jobSnapshotCapacity
  , jobSnapshotFunction
  , jobSnapshotState
  , jobSnapshotWork
  , snapshotJob
  , startJob
  , startSeededJob
  , withDetachLease
  )
import Haskoki.Runtime.Lifecycle (Env, envRules, snapshotModel)
import Haskoki.Rules (Rules)
import Haskoki.Session (SessionLogin (..), TokenAuth (..))
import qualified Haskoki.Runtime.Storage as S
import Haskoki.Runtime.Storage
  ( CommitResult (..)
  , JobBody (..)
  , JobExecState (..)
  , JobRecord (..)
  , Reconcile (..)
  , Store (..)
  , StoreDelta (..)
  , StoreError (..)
  , TokenRecord (..)
  , decodeAttrsDoc
  , emptyDelta
  , encodeAttrsDoc
  , reconcileJobsReload
  )
import Haskoki.Transition (planCall)
import Haskoki.Types
  ( Generation (..)
  , JobId (..)
  , ObjectId (..)
  , Pkcs11Version (..)
  , ReturnCode (..)
  , SessionId (..)
  , SlotId (..)
  , TokenId (..)
  )

-- ---------------------------------------------------------------------------
-- Context
-- ---------------------------------------------------------------------------

-- | Detach state bound to one durable store (NOT to one provider
-- generation): the attachment registry, the live-job reverse
-- map keyed by table and job identity, the adapter's opaque
-- marks, and the TEST-ONLY join-transfer hook (a no-op unless
-- a test sets it). Persistent ids are NOT minted here: every
-- detach reserves its id from the store ('storeReserveJobId'),
-- so two contexts on one store never share an id. One context
-- may serve several live tables at once (two FFI contexts on
-- one store box); a restart reopens the store and calls
-- 'openDetached' again; durable records survive, live
-- attachments do not (close drains them first).
data DetachCtx = DetachCtx
  { dcStore :: !Store
  , dcToken :: !TokenId
  , dcSlot :: !SlotId
  , dcAttach :: !(TVar (Map Word64 Attachment))
  , dcReverse :: !(TVar (Map (AsyncTableId, JobId) Word64))
  , dcOpaque :: !(TVar (Map JobId String))
  , dcJoinHook :: !(TVar (IO ()))
  }

-- | Why a detach context failed to open.
data OpenDeny
  = OpenNoToken
  | OpenStore !StoreError
  | OpenJobs !StoreError
  deriving (Eq, Show)

-- | Open detach state over a store homed to one token. The token
-- record must exist (it carries the slot and the generation jobs
-- are stamped with); the stored jobs must load (a corrupt job
-- table refuses the context rather than serving half a view).
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
            attachVar <- newTVarIO Map.empty
            revVar <- newTVarIO Map.empty
            opaqueVar <- newTVarIO Map.empty
            hookVar <- newTVarIO (pure ())
            pure (Right DetachCtx
              { dcStore = store
              , dcToken = tok
              , dcSlot = trSlot trec
              , dcAttach = attachVar
              , dcReverse = revVar
              , dcOpaque = opaqueVar
              , dcJoinHook = hookVar
              })

-- | The home token jobs are stamped with.
detachToken :: DetachCtx -> TokenId
detachToken = dcToken

-- | The home token's slot (target-session compatibility).
detachSlot :: DetachCtx -> SlotId
detachSlot = dcSlot

-- ---------------------------------------------------------------------------
-- Saveability
-- ---------------------------------------------------------------------------

-- | Flag a live job as native-opaque: its workflow holds a live
-- native context (a real adapter's un-checkpointable state) that has
-- no pointer-free record. Detach then reports the permitted typed
-- unsaveable outcome with the job preserved. Marks are consumed by
-- the detach attempt (one mark, one verdict) so a later table
-- generation reusing the job id is never misjudged.
markJobOpaque :: DetachCtx -> JobId -> String -> IO ()
markJobOpaque dc jid reason = atomically $ do
  marks <- readTVar (dcOpaque dc)
  writeTVar (dcOpaque dc) (Map.insert jid reason marks)

-- | Take (consume) a job's opaque mark, if any.
takeOpaque :: DetachCtx -> JobId -> IO (Maybe String)
takeOpaque dc jid = atomically $ do
  marks <- readTVar (dcOpaque dc)
  case Map.lookup jid marks of
    Nothing -> pure Nothing
    Just reason -> do
      writeTVar (dcOpaque dc) (Map.delete jid marks)
      pure (Just reason)

-- ---------------------------------------------------------------------------
-- Recipes
-- ---------------------------------------------------------------------------

-- | A pointer-free pending-job recipe: everything a rejoin needs to
-- replay the submission against the current model. Logical identities
-- only (mechanism ids, byte blobs, logical object ids, attribute
-- documents): no handle, no pointer, no native context.
data Recipe
  = RecipeCall
      { rcFunc :: !JobFunction
      , rcTicks :: !Int
      , rcCapacity :: !Word64
      , rcEffect :: !CryptoEffect
      }
  | RecipeGenKey
      { rkTicks :: !Int
      , rkCapacity :: !Word64
      , rkEffect :: !CryptoEffect
      , rkTemplate :: !(Map AttributeType AttributeValue)
      , rkSessionOwned :: !Bool
      }
  | RecipeGenKeyPair
      { rkpTicks :: !Int
      , rkpCapacity :: !Word64
      , rkpEffect :: !CryptoEffect
      , rkpPub :: !(Map AttributeType AttributeValue)
      , rkpPriv :: !(Map AttributeType AttributeValue)
      , rkpPubOwned :: !Bool
      , rkpPrivOwned :: !Bool
      }
  deriving (Eq, Show)

-- | Pending-recipe names (versioned; unknown names reject on join).
recipeNameCall, recipeNameGenKey, recipeNameGenKeyPair :: String
recipeNameCall = "haskoki-call/v1"
recipeNameGenKey = "haskoki-genkey/v1"
recipeNameGenKeyPair = "haskoki-genkeypair/v1"

-- | Durable function names for 'jrFunction'.
jobFunctionName :: JobFunction -> String
jobFunctionName JobSign = "sign"
jobFunctionName JobDigest = "digest"
jobFunctionName JobGenKey = "genkey"
jobFunctionName JobGenKeyPair = "genkeypair"

-- | Parse a durable function name.
nameJobFunction :: String -> Maybe JobFunction
nameJobFunction "sign" = Just JobSign
nameJobFunction "digest" = Just JobDigest
nameJobFunction "genkey" = Just JobGenKey
nameJobFunction "genkeypair" = Just JobGenKeyPair
nameJobFunction _ = Nothing

-- | Function codes in recipe params (explicit, stable: append-only).
-- They match the FFI poller codes by convention, not by import.
functionCode :: JobFunction -> Word64
functionCode JobSign = 1
functionCode JobDigest = 2
functionCode JobGenKey = 3
functionCode JobGenKeyPair = 4

-- | Parse a recipe function code.
codeFunction :: Word64 -> Maybe JobFunction
codeFunction 1 = Just JobSign
codeFunction 2 = Just JobDigest
codeFunction 3 = Just JobGenKey
codeFunction 4 = Just JobGenKeyPair
codeFunction _ = Nothing

-- | Encode a recipe to its (name, params) record body. Encoding is
-- strict big-endian frames: exact-length decode only.
encodeRecipe :: Recipe -> (String, ByteString)
encodeRecipe r = case r of
  RecipeCall func ticks cap fx ->
    ( recipeNameCall
    , BS.pack [codeByte func]
      <> u32be (fromIntegral ticks)
      <> u64be cap
      <> encodeEffect fx
    )
  RecipeGenKey ticks cap fx tmpl owned ->
    ( recipeNameGenKey
    , u32be (fromIntegral ticks)
      <> u64be cap
      <> encodeEffect fx
      <> BS.pack [if owned then 1 else 0]
      <> u32prefixed (BC8.pack (encodeAttrsDoc tmpl))
    )
  RecipeGenKeyPair ticks cap fx pub priv pubOwned privOwned ->
    ( recipeNameGenKeyPair
    , u32be (fromIntegral ticks)
      <> u64be cap
      <> encodeEffect fx
      <> BS.pack [if pubOwned then 1 else 0, if privOwned then 1 else 0]
      <> u32prefixed (BC8.pack (encodeAttrsDoc pub))
      <> u32prefixed (BC8.pack (encodeAttrsDoc priv))
    )
  where
    codeByte :: JobFunction -> Word8
    codeByte f = fromIntegral (functionCode f)

-- | Strict recipe decode: the name selects the shape, and every
-- frame must consume its bytes exactly. 'Nothing' rejects unknown
-- names, short/trailing bytes, and unknown effect shapes.
decodeRecipe :: String -> ByteString -> Maybe Recipe
decodeRecipe name bs
  | name == recipeNameCall = case BS.uncons bs of
      Just (fb, rest0) -> do
        func <- codeFunction (fromIntegral fb)
        (ticks, rest1) <- takeU32 rest0
        (cap, rest2) <- takeU64 rest1
        (fx, rest3) <- takeEffect rest2
        guardEmpty rest3
        pure RecipeCall
          { rcFunc = func
          , rcTicks = fromIntegral ticks
          , rcCapacity = cap
          , rcEffect = fx
          }
      Nothing -> Nothing
  | name == recipeNameGenKey = do
      (ticks, rest0) <- takeU32 bs
      (cap, rest1) <- takeU64 rest0
      (fx, rest2) <- takeEffect rest1
      (owned, rest3) <- takeFlag rest2
      (doc, rest4) <- takePrefixed rest3
      guardEmpty rest4
      tmpl <- decodeAttrsDoc (BC8.unpack doc)
      pure RecipeGenKey
        { rkTicks = fromIntegral ticks
        , rkCapacity = cap
        , rkEffect = fx
        , rkTemplate = tmpl
        , rkSessionOwned = owned
        }
  | name == recipeNameGenKeyPair = do
      (ticks, rest0) <- takeU32 bs
      (cap, rest1) <- takeU64 rest0
      (fx, rest2) <- takeEffect rest1
      (pubOwned, rest3) <- takeFlag rest2
      (privOwned, rest4) <- takeFlag rest3
      (pubDoc, rest5) <- takePrefixed rest4
      (privDoc, rest6) <- takePrefixed rest5
      guardEmpty rest6
      pub <- decodeAttrsDoc (BC8.unpack pubDoc)
      priv <- decodeAttrsDoc (BC8.unpack privDoc)
      pure RecipeGenKeyPair
        { rkpTicks = fromIntegral ticks
        , rkpCapacity = cap
        , rkpEffect = fx
        , rkpPub = pub
        , rkpPriv = priv
        , rkpPubOwned = pubOwned
        , rkpPrivOwned = privOwned
        }
  | otherwise = Nothing

-- | Effect shapes with a detach recipe: one-shot digest, one-shot
-- sign, and key generation. Every other shape (cipher, verify,
-- message, wrap, derive, KEM, and the digest stream steps, which
-- name live backend contexts) has no async submission path in this
-- facility and no recipe.
encodeEffect :: CryptoEffect -> ByteString
encodeEffect fx = case fx of
  FxDigest (MechanismId m) input ->
    BS.pack [0xD1] <> u64be m <> u32prefixed input
  FxSign (MechanismId m) key params input ->
    BS.pack [0x51] <> u64be m <> encodeKey key
      <> u32prefixed params <> u32prefixed input
  FxGenerateKey (MechanismId m) params input ->
    BS.pack [0x6B] <> u64be m <> u32prefixed params <> u32prefixed input
  _ -> BS.pack [0x00]

-- | Strict effect decode; tag @0x00@ and unknown tags reject.
takeEffect :: ByteString -> Maybe (CryptoEffect, ByteString)
takeEffect bs = case BS.uncons bs of
  Just (0xD1, rest0) -> do
    (m, rest1) <- takeU64 rest0
    (input, rest2) <- takePrefixed rest1
    pure (FxDigest (MechanismId m) input, rest2)
  Just (0x51, rest0) -> do
    (m, rest1) <- takeU64 rest0
    (key, rest2) <- takeKey rest1
    (params, rest3) <- takePrefixed rest2
    (input, rest4) <- takePrefixed rest3
    pure (FxSign (MechanismId m) key params input, rest4)
  Just (0x6B, rest0) -> do
    (m, rest1) <- takeU64 rest0
    (params, rest2) <- takePrefixed rest1
    (input, rest3) <- takePrefixed rest2
    pure (FxGenerateKey (MechanismId m) params input, rest3)
  _ -> Nothing

-- | Optional logical key reference: @0x00@ = none, @0x01@ + u64be id.
encodeKey :: Maybe ObjectId -> ByteString
encodeKey Nothing = BS.pack [0x00]
encodeKey (Just (ObjectId n)) = BS.pack [0x01] <> u64be (fromIntegral n)

-- | Strict key-reference decode.
takeKey :: ByteString -> Maybe (Maybe ObjectId, ByteString)
takeKey bs = case BS.uncons bs of
  Just (0x00, rest) -> Just (Nothing, rest)
  Just (0x01, rest) -> do
    (n, rest') <- takeU64 rest
    if n > fromIntegral (maxBound :: Int)
      then Nothing
      else Just (Just (ObjectId (fromIntegral n)), rest')
  _ -> Nothing

-- | Strict one-byte flag decode (@0x00@\/@0x01@ only).
takeFlag :: ByteString -> Maybe (Bool, ByteString)
takeFlag bs = case BS.uncons bs of
  Just (0x00, rest) -> Just (False, rest)
  Just (0x01, rest) -> Just (True, rest)
  _ -> Nothing

-- | Reject trailing bytes.
guardEmpty :: ByteString -> Maybe ()
guardEmpty rest
  | BS.null rest = Just ()
  | otherwise = Nothing

-- | Big-endian 32-bit frame.
u32be :: Word64 -> ByteString
u32be w = BS.pack
  [ fromIntegral ((w `shiftR` 24) .&. 0xFF)
  , fromIntegral ((w `shiftR` 16) .&. 0xFF)
  , fromIntegral ((w `shiftR` 8) .&. 0xFF)
  , fromIntegral (w .&. 0xFF)
  ]

-- | Big-endian 64-bit frame.
u64be :: Word64 -> ByteString
u64be w = BS.pack
  [ fromIntegral ((w `shiftR` 56) .&. 0xFF)
  , fromIntegral ((w `shiftR` 48) .&. 0xFF)
  , fromIntegral ((w `shiftR` 40) .&. 0xFF)
  , fromIntegral ((w `shiftR` 32) .&. 0xFF)
  , fromIntegral ((w `shiftR` 24) .&. 0xFF)
  , fromIntegral ((w `shiftR` 16) .&. 0xFF)
  , fromIntegral ((w `shiftR` 8) .&. 0xFF)
  , fromIntegral (w .&. 0xFF)
  ]

-- | Length-prefixed blob (@u32BE@ length + bytes).
u32prefixed :: ByteString -> ByteString
u32prefixed bs = u32be (fromIntegral (BS.length bs)) <> bs

-- | Take a big-endian 32-bit frame.
takeU32 :: ByteString -> Maybe (Word64, ByteString)
takeU32 bs
  | BS.length bs < 4 = Nothing
  | otherwise =
      let (b, rest) = BS.splitAt 4 bs
      in Just (foldBE b, rest)

-- | Take a big-endian 64-bit frame.
takeU64 :: ByteString -> Maybe (Word64, ByteString)
takeU64 bs
  | BS.length bs < 8 = Nothing
  | otherwise =
      let (b, rest) = BS.splitAt 8 bs
      in Just (foldBE b, rest)

-- | Take a length-prefixed blob (exact bytes, no overrun).
takePrefixed :: ByteString -> Maybe (ByteString, ByteString)
takePrefixed bs = do
  (n, rest) <- takeU32 bs
  if fromIntegral n > BS.length rest
    then Nothing
    else Just (BS.splitAt (fromIntegral n) rest)

-- | Big-endian fold.
foldBE :: ByteString -> Word64
foldBE = BS.foldl' (\acc b -> acc * 256 + fromIntegral b) 0

-- | Build a recipe from live planned work, or 'Nothing' when the
-- work shape has no async recipe (not every 'CryptoEffect' is an
-- async function of this facility).
recipeFromWork :: JobFunction -> AsyncWork -> Int -> Word64 -> Maybe Recipe
recipeFromWork func work ticks cap = case work of
  WorkCall _ (EffectCrypto fx) -> case fx of
    FxDigest {} -> Just RecipeCall
      { rcFunc = func, rcTicks = ticks, rcCapacity = cap, rcEffect = fx }
    FxSign {} -> Just RecipeCall
      { rcFunc = func, rcTicks = ticks, rcCapacity = cap, rcEffect = fx }
    _ -> Nothing
  WorkKey _ pw fx -> case (pw, fx) of
    (PwGenerateKey k, FxGenerateKey {}) -> Just RecipeGenKey
      { rkTicks = ticks
      , rkCapacity = cap
      , rkEffect = fx
      , rkTemplate = poAttrs k
      , rkSessionOwned = ownedOf k
      }
    (PwGeneratePair pub priv, FxGenerateKey {}) -> Just RecipeGenKeyPair
      { rkpTicks = ticks
      , rkpCapacity = cap
      , rkpEffect = fx
      , rkpPub = poAttrs pub
      , rkpPriv = poAttrs priv
      , rkpPubOwned = ownedOf pub
      , rkpPrivOwned = ownedOf priv
      }
    _ -> Nothing
  where
    ownedOf :: PendingObject -> Bool
    ownedOf k = case poOwner k of
      Nothing -> False
      Just _ -> True

-- ---------------------------------------------------------------------------
-- Detach (GetID)
-- ---------------------------------------------------------------------------

-- | One GetID outcome. Success ('DetachOk') comes only after the
-- record is durable AND the old binding is revoked; every other
-- outcome preserves the old live attachment.
data DetachOutcome
  = DetachOk { doPid :: !Word64 }
  | DetachUnknown
  | DetachWrongFunction { dwExpected :: !JobFunction, dwGot :: !JobFunction }
  | DetachAlready !TerminalState
  | DetachTransient
  | DetachUnsaveable { duReason :: !String }
  | DetachStore !StoreError
  | DetachNoToken
  deriving (Eq, Show)

-- | Source-backed code for a detach outcome.
detachCode :: DetachOutcome -> ReturnCode
detachCode out = case out of
  DetachOk _ -> CKR_OK
  DetachUnknown -> CKR_ARGUMENTS_BAD
  DetachWrongFunction {} -> CKR_ARGUMENTS_BAD
  DetachAlready t -> termCode t
  DetachTransient -> CKR_GENERAL_ERROR
  DetachUnsaveable {} -> CKR_STATE_UNSAVEABLE
  DetachStore _ -> CKR_GENERAL_ERROR
  DetachNoToken -> CKR_TOKEN_NOT_PRESENT

-- | Terminal-state code (mirrors the async export mapping).
termCode :: TerminalState -> ReturnCode
termCode (TermDelivered _) = CKR_OK
termCode TermCanceled = CKR_FUNCTION_CANCELED
termCode (TermFailed code _) = code

-- | Detach a live job (GetID): validate under the attachment-change
-- lease, prepare the pointer-free record, commit it durably, revoke
-- the old binding, and only then return the persistent id. Any
-- failure aborts the lease with the job untouched (the abort is
-- owned by 'withDetachLease', never paired by hand).
detachJob :: DetachCtx -> AsyncTable -> JobId -> JobFunction -> IO DetachOutcome
detachJob dc table jid func =
  withDetachLease table jid $ \mView -> case mView of
    Nothing -> pure DetachUnknown
    Just view -> detachUnder dc jid func view

-- | The detach body under a held lease (aborts on every refusal).
detachUnder :: DetachCtx -> JobId -> JobFunction -> LeaseView -> IO DetachOutcome
detachUnder dc jid func view = do
  mOpaque <- takeOpaque dc jid
  case mOpaque of
    Just reason ->
      pure (DetachUnsaveable reason)
    Nothing -> do
      let snap = lvSnapshot view
      if jobSnapshotFunction snap /= func
        then pure (DetachWrongFunction (jobSnapshotFunction snap) func)
        else case jobSnapshotState snap of
          SnapTerminal t ->
            pure (DetachAlready t)
          SnapRunning ->
            pure DetachTransient
          SnapHeld tag ->
            pure (DetachUnsaveable ("held " ++ tag ++ " has no result record"))
          SnapPending n -> detachPending dc view snap n
          SnapReady bs -> detachReady dc view snap bs

-- | Detach a pending job: recipe record, durable, then revoked.
detachPending :: DetachCtx -> LeaseView -> JobSnapshot -> Int -> IO DetachOutcome
detachPending dc view snap ticks =
  case recipeFromWork
    (jobSnapshotFunction snap)
    (jobSnapshotWork snap)
    ticks
    (jobSnapshotCapacity snap) of
    Nothing ->
      pure (DetachUnsaveable "no detach recipe for this work shape")
    Just recipe -> do
      let (name, params) = encodeRecipe recipe
      commitDetach dc view JobQueued (JobPending name params)

-- | Detach a ready job: prepared-result record (recipe plus owned
-- result bytes, so rejoin can replay the reservation AND seed the
-- held result without re-running the effect), durable, then revoked.
detachReady :: DetachCtx -> LeaseView -> JobSnapshot -> ByteString -> IO DetachOutcome
detachReady dc view snap bs =
  case recipeFromWork
    (jobSnapshotFunction snap)
    (jobSnapshotWork snap)
    0
    (jobSnapshotCapacity snap) of
    Nothing ->
      pure (DetachUnsaveable "no detach recipe for this work shape")
    Just recipe ->
      commitDetach dc view JobReady
        (JobResult CKR_OK (encodeResultBody recipe bs))

-- | Frame a prepared result: recipe name + recipe params + owned
-- result bytes, each length-prefixed. The recipe replays the
-- reservation on rejoin; the bytes seed the held result.
encodeResultBody :: Recipe -> ByteString -> ByteString
encodeResultBody recipe bs =
  let (name, params) = encodeRecipe recipe
  in u32prefixed (BC8.pack name) <> u32prefixed params <> u32prefixed bs

-- | Strict prepared-result decode.
decodeResultBody :: ByteString -> Maybe (Recipe, ByteString)
decodeResultBody body = do
  (nameBs, rest0) <- takePrefixed body
  (params, rest1) <- takePrefixed rest0
  (result, rest2) <- takePrefixed rest1
  guardEmpty rest2
  recipe <- decodeRecipe (BC8.unpack nameBs) params
  pure (recipe, result)

-- | Reserve the persistent id from the store, commit the record
-- durably, and on success revoke the old binding and report the
-- id. Reservation and insertion are two durable commits: a
-- reservation failure reports before anything is written, and a
-- failed insertion leaves a gap in the id sequence (the burned
-- id is never reused, never re-minted). An ambiguous insert
-- reloads and reconciles: present means the record IS durable
-- (revoke and succeed — the caller asked for durability, which
-- held), absent means nothing was written (abort and report).
commitDetach
  :: DetachCtx -> LeaseView -> JobExecState -> JobBody -> IO DetachOutcome
commitDetach dc view execState body = do
  eToks <- storeLoadTokens (dcStore dc)
  case eToks of
    Left err ->
      pure (DetachStore err)
    Right toks -> case [t | (t, _) <- toks, trId t == dcToken dc] of
      [] ->
        pure DetachNoToken
      (trec : _) -> do
        ePid <- storeReserveJobId (dcStore dc)
        case ePid of
          Left err ->
            pure (DetachStore err)
          Right pid -> do
            let rec = JobRecord
                  { jrPersistentId = pid
                  , jrToken = dcToken dc
                  , jrTokenGeneration = trGeneration trec
                  , jrFunction = jobFunctionName (jobSnapshotFunction (lvSnapshot view))
                  , jrState = execState
                  , jrBody = body
                  }
                delta = emptyDelta { sdPutJobs = [rec] }
            res <- storeCommit (dcStore dc) delta
            case res of
              Committed -> do
                lvCommit view
                setIdle dc pid
                pure (DetachOk pid)
              NotCommitted err ->
                pure (DetachStore err)
              CommitUnknown err -> reconcileDetach dc view pid delta err

-- | Reconcile an ambiguous detach commit against a fresh reload.
reconcileDetach
  :: DetachCtx -> LeaseView -> Word64 -> StoreDelta -> StoreError
  -> IO DetachOutcome
reconcileDetach dc view pid delta err = do
  _ <- storeReload (dcStore dc)
  eJobs <- storeLoadJobs (dcStore dc)
  case eJobs of
    Left _ ->
      pure (DetachStore err)
    Right jobs -> case reconcileJobsReload delta jobs of
      ReconciledPresent -> do
        lvCommit view
        setIdle dc pid
        pure (DetachOk pid)
      ReconciledAbsent ->
        pure (DetachStore err)

-- ---------------------------------------------------------------------------
-- Attachments
-- ---------------------------------------------------------------------------

-- | One persistent job's attachment: actively bound to a live job,
-- detached-awaiting-join, or terminally resolved (delivered,
-- canceled, or failed — never rejoinable, never recompleted).
-- The public inspection vocabulary is stable: an in-progress join
-- claim projects to 'AvIdle' (no live binding exists yet — the
-- job is still detached-awaiting-join).
data AttachmentView
  = AvActive !JobId
  | AvIdle
  | AvTerminal !JobExecState
  deriving (Eq, Show)

-- | Internal attachment state: the public view plus the owning
-- table for actives and the in-progress join claim carrying the
-- claiming table and session identity plus a fresh per-attempt
-- token. Actives and claims name their table so two tables
-- sharing this context never resolve each other's local job
-- ids; the attempt token makes commit and rollback exact — a
-- retry's later claim is never mistaken for the older one it
-- follows. (No 'Show': 'Unique' has none, and this state is
-- never rendered.)
data Attachment
  = AttActive !AsyncTableId !JobId
  | AttIdle
  | AttTerminal !JobExecState
  | AttClaim !AsyncTableId !SessionId !Unique
  deriving (Eq)

-- | Project internal attachment state onto the public view.
attView :: Attachment -> AttachmentView
attView (AttActive _ jid) = AvActive jid
attView AttIdle = AvIdle
attView (AttTerminal st) = AvTerminal st
attView (AttClaim _ _ _) = AvIdle

-- | Inspect a persistent job's attachment ('Nothing' = never
-- detached in this context generation — rejoin resolves those
-- against the durable record instead).
inspectAttachment :: DetachCtx -> Word64 -> IO (Maybe AttachmentView)
inspectAttachment dc pid =
  (fmap attView . Map.lookup pid) <$> readTVarIO (dcAttach dc)

-- | Resolve a live job to its persistent id through the reverse
-- map, keyed by the job's own table and job identity. Colliding
-- local job ids on sibling tables resolve independently.
-- Focused test\/diagnostic helper (the map itself stays private).
inspectReverse :: DetachCtx -> AsyncTableId -> JobId -> IO (Maybe Word64)
inspectReverse dc tid jid =
  Map.lookup (tid, jid) <$> readTVarIO (dcReverse dc)

-- | Registry census: @(active, idle, terminal)@ over the public
-- projection (in-progress claims count as idle: still awaiting a
-- live binding).
detachStats :: DetachCtx -> IO (Int, Int, Int)
detachStats dc = do
  attach <- readTVarIO (dcAttach dc)
  let views = map attView (Map.elems attach)
      active = length [() | AvActive _ <- views]
      idle = length [() | AvIdle <- views]
  pure (active, idle, length views - active - idle)

-- | Record a fresh detach as idle (awaiting join).
setIdle :: DetachCtx -> Word64 -> IO ()
setIdle dc pid = atomically $ do
  attach <- readTVar (dcAttach dc)
  writeTVar (dcAttach dc) (Map.insert pid AttIdle attach)

-- | What a join claim replaced: the rollback target. Claims only
-- ever replace an idle entry or an absent one.
data ClaimPrior
  = ClaimHadIdle
  | ClaimHadNone
  deriving (Eq, Show)

-- | Take the in-progress join claim for a persistent id in one
-- STM step, stamping it with the attempt token the caller
-- minted. Succeeds only from idle or absent; anything else
-- (another claim, an active, a terminal) refuses with 'Nothing'
-- and the map untouched. STM touches the attachment map only —
-- never Store IO.
tryClaim
  :: DetachCtx -> Word64 -> AsyncTableId -> SessionId -> Unique
  -> IO (Maybe ClaimPrior)
tryClaim dc pid tid sid uniq = atomically $ do
  attach <- readTVar (dcAttach dc)
  case Map.lookup pid attach of
    Just AttIdle -> do
      writeTVar (dcAttach dc) (Map.insert pid (AttClaim tid sid uniq) attach)
      pure (Just ClaimHadIdle)
    Nothing -> do
      writeTVar (dcAttach dc) (Map.insert pid (AttClaim tid sid uniq) attach)
      pure (Just ClaimHadNone)
    _ -> pure Nothing

-- | Roll back only our own claim attempt, restoring exactly
-- what it replaced (idle or absent). Anything else in the slot —
-- committed, rolled back already, or a retry's later claim — is
-- left untouched, so rollback is safe on every exit path
-- including nested cleanup.
rollbackClaim
  :: DetachCtx -> Word64 -> AsyncTableId -> SessionId -> Unique
  -> ClaimPrior -> IO ()
rollbackClaim dc pid tid sid uniq prior = atomically $ do
  attach <- readTVar (dcAttach dc)
  case Map.lookup pid attach of
    Just (AttClaim tid' sid' uniq')
      | tid' == tid && sid' == sid && uniq' == uniq ->
          let attach' = case prior of
                ClaimHadIdle -> Map.insert pid AttIdle attach
                ClaimHadNone -> Map.delete pid attach
          in writeTVar (dcAttach dc) attach'
    _ -> pure ()

-- | Commit only our own claim attempt to the live attachment,
-- recording the forward entry (owned by our table) and the
-- reverse entry keyed by our table and job identity, in one STM
-- step. Reports 'False' — committing nothing — when the claim
-- is no longer ours (unreachable: claims transition only via
-- their claimant, but the transfer handles it by retiring the
-- fresh job rather than stranding it).
commitClaim
  :: DetachCtx -> Word64 -> AsyncTableId -> SessionId -> Unique
  -> JobId -> IO Bool
commitClaim dc pid tid sid uniq jid = atomically $ do
  attach <- readTVar (dcAttach dc)
  case Map.lookup pid attach of
    Just (AttClaim tid' sid' uniq')
      | tid' == tid && sid' == sid && uniq' == uniq -> do
          writeTVar (dcAttach dc) (Map.insert pid (AttActive tid jid) attach)
          rev <- readTVar (dcReverse dc)
          writeTVar (dcReverse dc) (Map.insert (tid, jid) pid rev)
          pure True
    _ -> pure False

-- ---------------------------------------------------------------------------
-- Join (rejoin)
-- ---------------------------------------------------------------------------

-- | One rejoin request: the persistent id, the caller's function
-- identity, the target session, and the NEW caller storage capacity.
data JoinRequest = JoinRequest
  { jqPid :: !Word64
  , jqFunction :: !JobFunction
  , jqSession :: !SessionId
  , jqCapacity :: !Word64
  } deriving (Eq, Show)

-- | One rejoin outcome. Only 'JoinOk' attaches storage; every other
-- outcome leaves the durable job intact (except the self-healing
-- terminal resolutions, which only confirm what the live table
-- already decided).
data JoinOutcome
  = JoinOk !JobId
  | JoinUnknown
  | JoinWrongFunction { jwExpected :: !JobFunction, jwGot :: !JobFunction }
  | JoinUnknownVersion { juRecipe :: !String }
  | JoinStaleGeneration { jgRecord :: !Generation, jgCurrent :: !Generation }
  | JoinBadSession
  | JoinSessionNotAsync
  | JoinAuthRequired
  | JoinIncompatible { jiReason :: !String }
  | JoinShort { jsNeeded :: !Word64 }
  | JoinAlreadyAttached { jaPolicy :: !String }
  | JoinTerminal !JobExecState
  | JoinDenied !StartDeny
  | JoinStore !StoreError
  deriving (Eq, Show)

-- | The named competing-join policy. PKCS#11 3.2 is silent on
-- repeat\/competing joins; this facility decides explicitly: the
-- FIRST attachment wins and competitors are refused typed, with no
-- duplicated engine work and no resurrection of delivered jobs.
-- Pinned by the @HASKOKI-JOIN-FIRST-WINS@ source-decision test.
joinPolicyName :: String
joinPolicyName = "HASKOKI-JOIN-FIRST-WINS"

-- | Source-backed code for a rejoin outcome.
joinCode :: JoinOutcome -> ReturnCode
joinCode out = case out of
  JoinOk _ -> CKR_PENDING
  JoinUnknown -> CKR_SAVED_STATE_INVALID
  JoinWrongFunction {} -> CKR_ARGUMENTS_BAD
  JoinUnknownVersion {} -> CKR_SAVED_STATE_INVALID
  JoinStaleGeneration {} -> CKR_SAVED_STATE_INVALID
  JoinBadSession -> CKR_SESSION_HANDLE_INVALID
  JoinSessionNotAsync -> CKR_SESSION_ASYNC_NOT_SUPPORTED
  JoinAuthRequired -> CKR_USER_NOT_LOGGED_IN
  JoinIncompatible {} -> CKR_OPERATION_NOT_INITIALIZED
  JoinShort {} -> CKR_BUFFER_TOO_SMALL
  JoinAlreadyAttached {} -> CKR_OPERATION_ACTIVE
  JoinTerminal s -> terminalJoinCode s
  JoinDenied deny -> denyCode deny
  JoinStore _ -> CKR_GENERAL_ERROR

-- | Terminal rejoin codes: delivered is a stale-id use, canceled
-- reports its winner, failed reports generally.
terminalJoinCode :: JobExecState -> ReturnCode
terminalJoinCode JobDelivered = CKR_ARGUMENTS_BAD
terminalJoinCode JobCanceled = CKR_FUNCTION_CANCELED
terminalJoinCode JobFailed = CKR_GENERAL_ERROR
terminalJoinCode JobQueued = CKR_GENERAL_ERROR
terminalJoinCode JobReady = CKR_GENERAL_ERROR

-- | Submit-denial codes (mirrors the async export mapping).
denyCode :: StartDeny -> ReturnCode
denyCode StartSessionNotAsync = CKR_SESSION_ASYNC_NOT_SUPPORTED
denyCode StartOverCapacity = CKR_HOST_MEMORY
denyCode StartBadCapacity = CKR_ARGUMENTS_BAD
denyCode StartIncompatibleWork = CKR_ARGUMENTS_BAD

-- | Rejoin a detached job: validate (id, function, token
-- identity\/generation, version, session, auth, capacity — in that
-- order, before attaching anything), replay the recipe against the
-- current model for a fresh reservation, start the live job (seeded
-- when the record holds a prepared result), record the attachment,
-- and report the new live job. At most one active attachment per
-- persistent job, ever.
joinJob :: DetachCtx -> Env -> AsyncTable -> JoinRequest -> IO JoinOutcome
joinJob dc env table req = do
  eJobs <- storeLoadJobs (dcStore dc)
  case eJobs of
    Left err -> pure (JoinStore err)
    Right jobs -> case [r | r <- jobs, jrPersistentId r == jqPid req] of
      [] -> pure JoinUnknown
      (rec : _) -> joinRecord dc env table req rec

-- | The rejoin body for one durable record.
joinRecord :: DetachCtx -> Env -> AsyncTable -> JoinRequest -> JobRecord -> IO JoinOutcome
joinRecord dc env table req rec = do
  mGate <- attachmentGate dc table (jqPid req) rec
  case mGate of
    Just blocked -> pure blocked
    Nothing -> do
      mFunc <- checkFunction req rec
      case mFunc of
        Just refused -> pure refused
        Nothing -> do
          let recFunc = mustFunction rec
          eTok <- checkToken dc rec
          case eTok of
            Left refused -> pure refused
            Right trec -> joinValidated dc env table req rec recFunc trec

-- | The one-active-attachment gate: terminal stays terminal, live
-- actives and in-progress claims refuse competitors under the
-- named policy, and actives whose live job already died without
-- the wrappers self-heal to the terminal state the table decided.
-- An active owned by another table refuses WITHOUT resolving its
-- local job id in this (wrong) table. 'Nothing' means the id is
-- free to attach. This gate is advisory — the atomic claim in
-- 'joinRecipe' is the arbiter that decides genuinely simultaneous
-- joins.
attachmentGate
  :: DetachCtx -> AsyncTable -> Word64 -> JobRecord -> IO (Maybe JoinOutcome)
attachmentGate dc table pid rec = do
  mAtt <- Map.lookup pid <$> readTVarIO (dcAttach dc)
  case mAtt of
    Just (AttTerminal s) -> pure (Just (JoinTerminal s))
    Just (AttClaim _ _ _) ->
      pure (Just (JoinAlreadyAttached joinPolicyName))
    Just (AttActive owner jid)
      | owner /= asyncTableId table ->
          pure (Just (JoinAlreadyAttached joinPolicyName))
      | otherwise -> do
          mSnap <- snapshotJob table jid
          case mSnap of
            Just snap | snapLive (jobSnapshotState snap) ->
              pure (Just (JoinAlreadyAttached joinPolicyName))
            other -> do
              let st = case other of
                    Just snap -> case jobSnapshotState snap of
                      SnapTerminal t -> execStateOf t
                      _ -> JobCanceled
                    Nothing -> JobCanceled
              _ <- markState dc pid rec st
              pure (Just (JoinTerminal st))
    Just AttIdle -> pure Nothing
    Nothing -> case jrState rec of
      JobDelivered -> healTerminal JobDelivered
      JobCanceled -> healTerminal JobCanceled
      JobFailed -> healTerminal JobFailed
      JobQueued -> pure Nothing
      JobReady -> pure Nothing
  where
    healTerminal :: JobExecState -> IO (Maybe JoinOutcome)
    healTerminal st = do
      setTerminal dc pid st
      pure (Just (JoinTerminal st))

-- | Whether a snapshot state is still live (attachable against).
snapLive :: JobSnapState -> Bool
snapLive (SnapTerminal _) = False
snapLive _ = True

-- | Project a terminal state onto its durable execution state.
execStateOf :: TerminalState -> JobExecState
execStateOf (TermDelivered _) = JobDelivered
execStateOf TermCanceled = JobCanceled
execStateOf (TermFailed _ _) = JobFailed

-- | Check the durable function name against the caller's identity.
checkFunction :: JoinRequest -> JobRecord -> IO (Maybe JoinOutcome)
checkFunction req rec = case nameJobFunction (S.jrFunction rec) of
  Nothing -> pure (Just (JoinUnknownVersion (S.jrFunction rec)))
  Just recFunc
    | recFunc /= jqFunction req ->
        pure (Just (JoinWrongFunction recFunc (jqFunction req)))
    | otherwise -> pure Nothing

-- | The record's function (checked present by 'checkFunction').
mustFunction :: JobRecord -> JobFunction
mustFunction rec = case nameJobFunction (S.jrFunction rec) of
  Just f -> f
  Nothing -> JobDigest

-- | Check token identity/generation against the live token
-- record: the record must name this context's home token (an
-- id homed elsewhere is unknown to this join, even at an equal
-- generation) at the current generation. Runs before session,
-- body, capacity, claim, replan, and start.
checkToken :: DetachCtx -> JobRecord -> IO (Either JoinOutcome TokenRecord)
checkToken dc rec = do
  eToks <- storeLoadTokens (dcStore dc)
  case eToks of
    Left err -> pure (Left (JoinStore err))
    Right toks -> case [t | (t, _) <- toks, trId t == dcToken dc] of
      [] -> pure (Left (JoinStore
        (StoreRevisionConflict "home token is gone")))
      (trec : _)
        | jrToken rec /= dcToken dc ->
            pure (Left JoinUnknown)
        | trGeneration trec /= jrTokenGeneration rec ->
            pure (Left (JoinStaleGeneration
              (jrTokenGeneration rec) (trGeneration trec)))
        | otherwise -> pure (Right trec)

-- | Session, auth, body, capacity, replan, and start — after the
-- attachment gate, function check, and token check all pass.
joinValidated
  :: DetachCtx -> Env -> AsyncTable -> JoinRequest -> JobRecord
  -> JobFunction -> TokenRecord -> IO JoinOutcome
joinValidated dc env table req rec recFunc trec = do
  m <- snapshotModel env
  case lookupSession m (jqSession req) of
    Nothing -> pure JoinBadSession
    Just st
      | ssSlot st /= dcSlot dc -> pure JoinBadSession
      | otherwise -> do
          async <- isAsyncSession table (jqSession req)
          if not async
            then pure JoinSessionNotAsync
            else if authBlocked trec st
              then pure JoinAuthRequired
              else joinBody dc env table req rec recFunc st

-- | Auth rule: a token with an active login admits only
-- authenticated joins; a public session must log in first.
authBlocked :: TokenRecord -> SessionState -> Bool
authBlocked trec st = case taLogin (trAuth trec) of
  Nothing -> False
  Just _ -> ssLogin st == LoginPublic

-- | Decode the record body (recipe or prepared result) and continue.
joinBody
  :: DetachCtx -> Env -> AsyncTable -> JoinRequest -> JobRecord
  -> JobFunction -> SessionState -> IO JoinOutcome
joinBody dc env table req rec recFunc st = case jrBody rec of
  JobPending name params -> case decodeRecipe name params of
    Nothing -> pure (JoinUnknownVersion name)
    Just recipe
      | recipeFunction recipe /= recFunc ->
          pure (JoinWrongFunction recFunc (recipeFunction recipe))
      | otherwise -> joinRecipe dc env table req st recFunc recipe Nothing
  JobResult code body
    | code /= CKR_OK -> do
        _ <- markState dc (jqPid req) rec JobFailed
        pure (JoinTerminal JobFailed)
    | otherwise -> case decodeResultBody body of
        Nothing -> pure (JoinUnknownVersion "haskoki-result/v1")
        Just (recipe, result)
          | recipeFunction recipe /= recFunc ->
              pure (JoinWrongFunction recFunc (recipeFunction recipe))
          | otherwise ->
              joinRecipe dc env table req st recFunc recipe (Just result)

-- | A recipe's function family.
recipeFunction :: Recipe -> JobFunction
recipeFunction (RecipeCall f _ _ _) = f
recipeFunction RecipeGenKey {} = JobGenKey
recipeFunction RecipeGenKeyPair {} = JobGenKeyPair

-- | Capacity check (BEFORE attaching anything), atomic claim,
-- recipe replay against the current model, live start, and claim
-- commit. Only the claim decides between simultaneous joins.
joinRecipe
  :: DetachCtx -> Env -> AsyncTable -> JoinRequest -> SessionState
  -> JobFunction -> Recipe -> Maybe ByteString -> IO JoinOutcome
joinRecipe dc env table req st recFunc recipe mSeed = do
  let need = case mSeed of
        Just result -> fromIntegral (BS.length result)
        Nothing -> recipeCapacity recipe
      cap = jqCapacity req
  if cap == 0 || cap > maxOutputBytes
    then pure (JoinDenied StartBadCapacity)
    else if cap < need
      then pure (JoinShort need)
      else joinClaimed dc env table req st recFunc recipe mSeed

-- | The lost-claim outcome: re-read the winner's state so a
-- concurrently terminalized id reports its terminal fate;
-- anything still live (active or a rival claim, including a
-- claim that rolled back between our attempt and this re-read)
-- reports the existing already-attached refusal.
claimLost :: DetachCtx -> Word64 -> IO JoinOutcome
claimLost dc pid = do
  mAtt <- Map.lookup pid <$> readTVarIO (dcAttach dc)
  case mAtt of
    Just (AttTerminal s) -> pure (JoinTerminal s)
    _ -> pure (JoinAlreadyAttached joinPolicyName)

-- | Claim, replan, start, and attach as one protected
-- transfer. The claim is acquired masked and the rollback
-- handler is installed before anything interruptible runs, so
-- no kill can strand a claim between acquisition and
-- protection. A replan or start refusal rolls back ONLY our
-- claim attempt (the durable job is untouched and a retry may
-- claim again). The start runs masked inside a second mask —
-- its acquisition is one retry-free STM step plus a fresh
-- lock, so it never blocks — and cleanup owns the fresh id
-- before anything runs restored again: from the STM commit
-- through the attachment commit the transfer is either masked
-- or covered by cleanup, so an interruption after the live
-- start but before the commit retires the newly created
-- unregistered job and rolls the claim back — no live job
-- ever strands without an attachment decision and no claim
-- ever sticks. The TEST-ONLY hook runs restored inside that
-- transfer window (a no-op unless a test sets it); the commit
-- itself and the outcome return run masked, so a kill can
-- neither split the commit nor strand cleanup.
joinClaimed
  :: DetachCtx -> Env -> AsyncTable -> JoinRequest -> SessionState
  -> JobFunction -> Recipe -> Maybe ByteString -> IO JoinOutcome
joinClaimed dc env table req st recFunc recipe mSeed =
  let tid = asyncTableId table
      sid = jqSession req
      pid = jqPid req
  in mask $ \restore -> do
    uniq <- newUnique
    mPrior <- tryClaim dc pid tid sid uniq
    case mPrior of
      Nothing -> claimLost dc pid
      Just prior ->
        let rollback = rollbackClaim dc pid tid sid uniq prior
        in flip onException rollback $ restore $ do
          m <- snapshotModel env
          case replanRecipe (envRules env) m st recFunc recipe of
            Left reason -> rollback >> pure (JoinIncompatible reason)
            Right work -> mask $ \restoreStart -> do
              let jr = JobRequest
                    { jrSession = jqSession req
                    , jrFunction = recFunc
                    , jrWork = work
                    , jrTicks = recipeTicks recipe
                    , jrCapacity = jqCapacity req
                    }
              -- Masked: a kill must not land between the STM
              -- insert and cleanup ownership of the fresh id.
              started <- case mSeed of
                Nothing -> startJob table jr
                Just result -> startSeededJob table jr result
              case started of
                Left deny -> rollback >> pure (JoinDenied deny)
                Right jid -> do
                  hook <- readTVarIO (dcJoinHook dc)
                  committed <- (restoreStart hook >> commitClaim dc pid tid sid uniq jid)
                    `onException` mask_ (retireFresh table jid >> rollback)
                  if committed
                    then pure (JoinOk jid)
                    else do
                      mask_ (retireFresh table jid >> rollback)
                      pure (JoinAlreadyAttached joinPolicyName)
  where
    -- | Retire a freshly started but unregistered job: it has no
    -- attachment and no owner yet, so cancel it outright. Fresh
    -- and table-local: no other thread can hold its lease, so the
    -- masked cancel cannot block.
    retireFresh :: AsyncTable -> JobId -> IO ()
    retireFresh tbl jid = do
      _ <- cancelJob tbl jid
      pure ()

-- | A recipe's original attached capacity (the conservative pending
-- need: the replayed result may run up to its first bound).
recipeCapacity :: Recipe -> Word64
recipeCapacity (RecipeCall _ _ cap _) = cap
recipeCapacity (RecipeGenKey _ cap _ _ _) = cap
recipeCapacity (RecipeGenKeyPair _ cap _ _ _ _ _) = cap

-- | A recipe's remaining schedule.
recipeTicks :: Recipe -> Int
recipeTicks (RecipeCall _ ticks _ _) = ticks
recipeTicks (RecipeGenKey ticks _ _ _ _) = ticks
recipeTicks (RecipeGenKeyPair ticks _ _ _ _ _ _) = ticks

-- | Replay a recipe against the current model: re-plan the original
-- submission for a FRESH reservation and refuse anything that does
-- not reproduce the detached effect exactly (mechanism, key,
-- params, input). Session-owned template objects remap to the
-- joining session; old handles are never trusted.
replanRecipe :: Rules -> Model -> SessionState -> JobFunction -> Recipe -> Either String AsyncWork
replanRecipe rules m st recFunc recipe = case recipe of
  RecipeCall func _ _ fx
    | func == recFunc -> case (recFunc, callInput fx) of
        (JobSign, Just input) -> replanCall F_Sign input fx
        (JobDigest, Just input) -> replanCall F_Digest input fx
        _ -> Left "recipe/function incoherence"
    | otherwise -> Left "recipe/function incoherence"
  RecipeGenKey _ _ fx tmpl owned
    | recFunc == JobGenKey -> case fx of
        FxGenerateKey mech params _ -> case planGenerateKey rules m st mech params (Map.toList tmpl) of
          KeyEffect (PwGenerateKey k) fx'
            | fx' == fx -> Right (WorkKey (joinReservation st)
                (PwGenerateKey k { poOwner = joinOwner owned }) fx')
            | otherwise -> Left "key plan does not reproduce the detached effect"
          KeyEffect _ _ -> Left "key plan shape drift"
          KeyDenied d -> Left ("key plan denied: " ++ kdReason d)
          KeyImmediate _ -> Left "key plan is immediate"
        _ -> Left "recipe/function incoherence"
    | otherwise -> Left "recipe/function incoherence"
  RecipeGenKeyPair _ _ fx pub priv pubOwned privOwned
    | recFunc == JobGenKeyPair -> case fx of
        FxGenerateKey mech _ _ ->
          case planGenerateKeyPair rules m st mech (Map.toList pub) (Map.toList priv) of
            KeyEffect (PwGeneratePair pubK privK) fx'
              | fx' == fx -> Right (WorkKey (joinReservation st)
                  (PwGeneratePair pubK { poOwner = joinOwner pubOwned }
                    privK { poOwner = joinOwner privOwned }) fx')
              | otherwise -> Left "key plan does not reproduce the detached effect"
            KeyEffect _ _ -> Left "key plan shape drift"
            KeyDenied d -> Left ("key plan denied: " ++ kdReason d)
            KeyImmediate _ -> Left "key plan is immediate"
        _ -> Left "recipe/function incoherence"
    | otherwise -> Left "recipe/function incoherence"
  where
    sid = ssId st
    -- | The replayable input of a call effect (digest\/sign only).
    callInput :: CryptoEffect -> Maybe ByteString
    callInput (FxDigest _ input) = Just input
    callInput (FxSign _ _ _ input) = Just input
    callInput _ = Nothing
    -- | Re-plan one call submission; the planned effect must equal
    -- the detached one exactly.
    replanCall :: FunctionId -> ByteString -> CryptoEffect -> Either String AsyncWork
    replanCall fid input fx =
      let req = Request Pkcs11_3_2 fid (Just sid) Nothing input
            [RegionBytes "async-join" (IntentBuffer maxOutputBytes)]
      in case planCall rules m req of
        Execute res (EffectCrypto fx')
          | fx' == fx -> Right (WorkCall res (EffectCrypto fx'))
          | otherwise -> Left "session operation does not match the detached recipe"
        Reject rej -> Left ("plan rejected: " ++ show (rejCode rej))
        Immediate _ -> Left "plan is immediate (operation is not pending on this session)"
    -- | Remap a session-owned template object to the joining
    -- session; token objects keep no owner.
    joinOwner :: Bool -> Maybe SessionId
    joinOwner True = Just sid
    joinOwner False = Nothing

-- | A fresh reservation pinning the joining session's revisions.
joinReservation :: SessionState -> Reservation
joinReservation st = Reservation "async-join"
  [DepSession (ssId st) (ssRevision st) (ssGeneration st)] Nothing Nothing

-- ---------------------------------------------------------------------------
-- Joined completion and cancellation
-- ---------------------------------------------------------------------------

-- | One joined completion: the async outcome plus the durable-mark
-- error, if the delivered mark failed to commit. The delivery itself
-- already happened (the job lease decided); a mark error means the
-- durable record lags the live table, and the in-memory attachment
-- is terminal regardless so this generation never rejoins.
data JoinedComplete = JoinedComplete
  { jcOutcome :: !CompleteOutcome
  , jcMarkError :: !(Maybe StoreError)
  } deriving (Eq, Show)

-- | Complete a possibly-joined job through the job lease, marking
-- the durable record delivered on delivery. Non-joined jobs pass
-- through untouched (mark clean).
completeJoined
  :: DetachCtx -> Env -> AsyncTable -> JobFunction -> JobId -> Delivery
  -> (ResourceRelease -> IO ()) -> IO JoinedComplete
completeJoined dc env table func jid del release = do
  out <- completeJob env table func jid del release
  case out of
    CompleteDelivered _ -> do
      merr <- markResolved dc table jid JobDelivered
      pure (JoinedComplete out merr)
    CompleteAlready (TermDelivered _) -> do
      merr <- markResolved dc table jid JobDelivered
      pure (JoinedComplete out merr)
    _ -> pure (JoinedComplete out Nothing)

-- | Cancel a possibly-joined job, marking the durable record with
-- the terminal fate. Non-joined jobs pass through untouched.
cancelJoined :: DetachCtx -> AsyncTable -> JobId -> IO (CancelOutcome, Maybe StoreError)
cancelJoined dc table jid = do
  out <- cancelJob table jid
  case out of
    CancelOk -> do
      merr <- markResolved dc table jid JobCanceled
      pure (out, merr)
    CancelAlready t -> do
      merr <- markResolved dc table jid (execStateOf t)
      pure (out, merr)
    CancelUnknown -> pure (out, Nothing)

-- | Mark a joined live job's durable record resolved, resolving
-- through the reverse map by the job's own table and job
-- identity. Unknown (never joined) jobs report clean with no
-- write; a colliding local job id on a sibling table resolves to
-- that table's own record, never this one.
markResolved :: DetachCtx -> AsyncTable -> JobId -> JobExecState -> IO (Maybe StoreError)
markResolved dc table jid st = do
  rev <- readTVarIO (dcReverse dc)
  case Map.lookup (asyncTableId table, jid) rev of
    Nothing -> pure Nothing
    Just pid -> do
      eJobs <- storeLoadJobs (dcStore dc)
      case eJobs of
        Left err -> do
          setTerminal dc pid st
          pure (Just err)
        Right jobs -> case [r | r <- jobs, jrPersistentId r == pid] of
          [] -> do
            setTerminal dc pid st
            pure (Just (StoreRevisionConflict "durable job is gone"))
          (rec : _) -> markState dc pid rec st

-- | Retire the live table (provider close): every active attachment
-- resolves canceled, durably and in memory, and the adapter's opaque
-- marks clear (a new table generation starts unflagged). Returns one
-- entry per retired attachment with its mark error, if any. This is
-- whole-context retirement for single-table owners (the Standard
-- adapter, whose instance owns exactly one table and one detach
-- context); callers sharing one context across tables retire with
-- 'retireLiveTableFor' so a closing table never cancels a sibling's
-- attachments.
retireLiveTable :: DetachCtx -> IO [(Word64, Maybe StoreError)]
retireLiveTable dc = do
  atomically (writeTVar (dcOpaque dc) Map.empty)
  retireMatching dc Nothing

-- | Retire one live table's attachments (context close on a shared
-- store): only actives owned by the retiring table identity
-- resolve canceled, durably and in memory; sibling tables'
-- attachments — active, idle, terminal, or mid-claim — are
-- untouched. Returns one entry per retired attachment with its
-- mark error, if any. Opaque marks are NOT cleared here: they are
-- keyed by bare job id (table-blind), so a scoped retire cannot
-- attribute them — clearing would drop a sibling table's live
-- marks. A join racing close may still commit after retirement
-- (close does not coordinate with in-flight claims); full
-- close\/join admission coordination is follow-up work under
-- async retirement accounting, which can refuse the commit
-- through the existing 'False' arm.
retireLiveTableFor
  :: DetachCtx -> AsyncTableId -> IO [(Word64, Maybe StoreError)]
retireLiveTableFor dc tid = retireMatching dc (Just tid)

-- | Shared retire worker: 'Nothing' retires every active (whole
-- context), @'Just' tid@ retires only that table's actives. Claims
-- are never retired (their claimant still owns the transfer).
retireMatching
  :: DetachCtx -> Maybe AsyncTableId -> IO [(Word64, Maybe StoreError)]
retireMatching dc mTid = do
  attach <- readTVarIO (dcAttach dc)
  let actives =
        [ pid
        | (pid, AttActive owner _) <- Map.toList attach
        , case mTid of
            Nothing -> True
            Just tid -> owner == tid
        ]
  eJobs <- storeLoadJobs (dcStore dc)
  case eJobs of
    Left err -> do
      mapM_ (\pid -> setTerminal dc pid JobCanceled) actives
      pure [(pid, Just err) | pid <- actives]
    Right jobs -> mapM (retireOne jobs) actives
  where
    retireOne :: [JobRecord] -> Word64 -> IO (Word64, Maybe StoreError)
    retireOne jobs pid =
      case [r | r <- jobs, jrPersistentId r == pid] of
        [] -> do
          setTerminal dc pid JobCanceled
          pure (pid, Just (StoreRevisionConflict "durable job is gone"))
        (rec : _) -> do
          merr <- markState dc pid rec JobCanceled
          pure (pid, merr)

-- | Write one durable terminal state and record it in memory. The
-- in-memory mark lands even when the commit fails, so this context
-- generation never rejoins a resolved job; the returned error tells
-- the caller the durable record lags.
markState :: DetachCtx -> Word64 -> JobRecord -> JobExecState -> IO (Maybe StoreError)
markState dc pid rec st = do
  let rec' = rec { jrState = st }
      delta = emptyDelta { sdPutJobs = [rec'] }
  res <- storeCommit (dcStore dc) delta
  setTerminal dc pid st
  case res of
    Committed -> pure Nothing
    NotCommitted err -> pure (Just err)
    CommitUnknown err -> do
      _ <- storeReload (dcStore dc)
      eJobs <- storeLoadJobs (dcStore dc)
      case eJobs of
        Right jobs | reconcileJobsReload delta jobs == ReconciledPresent ->
          pure Nothing
        _ -> pure (Just err)

-- | Record a terminal attachment.
setTerminal :: DetachCtx -> Word64 -> JobExecState -> IO ()
setTerminal dc pid st = atomically $ do
  attach <- readTVar (dcAttach dc)
  writeTVar (dcAttach dc) (Map.insert pid (AttTerminal st) attach)

-- ---------------------------------------------------------------------------
-- Join-claim test seam
-- ---------------------------------------------------------------------------

-- | TEST-ONLY: set the action a claimed join runs between its live
-- start and its attachment commit — the interruption window the
-- transfer must survive. Production leaves the default no-op, so
-- normal joins pay one @TVar@ read and no hook call. Tests set a
-- rendezvous here to land a kill deterministically inside the
-- window, then assert the claim rolled back and the fresh
-- unregistered job retired.
setJoinTestHook :: DetachCtx -> IO () -> IO ()
setJoinTestHook dc hook = atomically (writeTVar (dcJoinHook dc) hook)
