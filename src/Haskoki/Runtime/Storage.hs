{- | Narrow persistent-store contract.

The process-level store owns token metadata, credentials, token
objects, and detached-job records. Sessions and active
operations stay transient. Memory and SQLite backends implement the
same 'Store' record; the @haskoki-storage-tests@ suite runs the
identical contract cases against both.

Canonical record encoding (design 08, section 3):

* Every stored document is versioned JSON with @format_version = 1@.
  Unknown format versions are rejected, never decoded speculatively.
* Bytes ride as base64 strings; full-width unsigned quantities
  (ids, classes, enums, revisions) ride as fixed 16-hex-character
  strings, never bare JSON numbers and never blindly cast through
  the SQLite signed-integer domain.
* The only bare JSON number in any document is @format_version@;
  the only JSON booleans are semantic flags. Object keys sort
  ascending, so rendering is byte-canonical for a given value.
* Documents carry logical state only: no handle, pointer, callback
  address, @EVP_*@ context, or struct image may appear (pinned by
  fixture scans in the storage suite).

The contract layers capabilities: open\/load\/commit\/close\/inspect,
the commit protocol (fault injection, quarantine, reload),
adversarial validation, detached-job records, and token reset.

Each open 'Store' handle owns one detached-job claim authority
('storeClaims'); a reopened handle starts empty, so closing a store
while detached attachments are live is a documented boundary (see
docs\/operations-notes.md).
-}
module Haskoki.Runtime.Storage
  ( -- * Limits
    StoreLimits (..)
  , defaultLimits
    -- * Records
  , TokenRecord (..)
  , CredentialRecord (..)
  , ObjectRecord (..)
  , ObjectPut (..)
  , JobRecord (..)
  , JobExecState (..)
  , JobBody (..)
    -- * Deltas and results
  , StoreDelta (..)
  , emptyDelta
  , StoreDeltaClass (..)
  , deltaClasses
  , scrubTokenAuth
  , scrubDeltaAuth
  , CommitResult (..)
  , StoreError (..)
    -- * Commit protocol
  , FaultPoint (..)
  , FaultInjector (..)
  , noFaults
  , scriptedFaults
  , withMaskHook
  , withResultHook
  , StoreStats (..)
  , zeroStats
  , PublicationAdvice (..)
  , decidePublication
  , Reconcile (..)
  , reconcileReload
  , reconcileJobsReload
  , reconcileCredentialsReload
  , jobIdCounterKey
  , nextJobReservation
  , coverDeletedJobIds
    -- * Pre-commit validation
  , LoadedState (..)
  , checkLimits
  , checkExpectedRevisions
  , checkTokenRefs
  , checkSlotUnique
  , knownMaterialEncodings
    -- * Durable token identity
  , DesiredToken (..)
  , IdentityRefusal (..)
  , ReconcilePlan (..)
  , reconcileIdentities
  , renderIdentityRefusal
  , tokensWithoutCredentials
  , SlotMoveRefusal (..)
  , planSlotMoves
  , renderSlotMoveRefusal
    -- * Store contract
  , Store (..)
  , ClaimAuthority
  , claimCensus
  , markCensus
  , StoredDoc (..)
  , HandleState (..)
  , storeClosed
    -- * Model projection
  , objectToRecord
  , reserveRestoredIds
    -- * Canonical encoding
  , recordFormatVersion
  , encodeTokenRecord
  , decodeTokenRecord
  , encodeCredentialRecord
  , decodeCredentialRecord
  , encodeObjectRecord
  , decodeObjectRecord
  , encodeAttrsDoc
  , decodeAttrsDoc
  , encodeJobRecord
  , decodeJobRecord
  , execStateName
  , nameExecState
  , encodeReturnCode
  , decodeReturnCode
  , docTopKeys
  , encodeBase64
  , decodeBase64
  , encodeHex16
  , decodeHex16
  , encodeHexWord64
  , decodeHexWord64
  ) where

import Data.Bits (shiftL, shiftR, (.&.))
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Char (chr, isHexDigit, ord)
import Data.List (nub, sort, sortOn)
import Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map
import qualified Data.Set as Set
import Data.Word (Word8, Word64)

import Control.Exception (Exception)
import Control.Monad (guard)
import Data.IORef (IORef, atomicModifyIORef', newIORef)
import Data.Maybe (listToMaybe)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE

import Haskoki.Attribute (AttributeType (..), AttributeValue (..))
import Haskoki.Model (Model (..), ObjectState (..))
import Haskoki.Runtime.Attach (ClaimAuthority, JobExecState (..), claimCensus, markCensus)
import Haskoki.Session
  ( TokenAuth (..)
  , clearTransientAuth
  , tokenAuthNew
  )
import Haskoki.Types
  ( Generation (..)
  , ObjectId (..)
  , ReturnCode (..)
  , Revision (..)
  , SlotId (..)
  , TokenId (..)
  , redactShown
  )

-- ---------------------------------------------------------------------------
-- Limits
-- ---------------------------------------------------------------------------

-- | Pre-commit bounds (enforced; the opener has always
-- carried them, so its shape is stable).
data StoreLimits = StoreLimits
  { limMaxObjects :: !Int
  , limMaxTotalBytes :: !Int
  , limMaxRecordBytes :: !Int
  , limMaxJobs :: !Int
  } deriving (Eq, Show)

-- | Demonstration bounds: 4096 objects, 16 MiB total, 256 KiB per
-- record, 256 detached jobs.
defaultLimits :: StoreLimits
defaultLimits = StoreLimits
  { limMaxObjects = 4096
  , limMaxTotalBytes = 16777216
  , limMaxRecordBytes = 262144
  , limMaxJobs = 256
  }

-- ---------------------------------------------------------------------------
-- Records
-- ---------------------------------------------------------------------------

-- | One persisted token: stable identity, slot assignment,
-- generation, label, and the DURABLE authentication half (retry
-- counters and lock flags). The transient half (active login,
-- principal, epoch) is scrubbed at the commit boundary and never
-- encoded, so reopening never restores an authenticated session.
data TokenRecord = TokenRecord
  { trId :: !TokenId
  , trSlot :: !SlotId
  , trGeneration :: !Generation
  , trLabel :: !String
  , trAuth :: !TokenAuth
  } deriving (Eq, Show)

-- | One persisted token credential: the provisioned SO PIN
-- (always present once the row exists) and the provisioned user
-- PIN ('Nothing' = uninitialized: no user login can succeed
-- until the SO sets one). At most one row per token. A stored
-- token gets its row when it is seeded (the catalog PINs, in the
-- seed transaction), and from then on the row is its only
-- credential: config PIN edits never replace it, and a stored
-- token without a row serves no login (a legacy store).
-- The row is owned by its token like objects and jobs: dropping
-- the token removes it. A token reset keeps it (the durable
-- credential always wins), unlike the reset token's objects and
-- jobs.
data CredentialRecord = CredentialRecord
  { crToken :: !TokenId
  , crSoPin :: !ByteString
  , crUserPin :: !(Maybe ByteString)
  } deriving (Eq)

-- | 'Show' redacts both PINs: each renders its kind and length
-- only ('redactShown'); the home token renders normally.
-- Explicit inspection pattern-matches the exported record
-- (never 'Show').
instance Show CredentialRecord where
  show c = "CredentialRecord {crToken = " ++ show (crToken c)
    ++ ", crSoPin = " ++ redactShown "pin" (BS.length (crSoPin c))
    ++ ", crUserPin = " ++ showPin (crUserPin c) ++ "}"
    where
      showPin Nothing = "Nothing"
      showPin (Just bs) = "Just " ++ redactShown "pin" (BS.length bs)

-- | One persisted token object: stable logical id, home token,
-- class\/key-type keys, the canonical attribute document, typed
-- key-material encoding, and revision. Session objects are never
-- stored; external handles are never stored (they are minted by the
-- live model on reload).
data ObjectRecord = ObjectRecord
  { orId :: !ObjectId
  , orToken :: !TokenId
  , orClass :: !Word64
  , orKeyType :: !(Maybe Word64)
  , orAttrs :: !(Map AttributeType AttributeValue)
  , orMaterialEncoding :: !String
  , orMaterial :: !(Maybe ByteString)
  , orRevision :: !Revision
  } deriving (Eq)

-- | 'Show' redacts the material blob: 'orMaterial' renders
-- its kind and length only ('redactShown'); the attribute map
-- renders through the redacted 'AttributeValue' instance. All
-- other fields render normally. Explicit inspection
-- pattern-matches the exported record (never 'Show').
instance Show ObjectRecord where
  show o = "ObjectRecord {orId = " ++ show (orId o)
    ++ ", orToken = " ++ show (orToken o)
    ++ ", orClass = " ++ show (orClass o)
    ++ ", orKeyType = " ++ show (orKeyType o)
    ++ ", orAttrs = " ++ show (orAttrs o)
    ++ ", orMaterialEncoding = " ++ show (orMaterialEncoding o)
    ++ ", orMaterial = " ++ showMat (orMaterial o)
    ++ ", orRevision = " ++ show (orRevision o) ++ "}"
    where
      showMat Nothing = "Nothing"
      showMat (Just bs) = "Just " ++ redactShown "key" (BS.length bs)

-- | One object write: the expected current revision ('Nothing' =
-- the object must not exist yet) plus the replacement record.
data ObjectPut = ObjectPut
  { opExpected :: !(Maybe Revision)
  , opRecord :: !ObjectRecord
  } deriving (Eq, Show)

-- | The durable job body: either a deterministic pending recipe
-- (a named recipe plus owned parameter bytes, replayable after
-- restart) or a fully prepared owned result (a verdict plus owned
-- result bytes, deliverable without any live context). Real opaque
-- native contexts are never serialized here: an unsaveable job is
-- an explicit outcome at the lifecycle layer, not a memory image
-- described as resumable state.
data JobBody
  = JobPending { jbRecipe :: !String, jbParams :: !ByteString }
  | JobResult { jbCode :: !ReturnCode, jbBytes :: !ByteString }
  deriving (Eq)

-- | 'Show' redacts job bytes: recipe parameters may embed
-- templates and prepared results may embed a ready-but-unfinished
-- keygen answer, so both byte fields render their kind and length
-- only ('redactShown'). Recipe names and return codes render
-- normally. Explicit inspection pattern-matches the exported
-- constructors (never 'Show').
instance Show JobBody where
  show (JobPending name params) =
    "JobPending {jbRecipe = " ++ show name
      ++ ", jbParams = " ++ redactShown "params" (BS.length params) ++ "}"
  show (JobResult code bs) =
    "JobResult {jbCode = " ++ show code
      ++ ", jbBytes = " ++ redactShown "result" (BS.length bs) ++ "}"

-- | One persisted detached job: a stable module\/store-wide
-- persistent id (never a recycled row number), the home token and
-- the token generation the id is valid under (reset kills old
-- ids), the function name, the execution state, and the body.
data JobRecord = JobRecord
  { jrPersistentId :: !Word64
  , jrToken :: !TokenId
  , jrTokenGeneration :: !Generation
  , jrFunction :: !String
  , jrState :: !JobExecState
  , jrBody :: !JobBody
  } deriving (Eq, Show)

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
-- 'storeResetToken' is the generation-guarded
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
--   'storeReload' or a reopen (fresh handle) clears it. A
--   connection-wide quarantine (SQLite: a write transaction left
--   open by a failed ROLLBACK) refuses every load, commit, reset
--   and reservation; only a 'storeReload' whose retried ROLLBACK
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
  deriving (Eq, Show)

-- | Store failures throw as exceptions on the paths with no
-- 'Either' channel (a failed 'storeClose' reports by
-- throwing the failure instead of returning silently).
instance Exception StoreError

-- ---------------------------------------------------------------------------
-- Commit protocol
-- ---------------------------------------------------------------------------

-- | Fault-injection points in the commit path, plus the close
-- path ('FaultClose'). A fired 'FaultClose' simulates a failed
-- close: ownership and guards are retained, the handle stops
-- serving new operations, the close reports the failure by
-- throwing, and a later close retries for real. Both backends
-- honor it identically (one shot, like every other point).
data FaultPoint
  = FaultBeforeCommit
  | FaultAmbiguousCommit
  | FaultVerifyReload
  | FaultAfterCommit
  | FaultFullDisk
  | FaultClose
  deriving (Eq, Show)

-- | One-shot fault injector plus masked-region observation hooks.
-- 'fiFire' reports 'True' once per scripted occurrence of the
-- probed point. The hooks are test observability: 'fiOnMasked'
-- fires on entry to the masked commit region, 'fiOnResult' fires
-- with the determined result while still masked. Both default to
-- no-ops; neither affects the commit outcome.
data FaultInjector = FaultInjector
  { fiFire :: FaultPoint -> IO Bool
  , fiOnMasked :: IO ()
  , fiOnResult :: CommitResult -> IO ()
  }

-- | The inert injector: no faults, no hooks.
noFaults :: FaultInjector
noFaults = FaultInjector
  { fiFire = \_ -> pure False
  , fiOnMasked = pure ()
  , fiOnResult = \_ -> pure ()
  }

-- | An injector that fires once per listed script entry, in any
-- probe order (each probe consumes at most one matching entry).
scriptedFaults :: [FaultPoint] -> IO FaultInjector
scriptedFaults script = do
  v <- newIORef script
  pure FaultInjector
    { fiFire = firing v
    , fiOnMasked = pure ()
    , fiOnResult = \_ -> pure ()
    }
  where
    firing :: IORef [FaultPoint] -> FaultPoint -> IO Bool
    firing v p = atomicModifyIORef' v (\s -> case removeFirst p s of
      (fired, s') -> (s', fired))

-- | Remove the first matching entry, reporting whether one fired.
removeFirst :: Eq a => a -> [a] -> (Bool, [a])
removeFirst _ [] = (False, [])
removeFirst x (y : ys)
  | x == y = (True, ys)
  | otherwise = let (fired, rest) = removeFirst x ys in (fired, y : rest)

-- | Attach a masked-entry hook to an injector.
withMaskHook :: IO () -> FaultInjector -> FaultInjector
withMaskHook hook inj = inj { fiOnMasked = hook }

-- | Attach a result hook to an injector. The hook fires inside the
-- masked region with the determined 'CommitResult'.
withResultHook :: (CommitResult -> IO ()) -> FaultInjector -> FaultInjector
withResultHook hook inj = inj { fiOnResult = hook }

-- | Per-handle commit counters: known durable commits,
-- verification reloads run, and quarantine events (per token).
data StoreStats = StoreStats
  { ssCommits :: !Int
  , ssVerifyReloads :: !Int
  , ssQuarantines :: !Int
  } deriving (Eq, Show)

-- | Zeroed counters.
zeroStats :: StoreStats
zeroStats = StoreStats
  { ssCommits = 0
  , ssVerifyReloads = 0
  , ssQuarantines = 0
  }

-- | What the runtime must do with its in-memory delta after a
-- commit: publish it, drop it, or reload the authoritative state
-- and reconcile before deciding.
data PublicationAdvice
  = PublishDelta
  | PublishNothing
  | ReloadFirst
  deriving (Eq, Show)

-- | The runtime publication rule, pure: only 'Committed'
-- publishes; 'CommitUnknown' must reload first and must never
-- blindly reissue the operation.
decidePublication :: CommitResult -> PublicationAdvice
decidePublication result = case result of
  Committed -> PublishDelta
  NotCommitted _ -> PublishNothing
  CommitUnknown _ -> ReloadFirst

-- | Reload reconciliation: does the authoritative state contain
-- exactly the committed delta (every put present with equal
-- content, every drop absent)?
data Reconcile
  = ReconciledPresent
  | ReconciledAbsent
  deriving (Eq, Show)

-- | Compare a delta against reloaded state with full-record
-- equality (pure; shared by the backends' ambiguous-commit
-- verification and the caller's post-'CommitUnknown' decision).
-- Token puts compare scrubbed ('scrubDeltaAuth' at the commit
-- boundary, and the projection scrubs before issuing), so an
-- auth-only write reconciles present exactly when it landed.
reconcileReload :: StoreDelta -> [(TokenRecord, [ObjectRecord])] -> Reconcile
reconcileReload delta loaded
  | all tokenPutPresent (sdPutTokens delta)
  , all tokenDropAbsent (sdDropTokens delta)
  , all objectPutPresent (sdPutObjects delta)
  , all objectDropAbsent (sdDropObjects delta) = ReconciledPresent
  | otherwise = ReconciledAbsent
  where
    toks = [(trId t, t) | (t, _) <- loaded]
    objs = [(orId o, o) | (_, os) <- loaded, o <- os]
    tokenPutPresent t = lookup (trId t) toks == Just t
    tokenDropAbsent tid = tid `notElem` map fst toks
    objectPutPresent p = lookup (orId (opRecord p)) objs == Just (opRecord p)
    objectDropAbsent oid = oid `notElem` map fst objs

-- | Compare a delta's jobs against reloaded jobs with full-record
-- equality. Backends AND this with 'reconcileReload' so an
-- ambiguous commit verifies only when every table agrees.
reconcileJobsReload :: StoreDelta -> [JobRecord] -> Reconcile
reconcileJobsReload delta jobs
  | all jobPutPresent (sdPutJobs delta)
  , all jobDropAbsent (sdDropJobs delta) = ReconciledPresent
  | otherwise = ReconciledAbsent
  where
    byId = [(jrPersistentId j, j) | j <- jobs]
    jobPutPresent j = lookup (jrPersistentId j) byId == Just j
    jobDropAbsent pid = pid `notElem` map fst byId

-- | Compare a delta's credentials against reloaded credentials
-- with full-record equality (the job-table precedent: backends
-- AND this with 'reconcileReload' and 'reconcileJobsReload').
-- A credential put naming a token dropped in the same delta
-- never reaches reconciliation: 'checkTokenRefs' refuses it at
-- validation, since the projected token set has no such token.
reconcileCredentialsReload :: StoreDelta -> [CredentialRecord] -> Reconcile
reconcileCredentialsReload delta creds
  | all credPutPresent (sdPutCredentials delta)
  , all credDropAbsent (sdDropCredentials delta) = ReconciledPresent
  | otherwise = ReconciledAbsent
  where
    byToken = [(crToken c, c) | c <- creds]
    credPutPresent c = lookup (crToken c) byToken == Just c
    credDropAbsent tid = tid `notElem` map fst byToken

-- | The metadata key carrying the store-wide
-- next-persistent-job-id high-water mark (16-hex-character
-- 'Word64', starting at 1). The key predates durable
-- reservation (schema version 1 seeds it), so adopting it
-- changes no row format and no schema version.
jobIdCounterKey :: String
jobIdCounterKey = "next_persistent_job_id"

-- | Pure reservation step shared by both backends: given the
-- stored counter value ('Nothing' = the key is absent, as on a
-- fresh memory world or a hand-built database) and the
-- persistent ids currently stored, compute the id to hand out
-- plus the counter value to persist. The mark reconciles with
-- the stored maximum ('maxJob + 1') without ever lowering, a
-- corrupt counter fails closed, and exhaustion refuses before
-- the 'Word64' domain can wrap — so every increment below is
-- guarded and no arithmetic here can overflow.
nextJobReservation :: Maybe String -> [Word64] -> Either StoreError (Word64, String)
nextJobReservation mStored pids = do
  stored <- case mStored of
    Nothing -> Right 1
    Just s -> case decodeHexWord64 s of
      Just w -> Right w
      Nothing -> Left (StoreCorrupt
        ("corrupt " ++ jobIdCounterKey ++ " counter: " ++ show s))
  need <- case pids of
    [] -> Right 1
    _ -> let m = maximum pids
         in if m == maxBound
              then Left exhausted
              else Right (m + 1)
  let next = max stored need
  if next == maxBound
    then Left exhausted
    else Right (next, encodeHexWord64 (next + 1))
  where
    exhausted = StoreFull
      "persistent job id space exhausted (refusing before Word64 wrap)"

-- | Advance a job-id high-water mark to cover pids whose
-- records are being deleted (reset, token drop, or explicit
-- job drop): the mark becomes at least every deleted pid + 1,
-- saturating at 'maxBound' (which reservations already refuse)
-- so no arithmetic here can wrap. Backends fold this over the
-- doomed set inside the deleting commit, so a legacy store
-- whose mark never advanced still cannot re-mint a deleted id
-- after the evidence is gone. An empty doomed set leaves the
-- mark untouched. A corrupt mark stays corrupt — and
-- reservations keep failing closed — until an explicit,
-- authoritative repair re-establishes it: deleted rows alone
-- cannot reconstruct the full issued history, so deriving a
-- small counter from them could re-mint an id whose row is
-- already gone. 'Nothing' means the key stays absent.
coverDeletedJobIds :: Maybe String -> [Word64] -> Maybe String
coverDeletedJobIds mStored doomed
  | null doomed = mStored
  | otherwise = case base of
      Just b -> Just (encodeHexWord64 (foldr max b (map saturate doomed)))
      Nothing -> mStored
  where
    base = case mStored of
      Nothing -> Just 1
      Just s -> decodeHexWord64 s
    saturate p = if p == maxBound then maxBound else p + 1

-- ---------------------------------------------------------------------------
-- Store contract
-- ---------------------------------------------------------------------------

-- ---------------------------------------------------------------------------
-- Pre-commit validation (pure)
-- ---------------------------------------------------------------------------

-- | Loaded state for validation: tokens with their objects,
-- the detached jobs, plus the provisioned credentials.
data LoadedState = LoadedState
  { lsTokens :: ![(TokenRecord, [ObjectRecord])]
  , lsJobs :: ![JobRecord]
  , lsCredentials :: ![CredentialRecord]
  } deriving (Eq, Show)

-- | Project a delta against current state and enforce the
-- pre-commit bounds: per-record bytes on every put, then the
-- projected object and job counts, then the projected total
-- stored bytes (exact UTF-8 sizes of the canonical documents).
-- The projection drops explicitly removed records and cascades
-- token drops onto the owned objects, jobs, and credentials,
-- matching what both backends commit. The first hit wins;
-- 'Nothing' commits clean.
checkLimits :: StoreLimits -> StoreDelta -> LoadedState -> Maybe StoreError
checkLimits lim delta current
  | Just over <- firstOverRecord =
      Just (StoreLimit ("record exceeds per-record limit (" ++ show (limMaxRecordBytes lim) ++ " bytes): " ++ over))
  | Map.size objMap' > limMaxObjects lim =
      Just (StoreLimit ("object count exceeds limit (" ++ show (limMaxObjects lim) ++ ")"))
  | Map.size jobMap' > limMaxJobs lim =
      Just (StoreLimit ("job count exceeds limit (" ++ show (limMaxJobs lim) ++ ")"))
  | totalBytes > limMaxTotalBytes lim =
      Just (StoreLimit ("total stored bytes exceed limit (" ++ show (limMaxTotalBytes lim) ++ ")"))
  | otherwise = Nothing
  where
    putToks = sdPutTokens delta
    putObjs = map opRecord (sdPutObjects delta)
    putJobs = sdPutJobs delta
    putCreds = sdPutCredentials delta
    sized =
      [("token " ++ show (trId t), utf8Bytes (encodeTokenRecord t)) | t <- putToks]
        ++ [("object " ++ show (orId o), utf8Bytes (encodeObjectRecord o)) | o <- putObjs]
        ++ [("job " ++ show (jrPersistentId j), utf8Bytes (encodeJobRecord j)) | j <- putJobs]
        ++ [("credential " ++ show (crToken c), utf8Bytes (encodeCredentialRecord c)) | c <- putCreds]
    firstOverRecord = listToMaybe [d | (d, n) <- sized, n > limMaxRecordBytes lim]
    tokMap = foldr Map.delete
      (Map.fromList [(trId t, t) | (t, _) <- lsTokens current]) (sdDropTokens delta)
    tokMap' = foldr (\t m -> Map.insert (trId t) t m) tokMap putToks
    objMap = foldr Map.delete
      (Map.fromList [(orId o, o) | (_, os) <- lsTokens current, o <- os]) (sdDropObjects delta)
    objKept = Map.filter (\o -> orToken o `notElem` sdDropTokens delta) objMap
    objMap' = foldr (\o m -> Map.insert (orId o) o m) objKept putObjs
    jobMap = foldr Map.delete
      (Map.fromList [(jrPersistentId j, j) | j <- lsJobs current]) (sdDropJobs delta)
    jobKept = Map.filter (\j -> jrToken j `notElem` sdDropTokens delta) jobMap
    jobMap' = foldr (\j m -> Map.insert (jrPersistentId j) j m) jobKept putJobs
    credMap = foldr Map.delete
      (Map.fromList [(crToken c, c) | c <- lsCredentials current]) (sdDropCredentials delta)
    credKept = Map.filter (\c -> crToken c `notElem` sdDropTokens delta) credMap
    credMap' = foldr (\c m -> Map.insert (crToken c) c m) credKept putCreds
    totalBytes =
      sum [utf8Bytes (encodeTokenRecord t) | t <- Map.elems tokMap']
        + sum [utf8Bytes (encodeObjectRecord o) | o <- Map.elems objMap']
        + sum [utf8Bytes (encodeJobRecord j) | j <- Map.elems jobMap']
        + sum [utf8Bytes (encodeCredentialRecord c) | c <- Map.elems credMap']

-- | Exact UTF-8 byte size of canonical document text.
utf8Bytes :: String -> Int
utf8Bytes = BS.length . TE.encodeUtf8 . T.pack

-- | Enforce expected object revisions: an unguarded put ('Nothing')
-- is an upsert; a guarded put requires the object to exist at
-- exactly the expected revision. The first conflict wins;
-- 'Nothing' applies clean.
checkExpectedRevisions :: (ObjectId -> Maybe Revision) -> StoreDelta -> Maybe StoreError
checkExpectedRevisions current delta = go (sdPutObjects delta)
  where
    go [] = Nothing
    go (ObjectPut Nothing _ : rest) = go rest
    go (ObjectPut (Just want) rec : rest) = case current (orId rec) of
      Nothing -> Just (StoreRevisionConflict
        ("expected " ++ show want ++ " but object " ++ show (orId rec) ++ " is missing"))
      Just have
        | have == want -> go rest
        | otherwise -> Just (StoreRevisionConflict
            ("object " ++ show (orId rec) ++ ": expected " ++ show want ++ " but found " ++ show have))

-- | The material encodings this format version understands.
-- Anything else in a stored row is corruption, never silently
-- preserved.
knownMaterialEncodings :: [String]
knownMaterialEncodings = ["none", "attr-value/v1"]

-- | Enforce token references: every object put must name a token
-- that exists in the projected token set (current minus drops
-- plus the delta's own puts), every job put must name a
-- token at exactly the job's generation, and every credential
-- put must name a projected token (a credential for a missing
-- or same-delta-dropped token refuses: no orphan credentials).
-- The first conflict wins; 'Nothing' applies clean. Reset kills
-- old ids through this check: a job stamped with a superseded
-- generation refuses.
checkTokenRefs :: [(TokenId, TokenRecord)] -> StoreDelta -> Maybe StoreError
checkTokenRefs currentToks delta =
  case [o | o <- map opRecord (sdPutObjects delta), orToken o `Map.notMember` projected] of
    (o : _) -> Just (StoreRevisionConflict
      ("object " ++ show (orId o) ++ " references missing token " ++ show (orToken o)))
    [] -> case [c | c <- sdPutCredentials delta, crToken c `Map.notMember` projected] of
      (c : _) -> Just (StoreRevisionConflict
        ("credential references missing token " ++ show (crToken c)))
      [] -> goJobs (sdPutJobs delta)
  where
    projected = foldr (\t m -> Map.insert (trId t) t m)
      (foldr Map.delete (Map.fromList currentToks) (sdDropTokens delta))
      (sdPutTokens delta)
    goJobs [] = Nothing
    goJobs (j : rest) = case Map.lookup (jrToken j) projected of
      Nothing -> Just (StoreRevisionConflict
        ("job " ++ show (jrPersistentId j) ++ " references missing token " ++ show (jrToken j)))
      Just t
        | trGeneration t == jrTokenGeneration j -> goJobs rest
        | otherwise -> Just (StoreRevisionConflict
            ("job " ++ show (jrPersistentId j) ++ " names token generation "
              ++ show (jrTokenGeneration j) ++ " but token " ++ show (jrToken j)
              ++ " is at " ++ show (trGeneration t)))

-- | Enforce one token per slot (mirrors the SQLite
-- @UNIQUE(slot_key)@ in backends without the constraint).
checkSlotUnique :: [(TokenId, TokenRecord)] -> StoreDelta -> Maybe StoreError
checkSlotUnique currentToks delta =
  let projected = foldr (\t m -> Map.insert (trId t) t m)
        (foldr Map.delete (Map.fromList currentToks) (sdDropTokens delta))
        (sdPutTokens delta)
      slots = sort (map trSlot (Map.elems projected))
  in if nub slots == slots
    then Nothing
    else Just (StoreRevisionConflict "two tokens share one slot")

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
-- ('renderIdentityRefusal'). There are no automatic migrations in
-- this phase: a reorder, an insertion that shifts slots, a
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
-- * The SQLite schema keeps @schema_version = 1@ with no
--   migration: a wrong version refuses at open without writing
--   a byte, as before.
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
      ++ "pinned token_ids value) and reopen; removal-by-config is not "
      ++ "supported in this phase."
  RefuseLabelChanged tid slot durableLabel desiredLabel ->
    "stored token " ++ show tid ++ " at " ++ show slot ++ " is labeled \""
      ++ durableLabel ++ "\" but the catalog says \"" ++ desiredLabel
      ++ "\": the durable label is authoritative and labels never "
      ++ "identify a token, so the catalog is not renamed silently. "
      ++ "Restore the durable label in [tokens] and reopen; relabeling "
      ++ "is not supported in this phase."
  RefuseSlotChanged tid durableSlot desiredSlot label ->
    "stored token " ++ show tid ++ " (\"" ++ label ++ "\") sits at "
      ++ show durableSlot ++ " but the catalog seats it at " ++ show desiredSlot
      ++ ": slot assignment is separate from token identity and never "
      ++ "moves automatically, so the wrong credential cannot silently "
      ++ "reach this token's objects. Either restore the durable slot "
      ++ "in [tokens], or move the token explicitly (planSlotMoves, "
      ++ "committed before reopening) and then reopen with the new layout."

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

-- ---------------------------------------------------------------------------
-- Model projection
-- ---------------------------------------------------------------------------

-- | Project a live token object onto its storable record. The class
-- and key-type keys derive from the stored attributes (absent or
-- wrongly shaped = 0\/absent, matching the model's lenient reads);
-- the material columns carry the @AttrValue@ payload bytes when
-- present, else the explicit @none@ encoding with no blob.
objectToRecord :: TokenId -> ObjectState -> ObjectRecord
objectToRecord tok ost =
  let attrs = osAttrs ost
  in ObjectRecord
    { orId = osId ost
    , orToken = tok
    , orClass = classOf attrs
    , orKeyType = keyTypeOf attrs
    , orAttrs = attrs
    , orMaterialEncoding = materialEncodingOf attrs
    , orMaterial = materialOf attrs
    , orRevision = osRevision ost
    }
  where
    classOf :: Map AttributeType AttributeValue -> Word64
    classOf attrs = case Map.lookup AttrClass attrs of
      Just (ValULong n) -> n
      _ -> 0
    keyTypeOf :: Map AttributeType AttributeValue -> Maybe Word64
    keyTypeOf attrs = case Map.lookup AttrKeyType attrs of
      Just (ValULong n) -> Just n
      _ -> Nothing
    materialEncodingOf :: Map AttributeType AttributeValue -> String
    materialEncodingOf attrs = case Map.lookup AttrValue attrs of
      Just (ValBytes _) -> "attr-value/v1"
      _ -> "none"
    materialOf :: Map AttributeType AttributeValue -> Maybe ByteString
    materialOf attrs = case Map.lookup AttrValue attrs of
      Just (ValBytes bs) -> Just bs
      _ -> Nothing

-- | Reserve the restored id space in a fresh model: after re-seating
-- persisted objects under their stable 'ObjectId's, advance
-- @mNextObject@ past the restored maximum so later allocations
-- never collide with it. (Handle counters advance on bind; object
-- counters do not advance on explicit-id creates.)
reserveRestoredIds :: [ObjectId] -> Model -> Model
reserveRestoredIds oids m =
  m { mNextObject = max (mNextObject m) (restoredMax + 1) }
  where
    restoredMax = maximum (0 : [n | ObjectId n <- oids])

-- ---------------------------------------------------------------------------
-- Canonical encoding
-- ---------------------------------------------------------------------------

-- | The record format version. Every document carries it; anything
-- else is rejected on decode.
recordFormatVersion :: Int
recordFormatVersion = 1

-- | Lowest-level JSON value subset used by stored documents.
data Json
  = JObject ![(String, Json)]
  | JString !String
  | JBool !Bool
  | JNumber !Integer
  | JNull
  deriving (Eq, Show)

-- | Render canonical JSON: object keys ascending, minimal escapes,
-- no whitespace. Decoding ('parseJson') accepts exactly this shape
-- plus insignificant whitespace.
renderJson :: Json -> String
renderJson v = case v of
  JObject kvs -> "{" ++ join "," [renderString k ++ ":" ++ renderJson j | (k, j) <- sortOn fst kvs] ++ "}"
  JString s -> renderString s
  JBool True -> "true"
  JBool False -> "false"
  JNumber n -> show n
  JNull -> "null"
  where
    join :: String -> [String] -> String
    join _ [] = ""
    join _ [x] = x
    join sep (x : xs) = x ++ sep ++ join sep xs

-- | Render a JSON string with minimal escapes.
renderString :: String -> String
renderString s = '"' : concatMap esc s ++ "\""
  where
    esc :: Char -> String
    esc '"' = "\\\""
    esc '\\' = "\\\\"
    esc '\b' = "\\b"
    esc '\f' = "\\f"
    esc '\n' = "\\n"
    esc '\r' = "\\r"
    esc '\t' = "\\t"
    esc c
      | ord c < 0x20 = "\\u" ++ hex4 (ord c)
      | otherwise = [c]
    hex4 :: Int -> String
    hex4 n =
      [ hexDigit ((n `shiftR` 12) .&. 0xF)
      , hexDigit ((n `shiftR` 8) .&. 0xF)
      , hexDigit ((n `shiftR` 4) .&. 0xF)
      , hexDigit (n .&. 0xF)
      ]

-- | Strict subset parser: objects, strings (with @\\u@ escapes),
-- true\/false\/null, and non-negative integers. Rejects trailing
-- input, unknown escapes, and malformed numbers.
parseJson :: String -> Maybe Json
parseJson s = case parseValue (skipWs s) of
  Just (v, rest)
    | all isWs rest -> Just v
  _ -> Nothing
  where
    isWs c = c == ' ' || c == '\t' || c == '\n' || c == '\r'
    skipWs = dropWhile isWs
    parseValue :: String -> Maybe (Json, String)
    parseValue [] = Nothing
    parseValue (c : cs) = case c of
      '{' -> parseObject (skipWs cs)
      '"' -> parseStringBody cs
      't' -> parseLit "true" (JBool True) (c : cs)
      'f' -> parseLit "false" (JBool False) (c : cs)
      'n' -> parseLit "null" JNull (c : cs)
      _
        | c >= '0' && c <= '9' -> parseNumber (c : cs)
        | otherwise -> Nothing
    parseLit :: String -> Json -> String -> Maybe (Json, String)
    parseLit lit v s0 =
      let (pre, rest) = splitAt (length lit) s0
      in if pre == lit then Just (v, rest) else Nothing
    parseNumber :: String -> Maybe (Json, String)
    parseNumber s0 =
      let (digits, rest) = span (\c -> c >= '0' && c <= '9') s0
      in if null digits then Nothing else Just (JNumber (read digits), rest)
    parseObject :: String -> Maybe (Json, String)
    parseObject ('}' : rest) = Just (JObject [], rest)
    parseObject s0 = do
      ('"' : kcs) <- Just s0
      (JString k, afterK) <- parseStringBody kcs
      (':' : vcs) <- Just (skipWs afterK)
      (v, afterV) <- parseValue (skipWs vcs)
      parseMore [(k, v)] (skipWs afterV)
      where
        parseMore :: [(String, Json)] -> String -> Maybe (Json, String)
        parseMore acc (',' : rest) = do
          ('"' : kcs) <- Just (skipWs rest)
          (JString k, afterK) <- parseStringBody kcs
          (':' : vcs) <- Just (skipWs afterK)
          (v, afterV) <- parseValue (skipWs vcs)
          parseMore (acc ++ [(k, v)]) (skipWs afterV)
        parseMore acc ('}' : rest) = Just (JObject acc, rest)
        parseMore _ _ = Nothing
    -- | Parse the body of a string (after the opening quote).
    parseStringBody :: String -> Maybe (Json, String)
    parseStringBody = go []
      where
        go :: String -> String -> Maybe (Json, String)
        go _ [] = Nothing
        go acc ('"' : rest) = Just (JString (reverse acc), rest)
        go acc ('\\' : e : rest) = case e of
          '"' -> go ('"' : acc) rest
          '\\' -> go ('\\' : acc) rest
          '/' -> go ('/' : acc) rest
          'b' -> go ('\b' : acc) rest
          'f' -> go ('\f' : acc) rest
          'n' -> go ('\n' : acc) rest
          'r' -> go ('\r' : acc) rest
          't' -> go ('\t' : acc) rest
          'u' -> case rest of
            [a, b, c, d] -> hexChar a b c d >>= \n -> go (chr n : acc) []
            (a : b : c : d : more) -> hexChar a b c d >>= \n ->
              if n >= 0xD800 && n <= 0xDBFF
                then case more of
                  ('\\' : 'u' : a2 : b2 : c2 : d2 : more2) ->
                    hexChar a2 b2 c2 d2 >>= \m ->
                      if m >= 0xDC00 && m <= 0xDFFF
                        then go (chr (0x10000 + (n - 0xD800) * 0x400 + (m - 0xDC00)) : acc) more2
                        else Nothing
                  _ -> Nothing
                else go (chr n : acc) more
            _ -> Nothing
          _ -> Nothing
        go acc (c : rest) = go (c : acc) rest
        hexChar :: Char -> Char -> Char -> Char -> Maybe Int
        hexChar a b c d
          | all isHexDigit [a, b, c, d] =
              Just (hexVal a * 4096 + hexVal b * 256 + hexVal c * 16 + hexVal d)
          | otherwise = Nothing

-- | Field accessors over a decoded object body.
lookupField :: String -> [(String, Json)] -> Maybe Json
lookupField k kvs = lookup k kvs

asString :: Json -> Maybe String
asString (JString s) = Just s
asString _ = Nothing

asBool :: Json -> Maybe Bool
asBool (JBool b) = Just b
asBool _ = Nothing

asObject :: Json -> Maybe [(String, Json)]
asObject (JObject kvs) = Just kvs
asObject _ = Nothing

-- | The sorted top-level keys of a canonical document ('[]' when
-- the bytes do not parse). The storage suite pins exact key sets.
docTopKeys :: String -> [String]
docTopKeys s = case parseJson s of
  Just (JObject kvs) -> map fst kvs
  _ -> []

-- ---------------------------------------------------------------------------
-- Base64 (RFC 4648, strict)
-- ---------------------------------------------------------------------------

-- | Base64 alphabet.
b64Alphabet :: String
b64Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

-- | Encode bytes as base64 text.
encodeBase64 :: ByteString -> String
encodeBase64 bs = go (BS.unpack bs)
  where
    go :: [Word8] -> String
    go [] = []
    go [a] =
      let n = (fromIntegral a :: Int) `shiftL` 16
      in [at (n `shiftR` 18), at ((n `shiftR` 12) .&. 0x3F), '=', '=']
    go [a, b] =
      let n = ((fromIntegral a :: Int) `shiftL` 16) + ((fromIntegral b :: Int) `shiftL` 8)
      in [at (n `shiftR` 18), at ((n `shiftR` 12) .&. 0x3F), at ((n `shiftR` 6) .&. 0x3F), '=']
    go (a : b : c : rest) =
      let n = ((fromIntegral a :: Int) `shiftL` 16)
            + ((fromIntegral b :: Int) `shiftL` 8)
            + (fromIntegral c :: Int)
      in [ at (n `shiftR` 18)
         , at ((n `shiftR` 12) .&. 0x3F)
         , at ((n `shiftR` 6) .&. 0x3F)
         , at (n .&. 0x3F)
         ] ++ go rest
    at :: Int -> Char
    at i = b64Alphabet !! i

-- | Strict base64 decode: canonical padding only, no whitespace,
-- no trailing characters.
decodeBase64 :: String -> Maybe ByteString
decodeBase64 s
  | length s `mod` 4 /= 0 = Nothing
  | otherwise = BS.pack <$> go s
  where
    go :: String -> Maybe [Word8]
    go [] = Just []
    go [a, b, '=', '='] = do
      x <- val a
      y <- val b
      if y .&. 0xF /= 0
        then Nothing
        else Just [fromIntegral ((x `shiftL` 2) + (y `shiftR` 4))]
    go [a, b, c, '='] = do
      x <- val a
      y <- val b
      z <- val c
      if z .&. 0x3 /= 0
        then Nothing
        else Just
          [ fromIntegral ((x `shiftL` 2) + (y `shiftR` 4))
          , fromIntegral (((y .&. 0xF) `shiftL` 4) + (z `shiftR` 2))
          ]
    go (a : b : c : d : rest) = do
      x <- val a
      y <- val b
      z <- val c
      w <- val d
      more <- go rest
      Just
        ( fromIntegral ((x `shiftL` 2) + (y `shiftR` 4))
        : fromIntegral (((y .&. 0xF) `shiftL` 4) + (z `shiftR` 2))
        : fromIntegral (((z .&. 0x3) `shiftL` 6) + w)
        : more
        )
    go _ = Nothing
    val :: Char -> Maybe Int
    val c = lookup c (zip b64Alphabet [0 ..])

-- ---------------------------------------------------------------------------
-- Fixed hex for full-width unsigned quantities
-- ---------------------------------------------------------------------------

-- | One hex digit, lowercase.
hexDigit :: Int -> Char
hexDigit n
  | n >= 0 && n <= 9 = chr (ord '0' + n)
  | otherwise = chr (ord 'a' + n - 10)

-- | One hex digit value (either case on decode).
hexVal :: Char -> Int
hexVal c
  | c >= '0' && c <= '9' = ord c - ord '0'
  | c >= 'a' && c <= 'f' = ord c - ord 'a' + 10
  | otherwise = ord c - ord 'A' + 10

-- | Encode a non-negative 'Int' as 16 lowercase hex characters
-- (8-byte big-endian). Negative inputs are rejected by the caller
-- contract; encoding masks to the low 64 bits regardless.
encodeHex16 :: Int -> String
encodeHex16 n =
  [ hexDigit (fromIntegral ((w `shiftR` s) .&. 0xF)) | s <- [60, 56 .. 0] ]
  where
    w :: Word64
    w = fromIntegral n

-- | Decode exactly 16 hex characters into a non-negative 'Int';
-- anything else (wrong length, non-hex, out of 'Int' range) fails.
decodeHex16 :: String -> Maybe Int
decodeHex16 s
  | length s == 16
  , all isHexDigit s =
      let w = foldl (\acc c -> acc * 16 + fromIntegral (hexVal c)) 0 s :: Word64
      in if w > fromIntegral (maxBound :: Int) then Nothing else Just (fromIntegral w)
  | otherwise = Nothing

-- ---------------------------------------------------------------------------
-- Attribute names
-- ---------------------------------------------------------------------------

-- | Canonical attribute names in stored documents. Names (not 'Enum'
-- tags) keep the encoding readable across inventory growth; unknown
-- names reject on decode.
attrName :: AttributeType -> String
attrName t = case t of
  AttrClass -> "class"
  AttrToken -> "token"
  AttrPrivate -> "private"
  AttrLabel -> "label"
  AttrApplication -> "application"
  AttrValue -> "value"
  AttrSensitive -> "sensitive"
  AttrExtractable -> "extractable"
  AttrKeyType -> "key_type"
  AttrValueLen -> "value_len"
  AttrEncrypt -> "encrypt"
  AttrDecrypt -> "decrypt"
  AttrSign -> "sign"
  AttrSignRecover -> "sign_recover"
  AttrVerify -> "verify"
  AttrVerifyRecover -> "verify_recover"
  AttrWrap -> "wrap"
  AttrUnwrap -> "unwrap"
  AttrDerive -> "derive"
  AttrAlwaysAuthenticate -> "always_authenticate"
  AttrEcParams -> "ec_params"
  AttrModulusBits -> "modulus_bits"
  AttrKemAlg -> "kem_alg"
  AttrEncapsulate -> "encapsulate"
  AttrDecapsulate -> "decapsulate"
  AttrId -> "id"
  AttrPublicExponent -> "public_exponent"
  AttrModulus -> "modulus"
  AttrPrivateExponent -> "private_exponent"
  AttrPrime1 -> "prime_1"
  AttrPrime2 -> "prime_2"
  AttrExponent1 -> "exponent_1"
  AttrExponent2 -> "exponent_2"
  AttrCoefficient -> "coefficient"
  AttrEcPoint -> "ec_point"
  AttrAllowedMechanisms -> "allowed_mechanisms"
  AttrCopyable -> "copyable"
  AttrDestroyable -> "destroyable"
  AttrModifiable -> "modifiable"
  AttrCertificateType -> "certificate_type"
  AttrSubject -> "subject"
  AttrIssuer -> "issuer"
  AttrSerialNumber -> "serial_number"
  AttrPublicKeyInfo -> "public_key_info"
  AttrHashOfSubjectPublicKey -> "hash_of_subject_public_key"
  AttrHashOfIssuerPublicKey -> "hash_of_issuer_public_key"
  AttrPrime -> "prime"
  AttrSubprime -> "subprime"
  AttrBase -> "base"
  AttrPrimeBits -> "prime_bits"
  AttrSubprimeBits -> "subprime_bits"
  AttrParameterSet -> "parameter_set"
  AttrSeed -> "seed"
  AttrTrusted -> "trusted"
  AttrCertificateCategory -> "certificate_category"
  AttrStartDate -> "start_date"
  AttrEndDate -> "end_date"

-- | Name back to type; unknown names fail.
nameAttr :: String -> Maybe AttributeType
nameAttr s = case s of
  "class" -> Just AttrClass
  "token" -> Just AttrToken
  "private" -> Just AttrPrivate
  "label" -> Just AttrLabel
  "application" -> Just AttrApplication
  "value" -> Just AttrValue
  "sensitive" -> Just AttrSensitive
  "extractable" -> Just AttrExtractable
  "key_type" -> Just AttrKeyType
  "value_len" -> Just AttrValueLen
  "encrypt" -> Just AttrEncrypt
  "decrypt" -> Just AttrDecrypt
  "sign" -> Just AttrSign
  "sign_recover" -> Just AttrSignRecover
  "verify" -> Just AttrVerify
  "verify_recover" -> Just AttrVerifyRecover
  "wrap" -> Just AttrWrap
  "unwrap" -> Just AttrUnwrap
  "derive" -> Just AttrDerive
  "always_authenticate" -> Just AttrAlwaysAuthenticate
  "ec_params" -> Just AttrEcParams
  "modulus_bits" -> Just AttrModulusBits
  "kem_alg" -> Just AttrKemAlg
  "encapsulate" -> Just AttrEncapsulate
  "decapsulate" -> Just AttrDecapsulate
  "id" -> Just AttrId
  "public_exponent" -> Just AttrPublicExponent
  "modulus" -> Just AttrModulus
  "private_exponent" -> Just AttrPrivateExponent
  "prime_1" -> Just AttrPrime1
  "prime_2" -> Just AttrPrime2
  "exponent_1" -> Just AttrExponent1
  "exponent_2" -> Just AttrExponent2
  "coefficient" -> Just AttrCoefficient
  "ec_point" -> Just AttrEcPoint
  "allowed_mechanisms" -> Just AttrAllowedMechanisms
  "copyable" -> Just AttrCopyable
  "destroyable" -> Just AttrDestroyable
  "modifiable" -> Just AttrModifiable
  "certificate_type" -> Just AttrCertificateType
  "subject" -> Just AttrSubject
  "issuer" -> Just AttrIssuer
  "serial_number" -> Just AttrSerialNumber
  "public_key_info" -> Just AttrPublicKeyInfo
  "hash_of_subject_public_key" -> Just AttrHashOfSubjectPublicKey
  "hash_of_issuer_public_key" -> Just AttrHashOfIssuerPublicKey
  "prime" -> Just AttrPrime
  "subprime" -> Just AttrSubprime
  "base" -> Just AttrBase
  "prime_bits" -> Just AttrPrimeBits
  "subprime_bits" -> Just AttrSubprimeBits
  "parameter_set" -> Just AttrParameterSet
  "seed" -> Just AttrSeed
  "trusted" -> Just AttrTrusted
  "certificate_category" -> Just AttrCertificateCategory
  "start_date" -> Just AttrStartDate
  "end_date" -> Just AttrEndDate
  _ -> Nothing

-- | Encode one attribute value: bools as JSON booleans, unsigned
-- longs as full-width 16-hex strings, byte arrays as base64
-- strings.
encodeAttrValue :: AttributeValue -> Json
encodeAttrValue v = case v of
  ValBool b -> JBool b
  ValULong n -> JString (encodeHexWord64 n)
  ValBytes bs -> JString (encodeBase64 bs)

-- | Decode one attribute value against its owning type's shape.
-- Cross-shape bytes fail.
decodeAttrValue :: AttributeType -> Json -> Maybe AttributeValue
decodeAttrValue t j = case t of
  AttrToken -> boolOf j
  AttrPrivate -> boolOf j
  AttrSensitive -> boolOf j
  AttrExtractable -> boolOf j
  AttrEncrypt -> boolOf j
  AttrDecrypt -> boolOf j
  AttrSign -> boolOf j
  AttrSignRecover -> boolOf j
  AttrVerify -> boolOf j
  AttrVerifyRecover -> boolOf j
  AttrWrap -> boolOf j
  AttrUnwrap -> boolOf j
  AttrDerive -> boolOf j
  AttrAlwaysAuthenticate -> boolOf j
  AttrEncapsulate -> boolOf j
  AttrDecapsulate -> boolOf j
  AttrCopyable -> boolOf j
  AttrDestroyable -> boolOf j
  AttrModifiable -> boolOf j
  AttrClass -> ulongOf j
  AttrKeyType -> ulongOf j
  AttrValueLen -> ulongOf j
  AttrModulusBits -> ulongOf j
  AttrKemAlg -> ulongOf j
  AttrCertificateType -> ulongOf j
  AttrLabel -> bytesOf j
  AttrApplication -> bytesOf j
  AttrValue -> bytesOf j
  AttrEcParams -> bytesOf j
  AttrId -> bytesOf j
  AttrPublicExponent -> bytesOf j
  AttrModulus -> bytesOf j
  AttrPrivateExponent -> bytesOf j
  AttrPrime1 -> bytesOf j
  AttrPrime2 -> bytesOf j
  AttrExponent1 -> bytesOf j
  AttrExponent2 -> bytesOf j
  AttrCoefficient -> bytesOf j
  AttrEcPoint -> bytesOf j
  AttrAllowedMechanisms -> bytesOf j
  AttrSubject -> bytesOf j
  AttrIssuer -> bytesOf j
  AttrSerialNumber -> bytesOf j
  AttrPublicKeyInfo -> bytesOf j
  AttrHashOfSubjectPublicKey -> bytesOf j
  AttrHashOfIssuerPublicKey -> bytesOf j
  AttrPrime -> bytesOf j
  AttrSubprime -> bytesOf j
  AttrBase -> bytesOf j
  AttrPrimeBits -> ulongOf j
  AttrSubprimeBits -> ulongOf j
  AttrParameterSet -> ulongOf j
  AttrSeed -> bytesOf j
  AttrTrusted -> boolOf j
  AttrCertificateCategory -> ulongOf j
  AttrStartDate -> bytesOf j
  AttrEndDate -> bytesOf j
  where
    boolOf (JBool b) = Just (ValBool b)
    boolOf _ = Nothing
    ulongOf (JString s) = ValULong <$> decodeHexWord64 s
    ulongOf _ = Nothing
    bytesOf (JString s) = ValBytes <$> decodeBase64 s
    bytesOf _ = Nothing

-- ---------------------------------------------------------------------------
-- Token documents
-- ---------------------------------------------------------------------------

-- | Canonical token document bytes.
encodeTokenRecord :: TokenRecord -> String
encodeTokenRecord t = renderJson $ JObject
  [ ("format_version", JNumber (fromIntegral recordFormatVersion))
  , ("token_id", JString (encodeHex16 (unTokenId (trId t))))
  , ("slot", JString (encodeHex16 (unSlotId (trSlot t))))
  , ("generation", JString (encodeHex16 (unGeneration (trGeneration t))))
  , ("label", JString (trLabel t))
  , ("auth", encodeAuth (trAuth t))
  ]

-- | Canonical auth-state sub-document: the DURABLE half only
-- (retry counters and lock flags). The transient half (active
-- login, principal, epoch) is never encoded — even a caller that
-- hands over a logged-in 'TokenAuth' persists counters alone
-- (and the commit boundary scrubs first, so the bytes cannot
-- carry a session either way).
encodeAuth :: TokenAuth -> Json
encodeAuth a = JObject
  [ ("user_attempts", JString (encodeHex16 (taUserAttempts a)))
  , ("so_attempts", JString (encodeHex16 (taSoAttempts a)))
  , ("user_locked", JBool (taUserLocked a))
  , ("so_locked", JBool (taSoLocked a))
  ]

-- | Decode a token document; unknown format versions, unknown
-- fields shapes, and out-of-range quantities all fail.
decodeTokenRecord :: String -> Maybe TokenRecord
decodeTokenRecord s = do
  JObject kvs <- parseJson s
  JNumber v <- lookupField "format_version" kvs
  if v /= fromIntegral recordFormatVersion then Nothing else do
    tid <- lookupField "token_id" kvs >>= asString >>= decodeHex16
    slot <- lookupField "slot" kvs >>= asString >>= decodeHex16
    gen <- lookupField "generation" kvs >>= asString >>= decodeHex16
    label <- lookupField "label" kvs >>= asString
    authJson <- lookupField "auth" kvs >>= asObject
    auth <- decodeAuth authJson
    pure TokenRecord
      { trId = TokenId tid
      , trSlot = SlotId slot
      , trGeneration = Generation gen
      , trLabel = label
      , trAuth = auth
      }

-- | Decode an auth-state sub-document. Only the durable keys
-- are read; the transient half always decodes cleared (public,
-- no principal, epoch zero), so no stored bytes can restore an
-- authenticated application session. Legacy @login@\/@principal@\/
-- @auth_epoch@ keys, when present from an older writer, are
-- ignored rather than refused: they were never load-bearing for
-- retry enforcement, and refusing them would strand older files
-- instead of seating them public with their counters intact.
decodeAuth :: [(String, Json)] -> Maybe TokenAuth
decodeAuth kvs = do
  uatt <- lookupField "user_attempts" kvs >>= asString >>= decodeHex16
  satt <- lookupField "so_attempts" kvs >>= asString >>= decodeHex16
  ulock <- lookupField "user_locked" kvs >>= asBool
  slock <- lookupField "so_locked" kvs >>= asBool
  pure TokenAuth
    { taLogin = Nothing
    , taPrincipal = Nothing
    , taAuthEpoch = 0
    , taUserAttempts = uatt
    , taSoAttempts = satt
    , taUserLocked = ulock
    , taSoLocked = slock
    }

-- ---------------------------------------------------------------------------
-- Credential documents
-- ---------------------------------------------------------------------------

-- | Canonical credential document bytes: the home token, the SO
-- PIN (base64, always present), and the user PIN (base64, or
-- null when uninitialized). PIN bytes ride base64 like every
-- other stored byte string; the document carries no handle,
-- pointer, or session reference.
encodeCredentialRecord :: CredentialRecord -> String
encodeCredentialRecord c = renderJson $ JObject
  [ ("format_version", JNumber (fromIntegral recordFormatVersion))
  , ("token_id", JString (encodeHex16 (unTokenId (crToken c))))
  , ("so_pin", JString (encodeBase64 (crSoPin c)))
  , ("user_pin", maybe JNull (JString . encodeBase64) (crUserPin c))
  ]

-- | Decode a credential document; unknown format versions,
-- malformed PIN bytes, and out-of-range quantities all fail.
decodeCredentialRecord :: String -> Maybe CredentialRecord
decodeCredentialRecord s = do
  JObject kvs <- parseJson s
  JNumber v <- lookupField "format_version" kvs
  if v /= fromIntegral recordFormatVersion then Nothing else do
    tid <- lookupField "token_id" kvs >>= asString >>= decodeHex16
    so <- lookupField "so_pin" kvs >>= asString >>= decodeBase64
    user <- case lookupField "user_pin" kvs of
      Just JNull -> Just Nothing
      Just (JString b) -> Just <$> decodeBase64 b
      _ -> Nothing
    pure CredentialRecord
      { crToken = TokenId tid
      , crSoPin = so
      , crUserPin = user
      }

-- ---------------------------------------------------------------------------
-- Object documents
-- ---------------------------------------------------------------------------

-- | Canonical object document bytes.
encodeObjectRecord :: ObjectRecord -> String
encodeObjectRecord o = renderJson $ JObject
  [ ("format_version", JNumber (fromIntegral recordFormatVersion))
  , ("object_id", JString (encodeHex16 (unObjectId (orId o))))
  , ("token_id", JString (encodeHex16 (unTokenId (orToken o))))
  , ("class", JString (encodeHexWord64 (orClass o)))
  , ("key_type", maybe JNull (JString . encodeHexWord64) (orKeyType o))
  , ("attrs", JObject [(attrName t, encodeAttrValue v) | (t, v) <- Map.toAscList (orAttrs o)])
  , ("material_encoding", JString (orMaterialEncoding o))
  , ("material", maybe JNull (JString . encodeBase64) (orMaterial o))
  , ("revision", JString (encodeHex16 (unRevision (orRevision o))))
  ]

-- | Decode an object document; unknown format versions and
-- cross-shape attribute bytes all fail.
decodeObjectRecord :: String -> Maybe ObjectRecord
decodeObjectRecord s = do
  JObject kvs <- parseJson s
  JNumber v <- lookupField "format_version" kvs
  if v /= fromIntegral recordFormatVersion then Nothing else do
    oid <- lookupField "object_id" kvs >>= asString >>= decodeHex16
    tid <- lookupField "token_id" kvs >>= asString >>= decodeHex16
    cls <- lookupField "class" kvs >>= asString >>= decodeHexWord64
    kty <- case lookupField "key_type" kvs of
      Just JNull -> Just Nothing
      Just (JString h) -> Just <$> decodeHexWord64 h
      _ -> Nothing
    attrJson <- lookupField "attrs" kvs >>= asObject
    attrs <- decodeAttrPairs attrJson
    menc <- lookupField "material_encoding" kvs >>= asString
    guard (menc `elem` knownMaterialEncodings)
    mat <- case lookupField "material" kvs of
      Just JNull -> Just Nothing
      Just (JString b) -> Just <$> decodeBase64 b
      _ -> Nothing
    rev <- lookupField "revision" kvs >>= asString >>= decodeHex16
    pure ObjectRecord
      { orId = ObjectId oid
      , orToken = TokenId tid
      , orClass = cls
      , orKeyType = kty
      , orAttrs = attrs
      , orMaterialEncoding = menc
      , orMaterial = mat
      , orRevision = Revision rev
      }

-- | Decode parsed attribute pairs (shared by the object document
-- and the SQLite @attributes_json@ column decoders).
decodeAttrPairs :: [(String, Json)] -> Maybe (Map AttributeType AttributeValue)
decodeAttrPairs pairs = Map.fromList <$> mapM decodeOne pairs
  where
    decodeOne :: (String, Json) -> Maybe (AttributeType, AttributeValue)
    decodeOne (name, j) = do
      t <- nameAttr name
      v <- decodeAttrValue t j
      pure (t, v)

-- | Canonical attribute-document bytes (the SQLite
-- @attributes_json@ column encoding): the bare attrs object.
encodeAttrsDoc :: Map AttributeType AttributeValue -> String
encodeAttrsDoc attrs = renderJson
  (JObject [(attrName t, encodeAttrValue v) | (t, v) <- Map.toAscList attrs])

-- | Decode attribute-document bytes; unknown names and
-- cross-shape values fail.
decodeAttrsDoc :: String -> Maybe (Map AttributeType AttributeValue)
decodeAttrsDoc s = do
  JObject pairs <- parseJson s
  decodeAttrPairs pairs

-- Identifier projections ('unTokenId' et al.) come from 'Haskoki.Types'.

-- ---------------------------------------------------------------------------
-- Full-width Word64 hex (persistent job ids use the whole domain)
-- ---------------------------------------------------------------------------

-- | Encode a 'Word64' as 16 lowercase hex characters.
encodeHexWord64 :: Word64 -> String
encodeHexWord64 w =
  [hexDigit (fromIntegral ((w `shiftR` s) .&. 0xF)) | s <- [60, 56 .. 0]]

-- | Decode exactly 16 hex characters into a 'Word64'; anything
-- else fails.
decodeHexWord64 :: String -> Maybe Word64
decodeHexWord64 s
  | length s == 16
  , all isHexDigit s =
      Just (foldl (\acc c -> acc * 16 + fromIntegral (hexVal c)) 0 s)
  | otherwise = Nothing

-- ---------------------------------------------------------------------------
-- Job documents
-- ---------------------------------------------------------------------------

-- | Canonical execution-state names (matching the schema's
-- @CHECK@ constraint).
execStateName :: JobExecState -> String
execStateName s = case s of
  JobQueued -> "queued"
  JobReady -> "ready"
  JobFailed -> "failed"
  JobCanceled -> "canceled"
  JobDelivered -> "delivered"

-- | State name back to state; unknown names fail.
nameExecState :: String -> Maybe JobExecState
nameExecState s = case s of
  "queued" -> Just JobQueued
  "ready" -> Just JobReady
  "failed" -> Just JobFailed
  "canceled" -> Just JobCanceled
  "delivered" -> Just JobDelivered
  _ -> Nothing

-- | Canonical return-code names in stored documents. An explicit
-- table (not 'Show'-derived at decode time): unknown names reject
-- rather than decoding speculatively.
encodeReturnCode :: ReturnCode -> String
encodeReturnCode c = case c of
  CKR_OK -> "CKR_OK"
  CKR_HOST_MEMORY -> "CKR_HOST_MEMORY"
  CKR_FUNCTION_CANCELED -> "CKR_FUNCTION_CANCELED"
  CKR_PENDING -> "CKR_PENDING"
  CKR_SESSION_ASYNC_NOT_SUPPORTED -> "CKR_SESSION_ASYNC_NOT_SUPPORTED"
  CKR_GENERAL_ERROR -> "CKR_GENERAL_ERROR"
  CKR_ARGUMENTS_BAD -> "CKR_ARGUMENTS_BAD"
  CKR_BUFFER_TOO_SMALL -> "CKR_BUFFER_TOO_SMALL"
  CKR_SESSION_HANDLE_INVALID -> "CKR_SESSION_HANDLE_INVALID"
  CKR_SESSION_COUNT -> "CKR_SESSION_COUNT"
  CKR_SESSION_READ_ONLY_EXISTS -> "CKR_SESSION_READ_ONLY_EXISTS"
  CKR_SESSION_READ_ONLY -> "CKR_SESSION_READ_ONLY"
  CKR_TOKEN_NOT_PRESENT -> "CKR_TOKEN_NOT_PRESENT"
  CKR_USER_ALREADY_LOGGED_IN -> "CKR_USER_ALREADY_LOGGED_IN"
  CKR_USER_ANOTHER_ALREADY_LOGGED_IN -> "CKR_USER_ANOTHER_ALREADY_LOGGED_IN"
  CKR_USER_NOT_LOGGED_IN -> "CKR_USER_NOT_LOGGED_IN"
  CKR_PIN_INCORRECT -> "CKR_PIN_INCORRECT"
  CKR_PIN_LOCKED -> "CKR_PIN_LOCKED"
  CKR_CRYPTOKI_NOT_INITIALIZED -> "CKR_CRYPTOKI_NOT_INITIALIZED"
  CKR_CRYPTOKI_ALREADY_INITIALIZED -> "CKR_CRYPTOKI_ALREADY_INITIALIZED"
  CKR_OBJECT_HANDLE_INVALID -> "CKR_OBJECT_HANDLE_INVALID"
  CKR_KEY_HANDLE_INVALID -> "CKR_KEY_HANDLE_INVALID"
  CKR_ATTRIBUTE_SENSITIVE -> "CKR_ATTRIBUTE_SENSITIVE"
  CKR_ATTRIBUTE_TYPE_INVALID -> "CKR_ATTRIBUTE_TYPE_INVALID"
  CKR_ATTRIBUTE_READ_ONLY -> "CKR_ATTRIBUTE_READ_ONLY"
  CKR_ATTRIBUTE_VALUE_INVALID -> "CKR_ATTRIBUTE_VALUE_INVALID"
  CKR_ACTION_PROHIBITED -> "CKR_ACTION_PROHIBITED"
  CKR_TEMPLATE_INCOMPLETE -> "CKR_TEMPLATE_INCOMPLETE"
  CKR_TEMPLATE_INCONSISTENT -> "CKR_TEMPLATE_INCONSISTENT"
  CKR_MECHANISM_INVALID -> "CKR_MECHANISM_INVALID"
  CKR_MECHANISM_PARAM_INVALID -> "CKR_MECHANISM_PARAM_INVALID"
  CKR_OPERATION_ACTIVE -> "CKR_OPERATION_ACTIVE"
  CKR_OPERATION_NOT_INITIALIZED -> "CKR_OPERATION_NOT_INITIALIZED"
  CKR_SIGNATURE_INVALID -> "CKR_SIGNATURE_INVALID"
  CKR_SIGNATURE_LEN_RANGE -> "CKR_SIGNATURE_LEN_RANGE"
  CKR_KEY_FUNCTION_NOT_PERMITTED -> "CKR_KEY_FUNCTION_NOT_PERMITTED"
  CKR_KEY_TYPE_INCONSISTENT -> "CKR_KEY_TYPE_INCONSISTENT"
  CKR_WRAPPING_KEY_TYPE_INCONSISTENT -> "CKR_WRAPPING_KEY_TYPE_INCONSISTENT"
  CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT -> "CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT"
  CKR_CURVE_NOT_SUPPORTED -> "CKR_CURVE_NOT_SUPPORTED"
  CKR_KEY_SIZE_RANGE -> "CKR_KEY_SIZE_RANGE"
  CKR_DATA_LEN_RANGE -> "CKR_DATA_LEN_RANGE"
  CKR_ENCRYPTED_DATA_INVALID -> "CKR_ENCRYPTED_DATA_INVALID"
  CKR_ENCRYPTED_DATA_LEN_RANGE -> "CKR_ENCRYPTED_DATA_LEN_RANGE"
  CKR_KEY_UNEXTRACTABLE -> "CKR_KEY_UNEXTRACTABLE"
  CKR_KEY_NOT_WRAPPABLE -> "CKR_KEY_NOT_WRAPPABLE"
  CKR_STATE_UNSAVEABLE -> "CKR_STATE_UNSAVEABLE"
  CKR_SAVED_STATE_INVALID -> "CKR_SAVED_STATE_INVALID"

-- | Code name back to code; unknown names fail.
decodeReturnCode :: String -> Maybe ReturnCode
decodeReturnCode s = case s of
  "CKR_OK" -> Just CKR_OK
  "CKR_HOST_MEMORY" -> Just CKR_HOST_MEMORY
  "CKR_FUNCTION_CANCELED" -> Just CKR_FUNCTION_CANCELED
  "CKR_PENDING" -> Just CKR_PENDING
  "CKR_SESSION_ASYNC_NOT_SUPPORTED" -> Just CKR_SESSION_ASYNC_NOT_SUPPORTED
  "CKR_GENERAL_ERROR" -> Just CKR_GENERAL_ERROR
  "CKR_ARGUMENTS_BAD" -> Just CKR_ARGUMENTS_BAD
  "CKR_BUFFER_TOO_SMALL" -> Just CKR_BUFFER_TOO_SMALL
  "CKR_SESSION_HANDLE_INVALID" -> Just CKR_SESSION_HANDLE_INVALID
  "CKR_SESSION_COUNT" -> Just CKR_SESSION_COUNT
  "CKR_SESSION_READ_ONLY_EXISTS" -> Just CKR_SESSION_READ_ONLY_EXISTS
  "CKR_SESSION_READ_ONLY" -> Just CKR_SESSION_READ_ONLY
  "CKR_TOKEN_NOT_PRESENT" -> Just CKR_TOKEN_NOT_PRESENT
  "CKR_USER_ALREADY_LOGGED_IN" -> Just CKR_USER_ALREADY_LOGGED_IN
  "CKR_USER_ANOTHER_ALREADY_LOGGED_IN" -> Just CKR_USER_ANOTHER_ALREADY_LOGGED_IN
  "CKR_USER_NOT_LOGGED_IN" -> Just CKR_USER_NOT_LOGGED_IN
  "CKR_PIN_INCORRECT" -> Just CKR_PIN_INCORRECT
  "CKR_PIN_LOCKED" -> Just CKR_PIN_LOCKED
  "CKR_CRYPTOKI_NOT_INITIALIZED" -> Just CKR_CRYPTOKI_NOT_INITIALIZED
  "CKR_CRYPTOKI_ALREADY_INITIALIZED" -> Just CKR_CRYPTOKI_ALREADY_INITIALIZED
  "CKR_OBJECT_HANDLE_INVALID" -> Just CKR_OBJECT_HANDLE_INVALID
  "CKR_KEY_HANDLE_INVALID" -> Just CKR_KEY_HANDLE_INVALID
  "CKR_ATTRIBUTE_SENSITIVE" -> Just CKR_ATTRIBUTE_SENSITIVE
  "CKR_ATTRIBUTE_TYPE_INVALID" -> Just CKR_ATTRIBUTE_TYPE_INVALID
  "CKR_ATTRIBUTE_READ_ONLY" -> Just CKR_ATTRIBUTE_READ_ONLY
  "CKR_ATTRIBUTE_VALUE_INVALID" -> Just CKR_ATTRIBUTE_VALUE_INVALID
  "CKR_ACTION_PROHIBITED" -> Just CKR_ACTION_PROHIBITED
  "CKR_TEMPLATE_INCOMPLETE" -> Just CKR_TEMPLATE_INCOMPLETE
  "CKR_TEMPLATE_INCONSISTENT" -> Just CKR_TEMPLATE_INCONSISTENT
  "CKR_MECHANISM_INVALID" -> Just CKR_MECHANISM_INVALID
  "CKR_MECHANISM_PARAM_INVALID" -> Just CKR_MECHANISM_PARAM_INVALID
  "CKR_OPERATION_ACTIVE" -> Just CKR_OPERATION_ACTIVE
  "CKR_OPERATION_NOT_INITIALIZED" -> Just CKR_OPERATION_NOT_INITIALIZED
  "CKR_SIGNATURE_INVALID" -> Just CKR_SIGNATURE_INVALID
  "CKR_SIGNATURE_LEN_RANGE" -> Just CKR_SIGNATURE_LEN_RANGE
  "CKR_KEY_FUNCTION_NOT_PERMITTED" -> Just CKR_KEY_FUNCTION_NOT_PERMITTED
  "CKR_KEY_TYPE_INCONSISTENT" -> Just CKR_KEY_TYPE_INCONSISTENT
  "CKR_WRAPPING_KEY_TYPE_INCONSISTENT" -> Just CKR_WRAPPING_KEY_TYPE_INCONSISTENT
  "CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT" -> Just CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT
  "CKR_CURVE_NOT_SUPPORTED" -> Just CKR_CURVE_NOT_SUPPORTED
  "CKR_KEY_SIZE_RANGE" -> Just CKR_KEY_SIZE_RANGE
  "CKR_DATA_LEN_RANGE" -> Just CKR_DATA_LEN_RANGE
  "CKR_ENCRYPTED_DATA_INVALID" -> Just CKR_ENCRYPTED_DATA_INVALID
  "CKR_ENCRYPTED_DATA_LEN_RANGE" -> Just CKR_ENCRYPTED_DATA_LEN_RANGE
  "CKR_KEY_UNEXTRACTABLE" -> Just CKR_KEY_UNEXTRACTABLE
  "CKR_KEY_NOT_WRAPPABLE" -> Just CKR_KEY_NOT_WRAPPABLE
  "CKR_STATE_UNSAVEABLE" -> Just CKR_STATE_UNSAVEABLE
  "CKR_SAVED_STATE_INVALID" -> Just CKR_SAVED_STATE_INVALID
  _ -> Nothing

-- | Canonical job document bytes.
encodeJobRecord :: JobRecord -> String
encodeJobRecord j = renderJson $ JObject
  [ ("format_version", JNumber (fromIntegral recordFormatVersion))
  , ("persistent_id", JString (encodeHexWord64 (jrPersistentId j)))
  , ("token_id", JString (encodeHex16 (unTokenId (jrToken j))))
  , ("token_generation", JString (encodeHex16 (unGeneration (jrTokenGeneration j))))
  , ("function", JString (jrFunction j))
  , ("state", JString (execStateName (jrState j)))
  , ("body", encodeJobBody (jrBody j))
  ]

-- | Canonical job-body sub-document.
encodeJobBody :: JobBody -> Json
encodeJobBody b = case b of
  JobPending recipe params -> JObject
    [ ("kind", JString "recipe")
    , ("recipe", JString recipe)
    , ("params", JString (encodeBase64 params))
    ]
  JobResult code bytes -> JObject
    [ ("kind", JString "result")
    , ("code", JString (encodeReturnCode code))
    , ("bytes", JString (encodeBase64 bytes))
    ]

-- | Decode a job document; unknown format versions, states, body
-- kinds, and codes all fail.
decodeJobRecord :: String -> Maybe JobRecord
decodeJobRecord s = do
  JObject kvs <- parseJson s
  JNumber v <- lookupField "format_version" kvs
  if v /= fromIntegral recordFormatVersion then Nothing else do
    pid <- lookupField "persistent_id" kvs >>= asString >>= decodeHexWord64
    tid <- lookupField "token_id" kvs >>= asString >>= decodeHex16
    gen <- lookupField "token_generation" kvs >>= asString >>= decodeHex16
    fun <- lookupField "function" kvs >>= asString
    stName <- lookupField "state" kvs >>= asString
    st <- nameExecState stName
    bodyJson <- lookupField "body" kvs >>= asObject
    body <- decodeJobBody bodyJson
    pure JobRecord
      { jrPersistentId = pid
      , jrToken = TokenId tid
      , jrTokenGeneration = Generation gen
      , jrFunction = fun
      , jrState = st
      , jrBody = body
      }

-- | Decode a job-body sub-document.
decodeJobBody :: [(String, Json)] -> Maybe JobBody
decodeJobBody kvs = do
  kind <- lookupField "kind" kvs >>= asString
  case kind of
    "recipe" -> do
      recipe <- lookupField "recipe" kvs >>= asString
      params <- lookupField "params" kvs >>= asString >>= decodeBase64
      pure (JobPending recipe params)
    "result" -> do
      codeName <- lookupField "code" kvs >>= asString
      code <- decodeReturnCode codeName
      bytes <- lookupField "bytes" kvs >>= asString >>= decodeBase64
      pure (JobResult code bytes)
    _ -> Nothing