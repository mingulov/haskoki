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
-}
module Haskoki.Runtime.Storage
  ( -- * Limits
    StoreLimits (..)
  , defaultLimits
    -- * Records
  , TokenRecord (..)
  , ObjectRecord (..)
  , ObjectPut (..)
  , JobRecord (..)
  , JobExecState (..)
  , JobBody (..)
    -- * Deltas and results
  , StoreDelta (..)
  , emptyDelta
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
    -- * Pre-commit validation
  , LoadedState (..)
  , checkLimits
  , checkExpectedRevisions
  , checkTokenRefs
  , checkSlotUnique
  , knownMaterialEncodings
    -- * Store contract
  , Store (..)
  , StoredDoc (..)
    -- * Model projection
  , objectToRecord
  , reserveRestoredIds
    -- * Canonical encoding
  , recordFormatVersion
  , encodeTokenRecord
  , decodeTokenRecord
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
import Data.Word (Word8, Word64)

import Control.Monad (guard)
import Data.IORef (IORef, atomicModifyIORef', newIORef)
import Data.Maybe (listToMaybe)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE

import Haskoki.Attribute (AttributeType (..), AttributeValue (..))
import Haskoki.Model (Model (..), ObjectState (..))
import Haskoki.Session
  ( ActiveLogin (..)
  , TokenAuth (..)
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
-- generation, label, and credential/auth state.
data TokenRecord = TokenRecord
  { trId :: !TokenId
  , trSlot :: !SlotId
  , trGeneration :: !Generation
  , trLabel :: !String
  , trAuth :: !TokenAuth
  } deriving (Eq, Show)

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
data StoreDelta = StoreDelta
  { sdPutTokens :: ![TokenRecord]
  , sdDropTokens :: ![TokenId]
  , sdPutObjects :: ![ObjectPut]
  , sdDropObjects :: ![ObjectId]
  , sdPutJobs :: ![JobRecord]
  , sdDropJobs :: ![Word64]
  , sdPutMeta :: ![(String, String)]
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
  }

-- | Commit outcome classification (design 08, section 5).
--
-- * 'Committed': the delta is durable; the caller may publish its
--   in-memory delta.
-- * 'NotCommitted': nothing was written (pre-commit failure, limit
--   hit, revision conflict); the caller publishes nothing.
-- * 'CommitUnknown': the commit was issued but its
--   outcome could not be determined; the caller must reload and
--   reconcile, and must NEVER blindly reissue the PKCS#11 operation.
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

-- ---------------------------------------------------------------------------
-- Commit protocol
-- ---------------------------------------------------------------------------

-- | Fault-injection points in the commit path.
data FaultPoint
  = FaultBeforeCommit
  | FaultAmbiguousCommit
  | FaultVerifyReload
  | FaultAfterCommit
  | FaultFullDisk
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

-- ---------------------------------------------------------------------------
-- Store contract
-- ---------------------------------------------------------------------------

-- ---------------------------------------------------------------------------
-- Pre-commit validation (pure)
-- ---------------------------------------------------------------------------

-- | Loaded state for validation: tokens with their objects,
-- plus the detached jobs.
data LoadedState = LoadedState
  { lsTokens :: ![(TokenRecord, [ObjectRecord])]
  , lsJobs :: ![JobRecord]
  } deriving (Eq, Show)

-- | Project a delta against current state and enforce the
-- pre-commit bounds: per-record bytes on every put, then the
-- projected object and job counts, then the projected total
-- stored bytes (exact UTF-8 sizes of the canonical documents).
-- The first hit wins; 'Nothing' commits clean.
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
    sized =
      [("token " ++ show (trId t), utf8Bytes (encodeTokenRecord t)) | t <- putToks]
        ++ [("object " ++ show (orId o), utf8Bytes (encodeObjectRecord o)) | o <- putObjs]
        ++ [("job " ++ show (jrPersistentId j), utf8Bytes (encodeJobRecord j)) | j <- putJobs]
    firstOverRecord = listToMaybe [d | (d, n) <- sized, n > limMaxRecordBytes lim]
    tokMap = foldr Map.delete
      (Map.fromList [(trId t, t) | (t, _) <- lsTokens current]) (sdDropTokens delta)
    tokMap' = foldr (\t m -> Map.insert (trId t) t m) tokMap putToks
    objMap = foldr Map.delete
      (Map.fromList [(orId o, o) | (_, os) <- lsTokens current, o <- os]) (sdDropObjects delta)
    objMap' = foldr (\o m -> Map.insert (orId o) o m) objMap putObjs
    jobMap = foldr Map.delete
      (Map.fromList [(jrPersistentId j, j) | j <- lsJobs current]) (sdDropJobs delta)
    jobMap' = foldr (\j m -> Map.insert (jrPersistentId j) j m) jobMap putJobs
    totalBytes =
      sum [utf8Bytes (encodeTokenRecord t) | t <- Map.elems tokMap']
        + sum [utf8Bytes (encodeObjectRecord o) | o <- Map.elems objMap']
        + sum [utf8Bytes (encodeJobRecord j) | j <- Map.elems jobMap']

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
-- plus the delta's own puts), and every job put must name a
-- token at exactly the job's generation. The first conflict wins;
-- 'Nothing' applies clean. Reset kills old ids through this
-- check: a job stamped with a superseded generation refuses.
checkTokenRefs :: [(TokenId, TokenRecord)] -> StoreDelta -> Maybe StoreError
checkTokenRefs currentToks delta =
  case [o | o <- map opRecord (sdPutObjects delta), orToken o `Map.notMember` projected] of
    (o : _) -> Just (StoreRevisionConflict
      ("object " ++ show (orId o) ++ " references missing token " ++ show (orToken o)))
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

-- | The narrow backend contract: load, commit, close, and
-- raw-document inspection (the fixture hook for encoding scans),
-- quarantine listing, authoritative reload, commit counters, job
-- loads, and token reset:
-- 'storeResetToken' replaces the token (expected-generation
-- guarded) and atomically removes its objects and jobs.
--
-- Quarantine is a live-handle property: it guards a handle whose
-- view may have diverged from durable truth. A fresh handle loads
-- the authoritative bytes and starts clean.
data Store = Store
  { storeLoadTokens :: IO (Either StoreError [(TokenRecord, [ObjectRecord])])
  , storeLoadJobs :: IO (Either StoreError [JobRecord])
  , storeCommit :: StoreDelta -> IO CommitResult
  , storeResetToken :: TokenId -> Generation -> TokenRecord -> IO CommitResult
  , storeClose :: IO ()
  , storeInspect :: IO [StoredDoc]
  , storeQuarantined :: IO [(TokenId, String)]
  , storeReload :: IO (Either StoreError ())
  , storeStats :: IO StoreStats
  , storeLoadMeta :: IO (Either StoreError [(String, String)])
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

-- | Canonical auth-state sub-document.
encodeAuth :: TokenAuth -> Json
encodeAuth a = JObject
  [ ("login", JString (loginName (taLogin a)))
  , ("principal", maybe JNull JString (taPrincipal a))
  , ("auth_epoch", JString (encodeHex16 (taAuthEpoch a)))
  , ("user_attempts", JString (encodeHex16 (taUserAttempts a)))
  , ("so_attempts", JString (encodeHex16 (taSoAttempts a)))
  , ("user_locked", JBool (taUserLocked a))
  , ("so_locked", JBool (taSoLocked a))
  ]
  where
    loginName :: Maybe ActiveLogin -> String
    loginName Nothing = "none"
    loginName (Just AuthUser) = "user"
    loginName (Just AuthSO) = "so"

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

-- | Decode an auth-state sub-document.
decodeAuth :: [(String, Json)] -> Maybe TokenAuth
decodeAuth kvs = do
  loginName <- lookupField "login" kvs >>= asString
  login <- case loginName of
    "none" -> Just Nothing
    "user" -> Just (Just AuthUser)
    "so" -> Just (Just AuthSO)
    _ -> Nothing
  principal <- case lookupField "principal" kvs of
    Just JNull -> Just Nothing
    Just (JString p) -> Just (Just p)
    _ -> Nothing
  epoch <- lookupField "auth_epoch" kvs >>= asString >>= decodeHex16
  uatt <- lookupField "user_attempts" kvs >>= asString >>= decodeHex16
  satt <- lookupField "so_attempts" kvs >>= asString >>= decodeHex16
  ulock <- lookupField "user_locked" kvs >>= asBool
  slock <- lookupField "so_locked" kvs >>= asBool
  pure TokenAuth
    { taLogin = login
    , taPrincipal = principal
    , taAuthEpoch = epoch
    , taUserAttempts = uatt
    , taSoAttempts = satt
    , taUserLocked = ulock
    , taSoLocked = slock
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