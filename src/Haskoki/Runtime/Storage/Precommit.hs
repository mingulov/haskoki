{- | Detached pre-commit validation (pure).
-}
module Haskoki.Runtime.Storage.Precommit
  ( LoadedState (..)
  , checkLimits
  , checkExpectedRevisions
  , checkTokenRefs
  , checkSlotUnique
  ) where

import qualified Data.ByteString as BS
import Data.List (nub, sort)
import qualified Data.Map.Strict as Map
import Data.Maybe (listToMaybe)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import Haskoki.Types
  ( ObjectId (..)
  , Revision (..)
  , TokenId (..)
  )
import Haskoki.Runtime.Storage.CredDocs
import Haskoki.Runtime.Storage.Deltas
import Haskoki.Runtime.Storage.JobDocs
import Haskoki.Runtime.Storage.Limits
import Haskoki.Runtime.Storage.ObjectDocs
import Haskoki.Runtime.Storage.Records
import Haskoki.Runtime.Storage.TokenDocs

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
