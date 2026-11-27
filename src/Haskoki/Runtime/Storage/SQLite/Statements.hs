{- | SQLite store statements: row codecs, statement builders,
and the guarded execution helpers.

Leaf module: SQL text and bindings only, no store logic.
-}
{-# LANGUAGE OverloadedStrings #-}
module Haskoki.Runtime.Storage.SQLite.Statements
  ( dropObjectStmt
  , dropTokenStmt
  , dropJobStmt
  , dropCredentialStmt
  , putCredentialStmt
  , firstByCredential
  , putJobStmt
  , putTokenStmt
  , stageTokenStmt
  , firstByToken
  , pickTempSlots
  , parseSlotKey
  , putMetaStmt
  , putObjectStmt
  , execParams
  , queryRows
  , trySQLite
  , tryStoreIO
  , closeQuiet
  , rollbackQuiet
  , encodeBlob8
  , decodeBlob8
  , decodeRevision
  , encodeBlobW64
  , decodeBlobW64
  ) where

import Control.Exception (bracket, try)
import Data.Bits (shiftR, (.&.))
import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import Data.Int (Int64)
import qualified Data.Text as T
import Data.Text (Text)
import Data.Word (Word64)
import qualified Database.SQLite3 as S
import System.IO.Error (tryIOError)

import Haskoki.Runtime.Storage
  ( CredentialRecord (..)
  , JobRecord (..)
  , ObjectPut (..)
  , ObjectRecord (..)
  , StoreError (..)
  , TokenRecord (..)
  , encodeAttrsDoc
  , encodeCredentialRecord
  , encodeHex16
  , encodeJobRecord
  , encodeTokenRecord
  , execStateName
  )
import Haskoki.Types (Generation (..), ObjectId (..), Revision (..), SlotId (..), TokenId (..))

-- | DELETE one object by id.
dropObjectStmt :: ObjectId -> (Text, [S.SQLData])
dropObjectStmt (ObjectId n) =
  ("DELETE FROM objects WHERE object_id = ?", [S.SQLText (T.pack (encodeHex16 n))])

-- | DELETE one token by id (owned objects and jobs cascade).
dropTokenStmt :: TokenId -> (Text, [S.SQLData])
dropTokenStmt (TokenId n) =
  ("DELETE FROM tokens WHERE token_id = ?", [S.SQLText (T.pack (encodeHex16 n))])

-- | DELETE one job by persistent id.
dropJobStmt :: Word64 -> (Text, [S.SQLData])
dropJobStmt pid =
  ("DELETE FROM detached_jobs WHERE persistent_id_key = ?", [S.SQLBlob (encodeBlobW64 pid)])

-- | DELETE one credential by home token.
dropCredentialStmt :: TokenId -> (Text, [S.SQLData])
dropCredentialStmt (TokenId n) =
  ("DELETE FROM credentials WHERE token_id = ?", [S.SQLText (T.pack (encodeHex16 n))])

-- | Upsert one credential row (full document plus the redundant
-- key column, which loads cross-check). Callers dedupe
-- first-wins ('firstByCredential'), matching the memory
-- backend and the validated projection.
putCredentialStmt :: CredentialRecord -> (Text, [S.SQLData])
putCredentialStmt c =
  ( "INSERT OR REPLACE INTO credentials (token_id, record_json, format_version) VALUES (?, ?, 1)"
  , [ S.SQLText (T.pack (encodeHex16 (unTokenId (crToken c))))
    , S.SQLText (T.pack (encodeCredentialRecord c))
    ]
  )

-- | Keep the first put per home token (the 'firstByToken'
-- precedent: the validated projection and the memory backend
-- both resolve duplicate puts first-wins).
firstByCredential :: [CredentialRecord] -> [CredentialRecord]
firstByCredential = go []
  where
    go :: [TokenId] -> [CredentialRecord] -> [CredentialRecord]
    go _ [] = []
    go seen (c : rest)
      | crToken c `elem` seen = go seen rest
      | otherwise = c : go (crToken c : seen) rest

-- | Upsert one job row (full document plus redundant key columns).
putJobStmt :: JobRecord -> (Text, [S.SQLData])
putJobStmt j =
  ( "INSERT OR REPLACE INTO detached_jobs (persistent_id_key, token_id, token_generation_key, function_name, execution_state, record_json, format_version) VALUES (?, ?, ?, ?, ?, ?, 1)"
  , [ S.SQLBlob (encodeBlobW64 (jrPersistentId j))
    , S.SQLText (T.pack (encodeHex16 (unTokenId (jrToken j))))
    , S.SQLBlob (encodeBlob8 (unGeneration (jrTokenGeneration j)))
    , S.SQLText (T.pack (jrFunction j))
    , S.SQLText (T.pack (execStateName (jrState j)))
    , S.SQLText (T.pack (encodeJobRecord j))
    ]
  )

-- | Upsert one token row. An ordinary same-id update preserves the
-- parent row — and therefore every owned object and job — while a
-- conflicting slot still refuses (never silently replacing another
-- token's row). Only an explicit token drop or reset removes
-- children; foreign keys stay on.
putTokenStmt :: TokenRecord -> (Text, [S.SQLData])
putTokenStmt t =
  ( "INSERT INTO tokens (token_id, slot_key, generation_key, record_json, format_version) VALUES (?, ?, ?, ?, 1) ON CONFLICT(token_id) DO UPDATE SET slot_key = excluded.slot_key, generation_key = excluded.generation_key, record_json = excluded.record_json, format_version = excluded.format_version"
  , [ S.SQLText (T.pack (encodeHex16 (unTokenId (trId t))))
    , S.SQLBlob (encodeBlob8 (unSlotId (trSlot t)))
    , S.SQLBlob (encodeBlob8 (unGeneration (trGeneration t)))
    , S.SQLText (T.pack (encodeTokenRecord t))
    ]
  )

-- | Park one token on a staging slot. The row keeps its
-- 'token_id' (a put for a not-yet-existing token matches nothing
-- and changes nothing); owned objects and jobs keep referencing
-- the same parent throughout.
stageTokenStmt :: Int -> TokenRecord -> (Text, [S.SQLData])
stageTokenStmt tmp t =
  ( "UPDATE tokens SET slot_key = ? WHERE token_id = ?"
  , [ S.SQLBlob (encodeBlob8 tmp)
    , S.SQLText (T.pack (encodeHex16 (unTokenId (trId t))))
    ]
  )

-- | Keep the first put per token id. The validated projection
-- ('checkSlotUnique') and the memory backend both resolve
-- duplicate puts first-wins, so staging and upserting only the
-- first occurrence commits exactly what validation approved.
firstByToken :: [TokenRecord] -> [TokenRecord]
firstByToken = go []
  where
    go :: [TokenId] -> [TokenRecord] -> [TokenRecord]
    go _ [] = []
    go seen (t : rest)
      | trId t `elem` seen = go seen rest
      | otherwise = t : go (trId t : seen) rest

-- | Pick @n@ staging slots disjoint from every occupied slot
-- (current plus final). Candidates cover the whole 'Int' range
-- from zero upward (reaching the negatives only past
-- 'maxBound'), skipping anything occupied, so the result never
-- collides with a live slot however slots are valued — including
-- at the range boundaries, where ascending past the maximum
-- alone would run dry.
pickTempSlots :: [Int] -> Int -> [Int]
pickTempSlots occupied n =
  take n [c | c <- [0 .. maxBound] ++ [minBound .. -1], c `notElem` occupied]

-- | Decode one @slot_key@ cell.
parseSlotKey :: [S.SQLData] -> Maybe Int
parseSlotKey [S.SQLBlob b] = decodeBlob8 b
parseSlotKey _ = Nothing

-- | Upsert one meta row.
putMetaStmt :: (String, String) -> (Text, [S.SQLData])
putMetaStmt (k, v) =
  ( "INSERT OR REPLACE INTO store_meta(key, value) VALUES (?, ?)"
  , [S.SQLText (T.pack k), S.SQLText (T.pack v)]
  )

-- | Upsert one object row.
putObjectStmt :: ObjectPut -> (Text, [S.SQLData])
putObjectStmt p =
  let o = opRecord p
  in ( "INSERT OR REPLACE INTO objects (object_id, token_id, class_key, key_type_key, attributes_json, material_encoding, material_blob, revision, format_version) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)"
     , [ S.SQLText (T.pack (encodeHex16 (unObjectId (orId o))))
       , S.SQLText (T.pack (encodeHex16 (unTokenId (orToken o))))
       , S.SQLBlob (encodeBlobW64 (orClass o))
       , maybe S.SQLNull (S.SQLBlob . encodeBlobW64) (orKeyType o)
       , S.SQLText (T.pack (encodeAttrsDoc (orAttrs o)))
       , S.SQLText (T.pack (orMaterialEncoding o))
       , maybe S.SQLNull S.SQLBlob (orMaterial o)
       , S.SQLInteger (fromIntegral (unRevision (orRevision o)))
       ]
     )

-- | Run a parameterized statement expecting no result rows.
execParams :: S.Database -> Text -> [S.SQLData] -> IO (Either StoreError ())
execParams db sql params = trySQLite $ bracket (S.prepare db sql) S.finalize $ \stmt -> do
  S.bind stmt params
  _ <- S.step stmt
  pure ()

-- | Run a parameterized query, collecting every row.
queryRows :: S.Database -> Text -> [S.SQLData] -> IO (Either StoreError [[S.SQLData]])
queryRows db sql params = trySQLite $ bracket (S.prepare db sql) S.finalize $ \stmt -> do
  S.bind stmt params
  collect stmt
  where
    collect :: S.Statement -> IO [[S.SQLData]]
    collect stmt = do
      r <- S.step stmt
      case r of
        S.Done -> pure []
        S.Row -> do
          row <- S.columns stmt
          rest <- collect stmt
          pure (row : rest)

-- | Run a SQLite action, converting 'S.SQLError' to 'StoreIO'
-- ('StoreFull' for a real SQLITE_FULL). Async exceptions do not
-- match 'S.SQLError' and propagate.
trySQLite :: forall a. IO a -> IO (Either StoreError a)
trySQLite act = do
  e <- try act
  pure (either (Left . toStore) Right (e :: Either S.SQLError a))
  where
    toStore :: S.SQLError -> StoreError
    toStore err
      | S.sqlError err == S.ErrorFull = StoreFull (show err)
      | otherwise = StoreIO (show err)

-- | Run a filesystem action, converting 'IOError' to 'StoreIO'.
tryStoreIO :: IO a -> IO (Either StoreError a)
tryStoreIO act = do
  e <- tryIOError act
  pure (either (Left . StoreIO . show) Right e)

-- | Close a handle best-effort (failure paths; errors ignored).
closeQuiet :: S.Database -> IO ()
closeQuiet db = do
  _ <- trySQLite (S.close db)
  pure ()

-- | Roll back best-effort (exception-path cleanup before the
-- handle close; errors ignored).
rollbackQuiet :: S.Database -> IO ()
rollbackQuiet db = do
  _ <- trySQLite (S.exec db "ROLLBACK")
  pure ()

-- | Encode a non-negative 'Int' as an 8-byte big-endian blob.
encodeBlob8 :: Int -> ByteString
encodeBlob8 n = BS.pack
  [ fromIntegral ((w `shiftR` s) .&. 0xFF) | s <- [56, 48 .. 0] ]
  where
    w :: Word64
    w = fromIntegral n

-- | Decode an 8-byte big-endian blob into a non-negative 'Int';
-- wrong lengths and out-of-range values fail.
decodeBlob8 :: ByteString -> Maybe Int
decodeBlob8 bs
  | BS.length bs /= 8 = Nothing
  | w > fromIntegral (maxBound :: Int) = Nothing
  | otherwise = Just (fromIntegral w)
  where
    w :: Word64
    w = BS.foldl' (\acc b -> acc * 256 + fromIntegral b) 0 bs

-- | Decode a bounded revision counter; rejects non-positive and
-- out-of-range values (never a blind cast).
decodeRevision :: Int64 -> Maybe Int
decodeRevision n
  | n >= 1 && n <= fromIntegral (maxBound :: Int) = Just (fromIntegral n)
  | otherwise = Nothing

-- | Encode a 'Word64' persistent id as an 8-byte big-endian blob
-- (the whole domain, no narrowing).
encodeBlobW64 :: Word64 -> ByteString
encodeBlobW64 w = BS.pack
  [ fromIntegral ((w `shiftR` s) .&. 0xFF) | s <- [56, 48 .. 0] ]

-- | Decode an 8-byte big-endian blob into a 'Word64'; wrong
-- lengths fail.
decodeBlobW64 :: ByteString -> Maybe Word64
decodeBlobW64 bs
  | BS.length bs /= 8 = Nothing
  | otherwise = Just (BS.foldl' (\acc b -> acc * 256 + fromIntegral b) 0 bs)
