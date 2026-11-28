{- | Detached token documents.
-}
module Haskoki.Runtime.Storage.TokenDocs
  ( encodeTokenRecord
  , encodeAuth
  , decodeTokenRecord
  , decodeAuth
  ) where

import Haskoki.Session
  ( TokenAuth (..)
  )
import Haskoki.Types
  ( Generation (..)
  , SlotId (..)
  , TokenId (..)
  )
import Haskoki.Runtime.Storage.Encoding
import Haskoki.Runtime.Storage.FixedHex
import Haskoki.Runtime.Storage.Records

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
