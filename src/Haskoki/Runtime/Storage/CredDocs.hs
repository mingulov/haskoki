{- | Detached credential documents.
-}
module Haskoki.Runtime.Storage.CredDocs
  ( encodeCredentialRecord
  , decodeCredentialRecord
  ) where

import Haskoki.Types
  ( TokenId (..)
  )
import Haskoki.Runtime.Storage.Base64
import Haskoki.Runtime.Storage.Encoding
import Haskoki.Runtime.Storage.FixedHex
import Haskoki.Runtime.Storage.Records

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
