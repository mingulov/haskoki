-- | The effective serving catalog, shared by both interval owners.
module Haskoki.Runtime.Catalog
  ( effectiveCatalog
  , homeCatalogEntry
  , identityCatalog
  , tokenSerial
  ) where

import qualified Data.Map.Strict as Map
import Data.Map.Strict (Map)

import Haskoki.Runtime.Config (Config (..), TokensCfg (..))
import Haskoki.Runtime.Storage (encodeHex16)
import Haskoki.Types (SlotId (..), TokenId (..))

-- | Label, SO PIN, user PIN. The absent-section provisioning is unchanged.
homeCatalogEntry :: (String, String, String)
homeCatalogEntry = ("haskoki-demo", "5678", "1234")

-- | Declared catalog indices, or the home singleton when absent.
effectiveCatalog :: Config -> Map SlotId (String, String, String)
effectiveCatalog cfg = case tcEntries (cfgTokens cfg) of
  [] -> Map.singleton (SlotId 0) homeCatalogEntry
  triples -> Map.fromList (zip [SlotId n | n <- [0 ..]] triples)

-- | Declared catalog identities: slot to (stable identity,
-- label), or the home singleton (@TokenId 1@, @haskoki-demo@)
-- when the section is absent. Pinned @token_ids@ win when
-- present and rectangular with the entries (the parser upholds
-- this); otherwise the legacy positional reading applies (slot
-- @n@ owns @TokenId (n+1)@). Total: a hand-built config whose
-- pinned list mismatches the entries falls back to positional
-- for every slot, never a silent mix.
identityCatalog :: Config -> Map SlotId (TokenId, String)
identityCatalog cfg = case tcEntries (cfgTokens cfg) of
  [] ->
    let (homeLabel, _, _) = homeCatalogEntry
    in Map.singleton (SlotId 0) (TokenId 1, homeLabel)
  triples ->
    let ids = pinnedOrPositional (length triples) (cfgTokenIds cfg)
    in Map.fromList
      [(SlotId n, (tid, label)) | (n, (label, _, _), tid) <- zip3 [0 ..] triples ids]

-- | Pinned identities when rectangular, else legacy positional.
pinnedOrPositional :: Int -> Maybe [TokenId] -> [TokenId]
pinnedOrPositional n (Just ids) | length ids == n = ids
pinnedOrPositional n _ = [TokenId (k + 1) | k <- [0 .. n - 1]]

-- | The token's @CK_TOKEN_INFO.serialNumber@: its durable identity
-- in the one canonical 16-char lowercase-hex form the store
-- writes for @token_id@ ('encodeHex16'), so the serial depends
-- on the identity alone (never on slot, label or store). Every
-- identity the config parser admits (@1..2147483647@) fits the
-- 16 characters exactly.
tokenSerial :: TokenId -> String
tokenSerial = encodeHex16 . unTokenId
