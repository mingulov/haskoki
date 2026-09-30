-- | The effective serving catalog, shared by both interval owners.
module Haskoki.Runtime.Catalog (effectiveCatalog, homeCatalogEntry) where

import qualified Data.Map.Strict as Map
import Data.Map.Strict (Map)

import Haskoki.Runtime.Config (Config (..), TokensCfg (..))
import Haskoki.Types (SlotId (..))

-- | Label, SO PIN, user PIN. The absent-section provisioning is unchanged.
homeCatalogEntry :: (String, String, String)
homeCatalogEntry = ("haskoki-demo", "5678", "1234")

-- | Declared catalog indices, or the home singleton when absent.
effectiveCatalog :: Config -> Map SlotId (String, String, String)
effectiveCatalog cfg = case tcEntries (cfgTokens cfg) of
  [] -> Map.singleton (SlotId 0) homeCatalogEntry
  triples -> Map.fromList (zip [SlotId n | n <- [0 ..]] triples)
