-- | The effective serving catalog, shared by both interval owners.
module Haskoki.Runtime.Catalog
  ( catalogCredential
  , desiredTokens
  , effectiveCatalog
  , homeCatalogEntry
  , identityCatalog
  , tokenSerial
  ) where

import qualified Data.ByteString.Char8 as BC8
import qualified Data.Map.Strict as Map
import Data.Map.Strict (Map)

import Haskoki.Runtime.Config (Config (..), TokensCfg (..))
import Haskoki.Runtime.Storage (CredentialRecord (..), DesiredToken (..), encodeHex16)
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

-- | The configured catalog as the reconciler sees it: one desired
-- token per catalog slot, slot ascending. The serving open and the
-- offline preflight both compare stores through this one projection.
desiredTokens :: Config -> [DesiredToken]
desiredTokens cfg =
  [ DesiredToken slot tid label
  | (slot, (tid, label)) <- Map.toAscList (identityCatalog cfg)
  ]

-- | The credential row the catalog selects for one identity: the SO
-- and user PIN of the one slot that carries it ('Nothing' when no
-- slot, or more than one, carries it). A fresh token's seed and a
-- legacy token's migration freeze both write exactly this row.
catalogCredential :: Config -> TokenId -> Maybe CredentialRecord
catalogCredential cfg tid =
  case [slot | (slot, (t, _)) <- Map.toList (identityCatalog cfg), t == tid] of
    [slot] -> do
      (_, so, user) <- Map.lookup slot (effectiveCatalog cfg)
      pure (CredentialRecord tid (BC8.pack so) (Just (BC8.pack user)))
    _ -> Nothing

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
