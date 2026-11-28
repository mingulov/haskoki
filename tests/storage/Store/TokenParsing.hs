{- | Store token identity parsing cases.
-}
{-# LANGUAGE OverloadedStrings #-}
module Store.TokenParsing
  ( caseAbsentIdsPositional
  , caseCatalogCredentialByIdentity
  , caseDesiredTokensProject
  , caseDuplicateDesiredRefuses
  , caseDuplicateIdsRefused
  , caseIdsWithoutLabelsRefused
  , caseMalformedIdsRefused
  , caseMismatchFallsBack
  , caseNonHomeIdRefused
  , casePinnedIdsParse
  , caseRaggedIdsRefused
  , caseReconcilerHomeAnchor
  , caseTokenSerialCanonical
  , caseTokensWithoutCredentials
  ) where

import qualified Data.Map.Strict as Map
import Test.Tasty.HUnit (assertBool, assertEqual, assertFailure)
import Haskoki.Runtime.Storage
  ( CredentialRecord (..)
  , DesiredToken (..)
  , IdentityRefusal (..)
  , TokenRecord (..)
  , encodeHex16
  , reconcileIdentities
  , tokensWithoutCredentials
  )
import Haskoki.Runtime.Catalog (catalogCredential, desiredTokens, effectiveCatalog, identityCatalog, tokenSerial)
import Haskoki.Runtime.Config
  ( Config (..)
  , ConfigError (..)
  , parseConfig
  )
import Haskoki.Session (tokenAuthNew)
import Haskoki.Types
  ( Generation (..)
  , SlotId (..)
  , TokenId (..)
  )
import Store.Fixtures

-- | A catalog document must refuse as 'CfgInvalid'.
expectInvalid :: String -> String -> IO ()
expectInvalid ctx body = case parseConfig body of
  Left (CfgInvalid _) -> pure ()
  Left err -> assertFailure (ctx ++ ": wrong refusal: " ++ show err)
  Right _ -> assertFailure (ctx ++ ": bad catalog parsed")

-- | Pinned @token_ids@ parse and project onto both catalogs:
-- identities pin per entry while the serving triples stay
-- positional.
casePinnedIdsParse :: IO ()
casePinnedIdsParse = do
  cfg <- parseCatalog (catalogDoc threeLabels threeSo threeUser ["1", "2", "3"])
  assertEqual "pinned ids" (Just [TokenId 1, TokenId 2, TokenId 3]) (cfgTokenIds cfg)
  assertEqual "identity projection"
    [ (SlotId 0, (TokenId 1, "haskoki-demo"))
    , (SlotId 1, (TokenId 2, "haskoki-ops"))
    , (SlotId 2, (TokenId 3, "haskoki-audit"))
    ]
    (Map.toAscList (identityCatalog cfg))
  assertEqual "serving triples stay positional"
    (zip3 threeLabels threeSo threeUser)
    [triple | (_, triple) <- Map.toAscList (effectiveCatalog cfg)]

-- | A duplicate pinned identity refuses the whole config.
caseDuplicateIdsRefused :: IO ()
caseDuplicateIdsRefused =
  expectInvalid "duplicate ids" (catalogDoc threeLabels threeSo threeUser ["1", "2", "2"])

-- | Pinned ids ragged against the labels refuse.
caseRaggedIdsRefused :: IO ()
caseRaggedIdsRefused =
  expectInvalid "ragged ids" (catalogDoc threeLabels threeSo threeUser ["1", "2"])

-- | Non-decimal, zero, and out-of-range ids refuse.
caseMalformedIdsRefused :: IO ()
caseMalformedIdsRefused = do
  expectInvalid "non-decimal id"
    (catalogDoc threeLabels threeSo threeUser ["1", "two", "3"])
  expectInvalid "zero id"
    (catalogDoc threeLabels threeSo threeUser ["1", "0", "3"])
  expectInvalid "oversized id"
    (catalogDoc threeLabels threeSo threeUser ["1", "4294967296", "3"])

-- | Slot 0 must carry @TokenId 1@: a pinned catalog that seats
-- anything else at slot 0 refuses.
caseNonHomeIdRefused :: IO ()
caseNonHomeIdRefused =
  expectInvalid "non-home slot zero" (catalogDoc threeLabels threeSo threeUser ["2", "1", "3"])

-- | Without @token_ids@ the catalog reads positionally.
caseAbsentIdsPositional :: IO ()
caseAbsentIdsPositional = do
  cfg <- parseCatalog positionalDoc
  assertEqual "no pinned ids" Nothing (cfgTokenIds cfg)
  assertEqual "positional projection" [TokenId 1, TokenId 2, TokenId 3]
    [tid | (_, (tid, _)) <- Map.toAscList (identityCatalog cfg)]

-- | Pinned ids without any labeled entry refuse.
caseIdsWithoutLabelsRefused :: IO ()
caseIdsWithoutLabelsRefused =
  expectInvalid "ids without labels" (unlines
    [ "schema_version = 1"
    , "[tokens]"
    , "token_ids = [\"1\"]"
    ])

-- | A hand-built config whose pinned list mismatches the
-- entries falls back to positional for every slot (total,
-- never a silent mix).
caseMismatchFallsBack :: IO ()
caseMismatchFallsBack = do
  cfg <- parseCatalog (catalogDoc threeLabels threeSo threeUser ["1", "2", "3"])
  let short = cfg { cfgTokenIds = Just [TokenId 1] }
      dropped = cfg { cfgTokenIds = Nothing }
      positional = [TokenId 1, TokenId 2, TokenId 3]
      project c = [tid | (_, (tid, _)) <- Map.toAscList (identityCatalog c)]
  assertEqual "short list falls back" positional (project short)
  assertEqual "dropped list falls back" positional (project dropped)

-- | The reconciler refuses duplicate desired identities even
-- for hand-built inputs (defense behind the parser check).
caseDuplicateDesiredRefuses :: IO ()
caseDuplicateDesiredRefuses =
  case reconcileIdentities
    [ DesiredToken (SlotId 1) (TokenId 2) "haskoki-ops"
    , DesiredToken (SlotId 2) (TokenId 2) "haskoki-dup"
    ] [] of
    Left (RefuseDuplicateDesired tid) -> assertEqual "duplicate id" (TokenId 2) tid
    other -> assertFailure ("duplicate desired identity must refuse: " ++ show other)

-- | The reconciler enforces the home anchor in both
-- directions: @TokenId 1@ sits at @SlotId 0@ only, and
-- @SlotId 0@ holds @TokenId 1@ only.
caseReconcilerHomeAnchor :: IO ()
caseReconcilerHomeAnchor = do
  case reconcileIdentities [DesiredToken (SlotId 2) (TokenId 1) "haskoki-demo"] [] of
    Left (RefuseHomeAnchor tid slot) -> do
      assertEqual "home token" (TokenId 1) tid
      assertEqual "home slot" (SlotId 2) slot
    other -> assertFailure ("home token away from slot 0 must refuse: " ++ show other)
  case reconcileIdentities [DesiredToken (SlotId 0) (TokenId 5) "haskoki-demo"] [] of
    Left (RefuseHomeAnchor tid slot) -> do
      assertEqual "intruder token" (TokenId 5) tid
      assertEqual "intruder slot" (SlotId 0) slot
    other -> assertFailure ("intruder at slot 0 must refuse: " ++ show other)

-- | The serial projection is the stored 16-hex identity encoding:
-- lowercase, fixed width, and the same bytes 'encodeHex16' writes
-- for @token_id@ (ids above 9 tell hex from the old decimal form).
caseTokenSerialCanonical :: IO ()
caseTokenSerialCanonical = do
  assertEqual "home serial" "0000000000000001" (tokenSerial (TokenId 1))
  assertEqual "id 26 serial" "000000000000001a" (tokenSerial (TokenId 26))
  let top = tokenSerial (TokenId 0x7fffffff)
  assertEqual "max id serial" "000000007fffffff" top
  assertEqual "max id serial width" 16 (length top)
  assertBool "max id serial lowercase hex" (all (`elem` ("0123456789abcdef" :: String)) top)
  assertEqual "serial is the stored id encoding"
    (encodeHex16 0x7fffffff) top

caseDesiredTokensProject :: IO ()
caseDesiredTokensProject = do
  cfg <- parseCatalog swappedDoc
  assertEqual "desired tokens follow the pinned ids"
    [ DesiredToken (SlotId 0) (TokenId 1) "haskoki-demo"
    , DesiredToken (SlotId 1) (TokenId 3) "haskoki-audit"
    , DesiredToken (SlotId 2) (TokenId 2) "haskoki-ops"
    ]
    (desiredTokens cfg)

caseCatalogCredentialByIdentity :: IO ()
caseCatalogCredentialByIdentity = do
  cfg <- parseCatalog swappedDoc
  assertEqual "id 3 takes slot 1's PINs"
    (Just (CredentialRecord (TokenId 3) "7890" (Just "3456")))
    (catalogCredential cfg (TokenId 3))
  assertEqual "id 2 takes slot 2's PINs"
    (Just (CredentialRecord (TokenId 2) "6789" (Just "2345")))
    (catalogCredential cfg (TokenId 2))
  assertEqual "an unconfigured id has no catalog credential"
    Nothing (catalogCredential cfg (TokenId 9))

caseTokensWithoutCredentials :: IO ()
caseTokensWithoutCredentials = do
  let tok n = TokenRecord (TokenId n) (SlotId (fromIntegral n - 1)) (Generation 0) "t" tokenAuthNew
  assertEqual "rowless ids, ascending"
    [TokenId 1, TokenId 3]
    (tokensWithoutCredentials [tok 3, tok 2, tok 1] [TokenId 2])
  assertEqual "no tokens, no gaps" [] (tokensWithoutCredentials [] [TokenId 2])
