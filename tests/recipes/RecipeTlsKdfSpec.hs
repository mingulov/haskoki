{- | TLS-KDF recipe pins (slice 11i).

'Haskoki.Recipe.TlsKdf' owns the canonical codec, parameter
validation, and the eight-row table; 'Haskoki.Operation.Derive'
owns admission; 'Haskoki.Engine.Driver' owns the
params-to-execution mapping. This spec pins all three against
the table: the table shape, id resolution, codec identity, the
per-kind parameter matrix (fixed labels, seed widths, PRF
range, context rules, ceilings), the PRF mechanism map, one
planDerive accept\/deny pair, and the driver mapping.

Reference vectors (independent python construction, oracle
reference, provider TLS1-PRF CLI agree where the oracle
covers the row; DH legs are own vectors):

* 0x375 master\/48: 53939182...
* 0x3e0 master\/48: 2b7cccb6...
* 0x3d9 kdf\/32: 4ac38c4d...
* 0x3d9 kdf-ctx\/32: 5c0125c5...
* 0x56 ext\/48: c3d5ea08...
* 0x3e5 tlsprf\/32: 023d49a0...
-}
{-# LANGUAGE OverloadedStrings #-}
module RecipeTlsKdfSpec (spec) where

import qualified Data.ByteString as BS
import qualified Data.Map.Strict as Map
import Data.Word (Word64)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertBool, assertEqual, assertFailure, testCase)

import Haskoki.Attribute (AttributeType (..), AttributeValue (..))
import Haskoki.Engine.Backend (DigestAlg (..))
import Haskoki.Engine.Driver (TlsKdfExec (..), tlsKdfParamsFor)
import Haskoki.FFI.NativeParams
  ( tlsKdfExtStructToCanonical
  , tlsKdfFreeStructToCanonical
  , tlsKdfMasterStructToCanonical
  , tlsKdfTls12MasterStructToCanonical
  )
import Haskoki.Model
  ( HandleBinding (..)
  , Model (..)
  , ObjectState (..)
  , SessionState (..)
  , emptyModel
  )
import Haskoki.Operation (emptySessionOps)
import Haskoki.Operation.Derive
  ( encodeDeriveParams
  , planDerive
  )
import Haskoki.Operation.Effect (CryptoEffect (..))
import Haskoki.Operation.KeyManagement
  ( KeyDeny (..)
  , KeyPlan (..)
  , ckkGenericSecret
  , ckoSecretKey
  )
import Haskoki.Recipe.TlsKdf
import Haskoki.Registry.Generated
  ( ckm_TLS_MASTER_KEY_DERIVE
  , ckm_TLS_MASTER_KEY_DERIVE_DH
  , ckm_TLS12_MASTER_KEY_DERIVE
  , ckm_TLS12_MASTER_KEY_DERIVE_DH
  , ckm_TLS12_EXTENDED_MASTER_KEY_DERIVE
  , ckm_TLS12_EXTENDED_MASTER_KEY_DERIVE_DH
  , ckm_TLS12_KDF
  , ckm_TLS_KDF
  , ckm_TLS_PRF
  , ckm_SHA256
  , ckm_SHA384
  , ckm_SHA256_RSA_PKCS
  , ckm_MD2_HMAC
  )
import Haskoki.Registry.Types (MechanismId (..))
import Haskoki.Rules (defaultRules)
import Haskoki.Session (SessionLogin (..))
import Haskoki.Types
  ( ExternalHandle (..)
  , Generation (..)
  , ObjectId (..)
  , ReturnCode (..)
  , Revision (..)
  , SessionId (..)
  , SlotId (..)
  )

spec :: TestTree
spec = testGroup "TLS-KDF recipe"
  [ testCase "table: eight rows with kinds" caseTable
  , testCase "lookup: ids resolve, others do not" caseLookup
  , testCase "codec identity" caseCodec
  , testCase "params: per-kind matrix" caseParams
  , testCase "PRF mechanisms map to codes" casePrfCodes
  , testCase "planDerive: accept and deny" casePlan
  , testCase "driver maps the pair to the exec tuple" caseDriverMap
  , testCase "native structs translate" caseNative
  ]

caseTable :: IO ()
caseTable = assertEqual "eight rows" expected
  [(tkName r, tkKind r) | r <- tlsKdfRecipes]
  where
    expected =
      [ ("CKM_TLS_MASTER_KEY_DERIVE", TlsMaster10)
      , ("CKM_TLS_MASTER_KEY_DERIVE_DH", TlsMaster10)
      , ("CKM_TLS12_MASTER_KEY_DERIVE", TlsMaster12)
      , ("CKM_TLS12_MASTER_KEY_DERIVE_DH", TlsMaster12)
      , ("CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE", TlsExtended12)
      , ("CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE_DH", TlsExtended12)
      , ("CKM_TLS12_KDF", TlsKdfFree)
      , ("CKM_TLS_KDF", TlsKdfFree)
      ]

caseLookup :: IO ()
caseLookup = do
  mapM_ resolves
    [ ckm_TLS_MASTER_KEY_DERIVE
    , ckm_TLS_MASTER_KEY_DERIVE_DH
    , ckm_TLS12_MASTER_KEY_DERIVE
    , ckm_TLS12_MASTER_KEY_DERIVE_DH
    , ckm_TLS12_EXTENDED_MASTER_KEY_DERIVE
    , ckm_TLS12_EXTENDED_MASTER_KEY_DERIVE_DH
    , ckm_TLS12_KDF
    , ckm_TLS_KDF
    ]
  assertEqual "other id" Nothing (tlsKdfRecipeFor (MechanismId 0x3dc))
  where
    resolves i = assertBool ("resolves " ++ show i)
      (case tlsKdfRecipeFor (MechanismId i) of Just _ -> True; Nothing -> False)

caseCodec :: IO ()
caseCodec = do
  let frame = encodeTlsKdfParams 4 "key expansion" (BS.replicate 64 7) "context-info"
  assertEqual "roundtrip" (Just (4, "key expansion", BS.replicate 64 7, "context-info"))
    (decodeTlsKdfParams frame)
  let master = encodeTlsKdfParams 0 "master secret" (BS.replicate 64 1) BS.empty
  assertEqual "master roundtrip" (Just (0, "master secret", BS.replicate 64 1, BS.empty))
    (decodeTlsKdfParams master)

resolveTlsKdf :: Word64 -> IO TlsKdfRecipe
resolveTlsKdf mid = case tlsKdfRecipeFor (MechanismId mid) of
  Just r -> pure r
  Nothing -> assertFailure ("recipe must resolve " ++ show mid)

caseParams :: IO ()
caseParams = do
  r10 <- resolveTlsKdf ckm_TLS_MASTER_KEY_DERIVE
  r12 <- resolveTlsKdf ckm_TLS12_MASTER_KEY_DERIVE
  rExt <- resolveTlsKdf ckm_TLS12_EXTENDED_MASTER_KEY_DERIVE
  rKdf <- resolveTlsKdf ckm_TLS12_KDF
  rGen <- resolveTlsKdf ckm_TLS_KDF
  let seed64 = BS.replicate 64 9
      sess32 = BS.replicate 32 3
  -- Valid shapes.
  assertBool "master10 valid"
    (tlsKdfParamsValid r10 (encodeTlsKdfParams 0 "master secret" seed64 BS.empty))
  assertBool "master12 valid"
    (tlsKdfParamsValid r12 (encodeTlsKdfParams 4 "master secret" seed64 BS.empty))
  assertBool "extended valid"
    (tlsKdfParamsValid rExt (encodeTlsKdfParams 4 "extended master secret" sess32 BS.empty))
  assertBool "kdf valid"
    (tlsKdfParamsValid rKdf (encodeTlsKdfParams 4 "key expansion" seed64 "context-info"))
  assertBool "generic legacy valid"
    (tlsKdfParamsValid rGen (encodeTlsKdfParams 0 "key expansion" seed64 BS.empty))
  assertBool "generic hash valid"
    (tlsKdfParamsValid rGen (encodeTlsKdfParams 5 "key expansion" seed64 BS.empty))
  -- Refused shapes.
  assertBool "master10 hash refused"
    (not (tlsKdfParamsValid r10 (encodeTlsKdfParams 4 "master secret" seed64 BS.empty)))
  assertBool "master12 legacy refused"
    (not (tlsKdfParamsValid r12 (encodeTlsKdfParams 0 "master secret" seed64 BS.empty)))
  assertBool "master10 label fixed"
    (not (tlsKdfParamsValid r10 (encodeTlsKdfParams 0 "other" seed64 BS.empty)))
  assertBool "extended label fixed"
    (not (tlsKdfParamsValid rExt (encodeTlsKdfParams 4 "master secret" sess32 BS.empty)))
  assertBool "kdf label required"
    (not (tlsKdfParamsValid rKdf (encodeTlsKdfParams 4 BS.empty seed64 BS.empty)))
  assertBool "master10 seed 64"
    (not (tlsKdfParamsValid r10 (encodeTlsKdfParams 0 "master secret" sess32 BS.empty)))
  assertBool "extended seed short refused"
    (not (tlsKdfParamsValid rExt (encodeTlsKdfParams 4 "extended master secret" (BS.replicate 8 1) BS.empty)))
  assertBool "master ctx refused"
    (not (tlsKdfParamsValid r10 (encodeTlsKdfParams 0 "master secret" seed64 "x")))
  assertBool "legacy ctx refused"
    (not (tlsKdfParamsValid rGen (encodeTlsKdfParams 0 "key expansion" seed64 "x")))
  assertBool "prf code range"
    (not (tlsKdfParamsValid rKdf (encodeTlsKdfParams 14 "key expansion" seed64 BS.empty)))
  assertBool "truncation refused"
    (not (tlsKdfParamsValid rKdf (BS.take 3 (encodeTlsKdfParams 4 "key expansion" seed64 BS.empty))))
  assertBool "trailing refused"
    (not (tlsKdfParamsValid rKdf (encodeTlsKdfParams 4 "key expansion" seed64 BS.empty <> "x")))
  assertBool "ceiling refused"
    (not (tlsKdfParamsValid rKdf (encodeTlsKdfParams 4 (BS.replicate 70000 1) seed64 BS.empty)))

casePrfCodes :: IO ()
casePrfCodes = do
  assertEqual "TLS_PRF is legacy" (Just 0) (tlsKdfPrfCodeFor (MechanismId ckm_TLS_PRF))
  assertEqual "SHA256 code" (Just 4) (tlsKdfPrfCodeFor (MechanismId ckm_SHA256))
  assertEqual "SHA384 code" (Just 5) (tlsKdfPrfCodeFor (MechanismId ckm_SHA384))
  assertEqual "RSA is no PRF" Nothing (tlsKdfPrfCodeFor (MechanismId ckm_SHA256_RSA_PKCS))
  assertEqual "unserved HMAC is no PRF" Nothing (tlsKdfPrfCodeFor (MechanismId ckm_MD2_HMAC))

-- planDerive pins (light model harness: one secret base key + handle)
-- ---------------------------------------------------------------------------

baseOid :: ObjectId
baseOid = ObjectId 44

baseHandle :: ExternalHandle
baseHandle = ExternalHandle 404

testSession :: SessionState
testSession = SessionState
  { ssId = SessionId 1
  , ssSlot = SlotId 7
  , ssRevision = Revision 1
  , ssGeneration = Generation 1
  , ssReadOnly = False
  , ssLogin = LoginPublic
  , ssOps = emptySessionOps
  }

mkBaseModel :: BS.ByteString -> Bool -> Model
mkBaseModel mat canDerive = emptyModel
  { mObjects = Map.fromList [(baseOid, ost)]
  , mHandles = Map.fromList [(baseHandle, HandleBinding baseOid (Generation 1))]
  }
  where
    ost = ObjectState
      { osId = baseOid
      , osRevision = Revision 1
      , osGeneration = Generation 1
      , osAttrs = Map.fromList
          [ (AttrClass, ValULong ckoSecretKey)
          , (AttrKeyType, ValULong ckkGenericSecret)
          , (AttrPrivate, ValBool False)
          , (AttrDerive, ValBool canDerive)
          , (AttrValue, ValBytes mat)
          ]
      , osOwner = Nothing
      , osSlot = SlotId 7
      }

derivedTmpl :: Int -> [(AttributeType, AttributeValue)]
derivedTmpl n =
  [ (AttrClass, ValULong ckoSecretKey)
  , (AttrKeyType, ValULong ckkGenericSecret)
  , (AttrValueLen, ValULong (fromIntegral n))
  , (AttrToken, ValBool False)
  ]

masterMech :: MechanismId
masterMech = MechanismId ckm_TLS_MASTER_KEY_DERIVE

kdfMech :: MechanismId
kdfMech = MechanismId ckm_TLS12_KDF

masterFrame :: BS.ByteString
masterFrame = encodeTlsKdfParams 0 "master secret" (BS.replicate 64 1) BS.empty

kdfFrame :: BS.ByteString
kdfFrame = encodeTlsKdfParams 4 "key expansion" (BS.replicate 64 2) BS.empty

expectDeny :: String -> ReturnCode -> KeyPlan -> IO ()
expectDeny label code plan = case plan of
  KeyDenied (KeyDeny c _) -> assertEqual ("deny " ++ label) code c
  other -> assertFailure ("expected denial, got " ++ show other)

casePlan :: IO ()
casePlan = do
  let m = mkBaseModel "secret" True
  -- Accepted: the master frame plus a VALUE_LEN template.
  case planDerive defaultRules m testSession masterMech baseHandle
      (encodeDeriveParams masterFrame [derivedTmpl 48]) of
    KeyEffect _ (FxDerive mech (Just oid) Nothing params info total) -> do
      assertEqual "mech" masterMech mech
      assertEqual "base" baseOid oid
      assertEqual "params" masterFrame params
      assertEqual "info empty" BS.empty info
      assertEqual "total" 48 total
    other -> assertFailure ("expected effect, got " ++ show other)
  -- Accepted: the free frame plus a VALUE_LEN template.
  case planDerive defaultRules m testSession kdfMech baseHandle
      (encodeDeriveParams kdfFrame [derivedTmpl 32]) of
    KeyEffect _ (FxDerive mech (Just oid) Nothing params info total) -> do
      assertEqual "mech" kdfMech mech
      assertEqual "base" baseOid oid
      assertEqual "params" kdfFrame params
      assertEqual "info empty" BS.empty info
      assertEqual "total" 32 total
    other -> assertFailure ("expected effect, got " ++ show other)
  -- Malformed frames refuse typed.
  expectDeny "junk params" CKR_ARGUMENTS_BAD
    (planDerive defaultRules m testSession masterMech baseHandle
      (encodeDeriveParams "junk" [derivedTmpl 48]))
  -- Output past the ceiling refuses typed.
  expectDeny "over ceiling" CKR_ARGUMENTS_BAD
    (planDerive defaultRules m testSession kdfMech baseHandle
      (encodeDeriveParams kdfFrame [derivedTmpl (maxTlsKdfOutput + 1)]))
  -- A non-derive-marked base refuses typed.
  expectDeny "sealed base" CKR_KEY_FUNCTION_NOT_PERMITTED
    (planDerive defaultRules (mkBaseModel "secret" False) testSession masterMech baseHandle
      (encodeDeriveParams masterFrame [derivedTmpl 48]))

caseDriverMap :: IO ()
caseDriverMap = do
  assertEqual "master pair decodes"
    (Just (TlsKdfExec TlsMaster10 True Nothing "master secret" (BS.replicate 64 1) BS.empty))
    (tlsKdfParamsFor masterMech masterFrame)
  assertEqual "kdf pair decodes"
    (Just (TlsKdfExec TlsKdfFree False (Just D_SHA256) "key expansion" (BS.replicate 64 2) BS.empty))
    (tlsKdfParamsFor kdfMech kdfFrame)
  assertEqual "junk refused" Nothing
    (tlsKdfParamsFor masterMech "junk")

caseNative :: IO ()
caseNative = do
  let cli = BS.replicate 32 1
      srv = BS.replicate 32 2
      seed = cli <> srv
  -- Master: the legacy frame with the fixed label.
  assertEqual "master translates"
    (Just (encodeTlsKdfParams 0 "master secret" seed BS.empty))
    (tlsKdfMasterStructToCanonical cli srv)
  assertEqual "master short random refuses" Nothing
    (tlsKdfMasterStructToCanonical (BS.take 16 cli) srv)
  -- TLS 1.2 master: hash PRFs only.
  assertEqual "tls12 master translates"
    (Just (encodeTlsKdfParams 4 "master secret" seed BS.empty))
    (tlsKdfTls12MasterStructToCanonical ckm_SHA256 cli srv)
  assertEqual "tls12 master legacy refuses" Nothing
    (tlsKdfTls12MasterStructToCanonical ckm_TLS_PRF cli srv)
  assertEqual "tls12 master RSA refuses" Nothing
    (tlsKdfTls12MasterStructToCanonical ckm_SHA256_RSA_PKCS cli srv)
  -- Extended: the session hash rides 16..64 bytes.
  let sess = BS.replicate 32 3
  assertEqual "extended translates"
    (Just (encodeTlsKdfParams 4 "extended master secret" sess BS.empty))
    (tlsKdfExtStructToCanonical ckm_SHA256 sess)
  assertEqual "extended short refuses" Nothing
    (tlsKdfExtStructToCanonical ckm_SHA256 (BS.replicate 8 1))
  assertEqual "extended legacy refuses" Nothing
    (tlsKdfExtStructToCanonical ckm_TLS_PRF sess)
  -- Free: caller label, legacy-or-hash, context on hash only.
  assertEqual "free translates"
    (Just (encodeTlsKdfParams 4 "key expansion" seed "ctx"))
    (tlsKdfFreeStructToCanonical ckm_SHA256 "key expansion" cli srv "ctx")
  assertEqual "free legacy translates"
    (Just (encodeTlsKdfParams 0 "key expansion" seed BS.empty))
    (tlsKdfFreeStructToCanonical ckm_TLS_PRF "key expansion" cli srv BS.empty)
  assertEqual "free empty label refuses" Nothing
    (tlsKdfFreeStructToCanonical ckm_SHA256 BS.empty cli srv BS.empty)
  assertEqual "free legacy ctx refuses" Nothing
    (tlsKdfFreeStructToCanonical ckm_TLS_PRF "key expansion" cli srv "ctx")
