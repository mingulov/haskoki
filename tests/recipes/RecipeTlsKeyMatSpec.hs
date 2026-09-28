{- | TLS key-material recipe pins (slice 11l).

'Haskoki.Recipe.TlsKeyMat' owns the canonical codec, parameter
validation, and the three-row table; 'Haskoki.Operation.Derive'
owns admission (the template protection-match rule, per-output
lengths from params); 'Haskoki.Engine.Driver' owns the
params-to-execution mapping. This spec pins all three against
the table: the table shape, id resolution, codec identity, the
per-kind parameter matrix (PRF rules, sizes, random widths,
ceilings), the base key types, one planDerive accept\/deny set,
and the driver mapping.

Reference vectors (master secret = bytes 0..47, client random =
bytes 0..31, server random = bytes 32..63; seed = server ++
client per RFC 2246 §6.3; cross-checked against the oracle's
own _p_hash\/_tls_prf_legacy_md5_sha1):

* 0x376 tls10 mac0\/key16\/iv16 (64-byte block): f3771f99...
* 0x3e1 tls12-sha256 mac0\/key16\/iv16 (64-byte block):
  fbe0dbb7...
* tls12-sha256 mac20\/key16\/iv16 (104-byte block): fbe0dbb7...
  (first 64 bytes shared with the mac0 block)
-}
{-# LANGUAGE OverloadedStrings #-}
module RecipeTlsKeyMatSpec (spec) where

import qualified Data.ByteString as BS
import qualified Data.Map.Strict as Map
import Data.Word (Word64)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertBool, assertEqual, assertFailure, testCase)

import Haskoki.Attribute (AttributeType (..), AttributeValue (..))
import Haskoki.Engine.Driver (KeyMatExec (..), keyMatParamsFor)
import Haskoki.FFI.NativeParams
  ( tls12KeyMatStructToCanonical
  , tlsKeyMatStructToCanonical
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
  , PendingWork (..)
  , ckkAes
  , ckkGenericSecret
  , ckoSecretKey
  )
import Haskoki.Recipe.TlsKeyMat
import Haskoki.Registry.Generated
  ( ckm_TLS12_KEY_AND_MAC_DERIVE
  , ckm_TLS12_KEY_SAFE_DERIVE
  , ckm_TLS_KEY_AND_MAC_DERIVE
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
spec = testGroup "TlsKeyMat recipe"
  [ testCase "table: three rows with kinds" caseTable
  , testCase "lookup: ids resolve, others do not" caseLookup
  , testCase "codec identity" caseCodec
  , testCase "params: per-kind matrix" caseParams
  , testCase "layout: RFC-ordered segments" caseLayout
  , testCase "base key types" caseBaseTypes
  , testCase "planDerive: accept and deny" casePlan
  , testCase "driver maps the pair to the exec tuple" caseDriverMap
  , testCase "native structs translate" caseNative
  ]

caseTable :: IO ()
caseTable = assertEqual "three rows" expected
  [(tkmName r, tkmKind r) | r <- tlsKeyMatRecipes]
  where
    expected =
      [ ("CKM_TLS_KEY_AND_MAC_DERIVE", KeyMatTls10)
      , ("CKM_TLS12_KEY_AND_MAC_DERIVE", KeyMatTls12)
      , ("CKM_TLS12_KEY_SAFE_DERIVE", KeyMatTls12Safe)
      ]

caseLookup :: IO ()
caseLookup = do
  mapM_ resolves
    [ ckm_TLS_KEY_AND_MAC_DERIVE
    , ckm_TLS12_KEY_AND_MAC_DERIVE
    , ckm_TLS12_KEY_SAFE_DERIVE
    ]
  assertEqual "other id" Nothing (tlsKeyMatRecipeFor (MechanismId 0x3e2))
  where
    resolves i = assertBool ("resolves " ++ show i)
      (case tlsKeyMatRecipeFor (MechanismId i) of Just _ -> True; Nothing -> False)

caseCodec :: IO ()
caseCodec = do
  let frame = encodeTlsKeyMatParams 4 0 16 16 clientRandom serverRandom
  assertEqual "roundtrip"
    (Just (4, 0, 16, 16, clientRandom, serverRandom))
    (decodeTlsKeyMatParams frame)
  let bare = encodeTlsKeyMatParams 0 0 16 0 BS.empty BS.empty
  assertEqual "bare roundtrip" (Just (0, 0, 16, 0, BS.empty, BS.empty))
    (decodeTlsKeyMatParams bare)
  assertEqual "truncation refused" Nothing
    (decodeTlsKeyMatParams (BS.take 9 frame))
  assertEqual "trailing bytes refused" Nothing
    (decodeTlsKeyMatParams (frame <> BS.singleton 0))

resolveKeyMat :: Word64 -> IO TlsKeyMatRecipe
resolveKeyMat mid = case tlsKeyMatRecipeFor (MechanismId mid) of
  Just r -> pure r
  Nothing -> assertFailure ("recipe must resolve " ++ show mid)

caseParams :: IO ()
caseParams = do
  r10 <- resolveKeyMat ckm_TLS_KEY_AND_MAC_DERIVE
  r12 <- resolveKeyMat ckm_TLS12_KEY_AND_MAC_DERIVE
  rSafe <- resolveKeyMat ckm_TLS12_KEY_SAFE_DERIVE
  let sha256 = 4
  -- Each row accepts its own profile.
  assertBool "tls10 accepts legacy" (tlsKeyMatParamsValid r10
    (encodeTlsKeyMatParams 0 0 16 16 clientRandom serverRandom))
  assertBool "tls12 accepts hash" (tlsKeyMatParamsValid r12
    (encodeTlsKeyMatParams sha256 0 16 16 clientRandom serverRandom))
  assertBool "safe accepts hash" (tlsKeyMatParamsValid rSafe
    (encodeTlsKeyMatParams sha256 0 16 0 clientRandom serverRandom))
  -- PRF rules.
  assertBool "tls10 refuses hash prf" (not (tlsKeyMatParamsValid r10
    (encodeTlsKeyMatParams sha256 0 16 16 clientRandom serverRandom)))
  assertBool "tls12 refuses legacy" (not (tlsKeyMatParamsValid r12
    (encodeTlsKeyMatParams 0 0 16 16 clientRandom serverRandom)))
  assertBool "tls12 refuses wild prf" (not (tlsKeyMatParamsValid r12
    (encodeTlsKeyMatParams 99 0 16 16 clientRandom serverRandom)))
  -- Sizes: keys mandatory, MAC/IV optional.
  assertBool "zero key refuses" (not (tlsKeyMatParamsValid r12
    (encodeTlsKeyMatParams sha256 0 0 16 clientRandom serverRandom)))
  assertBool "mac ok" (tlsKeyMatParamsValid r12
    (encodeTlsKeyMatParams sha256 20 16 16 clientRandom serverRandom))
  -- Randoms are fixed 32-byte TLS randoms.
  assertBool "short random refuses" (not (tlsKeyMatParamsValid r12
    (encodeTlsKeyMatParams sha256 0 16 16 (BS.take 31 clientRandom) serverRandom)))
  -- Over-ceiling blocks refuse.
  assertBool "block ceiling" (not (tlsKeyMatParamsValid r12
    (encodeTlsKeyMatParams sha256 20000 20000 20000 clientRandom serverRandom)))
  -- Junk never validates.
  assertBool "junk refuses" (not (tlsKeyMatParamsValid r12 "junk"))

caseLayout :: IO ()
caseLayout = do
  assertEqual "mac0 layout"
    [ (KeyMatKeyClient, 16), (KeyMatKeyServer, 16)
    , (KeyMatIvClient, 16), (KeyMatIvServer, 16)
    ]
    (tlsKeyMatLayout 0 16 16)
  assertEqual "mac160 layout"
    [ (KeyMatMacClient, 20), (KeyMatMacServer, 20)
    , (KeyMatKeyClient, 16), (KeyMatKeyServer, 16)
    , (KeyMatIvClient, 16), (KeyMatIvServer, 16)
    ]
    (tlsKeyMatLayout 20 16 16)
  assertEqual "no-iv layout"
    [(KeyMatKeyClient, 16), (KeyMatKeyServer, 16)]
    (tlsKeyMatLayout 0 16 0)

caseBaseTypes :: IO ()
caseBaseTypes = do
  assertBool "generic ok" (tlsKeyMatBaseKeyOk ckkGenericSecret)
  assertBool "aes refused" (not (tlsKeyMatBaseKeyOk ckkAes))

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

mkSecret :: ObjectId -> Word64 -> BS.ByteString -> Bool -> ObjectState
mkSecret oid kty mat canDerive = ObjectState
  { osId = oid
  , osRevision = Revision 1
  , osGeneration = Generation 1
  , osAttrs = Map.fromList
      [ (AttrClass, ValULong ckoSecretKey)
      , (AttrKeyType, ValULong kty)
      , (AttrPrivate, ValBool False)
      , (AttrDerive, ValBool canDerive)
      , (AttrSensitive, ValBool False)
      , (AttrExtractable, ValBool True)
      , (AttrValue, ValBytes mat)
      ]
  , osOwner = Nothing
  , osSlot = SlotId 7
  }

mkKeyMatModel :: Word64 -> Bool -> Model
mkKeyMatModel baseType canDerive = emptyModel
  { mObjects = Map.fromList
      [(baseOid, mkSecret baseOid baseType (BS.pack [0 .. 47]) canDerive)]
  , mHandles = Map.fromList
      [(baseHandle, HandleBinding baseOid (Generation 1))]
  }

-- | The single key-material template: no length (lengths come
-- from params), protection matching the base.
keyMatTmpl :: [(AttributeType, AttributeValue)]
keyMatTmpl =
  [ (AttrClass, ValULong ckoSecretKey)
  , (AttrKeyType, ValULong ckkGenericSecret)
  , (AttrSensitive, ValBool False)
  , (AttrExtractable, ValBool True)
  , (AttrToken, ValBool False)
  ]

clientRandom :: BS.ByteString
clientRandom = BS.pack [0 .. 31]

serverRandom :: BS.ByteString
serverRandom = BS.pack [32 .. 63]

tls10Mech :: MechanismId
tls10Mech = MechanismId ckm_TLS_KEY_AND_MAC_DERIVE

tls12Mech :: MechanismId
tls12Mech = MechanismId ckm_TLS12_KEY_AND_MAC_DERIVE

tlsSafeMech :: MechanismId
tlsSafeMech = MechanismId ckm_TLS12_KEY_SAFE_DERIVE

tls10Frame :: BS.ByteString
tls10Frame = encodeTlsKeyMatParams 0 0 16 16 clientRandom serverRandom

tls12Frame :: BS.ByteString
tls12Frame = encodeTlsKeyMatParams 4 0 16 16 clientRandom serverRandom

tls12MacFrame :: BS.ByteString
tls12MacFrame = encodeTlsKeyMatParams 4 20 16 16 clientRandom serverRandom

expectDeny :: String -> ReturnCode -> KeyPlan -> IO ()
expectDeny label code plan = case plan of
  KeyDenied (KeyDeny c _) -> assertEqual ("deny " ++ label) code c
  other -> assertFailure ("expected denial, got " ++ show other)

casePlan :: IO ()
casePlan = do
  let m = mkKeyMatModel ckkGenericSecret True
  -- Accepted: TLS 1.0 mac0/key16/iv16 plans two keys + two IVs.
  case planDerive defaultRules m testSession tls10Mech baseHandle
      (encodeDeriveParams tls10Frame [keyMatTmpl]) of
    KeyEffect (PwDeriveIv _ lens ivs) (FxDerive mech _ _ _ _ total) -> do
      assertEqual "mech" tls10Mech mech
      assertEqual "key lens" [16, 16] lens
      assertEqual "iv lens" (16, 16) ivs
      assertEqual "block total" 64 total
    other -> assertFailure ("expected effect, got " ++ show other)
  -- Accepted: TLS 1.2 mac160 plans four keys + two IVs.
  case planDerive defaultRules m testSession tls12Mech baseHandle
      (encodeDeriveParams tls12MacFrame [keyMatTmpl]) of
    KeyEffect (PwDeriveIv _ lens ivs) (FxDerive mech _ _ _ _ total) -> do
      assertEqual "mech" tls12Mech mech
      assertEqual "key lens" [20, 20, 16, 16] lens
      assertEqual "iv lens" (16, 16) ivs
      assertEqual "block total" 104 total
    other -> assertFailure ("expected effect, got " ++ show other)
  -- Accepted: KEY_SAFE suppresses IVs even when the frame carries them.
  case planDerive defaultRules m testSession tlsSafeMech baseHandle
      (encodeDeriveParams tls12Frame [keyMatTmpl]) of
    KeyEffect (PwDeriveIv _ lens ivs) (FxDerive mech _ _ _ _ total) -> do
      assertEqual "mech" tlsSafeMech mech
      assertEqual "key lens" [16, 16] lens
      assertEqual "iv lens" (0, 0) ivs
      assertEqual "block total" 32 total
    other -> assertFailure ("expected effect, got " ++ show other)
  -- Malformed frames refuse typed.
  expectDeny "junk params" CKR_ARGUMENTS_BAD
    (planDerive defaultRules m testSession tls12Mech baseHandle
      (encodeDeriveParams "junk" [keyMatTmpl]))
  -- A template length refuses: lengths come from params.
  expectDeny "value len present" CKR_TEMPLATE_INCONSISTENT
    (planDerive defaultRules m testSession tls12Mech baseHandle
      (encodeDeriveParams tls12Frame
        [keyMatTmpl ++ [(AttrValueLen, ValULong 16)]]))
  -- Protection differing from the base refuses (the oracle's
  -- template-conflict leg).
  expectDeny "sensitive conflict" CKR_TEMPLATE_INCONSISTENT
    (planDerive defaultRules m testSession tls10Mech baseHandle
      (encodeDeriveParams tls10Frame
        [[ (AttrClass, ValULong ckoSecretKey)
        , (AttrKeyType, ValULong ckkGenericSecret)
        , (AttrSensitive, ValBool True)
        , (AttrExtractable, ValBool True)
        , (AttrToken, ValBool False)
        ]]))
  -- A wrong-typed base refuses typed.
  expectDeny "aes base" CKR_KEY_TYPE_INCONSISTENT
    (planDerive defaultRules (mkKeyMatModel ckkAes True) testSession tls12Mech baseHandle
      (encodeDeriveParams tls12Frame [keyMatTmpl]))

caseDriverMap :: IO ()
caseDriverMap = do
  assertEqual "tls10 pair decodes"
    (Just (KeyMatExec KeyMatTls10 0 0 16 16 clientRandom serverRandom))
    (keyMatParamsFor tls10Mech tls10Frame)
  assertEqual "tls12 pair decodes"
    (Just (KeyMatExec KeyMatTls12 4 0 16 16 clientRandom serverRandom))
    (keyMatParamsFor tls12Mech tls12Frame)
  assertEqual "junk refused" Nothing
    (keyMatParamsFor tls12Mech "junk")

caseNative :: IO ()
caseNative = do
  -- Flat sizes in bits onto the canonical frame (32-byte randoms).
  assertEqual "tls10 struct translates"
    (Just (encodeTlsKeyMatParams 0 0 16 16 clientRandom serverRandom))
    (tlsKeyMatStructToCanonical 0 128 128 False clientRandom serverRandom)
  assertEqual "non-multiple-of-8 refuses" Nothing
    (tlsKeyMatStructToCanonical 0 127 128 False clientRandom serverRandom)
  assertEqual "export refuses" Nothing
    (tlsKeyMatStructToCanonical 0 128 128 True clientRandom serverRandom)
  assertEqual "tls12 struct translates"
    (Just (encodeTlsKeyMatParams 4 20 16 16 clientRandom serverRandom))
    (tls12KeyMatStructToCanonical 160 128 128 False 0x250 clientRandom serverRandom)
  assertEqual "tls12 wild prf refuses" Nothing
    (tls12KeyMatStructToCanonical 160 128 128 False 0x999 clientRandom serverRandom)
