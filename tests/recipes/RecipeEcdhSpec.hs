{- | ECDH recipe tests.

The ECDH group: 2 header mechanisms sharing the agreement
parameter shape — @ecdh-params\/1@: @kdf:u64be sharedLen:u64be
shared pubLen:u64be pub@. Only the @CKD_NULL@ selector (code 0,
raw x-coordinate secret) is served; every other KDF selector is a
typed refusal naming a deferred dimension, never silent fallback.
The cofactor flag comes from the mechanism row, not the params.

'Haskoki.Recipe.Ecdh' owns the group's canonical codec, parameter
validation, mechanism table, and secret-width rule; these tests pin
the recipe and its three consumers:

* the derive planner accepts ECDH frames ('planDerive') with the
  curve-width ceiling and base\/peer curve agreement;
* the driver maps covered (mechanism, params) pairs to
  (@EcdhSpec@, peer) ('ecdhParamsFor');
* engines execute the agreement (SyntheticSpec constructions,
  OpenSSLSpec CLI cross-checked KATs against the pinned libcrypto).
-}
{-# LANGUAGE OverloadedStrings #-}
module RecipeEcdhSpec (spec) where

import qualified Data.ByteString as BS
import Data.Char (digitToInt, isHexDigit)
import qualified Data.Map.Strict as Map
import Data.Text (Text)
import qualified Data.Text as T
import Data.Word (Word64)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertBool, assertEqual, assertFailure, testCase)

import Haskoki.Attribute (AttributeType (..), AttributeValue (..))
import Haskoki.Der (curveTable)
import Haskoki.Engine.Backend (EcdhSpec (..))
import Haskoki.Engine.Driver (ecdhParamsFor)
import Haskoki.Model
  ( HandleBinding (..)
  , Model (..)
  , ObjectState (..)
  , SessionState (..)
  , emptyModel
  )
import Haskoki.Operation (emptySessionOps)
import Haskoki.Operation.Derive (encodeDeriveParams, encodeHkdfInfo, planDerive)
import Haskoki.Operation.Effect (CryptoEffect (..))
import Haskoki.Operation.KeyManagement
  ( KeyDeny (..)
  , KeyPlan (..)
  , PendingObject (..)
  , PendingWork (..)
  , ckkEc
  , ckkEcMontgomery
  , ckkGenericSecret
  , ckoSecretKey
  )
import Haskoki.Recipe.Ecdh
  ( EcdhRecipe (..)
  , decodeEcdhParams
  , ecdhCodec
  , ecdhCodecFor
  , ecdhParamsValid
  , ecdhPeerWidth
  , ecdhRecipeFor
  , ecdhRecipes
  , ecdhSecretWidth
  , ecdhSecretWidthMax
  , encodeEcdhParams
  )
import Haskoki.Registry (MechanismId (..))
import Haskoki.Registry.Generated
  ( mustGeneratedId
  , ckm_ECDH1_COFACTOR_DERIVE
  , ckm_ECDH1_DERIVE
  , ckm_ECDH_AES_KEY_WRAP
  , ckm_ECDSA_SHA256
  , ckm_ECMQV_DERIVE
  , ckm_HKDF_DERIVE
  , ckm_SHA256_KEY_DERIVATION
  )
import Haskoki.Registry.Types (ParameterCodec (..))
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
spec = testGroup "ECDH recipe"
  [ testCase "table: two rows, cofactor flags" caseTable
  , testCase "lookup: ids resolve, others do not" caseLookup
  , testCase "codec identity" caseCodec
  , testCase "params: valid and refused shapes" caseParams
  , testCase "secret width per curve" caseWidth
  , testCase "peer width resolves widths not curves" casePeerWidth
  , testCase "planDerive: ECDH accept and deny" casePlan
  , testCase "secret width over Montgomery bases" caseWidthMontgomery
  , testCase "planDerive: XDH accept and deny" casePlanMontgomery
  , testCase "driver maps mechanisms to specs" caseDriverMap
  ]

-- ---------------------------------------------------------------------------
-- Table + lookup + codec
-- ---------------------------------------------------------------------------

groupShape :: [(Text, Bool)]
groupShape =
  [ ("ECDH1_DERIVE", False)
  , ("ECDH1_COFACTOR_DERIVE", True)
  ]

mechName :: Text -> Text
mechName suffix = "CKM_" <> suffix

caseTable :: IO ()
caseTable = do
  assertEqual "recipe count" 2 (length ecdhRecipes)
  mapM_ (\(suffix, cof) -> do
    let name = mechName suffix
        found = [ r | r <- ecdhRecipes, rhName r == name ]
    case found of
      [r] -> assertEqual ("cofactor " ++ T.unpack name) cof (rhCofactor r)
      rs -> assertFailure ("rows " ++ T.unpack name ++ ": " ++ show (length rs))
    ) groupShape

caseLookup :: IO ()
caseLookup = do
  mapM_ (\(suffix, _) -> do
    let name = mechName suffix
    case ecdhRecipeFor (MechanismId (mustGeneratedId name)) of
      Nothing -> assertFailure ("unresolved " ++ T.unpack name)
      Just r -> assertEqual ("lookup " ++ T.unpack name) name (rhName r)
    ) groupShape
  assertEqual "unknown id has no recipe" Nothing
    (ecdhRecipeFor (MechanismId 0x4712))
  assertEqual "ECDSA has no ECDH recipe" Nothing
    (ecdhRecipeFor (MechanismId (ckm_ECDSA_SHA256)))
  assertEqual "ECMQV has no ECDH recipe" Nothing
    (ecdhRecipeFor (MechanismId (ckm_ECMQV_DERIVE)))
  assertEqual "ECDH+AES-KW has no ECDH recipe" Nothing
    (ecdhRecipeFor (MechanismId (ckm_ECDH_AES_KEY_WRAP)))
  assertEqual "HKDF has no ECDH recipe" Nothing
    (ecdhRecipeFor (MechanismId (ckm_HKDF_DERIVE)))

caseCodec :: IO ()
caseCodec = do
  assertEqual "ecdh codec" (ParameterCodec "ecdh-params" 1) ecdhCodec
  mapM_ (\(suffix, _) ->
    case ecdhRecipeFor (MechanismId (mustGeneratedId (mechName suffix))) of
      Nothing -> assertFailure ("unresolved " ++ T.unpack suffix)
      Just r -> assertEqual ("codec " ++ T.unpack suffix) ecdhCodec
        (ecdhCodecFor r)
    ) groupShape

-- ---------------------------------------------------------------------------
-- Fixtures: real DER bytes (CLI fixtures, copied verbatim)
-- ---------------------------------------------------------------------------

hex :: String -> BS.ByteString
hex s = BS.pack (go (filter isHexDigit s))
  where
    go [] = []
    go (a : b : rest) = fromIntegral (digitToInt a * 16 + digitToInt b) : go rest
    go [_] = error "hex: odd digit count"

p256Priv, p256Pub, p384Pub, p521Pub :: BS.ByteString
p256Priv = hex "308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b0201010420e9032e4f06ee6b5397252cfb48e73a8d3f7717d4024dd4cc5b98bbf041c11bb3a14403420004a348bab88ded75858acef31e9afa0ef8680ad8ec1196227b10083a630f029ecfc5503e37b76e2538f9ec2ceb6aa766cc7948071e6c39b9a93f0c54d5f7b12086"
p256Pub = hex "3059301306072a8648ce3d020106082a8648ce3d03010703420004a348bab88ded75858acef31e9afa0ef8680ad8ec1196227b10083a630f029ecfc5503e37b76e2538f9ec2ceb6aa766cc7948071e6c39b9a93f0c54d5f7b12086"
p384Pub = hex "3076301006072a8648ce3d020106052b8104002203620004467ab2e9c927f143e9f6151006e492da4d11c9e079e339f6086dfd988bd0cac51e25adf31d504a7c730a94c1c4b3bb880cffcceaf56ebc0c1a42e04051e8d11e409440f6a4924c1cfea44e8858601cd2a041d7340fe670712e91ca3ec5389a0c"
p521Pub = hex "30819b301006072a8648ce3d020106052b810400230381860004019eed1a84c846d69d26a869d864b0d1bf557cc7320ce1d8018f22f3b963f6b4c136b38d44c8cb2e21218e96f93aa82459dfb186d80fe06db19cc3c49989e1da9c1701a6889745283941b46bb94ab6f59ad10786191c910aa0183b702b25cd18de9afa5731805cab4f7e3309226b19e397fbaed8b54a03e2e9e1e79ec3862f0ca47a1fc9"

-- Montgomery fixtures: the openssl-emitted X25519/X448 PKCS#8
-- halves (KeyImportSpec goldens, copied verbatim) plus raw
-- RFC 7748 peers.
x19P8, x48P8 :: BS.ByteString
x19P8 = hex "302e020100300506032b656e04220420107c0296168df7ef1da8bf471f5ac2d793788e84eb8b34d86a2605b2424d0847"
x48P8 = hex "3046020100300506032b656f043a0438f0b746caef9d715d94ecf3cc83b6b5caf0140402ff06b3043a56f2904b1594350ce4b7523116d8422a97365bb37c3f11f746e4765e71efad"

x19Peer, x48Peer :: BS.ByteString
x19Peer = hex "504a36999f489cd2fdbc08baff3d88fa00569ba986cba22548ffde80f9806829"
x48Peer = hex "f8073fc01c8358362c08740c914b419847ef1e409f4e40d9440febc26f00551adb1c37c6c2a87d8283b8cb453e928a0d42793f72894e0f81"

recipeOf :: Text -> EcdhRecipe
recipeOf name =
  case ecdhRecipeFor (MechanismId (mustGeneratedId name)) of
    Just r -> r
    Nothing -> error ("test recipe missing: " ++ T.unpack name)

-- ---------------------------------------------------------------------------
-- Params codec
-- ---------------------------------------------------------------------------

caseParams :: IO ()
caseParams = do
  let r = recipeOf "CKM_ECDH1_DERIVE"
      good = encodeEcdhParams 0 BS.empty p256Pub
  assertEqual "roundtrip" (Just (0, BS.empty, p256Pub)) (decodeEcdhParams good)
  assertBool "null kdf valid" (ecdhParamsValid r good)
  assertBool "shared data ignored, still valid"
    (ecdhParamsValid r (encodeEcdhParams 0 "shared" p256Pub))
  assertBool "cofactor row takes the same params"
    (ecdhParamsValid (recipeOf "CKM_ECDH1_COFACTOR_DERIVE") good)
  -- Every nonzero KDF selector names a deferred dimension: refused.
  mapM_ (\k ->
    assertBool ("kdf refused: " ++ show k)
      (not (ecdhParamsValid r (encodeEcdhParams k BS.empty p256Pub)))
    ) [1, 2, 3, 9, 0x7fffffff]
  -- Framing faults refuse.
  assertBool "empty refused" (not (ecdhParamsValid r BS.empty))
  assertBool "truncated refused"
    (not (ecdhParamsValid r (BS.take 20 good)))
  assertBool "overrun shared refused"
    (not (ecdhParamsValid r (encodeEcdhParams 0 BS.empty p256Pub <> BS.pack [0])))
  assertBool "empty peer refused"
    (not (ecdhParamsValid r (encodeEcdhParams 0 BS.empty BS.empty)))
  -- Overrun length prefixes decode to Nothing (never a crash).
  assertEqual "overrun prefix" Nothing
    (decodeEcdhParams (BS.pack [0,0,0,0,0,0,0,0, 0,0,0,0,0x10,0,0,0]))

caseWidth :: IO ()
caseWidth = do
  assertEqual "P-256 width" 32 (ecdhSecretWidth p256Priv)
  assertEqual "P-256 pub width" 32 (ecdhSecretWidth p256Pub)
  assertEqual "P-384 width" 48 (ecdhSecretWidth p384Pub)
  assertEqual "P-521 width" 66 (ecdhSecretWidth p521Pub)
  -- Every table row resolves its width from the bare OID (the
  -- substring scan on real DER is pinned by the ECDSA sniff test).
  mapM_ (\(_, oid, w) ->
    assertEqual ("width " ++ show w) w (ecdhSecretWidth oid)) curveTable
  assertEqual "max width is the sect571 width" 72 ecdhSecretWidthMax
  assertEqual "unscannable defaults to the max width" 72
    (ecdhSecretWidth (BS.replicate 32 0))
  assertEqual "garbage defaults to the max width" 72
    (ecdhSecretWidth "bogus")

casePeerWidth :: IO ()
casePeerWidth = do
  -- SPKI peers resolve exactly.
  assertEqual "P-256 SPKI" (Just 32) (ecdhPeerWidth p256Pub)
  assertEqual "P-384 SPKI" (Just 48) (ecdhPeerWidth p384Pub)
  assertEqual "P-521 SPKI" (Just 66) (ecdhPeerWidth p521Pub)
  -- Bare points resolve widths, never curves: 65 bytes is 32 wide
  -- whether the curve is P-256, secp256k1, or brainpoolP256r1.
  let point w = BS.cons 0x04 (BS.replicate (2 * w) 0x11)
  mapM_ (\(_, _, w) ->
    assertEqual ("bare width " ++ show w) (Just w) (ecdhPeerWidth (point w))
    ) curveTable
  assertEqual "compressed refuses" Nothing
    (ecdhPeerWidth (BS.cons 0x02 (BS.replicate 64 0x11)))
  assertEqual "off-width refuses" Nothing
    (ecdhPeerWidth (BS.cons 0x04 (BS.replicate 61 0x11)))
  assertEqual "unknown even width refuses" Nothing
    (ecdhPeerWidth (BS.cons 0x04 (BS.replicate 66 0x11)))
  assertEqual "empty refuses" Nothing (ecdhPeerWidth BS.empty)
  assertEqual "garbage refuses" Nothing (ecdhPeerWidth "bogus")

-- ---------------------------------------------------------------------------
-- planDerive pins (light model harness: one EC base key + handle)
-- ---------------------------------------------------------------------------

baseOid :: ObjectId
baseOid = ObjectId 41

baseHandle :: ExternalHandle
baseHandle = ExternalHandle 401

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

mkBaseModel :: Word64 -> BS.ByteString -> Bool -> Model
mkBaseModel keyType mat canDerive = emptyModel
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
          , (AttrKeyType, ValULong keyType)
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

-- | Derive template without CKA_VALUE_LEN (the oracle's basic-ECDH shape).
derivedTmplNoLen :: [(AttributeType, AttributeValue)]
derivedTmplNoLen =
  [ (AttrClass, ValULong ckoSecretKey)
  , (AttrKeyType, ValULong ckkGenericSecret)
  , (AttrSensitive, ValBool False)
  , (AttrExtractable, ValBool True)
  ]

ecdhMech, ecdhCofMech :: MechanismId
ecdhMech = MechanismId (ckm_ECDH1_DERIVE)
ecdhCofMech = MechanismId (ckm_ECDH1_COFACTOR_DERIVE)

expectDeny :: String -> ReturnCode -> KeyPlan -> IO ()
expectDeny label code plan = case plan of
  KeyDenied (KeyDeny c _) -> assertEqual ("deny " ++ label) code c
  other -> assertFailure ("expected denial, got " ++ show other)

casePlan :: IO ()
casePlan = do
  let m = mkBaseModel ckkEc p256Priv True
      blob peer = encodeDeriveParams (encodeEcdhParams 0 BS.empty peer)
  -- Accepted: single key under the P-256 width; the effect carries
  -- the ECDH blob as mechanism params with empty info.
  case planDerive defaultRules m testSession ecdhMech baseHandle (blob p256Pub [derivedTmpl 32]) of
    KeyEffect _ (FxDerive mech (Just oid) params info total) -> do
      assertEqual "mech" ecdhMech mech
      assertEqual "base" baseOid oid
      assertEqual "params" (encodeEcdhParams 0 BS.empty p256Pub) params
      assertEqual "info empty" BS.empty info
      assertEqual "total" 32 total
    other -> assertFailure ("expected effect, got " ++ show other)
  -- Multi-template fan-out sums under the width.
  case planDerive defaultRules m testSession ecdhMech baseHandle (blob p256Pub [derivedTmpl 16, derivedTmpl 16]) of
    KeyEffect _ (FxDerive _ _ _ _ total) -> assertEqual "total" 32 total
    other -> assertFailure ("expected effect, got " ++ show other)
  -- The cofactor row plans identically (flag is mechanism-side).
  case planDerive defaultRules m testSession ecdhCofMech baseHandle (blob p256Pub [derivedTmpl 32]) of
    KeyEffect _ (FxDerive mech _ _ _ _) -> assertEqual "mech" ecdhCofMech mech
    other -> assertFailure ("expected effect, got " ++ show other)
  -- Width ceiling: 33 bytes from a 32-byte secret denies, zero objects.
  expectDeny "over width" CKR_ARGUMENTS_BAD
    (planDerive defaultRules m testSession ecdhMech baseHandle (blob p256Pub [derivedTmpl 33]))
  -- Unscannable base (synthetic opaque bytes) plans against the max width.
  case planDerive defaultRules (mkBaseModel ckkEc (BS.replicate 32 0) True) testSession
        ecdhMech baseHandle (blob p256Pub [derivedTmpl 72]) of
    KeyEffect _ (FxDerive _ _ _ _ total) -> assertEqual "total" 72 total
    other -> assertFailure ("expected effect, got " ++ show other)
  expectDeny "over max width" CKR_ARGUMENTS_BAD
    (planDerive defaultRules (mkBaseModel ckkEc (BS.replicate 32 0) True) testSession
      ecdhMech baseHandle (blob p256Pub [derivedTmpl 73]))
  -- Base/peer curve mismatch denies (both scan, curves differ).
  expectDeny "curve mismatch" CKR_MECHANISM_PARAM_INVALID
    (planDerive defaultRules m testSession ecdhMech baseHandle (blob p384Pub [derivedTmpl 32]))
  -- KDF selectors deny as bad mechanism parameters; malformed
  -- blobs deny at the frame.
  expectDeny "kdf selector" CKR_MECHANISM_PARAM_INVALID
    (planDerive defaultRules m testSession ecdhMech baseHandle
      (encodeDeriveParams (encodeEcdhParams 1 BS.empty p256Pub) [derivedTmpl 32]))
  expectDeny "malformed blob" CKR_ARGUMENTS_BAD
    (planDerive defaultRules m testSession ecdhMech baseHandle "truncated")
  expectDeny "no templates" CKR_ARGUMENTS_BAD
    (planDerive defaultRules m testSession ecdhMech baseHandle (blob p256Pub []))
  -- Base-key faults mirror the HKDF denials.
  expectDeny "no derive mark" CKR_KEY_FUNCTION_NOT_PERMITTED
    (planDerive defaultRules (mkBaseModel ckkEc p256Priv False) testSession
      ecdhMech baseHandle (blob p256Pub [derivedTmpl 32]))
  expectDeny "unknown handle" CKR_KEY_HANDLE_INVALID
    (planDerive defaultRules m testSession ecdhMech (ExternalHandle 999) (blob p256Pub [derivedTmpl 32]))
  -- HKDF still plans (ECDH extension changes nothing there).
  case planDerive defaultRules m testSession (MechanismId (ckm_HKDF_DERIVE))
      baseHandle (encodeDeriveParams (encodeHkdfInfo 4 0x02 BS.empty "info") [derivedTmpl 32]) of
    KeyEffect _ _ -> pure ()
    other -> assertFailure ("hkdf must still plan, got " ++ show other)
  -- Missing CKA_VALUE_LEN defaults to the full agreement secret
  -- (PKCS#11 v3.2 ECDH: "if it has one" a length); the default is
  -- stamped on the pending object so readback matches explicit.
  case planDerive defaultRules m testSession ecdhMech baseHandle (blob p256Pub [derivedTmplNoLen]) of
    KeyEffect (PwDerive [po] [n]) (FxDerive _ _ _ _ total) -> do
      assertEqual "default total" 32 total
      assertEqual "default len" 32 n
      assertEqual "default stamped" (Just (ValULong 32))
        (Map.lookup AttrValueLen (poAttrs po))
    other -> assertFailure ("expected defaulted effect, got " ++ show other)
  -- The cofactor row defaults identically.
  case planDerive defaultRules m testSession ecdhCofMech baseHandle (blob p256Pub [derivedTmplNoLen]) of
    KeyEffect _ (FxDerive _ _ _ _ total) -> assertEqual "cofactor default total" 32 total
    other -> assertFailure ("expected defaulted effect, got " ++ show other)
  -- Unscannable base material defaults to the max width.
  case planDerive defaultRules (mkBaseModel ckkEc (BS.replicate 32 0) True) testSession
        ecdhMech baseHandle (blob p256Pub [derivedTmplNoLen]) of
    KeyEffect _ (FxDerive _ _ _ _ total) -> assertEqual "opaque default total" 72 total
    other -> assertFailure ("expected defaulted effect, got " ++ show other)
  -- Open-ended SHA-KDF generic secrets have no well-defined
  -- length, so they keep INCOMPLETE without one. HKDF instead
  -- defaults to the hash length: the mechanism doc says VALUE_LEN
  -- "should be set" (non-mandatory), and callers omit it.
  case planDerive defaultRules m testSession (MechanismId (ckm_HKDF_DERIVE))
      baseHandle (encodeDeriveParams (encodeHkdfInfo 4 0x02 BS.empty "info") [derivedTmplNoLen]) of
    KeyEffect (PwDerive [po] [n]) (FxDerive _ _ _ _ total) -> do
      assertEqual "hkdf default total" 32 total
      assertEqual "hkdf default len" 32 n
      assertEqual "hkdf default stamped" (Just (ValULong 32))
        (Map.lookup AttrValueLen (poAttrs po))
    other -> assertFailure ("hkdf must default the length, got " ++ show other)
  -- The default follows the PRF hash length, not SHA-256.
  case planDerive defaultRules m testSession (MechanismId (ckm_HKDF_DERIVE))
      baseHandle (encodeDeriveParams (encodeHkdfInfo 6 0x02 BS.empty "info") [derivedTmplNoLen]) of
    KeyEffect (PwDerive [po] [n]) (FxDerive _ _ _ _ total) -> do
      assertEqual "hkdf512 default total" 64 total
      assertEqual "hkdf512 default len" 64 n
      assertEqual "hkdf512 default stamped" (Just (ValULong 64))
        (Map.lookup AttrValueLen (poAttrs po))
    other -> assertFailure ("hkdf512 must default the length, got " ++ show other)
  let gm = mkBaseModel ckkGenericSecret (BS.replicate 32 0x11) True
  expectDeny "sha-kdf generic needs length" CKR_TEMPLATE_INCOMPLETE
    (planDerive defaultRules gm testSession (MechanismId (ckm_SHA256_KEY_DERIVATION))
      baseHandle (encodeDeriveParams BS.empty [derivedTmplNoLen]))

caseWidthMontgomery :: IO ()
caseWidthMontgomery = do
  assertEqual "X25519 width" 32 (ecdhSecretWidth x19P8)
  assertEqual "X448 width" 56 (ecdhSecretWidth x48P8)
  assertEqual "X25519 bare OID" 32 (ecdhSecretWidth (hex "06032b656e"))
  assertEqual "X448 bare OID" 56 (ecdhSecretWidth (hex "06032b656f"))
  -- Weierstrass widths are unchanged (no table cross-talk).
  assertEqual "P-256 width still" 32 (ecdhSecretWidth p256Priv)

casePlanMontgomery :: IO ()
casePlanMontgomery = do
  let m = mkBaseModel ckkEcMontgomery x19P8 True
      blob peer = encodeDeriveParams (encodeEcdhParams 0 BS.empty peer)
  -- Accepted: the raw 32-byte peer derives under the X25519 width.
  case planDerive defaultRules m testSession ecdhMech baseHandle (blob x19Peer [derivedTmpl 32]) of
    KeyEffect _ (FxDerive mech (Just oid) params info total) -> do
      assertEqual "mech" ecdhMech mech
      assertEqual "base" baseOid oid
      assertEqual "params" (encodeEcdhParams 0 BS.empty x19Peer) params
      assertEqual "info empty" BS.empty info
      assertEqual "total" 32 total
    other -> assertFailure ("expected effect, got " ++ show other)
  -- X448 plans under its own width.
  case planDerive defaultRules (mkBaseModel ckkEcMontgomery x48P8 True) testSession
      ecdhMech baseHandle (blob x48Peer [derivedTmpl 56]) of
    KeyEffect _ (FxDerive _ _ _ _ total) -> assertEqual "x448 total" 56 total
    other -> assertFailure ("expected effect, got " ++ show other)
  -- Missing CKA_VALUE_LEN defaults to the curve width, not the max.
  case planDerive defaultRules m testSession ecdhMech baseHandle (blob x19Peer [derivedTmplNoLen]) of
    KeyEffect (PwDerive [po] [n]) (FxDerive _ _ _ _ total) -> do
      assertEqual "default total" 32 total
      assertEqual "default len" 32 n
      assertEqual "default stamped" (Just (ValULong 32))
        (Map.lookup AttrValueLen (poAttrs po))
    other -> assertFailure ("expected defaulted effect, got " ++ show other)
  -- Width ceiling: 33 bytes from a 32-byte secret denies.
  expectDeny "over width" CKR_ARGUMENTS_BAD
    (planDerive defaultRules m testSession ecdhMech baseHandle (blob x19Peer [derivedTmpl 33]))
  -- Off-width peers deny as bad mechanism parameters (the
  -- invalid-peer legs of the wycheproof XDH files).
  mapM_ (\(label, peer) ->
    expectDeny label CKR_MECHANISM_PARAM_INVALID
      (planDerive defaultRules m testSession ecdhMech baseHandle (blob peer [derivedTmpl 32]))
    ) [ ("short peer", BS.take 31 x19Peer)
      , ("long peer", x19Peer <> BS.singleton 0)
      , ("x448 peer on x25519", x48Peer)
      , ("weierstrass peer", p256Pub)
      ]
  -- Unscannable Montgomery base (synthetic opaque bytes) plans
  -- against the max width; the peer check cannot run and the
  -- backend arbitrates (the Weierstrass opaque precedent).
  case planDerive defaultRules (mkBaseModel ckkEcMontgomery (BS.replicate 32 0) True) testSession
        ecdhMech baseHandle (blob x19Peer [derivedTmpl 72]) of
    KeyEffect _ (FxDerive _ _ _ _ total) -> assertEqual "opaque total" 72 total
    other -> assertFailure ("expected effect, got " ++ show other)
  -- Cofactor derive over Montgomery curves is unserved (named
  -- gap: clamping already clears the cofactor and the composed
  -- operation has no PKCS#11 definition).
  expectDeny "cofactor over montgomery" CKR_MECHANISM_PARAM_INVALID
    (planDerive defaultRules m testSession ecdhCofMech baseHandle (blob x19Peer [derivedTmpl 32]))
  -- A non-EC, non-Montgomery base still contradicts the key type.
  expectDeny "generic base contradicts" CKR_KEY_TYPE_INCONSISTENT
    (planDerive defaultRules (mkBaseModel ckkGenericSecret x19P8 True) testSession
      ecdhMech baseHandle (blob x19Peer [derivedTmpl 32]))

-- ---------------------------------------------------------------------------
-- Driver mapping
-- ---------------------------------------------------------------------------

caseDriverMap :: IO ()
caseDriverMap = do
  let good = encodeEcdhParams 0 BS.empty p256Pub
  assertEqual "derive maps plain"
    (Just (EcdhPlain, p256Pub))
    (ecdhParamsFor ecdhMech good)
  assertEqual "cofactor maps flagged"
    (Just (EcdhCofactor, p256Pub))
    (ecdhParamsFor ecdhCofMech good)
  assertEqual "kdf refused" Nothing
    (ecdhParamsFor ecdhMech (encodeEcdhParams 1 BS.empty p256Pub))
  assertEqual "truncated refused" Nothing
    (ecdhParamsFor ecdhMech (BS.take 20 good))
  assertEqual "non-ECDH uncovered" Nothing
    (ecdhParamsFor (MechanismId (ckm_HKDF_DERIVE)) good)
