{- | Pub-from-priv recipe tests.

The single header mechanism @CKM_PUB_KEY_FROM_PRIV_KEY@ (0x403A):
C_DeriveKey with no parameters derives a public key object from
a private base key, ignoring CKA_DERIVE (the only derive row
allowed to). Served base types: RSA, EC Weierstrass (only when
the private half embeds its public point — scalar-only imports
refuse, since y-recovery is Fp math), EC Montgomery (agreement
against the base point), EC Edwards. DSA\/DH refuse (no provider
path); ML-DSA\/SLH-DSA\/ML-KEM refuse (no provider priv-import
path at all).

The recipe owns the row table, the no-params codec, the base
type gate, and the attribute map (modeled attrs only: CKA_LOCAL,
CKA_TRUSTED, dates, CKA_GEN_MECHANISM and CKA_WRAP_TEMPLATE have
no 'AttributeType' here, so the map covers the rest — reflections
ENCRYPT<-DECRYPT, VERIFY<-SIGN, VERIFY_RECOVER<-SIGN_RECOVER,
WRAP<-UNWRAP, ENCAPSULATE<-DECAPSULATE; copies DERIVE\/ID\/SUBJECT\/
PUBLIC_KEY_INFO\/ALLOWED_MECHANISMS; forces TOKEN\/PRIVATE false
and MODIFIABLE\/COPYABLE\/DESTROYABLE true; forces LABEL empty).
Missing base booleans stay missing (reads default false); the
caller template wins over map defaults at the planner.
-}
{-# LANGUAGE OverloadedStrings #-}
module RecipePubPrivSpec (spec) where

import qualified Data.ByteString as BS
import Data.Char (digitToInt, isHexDigit)
import qualified Data.Map.Strict as Map
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertBool, assertEqual, testCase)

import Haskoki.Attribute (AttributeType (..), AttributeValue (..))
import Haskoki.Der (ecPkcs8HasPub, ecPrivateDer, ecSec1HasPub)
import Haskoki.Operation.KeyManagement
  ( ckkDh
  , ckkDsa
  , ckkEc
  , ckkEcEdwards
  , ckkEcMontgomery
  , ckkMlDsa
  , ckkMlKem
  , ckkRsa
  , ckkSlhDsa
  )
import Haskoki.Recipe.PubPriv
  ( PubPrivRecipe (..)
  , pubPrivBaseKeyOk
  , pubPrivBaseMatOk
  , pubPrivCodecFor
  , pubPrivMapAttrs
  , pubPrivParamsValid
  , pubPrivRecipeFor
  , pubPrivRecipes
  )
import Haskoki.Registry.Types (MechanismId (..), ParameterCodec (..))

spec :: TestTree
spec = testGroup "pub-from-priv recipe"
  [ testCase "row lookup resolves 0x403A only" caseRowLookup
  , testCase "empty params valid, nonempty refused" caseParams
  , testCase "codec is no-params/1" caseCodec
  , testCase "base scope serves four families, refuses the rest" caseScope
  , testCase "attribute map reflects, copies, forces" caseMap
  , testCase "map output key set is exactly the modeled table" caseMapShape
  , testCase "EC halves need the embedded point" caseEmbeddedPub
  , testCase "material gate by type" caseMatGate
  ]

-- | Decode a hex string (whitespace-tolerant).
hex :: String -> BS.ByteString
hex s = BS.pack (go (filter isHexDigit s))
  where
    go [] = []
    go (a : b : rest) = fromIntegral (digitToInt a * 16 + digitToInt b) : go rest
    go [_] = error "hex: odd digit count"

-- | Provider P-256 PKCS#8 (pinned openssl CLI output, public
-- half embedded as SEC1 [1]).
providerP256 :: BS.ByteString
providerP256 = hex
  "308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b0201010420\
  \ea3851e04e9fa14c421e7669f374493c50ea6f3d5ae5c7d57a31812bd779e8fca144\
  \034200040146e4dc41f540fedb82ff563b9c49f92fd69f1f7e2bf4c498287c54b8c70\
  \f2ec528757041bab6c0d808840432f506a84c1d7271fbc068a05fbce16dfdc158d2"

-- | Scalar-only half from our own builder (import shape).
scalarP256 :: BS.ByteString
scalarP256 = ecPrivateDer (hex "06082a8648ce3d030107") (BS.replicate 32 0x51)

-- | Raw-SEC1 half in the live keygen shape (121 bytes: version,
-- scalar, @[0]@ params, @[1]@ point; scalar/point fixed-fill).
sec1P256 :: BS.ByteString
sec1P256 =
  hex "30770201010420" <> BS.replicate 32 0x51
    <> hex "a00a06082a8648ce3d030107a14403420004" <> BS.replicate 64 0x52

-- | Scalar-only raw SEC1 (no @[1]@): version, scalar, params.
sec1ScalarP256 :: BS.ByteString
sec1ScalarP256 =
  hex "30310201010420" <> BS.replicate 32 0x51
    <> hex "a00a06082a8648ce3d030107"

caseRowLookup :: IO ()
caseRowLookup = do
  assertEqual "one row" 1 (length pubPrivRecipes)
  case pubPrivRecipes of
    (r : _) -> do
      assertEqual "row name" "CKM_PUB_KEY_FROM_PRIV_KEY" (pprName r)
      assertEqual "lookup by id" (Just r)
        (pubPrivRecipeFor (MechanismId 0x403A))
    [] -> assertBool "table nonempty" False
  assertEqual "unknown id refused" Nothing
    (pubPrivRecipeFor (MechanismId 0x403B))

caseParams :: IO ()
caseParams = case pubPrivRecipeFor (MechanismId 0x403A) of
  Nothing -> assertBool "row resolves" False
  Just r -> do
    assertBool "empty valid" (pubPrivParamsValid r "")
    assertBool "nonempty refused" (not (pubPrivParamsValid r "x"))

caseCodec :: IO ()
caseCodec = case pubPrivRecipeFor (MechanismId 0x403A) of
  Nothing -> assertBool "row resolves" False
  Just r ->
    assertEqual "codec" (ParameterCodec "no-params" 1) (pubPrivCodecFor r)

caseScope :: IO ()
caseScope = do
  mapM_ (\k -> assertBool ("served: " ++ show k) (pubPrivBaseKeyOk k))
    [ckkRsa, ckkEc, ckkEcMontgomery, ckkEcEdwards]
  mapM_ (\k -> assertBool ("refused: " ++ show k) (not (pubPrivBaseKeyOk k)))
    [ckkDsa, ckkDh, ckkMlDsa, ckkSlhDsa, ckkMlKem, 0xDEAD]

caseMap :: IO ()
caseMap = do
  let base = Map.fromList
        [ (AttrDecrypt, ValBool True)
        , (AttrSign, ValBool False)
        , (AttrSignRecover, ValBool True)
        , (AttrUnwrap, ValBool True)
        , (AttrDecapsulate, ValBool False)
        , (AttrDerive, ValBool True)
        , (AttrId, ValBytes "key-id")
        , (AttrSubject, ValBytes "subject")
        , (AttrPublicKeyInfo, ValBytes "spki")
        , (AttrAllowedMechanisms, ValBytes "mechs")
        , (AttrToken, ValBool True)
        , (AttrPrivate, ValBool True)
        , (AttrLabel, ValBytes "base-label")
        ]
      got = pubPrivMapAttrs base
  -- Reflections follow the base halves.
  assertEqual "encrypt" (Just (ValBool True)) (Map.lookup AttrEncrypt got)
  assertEqual "verify" (Just (ValBool False)) (Map.lookup AttrVerify got)
  assertEqual "verify-recover" (Just (ValBool True))
    (Map.lookup AttrVerifyRecover got)
  assertEqual "wrap" (Just (ValBool True)) (Map.lookup AttrWrap got)
  assertEqual "encapsulate" (Just (ValBool False))
    (Map.lookup AttrEncapsulate got)
  -- Copies ride through.
  assertEqual "derive" (Just (ValBool True)) (Map.lookup AttrDerive got)
  assertEqual "id" (Just (ValBytes "key-id")) (Map.lookup AttrId got)
  assertEqual "subject" (Just (ValBytes "subject"))
    (Map.lookup AttrSubject got)
  assertEqual "spki" (Just (ValBytes "spki"))
    (Map.lookup AttrPublicKeyInfo got)
  assertEqual "allowed" (Just (ValBytes "mechs"))
    (Map.lookup AttrAllowedMechanisms got)
  -- Forced values ignore the base.
  assertEqual "token" (Just (ValBool False)) (Map.lookup AttrToken got)
  assertEqual "private" (Just (ValBool False)) (Map.lookup AttrPrivate got)
  assertEqual "modifiable" (Just (ValBool True))
    (Map.lookup AttrModifiable got)
  assertEqual "copyable" (Just (ValBool True)) (Map.lookup AttrCopyable got)
  assertEqual "destroyable" (Just (ValBool True))
    (Map.lookup AttrDestroyable got)
  assertEqual "label" (Just (ValBytes "")) (Map.lookup AttrLabel got)

caseMapShape :: IO ()
caseMapShape = do
  -- A bare base still yields exactly the forced set (reflections
  -- and copies stay missing; reads default booleans false).
  let got = pubPrivMapAttrs Map.empty
  assertEqual "forced key set"
    [ AttrToken
    , AttrPrivate
    , AttrLabel
    , AttrCopyable
    , AttrDestroyable
    , AttrModifiable
    ]
    (Map.keys got)

caseEmbeddedPub :: IO ()
caseEmbeddedPub = do
  assertEqual "provider vector length" 138 (BS.length providerP256)
  assertBool "provider half embeds" (ecPkcs8HasPub providerP256)
  assertBool "scalar-only lacks" (not (ecPkcs8HasPub scalarP256))
  assertBool "garbage lacks"
    (not (ecPkcs8HasPub (BS.replicate 64 0xAA)))
  assertBool "truncation lacks"
    (not (ecPkcs8HasPub (BS.take 100 providerP256)))
  assertEqual "sec1 vector length" 121 (BS.length sec1P256)
  assertBool "sec1 half embeds" (ecSec1HasPub sec1P256)
  assertBool "sec1 scalar-only lacks" (not (ecSec1HasPub sec1ScalarP256))
  assertBool "sec1 garbage lacks"
    (not (ecSec1HasPub (BS.replicate 64 0xAA)))
  assertBool "sec1 truncation lacks"
    (not (ecSec1HasPub (BS.take 100 sec1P256)))
  assertBool "framings do not cross-match"
    (not (ecPkcs8HasPub sec1P256) && not (ecSec1HasPub providerP256))

caseMatGate :: IO ()
caseMatGate = do
  assertBool "EC embedded serves"
    (pubPrivBaseMatOk ckkEc providerP256)
  assertBool "EC scalar-only refuses"
    (not (pubPrivBaseMatOk ckkEc scalarP256))
  assertBool "EC sec1 embedded serves"
    (pubPrivBaseMatOk ckkEc sec1P256)
  assertBool "EC sec1 scalar-only refuses"
    (not (pubPrivBaseMatOk ckkEc sec1ScalarP256))
  mapM_ (\k -> assertBool ("passthrough: " ++ show k)
    (pubPrivBaseMatOk k "opaque"))
    [ckkRsa, ckkEcMontgomery, ckkEcEdwards]
