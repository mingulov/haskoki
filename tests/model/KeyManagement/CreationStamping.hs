{- | KeyManagement creation stamping.
-}
{-# LANGUAGE OverloadedStrings #-}
module KeyManagement.CreationStamping
  ( assertKemHistory
  , bareSecretTmpl
  , caseGenerateStampsKeyAttrs
  , casePairStampsBothHalves
  , caseGenerateStampsEveryKeygen
  , casePairStampsEveryPair
  , caseGenerateExplicitBirthFlags
  , caseUnwrapStampsEveryMech
  , caseDeriveStampsEveryFamily
  , caseCopyGeneratedKeyDerivesHistory
  , caseDeriveEcdhRefusesSecretEc
  , caseDeriveEcdhRefusesSecretMont
  , caseDeriveEcdhRefusesPublicEc
  , caseDeriveEcdhRefusesSecretEcCofactor
  , caseDeriveEcdhPlansPrivate
  , caseDeriveDhRefusesSecretDh
  , caseDeriveDhRefusesPublicDh
  , caseDeriveDhRefusesSecretX942
  , caseDeriveDhRefusesPublicX942
  , caseDeriveDhPlansPrivate
  , caseKemEncapsRefusesPrivate
  , caseKemDecapsRefusesPublic
  , caseKemPlansCorrectHalves
  , caseDeriveRefusalOrderPin
  , caseDeriveMarkBeforeClassPin
  , caseDeriveAllowedBeforeTypePin
  ) where

import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import qualified Data.Map.Strict as Map
import Data.Word (Word64)
import Test.Tasty.HUnit (assertEqual, assertFailure)
import Haskoki.Attribute
  ( AttributeType (..)
  , AttributeValue (..)
  , decodeValue
  )
import Haskoki.Model
  ( Model (..)
  , ObjectState (..)
  , SessionState
  )
import Haskoki.Object (planCopyObject, resolveHandle)
import Haskoki.Operation.Derive
  ( encodeDeriveParams
  , encodeHkdfInfo
  , hkdfDataMech
  , hkdfDeriveMech
  , planDerive
  , pubPrivMech
  )
import Haskoki.Operation.Effect (CryptoEffect (..), CryptoResult (..))
import Haskoki.Operation.Kem
  ( KemAlg (..)
  , kemCtLen
  , mlKemKeyPairGenMech
  , mlKemMech
  , planKemDecaps
  , planKemEncaps
  )
import Haskoki.Operation.KeyManagement
  ( KeyDeny (..)
  , KeyPlan (..)
  , PendingObject (..)
  , PendingWork (..)
  , aesCbcMech
  , aesKeyGenMech
  , aesKwMech
  , aesKwPadMech
  , aesKwpMech
  , aesKwp7Mech
  , ecdhAesKwMech
  , ecdhCofAesKwMech
  , ecdhXAesKwMech
  , chacha20KeyGenMech
  , ckkAes
  , ckkChacha20
  , ckkDes3
  , ckkDh
  , ckkDsa
  , ckkEc
  , ckkEcEdwards
  , ckkEcMontgomery
  , ckkGenericSecret
  , ckkHotp
  , ckkMlDsa
  , ckkMlKem
  , ckkRsa
  , ckkSlhDsa
  , ckkX9_42Dh
  , ckkDes
  , ckkDes2
  , ckkCast
  , ckkCast3
  , ckkCast128
  , ckkRc2
  , ckkRc4
  , ckoData
  , ckoPrivateKey
  , ckoPublicKey
  , ckoSecretKey
  , des3KeyGenMech
  , dhKeyPairGenMech
  , dsaKeyPairGenMech
  , dsaParameterGenMech
  , ecKeyPairGenMech
  , ecExtraBitsKeyPairGenMech
  , dhPkcsParameterGenMech
  , x9_42DhKeyPairGenMech
  , x9_42DhParameterGenMech
  , edwardsKeyPairGenMech
  , montgomeryKeyPairGenMech
  , mldsaKeyPairGenMech
  , finishWork
  , genericSecretKeyGenMech
  , hotpKeyGenMech
  , slhdsaKeyPairGenMech
  , keyBytesOf
  , planAuthUnwrapKey
  , planGenerateKey
  , planGenerateKeyPair
  , ssl3PremasterKeyGenMech
  , tlsPremasterKeyGenMech
  , wtlsPremasterKeyGenMech
  , planUnwrapKey
  , planWrapKey
  , rsaAesKwMech
  , rsaKeyPairGenMech
  , rsaOaepMech
  , rsaPkcsMech
  , rsaX509Mech
  )
import Haskoki.Outcome
  ( NativeOutput (..)
  , PlanResult (..)
  , PreparedCommit (..)
  , Rejection (..)
  , StateDelta (..)
  )
import Haskoki.Registry (MechanismId (..))
import Haskoki.Recipe.Dh (encodeDhParams)
import Haskoki.Recipe.Ecdh (encodeEcdhParams)
import Haskoki.Recipe.Kdf (encodePbkd2Params)
import Haskoki.Recipe.TlsPrf (encodeTlsPrfParams)
import Haskoki.Recipe.Sp800108 (encodeSp800Params)
import Haskoki.Recipe.TlsKdf (encodeTlsKdfParams)
import Haskoki.Recipe.ByteOps (encodeByteOpsParams)
import Haskoki.Recipe.Pbe (encodePbeParams)
import Haskoki.Recipe.Ssl3 (encodeSsl3KeyMatParams, encodeSsl3MasterParams)
import Haskoki.Recipe.TlsKeyMat (encodeTlsKeyMatParams)
import Haskoki.Recipe.Ike (encodeIkeParams)
import Haskoki.Recipe.RsaOaep (encodeOaepParams)
import Haskoki.Recipe.WrapComp (encodeWrapCompEcdhParams)
import Haskoki.Recipe.WrapCompRsa (encodeWrapCompRsaParams)
import Haskoki.Registry.Generated
  ( ckm_AES_CBC_ENCRYPT_DATA
  , ckm_DH_PKCS_DERIVE
  , ckm_ECDH1_DERIVE
  , ckm_ECDH1_COFACTOR_DERIVE
  , ckm_X9_42_DH_DERIVE
  , ckm_PKCS5_PBKD2
  , ckm_SHA256_KEY_DERIVATION
  , ckm_SHAKE_128_KEY_DERIVATION
  , ckm_TLS_PRF
  )
import Haskoki.Request (OutputIntent (..), OutputRegion (..))
import Haskoki.Rules (defaultRules)
import Haskoki.Transition (publishDelta)
import Haskoki.Types
  ( ExternalHandle (..)
  , ReturnCode (..)
  )
import KeyManagement.Fixtures
import KeyManagement.KeygenSweep
import KeyManagement.Part2Fixtures
import KeyManagement.Premaster
import KeyManagement.Part6

-- ---------------------------------------------------------------------------
-- Creation stamping: every path mints explicit protection and history
-- ---------------------------------------------------------------------------

-- | Assert one stored or pending boolean row.
assertStoredBool :: String -> Map.Map AttributeType AttributeValue -> AttributeType -> Bool -> IO ()
assertStoredBool tag attrs t v =
  assertEqual tag (Just (ValBool v)) (Map.lookup t attrs)

-- | Assert the birth-history rows of a freshly generated secret or
-- private key: defaulted protection plus birth history.
assertBirthHistory :: String -> Map.Map AttributeType AttributeValue -> MechanismId -> IO ()
assertBirthHistory tag attrs mech = do
  assertStoredBool (tag ++ " sensitive") attrs AttrSensitive False
  assertStoredBool (tag ++ " extractable") attrs AttrExtractable False
  assertStoredBool (tag ++ " always-sensitive") attrs AttrAlwaysSensitive False
  assertStoredBool (tag ++ " never-extractable") attrs AttrNeverExtractable True
  assertStoredBool (tag ++ " local") attrs AttrLocal True
  assertEqual (tag ++ " key-gen mechanism")
    (Just (ValULong (unMechanismId mech))) (Map.lookup AttrKeyGenMechanism attrs)

-- | Assert the import-history rows of an unwrapped key: the unwrap
-- protection defaults plus false origin rows.
assertImportHistory :: String -> Map.Map AttributeType AttributeValue -> IO ()
assertImportHistory tag attrs = do
  assertStoredBool (tag ++ " sensitive") attrs AttrSensitive False
  assertStoredBool (tag ++ " extractable") attrs AttrExtractable True
  assertStoredBool (tag ++ " always-sensitive") attrs AttrAlwaysSensitive False
  assertStoredBool (tag ++ " never-extractable") attrs AttrNeverExtractable False
  assertStoredBool (tag ++ " local") attrs AttrLocal False
  assertEqual (tag ++ " key-gen mechanism")
    (Just (ValULong maxBound)) (Map.lookup AttrKeyGenMechanism attrs)

-- | Assert one derived secret child: caller-or-inherited protection
-- plus source-derived history.
assertDerivedHistory :: String -> Map.Map AttributeType AttributeValue
  -> Bool -> Bool -> Bool -> Bool -> IO ()
assertDerivedHistory tag attrs sens ext alw nev = do
  assertStoredBool (tag ++ " sensitive") attrs AttrSensitive sens
  assertStoredBool (tag ++ " extractable") attrs AttrExtractable ext
  assertStoredBool (tag ++ " always-sensitive") attrs AttrAlwaysSensitive alw
  assertStoredBool (tag ++ " never-extractable") attrs AttrNeverExtractable nev
  assertStoredBool (tag ++ " local") attrs AttrLocal False
  assertEqual (tag ++ " key-gen mechanism")
    (Just (ValULong maxBound)) (Map.lookup AttrKeyGenMechanism attrs)

-- | Assert one KEM output secret: caller-or-defaulted protection
-- plus false history and origin (exposed material, never a
-- never-extracted claim).
assertKemHistory :: String -> Map.Map AttributeType AttributeValue
  -> Bool -> Bool -> IO ()
assertKemHistory tag attrs sens ext = do
  assertStoredBool (tag ++ " sensitive") attrs AttrSensitive sens
  assertStoredBool (tag ++ " extractable") attrs AttrExtractable ext
  assertStoredBool (tag ++ " always-sensitive") attrs AttrAlwaysSensitive False
  assertStoredBool (tag ++ " never-extractable") attrs AttrNeverExtractable False
  assertStoredBool (tag ++ " local") attrs AttrLocal False
  assertEqual (tag ++ " key-gen mechanism")
    (Just (ValULong maxBound)) (Map.lookup AttrKeyGenMechanism attrs)

-- | Assert that no key row is present (non-key outputs own none).
assertNoKeyRows :: String -> Map.Map AttributeType AttributeValue -> IO ()
assertNoKeyRows tag attrs = mapM_
  (\t -> assertEqual (tag ++ " absent " ++ show t) Nothing (Map.lookup t attrs))
  [AttrSensitive, AttrExtractable, AttrAlwaysSensitive, AttrNeverExtractable, AttrLocal, AttrKeyGenMechanism]

-- | A minimal secret template: class, key type, length and the
-- session mark. No protection or usage flags.
bareSecretTmpl :: Word64 -> Int -> [(AttributeType, AttributeValue)]
bareSecretTmpl kt n =
  [ (AttrClass, ValULong ckoSecretKey)
  , (AttrKeyType, ValULong kt)
  , (AttrValueLen, ValULong (fromIntegral n))
  , (AttrToken, ValBool False)
  ]

-- | AES generation from a minimal template mints explicit birth
-- history: defaulted protection plus the mechanism origin.
caseGenerateStampsKeyAttrs :: IO ()
caseGenerateStampsKeyAttrs = withSynth $ \answer -> do
  m0 <- seedModel
  st <- getSession m0
  let tmpl =
        [ (AttrClass, ValULong ckoSecretKey)
        , (AttrKeyType, ValULong ckkAes)
        , (AttrValueLen, ValULong 16)
        , (AttrToken, ValBool False)
        ]
  (m1, h) <- genAesKey answer m0 st tmpl
  Just ost <- pure (resolveHandle m1 h)
  assertBirthHistory "aes" (osAttrs ost) aesKeyGenMech

-- | A minimal pair mints both halves with birth history: the
-- private half carries the birth rows, the public half the public
-- rows plus origin and no history rows at all.
casePairStampsBothHalves :: IO ()
casePairStampsBothHalves = withSynth $ \answer -> do
  m0 <- seedModel
  st <- getSession m0
  let pub =
        [ (AttrClass, ValULong ckoPublicKey)
        , (AttrKeyType, ValULong ckkMlKem)
        , (AttrKemAlg, ValULong 768)
        , (AttrToken, ValBool False)
        , (AttrPrivate, ValBool False)
        ]
      priv =
        [ (AttrClass, ValULong ckoPrivateKey)
        , (AttrKeyType, ValULong ckkMlKem)
        , (AttrKemAlg, ValULong 768)
        , (AttrToken, ValBool False)
        , (AttrPrivate, ValBool True)
        ]
  (m1, pubH, privH) <-
    case planGenerateKeyPair defaultRules m0 st mlKemKeyPairGenMech pub priv of
      KeyEffect pw fx -> do
        res <- answer m0 fx
        c <- finishCommit m0 st pw res 2
        h1 <- handleOf (pcOutputs c !! 0)
        h2 <- handleOf (pcOutputs c !! 1)
        m' <- expectRight (publishDelta m0 (pcDelta c))
        pure (m', h1, h2)
      other -> assertFailure ("pair plan is not an effect: " ++ show other) >> undefined
  Just pubOst <- pure (resolveHandle m1 pubH)
  Just privOst <- pure (resolveHandle m1 privH)
  assertStoredBool "pub sensitive" (osAttrs pubOst) AttrSensitive False
  assertStoredBool "pub extractable" (osAttrs pubOst) AttrExtractable True
  assertStoredBool "pub local" (osAttrs pubOst) AttrLocal True
  assertEqual "pub key-gen mechanism"
    (Just (ValULong (unMechanismId mlKemKeyPairGenMech)))
    (Map.lookup AttrKeyGenMechanism (osAttrs pubOst))
  assertEqual "pub always-sensitive absent" Nothing
    (Map.lookup AttrAlwaysSensitive (osAttrs pubOst))
  assertEqual "pub never-extractable absent" Nothing
    (Map.lookup AttrNeverExtractable (osAttrs pubOst))
  assertBirthHistory "priv" (osAttrs privOst) mlKemKeyPairGenMech

-- | Mint one sweep row and pin its birth history (the mechanism id
-- proves the stamp ran at that row's own site).
mintSweepStampRow
  :: (Model -> CryptoEffect -> IO CryptoResult)
  -> SessionState -> Model
  -> (String, MechanismId, Word64, SweepLens, Bool)
  -> IO Model
mintSweepStampRow answer st m (label, mech, kt, lens, _parity) = do
  let (good, _, _) = sweepLengths lens
  case good of
    [] -> assertFailure (label ++ " sweep has no good length") >> pure m
    (g0 : _) -> do
      (m', h) <- genSweepKey answer m st mech (sweepTmpl kt g0)
      Just ost <- pure (resolveHandle m' h)
      assertBirthHistory label (osAttrs ost) mech
      pure m'

-- | Every single-key keygen mints birth history: the full sweep
-- table end to end, the bespoke arms end to end, and the PBE rows
-- at plan level (both work shapes).
caseGenerateStampsEveryKeygen :: IO ()
caseGenerateStampsEveryKeygen = withSynth $ \answer -> do
  m0 <- seedModel
  st <- getSession m0
  let go m [] = pure m
      go m (row : rows) = do
        m' <- mintSweepStampRow answer st m row
        go m' rows
  m1 <- go m0 keygenSweepTable
  (m2, hDes3) <- genDes3Key answer m1 st (bareSecretTmpl ckkDes3 24)
  Just ostDes3 <- pure (resolveHandle m2 hDes3)
  assertBirthHistory "des3" (osAttrs ostDes3) des3KeyGenMech
  (m3, hDes3d) <- genDes3Key answer m2 st
    [(AttrClass, ValULong ckoSecretKey), (AttrKeyType, ValULong ckkDes3), (AttrToken, ValBool False)]
  Just ostDes3d <- pure (resolveHandle m3 hDes3d)
  assertEqual "des3 default length" (Just 24) (fmap BS.length (keyBytesOf ostDes3d))
  assertBirthHistory "des3-default" (osAttrs ostDes3d) des3KeyGenMech
  (m4, hHotp) <- genKeyWith answer m3 st hotpKeyGenMech (bareSecretTmpl ckkHotp 32)
  Just ostHotp <- pure (resolveHandle m4 hHotp)
  assertBirthHistory "hotp" (osAttrs ostHotp) hotpKeyGenMech
  (m5, hCha) <- genKeyWith answer m4 st chacha20KeyGenMech (bareSecretTmpl ckkChacha20 32)
  Just ostCha <- pure (resolveHandle m5 hCha)
  assertBirthHistory "chacha20" (osAttrs ostCha) chacha20KeyGenMech
  (m6, hGen) <- genKeyWith answer m5 st genericSecretKeyGenMech (genericTmpl 32)
  Just ostGen <- pure (resolveHandle m6 hGen)
  assertBirthHistory "generic" (osAttrs ostGen) genericSecretKeyGenMech
  (m7, hTls) <- genPremasterKey answer m6 st tlsPremasterKeyGenMech
    (BS.pack [3, 3]) (premasterTmpl 48)
  Just ostTls <- pure (resolveHandle m7 hTls)
  assertBirthHistory "tls-premaster" (osAttrs ostTls) tlsPremasterKeyGenMech
  (m8, hSsl) <- genPremasterKey answer m7 st ssl3PremasterKeyGenMech
    (BS.pack [3, 0]) (premasterTmpl 48)
  Just ostSsl <- pure (resolveHandle m8 hSsl)
  assertBirthHistory "ssl3-premaster" (osAttrs ostSsl) ssl3PremasterKeyGenMech
  (m9, hWtls) <- genPremasterKey answer m8 st wtlsPremasterKeyGenMech
    (BS.singleton 1) (premasterTmpl 32)
  Just ostWtls <- pure (resolveHandle m9 hWtls)
  assertBirthHistory "wtls-premaster" (osAttrs ostWtls) wtlsPremasterKeyGenMech
  let pbkd2Mech = MechanismId ckm_PKCS5_PBKD2
      pbkd2Frame = encodePbkd2Params 4 4096 "salt" "password"
  (m10, hPbkd2) <- genPremasterKey answer m9 st pbkd2Mech pbkd2Frame (premasterTmpl 32)
  Just ostPbkd2 <- pure (resolveHandle m10 hPbkd2)
  assertBirthHistory "pbkd2-generic" (osAttrs ostPbkd2) pbkd2Mech
  (m11, hPbkd2a) <- genPremasterKey answer m10 st pbkd2Mech pbkd2Frame (bareSecretTmpl ckkAes 32)
  Just ostPbkd2a <- pure (resolveHandle m11 hPbkd2a)
  assertEqual "pbkd2 aes type" (Just (ValULong ckkAes))
    (Map.lookup AttrKeyType (osAttrs ostPbkd2a))
  assertBirthHistory "pbkd2-aes" (osAttrs ostPbkd2a) pbkd2Mech
  -- The PBE rows plan with birth history on both work shapes
  -- (key-only RC4 rows, key-plus-IV rows).
  let pbeFrame = encodePbeParams 1024 pbePw pbeSalt
      pbeBare k =
        [ (AttrClass, ValULong ckoSecretKey)
        , (AttrKeyType, ValULong k)
        , (AttrEncrypt, ValBool True)
        , (AttrDecrypt, ValBool True)
        , (AttrToken, ValBool False)
        ]
  mapM_ (\(mech, wantKey) ->
    case planGenerateKey defaultRules m11 st mech pbeFrame (pbeBare wantKey) of
      KeyEffect (PwGenerateKey po) _ ->
        assertBirthHistory ("pbe " ++ show mech) (poAttrs po) mech
      KeyEffect (PwGenerateKeyIv po _) _ ->
        assertBirthHistory ("pbe " ++ show mech) (poAttrs po) mech
      other -> assertFailure ("PBE must plan, got: " ++ show other))
    [ (pbeDes3Mech, ckkDes3), (pbeDes2Mech, ckkDes2)
    , (pbeSha1Cast128Mech, ckkCast128)
    , (pbeSha1Rc4_128Mech, ckkRc4)
    , (pbeSha1Rc4_40Mech, ckkRc4)
    , (pbeSha1Rc2_128Mech, ckkRc2)
    , (pbeSha1Rc2_40Mech, ckkRc2)
    , (pbeMd5DesMech, ckkDes)
    , (pbeMd5CastMech, ckkCast)
    , (pbeMd5Cast3Mech, ckkCast3)
    , (pbeMd5Cast128Mech, ckkCast128)
    ]

-- | Assert the public-half rows of a freshly generated pair: the
-- public protection rows plus origin, with no history rows.
assertPubBirthHistory :: String -> Map.Map AttributeType AttributeValue -> MechanismId -> IO ()
assertPubBirthHistory tag attrs mech = do
  assertStoredBool (tag ++ " sensitive") attrs AttrSensitive False
  assertStoredBool (tag ++ " extractable") attrs AttrExtractable True
  assertStoredBool (tag ++ " local") attrs AttrLocal True
  assertEqual (tag ++ " key-gen mechanism")
    (Just (ValULong (unMechanismId mech))) (Map.lookup AttrKeyGenMechanism attrs)
  assertEqual (tag ++ " always-sensitive absent") Nothing
    (Map.lookup AttrAlwaysSensitive attrs)
  assertEqual (tag ++ " never-extractable absent") Nothing
    (Map.lookup AttrNeverExtractable attrs)

-- | Every pair mechanism mints both halves with birth history end
-- to end; domain-parameter outputs own no key rows; explicit
-- caller flags win on both halves.
casePairStampsEveryPair :: IO ()
casePairStampsEveryPair = withSynth $ \answer -> do
  m0 <- seedModel
  st <- getSession m0
  let barePub kt extra =
        [(AttrClass, ValULong ckoPublicKey), (AttrKeyType, ValULong kt), (AttrToken, ValBool False)]
          ++ extra
      barePriv kt =
        [ (AttrClass, ValULong ckoPrivateKey)
        , (AttrKeyType, ValULong kt)
        , (AttrToken, ValBool False)
        , (AttrPrivate, ValBool True)
        ]
      mintOne m (tag, mech, pubT, privT) =
        case planGenerateKeyPair defaultRules m st mech pubT privT of
          KeyEffect pw fx -> do
            res <- answer m fx
            c <- finishCommit m st pw res 2
            pubH <- handleOf (pcOutputs c !! 0)
            privH <- handleOf (pcOutputs c !! 1)
            m' <- expectRight (publishDelta m (pcDelta c))
            Just pubOst <- pure (resolveHandle m' pubH)
            Just privOst <- pure (resolveHandle m' privH)
            assertPubBirthHistory tag (osAttrs pubOst) mech
            assertBirthHistory tag (osAttrs privOst) mech
            pure m'
          other -> assertFailure (tag ++ " pair plan is not an effect: " ++ show other)
            >> undefined
      go m [] = pure m
      go m (row : rows) = do
        m' <- mintOne m row
        go m' rows
  m1 <- go m0
    [ ("kem", mlKemKeyPairGenMech
      , barePub ckkMlKem [(AttrKemAlg, ValULong 768), (AttrPrivate, ValBool False)]
      , barePriv ckkMlKem ++ [(AttrKemAlg, ValULong 768)])
    , ("ec", ecKeyPairGenMech
      , barePub ckkEc [(AttrEcParams, ValBytes "P-256")]
      , barePriv ckkEc)
    , ("ec-extra-bits", ecExtraBitsKeyPairGenMech
      , barePub ckkEc [(AttrEcParams, ValBytes "P-256")]
      , barePriv ckkEc)
    , ("rsa", rsaKeyPairGenMech
      , barePub ckkRsa [(AttrModulusBits, ValULong 2048)]
      , barePriv ckkRsa ++ [(AttrModulusBits, ValULong 2048)])
    , ("dsa", dsaKeyPairGenMech
      , barePub ckkDsa
          [(AttrPrime, ValBytes dsaP), (AttrSubprime, ValBytes dsaQ), (AttrBase, ValBytes dsaG)]
      , barePriv ckkDsa)
    , ("dh", dhKeyPairGenMech
      , barePub ckkDh [(AttrPrime, ValBytes dhP), (AttrBase, ValBytes dhG)]
      , barePriv ckkDh)
    , ("x9.42-dh", x9_42DhKeyPairGenMech
      , barePub ckkX9_42Dh
          [(AttrPrime, ValBytes dhP), (AttrBase, ValBytes dhG), (AttrSubprime, ValBytes dhQ)]
      , barePriv ckkX9_42Dh)
    , ("edwards", edwardsKeyPairGenMech
      , barePub ckkEcEdwards [(AttrEcParams, ValBytes "Ed25519")]
      , barePriv ckkEcEdwards)
    , ("montgomery", montgomeryKeyPairGenMech
      , barePub ckkEcMontgomery [(AttrEcParams, ValBytes "X25519")]
      , barePriv ckkEcMontgomery)
    , ("ml-dsa", mldsaKeyPairGenMech
      , barePub ckkMlDsa [(AttrParameterSet, ValULong 1)]
      , barePriv ckkMlDsa)
    , ("slh-dsa", slhdsaKeyPairGenMech
      , barePub ckkSlhDsa [(AttrParameterSet, ValULong 1)]
      , barePriv ckkSlhDsa)
    ]
  -- Domain-parameter outputs are not keys: no protection or
  -- history rows are stamped.
  mapM_ (\(tag, mech, tmpl) ->
    case planGenerateKey defaultRules m1 st mech BS.empty tmpl of
      KeyEffect (PwGenerateKey po) _ -> assertNoKeyRows tag (poAttrs po)
      other -> assertFailure (tag ++ " paramgen must plan, got: " ++ show other))
    [ ("dsa-params", dsaParameterGenMech, dsaParamsTmpl 1024)
    , ("x9.42-params", x9_42DhParameterGenMech, x942ParamsTmpl 2048 256)
    , ("dh-pkcs-params", dhPkcsParameterGenMech, dhPkcsParamsTmpl 2048 256)
    ]
  -- Explicit caller flags win on both halves; the private history
  -- follows the birth flags, the public half keeps no history.
  let expPub =
        barePub ckkRsa [(AttrModulusBits, ValULong 2048), (AttrSensitive, ValBool True)]
      expPriv =
        barePriv ckkRsa ++ [(AttrModulusBits, ValULong 2048)
          , (AttrSensitive, ValBool True), (AttrExtractable, ValBool True)]
  case planGenerateKeyPair defaultRules m1 st rsaKeyPairGenMech expPub expPriv of
    KeyEffect (PwGeneratePair pub priv) _ -> do
      assertStoredBool "explicit pub sensitive" (poAttrs pub) AttrSensitive True
      assertStoredBool "explicit pub extractable" (poAttrs pub) AttrExtractable True
      assertStoredBool "explicit pub local" (poAttrs pub) AttrLocal True
      assertEqual "explicit pub always-sensitive absent" Nothing
        (Map.lookup AttrAlwaysSensitive (poAttrs pub))
      assertEqual "explicit pub never-extractable absent" Nothing
        (Map.lookup AttrNeverExtractable (poAttrs pub))
      assertStoredBool "explicit priv sensitive" (poAttrs priv) AttrSensitive True
      assertStoredBool "explicit priv extractable" (poAttrs priv) AttrExtractable True
      assertStoredBool "explicit priv always-sensitive" (poAttrs priv) AttrAlwaysSensitive True
      assertStoredBool "explicit priv never-extractable" (poAttrs priv) AttrNeverExtractable False
      assertStoredBool "explicit priv local" (poAttrs priv) AttrLocal True
    other -> assertFailure ("explicit pair must plan, got: " ++ show other)

-- | Explicit birth flags drive the history rows end to end: a
-- sensitive birth stamps always-sensitive true, an extractable
-- birth stamps never-extractable false.
caseGenerateExplicitBirthFlags :: IO ()
caseGenerateExplicitBirthFlags = withSynth $ \answer -> do
  m0 <- seedModel
  st <- getSession m0
  let mint tag sens ext = do
        (m', h) <- genAesKey answer m0 st
          [ (AttrClass, ValULong ckoSecretKey)
          , (AttrKeyType, ValULong ckkAes)
          , (AttrValueLen, ValULong 16)
          , (AttrToken, ValBool False)
          , (AttrSensitive, ValBool sens)
          , (AttrExtractable, ValBool ext)
          ]
        Just ost <- pure (resolveHandle m' h)
        assertStoredBool (tag ++ " sensitive") (osAttrs ost) AttrSensitive sens
        assertStoredBool (tag ++ " extractable") (osAttrs ost) AttrExtractable ext
        assertStoredBool (tag ++ " always-sensitive") (osAttrs ost) AttrAlwaysSensitive sens
        assertStoredBool (tag ++ " never-extractable") (osAttrs ost) AttrNeverExtractable (not ext)
        assertStoredBool (tag ++ " local") (osAttrs ost) AttrLocal True
        assertEqual (tag ++ " key-gen mechanism")
          (Just (ValULong (unMechanismId aesKeyGenMech)))
          (Map.lookup AttrKeyGenMechanism (osAttrs ost))
  mint "sensitive-extractable" True True
  mint "sensitive-locked" True False

-- | Project the pending attributes out of any unwrap plan shape.
unwrapPending :: String -> KeyPlan -> IO (Map.Map AttributeType AttributeValue)
unwrapPending tag plan = case plan of
  KeyEffect (PwUnwrap po) _ -> pure (poAttrs po)
  KeyEffect (PwUnwrapRaw po) _ -> pure (poAttrs po)
  KeyEffect (PwUnwrapPad8 po) _ -> pure (poAttrs po)
  KeyEffect (PwUnwrapTail po _ _) _ -> pure (poAttrs po)
  other -> assertFailure (tag ++ " unwrap plan is not an effect: " ++ show other) >> undefined

-- | Every unwrap mechanism stamps import history on its pending
-- child; explicit caller flags win but never forge history.
caseUnwrapStampsEveryMech :: IO ()
caseUnwrapStampsEveryMech = withSynth $ \answer -> do
  m0 <- seedModel >>= loginUser
  st <- getSession m0
  (m1, wrapH) <- genAesKey answer m0 st wrapKeyTmpl
  (m2, targetH) <- genAesKey answer m1 st (aesTmpl 16)
  let bareTmpl =
        [ (AttrClass, ValULong ckoSecretKey)
        , (AttrKeyType, ValULong ckkAes)
        , (AttrToken, ValBool False)
        ]
      wrapBlob m mech params wh th = do
        n <- case planWrapKey m st mech params wh th IntentNull of
          KeyImmediate (Immediate c) -> case pcOutputs c of
            [NativeOutput (RegionBytes "wrapped" _) bs] -> case decodeValue AttrValueLen bs of
              Just (ValULong k) -> pure (fromIntegral k)
              _ -> assertFailure ("query length shape " ++ show mech) >> undefined
            o -> assertFailure ("query outputs: " ++ show o) >> undefined
          other -> assertFailure ("query must commit: " ++ show other) >> undefined
        case planWrapKey m st mech params wh th (IntentBuffer n) of
          KeyEffect pw fx -> do
            res <- answer m fx
            case finishWork m st pw res of
              Immediate c -> case pcOutputs c of
                [NativeOutput (RegionBytes "wrapped" _) bs] -> pure bs
                o -> assertFailure ("wrap outputs one blob, got: " ++ show o) >> undefined
              other -> assertFailure ("wrap finish must commit, got: " ++ show other) >> undefined
          other -> assertFailure ("wrap plan is not an effect: " ++ show other) >> undefined
      mintPair m tag mech pubT privT =
        case planGenerateKeyPair defaultRules m st mech pubT privT of
          KeyEffect pw fx -> do
            res <- answer m fx
            c <- finishCommit m st pw res 2
            pubH <- handleOf (pcOutputs c !! 0)
            privH <- handleOf (pcOutputs c !! 1)
            m' <- expectRight (publishDelta m (pcDelta c))
            pure (m', pubH, privH)
          other -> assertFailure (tag ++ " pair plan is not an effect: " ++ show other)
            >> undefined
  -- The AES rows plan over shaped blobs (no wrap needed).
  poCbc <- unwrapPending "aes-cbc"
    (planUnwrapKey defaultRules m2 st aesCbcMech iv16 wrapH (BS.replicate 32 0) bareTmpl)
  assertImportHistory "aes-cbc" poCbc
  poKw <- unwrapPending "aes-kw"
    (planUnwrapKey defaultRules m2 st aesKwMech BS.empty wrapH (BS.replicate 24 0) bareTmpl)
  assertImportHistory "aes-kw" poKw
  poKwp <- unwrapPending "aes-kwp"
    (planUnwrapKey defaultRules m2 st aesKwpMech BS.empty wrapH (BS.replicate 16 0) bareTmpl)
  assertImportHistory "aes-kwp" poKwp
  poKwPad <- unwrapPending "aes-kw-pad"
    (planUnwrapKey defaultRules m2 st aesKwPadMech BS.empty wrapH (BS.replicate 16 0) bareTmpl)
  assertImportHistory "aes-kw-pad" poKwPad
  poKwp7 <- unwrapPending "aes-kw-pkcs7"
    (planUnwrapKey defaultRules m2 st aesKwp7Mech BS.empty wrapH (BS.replicate 24 0) bareTmpl)
  assertImportHistory "aes-kw-pkcs7" poKwp7
  -- The RSA rows plan over modulus-wide blobs.
  (m3, rsaPubH, rsaPrivH) <- mintPair m2 "rsa" rsaKeyPairGenMech
    (rsaPubTmpl ++ [(AttrWrap, ValBool True)])
    (rsaPrivTmpl ++ [(AttrUnwrap, ValBool True)])
  let oaep = encodeOaepParams "SHA256" "SHA256" BS.empty
      rsaBlob = BS.replicate 256 0
  poPkcs <- unwrapPending "rsa-pkcs"
    (planUnwrapKey defaultRules m3 st rsaPkcsMech BS.empty rsaPrivH rsaBlob bareTmpl)
  assertImportHistory "rsa-pkcs" poPkcs
  poOaep <- unwrapPending "rsa-oaep"
    (planUnwrapKey defaultRules m3 st rsaOaepMech oaep rsaPrivH rsaBlob bareTmpl)
  assertImportHistory "rsa-oaep" poOaep
  poX509 <- unwrapPending "rsa-x509"
    (planUnwrapKey defaultRules m3 st rsaX509Mech BS.empty rsaPrivH rsaBlob
      (bareTmpl ++ [(AttrValueLen, ValULong 16)]))
  assertImportHistory "rsa-x509" poX509
  -- The composition rows plan over freshly wrapped blobs.
  (m4, ecPubH, ecPrivH) <- mintPair m3 "ec" ecKeyPairGenMech
    (ecPubTmpl ++ [(AttrWrap, ValBool True)])
    (ecPrivTmpl ++ [(AttrUnwrap, ValBool True)])
  let compParams = encodeWrapCompEcdhParams 0 BS.empty 128
  mapM_ (\mech -> do
    blob <- wrapBlob m4 mech compParams ecPubH targetH
    po <- unwrapPending (show mech)
      (planUnwrapKey defaultRules m4 st mech compParams ecPrivH blob bareTmpl)
    assertImportHistory (show mech) po)
    [ecdhAesKwMech, ecdhCofAesKwMech]
  (m5, xdPubH, xdPrivH) <- mintPair m4 "xdh" montgomeryKeyPairGenMech
    (xdPubTmpl ++ [(AttrWrap, ValBool True)])
    (xdPrivTmpl ++ [(AttrUnwrap, ValBool True)])
  blobX <- wrapBlob m5 ecdhXAesKwMech compParams xdPubH targetH
  poX <- unwrapPending "ecdh-x"
    (planUnwrapKey defaultRules m5 st ecdhXAesKwMech compParams xdPrivH blobX bareTmpl)
  assertImportHistory "ecdh-x" poX
  let rsaCompParams = encodeWrapCompRsaParams "SHA256" "SHA256" BS.empty 256
  blobRsa <- wrapBlob m5 rsaAesKwMech rsaCompParams rsaPubH targetH
  poRsa <- unwrapPending "rsa-comp"
    (planUnwrapKey defaultRules m5 st rsaAesKwMech rsaCompParams rsaPrivH blobRsa bareTmpl)
  assertImportHistory "rsa-comp" poRsa
  -- Authenticated unwrap stamps the same import history.
  poAuth <- unwrapPending "auth"
    (planAuthUnwrapKey defaultRules m5 st aesCbcMech iv16 wrapH
      (BS.replicate 64 0) "auth-aad" bareTmpl)
  assertImportHistory "auth" poAuth
  -- Explicit caller flags win on the child but history stays
  -- false: unwrapped material was exposed outside the token.
  poExp <- unwrapPending "explicit"
    (planUnwrapKey defaultRules m5 st aesCbcMech iv16 wrapH (BS.replicate 32 0)
      (bareTmpl ++ [(AttrSensitive, ValBool True), (AttrExtractable, ValBool False)]))
  assertStoredBool "explicit sensitive" poExp AttrSensitive True
  assertStoredBool "explicit extractable" poExp AttrExtractable False
  assertStoredBool "explicit always-sensitive" poExp AttrAlwaysSensitive False
  assertStoredBool "explicit never-extractable" poExp AttrNeverExtractable False
  assertStoredBool "explicit local" poExp AttrLocal False
  assertEqual "explicit key-gen mechanism"
    (Just (ValULong maxBound)) (Map.lookup AttrKeyGenMechanism poExp)

ecdhMech, dhPkcsMech, tlsPrfMech, encDataMech, shake128Mech, sha256KdfMech :: MechanismId
ecdhMech = MechanismId ckm_ECDH1_DERIVE
dhPkcsMech = MechanismId ckm_DH_PKCS_DERIVE
tlsPrfMech = MechanismId ckm_TLS_PRF
encDataMech = MechanismId ckm_AES_CBC_ENCRYPT_DATA
shake128Mech = MechanismId ckm_SHAKE_128_KEY_DERIVATION
sha256KdfMech = MechanismId ckm_SHA256_KEY_DERIVATION

-- | Plan one derive and project the first pending child's
-- attributes (single-output legs).
derivePending :: String -> Model -> SessionState -> MechanismId -> ExternalHandle
  -> ByteString -> [[(AttributeType, AttributeValue)]] -> IO (Map.Map AttributeType AttributeValue)
derivePending tag m st mech base blob tmpls =
  case planDerive defaultRules m st mech base (encodeDeriveParams blob tmpls) of
    KeyEffect (PwDerive (po : _) _) _ -> pure (poAttrs po)
    other -> assertFailure (tag ++ " derive must plan, got: " ++ show other) >> undefined

-- | Every derive family stamps source-derived history: omitted
-- protection inherits the sources, history follows the child flags
-- and the source history, origin stays false. Data outputs own no
-- key rows; the public row stamps the public set.
caseDeriveStampsEveryFamily :: IO ()
caseDeriveStampsEveryFamily = withSynth $ \answer -> do
  m0 <- seedModel
  st <- getSession m0
  (m1, protH) <- plantKey m0 st
    [ (AttrClass, ValULong ckoSecretKey)
    , (AttrKeyType, ValULong ckkGenericSecret)
    , (AttrToken, ValBool False)
    , (AttrDerive, ValBool True)
    , (AttrSensitive, ValBool True)
    , (AttrExtractable, ValBool False)
    ] (BS.pack [0 .. 31])
  (m2, plainH) <- plantKey m1 st
    [ (AttrClass, ValULong ckoSecretKey)
    , (AttrKeyType, ValULong ckkGenericSecret)
    , (AttrToken, ValBool False)
    , (AttrDerive, ValBool True)
    , (AttrSensitive, ValBool False)
    , (AttrExtractable, ValBool True)
    ] (BS.pack [0 .. 31])
  (m3, ecH) <- plantKey m2 st
    [ (AttrClass, ValULong ckoPrivateKey)
    , (AttrKeyType, ValULong ckkEc)
    , (AttrToken, ValBool False)
    , (AttrDerive, ValBool True)
    , (AttrSensitive, ValBool True)
    , (AttrExtractable, ValBool False)
    ] (BS.pack [0 .. 63])
  (m4, dhH) <- plantKey m3 st
    [ (AttrClass, ValULong ckoPrivateKey)
    , (AttrKeyType, ValULong ckkDh)
    , (AttrToken, ValBool False)
    , (AttrDerive, ValBool True)
    , (AttrSensitive, ValBool True)
    , (AttrExtractable, ValBool False)
    ] (BS.pack [0 .. 63])
  (m5, aesH) <- plantKey m4 st
    [ (AttrClass, ValULong ckoSecretKey)
    , (AttrKeyType, ValULong ckkAes)
    , (AttrToken, ValBool False)
    , (AttrDerive, ValBool True)
    ] (BS.pack [0 .. 15])
  (m6, rsaH) <- plantKey m5 st
    [ (AttrClass, ValULong ckoPrivateKey)
    , (AttrKeyType, ValULong ckkRsa)
    , (AttrToken, ValBool False)
    ] (BS.pack [0 .. 63])
  (m7, auxH) <- plantKey m6 st
    [ (AttrClass, ValULong ckoSecretKey)
    , (AttrKeyType, ValULong ckkGenericSecret)
    , (AttrToken, ValBool False)
    , (AttrDerive, ValBool True)
    , (AttrSensitive, ValBool False)
    , (AttrExtractable, ValBool True)
    ] (BS.pack [32 .. 63])
  let kid :: Int -> [(AttributeType, AttributeValue)]
      kid n =
        [ (AttrClass, ValULong ckoSecretKey)
        , (AttrKeyType, ValULong ckkGenericSecret)
        , (AttrValueLen, ValULong (fromIntegral n))
        , (AttrToken, ValBool False)
        ]
      auxN = fromIntegral (unExternalHandle auxH)
  poHkdf <- derivePending "hkdf" m7 st hkdfDeriveMech protH
    (encodeHkdfInfo 4 0x02 BS.empty "stamp-info") [kid 32]
  assertDerivedHistory "hkdf" poHkdf True False False False
  poEcdh <- derivePending "ecdh" m7 st ecdhMech ecH
    (encodeEcdhParams 0 BS.empty (BS.pack [1 .. 32])) [kid 32]
  assertDerivedHistory "ecdh" poEcdh True False False False
  poDh <- derivePending "dh-pkcs" m7 st dhPkcsMech dhH
    (encodeDhParams 0 (BS.pack [1 .. 32])) [kid 32]
  assertDerivedHistory "dh-pkcs" poDh True False False False
  poShaKdf <- derivePending "sha256-kdf" m7 st sha256KdfMech plainH
    BS.empty [[(AttrClass, ValULong ckoSecretKey), (AttrToken, ValBool False)]]
  assertDerivedHistory "sha256-kdf" poShaKdf False True False False
  poXof <- derivePending "shake128" m7 st shake128Mech plainH BS.empty [kid 40]
  assertDerivedHistory "shake128" poXof False True False False
  poPrf <- derivePending "tls-prf" m7 st tlsPrfMech plainH
    (encodeTlsPrfParams "label" (BS.pack [0 .. 31])) [kid 32]
  assertDerivedHistory "tls-prf" poPrf False True False False
  poTlsKdf <- derivePending "tls-kdf" m7 st tlsKdfFreeMech plainH
    (encodeTlsKdfParams 4 "key expansion" tlsKdfSeed64 BS.empty) [kid 32]
  assertDerivedHistory "tls-kdf" poTlsKdf False True False False
  case planDerive defaultRules m7 st keyMat12Mech plainH
      (encodeDeriveParams (encodeTlsKeyMatParams 4 0 16 16 keyMatCr keyMatSr)
        [[(AttrClass, ValULong ckoSecretKey)
          , (AttrKeyType, ValULong ckkGenericSecret)
          , (AttrToken, ValBool False)]]) of
    KeyEffect (PwDeriveIv pos [16, 16] _) _ ->
      mapM_ (\po -> assertDerivedHistory "tls-keymat" (poAttrs po) False True False False) pos
    other -> assertFailure ("tls-keymat must plan, got: " ++ show other)
  poSsl3m <- derivePending "ssl3-master" m7 st ssl3MasterMech plainH
    (encodeSsl3MasterParams ssl3Cr ssl3Sr)
    [[ (AttrClass, ValULong ckoSecretKey)
      , (AttrKeyType, ValULong ckkGenericSecret)
      , (AttrValueLen, ValULong 48)
      , (AttrToken, ValBool False)
      , (AttrDerive, ValBool True)
      ]]
  assertDerivedHistory "ssl3-master" poSsl3m False True False False
  case planDerive defaultRules m7 st ssl3KeyMatMech plainH
      (encodeDeriveParams (encodeSsl3KeyMatParams 16 16 16 ssl3Cr ssl3Sr)
        [[(AttrClass, ValULong ckoSecretKey)
          , (AttrKeyType, ValULong ckkGenericSecret)
          , (AttrToken, ValBool False)]]) of
    KeyEffect (PwDeriveIv pos [16, 16, 16, 16] _) _ ->
      mapM_ (\po -> assertDerivedHistory "ssl3-keymat" (poAttrs po) False True False False) pos
    other -> assertFailure ("ssl3-keymat must plan, got: " ++ show other)
  poIke <- derivePending "ike-plus" m7 st ikePlusMech plainH
    (encodeIkeParams 4 0 0 0 ikeSeed32 BS.empty) [kid 32]
  assertDerivedHistory "ike-plus" poIke False True False False
  poIkeAux <- derivePending "ike1-aux" m7 st ike1Mech plainH
    (encodeIkeParams 4 0 7 auxN ikeNi ikeNr) [kid 32]
  assertDerivedHistory "ike1-aux" poIkeAux False True False False
  poSp800 <- derivePending "sp800" m7 st sp800CounterMech plainH
    (encodeSp800Params 4 32 32 BS.empty sp800Fixed)
    [[ (AttrClass, ValULong ckoSecretKey)
      , (AttrKeyType, ValULong ckkAes)
      , (AttrValueLen, ValULong 16)
      , (AttrToken, ValBool False)
      ]]
  assertDerivedHistory "sp800" poSp800 False True False False
  poEncData <- derivePending "encrypt-data" m7 st encDataMech aesH
    (iv16 <> BS.pack [0 .. 31]) [kid 32]
  assertDerivedHistory "encrypt-data" poEncData False False False False
  case planDerive defaultRules m7 st hkdfDataMech plainH
      (encodeDeriveParams (encodeHkdfInfo 4 0x03 BS.empty rfcInfo)
        [[ (AttrClass, ValULong ckoData)
          , (AttrValueLen, ValULong 42)
          , (AttrToken, ValBool False)
          ]]) of
    KeyEffect (PwDerive (po : _) _) _ -> assertNoKeyRows "hkdf-data" (poAttrs po)
    other -> assertFailure ("hkdf-data must plan, got: " ++ show other)
  case planDerive defaultRules m7 st pubPrivMech rsaH
      (encodeDeriveParams BS.empty
        [[ (AttrClass, ValULong ckoPublicKey)
          , (AttrKeyType, ValULong ckkRsa)
          , (AttrToken, ValBool False)
          ]]) of
    KeyEffect (PwDerivePub po kty) _ -> do
      assertEqual "pubpriv type" ckkRsa kty
      assertStoredBool "pubpriv sensitive" (poAttrs po) AttrSensitive False
      assertStoredBool "pubpriv extractable" (poAttrs po) AttrExtractable True
      assertStoredBool "pubpriv local" (poAttrs po) AttrLocal False
      assertEqual "pubpriv key-gen mechanism"
        (Just (ValULong maxBound)) (Map.lookup AttrKeyGenMechanism (poAttrs po))
      assertEqual "pubpriv always-sensitive absent" Nothing
        (Map.lookup AttrAlwaysSensitive (poAttrs po))
      assertEqual "pubpriv never-extractable absent" Nothing
        (Map.lookup AttrNeverExtractable (poAttrs po))
    other -> assertFailure ("pubpriv must plan, got: " ++ show other)
  -- True history propagates: a generated locked base derives a
  -- child that is still always-sensitive and never-extractable.
  (m8, genH) <- genKeyWith answer m7 st genericSecretKeyGenMech
    [ (AttrClass, ValULong ckoSecretKey)
    , (AttrKeyType, ValULong ckkGenericSecret)
    , (AttrValueLen, ValULong 32)
    , (AttrToken, ValBool False)
    , (AttrDerive, ValBool True)
    , (AttrSensitive, ValBool True)
    , (AttrExtractable, ValBool False)
    ]
  Just genOst <- pure (resolveHandle m8 genH)
  assertStoredBool "generated base always" (osAttrs genOst) AttrAlwaysSensitive True
  assertStoredBool "generated base never" (osAttrs genOst) AttrNeverExtractable True
  poTrue <- derivePending "hkdf-true" m8 st hkdfDeriveMech genH
    (encodeHkdfInfo 4 0x02 BS.empty "stamp-true") [kid 32]
  assertDerivedHistory "hkdf-true" poTrue True False True True
  poTrueByte <- derivePending "concat-true" m8 st concatDataMech genH
    (encodeByteOpsParams 0 0 byteOpsD16) [kid 48]
  assertDerivedHistory "concat-true" poTrueByte True False True True
  -- One history-free aux poisons the conjunction: the child keeps
  -- the inherited protection but loses both history rows.
  poAnd <- derivePending "concat-aux-and" m8 st concatKeyMech genH
    (encodeByteOpsParams auxN 0 BS.empty) [kid 64]
  assertDerivedHistory "concat-aux-and" poAnd True False False False
  -- Explicit caller flags win over inheritance; history follows
  -- the child flags, not the base.
  poExp <- derivePending "hkdf-explicit" m8 st hkdfDeriveMech protH
    (encodeHkdfInfo 4 0x02 BS.empty "stamp-explicit")
    [[ (AttrClass, ValULong ckoSecretKey)
      , (AttrKeyType, ValULong ckkGenericSecret)
      , (AttrValueLen, ValULong 32)
      , (AttrToken, ValBool False)
      , (AttrSensitive, ValBool False)
      , (AttrExtractable, ValBool True)
      ]]
  assertDerivedHistory "hkdf-explicit" poExp False True False False

-- | Copies of generated keys inherit birth history: an
-- empty-template copy keeps the true history rows and the origin,
-- forging history through the template is refused, and sensitizing
-- a born-open key keeps always-sensitive false.
caseCopyGeneratedKeyDerivesHistory :: IO ()
caseCopyGeneratedKeyDerivesHistory = withSynth $ \answer -> do
  m0 <- seedModel >>= loginUser
  st <- getSession m0
  (m1, h) <- genAesKey answer m0 st
    [ (AttrClass, ValULong ckoSecretKey)
    , (AttrKeyType, ValULong ckkAes)
    , (AttrValueLen, ValULong 16)
    , (AttrToken, ValBool False)
    , (AttrSensitive, ValBool True)
    , (AttrExtractable, ValBool False)
    ]
  Just src <- pure (resolveHandle m1 h)
  assertStoredBool "source always-sensitive" (osAttrs src) AttrAlwaysSensitive True
  assertStoredBool "source never-extractable" (osAttrs src) AttrNeverExtractable True
  (m2, copyH) <- case planCopyObject m1 st h [] of
    Immediate c -> do
      ch <- handleOf (pcOutputs c !! 0)
      m' <- expectRight (publishDelta m1 (pcDelta c))
      pure (m', ch)
    other -> assertFailure ("copy must commit: " ++ show other) >> undefined
  Just cpy <- pure (resolveHandle m2 copyH)
  assertStoredBool "copy sensitive" (osAttrs cpy) AttrSensitive True
  assertStoredBool "copy extractable" (osAttrs cpy) AttrExtractable False
  assertStoredBool "copy always-sensitive" (osAttrs cpy) AttrAlwaysSensitive True
  assertStoredBool "copy never-extractable" (osAttrs cpy) AttrNeverExtractable True
  assertStoredBool "copy local" (osAttrs cpy) AttrLocal True
  assertEqual "copy key-gen mechanism"
    (Just (ValULong (unMechanismId aesKeyGenMech)))
    (Map.lookup AttrKeyGenMechanism (osAttrs cpy))
  mapM_ (\(tag, attr) ->
    case planCopyObject m2 st h [attr] of
      Reject r -> do
        assertEqual (tag ++ " code") CKR_ATTRIBUTE_READ_ONLY (rejCode r)
        assertEqual (tag ++ " delta") (StateDelta []) (rejDelta r)
      other -> assertFailure (tag ++ " forge must refuse, got: " ++ show other))
    [ ("local", (AttrLocal, ValBool False))
    , ("always", (AttrAlwaysSensitive, ValBool False))
    , ("never", (AttrNeverExtractable, ValBool False))
    , ("kgm", (AttrKeyGenMechanism, ValULong 0))
    ]
  (m3, openH) <- genAesKey answer m2 st
    [ (AttrClass, ValULong ckoSecretKey)
    , (AttrKeyType, ValULong ckkAes)
    , (AttrValueLen, ValULong 16)
    , (AttrToken, ValBool False)
    ]
  (m4, sensH) <- case planCopyObject m3 st openH [(AttrSensitive, ValBool True)] of
    Immediate c -> do
      ch <- handleOf (pcOutputs c !! 0)
      m' <- expectRight (publishDelta m3 (pcDelta c))
      pure (m', ch)
    other -> assertFailure ("sensitize must commit: " ++ show other) >> undefined
  Just sensOst <- pure (resolveHandle m4 sensH)
  assertStoredBool "sensitized sensitive" (osAttrs sensOst) AttrSensitive True
  assertStoredBool "sensitized always-sensitive" (osAttrs sensOst) AttrAlwaysSensitive False
  assertStoredBool "sensitized never-extractable" (osAttrs sensOst) AttrNeverExtractable True
  assertStoredBool "sensitized local" (osAttrs sensOst) AttrLocal True

-- Shared fixtures for the class-gate legs: one 32-byte
-- generic-secret target, one ECDH peer frame, one DH peer frame,
-- and a confused-base attribute constructor. Each refused leg is
-- its own case so each leg shows its own failure.
gateTmpl :: [(AttributeType, AttributeValue)]
gateTmpl =
  [ (AttrClass, ValULong ckoSecretKey)
  , (AttrKeyType, ValULong ckkGenericSecret)
  , (AttrValueLen, ValULong 32)
  , (AttrToken, ValBool False)
  ]

gateEcdhFrame :: ByteString
gateEcdhFrame =
  encodeDeriveParams (encodeEcdhParams 0 BS.empty (BS.pack [1 .. 32])) [gateTmpl]

gateDhFrame :: ByteString
gateDhFrame =
  encodeDeriveParams (encodeDhParams 0 (BS.pack [1 .. 32])) [gateTmpl]

gateBaseAttrs :: Word64 -> Word64 -> Bool -> [(AttributeType, AttributeValue)]
gateBaseAttrs cls kty canDerive =
  [ (AttrClass, ValULong cls)
  , (AttrKeyType, ValULong kty)
  , (AttrToken, ValBool False)
  , (AttrDerive, ValBool canDerive)
  ]

gateMat :: ByteString
gateMat = BS.pack [0 .. 63]

expectGateRefused :: String -> KeyPlan -> IO ()
expectGateRefused tag plan = case plan of
  KeyDenied (KeyDeny code _) ->
    assertEqual tag CKR_KEY_TYPE_INCONSISTENT code
  other -> assertFailure (tag ++ " must not plan: " ++ show other)

expectGatePlans :: String -> KeyPlan -> IO ()
expectGatePlans tag plan = case plan of
  KeyEffect _ _ -> pure ()
  other -> assertFailure (tag ++ " must plan: " ++ show other)

-- | A secret-class EC base with the derive mark (a pre-gate
-- stored shape) refuses KEY_TYPE_INCONSISTENT on the plain ECDH
-- row.
caseDeriveEcdhRefusesSecretEc :: IO ()
caseDeriveEcdhRefusesSecretEc = do
  m0 <- seedModel
  st <- getSession m0
  (m1, h) <- plantKey m0 st (gateBaseAttrs ckoSecretKey ckkEc True) gateMat
  expectGateRefused "secret-class EC base"
    (planDerive defaultRules m1 st (MechanismId ckm_ECDH1_DERIVE) h gateEcdhFrame)

-- | A secret-class Montgomery base with the derive mark refuses
-- KEY_TYPE_INCONSISTENT on the plain ECDH row.
caseDeriveEcdhRefusesSecretMont :: IO ()
caseDeriveEcdhRefusesSecretMont = do
  m0 <- seedModel
  st <- getSession m0
  (m1, h) <- plantKey m0 st (gateBaseAttrs ckoSecretKey ckkEcMontgomery True) gateMat
  expectGateRefused "secret-class Montgomery base"
    (planDerive defaultRules m1 st (MechanismId ckm_ECDH1_DERIVE) h gateEcdhFrame)

-- | A public-class EC base with the derive mark refuses
-- KEY_TYPE_INCONSISTENT on the plain ECDH row.
caseDeriveEcdhRefusesPublicEc :: IO ()
caseDeriveEcdhRefusesPublicEc = do
  m0 <- seedModel
  st <- getSession m0
  (m1, h) <- plantKey m0 st (gateBaseAttrs ckoPublicKey ckkEc True) gateMat
  expectGateRefused "public-class EC base"
    (planDerive defaultRules m1 st (MechanismId ckm_ECDH1_DERIVE) h gateEcdhFrame)

-- | A secret-class EC base with the derive mark refuses
-- KEY_TYPE_INCONSISTENT on the cofactor ECDH row.
caseDeriveEcdhRefusesSecretEcCofactor :: IO ()
caseDeriveEcdhRefusesSecretEcCofactor = do
  m0 <- seedModel
  st <- getSession m0
  (m1, h) <- plantKey m0 st (gateBaseAttrs ckoSecretKey ckkEc True) gateMat
  expectGateRefused "secret-class EC base, cofactor row"
    (planDerive defaultRules m1 st (MechanismId ckm_ECDH1_COFACTOR_DERIVE) h gateEcdhFrame)

-- | Correctly-classed private EC and Montgomery bases still plan
-- on both ECDH rows.
caseDeriveEcdhPlansPrivate :: IO ()
caseDeriveEcdhPlansPrivate = do
  m0 <- seedModel
  st <- getSession m0
  (m1, privEcH) <- plantKey m0 st (gateBaseAttrs ckoPrivateKey ckkEc True) gateMat
  (m2, privMontH) <- plantKey m1 st (gateBaseAttrs ckoPrivateKey ckkEcMontgomery True) gateMat
  let mech = MechanismId ckm_ECDH1_DERIVE
      cofactorMech = MechanismId ckm_ECDH1_COFACTOR_DERIVE
  expectGatePlans "private-class EC base"
    (planDerive defaultRules m2 st mech privEcH gateEcdhFrame)
  expectGatePlans "private-class Montgomery base"
    (planDerive defaultRules m2 st mech privMontH gateEcdhFrame)
  expectGatePlans "private-class EC base, cofactor row"
    (planDerive defaultRules m2 st cofactorMech privEcH gateEcdhFrame)

-- | A secret-class DH base with the derive mark refuses
-- KEY_TYPE_INCONSISTENT on the PKCS#3 row.
caseDeriveDhRefusesSecretDh :: IO ()
caseDeriveDhRefusesSecretDh = do
  m0 <- seedModel
  st <- getSession m0
  (m1, h) <- plantKey m0 st (gateBaseAttrs ckoSecretKey ckkDh True) gateMat
  expectGateRefused "secret-class DH base"
    (planDerive defaultRules m1 st (MechanismId ckm_DH_PKCS_DERIVE) h gateDhFrame)

-- | A public-class DH base with the derive mark refuses
-- KEY_TYPE_INCONSISTENT on the PKCS#3 row.
caseDeriveDhRefusesPublicDh :: IO ()
caseDeriveDhRefusesPublicDh = do
  m0 <- seedModel
  st <- getSession m0
  (m1, h) <- plantKey m0 st (gateBaseAttrs ckoPublicKey ckkDh True) gateMat
  expectGateRefused "public-class DH base"
    (planDerive defaultRules m1 st (MechanismId ckm_DH_PKCS_DERIVE) h gateDhFrame)

-- | A secret-class X9.42 base with the derive mark refuses
-- KEY_TYPE_INCONSISTENT on the X9.42 row.
caseDeriveDhRefusesSecretX942 :: IO ()
caseDeriveDhRefusesSecretX942 = do
  m0 <- seedModel
  st <- getSession m0
  (m1, h) <- plantKey m0 st (gateBaseAttrs ckoSecretKey ckkX9_42Dh True) gateMat
  expectGateRefused "secret-class X9.42 base"
    (planDerive defaultRules m1 st (MechanismId ckm_X9_42_DH_DERIVE) h gateDhFrame)

-- | A public-class X9.42 base with the derive mark refuses
-- KEY_TYPE_INCONSISTENT on the X9.42 row.
caseDeriveDhRefusesPublicX942 :: IO ()
caseDeriveDhRefusesPublicX942 = do
  m0 <- seedModel
  st <- getSession m0
  (m1, h) <- plantKey m0 st (gateBaseAttrs ckoPublicKey ckkX9_42Dh True) gateMat
  expectGateRefused "public-class X9.42 base"
    (planDerive defaultRules m1 st (MechanismId ckm_X9_42_DH_DERIVE) h gateDhFrame)

-- | Correctly-classed private DH and X9.42 bases still plan on
-- their rows.
caseDeriveDhPlansPrivate :: IO ()
caseDeriveDhPlansPrivate = do
  m0 <- seedModel
  st <- getSession m0
  (m1, privDhH) <- plantKey m0 st (gateBaseAttrs ckoPrivateKey ckkDh True) gateMat
  (m2, privX942H) <- plantKey m1 st (gateBaseAttrs ckoPrivateKey ckkX9_42Dh True) gateMat
  expectGatePlans "private-class DH base"
    (planDerive defaultRules m2 st (MechanismId ckm_DH_PKCS_DERIVE) privDhH gateDhFrame)
  expectGatePlans "private-class X9.42 base"
    (planDerive defaultRules m2 st (MechanismId ckm_X9_42_DH_DERIVE) privX942H gateDhFrame)

-- | A private-class ML-KEM key (right type, right set, usage
-- mark set) presented to encapsulate refuses
-- KEY_TYPE_INCONSISTENT: encapsulation takes the public key.
caseKemEncapsRefusesPrivate :: IO ()
caseKemEncapsRefusesPrivate = do
  m0 <- seedModel >>= loginUser
  st <- getSession m0
  (m1, h) <- plantKey m0 st
    [ (AttrClass, ValULong ckoPrivateKey)
    , (AttrKeyType, ValULong ckkMlKem)
    , (AttrKemAlg, ValULong 768)
    , (AttrToken, ValBool False)
    , (AttrEncapsulate, ValBool True)
    ] (BS.pack [0 .. 63])
  let ctLen = kemCtLen KemMl768
      intent = IntentBuffer (fromIntegral ctLen)
  case planKemEncaps m1 st mlKemMech h KemMl768 secretTmpl intent of
    KeyDenied (KeyDeny code _) ->
      assertEqual "encaps private-class code" CKR_KEY_TYPE_INCONSISTENT code
    other -> assertFailure ("encaps with a private-class key must not plan: " ++ show other)

-- | A public-class ML-KEM key (right type, right set, usage mark
-- set) presented to decapsulate refuses KEY_TYPE_INCONSISTENT:
-- decapsulation takes the private key.
caseKemDecapsRefusesPublic :: IO ()
caseKemDecapsRefusesPublic = do
  m0 <- seedModel >>= loginUser
  st <- getSession m0
  (m1, h) <- plantKey m0 st
    [ (AttrClass, ValULong ckoPublicKey)
    , (AttrKeyType, ValULong ckkMlKem)
    , (AttrKemAlg, ValULong 768)
    , (AttrToken, ValBool False)
    , (AttrDecapsulate, ValBool True)
    ] (BS.pack [64 .. 127])
  let ctLen = kemCtLen KemMl768
  case planKemDecaps m1 st mlKemMech h KemMl768 (BS.replicate ctLen 0) secretTmpl of
    KeyDenied (KeyDeny code _) ->
      assertEqual "decaps public-class code" CKR_KEY_TYPE_INCONSISTENT code
    other -> assertFailure ("decaps with a public-class key must not plan: " ++ show other)

-- | KEM directions take opposite halves: the generated public key
-- still encapsulates and the generated private key still
-- decapsulates.
caseKemPlansCorrectHalves :: IO ()
caseKemPlansCorrectHalves = withSynth $ \answer -> do
  m0 <- seedModel >>= loginUser
  st <- getSession m0
  (m1, pubH, privH) <- genKemPair answer m0 st
  let ctLen = kemCtLen KemMl768
      intent = IntentBuffer (fromIntegral ctLen)
  case planKemEncaps m1 st mlKemMech pubH KemMl768 secretTmpl intent of
    KeyEffect _ _ -> pure ()
    other -> assertFailure ("encaps with the public key must plan: " ++ show other)
  case planKemDecaps m1 st mlKemMech privH KemMl768 (BS.replicate ctLen 0) secretTmpl of
    KeyEffect _ _ -> pure ()
    other -> assertFailure ("decaps with the private key must plan: " ++ show other)

-- | Derive refusal order: the derive mark and the
-- allowed-mechanism list refuse before the family key type, so
-- a wrong-type generated base (DERIVE false by default)
-- answers KEY_FUNCTION_NOT_PERMITTED rather than
-- KEY_TYPE_INCONSISTENT.
caseDeriveRefusalOrderPin :: IO ()
caseDeriveRefusalOrderPin = withSynth $ \answer -> do
  m0 <- seedModel >>= loginUser
  st <- getSession m0
  (m1, aesH) <- genAesKey answer m0 st (aesTmpl 32)
  Just ost <- pure (resolveHandle m1 aesH)
  assertEqual "generated DERIVE reads false"
    (Just (ValBool False)) (Map.lookup AttrDerive (osAttrs ost))
  let tmpl =
        [ (AttrClass, ValULong ckoSecretKey)
        , (AttrKeyType, ValULong ckkGenericSecret)
        , (AttrValueLen, ValULong 16)
        , (AttrToken, ValBool False)
        ]
      mech = MechanismId ckm_ECDH1_DERIVE
      frame = encodeDeriveParams (encodeEcdhParams 0 BS.empty "peer") [tmpl]
  case planDerive defaultRules m1 st mech aesH frame of
    KeyDenied (KeyDeny code _) ->
      assertEqual "wrong-type DERIVE=false code" CKR_KEY_FUNCTION_NOT_PERMITTED code
    other -> assertFailure ("wrong-type DERIVE=false base must not plan: " ++ show other)

-- | Derive refusal order: the derive mark refuses before the
-- object class, so a public-class EC base (right type, wrong
-- class) without the mark answers KEY_FUNCTION_NOT_PERMITTED
-- rather than KEY_TYPE_INCONSISTENT.
caseDeriveMarkBeforeClassPin :: IO ()
caseDeriveMarkBeforeClassPin = do
  m0 <- seedModel
  st <- getSession m0
  (m1, h) <- plantKey m0 st (gateBaseAttrs ckoPublicKey ckkEc False) gateMat
  case planDerive defaultRules m1 st (MechanismId ckm_ECDH1_DERIVE) h gateEcdhFrame of
    KeyDenied (KeyDeny code _) ->
      assertEqual "public-class DERIVE=false code" CKR_KEY_FUNCTION_NOT_PERMITTED code
    other -> assertFailure ("public-class DERIVE=false base must not plan: " ++ show other)

-- | Derive refusal order: the allowed-mechanism list refuses
-- before the family key type, so a wrong-type base with the
-- mark whose list excludes ECDH answers
-- KEY_FUNCTION_NOT_PERMITTED rather than KEY_TYPE_INCONSISTENT.
caseDeriveAllowedBeforeTypePin :: IO ()
caseDeriveAllowedBeforeTypePin = do
  m0 <- seedModel
  st <- getSession m0
  (m1, h) <- plantKey m0 st
    (gateBaseAttrs ckoSecretKey ckkAes True
      ++ [(AttrAllowedMechanisms, allowedList [hmacSha256Mech])])
    gateMat
  case planDerive defaultRules m1 st (MechanismId ckm_ECDH1_DERIVE) h gateEcdhFrame of
    KeyDenied (KeyDeny code _) ->
      assertEqual "excluded-list wrong-type code" CKR_KEY_FUNCTION_NOT_PERMITTED code
    other -> assertFailure ("excluded-list wrong-type base must not plan: " ++ show other)
