{- | Key management, KEM and authenticated-wrapping tests.

A KEM encapsulation length query creates no key; the delivery
call then returns ciphertext plus exactly one handle. Key/pair
generation, wrap/unwrap, derivation and authenticated wrapping
run through the shared atomic-publish mechanism; multi-key
derive with an invalid additional template publishes zero
objects. AAD/key/parameter mismatches fail closed, key
attributes land on unwrap/derive children, and the KeyPolicy
seam disposition is covered. The real backend is proven only
for implemented capabilities; key-output codec cases close the
suite.
-}
{-# LANGUAGE OverloadedStrings #-}
module KeyManagementSpec (spec) where

import Data.Bits ((.&.), complement, popCount, shiftR, xor)
import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import Data.Char (digitToInt, isHexDigit)
import qualified Data.Map.Strict as Map
import Data.Maybe (isJust)
import Data.Word (Word64, Word8)
import Foreign.Marshal.Alloc (allocaBytes)
import Foreign.Marshal.Array (pokeArray)
import Foreign.Ptr (Ptr, nullPtr)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertBool, assertEqual, assertFailure, testCase)

import Haskoki.Attribute
  ( AttributeResult (..)
  , AttributeType (..)
  , AttributeValue (..)
  , PartialReads (..)
  , encodeValue
  , getAttributes
  )
import Haskoki.Attribute.Generated (mustKeyTypeId)
import Haskoki.Der (curveTable, dhParamsDer, dhParamsDerQ, dhPrivateDer, dhPrivateDerQ, dhPublicDer, dhPublicDerQ, dhSpkiFields, dsaParamsDer, dsaPrivateDer, dsaPublicDer, ecPrivateDer, ecPublicDer, eddsaPrivateDer, eddsaPublicDer, mlkemPkcs8Fields, mlkemSpkiFields, montgomeryPrivateDer, montgomeryPublicDer, parseDhParams, parseDsaParams, rsaPrivateDer, rsaPublicDer)
import Haskoki.Engine.Backend
  ( BackendError (..)
  , CryptoBackend (..)
  , DhSpec (..)
  , DigestAlg (..)
  , EcSpec (..)
  , EngineResult (..)
  , KeyGenSpec (..)
  , KeyMaterial (..)
  , MacSpec (..)
  , SigSpec (..)
  )
import Haskoki.Engine.Driver (KeyResolver, runEffect)
import Haskoki.Engine.OpenSSL4 (OpenSSL4 (..))
import Haskoki.Engine.Synthetic (Synthetic (..))
import Haskoki.FFI.Decode (maxInputBytes)
import Haskoki.FFI.KeyOutputs
  ( KeyOutputError (..)
  , decodeKemCiphertext
  , decodeWrappedInput
  , planCiphertextWriteback
  , planHandleWriteback
  , planWrappedWriteback
  )
import Haskoki.Model
  ( Model (..)
  , ObjectState (..)
  , SessionState
  , addToken
  , emptyModel
  , lookupSession
  )
import Haskoki.Object (resolveHandle)
import Haskoki.Operation.Cipher (pkcs7Pad, pkcs7Unpad)
import Haskoki.Operation
  ( CipherSpec (..)
  , InitArgs (..)
  , InitOutcome (..)
  , KeyPolicy (..)
  , OpEnv (..)
  , emptySessionOps
  , initOperation
  )
import Haskoki.Operation.Derive
  ( decodeDeriveParams
  , decodeHkdfInfo
  , encodeDeriveParams
  , encodeHkdfInfo
  , hkdfDataMech
  , hkdfDeriveMech
  , maxDerivedTotal
  , planDerive
  , pubPrivMech
  )
import Haskoki.Operation.Effect (CryptoEffect (..), CryptoError (..), CryptoResult (..))
import Haskoki.Operation.Kem
  ( KemAlg (..)
  , kemCtLen
  , mlKemKeyPairGenMech
  , mlKemMech
  , planKemDecaps
  , planKemEncaps
  )
import Haskoki.Operation.KeyManagement
  ( GenArgs (..)
  , KeyDeny (..)
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
  , blake2b512KeyGenMech
  , chacha20KeyGenMech
  , ckkAes
  , ckkBlake2b512Hmac
  , ckkChacha20
  , ckkDes3
  , ckkDh
  , ckkDsa
  , ckkEc
  , ckkEcEdwards
  , ckkEcMontgomery
  , ckkGenericSecret
  , ckkMlDsa
  , ckkMlKem
  , ckkRsa
  , ckkX9_42Dh
  , ckkAesXts
  , ckkDes
  , ckkDes2
  , ckkCdmf
  , ckkCast
  , ckkCast3
  , ckkCast128
  , ckkRc2
  , ckkRc4
  , ckkRc5
  , ckkIdea
  , ckkSkipjack
  , ckkBaton
  , ckkJuniper
  , ckkBlowfish
  , ckkTwofish
  , ckkGost28147
  , ckkSeed
  , ckkAria
  , ckkCamellia
  , ckkSalsa20
  , ckkPoly1305
  , ckkHkdf
  , ckkSha1Hmac
  , ckkSha224Hmac
  , ckkSha256Hmac
  , ckkSha384Hmac
  , ckkSha512Hmac
  , ckkSha512_224Hmac
  , ckkSha512_256Hmac
  , ckkSha512THmac
  , ckkSha3_224Hmac
  , ckkSha3_256Hmac
  , ckkSha3_384Hmac
  , ckkSha3_512Hmac
  , ckkBlake2b160Hmac
  , ckkBlake2b256Hmac
  , ckkBlake2b384Hmac
  , ckoData
  , ckoDomainParameters
  , ckoPrivateKey
  , ckoPublicKey
  , ckoSecretKey
  , checkKeyTemplate
  , decodeGenArgs
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
  , encodeGenArgs
  , mldsaKeyPairGenMech
  , finishWork
  , genericSecretKeyGenMech
  , genericSecretKeygenMaxBytes
  , genericSecretKeygenMinBytes
  , keyBytesOf
  , keyPairCompatible
  , padPkcs7
  , pendingFromAttrs
  , planAuthUnwrapKey
  , planAuthWrapKey
  , planGenerateKey
  , planGenerateKeyPair
  , desKeyGenMech
  , des2KeyGenMech
  , cdmfKeyGenMech
  , castKeyGenMech
  , cast3KeyGenMech
  , cast128KeyGenMech
  , rc2KeyGenMech
  , rc4KeyGenMech
  , rc5KeyGenMech
  , ideaKeyGenMech
  , skipjackKeyGenMech
  , batonKeyGenMech
  , juniperKeyGenMech
  , blowfishKeyGenMech
  , twofishKeyGenMech
  , gost28147KeyGenMech
  , seedKeyGenMech
  , ariaKeyGenMech
  , camelliaKeyGenMech
  , salsa20KeyGenMech
  , poly1305KeyGenMech
  , aesXtsKeyGenMech
  , hkdfKeyGenMech
  , sha1KeyGenMech
  , sha224KeyGenMech
  , sha256KeyGenMech
  , sha384KeyGenMech
  , sha512KeyGenMech
  , sha512_224KeyGenMech
  , sha512_256KeyGenMech
  , sha512TKeyGenMech
  , sha3_224KeyGenMech
  , sha3_256KeyGenMech
  , sha3_384KeyGenMech
  , sha3_512KeyGenMech
  , blake2b160KeyGenMech
  , blake2b256KeyGenMech
  , blake2b384KeyGenMech
  , ssl3PremasterKeyGenMech
  , tlsPremasterKeyGenMech
  , wtlsPremasterKeyGenMech
  , planUnwrapKey
  , policyFromObject
  , planWrapKey
  , publishPending
  , rsaAesKwMech
  , rsaKeyPairGenMech
  , rsaOaepMech
  , rsaPkcsMech
  , rsaX509Mech
  , stampPairComponents
  , stampParamsObject
  , unpadPkcs7
  )
import Haskoki.Outcome
  ( DeltaOp (..)
  , NativeOutput (..)
  , PlanResult (..)
  , PreparedCommit (..)
  , Rejection (..)
  , StateDelta (..)
  )
import Haskoki.Output (OutputPlan (..), TypedWrite (..), WritePayload (..))
import Haskoki.Registry (MechanismId (..), Operation (..), curatedRegistry, mkCapabilities)
import Haskoki.Recipe.Ecdh (encodeEcdhParams)
import Haskoki.Recipe.Kdf (encodePbkd2Params, maxPbkd2Iters)
import Haskoki.Recipe.Sp800108 (encodeSp800Params, maxSp800Total)
import Haskoki.Recipe.TlsKdf (encodeTlsKdfParams, maxTlsKdfOutput)
import Haskoki.Recipe.ByteOps (encodeByteOpsParams)
import Haskoki.Recipe.Pbe (encodePbeParams, maxPbeIters)
import Haskoki.Recipe.Ssl3 (encodeSsl3KeyMatParams, encodeSsl3MasterParams)
import Haskoki.Recipe.TlsKeyMat (encodeTlsKeyMatParams)
import Haskoki.Recipe.Ike (encodeIkeParams, maxIkeOutput)
import Haskoki.Recipe.RsaOaep (encodeOaepParams)
import Haskoki.Recipe.WrapComp (encodeWrapCompEcdhParams)
import Haskoki.Recipe.WrapCompRsa (encodeWrapCompRsaParams)
import Haskoki.Registry.Generated
  ( ckm_AES_CCM
  , ckm_DES3_MAC
  , ckm_DES3_MAC_GENERAL
  , ckm_CONCATENATE_BASE_AND_DATA
  , ckm_CONCATENATE_BASE_AND_KEY
  , ckm_CONCATENATE_DATA_AND_BASE
  , ckm_ECDH1_DERIVE
  , ckm_EXTRACT_KEY_FROM_KEY
  , ckm_IKE1_EXTENDED_DERIVE
  , ckm_IKE1_PRF_DERIVE
  , ckm_IKE2_PRF_PLUS_DERIVE
  , ckm_IKE_PRF_DERIVE
  , ckm_PKCS5_PBKD2
  , ckm_SHA256
  , ckm_SHA256_HMAC
  , ckm_SHA256_KEY_DERIVATION
  , ckm_SP800_108_COUNTER_KDF
  , ckm_SP800_108_DOUBLE_PIPELINE_KDF
  , ckm_SP800_108_FEEDBACK_KDF
  , ckm_TLS_MASTER_KEY_DERIVE
  , ckm_TLS_KEY_AND_MAC_DERIVE
  , ckm_TLS12_KEY_AND_MAC_DERIVE
  , ckm_TLS12_KEY_SAFE_DERIVE
  , ckm_TLS12_KDF
  , ckm_TLS12_MASTER_KEY_DERIVE
  , ckm_TLS12_EXTENDED_MASTER_KEY_DERIVE
  , ckm_TLS_KDF
  , ckm_XOR_BASE_AND_DATA
  , ckm_PBE_SHA1_DES3_EDE_CBC
  , ckm_PBE_SHA1_DES2_EDE_CBC
  , ckm_PBE_SHA1_CAST128_CBC
  , ckm_PBE_SHA1_RC4_128
  , ckm_PBE_SHA1_RC4_40
  , ckm_PBE_SHA1_RC2_128_CBC
  , ckm_PBE_SHA1_RC2_40_CBC
  , ckm_PBE_MD5_DES_CBC
  , ckm_PBE_MD5_CAST_CBC
  , ckm_PBE_MD5_CAST3_CBC
  , ckm_PBE_MD5_CAST128_CBC
  , ckm_SSL3_MASTER_KEY_DERIVE
  , ckm_SSL3_MASTER_KEY_DERIVE_DH
  , ckm_SSL3_KEY_AND_MAC_DERIVE
  )
import Haskoki.Registry.KeyMatrix (matrixKeyTypes)
import Haskoki.Request (OutputIntent (..), OutputRegion (..))
import Haskoki.Rules (defaultRules)
import Haskoki.Session (SessionLogin (..))
import Haskoki.Transition (publishDelta)
import Haskoki.Types
  ( ExternalHandle (..)
  , ReturnCode (..)
  , SessionId (..)
  , SlotId (..)
  )

spec :: TestTree
spec = testGroup "Key management, KEM and wrapping"
  [ testCase "Setup: ML-KEM-768 keypair generation delivers two handles"
      caseKemKeygen
  , testCase "Encaps length query creates no key" caseKemLengthQuery
  , testCase "Encaps delivers ciphertext and exactly one handle" caseKemEncaps
  , testCase "Short-buffer encaps creates no key" caseKemEncapsShort
  , testCase "AES keygen delivers one handle" caseAesKeygen
  , testCase "DES3 keygen delivers one handle" caseDes3Keygen
  , testCase "BLAKE2B-512 keygen mints variable lengths" caseBlake2b512Keygen
  , testCase "Keygen sweep mints typed material per table" caseKeygenSweep
  , testCase "TLS pre-master keygen embeds the client version" caseTlsPremasterKeygen
  , testCase "SSL3 pre-master keygen embeds the client version" caseSsl3PremasterKeygen
  , testCase "WTLS pre-master keygen embeds the version byte" caseWtlsPremasterKeygen
  , testCase "PBKD2 keygen derives deterministic material" casePbkd2Keygen
  , testCase "ChaCha20 keygen mints 32 bytes" caseChacha20Keygen
  , testCase "AES keygen refuses PQC wrap flags" caseAesKeygenEncapsulate
  , testCase "Init enforces the allowed-mechanism list" caseInitAllowedMechanisms
  , testCase "Generic-secret keygen mints typed material in bounds" caseGenericSecretKeygen
  , testCase "Init enforces the key-type matrix" caseInitKeyTypeMatrix
  , testCase "EC keypair delivers two handles" caseEcKeypair
  , testCase "ML-DSA keypair delivers two handles" caseMldsaKeypair
  , testCase "ML-DSA set plans, agrees and refuses" caseMldsaSetPlanner
  , testCase "ML-DSA stamping lands CKA_SEED on agreement" caseMldsaStampSeed
  , testCase "EC keypair serves all covered curves" caseEcKeygenCurves
  , testCase "RSA keypair stamps components and round-trips" caseRsaKeygen
  , testCase "RSA keypair generations are distinct" caseRsaKeygenDistinct
  , testCase "RSA keygen bounds refuse out-of-window specs" caseRsaKeygenBounds
  , testCase "RSA exponent plans, agrees and refuses" caseRsaExponentPlanner
  , testCase "RSA stamping refuses mismatched halves" caseRsaStampMismatch
  , testCase "EC stamping lands CKA_EC_POINT" caseEcPointStamped
  , testCase "Wrap length query then wrap/unwrap roundtrip" caseWrapRoundtrip
  , testCase "AES-KW wrap/unwrap roundtrips with +8 expansion" caseAesKwWrapRoundtrip
  , testCase "AES-KWP wrap/unwrap roundtrips ragged (PAD alias)" caseAesKwpWrapRoundtrip
  , testCase "AES-KW-PKCS7 wrap/unwrap pads, IVs, fails closed" caseAesKwPkcs7WrapRoundtrip
  , testCase "ECDH wrap/unwrap composes transport + KWP, gates rows" caseEcdhCompWrapRoundtrip
  , testCase "RSA wrap/unwrap seals a random KEK plus KWP, gates fit" caseRsaCompWrapRoundtrip
  , testCase "unwrap commits refuse type/length confusion" caseUnwrapKeyTypeLength
  , testCase "RSA wrap/unwrap roundtrips modulus-wide" caseRsaWrapRoundtrip
  , testCase "RSA wrap key/parameter/length mismatches fail closed" caseRsaWrapMismatch
  , testCase "RSA-X.509 wrap seals wide, unwrap tails value_len" caseRsaX509Wrap
  , testCase "recover usage flags store and gate permits" caseRecoverAttrs
  , testCase "Authenticated wrap roundtrip binds the tag" caseAuthWrapRoundtrip
  , testCase "Single-key derive delivers one handle" caseDeriveSingle
  , testCase "ECDH derive refuses a non-EC base before params" caseDeriveEcdhWrongKeyType
  , testCase "ECDH derive refuses malformed params on an EC base" caseDeriveEcdhBadParams
  , testCase "SHA-KDF derive refuses a destroyed base handle" caseDeriveKdfBadHandle
  , testCase "SHA-KDF derive refuses a non-generic-secret base" caseDeriveKdfWrongKeyType
  , testCase "Shared publication is all-or-nothing" casePublishAtomic
  , testCase "Wrap padding mirrors the cipher construction" casePadMirror
  , testCase "Multi-key derive delivers N handles" caseDeriveMulti
  , testCase "Invalid additional template publishes zero objects" caseDeriveInvalidExtra
  , testCase "Derive codec round-trips and rejects malformed frames" caseDeriveCodec
  , testCase "pub-from-priv RSA ignores CKA_DERIVE, maps attrs" casePubPrivRsa
  , testCase "pub-from-priv EC serves embedded, refuses scalar-only" casePubPrivEc
  , testCase "pub-from-priv EC stamps point and params from SPKI" casePubPrivEcSpkiStamp
  , testCase "pub-from-priv refusals: scope, class, params, templates" casePubPrivRefusals
  , testCase "HKDF info codec round-trips mode/salt/context" caseHkdfInfoCodec
  , testCase "Decaps recovers the secret as one handle" caseKemDecaps
  , testCase "KEM key/ciphertext mismatches fail closed" caseKemMismatch
  , testCase "Wrap key/parameter mismatches fail closed" caseWrapMismatch
  , testCase "Wrap/unwrap with a non-AES key is a key-type refusal" caseWrapKeyTypeGate
  , testCase "Auth-unwrap AAD/tag mismatches fail closed" caseAuthWrapMismatch
  , testCase "Init reads usage from the key object" caseInitFromObject
  , testCase "Usage attributes land on unwrap/derive children" caseAttrsLand
  , testCase "Real EC keypair generates and signs" caseRealEcKeygen
  , testCase "Real RSA keypair generates and signs" caseRealRsaKeygen
  , testCase "X9.42 DH param sizes plan and refuse" caseX942ParamSizesPlanner
  , testCase "DH PKCS param sizes plan and refuse" caseDhPkcsParamSizesPlanner
  , testCase "EC extra-bits keygen plans like EC keygen" caseEcExtraBitsPlanner
  , testCase "DSA param sizes plan and refuse" caseDsaParamSizesPlanner
  , testCase "DSA domain templates plan and refuse" caseDsaDomainPlanner
  , testCase "DSA GenArgs codec round-trips and rejects" caseDsaGenArgsCodec
  , testCase "DSA pending/effect pairs cohere" caseDsaCompatible
  , testCase "DH domain templates plan and refuse" caseDhDomainPlanner
  , testCase "DH GenArgs codec round-trips and rejects" caseDhGenArgsCodec
  , testCase "DH pending/effect pairs cohere" caseDhCompatible
  , testCase "DH halves stamp domain components" caseDhStamp
  , testCase "Edwards GenArgs codec round-trips and rejects" caseEdwardsGenArgsCodec
  , testCase "Edwards pair templates plan and refuse" caseEdwardsPairPlanner
  , testCase "Edwards pending/effect pairs cohere" caseEdwardsCompatible
  , testCase "Edwards components stamp, doubles pass through" caseEdwardsStamp
  , testCase "Montgomery GenArgs codec round-trips and rejects" caseMontgomeryGenArgsCodec
  , testCase "Montgomery pair templates plan and refuse" caseMontgomeryPairPlanner
  , testCase "Montgomery pending/effect pairs cohere" caseMontgomeryCompatible
  , testCase "Montgomery components stamp, doubles pass through" caseMontgomeryStamp
  , testCase "DSA components stamp, doubles pass through" caseDsaStamp
  , testCase "Real X9.42 DH params generate with readback" caseRealX942Paramgen
  , testCase "Real DH PKCS params generate with readback" caseRealDhPkcsParamgen
  , testCase "Real DSA params generate with readback" caseRealDsaParamgen
  , testCase "Real DSA keypair generates and signs" caseRealDsaKeygen
  , testCase "Real DH keypairs generate and agree" caseRealDhKeygen
  , testCase "Keygen defaults absent usage flags true" caseKeygenUsageDefaults
  , testCase "Real P-384 keypair generates and signs" caseRealEcKeygen384
  , testCase "Real P-521 keypair generates and signs" caseRealEcKeygen521
  , testCase "Real wrap matches SP 800-38A and round-trips" caseRealWrapVector
  , testCase "Real derive matches RFC 5869" caseRealHkdfVector
  , testCase "Real derive extracts then expands (RFC 5869 A.1/A.3)" caseRealHkdfExtractExpand
  , testCase "Real derive serves SHA-1/SHA-512 PRFs" caseRealHkdfMultiPrf
  , testCase "HKDF extract-only refuses mechanism-param-invalid" caseHkdfExtractOnlyRefused
  , testCase "HKDF-DATA plans data outputs, refuses key shapes" caseHkdfDataPlans
  , testCase "Real HKDF-DATA derive matches RFC 5869" caseRealHkdfDataVector
  , testCase "SP800-108 plans the three modes, refuses bad shapes" caseSp800Plans
  , testCase "Real SP800-108 derive matches the KAT" caseRealSp800Vector
  , testCase "TLS-KDF plans rows, refuses bad shapes" caseTlsKdfPlans
  , testCase "Real TLS-KDF derives match the KATs" caseRealTlsKdfVector
  , testCase "IKE plans rows, refuses bad shapes" caseIkePlans
  , testCase "Real IKE derives match the KATs" caseRealIkeVector
  , testCase "Byte-op plans rows, refuses bad shapes" caseByteOpsPlans
  , testCase "Real byte-op derives match the KATs" caseRealByteOpsVector
  , testCase "Key-material plans rows, refuses bad shapes" caseKeyMatPlans
  , testCase "Real key-material derives match the KATs" caseRealKeyMatVector
  , testCase "SSL3 plans rows, refuses bad shapes" caseSsl3DerivePlans
  , testCase "Real SSL3 derives match the KATs" caseRealSsl3Vector
  , testCase "PBE plans rows, refuses bad shapes" casePbePlans
  , testCase "Real PBE keygens match the KATs" caseRealPbeVector
  , testCase "Real SHA1 PBE keygens match the KATs" caseRealPbeSha1Vector
  , testCase "Real MD5 PBE keygens match the KATs" caseRealPbeMd5Vector
  , testCase "SP800 plans primary plus additional keys" caseSp800MultiPlans
  , testCase "Real authenticated wrap round-trips" caseRealAuthWrap
  , testCase "Real backend mints AES and ML-KEM" caseRealAesKem
  , testCase "KEM refuses wrong key types inconsistent" caseKemWrongKeyType
  , testCase "KEM accepts AES-256 secret templates" caseKemAesTemplate
  , testCase "KEM keygen honors CKA_PARAMETER_SET" caseKemKeygenParamSet
  , testCase "Handle writeback plans one exact handle" caseHandleWriteback
  , testCase "Wrapped writeback plans query/short/exact" caseWrappedWriteback
  , testCase "Ciphertext writeback enforces the length" caseCiphertextWriteback
  , testCase "Wrapped/KEM inputs decode with checks" caseKeyInputDecode
  ]

-- ---------------------------------------------------------------------------
-- Fixtures
-- ---------------------------------------------------------------------------

slot0 :: SlotId
slot0 = SlotId 0

sid1 :: SessionId
sid1 = SessionId 1

-- | A model with one token and one open session.
seedModel :: IO Model
seedModel = do
  let m0 = addToken emptyModel slot0
  expectRight (publishDelta m0 (StateDelta [DeltaOpenSession sid1 slot0 False]))

getSession :: Model -> IO SessionState
getSession m = case lookupSession m sid1 of
  Nothing -> assertFailure "seed session missing" >> undefined
  Just st -> pure st

-- | Log the seed session in as a normal user (private wrapping and
-- base keys are only visible past a login).
loginUser :: Model -> IO Model
loginUser m =
  expectRight (publishDelta m (StateDelta [DeltaSetSessionLogin sid1 LoginUser]))

expectRight :: Show e => Either e a -> IO a
expectRight (Right a) = pure a
expectRight (Left e) = assertFailure ("expected Right, got: " ++ show e) >> undefined

-- | Production-shaped key resolver: material comes from the key
-- objects' stored value, never from caller fixtures.
resolverFromModel :: Model -> KeyResolver
resolverFromModel m oid = KeyBytes <$> (keyBytesOf =<< Map.lookup oid (mObjects m))

-- | Decode a hex string (whitespace-tolerant).
hex :: String -> ByteString
hex s = BS.pack (go (filter isHexDigit s))
  where
    go [] = []
    go (a : b : rest) = fromIntegral (digitToInt a * 16 + digitToInt b) : go rest
    go [_] = error "hex: odd digit count"

-- | Answer effects against the real OpenSSL4 backend.
withRealEnv :: (BackendEnv OpenSSL4 -> IO a) -> IO a
withRealEnv action = do
  opened <- openBackend "provider=default" :: IO (EngineResult (BackendEnv OpenSSL4))
  case opened of
    EngineFail err -> assertFailure ("openssl4 open failed: " ++ show err) >> undefined
    EngineOk env -> do
      r <- action env
      closeBackend env
      pure r

answerReal :: BackendEnv OpenSSL4 -> Model -> CryptoEffect -> IO CryptoResult
answerReal env m fx = runEffect env (resolverFromModel m) fx

-- | Plant one key object with fixed material (for real-backend
-- proofs over capabilities the real backend cannot generate).
plantKey :: Model -> SessionState -> [(AttributeType, AttributeValue)] -> ByteString
  -> IO (Model, ExternalHandle)
plantKey m st tmpl mat = do
  let attrs = Map.fromList tmpl
      base = pendingFromAttrs st attrs
      po = base { poAttrs = Map.insert AttrValue (ValBytes mat) (poAttrs base) }
  case publishPending m st [po] of
    Left deny -> assertFailure ("plant must publish: " ++ show deny) >> undefined
    Right (delta, [h]) -> do
      m' <- expectRight (publishDelta m delta)
      pure (m', h)
    Right _ -> assertFailure "plant arity" >> undefined

-- | Answer effects against one seeded synthetic backend per test
-- case: sequential generations draw distinct keys from the
-- backend's counter, while every case replays the same sequence.
withSynth :: ((Model -> CryptoEffect -> IO CryptoResult) -> IO a) -> IO a
withSynth action = do
  opened <- openBackend "11" :: IO (EngineResult (BackendEnv Synthetic))
  case opened of
    EngineFail err -> assertFailure ("synthetic open failed: " ++ show err) >> undefined
    EngineOk env -> do
      r <- action (\m fx -> runEffect env (resolverFromModel m) fx)
      closeBackend env
      pure r

-- | ML-KEM-768 keypair templates.
kemPubTmpl :: [(AttributeType, AttributeValue)]
kemPubTmpl =
  [ (AttrClass, ValULong ckoPublicKey)
  , (AttrKeyType, ValULong ckkMlKem)
  , (AttrKemAlg, ValULong 768)
  , (AttrToken, ValBool False)
  , (AttrPrivate, ValBool False)
  , (AttrEncapsulate, ValBool True)
  ]

kemPrivTmpl :: [(AttributeType, AttributeValue)]
kemPrivTmpl =
  [ (AttrClass, ValULong ckoPrivateKey)
  , (AttrKeyType, ValULong ckkMlKem)
  , (AttrKemAlg, ValULong 768)
  , (AttrToken, ValBool False)
  , (AttrPrivate, ValBool True)
  , (AttrSensitive, ValBool True)
  , (AttrExtractable, ValBool False)
  , (AttrDecapsulate, ValBool True)
  ]

-- | Shared-secret template for encapsulation.
secretTmpl :: [(AttributeType, AttributeValue)]
secretTmpl =
  [ (AttrClass, ValULong ckoSecretKey)
  , (AttrKeyType, ValULong ckkGenericSecret)
  , (AttrValueLen, ValULong 32)
  , (AttrToken, ValBool False)
  , (AttrPrivate, ValBool True)
  , (AttrSensitive, ValBool True)
  , (AttrExtractable, ValBool True)
  , (AttrEncrypt, ValBool True)
  , (AttrDecrypt, ValBool True)
  ]

handleOf :: NativeOutput -> IO ExternalHandle
handleOf (NativeOutput (RegionHandle _) bs) = case BS.length bs of
  8 -> pure (ExternalHandle (fromIntegral (BS.foldl' (\a b -> a * 256 + fromIntegral b) 0 bs :: Int)))
  _ -> assertFailure "handle output is not 8 bytes" >> undefined
handleOf _ = assertFailure "expected a handle output" >> undefined

-- | Generate an ML-KEM-768 pair through the planner + synthetic
-- backend, publishing both objects. Returns the model and the
-- (public, private) handles.
genKemPair :: (Model -> CryptoEffect -> IO CryptoResult)
  -> Model -> SessionState -> IO (Model, ExternalHandle, ExternalHandle)
genKemPair answer m st = case planGenerateKeyPair defaultRules m st mlKemKeyPairGenMech kemPubTmpl kemPrivTmpl of
  KeyEffect pw fx -> do
    res <- answer m fx
    c <- finishCommit m st pw res 2
    pubH <- handleOf (pcOutputs c !! 0)
    privH <- handleOf (pcOutputs c !! 1)
    m' <- expectRight (publishDelta m (pcDelta c))
    pure (m', pubH, privH)
  other -> assertFailure ("keypair plan is not an effect: " ++ show other) >> undefined

-- | Finish planned work and demand an Immediate commit publishing
-- exactly @n@ objects.
finishCommit :: Model -> SessionState -> PendingWork -> CryptoResult -> Int -> IO PreparedCommit
finishCommit m st pw res n = case finishWork m st pw res of
  Immediate c -> do
    let StateDelta ops = pcDelta c
        created = length [() | DeltaCreateObjectFull {} <- ops]
    assertEqual "published object count" n created
    pure c
  other -> assertFailure ("finish is not Immediate: " ++ show other) >> undefined

-- ---------------------------------------------------------------------------
-- Part 1
-- ---------------------------------------------------------------------------

caseKemKeygen :: IO ()
caseKemKeygen = withSynth $ \answer -> do
  m0 <- seedModel
  st <- getSession m0
  (m1, pubH, privH) <- genKemPair answer m0 st
  assertBool "handles differ" (pubH /= privH)
  Just pub <- pure (resolveHandle m1 pubH)
  Just priv <- pure (resolveHandle m1 privH)
  assertEqual "pub class" (Just (ValULong ckoPublicKey)) (Map.lookup AttrClass (osAttrs pub))
  assertEqual "priv class" (Just (ValULong ckoPrivateKey)) (Map.lookup AttrClass (osAttrs priv))
  assertEqual "pub keytype" (Just (ValULong ckkMlKem)) (Map.lookup AttrKeyType (osAttrs pub))
  assertEqual "priv kem alg" (Just (ValULong 768)) (Map.lookup AttrKemAlg (osAttrs priv))
  assertEqual "pub usage" (Just (ValBool True)) (Map.lookup AttrEncapsulate (osAttrs pub))
  assertEqual "priv usage" (Just (ValBool True)) (Map.lookup AttrDecapsulate (osAttrs priv))
  case (keyBytesOf pub, keyBytesOf priv) of
    (Just p, Just q) -> do
      assertBool "pub material nonempty" (not (BS.null p))
      assertBool "priv material nonempty" (not (BS.null q))
      assertBool "halves differ" (p /= q)
    _ -> assertFailure "keypair halves lack stored material"

caseKemLengthQuery :: IO ()
caseKemLengthQuery = withSynth $ \answer -> do
  m0 <- seedModel
  st <- getSession m0
  (m1, pubH, _) <- genKemPair answer m0 st
  let before = Map.size (mObjects m1)
  case planKemEncaps m1 st mlKemMech pubH KemMl768 secretTmpl IntentNull of
    KeyImmediate (Immediate c) -> do
      assertEqual "query code" CKR_OK (pcCode c)
      assertEqual "query publishes nothing" (StateDelta []) (pcDelta c)
      assertEqual "query answers the ct length"
        [NativeOutput (RegionBytes "ciphertext" IntentNull)
          (encodeValue (ValULong (fromIntegral (kemCtLen KemMl768))))]
        (pcOutputs c)
      m2 <- expectRight (publishDelta m1 (pcDelta c))
      assertEqual "no key created" before (Map.size (mObjects m2))
    other -> assertFailure ("length query is not an Immediate commit: " ++ show other)

caseKemEncaps :: IO ()
caseKemEncaps = withSynth $ \answer -> do
  m0 <- seedModel
  st <- getSession m0
  (m1, pubH, _) <- genKemPair answer m0 st
  let before = Map.size (mObjects m1)
      ctLen = kemCtLen KemMl768
      intent = IntentBuffer (fromIntegral ctLen)
  (ct1, h) <- case planKemEncaps m1 st mlKemMech pubH KemMl768 secretTmpl intent of
    KeyEffect pw fx -> do
      res <- answer m1 fx
      c <- finishCommit m1 st pw res 1
      let outs = pcOutputs c
      assertEqual "ciphertext plus exactly one handle" 2 (length outs)
      ct <- case outs !! 0 of
        NativeOutput (RegionBytes "ciphertext" _) bs -> pure bs
        o -> assertFailure ("first output is not the ciphertext: " ++ show o) >> undefined
      assertEqual "ciphertext length" ctLen (BS.length ct)
      hh <- handleOf (outs !! 1)
      m2 <- expectRight (publishDelta m1 (pcDelta c))
      assertEqual "exactly one object published" (before + 1) (Map.size (mObjects m2))
      Just ost <- pure (resolveHandle m2 hh)
      assertEqual "secret class" (Just (ValULong ckoSecretKey)) (Map.lookup AttrClass (osAttrs ost))
      assertEqual "secret keytype" (Just (ValULong ckkGenericSecret)) (Map.lookup AttrKeyType (osAttrs ost))
      assertEqual "secret usage" (Just (ValBool True)) (Map.lookup AttrEncrypt (osAttrs ost))
      case keyBytesOf ost of
        Just ss -> assertEqual "shared secret length" 32 (BS.length ss)
        Nothing -> assertFailure "secret object lacks stored material"
      pure (ct, hh)
    other -> assertFailure ("encaps plan is not an effect: " ++ show other) >> undefined
  -- Deterministic test engine: the same key encapsulates the same bytes.
  case planKemEncaps m1 st mlKemMech pubH KemMl768 secretTmpl intent of
    KeyEffect pw fx -> do
      res <- answer m1 fx
      c <- finishCommit m1 st pw res 1
      case pcOutputs c of
        (NativeOutput (RegionBytes "ciphertext" _) ct2 : _) ->
          assertEqual "synthetic encaps is seed-deterministic" ct1 ct2
        _ -> assertFailure "no ciphertext output"
    other -> assertFailure ("encaps plan is not an effect: " ++ show other) >> undefined
  _ <- pure h
  pure ()

caseKemEncapsShort :: IO ()
caseKemEncapsShort = withSynth $ \answer -> do
  m0 <- seedModel
  st <- getSession m0
  (m1, pubH, _) <- genKemPair answer m0 st
  let before = Map.size (mObjects m1)
      ctLen = kemCtLen KemMl768
  case planKemEncaps m1 st mlKemMech pubH KemMl768 secretTmpl (IntentBuffer 100) of
    KeyImmediate (Reject r) -> do
      assertEqual "short code" CKR_BUFFER_TOO_SMALL (rejCode r)
      assertEqual "short publishes nothing" (StateDelta []) (rejDelta r)
      assertEqual "short answers the ct length"
        [NativeOutput (RegionBytes "ciphertext" (IntentBuffer 100))
          (encodeValue (ValULong (fromIntegral ctLen)))]
        (rejOutputs r)
      m2 <- expectRight (publishDelta m1 (rejDelta r))
      assertEqual "no key created" before (Map.size (mObjects m2))
    other -> assertFailure ("short encaps is not a length rejection: " ++ show other)

-- ---------------------------------------------------------------------------
-- Part 2 fixtures
-- ---------------------------------------------------------------------------

iv16 :: ByteString
iv16 = "0123456789abcdef"

-- | Generate one AES key through the planner + synthetic backend.
genAesKey :: (Model -> CryptoEffect -> IO CryptoResult)
  -> Model -> SessionState -> [(AttributeType, AttributeValue)]
  -> IO (Model, ExternalHandle)
genAesKey answer m st tmpl = case planGenerateKey defaultRules m st aesKeyGenMech BS.empty tmpl of
  KeyEffect pw fx -> do
    res <- answer m fx
    c <- finishCommit m st pw res 1
    h <- handleOf (pcOutputs c !! 0)
    m' <- expectRight (publishDelta m (pcDelta c))
    pure (m', h)
  other -> assertFailure ("keygen plan is not an effect: " ++ show other) >> undefined

aesTmpl :: Int -> [(AttributeType, AttributeValue)]
aesTmpl n =
  [ (AttrClass, ValULong ckoSecretKey)
  , (AttrKeyType, ValULong ckkAes)
  , (AttrValueLen, ValULong (fromIntegral n))
  , (AttrToken, ValBool False)
  , (AttrPrivate, ValBool True)
  , (AttrSensitive, ValBool True)
  , (AttrExtractable, ValBool True)
  , (AttrEncrypt, ValBool True)
  , (AttrDecrypt, ValBool True)
  ]

-- | Generate one 3DES key through the planner + synthetic backend.
genDes3Key :: (Model -> CryptoEffect -> IO CryptoResult)
  -> Model -> SessionState -> [(AttributeType, AttributeValue)]
  -> IO (Model, ExternalHandle)
genDes3Key answer m st tmpl = case planGenerateKey defaultRules m st des3KeyGenMech BS.empty tmpl of
  KeyEffect pw fx -> do
    res <- answer m fx
    c <- finishCommit m st pw res 1
    h <- handleOf (pcOutputs c !! 0)
    m' <- expectRight (publishDelta m (pcDelta c))
    pure (m', h)
  other -> assertFailure ("keygen plan is not an effect: " ++ show other) >> undefined

des3Tmpl :: Int -> [(AttributeType, AttributeValue)]
des3Tmpl n =
  [ (AttrClass, ValULong ckoSecretKey)
  , (AttrKeyType, ValULong ckkDes3)
  , (AttrValueLen, ValULong (fromIntegral n))
  , (AttrToken, ValBool False)
  , (AttrPrivate, ValBool True)
  , (AttrSensitive, ValBool True)
  , (AttrExtractable, ValBool True)
  , (AttrSign, ValBool True)
  , (AttrVerify, ValBool True)
  ]

wrapKeyTmpl :: [(AttributeType, AttributeValue)]
wrapKeyTmpl =
  [ (AttrClass, ValULong ckoSecretKey)
  , (AttrKeyType, ValULong ckkAes)
  , (AttrValueLen, ValULong 32)
  , (AttrToken, ValBool False)
  , (AttrPrivate, ValBool True)
  , (AttrExtractable, ValBool False)
  , (AttrWrap, ValBool True)
  , (AttrUnwrap, ValBool True)
  ]

ecPubTmpl :: [(AttributeType, AttributeValue)]
ecPubTmpl =
  [ (AttrClass, ValULong ckoPublicKey)
  , (AttrKeyType, ValULong ckkEc)
  , (AttrEcParams, ValBytes "P-256")
  , (AttrToken, ValBool False)
  , (AttrVerify, ValBool True)
  ]

ecPrivTmpl :: [(AttributeType, AttributeValue)]
ecPrivTmpl =
  [ (AttrClass, ValULong ckoPrivateKey)
  , (AttrKeyType, ValULong ckkEc)
  , (AttrEcParams, ValBytes "P-256")
  , (AttrToken, ValBool False)
  , (AttrPrivate, ValBool True)
  , (AttrSensitive, ValBool True)
  , (AttrExtractable, ValBool False)
  , (AttrSign, ValBool True)
  ]

rsaPubTmpl :: [(AttributeType, AttributeValue)]
rsaPubTmpl =
  [ (AttrClass, ValULong ckoPublicKey)
  , (AttrKeyType, ValULong ckkRsa)
  , (AttrModulusBits, ValULong 2048)
  , (AttrToken, ValBool False)
  ]

rsaPrivTmpl :: [(AttributeType, AttributeValue)]
rsaPrivTmpl =
  [ (AttrClass, ValULong ckoPrivateKey)
  , (AttrKeyType, ValULong ckkRsa)
  , (AttrModulusBits, ValULong 2048)
  , (AttrToken, ValBool False)
  , (AttrPrivate, ValBool True)
  , (AttrSensitive, ValBool True)
  , (AttrExtractable, ValBool False)
  ]

-- Toy DSA domain values (shaped, not prime: planners check
-- presence and shape, never primality).
dsaP :: ByteString
dsaP = BS.pack (0x80 : replicate 127 1)

dsaQ :: ByteString
dsaQ = BS.pack (0x80 : replicate 19 2)

dsaG :: ByteString
dsaG = BS.pack (0x40 : replicate 127 3)

dsaPubTmpl :: [(AttributeType, AttributeValue)]
dsaPubTmpl =
  [ (AttrClass, ValULong ckoPublicKey)
  , (AttrKeyType, ValULong ckkDsa)
  , (AttrPrime, ValBytes dsaP)
  , (AttrSubprime, ValBytes dsaQ)
  , (AttrBase, ValBytes dsaG)
  , (AttrToken, ValBool False)
  , (AttrVerify, ValBool True)
  ]

dsaPrivTmpl :: [(AttributeType, AttributeValue)]
dsaPrivTmpl =
  [ (AttrClass, ValULong ckoPrivateKey)
  , (AttrKeyType, ValULong ckkDsa)
  , (AttrToken, ValBool False)
  , (AttrPrivate, ValBool True)
  , (AttrSensitive, ValBool True)
  , (AttrExtractable, ValBool False)
  , (AttrSign, ValBool True)
  ]

dsaParamsTmpl :: Word64 -> [(AttributeType, AttributeValue)]
dsaParamsTmpl l =
  [ (AttrClass, ValULong ckoDomainParameters)
  , (AttrKeyType, ValULong ckkDsa)
  , (AttrPrimeBits, ValULong l)
  , (AttrToken, ValBool False)
  ]

x942ParamsTmpl :: Word64 -> Word64 -> [(AttributeType, AttributeValue)]
x942ParamsTmpl l n =
  [ (AttrClass, ValULong ckoDomainParameters)
  , (AttrKeyType, ValULong ckkX9_42Dh)
  , (AttrPrimeBits, ValULong l)
  , (AttrSubprimeBits, ValULong n)
  , (AttrToken, ValBool False)
  ]

dhPkcsParamsTmpl :: Word64 -> Word64 -> [(AttributeType, AttributeValue)]
dhPkcsParamsTmpl l n =
  [ (AttrClass, ValULong ckoDomainParameters)
  , (AttrKeyType, ValULong ckkDh)
  , (AttrPrimeBits, ValULong l)
  , (AttrSubprimeBits, ValULong n)
  , (AttrToken, ValBool False)
  ]

-- Toy DH values (shaped: planners check presence and shape;
-- the real test below mints on the RFC 3526 prime).
dhP :: ByteString
dhP = BS.pack (0x80 : replicate 255 1)

dhG :: ByteString
dhG = BS.singleton 2

dhQ :: ByteString
dhQ = BS.pack (0x80 : replicate 31 4)

dhPubTmpl :: [(AttributeType, AttributeValue)]
dhPubTmpl =
  [ (AttrClass, ValULong ckoPublicKey)
  , (AttrKeyType, ValULong ckkDh)
  , (AttrPrime, ValBytes dhP)
  , (AttrBase, ValBytes dhG)
  , (AttrToken, ValBool False)
  , (AttrDerive, ValBool True)
  ]

dhPrivTmpl :: [(AttributeType, AttributeValue)]
dhPrivTmpl =
  [ (AttrClass, ValULong ckoPrivateKey)
  , (AttrKeyType, ValULong ckkDh)
  , (AttrToken, ValBool False)
  , (AttrPrivate, ValBool True)
  , (AttrSensitive, ValBool True)
  , (AttrExtractable, ValBool False)
  , (AttrDerive, ValBool True)
  ]

dhX942PubTmpl :: [(AttributeType, AttributeValue)]
dhX942PubTmpl =
  [ (AttrClass, ValULong ckoPublicKey)
  , (AttrKeyType, ValULong ckkX9_42Dh)
  , (AttrPrime, ValBytes dhP)
  , (AttrBase, ValBytes dhG)
  , (AttrSubprime, ValBytes dhQ)
  , (AttrToken, ValBool False)
  , (AttrDerive, ValBool True)
  ]

dhX942PrivTmpl :: [(AttributeType, AttributeValue)]
dhX942PrivTmpl =
  [ (AttrClass, ValULong ckoPrivateKey)
  , (AttrKeyType, ValULong ckkX9_42Dh)
  , (AttrToken, ValBool False)
  , (AttrPrivate, ValBool True)
  , (AttrSensitive, ValBool True)
  , (AttrExtractable, ValBool False)
  , (AttrDerive, ValBool True)
  ]

-- | The RFC 3526 2048-bit MODP prime (real keygen domain).
dhRealP :: ByteString
dhRealP = hex $ concat
  [ "ffffffffffffffffadf85458a2bb4a9aafdc5620273d3cf1d8b9c583ce2d3695a9"
  , "e13641146433fbcc939dce249b3ef97d2fe363630c75d8f681b202aec4617ad3"
  , "df1ed5d5fd65612433f51f5f066ed0856365553ded1af3b557135e7f57c93598"
  , "4f0c70e0e68b77e2a689daf3efe8721df158a136ade73530acca4f483a797abc"
  , "0ab182b324fb61d108a94bb2c8e3fbb96adab760d7f4681d4f42a3de394df4ae"
  , "56ede76372bb190b07a7c8ee0a6d709e02fce1cdf7e2ecc03404cd28342f6191"
  , "72fe9ce98583ff8e4f1232eef28183c3fe3b1b4c6fad733bb5fcbc2ec22005c5"
  , "8ef1837d1683b2c6f34a26c1b2effa886b423861285c97ffffffffffffffff"
  ]

-- Toy Edwards values (shaped: planners check presence and shape;
-- stamping parses real DER assembled from these parts).
ed19OidBytes :: ByteString
ed19OidBytes = hex "06032b6570"

ed48OidBytes :: ByteString
ed48OidBytes = hex "06032b6571"

edPoint19 :: ByteString
edPoint19 = BS.pack (0x58 : replicate 31 0x42)

edSeed19 :: ByteString
edSeed19 = BS.pack (0x11 : replicate 31 0x24)

edPubTmpl :: [(AttributeType, AttributeValue)]
edPubTmpl =
  [ (AttrClass, ValULong ckoPublicKey)
  , (AttrKeyType, ValULong ckkEcEdwards)
  , (AttrEcParams, ValBytes "Ed25519")
  , (AttrToken, ValBool False)
  , (AttrVerify, ValBool True)
  ]

edPrivTmpl :: [(AttributeType, AttributeValue)]
edPrivTmpl =
  [ (AttrClass, ValULong ckoPrivateKey)
  , (AttrKeyType, ValULong ckkEcEdwards)
  , (AttrToken, ValBool False)
  , (AttrPrivate, ValBool True)
  , (AttrSensitive, ValBool True)
  , (AttrExtractable, ValBool False)
  , (AttrSign, ValBool True)
  ]

-- Toy Montgomery values (shaped: planners check presence and
-- shape; stamping parses real DER assembled from these parts).
x19OidBytes :: ByteString
x19OidBytes = hex "06032b656e"

x48OidBytes :: ByteString
x48OidBytes = hex "06032b656f"

xPoint19 :: ByteString
xPoint19 = BS.pack (0x68 : replicate 31 0x42)

xScalar19 :: ByteString
xScalar19 = BS.pack (0x10 : replicate 31 0x24)

xdPubTmpl :: [(AttributeType, AttributeValue)]
xdPubTmpl =
  [ (AttrClass, ValULong ckoPublicKey)
  , (AttrKeyType, ValULong ckkEcMontgomery)
  , (AttrEcParams, ValBytes "X25519")
  , (AttrToken, ValBool False)
  , (AttrDerive, ValBool True)
  ]

xdPrivTmpl :: [(AttributeType, AttributeValue)]
xdPrivTmpl =
  [ (AttrClass, ValULong ckoPrivateKey)
  , (AttrKeyType, ValULong ckkEcMontgomery)
  , (AttrToken, ValBool False)
  , (AttrPrivate, ValBool True)
  , (AttrSensitive, ValBool True)
  , (AttrExtractable, ValBool False)
  , (AttrDerive, ValBool True)
  ]

-- ---------------------------------------------------------------------------
-- Part 2
-- ---------------------------------------------------------------------------

caseAesKeygen :: IO ()
caseAesKeygen = withSynth $ \answer -> do
  m0 <- seedModel
  st <- getSession m0
  (m1, h) <- genAesKey answer m0 st (aesTmpl 32)
  Just ost <- pure (resolveHandle m1 h)
  assertEqual "key class" (Just (ValULong ckoSecretKey)) (Map.lookup AttrClass (osAttrs ost))
  assertEqual "key type" (Just (ValULong ckkAes)) (Map.lookup AttrKeyType (osAttrs ost))
  assertEqual "usage landed" (Just (ValBool True)) (Map.lookup AttrEncrypt (osAttrs ost))
  case keyBytesOf ost of
    Just mat -> assertEqual "AES-256 material" 32 (BS.length mat)
    Nothing -> assertFailure "generated key lacks material"

caseDes3Keygen :: IO ()
caseDes3Keygen = withSynth $ \answer -> do
  m0 <- seedModel
  st <- getSession m0
  (m1, h) <- genDes3Key answer m0 st (des3Tmpl 24)
  Just ost <- pure (resolveHandle m1 h)
  assertEqual "key class" (Just (ValULong ckoSecretKey)) (Map.lookup AttrClass (osAttrs ost))
  assertEqual "key type" (Just (ValULong ckkDes3)) (Map.lookup AttrKeyType (osAttrs ost))
  assertEqual "usage landed" (Just (ValBool True)) (Map.lookup AttrSign (osAttrs ost))
  case keyBytesOf ost of
    Just mat -> assertEqual "DES3 material" 24 (BS.length mat)
    Nothing -> assertFailure "generated key lacks material"
  -- Two-key mints; off-geometry refuses inconsistent; a missing
  -- length mints three-key (24 bytes, the headline default).
  (m2, h2) <- genDes3Key answer m1 st (des3Tmpl 16)
  Just ost2 <- pure (resolveHandle m2 h2)
  case keyBytesOf ost2 of
    Just mat2 -> assertEqual "DES3 two-key material" 16 (BS.length mat2)
    Nothing -> assertFailure "generated key lacks material"
  case planGenerateKey defaultRules m2 st des3KeyGenMech BS.empty (des3Tmpl 32) of
    KeyDenied deny -> assertEqual "bad length code"
      CKR_TEMPLATE_INCONSISTENT (kdCode deny)
    other -> assertFailure ("32-byte DES3 must refuse: " ++ show other)
  (m3, h3) <- genDes3Key answer m2 st
    [a | a@(t, _) <- des3Tmpl 24, t /= AttrValueLen]
  Just ost3 <- pure (resolveHandle m3 h3)
  case keyBytesOf ost3 of
    Just mat3 -> assertEqual "DES3 default material" 24 (BS.length mat3)
    Nothing -> assertFailure "generated key lacks material"

caseBlake2b512Keygen :: IO ()
caseBlake2b512Keygen = withSynth $ \answer -> do
  m0 <- seedModel
  st <- getSession m0
  (m1, h) <- genBlake2b512Key answer m0 st (blake2b512Tmpl 64)
  Just ost <- pure (resolveHandle m1 h)
  assertEqual "key class" (Just (ValULong ckoSecretKey)) (Map.lookup AttrClass (osAttrs ost))
  assertEqual "key type" (Just (ValULong ckkBlake2b512Hmac)) (Map.lookup AttrKeyType (osAttrs ost))
  case keyBytesOf ost of
    Just mat -> assertEqual "BLAKE2B-512 material" 64 (BS.length mat)
    Nothing -> assertFailure "generated key lacks material"
  -- HMAC keygens take a VALUE_LEN-sized key (spec 6.x: "with a
  -- particular length in bytes, as specified in CKA_VALUE_LEN"),
  -- so 32 bytes mint; empty and over-frame refuse
  -- inconsistent, and a missing length refuses incomplete.
  (m2, h2) <- genBlake2b512Key answer m1 st (blake2b512Tmpl 32)
  Just ost2 <- pure (resolveHandle m2 h2)
  case keyBytesOf ost2 of
    Just mat2 -> assertEqual "BLAKE2B-512 short material" 32 (BS.length mat2)
    Nothing -> assertFailure "generated key lacks material"
  (m3, h3) <- genBlake2b512Key answer m2 st (blake2b512Tmpl 1)
  Just ost3 <- pure (resolveHandle m3 h3)
  case keyBytesOf ost3 of
    Just mat3 -> assertEqual "BLAKE2B-512 minimal material" 1 (BS.length mat3)
    Nothing -> assertFailure "generated key lacks material"
  (m4, h4) <- genBlake2b512Key answer m3 st (blake2b512Tmpl 255)
  Just ost4 <- pure (resolveHandle m4 h4)
  case keyBytesOf ost4 of
    Just mat4 -> assertEqual "BLAKE2B-512 maximal material" 255 (BS.length mat4)
    Nothing -> assertFailure "generated key lacks material"
  case planGenerateKey defaultRules m4 st blake2b512KeyGenMech BS.empty (blake2b512Tmpl 0) of
    KeyDenied deny -> assertEqual "empty length code"
      CKR_TEMPLATE_INCONSISTENT (kdCode deny)
    other -> assertFailure ("0-byte BLAKE2B-512 must refuse: " ++ show other)
  case planGenerateKey defaultRules m4 st blake2b512KeyGenMech BS.empty (blake2b512Tmpl 256) of
    KeyDenied deny -> assertEqual "over-frame length code"
      CKR_TEMPLATE_INCONSISTENT (kdCode deny)
    other -> assertFailure ("256-byte BLAKE2B-512 must refuse: " ++ show other)
  case planGenerateKey defaultRules m4 st blake2b512KeyGenMech BS.empty
      [a | a@(t, _) <- blake2b512Tmpl 64, t /= AttrValueLen] of
    KeyDenied deny -> assertEqual "missing length code"
      CKR_TEMPLATE_INCOMPLETE (kdCode deny)
    other -> assertFailure ("missing length must refuse: " ++ show other)

-- | Generate one BLAKE2B-512 HMAC key through the planner +
-- synthetic backend.
genBlake2b512Key :: (Model -> CryptoEffect -> IO CryptoResult)
  -> Model -> SessionState -> [(AttributeType, AttributeValue)]
  -> IO (Model, ExternalHandle)
genBlake2b512Key answer m st tmpl = case planGenerateKey defaultRules m st blake2b512KeyGenMech BS.empty tmpl of
  KeyEffect pw fx -> do
    res <- answer m fx
    c <- finishCommit m st pw res 1
    h <- handleOf (pcOutputs c !! 0)
    m' <- expectRight (publishDelta m (pcDelta c))
    pure (m', h)
  other -> assertFailure ("keygen plan is not an effect: " ++ show other) >> undefined

blake2b512Tmpl :: Int -> [(AttributeType, AttributeValue)]
blake2b512Tmpl n =
  [ (AttrClass, ValULong ckoSecretKey)
  , (AttrKeyType, ValULong ckkBlake2b512Hmac)
  , (AttrValueLen, ValULong (fromIntegral n))
  , (AttrToken, ValBool False)
  , (AttrSign, ValBool True)
  , (AttrVerify, ValBool True)
  ]

caseChacha20Keygen :: IO ()
caseChacha20Keygen = withSynth $ \answer -> do
  m0 <- seedModel
  st <- getSession m0
  (m1, h) <- genChacha20Key answer m0 st (chacha20Tmpl 32)
  Just ost <- pure (resolveHandle m1 h)
  assertEqual "key class" (Just (ValULong ckoSecretKey)) (Map.lookup AttrClass (osAttrs ost))
  assertEqual "key type" (Just (ValULong ckkChacha20)) (Map.lookup AttrKeyType (osAttrs ost))
  case keyBytesOf ost of
    Just mat -> assertEqual "ChaCha20 material" 32 (BS.length mat)
    Nothing -> assertFailure "generated key lacks material"
  -- Off-width refuses inconsistent; a missing length refuses
  -- incomplete (exact-32, the HOTP explicit-length precedent).
  case planGenerateKey defaultRules m1 st chacha20KeyGenMech BS.empty (chacha20Tmpl 16) of
    KeyDenied deny -> assertEqual "bad length code"
      CKR_TEMPLATE_INCONSISTENT (kdCode deny)
    other -> assertFailure ("16-byte ChaCha20 must refuse: " ++ show other)
  case planGenerateKey defaultRules m1 st chacha20KeyGenMech BS.empty
      [a | a@(t, _) <- chacha20Tmpl 32, t /= AttrValueLen] of
    KeyDenied deny -> assertEqual "missing length code"
      CKR_TEMPLATE_INCOMPLETE (kdCode deny)
    other -> assertFailure ("missing length must refuse: " ++ show other)

-- | Generate one ChaCha20 key through the planner + synthetic backend.
genChacha20Key :: (Model -> CryptoEffect -> IO CryptoResult)
  -> Model -> SessionState -> [(AttributeType, AttributeValue)]
  -> IO (Model, ExternalHandle)
genChacha20Key answer m st tmpl = case planGenerateKey defaultRules m st chacha20KeyGenMech BS.empty tmpl of
  KeyEffect pw fx -> do
    res <- answer m fx
    c <- finishCommit m st pw res 1
    h <- handleOf (pcOutputs c !! 0)
    m' <- expectRight (publishDelta m (pcDelta c))
    pure (m', h)
  other -> assertFailure ("keygen plan is not an effect: " ++ show other) >> undefined

chacha20Tmpl :: Int -> [(AttributeType, AttributeValue)]
chacha20Tmpl n =
  [ (AttrClass, ValULong ckoSecretKey)
  , (AttrKeyType, ValULong ckkChacha20)
  , (AttrValueLen, ValULong (fromIntegral n))
  , (AttrToken, ValBool False)
  , (AttrEncrypt, ValBool True)
  , (AttrDecrypt, ValBool True)
  ]

-- ---------------------------------------------------------------------------
-- Keygen sweep (slice 11a)
-- ---------------------------------------------------------------------------

-- | Sweep length shapes: fixed sizes mint the headline length when
-- @CKA_VALUE_LEN@ is absent; discrete and ranged shapes require it.
data SweepLens
  = SweepFixed Int
  | SweepDiscrete [Int]
  | SweepRange Int Int
  deriving (Eq, Show)

-- | (label, mechanism, key type, lengths, DES-parity?).
keygenSweepTable :: [(String, MechanismId, Word64, SweepLens, Bool)]
keygenSweepTable =
  [ ("DES", desKeyGenMech, ckkDes, SweepFixed 8, True)
  , ("DES2", des2KeyGenMech, ckkDes2, SweepFixed 16, True)
  , ("CDMF", cdmfKeyGenMech, ckkCdmf, SweepFixed 8, True)
  , ("IDEA", ideaKeyGenMech, ckkIdea, SweepFixed 16, False)
  , ("SEED", seedKeyGenMech, ckkSeed, SweepFixed 16, False)
  , ("SKIPJACK", skipjackKeyGenMech, ckkSkipjack, SweepFixed 12, False)
  , ("BATON", batonKeyGenMech, ckkBaton, SweepFixed 40, False)
  , ("JUNIPER", juniperKeyGenMech, ckkJuniper, SweepFixed 40, False)
  , ("GOST28147", gost28147KeyGenMech, ckkGost28147, SweepFixed 32, False)
  , ("SALSA20", salsa20KeyGenMech, ckkSalsa20, SweepFixed 32, False)
  , ("POLY1305", poly1305KeyGenMech, ckkPoly1305, SweepFixed 32, False)
  , ("ARIA", ariaKeyGenMech, ckkAria, SweepDiscrete [16, 24, 32], False)
  , ("CAMELLIA", camelliaKeyGenMech, ckkCamellia, SweepDiscrete [16, 24, 32], False)
  , ("TWOFISH", twofishKeyGenMech, ckkTwofish, SweepDiscrete [16, 24, 32], False)
  , ("AES-XTS", aesXtsKeyGenMech, ckkAesXts, SweepDiscrete [32, 64], False)
  , ("CAST", castKeyGenMech, ckkCast, SweepRange 1 8, False)
  , ("CAST3", cast3KeyGenMech, ckkCast3, SweepRange 1 8, False)
  , ("CAST128", cast128KeyGenMech, ckkCast128, SweepRange 1 16, False)
  , ("RC2", rc2KeyGenMech, ckkRc2, SweepRange 1 128, False)
  , ("RC4", rc4KeyGenMech, ckkRc4, SweepRange 1 255, False)
  , ("RC5", rc5KeyGenMech, ckkRc5, SweepRange 1 255, False)
  , ("BLOWFISH", blowfishKeyGenMech, ckkBlowfish, SweepRange 4 56, False)
  , ("HKDF", hkdfKeyGenMech, ckkHkdf, SweepRange 1 255, False)
  , ("SHA-1-HMAC", sha1KeyGenMech, ckkSha1Hmac, SweepRange 1 255, False)
  , ("SHA224-HMAC", sha224KeyGenMech, ckkSha224Hmac, SweepRange 1 255, False)
  , ("SHA256-HMAC", sha256KeyGenMech, ckkSha256Hmac, SweepRange 1 255, False)
  , ("SHA384-HMAC", sha384KeyGenMech, ckkSha384Hmac, SweepRange 1 255, False)
  , ("SHA512-HMAC", sha512KeyGenMech, ckkSha512Hmac, SweepRange 1 255, False)
  , ("SHA512/224-HMAC", sha512_224KeyGenMech, ckkSha512_224Hmac, SweepRange 1 255, False)
  , ("SHA512/256-HMAC", sha512_256KeyGenMech, ckkSha512_256Hmac, SweepRange 1 255, False)
  , ("SHA512/t-HMAC", sha512TKeyGenMech, ckkSha512THmac, SweepRange 1 255, False)
  , ("SHA3-224-HMAC", sha3_224KeyGenMech, ckkSha3_224Hmac, SweepRange 1 255, False)
  , ("SHA3-256-HMAC", sha3_256KeyGenMech, ckkSha3_256Hmac, SweepRange 1 255, False)
  , ("SHA3-384-HMAC", sha3_384KeyGenMech, ckkSha3_384Hmac, SweepRange 1 255, False)
  , ("SHA3-512-HMAC", sha3_512KeyGenMech, ckkSha3_512Hmac, SweepRange 1 255, False)
  , ("BLAKE2B-160-HMAC", blake2b160KeyGenMech, ckkBlake2b160Hmac, SweepRange 1 255, False)
  , ("BLAKE2B-256-HMAC", blake2b256KeyGenMech, ckkBlake2b256Hmac, SweepRange 1 255, False)
  , ("BLAKE2B-384-HMAC", blake2b384KeyGenMech, ckkBlake2b384Hmac, SweepRange 1 255, False)
  ]

-- | Good lengths, bad lengths, and the missing-length default (fixed
-- sizes only) for one sweep shape.
sweepLengths :: SweepLens -> ([Int], [Int], Maybe Int)
sweepLengths (SweepFixed n) =
  ([n], [x | x <- [n - 1, n + 1], x >= 0], Just n)
sweepLengths (SweepDiscrete ns) =
  (ns, filter (`notElem` ns) [0, 1, 8, 20, 48, 65], Nothing)
sweepLengths (SweepRange lo hi) =
  ([lo, (lo + hi) `div` 2, hi], [0] ++ [x | x <- [lo - 1, hi + 1], x > 0], Nothing)

caseKeygenSweep :: IO ()
caseKeygenSweep = withSynth $ \answer -> do
  m0 <- seedModel
  st <- getSession m0
  go answer st m0 keygenSweepTable
  where
    go _ _ _m [] = pure ()
    go answer st m (row : rows) = do
      m' <- runSweepRow answer st m row
      go answer st m' rows

runSweepRow
  :: (Model -> CryptoEffect -> IO CryptoResult)
  -> SessionState -> Model
  -> (String, MechanismId, Word64, SweepLens, Bool)
  -> IO Model
runSweepRow answer st m (label, mech, kt, lens, parity) = do
  let (good, bad, defLen) = sweepLengths lens
  case good of
    [] -> assertFailure (label ++ " sweep has no good length") >> pure m
    (g0 : _) -> do
      m1 <- mintGood m good
      mapM_ (refuseBad m1) bad
      m2 <- missingLen m1 g0 defLen
      case planGenerateKey defaultRules m2 st mech BS.empty (sweepTmpl ckkAes g0) of
        KeyDenied deny -> assertEqual (label ++ " wrong type code")
          CKR_TEMPLATE_INCONSISTENT (kdCode deny)
        other -> assertFailure (label ++ " wrong key type must refuse: " ++ show other)
      pure m2
  where
    mintGood m' [] = pure m'
    mintGood m' (n : ns) = do
      (m'', h) <- genSweepKey answer m' st mech (sweepTmpl kt n)
      Just ost <- pure (resolveHandle m'' h)
      assertEqual (label ++ " class")
        (Just (ValULong ckoSecretKey)) (Map.lookup AttrClass (osAttrs ost))
      assertEqual (label ++ " type")
        (Just (ValULong kt)) (Map.lookup AttrKeyType (osAttrs ost))
      case keyBytesOf ost of
        Just mat -> do
          assertEqual (label ++ " material length") n (BS.length mat)
          if parity
            then assertBool (label ++ " odd parity") (BS.all oddParity mat)
            else pure ()
        Nothing -> assertFailure (label ++ " generated key lacks material")
      mintGood m'' ns
    refuseBad m' n = case planGenerateKey defaultRules m' st mech BS.empty (sweepTmpl kt n) of
      KeyDenied deny -> assertEqual (label ++ " bad length code " ++ show n)
        CKR_TEMPLATE_INCONSISTENT (kdCode deny)
      other -> assertFailure (label ++ " length " ++ show n ++ " must refuse: " ++ show other)
    missingLen m' n (Just d) = do
      (m'', h) <- genSweepKey answer m' st mech (dropValueLen (sweepTmpl kt n))
      Just ost <- pure (resolveHandle m'' h)
      case keyBytesOf ost of
        Just mat -> assertEqual (label ++ " default material") d (BS.length mat)
        Nothing -> assertFailure (label ++ " generated key lacks material")
      pure m''
    missingLen m' n Nothing =
      case planGenerateKey defaultRules m' st mech BS.empty (dropValueLen (sweepTmpl kt n)) of
        KeyDenied deny -> do
          assertEqual (label ++ " missing length code")
            CKR_TEMPLATE_INCOMPLETE (kdCode deny)
          pure m'
        other -> assertFailure (label ++ " missing length must refuse: " ++ show other)
    dropValueLen tmpl = [a | a@(t, _) <- tmpl, t /= AttrValueLen]

-- | Odd DES parity: every key byte carries an odd number of 1 bits.
oddParity :: Word8 -> Bool
oddParity b = odd (popCount b)

-- | Generate one sweep key through the planner + synthetic backend.
genSweepKey :: (Model -> CryptoEffect -> IO CryptoResult)
  -> Model -> SessionState -> MechanismId
  -> [(AttributeType, AttributeValue)]
  -> IO (Model, ExternalHandle)
genSweepKey answer m st mech tmpl = case planGenerateKey defaultRules m st mech BS.empty tmpl of
  KeyEffect pw fx -> do
    res <- answer m fx
    c <- finishCommit m st pw res 1
    h <- handleOf (pcOutputs c !! 0)
    m' <- expectRight (publishDelta m (pcDelta c))
    pure (m', h)
  other -> assertFailure ("keygen plan is not an effect: " ++ show other) >> undefined

sweepTmpl :: Word64 -> Int -> [(AttributeType, AttributeValue)]
sweepTmpl kt n =
  [ (AttrClass, ValULong ckoSecretKey)
  , (AttrKeyType, ValULong kt)
  , (AttrValueLen, ValULong (fromIntegral n))
  , (AttrToken, ValBool False)
  , (AttrSign, ValBool True)
  ]

-- ---------------------------------------------------------------------------
-- Pre-master keygens (slice 11a, phase 2)
-- ---------------------------------------------------------------------------

-- | TLS/SSL3 pre-master: the 2-byte CK_VERSION parameter is
-- required and its bytes lead the 48-byte generic secret.
caseTlsPremasterKeygen :: IO ()
caseTlsPremasterKeygen = withSynth $ \answer -> do
  m0 <- seedModel
  st <- getSession m0
  (m1, h) <- genPremasterKey answer m0 st tlsPremasterKeyGenMech
    (BS.pack [3, 3]) (premasterTmpl 48)
  Just ost <- pure (resolveHandle m1 h)
  assertEqual "key type"
    (Just (ValULong ckkGenericSecret)) (Map.lookup AttrKeyType (osAttrs ost))
  case keyBytesOf ost of
    Just mat -> do
      assertEqual "pre-master length" 48 (BS.length mat)
      assertEqual "version prefix" (BS.pack [3, 3]) (BS.take 2 mat)
    Nothing -> assertFailure "generated key lacks material"
  -- A missing length defaults to 48; any other length refuses.
  (m2, h2) <- genPremasterKey answer m1 st tlsPremasterKeyGenMech
    (BS.pack [3, 1]) [a | a@(t, _) <- premasterTmpl 48, t /= AttrValueLen]
  Just ost2 <- pure (resolveHandle m2 h2)
  case keyBytesOf ost2 of
    Just mat2 -> do
      assertEqual "default length" 48 (BS.length mat2)
      assertEqual "default version prefix" (BS.pack [3, 1]) (BS.take 2 mat2)
    Nothing -> assertFailure "generated key lacks material"
  case planGenerateKey defaultRules m2 st tlsPremasterKeyGenMech
      (BS.pack [3, 3]) (premasterTmpl 16) of
    KeyDenied deny -> assertEqual "bad length code"
      CKR_TEMPLATE_INCONSISTENT (kdCode deny)
    other -> assertFailure ("16-byte pre-master must refuse: " ++ show other)
  -- The version parameter is required and exactly 2 bytes.
  mapM_ (refuseParams m2 st tlsPremasterKeyGenMech)
    [BS.empty, BS.singleton 3, BS.pack [3, 3, 3]]
  -- A non-generic-secret key type refuses.
  case planGenerateKey defaultRules m2 st tlsPremasterKeyGenMech
      (BS.pack [3, 3]) (sweepTmpl ckkAes 48) of
    KeyDenied deny -> assertEqual "wrong type code"
      CKR_TEMPLATE_INCONSISTENT (kdCode deny)
    other -> assertFailure ("AES-typed pre-master must refuse: " ++ show other)
  where
    refuseParams m st mech params =
      case planGenerateKey defaultRules m st mech params (premasterTmpl 48) of
        KeyDenied deny -> assertEqual ("params code " ++ show params)
          CKR_MECHANISM_PARAM_INVALID (kdCode deny)
        other -> assertFailure
          ("params " ++ show params ++ " must refuse: " ++ show other)

-- | SSL3 pre-master mirrors TLS (same parameter, same shape).
caseSsl3PremasterKeygen :: IO ()
caseSsl3PremasterKeygen = withSynth $ \answer -> do
  m0 <- seedModel
  st <- getSession m0
  (m1, h) <- genPremasterKey answer m0 st ssl3PremasterKeyGenMech
    (BS.pack [3, 0]) (premasterTmpl 48)
  Just ost <- pure (resolveHandle m1 h)
  case keyBytesOf ost of
    Just mat -> do
      assertEqual "pre-master length" 48 (BS.length mat)
      assertEqual "version prefix" (BS.pack [3, 0]) (BS.take 2 mat)
    Nothing -> assertFailure "generated key lacks material"
  case planGenerateKey defaultRules m1 st ssl3PremasterKeyGenMech
      BS.empty (premasterTmpl 48) of
    KeyDenied deny -> assertEqual "null params code"
      CKR_MECHANISM_PARAM_INVALID (kdCode deny)
    other -> assertFailure ("null params must refuse: " ++ show other)

-- | WTLS pre-master: a 1-byte version parameter leads a
-- variable-length (20-255 byte) generic secret.
caseWtlsPremasterKeygen :: IO ()
caseWtlsPremasterKeygen = withSynth $ \answer -> do
  m0 <- seedModel
  st <- getSession m0
  (m1, h) <- genPremasterKey answer m0 st wtlsPremasterKeyGenMech
    (BS.singleton 1) (premasterTmpl 32)
  Just ost <- pure (resolveHandle m1 h)
  case keyBytesOf ost of
    Just mat -> do
      assertEqual "pre-master length" 32 (BS.length mat)
      assertEqual "version prefix" (BS.singleton 1) (BS.take 1 mat)
    Nothing -> assertFailure "generated key lacks material"
  (m2, h2) <- genPremasterKey answer m1 st wtlsPremasterKeyGenMech
    (BS.singleton 1) (premasterTmpl 20)
  Just ost2 <- pure (resolveHandle m2 h2)
  case keyBytesOf ost2 of
    Just mat2 -> assertEqual "minimal length" 20 (BS.length mat2)
    Nothing -> assertFailure "generated key lacks material"
  mapM_ (refuseLen m2 st) [0, 19, 256]
  case planGenerateKey defaultRules m2 st wtlsPremasterKeyGenMech
      (BS.singleton 1) [a | a@(t, _) <- premasterTmpl 32, t /= AttrValueLen] of
    KeyDenied deny -> assertEqual "missing length code"
      CKR_TEMPLATE_INCOMPLETE (kdCode deny)
    other -> assertFailure ("missing length must refuse: " ++ show other)
  mapM_ (refuseParams m2 st) [BS.empty, BS.pack [1, 2]]
  where
    refuseLen m st n =
      case planGenerateKey defaultRules m st wtlsPremasterKeyGenMech
          (BS.singleton 1) (premasterTmpl n) of
        KeyDenied deny -> assertEqual ("length code " ++ show n)
          CKR_TEMPLATE_INCONSISTENT (kdCode deny)
        other -> assertFailure
          ("length " ++ show n ++ " must refuse: " ++ show other)
    refuseParams m st params =
      case planGenerateKey defaultRules m st wtlsPremasterKeyGenMech
          params (premasterTmpl 32) of
        KeyDenied deny -> assertEqual ("params code " ++ show params)
          CKR_MECHANISM_PARAM_INVALID (kdCode deny)
        other -> assertFailure
          ("params " ++ show params ++ " must refuse: " ++ show other)

-- | Generate one pre-master key through the planner + synthetic backend.
genPremasterKey :: (Model -> CryptoEffect -> IO CryptoResult)
  -> Model -> SessionState -> MechanismId -> ByteString
  -> [(AttributeType, AttributeValue)]
  -> IO (Model, ExternalHandle)
genPremasterKey answer m st mech params tmpl =
  case planGenerateKey defaultRules m st mech params tmpl of
    KeyEffect pw fx -> do
      res <- answer m fx
      c <- finishCommit m st pw res 1
      h <- handleOf (pcOutputs c !! 0)
      m' <- expectRight (publishDelta m (pcDelta c))
      pure (m', h)
    other -> assertFailure ("keygen plan is not an effect: " ++ show other) >> undefined

premasterTmpl :: Int -> [(AttributeType, AttributeValue)]
premasterTmpl n =
  [ (AttrClass, ValULong ckoSecretKey)
  , (AttrKeyType, ValULong ckkGenericSecret)
  , (AttrValueLen, ValULong (fromIntegral n))
  , (AttrToken, ValBool False)
  , (AttrSign, ValBool True)
  ]

-- | PBKD2 keygen (slice 11b): the v2 frame carries the password
-- inline and the planner mints deterministic generic-secret
-- material through the synthetic backend.
casePbkd2Keygen :: IO ()
casePbkd2Keygen = withSynth $ \answer -> do
  m0 <- seedModel
  st <- getSession m0
  let mech = MechanismId ckm_PKCS5_PBKD2
      frame = encodePbkd2Params 4 4096 "salt" "password"
  (m1, h) <- genPremasterKey answer m0 st mech frame (premasterTmpl 32)
  Just ost <- pure (resolveHandle m1 h)
  mat1 <- case keyBytesOf ost of
    Just mat -> do
      assertEqual "derived length" 32 (BS.length mat)
      pure mat
    Nothing -> assertFailure "generated key lacks material" >> undefined
  (m2, h2) <- genPremasterKey answer m1 st mech frame (premasterTmpl 32)
  Just ost2 <- pure (resolveHandle m2 h2)
  case keyBytesOf ost2 of
    Just mat2 -> assertEqual "deterministic material" mat1 mat2
    Nothing -> assertFailure "generated key lacks material"
  -- Typed secret targets (fast r46 `test_derive_aes_key`): AES-256
  -- plans and mints 32 bytes stamped CKK_AES; off-domain AES
  -- lengths refuse. DES3/XTS serve their fixed domains; unlisted
  -- types refuse closed.
  (mAes, hAes) <- genPremasterKey answer m2 st mech frame (aesTmpl 32)
  Just ostAes <- pure (resolveHandle mAes hAes)
  assertEqual "aes keytype" (Just (ValULong ckkAes))
    (Map.lookup AttrKeyType (osAttrs ostAes))
  case keyBytesOf ostAes of
    Just matAes -> assertEqual "aes length" 32 (BS.length matAes)
    Nothing -> assertFailure "AES target lacks material"
  case planGenerateKey defaultRules mAes st mech frame (aesTmpl 20) of
    KeyDenied deny -> assertEqual "aes-20 code"
      CKR_TEMPLATE_INCONSISTENT (kdCode deny)
    other -> assertFailure ("AES-20 must refuse: " ++ show other)
  case planGenerateKey defaultRules mAes st mech frame (typedTmpl ckkDes3 24) of
    KeyEffect _ _ -> pure ()
    other -> assertFailure ("DES3-24 must plan: " ++ show (voidFx other))
  case planGenerateKey defaultRules mAes st mech frame (typedTmpl ckkAesXts 64) of
    KeyEffect _ _ -> pure ()
    other -> assertFailure ("XTS-64 must plan: " ++ show (voidFx other))
  case planGenerateKey defaultRules mAes st mech frame (typedTmpl ckkSha256Hmac 32) of
    KeyDenied deny -> assertEqual "hmac code"
      CKR_TEMPLATE_INCONSISTENT (kdCode deny)
    other -> assertFailure ("HMAC target must refuse: " ++ show (voidFx other))
  -- A missing length refuses; zero and over-ceiling refuse.
  case planGenerateKey defaultRules m2 st mech frame
      [a | a@(t, _) <- premasterTmpl 32, t /= AttrValueLen] of
    KeyDenied deny -> assertEqual "missing length code"
      CKR_TEMPLATE_INCOMPLETE (kdCode deny)
    other -> assertFailure ("missing length must refuse: " ++ show other)
  mapM_ (refuseLen m2 st mech frame) [0, maxDerivedTotal + 1]
  -- Malformed frames refuse with the parameter code.
  mapM_ (refuseParams m2 st mech)
    [ BS.empty
    , BS.take 30 frame
    , encodePbkd2Params 4 0 "salt" "password"
    , encodePbkd2Params 4 (maxPbkd2Iters + 1) "salt" "password"
    , encodePbkd2Params 99 1 "salt" "password"
    ]
  where
    refuseLen m st mech frame n =
      case planGenerateKey defaultRules m st mech frame (premasterTmpl n) of
        KeyDenied deny -> assertEqual ("length code " ++ show n)
          CKR_TEMPLATE_INCONSISTENT (kdCode deny)
        other -> assertFailure
          ("length " ++ show n ++ " must refuse: " ++ show other)
    refuseParams m st mech params =
      case planGenerateKey defaultRules m st mech params (premasterTmpl 32) of
        KeyDenied deny -> assertEqual ("params code " ++ show params)
          CKR_MECHANISM_PARAM_INVALID (kdCode deny)
        other -> assertFailure
          ("params " ++ show params ++ " must refuse: " ++ show other)
    typedTmpl :: Word64 -> Int -> [(AttributeType, AttributeValue)]
    typedTmpl k n =
      [ (AttrClass, ValULong ckoSecretKey)
      , (AttrKeyType, ValULong k)
      , (AttrValueLen, ValULong (fromIntegral n))
      , (AttrToken, ValBool False)
      ]
    voidFx :: KeyPlan -> String
    voidFx (KeyDenied deny) = "denied: " ++ show (kdCode deny)
    voidFx (KeyImmediate _) = "immediate"
    voidFx (KeyEffect _ _) = "effect"

caseAesKeygenEncapsulate :: IO ()
caseAesKeygenEncapsulate = withSynth $ \_answer -> do
  m0 <- seedModel
  st <- getSession m0
  case planGenerateKey defaultRules m0 st aesKeyGenMech BS.empty (aesTmpl 16 ++
      [(AttrEncapsulate, ValBool True)]) of
    KeyDenied deny -> assertEqual "encapsulate code"
      CKR_TEMPLATE_INCONSISTENT (kdCode deny)
    other -> assertFailure
      ("encapsulate on AES keygen must refuse: " ++ show (voidFx other))
  where
    voidFx :: KeyPlan -> String
    voidFx (KeyDenied deny) = "denied: " ++ show (kdCode deny)
    voidFx (KeyImmediate _) = "immediate"
    voidFx (KeyEffect _ _) = "effect"

caseInitAllowedMechanisms :: IO ()
caseInitAllowedMechanisms = withSynth $ \answer -> do
  mSeed <- seedModel
  m0 <- loginUser mSeed
  st <- getSession m0
  let listed = le64 (unMech hmacSha256Mech)
      other = le64 (unMech aesCbcMech)
  (m1, listedH) <- genKeyWith answer m0 st genericSecretKeyGenMech
    (genericTmpl 32 ++ [(AttrAllowedMechanisms, ValBytes listed)])
  (m2, otherH) <- genKeyWith answer m1 st genericSecretKeyGenMech
    (genericTmpl 32 ++ [(AttrAllowedMechanisms, ValBytes other)])
  (m3, freeH) <- genKeyWith answer m2 st genericSecretKeyGenMech
    (genericTmpl 32)
  let env = OpEnv
        { oeRegistry = curatedRegistry
        , oeCaps = mkCapabilities [(hmacSha256Mech, OpSign)]
        , oeModel = m3
        }
      mkSign h = InitArgs
        { iaOp = OpSign
        , iaMech = hmacSha256Mech
        , iaParams = BS.empty
        , iaKey = Just (KeyPolicy h [OpSign] False)
        , iaCipher = Nothing
        , iaRecover = Nothing
        }
  let (_, okListed) = initOperation env emptySessionOps st (mkSign listedH)
  assertEqual "listed mech inits" CKR_OK (ioCode okListed)
  let (_, denyOther) = initOperation env emptySessionOps st (mkSign otherH)
  assertEqual "unlisted mech refused" CKR_KEY_FUNCTION_NOT_PERMITTED
    (ioCode denyOther)
  let (_, okFree) = initOperation env emptySessionOps st (mkSign freeH)
  assertEqual "unlisted key inits" CKR_OK (ioCode okFree)
  where
    unMech (MechanismId w) = w
    le64 :: Word64 -> ByteString
    le64 w = BS.pack
      [ fromIntegral ((w `shiftR` s) .&. 0xFF) | s <- [0, 8 .. 56] ]

genericTmpl :: Int -> [(AttributeType, AttributeValue)]
genericTmpl n =
  [ (AttrClass, ValULong ckoSecretKey)
  , (AttrKeyType, ValULong ckkGenericSecret)
  , (AttrValueLen, ValULong (fromIntegral n))
  , (AttrToken, ValBool False)
  , (AttrPrivate, ValBool True)
  , (AttrSign, ValBool True)
  , (AttrVerify, ValBool True)
  , (AttrEncrypt, ValBool True)
  ]

-- | Generate one key with an explicit mechanism through the planner
-- + synthetic backend.
genKeyWith :: (Model -> CryptoEffect -> IO CryptoResult)
  -> Model -> SessionState -> MechanismId -> [(AttributeType, AttributeValue)]
  -> IO (Model, ExternalHandle)
genKeyWith answer m st mech tmpl = case planGenerateKey defaultRules m st mech BS.empty tmpl of
  KeyEffect pw fx -> do
    res <- answer m fx
    c <- finishCommit m st pw res 1
    h <- handleOf (pcOutputs c !! 0)
    m' <- expectRight (publishDelta m (pcDelta c))
    pure (m', h)
  other -> assertFailure ("keygen plan is not an effect: " ++ show other) >> undefined

caseGenericSecretKeygen :: IO ()
caseGenericSecretKeygen = withSynth $ \answer -> do
  m0 <- seedModel
  st <- getSession m0
  (m1, h) <- genKeyWith answer m0 st genericSecretKeyGenMech (genericTmpl 32)
  Just ost <- pure (resolveHandle m1 h)
  assertEqual "key type" (Just (ValULong ckkGenericSecret)) (Map.lookup AttrKeyType (osAttrs ost))
  case keyBytesOf ost of
    Just mat -> assertEqual "generic-256 material" 32 (BS.length mat)
    Nothing -> assertFailure "generated key lacks material"
  -- Bounds: the 1..255 window mints, edges refuse.
  let plan n = planGenerateKey defaultRules m1 st genericSecretKeyGenMech BS.empty (genericTmpl n)
  case plan genericSecretKeygenMinBytes of
    KeyEffect _ _ -> pure ()
    other -> assertFailure ("min length must plan: " ++ show (voidFx other))
  case plan genericSecretKeygenMaxBytes of
    KeyEffect _ _ -> pure ()
    other -> assertFailure ("max length must plan: " ++ show (voidFx other))
  case plan (genericSecretKeygenMinBytes - 1) of
    KeyDenied deny -> assertEqual "zero length code" CKR_TEMPLATE_INCONSISTENT (kdCode deny)
    other -> assertFailure ("zero length must refuse: " ++ show (voidFx other))
  case plan (genericSecretKeygenMaxBytes + 1) of
    KeyDenied deny -> assertEqual "over length code" CKR_TEMPLATE_INCONSISTENT (kdCode deny)
    other -> assertFailure ("over length must refuse: " ++ show (voidFx other))
  -- A contradictory key type refuses.
  case planGenerateKey defaultRules m1 st genericSecretKeyGenMech BS.empty
      [ (AttrClass, ValULong ckoSecretKey)
      , (AttrKeyType, ValULong ckkAes)
      , (AttrValueLen, ValULong 16)
      ] of
    KeyDenied deny -> assertEqual "wrong type code" CKR_TEMPLATE_INCONSISTENT (kdCode deny)
    other -> assertFailure ("wrong key type must refuse: " ++ show (voidFx other))
  where
    voidFx :: KeyPlan -> String
    voidFx (KeyDenied deny) = "denied: " ++ show (kdCode deny)
    voidFx (KeyImmediate _) = "immediate"
    voidFx (KeyEffect _ _) = "effect"

hmacSha256Mech :: MechanismId
hmacSha256Mech = MechanismId ckm_SHA256_HMAC

des3macMech :: MechanismId
des3macMech = MechanismId ckm_DES3_MAC

des3macGenMech :: MechanismId
des3macGenMech = MechanismId ckm_DES3_MAC_GENERAL

sha256Mech :: MechanismId
sha256Mech = MechanismId ckm_SHA256

aesCcmMech :: MechanismId
aesCcmMech = MechanismId ckm_AES_CCM

caseInitKeyTypeMatrix :: IO ()
caseInitKeyTypeMatrix = withSynth $ \answer -> do
  mSeed <- seedModel
  m0 <- loginUser mSeed
  st <- getSession m0
  -- All keys carry sign, verify, AND encrypt usage: a usage-first
  -- check would admit every leg below, so each refusal proves the
  -- matrix fired (type before usage).
  (m1, aesH) <- genKeyWith answer m0 st aesKeyGenMech
    [ (AttrClass, ValULong ckoSecretKey)
    , (AttrKeyType, ValULong ckkAes)
    , (AttrValueLen, ValULong 16)
    , (AttrToken, ValBool False)
    , (AttrSign, ValBool True)
    , (AttrVerify, ValBool True)
    , (AttrEncrypt, ValBool True)
    ]
  (m2, genH) <- genKeyWith answer m1 st genericSecretKeyGenMech (genericTmpl 32)
  (m3, des3H) <- genDes3Key answer m2 st (des3Tmpl 24)
  let env = OpEnv
        { oeRegistry = curatedRegistry
        , oeCaps = mkCapabilities
            [ (hmacSha256Mech, OpSign)
            , (aesCbcMech, OpEncrypt)
            , (des3macMech, OpSign)
            , (des3macMech, OpVerify)
            ]
        , oeModel = m3
        }
      mkSign h = InitArgs
        { iaOp = OpSign
        , iaMech = hmacSha256Mech
        , iaParams = BS.empty
        , iaKey = Just (KeyPolicy h [OpSign] False)
        , iaCipher = Nothing
        , iaRecover = Nothing
        }
      mkEnc h = InitArgs
        { iaOp = OpEncrypt
        , iaMech = aesCbcMech
        , iaParams = iv16
        , iaKey = Just (KeyPolicy h [OpEncrypt] False)
        , iaCipher = Just (CipherSpec 16 False)
        , iaRecover = Nothing
        }
      mkMacSign h = InitArgs
        { iaOp = OpSign
        , iaMech = des3macMech
        , iaParams = BS.empty
        , iaKey = Just (KeyPolicy h [OpSign] False)
        , iaCipher = Nothing
        , iaRecover = Nothing
        }
      mkMacVerify h = InitArgs
        { iaOp = OpVerify
        , iaMech = des3macMech
        , iaParams = BS.empty
        , iaKey = Just (KeyPolicy h [OpVerify] False)
        , iaCipher = Nothing
        , iaRecover = Nothing
        }
  let (_, signGen) = initOperation env emptySessionOps st (mkSign genH)
  assertEqual "HMAC sign with generic key" CKR_OK (ioCode signGen)
  let (_, signAes) = initOperation env emptySessionOps st (mkSign aesH)
  assertEqual "HMAC sign with AES key" CKR_KEY_TYPE_INCONSISTENT (ioCode signAes)
  let (_, encAes) = initOperation env emptySessionOps st (mkEnc aesH)
  assertEqual "AES-CBC encrypt with AES key" CKR_OK (ioCode encAes)
  let (_, encGen) = initOperation env emptySessionOps st (mkEnc genH)
  assertEqual "AES-CBC encrypt with generic key" CKR_KEY_TYPE_INCONSISTENT (ioCode encGen)
  let (_, macSignDes3) = initOperation env emptySessionOps st (mkMacSign des3H)
  assertEqual "3DES-MAC sign with DES3 key" CKR_OK (ioCode macSignDes3)
  let (_, macSignAes) = initOperation env emptySessionOps st (mkMacSign aesH)
  assertEqual "3DES-MAC sign with AES key" CKR_KEY_TYPE_INCONSISTENT (ioCode macSignAes)
  let (_, macVerifyDes3) = initOperation env emptySessionOps st (mkMacVerify des3H)
  assertEqual "3DES-MAC verify with DES3 key" CKR_OK (ioCode macVerifyDes3)
  let (_, macVerifyGen) = initOperation env emptySessionOps st (mkMacVerify genH)
  assertEqual "3DES-MAC verify with generic key" CKR_KEY_TYPE_INCONSISTENT (ioCode macVerifyGen)
  -- Direct matrix pins.
  assertEqual "hmac row" (Just [ckkGenericSecret, mustKeyTypeId "CKK_SHA256_HMAC"])
    (matrixKeyTypes hmacSha256Mech OpSign)
  assertEqual "des3mac row" (Just [ckkDes3]) (matrixKeyTypes des3macMech OpSign)
  assertEqual "des3mac row verify" (Just [ckkDes3]) (matrixKeyTypes des3macMech OpVerify)
  assertEqual "des3mac general row" (Just [ckkDes3]) (matrixKeyTypes des3macGenMech OpSign)
  assertEqual "des3mac general row verify" (Just [ckkDes3]) (matrixKeyTypes des3macGenMech OpVerify)
  assertEqual "cbc row" (Just [ckkAes]) (matrixKeyTypes aesCbcMech OpEncrypt)
  assertEqual "ccm row" (Just [ckkAes]) (matrixKeyTypes aesCcmMech OpEncrypt)
  assertEqual "ccm row decrypt" (Just [ckkAes]) (matrixKeyTypes aesCcmMech OpDecrypt)
  assertEqual "digest unmatrices" Nothing (matrixKeyTypes sha256Mech OpDigest)
  assertEqual "off-op unmatrices" Nothing (matrixKeyTypes hmacSha256Mech OpEncrypt)
  -- Legacy objects without a key type skip the matrix (the seam).
  let legacyAttrs = Map.fromList
        [ (AttrClass, ValULong ckoSecretKey)
        , (AttrToken, ValBool False)
        ]
  (m4, legacyH) <- case publishPending m2 st [pendingFromAttrs st legacyAttrs] of
    Left deny -> assertFailure ("plant must publish: " ++ show deny) >> undefined
    Right (delta, [h]) -> do
      m' <- expectRight (publishDelta m2 delta)
      pure (m', h)
    Right _ -> assertFailure "plant must mint one handle" >> undefined
  let env3 = env { oeModel = m4 }
      (_, signLegacy) = initOperation env3 emptySessionOps st (mkSign legacyH)
  assertEqual "untyped legacy key skips matrix" CKR_OK (ioCode signLegacy)

caseEcKeypair :: IO ()
caseEcKeypair = withSynth $ \answer -> do
  m0 <- seedModel
  st <- getSession m0
  case planGenerateKeyPair defaultRules m0 st ecKeyPairGenMech ecPubTmpl ecPrivTmpl of
    KeyEffect pw fx -> do
      res <- answer m0 fx
      c <- finishCommit m0 st pw res 2
      pubH <- handleOf (pcOutputs c !! 0)
      privH <- handleOf (pcOutputs c !! 1)
      m1 <- expectRight (publishDelta m0 (pcDelta c))
      Just pub <- pure (resolveHandle m1 pubH)
      Just priv <- pure (resolveHandle m1 privH)
      assertEqual "pub usage" (Just (ValBool True)) (Map.lookup AttrVerify (osAttrs pub))
      assertEqual "priv usage" (Just (ValBool True)) (Map.lookup AttrSign (osAttrs priv))
      case (keyBytesOf pub, keyBytesOf priv) of
        (Just p, Just q) -> do
          assertEqual "pub half length" 69 (BS.length p)
          assertEqual "priv half length" 69 (BS.length q)
          assertEqual "pair magic" "HKS1" (BS.take 4 p)
        _ -> assertFailure "EC halves lack material"
    other -> assertFailure ("EC keypair plan is not an effect: " ++ show other)

-- | ML-DSA keygen templates (the set rides the public half; the
-- private half inherits it).
mldsaPubTmpl :: [(AttributeType, AttributeValue)]
mldsaPubTmpl =
  [ (AttrClass, ValULong ckoPublicKey)
  , (AttrKeyType, ValULong ckkMlDsa)
  , (AttrToken, ValBool False)
  , (AttrVerify, ValBool True)
  , (AttrParameterSet, ValULong 1)
  ]

mldsaPrivTmpl :: [(AttributeType, AttributeValue)]
mldsaPrivTmpl =
  [ (AttrClass, ValULong ckoPrivateKey)
  , (AttrKeyType, ValULong ckkMlDsa)
  , (AttrToken, ValBool False)
  , (AttrSign, ValBool True)
  ]

caseMldsaKeypair :: IO ()
caseMldsaKeypair = withSynth $ \answer -> do
  m0 <- seedModel
  st <- getSession m0
  case planGenerateKeyPair defaultRules m0 st mldsaKeyPairGenMech mldsaPubTmpl mldsaPrivTmpl of
    KeyEffect pw fx -> do
      res <- answer m0 fx
      c <- finishCommit m0 st pw res 2
      pubH <- handleOf (pcOutputs c !! 0)
      privH <- handleOf (pcOutputs c !! 1)
      m1 <- expectRight (publishDelta m0 (pcDelta c))
      Just pub <- pure (resolveHandle m1 pubH)
      Just priv <- pure (resolveHandle m1 privH)
      assertEqual "pub usage" (Just (ValBool True)) (Map.lookup AttrVerify (osAttrs pub))
      assertEqual "priv usage" (Just (ValBool True)) (Map.lookup AttrSign (osAttrs priv))
      assertEqual "pub set" (Just (ValULong 1)) (Map.lookup AttrParameterSet (osAttrs pub))
      assertEqual "priv set inherited" (Just (ValULong 1)) (Map.lookup AttrParameterSet (osAttrs priv))
      -- Opaque synthetic halves pass through unstamped: no seed.
      assertEqual "no seed stamped" Nothing (Map.lookup AttrSeed (osAttrs priv))
      case (keyBytesOf pub, keyBytesOf priv) of
        (Just p, Just q) -> do
          assertEqual "pair magic" "HKS1" (BS.take 4 p)
          assertBool "halves differ" (p /= q)
        _ -> assertFailure "ML-DSA halves lack material"
    other -> assertFailure ("ML-DSA keypair plan is not an effect: " ++ show other)

caseMldsaSetPlanner :: IO ()
caseMldsaSetPlanner = do
  m0 <- seedModel
  st <- getSession m0
  let argsOf pubT privT =
        case planGenerateKeyPair defaultRules m0 st mldsaKeyPairGenMech pubT privT of
          KeyEffect _ (FxGenerateKey _ _ input) -> Right (decodeGenArgs input)
          KeyDenied (KeyDeny code _) -> Left code
          other -> error ("unexpected plan shape: " ++ show other)
      withSet tmpl n = tmpl ++ [(AttrParameterSet, ValULong n)]
      noSet = filter ((/= AttrParameterSet) . fst) mldsaPubTmpl
  -- Public-side set carries into the effect args.
  assertEqual "44 plans" (Right (Just (GenMlDsa 1)))
    (argsOf mldsaPubTmpl mldsaPrivTmpl)
  assertEqual "87 plans" (Right (Just (GenMlDsa 3)))
    (argsOf (withSet noSet 3) mldsaPrivTmpl)
  -- Private-side set alone also plans.
  assertEqual "private-side set" (Right (Just (GenMlDsa 3)))
    (argsOf noSet (withSet mldsaPrivTmpl 3))
  -- Absent everywhere defaults to 65 (the KEM precedent).
  assertEqual "default 65" (Right (Just (GenMlDsa 2)))
    (argsOf noSet mldsaPrivTmpl)
  -- Disagreement and unknown sets refuse.
  assertEqual "set disagreement" (Left CKR_TEMPLATE_INCONSISTENT)
    (argsOf mldsaPubTmpl (withSet mldsaPrivTmpl 3))
  assertEqual "unknown set" (Left CKR_TEMPLATE_INCONSISTENT)
    (argsOf (withSet noSet 7) mldsaPrivTmpl)
  -- The tag-8 frame pins the CKP id big-endian.
  assertEqual "frame tag 8" (BS.pack [8, 0, 2]) (encodeGenArgs (GenMlDsa 2))
  assertEqual "frame roundtrip" (Just (GenMlDsa 3))
    (decodeGenArgs (BS.pack [8, 0, 3]))
  assertEqual "short frame refuses" Nothing
    (decodeGenArgs (BS.pack [8, 0]))

caseMldsaStampSeed :: IO ()
caseMldsaStampSeed = do
  m0 <- seedModel
  st <- getSession m0
  pub44 <- BS.readFile "tests/fixtures/mldsa44-pub.der"
  priv44 <- BS.readFile "tests/fixtures/mldsa44-priv.der"
  priv65 <- BS.readFile "tests/fixtures/mldsa65-priv.der"
  let pub = pendingFromAttrs st (Map.fromList mldsaPubTmpl)
      priv = pendingFromAttrs st (Map.fromList mldsaPrivTmpl)
  case stampPairComponents pub priv pub44 priv44 of
    Just (_, priv') -> case Map.lookup AttrSeed (poAttrs priv') of
      Just (ValBytes seed) -> assertEqual "seed width" 32 (BS.length seed)
      other -> assertFailure ("seed not stamped: " ++ show other)
    Nothing -> assertFailure "agreeing halves must stamp"
  -- Disagreeing or opaque halves pass through unstamped (no
  -- seed), never refused.
  case stampPairComponents pub priv pub44 priv65 of
    Just (_, priv') -> assertEqual "mismatch unstamped" Nothing
      (Map.lookup AttrSeed (poAttrs priv'))
    Nothing -> assertFailure "mismatched halves must pass through"
  case stampPairComponents pub priv "nope" "nope" of
    Just (_, priv') -> assertEqual "garbage unstamped" Nothing
      (Map.lookup AttrSeed (poAttrs priv'))
    Nothing -> assertFailure "opaque halves must pass through"

-- | EC templates on the given engine curve name.
ecTmpls :: ByteString
  -> ([(AttributeType, AttributeValue)], [(AttributeType, AttributeValue)])
ecTmpls curve = (retmpl ecPubTmpl, retmpl ecPrivTmpl)
  where
    retmpl = map (\(t, v) -> if t == AttrEcParams then (t, ValBytes curve) else (t, v))

caseEcKeygenCurves :: IO ()
caseEcKeygenCurves = withSynth $ \answer -> do
  m0 <- seedModel
  st <- getSession m0
  let gen m curve = do
        let (pubT, privT) = ecTmpls curve
        case planGenerateKeyPair defaultRules m st ecKeyPairGenMech pubT privT of
          KeyEffect pw fx -> do
            res <- answer m fx
            c <- finishCommit m st pw res 2
            pubH <- handleOf (pcOutputs c !! 0)
            privH <- handleOf (pcOutputs c !! 1)
            m' <- expectRight (publishDelta m (pcDelta c))
            Just pub <- pure (resolveHandle m' pubH)
            Just priv <- pure (resolveHandle m' privH)
            case (keyBytesOf pub, keyBytesOf priv) of
              (Just p, Just q) -> do
                assertEqual "pair magic" "HKS1" (BS.take 4 p)
                assertBool "halves differ" (p /= q)
              _ -> assertFailure "EC halves lack material"
            pure m'
          other -> assertFailure ("EC plan is not an effect: " ++ show other) >> undefined
  let go m [] = pure m
      go m (c : cs) = do
        m' <- gen m c
        go m' cs
  _ <- go m0 [n | (n, _, _) <- curveTable]
  pure ()

caseRsaKeygen :: IO ()
caseRsaKeygen = do
  opened <- openBackend "11" :: IO (EngineResult (BackendEnv Synthetic))
  case opened of
    EngineFail err -> assertFailure ("synthetic open failed: " ++ show err)
    EngineOk env -> do
      let answer m fx = runEffect env (resolverFromModel m) fx
      m0 <- seedModel
      st <- getSession m0
      (m1, pubH, privH) <- case planGenerateKeyPair defaultRules m0 st rsaKeyPairGenMech rsaPubTmpl rsaPrivTmpl of
        KeyEffect pw fx -> do
          res <- answer m0 fx
          c <- finishCommit m0 st pw res 2
          h1 <- handleOf (pcOutputs c !! 0)
          h2 <- handleOf (pcOutputs c !! 1)
          m' <- expectRight (publishDelta m0 (pcDelta c))
          pure (m', h1, h2)
        other -> assertFailure ("RSA plan is not an effect: " ++ show other) >> undefined
      Just pub <- pure (resolveHandle m1 pubH)
      Just priv <- pure (resolveHandle m1 privH)
      -- Components stamped: 256-byte modulus, default exponent.
      n <- case Map.lookup AttrModulus (osAttrs pub) of
        Just (ValBytes bs) -> do
          assertEqual "modulus length" 256 (BS.length bs)
          pure bs
        other -> assertFailure ("pub lacks modulus: " ++ show other) >> undefined
      assertEqual "default exponent"
        (Just (ValBytes (BS.pack [1, 0, 1])))
        (Map.lookup AttrPublicExponent (osAttrs pub))
      -- Generation params are not stored attributes.
      assertBool "modulus bits dropped"
        (Map.notMember AttrModulusBits (osAttrs pub))
      assertBool "modulus bits dropped (priv)"
        (Map.notMember AttrModulusBits (osAttrs priv))
      -- The private half carries all eight CRT parts ...
      mapM_ (assertPresent (osAttrs priv))
        [ AttrModulus, AttrPublicExponent, AttrPrivateExponent, AttrPrime1
        , AttrPrime2, AttrExponent1, AttrExponent2, AttrCoefficient
        ]
      -- ... sealed on the read path (sensitive + unextractable template).
      case getAttributes (osAttrs priv) [AttrPrivateExponent, AttrModulus] of
        PartialReads code results -> do
          assertEqual "seal code" CKR_ATTRIBUTE_SENSITIVE code
          assertEqual "private exponent sealed" (Just ResSensitive)
            (lookup AttrPrivateExponent results)
          assertEqual "modulus stays readable"
            (Just (ResOk (ValBytes n))) (lookup AttrModulus results)
      -- The generated pair really signs at the backend.
      case (keyBytesOf pub, keyBytesOf priv) of
        (Just pubB, Just privB) -> do
          sres <- sign env (SigRSA_PKCS1v15 D_SHA256) (KeyDer privB) "rsa-msg"
          sig <- case sres of
            EngineOk s -> pure s
            EngineFail err -> assertFailure ("synth sign failed: " ++ show err) >> undefined
          vres <- verify env (SigRSA_PKCS1v15 D_SHA256) (KeyDer pubB) "rsa-msg" sig
          case vres of
            EngineOk () -> pure ()
            EngineFail err -> assertFailure ("synth verify failed: " ++ show err)
        _ -> assertFailure "RSA halves lack material"
      closeBackend env
  where
    assertPresent attrs t = case Map.lookup t attrs of
      Just (ValBytes bs) | not (BS.null bs) -> pure ()
      other -> assertFailure ("missing component " ++ show t ++ ": " ++ show other)

caseRsaKeygenDistinct :: IO ()
caseRsaKeygenDistinct = withSynth $ \answer -> do
  m0 <- seedModel
  st <- getSession m0
  let gen m = case planGenerateKeyPair defaultRules m st rsaKeyPairGenMech rsaPubTmpl rsaPrivTmpl of
        KeyEffect pw fx -> do
          res <- answer m fx
          c <- finishCommit m st pw res 2
          h <- handleOf (pcOutputs c !! 0)
          m' <- expectRight (publishDelta m (pcDelta c))
          Just ost <- pure (resolveHandle m' h)
          case Map.lookup AttrModulus (osAttrs ost) of
            Just (ValBytes n) -> pure (m', n)
            other -> assertFailure ("modulus missing: " ++ show other) >> undefined
        other -> assertFailure ("RSA plan is not an effect: " ++ show other) >> undefined
  (m1, n1) <- gen m0
  (_, n2) <- gen m1
  assertBool "sequential pairs differ" (n1 /= n2)

caseRsaKeygenBounds :: IO ()
caseRsaKeygenBounds = do
  opened <- openBackend "11" :: IO (EngineResult (BackendEnv Synthetic))
  case opened of
    EngineFail err -> assertFailure ("synthetic open failed: " ++ show err)
    EngineOk env -> do
      ok <- generateKey env (GenRSA 2048 65537)
      case ok of
        EngineOk (KeyDer priv, Just (KeyDer pub)) -> do
          assertBool "priv DER nonempty" (not (BS.null priv))
          assertBool "pub DER nonempty" (not (BS.null pub))
          assertBool "halves differ" (priv /= pub)
        other -> assertFailure ("2048/65537 must mint: " ++ show other)
      badBits <- generateKey env (GenRSA 1024 65537)
      case badBits of
        EngineFail (BackendBadParam _ _) -> pure ()
        other -> assertFailure ("1024 bits must refuse: " ++ show other)
      evenE <- generateKey env (GenRSA 2048 4)
      case evenE of
        EngineFail (BackendBadParam _ _) -> pure ()
        other -> assertFailure ("even exponent must refuse: " ++ show other)
      closeBackend env

caseRsaExponentPlanner :: IO ()
caseRsaExponentPlanner = do
  m0 <- seedModel
  st <- getSession m0
  let argsOf pubT privT =
        case planGenerateKeyPair defaultRules m0 st rsaKeyPairGenMech pubT privT of
          KeyEffect _ (FxGenerateKey _ _ input) -> Right (decodeGenArgs input)
          KeyDenied (KeyDeny code _) -> Left code
          other -> error ("unexpected plan shape: " ++ show other)
      withExp tmpl e = tmpl ++ [(AttrPublicExponent, ValBytes e)]
  -- Absent on both sides: the 65537 default.
  assertEqual "default exponent" (Right (Just (GenRsa 2048 65537)))
    (argsOf rsaPubTmpl rsaPrivTmpl)
  -- Custom odd exponent carries into the effect args.
  assertEqual "custom exponent" (Right (Just (GenRsa 2048 257)))
    (argsOf (withExp rsaPubTmpl (BS.pack [1, 1])) rsaPrivTmpl)
  -- Private-side exponent alone also plans.
  assertEqual "private-side exponent" (Right (Just (GenRsa 2048 3)))
    (argsOf rsaPubTmpl (withExp rsaPrivTmpl (BS.pack [3])))
  -- Disagreement refuses.
  assertEqual "exponent disagreement" (Left CKR_TEMPLATE_INCONSISTENT)
    (argsOf (withExp rsaPubTmpl (BS.pack [1, 0, 1]))
      (withExp rsaPrivTmpl (BS.pack [3])))
  -- Even exponents refuse.
  assertEqual "even exponent" (Left CKR_TEMPLATE_INCONSISTENT)
    (argsOf (withExp rsaPubTmpl (BS.pack [4])) rsaPrivTmpl)
  -- Overlong exponents refuse.
  assertEqual "overlong exponent" (Left CKR_TEMPLATE_INCONSISTENT)
    (argsOf (withExp rsaPubTmpl (BS.replicate 9 1)) rsaPrivTmpl)

caseRsaStampMismatch :: IO ()
caseRsaStampMismatch = do
  m0 <- seedModel
  st <- getSession m0
  let n = BS.pack [1, 2, 3]
      n2 = BS.pack [4, 5, 6]
      e = BS.pack [1, 0, 1]
      tiny = BS.pack [7]
      pubM = rsaPublicDer n e
      privM = rsaPrivateDer n e tiny tiny tiny tiny tiny tiny
      privM2 = rsaPrivateDer n2 e tiny tiny tiny tiny tiny tiny
      pub = pendingFromAttrs st (Map.fromList rsaPubTmpl)
      priv = pendingFromAttrs st (Map.fromList rsaPrivTmpl)
  case stampPairComponents pub priv pubM privM of
    Just (pub', _) -> assertEqual "modulus stamped"
      (Just (ValBytes n)) (Map.lookup AttrModulus (poAttrs pub'))
    Nothing -> assertFailure "matching halves must stamp"
  assertEqual "mismatched halves refuse" Nothing
    (stampPairComponents pub priv pubM privM2)
  assertEqual "garbage refuses" Nothing
    (stampPairComponents pub priv "nope" "nope")
  -- Non-RSA, non-EC pairs pass through untouched.
  let ecPub = pendingFromAttrs st (Map.fromList ecPubTmpl)
      ecPriv = pendingFromAttrs st (Map.fromList ecPrivTmpl)
  assertEqual "EC opaque passthrough" (Just (ecPub, ecPriv))
    (stampPairComponents ecPub ecPriv "pub" "priv")

caseX942ParamSizesPlanner :: IO ()
caseX942ParamSizesPlanner = do
  m0 <- seedModel
  st <- getSession m0
  let argsOf tmpl =
        case planGenerateKey defaultRules m0 st x9_42DhParameterGenMech BS.empty tmpl of
          KeyEffect _ (FxGenerateKey _ _ input) -> Right (decodeGenArgs input)
          KeyDenied (KeyDeny code _) -> Left code
          other -> error ("unexpected plan shape: " ++ show other)
  -- Explicit served pairs plan (the DSA frame: the driver
  -- runs the DSA FIPS 186-4 entry point).
  assertEqual "explicit (1024, 160)" (Right (Just (GenDsaParams 1024 160)))
    (argsOf (x942ParamsTmpl 1024 160))
  assertEqual "explicit (2048, 224)" (Right (Just (GenDsaParams 2048 224)))
    (argsOf (x942ParamsTmpl 2048 224))
  assertEqual "explicit (2048, 256)" (Right (Just (GenDsaParams 2048 256)))
    (argsOf (x942ParamsTmpl 2048 256))
  -- A missing subprime is incomplete (the oracle requires it;
  -- DSA keeps the per-L default).
  assertEqual "missing subprime bits" (Left CKR_TEMPLATE_INCOMPLETE)
    (argsOf (filter ((/= AttrSubprimeBits) . fst) (x942ParamsTmpl 2048 256)))
  -- The oracle's minimal template (no class, no key type) plans.
  assertEqual "oracle minimal plans" (Right (Just (GenDsaParams 2048 256)))
    (argsOf [(AttrPrimeBits, ValULong 2048), (AttrSubprimeBits, ValULong 256),
             (AttrToken, ValBool False)])
  -- A DSA-typed template contradicts the mechanism.
  assertEqual "DSA key type refused" (Left CKR_TEMPLATE_INCONSISTENT)
    (argsOf (dsaParamsTmpl 1024))
  -- Missing prime bits are incomplete.
  assertEqual "missing prime bits" (Left CKR_TEMPLATE_INCOMPLETE)
    (argsOf [(AttrToken, ValBool False)])
  -- Unserved sizes and pairs are inconsistent.
  assertEqual "unserved L" (Left CKR_TEMPLATE_INCONSISTENT)
    (argsOf (x942ParamsTmpl 512 160))
  assertEqual "unserved pair" (Left CKR_TEMPLATE_INCONSISTENT)
    (argsOf (x942ParamsTmpl 2048 160))

caseDhPkcsParamSizesPlanner :: IO ()
caseDhPkcsParamSizesPlanner = do
  m0 <- seedModel
  st <- getSession m0
  let argsOf tmpl =
        case planGenerateKey defaultRules m0 st dhPkcsParameterGenMech BS.empty tmpl of
          KeyEffect _ (FxGenerateKey _ _ input) -> Right (decodeGenArgs input)
          KeyDenied (KeyDeny code _) -> Left code
          other -> error ("unexpected plan shape: " ++ show other)
  -- Explicit served pairs plan (the DSA frame: the driver
  -- runs the DSA FIPS 186-4 entry point, as for X9.42).
  assertEqual "explicit (1024, 160)" (Right (Just (GenDsaParams 1024 160)))
    (argsOf (dhPkcsParamsTmpl 1024 160))
  assertEqual "explicit (2048, 256)" (Right (Just (GenDsaParams 2048 256)))
    (argsOf (dhPkcsParamsTmpl 2048 256))
  -- A missing subprime defaults from L (the oracle sends
  -- CKA_PRIME_BITS only and expects CKR_OK — unlike X9.42,
  -- which requires the subprime).
  assertEqual "missing subprime defaults" (Right (Just (GenDsaParams 2048 256)))
    (argsOf (filter ((/= AttrSubprimeBits) . fst) (dhPkcsParamsTmpl 2048 256)))
  -- The oracle's minimal template (PRIME_BITS only) plans.
  assertEqual "oracle minimal plans" (Right (Just (GenDsaParams 2048 256)))
    (argsOf [(AttrPrimeBits, ValULong 2048), (AttrToken, ValBool False)])
  -- An X9.42-typed template contradicts the mechanism.
  assertEqual "X9.42 key type refused" (Left CKR_TEMPLATE_INCONSISTENT)
    (argsOf (x942ParamsTmpl 1024 160))
  -- Missing prime bits are incomplete.
  assertEqual "missing prime bits" (Left CKR_TEMPLATE_INCOMPLETE)
    (argsOf [(AttrToken, ValBool False)])
  -- Unserved sizes and pairs are inconsistent.
  assertEqual "unserved L" (Left CKR_TEMPLATE_INCONSISTENT)
    (argsOf (dhPkcsParamsTmpl 512 160))
  assertEqual "unserved pair" (Left CKR_TEMPLATE_INCONSISTENT)
    (argsOf (dhPkcsParamsTmpl 2048 160))

caseEcExtraBitsPlanner :: IO ()
caseEcExtraBitsPlanner = do
  m0 <- seedModel
  st <- getSession m0
  let argsOf mech = case planGenerateKeyPair defaultRules m0 st mech ecPubTmpl ecPrivTmpl of
        KeyEffect _ (FxGenerateKey _ _ input) -> Right (decodeGenArgs input)
        KeyDenied (KeyDeny code _) -> Left code
        other -> error ("unexpected plan shape: " ++ show other)
  -- The extra-bits mechanism plans exactly like plain EC keygen
  -- (the FIPS 186-5 B.4.2 method is unobservable from outside).
  assertEqual "extra-bits plans like EC"
    (argsOf ecKeyPairGenMech) (argsOf ecExtraBitsKeyPairGenMech)

caseDsaParamSizesPlanner :: IO ()
caseDsaParamSizesPlanner = do
  m0 <- seedModel
  st <- getSession m0
  let argsOf tmpl =
        case planGenerateKey defaultRules m0 st dsaParameterGenMech BS.empty tmpl of
          KeyEffect _ (FxGenerateKey _ _ input) -> Right (decodeGenArgs input)
          KeyDenied (KeyDeny code _) -> Left code
          other -> error ("unexpected plan shape: " ++ show other)
      withN tmpl n = tmpl ++ [(AttrSubprimeBits, ValULong n)]
  -- Served sizes plan with per-L subprime defaults.
  assertEqual "1024 defaults to 160" (Right (Just (GenDsaParams 1024 160)))
    (argsOf (dsaParamsTmpl 1024))
  assertEqual "2048 defaults to 256" (Right (Just (GenDsaParams 2048 256)))
    (argsOf (dsaParamsTmpl 2048))
  assertEqual "3072 defaults to 256" (Right (Just (GenDsaParams 3072 256)))
    (argsOf (dsaParamsTmpl 3072))
  -- Explicit served pairs plan.
  assertEqual "explicit (2048, 224)" (Right (Just (GenDsaParams 2048 224)))
    (argsOf (withN (dsaParamsTmpl 2048) 224))
  assertEqual "explicit (2048, 256)" (Right (Just (GenDsaParams 2048 256)))
    (argsOf (withN (dsaParamsTmpl 2048) 256))
  -- Missing prime bits are incomplete (oracle-pinned).
  assertEqual "missing prime bits" (Left CKR_TEMPLATE_INCOMPLETE)
    (argsOf [(AttrToken, ValBool False)])
  -- Unserved sizes and pairs are inconsistent.
  assertEqual "unserved L" (Left CKR_TEMPLATE_INCONSISTENT)
    (argsOf (dsaParamsTmpl 512))
  assertEqual "unserved pair" (Left CKR_TEMPLATE_INCONSISTENT)
    (argsOf (withN (dsaParamsTmpl 2048) 160))
  -- Malformed sizes are inconsistent.
  assertEqual "malformed prime bits" (Left CKR_TEMPLATE_INCONSISTENT)
    (argsOf ([(AttrPrimeBits, ValBool True), (AttrToken, ValBool False)]))

caseDsaDomainPlanner :: IO ()
caseDsaDomainPlanner = do
  m0 <- seedModel
  st <- getSession m0
  let argsOf pubT privT =
        case planGenerateKeyPair defaultRules m0 st dsaKeyPairGenMech pubT privT of
          KeyEffect _ (FxGenerateKey _ _ input) -> Right (decodeGenArgs input)
          KeyDenied (KeyDeny code _) -> Left code
          other -> error ("unexpected plan shape: " ++ show other)
      dropT t = filter ((/= t) . fst)
      withT tmpl t v = tmpl ++ [(t, v)]
  -- Happy path frames DER DSS-Parms.
  case argsOf dsaPubTmpl dsaPrivTmpl of
    Right (Just (GenDsaKeypair der)) ->
      assertEqual "DER round-trips" (Just (dsaP, dsaQ, dsaG)) (parseDsaParams der)
    other -> assertFailure ("DSA pair must plan: " ++ show other)
  -- Served size hints alongside the domain are accepted.
  case argsOf (withT dsaPubTmpl AttrPrimeBits (ValULong 2048)) dsaPrivTmpl of
    Right (Just (GenDsaKeypair _)) -> pure ()
    other -> assertFailure ("served size hint must plan: " ++ show other)
  -- Missing parameters are incomplete.
  assertEqual "missing base" (Left CKR_TEMPLATE_INCOMPLETE)
    (argsOf (dropT AttrBase dsaPubTmpl) dsaPrivTmpl)
  assertEqual "missing all" (Left CKR_TEMPLATE_INCOMPLETE)
    (argsOf [(AttrToken, ValBool False)] dsaPrivTmpl)
  -- The field-size probe shape (PRIME_BITS=(1<<32)+1024, no p/q/g)
  -- refuses inconsistent, never incomplete.
  assertEqual "oversized prime bits" (Left CKR_TEMPLATE_INCONSISTENT)
    (argsOf [(AttrPrimeBits, ValULong 4294968320), (AttrToken, ValBool False)]
      [(AttrToken, ValBool False)])
  assertEqual "unserved prime bits" (Left CKR_TEMPLATE_INCONSISTENT)
    (argsOf (withT dsaPubTmpl AttrPrimeBits (ValULong 512)) dsaPrivTmpl)
  assertEqual "unserved subprime bits" (Left CKR_TEMPLATE_INCONSISTENT)
    (argsOf (withT dsaPubTmpl AttrSubprimeBits (ValULong 128)) dsaPrivTmpl)
  -- Disagreement, empty, oversized and malformed parts refuse.
  assertEqual "domain disagreement" (Left CKR_TEMPLATE_INCONSISTENT)
    (argsOf dsaPubTmpl (withT dsaPrivTmpl AttrPrime (ValBytes "other")))
  assertEqual "empty prime" (Left CKR_TEMPLATE_INCONSISTENT)
    (argsOf (withT (dropT AttrPrime dsaPubTmpl) AttrPrime (ValBytes BS.empty)) dsaPrivTmpl)
  assertEqual "oversized prime" (Left CKR_TEMPLATE_INCONSISTENT)
    (argsOf (withT (dropT AttrPrime dsaPubTmpl) AttrPrime (ValBytes (BS.replicate 513 1))) dsaPrivTmpl)
  assertEqual "malformed prime" (Left CKR_TEMPLATE_INCONSISTENT)
    (argsOf (withT (dropT AttrPrime dsaPubTmpl) AttrPrime (ValULong 7)) dsaPrivTmpl)
  -- Private-side agreement plans.
  case argsOf dsaPubTmpl (dsaPrivTmpl ++
      [(AttrPrime, ValBytes dsaP), (AttrSubprime, ValBytes dsaQ), (AttrBase, ValBytes dsaG)]) of
    Right (Just (GenDsaKeypair _)) -> pure ()
    other -> assertFailure ("agreeing priv domain must plan: " ++ show other)

caseDsaGenArgsCodec :: IO ()
caseDsaGenArgsCodec = do
  let rt args = assertEqual ("round-trip " ++ show args) (Just args)
        (decodeGenArgs (encodeGenArgs args))
  rt (GenDsaParams 1024 160)
  rt (GenDsaParams 2048 224)
  rt (GenDsaParams 2048 256)
  rt (GenDsaParams 3072 256)
  rt (GenDsaKeypair (dsaParamsDer dsaP dsaQ dsaG))
  -- Tag bytes are pinned (5 sizes, 6 domain DER).
  assertEqual "params tag" (Just 5) (fst <$> BS.uncons (encodeGenArgs (GenDsaParams 2048 256)))
  assertEqual "keypair tag" (Just 6)
    (fst <$> BS.uncons (encodeGenArgs (GenDsaKeypair "d")))
  -- Short frames, trailing bytes, empty DER and unknown tags fail.
  assertEqual "short params" Nothing (decodeGenArgs (BS.pack [5, 8]))
  assertEqual "params trailing" Nothing
    (decodeGenArgs (encodeGenArgs (GenDsaParams 2048 256) <> "x"))
  assertEqual "short keypair" Nothing (decodeGenArgs (BS.pack [6, 0, 0]))
  assertEqual "keypair trailing" Nothing
    (decodeGenArgs (encodeGenArgs (GenDsaKeypair "der") <> "x"))
  assertEqual "empty keypair DER" Nothing
    (decodeGenArgs (BS.pack [6, 0, 0, 0, 0]))
  assertEqual "unknown tag" Nothing (decodeGenArgs (BS.pack [8, 1, 2, 3]))

caseDsaCompatible :: IO ()
caseDsaCompatible = do
  m0 <- seedModel
  st <- getSession m0
  let pub = pendingFromAttrs st (Map.fromList dsaPubTmpl)
      priv = pendingFromAttrs st (Map.fromList dsaPrivTmpl)
      params = pendingFromAttrs st (Map.fromList (dsaParamsTmpl 2048))
      fx args = FxGenerateKey dsaKeyPairGenMech BS.empty (encodeGenArgs args)
      fxP args = FxGenerateKey dsaParameterGenMech BS.empty (encodeGenArgs args)
      der = dsaParamsDer dsaP dsaQ dsaG
  assertBool "pair/keypair cohere"
    (keyPairCompatible (PwGeneratePair pub priv) (fx (GenDsaKeypair der)))
  assertBool "single/params cohere"
    (keyPairCompatible (PwGenerateKey params) (fxP (GenDsaParams 2048 256)))
  assertBool "pair/params incoherent"
    (not (keyPairCompatible (PwGeneratePair pub priv) (fxP (GenDsaParams 2048 256))))
  assertBool "single/keypair incoherent"
    (not (keyPairCompatible (PwGenerateKey params) (fx (GenDsaKeypair der))))
  -- Coherence is shape-level: any pair-shaped args cohere with a pair.
  assertBool "pair/RSA coherent"
    (keyPairCompatible (PwGeneratePair pub priv) (fx (GenRsa 2048 65537)))
  assertBool "pair/AES incoherent"
    (not (keyPairCompatible (PwGeneratePair pub priv) (fx (GenAes 16))))

caseDsaStamp :: IO ()
caseDsaStamp = do
  m0 <- seedModel
  st <- getSession m0
  let y = BS.pack (0x60 : replicate 127 4)
      x = BS.pack (0x07 : replicate 19 5)
      pubM = dsaPublicDer dsaP dsaQ dsaG y
      privM = dsaPrivateDer dsaP dsaQ dsaG x
      privM2 = dsaPrivateDer dsaQ dsaQ dsaG x
      pub = pendingFromAttrs st (Map.fromList dsaPubTmpl)
      priv = pendingFromAttrs st (Map.fromList dsaPrivTmpl)
  case stampPairComponents pub priv pubM privM of
    Just (pub', priv') -> do
      assertEqual "prime stamped"
        (Just (ValBytes dsaP)) (Map.lookup AttrPrime (poAttrs pub'))
      assertEqual "subprime stamped"
        (Just (ValBytes dsaQ)) (Map.lookup AttrSubprime (poAttrs pub'))
      assertEqual "base stamped"
        (Just (ValBytes dsaG)) (Map.lookup AttrBase (poAttrs pub'))
      assertEqual "priv inherits prime"
        (Just (ValBytes dsaP)) (Map.lookup AttrPrime (poAttrs priv'))
      assertEqual "priv inherits base"
        (Just (ValBytes dsaG)) (Map.lookup AttrBase (poAttrs priv'))
    Nothing -> assertFailure "matching DSA halves must stamp"
  -- Disagreeing and opaque halves pass through unstamped (EC mirror).
  assertEqual "mismatched halves pass through" (Just (pub, priv))
    (stampPairComponents pub priv pubM privM2)
  assertEqual "opaque halves pass through" (Just (pub, priv))
    (stampPairComponents pub priv "HKS1pub" "HKS1priv")
  -- Params objects stamp p/q/g plus true bit widths.
  let params = pendingFromAttrs st (Map.fromList (dsaParamsTmpl 1024))
      mat = dsaParamsDer dsaP dsaQ dsaG
  case stampParamsObject params mat of
    Just po' -> do
      assertEqual "params prime" (Just (ValBytes dsaP))
        (Map.lookup AttrPrime (poAttrs po'))
      assertEqual "params subprime" (Just (ValBytes dsaQ))
        (Map.lookup AttrSubprime (poAttrs po'))
      assertEqual "params base" (Just (ValBytes dsaG))
        (Map.lookup AttrBase (poAttrs po'))
      assertEqual "prime bits" (Just (ValULong 1024))
        (Map.lookup AttrPrimeBits (poAttrs po'))
      assertEqual "subprime bits" (Just (ValULong 160))
        (Map.lookup AttrSubprimeBits (poAttrs po'))
    Nothing -> assertFailure "DER params must stamp"
  assertEqual "opaque params pass through" (Just params)
    (stampParamsObject params "HKS1params")
  -- Non-params classes pass through untouched.
  let secret = pendingFromAttrs st (Map.fromList
        [(AttrClass, ValULong ckoSecretKey), (AttrToken, ValBool False)])
  assertEqual "secret untouched" (Just secret)
    (stampParamsObject secret mat)

caseDhDomainPlanner :: IO ()
caseDhDomainPlanner = do
  m0 <- seedModel
  st <- getSession m0
  let argsOf mech pubT privT =
        case planGenerateKeyPair defaultRules m0 st mech pubT privT of
          KeyEffect _ (FxGenerateKey _ _ input) -> Right (decodeGenArgs input)
          KeyDenied (KeyDeny code _) -> Left code
          other -> error ("unexpected plan shape: " ++ show other)
      dropT t = filter ((/= t) . fst)
      withT tmpl t v = tmpl ++ [(t, v)]
  -- Happy paths frame DER domain params (PKCS#3 without q,
  -- X9.42 with q).
  case argsOf dhKeyPairGenMech dhPubTmpl dhPrivTmpl of
    Right (Just (GenDhKeypair der)) ->
      assertEqual "PKCS#3 round-trips" (Just (dhP, dhG, Nothing)) (parseDhParams der)
    other -> assertFailure ("DH pair must plan: " ++ show other)
  case argsOf x9_42DhKeyPairGenMech dhX942PubTmpl dhX942PrivTmpl of
    Right (Just (GenDhKeypair der)) ->
      assertEqual "X9.42 round-trips" (Just (dhP, dhG, Just dhQ)) (parseDhParams der)
    other -> assertFailure ("X9.42 pair must plan: " ++ show other)
  -- Served size hints alongside the domain are accepted.
  case argsOf dhKeyPairGenMech (withT dhPubTmpl AttrPrimeBits (ValULong 2048)) dhPrivTmpl of
    Right (Just (GenDhKeypair _)) -> pure ()
    other -> assertFailure ("served size hint must plan: " ++ show other)
  -- Missing parameters are incomplete.
  assertEqual "missing base" (Left CKR_TEMPLATE_INCOMPLETE)
    (argsOf dhKeyPairGenMech (dropT AttrBase dhPubTmpl) dhPrivTmpl)
  assertEqual "missing all" (Left CKR_TEMPLATE_INCOMPLETE)
    (argsOf dhKeyPairGenMech [(AttrToken, ValBool False)] dhPrivTmpl)
  assertEqual "x942 missing subprime" (Left CKR_TEMPLATE_INCOMPLETE)
    (argsOf x9_42DhKeyPairGenMech (dropT AttrSubprime dhX942PubTmpl) dhX942PrivTmpl)
  -- The field-size probe shape refuses inconsistent, never incomplete.
  assertEqual "oversized prime bits" (Left CKR_TEMPLATE_INCONSISTENT)
    (argsOf dhKeyPairGenMech
      [(AttrPrimeBits, ValULong 4294968320), (AttrToken, ValBool False)]
      [(AttrToken, ValBool False)])
  assertEqual "unserved prime bits" (Left CKR_TEMPLATE_INCONSISTENT)
    (argsOf dhKeyPairGenMech (withT dhPubTmpl AttrPrimeBits (ValULong 512)) dhPrivTmpl)
  assertEqual "unserved subprime bits" (Left CKR_TEMPLATE_INCONSISTENT)
    (argsOf x9_42DhKeyPairGenMech
      (withT dhX942PubTmpl AttrSubprimeBits (ValULong 128)) dhX942PrivTmpl)
  -- PKCS#3 has no subprime: carrying one is inconsistent.
  assertEqual "pkcs rejects subprime" (Left CKR_TEMPLATE_INCONSISTENT)
    (argsOf dhKeyPairGenMech
      (withT dhPubTmpl AttrSubprime (ValBytes dhQ)) dhPrivTmpl)
  -- Crossed key types refuse.
  assertEqual "pkcs mech x942 templates" (Left CKR_TEMPLATE_INCONSISTENT)
    (argsOf dhKeyPairGenMech dhX942PubTmpl dhX942PrivTmpl)
  assertEqual "x942 mech pkcs templates" (Left CKR_TEMPLATE_INCONSISTENT)
    (argsOf x9_42DhKeyPairGenMech dhPubTmpl dhPrivTmpl)
  -- Disagreement, empty, oversized and malformed parts refuse.
  assertEqual "domain disagreement" (Left CKR_TEMPLATE_INCONSISTENT)
    (argsOf dhKeyPairGenMech dhPubTmpl (withT dhPrivTmpl AttrPrime (ValBytes "other")))
  assertEqual "empty prime" (Left CKR_TEMPLATE_INCONSISTENT)
    (argsOf dhKeyPairGenMech
      (withT (dropT AttrPrime dhPubTmpl) AttrPrime (ValBytes BS.empty)) dhPrivTmpl)
  assertEqual "oversized prime" (Left CKR_TEMPLATE_INCONSISTENT)
    (argsOf dhKeyPairGenMech
      (withT (dropT AttrPrime dhPubTmpl) AttrPrime (ValBytes (BS.replicate 513 1))) dhPrivTmpl)
  assertEqual "malformed prime" (Left CKR_TEMPLATE_INCONSISTENT)
    (argsOf dhKeyPairGenMech
      (withT (dropT AttrPrime dhPubTmpl) AttrPrime (ValULong 7)) dhPrivTmpl)
  -- Private-side agreement plans.
  case argsOf dhKeyPairGenMech dhPubTmpl (dhPrivTmpl ++
      [(AttrPrime, ValBytes dhP), (AttrBase, ValBytes dhG)]) of
    Right (Just (GenDhKeypair _)) -> pure ()
    other -> assertFailure ("agreeing priv domain must plan: " ++ show other)
  -- Structural floor (NIST SP 800-56A rev. 3 section 5.5.1;
  -- the security suite probes prime=1, tiny prime and
  -- generator=0): primes under 512 significant bits and
  -- generators outside 2..p-1 refuse inconsistent, never
  -- incomplete, and never plan.
  assertEqual "prime one" (Left CKR_TEMPLATE_INCONSISTENT)
    (argsOf dhKeyPairGenMech
      (withT (dropT AttrPrime dhPubTmpl) AttrPrime (ValBytes "\x01")) dhPrivTmpl)
  assertEqual "tiny prime" (Left CKR_TEMPLATE_INCONSISTENT)
    (argsOf dhKeyPairGenMech
      (withT (dropT AttrPrime dhPubTmpl) AttrPrime (ValBytes "\x0f")) dhPrivTmpl)
  assertEqual "zero generator" (Left CKR_TEMPLATE_INCONSISTENT)
    (argsOf dhKeyPairGenMech
      (withT (dropT AttrBase dhPubTmpl) AttrBase (ValBytes "\x00")) dhPrivTmpl)
  assertEqual "generator one" (Left CKR_TEMPLATE_INCONSISTENT)
    (argsOf dhKeyPairGenMech
      (withT (dropT AttrBase dhPubTmpl) AttrBase (ValBytes "\x01")) dhPrivTmpl)
  assertEqual "generator at prime" (Left CKR_TEMPLATE_INCONSISTENT)
    (argsOf dhKeyPairGenMech
      (withT (dropT AttrBase dhPubTmpl) AttrBase (ValBytes dhP)) dhPrivTmpl)
  assertEqual "short prime" (Left CKR_TEMPLATE_INCONSISTENT)
    (argsOf dhKeyPairGenMech
      (withT (dropT AttrPrime dhPubTmpl) AttrPrime
        (ValBytes (BS.pack (0x80 : replicate 62 1)))) dhPrivTmpl)
  assertEqual "zero-padded tiny prime" (Left CKR_TEMPLATE_INCONSISTENT)
    (argsOf dhKeyPairGenMech
      (withT (dropT AttrPrime dhPubTmpl) AttrPrime
        (ValBytes (BS.replicate 63 0 <> "\x0f"))) dhPrivTmpl)
  case argsOf dhKeyPairGenMech
      (withT (dropT AttrPrime dhPubTmpl) AttrPrime
        (ValBytes (BS.pack (0x80 : replicate 63 1)))) dhPrivTmpl of
    Right (Just (GenDhKeypair _)) -> pure ()
    other -> assertFailure ("512-bit floor prime must plan: " ++ show other)
  assertEqual "x942 generator above prime" (Left CKR_TEMPLATE_INCONSISTENT)
    (argsOf x9_42DhKeyPairGenMech
      (withT (dropT AttrBase dhX942PubTmpl) AttrBase (ValBytes (dhP <> "\x01")))
      dhX942PrivTmpl)
  assertEqual "x942 subprime one" (Left CKR_TEMPLATE_INCONSISTENT)
    (argsOf x9_42DhKeyPairGenMech
      (withT (dropT AttrSubprime dhX942PubTmpl) AttrSubprime (ValBytes "\x01"))
      dhX942PrivTmpl)

caseDhGenArgsCodec :: IO ()
caseDhGenArgsCodec = do
  let rt args = assertEqual ("round-trip " ++ show args) (Just args)
        (decodeGenArgs (encodeGenArgs args))
  rt (GenDhKeypair (dhParamsDer dhP dhG))
  rt (GenDhKeypair (dhParamsDerQ dhP dhG dhQ))
  -- Tag byte is pinned (10 DH keypair domain DER).
  assertEqual "keypair tag" (Just 10)
    (fst <$> BS.uncons (encodeGenArgs (GenDhKeypair "d")))
  -- Short frames, trailing bytes, empty DER and unknown tags fail.
  assertEqual "short keypair" Nothing (decodeGenArgs (BS.pack [10, 0, 0]))
  assertEqual "keypair trailing" Nothing
    (decodeGenArgs (encodeGenArgs (GenDhKeypair "der") <> "x"))
  assertEqual "empty keypair DER" Nothing
    (decodeGenArgs (BS.pack [10, 0, 0, 0, 0]))
  assertEqual "unknown tag" Nothing (decodeGenArgs (BS.pack [11, 1, 2, 3]))

caseDhCompatible :: IO ()
caseDhCompatible = do
  m0 <- seedModel
  st <- getSession m0
  let pub = pendingFromAttrs st (Map.fromList dhPubTmpl)
      priv = pendingFromAttrs st (Map.fromList dhPrivTmpl)
      params = pendingFromAttrs st (Map.fromList (dsaParamsTmpl 2048))
      fx args = FxGenerateKey dhKeyPairGenMech BS.empty (encodeGenArgs args)
      fxP args = FxGenerateKey dsaParameterGenMech BS.empty (encodeGenArgs args)
      der = dhParamsDer dhP dhG
  assertBool "pair/keypair cohere"
    (keyPairCompatible (PwGeneratePair pub priv) (fx (GenDhKeypair der)))
  assertBool "single/keypair incoherent"
    (not (keyPairCompatible (PwGenerateKey params) (fx (GenDhKeypair der))))
  assertBool "pair/params incoherent"
    (not (keyPairCompatible (PwGeneratePair pub priv) (fxP (GenDsaParams 2048 256))))

caseDhStamp :: IO ()
caseDhStamp = do
  m0 <- seedModel
  st <- getSession m0
  let y = BS.pack (0x60 : replicate 255 4)
      x = BS.pack (0x07 : replicate 31 5)
      pubM = dhPublicDer dhP dhG y
      privM = dhPrivateDer dhP dhG x
      privM2 = dhPrivateDer dhQ dhG x
      pubX = dhPublicDerQ dhP dhG dhQ y
      privX = dhPrivateDerQ dhP dhG dhQ x
      pub = pendingFromAttrs st (Map.fromList dhPubTmpl)
      priv = pendingFromAttrs st (Map.fromList dhPrivTmpl)
      pub9 = pendingFromAttrs st (Map.fromList dhX942PubTmpl)
      priv9 = pendingFromAttrs st (Map.fromList dhX942PrivTmpl)
  case stampPairComponents pub priv pubM privM of
    Just (pub', priv') -> do
      assertEqual "prime stamped"
        (Just (ValBytes dhP)) (Map.lookup AttrPrime (poAttrs pub'))
      assertEqual "base stamped"
        (Just (ValBytes dhG)) (Map.lookup AttrBase (poAttrs pub'))
      assertEqual "no subprime stamped"
        Nothing (Map.lookup AttrSubprime (poAttrs pub'))
      assertEqual "priv inherits prime"
        (Just (ValBytes dhP)) (Map.lookup AttrPrime (poAttrs priv'))
      assertEqual "priv inherits base"
        (Just (ValBytes dhG)) (Map.lookup AttrBase (poAttrs priv'))
    Nothing -> assertFailure "matching DH halves must stamp"
  case stampPairComponents pub9 priv9 pubX privX of
    Just (pub', _) ->
      assertEqual "x942 subprime stamped"
        (Just (ValBytes dhQ)) (Map.lookup AttrSubprime (poAttrs pub'))
    Nothing -> assertFailure "matching X9.42 halves must stamp"
  -- Disagreeing and opaque halves pass through unstamped.
  assertEqual "mismatched halves pass through" (Just (pub, priv))
    (stampPairComponents pub priv pubM privM2)
  assertEqual "opaque halves pass through" (Just (pub, priv))
    (stampPairComponents pub priv "HKS1pub" "HKS1priv")

caseEdwardsGenArgsCodec :: IO ()
caseEdwardsGenArgsCodec = do
  let rt args = assertEqual ("round-trip " ++ show args) (Just args)
        (decodeGenArgs (encodeGenArgs args))
  rt (GenEdwardsKeypair "Ed25519")
  rt (GenEdwardsKeypair "Ed448")
  -- Tag byte is pinned (7 Edwards keypair curve name).
  assertEqual "keypair tag" (Just 7)
    (fst <$> BS.uncons (encodeGenArgs (GenEdwardsKeypair "Ed25519")))
  -- Short frames and empty names fail.
  assertEqual "short keypair" Nothing (decodeGenArgs (BS.singleton 7))
  assertEqual "unknown tag" Nothing (decodeGenArgs (BS.pack [8, 1, 2, 3]))

caseEdwardsPairPlanner :: IO ()
caseEdwardsPairPlanner = do
  m0 <- seedModel
  st <- getSession m0
  let argsOf pubT privT =
        case planGenerateKeyPair defaultRules m0 st edwardsKeyPairGenMech pubT privT of
          KeyEffect _ (FxGenerateKey _ _ input) -> Right (decodeGenArgs input)
          KeyDenied (KeyDeny code _) -> Left code
          other -> error ("unexpected plan shape: " ++ show other)
      dropT t = filter ((/= t) . fst)
      withT tmpl t v = tmpl ++ [(t, v)]
      setParams tmpl curve =
        withT (dropT AttrEcParams tmpl) AttrEcParams (ValBytes curve)
  -- Happy path frames the curve name (both curves).
  case argsOf edPubTmpl edPrivTmpl of
    Right (Just (GenEdwardsKeypair "Ed25519")) -> pure ()
    other -> assertFailure ("Ed25519 pair must plan: " ++ show other)
  case argsOf (setParams edPubTmpl "Ed448") edPrivTmpl of
    Right (Just (GenEdwardsKeypair "Ed448")) -> pure ()
    other -> assertFailure ("Ed448 pair must plan: " ++ show other)
  -- Missing curve is incomplete.
  assertEqual "missing params" (Left CKR_TEMPLATE_INCOMPLETE)
    (argsOf (dropT AttrEcParams edPubTmpl) edPrivTmpl)
  assertEqual "missing all" (Left CKR_TEMPLATE_INCOMPLETE)
    (argsOf [(AttrToken, ValBool False)] edPrivTmpl)
  -- Foreign curves refuse mechanism-invalid (the EC precedent),
  -- never incomplete: the template names a curve the mechanism
  -- cannot serve.
  assertEqual "weierstrass refused" (Left CKR_MECHANISM_INVALID)
    (argsOf (setParams edPubTmpl "P-256") edPrivTmpl)
  assertEqual "garbage refused" (Left CKR_MECHANISM_INVALID)
    (argsOf (setParams edPubTmpl "nope") edPrivTmpl)
  -- Disagreement and malformed parts refuse inconsistent.
  assertEqual "curve disagreement" (Left CKR_TEMPLATE_INCONSISTENT)
    (argsOf edPubTmpl (withT edPrivTmpl AttrEcParams (ValBytes "Ed448")))
  assertEqual "malformed params" (Left CKR_TEMPLATE_INCONSISTENT)
    (argsOf (withT (dropT AttrEcParams edPubTmpl) AttrEcParams (ValULong 7)) edPrivTmpl)
  assertEqual "malformed priv params" (Left CKR_TEMPLATE_INCONSISTENT)
    (argsOf edPubTmpl (withT edPrivTmpl AttrEcParams (ValULong 7)))
  -- Private-side agreement plans; key-type contradiction refuses.
  case argsOf edPubTmpl (withT edPrivTmpl AttrEcParams (ValBytes "Ed25519")) of
    Right (Just (GenEdwardsKeypair "Ed25519")) -> pure ()
    other -> assertFailure ("agreeing priv curve must plan: " ++ show other)
  assertEqual "key-type contradiction" (Left CKR_TEMPLATE_INCONSISTENT)
    (argsOf (withT (dropT AttrKeyType edPubTmpl) AttrKeyType (ValULong ckkEc)) edPrivTmpl)

caseEdwardsCompatible :: IO ()
caseEdwardsCompatible = do
  m0 <- seedModel
  st <- getSession m0
  let pub = pendingFromAttrs st (Map.fromList edPubTmpl)
      priv = pendingFromAttrs st (Map.fromList edPrivTmpl)
      fx args = FxGenerateKey edwardsKeyPairGenMech BS.empty (encodeGenArgs args)
  assertBool "pair/edwards cohere"
    (keyPairCompatible (PwGeneratePair pub priv) (fx (GenEdwardsKeypair "Ed25519")))
  assertBool "single/edwards incoherent"
    (not (keyPairCompatible (PwGenerateKey pub) (fx (GenEdwardsKeypair "Ed25519"))))
  -- Coherence is shape-level: any pair-shaped args cohere with a pair.
  assertBool "pair/RSA coherent"
    (keyPairCompatible (PwGeneratePair pub priv) (fx (GenRsa 2048 65537)))
  assertBool "pair/AES incoherent"
    (not (keyPairCompatible (PwGeneratePair pub priv) (fx (GenAes 16))))

caseEdwardsStamp :: IO ()
caseEdwardsStamp = do
  m0 <- seedModel
  st <- getSession m0
  let pubM = eddsaPublicDer ed19OidBytes edPoint19
      privM = eddsaPrivateDer ed19OidBytes edSeed19
      privM48 = eddsaPrivateDer ed48OidBytes (BS.replicate 57 9)
      pub = pendingFromAttrs st (Map.fromList edPubTmpl)
      priv = pendingFromAttrs st (Map.fromList edPrivTmpl)
  case stampPairComponents pub priv pubM privM of
    Just (pub', priv') -> do
      assertEqual "point stamped raw"
        (Just (ValBytes edPoint19)) (Map.lookup AttrEcPoint (poAttrs pub'))
      assertEqual "pub params kept"
        (Just (ValBytes "Ed25519")) (Map.lookup AttrEcParams (poAttrs pub'))
      assertEqual "priv inherits params"
        (Just (ValBytes "Ed25519")) (Map.lookup AttrEcParams (poAttrs priv'))
    Nothing -> assertFailure "matching Edwards halves must stamp"
  -- Disagreeing and opaque halves pass through unstamped (EC mirror).
  assertEqual "mismatched halves pass through" (Just (pub, priv))
    (stampPairComponents pub priv pubM privM48)
  assertEqual "opaque halves pass through" (Just (pub, priv))
    (stampPairComponents pub priv "HKS1pub" "HKS1priv")

caseMontgomeryGenArgsCodec :: IO ()
caseMontgomeryGenArgsCodec = do
  let rt args = assertEqual ("round-trip " ++ show args) (Just args)
        (decodeGenArgs (encodeGenArgs args))
  rt (GenMontgomeryKeypair "X25519")
  rt (GenMontgomeryKeypair "X448")
  -- Tag byte is pinned (15 Montgomery keypair curve name).
  assertEqual "keypair tag" (Just 15)
    (fst <$> BS.uncons (encodeGenArgs (GenMontgomeryKeypair "X25519")))
  -- Short frames and empty names fail.
  assertEqual "short keypair" Nothing (decodeGenArgs (BS.singleton 15))
  assertEqual "unknown tag" Nothing (decodeGenArgs (BS.pack [16, 1, 2, 3]))

caseMontgomeryPairPlanner :: IO ()
caseMontgomeryPairPlanner = do
  m0 <- seedModel
  st <- getSession m0
  let argsOf pubT privT =
        case planGenerateKeyPair defaultRules m0 st montgomeryKeyPairGenMech pubT privT of
          KeyEffect _ (FxGenerateKey _ _ input) -> Right (decodeGenArgs input)
          KeyDenied (KeyDeny code _) -> Left code
          other -> error ("unexpected plan shape: " ++ show other)
      dropT t = filter ((/= t) . fst)
      withT tmpl t v = tmpl ++ [(t, v)]
      setParams tmpl curve =
        withT (dropT AttrEcParams tmpl) AttrEcParams (ValBytes curve)
  -- Happy path frames the curve name (both curves).
  case argsOf xdPubTmpl xdPrivTmpl of
    Right (Just (GenMontgomeryKeypair "X25519")) -> pure ()
    other -> assertFailure ("X25519 pair must plan: " ++ show other)
  case argsOf (setParams xdPubTmpl "X448") xdPrivTmpl of
    Right (Just (GenMontgomeryKeypair "X448")) -> pure ()
    other -> assertFailure ("X448 pair must plan: " ++ show other)
  -- Missing curve is incomplete.
  assertEqual "missing params" (Left CKR_TEMPLATE_INCOMPLETE)
    (argsOf (dropT AttrEcParams xdPubTmpl) xdPrivTmpl)
  assertEqual "missing all" (Left CKR_TEMPLATE_INCOMPLETE)
    (argsOf [(AttrToken, ValBool False)] xdPrivTmpl)
  -- Foreign curves refuse mechanism-invalid (the Edwards
  -- precedent), never incomplete: the template names a curve
  -- the mechanism cannot serve.
  assertEqual "weierstrass refused" (Left CKR_MECHANISM_INVALID)
    (argsOf (setParams xdPubTmpl "P-256") xdPrivTmpl)
  assertEqual "edwards refused" (Left CKR_MECHANISM_INVALID)
    (argsOf (setParams xdPubTmpl "Ed25519") xdPrivTmpl)
  assertEqual "garbage refused" (Left CKR_MECHANISM_INVALID)
    (argsOf (setParams xdPubTmpl "nope") xdPrivTmpl)
  -- Disagreement and malformed parts refuse inconsistent.
  assertEqual "curve disagreement" (Left CKR_TEMPLATE_INCONSISTENT)
    (argsOf xdPubTmpl (withT xdPrivTmpl AttrEcParams (ValBytes "X448")))
  assertEqual "malformed params" (Left CKR_TEMPLATE_INCONSISTENT)
    (argsOf (withT (dropT AttrEcParams xdPubTmpl) AttrEcParams (ValULong 7)) xdPrivTmpl)
  assertEqual "malformed priv params" (Left CKR_TEMPLATE_INCONSISTENT)
    (argsOf xdPubTmpl (withT xdPrivTmpl AttrEcParams (ValULong 7)))
  -- Private-side agreement plans; key-type contradiction refuses.
  case argsOf xdPubTmpl (withT xdPrivTmpl AttrEcParams (ValBytes "X25519")) of
    Right (Just (GenMontgomeryKeypair "X25519")) -> pure ()
    other -> assertFailure ("agreeing priv curve must plan: " ++ show other)
  assertEqual "key-type contradiction" (Left CKR_TEMPLATE_INCONSISTENT)
    (argsOf (withT (dropT AttrKeyType xdPubTmpl) AttrKeyType (ValULong ckkEc)) xdPrivTmpl)

caseMontgomeryCompatible :: IO ()
caseMontgomeryCompatible = do
  m0 <- seedModel
  st <- getSession m0
  let pub = pendingFromAttrs st (Map.fromList xdPubTmpl)
      priv = pendingFromAttrs st (Map.fromList xdPrivTmpl)
      fx args = FxGenerateKey montgomeryKeyPairGenMech BS.empty (encodeGenArgs args)
  assertBool "pair/montgomery cohere"
    (keyPairCompatible (PwGeneratePair pub priv) (fx (GenMontgomeryKeypair "X25519")))
  assertBool "single/montgomery incoherent"
    (not (keyPairCompatible (PwGenerateKey pub) (fx (GenMontgomeryKeypair "X25519"))))
  -- Coherence is shape-level: any pair-shaped args cohere with a pair.
  assertBool "pair/RSA coherent"
    (keyPairCompatible (PwGeneratePair pub priv) (fx (GenRsa 2048 65537)))
  assertBool "pair/AES incoherent"
    (not (keyPairCompatible (PwGeneratePair pub priv) (fx (GenAes 16))))

caseMontgomeryStamp :: IO ()
caseMontgomeryStamp = do
  m0 <- seedModel
  st <- getSession m0
  let pubM = montgomeryPublicDer x19OidBytes xPoint19
      privM = montgomeryPrivateDer x19OidBytes xScalar19
      privM48 = montgomeryPrivateDer x48OidBytes (BS.replicate 56 9)
      pub = pendingFromAttrs st (Map.fromList xdPubTmpl)
      priv = pendingFromAttrs st (Map.fromList xdPrivTmpl)
  case stampPairComponents pub priv pubM privM of
    Just (pub', priv') -> do
      assertEqual "point stamped raw"
        (Just (ValBytes xPoint19)) (Map.lookup AttrEcPoint (poAttrs pub'))
      assertEqual "pub params kept"
        (Just (ValBytes "X25519")) (Map.lookup AttrEcParams (poAttrs pub'))
      assertEqual "priv inherits params"
        (Just (ValBytes "X25519")) (Map.lookup AttrEcParams (poAttrs priv'))
    Nothing -> assertFailure "matching Montgomery halves must stamp"
  -- Disagreeing and opaque halves pass through unstamped (EC mirror).
  assertEqual "mismatched halves pass through" (Just (pub, priv))
    (stampPairComponents pub priv pubM privM48)
  assertEqual "opaque halves pass through" (Just (pub, priv))
    (stampPairComponents pub priv "HKS1pub" "HKS1priv")

caseKeygenUsageDefaults :: IO ()
caseKeygenUsageDefaults = do
  -- Minimal templates (the oracle's DSA leg shape: p/q/g only, empty
  -- private side) mint keys whose absent usage flags read TRUE,
  -- scoped by class: public keys default the public operations,
  -- private keys the full set, domain parameters none.
  let minimal =
        [ (AttrClass, ValULong ckoPublicKey)
        , (AttrPrime, ValBytes dsaP)
        , (AttrSubprime, ValBytes dsaQ)
        , (AttrBase, ValBytes dsaG)
        ]
  case checkKeyTemplate ckoPublicKey ckkDsa minimal of
    Right attrs -> do
      mapM_
        (\t -> assertEqual ("pub default " ++ show t) (Just (ValBool True))
          (Map.lookup t attrs))
        [AttrEncrypt, AttrVerify, AttrWrap, AttrEncapsulate]
      mapM_
        (\t -> assertEqual ("pub skips " ++ show t) Nothing
          (Map.lookup t attrs))
        [AttrDecrypt, AttrSign, AttrUnwrap, AttrDerive, AttrDecapsulate]
    Left deny -> assertFailure ("minimal template must check: " ++ show deny)
  case checkKeyTemplate ckoPrivateKey ckkDsa [(AttrClass, ValULong ckoPrivateKey)] of
    Right attrs -> mapM_
      (\t -> assertEqual ("priv default " ++ show t) (Just (ValBool True))
        (Map.lookup t attrs))
      [ AttrEncrypt, AttrDecrypt, AttrSign, AttrVerify
      , AttrWrap, AttrUnwrap, AttrDerive
      , AttrEncapsulate, AttrDecapsulate
      ]
    Left deny -> assertFailure ("empty priv template must check: " ++ show deny)
  case checkKeyTemplate ckoDomainParameters ckkDsa
      [(AttrClass, ValULong ckoDomainParameters), (AttrPrimeBits, ValULong 1024)] of
    Right attrs -> mapM_
      (\t -> assertEqual ("params skip " ++ show t) Nothing
        (Map.lookup t attrs))
      [AttrEncrypt, AttrSign, AttrVerify, AttrDerive]
    Left deny -> assertFailure ("params template must check: " ++ show deny)
  -- Explicit values win, including FALSE (refusal tests unaffected).
  case checkKeyTemplate ckoPrivateKey ckkDsa
      [(AttrSign, ValBool False), (AttrToken, ValBool False)] of
    Right attrs -> do
      assertEqual "explicit false kept" (Just (ValBool False))
        (Map.lookup AttrSign attrs)
      assertEqual "sibling defaulted" (Just (ValBool True))
        (Map.lookup AttrVerify attrs)
    Left deny -> assertFailure ("explicit template must check: " ++ show deny)
  -- A minimal pair plans and carries usable permits end to end.
  m0 <- seedModel
  st <- getSession m0
  case planGenerateKeyPair defaultRules m0 st dsaKeyPairGenMech minimal [] of
    KeyEffect (PwGeneratePair pub priv) _ -> do
      assertEqual "pub verify default" (Just (ValBool True))
        (Map.lookup AttrVerify (poAttrs pub))
      assertEqual "priv sign default" (Just (ValBool True))
        (Map.lookup AttrSign (poAttrs priv))
    other -> assertFailure ("minimal pair must plan: " ++ show other)
  -- Rule-forbidden flags stay absent (AES secrets forbid the
  -- encapsulate pair; a defaulted forbidden flag would poison
  -- detached rejoin, which replays stored templates).
  case checkKeyTemplate ckoSecretKey ckkAes [(AttrValueLen, ValULong 16)] of
    Right attrs -> do
      assertEqual "aes encrypt default" (Just (ValBool True))
        (Map.lookup AttrEncrypt attrs)
      assertEqual "encapsulate stays absent" Nothing
        (Map.lookup AttrEncapsulate attrs)
      assertEqual "decapsulate stays absent" Nothing
        (Map.lookup AttrDecapsulate attrs)
    Left deny -> assertFailure ("minimal AES template must check: " ++ show deny)

caseEcPointStamped :: IO ()
caseEcPointStamped = do
  m0 <- seedModel
  st <- getSession m0
  let p256oid = hex "06082a8648ce3d030107"
      point = BS.pack (0x04 : [1 .. 64])
      spki = ecPublicDer p256oid point
      ecPub = pendingFromAttrs st (Map.fromList ecPubTmpl)
      ecPriv = pendingFromAttrs st (Map.fromList ecPrivTmpl)
  -- A parseable EC SPKI stamps CKA_EC_POINT (DER OCTET STRING
  -- of the uncompressed point) on the public half; the private
  -- half is untouched.
  case stampPairComponents ecPub ecPriv spki "opaque-priv" of
    Just (pub', priv') -> do
      -- CKA_EC_POINT is the DER OCTET STRING of the point
      -- (0x04 0x41 header over the 65 uncompressed bytes).
      assertEqual "EC_POINT stamped"
        (Just (ValBytes ("\x04\x41" <> point))) (Map.lookup AttrEcPoint (poAttrs pub'))
      assertEqual "priv untouched" (poAttrs ecPriv) (poAttrs priv')
    Nothing -> assertFailure "EC SPKI halves must stamp"
  -- Opaque halves (synthetic HKS1 frames) pass through: no
  -- EC_POINT, no rejection.
  assertEqual "opaque passthrough" (Just (ecPub, ecPriv))
    (stampPairComponents ecPub ecPriv "pub" "priv")

caseWrapRoundtrip :: IO ()
caseWrapRoundtrip = withSynth $ \answer -> do
  m0 <- seedModel >>= loginUser
  st <- getSession m0
  (m1, wrapH) <- genAesKey answer m0 st wrapKeyTmpl
  (m2, targetH) <- genAesKey answer m1 st (aesTmpl 16)
  Just target <- pure (resolveHandle m2 targetH)
  Just targetMat <- pure (keyBytesOf target)
  -- Length query first: padded length, no effect planned.
  case planWrapKey m2 st aesCbcMech iv16 wrapH targetH IntentNull of
    KeyImmediate (Immediate c) -> do
      assertEqual "wrap query length"
        [NativeOutput (RegionBytes "wrapped" IntentNull) (encodeValue (ValULong 32))]
        (pcOutputs c)
      assertEqual "query publishes nothing" (StateDelta []) (pcDelta c)
    other -> assertFailure ("wrap query is not an Immediate commit: " ++ show other)
  -- Wrap for real.
  blob <- case planWrapKey m2 st aesCbcMech iv16 wrapH targetH (IntentBuffer 32) of
    KeyEffect pw fx -> do
      res <- answer m2 fx
      case finishWork m2 st pw res of
        Immediate c -> do
          assertEqual "wrap publishes nothing" (StateDelta []) (pcDelta c)
          case pcOutputs c of
            [NativeOutput (RegionBytes "wrapped" _) bs] -> pure bs
            o -> assertFailure ("wrap outputs one blob, got: " ++ show o) >> undefined
        other -> assertFailure ("wrap finish must commit, got: " ++ show other) >> undefined
    other -> assertFailure ("wrap plan is not an effect: " ++ show other) >> undefined
  assertEqual "wrapped length" 32 (BS.length blob)
  assertBool "blob differs from plaintext" (blob /= targetMat)
  -- Unwrap under a fresh template: material back, attributes landed.
  let tmpl =
        [ (AttrClass, ValULong ckoSecretKey)
        , (AttrKeyType, ValULong ckkAes)
        , (AttrToken, ValBool False)
        , (AttrLabel, ValBytes "unwrapped")
        , (AttrEncrypt, ValBool True)
        ]
  case planUnwrapKey defaultRules m2 st aesCbcMech iv16 wrapH blob tmpl of
    KeyEffect pw fx -> do
      res <- answer m2 fx
      c <- finishCommit m2 st pw res 1
      h <- handleOf (pcOutputs c !! 0)
      m3 <- expectRight (publishDelta m2 (pcDelta c))
      Just ost <- pure (resolveHandle m3 h)
      assertEqual "unwrapped material" (Just targetMat) (keyBytesOf ost)
      assertEqual "label landed"
        (Just (ValBytes "unwrapped")) (Map.lookup AttrLabel (osAttrs ost))
      assertEqual "usage landed" (Just (ValBool True)) (Map.lookup AttrEncrypt (osAttrs ost))
    other -> assertFailure ("unwrap plan is not an effect: " ++ show other)

-- | Extractable generic-secret template with caller-chosen length
-- (ragged wrap targets the AES keygen bounds cannot mint).
secretTmplN :: Int -> [(AttributeType, AttributeValue)]
secretTmplN n =
  [ (AttrClass, ValULong ckoSecretKey)
  , (AttrKeyType, ValULong ckkGenericSecret)
  , (AttrValueLen, ValULong (fromIntegral n))
  , (AttrToken, ValBool False)
  , (AttrPrivate, ValBool True)
  , (AttrSensitive, ValBool True)
  , (AttrExtractable, ValBool True)
  ]

caseAesKwWrapRoundtrip :: IO ()
caseAesKwWrapRoundtrip = withSynth $ \answer -> do
  m0 <- seedModel >>= loginUser
  st <- getSession m0
  (m1, wrapH) <- genAesKey answer m0 st wrapKeyTmpl
  (m2, targetH) <- genAesKey answer m1 st (aesTmpl 16)
  Just target <- pure (resolveHandle m2 targetH)
  Just targetMat <- pure (keyBytesOf target)
  -- Length query first: 16 + 8 expansion, no effect planned.
  case planWrapKey m2 st aesKwMech BS.empty wrapH targetH IntentNull of
    KeyImmediate (Immediate c) -> do
      assertEqual "kw query length"
        [NativeOutput (RegionBytes "wrapped" IntentNull) (encodeValue (ValULong 24))]
        (pcOutputs c)
      assertEqual "query publishes nothing" (StateDelta []) (pcDelta c)
    other -> assertFailure ("kw query is not an Immediate commit: " ++ show other)
  -- Short buffer refuses with the predicted length.
  case planWrapKey m2 st aesKwMech BS.empty wrapH targetH (IntentBuffer 23) of
    KeyImmediate (Reject r) -> do
      assertEqual "short buffer code" CKR_BUFFER_TOO_SMALL (rejCode r)
      assertEqual "short buffer length"
        [NativeOutput (RegionBytes "wrapped" (IntentBuffer 23)) (encodeValue (ValULong 24))]
        (rejOutputs r)
    other -> assertFailure ("kw short buffer is not a Reject: " ++ show other)
  -- Non-empty parameters refuse (KW takes empty params like ECB).
  case planWrapKey m2 st aesKwMech iv16 wrapH targetH IntentNull of
    KeyDenied d -> assertEqual "params code" CKR_ARGUMENTS_BAD (kdCode d)
    other -> assertFailure ("kw params accepted, got: " ++ show other)
  -- Wrap for real.
  blob <- case planWrapKey m2 st aesKwMech BS.empty wrapH targetH (IntentBuffer 24) of
    KeyEffect pw fx -> do
      res <- answer m2 fx
      case finishWork m2 st pw res of
        Immediate c -> do
          assertEqual "wrap publishes nothing" (StateDelta []) (pcDelta c)
          case pcOutputs c of
            [NativeOutput (RegionBytes "wrapped" _) bs] -> pure bs
            o -> assertFailure ("wrap outputs one blob, got: " ++ show o) >> undefined
        other -> assertFailure ("wrap finish must commit, got: " ++ show other) >> undefined
    other -> assertFailure ("kw plan is not an effect: " ++ show other) >> undefined
  assertEqual "wrapped length" 24 (BS.length blob)
  assertBool "blob differs from plaintext" (blob /= targetMat)
  -- Unwrap under a fresh template: material back.
  let tmpl =
        [ (AttrClass, ValULong ckoSecretKey)
        , (AttrKeyType, ValULong ckkAes)
        , (AttrToken, ValBool False)
        , (AttrLabel, ValBytes "unwrapped-kw")
        ]
  case planUnwrapKey defaultRules m2 st aesKwMech BS.empty wrapH blob tmpl of
    KeyEffect pw fx -> do
      res <- answer m2 fx
      c <- finishCommit m2 st pw res 1
      h <- handleOf (pcOutputs c !! 0)
      m3 <- expectRight (publishDelta m2 (pcDelta c))
      Just ost <- pure (resolveHandle m3 h)
      assertEqual "unwrapped material" (Just targetMat) (keyBytesOf ost)
    other -> assertFailure ("kw unwrap plan is not an effect: " ++ show other)
  -- An 8-byte target is below the KW floor (generic secret mints
  -- what AES keygen bounds forbid).
  (m4, shortH) <- genKeyWith answer m2 st genericSecretKeyGenMech (secretTmplN 8)
  case planWrapKey m4 st aesKwMech BS.empty wrapH shortH IntentNull of
    KeyDenied d -> assertEqual "floor code" CKR_DATA_LEN_RANGE (kdCode d)
    other -> assertFailure ("short target accepted, got: " ++ show other)
  -- A 16-byte blob cannot be a KW wrap (minimum 24).
  case planUnwrapKey defaultRules m2 st aesKwMech BS.empty wrapH (BS.replicate 16 0) tmpl of
    KeyDenied d -> assertEqual "blob code" CKR_ARGUMENTS_BAD (kdCode d)
    other -> assertFailure ("short blob accepted, got: " ++ show other)

caseAesKwpWrapRoundtrip :: IO ()
caseAesKwpWrapRoundtrip = withSynth $ \answer -> do
  m0 <- seedModel >>= loginUser
  st <- getSession m0
  (m1, wrapH) <- genAesKey answer m0 st wrapKeyTmpl
  (m2, targetH) <- genKeyWith answer m1 st genericSecretKeyGenMech (secretTmplN 20)
  Just target <- pure (resolveHandle m2 targetH)
  Just targetMat <- pure (keyBytesOf target)
  assertEqual "target length" 20 (BS.length targetMat)
  -- Length query: ceil8(20) + 8 = 32, no effect planned.
  case planWrapKey m2 st aesKwpMech BS.empty wrapH targetH IntentNull of
    KeyImmediate (Immediate c) ->
      assertEqual "kwp query length"
        [NativeOutput (RegionBytes "wrapped" IntentNull) (encodeValue (ValULong 32))]
        (pcOutputs c)
    other -> assertFailure ("kwp query is not an Immediate commit: " ++ show other)
  -- Wrap under the PAD alias, unwrap under KWP: the equation holds
  -- end to end (same RFC 5649 construction).
  blob <- case planWrapKey m2 st aesKwPadMech BS.empty wrapH targetH (IntentBuffer 32) of
    KeyEffect pw fx -> do
      res <- answer m2 fx
      case finishWork m2 st pw res of
        Immediate c -> case pcOutputs c of
          [NativeOutput (RegionBytes "wrapped" _) bs] -> pure bs
          o -> assertFailure ("wrap outputs one blob, got: " ++ show o) >> undefined
        other -> assertFailure ("wrap finish must commit, got: " ++ show other) >> undefined
    other -> assertFailure ("pad plan is not an effect: " ++ show other) >> undefined
  assertEqual "wrapped length" 32 (BS.length blob)
  let tmpl =
        [ (AttrClass, ValULong ckoSecretKey)
        , (AttrKeyType, ValULong ckkGenericSecret)
        , (AttrToken, ValBool False)
        ]
  case planUnwrapKey defaultRules m2 st aesKwpMech BS.empty wrapH blob tmpl of
    KeyEffect pw fx -> do
      res <- answer m2 fx
      c <- finishCommit m2 st pw res 1
      h <- handleOf (pcOutputs c !! 0)
      m3 <- expectRight (publishDelta m2 (pcDelta c))
      Just ost <- pure (resolveHandle m3 h)
      assertEqual "unwrapped material" (Just targetMat) (keyBytesOf ost)
    other -> assertFailure ("kwp unwrap plan is not an effect: " ++ show other)
  -- A 10-byte blob is not KWP framing (multiple of 8, >= 16).
  case planUnwrapKey defaultRules m2 st aesKwpMech BS.empty wrapH (BS.replicate 10 0) tmpl of
    KeyDenied d -> assertEqual "blob code" CKR_ARGUMENTS_BAD (kdCode d)
    other -> assertFailure ("ragged blob accepted, got: " ++ show other)

-- | KW-PKCS7 pads the target to the 8-byte quantum (always
-- padding) and wraps with RFC 3394 under the default AIV or a
-- caller 8-byte IV: a 20-byte target queries 32 (24 padded + 8),
-- wraps/unwraps end to end under the same IV, and fails closed
-- (reject, nothing published) under the wrong IV.
caseAesKwPkcs7WrapRoundtrip :: IO ()
caseAesKwPkcs7WrapRoundtrip = withSynth $ \answer -> do
  m0 <- seedModel >>= loginUser
  st <- getSession m0
  (m1, wrapH) <- genAesKey answer m0 st wrapKeyTmpl
  (m2, targetH) <- genKeyWith answer m1 st genericSecretKeyGenMech (secretTmplN 20)
  Just target <- pure (resolveHandle m2 targetH)
  Just targetMat <- pure (keyBytesOf target)
  assertEqual "target length" 20 (BS.length targetMat)
  let iv8 = BS.pack [0xde, 0xad, 0xbe, 0xef, 0x00, 0x11, 0x22, 0x33]
      queryLen params = case planWrapKey m2 st aesKwp7Mech params wrapH targetH IntentNull of
        KeyImmediate (Immediate c) -> pure (pcOutputs c)
        other -> assertFailure ("pkcs7 query is not an Immediate commit: " ++ show other) >> undefined
  -- Length query: pad 20 -> 24, + 8 wrap = 32 (same under
  -- either IV: the IV is not part of the blob).
  assertEqual "pkcs7 query length default iv"
    [NativeOutput (RegionBytes "wrapped" IntentNull) (encodeValue (ValULong 32))]
    =<< queryLen BS.empty
  assertEqual "pkcs7 query length caller iv"
    [NativeOutput (RegionBytes "wrapped" IntentNull) (encodeValue (ValULong 32))]
    =<< queryLen iv8
  -- A 4-byte IV is neither empty nor 8: refused.
  case planWrapKey m2 st aesKwp7Mech (BS.replicate 4 0) wrapH targetH IntentNull of
    KeyDenied d -> assertEqual "iv code" CKR_ARGUMENTS_BAD (kdCode d)
    other -> assertFailure ("ragged iv accepted, got: " ++ show other)
  -- Wrap under the caller IV, unwrap under the same IV.
  blob <- case planWrapKey m2 st aesKwp7Mech iv8 wrapH targetH (IntentBuffer 32) of
    KeyEffect pw fx -> do
      res <- answer m2 fx
      case finishWork m2 st pw res of
        Immediate c -> case pcOutputs c of
          [NativeOutput (RegionBytes "wrapped" _) bs] -> pure bs
          o -> assertFailure ("wrap outputs one blob, got: " ++ show o) >> undefined
        other -> assertFailure ("wrap finish must commit, got: " ++ show other) >> undefined
    other -> assertFailure ("pkcs7 plan is not an effect: " ++ show other) >> undefined
  assertEqual "wrapped length" 32 (BS.length blob)
  let tmpl =
        [ (AttrClass, ValULong ckoSecretKey)
        , (AttrKeyType, ValULong ckkGenericSecret)
        , (AttrToken, ValBool False)
        ]
  case planUnwrapKey defaultRules m2 st aesKwp7Mech iv8 wrapH blob tmpl of
    KeyEffect pw fx -> do
      res <- answer m2 fx
      c <- finishCommit m2 st pw res 1
      h <- handleOf (pcOutputs c !! 0)
      m3 <- expectRight (publishDelta m2 (pcDelta c))
      Just ost <- pure (resolveHandle m3 h)
      assertEqual "unwrapped material" (Just targetMat) (keyBytesOf ost)
    other -> assertFailure ("pkcs7 unwrap plan is not an effect: " ++ show other)
  -- Unwrap under the WRONG (empty) IV plans, then the driver
  -- answers AuthFailed and the finish rejects with nothing
  -- published (fail closed, never wrong plaintext).
  case planUnwrapKey defaultRules m2 st aesKwp7Mech BS.empty wrapH blob tmpl of
    KeyEffect pw fx -> do
      res <- answer m2 fx
      case finishWork m2 st pw res of
        Reject r -> assertEqual "wrong iv publishes nothing" (StateDelta []) (rejDelta r)
        other -> assertFailure ("wrong-iv unwrap committed, got: " ++ show other)
    other -> assertFailure ("wrong-iv unwrap plan is not an effect: " ++ show other)
  -- A 7-byte target is below the floor (pads to 8 < 16).
  (m4, shortH) <- genKeyWith answer m2 st genericSecretKeyGenMech (secretTmplN 7)
  case planWrapKey m4 st aesKwp7Mech BS.empty wrapH shortH IntentNull of
    KeyDenied d -> assertEqual "floor code" CKR_DATA_LEN_RANGE (kdCode d)
    other -> assertFailure ("short target accepted, got: " ++ show other)
  -- A 16-byte blob is not PKCS7 framing (multiple of 8, >= 24).
  case planUnwrapKey defaultRules m2 st aesKwp7Mech BS.empty wrapH (BS.replicate 16 0) tmpl of
    KeyDenied d -> assertEqual "blob code" CKR_ARGUMENTS_BAD (kdCode d)
    other -> assertFailure ("short blob accepted, got: " ++ show other)

caseEcdhCompWrapRoundtrip :: IO ()
caseEcdhCompWrapRoundtrip = withSynth $ \answer -> do
  m0 <- seedModel >>= loginUser
  st <- getSession m0
  -- EC recipient pair with the marks (synthetic opaque material:
  -- transport prefix 69, agreement secret 72). Composition wrap
  -- takes the PUBLIC half, unwrap takes the private half.
  let ecPubWrapTmpl = ecPubTmpl ++ [(AttrWrap, ValBool True), (AttrUnwrap, ValBool True)]
      ecPrivWrapTmpl = ecPrivTmpl ++ [(AttrWrap, ValBool True), (AttrUnwrap, ValBool True)]
  (m1, pubH, privH) <- case planGenerateKeyPair defaultRules m0 st ecKeyPairGenMech ecPubWrapTmpl ecPrivWrapTmpl of
    KeyEffect pw fx -> do
      res <- answer m0 fx
      c <- finishCommit m0 st pw res 2
      pub <- handleOf (pcOutputs c !! 0)
      priv <- handleOf (pcOutputs c !! 1)
      m' <- expectRight (publishDelta m0 (pcDelta c))
      pure (m', pub, priv)
    other -> assertFailure ("EC keypair plan is not an effect: " ++ show other) >> undefined
  (m2, targetH) <- genAesKey answer m1 st (aesTmpl 16)
  Just target <- pure (resolveHandle m2 targetH)
  Just targetMat <- pure (keyBytesOf target)
  let params128 = encodeWrapCompEcdhParams 0 BS.empty 128
      queryLen m wh mech ps = case planWrapKey m st mech ps wh targetH IntentNull of
        KeyImmediate (Immediate c) -> pure (pcOutputs c)
        other -> assertFailure ("comp query is not an Immediate commit: " ++ show other) >> undefined
  -- Length query: opaque transport 69 + KWP(16) 24 = 93.
  assertEqual "comp query length"
    [NativeOutput (RegionBytes "wrapped" IntentNull) (encodeValue (ValULong 93))]
    =<< queryLen m2 pubH ecdhAesKwMech params128
  -- Short buffer answers the length and refuses.
  case planWrapKey m2 st ecdhAesKwMech params128 pubH targetH (IntentBuffer 92) of
    KeyImmediate (Reject r) -> do
      assertEqual "short code" CKR_BUFFER_TOO_SMALL (rejCode r)
      assertEqual "short length"
        [NativeOutput (RegionBytes "wrapped" (IntentBuffer 92)) (encodeValue (ValULong 93))]
        (rejOutputs r)
    other -> assertFailure ("short buffer accepted, got: " ++ show other)
  -- Full wrap: 93 bytes, opaque transport prefix + KWP tail.
  blob <- case planWrapKey m2 st ecdhAesKwMech params128 pubH targetH (IntentBuffer 93) of
    KeyEffect pw fx -> do
      res <- answer m2 fx
      case finishWork m2 st pw res of
        Immediate c -> case pcOutputs c of
          [NativeOutput (RegionBytes "wrapped" _) bs] -> pure bs
          o -> assertFailure ("wrap outputs one blob, got: " ++ show o) >> undefined
        other -> assertFailure ("wrap finish must commit, got: " ++ show other) >> undefined
    other -> assertFailure ("comp plan is not an effect: " ++ show other) >> undefined
  assertEqual "wrapped length" 93 (BS.length blob)
  assertEqual "opaque prefix tag" "HKS1" (BS.take 4 blob)
  let tmpl =
        [ (AttrClass, ValULong ckoSecretKey)
        , (AttrKeyType, ValULong ckkAes)
        , (AttrToken, ValBool False)
        ]
  -- Unwrap roundtrip recovers the target material.
  case planUnwrapKey defaultRules m2 st ecdhAesKwMech params128 privH blob tmpl of
    KeyEffect pw fx -> do
      res <- answer m2 fx
      c <- finishCommit m2 st pw res 1
      h <- handleOf (pcOutputs c !! 0)
      mu <- expectRight (publishDelta m2 (pcDelta c))
      Just ost <- pure (resolveHandle mu h)
      assertEqual "unwrapped material" (Just targetMat) (keyBytesOf ost)
    other -> assertFailure ("comp unwrap plan is not an effect: " ++ show other)
  -- Tampered KWP tail plans, then the driver answers AuthFailed
  -- and the finish rejects with nothing published (fail closed).
  let (pre, tailB) = BS.splitAt 69 blob
      badTail = BS.pack [BS.index tailB 0 `xor` 0x01] <> BS.drop 1 tailB
  case planUnwrapKey defaultRules m2 st ecdhAesKwMech params128 privH (pre <> badTail) tmpl of
    KeyEffect pw fx -> do
      res <- answer m2 fx
      case finishWork m2 st pw res of
        Reject r -> assertEqual "tamper publishes nothing" (StateDelta []) (rejDelta r)
        other -> assertFailure ("tampered unwrap committed, got: " ++ show other)
    other -> assertFailure ("tampered unwrap plan is not an effect: " ++ show other)
  -- Bad parameters: off-set strengths refuse argument-bad
  -- (malformed), unserved KDFs refuse parameter-invalid (the open
  -- KDF enum is a feature refusal, not a malformed struct).
  case planWrapKey m2 st ecdhAesKwMech (encodeWrapCompEcdhParams 1 BS.empty 128) pubH targetH IntentNull of
    KeyDenied d -> assertEqual "kdf code" CKR_MECHANISM_PARAM_INVALID (kdCode d)
    other -> assertFailure ("non-null kdf accepted, got: " ++ show other)
  case planWrapKey m2 st ecdhAesKwMech (encodeWrapCompEcdhParams 0 BS.empty 512) pubH targetH IntentNull of
    KeyDenied d -> assertEqual "strength code" CKR_ARGUMENTS_BAD (kdCode d)
    other -> assertFailure ("off-set strength accepted, got: " ++ show other)
  -- Foreign wrapping keys refuse type-inconsistent: an AES
  -- secret, an RSA public half, and the EC PRIVATE half (wrap
  -- takes the public half; the swapped-roles regression pin).
  (m3, aesH) <- genAesKey answer m2 st wrapKeyTmpl
  case planWrapKey m3 st ecdhAesKwMech params128 aesH targetH IntentNull of
    KeyDenied d -> assertEqual "aes code" CKR_WRAPPING_KEY_TYPE_INCONSISTENT (kdCode d)
    other -> assertFailure ("AES wrapping accepted, got: " ++ show other)
  (m4, rsaH) <- plantKey m3 st
    [ (AttrClass, ValULong ckoPublicKey)
    , (AttrKeyType, ValULong ckkRsa)
    , (AttrToken, ValBool False)
    , (AttrWrap, ValBool True)
    ]
    (BS.replicate 32 0x43)
  case planWrapKey m4 st ecdhAesKwMech params128 rsaH targetH IntentNull of
    KeyDenied d -> assertEqual "rsa code" CKR_WRAPPING_KEY_TYPE_INCONSISTENT (kdCode d)
    other -> assertFailure ("RSA wrapping accepted, got: " ++ show other)
  case planWrapKey m4 st ecdhAesKwMech params128 privH targetH IntentNull of
    KeyDenied d -> assertEqual "priv-half code" CKR_WRAPPING_KEY_TYPE_INCONSISTENT (kdCode d)
    other -> assertFailure ("private-half wrapping accepted, got: " ++ show other)
  case planUnwrapKey defaultRules m4 st ecdhAesKwMech params128 pubH blob tmpl of
    KeyDenied d -> assertEqual "pub-half unwrap code" CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT (kdCode d)
    other -> assertFailure ("public-half unwrap accepted, got: " ++ show other)
  -- Row gates: X refuses the EC key, cofactor refuses Montgomery.
  case planWrapKey m2 st ecdhXAesKwMech params128 pubH targetH IntentNull of
    KeyDenied d -> assertEqual "x/ec code" CKR_WRAPPING_KEY_TYPE_INCONSISTENT (kdCode d)
    other -> assertFailure ("X over EC accepted, got: " ++ show other)
  (m5, montPubH) <- case planGenerateKeyPair defaultRules m4 st montgomeryKeyPairGenMech
      (xdPubTmpl ++ [(AttrWrap, ValBool True)])
      (xdPrivTmpl ++ [(AttrUnwrap, ValBool True)]) of
    KeyEffect pw fx -> do
      res <- answer m4 fx
      c <- finishCommit m4 st pw res 2
      h <- handleOf (pcOutputs c !! 0)
      m' <- expectRight (publishDelta m4 (pcDelta c))
      pure (m', h)
    other -> assertFailure ("Montgomery keypair plan is not an effect: " ++ show other) >> undefined
  case planWrapKey m5 st ecdhCofAesKwMech params128 montPubH targetH IntentNull of
    KeyDenied d -> assertEqual "cof/mont code" CKR_WRAPPING_KEY_TYPE_INCONSISTENT (kdCode d)
    other -> assertFailure ("cofactor over Montgomery accepted, got: " ++ show other)
  -- Plain over Montgomery plans (opaque 69 + KWP 24 = 93).
  assertEqual "plain/mont query length"
    [NativeOutput (RegionBytes "wrapped" IntentNull) (encodeValue (ValULong 93))]
    =<< queryLen m5 montPubH ecdhAesKwMech params128
  -- Blob framing: short and ragged tails refuse argument-bad.
  case planUnwrapKey defaultRules m2 st ecdhAesKwMech params128 privH (BS.replicate 80 0) tmpl of
    KeyDenied d -> assertEqual "short blob code" CKR_ARGUMENTS_BAD (kdCode d)
    other -> assertFailure ("short blob accepted, got: " ++ show other)
  case planUnwrapKey defaultRules m2 st ecdhAesKwMech params128 privH (BS.replicate 69 0 <> BS.replicate 20 0) tmpl of
    KeyDenied d -> assertEqual "ragged code" CKR_ARGUMENTS_BAD (kdCode d)
    other -> assertFailure ("ragged tail accepted, got: " ++ show other)
  -- The secret-width rule: a P-192 key (24-byte secret) refuses
  -- AES-256 but serves AES-128 (49 + 24 = 73).
  let p192oid = BS.pack [0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x01]
  (m6, p192H) <- plantKey m5 st
    [ (AttrClass, ValULong ckoPublicKey)
    , (AttrKeyType, ValULong ckkEc)
    , (AttrToken, ValBool False)
    , (AttrWrap, ValBool True)
    ]
    ("junk" <> p192oid <> "junk")
  case planWrapKey m6 st ecdhAesKwMech (encodeWrapCompEcdhParams 0 BS.empty 256) p192H targetH IntentNull of
    KeyDenied d -> assertEqual "width code" CKR_MECHANISM_PARAM_INVALID (kdCode d)
    other -> assertFailure ("P-192 x AES-256 accepted, got: " ++ show other)
  case planWrapKey m6 st ecdhAesKwMech params128 p192H targetH IntentNull of
    KeyImmediate (Immediate c) ->
      assertEqual "P-192 x AES-128 length"
        [NativeOutput (RegionBytes "wrapped" IntentNull) (encodeValue (ValULong 73))]
        (pcOutputs c)
    other -> assertFailure ("P-192 x AES-128 refused, got: " ++ show other)

-- | RSA-composition wrap mints a random temp KEK under the
-- recipient PUBLIC key (OAEP head, modulus-wide) plus the
-- KWP-sealed target; unwrap splits the head, opens the KEK
-- with the PRIVATE key, and recovers the target. Off-fit
-- strengths refuse the length range; foreign halves refuse
-- type-inconsistent.
caseRsaCompWrapRoundtrip :: IO ()
caseRsaCompWrapRoundtrip = withSynth $ \answer -> do
  m0 <- seedModel >>= loginUser
  st <- getSession m0
  let pubT = rsaPubTmpl ++ [(AttrWrap, ValBool True), (AttrUnwrap, ValBool True)]
      privT = rsaPrivTmpl ++ [(AttrWrap, ValBool True), (AttrUnwrap, ValBool True)]
      params256 = encodeWrapCompRsaParams "SHA256" "SHA256" BS.empty 256
  (m1, pubH, privH) <- genRsaPair answer m0 st pubT privT
  (m2, targetH) <- genAesKey answer m1 st (aesTmpl 16)
  Just target <- pure (resolveHandle m2 targetH)
  Just targetMat <- pure (keyBytesOf target)
  let queryLen m wh mech ps = case planWrapKey m st mech ps wh targetH IntentNull of
        KeyImmediate (Immediate c) -> pure (pcOutputs c)
        other -> assertFailure ("comp query is not an Immediate commit: " ++ show other) >> undefined
  -- Length query: 2048-bit modulus 256 + KWP(16) 24 = 280.
  assertEqual "comp query length"
    [NativeOutput (RegionBytes "wrapped" IntentNull) (encodeValue (ValULong 280))]
    =<< queryLen m2 pubH rsaAesKwMech params256
  -- Short buffer answers the length and refuses.
  case planWrapKey m2 st rsaAesKwMech params256 pubH targetH (IntentBuffer 279) of
    KeyImmediate (Reject r) -> do
      assertEqual "short code" CKR_BUFFER_TOO_SMALL (rejCode r)
      assertEqual "short length"
        [NativeOutput (RegionBytes "wrapped" (IntentBuffer 279)) (encodeValue (ValULong 280))]
        (rejOutputs r)
    other -> assertFailure ("short buffer accepted, got: " ++ show other)
  -- Full wrap: 280 bytes, modulus head + KWP tail.
  blob <- case planWrapKey m2 st rsaAesKwMech params256 pubH targetH (IntentBuffer 280) of
    KeyEffect pw fx -> do
      res <- answer m2 fx
      case finishWork m2 st pw res of
        Immediate c -> case pcOutputs c of
          [NativeOutput (RegionBytes "wrapped" _) bs] -> pure bs
          o -> assertFailure ("wrap outputs one blob, got: " ++ show o) >> undefined
        other -> assertFailure ("wrap finish must commit, got: " ++ show other) >> undefined
    other -> assertFailure ("comp plan is not an effect: " ++ show other) >> undefined
  assertEqual "wrapped length" 280 (BS.length blob)
  -- A second wrap mints a FRESH random KEK (heads differ).
  blob2 <- case planWrapKey m2 st rsaAesKwMech params256 pubH targetH (IntentBuffer 280) of
    KeyEffect pw fx -> do
      res <- answer m2 fx
      case finishWork m2 st pw res of
        Immediate c -> case pcOutputs c of
          [NativeOutput (RegionBytes "wrapped" _) bs] -> pure bs
          o -> assertFailure ("rewrap outputs one blob, got: " ++ show o) >> undefined
        other -> assertFailure ("rewrap finish must commit, got: " ++ show other) >> undefined
    other -> assertFailure ("rewrap plan is not an effect: " ++ show other) >> undefined
  assertBool "fresh KEK per wrap" (BS.take 256 blob2 /= BS.take 256 blob)
  let tmpl =
        [ (AttrClass, ValULong ckoSecretKey)
        , (AttrKeyType, ValULong ckkAes)
        , (AttrToken, ValBool False)
        ]
  -- Unwrap roundtrip recovers the target material.
  case planUnwrapKey defaultRules m2 st rsaAesKwMech params256 privH blob tmpl of
    KeyEffect pw fx -> do
      res <- answer m2 fx
      c <- finishCommit m2 st pw res 1
      h <- handleOf (pcOutputs c !! 0)
      mu <- expectRight (publishDelta m2 (pcDelta c))
      Just ost <- pure (resolveHandle mu h)
      assertEqual "unwrapped material" (Just targetMat) (keyBytesOf ost)
    other -> assertFailure ("comp unwrap plan is not an effect: " ++ show other)
  -- Tampered head and tampered tail both fail closed (nothing
  -- published).
  let (hd, tl) = BS.splitAt 256 blob
      badHead = BS.pack [BS.index hd 0 `xor` 0x01] <> BS.drop 1 hd
  case planUnwrapKey defaultRules m2 st rsaAesKwMech params256 privH (badHead <> tl) tmpl of
    KeyEffect pw fx -> do
      res <- answer m2 fx
      case finishWork m2 st pw res of
        Reject r -> assertEqual "head tamper publishes nothing" (StateDelta []) (rejDelta r)
        other -> assertFailure ("tampered head committed, got: " ++ show other)
    other -> assertFailure ("tampered-head unwrap plan is not an effect: " ++ show other)
  let badTail = BS.pack [BS.index tl 0 `xor` 0x01] <> BS.drop 1 tl
  case planUnwrapKey defaultRules m2 st rsaAesKwMech params256 privH (hd <> badTail) tmpl of
    KeyEffect pw fx -> do
      res <- answer m2 fx
      case finishWork m2 st pw res of
        Reject r -> assertEqual "tail tamper publishes nothing" (StateDelta []) (rejDelta r)
        other -> assertFailure ("tampered tail committed, got: " ++ show other)
    other -> assertFailure ("tampered-tail unwrap plan is not an effect: " ++ show other)
  -- Bad parameters refuse argument-bad.
  case planWrapKey m2 st rsaAesKwMech (encodeWrapCompRsaParams "SHA256" "SHA256" BS.empty 512) pubH targetH IntentNull of
    KeyDenied d -> assertEqual "strength code" CKR_ARGUMENTS_BAD (kdCode d)
    other -> assertFailure ("off-set strength accepted, got: " ++ show other)
  case planWrapKey m2 st rsaAesKwMech "truncated" pubH targetH IntentNull of
    KeyDenied d -> assertEqual "truncated code" CKR_ARGUMENTS_BAD (kdCode d)
    other -> assertFailure ("truncated params accepted, got: " ++ show other)
  -- Foreign wrapping halves refuse type-inconsistent: an AES
  -- secret, an EC public half, and the RSA PRIVATE half (wrap
  -- takes the public half).
  (m3, aesH) <- genAesKey answer m2 st wrapKeyTmpl
  case planWrapKey m3 st rsaAesKwMech params256 aesH targetH IntentNull of
    KeyDenied d -> assertEqual "aes code" CKR_WRAPPING_KEY_TYPE_INCONSISTENT (kdCode d)
    other -> assertFailure ("AES wrapping accepted, got: " ++ show other)
  (m4, ecH) <- plantKey m3 st
    [ (AttrClass, ValULong ckoPublicKey)
    , (AttrKeyType, ValULong ckkEc)
    , (AttrToken, ValBool False)
    , (AttrWrap, ValBool True)
    ]
    (BS.replicate 32 0x45)
  case planWrapKey m4 st rsaAesKwMech params256 ecH targetH IntentNull of
    KeyDenied d -> assertEqual "ec code" CKR_WRAPPING_KEY_TYPE_INCONSISTENT (kdCode d)
    other -> assertFailure ("EC wrapping accepted, got: " ++ show other)
  case planWrapKey m4 st rsaAesKwMech params256 privH targetH IntentNull of
    KeyDenied d -> assertEqual "priv-half code" CKR_WRAPPING_KEY_TYPE_INCONSISTENT (kdCode d)
    other -> assertFailure ("private-half wrapping accepted, got: " ++ show other)
  case planUnwrapKey defaultRules m4 st rsaAesKwMech params256 pubH blob tmpl of
    KeyDenied d -> assertEqual "pub-half unwrap code" CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT (kdCode d)
    other -> assertFailure ("public-half unwrap accepted, got: " ++ show other)
  -- Blob framing: short and ragged tails refuse argument-bad.
  case planUnwrapKey defaultRules m2 st rsaAesKwMech params256 privH (BS.replicate 270 0) tmpl of
    KeyDenied d -> assertEqual "short blob code" CKR_ARGUMENTS_BAD (kdCode d)
    other -> assertFailure ("short blob accepted, got: " ++ show other)
  case planUnwrapKey defaultRules m2 st rsaAesKwMech params256 privH (BS.replicate 256 0 <> BS.replicate 20 0) tmpl of
    KeyDenied d -> assertEqual "ragged code" CKR_ARGUMENTS_BAD (kdCode d)
    other -> assertFailure ("ragged tail accepted, got: " ++ show other)
  -- The KEK-fit rule: a 512-bit modulus (64-byte head) refuses
  -- AES-256 under SHA-256 (64 - 64 - 2 < 32) but serves
  -- AES-128 under SHA-1 (64 - 40 - 2 = 22 >= 16; 64 + 24 = 88).
  (m5, shortH) <- plantKey m4 st
    [ (AttrClass, ValULong ckoPublicKey)
    , (AttrKeyType, ValULong ckkRsa)
    , (AttrToken, ValBool False)
    , (AttrWrap, ValBool True)
    , (AttrModulus, ValBytes (BS.pack (0x80 : replicate 63 0x4d)))
    ]
    "opaque-rsa-half"
  case planWrapKey m5 st rsaAesKwMech params256 shortH targetH IntentNull of
    KeyDenied d -> assertEqual "fit code" CKR_DATA_LEN_RANGE (kdCode d)
    other -> assertFailure ("unfit KEK accepted, got: " ++ show other)
  case planWrapKey m5 st rsaAesKwMech (encodeWrapCompRsaParams "SHA_1" "SHA_1" BS.empty 128) shortH targetH IntentNull of
    KeyImmediate (Immediate c) ->
      assertEqual "short-modulus query length"
        [NativeOutput (RegionBytes "wrapped" IntentNull) (encodeValue (ValULong 88))]
        (pcOutputs c)
    other -> assertFailure ("fit KEK refused, got: " ++ show other)

-- | Unwrap commits measure the answered material against the
-- template key type (Tookan §3.2 key-type confusion: a 16-byte
-- AES blob unwrapped as CKK_DES3 must refuse, never mint a
-- confused key). AES takes 16/24/32 bytes, DES3 takes 24, XTS
-- takes 32/64, and generic secret takes any length.
caseUnwrapKeyTypeLength :: IO ()
caseUnwrapKeyTypeLength = withSynth $ \answer -> do
  m0 <- seedModel >>= loginUser
  st <- getSession m0
  (m1, wrapH) <- genAesKey answer m0 st wrapKeyTmpl
  (m2, targetH) <- genAesKey answer m1 st (aesTmpl 16)
  (m3, target24H) <- genAesKey answer m2 st (aesTmpl 24)
  Just target24 <- pure (resolveHandle m3 target24H)
  Just target24Mat <- pure (keyBytesOf target24)
  let wrap16Blob = doWrap aesKwMech m3 st answer wrapH targetH 24
  blob16 <- wrap16Blob
  blob32 <- doWrap aesKwMech m3 st answer wrapH target24H 32
  let des3UnwrapTmpl =
        [ (AttrClass, ValULong ckoSecretKey)
        , (AttrKeyType, ValULong (mustKeyTypeId "CKK_DES3"))
        , (AttrToken, ValBool False)
        , (AttrExtractable, ValBool True)
        ]
      xtsTmpl =
        [ (AttrClass, ValULong ckoSecretKey)
        , (AttrKeyType, ValULong (mustKeyTypeId "CKK_AES_XTS"))
        , (AttrToken, ValBool False)
        , (AttrExtractable, ValBool True)
        ]
  -- 16 bytes as DES3 refuses at commit (the confusion leg).
  case planUnwrapKey defaultRules m3 st aesKwMech BS.empty wrapH blob16 des3UnwrapTmpl of
    KeyEffect pw fx -> do
      res <- answer m3 fx
      case finishWork m3 st pw res of
        Reject r -> do
          assertEqual "confusion code" CKR_TEMPLATE_INCONSISTENT (rejCode r)
          assertEqual "confusion publishes nothing" (StateDelta []) (rejDelta r)
        other -> assertFailure ("confused unwrap committed, got: " ++ show other)
    other -> assertFailure ("unwrap plan is not an effect: " ++ show other)
  -- 24 bytes as DES3 commits (the type path itself works).
  case planUnwrapKey defaultRules m3 st aesKwMech BS.empty wrapH blob32 des3UnwrapTmpl of
    KeyEffect pw fx -> do
      res <- answer m3 fx
      c <- finishCommit m3 st pw res 1
      h <- handleOf (pcOutputs c !! 0)
      m4 <- expectRight (publishDelta m3 (pcDelta c))
      Just ost <- pure (resolveHandle m4 h)
      assertEqual "des3 material" (Just target24Mat) (keyBytesOf ost)
    other -> assertFailure ("unwrap plan is not an effect: " ++ show other)
  -- 32 bytes as XTS commits (double-width data + tweak halves).
  (m5, target32H) <- genAesKey answer m3 st (aesTmpl 32)
  Just target32 <- pure (resolveHandle m5 target32H)
  Just target32Mat <- pure (keyBytesOf target32)
  blob40 <- doWrap aesKwMech m5 st answer wrapH target32H 40
  case planUnwrapKey defaultRules m5 st aesKwMech BS.empty wrapH blob40 xtsTmpl of
    KeyEffect pw fx -> do
      res <- answer m5 fx
      c <- finishCommit m5 st pw res 1
      h <- handleOf (pcOutputs c !! 0)
      m6 <- expectRight (publishDelta m5 (pcDelta c))
      Just ost <- pure (resolveHandle m6 h)
      assertEqual "xts material" (Just target32Mat) (keyBytesOf ost)
    other -> assertFailure ("unwrap plan is not an effect: " ++ show other)
  -- 12 bytes as XTS refuses (not a double width).
  (m7, target12H) <- genKeyWith answer m5 st genericSecretKeyGenMech (secretTmplN 12)
  blob24 <- doWrap aesKwpMech m7 st answer wrapH target12H 24
  case planUnwrapKey defaultRules m7 st aesKwpMech BS.empty wrapH blob24 xtsTmpl of
    KeyEffect pw fx -> do
      res <- answer m7 fx
      case finishWork m7 st pw res of
        Reject r -> do
          assertEqual "xts confusion code" CKR_TEMPLATE_INCONSISTENT (rejCode r)
          assertEqual "xts confusion publishes nothing" (StateDelta []) (rejDelta r)
        other -> assertFailure ("confused unwrap committed, got: " ++ show other)
    other -> assertFailure ("unwrap plan is not an effect: " ++ show other)
  where
    doWrap wmech m st answer wrapH targetH wantLen =
      case planWrapKey m st wmech BS.empty wrapH targetH (IntentBuffer wantLen) of
        KeyEffect pw fx -> do
          res <- answer m fx
          case finishWork m st pw res of
            Immediate c -> case pcOutputs c of
              [NativeOutput (RegionBytes "wrapped" _) bs] -> pure bs
              o -> assertFailure ("wrap outputs one blob, got: " ++ show o) >> undefined
            other -> assertFailure ("wrap finish must commit, got: " ++ show other) >> undefined
        other -> assertFailure ("wrap plan is not an effect: " ++ show other) >> undefined

-- | Generate one RSA pair through the planner + backend, with
-- caller-supplied templates (so the wrap/unwrap marks land).
genRsaPair :: (Model -> CryptoEffect -> IO CryptoResult)
  -> Model -> SessionState
  -> [(AttributeType, AttributeValue)] -> [(AttributeType, AttributeValue)]
  -> IO (Model, ExternalHandle, ExternalHandle)
genRsaPair answer m st pubT privT =
  case planGenerateKeyPair defaultRules m st rsaKeyPairGenMech pubT privT of
    KeyEffect pw fx -> do
      res <- answer m fx
      c <- finishCommit m st pw res 2
      h1 <- handleOf (pcOutputs c !! 0)
      h2 <- handleOf (pcOutputs c !! 1)
      m' <- expectRight (publishDelta m (pcDelta c))
      pure (m', h1, h2)
    other -> assertFailure ("RSA plan is not an effect: " ++ show other) >> undefined

caseRsaWrapRoundtrip :: IO ()
caseRsaWrapRoundtrip = withSynth $ \answer -> do
  m0 <- seedModel >>= loginUser
  st <- getSession m0
  let pubT = rsaPubTmpl ++ [(AttrWrap, ValBool True), (AttrUnwrap, ValBool True)]
      privT = rsaPrivTmpl ++ [(AttrWrap, ValBool True), (AttrUnwrap, ValBool True)]
      oaep = encodeOaepParams "SHA256" "SHA256" BS.empty
      oaepLabel = encodeOaepParams "SHA_1" "SHA_1" "label"
  (m1, pubH, privH) <- genRsaPair answer m0 st pubT privT
  (m2, targetH) <- genAesKey answer m1 st (aesTmpl 16)
  Just target <- pure (resolveHandle m2 targetH)
  Just targetMat <- pure (keyBytesOf target)
  -- Length queries answer the modulus width and plan no crypto.
  mapM_ (queryOk m2 st pubH targetH) [(rsaPkcsMech, BS.empty), (rsaOaepMech, oaep)]
  -- Both paddings wrap the raw material. (The synthetic seal is
  -- tag-sized, not modulus-wide; the modulus-wide real-backend
  -- roundtrip is pinned in RoutingE2ESpec caseDriverRsaWrap.)
  blob15 <- wrapOk m2 st answer rsaPkcsMech BS.empty pubH targetH
  assertEqual "v1.5 synthetic length" 32 (BS.length blob15)
  assertBool "v1.5 blob differs from plaintext" (blob15 /= targetMat)
  blobO <- wrapOk m2 st answer rsaOaepMech oaep pubH targetH
  assertEqual "oaep synthetic length" 32 (BS.length blobO)
  assertBool "padding domains separate" (blob15 /= blobO)
  blobL <- wrapOk m2 st answer rsaOaepMech oaepLabel pubH targetH
  assertBool "labeled row differs" (blobL /= blobO)
  -- Unwrap plans pair raw pending work with the unwrap effect
  -- (coherent, modulus-wide blob), and the finisher stores the
  -- answer raw (no PKCS#7 framing to strip).
  mapM_ (unwrapPlanOk m2 st privH) [(rsaPkcsMech, BS.empty), (rsaOaepMech, oaep)]
  case planUnwrapKey defaultRules m2 st rsaPkcsMech BS.empty privH
    (BS.replicate 256 0)
    [ (AttrClass, ValULong ckoSecretKey)
    , (AttrKeyType, ValULong ckkAes)
    , (AttrToken, ValBool False)
    , (AttrLabel, ValBytes "unwrapped")
    , (AttrEncrypt, ValBool True)
    ] of
    KeyEffect pw@(PwUnwrapRaw _) fx@(FxUnwrap _ _ _ _) -> do
      assertBool "raw pair coherent" (keyPairCompatible pw fx)
      c <- finishCommit m2 st pw (GotBytes targetMat) 1
      h <- handleOf (pcOutputs c !! 0)
      m3 <- expectRight (publishDelta m2 (pcDelta c))
      Just ost <- pure (resolveHandle m3 h)
      assertEqual "unwrapped material" (Just targetMat) (keyBytesOf ost)
      assertEqual "label landed"
        (Just (ValBytes "unwrapped")) (Map.lookup AttrLabel (osAttrs ost))
      assertEqual "usage landed" (Just (ValBool True)) (Map.lookup AttrEncrypt (osAttrs ost))
    other -> assertFailure ("unwrap plan is not a raw effect: " ++ show other)
  where
    queryOk m st pubH targetH (mech, params) =
      case planWrapKey m st mech params pubH targetH IntentNull of
        KeyImmediate (Immediate c) -> do
          assertEqual ("query length " ++ show mech)
            [NativeOutput (RegionBytes "wrapped" IntentNull) (encodeValue (ValULong 256))]
            (pcOutputs c)
          assertEqual "query publishes nothing" (StateDelta []) (pcDelta c)
        other -> assertFailure ("wrap query is not an Immediate commit: " ++ show other)
    wrapOk m st answer mech params wrapH targetH =
      case planWrapKey m st mech params wrapH targetH (IntentBuffer 256) of
        KeyEffect pw fx -> do
          res <- answer m fx
          case finishWork m st pw res of
            Immediate c -> case pcOutputs c of
              [NativeOutput (RegionBytes "wrapped" _) bs] -> pure bs
              o -> assertFailure ("wrap outputs one blob, got: " ++ show o) >> undefined
            other -> assertFailure ("wrap finish must commit, got: " ++ show other) >> undefined
        other -> assertFailure ("wrap plan is not an effect: " ++ show other) >> undefined
    unwrapPlanOk m st wrapH (mech, params) =
      case planUnwrapKey defaultRules m st mech params wrapH (BS.replicate 256 0)
        [(AttrClass, ValULong ckoSecretKey), (AttrKeyType, ValULong ckkAes)] of
        KeyEffect pw@(PwUnwrapRaw _) fx@(FxUnwrap _ _ _ _) ->
          assertBool ("raw pair coherent " ++ show mech) (keyPairCompatible pw fx)
        other -> assertFailure ("unwrap plan is not a raw effect: " ++ show other)

caseRsaWrapMismatch :: IO ()
caseRsaWrapMismatch = withSynth $ \answer -> do
  m0 <- seedModel >>= loginUser
  st <- getSession m0
  -- Both halves carry both marks, so the wrong-half legs reach
  -- the type gate (usage gates first, mirroring the AES resolver).
  let pubT = rsaPubTmpl ++ [(AttrWrap, ValBool True), (AttrUnwrap, ValBool True)]
      privT = rsaPrivTmpl ++ [(AttrWrap, ValBool True), (AttrUnwrap, ValBool True)]
  (m1, pubH, privH) <- genRsaPair answer m0 st pubT privT
  (m2, targetH) <- genAesKey answer m1 st (aesTmpl 16)
  (m3, aesWrapH) <- genAesKey answer m2 st wrapKeyTmpl
  let denyWrap m mech params wrapH tgtH cap = case planWrapKey m st mech params wrapH tgtH cap of
        KeyDenied (KeyDeny code _) -> pure code
        other -> assertFailure ("wrap must deny, got: " ++ show other) >> undefined
      denyUnwrap m mech params wrapH blob outTmpl =
        case planUnwrapKey defaultRules m st mech params wrapH blob outTmpl of
          KeyDenied (KeyDeny code _) -> pure code
          other -> assertFailure ("unwrap must deny, got: " ++ show other) >> undefined
      tmpl = [(AttrClass, ValULong ckoSecretKey), (AttrKeyType, ValULong ckkAes)]
  -- Parameter shapes refuse.
  code1 <- denyWrap m3 rsaPkcsMech "nonempty" pubH targetH (IntentBuffer 256)
  assertEqual "v1.5 params code" CKR_ARGUMENTS_BAD code1
  code2 <- denyWrap m3 rsaOaepMech "garbage" pubH targetH (IntentBuffer 256)
  assertEqual "oaep params code" CKR_ARGUMENTS_BAD code2
  -- Wrong halves and foreign key types refuse.
  code3 <- denyWrap m3 rsaPkcsMech BS.empty privH targetH (IntentBuffer 256)
  assertEqual "private-half wrap code" CKR_WRAPPING_KEY_TYPE_INCONSISTENT code3
  code4 <- denyWrap m3 rsaPkcsMech BS.empty aesWrapH targetH (IntentBuffer 256)
  assertEqual "aes-key wrap code" CKR_WRAPPING_KEY_TYPE_INCONSISTENT code4
  code5 <- denyUnwrap m3 rsaPkcsMech BS.empty pubH (BS.replicate 256 0) tmpl
  assertEqual "public-half unwrap code" CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT code5
  -- A key marked non-wrapping cannot wrap (absent flags default
  -- true at keygen, so the refusal needs an explicit false).
  (m4, plainPubH, _) <- genRsaPair answer m3 st
    (rsaPubTmpl ++ [(AttrWrap, ValBool False)]) rsaPrivTmpl
  code6 <- denyWrap m4 rsaPkcsMech BS.empty plainPubH targetH (IntentBuffer 256)
  assertEqual "no-wrap-mark code" CKR_KEY_FUNCTION_NOT_PERMITTED code6
  -- An unextractable target cannot wrap.
  (m5, sealedH) <- genAesKey answer m4 st
    [ (AttrClass, ValULong ckoSecretKey)
    , (AttrKeyType, ValULong ckkAes)
    , (AttrValueLen, ValULong 16)
    , (AttrToken, ValBool False)
    , (AttrExtractable, ValBool False)
    ]
  code7 <- denyWrap m5 rsaPkcsMech BS.empty pubH sealedH (IntentBuffer 256)
  assertEqual "unextractable code" CKR_KEY_UNEXTRACTABLE code7
  -- Oversized payloads refuse with the length code (v1.5 bound
  -- k-11 = 245; OAEP-SHA-512 bound k-2*64-2 = 126).
  (m6, bigH) <- genKeyWith answer m5 st genericSecretKeyGenMech
    (genericTmpl 250 ++ [(AttrExtractable, ValBool True)])
  code8 <- denyWrap m6 rsaPkcsMech BS.empty pubH bigH (IntentBuffer 256)
  assertEqual "oversized code" CKR_DATA_LEN_RANGE code8
  let oaep512 = encodeOaepParams "SHA512" "SHA512" BS.empty
  (m7, midH) <- genKeyWith answer m6 st genericSecretKeyGenMech
    (genericTmpl 200 ++ [(AttrExtractable, ValBool True)])
  code9 <- denyWrap m7 rsaOaepMech oaep512 pubH midH (IntentBuffer 256)
  assertEqual "oversized oaep code" CKR_DATA_LEN_RANGE code9
  -- Off-modulus blobs and key-typeless templates refuse.
  code10 <- denyUnwrap m7 rsaPkcsMech BS.empty privH "short" tmpl
  assertEqual "short blob code" CKR_ARGUMENTS_BAD code10
  code11 <- denyUnwrap m7 rsaPkcsMech BS.empty privH (BS.replicate 256 0)
    [(AttrClass, ValULong ckoSecretKey)]
  assertEqual "typeless template code" CKR_TEMPLATE_INCOMPLETE code11
  -- Short buffers answer the modulus width.
  case planWrapKey m3 st rsaPkcsMech BS.empty pubH targetH (IntentBuffer 255) of
    KeyImmediate (Reject r) -> do
      assertEqual "short code" CKR_BUFFER_TOO_SMALL (rejCode r)
      assertEqual "short length"
        [NativeOutput (RegionBytes "wrapped" (IntentBuffer 255)) (encodeValue (ValULong 256))]
        (rejOutputs r)
    other -> assertFailure ("short buffer must reject, got: " ++ show other)

caseRsaX509Wrap :: IO ()
caseRsaX509Wrap = withSynth $ \answer -> do
  m0 <- seedModel >>= loginUser
  st <- getSession m0
  let pubT = rsaPubTmpl ++ [(AttrWrap, ValBool True), (AttrUnwrap, ValBool True)]
      privT = rsaPrivTmpl ++ [(AttrWrap, ValBool True), (AttrUnwrap, ValBool True)]
  (m1, pubH, privH) <- genRsaPair answer m0 st pubT privT
  (m2, targetH) <- genAesKey answer m1 st (aesTmpl 16)
  Just target <- pure (resolveHandle m2 targetH)
  Just targetMat <- pure (keyBytesOf target)
  -- Length queries answer the modulus width and plan no crypto.
  case planWrapKey m2 st rsaX509Mech BS.empty pubH targetH IntentNull of
    KeyImmediate (Immediate c) -> do
      assertEqual "query length"
        [NativeOutput (RegionBytes "wrapped" IntentNull) (encodeValue (ValULong 256))]
        (pcOutputs c)
      assertEqual "query publishes nothing" (StateDelta []) (pcDelta c)
    other -> assertFailure ("wrap query is not an Immediate commit: " ++ show other)
  -- Wrap seals modulus-wide (the synthetic seal pads like the real one).
  blob <- case planWrapKey m2 st rsaX509Mech BS.empty pubH targetH (IntentBuffer 256) of
    KeyEffect pw fx -> do
      res <- answer m2 fx
      case finishWork m2 st pw res of
        Immediate c -> case pcOutputs c of
          [NativeOutput (RegionBytes "wrapped" _) bs] -> pure bs
          o -> assertFailure ("wrap outputs one blob, got: " ++ show o) >> undefined
        other -> assertFailure ("wrap finish must commit, got: " ++ show other) >> undefined
    other -> assertFailure ("wrap plan is not an effect: " ++ show other) >> undefined
  assertEqual "wrapped width" 256 (BS.length blob)
  assertBool "blob differs from plaintext" (blob /= targetMat)
  -- Unwrap pairs tail pending work with the unwrap effect, and the
  -- full roundtrip recovers the target material.
  let tmpl16 =
        [ (AttrClass, ValULong ckoSecretKey)
        , (AttrKeyType, ValULong ckkAes)
        , (AttrValueLen, ValULong 16)
        , (AttrToken, ValBool False)
        , (AttrExtractable, ValBool True)
        ]
  case planUnwrapKey defaultRules m2 st rsaX509Mech BS.empty privH blob tmpl16 of
    KeyEffect pw@(PwUnwrapTail _ 256 16) fx@(FxUnwrap _ _ _ _) -> do
      assertBool "tail pair coherent" (keyPairCompatible pw fx)
      res <- answer m2 fx
      case finishWork m2 st pw res of
        Immediate c -> do
          h <- handleOf (pcOutputs c !! 0)
          m3 <- expectRight (publishDelta m2 (pcDelta c))
          Just ost <- pure (resolveHandle m3 h)
          assertEqual "unwrapped material" (Just targetMat) (keyBytesOf ost)
        other -> assertFailure ("unwrap finish must commit, got: " ++ show other)
    other -> assertFailure ("unwrap plan is not a tail effect: " ++ show other)
  -- Direct finisher pin: the key is the trailing value_len bytes.
  let block = BS.replicate 240 0 <> targetMat
  case planUnwrapKey defaultRules m2 st rsaX509Mech BS.empty privH
    (BS.replicate 256 0) tmpl16 of
    KeyEffect pw@(PwUnwrapTail _ 256 16) _ ->
      case finishWork m2 st pw (GotBytes block) of
        Immediate c -> do
          h <- handleOf (pcOutputs c !! 0)
          m3 <- expectRight (publishDelta m2 (pcDelta c))
          Just ost <- pure (resolveHandle m3 h)
          assertEqual "tail material" (Just targetMat) (keyBytesOf ost)
        other -> assertFailure ("tail finish must commit, got: " ++ show other)
    other -> assertFailure ("unwrap plan is not a tail effect: " ++ show other)
  -- Refusals: parameters, lengths, blobs, oversized payloads.
  let denyWrap m mech params wrapH tgtH cap =
        case planWrapKey m st mech params wrapH tgtH cap of
          KeyDenied (KeyDeny code _) -> pure code
          other -> assertFailure ("wrap must deny, got: " ++ show other) >> undefined
      denyUnwrap m mech params wrapH wrapBlob tmpl =
        case planUnwrapKey defaultRules m st mech params wrapH wrapBlob tmpl of
          KeyDenied (KeyDeny code _) -> pure code
          other -> assertFailure ("unwrap must deny, got: " ++ show other) >> undefined
      notmpl = [(AttrClass, ValULong ckoSecretKey), (AttrKeyType, ValULong ckkAes)]
  xcode1 <- denyWrap m2 rsaX509Mech "nonempty" pubH targetH (IntentBuffer 256)
  assertEqual "params code" CKR_ARGUMENTS_BAD xcode1
  xcode2 <- denyUnwrap m2 rsaX509Mech BS.empty privH (BS.replicate 256 0) notmpl
  assertEqual "missing length code" CKR_TEMPLATE_INCOMPLETE xcode2
  xcode3 <- denyUnwrap m2 rsaX509Mech BS.empty privH (BS.replicate 256 0)
    (notmpl ++ [(AttrValueLen, ValULong 300)])
  assertEqual "over-wide length code" CKR_TEMPLATE_INCONSISTENT xcode3
  xcode4 <- denyUnwrap m2 rsaX509Mech BS.empty privH (BS.replicate 256 0)
    (notmpl ++ [(AttrValueLen, ValBool True)])
  assertEqual "malformed length code" CKR_TEMPLATE_INCONSISTENT xcode4
  xcode5 <- denyUnwrap m2 rsaX509Mech BS.empty privH "short" tmpl16
  assertEqual "short blob code" CKR_ARGUMENTS_BAD xcode5
  -- Zero overhead: the widest generatable secret (255) fits, while
  -- an extractable RSA private half (DER wider than k) refuses.
  (m3, wideH) <- genKeyWith answer m2 st genericSecretKeyGenMech
    (genericTmpl 255 ++ [(AttrExtractable, ValBool True)])
  case planWrapKey m3 st rsaX509Mech BS.empty pubH wideH (IntentBuffer 256) of
    KeyEffect _ _ -> pure ()
    other -> assertFailure ("255-byte payload must plan, got: " ++ show other)
  (m4, _, bigPrivH) <- genRsaPair answer m3 st rsaPubTmpl
    (filter ((/= AttrExtractable) . fst) rsaPrivTmpl
      ++ [(AttrExtractable, ValBool True)])
  xcode6 <- denyWrap m4 rsaX509Mech BS.empty pubH bigPrivH (IntentBuffer 512)
  assertEqual "oversized code" CKR_DATA_LEN_RANGE xcode6

caseRecoverAttrs :: IO ()
caseRecoverAttrs = withSynth $ \answer -> do
  m0 <- seedModel >>= loginUser
  st <- getSession m0
  -- The oracle's sign-recover subset generates with these flags; the
  -- template must accept and store them (C_SignRecover itself stays
  -- stubbed, which the oracle skips cleanly).
  (m1, pubH, privH) <- genRsaPair answer m0 st
    (rsaPubTmpl ++ [(AttrVerifyRecover, ValBool True)])
    (rsaPrivTmpl ++ [(AttrSignRecover, ValBool True)])
  Just pub <- pure (resolveHandle m1 pubH)
  Just priv <- pure (resolveHandle m1 privH)
  assertEqual "verify-recover stored" (Just (ValBool True))
    (Map.lookup AttrVerifyRecover (osAttrs pub))
  assertEqual "sign-recover stored" (Just (ValBool True))
    (Map.lookup AttrSignRecover (osAttrs priv))
  case (policyFromObject pub, policyFromObject priv) of
    (Just (pubPermits, _), Just (privPermits, _)) -> do
      assertBool "pub recover permit" (OpVerifyRecover `elem` pubPermits)
      assertBool "priv recover permit" (OpSignRecover `elem` privPermits)
    other -> assertFailure ("policies must resolve, got: " ++ show other)
  -- Absent flags read as false (the PKCS#11 defaults): a plain pair
  -- carries no recover permits.
  (m2, pubH2, privH2) <- genRsaPair answer m1 st rsaPubTmpl rsaPrivTmpl
  Just pub2 <- pure (resolveHandle m2 pubH2)
  Just priv2 <- pure (resolveHandle m2 privH2)
  case (policyFromObject pub2, policyFromObject priv2) of
    (Just (pubPermits, _), Just (privPermits, _)) -> do
      assertBool "no pub recover permit" (OpVerifyRecover `notElem` pubPermits)
      assertBool "no priv recover permit" (OpSignRecover `notElem` privPermits)
    other -> assertFailure ("policies must resolve, got: " ++ show other)

caseAuthWrapRoundtrip :: IO ()
caseAuthWrapRoundtrip = withSynth $ \answer -> do
  m0 <- seedModel >>= loginUser
  st <- getSession m0
  (m1, wrapH) <- genAesKey answer m0 st wrapKeyTmpl
  (m2, targetH) <- genAesKey answer m1 st (aesTmpl 24)
  Just target <- pure (resolveHandle m2 targetH)
  Just targetMat <- pure (keyBytesOf target)
  let aad = "associated-data"
  blob <- case planAuthWrapKey m2 st aesCbcMech iv16 wrapH targetH aad (IntentBuffer 64) of
    KeyEffect pw fx -> do
      res <- answer m2 fx
      case finishWork m2 st pw res of
        Immediate c -> case pcOutputs c of
          [NativeOutput (RegionBytes "wrapped" _) bs] -> pure bs
          o -> assertFailure ("auth-wrap outputs one blob, got: " ++ show o) >> undefined
        other -> assertFailure ("auth-wrap finish must commit, got: " ++ show other) >> undefined
    other -> assertFailure ("auth-wrap plan is not an effect: " ++ show other) >> undefined
  assertEqual "blob is padded ct plus 32-byte tag" 64 (BS.length blob)
  let tmpl =
        [ (AttrClass, ValULong ckoSecretKey)
        , (AttrKeyType, ValULong ckkAes)
        , (AttrToken, ValBool False)
        , (AttrDecrypt, ValBool True)
        ]
  case planAuthUnwrapKey defaultRules m2 st aesCbcMech iv16 wrapH blob aad tmpl of
    KeyEffect pw fx -> do
      res <- answer m2 fx
      c <- finishCommit m2 st pw res 1
      h <- handleOf (pcOutputs c !! 0)
      m3 <- expectRight (publishDelta m2 (pcDelta c))
      Just ost <- pure (resolveHandle m3 h)
      assertEqual "auth-unwrapped material" (Just targetMat) (keyBytesOf ost)
      assertEqual "usage landed" (Just (ValBool True)) (Map.lookup AttrDecrypt (osAttrs ost))
    other -> assertFailure ("auth-unwrap plan is not an effect: " ++ show other)

caseDeriveSingle :: IO ()
caseDeriveSingle = withSynth $ \answer -> do
  m0 <- seedModel
  st <- getSession m0
  let baseTmpl =
        [ (AttrClass, ValULong ckoSecretKey)
        , (AttrKeyType, ValULong ckkAes)
        , (AttrValueLen, ValULong 32)
        , (AttrToken, ValBool False)
        , (AttrDerive, ValBool True)
        ]
  (m1, baseH) <- genAesKey answer m0 st baseTmpl
  let soloTmpl =
        [ (AttrClass, ValULong ckoSecretKey)
        , (AttrKeyType, ValULong ckkGenericSecret)
        , (AttrValueLen, ValULong 32)
        , (AttrToken, ValBool False)
        , (AttrEncrypt, ValBool True)
        ]
      blob = encodeDeriveParams (encodeHkdfInfo 4 0x02 BS.empty "derive-info") [soloTmpl]
      before = Map.size (mObjects m1)
  mats <- case planDerive defaultRules m1 st hkdfDeriveMech baseH blob of
    KeyEffect pw fx -> do
      res <- answer m1 fx
      c <- finishCommit m1 st pw res 1
      h <- handleOf (pcOutputs c !! 0)
      m2 <- expectRight (publishDelta m1 (pcDelta c))
      assertEqual "one derived object" (before + 1) (Map.size (mObjects m2))
      Just ost <- pure (resolveHandle m2 h)
      assertEqual "usage landed" (Just (ValBool True)) (Map.lookup AttrEncrypt (osAttrs ost))
      case keyBytesOf ost of
        Just mat -> do
          assertEqual "derived length" 32 (BS.length mat)
          pure (mat, m2)
        Nothing -> assertFailure "derived key lacks material" >> undefined
    other -> assertFailure ("derive plan is not an effect: " ++ show other) >> undefined
  -- Deterministic construction: the same derive replays its bytes.
  case planDerive defaultRules m1 st hkdfDeriveMech baseH blob of
    KeyEffect pw fx -> do
      res <- answer m1 fx
      c <- finishCommit m1 st pw res 1
      h <- handleOf (pcOutputs c !! 0)
      m3 <- expectRight (publishDelta m1 (pcDelta c))
      Just ost <- pure (resolveHandle m3 h)
      assertEqual "derive replays" (Just (fst mats)) (keyBytesOf ost)
    other -> assertFailure ("derive plan is not an effect: " ++ show other)

-- | ECDH key-type-before-params ordering (the Init-matrix rule for
-- derive): an RSA base refuses KEY_TYPE_INCONSISTENT whether the
-- agreement parameters are garbage or well-formed.
caseDeriveEcdhWrongKeyType :: IO ()
caseDeriveEcdhWrongKeyType = do
  m0 <- seedModel
  st <- getSession m0
  let rsaAttrs = Map.fromList
        [ (AttrClass, ValULong ckoPrivateKey)
        , (AttrKeyType, ValULong ckkRsa)
        , (AttrToken, ValBool False)
        , (AttrDerive, ValBool True)
        , (AttrModulus, ValBytes "n")
        , (AttrPublicExponent, ValBytes "e")
        , (AttrPrivateExponent, ValBytes "d")
        , (AttrPrime1, ValBytes "p")
        , (AttrPrime2, ValBytes "q")
        , (AttrExponent1, ValBytes "dp")
        , (AttrExponent2, ValBytes "dq")
        , (AttrCoefficient, ValBytes "qi")
        , (AttrValue, ValBytes "rsa-material-stands-in")
        ]
      tmpl =
        [ (AttrClass, ValULong ckoSecretKey)
        , (AttrKeyType, ValULong ckkGenericSecret)
        , (AttrValueLen, ValULong 16)
        , (AttrToken, ValBool False)
        ]
      mech = MechanismId ckm_ECDH1_DERIVE
  (m1, baseH) <- case publishPending m0 st [pendingFromAttrs st rsaAttrs] of
    Left deny -> assertFailure ("plant must publish: " ++ show deny) >> undefined
    Right (delta, [h]) -> do
      m' <- expectRight (publishDelta m0 delta)
      pure (m', h)
    Right _ -> assertFailure "plant must mint one handle" >> undefined
  let garbage = encodeDeriveParams "not-ecdh-params" [tmpl]
      wellFormed = encodeDeriveParams (encodeEcdhParams 0 BS.empty "peer") [tmpl]
  case planDerive defaultRules m1 st mech baseH garbage of
    KeyDenied (KeyDeny code _) ->
      assertEqual "garbage params, RSA base" CKR_KEY_TYPE_INCONSISTENT code
    other -> assertFailure ("RSA base must not plan: " ++ show other)
  case planDerive defaultRules m1 st mech baseH wellFormed of
    KeyDenied (KeyDeny code _) ->
      assertEqual "valid params, RSA base" CKR_KEY_TYPE_INCONSISTENT code
    other -> assertFailure ("RSA base must not plan: " ++ show other)

-- | ECDH parameter shape still enforced: an EC base with malformed
-- agreement parameters refuses CKR_MECHANISM_PARAM_INVALID.
caseDeriveEcdhBadParams :: IO ()
caseDeriveEcdhBadParams = withSynth $ \answer -> do
  m0 <- seedModel >>= loginUser
  st <- getSession m0
  let privTmpl = ecPrivTmpl ++ [(AttrDerive, ValBool True)]
      tmpl =
        [ (AttrClass, ValULong ckoSecretKey)
        , (AttrKeyType, ValULong ckkGenericSecret)
        , (AttrValueLen, ValULong 16)
        , (AttrToken, ValBool False)
        ]
      mech = MechanismId ckm_ECDH1_DERIVE
  (m1, privH) <- case planGenerateKeyPair defaultRules m0 st ecKeyPairGenMech ecPubTmpl privTmpl of
    KeyEffect pw fx -> do
      res <- answer m0 fx
      c <- finishCommit m0 st pw res 2
      h <- handleOf (pcOutputs c !! 1)
      m' <- expectRight (publishDelta m0 (pcDelta c))
      pure (m', h)
    other -> assertFailure ("EC keypair must plan: " ++ show other) >> undefined
  case planDerive defaultRules m1 st mech privH (encodeDeriveParams "garbage" [tmpl]) of
    KeyDenied (KeyDeny code _) ->
      assertEqual "EC base, garbage params" CKR_MECHANISM_PARAM_INVALID code
    other -> assertFailure ("garbage params must not plan: " ++ show other)

-- | KDF handle resolution: a destroyed base handle refuses
-- KEY_HANDLE_INVALID (the oracle's null-base leg prefers the
-- key-specific code over OBJECT_HANDLE_INVALID).
caseDeriveKdfBadHandle :: IO ()
caseDeriveKdfBadHandle = do
  m0 <- seedModel
  st <- getSession m0
  let tmpl =
        [ (AttrClass, ValULong ckoSecretKey)
        , (AttrKeyType, ValULong ckkGenericSecret)
        , (AttrValueLen, ValULong 16)
        , (AttrToken, ValBool False)
        ]
      mech = MechanismId ckm_SHA256_KEY_DERIVATION
  case planDerive defaultRules m0 st mech (ExternalHandle 99999)
      (encodeDeriveParams BS.empty [tmpl]) of
    KeyDenied (KeyDeny code _) ->
      assertEqual "destroyed base handle" CKR_KEY_HANDLE_INVALID code
    other -> assertFailure ("destroyed handle must not plan: " ++ show other)

-- | SHA-KDF rows derive from generic-secret bases only: an AES
-- base refuses KEY_TYPE_INCONSISTENT (the oracle's
-- derive-wrong-key-type legs).
caseDeriveKdfWrongKeyType :: IO ()
caseDeriveKdfWrongKeyType = withSynth $ \answer -> do
  m0 <- seedModel >>= loginUser
  st <- getSession m0
  (m1, baseH) <- genAesKey answer m0 st (aesTmpl 32 ++ [(AttrDerive, ValBool True)])
  let tmpl =
        [ (AttrClass, ValULong ckoSecretKey)
        , (AttrKeyType, ValULong ckkGenericSecret)
        , (AttrValueLen, ValULong 16)
        , (AttrToken, ValBool False)
        ]
      mech = MechanismId ckm_SHA256_KEY_DERIVATION
  case planDerive defaultRules m1 st mech baseH (encodeDeriveParams BS.empty [tmpl]) of
    KeyDenied (KeyDeny code _) ->
      assertEqual "AES base" CKR_KEY_TYPE_INCONSISTENT code
    other -> assertFailure ("AES base must not plan: " ++ show other)

casePublishAtomic :: IO ()
casePublishAtomic = do
  m0 <- seedModel
  st <- getSession m0
  let goodAttrs = Map.fromList
        [ (AttrClass, ValULong ckoSecretKey)
        , (AttrKeyType, ValULong ckkAes)
        , (AttrValue, ValBytes "0123456789abcdef")
        ]
      badAttrs = Map.delete AttrClass goodAttrs
      good = pendingFromAttrs st goodAttrs
      bad = PendingObject badAttrs (Just sid1) slot0
  case publishPending m0 st [good, bad] of
    Left (KeyDeny code _) -> assertEqual "bad batch code" CKR_TEMPLATE_INCOMPLETE code
    Right _ -> assertFailure "mixed batch must not publish"
  case publishPending m0 st [good, good] of
    Left deny -> assertFailure ("good batch must publish: " ++ show deny)
    Right (StateDelta ops, [h1, h2]) -> do
      assertEqual "two creates plus two binds" 4 (length ops)
      assertBool "handles differ" (h1 /= h2)
      m1 <- expectRight (publishDelta m0 (StateDelta ops))
      assertEqual "two objects" 2 (Map.size (mObjects m1))
    Right _ -> assertFailure "good batch arity"

casePadMirror :: IO ()
casePadMirror = do
  let samples = ["", "a", "0123456789abcde", "0123456789abcdef", "0123456789abcdefg"]
  mapM_ checkPad samples
  mapM_ checkUnpad
    ["0123456789abcdef\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10", "short", ""]
  where
    checkPad s = assertEqual ("pad " ++ show s) (pkcs7Pad 16 s) (padPkcs7 16 s)
    checkUnpad s = assertEqual ("unpad " ++ show s) (pkcs7Unpad 16 s) (unpadPkcs7 16 s)

-- ---------------------------------------------------------------------------
-- Part 3
-- ---------------------------------------------------------------------------

childTmpl :: Int -> [(AttributeType, AttributeValue)]
childTmpl n =
  [ (AttrClass, ValULong ckoSecretKey)
  , (AttrKeyType, ValULong ckkGenericSecret)
  , (AttrValueLen, ValULong (fromIntegral n))
  , (AttrToken, ValBool False)
  ]

deriveBase :: (Model -> CryptoEffect -> IO CryptoResult)
  -> Model -> SessionState -> IO (Model, ExternalHandle)
deriveBase answer m st = genAesKey answer m st
  [ (AttrClass, ValULong ckoSecretKey)
  , (AttrKeyType, ValULong ckkAes)
  , (AttrValueLen, ValULong 32)
  , (AttrToken, ValBool False)
  , (AttrDerive, ValBool True)
  ]

runDerive :: (Model -> CryptoEffect -> IO CryptoResult)
  -> Model -> SessionState -> ExternalHandle -> ByteString -> Int
  -> IO (Model, [ExternalHandle])
runDerive answer m st baseH blob n = case planDerive defaultRules m st hkdfDeriveMech baseH blob of
  KeyEffect pw fx -> do
    res <- answer m fx
    c <- finishCommit m st pw res n
    hs <- mapM handleOf (pcOutputs c)
    m' <- expectRight (publishDelta m (pcDelta c))
    pure (m', hs)
  other -> assertFailure ("derive plan is not an effect: " ++ show other) >> undefined

caseDeriveMulti :: IO ()
caseDeriveMulti = withSynth $ \answer -> do
  m0 <- seedModel
  st <- getSession m0
  (m1, baseH) <- deriveBase answer m0 st
  let before = Map.size (mObjects m1)
  (m2, [h1, h2, h3]) <- runDerive answer m1 st baseH
    (encodeDeriveParams (encodeHkdfInfo 4 0x02 BS.empty "multi-child") [childTmpl 16, childTmpl 24, childTmpl 32]) 3
  assertEqual "three derived objects" (before + 3) (Map.size (mObjects m2))
  Just o1 <- pure (resolveHandle m2 h1)
  Just o2 <- pure (resolveHandle m2 h2)
  Just o3 <- pure (resolveHandle m2 h3)
  case (keyBytesOf o1, keyBytesOf o2, keyBytesOf o3) of
    (Just m16, Just m24, Just m32) -> do
      assertEqual "first length" 16 (BS.length m16)
      assertEqual "second length" 24 (BS.length m24)
      assertEqual "third length" 32 (BS.length m32)
      -- The multi answer is the concatenation the finisher splits:
      -- a lone 16-byte derive replays the first child's bytes.
      (mSolo, [hsolo]) <- runDerive answer m1 st baseH (encodeDeriveParams (encodeHkdfInfo 4 0x02 BS.empty "multi-child") [childTmpl 16]) 1
      Just osolo <- pure (resolveHandle mSolo hsolo)
      assertEqual "split matches lone derive" (Just m16) (keyBytesOf osolo)
    _ -> assertFailure "derived children lack material"

caseDeriveInvalidExtra :: IO ()
caseDeriveInvalidExtra = withSynth $ \answer -> do
  m0 <- seedModel
  st <- getSession m0
  (m1, baseH) <- deriveBase answer m0 st
  let before = Map.size (mObjects m1)
      badClass = [(AttrClass, ValULong ckoPublicKey), (AttrKeyType, ValULong ckkGenericSecret), (AttrValueLen, ValULong 16)]
      badLen =
        [ (AttrClass, ValULong ckoSecretKey)
        , (AttrKeyType, ValULong ckkGenericSecret)
        , (AttrValueLen, ValULong 0)
        ]
  -- An invalid SECOND template denies the whole derive.
  case planDerive defaultRules m1 st hkdfDeriveMech baseH
      (encodeDeriveParams (encodeHkdfInfo 4 0x02 BS.empty "probe") [childTmpl 32, badClass]) of
    KeyDenied (KeyDeny code _) ->
      assertEqual "wrong class code" CKR_TEMPLATE_INCONSISTENT code
    other -> assertFailure ("bad additional template must deny, got: " ++ show other)
  -- An invalid THIRD template denies the whole derive.
  case planDerive defaultRules m1 st hkdfDeriveMech baseH
      (encodeDeriveParams (encodeHkdfInfo 4 0x02 BS.empty "probe") [childTmpl 16, childTmpl 16, badLen]) of
    KeyDenied (KeyDeny code _) ->
      assertEqual "zero length code" CKR_KEY_SIZE_RANGE code
    other -> assertFailure ("bad additional template must deny, got: " ++ show other)
  -- A malformed frame denies too.
  case planDerive defaultRules m1 st hkdfDeriveMech baseH "truncated" of
    KeyDenied (KeyDeny code _) ->
      assertEqual "malformed frame code" CKR_ARGUMENTS_BAD code
    other -> assertFailure ("malformed frame must deny, got: " ++ show other)
  assertEqual "zero objects published" before (Map.size (mObjects m1))

caseDeriveCodec :: IO ()
caseDeriveCodec = do
  let tmpls = [childTmpl 16, childTmpl 32]
      blob = encodeDeriveParams "info" tmpls
  assertEqual "codec round-trips" (Just ("info", tmpls)) (decodeDeriveParams blob)
  assertEqual "truncated frame" Nothing (decodeDeriveParams (BS.take 7 blob))
  assertEqual "trailing bytes" Nothing (decodeDeriveParams (blob <> "junk"))
  assertEqual "empty blob" Nothing (decodeDeriveParams BS.empty)
  -- A count past the fan-out bound rejects even when well-framed.
  let info = "i" :: ByteString
      over = BS.concat
        [ BS.pack [0, 0, 0, 1], info, BS.pack [0, 17]
        , BS.concat (replicate 17 (BS.pack [0, 0, 0, 0]))
        ]
  assertEqual "fan-out bound" Nothing (decodeDeriveParams over)

-- | Provider P-256 PKCS#8 (pinned openssl CLI output, public
-- half embedded as SEC1 [1]; same vector as RecipePubPrivSpec).
pubPrivP256 :: ByteString
pubPrivP256 = hex
  "308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b0201010420\
  \ea3851e04e9fa14c421e7669f374493c50ea6f3d5ae5c7d57a31812bd779e8fca144\
  \034200040146e4dc41f540fedb82ff563b9c49f92fd69f1f7e2bf4c498287c54b8c70\
  \f2ec528757041bab6c0d808840432f506a84c1d7271fbc068a05fbce16dfdc158d2"

-- | Raw-SEC1 P-256 half in the live keygen shape (121 bytes;
-- same vector as RecipePubPrivSpec): this is what a generated
-- key's CKA_VALUE carries.
pubPrivSec1P256 :: ByteString
pubPrivSec1P256 =
  hex "30770201010420" <> BS.replicate 32 0x51
    <> hex "a00a06082a8648ce3d030107a14403420004" <> BS.replicate 64 0x52

-- | Scalar-only raw SEC1 (no @[1]@): version, scalar, params.
pubPrivSec1ScalarP256 :: ByteString
pubPrivSec1ScalarP256 =
  hex "30310201010420" <> BS.replicate 32 0x51
    <> hex "a00a06082a8648ce3d030107"

casePubPrivRsa :: IO ()
casePubPrivRsa = withSynth $ \answer -> do
  m0 <- seedModel >>= loginUser
  st <- getSession m0
  -- CKA_DERIVE false on purpose: the row ignores the mark.
  let privT = rsaPrivTmpl ++ [(AttrDecrypt, ValBool True), (AttrDerive, ValBool False)]
  (m1, _pubH, privH) <- genRsaPair answer m0 st rsaPubTmpl privT
  let tmpl =
        [ (AttrClass, ValULong ckoPublicKey)
        , (AttrKeyType, ValULong ckkRsa)
        , (AttrToken, ValBool False)
        , (AttrLabel, ValBytes "custom")
        ]
      blob = encodeDeriveParams BS.empty [tmpl]
  case planDerive defaultRules m1 st pubPrivMech privH blob of
    KeyEffect pw fx -> do
      res <- answer m1 fx
      c <- finishCommit m1 st pw res 1
      h <- handleOf (pcOutputs c !! 0)
      m2 <- expectRight (publishDelta m1 (pcDelta c))
      Just ost <- pure (resolveHandle m2 h)
      assertEqual "class" (Just (ValULong ckoPublicKey))
        (Map.lookup AttrClass (osAttrs ost))
      assertEqual "type" (Just (ValULong ckkRsa))
        (Map.lookup AttrKeyType (osAttrs ost))
      assertEqual "encrypt reflects decrypt" (Just (ValBool True))
        (Map.lookup AttrEncrypt (osAttrs ost))
      assertEqual "token forced" (Just (ValBool False))
        (Map.lookup AttrToken (osAttrs ost))
      assertEqual "template wins over map default" (Just (ValBytes "custom"))
        (Map.lookup AttrLabel (osAttrs ost))
      assertBool "material stored" (isJust (keyBytesOf ost))
    other -> assertFailure ("pubpriv plan is not an effect: " ++ show other)

casePubPrivEc :: IO ()
casePubPrivEc = withSynth $ \answer -> do
  m0 <- seedModel >>= loginUser
  st <- getSession m0
  let oid = hex "06082a8648ce3d030107"
      privT =
        [ (AttrClass, ValULong ckoPrivateKey)
        , (AttrKeyType, ValULong ckkEc)
        , (AttrEcParams, ValBytes oid)
        , (AttrToken, ValBool False)
        , (AttrDerive, ValBool False)
        ]
      tmpl =
        [ (AttrClass, ValULong ckoPublicKey)
        , (AttrKeyType, ValULong ckkEc)
        , (AttrToken, ValBool False)
        ]
      blob = encodeDeriveParams BS.empty [tmpl]
  -- The live keygen shape is raw SEC1; PKCS#8 with an embedded
  -- half plans too. Scalar-only halves in either framing
  -- refuse: y-recovery is Fp math.
  (m1, privH) <- plantKey m0 st privT pubPrivSec1P256
  case planDerive defaultRules m1 st pubPrivMech privH blob of
    KeyEffect pw fx -> do
      res <- answer m1 fx
      c <- finishCommit m1 st pw res 1
      h <- handleOf (pcOutputs c !! 0)
      m2 <- expectRight (publishDelta m1 (pcDelta c))
      Just ost <- pure (resolveHandle m2 h)
      assertEqual "class" (Just (ValULong ckoPublicKey))
        (Map.lookup AttrClass (osAttrs ost))
      assertEqual "params copied from base" (Just (ValBytes oid))
        (Map.lookup AttrEcParams (osAttrs ost))
      -- Synthetic answers opaque halves: the finisher passes
      -- them through unstamped (the keygen stamping precedent).
      assertEqual "point unstamped on synthetic" Nothing
        (Map.lookup AttrEcPoint (osAttrs ost))
    other -> assertFailure ("pubpriv plan is not an effect: " ++ show other)
  (m3, privHP8) <- plantKey m1 st privT pubPrivP256
  case planDerive defaultRules m3 st pubPrivMech privHP8 blob of
    KeyEffect {} -> pure ()
    other -> assertFailure ("pkcs8 embedded refused, got: " ++ show other)
  (m4, privH2) <- plantKey m3 st privT (ecPrivateDer oid (BS.replicate 32 0x51))
  case planDerive defaultRules m4 st pubPrivMech privH2 blob of
    KeyDenied d -> assertEqual "scalar code" CKR_TEMPLATE_INCOMPLETE (kdCode d)
    other -> assertFailure ("scalar-only accepted, got: " ++ show other)
  (m5, privH3) <- plantKey m4 st privT pubPrivSec1ScalarP256
  case planDerive defaultRules m5 st pubPrivMech privH3 blob of
    KeyDenied d -> assertEqual "sec1 scalar code" CKR_TEMPLATE_INCOMPLETE (kdCode d)
    other -> assertFailure ("sec1 scalar-only accepted, got: " ++ show other)

casePubPrivEcSpkiStamp :: IO ()
casePubPrivEcSpkiStamp = do
  m0 <- seedModel >>= loginUser
  st <- getSession m0
  let oid = hex "06082a8648ce3d030107"
      point = BS.pack (0x04 : [1 .. 64])
      spki = ecPublicDer oid point
      -- Live keygen shape: the private half carries no
      -- EC_PARAMS (params ride the public template only).
      privT =
        [ (AttrClass, ValULong ckoPrivateKey)
        , (AttrKeyType, ValULong ckkEc)
        , (AttrToken, ValBool False)
        ]
      tmpl =
        [ (AttrClass, ValULong ckoPublicKey)
        , (AttrKeyType, ValULong ckkEc)
        , (AttrToken, ValBool False)
        ]
      blob = encodeDeriveParams BS.empty [tmpl]
  (m1, privH) <- plantKey m0 st privT pubPrivSec1P256
  case planDerive defaultRules m1 st pubPrivMech privH blob of
    KeyEffect pw _fx -> do
      c <- finishCommit m1 st pw (GotBytes spki) 1
      h <- handleOf (pcOutputs c !! 0)
      m2 <- expectRight (publishDelta m1 (pcDelta c))
      case resolveHandle m2 h of
        Nothing -> assertFailure "derived handle unpublished"
        Just ost -> do
          assertEqual "point stamped"
            (Just (ValBytes ("\x04\x41" <> point)))
            (Map.lookup AttrEcPoint (osAttrs ost))
          assertEqual "params stamped from SPKI" (Just (ValBytes oid))
            (Map.lookup AttrEcParams (osAttrs ost))
    other -> assertFailure ("pubpriv plan is not an effect: " ++ show other)

casePubPrivRefusals :: IO ()
casePubPrivRefusals = withSynth $ \_answer -> do
  m0 <- seedModel >>= loginUser
  st <- getSession m0
  let rsaBase =
        [ (AttrClass, ValULong ckoPrivateKey)
        , (AttrKeyType, ValULong ckkRsa)
        , (AttrToken, ValBool False)
        ]
      rsaTmpl =
        [ (AttrClass, ValULong ckoPublicKey)
        , (AttrKeyType, ValULong ckkRsa)
        , (AttrToken, ValBool False)
        ]
      denyCode m baseH b = case planDerive defaultRules m st pubPrivMech baseH b of
        KeyDenied d -> pure (kdCode d)
        other -> assertFailure ("refusal expected, got: " ++ show other) >> undefined
  (m1, rsaH) <- plantKey m0 st rsaBase "opaque-rsa-half"
  let blob0 = encodeDeriveParams BS.empty [rsaTmpl]
  -- Out-of-scope key types refuse type-inconsistent.
  (m2, dsaH) <- plantKey m1 st
    [(AttrClass, ValULong ckoPrivateKey), (AttrKeyType, ValULong ckkDsa), (AttrToken, ValBool False)]
    "opaque-dsa-half"
  c1 <- denyCode m2 dsaH blob0
  assertEqual "dsa code" CKR_KEY_TYPE_INCONSISTENT c1
  (m3, dhH) <- plantKey m2 st
    [(AttrClass, ValULong ckoPrivateKey), (AttrKeyType, ValULong ckkDh), (AttrToken, ValBool False)]
    "opaque-dh-half"
  c2 <- denyCode m3 dhH blob0
  assertEqual "dh code" CKR_KEY_TYPE_INCONSISTENT c2
  (m4, kemH) <- plantKey m3 st
    [(AttrClass, ValULong ckoPrivateKey), (AttrKeyType, ValULong ckkMlKem), (AttrToken, ValBool False)]
    "opaque-kem-half"
  c3 <- denyCode m4 kemH blob0
  assertEqual "pqc code" CKR_KEY_TYPE_INCONSISTENT c3
  -- A public base is a class contradiction.
  (m5, pubH) <- plantKey m4 st
    [(AttrClass, ValULong ckoPublicKey), (AttrKeyType, ValULong ckkRsa), (AttrToken, ValBool False)]
    "opaque-rsa-pub"
  c4 <- denyCode m5 pubH blob0
  assertEqual "class code" CKR_TEMPLATE_INCONSISTENT c4
  -- Non-empty params refuse.
  c5 <- denyCode m5 rsaH (encodeDeriveParams "params" [rsaTmpl])
  assertEqual "params code" CKR_ARGUMENTS_BAD c5
  -- Template count is exactly one.
  c6 <- denyCode m5 rsaH (encodeDeriveParams BS.empty [])
  assertEqual "zero templates code" CKR_ARGUMENTS_BAD c6
  c7 <- denyCode m5 rsaH (encodeDeriveParams BS.empty [rsaTmpl, rsaTmpl])
  assertEqual "two templates code" CKR_ARGUMENTS_BAD c7
  -- Template class/type must fit the derivation.
  let rsaSecretTmpl =
        [ (AttrClass, ValULong ckoSecretKey)
        , (AttrKeyType, ValULong ckkRsa)
        , (AttrToken, ValBool False)
        ]
  c8 <- denyCode m5 rsaH (encodeDeriveParams BS.empty [rsaSecretTmpl])
  assertEqual "class fit code" CKR_TEMPLATE_INCONSISTENT c8
  let ecTmpl =
        [ (AttrClass, ValULong ckoPublicKey)
        , (AttrKeyType, ValULong ckkEc)
        , (AttrToken, ValBool False)
        ]
  c9 <- denyCode m5 rsaH (encodeDeriveParams BS.empty [ecTmpl])
  assertEqual "type fit code" CKR_TEMPLATE_INCONSISTENT c9
  -- Unknown handles refuse.
  c10 <- denyCode m5 (ExternalHandle 99999) blob0
  assertEqual "handle code" CKR_KEY_HANDLE_INVALID c10

caseHkdfInfoCodec :: IO ()
caseHkdfInfoCodec = do
  let framed = encodeHkdfInfo 4 0x03 "salt" "context"
  assertEqual "codec round-trips"
    (Just (4, 0x03, "salt", "context")) (decodeHkdfInfo framed)
  assertEqual "expand-only round-trips"
    (Just (4, 0x02, BS.empty, "ctx")) (decodeHkdfInfo (encodeHkdfInfo 4 0x02 BS.empty "ctx"))
  assertEqual "sha512 prf round-trips"
    (Just (6, 0x03, "salt", "context"))
    (decodeHkdfInfo (encodeHkdfInfo 6 0x03 "salt" "context"))
  assertEqual "unknown prf refused" Nothing
    (decodeHkdfInfo (encodeHkdfInfo 99 0x03 "salt" "context"))
  assertEqual "zero prf refused" Nothing
    (decodeHkdfInfo (encodeHkdfInfo 0 0x03 "salt" "context"))
  assertEqual "no stage selected" Nothing (decodeHkdfInfo (encodeHkdfInfo 4 0x00 BS.empty "ctx"))
  assertEqual "reserved mode bit" Nothing (decodeHkdfInfo (encodeHkdfInfo 4 0x04 BS.empty "ctx"))
  assertEqual "truncated frame" Nothing (decodeHkdfInfo (BS.take 2 framed))
  -- The context takes the remainder by design; exact consumption
  -- is the outer derive frame's job (pinned by caseDeriveCodec).
  assertEqual "truncated salt" Nothing
    (decodeHkdfInfo (BS.take 8 (encodeHkdfInfo 4 0x03 "salty" "context")))
  assertEqual "empty blob" Nothing (decodeHkdfInfo BS.empty)

-- ---------------------------------------------------------------------------
-- Part 4
-- ---------------------------------------------------------------------------

runEncaps :: (Model -> CryptoEffect -> IO CryptoResult)
  -> Model -> SessionState -> ExternalHandle -> IO (Model, ByteString, ByteString)
runEncaps answer m st pubH = do
  let ctLen = kemCtLen KemMl768
  case planKemEncaps m st mlKemMech pubH KemMl768 secretTmpl
      (IntentBuffer (fromIntegral ctLen)) of
    KeyEffect pw fx -> do
      res <- answer m fx
      c <- finishCommit m st pw res 1
      ct <- case pcOutputs c !! 0 of
        NativeOutput (RegionBytes "ciphertext" _) bs -> pure bs
        o -> assertFailure ("no ciphertext: " ++ show o) >> undefined
      h <- handleOf (pcOutputs c !! 1)
      m' <- expectRight (publishDelta m (pcDelta c))
      Just ost <- pure (resolveHandle m' h)
      case keyBytesOf ost of
        Just ss -> pure (m', ct, ss)
        Nothing -> assertFailure "secret lacks material" >> undefined
    other -> assertFailure ("encaps plan is not an effect: " ++ show other) >> undefined

caseKemDecaps :: IO ()
caseKemDecaps = withSynth $ \answer -> do
  m0 <- seedModel >>= loginUser
  st <- getSession m0
  (m1, pubH, privH) <- genKemPair answer m0 st
  (m2, ct, ssEnc) <- runEncaps answer m1 st pubH
  let before = Map.size (mObjects m2)
  case planKemDecaps m2 st mlKemMech privH KemMl768 ct secretTmpl of
    KeyEffect pw fx -> do
      res <- answer m2 fx
      c <- finishCommit m2 st pw res 1
      assertEqual "decaps outputs exactly one handle" 1 (length (pcOutputs c))
      h <- handleOf (pcOutputs c !! 0)
      m3 <- expectRight (publishDelta m2 (pcDelta c))
      assertEqual "exactly one object" (before + 1) (Map.size (mObjects m3))
      Just ost <- pure (resolveHandle m3 h)
      assertEqual "decaps recovers the encaps secret" (Just ssEnc) (keyBytesOf ost)
      assertEqual "secret class" (Just (ValULong ckoSecretKey))
        (Map.lookup AttrClass (osAttrs ost))
    other -> assertFailure ("decaps plan is not an effect: " ++ show other)

caseKemMismatch :: IO ()
caseKemMismatch = withSynth $ \answer -> do
  m0 <- seedModel >>= loginUser
  st <- getSession m0
  (m1, pubH, privH) <- genKemPair answer m0 st
  (m2, _, privH2) <- genKemPair answer m1 st
  (m3, ct, _) <- runEncaps answer m2 st pubH
  let before = Map.size (mObjects m3)
  -- Decaps under the WRONG private key fails closed.
  case planKemDecaps m3 st mlKemMech privH2 KemMl768 ct secretTmpl of
    KeyEffect pw fx -> do
      res <- answer m3 fx
      case finishWork m3 st pw res of
        Reject r -> do
          assertEqual "wrong-key code" CKR_ENCRYPTED_DATA_INVALID (rejCode r)
          assertEqual "zero objects" (StateDelta []) (rejDelta r)
        other -> assertFailure ("wrong-key decaps must reject, got: " ++ show other)
    other -> assertFailure ("decaps plan is not an effect: " ++ show other)
  -- A tampered ciphertext fails closed.
  let bad = BS.map complement ct
  case planKemDecaps m3 st mlKemMech privH KemMl768 bad secretTmpl of
    KeyEffect pw fx -> do
      res <- answer m3 fx
      case finishWork m3 st pw res of
        Reject r -> assertEqual "tampered code" CKR_ENCRYPTED_DATA_INVALID (rejCode r)
        other -> assertFailure ("tampered decaps must reject, got: " ++ show other)
    other -> assertFailure ("decaps plan is not an effect: " ++ show other)
  -- A short ciphertext is a length-range refusal with no
  -- effect planned (the cipher/dual precedent for wrong-length
  -- crypto inputs, and the oracle's expected code).
  case planKemDecaps m3 st mlKemMech privH KemMl768 "short" secretTmpl of
    KeyDenied (KeyDeny code _) ->
      assertEqual "short ct code" CKR_ENCRYPTED_DATA_LEN_RANGE code
    other -> assertFailure ("short ct must deny, got: " ++ show other)
  assertEqual "zero objects published" before (Map.size (mObjects m3))

caseWrapMismatch :: IO ()
caseWrapMismatch = withSynth $ \answer -> do
  m0 <- seedModel >>= loginUser
  st <- getSession m0
  (m1, wrapH) <- genAesKey answer m0 st wrapKeyTmpl
  (m2, targetH) <- genAesKey answer m1 st (aesTmpl 16)
  let before = Map.size (mObjects m2)
      tmpl = [(AttrClass, ValULong ckoSecretKey), (AttrKeyType, ValULong ckkAes)]
  -- NOTE: a plain-wrap wrong-key outcome is padding luck (CBC has no
  -- integrity), so fail-closed key mismatch is tested on the
  -- authenticated wrap, which binds a tag. Here the deterministic
  -- parameter and usage/shape refuses:
  -- A short IV is a parameter refusal.
  case planWrapKey m2 st aesCbcMech "short" wrapH targetH (IntentBuffer 32) of
    KeyDenied (KeyDeny code _) ->
      assertEqual "short IV code" CKR_ARGUMENTS_BAD code
    other -> assertFailure ("short IV must deny, got: " ++ show other)
  -- A ragged blob is a parameter refusal.
  case planUnwrapKey defaultRules m2 st aesCbcMech iv16 wrapH "15-bytes-blob!!" tmpl of
    KeyDenied (KeyDeny code _) ->
      assertEqual "ragged blob code" CKR_ARGUMENTS_BAD code
    other -> assertFailure ("ragged blob must deny, got: " ++ show other)
  -- A key marked non-wrapping cannot wrap (absent flags default
  -- true at keygen, so the refusal needs an explicit false).
  (m3, plainH) <- genAesKey answer m2 st (aesTmpl 32 ++ [(AttrWrap, ValBool False)])
  case planWrapKey m3 st aesCbcMech iv16 plainH targetH (IntentBuffer 32) of
    KeyDenied (KeyDeny code _) ->
      assertEqual "no-wrap-mark code" CKR_KEY_FUNCTION_NOT_PERMITTED code
    other -> assertFailure ("unmarked wrap must deny, got: " ++ show other)
  -- An unextractable target cannot wrap.
  (m4, sealedH) <- genAesKey answer m3 st
    [ (AttrClass, ValULong ckoSecretKey)
    , (AttrKeyType, ValULong ckkAes)
    , (AttrValueLen, ValULong 16)
    , (AttrToken, ValBool False)
    , (AttrExtractable, ValBool False)
    ]
  case planWrapKey m4 st aesCbcMech iv16 wrapH sealedH (IntentBuffer 32) of
    KeyDenied (KeyDeny code _) ->
      assertEqual "sealed code" CKR_KEY_UNEXTRACTABLE code
    other -> assertFailure ("sealed wrap must deny, got: " ++ show other)
  -- A material-less object is not wrappable.
  let bareAttrs = Map.fromList
        [ (AttrClass, ValULong ckoSecretKey)
        , (AttrKeyType, ValULong ckkAes)
        , (AttrExtractable, ValBool True)
        ]
  (m5, bareH) <- case publishPending m4 st [pendingFromAttrs st bareAttrs] of
    Left deny -> assertFailure ("plant must publish: " ++ show deny) >> undefined
    Right (delta, [h]) -> do
      m' <- expectRight (publishDelta m4 delta)
      pure (m', h)
    Right _ -> assertFailure "plant arity" >> undefined
  case planWrapKey m5 st aesCbcMech iv16 wrapH bareH (IntentBuffer 32) of
    KeyDenied (KeyDeny code _) ->
      assertEqual "bare code" CKR_KEY_NOT_WRAPPABLE code
    other -> assertFailure ("bare wrap must deny, got: " ++ show other)
  assertEqual "zero objects from denies" (before + 3) (Map.size (mObjects m5))

caseWrapKeyTypeGate :: IO ()
caseWrapKeyTypeGate = withSynth $ \answer -> do
  m0 <- seedModel >>= loginUser
  st <- getSession m0
  -- An EC private key carrying the wrap/unwrap marks: the marks
  -- pass, but the key type must refuse (AES-CBC wrap takes an AES
  -- secret key only — never foreign key material).
  let ecWrapTmpl = ecPrivTmpl ++ [(AttrWrap, ValBool True), (AttrUnwrap, ValBool True)]
  (m1, privH) <- case planGenerateKeyPair defaultRules m0 st ecKeyPairGenMech ecPubTmpl ecWrapTmpl of
    KeyEffect pw fx -> do
      res <- answer m0 fx
      c <- finishCommit m0 st pw res 2
      h <- handleOf (pcOutputs c !! 1)
      m' <- expectRight (publishDelta m0 (pcDelta c))
      pure (m', h)
    other -> assertFailure ("EC keypair plan is not an effect: " ++ show other) >> undefined
  (m2, targetH) <- genAesKey answer m1 st (aesTmpl 16)
  case planWrapKey m2 st aesCbcMech iv16 privH targetH (IntentBuffer 64) of
    KeyDenied (KeyDeny code _) ->
      assertEqual "wrap key-type code" CKR_WRAPPING_KEY_TYPE_INCONSISTENT code
    other -> assertFailure ("EC wrap must deny, got: " ++ show other)
  let tmpl =
        [ (AttrClass, ValULong ckoSecretKey)
        , (AttrKeyType, ValULong ckkAes)
        , (AttrToken, ValBool False)
        ]
  case planUnwrapKey defaultRules m2 st aesCbcMech iv16 privH (BS.replicate 32 0) tmpl of
    KeyDenied (KeyDeny code _) ->
      assertEqual "unwrap key-type code" CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT code
    other -> assertFailure ("EC unwrap must deny, got: " ++ show other)
  -- A generic-secret key with the marks (the oracle's exact
  -- wrong-key setup: negotiated import, not keygen) refuses the
  -- same way.
  (m3, genH) <- plantKey m2 st
    [ (AttrClass, ValULong ckoSecretKey)
    , (AttrKeyType, ValULong ckkGenericSecret)
    , (AttrToken, ValBool False)
    , (AttrWrap, ValBool True)
    , (AttrUnwrap, ValBool True)
    ]
    (BS.replicate 32 0x42)
  case planWrapKey m3 st aesCbcMech iv16 genH targetH (IntentBuffer 64) of
    KeyDenied (KeyDeny code _) ->
      assertEqual "generic wrap key-type code" CKR_WRAPPING_KEY_TYPE_INCONSISTENT code
    other -> assertFailure ("generic wrap must deny, got: " ++ show other)
  case planUnwrapKey defaultRules m3 st aesCbcMech iv16 genH (BS.replicate 32 0) tmpl of
    KeyDenied (KeyDeny code _) ->
      assertEqual "generic unwrap key-type code" CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT code
    other -> assertFailure ("generic unwrap must deny, got: " ++ show other)
  -- An RSA private half refuses too (no silent use of
  -- asymmetric material as a block-cipher key).
  (m4, rsaH) <- plantKey m3 st
    [ (AttrClass, ValULong ckoPrivateKey)
    , (AttrKeyType, ValULong ckkRsa)
    , (AttrToken, ValBool False)
    , (AttrWrap, ValBool True)
    ]
    (BS.replicate 32 0x43)
  case planWrapKey m4 st aesCbcMech iv16 rsaH targetH (IntentBuffer 64) of
    KeyDenied (KeyDeny code _) ->
      assertEqual "RSA wrap key-type code" CKR_WRAPPING_KEY_TYPE_INCONSISTENT code
    other -> assertFailure ("RSA wrap must deny, got: " ++ show other)
  -- The authenticated paths share the gate (all four
  -- 'withWrappingKey' call sites).
  let aad = "associated-data"
  case planAuthWrapKey m4 st aesCbcMech iv16 privH targetH aad (IntentBuffer 64) of
    KeyDenied (KeyDeny code _) ->
      assertEqual "auth-wrap key-type code" CKR_WRAPPING_KEY_TYPE_INCONSISTENT code
    other -> assertFailure ("EC auth-wrap must deny, got: " ++ show other)
  case planAuthUnwrapKey defaultRules m4 st aesCbcMech iv16 privH (BS.replicate 48 0) aad tmpl of
    KeyDenied (KeyDeny code _) ->
      assertEqual "auth-unwrap key-type code" CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT code
    other -> assertFailure ("EC auth-unwrap must deny, got: " ++ show other)

caseAuthWrapMismatch :: IO ()
caseAuthWrapMismatch = withSynth $ \answer -> do
  m0 <- seedModel >>= loginUser
  st <- getSession m0
  (m1, wrapH) <- genAesKey answer m0 st wrapKeyTmpl
  (m2, wrapH2) <- genAesKey answer m1 st wrapKeyTmpl
  (m3, targetH) <- genAesKey answer m2 st (aesTmpl 16)
  let aad = "wrap-aad"
  blob <- case planAuthWrapKey m3 st aesCbcMech iv16 wrapH targetH aad (IntentBuffer 64) of
    KeyEffect pw fx -> do
      res <- answer m3 fx
      case finishWork m3 st pw res of
        Immediate c -> case pcOutputs c of
          [NativeOutput (RegionBytes "wrapped" _) bs] -> pure bs
          o -> assertFailure ("one blob: " ++ show o) >> undefined
        other -> assertFailure ("wrap must commit: " ++ show other) >> undefined
    other -> assertFailure ("wrap must plan: " ++ show other) >> undefined
  let before = Map.size (mObjects m3)
      tmpl = [(AttrClass, ValULong ckoSecretKey), (AttrKeyType, ValULong ckkAes)]
  -- Wrong AAD fails closed.
  case planAuthUnwrapKey defaultRules m3 st aesCbcMech iv16 wrapH blob "wrong-aad" tmpl of
    KeyEffect pw fx -> do
      res <- answer m3 fx
      case finishWork m3 st pw res of
        Reject r -> do
          assertEqual "wrong-AAD code" CKR_ENCRYPTED_DATA_INVALID (rejCode r)
          assertEqual "zero objects" (StateDelta []) (rejDelta r)
        other -> assertFailure ("wrong-AAD unwrap must reject, got: " ++ show other)
    other -> assertFailure ("unwrap must plan: " ++ show other)
  -- A tampered blob fails closed.
  let bad = BS.map complement blob
  case planAuthUnwrapKey defaultRules m3 st aesCbcMech iv16 wrapH bad aad tmpl of
    KeyEffect pw fx -> do
      res <- answer m3 fx
      case finishWork m3 st pw res of
        Reject r -> assertEqual "tampered code" CKR_ENCRYPTED_DATA_INVALID (rejCode r)
        other -> assertFailure ("tampered unwrap must reject, got: " ++ show other)
    other -> assertFailure ("unwrap must plan: " ++ show other)
  -- The WRONG wrapping key fails closed (the tag binds the key).
  case planAuthUnwrapKey defaultRules m3 st aesCbcMech iv16 wrapH2 blob aad tmpl of
    KeyEffect pw fx -> do
      res <- answer m3 fx
      case finishWork m3 st pw res of
        Reject r -> do
          assertEqual "wrong-key code" CKR_ENCRYPTED_DATA_INVALID (rejCode r)
          assertEqual "zero objects" (StateDelta []) (rejDelta r)
        other -> assertFailure ("wrong-key unwrap must reject, got: " ++ show other)
    other -> assertFailure ("unwrap must plan: " ++ show other)
  assertEqual "zero objects published" before (Map.size (mObjects m3))

caseInitFromObject :: IO ()
caseInitFromObject = withSynth $ \answer -> do
  mSeed <- seedModel
  m0 <- loginUser mSeed
  stPublic <- getSession mSeed
  st <- getSession m0
  -- A key permitting encrypt but not decrypt.
  (m1, keyH) <- genAesKey answer m0 st
    [ (AttrClass, ValULong ckoSecretKey)
    , (AttrKeyType, ValULong ckkAes)
    , (AttrValueLen, ValULong 32)
    , (AttrToken, ValBool False)
    , (AttrEncrypt, ValBool True)
    , (AttrDecrypt, ValBool False)
    ]
  let env = OpEnv
        { oeRegistry = curatedRegistry
        , oeCaps = mkCapabilities [(aesCbcMech, OpEncrypt), (aesCbcMech, OpDecrypt)]
        , oeModel = m1
        }
      mkArgs op permits auth = InitArgs
        { iaOp = op
        , iaMech = aesCbcMech
        , iaParams = iv16
        , iaKey = Just (KeyPolicy keyH permits auth)
        , iaCipher = Just (CipherSpec 16 False)
        , iaRecover = Nothing
        }
  -- The object permits encrypt even when the caller claims nothing.
  let (_, encNone) = initOperation env emptySessionOps st (mkArgs OpEncrypt [] False)
  assertEqual "object permits encrypt" CKR_OK (ioCode encNone)
  -- The object forbids decrypt even when the caller claims it.
  let (_, decClaim) = initOperation env emptySessionOps st (mkArgs OpDecrypt [OpDecrypt] False)
  assertEqual "object forbids decrypt" CKR_KEY_FUNCTION_NOT_PERMITTED (ioCode decClaim)
  -- The object policy reads back directly (absent flags defaulted
  -- true at keygen; the explicit Decrypt=false stays out, as do
  -- the rule-forbidden encapsulate flags on AES secrets).
  Just ost <- pure (resolveHandle m1 keyH)
  assertEqual "policy from object"
    (Just ([OpEncrypt, OpSign, OpVerify, OpWrap, OpUnwrap, OpDerive], False))
    (policyFromObject ost)
  -- Legacy objects without usage attributes still honor the caller.
  let legacyAttrs = Map.fromList
        [ (AttrClass, ValULong ckoSecretKey)
        , (AttrToken, ValBool False)
        ]
  (m2, legacyH) <- case publishPending m1 st [pendingFromAttrs st legacyAttrs] of
    Left deny -> assertFailure ("plant must publish: " ++ show deny) >> undefined
    Right (delta, [h]) -> do
      m' <- expectRight (publishDelta m1 delta)
      pure (m', h)
    Right _ -> assertFailure "plant arity" >> undefined
  let env2 = env { oeModel = m2 }
      mkLegacy op permits auth = InitArgs
        { iaOp = op
        , iaMech = aesCbcMech
        , iaParams = iv16
        , iaKey = Just (KeyPolicy legacyH permits auth)
        , iaCipher = Just (CipherSpec 16 False)
        , iaRecover = Nothing
        }
  let (_, legYes) = initOperation env2 emptySessionOps st (mkLegacy OpEncrypt [OpEncrypt] False)
  assertEqual "legacy honors caller permit" CKR_OK (ioCode legYes)
  let (_, legNo) = initOperation env2 emptySessionOps st (mkLegacy OpEncrypt [] False)
  assertEqual "legacy honors caller denial" CKR_KEY_FUNCTION_NOT_PERMITTED (ioCode legNo)
  Just lost <- pure (resolveHandle m2 legacyH)
  assertEqual "no policy without attrs" Nothing (policyFromObject lost)
  -- An always-authenticate key needs a user login however the
  -- caller marks it; the public session cannot use it.
  (m3, authH) <- genAesKey answer m2 st
    [ (AttrClass, ValULong ckoSecretKey)
    , (AttrKeyType, ValULong ckkAes)
    , (AttrValueLen, ValULong 32)
    , (AttrToken, ValBool False)
    , (AttrEncrypt, ValBool True)
    , (AttrAlwaysAuthenticate, ValBool True)
    ]
  let env3 = env { oeModel = m3 }
      mkAuth loginH permits auth = InitArgs
        { iaOp = OpEncrypt
        , iaMech = aesCbcMech
        , iaParams = iv16
        , iaKey = Just (KeyPolicy loginH permits auth)
        , iaCipher = Just (CipherSpec 16 False)
        , iaRecover = Nothing
        }
  let (_, authPub) = initOperation env3 emptySessionOps stPublic (mkAuth authH [OpEncrypt] False)
  assertEqual "object demands login" CKR_USER_NOT_LOGGED_IN (ioCode authPub)
  let (_, authUser) = initOperation env3 emptySessionOps st (mkAuth authH [] False)
  assertEqual "login satisfies object" CKR_OK (ioCode authUser)

caseAttrsLand :: IO ()
caseAttrsLand = withSynth $ \answer -> do
  m0 <- seedModel >>= loginUser
  st <- getSession m0
  (m1, wrapH) <- genAesKey answer m0 st wrapKeyTmpl
  (m2, targetH) <- genAesKey answer m1 st (aesTmpl 16)
  blob <- case planWrapKey m2 st aesCbcMech iv16 wrapH targetH (IntentBuffer 32) of
    KeyEffect pw fx -> do
      res <- answer m2 fx
      case finishWork m2 st pw res of
        Immediate c -> case pcOutputs c of
          [NativeOutput (RegionBytes "wrapped" _) bs] -> pure bs
          o -> assertFailure ("one blob: " ++ show o) >> undefined
        other -> assertFailure ("wrap must commit: " ++ show other) >> undefined
    other -> assertFailure ("wrap must plan: " ++ show other) >> undefined
  -- Unwrap template flags land verbatim; unnamed flags stay absent
  -- (absent reads as false in every usage check).
  let tmpl =
        [ (AttrClass, ValULong ckoSecretKey)
        , (AttrKeyType, ValULong ckkAes)
        , (AttrToken, ValBool True)
        , (AttrWrap, ValBool True)
        , (AttrUnwrap, ValBool False)
        ]
  case planUnwrapKey defaultRules m2 st aesCbcMech iv16 wrapH blob tmpl of
    KeyEffect pw fx -> do
      res <- answer m2 fx
      c <- finishCommit m2 st pw res 1
      h <- handleOf (pcOutputs c !! 0)
      m3 <- expectRight (publishDelta m2 (pcDelta c))
      Just ost <- pure (resolveHandle m3 h)
      assertEqual "wrap landed" (Just (ValBool True)) (Map.lookup AttrWrap (osAttrs ost))
      assertEqual "unwrap landed" (Just (ValBool False)) (Map.lookup AttrUnwrap (osAttrs ost))
      assertEqual "unnamed stays absent" Nothing (Map.lookup AttrEncrypt (osAttrs ost))
      assertEqual "token object" Nothing (osOwner ost)
    other -> assertFailure ("unwrap must plan: " ++ show other)
  -- Derive children likewise carry their template flags.
  (m4, baseH) <- deriveBase answer m2 st
  let kid =
        [ (AttrClass, ValULong ckoSecretKey)
        , (AttrKeyType, ValULong ckkGenericSecret)
        , (AttrValueLen, ValULong 16)
        , (AttrToken, ValBool False)
        , (AttrSign, ValBool True)
        , (AttrVerify, ValBool False)
        ]
  (m5, [dh]) <- runDerive answer m4 st baseH (encodeDeriveParams (encodeHkdfInfo 4 0x02 BS.empty "derive-attrs") [kid]) 1
  Just dost <- pure (resolveHandle m5 dh)
  assertEqual "sign landed" (Just (ValBool True)) (Map.lookup AttrSign (osAttrs dost))
  assertEqual "verify landed" (Just (ValBool False)) (Map.lookup AttrVerify (osAttrs dost))

-- ---------------------------------------------------------------------------
-- Part 5: real-backend proofs (implemented capabilities only)
-- ---------------------------------------------------------------------------

-- SP 800-38A F.2.5 AES-256-CBC vector.
spKey, spIv, spP1, spC1 :: ByteString
spKey = hex "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"
spIv = hex "000102030405060708090a0b0c0d0e0f"
spP1 = hex "6bc1bee22e409f96e93d7e117393172a"
spC1 = hex "f58c4c04d6e5f1ba779eabfb5f7bfbd6"

-- RFC 5869 A.1 Test Case 1 (SHA-256): our construction runs Expand
-- over the base key bytes, so the base carries the RFC PRK and the
-- derived 42 bytes must equal the RFC OKM. Vector confirmed with an
-- independent Python implementation before embedding.
rfcPrk, rfcInfo, rfcOkm :: ByteString
rfcPrk = hex "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
rfcInfo = hex "f0f1f2f3f4f5f6f7f8f9"
rfcOkm = hex "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
rfcIkm, rfcSalt, rfcOkmZeroSalt :: ByteString
rfcIkm = hex "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"
rfcSalt = hex "000102030405060708090a0b0c"
rfcOkmZeroSalt = hex "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"

caseRealEcKeygen :: IO ()
caseRealEcKeygen = withRealEnv $ \env -> do
  m0 <- seedModel
  st <- getSession m0
  let answer = answerReal env
  (m1, pubH, privH) <- case planGenerateKeyPair defaultRules m0 st ecKeyPairGenMech ecPubTmpl ecPrivTmpl of
    KeyEffect pw fx -> do
      res <- answer m0 fx
      c <- finishCommit m0 st pw res 2
      h1 <- handleOf (pcOutputs c !! 0)
      h2 <- handleOf (pcOutputs c !! 1)
      m' <- expectRight (publishDelta m0 (pcDelta c))
      pure (m', h1, h2)
    other -> assertFailure ("EC plan is not an effect: " ++ show other) >> undefined
  Just pub <- pure (resolveHandle m1 pubH)
  Just priv <- pure (resolveHandle m1 privH)
  case (keyBytesOf pub, keyBytesOf priv) of
    (Just pubB, Just privB) -> do
      assertBool "real pub DER nonempty" (not (BS.null pubB))
      assertBool "real priv DER nonempty" (not (BS.null privB))
      assertBool "halves differ" (pubB /= privB)
      -- The generated pair really signs: ECDSA roundtrip at the backend.
      sres <- sign env (SigECDSA (EcSpec "P-256" "DER") (Just D_SHA256))
        (KeyDer privB) "ec-msg"
      sig <- case sres of
        EngineOk s -> pure s
        EngineFail err -> assertFailure ("real sign failed: " ++ show err) >> undefined
      vres <- verify env (SigECDSA (EcSpec "P-256" "DER") (Just D_SHA256))
        (KeyDer pubB) "ec-msg" sig
      case vres of
        EngineOk () -> pure ()
        EngineFail err -> assertFailure ("real verify failed: " ++ show err)
    _ -> assertFailure "real EC halves lack material"

caseRealRsaKeygen :: IO ()
caseRealRsaKeygen = withRealEnv $ \env -> do
  m0 <- seedModel
  st <- getSession m0
  let answer = answerReal env
  (m1, pubH, privH) <- case planGenerateKeyPair defaultRules m0 st rsaKeyPairGenMech rsaPubTmpl rsaPrivTmpl of
    KeyEffect pw fx -> do
      res <- answer m0 fx
      c <- finishCommit m0 st pw res 2
      h1 <- handleOf (pcOutputs c !! 0)
      h2 <- handleOf (pcOutputs c !! 1)
      m' <- expectRight (publishDelta m0 (pcDelta c))
      pure (m', h1, h2)
    other -> assertFailure ("RSA plan is not an effect: " ++ show other) >> undefined
  Just pub <- pure (resolveHandle m1 pubH)
  Just priv <- pure (resolveHandle m1 privH)
  -- The native halves carry real DER; stamped components match.
  case (keyBytesOf pub, keyBytesOf priv) of
    (Just pubB, Just privB) -> do
      assertBool "real pub DER nonempty" (not (BS.null pubB))
      assertBool "real priv DER nonempty" (not (BS.null privB))
      assertBool "halves differ" (pubB /= privB)
      case Map.lookup AttrModulus (osAttrs pub) of
        Just (ValBytes n) -> assertEqual "real modulus length" 256 (BS.length n)
        other -> assertFailure ("real pub lacks modulus: " ++ show other)
      assertEqual "real default exponent"
        (Just (ValBytes (BS.pack [1, 0, 1])))
        (Map.lookup AttrPublicExponent (osAttrs pub))
      -- The generated pair really signs: RSA v1.5 roundtrip at the backend.
      sres <- sign env (SigRSA_PKCS1v15 D_SHA256) (KeyDer privB) "rsa-msg"
      sig <- case sres of
        EngineOk s -> pure s
        EngineFail err -> assertFailure ("real sign failed: " ++ show err) >> undefined
      vres <- verify env (SigRSA_PKCS1v15 D_SHA256) (KeyDer pubB) "rsa-msg" sig
      case vres of
        EngineOk () -> pure ()
        EngineFail err -> assertFailure ("real verify failed: " ++ show err)
    _ -> assertFailure "real RSA halves lack material"

caseRealX942Paramgen :: IO ()
caseRealX942Paramgen = withRealEnv $ \env -> do
  m0 <- seedModel
  st <- getSession m0
  let answer = answerReal env
  (m1, h) <- case planGenerateKey defaultRules m0 st x9_42DhParameterGenMech BS.empty (x942ParamsTmpl 1024 160) of
    KeyEffect pw fx -> do
      res <- answer m0 fx
      c <- finishCommit m0 st pw res 1
      h' <- handleOf (pcOutputs c !! 0)
      m' <- expectRight (publishDelta m0 (pcDelta c))
      pure (m', h')
    other -> assertFailure ("X9.42 paramgen plan is not an effect: " ++ show other) >> undefined
  Just ost <- pure (resolveHandle m1 h)
  assertEqual "params class" (Just (ValULong ckoDomainParameters))
    (Map.lookup AttrClass (osAttrs ost))
  assertEqual "params key type" (Just (ValULong ckkX9_42Dh))
    (Map.lookup AttrKeyType (osAttrs ost))
  case (Map.lookup AttrPrime (osAttrs ost), Map.lookup AttrSubprime (osAttrs ost),
      Map.lookup AttrBase (osAttrs ost)) of
    (Just (ValBytes p), Just (ValBytes q), Just (ValBytes g)) -> do
      assertEqual "prime width" 128 (BS.length p)
      assertEqual "subprime width" 20 (BS.length q)
      assertEqual "base width" 128 (BS.length g)
      assertEqual "prime bits" (Just (ValULong 1024))
        (Map.lookup AttrPrimeBits (osAttrs ost))
      assertEqual "subprime bits" (Just (ValULong 160))
        (Map.lookup AttrSubprimeBits (osAttrs ost))
    other -> assertFailure ("real params lack components: " ++ show other)

caseRealDhPkcsParamgen :: IO ()
caseRealDhPkcsParamgen = withRealEnv $ \env -> do
  m0 <- seedModel
  st <- getSession m0
  let answer = answerReal env
  (m1, h) <- case planGenerateKey defaultRules m0 st dhPkcsParameterGenMech BS.empty (dhPkcsParamsTmpl 1024 160) of
    KeyEffect pw fx -> do
      res <- answer m0 fx
      c <- finishCommit m0 st pw res 1
      h' <- handleOf (pcOutputs c !! 0)
      m' <- expectRight (publishDelta m0 (pcDelta c))
      pure (m', h')
    other -> assertFailure ("DH PKCS paramgen plan is not an effect: " ++ show other) >> undefined
  Just ost <- pure (resolveHandle m1 h)
  assertEqual "params class" (Just (ValULong ckoDomainParameters))
    (Map.lookup AttrClass (osAttrs ost))
  assertEqual "params key type" (Just (ValULong ckkDh))
    (Map.lookup AttrKeyType (osAttrs ost))
  case (Map.lookup AttrPrime (osAttrs ost), Map.lookup AttrSubprime (osAttrs ost),
      Map.lookup AttrBase (osAttrs ost)) of
    (Just (ValBytes p), Just (ValBytes q), Just (ValBytes g)) -> do
      assertEqual "prime width" 128 (BS.length p)
      assertEqual "subprime width" 20 (BS.length q)
      assertEqual "base width" 128 (BS.length g)
      assertEqual "prime bits" (Just (ValULong 1024))
        (Map.lookup AttrPrimeBits (osAttrs ost))
      assertEqual "subprime bits" (Just (ValULong 160))
        (Map.lookup AttrSubprimeBits (osAttrs ost))
    other -> assertFailure ("real params lack components: " ++ show other)

caseRealDsaParamgen :: IO ()
caseRealDsaParamgen = withRealEnv $ \env -> do
  m0 <- seedModel
  st <- getSession m0
  let answer = answerReal env
  (m1, h) <- case planGenerateKey defaultRules m0 st dsaParameterGenMech BS.empty (dsaParamsTmpl 1024) of
    KeyEffect pw fx -> do
      res <- answer m0 fx
      c <- finishCommit m0 st pw res 1
      h' <- handleOf (pcOutputs c !! 0)
      m' <- expectRight (publishDelta m0 (pcDelta c))
      pure (m', h')
    other -> assertFailure ("DSA paramgen plan is not an effect: " ++ show other) >> undefined
  Just ost <- pure (resolveHandle m1 h)
  assertEqual "params class" (Just (ValULong ckoDomainParameters))
    (Map.lookup AttrClass (osAttrs ost))
  assertEqual "params key type" (Just (ValULong ckkDsa))
    (Map.lookup AttrKeyType (osAttrs ost))
  case (Map.lookup AttrPrime (osAttrs ost), Map.lookup AttrSubprime (osAttrs ost),
      Map.lookup AttrBase (osAttrs ost)) of
    (Just (ValBytes p), Just (ValBytes q), Just (ValBytes g)) -> do
      assertEqual "prime width" 128 (BS.length p)
      assertEqual "subprime width" 20 (BS.length q)
      assertEqual "base width" 128 (BS.length g)
      assertEqual "prime bits" (Just (ValULong 1024))
        (Map.lookup AttrPrimeBits (osAttrs ost))
      assertEqual "subprime bits" (Just (ValULong 160))
        (Map.lookup AttrSubprimeBits (osAttrs ost))
    other -> assertFailure ("real params lack components: " ++ show other)

caseRealDsaKeygen :: IO ()
caseRealDsaKeygen = withRealEnv $ \env -> do
  m0 <- seedModel
  st <- getSession m0
  let answer = answerReal env
  (m1, ph) <- case planGenerateKey defaultRules m0 st dsaParameterGenMech BS.empty (dsaParamsTmpl 1024) of
    KeyEffect pw fx -> do
      res <- answer m0 fx
      c <- finishCommit m0 st pw res 1
      h' <- handleOf (pcOutputs c !! 0)
      m' <- expectRight (publishDelta m0 (pcDelta c))
      pure (m', h')
    other -> assertFailure ("DSA paramgen plan is not an effect: " ++ show other) >> undefined
  Just post <- pure (resolveHandle m1 ph)
  (p, q, g) <- case (Map.lookup AttrPrime (osAttrs post),
      Map.lookup AttrSubprime (osAttrs post), Map.lookup AttrBase (osAttrs post)) of
    (Just (ValBytes p), Just (ValBytes q), Just (ValBytes g)) -> pure (p, q, g)
    other -> assertFailure ("real params lack components: " ++ show other) >> undefined
  let pubT =
        [ (AttrClass, ValULong ckoPublicKey)
        , (AttrKeyType, ValULong ckkDsa)
        , (AttrPrime, ValBytes p)
        , (AttrSubprime, ValBytes q)
        , (AttrBase, ValBytes g)
        , (AttrToken, ValBool False)
        , (AttrVerify, ValBool True)
        ]
  (m2, pubH, privH) <- case planGenerateKeyPair defaultRules m1 st dsaKeyPairGenMech pubT dsaPrivTmpl of
    KeyEffect pw fx -> do
      res <- answer m1 fx
      c <- finishCommit m1 st pw res 2
      h1 <- handleOf (pcOutputs c !! 0)
      h2 <- handleOf (pcOutputs c !! 1)
      m' <- expectRight (publishDelta m1 (pcDelta c))
      pure (m', h1, h2)
    other -> assertFailure ("DSA plan is not an effect: " ++ show other) >> undefined
  Just pub <- pure (resolveHandle m2 pubH)
  Just priv <- pure (resolveHandle m2 privH)
  case (keyBytesOf pub, keyBytesOf priv) of
    (Just pubB, Just privB) -> do
      assertBool "real pub DER nonempty" (not (BS.null pubB))
      assertBool "real priv DER nonempty" (not (BS.null privB))
      assertBool "halves differ" (pubB /= privB)
      assertEqual "priv inherits prime" (Just (ValBytes p))
        (Map.lookup AttrPrime (osAttrs priv))
      -- The generated pair really signs: DSA-SHA256 roundtrip at the backend.
      sres <- sign env (SigDSA "DER" (Just D_SHA256)) (KeyDer privB) "dsa-msg"
      sig <- case sres of
        EngineOk s -> pure s
        EngineFail err -> assertFailure ("real sign failed: " ++ show err) >> undefined
      vres <- verify env (SigDSA "DER" (Just D_SHA256)) (KeyDer pubB) "dsa-msg" sig
      case vres of
        EngineOk () -> pure ()
        EngineFail err -> assertFailure ("real verify failed: " ++ show err)
    _ -> assertFailure "real DSA halves lack material"

caseRealDhKeygen :: IO ()
caseRealDhKeygen = withRealEnv $ \env -> do
  m0 <- seedModel
  st <- getSession m0
  let answer = answerReal env
      pubT =
        [ (AttrClass, ValULong ckoPublicKey)
        , (AttrKeyType, ValULong ckkDh)
        , (AttrPrime, ValBytes dhRealP)
        , (AttrBase, ValBytes dhG)
        , (AttrToken, ValBool False)
        , (AttrDerive, ValBool True)
        ]
      mint m n = case planGenerateKeyPair defaultRules m st dhKeyPairGenMech pubT dhPrivTmpl of
        KeyEffect pw fx -> do
          res <- answer m fx
          c <- finishCommit m st pw res n
          h1 <- handleOf (pcOutputs c !! 0)
          h2 <- handleOf (pcOutputs c !! 1)
          m' <- expectRight (publishDelta m (pcDelta c))
          pure (m', h1, h2)
        other -> assertFailure ("DH plan is not an effect: " ++ show other) >> undefined
  (m1, pubHA, privHA) <- mint m0 2
  (m2, pubHB, privHB) <- mint m1 2
  Just pubA <- pure (resolveHandle m2 pubHA)
  Just privA <- pure (resolveHandle m2 privHA)
  Just pubB <- pure (resolveHandle m2 pubHB)
  Just privB <- pure (resolveHandle m2 privHB)
  case (keyBytesOf pubA, keyBytesOf privA, keyBytesOf pubB, keyBytesOf privB) of
    (Just pubBA, Just privBA, Just pubBB, Just privBB) -> do
      assertBool "halves differ" (pubBA /= privBA)
      assertEqual "priv inherits prime" (Just (ValBytes dhRealP))
        (Map.lookup AttrPrime (osAttrs privA))
      assertEqual "priv inherits base" (Just (ValBytes dhG))
        (Map.lookup AttrBase (osAttrs privA))
      -- The generated pairs really agree: cross-derive both ways.
      yA <- case dhSpkiFields pubBA of
        Just (_, _, _, y) -> pure y
        Nothing -> assertFailure "SPKI A failed to parse" >> undefined
      yB <- case dhSpkiFields pubBB of
        Just (_, _, _, y) -> pure y
        Nothing -> assertFailure "SPKI B failed to parse" >> undefined
      rab <- dhDerive env DhPlain (KeyDer privBA) (KeyDer yB)
      sAB <- case rab of
        EngineOk s -> pure s
        EngineFail err -> assertFailure ("real derive A->B failed: " ++ show err) >> undefined
      rba <- dhDerive env DhPlain (KeyDer privBB) (KeyDer yA)
      sBA <- case rba of
        EngineOk s -> pure s
        EngineFail err -> assertFailure ("real derive B->A failed: " ++ show err) >> undefined
      assertEqual "agreement commutes" sAB sBA
      assertEqual "prime width" 256 (BS.length sAB)
    _ -> assertFailure "real DH halves lack material"

caseRealEcKeygen384 :: IO ()
caseRealEcKeygen384 = withRealEnv $ \env -> do
  m0 <- seedModel
  st <- getSession m0
  let answer = answerReal env
      (pubT, privT) = ecTmpls "P-384"
  (m1, pubH, privH) <- case planGenerateKeyPair defaultRules m0 st ecKeyPairGenMech pubT privT of
    KeyEffect pw fx -> do
      res <- answer m0 fx
      c <- finishCommit m0 st pw res 2
      h1 <- handleOf (pcOutputs c !! 0)
      h2 <- handleOf (pcOutputs c !! 1)
      m' <- expectRight (publishDelta m0 (pcDelta c))
      pure (m', h1, h2)
    other -> assertFailure ("P-384 plan is not an effect: " ++ show other) >> undefined
  Just pub <- pure (resolveHandle m1 pubH)
  Just priv <- pure (resolveHandle m1 privH)
  case (keyBytesOf pub, keyBytesOf priv) of
    (Just pubB, Just privB) -> do
      assertBool "real pub DER nonempty" (not (BS.null pubB))
      assertBool "real priv DER nonempty" (not (BS.null privB))
      sres <- sign env (SigECDSA (EcSpec "P-384" "DER") (Just D_SHA384))
        (KeyDer privB) "ec384-msg"
      sig <- case sres of
        EngineOk s -> pure s
        EngineFail err -> assertFailure ("real sign failed: " ++ show err) >> undefined
      vres <- verify env (SigECDSA (EcSpec "P-384" "DER") (Just D_SHA384))
        (KeyDer pubB) "ec384-msg" sig
      case vres of
        EngineOk () -> pure ()
        EngineFail err -> assertFailure ("real verify failed: " ++ show err)
    _ -> assertFailure "real P-384 halves lack material"

caseRealEcKeygen521 :: IO ()
caseRealEcKeygen521 = withRealEnv $ \env -> do
  m0 <- seedModel
  st <- getSession m0
  let answer = answerReal env
      (pubT, privT) = ecTmpls "P-521"
  (m1, pubH, privH) <- case planGenerateKeyPair defaultRules m0 st ecKeyPairGenMech pubT privT of
    KeyEffect pw fx -> do
      res <- answer m0 fx
      c <- finishCommit m0 st pw res 2
      h1 <- handleOf (pcOutputs c !! 0)
      h2 <- handleOf (pcOutputs c !! 1)
      m' <- expectRight (publishDelta m0 (pcDelta c))
      pure (m', h1, h2)
    other -> assertFailure ("P-521 plan is not an effect: " ++ show other) >> undefined
  Just pub <- pure (resolveHandle m1 pubH)
  Just priv <- pure (resolveHandle m1 privH)
  case (keyBytesOf pub, keyBytesOf priv) of
    (Just pubB, Just privB) -> do
      assertBool "real pub DER nonempty" (not (BS.null pubB))
      assertBool "real priv DER nonempty" (not (BS.null privB))
      sres <- sign env (SigECDSA (EcSpec "P-521" "DER") (Just D_SHA512))
        (KeyDer privB) "ec521-msg"
      sig <- case sres of
        EngineOk s -> pure s
        EngineFail err -> assertFailure ("real sign failed: " ++ show err) >> undefined
      vres <- verify env (SigECDSA (EcSpec "P-521" "DER") (Just D_SHA512))
        (KeyDer pubB) "ec521-msg" sig
      case vres of
        EngineOk () -> pure ()
        EngineFail err -> assertFailure ("real verify failed: " ++ show err)
    _ -> assertFailure "real P-521 halves lack material"

caseRealWrapVector :: IO ()
caseRealWrapVector = withRealEnv $ \env -> do
  m0 <- seedModel >>= loginUser
  st <- getSession m0
  let answer = answerReal env
  (m1, wrapH) <- plantKey m0 st
    [ (AttrClass, ValULong ckoSecretKey)
    , (AttrKeyType, ValULong ckkAes)
    , (AttrToken, ValBool False)
    , (AttrWrap, ValBool True)
    , (AttrUnwrap, ValBool True)
    ] spKey
  (m2, targetH) <- plantKey m1 st
    [ (AttrClass, ValULong ckoSecretKey)
    , (AttrKeyType, ValULong ckkAes)
    , (AttrToken, ValBool False)
    , (AttrExtractable, ValBool True)
    ] spP1
  blob <- case planWrapKey m2 st aesCbcMech spIv wrapH targetH (IntentBuffer 32) of
    KeyEffect pw fx -> do
      res <- answer m2 fx
      case finishWork m2 st pw res of
        Immediate c -> case pcOutputs c of
          [NativeOutput (RegionBytes "wrapped" _) bs] -> pure bs
          o -> assertFailure ("one blob: " ++ show o) >> undefined
        other -> assertFailure ("wrap must commit: " ++ show other) >> undefined
    other -> assertFailure ("wrap must plan: " ++ show other) >> undefined
  -- The padded target's first block is the F.2.5 vector plaintext,
  -- so the blob opens with the F.2.5 ciphertext block.
  assertEqual "SP 800-38A F.2.5 first block" spC1 (BS.take 16 blob)
  let tmpl = [(AttrClass, ValULong ckoSecretKey), (AttrKeyType, ValULong ckkAes)]
  case planUnwrapKey defaultRules m2 st aesCbcMech spIv wrapH blob tmpl of
    KeyEffect pw fx -> do
      res <- answer m2 fx
      c <- finishCommit m2 st pw res 1
      h <- handleOf (pcOutputs c !! 0)
      m3 <- expectRight (publishDelta m2 (pcDelta c))
      Just ost <- pure (resolveHandle m3 h)
      assertEqual "real unwrap recovers" (Just spP1) (keyBytesOf ost)
    other -> assertFailure ("unwrap must plan: " ++ show other)

caseRealHkdfVector :: IO ()
caseRealHkdfVector = withRealEnv $ \env -> do
  m0 <- seedModel
  st <- getSession m0
  let answer = answerReal env
  (m1, baseH) <- plantKey m0 st
    [ (AttrClass, ValULong ckoSecretKey)
    , (AttrKeyType, ValULong ckkGenericSecret)
    , (AttrToken, ValBool False)
    , (AttrDerive, ValBool True)
    ] rfcPrk
  let kid =
        [ (AttrClass, ValULong ckoSecretKey)
        , (AttrKeyType, ValULong ckkGenericSecret)
        , (AttrValueLen, ValULong 42)
        , (AttrToken, ValBool False)
        ]
  (m2, [h]) <- case planDerive defaultRules m1 st hkdfDeriveMech baseH (encodeDeriveParams (encodeHkdfInfo 4 0x02 BS.empty rfcInfo) [kid]) of
    KeyEffect pw fx -> do
      res <- answer m1 fx
      c <- finishCommit m1 st pw res 1
      hh <- handleOf (pcOutputs c !! 0)
      m' <- expectRight (publishDelta m1 (pcDelta c))
      pure (m', [hh])
    other -> assertFailure ("derive must plan: " ++ show other) >> undefined
  Just ost <- pure (resolveHandle m2 h)
  assertEqual "RFC 5869 A.1 OKM" (Just rfcOkm) (keyBytesOf ost)
  -- The synthetic construction is a different (test-only) MAC, so it
  -- must replay itself rather than the RFC vector.
  withSynth $ \sanswer -> do
    let deriveOnce mm = case planDerive defaultRules mm st hkdfDeriveMech baseH (encodeDeriveParams (encodeHkdfInfo 4 0x02 BS.empty rfcInfo) [kid]) of
          KeyEffect pw fx -> do
            res <- sanswer mm fx
            c <- finishCommit mm st pw res 1
            hh <- handleOf (pcOutputs c !! 0)
            m' <- expectRight (publishDelta mm (pcDelta c))
            pure (m', hh)
          _ -> assertFailure "derive must plan" >> undefined
    (ms1, hs1) <- deriveOnce m1
    (ms2, hs2) <- deriveOnce m1
    Just os1 <- pure (resolveHandle ms1 hs1)
    Just os2 <- pure (resolveHandle ms2 hs2)
    assertEqual "synthetic derive replays" (keyBytesOf os1) (keyBytesOf os2)

caseRealHkdfExtractExpand :: IO ()
caseRealHkdfExtractExpand = withRealEnv $ \env -> do
  m0 <- seedModel
  st <- getSession m0
  let answer = answerReal env
  (m1, baseH) <- plantKey m0 st
    [ (AttrClass, ValULong ckoSecretKey)
    , (AttrKeyType, ValULong ckkGenericSecret)
    , (AttrToken, ValBool False)
    , (AttrDerive, ValBool True)
    ] rfcIkm
  let kid =
        [ (AttrClass, ValULong ckoSecretKey)
        , (AttrKeyType, ValULong ckkGenericSecret)
        , (AttrValueLen, ValULong 42)
        , (AttrToken, ValBool False)
        ]
      deriveWith salt info = case planDerive defaultRules m1 st hkdfDeriveMech baseH
        (encodeDeriveParams (encodeHkdfInfo 4 0x03 salt info) [kid]) of
          KeyEffect pw fx -> do
            res <- answer m1 fx
            c <- finishCommit m1 st pw res 1
            hh <- handleOf (pcOutputs c !! 0)
            m' <- expectRight (publishDelta m1 (pcDelta c))
            pure (m', hh)
          other -> assertFailure ("derive must plan: " ++ show other) >> undefined
  (m2, h1) <- deriveWith rfcSalt rfcInfo
  Just ost1 <- pure (resolveHandle m2 h1)
  assertEqual "RFC 5869 A.1 OKM" (Just rfcOkm) (keyBytesOf ost1)
  (m3, h3) <- deriveWith BS.empty BS.empty
  Just ost3 <- pure (resolveHandle m3 h3)
  assertEqual "RFC 5869 A.3 OKM (zero salt)" (Just rfcOkmZeroSalt) (keyBytesOf ost3)
  -- Synthetic replays itself on the same extract profile.
  withSynth $ \sanswer -> do
    let once mm = case planDerive defaultRules mm st hkdfDeriveMech baseH
          (encodeDeriveParams (encodeHkdfInfo 4 0x03 rfcSalt rfcInfo) [kid]) of
            KeyEffect pw fx -> do
              res <- sanswer mm fx
              c <- finishCommit mm st pw res 1
              hh <- handleOf (pcOutputs c !! 0)
              m' <- expectRight (publishDelta mm (pcDelta c))
              pure (m', hh)
            _ -> assertFailure "derive must plan" >> undefined
    (ms1, hs1) <- once m1
    (ms2, hs2) <- once m1
    Just os1 <- pure (resolveHandle ms1 hs1)
    Just os2 <- pure (resolveHandle ms2 hs2)
    assertEqual "synthetic extract replays" (keyBytesOf os1) (keyBytesOf os2)

-- | Multi-PRF HKDF over the real backend: the A.1 inputs
-- under SHA-1 and SHA-512. RFC 5869 pins SHA-256 only; these
-- references were computed programmatically (a python hmac
-- one-off) and cross-check the PRF threading, not the RFC.
caseRealHkdfMultiPrf :: IO ()
caseRealHkdfMultiPrf = withRealEnv $ \env -> do
  m0 <- seedModel
  st <- getSession m0
  let answer = answerReal env
  (m1, baseH) <- plantKey m0 st
    [ (AttrClass, ValULong ckoSecretKey)
    , (AttrKeyType, ValULong ckkGenericSecret)
    , (AttrToken, ValBool False)
    , (AttrDerive, ValBool True)
    ] rfcIkm
  let kid =
        [ (AttrClass, ValULong ckoSecretKey)
        , (AttrKeyType, ValULong ckkGenericSecret)
        , (AttrValueLen, ValULong 42)
        , (AttrToken, ValBool False)
        ]
      deriveWith prf = case planDerive defaultRules m1 st hkdfDeriveMech baseH
        (encodeDeriveParams (encodeHkdfInfo prf 0x03 rfcSalt rfcInfo) [kid]) of
          KeyEffect pw fx -> do
            res <- answer m1 fx
            c <- finishCommit m1 st pw res 1
            hh <- handleOf (pcOutputs c !! 0)
            m' <- expectRight (publishDelta m1 (pcDelta c))
            pure (m', hh)
          other -> assertFailure ("derive must plan: " ++ show other) >> undefined
      sha1Okm = hex "d6000ffb5b50bd3970b260017798fb9c8df9ce2e2c16b6cd709cca07dc3cf9cf26d6c6d750d0aaf5ac94"
      sha512Okm = hex "832390086cda71fb47625bb5ceb168e4c8e26a1a16ed34d9fc7fe92c1481579338da362cb8d9f925d7cb"
  (m2, h1) <- deriveWith 2
  Just ost1 <- pure (resolveHandle m2 h1)
  assertEqual "HKDF-SHA-1 OKM" (Just sha1Okm) (keyBytesOf ost1)
  (m3, h2) <- deriveWith 6
  Just ost2 <- pure (resolveHandle m3 h2)
  assertEqual "HKDF-SHA-512 OKM" (Just sha512Okm) (keyBytesOf ost2)

caseHkdfExtractOnlyRefused :: IO ()
caseHkdfExtractOnlyRefused = do
  m0 <- seedModel
  st <- getSession m0
  (m1, baseH) <- plantKey m0 st
    [ (AttrClass, ValULong ckoSecretKey)
    , (AttrKeyType, ValULong ckkGenericSecret)
    , (AttrToken, ValBool False)
    , (AttrDerive, ValBool True)
    ] rfcIkm
  let kid =
        [ (AttrClass, ValULong ckoSecretKey)
        , (AttrKeyType, ValULong ckkGenericSecret)
        , (AttrValueLen, ValULong 32)
        , (AttrToken, ValBool False)
        ]
      blob = encodeDeriveParams (encodeHkdfInfo 4 0x01 BS.empty BS.empty) [kid]
  case planDerive defaultRules m1 st hkdfDeriveMech baseH blob of
    KeyDenied (KeyDeny code _) ->
      assertEqual "extract-only code" CKR_MECHANISM_PARAM_INVALID code
    other -> assertFailure ("extract-only must deny, got: " ++ show other)

caseHkdfDataPlans :: IO ()
caseHkdfDataPlans = do
  m0 <- seedModel
  st <- getSession m0
  (m1, baseH) <- plantKey m0 st
    [ (AttrClass, ValULong ckoSecretKey)
    , (AttrKeyType, ValULong ckkGenericSecret)
    , (AttrToken, ValBool False)
    , (AttrDerive, ValBool True)
    ] rfcIkm
  (m2, hkdfH) <- plantKey m1 st
    [ (AttrClass, ValULong ckoSecretKey)
    , (AttrKeyType, ValULong ckkHkdf)
    , (AttrToken, ValBool False)
    , (AttrDerive, ValBool True)
    ] rfcIkm
  let frame = encodeHkdfInfo 4 0x03 BS.empty rfcInfo
      dat = [ (AttrClass, ValULong ckoData)
            , (AttrValueLen, ValULong 42)
            , (AttrToken, ValBool False)
            ]
      key = [ (AttrClass, ValULong ckoSecretKey)
            , (AttrKeyType, ValULong ckkGenericSecret)
            , (AttrValueLen, ValULong 42)
            , (AttrToken, ValBool False)
            ]
      noLen = [ (AttrClass, ValULong ckoData)
              , (AttrToken, ValBool False)
              ]
  case planDerive defaultRules m2 st hkdfDataMech baseH
      (encodeDeriveParams frame [dat]) of
    KeyEffect _ _ -> pure ()
    other -> assertFailure ("data output must plan, got: " ++ show other)
  case planDerive defaultRules m2 st hkdfDataMech baseH
      (encodeDeriveParams frame [key]) of
    KeyDenied (KeyDeny code _) ->
      assertEqual "key-class code" CKR_KEY_TYPE_INCONSISTENT code
    other -> assertFailure ("key output must deny, got: " ++ show other)
  -- Base acceptance mirrors HKDF-DERIVE (any derive-marked
  -- base): only the output class differs.
  case planDerive defaultRules m2 st hkdfDataMech hkdfH
      (encodeDeriveParams frame [dat]) of
    KeyEffect _ _ -> pure ()
    other -> assertFailure ("hkdf base must plan, got: " ++ show other)
  case planDerive defaultRules m2 st hkdfDataMech baseH
      (encodeDeriveParams frame [noLen]) of
    KeyDenied (KeyDeny code _) ->
      assertEqual "missing length code" CKR_TEMPLATE_INCOMPLETE code
    other -> assertFailure ("missing length must deny, got: " ++ show other)
  case planDerive defaultRules m2 st hkdfDataMech baseH
      (encodeDeriveParams (encodeHkdfInfo 4 0x01 BS.empty BS.empty) [dat]) of
    KeyDenied (KeyDeny code _) ->
      assertEqual "extract-only code" CKR_MECHANISM_PARAM_INVALID code
    other -> assertFailure ("extract-only must deny, got: " ++ show other)

caseRealHkdfDataVector :: IO ()
caseRealHkdfDataVector = withRealEnv $ \env -> do
  m0 <- seedModel
  st <- getSession m0
  let answer = answerReal env
  -- The A.1 shape, mirrored from caseRealHkdfVector: the base
  -- carries the RFC PRK, expand-only, and the derived 42 bytes
  -- must equal the RFC OKM — the same KDF as HKDF-DERIVE, only
  -- the output class differs.
  (m1, baseH) <- plantKey m0 st
    [ (AttrClass, ValULong ckoSecretKey)
    , (AttrKeyType, ValULong ckkGenericSecret)
    , (AttrToken, ValBool False)
    , (AttrDerive, ValBool True)
    ] rfcPrk
  let dat =
        [ (AttrClass, ValULong ckoData)
        , (AttrValueLen, ValULong 42)
        , (AttrToken, ValBool False)
        ]
      frame = encodeDeriveParams (encodeHkdfInfo 4 0x02 BS.empty rfcInfo) [dat]
  (m2, [h]) <- case planDerive defaultRules m1 st hkdfDataMech baseH frame of
    KeyEffect pw fx -> do
      res <- answer m1 fx
      c <- finishCommit m1 st pw res 1
      hh <- handleOf (pcOutputs c !! 0)
      m' <- expectRight (publishDelta m1 (pcDelta c))
      pure (m', [hh])
    other -> assertFailure ("derive must plan: " ++ show other) >> undefined
  Just ost <- pure (resolveHandle m2 h)
  assertEqual "RFC 5869 A.1 OKM" (Just rfcOkm) (keyBytesOf ost)
  assertEqual "data class" (Just (ValULong ckoData))
    (Map.lookup AttrClass (osAttrs ost))
  -- The synthetic construction replays itself on the data-output
  -- arm (same determinism bar as the key-output arm).
  withSynth $ \sanswer -> do
    let deriveOnce mm = case planDerive defaultRules mm st hkdfDataMech baseH frame of
          KeyEffect pw fx -> do
            res <- sanswer mm fx
            c <- finishCommit mm st pw res 1
            hh <- handleOf (pcOutputs c !! 0)
            m' <- expectRight (publishDelta mm (pcDelta c))
            pure (m', hh)
          _ -> assertFailure "derive must plan" >> undefined
    (ms1, hs1) <- deriveOnce m1
    (ms2, hs2) <- deriveOnce m1
    Just os1 <- pure (resolveHandle ms1 hs1)
    Just os2 <- pure (resolveHandle ms2 hs2)
    assertEqual "synthetic data derive replays" (keyBytesOf os1) (keyBytesOf os2)

-- | The oracle-profile fixed input: label, 0x00 separator,
-- context (the DKM length rides execution, never the frame).
sp800Fixed :: BS.ByteString
sp800Fixed = "SP800-108 test label" <> "\x00" <> "SP800-108 test context"

sp800CounterMech, sp800FeedbackMech, sp800DoubleMech :: MechanismId
sp800CounterMech = MechanismId ckm_SP800_108_COUNTER_KDF
sp800FeedbackMech = MechanismId ckm_SP800_108_FEEDBACK_KDF
sp800DoubleMech = MechanismId ckm_SP800_108_DOUBLE_PIPELINE_KDF

caseSp800Plans :: IO ()
caseSp800Plans = do
  m0 <- seedModel
  st <- getSession m0
  (m1, baseH) <- plantKey m0 st
    [ (AttrClass, ValULong ckoSecretKey)
    , (AttrKeyType, ValULong ckkGenericSecret)
    , (AttrToken, ValBool False)
    , (AttrDerive, ValBool True)
    ] (BS.pack [0 .. 31])
  let kid n =
        [ (AttrClass, ValULong ckoSecretKey)
        , (AttrKeyType, ValULong ckkAes)
        , (AttrValueLen, ValULong n)
        , (AttrToken, ValBool False)
        ]
      counter = encodeSp800Params 4 32 32 BS.empty sp800Fixed
      feedback = encodeSp800Params 4 32 32 (BS.pack [0 .. 15]) sp800Fixed
      dbl = encodeSp800Params 4 32 32 BS.empty sp800Fixed
  -- All three modes plan with a VALUE_LEN template.
  case planDerive defaultRules m1 st sp800CounterMech baseH
      (encodeDeriveParams counter [kid 16]) of
    KeyEffect _ (FxDerive mech _ _ params info total) -> do
      assertEqual "counter mech" sp800CounterMech mech
      assertEqual "counter params" counter params
      assertEqual "counter info empty" BS.empty info
      assertEqual "counter total" 16 total
    other -> assertFailure ("counter must plan: " ++ show other)
  case planDerive defaultRules m1 st sp800FeedbackMech baseH
      (encodeDeriveParams feedback [kid 16]) of
    KeyEffect _ _ -> pure ()
    other -> assertFailure ("feedback must plan: " ++ show other)
  case planDerive defaultRules m1 st sp800DoubleMech baseH
      (encodeDeriveParams dbl [kid 32]) of
    KeyEffect _ _ -> pure ()
    other -> assertFailure ("double-pipeline must plan: " ++ show other)
  -- Junk frames refuse typed.
  case planDerive defaultRules m1 st sp800CounterMech baseH
      (encodeDeriveParams "junk" [kid 16]) of
    KeyDenied (KeyDeny code _) ->
      assertEqual "junk code" CKR_ARGUMENTS_BAD code
    other -> assertFailure ("junk must deny, got: " ++ show other)
  -- An IV on a counter frame refuses typed (mode/IV
  -- consistency).
  case planDerive defaultRules m1 st sp800CounterMech baseH
      (encodeDeriveParams feedback [kid 16]) of
    KeyDenied (KeyDeny code _) ->
      assertEqual "counter-iv code" CKR_ARGUMENTS_BAD code
    other -> assertFailure ("counter iv must deny, got: " ++ show other)
  -- A missing length stays INCOMPLETE (no natural width).
  let noLen =
        [ (AttrClass, ValULong ckoSecretKey)
        , (AttrKeyType, ValULong ckkAes)
        , (AttrToken, ValBool False)
        ]
  case planDerive defaultRules m1 st sp800CounterMech baseH
      (encodeDeriveParams counter [noLen]) of
    KeyDenied (KeyDeny code _) ->
      assertEqual "no-length code" CKR_TEMPLATE_INCOMPLETE code
    other -> assertFailure ("missing length must deny, got: " ++ show other)
  -- Output past the ceiling refuses typed.
  case planDerive defaultRules m1 st sp800CounterMech baseH
      (encodeDeriveParams counter [kid (fromIntegral (maxSp800Total + 1))]) of
    KeyDenied (KeyDeny code _) ->
      assertEqual "ceiling code" CKR_ARGUMENTS_BAD code
    other -> assertFailure ("over-ceiling must deny, got: " ++ show other)
  -- L must fit its width (320 bits need more than 8).
  let narrow = encodeSp800Params 4 32 8 BS.empty sp800Fixed
  case planDerive defaultRules m1 st sp800CounterMech baseH
      (encodeDeriveParams narrow [kid 40]) of
    KeyDenied (KeyDeny code _) ->
      assertEqual "L-fit code" CKR_KEY_SIZE_RANGE code
    other -> assertFailure ("L misfit must deny, got: " ++ show other)
  -- Counter mode past 2^r - 1 iterations refuses typed (256
  -- blocks need more than 8 counter bits).
  let short = encodeSp800Params 4 8 32 BS.empty sp800Fixed
  case planDerive defaultRules m1 st sp800CounterMech baseH
      (encodeDeriveParams short [kid 8192]) of
    KeyDenied (KeyDeny code _) ->
      assertEqual "counter-fit code" CKR_KEY_SIZE_RANGE code
    other -> assertFailure ("counter misfit must deny, got: " ++ show other)

caseRealSp800Vector :: IO ()
caseRealSp800Vector = withRealEnv $ \env -> do
  m0 <- seedModel
  st <- getSession m0
  let answer = answerReal env
  (m1, baseH) <- plantKey m0 st
    [ (AttrClass, ValULong ckoSecretKey)
    , (AttrKeyType, ValULong ckkGenericSecret)
    , (AttrToken, ValBool False)
    , (AttrDerive, ValBool True)
    ] (BS.pack [0 .. 31])
  let kid =
        [ (AttrClass, ValULong ckoSecretKey)
        , (AttrKeyType, ValULong ckkAes)
        , (AttrValueLen, ValULong 16)
        , (AttrToken, ValBool False)
        ]
      frame = encodeSp800Params 4 32 32 BS.empty sp800Fixed
  (m2, [h]) <- case planDerive defaultRules m1 st sp800CounterMech baseH
      (encodeDeriveParams frame [kid]) of
    KeyEffect pw fx -> do
      res <- answer m1 fx
      c <- finishCommit m1 st pw res 1
      hh <- handleOf (pcOutputs c !! 0)
      m' <- expectRight (publishDelta m1 (pcDelta c))
      pure (m', [hh])
    other -> assertFailure ("derive must plan: " ++ show other) >> undefined
  Just ost <- pure (resolveHandle m2 h)
  -- Triple-verified: independent python construction, the
  -- oracle reference, and the provider KBKDF CLI agree.
  assertEqual "SP800-108 counter AES-128 KAT"
    (Just (hex "caff7a6a35ca9b35afcc64fa658d8bc2")) (keyBytesOf ost)

tlsKdfMasterMech, tlsKdfTls12Mech, tlsKdfExtMech, tlsKdfFreeMech, tlsKdfGenMech :: MechanismId
tlsKdfMasterMech = MechanismId ckm_TLS_MASTER_KEY_DERIVE
tlsKdfTls12Mech = MechanismId ckm_TLS12_MASTER_KEY_DERIVE
tlsKdfExtMech = MechanismId ckm_TLS12_EXTENDED_MASTER_KEY_DERIVE
tlsKdfFreeMech = MechanismId ckm_TLS12_KDF
tlsKdfGenMech = MechanismId ckm_TLS_KDF

tlsKdfSeed64 :: BS.ByteString
tlsKdfSeed64 = BS.pack [0 .. 63]

tlsKdfSess32 :: BS.ByteString
tlsKdfSess32 = BS.pack [0 .. 31]

caseTlsKdfPlans :: IO ()
caseTlsKdfPlans = do
  m0 <- seedModel
  st <- getSession m0
  (m1, baseH) <- plantKey m0 st
    [ (AttrClass, ValULong ckoSecretKey)
    , (AttrKeyType, ValULong ckkGenericSecret)
    , (AttrToken, ValBool False)
    , (AttrDerive, ValBool True)
    ] (BS.pack [0 .. 47])
  let kid :: Int -> [(AttributeType, AttributeValue)]
      kid n =
        [ (AttrClass, ValULong ckoSecretKey)
        , (AttrKeyType, ValULong ckkGenericSecret)
        , (AttrValueLen, ValULong (fromIntegral n))
        , (AttrToken, ValBool False)
        ]
      master = encodeTlsKdfParams 0 "master secret" tlsKdfSeed64 BS.empty
      kdf = encodeTlsKdfParams 4 "key expansion" tlsKdfSeed64 BS.empty
  -- Each row plans with its frame.
  mapM_ (\(mech, frame, n) ->
    case planDerive defaultRules m1 st mech baseH
        (encodeDeriveParams frame [kid n]) of
      KeyEffect _ (FxDerive _ _ _ _ _ total) ->
        assertEqual ("total " ++ show mech) n total
      other -> assertFailure ("must plan, got: " ++ show other))
    [ (tlsKdfMasterMech, master, 48)
    , (tlsKdfTls12Mech, encodeTlsKdfParams 4 "master secret" tlsKdfSeed64 BS.empty, 48)
    , (tlsKdfExtMech, encodeTlsKdfParams 4 "extended master secret" tlsKdfSess32 BS.empty, 48)
    , (tlsKdfFreeMech, kdf, 32)
    , (tlsKdfGenMech, encodeTlsKdfParams 0 "key expansion" tlsKdfSeed64 BS.empty, 32)
    ]
  -- A wrong-row frame refuses typed.
  case planDerive defaultRules m1 st tlsKdfMasterMech baseH
      (encodeDeriveParams kdf [kid 32]) of
    KeyDenied (KeyDeny code _) ->
      assertEqual "wrong-row code" CKR_ARGUMENTS_BAD code
    other -> assertFailure ("wrong row must deny, got: " ++ show other)
  -- A missing length stays INCOMPLETE (no natural width).
  let noLen =
        [ (AttrClass, ValULong ckoSecretKey)
        , (AttrKeyType, ValULong ckkGenericSecret)
        , (AttrToken, ValBool False)
        ]
  case planDerive defaultRules m1 st tlsKdfMasterMech baseH
      (encodeDeriveParams master [noLen]) of
    KeyDenied (KeyDeny code _) ->
      assertEqual "no-length code" CKR_TEMPLATE_INCOMPLETE code
    other -> assertFailure ("missing length must deny, got: " ++ show other)
  -- Output past the ceiling refuses typed.
  case planDerive defaultRules m1 st tlsKdfFreeMech baseH
      (encodeDeriveParams kdf [kid (fromIntegral (maxTlsKdfOutput + 1))]) of
    KeyDenied (KeyDeny code _) ->
      assertEqual "ceiling code" CKR_ARGUMENTS_BAD code
    other -> assertFailure ("over-ceiling must deny, got: " ++ show other)

caseRealTlsKdfVector :: IO ()
caseRealTlsKdfVector = withRealEnv $ \env -> do
  m0 <- seedModel >>= loginUser
  st <- getSession m0
  let answer = answerReal env
  (m1, baseH) <- plantKey m0 st
    [ (AttrClass, ValULong ckoSecretKey)
    , (AttrKeyType, ValULong ckkGenericSecret)
    , (AttrToken, ValBool False)
    , (AttrDerive, ValBool True)
    ] (BS.pack [0 .. 47])
  let kid :: Int -> [(AttributeType, AttributeValue)]
      kid n =
        [ (AttrClass, ValULong ckoSecretKey)
        , (AttrKeyType, ValULong ckkGenericSecret)
        , (AttrValueLen, ValULong (fromIntegral n))
        , (AttrToken, ValBool False)
        ]
      derive mech frame n = do
        (m', [h]) <- case planDerive defaultRules m1 st mech baseH
            (encodeDeriveParams frame [kid n]) of
          KeyEffect pw fx -> do
            res <- answer m1 fx
            c <- finishCommit m1 st pw res 1
            hh <- handleOf (pcOutputs c !! 0)
            m' <- expectRight (publishDelta m1 (pcDelta c))
            pure (m', [hh])
          other -> assertFailure ("derive must plan: " ++ show other) >> undefined
        Just ost <- pure (resolveHandle m' h)
        pure (keyBytesOf ost)
  gotM10 <- derive tlsKdfMasterMech
    (encodeTlsKdfParams 0 "master secret" tlsKdfSeed64 BS.empty) 48
  assertEqual "TLS master KAT"
    (Just (hex "539391828d1d131678646180c5bda5c9a2eb62382c8cfb9440545cae85c8c205b93e0d22161e06be1189235aefca7570")) gotM10
  gotM12 <- derive tlsKdfTls12Mech
    (encodeTlsKdfParams 4 "master secret" tlsKdfSeed64 BS.empty) 48
  assertEqual "TLS12 master KAT"
    (Just (hex "2b7cccb6d48adb8692df640b9252502fb000fd68fb2dc4b6a8cd67d870492f38e4c5dd509ba7c4863c003c07d23f9a3b")) gotM12
  gotKdf <- derive tlsKdfFreeMech
    (encodeTlsKdfParams 4 "key expansion" tlsKdfSeed64 "context-info") 32
  assertEqual "TLS12 KDF ctx KAT"
    (Just (hex "5c0125c5f281488f681349499f252df0d29934469aabc15136b0a6a78a4b39d7")) gotKdf
  gotExt <- derive tlsKdfExtMech
    (encodeTlsKdfParams 4 "extended master secret" tlsKdfSess32 BS.empty) 48
  assertEqual "extended master KAT"
    (Just (hex "c3d5ea08b472cbb67e205711e5006647e2b8cb5f6b2a20847780122bdb78cf874a37fb5aa6ae0e3ce513256f888efa1b")) gotExt

ikePlusMech, ikePrfMech, ike1Mech, ikeExtMech :: MechanismId
ikePlusMech = MechanismId ckm_IKE2_PRF_PLUS_DERIVE
ikePrfMech = MechanismId ckm_IKE_PRF_DERIVE
ike1Mech = MechanismId ckm_IKE1_PRF_DERIVE
ikeExtMech = MechanismId ckm_IKE1_EXTENDED_DERIVE

ikeNi, ikeNr, ikeSeed32 :: BS.ByteString
ikeNi = BS.pack (replicate 16 1)
ikeNr = BS.pack (replicate 16 2)
ikeSeed32 = ikeNi <> ikeNr

caseIkePlans :: IO ()
caseIkePlans = do
  m0 <- seedModel
  st <- getSession m0
  (m1, baseH) <- plantKey m0 st
    [ (AttrClass, ValULong ckoSecretKey)
    , (AttrKeyType, ValULong ckkGenericSecret)
    , (AttrToken, ValBool False)
    , (AttrDerive, ValBool True)
    ] (BS.pack [0 .. 31])
  (m2, auxH) <- plantKey m1 st
    [ (AttrClass, ValULong ckoSecretKey)
    , (AttrKeyType, ValULong ckkGenericSecret)
    , (AttrToken, ValBool False)
    , (AttrDerive, ValBool True)
    ] (BS.pack [32 .. 63])
  let auxN = fromIntegral (unExternalHandle auxH)
      kid :: Int -> [(AttributeType, AttributeValue)]
      kid n =
        [ (AttrClass, ValULong ckoSecretKey)
        , (AttrKeyType, ValULong ckkGenericSecret)
        , (AttrValueLen, ValULong (fromIntegral n))
        , (AttrToken, ValBool False)
        ]
      fPlus = encodeIkeParams 4 0 0 0 ikeSeed32 BS.empty
      fPrf = encodeIkeParams 4 1 0 0 ikeNi ikeNr
      fIke1 = encodeIkeParams 4 0 7 auxN ikeNi ikeNr
      fExt = encodeIkeParams 4 0 0 auxN ikeSeed32 BS.empty
  -- Each row plans with its frame; the two-key rows bind fxKey2.
  mapM_ (\(mech, frame, n, needsAux) ->
    case planDerive defaultRules m2 st mech baseH
        (encodeDeriveParams frame [kid n]) of
      KeyEffect _ (FxDerive _ _ mAux _ _ total) -> do
        assertEqual ("total " ++ show mech) n total
        assertEqual ("aux " ++ show mech) needsAux (mAux /= Nothing)
      other -> assertFailure ("must plan, got: " ++ show other))
    [ (ikePlusMech, fPlus, 32, False)
    , (ikePrfMech, fPrf, 32, False)
    , (ike1Mech, fIke1, 32, True)
    , (ikeExtMech, fExt, 32, True)
    ]
  -- A wrong-row frame refuses typed.
  case planDerive defaultRules m2 st ike1Mech baseH
      (encodeDeriveParams fPlus [kid 32]) of
    KeyDenied (KeyDeny code _) ->
      assertEqual "wrong-row code" CKR_ARGUMENTS_BAD code
    other -> assertFailure ("wrong row must deny, got: " ++ show other)
  -- The reserved PRF code denies with the spec-exact code.
  case planDerive defaultRules m2 st ikePrfMech baseH
      (encodeDeriveParams (encodeIkeParams 0 1 0 0 ikeNi ikeNr) [kid 32]) of
    KeyDenied (KeyDeny code _) ->
      assertEqual "prf code" CKR_MECHANISM_PARAM_INVALID code
    other -> assertFailure ("prf 0 must deny, got: " ++ show other)
  -- An unknown aux handle denies typed.
  case planDerive defaultRules m2 st ike1Mech baseH
      (encodeDeriveParams (encodeIkeParams 4 0 7 999999 ikeNi ikeNr) [kid 32]) of
    KeyDenied (KeyDeny code _) ->
      assertEqual "aux code" CKR_KEY_HANDLE_INVALID code
    other -> assertFailure ("bad aux must deny, got: " ++ show other)
  -- Output past the ceiling refuses typed.
  case planDerive defaultRules m2 st ikePlusMech baseH
      (encodeDeriveParams fPlus [kid (fromIntegral (maxIkeOutput + 1))]) of
    KeyDenied (KeyDeny code _) ->
      assertEqual "ceiling code" CKR_ARGUMENTS_BAD code
    other -> assertFailure ("over-ceiling must deny, got: " ++ show other)

caseRealIkeVector :: IO ()
caseRealIkeVector = withRealEnv $ \env -> do
  m0 <- seedModel >>= loginUser
  st <- getSession m0
  let answer = answerReal env
  (m1, baseH) <- plantKey m0 st
    [ (AttrClass, ValULong ckoSecretKey)
    , (AttrKeyType, ValULong ckkGenericSecret)
    , (AttrToken, ValBool False)
    , (AttrDerive, ValBool True)
    ] (BS.pack [0 .. 31])
  (m2, auxH) <- plantKey m1 st
    [ (AttrClass, ValULong ckoSecretKey)
    , (AttrKeyType, ValULong ckkGenericSecret)
    , (AttrToken, ValBool False)
    , (AttrDerive, ValBool True)
    ] (BS.pack [32 .. 63])
  let auxN = fromIntegral (unExternalHandle auxH)
      kid :: Int -> [(AttributeType, AttributeValue)]
      kid n =
        [ (AttrClass, ValULong ckoSecretKey)
        , (AttrKeyType, ValULong ckkGenericSecret)
        , (AttrValueLen, ValULong (fromIntegral n))
        , (AttrToken, ValBool False)
        ]
      derive mech frame n = do
        (m', [h]) <- case planDerive defaultRules m2 st mech baseH
            (encodeDeriveParams frame [kid n]) of
          KeyEffect pw fx -> do
            res <- answer m2 fx
            c <- finishCommit m2 st pw res 1
            hh <- handleOf (pcOutputs c !! 0)
            m' <- expectRight (publishDelta m2 (pcDelta c))
            pure (m', [hh])
          other -> assertFailure ("derive must plan: " ++ show other) >> undefined
        Just ost <- pure (resolveHandle m' h)
        pure (keyBytesOf ost)
      fPlus = encodeIkeParams 4 0 0 0 ikeSeed32 BS.empty
      fPrfDk = encodeIkeParams 4 1 0 0 ikeNi ikeNr
      fPrfK = encodeIkeParams 4 0 0 0 ikeNi ikeNr
      fIke1 = encodeIkeParams 4 0 7 auxN ikeNi ikeNr
      fExt = encodeIkeParams 4 0 0 auxN ikeSeed32 BS.empty
  gotPlus <- derive ikePlusMech fPlus 32
  assertEqual "ike prf+ KAT"
    (Just (hex "e3703ee905295e6c0141c98f382e17e9df07a5d0e7fb5d1d5eb45e117022cbb1")) gotPlus
  gotPrfDk <- derive ikePrfMech fPrfDk 32
  assertEqual "ike prf data-as-key KAT"
    (Just (hex "909be39279fec3ad8b16546a956974ee435bb4acfa8f0c9167f0f019ff977f45")) gotPrfDk
  gotPrfK <- derive ikePrfMech fPrfK 32
  assertEqual "ike prf key order KAT"
    (Just (hex "df53a0de91b1e3a8d1523ea225bbc6814065bbe96203108f45501f20467046fb")) gotPrfK
  gotIke1 <- derive ike1Mech fIke1 32
  assertEqual "ike1 prf KAT"
    (Just (hex "612802ecc378ea82898f416865a51c36ade29e1acfbe2bceb19033c95a702f5a")) gotIke1
  gotExt <- derive ikeExtMech fExt 32
  assertEqual "ike extended KAT"
    (Just (hex "1c81c4b9c9083605362e98bed89e4eef320559270ae273a55ed90710e74e6951")) gotExt

concatKeyMech, concatDataMech, dataConcatMech, xorMech, extractMech :: MechanismId
concatKeyMech = MechanismId ckm_CONCATENATE_BASE_AND_KEY
concatDataMech = MechanismId ckm_CONCATENATE_BASE_AND_DATA
dataConcatMech = MechanismId ckm_CONCATENATE_DATA_AND_BASE
xorMech = MechanismId ckm_XOR_BASE_AND_DATA
extractMech = MechanismId ckm_EXTRACT_KEY_FROM_KEY

byteOpsD16 :: BS.ByteString
byteOpsD16 = BS.pack (replicate 16 1)

caseByteOpsPlans :: IO ()
caseByteOpsPlans = do
  m0 <- seedModel
  st <- getSession m0
  (m1, baseH) <- plantKey m0 st
    [ (AttrClass, ValULong ckoSecretKey)
    , (AttrKeyType, ValULong ckkGenericSecret)
    , (AttrToken, ValBool False)
    , (AttrDerive, ValBool True)
    ] (BS.pack [0 .. 31])
  (m2, auxH) <- plantKey m1 st
    [ (AttrClass, ValULong ckoSecretKey)
    , (AttrKeyType, ValULong ckkGenericSecret)
    , (AttrToken, ValBool False)
    , (AttrDerive, ValBool True)
    ] (BS.pack [32 .. 63])
  let auxN = fromIntegral (unExternalHandle auxH)
      kid :: Int -> [(AttributeType, AttributeValue)]
      kid n =
        [ (AttrClass, ValULong ckoSecretKey)
        , (AttrKeyType, ValULong ckkGenericSecret)
        , (AttrValueLen, ValULong (fromIntegral n))
        , (AttrToken, ValBool False)
        ]
      kidNoLen =
        [ (AttrClass, ValULong ckoSecretKey)
        , (AttrKeyType, ValULong ckkGenericSecret)
        , (AttrToken, ValBool False)
        ]
      fKey = encodeByteOpsParams auxN 0 BS.empty
      fBD = encodeByteOpsParams 0 0 byteOpsD16
      fXor = encodeByteOpsParams 0 0 (BS.pack [0 .. 31])
      fExt = encodeByteOpsParams 0 0 BS.empty
  -- Each row plans with its frame; concat-key binds fxKey2.
  mapM_ (\(mech, frame, n, needsAux) ->
    case planDerive defaultRules m2 st mech baseH
        (encodeDeriveParams frame [kid n]) of
      KeyEffect _ (FxDerive _ _ mAux _ _ total) -> do
        assertEqual ("total " ++ show mech) n total
        assertEqual ("aux " ++ show mech) needsAux (mAux /= Nothing)
      other -> assertFailure ("must plan, got: " ++ show other))
    [ (concatKeyMech, fKey, 64, True)
    , (concatDataMech, fBD, 16, False)
    , (dataConcatMech, fBD, 16, False)
    , (xorMech, fXor, 16, False)
    , (extractMech, fExt, 16, False)
    ]
  -- Concat rows default a missing length to the full width.
  case planDerive defaultRules m2 st concatDataMech baseH
      (encodeDeriveParams fBD [kidNoLen]) of
    KeyEffect _ (FxDerive _ _ _ _ _ total) ->
      assertEqual "natural total" 48 total
    other -> assertFailure ("must default, got: " ++ show other)
  -- A wrong-row frame refuses typed.
  case planDerive defaultRules m2 st concatKeyMech baseH
      (encodeDeriveParams fBD [kid 16]) of
    KeyDenied (KeyDeny code _) ->
      assertEqual "wrong-row code" CKR_ARGUMENTS_BAD code
    other -> assertFailure ("wrong row must deny, got: " ++ show other)
  -- Output past the natural width refuses typed.
  case planDerive defaultRules m2 st concatDataMech baseH
      (encodeDeriveParams fBD [kid 49]) of
    KeyDenied (KeyDeny code _) ->
      assertEqual "natural code" CKR_KEY_SIZE_RANGE code
    other -> assertFailure ("over-natural must deny, got: " ++ show other)
  -- XOR over mismatched lengths refuses typed.
  case planDerive defaultRules m2 st xorMech baseH
      (encodeDeriveParams fBD [kid 16]) of
    KeyDenied (KeyDeny code _) ->
      assertEqual "xor code" CKR_DATA_LEN_RANGE code
    other -> assertFailure ("xor mismatch must deny, got: " ++ show other)
  -- EXTRACT without a template length refuses typed.
  case planDerive defaultRules m2 st extractMech baseH
      (encodeDeriveParams fExt [kidNoLen]) of
    KeyDenied (KeyDeny code _) ->
      assertEqual "extract code" CKR_TEMPLATE_INCOMPLETE code
    other -> assertFailure ("extract no-len must deny, got: " ++ show other)
  -- EXTRACT past the base end refuses typed.
  case planDerive defaultRules m2 st extractMech baseH
      (encodeDeriveParams (encodeByteOpsParams 0 248 BS.empty) [kid 16]) of
    KeyDenied (KeyDeny code _) ->
      assertEqual "overrun code" CKR_ARGUMENTS_BAD code
    other -> assertFailure ("overrun must deny, got: " ++ show other)
  -- An unknown second handle denies typed.
  case planDerive defaultRules m2 st concatKeyMech baseH
      (encodeDeriveParams (encodeByteOpsParams 999999 0 BS.empty) [kid 64]) of
    KeyDenied (KeyDeny code _) ->
      assertEqual "aux code" CKR_KEY_HANDLE_INVALID code
    other -> assertFailure ("bad aux must deny, got: " ++ show other)

caseRealByteOpsVector :: IO ()
caseRealByteOpsVector = withRealEnv $ \env -> do
  m0 <- seedModel >>= loginUser
  st <- getSession m0
  let answer = answerReal env
  (m1, baseH) <- plantKey m0 st
    [ (AttrClass, ValULong ckoSecretKey)
    , (AttrKeyType, ValULong ckkGenericSecret)
    , (AttrToken, ValBool False)
    , (AttrDerive, ValBool True)
    ] (BS.pack [0 .. 31])
  (m2, auxH) <- plantKey m1 st
    [ (AttrClass, ValULong ckoSecretKey)
    , (AttrKeyType, ValULong ckkGenericSecret)
    , (AttrToken, ValBool False)
    , (AttrDerive, ValBool True)
    ] (BS.pack [32 .. 63])
  let auxN = fromIntegral (unExternalHandle auxH)
      kid :: Int -> [(AttributeType, AttributeValue)]
      kid n =
        [ (AttrClass, ValULong ckoSecretKey)
        , (AttrKeyType, ValULong ckkGenericSecret)
        , (AttrValueLen, ValULong (fromIntegral n))
        , (AttrToken, ValBool False)
        ]
      derive mech frame n = do
        (m', [h]) <- case planDerive defaultRules m2 st mech baseH
            (encodeDeriveParams frame [kid n]) of
          KeyEffect pw fx -> do
            res <- answer m2 fx
            c <- finishCommit m2 st pw res 1
            hh <- handleOf (pcOutputs c !! 0)
            m' <- expectRight (publishDelta m2 (pcDelta c))
            pure (m', [hh])
          other -> assertFailure ("derive must plan: " ++ show other) >> undefined
        Just ost <- pure (resolveHandle m' h)
        pure (keyBytesOf ost)
      fKey = encodeByteOpsParams auxN 0 BS.empty
      fBD = encodeByteOpsParams 0 0 byteOpsD16
      fXor = encodeByteOpsParams 0 0 (BS.pack (replicate 32 0x0f))
      fExt = encodeByteOpsParams 0 0 BS.empty
      fExt4 = encodeByteOpsParams 0 4 BS.empty
  gotKey <- derive concatKeyMech fKey 64
  assertEqual "concat-key KAT"
    (Just (hex "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f")) gotKey
  gotBD <- derive concatDataMech fBD 48
  assertEqual "concat-data KAT"
    (Just (hex "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f01010101010101010101010101010101")) gotBD
  gotDB <- derive dataConcatMech fBD 48
  assertEqual "data-concat KAT"
    (Just (hex "01010101010101010101010101010101000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")) gotDB
  gotXor <- derive xorMech fXor 32
  assertEqual "xor KAT"
    (Just (hex "0f0e0d0c0b0a090807060504030201001f1e1d1c1b1a19181716151413121110")) gotXor
  gotExt <- derive extractMech fExt 16
  assertEqual "extract KAT"
    (Just (hex "000102030405060708090a0b0c0d0e0f")) gotExt
  gotExt4 <- derive extractMech fExt4 2
  assertEqual "extract sub-byte KAT" (Just (hex "0010")) gotExt4

keyMat10Mech, keyMat12Mech, keyMatSafeMech :: MechanismId
keyMat10Mech = MechanismId ckm_TLS_KEY_AND_MAC_DERIVE
keyMat12Mech = MechanismId ckm_TLS12_KEY_AND_MAC_DERIVE
keyMatSafeMech = MechanismId ckm_TLS12_KEY_SAFE_DERIVE

keyMatCr, keyMatSr :: BS.ByteString
keyMatCr = BS.pack [0 .. 31]
keyMatSr = BS.pack [32 .. 63]

-- | The single key-material template: protection matching an
-- extractable non-sensitive base, no length (lengths come
-- from params).
keyMatKid :: [(AttributeType, AttributeValue)]
keyMatKid =
  [ (AttrClass, ValULong ckoSecretKey)
  , (AttrKeyType, ValULong ckkGenericSecret)
  , (AttrSensitive, ValBool False)
  , (AttrExtractable, ValBool True)
  , (AttrToken, ValBool False)
  ]

ssl3MasterMech, ssl3MasterDhMech, ssl3KeyMatMech :: MechanismId
ssl3MasterMech = MechanismId ckm_SSL3_MASTER_KEY_DERIVE
ssl3MasterDhMech = MechanismId ckm_SSL3_MASTER_KEY_DERIVE_DH
ssl3KeyMatMech = MechanismId ckm_SSL3_KEY_AND_MAC_DERIVE

-- | The oracle's 28-byte randoms (SSL3 randoms carry
-- explicit lengths; no fixed 32).
ssl3Cr, ssl3Sr :: BS.ByteString
ssl3Cr = BS.pack [0 .. 27]
ssl3Sr = BS.pack [28 .. 55]

-- | The SSL3 master template: the oracle's shape (48-byte
-- generic secret, protection matching the base).
ssl3MasterKid :: [(AttributeType, AttributeValue)]
ssl3MasterKid =
  [ (AttrClass, ValULong ckoSecretKey)
  , (AttrKeyType, ValULong ckkGenericSecret)
  , (AttrValueLen, ValULong 48)
  , (AttrSensitive, ValBool False)
  , (AttrExtractable, ValBool True)
  , (AttrToken, ValBool False)
  , (AttrDerive, ValBool True)
  ]

caseSsl3DerivePlans :: IO ()
caseSsl3DerivePlans = do
  m0 <- seedModel
  st <- getSession m0
  (m1, baseH) <- plantKey m0 st
    [ (AttrClass, ValULong ckoSecretKey)
    , (AttrKeyType, ValULong ckkGenericSecret)
    , (AttrToken, ValBool False)
    , (AttrDerive, ValBool True)
    , (AttrSensitive, ValBool False)
    , (AttrExtractable, ValBool True)
    ] (BS.pack [0 .. 47])
  let fm = encodeSsl3MasterParams ssl3Cr ssl3Sr
      fk = encodeSsl3KeyMatParams 16 16 16 ssl3Cr ssl3Sr
  -- Master rows plan the fixed 48-byte output.
  mapM_ (\mech ->
    case planDerive defaultRules m1 st mech baseH
        (encodeDeriveParams fm [ssl3MasterKid]) of
      KeyEffect (PwDerive _ [48]) (FxDerive _ _ _ _ _ 48) -> pure ()
      other -> assertFailure ("master must plan, got: " ++ show other))
    [ssl3MasterMech, ssl3MasterDhMech]
  -- The keymat row plans its key/IV shape with the block total.
  case planDerive defaultRules m1 st ssl3KeyMatMech baseH
      (encodeDeriveParams fk [keyMatKid]) of
    KeyEffect (PwDeriveIv _ [16, 16, 16, 16] (16, 16)) (FxDerive _ _ _ _ _ 96) ->
      pure ()
    other -> assertFailure ("keymat must plan, got: " ++ show other)
  -- A non-generic base refuses (the key-type gate outranks shape).
  (m2, aesH) <- plantKey m1 st
    [ (AttrClass, ValULong ckoSecretKey)
    , (AttrKeyType, ValULong ckkAes)
    , (AttrToken, ValBool False)
    , (AttrDerive, ValBool True)
    , (AttrSensitive, ValBool False)
    , (AttrExtractable, ValBool True)
    ] (BS.pack [0 .. 15])
  case planDerive defaultRules m2 st ssl3MasterMech aesH
      (encodeDeriveParams fm [ssl3MasterKid]) of
    KeyDenied (KeyDeny code _) ->
      assertEqual "base code" CKR_KEY_TYPE_INCONSISTENT code
    other -> assertFailure ("AES base must deny, got: " ++ show other)
  -- A template length on keymat refuses: lengths come from params.
  case planDerive defaultRules m1 st ssl3KeyMatMech baseH
      (encodeDeriveParams fk [keyMatKid ++ [(AttrValueLen, ValULong 16)]]) of
    KeyDenied (KeyDeny code _) ->
      assertEqual "vlen code" CKR_TEMPLATE_INCONSISTENT code
    other -> assertFailure ("vlen must deny, got: " ++ show other)
  -- Protection differing from the base refuses (the oracle's
  -- template-conflict leg).
  let conflict =
        [ (AttrClass, ValULong ckoSecretKey)
        , (AttrKeyType, ValULong ckkGenericSecret)
        , (AttrSensitive, ValBool True)
        , (AttrExtractable, ValBool True)
        , (AttrToken, ValBool False)
        ]
  case planDerive defaultRules m1 st ssl3KeyMatMech baseH
      (encodeDeriveParams fk [conflict]) of
    KeyDenied (KeyDeny code _) ->
      assertEqual "conflict code" CKR_TEMPLATE_INCONSISTENT code
    other -> assertFailure ("conflict must deny, got: " ++ show other)
  -- A malformed frame refuses typed.
  case planDerive defaultRules m1 st ssl3MasterMech baseH
      (encodeDeriveParams (BS.take 10 fm) [ssl3MasterKid]) of
    KeyDenied (KeyDeny code _) ->
      assertEqual "shape code" CKR_ARGUMENTS_BAD code
    other -> assertFailure ("bad shape must deny, got: " ++ show other)

caseRealSsl3Vector :: IO ()
caseRealSsl3Vector = withRealEnv $ \env -> do
  m0 <- seedModel >>= loginUser
  st <- getSession m0
  let answer = answerReal env
  (m1, baseH) <- plantKey m0 st
    [ (AttrClass, ValULong ckoSecretKey)
    , (AttrKeyType, ValULong ckkGenericSecret)
    , (AttrToken, ValBool False)
    , (AttrDerive, ValBool True)
    , (AttrSensitive, ValBool False)
    , (AttrExtractable, ValBool True)
    ] (BS.pack [3, 0] <> BS.pack [2 .. 47])
  (m2, dhH) <- plantKey m1 st
    [ (AttrClass, ValULong ckoSecretKey)
    , (AttrKeyType, ValULong ckkGenericSecret)
    , (AttrToken, ValBool False)
    , (AttrDerive, ValBool True)
    , (AttrSensitive, ValBool False)
    , (AttrExtractable, ValBool True)
    ] (BS.pack [0 .. 31])
  let fm = encodeSsl3MasterParams ssl3Cr ssl3Sr
      deriveOne mech base tmpl = do
        (_m', mat) <- case planDerive defaultRules m2 st mech base
            (encodeDeriveParams fm [tmpl]) of
          KeyEffect pw fx -> do
            res <- answer m2 fx
            c <- finishCommit m2 st pw res 1
            let outs = pcOutputs c
            hs <- mapM handleOf [o | o@(NativeOutput (RegionHandle "key") _) <- outs]
            m' <- expectRight (publishDelta m2 (pcDelta c))
            mats <- mapM (\h -> case resolveHandle m' h of
              Just ost -> pure (keyBytesOf ost)
              Nothing -> assertFailure "derived key must resolve" >> undefined) hs
            pure (m', mats)
          other -> assertFailure ("derive must plan: " ++ show other) >> undefined
        pure mat
  [master48] <- deriveOne ssl3MasterMech baseH ssl3MasterKid
  assertEqual "master48"
    (Just (hex "faf3f20343e53bd6b6d81b3642a2f78a64e1b5837aace5b9ce41e8e14ff1140d3908bac02e5afe34652644a90dbb5f59"))
    master48
  [masterDh] <- deriveOne ssl3MasterDhMech dhH ssl3MasterKid
  assertEqual "masterDH32"
    (Just (hex "159ce46fa901e70e79d351599fd24cdc5e98c7db7921972aa8c67151657aa89232e3b01d3fb09584bfd678b52b31e302"))
    masterDh
  (m3, msH) <- plantKey m2 st
    [ (AttrClass, ValULong ckoSecretKey)
    , (AttrKeyType, ValULong ckkGenericSecret)
    , (AttrToken, ValBool False)
    , (AttrDerive, ValBool True)
    , (AttrSensitive, ValBool False)
    , (AttrExtractable, ValBool True)
    ] (hex "faf3f20343e53bd6b6d81b3642a2f78a64e1b5837aace5b9ce41e8e14ff1140d3908bac02e5afe34652644a90dbb5f59")
  let fk = encodeSsl3KeyMatParams 16 16 16 ssl3Cr ssl3Sr
  (mats, (ivc, ivs)) <- case planDerive defaultRules m3 st ssl3KeyMatMech msH
      (encodeDeriveParams fk [keyMatKid]) of
    KeyEffect pw fx -> do
      res <- answer m3 fx
      c <- finishCommit m3 st pw res 4
      let outs = pcOutputs c
      hs <- mapM handleOf [o | o@(NativeOutput (RegionHandle "key") _) <- outs]
      let iv n = case [bs | NativeOutput (RegionBytes m _) bs <- outs, m == n] of
            [bs] -> bs
            _ -> BS.empty
      m' <- expectRight (publishDelta m3 (pcDelta c))
      mats <- mapM (\h -> case resolveHandle m' h of
        Just ost -> pure (keyBytesOf ost)
        Nothing -> assertFailure "derived key must resolve" >> undefined) hs
      pure (mats, (iv "iv-client", iv "iv-server"))
    other -> assertFailure ("keymat must plan: " ++ show other) >> undefined
  assertEqual "keymat keys"
    [ Just (hex "698e3265825326fdf57444e2b1e45064")
    , Just (hex "cceb1267b84f81e14a1ce6c2d9696031")
    , Just (hex "f9efaf9d8e27955f638bda4d0df1d6ab")
    , Just (hex "0eca6dccabd29fdff201da989870bcea")
    ] mats
  assertEqual "keymat ivc" (hex "083ea2e07385c9580f7cf01db35d0a20") ivc
  assertEqual "keymat ivs" (hex "e601719a5c2a088bd3478436d42fe569") ivs

caseKeyMatPlans :: IO ()
caseKeyMatPlans = do
  m0 <- seedModel
  st <- getSession m0
  (m1, baseH) <- plantKey m0 st
    [ (AttrClass, ValULong ckoSecretKey)
    , (AttrKeyType, ValULong ckkGenericSecret)
    , (AttrToken, ValBool False)
    , (AttrDerive, ValBool True)
    , (AttrSensitive, ValBool False)
    , (AttrExtractable, ValBool True)
    ] (BS.pack [0 .. 47])
  let f10 = encodeTlsKeyMatParams 0 0 16 16 keyMatCr keyMatSr
      f12 = encodeTlsKeyMatParams 4 0 16 16 keyMatCr keyMatSr
      f12m = encodeTlsKeyMatParams 4 20 16 16 keyMatCr keyMatSr
  -- Each row plans its key/IV shape with the block total.
  mapM_ (\(mech, frame, lens, ivs, total) ->
    case planDerive defaultRules m1 st mech baseH
        (encodeDeriveParams frame [keyMatKid]) of
      KeyEffect (PwDeriveIv _ gotLens gotIvs) (FxDerive _ _ _ _ _ gotTotal) -> do
        assertEqual ("lens " ++ show mech) lens gotLens
        assertEqual ("ivs " ++ show mech) ivs gotIvs
        assertEqual ("total " ++ show mech) total gotTotal
      other -> assertFailure ("must plan, got: " ++ show other))
    [ (keyMat10Mech, f10, [16, 16], (16, 16), 64)
    , (keyMat12Mech, f12, [16, 16], (16, 16), 64)
    , (keyMat12Mech, f12m, [20, 20, 16, 16], (16, 16), 104)
    , (keyMatSafeMech, f12, [16, 16], (0, 0), 32)
    ]
  -- A template length refuses: lengths come from params.
  case planDerive defaultRules m1 st keyMat12Mech baseH
      (encodeDeriveParams f12 [keyMatKid ++ [(AttrValueLen, ValULong 16)]]) of
    KeyDenied (KeyDeny code _) ->
      assertEqual "vlen code" CKR_TEMPLATE_INCONSISTENT code
    other -> assertFailure ("vlen must deny, got: " ++ show other)
  -- Protection differing from the base refuses (the oracle's
  -- template-conflict leg).
  let conflict =
        [ (AttrClass, ValULong ckoSecretKey)
        , (AttrKeyType, ValULong ckkGenericSecret)
        , (AttrSensitive, ValBool True)
        , (AttrExtractable, ValBool True)
        , (AttrToken, ValBool False)
        ]
  case planDerive defaultRules m1 st keyMat10Mech baseH
      (encodeDeriveParams f10 [conflict]) of
    KeyDenied (KeyDeny code _) ->
      assertEqual "conflict code" CKR_TEMPLATE_INCONSISTENT code
    other -> assertFailure ("conflict must deny, got: " ++ show other)
  -- A wrong-row frame refuses typed.
  case planDerive defaultRules m1 st keyMat10Mech baseH
      (encodeDeriveParams f12 [keyMatKid]) of
    KeyDenied (KeyDeny code _) ->
      assertEqual "wrong-row code" CKR_ARGUMENTS_BAD code
    other -> assertFailure ("wrong row must deny, got: " ++ show other)

caseRealKeyMatVector :: IO ()
caseRealKeyMatVector = withRealEnv $ \env -> do
  m0 <- seedModel >>= loginUser
  st <- getSession m0
  let answer = answerReal env
  (m1, baseH) <- plantKey m0 st
    [ (AttrClass, ValULong ckoSecretKey)
    , (AttrKeyType, ValULong ckkGenericSecret)
    , (AttrToken, ValBool False)
    , (AttrDerive, ValBool True)
    , (AttrSensitive, ValBool False)
    , (AttrExtractable, ValBool True)
    ] (BS.pack [0 .. 47])
  let derive mech frame nKeys = do
        (m', hs, ivs) <- case planDerive defaultRules m1 st mech baseH
            (encodeDeriveParams frame [keyMatKid]) of
          KeyEffect pw fx -> do
            res <- answer m1 fx
            c <- finishCommit m1 st pw res nKeys
            let outs = pcOutputs c
            hs <- mapM handleOf [o | o@(NativeOutput (RegionHandle "key") _) <- outs]
            let iv n = case [bs | NativeOutput (RegionBytes m _) bs <- outs, m == n] of
                  [bs] -> bs
                  _ -> BS.empty
            m' <- expectRight (publishDelta m1 (pcDelta c))
            pure (m', hs, (iv "iv-client", iv "iv-server"))
          other -> assertFailure ("derive must plan: " ++ show other) >> undefined
        mats <- mapM (\h -> case resolveHandle m' h of
          Just ost -> pure (keyBytesOf ost)
          Nothing -> assertFailure "derived key must resolve" >> undefined) hs
        pure (mats, ivs)
      f10 = encodeTlsKeyMatParams 0 0 16 16 keyMatCr keyMatSr
      f12m = encodeTlsKeyMatParams 4 20 16 16 keyMatCr keyMatSr
      fSafe = encodeTlsKeyMatParams 4 0 16 0 keyMatCr keyMatSr
  (tls10Keys, (tls10Ivc, tls10Ivs)) <- derive keyMat10Mech f10 2
  assertEqual "tls10 keys"
    [ Just (hex "f3771f99cf91858748dc50ed540edc39")
    , Just (hex "efb06a256dcd4d9ffdf87298f72cf700")
    ] tls10Keys
  assertEqual "tls10 ivc" (hex "f5585f14e9db80e3af1a7ccc2c218d42") tls10Ivc
  assertEqual "tls10 ivs" (hex "b36aa1a7584498f75edaca5bf8f86328") tls10Ivs
  (tls12Keys, (tls12Ivc, tls12Ivs)) <- derive keyMat12Mech f12m 4
  assertEqual "tls12 keys"
    [ Just (hex "fbe0dbb71e9097fcfe644317a16d334fac721a5f")
    , Just (hex "822730468a366a4ef2f2206848092b65ca8b00c3")
    , Just (hex "56742cd5bae70ed8ac35e70945a53033")
    , Just (hex "866a9b3abca98806f6ba1048b7cd53eb")
    ] tls12Keys
  assertEqual "tls12 ivc" (hex "2f2584955a68b87c9d198ce2c55c204f") tls12Ivc
  assertEqual "tls12 ivs" (hex "053dddc6f5ce4f96c242e8bb758cd5fa") tls12Ivs
  (safeKeys, (safeIvc, safeIvs)) <- derive keyMatSafeMech fSafe 2
  assertEqual "safe keys"
    [ Just (hex "fbe0dbb71e9097fcfe644317a16d334f")
    , Just (hex "ac721a5f822730468a366a4ef2f22068")
    ] safeKeys
  assertEqual "safe writes no ivs" (BS.empty, BS.empty) (safeIvc, safeIvs)

caseSp800MultiPlans :: IO ()
caseSp800MultiPlans = do
  m0 <- seedModel
  st <- getSession m0
  (m1, baseH) <- plantKey m0 st
    [ (AttrClass, ValULong ckoSecretKey)
    , (AttrKeyType, ValULong ckkGenericSecret)
    , (AttrToken, ValBool False)
    , (AttrDerive, ValBool True)
    ] (BS.pack [0 .. 31])
  let kid n =
        [ (AttrClass, ValULong ckoSecretKey)
        , (AttrKeyType, ValULong ckkAes)
        , (AttrValueLen, ValULong n)
        , (AttrToken, ValBool False)
        ]
      counter = encodeSp800Params 4 32 32 BS.empty sp800Fixed
  -- Primary plus one additional template plans two keys
  -- with the summed total (the frame-level multi path the
  -- FFI additional-keys chase feeds).
  case planDerive defaultRules m1 st sp800CounterMech baseH
      (encodeDeriveParams counter [kid 16, kid 16]) of
    KeyEffect (PwDerive _ lens) (FxDerive mech _ _ _ _ total) -> do
      assertEqual "mech" sp800CounterMech mech
      assertEqual "lens" [16, 16] lens
      assertEqual "total" 32 total
    other -> assertFailure ("multi must plan: " ++ show other)
  -- Over the fan-out the frame refuses typed.
  case planDerive defaultRules m1 st sp800CounterMech baseH
      (encodeDeriveParams counter (replicate 17 (kid 16))) of
    KeyDenied (KeyDeny code _) ->
      assertEqual "fanout code" CKR_ARGUMENTS_BAD code
    other -> assertFailure ("fanout must deny, got: " ++ show other)

caseRealAuthWrap :: IO ()
caseRealAuthWrap = withRealEnv $ \env -> do
  m0 <- seedModel >>= loginUser
  st <- getSession m0
  let answer = answerReal env
  (m1, wrapH) <- plantKey m0 st
    [ (AttrClass, ValULong ckoSecretKey)
    , (AttrKeyType, ValULong ckkAes)
    , (AttrToken, ValBool False)
    , (AttrWrap, ValBool True)
    , (AttrUnwrap, ValBool True)
    ] spKey
  (m2, targetH) <- plantKey m1 st
    [ (AttrClass, ValULong ckoSecretKey)
    , (AttrKeyType, ValULong ckkAes)
    , (AttrToken, ValBool False)
    , (AttrExtractable, ValBool True)
    ] spP1
  let aad = "real-aad"
  blob <- case planAuthWrapKey m2 st aesCbcMech spIv wrapH targetH aad (IntentBuffer 64) of
    KeyEffect pw fx -> do
      res <- answer m2 fx
      case finishWork m2 st pw res of
        Immediate c -> case pcOutputs c of
          [NativeOutput (RegionBytes "wrapped" _) bs] -> pure bs
          o -> assertFailure ("one blob: " ++ show o) >> undefined
        other -> assertFailure ("wrap must commit: " ++ show other) >> undefined
    other -> assertFailure ("wrap must plan: " ++ show other) >> undefined
  assertEqual "blob length" 64 (BS.length blob)
  -- The tag is the KAT'd HMAC over aad||ct under the derived tag key.
  mkRes <- macSign env (MacHMAC D_SHA256 Nothing) (KeyBytes spKey)
    "HASKOKI-AUTHWRAP-MAC-V1"
  macKey <- case mkRes of
    EngineOk k -> pure k
    EngineFail err -> assertFailure ("tag key failed: " ++ show err) >> undefined
  let (ct, tag) = BS.splitAt 32 blob
  tagRes <- macSign env (MacHMAC D_SHA256 Nothing) (KeyBytes macKey) (aad <> ct)
  tag2 <- case tagRes of
    EngineOk t -> pure t
    EngineFail err -> assertFailure ("tag recompute failed: " ++ show err) >> undefined
  assertEqual "tag binds aad and ct" tag tag2
  let tmpl = [(AttrClass, ValULong ckoSecretKey), (AttrKeyType, ValULong ckkAes)]
  case planAuthUnwrapKey defaultRules m2 st aesCbcMech spIv wrapH blob aad tmpl of
    KeyEffect pw fx -> do
      res <- answer m2 fx
      c <- finishCommit m2 st pw res 1
      h <- handleOf (pcOutputs c !! 0)
      m3 <- expectRight (publishDelta m2 (pcDelta c))
      Just ost <- pure (resolveHandle m3 h)
      assertEqual "real auth-unwrap recovers" (Just spP1) (keyBytesOf ost)
    other -> assertFailure ("unwrap must plan: " ++ show other)

caseRealAesKem :: IO ()
caseRealAesKem = withRealEnv $ \env -> do
  m0 <- seedModel >>= loginUser
  st <- getSession m0
  let answer = answerReal env
  (m1, fakeH) <- plantKey m0 st
    [ (AttrClass, ValULong ckoPublicKey)
    , (AttrKeyType, ValULong ckkMlKem)
    , (AttrKemAlg, ValULong 768)
    , (AttrToken, ValBool False)
    , (AttrEncapsulate, ValBool True)
    ] "not-a-real-kem-key"
  -- AES keygen: real via the native DRBG surface; one
  -- object lands carrying 32 fresh bytes.
  case planGenerateKey defaultRules m1 st aesKeyGenMech BS.empty (aesTmpl 32) of
    KeyEffect pw fx -> do
      res <- answer m1 fx
      c <- finishCommit m1 st pw res 1
      h <- handleOf (pcOutputs c !! 0)
      m2 <- expectRight (publishDelta m1 (pcDelta c))
      Just ost <- pure (resolveHandle m2 h)
      Just mat <- pure (keyBytesOf ost)
      assertEqual "real AES-256 material length" 32 (BS.length mat)
    other -> assertFailure ("AES keygen plan is not an effect: " ++ show other)
  -- ML-KEM keygen through the real backend mints a usable
  -- pair (provider DER halves, agreeing OIDs, 64-byte seed
  -- stamped, set tag kept); encaps/decaps round-trip; a
  -- corrupt KEM key fails closed as a bad key (GENERAL_ERROR),
  -- never unsupported.
  (m2, realPubH, realPrivH) <- genKemPair answer m1 st
  Just realPub <- pure (resolveHandle m2 realPubH)
  Just realPriv <- pure (resolveHandle m2 realPrivH)
  Just pubDer <- pure (keyBytesOf realPub)
  Just privDer <- pure (keyBytesOf realPriv)
  case (mlkemSpkiFields pubDer, mlkemPkcs8Fields privDer) of
    (Just (pubOid, _), Just (privOid, seed, _))
      | pubOid == privOid -> assertEqual "real seed width" 64 (BS.length seed)
    _ -> assertFailure "real KEM halves disagree or do not parse"
  assertEqual "real set tag" (Just (ValULong 2))
    (Map.lookup AttrParameterSet (osAttrs realPub))
  (m3, ct, ss) <- runEncaps answer m2 st realPubH
  assertEqual "real ct length" (kemCtLen KemMl768) (BS.length ct)
  assertEqual "real ss length" 32 (BS.length ss)
  case planKemDecaps m3 st mlKemMech realPrivH KemMl768 ct secretTmpl of
    KeyEffect pw fx -> do
      res <- answer m3 fx
      c <- finishCommit m3 st pw res 1
      h <- handleOf (pcOutputs c !! 0)
      m4 <- expectRight (publishDelta m3 (pcDelta c))
      Just ost <- pure (resolveHandle m4 h)
      assertEqual "real decaps recovers" (Just ss) (keyBytesOf ost)
    other -> assertFailure ("real decaps must plan: " ++ show other)
  case planKemEncaps m1 st mlKemMech fakeH KemMl768 secretTmpl
      (IntentBuffer (fromIntegral (kemCtLen KemMl768))) of
    KeyEffect pw fx -> do
      res <- answer m1 fx
      case res of
        GotCryptoError (CryptoBadKey _ _) -> pure ()
        other -> assertFailure ("must be a bad key, got: " ++ show other)
      case finishWork m1 st pw res of
        Reject r -> do
          assertEqual "code" CKR_GENERAL_ERROR (rejCode r)
          assertEqual "zero objects" (StateDelta []) (rejDelta r)
        other -> assertFailure ("must reject, got: " ++ show other)
    other -> assertFailure ("must plan an effect, got: " ++ show other)

caseKemWrongKeyType :: IO ()
caseKemWrongKeyType = withSynth $ \answer -> do
  m0 <- seedModel >>= loginUser
  st <- getSession m0
  (m1, aesH) <- genAesKey answer m0 st wrapKeyTmpl
  (m2, pubH, _) <- genKemPair answer m1 st
  let ctLen = kemCtLen KemMl768
      intent = IntentBuffer (fromIntegral ctLen)
  -- A wrong-typed key refuses TYPE_INCONSISTENT (the deep
  -- mismatch), even carrying usage flags.
  case planKemEncaps m2 st mlKemMech aesH KemMl768 secretTmpl intent of
    KeyDenied (KeyDeny code _) ->
      assertEqual "encaps wrong-type code" CKR_KEY_TYPE_INCONSISTENT code
    other -> assertFailure ("must deny, got: " ++ show other)
  case planKemDecaps m2 st mlKemMech aesH KemMl768 (BS.replicate ctLen 0) secretTmpl of
    KeyDenied (KeyDeny code _) ->
      assertEqual "decaps wrong-type code" CKR_KEY_TYPE_INCONSISTENT code
    other -> assertFailure ("must deny, got: " ++ show other)
  -- A right-typed key on another set refuses PERMITTED (the
  -- usage-class refusal, not a type contradiction).
  case planKemEncaps m2 st mlKemMech pubH KemMl512 secretTmpl intent of
    KeyDenied (KeyDeny code _) ->
      assertEqual "encaps wrong-set code" CKR_KEY_FUNCTION_NOT_PERMITTED code
    other -> assertFailure ("must deny, got: " ++ show other)
  -- An unknown handle refuses handle-invalid.
  case planKemEncaps m2 st mlKemMech (ExternalHandle 9999) KemMl768 secretTmpl intent of
    KeyDenied (KeyDeny code _) ->
      assertEqual "encaps bad-handle code" CKR_OBJECT_HANDLE_INVALID code
    other -> assertFailure ("must deny, got: " ++ show other)

caseKemAesTemplate :: IO ()
caseKemAesTemplate = withSynth $ \answer -> do
  m0 <- seedModel >>= loginUser
  st <- getSession m0
  (m1, pubH, privH) <- genKemPair answer m0 st
  let aesKemTmpl =
        [ (AttrClass, ValULong ckoSecretKey)
        , (AttrKeyType, ValULong ckkAes)
        , (AttrValueLen, ValULong 32)
        , (AttrToken, ValBool False)
        , (AttrExtractable, ValBool True)
        ]
      ctLen = kemCtLen KemMl768
  -- Encaps against an AES template mints an AES-256 object
  -- carrying the 32-byte secret.
  (m2, ct) <- case planKemEncaps m1 st mlKemMech pubH KemMl768 aesKemTmpl
      (IntentBuffer (fromIntegral ctLen)) of
    KeyEffect pw fx -> do
      res <- answer m1 fx
      c <- finishCommit m1 st pw res 1
      hh <- handleOf (pcOutputs c !! 1)
      m' <- expectRight (publishDelta m1 (pcDelta c))
      Just ost <- pure (resolveHandle m' hh)
      assertEqual "secret keytype" (Just (ValULong ckkAes))
        (Map.lookup AttrKeyType (osAttrs ost))
      case keyBytesOf ost of
        Just ss -> assertEqual "secret length" 32 (BS.length ss)
        Nothing -> assertFailure "AES secret lacks material"
      case pcOutputs c !! 0 of
        NativeOutput (RegionBytes "ciphertext" _) bytes -> pure (m', bytes)
        o -> assertFailure ("no ciphertext: " ++ show o) >> undefined
    other -> assertFailure ("must plan, got: " ++ show other) >> undefined
  -- Decaps against an AES template likewise mints AES-256.
  case planKemDecaps m2 st mlKemMech privH KemMl768 ct aesKemTmpl of
    KeyEffect pw fx -> do
      res <- answer m2 fx
      c <- finishCommit m2 st pw res 1
      hh <- handleOf (pcOutputs c !! 0)
      m' <- expectRight (publishDelta m2 (pcDelta c))
      Just ost <- pure (resolveHandle m' hh)
      assertEqual "decaps keytype" (Just (ValULong ckkAes))
        (Map.lookup AttrKeyType (osAttrs ost))
    other -> assertFailure ("must plan, got: " ++ show other)
  -- Any other explicit secret type refuses inconsistent.
  let rsaTmpl = (AttrKeyType, ValULong ckkRsa) :
        filter ((/= AttrKeyType) . fst) aesKemTmpl
  case planKemEncaps m1 st mlKemMech pubH KemMl768 rsaTmpl
      (IntentBuffer (fromIntegral ctLen)) of
    KeyDenied (KeyDeny code _) ->
      assertEqual "rsa template code" CKR_TEMPLATE_INCONSISTENT code
    other -> assertFailure ("must deny, got: " ++ show other)
  -- Mechanism-contributed attributes refuse inconsistent on
  -- both entries (the finisher would otherwise silently
  -- overwrite caller bytes with the real secret).
  let injected = (AttrValue, ValBytes "injected") : aesKemTmpl
  case planKemEncaps m1 st mlKemMech pubH KemMl768 injected
      (IntentBuffer (fromIntegral ctLen)) of
    KeyDenied (KeyDeny code _) ->
      assertEqual "encaps injection code" CKR_TEMPLATE_INCONSISTENT code
    other -> assertFailure ("must deny, got: " ++ show other)
  case planKemDecaps m2 st mlKemMech privH KemMl768 ct injected of
    KeyDenied (KeyDeny code _) ->
      assertEqual "decaps injection code" CKR_TEMPLATE_INCONSISTENT code
    other -> assertFailure ("must deny, got: " ++ show other)
  -- An AES template without CKA_VALUE_LEN proceeds (the 32 is
  -- mechanism-determined, supplied upfront for the presence
  -- rule rather than refused).
  let noLen = filter ((/= AttrValueLen) . fst) aesKemTmpl
  case planKemEncaps m1 st mlKemMech pubH KemMl768 noLen
      (IntentBuffer (fromIntegral ctLen)) of
    KeyEffect _ _ -> pure ()
    other -> assertFailure ("must plan, got: " ++ show other)

caseKemKeygenParamSet :: IO ()
caseKemKeygenParamSet = withSynth $ \answer -> do
  m0 <- seedModel >>= loginUser
  st <- getSession m0
  let setT tmpl v = (AttrParameterSet, ValULong v) :
        filter ((/= AttrParameterSet) . fst) tmpl
      noAlg tmpl = filter ((/= AttrKemAlg) . fst) tmpl
      gen pubT privT = planGenerateKeyPair defaultRules m0 st
        mlKemKeyPairGenMech pubT privT
  -- CKA_PARAMETER_SET selects the set (1/2/3 -> 512/768/1024);
  -- the minted halves carry both the numeric tag and the CKP id.
  mapM_ (\(ckp, alg) -> do
    let pubT = setT (noAlg kemPubTmpl) ckp
        privT = setT (noAlg kemPrivTmpl) ckp
    case gen pubT privT of
      KeyEffect pw fx -> do
        res <- answer m0 fx
        c <- finishCommit m0 st pw res 2
        pubH <- handleOf (pcOutputs c !! 0)
        privH <- handleOf (pcOutputs c !! 1)
        m' <- expectRight (publishDelta m0 (pcDelta c))
        Just pub <- pure (resolveHandle m' pubH)
        Just priv <- pure (resolveHandle m' privH)
        assertEqual ("alg tag " ++ show alg) (Just (ValULong alg))
          (Map.lookup AttrKemAlg (osAttrs pub))
        assertEqual ("ckp tag " ++ show alg) (Just (ValULong ckp))
          (Map.lookup AttrParameterSet (osAttrs priv))
        assertBool ("halves differ " ++ show alg)
          (keyBytesOf pub /= keyBytesOf priv)
      other -> assertFailure ("must plan: " ++ show other))
    [(1, 512), (2, 768), (3, 1024)]
  -- An unknown set refuses inconsistent.
  case gen (setT (noAlg kemPubTmpl) 7) (noAlg kemPrivTmpl) of
    KeyDenied (KeyDeny code _) ->
      assertEqual "unknown set code" CKR_TEMPLATE_INCONSISTENT code
    other -> assertFailure ("must deny, got: " ++ show other)
  -- Disagreeing templates refuse inconsistent.
  case gen (setT (noAlg kemPubTmpl) 1) (setT (noAlg kemPrivTmpl) 2) of
    KeyDenied (KeyDeny code _) ->
      assertEqual "disagree code" CKR_TEMPLATE_INCONSISTENT code
    other -> assertFailure ("must deny, got: " ++ show other)
  -- A template contradicting itself refuses inconsistent.
  let contra = (AttrKemAlg, ValULong 512) : setT (noAlg kemPubTmpl) 2
  case gen contra (noAlg kemPrivTmpl) of
    KeyDenied (KeyDeny code _) ->
      assertEqual "self-contradiction code" CKR_TEMPLATE_INCONSISTENT code
    other -> assertFailure ("must deny, got: " ++ show other)
  -- CKA_DERIVE stamps false on KEM halves (no derive
  -- operation exists): explicit-true refuses, and minted
  -- halves read back false (the oracle's derive-false leg
  -- only passes on an explicit false, not a missing flag).
  let withDerive tmpl = (AttrDerive, ValBool True) : tmpl
  case gen (withDerive (setT (noAlg kemPubTmpl) 2)) (noAlg kemPrivTmpl) of
    KeyDenied (KeyDeny code _) ->
      assertEqual "pub derive code" CKR_TEMPLATE_INCONSISTENT code
    other -> assertFailure ("must deny, got: " ++ show other)
  case gen (setT (noAlg kemPubTmpl) 2) (withDerive (noAlg kemPrivTmpl)) of
    KeyDenied (KeyDeny code _) ->
      assertEqual "priv derive code" CKR_TEMPLATE_INCONSISTENT code
    other -> assertFailure ("must deny, got: " ++ show other)
  case gen (setT (noAlg kemPubTmpl) 2) (setT (noAlg kemPrivTmpl) 2) of
    KeyEffect pw fx -> do
      res <- answer m0 fx
      c <- finishCommit m0 st pw res 2
      pubH <- handleOf (pcOutputs c !! 0)
      privH <- handleOf (pcOutputs c !! 1)
      m' <- expectRight (publishDelta m0 (pcDelta c))
      Just pub <- pure (resolveHandle m' pubH)
      Just priv <- pure (resolveHandle m' privH)
      assertEqual "minted pub derive false" (Just (ValBool False))
        (Map.lookup AttrDerive (osAttrs pub))
      assertEqual "minted priv derive false" (Just (ValBool False))
        (Map.lookup AttrDerive (osAttrs priv))
    other -> assertFailure ("must plan: " ++ show other)

-- ---------------------------------------------------------------------------
-- Part 6: key-output codecs
-- ---------------------------------------------------------------------------

-- | Fill a fresh buffer with the given bytes and hand its pointer on.
withInputBytes :: [Word8] -> (Ptr Word8 -> Word64 -> IO a) -> IO a
withInputBytes bytes k =
  allocaBytes (length bytes) $ \ptr -> do
    pokeArray ptr bytes
    k ptr (fromIntegral (length bytes))

caseHandleWriteback :: IO ()
caseHandleWriteback = do
  let plan = planHandleWriteback "key" (ExternalHandle 7)
  assertEqual "handle code" CKR_OK (opCode plan)
  assertEqual "one handle write"
    [TypedWrite ["key"] (RegionHandle "key") (PayloadHandle (ExternalHandle 7))]
    (opWrites plan)
  assertEqual "handle length" [(["key"], 8)] (opLengths plan)

caseWrappedWriteback :: IO ()
caseWrappedWriteback = do
  let blob = BS.pack [1 .. 32]
      query = planWrappedWriteback "wrapped" blob IntentNull
  assertEqual "query code" CKR_OK (opCode query)
  assertEqual "query writes nothing" [] (opWrites query)
  assertEqual "query length" [(["wrapped"], 32)] (opLengths query)
  let short = planWrappedWriteback "wrapped" blob (IntentBuffer 16)
  assertEqual "short code" CKR_BUFFER_TOO_SMALL (opCode short)
  assertEqual "short writes nothing" [] (opWrites short)
  assertEqual "short still reports" [(["wrapped"], 32)] (opLengths short)
  let exact = planWrappedWriteback "wrapped" blob (IntentBuffer 32)
  assertEqual "exact code" CKR_OK (opCode exact)
  assertEqual "exact writes the blob"
    [TypedWrite ["wrapped"] (RegionBytes "wrapped" (IntentBuffer 32)) (PayloadBytes blob)]
    (opWrites exact)

caseCiphertextWriteback :: IO ()
caseCiphertextWriteback = do
  let ct = BS.replicate 1088 9
      good = planCiphertextWriteback "ciphertext" 1088 ct (IntentBuffer 1088)
  assertEqual "good code" CKR_OK (opCode good)
  assertEqual "good writes once" 1 (length (opWrites good))
  let bad = planCiphertextWriteback "ciphertext" 1088 (BS.pack [1, 2, 3]) (IntentBuffer 1088)
  assertEqual "wrong length code" CKR_ARGUMENTS_BAD (opCode bad)
  assertEqual "wrong length writes nothing" [] (opWrites bad)
  let short = planCiphertextWriteback "ciphertext" 1088 ct (IntentBuffer 100)
  assertEqual "short code" CKR_BUFFER_TOO_SMALL (opCode short)
  assertEqual "short reports the length" [(["ciphertext"], 1088)] (opLengths short)

caseKeyInputDecode :: IO ()
caseKeyInputDecode = do
  withInputBytes [1 .. 40] $ \ptr len -> do
    wrapped <- decodeWrappedInput ptr len
    assertEqual "wrapped copied" (Right (BS.pack [1 .. 40])) wrapped
    kem <- decodeKemCiphertext 40 ptr len
    assertEqual "kem copied" (Right (BS.pack [1 .. 40])) kem
    mismatch <- decodeKemCiphertext 32 ptr len
    assertEqual "kem length enforced" (Left (KeyOutputLengthMismatch 32 40)) mismatch
  badNull <- decodeWrappedInput nullPtr 4
  assertEqual "null with length" (Left (KeyOutputBadPointer 4)) badNull
  tooLarge <- decodeWrappedInput nullPtr (maxInputBytes + 1)
  assertEqual "oversize rejects" (Left (KeyOutputTooLarge (maxInputBytes + 1))) tooLarge
  empty <- decodeWrappedInput nullPtr 0
  assertEqual "null empty" (Right BS.empty) empty

pbeDes3Mech, pbeDes2Mech :: MechanismId
pbeDes3Mech = MechanismId ckm_PBE_SHA1_DES3_EDE_CBC
pbeDes2Mech = MechanismId ckm_PBE_SHA1_DES2_EDE_CBC
pbeSha1Cast128Mech, pbeSha1Rc4_128Mech, pbeSha1Rc4_40Mech :: MechanismId
pbeSha1Cast128Mech = MechanismId ckm_PBE_SHA1_CAST128_CBC
pbeSha1Rc4_128Mech = MechanismId ckm_PBE_SHA1_RC4_128
pbeSha1Rc4_40Mech = MechanismId ckm_PBE_SHA1_RC4_40
pbeSha1Rc2_128Mech, pbeSha1Rc2_40Mech :: MechanismId
pbeSha1Rc2_128Mech = MechanismId ckm_PBE_SHA1_RC2_128_CBC
pbeSha1Rc2_40Mech = MechanismId ckm_PBE_SHA1_RC2_40_CBC
pbeMd5DesMech, pbeMd5CastMech :: MechanismId
pbeMd5DesMech = MechanismId ckm_PBE_MD5_DES_CBC
pbeMd5CastMech = MechanismId ckm_PBE_MD5_CAST_CBC
pbeMd5Cast3Mech, pbeMd5Cast128Mech :: MechanismId
pbeMd5Cast3Mech = MechanismId ckm_PBE_MD5_CAST3_CBC
pbeMd5Cast128Mech = MechanismId ckm_PBE_MD5_CAST128_CBC

pbePw, pbeSalt :: BS.ByteString
pbePw = "TestPassword123!"
pbeSalt = BS.pack [0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe]

-- | The lane's PBE template: fixed key type, usable secret,
-- no length (fixed widths default).
pbeTmpl :: Word64 -> [(AttributeType, AttributeValue)]
pbeTmpl k =
  [ (AttrClass, ValULong ckoSecretKey)
  , (AttrKeyType, ValULong k)
  , (AttrSensitive, ValBool False)
  , (AttrExtractable, ValBool True)
  , (AttrEncrypt, ValBool True)
  , (AttrDecrypt, ValBool True)
  , (AttrToken, ValBool False)
  ]

casePbePlans :: IO ()
casePbePlans = do
  m0 <- seedModel
  st <- getSession m0
  let frame = encodePbeParams 1024 pbePw pbeSalt
  -- Each row plans its fixed key type and length; the frame
  -- rides the effect and the pair stays coherent. The RC4
  -- rows plan key-only work, every other row key+iv.
  mapM_ (\(mech, wantKey, wantLen, wantIv) ->
    case planGenerateKey defaultRules m0 st mech frame (pbeTmpl wantKey) of
      KeyEffect pw fx@(FxGenerateKey _ gotFrame gotArgs) -> do
        assertEqual ("frame " ++ show mech) frame gotFrame
        assertEqual ("args " ++ show mech) (Just (GenPbe wantLen)) (decodeGenArgs gotArgs)
        case (pw, wantIv) of
          (PwGenerateKeyIv _ gotLen, True) ->
            assertEqual ("iv keylen " ++ show mech) wantLen gotLen
          (PwGenerateKey _, False) -> pure ()
          _ -> assertFailure ("PBE work mismatch, got: " ++ show pw)
        assertBool ("coherent " ++ show mech) (keyPairCompatible pw fx)
      other -> assertFailure ("PBE must plan, got: " ++ show other))
    [ (pbeDes3Mech, ckkDes3, 24, True), (pbeDes2Mech, ckkDes2, 16, True)
    , (pbeSha1Cast128Mech, ckkCast128, 16, True)
    , (pbeSha1Rc4_128Mech, ckkRc4, 16, False)
    , (pbeSha1Rc4_40Mech, ckkRc4, 5, False)
    , (pbeSha1Rc2_128Mech, ckkRc2, 16, True)
    , (pbeSha1Rc2_40Mech, ckkRc2, 5, True)
    , (pbeMd5DesMech, ckkDes, 8, True)
    , (pbeMd5CastMech, ckkCast, 5, True)
    , (pbeMd5Cast3Mech, ckkCast3, 10, True)
    , (pbeMd5Cast128Mech, ckkCast128, 16, True)
    ]
  -- A present length must match the fixed width.
  case planGenerateKey defaultRules m0 st pbeDes3Mech frame
      (pbeTmpl ckkDes3 ++ [(AttrValueLen, ValULong 16)]) of
    KeyDenied (KeyDeny code _) ->
      assertEqual "des3-16 code" CKR_TEMPLATE_INCONSISTENT code
    other -> assertFailure ("DES3-16 must deny, got: " ++ show other)
  case planGenerateKey defaultRules m0 st pbeDes3Mech frame
      (pbeTmpl ckkDes3 ++ [(AttrValueLen, ValULong 24)]) of
    KeyEffect _ _ -> pure ()
    other -> assertFailure ("DES3-24 must plan, got: " ++ show other)
  case planGenerateKey defaultRules m0 st pbeDes2Mech frame
      (pbeTmpl ckkDes2 ++ [(AttrValueLen, ValULong 24)]) of
    KeyDenied (KeyDeny code _) ->
      assertEqual "des2-24 code" CKR_TEMPLATE_INCONSISTENT code
    other -> assertFailure ("DES2-24 must deny, got: " ++ show other)
  -- A foreign key type refuses.
  case planGenerateKey defaultRules m0 st pbeDes3Mech frame (pbeTmpl ckkAes) of
    KeyDenied (KeyDeny code _) ->
      assertEqual "aes-type code" CKR_TEMPLATE_INCONSISTENT code
    other -> assertFailure ("AES type must deny, got: " ++ show other)
  -- Malformed frames refuse with the parameter code.
  mapM_ (\params ->
    case planGenerateKey defaultRules m0 st pbeDes3Mech params (pbeTmpl ckkDes3) of
      KeyDenied (KeyDeny code _) ->
        assertEqual ("params code " ++ show params) CKR_MECHANISM_PARAM_INVALID code
      other -> assertFailure ("params must deny, got: " ++ show other))
    [ BS.empty
    , BS.take 10 frame
    , encodePbeParams 0 pbePw pbeSalt
    , encodePbeParams (fromIntegral maxPbeIters + 1) pbePw pbeSalt
    ]

caseRealPbeVector :: IO ()
caseRealPbeVector = withRealEnv $ \env -> do
  m0 <- seedModel >>= loginUser
  st <- getSession m0
  let answer = answerReal env
      frame = encodePbeParams 1024 pbePw pbeSalt
      gen mech tmpl = case planGenerateKey defaultRules m0 st mech frame tmpl of
        KeyEffect pw fx -> do
          res <- answer m0 fx
          c <- finishCommit m0 st pw res 1
          let iv = case [bs | NativeOutput (RegionBytes m _) bs <- pcOutputs c, m == "iv"] of
                [bs] -> bs
                _ -> BS.empty
          m' <- expectRight (publishDelta m0 (pcDelta c))
          pure (m', iv)
        other -> assertFailure ("PBE must plan: " ++ show other) >> undefined
  (m1, iv3) <- gen pbeDes3Mech (pbeTmpl ckkDes3)
  assertEqual "des3 iv" (hex "f7eb3b1c7d9ce2a0") iv3
  case [ost | (_, ost) <- Map.toList (mObjects m1), keyBytesOf ost /= Nothing] of
    [ost] -> assertEqual "des3 key"
      (Just (hex "73b93bb0f797b564f7d90216b37f0ee9e9bc8004021fd39d"))
      (keyBytesOf ost)
    _ -> assertFailure "DES3 keygen must mint exactly one key"
  (m2, iv2) <- gen pbeDes2Mech (pbeTmpl ckkDes2)
  assertEqual "des2 iv" (hex "f7eb3b1c7d9ce2a0") iv2
  case [mat | (_, ost) <- Map.toList (mObjects m2), Just mat <- [keyBytesOf ost]] of
    [mat] -> assertEqual "des2 key" (hex "73b93bb0f797b564f7d90216b37f0ee9") mat
    _ -> assertFailure "DES2 keygen must mint exactly one key"

caseRealPbeSha1Vector :: IO ()
caseRealPbeSha1Vector = withRealEnv $ \env -> do
  m0 <- seedModel >>= loginUser
  st <- getSession m0
  let answer = answerReal env
      frame = encodePbeParams 1024 pbePw pbeSalt
      gen mech tmpl = case planGenerateKey defaultRules m0 st mech frame tmpl of
        KeyEffect pw fx -> do
          res <- answer m0 fx
          c <- finishCommit m0 st pw res 1
          let iv = case [bs | NativeOutput (RegionBytes m _) bs <- pcOutputs c, m == "iv"] of
                [bs] -> bs
                _ -> BS.empty
          m' <- expectRight (publishDelta m0 (pcDelta c))
          pure (m', iv)
        other -> assertFailure ("PBE must plan: " ++ show other) >> undefined
      keyOf m' label = case [mat | (_, ost) <- Map.toList (mObjects m'), Just mat <- [keyBytesOf ost]] of
        [mat] -> pure mat
        _ -> assertFailure (label ++ " must mint exactly one key") >> undefined
  (m5, iv5) <- gen pbeSha1Cast128Mech (pbeTmpl ckkCast128)
  assertEqual "cast128 iv" (hex "f7eb3b1c7d9ce2a0") iv5
  k5 <- keyOf m5 "CAST128"
  assertEqual "cast128 key" (hex "72b93bb1f796b464f6d80317b27e0fe8") k5
  (m6, iv6) <- gen pbeSha1Rc4_128Mech (pbeTmpl ckkRc4 ++ [(AttrValueLen, ValULong 16)])
  assertEqual "rc4-128 iv" BS.empty iv6
  k6 <- keyOf m6 "RC4-128"
  assertEqual "rc4-128 key" (hex "72b93bb1f796b464f6d80317b27e0fe8") k6
  (m7, iv7) <- gen pbeSha1Rc4_40Mech (pbeTmpl ckkRc4 ++ [(AttrValueLen, ValULong 5)])
  assertEqual "rc4-40 iv" BS.empty iv7
  k7 <- keyOf m7 "RC4-40"
  assertEqual "rc4-40 key" (hex "72b93bb1f7") k7
  (ma, iva) <- gen pbeSha1Rc2_128Mech (pbeTmpl ckkRc2 ++ [(AttrValueLen, ValULong 16)])
  assertEqual "rc2-128 iv" (hex "f7eb3b1c7d9ce2a0") iva
  ka <- keyOf ma "RC2-128"
  assertEqual "rc2-128 key" (hex "72b93bb1f796b464f6d80317b27e0fe8") ka
  (mb, ivb) <- gen pbeSha1Rc2_40Mech (pbeTmpl ckkRc2 ++ [(AttrValueLen, ValULong 5)])
  assertEqual "rc2-40 iv" (hex "f7eb3b1c7d9ce2a0") ivb
  kb <- keyOf mb "RC2-40"
  assertEqual "rc2-40 key" (hex "72b93bb1f7") kb

caseRealPbeMd5Vector :: IO ()
caseRealPbeMd5Vector = withRealEnv $ \env -> do
  m0 <- seedModel >>= loginUser
  st <- getSession m0
  let answer = answerReal env
      frame = encodePbeParams 1024 pbePw pbeSalt
      gen mech tmpl = case planGenerateKey defaultRules m0 st mech frame tmpl of
        KeyEffect pw fx -> do
          res <- answer m0 fx
          c <- finishCommit m0 st pw res 1
          let iv = case [bs | NativeOutput (RegionBytes m _) bs <- pcOutputs c, m == "iv"] of
                [bs] -> bs
                _ -> BS.empty
          m' <- expectRight (publishDelta m0 (pcDelta c))
          pure (m', iv)
        other -> assertFailure ("PBE must plan: " ++ show other) >> undefined
      keyOf m' label = case [mat | (_, ost) <- Map.toList (mObjects m'), Just mat <- [keyBytesOf ost]] of
        [mat] -> pure mat
        _ -> assertFailure (label ++ " must mint exactly one key") >> undefined
  (m1, iv1) <- gen pbeMd5DesMech (pbeTmpl ckkDes)
  assertEqual "md5-des iv" (hex "f3a2adee8fa98e67") iv1
  k1 <- keyOf m1 "MD5-DES"
  assertEqual "md5-des key" (hex "fed54f04efa44a7a") k1
  (m2, iv2) <- gen pbeMd5CastMech (pbeTmpl ckkCast ++ [(AttrValueLen, ValULong 5)])
  assertEqual "md5-cast iv" (hex "a44b7bf3a2adee8f") iv2
  k2 <- keyOf m2 "MD5-CAST"
  assertEqual "md5-cast key" (hex "ffd54e05ee") k2
  (m3, iv3) <- gen pbeMd5Cast3Mech (pbeTmpl ckkCast3 ++ [(AttrValueLen, ValULong 10)])
  assertEqual "md5-cast3 iv" (hex "adee8fa98e6769fb") iv3
  k3 <- keyOf m3 "MD5-CAST3"
  assertEqual "md5-cast3 key" (hex "ffd54e05eea44b7bf3a2") k3
  (m4, iv4) <- gen pbeMd5Cast128Mech (pbeTmpl ckkCast128 ++ [(AttrValueLen, ValULong 16)])
  assertEqual "md5-cast128 iv" (hex "69fba8ad294fa220") iv4
  k4 <- keyOf m4 "MD5-CAST128"
  assertEqual "md5-cast128 key" (hex "ffd54e05eea44b7bf3a2adee8fa98e67") k4
