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

import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit ( testCase)

import KeyManagement.Part1
import KeyManagement.Part2
import KeyManagement.KeygenSweep
import KeyManagement.Premaster
import KeyManagement.Part3
import KeyManagement.Part4
import KeyManagement.Part5
import KeyManagement.Part6
import KeyManagement.TC03f
import KeyManagement.CreationStamping

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
  , testCase "Derive inputs enforce the allowed-mechanism list" caseDeriveAllowedMechanisms
  , testCase "Derived DES-family bytes take odd-parity adjustment" caseDeriveDesParity
  , testCase "Derived generic bytes pass through unadjusted" caseDeriveGenericPassthrough
  , testCase "Derived keymat adjusts keys, never IVs" caseDeriveKeymatParity
  , testCase "Wrap inputs enforce the allowed-mechanism list" caseWrapAllowedMechanisms
  , testCase "KEM inputs enforce the allowed-mechanism list" caseKemAllowedMechanisms
  , testCase "Generic-secret keygen mints typed material in bounds" caseGenericSecretKeygen
  , testCase "Init enforces the key-type matrix" caseInitKeyTypeMatrix
  , testCase "Init refuses class/type confusion" caseInitClassConfusion
  , testCase "Unwrap refuses asymmetric types on secret templates" caseUnwrapRefusesAsymmetric
  , testCase "EC keypair delivers two handles" caseEcKeypair
  , testCase "ML-DSA keypair delivers two handles" caseMldsaKeypair
  , testCase "ML-DSA set plans, agrees and refuses" caseMldsaSetPlanner
  , testCase "ML-DSA stamping lands CKA_SEED on agreement" caseMldsaStampSeed
  , testCase "EC keypair serves all covered curves" caseEcKeygenCurves
  , testCase "RSA keypair stamps components and round-trips" caseRsaKeygen
  , testCase "RSA keypair stamps modulus bits on the public half" caseRsaModulusBits
  , testCase "RSA keypair generations are distinct" caseRsaKeygenDistinct
  , testCase "generated public halves read without protection flags"
      caseGeneratedPublicReads
  , testCase "RSA keygen bounds refuse out-of-window specs" caseRsaKeygenBounds
  , testCase "RSA exponent plans, agrees and refuses" caseRsaExponentPlanner
  , testCase "RSA stamping refuses mismatched halves" caseRsaStampMismatch
  , testCase "EC stamping lands CKA_EC_POINT" caseEcPointStamped
  , testCase "EC stamping copies params onto opaque bare half" caseEcOpaqueBareCopy
  , testCase "EC planner refuses disagreeing curve parameters" caseEcParamsDisagree
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
  , testCase "ECDH derive refuses a secret-class EC base" caseDeriveEcdhRefusesSecretEc
  , testCase "ECDH derive refuses a secret-class Montgomery base" caseDeriveEcdhRefusesSecretMont
  , testCase "ECDH derive refuses a public-class EC base" caseDeriveEcdhRefusesPublicEc
  , testCase "ECDH derive refuses a secret-class EC base on the cofactor row" caseDeriveEcdhRefusesSecretEcCofactor
  , testCase "ECDH derive plans private-class bases" caseDeriveEcdhPlansPrivate
  , testCase "DH derive refuses a secret-class DH base" caseDeriveDhRefusesSecretDh
  , testCase "DH derive refuses a public-class DH base" caseDeriveDhRefusesPublicDh
  , testCase "DH derive refuses a secret-class X9.42 base" caseDeriveDhRefusesSecretX942
  , testCase "DH derive refuses a public-class X9.42 base" caseDeriveDhRefusesPublicX942
  , testCase "DH derive plans private-class bases" caseDeriveDhPlansPrivate
  , testCase "Derive mark refuses before the family key type" caseDeriveRefusalOrderPin
  , testCase "Derive mark refuses before the object class" caseDeriveMarkBeforeClassPin
  , testCase "Derive allowed list refuses before the family key type" caseDeriveAllowedBeforeTypePin
  , testCase "SHA-KDF derive refuses a destroyed base handle" caseDeriveKdfBadHandle
  , testCase "SHA-KDF derive refuses a non-generic-secret base" caseDeriveKdfWrongKeyType
  , testCase "Shared publication is all-or-nothing" casePublishAtomic
  , testCase "Wrap padding mirrors the cipher construction" casePadMirror
  , testCase "Multi-key derive delivers N handles" caseDeriveMulti
  , testCase "Invalid additional template publishes zero objects" caseDeriveInvalidExtra
  , testCase "Derive refuses destinations outside their key domain"
      caseDeriveRejectsInvalidTargetDomain
  , testCase "Derive finish refuses off-domain material"
      caseDeriveFinishRejectsOffDomainMaterial
  , testCase "Derive codec round-trips and rejects malformed frames" caseDeriveCodec
  , testCase "pub-from-priv RSA ignores CKA_DERIVE, maps attrs" casePubPrivRsa
  , testCase "pub-from-priv EC serves embedded, refuses scalar-only" casePubPrivEc
  , testCase "pub-from-priv EC stamps point and params from SPKI" casePubPrivEcSpkiStamp
  , testCase "pub-from-priv EC finds by read-back params through the FFI codec" casePubPrivEcFindByReadback
  , testCase "pub-from-priv EC copies EC_PARAMS from the base" casePubPrivEcParamsCopy
  , testCase "pub-from-priv refusals: scope, class, params, templates" casePubPrivRefusals
  , testCase "finished key failures carry a trace cause" caseFinishWorkCause
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
  , testCase "Keygen defaults absent usage flags (derive false)" caseKeygenUsageDefaults
  , testCase "Generated keys default CKA_DERIVE to false" caseDeriveDefaultsFalse
  , testCase "Unwrapped and derived keys read CKA_DERIVE false" caseDeriveReadViewUnwrapDerive
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
  , testCase "Sealed bases refuse shortening byte derivations" caseSealedByteOpsRefuse
  , testCase "Sealed bases refuse IKEv1-extended truncation" caseSealedIkeTruncRefuse
  , testCase "Real byte-op derives match the KATs" caseRealByteOpsVector
  , testCase "Byte-op derives preserve source protection" caseByteOpsProtection
  , testCase "Generate stamps key attributes at birth" caseGenerateStampsKeyAttrs
  , testCase "Generated pairs stamp both halves" casePairStampsBothHalves
  , testCase "Every single-key keygen stamps birth history" caseGenerateStampsEveryKeygen
  , testCase "Every pair mechanism stamps both halves" casePairStampsEveryPair
  , testCase "Explicit birth flags drive the history rows" caseGenerateExplicitBirthFlags
  , testCase "Every unwrap mechanism stamps import history" caseUnwrapStampsEveryMech
  , testCase "Every derive family stamps source-derived history" caseDeriveStampsEveryFamily
  , testCase "Copies of generated keys inherit birth history" caseCopyGeneratedKeyDerivesHistory
  , testCase "Generate refuses history attributes in the caller template" caseKeyTemplatesRefuseHistory
  , testCase "Key-material plans rows, refuses bad shapes" caseKeyMatPlans
  , testCase "Key-material absent base reads the defaults" caseKeyMatAbsentBase
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
  , testCase "KEM encapsulate refuses a private-class key" caseKemEncapsRefusesPrivate
  , testCase "KEM decapsulate refuses a public-class key" caseKemDecapsRefusesPublic
  , testCase "KEM plans the correct half per direction" caseKemPlansCorrectHalves
  , testCase "KEM accepts AES-256 secret templates" caseKemAesTemplate
  , testCase "KEM keygen honors CKA_PARAMETER_SET" caseKemKeygenParamSet
  , testCase "KEM outputs stamp creation history" caseKemStampsOutputHistory
  , testCase "Handle writeback plans one exact handle" caseHandleWriteback
  , testCase "Wrapped writeback plans query/short/exact" caseWrappedWriteback
  , testCase "Ciphertext writeback enforces the length" caseCiphertextWriteback
  , testCase "Wrapped/KEM inputs decode with checks" caseKeyInputDecode
  , testGroup "T-C03f"
    [ testCase "caseKeygenTrustedUserRefused" caseKeygenTrustedUserRefused
    , testCase "caseKeypairTrustedUserRefused" caseKeypairTrustedUserRefused
    , testCase "caseDeriveUnwrapTrustedUserRefused" caseDeriveUnwrapTrustedUserRefused
    , testCase "caseKeygenTrustedAllowedPaths" caseKeygenTrustedAllowedPaths
    , testCase "caseFinishTrustedUserRefused" caseFinishTrustedUserRefused
    , testCase "caseFinishTrustedSoSucceeds" caseFinishTrustedSoSucceeds
    , testCase "caseFinishUntrustedUserSucceeds" caseFinishUntrustedUserSucceeds
    ]
  ]
