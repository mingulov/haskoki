{- | Caller-native mechanism structs into the recipe canonical codecs.

The Init and Derive planners validate mechanism parameters against
the recipe canonical codecs ('Haskoki.Recipe.RsaPss',
'Haskoki.Recipe.RsaOaep', 'Haskoki.Recipe.Ecdh'): big-endian words
over small digest tables. Real PKCS#11 callers pass native C
structs instead (@CK_RSA_PKCS_PSS_PARAMS@,
@CK_RSA_PKCS_OAEP_PARAMS@, @CK_ECDH1_DERIVE_PARAMS@): host-order
words, real @CKM_*@/@CKG_*@/@CKD_*@ ids, and (for OAEP/ECDH) data
pointers the pure core can never chase. 'normalizeMechParams' and
'normalizeEcdhParams' translate at the FFI boundary, where the
caller's memory is still live.

Covered structs (caller-native layout, offsets derived from
'Foreign.Storable' so LP64 and ILP32 both work; words read with
'Foreign.Storable.peekByteOff' so the host endianness is honored):

* PSS (@CK_RSA_PKCS_PSS_PARAMS@: hashAlg, mgf, sLen — three
  @CK_ULONG@, no pointers): the @CKM_*@ hash id maps onto a digest
  stem through the generated vocabulary, the @CKG_MGF1_*@ id onto an
  MGF stem through header-cited constants (@spec/vendor/pkcs11.h@,
  @CKG_*@ has no generated vocabulary), and the salt length carries
  over; the triple re-encodes with 'encodePssParams'.
* OAEP (@CK_RSA_PKCS_OAEP_PARAMS@: hashAlg, mgf, source, pSourceData,
  ulSourceDataLen): the ids map as for PSS; @source@ must be
  @CKZ_DATA_SPECIFIED@ (0x01); the label chases @pSourceData@ under
  'maxInputBytes' with the 'decodeInputBytes' null conventions
  (null-with-zero is the empty label, null-with-length rejects).
* ECDH (@CK_ECDH1_DERIVE_PARAMS@: kdf, shared length, shared
  pointer, public length, public pointer): @kdf@ must be @CKD_NULL@
  (0x01, the only served selector — every other KDF is a deferred
  recipe dimension); both byte strings chase under 'maxInputBytes'
  with the same null conventions, and the triple re-encodes with
  'encodeEcdhParams' (canonical null-KDF code 0).
* DH PKCS#3: the parameter image is the bare big-endian peer value
  (the PKCS#11 parameter form — no struct); 1..4096 bytes wrap with
  'encodeDhParams' (canonical null-KDF code 0), while an image that
  already parses as canonical passes through untouched (idempotent:
  a bare peer that happens to parse as @(0, peer)@ carries the same
  integer either way, since the parse only strips leading zeros).
* DH X9.42 (@CK_X9_42_DH1_DERIVE_PARAMS@, the ECDH struct layout):
  @kdf@ must be @CKD_NULL@ and the shared data must be empty (the
  recipe has no shared slot — non-empty shared refuses rather than
  dropping caller bytes); the peer chases under 'maxInputBytes'
  and re-encodes with 'encodeDhParams'.
* EdDSA (@CK_EDDSA_PARAMS@: phFlag, context length, context
  pointer): flags 0/1 translate (anything else passes through);
  the context chases under 'maxInputBytes' with the same null
  conventions, and the pair re-encodes with 'encodeEddsaParams'
  (non-pure combinations refuse downstream at the recipe).
* ML-DSA (@CK_SIGN_ADDITIONAL_CONTEXT@: hedge word, context
  pointer, context length): hedge words 0/1/2 translate
  (anything else passes through); the context chases under
  'maxInputBytes' with the same null conventions, and the pair
  re-encodes with 'encodeMldsaParams' (overlong contexts refuse
  downstream at the recipe).
* ChaCha20 (@CK_CHACHA20_PARAMS@: counter pointer, counter bits,
  nonce pointer, nonce bits): the counter chases
  counter-bits/8 bytes (whole bytes only) and decodes
  little-endian — the OASIS text pins no byte order, so the
  IETF/RFC 8439 state-word order is the documented
  interpretation — and the nonce chases nonce-bits/8 bytes;
  the pair re-encodes with 'encodeChachaStreamParams'
  (non-IETF widths translate and refuse downstream at the
  recipe, never a malformed struct).
* ChaCha20-Poly1305 (@CK_SALSA20_CHACHA20_POLY1305_PARAMS@:
  nonce pointer, nonce length, AAD pointer, AAD length): both
  byte strings chase under 'maxInputBytes' with the same null
  conventions and re-encode with 'encodeChachaPolyParams' at
  the fixed 16-byte tag (the struct carries no tag width;
  off-12 nonces refuse downstream at the recipe).
* PBKD2 (@CK_PKCS5_PBKD2_PARAMS2@: salt source, salt
  pointer/length, iterations, PRF, PRF-data pointer/length,
  password pointer/length): the source must be
  @CKZ_SALT_SPECIFIED@, the PRF-data chase must be empty, the
  PRF maps through 'ckpCodeByPrf' (GOSTR3411 unmapped), and
  iterations fit @1..maxPbkd2Iters@; the salt and password
  chase under 'maxInputBytes' with the same null conventions
  (null-with-zero is the empty string) and re-encode with
  'encodePbkd2Params'.
* TLS 1.0 master (@CK_SSL3_MASTER_KEY_DERIVE_PARAMS@: the
  inline @CK_SSL3_RANDOM_DATA@ plus @pVersion@): both randoms
  chase under 'maxInputBytes' (exact 32 bytes each — the
  canonical profile) and re-encode at the legacy PRF with the
  fixed @"master secret"@ label; @pVersion@ is NULL-or-live
  (never written back — the oracle never asserts it), so the
  pointer is not even read.
* TLS 1.2 master (@CK_TLS12_MASTER_KEY_DERIVE_PARAMS@: the
  randoms, @pVersion@, the PRF hash id): as above, with the
  PRF id mapping through 'tlsKdfPrfCodeFor' onto a hash code
  (the legacy code refuses — TLS 1.2 rows are hash-only).
* TLS 1.2 extended master
  (@CK_TLS12_EXTENDED_MASTER_KEY_DERIVE_PARAMS@: the PRF hash
  id, the session hash pointer\/length, @pVersion@): the hash
  code maps as above and the session hash chases under
  'maxInputBytes' (16..64 bytes — a real hash output), with
  the fixed @"extended master secret"@ label.
* TLS KDF (@CK_TLS_KDF_PARAMS@: the PRF id, the label
  pointer\/length, the randoms, the context pointer\/length):
  the PRF id maps through 'tlsKdfPrfCodeFor' (legacy or hash),
  the label must be non-empty, the randoms are exact 32 bytes
  each, and the context chases under 'maxInputBytes' (empty
  unless a hash PRF — the legacy construction has no context
  input).

Anything unmappable — wrong length, unknown ids, a bad source tag,
a null-with-length or over-bound chase — passes the input bytes
through untouched, so the recipe refusal (and its @CKR@) is
exactly today's: the normalizer only ever turns a would-be refusal
into an acceptance when the native struct is fully understood. In
particular the historical canonical byte images still validate,
since their words never parse as mapped native ids. Non-null
chased pointers must be readable for the stated length (the usual
PKCS#11 caller contract, shared with 'decodeInputBytes'): a wild
pointer is undefined behavior, not a refusal.
-}
{-# LANGUAGE OverloadedStrings #-}
module Haskoki.FFI.NativeParams
  ( normalizeMechParams
  , normalizeEcdhParams
  , normalizeWrapCompEcdhParams
  , normalizeDhPkcsParams
  , normalizeDhX942Params
  , normalizeTlsPrfParams
  , normalizeEncryptDataCbcParams
  , encryptDataCbcNativeSize
  , normalizeEncryptDataEcbParams
  , encryptDataEcbNativeSize
  , normalizePbkd2Params2
  , pbkd2Params2NativeSize
  , Sp800DataParam (..)
  , sp800StructToCanonical
  , normalizeSp800KdfParams
  , sp800NativeSize
  , tlsPrfStructToCanonical
  , tlsPrfNativeSize
  , normalizeTlsKdfMasterParams
  , normalizeTlsKdfTls12MasterParams
  , normalizeTlsKdfExtParams
  , normalizeTlsKdfFreeParams
  , tlsKdfMasterStructToCanonical
  , tlsKdfTls12MasterStructToCanonical
  , tlsKdfExtStructToCanonical
  , tlsKdfFreeStructToCanonical
  , ssl3RandomSize
  , tlsKdfMasterNativeSize
  , tlsKdfTls12MasterNativeSize
  , tlsKdfExtNativeSize
  , tlsKdfFreeNativeSize
  , ikePrfPlusStructToCanonical
  , ikePrfStructToCanonical
  , ike1PrfStructToCanonical
  , ike1ExtStructToCanonical
  , normalizeIkePrfPlusParams
  , normalizeIkePrfParams
  , normalizeIke1PrfParams
  , normalizeIke1ExtParams
  , ikePrfPlusNativeSize
  , ikePrfNativeSize
  , ike1PrfNativeSize
  , ike1ExtNativeSize
  , byteOpsConcatKeyStructToCanonical
  , byteOpsStringDataStructToCanonical
  , byteOpsExtractStructToCanonical
  , tlsKeyMatStructToCanonical
  , tls12KeyMatStructToCanonical
  , normalizeTlsKeyMatParams
  , normalizeTls12KeyMatParams
  , normalizeTls12KeySafeParams
  , normalizeSsl3MasterParams
  , normalizeSsl3KeyMatParams
  , ssl3MasterNativeSize
  , pbeStructToCanonical
  , normalizePbeParams
  , normalizePbeParamsMaybeIv
  , pbeParamsNativeSize
  , tlsKeyMatNativeSize
  , tls12KeyMatNativeSize
  , KeyMatSlots (..)
  , DerivedKeySlot (..)
  , chaseAttrTemplate
  , maxSp800AdditionalKeys
  , normalizeByteOpsConcatKeyParams
  , normalizeByteOpsStringDataParams
  , normalizeByteOpsExtractParams
  , byteOpsUlongNativeSize
  , byteOpsStringDataNativeSize
  , pssStructToCanonical
  , oaepStructToCanonical
  , ecdhStructToCanonical
  , wrapCompEcdhStructToCanonical
  , dhPkcsStructToCanonical
  , dhX942StructToCanonical
  , gcmStructToCanonical
  , ccmStructToCanonical
  , ctrStructToCanonical
  , rc2StructToCanonical
  , eddsaStructToCanonical
  , mldsaStructToCanonical
  , slhdsaStructToCanonical
  , chachaStreamStructToCanonical
  , chachaPolyStructToCanonical
  , pbkd2Params2StructToCanonical
  , ckpCodeByPrf
  , digestStemByCkm
  , mgfStemByCkg
  , pssNativeSize
  , oaepNativeSize
  , ecdhNativeSize
  , wrapCompEcdhNativeSize
  , dhX942NativeSize
  , gcmNativeSize
  , ccmNativeSize
  , ctrNativeSize
  , rc2EcbNativeSize
  , rc2CbcNativeSize
  , eddsaNativeSize
  , mldsaNativeSize
  , slhdsaNativeSize
  , chachaStreamNativeSize
  , chachaPolyNativeSize
  ) where

import Control.Monad (guard)
import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map
import Data.Maybe (fromMaybe, isJust)
import Data.Text (Text)
import Data.Word (Word64, Word8)
import Foreign.C.String (CStringLen)
import Foreign.C.Types (CULong (..))
import Foreign.Ptr (Ptr, castPtr, nullPtr, plusPtr)
import Foreign.Storable (alignment, peekByteOff, sizeOf)

import Haskoki.FFI.Decode (maxInputBytes)
import Haskoki.Recipe.ByteOps (encodeByteOpsParams)
import Haskoki.Recipe.Ccm (ccmRecipeFor, encodeCcmParams)
import Haskoki.Recipe.Dh (decodeDhParams, encodeDhParams)
import Haskoki.Recipe.Chacha20
  ( chachaName
  , chachaPolyTagLen
  , chachaRecipeFor
  , encodeChachaPolyParams
  , encodeChachaStreamParams
  )
import Haskoki.Recipe.Cipher (ctrRecipeFor, encodeCtrParams, encodeRc2CbcParams, rc2RecipeFor)
import Haskoki.Recipe.Ecdh (encodeEcdhParams)
import Haskoki.Recipe.WrapComp (encodeWrapCompEcdhParams, wrapCompEcdhRecipeFor)
import Haskoki.Recipe.Eddsa (eddsaRecipeFor, encodeEddsaParams)
import Haskoki.Recipe.Gcm (encodeGcmParams, gcmRecipeFor)
import Haskoki.Recipe.Gmac (gmacRecipeFor)
import Haskoki.Recipe.MlDsa (encodeMldsaParams, hedgeOfWord, mldsaRecipeFor)
import Haskoki.Recipe.SlhDsa (encodeSlhdsaParams, slhdsaRecipeFor)
import qualified Haskoki.Recipe.SlhDsa as SlhDsa
import Haskoki.Recipe.Sp800108
  ( Sp800Mode (..)
  , encodeSp800Params
  , sp800PrfCodeFor
  )
import Haskoki.Recipe.Kdf (encodePbkd2Params, maxPbkd2Iters)
import Haskoki.Recipe.RsaOaep (encodeOaepParams, rsaOaepRecipeFor)
import Haskoki.Recipe.RsaPss (encodePssParams, rsaPssRecipeFor)
import Haskoki.Recipe.Ike (encodeIkeParams, ikePrfCodeFor)
import Haskoki.Recipe.TlsKdf (encodeTlsKdfParams, tlsKdfPrfCodeFor)
import Haskoki.Recipe.Ssl3 (encodeSsl3KeyMatParams, encodeSsl3MasterParams)
import Haskoki.Recipe.TlsKeyMat (encodeTlsKeyMatParams)
import Haskoki.Recipe.Pbe (encodePbeParams)
import Haskoki.Attribute
  ( AttributeType (..)
  , AttributeValue (..)
  , Shape (..)
  , attributeTypeByName
  , decodeValue
  , shapeOf
  )
import Haskoki.Attribute.Generated (generatedAttributes)
import Haskoki.Object (maxTemplateEntries)
import Haskoki.Recipe.TlsPrf (encodeTlsPrfParams)
import Haskoki.Registry.Generated (mustGeneratedId)
import Haskoki.Registry.Types (MechanismId (..))

-- | Width of one @CK_ULONG@ word on this build.
wordSize :: Int
wordSize = sizeOf (undefined :: CULong)

-- | Width of one pointer on this build.
ptrSize :: Int
ptrSize = sizeOf (undefined :: Ptr Word8)

-- | Native @CK_RSA_PKCS_PSS_PARAMS@ image size: three words.
pssNativeSize :: Int
pssNativeSize = 3 * wordSize

-- | Native @CK_RSA_PKCS_OAEP_PARAMS@ image size: three words, one
-- pointer, one length.
oaepNativeSize :: Int
oaepNativeSize = 4 * wordSize + ptrSize

-- | Native @CK_ECDH1_DERIVE_PARAMS@ image size: one KDF word, then
-- (length, pointer) twice (shared data, peer public key).
ecdhNativeSize :: Int
ecdhNativeSize = 3 * wordSize + 2 * ptrSize

-- | Native @CK_ECDH_AES_KEY_WRAP_PARAMS@ image size: one KDF word,
-- (length, pointer) for the shared data, one AES-strength word.
wrapCompEcdhNativeSize :: Int
wrapCompEcdhNativeSize = 3 * wordSize + ptrSize

-- | Native @CK_X9_42_DH1_DERIVE_PARAMS@ image size: the ECDH
-- struct layout (kdf, shared length/pointer, public
-- length/pointer).
dhX942NativeSize :: Int
dhX942NativeSize = 3 * wordSize + 2 * ptrSize

-- | Native @CK_TLS_PRF_PARAMS@ image size: (pointer, length) for
-- the seed, (pointer, length) for the label, then the output
-- pointer pair (ignored on the derive path — the output lands in
-- the derived object).
tlsPrfNativeSize :: Int
tlsPrfNativeSize = 2 * wordSize + 4 * ptrSize

-- | Native @CK_SSL3_RANDOM_DATA@ image size: (pointer, length)
-- for the client random, (pointer, length) for the server
-- random — inline in the three master-derive structs and the
-- TLS-KDF struct alike (@spec\/vendor\/pkcs11.h:2024-2029@).
ssl3RandomSize :: Int
ssl3RandomSize = 2 * wordSize + 2 * ptrSize

-- | Native @CK_SSL3_MASTER_KEY_DERIVE_PARAMS@ image size: the
-- inline randoms plus the @pVersion@ pointer.
tlsKdfMasterNativeSize :: Int
tlsKdfMasterNativeSize = ssl3RandomSize + ptrSize

-- | Native @CK_SSL3_MASTER_KEY_DERIVE_PARAMS@ image size for
-- the SSL3 rows: the same geometry as the TLS-KDF master
-- struct (aliased so the row reads on its own name).
ssl3MasterNativeSize :: Int
ssl3MasterNativeSize = ssl3RandomSize + ptrSize

-- | Native @CK_TLS12_MASTER_KEY_DERIVE_PARAMS@ image size: the
-- inline randoms, the @pVersion@ pointer, the PRF hash id.
tlsKdfTls12MasterNativeSize :: Int
tlsKdfTls12MasterNativeSize = ssl3RandomSize + ptrSize + wordSize

-- | Native @CK_TLS12_EXTENDED_MASTER_KEY_DERIVE_PARAMS@ image
-- size: the PRF hash id, (pointer, length) for the session
-- hash, the @pVersion@ pointer.
tlsKdfExtNativeSize :: Int
tlsKdfExtNativeSize = 2 * wordSize + 2 * ptrSize

-- | Native @CK_TLS_KDF_PARAMS@ image size: the PRF id, (pointer,
-- length) for the label, the inline randoms, (pointer, length)
-- for the context.
tlsKdfFreeNativeSize :: Int
tlsKdfFreeNativeSize = 5 * wordSize + 4 * ptrSize

-- | Native @CK_IKE2_PRF_PLUS_DERIVE_PARAMS@ image size: the PRF
-- id, the seed-key flag (padded to a word), the seed-key
-- handle, (pointer, length) for the seed data
-- (@spec\\/vendor\\/pkcs11.h:1682-1688@; 40 bytes on LP64).
ikePrfPlusNativeSize :: Int
ikePrfPlusNativeSize = 4 * wordSize + ptrSize

-- | Native @CK_IKE_PRF_DERIVE_PARAMS@ image size: the PRF id,
-- the two flag bytes (padded to a word), (pointer, length)
-- for each nonce, the rekey handle
-- (@spec\\/vendor\\/pkcs11.h:1651-1660@; 56 bytes on LP64).
ikePrfNativeSize :: Int
ikePrfNativeSize = 5 * wordSize + 2 * ptrSize

-- | Native bare-@CK_ULONG@ image size: the second-key handle
-- (@CKM_CONCATENATE_BASE_AND_KEY@) or the bit offset
-- (@CKM_EXTRACT_KEY_FROM_KEY@).
byteOpsUlongNativeSize :: Int
byteOpsUlongNativeSize = wordSize

-- | Native @CK_KEY_DERIVATION_STRING_DATA@ image size:
-- (pointer, length) for the data bytes (the two data-concat
-- rows and the XOR row;
-- @spec\/vendor\/pkcs11.h:1699-1702@; 16 bytes on LP64).
byteOpsStringDataNativeSize :: Int
byteOpsStringDataNativeSize = ptrSize + wordSize

-- | Native @CK_IKE1_PRF_DERIVE_PARAMS@ image size: the PRF id,
-- the prev-key flag (padded to a word), the keygxy and
-- prev-key handles, (pointer, length) for each cookie, the
-- key-number byte (padded to a word;
-- @spec\\/vendor\\/pkcs11.h:1670-1680@; 72 bytes on LP64).
ike1PrfNativeSize :: Int
ike1PrfNativeSize = 7 * wordSize + 2 * ptrSize

-- | Native @CK_IKE1_EXTENDED_DERIVE_PARAMS@ image size: the
-- PRF id, the keygxy flag (padded to a word), the keygxy
-- handle, (pointer, length) for the extra data
-- (@spec\\/vendor\\/pkcs11.h:1662-1668@; 40 bytes on LP64).
ike1ExtNativeSize :: Int
ike1ExtNativeSize = 4 * wordSize + ptrSize

-- | Native @CK_PKCS5_PBKD2_PARAMS2@ image size: the salt-source
-- word, (pointer, length) for the salt, the iterations and PRF
-- words, (pointer, length) for the PRF data, (pointer, length)
-- for the password. Nine words, no padding. The v1 struct
-- (@CK_PKCS5_PBKD2_PARAMS@) is layout-identical but reads its
-- password length through a pointer — a v1 image misparsed here
-- carries a wild length and fails the chase bounds, never
-- silently mistranslating.
pbkd2Params2NativeSize :: Int
pbkd2Params2NativeSize = 6 * wordSize + 3 * ptrSize

-- | Native @CK_GCM_PARAMS@ image size: (pointer, length, bits) for
-- the IV, then (pointer, length) for the AAD, then the tag-bits
-- word.
gcmNativeSize :: Int
gcmNativeSize = 4 * wordSize + 2 * ptrSize

-- | Native @CK_AES_CCM_PARAMS@ (layout-identical to
-- @CK_CCM_PARAMS@) image size: the data-length word, (pointer,
-- length) for the nonce, (pointer, length) for the AAD, then the
-- MAC-length word. All lengths are BYTES (unlike GCM bits).
ccmNativeSize :: Int
ccmNativeSize = 4 * wordSize + 2 * ptrSize

-- | Native @CK_CHACHA20_PARAMS@ image size: (pointer, bits) for
-- the block counter, (pointer, bits) for the nonce. Both widths
-- are BITS (the GCM convention, unlike CCM bytes).
chachaStreamNativeSize :: Int
chachaStreamNativeSize = 2 * wordSize + 2 * ptrSize

-- | Native @CK_SALSA20_CHACHA20_POLY1305_PARAMS@ image size:
-- (pointer, length) for the nonce, (pointer, length) for the
-- AAD. Both lengths are BYTES (the CCM convention).
chachaPolyNativeSize :: Int
chachaPolyNativeSize = 2 * wordSize + 2 * ptrSize

-- | Native @CK_AES_CTR_PARAMS@ image size: one counter-bits word
-- plus the inline 16-byte counter block.
ctrNativeSize :: Int
ctrNativeSize = wordSize + 16

-- | Native RC2 image sizes (@spec\/vendor\/pkcs11.h@: @CK_RC2_PARAMS@
-- is one effective-bits word; @CK_RC2_CBC_PARAMS@ appends the
-- inline 8-byte IV).
rc2EcbNativeSize, rc2CbcNativeSize :: Int
rc2EcbNativeSize = wordSize
rc2CbcNativeSize = wordSize + 8

-- | Offset of @ulContextDataLen@ in a native @CK_EDDSA_PARAMS@
-- image: the @CK_BBOOL@ flag byte plus padding to the word
-- alignment. The header order is flag, length, pointer (the
-- pointer follows at @eddsaLenOff + wordSize@).
eddsaLenOff :: Int
eddsaLenOff = ((1 + wordAlign - 1) `div` wordAlign) * wordAlign
  where
    wordAlign = alignment (undefined :: CULong)

-- | Native @CK_EDDSA_PARAMS@ image size: the flag byte (plus
-- padding), one length word, one pointer.
eddsaNativeSize :: Int
eddsaNativeSize = eddsaLenOff + wordSize + ptrSize

-- | Native @CK_SIGN_ADDITIONAL_CONTEXT@ image size: the hedge
-- word, one pointer, one length word — all-word, 24 bytes on
-- LP64 (no padding traps; the header order is hedge, pointer,
-- length).
mldsaNativeSize :: Int
mldsaNativeSize = 2 * wordSize + ptrSize

-- | Native @CK_SIGN_ADDITIONAL_CONTEXT@ size for CKM_SLH_DSA:
-- same struct shape as ML-DSA (the header order is hedge,
-- pointer, length).
slhdsaNativeSize :: Int
slhdsaNativeSize = 2 * wordSize + ptrSize

-- | Native @CKM_*@ hash ids onto recipe digest stems. Ids come from
-- the generated vocabulary, so a header drift breaks the build
-- instead of mistranslating.
digestStemByCkm :: Map Word64 Text
digestStemByCkm = Map.fromList
  [ (mustGeneratedId "CKM_MD5", "MD5")
  , (mustGeneratedId "CKM_SHA_1", "SHA_1")
  , (mustGeneratedId "CKM_SHA224", "SHA224")
  , (mustGeneratedId "CKM_SHA256", "SHA256")
  , (mustGeneratedId "CKM_SHA384", "SHA384")
  , (mustGeneratedId "CKM_SHA512", "SHA512")
  , (mustGeneratedId "CKM_SHA3_224", "SHA3_224")
  , (mustGeneratedId "CKM_SHA3_256", "SHA3_256")
  , (mustGeneratedId "CKM_SHA3_384", "SHA3_384")
  , (mustGeneratedId "CKM_SHA3_512", "SHA3_512")
  , (mustGeneratedId "CKM_RIPEMD160", "RIPEMD160")
  ]

-- | Native @CKG_MGF1_*@ ids onto recipe digest stems. @CKG_*@ has no
-- generated vocabulary; the ids are numeric literals cited to
-- @spec/vendor/pkcs11.h:439-447@. There are no MGF1 ids for MD5 or
-- RIPEMD160, so those stems are unreachable here (correctly: no
-- caller can name them).
mgfStemByCkg :: Map Word64 Text
mgfStemByCkg = Map.fromList
  [ (0x01, "SHA_1")
  , (0x02, "SHA256")
  , (0x03, "SHA384")
  , (0x04, "SHA512")
  , (0x05, "SHA224")
  , (0x06, "SHA3_224")
  , (0x07, "SHA3_256")
  , (0x08, "SHA3_384")
  , (0x09, "SHA3_512")
  ]

-- | @CKZ_DATA_SPECIFIED@ (@spec/vendor/pkcs11.h:1224@): the only
-- OAEP label source with pointed-to bytes.
ckzDataSpecified :: Word64
ckzDataSpecified = 0x01

-- | @CKD_NULL@ (@spec/vendor/pkcs11.h:306@): the only served ECDH
-- KDF selector (canonical code 0).
ckdNull :: Word64
ckdNull = 0x01

-- | @CKZ_SALT_SPECIFIED@ (@spec/vendor/pkcs11.h:1227@): the only
-- served PBKD2 salt source (the salt bytes ride the struct).
ckzSaltSpecified :: Word64
ckzSaltSpecified = 0x01

-- | Native @CKP_PKCS5_PBKD2_HMAC_*@ ids onto engine-local PRF
-- codes ('Haskoki.Recipe.Kdf.kdfCodeDigest'). @CKP_*@ has no
-- generated vocabulary; the ids are numeric literals cited to
-- @spec/vendor/pkcs11.h:1049-1056@. GOSTR3411 (0x02) has no
-- servable HMAC and stays unmapped.
ckpCodeByPrf :: Map Word64 Int
ckpCodeByPrf = Map.fromList
  [ (0x01, 2)
  , (0x03, 3)
  , (0x04, 4)
  , (0x05, 5)
  , (0x06, 6)
  , (0x07, 7)
  , (0x08, 8)
  ]

-- | Pure PSS translation: native (hashAlg, mgf, sLen) words onto the
-- canonical @pss-params/1@ image. Unknown ids and unrepresentable
-- salt lengths refuse ('Nothing'); the recipe bounds the rest.
-- | Pure IKEv2 prf+ translation: the native PRF id plus
-- the chased seed bytes onto the canonical @ike-params\/1@
-- image. The PRF id maps through 'ikePrfCodeFor'; an
-- unmapped selector marks the reserved code 0 (structurally
-- valid — the planner denies it with the spec code). The
-- seed-key leg refuses upstream (the IO normalizer sees the
-- flag\/handle before this runs).
ikePrfPlusStructToCanonical :: Word64 -> ByteString -> Maybe ByteString
ikePrfPlusStructToCanonical prf seed =
  Just (encodeIkeParams (prfCode prf) 0 0 0 seed BS.empty)

-- | Pure IKE-PRF translation: flags, nonces, and the rekey
-- handle onto the canonical image. Rekey (flag or handle)
-- refuses ('Nothing' — the struct image passes through raw
-- so the recipe refusal is exactly the planner's); the
-- data-as-key flag rides bit 0.
ikePrfStructToCanonical :: Word64 -> Bool -> Bool -> ByteString -> ByteString -> Word64 -> Maybe ByteString
ikePrfStructToCanonical prf dataAsKey rekey ni nr hNew = do
  guard (not rekey && hNew == 0)
  Just (encodeIkeParams (prfCode prf) (if dataAsKey then 1 else 0) 0 0 ni nr)

-- | Pure IKEv1-PRF translation: the PRF id, the keygxy
-- handle, the cookies, and the key number onto the
-- canonical image. A missing keygxy or any prevkey (flag
-- or handle) refuses.
ike1PrfStructToCanonical :: Word64 -> Bool -> Word64 -> Word64 -> ByteString -> ByteString -> Word8 -> Maybe ByteString
ike1PrfStructToCanonical prf hasPrev hKeygxy hPrev ckyi ckyr keynum = do
  guard (hKeygxy /= 0 && not hasPrev && hPrev == 0)
  Just (encodeIkeParams (prfCode prf) 0 keynum hKeygxy ckyi ckyr)

-- | Pure IKEv1-extended translation: the PRF id, the
-- optional keygxy handle, and the extra bytes onto the
-- canonical image. Flag and handle must agree (both absent
-- or both present).
ike1ExtStructToCanonical :: Word64 -> Bool -> Word64 -> ByteString -> Maybe ByteString
ike1ExtStructToCanonical prf hasKeygxy hKeygxy extra = do
  guard (hasKeygxy == (hKeygxy /= 0))
  Just (encodeIkeParams (prfCode prf) 0 0 hKeygxy extra BS.empty)

-- | The native PRF id onto the frame code: served HMAC
-- selectors map, everything else marks the reserved 0.
prfCode :: Word64 -> Word8
prfCode prf = fromMaybe 0 (ikePrfCodeFor (MechanismId (fromIntegral prf)))

pssStructToCanonical :: Word64 -> Word64 -> Word64 -> Maybe ByteString
pssStructToCanonical hashId mgfId salt = do
  d <- Map.lookup hashId digestStemByCkm
  m <- Map.lookup mgfId mgfStemByCkg
  if salt > fromIntegral (maxBound :: Int)
    then Nothing
    else Just (encodePssParams d m (fromIntegral salt))

-- | Pure OAEP translation: native (hashAlg, mgf) words plus the
-- chased label onto the canonical @oaep-params/1@ image. Unknown ids
-- refuse ('Nothing').
oaepStructToCanonical :: Word64 -> Word64 -> ByteString -> Maybe ByteString
oaepStructToCanonical hashId mgfId label = do
  d <- Map.lookup hashId digestStemByCkm
  m <- Map.lookup mgfId mgfStemByCkg
  Just (encodeOaepParams d m label)

-- | Pure ECDH translation: the native KDF selector plus the chased
-- shared-data and peer-key bytes onto the canonical
-- @ecdh-params/1@ image. Only @CKD_NULL@ translates (canonical
-- code 0); every other selector refuses ('Nothing'). An empty peer
-- key translates and is refused downstream by the recipe
-- (invalid parameters, not a malformed struct).
ecdhStructToCanonical :: Word64 -> ByteString -> ByteString -> Maybe ByteString
ecdhStructToCanonical kdf shared peer
  | kdf /= ckdNull = Nothing
  | otherwise = Just (encodeEcdhParams 0 shared peer)

-- | Pure wrap-composition ECDH translation: the native KDF word,
-- shared data, and AES-strength word onto the canonical
-- @wrapcomp-ecdh-params\/1@ image. Only @CKD_NULL@ translates
-- (canonical code 0); every other selector refuses ('Nothing').
-- The strength word translates verbatim and is refused downstream
-- by the recipe when off-set (invalid parameters, not a malformed
-- struct).
wrapCompEcdhStructToCanonical :: Word64 -> ByteString -> Word64 -> Maybe ByteString
wrapCompEcdhStructToCanonical kdf shared aesBits
  | kdf /= ckdNull = Nothing
  | otherwise = Just (encodeWrapCompEcdhParams 0 shared (fromIntegral aesBits))

-- | Pure PKCS#3 DH translation: the bare peer image onto the
-- canonical @dh-params/1@ image. An image that already parses as
-- canonical passes through untouched (idempotent); any other
-- 1..4096-byte image wraps as the null-KDF peer (the native
-- @HSK_OSSL4_DH_PEER_MAX@ bound — longer images refuse
-- downstream either way). Empty images refuse ('Nothing').
dhPkcsStructToCanonical :: ByteString -> Maybe ByteString
dhPkcsStructToCanonical raw = case decodeDhParams raw of
  Just (0, _) -> Just raw
  _ | BS.length raw >= 1 && BS.length raw <= 4096 -> Just (encodeDhParams 0 raw)
    | otherwise -> Nothing

-- | Pure X9.42 DH translation: the chased shared/peer pair onto
-- the canonical @dh-params/1@ image. Non-null KDF selectors and
-- non-empty shared data refuse ('Nothing' — the recipe has no
-- shared slot, so caller bytes are never dropped silently).
dhX942StructToCanonical :: Word64 -> ByteString -> ByteString -> Maybe ByteString
dhX942StructToCanonical kdf shared peer
  | kdf /= ckdNull = Nothing
  | not (BS.null shared) = Nothing
  | otherwise = Just (encodeDhParams 0 peer)

-- | Pure TLS-PRF translation: the chased label and seed onto the
-- canonical @tls-prf-params\/1@ image. The over-ceiling refusal
-- lives downstream (the recipe validation in 'planDerive'); the
-- chase bounds plus that check fail the shape closed.
tlsPrfStructToCanonical :: ByteString -> ByteString -> Maybe ByteString
tlsPrfStructToCanonical lab seed = Just (encodeTlsPrfParams lab seed)

-- | Pure TLS 1.0 master translation: the chased client\/server
-- randoms onto the canonical @tls-kdf-params\/1@ image at the
-- legacy PRF (code 0) with the fixed @"master secret"@ label.
-- Both randoms must be exactly 32 bytes (the canonical
-- profile); anything else refuses ('Nothing' — the struct
-- image passes through raw so the recipe refusal is exactly
-- the planner's).
tlsKdfMasterStructToCanonical :: ByteString -> ByteString -> Maybe ByteString
tlsKdfMasterStructToCanonical cli srv = do
  guard (BS.length cli == 32 && BS.length srv == 32)
  Just (encodeTlsKdfParams 0 "master secret" (cli <> srv) BS.empty)

-- | Pure TLS 1.2 master translation: the native PRF hash id
-- plus the chased randoms onto the canonical image with the
-- fixed @"master secret"@ label. The PRF id maps through
-- 'tlsKdfPrfCodeFor' onto a hash code (the legacy code refuses
-- — TLS 1.2 rows are hash-only); the randoms are exact 32
-- bytes each.
tlsKdfTls12MasterStructToCanonical :: Word64 -> ByteString -> ByteString -> Maybe ByteString
tlsKdfTls12MasterStructToCanonical prf cli srv = do
  code <- tlsKdfPrfCodeFor (MechanismId (fromIntegral prf))
  guard (code /= 0)
  guard (BS.length cli == 32 && BS.length srv == 32)
  Just (encodeTlsKdfParams code "master secret" (cli <> srv) BS.empty)

-- | Pure TLS 1.2 extended-master translation: the native PRF
-- hash id plus the chased session hash onto the canonical
-- image with the fixed @"extended master secret"@ label. The
-- PRF code maps hash-only as above; the session hash is 16..64
-- bytes (a real hash output — the recipe rule, enforced here
-- so off-profile images pass through raw).
tlsKdfExtStructToCanonical :: Word64 -> ByteString -> Maybe ByteString
tlsKdfExtStructToCanonical prf sess = do
  code <- tlsKdfPrfCodeFor (MechanismId (fromIntegral prf))
  guard (code /= 0)
  guard (let n = BS.length sess in n >= 16 && n <= 64)
  Just (encodeTlsKdfParams code "extended master secret" sess BS.empty)

-- | Pure TLS-KDF translation: the native PRF id plus the
-- chased label, randoms, and context onto the canonical
-- image. The PRF id maps through 'tlsKdfPrfCodeFor' (legacy
-- or hash); the label must be non-empty, the randoms exact 32
-- bytes each, and the context empty unless a hash PRF (the
-- legacy construction has no context input).
tlsKdfFreeStructToCanonical
  :: Word64 -> ByteString -> ByteString -> ByteString -> ByteString -> Maybe ByteString
tlsKdfFreeStructToCanonical prf lab cli srv ctx = do
  code <- tlsKdfPrfCodeFor (MechanismId (fromIntegral prf))
  guard (not (BS.null lab))
  guard (BS.length cli == 32 && BS.length srv == 32)
  guard (code /= 0 || BS.null ctx)
  Just (encodeTlsKdfParams code lab (cli <> srv) ctx)

-- | Pure GCM translation: the chased IV and AAD plus the native
-- bit/tag widths onto the canonical @gcm-params/1@ image. The bit
-- width must agree with the chased IV length and the tag width
-- must be whole bytes; the IV must be caller-supplied, so the
-- provider-generated-IV convention (empty IV) never translates and
-- passes through to the recipe refusal downstream.
gcmStructToCanonical :: ByteString -> ByteString -> Word64 -> Word64 -> Maybe ByteString
gcmStructToCanonical iv aad ivBits tagBits = do
  guard (fromIntegral (BS.length iv) * 8 == ivBits)
  guard (tagBits `mod` 8 == 0)
  let tagLen = fromIntegral (tagBits `div` 8)
  guard (not (BS.null iv))
  pure (encodeGcmParams iv aad tagLen)

-- | Pure CCM translation: the chased nonce and AAD plus the
-- native byte lengths onto the canonical @ccm-params/1@ image.
-- The nonce length must agree with the chased nonce bytes; any
-- width translates (even unserved ones: the recipe refuses
-- downstream with the parameter CKR, never a malformed struct);
-- only an unrepresentable width refuses here.
ccmStructToCanonical :: ByteString -> ByteString -> Word64 -> Word64 -> Word64 -> Maybe ByteString
ccmStructToCanonical nonce aad dataLen nonceLen macLen = do
  guard (fromIntegral (BS.length nonce) == nonceLen)
  tagLen <- word64ToInt macLen
  dLen <- word64ToInt dataLen
  pure (encodeCcmParams nonce aad tagLen dLen)

-- | Pure ChaCha20 translation: the chased counter and nonce plus
-- the native bit widths onto the canonical @chacha20-params/1@
-- image. Both widths must agree with the chased bytes; the
-- counter decodes little-endian (the documented OASIS-gap
-- interpretation — RFC 8439 state-word order) and must fit an
-- 'Int'. Any width translates (even non-IETF ones: the recipe
-- refuses downstream with the parameter CKR, never a malformed
-- struct); only disagreement or an unrepresentable counter
-- refuses here.
chachaStreamStructToCanonical :: ByteString -> Word64 -> ByteString -> Word64 -> Maybe ByteString
chachaStreamStructToCanonical ctr ctrBits nonce nonceBits = do
  guard (fromIntegral (BS.length ctr) * 8 == ctrBits)
  guard (fromIntegral (BS.length nonce) * 8 == nonceBits)
  counter <- leWordToInt ctr
  pure (encodeChachaStreamParams counter nonce)

-- | Pure ChaCha20-Poly1305 translation: the chased nonce and AAD
-- plus the native byte lengths onto the canonical
-- @chacha20poly1305-params/1@ image at the fixed 16-byte tag.
-- Both lengths must agree with the chased bytes; any width
-- translates (off-12 nonces refuse downstream at the recipe).
chachaPolyStructToCanonical :: ByteString -> Word64 -> ByteString -> Word64 -> Maybe ByteString
chachaPolyStructToCanonical nonce nonceLen aad aadLen = do
  guard (fromIntegral (BS.length nonce) == nonceLen)
  guard (fromIntegral (BS.length aad) == aadLen)
  pure (encodeChachaPolyParams nonce aad chachaPolyTagLen)

-- | Pure PBKD2 translation: the chased salt and password plus
-- the native @CK_PKCS5_PBKD2_PARAMS2@ scalars onto the canonical
-- @pbkd2-params/2@ image. The salt source must be
-- @CKZ_SALT_SPECIFIED@, the PRF data must be empty (no PRF
-- parameters are served), the PRF must map through
-- 'ckpCodeByPrf', and iterations must fit
-- @1..'maxPbkd2Iters'@. Anything else refuses ('Nothing');
-- the recipe bounds the rest.
pbkd2Params2StructToCanonical
  :: Word64 -> ByteString -> Word64 -> Word64 -> ByteString -> ByteString
  -> Maybe ByteString
pbkd2Params2StructToCanonical saltSource salt iters prf prfData password = do
  guard (saltSource == ckzSaltSpecified)
  guard (BS.null prfData)
  code <- Map.lookup prf ckpCodeByPrf
  nIters <- word64ToInt iters
  guard (nIters >= 1 && nIters <= maxPbkd2Iters)
  pure (encodePbkd2Params code nIters salt password)

-- | Decode a little-endian byte string (at most 8 bytes) onto an
-- 'Int'; 'Nothing' on over-width or overflow (mirrors the
-- recipe's LE IV framing, 'decodeChachaIv', generalized past 4
-- bytes for the 64-bit counter width).
leWordToInt :: ByteString -> Maybe Int
leWordToInt bs
  | BS.length bs > 8 = Nothing
  | otherwise = word64ToInt (BS.foldr (\b a -> a * 256 + fromIntegral b) 0 bs)

-- | Narrow a native bit width onto whole bytes; 'Nothing' on a
-- ragged width (the struct cannot name a sub-byte chase).
bitsToBytes :: Word64 -> Maybe Word64
bitsToBytes b
  | b `mod` 8 == 0 = Just (b `div` 8)
  | otherwise = Nothing

-- | Narrow one native word onto 'Int'; 'Nothing' when it does not
-- fit (which cannot encode downstream).
word64ToInt :: Word64 -> Maybe Int
word64ToInt w
  | w > fromIntegral (maxBound :: Int) = Nothing
  | otherwise = Just (fromIntegral w)

-- | Pure CTR translation: the native counter-bits word plus the
-- inline counter block onto the canonical @ctr-params/1@ image.
-- Any width translates (even unserved ones: the recipe refuses
-- downstream with the parameter CKR, never a malformed struct);
-- only an unrepresentable width refuses here.
ctrStructToCanonical :: Word64 -> ByteString -> Maybe ByteString
ctrStructToCanonical bits cb
  | bits > fromIntegral (maxBound :: Int) = Nothing
  | BS.length cb /= 16 = Nothing
  | otherwise = Just (encodeCtrParams (fromIntegral bits) cb)

-- | Pure RC2 translation: the native effective-bits word plus the
-- inline IV (empty for the word-only @CK_RC2_PARAMS@ shape) onto
-- the canonical @rc2-params/1@ image. Any width translates (the
-- recipe enforces 1..1024 downstream with the parameter CKR);
-- only an unrepresentable width or a mistimed IV refuses here.
rc2StructToCanonical :: Word64 -> ByteString -> Maybe ByteString
rc2StructToCanonical bits iv
  | bits > fromIntegral (maxBound :: Int) = Nothing
  | BS.length iv /= 0 && BS.length iv /= 8 = Nothing
  | otherwise = Just (encodeRc2CbcParams (fromIntegral bits) iv)

-- | Pure EdDSA translation: the native @CK_BBOOL@ prehash flag
-- plus the chased context bytes onto the canonical
-- @eddsa-params/1@ image. Only flags 0/1 translate; anything
-- else refuses ('Nothing'). Non-pure combinations translate and
-- are refused downstream by the recipe (invalid parameters, not
-- a malformed struct).
eddsaStructToCanonical :: Word8 -> ByteString -> Maybe ByteString
eddsaStructToCanonical flag ctx
  | flag == 0 = Just (encodeEddsaParams False ctx)
  | flag == 1 = Just (encodeEddsaParams True ctx)
  | otherwise = Nothing

-- | ML-DSA translation: the native @CK_HEDGE_TYPE@ word plus the
-- chased context onto the canonical @mldsa-params/1@ image. Only
-- words 0/1/2 translate (the bound check runs on the 'Word64'
-- before narrowing, so no wrap-around can smuggle a hedge);
-- anything else passes through.
mldsaStructToCanonical :: Word64 -> ByteString -> Maybe ByteString
mldsaStructToCanonical hedge ctx
  | hedge > 2 = Nothing
  | otherwise = case hedgeOfWord (fromIntegral hedge) of
      Just h -> Just (encodeMldsaParams h ctx)
      Nothing -> Nothing

-- | SLH-DSA translation: the native @CK_HEDGE_TYPE@ word plus the
-- chased context onto the canonical @slhdsa-params/1@ image
-- (same struct shape as ML-DSA — @CK_SIGN_ADDITIONAL_CONTEXT@
-- is shared). Only words 0/1/2 translate; anything else passes
-- through.
slhdsaStructToCanonical :: Word64 -> ByteString -> Maybe ByteString
slhdsaStructToCanonical hedge ctx
  | hedge > 2 = Nothing
  | otherwise = case SlhDsa.hedgeOfWord (fromIntegral hedge) of
      Just h -> Just (encodeSlhdsaParams h ctx)
      Nothing -> Nothing

-- | One chased SP 800-108 data parameter: the iteration
-- variable (little-endian flag, width in bits), its absence
-- (the NULL\/0 placeholder feedback and double-pipeline callers
-- send — those modes have no counter), a byte-array
-- fixed-input segment, or the DKM-length trailer (method,
-- little-endian flag, width in bits). The IO normalizer parses
-- the native @CK_PRF_DATA_PARAM@ array into these; the pure
-- translator below enforces the canonical profile.
data Sp800DataParam
  = Sp800Iter !Bool !Word64
  | Sp800IterAbsent
  | Sp800Bytes !ByteString
  | Sp800DkmLen !Word64 !Bool !Word64
  deriving (Eq, Show)

-- | Pure SP 800-108 translation: the mode, the native PRF
-- mechanism id, the chased data parameters, the chased IV, and
-- the additional-keys count onto the canonical
-- @sp800-params\/1@ image. Only the canonical profile
-- translates: an HMAC PRF with a frame code, the iteration
-- variable first (big-endian, width 8\/16\/24\/32 — or the
-- NULL\/0 placeholder outside counter mode, which records
-- width 32), byte arrays in the middle (flattened in order),
-- the DKM length last (@SUM_OF_KEYS@, big-endian, width
-- 8\/16\/24\/32), an empty IV unless feedback mode, and zero
-- additional keys. Anything else refuses ('Nothing'), which
-- passes through raw so the recipe refusal (and its @CKR@) is
-- unchanged.
sp800StructToCanonical :: Sp800Mode -> Word64 -> [Sp800DataParam] -> ByteString -> Word64 -> Maybe ByteString
sp800StructToCanonical mode prf params iv additional = do
  guard (additional == 0)
  sp800StructToCanonicalProfile mode prf params iv

-- | The profile half of 'sp800StructToCanonical' (no
-- additional-keys gate): the multi-output normalizer chases
-- the array itself and calls this once the chase succeeds.
sp800StructToCanonicalProfile :: Sp800Mode -> Word64 -> [Sp800DataParam] -> ByteString -> Maybe ByteString
sp800StructToCanonicalProfile mode prf params iv = do
  code <- sp800PrfCodeFor (MechanismId (fromIntegral prf))
  guard (mode == Sp800Feedback || BS.null iv)
  (r, l, fixed) <- sp800ProfileSegments mode params
  Just (encodeSp800Params code r l iv fixed)

-- | The canonical data-parameter profile: the iteration
-- variable leads (big-endian, width 8\/16\/24\/32), byte
-- arrays fill the middle (flattened in order), and the DKM
-- length trails (@SUM_OF_KEYS@, big-endian, width
-- 8\/16\/24\/32). Outside counter mode the lead may be the
-- NULL\/0 placeholder (those modes have no counter); the frame
-- records width 32, inert downstream (planner and driver read
-- the counter width in counter mode only). The width check
-- runs on the 'Word64' before narrowing (the ML-DSA
-- precedent), so no wrap-around can smuggle a width.
-- 'Nothing' means off-profile.
sp800ProfileSegments :: Sp800Mode -> [Sp800DataParam] -> Maybe (Int, Int, ByteString)
sp800ProfileSegments mode (lead : rest) = do
  r <- case lead of
    Sp800Iter False w | w `elem` [8, 16, 24, 32] -> Just (fromIntegral w)
    Sp800IterAbsent | mode /= Sp800Counter -> Just 32
    _ -> Nothing
  (mid, Sp800DkmLen m False l) <- splitSp800Last rest
  guard (m == 1)
  guard (l `elem` [8, 16, 24, 32])
  segs <- traverse sp800SegBytes mid
  Just (r, fromIntegral l, BS.concat segs)
sp800ProfileSegments _ _ = Nothing

-- | Split a non-empty list into its init and its last element
-- ('Nothing' on empty — the profile needs at least the
-- iteration\/DKM-length pair).
splitSp800Last :: [a] -> Maybe ([a], a)
splitSp800Last [] = Nothing
splitSp800Last xs = Just (init xs, last xs)

-- | One middle segment flattens only when it is a byte array
-- (a second iteration variable or DKM length off-profile
-- refuses).
sp800SegBytes :: Sp800DataParam -> Maybe ByteString
sp800SegBytes (Sp800Bytes b) = Just b
sp800SegBytes _ = Nothing

-- | Chase one bounded byte string from caller memory under the
-- 'decodeInputBytes' null conventions: zero length never
-- dereferences, null-with-length and over-bound lengths refuse.
chaseBytes :: Ptr Word8 -> Word64 -> IO (Maybe ByteString)
chaseBytes ptr len
  | len == 0 = pure (Just BS.empty)
  | ptr == nullPtr = pure Nothing
  | len > maxInputBytes = pure Nothing
  | otherwise = do
      let cstr :: CStringLen
          cstr = (castPtr ptr, fromIntegral len)
      Just <$> BS.packCStringLen cstr

-- | Normalize one ECDH agreement struct: the native
-- @CK_ECDH1_DERIVE_PARAMS@ image at @pParams@/@paramsLen@ onto the
-- canonical @ecdh-params/1@ image. Wrong-sized images, non-null KDF
-- selectors, and null-with-length or over-bound shared/peer chases
-- refuse ('Nothing').
normalizeEcdhParams :: Ptr Word8 -> Word64 -> IO (Maybe ByteString)
normalizeEcdhParams pParams paramsLen
  | paramsLen /= fromIntegral ecdhNativeSize = pure Nothing
  | otherwise = do
      CULong kdf <- peekByteOff pParams 0
      CULong sharedLen <- peekByteOff pParams wordSize
      pShared <- peekByteOff pParams (2 * wordSize)
      CULong pubLen <- peekByteOff pParams (2 * wordSize + ptrSize)
      pPub <- peekByteOff pParams (3 * wordSize + ptrSize)
      mShared <- chaseBytes pShared sharedLen
      mPub <- chaseBytes pPub pubLen
      pure (mShared >>= \shared -> mPub >>= ecdhStructToCanonical kdf shared)

-- | Normalize one wrap-composition ECDH parameter image: the
-- native @CK_ECDH_AES_KEY_WRAP_PARAMS@ image at
-- @pParams@/@paramsLen@ onto the canonical
-- @wrapcomp-ecdh-params\/1@ image. Wrong-sized images, non-null
-- KDF selectors, and null-with-length or over-bound shared-data
-- chases refuse ('Nothing').
normalizeWrapCompEcdhParams :: Ptr Word8 -> Word64 -> IO (Maybe ByteString)
normalizeWrapCompEcdhParams pParams paramsLen
  | paramsLen /= fromIntegral wrapCompEcdhNativeSize = pure Nothing
  | otherwise = do
      -- Native field order leads with the strength word
      -- (ulAESKeyBits, kdf, ulSharedDataLen, pSharedData).
      CULong aesBits <- peekByteOff pParams 0
      CULong kdf <- peekByteOff pParams wordSize
      CULong sharedLen <- peekByteOff pParams (2 * wordSize)
      pShared <- peekByteOff pParams (2 * wordSize + ptrSize)
      mShared <- chaseBytes pShared sharedLen
      pure (mShared >>= \shared -> wrapCompEcdhStructToCanonical kdf shared aesBits)

-- | Normalize one PKCS#3 DH parameter image: the bare peer value
-- onto the canonical @dh-params/1@ image ('Just'), or 'Nothing'
-- for an empty image (which passes through raw so the recipe
-- refusal — and its @CKR@ — is exactly today's). Pure: no
-- pointers chase (the image is already in hand).
normalizeDhPkcsParams :: ByteString -> Maybe ByteString
normalizeDhPkcsParams = dhPkcsStructToCanonical

-- | Normalize one X9.42 DH agreement struct: the native
-- @CK_X9_42_DH1_DERIVE_PARAMS@ image at @pParams@/@paramsLen@
-- onto the canonical @dh-params/1@ image. Wrong-sized images,
-- non-null KDF selectors, non-empty shared data, and
-- null-with-length or over-bound shared/peer chases refuse
-- ('Nothing').
normalizeDhX942Params :: Ptr Word8 -> Word64 -> IO (Maybe ByteString)
normalizeDhX942Params pParams paramsLen
  | paramsLen /= fromIntegral dhX942NativeSize = pure Nothing
  | otherwise = do
      CULong kdf <- peekByteOff pParams 0
      CULong sharedLen <- peekByteOff pParams wordSize
      pShared <- peekByteOff pParams (2 * wordSize)
      CULong pubLen <- peekByteOff pParams (2 * wordSize + ptrSize)
      pPub <- peekByteOff pParams (3 * wordSize + ptrSize)
      mShared <- chaseBytes pShared sharedLen
      mPub <- chaseBytes pPub pubLen
      pure (mShared >>= \shared -> mPub >>= dhX942StructToCanonical kdf shared)

-- | Normalize one TLS-PRF struct: the native @CK_TLS_PRF_PARAMS@
-- image at @pParams@/@paramsLen@ onto the canonical
-- @tls-prf-params\/1@ image. Wrong-sized images and null-with-length
-- or over-bound seed\/label chases refuse ('Nothing'). The output
-- pointer pair is ignored (the derive path publishes objects, not
-- caller buffers).
normalizeTlsPrfParams :: Ptr Word8 -> Word64 -> IO (Maybe ByteString)
normalizeTlsPrfParams pParams paramsLen
  | paramsLen /= fromIntegral tlsPrfNativeSize = pure Nothing
  | otherwise = do
      pSeed <- peekByteOff pParams 0
      CULong seedLen <- peekByteOff pParams ptrSize
      pLabel <- peekByteOff pParams (ptrSize + wordSize)
      CULong labelLen <- peekByteOff pParams (2 * ptrSize + wordSize)
      mSeed <- chaseBytes pSeed seedLen
      mLabel <- chaseBytes pLabel labelLen
      pure (mSeed >>= \seed -> mLabel >>= \lab -> tlsPrfStructToCanonical lab seed)

-- | Chase one inline @CK_SSL3_RANDOM_DATA@ image: the client
-- and server randoms under 'maxInputBytes' with the
-- 'decodeInputBytes' null conventions (zero length never
-- dereferences, null-with-length and over-bound lengths
-- refuse).
chaseSsl3Random :: Ptr Word8 -> IO (Maybe (ByteString, ByteString))
chaseSsl3Random pRand = do
  pCli <- peekByteOff pRand 0
  CULong cliLen <- peekByteOff pRand ptrSize
  pSrv <- peekByteOff pRand (ptrSize + wordSize)
  CULong srvLen <- peekByteOff pRand (2 * ptrSize + wordSize)
  mCli <- chaseBytes pCli cliLen
  mSrv <- chaseBytes pSrv srvLen
  pure ((,) <$> mCli <*> mSrv)

-- | Normalize one TLS 1.0 master struct: the native
-- @CK_SSL3_MASTER_KEY_DERIVE_PARAMS@ image at
-- @pParams@/@paramsLen@ onto the canonical @tls-kdf-params\/1@
-- image. Wrong-sized images and refused random chases refuse
-- ('Nothing'); @pVersion@ (NULL-or-live, never written back)
-- is not even read.
normalizeTlsKdfMasterParams :: Ptr Word8 -> Word64 -> IO (Maybe ByteString)
normalizeTlsKdfMasterParams pParams paramsLen
  | paramsLen /= fromIntegral tlsKdfMasterNativeSize = pure Nothing
  | otherwise = do
      mRand <- chaseSsl3Random pParams
      pure (mRand >>= uncurry tlsKdfMasterStructToCanonical)

-- | Normalize one TLS 1.2 master struct: the native
-- @CK_TLS12_MASTER_KEY_DERIVE_PARAMS@ image at
-- @pParams@/@paramsLen@ onto the canonical image. Wrong-sized
-- images, refused chases, and unmapped PRF ids refuse
-- ('Nothing').
normalizeTlsKdfTls12MasterParams :: Ptr Word8 -> Word64 -> IO (Maybe ByteString)
normalizeTlsKdfTls12MasterParams pParams paramsLen
  | paramsLen /= fromIntegral tlsKdfTls12MasterNativeSize = pure Nothing
  | otherwise = do
      CULong prf <- peekByteOff pParams (ssl3RandomSize + ptrSize)
      mRand <- chaseSsl3Random pParams
      pure (mRand >>= \(cli, srv) -> tlsKdfTls12MasterStructToCanonical prf cli srv)

-- | Normalize one TLS 1.2 extended-master struct: the native
-- @CK_TLS12_EXTENDED_MASTER_KEY_DERIVE_PARAMS@ image at
-- @pParams@/@paramsLen@ onto the canonical image. Wrong-sized
-- images, refused chases, and unmapped PRF ids refuse
-- ('Nothing').
normalizeTlsKdfExtParams :: Ptr Word8 -> Word64 -> IO (Maybe ByteString)
normalizeTlsKdfExtParams pParams paramsLen
  | paramsLen /= fromIntegral tlsKdfExtNativeSize = pure Nothing
  | otherwise = do
      CULong prf <- peekByteOff pParams 0
      pSess <- peekByteOff pParams wordSize
      CULong sessLen <- peekByteOff pParams (wordSize + ptrSize)
      mSess <- chaseBytes pSess sessLen
      pure (mSess >>= tlsKdfExtStructToCanonical prf)

-- | Normalize one TLS-KDF struct: the native
-- @CK_TLS_KDF_PARAMS@ image at @pParams@/@paramsLen@ onto the
-- canonical image. Wrong-sized images, refused chases, and
-- unmapped PRF ids refuse ('Nothing').
normalizeTlsKdfFreeParams :: Ptr Word8 -> Word64 -> IO (Maybe ByteString)
normalizeTlsKdfFreeParams pParams paramsLen
  | paramsLen /= fromIntegral tlsKdfFreeNativeSize = pure Nothing
  | otherwise = do
      CULong prf <- peekByteOff pParams 0
      pLabel <- peekByteOff pParams wordSize
      CULong labLen <- peekByteOff pParams (wordSize + ptrSize)
      mLabel <- chaseBytes pLabel labLen
      mRand <- chaseSsl3Random (pParams `plusPtr` randOff)
      pCtx <- peekByteOff pParams ctxPtrOff
      CULong ctxLen <- peekByteOff pParams (ctxPtrOff + ptrSize)
      mCtx <- chaseBytes pCtx ctxLen
      pure (mLabel >>= \lab -> mRand >>= \(cli, srv) -> mCtx >>= \ctx ->
        tlsKdfFreeStructToCanonical prf lab cli srv ctx)
  where
    randOff = 2 * wordSize + ptrSize
    ctxPtrOff = randOff + ssl3RandomSize

-- | One native @CK_BBOOL@ byte onto 'Bool'; only 0\/1
-- translate (any other byte refuses — the EdDSA flag
-- convention, shared by the four IKE flag fields).
asBool :: Word8 -> Maybe Bool
asBool 0 = Just False
asBool 1 = Just True
asBool _ = Nothing

-- | Normalize one IKEv2 prf+ struct: the native
-- @CK_IKE2_PRF_PLUS_DERIVE_PARAMS@ image at
-- @pParams@/@paramsLen@ onto the canonical @ike-params\\/1@
-- image. Wrong-sized images, non-0\/1 flag bytes, the
-- seed-key leg (flag or handle), and refused seed chases
-- refuse ('Nothing').
normalizeIkePrfPlusParams :: Ptr Word8 -> Word64 -> IO (Maybe ByteString)
normalizeIkePrfPlusParams pParams paramsLen
  | paramsLen /= fromIntegral ikePrfPlusNativeSize = pure Nothing
  | otherwise = do
      CULong prf <- peekByteOff pParams 0
      hasSeed <- peekByteOff pParams wordSize
      CULong hSeed <- peekByteOff pParams (2 * wordSize)
      pSeed <- peekByteOff pParams (3 * wordSize)
      CULong seedLen <- peekByteOff pParams (3 * wordSize + ptrSize)
      mSeed <- chaseBytes pSeed seedLen
      pure (asBool hasSeed >>= \has ->
        if has || hSeed /= 0 then Nothing
        else mSeed >>= ikePrfPlusStructToCanonical prf)

-- | Normalize one IKE-PRF struct: the native
-- @CK_IKE_PRF_DERIVE_PARAMS@ image at @pParams@/@paramsLen@
-- onto the canonical @ike-params\\/1@ image. Wrong-sized
-- images, non-0\/1 flag bytes, the rekey leg, and refused
-- nonce chases refuse ('Nothing').
normalizeIkePrfParams :: Ptr Word8 -> Word64 -> IO (Maybe ByteString)
normalizeIkePrfParams pParams paramsLen
  | paramsLen /= fromIntegral ikePrfNativeSize = pure Nothing
  | otherwise = do
      CULong prf <- peekByteOff pParams 0
      dataAsKey <- peekByteOff pParams wordSize
      rekey <- peekByteOff pParams (wordSize + 1)
      pNi <- peekByteOff pParams (2 * wordSize)
      CULong niLen <- peekByteOff pParams (3 * wordSize)
      pNr <- peekByteOff pParams (3 * wordSize + ptrSize)
      CULong nrLen <- peekByteOff pParams (4 * wordSize + ptrSize)
      CULong hNew <- peekByteOff pParams (5 * wordSize + ptrSize)
      mNi <- chaseBytes pNi niLen
      mNr <- chaseBytes pNr nrLen
      pure (asBool dataAsKey >>= \dk -> asBool rekey >>= \rk ->
        mNi >>= \ni -> mNr >>= \nr ->
          ikePrfStructToCanonical prf dk rk ni nr hNew)

-- | Normalize one IKEv1-PRF struct: the native
-- @CK_IKE1_PRF_DERIVE_PARAMS@ image at @pParams@/@paramsLen@
-- onto the canonical @ike-params\\/1@ image. Wrong-sized
-- images, non-0\/1 flag bytes, a missing keygxy, any
-- prevkey, and refused cookie chases refuse ('Nothing').
normalizeIke1PrfParams :: Ptr Word8 -> Word64 -> IO (Maybe ByteString)
normalizeIke1PrfParams pParams paramsLen
  | paramsLen /= fromIntegral ike1PrfNativeSize = pure Nothing
  | otherwise = do
      CULong prf <- peekByteOff pParams 0
      hasPrev <- peekByteOff pParams wordSize
      CULong hKeygxy <- peekByteOff pParams (2 * wordSize)
      CULong hPrev <- peekByteOff pParams (3 * wordSize)
      pCkyi <- peekByteOff pParams (4 * wordSize)
      CULong ckyiLen <- peekByteOff pParams (5 * wordSize)
      pCkyr <- peekByteOff pParams (5 * wordSize + ptrSize)
      CULong ckyrLen <- peekByteOff pParams (6 * wordSize + ptrSize)
      keynum <- peekByteOff pParams (8 * wordSize)
      mCkyi <- chaseBytes pCkyi ckyiLen
      mCkyr <- chaseBytes pCkyr ckyrLen
      pure (asBool hasPrev >>= \hp ->
        mCkyi >>= \ckyi -> mCkyr >>= \ckyr ->
          ike1PrfStructToCanonical prf hp hKeygxy hPrev ckyi ckyr keynum)

-- | Normalize one IKEv1-extended struct: the native
-- @CK_IKE1_EXTENDED_DERIVE_PARAMS@ image at
-- @pParams@/@paramsLen@ onto the canonical @ike-params\\/1@
-- image. Wrong-sized images, non-0\/1 flag bytes, a
-- flag\/handle mismatch, and refused extra-data chases
-- refuse ('Nothing').
-- | The bare second-key handle of
-- @CKM_CONCATENATE_BASE_AND_KEY@ onto the canonical
-- @byteops-params\/1@ image (a zero handle refuses: no
-- second key to concatenate).
byteOpsConcatKeyStructToCanonical :: Word64 -> Maybe ByteString
byteOpsConcatKeyStructToCanonical h = do
  guard (h /= 0)
  Just (encodeByteOpsParams h 0 BS.empty)

-- | One @CK_KEY_DERIVATION_STRING_DATA@ payload onto the
-- canonical @byteops-params\/1@ image (shared by the two
-- data-concat rows and the XOR row).
byteOpsStringDataStructToCanonical :: ByteString -> Maybe ByteString
byteOpsStringDataStructToCanonical blob =
  Just (encodeByteOpsParams 0 0 blob)

-- | TLS 1.0 key-material sizes (bits), the export flag, and the
-- chased randoms onto the canonical @keymat-params\/1@ image.
-- The legacy PRF is fixed (code 0); non-multiple-of-8 sizes
-- and the export variant refuse ('Nothing').
tlsKeyMatStructToCanonical :: Word64 -> Word64 -> Word64 -> Bool -> ByteString -> ByteString -> Maybe ByteString
tlsKeyMatStructToCanonical macBits keyBits ivBits isExport cr sr = do
  guard (not isExport)
  mac <- bitsToBytesInt macBits
  key <- bitsToBytesInt keyBits
  iv <- bitsToBytesInt ivBits
  pure (encodeTlsKeyMatParams 0 mac key iv cr sr)

-- | SSL3 key-material sizes (bits), the export flag, and the
-- chased randoms onto the canonical @ssl3-keymat-params\/1@
-- image. Non-multiple-of-8 sizes and the export variant
-- refuse ('Nothing'; the export key expansion is not
-- served).
ssl3KeyMatStructToCanonical :: Word64 -> Word64 -> Word64 -> Bool -> ByteString -> ByteString -> Maybe ByteString
ssl3KeyMatStructToCanonical macBits keyBits ivBits isExport cr sr = do
  guard (not isExport)
  mac <- bitsToBytesInt macBits
  key <- bitsToBytesInt keyBits
  iv <- bitsToBytesInt ivBits
  pure (encodeSsl3KeyMatParams mac key iv cr sr)

-- | TLS 1.2 key-material sizes (bits), the export flag, the PRF
-- mechanism id, and the chased randoms onto the canonical
-- @keymat-params\/1@ image. Non-multiple-of-8 sizes, the
-- export variant, and unserved PRFs refuse ('Nothing').
tls12KeyMatStructToCanonical :: Word64 -> Word64 -> Word64 -> Bool -> Word64 -> ByteString -> ByteString -> Maybe ByteString
tls12KeyMatStructToCanonical macBits keyBits ivBits isExport prfMech cr sr = do
  guard (not isExport)
  mac <- bitsToBytesInt macBits
  key <- bitsToBytesInt keyBits
  iv <- bitsToBytesInt ivBits
  prf <- tlsKdfPrfCodeFor (MechanismId (fromIntegral prfMech))
  guard (prf /= 0)
  pure (encodeTlsKeyMatParams prf mac key iv cr sr)

-- | A bit size onto whole 'Int' bytes ('Nothing' on a ragged
-- width or an unnarrowable word).
bitsToBytesInt :: Word64 -> Maybe Int
bitsToBytesInt bits = bitsToBytes bits >>= word64ToInt

-- ---------------------------------------------------------------------------
-- Multi-output derives: params-embedded templates + write-back slots
-- ---------------------------------------------------------------------------

-- | Native @CK_SSL3_KEY_MAT_PARAMS@ image size: three size
-- words, the export byte (+ pad), the 32-byte random info, and
-- the out-struct pointer.
tlsKeyMatNativeSize :: Int
tlsKeyMatNativeSize = 3 * wordSize + 8 + 4 * wordSize + ptrSize

-- | Native @CK_TLS12_KEY_MAT_PARAMS@ image size: the TLS 1.0
-- shape plus the PRF mechanism word.
tls12KeyMatNativeSize :: Int
tls12KeyMatNativeSize = tlsKeyMatNativeSize + wordSize

-- | Write-back slots for one key-material call: the ordered
-- handle slots (two, or four when MACs are sized — plan
-- order) plus the IV buffers with their byte lengths (a zero
-- length ignores its pointer).
data KeyMatSlots = KeyMatSlots
  { kmsHandles :: ![Ptr CULong]
  , kmsIvC :: !(Ptr Word8)
  , kmsIvCLen :: !Int
  , kmsIvS :: !(Ptr Word8)
  , kmsIvSLen :: !Int
  } deriving (Eq, Show)

-- | One chased @CK_DERIVED_KEY@: its template plus the
-- caller handle slot.
data DerivedKeySlot = DerivedKeySlot
  { dksTemplate :: ![(AttributeType, AttributeValue)]
  , dksOut :: !(Ptr CULong)
  } deriving (Eq, Show)

-- | Additional-keys bound: the 16-key fan-out minus the
-- primary (deeper arrays refuse).
maxSp800AdditionalKeys :: Word64
maxSp800AdditionalKeys = 15

-- | A native attribute id onto its model type ('Nothing' for
-- unmapped ids, which refuse the chase).
attrTypeByNativeId :: Word64 -> Maybe AttributeType
attrTypeByNativeId w =
  lookup w [(i, n) | (i, n, _) <- generatedAttributes] >>= attributeTypeByName

-- | Native @CK_ATTRIBUTE@ image size: type word, value
-- pointer, length word.
ckAttrSize :: Int
ckAttrSize = 3 * wordSize

-- | Chase a native attribute array into a template: over-long
-- arrays, null arrays, unmapped ids, refused value chases,
-- and cross-shape values refuse ('Nothing'). Entries chase in
-- order and short-circuit on the first refusal. Native words
-- decode little-endian (caller layout); bytes and bools ride
-- the canonical value decoder.
chaseAttrTemplate :: Ptr Word8 -> Word64 -> IO (Maybe [(AttributeType, AttributeValue)])
chaseAttrTemplate pAttrs n
  | n > fromIntegral maxTemplateEntries = pure Nothing
  | n == 0 = pure (Just [])
  | pAttrs == nullPtr = pure Nothing
  | otherwise = go 0
  where
    go :: Word64 -> IO (Maybe [(AttributeType, AttributeValue)])
    go i
      | i >= n = pure (Just [])
      | otherwise = do
          let el = pAttrs `plusPtr` (fromIntegral i * ckAttrSize)
          CULong typ <- peekByteOff el 0
          pVal <- peekByteOff el wordSize
          CULong vlen <- peekByteOff el (2 * wordSize)
          mOne <- case attrTypeByNativeId typ of
            Nothing -> pure Nothing
            Just t -> do
              mBs <- chaseBytes pVal vlen
              pure $ do
                bs <- mBs
                v <- case shapeOf t of
                  ShapeULong -> ValULong . fromIntegral <$> leWordToInt bs
                  _ -> decodeValue t bs
                pure (t, v)
          case mOne of
            Nothing -> pure Nothing
            Just one -> (fmap . fmap) (one :) (go (i + 1))

-- | Native @CK_DERIVED_KEY@ image size: template pointer,
-- count word, handle-slot pointer.
ckDerivedKeySize :: Int
ckDerivedKeySize = 2 * ptrSize + wordSize

-- | Chase the @CK_DERIVED_KEY@ array into slots: over-bound
-- counts, null arrays, refused templates, and null handle
-- slots refuse ('Nothing').
chaseDerivedKeys :: Ptr Word8 -> Word64 -> IO (Maybe [DerivedKeySlot])
chaseDerivedKeys pArr n
  | n > maxSp800AdditionalKeys = pure Nothing
  | n == 0 = pure (Just [])
  | pArr == nullPtr = pure Nothing
  | otherwise = go 0
  where
    go :: Word64 -> IO (Maybe [DerivedKeySlot])
    go i
      | i >= n = pure (Just [])
      | otherwise = do
          let el = pArr `plusPtr` (fromIntegral i * ckDerivedKeySize)
          pTmpl <- peekByteOff el 0
          CULong tcount <- peekByteOff el ptrSize
          phKey <- peekByteOff el (ptrSize + wordSize)
          mTmpl <- chaseAttrTemplate pTmpl tcount
          case (mTmpl, phKey == (nullPtr :: Ptr CULong)) of
            (Just t, False) ->
              (fmap . fmap) (DerivedKeySlot t phKey :) (go (i + 1))
            _ -> pure Nothing

-- | Normalize one TLS 1.0 key-material struct: the canonical
-- frame plus the caller write-back slots. Wrong-sized
-- images, null out-structs, null IV buffers under a nonzero
-- IV size, refused random chases, and off-profile sizes
-- refuse ('Nothing').
normalizeTlsKeyMatParams :: Ptr Word8 -> Word64 -> IO (Maybe (ByteString, KeyMatSlots))
normalizeTlsKeyMatParams pParams paramsLen
  | paramsLen /= fromIntegral tlsKeyMatNativeSize = pure Nothing
  | otherwise = normalizeKeyMatCommon pParams tlsKeyMatStructToCanonical False

-- | Normalize one SSL3 key-material struct: the
-- @CK_SSL3_KEY_MAT_PARAMS@ geometry matches
-- @CK_TLS_KEY_MAT_PARAMS@ exactly, so the shared chase runs
-- with the SSL3 frame translator. Wrong-sized images, null
-- out-structs, null IV buffers under a nonzero IV size,
-- refused random chases, and off-profile sizes refuse
-- ('Nothing').
normalizeSsl3KeyMatParams :: Ptr Word8 -> Word64 -> IO (Maybe (ByteString, KeyMatSlots))
normalizeSsl3KeyMatParams pParams paramsLen
  | paramsLen /= fromIntegral tlsKeyMatNativeSize = pure Nothing
  | otherwise = normalizeKeyMatCommon pParams ssl3KeyMatStructToCanonical False

-- | Normalize one SSL3 master struct: the native
-- @CK_SSL3_MASTER_KEY_DERIVE_PARAMS@ image at
-- @pParams@/@paramsLen@ onto the canonical
-- @ssl3-master-params\/1@ image. Wrong-sized images and
-- refused random chases refuse ('Nothing'); @pVersion@
-- (NULL-or-live, never written back) is not even read.
normalizeSsl3MasterParams :: Ptr Word8 -> Word64 -> IO (Maybe ByteString)
normalizeSsl3MasterParams pParams paramsLen
  | paramsLen /= fromIntegral ssl3MasterNativeSize = pure Nothing
  | otherwise = do
      mRand <- chaseSsl3Random pParams
      pure (uncurry encodeSsl3MasterParams <$> mRand)

-- | Normalize one TLS 1.2 key-material struct (the AND_MAC
-- row): like 'normalizeTlsKeyMatParams' plus the PRF word.
normalizeTls12KeyMatParams :: Ptr Word8 -> Word64 -> IO (Maybe (ByteString, KeyMatSlots))
normalizeTls12KeyMatParams pParams paramsLen
  | paramsLen /= fromIntegral tls12KeyMatNativeSize = pure Nothing
  | otherwise = do
      CULong prf <- peekByteOff pParams (tlsKeyMatNativeSize)
      normalizeKeyMatCommon pParams
        (\m k i e cr sr -> tls12KeyMatStructToCanonical m k i e prf cr sr) False

-- | Normalize one TLS 1.2 key-safe struct: like
-- 'normalizeTls12KeyMatParams', except the IV size is ignored
-- and treated as 0 (v3.2 §6.40.7) — null IV pointers accept
-- and the slots carry zero IV lengths, matching the planner's
-- suppression.
normalizeTls12KeySafeParams :: Ptr Word8 -> Word64 -> IO (Maybe (ByteString, KeyMatSlots))
normalizeTls12KeySafeParams pParams paramsLen
  | paramsLen /= fromIntegral tls12KeyMatNativeSize = pure Nothing
  | otherwise = do
      CULong prf <- peekByteOff pParams (tlsKeyMatNativeSize)
      normalizeKeyMatCommon pParams
        (\m k i e cr sr -> tls12KeyMatStructToCanonical m k i e prf cr sr) True

-- | Shared key-material chase: sizes, the export byte, the
-- random info, and the out-struct slots; the pure translator
-- (legacy or hash-selected) builds the frame. The key-safe
-- row ignores the IV size (treated as 0).
normalizeKeyMatCommon :: Ptr Word8 -> (Word64 -> Word64 -> Word64 -> Bool -> ByteString -> ByteString -> Maybe ByteString) -> Bool -> IO (Maybe (ByteString, KeyMatSlots))
normalizeKeyMatCommon pParams structToCanonical ignoreIv = do
  CULong macBits <- peekByteOff pParams 0
  CULong keyBits <- peekByteOff pParams wordSize
  CULong ivBits <- peekByteOff pParams (2 * wordSize)
  exportByte <- peekByteOff pParams (3 * wordSize)
  pCr <- peekByteOff pParams (4 * wordSize)
  CULong crLen <- peekByteOff pParams (5 * wordSize)
  pSr <- peekByteOff pParams (6 * wordSize)
  CULong srLen <- peekByteOff pParams (7 * wordSize)
  pOut <- peekByteOff pParams (8 * wordSize)
  mCr <- chaseBytes pCr crLen
  mSr <- chaseBytes pSr srLen
  case (mCr, mSr, pOut == (nullPtr :: Ptr Word8)) of
    (Just cr, Just sr, False) -> do
      pIvC <- peekByteOff pOut (4 * wordSize)
      pIvS <- peekByteOff pOut (5 * wordSize)
      let ivOk = ignoreIv || ivBits == 0
            || (pIvC /= (nullPtr :: Ptr Word8) && pIvS /= (nullPtr :: Ptr Word8))
          isExport = (exportByte :: Word8) /= 0
          mFrame = structToCanonical macBits keyBits ivBits isExport cr sr
      case (ivOk, mFrame) of
        (True, Just frame) -> case (bitsToBytesInt macBits, bitsToBytesInt ivBits) of
          (Just mac, Just iv) -> do
            let slot :: Int -> IO (Ptr CULong)
                slot o = pure (castPtr (pOut `plusPtr` o))
            s0 <- slot 0
            s1 <- slot wordSize
            s2 <- slot (2 * wordSize)
            s3 <- slot (3 * wordSize)
            pure (Just (frame, KeyMatSlots
              { kmsHandles = if mac > 0 then [s0, s1, s2, s3] else [s2, s3]
              , kmsIvC = pIvC
              , kmsIvCLen = if ignoreIv then 0 else iv
              , kmsIvS = pIvS
              , kmsIvSLen = if ignoreIv then 0 else iv
              }))
          _ -> pure Nothing
        _ -> pure Nothing
    _ -> pure Nothing

-- | The bare bit offset of @CKM_EXTRACT_KEY_FROM_KEY@ onto
-- the canonical @byteops-params\/1@ image (range is checked
-- against the base length downstream).
byteOpsExtractStructToCanonical :: Word64 -> Maybe ByteString
byteOpsExtractStructToCanonical off =
  Just (encodeByteOpsParams 0 off BS.empty)

-- | Normalize one bare second-key handle: the native
-- @CK_ULONG@ image at @pParams@/@paramsLen@ onto the
-- canonical @byteops-params\/1@ image. Wrong-sized images
-- and the zero handle refuse ('Nothing').
normalizeByteOpsConcatKeyParams :: Ptr Word8 -> Word64 -> IO (Maybe ByteString)
normalizeByteOpsConcatKeyParams pParams paramsLen
  | paramsLen /= fromIntegral byteOpsUlongNativeSize = pure Nothing
  | otherwise = do
      CULong h <- peekByteOff pParams 0
      pure (byteOpsConcatKeyStructToCanonical (fromIntegral h))

-- | Normalize one string-data struct: the native
-- @CK_KEY_DERIVATION_STRING_DATA@ image at
-- @pParams@/@paramsLen@ onto the canonical @byteops-params\/1@
-- image. Wrong-sized images and refused data chases refuse
-- ('Nothing').
normalizeByteOpsStringDataParams :: Ptr Word8 -> Word64 -> IO (Maybe ByteString)
normalizeByteOpsStringDataParams pParams paramsLen
  | paramsLen /= fromIntegral byteOpsStringDataNativeSize = pure Nothing
  | otherwise = do
      pData <- peekByteOff pParams 0
      CULong dataLen <- peekByteOff pParams ptrSize
      mData <- chaseBytes pData dataLen
      pure (mData >>= byteOpsStringDataStructToCanonical)

-- | Normalize one bare bit offset: the native @CK_ULONG@
-- image at @pParams@/@paramsLen@ onto the canonical
-- @byteops-params\/1@ image. Wrong-sized images refuse
-- ('Nothing').
normalizeByteOpsExtractParams :: Ptr Word8 -> Word64 -> IO (Maybe ByteString)
normalizeByteOpsExtractParams pParams paramsLen
  | paramsLen /= fromIntegral byteOpsUlongNativeSize = pure Nothing
  | otherwise = do
      CULong off <- peekByteOff pParams 0
      pure (byteOpsExtractStructToCanonical (fromIntegral off))

normalizeIke1ExtParams :: Ptr Word8 -> Word64 -> IO (Maybe ByteString)
normalizeIke1ExtParams pParams paramsLen
  | paramsLen /= fromIntegral ike1ExtNativeSize = pure Nothing
  | otherwise = do
      CULong prf <- peekByteOff pParams 0
      hasKeygxy <- peekByteOff pParams wordSize
      CULong hKeygxy <- peekByteOff pParams (2 * wordSize)
      pExtra <- peekByteOff pParams (3 * wordSize)
      CULong extraLen <- peekByteOff pParams (3 * wordSize + ptrSize)
      mExtra <- chaseBytes pExtra extraLen
      pure (asBool hasKeygxy >>= \has ->
        mExtra >>= ike1ExtStructToCanonical prf has hKeygxy)

-- | Native @CK_*_CBC_ENCRYPT_DATA_PARAMS@ image size for one IV
-- width: the inline IV plus (pointer, length) for the data (the
-- four family structs share this layout; only the IV width
-- differs: 16 for AES/ARIA/Camellia, 8 for Triple-DES).
encryptDataCbcNativeSize :: Int -> Int
encryptDataCbcNativeSize iv = iv + ptrSize + wordSize

-- | Normalize one CBC-encrypt-data struct: the native image at
-- @pParams@/@paramsLen@ onto the canonical @iv||data@ frame.
-- Wrong-sized images and null-with-length or over-bound data
-- chases refuse ('Nothing', which passes through raw so the
-- recipe refusal is exactly the planner's).
normalizeEncryptDataCbcParams :: Int -> Ptr Word8 -> Word64 -> IO (Maybe ByteString)
normalizeEncryptDataCbcParams iv pParams paramsLen
  | paramsLen /= fromIntegral (encryptDataCbcNativeSize iv) = pure Nothing
  | otherwise = do
      pData <- peekByteOff pParams iv
      CULong dataLen <- peekByteOff pParams (iv + ptrSize)
      mData <- chaseBytes pData dataLen
      case mData of
        Nothing -> pure Nothing
        Just dat -> do
          ivBytes <- BS.packCStringLen (castPtr pParams, iv)
          pure (Just (ivBytes <> dat))

-- | Native @CK_KEY_DERIVATION_STRING_DATA@ image size: (pointer,
-- length) for the data (the ECB encrypt-data rows take this
-- struct, not the raw data bytes).
encryptDataEcbNativeSize :: Int
encryptDataEcbNativeSize = ptrSize + wordSize

-- | Normalize one ECB-encrypt-data struct: chase the string-data
-- struct at @pParams@/@paramsLen@ onto the canonical raw data
-- bytes. Wrong-sized images and null-with-length or over-bound
-- data chases refuse ('Nothing', which the derive blob poisons
-- so the recipe refusal is exactly the planner's).
normalizeEncryptDataEcbParams :: Ptr Word8 -> Word64 -> IO (Maybe ByteString)
normalizeEncryptDataEcbParams pParams paramsLen
  | paramsLen /= fromIntegral encryptDataEcbNativeSize = pure Nothing
  | otherwise = do
      pData <- peekByteOff pParams 0
      CULong dataLen <- peekByteOff pParams ptrSize
      chaseBytes pData dataLen

-- | Normalize one PBKD2 generation struct: the native
-- @CK_PKCS5_PBKD2_PARAMS2@ image at @pParams@/@paramsLen@ onto
-- the canonical @pbkd2-params\/2@ image. Wrong-sized images and
-- null-with-length or over-bound salt\/PRF-data\/password chases
-- refuse ('Nothing'); the pure translator bounds the rest.
normalizePbkd2Params2 :: Ptr Word8 -> Word64 -> IO (Maybe ByteString)
normalizePbkd2Params2 pParams paramsLen
  | paramsLen /= fromIntegral pbkd2Params2NativeSize = pure Nothing
  | otherwise = do
      CULong saltSource <- peekByteOff pParams 0
      pSalt <- peekByteOff pParams wordSize
      CULong saltLen <- peekByteOff pParams (wordSize + ptrSize)
      CULong iters <- peekByteOff pParams (2 * wordSize + ptrSize)
      CULong prf <- peekByteOff pParams (3 * wordSize + ptrSize)
      pPrfData <- peekByteOff pParams (4 * wordSize + ptrSize)
      CULong prfDataLen <- peekByteOff pParams (4 * wordSize + 2 * ptrSize)
      pPassword <- peekByteOff pParams (5 * wordSize + 2 * ptrSize)
      CULong pwdLen <- peekByteOff pParams (5 * wordSize + 3 * ptrSize)
      mSalt <- chaseBytes pSalt saltLen
      mPrfData <- chaseBytes pPrfData prfDataLen
      mPwd <- chaseBytes pPassword pwdLen
      pure (mSalt >>= \salt -> mPrfData >>= \prfData -> mPwd >>= \pwd ->
        pbkd2Params2StructToCanonical saltSource salt iters prf prfData pwd)

-- | Native SP 800-108 KDF params image size: three words
-- plus two pointers for counter and double-pipeline mode
-- (@CK_SP800_108_KDF_PARAMS@, 40 bytes), four words plus three
-- pointers for feedback mode (@CK_SP800_108_FEEDBACK_KDF_PARAMS@,
-- 56 bytes).
sp800NativeSize :: Sp800Mode -> Int
sp800NativeSize Sp800Feedback = 4 * wordSize + 3 * ptrSize
sp800NativeSize _ = 3 * wordSize + 2 * ptrSize

-- | Native @CK_PBE_PARAMS@ image size: the IV and password
-- pointers, the password length, the salt pointer and length,
-- and the iteration count.
pbeParamsNativeSize :: Int
pbeParamsNativeSize = 2 * ptrSize + 4 * wordSize

-- | Password, salt, and the iteration count onto the canonical
-- @pbe-params\/1@ image (bounds are the recipe's).
pbeStructToCanonical :: Word64 -> ByteString -> ByteString -> Maybe ByteString
pbeStructToCanonical iters pw salt = Just (encodePbeParams iters pw salt)

-- | Normalize one PBE keygen struct: the native
-- @CK_PBE_PARAMS@ image at @pParams@/@paramsLen@ onto the
-- canonical @pbe-params\/1@ image plus the caller IV slot.
-- Wrong-sized images, a null IV buffer (the IV is required
-- output for the served rows), and null-with-length or
-- over-bound password\/salt chases refuse ('Nothing').
normalizePbeParams :: Ptr Word8 -> Word64 -> IO (Maybe (ByteString, Ptr Word8))
normalizePbeParams pParams paramsLen = do
  m <- normalizePbeParamsMaybeIv pParams paramsLen
  pure $ case m of
    Just (b, Just slot) -> Just (b, slot)
    _ -> Nothing

-- | Normalize one PBE keygen struct, accepting a null IV
-- buffer for the no-IV rows (RC4): the canonical image plus
-- the IV slot when present ('Nothing' slot with canonical
-- bytes for the null-IV shape). Wrong-sized images and
-- null-with-length or over-bound password\/salt chases
-- refuse ('Nothing').
normalizePbeParamsMaybeIv :: Ptr Word8 -> Word64 -> IO (Maybe (ByteString, Maybe (Ptr Word8)))
normalizePbeParamsMaybeIv pParams paramsLen
  | paramsLen /= fromIntegral pbeParamsNativeSize = pure Nothing
  | otherwise = do
      pIv <- peekByteOff pParams 0
      pPw <- peekByteOff pParams ptrSize
      CULong pwLen <- peekByteOff pParams (ptrSize + wordSize)
      pSalt <- peekByteOff pParams (ptrSize + 2 * wordSize)
      CULong saltLen <- peekByteOff pParams (ptrSize + 3 * wordSize)
      CULong iters <- peekByteOff pParams (ptrSize + 4 * wordSize)
      mPw <- chaseBytes pPw pwLen
      mSalt <- chaseBytes pSalt saltLen
      case (mPw, mSalt, pIv == (nullPtr :: Ptr Word8)) of
        (Just pw, Just salt, False) ->
          pure ((, Just pIv) <$> pbeStructToCanonical iters pw salt)
        (Just pw, Just salt, True) ->
          pure ((, Nothing) <$> pbeStructToCanonical iters pw salt)
        _ -> pure Nothing

-- | Normalize one SP 800-108 KDF struct: the native image at
-- @pParams@/@paramsLen@ onto the canonical @sp800-params\/1@
-- image. Wrong-sized images, null or over-long data-parameter
-- arrays, refused chases, and off-profile parameters refuse
-- ('Nothing'), which passes through raw so the recipe refusal
-- is exactly the planner's.
normalizeSp800KdfParams :: Sp800Mode -> Ptr Word8 -> Word64 -> IO (Maybe (ByteString, [DerivedKeySlot]))
normalizeSp800KdfParams mode pParams paramsLen
  | paramsLen /= fromIntegral (sp800NativeSize mode) = pure Nothing
  | otherwise = do
      CULong prf <- peekByteOff pParams 0
      CULong nParams <- peekByteOff pParams wordSize
      pDataParams <- peekByteOff pParams (2 * wordSize)
      (ivLen, pIv, additional, pAdditional) <- case mode of
        Sp800Feedback -> do
          CULong il <- peekByteOff pParams (2 * wordSize + ptrSize)
          piv <- peekByteOff pParams (3 * wordSize + ptrSize)
          CULong ad <- peekByteOff pParams (3 * wordSize + 2 * ptrSize)
          pAd <- peekByteOff pParams (4 * wordSize + 2 * ptrSize)
          pure (il, piv, ad, pAd)
        _ -> do
          CULong ad <- peekByteOff pParams (2 * wordSize + ptrSize)
          pAd <- peekByteOff pParams (3 * wordSize + ptrSize)
          pure (0, nullPtr, ad, pAd)
      mParams <- chaseSp800DataParams pDataParams nParams
      mIv <- chaseBytes pIv ivLen
      mSlots <- chaseSp800Additional additional pAdditional
      pure (mParams >>= \ps -> mIv >>= \iv -> mSlots >>= \slots ->
        fmap (\b -> (b, slots)) (sp800StructToCanonicalProfile mode prf ps iv))

-- | Chase the additional-keys array: a zero count demands a
-- NULL pointer (v3.2: "must be set to NULL_PTR"); a nonzero
-- count chases that many entries ('chaseDerivedKeys').
chaseSp800Additional :: Word64 -> Ptr Word8 -> IO (Maybe [DerivedKeySlot])
chaseSp800Additional additional pAdditional
  | additional == 0 =
      if pAdditional == nullPtr then pure (Just []) else pure Nothing
  | otherwise = chaseDerivedKeys pAdditional additional

-- | Native @CK_PRF_DATA_PARAM@ image size: one type word, one
-- pointer, one length word.
sp800DataParamSize :: Int
sp800DataParamSize = 2 * wordSize + ptrSize

-- | Data-parameter array bound (the oracle sends five; the
-- content ceilings live in the recipe): longer arrays refuse.
maxSp800DataParams :: Word64
maxSp800DataParams = 32

-- | Chase the native data-parameter array into 'Sp800DataParam'
-- values. Arrays shorter than the iteration\/DKM-length pair,
-- longer than 'maxSp800DataParams', null, or holding an
-- unchased element refuse ('Nothing'). Elements chase in
-- order and short-circuit on the first refusal.
chaseSp800DataParams :: Ptr Word8 -> Word64 -> IO (Maybe [Sp800DataParam])
chaseSp800DataParams pData n
  | n < 2 || n > maxSp800DataParams = pure Nothing
  | pData == nullPtr = pure Nothing
  | otherwise = go 0
  where
    go :: Word64 -> IO (Maybe [Sp800DataParam])
    go i
      | i >= n = pure (Just [])
      | otherwise = do
          let el = pData `plusPtr` (fromIntegral i * sp800DataParamSize)
          CULong typ <- peekByteOff el 0
          pVal <- peekByteOff el wordSize
          CULong vlen <- peekByteOff el (wordSize + ptrSize)
          mOne <- chaseSp800One typ pVal vlen
          case mOne of
            Nothing -> pure Nothing
            Just one -> (fmap . fmap) (one :) (go (i + 1))

-- | Chase one data parameter: the iteration variable and the
-- DKM length dereference their native format structs
-- (@CK_SP800_108_COUNTER_FORMAT@, 16 bytes: flag plus width;
-- @CK_SP800_108_DKM_LENGTH_FORMAT@, 24 bytes: method plus
-- flag plus width — @spec\/vendor\/pkcs11.h:1881-1890@), byte
-- arrays chase as bytes. A NULL\/0 iteration variable chases
-- as the counterless placeholder (the translator admits it
-- outside counter mode only); half-absent shapes (null with
-- length, zero length with a live pointer), wrong-sized
-- format images, and unknown parameter types refuse
-- ('Nothing').
chaseSp800One :: Word64 -> Ptr Word8 -> Word64 -> IO (Maybe Sp800DataParam)
chaseSp800One typ pVal vlen = case typ of
  1 | pVal == nullPtr && vlen == 0 -> pure (Just Sp800IterAbsent)
  1 | vlen == 16 && pVal /= nullPtr -> do
    le <- (peekByteOff pVal 0 :: IO Word8)
    CULong w <- peekByteOff pVal 8
    pure (Just (Sp800Iter (le /= 0) w))
  3 | vlen == 24 && pVal /= nullPtr -> do
    CULong m <- peekByteOff pVal 0
    le <- (peekByteOff pVal 8 :: IO Word8)
    CULong w <- peekByteOff pVal 16
    pure (Just (Sp800DkmLen m (le /= 0) w))
  4 -> (fmap . fmap) Sp800Bytes (chaseBytes pVal vlen)
  _ -> pure Nothing

-- | Normalize one call's mechanism parameters: struct mechanisms
-- translate from the live caller image at @pParams@/@paramsLen@
-- (already length-checked by 'decodeInputBytes', whose copy is
-- @raw@); every other mechanism passes @raw@ through. Unmappable
-- struct images also pass through, preserving today's recipe
-- refusal.
normalizeMechParams
  :: MechanismId -> Ptr Word8 -> Word64 -> ByteString -> IO ByteString
normalizeMechParams mid pParams paramsLen raw
  | isJust (rsaPssRecipeFor mid) = fromMaybe raw <$> decodePssNative
  | isJust (rsaOaepRecipeFor mid) = fromMaybe raw <$> decodeOaepNative
  | isJust (gcmRecipeFor mid) = fromMaybe raw <$> decodeGcmNative
  | isJust (gmacRecipeFor mid) = fromMaybe raw <$> decodeGcmNative
  | isJust (ccmRecipeFor mid) = fromMaybe raw <$> decodeCcmNative
  | isJust (ctrRecipeFor mid) = fromMaybe raw <$> decodeCtrNative
  | isJust (rc2RecipeFor mid) = fromMaybe raw <$> decodeRc2Native
  | isJust (eddsaRecipeFor mid) = fromMaybe raw <$> decodeEddsaNative
  | isJust (mldsaRecipeFor mid) = fromMaybe raw <$> decodeMldsaNative
  | isJust (slhdsaRecipeFor mid) = fromMaybe raw <$> decodeSlhdsaNative
  | Just r <- chachaRecipeFor mid, chachaName r == "CKM_CHACHA20" =
      fromMaybe raw <$> decodeChachaStreamNative
  | Just r <- chachaRecipeFor mid, chachaName r == "CKM_CHACHA20_POLY1305" =
      fromMaybe raw <$> decodeChachaPolyNative
  | isJust (wrapCompEcdhRecipeFor mid) =
      fromMaybe raw <$> normalizeWrapCompEcdhParams pParams paramsLen
  | otherwise = pure raw
  where
    decodePssNative :: IO (Maybe ByteString)
    decodePssNative
      | paramsLen /= fromIntegral pssNativeSize = pure Nothing
      | otherwise = do
          CULong hashId <- peekByteOff pParams 0
          CULong mgfId <- peekByteOff pParams wordSize
          CULong salt <- peekByteOff pParams (2 * wordSize)
          pure (pssStructToCanonical hashId mgfId salt)
    decodeOaepNative :: IO (Maybe ByteString)
    decodeOaepNative
      | paramsLen /= fromIntegral oaepNativeSize = pure Nothing
      | otherwise = do
          CULong hashId <- peekByteOff pParams 0
          CULong mgfId <- peekByteOff pParams wordSize
          CULong source <- peekByteOff pParams (2 * wordSize)
          pLabel <- peekByteOff pParams (3 * wordSize)
          CULong labelLen <- peekByteOff pParams (3 * wordSize + ptrSize)
          if source /= ckzDataSpecified
            then pure Nothing
            else do
              mLabel <- chaseBytes pLabel labelLen
              pure (mLabel >>= oaepStructToCanonical hashId mgfId)
    decodeGcmNative :: IO (Maybe ByteString)
    decodeGcmNative
      | paramsLen /= fromIntegral gcmNativeSize = pure Nothing
      | otherwise = do
          pIv <- peekByteOff pParams 0
          CULong ivLen <- peekByteOff pParams ptrSize
          CULong ivBits <- peekByteOff pParams (ptrSize + wordSize)
          pAad <- peekByteOff pParams (ptrSize + 2 * wordSize)
          CULong aadLen <- peekByteOff pParams (2 * ptrSize + 2 * wordSize)
          CULong tagBits <- peekByteOff pParams (2 * ptrSize + 3 * wordSize)
          mIv <- chaseBytes pIv ivLen
          mAad <- chaseBytes pAad aadLen
          pure (mIv >>= \iv -> mAad >>= \aad -> gcmStructToCanonical iv aad ivBits tagBits)
    decodeCcmNative :: IO (Maybe ByteString)
    decodeCcmNative
      | paramsLen /= fromIntegral ccmNativeSize = pure Nothing
      | otherwise = do
          CULong dataLen <- peekByteOff pParams 0
          pNonce <- peekByteOff pParams wordSize
          CULong nonceLen <- peekByteOff pParams (wordSize + ptrSize)
          pAad <- peekByteOff pParams (2 * wordSize + ptrSize)
          CULong aadLen <- peekByteOff pParams (2 * wordSize + 2 * ptrSize)
          CULong macLen <- peekByteOff pParams (3 * wordSize + 2 * ptrSize)
          mNonce <- chaseBytes pNonce nonceLen
          mAad <- chaseBytes pAad aadLen
          pure (mNonce >>= \nonce -> mAad >>= \aad -> ccmStructToCanonical nonce aad dataLen nonceLen macLen)
    decodeCtrNative :: IO (Maybe ByteString)
    decodeCtrNative
      | paramsLen /= fromIntegral ctrNativeSize = pure Nothing
      | otherwise = do
          CULong bits <- peekByteOff pParams 0
          cb <- BS.packCStringLen (castPtr (pParams `plusPtr` wordSize), 16)
          pure (ctrStructToCanonical bits cb)
    decodeRc2Native :: IO (Maybe ByteString)
    decodeRc2Native
      | paramsLen == fromIntegral rc2EcbNativeSize = do
          CULong bits <- peekByteOff pParams 0
          pure (rc2StructToCanonical bits BS.empty)
      | paramsLen == fromIntegral rc2CbcNativeSize = do
          CULong bits <- peekByteOff pParams 0
          iv <- BS.packCStringLen (castPtr (pParams `plusPtr` wordSize), 8)
          pure (rc2StructToCanonical bits iv)
      | otherwise = pure Nothing
    decodeEddsaNative :: IO (Maybe ByteString)
    decodeEddsaNative
      | paramsLen /= fromIntegral eddsaNativeSize = pure Nothing
      | otherwise = do
          flag <- peekByteOff pParams 0
          CULong ctxLen <- peekByteOff pParams eddsaLenOff
          pCtx <- peekByteOff pParams (eddsaLenOff + wordSize)
          mCtx <- chaseBytes pCtx ctxLen
          pure (mCtx >>= eddsaStructToCanonical flag)
    decodeMldsaNative :: IO (Maybe ByteString)
    decodeMldsaNative
      | paramsLen /= fromIntegral mldsaNativeSize = pure Nothing
      | otherwise = do
          CULong hedge <- peekByteOff pParams 0
          pCtx <- peekByteOff pParams wordSize
          CULong ctxLen <- peekByteOff pParams (wordSize + ptrSize)
          mCtx <- chaseBytes pCtx ctxLen
          pure (mCtx >>= mldsaStructToCanonical hedge)
    decodeSlhdsaNative :: IO (Maybe ByteString)
    decodeSlhdsaNative
      | paramsLen /= fromIntegral slhdsaNativeSize = pure Nothing
      | otherwise = do
          CULong hedge <- peekByteOff pParams 0
          pCtx <- peekByteOff pParams wordSize
          CULong ctxLen <- peekByteOff pParams (wordSize + ptrSize)
          mCtx <- chaseBytes pCtx ctxLen
          pure (mCtx >>= slhdsaStructToCanonical hedge)
    decodeChachaStreamNative :: IO (Maybe ByteString)
    decodeChachaStreamNative
      | paramsLen /= fromIntegral chachaStreamNativeSize = pure Nothing
      | otherwise = do
          pCtr <- peekByteOff pParams 0
          CULong ctrBits <- peekByteOff pParams ptrSize
          pNonce <- peekByteOff pParams (ptrSize + wordSize)
          CULong nonceBits <- peekByteOff pParams (2 * ptrSize + wordSize)
          case (bitsToBytes ctrBits, bitsToBytes nonceBits) of
            (Just ctrLen, Just nonceLen) -> do
              mCtr <- chaseBytes pCtr ctrLen
              mNonce <- chaseBytes pNonce nonceLen
              pure (mCtr >>= \ctr -> mNonce >>= \nonce ->
                chachaStreamStructToCanonical ctr ctrBits nonce nonceBits)
            _ -> pure Nothing
    decodeChachaPolyNative :: IO (Maybe ByteString)
    decodeChachaPolyNative
      | paramsLen /= fromIntegral chachaPolyNativeSize = pure Nothing
      | otherwise = do
          pNonce <- peekByteOff pParams 0
          CULong nonceLen <- peekByteOff pParams ptrSize
          pAad <- peekByteOff pParams (ptrSize + wordSize)
          CULong aadLen <- peekByteOff pParams (2 * ptrSize + wordSize)
          mNonce <- chaseBytes pNonce nonceLen
          mAad <- chaseBytes pAad aadLen
          pure (mNonce >>= \nonce -> mAad >>= \aad ->
            chachaPolyStructToCanonical nonce nonceLen aad aadLen)
