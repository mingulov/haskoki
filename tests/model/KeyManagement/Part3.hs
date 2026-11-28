{- | KeyManagement Part 3: derivation.
-}
{-# LANGUAGE OverloadedStrings #-}
module KeyManagement.Part3
  ( childTmpl
  , deriveBase
  , runDerive
  , caseDeriveMulti
  , caseDeriveInvalidExtra
  , caseDeriveRejectsInvalidTargetDomain
  , caseDeriveFinishRejectsOffDomainMaterial
  , caseDeriveCodec
  , casePubPrivRsa
  , casePubPrivEc
  , casePubPrivEcSpkiStamp
  , casePubPrivEcFindByReadback
  , casePubPrivEcParamsCopy
  , casePubPrivRefusals
  , caseFinishWorkCause
  , caseHkdfInfoCodec
  ) where

import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import qualified Data.Map.Strict as Map
import Data.Maybe (isJust)
import Data.Word (Word64)
import Test.Tasty.HUnit (assertBool, assertEqual, assertFailure)
import Haskoki.Attribute
  ( AttributeType (..)
  , AttributeValue (..)
  )
import Haskoki.Attribute.Generated (mustKeyTypeId)
import Haskoki.Der ( ecPrivateDer, ecPublicDer)
import Haskoki.Model
  ( Model (..)
  , ObjectState (..)
  , SessionState
  )
import Haskoki.FFI.Standard (decodeNativeValue, ecParamsToWire, nativeFromCanonical)
import Haskoki.Object ( planFindObjects, planGetAttributes, resolveHandle)
import Haskoki.Operation.Derive
  ( decodeDeriveParams
  , decodeHkdfInfo
  , encodeDeriveParams
  , encodeHkdfInfo
  , hkdfDeriveMech
  , planDerive
  , pubPrivMech
  )
import Haskoki.Operation.Effect (CryptoCause (..), CryptoEffect (..), CryptoError (..), CryptoResult (..))
import Haskoki.Operation.KeyManagement
  ( KeyDeny (..)
  , KeyPlan (..)
  , PendingObject (..)
  , PendingWork (..)
  , ckkAes
  , ckkChacha20
  , ckkDes3
  , ckkDh
  , ckkDsa
  , ckkEc
  , ckkEcMontgomery
  , ckkGenericSecret
  , ckkMlKem
  , ckkRsa
  , ckkAesXts
  , ckkDes
  , ckkDes2
  , ckkCast128
  , ckkRc4
  , ckkBlowfish
  , ckkAria
  , ckkHkdf
  , ckkSha256Hmac
  , ckoData
  , ckoPrivateKey
  , ckoPublicKey
  , ckoSecretKey
  , finishWork
  , keyBytesOf
  , pendingFromAttrs
  )
import Haskoki.Outcome
  ( NativeOutput (..)
  , PlanResult (..)
  , PreparedCommit (..)
  , Rejection (..)
  , StateDelta (..)
  )
import Haskoki.Registry (MechanismId (..))
import Haskoki.Recipe.Kdf (encodePbkd2Params)
import Haskoki.Recipe.Sp800108 (encodeSp800Params)
import Haskoki.Recipe.ByteOps (encodeByteOpsParams)
import Haskoki.Recipe.Ssl3 (encodeSsl3KeyMatParams)
import Haskoki.Recipe.TlsKeyMat (encodeTlsKeyMatParams)
import Haskoki.Registry.Generated
  ( ckm_PKCS5_PBKD2
  , ckm_SHA1_KEY_DERIVATION
  , ckm_SHA256_KEY_DERIVATION
  )
import Haskoki.Request (FunctionId (..), OutputRegion (..))
import Haskoki.Rules (defaultRules)
import Haskoki.Transition (publishDelta)
import Haskoki.Types
  ( ExternalHandle (..)
  , ReturnCode (..)
  )
import KeyManagement.Fixtures
import KeyManagement.Part2Fixtures

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

-- | Derived key domain: every shared opaque derive path validates
-- the destination key domain before any effect. Well-formed but
-- incompatible type/length templates refuse
-- @CKR_TEMPLATE_INCONSISTENT@ (AES: 16\/24\/32 only; asymmetric
-- and unserved numeric types never publish as secret keys), valid
-- typed and generic controls plan, mechanism ceilings/defaults
-- keep their own codes and precedence (an off-domain length past
-- the family ceiling keeps the ceiling code), and one invalid
-- template refuses the whole batch. A refusal is a pure
-- 'KeyDenied' (no effect, no pending objects, no counters).
caseDeriveRejectsInvalidTargetDomain :: IO ()
caseDeriveRejectsInvalidTargetDomain = do
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
  let vendorKt = 0x80000123 :: Word64
      typed :: Word64 -> Word64 -> [(AttributeType, AttributeValue)]
      typed kt n =
        [ (AttrClass, ValULong ckoSecretKey)
        , (AttrKeyType, ValULong kt)
        , (AttrValueLen, ValULong n)
        , (AttrToken, ValBool False)
        ]
      typedNoLen kt = [a | a@(t, _) <- typed kt 1, t /= AttrValueLen]
      untyped n = [a | a@(t, _) <- typed 0 n, t /= AttrKeyType]
      untypedNoLen = [a | a@(t, _) <- untyped 1, t /= AttrValueLen]
      plan mech frame tmpls = planDerive defaultRules m1 st mech baseH
        (encodeDeriveParams frame tmpls)
      refuses label code p = case p of
        KeyDenied (KeyDeny c _) -> assertEqual (label ++ " code") code c
        other -> assertFailure (label ++ " must refuse: " ++ show other)
      plans label n p = case p of
        KeyEffect (PwDerive _ _) (FxDerive _ _ _ _ _ total) ->
          assertEqual (label ++ " total") n total
        other -> assertFailure (label ++ " must plan: " ++ show other)
      plansTyped label kt n p = case p of
        KeyEffect (PwDerive [po] [k]) _ -> do
          assertEqual (label ++ " length") n k
          assertEqual (label ++ " type") (Just (ValULong kt))
            (Map.lookup AttrKeyType (poAttrs po))
        other -> assertFailure (label ++ " must plan: " ++ show other)
      -- Shared-validator families (finish/checkOne): byte concat
      -- (natural 64), SHA-256 KDF (digest 32), HKDF, SP 800-108
      -- and PBKDF2 derive.
      families =
        [ ("concat", concatDataMech, encodeByteOpsParams 0 0 byteOpsD16)
        , ("sha256", MechanismId ckm_SHA256_KEY_DERIVATION, BS.empty)
        , ("hkdf", hkdfDeriveMech, encodeHkdfInfo 4 0x02 BS.empty "ac16")
        , ("sp800-108", sp800CounterMech
          , encodeSp800Params 4 32 32 BS.empty sp800Fixed)
        , ("pbkdf2", MechanismId ckm_PKCS5_PBKD2
          , encodePbkd2Params 4 1 "salt" BS.empty)
        ]
  mapM_ (\(name, mech, frame) -> do
    mapM_ (\n -> refuses (name ++ " AES/" ++ show n) CKR_TEMPLATE_INCONSISTENT
      (plan mech frame [typed ckkAes n])) [1, 15, 17, 20, 31]
    -- AES/33 is off-domain; past a family ceiling (SHA-256: the
    -- 32-byte digest) the family's sourced ceiling code wins.
    refuses (name ++ " AES/33") (if name == "sha256" then CKR_KEY_SIZE_RANGE
      else CKR_TEMPLATE_INCONSISTENT) (plan mech frame [typed ckkAes 33])
    mapM_ (\kt -> refuses (name ++ " SECRET_KEY/" ++ show kt)
      CKR_TEMPLATE_INCONSISTENT (plan mech frame [typed kt 16]))
      [ckkRsa, ckkEc, ckkDsa, ckkDh, ckkEcMontgomery, ckkMlKem, vendorKt]
    refuses (name ++ " SECRET_KEY/RSA without length") CKR_TEMPLATE_INCONSISTENT
      (plan mech frame [typedNoLen ckkRsa])
    mapM_ (\n -> plansTyped (name ++ " AES/" ++ show n) ckkAes (fromIntegral n)
      (plan mech frame [typed ckkAes n])) [16, 24, 32]
    plansTyped (name ++ " GENERIC/1") ckkGenericSecret 1
      (plan mech frame [typed ckkGenericSecret 1])
    plansTyped (name ++ " untyped/7") ckkGenericSecret 7
      (plan mech frame [untyped 7])
    -- AES has no single defined length: a missing length stays
    -- incomplete in every family.
    refuses (name ++ " AES without length") CKR_TEMPLATE_INCOMPLETE
      (plan mech frame [typedNoLen ckkAes])
    -- Zero keeps its pre-existing size code.
    refuses (name ++ " AES/0") CKR_KEY_SIZE_RANGE
      (plan mech frame [typed ckkAes 0])
    -- One invalid destination refuses the whole batch.
    refuses (name ++ " mixed batch") CKR_TEMPLATE_INCONSISTENT
      (plan mech frame [typed ckkAes 16, typed ckkAes 1]))
    families
  -- Mechanism defaults per family. Hash KDF and concat\/XOR follow
  -- PKCS#11: no type and no length gives a generic secret of the
  -- digest\/combined width; a typed target without a length takes
  -- its type's single defined length (DES 8, DES2 16, DES3 24) or
  -- refuses INCOMPLETE (AES, HMAC); a defined length past the
  -- digest width is a capacity error. HKDF keeps its hash-length
  -- generic default; its typed defaults are left unpinned.
  let sha1 = MechanismId ckm_SHA1_KEY_DERIVATION
      sha256 = MechanismId ckm_SHA256_KEY_DERIVATION
      concatD = plan concatDataMech (encodeByteOpsParams 0 0 byteOpsD16)
      xorD = plan xorMech (encodeByteOpsParams 0 0 (BS.pack [0 .. 47]))
  plans "concat untyped default" 64 (concatD [untypedNoLen])
  plans "xor untyped default" 48 (xorD [untypedNoLen])
  plans "hkdf untyped default" 32
    (plan hkdfDeriveMech (encodeHkdfInfo 4 0x02 BS.empty "ac16") [untypedNoLen])
  plansTyped "sha256 untyped default" ckkGenericSecret 32
    (plan sha256 BS.empty [untypedNoLen])
  plansTyped "sha1 untyped default" ckkGenericSecret 20
    (plan sha1 BS.empty [untypedNoLen])
  mapM_ (\(kt, d) -> do
    plansTyped ("concat " ++ show kt ++ " default") kt d (concatD [typedNoLen kt])
    plansTyped ("xor " ++ show kt ++ " default") kt d (xorD [typedNoLen kt])
    plansTyped ("sha256 " ++ show kt ++ " default") kt d
      (plan sha256 BS.empty [typedNoLen kt]))
    [(ckkDes, 8), (ckkDes2, 16), (ckkDes3, 24)]
  refuses "sha1 DES3 default past the digest" CKR_KEY_SIZE_RANGE
    (plan sha1 BS.empty [typedNoLen ckkDes3])
  refuses "concat HMAC without length" CKR_TEMPLATE_INCOMPLETE
    (concatD [typedNoLen ckkSha256Hmac])
  refuses "sha256 HMAC without length" CKR_TEMPLATE_INCOMPLETE
    (plan sha256 BS.empty [typedNoLen ckkSha256Hmac])
  refuses "sha256 GENERIC/33 ceiling" CKR_KEY_SIZE_RANGE
    (plan (MechanismId ckm_SHA256_KEY_DERIVATION) BS.empty
      [typed ckkGenericSecret 33])
  -- The served secret-key domains (algorithm sizes, not keygen
  -- frame caps): fixed, discrete and ranged types refuse off-domain
  -- lengths; variable-length types (generic, HMAC) take any length
  -- the mechanism yields (300 bytes is past every keygen cap).
  let hkdf tmpl = plan hkdfDeriveMech (encodeHkdfInfo 4 0x02 BS.empty "ac16") [tmpl]
  mapM_ (\(kt, good, bad) -> do
    plansTyped ("domain " ++ show kt ++ "/" ++ show good) kt
      (fromIntegral good) (hkdf (typed kt good))
    refuses ("domain " ++ show kt ++ "/" ++ show bad)
      CKR_TEMPLATE_INCONSISTENT (hkdf (typed kt bad)))
    [ (ckkDes, 8, 7), (ckkDes3, 24, 16), (ckkAesXts, 64, 48)
    , (ckkChacha20, 32, 16), (ckkCast128, 16, 17), (ckkBlowfish, 56, 3)
    , (ckkAria, 24, 20), (mustKeyTypeId "CKK_HOTP", 20, 15)
    , (ckkRc4, 256, 257)
    ]
  mapM_ (\kt -> plansTyped ("variable " ++ show kt) kt 300 (hkdf (typed kt 300)))
    [ckkGenericSecret, ckkSha256Hmac, ckkHkdf]
  -- Key-material rows (PwDeriveIv): the cipher-key outputs carry
  -- the template type with the params length, so the same domain
  -- applies; MAC outputs stay generic at any length.
  let keyMat kt = (AttrKeyType, ValULong kt)
        : [a | a@(t, _) <- keyMatKid, t /= AttrKeyType]
      tls key = encodeTlsKeyMatParams 4 20 key 16 keyMatCr keyMatSr
      ssl3 key = encodeSsl3KeyMatParams 16 key 16 ssl3Cr ssl3Sr
  mapM_ (\(name, mech, frame, mac) -> do
    case plan mech (frame 16) [keyMat ckkAes] of
      KeyEffect (PwDeriveIv pos lens _) _ -> do
        assertEqual (name ++ " lens") [mac, mac, 16, 16] lens
        assertEqual (name ++ " types")
          (map (Just . ValULong) [ckkGenericSecret, ckkGenericSecret, ckkAes, ckkAes])
          (map (Map.lookup AttrKeyType . poAttrs) pos)
      other -> assertFailure (name ++ " AES/16 must plan: " ++ show other)
    refuses (name ++ " AES/7 key") CKR_TEMPLATE_INCONSISTENT
      (plan mech (frame 7) [keyMat ckkAes])
    refuses (name ++ " RSA key") CKR_TEMPLATE_INCONSISTENT
      (plan mech (frame 16) [keyMat ckkRsa]))
    [ ("tls12 keymat", keyMat12Mech, tls, 20)
    , ("ssl3 keymat", ssl3KeyMatMech, ssl3, 16)
    ]

-- | Derived key domain, defense in depth: 'finishWork' checks the
-- final returned material of every derived secret against its
-- resolved type and declared length before publication, so
-- incoherent pending work (an injected wrong-sized split) cannot
-- create an invalid typed object. Refusals publish nothing and
-- write no outputs; coherent controls (secret and data objects)
-- publish. A real driver answer cut short by one byte (the shape a
-- short backend result takes on the SHA and byte-op paths, which
-- return the requested prefix) refuses through the answer-length
-- guard with an empty delta.
caseDeriveFinishRejectsOffDomainMaterial :: IO ()
caseDeriveFinishRejectsOffDomainMaterial = withSynth $ \answer -> do
  m <- seedModel
  st <- getSession m
  let secret kt n = pendingFromAttrs st (Map.fromList
        [ (AttrClass, ValULong ckoSecretKey)
        , (AttrKeyType, ValULong kt)
        , (AttrValueLen, ValULong n)
        , (AttrToken, ValBool False)
        ])
      dataObj n = pendingFromAttrs st (Map.fromList
        [ (AttrClass, ValULong ckoData)
        , (AttrValueLen, ValULong n)
        , (AttrToken, ValBool False)
        ])
      bytes n = BS.replicate n 0x5a
      refused label pw bs = case finishWork m st pw (GotBytes bs) of
        Reject r -> do
          assertEqual (label ++ " code") CKR_TEMPLATE_INCONSISTENT (rejCode r)
          assertEqual (label ++ " empty delta") (StateDelta []) (rejDelta r)
          assertEqual (label ++ " no outputs") 0 (length (rejOutputs r))
        other -> assertFailure (label ++ " must refuse: " ++ show other)
      published label n pw bs = case finishWork m st pw (GotBytes bs) of
        Immediate c -> assertEqual (label ++ " handles") n
          (length [() | NativeOutput (RegionHandle _) _ <- pcOutputs c])
        other -> assertFailure (label ++ " must publish: " ++ show other)
  published "AES/16 control" 1 (PwDerive [secret ckkAes 16] [16]) (bytes 16)
  (m1, baseH) <- plantKey m st
    [ (AttrClass, ValULong ckoSecretKey)
    , (AttrKeyType, ValULong ckkGenericSecret)
    , (AttrToken, ValBool False)
    , (AttrDerive, ValBool True)
    ] "abc"
  case planDerive defaultRules m1 st (MechanismId ckm_SHA256_KEY_DERIVATION) baseH
      (encodeDeriveParams BS.empty
        [ [ (AttrClass, ValULong ckoSecretKey)
          , (AttrKeyType, ValULong ckkAes)
          , (AttrValueLen, ValULong 16)
          , (AttrToken, ValBool False)
          ] ]) of
    KeyEffect pw fx -> do
      res <- answer m1 fx
      case res of
        GotBytes full -> do
          assertEqual "driver answer width" 16 (BS.length full)
          case finishWork m1 st pw (GotBytes (BS.take 15 full)) of
            Reject r -> do
              assertEqual "short answer code" CKR_GENERAL_ERROR (rejCode r)
              assertEqual "short answer empty delta" (StateDelta []) (rejDelta r)
              assertEqual "short answer no outputs" 0 (length (rejOutputs r))
            other -> assertFailure ("short answer must refuse: " ++ show other)
        other -> assertFailure ("driver must answer bytes: " ++ show other)
    other -> assertFailure ("SHA-256 AES/16 must plan: " ++ show other)
  published "data control" 1 (PwDerive [dataObj 5] [5]) (bytes 5)
  refused "AES/1" (PwDerive [secret ckkAes 1] [1]) (bytes 1)
  refused "AES/33" (PwDerive [secret ckkAes 33] [33]) (bytes 33)
  refused "SECRET_KEY/RSA" (PwDerive [secret ckkRsa 16] [16]) (bytes 16)
  refused "declared 16, answered 24" (PwDerive [secret ckkAes 16] [24]) (bytes 24)
  refused "mixed split" (PwDerive [secret ckkAes 16, secret ckkAes 16] [15, 17])
    (bytes 32)
  published "keymat control" 4
    (PwDeriveIv [secret ckkGenericSecret 20, secret ckkGenericSecret 20
      , secret ckkAes 16, secret ckkAes 16] [20, 20, 16, 16] (16, 16))
    (bytes 104)
  refused "keymat AES/7"
    (PwDeriveIv [secret ckkGenericSecret 20, secret ckkGenericSecret 20
      , secret ckkAes 7, secret ckkAes 7] [20, 20, 7, 7] (16, 16))
    (bytes 86)

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

casePubPrivEcFindByReadback :: IO ()
casePubPrivEcFindByReadback = do
  m0 <- seedModel >>= loginUser
  st <- getSession m0
  let oid = hex "06082a8648ce3d030107"
      point = BS.pack (0x04 : [1 .. 64])
      spki = ecPublicDer oid point
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
      Just ost <- pure (resolveHandle m2 h)
      assertEqual "stored params stay OID"
        (Just (ValBytes oid)) (Map.lookup AttrEcParams (osAttrs ost))
      canon <- case planGetAttributes m2 st h [AttrEcParams] of
        Immediate pc -> case pcOutputs pc of
          [o] -> pure (outBytes o)
          _ -> assertFailure "params read outputs arity" >> undefined
        Reject rej -> assertFailure ("params read rejected: " ++ show (rejCode rej)) >> undefined
        Execute _ _ -> assertFailure "params read must not execute" >> undefined
      wire <- case nativeFromCanonical AttrEcParams canon of
        Just w -> pure w
        Nothing -> assertFailure "params wire undecodable" >> undefined
      assertEqual "wire stays the OID" oid wire
      assertEqual "wire mapping emits the OID" oid (ecParamsToWire "P-256")
      tmplVal <- case decodeNativeValue AttrEcParams wire of
        Just v -> pure v
        Nothing -> assertFailure "params template undecodable" >> undefined
      assertEqual "template decodes to the curve name" (ValBytes "P-256") tmplVal
      hits <- case planFindObjects m2 st
        [ (AttrClass, ValULong ckoPublicKey)
        , (AttrKeyType, ValULong ckkEc)
        , (AttrEcParams, tmplVal)
        ] of
        Immediate fc -> mapM handleOf (pcOutputs fc)
        Reject rej -> assertFailure ("find rejected: " ++ show (rejCode rej)) >> undefined
        Execute _ _ -> assertFailure "find must not execute" >> undefined
      assertEqual "find by read-back params hits" [h] hits
    other -> assertFailure ("pubpriv plan is not an effect: " ++ show other)

casePubPrivEcParamsCopy :: IO ()
casePubPrivEcParamsCopy = withSynth $ \answer -> do
  m0 <- seedModel >>= loginUser
  st <- getSession m0
  -- The base carries the engine name, not the OID: with an opaque
  -- answer (no SPKI stamp) the derived key carries the copy
  -- verbatim, proving the copy lands and no stamp rewrote it.
  -- A caller-supplied value wins over the copy.
  let baseT =
        [ (AttrClass, ValULong ckoPrivateKey)
        , (AttrKeyType, ValULong ckkEc)
        , (AttrEcParams, ValBytes "P-256")
        , (AttrToken, ValBool False)
        ]
      derive m h tmpl = case planDerive defaultRules m st pubPrivMech h (encodeDeriveParams BS.empty [tmpl]) of
        KeyEffect pw fx -> do
          res <- answer m fx
          c <- finishCommit m st pw res 1
          h2 <- handleOf (pcOutputs c !! 0)
          m' <- expectRight (publishDelta m (pcDelta c))
          pure (m', h2)
        other -> assertFailure ("pubpriv plan is not an effect: " ++ show other) >> undefined
      omitT =
        [ (AttrClass, ValULong ckoPublicKey)
        , (AttrKeyType, ValULong ckkEc)
        , (AttrToken, ValBool False)
        ]
      callerT =
        [ (AttrClass, ValULong ckoPublicKey)
        , (AttrKeyType, ValULong ckkEc)
        , (AttrEcParams, ValBytes "P-384")
        , (AttrToken, ValBool False)
        ]
  (m1, privH) <- plantKey m0 st baseT pubPrivSec1P256
  (m2, hCopy) <- derive m1 privH omitT
  Just copied <- pure (resolveHandle m2 hCopy)
  assertEqual "params copied from base" (Just (ValBytes "P-256"))
    (Map.lookup AttrEcParams (osAttrs copied))
  (m3, privH2) <- plantKey m2 st baseT pubPrivSec1P256
  (m4, hCaller) <- derive m3 privH2 callerT
  Just callerWon <- pure (resolveHandle m4 hCaller)
  assertEqual "caller params win over the copy" (Just (ValBytes "P-384"))
    (Map.lookup AttrEcParams (osAttrs callerWon))

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
  assertEqual "class code" CKR_KEY_TYPE_INCONSISTENT c4
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

caseFinishWorkCause :: IO ()
caseFinishWorkCause = do
  m0 <- seedModel
  st <- getSession m0
  let pw = PwDerive [] []
  -- A kept failure through the key finisher carries its cause.
  case finishWork m0 st pw (GotCryptoError (CryptoNative "op" 7 "why")) of
    Reject rej -> do
      assertEqual "kept code" CKR_GENERAL_ERROR (rejCode rej)
      assertEqual "kept cause"
        (Just (CryptoCause F_DeriveKey (CryptoNative "op" 7 "why"))) (rejCause rej)
    other -> fail ("expected rejection, got: " ++ show other)
  -- A distinct cell carries no cause.
  case finishWork m0 st pw (GotCryptoError (CryptoBadKey "op" "why")) of
    Reject rej -> do
      assertEqual "distinct code" CKR_KEY_TYPE_INCONSISTENT (rejCode rej)
      assertEqual "distinct no cause" Nothing (rejCause rej)
    other -> fail ("expected rejection, got: " ++ show other)

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
