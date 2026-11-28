{- | KeyManagement Part 6: key-output codecs and PBE.
-}
{-# LANGUAGE OverloadedStrings #-}
module KeyManagement.Part6
  ( caseHandleWriteback
  , caseWrappedWriteback
  , caseCiphertextWriteback
  , caseKeyInputDecode
  , pbeDes3Mech
  , pbeDes2Mech
  , pbeSha1Cast128Mech
  , pbeSha1Rc4_128Mech
  , pbeSha1Rc4_40Mech
  , pbeSha1Rc2_128Mech
  , pbeSha1Rc2_40Mech
  , pbeMd5DesMech
  , pbeMd5CastMech
  , pbeMd5Cast3Mech
  , pbeMd5Cast128Mech
  , pbePw
  , pbeSalt
  , casePbePlans
  , caseRealPbeVector
  , caseRealPbeSha1Vector
  , caseRealPbeMd5Vector
  ) where

import qualified Data.ByteString as BS
import qualified Data.Map.Strict as Map
import Data.Word (Word64, Word8)
import Foreign.Marshal.Alloc (allocaBytes)
import Foreign.Marshal.Array (pokeArray)
import Foreign.Ptr (Ptr, nullPtr)
import Test.Tasty.HUnit (assertBool, assertEqual, assertFailure)
import Haskoki.Attribute
  ( AttributeType (..)
  , AttributeValue (..)
  )
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
  )
import Haskoki.Operation.Effect (CryptoEffect (..))
import Haskoki.Operation.KeyManagement
  ( GenArgs (..)
  , KeyDeny (..)
  , KeyPlan (..)
  , PendingWork (..)
  , ckkAes
  , ckkDes3
  , ckkDes
  , ckkDes2
  , ckkCast
  , ckkCast3
  , ckkCast128
  , ckkRc2
  , ckkRc4
  , ckoSecretKey
  , decodeGenArgs
  , keyBytesOf
  , keyPairCompatible
  , planGenerateKey
  )
import Haskoki.Outcome
  ( NativeOutput (..)
  , PreparedCommit (..)
  )
import Haskoki.Output (OutputPlan (..), TypedWrite (..), WritePayload (..))
import Haskoki.Registry (MechanismId (..))
import Haskoki.Recipe.Pbe (encodePbeParams, maxPbeIters)
import Haskoki.Registry.Generated
  ( ckm_PBE_SHA1_DES3_EDE_CBC
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
  )
import Haskoki.Request (OutputIntent (..), OutputRegion (..))
import Haskoki.Rules (defaultRules)
import Haskoki.Transition (publishDelta)
import Haskoki.Types
  ( ExternalHandle (..)
  , ReturnCode (..)
  )
import KeyManagement.Fixtures

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
