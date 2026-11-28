{- | KeyManagement Part 4: decaps, wrap mismatch and init.
-}
{-# LANGUAGE OverloadedStrings #-}
module KeyManagement.Part4
  ( runEncaps
  , caseKemDecaps
  , caseKemMismatch
  , caseWrapMismatch
  , caseWrapKeyTypeGate
  , caseAuthWrapMismatch
  , caseInitFromObject
  , caseAttrsLand
  ) where

import Data.Bits (complement)
import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import qualified Data.Map.Strict as Map
import Test.Tasty.HUnit (assertEqual, assertFailure)
import Haskoki.Attribute
  ( AttributeType (..)
  , AttributeValue (..)
  )
import Haskoki.Model
  ( Model (..)
  , ObjectState (..)
  , SessionState
  )
import Haskoki.Object (resolveHandle)
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
  ( encodeDeriveParams
  , encodeHkdfInfo
  )
import Haskoki.Operation.Effect (CryptoEffect (..), CryptoResult (..))
import Haskoki.Operation.Kem
  ( KemAlg (..)
  , kemCtLen
  , mlKemMech
  , planKemDecaps
  , planKemEncaps
  )
import Haskoki.Operation.KeyManagement
  ( KeyDeny (..)
  , KeyPlan (..)
  , aesCbcMech
  , ckkAes
  , ckkGenericSecret
  , ckkRsa
  , ckoPrivateKey
  , ckoSecretKey
  , ecKeyPairGenMech
  , finishWork
  , keyBytesOf
  , pendingFromAttrs
  , planAuthUnwrapKey
  , planAuthWrapKey
  , planGenerateKeyPair
  , planUnwrapKey
  , policyFromObject
  , planWrapKey
  , publishPending
  )
import Haskoki.Outcome
  ( NativeOutput (..)
  , PlanResult (..)
  , PreparedCommit (..)
  , Rejection (..)
  , StateDelta (..)
  )
import Haskoki.Registry (Operation (..), curatedRegistry, mkCapabilities)
import Haskoki.Request (OutputIntent (..), OutputRegion (..))
import Haskoki.Rules (defaultRules)
import Haskoki.Transition (publishDelta)
import Haskoki.Types
  ( ExternalHandle (..)
  , ReturnCode (..)
  )
import KeyManagement.Fixtures
import KeyManagement.Part2Fixtures
import KeyManagement.Part3

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
    , (AttrDerive, ValBool True)
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
  -- true at keygen, Derive is explicit here since it defaults
  -- false; the explicit Decrypt=false stays out, as do
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
