{- | Snapshot laws: save/restore roundtrips over generated staged
outputs, buffered slots, cipher slots, sign\/verify\/decrypt\/
recover\/message slots, and the live-stream refusal — generalizing
the SnapshotSpec precedent cases.
-}
{-# LANGUAGE OverloadedStrings #-}
module SnapshotProps (spec) where

import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import qualified Data.Map.Strict as Map
import Data.Word (Word64)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertBool, assertEqual, assertFailure, testCase)

import Gen (lcgBytes)
import Haskoki.Attribute (AttributeType (..), AttributeValue (..))
import Haskoki.Model
  ( HandleBinding (..)
  , Model (..)
  , ObjectState (..)
  , SessionState (..)
  , emptyModel
  )
import Haskoki.Operation
  ( ActiveOp
  , CipherSpec (..)
  , CryptoResult (..)
  , DigestStream (..)
  , InitArgs (..)
  , InitOutcome (..)
  , KeyPolicy (..)
  , MsgFamily (..)
  , MsgInner (..)
  , MsgState (..)
  , OpAuth (..)
  , OpEnv (..)
  , RecoverRole (..)
  , RecoverSpec (..)
  , SlotCommon
  , SlotKind (..)
  , StepDeny (..)
  , StepOutcome (..)
  , activeDigest
  , dualOf
  , emptySessionOps
  , initDualOperation
  , initOperation
  , insertOp
  , lookupSingle
  , maxBuffered
  , mkActiveDigest
  , mkActiveMessage
  , mkActiveRecover
  , mkActiveSign
  , mkActiveVerify
  , mkSlotCommon
  , msgFamilyKind
  , msgOperation
  , setBuffered
  , setLive
  , validateOperationIn
  )
import Haskoki.Operation.Cipher (planCipherFinal, planCipherUpdate)
import Haskoki.Operation.Digest (finishDigest, planDigestOneShot)
import Haskoki.Operation.Dual (planDualUpdate)
import Haskoki.Operation.Signature (planSignRecoverOneShot)
import Haskoki.Registry
  ( MechanismId (..)
  , Operation (..)
  , curatedRegistry
  , mkCapabilities
  )
import Haskoki.Request (OutputIntent (..))
import Haskoki.Session (SessionLogin (..))
import Haskoki.Snapshot
  ( RestoreError (..)
  , RestoreKeys (..)
  , SaveError (SaveEmpty, SaveStreamLive)
  , SaveTarget (..)
  , defaultQuotas
  , restoreCode
  , restoreOperation
  , saveOperation
  )
import Haskoki.Types
  ( EngineResourceId (..)
  , ExternalHandle (..)
  , Generation (..)
  , ObjectId (..)
  , Pkcs11Version (..)
  , ReturnCode (..)
  , Revision (..)
  , SessionId (..)
  , SlotId (..)
  )

spec :: Int -> TestTree
spec count =
  testGroup
    "snapshot laws"
    [ testCase "staged outputs roundtrip" (caseStaged count)
    , testCase "small outputs free the slot" caseFreedSmall
    , testCase "max staged output roundtrips" caseMaxStaged
    , testCase "buffered slots roundtrip" (caseBuffered count)
    , testCase "cipher slots roundtrip" (caseCipher count)
    , testCase "dual slots roundtrip" (caseDual count)
    , testCase "sign slots roundtrip" (caseSign count)
    , testCase "verify slots roundtrip" (caseVerify count)
    , testCase "decrypt slots roundtrip" (caseDecrypt count)
    , testCase "cipher pad values cover 0x00 and 0x01" caseCipherPadCoverage
    , testCase "padded decrypt slots roundtrip" (caseDecryptPadded count)
    , testCase "recover slots roundtrip" (caseRecover count)
    , testCase "message slots roundtrip" (caseMessage count)
    , testCase "cipher geometry mutations reject" (caseCipherGeometryRejects count)
    , testCase "recover geometry mutations reject" (caseRecoverGeometryRejects count)
    , testCase "live stream refuses save" caseStreamLive
    , testCase "preflight admits exactly within-bound pairs" (casePreflight count)
    ]

-- ---------------------------------------------------------------------------
-- Fixtures (mirroring SnapshotSpec)
-- ---------------------------------------------------------------------------

sha256Mech :: MechanismId
sha256Mech = MechanismId 0x250

testSlot :: SlotId
testSlot = SlotId 7

testEnv :: OpEnv
testEnv =
  OpEnv
    { oeRegistry = curatedRegistry
    , oeCaps = mkCapabilities [(sha256Mech, OpDigest)]
    , oeModel = emptyModel
    }

digestArgs :: InitArgs
digestArgs =
  InitArgs
    { iaOp = OpDigest
    , iaMech = sha256Mech
    , iaParams = BS.empty
    , iaKey = Nothing
    , iaCipher = Nothing
    , iaRecover = Nothing
    }

mkSession :: SessionId -> SessionState
mkSession sid =
  SessionState
    { ssId = sid
    , ssSlot = testSlot
    , ssRevision = Revision 1
    , ssGeneration = Generation 1
    , ssReadOnly = False
    , ssLogin = LoginPublic
    , ssOps = emptySessionOps
    }

aesCbcMech :: MechanismId
aesCbcMech = MechanismId 0x1082

keyHandle :: ExternalHandle
keyHandle = ExternalHandle 3

modelWithAesKey :: Model
modelWithAesKey =
  let ost =
        ObjectState
          { osId = ObjectId 9
          , osRevision = Revision 1
          , osGeneration = Generation 1
          , osAttrs =
              Map.fromList
                [ (AttrClass, ValULong 4)
                , (AttrKeyType, ValULong 0x1F)
                , (AttrPrivate, ValBool False)
                , (AttrEncrypt, ValBool True)
                , (AttrDecrypt, ValBool True)
                , (AttrValue, ValBytes "0123456789abcdef0123456789abcdef")
                ]
          , osOwner = Nothing
          , osSlot = testSlot
          }
  in emptyModel
        { mObjects = Map.singleton (ObjectId 9) ost
        , mHandles =
            Map.singleton keyHandle (HandleBinding (ObjectId 9) (Generation 1))
        }

cipherEnv :: OpEnv
cipherEnv =
  OpEnv
    { oeRegistry = curatedRegistry
    , oeCaps = mkCapabilities [(aesCbcMech, OpEncrypt)]
    , oeModel = modelWithAesKey
    }

encryptArgs :: InitArgs
encryptArgs =
  InitArgs
    { iaOp = OpEncrypt
    , iaMech = aesCbcMech
    , iaParams = "0123456789abcdef"
    , iaKey = Just (KeyPolicy keyHandle [OpEncrypt] False)
    , iaCipher = Just (CipherSpec 16 False)
    , iaRecover = Nothing
    }

otherHandle :: ExternalHandle
otherHandle = ExternalHandle 4

-- | Model holding two AES keys with distinct material (handles 3+4).
modelWithTwoKeys :: Model
modelWithTwoKeys =
  let mkKey oid mat =
        ObjectState
          { osId = oid
          , osRevision = Revision 1
          , osGeneration = Generation 1
          , osAttrs =
              Map.fromList
                [ (AttrClass, ValULong 4)
                , (AttrKeyType, ValULong 0x1F)
                , (AttrPrivate, ValBool False)
                , (AttrEncrypt, ValBool True)
                , (AttrDecrypt, ValBool True)
                , (AttrValue, ValBytes mat)
                ]
          , osOwner = Nothing
          , osSlot = testSlot
          }
      ost1 = mkKey (ObjectId 9) "0123456789abcdef0123456789abcdef"
      ost2 = mkKey (ObjectId 10) "fedcba9876543210fedcba9876543210"
  in emptyModel
        { mObjects = Map.fromList [(ObjectId 9, ost1), (ObjectId 10, ost2)]
        , mHandles =
            Map.fromList
              [ (keyHandle, HandleBinding (ObjectId 9) (Generation 1))
              , (otherHandle, HandleBinding (ObjectId 10) (Generation 1))
              ]
        }

dualEnv :: OpEnv
dualEnv =
  OpEnv
    { oeRegistry = curatedRegistry
    , oeCaps =
        mkCapabilities
          [(sha256Mech, OpDigest), (aesCbcMech, OpEncrypt)]
    , oeModel = modelWithTwoKeys
    }

-- ---------------------------------------------------------------------------
-- Digest helpers
-- ---------------------------------------------------------------------------

-- | Init a digest; fails the test on any denial.
initDigest :: SessionState -> IO SessionState
initDigest st = do
  let (ops1, out1) = initOperation testEnv (ssOps st) st digestArgs
  assertEqual "init code" CKR_OK (ioCode out1)
  pure st { ssOps = ops1 }

-- | Finish a one-shot with canned digest bytes under a short intent,
-- requiring the staged disposition; returns the staged session.
finishStaged :: SessionState -> ByteString -> IO SessionState
finishStaged st canned = do
  let (ops1, _, oneOut) = planDigestOneShot (ssOps st) st "digest" "hello"
  assertEqual "one-shot code" CKR_OK (soCode oneOut)
  let (ops2, shortOut) =
        finishDigest ops1 SlotDigest "digest" (GotBytes canned) (IntentBuffer 2)
  assertEqual "staged code" CKR_BUFFER_TOO_SMALL (soCode shortOut)
  pure st { ssOps = ops2 }

-- | Save a digest slot and restore it into a fresh session; the slot
-- must roundtrip exactly.
roundtripDigest :: SessionState -> IO ()
roundtripDigest stA = do
  bytes <- case saveOperation defaultQuotas emptyModel stA Pkcs11_3_2 (SaveSlot SlotDigest) of
    Left err -> assertFailure ("save failed: " ++ show err) >> undefined
    Right b -> pure b
  stB <- case restoreOperation defaultQuotas emptyModel
    (mkSession (SessionId 2)) Pkcs11_3_2 (RestoreSingle Nothing) bytes of
    Left err -> assertFailure ("restore failed: " ++ show err) >> undefined
    Right s -> pure s
  assertEqual "restored slot equals saved slot"
    (lookupSingle (ssOps stA) SlotDigest)
    (lookupSingle (ssOps stB) SlotDigest)

-- | Staged outputs over generated bytes (sizes 3..64, always staged
-- under the 2-byte intent) roundtrip exactly.
caseStaged :: Int -> IO ()
caseStaged count = mapM_ check [1 .. fromIntegral count]
  where
    check :: Word64 -> IO ()
    check seed = do
      let size = 3 + fromIntegral (seed `mod` 62)
          canned = lcgBytes seed size
      stA <- initDigest (mkSession (SessionId 1)) >>= \st -> finishStaged st canned
      roundtripDigest stA

-- | Outputs that fit the intent free the slot (nothing staged), so
-- the empty slot refuses to save with the documented error.
caseFreedSmall :: IO ()
caseFreedSmall = mapM_ check [0, 1, 2]
  where
    check :: Int -> IO ()
    check size = do
      stA <- initDigest (mkSession (SessionId 1))
      let (ops1, _, oneOut) = planDigestOneShot (ssOps stA) stA "digest" "hello"
      assertEqual "one-shot code" CKR_OK (soCode oneOut)
      let (ops2, finOut) =
            finishDigest ops1 SlotDigest "digest"
              (GotBytes (BS.replicate size 0xAB)) (IntentBuffer 2)
      assertEqual ("finish code size=" ++ show size) CKR_OK (soCode finOut)
      assertEqual ("slot freed size=" ++ show size) Nothing
        (lookupSingle ops2 SlotDigest)
      assertEqual ("save empty size=" ++ show size)
        (Left (SaveEmpty SlotDigest))
        (saveOperation defaultQuotas emptyModel (stA { ssOps = ops2 })
          Pkcs11_3_2 (SaveSlot SlotDigest))

-- | The documented max bound stages and roundtrips (single case).
caseMaxStaged :: IO ()
caseMaxStaged = do
  stA <- initDigest (mkSession (SessionId 1))
    >>= \st -> finishStaged st (BS.replicate maxBuffered 0xAB)
  roundtripDigest stA

-- ---------------------------------------------------------------------------
-- Buffered + cipher slots
-- ---------------------------------------------------------------------------

-- | A legacy buffered digest slot over generated bytes roundtrips.
caseBuffered :: Int -> IO ()
caseBuffered count = mapM_ check [1 .. fromIntegral count]
  where
    check :: Word64 -> IO ()
    check seed = do
      let size = fromIntegral (seed `mod` 65)
          part = lcgBytes seed size
      st0 <- initDigest (mkSession (SessionId 1))
      case lookupSingle (ssOps st0) SlotDigest of
        Just active -> case activeDigest active of
          Just sc -> do
            let stA = st0
                  { ssOps = insertOp
                      (mkActiveDigest (setBuffered part sc)) (ssOps st0)
                  }
            roundtripDigest stA
          Nothing -> assertFailure "digest slot missing after init"
        Nothing -> assertFailure "digest slot missing after init"

-- | A keyed cipher slot buffering generated bytes roundtrips with
-- its key binding intact.
caseCipher :: Int -> IO ()
caseCipher count = mapM_ check [1 .. fromIntegral count]
  where
    check :: Word64 -> IO ()
    check seed = do
      let size = fromIntegral (seed `mod` 65)
          part = lcgBytes seed size
          stA0 = mkSession (SessionId 1)
          (ops1, out1) = initOperation cipherEnv (ssOps stA0) stA0 encryptArgs
      assertEqual "init code" CKR_OK (ioCode out1)
      let stA1 = stA0 { ssOps = ops1 }
          (ops2, stA2, stepU) = planCipherUpdate ops1 stA1 SlotEncrypt part Nothing
      assertEqual "update code" CKR_OK (soCode stepU)
      let stA = stA2 { ssOps = ops2 }
      bytes <- case saveOperation defaultQuotas modelWithAesKey stA
        Pkcs11_3_2 (SaveSlot SlotEncrypt) of
        Left err -> assertFailure ("save failed: " ++ show err) >> undefined
        Right b -> pure b
      stB <- case restoreOperation defaultQuotas modelWithAesKey
        (mkSession (SessionId 2)) Pkcs11_3_2 (RestoreSingle (Just keyHandle)) bytes of
        Left err -> assertFailure ("restore failed: " ++ show err) >> undefined
        Right s -> pure s
      assertEqual "restored slot equals saved slot"
        (lookupSingle (ssOps stA) SlotEncrypt)
        (lookupSingle (ssOps stB) SlotEncrypt)

-- | A dual operation buffering a generated stream roundtrips with
-- both sides and the cipher key binding intact.
caseDual :: Int -> IO ()
caseDual count = mapM_ check [1 .. fromIntegral count]
  where
    check :: Word64 -> IO ()
    check seed = do
      let size = fromIntegral (seed `mod` 65)
          part = lcgBytes seed size
          stA0 = mkSession (SessionId 1)
          (ops1, out1) =
            initDualOperation dualEnv (ssOps stA0) stA0 digestArgs encryptArgs
      assertEqual "init code" CKR_OK (ioCode out1)
      let (ops2, stA2, stepU) =
            planDualUpdate ops1 (stA0 { ssOps = ops1 }) part
      assertEqual "update code" CKR_OK (soCode stepU)
      let stA = stA2 { ssOps = ops2 }
      bytes <- case saveOperation defaultQuotas modelWithTwoKeys stA
        Pkcs11_3_2 SaveDual of
        Left err -> assertFailure ("save failed: " ++ show err) >> undefined
        Right b -> pure b
      stB <- case restoreOperation defaultQuotas modelWithTwoKeys
        (mkSession (SessionId 2)) Pkcs11_3_2
        (RestoreDual Nothing (Just keyHandle)) bytes of
        Left err -> assertFailure ("restore failed: " ++ show err) >> undefined
        Right s -> pure s
      assertEqual "restored dual equals saved dual"
        (dualOf (ssOps stA))
        (dualOf (ssOps stB))

-- ---------------------------------------------------------------------------
-- Sign / verify / decrypt / recover / message slots
-- ---------------------------------------------------------------------------

hmacSha256Mech :: MechanismId
hmacSha256Mech = MechanismId 0x251

rsaX509Mech :: MechanismId
rsaX509Mech = MechanismId 0x3

-- | A keyed slot state over caller bytes, bound to the AES fixture
-- key (ObjectId 9): the codec input for the init-free roundtrips
-- (sign\/verify\/recover\/message), mirroring the caseCipher key
-- binding without re-running init validation (the property under
-- test is save\/restore, not init).
mkKeyedCommon :: MechanismId -> Operation -> ByteString -> SlotCommon
mkKeyedCommon mech op buf =
  setBuffered buf (mkSlotCommon mech op (Just (ObjectId 9)) BS.empty AuthNone)

-- | Save one keyed slot and restore it into a fresh session with
-- the fixture key handle; the slot must roundtrip exactly.
roundtripKeyed :: SlotKind -> ActiveOp -> IO ()
roundtripKeyed kind active = do
  let stA = (mkSession (SessionId 1))
        { ssOps = insertOp active emptySessionOps }
  bytes <- case saveOperation defaultQuotas modelWithAesKey stA
    Pkcs11_3_2 (SaveSlot kind) of
    Left err -> assertFailure ("save failed: " ++ show err) >> undefined
    Right b -> pure b
  stB <- case restoreOperation defaultQuotas modelWithAesKey
    (mkSession (SessionId 2)) Pkcs11_3_2 (RestoreSingle (Just keyHandle)) bytes of
    Left err -> assertFailure ("restore failed: " ++ show err) >> undefined
    Right s -> pure s
  assertEqual "restored slot equals saved slot"
    (lookupSingle (ssOps stA) kind)
    (lookupSingle (ssOps stB) kind)

-- | A keyed sign slot buffering generated bytes roundtrips (tag 1).
caseSign :: Int -> IO ()
caseSign count = mapM_ check [1 .. fromIntegral count]
  where
    check :: Word64 -> IO ()
    check seed = do
      let size = fromIntegral (seed `mod` 65)
          part = lcgBytes seed size
      roundtripKeyed SlotSign
        (mkActiveSign (mkKeyedCommon hmacSha256Mech OpSign part))

-- | A keyed verify slot buffering generated bytes roundtrips (tag 2).
caseVerify :: Int -> IO ()
caseVerify count = mapM_ check [1 .. fromIntegral count]
  where
    check :: Word64 -> IO ()
    check seed = do
      let size = fromIntegral (seed `mod` 65)
          part = lcgBytes seed size
      roundtripKeyed SlotVerify
        (mkActiveVerify (mkKeyedCommon hmacSha256Mech OpVerify part))

decryptEnv :: OpEnv
decryptEnv =
  OpEnv
    { oeRegistry = curatedRegistry
    , oeCaps = mkCapabilities [(aesCbcMech, OpDecrypt)]
    , oeModel = modelWithAesKey
    }

decryptArgs :: InitArgs
decryptArgs =
  encryptArgs
    { iaOp = OpDecrypt
    , iaKey = Just (KeyPolicy keyHandle [OpDecrypt] False)
    }

aesCbcPadMech :: MechanismId
aesCbcPadMech = MechanismId 0x1085

decryptPadEnv :: OpEnv
decryptPadEnv =
  OpEnv
    { oeRegistry = curatedRegistry
    , oeCaps = mkCapabilities [(aesCbcPadMech, OpDecrypt)]
    , oeModel = modelWithAesKey
    }

decryptPadArgs :: InitArgs
decryptPadArgs =
  decryptArgs
    { iaMech = aesCbcPadMech
    , iaCipher = Just (CipherSpec 16 True)
    }

-- | A keyed decrypt slot buffering generated bytes roundtrips with
-- its key binding intact (tag 4, DirDecrypt) — the caseCipher
-- mirror on the decrypt direction.
caseDecrypt :: Int -> IO ()
caseDecrypt count = mapM_ check [1 .. fromIntegral count]
  where
    check :: Word64 -> IO ()
    check seed = do
      let size = fromIntegral (seed `mod` 65)
          part = lcgBytes seed size
          stA0 = mkSession (SessionId 1)
          (ops1, out1) = initOperation decryptEnv (ssOps stA0) stA0 decryptArgs
      assertEqual "init code" CKR_OK (ioCode out1)
      let stA1 = stA0 { ssOps = ops1 }
          (ops2, stA2, stepU) = planCipherUpdate ops1 stA1 SlotDecrypt part Nothing
      assertEqual "update code" CKR_OK (soCode stepU)
      let stA = stA2 { ssOps = ops2 }
      bytes <- case saveOperation defaultQuotas modelWithAesKey stA
        Pkcs11_3_2 (SaveSlot SlotDecrypt) of
        Left err -> assertFailure ("save failed: " ++ show err) >> undefined
        Right b -> pure b
      stB <- case restoreOperation defaultQuotas modelWithAesKey
        (mkSession (SessionId 2)) Pkcs11_3_2 (RestoreSingle (Just keyHandle)) bytes of
        Left err -> assertFailure ("restore failed: " ++ show err) >> undefined
        Right s -> pure s
      assertEqual "restored slot equals saved slot"
        (lookupSingle (ssOps stA) SlotDecrypt)
        (lookupSingle (ssOps stB) SlotDecrypt)

-- ---------------------------------------------------------------------------
-- ActiveCipher pad-bit coverage
-- ---------------------------------------------------------------------------

-- | Save one cipher slot through init + update; returns the raw
-- snapshot bytes so the probe can read the tag-4 pad byte (the
-- trailing byte of a cipher save: dirB, block u32, then padB).
saveCipherBytes :: OpEnv -> InitArgs -> SlotKind -> IO ByteString
saveCipherBytes env args kind = do
  let stA0 = mkSession (SessionId 1)
      (ops1, out1) = initOperation env (ssOps stA0) stA0 args
  assertEqual "init code" CKR_OK (ioCode out1)
  let stA1 = stA0 { ssOps = ops1 }
      (ops2, stA2, stepU) = planCipherUpdate ops1 stA1 kind "probe-part" Nothing
  assertEqual "update code" CKR_OK (soCode stepU)
  case saveOperation defaultQuotas modelWithAesKey (stA2 { ssOps = ops2 })
    Pkcs11_3_2 (SaveSlot kind) of
    Left err -> assertFailure ("save failed: " ++ show err) >> undefined
    Right b -> pure b

-- | Every ActiveCipher producer exercised by this suite: the pad
-- byte (tag-4 trailing byte) across these saves must cover both
-- 0x00 and 0x01. The first two use @CipherSpec 16 False@ (the
-- known gap on their own); the padded decrypt producer
-- closes the coverage.
cipherProducers :: [(OpEnv, InitArgs, SlotKind)]
cipherProducers =
  [ (cipherEnv, encryptArgs, SlotEncrypt)
  , (decryptEnv, decryptArgs, SlotDecrypt)
  , (decryptPadEnv, decryptPadArgs, SlotDecrypt)
  ]

-- | Both padB values appear on the ActiveCipher wire.
caseCipherPadCoverage :: IO ()
caseCipherPadCoverage = do
  bytes <- mapM (\(env, args, kind) -> saveCipherBytes env args kind)
    cipherProducers
  let pads = map BS.last bytes
  assertBool ("padB 0x00 exercised, got: " ++ show pads) (0x00 `elem` pads)
  assertBool ("padB 0x01 exercised, got: " ++ show pads) (0x01 `elem` pads)

-- | A padded decrypt slot (CKM_AES_CBC_PAD, @CipherSpec 16 True@)
-- roundtrips through the ActiveCipher branch with its key binding
-- intact; the tag-4 wire suffix (dirB, block u32, padB) is pinned
-- explicitly, not just the roundtrip equality.
caseDecryptPadded :: Int -> IO ()
caseDecryptPadded count = mapM_ check [1 .. fromIntegral count]
  where
    check :: Word64 -> IO ()
    check seed = do
      let size = fromIntegral (seed `mod` 65)
          part = lcgBytes seed size
          stA0 = mkSession (SessionId 1)
          (ops1, out1) = initOperation decryptPadEnv (ssOps stA0) stA0 decryptPadArgs
      assertEqual "init code" CKR_OK (ioCode out1)
      let stA1 = stA0 { ssOps = ops1 }
          (ops2, stA2, stepU) = planCipherUpdate ops1 stA1 SlotDecrypt part Nothing
      assertEqual "update code" CKR_OK (soCode stepU)
      let stA = stA2 { ssOps = ops2 }
      bytes <- case saveOperation defaultQuotas modelWithAesKey stA
        Pkcs11_3_2 (SaveSlot SlotDecrypt) of
        Left err -> assertFailure ("save failed: " ++ show err) >> undefined
        Right b -> pure b
      assertEqual "tag-4 wire suffix"
        (BS.pack [0x01, 0x00, 0x00, 0x00, 0x10, 0x01])
        (BS.takeEnd 6 bytes)
      stB <- case restoreOperation defaultQuotas modelWithAesKey
        (mkSession (SessionId 2)) Pkcs11_3_2 (RestoreSingle (Just keyHandle)) bytes of
        Left err -> assertFailure ("restore failed: " ++ show err) >> undefined
        Right s -> pure s
      assertEqual "restored slot equals saved slot"
        (lookupSingle (ssOps stA) SlotDecrypt)
        (lookupSingle (ssOps stB) SlotDecrypt)

-- | Both recovery roles roundtrip with their shape specs intact
-- (tag 3, role bytes 0\/1).
caseRecover :: Int -> IO ()
caseRecover count =
  mapM_ check
    [ (seed, role)
    | seed <- [1 .. fromIntegral count]
    , role <- [RoleSignRecover, RoleVerifyRecover]
    ]
  where
    check :: (Word64, RecoverRole) -> IO ()
    check (seed, role) = do
      let size = fromIntegral (seed `mod` 65)
          part = lcgBytes seed size
          (op, kind) = case role of
            RoleSignRecover -> (OpSignRecover, SlotSign)
            RoleVerifyRecover -> (OpVerifyRecover, SlotVerify)
      roundtripKeyed kind
        (mkActiveRecover role
          (mkKeyedCommon rsaX509Mech op part) (RecoverSpec 128 16))

-- | All four message families roundtrip, each with an idle and an
-- open inner message (tag 5): family tag, inner state, cipher
-- shape, and delivered-message count all survive the trip.
caseMessage :: Int -> IO ()
caseMessage count =
  mapM_ check
    [ (seed, fam, open)
    | seed <- [1 .. fromIntegral count]
    , fam <- [MsgEncrypt .. MsgVerify]
    , open <- [False, True]
    ]
  where
    check :: (Word64, MsgFamily, Bool) -> IO ()
    check (seed, fam, open) = do
      let part = lcgBytes seed (fromIntegral (seed `mod` 65))
          inner =
            if open
              then MsgOpen
                (lcgBytes (seed + 1) 8) (lcgBytes (seed + 2) 12) part
              else MsgIdle
          (mech, mspec) = case fam of
            MsgEncrypt -> (aesCbcMech, Just (CipherSpec 16 False))
            MsgDecrypt -> (aesCbcMech, Just (CipherSpec 16 True))
            _ -> (hmacSha256Mech, Nothing)
          ms = MsgState fam
            (mkKeyedCommon mech (msgOperation fam) part)
            inner mspec (fromIntegral (seed `mod` 5))
      roundtripKeyed (msgFamilyKind fam) (mkActiveMessage ms)

-- ---------------------------------------------------------------------------
-- Geometry revalidation laws
-- ---------------------------------------------------------------------------

-- | Big-endian u32, mirroring the snapshot codec.
u32be :: Int -> ByteString
u32be n = BS.pack
  [ fromIntegral (n `div` 0x1000000)
  , fromIntegral (n `div` 0x10000)
  , fromIntegral (n `div` 0x100)
  , fromIntegral n
  ]

-- | Replace the 4 bytes ending @back@ bytes from the end (a trailing
-- u32 field) with the big-endian encoding of @n@.
pokeU32 :: ByteString -> Int -> Int -> ByteString
pokeU32 bs back n =
  let len = BS.length bs
      (h, t) = BS.splitAt (len - back) bs
  in h <> u32be n <> BS.drop 4 t

-- | Save one keyed cipher slot buffering the given part.
saveCipherPart :: ByteString -> IO ByteString
saveCipherPart part = do
  let stA0 = mkSession (SessionId 1)
      (ops1, out1) = initOperation cipherEnv (ssOps stA0) stA0 encryptArgs
  assertEqual "init code" CKR_OK (ioCode out1)
  let stA1 = stA0 { ssOps = ops1 }
      (ops2, stA2, stepU) = planCipherUpdate ops1 stA1 SlotEncrypt part Nothing
  assertEqual "update code" CKR_OK (soCode stepU)
  case saveOperation defaultQuotas modelWithAesKey (stA2 { ssOps = ops2 })
      Pkcs11_3_2 (SaveSlot SlotEncrypt) of
    Left err -> assertFailure ("save failed: " ++ show err) >> undefined
    Right b -> pure b

-- | Every generated cipher save with a corrupted block field rejects
-- as malformed: decode revalidates the shared init bounds instead
-- of installing hostile geometry. The target still restores a
-- valid save afterwards, and the restored slot plans a final.
caseCipherGeometryRejects :: Int -> IO ()
caseCipherGeometryRejects count = do
  mapM_ check [1 .. fromIntegral count]
  good <- saveCipherPart (lcgBytes 999 16)
  let target = mkSession (SessionId 2)
  stR <- case restoreOperation defaultQuotas modelWithAesKey target
      Pkcs11_3_2 (RestoreSingle (Just keyHandle)) good of
    Left err -> assertFailure ("follow-up restore failed: " ++ show err)
      >> undefined
    Right s -> pure s
  let (_, _, fin) = planCipherFinal (ssOps stR) stR SlotEncrypt "cipher"
  assertEqual "follow-up final code" CKR_OK (soCode fin)
  where
    badBlocks = [0, 1025, 65536, 0x7FFFFFFF, 0xFFFFFFFF]
    check :: Word64 -> IO ()
    check seed = do
      let size = fromIntegral (seed `mod` 65)
          part = lcgBytes seed size
      good <- saveCipherPart part
      let bad = badBlocks !! fromIntegral (seed `mod` fromIntegral (length badBlocks))
          mutated = pokeU32 good 5 bad
      case restoreOperation defaultQuotas modelWithAesKey (mkSession (SessionId 2))
          Pkcs11_3_2 (RestoreSingle (Just keyHandle)) mutated of
        Left err@(RestoreMalformed _) ->
          assertEqual "restore code" CKR_SAVED_STATE_INVALID (restoreCode err)
        other -> assertFailure
          ("corrupt block " ++ show bad ++ " accepted: " ++ show other)

-- | Save one keyed sign-recover slot buffering the given part.
saveRecoverPart :: ByteString -> RecoverSpec -> IO ByteString
saveRecoverPart part rspec = do
  let stA = (mkSession (SessionId 1))
        { ssOps = insertOp
            (mkActiveRecover RoleSignRecover
              (mkKeyedCommon rsaX509Mech OpSignRecover part) rspec)
            emptySessionOps
        }
  case saveOperation defaultQuotas modelWithAesKey stA
      Pkcs11_3_2 (SaveSlot SlotSign) of
    Left err -> assertFailure ("save failed: " ++ show err) >> undefined
    Right b -> pure b

-- | Every generated recovery save with corrupted length fields
-- rejects as malformed. The target still restores a valid save
-- afterwards, and the restored slot plans a one-shot.
caseRecoverGeometryRejects :: Int -> IO ()
caseRecoverGeometryRejects count = do
  mapM_ check [1 .. fromIntegral count]
  good <- saveRecoverPart BS.empty (RecoverSpec 128 16)
  stR <- case restoreOperation defaultQuotas modelWithAesKey (mkSession (SessionId 2))
      Pkcs11_3_2 (RestoreSingle (Just keyHandle)) good of
    Left err -> assertFailure ("follow-up restore failed: " ++ show err)
      >> undefined
    Right s -> pure s
  let (_, _, o1) = planSignRecoverOneShot (ssOps stR) stR "block" "recover-me"
  assertEqual "follow-up one-shot code" CKR_OK (soCode o1)
  assertEqual "follow-up one-shot plans" 1 (length (soEffects o1))
  where
    badShapes = [(0, 16), (128, 0), (16, 32), (0, 0), (1, 2)]
    check :: Word64 -> IO ()
    check seed = do
      let size = fromIntegral (seed `mod` 65)
          part = lcgBytes seed size
      good <- saveRecoverPart part (RecoverSpec 128 16)
      let (cap, tagLen) =
            badShapes !! fromIntegral (seed `mod` fromIntegral (length badShapes))
          mutated = pokeU32 (pokeU32 good 8 cap) 4 tagLen
      case restoreOperation defaultQuotas modelWithAesKey (mkSession (SessionId 2))
          Pkcs11_3_2 (RestoreSingle (Just keyHandle)) mutated of
        Left err@(RestoreMalformed _) ->
          assertEqual "restore code" CKR_SAVED_STATE_INVALID (restoreCode err)
        other -> assertFailure
          ("corrupt lengths " ++ show (cap, tagLen)
            ++ " accepted: " ++ show other)

-- | A digest slot with a live backend stream refuses to save
-- (Snapshot.hs `SaveStreamLive`): the portable bytes cannot
-- capture native context, so save fails honestly instead of
-- dropping the fed bytes.
caseStreamLive :: IO ()
caseStreamLive = do
  let sc = setLive (DigestStream (EngineResourceId 7) True)
            (setBuffered "fed-bytes"
              (mkSlotCommon sha256Mech OpDigest Nothing BS.empty AuthNone))
      stA = (mkSession (SessionId 1))
        { ssOps = insertOp (mkActiveDigest sc) emptySessionOps }
  assertEqual "live stream refuses save"
    (Left (SaveStreamLive SlotDigest))
    (saveOperation defaultQuotas emptyModel stA Pkcs11_3_2
      (SaveSlot SlotDigest))

-- | Length-preflight law: admission depends on the two lengths
-- alone — admitted exactly when the joined bytes fit the bound —
-- and admitted bytes equal the concatenation. Boundary edges plus
-- generated small pairs; distinct fills pin the join order too.
casePreflight :: Int -> IO ()
casePreflight count = mapM_ check (edgePairs ++ genPairs)
  where
    edgeSizes :: [Int]
    edgeSizes =
      [0, 1, 15, 16, 17, maxBuffered - 1, maxBuffered, maxBuffered + 1]
    edgePairs :: [(Int, Int)]
    edgePairs = [(a, b) | a <- edgeSizes, b <- edgeSizes]
    genPairs :: [(Int, Int)]
    genPairs =
      [ (s `mod` 257, (s * 7) `mod` 257)
      | s <- [1 .. count]
      ]
    check :: (Int, Int) -> IO ()
    check (n, m) =
      let cur = BS.replicate n 0x41
          inc = BS.replicate m 0x42
          label = "preflight " ++ show (n, m)
      in case validateOperationIn cur inc of
        Left d
          | n + m > maxBuffered ->
              assertEqual (label ++ " code") CKR_ARGUMENTS_BAD (sdCode d)
          | otherwise ->
              assertFailure (label ++ ": within-bound pair rejected")
        Right joined
          | n + m <= maxBuffered ->
              assertEqual (label ++ " bytes") (cur <> inc) joined
          | otherwise ->
              assertFailure (label ++ ": over-limit pair admitted")
