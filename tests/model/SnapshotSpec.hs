{- | Portable operation snapshot tests.

Live streamed digests refuse to save (their backend context is not
portable); staged outputs and legacy buffered slots roundtrip, and
retrying after restore yields the same bytes as uninterrupted
execution.
-}
{-# LANGUAGE OverloadedStrings #-}
module SnapshotSpec (spec) where

import qualified Data.ByteString as BS
import qualified Data.Map.Strict as Map
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertBool, assertEqual, assertFailure, testCase)

import Haskoki.Attribute (AttributeType (..), AttributeValue (..))
import Haskoki.Model
  ( HandleBinding (..)
  , Model (..)
  , ObjectState (..)
  , SessionState (..)
  , emptyModel
  )
import Haskoki.Operation
  ( CipherDir (..)
  , CipherSpec (..)
  , CryptoEffect (..)
  , CryptoResult (..)
  , DigestStream (..)
  , DualState (..)
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
  , SessionOps
  , SlotKind (..)
  , StepOutcome (..)
  , activeDigest
  , activeSlots
  , bufferedOf
  , commonAuth
  , dualOf
  , emptySessionOps
  , initDualOperation
  , initOperation
  , insertOp
  , lookupSingle
  , maxBuffered
  , mkActiveCipher
  , mkActiveDigest
  , mkActiveMessage
  , mkActiveRecover
  , mkSlotCommon
  , msgFamilyKind
  , msgOperation
  , retryStaged
  , setBuffered
  , setDual
  , setLive
  , slotAuth
  )
import Haskoki.Operation.Cipher (finishCipherUpdate, planCipherFinal, planCipherUpdate)
import Haskoki.Operation.Dual (planDualFinal, planDualUpdate)
import Haskoki.Operation.Digest
  ( finishDigest
  , planDigestFinal
  , planDigestOneShot
  , planDigestUpdate
  )
import Haskoki.Operation.Message (MsgOneShot (..), planMessageOneShot)
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
  , SaveError (..)
  , SaveTarget (..)
  , SnapshotQuotas (..)
  , defaultQuotas
  , restoreCode
  , restoreOperation
  , saveCode
  , saveOperation
  )
import Haskoki.Types
  ( EngineResourceId (..)
  , ExternalHandle (..)
  , Generation (..)
  , ObjectId (..)
  , Pkcs11Version (..)
  , Revision (..)
  , ReturnCode (..)
  , SessionId (..)
  , SlotId (..)
  )

spec :: TestTree
spec = testGroup "operation snapshots"
  [ testCase "live stream refuses save; staged output roundtrips" caseDigestRoundtrip
  , testCase "retry after restore equals uninterrupted" caseFinalizeEquals
  , testCase "keyed cipher save/restore roundtrip preserves the slot" caseCipherRoundtrip
  , testCase "mid-stream save resumes chaining after restore" caseMidStreamRoundtrip
  , testCase "golden fixture bytes are pinned" caseGolden
  , testCase "profile mismatch rejects without touching the target" caseProfileMismatch
  , testCase "token mismatch rejects without touching the target" caseTokenMismatch
  , testCase "wrong key rejects without touching the target" caseKeyMismatch
  , testCase "missing and unexpected keys reject" caseKeyShape
  , testCase "bad schema and busy slots reject" caseSchemaAndBusy
  , testCase "truncated snapshots reject at every length" caseTruncated
  , testCase "random and bit-flipped bytes reject" caseRandomFlips
  , testCase "absurd length claims reject" caseAbsurdLength
  , testCase "save quota boundary: at quota OK, over rejected" caseSaveQuota
  , testCase "staged quota boundary on save and restore" caseStagedQuota
  , testCase "defaults admit buffer-bound states" caseBufferBound
  , testCase "fixtures carry no pointer or handle encodings" caseNoPointers
  , testCase "dual save/restore roundtrip preserves both sides" caseDualRoundtrip
  , testCase "restore into grant-bound target refuses; grant survives" caseRestoreGrantBound
  , testCase "pending dual restore respects grant binding" caseRestoreGrantBoundDual
  , testCase "cipher geometry mutations reject, target untouched" caseCipherGeometry
  , testCase "cipher bound probes restore and plan" caseCipherBounds
  , testCase "recovery lengths reject, target untouched" caseRecoverGeometry
  , testCase "message spec presence rejects, target untouched" caseMessagePresence
  , testCase "dual spec mutations reject, target untouched" caseDualGeometry
  , testCase "restored buffers preflight the next update" casePreflightRestoredBuffer
  ]

sha256Mech :: MechanismId
sha256Mech = MechanismId 0x250

testSlot :: SlotId
testSlot = SlotId 7

testEnv :: OpEnv
testEnv = OpEnv
  { oeRegistry = curatedRegistry
  , oeCaps = mkCapabilities [(sha256Mech, OpDigest)]
  , oeModel = emptyModel
  }

digestArgs :: InitArgs
digestArgs = InitArgs
  { iaOp = OpDigest
  , iaMech = sha256Mech
  , iaParams = BS.empty
  , iaKey = Nothing
  , iaCipher = Nothing
  , iaRecover = Nothing
  }

mkSession :: SessionId -> SessionState
mkSession sid = SessionState
  { ssId = sid
  , ssSlot = testSlot
  , ssRevision = Revision 1
  , ssGeneration = Generation 1
  , ssReadOnly = False
  , ssLogin = LoginPublic
  , ssOps = emptySessionOps
  }

-- | Fake stream resource for planner-level tests, which bypass the
-- init-alloc finish that records the real one.
streamRid :: EngineResourceId
streamRid = EngineResourceId 7

-- | Install a fake live (unfed) stream on the digest slot.
withDigestStream :: SessionOps -> SessionOps
withDigestStream ops = case lookupSingle ops SlotDigest of
  Just active -> case activeDigest active of
    Just sc -> insertOp
      (mkActiveDigest (setLive (DigestStream streamRid False) sc)) ops
    Nothing -> ops
  Nothing -> ops

-- | Init a digest and feed one part through its stream; fails the
-- test on any denial. The slot holds a live stream and refuses to
-- save.
initPlusUpdate :: SessionState -> BS.ByteString -> IO SessionState
initPlusUpdate st part = do
  let (ops1, out1) = initOperation testEnv (ssOps st) st digestArgs
  assertEqual "init code" CKR_OK (ioCode out1)
  let st1 = st { ssOps = withDigestStream ops1 }
      (ops2, st2, step) = planDigestUpdate (ssOps st1) st1 part
  assertEqual "update code" CKR_OK (soCode step)
  pure st2 { ssOps = ops2 }

-- | Init a digest with no input; fails the test on any denial.
initDigest :: SessionState -> IO SessionState
initDigest st = do
  let (ops1, out1) = initOperation testEnv (ssOps st) st digestArgs
  assertEqual "init code" CKR_OK (ioCode out1)
  pure st { ssOps = ops1 }

-- | A legacy buffered digest slot: bytes in the buffer, no live
-- stream. Old snapshots restore to this shape; it saves normally.
legacyBuffered :: SessionState -> BS.ByteString -> IO SessionState
legacyBuffered st part = do
  let (ops1, out1) = initOperation testEnv (ssOps st) st digestArgs
  assertEqual "init code" CKR_OK (ioCode out1)
  case lookupSingle ops1 SlotDigest of
    Just active -> case activeDigest active of
      Just sc ->
        let sc' = setBuffered part sc
        in pure st { ssOps = insertOp (mkActiveDigest sc') ops1 }
      Nothing -> assertFailure "digest slot missing after init" >> undefined
    Nothing -> assertFailure "digest slot missing after init" >> undefined

caseDigestRoundtrip :: IO ()
caseDigestRoundtrip = do
  -- A live stream refuses to save: the backend context is not portable.
  stLive <- initPlusUpdate (mkSession (SessionId 1)) "hello "
  case saveOperation defaultQuotas emptyModel stLive Pkcs11_3_2 (SaveSlot SlotDigest) of
    Left err -> do
      assertEqual "live error" (SaveStreamLive SlotDigest) err
      assertEqual "live code" CKR_STATE_UNSAVEABLE (saveCode err)
    Right _ -> assertFailure "live stream saved"
  -- A staged (consumed, streamless) slot roundtrips exactly.
  stA <- stagedDigest
  bytes <- case saveOperation defaultQuotas emptyModel stA Pkcs11_3_2 (SaveSlot SlotDigest) of
    Left err -> assertFailure ("save failed: " ++ show err) >> undefined
    Right b -> pure b
  assertEqual "magic" "HKSNAP02" (BS.take 8 bytes)
  let stB = mkSession (SessionId 2)
  stB' <- case restoreOperation defaultQuotas emptyModel stB Pkcs11_3_2 (RestoreSingle Nothing) bytes of
    Left err -> assertFailure ("restore failed: " ++ show err) >> undefined
    Right s -> pure s
  assertEqual "restored slot equals saved slot"
    (lookupSingle (ssOps stA) SlotDigest)
    (lookupSingle (ssOps stB') SlotDigest)

caseFinalizeEquals :: IO ()
caseFinalizeEquals = do
  -- Uninterrupted: one-shot, short finish, retry.
  stU0 <- initDigest (mkSession (SessionId 1))
  let (opsU1, _, oneU) = planDigestOneShot (ssOps stU0) stU0 "digest" "hello"
  assertEqual "one-shot code" CKR_OK (soCode oneU)
  let (opsU2, shortU) = finishDigest opsU1 SlotDigest "digest"
        (GotBytes cannedDigest) (IntentBuffer 2)
  assertEqual "short code" CKR_BUFFER_TOO_SMALL (soCode shortU)
  let (opsU3, retryU) = retryStaged opsU2 SlotDigest (IntentBuffer 64)
  assertEqual "retry code" CKR_OK (soCode retryU)
  -- Save/restore between the short finish and the retry.
  stA <- initDigest (mkSession (SessionId 1))
  let (opsA1, _, _) = planDigestOneShot (ssOps stA) stA "digest" "hello"
  let (opsA2, _) = finishDigest opsA1 SlotDigest "digest"
        (GotBytes cannedDigest) (IntentBuffer 2)
  bytes <- case saveOperation defaultQuotas emptyModel
      (stA { ssOps = opsA2 }) Pkcs11_3_2 (SaveSlot SlotDigest) of
    Left err -> assertFailure ("save failed: " ++ show err) >> undefined
    Right b -> pure b
  stR0 <- case restoreOperation defaultQuotas emptyModel
      (mkSession (SessionId 2)) Pkcs11_3_2 (RestoreSingle Nothing) bytes of
    Left err -> assertFailure ("restore failed: " ++ show err) >> undefined
    Right s -> pure s
  let (opsR1, retryR) = retryStaged (ssOps stR0) SlotDigest (IntentBuffer 64)
  assertEqual "post-restore retry code" CKR_OK (soCode retryR)
  assertEqual "retry outcomes" retryU retryR
  assertEqual "post-retry ops" opsU3 opsR1
  where
    cannedDigest :: BS.ByteString
    cannedDigest = BS.replicate 32 0xAB

aesCbcMech :: MechanismId
aesCbcMech = MechanismId 0x1082

keyHandle :: ExternalHandle
keyHandle = ExternalHandle 3

-- | Model holding one public AES token key (id 9, handle 3) with
-- usage attributes and stored material, so snapshots can record a
-- canonical key identity for it.
modelWithAesKey :: Model
modelWithAesKey =
  let ost = ObjectState
        { osId = ObjectId 9
        , osRevision = Revision 1
        , osGeneration = Generation 1
        , osAttrs = Map.fromList
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
    , mHandles = Map.singleton keyHandle
        (HandleBinding (ObjectId 9) (Generation 1))
    }

cipherEnv :: OpEnv
cipherEnv = OpEnv
  { oeRegistry = curatedRegistry
  , oeCaps = mkCapabilities [(aesCbcMech, OpEncrypt)]
  , oeModel = modelWithAesKey
  }

encryptArgs :: InitArgs
encryptArgs = InitArgs
  { iaOp = OpEncrypt
  , iaMech = aesCbcMech
  , iaParams = "0123456789abcdef"
  , iaKey = Just (KeyPolicy keyHandle [OpEncrypt] False)
  , iaCipher = Just (CipherSpec 16 False)
  , iaRecover = Nothing
  }

caseCipherRoundtrip :: IO ()
caseCipherRoundtrip = do
  let stA0 = mkSession (SessionId 1)
      (ops1, out1) = initOperation cipherEnv (ssOps stA0) stA0 encryptArgs
  assertEqual "init code" CKR_OK (ioCode out1)
  let stA1 = stA0 { ssOps = ops1 }
      (ops2, stA2, stepU) = planCipherUpdate ops1 stA1 SlotEncrypt "block#1-block#2-" Nothing
  assertEqual "update code" CKR_OK (soCode stepU)
  let stA = stA2 { ssOps = ops2 }
  bytes <- case saveOperation defaultQuotas modelWithAesKey stA Pkcs11_3_2 (SaveSlot SlotEncrypt) of
    Left err -> assertFailure ("save failed: " ++ show err) >> undefined
    Right b -> pure b
  stB' <- case restoreOperation defaultQuotas modelWithAesKey
      (mkSession (SessionId 2)) Pkcs11_3_2 (RestoreSingle (Just keyHandle)) bytes of
    Left err -> assertFailure ("restore failed: " ++ show err) >> undefined
    Right s -> pure s
  assertEqual "restored slot equals saved slot"
    (lookupSingle (ssOps stA) SlotEncrypt)
    (lookupSingle (ssOps stB') SlotEncrypt)

-- | A mid-stream cipher save carries the running chaining value:
-- restore resumes chaining exactly (the final over the restored
-- slot chains from the streamed answer block, not the init IV).
caseMidStreamRoundtrip :: IO ()
caseMidStreamRoundtrip = do
  let stA0 = mkSession (SessionId 1)
      (ops1, out1) = initOperation cipherEnv (ssOps stA0) stA0 encryptArgs
  assertEqual "init code" CKR_OK (ioCode out1)
  let stA1 = stA0 { ssOps = ops1 }
      (ops2, _, stepU) = planCipherUpdate ops1 stA1 SlotEncrypt
        (BS.replicate 32 0x44) Nothing
  assertEqual "update code" CKR_OK (soCode stepU)
  case soEffects stepU of
    [_] -> pure ()
    other -> assertFailure ("expected one update effect, got " ++ show other)
  let answer = BS.pack [200 .. 215]
      (ops3, finU) = finishCipherUpdate ops2 SlotEncrypt "cipher"
        (GotBytes answer) (IntentBuffer 128)
  assertEqual "update finish ok" CKR_OK (soCode finU)
  let stA = stA1 { ssOps = ops3 }
  bytes <- case saveOperation defaultQuotas modelWithAesKey stA Pkcs11_3_2 (SaveSlot SlotEncrypt) of
    Left err -> assertFailure ("save failed: " ++ show err)
    Right b -> pure b
  stB' <- case restoreOperation defaultQuotas modelWithAesKey
      (mkSession (SessionId 2)) Pkcs11_3_2 (RestoreSingle (Just keyHandle)) bytes of
    Left err -> assertFailure ("restore failed: " ++ show err)
    Right s -> pure s
  assertEqual "restored slot equals saved slot"
    (lookupSingle (ssOps stA) SlotEncrypt)
    (lookupSingle (ssOps stB') SlotEncrypt)
  let (_, _, f0) = planCipherFinal (ssOps stB') stB' SlotEncrypt "cipher"
  assertEqual "final plans" CKR_OK (soCode f0)
  case soEffects f0 of
    [FxCipher _ _ _ params _] ->
      assertEqual "final chains the streamed answer" answer params
    other -> assertFailure ("expected one final effect, got " ++ show other)

-- | Golden fixture: a digest snapshot over buffered "ab" on slot 7 under
-- profile 3.2, hand-derived from the format document in
-- 'Haskoki.Snapshot'. Any format drift — including a smuggled pointer,
-- handle, or resource-id field — breaks this pin.
goldenDigestAb :: BS.ByteString
goldenDigestAb = BS.pack
  [ 0x48, 0x4B, 0x53, 0x4E, 0x41, 0x50, 0x30, 0x32 -- "HKSNAP02"
  , 0x03                                        -- profile 3.2
  , 0x00, 0x00, 0x00, 0x07                      -- slot 7
  , 0x00                                        -- single body
  , 0x00                                        -- SlotDigest
  , 0x00                                        -- digest op
  , 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x50 -- CKM_SHA256
  , 0x00                                        -- OpDigest
  , 0x00, 0x00, 0x00, 0x00                      -- params ""
  , 0x00                                        -- AuthNone
  , 0x00, 0x00, 0x00, 0x02, 0x61, 0x62          -- buffered "ab"
  , 0x00                                        -- no chaining value
  , 0x00                                        -- no staged output
  , 0x00                                        -- unkeyed
  ]

caseGolden :: IO ()
caseGolden = do
  stA <- legacyBuffered (mkSession (SessionId 1)) "ab"
  bytes <- case saveOperation defaultQuotas emptyModel stA Pkcs11_3_2 (SaveSlot SlotDigest) of
    Left err -> assertFailure ("save failed: " ++ show err) >> undefined
    Right b -> pure b
  assertEqual "golden bytes" goldenDigestAb bytes

-- | Assert a restore fails with exactly the expected error and return
-- code. Callers additionally prove the target is untouched by
-- completing a follow-up on the same pre-state (a valid restore, or
-- the resident operation's own final), which would fail had the
-- rejected call replaced or consumed anything.
assertRejectedUntouched
  :: Either RestoreError SessionState -> RestoreError -> ReturnCode -> IO ()
assertRejectedUntouched res wantErr wantCode = case res of
  Left err -> do
    assertEqual "restore error" wantErr err
    assertEqual "return code" wantCode (restoreCode err)
  Right st' ->
    assertFailure ("restore unexpectedly succeeded: " ++ show st')

caseProfileMismatch :: IO ()
caseProfileMismatch = do
  stA <- legacyBuffered (mkSession (SessionId 1)) "hello "
  bytes <- expectSaved emptyModel stA Pkcs11_3_2 (SaveSlot SlotDigest)
  let target = mkSession (SessionId 2)
  assertRejectedUntouched
    (restoreOperation defaultQuotas emptyModel target Pkcs11_3_0
      (RestoreSingle Nothing) bytes)
    RestoreProfileMismatch CKR_SAVED_STATE_INVALID
  -- The same bytes restore fine under the matching profile.
  case restoreOperation defaultQuotas emptyModel target Pkcs11_3_2
      (RestoreSingle Nothing) bytes of
    Left err -> assertFailure ("valid restore failed: " ++ show err)
    Right _ -> pure ()

caseTokenMismatch :: IO ()
caseTokenMismatch = do
  stA <- legacyBuffered (mkSession (SessionId 1)) "hello "
  bytes <- expectSaved emptyModel stA Pkcs11_3_2 (SaveSlot SlotDigest)
  let target = (mkSession (SessionId 2)) { ssSlot = SlotId 9 }
  assertRejectedUntouched
    (restoreOperation defaultQuotas emptyModel target Pkcs11_3_2
      (RestoreSingle Nothing) bytes)
    RestoreTokenMismatch CKR_SAVED_STATE_INVALID
  -- The same bytes restore fine into the home token.
  case restoreOperation defaultQuotas emptyModel (mkSession (SessionId 2))
      Pkcs11_3_2 (RestoreSingle Nothing) bytes of
    Left err -> assertFailure ("valid restore failed: " ++ show err)
    Right _ -> pure ()

otherHandle :: ExternalHandle
otherHandle = ExternalHandle 4

-- | Model holding two AES keys with distinct material (handles 3 and 4).
modelWithTwoKeys :: Model
modelWithTwoKeys =
  let mkKey oid mat = ObjectState
        { osId = oid
        , osRevision = Revision 1
        , osGeneration = Generation 1
        , osAttrs = Map.fromList
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
    , mHandles = Map.fromList
        [ (keyHandle, HandleBinding (ObjectId 9) (Generation 1))
        , (otherHandle, HandleBinding (ObjectId 10) (Generation 1))
        ]
    }

twoKeyEnv :: OpEnv
twoKeyEnv = OpEnv
  { oeRegistry = curatedRegistry
  , oeCaps = mkCapabilities [(aesCbcMech, OpEncrypt)]
  , oeModel = modelWithTwoKeys
  }

-- | Init an encrypt under the given key handle and buffer one part.
initEncryptAs :: ExternalHandle -> SessionState -> IO SessionState
initEncryptAs h st = do
  let args = encryptArgs { iaKey = Just (KeyPolicy h [OpEncrypt] False) }
      (ops1, out1) = initOperation twoKeyEnv (ssOps st) st args
  assertEqual "init code" CKR_OK (ioCode out1)
  let (ops2, st2, stepU) =
        planCipherUpdate ops1 (st { ssOps = ops1 }) SlotEncrypt "block#1-block#2-" Nothing
  assertEqual "update code" CKR_OK (soCode stepU)
  pure st2 { ssOps = ops2 }

caseKeyMismatch :: IO ()
caseKeyMismatch = do
  stA <- initEncryptAs keyHandle (mkSession (SessionId 1))
  bytes <- expectSaved modelWithTwoKeys stA Pkcs11_3_2 (SaveSlot SlotEncrypt)
  let target = mkSession (SessionId 2)
  assertRejectedUntouched
    (restoreOperation defaultQuotas modelWithTwoKeys target Pkcs11_3_2
      (RestoreSingle (Just otherHandle)) bytes)
    RestoreKeyMismatch CKR_SAVED_STATE_INVALID
  -- The same bytes restore fine under the recorded key.
  case restoreOperation defaultQuotas modelWithTwoKeys target Pkcs11_3_2
      (RestoreSingle (Just keyHandle)) bytes of
    Left err -> assertFailure ("valid restore failed: " ++ show err)
    Right _ -> pure ()

caseKeyShape :: IO ()
caseKeyShape = do
  -- Keyed bytes with no key argument.
  stA <- initEncryptAs keyHandle (mkSession (SessionId 1))
  keyed <- expectSaved modelWithTwoKeys stA Pkcs11_3_2 (SaveSlot SlotEncrypt)
  let target = mkSession (SessionId 2)
  assertRejectedUntouched
    (restoreOperation defaultQuotas modelWithTwoKeys target Pkcs11_3_2
      (RestoreSingle Nothing) keyed)
    RestoreKeyMissing CKR_SAVED_STATE_INVALID
  -- Unknown handle: gone, not mismatched.
  assertRejectedUntouched
    (restoreOperation defaultQuotas modelWithTwoKeys target Pkcs11_3_2
      (RestoreSingle (Just (ExternalHandle 99))) keyed)
    RestoreKeyGone CKR_OBJECT_HANDLE_INVALID
  -- The target still accepts the valid restore afterwards.
  case restoreOperation defaultQuotas modelWithTwoKeys target Pkcs11_3_2
      (RestoreSingle (Just keyHandle)) keyed of
    Left err -> assertFailure ("valid restore failed: " ++ show err)
    Right _ -> pure ()
  -- Unkeyed bytes with a key argument.
  stD <- legacyBuffered (mkSession (SessionId 1)) "hello "
  unkeyed <- expectSaved emptyModel stD Pkcs11_3_2 (SaveSlot SlotDigest)
  assertRejectedUntouched
    (restoreOperation defaultQuotas modelWithTwoKeys target Pkcs11_3_2
      (RestoreSingle (Just keyHandle)) unkeyed)
    RestoreKeyUnexpected CKR_SAVED_STATE_INVALID

caseSchemaAndBusy :: IO ()
caseSchemaAndBusy = do
  stA <- legacyBuffered (mkSession (SessionId 1)) "hello "
  bytes <- expectSaved emptyModel stA Pkcs11_3_2 (SaveSlot SlotDigest)
  let target = mkSession (SessionId 2)
  -- Flipped magic: not a snapshot at all.
  let badMagic = BS.singleton 0x00 <> BS.drop 1 bytes
  case restoreOperation defaultQuotas emptyModel target Pkcs11_3_2
      (RestoreSingle Nothing) badMagic of
    Left (RestoreMalformed _) -> pure ()
    other -> assertFailure ("bad magic accepted: " ++ show other)
  -- Occupied target slot: busy, and the occupying op is untouched —
  -- it still finalizes over exactly its own buffered input.
  occupier <- initPlusUpdate (mkSession (SessionId 2)) "resident"
  case restoreOperation defaultQuotas emptyModel occupier Pkcs11_3_2
      (RestoreSingle Nothing) bytes of
    Left err -> do
      assertEqual "busy error" (RestoreSlotBusy SlotDigest) err
      assertEqual "busy code" CKR_OPERATION_ACTIVE (restoreCode err)
    Right _ -> assertFailure "restore into busy slot succeeded"
  let (_, _, residentFinal) =
        planDigestFinal (ssOps occupier) occupier "digest"
  assertEqual "resident final code" CKR_OK (soCode residentFinal)
  assertEqual "resident final consumes its stream"
    [FxDigestConsume streamRid] (soEffects residentFinal)

-- | Save, failing the test on any save error.
expectSaved
  :: Model -> SessionState -> Pkcs11Version -> SaveTarget -> IO BS.ByteString
expectSaved model st profile target =
  case saveOperation defaultQuotas model st profile target of
    Left err -> assertFailure ("save failed: " ++ show err) >> undefined
    Right b -> pure b

caseTruncated :: IO ()
caseTruncated = do
  stA <- legacyBuffered (mkSession (SessionId 1)) "hello "
  bytes <- expectSaved emptyModel stA Pkcs11_3_2 (SaveSlot SlotDigest)
  let target = mkSession (SessionId 2)
      go n = case restoreOperation defaultQuotas emptyModel target Pkcs11_3_2
        (RestoreSingle Nothing) (BS.take n bytes) of
        Left (RestoreMalformed _) -> pure ()
        other -> assertFailure
          ("prefix length " ++ show n ++ " accepted: " ++ show other)
  mapM_ go [0 .. BS.length bytes - 1]
  -- The full bytes still restore (the loop above proves nothing alone).
  case restoreOperation defaultQuotas emptyModel target Pkcs11_3_2
      (RestoreSingle Nothing) bytes of
    Left err -> assertFailure ("full bytes rejected: " ++ show err)
    Right _ -> pure ()

caseRandomFlips :: IO ()
caseRandomFlips = do
  let target = mkSession (SessionId 2)
      rejects label bs =
        case restoreOperation defaultQuotas emptyModel target Pkcs11_3_2
            (RestoreSingle Nothing) bs of
          Left (RestoreMalformed _) -> pure ()
          other -> assertFailure (label ++ " accepted: " ++ show other)
  rejects "0xff block" (BS.replicate 16 0xFF)
  rejects "0x00 block" (BS.replicate 32 0x00)
  rejects "ascii garbage" "bogus-bytes-not-a-snapshot"
  rejects "oversized garbage" (BS.replicate 70000 0xA5)
  -- Structural bit flips: profile, body tag, op tag, auth mark.
  rejects "profile tag 9" (poke goldenDigestAb 8 0x09)
  rejects "body tag 2" (poke goldenDigestAb 13 0x02)
  rejects "op tag 9" (poke goldenDigestAb 15 0x09)
  rejects "auth tag 9" (poke goldenDigestAb 29 0x09)
  -- A flipped CONTENT byte still decodes: buffered input is free-form.
  -- (Golden layout: buffered "ab" sits at indices 34..35.)
  case restoreOperation defaultQuotas emptyModel target Pkcs11_3_2
      (RestoreSingle Nothing) (poke goldenDigestAb 35 0x63) of
    Left err -> assertFailure ("content flip rejected: " ++ show err)
    Right st' -> case lookupSingle (ssOps st') SlotDigest of
      Just active -> case activeDigest active of
        Just sc ->
          assertEqual "flipped buffer" "ac" (bufferedOf sc)
        Nothing -> assertFailure ("expected digest slot, got: " ++ show active)
      Nothing -> assertFailure "expected digest slot, got: Nothing"
  where
    poke bs i b = BS.take i bs <> BS.singleton b <> BS.drop (i + 1) bs

caseAbsurdLength :: IO ()
caseAbsurdLength = do
  -- Buffered-length field (golden indices 30..33) claims 4 GiB with a
  -- 38-byte tail: truncation, not an allocation.
  let huge = BS.take 30 goldenDigestAb <> BS.replicate 4 0xFF
        <> BS.drop 34 goldenDigestAb
      target = mkSession (SessionId 2)
  case restoreOperation defaultQuotas emptyModel target Pkcs11_3_2
      (RestoreSingle Nothing) huge of
    Left (RestoreMalformed _) -> pure ()
    other -> assertFailure ("absurd length accepted: " ++ show other)

caseSaveQuota :: IO ()
caseSaveQuota = do
  stA <- legacyBuffered (mkSession (SessionId 1)) "hello "
  bytes <- expectSaved emptyModel stA Pkcs11_3_2 (SaveSlot SlotDigest)
  let len = BS.length bytes
  -- At quota: OK.
  case saveOperation (SnapshotQuotas len maxBuffered) emptyModel stA
      Pkcs11_3_2 (SaveSlot SlotDigest) of
    Left err -> assertFailure ("at-quota save failed: " ++ show err)
    Right b -> assertEqual "at-quota bytes" bytes b
  -- One byte over: rejected with the measured size and the bound.
  case saveOperation (SnapshotQuotas (len - 1) maxBuffered) emptyModel stA
      Pkcs11_3_2 (SaveSlot SlotDigest) of
    Left err -> do
      assertEqual "quota error" (SaveOverQuota len (len - 1)) err
      assertEqual "quota code" CKR_STATE_UNSAVEABLE (saveCode err)
    Right _ -> assertFailure "over-quota save succeeded"

-- | A digest whose 40-byte final is staged behind a 2-byte buffer.
stagedDigest :: IO SessionState
stagedDigest = do
  stA <- initPlusUpdate (mkSession (SessionId 1)) "hello "
  let (opsF, stF, fin) = planDigestFinal (ssOps stA) stA "digest"
  assertEqual "final code" CKR_OK (soCode fin)
  let (opsS, out) = finishDigest opsF SlotDigest "digest"
        (GotBytes (BS.replicate 40 0xAA)) (IntentBuffer 2)
  assertEqual "short code" CKR_BUFFER_TOO_SMALL (soCode out)
  pure stF { ssOps = opsS }

caseStagedQuota :: IO ()
caseStagedQuota = do
  stS <- stagedDigest
  bytes <- expectSaved emptyModel stS Pkcs11_3_2 (SaveSlot SlotDigest)
  let len = BS.length bytes
      target = mkSession (SessionId 2)
  -- Staged boundary on save: 40 OK, 39 rejected.
  case saveOperation (SnapshotQuotas len 40) emptyModel stS
      Pkcs11_3_2 (SaveSlot SlotDigest) of
    Left err -> assertFailure ("at-quota staged save failed: " ++ show err)
    Right _ -> pure ()
  case saveOperation (SnapshotQuotas len 39) emptyModel stS
      Pkcs11_3_2 (SaveSlot SlotDigest) of
    Left err -> do
      assertEqual "staged error" (SaveStagedOverQuota 40 39) err
      assertEqual "staged code" CKR_STATE_UNSAVEABLE (saveCode err)
    Right _ -> assertFailure "over-quota staged save succeeded"
  -- Restore enforces the same staged bound on hostile bytes.
  case restoreOperation (SnapshotQuotas len 39) emptyModel target Pkcs11_3_2
      (RestoreSingle Nothing) bytes of
    Left err -> assertEqual "restore staged error"
      (RestoreStagedOverQuota 40 39) err
    Right _ -> assertFailure "over-quota staged restore succeeded"
  -- And the same total bound.
  case restoreOperation (SnapshotQuotas (len - 1) maxBuffered) emptyModel
      target Pkcs11_3_2 (RestoreSingle Nothing) bytes of
    Left err -> assertEqual "restore total error"
      (RestoreOverQuota len (len - 1)) err
    Right _ -> assertFailure "over-quota restore succeeded"

caseBufferBound :: IO ()
caseBufferBound = do
  stA <- legacyBuffered (mkSession (SessionId 1))
    (BS.replicate maxBuffered 0x41)
  bytes <- expectSaved emptyModel stA Pkcs11_3_2 (SaveSlot SlotDigest)
  stB' <- case restoreOperation defaultQuotas emptyModel
      (mkSession (SessionId 2)) Pkcs11_3_2 (RestoreSingle Nothing) bytes of
    Left err -> assertFailure ("restore failed: " ++ show err) >> undefined
    Right s -> pure s
  assertEqual "buffer-bound slot roundtrips"
    (lookupSingle (ssOps stA) SlotDigest)
    (lookupSingle (ssOps stB') SlotDigest)

-- | Forbidden byte patterns: encodings that must never appear in snapshot
-- fixtures.
--
-- * @"PTR\\0"@ — a native-pointer field tag. The format has no pointer
--   fields; a serialized @Ptr@ would need a tag like this to be
--   decodable.
-- * @"HDL\\0"@ — a native-handle field tag, for the same reason.
-- * @"RID\\0"@ — a backend resource-id field tag. Snapshots carry
--   logical state plus canonical key identities, never
--   'EngineResourceId' values.
-- * BE32\/BE64 of @0xDEADBEEF@ — a distinctive handle\/pointer-sized
--   canary standing in for a live native value.
-- * BE32\/BE64 of object id 9 and handle 3 — the live ids behind the
--   keyed fixture; the snapshot must carry the key's canonical
--   identity, never its ids.
forbiddenPatterns :: [(String, BS.ByteString)]
forbiddenPatterns =
  [ ("PTR tag", "PTR\0")
  , ("HDL tag", "HDL\0")
  , ("RID tag", "RID\0")
  , ("BE32 canary", be32 0xDEADBEEF)
  , ("BE64 canary", be64 0xDEADBEEF)
  , ("BE32 object id", be32 9)
  , ("BE64 object id", be64 9)
  , ("BE32 handle", be32 3)
  , ("BE64 handle", be64 3)
  ]
  where
    be32 :: Int -> BS.ByteString
    be32 n = BS.pack
      [ fromIntegral (n `div` 0x1000000)
      , fromIntegral (n `div` 0x10000)
      , fromIntegral (n `div` 0x100)
      , fromIntegral n
      ]
    be64 :: Int -> BS.ByteString
    be64 n = BS.replicate 4 0x00 <> be32 n

caseNoPointers :: IO ()
caseNoPointers = do
  stD <- legacyBuffered (mkSession (SessionId 1)) "hello "
  digest <- expectSaved emptyModel stD Pkcs11_3_2 (SaveSlot SlotDigest)
  stC <- initEncryptAs keyHandle (mkSession (SessionId 1))
  keyed <- expectSaved modelWithTwoKeys stC Pkcs11_3_2 (SaveSlot SlotEncrypt)
  stS <- stagedDigest
  staged <- expectSaved emptyModel stS Pkcs11_3_2 (SaveSlot SlotDigest)
  -- Positive control first: the scanner finds the magic it must find,
  -- so a clean scan means clean bytes, not a broken scanner.
  let found pat bs = pat `BS.isInfixOf` bs
  assertBool "control: magic in digest" (found "HKSNAP02" digest)
  assertBool "control: magic in keyed" (found "HKSNAP02" keyed)
  assertBool "control: magic in staged" (found "HKSNAP02" staged)
  assertBool "control: planted tag detected"
    (found "PTR\0" (digest <> "PTR\0"))
  -- The real assertion: no fixture carries a forbidden encoding.
  let clean label bs =
        mapM_ (\(name, pat) -> assertBool
          (label ++ " carries " ++ name) (not (found pat bs)))
        forbiddenPatterns
  clean "digest" digest
  clean "keyed" keyed
  clean "staged" staged

dualEnv :: OpEnv
dualEnv = OpEnv
  { oeRegistry = curatedRegistry
  , oeCaps = mkCapabilities
      [ (sha256Mech, OpDigest)
      , (aesCbcMech, OpEncrypt)
      ]
  , oeModel = modelWithTwoKeys
  }

caseDualRoundtrip :: IO ()
caseDualRoundtrip = do
  let stA0 = mkSession (SessionId 1)
      (ops1, out1) = initDualOperation dualEnv (ssOps stA0) stA0
        digestArgs encryptArgs
  assertEqual "init code" CKR_OK (ioCode out1)
  let (ops2, stA2, stepU) =
        planDualUpdate ops1 (stA0 { ssOps = ops1 }) "dual-stream"
  assertEqual "update code" CKR_OK (soCode stepU)
  let stA = stA2 { ssOps = ops2 }
  bytes <- expectSaved modelWithTwoKeys stA Pkcs11_3_2 SaveDual
  stB' <- case restoreOperation defaultQuotas modelWithTwoKeys
      (mkSession (SessionId 2)) Pkcs11_3_2
      (RestoreDual Nothing (Just keyHandle)) bytes of
    Left err -> assertFailure ("restore failed: " ++ show err) >> undefined
    Right s -> pure s
  assertEqual "restored dual equals saved dual"
    (dualOf (ssOps stA)) (dualOf (ssOps stB'))
  -- A dual restore onto an occupied cipher slot stays out, untouched.
  stC <- initEncryptAs keyHandle (mkSession (SessionId 3))
  case restoreOperation defaultQuotas modelWithTwoKeys stC Pkcs11_3_2
      (RestoreDual Nothing (Just keyHandle)) bytes of
    Left err -> assertEqual "dual busy error"
      (RestoreSlotBusy SlotEncrypt) err
    Right _ -> assertFailure "dual restore into busy slot succeeded"

-- ---------------------------------------------------------------------------
-- Grant binding: restored work joins the same guard as init
-- ---------------------------------------------------------------------------

-- | Model holding two always-authenticate AES keys (handles 3 and 4).
-- Usage and the always-authenticate mark come from the key objects,
-- so inits under a user login mark their slots auth-pending.
modelWithAuthKeys :: Model
modelWithAuthKeys =
  let mkKey oid mat = ObjectState
        { osId = oid
        , osRevision = Revision 1
        , osGeneration = Generation 1
        , osAttrs = Map.fromList
            [ (AttrClass, ValULong 4)
            , (AttrKeyType, ValULong 0x1F)
            , (AttrPrivate, ValBool False)
            , (AttrEncrypt, ValBool True)
            , (AttrDecrypt, ValBool True)
            , (AttrAlwaysAuthenticate, ValBool True)
            , (AttrValue, ValBytes mat)
            ]
        , osOwner = Nothing
        , osSlot = testSlot
        }
      ost1 = mkKey (ObjectId 9) "0123456789abcdef0123456789abcdef"
      ost2 = mkKey (ObjectId 10) "fedcba9876543210fedcba9876543210"
  in emptyModel
    { mObjects = Map.fromList [(ObjectId 9, ost1), (ObjectId 10, ost2)]
    , mHandles = Map.fromList
        [ (keyHandle, HandleBinding (ObjectId 9) (Generation 1))
        , (otherHandle, HandleBinding (ObjectId 10) (Generation 1))
        ]
    }

authEnv :: OpEnv
authEnv = OpEnv
  { oeRegistry = curatedRegistry
  , oeCaps = mkCapabilities [(aesCbcMech, OpEncrypt), (aesCbcMech, OpDecrypt)]
  , oeModel = modelWithAuthKeys
  }

authDualEnv :: OpEnv
authDualEnv = OpEnv
  { oeRegistry = curatedRegistry
  , oeCaps = mkCapabilities [(sha256Mech, OpDigest), (aesCbcMech, OpEncrypt)]
  , oeModel = modelWithAuthKeys
  }

decryptArgsFor :: ExternalHandle -> InitArgs
decryptArgsFor h = InitArgs
  { iaOp = OpDecrypt
  , iaMech = aesCbcMech
  , iaParams = BS.replicate 16 0
  , iaKey = Just (KeyPolicy h [OpDecrypt] False)
  , iaCipher = Just (CipherSpec 16 True)
  , iaRecover = Nothing
  }

-- | Restoring auth-pending work into a grant-bound target refuses with
-- the same code as a second pending init: the restored operation must
-- not steal the grant held for the resident one. The refusal leaves
-- the target untouched — the resident operation still spends its own
-- grant — while the same bytes restore fine into unbound targets.
caseRestoreGrantBound :: IO ()
caseRestoreGrantBound = do
  -- Source: pending encrypt/key-A under a user login (saved pre-use,
  -- so the bytes carry AUTH=pending).
  let src0 = (mkSession (SessionId 1)) { ssLogin = LoginUser }
      (opsA, outA) = initOperation authEnv (ssOps src0) src0 encryptArgs
  assertEqual "source init code" CKR_OK (ioCode outA)
  assertEqual "source slot pending" (Just AuthPending) (slotAuth opsA SlotEncrypt)
  let stA = src0 { ssOps = opsA }
  bytes <- expectSaved modelWithAuthKeys stA Pkcs11_3_2 (SaveSlot SlotEncrypt)
  -- Target: pending decrypt/key-B holding a context grant.
  let tgt0 = (mkSession (SessionId 2)) { ssLogin = LoginUser }
      (opsB, outB) = initOperation authEnv (ssOps tgt0) tgt0
        (decryptArgsFor otherHandle)
  assertEqual "target init code" CKR_OK (ioCode outB)
  assertEqual "target slot pending" (Just AuthPending) (slotAuth opsB SlotDecrypt)
  let granted = (tgt0 { ssOps = opsB }) { ssLogin = LoginContextUser }
  -- The restore refuses: the grant already binds to the decrypt.
  assertRejectedUntouched
    (restoreOperation defaultQuotas modelWithAuthKeys granted Pkcs11_3_2
      (RestoreSingle (Just keyHandle)) bytes)
    (RestoreSlotBusy SlotEncrypt) CKR_OPERATION_ACTIVE
  -- Non-consumption proof: the resident decrypt still spends its own
  -- grant on its first data call.
  let (opsB', stB', stepB) =
        planCipherUpdate (ssOps granted) granted SlotDecrypt "part-1" Nothing
  assertEqual "owner consumes its grant" CKR_OK (soCode stepB)
  assertEqual "grant spent" LoginUser (ssLogin stB')
  assertEqual "owner satisfied" (Just AuthSatisfied) (slotAuth opsB' SlotDecrypt)
  -- Valid-restore control: the same bytes land in a fresh session.
  stC <- case restoreOperation defaultQuotas modelWithAuthKeys
      (mkSession (SessionId 3)) Pkcs11_3_2 (RestoreSingle (Just keyHandle)) bytes of
    Left err -> assertFailure ("valid restore failed: " ++ show err) >> undefined
    Right s -> pure s
  assertEqual "restored slot equals saved slot"
    (lookupSingle (ssOps stA) SlotEncrypt)
    (lookupSingle (ssOps stC) SlotEncrypt)
  -- Ungranted pair admits (init parity): B pending without a grant is
  -- no barrier to the pending restore.
  let ungranted = tgt0 { ssOps = opsB }
  case restoreOperation defaultQuotas modelWithAuthKeys ungranted Pkcs11_3_2
      (RestoreSingle (Just keyHandle)) bytes of
    Left err -> assertFailure ("ungranted pair restore failed: " ++ show err)
    Right stD -> assertEqual "pair slots" [SlotEncrypt, SlotDecrypt]
      (activeSlots (ssOps stD))
  -- Plain work still admits under a held grant (init parity): an
  -- AuthNone digest lands without disturbing the bound grant.
  stP <- legacyBuffered (mkSession (SessionId 4)) "hello "
  plain <- expectSaved emptyModel stP Pkcs11_3_2 (SaveSlot SlotDigest)
  case restoreOperation defaultQuotas modelWithAuthKeys granted Pkcs11_3_2
      (RestoreSingle Nothing) plain of
    Left err -> assertFailure ("plain restore under grant failed: " ++ show err)
    Right stE -> do
      assertEqual "grant survives plain arrival" LoginContextUser (ssLogin stE)
      assertEqual "digest joins the bound slot" [SlotDigest, SlotDecrypt]
        (activeSlots (ssOps stE))

-- | The grant guard covers dual restores in both directions: a pending
-- dual refuses into a bound single target, and a pending single
-- refuses into a bound dual target. Valid dual bytes still restore.
caseRestoreGrantBoundDual :: IO ()
caseRestoreGrantBoundDual = do
  -- Source: pending dual (digest + encrypt/key-A) under a user login.
  let src0 = (mkSession (SessionId 1)) { ssLogin = LoginUser }
      (opsD, outD) = initDualOperation authDualEnv (ssOps src0) src0
        digestArgs encryptArgs
  assertEqual "dual init code" CKR_OK (ioCode outD)
  case dualOf opsD of
    Just du -> assertEqual "dual cipher pending" AuthPending
      (commonAuth (duCipher du))
    Nothing -> assertFailure "dual missing after init"
  let stD = src0 { ssOps = opsD }
  dualBytes <- expectSaved modelWithAuthKeys stD Pkcs11_3_2 SaveDual
  -- Bound single target refuses the pending dual.
  let tgt0 = (mkSession (SessionId 2)) { ssLogin = LoginUser }
      (opsB, outB) = initOperation authEnv (ssOps tgt0) tgt0
        (decryptArgsFor otherHandle)
  assertEqual "target init code" CKR_OK (ioCode outB)
  let granted = (tgt0 { ssOps = opsB }) { ssLogin = LoginContextUser }
  assertRejectedUntouched
    (restoreOperation defaultQuotas modelWithAuthKeys granted Pkcs11_3_2
      (RestoreDual Nothing (Just keyHandle)) dualBytes)
    RestoreDualBusy CKR_OPERATION_ACTIVE
  -- Bound dual target refuses a pending single on a free slot.
  let dualTgt0 = (mkSession (SessionId 3)) { ssLogin = LoginUser }
      (opsDT, outDT) = initDualOperation authDualEnv (ssOps dualTgt0) dualTgt0
        digestArgs encryptArgs
  assertEqual "dual target init code" CKR_OK (ioCode outDT)
  let grantedDual = (dualTgt0 { ssOps = opsDT }) { ssLogin = LoginContextUser }
      srcS0 = (mkSession (SessionId 4)) { ssLogin = LoginUser }
      (opsS, outS) = initOperation authEnv (ssOps srcS0) srcS0
        (decryptArgsFor otherHandle)
  assertEqual "single init code" CKR_OK (ioCode outS)
  assertEqual "single slot pending" (Just AuthPending) (slotAuth opsS SlotDecrypt)
  singleBytes <- expectSaved modelWithAuthKeys (srcS0 { ssOps = opsS })
    Pkcs11_3_2 (SaveSlot SlotDecrypt)
  assertRejectedUntouched
    (restoreOperation defaultQuotas modelWithAuthKeys grantedDual Pkcs11_3_2
      (RestoreSingle (Just otherHandle)) singleBytes)
    (RestoreSlotBusy SlotDecrypt) CKR_OPERATION_ACTIVE
  -- Non-consumption proof: the resident dual still spends its own
  -- grant on its first update.
  let (opsDU', stDU', stepDU) = planDualUpdate opsDT grantedDual "dual-part"
  assertEqual "dual consumes its grant" CKR_OK (soCode stepDU)
  assertEqual "dual grant spent" LoginUser (ssLogin stDU')
  case dualOf opsDU' of
    Just du -> assertEqual "dual cipher satisfied" AuthSatisfied
      (commonAuth (duCipher du))
    Nothing -> assertFailure "dual missing after update"
  -- Valid-restore control: the same dual bytes land in a fresh session.
  case restoreOperation defaultQuotas modelWithAuthKeys
      (mkSession (SessionId 5)) Pkcs11_3_2
      (RestoreDual Nothing (Just keyHandle)) dualBytes of
    Left err -> assertFailure ("valid dual restore failed: " ++ show err)
    Right stR -> assertEqual "restored dual equals saved dual"
      (dualOf (ssOps stD)) (dualOf (ssOps stR))

-- ---------------------------------------------------------------------------
-- Geometry revalidation: decode admits exactly what init admits
-- ---------------------------------------------------------------------------

-- | Big-endian u32, mirroring the snapshot codec.
u32be :: Int -> BS.ByteString
u32be n = BS.pack
  [ fromIntegral (n `div` 0x1000000)
  , fromIntegral (n `div` 0x10000)
  , fromIntegral (n `div` 0x100)
  , fromIntegral n
  ]

-- | Replace the 4 bytes ending @back@ bytes from the end (a trailing
-- u32 field) with the big-endian encoding of @n@.
pokeU32 :: BS.ByteString -> Int -> Int -> BS.ByteString
pokeU32 bs back n =
  let len = BS.length bs
      (h, t) = BS.splitAt (len - back) bs
  in h <> u32be n <> BS.drop 4 t

-- | Save one keyed cipher slot directly (the encoder is total, so
-- even geometries init would refuse encode): the baseline whose
-- trailing block field the geometry tests mutate.
saveCipherSlot :: CipherSpec -> IO BS.ByteString
saveCipherSlot cspec = do
  let sc = setBuffered "block#1-block#2-"
        (mkSlotCommon aesCbcMech OpEncrypt (Just (ObjectId 9))
          "0123456789abcdef" AuthNone)
      stA = (mkSession (SessionId 1))
        { ssOps = insertOp (mkActiveCipher DirEncrypt sc cspec) emptySessionOps }
  expectSaved modelWithTwoKeys stA Pkcs11_3_2 (SaveSlot SlotEncrypt)

-- | Restore cipher bytes into the target and plan a final over the
-- restored slot: the follow-up proving a rejected restore left the
-- target untouched.
expectRestorePlan :: BS.ByteString -> SessionState -> IO ()
expectRestorePlan bytes target = do
  stR <- case restoreOperation defaultQuotas modelWithTwoKeys target
      Pkcs11_3_2 (RestoreSingle (Just keyHandle)) bytes of
    Left err -> assertFailure ("follow-up restore failed: " ++ show err) >> undefined
    Right s -> pure s
  let (_, _, fin) = planCipherFinal (ssOps stR) stR SlotEncrypt "cipher"
  assertEqual "follow-up final code" CKR_OK (soCode fin)
  case soEffects fin of
    [_] -> pure ()
    other -> assertFailure ("expected one final effect, got " ++ show other)

caseCipherGeometry :: IO ()
caseCipherGeometry = do
  good <- saveCipherSlot (CipherSpec 16 False)
  -- Golden frame: tag-4 suffix (dirB, block u32, padB).
  assertEqual "cipher wire suffix"
    (BS.pack [0x00, 0x00, 0x00, 0x00, 0x10, 0x00])
    (BS.takeEnd 6 good)
  padded <- saveCipherSlot (CipherSpec 16 True)
  let target = mkSession (SessionId 2)
      rejects label bytes =
        case restoreOperation defaultQuotas modelWithTwoKeys target
            Pkcs11_3_2 (RestoreSingle (Just keyHandle)) bytes of
          Left err@(RestoreMalformed _) -> do
            assertEqual (label ++ " code")
              CKR_SAVED_STATE_INVALID (restoreCode err)
            expectRestorePlan good target
          other -> assertFailure (label ++ " accepted: " ++ show other)
  rejects "block 0" (pokeU32 good 5 0)
  rejects "block 1025" (pokeU32 good 5 1025)
  rejects "block u32max" (pokeU32 good 5 0xFFFFFFFF)
  rejects "padded block 256" (pokeU32 padded 5 256)
  -- Negative control: 256 unpadded is in range, restores, and plans
  -- (the 16 buffered bytes are ragged for a 256 final, so an update
  -- proves the slot is live instead).
  stN <- case restoreOperation defaultQuotas modelWithTwoKeys target
      Pkcs11_3_2 (RestoreSingle (Just keyHandle)) (pokeU32 good 5 256) of
    Left err -> assertFailure ("block 256 rejected: " ++ show err) >> undefined
    Right s -> pure s
  let (_, _, updN) = planCipherUpdate (ssOps stN) stN SlotEncrypt
        "more-bytes" Nothing
  assertEqual "block-256 update code" CKR_OK (soCode updN)
  -- Aligned control: block 8 divides the 16 buffered bytes, so the
  -- restored slot plans a final.
  stA <- case restoreOperation defaultQuotas modelWithTwoKeys target
      Pkcs11_3_2 (RestoreSingle (Just keyHandle)) (pokeU32 good 5 8) of
    Left err -> assertFailure ("block 8 rejected: " ++ show err) >> undefined
    Right s -> pure s
  let (_, _, finA) = planCipherFinal (ssOps stA) stA SlotEncrypt "cipher"
  assertEqual "block-8 final code" CKR_OK (soCode finA)

-- | Valid geometry bounds roundtrip through init, save, and
-- restore, and every restored slot plans a final: the shared
-- predicate admits 1\/16\/255\/1024 unpadded and 1\/16\/255 padded.
caseCipherBounds :: IO ()
caseCipherBounds = mapM_ check
  [ CipherSpec 1 False
  , CipherSpec 16 False
  , CipherSpec 255 False
  , CipherSpec 1024 False
  , CipherSpec 1 True
  , CipherSpec 16 True
  , CipherSpec 255 True
  ]
  where
    check cspec = do
      let args = encryptArgs { iaCipher = Just cspec }
          stA0 = mkSession (SessionId 1)
          (ops1, out1) = initOperation twoKeyEnv (ssOps stA0) stA0 args
      assertEqual ("init " ++ show cspec) CKR_OK (ioCode out1)
      let stA = stA0 { ssOps = ops1 }
      bytes <- expectSaved modelWithTwoKeys stA Pkcs11_3_2 (SaveSlot SlotEncrypt)
      -- Golden frame: tag-4 suffix pins the wire geometry.
      assertEqual ("wire suffix " ++ show cspec)
        (BS.pack [0x00] <> u32be (csBlock cspec)
          <> BS.singleton (if csPad cspec then 0x01 else 0x00))
        (BS.takeEnd 6 bytes)
      stR <- case restoreOperation defaultQuotas modelWithTwoKeys
          (mkSession (SessionId 2)) Pkcs11_3_2
          (RestoreSingle (Just keyHandle)) bytes of
        Left err ->
          assertFailure ("restore " ++ show cspec ++ " failed: " ++ show err)
            >> undefined
        Right s -> pure s
      assertEqual ("roundtrip " ++ show cspec)
        (lookupSingle (ssOps stA) SlotEncrypt)
        (lookupSingle (ssOps stR) SlotEncrypt)
      let (_, _, fin) = planCipherFinal (ssOps stR) stR SlotEncrypt "cipher"
      assertEqual ("final " ++ show cspec) CKR_OK (soCode fin)
      case soEffects fin of
        [FxCipher _ _ _ _ input] ->
          assertEqual ("effect input " ++ show cspec)
            (if csPad cspec then csBlock cspec else 0) (BS.length input)
        other -> assertFailure ("expected one final effect, got " ++ show other)

-- | Save one keyed sign-recovery slot directly: the baseline whose
-- trailing capacity\/tag fields the length tests mutate.
saveRecoverSlot :: RecoverSpec -> IO BS.ByteString
saveRecoverSlot rspec = do
  let sc = setBuffered "recover-me"
        (mkSlotCommon aesCbcMech OpSignRecover (Just (ObjectId 9))
          BS.empty AuthNone)
      stA = (mkSession (SessionId 1))
        { ssOps = insertOp
            (mkActiveRecover RoleSignRecover sc rspec) emptySessionOps }
  expectSaved modelWithTwoKeys stA Pkcs11_3_2 (SaveSlot SlotSign)

caseRecoverGeometry :: IO ()
caseRecoverGeometry = do
  good <- saveRecoverSlot (RecoverSpec 128 16)
  -- Golden frame: tag-3 suffix (roleB, capacity u32, tagLen u32).
  assertEqual "recover wire suffix"
    (BS.pack [0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x10])
    (BS.takeEnd 9 good)
  cipher <- saveCipherSlot (CipherSpec 16 False)
  let target = mkSession (SessionId 2)
      rejects label bytes =
        case restoreOperation defaultQuotas modelWithTwoKeys target
            Pkcs11_3_2 (RestoreSingle (Just keyHandle)) bytes of
          Left err@(RestoreMalformed _) -> do
            assertEqual (label ++ " code")
              CKR_SAVED_STATE_INVALID (restoreCode err)
            expectRestorePlan cipher target
          other -> assertFailure (label ++ " accepted: " ++ show other)
  rejects "capacity 0" (pokeU32 good 8 0)
  rejects "tag 0" (pokeU32 good 4 0)
  rejects "tag wider than capacity" (pokeU32 (pokeU32 good 8 16) 4 32)
  rejects "capacity 0 tag 0" (pokeU32 (pokeU32 good 8 0) 4 0)

-- | Save one keyed message slot directly with the given family and
-- cipher-spec presence.
saveMessageSlot :: MsgFamily -> Maybe CipherSpec -> IO BS.ByteString
saveMessageSlot fam mspec = do
  let sc = mkSlotCommon aesCbcMech (msgOperation fam) (Just (ObjectId 9))
        "0123456789abcdef" AuthNone
      ms = MsgState fam sc MsgIdle mspec 0
      stA = (mkSession (SessionId 1))
        { ssOps = insertOp (mkActiveMessage ms) emptySessionOps }
  expectSaved modelWithTwoKeys stA Pkcs11_3_2 (SaveSlot (msgFamilyKind fam))

caseMessagePresence :: IO ()
caseMessagePresence = do
  cipher <- saveCipherSlot (CipherSpec 16 False)
  let target = mkSession (SessionId 2)
      rejects label fam mspec = do
        bytes <- saveMessageSlot fam mspec
        case restoreOperation defaultQuotas modelWithTwoKeys target
            Pkcs11_3_2 (RestoreSingle (Just keyHandle)) bytes of
          Left err@(RestoreMalformed _) -> do
            assertEqual (label ++ " code")
              CKR_SAVED_STATE_INVALID (restoreCode err)
            expectRestorePlan cipher target
          other -> assertFailure (label ++ " accepted: " ++ show other)
  rejects "encrypt without spec" MsgEncrypt Nothing
  rejects "decrypt without spec" MsgDecrypt Nothing
  rejects "sign with spec" MsgSign (Just (CipherSpec 16 False))
  rejects "verify with spec" MsgVerify (Just (CipherSpec 16 False))
  rejects "encrypt with corrupt spec" MsgEncrypt (Just (CipherSpec 0 False))
  rejects "encrypt with wide spec" MsgEncrypt (Just (CipherSpec 1025 False))
  rejects "encrypt with padded 256" MsgEncrypt (Just (CipherSpec 256 True))
  -- Accepted control: a cipher family WITH a well-formed spec
  -- restores and plans a one-shot over the restored geometry.
  valid <- saveMessageSlot MsgEncrypt (Just (CipherSpec 16 False))
  -- Golden frame: message suffix (mspec-present flag, block u32,
  -- padB, delivered-count u32).
  assertEqual "message wire suffix"
    (BS.pack [0x01, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00])
    (BS.takeEnd 10 valid)
  stV <- case restoreOperation defaultQuotas modelWithTwoKeys target
      Pkcs11_3_2 (RestoreSingle (Just keyHandle)) valid of
    Left err -> assertFailure ("valid message rejected: " ++ show err) >> undefined
    Right s -> pure s
  let scV = mkSlotCommon aesCbcMech (msgOperation MsgEncrypt)
        (Just (ObjectId 9)) "0123456789abcdef" AuthNone
  assertEqual "message roundtrip"
    (Just (mkActiveMessage
      (MsgState MsgEncrypt scV MsgIdle (Just (CipherSpec 16 False)) 0)))
    (lookupSingle (ssOps stV) SlotEncrypt)
  let (_, _, mo) = planMessageOneShot (ssOps stV) stV MsgEncrypt "message"
        (MsgOneShotCipher BS.empty BS.empty "block#1-block#2-")
  assertEqual "message one-shot code" CKR_OK (soCode mo)
  assertEqual "message one-shot plans" 1 (length (soEffects mo))

-- | Save one dual operation directly with the given cipher shape.
saveDualSlot :: CipherSpec -> IO BS.ByteString
saveDualSlot cspec = do
  let dCommon = mkSlotCommon sha256Mech OpDigest Nothing BS.empty AuthNone
      cCommon = mkSlotCommon aesCbcMech OpEncrypt (Just (ObjectId 9))
        "0123456789abcdef" AuthNone
      stA = (mkSession (SessionId 1))
        { ssOps = setDual
            (Just (DualState dCommon cCommon DirEncrypt cspec Nothing))
            emptySessionOps }
  expectSaved modelWithTwoKeys stA Pkcs11_3_2 SaveDual

caseDualGeometry :: IO ()
caseDualGeometry = do
  -- Golden frame: a valid dual save ends with SPEC (block u32, padB)
  -- plus the empty dual-staged flag.
  let stA0 = mkSession (SessionId 1)
      (ops1, out1) = initDualOperation dualEnv (ssOps stA0) stA0
        digestArgs encryptArgs
  assertEqual "dual init code" CKR_OK (ioCode out1)
  valid <- expectSaved modelWithTwoKeys (stA0 { ssOps = ops1 })
    Pkcs11_3_2 SaveDual
  assertEqual "dual wire suffix"
    (BS.pack [0x00, 0x00, 0x00, 0x10, 0x00, 0x00])
    (BS.takeEnd 6 valid)
  -- Accepted control: the valid dual restores and plans a final
  -- over the restored geometry (one digest plus one cipher effect).
  stV <- case restoreOperation defaultQuotas modelWithTwoKeys
      (mkSession (SessionId 4)) Pkcs11_3_2
      (RestoreDual Nothing (Just keyHandle)) valid of
    Left err -> assertFailure ("valid dual rejected: " ++ show err) >> undefined
    Right s -> pure s
  assertEqual "dual roundtrip"
    (dualOf (ssOps (stA0 { ssOps = ops1 }))) (dualOf (ssOps stV))
  let (_, _, dfin) = planDualFinal (ssOps stV) stV
  assertEqual "dual final code" CKR_OK (soCode dfin)
  assertEqual "dual final plans" 2 (length (soEffects dfin))
  cipher <- saveCipherSlot (CipherSpec 16 False)
  let target = mkSession (SessionId 2)
      rejects label cspec = do
        bytes <- saveDualSlot cspec
        case restoreOperation defaultQuotas modelWithTwoKeys target
            Pkcs11_3_2 (RestoreDual Nothing (Just keyHandle)) bytes of
          Left err@(RestoreMalformed _) -> do
            assertEqual (label ++ " code")
              CKR_SAVED_STATE_INVALID (restoreCode err)
            expectRestorePlan cipher target
          other -> assertFailure (label ++ " accepted: " ++ show other)
  rejects "dual block 0" (CipherSpec 0 False)
  rejects "dual block 1025" (CipherSpec 1025 False)
  rejects "dual padded 256" (CipherSpec 256 True)

-- | A restored cipher slot keeps its buffer bound: one byte past
-- the restored buffer terminates the next update, while a total
-- exactly at the bound still plans.
casePreflightRestoredBuffer :: IO ()
casePreflightRestoredBuffer = do
  stFull <- restoreCipherBuffer (BS.replicate maxBuffered 0x41)
  let (opsF, _, over) = planCipherUpdate (ssOps stFull) stFull SlotEncrypt
        (BS.singleton 0x42) Nothing
  assertEqual "past-bound restored code" CKR_ARGUMENTS_BAD (soCode over)
  assertEqual "past-bound restored terminates" [] (activeSlots opsF)
  stRoom <- restoreCipherBuffer (BS.replicate (maxBuffered - 1) 0x41)
  let (_, _, u1) = planCipherUpdate (ssOps stRoom) stRoom SlotEncrypt
        (BS.singleton 0x42) Nothing
  assertEqual "boundary restored plans" CKR_OK (soCode u1)
  where
    restoreCipherBuffer :: BS.ByteString -> IO SessionState
    restoreCipherBuffer buf = do
      let sc = setBuffered buf
            (mkSlotCommon aesCbcMech OpEncrypt (Just (ObjectId 9))
              "0123456789abcdef" AuthNone)
          stA = (mkSession (SessionId 1))
            { ssOps = insertOp
                (mkActiveCipher DirEncrypt sc (CipherSpec 16 False)) emptySessionOps }
      bytes <- expectSaved modelWithAesKey stA Pkcs11_3_2 (SaveSlot SlotEncrypt)
      case restoreOperation defaultQuotas modelWithAesKey
          (mkSession (SessionId 2)) Pkcs11_3_2
          (RestoreSingle (Just keyHandle)) bytes of
        Left err -> assertFailure ("restore failed: " ++ show err) >> undefined
        Right s -> pure s
