{- | Decoded requests + pure admission.

The 'DecodedRequest' sum type carries already-decoded domain
values (templates, wanted lists, init arguments) from the FFI
boundary to the planner, so the planner never re-parses
'reqInput' on migrated paths. Equivalent requests through the C
adapter, the Haskell API ('planDecoded'), and the simulated
provider loop (plan → publish → re-read against a pure 'Model')
receive the same domain decision.

Session writability is decided once in pure core
('admitWritable', owner-aware per §5.7.1-5.7.3); the FFI owns
only the transport.

The Transition create/copy seams dissolve with decode hoisting
(decode is hoisted before admission on every path); the
KeyManagement seams align to parse-first after the same change.
-}
{-# LANGUAGE OverloadedStrings #-}
module DecodedRequestSpec (spec) where

import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import Control.Exception (bracket)
import Data.List (isInfixOf)
import Data.Either (isLeft)
import Data.IORef (atomicModifyIORef', newIORef, readIORef)
import qualified Data.Map.Strict as Map
import Data.Word (Word64, Word8)
import Foreign.C.Types (CULong (..))
import Foreign.Marshal.Alloc (alloca)
import Foreign.Marshal.Array (allocaArray)
import Foreign.Ptr (Ptr, castPtr, nullPtr)
import Foreign.StablePtr (StablePtr, newStablePtr)
import Foreign.Storable (peek, poke)
import System.Timeout (timeout)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertBool, assertEqual, assertFailure, testCase)

import Haskoki.Attribute (AttributeType (..), AttributeValue (..))
import Haskoki.Model
  ( HandleBinding (..)
  , Model (..)
  , ObjectState (..)
  , SessionState (..)
  , addToken
  , emptyModel
  , lookupHandle
  , lookupObject
  , lookupSession
  )
import Haskoki.Object (decodeHandle, encodeTemplate, encodeWanted)
import Haskoki.Outcome
  ( EffectRequest (..)
  , NativeOutput (..)
  , PlanResult (..)
  , PreparedCommit (..)
  , Rejection (..)
  , Reservation (..)
  )
import Haskoki.Engine.Backend (BackendEnv, CryptoBackend (..), EngineResult (..))
import Haskoki.Engine.OpenSSL4 (OpenSSL4)
import Haskoki.FFI.Exports (returnCodeToRV)
import Haskoki.FFI.Standard
  ( StdInstance (..)
  , haskokiStdClose
  , haskokiStdCopyObject
  , haskokiStdCreateObject
  , haskokiStdDestroyObject
  , haskokiStdDigestInit
  , haskokiStdFindInit
  , haskokiStdGenerateKey
  , haskokiStdGetOneAttr
  , haskokiStdLogin
  , haskokiStdOpenSession
  , haskokiStdSetAttributeValue
  , haskokiStdSignInit
  , haskokiStdWrapKey
  , nativeEncodeAttr
  , parseTemplateFrame
  )
import Haskoki.Operation.Codec (decodeInitInput, encodeInitInput)
import Haskoki.Operation (CipherDir (..), CryptoEffect (..), CryptoResult (..))
import Haskoki.Operation.Effect (DenyDetail (..), StepDeny (..), mkDeny)
import Haskoki.Operation.KeyManagement
  ( GenArgs (..)
  , KeyDeny (..)
  , KeyPlan (..)
  , PendingObject (..)
  , PendingWork (..)
  , aesCbcMech
  , aesKeyGenMech
  , decodeGenArgs
  , ecKeyPairGenMech
  , encodeGenArgs
  , keyPairCompatible
  , planAuthUnwrapKey
  , planGenerateKey
  , planGenerateKeyPair
  , planUnwrapKey
  )
import Haskoki.Registry (MechanismId (..), Operation (..))
import Haskoki.Request
  ( DecodedRequest (..)
  , FunctionId (..)
  , InitFunction (..)
  , Request (..)
  , initFunctionId
  , initOperation
  )
import Haskoki.Rules (Rules (..), defaultRules)
import Haskoki.Runtime.Async
  ( AsyncWork (..)
  , JobFunction (..)
  , JobRequest (..)
  , PollOutcome (..)
  , StartDeny (..)
  , TerminalState (..)
  , effectHoldable
  , enableAsyncSession
  , newAsyncTable
  , pollJob
  , startJob
  )
import Haskoki.Runtime.Lifecycle
  ( defaultInitArgs
  , initialize
  , newEnv
  , seatToken
  )
import Haskoki.Runtime.Storage (decodeReturnCode, encodeReturnCode)
import Haskoki.Session (AdmitDeny (..), SessionLogin (..), admitCode, admitPrivate, admitWritable)
import Haskoki.Transition (planCall, planDecoded, publishDelta)
import Haskoki.Types
  ( EngineResourceId (..)
  , ExternalHandle (..)
  , Outcome (..)
  , Pkcs11Version (..)
  , ReturnCode (..)
  , SessionId (..)
  , SlotId (..)
  )

spec :: TestTree
spec = testGroup "Decoded requests"
  [ testGroup "decoded requests"
    [ testCase "Create double-fault is ARGUMENTS_BAD" caseCreateDoubleFault
  , testCase "Create decides identically on all three paths" caseCreateEquivalence
  , testCase "Malformed create refused at every boundary" caseCreateBoundary
  , testCase "Decoders refuse cross-shaped bytes" caseDecoderBattery
  , testCase "Copy double-fault is ARGUMENTS_BAD" caseCopyDoubleFault
  , testCase "Find has no admission gate (guard)" caseFindNoGate
  , testCase "Get-attr has no admission gate (guard)" caseGetAttrNoGate
  , testCase "Copy decides identically on all three paths" caseCopyParity
  , testCase "Find parity (Haskell API vs sim)" caseFindParity
  , testCase "Get-attr parity (Haskell API vs sim)" caseGetAttrParity
  , testCase "Digest init decides identically on all three paths" caseInitEquivalence
  , testCase "Sign init parity on all three paths" caseKeyedInitParity
  , testCase "Init precedence unchanged (guards)" caseInitPrecedence
  , testCase "Init-function maps are total" caseInitFunctionMaps
  , testCase "Writability is one pure admission" casePureAdmission
  , testCase "Read-only code maps everywhere" caseCodeMaps
  , testCase "Param-invalid code maps everywhere" caseParamInvalidMaps
  , testCase "Key-size-range code maps everywhere" caseKeySizeRangeMaps
  , testCase "Read-only sessions enforce the owner dimension" caseRoRefusals
  , testCase "Session objects admitted on read-only sessions" caseRoTokenDimension
  , testCase "Read-only sessions read and compute" caseRoAllowed
  , testCase "Public sessions refuse private creation" casePublicPrivateRefusals
  , testCase "Context login needs an active operation" caseContextLoginOpGate
  , testCase "Copy VALUE_LEN mismatch refuses" caseCopyValueLenMismatch
  , testCase "Modifiable data object flow" caseModifiableDataFlow
  , testCase "DecodedRequest Show redacts templates" caseShowRedacts
  , testCase "Pre-master keygen forwards version params via C" casePremasterViaC
    ]
  , testGroup "async construction"
    [ testCase "Bytes job with FxDigestInit refused at submit" caseSubmitRefusesInit
    , testCase "Coherent jobs still submit (guard)" caseSubmitAcceptsCoherent
    , testCase "Holdability battery" caseHoldableBattery
    , testCase "Pair-coherence battery" casePairBattery
    , testCase "Mismatched pair refused before execution" caseDriveRefusesMismatch
    ]
  , testGroup "parse-first"
    [ testCase "Keygen double-fault is the template code" caseKeygenDoubleFault
    , testCase "Keypair double-fault is the validation code" caseKeypairDoubleFault
    , testCase "Unwrap double-fault is ARGUMENTS_BAD" caseUnwrapDoubleFault
    , testCase "Auth-unwrap double-fault is ARGUMENTS_BAD" caseAuthUnwrapDoubleFault
    ]
  ]

-- | 'DecodedRequest' 'Show' redacts decoded templates (following
-- the 'Request' precedent): template structure and bytes never
-- render; the shape tag still does.
caseShowRedacts :: IO ()
caseShowRedacts = do
  let dr = DRCreateObject (SessionId 1)
        [(AttrValueLen, ValULong 16), (AttrLabel, ValBytes "SECRET")]
      shown = show dr
  assertBool ("template structure leaked: " ++ shown)
    (not ("ValULong" `isInfixOf` shown))
  assertBool ("template bytes leaked: " ++ shown)
    (not ("SECRET" `isInfixOf` shown))
  assertBool ("shape lost: " ++ shown)
    ("DRCreateObject" `isInfixOf` shown)

-- ---------------------------------------------------------------------------
-- Harness (AdmissionSpec-shaped; small bound, test-local rules)
-- ---------------------------------------------------------------------------

rulesB :: Rules
rulesB = defaultRules { rulesMaxObjects = 8 }

slot0 :: SlotId
slot0 = SlotId 0

seeded :: Model
seeded = addToken emptyModel slot0

tmpl :: [(AttributeType, AttributeValue)]
tmpl = [(AttrClass, ValULong 0), (AttrLabel, ValBytes "a")]

mkRequest :: FunctionId -> Maybe SessionId -> Request
mkRequest fun mSid = Request
  { reqVersion = Pkcs11_3_2
  , reqFunction = fun
  , reqSession = mSid
  , reqHandle = Nothing
  , reqInput = mempty
  , reqRegions = []
  }

openSession :: Rules -> Model -> IO (SessionId, Model)
openSession rules model = do
  let req = (mkRequest F_OpenSession Nothing) { reqInput = "slot=0,rw" }
  case planCall rules model req of
    Immediate pc -> case publishDelta model (pcDelta pc) of
      Left fault -> assertFailure ("open delta fault: " ++ show fault)
      Right m' -> pure (SessionId (mNextSession model), m')
    other -> assertFailure ("open failed: " ++ show other)

createOne :: Rules -> Model -> SessionId -> IO (ExternalHandle, Model)
createOne rules model sid = do
  let req = (mkRequest F_CreateObject (Just sid))
        { reqInput = encodeTemplate tmpl }
  case planCall rules model req of
    Immediate pc -> case publishDelta model (pcDelta pc) of
      Left fault -> assertFailure ("create delta fault: " ++ show fault)
      Right m' -> do
        h <- commitHandle pc
        pure (h, m')
    Reject rej -> assertFailure
      ("fill create rejected early: " ++ show (rejCode rej))
    Execute _ _ -> assertFailure "fill create executed (impossible)"

commitHandle :: PreparedCommit -> IO ExternalHandle
commitHandle pc = case pcOutputs pc of
  [NativeOutput _ bs] -> case decodeHandle bs of
    Just h -> pure h
    Nothing -> assertFailure "handle output undecodable"
  outs -> assertFailure ("expected one handle output, got: " ++ show outs)

fillObjects :: Rules -> SessionId -> Int -> Model -> IO Model
fillObjects _ _ 0 m = pure m
fillObjects rules sid n m = do
  (_, m') <- createOne rules m sid
  fillObjects rules sid (n - 1) m'

-- ---------------------------------------------------------------------------
-- The Transition create seam admits before it validates.
-- Before decode hoisting, a full store plus malformed bytes refused
-- HOST_MEMORY; hoisted decode (completed in the parse-first
-- alignment) refuses ARGUMENTS_BAD instead. Fail-safe either way.
-- ---------------------------------------------------------------------------

caseCreateDoubleFault :: IO ()
caseCreateDoubleFault = do
  (sid, m1) <- openSession rulesB seeded
  mFull <- fillObjects rulesB sid 8 m1
  assertEqual "filled to the bound" 8 (Map.size (mObjects mFull))
  -- One byte: shorter than a template entry header, so
  -- 'parseTemplate' fails closed.
  let bad = (mkRequest F_CreateObject (Just sid)) { reqInput = BS.singleton 0xFF }
  case planCall rulesB mFull bad of
    Reject rej -> assertEqual "double-fault code" CKR_ARGUMENTS_BAD (rejCode rej)
    Immediate pc -> assertFailure
      ("malformed create committed at a full store: " ++ show (pcCode pc))
    Execute _ _ -> assertFailure "malformed create executed (impossible)"

-- ---------------------------------------------------------------------------
-- The Transition copy seam admits before it validates
-- (same flip as create); find and get-attribute carry no
-- admission gate, so their malformed-input refusal is unchanged.
-- ---------------------------------------------------------------------------

caseCopyDoubleFault :: IO ()
caseCopyDoubleFault = do
  (sid, m1) <- openSession rulesB seeded
  (h1, m2) <- createOne rulesB m1 sid
  mFull <- fillObjects rulesB sid 7 m2
  assertEqual "filled to the bound" 8 (Map.size (mObjects mFull))
  let bad = (mkRequest F_CopyObject (Just sid))
        { reqHandle = Just h1, reqInput = BS.singleton 0xFF }
  case planCall rulesB mFull bad of
    Reject rej -> assertEqual "double-fault code" CKR_ARGUMENTS_BAD (rejCode rej)
    Immediate pc -> assertFailure
      ("malformed copy committed at a full store: " ++ show (pcCode pc))
    Execute _ _ -> assertFailure "malformed copy executed (impossible)"

caseFindNoGate :: IO ()
caseFindNoGate = do
  (sid, m1) <- openSession rulesB seeded
  mFull <- fillObjects rulesB sid 8 m1
  let bad = (mkRequest F_FindObjects (Just sid))
        { reqInput = BS.singleton 0xFF }
  case planCall rulesB mFull bad of
    Reject rej -> assertEqual "malformed find code" CKR_ARGUMENTS_BAD (rejCode rej)
    other -> assertFailure ("malformed find accepted: " ++ show other)

caseGetAttrNoGate :: IO ()
caseGetAttrNoGate = do
  (sid, m1) <- openSession rulesB seeded
  (h1, m2) <- createOne rulesB m1 sid
  mFull <- fillObjects rulesB sid 7 m2
  -- 0xFF is past the attribute-tag enum, so 'parseWanted' fails.
  let bad = (mkRequest F_GetAttributeValue (Just sid))
        { reqHandle = Just h1, reqInput = BS.singleton 0xFF }
  case planCall rulesB mFull bad of
    Reject rej -> assertEqual "malformed wanted code" CKR_ARGUMENTS_BAD (rejCode rej)
    other -> assertFailure ("malformed wanted accepted: " ++ show other)

-- ---------------------------------------------------------------------------
-- Three-path equivalence (C adapter / Haskell API / sim).
-- ---------------------------------------------------------------------------

-- | The same create request decides identically through the C
-- adapter ('haskokiStdCreateObject' on a live manual instance), the
-- Haskell API ('planDecoded' on a 'DecodedRequest'), and the
-- simulated provider loop ('planCall' on wire bytes + 'publishDelta'
-- + model re-read): same code, same handle, same stored object.
caseCreateEquivalence :: IO ()
caseCreateEquivalence = do
  mTimed <- timeout 30000000 $ do
    -- C adapter path: live manual instance, fresh RW session.
    (cRv, cH) <- withManualInstance [slot0] $ \inst -> do
      hSession <- openRwSession inst 0
      createViaC inst hSession (frameOf tmpl)
    assertEqual "C adapter rv" (CULong 0) cRv
    -- Haskell API path: 'planDecoded' on a scratch model.
    (sidH, mH0) <- openSession defaultRules seeded
    hH <- case planDecoded defaultRules mH0 (DRCreateObject sidH tmpl) of
      Immediate pc -> do
        assertEqual "Haskell API code" CKR_OK (pcCode pc)
        commitHandle pc
      Reject rej -> assertFailure
        ("Haskell API rejected a valid create: " ++ show (rejCode rej))
      Execute _ _ -> assertFailure "Haskell API executed a create (impossible)"
    assertEqual "C adapter and Haskell API agree on the handle" cH hH
    -- Simulated provider loop: wire bytes through 'planCall',
    -- publish, re-read the stored object.
    (sidS, mS0) <- openSession defaultRules seeded
    let wire = (mkRequest F_CreateObject (Just sidS))
          { reqInput = encodeTemplate tmpl }
    case planCall defaultRules mS0 wire of
      Immediate pc -> do
        assertEqual "sim code" CKR_OK (pcCode pc)
        hS <- commitHandle pc
        assertEqual "sim agrees on the handle" cH hS
        case publishDelta mS0 (pcDelta pc) of
          Left fault -> assertFailure ("sim delta fault: " ++ show fault)
          Right mS1 -> case lookupHandle mS1 hS >>= lookupObject mS1 . hbObject of
            Nothing -> assertFailure "sim stored object unresolvable"
            Just ost -> assertEqual "sim stored attributes"
              (Map.fromList tmpl) (osAttrs ost)
      Reject rej -> assertFailure
        ("sim rejected a valid create: " ++ show (rejCode rej))
      Execute _ _ -> assertFailure "sim executed a create (impossible)"
  case mTimed of
    Nothing -> assertFailure "create equivalence wedged (30s timeout)"
    Just () -> pure ()

-- | Malformed create bytes refuse at every representation
-- boundary: a truncated frame refuses at the C adapter with
-- @CKR_ARGUMENTS_BAD@ (never reaching the planner), and malformed
-- wire bytes refuse through the Haskell bytes path with the same
-- code.
caseCreateBoundary :: IO ()
caseCreateBoundary = do
  mTimed <- timeout 30000000 $ do
    (cRv, _) <- withManualInstance [slot0] $ \inst -> do
      hSession <- openRwSession inst 0
      -- One record header, no record body: truncated.
      createViaC inst hSession (word 1 <> word 0x00)
    assertEqual "C adapter frame rv" (CULong 0x07) cRv
    (sid, m0) <- openSession defaultRules seeded
    let bad = (mkRequest F_CreateObject (Just sid))
          { reqInput = BS.singleton 0xFF }
    case planCall defaultRules m0 bad of
      Reject rej -> assertEqual "bytes-path code" CKR_ARGUMENTS_BAD (rejCode rej)
      other -> assertFailure ("malformed bytes accepted: " ++ show other)
  case mTimed of
    Nothing -> assertFailure "create boundary wedged (30s timeout)"
    Just () -> pure ()

-- | The validated boundary decoders refuse cross-shaped bytes: an
-- init frame is not a template frame, and init bytes with a
-- reserved permit bit set are not init arguments. (Positive
-- controls pin the decoders still accept their own shapes, so the
-- battery cannot pass vacuously.)
caseDecoderBattery :: IO ()
caseDecoderBattery = do
  let goodInit = encodeInitInput (MechanismId 0x250) [] False "params"
  assertBool "init frame refused as a template frame"
    (isLeft (parseTemplateFrame goodInit))
  assertBool "reserved permit bit refused"
    (decodeInitInput (setReservedBit goodInit) == Nothing)
  case decodeInitInput goodInit of
    Just (MechanismId 0x250, [], False, "params") -> pure ()
    other -> assertFailure ("valid init rejected: " ++ show other)
  case parseTemplateFrame (frameOf tmpl) of
    Right entries -> assertEqual "valid frame decodes" tmpl entries
    Left err -> assertFailure ("valid frame refused: " ++ show err)
  where
    -- Permit bits live in bytes 8-9 (big-endian u16); set reserved
    -- bit 14 so the reserved-bits guard must fail.
    setReservedBit bs =
      let (h, t) = BS.splitAt 8 bs
      in h <> BS.singleton 0x40 <> BS.drop 1 t

-- ---------------------------------------------------------------------------
-- Copy/find/get-attribute parity.
-- ---------------------------------------------------------------------------

-- | The same copy request decides identically through the C
-- adapter, the Haskell API, and the simulated provider loop: same
-- code, same handle, same merged label. An unknown source handle
-- refuses identically on the Haskell and sim paths.
caseCopyParity :: IO ()
caseCopyParity = do
  mTimed <- timeout 30000000 $ do
    let over = [(AttrLabel, ValBytes "b")]
    -- C adapter path: create then copy through the C surface.
    (cRv, cH) <- withManualInstance [slot0] $ \inst -> do
      hSession <- openRwSession inst 0
      (rvC, hC) <- createViaC inst hSession (frameOf tmpl)
      assertEqual "C create rv" (CULong 0) rvC
      copyViaC inst hSession hC (frameOf over)
    assertEqual "C adapter copy rv" (CULong 0) cRv
    -- Haskell API path on a scratch model.
    (sidH, mH0) <- openSession defaultRules seeded
    pcH <- createDecoded mH0 sidH tmpl
    mH1 <- publishOne mH0 pcH
    h1H <- commitHandle pcH
    h2H <- case planDecoded defaultRules mH1 (DRCopyObject sidH h1H over) of
      Immediate pc -> do
        assertEqual "Haskell API copy code" CKR_OK (pcCode pc)
        commitHandle pc
      other -> assertFailure ("Haskell API copy failed: " ++ show other)
    assertEqual "C adapter and Haskell API agree on the copy handle" cH h2H
    -- Simulated provider loop: wire bytes through 'planCall'.
    (sidS, mS0) <- openSession defaultRules seeded
    pcS <- createDecoded mS0 sidS tmpl
    mS1 <- publishOne mS0 pcS
    h1S <- commitHandle pcS
    let wire = (mkRequest F_CopyObject (Just sidS))
          { reqHandle = Just h1S, reqInput = encodeTemplate over }
    case planCall defaultRules mS1 wire of
      Immediate pc -> do
        assertEqual "sim copy code" CKR_OK (pcCode pc)
        h2S <- commitHandle pc
        assertEqual "sim agrees on the copy handle" cH h2S
      other -> assertFailure ("sim copy failed: " ++ show other)
    -- Unknown source refuses identically (Haskell API vs sim).
    let unknown = ExternalHandle 9999
    case planDecoded defaultRules mH1 (DRCopyObject sidH unknown over) of
      Reject rej -> assertEqual "Haskell unknown-source code"
        CKR_OBJECT_HANDLE_INVALID (rejCode rej)
      other -> assertFailure ("Haskell copy of unknown accepted: " ++ show other)
    let wireBad = (mkRequest F_CopyObject (Just sidH))
          { reqHandle = Just unknown, reqInput = encodeTemplate over }
    case planCall defaultRules mH1 wireBad of
      Reject rej -> assertEqual "sim unknown-source code"
        CKR_OBJECT_HANDLE_INVALID (rejCode rej)
      other -> assertFailure ("sim copy of unknown accepted: " ++ show other)
  case mTimed of
    Nothing -> assertFailure "copy parity wedged (30s timeout)"
    Just () -> pure ()

-- | Plan one decoded create (helper for parity setups).
createDecoded :: Model -> SessionId -> [(AttributeType, AttributeValue)] -> IO PreparedCommit
createDecoded m sid t = case planDecoded defaultRules m (DRCreateObject sid t) of
  Immediate pc -> pure pc
  other -> assertFailure ("decoded setup create failed: " ++ show other)

-- | Publish one commit into a model (helper for parity setups).
publishOne :: Model -> PreparedCommit -> IO Model
publishOne m pc = case publishDelta m (pcDelta pc) of
  Left fault -> assertFailure ("setup delta fault: " ++ show fault)
  Right m' -> pure m'

-- | Publish one decoded create into a model (helper for parity setups).
publishModel :: Model -> SessionId -> [(AttributeType, AttributeValue)] -> IO Model
publishModel m sid t = createDecoded m sid t >>= publishOne m

-- | Find parity: the same template finds the same handles through
-- the Haskell API and the sim bytes path (valid template, empty
-- template, and malformed bytes).
caseFindParity :: IO ()
caseFindParity = do
  (sid, m0) <- openSession defaultRules seeded
  m1 <- publishModel m0 sid tmpl
  m2 <- publishModel m1 sid [(AttrClass, ValULong 0), (AttrLabel, ValBytes "b")]
  let check q = do
        outsH <- case planDecoded defaultRules m2 (DRFindObjects sid q) of
          Immediate pc -> pure (pcCode pc, pcOutputs pc)
          other -> assertFailure ("Haskell find failed: " ++ show other)
        let wire = (mkRequest F_FindObjects (Just sid))
              { reqInput = encodeTemplate q }
        outsS <- case planCall defaultRules m2 wire of
          Immediate pc -> pure (pcCode pc, pcOutputs pc)
          other -> assertFailure ("sim find failed: " ++ show other)
        assertEqual ("find parity for " ++ show q) outsH outsS
  check [(AttrLabel, ValBytes "a")]
  check []
  -- Malformed bytes refuse identically.
  let bad = (mkRequest F_FindObjects (Just sid)) { reqInput = BS.singleton 0xFF }
  case planCall defaultRules m2 bad of
    Reject rej -> assertEqual "sim malformed find" CKR_ARGUMENTS_BAD (rejCode rej)
    other -> assertFailure ("sim malformed find accepted: " ++ show other)

-- | Get-attribute parity: the same wanted list reads the same value
-- bytes through the Haskell API and the sim bytes path; malformed
-- wanted lists and unknown handles refuse identically.
caseGetAttrParity :: IO ()
caseGetAttrParity = do
  (sid, m0) <- openSession defaultRules seeded
  pc <- createDecoded m0 sid tmpl
  m1 <- publishOne m0 pc
  h1 <- commitHandle pc
  let check wanted = do
        outsH <- case planDecoded defaultRules m1 (DRGetAttributeValue sid h1 wanted) of
          Immediate pc' -> pure (pcCode pc', pcOutputs pc')
          other -> assertFailure ("Haskell get-attr failed: " ++ show other)
        let wire = (mkRequest F_GetAttributeValue (Just sid))
              { reqHandle = Just h1, reqInput = encodeWanted wanted }
        outsS <- case planCall defaultRules m1 wire of
          Immediate pc' -> pure (pcCode pc', pcOutputs pc')
          other -> assertFailure ("sim get-attr failed: " ++ show other)
        assertEqual ("get-attr parity for " ++ show wanted) outsH outsS
  check [AttrLabel]
  check [AttrClass]
  let badWanted = (mkRequest F_GetAttributeValue (Just sid))
        { reqHandle = Just h1, reqInput = BS.singleton 0xFF }
  case planCall defaultRules m1 badWanted of
    Reject rej -> assertEqual "sim malformed wanted" CKR_ARGUMENTS_BAD (rejCode rej)
    other -> assertFailure ("sim malformed wanted accepted: " ++ show other)
  case planDecoded defaultRules m1 (DRGetAttributeValue sid (ExternalHandle 9999) [AttrLabel]) of
    Reject rej -> assertEqual "Haskell unknown-handle code"
      CKR_OBJECT_HANDLE_INVALID (rejCode rej)
    other -> assertFailure ("Haskell get-attr of unknown accepted: " ++ show other)

-- ---------------------------------------------------------------------------
-- Key-init equivalence (digest init + sign init).
-- ---------------------------------------------------------------------------

sha256Mech, hmacMech :: MechanismId
sha256Mech = MechanismId 0x250
hmacMech = MechanismId 0x251

-- | One sign-capable HMAC key template (mirrors the AdmissionSpec
-- derive base, with the sign mark instead of the derive mark).
signKeyTmpl :: [(AttributeType, AttributeValue)]
signKeyTmpl =
  [ (AttrClass, ValULong 4)
  , (AttrKeyType, ValULong 0x10)
  , (AttrToken, ValBool False)
  , (AttrSign, ValBool True)
  , (AttrValue, ValBytes (BS.replicate 32 0x6B))
  ]

-- | The same digest init decides identically on all three paths:
-- the C adapter drives it to OK, and the Haskell API and the sim
-- bytes path plan the identical effect.
caseInitEquivalence :: IO ()
caseInitEquivalence = do
  mTimed <- timeout 30000000 $ do
    cRv <- withManualInstance [slot0] $ \inst -> do
      hSession <- openRwSession inst 0
      digestInitViaC inst hSession sha256Mech BS.empty
    assertEqual "C adapter digest-init rv" (CULong 0) cRv
    (sidH, mH0) <- openSession defaultRules seeded
    fxH <- case planDecoded defaultRules mH0
        (DRInit sidH InitDigest Nothing sha256Mech [] False BS.empty) of
      Execute res (EffectCrypto fx) -> do
        assertEqual "Haskell op tag" "digest" (resOperation res)
        pure fx
      other -> assertFailure ("Haskell digest init did not execute: " ++ show other)
    assertEqual "Haskell plans the digest-alloc effect"
      (FxDigestInit sha256Mech) fxH
    (sidS, mS0) <- openSession defaultRules seeded
    let wire = (mkRequest F_DigestInit (Just sidS))
          { reqInput = encodeInitInput sha256Mech [] False BS.empty }
    case planCall defaultRules mS0 wire of
      Execute _ (EffectCrypto fxS) ->
        assertEqual "sim plans the identical effect" fxH fxS
      other -> assertFailure ("sim digest init did not execute: " ++ show other)
  case mTimed of
    Nothing -> assertFailure "init equivalence wedged (30s timeout)"
    Just () -> pure ()

-- | The same sign init decides identically on all three paths: the
-- C adapter drives it to OK over a C-created key, and the Haskell
-- API and sim bytes path commit identically over a matching key.
caseKeyedInitParity :: IO ()
caseKeyedInitParity = do
  mTimed <- timeout 30000000 $ do
    cRv <- withManualInstance [slot0] $ \inst -> do
      hSession <- openRwSession inst 0
      (rvC, hC) <- createViaC inst hSession (frameOf signKeyTmpl)
      assertEqual "C key-create rv" (CULong 0) rvC
      signInitViaC inst hSession hmacMech BS.empty hC
    assertEqual "C adapter sign-init rv" (CULong 0) cRv
    (sidH, mH0) <- openSession defaultRules seeded
    pcH <- createDecoded mH0 sidH signKeyTmpl
    mH1 <- publishOne mH0 pcH
    hH <- commitHandle pcH
    delH <- case planDecoded defaultRules mH1
        (DRInit sidH InitSign (Just hH) hmacMech [OpSign] False BS.empty) of
      Immediate pc -> pure (pcCode pc, pcDelta pc)
      other -> assertFailure ("Haskell sign init failed: " ++ show other)
    assertEqual "Haskell sign-init code" CKR_OK (fst delH)
    let wire = (mkRequest F_SignInit (Just sidH))
          { reqHandle = Just hH
          , reqInput = encodeInitInput hmacMech [OpSign] False BS.empty
          }
    case planCall defaultRules mH1 wire of
      Immediate pc -> assertEqual "sim commits identically" delH (pcCode pc, pcDelta pc)
      other -> assertFailure ("sim sign init failed: " ++ show other)
  case mTimed of
    Nothing -> assertFailure "keyed-init parity wedged (30s timeout)"
    Just () -> pure ()

-- | Init precedence is unchanged by the migration (guards): an
-- unknown session refuses before any decode on every init shape,
-- and malformed bytes refuse with ARGUMENTS_BAD on a live session.
caseInitPrecedence :: IO ()
caseInitPrecedence = do
  (sid, m0) <- openSession defaultRules seeded
  let funs = [F_DigestInit, F_SignInit, F_VerifyInit, F_EncryptInit, F_DecryptInit]
      badLive fun = (mkRequest fun (Just sid)) { reqInput = BS.singleton 0xFF }
      badGone fun = (mkRequest fun (Just (SessionId 9999)))
        { reqInput = BS.singleton 0xFF }
  mapM_ (\fun -> case planCall defaultRules m0 (badLive fun) of
      Reject rej -> assertEqual ("live malformed " ++ show fun)
        CKR_ARGUMENTS_BAD (rejCode rej)
      other -> assertFailure ("live malformed accepted: " ++ show other)) funs
  mapM_ (\fun -> case planCall defaultRules m0 (badGone fun) of
      Reject rej -> assertEqual ("unknown session " ++ show fun)
        CKR_SESSION_HANDLE_INVALID (rejCode rej)
      other -> assertFailure ("unknown session accepted: " ++ show other)) funs

-- | Every init function maps to exactly one planner function id
-- and one registry operation (the pair is derived, never supplied
-- twice, so an init/function mismatch is unrepresentable).
caseInitFunctionMaps :: IO ()
caseInitFunctionMaps = do
  let rows =
        [ (InitDigest, F_DigestInit, OpDigest)
        , (InitSign, F_SignInit, OpSign)
        , (InitVerify, F_VerifyInit, OpVerify)
        , (InitEncrypt, F_EncryptInit, OpEncrypt)
        , (InitDecrypt, F_DecryptInit, OpDecrypt)
        ]
  mapM_ (\(ifunc, fun, op) -> do
    assertEqual ("function id of " ++ show ifunc) fun (initFunctionId ifunc)
    assertEqual ("operation of " ++ show ifunc) op (initOperation ifunc)) rows
  assertEqual "all init functions mapped"
    [InitDigest, InitSign, InitVerify, InitEncrypt, InitDecrypt]
    [minBound .. maxBound :: InitFunction]

-- ---------------------------------------------------------------------------
-- Pure writability admission + read-only matrix.
-- ---------------------------------------------------------------------------

-- | Writability is decided once in pure core: a read/write session
-- admits every owner, a read-only session admits session objects
-- and denies token objects with 'AdmitReadOnly', which maps to
-- 'CKR_SESSION_READ_ONLY'.
casePureAdmission :: IO ()
casePureAdmission = do
  assertEqual "writable admits session" (Right ()) (admitWritable False False)
  assertEqual "writable admits token" (Right ()) (admitWritable False True)
  assertEqual "read-only admits session" (Right ()) (admitWritable True False)
  assertEqual "read-only denies token" (Left AdmitReadOnly) (admitWritable True True)
  assertEqual "denial code" CKR_SESSION_READ_ONLY (admitCode AdmitReadOnly)
  assertEqual "public creating private denies"
    (Left AdmitLoginRequired) (admitPrivate LoginPublic True)
  assertEqual "public creating public admits"
    (Right ()) (admitPrivate LoginPublic False)
  assertEqual "user creating private admits"
    (Right ()) (admitPrivate LoginUser True)
  assertEqual "login denial code" CKR_USER_NOT_LOGGED_IN (admitCode AdmitLoginRequired)

-- | The read-only code maps identically at every boundary: the
-- C value (locked header @CKR_SESSION_READ_ONLY = 0xB5@), the
-- stored document name, and the denial category (session-state,
-- like every other session code).
caseCodeMaps :: IO ()
caseCodeMaps = do
  assertEqual "C value" 0xB5 (returnCodeToRV CKR_SESSION_READ_ONLY)
  assertEqual "stored name" "CKR_SESSION_READ_ONLY"
    (encodeReturnCode CKR_SESSION_READ_ONLY)
  assertEqual "stored round-trip" (Just CKR_SESSION_READ_ONLY)
    (decodeReturnCode "CKR_SESSION_READ_ONLY")
  assertEqual "denial category"
    (StepDeny CKR_SESSION_READ_ONLY (DenyOpState "w"))
    (mkDeny CKR_SESSION_READ_ONLY "w")

-- | The mechanism-param code maps identically at every boundary:
-- the C value (locked header @CKR_MECHANISM_PARAM_INVALID = 0x71@),
-- the stored document name, and the denial category (bad-params,
-- like every other parameter refusal).
caseParamInvalidMaps :: IO ()
caseParamInvalidMaps = do
  assertEqual "C value" 0x71 (returnCodeToRV CKR_MECHANISM_PARAM_INVALID)
  assertEqual "stored name" "CKR_MECHANISM_PARAM_INVALID"
    (encodeReturnCode CKR_MECHANISM_PARAM_INVALID)
  assertEqual "stored round-trip" (Just CKR_MECHANISM_PARAM_INVALID)
    (decodeReturnCode "CKR_MECHANISM_PARAM_INVALID")
  assertEqual "denial category"
    (StepDeny CKR_MECHANISM_PARAM_INVALID (DenyBadParams "w"))
    (mkDeny CKR_MECHANISM_PARAM_INVALID "w")

-- | The key-size-range code maps identically at every boundary:
-- the C value (locked header @CKR_KEY_SIZE_RANGE = 0x62@), the
-- stored document name, and the denial category (range, like the
-- data-length code).
caseKeySizeRangeMaps :: IO ()
caseKeySizeRangeMaps = do
  assertEqual "C value" 0x62 (returnCodeToRV CKR_KEY_SIZE_RANGE)
  assertEqual "stored name" "CKR_KEY_SIZE_RANGE"
    (encodeReturnCode CKR_KEY_SIZE_RANGE)
  assertEqual "stored round-trip" (Just CKR_KEY_SIZE_RANGE)
    (decodeReturnCode "CKR_KEY_SIZE_RANGE")
  assertEqual "denial category"
    (StepDeny CKR_KEY_SIZE_RANGE (DenyRange "w"))
    (mkDeny CKR_KEY_SIZE_RANGE "w")

-- | Read-only sessions enforce the owner dimension through the C
-- adapter (§5.7.1-5.7.3): session-object create, copy,
-- set-attributes, destroy, and generate admit; the token-object
-- counterparts refuse with @CKR_SESSION_READ_ONLY@. Wrap creates
-- no object and is ungated.
caseRoRefusals :: IO ()
caseRoRefusals = do
  mTimed <- timeout 60000000 $ withManualInstance [slot0] $ \inst -> do
    hRW <- openRwSession inst 0
    hRO <- openRoSession inst 0
    let sessionTmpl = tmpl ++ [(AttrToken, ValBool False)]
        tokenTmpl = tmpl ++ [(AttrToken, ValBool True)]
        labelOver = frameOf [(AttrLabel, ValBytes "b")]
    -- Create: session admits, token refuses.
    (rvCS, _) <- createViaC inst hRO (frameOf sessionTmpl)
    assertEqual "RO session-object create" (CULong 0) rvCS
    (rvCT, _) <- createViaC inst hRO (frameOf tokenTmpl)
    assertEqual "RO token-object create" (CULong 0xB5) rvCT
    -- Copy, set-attributes, destroy (objects made over RW).
    (rvC, hC) <- createViaC inst hRW (frameOf sessionTmpl)
    assertEqual "RW session create" (CULong 0) rvC
    (rvT, hT) <- createViaC inst hRW (frameOf tokenTmpl)
    assertEqual "RW token create" (CULong 0) rvT
    (rvCopyS, _) <- copyViaC inst hRO hC labelOver
    assertEqual "RO session copy" (CULong 0) rvCopyS
    (rvCopyT, _) <- copyViaC inst hRO hT labelOver
    assertEqual "RO token copy" (CULong 0xB5) rvCopyT
    (rvCopyP, _) <- copyViaC inst hRO hC (frameOf [(AttrToken, ValBool True)])
    assertEqual "RO copy promoting to token" (CULong 0xB5) rvCopyP
    rvSetS <- setViaC inst hRO hC labelOver
    assertEqual "RO session set-attributes" (CULong 0) rvSetS
    rvSetT <- setViaC inst hRO hT labelOver
    assertEqual "RO token set-attributes" (CULong 0xB5) rvSetT
    rvDestroyS <- haskokiStdDestroyObject inst hRO (cuLongOf hC)
    assertEqual "RO session destroy" (CULong 0) rvDestroyS
    rvDestroyT <- haskokiStdDestroyObject inst hRO (cuLongOf hT)
    assertEqual "RO token destroy" (CULong 0xB5) rvDestroyT
    -- Generate: session admits, token refuses.
    rvGenS <- generateViaC inst hRO (MechanismId 0x1080) BS.empty (frameOf aesGenTmpl)
    assertEqual "RO session generate" (CULong 0) rvGenS
    rvGenT <- generateViaC inst hRO (MechanismId 0x1080) BS.empty (frameOf aesGenTokenTmpl)
    assertEqual "RO token generate" (CULong 0xB5) rvGenT
    -- Wrap is ungated (keys made over the RW session).
    (rvW, hW) <- createViaC inst hRW (frameOf wrapKeyTmpl)
    assertEqual "RW wrapper create" (CULong 0) rvW
    (rvT2, hT2) <- createViaC inst hRW (frameOf targetKeyTmpl)
    assertEqual "RW target create" (CULong 0) rvT2
    rvWrap <- wrapViaC inst hRO (MechanismId 0x1082) (BS.replicate 16 0) hW hT2
    assertEqual "RO wrap admitted" (CULong 0) rvWrap
  case mTimed of
    Nothing -> assertFailure "RO refusals wedged (60s timeout)"
    Just () -> pure ()

-- | The §5.7 owner dimension, pinned end to end on create:
-- read-only sessions admit session objects and refuse token
-- objects; read/write sessions admit both.
caseRoTokenDimension :: IO ()
caseRoTokenDimension = do
  mTimed <- timeout 30000000 $ withManualInstance [slot0] $ \inst -> do
    hRW <- openRwSession inst 0
    hRO <- openRoSession inst 0
    let sessionTmpl = tmpl ++ [(AttrToken, ValBool False)]
        tokenTmpl = tmpl ++ [(AttrToken, ValBool True)]
    (rvSO, _) <- createViaC inst hRO (frameOf sessionTmpl)
    assertEqual "RO session-object create admitted" (CULong 0) rvSO
    (rvTO, _) <- createViaC inst hRO (frameOf tokenTmpl)
    assertEqual "RO token-object create refused" (CULong 0xB5) rvTO
    (rvRWS, _) <- createViaC inst hRW (frameOf sessionTmpl)
    assertEqual "RW session-object create" (CULong 0) rvRWS
    (rvRWT, _) <- createViaC inst hRW (frameOf tokenTmpl)
    assertEqual "RW token-object create" (CULong 0) rvRWT
  case mTimed of
    Nothing -> assertFailure "RO token dimension wedged (30s timeout)"
    Just () -> pure ()

-- | Read-only sessions still read and compute:
-- find, single-attribute read, and digest init all succeed.
caseRoAllowed :: IO ()
caseRoAllowed = do
  mTimed <- timeout 30000000 $ withManualInstance [slot0] $ \inst -> do
    hRW <- openRwSession inst 0
    hRO <- openRoSession inst 0
    (rvC, hC) <- createViaC inst hRW (frameOf tmpl)
    assertEqual "RW create" (CULong 0) rvC
    rvFind <- findInitViaC inst hRO (frameOf [])
    assertEqual "RO find-init" (CULong 0) rvFind
    rvAttr <- getOneAttrViaC inst hRO hC 0x03
    assertEqual "RO get-attr" (CULong 0) rvAttr
    rvDigest <- digestInitViaC inst hRO sha256Mech BS.empty
    assertEqual "RO digest-init" (CULong 0) rvDigest
  case mTimed of
    Nothing -> assertFailure "RO allowed wedged (30s timeout)"
    Just () -> pure ()

-- | Public (unauthenticated) sessions refuse private-object
-- creation with @CKR_USER_NOT_LOGGED_IN@: token objects, session
-- objects, and copies landing private. Public creation on the
-- same session still admits.
casePublicPrivateRefusals :: IO ()
casePublicPrivateRefusals = do
  mTimed <- timeout 30000000 $ withManualInstance [slot0] $ \inst -> do
    hRW <- openRwSession inst 0
    let privTok = tmpl ++ [(AttrToken, ValBool True), (AttrPrivate, ValBool True)]
        privSes = tmpl ++ [(AttrToken, ValBool False), (AttrPrivate, ValBool True)]
    (rvT, _) <- createViaC inst hRW (frameOf privTok)
    assertEqual "public create private token" (CULong 0x101) rvT
    (rvS, _) <- createViaC inst hRW (frameOf privSes)
    assertEqual "public create private session" (CULong 0x101) rvS
    (rvC, hC) <- createViaC inst hRW (frameOf tmpl)
    assertEqual "public create public" (CULong 0) rvC
    (rvCopy, _) <- copyViaC inst hRW hC (frameOf [(AttrPrivate, ValBool True)])
    assertEqual "public copy to private" (CULong 0x101) rvCopy
  case mTimed of
    Nothing -> assertFailure "public/private refusals wedged (30s timeout)"
    Just () -> pure ()

-- | Context login through the C adapter needs an active operation
-- to re-authenticate: user login on A, then context login on B
-- refuses while B is idle and grants once B holds a digest.
caseContextLoginOpGate :: IO ()
caseContextLoginOpGate = do
  mTimed <- timeout 30000000 $ withManualInstance [slot0] $ \inst -> do
    hA <- openRwSession inst 0
    hB <- openRwSession inst 0
    rvLogin <- loginViaC inst hA 1 "1234"
    assertEqual "user login" (CULong 0) rvLogin
    rvBare <- loginViaC inst hB 2 "1234"
    assertEqual "context without op" (CULong 0x91) rvBare
    rvInit <- digestInitViaC inst hB sha256Mech BS.empty
    assertEqual "digest init" (CULong 0) rvInit
    rvCtx <- loginViaC inst hB 2 "1234"
    assertEqual "context with op grants" (CULong 0) rvCtx
  case mTimed of
    Nothing -> assertFailure "context op gate wedged (30s timeout)"
    Just () -> pure ()

-- | Copying a secret key with a CKA_VALUE_LEN that does not match
-- the value refuses TEMPLATE_INCONSISTENT (a huge LEN is never an
-- allocation); a label-only copy of the same key admits.
caseCopyValueLenMismatch :: IO ()
caseCopyValueLenMismatch = do
  mTimed <- timeout 30000000 $ withManualInstance [slot0] $ \inst -> do
    hRW <- openRwSession inst 0
    let keyTmpl = [ (AttrClass, ValULong 4)
                  , (AttrKeyType, ValULong 0x10)
                  , (AttrValue, ValBytes "12345678")
                  ]
    (rvK, hK) <- createViaC inst hRW (frameOf keyTmpl)
    assertEqual "secret create" (CULong 0) rvK
    (rvCopy, _) <- copyViaC inst hRW hK
      (frameOf [(AttrValueLen, ValULong 0xFFFFFFFFFFFFFFFF)])
    assertEqual "huge VALUE_LEN refused" (CULong 0xD1) rvCopy
    (rvCopy2, _) <- copyViaC inst hRW hK (frameOf [(AttrLabel, ValBytes "k2")])
    assertEqual "label-only copy admits" (CULong 0) rvCopy2
  case mTimed of
    Nothing -> assertFailure "copy VALUE_LEN wedged (30s timeout)"
    Just () -> pure ()

-- | CKA_MODIFIABLE end to end: creation carrying the flag admits
-- (it once decoded as unknown), label modification on a modifiable
-- object admits, value modification refuses READ_ONLY, and an
-- unmodifiable object refuses changes while admitting no-op writes.
caseModifiableDataFlow :: IO ()
caseModifiableDataFlow = do
  mTimed <- timeout 30000000 $ withManualInstance [slot0] $ \inst -> do
    hRW <- openRwSession inst 0
    let modTmpl = tmpl ++ [(AttrToken, ValBool True), (AttrModifiable, ValBool True)]
        unmodTmpl = tmpl ++ [(AttrToken, ValBool True), (AttrModifiable, ValBool False)]
    (rvM, hM) <- createViaC inst hRW (frameOf modTmpl)
    assertEqual "modifiable create" (CULong 0) rvM
    rvSet <- setViaC inst hRW hM (frameOf [(AttrLabel, ValBytes "b")])
    assertEqual "label set admits" (CULong 0) rvSet
    rvVal <- setViaC inst hRW hM (frameOf [(AttrValue, ValBytes "v2")])
    assertEqual "value set refuses" (CULong 0x10) rvVal
    (rvU, hU) <- createViaC inst hRW (frameOf unmodTmpl)
    assertEqual "unmodifiable create" (CULong 0) rvU
    rvSetU <- setViaC inst hRW hU (frameOf [(AttrLabel, ValBytes "c")])
    assertEqual "unmodifiable change refuses" (CULong 0x10) rvSetU
    rvNoop <- setViaC inst hRW hU (frameOf [(AttrLabel, ValBytes "a")])
    assertEqual "unmodifiable no-op admits" (CULong 0) rvNoop
  case mTimed of
    Nothing -> assertFailure "modifiable flow wedged (30s timeout)"
    Just () -> pure ()

-- | AES-128 keygen template (CKO_SECRET_KEY, CKK_AES, 16 bytes).
aesGenTmpl :: [(AttributeType, AttributeValue)]
aesGenTmpl =
  [ (AttrClass, ValULong 4)
  , (AttrKeyType, ValULong 0x1F)
  , (AttrValueLen, ValULong 16)
  , (AttrToken, ValBool False)
  ]

-- | AES-128 keygen template asking for a token object.
aesGenTokenTmpl :: [(AttributeType, AttributeValue)]
aesGenTokenTmpl =
  [ (AttrClass, ValULong 4)
  , (AttrKeyType, ValULong 0x1F)
  , (AttrValueLen, ValULong 16)
  , (AttrToken, ValBool True)
  ]

-- | AES wrapping-key template (wrap mark + 16 material bytes).
wrapKeyTmpl :: [(AttributeType, AttributeValue)]
wrapKeyTmpl =
  [ (AttrClass, ValULong 4)
  , (AttrKeyType, ValULong 0x1F)
  , (AttrToken, ValBool False)
  , (AttrWrap, ValBool True)
  , (AttrValue, ValBytes (BS.replicate 16 0x77))
  ]

-- | AES wrap-target template (extractable + 16 material bytes).
targetKeyTmpl :: [(AttributeType, AttributeValue)]
targetKeyTmpl =
  [ (AttrClass, ValULong 4)
  , (AttrKeyType, ValULong 0x1F)
  , (AttrToken, ValBool False)
  , (AttrExtractable, ValBool True)
  , (AttrValue, ValBytes (BS.replicate 16 0x74))
  ]

-- ---------------------------------------------------------------------------
-- Validated construction (submit + pre-execution).
-- ---------------------------------------------------------------------------

-- | The codex construction hole, closed: a bytes job carrying a
-- resource-producing effect ('FxDigestInit') is refused AT SUBMIT
-- with a loud typed denial — no id consumed, nothing to drive.
caseSubmitRefusesInit :: IO ()
caseSubmitRefusesInit = do
  table <- newAsyncTable 8
  let sid = SessionId 7
  enableAsyncSession table sid
  let jr = JobRequest
        { jrSession = sid
        , jrFunction = JobSign
        , jrWork = WorkCall
            (Reservation "construct" [] Nothing Nothing)
            (EffectCrypto (FxDigestInit sha256Mech))
        , jrTicks = 1
        , jrCapacity = 64
        }
  r <- startJob table jr
  assertEqual "misconstructed submit refused" (Left StartIncompatibleWork) r

-- | Coherent jobs still submit (guard against over-refusal): a
-- bytes job with a bytes effect, and a key job with a
-- planner-produced pair.
caseSubmitAcceptsCoherent :: IO ()
caseSubmitAcceptsCoherent = do
  table <- newAsyncTable 8
  (sid, m0) <- openSession defaultRules seeded
  enableAsyncSession table sid
  let signJr = JobRequest
        { jrSession = sid
        , jrFunction = JobSign
        , jrWork = WorkCall
            (Reservation "construct-sign" [] Nothing Nothing)
            (EffectCrypto (FxSign hmacMech Nothing BS.empty "hello"))
        , jrTicks = 1
        , jrCapacity = 64
        }
  rSign <- startJob table signJr
  case rSign of
    Right _ -> pure ()
    Left deny -> assertFailure ("coherent sign submit refused: " ++ show deny)
  st <- sessionOf m0 sid
  (pw, fx) <- case planGenerateKey defaultRules m0 st aesKeyGenMech BS.empty (aesTmpl 32) of
    KeyEffect pw0 fx0 -> pure (pw0, fx0)
    other -> assertFailure ("genkey is not an effect: " ++ show other)
  let keyJr = JobRequest
        { jrSession = sid
        , jrFunction = JobGenKey
        , jrWork = WorkKey (Reservation "construct-key" [] Nothing Nothing) pw fx
        , jrTicks = 1
        , jrCapacity = 64
        }
  rKey <- startJob table keyJr
  case rKey of
    Right _ -> pure ()
    Left deny -> assertFailure ("coherent key submit refused: " ++ show deny)

-- | Look up a session (fails the test when absent).
sessionOf :: Model -> SessionId -> IO SessionState
sessionOf m sid = case lookupSession m sid of
  Nothing -> assertFailure "session lost" >> undefined
  Just st -> pure st

-- | AES keygen template (mirrors the AdmissionSpec helper).
aesTmpl :: Int -> [(AttributeType, AttributeValue)]
aesTmpl n =
  [ (AttrClass, ValULong 4)
  , (AttrKeyType, ValULong 0x1F)
  , (AttrValueLen, ValULong (fromIntegral n))
  , (AttrToken, ValBool False)
  ]

-- | Holdability battery: resource- and verdict-producing effects
-- can never hold on a job (every completion gates on bytes-like
-- holdings); everything else holds. Recovery effects hold by
-- their natural bytes shape — a driver that cannot run them
-- refuses loudly at drive time (defense in depth, unchanged).
caseHoldableBattery :: IO ()
caseHoldableBattery = do
  let noHold =
        [ FxDigestInit sha256Mech
        , FxVerify hmacMech Nothing BS.empty "hello" "tag"
        , FxMessageVerify hmacMech Nothing BS.empty "hello" "tag"
        ]
      holds =
        [ FxDigest sha256Mech "abc"
        , FxDigestFeed (EngineResourceId 1) "abc"
        , FxDigestConsume (EngineResourceId 1)
        , FxCipher DirEncrypt (MechanismId 0x1082) Nothing BS.empty "block-block-blok!"
        , FxSign hmacMech Nothing BS.empty "hello"
        , FxMessageCipher DirEncrypt (MechanismId 0x1082) Nothing BS.empty BS.empty "x"
        , FxMessageSign hmacMech Nothing BS.empty "hello"
        , FxSignRecover hmacMech Nothing BS.empty "hello" 28
        , FxVerifyRecover hmacMech Nothing BS.empty "sig" 28
        , FxGenerateKey aesKeyGenMech BS.empty (encodeGenArgs (GenAes 16))
        , FxWrap (MechanismId 0x1082) Nothing BS.empty "padded-material!!"
        , FxUnwrap (MechanismId 0x1082) Nothing BS.empty "blob-blob-blob!!"
        , FxAuthWrap (MechanismId 0x1082) Nothing BS.empty "padded-material!!"
        , FxAuthUnwrap (MechanismId 0x1082) Nothing BS.empty "blob"
        , FxDerive (MechanismId 0x1082) Nothing Nothing BS.empty BS.empty 32
        , FxKemEncaps (MechanismId 0x1082) Nothing BS.empty BS.empty
        , FxKemDecaps (MechanismId 0x1082) Nothing BS.empty BS.empty
        ]
  mapM_ (\fx -> assertBool ("unholdable: " ++ show fx) (not (effectHoldable fx))) noHold
  mapM_ (\fx -> assertBool ("holdable: " ++ show fx) (effectHoldable fx)) holds

-- | Pair-coherence battery: every planner-produced
-- (pending-work, effect) shape coheres, and crossed shapes do
-- not — including the generation-args refinement (single vs pair
-- args) and undecodable args.
casePairBattery :: IO ()
casePairBattery = do
  let po = PendingObject Map.empty (Just (SessionId 1)) slot0
      genKey = FxGenerateKey aesKeyGenMech BS.empty
      yes =
        [ (PwGeneratePair po po, genKey (encodeGenArgs (GenEc "P-256")))
        , (PwGeneratePair po po, genKey (encodeGenArgs (GenRsa 2048 65537)))
        , (PwGeneratePair po po, genKey (encodeGenArgs (GenMlKem 768)))
        , (PwGenerateKey po, genKey (encodeGenArgs (GenAes 16)))
        , (PwGenerateKey po, genKey (encodeGenArgs (GenBytes 32)))
        , (PwBlobOut "wrapped", FxWrap (MechanismId 0x1082) Nothing BS.empty "p")
        , (PwBlobOut "wrapped", FxAuthWrap (MechanismId 0x1082) Nothing BS.empty "p")
        , (PwUnwrap po, FxUnwrap (MechanismId 0x1082) Nothing BS.empty "b")
        , (PwUnwrap po, FxAuthUnwrap (MechanismId 0x1082) Nothing BS.empty "b")
        , (PwEncaps po 8 32, FxKemEncaps (MechanismId 0x1082) Nothing BS.empty "i")
        , (PwDecaps po, FxKemDecaps (MechanismId 0x1082) Nothing BS.empty "c")
        , (PwDerive [po] [32], FxDerive (MechanismId 0x1082) Nothing Nothing BS.empty "i" 32)
        ]
      no =
        [ (PwGenerateKey po, FxDigestInit sha256Mech)
        , (PwGenerateKey po, FxSign hmacMech Nothing BS.empty "hello")
        , (PwGenerateKey po, FxWrap (MechanismId 0x1082) Nothing BS.empty "p")
        , (PwGenerateKey po, genKey (encodeGenArgs (GenEc "P-256")))
        , (PwGeneratePair po po, genKey (encodeGenArgs (GenAes 16)))
        , (PwGenerateKey po, genKey "not-args")
        , (PwBlobOut "wrapped", genKey (encodeGenArgs (GenAes 16)))
        , (PwUnwrap po, FxDigest sha256Mech "abc")
        , (PwDerive [po] [32], FxWrap (MechanismId 0x1082) Nothing BS.empty "p")
        , (PwEncaps po 8 32, FxKemDecaps (MechanismId 0x1082) Nothing BS.empty "c")
        , (PwDecaps po, FxKemEncaps (MechanismId 0x1082) Nothing BS.empty "i")
        ]
  mapM_ (\(pw, fx) -> assertBool ("coherent: " ++ show pw) (keyPairCompatible pw fx)) yes
  mapM_ (\(pw, fx) -> assertBool ("incoherent: " ++ show pw) (not (keyPairCompatible pw fx))) no
  -- The args codec round-trips (control: the refinement above
  -- cannot pass vacuously on undecodable fixtures).
  assertEqual "genargs round-trip" (Just (GenAes 16))
    (decodeGenArgs (encodeGenArgs (GenAes 16)))

-- | A pair that is holdable but finisher-incoherent submits, then
-- is refused BEFORE execution: the drive terminalizes loudly and
-- the runner never fires (count stays zero).
caseDriveRefusesMismatch :: IO ()
caseDriveRefusesMismatch = do
  table <- newAsyncTable 8
  env <- newEnv defaultRules
  (sid, m0) <- openSession defaultRules seeded
  enableAsyncSession table sid
  st <- sessionOf m0 sid
  (pw, _) <- case planGenerateKey defaultRules m0 st aesKeyGenMech BS.empty (aesTmpl 32) of
    KeyEffect pw0 _ -> pure (pw0, ())
    other -> assertFailure ("genkey is not an effect: " ++ show other)
  -- Holdable (bytes-producing) but finisher-incoherent: a wrap
  -- answer is not framed key material.
  let fx = FxWrap (MechanismId 0x1082) Nothing BS.empty "padded-material!!"
      jr = JobRequest
        { jrSession = sid
        , jrFunction = JobGenKey
        , jrWork = WorkKey (Reservation "construct-b" [] Nothing Nothing) pw fx
        , jrTicks = 1
        , jrCapacity = 64
        }
  rSub <- startJob table jr
  jid <- case rSub of
    Right j -> pure j
    Left deny -> assertFailure ("holdable submit refused: " ++ show deny)
  fired <- newIORef (0 :: Int)
  let counting _fx = do
        atomicModifyIORef' fired (\n -> (n + 1, ()))
        pure (GotBytes "should-never-run")
  out <- pollJob counting env table JobGenKey jid
  case out of
    PollTerminal (TermFailed code _) ->
      assertEqual "drive refusal code" CKR_GENERAL_ERROR code
    other -> assertFailure ("mismatched drive not refused: " ++ show other)
  n <- readIORef fired
  assertEqual "runner never fired" 0 n

-- ---------------------------------------------------------------------------
-- Parse-first double-fault boundaries.
-- ---------------------------------------------------------------------------

-- | The denial code behind a key plan (fails unless denied).
denyCodeOf :: KeyPlan -> IO ReturnCode
denyCodeOf (KeyDenied deny) = pure (kdCode deny)
denyCodeOf other = assertFailure ("expected denial, got: " ++ show other)

-- | A template that contradicts itself (same attribute, two
-- values — identical repeats collapse, so the values differ).
contradictoryTmpl :: [(AttributeType, AttributeValue)]
contradictoryTmpl = [(AttrClass, ValULong 4), (AttrClass, ValULong 0)]

-- | Keygen at a full store with a contradictory template refuses
-- the template code, not the bound code (fail-safe either way).
caseKeygenDoubleFault :: IO ()
caseKeygenDoubleFault = do
  (sid, m1) <- openSession rulesB seeded
  mFull <- fillObjects rulesB sid 8 m1
  st <- sessionOf mFull sid
  code <- denyCodeOf (planGenerateKey rulesB mFull st aesKeyGenMech BS.empty contradictoryTmpl)
  assertEqual "keygen double-fault code" CKR_TEMPLATE_INCONSISTENT code

-- | Keypair generation at a full store refuses the validation
-- code first: a contradictory public template refuses the
-- template code, and an unknown mechanism refuses
-- MECHANISM_INVALID — never the bound code.
caseKeypairDoubleFault :: IO ()
caseKeypairDoubleFault = do
  (sid, m1) <- openSession rulesB seeded
  mFull <- fillObjects rulesB sid 8 m1
  st <- sessionOf mFull sid
  let privT = [(AttrClass, ValULong 3), (AttrKeyType, ValULong 3)]
  codeT <- denyCodeOf
    (planGenerateKeyPair rulesB mFull st ecKeyPairGenMech contradictoryTmpl privT)
  assertEqual "keypair double-fault (template) code" CKR_TEMPLATE_INCONSISTENT codeT
  let pubT = [(AttrClass, ValULong 2), (AttrKeyType, ValULong 3)]
  codeM <- denyCodeOf
    (planGenerateKeyPair rulesB mFull st (MechanismId 0xFFFF) pubT privT)
  assertEqual "keypair double-fault (mechanism) code" CKR_MECHANISM_INVALID codeM

-- | Fill to the bound holding one unwrap-capable AES wrapping key;
-- returns the model, the session state, and the wrapping handle.
fillWithWrapper :: IO (Model, SessionState, ExternalHandle)
fillWithWrapper = do
  (sid, m1) <- openSession rulesB seeded
  let wrapT =
        [ (AttrClass, ValULong 4)
        , (AttrKeyType, ValULong 0x1F)
        , (AttrToken, ValBool False)
        , (AttrUnwrap, ValBool True)
        , (AttrValue, ValBytes (BS.replicate 16 0x75))
        ]
  (hW, m2) <- createViaPlan rulesB m1 sid wrapT
  mFull <- fillObjects rulesB sid 7 m2
  assertEqual "filled to the bound" 8 (Map.size (mObjects mFull))
  st <- sessionOf mFull sid
  pure (mFull, st, hW)

-- | Create one object from a template through the planner
-- (helper for fault setups).
createViaPlan :: Rules -> Model -> SessionId -> [(AttributeType, AttributeValue)]
  -> IO (ExternalHandle, Model)
createViaPlan rules model sid t = do
  let req = (mkRequest F_CreateObject (Just sid)) { reqInput = encodeTemplate t }
  case planCall rules model req of
    Immediate pc -> case publishDelta model (pcDelta pc) of
      Left fault -> assertFailure ("setup create fault: " ++ show fault)
      Right m' -> do
        h <- commitHandle pc
        pure (h, m')
    other -> assertFailure ("setup create failed: " ++ show other)

-- | Unwrap at a full store refuses the validation code first: a
-- short IV and a misaligned blob both refuse ARGUMENTS_BAD, and
-- an unknown wrapping handle refuses OBJECT_HANDLE_INVALID —
-- never the bound code.
caseUnwrapDoubleFault :: IO ()
caseUnwrapDoubleFault = do
  (mFull, st, hW) <- fillWithWrapper
  let blob16 = BS.replicate 16 0x62
      codeOf kp = denyCodeOf kp
  codeIv <- codeOf
    (planUnwrapKey rulesB mFull st aesCbcMech (BS.replicate 8 0) hW blob16 (aesTmpl 16))
  assertEqual "unwrap double-fault (IV) code" CKR_ARGUMENTS_BAD codeIv
  codeBlob <- codeOf
    (planUnwrapKey rulesB mFull st aesCbcMech (BS.replicate 16 0) hW
      (BS.replicate 20 0x62) (aesTmpl 16))
  assertEqual "unwrap double-fault (blob) code" CKR_ARGUMENTS_BAD codeBlob
  codeH <- codeOf
    (planUnwrapKey rulesB mFull st aesCbcMech (BS.replicate 16 0)
      (ExternalHandle 9999) blob16 (aesTmpl 16))
  assertEqual "unwrap double-fault (handle) code" CKR_OBJECT_HANDLE_INVALID codeH

-- | Authenticated unwrap at a full store refuses the validation
-- code first: a short IV and a wrong-length blob both refuse
-- ARGUMENTS_BAD — never the bound code.
caseAuthUnwrapDoubleFault :: IO ()
caseAuthUnwrapDoubleFault = do
  (mFull, st, hW) <- fillWithWrapper
  codeIv <- denyCodeOf
    (planAuthUnwrapKey rulesB mFull st aesCbcMech (BS.replicate 8 0) hW
      (BS.replicate 48 0x61) BS.empty (aesTmpl 16))
  assertEqual "auth-unwrap double-fault (IV) code" CKR_ARGUMENTS_BAD codeIv
  codeBlob <- denyCodeOf
    (planAuthUnwrapKey rulesB mFull st aesCbcMech (BS.replicate 16 0) hW
      (BS.replicate 16 0x61) BS.empty (aesTmpl 16))
  assertEqual "auth-unwrap double-fault (blob) code" CKR_ARGUMENTS_BAD codeBlob

-- ---------------------------------------------------------------------------
-- C-adapter harness (MultiTokenSpec-shaped manual instance)
-- ---------------------------------------------------------------------------

-- | Open a live instance with exactly the given slots seated (fresh
-- Env, provider init, per-slot 'seatToken', live OpenSSL4 backend,
-- empty find cursors, no store).
openManualInstance :: [SlotId] -> IO (StablePtr StdInstance)
openManualInstance slots = do
  env <- newEnv defaultRules
  ini <- initialize env defaultInitArgs
  case ini of
    OutcomeErr code -> fail ("manual init failed: " ++ show code)
    OutcomeOk () -> pure ()
  mapM_ (seatOne env) slots
  eBe <- openBackend "provider=default" :: IO (EngineResult (BackendEnv OpenSSL4))
  be <- case eBe of
    EngineFail err -> fail ("manual backend open failed: " ++ show err)
    EngineOk b -> pure b
  cursors <- newIORef Map.empty
  table <- newAsyncTable 8
  views <- newIORef Map.empty
  bindings <- newIORef Map.empty
  newStablePtr (StdInstance env be cursors Nothing Map.empty table Nothing views bindings)
  where
    seatOne env slot = do
      eSeat <- seatToken env slot
      case eSeat of
        Left deny -> fail ("manual seat failed: " ++ show deny)
        Right () -> pure ()

-- | Bracket a manually seated instance (closed via the real close).
withManualInstance :: [SlotId] -> (StablePtr StdInstance -> IO a) -> IO a
withManualInstance slots = bracket (openManualInstance slots) haskokiStdClose

-- | Open one read/write session on the given slot (fails unless OK).
openRwSession :: StablePtr StdInstance -> CULong -> IO CULong
openRwSession inst slot =
  alloca $ \(phSession :: Ptr CULong) -> do
    poke phSession (CULong 0)
    rv <- haskokiStdOpenSession inst slot (CULong 0) phSession
    assertEqual "open rv" (CULong 0) rv
    peek phSession

-- | Open one read-only session on the given slot (fails unless OK).
openRoSession :: StablePtr StdInstance -> CULong -> IO CULong
openRoSession inst slot =
  alloca $ \(phSession :: Ptr CULong) -> do
    poke phSession (CULong 0)
    rv <- haskokiStdOpenSession inst slot (CULong 1) phSession
    assertEqual "open RO rv" (CULong 0) rv
    peek phSession

-- | Pre-master keygen through the C adapter: a 2-byte
-- CK_VERSION parameter admits (TLS 0x374), a null parameter
-- refuses PARAM_INVALID (0x71) — the funnel forwards params.
casePremasterViaC :: IO ()
casePremasterViaC = do
  mTimed <- timeout 30000000 $ withManualInstance [slot0] $ \inst -> do
    hRW <- openRwSession inst 0
    rvOk <- generateViaC inst hRW (MechanismId 0x374)
      (BS.pack [3, 3]) (frameOf premasterTmpl)
    assertEqual "TLS pre-master via C" (CULong 0) rvOk
    rvNull <- generateViaC inst hRW (MechanismId 0x374)
      BS.empty (frameOf premasterTmpl)
    assertEqual "TLS pre-master null params" (CULong 0x71) rvNull
    rvStray <- generateViaC inst hRW (MechanismId 0x1080)
      (BS.pack [3, 3]) (frameOf aesGenTmpl)
    assertEqual "AES keygen stray params" (CULong 0x71) rvStray
  case mTimed of
    Nothing -> assertFailure "pre-master via C wedged (30s timeout)"
    Just () -> pure ()
  where
    premasterTmpl =
      [ (AttrClass, ValULong 4)
      , (AttrKeyType, ValULong 0x10)
      , (AttrValueLen, ValULong 48)
      , (AttrToken, ValBool False)
      ]

-- | The C word behind an external handle.
cuLongOf :: ExternalHandle -> CULong
cuLongOf (ExternalHandle w) = CULong (fromIntegral w)

-- | Generate one key through the C adapter; returns the CK_RV.
generateViaC :: StablePtr StdInstance -> CULong -> MechanismId -> ByteString -> ByteString -> IO CULong
generateViaC inst hSession (MechanismId mech) params frame =
  alloca $ \(phKey :: Ptr CULong) -> do
    poke phKey (CULong 0)
    BS.useAsCStringLen frame $ \(p, n) ->
      BS.useAsCStringLen params $ \(pp, pn) ->
        haskokiStdGenerateKey inst hSession (CULong (fromIntegral mech))
          (castPtr p) (fromIntegral n) (castPtr pp) (fromIntegral pn) phKey

-- | Wrap one key through the C adapter; returns the CK_RV.
wrapViaC :: StablePtr StdInstance -> CULong -> MechanismId -> ByteString
  -> ExternalHandle -> ExternalHandle -> IO CULong
wrapViaC inst hSession (MechanismId mech) iv (ExternalHandle w) (ExternalHandle t) =
  allocaArray 64 $ \(pOut :: Ptr Word8) ->
  alloca $ \(pLen :: Ptr CULong) -> do
    poke pLen (CULong 64)
    BS.useAsCStringLen iv $ \(pIv, nIv) ->
      haskokiStdWrapKey inst hSession (CULong (fromIntegral mech))
        (castPtr pIv) (fromIntegral nIv)
        (CULong (fromIntegral w)) (CULong (fromIntegral t)) pOut pLen

-- | Open a find cursor through the C adapter; returns the CK_RV.
findInitViaC :: StablePtr StdInstance -> CULong -> ByteString -> IO CULong
findInitViaC inst hSession frame =
  BS.useAsCStringLen frame $ \(p, n) ->
    haskokiStdFindInit inst hSession (castPtr p) (fromIntegral n)

-- | Read one attribute through the C adapter (size query);
-- returns the CK_RV.
getOneAttrViaC :: StablePtr StdInstance -> CULong -> ExternalHandle -> Word64 -> IO CULong
getOneAttrViaC inst hSession (ExternalHandle o) cka =
  alloca $ \(pLen :: Ptr CULong) -> do
    poke pLen (CULong 0)
    haskokiStdGetOneAttr inst hSession (CULong (fromIntegral o))
      (CULong cka) nullPtr pLen

-- | Create one object through the C adapter from a template frame;
-- returns the CK_RV and the written handle word.
createViaC :: StablePtr StdInstance -> CULong -> ByteString -> IO (CULong, ExternalHandle)
createViaC inst hSession frame =
  alloca $ \(phObj :: Ptr CULong) -> do
    poke phObj (CULong 0)
    rv <- BS.useAsCStringLen frame $ \(p, n) ->
      haskokiStdCreateObject inst hSession (castPtr p) (fromIntegral n) phObj
    CULong oh <- peek phObj
    pure (rv, ExternalHandle (fromIntegral oh))

-- | Copy one object through the C adapter under a modifier frame;
-- returns the CK_RV and the written handle word.
copyViaC :: StablePtr StdInstance -> CULong -> ExternalHandle -> ByteString
  -> IO (CULong, ExternalHandle)
copyViaC inst hSession (ExternalHandle o) frame =
  alloca $ \(phNew :: Ptr CULong) -> do
    poke phNew (CULong 0)
    rv <- BS.useAsCStringLen frame $ \(p, n) ->
      haskokiStdCopyObject inst hSession (CULong (fromIntegral o))
        (castPtr p) (fromIntegral n) phNew
    CULong oh <- peek phNew
    pure (rv, ExternalHandle (fromIntegral oh))

-- | Set attributes through the C adapter; returns the CK_RV.
setViaC :: StablePtr StdInstance -> CULong -> ExternalHandle -> ByteString -> IO CULong
setViaC inst hSession (ExternalHandle o) frame =
  BS.useAsCStringLen frame $ \(p, n) ->
    haskokiStdSetAttributeValue inst hSession (CULong (fromIntegral o))
      (castPtr p) (fromIntegral n)

-- | One little-endian u64 word (frame integers are caller-native).
word :: Word64 -> ByteString
word w = BS.pack
  [ fromIntegral (w `mod` 256)
  , fromIntegral (w `div` 256 `mod` 256)
  , fromIntegral (w `div` 65536 `mod` 256)
  , fromIntegral (w `div` 16777216 `mod` 256)
  , fromIntegral (w `div` 4294967296 `mod` 256)
  , fromIntegral (w `div` 1099511627776 `mod` 256)
  , fromIntegral (w `div` 281474976710656 `mod` 256)
  , fromIntegral (w `div` 72057594037927936 `mod` 256)
  ]

-- | Initialize a digest operation through the C adapter.
digestInitViaC :: StablePtr StdInstance -> CULong -> MechanismId -> ByteString -> IO CULong
digestInitViaC inst hSession (MechanismId mech) params =
  BS.useAsCStringLen params $ \(p, n) ->
    haskokiStdDigestInit inst hSession (CULong (fromIntegral mech))
      (castPtr p) (fromIntegral n)

-- | Log in through the C adapter (userType 0=SO, 1=user,
-- 2=context); returns the CK_RV.
loginViaC :: StablePtr StdInstance -> CULong -> CULong -> ByteString -> IO CULong
loginViaC inst hSession userType pin =
  BS.useAsCStringLen pin $ \(p, n) ->
    haskokiStdLogin inst hSession userType (castPtr p) (fromIntegral n)

-- | Initialize a sign operation through the C adapter over one key.
signInitViaC :: StablePtr StdInstance -> CULong -> MechanismId -> ByteString
  -> ExternalHandle -> IO CULong
signInitViaC inst hSession (MechanismId mech) params (ExternalHandle key) =
  BS.useAsCStringLen params $ \(p, n) ->
    haskokiStdSignInit inst hSession (CULong (fromIntegral mech))
      (castPtr p) (fromIntegral n) (CULong (fromIntegral key))

-- | Attribute type ids for the frames under test (locked header
-- @spec/vendor/pkcs11.h@: CKA_CLASS 0x00, CKA_TOKEN
-- 0x01, CKA_PRIVATE 0x02, CKA_LABEL 0x03, CKA_VALUE 0x11,
-- CKA_KEY_TYPE 0x100, CKA_WRAP 0x106, CKA_SIGN 0x108,
-- CKA_VALUE_LEN 0x161, CKA_EXTRACTABLE 0x162,
-- CKA_MODIFIABLE 0x170).
attrId :: AttributeType -> Word64
attrId AttrClass = 0x00
attrId AttrToken = 0x01
attrId AttrPrivate = 0x02
attrId AttrModifiable = 0x170
attrId AttrLabel = 0x03
attrId AttrValue = 0x11
attrId AttrKeyType = 0x100
attrId AttrWrap = 0x106
attrId AttrSign = 0x108
attrId AttrValueLen = 0x161
attrId AttrExtractable = 0x162
attrId t = error ("frameOf: no id pinned for " ++ show t)

-- | Frame one template the way the C packer does: @count:u64le@
-- then @count@ records of @type:u64le, len:u64le, value:len@ with
-- caller-native value bytes ('nativeEncodeAttr').
frameOf :: [(AttributeType, AttributeValue)] -> ByteString
frameOf entries =
  word (fromIntegral (length entries)) <> mconcat (map rec entries)
  where
    rec (t, v) =
      let vb = nativeEncodeAttr t v
      in word (attrId t) <> word (fromIntegral (BS.length vb)) <> vb
