{- | Attached-job engine proofs over the real OpenSSL4 backend
through the production driver: a planned digest completes
through shaped finisher outputs (exact KAT bytes, slot
terminated); an HMAC sign completes through the legacy path
with RFC 4231 bytes.
-}
{-# LANGUAGE OverloadedStrings #-}
module AsyncEngineSpec (spec) where

import Control.Concurrent.MVar (MVar)
import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import Data.Char (digitToInt, isHexDigit)
import Data.IORef (IORef, newIORef, readIORef, modifyIORef')
import Data.Word (Word64, Word8)
import EnvLock (withEnvLock)
import Foreign.C.Types (CULong (..))
import Foreign.Marshal.Alloc (alloca, allocaBytes)
import Foreign.Marshal.Array (peekArray, pokeArray)
import Foreign.Ptr (Ptr, castPtr, nullPtr, plusPtr)
import Foreign.StablePtr
  ( StablePtr
  , castPtrToStablePtr
  , castStablePtrToPtr
  , deRefStablePtr
  , freeStablePtr
  )
import Foreign.Storable (peek, poke, peekByteOff, pokeByteOff)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertBool, assertEqual, assertFailure, testCase)

import Haskoki.Engine.Backend
  ( BackendEnv
  , CryptoBackend (..)
  , EngineResult (..)
  , KeyMaterial (..)
  , closeBackend
  , openBackend
  )
import Haskoki.Engine.Driver (runEffect)
import Haskoki.Engine.OpenSSL4 (OpenSSL4 (..))
import Haskoki.FFI.Async
  ( AsyncCtx (..)
  , AsyncData
  , JobHandle
  , asyncCloseCtx
  , asyncLiveHandles
  , haskokiAsyncCancel
  , haskokiAsyncClose
  , haskokiAsyncComplete
  , haskokiAsyncDigestInit
  , haskokiAsyncOpen
  , haskokiAsyncPoll
  , haskokiAsyncStart
  , pokeCompletion
  , pokeNeed
  )
import Haskoki.FFI.Exports (returnCodeToRV)
import Haskoki.Model (Model (..), SessionState (..), lookupSession)
import Haskoki.Operation
  ( CryptoEffect (..)
  , SlotKind (..)
  , lookupSingle
  )
import Haskoki.Operation.Codec (encodeInitInput)
import Haskoki.Outcome
  ( EffectRequest (..)
  , PlanResult (..)
  , PreparedCommit (..)
  , Reservation (..)
  , ResourceRelease (..)
  )
import qualified Haskoki.Outcome as O
import Haskoki.Output (maxOutputBytes)
import Haskoki.Registry (MechanismId (..))
import Haskoki.Request
  ( FunctionId (..)
  , OutputIntent (..)
  , OutputRegion (..)
  , Request (..)
  )
import Haskoki.Rules (defaultRules)
import Haskoki.Runtime.Async
  ( CompleteOutcome (..)
  , Completion (..)
  , Delivery (..)
  , JobFunction (..)
  , JobRequest (..)
  , AsyncWork (..)
  , PollOutcome (..)
  , completeJob
  , enableAsyncSession
  , newAsyncTable
  , pollJob
  , startJob
  )
import Haskoki.Runtime.Lifecycle
  ( Env
  , defaultInitArgs
  , initialize
  , invalidateSession
  , newEnv
  , publish
  , seatToken
  , snapshotModel
  )
import Haskoki.Transition (finishEffect, planCall)
import Haskoki.Types
  ( EngineResourceId (..)
  , ExternalHandle (..)
  , ObjectId (..)
  , Outcome (..)
  , Pkcs11Version (..)
  , ReturnCode (..)
  , SessionId (..)
  , SlotId (..)
  , unSessionId
  )

spec :: MVar () -> TestTree
spec envLock = testGroup "Async engine"
  [ testCase "planned digest completes shaped with KAT bytes" caseDigestShaped
  , testCase "hmac sign completes with RFC 4231 bytes" caseHmacSign
  , testCase "new return codes pin to header values" caseRvPins
  , testCase "FFI digest: pending canaries, exact delivery" (caseFfiDigestFlow envLock)
  , testCase "FFI wrong function refused; job intact" (caseFfiWrongFunction envLock)
  , testCase "FFI cancel frees; late use is stale" (caseFfiCancel envLock)
  , testCase "FFI refusals: typed codes, null handles" (caseFfiRefusals envLock)
  , testCase "FFI null-value probe sizes without consuming" (caseFfiProbe envLock)
  , testCase "FFI short complete sizes; retry delivers" (caseFfiShort envLock)
  , testCase "FFI drive error frees the handle exactly once" (caseFfiDriveError envLock)
  , testCase "FFI close drains pending jobs exactly once" (caseFfiDrain envLock)
  , testCase "FFI double close is silent" (caseFfiDoubleClose envLock)
  , testCase "struct sink writes all three shapes exactly" caseSinkShapes
  ]

hex :: String -> ByteString
hex s = BS.pack (go (filter isHexDigit s))
  where
    go [] = []
    go (a : b : rest) = fromIntegral (digitToInt a * 16 + digitToInt b) : go rest
    go [_] = error "hex: odd digit count"

-- FIPS 180-4: SHA-256("abc").
sha256Abc :: ByteString
sha256Abc = hex "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

-- RFC 4231 case 1: key = 0x0b * 20, data = "Hi There".
rfc4231Case1 :: ByteString
rfc4231Case1 = hex "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"

withBackend :: (BackendEnv OpenSSL4 -> IO a) -> IO a
withBackend action = do
  r <- openBackend "provider=default" :: IO (EngineResult (BackendEnv OpenSSL4))
  case r of
    EngineFail err -> assertFailure ("openBackend failed: " ++ show err)
    EngineOk be -> do
      out <- action be
      closeBackend be
      pure out

openSessionEnv :: IO (Env, SessionState)
openSessionEnv = do
  env <- newEnv defaultRules
  ini <- initialize env defaultInitArgs
  case ini of
    OutcomeOk () -> pure ()
    OutcomeErr c -> assertFailure ("init failed: " ++ show c)
  seatToken env (SlotId 0) >>= assertEqual "seat ok" (Right ())
  m0 <- snapshotModel env
  let sid = SessionId (mNextSession m0)
      req = Request Pkcs11_3_2 F_OpenSession Nothing Nothing "slot=0,rw" []
  case planCall defaultRules m0 req of
    Immediate pc -> do
      pr <- publish env (pcDelta pc)
      case pr of
        Right () -> pure ()
        Left f -> assertFailure ("open publish failed: " ++ show f)
    other -> assertFailure ("open did not plan: " ++ show other)
  m1 <- snapshotModel env
  case lookupSession m1 sid of
    Just st -> pure (env, st)
    Nothing -> assertFailure "session missing after open"

initDigest :: Env -> SessionId -> IO ()
initDigest env sid = do
  m <- snapshotModel env
  let req = Request Pkcs11_3_2 F_DigestInit (Just sid) Nothing
        (encodeInitInput (MechanismId 0x250) [] False BS.empty) []
  case planCall defaultRules m req of
    Execute res (EffectCrypto _) -> do
      m2 <- snapshotModel env
      case finishEffect defaultRules m2 res
          (O.EngineOkResource (EngineResourceId 31)) of
        Left rej -> assertFailure ("digest init rejected: " ++ show rej)
        Right pc -> do
          pr <- publish env (pcDelta pc)
          case pr of
            Right () -> pure ()
            Left f -> assertFailure ("digest init publish failed: " ++ show f)
    other -> assertFailure ("digest init did not plan: " ++ show other)

-- | Drain one committed release through a backend.
drainOne :: CryptoBackend b => BackendEnv b -> ResourceRelease -> IO ()
drainOne be (ReleaseEngineResource rid) = releaseResource be rid

newCapture :: IO (Delivery, IORef [ByteString])
newCapture = do
  ref <- newIORef []
  needed <- newIORef ([] :: [Word64])
  let del = Delivery
        { dCapacity = 32
        , dWrite = \bs -> modifyIORef' ref (++ [bs])
        , dReportNeeded = \n -> modifyIORef' needed (++ [n])
        }
  _ <- pure needed
  pure (del, ref)

-- | Plan a real async digest: init published, one-shot planned with
-- the async max-capacity intent (Async sizes at delivery, never the
-- sync finisher).
planDigestJob :: Env -> SessionState -> IO (Reservation, EffectRequest)
planDigestJob env st = do
  initDigest env (ssId st)
  m <- snapshotModel env
  let req = Request Pkcs11_3_2 F_Digest (Just (ssId st)) Nothing "abc"
        [RegionBytes "digest" (IntentBuffer maxOutputBytes)]
  case planCall defaultRules m req of
    Execute res eff -> pure (res, eff)
    other -> assertFailure ("digest did not plan Execute: " ++ show other)

caseDigestShaped :: IO ()
caseDigestShaped = withBackend $ \be -> do
  (env, st) <- openSessionEnv
  table <- newAsyncTable 4
  enableAsyncSession table (ssId st)
  (res, eff) <- planDigestJob env st
  let req = JobRequest
        { jrSession = ssId st
        , jrFunction = JobDigest
        , jrWork = WorkCall res eff
        , jrTicks = 1
        , jrCapacity = 32
        }
  Right j0 <- startJob table req
  runs <- newIORef (0 :: Int)
  let run fx = do
        modifyIORef' runs (+ 1)
        runEffect be (const Nothing) fx
  p <- pollJob run env table JobDigest j0
  assertEqual "digest ready" PollReady p
  (del, ref) <- newCapture
  c <- completeJob env table JobDigest j0 del (drainOne be)
  case c of
    CompleteDelivered (CompBytes bs) ->
      assertEqual "FIPS 180-4 digest of abc" sha256Abc bs
    other -> assertFailure ("expected shaped delivery, got " ++ show other)
  writes <- readIORef ref
  assertEqual "one frame"
    [BS.pack [0x01, 0x00, 0x00, 0x00, 0x20] <> sha256Abc] writes
  nRuns <- readIORef runs
  assertEqual "effect ran once" 1 nRuns
  -- The finisher's commit terminated the digest slot.
  m2 <- snapshotModel env
  case lookupSession m2 (ssId st) of
    Nothing -> assertFailure "session lost"
    Just st2 -> assertEqual "digest slot terminated" Nothing
      (lookupSingle (ssOps st2) SlotDigest)
  _ <- pure (j0, table)
  pure ()

caseHmacSign :: IO ()
caseHmacSign = withBackend $ \be -> do
  (env, st) <- openSessionEnv
  table <- newAsyncTable 4
  enableAsyncSession table (ssId st)
  let rfcKey = BS.replicate 20 0x0b
      req = JobRequest
        { jrSession = ssId st
        , jrFunction = JobSign
        , jrWork = WorkCall
            (Reservation "async-hmac-sign" [] Nothing Nothing)
            (EffectCrypto (FxSign (MechanismId 0x251)
              (Just (ObjectId 7)) BS.empty "Hi There"))
        , jrTicks = 1
        , jrCapacity = 32
        }
  Right j0 <- startJob table req
  runs <- newIORef (0 :: Int)
  let run fx = do
        modifyIORef' runs (+ 1)
        runEffect be (const (Just (KeyBytes rfcKey))) fx
  p <- pollJob run env table JobSign j0
  assertEqual "sign ready" PollReady p
  (del, ref) <- newCapture
  c <- completeJob env table JobSign j0 del (drainOne be)
  case c of
    CompleteDelivered (CompBytes bs) ->
      assertEqual "RFC 4231 case 1" rfc4231Case1 bs
    other -> assertFailure ("expected sign delivery, got " ++ show other)
  writes <- readIORef ref
  assertEqual "one frame"
    [BS.pack [0x01, 0x00, 0x00, 0x00, 0x20] <> rfc4231Case1] writes
  nRuns <- readIORef runs
  assertEqual "effect ran once" 1 nRuns
  _ <- pure (j0, table)
  pure ()

-- ---------------------------------------------------------------------------
-- S5b: async FFI surface
-- ---------------------------------------------------------------------------

-- Pinned CK_RV values (0x50/0x205 pinned directly in caseRvPins;
-- no attached-async FFI path emits them: cancel frees the handle, and the ctx
-- session is async by construction).
rvOK, rvBad, rvShort, rvSession, rvNotInit, rvPending, rvHostMem, rvGeneral :: CULong
rvOK = CULong 0x0
rvGeneral = CULong 0x05
rvBad = CULong 0x07
rvHostMem = CULong 0x02
rvNotInit = CULong 0x91
rvShort = CULong 0x150
rvPending = CULong 0x204
rvSession = CULong 0xB3

-- Function codes (the FFI's explicit poller identity).
fnSign, fnDigest :: CULong
fnSign = CULong 1
fnDigest = CULong 2

-- CK_ASYNC_DATA field offsets, pinned by tests/c/layout_320.c.
offVersion, offValueLen, offObject, offObject2 :: Int
offVersion = 0
offValueLen = 16
offObject = 24
offObject2 = 32

offValue :: Int
offValue = 8

structSize :: Int
structSize = 40

caseRvPins :: IO ()
caseRvPins = do
  assertEqual "PENDING" 0x204 (returnCodeToRV CKR_PENDING)
  assertEqual "ASYNC_NOT_SUPPORTED" 0x205 (returnCodeToRV CKR_SESSION_ASYNC_NOT_SUPPORTED)
  assertEqual "CANCELED" 0x50 (returnCodeToRV CKR_FUNCTION_CANCELED)
  assertEqual "HOST_MEMORY" 0x02 (returnCodeToRV CKR_HOST_MEMORY)

withACtx :: MVar () -> (StablePtr AsyncCtx -> IO a) -> IO a
withACtx envLock action =
  alloca $ \(pSlot :: Ptr (StablePtr AsyncCtx)) -> do
    ctx <- withEnvLock envLock haskokiAsyncOpen
    assertBool "ctx opened" (castStablePtrToPtr ctx /= nullPtr)
    poke pSlot ctx
    out <- action ctx
    haskokiAsyncClose pSlot
    nulled <- peek pSlot
    assertBool "slot nulled on close" (castStablePtrToPtr nulled == nullPtr)
    pure out

hSessionOf :: StablePtr AsyncCtx -> IO CULong
hSessionOf ctx = do
  c <- deRefStablePtr ctx
  pure (CULong (fromIntegral (unSessionId (acSession c))))

initDigestFfi :: StablePtr AsyncCtx -> CULong -> IO CULong
initDigestFfi ctx h = haskokiAsyncDigestInit ctx h 0x250 nullPtr 0

nullJob :: StablePtr JobHandle
nullJob = castPtrToStablePtr nullPtr

isNullJob :: StablePtr JobHandle -> Bool
isNullJob h = castStablePtrToPtr h == nullPtr

startFfi
  :: StablePtr AsyncCtx -> CULong -> CULong -> ByteString -> Word64 -> Word64
  -> IO (CULong, StablePtr JobHandle)
startFfi ctx h func input cap ticks =
  BS.useAsCStringLen input $ \(pIn, nIn) ->
    alloca $ \(pH :: Ptr (StablePtr JobHandle)) -> do
      poke pH nullJob
      rv <- haskokiAsyncStart ctx h func
        (castPtr pIn) (fromIntegral nIn) (CULong cap) (CULong ticks) pH
      hJob <- peek pH
      pure (rv, hJob)

-- | A canary CK_ASYNC_DATA struct over a canary value buffer.
withStruct :: Int -> ((Ptr AsyncData, Ptr Word8) -> IO a) -> IO a
withStruct cap action =
  allocaBytes structSize $ \(pS :: Ptr AsyncData) ->
    allocaBytes cap $ \(pV :: Ptr Word8) -> do
      pokeArray (castPtr pS) (replicate structSize (0xA5 :: Word8))
      pokeArray pV (replicate cap (0xA5 :: Word8))
      pokeByteOff (castPtr pS :: Ptr Word8) offValue pV
      poke (castPtr pS `plusPtr` offValueLen :: Ptr CULong) (CULong (fromIntegral cap))
      action (pS, pV)

readField :: Ptr AsyncData -> Int -> IO CULong
readField pS off = peekByteOff (castPtr pS) off

readBytes :: Ptr Word8 -> Int -> IO ByteString
readBytes pV n = BS.packCStringLen (castPtr pV, n)

assertCanaryStruct :: String -> Ptr AsyncData -> IO ()
assertCanaryStruct msg pS = do
  raw <- peekArray structSize (castPtr pS :: Ptr Word8)
  -- The pValue (8..16) and ulValue (16..24) fields were set up by
  -- withStruct; mask them out, then everything else must be canary.
  let masked = take offValue raw ++ replicate 8 0xA5 ++ drop (offValue + 8) raw
      wipeLen = take offValueLen masked ++ replicate 8 0xA5 ++ drop (offValueLen + 8) masked
  assertEqual msg (replicate structSize 0xA5) wipeLen

assertCanaryBuf :: String -> Ptr Word8 -> Int -> IO ()
assertCanaryBuf msg pV n = do
  raw <- peekArray n pV
  assertEqual msg (replicate n 0xA5) raw

caseFfiDigestFlow :: MVar () -> IO ()
caseFfiDigestFlow envLock = withACtx envLock $ \ctx -> do
  h <- hSessionOf ctx
  rvInit <- initDigestFfi ctx h
  assertEqual "init ok" rvOK rvInit
  (rvStart, hJob) <- startFfi ctx h fnDigest "abc" 32 2
  assertEqual "start pending" rvPending rvStart
  assertBool "handle live" (not (isNullJob hJob))
  nLive <- deRefStablePtr ctx >>= asyncLiveHandles
  assertEqual "one live handle" 1 nLive
  withStruct 32 $ \(pS, pV) -> do
    rvPoll1 <- haskokiAsyncPoll ctx hJob fnDigest
    assertEqual "poll 1 pending" rvPending rvPoll1
    assertCanaryStruct "poll-pending struct intact" pS
    assertCanaryBuf "poll-pending buffer intact" pV 32
    rvComp0 <- haskokiAsyncComplete ctx hJob fnDigest pS
    assertEqual "complete-while-pending" rvPending rvComp0
    assertCanaryStruct "pending-complete struct intact" pS
    assertCanaryBuf "pending-complete buffer intact" pV 32
    rvPoll2 <- haskokiAsyncPoll ctx hJob fnDigest
    assertEqual "poll 2 ready" rvOK rvPoll2
    assertCanaryStruct "drive writes nothing" pS
    rvComp1 <- haskokiAsyncComplete ctx hJob fnDigest pS
    assertEqual "complete ok" rvOK rvComp1
    ver <- readField pS offVersion
    len <- readField pS offValueLen
    o1 <- readField pS offObject
    o2 <- readField pS offObject2
    assertEqual "version" (CULong 1) ver
    assertEqual "length" (CULong 32) len
    assertEqual "hObject zero" (CULong 0) o1
    assertEqual "hAdditional zero" (CULong 0) o2
    out <- readBytes pV 32
    assertEqual "FIPS 180-4 digest of abc" sha256Abc out
  -- Terminal delivery freed the native handle exactly once.
  nLive2 <- deRefStablePtr ctx >>= asyncLiveHandles
  assertEqual "handle freed on delivery" 0 nLive2
  rvPoll3 <- haskokiAsyncPoll ctx hJob fnDigest
  assertEqual "poll-after-deliver stale" rvBad rvPoll3
  rvComp2 <- haskokiAsyncComplete ctx hJob fnDigest nullPtr
  assertEqual "double complete stale" rvBad rvComp2

caseFfiWrongFunction :: MVar () -> IO ()
caseFfiWrongFunction envLock = withACtx envLock $ \ctx -> do
  h <- hSessionOf ctx
  rvInit <- initDigestFfi ctx h
  assertEqual "init ok" rvOK rvInit
  (rvStart, hJob) <- startFfi ctx h fnDigest "abc" 32 1
  assertEqual "start pending" rvPending rvStart
  rvPollW <- haskokiAsyncPoll ctx hJob fnSign
  assertEqual "wrong poller refused" rvBad rvPollW
  withStruct 32 $ \(pS, pV) -> do
    rvCompW <- haskokiAsyncComplete ctx hJob fnSign pS
    assertEqual "wrong completer refused" rvBad rvCompW
    assertCanaryStruct "wrong-complete struct intact" pS
    assertCanaryBuf "wrong-complete buffer intact" pV 32
    -- The job is intact: the correct flow still delivers KAT bytes.
    rvPoll <- haskokiAsyncPoll ctx hJob fnDigest
    assertEqual "correct poll ready" rvOK rvPoll
    rvComp <- haskokiAsyncComplete ctx hJob fnDigest pS
    assertEqual "complete ok" rvOK rvComp
    out <- readBytes pV 32
    assertEqual "KAT bytes after refusal" sha256Abc out

caseFfiCancel :: MVar () -> IO ()
caseFfiCancel envLock = withACtx envLock $ \ctx -> do
  h <- hSessionOf ctx
  rvInit <- initDigestFfi ctx h
  assertEqual "init ok" rvOK rvInit
  (rvStart, hJob) <- startFfi ctx h fnDigest "abc" 32 5
  assertEqual "start pending" rvPending rvStart
  rvCancel <- haskokiAsyncCancel ctx hJob
  assertEqual "cancel ok" rvOK rvCancel
  nLive <- deRefStablePtr ctx >>= asyncLiveHandles
  assertEqual "handle freed on cancel" 0 nLive
  withStruct 32 $ \(pS, pV) -> do
    rvComp <- haskokiAsyncComplete ctx hJob fnDigest pS
    assertEqual "complete-after-cancel stale" rvBad rvComp
    assertCanaryStruct "cancelled struct intact" pS
    assertCanaryBuf "cancelled buffer intact" pV 32
  rvPoll <- haskokiAsyncPoll ctx hJob fnDigest
  assertEqual "poll-after-cancel stale" rvBad rvPoll
  rvCancel2 <- haskokiAsyncCancel ctx hJob
  assertEqual "double cancel stale" rvBad rvCancel2

caseFfiRefusals :: MVar () -> IO ()
caseFfiRefusals envLock = withACtx envLock $ \ctx -> do
  h <- hSessionOf ctx
  -- No init yet: sign start reports not-initialized with no handle.
  (rvSign, hSign) <- startFfi ctx h fnSign "abc" 64 1
  assertEqual "uninit sign refused" rvNotInit rvSign
  assertBool "null handle" (isNullJob hSign)
  -- Bad function, bad session, bad capacity: typed codes, null handles.
  (rvFn, hFn) <- startFfi ctx h 9 "abc" 32 1
  assertEqual "bad function" rvBad rvFn
  assertBool "null handle" (isNullJob hFn)
  (rvSess, hSess) <- startFfi ctx 99 fnDigest "abc" 32 1
  assertEqual "bad session" rvSession rvSess
  assertBool "null handle" (isNullJob hSess)
  rvInit <- initDigestFfi ctx h
  assertEqual "init ok" rvOK rvInit
  (rvCap0, hCap0) <- startFfi ctx h fnDigest "abc" 0 1
  assertEqual "zero cap" rvBad rvCap0
  assertBool "null handle" (isNullJob hCap0)
  -- Fill the table (8 live): the 9th refuses with host-memory.
  jobs <- mapM (\_ -> startFfi ctx h fnDigest "abc" 32 5) [1 .. 8 :: Int]
  assertEqual "8 starts pending" (replicate 8 rvPending) (map fst jobs)
  assertBool "8 live handles" (all (not . isNullJob . snd) jobs)
  (rvFull, hFull) <- startFfi ctx h fnDigest "abc" 32 1
  assertEqual "9th start host-memory" rvHostMem rvFull
  assertBool "null handle" (isNullJob hFull)
  nLive <- deRefStablePtr ctx >>= asyncLiveHandles
  assertEqual "8 live" 8 nLive

caseFfiProbe :: MVar () -> IO ()
caseFfiProbe envLock = withACtx envLock $ \ctx -> do
  h <- hSessionOf ctx
  rvInit <- initDigestFfi ctx h
  assertEqual "init ok" rvOK rvInit
  (rvStart, hJob) <- startFfi ctx h fnDigest "abc" 32 2
  assertEqual "start pending" rvPending rvStart
  allocaBytes structSize $ \(pS :: Ptr AsyncData) -> do
    pokeArray (castPtr pS) (replicate structSize (0xA5 :: Word8))
    pokeByteOff (castPtr pS :: Ptr Word8) offValue (nullPtr :: Ptr Word8)
    poke (castPtr pS `plusPtr` offValueLen :: Ptr CULong) (CULong 0)
    -- Probe while pending: PENDING, length untouched.
    rvProbe0 <- haskokiAsyncComplete ctx hJob fnDigest pS
    assertEqual "probe while pending" rvPending rvProbe0
    len0 <- readField pS offValueLen
    assertEqual "probe-pending length intact" (CULong 0) len0
    -- Drive to ready, then probe: OK + sizing, job still ready.
    rvPoll1 <- haskokiAsyncPoll ctx hJob fnDigest
    assertEqual "poll 1 pending" rvPending rvPoll1
    rvPoll2 <- haskokiAsyncPoll ctx hJob fnDigest
    assertEqual "poll 2 ready" rvOK rvPoll2
    rvProbe1 <- haskokiAsyncComplete ctx hJob fnDigest pS
    assertEqual "probe ready sizes" rvOK rvProbe1
    len1 <- readField pS offValueLen
    assertEqual "probe reports need" (CULong 32) len1
    -- The probe consumed nothing: a real complete still delivers.
    withStruct 32 $ \(pS2, pV2) -> do
      rvComp <- haskokiAsyncComplete ctx hJob fnDigest pS2
      assertEqual "complete after probe" rvOK rvComp
      out <- readBytes pV2 32
      assertEqual "KAT bytes" sha256Abc out

caseFfiShort :: MVar () -> IO ()
caseFfiShort envLock = withACtx envLock $ \ctx -> do
  h <- hSessionOf ctx
  rvInit <- initDigestFfi ctx h
  assertEqual "init ok" rvOK rvInit
  (rvStart, hJob) <- startFfi ctx h fnDigest "abc" 32 1
  assertEqual "start pending" rvPending rvStart
  rvPoll <- haskokiAsyncPoll ctx hJob fnDigest
  assertEqual "ready" rvOK rvPoll
  withStruct 8 $ \(pS, pV) -> do
    rvShort1 <- haskokiAsyncComplete ctx hJob fnDigest pS
    assertEqual "short sizes" rvShort rvShort1
    len <- readField pS offValueLen
    assertEqual "need reported" (CULong 32) len
    assertCanaryBuf "short buffer intact" pV 8
  withStruct 32 $ \(pS, pV) -> do
    rvComp <- haskokiAsyncComplete ctx hJob fnDigest pS
    assertEqual "retry delivers" rvOK rvComp
    out <- readBytes pV 32
    assertEqual "KAT bytes" sha256Abc out

caseFfiDriveError :: MVar () -> IO ()
caseFfiDriveError envLock = withACtx envLock $ \ctx -> do
  h <- hSessionOf ctx
  rvInit <- initDigestFfi ctx h
  assertEqual "init ok" rvOK rvInit
  (rvStart, hJob) <- startFfi ctx h fnDigest "abc" 32 1
  assertEqual "start pending" rvPending rvStart
  -- Invalidate the planned revision before the drive poll.
  c <- deRefStablePtr ctx
  invalidateSession (acEnv c) (acSession c)
  rvPoll <- haskokiAsyncPoll ctx hJob fnDigest
  assertEqual "stale drive fails typed" rvGeneral rvPoll
  nLive <- asyncLiveHandles c
  assertEqual "error path frees the handle" 0 nLive
  rvPoll2 <- haskokiAsyncPoll ctx hJob fnDigest
  assertEqual "late poll stale, not double-free" rvBad rvPoll2
  withStruct 32 $ \(pS, pV) -> do
    rvComp <- haskokiAsyncComplete ctx hJob fnDigest pS
    assertEqual "complete-after-error stale" rvBad rvComp
    assertCanaryStruct "error struct intact" pS
    assertCanaryBuf "error buffer intact" pV 32

caseFfiDrain :: MVar () -> IO ()
caseFfiDrain envLock = do
  ctx <- withEnvLock envLock haskokiAsyncOpen
  assertBool "ctx opened" (castStablePtrToPtr ctx /= nullPtr)
  h <- hSessionOf ctx
  rvInit <- initDigestFfi ctx h
  assertEqual "init ok" rvOK rvInit
  (rv1, _) <- startFfi ctx h fnDigest "abc" 32 5
  (rv2, _) <- startFfi ctx h fnDigest "abc" 32 1
  assertEqual "starts pending" [rvPending, rvPending] [rv1, rv2]
  c <- deRefStablePtr ctx
  nLive <- asyncLiveHandles c
  assertEqual "2 live" 2 nLive
  -- The export's own worker: every pending job cancels exactly once.
  asyncCloseCtx c
  nLive2 <- asyncLiveHandles c
  assertEqual "drained" 0 nLive2
  freeStablePtr ctx

caseFfiDoubleClose :: MVar () -> IO ()
caseFfiDoubleClose envLock =
  alloca $ \(pSlot :: Ptr (StablePtr AsyncCtx)) -> do
    ctx <- withEnvLock envLock haskokiAsyncOpen
    assertBool "ctx opened" (castStablePtrToPtr ctx /= nullPtr)
    poke pSlot ctx
    haskokiAsyncClose pSlot
    haskokiAsyncClose pSlot
    nulled <- peek pSlot
    assertBool "slot stays nulled" (castStablePtrToPtr nulled == nullPtr)

caseSinkShapes :: IO ()
caseSinkShapes = do
  -- Byte completion lands payload + length, zeroing handles.
  withStruct 4 $ \(pS, pV) -> do
    pokeCompletion pS (CompBytes "ab")
    len <- readField pS offValueLen
    ver <- readField pS offVersion
    o1 <- readField pS offObject
    o2 <- readField pS offObject2
    assertEqual "length" (CULong 2) len
    assertEqual "version" (CULong 1) ver
    assertEqual "hObject" (CULong 0) o1
    assertEqual "hAdditional" (CULong 0) o2
    out <- readBytes pV 2
    assertEqual "payload" "ab" out
    rest <- peekArray 2 (pV `plusPtr` 2 :: Ptr Word8)
    assertEqual "tail canary" [0xA5, 0xA5] rest
  -- One-handle completion lands the handle; value bytes stay canary.
  withStruct 4 $ \(pS, pV) -> do
    pokeCompletion pS (CompOneHandle (ExternalHandle 7))
    o1 <- readField pS offObject
    o2 <- readField pS offObject2
    len <- readField pS offValueLen
    assertEqual "hObject" (CULong 7) o1
    assertEqual "hAdditional" (CULong 0) o2
    assertEqual "length zero" (CULong 0) len
    assertCanaryBuf "value canary" pV 4
  -- Two-handle completion lands both handles.
  withStruct 4 $ \(pS, pV) -> do
    pokeCompletion pS (CompTwoHandles (ExternalHandle 3) (ExternalHandle 9))
    o1 <- readField pS offObject
    o2 <- readField pS offObject2
    assertEqual "hObject" (CULong 3) o1
    assertEqual "hAdditional" (CULong 9) o2
    assertCanaryBuf "value canary" pV 4
  -- Sizing poke writes the length only.
  withStruct 4 $ \(pS, pV) -> do
    pokeNeed pS 32
    len <- readField pS offValueLen
    assertEqual "need" (CULong 32) len
    assertCanaryBuf "value canary" pV 4
