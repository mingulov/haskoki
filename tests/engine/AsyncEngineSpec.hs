{- | Attached-job engine proofs over the real OpenSSL4 backend
through the production driver: a planned digest completes
through shaped finisher outputs (exact KAT bytes, slot
terminated); an HMAC sign completes through the legacy path
with RFC 4231 bytes.
-}
{-# LANGUAGE OverloadedStrings #-}
module AsyncEngineSpec (spec) where

import Control.Concurrent.MVar (MVar)
import Control.Exception (bracket, evaluate, finally)
import Control.Monad (forM, forM_, replicateM, when)
import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import Data.Char (digitToInt, isHexDigit)
import Data.IORef (IORef, newIORef, readIORef, modifyIORef', writeIORef)
import qualified Data.Map.Strict as Map
import Data.Maybe (isNothing)
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
import System.Directory (createDirectoryIfMissing)
import System.Mem.StableName (makeStableName)
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
  , haskokiAsyncGetId
  , jobFunctionCode
  , haskokiAsyncOpen
  , haskokiAsyncPoll
  , haskokiAsyncStart
  , pokeCompletion
  , pokeNeed
  )
import Haskoki.FFI.Exports (returnCodeToRV)
import Haskoki.FFI.Standard
  ( StdAcquisition (..)
  , StdAsyncBinding (..)
  , StdInstance (..)
  , StdStore (..)
  , haskokiStdClose
  , haskokiStdCloseAllSessions
  , haskokiStdCloseSession
  , haskokiStdDigest
  , haskokiStdDigestFinal
  , haskokiStdDigestInit
  , haskokiStdDigestUpdate
  , haskokiStdGetSessionInfoWithAsync
  , haskokiStdOpenSession
  , haskokiStdOpenSessionWithAsync
  , lookupStdAsyncBinding
  , openStdInstance
  , openStdInstanceWith
  , stdAcquisition
  )
import Haskoki.Model (Model (..), SessionState (..), lookupSession)
import Haskoki.Operation
  ( CryptoEffect (..)
  , DigestStream (..)
  , SlotKind (..)
  , OpAuth (..)
  , commonOf
  , insertOp
  , lookupSingle
  , mkActiveDigest
  , mkSlotCommon
  , streamOf
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
import Haskoki.Registry (MechanismId (..), Operation (OpDigest))
import Haskoki.Registry.Generated (mustGeneratedId)
import Haskoki.Recipe.Digest (DigestRecipe (..), digestRecipeFor, digestRecipes)
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
  , isAsyncSession
  , newAsyncTable
  , pollJob
  , startJob
  , tableStats
  )
import Haskoki.Runtime.Config (Config, resolveFrom)
import Haskoki.Runtime.Detached (detachSlot, detachToken)
import Haskoki.Runtime.Storage (Store (..), StoreError (..))
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
  , testCase "caseAsyncBorrowedOwnership" (caseAsyncBorrowedOwnership envLock)
  , testCase "caseAsyncAdmissionWidths" (caseAsyncAdmissionWidths envLock)
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

-- ---------------------------------------------------------------------------
-- Standard's borrowed views and Digest-only admission (routing Task 2).
-- These cases catch private-context ownership, per-session tables, accidental
-- synchronous starts, and orphaned allocations on registry publication failure.
-- Configuration fixtures and SQLite files stay inside this task's evidence.
-- ---------------------------------------------------------------------------

stdAsyncConfig :: MVar () -> String -> Bool -> IO Config
stdAsyncConfig envLock tag sqlite = withEnvLock envLock $ do
  let dir = "dist-release-evidence/async-routing/task-2/fixtures"
      path = dir ++ "/" ++ tag ++ ".toml"
  createDirectoryIfMissing True dir
  writeFile path $ unlines $
    [ "schema_version = 1"
    , "profile = \"demo-maximal\""
    , "[async]"
    , "enabled = false"
    , "pending_polls = 19"
    , "[tokens]"
    , "labels = [\"haskoki-demo\", \"other-token\"]"
    , "so_pins = [\"5678\", \"6789\"]"
    , "user_pins = [\"1234\", \"2345\"]"
    ] ++ if sqlite then
      [ "[storage]"
      , "kind = \"sqlite\""
      , "path = \"" ++ dir ++ "/" ++ tag ++ ".db\""
      ] else []
  resolved <- resolveFrom (Just path) Nothing
  either (assertFailure . show) pure resolved

withStdAsync :: Config -> (StablePtr StdInstance -> StdInstance -> IO a) -> IO a
withStdAsync cfg action = bracket (openStdInstance cfg) haskokiStdClose $ \ctx -> do
  assertBool "Standard opened" (castStablePtrToPtr ctx /= nullPtr)
  deRefStablePtr ctx >>= action ctx

openStdAsyncSession :: StablePtr StdInstance -> CULong -> Bool -> IO CULong
openStdAsyncSession ctx slot async = alloca $ \pH -> do
  poke pH 0xA5
  rv <- if async then haskokiStdOpenSessionWithAsync ctx slot 0 1 pH
        else haskokiStdOpenSession ctx slot 0 pH
  assertEqual "open Standard session" rvOK rv
  peek pH

stdSessionId :: CULong -> SessionId
stdSessionId (CULong h) = SessionId (fromIntegral h)

stdAsyncView :: StdInstance -> CULong -> IO (StablePtr AsyncCtx, AsyncCtx)
stdAsyncView inst h = do
  views <- readIORef (siAsyncViews inst)
  case Map.lookup (stdSessionId h) views of
    Nothing -> assertFailure "missing borrowed view"
    Just view -> (view,) <$> deRefStablePtr view

stdDigestBinding :: StdInstance -> CULong -> IO StdAsyncBinding
stdDigestBinding inst h = do
  bindings <- readIORef (siAsyncBindings inst)
  maybe (assertFailure "missing Digest binding") pure $
    lookupStdAsyncBinding (stdSessionId h) JobDigest bindings

assertSameObject :: String -> a -> a -> IO ()
assertSameObject label a b = do
  sa <- evaluate a >>= makeStableName
  sb <- evaluate b >>= makeStableName
  assertBool label (sa == sb)

assertStdEmpty :: StdInstance -> IO ()
assertStdEmpty inst = do
  (live, _, _) <- tableStats (siAsyncTable inst)
  assertEqual "zero live jobs" 0 live
  assertEqual "zero bindings" 0 . Map.size =<< readIORef (siAsyncBindings inst)
  views <- readIORef (siAsyncViews inst)
  forM_ (Map.elems views) $ \view ->
    deRefStablePtr view >>= asyncLiveHandles >>= assertEqual "zero native handles" 0

stdDigestCall :: StablePtr StdInstance -> CULong -> Ptr Word8 -> Ptr CULong -> IO CULong
stdDigestCall ctx h pOut pLen = BS.useAsCStringLen "abc" $ \(pIn, nIn) ->
  haskokiStdDigest ctx h (castPtr pIn) (fromIntegral nIn) pOut pLen

initStdDigest :: StablePtr StdInstance -> CULong -> IO ()
initStdDigest ctx h =
  haskokiStdDigestInit ctx h 0x250 nullPtr 0 >>= assertEqual "SHA-256 init" rvOK

-- Exercise the existing worker directly; the public Complete adapter belongs
-- to Task 3. No test dereferences a private job token, even after completion.
completeStdBorrowed :: StdInstance -> CULong -> Ptr Word8 -> Int -> IO ()
completeStdBorrowed inst h pOut width = do
  (view, c) <- stdAsyncView inst h
  binding <- stdDigestBinding inst h
  assertEqual "binding function" JobDigest (sabFunction binding)
  assertEqual "function code" 2 (jobFunctionCode (sabFunction binding))
  haskokiAsyncPoll view (sabHandle binding) fnDigest >>= assertEqual "first logical poll" rvPending
  haskokiAsyncPoll view (sabHandle binding) fnDigest >>= assertEqual "second logical poll" rvOK
  allocaBytes structSize $ \pS -> do
    pokeArray (castPtr pS) (replicate structSize (0xA5 :: Word8))
    pokeByteOff pS offValue pOut
    pokeByteOff pS offValueLen (CULong (fromIntegral width))
    haskokiAsyncComplete view (sabHandle binding) fnDigest pS >>= assertEqual "worker delivery" rvOK
    readField pS offValueLen >>= assertEqual "recipe output width" (fromIntegral width)
  asyncLiveHandles c >>= assertEqual "worker released handle" 0

caseAsyncBorrowedOwnership :: MVar () -> IO ()
caseAsyncBorrowedOwnership envLock = do
  cfg <- stdAsyncConfig envLock "borrowed-memory" False
  backend <- withStdAsync cfg $ \ctx inst -> do
    assertBool "memory retains no store" (isNothing (siStore inst))
    assertBool "memory retains no detach context" (isNothing (siDetach inst))
    a <- openStdAsyncSession ctx 0 True
    b <- openStdAsyncSession ctx 0 True
    ordinary <- openStdAsyncSession ctx 0 False
    assertEqual "actual distinct model session ids" [1, 2, 3] [a, b, ordinary]
    (_, ca) <- stdAsyncView inst a
    (_, cb) <- stdAsyncView inst b
    (_, co) <- stdAsyncView inst ordinary
    forM_ [(a, ca, True), (b, cb, True), (ordinary, co, False)] $ \(h, c, enabled) -> do
      assertEqual "view uses actual session" (stdSessionId h) (acSession c)
      assertSameObject "borrowed environment" (siEnv inst) (acEnv c)
      -- BackendEnv is a small data-family wrapper that GHC may rebox. Prove
      -- shared native state: feed its Standard-created resource via the view,
      -- then consume that same resource through Standard's backend.
      initStdDigest ctx h
      model <- snapshotModel (siEnv inst)
      st <- maybe (assertFailure "missing backend-proof session") pure (lookupSession model (acSession c))
      op <- maybe (assertFailure "missing backend-proof digest") pure (lookupSingle (ssOps st) SlotDigest)
      stream <- maybe (assertFailure "missing native digest resource") pure (streamOf (commonOf op))
      digestUpdate (acBackend c) (dsResource stream) "abc" >>= assertEqual "borrowed native resource" (EngineOk ())
      allocaBytes 32 $ \pOut -> alloca $ \pLen -> do
        poke pLen 32
        haskokiStdDigestFinal ctx h pOut pLen >>= assertEqual "consume shared backend resource" rvOK
        readBytes pOut 32 >>= assertEqual "shared backend resource KAT" sha256Abc
      assertSameObject "one instance table" (siAsyncTable inst) (acTable c)
      assertBool "memory view cannot detach" (isNothing (acDetach c))
      isAsyncSession (siAsyncTable inst) (acSession c) >>= assertEqual "explicit async only" enabled
      alloca $ \pSlot -> alloca $ \pRO -> alloca $ \pLogin -> alloca $ \pErr -> alloca $ \pAsync -> do
        haskokiStdGetSessionInfoWithAsync ctx h pSlot pRO pLogin pErr pAsync
          >>= assertEqual "session-info ABI" rvOK
        peek pAsync >>= assertEqual "private async scalar" (if enabled then 1 else 0)
    assertBool "separate handle sets" (acLive ca /= acLive cb && acLive ca /= acLive co)
    allocaBytes 32 $ \pOut -> alloca $ \pLen -> do
      forM_ [a, b] $ \h -> do
        initStdDigest ctx h
        poke pLen 32
        stdDigestCall ctx h pOut pLen >>= assertEqual "memory attached start" rvPending
      asyncLiveHandles ca >>= assertEqual "a owns one handle" 1
      asyncLiveHandles cb >>= assertEqual "b owns one handle" 1
      (va, _) <- stdAsyncView inst a
      binding <- stdDigestBinding inst a
      alloca $ \pId -> do
        poke pId (0xA5 :: Word64)
        haskokiAsyncGetId va (sabHandle binding) fnDigest pId >>= assertEqual "memory no-store error" rvGeneral
        peek pId >>= assertEqual "private no-store worker zeros id" 0
      haskokiStdCloseSession ctx a >>= assertEqual "close one borrowed view" rvOK
      asyncLiveHandles ca >>= assertEqual "closed view drained" 0
      asyncLiveHandles cb >>= assertEqual "other view remains live" 1
      completeStdBorrowed inst b pOut 32
      readBytes pOut 32 >>= assertEqual "backend still usable after view close" sha256Abc
      haskokiStdCloseAllSessions ctx 0 >>= assertEqual "close all borrowed views" rvOK
    assertStdEmpty inst
    assertEqual "all views freed from registry" 0 . Map.size =<< readIORef (siAsyncViews inst)
    assertEqual "all model sessions closed" 0 . Map.size . mSessions =<< snapshotModel (siEnv inst)
    pure (siBackend inst)
  -- This uses the backend's guarded operation, never a raw freed pointer.
  randomBytes backend 1 >>= \case
    EngineFail _ -> pure ()
    EngineOk _ -> assertFailure "instance close did not shut its backend"

  sqlCfg <- stdAsyncConfig envLock "borrowed-sqlite" True
  loads <- newIORef (0 :: Int)
  closes <- newIORef (0 :: Int)
  let counted = stdAcquisition { saOpenStore = \env config -> do
        result <- saOpenStore stdAcquisition env config
        pure $ fmap (fmap (\ss -> ss { stdStore = (stdStore ss)
          { storeLoadJobs = modifyIORef' loads (+ 1) >> storeLoadJobs (stdStore ss)
          , storeClose = modifyIORef' closes (+ 1) >> storeClose (stdStore ss)
          } })) result }
  bracket (openStdInstanceWith counted sqlCfg) haskokiStdClose $ \ctx -> do
    assertBool "SQLite Standard opened" (castStablePtrToPtr ctx /= nullPtr)
    inst <- deRefStablePtr ctx
    ss <- maybe (assertFailure "missing owned store") pure (siStore inst)
    dc <- maybe (assertFailure "missing instance detach context") pure (siDetach inst)
    readIORef loads >>= assertEqual "openDetached once over the owned store" 1
    assertEqual "home token" (stdToken ss) (detachToken dc)
    assertEqual "home slot" (SlotId 0) (detachSlot dc)
    home <- openStdAsyncSession ctx 0 True
    other <- openStdAsyncSession ctx 1 True
    (_, ch) <- stdAsyncView inst home
    (_, co) <- stdAsyncView inst other
    dh <- maybe (assertFailure "home view has no detach context") pure (acDetach ch)
    assertSameObject "home borrows instance detach context" dc dh
    assertBool "other slot cannot detach under home token" (isNothing (acDetach co))
    readIORef loads >>= assertEqual "views do not reopen detach context" 1
    allocaBytes 32 $ \pOut -> alloca $ \pLen -> do
      initStdDigest ctx other
      poke pLen 32
      stdDigestCall ctx other pOut pLen >>= assertEqual "other-slot attached start" rvPending
      completeStdBorrowed inst other pOut 32
      readBytes pOut 32 >>= assertEqual "other-slot attached KAT" sha256Abc
      initStdDigest ctx home
      poke pLen 32
      stdDigestCall ctx home pOut pLen >>= assertEqual "home-slot start" rvPending
      (vh, _) <- stdAsyncView inst home
      binding <- stdDigestBinding inst home
      alloca $ \pId ->
        haskokiAsyncGetId vh (sabHandle binding) fnDigest pId >>= assertEqual "home detaches" rvOK
      storeLoadJobs (stdStore ss) >>= \case
        Left err -> assertFailure (show err)
        Right jobs -> assertBool "detached record is in Standard's owned store" (not (null jobs))
      haskokiStdCloseAllSessions ctx 1 >>= assertEqual "close other slot" rvOK
      assertEqual "home view retained" [stdSessionId home] . Map.keys =<< readIORef (siAsyncViews inst)
    readIORef closes >>= assertEqual "borrowed close never closes store" 0
  readIORef closes >>= assertEqual "instance closes store once" 1
  withStdAsync sqlCfg $ \_ _ -> pure () -- writer lease was released

  -- Finalize must drain pending handles and free views even if retirement of
  -- the borrowed detached table throws. Keep the caller allocation alive until
  -- the owned instance has closed, and inspect only Haskell values afterwards.
  forM_ [False, True] $ \throws -> do
    finalCfg <- stdAsyncConfig envLock (if throws then "finalize-throw" else "finalize") True
    retiring <- newIORef False
    finalCloses <- newIORef (0 :: Int)
    let acquisition = stdAcquisition { saOpenStore = \env config -> do
          result <- saOpenStore stdAcquisition env config
          pure $ fmap (fmap (\ss -> ss { stdStore = (stdStore ss)
            { storeLoadJobs = do
                failNow <- readIORef retiring
                when (throws && failNow) (ioError (userError "retirement injection"))
                storeLoadJobs (stdStore ss)
            , storeClose = modifyIORef' finalCloses (+ 1) >> storeClose (stdStore ss)
            } })) result }
    allocaBytes 32 $ \pOut -> alloca $ \pLen -> do
      pokeArray pOut (replicate 32 0xA5)
      poke pLen 32
      (inst, views) <- bracket (openStdInstanceWith acquisition finalCfg)
        (\ctx -> writeIORef retiring True >> haskokiStdClose ctx) $ \ctx -> do
          assertBool "finalize fixture opened" (castStablePtrToPtr ctx /= nullPtr)
          inst <- deRefStablePtr ctx
          hs <- replicateM 2 (openStdAsyncSession ctx 0 True)
          forM_ hs $ \h -> do
            initStdDigest ctx h
            stdDigestCall ctx h pOut pLen >>= assertEqual "pending at finalize" rvPending
          views <- mapM (fmap snd . stdAsyncView inst) hs
          pure (inst, views)
      assertStdEmpty inst
      forM_ views $ \view -> asyncLiveHandles view >>= assertEqual "finalize frees pending handles" 0
      assertEqual "finalize frees every borrowed view" 0 . Map.size =<< readIORef (siAsyncViews inst)
      tableStats (siAsyncTable inst) >>= assertEqual "finalize cancels both jobs" (0, 2, 2)
      readIORef finalCloses >>= assertEqual "finalize closes writer once" 1
      randomBytes (siBackend inst) 1 >>= \case
        EngineFail _ -> pure ()
        EngineOk _ -> assertFailure "finalize left the shared backend live"
      assertCanaryBuf "finalize revokes without delivery" pOut 32
      peek pLen >>= assertEqual "finalize never retains length pointer" 32
    withStdAsync finalCfg $ \_ _ -> pure ()

  -- Fail inside openDetached after both store and backend were acquired.
  -- The injected actions live on test-local store records, not a public API.
  forM_ [False, True] $ \throws -> do
    failedCfg <- stdAsyncConfig envLock (if throws then "detach-throw" else "detach-deny") True
    storeCloses <- newIORef (0 :: Int)
    backendCloses <- newIORef (0 :: Int)
    acquiredBackend <- newIORef Nothing
    let failing = stdAcquisition
          { saOpenStore = \env config -> do
              result <- saOpenStore stdAcquisition env config
              pure $ fmap (fmap (\ss -> ss { stdStore = (stdStore ss)
                { storeLoadJobs = if throws then ioError (userError "detached allocation injection")
                    else pure (Left (StoreIO "detached allocation injection")) } })) result
          , saOpenBackend = do
              result <- saOpenBackend stdAcquisition
              case result of
                EngineOk be -> writeIORef acquiredBackend (Just be)
                EngineFail _ -> pure ()
              pure result
          , saCloseBackend = \be -> modifyIORef' backendCloses (+ 1) >> saCloseBackend stdAcquisition be
          , saCloseStore = \ss -> modifyIORef' storeCloses (+ 1) >> saCloseStore stdAcquisition ss
          }
    failed <- openStdInstanceWith failing failedCfg
    assertBool "failed detached allocation returns no instance/view" (castStablePtrToPtr failed == nullPtr)
    readIORef storeCloses >>= assertEqual "failed allocation closes writer once" 1
    readIORef backendCloses >>= assertEqual "failed allocation closes backend once" 1
    readIORef acquiredBackend >>= \case
      Nothing -> assertFailure "backend was not acquired before injection"
      Just be -> randomBytes be 1 >>= \case
        EngineFail _ -> pure ()
        EngineOk _ -> assertFailure "failed allocation leaked live backend"
    withStdAsync failedCfg $ \_ inst -> do
      assertEqual "fresh instance has no leaked views" 0 . Map.size =<< readIORef (siAsyncViews inst)
      assertEqual "fresh instance has no session admission" 0 . Map.size . mSessions =<< snapshotModel (siEnv inst)

  withStdAsync cfg $ \ctx inst -> do
    -- A bottom in the destination map throws when the new view is installed.
    -- Restore it for inspection and the enclosing instance's normal close.
    writeIORef (siAsyncViews inst) (error "view installation injection")
    alloca (\pH -> do
      poke pH 0xA5
      haskokiStdOpenSessionWithAsync ctx 0 0 1 pH >>= assertEqual "view install failure fenced" rvGeneral
      peek pH >>= assertEqual "failed view never publishes caller handle" 0xA5)
      `finally` writeIORef (siAsyncViews inst) Map.empty
    assertEqual "failed view leaves no admitted session" 0 . Map.size . mSessions =<< snapshotModel (siEnv inst)
    assertStdEmpty inst
    h <- openStdAsyncSession ctx 0 True
    initStdDigest ctx h -- shared backend survives failed view installation

caseAsyncAdmissionWidths :: MVar () -> IO ()
caseAsyncAdmissionWidths envLock = do
  cfg <- stdAsyncConfig envLock "admission" False
  withStdAsync cfg $ \ctx inst -> do
    h <- openStdAsyncSession ctx 0 True
    initStdDigest ctx h
    allocaBytes 3 $ \pIn -> allocaBytes 32 $ \pOut -> alloca $ \pLen -> do
      pokeArray pIn [97, 98, 99]
      pokeArray pOut (replicate 32 0xA5)
      poke pLen 32
      haskokiStdDigest ctx h pIn 3 pOut pLen >>= assertEqual "fresh full-buffer admission" rvPending
      pokeArray pIn [120, 120, 120]
      assertCanaryBuf "start does not write output" pOut 32
      peek pLen >>= assertEqual "start does not write length" 32
      binding <- stdDigestBinding inst h
      assertEqual "bound caller output" pOut (sabOutput binding)
      assertEqual "bound capacity" 32 (sabCapacity binding)
      completeStdBorrowed inst h pOut 32
      readBytes pOut 32 >>= assertEqual "input copied before caller mutation" sha256Abc
      peek pLen >>= assertEqual "length pointer never retained" 32
    haskokiStdCloseSession ctx h >>= assertEqual "retire completed worker binding" rvOK
    assertStdEmpty inst

  -- Widths come from the canonical recipe list; no adapter-local numeric table.
  -- Every recipe must execute, and width-1 must stay on the short/recall path.
  forM_ digestRecipes $ \recipe -> withStdAsync cfg $ \ctx inst -> do
    let mid = MechanismId (mustGeneratedId (drName recipe))
        width = drOutLen recipe
    assertEqual "canonical recipe lookup" (Just recipe) (digestRecipeFor mid)
    h <- openStdAsyncSession ctx 0 True
    let initRecipe = haskokiStdDigestInit ctx h (fromIntegral (unMechanismId mid)) nullPtr 0
          >>= assertEqual ("init " ++ show (drName recipe)) rvOK
    initRecipe
    allocaBytes width $ \pOut -> alloca $ \pLen -> do
      pokeArray pOut (replicate width 0xA5)
      poke pLen (fromIntegral (width - 1))
      stdDigestCall ctx h pOut pLen >>= assertEqual "recipe short" rvShort
      peek pLen >>= assertEqual "recipe short need" (fromIntegral width)
      assertCanaryBuf "recipe short output untouched" pOut width
      assertStdEmpty inst
      stdDigestCall ctx h pOut pLen >>= assertEqual "recipe recall stays synchronous" rvOK
      expected <- readBytes pOut width
      assertStdEmpty inst
      initRecipe
      poke pLen (fromIntegral width)
      pokeArray pOut (replicate width 0xA5)
      stdDigestCall ctx h pOut pLen >>= assertEqual "recipe full start" rvPending
      binding <- stdDigestBinding inst h
      assertEqual "recipe admitted capacity" (fromIntegral width) (sabCapacity binding)
      assertCanaryBuf "recipe start output untouched" pOut width
      completeStdBorrowed inst h pOut width
      readBytes pOut width >>= assertEqual "async agrees with real synchronous digest" expected

  forM_ [32, maxOutputBytes, maxOutputBytes + 1, maxBound] $ \cap ->
    withStdAsync cfg $ \ctx inst -> do
      h <- openStdAsyncSession ctx 0 True
      initStdDigest ctx h
      allocaBytes 32 $ \pOut -> alloca $ \pLen -> do
        -- Capacity metadata only: no huge allocation and no completion write.
        poke pLen (CULong cap)
        stdDigestCall ctx h pOut pLen >>= assertEqual "bounded capacity starts" rvPending
        binding <- stdDigestBinding inst h
        assertEqual "effective capacity" (min cap 16777216) (sabCapacity binding)
        peek pLen >>= assertEqual "capacity word unchanged" (CULong cap)
        haskokiStdCloseSession ctx h >>= assertEqual "cancel metadata-only start" rvOK
      assertStdEmpty inst

  forM_ [Nothing, Just 0, Just 31] $ \capacity -> withStdAsync cfg $ \ctx inst -> do
    h <- openStdAsyncSession ctx 0 True
    initStdDigest ctx h
    allocaBytes 32 $ \pOut -> alloca $ \pLen -> do
      pokeArray pOut (replicate 32 0xA5)
      poke pLen (maybe 0xA5 id capacity)
      stdDigestCall ctx h (maybe nullPtr (const pOut) capacity) pLen
        >>= assertEqual "query/zero/short dialogue" (maybe rvOK (const rvShort) capacity)
      peek pLen >>= assertEqual "SHA-256 need" 32
      assertCanaryBuf "query/short canary" pOut 32
      tableStats (siAsyncTable inst) >>= assertEqual "query/short allocate no ids" (0, 0, 0)
      assertStdEmpty inst
      stdDigestCall ctx h pOut pLen >>= assertEqual "staged recall synchronous" rvOK
      readBytes pOut 32 >>= assertEqual "staged KAT" sha256Abc
      tableStats (siAsyncTable inst) >>= assertEqual "recall allocates no ids" (0, 0, 0)
      assertStdEmpty inst

  withStdAsync cfg $ \ctx inst -> do
    h <- openStdAsyncSession ctx 0 False
    initStdDigest ctx h
    allocaBytes 32 $ \pOut -> alloca $ \pLen -> do
      poke pLen 32
      stdDigestCall ctx h pOut pLen >>= assertEqual "ordinary synchronous digest" rvOK
      readBytes pOut 32 >>= assertEqual "ordinary KAT" sha256Abc
    assertStdEmpty inst

  withStdAsync cfg $ \ctx inst -> do
    h <- openStdAsyncSession ctx 0 True
    initStdDigest ctx h
    -- A real planner refusal after multipart input must not become a job.
    BS.useAsCStringLen "a" $ \(p, n) ->
      haskokiStdDigestUpdate ctx h (castPtr p) (fromIntegral n) >>= assertEqual "multipart feed" rvOK
    allocaBytes 32 $ \pOut -> alloca $ \pLen -> do
      poke pLen 32
      stdDigestCall ctx h pOut pLen >>= assertEqual "planner refusal preserved" (CULong 0x90)
    assertStdEmpty inst

  withStdAsync cfg $ \ctx inst -> do
    h <- openStdAsyncSession ctx 0 True
    m <- snapshotModel (siEnv inst)
    st <- maybe (assertFailure "missing session") pure (lookupSession m (stdSessionId h))
    let absent = MechanismId 0xFFFFFFFF
        ops = insertOp (mkActiveDigest (mkSlotCommon absent OpDigest Nothing BS.empty AuthNone)) (ssOps st)
    assertEqual "injected recipe is absent" Nothing (digestRecipeFor absent)
    publish (siEnv inst) (O.StateDelta [O.DeltaSetSessionOps (stdSessionId h) ops])
      >>= assertEqual "install recipe-miss fixture" (Right ())
    allocaBytes 32 $ \pOut -> alloca $ \pLen -> do
      poke pLen 32
      stdDigestCall ctx h pOut pLen >>= assertEqual "recipe miss uses synchronous unsupported effect" (CULong 0x70)
    assertStdEmpty inst

  withStdAsync cfg $ \ctx inst -> do
    first <- openStdAsyncSession ctx 0 True
    middle <- replicateM 7 (openStdAsyncSession ctx 0 True)
    ninth <- openStdAsyncSession ctx 0 True
    let sessions = first : middle ++ [ninth]
    forM_ sessions (initStdDigest ctx)
    allocaBytes 32 $ \pOut -> alloca $ \pLen -> do
      forM_ (take 8 sessions) $ \h -> do
        poke pLen 32
        stdDigestCall ctx h pOut pLen >>= assertEqual "first eight starts" rvPending
      tableStats (siAsyncTable inst) >>= assertEqual "shared table capacity eight" (8, 0, 8)
      assertEqual "eight exact bindings" 8 . Map.size =<< readIORef (siAsyncBindings inst)
      live <- forM sessions $ \h -> snd <$> stdAsyncView inst h >>= asyncLiveHandles
      assertEqual "separate live-handle sets" (replicate 8 1 ++ [0]) live
      poke pLen 32
      stdDigestCall ctx ninth pOut pLen >>= assertEqual "ninth start refused" rvHostMem
      tableStats (siAsyncTable inst) >>= assertEqual "refusal allocates nothing" (8, 0, 8)
      assertEqual "refusal leaves eight bindings" 8 . Map.size =<< readIORef (siAsyncBindings inst)
      haskokiStdCloseSession ctx first >>= assertEqual "close cancels one job" rvOK
      stdDigestCall ctx ninth pOut pLen >>= assertEqual "retry after cancellation" rvPending
      tableStats (siAsyncTable inst) >>= assertEqual "capacity reused" (8, 1, 9)
      haskokiStdCloseAllSessions ctx 0 >>= assertEqual "drain full table" rvOK
    assertStdEmpty inst

  withStdAsync cfg $ \ctx inst -> do
    h <- openStdAsyncSession ctx 0 True
    initStdDigest ctx h
    writeIORef (siAsyncBindings inst) (error "binding installation injection")
    (allocaBytes 32 $ \pOut -> alloca $ \pLen -> do
      pokeArray pOut (replicate 32 0xA5)
      poke pLen 32
      stdDigestCall ctx h pOut pLen >>= assertEqual "binding failure fenced" rvGeneral
      assertCanaryBuf "failed binding never writes output" pOut 32
      peek pLen >>= assertEqual "failed binding never writes length" 32)
      `finally` writeIORef (siAsyncBindings inst) Map.empty
    tableStats (siAsyncTable inst) >>= assertEqual "allocated job canceled before unwind" (0, 1, 1)
    assertStdEmpty inst
