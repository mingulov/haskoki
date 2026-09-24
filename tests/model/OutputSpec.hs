{- | Exact output planning tests.

Part 1: one-shot sign-final size query followed by short/exact
retries consumes the input exactly once and writes nothing until the
exact call.
-}
{-# LANGUAGE OverloadedStrings #-}
module OutputSpec (spec) where

import qualified Data.ByteString as BS
import Data.IORef (IORef, atomicModifyIORef', newIORef, readIORef, writeIORef)
import Data.Word (Word32, Word64, Word8)
import Foreign.C.Types (CULong (..))
import Foreign.Marshal.Alloc (alloca, allocaBytes)
import Foreign.Ptr (Ptr, nullPtr, plusPtr)
import Foreign.Storable (peek, poke)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertBool, assertEqual, assertFailure, testCase)

import Haskoki.Engine.Backend
  ( BackendEnv
  , CryptoBackend (..)
  , DigestAlg (..)
  , EngineResult (..)
  , ResourceSaveability (..)
  , UnsaveableReason (..)
  )
import Haskoki.Engine.Synthetic (Synthetic)
import Haskoki.FFI.Decode
  ( DecodeError (..)
  , decodeInputBytes
  , decodeIntent
  , maxInputBytes
  )
import Haskoki.FFI.Encode
  ( BoundBuffer (..)
  , EncodeReport (..)
  , encodeLength
  , encodeWrites
  )
import Haskoki.Object (decodeHandle)
import Haskoki.Outcome
  ( DeltaOp (..)
  , ModelFault (..)
  , PreparedCommit (..)
  , ResourceRelease (..)
  , StateDelta (..)
  )
import Haskoki.Rules (defaultRules)
import Haskoki.Runtime.Lifecycle
  ( Gate
  , MutexCounts (..)
  , MutexHooks (..)
  , adapterCounts
  , adapterLive
  , commitAndDeliver
  , envAdapter
  , envGate
  , gateBusy
  , newEnv
  , newEnvWith
  , referenceHooks
  , withGate
  )
import Haskoki.Output
  ( BindError (..)
  , Binding (..)
  , DataSource (..)
  , LegResult (..)
  , LengthError (..)
  , OpDisposition (..)
  , OutputPlan (..)
  , RegionOutcome (..)
  , ResultDisposition (..)
  , TypedWrite (..)
  , WritePayload (..)
  , bindRegions
  , checkedTotal
  , checkedULong
  , maxOutputBytes
  , planBatch
  , planGeneratedIV
  , planOneShot
  , planOutputs
  , typedWriteBytes
  )
import Haskoki.Request (OutputIntent (..), OutputRegion (..))
import Haskoki.Types (BindingId (..), Consumption (..), EngineResourceId (..), ExternalHandle (..), OpState (..), ReturnCode (..), SessionId (..))

spec :: TestTree
spec = testGroup "exact output planning"
  [ testCase "sign-final: query/short/exact consumes input once" caseOneShotSequence
  , testCase "null versus zero capacity are distinct" caseNullVsZero
  , testCase "scalar plan writes fixed width" caseScalar
  , testCase "handle plan writes decodable bytes" caseHandle
  , testCase "byte plan honors capacity" caseBytes
  , testCase "nested plan recurses with paths" caseNested
  , testCase "kind mismatch rejects" caseMismatch
  , testCase "checked conversion rejects overflow" caseChecked
  , testCase "oversized sources and duplicate bindings rejected" caseBounds
  , testCase "partial reads deliver successes under a failing code" casePartial
  , testCase "multi-handle transaction releases only failed legs" caseMultiHandle
  , testCase "short legs keep their resources for retry" caseShortKeeps
  , testCase "generated IV writes back into nested params" caseGeneratedIV
  , testCase "wrong-length IV rejects without writing" caseGeneratedIVLength
  , testCase "decode: null pointer means size query" caseDecodeIntent
  , testCase "decode: bounded input copy with null guards" caseDecodeInput
  , testCase "encode: exact write keeps canaries" caseEncodeCanaries
  , testCase "encode: short write touches nothing" caseEncodeShort
  , testCase "encode: missing binding fails clean, full width lands" caseEncodeBad
  , testCase "encode: nested writeback lands at its path" caseEncodeNested
  , testCase "encode: length answers poke or reject null" caseEncodeLength
  , testCase "A05: no callbacks while holding the model gate" caseGateNoCallbacks
  , testCase "A05: gate probe detects held gate" caseGateProbeDetects
  , testCase "A05: faulted publish skips delivery" caseGateFaultSkipsDelivery
  , testCase "Commit carrying releases drains them" caseReleasesDrainedOnCommit
  ]

sig32 :: BS.ByteString
sig32 = BS.pack [1 .. 32]

-- | Size query, short retry, exact retry: only the exact call writes
-- and consumes; a retry after termination fails without consuming.
caseOneShotSequence :: IO ()
caseOneShotSequence = do
  let live0 = OpLive (Consumption 0)
  let (st1, q) = planOneShot live0 "sig" sig32 IntentNull
  assertEqual "query keeps op live unconsumed" live0 st1
  assertEqual "query code" CKR_OK (opCode q)
  assertEqual "query writes nothing" [] (opWrites q)
  assertEqual "query reports required" [(["sig"], 32)] (opLengths q)
  assertEqual "query keeps op"
    [ResultDisposition ["sig"] CKR_OK OpKeep] (opDispositions q)
  let (st2, short) = planOneShot st1 "sig" sig32 (IntentBuffer 16)
  assertEqual "short keeps op live unconsumed" live0 st2
  assertEqual "short code" CKR_BUFFER_TOO_SMALL (opCode short)
  assertEqual "short writes nothing" [] (opWrites short)
  assertEqual "short reports required" [(["sig"], 32)] (opLengths short)
  assertEqual "short keeps op for retry"
    [ResultDisposition ["sig"] CKR_BUFFER_TOO_SMALL OpKeep]
    (opDispositions short)
  let (st3, exact) = planOneShot st2 "sig" sig32 (IntentBuffer 32)
  assertEqual "exact consumes once" (OpLive (Consumption 1)) st3
  assertEqual "exact code" CKR_OK (opCode exact)
  assertEqual "exact writes payload" 1 (length (opWrites exact))
  case opWrites exact of
    [w] -> do
      assertEqual "write path" ["sig"] (twPath w)
      assertEqual "write payload" (PayloadBytes sig32) (twPayload w)
    _ -> error "unreachable: length asserted above"
  assertEqual "exact terminates op"
    [ResultDisposition ["sig"] CKR_OK OpTerminate] (opDispositions exact)
  -- The terminal call ends the operation: model the runtime honoring
  -- OpTerminate by parking OpDead, then prove a further retry fails
  -- cleanly without consuming again.
  let (st4, retry) = planOneShot OpDead "sig" sig32 (IntentBuffer 32)
  assertEqual "retry stays dead" OpDead st4
  assertEqual "retry code" CKR_GENERAL_ERROR (opCode retry)
  assertEqual "retry writes nothing" [] (opWrites retry)

-- ---------------------------------------------------------------------------
-- Part 2: region plans, null-versus-zero, checked conversion
-- ---------------------------------------------------------------------------

okOutcome :: OutputRegion -> DataSource -> RegionOutcome
okOutcome region src = RegionOutcome region (Right src)

-- | Null queries while a zero-capacity buffer is a short buffer: the
-- two calls plan differently. A zero-capacity buffer only succeeds
-- for an empty value.
caseNullVsZero :: IO ()
caseNullVsZero = do
  let query = planOutputs [okOutcome (RegionBytes "v" IntentNull) (SourceBytes "abc")]
  assertEqual "query code" CKR_OK (opCode query)
  assertEqual "query writes nothing" [] (opWrites query)
  assertEqual "query reports required" [(["v"], 3)] (opLengths query)
  let zero = planOutputs
        [okOutcome (RegionBytes "v" (IntentBuffer 0)) (SourceBytes "abc")]
  assertEqual "zero-cap is a short buffer" CKR_BUFFER_TOO_SMALL (opCode zero)
  assertEqual "zero-cap writes nothing" [] (opWrites zero)
  assertEqual "zero-cap reports required" [(["v"], 3)] (opLengths zero)
  let empty = planOutputs
        [okOutcome (RegionBytes "v" (IntentBuffer 0)) (SourceBytes "")]
  assertEqual "zero-cap empty succeeds" CKR_OK (opCode empty)
  assertEqual "zero-cap empty writes once" 1 (length (opWrites empty))

-- | Scalar regions always write their fixed 8-byte width; the
-- full 'Word64' domain plans (the old past-'Int'-range
-- planner rejection retired with the 'Int' payload).
caseScalar :: IO ()
caseScalar = do
  let plan = planOutputs [okOutcome (RegionScalar "count") (SourceULong 7)]
  assertEqual "scalar code" CKR_OK (opCode plan)
  assertEqual "scalar length" [(["count"], 8)] (opLengths plan)
  case opWrites plan of
    [w] -> do
      assertEqual "scalar path" ["count"] (twPath w)
      assertEqual "scalar payload" (PayloadULong 7) (twPayload w)
      assertEqual "scalar bytes"
        (Just (BS.pack [0, 0, 0, 0, 0, 0, 0, 7])) (typedWriteBytes w)
    _ -> error "scalar must plan exactly one write"
  let huge = planOutputs [okOutcome (RegionScalar "count") (SourceULong (2 ^ (63 :: Int)))]
  assertEqual "full-width scalar plans" CKR_OK (opCode huge)
  case opWrites huge of
    [w] -> assertEqual "full-width scalar bytes"
      (Just (BS.pack [0x80, 0, 0, 0, 0, 0, 0, 0])) (typedWriteBytes w)
    _ -> error "full-width scalar must plan exactly one write"

-- | Handle regions write bytes that decode back to the handle.
caseHandle :: IO ()
caseHandle = do
  let plan = planOutputs
        [okOutcome (RegionHandle "obj") (SourceHandle (ExternalHandle 9))]
  assertEqual "handle code" CKR_OK (opCode plan)
  assertEqual "handle length" [(["obj"], 8)] (opLengths plan)
  case opWrites plan of
    [w] -> case typedWriteBytes w of
      Nothing -> error "handle write must encode"
      Just bs -> assertEqual "handle roundtrip"
        (Just (ExternalHandle 9)) (decodeHandle bs)
    _ -> error "handle must plan exactly one write"

-- | Byte regions follow the size-query/short/exact contract through
-- the general planner too.
caseBytes :: IO ()
caseBytes = do
  let exact = planOutputs
        [okOutcome (RegionBytes "b" (IntentBuffer 4)) (SourceBytes "data")]
  assertEqual "exact code" CKR_OK (opCode exact)
  assertEqual "exact writes once" 1 (length (opWrites exact))
  let short = planOutputs
        [okOutcome (RegionBytes "b" (IntentBuffer 3)) (SourceBytes "data")]
  assertEqual "short code" CKR_BUFFER_TOO_SMALL (opCode short)
  assertEqual "short writes nothing" [] (opWrites short)
  assertEqual "short reports required" [(["b"], 4)] (opLengths short)

-- | Nested regions plan field-by-field with extended paths; a source
-- missing a field rejects the nested leg.
caseNested :: IO ()
caseNested = do
  let region = RegionNested "mech" [RegionBytes "iv" (IntentBuffer 16)]
      iv = BS.replicate 16 0xA5
      plan = planOutputs [okOutcome region (SourceNested [("iv", SourceBytes iv)])]
  assertEqual "nested code" CKR_OK (opCode plan)
  case opWrites plan of
    [w] -> do
      assertEqual "nested path" ["mech", "iv"] (twPath w)
      assertEqual "nested payload" (PayloadBytes iv) (twPayload w)
    _ -> error "nested must plan exactly one write"
  assertEqual "nested length" [(["mech", "iv"], 16)] (opLengths plan)
  let missing = planOutputs [okOutcome region (SourceNested [])]
  assertEqual "missing field rejects" CKR_ARGUMENTS_BAD (opCode missing)
  assertEqual "missing field writes nothing" [] (opWrites missing)

-- | A source of the wrong kind for its region rejects; nothing is
-- written on any mismatch.
caseMismatch :: IO ()
caseMismatch = do
  let bad =
        [ okOutcome (RegionScalar "s") (SourceBytes "x")
        , okOutcome (RegionHandle "h") (SourceULong 1)
        , okOutcome (RegionBytes "b" IntentNull) (SourceULong 1)
        , okOutcome (RegionNested "n" []) (SourceBytes "x")
        , okOutcome (RegionScalar "s") (SourceNested [])
        ]
  mapM_ check bad
  where
    check outcome = do
      let plan = planOutputs [outcome]
      assertEqual ("mismatch rejects: " ++ show outcome)
        CKR_ARGUMENTS_BAD (opCode plan)
      assertEqual "mismatch writes nothing" [] (opWrites plan)

-- | Length conversion is checked: negatives and values past the
-- 64-bit bound reject, and totals that wrap reject too.
caseChecked :: IO ()
caseChecked = do
  assertEqual "negative rejects" (Left (LengthNegative (-1))) (checkedULong (-1))
  assertEqual "2^64 rejects"
    (Left (LengthTooLarge (2 ^ (64 :: Int)))) (checkedULong (2 ^ (64 :: Int)))
  assertEqual "zero converts" (Right 0) (checkedULong 0)
  assertEqual "maxBound converts"
    (Right (maxBound :: Word64)) (checkedULong (toInteger (maxBound :: Word64)))
  assertEqual "small total" (Right 3) (checkedTotal [1, 2])
  assertEqual "wrapping total rejects"
    (Left (LengthTooLarge (2 ^ (64 :: Int))))
    (checkedTotal [maxBound, 1])

-- | Sources past the output bound reject, and regions whose leaf
-- paths collide fail to bind (the encoder could not tell their
-- write targets apart).
caseBounds :: IO ()
caseBounds = do
  assertBool "bound is positive" (maxOutputBytes > 0)
  let huge = BS.replicate (fromIntegral maxOutputBytes + 1) 0
      plan = planOutputs [okOutcome (RegionBytes "b" IntentNull) (SourceBytes huge)]
  assertEqual "oversized source rejects" CKR_ARGUMENTS_BAD (opCode plan)
  assertEqual "oversized source writes nothing" [] (opWrites plan)
  case bindRegions [RegionScalar "a", RegionScalar "b"] of
    Left err -> error ("distinct regions must bind: " ++ show err)
    Right binds -> do
      assertEqual "binding ids" [0, 1] (map (unBindingId . bindId) binds)
      assertEqual "binding paths" [["a"], ["b"]] (map bindPath binds)
      assertEqual "scalar bounds" [8, 8] (map bindBound binds)
  case bindRegions [RegionScalar "a", RegionScalar "a"] of
    Left (BindDuplicate ["a"]) -> pure ()
    other -> error ("duplicate paths must fail to bind: " ++ show other)
  let dupPlan = planOutputs
        [ okOutcome (RegionScalar "a") (SourceULong 1)
        , okOutcome (RegionScalar "a") (SourceULong 2)
        ]
  assertEqual "duplicate regions reject" CKR_ARGUMENTS_BAD (opCode dupPlan)
  assertEqual "duplicate regions write nothing" [] (opWrites dupPlan)

-- ---------------------------------------------------------------------------
-- Part 3: partial reads, multi-handle transactions, dispositions
-- ---------------------------------------------------------------------------

leg :: OutputRegion -> Either ReturnCode DataSource -> LegResult
leg region outcome = LegResult region outcome Nothing

resLeg :: OutputRegion -> Either ReturnCode DataSource -> Word32 -> LegResult
resLeg region outcome rid =
  LegResult region outcome (Just (EngineResourceId rid))

-- | A mixed batch plans its successful legs (writes plus reported
-- lengths, short legs included) under the first failure's overall
-- code, with one disposition per result.
casePartial :: IO ()
casePartial = do
  let plan = planBatch
        [ leg (RegionBytes "a" (IntentBuffer 8)) (Right (SourceBytes "value"))
        , leg (RegionBytes "b" IntentNull) (Left CKR_ATTRIBUTE_SENSITIVE)
        , leg (RegionBytes "c" (IntentBuffer 1)) (Right (SourceBytes "long"))
        ]
  assertEqual "overall is first failure" CKR_ATTRIBUTE_SENSITIVE (opCode plan)
  assertEqual "only successes write" [["a"]] (map twPath (opWrites plan))
  assertEqual "success and short lengths reported"
    [(["a"], 5), (["c"], 4)] (opLengths plan)
  assertEqual "one disposition per result"
    [ ResultDisposition ["a"] CKR_OK OpKeep
    , ResultDisposition ["b"] CKR_ATTRIBUTE_SENSITIVE OpKeep
    , ResultDisposition ["c"] CKR_BUFFER_TOO_SMALL OpKeep
    ]
    (opDispositions plan)

-- | Each leg of a multi-handle transaction disposes only its own
-- engine resource: the failed leg releases exactly its resource
-- while the successful legs keep theirs (no generic cleanup).
caseMultiHandle :: IO ()
caseMultiHandle = do
  let plan = planBatch
        [ leg (RegionHandle "h1") (Right (SourceHandle (ExternalHandle 1)))
        , resLeg (RegionHandle "h2") (Left CKR_ATTRIBUTE_SENSITIVE) 2
        , resLeg (RegionHandle "h3") (Right (SourceHandle (ExternalHandle 3))) 3
        ]
  assertEqual "overall is the failure" CKR_ATTRIBUTE_SENSITIVE (opCode plan)
  assertEqual "live handles still write"
    [["h1"], ["h3"]] (map twPath (opWrites plan))
  assertEqual "only the failed leg releases"
    [ ResultDisposition ["h1"] CKR_OK OpKeep
    , ResultDisposition ["h2"] CKR_ATTRIBUTE_SENSITIVE
        (OpRelease (EngineResourceId 2))
    , ResultDisposition ["h3"] CKR_OK OpKeep
    ]
    (opDispositions plan)

-- | A short buffer is retryable, never terminal: the leg keeps its
-- engine resource, reports the required length, and writes nothing.
caseShortKeeps :: IO ()
caseShortKeeps = do
  let plan = planBatch
        [ resLeg (RegionBytes "b" (IntentBuffer 2)) (Right (SourceBytes "long")) 7 ]
  assertEqual "short code" CKR_BUFFER_TOO_SMALL (opCode plan)
  assertEqual "short writes nothing" [] (opWrites plan)
  assertEqual "short reports required" [(["b"], 4)] (opLengths plan)
  assertEqual "short keeps its resource"
    [ResultDisposition ["b"] CKR_BUFFER_TOO_SMALL OpKeep] (opDispositions plan)

-- ---------------------------------------------------------------------------
-- Part 4: generated-IV nested writeback
-- ---------------------------------------------------------------------------

-- | The generated-IV vertical slice: a fresh IV writes back into the
-- nested mechanism-params buffer at its full path, proving nested
-- writeback works before broad mechanisms arrive.
caseGeneratedIV :: IO ()
caseGeneratedIV = do
  let iv = BS.pack [1 .. 12]
      plan = planGeneratedIV "mech-gcm" 12 iv (IntentBuffer 12)
  assertEqual "iv code" CKR_OK (opCode plan)
  assertEqual "iv length" [(["mech-gcm", "iv"], 12)] (opLengths plan)
  case opWrites plan of
    [w] -> do
      assertEqual "iv path" ["mech-gcm", "iv"] (twPath w)
      assertEqual "iv payload" (PayloadBytes iv) (twPayload w)
      assertEqual "iv bytes" (Just iv) (typedWriteBytes w)
    _ -> error "iv writeback must plan exactly one write"
  assertEqual "iv keeps op"
    [ResultDisposition ["mech-gcm", "iv"] CKR_OK OpKeep] (opDispositions plan)

-- | An IV of the wrong length for its mechanism rejects without
-- writing; a short IV buffer stays retryable with its length
-- reported.
caseGeneratedIVLength :: IO ()
caseGeneratedIVLength = do
  let wrong = planGeneratedIV "mech-gcm" 12 (BS.replicate 16 0) (IntentBuffer 16)
  assertEqual "wrong-length IV rejects" CKR_ARGUMENTS_BAD (opCode wrong)
  assertEqual "wrong-length IV writes nothing" [] (opWrites wrong)
  let short = planGeneratedIV "mech-gcm" 12 (BS.pack [1 .. 12]) (IntentBuffer 8)
  assertEqual "short IV buffer" CKR_BUFFER_TOO_SMALL (opCode short)
  assertEqual "short IV writes nothing" [] (opWrites short)
  assertEqual "short IV reports required"
    [(["mech-gcm", "iv"], 12)] (opLengths short)

-- ---------------------------------------------------------------------------
-- Part 5: native decode/encode side
-- ---------------------------------------------------------------------------

-- | A null buffer pointer decodes to a size-query intent however the
-- length word reads; a live pointer decodes to a bounded buffer.
caseDecodeIntent :: IO ()
caseDecodeIntent = do
  assertEqual "null is a query" IntentNull
    (decodeIntent (nullPtr :: Ptr Word8) 99)
  allocaBytes 1 $ \ptr ->
    assertEqual "live pointer is a buffer" (IntentBuffer 7)
      (decodeIntent ptr 7)

-- | Input decoding copies bounded bytes, accepts null-with-zero as
-- empty, and rejects null-with-length plus over-bound lengths (the
-- bound is checked before any dereference).
caseDecodeInput :: IO ()
caseDecodeInput = do
  allocaBytes 4 $ \ptr -> do
    poke (ptr `plusPtr` 0) (1 :: Word8)
    poke (ptr `plusPtr` 1) (2 :: Word8)
    poke (ptr `plusPtr` 2) (3 :: Word8)
    poke (ptr `plusPtr` 3) (4 :: Word8)
    decoded <- decodeInputBytes ptr 4
    assertEqual "bytes copied" (Right (BS.pack [1, 2, 3, 4])) decoded
  empty <- decodeInputBytes (nullPtr :: Ptr Word8) 0
  assertEqual "null with zero is empty" (Right BS.empty) empty
  nullLen <- decodeInputBytes (nullPtr :: Ptr Word8) 3
  assertEqual "null with length rejected" (Left (DecodeNullInput 3)) nullLen
  huge <- decodeInputBytes (nullPtr :: Ptr Word8) (maxInputBytes + 1)
  assertEqual "over-bound rejected before dereference"
    (Left (DecodeTooLarge (maxInputBytes + 1))) huge

canary :: Word8
canary = 0xC3

filler :: Word8
filler = 0xAA

-- | Run an action over a canary-guarded buffer of the given capacity:
-- one canary byte on each side, the body pre-filled.
withGuarded :: Int -> (Ptr Word8 -> IO a) -> IO (a, Word8, Word8, [Word8])
withGuarded cap action = allocaBytes (cap + 2) $ \base -> do
  let buf = base `plusPtr` 1
  poke base canary
  poke (base `plusPtr` (cap + 1)) canary
  mapM_ (\i -> poke (buf `plusPtr` i) filler) [0 .. cap - 1]
  r <- action buf
  lo <- peek base
  hi <- peek (base `plusPtr` (cap + 1))
  body <- mapM (peek . (buf `plusPtr`)) [0 .. cap - 1]
  pure (r, lo, hi, body)

-- | The exact one-shot write lands byte-for-byte with both canaries
-- intact; plans with no writes encode to no reports.
caseEncodeCanaries :: IO ()
caseEncodeCanaries = do
  (reports, lo, hi, body) <- withGuarded 32 $ \buf -> do
    let (_, plan) = planOneShot (OpLive (Consumption 0)) "sig" sig32 (IntentBuffer 32)
    encodeWrites [BoundBuffer ["sig"] buf 32] (opWrites plan)
  assertEqual "one ok report"
    [EncodeReport ["sig"] 32 CKR_OK] reports
  assertEqual "payload landed" (BS.unpack sig32) body
  assertEqual "low canary" canary lo
  assertEqual "high canary" canary hi
  none <- encodeWrites [] []
  assertEqual "no writes, no reports" [] none

-- | A write past its buffer's capacity reports short and touches
-- neither the buffer nor its canaries.
caseEncodeShort :: IO ()
caseEncodeShort = do
  (reports, lo, hi, body) <- withGuarded 16 $ \buf -> do
    let (_, plan) = planOneShot (OpLive (Consumption 0)) "sig" sig32 (IntentBuffer 32)
    encodeWrites [BoundBuffer ["sig"] buf 16] (opWrites plan)
  assertEqual "one short report"
    [EncodeReport ["sig"] 0 CKR_BUFFER_TOO_SMALL] reports
  assertEqual "buffer untouched" (replicate 16 filler) body
  assertEqual "low canary" canary lo
  assertEqual "high canary" canary hi

-- | A write with no bound buffer fails clean with no report of
-- success; a full-width ULong payload (the codec is total,
-- so 'maxBound' is encodable) lands its eight 0xFF bytes.
caseEncodeBad :: IO ()
caseEncodeBad = do
  let (_, plan) = planOneShot (OpLive (Consumption 0)) "sig" sig32 (IntentBuffer 32)
  missing <- encodeWrites [] (opWrites plan)
  assertEqual "missing binding fails clean"
    [EncodeReport ["sig"] 0 CKR_GENERAL_ERROR] missing
  allocaBytes 8 $ \buf -> do
    mapM_ (\i -> poke (buf `plusPtr` i) filler) [0 .. 7]
    let full = TypedWrite ["s"] (RegionScalar "s") (PayloadULong maxBound)
    encoded <- encodeWrites [BoundBuffer ["s"] buf 8] [full]
    assertEqual "full-width payload encodes"
      [EncodeReport ["s"] 8 CKR_OK] encoded
    peeked <- mapM (peek . (buf `plusPtr`)) [0 .. 7]
    assertEqual "bytes landed" (replicate 8 (0xFF :: Word8)) peeked

-- | A nested writeback encodes through its full path into the
-- buffer bound at that path.
caseEncodeNested :: IO ()
caseEncodeNested = do
  (reports, lo, hi, body) <- withGuarded 12 $ \buf -> do
    let iv = BS.pack [1 .. 12]
        plan = planGeneratedIV "mech-gcm" 12 iv (IntentBuffer 12)
    encodeWrites [BoundBuffer ["mech-gcm", "iv"] buf 12] (opWrites plan)
  assertEqual "one ok report"
    [EncodeReport ["mech-gcm", "iv"] 12 CKR_OK] reports
  assertEqual "iv landed" [1 .. 12] body
  assertEqual "low canary" canary lo
  assertEqual "high canary" canary hi

-- | Length answers poke the word, and a null length pointer rejects.
caseEncodeLength :: IO ()
caseEncodeLength = do
  code <- alloca $ \ptr -> do
    poke ptr (CULong 0)
    code' <- encodeLength ptr 32
    seen <- peek ptr
    assertEqual "length poked" (CULong 32) seen
    pure code'
  assertEqual "length code" CKR_OK code
  nullCode <- encodeLength (nullPtr :: Ptr CULong) 32
  assertEqual "null length pointer" CKR_ARGUMENTS_BAD nullCode

-- ---------------------------------------------------------------------------
-- Part 7: A05 locking-adapter invariant
-- ---------------------------------------------------------------------------

-- | Host hooks that record, at every callback, whether the model
-- gate was held at that moment. The gate resolves through a slot
-- the test fills once the environment exists.
trackingHooks :: IO (Maybe Gate) -> IORef [Bool] -> IO MutexHooks
trackingHooks getGate logRef = do
  ref <- referenceHooks
  let note = do
        mGate <- getGate
        held <- case mGate of
          Nothing -> pure False
          Just g -> gateBusy g
        atomicModifyIORef' logRef (\xs -> (held : xs, ()))
  pure MutexHooks
    { hookCreate = note >> hookCreate ref
    , hookDestroy = \m -> note >> hookDestroy ref m
    , hookLock = \m -> note >> hookLock ref m
    , hookUnlock = \m -> note >> hookUnlock ref m
    }

-- | Committing under the gate and delivering under a host mutex:
-- every host callback (create/lock/unlock/destroy) must observe a
-- free gate, delivery runs in order, and the mutex is destroyed.
caseGateNoCallbacks :: IO ()
caseGateNoCallbacks = do
  slot <- newIORef Nothing
  logRef <- newIORef []
  hooks <- trackingHooks (readIORef slot) logRef
  env <- newEnvWith defaultRules hooks
  writeIORef slot (Just (envGate env))
  delivered <- newIORef ([] :: [String])
  verdict <- commitAndDeliver env (StateDelta []) [] ["a", "b"]
    (\x -> atomicModifyIORef' delivered (\xs -> (x : xs, ())))
    (\_ -> pure ())
  assertEqual "publish verdict" (Right ()) verdict
  assertEqual "delivery order" ["b", "a"] =<< readIORef delivered
  obs <- readIORef logRef
  assertEqual "four callbacks fired" 4 (length obs)
  assertBool "no callback saw a held gate" (not (or obs))
  counts <- adapterCounts (envAdapter env)
  assertEqual "adapter counts" (MutexCounts 1 1 1 1) counts
  live <- adapterLive (envAdapter env)
  assertEqual "delivery mutex destroyed" 0 live

-- | Positive control for the probe: a free gate reads free, and a
-- callback invoked inside 'withGate' observes a held gate (the
-- MVar gate is non-reentrant, so same-thread holding is visible).
caseGateProbeDetects :: IO ()
caseGateProbeDetects = do
  env <- newEnv defaultRules
  let gate = envGate env
  free <- gateBusy gate
  assertBool "free gate reads free" (not free)
  held <- withGate gate (gateBusy gate)
  assertBool "held gate reads busy" held

-- | A faulted publish delivers nothing and fires no host callback:
-- the adapter stays silent when there is nothing to deliver.
caseGateFaultSkipsDelivery :: IO ()
caseGateFaultSkipsDelivery = do
  slot <- newIORef Nothing
  logRef <- newIORef []
  hooks <- trackingHooks (readIORef slot) logRef
  env <- newEnvWith defaultRules hooks
  writeIORef slot (Just (envGate env))
  delivered <- newIORef (0 :: Int)
  verdict <- commitAndDeliver env (StateDelta [DeltaCloseSession (SessionId 99)])
    [] (["a"] :: [String]) (\_ -> atomicModifyIORef' delivered (\n -> (n + 1, ())))
    (\_ -> pure ())
  assertEqual "fault verdict"
    (Left (FaultUnknownSession (SessionId 99))) verdict
  assertEqual "nothing delivered" 0 =<< readIORef delivered
  assertEqual "no callbacks fired" [] =<< readIORef logRef

-- | A commit carrying @ReleaseEngineResource@ must
-- leave the backend resource gone after commit application. Nothing
-- reads @pcReleases@ today, so the resource stays live (leak).
caseReleasesDrainedOnCommit :: IO ()
caseReleasesDrainedOnCommit = do
  env <- newEnv defaultRules
  be <- openSynthetic
  rid <- do
    eRid <- digestInit be D_SHA256
    case eRid of
      EngineOk r -> pure r
      EngineFail err ->
        assertFailure ("digestInit failed: " ++ show err) >> undefined
  live <- resourceSaveability be rid
  assertEqual "resource live before commit" ResourceSaveable live
  let pc = PreparedCommit
        { pcCode = CKR_OK
        , pcDelta = StateDelta []
        , pcPersist = []
        , pcOutputs = []
        , pcReleases = [ReleaseEngineResource rid]
        , pcReasons = ["release probe"]
        }
  verdict <- commitAndDeliver env (pcDelta pc) (pcReleases pc)
    (pcOutputs pc) (\_ -> pure ()) (drainOne be)
  assertEqual "publish verdict" (Right ()) verdict
  gone <- resourceSaveability be rid
  assertEqual "release drained by commit"
    (ResourceUnsaveable (UnsaveableGone rid)) gone
  -- A faulted publish drains nothing: the commit never landed.
  eRid2 <- digestInit be D_SHA256
  rid2 <- case eRid2 of
    EngineOk r -> pure r
    EngineFail err ->
      assertFailure ("digestInit failed: " ++ show err) >> undefined
  let bad = pc
        { pcDelta = StateDelta [DeltaCloseSession (SessionId 99)]
        , pcReleases = [ReleaseEngineResource rid2]
        }
  verdict2 <- commitAndDeliver env (pcDelta bad) (pcReleases bad)
    (pcOutputs bad) (\_ -> pure ()) (drainOne be)
  assertEqual "fault verdict"
    (Left (FaultUnknownSession (SessionId 99))) verdict2
  live2 <- resourceSaveability be rid2
  assertEqual "faulted commit drains nothing" ResourceSaveable live2
  closeBackend be

-- | Drain one committed release through the backend.
drainOne :: BackendEnv Synthetic -> ResourceRelease -> IO ()
drainOne be (ReleaseEngineResource rid) = releaseResource be rid

-- | Open the synthetic backend on the decimal seed (the only shape
-- 'openBackend' accepts for it).
openSynthetic :: IO (BackendEnv Synthetic)
openSynthetic = do
  eBe <- openBackend "0"
  case eBe of
    EngineOk be -> pure be
    EngineFail err ->
      assertFailure ("synthetic open failed: " ++ show err) >> undefined
