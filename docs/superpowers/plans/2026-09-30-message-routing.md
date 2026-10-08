# v3 message-family C routing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Route all twenty message-family entries through the existing Haskell planner and real backend on interfaces 3.0, 3.1, and 3.2 with independently checked boundary behavior.

**Architecture:** C guards and the interval lock protect the existing Standard instance throughout decoding, planning, execution, publication, and encoding. Eight owned-frame decoders feed twenty Haskell exports; message-specific output runners preserve staged queries without changing classic runners or the pure planner. One pinned-header consumer exercises the actual versioned tables in direct and proxy topologies.

**Tech Stack:** Haskell GHC2024, Cabal, C11 on Linux x86-64, OpenSSL4, Python 3, POSIX shell, Tasty/HUnit, Docker, pinned PKCS#11 headers.

**Spec:** docs/superpowers/specs/2026-09-30-message-routing-design.md

## Global Constraints

- Requirements source: the complete spec at `d476e97a57e19e84d224541c5713f2714ca909b5`; implementation starts from this inspected revision on `main`.
- Pinned header: `spec/vendor/pkcs11.h`, latchset `c5e61990c5621a9b955fc208644fe8145ac0a75d`, SHA-256 `61e0b3f996fa9f095859d7d3b8e361d0b982de69fc8b6a4bf10291afbe7e24d8`; retain `spec/sources.lock.json`.
- Toolchain: use the spec's pinned toolchain environment; `toolchain.lock` resolves it to `haskoki-dev:ghc-9.10.3`, GHC `9.10.3`, cabal-install `3.12.1.0`, OpenSSL `4.0.2` (these versions are repository grounding, not additional spec requirements).
- No catalog change: preserve exactly `316` real-tested rows and flags in `spec/mechanisms.json` and `cbits/mech_catalog.inc`; add no `CKF_MESSAGE_*` or `CKF_MULTI_MESSAGE` advertising.
- Precedence: liveness peek → ordered structural guards → state lock → authoritative `live_std()` → `withStdCtx` → `withStdSession` → bounded decode → planner/backend → output → unlock; lock failures propagate verbatim.
- Input limits: each component is at most `maxInputBytes = 16 * 1024 * 1024`; multipart accumulation uses existing `maxBuffered`; no extra whole-frame limit.
- Output convention: One-shot/Next always have exactly one `RegionBytes`; Verify and silent Sign continuation use `IntentBuffer 0`; Init/Begin/Final have no regions; internal version is `Pkcs11_3_2`.
- Gate commands: `scripts/test-consumers.sh`; `HASKOKI_PROXY_DIR=/opt/pkcs11-proxy-ng scripts/test-proxy-parity.sh`; `HASKOKI_PROXY_DIR=/opt/pkcs11-proxy-ng bash scripts/run-gates.sh` (eighteen static gates, forced build, all suites, release evidence, installation).
- Oracle pins: `/tmp/pkcs11-ws/pkcs11-check-0.2.2rc2`; `26` source test definitions in `test_mech_message.py` and `13` in `test_message_crypto.py`; these are not runtime pass counts.
- Lane commands, in order: `bash /tmp/pkcs11-ws/run-lane-rc2.sh fast`, inspect findings, then `bash /tmp/pkcs11-ws/run-lane-rc2.sh kat`, inspect findings; a zero wrapper exit is insufficient.
- ABI counts: `68/92/92/104` for `2.40/3.0/3.1/3.2`; 3.1 uses `CK_FUNCTION_LIST_3_0`; never extend or enlarge-cast the legacy table.
- Scope: preserve `FunctionId`, `planCall`, `Operation.Message`, authentication, classic behavior, backend algorithms, and all seventeen existing `MessageSpec` cases; async, recovery, dual operations, authenticated wrapping, new recipes, native nonce generation, and detached tags are deferrable.
- Contracts: all twenty rows retain `planned-with-behavior`, existing planner entry, layouts, ordinal, acceptance identifiers, and model evidence; the total remains `70`.
- Drafting boundary: only this plan is written now; all commands, tests, edits, and commits below are instructions for the executor. No test failure, gate result, lane result, or upstream filing is claimed by this plan.

---

## Files

| Area | Action and exact paths | Responsibility |
|---|---|---|
| Frame boundary | Modify `ffi/Haskoki/FFI/MessageParams.hs`; test `tests/model/MessageSpec.hs` | Eight owned frame decoders and seven named case groups, preserving existing cases. |
| Haskell entry boundary | Modify `ffi/Haskoki/FFI/Standard.hs`; test `tests/model/StandardSurfaceSpec.hs` | Twenty exports and message-only buffered/query dialogues over real planner snapshots. |
| C entry boundary | Modify `cbits/standard_surface.c` and `cbits/exports.c`; temporary test `/tmp/haskoki-message-surface/probe.c` | Exact prototypes, ordered guards, lock lifetime, scalar forwarding, and explicit unlock checks. |
| Generated registration | Modify `scripts/generate-abi.py`; regenerate `cbits/abi_stubs.inc` | Register all twenty routes only in `routed300`; compare every other generated output byte for byte. |
| Independent consumer | Create `tests/c/message_routed.c`; modify `scripts/test-consumers.sh` and `scripts/test-proxy-parity.sh` | All entry legs on all three tables; include the scenario exactly once and extend independence checking. |
| Contract/documentation | Modify `spec/function-contracts.json`, `docs/demo-walkthrough.md`, and `cbits/exports.c` | Executed consumer evidence and accurate function/catalog boundaries. |
| Qualification record | Modify `docs/pkcs11-oracle-triage.md` and `docs/pkcs11-check-upstream-issues.md` | Revision-bound verification, findings, reproductions, classification, and actual upstream status. |
| Read-only contracts | Read `ffi/Haskoki/FFI/Decode.hs`, `core/Haskoki/Operation/Codec.hs`, `core/Haskoki/Operation/State.hs`, `core/Haskoki/Operation/Message.hs`, `core/Haskoki/Transition.hs`, `spec/abi-inventory.json`, `spec/abi-reconciliation.json`, and `cbits/abi_generated.h` | Existing bounds, frames, state behavior, table inventory, and invariants; no implementation edits. |

## Tasks

Coverage map: sections 1 and 2 → Tasks 1–7; section 3 → Tasks 1–6; section 3.1 → Tasks 2–3; section 3.2 → Tasks 1–2; section 3.3 → Tasks 3 and 5; section 3.4 → Tasks 2 and 5; section 3.5 → Task 4; section 3.6 → Tasks 5–7; section 4 → Tasks 1–3 and 5; section 5 → Tasks 1–7; section 5.1 → Tasks 1–2; sections 5.2 and 5.3 → Task 5; section 5.4 → Task 7; section 6 → Tasks 4–7.

Every test cycle below requires the executor to observe and retain the stated failure before adding its implementation. An unexpected failure is investigated before proceeding. Commands are rooted at `<haskoki-checkout>`; scoped Cabal commands run in the pinned environment. Preserve the pre-existing untracked `ws/` directory. The executor commits each task with the listed exact path set; the plan author does not commit.

### Task 1: Owned message frames and decoder cases

**Files:** Modify `ffi/Haskoki/FFI/MessageParams.hs`; modify/test `tests/model/MessageSpec.hs`.

**Interfaces:** Consumes `decodeInputBytes :: Ptr Word8 -> Word64 -> IO (Either DecodeError ByteString)`, `normalizeMechParams :: MechanismId -> Ptr Word8 -> Word64 -> ByteString -> IO ByteString`, `encodeInitInput :: MechanismId -> [Operation] -> Bool -> ByteString -> ByteString`, `encodeMsgBegin :: MsgBegin -> ByteString`, `encodeMsgOneShot :: MsgOneShot -> ByteString`, and `encodeMsgNext :: MsgNext -> ByteString`. Produces these public functions (add each to the module export list):

```haskell
decodeMessageInitFrame :: MsgFamily -> CULong -> Ptr Word8 -> Word64 -> IO (Either MsgParamError ByteString)
decodeMessageBeginFrame :: MsgFamily -> Ptr Word8 -> Word64 -> Ptr Word8 -> Word64 -> IO (Either MsgParamError ByteString)
decodeMessageCipherFrame :: MsgFamily -> Ptr Word8 -> Word64 -> Ptr Word8 -> Word64 -> Ptr Word8 -> Word64 -> IO (Either MsgParamError ByteString)
decodeMessageSignFrame :: Ptr Word8 -> Word64 -> Ptr Word8 -> Word64 -> IO (Either MsgParamError ByteString)
decodeMessageVerifyFrame :: Ptr Word8 -> Word64 -> Ptr Word8 -> Word64 -> Ptr Word8 -> Word64 -> IO (Either MsgParamError ByteString)
decodeMessageCipherNextFrame :: MsgFamily -> Ptr Word8 -> Word64 -> Ptr Word8 -> Word64 -> Bool -> IO (Either MsgParamError ByteString)
decodeMessageSignNextFrame :: Ptr Word8 -> Word64 -> Ptr Word8 -> Word64 -> Bool -> IO (Either MsgParamError ByteString)
decodeMessageVerifyNextFrame :: Ptr Word8 -> Word64 -> Ptr Word8 -> Word64 -> Ptr Word8 -> Word64 -> IO (Either MsgParamError ByteString)
```

- [ ] Write the decoder tests in `tests/model/MessageSpec.hs`, adding the following seven `testCase` entries to its existing list without editing its seventeen existing cases.

```haskell
  , testCase "message boundary init frames" caseMessageInitFrames
  , testCase "message boundary begin frames" caseMessageBeginFrames
  , testCase "message boundary one-shot frames" caseMessageOneShotFrames
  , testCase "message boundary next frames" caseMessageNextFrames
  , testCase "message boundary decode bounds" caseMessageDecodeBounds
  , testCase "message boundary owned frames" caseMessageOwnedFrames
  , testCase "message boundary request regions" caseMessageRequestRegions
```

Add imports for `Control.Monad (forM_)`, `Foreign.C.Types (CULong)`, all eight frame decoders, `Haskoki.Operation.Codec (decodeInitInput, decodeMsgBegin, decodeMsgNext, decodeMsgOneShot)`, `Haskoki.Outcome (PlanResult(..), PreparedCommit(..), Rejection(..))`, `Haskoki.Request (FunctionId(..), Request(..), OutputRegion(..))`, `Haskoki.Rules (defaultRules)`, `Haskoki.Transition (planCall, publishDelta)`, and `Haskoki.Types (Pkcs11Version(..))`; merge these into existing imports. The existing `withInputBytes` supplies owned temporary caller buffers.

```haskell
frameRight :: Either MsgParamError ByteString -> IO ByteString
frameRight = either (fail . show) pure

caseMessageInitFrames :: IO ()
caseMessageInitFrames = do
  withInputBytes [0..15] $ \p n -> do
    e <- decodeMessageInitFrame MsgEncrypt 0x1082 p n >>= frameRight
    d <- decodeMessageInitFrame MsgDecrypt 0x1082 p n >>= frameRight
    assertEqual "encrypt init byte order" (BS.pack [0,0,0,0,0,0,16,130,0,4,0] <> BS.pack [0..15]) e
    assertEqual "decrypt init byte order" (BS.pack [0,0,0,0,0,0,16,130,0,8,0] <> BS.pack [0..15]) d
    assertEqual "encrypt init" (Just (aesCbcMech, [OpEncrypt], False, BS.pack [0..15])) (decodeInitInput e)
    assertEqual "decrypt init" (Just (aesCbcMech, [OpDecrypt], False, BS.pack [0..15])) (decodeInitInput d)
  s <- decodeMessageInitFrame MsgSign 0x251 nullPtr 0 >>= frameRight
  v <- decodeMessageInitFrame MsgVerify 0x251 nullPtr 0 >>= frameRight
  assertEqual "sign init byte order" (BS.pack [0,0,0,0,0,0,2,81,0,1,0]) s
  assertEqual "verify init byte order" (BS.pack [0,0,0,0,0,0,2,81,0,2,0]) v
  assertEqual "sign init" (Just (hmacMech, [OpSign], False, BS.empty)) (decodeInitInput s)
  assertEqual "verify init" (Just (hmacMech, [OpVerify], False, BS.empty)) (decodeInitInput v)

caseMessageBeginFrames :: IO ()
caseMessageBeginFrames = withInputBytes [17] $ \p pn ->
  withInputBytes [33,34] $ \a an -> do
    e <- decodeMessageBeginFrame MsgEncrypt p pn a an >>= frameRight
    d <- decodeMessageBeginFrame MsgDecrypt p pn a an >>= frameRight
    s <- decodeMessageBeginFrame MsgSign p pn nullPtr 0 >>= frameRight
    v <- decodeMessageBeginFrame MsgVerify p pn nullPtr 0 >>= frameRight
    assertEqual "encrypt layout" (BS.pack [0,0,0,1,17,33,34]) e
    assertEqual "decrypt layout" (BS.pack [0,0,0,1,17,33,34]) d
    assertEqual "sign layout" (BS.pack [0,0,0,1,17]) s
    assertEqual "verify layout" (BS.pack [0,0,0,1,17]) v
    assertEqual "cipher begin" (Just (MsgBegin (BS.pack [17]) (BS.pack [33,34]))) (decodeMsgBegin e)
    assertEqual "signature begin" (Just (MsgBegin (BS.pack [17]) BS.empty)) (decodeMsgBegin s)
    assertEqual "truncated prefix" Nothing (decodeMsgBegin (BS.pack [0,0,0]))

caseMessageOneShotFrames :: IO ()
caseMessageOneShotFrames = withInputBytes [17] $ \p pn ->
  withInputBytes [33,34] $ \a an ->
  withInputBytes [49,50,51] $ \d dn ->
  withInputBytes [65,66] $ \w wn -> do
    e <- decodeMessageCipherFrame MsgEncrypt p pn a an d dn >>= frameRight
    c <- decodeMessageCipherFrame MsgDecrypt p pn a an d dn >>= frameRight
    s <- decodeMessageSignFrame p pn d dn >>= frameRight
    v <- decodeMessageVerifyFrame p pn d dn w wn >>= frameRight
    assertEqual "cipher bytes" (BS.pack [0,0,0,0,1,17,0,0,0,2,33,34,49,50,51]) e
    assertEqual "decrypt bytes" e c
    assertEqual "sign bytes" (BS.pack [1,0,0,0,1,17,49,50,51]) s
    assertEqual "verify witness before data" (BS.pack [2,0,0,0,1,17,0,0,0,2,65,66,49,50,51]) v
    assertEqual "encrypt decode" (Just (MsgOneShotCipher (BS.pack [17]) (BS.pack [33,34]) (BS.pack [49,50,51]))) (decodeMsgOneShot MsgEncrypt e)
    assertEqual "decrypt decode" (Just (MsgOneShotCipher (BS.pack [17]) (BS.pack [33,34]) (BS.pack [49,50,51]))) (decodeMsgOneShot MsgDecrypt c)
    assertEqual "sign decode" (Just (MsgOneShotSign (BS.pack [17]) (BS.pack [49,50,51]))) (decodeMsgOneShot MsgSign s)
    assertEqual "verify decode" (Just (MsgOneShotVerify (BS.pack [17]) (BS.pack [49,50,51]) (BS.pack [65,66]))) (decodeMsgOneShot MsgVerify v)
    assertEqual "wrong family" Nothing (decodeMsgOneShot MsgSign e)
    assertEqual "wrong witness family" Nothing (decodeMsgOneShot MsgEncrypt v)
    assertEqual "truncated witness" Nothing (decodeMsgOneShot MsgVerify (BS.take 11 v))
    unit <- decodeMessageCipherFrame MsgEncrypt p 1 a 1 d 1 >>= frameRight
    assertEqual "single byte fields" (BS.pack [0,0,0,0,1,17,0,0,0,1,33,49]) unit
    unitV <- decodeMessageVerifyFrame p 1 d 1 w 1 >>= frameRight
    assertEqual "single byte witness" (BS.pack [2,0,0,0,1,17,0,0,0,1,65,49]) unitV

caseMessageNextFrames :: IO ()
caseMessageNextFrames = withInputBytes [17] $ \p pn ->
  withInputBytes [49,50,51] $ \d dn ->
  withInputBytes [65,66] $ \w wn -> do
    forM_ [False, True] $ \end -> do
      e <- decodeMessageCipherNextFrame MsgEncrypt p pn d dn end >>= frameRight
      c <- decodeMessageCipherNextFrame MsgDecrypt p pn d dn end >>= frameRight
      s <- decodeMessageSignNextFrame p pn d dn end >>= frameRight
      let flag = if end then 1 else 0
      assertEqual "encrypt next bytes" (BS.pack [0,0,0,0,1,17,flag,49,50,51]) e
      assertEqual "decrypt next bytes" e c
      assertEqual "sign next bytes" (BS.pack [1,0,0,0,1,17,flag,49,50,51]) s
      assertEqual "cipher next" (Just (MsgNextCipher (BS.pack [17]) (BS.pack [49,50,51]) end)) (decodeMsgNext MsgDecrypt c)
      assertEqual "sign next" (Just (MsgNextSign (BS.pack [17]) (BS.pack [49,50,51]) end)) (decodeMsgNext MsgSign s)
    absent <- decodeMessageVerifyNextFrame p pn d dn nullPtr 0 >>= frameRight
    empty <- decodeMessageVerifyNextFrame p pn d dn w 0 >>= frameRight
    witness <- decodeMessageVerifyNextFrame p pn d dn w wn >>= frameRight
    assertEqual "absent bytes" (BS.pack [2,0,0,0,1,17,0,49,50,51]) absent
    assertEqual "present empty bytes" (BS.pack [2,0,0,0,1,17,1,0,0,0,0,49,50,51]) empty
    assertEqual "present witness bytes" (BS.pack [2,0,0,0,1,17,1,0,0,0,2,65,66,49,50,51]) witness
    assertEqual "absent witness" (Just (MsgNextVerify (BS.pack [17]) (BS.pack [49,50,51]) Nothing)) (decodeMsgNext MsgVerify absent)
    assertEqual "empty witness" (Just (MsgNextVerify (BS.pack [17]) (BS.pack [49,50,51]) (Just BS.empty))) (decodeMsgNext MsgVerify empty)
    assertEqual "witness" (Just (MsgNextVerify (BS.pack [17]) (BS.pack [49,50,51]) (Just (BS.pack [65,66])))) (decodeMsgNext MsgVerify witness)
    assertEqual "bad cipher end" Nothing (decodeMsgNext MsgEncrypt (BS.pack [0,0,0,0,0,2]))
    assertEqual "bad sign end" Nothing (decodeMsgNext MsgSign (BS.pack [1,0,0,0,0,2]))
    assertEqual "bad witness presence" Nothing (decodeMsgNext MsgVerify (BS.pack [2,0,0,0,0,2]))
    assertEqual "wrong next family" Nothing (decodeMsgNext MsgVerify (BS.pack [1,0,0,0,0,0]))
```

Continue the same test edit with per-component refusal/ownership probes. Each lambda changes exactly one input component; witness presence is checked separately from byte emptiness.

```haskell
boundaryComponents :: [(String, Ptr Word8 -> Word64 -> IO (Either MsgParamError ByteString))]
boundaryComponents =
  [ ("Encrypt init parameter", \p n -> decodeMessageInitFrame MsgEncrypt 0x1082 p n)
  , ("Decrypt init parameter", \p n -> decodeMessageInitFrame MsgDecrypt 0x1082 p n)
  , ("Sign init parameter", \p n -> decodeMessageInitFrame MsgSign 0x251 p n)
  , ("Verify init parameter", \p n -> decodeMessageInitFrame MsgVerify 0x251 p n)
  , ("Encrypt begin parameter", \p n -> decodeMessageBeginFrame MsgEncrypt p n nullPtr 0)
  , ("Encrypt begin aad", \p n -> decodeMessageBeginFrame MsgEncrypt nullPtr 0 p n)
  , ("Decrypt begin parameter", \p n -> decodeMessageBeginFrame MsgDecrypt p n nullPtr 0)
  , ("Decrypt begin aad", \p n -> decodeMessageBeginFrame MsgDecrypt nullPtr 0 p n)
  , ("Sign begin parameter", \p n -> decodeMessageBeginFrame MsgSign p n nullPtr 0)
  , ("Sign begin aad", \p n -> decodeMessageBeginFrame MsgSign nullPtr 0 p n)
  , ("Verify begin parameter", \p n -> decodeMessageBeginFrame MsgVerify p n nullPtr 0)
  , ("Verify begin aad", \p n -> decodeMessageBeginFrame MsgVerify nullPtr 0 p n)
  , ("Encrypt one parameter", \p n -> decodeMessageCipherFrame MsgEncrypt p n nullPtr 0 nullPtr 0)
  , ("Encrypt one aad", \p n -> decodeMessageCipherFrame MsgEncrypt nullPtr 0 p n nullPtr 0)
  , ("Encrypt one input", \p n -> decodeMessageCipherFrame MsgEncrypt nullPtr 0 nullPtr 0 p n)
  , ("Decrypt one parameter", \p n -> decodeMessageCipherFrame MsgDecrypt p n nullPtr 0 nullPtr 0)
  , ("Decrypt one aad", \p n -> decodeMessageCipherFrame MsgDecrypt nullPtr 0 p n nullPtr 0)
  , ("Decrypt one input", \p n -> decodeMessageCipherFrame MsgDecrypt nullPtr 0 nullPtr 0 p n)
  , ("Sign one component 1", \p n -> decodeMessageSignFrame p n nullPtr 0)
  , ("Sign one component 2", \p n -> decodeMessageSignFrame nullPtr 0 p n)
  , ("Verify one component 1", \p n -> decodeMessageVerifyFrame p n nullPtr 0 nullPtr 0)
  , ("Verify one component 2", \p n -> decodeMessageVerifyFrame nullPtr 0 p n nullPtr 0)
  , ("Verify one component 3", \p n -> decodeMessageVerifyFrame nullPtr 0 nullPtr 0 p n)
  , ("Encrypt next parameter", \p n -> decodeMessageCipherNextFrame MsgEncrypt p n nullPtr 0 False)
  , ("Encrypt next part", \p n -> decodeMessageCipherNextFrame MsgEncrypt nullPtr 0 p n False)
  , ("Decrypt next parameter", \p n -> decodeMessageCipherNextFrame MsgDecrypt p n nullPtr 0 False)
  , ("Decrypt next part", \p n -> decodeMessageCipherNextFrame MsgDecrypt nullPtr 0 p n False)
  , ("Sign next component 1", \p n -> decodeMessageSignNextFrame p n nullPtr 0 False)
  , ("Sign next component 2", \p n -> decodeMessageSignNextFrame nullPtr 0 p n False)
  , ("Verify next component 1", \p n -> decodeMessageVerifyNextFrame p n nullPtr 0 nullPtr 0)
  , ("Verify next component 2", \p n -> decodeMessageVerifyNextFrame nullPtr 0 p n nullPtr 0)
  , ("Verify next component 3", \p n -> decodeMessageVerifyNextFrame nullPtr 0 nullPtr 0 p n)
  ]

caseMessageDecodeBounds :: IO ()
caseMessageDecodeBounds = withInputBytes [7] $ \tiny _ -> do
  forM_ boundaryComponents $ \(label, decode) -> do
    emptyNull <- decode nullPtr 0
    emptyPresent <- decode tiny 0
    assertBool (label ++ " empty null") (either (const False) (const True) emptyNull)
    assertBool (label ++ " empty present") (either (const False) (const True) emptyPresent)
    decode nullPtr 1 >>= assertEqual (label ++ " null nonzero") (Left (MsgParamBadPointer 1))
    decode tiny (maxInputBytes + 1) >>= assertEqual (label ++ " oversize tiny") (Left (MsgParamTooLarge (maxInputBytes + 1)))
  let large = BS.replicate (fromIntegral maxInputBytes) 97
  BS.useAsCStringLen large $ \(raw, n) -> do
    frame <- decodeMessageSignFrame nullPtr 0 (castPtr raw) (fromIntegral n) >>= frameRight
    assertEqual "legal component plus framing" (fromIntegral maxInputBytes + 5) (BS.length frame)
    cipherFrame <- decodeMessageCipherFrame MsgEncrypt (castPtr raw) (fromIntegral n) (castPtr raw) (fromIntegral n) (castPtr raw) (fromIntegral n) >>= frameRight
    assertEqual "three legal cipher components" (3 * fromIntegral maxInputBytes + 9) (BS.length cipherFrame)
    verifyFrame <- decodeMessageVerifyFrame (castPtr raw) (fromIntegral n) (castPtr raw) (fromIntegral n) (castPtr raw) (fromIntegral n) >>= frameRight
    assertEqual "three legal verify components" (3 * fromIntegral maxInputBytes + 9) (BS.length verifyFrame)

caseMessageOwnedFrames :: IO ()
caseMessageOwnedFrames = withInputBytes [17] $ \p pn ->
  withInputBytes [33,34] $ \a an ->
  withInputBytes [49,50,51] $ \d dn ->
  withInputBytes [65,66] $ \w wn -> do
    frames <- sequence
      [ decodeMessageInitFrame MsgSign 0x251 p pn
      , decodeMessageBeginFrame MsgEncrypt p pn a an
      , decodeMessageCipherFrame MsgDecrypt p pn a an d dn
      , decodeMessageSignFrame p pn d dn
      , decodeMessageVerifyFrame p pn d dn w wn
      , decodeMessageCipherNextFrame MsgEncrypt p pn d dn False
      , decodeMessageSignNextFrame p pn d dn True
      , decodeMessageVerifyNextFrame p pn d dn w wn
      ] >>= traverse frameRight
    let copies = map BS.copy frames
    forM_ copies $ \b -> BS.length b `seq` pure ()
    pokeArray p [255]
    pokeArray a [255,255]
    pokeArray d [255,255,255]
    pokeArray w [255,255]
    assertEqual "caller overwrite cannot alter owned frames" copies frames

commitFrame :: Model -> Request -> IO Model
commitFrame m req = case planCall defaultRules m req of
  Immediate pc -> do
    assertEqual "immediate code" CKR_OK (pcCode pc)
    either (fail . show) pure (publishDelta m (pcDelta pc))
  other -> fail ("expected immediate: " ++ show other)

caseMessageRequestRegions :: IO ()
caseMessageRequestRegions = withInputBytes [0..15] $ \iv ivn ->
  withInputBytes [1..16] $ \d dn ->
  withInputBytes [9] $ \w wn -> do
    let m = modelWithKey { mSessions = Map.singleton (SessionId 1) testSession }
        request fid frame regions = Request Pkcs11_3_2 fid (Just (SessionId 1)) Nothing frame regions
        checkRefusal req state = case planCall defaultRules state req of
          Reject r -> assertEqual "region omission" CKR_ARGUMENTS_BAD (rejCode r)
          other -> assertFailure ("expected region refusal: " ++ show other)
        checkAccepted req state = case planCall defaultRules state req of
          Reject r -> assertFailure ("unexpected refusal: " ++ show (rejCode r))
          _ -> pure ()
    encryptInit <- decodeMessageInitFrame MsgEncrypt 0x1082 iv ivn >>= frameRight
    let encryptInitReq = (request F_MessageEncryptInit encryptInit []) { reqHandle = Just (ExternalHandle 3) }
    assertEqual "Encrypt key outside frame" (Just (ExternalHandle 3)) (reqHandle encryptInitReq)
    assertEqual "Encrypt init route" F_MessageEncryptInit (reqFunction encryptInitReq)
    encryptIdle <- commitFrame m encryptInitReq
    encryptOne <- decodeMessageCipherFrame MsgEncrypt iv ivn nullPtr 0 d dn >>= frameRight
    checkRefusal (request F_EncryptMessage encryptOne []) encryptIdle
    checkAccepted (request F_EncryptMessage encryptOne [RegionBytes "message-encrypt" (IntentBuffer 64)]) encryptIdle
    encryptBegin <- decodeMessageBeginFrame MsgEncrypt iv ivn nullPtr 0 >>= frameRight
    encryptOpen <- commitFrame encryptIdle (request F_EncryptMessageBegin encryptBegin [])
    encryptNext <- decodeMessageCipherNextFrame MsgEncrypt nullPtr 0 d dn False >>= frameRight
    checkRefusal (request F_EncryptMessageNext encryptNext []) encryptOpen
    checkAccepted (request F_EncryptMessageNext encryptNext [RegionBytes "message-encrypt" (IntentBuffer 0)]) encryptOpen
    encryptDone <- commitFrame encryptIdle (request F_MessageEncryptFinal BS.empty [])
    assertEqual "Encrypt final removes idle context" [] (activeSlots (ssOps ((mSessions encryptDone) Map.! SessionId 1)))
    decryptInit <- decodeMessageInitFrame MsgDecrypt 0x1082 iv ivn >>= frameRight
    let decryptInitReq = (request F_MessageDecryptInit decryptInit []) { reqHandle = Just (ExternalHandle 3) }
    assertEqual "Decrypt key outside frame" (Just (ExternalHandle 3)) (reqHandle decryptInitReq)
    assertEqual "Decrypt init route" F_MessageDecryptInit (reqFunction decryptInitReq)
    decryptIdle <- commitFrame m decryptInitReq
    decryptOne <- decodeMessageCipherFrame MsgDecrypt iv ivn nullPtr 0 d dn >>= frameRight
    checkRefusal (request F_DecryptMessage decryptOne []) decryptIdle
    checkAccepted (request F_DecryptMessage decryptOne [RegionBytes "message-decrypt" (IntentBuffer 64)]) decryptIdle
    decryptBegin <- decodeMessageBeginFrame MsgDecrypt iv ivn nullPtr 0 >>= frameRight
    decryptOpen <- commitFrame decryptIdle (request F_DecryptMessageBegin decryptBegin [])
    decryptNext <- decodeMessageCipherNextFrame MsgDecrypt nullPtr 0 d dn False >>= frameRight
    checkRefusal (request F_DecryptMessageNext decryptNext []) decryptOpen
    checkAccepted (request F_DecryptMessageNext decryptNext [RegionBytes "message-decrypt" (IntentBuffer 0)]) decryptOpen
    decryptDone <- commitFrame decryptIdle (request F_MessageDecryptFinal BS.empty [])
    assertEqual "Decrypt final removes idle context" [] (activeSlots (ssOps ((mSessions decryptDone) Map.! SessionId 1)))
    signInit <- decodeMessageInitFrame MsgSign 0x251 nullPtr 0 >>= frameRight
    let signInitReq = (request F_MessageSignInit signInit []) { reqHandle = Just (ExternalHandle 3) }
    assertEqual "Sign key outside frame" (Just (ExternalHandle 3)) (reqHandle signInitReq)
    assertEqual "Sign init route" F_MessageSignInit (reqFunction signInitReq)
    signIdle <- commitFrame m signInitReq
    signOne <- decodeMessageSignFrame nullPtr 0 d dn >>= frameRight
    checkRefusal (request F_SignMessage signOne []) signIdle
    checkAccepted (request F_SignMessage signOne [RegionBytes "message-sign" (IntentBuffer 64)]) signIdle
    signBegin <- decodeMessageBeginFrame MsgSign nullPtr 0 nullPtr 0 >>= frameRight
    signOpen <- commitFrame signIdle (request F_SignMessageBegin signBegin [])
    signNext <- decodeMessageSignNextFrame nullPtr 0 d dn False >>= frameRight
    checkRefusal (request F_SignMessageNext signNext []) signOpen
    checkAccepted (request F_SignMessageNext signNext [RegionBytes "message-sign" (IntentBuffer 0)]) signOpen
    signDone <- commitFrame signIdle (request F_MessageSignFinal BS.empty [])
    assertEqual "Sign final removes idle context" [] (activeSlots (ssOps ((mSessions signDone) Map.! SessionId 1)))
    verifyInit <- decodeMessageInitFrame MsgVerify 0x251 nullPtr 0 >>= frameRight
    let verifyInitReq = (request F_MessageVerifyInit verifyInit []) { reqHandle = Just (ExternalHandle 3) }
    assertEqual "Verify key outside frame" (Just (ExternalHandle 3)) (reqHandle verifyInitReq)
    assertEqual "Verify init route" F_MessageVerifyInit (reqFunction verifyInitReq)
    verifyIdle <- commitFrame m verifyInitReq
    verifyOne <- decodeMessageVerifyFrame nullPtr 0 d dn w wn >>= frameRight
    checkRefusal (request F_VerifyMessage verifyOne []) verifyIdle
    checkAccepted (request F_VerifyMessage verifyOne [RegionBytes "message-verify" (IntentBuffer 64)]) verifyIdle
    verifyBegin <- decodeMessageBeginFrame MsgVerify nullPtr 0 nullPtr 0 >>= frameRight
    verifyOpen <- commitFrame verifyIdle (request F_VerifyMessageBegin verifyBegin [])
    verifyNext <- decodeMessageVerifyNextFrame nullPtr 0 d dn nullPtr 0 >>= frameRight
    checkRefusal (request F_VerifyMessageNext verifyNext []) verifyOpen
    checkAccepted (request F_VerifyMessageNext verifyNext [RegionBytes "message-verify" (IntentBuffer 0)]) verifyOpen
    verifyDone <- commitFrame verifyIdle (request F_MessageVerifyFinal BS.empty [])
    assertEqual "Verify final removes idle context" [] (activeSlots (ssOps ((mSessions verifyDone) Map.! SessionId 1)))
```

Also add `castPtr` to the existing `Foreign.Ptr` import. The tests use existing pure planning fixtures; their toy results are not C-table evidence.

- [ ] Run the new decoder cases before implementation.

```sh
cabal test haskoki-model-tests --test-option='--pattern=message boundary'
```

Expected failure: the module does not export the eight new decoder names. Retain that compiler output as the observed failure for this cycle; a build-environment failure does not satisfy it.

- [ ] Implement the eight decoders and their two private copy/composition helpers in `ffi/Haskoki/FFI/MessageParams.hs`.

Add imports `Foreign.C.Types (CULong)`, `Foreign.Ptr (nullPtr)`, `Haskoki.FFI.NativeParams (normalizeMechParams)`, `Haskoki.Operation.State (msgFamilyOp)`, `Haskoki.Registry (MechanismId(..))`, `Haskoki.Operation.Codec (encodeInitInput, encodeMsgBegin, encodeMsgOneShot, encodeMsgNext)`, and the constructors `MsgBegin(..), MsgOneShot(..), MsgNext(..)` from `Haskoki.Operation.Message`. Retain the existing `MsgParamError` constructors, `fromDecode`, parameter decoder, and nested writeback functions.

```haskell
copyMessageBytes :: Ptr Word8 -> Word64 -> IO (Either MsgParamError ByteString)
copyMessageBytes p n = fmap (either (Left . fromDecode) Right) (decodeInputBytes p n)

bindMessage :: IO (Either MsgParamError a) -> (a -> IO (Either MsgParamError b)) -> IO (Either MsgParamError b)
bindMessage action next = action >>= either (pure . Left) next

decodeMessageInitFrame :: MsgFamily -> CULong -> Ptr Word8 -> Word64 -> IO (Either MsgParamError ByteString)
decodeMessageInitFrame fam mech p n = bindMessage (copyMessageBytes p n) $ \raw -> do
  let mid = MechanismId (fromIntegral mech)
  params <- normalizeMechParams mid p n raw
  pure (Right (encodeInitInput mid [msgFamilyOp fam] False params))

decodeMessageBeginFrame :: MsgFamily -> Ptr Word8 -> Word64 -> Ptr Word8 -> Word64 -> IO (Either MsgParamError ByteString)
decodeMessageBeginFrame fam p pn a an =
  bindMessage (decodeMessageParams fam p pn a an) $ \mp ->
    pure (Right (encodeMsgBegin (MsgBegin (mpParams mp) (mpAad mp))))

decodeMessageCipherFrame :: MsgFamily -> Ptr Word8 -> Word64 -> Ptr Word8 -> Word64 -> Ptr Word8 -> Word64 -> IO (Either MsgParamError ByteString)
decodeMessageCipherFrame fam p pn a an d dn =
  bindMessage (decodeMessageParams fam p pn a an) $ \mp ->
  bindMessage (copyMessageBytes d dn) $ \input ->
    pure (Right (encodeMsgOneShot (MsgOneShotCipher (mpParams mp) (mpAad mp) input)))

decodeMessageSignFrame :: Ptr Word8 -> Word64 -> Ptr Word8 -> Word64 -> IO (Either MsgParamError ByteString)
decodeMessageSignFrame p pn d dn =
  bindMessage (decodeMessageParams MsgSign p pn nullPtr 0) $ \mp ->
  bindMessage (copyMessageBytes d dn) $ \input ->
    pure (Right (encodeMsgOneShot (MsgOneShotSign (mpParams mp) input)))

decodeMessageVerifyFrame :: Ptr Word8 -> Word64 -> Ptr Word8 -> Word64 -> Ptr Word8 -> Word64 -> IO (Either MsgParamError ByteString)
decodeMessageVerifyFrame p pn d dn w wn =
  bindMessage (decodeMessageParams MsgVerify p pn nullPtr 0) $ \mp ->
  bindMessage (copyMessageBytes d dn) $ \input ->
  bindMessage (copyMessageBytes w wn) $ \witness ->
    pure (Right (encodeMsgOneShot (MsgOneShotVerify (mpParams mp) input witness)))

decodeMessageCipherNextFrame :: MsgFamily -> Ptr Word8 -> Word64 -> Ptr Word8 -> Word64 -> Bool -> IO (Either MsgParamError ByteString)
decodeMessageCipherNextFrame fam p pn d dn end =
  bindMessage (decodeMessageParams fam p pn nullPtr 0) $ \mp ->
  bindMessage (copyMessageBytes d dn) $ \part ->
    pure (Right (encodeMsgNext (MsgNextCipher (mpParams mp) part end)))

decodeMessageSignNextFrame :: Ptr Word8 -> Word64 -> Ptr Word8 -> Word64 -> Bool -> IO (Either MsgParamError ByteString)
decodeMessageSignNextFrame p pn d dn end =
  bindMessage (decodeMessageParams MsgSign p pn nullPtr 0) $ \mp ->
  bindMessage (copyMessageBytes d dn) $ \part ->
    pure (Right (encodeMsgNext (MsgNextSign (mpParams mp) part end)))

decodeMessageVerifyNextFrame :: Ptr Word8 -> Word64 -> Ptr Word8 -> Word64 -> Ptr Word8 -> Word64 -> IO (Either MsgParamError ByteString)
decodeMessageVerifyNextFrame p pn d dn w wn =
  bindMessage (decodeMessageParams MsgVerify p pn nullPtr 0) $ \mp ->
  bindMessage (copyMessageBytes d dn) $ \part ->
  bindMessage (copyMessageBytes w wn) $ \bytes ->
    let witness = if w == nullPtr then Nothing else Just bytes
    in pure (Right (encodeMsgNext (MsgNextVerify (mpParams mp) part witness)))
```

Component bounds are checked before copying and concatenation; the codec's 32-bit prefixes cover the component bounds, while the owned frame may exceed 16 MiB. Init alone normalizes native mechanism parameters. No per-message pointer or output buffer is serialized.

- [ ] Run the focused additions.

```sh
cabal test haskoki-model-tests --test-option='--pattern=message boundary'
```

Expected: all seven new case groups pass, including every listed family/component.

- [ ] Run the existing message group with the additions.

```sh
cabal test haskoki-model-tests --test-option='--pattern=message operations'
```

Expected: the seventeen original cases and seven new cases pass without changing planner expectations.

- [ ] Commit Task 1.

```sh
git add ffi/Haskoki/FFI/MessageParams.hs tests/model/MessageSpec.hs
git commit -m "feat: decode message frames per routing spec sections 3.2 and 5.1"
```

### Task 2: Twenty Haskell exports and message output dialogues

**Files:** Modify `ffi/Haskoki/FFI/Standard.hs`; modify/test `tests/model/StandardSurfaceSpec.hs`.

**Interfaces:** Consumes the eight exact decoder signatures in Task 1; `runCryptoPlan :: StdInstance -> Model -> Request -> IO (Either CULong PreparedCommit)`; `runCryptoPlanOn :: StdInstance -> Model -> PlanResult -> IO (Either CULong PreparedCommit)`; `runCryptoSilent :: StdInstance -> Request -> IO CULong`; `encodeCryptoCommit :: StdInstance -> SessionId -> SlotKind -> Ptr Word8 -> Ptr CULong -> Word64 -> PreparedCommit -> IO CULong`; and `reportCryptoQuery`, `reportShortLength :: StdInstance -> SessionId -> SlotKind -> Ptr CULong -> IO CULong`. Produces the twenty exports spelled below plus these private runners:

```haskell
runMessageBuffered :: StdInstance -> SessionId -> MsgFamily -> FunctionId -> ByteString -> Ptr Word8 -> Ptr CULong -> Word64 -> IO CULong
runMessageQuery :: StdInstance -> SessionId -> MsgFamily -> FunctionId -> ByteString -> Ptr CULong -> IO CULong
messageBytes :: StdInstance -> SessionId -> MsgFamily -> FunctionId -> ByteString -> Ptr Word8 -> Ptr CULong -> IO CULong
messageRegion :: MsgFamily -> String
matchingMessageLength :: MsgFamily -> Model -> SessionId -> Maybe Word64
messageContinuation :: MsgFamily -> FunctionId -> ByteString -> Bool
```

- [ ] Write the boundary tests in `tests/model/StandardSurfaceSpec.hs`.

Merge these imports into existing imports: `Control.Exception (bracket)`, `Control.Monad (forM_)`, `Foreign.Marshal.Alloc (alloca, allocaBytes)`, `Foreign.Marshal.Array (peekArray, pokeArray)`, `Foreign.Ptr (Ptr, nullPtr, castPtr)`, `Foreign.StablePtr (StablePtr, castStablePtrToPtr, deRefStablePtr)`, `Foreign.Storable (peek, poke)`, `Haskoki.FFI.Decode (maxInputBytes)`, `Haskoki.FFI.Standard`'s twenty new exports plus `StdInstance(..), openStdInstance, haskokiStdClose, haskokiStdOpenSession, haskokiStdCreateObject, haskokiStdEncryptInit, haskokiStdEncrypt, stdRvOf`, `Haskoki.Operation (MsgState(..), MsgFamily(..), SlotKind(..), stagedOf)`, `Haskoki.Operation.Message (lookupMessage, messageBuffered)`, `Haskoki.Model (lookupSession, ssOps)`, `Haskoki.Runtime.Config (defaultConfig)`, `Haskoki.Runtime.Lifecycle (snapshotModel)`, and `Haskoki.Types (ReturnCode(..))`.

```haskell
expectMessageRv :: String -> ReturnCode -> IO CULong -> IO ()
expectMessageRv label expected call = call >>= assertEqual label (stdRvOf expected)

withMessageBytes :: ByteString -> (Ptr Word8 -> CULong -> IO a) -> IO a
withMessageBytes bytes action = BS.useAsCStringLen bytes $ \(raw, n) -> action (castPtr raw) (fromIntegral n)

createMessageKey :: StablePtr StdInstance -> CULong -> Word64 -> ByteString -> [Word64] -> IO CULong
createMessageKey ctx session keyType bytes usages = do
  let attrs = [(0,word 4),(1,BS.singleton 0),(2,BS.singleton 0),(0x100,word keyType),(0x11,bytes)]
        ++ [(u,BS.singleton 1) | u <- usages]
      frame = word (fromIntegral (length attrs)) <> mconcat [attr t v | (t,v) <- attrs]
  withMessageBytes frame $ \p n -> alloca $ \key -> do
    expectMessageRv "create key" CKR_OK (haskokiStdCreateObject ctx session p n key)
    peek key

withMessageFixture :: (StablePtr StdInstance -> StdInstance -> CULong -> CULong -> CULong -> IO ()) -> IO ()
withMessageFixture action = bracket (openStdInstance defaultConfig) haskokiStdClose $ \ctx -> do
  assertBool "live Standard instance" (castStablePtrToPtr ctx /= nullPtr)
  inst <- deRefStablePtr ctx
  alloca $ \outSession -> do
    expectMessageRv "open session" CKR_OK (haskokiStdOpenSession ctx 0 0 outSession)
    session <- peek outSession
    aes <- createMessageKey ctx session 0x1f (BS.pack [0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c]) [0x104,0x105]
    mac <- createMessageKey ctx session 0x10 (BS.replicate 20 0x0b) [0x108,0x10a]
    action ctx inst session aes mac

messageState :: StdInstance -> CULong -> SlotKind -> IO MsgState
messageState inst session slot = do
  m <- snapshotModel (siEnv inst)
  case lookupSession m (SessionId (fromIntegral session)) >>= \st -> lookupMessage (ssOps st) slot of
    Nothing -> fail "message state absent"
    Just st -> pure st

messagePlain, messageCipher, messageMac, messageIv :: ByteString
messagePlain = BS.pack [0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a]
messageCipher = BS.pack [0x76,0x49,0xab,0xac,0x81,0x19,0xb2,0x46,0xce,0xe9,0x8e,0x9b,0x12,0xe9,0x19,0x7d]
messageMac = BS.pack [0xb0,0x34,0x4c,0x61,0xd8,0xdb,0x38,0x53,0x5c,0xa8,0xaf,0xce,0xaf,0x0b,0xf1,0x2b,0x88,0x1d,0xc2,0x00,0xc9,0x83,0x3d,0xa7,0x26,0xe9,0x37,0x6c,0x2e,0x32,0xcf,0xf7]
messageIv = BS.pack [0..15]
```

Add the following five cases to `spec`; every export is called explicitly in the cases.

```haskell
  , testCase "message exports and session precedence" caseMessageExports
  , testCase "message cipher continuation query preserves snapshot" caseMessageContinuationQuery
  , testCase "message staged query short and exact" caseMessageStagedQuery
  , testCase "message empty staged output" caseMessageEmptyQuery
  , testCase "message verify presence and sign continuation" caseMessageSignals

caseMessageExports :: IO ()
caseMessageExports = withMessageFixture $ \ctx _ session aes mac ->
  withMessageBytes messageIv $ \iv ivn ->
  withMessageBytes messagePlain $ \plain pn ->
  withMessageBytes messageCipher $ \cipher cn ->
  withMessageBytes "Hi There" $ \input inputn ->
  withMessageBytes messageMac $ \witness wn ->
  allocaBytes 40 $ \out -> alloca $ \len -> do
    let invalid = maxBound :: CULong
    expectMessageRv "EncryptInit invalid session" CKR_SESSION_HANDLE_INVALID (haskokiStdMessageEncryptInit ctx invalid 0x1082 iv ivn aes)
    expectMessageRv "Encrypt invalid session" CKR_SESSION_HANDLE_INVALID (haskokiStdMessageEncrypt ctx invalid iv ivn nullPtr 0 plain pn out len)
    expectMessageRv "EncryptBegin invalid session" CKR_SESSION_HANDLE_INVALID (haskokiStdMessageEncryptBegin ctx invalid iv ivn nullPtr 0)
    expectMessageRv "EncryptNext invalid session" CKR_SESSION_HANDLE_INVALID (haskokiStdMessageEncryptNext ctx invalid nullPtr 0 plain pn out len 1)
    expectMessageRv "EncryptFinal invalid session" CKR_SESSION_HANDLE_INVALID (haskokiStdMessageEncryptFinal ctx invalid)
    expectMessageRv "DecryptInit invalid session" CKR_SESSION_HANDLE_INVALID (haskokiStdMessageDecryptInit ctx invalid 0x1082 iv ivn aes)
    expectMessageRv "Decrypt invalid session" CKR_SESSION_HANDLE_INVALID (haskokiStdMessageDecrypt ctx invalid iv ivn nullPtr 0 cipher cn out len)
    expectMessageRv "DecryptBegin invalid session" CKR_SESSION_HANDLE_INVALID (haskokiStdMessageDecryptBegin ctx invalid iv ivn nullPtr 0)
    expectMessageRv "DecryptNext invalid session" CKR_SESSION_HANDLE_INVALID (haskokiStdMessageDecryptNext ctx invalid nullPtr 0 cipher cn out len 1)
    expectMessageRv "DecryptFinal invalid session" CKR_SESSION_HANDLE_INVALID (haskokiStdMessageDecryptFinal ctx invalid)
    expectMessageRv "SignInit invalid session" CKR_SESSION_HANDLE_INVALID (haskokiStdMessageSignInit ctx invalid 0x251 nullPtr 0 mac)
    expectMessageRv "Sign invalid session" CKR_SESSION_HANDLE_INVALID (haskokiStdMessageSign ctx invalid nullPtr 0 input inputn out len)
    expectMessageRv "SignBegin invalid session" CKR_SESSION_HANDLE_INVALID (haskokiStdMessageSignBegin ctx invalid nullPtr 0)
    expectMessageRv "SignNext invalid session" CKR_SESSION_HANDLE_INVALID (haskokiStdMessageSignNext ctx invalid nullPtr 0 input inputn out len)
    expectMessageRv "SignFinal invalid session" CKR_SESSION_HANDLE_INVALID (haskokiStdMessageSignFinal ctx invalid)
    expectMessageRv "VerifyInit invalid session" CKR_SESSION_HANDLE_INVALID (haskokiStdMessageVerifyInit ctx invalid 0x251 nullPtr 0 mac)
    expectMessageRv "Verify invalid session" CKR_SESSION_HANDLE_INVALID (haskokiStdMessageVerify ctx invalid nullPtr 0 input inputn witness wn)
    expectMessageRv "VerifyBegin invalid session" CKR_SESSION_HANDLE_INVALID (haskokiStdMessageVerifyBegin ctx invalid nullPtr 0)
    expectMessageRv "VerifyNext invalid session" CKR_SESSION_HANDLE_INVALID (haskokiStdMessageVerifyNext ctx invalid nullPtr 0 input inputn witness wn)
    expectMessageRv "VerifyFinal invalid session" CKR_SESSION_HANDLE_INVALID (haskokiStdMessageVerifyFinal ctx invalid)
    expectMessageRv "Encrypt init" CKR_OK (haskokiStdMessageEncryptInit ctx session 0x1082 iv ivn aes)
    poke len 40
    expectMessageRv "Encrypt one" CKR_OK (haskokiStdMessageEncrypt ctx session iv ivn nullPtr 0 plain pn out len)
    peek len >>= assertEqual "Encrypt one length" 16
    peekArray 16 out >>= assertEqual "Encrypt fixed bytes" (BS.unpack messageCipher)
    expectMessageRv "Encrypt begin" CKR_OK (haskokiStdMessageEncryptBegin ctx session iv ivn nullPtr 0)
    poke len 40
    expectMessageRv "Encrypt next" CKR_OK (haskokiStdMessageEncryptNext ctx session nullPtr 0 plain pn out len 1)
    peekArray 16 out >>= assertEqual "Encrypt multipart bytes" (BS.unpack messageCipher)
    expectMessageRv "Encrypt final" CKR_OK (haskokiStdMessageEncryptFinal ctx session)
    expectMessageRv "Decrypt init" CKR_OK (haskokiStdMessageDecryptInit ctx session 0x1082 iv ivn aes)
    poke len 40
    expectMessageRv "Decrypt one" CKR_OK (haskokiStdMessageDecrypt ctx session iv ivn nullPtr 0 cipher cn out len)
    peek len >>= assertEqual "Decrypt one length" 16
    peekArray 16 out >>= assertEqual "Decrypt fixed bytes" (BS.unpack messagePlain)
    expectMessageRv "Decrypt begin" CKR_OK (haskokiStdMessageDecryptBegin ctx session iv ivn nullPtr 0)
    poke len 40
    expectMessageRv "Decrypt next" CKR_OK (haskokiStdMessageDecryptNext ctx session nullPtr 0 cipher cn out len 1)
    peekArray 16 out >>= assertEqual "Decrypt multipart bytes" (BS.unpack messagePlain)
    expectMessageRv "Decrypt final" CKR_OK (haskokiStdMessageDecryptFinal ctx session)
    expectMessageRv "Sign init" CKR_OK (haskokiStdMessageSignInit ctx session 0x251 nullPtr 0 mac)
    poke len 40
    expectMessageRv "Sign one" CKR_OK (haskokiStdMessageSign ctx session nullPtr 0 input inputn out len)
    peek len >>= assertEqual "Sign one length" 32
    peekArray 32 out >>= assertEqual "Sign fixed bytes" (BS.unpack messageMac)
    expectMessageRv "Sign begin" CKR_OK (haskokiStdMessageSignBegin ctx session nullPtr 0)
    poke len 40
    expectMessageRv "Sign next" CKR_OK (haskokiStdMessageSignNext ctx session nullPtr 0 input inputn out len)
    peekArray 32 out >>= assertEqual "Sign multipart bytes" (BS.unpack messageMac)
    expectMessageRv "Sign final" CKR_OK (haskokiStdMessageSignFinal ctx session)
    expectMessageRv "Verify init" CKR_OK (haskokiStdMessageVerifyInit ctx session 0x251 nullPtr 0 mac)
    expectMessageRv "Verify one" CKR_OK (haskokiStdMessageVerify ctx session nullPtr 0 input inputn witness wn)
    expectMessageRv "Verify begin" CKR_OK (haskokiStdMessageVerifyBegin ctx session nullPtr 0)
    expectMessageRv "Verify next" CKR_OK (haskokiStdMessageVerifyNext ctx session nullPtr 0 input inputn witness wn)
    expectMessageRv "Verify final" CKR_OK (haskokiStdMessageVerifyFinal ctx session)
    expectMessageRv "session beats oversize" CKR_SESSION_HANDLE_INVALID
      (haskokiStdMessageSignNext ctx invalid nullPtr 0 input (fromIntegral maxInputBytes + 1) nullPtr nullPtr)
    expectMessageRv "cipher end scalar" CKR_ARGUMENTS_BAD
      (haskokiStdMessageEncryptNext ctx session nullPtr 0 plain pn out len 2)

caseMessageContinuationQuery :: IO ()
caseMessageContinuationQuery = withMessageFixture $ \ctx inst session aes _ ->
  withMessageBytes messageIv $ \iv ivn ->
  withMessageBytes (BS.take 7 messagePlain) $ \part n ->
  allocaBytes 1 $ \out -> alloca $ \len -> do
    expectMessageRv "init" CKR_OK (haskokiStdMessageEncryptInit ctx session 0x1082 iv ivn aes)
    expectMessageRv "begin" CKR_OK (haskokiStdMessageEncryptBegin ctx session iv ivn nullPtr 0)
    before <- snapshotModel (siEnv inst)
    poke len 887
    expectMessageRv "continuation query" CKR_OK (haskokiStdMessageEncryptNext ctx session nullPtr 0 part n nullPtr len 0)
    peek len >>= assertEqual "zero query length" 0
    after <- snapshotModel (siEnv inst)
    assertEqual "query preserves session and auth" (lookupSession before (SessionId (fromIntegral session))) (lookupSession after (SessionId (fromIntegral session)))
    expectMessageRv "outer final while open" CKR_OPERATION_ACTIVE (haskokiStdMessageEncryptFinal ctx session)
    poke len 0
    pokeArray out [165]
    expectMessageRv "present zero continues" CKR_OK (haskokiStdMessageEncryptNext ctx session nullPtr 0 part n out len 0)
    peek len >>= assertEqual "continuation reports zero" 0
    peekArray 1 out >>= assertEqual "continuation canary" [165]
    m <- snapshotModel (siEnv inst)
    assertEqual "part appended once" (Just (Just 7)) (fmap (\st -> messageBuffered (ssOps st) SlotEncrypt) (lookupSession m (SessionId (fromIntegral session))))

caseMessageStagedQuery :: IO ()
caseMessageStagedQuery = withMessageFixture $ \ctx inst session _ mac ->
  withMessageBytes "Hi There" $ \input n ->
  allocaBytes 34 $ \out -> alloca $ \len -> do
    expectMessageRv "init" CKR_OK (haskokiStdMessageSignInit ctx session 0x251 nullPtr 0 mac)
    pokeArray out (replicate 34 165)
    poke len 919
    expectMessageRv "first query" CKR_OK (haskokiStdMessageSign ctx session nullPtr 0 input n nullPtr len)
    peek len >>= assertEqual "query length" 32
    expectMessageRv "query keeps outer busy" CKR_OPERATION_ACTIVE (haskokiStdMessageSignFinal ctx session)
    before <- messageState inst session SlotSign
    assertEqual "no query delivery" 0 (msMessages before)
    poke len 1
    expectMessageRv "repeated query different input" CKR_OK (haskokiStdMessageSign ctx session nullPtr 0 input 1 nullPtr len)
    peek len >>= assertEqual "repeated required length" 32
    messageState inst session SlotSign >>= assertEqual "repeated query unchanged" before
    expectMessageRv "repeat keeps outer busy" CKR_OPERATION_ACTIVE (haskokiStdMessageSignFinal ctx session)
    poke len 31
    expectMessageRv "short recall" CKR_BUFFER_TOO_SMALL (haskokiStdMessageSign ctx session nullPtr 0 input n out len)
    peek len >>= assertEqual "short required length" 32
    peekArray 34 out >>= assertEqual "short untouched" (replicate 34 165)
    staged <- messageState inst session SlotSign
    assertEqual "short keeps bytes" (stagedOf (msCommon before)) (stagedOf (msCommon staged))
    expectMessageRv "short keeps outer busy" CKR_OPERATION_ACTIVE (haskokiStdMessageSignFinal ctx session)
    poke len 771
    expectMessageRv "malformed recall" CKR_ARGUMENTS_BAD (haskokiStdMessageSign ctx session nullPtr 0 nullPtr 1 out len)
    peek len >>= assertEqual "malformed length untouched" 771
    messageState inst session SlotSign >>= assertEqual "malformed keeps stage" staged
    poke len 32
    expectMessageRv "exact recall" CKR_OK (haskokiStdMessageSign ctx session nullPtr 0 input n out len)
    peekArray 34 out >>= assertEqual "exact span only" (BS.unpack messageMac ++ [165,165])
    delivered <- messageState inst session SlotSign
    assertEqual "one delivery" 1 (msMessages delivered)
    assertEqual "stage removed" Nothing (stagedOf (msCommon delivered))
    expectMessageRv "outer final after delivery" CKR_OK (haskokiStdMessageSignFinal ctx session)

caseMessageEmptyQuery :: IO ()
caseMessageEmptyQuery = withMessageFixture $ \ctx inst session aes _ ->
  withMessageBytes messageIv $ \iv ivn -> allocaBytes 32 $ \cipher ->
  allocaBytes 1 $ \out -> alloca $ \len -> do
    expectMessageRv "classic padded init" CKR_OK (haskokiStdEncryptInit ctx session 0x1085 iv ivn aes)
    poke len 32
    expectMessageRv "classic empty encryption" CKR_OK (haskokiStdEncrypt ctx session nullPtr 0 cipher len)
    cipherLen <- peek len
    expectMessageRv "message decrypt init" CKR_OK (haskokiStdMessageDecryptInit ctx session 0x1085 iv ivn aes)
    poke len 55
    expectMessageRv "empty query" CKR_OK (haskokiStdMessageDecrypt ctx session iv ivn nullPtr 0 cipher cipherLen nullPtr len)
    peek len >>= assertEqual "empty query length" 0
    expectMessageRv "empty query staged" CKR_OPERATION_ACTIVE (haskokiStdMessageDecryptFinal ctx session)
    before <- messageState inst session SlotDecrypt
    assertEqual "empty not delivered" 0 (msMessages before)
    poke len 999
    expectMessageRv "empty repeat" CKR_OK (haskokiStdMessageDecrypt ctx session iv ivn nullPtr 0 cipher cipherLen nullPtr len)
    peek len >>= assertEqual "empty repeat length" 0
    messageState inst session SlotDecrypt >>= assertEqual "empty stage unchanged" before
    expectMessageRv "repeat still staged" CKR_OPERATION_ACTIVE (haskokiStdMessageDecryptFinal ctx session)
    poke len 0
    pokeArray out [165]
    expectMessageRv "accept empty present buffer" CKR_OK (haskokiStdMessageDecrypt ctx session iv ivn nullPtr 0 cipher cipherLen out len)
    peekArray 1 out >>= assertEqual "empty untouched canary" [165]
    after <- messageState inst session SlotDecrypt
    assertEqual "empty delivered exactly once" 1 (msMessages after)
    expectMessageRv "empty final" CKR_OK (haskokiStdMessageDecryptFinal ctx session)

caseMessageSignals :: IO ()
caseMessageSignals = withMessageFixture $ \ctx inst session _ mac ->
  withMessageBytes "Hi " $ \first firstn ->
  withMessageBytes "There" $ \lastPart lastn ->
  withMessageBytes messageMac $ \witness wn ->
  allocaBytes 32 $ \out -> alloca $ \len -> do
    expectMessageRv "sign init" CKR_OK (haskokiStdMessageSignInit ctx session 0x251 nullPtr 0 mac)
    expectMessageRv "sign begin" CKR_OK (haskokiStdMessageSignBegin ctx session nullPtr 0)
    pokeArray out (replicate 32 165)
    expectMessageRv "ignored output on sign continue" CKR_OK (haskokiStdMessageSignNext ctx session nullPtr 0 first firstn out nullPtr)
    peekArray 32 out >>= assertEqual "ignored bytes untouched" (replicate 32 165)
    poke len 32
    expectMessageRv "sign terminal" CKR_OK (haskokiStdMessageSignNext ctx session nullPtr 0 lastPart lastn out len)
    peekArray 32 out >>= assertEqual "split signature" (BS.unpack messageMac)
    expectMessageRv "verify init" CKR_OK (haskokiStdMessageVerifyInit ctx session 0x251 nullPtr 0 mac)
    expectMessageRv "verify begin" CKR_OK (haskokiStdMessageVerifyBegin ctx session nullPtr 0)
    expectMessageRv "absent witness continues" CKR_OK (haskokiStdMessageVerifyNext ctx session nullPtr 0 first firstn nullPtr 0)
    expectMessageRv "present witness ends" CKR_OK (haskokiStdMessageVerifyNext ctx session nullPtr 0 lastPart lastn witness wn)
    expectMessageRv "verify begin again" CKR_OK (haskokiStdMessageVerifyBegin ctx session nullPtr 0)
    expectMessageRv "present empty witness ends" CKR_SIGNATURE_INVALID (haskokiStdMessageVerifyNext ctx session nullPtr 0 first firstn witness 0)
    expectMessageRv "begin after mismatch" CKR_OK (haskokiStdMessageVerifyBegin ctx session nullPtr 0)
    before <- messageState inst session SlotVerify
    expectMessageRv "absent nonempty witness refuses" CKR_ARGUMENTS_BAD (haskokiStdMessageVerifyNext ctx session nullPtr 0 first firstn nullPtr 1)
    messageState inst session SlotVerify >>= assertEqual "decode refusal unchanged" before
```

- [ ] Run the new Standard cases before adding exports.

```sh
cabal test haskoki-model-tests --test-option='--pattern=Standard surface'
```

Expected failure: `Haskoki.FFI.Standard` does not export the twenty names referenced by these tests. Capture this exact failure before implementation.

- [ ] Implement the message-specific runners in `ffi/Haskoki/FFI/Standard.hs`.

Merge imports for the eight decoders, `MsgFamily(..), MsgState(..), msgFamilyKind`, `lookupMessage`, `decodeMsgNext`, and `MsgNext(..)`. Retain classic helper bodies byte for byte. These helpers use the existing `stagedLenFor` through the existing reporting functions only after planning establishes the family slot.

```haskell
messageRegion :: MsgFamily -> String
messageRegion MsgEncrypt = "message-encrypt"
messageRegion MsgDecrypt = "message-decrypt"
messageRegion MsgSign = "message-sign"
messageRegion MsgVerify = "message-verify"

matchingMessageLength :: MsgFamily -> Model -> SessionId -> Maybe Word64
matchingMessageLength fam m sid = do
  st <- lookupSession m sid
  msg <- lookupMessage (ssOps st) (msgFamilyKind fam)
  if msFamily msg /= fam then Nothing else do
    staged <- stagedOf (msCommon msg)
    pure (fromIntegral (BS.length (stBytes staged)))

messageContinuation :: MsgFamily -> FunctionId -> ByteString -> Bool
messageContinuation fam func input = case (fam, func, decodeMsgNext fam input) of
  (MsgEncrypt, F_EncryptMessageNext, Just (MsgNextCipher _ _ False)) -> True
  (MsgDecrypt, F_DecryptMessageNext, Just (MsgNextCipher _ _ False)) -> True
  _ -> False

runMessageBuffered :: StdInstance -> SessionId -> MsgFamily -> FunctionId -> ByteString -> Ptr Word8 -> Ptr CULong -> Word64 -> IO CULong
runMessageBuffered inst sid fam func input pOut pLen cap = do
  m <- snapshotModel (siEnv inst)
  let kind = msgFamilyKind fam
      req = Request Pkcs11_3_2 func (Just sid) Nothing input
        [RegionBytes (messageRegion fam) (IntentBuffer cap)]
  result <- runCryptoPlan inst m req
  case result of
    Left rv
      | rv == ckrBufferTooSmall -> reportShortLength inst sid kind pLen
      | otherwise -> pure rv
    Right pc
      | pcCode pc == CKR_OK && null (pcOutputs pc) -> do
          _ <- encodeLength pLen 0
          pure ckrOk
      | otherwise -> encodeCryptoCommit inst sid kind pOut pLen cap pc

runMessageQuery :: StdInstance -> SessionId -> MsgFamily -> FunctionId -> ByteString -> Ptr CULong -> IO CULong
runMessageQuery inst sid fam func input pLen = do
  m <- snapshotModel (siEnv inst)
  let kind = msgFamilyKind fam
      req = Request Pkcs11_3_2 func (Just sid) Nothing input
        [RegionBytes (messageRegion fam) IntentNull]
      planned = planCall (envRules (siEnv inst)) m req
      report n = encodeLength pLen n >> pure ckrOk
      execute = do
        result <- runCryptoPlanOn inst m planned
        case result of
          Left rv
            | rv == ckrBufferTooSmall -> reportCryptoQuery inst sid kind pLen
            | otherwise -> pure rv
          Right pc
            | pcCode pc == CKR_BUFFER_TOO_SMALL -> reportCryptoQuery inst sid kind pLen
            | pcCode pc /= CKR_OK -> pure (stdRvOf (pcCode pc))
            | otherwise -> pure ckrGeneralError
  case planned of
    Reject _ -> execute
    Execute _ _ -> execute
    Immediate pc
      | pcCode pc /= CKR_OK -> pure (stdRvOf (pcCode pc))
      | Just n <- matchingMessageLength fam m sid -> report n
      | messageContinuation fam func input -> report 0
      | otherwise -> pure ckrGeneralError

messageBytes :: StdInstance -> SessionId -> MsgFamily -> FunctionId -> ByteString -> Ptr Word8 -> Ptr CULong -> IO CULong
messageBytes inst sid fam func frame pOut pLen
  | pLen == nullPtr = pure ckrArgsBad
  | pOut == nullPtr = runMessageQuery inst sid fam func frame pLen
  | otherwise = do
      cap <- fromIntegral <$> peek pLen
      runMessageBuffered inst sid fam func frame pOut pLen cap
```

The query runner computes one plan against one snapshot. Successful immediate previews never publish; a rejection still publishes through `runCryptoPlanOn`. A repeated query matches only this session/family's staging and imposes no input equality. No caller capacity word is read for a null output query.

- [ ] Add the twenty exports after the existing Sign/Verify export block in `ffi/Haskoki/FFI/Standard.hs`, and add every `haskokiStdMessage` name below to the module export list. The signatures also define the Haskell side consumed by Task 3.

```haskell
foreign export ccall "haskoki_std_message_encrypt_init" haskokiStdMessageEncryptInit
  :: StablePtr StdInstance -> CULong -> CULong -> Ptr Word8 -> CULong -> CULong -> IO CULong
haskokiStdMessageEncryptInit :: StablePtr StdInstance -> CULong -> CULong -> Ptr Word8 -> CULong -> CULong -> IO CULong
haskokiStdMessageEncryptInit ctx h mech p pn key =
  withStdCtx ctx $ \inst -> withStdSession inst h $ \sid -> do
    frame <- decodeMessageInitFrame MsgEncrypt mech p (fromIntegral pn)
    case frame of
      Left _ -> pure ckrArgsBad
      Right input -> runCryptoSilent inst
        (Request Pkcs11_3_2 F_MessageEncryptInit (Just sid)
          (Just (ExternalHandle (fromIntegral key))) input [])

foreign export ccall "haskoki_std_message_encrypt" haskokiStdMessageEncrypt
  :: StablePtr StdInstance -> CULong -> Ptr Word8 -> CULong -> Ptr Word8 -> CULong -> Ptr Word8 -> CULong -> Ptr Word8 -> Ptr CULong -> IO CULong
haskokiStdMessageEncrypt :: StablePtr StdInstance -> CULong -> Ptr Word8 -> CULong -> Ptr Word8 -> CULong -> Ptr Word8 -> CULong -> Ptr Word8 -> Ptr CULong -> IO CULong
haskokiStdMessageEncrypt ctx h p pn a an d dn out len =
  withStdCtx ctx $ \inst -> withStdSession inst h $ \sid -> do
    frame <- decodeMessageCipherFrame MsgEncrypt p (fromIntegral pn) a (fromIntegral an) d (fromIntegral dn)
    case frame of
      Left _ -> pure ckrArgsBad
      Right input -> messageBytes inst sid MsgEncrypt F_EncryptMessage input out len

foreign export ccall "haskoki_std_message_encrypt_begin" haskokiStdMessageEncryptBegin
  :: StablePtr StdInstance -> CULong -> Ptr Word8 -> CULong -> Ptr Word8 -> CULong -> IO CULong
haskokiStdMessageEncryptBegin :: StablePtr StdInstance -> CULong -> Ptr Word8 -> CULong -> Ptr Word8 -> CULong -> IO CULong
haskokiStdMessageEncryptBegin ctx h p pn a an =
  withStdCtx ctx $ \inst -> withStdSession inst h $ \sid -> do
    frame <- decodeMessageBeginFrame MsgEncrypt p (fromIntegral pn) a (fromIntegral an)
    case frame of
      Left _ -> pure ckrArgsBad
      Right input -> runCryptoSilent inst
        (Request Pkcs11_3_2 F_EncryptMessageBegin (Just sid) Nothing input [])

foreign export ccall "haskoki_std_message_encrypt_next" haskokiStdMessageEncryptNext
  :: StablePtr StdInstance -> CULong -> Ptr Word8 -> CULong -> Ptr Word8 -> CULong -> Ptr Word8 -> Ptr CULong -> CULong -> IO CULong
haskokiStdMessageEncryptNext :: StablePtr StdInstance -> CULong -> Ptr Word8 -> CULong -> Ptr Word8 -> CULong -> Ptr Word8 -> Ptr CULong -> CULong -> IO CULong
haskokiStdMessageEncryptNext ctx h p pn d dn out len end =
  withStdCtx ctx $ \inst -> withStdSession inst h $ \sid -> do
    if end /= 0 && end /= 1 then pure ckrArgsBad else do
      frame <- decodeMessageCipherNextFrame MsgEncrypt p (fromIntegral pn) d (fromIntegral dn) (end == 1)
      case frame of
        Left _ -> pure ckrArgsBad
        Right input -> messageBytes inst sid MsgEncrypt F_EncryptMessageNext input out len

foreign export ccall "haskoki_std_message_encrypt_final" haskokiStdMessageEncryptFinal
  :: StablePtr StdInstance -> CULong -> IO CULong
haskokiStdMessageEncryptFinal :: StablePtr StdInstance -> CULong -> IO CULong
haskokiStdMessageEncryptFinal ctx h =
  withStdCtx ctx $ \inst -> withStdSession inst h $ \sid -> do
    runCryptoSilent inst
      (Request Pkcs11_3_2 F_MessageEncryptFinal (Just sid) Nothing BS.empty [])

foreign export ccall "haskoki_std_message_decrypt_init" haskokiStdMessageDecryptInit
  :: StablePtr StdInstance -> CULong -> CULong -> Ptr Word8 -> CULong -> CULong -> IO CULong
haskokiStdMessageDecryptInit :: StablePtr StdInstance -> CULong -> CULong -> Ptr Word8 -> CULong -> CULong -> IO CULong
haskokiStdMessageDecryptInit ctx h mech p pn key =
  withStdCtx ctx $ \inst -> withStdSession inst h $ \sid -> do
    frame <- decodeMessageInitFrame MsgDecrypt mech p (fromIntegral pn)
    case frame of
      Left _ -> pure ckrArgsBad
      Right input -> runCryptoSilent inst
        (Request Pkcs11_3_2 F_MessageDecryptInit (Just sid)
          (Just (ExternalHandle (fromIntegral key))) input [])

foreign export ccall "haskoki_std_message_decrypt" haskokiStdMessageDecrypt
  :: StablePtr StdInstance -> CULong -> Ptr Word8 -> CULong -> Ptr Word8 -> CULong -> Ptr Word8 -> CULong -> Ptr Word8 -> Ptr CULong -> IO CULong
haskokiStdMessageDecrypt :: StablePtr StdInstance -> CULong -> Ptr Word8 -> CULong -> Ptr Word8 -> CULong -> Ptr Word8 -> CULong -> Ptr Word8 -> Ptr CULong -> IO CULong
haskokiStdMessageDecrypt ctx h p pn a an d dn out len =
  withStdCtx ctx $ \inst -> withStdSession inst h $ \sid -> do
    frame <- decodeMessageCipherFrame MsgDecrypt p (fromIntegral pn) a (fromIntegral an) d (fromIntegral dn)
    case frame of
      Left _ -> pure ckrArgsBad
      Right input -> messageBytes inst sid MsgDecrypt F_DecryptMessage input out len

foreign export ccall "haskoki_std_message_decrypt_begin" haskokiStdMessageDecryptBegin
  :: StablePtr StdInstance -> CULong -> Ptr Word8 -> CULong -> Ptr Word8 -> CULong -> IO CULong
haskokiStdMessageDecryptBegin :: StablePtr StdInstance -> CULong -> Ptr Word8 -> CULong -> Ptr Word8 -> CULong -> IO CULong
haskokiStdMessageDecryptBegin ctx h p pn a an =
  withStdCtx ctx $ \inst -> withStdSession inst h $ \sid -> do
    frame <- decodeMessageBeginFrame MsgDecrypt p (fromIntegral pn) a (fromIntegral an)
    case frame of
      Left _ -> pure ckrArgsBad
      Right input -> runCryptoSilent inst
        (Request Pkcs11_3_2 F_DecryptMessageBegin (Just sid) Nothing input [])

foreign export ccall "haskoki_std_message_decrypt_next" haskokiStdMessageDecryptNext
  :: StablePtr StdInstance -> CULong -> Ptr Word8 -> CULong -> Ptr Word8 -> CULong -> Ptr Word8 -> Ptr CULong -> CULong -> IO CULong
haskokiStdMessageDecryptNext :: StablePtr StdInstance -> CULong -> Ptr Word8 -> CULong -> Ptr Word8 -> CULong -> Ptr Word8 -> Ptr CULong -> CULong -> IO CULong
haskokiStdMessageDecryptNext ctx h p pn d dn out len end =
  withStdCtx ctx $ \inst -> withStdSession inst h $ \sid -> do
    if end /= 0 && end /= 1 then pure ckrArgsBad else do
      frame <- decodeMessageCipherNextFrame MsgDecrypt p (fromIntegral pn) d (fromIntegral dn) (end == 1)
      case frame of
        Left _ -> pure ckrArgsBad
        Right input -> messageBytes inst sid MsgDecrypt F_DecryptMessageNext input out len

foreign export ccall "haskoki_std_message_decrypt_final" haskokiStdMessageDecryptFinal
  :: StablePtr StdInstance -> CULong -> IO CULong
haskokiStdMessageDecryptFinal :: StablePtr StdInstance -> CULong -> IO CULong
haskokiStdMessageDecryptFinal ctx h =
  withStdCtx ctx $ \inst -> withStdSession inst h $ \sid -> do
    runCryptoSilent inst
      (Request Pkcs11_3_2 F_MessageDecryptFinal (Just sid) Nothing BS.empty [])

foreign export ccall "haskoki_std_message_sign_init" haskokiStdMessageSignInit
  :: StablePtr StdInstance -> CULong -> CULong -> Ptr Word8 -> CULong -> CULong -> IO CULong
haskokiStdMessageSignInit :: StablePtr StdInstance -> CULong -> CULong -> Ptr Word8 -> CULong -> CULong -> IO CULong
haskokiStdMessageSignInit ctx h mech p pn key =
  withStdCtx ctx $ \inst -> withStdSession inst h $ \sid -> do
    frame <- decodeMessageInitFrame MsgSign mech p (fromIntegral pn)
    case frame of
      Left _ -> pure ckrArgsBad
      Right input -> runCryptoSilent inst
        (Request Pkcs11_3_2 F_MessageSignInit (Just sid)
          (Just (ExternalHandle (fromIntegral key))) input [])

foreign export ccall "haskoki_std_message_sign" haskokiStdMessageSign
  :: StablePtr StdInstance -> CULong -> Ptr Word8 -> CULong -> Ptr Word8 -> CULong -> Ptr Word8 -> Ptr CULong -> IO CULong
haskokiStdMessageSign :: StablePtr StdInstance -> CULong -> Ptr Word8 -> CULong -> Ptr Word8 -> CULong -> Ptr Word8 -> Ptr CULong -> IO CULong
haskokiStdMessageSign ctx h p pn d dn out len =
  withStdCtx ctx $ \inst -> withStdSession inst h $ \sid -> do
    frame <- decodeMessageSignFrame p (fromIntegral pn) d (fromIntegral dn)
    case frame of
      Left _ -> pure ckrArgsBad
      Right input -> messageBytes inst sid MsgSign F_SignMessage input out len

foreign export ccall "haskoki_std_message_sign_begin" haskokiStdMessageSignBegin
  :: StablePtr StdInstance -> CULong -> Ptr Word8 -> CULong -> IO CULong
haskokiStdMessageSignBegin :: StablePtr StdInstance -> CULong -> Ptr Word8 -> CULong -> IO CULong
haskokiStdMessageSignBegin ctx h p pn =
  withStdCtx ctx $ \inst -> withStdSession inst h $ \sid -> do
    frame <- decodeMessageBeginFrame MsgSign p (fromIntegral pn) nullPtr 0
    case frame of
      Left _ -> pure ckrArgsBad
      Right input -> runCryptoSilent inst
        (Request Pkcs11_3_2 F_SignMessageBegin (Just sid) Nothing input [])

foreign export ccall "haskoki_std_message_sign_next" haskokiStdMessageSignNext
  :: StablePtr StdInstance -> CULong -> Ptr Word8 -> CULong -> Ptr Word8 -> CULong -> Ptr Word8 -> Ptr CULong -> IO CULong
haskokiStdMessageSignNext :: StablePtr StdInstance -> CULong -> Ptr Word8 -> CULong -> Ptr Word8 -> CULong -> Ptr Word8 -> Ptr CULong -> IO CULong
haskokiStdMessageSignNext ctx h p pn d dn out len =
  withStdCtx ctx $ \inst -> withStdSession inst h $ \sid -> do
    frame <- decodeMessageSignNextFrame p (fromIntegral pn) d (fromIntegral dn) (len /= nullPtr)
    case frame of
      Left _ -> pure ckrArgsBad
      Right input
        | len == nullPtr -> runCryptoSilent inst
            (Request Pkcs11_3_2 F_SignMessageNext (Just sid) Nothing input
              [RegionBytes "message-sign" (IntentBuffer 0)])
        | otherwise -> messageBytes inst sid MsgSign F_SignMessageNext input out len

foreign export ccall "haskoki_std_message_sign_final" haskokiStdMessageSignFinal
  :: StablePtr StdInstance -> CULong -> IO CULong
haskokiStdMessageSignFinal :: StablePtr StdInstance -> CULong -> IO CULong
haskokiStdMessageSignFinal ctx h =
  withStdCtx ctx $ \inst -> withStdSession inst h $ \sid -> do
    runCryptoSilent inst
      (Request Pkcs11_3_2 F_MessageSignFinal (Just sid) Nothing BS.empty [])

foreign export ccall "haskoki_std_message_verify_init" haskokiStdMessageVerifyInit
  :: StablePtr StdInstance -> CULong -> CULong -> Ptr Word8 -> CULong -> CULong -> IO CULong
haskokiStdMessageVerifyInit :: StablePtr StdInstance -> CULong -> CULong -> Ptr Word8 -> CULong -> CULong -> IO CULong
haskokiStdMessageVerifyInit ctx h mech p pn key =
  withStdCtx ctx $ \inst -> withStdSession inst h $ \sid -> do
    frame <- decodeMessageInitFrame MsgVerify mech p (fromIntegral pn)
    case frame of
      Left _ -> pure ckrArgsBad
      Right input -> runCryptoSilent inst
        (Request Pkcs11_3_2 F_MessageVerifyInit (Just sid)
          (Just (ExternalHandle (fromIntegral key))) input [])

foreign export ccall "haskoki_std_message_verify" haskokiStdMessageVerify
  :: StablePtr StdInstance -> CULong -> Ptr Word8 -> CULong -> Ptr Word8 -> CULong -> Ptr Word8 -> CULong -> IO CULong
haskokiStdMessageVerify :: StablePtr StdInstance -> CULong -> Ptr Word8 -> CULong -> Ptr Word8 -> CULong -> Ptr Word8 -> CULong -> IO CULong
haskokiStdMessageVerify ctx h p pn d dn out wn =
  withStdCtx ctx $ \inst -> withStdSession inst h $ \sid -> do
    frame <- decodeMessageVerifyFrame p (fromIntegral pn) d (fromIntegral dn) out (fromIntegral wn)
    case frame of
      Left _ -> pure ckrArgsBad
      Right input -> runCryptoSilent inst (Request Pkcs11_3_2 F_VerifyMessage (Just sid) Nothing input [RegionBytes "message-verify" (IntentBuffer 0)])

foreign export ccall "haskoki_std_message_verify_begin" haskokiStdMessageVerifyBegin
  :: StablePtr StdInstance -> CULong -> Ptr Word8 -> CULong -> IO CULong
haskokiStdMessageVerifyBegin :: StablePtr StdInstance -> CULong -> Ptr Word8 -> CULong -> IO CULong
haskokiStdMessageVerifyBegin ctx h p pn =
  withStdCtx ctx $ \inst -> withStdSession inst h $ \sid -> do
    frame <- decodeMessageBeginFrame MsgVerify p (fromIntegral pn) nullPtr 0
    case frame of
      Left _ -> pure ckrArgsBad
      Right input -> runCryptoSilent inst
        (Request Pkcs11_3_2 F_VerifyMessageBegin (Just sid) Nothing input [])

foreign export ccall "haskoki_std_message_verify_next" haskokiStdMessageVerifyNext
  :: StablePtr StdInstance -> CULong -> Ptr Word8 -> CULong -> Ptr Word8 -> CULong -> Ptr Word8 -> CULong -> IO CULong
haskokiStdMessageVerifyNext :: StablePtr StdInstance -> CULong -> Ptr Word8 -> CULong -> Ptr Word8 -> CULong -> Ptr Word8 -> CULong -> IO CULong
haskokiStdMessageVerifyNext ctx h p pn d dn out wn =
  withStdCtx ctx $ \inst -> withStdSession inst h $ \sid -> do
    frame <- decodeMessageVerifyNextFrame p (fromIntegral pn) d (fromIntegral dn) out (fromIntegral wn)
    case frame of
      Left _ -> pure ckrArgsBad
      Right input -> runCryptoSilent inst
        (Request Pkcs11_3_2 F_VerifyMessageNext (Just sid) Nothing input
          [RegionBytes "message-verify" (IntentBuffer 0)])

foreign export ccall "haskoki_std_message_verify_final" haskokiStdMessageVerifyFinal
  :: StablePtr StdInstance -> CULong -> IO CULong
haskokiStdMessageVerifyFinal :: StablePtr StdInstance -> CULong -> IO CULong
haskokiStdMessageVerifyFinal ctx h =
  withStdCtx ctx $ \inst -> withStdSession inst h $ \sid -> do
    runCryptoSilent inst
      (Request Pkcs11_3_2 F_MessageVerifyFinal (Just sid) Nothing BS.empty [])

```

The paired C ABI is fixed by these exact prototypes; these declarations are also the fallback block inserted in Task 3.

```c
unsigned long haskoki_std_message_encrypt_init(void *ctx, unsigned long session,
    unsigned long mechanism, unsigned char *params, unsigned long paramsLen,
    unsigned long key);
unsigned long haskoki_std_message_encrypt(void *ctx, unsigned long session,
    unsigned char *params, unsigned long paramsLen,
    unsigned char *aad, unsigned long aadLen,
    unsigned char *input, unsigned long inputLen,
    unsigned char *output, unsigned long *outputLen);
unsigned long haskoki_std_message_encrypt_begin(void *ctx, unsigned long session,
    unsigned char *params, unsigned long paramsLen,
    unsigned char *aad, unsigned long aadLen);
unsigned long haskoki_std_message_encrypt_next(void *ctx, unsigned long session,
    unsigned char *params, unsigned long paramsLen,
    unsigned char *part, unsigned long partLen,
    unsigned char *output, unsigned long *outputLen, unsigned long end);
unsigned long haskoki_std_message_encrypt_final(void *ctx, unsigned long session);

unsigned long haskoki_std_message_decrypt_init(void *ctx, unsigned long session,
    unsigned long mechanism, unsigned char *params, unsigned long paramsLen,
    unsigned long key);
unsigned long haskoki_std_message_decrypt(void *ctx, unsigned long session,
    unsigned char *params, unsigned long paramsLen,
    unsigned char *aad, unsigned long aadLen,
    unsigned char *input, unsigned long inputLen,
    unsigned char *output, unsigned long *outputLen);
unsigned long haskoki_std_message_decrypt_begin(void *ctx, unsigned long session,
    unsigned char *params, unsigned long paramsLen,
    unsigned char *aad, unsigned long aadLen);
unsigned long haskoki_std_message_decrypt_next(void *ctx, unsigned long session,
    unsigned char *params, unsigned long paramsLen,
    unsigned char *part, unsigned long partLen,
    unsigned char *output, unsigned long *outputLen, unsigned long end);
unsigned long haskoki_std_message_decrypt_final(void *ctx, unsigned long session);

unsigned long haskoki_std_message_sign_init(void *ctx, unsigned long session,
    unsigned long mechanism, unsigned char *params, unsigned long paramsLen,
    unsigned long key);
unsigned long haskoki_std_message_sign(void *ctx, unsigned long session,
    unsigned char *params, unsigned long paramsLen,
    unsigned char *input, unsigned long inputLen,
    unsigned char *signature, unsigned long *signatureLen);
unsigned long haskoki_std_message_sign_begin(void *ctx, unsigned long session,
    unsigned char *params, unsigned long paramsLen);
unsigned long haskoki_std_message_sign_next(void *ctx, unsigned long session,
    unsigned char *params, unsigned long paramsLen,
    unsigned char *part, unsigned long partLen,
    unsigned char *signature, unsigned long *signatureLen);
unsigned long haskoki_std_message_sign_final(void *ctx, unsigned long session);

unsigned long haskoki_std_message_verify_init(void *ctx, unsigned long session,
    unsigned long mechanism, unsigned char *params, unsigned long paramsLen,
    unsigned long key);
unsigned long haskoki_std_message_verify(void *ctx, unsigned long session,
    unsigned char *params, unsigned long paramsLen,
    unsigned char *input, unsigned long inputLen,
    unsigned char *signature, unsigned long signatureLen);
unsigned long haskoki_std_message_verify_begin(void *ctx, unsigned long session,
    unsigned char *params, unsigned long paramsLen);
unsigned long haskoki_std_message_verify_next(void *ctx, unsigned long session,
    unsigned char *params, unsigned long paramsLen,
    unsigned char *part, unsigned long partLen,
    unsigned char *signature, unsigned long signatureLen);
unsigned long haskoki_std_message_verify_final(void *ctx, unsigned long session);
```

- [ ] Run the boundary cases after implementation.

```sh
cabal test haskoki-model-tests --test-option='--pattern=Standard surface'
```

Expected: existing Standard cases and all five new case groups pass with fixed CBC/HMAC bytes; the first and repeated queries preserve staging, empty recall delivers once, and continuation queries preserve session/auth state.

- [ ] Run the decoder and planner regression group.

```sh
cabal test haskoki-model-tests --test-option='--pattern=message operations'
```

Expected: all twenty-four cases pass without edits to core planning code.

- [ ] Commit Task 2.

```sh
git add ffi/Haskoki/FFI/Standard.hs tests/model/StandardSurfaceSpec.hs
git commit -m "feat: export message dialogues per routing spec sections 3.1 3.4 and 5.1"
```

### Task 3: Twenty C bodies, fallback declarations, and lock probes

**Files:** Modify `cbits/standard_surface.c` and `cbits/exports.c`; temporary test file `/tmp/haskoki-message-surface/probe.c` (not committed).

**Interfaces:** Consumes all twenty `unsigned long haskoki_std_message_*` prototypes printed in Task 2; `int haskoki_live_interval(void)`, `CK_RV haskoki_state_lock(void)`, `CK_RV haskoki_state_unlock(void)`, and private `void *live_std(void)`. Produces these exact public-surface signatures in both C files:

```c
extern CK_RV std_MessageEncryptInit(CK_SESSION_HANDLE hSession,
    CK_MECHANISM *pMechanism, CK_OBJECT_HANDLE hKey);
extern CK_RV std_EncryptMessage(CK_SESSION_HANDLE hSession,
    void *pParameter, CK_ULONG ulParameterLen,
    CK_BYTE *pAssociatedData, CK_ULONG ulAssociatedDataLen,
    CK_BYTE *pPlaintext, CK_ULONG ulPlaintextLen,
    CK_BYTE *pCiphertext, CK_ULONG *pulCiphertextLen);
extern CK_RV std_EncryptMessageBegin(CK_SESSION_HANDLE hSession,
    void *pParameter, CK_ULONG ulParameterLen,
    CK_BYTE *pAssociatedData, CK_ULONG ulAssociatedDataLen);
extern CK_RV std_EncryptMessageNext(CK_SESSION_HANDLE hSession,
    void *pParameter, CK_ULONG ulParameterLen,
    CK_BYTE *pPlaintextPart, CK_ULONG ulPlaintextPartLen,
    CK_BYTE *pCiphertextPart, CK_ULONG *pulCiphertextPartLen, CK_FLAGS flags);
extern CK_RV std_MessageEncryptFinal(CK_SESSION_HANDLE hSession);
extern CK_RV std_MessageDecryptInit(CK_SESSION_HANDLE hSession,
    CK_MECHANISM *pMechanism, CK_OBJECT_HANDLE hKey);
extern CK_RV std_DecryptMessage(CK_SESSION_HANDLE hSession,
    void *pParameter, CK_ULONG ulParameterLen,
    CK_BYTE *pAssociatedData, CK_ULONG ulAssociatedDataLen,
    CK_BYTE *pCiphertext, CK_ULONG ulCiphertextLen,
    CK_BYTE *pPlaintext, CK_ULONG *pulPlaintextLen);
extern CK_RV std_DecryptMessageBegin(CK_SESSION_HANDLE hSession,
    void *pParameter, CK_ULONG ulParameterLen,
    CK_BYTE *pAssociatedData, CK_ULONG ulAssociatedDataLen);
extern CK_RV std_DecryptMessageNext(CK_SESSION_HANDLE hSession,
    void *pParameter, CK_ULONG ulParameterLen,
    CK_BYTE *pCiphertextPart, CK_ULONG ulCiphertextPartLen,
    CK_BYTE *pPlaintextPart, CK_ULONG *pulPlaintextPartLen, CK_FLAGS flags);
extern CK_RV std_MessageDecryptFinal(CK_SESSION_HANDLE hSession);
extern CK_RV std_MessageSignInit(CK_SESSION_HANDLE hSession,
    CK_MECHANISM *pMechanism, CK_OBJECT_HANDLE hKey);
extern CK_RV std_SignMessage(CK_SESSION_HANDLE hSession,
    void *pParameter, CK_ULONG ulParameterLen,
    CK_BYTE *pData, CK_ULONG ulDataLen,
    CK_BYTE *pSignature, CK_ULONG *pulSignatureLen);
extern CK_RV std_SignMessageBegin(CK_SESSION_HANDLE hSession,
    void *pParameter, CK_ULONG ulParameterLen);
extern CK_RV std_SignMessageNext(CK_SESSION_HANDLE hSession,
    void *pParameter, CK_ULONG ulParameterLen,
    CK_BYTE *pDataPart, CK_ULONG ulDataPartLen,
    CK_BYTE *pSignature, CK_ULONG *pulSignatureLen);
extern CK_RV std_MessageSignFinal(CK_SESSION_HANDLE hSession);
extern CK_RV std_MessageVerifyInit(CK_SESSION_HANDLE hSession,
    CK_MECHANISM *pMechanism, CK_OBJECT_HANDLE hKey);
extern CK_RV std_VerifyMessage(CK_SESSION_HANDLE hSession,
    void *pParameter, CK_ULONG ulParameterLen,
    CK_BYTE *pData, CK_ULONG ulDataLen,
    CK_BYTE *pSignature, CK_ULONG ulSignatureLen);
extern CK_RV std_VerifyMessageBegin(CK_SESSION_HANDLE hSession,
    void *pParameter, CK_ULONG ulParameterLen);
extern CK_RV std_VerifyMessageNext(CK_SESSION_HANDLE hSession,
    void *pParameter, CK_ULONG ulParameterLen,
    CK_BYTE *pDataPart, CK_ULONG ulDataPartLen,
    CK_BYTE *pSignature, CK_ULONG ulSignatureLen);
extern CK_RV std_MessageVerifyFinal(CK_SESSION_HANDLE hSession);
```

- [ ] Write `/tmp/haskoki-message-surface/probe.c` with the following source. This is an internal C boundary probe; it is separate from the independent consumer in Task 5. Including the production translation unit lets the linker discard unrelated functions while the probe supplies only message exports and mutex/liveness hooks.

```c
#include <assert.h>
#include <stdio.h>
#include "standard_surface.c"

static int live, locked, locks, unlocks, calls, peeks, marker;
static unsigned long expectedSession, expectedEnd;
static CK_RV lockResult, exportResult;
static unsigned char probeBytes[16];
static unsigned long probeLength;

int haskoki_live_interval(void) { ++peeks; return live; }
CK_RV haskoki_state_lock(void) {
  assert(peeks == 1);
  ++locks;
  if (lockResult == CKR_OK) locked = 1;
  return lockResult;
}
CK_RV haskoki_state_unlock(void) {
  assert(locked);
  locked = 0;
  ++unlocks;
  return CKR_OK;
}
static void reset_probe(void) {
  live = 1; locked = locks = unlocks = calls = peeks = 0;
  lockResult = CKR_OK; exportResult = CKR_SESSION_HANDLE_INVALID;
  expectedSession = 7; expectedEnd = 1;
  haskoki_std_install(&marker);
}
static unsigned long record_export(void *ctx, unsigned long session) {
  assert(ctx == &marker && locked && peeks == 2);
  assert(session == expectedSession);
  ++calls;
  return exportResult;
}
unsigned long haskoki_std_message_encrypt_init(void *ctx, unsigned long session, unsigned long mechanism, unsigned char *params, unsigned long paramsLen, unsigned long key) {
  assert(mechanism == CKM_SHA256_HMAC);
  assert(params == probeBytes);
  assert(paramsLen == 1);
  assert(key == 9);
  return record_export(ctx, session);
}
unsigned long haskoki_std_message_encrypt(void *ctx, unsigned long session, unsigned char *params, unsigned long paramsLen, unsigned char *aad, unsigned long aadLen, unsigned char *input, unsigned long inputLen, unsigned char *output, unsigned long *outputLen) {
  assert(params == probeBytes);
  assert(paramsLen == 1);
  assert(aad == probeBytes);
  assert(aadLen == 2);
  assert(input == probeBytes);
  assert(inputLen == 3);
  assert(output == probeBytes);
  assert(outputLen == &probeLength);
  return record_export(ctx, session);
}
unsigned long haskoki_std_message_encrypt_begin(void *ctx, unsigned long session, unsigned char *params, unsigned long paramsLen, unsigned char *aad, unsigned long aadLen) {
  assert(params == probeBytes);
  assert(paramsLen == 1);
  assert(aad == probeBytes);
  assert(aadLen == 2);
  return record_export(ctx, session);
}
unsigned long haskoki_std_message_encrypt_next(void *ctx, unsigned long session, unsigned char *params, unsigned long paramsLen, unsigned char *part, unsigned long partLen, unsigned char *output, unsigned long *outputLen, unsigned long end) {
  assert(params == probeBytes);
  assert(paramsLen == 1);
  assert(part == probeBytes);
  assert(partLen == 3);
  assert(output == probeBytes);
  assert(outputLen == &probeLength);
  assert(end == expectedEnd);
  return record_export(ctx, session);
}
unsigned long haskoki_std_message_encrypt_final(void *ctx, unsigned long session) {
  return record_export(ctx, session);
}
unsigned long haskoki_std_message_decrypt_init(void *ctx, unsigned long session, unsigned long mechanism, unsigned char *params, unsigned long paramsLen, unsigned long key) {
  assert(mechanism == CKM_SHA256_HMAC);
  assert(params == probeBytes);
  assert(paramsLen == 1);
  assert(key == 9);
  return record_export(ctx, session);
}
unsigned long haskoki_std_message_decrypt(void *ctx, unsigned long session, unsigned char *params, unsigned long paramsLen, unsigned char *aad, unsigned long aadLen, unsigned char *input, unsigned long inputLen, unsigned char *output, unsigned long *outputLen) {
  assert(params == probeBytes);
  assert(paramsLen == 1);
  assert(aad == probeBytes);
  assert(aadLen == 2);
  assert(input == probeBytes);
  assert(inputLen == 3);
  assert(output == probeBytes);
  assert(outputLen == &probeLength);
  return record_export(ctx, session);
}
unsigned long haskoki_std_message_decrypt_begin(void *ctx, unsigned long session, unsigned char *params, unsigned long paramsLen, unsigned char *aad, unsigned long aadLen) {
  assert(params == probeBytes);
  assert(paramsLen == 1);
  assert(aad == probeBytes);
  assert(aadLen == 2);
  return record_export(ctx, session);
}
unsigned long haskoki_std_message_decrypt_next(void *ctx, unsigned long session, unsigned char *params, unsigned long paramsLen, unsigned char *part, unsigned long partLen, unsigned char *output, unsigned long *outputLen, unsigned long end) {
  assert(params == probeBytes);
  assert(paramsLen == 1);
  assert(part == probeBytes);
  assert(partLen == 3);
  assert(output == probeBytes);
  assert(outputLen == &probeLength);
  assert(end == expectedEnd);
  return record_export(ctx, session);
}
unsigned long haskoki_std_message_decrypt_final(void *ctx, unsigned long session) {
  return record_export(ctx, session);
}
unsigned long haskoki_std_message_sign_init(void *ctx, unsigned long session, unsigned long mechanism, unsigned char *params, unsigned long paramsLen, unsigned long key) {
  assert(mechanism == CKM_SHA256_HMAC);
  assert(params == probeBytes);
  assert(paramsLen == 1);
  assert(key == 9);
  return record_export(ctx, session);
}
unsigned long haskoki_std_message_sign(void *ctx, unsigned long session, unsigned char *params, unsigned long paramsLen, unsigned char *input, unsigned long inputLen, unsigned char *signature, unsigned long *signatureLen) {
  assert(params == probeBytes);
  assert(paramsLen == 1);
  assert(input == probeBytes);
  assert(inputLen == 3);
  assert(signature == probeBytes);
  assert(signatureLen == &probeLength);
  return record_export(ctx, session);
}
unsigned long haskoki_std_message_sign_begin(void *ctx, unsigned long session, unsigned char *params, unsigned long paramsLen) {
  assert(params == probeBytes);
  assert(paramsLen == 1);
  return record_export(ctx, session);
}
unsigned long haskoki_std_message_sign_next(void *ctx, unsigned long session, unsigned char *params, unsigned long paramsLen, unsigned char *part, unsigned long partLen, unsigned char *signature, unsigned long *signatureLen) {
  assert(params == probeBytes);
  assert(paramsLen == 1);
  assert(part == probeBytes);
  assert(partLen == 3);
  assert(signature == probeBytes);
  assert(signatureLen == &probeLength);
  return record_export(ctx, session);
}
unsigned long haskoki_std_message_sign_final(void *ctx, unsigned long session) {
  return record_export(ctx, session);
}
unsigned long haskoki_std_message_verify_init(void *ctx, unsigned long session, unsigned long mechanism, unsigned char *params, unsigned long paramsLen, unsigned long key) {
  assert(mechanism == CKM_SHA256_HMAC);
  assert(params == probeBytes);
  assert(paramsLen == 1);
  assert(key == 9);
  return record_export(ctx, session);
}
unsigned long haskoki_std_message_verify(void *ctx, unsigned long session, unsigned char *params, unsigned long paramsLen, unsigned char *input, unsigned long inputLen, unsigned char *signature, unsigned long signatureLen) {
  assert(params == probeBytes);
  assert(paramsLen == 1);
  assert(input == probeBytes);
  assert(inputLen == 3);
  assert(signature == probeBytes);
  assert(signatureLen == 4);
  return record_export(ctx, session);
}
unsigned long haskoki_std_message_verify_begin(void *ctx, unsigned long session, unsigned char *params, unsigned long paramsLen) {
  assert(params == probeBytes);
  assert(paramsLen == 1);
  return record_export(ctx, session);
}
unsigned long haskoki_std_message_verify_next(void *ctx, unsigned long session, unsigned char *params, unsigned long paramsLen, unsigned char *part, unsigned long partLen, unsigned char *signature, unsigned long signatureLen) {
  assert(params == probeBytes);
  assert(paramsLen == 1);
  assert(part == probeBytes);
  assert(partLen == 3);
  assert(signature == probeBytes);
  assert(signatureLen == 4);
  return record_export(ctx, session);
}
unsigned long haskoki_std_message_verify_final(void *ctx, unsigned long session) {
  return record_export(ctx, session);
}

#define PROBE_CALL(call) do { \
  reset_probe(); live = 0; \
  assert((call) == CKR_CRYPTOKI_NOT_INITIALIZED); \
  assert(peeks == 1 && locks == 0 && calls == 0 && unlocks == 0); \
  reset_probe(); lockResult = CKR_CANT_LOCK; \
  assert((call) == CKR_CANT_LOCK); \
  assert(locks == 1 && calls == 0 && unlocks == 0); \
  reset_probe(); lockResult = CKR_FUNCTION_FAILED; \
  assert((call) == CKR_FUNCTION_FAILED); \
  assert(locks == 1 && calls == 0 && unlocks == 0); \
  reset_probe(); haskoki_std_install(NULL); \
  assert((call) == CKR_CRYPTOKI_NOT_INITIALIZED); \
  assert(locks == 1 && calls == 0 && unlocks == 1); \
  reset_probe(); \
  assert((call) == CKR_SESSION_HANDLE_INVALID); \
  assert(locks == 1 && calls == 1 && unlocks == 1 && !locked); \
} while (0)
#define PROBE_GUARD(call) do { \
  reset_probe(); live = 0; \
  assert((call) == CKR_CRYPTOKI_NOT_INITIALIZED); \
  assert(locks == 0 && calls == 0 && unlocks == 0); \
  reset_probe(); \
  assert((call) == CKR_ARGUMENTS_BAD); \
  assert(peeks == 1 && locks == 0 && calls == 0 && unlocks == 0); \
} while (0)

int main(void) {
  CK_MECHANISM mech = {CKM_SHA256_HMAC, probeBytes, 1};
  CK_MECHANISM badMech = {CKM_SHA256_HMAC, NULL, 1};
  CK_C_MessageEncryptInit typedMessageEncryptInit = std_MessageEncryptInit;
  (void)typedMessageEncryptInit;
  PROBE_CALL(std_MessageEncryptInit(7, &mech, 9));
  PROBE_GUARD(std_MessageEncryptInit(7, NULL, 9));
  PROBE_GUARD(std_MessageEncryptInit(999, NULL, 9));
  PROBE_GUARD(std_MessageEncryptInit(7, &badMech, 9));
  PROBE_GUARD(std_MessageEncryptInit(999, &badMech, 9));
  CK_C_EncryptMessage typedEncryptMessage = std_EncryptMessage;
  (void)typedEncryptMessage;
  PROBE_CALL(std_EncryptMessage(7, probeBytes, 1, probeBytes, 2, probeBytes, 3, probeBytes, &probeLength));
  PROBE_GUARD(std_EncryptMessage(7, probeBytes, 1, probeBytes, 2, probeBytes, 3, probeBytes, NULL));
  PROBE_GUARD(std_EncryptMessage(999, probeBytes, 1, probeBytes, 2, probeBytes, 3, probeBytes, NULL));
  PROBE_GUARD(std_EncryptMessage(7, NULL, 1, probeBytes, 2, probeBytes, 3, probeBytes, &probeLength));
  PROBE_GUARD(std_EncryptMessage(999, NULL, 1, probeBytes, 2, probeBytes, 3, probeBytes, &probeLength));
  PROBE_GUARD(std_EncryptMessage(7, probeBytes, 1, NULL, 2, probeBytes, 3, probeBytes, &probeLength));
  PROBE_GUARD(std_EncryptMessage(999, probeBytes, 1, NULL, 2, probeBytes, 3, probeBytes, &probeLength));
  PROBE_GUARD(std_EncryptMessage(7, probeBytes, 1, probeBytes, 2, NULL, 3, probeBytes, &probeLength));
  PROBE_GUARD(std_EncryptMessage(999, probeBytes, 1, probeBytes, 2, NULL, 3, probeBytes, &probeLength));
  CK_C_EncryptMessageBegin typedEncryptMessageBegin = std_EncryptMessageBegin;
  (void)typedEncryptMessageBegin;
  PROBE_CALL(std_EncryptMessageBegin(7, probeBytes, 1, probeBytes, 2));
  PROBE_GUARD(std_EncryptMessageBegin(7, NULL, 1, probeBytes, 2));
  PROBE_GUARD(std_EncryptMessageBegin(999, NULL, 1, probeBytes, 2));
  PROBE_GUARD(std_EncryptMessageBegin(7, probeBytes, 1, NULL, 2));
  PROBE_GUARD(std_EncryptMessageBegin(999, probeBytes, 1, NULL, 2));
  CK_C_EncryptMessageNext typedEncryptMessageNext = std_EncryptMessageNext;
  (void)typedEncryptMessageNext;
  PROBE_CALL(std_EncryptMessageNext(7, probeBytes, 1, probeBytes, 3, probeBytes, &probeLength, CKF_END_OF_MESSAGE));
  PROBE_GUARD(std_EncryptMessageNext(7, probeBytes, 1, probeBytes, 3, probeBytes, NULL, CKF_END_OF_MESSAGE));
  PROBE_GUARD(std_EncryptMessageNext(999, probeBytes, 1, probeBytes, 3, probeBytes, NULL, CKF_END_OF_MESSAGE));
  PROBE_GUARD(std_EncryptMessageNext(7, NULL, 1, probeBytes, 3, probeBytes, &probeLength, CKF_END_OF_MESSAGE));
  PROBE_GUARD(std_EncryptMessageNext(999, NULL, 1, probeBytes, 3, probeBytes, &probeLength, CKF_END_OF_MESSAGE));
  PROBE_GUARD(std_EncryptMessageNext(7, probeBytes, 1, NULL, 3, probeBytes, &probeLength, CKF_END_OF_MESSAGE));
  PROBE_GUARD(std_EncryptMessageNext(999, probeBytes, 1, NULL, 3, probeBytes, &probeLength, CKF_END_OF_MESSAGE));
  PROBE_GUARD(std_EncryptMessageNext(7, probeBytes, 1, probeBytes, 3, probeBytes, &probeLength, 2));
  PROBE_GUARD(std_EncryptMessageNext(999, probeBytes, 1, probeBytes, 3, probeBytes, &probeLength, 2));
  CK_C_MessageEncryptFinal typedMessageEncryptFinal = std_MessageEncryptFinal;
  (void)typedMessageEncryptFinal;
  PROBE_CALL(std_MessageEncryptFinal(7));
  CK_C_MessageDecryptInit typedMessageDecryptInit = std_MessageDecryptInit;
  (void)typedMessageDecryptInit;
  PROBE_CALL(std_MessageDecryptInit(7, &mech, 9));
  PROBE_GUARD(std_MessageDecryptInit(7, NULL, 9));
  PROBE_GUARD(std_MessageDecryptInit(999, NULL, 9));
  PROBE_GUARD(std_MessageDecryptInit(7, &badMech, 9));
  PROBE_GUARD(std_MessageDecryptInit(999, &badMech, 9));
  CK_C_DecryptMessage typedDecryptMessage = std_DecryptMessage;
  (void)typedDecryptMessage;
  PROBE_CALL(std_DecryptMessage(7, probeBytes, 1, probeBytes, 2, probeBytes, 3, probeBytes, &probeLength));
  PROBE_GUARD(std_DecryptMessage(7, probeBytes, 1, probeBytes, 2, probeBytes, 3, probeBytes, NULL));
  PROBE_GUARD(std_DecryptMessage(999, probeBytes, 1, probeBytes, 2, probeBytes, 3, probeBytes, NULL));
  PROBE_GUARD(std_DecryptMessage(7, NULL, 1, probeBytes, 2, probeBytes, 3, probeBytes, &probeLength));
  PROBE_GUARD(std_DecryptMessage(999, NULL, 1, probeBytes, 2, probeBytes, 3, probeBytes, &probeLength));
  PROBE_GUARD(std_DecryptMessage(7, probeBytes, 1, NULL, 2, probeBytes, 3, probeBytes, &probeLength));
  PROBE_GUARD(std_DecryptMessage(999, probeBytes, 1, NULL, 2, probeBytes, 3, probeBytes, &probeLength));
  PROBE_GUARD(std_DecryptMessage(7, probeBytes, 1, probeBytes, 2, NULL, 3, probeBytes, &probeLength));
  PROBE_GUARD(std_DecryptMessage(999, probeBytes, 1, probeBytes, 2, NULL, 3, probeBytes, &probeLength));
  CK_C_DecryptMessageBegin typedDecryptMessageBegin = std_DecryptMessageBegin;
  (void)typedDecryptMessageBegin;
  PROBE_CALL(std_DecryptMessageBegin(7, probeBytes, 1, probeBytes, 2));
  PROBE_GUARD(std_DecryptMessageBegin(7, NULL, 1, probeBytes, 2));
  PROBE_GUARD(std_DecryptMessageBegin(999, NULL, 1, probeBytes, 2));
  PROBE_GUARD(std_DecryptMessageBegin(7, probeBytes, 1, NULL, 2));
  PROBE_GUARD(std_DecryptMessageBegin(999, probeBytes, 1, NULL, 2));
  CK_C_DecryptMessageNext typedDecryptMessageNext = std_DecryptMessageNext;
  (void)typedDecryptMessageNext;
  PROBE_CALL(std_DecryptMessageNext(7, probeBytes, 1, probeBytes, 3, probeBytes, &probeLength, CKF_END_OF_MESSAGE));
  PROBE_GUARD(std_DecryptMessageNext(7, probeBytes, 1, probeBytes, 3, probeBytes, NULL, CKF_END_OF_MESSAGE));
  PROBE_GUARD(std_DecryptMessageNext(999, probeBytes, 1, probeBytes, 3, probeBytes, NULL, CKF_END_OF_MESSAGE));
  PROBE_GUARD(std_DecryptMessageNext(7, NULL, 1, probeBytes, 3, probeBytes, &probeLength, CKF_END_OF_MESSAGE));
  PROBE_GUARD(std_DecryptMessageNext(999, NULL, 1, probeBytes, 3, probeBytes, &probeLength, CKF_END_OF_MESSAGE));
  PROBE_GUARD(std_DecryptMessageNext(7, probeBytes, 1, NULL, 3, probeBytes, &probeLength, CKF_END_OF_MESSAGE));
  PROBE_GUARD(std_DecryptMessageNext(999, probeBytes, 1, NULL, 3, probeBytes, &probeLength, CKF_END_OF_MESSAGE));
  PROBE_GUARD(std_DecryptMessageNext(7, probeBytes, 1, probeBytes, 3, probeBytes, &probeLength, 2));
  PROBE_GUARD(std_DecryptMessageNext(999, probeBytes, 1, probeBytes, 3, probeBytes, &probeLength, 2));
  CK_C_MessageDecryptFinal typedMessageDecryptFinal = std_MessageDecryptFinal;
  (void)typedMessageDecryptFinal;
  PROBE_CALL(std_MessageDecryptFinal(7));
  CK_C_MessageSignInit typedMessageSignInit = std_MessageSignInit;
  (void)typedMessageSignInit;
  PROBE_CALL(std_MessageSignInit(7, &mech, 9));
  PROBE_GUARD(std_MessageSignInit(7, NULL, 9));
  PROBE_GUARD(std_MessageSignInit(999, NULL, 9));
  PROBE_GUARD(std_MessageSignInit(7, &badMech, 9));
  PROBE_GUARD(std_MessageSignInit(999, &badMech, 9));
  CK_C_SignMessage typedSignMessage = std_SignMessage;
  (void)typedSignMessage;
  PROBE_CALL(std_SignMessage(7, probeBytes, 1, probeBytes, 3, probeBytes, &probeLength));
  PROBE_GUARD(std_SignMessage(7, probeBytes, 1, probeBytes, 3, probeBytes, NULL));
  PROBE_GUARD(std_SignMessage(999, probeBytes, 1, probeBytes, 3, probeBytes, NULL));
  PROBE_GUARD(std_SignMessage(7, NULL, 1, probeBytes, 3, probeBytes, &probeLength));
  PROBE_GUARD(std_SignMessage(999, NULL, 1, probeBytes, 3, probeBytes, &probeLength));
  PROBE_GUARD(std_SignMessage(7, probeBytes, 1, NULL, 3, probeBytes, &probeLength));
  PROBE_GUARD(std_SignMessage(999, probeBytes, 1, NULL, 3, probeBytes, &probeLength));
  CK_C_SignMessageBegin typedSignMessageBegin = std_SignMessageBegin;
  (void)typedSignMessageBegin;
  PROBE_CALL(std_SignMessageBegin(7, probeBytes, 1));
  PROBE_GUARD(std_SignMessageBegin(7, NULL, 1));
  PROBE_GUARD(std_SignMessageBegin(999, NULL, 1));
  CK_C_SignMessageNext typedSignMessageNext = std_SignMessageNext;
  (void)typedSignMessageNext;
  PROBE_CALL(std_SignMessageNext(7, probeBytes, 1, probeBytes, 3, probeBytes, &probeLength));
  PROBE_GUARD(std_SignMessageNext(7, NULL, 1, probeBytes, 3, probeBytes, &probeLength));
  PROBE_GUARD(std_SignMessageNext(999, NULL, 1, probeBytes, 3, probeBytes, &probeLength));
  PROBE_GUARD(std_SignMessageNext(7, probeBytes, 1, NULL, 3, probeBytes, &probeLength));
  PROBE_GUARD(std_SignMessageNext(999, probeBytes, 1, NULL, 3, probeBytes, &probeLength));
  CK_C_MessageSignFinal typedMessageSignFinal = std_MessageSignFinal;
  (void)typedMessageSignFinal;
  PROBE_CALL(std_MessageSignFinal(7));
  CK_C_MessageVerifyInit typedMessageVerifyInit = std_MessageVerifyInit;
  (void)typedMessageVerifyInit;
  PROBE_CALL(std_MessageVerifyInit(7, &mech, 9));
  PROBE_GUARD(std_MessageVerifyInit(7, NULL, 9));
  PROBE_GUARD(std_MessageVerifyInit(999, NULL, 9));
  PROBE_GUARD(std_MessageVerifyInit(7, &badMech, 9));
  PROBE_GUARD(std_MessageVerifyInit(999, &badMech, 9));
  CK_C_VerifyMessage typedVerifyMessage = std_VerifyMessage;
  (void)typedVerifyMessage;
  PROBE_CALL(std_VerifyMessage(7, probeBytes, 1, probeBytes, 3, probeBytes, 4));
  PROBE_GUARD(std_VerifyMessage(7, NULL, 1, probeBytes, 3, probeBytes, 4));
  PROBE_GUARD(std_VerifyMessage(999, NULL, 1, probeBytes, 3, probeBytes, 4));
  PROBE_GUARD(std_VerifyMessage(7, probeBytes, 1, NULL, 3, probeBytes, 4));
  PROBE_GUARD(std_VerifyMessage(999, probeBytes, 1, NULL, 3, probeBytes, 4));
  PROBE_GUARD(std_VerifyMessage(7, probeBytes, 1, probeBytes, 3, NULL, 4));
  PROBE_GUARD(std_VerifyMessage(999, probeBytes, 1, probeBytes, 3, NULL, 4));
  CK_C_VerifyMessageBegin typedVerifyMessageBegin = std_VerifyMessageBegin;
  (void)typedVerifyMessageBegin;
  PROBE_CALL(std_VerifyMessageBegin(7, probeBytes, 1));
  PROBE_GUARD(std_VerifyMessageBegin(7, NULL, 1));
  PROBE_GUARD(std_VerifyMessageBegin(999, NULL, 1));
  CK_C_VerifyMessageNext typedVerifyMessageNext = std_VerifyMessageNext;
  (void)typedVerifyMessageNext;
  PROBE_CALL(std_VerifyMessageNext(7, probeBytes, 1, probeBytes, 3, probeBytes, 4));
  PROBE_GUARD(std_VerifyMessageNext(7, NULL, 1, probeBytes, 3, probeBytes, 4));
  PROBE_GUARD(std_VerifyMessageNext(999, NULL, 1, probeBytes, 3, probeBytes, 4));
  PROBE_GUARD(std_VerifyMessageNext(7, probeBytes, 1, NULL, 3, probeBytes, 4));
  PROBE_GUARD(std_VerifyMessageNext(999, probeBytes, 1, NULL, 3, probeBytes, 4));
  PROBE_GUARD(std_VerifyMessageNext(7, probeBytes, 1, probeBytes, 3, NULL, 4));
  PROBE_GUARD(std_VerifyMessageNext(999, probeBytes, 1, probeBytes, 3, NULL, 4));
  CK_C_MessageVerifyFinal typedMessageVerifyFinal = std_MessageVerifyFinal;
  (void)typedMessageVerifyFinal;
  PROBE_CALL(std_MessageVerifyFinal(7));
  puts("PASS: message surface guards, forwarding, and locks");
  return 0;
}
```

- [ ] Run the C probe before adding the bodies.

```sh
cc -std=c11 -O2 -g -Wall -Wextra -Werror -ffunction-sections -fdata-sections -Ispec/vendor -Icbits /tmp/haskoki-message-surface/probe.c -Wl,--gc-sections -lpthread -o /tmp/haskoki-message-surface/probe
```

Expected failure: undeclared `std_MessageEncryptInit` and the other nineteen missing `std_*` identifiers in the typed assignments/calls. Save the compiler output. Create the temporary directory with `mkdir -p /tmp/haskoki-message-surface` before writing the probe; it is not a source-tree change.

- [ ] Insert the twenty fallback prototypes from Task 2 in `cbits/standard_surface.c` inside `#ifndef HASKOKI_HAVE_STD_STUB_H`.

The generated stub header remains preferred. Use the printed `unsigned long` ABI exactly; do not invent a flags argument for Sign/Verify.

```c
unsigned long haskoki_std_message_encrypt_init(void *ctx, unsigned long session,
    unsigned long mechanism, unsigned char *params, unsigned long paramsLen,
    unsigned long key);
unsigned long haskoki_std_message_encrypt(void *ctx, unsigned long session,
    unsigned char *params, unsigned long paramsLen,
    unsigned char *aad, unsigned long aadLen,
    unsigned char *input, unsigned long inputLen,
    unsigned char *output, unsigned long *outputLen);
unsigned long haskoki_std_message_encrypt_begin(void *ctx, unsigned long session,
    unsigned char *params, unsigned long paramsLen,
    unsigned char *aad, unsigned long aadLen);
unsigned long haskoki_std_message_encrypt_next(void *ctx, unsigned long session,
    unsigned char *params, unsigned long paramsLen,
    unsigned char *part, unsigned long partLen,
    unsigned char *output, unsigned long *outputLen, unsigned long end);
unsigned long haskoki_std_message_encrypt_final(void *ctx, unsigned long session);

unsigned long haskoki_std_message_decrypt_init(void *ctx, unsigned long session,
    unsigned long mechanism, unsigned char *params, unsigned long paramsLen,
    unsigned long key);
unsigned long haskoki_std_message_decrypt(void *ctx, unsigned long session,
    unsigned char *params, unsigned long paramsLen,
    unsigned char *aad, unsigned long aadLen,
    unsigned char *input, unsigned long inputLen,
    unsigned char *output, unsigned long *outputLen);
unsigned long haskoki_std_message_decrypt_begin(void *ctx, unsigned long session,
    unsigned char *params, unsigned long paramsLen,
    unsigned char *aad, unsigned long aadLen);
unsigned long haskoki_std_message_decrypt_next(void *ctx, unsigned long session,
    unsigned char *params, unsigned long paramsLen,
    unsigned char *part, unsigned long partLen,
    unsigned char *output, unsigned long *outputLen, unsigned long end);
unsigned long haskoki_std_message_decrypt_final(void *ctx, unsigned long session);

unsigned long haskoki_std_message_sign_init(void *ctx, unsigned long session,
    unsigned long mechanism, unsigned char *params, unsigned long paramsLen,
    unsigned long key);
unsigned long haskoki_std_message_sign(void *ctx, unsigned long session,
    unsigned char *params, unsigned long paramsLen,
    unsigned char *input, unsigned long inputLen,
    unsigned char *signature, unsigned long *signatureLen);
unsigned long haskoki_std_message_sign_begin(void *ctx, unsigned long session,
    unsigned char *params, unsigned long paramsLen);
unsigned long haskoki_std_message_sign_next(void *ctx, unsigned long session,
    unsigned char *params, unsigned long paramsLen,
    unsigned char *part, unsigned long partLen,
    unsigned char *signature, unsigned long *signatureLen);
unsigned long haskoki_std_message_sign_final(void *ctx, unsigned long session);

unsigned long haskoki_std_message_verify_init(void *ctx, unsigned long session,
    unsigned long mechanism, unsigned char *params, unsigned long paramsLen,
    unsigned long key);
unsigned long haskoki_std_message_verify(void *ctx, unsigned long session,
    unsigned char *params, unsigned long paramsLen,
    unsigned char *input, unsigned long inputLen,
    unsigned char *signature, unsigned long signatureLen);
unsigned long haskoki_std_message_verify_begin(void *ctx, unsigned long session,
    unsigned char *params, unsigned long paramsLen);
unsigned long haskoki_std_message_verify_next(void *ctx, unsigned long session,
    unsigned char *params, unsigned long paramsLen,
    unsigned char *part, unsigned long partLen,
    unsigned char *signature, unsigned long signatureLen);
unsigned long haskoki_std_message_verify_final(void *ctx, unsigned long session);
```

- [ ] Insert the twenty `extern CK_RV std_*` declarations printed in this task in `cbits/exports.c` before `#include "abi_stubs.inc"`.

- [ ] Implement the twenty bodies below in `cbits/standard_surface.c`.

```c
CK_RV std_MessageEncryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM *pMechanism, CK_OBJECT_HANDLE hKey) {
  void *inst;
  CK_RV lr, rv;
  if (!haskoki_live_interval()) return CKR_CRYPTOKI_NOT_INITIALIZED;
  if (pMechanism == NULL) return CKR_ARGUMENTS_BAD;
  if (pMechanism->pParameter == NULL && pMechanism->ulParameterLen > 0) return CKR_ARGUMENTS_BAD;
  lr = haskoki_state_lock();
  if (lr != CKR_OK) return lr;
  inst = live_std();
  if (inst == NULL) {
    (void)haskoki_state_unlock();
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  rv = (CK_RV)haskoki_std_message_encrypt_init(inst, hSession, pMechanism->mechanism, (unsigned char *)pMechanism->pParameter, pMechanism->ulParameterLen, hKey);
  (void)haskoki_state_unlock();
  return rv;
}

CK_RV std_EncryptMessage(CK_SESSION_HANDLE hSession, void *pParameter, CK_ULONG ulParameterLen, CK_BYTE *pAssociatedData, CK_ULONG ulAssociatedDataLen, CK_BYTE *pPlaintext, CK_ULONG ulPlaintextLen, CK_BYTE *pCiphertext, CK_ULONG *pulCiphertextLen) {
  void *inst;
  CK_RV lr, rv;
  if (!haskoki_live_interval()) return CKR_CRYPTOKI_NOT_INITIALIZED;
  if (pulCiphertextLen == NULL) return CKR_ARGUMENTS_BAD;
  if (pParameter == NULL && ulParameterLen > 0) return CKR_ARGUMENTS_BAD;
  if (pAssociatedData == NULL && ulAssociatedDataLen > 0) return CKR_ARGUMENTS_BAD;
  if (pPlaintext == NULL && ulPlaintextLen > 0) return CKR_ARGUMENTS_BAD;
  lr = haskoki_state_lock();
  if (lr != CKR_OK) return lr;
  inst = live_std();
  if (inst == NULL) {
    (void)haskoki_state_unlock();
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  rv = (CK_RV)haskoki_std_message_encrypt(inst, hSession, (unsigned char *)pParameter, ulParameterLen, pAssociatedData, ulAssociatedDataLen, pPlaintext, ulPlaintextLen, pCiphertext, pulCiphertextLen);
  (void)haskoki_state_unlock();
  return rv;
}

CK_RV std_EncryptMessageBegin(CK_SESSION_HANDLE hSession, void *pParameter, CK_ULONG ulParameterLen, CK_BYTE *pAssociatedData, CK_ULONG ulAssociatedDataLen) {
  void *inst;
  CK_RV lr, rv;
  if (!haskoki_live_interval()) return CKR_CRYPTOKI_NOT_INITIALIZED;
  if (pParameter == NULL && ulParameterLen > 0) return CKR_ARGUMENTS_BAD;
  if (pAssociatedData == NULL && ulAssociatedDataLen > 0) return CKR_ARGUMENTS_BAD;
  lr = haskoki_state_lock();
  if (lr != CKR_OK) return lr;
  inst = live_std();
  if (inst == NULL) {
    (void)haskoki_state_unlock();
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  rv = (CK_RV)haskoki_std_message_encrypt_begin(inst, hSession, (unsigned char *)pParameter, ulParameterLen, pAssociatedData, ulAssociatedDataLen);
  (void)haskoki_state_unlock();
  return rv;
}

CK_RV std_EncryptMessageNext(CK_SESSION_HANDLE hSession, void *pParameter, CK_ULONG ulParameterLen, CK_BYTE *pPlaintextPart, CK_ULONG ulPlaintextPartLen, CK_BYTE *pCiphertextPart, CK_ULONG *pulCiphertextPartLen, CK_FLAGS flags) {
  void *inst;
  CK_RV lr, rv;
  if (!haskoki_live_interval()) return CKR_CRYPTOKI_NOT_INITIALIZED;
  if (pulCiphertextPartLen == NULL) return CKR_ARGUMENTS_BAD;
  if (pParameter == NULL && ulParameterLen > 0) return CKR_ARGUMENTS_BAD;
  if (pPlaintextPart == NULL && ulPlaintextPartLen > 0) return CKR_ARGUMENTS_BAD;
  if ((flags & ~CKF_END_OF_MESSAGE) != 0) return CKR_ARGUMENTS_BAD;
  lr = haskoki_state_lock();
  if (lr != CKR_OK) return lr;
  inst = live_std();
  if (inst == NULL) {
    (void)haskoki_state_unlock();
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  rv = (CK_RV)haskoki_std_message_encrypt_next(inst, hSession, (unsigned char *)pParameter, ulParameterLen, pPlaintextPart, ulPlaintextPartLen, pCiphertextPart, pulCiphertextPartLen, (flags & CKF_END_OF_MESSAGE) ? 1UL : 0UL);
  (void)haskoki_state_unlock();
  return rv;
}

CK_RV std_MessageEncryptFinal(CK_SESSION_HANDLE hSession) {
  void *inst;
  CK_RV lr, rv;
  if (!haskoki_live_interval()) return CKR_CRYPTOKI_NOT_INITIALIZED;
  lr = haskoki_state_lock();
  if (lr != CKR_OK) return lr;
  inst = live_std();
  if (inst == NULL) {
    (void)haskoki_state_unlock();
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  rv = (CK_RV)haskoki_std_message_encrypt_final(inst, hSession);
  (void)haskoki_state_unlock();
  return rv;
}

CK_RV std_MessageDecryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM *pMechanism, CK_OBJECT_HANDLE hKey) {
  void *inst;
  CK_RV lr, rv;
  if (!haskoki_live_interval()) return CKR_CRYPTOKI_NOT_INITIALIZED;
  if (pMechanism == NULL) return CKR_ARGUMENTS_BAD;
  if (pMechanism->pParameter == NULL && pMechanism->ulParameterLen > 0) return CKR_ARGUMENTS_BAD;
  lr = haskoki_state_lock();
  if (lr != CKR_OK) return lr;
  inst = live_std();
  if (inst == NULL) {
    (void)haskoki_state_unlock();
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  rv = (CK_RV)haskoki_std_message_decrypt_init(inst, hSession, pMechanism->mechanism, (unsigned char *)pMechanism->pParameter, pMechanism->ulParameterLen, hKey);
  (void)haskoki_state_unlock();
  return rv;
}

CK_RV std_DecryptMessage(CK_SESSION_HANDLE hSession, void *pParameter, CK_ULONG ulParameterLen, CK_BYTE *pAssociatedData, CK_ULONG ulAssociatedDataLen, CK_BYTE *pCiphertext, CK_ULONG ulCiphertextLen, CK_BYTE *pPlaintext, CK_ULONG *pulPlaintextLen) {
  void *inst;
  CK_RV lr, rv;
  if (!haskoki_live_interval()) return CKR_CRYPTOKI_NOT_INITIALIZED;
  if (pulPlaintextLen == NULL) return CKR_ARGUMENTS_BAD;
  if (pParameter == NULL && ulParameterLen > 0) return CKR_ARGUMENTS_BAD;
  if (pAssociatedData == NULL && ulAssociatedDataLen > 0) return CKR_ARGUMENTS_BAD;
  if (pCiphertext == NULL && ulCiphertextLen > 0) return CKR_ARGUMENTS_BAD;
  lr = haskoki_state_lock();
  if (lr != CKR_OK) return lr;
  inst = live_std();
  if (inst == NULL) {
    (void)haskoki_state_unlock();
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  rv = (CK_RV)haskoki_std_message_decrypt(inst, hSession, (unsigned char *)pParameter, ulParameterLen, pAssociatedData, ulAssociatedDataLen, pCiphertext, ulCiphertextLen, pPlaintext, pulPlaintextLen);
  (void)haskoki_state_unlock();
  return rv;
}

CK_RV std_DecryptMessageBegin(CK_SESSION_HANDLE hSession, void *pParameter, CK_ULONG ulParameterLen, CK_BYTE *pAssociatedData, CK_ULONG ulAssociatedDataLen) {
  void *inst;
  CK_RV lr, rv;
  if (!haskoki_live_interval()) return CKR_CRYPTOKI_NOT_INITIALIZED;
  if (pParameter == NULL && ulParameterLen > 0) return CKR_ARGUMENTS_BAD;
  if (pAssociatedData == NULL && ulAssociatedDataLen > 0) return CKR_ARGUMENTS_BAD;
  lr = haskoki_state_lock();
  if (lr != CKR_OK) return lr;
  inst = live_std();
  if (inst == NULL) {
    (void)haskoki_state_unlock();
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  rv = (CK_RV)haskoki_std_message_decrypt_begin(inst, hSession, (unsigned char *)pParameter, ulParameterLen, pAssociatedData, ulAssociatedDataLen);
  (void)haskoki_state_unlock();
  return rv;
}

CK_RV std_DecryptMessageNext(CK_SESSION_HANDLE hSession, void *pParameter, CK_ULONG ulParameterLen, CK_BYTE *pCiphertextPart, CK_ULONG ulCiphertextPartLen, CK_BYTE *pPlaintextPart, CK_ULONG *pulPlaintextPartLen, CK_FLAGS flags) {
  void *inst;
  CK_RV lr, rv;
  if (!haskoki_live_interval()) return CKR_CRYPTOKI_NOT_INITIALIZED;
  if (pulPlaintextPartLen == NULL) return CKR_ARGUMENTS_BAD;
  if (pParameter == NULL && ulParameterLen > 0) return CKR_ARGUMENTS_BAD;
  if (pCiphertextPart == NULL && ulCiphertextPartLen > 0) return CKR_ARGUMENTS_BAD;
  if ((flags & ~CKF_END_OF_MESSAGE) != 0) return CKR_ARGUMENTS_BAD;
  lr = haskoki_state_lock();
  if (lr != CKR_OK) return lr;
  inst = live_std();
  if (inst == NULL) {
    (void)haskoki_state_unlock();
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  rv = (CK_RV)haskoki_std_message_decrypt_next(inst, hSession, (unsigned char *)pParameter, ulParameterLen, pCiphertextPart, ulCiphertextPartLen, pPlaintextPart, pulPlaintextPartLen, (flags & CKF_END_OF_MESSAGE) ? 1UL : 0UL);
  (void)haskoki_state_unlock();
  return rv;
}

CK_RV std_MessageDecryptFinal(CK_SESSION_HANDLE hSession) {
  void *inst;
  CK_RV lr, rv;
  if (!haskoki_live_interval()) return CKR_CRYPTOKI_NOT_INITIALIZED;
  lr = haskoki_state_lock();
  if (lr != CKR_OK) return lr;
  inst = live_std();
  if (inst == NULL) {
    (void)haskoki_state_unlock();
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  rv = (CK_RV)haskoki_std_message_decrypt_final(inst, hSession);
  (void)haskoki_state_unlock();
  return rv;
}

CK_RV std_MessageSignInit(CK_SESSION_HANDLE hSession, CK_MECHANISM *pMechanism, CK_OBJECT_HANDLE hKey) {
  void *inst;
  CK_RV lr, rv;
  if (!haskoki_live_interval()) return CKR_CRYPTOKI_NOT_INITIALIZED;
  if (pMechanism == NULL) return CKR_ARGUMENTS_BAD;
  if (pMechanism->pParameter == NULL && pMechanism->ulParameterLen > 0) return CKR_ARGUMENTS_BAD;
  lr = haskoki_state_lock();
  if (lr != CKR_OK) return lr;
  inst = live_std();
  if (inst == NULL) {
    (void)haskoki_state_unlock();
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  rv = (CK_RV)haskoki_std_message_sign_init(inst, hSession, pMechanism->mechanism, (unsigned char *)pMechanism->pParameter, pMechanism->ulParameterLen, hKey);
  (void)haskoki_state_unlock();
  return rv;
}

CK_RV std_SignMessage(CK_SESSION_HANDLE hSession, void *pParameter, CK_ULONG ulParameterLen, CK_BYTE *pData, CK_ULONG ulDataLen, CK_BYTE *pSignature, CK_ULONG *pulSignatureLen) {
  void *inst;
  CK_RV lr, rv;
  if (!haskoki_live_interval()) return CKR_CRYPTOKI_NOT_INITIALIZED;
  if (pulSignatureLen == NULL) return CKR_ARGUMENTS_BAD;
  if (pParameter == NULL && ulParameterLen > 0) return CKR_ARGUMENTS_BAD;
  if (pData == NULL && ulDataLen > 0) return CKR_ARGUMENTS_BAD;
  lr = haskoki_state_lock();
  if (lr != CKR_OK) return lr;
  inst = live_std();
  if (inst == NULL) {
    (void)haskoki_state_unlock();
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  rv = (CK_RV)haskoki_std_message_sign(inst, hSession, (unsigned char *)pParameter, ulParameterLen, pData, ulDataLen, pSignature, pulSignatureLen);
  (void)haskoki_state_unlock();
  return rv;
}

CK_RV std_SignMessageBegin(CK_SESSION_HANDLE hSession, void *pParameter, CK_ULONG ulParameterLen) {
  void *inst;
  CK_RV lr, rv;
  if (!haskoki_live_interval()) return CKR_CRYPTOKI_NOT_INITIALIZED;
  if (pParameter == NULL && ulParameterLen > 0) return CKR_ARGUMENTS_BAD;
  lr = haskoki_state_lock();
  if (lr != CKR_OK) return lr;
  inst = live_std();
  if (inst == NULL) {
    (void)haskoki_state_unlock();
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  rv = (CK_RV)haskoki_std_message_sign_begin(inst, hSession, (unsigned char *)pParameter, ulParameterLen);
  (void)haskoki_state_unlock();
  return rv;
}

CK_RV std_SignMessageNext(CK_SESSION_HANDLE hSession, void *pParameter, CK_ULONG ulParameterLen, CK_BYTE *pDataPart, CK_ULONG ulDataPartLen, CK_BYTE *pSignature, CK_ULONG *pulSignatureLen) {
  void *inst;
  CK_RV lr, rv;
  if (!haskoki_live_interval()) return CKR_CRYPTOKI_NOT_INITIALIZED;
  if (pParameter == NULL && ulParameterLen > 0) return CKR_ARGUMENTS_BAD;
  if (pDataPart == NULL && ulDataPartLen > 0) return CKR_ARGUMENTS_BAD;
  lr = haskoki_state_lock();
  if (lr != CKR_OK) return lr;
  inst = live_std();
  if (inst == NULL) {
    (void)haskoki_state_unlock();
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  rv = (CK_RV)haskoki_std_message_sign_next(inst, hSession, (unsigned char *)pParameter, ulParameterLen, pDataPart, ulDataPartLen, pSignature, pulSignatureLen);
  (void)haskoki_state_unlock();
  return rv;
}

CK_RV std_MessageSignFinal(CK_SESSION_HANDLE hSession) {
  void *inst;
  CK_RV lr, rv;
  if (!haskoki_live_interval()) return CKR_CRYPTOKI_NOT_INITIALIZED;
  lr = haskoki_state_lock();
  if (lr != CKR_OK) return lr;
  inst = live_std();
  if (inst == NULL) {
    (void)haskoki_state_unlock();
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  rv = (CK_RV)haskoki_std_message_sign_final(inst, hSession);
  (void)haskoki_state_unlock();
  return rv;
}

CK_RV std_MessageVerifyInit(CK_SESSION_HANDLE hSession, CK_MECHANISM *pMechanism, CK_OBJECT_HANDLE hKey) {
  void *inst;
  CK_RV lr, rv;
  if (!haskoki_live_interval()) return CKR_CRYPTOKI_NOT_INITIALIZED;
  if (pMechanism == NULL) return CKR_ARGUMENTS_BAD;
  if (pMechanism->pParameter == NULL && pMechanism->ulParameterLen > 0) return CKR_ARGUMENTS_BAD;
  lr = haskoki_state_lock();
  if (lr != CKR_OK) return lr;
  inst = live_std();
  if (inst == NULL) {
    (void)haskoki_state_unlock();
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  rv = (CK_RV)haskoki_std_message_verify_init(inst, hSession, pMechanism->mechanism, (unsigned char *)pMechanism->pParameter, pMechanism->ulParameterLen, hKey);
  (void)haskoki_state_unlock();
  return rv;
}

CK_RV std_VerifyMessage(CK_SESSION_HANDLE hSession, void *pParameter, CK_ULONG ulParameterLen, CK_BYTE *pData, CK_ULONG ulDataLen, CK_BYTE *pSignature, CK_ULONG ulSignatureLen) {
  void *inst;
  CK_RV lr, rv;
  if (!haskoki_live_interval()) return CKR_CRYPTOKI_NOT_INITIALIZED;
  if (pParameter == NULL && ulParameterLen > 0) return CKR_ARGUMENTS_BAD;
  if (pData == NULL && ulDataLen > 0) return CKR_ARGUMENTS_BAD;
  if (pSignature == NULL && ulSignatureLen > 0) return CKR_ARGUMENTS_BAD;
  lr = haskoki_state_lock();
  if (lr != CKR_OK) return lr;
  inst = live_std();
  if (inst == NULL) {
    (void)haskoki_state_unlock();
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  rv = (CK_RV)haskoki_std_message_verify(inst, hSession, (unsigned char *)pParameter, ulParameterLen, pData, ulDataLen, pSignature, ulSignatureLen);
  (void)haskoki_state_unlock();
  return rv;
}

CK_RV std_VerifyMessageBegin(CK_SESSION_HANDLE hSession, void *pParameter, CK_ULONG ulParameterLen) {
  void *inst;
  CK_RV lr, rv;
  if (!haskoki_live_interval()) return CKR_CRYPTOKI_NOT_INITIALIZED;
  if (pParameter == NULL && ulParameterLen > 0) return CKR_ARGUMENTS_BAD;
  lr = haskoki_state_lock();
  if (lr != CKR_OK) return lr;
  inst = live_std();
  if (inst == NULL) {
    (void)haskoki_state_unlock();
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  rv = (CK_RV)haskoki_std_message_verify_begin(inst, hSession, (unsigned char *)pParameter, ulParameterLen);
  (void)haskoki_state_unlock();
  return rv;
}

CK_RV std_VerifyMessageNext(CK_SESSION_HANDLE hSession, void *pParameter, CK_ULONG ulParameterLen, CK_BYTE *pDataPart, CK_ULONG ulDataPartLen, CK_BYTE *pSignature, CK_ULONG ulSignatureLen) {
  void *inst;
  CK_RV lr, rv;
  if (!haskoki_live_interval()) return CKR_CRYPTOKI_NOT_INITIALIZED;
  if (pParameter == NULL && ulParameterLen > 0) return CKR_ARGUMENTS_BAD;
  if (pDataPart == NULL && ulDataPartLen > 0) return CKR_ARGUMENTS_BAD;
  if (pSignature == NULL && ulSignatureLen > 0) return CKR_ARGUMENTS_BAD;
  lr = haskoki_state_lock();
  if (lr != CKR_OK) return lr;
  inst = live_std();
  if (inst == NULL) {
    (void)haskoki_state_unlock();
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  rv = (CK_RV)haskoki_std_message_verify_next(inst, hSession, (unsigned char *)pParameter, ulParameterLen, pDataPart, ulDataPartLen, pSignature, ulSignatureLen);
  (void)haskoki_state_unlock();
  return rv;
}

CK_RV std_MessageVerifyFinal(CK_SESSION_HANDLE hSession) {
  void *inst;
  CK_RV lr, rv;
  if (!haskoki_live_interval()) return CKR_CRYPTOKI_NOT_INITIALIZED;
  lr = haskoki_state_lock();
  if (lr != CKR_OK) return lr;
  inst = live_std();
  if (inst == NULL) {
    (void)haskoki_state_unlock();
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  rv = (CK_RV)haskoki_std_message_verify_final(inst, hSession);
  (void)haskoki_state_unlock();
  return rv;
}

```

All guard refusals are plain returns. In particular, never invoke `refuse_null_arg`, `refuseArgsTerminate`, or `terminateSlot` from these routes. The absent Sign length pointer is not a guard: it must reach the continuation export without touching the output buffer. Flags two reject before locking; zero and `CKF_END_OF_MESSAGE` become scalar zero and one.

- [ ] Compile the probe after implementation.

```sh
cc -std=c11 -O2 -g -Wall -Wextra -Werror -ffunction-sections -fdata-sections -Ispec/vendor -Icbits /tmp/haskoki-message-surface/probe.c -Wl,--gc-sections -lpthread -o /tmp/haskoki-message-surface/probe
```

Expected: exit zero, no diagnostics; pinned `CK_C_*` assignments type-check every definition.

- [ ] Run the probe.

```sh
/tmp/haskoki-message-surface/probe
```

Expected: the exact PASS line above; each of twenty entries exercises lifecycle, both lock-error forms, disappearing instance, export result forwarding, and one unlock after a successful lock; every listed guard wins over both session values.

- [ ] Build the foreign library so the compiler also checks the generated Haskell stub header.

```sh
cabal build flib:haskoki
```

Expected: exit zero with the generated-header path; no prototype, width, or arity warnings.

- [ ] Commit Task 3.

```sh
git add cbits/standard_surface.c cbits/exports.c
git commit -m "feat: route C message boundaries per routing spec sections 3.1 3.3 and 4"
```

### Task 4: Register `routed300` and regenerate only the intended artifact

**Files:** Modify `scripts/generate-abi.py`; regenerate/test `cbits/abi_stubs.inc`; temporary test `/tmp/haskoki-message-registration.sh`; compare without modifying `spec/abi-inventory.json`, `spec/abi-reconciliation.json`, `cbits/abi_generated.h`, `spec/sources.lock.json`, `spec/vendor/pkcs11.h`, `spec/mechanisms.json`, and `cbits/mech_catalog.inc`.

**Interfaces:** Consumes the twenty exact `CK_RV std_*` signatures from Task 3. Produces the existing `HASKOKI_FILL_300_NEW(T)` macro with the explicit mappings below; `fill_30(CK_FUNCTION_LIST_3_0 *t, unsigned char minor, haskoki_fn_t *legacy)` and `do_fill(void)` consume it unchanged. No new Haskell interface is introduced.

- [ ] Write `/tmp/haskoki-message-registration.sh` with this registration assertion.

```sh
python3 - <<'PYCODE'
from pathlib import Path
import re
routes = {
    "C_MessageEncryptInit": "std_MessageEncryptInit",
    "C_EncryptMessage": "std_EncryptMessage",
    "C_EncryptMessageBegin": "std_EncryptMessageBegin",
    "C_EncryptMessageNext": "std_EncryptMessageNext",
    "C_MessageEncryptFinal": "std_MessageEncryptFinal",
    "C_MessageDecryptInit": "std_MessageDecryptInit",
    "C_DecryptMessage": "std_DecryptMessage",
    "C_DecryptMessageBegin": "std_DecryptMessageBegin",
    "C_DecryptMessageNext": "std_DecryptMessageNext",
    "C_MessageDecryptFinal": "std_MessageDecryptFinal",
    "C_MessageSignInit": "std_MessageSignInit",
    "C_SignMessage": "std_SignMessage",
    "C_SignMessageBegin": "std_SignMessageBegin",
    "C_SignMessageNext": "std_SignMessageNext",
    "C_MessageSignFinal": "std_MessageSignFinal",
    "C_MessageVerifyInit": "std_MessageVerifyInit",
    "C_VerifyMessage": "std_VerifyMessage",
    "C_VerifyMessageBegin": "std_VerifyMessageBegin",
    "C_VerifyMessageNext": "std_VerifyMessageNext",
    "C_MessageVerifyFinal": "std_MessageVerifyFinal",
}
generator = Path('scripts/generate-abi.py').read_text()
block = generator.split('    routed300 = ', 1)[1].split('    routed320 = ', 1)[0]
for public, target in routes.items():
    assert re.search(r'["\']' + public + r'["\']\s*:\s*["\']' + target + r'["\']', block), public + ' registration missing'
inc = Path('cbits/abi_stubs.inc').read_text()
for public, target in routes.items():
    assert not re.search(r'\b' + 'x30_' + public + r'\s*\(', inc), public + ' still has stub body'
    assert re.search(r'\(T\)->' + public + r'\s*=\s*' + target + r'\s*;', inc), public + ' assignment missing'
assert '"C_SessionCancel": "std_SessionCancel"' in block
print('PASS: twenty message registrations and assignments; no corresponding stub bodies')
PYCODE
```

- [ ] Run the registration assertion before editing the generator.

```sh
bash /tmp/haskoki-message-registration.sh
```

Expected failure: `C_MessageEncryptInit registration missing`. Preserve that observed output; after registration but before regeneration it must instead detect a surviving stub body.

- [ ] Replace only the `routed300` dictionary in `scripts/generate-abi.py` with this code.

```python
    routed300 = {
        "C_SessionCancel": "std_SessionCancel",
        "C_MessageEncryptInit": "std_MessageEncryptInit",
        "C_EncryptMessage": "std_EncryptMessage",
        "C_EncryptMessageBegin": "std_EncryptMessageBegin",
        "C_EncryptMessageNext": "std_EncryptMessageNext",
        "C_MessageEncryptFinal": "std_MessageEncryptFinal",
        "C_MessageDecryptInit": "std_MessageDecryptInit",
        "C_DecryptMessage": "std_DecryptMessage",
        "C_DecryptMessageBegin": "std_DecryptMessageBegin",
        "C_DecryptMessageNext": "std_DecryptMessageNext",
        "C_MessageDecryptFinal": "std_MessageDecryptFinal",
        "C_MessageSignInit": "std_MessageSignInit",
        "C_SignMessage": "std_SignMessage",
        "C_SignMessageBegin": "std_SignMessageBegin",
        "C_SignMessageNext": "std_SignMessageNext",
        "C_MessageSignFinal": "std_MessageSignFinal",
        "C_MessageVerifyInit": "std_MessageVerifyInit",
        "C_VerifyMessage": "std_VerifyMessage",
        "C_VerifyMessageBegin": "std_VerifyMessageBegin",
        "C_VerifyMessageNext": "std_VerifyMessageNext",
        "C_MessageVerifyFinal": "std_MessageVerifyFinal",
    }
```

- [ ] Regenerate the ABI artifacts using the generator.

```sh
python3 scripts/generate-abi.py
```

Expected: `generate-abi: PASS: 68/92/92/104 functions from locked sources; reconciliation matched=104 added=0 removed=0 aliased=0`. Never edit `cbits/abi_stubs.inc` directly.

- [ ] Run the registration assertion after regeneration.

```sh
bash /tmp/haskoki-message-registration.sh
```

Expected: twenty std assignments, no corresponding `x30_*` bodies, and the existing SessionCancel mapping retained.

- [ ] Verify all other generated outputs and catalog inputs are byte-identical to the task's starting commit.

```sh
python3 - <<'PYCODE'
import json, subprocess
from pathlib import Path
paths = ['spec/abi-inventory.json', 'spec/abi-reconciliation.json',
         'cbits/abi_generated.h', 'spec/sources.lock.json', 'spec/vendor/pkcs11.h',
         'spec/mechanisms.json', 'cbits/mech_catalog.inc']
for name in paths:
    old = subprocess.check_output(['git','show','HEAD:' + name])
    assert old == Path(name).read_bytes(), name + ' changed unexpectedly'
inv = json.loads(Path('spec/abi-inventory.json').read_text())['interfaces']
assert [inv[v]['function_count'] for v in ['2.40','3.0','3.1','3.2']] == [68,92,92,104]
assert inv['3.1']['layout'] == 'CK_FUNCTION_LIST_3_0'
old = subprocess.check_output(['git','show','HEAD:scripts/generate-abi.py']).decode()
new = Path('scripts/generate-abi.py').read_text()
def outside_registration(text):
    head, rest = text.split('    routed300 = ',1)
    return head + rest.split('    routed320 = ',1)[1]
assert outside_registration(old) == outside_registration(new)
print('PASS: other outputs, inventories, catalog, and unrelated routes unchanged')
PYCODE
```

- [ ] Build the table translation unit and foreign library.

```sh
cabal build flib:haskoki
```

Expected: all three versioned tables link against the twenty real bodies; the 2.40 table is unchanged.

- [ ] Commit Task 4.

```sh
git add scripts/generate-abi.py cbits/abi_stubs.inc
git commit -m "feat: register message tables per routing spec section 3.5"
```

### Task 5: Independent table consumer and script inclusion

**Files:** Create/test `tests/c/message_routed.c`; modify/test `scripts/test-consumers.sh` and `scripts/test-proxy-parity.sh`. Temporary test `/tmp/haskoki-message-scenario-inclusion.sh`; temporary compiler output `/tmp/haskoki-message-routed`.

**Interfaces:** Consumes the pinned `CK_C_GetInterface` discovery typedef and all twenty `CK_C_MessageEncryptInit` through `CK_C_MessageVerifyFinal` table fields with the public prototypes in Task 3. Produces `int main(int argc, char **argv)` with exactly one module-path argument, process exit zero only after all assertions pass, and deterministic `message:` entry/leg/version records. Internal `MessageApi` copies typed pointers from the correct table layout; no provider header or direct export is used. Shell drivers consume the complete sorted `SCEN_LIST` and run the same binary in both topologies. No Haskell interface is added.

- [ ] Write `/tmp/haskoki-message-scenario-inclusion.sh` with this scenario-inclusion test.

```sh
python3 - <<'PYCODE'
from pathlib import Path
for script in ['scripts/test-consumers.sh','scripts/test-proxy-parity.sh']:
    source = Path(script).read_text()
    assert '[ -f tests/c/message_routed.c ]' in source, script + ' lacks required scenario check'
    assert 'for scen in tests/c/consumer_*.c tests/c/message_routed.c' in source, script + ' omits message scenario'
    assert 'grep -nE' in source and '$SCEN_LIST' in source, script + ' lacks complete independence guard'
assert Path('tests/c/message_routed.c').is_file(), 'message consumer absent'
print('PASS: message scenario required and included in both source lists')
PYCODE
```

- [ ] Run the scenario-inclusion test before changing the scripts.

```sh
bash /tmp/haskoki-message-scenario-inclusion.sh
```

Expected failure: `scripts/test-consumers.sh lacks required scenario check`. Keep that output as the observed failure.

- [ ] Replace source-list discovery and the old independence block in each driver with the following block, immediately after its `fail()` definition and before its build/proxy checks.

```sh
[ -f tests/c/message_routed.c ] || fail "message consumer missing"
SCEN_LIST=$(
  for scen in tests/c/consumer_*.c tests/c/message_routed.c; do
    [ -f "$scen" ] && printf '%s\n' "$scen"
  done | LC_ALL=C sort -u
)
[ -n "$SCEN_LIST" ] || fail "consumer scenario list empty"
[ "$(printf '%s\n' "$SCEN_LIST" | grep -cx 'tests/c/message_routed.c')" -eq 1 ] \
  || fail "message consumer must occur exactly once"
for scen in $SCEN_LIST; do
  if grep -nE 'abi_generated|abi_stubs|abi-inventory' "$scen"; then
    fail "consumer independence violated: $scen"
  fi
done
```

Retain both scripts' existing compiler flags, module discovery, proxy daemon/shim provenance, and transcript normalization. Remove each old `SCEN_LIST=$(ls tests/c/consumer_*.c 2>/dev/null | sort)` reassignment so this list remains authoritative. Do not add a new driver or alter the release-evidence manifest.

- [ ] Write the consumer scaffold below to `tests/c/message_routed.c`, including the declarations of `boundary_legs`, `encrypt_legs`, `decrypt_legs`, `sign_legs`, `verify_legs`, `extra_legs`, and `oversize_legs` before `main`. Their complete bodies are supplied in subsequent steps; the first compile deliberately observes the missing definitions.

```c
#define _POSIX_C_SOURCE 200809L
#define CK_PTR *
#define CK_DECLARE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType (*name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType (*name)
#include "pkcs11.h"
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int failures, proxy;
static unsigned minor;
static CK_SLOT_ID tokenSlot;
static char configPath[256];
static CK_BYTE aesBytes[16] = {0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c};
static CK_BYTE iv[16] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
static CK_BYTE plain[16] = {0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a};
static CK_BYTE cipher[16] = {0x76,0x49,0xab,0xac,0x81,0x19,0xb2,0x46,0xce,0xe9,0x8e,0x9b,0x12,0xe9,0x19,0x7d};
static CK_BYTE macBytes[20] = {0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b};
static CK_BYTE witness[32] = {0xb0,0x34,0x4c,0x61,0xd8,0xdb,0x38,0x53,0x5c,0xa8,0xaf,0xce,0xaf,0x0b,0xf1,0x2b,0x88,0x1d,0xc2,0x00,0xc9,0x83,0x3d,0xa7,0x26,0xe9,0x37,0x6c,0x2e,0x32,0xcf,0xf7};
static CK_BYTE textBytes[8] = {'H','i',' ','T','h','e','r','e'};
static CK_MECHANISM cbc = {CKM_AES_CBC, iv, sizeof(iv)};
static CK_MECHANISM padded = {CKM_AES_CBC_PAD, iv, sizeof(iv)};
static CK_MECHANISM hmac = {CKM_SHA256_HMAC, NULL, 0};

typedef struct {
  CK_C_Initialize C_Initialize;
  CK_C_Finalize C_Finalize;
  CK_C_GetSlotList C_GetSlotList;
  CK_C_OpenSession C_OpenSession;
  CK_C_CloseSession C_CloseSession;
  CK_C_CreateObject C_CreateObject;
  CK_C_EncryptInit C_EncryptInit;
  CK_C_Encrypt C_Encrypt;
  CK_C_EncryptUpdate C_EncryptUpdate;
  CK_C_DecryptInit C_DecryptInit;
  CK_C_Decrypt C_Decrypt;
  CK_C_DecryptUpdate C_DecryptUpdate;
  CK_C_SignInit C_SignInit;
  CK_C_Sign C_Sign;
  CK_C_VerifyInit C_VerifyInit;
  CK_C_Verify C_Verify;
  CK_C_MessageEncryptInit C_MessageEncryptInit;
  CK_C_EncryptMessage C_EncryptMessage;
  CK_C_EncryptMessageBegin C_EncryptMessageBegin;
  CK_C_EncryptMessageNext C_EncryptMessageNext;
  CK_C_MessageEncryptFinal C_MessageEncryptFinal;
  CK_C_MessageDecryptInit C_MessageDecryptInit;
  CK_C_DecryptMessage C_DecryptMessage;
  CK_C_DecryptMessageBegin C_DecryptMessageBegin;
  CK_C_DecryptMessageNext C_DecryptMessageNext;
  CK_C_MessageDecryptFinal C_MessageDecryptFinal;
  CK_C_MessageSignInit C_MessageSignInit;
  CK_C_SignMessage C_SignMessage;
  CK_C_SignMessageBegin C_SignMessageBegin;
  CK_C_SignMessageNext C_SignMessageNext;
  CK_C_MessageSignFinal C_MessageSignFinal;
  CK_C_MessageVerifyInit C_MessageVerifyInit;
  CK_C_VerifyMessage C_VerifyMessage;
  CK_C_VerifyMessageBegin C_VerifyMessageBegin;
  CK_C_VerifyMessageNext C_VerifyMessageNext;
  CK_C_MessageVerifyFinal C_MessageVerifyFinal;
} MessageApi;
typedef struct { CK_SESSION_HANDLE session; CK_OBJECT_HANDLE aes, mac, noSign, noVerify; } Fixture;
typedef struct { CK_BYTE bytes[66]; CK_ULONG length; } Output;

static void check(const char *entry, const char *leg, int good) {
  printf("message:%s/%s/3.%u check=%s\n",entry,leg,minor,good ? "ok" : "FAIL");
  if (!good) ++failures;
}
static void rv(const char *entry, const char *leg, CK_RV got, CK_RV want) {
  printf("message:%s/%s/3.%u rv=0x%lx expected=0x%lx\n",entry,leg,minor,got,want);
  if (got != want) ++failures;
}
static void reset_output(Output *o, CK_ULONG n) { memset(o->bytes,0xa5,sizeof(o->bytes)); o->length=n; }
static void output_length(const char *entry, const char *leg, const Output *o, CK_ULONG want) {
  printf("message:%s/%s/3.%u length=%lu expected=%lu\n",entry,leg,minor,o->length,want);
  if (o->length != want) ++failures;
}
static void untouched(const char *entry, const char *leg, const Output *o, CK_ULONG n) {
  int good = o->length == n;
  for (size_t i=0;i<sizeof(o->bytes);++i) good &= o->bytes[i] == 0xa5;
  check(entry,leg,good);
}
static void output_bytes(const char *entry, const char *leg, const Output *o, const CK_BYTE *want, CK_ULONG n) {
  int good = o->length == n && n <= 64;
  printf("message:%s/%s/3.%u hex=",entry,leg,minor);
  for (CK_ULONG i=0;i<o->length && i<64;++i) printf("%02x",o->bytes[i+1]);
  printf("\n");
  if (n <= 64) good &= memcmp(o->bytes+1,want,n) == 0;
  good &= o->bytes[0] == 0xa5;
  for (size_t i=(size_t)n+1;i<sizeof(o->bytes);++i) good &= o->bytes[i] == 0xa5;
  check(entry,leg,good);
}
static CK_OBJECT_HANDLE make_key(MessageApi *a, CK_SESSION_HANDLE session, CK_KEY_TYPE type, CK_BYTE *value, CK_ULONG n, CK_BBOOL enc, CK_BBOOL dec, CK_BBOOL sign, CK_BBOOL verify) {
  CK_OBJECT_CLASS cls=CKO_SECRET_KEY;
  CK_BBOOL no=CK_FALSE;
  CK_OBJECT_HANDLE key=0;
  CK_ATTRIBUTE attrs[] = {
    {CKA_CLASS,&cls,sizeof(cls)}, {CKA_KEY_TYPE,&type,sizeof(type)},
    {CKA_TOKEN,&no,sizeof(no)}, {CKA_PRIVATE,&no,sizeof(no)},
    {CKA_VALUE,value,n}, {CKA_ENCRYPT,&enc,sizeof(enc)},
    {CKA_DECRYPT,&dec,sizeof(dec)}, {CKA_SIGN,&sign,sizeof(sign)},
    {CKA_VERIFY,&verify,sizeof(verify)}
  };
  CK_RV result=a->C_CreateObject(session,attrs,sizeof(attrs)/sizeof(attrs[0]),&key);
  rv("fixture","create-key",result,CKR_OK);
  if (result != CKR_OK) exit(1);
  return key;
}
static Fixture fixture(MessageApi *a) {
  Fixture f={0};
  CK_RV result=a->C_OpenSession(tokenSlot,CKF_SERIAL_SESSION|CKF_RW_SESSION,NULL,NULL,&f.session);
  rv("fixture","open",result,CKR_OK);
  if (result != CKR_OK) exit(1);
  f.aes=make_key(a,f.session,CKK_AES,aesBytes,16,CK_TRUE,CK_TRUE,CK_FALSE,CK_FALSE);
  f.mac=make_key(a,f.session,CKK_GENERIC_SECRET,macBytes,20,CK_FALSE,CK_FALSE,CK_TRUE,CK_TRUE);
  f.noSign=make_key(a,f.session,CKK_GENERIC_SECRET,macBytes,20,CK_FALSE,CK_FALSE,CK_FALSE,CK_TRUE);
  f.noVerify=make_key(a,f.session,CKK_GENERIC_SECRET,macBytes,20,CK_FALSE,CK_FALSE,CK_TRUE,CK_FALSE);
  return f;
}
static void close_fixture(MessageApi *a, Fixture f) { rv("fixture","close",a->C_CloseSession(f.session),CKR_OK); }
static void configure(void) {
  char path[]="/tmp/haskoki-message-config-XXXXXX";
  const char body[]="schema_version = 1\nprofile = \"real-crypto\"\n[storage]\nkind = \"memory\"\n[engine]\nkind = \"openssl\"\nallow_synthetic_fallback = false\nprivate_library_context = true\n[trace]\nenabled = false\n";
  int fd=mkstemp(path);
  if (fd<0 || write(fd,body,sizeof(body)-1)!=(ssize_t)(sizeof(body)-1)) exit(2);
  close(fd);
  snprintf(configPath,sizeof(configPath),"%s",path);
  if (setenv("HASKOKI_CONFIG",configPath,1)!=0) exit(2);
}
static MessageApi read_common(CK_FUNCTION_LIST_3_0 *table) {
  MessageApi a;
  a.C_Initialize=table->C_Initialize;
  a.C_Finalize=table->C_Finalize;
  a.C_GetSlotList=table->C_GetSlotList;
  a.C_OpenSession=table->C_OpenSession;
  a.C_CloseSession=table->C_CloseSession;
  a.C_CreateObject=table->C_CreateObject;
  a.C_EncryptInit=table->C_EncryptInit;
  a.C_Encrypt=table->C_Encrypt;
  a.C_EncryptUpdate=table->C_EncryptUpdate;
  a.C_DecryptInit=table->C_DecryptInit;
  a.C_Decrypt=table->C_Decrypt;
  a.C_DecryptUpdate=table->C_DecryptUpdate;
  a.C_SignInit=table->C_SignInit;
  a.C_Sign=table->C_Sign;
  a.C_VerifyInit=table->C_VerifyInit;
  a.C_Verify=table->C_Verify;
  a.C_MessageEncryptInit=table->C_MessageEncryptInit;
  a.C_EncryptMessage=table->C_EncryptMessage;
  a.C_EncryptMessageBegin=table->C_EncryptMessageBegin;
  a.C_EncryptMessageNext=table->C_EncryptMessageNext;
  a.C_MessageEncryptFinal=table->C_MessageEncryptFinal;
  a.C_MessageDecryptInit=table->C_MessageDecryptInit;
  a.C_DecryptMessage=table->C_DecryptMessage;
  a.C_DecryptMessageBegin=table->C_DecryptMessageBegin;
  a.C_DecryptMessageNext=table->C_DecryptMessageNext;
  a.C_MessageDecryptFinal=table->C_MessageDecryptFinal;
  a.C_MessageSignInit=table->C_MessageSignInit;
  a.C_SignMessage=table->C_SignMessage;
  a.C_SignMessageBegin=table->C_SignMessageBegin;
  a.C_SignMessageNext=table->C_SignMessageNext;
  a.C_MessageSignFinal=table->C_MessageSignFinal;
  a.C_MessageVerifyInit=table->C_MessageVerifyInit;
  a.C_VerifyMessage=table->C_VerifyMessage;
  a.C_VerifyMessageBegin=table->C_VerifyMessageBegin;
  a.C_VerifyMessageNext=table->C_VerifyMessageNext;
  a.C_MessageVerifyFinal=table->C_MessageVerifyFinal;
  check("C_MessageEncryptInit","slot-present",a.C_MessageEncryptInit != NULL);
  check("C_EncryptMessage","slot-present",a.C_EncryptMessage != NULL);
  check("C_EncryptMessageBegin","slot-present",a.C_EncryptMessageBegin != NULL);
  check("C_EncryptMessageNext","slot-present",a.C_EncryptMessageNext != NULL);
  check("C_MessageEncryptFinal","slot-present",a.C_MessageEncryptFinal != NULL);
  check("C_MessageDecryptInit","slot-present",a.C_MessageDecryptInit != NULL);
  check("C_DecryptMessage","slot-present",a.C_DecryptMessage != NULL);
  check("C_DecryptMessageBegin","slot-present",a.C_DecryptMessageBegin != NULL);
  check("C_DecryptMessageNext","slot-present",a.C_DecryptMessageNext != NULL);
  check("C_MessageDecryptFinal","slot-present",a.C_MessageDecryptFinal != NULL);
  check("C_MessageSignInit","slot-present",a.C_MessageSignInit != NULL);
  check("C_SignMessage","slot-present",a.C_SignMessage != NULL);
  check("C_SignMessageBegin","slot-present",a.C_SignMessageBegin != NULL);
  check("C_SignMessageNext","slot-present",a.C_SignMessageNext != NULL);
  check("C_MessageSignFinal","slot-present",a.C_MessageSignFinal != NULL);
  check("C_MessageVerifyInit","slot-present",a.C_MessageVerifyInit != NULL);
  check("C_VerifyMessage","slot-present",a.C_VerifyMessage != NULL);
  check("C_VerifyMessageBegin","slot-present",a.C_VerifyMessageBegin != NULL);
  check("C_VerifyMessageNext","slot-present",a.C_VerifyMessageNext != NULL);
  check("C_MessageVerifyFinal","slot-present",a.C_MessageVerifyFinal != NULL);
  return a;
}
static MessageApi read_newest(CK_FUNCTION_LIST_3_2 *table) {
  MessageApi a;
  a.C_Initialize=table->C_Initialize;
  a.C_Finalize=table->C_Finalize;
  a.C_GetSlotList=table->C_GetSlotList;
  a.C_OpenSession=table->C_OpenSession;
  a.C_CloseSession=table->C_CloseSession;
  a.C_CreateObject=table->C_CreateObject;
  a.C_EncryptInit=table->C_EncryptInit;
  a.C_Encrypt=table->C_Encrypt;
  a.C_EncryptUpdate=table->C_EncryptUpdate;
  a.C_DecryptInit=table->C_DecryptInit;
  a.C_Decrypt=table->C_Decrypt;
  a.C_DecryptUpdate=table->C_DecryptUpdate;
  a.C_SignInit=table->C_SignInit;
  a.C_Sign=table->C_Sign;
  a.C_VerifyInit=table->C_VerifyInit;
  a.C_Verify=table->C_Verify;
  a.C_MessageEncryptInit=table->C_MessageEncryptInit;
  a.C_EncryptMessage=table->C_EncryptMessage;
  a.C_EncryptMessageBegin=table->C_EncryptMessageBegin;
  a.C_EncryptMessageNext=table->C_EncryptMessageNext;
  a.C_MessageEncryptFinal=table->C_MessageEncryptFinal;
  a.C_MessageDecryptInit=table->C_MessageDecryptInit;
  a.C_DecryptMessage=table->C_DecryptMessage;
  a.C_DecryptMessageBegin=table->C_DecryptMessageBegin;
  a.C_DecryptMessageNext=table->C_DecryptMessageNext;
  a.C_MessageDecryptFinal=table->C_MessageDecryptFinal;
  a.C_MessageSignInit=table->C_MessageSignInit;
  a.C_SignMessage=table->C_SignMessage;
  a.C_SignMessageBegin=table->C_SignMessageBegin;
  a.C_SignMessageNext=table->C_SignMessageNext;
  a.C_MessageSignFinal=table->C_MessageSignFinal;
  a.C_MessageVerifyInit=table->C_MessageVerifyInit;
  a.C_VerifyMessage=table->C_VerifyMessage;
  a.C_VerifyMessageBegin=table->C_VerifyMessageBegin;
  a.C_VerifyMessageNext=table->C_VerifyMessageNext;
  a.C_MessageVerifyFinal=table->C_MessageVerifyFinal;
  check("C_MessageEncryptInit","slot-present",a.C_MessageEncryptInit != NULL);
  check("C_EncryptMessage","slot-present",a.C_EncryptMessage != NULL);
  check("C_EncryptMessageBegin","slot-present",a.C_EncryptMessageBegin != NULL);
  check("C_EncryptMessageNext","slot-present",a.C_EncryptMessageNext != NULL);
  check("C_MessageEncryptFinal","slot-present",a.C_MessageEncryptFinal != NULL);
  check("C_MessageDecryptInit","slot-present",a.C_MessageDecryptInit != NULL);
  check("C_DecryptMessage","slot-present",a.C_DecryptMessage != NULL);
  check("C_DecryptMessageBegin","slot-present",a.C_DecryptMessageBegin != NULL);
  check("C_DecryptMessageNext","slot-present",a.C_DecryptMessageNext != NULL);
  check("C_MessageDecryptFinal","slot-present",a.C_MessageDecryptFinal != NULL);
  check("C_MessageSignInit","slot-present",a.C_MessageSignInit != NULL);
  check("C_SignMessage","slot-present",a.C_SignMessage != NULL);
  check("C_SignMessageBegin","slot-present",a.C_SignMessageBegin != NULL);
  check("C_SignMessageNext","slot-present",a.C_SignMessageNext != NULL);
  check("C_MessageSignFinal","slot-present",a.C_MessageSignFinal != NULL);
  check("C_MessageVerifyInit","slot-present",a.C_MessageVerifyInit != NULL);
  check("C_VerifyMessage","slot-present",a.C_VerifyMessage != NULL);
  check("C_VerifyMessageBegin","slot-present",a.C_VerifyMessageBegin != NULL);
  check("C_VerifyMessageNext","slot-present",a.C_VerifyMessageNext != NULL);
  check("C_MessageVerifyFinal","slot-present",a.C_MessageVerifyFinal != NULL);
  return a;
}
static void boundary_legs(MessageApi *a, int lifecycle, const char *phase);
static void encrypt_legs(MessageApi *a);
static void decrypt_legs(MessageApi *a);
static void sign_legs(MessageApi *a);
static void verify_legs(MessageApi *a);
static void extra_legs(MessageApi *a);
static void oversize_legs(MessageApi *a);

int main(int argc, char **argv) {
  if (argc != 2) return 2;
  const char *topology=getenv("HASKOKI_CONSUMER_TOPOLOGY");
  proxy=topology && strcmp(topology,"proxy")==0;
  configure();
  void *module=dlopen(argv[1],RTLD_NOW|RTLD_LOCAL);
  if (!module) { fprintf(stderr,"module could not load\n"); return 2; }
  CK_C_GetInterface getInterface=(CK_C_GetInterface)dlsym(module,"C_GetInterface");
  if (!getInterface) return 2;
  for (minor=0;minor<=2;++minor) {
    CK_VERSION version={3,(CK_BYTE)minor};
    CK_INTERFACE_PTR interface=NULL;
    CK_RV result=getInterface(NULL,&version,&interface,0);
    rv("C_GetInterface","discover-before-init",result,CKR_OK);
    if (result != CKR_OK || !interface || !interface->pFunctionList) return 1;
    MessageApi a;
    if (minor<2) {
      CK_FUNCTION_LIST_3_0 *table=(CK_FUNCTION_LIST_3_0 *)interface->pFunctionList;
      check("C_GetInterface","version",table->version.major==3 && table->version.minor==minor);
      a=read_common(table);
    } else {
      CK_FUNCTION_LIST_3_2 *table=(CK_FUNCTION_LIST_3_2 *)interface->pFunctionList;
      check("C_GetInterface","version",table->version.major==3 && table->version.minor==minor);
      a=read_newest(table);
    }
    if (failures) return 1;
    boundary_legs(&a,1,"pre-init");
    result=a.C_Initialize(NULL);
    rv("C_Initialize","live",result,CKR_OK);
    if (result != CKR_OK) return 1;
    CK_SLOT_ID slots[16]; CK_ULONG count=16;
    result=a.C_GetSlotList(CK_TRUE,slots,&count);
    rv("C_GetSlotList","token-present",result,CKR_OK);
    if (result != CKR_OK || count==0 || count>16) return 1;
    tokenSlot=slots[0];
    boundary_legs(&a,0,"live");
    encrypt_legs(&a);
    decrypt_legs(&a);
    sign_legs(&a);
    verify_legs(&a);
    extra_legs(&a);
    if (!proxy) oversize_legs(&a);
    rv("C_Finalize","end",a.C_Finalize(NULL),CKR_OK);
    boundary_legs(&a,1,"post-finalize");
  }
  dlclose(module);
  unlink(configPath);
  if (failures) return 1;
  puts("PASS: message_routed");
  return 0;
}
```

- [ ] Compile the scaffold to observe the missing test bodies.

```sh
cc -std=c11 -O2 -g -Wall -Wextra -Werror -Ispec/vendor tests/c/message_routed.c -ldl -lpthread -o /tmp/haskoki-message-routed
```

Expected failure: the seven static leg functions are declared/used but not defined. Capture the diagnostics before adding their bodies.

- [ ] Implement the complete common boundary matrix in `tests/c/message_routed.c`.

```c
static CK_RV probe_C_MessageEncryptInit(MessageApi *a, Fixture *f, unsigned shape, Output *o) {
  (void)o;
  CK_MECHANISM badMechanism={CKM_SHA256_HMAC,NULL,1};
  switch(shape) {
    case 0: return a->C_MessageEncryptInit(f->session,&cbc,f->aes);
    case 1: return a->C_MessageEncryptInit(f->session,NULL,f->aes);
    case 2: return a->C_MessageEncryptInit(f->session,&badMechanism,f->aes);
    default: exit(2);
  }
}
static CK_RV probe_C_EncryptMessage(MessageApi *a, Fixture *f, unsigned shape, Output *o) {
  (void)o;
  switch(shape) {
    case 0: return a->C_EncryptMessage(f->session,iv,16,NULL,0,plain,16,o->bytes+1,&o->length);
    case 1: return a->C_EncryptMessage(f->session,iv,16,NULL,0,plain,16,o->bytes+1,NULL);
    case 2: return a->C_EncryptMessage(f->session,NULL,1,NULL,0,plain,16,o->bytes+1,&o->length);
    case 3: return a->C_EncryptMessage(f->session,iv,16,NULL,1,plain,16,o->bytes+1,&o->length);
    case 4: return a->C_EncryptMessage(f->session,iv,16,NULL,0,NULL,1,o->bytes+1,&o->length);
    default: exit(2);
  }
}
static CK_RV probe_C_EncryptMessageBegin(MessageApi *a, Fixture *f, unsigned shape, Output *o) {
  (void)o;
  switch(shape) {
    case 0: return a->C_EncryptMessageBegin(f->session,iv,16,NULL,0);
    case 1: return a->C_EncryptMessageBegin(f->session,NULL,1,NULL,0);
    case 2: return a->C_EncryptMessageBegin(f->session,iv,16,NULL,1);
    default: exit(2);
  }
}
static CK_RV probe_C_EncryptMessageNext(MessageApi *a, Fixture *f, unsigned shape, Output *o) {
  (void)o;
  switch(shape) {
    case 0: return a->C_EncryptMessageNext(f->session,iv,16,plain,16,o->bytes+1,&o->length,CKF_END_OF_MESSAGE);
    case 1: return a->C_EncryptMessageNext(f->session,iv,16,plain,16,o->bytes+1,NULL,CKF_END_OF_MESSAGE);
    case 2: return a->C_EncryptMessageNext(f->session,NULL,1,plain,16,o->bytes+1,&o->length,CKF_END_OF_MESSAGE);
    case 3: return a->C_EncryptMessageNext(f->session,iv,16,NULL,1,o->bytes+1,&o->length,CKF_END_OF_MESSAGE);
    case 4: return a->C_EncryptMessageNext(f->session,iv,16,plain,16,o->bytes+1,&o->length,2);
    default: exit(2);
  }
}
static CK_RV probe_C_MessageEncryptFinal(MessageApi *a, Fixture *f, unsigned shape, Output *o) {
  (void)o;
  switch(shape) {
    case 0: return a->C_MessageEncryptFinal(f->session);
    default: exit(2);
  }
}
static CK_RV probe_C_MessageDecryptInit(MessageApi *a, Fixture *f, unsigned shape, Output *o) {
  (void)o;
  CK_MECHANISM badMechanism={CKM_SHA256_HMAC,NULL,1};
  switch(shape) {
    case 0: return a->C_MessageDecryptInit(f->session,&cbc,f->aes);
    case 1: return a->C_MessageDecryptInit(f->session,NULL,f->aes);
    case 2: return a->C_MessageDecryptInit(f->session,&badMechanism,f->aes);
    default: exit(2);
  }
}
static CK_RV probe_C_DecryptMessage(MessageApi *a, Fixture *f, unsigned shape, Output *o) {
  (void)o;
  switch(shape) {
    case 0: return a->C_DecryptMessage(f->session,iv,16,NULL,0,cipher,16,o->bytes+1,&o->length);
    case 1: return a->C_DecryptMessage(f->session,iv,16,NULL,0,cipher,16,o->bytes+1,NULL);
    case 2: return a->C_DecryptMessage(f->session,NULL,1,NULL,0,cipher,16,o->bytes+1,&o->length);
    case 3: return a->C_DecryptMessage(f->session,iv,16,NULL,1,cipher,16,o->bytes+1,&o->length);
    case 4: return a->C_DecryptMessage(f->session,iv,16,NULL,0,NULL,1,o->bytes+1,&o->length);
    default: exit(2);
  }
}
static CK_RV probe_C_DecryptMessageBegin(MessageApi *a, Fixture *f, unsigned shape, Output *o) {
  (void)o;
  switch(shape) {
    case 0: return a->C_DecryptMessageBegin(f->session,iv,16,NULL,0);
    case 1: return a->C_DecryptMessageBegin(f->session,NULL,1,NULL,0);
    case 2: return a->C_DecryptMessageBegin(f->session,iv,16,NULL,1);
    default: exit(2);
  }
}
static CK_RV probe_C_DecryptMessageNext(MessageApi *a, Fixture *f, unsigned shape, Output *o) {
  (void)o;
  switch(shape) {
    case 0: return a->C_DecryptMessageNext(f->session,iv,16,cipher,16,o->bytes+1,&o->length,CKF_END_OF_MESSAGE);
    case 1: return a->C_DecryptMessageNext(f->session,iv,16,cipher,16,o->bytes+1,NULL,CKF_END_OF_MESSAGE);
    case 2: return a->C_DecryptMessageNext(f->session,NULL,1,cipher,16,o->bytes+1,&o->length,CKF_END_OF_MESSAGE);
    case 3: return a->C_DecryptMessageNext(f->session,iv,16,NULL,1,o->bytes+1,&o->length,CKF_END_OF_MESSAGE);
    case 4: return a->C_DecryptMessageNext(f->session,iv,16,cipher,16,o->bytes+1,&o->length,2);
    default: exit(2);
  }
}
static CK_RV probe_C_MessageDecryptFinal(MessageApi *a, Fixture *f, unsigned shape, Output *o) {
  (void)o;
  switch(shape) {
    case 0: return a->C_MessageDecryptFinal(f->session);
    default: exit(2);
  }
}
static CK_RV probe_C_MessageSignInit(MessageApi *a, Fixture *f, unsigned shape, Output *o) {
  (void)o;
  CK_MECHANISM badMechanism={CKM_SHA256_HMAC,NULL,1};
  switch(shape) {
    case 0: return a->C_MessageSignInit(f->session,&hmac,f->mac);
    case 1: return a->C_MessageSignInit(f->session,NULL,f->mac);
    case 2: return a->C_MessageSignInit(f->session,&badMechanism,f->mac);
    default: exit(2);
  }
}
static CK_RV probe_C_SignMessage(MessageApi *a, Fixture *f, unsigned shape, Output *o) {
  (void)o;
  switch(shape) {
    case 0: return a->C_SignMessage(f->session,NULL,0,textBytes,8,o->bytes+1,&o->length);
    case 1: return a->C_SignMessage(f->session,NULL,0,textBytes,8,o->bytes+1,NULL);
    case 2: return a->C_SignMessage(f->session,NULL,1,textBytes,8,o->bytes+1,&o->length);
    case 3: return a->C_SignMessage(f->session,NULL,0,NULL,1,o->bytes+1,&o->length);
    default: exit(2);
  }
}
static CK_RV probe_C_SignMessageBegin(MessageApi *a, Fixture *f, unsigned shape, Output *o) {
  (void)o;
  switch(shape) {
    case 0: return a->C_SignMessageBegin(f->session,NULL,0);
    case 1: return a->C_SignMessageBegin(f->session,NULL,1);
    default: exit(2);
  }
}
static CK_RV probe_C_SignMessageNext(MessageApi *a, Fixture *f, unsigned shape, Output *o) {
  (void)o;
  switch(shape) {
    case 0: return a->C_SignMessageNext(f->session,NULL,0,textBytes,8,o->bytes+1,&o->length);
    case 1: return a->C_SignMessageNext(f->session,NULL,1,textBytes,8,o->bytes+1,&o->length);
    case 2: return a->C_SignMessageNext(f->session,NULL,0,NULL,1,o->bytes+1,&o->length);
    default: exit(2);
  }
}
static CK_RV probe_C_MessageSignFinal(MessageApi *a, Fixture *f, unsigned shape, Output *o) {
  (void)o;
  switch(shape) {
    case 0: return a->C_MessageSignFinal(f->session);
    default: exit(2);
  }
}
static CK_RV probe_C_MessageVerifyInit(MessageApi *a, Fixture *f, unsigned shape, Output *o) {
  (void)o;
  CK_MECHANISM badMechanism={CKM_SHA256_HMAC,NULL,1};
  switch(shape) {
    case 0: return a->C_MessageVerifyInit(f->session,&hmac,f->mac);
    case 1: return a->C_MessageVerifyInit(f->session,NULL,f->mac);
    case 2: return a->C_MessageVerifyInit(f->session,&badMechanism,f->mac);
    default: exit(2);
  }
}
static CK_RV probe_C_VerifyMessage(MessageApi *a, Fixture *f, unsigned shape, Output *o) {
  (void)o;
  switch(shape) {
    case 0: return a->C_VerifyMessage(f->session,NULL,0,textBytes,8,witness,32);
    case 1: return a->C_VerifyMessage(f->session,NULL,1,textBytes,8,witness,32);
    case 2: return a->C_VerifyMessage(f->session,NULL,0,NULL,1,witness,32);
    case 3: return a->C_VerifyMessage(f->session,NULL,0,textBytes,8,NULL,1);
    default: exit(2);
  }
}
static CK_RV probe_C_VerifyMessageBegin(MessageApi *a, Fixture *f, unsigned shape, Output *o) {
  (void)o;
  switch(shape) {
    case 0: return a->C_VerifyMessageBegin(f->session,NULL,0);
    case 1: return a->C_VerifyMessageBegin(f->session,NULL,1);
    default: exit(2);
  }
}
static CK_RV probe_C_VerifyMessageNext(MessageApi *a, Fixture *f, unsigned shape, Output *o) {
  (void)o;
  switch(shape) {
    case 0: return a->C_VerifyMessageNext(f->session,NULL,0,textBytes,8,witness,32);
    case 1: return a->C_VerifyMessageNext(f->session,NULL,1,textBytes,8,witness,32);
    case 2: return a->C_VerifyMessageNext(f->session,NULL,0,NULL,1,witness,32);
    case 3: return a->C_VerifyMessageNext(f->session,NULL,0,textBytes,8,NULL,1);
    default: exit(2);
  }
}
static CK_RV probe_C_MessageVerifyFinal(MessageApi *a, Fixture *f, unsigned shape, Output *o) {
  (void)o;
  switch(shape) {
    case 0: return a->C_MessageVerifyFinal(f->session);
    default: exit(2);
  }
}
typedef CK_RV (*Probe)(MessageApi *,Fixture *,unsigned,Output *);
static void boundary_legs(MessageApi *a, int lifecycle, const char *phase) {
  static const struct { const char *name; Probe call; unsigned count; const char *labels[6]; } entries[] = {
    {"C_MessageEncryptInit",probe_C_MessageEncryptInit,3,{"well-shaped","null-mechanism","bad-mechanism-parameter"}},
    {"C_EncryptMessage",probe_C_EncryptMessage,5,{"well-shaped","missing-length","bad-pParameter","bad-pAssociatedData","bad-pPlaintext"}},
    {"C_EncryptMessageBegin",probe_C_EncryptMessageBegin,3,{"well-shaped","bad-pParameter","bad-pAssociatedData"}},
    {"C_EncryptMessageNext",probe_C_EncryptMessageNext,5,{"well-shaped","missing-length","bad-pParameter","bad-pPlaintextPart","unknown-flags"}},
    {"C_MessageEncryptFinal",probe_C_MessageEncryptFinal,1,{"well-shaped"}},
    {"C_MessageDecryptInit",probe_C_MessageDecryptInit,3,{"well-shaped","null-mechanism","bad-mechanism-parameter"}},
    {"C_DecryptMessage",probe_C_DecryptMessage,5,{"well-shaped","missing-length","bad-pParameter","bad-pAssociatedData","bad-pCiphertext"}},
    {"C_DecryptMessageBegin",probe_C_DecryptMessageBegin,3,{"well-shaped","bad-pParameter","bad-pAssociatedData"}},
    {"C_DecryptMessageNext",probe_C_DecryptMessageNext,5,{"well-shaped","missing-length","bad-pParameter","bad-pCiphertextPart","unknown-flags"}},
    {"C_MessageDecryptFinal",probe_C_MessageDecryptFinal,1,{"well-shaped"}},
    {"C_MessageSignInit",probe_C_MessageSignInit,3,{"well-shaped","null-mechanism","bad-mechanism-parameter"}},
    {"C_SignMessage",probe_C_SignMessage,4,{"well-shaped","missing-length","bad-pParameter","bad-pData"}},
    {"C_SignMessageBegin",probe_C_SignMessageBegin,2,{"well-shaped","bad-pParameter"}},
    {"C_SignMessageNext",probe_C_SignMessageNext,3,{"well-shaped","bad-pParameter","bad-pDataPart"}},
    {"C_MessageSignFinal",probe_C_MessageSignFinal,1,{"well-shaped"}},
    {"C_MessageVerifyInit",probe_C_MessageVerifyInit,3,{"well-shaped","null-mechanism","bad-mechanism-parameter"}},
    {"C_VerifyMessage",probe_C_VerifyMessage,4,{"well-shaped","bad-pParameter","bad-pData","bad-pSignature"}},
    {"C_VerifyMessageBegin",probe_C_VerifyMessageBegin,2,{"well-shaped","bad-pParameter"}},
    {"C_VerifyMessageNext",probe_C_VerifyMessageNext,4,{"well-shaped","bad-pParameter","bad-pDataPart","bad-pSignature"}},
    {"C_MessageVerifyFinal",probe_C_MessageVerifyFinal,1,{"well-shaped"}},
  };
  for (size_t i=0;i<sizeof(entries)/sizeof(entries[0]);++i) {
    for (unsigned shape=0;shape<entries[i].count;++shape) {
      unsigned variants=lifecycle ? 1U : (shape ? 2U : 1U);
      for (unsigned badSession=0;badSession<variants;++badSession) {
        Fixture owned={0};
        if (!lifecycle) owned=fixture(a);
        Fixture f=owned;
        if (lifecycle || badSession || shape==0) f.session=~0UL;
        Output o; reset_output(&o,777);
        char leg[160];
        snprintf(leg,sizeof(leg),"%s-%s-%s",phase,entries[i].labels[shape],f.session==~0UL ? "invalid-session" : "valid-session");
        CK_RV want=lifecycle ? CKR_CRYPTOKI_NOT_INITIALIZED : shape ? CKR_ARGUMENTS_BAD : CKR_SESSION_HANDLE_INVALID;
        rv(entries[i].name,leg,entries[i].call(a,&f,shape,&o),want);
        untouched(entries[i].name,leg,&o,777);
        if (!lifecycle) close_fixture(a,owned);
      }
    }
  }
}
```

Every malformed shape has its own call and a fresh live session, and lifecycle probes include both well-shaped and malformed variants before initialization and after finalization. These expectations are strict. If the canonical shim refuses locally with a different code, retain the direct assertion, establish its exact source path and runtime code, and add an exact topology assertion with the existing `topology:` prefix only for that refusal. A forwarded normal call, missing slot, incorrect output, or `CKR_FUNCTION_NOT_SUPPORTED` cannot receive that treatment. Do not broaden return-code sets.

- [ ] Implement `encrypt_legs(MessageApi *a)` in `tests/c/message_routed.c` with every Encrypt entry leg.

```c
static void encrypt_legs(MessageApi *a) {
  Fixture f=fixture(a);
  Output o;
  CK_MECHANISM unknown={0xffffffffUL,NULL,0};
  CK_BYTE changedIv[16]={0};
  reset_output(&o,777);
  rv("C_EncryptMessage","no-init",a->C_EncryptMessage(f.session,iv,16,NULL,0,plain,16,o.bytes+1,&o.length),CKR_OPERATION_NOT_INITIALIZED);
  untouched("C_EncryptMessage","no-init",&o,777);
  rv("C_EncryptMessageBegin","no-init",a->C_EncryptMessageBegin(f.session,iv,16,NULL,0),CKR_OPERATION_NOT_INITIALIZED);
  rv("C_EncryptMessageNext","no-begin",a->C_EncryptMessageNext(f.session,NULL,0,plain,16,o.bytes+1,&o.length,CKF_END_OF_MESSAGE),CKR_OPERATION_NOT_INITIALIZED);
  untouched("C_EncryptMessageNext","no-begin",&o,777);
  rv("C_MessageEncryptFinal","no-init",a->C_MessageEncryptFinal(f.session),CKR_OPERATION_NOT_INITIALIZED);
  rv("C_MessageEncryptInit","bad-key",a->C_MessageEncryptInit(f.session,&cbc,~0UL),CKR_OBJECT_HANDLE_INVALID);
  rv("C_MessageEncryptInit","unknown-mechanism",a->C_MessageEncryptInit(f.session,&unknown,f.aes),CKR_MECHANISM_INVALID);
  rv("C_MessageEncryptInit","init-cbc",a->C_MessageEncryptInit(f.session,&cbc,f.aes),CKR_OK);
  rv("C_MessageEncryptInit","duplicate-init",a->C_MessageEncryptInit(f.session,&cbc,f.aes),CKR_OPERATION_ACTIVE);
  rv("C_EncryptInit","message-collision",a->C_EncryptInit(f.session,&cbc,f.aes),CKR_OPERATION_ACTIVE);
  reset_output(&o,777);
  rv("C_EncryptMessage","one-cbc-query",a->C_EncryptMessage(f.session,iv,16,NULL,0,plain,16,NULL,&o.length),CKR_OK);
  output_length("C_EncryptMessage","one-cbc-query",&o,16);
  untouched("C_EncryptMessage","one-cbc-query",&o,16);
  rv("C_MessageEncryptFinal","one-cbc-query-staged",a->C_MessageEncryptFinal(f.session),CKR_OPERATION_ACTIVE);
  reset_output(&o,1);
  rv("C_EncryptMessage","one-cbc-repeat-query",a->C_EncryptMessage(f.session,iv,16,NULL,0,plain,16,NULL,&o.length),CKR_OK);
  output_length("C_EncryptMessage","one-cbc-repeat-query",&o,16);
  untouched("C_EncryptMessage","one-cbc-repeat-query",&o,16);
  rv("C_MessageEncryptFinal","one-cbc-repeat-query-staged",a->C_MessageEncryptFinal(f.session),CKR_OPERATION_ACTIVE);
  reset_output(&o,0);
  rv("C_EncryptMessage","one-cbc-zero-capacity",a->C_EncryptMessage(f.session,iv,16,NULL,0,plain,16,o.bytes+1,&o.length),CKR_BUFFER_TOO_SMALL);
  output_length("C_EncryptMessage","one-cbc-zero-capacity",&o,16);
  untouched("C_EncryptMessage","one-cbc-zero-capacity",&o,16);
  rv("C_MessageEncryptFinal","one-cbc-zero-capacity-staged",a->C_MessageEncryptFinal(f.session),CKR_OPERATION_ACTIVE);
  reset_output(&o,15);
  rv("C_EncryptMessage","one-cbc-short",a->C_EncryptMessage(f.session,iv,16,NULL,0,plain,16,o.bytes+1,&o.length),CKR_BUFFER_TOO_SMALL);
  output_length("C_EncryptMessage","one-cbc-short",&o,16);
  untouched("C_EncryptMessage","one-cbc-short",&o,16);
  rv("C_MessageEncryptFinal","one-cbc-short-staged",a->C_MessageEncryptFinal(f.session),CKR_OPERATION_ACTIVE);
  reset_output(&o,777);
  rv("C_EncryptMessage","one-cbc-exact-malformed-recall",a->C_EncryptMessage(f.session,NULL,1,NULL,0,plain,16,o.bytes+1,&o.length),CKR_ARGUMENTS_BAD);
  untouched("C_EncryptMessage","one-cbc-exact-malformed-recall",&o,777);
  reset_output(&o,16);
  rv("C_EncryptMessage","one-cbc-exact",a->C_EncryptMessage(f.session,iv,16,NULL,0,plain,16,o.bytes+1,&o.length),CKR_OK);
  output_bytes("C_EncryptMessage","one-cbc-exact",&o,cipher,16);
  reset_output(&o,16);
  rv("C_EncryptMessage","second-message",a->C_EncryptMessage(f.session,iv,16,NULL,0,plain,16,o.bytes+1,&o.length),CKR_OK);
  output_bytes("C_EncryptMessage","second-message",&o,cipher,16);
  rv("C_MessageEncryptFinal","final-idle",a->C_MessageEncryptFinal(f.session),CKR_OK);
  rv("C_MessageEncryptFinal","second-final",a->C_MessageEncryptFinal(f.session),CKR_OPERATION_NOT_INITIALIZED);
  rv("C_EncryptInit","released-slot",a->C_EncryptInit(f.session,&cbc,f.aes),CKR_OK);
  rv("C_MessageEncryptInit","classic-collision",a->C_MessageEncryptInit(f.session,&cbc,f.aes),CKR_OPERATION_ACTIVE);
  rv("C_EncryptMessageBegin","classic-only",a->C_EncryptMessageBegin(f.session,iv,16,NULL,0),CKR_OPERATION_NOT_INITIALIZED);
  reset_output(&o,16);
  rv("C_Encrypt","classic-completion",a->C_Encrypt(f.session,plain,16,o.bytes+1,&o.length),CKR_OK);
  rv("C_MessageEncryptInit","multipart-init",a->C_MessageEncryptInit(f.session,&cbc,f.aes),CKR_OK);
  rv("C_EncryptMessageBegin","begin-iv",a->C_EncryptMessageBegin(f.session,iv,16,NULL,0),CKR_OK);
  reset_output(&o,777);
  rv("C_EncryptMessage","while-open",a->C_EncryptMessage(f.session,iv,16,NULL,0,plain,16,o.bytes+1,&o.length),CKR_OPERATION_ACTIVE);
  untouched("C_EncryptMessage","while-open",&o,777);
  rv("C_MessageEncryptFinal","open-message",a->C_MessageEncryptFinal(f.session),CKR_OPERATION_ACTIVE);
  rv("C_EncryptUpdate","message-mixing",a->C_EncryptUpdate(f.session,plain,0,o.bytes+1,&o.length),CKR_GENERAL_ERROR);
  untouched("C_EncryptUpdate","message-mixing",&o,777);
  reset_output(&o,733);
  rv("C_EncryptMessageNext","non-ending-query",a->C_EncryptMessageNext(f.session,NULL,0,plain,7,NULL,&o.length,0),CKR_OK);
  output_length("C_EncryptMessageNext","non-ending-query",&o,0);
  rv("C_MessageEncryptFinal","continuation-query-open",a->C_MessageEncryptFinal(f.session),CKR_OPERATION_ACTIVE);
  reset_output(&o,0);
  rv("C_EncryptMessageNext","part-cbc",a->C_EncryptMessageNext(f.session,NULL,0,plain,7,o.bytes+1,&o.length,0),CKR_OK);
  untouched("C_EncryptMessageNext","zero-output-continuation",&o,0);
  rv("C_EncryptMessageBegin","second-begin-keeps-part",a->C_EncryptMessageBegin(f.session,iv,16,NULL,0),CKR_OPERATION_ACTIVE);
  reset_output(&o,777);
  rv("C_EncryptMessageNext","terminal-query",a->C_EncryptMessageNext(f.session,NULL,0,plain+7,9,NULL,&o.length,CKF_END_OF_MESSAGE),CKR_OK);
  output_length("C_EncryptMessageNext","terminal-query",&o,16);
  untouched("C_EncryptMessageNext","terminal-query",&o,16);
  rv("C_MessageEncryptFinal","terminal-query-staged",a->C_MessageEncryptFinal(f.session),CKR_OPERATION_ACTIVE);
  reset_output(&o,1);
  rv("C_EncryptMessageNext","terminal-repeat-query",a->C_EncryptMessageNext(f.session,NULL,0,plain+7,9,NULL,&o.length,CKF_END_OF_MESSAGE),CKR_OK);
  output_length("C_EncryptMessageNext","terminal-repeat-query",&o,16);
  untouched("C_EncryptMessageNext","terminal-repeat-query",&o,16);
  rv("C_MessageEncryptFinal","terminal-repeat-query-staged",a->C_MessageEncryptFinal(f.session),CKR_OPERATION_ACTIVE);
  reset_output(&o,0);
  rv("C_EncryptMessageNext","terminal-zero-capacity",a->C_EncryptMessageNext(f.session,NULL,0,plain+7,9,o.bytes+1,&o.length,CKF_END_OF_MESSAGE),CKR_BUFFER_TOO_SMALL);
  output_length("C_EncryptMessageNext","terminal-zero-capacity",&o,16);
  untouched("C_EncryptMessageNext","terminal-zero-capacity",&o,16);
  rv("C_MessageEncryptFinal","terminal-zero-capacity-staged",a->C_MessageEncryptFinal(f.session),CKR_OPERATION_ACTIVE);
  reset_output(&o,15);
  rv("C_EncryptMessageNext","terminal-short",a->C_EncryptMessageNext(f.session,NULL,0,plain+7,9,o.bytes+1,&o.length,CKF_END_OF_MESSAGE),CKR_BUFFER_TOO_SMALL);
  output_length("C_EncryptMessageNext","terminal-short",&o,16);
  untouched("C_EncryptMessageNext","terminal-short",&o,16);
  rv("C_MessageEncryptFinal","terminal-short-staged",a->C_MessageEncryptFinal(f.session),CKR_OPERATION_ACTIVE);
  reset_output(&o,777);
  rv("C_EncryptMessageNext","terminal-exact-malformed-recall",a->C_EncryptMessageNext(f.session,NULL,1,plain+7,9,o.bytes+1,&o.length,CKF_END_OF_MESSAGE),CKR_ARGUMENTS_BAD);
  untouched("C_EncryptMessageNext","terminal-exact-malformed-recall",&o,777);
  reset_output(&o,16);
  rv("C_EncryptMessageNext","terminal-exact",a->C_EncryptMessageNext(f.session,NULL,0,plain+7,9,o.bytes+1,&o.length,CKF_END_OF_MESSAGE),CKR_OK);
  output_bytes("C_EncryptMessageNext","terminal-exact",&o,cipher,16);
  rv("C_MessageEncryptFinal","multipart-final-idle",a->C_MessageEncryptFinal(f.session),CKR_OK);
  rv("C_MessageEncryptInit","recall-init",a->C_MessageEncryptInit(f.session,&cbc,f.aes),CKR_OK);
  reset_output(&o,1);
  rv("C_EncryptMessage","recall-stage",a->C_EncryptMessage(f.session,iv,16,NULL,0,plain,16,NULL,&o.length),CKR_OK);
  rv("C_MessageEncryptFinal","recall-stage-busy",a->C_MessageEncryptFinal(f.session),CKR_OPERATION_ACTIVE);
  reset_output(&o,777);
  rv("C_EncryptMessage","malformed-recall",a->C_EncryptMessage(f.session,NULL,1,NULL,0,plain,16,o.bytes+1,&o.length),CKR_ARGUMENTS_BAD);
  untouched("C_EncryptMessage","malformed-recall",&o,777);
  rv("C_Encrypt","staged-message-mixing",a->C_Encrypt(f.session,plain,16,o.bytes+1,&o.length),CKR_ARGUMENTS_BAD);
  untouched("C_Encrypt","staged-message-mixing",&o,777);
  reset_output(&o,16);
  rv("C_EncryptMessage","recall-after-malformed",a->C_EncryptMessage(f.session,iv,16,NULL,0,plain,16,o.bytes+1,&o.length),CKR_OK);
  output_bytes("C_EncryptMessage","recall-after-malformed",&o,cipher,16);
  reset_output(&o,777);
  rv("C_EncryptMessage","one-byte-unpadded",a->C_EncryptMessage(f.session,iv,16,NULL,0,plain,1,o.bytes+1,&o.length),CKR_DATA_LEN_RANGE);
  untouched("C_EncryptMessage","one-byte-unpadded",&o,777);
  rv("C_EncryptMessageBegin","after-one-byte-refusal",a->C_EncryptMessageBegin(f.session,iv,16,NULL,0),CKR_OK);
  rv("C_EncryptMessageNext","unaligned-end",a->C_EncryptMessageNext(f.session,NULL,0,plain,1,o.bytes+1,&o.length,CKF_END_OF_MESSAGE),CKR_DATA_LEN_RANGE);
  untouched("C_EncryptMessageNext","unaligned-end",&o,777);
  reset_output(&o,16);
  rv("C_EncryptMessageNext","repair-alignment",a->C_EncryptMessageNext(f.session,NULL,0,plain+1,15,o.bytes+1,&o.length,CKF_END_OF_MESSAGE),CKR_OK);
  output_bytes("C_EncryptMessageNext","repair-alignment",&o,cipher,16);
  rv("C_EncryptMessageBegin","empty-parameter-aad",a->C_EncryptMessageBegin(f.session,NULL,0,NULL,0),CKR_OK);
  reset_output(&o,16);
  rv("C_EncryptMessageNext","supply-iv-at-end",a->C_EncryptMessageNext(f.session,iv,16,plain,16,o.bytes+1,&o.length,CKF_END_OF_MESSAGE),CKR_OK);
  output_bytes("C_EncryptMessageNext","supply-iv-at-end",&o,cipher,16);
  rv("C_EncryptMessageBegin","replacement-iv-begin",a->C_EncryptMessageBegin(f.session,changedIv,16,NULL,0),CKR_OK);
  reset_output(&o,16);
  rv("C_EncryptMessageNext","replace-iv-at-end",a->C_EncryptMessageNext(f.session,iv,16,plain,16,o.bytes+1,&o.length,CKF_END_OF_MESSAGE),CKR_OK);
  output_bytes("C_EncryptMessageNext","replace-iv-at-end",&o,cipher,16);
  rv("C_MessageEncryptFinal","last-final-idle",a->C_MessageEncryptFinal(f.session),CKR_OK);
  CK_RV (*noQueryInit)(CK_SESSION_HANDLE,CK_MECHANISM *,CK_OBJECT_HANDLE)=a->C_MessageEncryptInit;
  CK_RV (*noQueryBegin)(CK_SESSION_HANDLE,void *,CK_ULONG,CK_BYTE *,CK_ULONG)=a->C_EncryptMessageBegin;
  CK_RV (*noQueryFinal)(CK_SESSION_HANDLE)=a->C_MessageEncryptFinal;
  check("C_MessageEncryptInit","no-query",noQueryInit!=NULL);
  check("C_EncryptMessageBegin","no-query",noQueryBegin!=NULL);
  check("C_MessageEncryptFinal","no-query",noQueryFinal!=NULL);
  close_fixture(a,f);
}
```

- [ ] Implement `decrypt_legs(MessageApi *a)` in `tests/c/message_routed.c` with every Decrypt entry leg.

```c
static void decrypt_legs(MessageApi *a) {
  Fixture f=fixture(a);
  Output o;
  CK_MECHANISM unknown={0xffffffffUL,NULL,0};
  CK_BYTE changedIv[16]={0};
  reset_output(&o,777);
  rv("C_DecryptMessage","no-init",a->C_DecryptMessage(f.session,iv,16,NULL,0,cipher,16,o.bytes+1,&o.length),CKR_OPERATION_NOT_INITIALIZED);
  untouched("C_DecryptMessage","no-init",&o,777);
  rv("C_DecryptMessageBegin","no-init",a->C_DecryptMessageBegin(f.session,iv,16,NULL,0),CKR_OPERATION_NOT_INITIALIZED);
  rv("C_DecryptMessageNext","no-begin",a->C_DecryptMessageNext(f.session,NULL,0,cipher,16,o.bytes+1,&o.length,CKF_END_OF_MESSAGE),CKR_OPERATION_NOT_INITIALIZED);
  untouched("C_DecryptMessageNext","no-begin",&o,777);
  rv("C_MessageDecryptFinal","no-init",a->C_MessageDecryptFinal(f.session),CKR_OPERATION_NOT_INITIALIZED);
  rv("C_MessageDecryptInit","bad-key",a->C_MessageDecryptInit(f.session,&cbc,~0UL),CKR_OBJECT_HANDLE_INVALID);
  rv("C_MessageDecryptInit","unknown-mechanism",a->C_MessageDecryptInit(f.session,&unknown,f.aes),CKR_MECHANISM_INVALID);
  rv("C_MessageDecryptInit","init-cbc",a->C_MessageDecryptInit(f.session,&cbc,f.aes),CKR_OK);
  rv("C_MessageDecryptInit","duplicate-init",a->C_MessageDecryptInit(f.session,&cbc,f.aes),CKR_OPERATION_ACTIVE);
  rv("C_DecryptInit","message-collision",a->C_DecryptInit(f.session,&cbc,f.aes),CKR_OPERATION_ACTIVE);
  reset_output(&o,777);
  rv("C_DecryptMessage","one-cbc-query",a->C_DecryptMessage(f.session,iv,16,NULL,0,cipher,16,NULL,&o.length),CKR_OK);
  output_length("C_DecryptMessage","one-cbc-query",&o,16);
  untouched("C_DecryptMessage","one-cbc-query",&o,16);
  rv("C_MessageDecryptFinal","one-cbc-query-staged",a->C_MessageDecryptFinal(f.session),CKR_OPERATION_ACTIVE);
  reset_output(&o,1);
  rv("C_DecryptMessage","one-cbc-repeat-query",a->C_DecryptMessage(f.session,iv,16,NULL,0,cipher,16,NULL,&o.length),CKR_OK);
  output_length("C_DecryptMessage","one-cbc-repeat-query",&o,16);
  untouched("C_DecryptMessage","one-cbc-repeat-query",&o,16);
  rv("C_MessageDecryptFinal","one-cbc-repeat-query-staged",a->C_MessageDecryptFinal(f.session),CKR_OPERATION_ACTIVE);
  reset_output(&o,0);
  rv("C_DecryptMessage","one-cbc-zero-capacity",a->C_DecryptMessage(f.session,iv,16,NULL,0,cipher,16,o.bytes+1,&o.length),CKR_BUFFER_TOO_SMALL);
  output_length("C_DecryptMessage","one-cbc-zero-capacity",&o,16);
  untouched("C_DecryptMessage","one-cbc-zero-capacity",&o,16);
  rv("C_MessageDecryptFinal","one-cbc-zero-capacity-staged",a->C_MessageDecryptFinal(f.session),CKR_OPERATION_ACTIVE);
  reset_output(&o,15);
  rv("C_DecryptMessage","one-cbc-short",a->C_DecryptMessage(f.session,iv,16,NULL,0,cipher,16,o.bytes+1,&o.length),CKR_BUFFER_TOO_SMALL);
  output_length("C_DecryptMessage","one-cbc-short",&o,16);
  untouched("C_DecryptMessage","one-cbc-short",&o,16);
  rv("C_MessageDecryptFinal","one-cbc-short-staged",a->C_MessageDecryptFinal(f.session),CKR_OPERATION_ACTIVE);
  reset_output(&o,777);
  rv("C_DecryptMessage","one-cbc-exact-malformed-recall",a->C_DecryptMessage(f.session,NULL,1,NULL,0,cipher,16,o.bytes+1,&o.length),CKR_ARGUMENTS_BAD);
  untouched("C_DecryptMessage","one-cbc-exact-malformed-recall",&o,777);
  reset_output(&o,16);
  rv("C_DecryptMessage","one-cbc-exact",a->C_DecryptMessage(f.session,iv,16,NULL,0,cipher,16,o.bytes+1,&o.length),CKR_OK);
  output_bytes("C_DecryptMessage","one-cbc-exact",&o,plain,16);
  reset_output(&o,16);
  rv("C_DecryptMessage","second-message",a->C_DecryptMessage(f.session,iv,16,NULL,0,cipher,16,o.bytes+1,&o.length),CKR_OK);
  output_bytes("C_DecryptMessage","second-message",&o,plain,16);
  rv("C_MessageDecryptFinal","final-idle",a->C_MessageDecryptFinal(f.session),CKR_OK);
  rv("C_MessageDecryptFinal","second-final",a->C_MessageDecryptFinal(f.session),CKR_OPERATION_NOT_INITIALIZED);
  rv("C_DecryptInit","released-slot",a->C_DecryptInit(f.session,&cbc,f.aes),CKR_OK);
  rv("C_MessageDecryptInit","classic-collision",a->C_MessageDecryptInit(f.session,&cbc,f.aes),CKR_OPERATION_ACTIVE);
  rv("C_DecryptMessageBegin","classic-only",a->C_DecryptMessageBegin(f.session,iv,16,NULL,0),CKR_OPERATION_NOT_INITIALIZED);
  reset_output(&o,16);
  rv("C_Decrypt","classic-completion",a->C_Decrypt(f.session,cipher,16,o.bytes+1,&o.length),CKR_OK);
  rv("C_MessageDecryptInit","multipart-init",a->C_MessageDecryptInit(f.session,&cbc,f.aes),CKR_OK);
  rv("C_DecryptMessageBegin","begin-iv",a->C_DecryptMessageBegin(f.session,iv,16,NULL,0),CKR_OK);
  reset_output(&o,777);
  rv("C_DecryptMessage","while-open",a->C_DecryptMessage(f.session,iv,16,NULL,0,cipher,16,o.bytes+1,&o.length),CKR_OPERATION_ACTIVE);
  untouched("C_DecryptMessage","while-open",&o,777);
  rv("C_MessageDecryptFinal","open-message",a->C_MessageDecryptFinal(f.session),CKR_OPERATION_ACTIVE);
  rv("C_DecryptUpdate","message-mixing",a->C_DecryptUpdate(f.session,cipher,0,o.bytes+1,&o.length),CKR_GENERAL_ERROR);
  untouched("C_DecryptUpdate","message-mixing",&o,777);
  reset_output(&o,733);
  rv("C_DecryptMessageNext","non-ending-query",a->C_DecryptMessageNext(f.session,NULL,0,cipher,8,NULL,&o.length,0),CKR_OK);
  output_length("C_DecryptMessageNext","non-ending-query",&o,0);
  rv("C_MessageDecryptFinal","continuation-query-open",a->C_MessageDecryptFinal(f.session),CKR_OPERATION_ACTIVE);
  reset_output(&o,0);
  rv("C_DecryptMessageNext","part-cbc",a->C_DecryptMessageNext(f.session,NULL,0,cipher,8,o.bytes+1,&o.length,0),CKR_OK);
  untouched("C_DecryptMessageNext","zero-output-continuation",&o,0);
  rv("C_DecryptMessageBegin","second-begin-keeps-part",a->C_DecryptMessageBegin(f.session,iv,16,NULL,0),CKR_OPERATION_ACTIVE);
  reset_output(&o,777);
  rv("C_DecryptMessageNext","terminal-query",a->C_DecryptMessageNext(f.session,NULL,0,cipher+8,8,NULL,&o.length,CKF_END_OF_MESSAGE),CKR_OK);
  output_length("C_DecryptMessageNext","terminal-query",&o,16);
  untouched("C_DecryptMessageNext","terminal-query",&o,16);
  rv("C_MessageDecryptFinal","terminal-query-staged",a->C_MessageDecryptFinal(f.session),CKR_OPERATION_ACTIVE);
  reset_output(&o,1);
  rv("C_DecryptMessageNext","terminal-repeat-query",a->C_DecryptMessageNext(f.session,NULL,0,cipher+8,8,NULL,&o.length,CKF_END_OF_MESSAGE),CKR_OK);
  output_length("C_DecryptMessageNext","terminal-repeat-query",&o,16);
  untouched("C_DecryptMessageNext","terminal-repeat-query",&o,16);
  rv("C_MessageDecryptFinal","terminal-repeat-query-staged",a->C_MessageDecryptFinal(f.session),CKR_OPERATION_ACTIVE);
  reset_output(&o,0);
  rv("C_DecryptMessageNext","terminal-zero-capacity",a->C_DecryptMessageNext(f.session,NULL,0,cipher+8,8,o.bytes+1,&o.length,CKF_END_OF_MESSAGE),CKR_BUFFER_TOO_SMALL);
  output_length("C_DecryptMessageNext","terminal-zero-capacity",&o,16);
  untouched("C_DecryptMessageNext","terminal-zero-capacity",&o,16);
  rv("C_MessageDecryptFinal","terminal-zero-capacity-staged",a->C_MessageDecryptFinal(f.session),CKR_OPERATION_ACTIVE);
  reset_output(&o,15);
  rv("C_DecryptMessageNext","terminal-short",a->C_DecryptMessageNext(f.session,NULL,0,cipher+8,8,o.bytes+1,&o.length,CKF_END_OF_MESSAGE),CKR_BUFFER_TOO_SMALL);
  output_length("C_DecryptMessageNext","terminal-short",&o,16);
  untouched("C_DecryptMessageNext","terminal-short",&o,16);
  rv("C_MessageDecryptFinal","terminal-short-staged",a->C_MessageDecryptFinal(f.session),CKR_OPERATION_ACTIVE);
  reset_output(&o,777);
  rv("C_DecryptMessageNext","terminal-exact-malformed-recall",a->C_DecryptMessageNext(f.session,NULL,1,cipher+8,8,o.bytes+1,&o.length,CKF_END_OF_MESSAGE),CKR_ARGUMENTS_BAD);
  untouched("C_DecryptMessageNext","terminal-exact-malformed-recall",&o,777);
  reset_output(&o,16);
  rv("C_DecryptMessageNext","terminal-exact",a->C_DecryptMessageNext(f.session,NULL,0,cipher+8,8,o.bytes+1,&o.length,CKF_END_OF_MESSAGE),CKR_OK);
  output_bytes("C_DecryptMessageNext","terminal-exact",&o,plain,16);
  rv("C_MessageDecryptFinal","multipart-final-idle",a->C_MessageDecryptFinal(f.session),CKR_OK);
  rv("C_MessageDecryptInit","recall-init",a->C_MessageDecryptInit(f.session,&cbc,f.aes),CKR_OK);
  reset_output(&o,1);
  rv("C_DecryptMessage","recall-stage",a->C_DecryptMessage(f.session,iv,16,NULL,0,cipher,16,NULL,&o.length),CKR_OK);
  rv("C_MessageDecryptFinal","recall-stage-busy",a->C_MessageDecryptFinal(f.session),CKR_OPERATION_ACTIVE);
  reset_output(&o,777);
  rv("C_DecryptMessage","malformed-recall",a->C_DecryptMessage(f.session,NULL,1,NULL,0,cipher,16,o.bytes+1,&o.length),CKR_ARGUMENTS_BAD);
  untouched("C_DecryptMessage","malformed-recall",&o,777);
  rv("C_Decrypt","staged-message-mixing",a->C_Decrypt(f.session,cipher,16,o.bytes+1,&o.length),CKR_ARGUMENTS_BAD);
  untouched("C_Decrypt","staged-message-mixing",&o,777);
  reset_output(&o,16);
  rv("C_DecryptMessage","recall-after-malformed",a->C_DecryptMessage(f.session,iv,16,NULL,0,cipher,16,o.bytes+1,&o.length),CKR_OK);
  output_bytes("C_DecryptMessage","recall-after-malformed",&o,plain,16);
  rv("C_DecryptMessageBegin","empty-parameter-aad",a->C_DecryptMessageBegin(f.session,NULL,0,NULL,0),CKR_OK);
  reset_output(&o,16);
  rv("C_DecryptMessageNext","supply-iv-at-end",a->C_DecryptMessageNext(f.session,iv,16,cipher,16,o.bytes+1,&o.length,CKF_END_OF_MESSAGE),CKR_OK);
  output_bytes("C_DecryptMessageNext","supply-iv-at-end",&o,plain,16);
  rv("C_DecryptMessageBegin","replacement-iv-begin",a->C_DecryptMessageBegin(f.session,changedIv,16,NULL,0),CKR_OK);
  reset_output(&o,16);
  rv("C_DecryptMessageNext","replace-iv-at-end",a->C_DecryptMessageNext(f.session,iv,16,cipher,16,o.bytes+1,&o.length,CKF_END_OF_MESSAGE),CKR_OK);
  output_bytes("C_DecryptMessageNext","replace-iv-at-end",&o,plain,16);
  rv("C_MessageDecryptFinal","last-final-idle",a->C_MessageDecryptFinal(f.session),CKR_OK);
  CK_RV (*noQueryInit)(CK_SESSION_HANDLE,CK_MECHANISM *,CK_OBJECT_HANDLE)=a->C_MessageDecryptInit;
  CK_RV (*noQueryBegin)(CK_SESSION_HANDLE,void *,CK_ULONG,CK_BYTE *,CK_ULONG)=a->C_DecryptMessageBegin;
  CK_RV (*noQueryFinal)(CK_SESSION_HANDLE)=a->C_MessageDecryptFinal;
  check("C_MessageDecryptInit","no-query",noQueryInit!=NULL);
  check("C_DecryptMessageBegin","no-query",noQueryBegin!=NULL);
  check("C_MessageDecryptFinal","no-query",noQueryFinal!=NULL);
  close_fixture(a,f);
}
```

- [ ] Implement `sign_legs(MessageApi *a)` in `tests/c/message_routed.c`.

```c
static void sign_legs(MessageApi *a) {
  Fixture f=fixture(a);
  Output o;
  reset_output(&o,777);
  rv("C_SignMessage","no-init",a->C_SignMessage(f.session,NULL,0,textBytes,8,o.bytes+1,&o.length),CKR_OPERATION_NOT_INITIALIZED);
  untouched("C_SignMessage","no-init",&o,777);
  rv("C_SignMessageBegin","no-init",a->C_SignMessageBegin(f.session,NULL,0),CKR_OPERATION_NOT_INITIALIZED);
  rv("C_SignMessageNext","no-begin",a->C_SignMessageNext(f.session,NULL,0,textBytes,8,o.bytes+1,&o.length),CKR_OPERATION_NOT_INITIALIZED);
  untouched("C_SignMessageNext","no-begin",&o,777);
  rv("C_MessageSignFinal","missing-context",a->C_MessageSignFinal(f.session),CKR_OPERATION_NOT_INITIALIZED);
  rv("C_MessageSignInit","bad-key",a->C_MessageSignInit(f.session,&hmac,~0UL),CKR_OBJECT_HANDLE_INVALID);
  rv("C_MessageSignInit","denied-sign-usage",a->C_MessageSignInit(f.session,&hmac,f.noSign),CKR_KEY_FUNCTION_NOT_PERMITTED);
  rv("C_MessageSignInit","init-hmac",a->C_MessageSignInit(f.session,&hmac,f.mac),CKR_OK);
  rv("C_MessageSignInit","duplicate-init",a->C_MessageSignInit(f.session,&hmac,f.mac),CKR_OPERATION_ACTIVE);
  rv("C_SignInit","message-collision",a->C_SignInit(f.session,&hmac,f.mac),CKR_OPERATION_ACTIVE);
  reset_output(&o,777);
  rv("C_SignMessage","one-hmac-query",a->C_SignMessage(f.session,NULL,0,textBytes,8,NULL,&o.length),CKR_OK);
  output_length("C_SignMessage","one-hmac-query",&o,32);
  untouched("C_SignMessage","one-hmac-query",&o,32);
  rv("C_MessageSignFinal","one-hmac-query-staged",a->C_MessageSignFinal(f.session),CKR_OPERATION_ACTIVE);
  reset_output(&o,1);
  rv("C_SignMessage","one-hmac-repeat-query",a->C_SignMessage(f.session,NULL,0,textBytes,8,NULL,&o.length),CKR_OK);
  output_length("C_SignMessage","one-hmac-repeat-query",&o,32);
  untouched("C_SignMessage","one-hmac-repeat-query",&o,32);
  rv("C_MessageSignFinal","one-hmac-repeat-query-staged",a->C_MessageSignFinal(f.session),CKR_OPERATION_ACTIVE);
  reset_output(&o,0);
  rv("C_SignMessage","one-hmac-zero-capacity",a->C_SignMessage(f.session,NULL,0,textBytes,8,o.bytes+1,&o.length),CKR_BUFFER_TOO_SMALL);
  output_length("C_SignMessage","one-hmac-zero-capacity",&o,32);
  untouched("C_SignMessage","one-hmac-zero-capacity",&o,32);
  rv("C_MessageSignFinal","one-hmac-zero-capacity-staged",a->C_MessageSignFinal(f.session),CKR_OPERATION_ACTIVE);
  reset_output(&o,31);
  rv("C_SignMessage","one-hmac-short",a->C_SignMessage(f.session,NULL,0,textBytes,8,o.bytes+1,&o.length),CKR_BUFFER_TOO_SMALL);
  output_length("C_SignMessage","one-hmac-short",&o,32);
  untouched("C_SignMessage","one-hmac-short",&o,32);
  rv("C_MessageSignFinal","one-hmac-short-staged",a->C_MessageSignFinal(f.session),CKR_OPERATION_ACTIVE);
  reset_output(&o,777);
  rv("C_SignMessage","one-hmac-exact-malformed-recall",a->C_SignMessage(f.session,NULL,1,textBytes,8,o.bytes+1,&o.length),CKR_ARGUMENTS_BAD);
  untouched("C_SignMessage","one-hmac-exact-malformed-recall",&o,777);
  reset_output(&o,32);
  rv("C_SignMessage","one-hmac-exact",a->C_SignMessage(f.session,NULL,0,textBytes,8,o.bytes+1,&o.length),CKR_OK);
  output_bytes("C_SignMessage","one-hmac-exact",&o,witness,32);
  reset_output(&o,32);
  rv("C_SignMessage","second-message",a->C_SignMessage(f.session,NULL,0,textBytes,8,o.bytes+1,&o.length),CKR_OK);
  output_bytes("C_SignMessage","second-message",&o,witness,32);
  rv("C_MessageSignFinal","final-idle",a->C_MessageSignFinal(f.session),CKR_OK);
  rv("C_SignInit","released-slot",a->C_SignInit(f.session,&hmac,f.mac),CKR_OK);
  rv("C_MessageSignInit","classic-collision",a->C_MessageSignInit(f.session,&hmac,f.mac),CKR_OPERATION_ACTIVE);
  rv("C_SignMessageBegin","classic-only",a->C_SignMessageBegin(f.session,NULL,0),CKR_OPERATION_NOT_INITIALIZED);
  reset_output(&o,32);
  rv("C_Sign","classic-completion",a->C_Sign(f.session,textBytes,8,o.bytes+1,&o.length),CKR_OK);
  rv("C_MessageSignInit","multipart-init",a->C_MessageSignInit(f.session,&hmac,f.mac),CKR_OK);
  rv("C_SignMessageBegin","begin-hmac",a->C_SignMessageBegin(f.session,NULL,0),CKR_OK);
  reset_output(&o,777);
  rv("C_SignMessage","while-open",a->C_SignMessage(f.session,NULL,0,textBytes,8,o.bytes+1,&o.length),CKR_OPERATION_ACTIVE);
  untouched("C_SignMessage","while-open",&o,777);
  rv("C_MessageSignFinal","open-message",a->C_MessageSignFinal(f.session),CKR_OPERATION_ACTIVE);
  rv("C_SignMessageNext","absent-output-and-length",a->C_SignMessageNext(f.session,NULL,0,NULL,0,NULL,NULL),CKR_OK);
  rv("C_SignMessageNext","ignored-present-output",a->C_SignMessageNext(f.session,NULL,0,textBytes,3,o.bytes+1,NULL),CKR_OK);
  untouched("C_SignMessageNext","ignored-present-output",&o,777);
  rv("C_SignMessageBegin","duplicate-begin-keeps-part",a->C_SignMessageBegin(f.session,NULL,0),CKR_OPERATION_ACTIVE);
  rv("C_SignMessageNext","null-part-nonzero",a->C_SignMessageNext(f.session,NULL,0,NULL,1,o.bytes+1,NULL),CKR_ARGUMENTS_BAD);
  untouched("C_SignMessageNext","null-part-nonzero",&o,777);
  reset_output(&o,777);
  rv("C_SignMessageNext","part-hmac-query",a->C_SignMessageNext(f.session,NULL,0,textBytes+3,5,NULL,&o.length),CKR_OK);
  output_length("C_SignMessageNext","part-hmac-query",&o,32);
  untouched("C_SignMessageNext","part-hmac-query",&o,32);
  rv("C_MessageSignFinal","part-hmac-query-staged",a->C_MessageSignFinal(f.session),CKR_OPERATION_ACTIVE);
  reset_output(&o,1);
  rv("C_SignMessageNext","part-hmac-repeat-query",a->C_SignMessageNext(f.session,NULL,0,textBytes+3,5,NULL,&o.length),CKR_OK);
  output_length("C_SignMessageNext","part-hmac-repeat-query",&o,32);
  untouched("C_SignMessageNext","part-hmac-repeat-query",&o,32);
  rv("C_MessageSignFinal","part-hmac-repeat-query-staged",a->C_MessageSignFinal(f.session),CKR_OPERATION_ACTIVE);
  reset_output(&o,0);
  rv("C_SignMessageNext","part-hmac-zero-capacity",a->C_SignMessageNext(f.session,NULL,0,textBytes+3,5,o.bytes+1,&o.length),CKR_BUFFER_TOO_SMALL);
  output_length("C_SignMessageNext","part-hmac-zero-capacity",&o,32);
  untouched("C_SignMessageNext","part-hmac-zero-capacity",&o,32);
  rv("C_MessageSignFinal","part-hmac-zero-capacity-staged",a->C_MessageSignFinal(f.session),CKR_OPERATION_ACTIVE);
  reset_output(&o,31);
  rv("C_SignMessageNext","part-hmac-short",a->C_SignMessageNext(f.session,NULL,0,textBytes+3,5,o.bytes+1,&o.length),CKR_BUFFER_TOO_SMALL);
  output_length("C_SignMessageNext","part-hmac-short",&o,32);
  untouched("C_SignMessageNext","part-hmac-short",&o,32);
  rv("C_MessageSignFinal","part-hmac-short-staged",a->C_MessageSignFinal(f.session),CKR_OPERATION_ACTIVE);
  reset_output(&o,777);
  rv("C_SignMessageNext","part-hmac-exact-malformed-recall",a->C_SignMessageNext(f.session,NULL,1,textBytes+3,5,o.bytes+1,&o.length),CKR_ARGUMENTS_BAD);
  untouched("C_SignMessageNext","part-hmac-exact-malformed-recall",&o,777);
  reset_output(&o,32);
  rv("C_SignMessageNext","part-hmac-exact",a->C_SignMessageNext(f.session,NULL,0,textBytes+3,5,o.bytes+1,&o.length),CKR_OK);
  output_bytes("C_SignMessageNext","part-hmac-exact",&o,witness,32);
  rv("C_MessageSignFinal","multipart-final-idle",a->C_MessageSignFinal(f.session),CKR_OK);
  rv("C_MessageSignFinal","second-final",a->C_MessageSignFinal(f.session),CKR_OPERATION_NOT_INITIALIZED);
  CK_RV (*noQueryInit)(CK_SESSION_HANDLE,CK_MECHANISM *,CK_OBJECT_HANDLE)=a->C_MessageSignInit;
  CK_RV (*noQueryBegin)(CK_SESSION_HANDLE,void *,CK_ULONG)=a->C_SignMessageBegin;
  CK_RV (*noQueryFinal)(CK_SESSION_HANDLE)=a->C_MessageSignFinal;
  check("C_MessageSignInit","no-query",noQueryInit!=NULL);
  check("C_SignMessageBegin","no-query",noQueryBegin!=NULL);
  check("C_MessageSignFinal","no-query",noQueryFinal!=NULL);
  close_fixture(a,f);
}
```

- [ ] Implement `verify_legs(MessageApi *a)` in `tests/c/message_routed.c`.

```c
static void verify_legs(MessageApi *a) {
  Fixture f=fixture(a);
  CK_BYTE badWitness[32]; memcpy(badWitness,witness,32); badWitness[0]^=1;
  rv("C_VerifyMessage","no-init",a->C_VerifyMessage(f.session,NULL,0,textBytes,8,witness,32),CKR_OPERATION_NOT_INITIALIZED);
  rv("C_VerifyMessageBegin","no-init",a->C_VerifyMessageBegin(f.session,NULL,0),CKR_OPERATION_NOT_INITIALIZED);
  rv("C_VerifyMessageNext","no-begin",a->C_VerifyMessageNext(f.session,NULL,0,textBytes,8,witness,32),CKR_OPERATION_NOT_INITIALIZED);
  rv("C_MessageVerifyFinal","missing-context",a->C_MessageVerifyFinal(f.session),CKR_OPERATION_NOT_INITIALIZED);
  rv("C_MessageVerifyInit","bad-key",a->C_MessageVerifyInit(f.session,&hmac,~0UL),CKR_OBJECT_HANDLE_INVALID);
  rv("C_MessageVerifyInit","denied-verify-usage",a->C_MessageVerifyInit(f.session,&hmac,f.noVerify),CKR_KEY_FUNCTION_NOT_PERMITTED);
  rv("C_MessageVerifyInit","init-hmac",a->C_MessageVerifyInit(f.session,&hmac,f.mac),CKR_OK);
  rv("C_MessageVerifyInit","duplicate-init",a->C_MessageVerifyInit(f.session,&hmac,f.mac),CKR_OPERATION_ACTIVE);
  rv("C_VerifyInit","message-collision",a->C_VerifyInit(f.session,&hmac,f.mac),CKR_OPERATION_ACTIVE);
  rv("C_VerifyMessage","one-hmac",a->C_VerifyMessage(f.session,NULL,0,textBytes,8,witness,32),CKR_OK);
  rv("C_VerifyMessage","flipped-witness",a->C_VerifyMessage(f.session,NULL,0,textBytes,8,badWitness,32),CKR_SIGNATURE_INVALID);
  rv("C_VerifyMessage","valid-after-invalid",a->C_VerifyMessage(f.session,NULL,0,textBytes,8,witness,32),CKR_OK);
  rv("C_VerifyMessage","null-empty-witness",a->C_VerifyMessage(f.session,NULL,0,textBytes,8,NULL,0),CKR_SIGNATURE_INVALID);
  rv("C_VerifyMessage","present-empty-witness",a->C_VerifyMessage(f.session,NULL,0,textBytes,8,witness,0),CKR_SIGNATURE_INVALID);
  rv("C_MessageVerifyFinal","final-idle-after-invalid",a->C_MessageVerifyFinal(f.session),CKR_OK);
  rv("C_VerifyInit","released-slot",a->C_VerifyInit(f.session,&hmac,f.mac),CKR_OK);
  rv("C_MessageVerifyInit","classic-collision",a->C_MessageVerifyInit(f.session,&hmac,f.mac),CKR_OPERATION_ACTIVE);
  rv("C_VerifyMessageBegin","classic-only",a->C_VerifyMessageBegin(f.session,NULL,0),CKR_OPERATION_NOT_INITIALIZED);
  rv("C_Verify","classic-completion",a->C_Verify(f.session,textBytes,8,witness,32),CKR_OK);
  rv("C_MessageVerifyInit","multipart-init",a->C_MessageVerifyInit(f.session,&hmac,f.mac),CKR_OK);
  rv("C_VerifyMessageBegin","begin-hmac",a->C_VerifyMessageBegin(f.session,NULL,0),CKR_OK);
  rv("C_VerifyMessageBegin","duplicate-begin",a->C_VerifyMessageBegin(f.session,NULL,0),CKR_OPERATION_ACTIVE);
  rv("C_MessageVerifyFinal","open-message",a->C_MessageVerifyFinal(f.session),CKR_OPERATION_ACTIVE);
  rv("C_VerifyMessage","while-open",a->C_VerifyMessage(f.session,NULL,0,textBytes,8,witness,32),CKR_OPERATION_ACTIVE);
  rv("C_VerifyMessageNext","absent-empty-witness",a->C_VerifyMessageNext(f.session,NULL,0,textBytes,3,NULL,0),CKR_OK);
  rv("C_VerifyMessageNext","absent-nonzero-witness",a->C_VerifyMessageNext(f.session,NULL,0,textBytes+3,5,NULL,1),CKR_ARGUMENTS_BAD);
  rv("C_VerifyMessageNext","part-hmac",a->C_VerifyMessageNext(f.session,NULL,0,textBytes+3,5,witness,32),CKR_OK);
  rv("C_VerifyMessageBegin","begin-again",a->C_VerifyMessageBegin(f.session,NULL,0),CKR_OK);
  rv("C_VerifyMessageNext","present-zero-ends",a->C_VerifyMessageNext(f.session,NULL,0,textBytes,8,witness,0),CKR_SIGNATURE_INVALID);
  rv("C_VerifyMessageBegin","begin-after-empty-mismatch",a->C_VerifyMessageBegin(f.session,NULL,0),CKR_OK);
  rv("C_VerifyMessageNext","flipped-witness-ends",a->C_VerifyMessageNext(f.session,NULL,0,textBytes,8,badWitness,32),CKR_SIGNATURE_INVALID);
  rv("C_VerifyMessageBegin","begin-after-flipped-mismatch",a->C_VerifyMessageBegin(f.session,NULL,0),CKR_OK);
  rv("C_VerifyMessageNext","recovered-verdict",a->C_VerifyMessageNext(f.session,NULL,0,textBytes,8,witness,32),CKR_OK);
  rv("C_MessageVerifyFinal","final-idle",a->C_MessageVerifyFinal(f.session),CKR_OK);
  rv("C_MessageVerifyFinal","second-final",a->C_MessageVerifyFinal(f.session),CKR_OPERATION_NOT_INITIALIZED);
  CK_RV (*noQueryInit)(CK_SESSION_HANDLE,CK_MECHANISM *,CK_OBJECT_HANDLE)=a->C_MessageVerifyInit;
  CK_RV (*noQueryOne)(CK_SESSION_HANDLE,void *,CK_ULONG,CK_BYTE *,CK_ULONG,CK_BYTE *,CK_ULONG)=a->C_VerifyMessage;
  CK_RV (*noQueryBegin)(CK_SESSION_HANDLE,void *,CK_ULONG)=a->C_VerifyMessageBegin;
  CK_RV (*noQueryNext)(CK_SESSION_HANDLE,void *,CK_ULONG,CK_BYTE *,CK_ULONG,CK_BYTE *,CK_ULONG)=a->C_VerifyMessageNext;
  CK_RV (*noQueryFinal)(CK_SESSION_HANDLE)=a->C_MessageVerifyFinal;
  check("C_MessageVerifyInit","no-query",noQueryInit!=NULL);
  check("C_VerifyMessage","no-query",noQueryOne!=NULL);
  check("C_VerifyMessageBegin","no-query",noQueryBegin!=NULL);
  check("C_VerifyMessageNext","no-query",noQueryNext!=NULL);
  check("C_MessageVerifyFinal","no-query",noQueryFinal!=NULL);
  close_fixture(a,f);
}
```

- [ ] Implement the additional cross-family, empty-output, padding, and session-lifetime sequences in `extra_legs(MessageApi *a)`.

```c
static void extra_legs(MessageApi *a) {
  Fixture f=fixture(a), reference=fixture(a);
  Output encrypted, decoded, classic;
  CK_BYTE abc[3]={'a','b','c'}, zero[16]={0}, presentEmpty=0;
  rv("C_MessageEncryptInit","pad-init",a->C_MessageEncryptInit(f.session,&padded,f.aes),CKR_OK);
  rv("C_MessageDecryptInit","pad-init",a->C_MessageDecryptInit(f.session,&padded,f.aes),CKR_OK);
  for (unsigned shape=0;shape<3;++shape) {
    CK_BYTE *input=shape==0 ? abc : shape==1 ? NULL : &presentEmpty;
    CK_ULONG n=shape==0 ? 3 : 0;
    const char *leg=shape==0 ? "pad-abc" : shape==1 ? "pad-empty-null" : "pad-empty-present";
    reset_output(&classic,64);
    rv("C_EncryptInit",leg,a->C_EncryptInit(reference.session,&padded,reference.aes),CKR_OK);
    rv("C_Encrypt",leg,a->C_Encrypt(reference.session,input,n,classic.bytes+1,&classic.length),CKR_OK);
    reset_output(&encrypted,64);
    rv("C_EncryptMessage",leg,a->C_EncryptMessage(f.session,iv,16,NULL,0,input,n,encrypted.bytes+1,&encrypted.length),CKR_OK);
    output_bytes("C_EncryptMessage",leg,&encrypted,classic.bytes+1,classic.length);
    rv("C_DecryptInit",leg,a->C_DecryptInit(reference.session,&padded,reference.aes),CKR_OK);
    reset_output(&classic,64);
    rv("C_Decrypt",leg,a->C_Decrypt(reference.session,encrypted.bytes+1,encrypted.length,classic.bytes+1,&classic.length),CKR_OK);
    output_bytes("C_Decrypt",leg,&classic,input ? input : &presentEmpty,n);
    if (n==0) {
      reset_output(&decoded,999);
      rv("C_DecryptMessage","empty-query",a->C_DecryptMessage(f.session,iv,16,NULL,0,encrypted.bytes+1,encrypted.length,NULL,&decoded.length),CKR_OK);
      untouched("C_DecryptMessage","empty-query",&decoded,0);
      rv("C_MessageDecryptFinal","empty-query-staged",a->C_MessageDecryptFinal(f.session),CKR_OPERATION_ACTIVE);
      reset_output(&decoded,1);
      rv("C_DecryptMessage","empty-query-repeat",a->C_DecryptMessage(f.session,iv,16,NULL,0,encrypted.bytes+1,encrypted.length,NULL,&decoded.length),CKR_OK);
      untouched("C_DecryptMessage","empty-query-repeat",&decoded,0);
      rv("C_MessageDecryptFinal","empty-repeat-staged",a->C_MessageDecryptFinal(f.session),CKR_OPERATION_ACTIVE);
      reset_output(&decoded,777);
      rv("C_DecryptMessage","empty-malformed-recall",a->C_DecryptMessage(f.session,NULL,1,NULL,0,encrypted.bytes+1,encrypted.length,decoded.bytes+1,&decoded.length),CKR_ARGUMENTS_BAD);
      untouched("C_DecryptMessage","empty-malformed-recall",&decoded,777);
    }
    reset_output(&decoded,n);
    rv("C_DecryptMessage",leg,a->C_DecryptMessage(f.session,iv,16,NULL,0,encrypted.bytes+1,encrypted.length,decoded.bytes+1,&decoded.length),CKR_OK);
    output_bytes("C_DecryptMessage",leg,&decoded,input ? input : &presentEmpty,n);
    rv("C_MessageDecryptFinal","after-delivery",a->C_MessageDecryptFinal(f.session),CKR_OK);
    rv("C_MessageDecryptInit","next-pad-context",a->C_MessageDecryptInit(f.session,&padded,f.aes),CKR_OK);
  }
  /* Deterministic invalid padding: unpadded encryption of an all-zero block. */
  rv("C_EncryptInit","bad-padding-source",a->C_EncryptInit(reference.session,&cbc,reference.aes),CKR_OK);
  reset_output(&classic,16);
  rv("C_Encrypt","bad-padding-source",a->C_Encrypt(reference.session,zero,16,classic.bytes+1,&classic.length),CKR_OK);
  reset_output(&decoded,777);
  rv("C_DecryptMessage","deterministic-bad-padding",a->C_DecryptMessage(f.session,iv,16,NULL,0,classic.bytes+1,16,decoded.bytes+1,&decoded.length),CKR_ENCRYPTED_DATA_INVALID);
  untouched("C_DecryptMessage","deterministic-bad-padding",&decoded,777);
  reset_output(&decoded,0);
  rv("C_DecryptMessage","valid-after-padding-failure",a->C_DecryptMessage(f.session,iv,16,NULL,0,encrypted.bytes+1,encrypted.length,decoded.bytes+1,&decoded.length),CKR_OK);
  untouched("C_DecryptMessage","valid-empty-after-padding-failure",&decoded,0);
  rv("C_MessageEncryptFinal","pad-final",a->C_MessageEncryptFinal(f.session),CKR_OK);
  rv("C_MessageDecryptFinal","pad-final",a->C_MessageDecryptFinal(f.session),CKR_OK);

  /* Sibling slots are independently usable and independently finalized. */
  rv("C_MessageEncryptInit","sibling-init",a->C_MessageEncryptInit(f.session,&cbc,f.aes),CKR_OK);
  rv("C_MessageDecryptInit","sibling-init",a->C_MessageDecryptInit(f.session,&cbc,f.aes),CKR_OK);
  reset_output(&encrypted,16);
  rv("C_EncryptMessage","sibling-one",a->C_EncryptMessage(f.session,iv,16,NULL,0,plain,16,encrypted.bytes+1,&encrypted.length),CKR_OK);
  output_bytes("C_EncryptMessage","sibling-one",&encrypted,cipher,16);
  reset_output(&decoded,16);
  rv("C_DecryptMessage","sibling-one",a->C_DecryptMessage(f.session,iv,16,NULL,0,cipher,16,decoded.bytes+1,&decoded.length),CKR_OK);
  output_bytes("C_DecryptMessage","sibling-one",&decoded,plain,16);
  rv("C_MessageEncryptFinal","sibling-release",a->C_MessageEncryptFinal(f.session),CKR_OK);
  reset_output(&decoded,16);
  rv("C_DecryptMessage","sibling-survives",a->C_DecryptMessage(f.session,iv,16,NULL,0,cipher,16,decoded.bytes+1,&decoded.length),CKR_OK);
  output_bytes("C_DecryptMessage","sibling-survives",&decoded,plain,16);
  rv("C_MessageDecryptFinal","sibling-release",a->C_MessageDecryptFinal(f.session),CKR_OK);

  /* Both empty data pointer shapes are real HMAC messages. */
  rv("C_SignInit","empty-reference",a->C_SignInit(reference.session,&hmac,reference.mac),CKR_OK);
  reset_output(&classic,32);
  rv("C_Sign","empty-reference",a->C_Sign(reference.session,NULL,0,classic.bytes+1,&classic.length),CKR_OK);
  rv("C_MessageSignInit","empty-init",a->C_MessageSignInit(f.session,&hmac,f.mac),CKR_OK);
  rv("C_MessageVerifyInit","empty-init",a->C_MessageVerifyInit(f.session,&hmac,f.mac),CKR_OK);
  for (unsigned shape=0;shape<2;++shape) {
    CK_BYTE *input=shape ? &presentEmpty : NULL;
    const char *leg=shape ? "empty-present" : "empty-null";
    reset_output(&decoded,32);
    rv("C_SignMessage",leg,a->C_SignMessage(f.session,input,0,input,0,decoded.bytes+1,&decoded.length),CKR_OK);
    output_bytes("C_SignMessage",leg,&decoded,classic.bytes+1,32);
    rv("C_VerifyMessage",leg,a->C_VerifyMessage(f.session,input,0,input,0,classic.bytes+1,32),CKR_OK);
    rv("C_SignMessageBegin",leg,a->C_SignMessageBegin(f.session,input,0),CKR_OK);
    rv("C_SignMessageNext",leg,a->C_SignMessageNext(f.session,input,0,input,0,NULL,NULL),CKR_OK);
    reset_output(&decoded,32);
    rv("C_SignMessageNext","empty-terminal",a->C_SignMessageNext(f.session,input,0,input,0,decoded.bytes+1,&decoded.length),CKR_OK);
    output_bytes("C_SignMessageNext",leg,&decoded,classic.bytes+1,32);
    rv("C_VerifyMessageBegin",leg,a->C_VerifyMessageBegin(f.session,input,0),CKR_OK);
    rv("C_VerifyMessageNext",leg,a->C_VerifyMessageNext(f.session,input,0,input,0,NULL,0),CKR_OK);
    rv("C_VerifyMessageNext","empty-terminal",a->C_VerifyMessageNext(f.session,input,0,input,0,classic.bytes+1,32),CKR_OK);
  }
  rv("C_MessageSignFinal","empty-final",a->C_MessageSignFinal(f.session),CKR_OK);
  rv("C_MessageVerifyFinal","empty-final",a->C_MessageVerifyFinal(f.session),CKR_OK);

  rv("C_MessageEncryptInit","close-open-init",a->C_MessageEncryptInit(f.session,&cbc,f.aes),CKR_OK);
  rv("C_EncryptMessageBegin","close-open-begin",a->C_EncryptMessageBegin(f.session,iv,16,NULL,0),CKR_OK);
  close_fixture(a,f);
  f=fixture(a);
  rv("C_MessageEncryptFinal","fresh-session-no-context",a->C_MessageEncryptFinal(f.session),CKR_OPERATION_NOT_INITIALIZED);
  rv("C_MessageDecryptFinal","fresh-session-no-context",a->C_MessageDecryptFinal(f.session),CKR_OPERATION_NOT_INITIALIZED);
  rv("C_MessageSignFinal","fresh-session-no-context",a->C_MessageSignFinal(f.session),CKR_OPERATION_NOT_INITIALIZED);
  rv("C_MessageVerifyFinal","fresh-session-no-context",a->C_MessageVerifyFinal(f.session),CKR_OPERATION_NOT_INITIALIZED);
  close_fixture(a,f);
  close_fixture(a,reference);
}
```

- [ ] Implement the direct-only oversized-input probe in `tests/c/message_routed.c`.

Add `static int directProbe;` beside `failures`. In `check`, `rv`, `output_length`, and `output_bytes`, replace the literal leading `message:` in the format string with `%s:` and insert `directProbe ? "topology:direct-only-message" : "message"` as the first printf argument. This includes fixture/cleanup records in the direct-only prefix. The normal entry, length, byte, query, and multipart records retain their `message:` prefix and stay in parity.

```c
static void oversize_legs(MessageApi *a) {
  directProbe=1;
  Fixture f=fixture(a);
  Output o;
  CK_ULONG limit=16UL*1024UL*1024UL;
  CK_BYTE *large=malloc((size_t)limit);
  if (!large) exit(2);
  memset(large,0x61,(size_t)limit);
  rv("C_MessageSignInit","direct-only-init",a->C_MessageSignInit(f.session,&hmac,f.mac),CKR_OK);
  rv("C_SignMessageBegin","direct-only-begin",a->C_SignMessageBegin(f.session,NULL,0),CKR_OK);
  rv("C_SignMessageNext","direct-only-full-bound",a->C_SignMessageNext(f.session,NULL,0,large,limit,NULL,NULL),CKR_OK);
  rv("C_SignMessageNext","direct-only-accumulation-overflow",a->C_SignMessageNext(f.session,NULL,0,textBytes,1,NULL,NULL),CKR_ARGUMENTS_BAD);
  rv("C_SignMessageBegin","direct-only-begin-after-abort",a->C_SignMessageBegin(f.session,NULL,0),CKR_OK);
  rv("C_SignMessageNext","direct-only-part",a->C_SignMessageNext(f.session,NULL,0,textBytes,3,NULL,NULL),CKR_OK);
  rv("C_SignMessageNext","direct-only-session-before-bound",a->C_SignMessageNext(~0UL,NULL,0,textBytes,limit+1,NULL,NULL),CKR_SESSION_HANDLE_INVALID);
  rv("C_SignMessageNext","direct-only-single-input-too-large",a->C_SignMessageNext(f.session,NULL,0,textBytes,limit+1,NULL,NULL),CKR_ARGUMENTS_BAD);
  reset_output(&o,32);
  rv("C_SignMessageNext","direct-only-open-message-preserved",a->C_SignMessageNext(f.session,NULL,0,textBytes+3,5,o.bytes+1,&o.length),CKR_OK);
  output_bytes("C_SignMessageNext","direct-only-normal-hmac",&o,witness,32);
  rv("C_MessageSignFinal","direct-only-final",a->C_MessageSignFinal(f.session),CKR_OK);
  free(large);
  close_fixture(a,f);
  directProbe=0;
}
```

The pinned proxy has a smaller request limit, so only these explicitly labeled excessive-size probes are direct-only. Its configuration or normal transcript must not be changed to conceal routed-call failures.

- [ ] Compile the complete consumer.

```sh
cc -std=c11 -O2 -g -Wall -Wextra -Werror -Ispec/vendor tests/c/message_routed.c -ldl -lpthread -o /tmp/haskoki-message-routed
```

Expected: exit zero and no diagnostics.

- [ ] Run the consumer against exactly one freshly built module.

```sh
python3 - <<'PYCODE'
from pathlib import Path
import subprocess
modules = sorted(Path('dist-newstyle').rglob('libhaskoki.so'))
assert len(modules) == 1, 'expected one built module'
subprocess.run(['/tmp/haskoki-message-routed',str(modules[0].resolve())],check=True)
PYCODE
```

Expected: `PASS: message_routed`; all twenty names occur for every interface version, every happy leg has live behavior, and all output bytes match. If a new boundary test exposes a defect, first keep that observed failure, then correct the responsible Task 1–4 boundary code and rerun its scoped checks; changing planner/mechanism semantics is outside this plan.

- [ ] Run the scenario-inclusion assertion after consumer creation and wiring.

```sh
bash /tmp/haskoki-message-scenario-inclusion.sh
```

Expected: both drivers include the required source exactly once, and both use the same complete independence list.

- [ ] Run all direct consumers.

```sh
scripts/test-consumers.sh
```

Expected: the existing scenarios and `message_routed` pass; no discovery or classic-behavior regression.

- [ ] Run parity in the existing pinned container arrangement.

```sh
timeout -s KILL 2400 docker run --rm --network host -v "$PWD:/work" -w /work -v /opt/pkcs11-proxy-ng:/opt/pkcs11-proxy-ng:ro haskoki-dev:ghc-9.10.3 sh -c 'HASKOKI_PROXY_DIR=/opt/pkcs11-proxy-ng scripts/test-proxy-parity.sh'
```

Expected: `message_routed.direct.norm` and `message_routed.proxied.norm` are identical with normal message records retained. Inspect the raw logs for exact CKR, lengths, and hex, not just the PASS line. A genuine canonical-shim discrepancy receives source-backed triage and remains visible; it does not authorize weaker consumer assertions or new unconditional exclusions.

- [ ] Commit Task 5.

```sh
git add tests/c/message_routed.c scripts/test-consumers.sh scripts/test-proxy-parity.sh
git commit -m "test: exercise message tables per routing spec sections 3.6 5.2 and 5.3"
```

### Task 6: Contract evidence and reachability documentation

**Files:** Modify/test `spec/function-contracts.json`, `docs/demo-walkthrough.md`, and `cbits/exports.c`; temporary test `/tmp/haskoki-message-contracts.sh`.

**Interfaces:** Consumes the executed `message_routed` transcript from Task 5 and existing JSON function rows. Produces exactly one appended `{ "suite": "test-consumers.sh", "spec": "tests/c/message_routed.c" }` evidence object per message row, without changing existing fields. C and Haskell callable signatures remain unchanged; this task changes JSON and prose only.

- [ ] Write `/tmp/haskoki-message-contracts.sh` with this contract/documentation assertion.

```sh
python3 - <<'PYCODE'
import json, subprocess
from pathlib import Path
names = {
    "C_MessageEncryptInit",
    "C_EncryptMessage",
    "C_EncryptMessageBegin",
    "C_EncryptMessageNext",
    "C_MessageEncryptFinal",
    "C_MessageDecryptInit",
    "C_DecryptMessage",
    "C_DecryptMessageBegin",
    "C_DecryptMessageNext",
    "C_MessageDecryptFinal",
    "C_MessageSignInit",
    "C_SignMessage",
    "C_SignMessageBegin",
    "C_SignMessageNext",
    "C_MessageSignFinal",
    "C_MessageVerifyInit",
    "C_VerifyMessage",
    "C_VerifyMessageBegin",
    "C_VerifyMessageNext",
    "C_MessageVerifyFinal",
}
old = json.loads(subprocess.check_output(['git','show','d476e97:spec/function-contracts.json']))
new = json.loads(Path('spec/function-contracts.json').read_text())
evidence = {'suite':'test-consumers.sh','spec':'tests/c/message_routed.c'}
oldrows = {row['name']:row for row in old['functions']}
assert sum(row['contract']=='planned-with-behavior' for row in new['functions']) == 70
assert len(new['functions']) == len(old['functions'])
for row in new['functions']:
    previous = oldrows[row['name']]
    if row['name'] in names:
        assert row['contract'] == 'planned-with-behavior'
        assert row['test_evidence'].count(evidence) == 1, row['name'] + ' missing unique C evidence'
        restored = dict(row)
        restored['test_evidence'] = [item for item in row['test_evidence'] if item != evidence]
        assert restored == previous, row['name'] + ' changed an existing contract field'
    else:
        assert row == previous, row['name'] + ' outside scope'
for name in ['spec/mechanisms.json','cbits/mech_catalog.inc']:
    assert Path(name).read_bytes() == subprocess.check_output(['git','show','d476e97:' + name])
walk = Path('docs/demo-walkthrough.md').read_text()
assert 'message_routed' in walk and '2026-09-30 message routing' in walk
assert '316' in walk and 'historical' in walk
assert '(in-process proofs vs the 130-row C surface).' in walk
assert 'every other post-2.40' not in Path('cbits/exports.c').read_text().split('*/',1)[0]
print('PASS: twenty evidence appends, seventy planner contracts, preserved catalog and historical text')
PYCODE
```

- [ ] Run the contract assertion before editing evidence.

```sh
bash /tmp/haskoki-message-contracts.sh
```

Expected failure: `C_MessageEncryptInit missing unique C evidence` (the first message row in inventory order). Capture the actual first failing row; a missing runtime consumer result is a reason to finish Task 5 before attaching evidence.

- [ ] Append the exact evidence object to the twenty JSON rows using this update.

```sh
python3 - <<'PYCODE'
import json
from pathlib import Path
path=Path('spec/function-contracts.json')
data=json.loads(path.read_text())
names={
    "C_MessageEncryptInit",
    "C_EncryptMessage",
    "C_EncryptMessageBegin",
    "C_EncryptMessageNext",
    "C_MessageEncryptFinal",
    "C_MessageDecryptInit",
    "C_DecryptMessage",
    "C_DecryptMessageBegin",
    "C_DecryptMessageNext",
    "C_MessageDecryptFinal",
    "C_MessageSignInit",
    "C_SignMessage",
    "C_SignMessageBegin",
    "C_SignMessageNext",
    "C_MessageSignFinal",
    "C_MessageVerifyInit",
    "C_VerifyMessage",
    "C_VerifyMessageBegin",
    "C_VerifyMessageNext",
    "C_MessageVerifyFinal",
}
evidence={'suite':'test-consumers.sh','spec':'tests/c/message_routed.c'}
seen=set()
for row in data['functions']:
    if row['name'] in names:
        assert row['contract']=='planned-with-behavior'
        assert evidence not in row['test_evidence']
        row['test_evidence'].append(evidence)
        seen.add(row['name'])
assert seen==names
path.write_text(json.dumps(data,indent=2)+'\n')
PYCODE
```

- [ ] Insert the following bullet into section 3 of `docs/demo-walkthrough.md` after the existing consumer bullets.

```markdown
- `message_routed`: all twenty message-family entries through the actual
  3.0, 3.1, and 3.2 tables, with fixed AES-CBC and SHA-256 HMAC bytes;
  multipart end signals, two messages per outer init, lifecycle and argument
  precedence, query and repeated-query recall, output canaries, empty
  CBC-PAD output, padding refusal, classic/message collisions, and sibling
  session-slot isolation. Normal calls run in direct/proxy parity; the
  explicitly labeled 16 MiB input/accumulation probes run directly because
  the pinned proxy has its own smaller request limit.
```

- [ ] Insert this dated note immediately after the existing 130-row boundary paragraph in section 5, leaving that paragraph's wording intact.

```markdown
**2026-09-30 message routing:** The 130-row C-surface boundary note above is
historical. At the inspected revision, the `support.real == "tested"`
projection in `spec/mechanisms.json` and `HASKOKI_MECH_COUNT` in
`cbits/mech_catalog.inc` both contain 316 mechanisms. This change routes
20 functions through the existing message planner; it changes neither
that catalog nor any mechanism flags and advertises no new
`CKF_MESSAGE_*` or `CKF_MULTI_MESSAGE` capability. The consumer demonstrates
function-level CBC/HMAC reachability on interfaces 3.0, 3.1, and 3.2,
without making a general v3.0 conformance claim. The function contracts
retain their planner-scoped `planned-with-behavior` label and add the
executed C consumer as evidence.
```

- [ ] Replace the stale post-2.40 routing sentences in the leading `cbits/exports.c` comment with this text.

```c
 * The generated cbits/abi_stubs.inc preserves exact pinned prototypes
 * and table order. C_GetInterfaceList and C_GetInterface remain discovery
 * globals callable before initialization. C_SessionCancel and all twenty
 * message-family entries use standard_surface.c bodies in every 3.x
 * table; C_EncapsulateKey and C_DecapsulateKey retain their existing 3.2
 * routes. The remaining generated entries retain lifecycle-aware stubs.
 * Message routing changes function reachability, not mechanism advertising.
```

Replace only the paragraph beginning with `The 24 + 12 post-2.40 entries` through its `NOT_SUPPORTED once live).` ending, preserving the preceding legacy-layout explanation and following discovery paragraph. Keep the `130` sentences in the walkthrough unchanged; do not rewrite old denominator prose elsewhere.

- [ ] Run the contract assertion after the evidence and prose edits.

```sh
bash /tmp/haskoki-message-contracts.sh
```

Expected: exactly twenty evidence additions, all other JSON row content intact, seventy planner-scoped contracts, unchanged catalog bytes, and the historical note retained beside the new note.

- [ ] Run the targeted documentation and denominator checks.

```sh
python3 scripts/check-denominators.py
python3 scripts/check-docs.py
python3 scripts/check-release-pivots.py
```

Expected: all three exit zero. No new quoted function-name denominator field or catalog row is introduced.

- [ ] Commit Task 6.

```sh
git add spec/function-contracts.json docs/demo-walkthrough.md cbits/exports.c
git commit -m "docs: attach message evidence per routing spec sections 3.6 and 6"
```

### Task 7: Revision-bound gates, lanes, and oracle dispositions

**Files:** Modify/test `docs/pkcs11-oracle-triage.md` and `docs/pkcs11-check-upstream-issues.md`; temporary tests `/tmp/haskoki-message-verification/check.py` and `/tmp/haskoki-message-verification/oracle-repro.c`; runtime evidence `dist-release-evidence/message-routing/`. No production implementation change belongs to this task.

**Interfaces:** Consumes the Task 5 executable, existing `scripts/run-gates.sh`, `scripts/release-evidence.sh`, and `scripts/ci-pkcs11-lane.sh`. Produces a JSON evidence block under `## Message routing verification (2026-09-30)` in each oracle document and raw revision/hash/log/result/trace records in the evidence directory. The reproduction consumes `CK_C_GetInterface` and `MessageApi` from the independent consumer; its entry is `int main(int argc, char **argv)`. No new Haskell or provider-C signature is introduced.

- [ ] Write `/tmp/haskoki-message-verification/check.py` with this acceptance test after creating its parent directory.

```python
import json
from pathlib import Path
heading = '## Message routing verification (2026-09-30)'
records = []
for filename in ['docs/pkcs11-oracle-triage.md','docs/pkcs11-check-upstream-issues.md']:
    text = Path(filename).read_text()
    assert heading in text, filename + ' has no message-routing revision evidence'
    section = text.split(heading,1)[1]
    record = json.loads(section.split('```json\n',1)[1].split('```',1)[0])
    assert len(record['source_revision']) == 40
    assert len(record['module_sha256']) == 64
    assert len(record['bundle_sha256']) == 64
    assert record['oracle_release'] == '0.2.2rc2'
    assert record['source_test_definitions'] == {'test_mech_message.py':26,'test_message_crypto.py':13}
    assert record['commands']['gates']['exit'] == 0
    assert record['commands']['fast']['exit'] == 0
    assert record['commands']['kat']['exit'] == 0
    for lane in ['fast','kat']:
        assert record['lanes'][lane]['result_path'].endswith('pkcs11-' + lane + '-results.json')
        assert record['lanes'][lane]['trace_path'].endswith('trace.jsonl')
        assert record['lanes'][lane]['reviewed'] is True
        assert record['lanes'][lane]['unexplained_new_findings'] == 0
        assert record['lanes'][lane]['provider_defects'] == 0
        assert record['lanes'][lane]['summary'].get('error',0) == 0
        assert record['lanes'][lane]['summary'].get('crashed',0) == 0
        assert record['lanes'][lane]['summary'].get('timeout',0) == 0
        assert not record['lanes'][lane]['summary'].get('incomplete',False)
    for finding in record['dispositions']:
        assert finding['classification'] in ['provider','oracle','capability coverage']
        for key in ['node_parameter','actual','expected','reproduction','normative_source','status']:
            assert finding[key].strip()
        assert finding['classification'] != 'provider', 'unresolved provider defect blocks acceptance'
        if finding['classification'] == 'oracle':
            assert finding['url'].startswith('https://github.com/mingulov/pkcs11-check/issues/')
    assert record['scope'] == 'function routing; unchanged 316-mechanism catalog'
    records.append(record)
assert records[0] == records[1], 'oracle documents disagree'
print('PASS: revision evidence and classified oracle dispositions agree')
```

- [ ] Run the acceptance test before qualification or documentation edits.

```sh
python3 /tmp/haskoki-message-verification/check.py
```

Expected failure: `docs/pkcs11-oracle-triage.md has no message-routing revision evidence`. Retain this observed failure. Do not interpret the old lane result files as new implementation evidence.

- [ ] Create the evidence directory and preserve existing lane result/trace files before the wrapper overwrites them.

```sh
python3 - <<'PYCODE'
from pathlib import Path
import shutil
root=Path('dist-release-evidence/message-routing')
root.mkdir(parents=True,exist_ok=False)
for lane in ['fast','kat']:
    previous=Path('/tmp/pkcs11-ws/out-rc2')/lane
    for name in ['pkcs11-' + lane + '-results.json','trace.jsonl']:
        source=previous/name
        if source.is_file():
            shutil.copy2(source,root/(lane + '-before-' + name))
PYCODE
```

The saved files are comparison inputs only. Establish their provenance from the existing qualification records before treating a difference as a regression; unproven old results cannot establish acceptance.

- [ ] Record the implementation revision, protected input hashes, toolchain image, and oracle source pin.

```sh
python3 - <<'PYCODE'
import ast, hashlib, json, subprocess
from pathlib import Path
root=Path('dist-release-evidence/message-routing')
oracle=Path('/tmp/pkcs11-ws/pkcs11-check-0.2.2rc2')
counts={}
sources={}
for name,want in [('test_mech_message.py',26),('test_message_crypto.py',13)]:
    path=oracle/'src/pkcs11_check/testcases'/name
    raw=path.read_bytes()
    tree=ast.parse(raw)
    count=sum(isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef)) and node.name.startswith('test_') for node in ast.walk(tree))
    assert count==want, (name,count,want)
    counts[name]=count
    sources[name]=hashlib.sha256(raw).hexdigest()
source_hash=hashlib.sha256()
for path in sorted((oracle/'src').rglob('*.py')):
    source_hash.update(str(path.relative_to(oracle)).encode()+b'\0'+path.read_bytes()+b'\0')
record={
 'source_revision':subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip(),
 'oracle_release':'0.2.2rc2',
 'oracle_source_sha256':source_hash.hexdigest(),
 'source_test_definitions':counts,
 'oracle_test_source_sha256':sources,
 'protected_sha256':{name:hashlib.sha256(Path(name).read_bytes()).hexdigest() for name in ['spec/vendor/pkcs11.h','spec/sources.lock.json','spec/mechanisms.json','cbits/mech_catalog.inc']},
 'toolchain_image':subprocess.check_output(['docker','image','inspect','haskoki-dev:ghc-9.10.3','--format','{{.Id}}'],text=True).strip(),
 'scope':'function routing; unchanged 316-mechanism catalog'
}
(root/'pins.json').write_text(json.dumps(record,indent=2)+'\n')
print(json.dumps(record,indent=2))
PYCODE
```

The local oracle directory is a release source tree, not necessarily a Git checkout. Its release name plus deterministic source digest is the oracle revision evidence; do not invent a Git SHA. Source definition counts are separate from collection, execution, skip, and finding dispositions.

- [ ] Run the final message model/decoder group in the pinned toolchain.

```sh
timeout -s KILL 2400 docker run --rm --network host -v "$PWD:/work" -w /work haskoki-dev:ghc-9.10.3 cabal test haskoki-model-tests --test-option='--pattern=message operations'
```

Expected: all seventeen original cases and all seven new decoder cases pass.

- [ ] Run the final Standard boundary group in the pinned toolchain.

```sh
timeout -s KILL 2400 docker run --rm --network host -v "$PWD:/work" -w /work haskoki-dev:ghc-9.10.3 cabal test haskoki-model-tests --test-option='--pattern=Standard surface'
```

Expected: the existing cases and all five new message-dialogue cases pass.

- [ ] Run the direct consumers in the pinned toolchain.

```sh
timeout -s KILL 2400 docker run --rm --network host -v "$PWD:/work" -w /work haskoki-dev:ghc-9.10.3 scripts/test-consumers.sh
```

Expected: `message_routed` and every existing scenario pass. Confirm all twenty entry names have happy legs for each version.

- [ ] Run the canonical proxy comparison.

```sh
timeout -s KILL 2400 docker run --rm --network host -v "$PWD:/work" -w /work -v /opt/pkcs11-proxy-ng:/opt/pkcs11-proxy-ng:ro haskoki-dev:ghc-9.10.3 sh -c 'HASKOKI_PROXY_DIR=/opt/pkcs11-proxy-ng scripts/test-proxy-parity.sh'
```

Expected: identical normal records across topologies; the only direct-only block is explicitly excessive input. Keep the external daemon/shim pair and provenance checks intact.

- [ ] Run all eighteen gates and their forced build, full suites, fourteen evidence drivers, release build, and clean installation check from the host.

```sh
python3 - <<'PYCODE'
import json, os, subprocess
from pathlib import Path
root=Path('dist-release-evidence/message-routing')
env=dict(os.environ,HASKOKI_PROXY_DIR='/opt/pkcs11-proxy-ng',HASKOKI_EVIDENCE_DIR=str((root/'gates').resolve()))
command=['bash','scripts/run-gates.sh']
with (root/'gates.log').open('w') as log:
    result=subprocess.run(command,env=env,stdout=log,stderr=subprocess.STDOUT)
(root/'gates-command.json').write_text(json.dumps({'command':'HASKOKI_PROXY_DIR=/opt/pkcs11-proxy-ng bash scripts/run-gates.sh','exit':result.returncode,'log':str(root/'gates.log')},indent=2)+'\n')
assert result.returncode==0, 'gate failure; inspect gates.log'
PYCODE
```

Expected: every named static check in `scripts/run-gates.sh`, forced `cabal build all --enable-tests`, `cabal test all`, and all release manifest entries succeed. Read `gates/MANIFEST.txt`; neither an earlier build nor a partial driver run meets this step.

- [ ] Bind the newly built release bundle to the recorded source revision.

```sh
python3 - <<'PYCODE'
import hashlib, json
from pathlib import Path
root=Path('dist-release-evidence/message-routing')
bundles=[p for p in Path('dist-release').glob('haskoki-*') if p.is_dir() and (p/'lib/libhaskoki.so').is_file()]
assert len(bundles)==1, 'lane wrapper requires one unambiguous fresh bundle'
bundle=bundles[0]
hash_bundle=hashlib.sha256()
for path in sorted(bundle.rglob('*')):
    if path.is_file():
        hash_bundle.update(str(path.relative_to(bundle)).encode()+b'\0'+path.read_bytes()+b'\0')
record=json.loads((root/'pins.json').read_text())
record.update(bundle_path=str(bundle.resolve()),bundle_sha256=hash_bundle.hexdigest(),module_sha256=hashlib.sha256((bundle/'lib/libhaskoki.so').read_bytes()).hexdigest())
(root/'pins.json').write_text(json.dumps(record,indent=2)+'\n')
print(record['bundle_path'],record['module_sha256'],record['bundle_sha256'])
PYCODE
```

Expected: the module is from this gate run and the source revision in `gates/MANIFEST.txt` matches `pins.json`. Do not allow the wrapper's wildcard to select an older artifact.

- [ ] Run the fast lane and record its command exit.

```sh
python3 - <<'PYCODE'
import json, subprocess
from pathlib import Path
root=Path('dist-release-evidence/message-routing')
command=['bash','/tmp/pkcs11-ws/run-lane-rc2.sh','fast']
with (root/'fast.log').open('w') as log:
    result=subprocess.run(command,stdout=log,stderr=subprocess.STDOUT)
(root/'fast-command.json').write_text(json.dumps({'command':'bash /tmp/pkcs11-ws/run-lane-rc2.sh fast','exit':result.returncode,'log':str(root/'fast.log')},indent=2)+'\n')
assert result.returncode==0, 'fast wrapper failed; inspect fast.log'
PYCODE
```

- [ ] Inspect the fast results and trace before starting kat.

```sh
python3 - <<'PYCODE'
import hashlib,json
from pathlib import Path
root=Path('dist-release-evidence/message-routing')
result=Path('/tmp/pkcs11-ws/out-rc2/fast/pkcs11-fast-results.json')
trace=result.with_name('trace.jsonl')
data=json.loads(result.read_text())
assert trace.is_file()
print(json.dumps(data['summary'],indent=2))
for unit in data.get('units',[]):
    for test in unit.get('tests',[]):
        if 'message' in test.get('nodeid','') or test.get('outcome') not in ['passed','skipped']:
            print(json.dumps(test,sort_keys=True))
for name,path in [('result',result),('trace',trace)]:
    print(name,str(path),hashlib.sha256(path.read_bytes()).hexdigest())
(root/'fast-reviewed-input.json').write_text(json.dumps(data,indent=2)+'\n')
PYCODE
```

Inspect every new disagreement, crash, error, timeout, and regression against the preserved comparison inputs and their provenance. Inspect message-node skip reasons and the actual `trace.jsonl` records. Source counts `26` and `13`, flag-based skips, or wrapper exit zero are never substitutes for a successful routed call. Proceed to kat only once fast has no unexplained new findings and no unresolved newly routed provider defect.

- [ ] Run the kat lane and record its command exit.

```sh
python3 - <<'PYCODE'
import json, subprocess
from pathlib import Path
root=Path('dist-release-evidence/message-routing')
command=['bash','/tmp/pkcs11-ws/run-lane-rc2.sh','kat']
with (root/'kat.log').open('w') as log:
    result=subprocess.run(command,stdout=log,stderr=subprocess.STDOUT)
(root/'kat-command.json').write_text(json.dumps({'command':'bash /tmp/pkcs11-ws/run-lane-rc2.sh kat','exit':result.returncode,'log':str(root/'kat.log')},indent=2)+'\n')
assert result.returncode==0, 'kat wrapper failed; inspect kat.log'
PYCODE
```

- [ ] Inspect the kat results and trace.

```sh
python3 - <<'PYCODE'
import hashlib,json
from pathlib import Path
root=Path('dist-release-evidence/message-routing')
result=Path('/tmp/pkcs11-ws/out-rc2/kat/pkcs11-kat-results.json')
trace=result.with_name('trace.jsonl')
data=json.loads(result.read_text())
assert trace.is_file()
print(json.dumps(data['summary'],indent=2))
for unit in data.get('units',[]):
    for test in unit.get('tests',[]):
        if 'message' in test.get('nodeid','') or test.get('outcome') not in ['passed','skipped']:
            print(json.dumps(test,sort_keys=True))
for name,path in [('result',result),('trace',trace)]:
    print(name,str(path),hashlib.sha256(path.read_bytes()).hexdigest())
(root/'kat-reviewed-input.json').write_text(json.dumps(data,indent=2)+'\n')
PYCODE
```

Expected: no unexplained new findings, crashes, setup errors, regressions, or unresolved provider defect in the new routes. Record collected, executed, skipped, expected-failure, and actual-failure counts independently. Existing documented oracle defects stay visible as findings, not successful provider tests.

- [ ] Write the independent CBC oracle-shape reproduction to `/tmp/haskoki-message-verification/oracle-repro.c`.

```c
#define main message_consumer_main
#include "tests/c/message_routed.c"
#undef main
int main(int argc,char **argv) {
  if (argc!=2) return 2;
  configure();
  void *module=dlopen(argv[1],RTLD_NOW|RTLD_LOCAL);
  if (!module) return 2;
  CK_C_GetInterface get=(CK_C_GetInterface)dlsym(module,"C_GetInterface");
  CK_VERSION version={3,2}; CK_INTERFACE_PTR interface=NULL;
  if (!get || get(NULL,&version,&interface,0)!=CKR_OK) return 2;
  minor=2;
  MessageApi a=read_newest((CK_FUNCTION_LIST_3_2 *)interface->pFunctionList);
  if (a.C_Initialize(NULL)!=CKR_OK) return 2;
  CK_SLOT_ID slots[16]; CK_ULONG count=16;
  if (a.C_GetSlotList(CK_TRUE,slots,&count)!=CKR_OK || count==0 || count>16) return 2;
  tokenSlot=slots[0];
  Fixture f=fixture(&a);
  CK_MECHANISM missingIv={CKM_AES_CBC,NULL,0};
  CK_RV init=a.C_MessageEncryptInit(f.session,&missingIv,f.aes);
  printf("probe: CBC init without IV rv=0x%lx\n",init);
  if (init==CKR_OK) {
    CK_RV begin=a.C_EncryptMessageBegin(f.session,NULL,0,plain,16);
    printf("probe: Begin with plaintext as AAD rv=0x%lx\n",begin);
    if (begin==CKR_OK) {
      Output o; reset_output(&o,64);
      CK_RV next=a.C_EncryptMessageNext(f.session,NULL,0,NULL,0,o.bytes+1,&o.length,CKF_END_OF_MESSAGE);
      printf("probe: empty terminal part rv=0x%lx length=%lu\n",next,o.length);
    }
  }
  close_fixture(&a,f);
  rv("C_Finalize","probe-cleanup",a.C_Finalize(NULL),CKR_OK);
  dlclose(module); unlink(configPath);
  return failures ? 1 : 0;
}
```

This reproduces the source shape of `TestMessageEncryptDecrypt.test_message_encrypt_multipart`. It reports actual codes; it does not predeclare that an unexecuted oracle lead is a defect or change the supported CBC recipe.

- [ ] Compile the reproduction.

```sh
cc -std=c11 -O2 -g -Wall -Wextra -Werror -Ispec/vendor -I"$PWD" /tmp/haskoki-message-verification/oracle-repro.c -ldl -lpthread -o /tmp/haskoki-message-verification/oracle-repro
```

Expected: exit zero without diagnostics.

- [ ] Run the reproduction on the just-qualified bundle.

```sh
python3 - <<'PYCODE'
import json,subprocess
from pathlib import Path
root=Path('dist-release-evidence/message-routing')
pins=json.loads((root/'pins.json').read_text())
module=Path(pins['bundle_path'])/'lib/libhaskoki.so'
with (root/'oracle-cbc-reproduction.log').open('w') as log:
    result=subprocess.run(['/tmp/haskoki-message-verification/oracle-repro',str(module)],stdout=log,stderr=subprocess.STDOUT)
assert result.returncode==0, 'reproduction setup failed'
print((root/'oracle-cbc-reproduction.log').read_text())
PYCODE
```

For each additional newly exposed disagreement, reduce the observed consumer sequence using these same fixture/discovery functions and its exact node parameters, then preserve its exact command and transcript with the disposition. Do not alter acceptance sets, add unconditional skips, or change core semantics to satisfy a discrepant oracle shape.

- [ ] Capture the measured dispositions in `/tmp/haskoki-message-verification/dispositions.json` with this code, executed by the worker in a terminal. The inputs come from the worker's completed source/runtime review; no end-user approval is required. Give the exact node parameters, actual/expected CKR or bytes, an executable reproduction command and its observed output, and the normative source section. A zero count is permitted only after reviewing all newly exposed findings.

```python
import json
from pathlib import Path
items=[]
count=int(input('Number of newly investigated disagreements: '))
for index in range(count):
    item={}
    for key in ['node_parameter','actual','expected','reproduction','normative_source','classification']:
        item[key]=input(str(index+1)+' '+key+': ').strip()
        assert item[key]
    assert item['classification'] in ['provider','oracle','capability coverage']
    item['status']='provider correction required' if item['classification']=='provider' else 'source and runtime review complete'
    items.append(item)
Path('/tmp/haskoki-message-verification/dispositions.json').write_text(json.dumps(items,indent=2)+'\n')
assert not any(item['classification']=='provider' for item in items), 'provider defect blocks acceptance; preserve reproduction and correct only within scope'
```

Expected: every new finding has a concrete classification and reproducible evidence. A planning/mechanism defect is an explicit scope blocker. Mechanism-flag skips remain capability coverage and cannot count toward the twenty-entry consumer proof.

- [ ] Materialize an issue body for every established oracle defect from those measured fields.

```sh
python3 - <<'PYCODE'
import json
from pathlib import Path
root=Path('/tmp/haskoki-message-verification')
items=json.loads((root/'dispositions.json').read_text())
pins=json.loads(Path('dist-release-evidence/message-routing/pins.json').read_text())
for index,item in enumerate(items):
    if item['classification']!='oracle':
        continue
    body='\n\n'.join([
      'Oracle node and parameter: '+item['node_parameter'],
      'Actual result: '+item['actual'],
      'Expected result: '+item['expected'],
      'Independent reproduction and observed output:\n'+item['reproduction'],
      'Normative source: '+item['normative_source'],
      'Provider source revision: '+pins['source_revision'],
      'Module SHA-256: '+pins['module_sha256'],
      'Oracle release: '+pins['oracle_release'],
      'Oracle source SHA-256: '+pins['oracle_source_sha256']
    ])+'\n'
    (root/('upstream-issue-'+str(index+1)+'.md')).write_text(body)
PYCODE
```

For a Sign/Verify end-signal disagreement, the normative field cites the relevant PKCS#11 v3.0 section 5.14.4 or 5.16.4. For the CBC source lead, distinguish the oracle's actual shape from this routing spec's existing opaque-IV recipe; an unexecuted source observation alone does not justify a filing.

- [ ] File each established oracle defect and record the returned URL/status using the exact generated body file.

```sh
python3 - <<'PYCODE'
import json,subprocess
from pathlib import Path
root=Path('/tmp/haskoki-message-verification')
path=root/'dispositions.json'
items=json.loads(path.read_text())
for index,item in enumerate(items):
    if item['classification']=='oracle':
        body=root/('upstream-issue-'+str(index+1)+'.md')
        title='Message API oracle: '+item['node_parameter']
        url=subprocess.check_output(['gh','issue','create','--repo','mingulov/pkcs11-check','--title',title,'--body-file',str(body)],text=True).strip()
        state=json.loads(subprocess.check_output(['gh','issue','view',url,'--repo','mingulov/pkcs11-check','--json','url,state'],text=True))
        item['url']=state['url']
        item['status']=state['state']
    else:
        item['url']=''
        item['status']='capability coverage; not a successful routed provider test'
    path.write_text(json.dumps(items,indent=2)+'\n')
PYCODE
```

Expected: only established oracle defects are filed, with actual issue URLs/statuses retained. If there are no such defects this command performs no external mutation. A filing failure leaves upstream evidence incomplete; do not describe it as filed or broaden acceptance.

- [ ] Write reviewed lane evidence and the completed dispositions into both oracle documents using this code in a terminal. Each `reviewed` response asserts that the worker inspected the findings and trace; it is evidence intake, not a replacement for that inspection.

```python
import hashlib,json,runpy,shutil
from pathlib import Path
root=Path('dist-release-evidence/message-routing')
record=json.loads((root/'pins.json').read_text())
record['commands']={name:json.loads((root/(name+'-command.json')).read_text()) for name in ['gates','fast','kat']}
record['lanes']={}
for lane in ['fast','kat']:
    result=Path('/tmp/pkcs11-ws/out-rc2')/lane/('pkcs11-'+lane+'-results.json')
    trace=result.with_name('trace.jsonl')
    data=json.loads(result.read_text())
    assert input(lane+': enter reviewed after inspecting every new finding and trace: ').strip()=='reviewed'
    unexplained=int(input(lane+': unexplained new finding count: '))
    defects=int(input(lane+': unresolved routed provider defect count: '))
    assert unexplained==0 and defects==0, 'acceptance blocked; preserve evidence and correct only within scope'
    archive=root/'reviewed'/lane
    archive.mkdir(parents=True,exist_ok=False)
    shutil.copy2(result,archive/result.name)
    shutil.copy2(trace,archive/trace.name)
    record['lanes'][lane]={
      'result_path':str(result),'trace_path':str(trace),
      'result_archive':str(archive/result.name),'trace_archive':str(archive/trace.name),
      'result_sha256':hashlib.sha256(result.read_bytes()).hexdigest(),
      'trace_sha256':hashlib.sha256(trace.read_bytes()).hexdigest(),
      'summary':data['summary'],'reviewed':True,
      'unexplained_new_findings':unexplained,'provider_defects':defects,
      'runtime_dispositions':[test for unit in data.get('units',[]) for test in unit.get('tests',[]) if 'message' in test.get('nodeid','')]
    }
record['dispositions']=json.loads(Path('/tmp/haskoki-message-verification/dispositions.json').read_text())
assert not any(item['classification']=='provider' for item in record['dispositions'])
record['oracle_cbc_probe']=(root/'oracle-cbc-reproduction.log').read_text()
serialized=json.dumps(record,indent=2)
# Preserve exact JSON values while keeping historical identifiers out of prose.
for _,pattern in runpy.run_path('scripts/check-history-codes.py')['PATTERNS']:
    serialized=pattern.sub(lambda match: ''.join('\\u'+format(ord(c),'04x') for c in match.group()),serialized)
assert json.loads(serialized)==record
heading='## Message routing verification (2026-09-30)'
section='\n'+heading+'\n\nThe source definition counts are pins; runtime dispositions and oracle findings remain separate. Routing adds no mechanism capability.\n\n```json\n'+serialized+'\n```\n'
for name in ['docs/pkcs11-oracle-triage.md','docs/pkcs11-check-upstream-issues.md']:
    path=Path(name)
    text=path.read_text()
    assert heading not in text, 'retain the prior record before adding another qualification'
    path.write_text(text+section)
(root/'reviewed-record.json').write_text(serialized+'\n')
```

Expected: both documents preserve their existing evidence and append identical measured records. The record includes actual CBC reproduction output, source and module pins, command exits, per-lane paths/hashes, runtime dispositions, and completed upstream status. No deferred value or fabricated pass is permitted.

- [ ] Run the acceptance test after both documents contain measured evidence.

```sh
python3 /tmp/haskoki-message-verification/check.py
```

Expected: the two records agree, gates/lane commands succeeded, source and artifact hashes are present, runtime findings are reviewed, and every oracle defect has its actual issue link.

- [ ] Run the targeted documentation checks.

```sh
python3 scripts/check-docs.py
python3 scripts/check-denominators.py
python3 scripts/check-history-codes.py
```

Expected: all exit zero; the twenty contracts and unchanged catalog remain intact.

- [ ] Commit Task 7.

```sh
git add docs/pkcs11-oracle-triage.md docs/pkcs11-check-upstream-issues.md
git commit -m "docs: record message qualification per routing spec sections 5.4 and 6"
```

- [ ] Run the final-revision gates after the documentation commit, capturing the final HEAD and command exit.

```sh
python3 - <<'PYCODE'
import json,os,subprocess
from pathlib import Path
root=Path('dist-release-evidence/message-routing/final')
root.mkdir(parents=True,exist_ok=False)
revision=subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip()
env=dict(os.environ,HASKOKI_PROXY_DIR='/opt/pkcs11-proxy-ng',HASKOKI_EVIDENCE_DIR=str((root/'gates').resolve()))
with (root/'gates.log').open('w') as log:
    result=subprocess.run(['bash','scripts/run-gates.sh'],env=env,stdout=log,stderr=subprocess.STDOUT)
record={'source_revision':revision,'command':'HASKOKI_PROXY_DIR=/opt/pkcs11-proxy-ng bash scripts/run-gates.sh','exit':result.returncode,'log':str(root/'gates.log')}
(root/'gates-command.json').write_text(json.dumps(record,indent=2)+'\n')
assert result.returncode==0
assert 'rev: '+revision in (root/'gates/MANIFEST.txt').read_text()
PYCODE
```

Expected: all eighteen gates, forced build, all suites, release evidence, and installation pass at the final HEAD; the manifest names that HEAD. The earlier successful revision does not qualify subsequent edits.

- [ ] Record the final bundle/module digests after that gate run.

```sh
python3 - <<'PYCODE'
import hashlib,json,subprocess
from pathlib import Path
root=Path('dist-release-evidence/message-routing/final')
bundles=[p for p in Path('dist-release').glob('haskoki-*') if p.is_dir() and (p/'lib/libhaskoki.so').is_file()]
assert len(bundles)==1
bundle=bundles[0]
digest=hashlib.sha256()
for path in sorted(bundle.rglob('*')):
    if path.is_file(): digest.update(str(path.relative_to(bundle)).encode()+b'\0'+path.read_bytes()+b'\0')
record=json.loads(Path('dist-release-evidence/message-routing/pins.json').read_text())
record.update(source_revision=subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip(),bundle_path=str(bundle.resolve()),bundle_sha256=digest.hexdigest(),module_sha256=hashlib.sha256((bundle/'lib/libhaskoki.so').read_bytes()).hexdigest())
(root/'pins.json').write_text(json.dumps(record,indent=2)+'\n')
print(json.dumps(record,indent=2))
PYCODE
```

Expected: the final gate run and these hashes identify one fresh bundle; the oracle source digest and pinned source-definition counts remain those reviewed earlier.

- [ ] Run the fast lane against the final bundle and archive its raw outputs.

```sh
python3 - <<'PYCODE'
import json,shutil,subprocess
from pathlib import Path
root=Path('dist-release-evidence/message-routing/final')
with (root/'fast.log').open('w') as log:
    result=subprocess.run(['bash','/tmp/pkcs11-ws/run-lane-rc2.sh','fast'],stdout=log,stderr=subprocess.STDOUT)
(root/'fast-command.json').write_text(json.dumps({'command':'bash /tmp/pkcs11-ws/run-lane-rc2.sh fast','exit':result.returncode,'log':str(root/'fast.log')},indent=2)+'\n')
assert result.returncode==0
archive=root/'fast'
archive.mkdir(exist_ok=False)
source=Path('/tmp/pkcs11-ws/out-rc2/fast')
shutil.copy2(source/'pkcs11-fast-results.json',archive/'pkcs11-fast-results.json')
shutil.copy2(source/'trace.jsonl',archive/'trace.jsonl')
PYCODE
```

- [ ] Inspect the archived final fast findings before running kat.

```sh
python3 - <<'PYCODE'
import hashlib,json
from pathlib import Path
root=Path('dist-release-evidence/message-routing')
path=root/'final/fast/pkcs11-fast-results.json'
trace=path.with_name('trace.jsonl')
actual=json.loads(path.read_text())
previous=json.loads((root/'reviewed/fast/pkcs11-fast-results.json').read_text())
def findings(data):
    return {(item.get('nodeid',''),item.get('outcome',''),str(item.get('wasxfail','')),str(item.get('longrepr',''))) for unit in data.get('units',[]) for item in unit.get('tests',[]) if item.get('outcome') not in ['passed','skipped']}
new=findings(actual)-findings(previous)
print(json.dumps(actual['summary'],indent=2))
for item in sorted(new): print(json.dumps(item))
for unit in actual.get('units',[]):
    for item in unit.get('tests',[]):
        if 'message' in item.get('nodeid',''): print(json.dumps(item,sort_keys=True))
for key in ['error','crashed','timeout','child_crash','child_timeout']:
    assert actual['summary'].get(key,0)==0, key
assert not actual['summary'].get('incomplete',False)
assert not new, 'new final-revision discrepancy: inspect, reproduce, classify, and refresh affected evidence'
assert trace.stat().st_size>0
record={'result_path':str(path),'result_sha256':hashlib.sha256(path.read_bytes()).hexdigest(),'trace_path':str(trace),'trace_sha256':hashlib.sha256(trace.read_bytes()).hexdigest(),'summary':actual['summary']}
(root/'final/fast-inspection.json').write_text(json.dumps(record,indent=2)+'\n')
PYCODE
```

Expected: no new discrepancy, crash, setup error, timeout, or unexplained regression; inspect message runtime dispositions and the actual trace as well as the summary. A difference is investigated with source evidence before further acceptance work; existing classified oracle defects stay visible.

- [ ] Run the kat lane against the final bundle and archive its raw outputs.

```sh
python3 - <<'PYCODE'
import json,shutil,subprocess
from pathlib import Path
root=Path('dist-release-evidence/message-routing/final')
with (root/'kat.log').open('w') as log:
    result=subprocess.run(['bash','/tmp/pkcs11-ws/run-lane-rc2.sh','kat'],stdout=log,stderr=subprocess.STDOUT)
(root/'kat-command.json').write_text(json.dumps({'command':'bash /tmp/pkcs11-ws/run-lane-rc2.sh kat','exit':result.returncode,'log':str(root/'kat.log')},indent=2)+'\n')
assert result.returncode==0
archive=root/'kat'
archive.mkdir(exist_ok=False)
source=Path('/tmp/pkcs11-ws/out-rc2/kat')
shutil.copy2(source/'pkcs11-kat-results.json',archive/'pkcs11-kat-results.json')
shutil.copy2(source/'trace.jsonl',archive/'trace.jsonl')
PYCODE
```

- [ ] Inspect the archived final kat findings before declaring acceptance.

```sh
python3 - <<'PYCODE'
import hashlib,json
from pathlib import Path
root=Path('dist-release-evidence/message-routing')
path=root/'final/kat/pkcs11-kat-results.json'
trace=path.with_name('trace.jsonl')
actual=json.loads(path.read_text())
previous=json.loads((root/'reviewed/kat/pkcs11-kat-results.json').read_text())
def findings(data):
    return {(item.get('nodeid',''),item.get('outcome',''),str(item.get('wasxfail','')),str(item.get('longrepr',''))) for unit in data.get('units',[]) for item in unit.get('tests',[]) if item.get('outcome') not in ['passed','skipped']}
new=findings(actual)-findings(previous)
print(json.dumps(actual['summary'],indent=2))
for item in sorted(new): print(json.dumps(item))
for unit in actual.get('units',[]):
    for item in unit.get('tests',[]):
        if 'message' in item.get('nodeid',''): print(json.dumps(item,sort_keys=True))
for key in ['error','crashed','timeout','child_crash','child_timeout']:
    assert actual['summary'].get(key,0)==0, key
assert not actual['summary'].get('incomplete',False)
assert not new, 'new final-revision discrepancy: inspect, reproduce, classify, and refresh affected evidence'
assert trace.stat().st_size>0
record={'result_path':str(path),'result_sha256':hashlib.sha256(path.read_bytes()).hexdigest(),'trace_path':str(trace),'trace_sha256':hashlib.sha256(trace.read_bytes()).hexdigest(),'summary':actual['summary']}
(root/'final/kat-inspection.json').write_text(json.dumps(record,indent=2)+'\n')
PYCODE
```

Expected: no new discrepancy, crash, setup error, timeout, or unexplained regression; inspect message runtime dispositions and the actual trace as well as the summary. A difference is investigated with source evidence before further acceptance work; existing classified oracle defects stay visible.

- [ ] Verify final artifact identity and collect the final evidence manifest.

```sh
python3 - <<'PYCODE'
import hashlib,json,subprocess
from pathlib import Path
root=Path('dist-release-evidence/message-routing/final')
pins=json.loads((root/'pins.json').read_text())
assert pins['source_revision']==subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip()
module=Path(pins['bundle_path'])/'lib/libhaskoki.so'
assert pins['module_sha256']==hashlib.sha256(module.read_bytes()).hexdigest()
manifest={'pins':pins,'commands':{},'lanes':{}}
for name in ['gates','fast','kat']:
    record=json.loads((root/(name+'-command.json')).read_text())
    assert record['exit']==0
    manifest['commands'][name]=record
for lane in ['fast','kat']:
    manifest['lanes'][lane]=json.loads((root/(lane+'-inspection.json')).read_text())
(root/'MANIFEST.json').write_text(json.dumps(manifest,indent=2)+'\n')
print(json.dumps(manifest,indent=2))
PYCODE
```

Expected: final HEAD, bundle/module pins, oracle source identity, commands, exits, result paths, trace paths, and hashes are durably linked. The tracked oracle documents retain the earlier reviewed record and its archived inputs; this final manifest supplies the evidence for the final documentation commit. Do not edit or commit additional tracked files after these final checks. A necessary correction starts a new observed-failure cycle and invalidates affected evidence.

Completion is conditional on every section 6 acceptance item: all twenty real table routes on three versions; decoder, guard, state, query, canary and collision checks; unchanged original model expectations; complete direct/proxy and release evidence; cleanly classified fast/kat results; preserved contracts and catalog; and synchronized oracle records. Report any unresolved provider defect or missing required upstream evidence as an acceptance blocker, with the exact reproduction and next permitted boundary action.
