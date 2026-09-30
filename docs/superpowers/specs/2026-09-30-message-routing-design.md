# v3.0 message-family C routing design

Design draft for approved sub-project one, approach A. Source inspection:
`main` at `c95418141370816754fbcf329ac5d78b79fa441e`, 2026-09-30.
This document specifies subsequent implementation; no implementation, test
execution, lane result, or release qualification is claimed by this draft.

## 1. Goal and non-goals

Route all twenty v3.0 message-family function-table entries through the existing
Haskell message planner and real backend, preserving its planning semantics and
the established C boundary precedence.

Async calls, recovery calls, dual operations, and authenticated wrapping belong
to later work. This change adds no mechanisms, mechanism flags, parameter
recipes, native nonce generation, or detached-tag protocol. It does not change
`FunctionId` ordering, `planCall`, `Operation.Message`, authentication policy,
classic operation behavior, or backend algorithms. The existing seventeen
`tests/model/MessageSpec.hs` cases remain authoritative for planning behavior.

The twenty entries are functions, not mechanisms. The catalog remains the
same projection of `support.real == "tested"`; neither `spec/mechanisms.json`
nor `cbits/mech_catalog.inc` changes. The requested walkthrough section 5 does
contain the 130-row C-surface note, but that note is stale at the inspected
revision: the manifest has 316 real-tested rows, the generated include defines
`HASKOKI_MECH_COUNT` as 316, and `consumer_discovery.c` asserts 316. Preserve
those 316 entries and their flags exactly; do not shrink the catalog to the
old documentation count or add twenty rows. Routing slots does not itself
advertise any `CKF_MESSAGE_*` or `CKF_MULTI_MESSAGE` capability.

## 2. Architecture

The implementation follows the existing `std_Sign` and `haskokiStdSign`
boundary, using the message planner in place of the classic planner:

1. A consumer obtains interface 3.0, 3.1, or 3.2 using `C_GetInterface` and calls
   its actual message slot. The slot points to the corresponding `std_*` body.
2. That C body checks `haskoki_live_interval()`, checks the pointer relationships
   in section 3, obtains `haskoki_state_lock()`, and resolves `live_std()`.
   It calls the Haskell export with that instance while holding the lock,
   unlocks, and returns the export's result.
3. The export enters `withStdCtx` and `withStdSession`, copies bounded inputs,
   constructs the existing operation frame, and builds a `Request`. Use
   `Pkcs11_3_2` internally as the current Standard exports do: all three
   interfaces use the same planner semantics; the table still reports its own
   interface version.
4. `runCryptoPlan` invokes `planCall`. Init, Begin, and outer Final normally
   publish an immediate state change. One-shot and terminating Next calls use
   the existing `FxMessageCipher`, `FxMessageSign`, or `FxMessageVerify`,
   `runEffect`, `finishEffect`, and `finishMessage` path. Rejections publish
   their existing deltas and releases.
5. The FFI returns a silent result, encodes committed bytes and their length, or
   reports the required length while retaining a staged result. Section 3.4
   defines the query preview and zero-output continuation cases.

There is one instance, session space, model, and backend per initialization
interval. There is no second message engine, new global state, Haskell worker,
or unlocked instance pointer. The C lock protects instance lifetime across
decode, planning, execution, publication, and output encoding.

`core/Haskoki/Transition.hs` already maps all twenty identifiers to
`planMessageInit`, `planMsgOneShot`, `planMsgBegin`, `planMsgNext`, and
`planMsgFinal`. It requires exactly one `RegionBytes` for every One-shot and
Next request, including Verify and silent Sign/Verify continuation calls.
Init, Begin, and outer Final have no output regions.

## 3. Components

### 3.1 Exact entry and export signatures

The ABI source is `spec/vendor/pkcs11.h`, locked by
`spec/sources.lock.json` to latchset commit
`c5e61990c5621a9b955fc208644fe8145ac0a75d`.
The inspected header SHA-256 is
`61e0b3f996fa9f095859d7d3b8e361d0b982de69fc8b6a4bf10291afbe7e24d8`.
Its message declarations are at lines 2235–2272; the function-pointer typedefs
at lines 2421–2460 provide the independent compile-time contract.

These are the pinned public prototypes with descriptive parameter names.
Each C surface definition and its declaration in `cbits/exports.c` has the
identical prototype with the initial `C_` replaced by `std_`.

```c
CK_RV C_MessageEncryptInit(CK_SESSION_HANDLE hSession,
    CK_MECHANISM *pMechanism, CK_OBJECT_HANDLE hKey);
CK_RV C_EncryptMessage(CK_SESSION_HANDLE hSession,
    void *pParameter, CK_ULONG ulParameterLen,
    CK_BYTE *pAssociatedData, CK_ULONG ulAssociatedDataLen,
    CK_BYTE *pPlaintext, CK_ULONG ulPlaintextLen,
    CK_BYTE *pCiphertext, CK_ULONG *pulCiphertextLen);
CK_RV C_EncryptMessageBegin(CK_SESSION_HANDLE hSession,
    void *pParameter, CK_ULONG ulParameterLen,
    CK_BYTE *pAssociatedData, CK_ULONG ulAssociatedDataLen);
CK_RV C_EncryptMessageNext(CK_SESSION_HANDLE hSession,
    void *pParameter, CK_ULONG ulParameterLen,
    CK_BYTE *pPlaintextPart, CK_ULONG ulPlaintextPartLen,
    CK_BYTE *pCiphertextPart, CK_ULONG *pulCiphertextPartLen, CK_FLAGS flags);
CK_RV C_MessageEncryptFinal(CK_SESSION_HANDLE hSession);

CK_RV C_MessageDecryptInit(CK_SESSION_HANDLE hSession,
    CK_MECHANISM *pMechanism, CK_OBJECT_HANDLE hKey);
CK_RV C_DecryptMessage(CK_SESSION_HANDLE hSession,
    void *pParameter, CK_ULONG ulParameterLen,
    CK_BYTE *pAssociatedData, CK_ULONG ulAssociatedDataLen,
    CK_BYTE *pCiphertext, CK_ULONG ulCiphertextLen,
    CK_BYTE *pPlaintext, CK_ULONG *pulPlaintextLen);
CK_RV C_DecryptMessageBegin(CK_SESSION_HANDLE hSession,
    void *pParameter, CK_ULONG ulParameterLen,
    CK_BYTE *pAssociatedData, CK_ULONG ulAssociatedDataLen);
CK_RV C_DecryptMessageNext(CK_SESSION_HANDLE hSession,
    void *pParameter, CK_ULONG ulParameterLen,
    CK_BYTE *pCiphertextPart, CK_ULONG ulCiphertextPartLen,
    CK_BYTE *pPlaintextPart, CK_ULONG *pulPlaintextPartLen, CK_FLAGS flags);
CK_RV C_MessageDecryptFinal(CK_SESSION_HANDLE hSession);

CK_RV C_MessageSignInit(CK_SESSION_HANDLE hSession,
    CK_MECHANISM *pMechanism, CK_OBJECT_HANDLE hKey);
CK_RV C_SignMessage(CK_SESSION_HANDLE hSession,
    void *pParameter, CK_ULONG ulParameterLen,
    CK_BYTE *pData, CK_ULONG ulDataLen,
    CK_BYTE *pSignature, CK_ULONG *pulSignatureLen);
CK_RV C_SignMessageBegin(CK_SESSION_HANDLE hSession,
    void *pParameter, CK_ULONG ulParameterLen);
CK_RV C_SignMessageNext(CK_SESSION_HANDLE hSession,
    void *pParameter, CK_ULONG ulParameterLen,
    CK_BYTE *pDataPart, CK_ULONG ulDataPartLen,
    CK_BYTE *pSignature, CK_ULONG *pulSignatureLen);
CK_RV C_MessageSignFinal(CK_SESSION_HANDLE hSession);

CK_RV C_MessageVerifyInit(CK_SESSION_HANDLE hSession,
    CK_MECHANISM *pMechanism, CK_OBJECT_HANDLE hKey);
CK_RV C_VerifyMessage(CK_SESSION_HANDLE hSession,
    void *pParameter, CK_ULONG ulParameterLen,
    CK_BYTE *pData, CK_ULONG ulDataLen,
    CK_BYTE *pSignature, CK_ULONG ulSignatureLen);
CK_RV C_VerifyMessageBegin(CK_SESSION_HANDLE hSession,
    void *pParameter, CK_ULONG ulParameterLen);
CK_RV C_VerifyMessageNext(CK_SESSION_HANDLE hSession,
    void *pParameter, CK_ULONG ulParameterLen,
    CK_BYTE *pDataPart, CK_ULONG ulDataPartLen,
    CK_BYTE *pSignature, CK_ULONG ulSignatureLen);
CK_RV C_MessageVerifyFinal(CK_SESSION_HANDLE hSession);
```

Add twenty `foreign export ccall` declarations and their Haskell functions
in `ffi/Haskoki/FFI/Standard.hs`, following the existing Sign export block.
Export names use the common `haskoki_std_message_` prefix. The following
native prototypes spell scalars as `unsigned long`, matching `CULong` on
the repository's supported 64-bit Unix ABI; byte pointers map to `Ptr Word8`,
length pointers to `Ptr CULong`, and `ctx` to `StablePtr StdInstance`.
Use the existing generated-stub-header preference and matching fallback
declarations in `cbits/standard_surface.c`.

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

The C cipher Next wrappers reject bits outside `CKF_END_OF_MESSAGE`, then
pass `end` as zero or one. Their Haskell exports reject any other `end`
value before constructing a Boolean. Sign/Verify signatures have no flags
argument; do not manufacture one or change their arity.

### 3.2 Frame decoders and per-entry mapping

Extend `ffi/Haskoki/FFI/MessageParams.hs` with the eight boundary helpers
below. Each returns `IO (Either MsgParamError ByteString)`, holding a complete
owned planner frame. Argument order is family first (a `MsgFamily` from
`core/Haskoki/Operation/State.hs`), then one `Ptr Word8` plus `Word64` length
pair per component in the order listed, then the end signal where noted.
"Absent AAD" means the literal `NULL,0` pair, which `decodeInputBytes`
maps to empty. Input lengths are converted from `CULong` without
narrowing before `decodeInputBytes`; every component is bounded by
`maxInputBytes` (16 MiB) before reading its bytes. Decode failures map to
`CKR_ARGUMENTS_BAD` with no output write or state mutation. Concretely:

```haskell
decodeMessageInitFrame      :: MsgFamily -> CULong -> Ptr Word8 -> Word64 -> IO (Either MsgParamError ByteString)
decodeMessageBeginFrame     :: MsgFamily -> Ptr Word8 -> Word64 -> Ptr Word8 -> Word64 -> IO (Either MsgParamError ByteString)
decodeMessageCipherFrame    :: MsgFamily -> Ptr Word8 -> Word64 -> Ptr Word8 -> Word64 -> Ptr Word8 -> Word64 -> IO (Either MsgParamError ByteString)
decodeMessageSignFrame      :: Ptr Word8 -> Word64 -> Ptr Word8 -> Word64 -> IO (Either MsgParamError ByteString)
decodeMessageVerifyFrame    :: Ptr Word8 -> Word64 -> Ptr Word8 -> Word64 -> Ptr Word8 -> Word64 -> IO (Either MsgParamError ByteString)
decodeMessageCipherNextFrame :: MsgFamily -> Ptr Word8 -> Word64 -> Ptr Word8 -> Word64 -> Bool -> IO (Either MsgParamError ByteString)
decodeMessageSignNextFrame  :: Ptr Word8 -> Word64 -> Ptr Word8 -> Word64 -> Bool -> IO (Either MsgParamError ByteString)
decodeMessageVerifyNextFrame :: Ptr Word8 -> Word64 -> Ptr Word8 -> Word64 -> Ptr Word8 -> Word64 -> IO (Either MsgParamError ByteString)
```

(`decodeMessageInitFrame` takes the mechanism id as a `CULong` scalar
alongside the parameter pair; the export attaches the key handle to the
`Request` separately. The Verify witness pair keeps pointer presence
through a `Maybe` inside the decoder, per its bullet below.)

- `decodeMessageInitFrame` takes the family, mechanism id, native parameter
  pointer, and parameter length. Copy the parameters, use the existing
  `normalizeMechParams`, and return
  `encodeInitInput mechanism [msgFamilyOp family] False params`.
  The Request carries `Just (ExternalHandle key)` separately. Preserve the
  current keyed-init permit and auth intake; key validation stays in the
  existing planner. Do not call `runKeyedInitParams` directly: it selects
  `DRInit` and would allocate a classic operation.
- `decodeMessageBeginFrame` takes the family and parameter/AAD pointer-length
  pairs. Use `decodeMessageParams`, then
  `encodeMsgBegin (MsgBegin params aad)`. Sign/Verify pass an absent AAD pair,
  so their public signatures cannot introduce AAD.
- `decodeMessageCipherFrame` takes the cipher family, parameter/AAD pairs,
  and input pair. Decode parameters and AAD, then input, and return
  `encodeMsgOneShot (MsgOneShotCipher params aad input)`.
- `decodeMessageSignFrame` takes the parameter and input pairs, uses
  `decodeMessageParams MsgSign` with absent AAD, copies input, and returns
  `encodeMsgOneShot (MsgOneShotSign params input)`.
- `decodeMessageVerifyFrame` takes the parameter, input, and signature
  pairs. Decode in that order, with absent AAD, and return
  `encodeMsgOneShot (MsgOneShotVerify params input signature)`.
  An empty signature is a decoded value, not a pointer error.
- `decodeMessageCipherNextFrame` takes the cipher family, parameter and
  part pairs, and a validated Boolean end signal. Decode with absent AAD,
  then return `encodeMsgNext (MsgNextCipher params part end)`.
- `decodeMessageSignNextFrame` takes the parameter and part pairs and a
  Boolean obtained from `pulSignatureLen /= NULL`. Return
  `encodeMsgNext (MsgNextSign params part end)`. It never copies an output
  signature buffer as input.
- `decodeMessageVerifyNextFrame` takes the parameter, part, and signature
  pairs. Preserve pointer presence before decoding the signature:
  `NULL,0` becomes `Nothing`; a present pointer becomes `Just bytes`,
  including `Just empty` at length zero. Return
  `encodeMsgNext (MsgNextVerify params part witness)`.

Final exports have no frame decoder: use empty input and empty regions.
The Haskell function spelling follows the export exactly; the twenty names
are `haskokiStdMessageEncryptInit`, `haskokiStdMessageEncrypt`,
`haskokiStdMessageEncryptBegin`, `haskokiStdMessageEncryptNext`,
`haskokiStdMessageEncryptFinal`, and the same five suffixes with the
`Decrypt`, `Sign`, and `Verify` infixes (`haskokiStdMessageDecryptInit`
through `haskokiStdMessageVerifyFinal`).

Use only the existing `Haskoki.Operation.Codec` encoders. Their integers are
big-endian, unlike Standard's native template frame. Begin has a parameter
length prefix followed by AAD; Next uses cipher/sign/verify tags zero/one/two
and the existing end or witness-presence byte; One-shot uses the same family
tags with length-prefixed parameters and, where present, AAD or witness.
Do not pack C structs into these frames or copy caller addresses into core
state. Bounded component lengths fit the codec's 32-bit length prefixes;
compute aggregate sizes without overflow. A cipher or Verify one-shot frame
is bounded by three component limits plus nine framing bytes. There is no
additional whole-frame 16 MiB cutoff that would reject a legal component
solely because framing adds bytes.

Per-message parameters retain the existing opaque codec. They are not passed
through the classic native-struct normalizer (this paragraph is about
per-message parameters only; Init decoding still uses `normalizeMechParams`
per its bullet above): message parameter structures
can have different layouts from init structures. CBC consumer calls supply
their actual IV at One-shot or Begin; empty Next parameters retain that
message's IV, and nonempty Next parameters replace it. An empty One-shot or
Begin parameter block does not inherit the outer init IV. The model's
`planNonceWriteback`, `planTagWriteback`, and toy AEAD cases remain intact,
but do not establish native message-struct support or authorize new nested
pointer handling in this routing change.

In this table, the export column is the suffix after
`haskoki_std_message_`. Every row uses the identically named
`F_` constructor after removing the public `C_` prefix.

| Public entry | Export suffix | Decoder / request payload | Family slot and output |
|---|---|---|---|
| C_MessageEncryptInit | encrypt_init | decodeMessageInitFrame MsgEncrypt | SlotEncrypt; no region |
| C_EncryptMessage | encrypt | decodeMessageCipherFrame MsgEncrypt | SlotEncrypt; bytes or query |
| C_EncryptMessageBegin | encrypt_begin | decodeMessageBeginFrame MsgEncrypt | SlotEncrypt; no region |
| C_EncryptMessageNext | encrypt_next | decodeMessageCipherNextFrame MsgEncrypt | SlotEncrypt; bytes or query |
| C_MessageEncryptFinal | encrypt_final | empty input | SlotEncrypt; no region |
| C_MessageDecryptInit | decrypt_init | decodeMessageInitFrame MsgDecrypt | SlotDecrypt; no region |
| C_DecryptMessage | decrypt | decodeMessageCipherFrame MsgDecrypt | SlotDecrypt; bytes or query |
| C_DecryptMessageBegin | decrypt_begin | decodeMessageBeginFrame MsgDecrypt | SlotDecrypt; no region |
| C_DecryptMessageNext | decrypt_next | decodeMessageCipherNextFrame MsgDecrypt | SlotDecrypt; bytes or query |
| C_MessageDecryptFinal | decrypt_final | empty input | SlotDecrypt; no region |
| C_MessageSignInit | sign_init | decodeMessageInitFrame MsgSign | SlotSign; no region |
| C_SignMessage | sign | decodeMessageSignFrame | SlotSign; bytes or query |
| C_SignMessageBegin | sign_begin | decodeMessageBeginFrame MsgSign | SlotSign; no region |
| C_SignMessageNext | sign_next | decodeMessageSignNextFrame | SlotSign; continuation or bytes/query |
| C_MessageSignFinal | sign_final | empty input | SlotSign; no region |
| C_MessageVerifyInit | verify_init | decodeMessageInitFrame MsgVerify | SlotVerify; no region |
| C_VerifyMessage | verify | decodeMessageVerifyFrame | SlotVerify; verdict |
| C_VerifyMessageBegin | verify_begin | decodeMessageBeginFrame MsgVerify | SlotVerify; no region |
| C_VerifyMessageNext | verify_next | decodeMessageVerifyNextFrame | SlotVerify; continuation or verdict |
| C_MessageVerifyFinal | verify_final | empty input | SlotVerify; no region |

Use region names `message-encrypt`, `message-decrypt`, `message-sign`, and
`message-verify` consistently for One-shot and Next within a family.
For byte outputs, select `IntentNull` or `IntentBuffer capacity` by output
pointer presence. Verify and Sign continuation use a dummy
`IntentBuffer 0` region solely to satisfy the existing planner shape;
their exports use `runCryptoSilent` and do not bind a caller output buffer.

### 3.3 C surface and null-argument matrix

Implement all twenty `std_*` definitions in `cbits/standard_surface.c`.
Preserve this order: liveness peek, structural guards, state lock, authoritative
`live_std` lookup, Haskell export, unlock. A lock failure returns the lock
result verbatim: `CKR_CANT_LOCK` from the internal mutex, or whatever the
negotiated application mutex callback returns. A missing instance after
locking unlocks and returns
`CKR_CRYPTOKI_NOT_INITIALIZED`. Every path after successful locking unlocks
exactly once. No caller pointer is read before the liveness peek.

The guards below return `CKR_ARGUMENTS_BAD`. Inits already use plain refusal
in `std_SignInit`. Message data guards must also be plain refusals: the classic
`refuse_null_arg`, `refuseArgsTerminate`, and `terminateSlot` helpers would
erase the outer message context and therefore cannot be reused. Malformed
boundary frames never reach planning and leave state unchanged.

Notation for this matrix:

- `bad(p,n)` means `p == NULL && n > 0`. Both `NULL,0` and a present
  pointer with zero length represent empty input, except for the Verify
  witness `W`: there pointer presence is load-bearing (`NULL,0`
  continues while a present pointer, even at length zero, ends), so
  "empty" never equates the two shapes for `W`.
- `P` is the per-message parameter pair; `A` is AAD; `D` is data or
  data-part; `W` is the Verify signature pair.
- `B` is the output byte pointer and `L` its length pointer.
  A query needs `B == NULL` and a present `L`; the incoming value of
  `*L` is ignored. A present `B` with `*L == 0` is a real zero-capacity
  buffer, never a query.
- `badMechanism` means a null mechanism pointer, or a present mechanism
  whose parameter pointer is null with nonzero parameter length. Check the
  mechanism pointer before accessing either field.

Read each refusal list in the written order. Other scalar values, including
session and key handles, go to the existing Haskell/planner checks.

| Entry | Refusal guards after liveness | Accepted nulls and output convention |
|---|---|---|
| C_MessageEncryptInit | badMechanism | NULL mechanism parameters with length zero reach recipe validation; no query |
| C_EncryptMessage | L null; bad(P); bad(A); bad(D) | Empty P/A/D allowed structurally; B null queries |
| C_EncryptMessageBegin | bad(P); bad(A) | Empty P/A allowed; no output or query |
| C_EncryptMessageNext | L null; bad(P); bad(D); unknown flag bits | Empty P/D allowed; B null queries; flags zero continues, CKF_END_OF_MESSAGE ends |
| C_MessageEncryptFinal | none | Only session argument; no query |
| C_MessageDecryptInit | badMechanism | NULL mechanism parameters with length zero reach recipe validation; no query |
| C_DecryptMessage | L null; bad(P); bad(A); bad(D) | Empty P/A/D allowed structurally; B null queries |
| C_DecryptMessageBegin | bad(P); bad(A) | Empty P/A allowed; no output or query |
| C_DecryptMessageNext | L null; bad(P); bad(D); unknown flag bits | Empty P/D allowed; B null queries; flags zero continues, CKF_END_OF_MESSAGE ends |
| C_MessageDecryptFinal | none | Only session argument; no query |
| C_MessageSignInit | badMechanism | Empty mechanism parameters allowed structurally; no query |
| C_SignMessage | L null; bad(P); bad(D) | Empty P/D allowed; B null queries |
| C_SignMessageBegin | bad(P) | Empty P allowed; no output or query |
| C_SignMessageNext | bad(P); bad(D) | L null continues and ignores B; L present ends, with B null selecting a query |
| C_MessageSignFinal | none | Only session argument; no query |
| C_MessageVerifyInit | badMechanism | Empty mechanism parameters allowed structurally; no query |
| C_VerifyMessage | bad(P); bad(D); bad(W) | W null with zero length decodes an empty witness and reaches verdict logic; no query |
| C_VerifyMessageBegin | bad(P) | Empty P allowed; no output or query |
| C_VerifyMessageNext | bad(P); bad(D); bad(W) | W null with zero length continues; present W ends even at zero length; no query |
| C_MessageVerifyFinal | none | Only session argument; no query |

Sign Next uses the length-pointer presence as its end signal; Verify Next
uses the signature-pointer presence. These distinct signals agree with
sections 5.14.4 and 5.16.4 of the
[PKCS #11 v3.0 specification](https://docs.oasis-open.org/pkcs11/pkcs11-base/v3.0/os/pkcs11-base-v3.0-os.html).
For Sign continuation (length pointer absent), neither a null output
pointer nor an ignored present one is a query. Do not read or write it
when the length pointer is absent. Once the length pointer is present
the call ends: a null output pointer then selects a query instead.

### 3.4 Output dialogues, queries, and recall

Reuse `runCryptoPlan`, `runCryptoPlanOn`, `runCryptoSilent`,
`encodeCryptoCommit`, `reportCryptoQuery`, and `reportShortLength`.
Add message-specific orchestration inside Standard; do not change the behavior
of the existing classic helpers.

For `runMessageBuffered`, construct the same family Request as above with
`IntentBuffer capacity`. Publish the plan through the existing pipeline.
A short result, whether a finisher commit or a planner rejection during
recall, reports the staged length and touches no output bytes. An ordinary
successful byte commit uses `encodeCryptoCommit`. A successful continuation
with no native outputs writes zero to its present length pointer and returns
`CKR_OK`; passing it unchanged to `encodeCryptoCommit` would incorrectly
produce `CKR_GENERAL_ERROR`. Silent Sign continuation uses
`runCryptoSilent` instead and has no length pointer to update.

For `runMessageQuery`, decode first and compute `planCall` once against a
snapshot with `IntentNull`. Handle that plan as follows:

1. A rejection goes through the existing rejection publication and code
   mapping; it is not converted to success merely because the call is a query.
2. "Matching" means the staged result stored under this session's slot for
   this family (the same `withMessageSlot` lookup `retryMessageStaged`
   uses): no input-equality check, no cross-session or cross-family
   matching. A successful immediate plan with such a matching staged
   message result reports that result's length from the pre-call
   snapshot, without publishing the preview. A successful immediate plan
   for a non-ending cipher Next with no staged result reports zero, also
   without publishing the preview. Neither case consumes input, changes
   auth state, or increments deliveries.
3. An execution plan goes through `runCryptoPlanOn` with that same snapshot
   and plan. Its first query executes the existing backend effect and stages
   the result through `finishMessage`; translate the resulting
   `CKR_BUFFER_TOO_SMALL` to a successful length report using
   `reportCryptoQuery`. Backend/planner errors retain their actual code.
4. Any other successful immediate shape is an internal mismatch and returns
   `CKR_GENERAL_ERROR` without an output write.

This explicit preview is necessary at the inspected revision:
`retryMessageStaged` branches on the output plan's `CKR_OK`, and
`planOneShot IntentNull` also returns that code. Publishing such a repeated
query would clear the staged bytes. Also, non-ending `planMessageNext`
builds an append delta without inspecting output intent. The query dialogue
must leave those successful previews unpublished, as the existing classic
update-query boundary already does. The pure planning functions remain
unchanged. Tests must pin repeated queries and non-ending query followed by
the real part, so this cannot be replaced by an unconditional
`runCryptoQuery` call.

A present output pointer at capacity zero is different: it consumes a valid
zero-output continuation, reports short for nonempty terminal output, and
delivers an empty terminal output exactly once. A first empty-result query
must still retain staged output until a present zero-capacity buffer accepts
it. Repeated queries do not deliver even an empty staged message.

The planner decides whether a well-formed One-shot/Next is a staged recall
before running a new message step. Keep that behavior: do not impose a new
input-equality rule, rerun crypto, or append the recalled terminal part twice.
All pointer checks and frame decoding still precede recall. The outer Final
never obtains staged bytes; it reports `CKR_OPERATION_ACTIVE` until delivery.

### 3.5 Table registration

Extend only `routed300` in `scripts/generate-abi.py` with all twenty
`C_*` to `std_*` mappings listed above, keeping `C_SessionCancel`.
"Only `routed300`" still reaches all three interface versions: the
existing `fill_30` seats the `HASKOKI_FILL_300_NEW` macro into both
the separate 3.0 and 3.1 tables, and `do_fill` seats it into 3.2.
`routed320` and unrelated stubs retain their existing routes.
Declare all twenty surface functions with the pinned prototypes in
`cbits/exports.c` before the generated include.

During implementation, regenerate with `python3 scripts/generate-abi.py`.
Never edit `cbits/abi_stubs.inc` by hand. The regenerated artifact must remove
all twenty corresponding `x30_*` function bodies and use `std_*` in their
`HASKOKI_FILL_300_NEW` assignments. No counts, slot order, header pins, or
ABI inventory prototypes change; the generator's other outputs remain
byte-identical.

The existing `fill_30` seats this macro into both the separate 3.0 and 3.1
tables, and `do_fill` seats it into 3.2. Version 3.1 uses
`CK_FUNCTION_LIST_3_0`; no new 3.1 structure exists. The function counts
remain 68/92/92/104 for 2.40/3.0/3.1/3.2. The legacy
`C_GetFunctionList` table has no message slots and must not be extended or
cast to a larger table.

### 3.6 Consumer, contract evidence, and documentation wiring

Add `tests/c/message_routed.c` as a standalone pinned-header consumer.
Follow `consumer_roundtrip.c` for configuration, `dlopen`, error accounting,
session/object creation, deterministic byte checks, and cleanup. Resolve
discovery symbols with `dlsym`, then exercise message calls only through
their versioned table slots; do not substitute direct Haskell exports or
provider-generated declarations.

Both `scripts/test-consumers.sh` and `scripts/test-proxy-parity.sh` currently
discover only `tests/c/consumer_*.c`. Explicitly include
`tests/c/message_routed.c` exactly once in each scenario list, require its
existence, and keep stable ordering. Extend the consumer independence check
to the same complete source list so the new filename cannot evade it.
Compile it using the existing C11, optimization, debug, warning-as-error,
`-Ispec/vendor`, `-ldl`, and `-lpthread` settings.

Run the same executable against the direct module and proxy shim. Keep normal
success, length, byte, and multipart checks in the compared transcript.
Print deterministic entry/leg labels, return codes, lengths, and output hex;
exclude addresses, session handles, and temporary paths. Only an explicitly
documented shim-local refusal can use an existing topology-specific prefix.
Such a refusal must still assert its exact code. Missing message slots or a
valid forwarded call returning `CKR_FUNCTION_NOT_SUPPORTED` fail this
scenario; do not turn them into a successful skip.

For every one of the twenty message rows in `spec/function-contracts.json`,
retain `contract: planned-with-behavior`, the existing `planCall:F_*` entry,
layout list, ordinal, acceptance ids, and `MessageSpec.hs` evidence. Append:

```json
{
  "suite": "test-consumers.sh",
  "spec": "tests/c/message_routed.c"
}
```

This records executed C coverage once the new consumer passes; it does not
rename the planner-scoped contract label. The total of seventy
`planned-with-behavior` rows stays unchanged. Consumer leg labels in section
5 make each row's evidence concrete without adding another quoted function
name field to the JSON denominator.

Update `docs/demo-walkthrough.md` section 3 with the consumer's actual
message coverage and section 5 with the distinction between newly routed
functions and the unchanged mechanism catalog. Do not edit the existing
130-row boundary sentences in place (documentation checks pin that
wording): add a dated note directly beside them stating the note is
historical and the inspected manifest plus C catalog contain 316 rows
with their source (`spec/mechanisms.json` projection,
`HASKOKI_MECH_COUNT`). This routing change does not alter either
catalog or mechanism coverage. Update the stale
post-2.40 stub description in `cbits/exports.c` during implementation.
Keep `docs/pkcs11-oracle-triage.md` and
`docs/pkcs11-check-upstream-issues.md` aligned with the findings described
in sections 5 and 6.

## 4. Error handling

For every row in the null matrix, the public precedence is
`CKR_CRYPTOKI_NOT_INITIALIZED` before the listed structural argument errors,
then the existing live behavior. Before initialization and after finalization,
even a null mechanism or missing output length returns the lifecycle code
without inspecting the pointer. Once live, a listed C argument error wins
over an invalid session or absent operation, with output bytes and length
words unchanged.

Preserve the finer ordering inside the existing shape as well. The rule in
one sentence: `bad(p,n)` null-shape checks run at the C level and beat a
bad session, while length-cap checks (`maxInputBytes` and friends) run at
the Haskell level after session lookup and lose to it. After the C guards
and lock, `withStdSession` resolves the session before Haskell copies or
bounds-checks inputs. Thus a well-shaped call with an unknown session
returns `CKR_SESSION_HANDLE_INVALID`, including when a present input has an
oversize length. Do not move all decoding ahead of session lookup in the name
of argument precedence. Exceptions caught by `withStdCtx` keep the existing
`CKR_GENERAL_ERROR` boundary.

| Entries | Behavior reached after boundary checks |
|---|---|
| All four Message Init calls | Decode init frame; cipher shape resolution for Encrypt/Decrypt; existing slot conflict and init validation. A duplicate init or classic/message init collision returns CKR_OPERATION_ACTIVE. Invalid visible key handles and denied usage retain existing planner codes. |
| EncryptMessage, DecryptMessage, SignMessage | Decode the family frame; validate the single output region; apply staged recall if present; otherwise require a matching idle outer context. No outer context returns CKR_OPERATION_NOT_INITIALIZED; an open inner message returns CKR_OPERATION_ACTIVE. |
| VerifyMessage | Same frame/region and outer-state checks; empty witness returns CKR_SIGNATURE_INVALID on an idle initialized context; nonempty witness produces the existing backend verdict. No output query exists. |
| All four Message Begin calls | Decode parameters; require the family's message context; staged output or an open message returns CKR_OPERATION_ACTIVE; then existing parameter/AAD bounds and auth gate. |
| EncryptMessageNext, DecryptMessageNext, SignMessageNext | Decode end signal and frame; use the existing retryable route. Without staged recall, no open inner message returns CKR_OPERATION_NOT_INITIALIZED; otherwise append or finish according to the encoded end signal. |
| VerifyMessageNext | Decode witness presence and frame; without an open inner message return CKR_OPERATION_NOT_INITIALIZED. Absent witness continues; present empty witness returns CKR_SIGNATURE_INVALID and aborts the inner message; a nonempty witness ends with a verdict. |
| All four Message Final calls | No data arguments. Missing or classic-only context returns CKR_OPERATION_NOT_INITIALIZED; an open or staged message returns CKR_OPERATION_ACTIVE; an idle message context is removed with CKR_OK. |

Do not collapse classic/message mixing to one convenient code.
`MessageSpec` pins classic cipher update on a message slot to
`CKR_GENERAL_ERROR`, message Begin on a classic slot to
`CKR_OPERATION_NOT_INITIALIZED`, and classic retry of staged message output
to `CKR_ARGUMENTS_BAD` while retaining that output. Both directions of init
collision return `CKR_OPERATION_ACTIVE`.

Other pinned dispositions also survive routing:

- Two completed messages may run under one outer init. Only an idle outer
  Final removes that context; a Verify mismatch still leaves it available.
- Backend failure and invalid decrypt padding abort the inner message and
  keep the outer context. Decrypt padding failure is
  `CKR_ENCRYPTED_DATA_INVALID`; unpadded output misalignment is
  `CKR_ENCRYPTED_DATA_LEN_RANGE`.
- An unaligned unpadded Encrypt ending returns `CKR_DATA_LEN_RANGE` and
  retains the accumulated part so a further part can repair alignment.
  The corresponding rejected One-shot opens no inner message.
- Accumulated multipart input beyond `maxBuffered` aborts the inner message
  with `CKR_ARGUMENTS_BAD`. This planner rejection differs from an individual
  input rejected by the FFI before any append; the latter changes no state.
- The existing late authentication failure can remove the whole pending
  outer context. Do not replace that planner delta with a blanket
  keep-context rule. The existing premature-grant and grant-consumption
  cases remain unchanged.
- A query or short output buffer retains the bytes for recall; query returns
  `CKR_OK`, short buffer returns `CKR_BUFFER_TOO_SMALL`, both report the
  required length. Other errors do not fabricate a length or overwrite an
  output buffer. Verify verdicts never write a signature or length.

## 5. Testing

### 5.1 Haskell boundary additions

Extend the already-wired `MessageSpec` with frame-decoder cases, leaving all
seventeen existing cases unchanged. Exercise every mapping row, including the
four Init encodings and four empty Final request shapes, through the existing
pure decoders and `planCall` with valid fixture sessions/keys.

| New case | Concrete assertions |
|---|---|
| caseMessageInitFrames | Decode each family's native input; decodeInitInput recovers the exact mechanism, that family's classic permit, False auth intake, and parameters. Verify the Request uses the corresponding F_Message init and carries the key separately. CBC uses a 16-byte IV; HMAC uses empty parameters. |
| caseMessageBeginFrames | Both cipher families preserve parameter and AAD bytes; both signature families encode empty AAD. decodeMsgBegin recovers the exact values. |
| caseMessageOneShotFrames | Cipher tags decode under Encrypt and Decrypt; Sign preserves data; Verify preserves data and witness in their distinct fields. Reject family-mismatched frames using the existing pure decoder. |
| caseMessageNextFrames | Cipher end false/true and Sign end false/true round-trip; Verify Nothing, Just empty, and Just nonempty remain distinct. Check exact family tags and field order, not only an encoder/decoder equality using one implementation. |
| caseMessageDecodeBounds | For each component in each decoder: NULL with zero succeeds, NULL with length one rejects, present zero is empty, and maxInputBytes plus one rejects before dereference. A tiny backing allocation paired with that excessive length proves ordering without a large allocation. |
| caseMessageOwnedFrames | Decode nonempty parameter, AAD, data, and witness buffers, then overwrite those buffers; decoded bytes do not change. End/output metadata never appears as copied input bytes. |
| caseMessageRequestRegions | All eight One-shot/Next routes receive one region, including Verify and Sign continuation; omission refuses before an append/effect. Init/Begin/Final have none. Empty Final removes only an idle outer context. |

Use fixed expected frame bytes for a one-byte parameter, AAD, input, and
witness to catch endian or field swaps; lengths two and three distinguish
AAD, data, and witness. Truncated length prefixes and end/witness tag values
outside zero/one must be rejected by the existing pure frame decoder.
Retain the existing nested nonce/tag canary cases without treating their toy
backend as a C-table proof.

Add boundary-dialogue tests in the already-wired `StandardSurfaceSpec` for
the query decision using real planner snapshots: a continuation query leaves
buffered bytes and auth unchanged; a staged repeated query leaves its bytes,
inner state, and delivery count unchanged; a short recall preserves staging;
a present exact buffer delivers once. Test both nonempty and empty staged
outputs. These tests exercise the new message query/encoding boundary,
without changing the core planner's expected result.

### 5.2 Native consumer fixtures and common legs

`message_routed.c` opens each of interfaces 3.0, 3.1, and 3.2 independently,
checks its version and every message slot, and runs all twenty entry legs
through each table. Read 3.0 and 3.1 using their common pinned layout and 3.2
using its actual layout. Discovery remains callable before initialization.

Use transient memory storage and the existing real-crypto configuration.
Discover the token-present slot, open a read/write serial session, and create
public session secret keys with explicit usage flags. Import deterministic
`CKA_VALUE` bytes; do not generate random expected outputs:

- AES: `CKO_SECRET_KEY`, `CKK_AES`, token/private false, Encrypt/Decrypt
  true, key hex `2b7e151628aed2a6abf7158809cf4f3c`.
  Use `CKM_AES_CBC`, IV `000102030405060708090a0b0c0d0e0f`,
  plaintext `6bc1bee22e409f96e93d7e117393172a`, and ciphertext
  `7649abac8119b246cee98e9b12e9197d`.
- HMAC: `CKO_SECRET_KEY`, `CKK_GENERIC_SECRET`, token/private false,
  Sign/Verify true, twenty bytes of `0x0b`, `CKM_SHA256_HMAC`,
  input `Hi There`, expected signature
  `b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7`.

These are the existing known-answer fixtures in
`tests/engine/OpenSSLSpec.hs`; transcribe their fixed bytes into the
independent C consumer. CBC init receives the IV, and One-shot/Begin receives
the IV again according to the existing per-message codec. AAD is empty for
CBC. HMAC has empty init and per-message parameters.

For every entry, run pre-init and post-finalize lifecycle calls. Where the
signature permits malformed pointers, combine the lifecycle state with each
listed malformed shape and require the lifecycle code. While live, exercise
every refusal guard separately, with both a valid and invalid session,
requiring `CKR_ARGUMENTS_BAD`; a well-shaped call with the invalid session
must return `CKR_SESSION_HANDLE_INVALID`. Finals have no pointer guard:
their negative legs are invalid-session and missing/open-context calls.

Use canary bytes around outputs and sentinel length words. Guard/decode/state
refusals preserve both. Short/query calls change only the length; successful
writes change exactly the returned byte span. Provide present zero-capacity
buffers using a valid canary address. Check empty input through both
`NULL,0` and present-zero pairs. Initialize and close a fresh session for
independent refusal sequences, so one prior denial cannot mask a bad test.

### 5.3 Per-entry consumer legs

Each entry emits stable labels consisting of its name plus the listed leg
name and interface version. `no-query` below is an asserted API shape, not
a skipped size-query test: there is no output-length pointer in that call.
For cipher Next rows, "non-ending query" means flags zero with `B == NULL`
and "terminal query" means flags `CKF_END_OF_MESSAGE` with `B == NULL`.
All rows also include the common lifecycle, session, and guard legs above.

| Entry | Happy leg | Behavior refusal leg | Query / short-buffer leg |
|---|---|---|---|
| C_MessageEncryptInit | init-cbc: OK; following EncryptMessage yields the fixed ciphertext | duplicate-init: OPERATION_ACTIVE; bad-key: OBJECT_HANDLE_INVALID; unknown mechanism: MECHANISM_INVALID | no-query; NULL mechanism is ARGUMENTS_BAD, not a query |
| C_EncryptMessage | one-cbc: fixed 16-byte ciphertext; repeat under the same init | no-init: OPERATION_NOT_INITIALIZED; while-open: OPERATION_ACTIVE; one-byte unpadded input: DATA_LEN_RANGE | query reports 16; repeat query with a different incoming length; capacities zero and 15 are BUFFER_TOO_SMALL; 16 delivers exact bytes |
| C_EncryptMessageBegin | begin-iv: OK; seven-byte and nine-byte Next parts produce the fixed ciphertext | no-init: OPERATION_NOT_INITIALIZED; second Begin: OPERATION_ACTIVE without losing the first part | no-query; empty P/A is an empty Begin, then provide IV at ending Next |
| C_EncryptMessageNext | part-cbc: seven bytes with flags zero returns OK/length zero; nine bytes with END flag yields fixed ciphertext | no-begin: OPERATION_NOT_INITIALIZED; flags value two: ARGUMENTS_BAD; unaligned end: DATA_LEN_RANGE, then enough bytes repair it | non-ending query reports zero and does not append; terminal query reports 16; repeated query, short 15, and exact 16 replay without duplicating the terminal part |
| C_MessageEncryptFinal | final-idle: OK after two deliveries; classic EncryptInit can use the released slot | no-init or second Final: OPERATION_NOT_INITIALIZED; open/staged message: OPERATION_ACTIVE and remains usable | no-query; no data or length parameters |
| C_MessageDecryptInit | init-cbc: OK; following DecryptMessage returns fixed plaintext | duplicate-init: OPERATION_ACTIVE; bad-key: OBJECT_HANDLE_INVALID; unknown mechanism: MECHANISM_INVALID | no-query; NULL mechanism is ARGUMENTS_BAD |
| C_DecryptMessage | one-cbc: fixed 16-byte plaintext; second message uses the same outer context | no-init: OPERATION_NOT_INITIALIZED; while-open: OPERATION_ACTIVE | query and repeated query report 16; capacities zero and 15 are BUFFER_TOO_SMALL; 16 delivers exact plaintext |
| C_DecryptMessageBegin | begin-iv: OK; two eight-byte Next parts recover fixed plaintext | no-init: OPERATION_NOT_INITIALIZED; duplicate Begin: OPERATION_ACTIVE | no-query; empty P/A is accepted structurally, with IV supplied at ending Next |
| C_DecryptMessageNext | part-cbc: first eight bytes return zero output; ending eight bytes recover fixed plaintext | no-begin: OPERATION_NOT_INITIALIZED; flags value two: ARGUMENTS_BAD | continuation query reports zero without consuming; terminal/repeated query reports 16; short/exact recall preserves plaintext and canaries |
| C_MessageDecryptFinal | final-idle: OK; classic DecryptInit can use the released slot | missing context: OPERATION_NOT_INITIALIZED; open or staged: OPERATION_ACTIVE | no-query; no data or length parameters |
| C_MessageSignInit | init-hmac: OK; following SignMessage returns the fixed signature | duplicate-init: OPERATION_ACTIVE; bad-key: OBJECT_HANDLE_INVALID; denied sign usage: KEY_FUNCTION_NOT_PERMITTED | no-query; NULL mechanism is ARGUMENTS_BAD |
| C_SignMessage | one-hmac: fixed 32-byte signature twice under one init | no-init: OPERATION_NOT_INITIALIZED; while-open: OPERATION_ACTIVE | query/repeated query report 32; capacities zero and 31 are BUFFER_TOO_SMALL; 32 delivers exact signature |
| C_SignMessageBegin | begin-hmac: empty parameters OK; split Hi There signs identically to One-shot | no-init: OPERATION_NOT_INITIALIZED; duplicate Begin: OPERATION_ACTIVE | no-query; NULL parameter with zero length succeeds |
| C_SignMessageNext | part-hmac: Hi followed by a space uses absent length to continue; There with a length pointer completes the fixed signature | no-begin: OPERATION_NOT_INITIALIZED; NULL part with length one: ARGUMENTS_BAD and no append | absent output and length continues; ignored present output with absent length also continues without writes; present length plus NULL output queries 32; repeated query, short 31, and exact recall work |
| C_MessageSignFinal | final-idle: OK; classic SignInit can use the released slot | missing context: OPERATION_NOT_INITIALIZED; open or staged: OPERATION_ACTIVE | no-query; it does not return a signature |
| C_MessageVerifyInit | init-hmac: OK; following VerifyMessage accepts the fixed signature | duplicate-init: OPERATION_ACTIVE; bad-key: OBJECT_HANDLE_INVALID; denied verify usage: KEY_FUNCTION_NOT_PERMITTED | no-query; NULL mechanism is ARGUMENTS_BAD |
| C_VerifyMessage | one-hmac: fixed witness yields OK; a second valid message succeeds after an invalid one | flipped first signature byte: SIGNATURE_INVALID; NULL/zero or present/zero witness: SIGNATURE_INVALID; no-init: OPERATION_NOT_INITIALIZED | no-query; NULL witness with nonzero length is ARGUMENTS_BAD, not an output request |
| C_VerifyMessageBegin | begin-hmac: empty parameters OK; split Hi There with witness on last part verifies | no-init: OPERATION_NOT_INITIALIZED; duplicate Begin: OPERATION_ACTIVE | no-query; NULL parameter with zero length succeeds |
| C_VerifyMessageNext | part-hmac: Hi followed by a space with NULL/zero witness continues; There plus fixed witness finishes OK | no-begin: OPERATION_NOT_INITIALIZED; present/zero witness ends with SIGNATURE_INVALID; flipped witness ends with SIGNATURE_INVALID; Begin then succeeds without re-init | no-query; NULL/zero witness is continuation; NULL/nonzero witness is ARGUMENTS_BAD |
| C_MessageVerifyFinal | final-idle: OK after either valid or invalid verdict; classic VerifyInit can use the slot | missing context: OPERATION_NOT_INITIALIZED; open message: OPERATION_ACTIVE | no-query; it does not verify or return a witness |

Spell each abbreviated result in the table with its full `CKR_` name in
assertions. For Sign/Verify split tests the first part is the three-byte
string `Hi `, and the last part is the five-byte string `There`.

Additional sequences are mandatory:

- In every family, collide message Init with a live classic Init and classic
  Init with a live message Init. Both report `CKR_OPERATION_ACTIVE`. Preserve
  the existing classic cipher-update and staged-retry mixing codes from
  section 4, then recover using the correct message call.
- Under `CKM_AES_CBC_PAD`, encrypt/decrypt `abc` and empty plaintext, with
  real classic calls on a separate session providing a byte cross-check.
  For decrypt of the empty plaintext's ciphertext, query twice for zero,
  reject outer Final while staged, deliver through a present zero-capacity
  buffer, then require outer Final to succeed.
- Construct deterministic bad CBC padding: encrypt one all-zero block with
  unpadded CBC, then decrypt it under CBC-PAD. Require
  `CKR_ENCRYPTED_DATA_INVALID`, unchanged output canaries, and a subsequent
  valid decrypt under the surviving outer context. This avoids a probabilistic
  ciphertext-bit-flip padding test.
- For direct boundary tests, feed one full 16 MiB Sign continuation and then
  one extra byte. The second append returns `CKR_ARGUMENTS_BAD`, a new Begin
  succeeds on the same outer context, and a normal HMAC message completes.
  A single oversize input fails decode instead and preserves an already-open
  message. Label the oversized direct-only legs explicitly because the pinned
  proxy has its own smaller request limit; do not exclude normal message legs
  from parity.
- Keep Encrypt and Decrypt contexts in sibling slots, complete messages in
  both, and finalize one without disturbing the other. Close a session with
  an open message and verify a new session starts with no message context.
- After every output query and short buffer, call outer Final and require
  `CKR_OPERATION_ACTIVE`; complete the recall, then require Final to succeed.
  Put a malformed recall before the valid one and verify staged bytes survive.

### 5.4 Orchestrator verification and oracle evidence

These commands describe later validation by the orchestrator. None is run as
part of drafting this spec.

1. Run the focused Haskell additions and direct consumer in the pinned
   toolchain environment, then `scripts/test-consumers.sh`. Confirm all
   twenty entries ran through each of the three interface versions.
2. Run `HASKOKI_PROXY_DIR=/opt/pkcs11-proxy-ng scripts/test-proxy-parity.sh`
   in its existing pinned container arrangement. Keep the canonical external
   daemon/shim pair and its provenance checks. Compare actual CKR, lengths,
   and bytes for the new scenario in both topologies.
3. Run `HASKOKI_PROXY_DIR=/opt/pkcs11-proxy-ng bash scripts/run-gates.sh`
   from the repository root in the host arrangement described by that script.
   Require all eighteen static gates, forced build, all Cabal suites, and
   release evidence. The existing evidence manifest already includes both
   consumer scripts, release build, and installation checks.
4. With the freshly built release bundle from that same implementation
   revision, run `bash /tmp/pkcs11-ws/run-lane-rc2.sh fast`, inspect its JSON
   findings, then run `bash /tmp/pkcs11-ws/run-lane-rc2.sh kat` and inspect its
   findings. Record the bundle/module hash, source revision, oracle revision,
   command, exit status, and result/trace paths.

The inspected local oracle is
`/tmp/pkcs11-ws/pkcs11-check-0.2.2rc2`. Its source files contain twenty-six
test definitions in `test_mech_message.py` and thirteen in
`test_message_crypto.py`. These are source-level pins, not an assertion that
thirty-nine parametrized runtime cases execute or pass. Record collection,
execution, skips, and findings separately. Mechanism-flag-based skips are
possible with the unchanged catalog and do not prove C routing.

The lane wrapper delegates to `scripts/ci-pkcs11-lane.sh`, which allows an
oracle test exit of one as reported findings. Therefore a zero wrapper exit
alone is not a clean lane. Inspect
`/tmp/pkcs11-ws/out-rc2/fast/pkcs11-fast-results.json` and
`/tmp/pkcs11-ws/out-rc2/kat/pkcs11-kat-results.json`, along with each
`trace.jsonl`. Require no unexplained new findings, crashes, setup errors,
or regressions, and no unresolved provider defect in the newly routed calls.

A concrete triage lead already visible in the inspected oracle source is
`TestMessageEncryptDecrypt.test_message_encrypt_multipart`: it constructs
CBC init without an IV and passes plaintext as Begin's AAD, then sends an
empty ending part. That differs from the pinned decoder and the existing
CBC planner/recipe intake. Record the actual newly exposed result and a
minimal independent consumer reproduction; do not alter the planner to make
this oracle shape succeed. This observation is a source discrepancy to
investigate, not a claim that a lane was executed or an upstream issue filed.

For every new oracle disagreement, update `docs/pkcs11-oracle-triage.md`
with the exact node/parameter, actual and expected return/bytes, reproduction,
normative source, and classification as provider, oracle, or capability
coverage. If the oracle expectation is wrong, make the upstream filing and
record its URL/status plus reproduction in
`docs/pkcs11-check-upstream-issues.md`. Do not replace precise evidence with
broader acceptance sets or new unconditional skips. A provider defect that
would require changing planning or mechanism semantics remains an explicit
acceptance blocker for this scope.

## 6. Acceptance

The implementation is accepted only when all of the following have evidence
for its final revision:

- All twenty generated stub bodies are absent, all twenty table assignments
  use the new `std_*` bodies, and each 3.0/3.1/3.2 table runs every entry's
  happy leg with live behavior. Valid CBC/HMAC calls use the existing supported
  recipe inputs and do not return `CKR_FUNCTION_NOT_SUPPORTED`.
- All decoder, guard, lifecycle-precedence, empty-input, state-ordering,
  classic/message collision, two-message, query, repeated-query,
  short-buffer, and canary legs above pass. The original seventeen model
  cases retain their behavior.
- All eighteen gates, forced build, Haskell suites, direct consumers,
  release-evidence drivers, and installation checks pass. The new scenario
  participates in direct/proxy parity using
  `HASKOKI_PROXY_DIR=/opt/pkcs11-proxy-ng`; it is not silently omitted by the
  consumer filename pattern or transcript normalization.
- The fast lane and then the kat lane complete against the fresh release
  bundle. Their result files are clean under section 5.4's explicit findings
  rule; source test-count pins and runtime dispositions are recorded
  separately. Documented oracle defects remain visible with source-backed
  triage and upstream filings, not relabeled as successful provider tests.
- All twenty contracts retain `planned-with-behavior` and gain the new
  consumer evidence. The walkthrough describes actual C reachability,
  the function/mechanism distinction, and the unchanged 316-row catalog, with
  the older 130-row boundary note explicitly identified as historical.
  Both oracle documents contain the new findings and their dispositions.

Routing success is function-level evidence for the existing implemented
behaviors. It is not a mechanism expansion or a general v3.0 conformance
claim.
