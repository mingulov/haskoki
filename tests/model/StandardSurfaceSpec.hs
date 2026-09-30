{- | Standard-surface unit tests.

Pins the pure boundary contracts the C surface relies on:

* template-frame decoding (count + @(type, len, bytes)@ records,
  all integers little-endian u64): shapes, truncation, unknown
  types, bad values;
* EC_PARAMS wire mapping (DER OIDs from RFC 5480 to engine curve
  names and back);
* session/token scalar projections (plain words; the C side owns
  all CK_STATE\/CKF_* spellings);
* constant-time provisioned-PIN comparison.
-}
{-# LANGUAGE OverloadedStrings #-}
module StandardSurfaceSpec (spec) where

import Control.Exception (bracket)
import Control.Monad (forM_)
import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import qualified Data.Map.Strict as Map
import Data.Word (Word64, Word8)
import Foreign.C.Types (CULong (..))
import Foreign.Marshal.Alloc (alloca, allocaBytes)
import Foreign.Marshal.Array (peekArray, pokeArray)
import Foreign.Ptr (Ptr, nullPtr, castPtr)
import Foreign.StablePtr (StablePtr, castStablePtrToPtr, deRefStablePtr)
import Foreign.Storable (peek, poke)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertEqual, assertBool, testCase)

import Haskoki.Attribute (AttributeType (..), AttributeValue (..))
import Haskoki.FFI.Async (decodeAsyncFunctionName, jobFunctionCode)
import Haskoki.FFI.Decode (maxInputBytes)
import Haskoki.FFI.Standard
  ( FrameError (..)
  , ecParamsFromWire
  , ecParamsToWire
  , frameErrorRV
  , lookupStdAsyncBinding
  , nativeEncodeAttr
  , parseTemplateFrame
  , pinsMatch
  , provisionedSoPin
  , provisionedUserPin
  , sessionScalars
  , tokenScalars
  , StdInstance (..)
  , openStdInstance
  , haskokiStdClose
  , haskokiStdOpenSession
  , haskokiStdCreateObject
  , haskokiStdEncryptInit
  , haskokiStdEncrypt
  , stdRvOf
  , haskokiStdMessageEncryptInit
  , haskokiStdMessageEncrypt
  , haskokiStdMessageEncryptBegin
  , haskokiStdMessageEncryptNext
  , haskokiStdMessageEncryptFinal
  , haskokiStdMessageDecryptInit
  , haskokiStdMessageDecrypt
  , haskokiStdMessageDecryptBegin
  , haskokiStdMessageDecryptNext
  , haskokiStdMessageDecryptFinal
  , haskokiStdMessageSignInit
  , haskokiStdMessageSign
  , haskokiStdMessageSignBegin
  , haskokiStdMessageSignNext
  , haskokiStdMessageSignFinal
  , haskokiStdMessageVerifyInit
  , haskokiStdMessageVerify
  , haskokiStdMessageVerifyBegin
  , haskokiStdMessageVerifyNext
  , haskokiStdMessageVerifyFinal
  )
import Haskoki.Model
  ( SessionState (..)
  , addToken
  , emptyModel
  , lookupSession
  )
import Haskoki.Operation (emptySessionOps, MsgState(..), MsgFamily(..), SlotKind(..), stagedOf)
import Haskoki.Operation.Message (lookupMessage, messageBuffered)
import Haskoki.Rules (Rules (..), defaultRules)
import Haskoki.Runtime.Async (JobFunction (..))
import Haskoki.Runtime.Config (defaultConfig)
import Haskoki.Runtime.Lifecycle (snapshotModel)
import Haskoki.Session (SessionLogin (..))
import Haskoki.Types
  ( Generation (..)
  , Revision (..)
  , ReturnCode (..)
  , SessionId (..)
  , SlotId (..)
  )

spec :: TestTree
spec = testGroup "Standard surface"
  [ testCase "policy constants pinned for C" casePolicyPins
  , testCase "native attr encoding" caseNativeEncode
  , testCase "frame errors map to CK_RV" caseFrameRV
  , testCase "empty frame decodes" caseEmptyFrame
  , testCase "ulong/bool/bytes values decode" caseValues
  , testCase "truncation and bounds fail" caseMalformed
  , testCase "unknown type and bad value fail typed" caseTypedFaults
  , testCase "EC params map both ways" caseEcParams
  , testCase "session scalars project" caseSessionScalars
  , testCase "token scalars project" caseTokenScalars
  , testCase "PIN comparison is exact" casePins
  , testCase "caseAsyncFunctionNames" caseAsyncFunctionNames
  , testCase "caseAsyncBindingLookup" caseAsyncBindingLookup
  , testCase "message exports and session precedence" caseMessageExports
  , testCase "message cipher continuation query preserves snapshot" caseMessageContinuationQuery
  , testCase "message staged query short and exact" caseMessageStagedQuery
  , testCase "message empty staged output" caseMessageEmptyQuery
  , testCase "message verify presence and sign continuation" caseMessageSignals
  ]

caseAsyncFunctionNames :: IO ()
caseAsyncFunctionNames = do
  forM_ [("C_Sign", JobSign, 1), ("C_Digest", JobDigest, 2)] $
    \(name, function, code) -> do
      result <- decodeBytes (BS.snoc name 0)
      assertEqual (show name <> " identity") (Right function) result
      assertEqual (show name <> " code") (Right code) (jobFunctionCode <$> result)
  forM_
    [ "", "c_Digest", "C_DIGEST", "C_Digestx", "1", "2"
    , "sign", "digest", "C_GenerateKey", "C_GenerateKeyPair"
    ] $ \name -> do
      result <- decodeBytes (BS.snoc name 0)
      assertEqual (show name <> " refused") (Left CKR_ARGUMENTS_BAD) result
  forM_
    [ ("non-ASCII byte", BS.pack [0x80, 0])
    , ("32 non-NUL bytes", BS.replicate 32 0x78)
    , ("NUL at byte 32", BS.snoc (BS.replicate 31 0x78) 0)
    ] $ \(label, bytes) -> do
      result <- decodeBytes bytes
      assertEqual label (Left CKR_ARGUMENTS_BAD) result
  result <- decodeBytes "C_Digest\0junk"
  assertEqual "first NUL ends the name" (Right JobDigest) result
  where
    -- Allocate exactly the supplied bytes, including only the first NUL
    -- for the valid names above. Protected-page checks belong to Task 6.
    decodeBytes :: ByteString -> IO (Either ReturnCode JobFunction)
    decodeBytes bytes = allocaBytes (BS.length bytes) $ \ptr -> do
      pokeArray ptr (BS.unpack bytes)
      decodeAsyncFunctionName ptr

caseAsyncBindingLookup :: IO ()
caseAsyncBindingLookup = do
  let bindings = Map.fromList
        [ ((SessionId 1, JobDigest), "session-1-digest" :: ByteString)
        , ((SessionId 1, JobSign), "session-1-sign")
        , ((SessionId 2, JobDigest), "session-2-digest")
        ]
  assertEqual "first session digest" (Just "session-1-digest")
    (lookupStdAsyncBinding (SessionId 1) JobDigest bindings)
  assertEqual "first session sign" (Just "session-1-sign")
    (lookupStdAsyncBinding (SessionId 1) JobSign bindings)
  assertEqual "second session digest" (Just "session-2-digest")
    (lookupStdAsyncBinding (SessionId 2) JobDigest bindings)
  assertEqual "no other function fallback" Nothing
    (lookupStdAsyncBinding (SessionId 2) JobSign bindings)
  assertEqual "no other session fallback" Nothing
    (lookupStdAsyncBinding (SessionId 3) JobDigest bindings)
  assertEqual "no key-generation binding" Nothing
    (lookupStdAsyncBinding (SessionId 1) JobGenKey bindings)
  assertEqual "empty bindings" Nothing
    (lookupStdAsyncBinding (SessionId 1) JobDigest (Map.empty :: Map.Map (SessionId, JobFunction) ByteString))

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

attr :: Word64 -> ByteString -> ByteString
attr t v = word t <> word (fromIntegral (BS.length v)) <> v

casePolicyPins :: IO ()
casePolicyPins = do
  -- The C token-info record duplicates these (standard_surface.c);
  -- this pin fails loudly if the Haskell side ever moves.
  assertEqual "max sessions" 1024 (rulesMaxSessions defaultRules)
  assertEqual "max PIN attempts" 3 (rulesMaxPinAttempts defaultRules)

caseNativeEncode :: IO ()
caseNativeEncode = do
  assertEqual "bool true" (BS.singleton 1)
    (nativeEncodeAttr AttrToken (ValBool True))
  assertEqual "bool false" (BS.singleton 0)
    (nativeEncodeAttr AttrToken (ValBool False))
  assertEqual "ulong LE" (word 4)
    (nativeEncodeAttr AttrClass (ValULong 4))
  assertEqual "bytes raw" "key-1"
    (nativeEncodeAttr AttrLabel (ValBytes "key-1"))
  assertEqual "ec params to wire" (BS.pack p256der)
    (nativeEncodeAttr AttrEcParams (ValBytes "P-256"))

caseFrameRV :: IO ()
caseFrameRV = do
  -- Pinned header values (spec/vendor/pkcs11.h):
  -- ARGUMENTS_BAD 0x07, TEMPLATE_INCONSISTENT 0xD1,
  -- ATTRIBUTE_TYPE_INVALID 0x12.
  assertEqual "truncated" (CULong 0x07) (frameErrorRV FrameTruncated)
  assertEqual "too many" (CULong 0x07) (frameErrorRV FrameTooManyAttrs)
  assertEqual "unknown type" (CULong 0x12)
    (frameErrorRV (FrameUnknownType 0xDEAD))
  assertEqual "bad value" (CULong 0xD1)
    (frameErrorRV (FrameBadValue AttrToken))

caseEmptyFrame :: IO ()
caseEmptyFrame = do
  assertEqual "count 0" (Right []) (parseTemplateFrame (word 0))
  assertEqual "empty input truncates" (Left FrameTruncated)
    (parseTemplateFrame BS.empty)

caseValues :: IO ()
caseValues = do
  let frame = word 4
        <> attr 0x00 (word 4) -- CKA_CLASS = 4 (secret key)
        <> attr 0x01 (BS.singleton 1) -- CKA_TOKEN = true
        <> attr 0x03 "key-1" -- CKA_LABEL
        <> attr 0x170 (BS.singleton 1) -- CKA_MODIFIABLE = true
  assertEqual "four attrs" (Right
    [ (AttrClass, ValULong 4)
    , (AttrToken, ValBool True)
    , (AttrLabel, ValBytes "key-1")
    , (AttrModifiable, ValBool True)
    ]) (parseTemplateFrame frame)

caseMalformed :: IO ()
caseMalformed = do
  assertEqual "short header" (Left FrameTruncated)
    (parseTemplateFrame (BS.take 7 (word 1)))
  assertEqual "short record" (Left FrameTruncated)
    (parseTemplateFrame (word 1 <> word 0x00))
  assertEqual "overrun value" (Left FrameTruncated)
    (parseTemplateFrame (word 1 <> word 0x00 <> word 8 <> "abcd"))
  assertEqual "too many attrs" (Left FrameTooManyAttrs)
    (parseTemplateFrame (word 65))

caseTypedFaults :: IO ()
caseTypedFaults = do
  assertEqual "unknown type" (Left (FrameUnknownType 0xDEAD))
    (parseTemplateFrame (word 1 <> attr 0xDEAD "x"))
  assertEqual "bool len 2" (Left (FrameBadValue AttrToken))
    (parseTemplateFrame (word 1 <> attr 0x01 (BS.pack [1, 0])))
  assertEqual "ulong len 4" (Left (FrameBadValue AttrClass))
    (parseTemplateFrame (word 1 <> attr 0x00 "abcd"))

p256der :: [Word8]
p256der = [0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07]

p384der :: [Word8]
p384der = [0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22]

p521der :: [Word8]
p521der = [0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x23]

caseEcParams :: IO ()
caseEcParams = do
  assertEqual "P-256 from wire" "P-256" (ecParamsFromWire (BS.pack p256der))
  assertEqual "P-384 from wire" "P-384" (ecParamsFromWire (BS.pack p384der))
  assertEqual "P-521 from wire" "P-521" (ecParamsFromWire (BS.pack p521der))
  assertEqual "unknown passes through" "weird" (ecParamsFromWire "weird")
  assertEqual "P-256 to wire" (BS.pack p256der) (ecParamsToWire "P-256")
  assertEqual "P-384 to wire" (BS.pack p384der) (ecParamsToWire "P-384")
  assertEqual "P-521 to wire" (BS.pack p521der) (ecParamsToWire "P-521")
  assertEqual "unknown to wire passes" "weird" (ecParamsToWire "weird")

mkSession :: SessionId -> SlotId -> Bool -> SessionLogin -> SessionState
mkSession sid slot ro login = SessionState
  { ssId = sid
  , ssSlot = slot
  , ssRevision = Revision 1
  , ssGeneration = Generation 1
  , ssReadOnly = ro
  , ssLogin = login
  , ssOps = emptySessionOps
  }

caseSessionScalars :: IO ()
caseSessionScalars = do
  assertEqual "ro public" (0, 1, 0, 0)
    (sessionScalars (mkSession (SessionId 7) (SlotId 0) True LoginPublic))
  assertEqual "rw user" (0, 0, 1, 0)
    (sessionScalars (mkSession (SessionId 7) (SlotId 0) False LoginUser))
  assertEqual "rw so" (0, 0, 2, 0)
    (sessionScalars (mkSession (SessionId 7) (SlotId 0) False LoginSO))
  assertEqual "ro context" (0, 1, 3, 0)
    (sessionScalars (mkSession (SessionId 7) (SlotId 0) True LoginContextUser))

caseTokenScalars :: IO ()
caseTokenScalars = do
  let m0 = emptyModel
  assertEqual "no token" (0, 0, 0, 0, 0, 0)
    (tokenScalars defaultRules m0 (SlotId 0))
  let m1 = addToken m0 (SlotId 0)
  assertEqual "fresh token, no sessions" (0, 0, 0, 0, 3, 3)
    (tokenScalars defaultRules m1 (SlotId 0))

casePins :: IO ()
casePins = do
  assertEqual "user PIN documented" "1234" provisionedUserPin
  assertEqual "so PIN documented" "5678" provisionedSoPin
  assertBool "equal" (pinsMatch "1234" "1234")
  assertBool "differ" (not (pinsMatch "1234" "1235"))
  assertBool "length differs" (not (pinsMatch "1234" "12345"))
  assertBool "empty differs" (not (pinsMatch "1234" ""))
  -- The accepted semantics, pinned beyond the originals.
  assertBool "prefix differs" (not (pinsMatch "1234" "123"))
  assertBool "both empty" (pinsMatch "" "")
  assertBool "high bytes equal" (pinsMatch "\255\0" "\255\0")
  assertBool "high bytes differ" (not (pinsMatch "a\255" "a\254"))

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
