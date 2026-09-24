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

import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import Data.Word (Word64, Word8)
import Foreign.C.Types (CULong (..))
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertEqual, assertBool, testCase)

import Haskoki.Attribute (AttributeType (..), AttributeValue (..))
import Haskoki.FFI.Standard
  ( FrameError (..)
  , ecParamsFromWire
  , ecParamsToWire
  , frameErrorRV
  , nativeEncodeAttr
  , parseTemplateFrame
  , pinsMatch
  , provisionedSoPin
  , provisionedUserPin
  , sessionScalars
  , tokenScalars
  )
import Haskoki.Model
  ( SessionState (..)
  , addToken
  , emptyModel
  )
import Haskoki.Operation (emptySessionOps)
import Haskoki.Rules (Rules (..), defaultRules)
import Haskoki.Session (SessionLogin (..))
import Haskoki.Types
  ( Generation (..)
  , Revision (..)
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
  ]

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
  let frame = word 3
        <> attr 0x00 (word 4) -- CKA_CLASS = 4 (secret key)
        <> attr 0x01 (BS.singleton 1) -- CKA_TOKEN = true
        <> attr 0x03 "key-1" -- CKA_LABEL
  assertEqual "three attrs" (Right
    [ (AttrClass, ValULong 4)
    , (AttrToken, ValBool True)
    , (AttrLabel, ValBytes "key-1")
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
