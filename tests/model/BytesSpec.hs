{- | Byte-representation pins.

The value codec preserves every byte value (0-255 including NUL
and bytes above 127) over 'ByteString' payloads; text decoding is
explicit and limited to the attributes with a text contract
('AttrLabel', 'AttrApplication'). Persisted v1 object documents
and snapshot key fingerprints survive the String-to-ByteString
migration byte-identically (compatibility, never silent
migration).
-}
{-# LANGUAGE OverloadedStrings #-}
module BytesSpec (spec) where

import qualified Data.ByteString as BS
import qualified Data.Map.Strict as Map
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertEqual, assertFailure, testCase)

import Haskoki.Attribute
  ( AttributeType (..)
  , AttributeValue (..)
  , decodeTextAttribute
  , decodeValue
  , encodeValue
  , hasTextContract
  , maxAttributeBytes
  )
import Haskoki.Model (ObjectState (..))
import Haskoki.Runtime.Storage
  ( ObjectRecord (..)
  , decodeAttrsDoc
  , decodeObjectRecord
  , encodeAttrsDoc
  , encodeObjectRecord
  )
import Haskoki.Snapshot (KeyIdentity (..), fingerprintKey, keyIdentityOf)
import Haskoki.Types
  ( Generation (..)
  , ObjectId (..)
  , Revision (..)
  , SlotId (..)
  )

spec :: TestTree
spec = testGroup "Byte representation"
  [ testCase "byte range 0-255 round-trips (NUL, >127)" caseByteRange
  , testCase "structured byte strings round-trip exactly" caseStructured
  , testCase "over-bound byte strings reject" caseBoundRejects
  , testCase "persisted v1 object doc survives byte-identically" casePersistedDocCompat
  , testCase "key fingerprint pins the FNV-1a value" caseFingerprintStable
  , testCase "key identity reads high-byte material" caseKeyIdentityHighBytes
  , testCase "text contract admits exactly label+application" caseTextContract
  , testCase "text decoding accepts valid UTF-8 labels" caseTextValid
  , testCase "text decoding rejects invalid UTF-8" caseTextInvalid
  , testCase "text decoding rejects non-contract types" caseTextNonContract
  , testCase "sqlite attrs doc golden" caseAttrsDocGolden
  ]

-- | Every single byte value decodes as 'AttrValue' and re-encodes
-- to itself.
caseByteRange :: IO ()
caseByteRange = mapM_ check [0 .. 255]
  where
    check :: Int -> IO ()
    check b =
      let bs = BS.singleton (fromIntegral b)
      in case decodeValue AttrValue bs of
        Nothing -> assertFailure ("byte " ++ show b ++ " rejected")
        Just v -> assertEqual ("byte " ++ show b) bs (encodeValue v)

-- | Structured inputs round-trip exactly: empty, NUL runs,
-- all-256-bytes, high bytes, multi-byte UTF-8 sequences, and the
-- 64 KiB bound itself.
caseStructured :: IO ()
caseStructured = mapM_ check
  [ BS.empty
  , BS.replicate 16 0
  , BS.pack [0 .. 255]
  , BS.pack [0, 127, 128, 255, 1, 254]
  , BS.pack [0xCC, 0x80]
  , "s3cret"
  , BS.replicate maxAttributeBytes 0xAB
  ]
  where
    check bs = case decodeValue AttrValue bs of
      Nothing -> assertFailure ("rejected: " ++ show (BS.length bs) ++ " bytes")
      Just v -> assertEqual "round-trip" bs (encodeValue v)

-- | One past the bound rejects; exactly the bound accepts.
caseBoundRejects :: IO ()
caseBoundRejects = do
  assertEqual "bound accepts" True $
    case decodeValue AttrValue (BS.replicate maxAttributeBytes 0) of
      Just _ -> True
      Nothing -> False
  assertEqual "bound+1 rejects" Nothing
    (decodeValue AttrValue (BS.replicate (maxAttributeBytes + 1) 0))

-- | A hand-written v1 object document with high-byte material
-- (bytes 0, 127, 128, 255, 1, 254): it decodes and re-encodes
-- byte-identically, pinning persisted-bytes compatibility across
-- the migration.
v1DocHighBytes :: String
v1DocHighBytes =
  "{\"attrs\":{\"class\":\"0000000000000004\",\
  \\"key_type\":\"000000000000001f\",\"value\":\"AH+A/wH+\"},\
  \\"class\":\"0000000000000004\",\"format_version\":1,\
  \\"key_type\":\"000000000000001f\",\"material\":\"AH+A/wH+\",\
  \\"material_encoding\":\"attr-value/v1\",\
  \\"object_id\":\"0000000000000009\",\
  \\"revision\":\"0000000000000001\",\"token_id\":\"0000000000000001\"}"

casePersistedDocCompat :: IO ()
casePersistedDocCompat = case decodeObjectRecord v1DocHighBytes of
  Nothing -> assertFailure "v1 doc rejected"
  Just rec -> do
    assertEqual "re-encode byte-identical" v1DocHighBytes (encodeObjectRecord rec)
    assertEqual "class key" 4 (orClass rec)
    assertEqual "key-type key" (Just 0x1F) (orKeyType rec)
    assertEqual "attr value bytes"
      (Just (ValBytes (BS.pack [0, 127, 128, 255, 1, 254])))
      (Map.lookup AttrValue (orAttrs rec))

-- | The FNV-1a 64 fingerprint of the high-byte material, pinned
-- against an independently computed oracle (Python).
caseFingerprintStable :: IO ()
caseFingerprintStable =
  assertEqual "FNV-1a 64 of high bytes" 3599896030550276814
    (fingerprintKey (BS.pack [0, 127, 128, 255, 1, 254]))

-- | 'keyIdentityOf' over high-byte material: class, key type, and
-- the pinned fingerprint.
caseKeyIdentityHighBytes :: IO ()
caseKeyIdentityHighBytes =
  let ost = ObjectState
        { osId = ObjectId 9
        , osRevision = Revision 1
        , osGeneration = Generation 1
        , osAttrs = Map.fromList
            [ (AttrClass, ValULong 4)
            , (AttrKeyType, ValULong 0x1F)
            , (AttrValue, ValBytes (BS.pack [0, 127, 128, 255, 1, 254]))
            ]
        , osOwner = Nothing
        , osSlot = SlotId 7
        }
  in assertEqual "identity over high-byte material"
    (Just (KeyIdentity 4 (Just 0x1F) 3599896030550276814))
    (keyIdentityOf ost)

-- | Exactly the label and application attributes carry a text
-- contract; a new inventory entry defaults to non-contract until
-- 'hasTextContract' says otherwise, explicitly.
caseTextContract :: IO ()
caseTextContract =
  assertEqual "contract set" [AttrLabel, AttrApplication]
    (filter hasTextContract [minBound .. maxBound])

-- | Valid UTF-8 decodes on contract types.
caseTextValid :: IO ()
caseTextValid = do
  assertEqual "label" (Just "key-1") (decodeTextAttribute AttrLabel "key-1")
  assertEqual "application" (Just "app") (decodeTextAttribute AttrApplication "app")
  assertEqual "empty" (Just "") (decodeTextAttribute AttrLabel BS.empty)

-- | Invalid UTF-8 rejects even on contract types.
caseTextInvalid :: IO ()
caseTextInvalid = do
  assertEqual "lone high byte" Nothing
    (decodeTextAttribute AttrLabel (BS.pack [0xFF, 0xFE]))
  assertEqual "truncated sequence" Nothing
    (decodeTextAttribute AttrApplication (BS.pack [0xCC]))

-- | Non-contract types reject even over valid UTF-8 bytes: binary
-- attributes are never text-decoded, including engine curve names.
caseTextNonContract :: IO ()
caseTextNonContract = do
  assertEqual "value" Nothing (decodeTextAttribute AttrValue "abc")
  assertEqual "ec params" Nothing (decodeTextAttribute AttrEcParams "P-256")
  assertEqual "id" Nothing (decodeTextAttribute AttrId "abc")
  assertEqual "public exponent" Nothing (decodeTextAttribute AttrPublicExponent "abc")
  assertEqual "class" Nothing (decodeTextAttribute AttrClass "abc")

-- | The SQLite @attributes_json@ column encoding, pinned
-- byte-exactly (hand-derived from docs/byte-formats.md §5): keys
-- sorted, no whitespace, ulongs as 16-hex, bytes as base64.
caseAttrsDocGolden :: IO ()
caseAttrsDocGolden = do
  let attrs = Map.fromList
        [ (AttrClass, ValULong 4)
        , (AttrToken, ValBool True)
        , (AttrLabel, ValBytes "ab")
        ]
      golden = "{\"class\":\"0000000000000004\",\"label\":\"YWI=\",\"token\":true}"
  assertEqual "attrs doc golden" golden (encodeAttrsDoc attrs)
  assertEqual "attrs doc round-trip" (Just attrs) (decodeAttrsDoc golden)
  assertEqual "unknown name" Nothing (decodeAttrsDoc "{\"nope\":true}")
  assertEqual "cross-shape" Nothing (decodeAttrsDoc "{\"token\":\"xx\"}")
