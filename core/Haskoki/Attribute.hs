{- | Attribute types, codecs, and visibility rules (pure).

Attribute inventory, 'getAttributes' mixed-result read, and the
canonical external byte codecs ('encodeValue'/'decodeValue') with
the 'maxAttributeBytes' bound. The semantic value stays separate
from its external encoding; search and retrieval compare/return the
intended encoding, never 'Show' output.
-}
{-# LANGUAGE OverloadedStrings #-}
module Haskoki.Attribute
  ( AttributeType (..)
  , AttributeValue (..)
  , AttributeResult (..)
  , PartialReads (..)
  , getAttributes
  , payloadSealed
  , encodeValue
  , decodeValue
  , maxAttributeBytes
  , attributeTypeByName
  , shapeMatches
  , hasTextContract
  , decodeTextAttribute
  ) where

import Data.Bits (shiftR, (.&.))
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map
import Data.Text (Text)
import qualified Data.Text.Encoding as TE
import Data.Word (Word64)

import Haskoki.Types (ReturnCode (..), redactShown)

-- | Attribute inventory: exactly the types the object flows
-- need (common storage/visibility flags, label/application search
-- keys, one sensitive payload, extractability flag), plus the
-- key-management attributes (key type, value length, usage flags,
-- always-authenticate mark, EC params, modulus bits, KEM parameter
-- set, encapsulate\/decapsulate flags), plus the standard-surface
-- attributes (key id search key, RSA public exponent). Later
-- constructors are appended so the external tag order
-- ('Haskoki.Object.attrTag') is stable.
data AttributeType
  = AttrClass
  | AttrToken
  | AttrPrivate
  | AttrLabel
  | AttrApplication
  | AttrValue
  | AttrSensitive
  | AttrExtractable
  | AttrKeyType
  | AttrValueLen
  | AttrEncrypt
  | AttrDecrypt
  | AttrSign
  | AttrVerify
  | AttrWrap
  | AttrUnwrap
  | AttrDerive
  | AttrAlwaysAuthenticate
  | AttrEcParams
  | AttrModulusBits
  | AttrKemAlg
  | AttrEncapsulate
  | AttrDecapsulate
  | AttrId
  | AttrPublicExponent
  deriving (Eq, Ord, Show, Enum, Bounded)

-- | Owned attribute values. The semantic value stays separate
-- from its external byte encoding. 'ValBytes' is a strict
-- 'ByteString': arbitrary binary keys and attributes
-- round-trip exactly, and the constructor no longer accepts values
-- (above codepoint 255) its encoder cannot preserve. 'ValULong'
-- is unsigned: negatives are unrepresentable, and the
-- codec is total over the 'Word64' domain. Conversions to
-- platform-width types ('Int' handles, ids, lengths) guard at
-- their own site, never in this representation.
data AttributeValue
  = ValBool !Bool
  | ValBytes !ByteString
  | ValULong !Word64
  deriving (Eq)

-- | 'Show' redacts byte payloads: 'ValBytes' renders its
-- kind and length only ('redactShown'), so an accidental
-- diagnostic can never expose key material. Scalars render
-- normally; explicit inspection pattern-matches the exported
-- constructors (never 'Show').
instance Show AttributeValue where
  show (ValBool b) = "ValBool " ++ show b
  show (ValULong n) = "ValULong " ++ show n
  show (ValBytes bs) = "ValBytes " ++ redactShown "bytes" (BS.length bs)

-- | Per-attribute read outcome: value delivered, withheld as
-- sensitive, or unavailable (absent type). Never an empty byte
-- array masquerading as either failure.
data AttributeResult
  = ResOk !AttributeValue
  | ResSensitive
  | ResUnavailable
  deriving (Eq, Show)

-- | One mixed read: an overall code plus per-attribute results.
-- A failing overall code still carries every readable value.
data PartialReads = PartialReads
  { prCode :: !ReturnCode
  , prResults :: ![(AttributeType, AttributeResult)]
  } deriving (Eq, Show)

-- | Read attributes from an owned attribute map. Absent types
-- report 'ResUnavailable'; the 'AttrValue' payload of an object with
-- @sensitive=true@ or @extractable=false@ redacts to 'ResSensitive'
-- (never leaks, on any path); anything else present delivers
-- 'ResOk'. Overall code: 'CKR_ATTRIBUTE_SENSITIVE' when any result
-- is sensitive (sensitivity dominates: its presence must never be
-- masked by an unrelated missing type), else
-- 'CKR_ATTRIBUTE_TYPE_INVALID' when any result is unavailable, else
-- 'CKR_OK'. Readable values ride alongside the failures in the one
-- outcome.
getAttributes :: Map AttributeType AttributeValue -> [AttributeType] -> PartialReads
getAttributes attrs wanted =
  let results = [(t, readOne t) | t <- wanted]
  in PartialReads (overallCode (map snd results)) results
  where
    readOne :: AttributeType -> AttributeResult
    readOne t = case Map.lookup t attrs of
      Nothing -> ResUnavailable
      Just v
        | t == AttrValue && payloadSealed attrs -> ResSensitive
        | otherwise -> ResOk v
    overallCode :: [AttributeResult] -> ReturnCode
    overallCode rs
      | any (== ResSensitive) rs = CKR_ATTRIBUTE_SENSITIVE
      | any (== ResUnavailable) rs = CKR_ATTRIBUTE_TYPE_INVALID
      | otherwise = CKR_OK

-- | Whether the payload ('AttrValue') of the given attribute map is
-- sealed: sensitive or unextractable. Either flag alone seals it.
payloadSealed :: Map AttributeType AttributeValue -> Bool
payloadSealed attrs = isTrue AttrSensitive || isFalse AttrExtractable
  where
    isTrue t = Map.lookup t attrs == Just (ValBool True)
    isFalse t = Map.lookup t attrs == Just (ValBool False)

-- | Bound on external byte-array attribute encodings (64 KiB;
-- pinned single source of truth, ConfigSpec pins the value).
-- 'decodeValue' rejects longer byte arrays for bytes-typed
-- attributes; scalar shapes have their own fixed widths. The C
-- packer enforces a looser 16 MiB per-value ceiling above this, so
-- this Haskell bound is the effective one. @limits.buffer_bytes@
-- does NOT drive this bound (reserved key, disclosed in the
-- capabilities report).
maxAttributeBytes :: Int
maxAttributeBytes = 65536

-- | Value shapes: each attribute type owns exactly one.
data Shape = ShapeBool | ShapeULong | ShapeBytes
  deriving (Eq, Show)

-- | The shape owned by an attribute type. Flag attributes are
-- booleans, class is an unsigned long, labels/payloads are bytes.
shapeOf :: AttributeType -> Shape
shapeOf t = case t of
  AttrToken -> ShapeBool
  AttrPrivate -> ShapeBool
  AttrSensitive -> ShapeBool
  AttrExtractable -> ShapeBool
  AttrEncrypt -> ShapeBool
  AttrDecrypt -> ShapeBool
  AttrSign -> ShapeBool
  AttrVerify -> ShapeBool
  AttrWrap -> ShapeBool
  AttrUnwrap -> ShapeBool
  AttrDerive -> ShapeBool
  AttrAlwaysAuthenticate -> ShapeBool
  AttrEncapsulate -> ShapeBool
  AttrDecapsulate -> ShapeBool
  AttrClass -> ShapeULong
  AttrKeyType -> ShapeULong
  AttrValueLen -> ShapeULong
  AttrModulusBits -> ShapeULong
  AttrKemAlg -> ShapeULong
  AttrLabel -> ShapeBytes
  AttrApplication -> ShapeBytes
  AttrValue -> ShapeBytes
  AttrEcParams -> ShapeBytes
  AttrId -> ShapeBytes
  AttrPublicExponent -> ShapeBytes

-- | Whether a value carries its type's shape. The template
-- wrong-type gate ('Haskoki.Object.validateTemplate' refuses
-- mismatches as inconsistent) and nothing else; value RANGES stay
-- the planners' call.
shapeMatches :: AttributeType -> AttributeValue -> Bool
shapeMatches t v = valueShape v == shapeOf t
  where
    valueShape :: AttributeValue -> Shape
    valueShape (ValBool _) = ShapeBool
    valueShape (ValULong _) = ShapeULong
    valueShape (ValBytes _) = ShapeBytes

-- | Canonical external encoding: booleans as one byte (0x00/0x01),
-- unsigned longs as 8-byte big-endian, byte arrays as their raw
-- bytes. Decoding validates the owning type's shape strictly, so a
-- cross-shape encoding never decodes.
encodeValue :: AttributeValue -> ByteString
encodeValue v = case v of
  ValBool False -> BS.singleton 0
  ValBool True -> BS.singleton 1
  ValULong n -> encodeULong n
  ValBytes bs -> bs

-- | Decode external bytes against the owning attribute type's
-- shape: exact widths for scalars (bool one byte of 0x00/0x01,
-- ULong 8-byte big-endian over the whole 'Word64' domain),
-- bounded length for byte arrays. Anything else is 'Nothing'.
decodeValue :: AttributeType -> ByteString -> Maybe AttributeValue
decodeValue t bs = case shapeOf t of
  ShapeBool -> case BS.unpack bs of
    [0] -> Just (ValBool False)
    [1] -> Just (ValBool True)
    _ -> Nothing
  ShapeULong -> ValULong <$> decodeULong bs
  ShapeBytes
    | BS.length bs <= maxAttributeBytes -> Just (ValBytes bs)
    | otherwise -> Nothing

-- | Whether an attribute type's bytes carry a text contract.
-- Exactly 'AttrLabel' and 'AttrApplication' do (PKCS#11 string
-- attributes); every other bytes-typed attribute ('AttrValue',
-- 'AttrEcParams', 'AttrId', 'AttrPublicExponent') is opaque binary
-- even when some layer stores ASCII in it (engine curve names stay
-- byte-compared, never text-decoded). Pinned by BytesSpec: a new
-- inventory entry defaults to non-contract until this predicate
-- says otherwise, explicitly.
hasTextContract :: AttributeType -> Bool
hasTextContract AttrLabel = True
hasTextContract AttrApplication = True
hasTextContract _ = False

-- | Decode a text-contract attribute's bytes as strict UTF-8: the
-- ONLY sanctioned text decoding of attribute bytes.
-- 'Nothing' for non-contract types (even over valid UTF-8 bytes)
-- and for invalid UTF-8.
decodeTextAttribute :: AttributeType -> ByteString -> Maybe Text
decodeTextAttribute t bs
  | hasTextContract t = either (const Nothing) Just (TE.decodeUtf8' bs)
  | otherwise = Nothing

-- | 8-byte big-endian encoding of an unsigned-long value.
-- Total: every 'Word64' encodes (same bytes as before for
-- in-range values).
encodeULong :: Word64 -> ByteString
encodeULong w = BS.pack
  [ fromIntegral ((w `shiftR` s) .&. 0xFF) | s <- [56, 48 .. 0] ]

-- | Standard @CKA_*@ name back to its inventory type. @AttrKemAlg@
-- is model-local (no standard @CKA_*@ names ML-KEM parameter sets in
-- the byte-locked headers), so it has no mapping; every other
-- constructor maps. Used by 'Haskoki.Object.checkRules' to interpret
-- template rules; pinned by TemplateRulesSpec.
attributeTypeByName :: Text -> Maybe AttributeType
attributeTypeByName name = case name of
  "CKA_CLASS" -> Just AttrClass
  "CKA_TOKEN" -> Just AttrToken
  "CKA_PRIVATE" -> Just AttrPrivate
  "CKA_LABEL" -> Just AttrLabel
  "CKA_APPLICATION" -> Just AttrApplication
  "CKA_VALUE" -> Just AttrValue
  "CKA_SENSITIVE" -> Just AttrSensitive
  "CKA_EXTRACTABLE" -> Just AttrExtractable
  "CKA_KEY_TYPE" -> Just AttrKeyType
  "CKA_VALUE_LEN" -> Just AttrValueLen
  "CKA_ENCRYPT" -> Just AttrEncrypt
  "CKA_DECRYPT" -> Just AttrDecrypt
  "CKA_SIGN" -> Just AttrSign
  "CKA_VERIFY" -> Just AttrVerify
  "CKA_WRAP" -> Just AttrWrap
  "CKA_UNWRAP" -> Just AttrUnwrap
  "CKA_DERIVE" -> Just AttrDerive
  "CKA_ALWAYS_AUTHENTICATE" -> Just AttrAlwaysAuthenticate
  "CKA_EC_PARAMS" -> Just AttrEcParams
  "CKA_MODULUS_BITS" -> Just AttrModulusBits
  "CKA_ENCAPSULATE" -> Just AttrEncapsulate
  "CKA_DECAPSULATE" -> Just AttrDecapsulate
  "CKA_ID" -> Just AttrId
  "CKA_PUBLIC_EXPONENT" -> Just AttrPublicExponent
  _ -> Nothing

-- | 8-byte big-endian decoding; total over 8-byte inputs (only
-- wrong lengths reject). Values past 'Int' range are first-class
-- model values; conversions to platform-width types guard at
-- their own site (e.g. 'Haskoki.Object.decodeHandle').
decodeULong :: ByteString -> Maybe Word64
decodeULong bs
  | BS.length bs /= 8 = Nothing
  | otherwise = Just (BS.foldl' (\acc b -> acc * 256 + fromIntegral b) 0 bs)
