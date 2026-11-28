{- | Detached detach recipes.
-}
module Haskoki.Runtime.Detached.Recipes
  ( Recipe (..)
  , recipeNameCall
  , recipeNameGenKey
  , recipeNameGenKeyPair
  , jobFunctionName
  , nameJobFunction
  , functionCode
  , codeFunction
  , encodeRecipe
  , decodeRecipe
  , encodeEffect
  , takeEffect
  , encodeKey
  , takeKey
  , takeFlag
  , guardEmpty
  , u32be
  , u64be
  , u32prefixed
  , takeU32
  , takeU64
  , takePrefixed
  , foldBE
  , recipeFromWork
  ) where

import Data.Bits (shiftR, (.&.))
import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import qualified Data.ByteString.Char8 as BC8
import Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map
import Data.Word (Word64, Word8)
import Haskoki.Attribute (AttributeType, AttributeValue, historyAttrs)
import Haskoki.CallWork (callWorkEffect)
import Haskoki.Operation.Effect (CryptoEffect (..))
import Haskoki.Operation.KeyManagement
  ( PendingObject (..)
  , PendingWork (..)
  )
import Haskoki.Outcome
  ( EffectRequest (..)
  )
import Haskoki.Registry (MechanismId (..))
import Haskoki.Runtime.Async
  ( AsyncWork (..)
  , JobFunction (..)
  )
import Haskoki.Runtime.Storage
  ( decodeAttrsDoc
  , encodeAttrsDoc
  )
import Haskoki.Types
  ( ObjectId (..)
  )

-- ---------------------------------------------------------------------------
-- Recipes
-- ---------------------------------------------------------------------------

-- | A pointer-free pending-job recipe: everything a rejoin needs to
-- replay the submission against the current model. Logical identities
-- only (mechanism ids, byte blobs, logical object ids, attribute
-- documents): no handle, no pointer, no native context.
data Recipe
  = RecipeCall
      { rcFunc :: !JobFunction
      , rcTicks :: !Int
      , rcCapacity :: !Word64
      , rcEffect :: !CryptoEffect
      }
  | RecipeGenKey
      { rkTicks :: !Int
      , rkCapacity :: !Word64
      , rkEffect :: !CryptoEffect
      , rkTemplate :: !(Map AttributeType AttributeValue)
      , rkSessionOwned :: !Bool
      }
  | RecipeGenKeyPair
      { rkpTicks :: !Int
      , rkpCapacity :: !Word64
      , rkpEffect :: !CryptoEffect
      , rkpPub :: !(Map AttributeType AttributeValue)
      , rkpPriv :: !(Map AttributeType AttributeValue)
      , rkpPubOwned :: !Bool
      , rkpPrivOwned :: !Bool
      }
  deriving (Eq, Show)

-- | Pending-recipe names (versioned; unknown names reject on join).
recipeNameCall, recipeNameGenKey, recipeNameGenKeyPair :: String
recipeNameCall = "haskoki-call/v1"
recipeNameGenKey = "haskoki-genkey/v1"
recipeNameGenKeyPair = "haskoki-genkeypair/v1"

-- | Durable function names for 'jrFunction'.
jobFunctionName :: JobFunction -> String
jobFunctionName JobSign = "sign"
jobFunctionName JobDigest = "digest"
jobFunctionName JobGenKey = "genkey"
jobFunctionName JobGenKeyPair = "genkeypair"

-- | Parse a durable function name.
nameJobFunction :: String -> Maybe JobFunction
nameJobFunction "sign" = Just JobSign
nameJobFunction "digest" = Just JobDigest
nameJobFunction "genkey" = Just JobGenKey
nameJobFunction "genkeypair" = Just JobGenKeyPair
nameJobFunction _ = Nothing

-- | Function codes in recipe params (explicit, stable: append-only).
-- They match the FFI poller codes by convention, not by import.
functionCode :: JobFunction -> Word64
functionCode JobSign = 1
functionCode JobDigest = 2
functionCode JobGenKey = 3
functionCode JobGenKeyPair = 4

-- | Parse a recipe function code.
codeFunction :: Word64 -> Maybe JobFunction
codeFunction 1 = Just JobSign
codeFunction 2 = Just JobDigest
codeFunction 3 = Just JobGenKey
codeFunction 4 = Just JobGenKeyPair
codeFunction _ = Nothing

-- | Encode a recipe to its (name, params) record body. Encoding is
-- strict big-endian frames: exact-length decode only.
encodeRecipe :: Recipe -> (String, ByteString)
encodeRecipe r = case r of
  RecipeCall func ticks cap fx ->
    ( recipeNameCall
    , BS.pack [codeByte func]
      <> u32be (fromIntegral ticks)
      <> u64be cap
      <> encodeEffect fx
    )
  RecipeGenKey ticks cap fx tmpl owned ->
    ( recipeNameGenKey
    , u32be (fromIntegral ticks)
      <> u64be cap
      <> encodeEffect fx
      <> BS.pack [if owned then 1 else 0]
      <> u32prefixed (BC8.pack (encodeAttrsDoc tmpl))
    )
  RecipeGenKeyPair ticks cap fx pub priv pubOwned privOwned ->
    ( recipeNameGenKeyPair
    , u32be (fromIntegral ticks)
      <> u64be cap
      <> encodeEffect fx
      <> BS.pack [if pubOwned then 1 else 0, if privOwned then 1 else 0]
      <> u32prefixed (BC8.pack (encodeAttrsDoc pub))
      <> u32prefixed (BC8.pack (encodeAttrsDoc priv))
    )
  where
    codeByte :: JobFunction -> Word8
    codeByte f = fromIntegral (functionCode f)

-- | Strict recipe decode: the name selects the shape, and every
-- frame must consume its bytes exactly. 'Nothing' rejects unknown
-- names, short/trailing bytes, and unknown effect shapes.
decodeRecipe :: String -> ByteString -> Maybe Recipe
decodeRecipe name bs
  | name == recipeNameCall = case BS.uncons bs of
      Just (fb, rest0) -> do
        func <- codeFunction (fromIntegral fb)
        (ticks, rest1) <- takeU32 rest0
        (cap, rest2) <- takeU64 rest1
        (fx, rest3) <- takeEffect rest2
        guardEmpty rest3
        pure RecipeCall
          { rcFunc = func
          , rcTicks = fromIntegral ticks
          , rcCapacity = cap
          , rcEffect = fx
          }
      Nothing -> Nothing
  | name == recipeNameGenKey = do
      (ticks, rest0) <- takeU32 bs
      (cap, rest1) <- takeU64 rest0
      (fx, rest2) <- takeEffect rest1
      (owned, rest3) <- takeFlag rest2
      (doc, rest4) <- takePrefixed rest3
      guardEmpty rest4
      tmpl <- decodeAttrsDoc (BC8.unpack doc)
      pure RecipeGenKey
        { rkTicks = fromIntegral ticks
        , rkCapacity = cap
        , rkEffect = fx
        , rkTemplate = tmpl
        , rkSessionOwned = owned
        }
  | name == recipeNameGenKeyPair = do
      (ticks, rest0) <- takeU32 bs
      (cap, rest1) <- takeU64 rest0
      (fx, rest2) <- takeEffect rest1
      (pubOwned, rest3) <- takeFlag rest2
      (privOwned, rest4) <- takeFlag rest3
      (pubDoc, rest5) <- takePrefixed rest4
      (privDoc, rest6) <- takePrefixed rest5
      guardEmpty rest6
      pub <- decodeAttrsDoc (BC8.unpack pubDoc)
      priv <- decodeAttrsDoc (BC8.unpack privDoc)
      pure RecipeGenKeyPair
        { rkpTicks = fromIntegral ticks
        , rkpCapacity = cap
        , rkpEffect = fx
        , rkpPub = pub
        , rkpPriv = priv
        , rkpPubOwned = pubOwned
        , rkpPrivOwned = privOwned
        }
  | otherwise = Nothing

-- | Effect shapes with a detach recipe: one-shot digest, one-shot
-- sign, and key generation. Every other shape (cipher, verify,
-- message, wrap, derive, KEM, and the digest stream steps, which
-- name live backend contexts) has no async submission path in this
-- facility and no recipe.
encodeEffect :: CryptoEffect -> ByteString
encodeEffect fx = case fx of
  FxDigest (MechanismId m) input ->
    BS.pack [0xD1] <> u64be m <> u32prefixed input
  FxSign (MechanismId m) key params input ->
    BS.pack [0x51] <> u64be m <> encodeKey key
      <> u32prefixed params <> u32prefixed input
  FxGenerateKey (MechanismId m) params input ->
    BS.pack [0x6B] <> u64be m <> u32prefixed params <> u32prefixed input
  _ -> BS.pack [0x00]

-- | Strict effect decode; tag @0x00@ and unknown tags reject.
takeEffect :: ByteString -> Maybe (CryptoEffect, ByteString)
takeEffect bs = case BS.uncons bs of
  Just (0xD1, rest0) -> do
    (m, rest1) <- takeU64 rest0
    (input, rest2) <- takePrefixed rest1
    pure (FxDigest (MechanismId m) input, rest2)
  Just (0x51, rest0) -> do
    (m, rest1) <- takeU64 rest0
    (key, rest2) <- takeKey rest1
    (params, rest3) <- takePrefixed rest2
    (input, rest4) <- takePrefixed rest3
    pure (FxSign (MechanismId m) key params input, rest4)
  Just (0x6B, rest0) -> do
    (m, rest1) <- takeU64 rest0
    (params, rest2) <- takePrefixed rest1
    (input, rest3) <- takePrefixed rest2
    pure (FxGenerateKey (MechanismId m) params input, rest3)
  _ -> Nothing

-- | Optional logical key reference: @0x00@ = none, @0x01@ + u64be id.
encodeKey :: Maybe ObjectId -> ByteString
encodeKey Nothing = BS.pack [0x00]
encodeKey (Just (ObjectId n)) = BS.pack [0x01] <> u64be (fromIntegral n)

-- | Strict key-reference decode.
takeKey :: ByteString -> Maybe (Maybe ObjectId, ByteString)
takeKey bs = case BS.uncons bs of
  Just (0x00, rest) -> Just (Nothing, rest)
  Just (0x01, rest) -> do
    (n, rest') <- takeU64 rest
    if n > fromIntegral (maxBound :: Int)
      then Nothing
      else Just (Just (ObjectId (fromIntegral n)), rest')
  _ -> Nothing

-- | Strict one-byte flag decode (@0x00@\/@0x01@ only).
takeFlag :: ByteString -> Maybe (Bool, ByteString)
takeFlag bs = case BS.uncons bs of
  Just (0x00, rest) -> Just (False, rest)
  Just (0x01, rest) -> Just (True, rest)
  _ -> Nothing

-- | Reject trailing bytes.
guardEmpty :: ByteString -> Maybe ()
guardEmpty rest
  | BS.null rest = Just ()
  | otherwise = Nothing

-- | Big-endian 32-bit frame.
u32be :: Word64 -> ByteString
u32be w = BS.pack
  [ fromIntegral ((w `shiftR` 24) .&. 0xFF)
  , fromIntegral ((w `shiftR` 16) .&. 0xFF)
  , fromIntegral ((w `shiftR` 8) .&. 0xFF)
  , fromIntegral (w .&. 0xFF)
  ]

-- | Big-endian 64-bit frame.
u64be :: Word64 -> ByteString
u64be w = BS.pack
  [ fromIntegral ((w `shiftR` 56) .&. 0xFF)
  , fromIntegral ((w `shiftR` 48) .&. 0xFF)
  , fromIntegral ((w `shiftR` 40) .&. 0xFF)
  , fromIntegral ((w `shiftR` 32) .&. 0xFF)
  , fromIntegral ((w `shiftR` 24) .&. 0xFF)
  , fromIntegral ((w `shiftR` 16) .&. 0xFF)
  , fromIntegral ((w `shiftR` 8) .&. 0xFF)
  , fromIntegral (w .&. 0xFF)
  ]

-- | Length-prefixed blob (@u32BE@ length + bytes).
u32prefixed :: ByteString -> ByteString
u32prefixed bs = u32be (fromIntegral (BS.length bs)) <> bs

-- | Take a big-endian 32-bit frame.
takeU32 :: ByteString -> Maybe (Word64, ByteString)
takeU32 bs
  | BS.length bs < 4 = Nothing
  | otherwise =
      let (b, rest) = BS.splitAt 4 bs
      in Just (foldBE b, rest)

-- | Take a big-endian 64-bit frame.
takeU64 :: ByteString -> Maybe (Word64, ByteString)
takeU64 bs
  | BS.length bs < 8 = Nothing
  | otherwise =
      let (b, rest) = BS.splitAt 8 bs
      in Just (foldBE b, rest)

-- | Take a length-prefixed blob (exact bytes, no overrun).
takePrefixed :: ByteString -> Maybe (ByteString, ByteString)
takePrefixed bs = do
  (n, rest) <- takeU32 bs
  if fromIntegral n > BS.length rest
    then Nothing
    else Just (BS.splitAt (fromIntegral n) rest)

-- | Big-endian fold.
foldBE :: ByteString -> Word64
foldBE = BS.foldl' (\acc b -> acc * 256 + fromIntegral b) 0

-- | Build a recipe from live planned work, or 'Nothing' when the
-- work shape has no async recipe (not every 'CryptoEffect' is an
-- async function of this facility).
recipeFromWork :: JobFunction -> AsyncWork -> Int -> Word64 -> Maybe Recipe
recipeFromWork func work ticks cap = case work of
  WorkCall w -> case callWorkEffect w of
    EffectCrypto fx -> case fx of
      FxDigest {} -> Just RecipeCall
        { rcFunc = func, rcTicks = ticks, rcCapacity = cap, rcEffect = fx }
      FxSign {} -> Just RecipeCall
        { rcFunc = func, rcTicks = ticks, rcCapacity = cap, rcEffect = fx }
      _ -> Nothing
  WorkKey _ pw fx -> case (pw, fx) of
    (PwGenerateKey k, FxGenerateKey {}) -> Just RecipeGenKey
      { rkTicks = ticks
      , rkCapacity = cap
      , rkEffect = fx
      , rkTemplate = stripDerived (poAttrs k)
      , rkSessionOwned = ownedOf k
      }
    (PwGeneratePair pub priv, FxGenerateKey {}) -> Just RecipeGenKeyPair
      { rkpTicks = ticks
      , rkpCapacity = cap
      , rkpEffect = fx
      , rkpPub = stripDerived (poAttrs pub)
      , rkpPriv = stripDerived (poAttrs priv)
      , rkpPubOwned = ownedOf pub
      , rkpPrivOwned = ownedOf priv
      }
    _ -> Nothing
  where
    ownedOf :: PendingObject -> Bool
    ownedOf k = case poOwner k of
      Nothing -> False
      Just _ -> True
    -- | Derived rows never persist in a recipe: rejoin replays the
    -- template through the planner, which re-derives them
    -- deterministically (replaying stamped rows would refuse, as
    -- caller templates may not carry history).
    stripDerived :: Map.Map AttributeType AttributeValue -> Map.Map AttributeType AttributeValue
    stripDerived = flip (foldr Map.delete) historyAttrs
