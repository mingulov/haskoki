{- | Driver byte-op derive dispatch and execution.
-}
{-# LANGUAGE OverloadedStrings #-}
module Haskoki.Engine.Driver.ByteOps
  ( ByteOpsExec (..)
  , byteOpsParamsFor
  , isByteOpsMech
  , byteOpsNeedsAux
  , runByteOps
  ) where
import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import Control.Monad (guard)
import Data.Bits ((.|.), shiftL, testBit)
import Data.Word (Word64)

import Haskoki.Engine.Backend (KeyMaterial (..))
import Haskoki.Engine.Driver.Common (xorB)
import Haskoki.Operation.Effect (CryptoError (..), CryptoResult (..))
import Haskoki.Recipe.ByteOps
  ( ByteOpsKind (..)
  , ByteOpsRecipe (..)
  , byteOpsParamsValid
  , byteOpsRecipeFor
  , decodeByteOpsParams
  )
import Haskoki.Registry (MechanismId (..))


-- | One decoded byte-op execution: the row kind, the second
-- handle (BASE_AND_KEY), the bit offset (EXTRACT), and the
-- string data (the three data rows).
data ByteOpsExec = ByteOpsExec
  { boeKind :: !ByteOpsKind
  , boeAux :: !Word64
  , boeOff :: !Word64
  , boeData :: !ByteString
  } deriving (Eq, Show)

-- | Byte-op dispatch: the covered (mechanism, params) pair to
-- its execution tuple (pinned by RecipeByteOpsSpec).
byteOpsParamsFor :: MechanismId -> ByteString -> Maybe ByteOpsExec
byteOpsParamsFor mech params = do
  r <- byteOpsRecipeFor mech
  guard (byteOpsParamsValid r params)
  (aux, off, blob) <- decodeByteOpsParams params
  pure (ByteOpsExec (boKind r) aux off blob)

-- | A byte-op mechanism (drives the parameter-refusal
-- branches).
isByteOpsMech :: MechanismId -> Bool
isByteOpsMech mech = case byteOpsRecipeFor mech of
  Just _ -> True
  Nothing -> False

-- | The byte-op rows needing an aux key: only
-- BASE_AND_KEY takes the second input (the planner
-- resolves it onto 'fxKey2').
byteOpsNeedsAux :: ByteOpsExec -> Bool
byteOpsNeedsAux ex = boeKind ex == ConcatBaseAndKey

-- | Byte-op derives: pure byte manipulation over secret
-- material (no backend crypto — identical on both
-- backends). Concat rows join base and second input and
-- truncate to the planned length; XOR folds the first
-- planned-length bytes of both inputs (at most the shorter
-- one; the planner refuses a longer length first); EXTRACT
-- slices whole bytes at the bit offset, bit-exact
-- (MSB-first) for sub-byte offsets. Off-range lengths are 'CryptoFailed';
-- non-bytes keys are 'CryptoBadKey'.
runByteOps :: ByteOpsExec -> KeyMaterial -> Maybe KeyMaterial -> Int -> IO CryptoResult
runByteOps ex key mAux outLen = case key of
  KeyBytes kb -> case auxOf mAux of
    Left err -> pure (GotCryptoError err)
    Right auxB -> case boeKind ex of
      ConcatBaseAndKey -> case auxB of
        -- Unreachable post-dispatch (concat-key needs
        -- aux); typed, never a crash.
        Nothing -> pure (GotCryptoError (CryptoBadKey "driver"
          "concat-key derive binds no second key"))
        Just sb
          | outLen >= 1, outLen <= BS.length kb + BS.length sb ->
              pure (GotBytes (BS.take outLen (kb <> sb)))
          | otherwise -> pure (GotCryptoError (CryptoFailed
              "driver: concat-key length out of range"))
      ConcatBaseAndData
        | outLen >= 1, outLen <= BS.length kb + BS.length dat ->
            pure (GotBytes (BS.take outLen (kb <> dat)))
        | otherwise -> pure (GotCryptoError (CryptoFailed
            "driver: concat-data length out of range"))
      ConcatDataAndBase
        | outLen >= 1, outLen <= BS.length dat + BS.length kb ->
            pure (GotBytes (BS.take outLen (dat <> kb)))
        | otherwise -> pure (GotCryptoError (CryptoFailed
            "driver: data-concat length out of range"))
      XorBaseAndData
        | outLen >= 1
        , outLen <= min (BS.length kb) (BS.length dat) ->
            pure (GotBytes (BS.take outLen (kb `xorB` dat)))
        | otherwise -> pure (GotCryptoError (CryptoFailed
            "driver: XOR length out of range"))
      ExtractKeyFromKey
        | outLen >= 1
        , toInteger off + toInteger outLen * 8 <= toInteger (BS.length kb) * 8 ->
            pure (GotBytes (extractBits kb (fromIntegral off) outLen))
        | otherwise -> pure (GotCryptoError (CryptoFailed
            "driver: EXTRACT window out of range"))
  _ -> pure (GotCryptoError (CryptoBadKey "driver"
    "key derivation needs raw secret bytes"))
  where
    dat = boeData ex
    off = boeOff ex
    auxOf Nothing
      | byteOpsNeedsAux ex = Left (CryptoBadKey "driver" "byte-op derive binds no aux key")
      | otherwise = Right Nothing
    auxOf (Just (KeyBytes ab)) = Right (Just ab)
    auxOf (Just _) = Left (CryptoBadKey "driver" "byte-op aux key is not byte material")

-- | Bit-exact slice (MSB-first): @n@ whole bytes starting
-- at bit @off@ of the input (the caller keeps the window
-- in range).
extractBits :: ByteString -> Int -> Int -> ByteString
extractBits bs off n = BS.pack [byteAt i | i <- [0 .. n - 1]]
  where
    byteAt i = foldl setBit 0 [0 .. 7]
      where
        setBit acc j
          | bitAt (off + i * 8 + j) = acc .|. (1 `shiftL` (7 - j))
          | otherwise = acc
    bitAt p = testBit (BS.index bs (p `div` 8)) (7 - (p `mod` 8))
