{- | Cipher operation lifecycle (pure).

Multipart sequencing over one encrypt or decrypt slot: updates
stream every block the padding rules release through one
'FxCipher' effect and retain the suffix (framed block ciphers
only; AEAD and asymmetric updates still buffer); the final plans
a single 'FxCipher' effect over the retained bytes, chained from
the running IV. A short update buffer refuses
'CKR_BUFFER_TOO_SMALL' with no state change. Padding is decided
in the pure layer with real PKCS#7 framing: an encrypt final pads
before the effect input is fixed, a decrypt final strips after
the driver answers. Every plan-time deny (ragged one-shot/final,
one-shot over buffered or streamed input) terminates the slot —
spec: every error other than BUFFER_TOO_SMALL terminates — as do
a corrupt pad and a ragged driver answer at finish time.
-}
module Haskoki.Operation.Cipher
  ( planCipherUpdate
  , planCipherOneShot
  , planCipherFinal
  , finishCipher
  , finishCipherUpdate
  , cipherUpdateSplit
  , pkcs7Pad
  , pkcs7Unpad
  ) where

import Control.Monad (guard)
import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import Data.Maybe (fromMaybe)

import Haskoki.Model (SessionState)
import Haskoki.Operation
  ( CipherDir (..)
  , CipherSpec (..)
  , CryptoEffect (..)
  , CryptoResult (..)
  , DataGate (..)
  , SessionOps
  , SlotCommon
  , SlotKind (..)
  , StepDeny (..)
  , StepOutcome (..)
  , appendBuffered
  , TypedError (..)
  , interpretError
  , denyOutcome
  , isAesStreamMech
  , isCtsMech
  , isOfbMech
  , isUnframedCipher
  , mkDeny
  , gateDataCall
  , insertOp
  , lookupSingle
  , maxBuffered
  , removeSingle
  , setStaged
  , setChainIv
  , stageBytes
  , stagedOf
  , chainIvOf
  , hasStreamed
  , activeCipher
  , bufferedOf
  , commonKey
  , commonMech
  , commonParams
  , mkActiveCipher
  , setBuffered
  )
import Haskoki.Output (OutputPlan (..), planOneShot)
import Haskoki.Registry (MechanismId)
import Haskoki.Request (OutputIntent (..))
import Haskoki.Recipe.Cipher (BlockCipherRecipe (..), cipherRecipeFor, ctrNextImage, ctrRecipeFor)
import Haskoki.Types (Consumption (..), OpState (..))
import Haskoki.Types (ReturnCode (..))

-- ---------------------------------------------------------------------------
-- PKCS#7 framing
-- ---------------------------------------------------------------------------

-- | Pad to a multiple of the block width, always adding at least one
-- byte. 'Nothing' for block widths outside the PKCS#7 byte range.
pkcs7Pad :: Int -> ByteString -> Maybe ByteString
pkcs7Pad block bs
  | block < 1 || block > 255 = Nothing
  | otherwise = Just (bs <> BS.replicate n (fromIntegral n))
  where
    n = block - (BS.length bs `mod` block)

-- | Strip PKCS#7 padding, checking the framing strictly: non-empty
-- block-aligned input, a pad length in @1..block@, and every pad byte
-- equal to the length. Anything else is 'Nothing'.
pkcs7Unpad :: Int -> ByteString -> Maybe ByteString
pkcs7Unpad block bs = do
  guard (block >= 1 && block <= 255)
  let len = BS.length bs
  guard (len > 0 && len `mod` block == 0)
  let padByte = BS.index bs (len - 1)
      n = fromIntegral padByte
  guard (n >= 1 && n <= min block len)
  let (plain, pad) = BS.splitAt (len - n) bs
  guard (BS.all (== padByte) pad)
  pure plain

-- ---------------------------------------------------------------------------
-- Slot validation
-- ---------------------------------------------------------------------------

-- | Resolve a cipher slot: the kind must be a cipher kind, the slot
-- must hold a cipher operation, and the direction must match.
withCipherSlot
  :: SessionOps -> SlotKind -> Either StepDeny (CipherDir, SlotCommon, CipherSpec)
withCipherSlot ops kind = do
  dir <- case kind of
    SlotEncrypt -> Right DirEncrypt
    SlotDecrypt -> Right DirDecrypt
    _ -> Left (mkDeny CKR_ARGUMENTS_BAD "not a cipher slot")
  active <- case lookupSingle ops kind of
    Nothing -> Left (mkDeny CKR_OPERATION_NOT_INITIALIZED
      "no cipher operation is active in this slot")
    Just a -> Right a
  case activeCipher active of
    Just (dir', sc, spec)
      | dir' == dir -> Right (dir, sc, spec)
      | otherwise -> Left (mkDeny CKR_GENERAL_ERROR
          "cipher slot holds the wrong direction")
    Nothing -> Left (mkDeny CKR_GENERAL_ERROR
      "cipher slot holds a foreign operation")

-- | The effect input for an encrypt step: padded bytes, or the raw
-- buffer when unpadded (which must already be block-aligned; the
-- denial keeps the slot so later updates can repair it).
-- Asymmetric rows ('isUnframedCipher') skip framing entirely: the
-- backend owns their length bound. CTS rows ('isCtsMech') replace
-- alignment with the stealing floor: >= 1 block, any length above.
-- AES stream rows ('isAesStreamMech') accept any length outright
-- (length-preserving, empty included).
encryptInput :: MechanismId -> CipherSpec -> ByteString -> Either StepDeny ByteString
encryptInput mech spec buf
  | isUnframedCipher mech = Right buf
  | isAesStreamMech mech = Right buf
  | isCtsMech mech
  , BS.length buf >= csBlock spec = Right buf
  | isCtsMech mech = Left (mkDeny CKR_DATA_LEN_RANGE
      "cts encrypt needs at least one block of input")
  | csPad spec = case pkcs7Pad (csBlock spec) buf of
      Just padded -> Right padded
      Nothing -> Left (mkDeny CKR_GENERAL_ERROR
        "cipher shape escapes the PKCS#7 range")
  | BS.length buf `mod` csBlock spec == 0 = Right buf
  | otherwise = Left (mkDeny CKR_DATA_LEN_RANGE
      "unpadded encrypt needs block-aligned input")

-- ---------------------------------------------------------------------------
-- Planners
-- ---------------------------------------------------------------------------

-- | Plan one cipher update: buffer the part. No crypto is planned.
-- | Split one update's total input (already-buffered plus the new
-- part) into the streamable prefix and the retained suffix, in
-- bytes. Unframed ciphers (AEAD, asymmetric) never stream: AEAD
-- decryption must not release plaintext before the tag verifies,
-- and asymmetric multipart is degenerate. CTS never streams
-- either: the steal pair intertwines the last two blocks, so only
-- the final (which sees the whole buffer) runs the effect. OFB
-- never streams either: its register evolves through the block
-- cipher, underivable from the answer tail.
-- Framed block ciphers
-- stream every block the padding rules release: unpadded modes
-- emit all full blocks both directions; padded encrypt holds back
-- the trailing partial block (or one full block when aligned, the
-- pad companion being undecided); padded decrypt always holds the
-- last block (it carries the pad). The streaming width is the
-- recipe block width (never the unit stream shape: CTR updates
-- stream whole counter blocks and retain the partial tail, since
-- a counter-block chain cannot name a mid-block offset; the tail
-- flushes at final). Exported for the FFI short-buffer length
-- dialogue, which re-derives the same split.
cipherUpdateSplit
  :: MechanismId -> CipherSpec -> CipherDir -> Int -> (Int, Int)
cipherUpdateSplit mech spec dir total
  | csBlock spec <= 0 = (0, total)
  | isUnframedCipher mech = (0, total)
  | isCtsMech mech = (0, total)
  | isOfbMech mech = (0, total)
  | isEcb = (total - total `mod` block, total `mod` block)
  | csPad spec = case dir of
      DirEncrypt
        | total < block -> (0, total)
        | r == 0 -> (total - block, block)
        | otherwise -> (total - r, r)
      DirDecrypt
        | total < 2 * block -> (0, total)
        | otherwise -> (total - hold, hold)
  | otherwise = (total - total `mod` block, total `mod` block)
  where
    block = streamBlock mech spec
    r = total `mod` block
    hold = block + (total - block) `mod` block
    isEcb = maybe False ((== 0) . crIvBytes) (cipherRecipeFor mech)

-- | Multipart streaming width: the recipe block width for cipher
-- rows (identical to the operation shape for CBC/ECB; 16 for the
-- CTR stream whose shape is unit), else the operation shape.
streamBlock :: MechanismId -> CipherSpec -> Int
streamBlock mech spec =
  fromMaybe (csBlock spec) (crBlockBytes <$> cipherRecipeFor mech)

-- | The chaining IV for a cipher effect: the running value once the
-- slot has streamed, else the init IV from the parameters.
effectParamsFor :: SlotCommon -> ByteString
effectParamsFor sc = fromMaybe (commonParams sc) (chainIvOf sc)

-- | Plan a cipher update: stream the releasable prefix through one
-- effect, retain the suffix. A short output buffer refuses
-- 'CKR_BUFFER_TOO_SMALL' with NO state change (no gate spend, no
-- append): the caller repeats the same part with room. Empty
-- streamable input buffers exactly as before (zero bytes out).
planCipherUpdate
  :: SessionOps -> SessionState -> SlotKind -> ByteString
  -> Maybe OutputIntent
  -> (SessionOps, SessionState, StepOutcome)
planCipherUpdate ops st kind part mIntent = case withCipherSlot ops kind of
  Left d -> (ops, st, denyOutcome d)
  Right (dir, sc, spec) -> case stagedOf sc of
    Just _ -> (ops, st, denyOutcome (mkDeny CKR_OPERATION_NOT_INITIALIZED
      "cipher operation is finalized; retry the staged output instead"))
    Nothing ->
      let full = bufferedOf sc <> part
          (streamable, _) =
            cipherUpdateSplit (commonMech sc) spec dir (BS.length full)
          cap = case mIntent of
            Just (IntentBuffer n)
              | n > fromIntegral (maxBound :: Int) -> maxBound
              | otherwise -> fromIntegral n
            _ -> maxBound
          block = csBlock spec
          isEcbMech =
            maybe False ((== 0) . crIvBytes) (cipherRecipeFor (commonMech sc))
          lastBlock bs = BS.drop (max 0 (BS.length bs - block)) bs
      in if BS.length full > maxBuffered
        then (removeSingle kind ops, st, denyOutcome (mkDeny CKR_ARGUMENTS_BAD
          "multipart input exceeds the buffer bound"))
        else if streamable > cap
          then (ops, st, denyOutcome (mkDeny CKR_BUFFER_TOO_SMALL
            ("update output needs " ++ show streamable ++ " bytes")))
          else case gateDataCall st sc of
            GateDeny d term ->
              (if term then removeSingle kind ops else ops, st, denyOutcome d)
            GateOk st' sc'
              | streamable == 0 -> case appendBuffered sc' part of
                  Left d -> (removeSingle kind ops, st', denyOutcome d)
                  Right sc'' ->
                    ( insertOp (mkActiveCipher dir sc'' spec) ops
                    , st'
                    , StepOutcome CKR_OK [] Nothing
                        ["buffered " ++ show (BS.length part)
                          ++ " bytes (" ++ show (BS.length (bufferedOf sc''))
                          ++ " total)"] [] Nothing
                    )
              | otherwise ->
                  let (streamBytes, retainBytes) = BS.splitAt streamable full
                      scRetain = setBuffered retainBytes sc'
                      -- CTR chains the counter forward by whole
                      -- blocks consumed (never the ciphertext tail:
                      -- the chain stays a parameter image). A
                      -- corrupt chain falls through to the CBC arm,
                      -- whose non-image the recipe refuses on the
                      -- next effect (fail closed; unreachable: init
                      -- and every advance keep images valid).
                      isCtr = case ctrRecipeFor (commonMech sc) of
                        Just _ -> True
                        Nothing -> False
                      ctrChain = ctrNextImage (effectParamsFor sc)
                        (BS.length streamBytes `div` 16)
                      scAdv = case dir of
                        DirDecrypt
                          | isEcbMech -> setChainIv (Just BS.empty) scRetain
                          | isCtr, Just img <- ctrChain ->
                              setChainIv (Just img) scRetain
                          | otherwise -> setChainIv (Just (lastBlock streamBytes)) scRetain
                        DirEncrypt
                          | isEcbMech -> setChainIv (Just BS.empty) scRetain
                          | otherwise -> scRetain
                  in ( insertOp (mkActiveCipher dir scAdv spec) ops
                     , st'
                     , StepOutcome CKR_OK
                         [FxCipher dir (commonMech sc) (commonKey sc)
                           (effectParamsFor sc) streamBytes]
                         Nothing
                         ["cipher update streams " ++ show streamable
                           ++ " bytes (" ++ show (BS.length retainBytes)
                           ++ " retained)"] [] Nothing
                     )

-- | Plan a cipher one-shot over the full input. Allowed only before
-- any update. One-shot denies terminate the slot (spec: every error
-- other than BUFFER_TOO_SMALL terminates); a re-init, not a final,
-- follows a denied one-shot.
planCipherOneShot
  :: SessionOps -> SessionState -> SlotKind -> String -> ByteString
  -> (SessionOps, SessionState, StepOutcome)
planCipherOneShot ops st kind _name input = case withCipherSlot ops kind of
  Left d -> (ops, st, denyOutcome d)
  Right (dir, sc, spec) -> case stagedOf sc of
    Just _ -> (ops, st, denyOutcome (mkDeny CKR_OPERATION_NOT_INITIALIZED
      "cipher operation is finalized; retry the staged output instead"))
    Nothing
      | not (BS.null (bufferedOf sc)) || hasStreamed sc ->
          (removeSingle kind ops, st, denyOutcome (mkDeny CKR_OPERATION_ACTIVE
            "multipart input already buffered or streamed; re-init to continue"))
      | otherwise -> case gateDataCall st sc of
          GateDeny d term ->
            (if term then removeSingle kind ops else ops, st, denyOutcome d)
          GateOk st' sc' -> case dir of
            DirEncrypt -> case encryptInput (commonMech sc') spec input of
              Left d -> (removeSingle kind ops, st', denyOutcome d)
              Right padded -> runOneShot ops st' kind dir sc' spec input padded
            DirDecrypt -> runOneShot ops st' kind dir sc' spec input input
  where
    runOneShot o s k d sc' spec raw effectInput =
      case appendBuffered sc' raw of
        Left deny -> (removeSingle k o, s, denyOutcome deny)
        Right sc'' ->
          ( insertOp (mkActiveCipher d sc'' spec) o
          , s
          , StepOutcome CKR_OK
              [FxCipher d (commonMech sc'') (commonKey sc'') (commonParams sc'') effectInput]
              Nothing
              ["cipher one-shot planned over " ++ show (BS.length raw) ++ " bytes"] [] Nothing
          )

-- | Plan a cipher final: one effect over the buffered input (padded
-- first for encrypt). The buffer is retained until the finisher runs.
planCipherFinal
  :: SessionOps -> SessionState -> SlotKind -> String
  -> (SessionOps, SessionState, StepOutcome)
planCipherFinal ops st kind _name = case withCipherSlot ops kind of
  Left d -> (ops, st, denyOutcome d)
  Right (dir, sc, spec) -> case stagedOf sc of
    Just _ -> (ops, st, denyOutcome (mkDeny CKR_OPERATION_NOT_INITIALIZED
      "cipher operation is finalized; retry the staged output instead"))
    Nothing -> case gateDataCall st sc of
      GateDeny d term ->
        (if term then removeSingle kind ops else ops, st, denyOutcome d)
      GateOk st' sc' -> case dir of
        DirEncrypt -> case encryptInput (commonMech sc') spec (bufferedOf sc') of
          Left d -> (removeSingle kind ops, st', denyOutcome d)
          Right padded ->
            ( insertOp (mkActiveCipher dir sc' spec) ops
            , st'
            , StepOutcome CKR_OK
                [FxCipher dir (commonMech sc') (commonKey sc') (effectParamsFor sc') padded]
                Nothing
                ["cipher final planned over "
                  ++ show (BS.length (bufferedOf sc')) ++ " bytes"] [] Nothing
            )
        DirDecrypt ->
          ( insertOp (mkActiveCipher dir sc' spec) ops
          , st'
          , StepOutcome CKR_OK
              [FxCipher dir (commonMech sc') (commonKey sc') (effectParamsFor sc') (bufferedOf sc')]
              Nothing
              ["cipher final planned over "
                ++ show (BS.length (bufferedOf sc')) ++ " bytes"] [] Nothing
          )

-- | Finish a planned cipher final or one-shot. Encrypt stages the
-- driver bytes; decrypt strips padding (padded) or checks alignment
-- (unpadded). Corrupt pads, ragged answers, verdict-shaped results,
-- and crypto failures all terminate the slot.
finishCipher
  :: SessionOps -> SlotKind -> String -> CryptoResult -> OutputIntent
  -> (SessionOps, StepOutcome)
finishCipher ops kind name result intent = case withCipherSlot ops kind of
  Left d -> (ops, denyOutcome d)
  Right (dir, sc, spec) -> case stagedOf sc of
    Just _ -> (ops, denyOutcome (mkDeny CKR_GENERAL_ERROR
      "cipher output already staged; use retry"))
    Nothing ->
      let stageRaw bytes =
            let (staged, plan, freed) = stageBytes name bytes intent
            in if freed
              then (removeSingle kind ops
                   , StepOutcome CKR_OK [] (Just plan) ["cipher step complete"] [] Nothing)
              else ( insertOp
                       (mkActiveCipher dir (setStaged staged sc) spec) ops
                   , StepOutcome CKR_BUFFER_TOO_SMALL [] (Just plan)
                       ["cipher output staged; retry with the reported length"] [] Nothing)
      in case result of
        GotBytes raw -> case dir of
          DirEncrypt -> stageRaw raw
          DirDecrypt
            | isUnframedCipher (commonMech sc) -> stageRaw raw
            | isAesStreamMech (commonMech sc) -> stageRaw raw
            | isCtsMech (commonMech sc)
            , BS.length raw >= csBlock spec -> stageRaw raw
            | isCtsMech (commonMech sc) ->
                ( removeSingle kind ops
                , denyOutcome (mkDeny CKR_ENCRYPTED_DATA_LEN_RANGE
                    "cts decrypt answer is shorter than one block")
                )
            | csPad spec -> case pkcs7Unpad (csBlock spec) raw of
                Just plain -> stageRaw plain
                Nothing ->
                  ( removeSingle kind ops
                  , denyOutcome (mkDeny CKR_ENCRYPTED_DATA_INVALID
                      "decrypt padding check failed")
                  )
            | BS.length raw `mod` csBlock spec == 0 -> stageRaw raw
            | otherwise ->
                ( removeSingle kind ops
                , denyOutcome (mkDeny CKR_ENCRYPTED_DATA_LEN_RANGE
                    "unpadded decrypt answer is not block-aligned")
                )
        GotValid _ ->
          ( removeSingle kind ops
          , denyOutcome (mkDeny CKR_GENERAL_ERROR
              "driver answered a cipher step with a verdict"))
        GotResource _ ->
          ( removeSingle kind ops
          , denyOutcome (mkDeny CKR_GENERAL_ERROR
              "driver answered a cipher step with a resource"))
        -- Unreachable via 'toCrypto' (which never produces
        -- 'GotUnit'); loud failure if the driver protocol is ever
        -- violated.
        GotUnit ->
          ( removeSingle kind ops
          , denyOutcome (mkDeny CKR_GENERAL_ERROR
              "driver answered a cipher step with a feed unit"))
        GotCryptoError err ->
          ( removeSingle kind ops
          , denyOutcome (mkDeny (interpretError (TyCrypto err))
              ("cipher crypto failed: " ++ show err)))

-- | Finish a planned cipher update: write the streamed chunk through
-- the output intent and advance the encrypt chaining value from
-- the answer (CBC: the ciphertext tail; CTR: the counter image
-- advanced by whole answer blocks; decrypt chaining and the ECB
-- marker advance at plan time, when their inputs are known). The
-- slot stays open with the retained suffix. Anything unexpected —
-- a verdict, a resource, a short answer, an over-cap answer, a
-- null intent (queries never execute) — terminates the slot
-- instead of releasing bytes.
finishCipherUpdate
  :: SessionOps -> SlotKind -> String -> CryptoResult -> OutputIntent
  -> (SessionOps, StepOutcome)
finishCipherUpdate ops kind name result intent = case withCipherSlot ops kind of
  Left d -> (ops, denyOutcome d)
  Right (dir, sc, spec) -> case stagedOf sc of
    Just _ -> (ops, denyOutcome (mkDeny CKR_GENERAL_ERROR
      "cipher output already staged; use retry"))
    Nothing ->
      let block = csBlock spec
          isEcbMech =
            maybe False ((== 0) . crIvBytes) (cipherRecipeFor (commonMech sc))
          isCtr = case ctrRecipeFor (commonMech sc) of
            Just _ -> True
            Nothing -> False
          advance = case dir of
            DirDecrypt -> const (Right sc)
            DirEncrypt
              | isEcbMech -> const (Right sc)
              | otherwise -> advanceEncrypt
          -- CTR advances the counter image by whole answer
          -- blocks (updates always stream multiples of 16; a
          -- ragged answer is a driver violation and fails
          -- closed). CBC keeps the ciphertext-tail chaining.
          advanceEncrypt raw
            | isCtr, BS.length raw `mod` 16 == 0
            , Just img <- ctrNextImage (effectParamsFor sc)
                (BS.length raw `div` 16) =
                Right (setChainIv (Just img) sc)
            | isCtr =
                Left "cipher update answer is not a whole CTR block run"
            | BS.length raw < block || block <= 0 =
                Left "cipher update answer shorter than one block"
            | otherwise = Right (setChainIv
                (Just (BS.drop (BS.length raw - block) raw)) sc)
      in case result of
        GotBytes raw -> case advance raw of
          Left why ->
            (removeSingle kind ops, denyOutcome (mkDeny CKR_GENERAL_ERROR why))
          Right scAdv ->
            let (_, plan) = planOneShot (OpLive (Consumption 0)) name raw intent
            in case opCode plan of
              CKR_OK ->
                ( insertOp (mkActiveCipher dir scAdv spec) ops
                , StepOutcome CKR_OK [] (Just plan)
                    ["cipher update streamed " ++ show (BS.length raw)
                      ++ " bytes"] [] Nothing
                )
              _ -> (removeSingle kind ops, denyOutcome (mkDeny CKR_GENERAL_ERROR
                "cipher update answer exceeds the checked output cap"))
        GotCryptoError err ->
          ( removeSingle kind ops
          , denyOutcome (mkDeny (interpretError (TyCrypto err))
              ("cipher update crypto failed: " ++ show err)))
        _ ->
          ( removeSingle kind ops
          , denyOutcome (mkDeny CKR_GENERAL_ERROR
              "driver answered a cipher update with a non-bytes result"))
