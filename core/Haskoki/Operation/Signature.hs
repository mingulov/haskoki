{- | Signature operation lifecycle (pure).

Sign and verify over their own slots: updates buffer purely, finals
and one-shots plan a single effect each. Verify answers carry no
output bytes, so verdicts finish through a hand-rolled terminating
plan instead of the byte stager; anything else stages through the
output planner with the usual short-buffer/failure dispositions.

Recovery flows are one-shot-only over @data \|\| tag@ model blocks:
sign-recover assembles the block from the buffered input plus the
driver tag (the block must fit the init-fixed capacity), and
verify-recover splits a driver-recovered payload out of the block.
Update, final, or plain one-shot calls on a recovery slot are
rejected, as are recovery calls on a plain slot.
-}
module Haskoki.Operation.Signature
  ( planSignUpdate
  , planSignOneShot
  , planSignFinal
  , finishSign
  , planVerifyUpdate
  , planVerifyOneShot
  , planVerifyFinal
  , finishVerify
  , planSignRecoverOneShot
  , finishSignRecover
  , planVerifyRecoverOneShot
  , finishVerifyRecover
  ) where

import qualified Data.ByteString as BS
import Data.ByteString (ByteString)

import Haskoki.Model (SessionState)
import Haskoki.Operation
  ( ActiveOp
  , CryptoEffect (..)
  , CryptoResult (..)
  , DataGate (..)
  , RecoverRole (..)
  , RecoverSpec (..)
  , SessionOps
  , SlotCommon
  , SlotKind (..)
  , StepDeny (..)
  , StepOutcome (..)
  , appendBuffered
  , TypedError (..)
  , interpretError
  , denyOutcome
  , mkDeny
  , gateDataCall
  , insertOp
  , lookupSingle
  , removeSingle
  , setStaged
  , stageBytes
  , stagedOf
  , activeRecover
  , activeSign
  , activeVerify
  , bufferedOf
  , commonKey
  , commonMech
  , commonParams
  , mkActiveRecover
  , mkActiveSign
  , mkActiveVerify
  )
import Haskoki.Output
  ( OpDisposition (..)
  , OutputPlan (..)
  , ResultDisposition (..)
  )
import Haskoki.Recipe.Dsa (dsaRawFloorFor)
import Haskoki.Request (OutputIntent)
import Haskoki.Types (ReturnCode (..))

-- ---------------------------------------------------------------------------
-- Shared verdict plans and slot checks
-- ---------------------------------------------------------------------------

-- | A terminating plan with no output bytes, for verification
-- verdicts: the code plus a single terminating disposition.
verdictPlan :: String -> ReturnCode -> String -> OutputPlan
verdictPlan name code why = OutputPlan
  { opCode = code
  , opWrites = []
  , opLengths = []
  , opDispositions = [ResultDisposition [name] code OpTerminate]
  , opReasons = [why]
  }

-- | Raw-DSA digest-floor denial: the raw row signs a
-- caller-supplied digest of at least 'dsaRawFloorFor' bytes;
-- shorter input refuses @CKR_DATA_LEN_RANGE@ (the callers
-- terminate the slot). Hash-and-sign rows and non-DSA mechanisms
-- pass ('Nothing').
rawFloorDeny :: SlotCommon -> Int -> Maybe StepDeny
rawFloorDeny sc len = case dsaRawFloorFor (commonMech sc) of
  Just fl
    | len < fl -> Just (mkDeny CKR_DATA_LEN_RANGE
        ("raw DSA digest is shorter than " ++ show fl ++ " bytes"))
  _ -> Nothing

-- | The active plain (non-recovery) operation in a sign/verify slot.
withPlainSlot :: SessionOps -> SlotKind -> Either StepDeny SlotCommon
withPlainSlot ops kind = case lookupSingle ops kind of
  Nothing -> Left (mkDeny CKR_OPERATION_NOT_INITIALIZED
    "no signature operation is active in this slot")
  Just active -> case kind of
    SlotSign -> case activeSign active of
      Just sc -> Right sc
      Nothing -> case activeRecover active of
        Just _ -> Left (mkDeny
          CKR_OPERATION_NOT_INITIALIZED "recovery operation takes no multipart calls")
        Nothing -> Left (mkDeny CKR_GENERAL_ERROR
          "signature slot holds a foreign operation")
    SlotVerify -> case activeVerify active of
      Just sc -> Right sc
      Nothing -> case activeRecover active of
        Just _ -> Left (mkDeny
          CKR_OPERATION_NOT_INITIALIZED "recovery operation takes no multipart calls")
        Nothing -> Left (mkDeny CKR_GENERAL_ERROR
          "signature slot holds a foreign operation")
    _ -> Left (mkDeny CKR_GENERAL_ERROR
      "signature slot holds a foreign operation")

-- | The active recovery operation in a sign/verify slot with the
-- expected role.
withRecoverSlot
  :: SessionOps -> SlotKind -> RecoverRole
  -> Either StepDeny (SlotCommon, RecoverSpec)
withRecoverSlot ops kind role = case lookupSingle ops kind of
  Nothing -> Left (mkDeny CKR_OPERATION_NOT_INITIALIZED
    "no recovery operation is active in this slot")
  Just active -> case activeRecover active of
    Just (role', sc, spec)
      | role' == role -> Right (sc, spec)
      | otherwise -> Left (mkDeny CKR_OPERATION_NOT_INITIALIZED
          "recovery role mismatch")
    Nothing -> Left (mkDeny CKR_OPERATION_NOT_INITIALIZED
      "not a recovery operation")

-- ---------------------------------------------------------------------------
-- Sign
-- ---------------------------------------------------------------------------

-- | Plan one sign update: buffer the part. No crypto is planned.
planSignUpdate
  :: SessionOps -> SessionState -> ByteString
  -> (SessionOps, SessionState, StepOutcome)
planSignUpdate ops st part = case withPlainSlot ops SlotSign of
  Left d -> (ops, st, denyOutcome d)
  Right sc -> runBuffer ops st SlotSign mkActiveSign sc part

-- | Buffer one multipart part for a plain sign/verify slot.
runBuffer
  :: SessionOps -> SessionState -> SlotKind
  -> (SlotCommon -> ActiveOp) -> SlotCommon -> ByteString
  -> (SessionOps, SessionState, StepOutcome)
runBuffer ops st kind wrap sc part = case stagedOf sc of
  Just _ -> (ops, st, denyOutcome (mkDeny CKR_OPERATION_NOT_INITIALIZED
    "operation is finalized; retry the staged output instead"))
  Nothing -> case gateDataCall st sc of
    GateDeny d term ->
      (if term then removeSingle kind ops else ops, st, denyOutcome d)
    GateOk st' sc' -> case appendBuffered sc' part of
      Left d -> (removeSingle kind ops, st', denyOutcome d)
      Right sc'' ->
        ( insertOp (wrap sc'') ops
        , st'
        , StepOutcome CKR_OK [] Nothing
            ["buffered " ++ show (BS.length part)
              ++ " bytes (" ++ show (BS.length (bufferedOf sc''))
              ++ " total)"] [] Nothing
        )

-- | Plan a sign one-shot. Allowed only before any update.
planSignOneShot
  :: SessionOps -> SessionState -> String -> ByteString
  -> (SessionOps, SessionState, StepOutcome)
planSignOneShot ops st _name input = case withPlainSlot ops SlotSign of
  Left d -> (ops, st, denyOutcome d)
  Right sc -> case stagedOf sc of
    Just _ -> (ops, st, denyOutcome (mkDeny CKR_OPERATION_NOT_INITIALIZED
      "operation is finalized; retry the staged output instead"))
    Nothing
      | not (BS.null (bufferedOf sc)) ->
          (removeSingle SlotSign ops, st, denyOutcome (mkDeny CKR_OPERATION_ACTIVE
            "multipart input already buffered; re-init to continue"))
      | otherwise -> case gateDataCall st sc of
          GateDeny d term ->
            (if term then removeSingle SlotSign ops else ops, st, denyOutcome d)
          GateOk st' sc' -> case appendBuffered sc' input of
            Left d -> (removeSingle SlotSign ops, st', denyOutcome d)
            Right sc'' -> case rawFloorDeny sc'' (BS.length (bufferedOf sc'')) of
              Just d -> (removeSingle SlotSign ops, st', denyOutcome d)
              Nothing ->
                ( insertOp (mkActiveSign sc'') ops
                , st'
                , StepOutcome CKR_OK
                    [FxSign (commonMech sc'') (commonKey sc'') (commonParams sc'')
                      (bufferedOf sc'')]
                    Nothing
                    ["sign one-shot planned over "
                      ++ show (BS.length input) ++ " bytes"] [] Nothing
                )

-- | Plan a sign final: one effect over the concatenation.
planSignFinal
  :: SessionOps -> SessionState -> String
  -> (SessionOps, SessionState, StepOutcome)
planSignFinal ops st _name = case withPlainSlot ops SlotSign of
  Left d -> (ops, st, denyOutcome d)
  Right sc -> case stagedOf sc of
    Just _ -> (ops, st, denyOutcome (mkDeny CKR_OPERATION_NOT_INITIALIZED
      "operation is finalized; retry the staged output instead"))
    Nothing -> case gateDataCall st sc of
      GateDeny d term ->
        (if term then removeSingle SlotSign ops else ops, st, denyOutcome d)
      GateOk st' sc' -> case rawFloorDeny sc' (BS.length (bufferedOf sc')) of
        Just d -> (removeSingle SlotSign ops, st', denyOutcome d)
        Nothing ->
          ( insertOp (mkActiveSign sc') ops
          , st'
          , StepOutcome CKR_OK
              [FxSign (commonMech sc') (commonKey sc') (commonParams sc') (bufferedOf sc')]
              Nothing
              ["sign final planned over "
                ++ show (BS.length (bufferedOf sc')) ++ " bytes"] [] Nothing
          )

-- | Finish a planned sign final or one-shot: stage the signature, or
-- terminate on any failure or driver-protocol violation.
finishSign
  :: SessionOps -> SlotKind -> String -> CryptoResult -> OutputIntent
  -> (SessionOps, StepOutcome)
finishSign ops kind name result intent
  | kind /= SlotSign =
      (ops, denyOutcome (mkDeny CKR_ARGUMENTS_BAD "not a sign slot"))
  | otherwise = case withPlainSlot ops SlotSign of
      Left d -> (ops, denyOutcome d)
      Right sc -> case stagedOf sc of
        Just _ -> (ops, denyOutcome (mkDeny CKR_GENERAL_ERROR
          "signature already staged; use retry"))
        Nothing -> case result of
          GotBytes sig ->
            let (staged, plan, freed) = stageBytes name sig intent
            in if freed
              then (removeSingle SlotSign ops
                   , StepOutcome CKR_OK [] (Just plan) ["sign complete"] [] Nothing)
              else ( insertOp
                       (mkActiveSign (setStaged staged sc)) ops
                   , StepOutcome CKR_BUFFER_TOO_SMALL [] (Just plan)
                       ["signature staged; retry with the reported length"] [] Nothing)
          GotValid _ ->
            ( removeSingle SlotSign ops
            , denyOutcome (mkDeny CKR_GENERAL_ERROR
                "driver answered a sign step with a verdict"))
          GotResource _ ->
            ( removeSingle SlotSign ops
            , denyOutcome (mkDeny CKR_GENERAL_ERROR
                "driver answered a sign step with a resource"))
          -- Unreachable via 'toCrypto'; loud on violation.
          GotUnit ->
            ( removeSingle SlotSign ops
            , denyOutcome (mkDeny CKR_GENERAL_ERROR
                "driver answered a sign step with a feed unit"))
          GotCryptoError err ->
            ( removeSingle SlotSign ops
            , denyOutcome (mkDeny (interpretError (TyCrypto err))
                ("sign crypto failed: " ++ show err)))

-- ---------------------------------------------------------------------------
-- Verify
-- ---------------------------------------------------------------------------

-- | Plan one verify update: buffer the part. No crypto is planned.
planVerifyUpdate
  :: SessionOps -> SessionState -> ByteString
  -> (SessionOps, SessionState, StepOutcome)
planVerifyUpdate ops st part = case withPlainSlot ops SlotVerify of
  Left d -> (ops, st, denyOutcome d)
  Right sc -> runBuffer ops st SlotVerify mkActiveVerify sc part

-- | Plan a verify one-shot. An empty witness is invalid without
-- planning an effect; one-shot is allowed only before any update.
planVerifyOneShot
  :: SessionOps -> SessionState -> String -> ByteString -> ByteString
  -> (SessionOps, SessionState, StepOutcome)
planVerifyOneShot ops st _name input sig = case withPlainSlot ops SlotVerify of
  Left d -> (ops, st, denyOutcome d)
  Right sc -> case stagedOf sc of
    Just _ -> (ops, st, denyOutcome (mkDeny CKR_OPERATION_NOT_INITIALIZED
      "operation is finalized"))
    Nothing
      | not (BS.null (bufferedOf sc)) ->
          (removeSingle SlotVerify ops, st, denyOutcome (mkDeny CKR_OPERATION_ACTIVE
            "multipart input already buffered; re-init to continue"))
      | BS.null sig ->
          ( removeSingle SlotVerify ops
          , st
          , StepOutcome CKR_SIGNATURE_INVALID [] Nothing ["empty signature"] [] Nothing)
      | otherwise -> case gateDataCall st sc of
          GateDeny d term ->
            (if term then removeSingle SlotVerify ops else ops, st, denyOutcome d)
          GateOk st' sc' -> case appendBuffered sc' input of
            Left d -> (removeSingle SlotVerify ops, st', denyOutcome d)
            Right sc'' -> case rawFloorDeny sc'' (BS.length (bufferedOf sc'')) of
              Just d -> (removeSingle SlotVerify ops, st', denyOutcome d)
              Nothing ->
                ( insertOp (mkActiveVerify sc'') ops
                , st'
                , StepOutcome CKR_OK
                    [FxVerify (commonMech sc'') (commonKey sc'') (commonParams sc'')
                      (bufferedOf sc'') sig]
                    Nothing
                    ["verify one-shot planned over "
                      ++ show (BS.length input) ++ " bytes"] [] Nothing
                )

-- | Plan a verify final: one effect over the concatenation plus the
-- witness. An empty witness is invalid without an effect.
planVerifyFinal
  :: SessionOps -> SessionState -> String -> ByteString
  -> (SessionOps, SessionState, StepOutcome)
planVerifyFinal ops st _name sig = case withPlainSlot ops SlotVerify of
  Left d -> (ops, st, denyOutcome d)
  Right sc -> case stagedOf sc of
    Just _ -> (ops, st, denyOutcome (mkDeny CKR_OPERATION_NOT_INITIALIZED
      "operation is finalized"))
    Nothing
      | BS.null sig ->
          ( removeSingle SlotVerify ops
          , st
          , StepOutcome CKR_SIGNATURE_INVALID [] Nothing ["empty signature"] [] Nothing)
      | otherwise -> case gateDataCall st sc of
          GateDeny d term ->
            (if term then removeSingle SlotVerify ops else ops, st, denyOutcome d)
          GateOk st' sc' -> case rawFloorDeny sc' (BS.length (bufferedOf sc')) of
            Just d -> (removeSingle SlotVerify ops, st', denyOutcome d)
            Nothing ->
              ( insertOp (mkActiveVerify sc') ops
              , st'
              , StepOutcome CKR_OK
                  [FxVerify (commonMech sc') (commonKey sc') (commonParams sc')
                    (bufferedOf sc') sig]
                  Nothing
                  ["verify final planned over "
                    ++ show (BS.length (bufferedOf sc')) ++ " bytes"] [] Nothing
              )

-- | Finish a planned verify final or one-shot. A valid witness
-- completes, a mismatch reports 'CKR_SIGNATURE_INVALID', and bytes
-- where a verdict belongs are a driver-protocol violation; all paths
-- terminate the slot.
finishVerify
  :: SessionOps -> SlotKind -> String -> CryptoResult -> OutputIntent
  -> (SessionOps, StepOutcome)
finishVerify ops kind name result _intent
  | kind /= SlotVerify =
      (ops, denyOutcome (mkDeny CKR_ARGUMENTS_BAD "not a verify slot"))
  | otherwise = case withPlainSlot ops SlotVerify of
      Left d -> (ops, denyOutcome d)
      Right _sc -> case result of
        GotValid True ->
          ( removeSingle SlotVerify ops
          , StepOutcome CKR_OK [] (Just (verdictPlan name CKR_OK "verify valid"))
              ["verify valid"] [] Nothing)
        GotValid False ->
          ( removeSingle SlotVerify ops
          , StepOutcome CKR_SIGNATURE_INVALID []
              (Just (verdictPlan name CKR_SIGNATURE_INVALID "signature mismatch"))
              ["signature mismatch"] [] Nothing)
        GotBytes _ ->
          ( removeSingle SlotVerify ops
          , denyOutcome (mkDeny CKR_GENERAL_ERROR
              "driver answered a verify step with bytes"))
        GotResource _ ->
          ( removeSingle SlotVerify ops
          , denyOutcome (mkDeny CKR_GENERAL_ERROR
              "driver answered a verify step with a resource"))
        -- Unreachable via 'toCrypto'; loud on violation.
        GotUnit ->
          ( removeSingle SlotVerify ops
          , denyOutcome (mkDeny CKR_GENERAL_ERROR
              "driver answered a verify step with a feed unit"))
        GotCryptoError err ->
          ( removeSingle SlotVerify ops
          , denyOutcome (mkDeny (interpretError (TyCrypto err))
              ("verify crypto failed: " ++ show err)))

-- ---------------------------------------------------------------------------
-- Sign-recover
-- ---------------------------------------------------------------------------

-- | Plan a sign-recover one-shot: the single effect whose driver tag
-- plus the buffered input assembles the @data \|\| tag@ block. The
-- block must fit the init-fixed capacity; oversize input terminates
-- the slot without planning an effect.
planSignRecoverOneShot
  :: SessionOps -> SessionState -> String -> ByteString
  -> (SessionOps, SessionState, StepOutcome)
planSignRecoverOneShot ops st _name input =
  case withRecoverSlot ops SlotSign RoleSignRecover of
    Left d -> (ops, st, denyOutcome d)
    Right (sc, spec) -> case stagedOf sc of
      Just _ -> (ops, st, denyOutcome (mkDeny CKR_OPERATION_NOT_INITIALIZED
        "operation is finalized; retry the staged output instead"))
      Nothing
        | not (BS.null (bufferedOf sc)) ->
            (ops, st, denyOutcome (mkDeny CKR_OPERATION_ACTIVE
              "recovery input already buffered"))
        | BS.length input + rsTagLen spec > rsCapacity spec ->
            ( removeSingle SlotSign ops
            , st
            , denyOutcome (mkDeny CKR_DATA_LEN_RANGE
                "recovery data exceeds the signature capacity"))
        | otherwise -> case gateDataCall st sc of
            GateDeny d term ->
              (if term then removeSingle SlotSign ops else ops, st, denyOutcome d)
            GateOk st' sc' -> case appendBuffered sc' input of
              Left d -> (removeSingle SlotSign ops, st', denyOutcome d)
              Right sc'' ->
                ( insertOp
                    (mkActiveRecover RoleSignRecover sc'' spec) ops
                , st'
                , StepOutcome CKR_OK
                    [FxSignRecover (commonMech sc'') (commonKey sc'') (commonParams sc'')
                      (bufferedOf sc'') (rsTagLen spec)]
                    Nothing
                    ["sign-recover one-shot planned over "
                      ++ show (BS.length input) ++ " bytes"] [] Nothing
                )

-- | Finish a planned sign-recover one-shot: assemble @data \|\| tag@
-- and stage the block. A wrong-width driver tag is a
-- driver-protocol violation; all failures terminate the slot.
finishSignRecover
  :: SessionOps -> SlotKind -> String -> CryptoResult -> OutputIntent
  -> (SessionOps, StepOutcome)
finishSignRecover ops kind name result intent
  | kind /= SlotSign =
      (ops, denyOutcome (mkDeny CKR_ARGUMENTS_BAD "not a sign slot"))
  | otherwise = case withRecoverSlot ops SlotSign RoleSignRecover of
      Left d -> (ops, denyOutcome d)
      Right (sc, spec) -> case stagedOf sc of
        Just _ -> (ops, denyOutcome (mkDeny CKR_GENERAL_ERROR
          "recovery block already staged; use retry"))
        Nothing -> case result of
          GotBytes tag
            | BS.length tag /= rsTagLen spec ->
                ( removeSingle SlotSign ops
                , denyOutcome (mkDeny CKR_GENERAL_ERROR
                    "driver tag width mismatch"))
            | otherwise ->
                let block = bufferedOf sc <> tag
                    (staged, plan, freed) = stageBytes name block intent
                in if freed
                  then (removeSingle SlotSign ops
                       , StepOutcome CKR_OK [] (Just plan) ["sign-recover complete"] [] Nothing)
                  else ( insertOp
                           (mkActiveRecover RoleSignRecover
                             (setStaged staged sc) spec) ops
                       , StepOutcome CKR_BUFFER_TOO_SMALL [] (Just plan)
                           ["recovery block staged; retry with the reported length"] [] Nothing)
          GotValid _ ->
            ( removeSingle SlotSign ops
            , denyOutcome (mkDeny CKR_GENERAL_ERROR
                "driver answered a sign-recover step with a verdict"))
          GotResource _ ->
            ( removeSingle SlotSign ops
            , denyOutcome (mkDeny CKR_GENERAL_ERROR
                "driver answered a sign-recover step with a resource"))
          -- Unreachable via 'toCrypto'; loud on violation.
          GotUnit ->
            ( removeSingle SlotSign ops
            , denyOutcome (mkDeny CKR_GENERAL_ERROR
                "driver answered a sign-recover step with a feed unit"))
          GotCryptoError err ->
            ( removeSingle SlotSign ops
            , denyOutcome (mkDeny (interpretError (TyCrypto err))
                ("sign-recover crypto failed: " ++ show err)))

-- ---------------------------------------------------------------------------
-- Verify-recover
-- ---------------------------------------------------------------------------

-- | Plan a verify-recover one-shot over a @data \|\| tag@ block. A
-- block no longer than the tag alone is invalid without an effect;
-- both shape failures terminate the slot.
planVerifyRecoverOneShot
  :: SessionOps -> SessionState -> String -> ByteString
  -> (SessionOps, SessionState, StepOutcome)
planVerifyRecoverOneShot ops st _name sig =
  case withRecoverSlot ops SlotVerify RoleVerifyRecover of
    Left d -> (ops, st, denyOutcome d)
    Right (sc, spec) -> case stagedOf sc of
      Just _ -> (ops, st, denyOutcome (mkDeny CKR_OPERATION_NOT_INITIALIZED
        "operation is finalized; retry the staged output instead"))
      Nothing
        | not (BS.null (bufferedOf sc)) ->
            (ops, st, denyOutcome (mkDeny CKR_OPERATION_ACTIVE
              "recovery input already buffered"))
        | BS.length sig <= rsTagLen spec ->
            ( removeSingle SlotVerify ops
            , st
            , StepOutcome CKR_SIGNATURE_INVALID [] Nothing
                ["recovery block holds no data"] [] Nothing)
        | BS.length sig > rsCapacity spec ->
            ( removeSingle SlotVerify ops
            , st
            , denyOutcome (mkDeny CKR_DATA_LEN_RANGE
                "recovery block exceeds the signature capacity"))
        | otherwise -> case gateDataCall st sc of
            GateDeny d term ->
              (if term then removeSingle SlotVerify ops else ops, st, denyOutcome d)
            GateOk st' sc' -> case appendBuffered sc' sig of
              Left d -> (removeSingle SlotVerify ops, st', denyOutcome d)
              Right sc'' ->
                ( insertOp
                    (mkActiveRecover RoleVerifyRecover sc'' spec) ops
                , st'
                , StepOutcome CKR_OK
                    [FxVerifyRecover (commonMech sc'') (commonKey sc'') (commonParams sc'')
                      (bufferedOf sc'') (rsTagLen spec)]
                    Nothing
                    ["verify-recover one-shot planned over "
                      ++ show (BS.length sig) ++ " bytes"] [] Nothing
                )

-- | Finish a planned verify-recover one-shot: stage the recovered
-- payload. A mismatch reports 'CKR_SIGNATURE_INVALID'; a bare
-- positive verdict is a driver-protocol violation (there is nothing
-- to stage); all paths terminate the slot.
finishVerifyRecover
  :: SessionOps -> SlotKind -> String -> CryptoResult -> OutputIntent
  -> (SessionOps, StepOutcome)
finishVerifyRecover ops kind name result intent
  | kind /= SlotVerify =
      (ops, denyOutcome (mkDeny CKR_ARGUMENTS_BAD "not a verify slot"))
  | otherwise = case withRecoverSlot ops SlotVerify RoleVerifyRecover of
      Left d -> (ops, denyOutcome d)
      Right (sc, spec) -> case stagedOf sc of
        Just _ -> (ops, denyOutcome (mkDeny CKR_GENERAL_ERROR
          "recovered data already staged; use retry"))
        Nothing -> case result of
          GotBytes dat ->
            let (staged, plan, freed) = stageBytes name dat intent
            in if freed
              then (removeSingle SlotVerify ops
                   , StepOutcome CKR_OK [] (Just plan) ["verify-recover complete"] [] Nothing)
              else ( insertOp
                       (mkActiveRecover RoleVerifyRecover
                         (setStaged staged sc) spec) ops
                   , StepOutcome CKR_BUFFER_TOO_SMALL [] (Just plan)
                       ["recovered data staged; retry with the reported length"] [] Nothing)
          GotValid False ->
            ( removeSingle SlotVerify ops
            , StepOutcome CKR_SIGNATURE_INVALID []
                (Just (verdictPlan name CKR_SIGNATURE_INVALID "recovery mismatch"))
                ["recovery mismatch"] [] Nothing)
          GotValid True ->
            ( removeSingle SlotVerify ops
            , denyOutcome (mkDeny CKR_GENERAL_ERROR
                "driver answered a verify-recover step with a bare verdict"))
          GotResource _ ->
            ( removeSingle SlotVerify ops
            , denyOutcome (mkDeny CKR_GENERAL_ERROR
                "driver answered a verify-recover step with a resource"))
          -- Unreachable via 'toCrypto'; loud on violation.
          GotUnit ->
            ( removeSingle SlotVerify ops
            , denyOutcome (mkDeny CKR_GENERAL_ERROR
                "driver answered a verify-recover step with a feed unit"))
          GotCryptoError err ->
            ( removeSingle SlotVerify ops
            , denyOutcome (mkDeny (interpretError (TyCrypto err))
                ("verify-recover crypto failed: " ++ show err)))