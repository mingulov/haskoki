{- | Dual digest+cipher operation lifecycle (pure).

One update stream feeds both sides: every dual update buffers into
the digest side and the cipher side together, so each dual update is
directly comparable to its supported non-combined sequence. The
combined final plans one digest effect plus one cipher effect
(padding decided exactly as for singles) and stages both outputs
through one merged output plan. A short buffer on either side keeps
the dual for 'retryDualFinal', which replays only the sides still
pending; any crypto failure, verdict mismatch, or corrupt pad
terminates the whole dual.
-}
module Haskoki.Operation.Dual
  ( dualBuffered
  , dualAuth
  , planDualUpdate
  , planDualFinal
  , finishDual
  , retryDualFinal
  ) where

import qualified Data.ByteString as BS

import Haskoki.Model (SessionState)
import Haskoki.Operation
  ( CipherDir (..)
  , CipherSpec (..)
  , CryptoEffect (..)
  , CryptoResult (..)
  , DataGate (..)
  , DualState (..)
  , DualStaged (..)
  , OpAuth (..)
  , SessionOps
  , StagedOutput (..)
  , StepOutcome (..)
  , appendBuffered
  , TypedError (..)
  , interpretError
  , denyOutcome
  , mkDeny
  , gateDataCall
  , bufferedOf
  , commonAuth
  , commonKey
  , commonMech
  , commonParams
  , dualOf
  , setDual
  )
import Haskoki.Operation.Cipher (pkcs7Pad, pkcs7Unpad)
import Haskoki.Output
  ( OpDisposition (..)
  , OutputPlan (..)
  , ResultDisposition (..)
  , planOneShot
  )
import Haskoki.Request (OutputIntent)
import Haskoki.Types (Consumption (..), OpState (..), ReturnCode (..))

-- | Buffered multipart bytes of both dual sides, if a dual is active.
dualBuffered :: SessionOps -> Maybe (Int, Int)
dualBuffered ops = case dualOf ops of
  Nothing -> Nothing
  Just du -> Just
    ( BS.length (bufferedOf (duDigest du))
    , BS.length (bufferedOf (duCipher du))
    )

-- | Auth state of the dual's keyed (cipher) side, if active.
dualAuth :: SessionOps -> Maybe OpAuth
dualAuth ops = commonAuth . duCipher <$> dualOf ops

-- | Free the dual operation.
freeDual :: SessionOps -> SessionOps
freeDual ops = setDual Nothing ops

-- | Merge two single-region plans into one dual plan, digest side
-- first. The first non-OK code wins; writes, lengths, dispositions,
-- and reasons concatenate in plan order.
mergePlans :: OutputPlan -> OutputPlan -> OutputPlan
mergePlans p q = OutputPlan
  { opCode = if opCode p == CKR_OK then opCode q else opCode p
  , opWrites = opWrites p ++ opWrites q
  , opLengths = opLengths p ++ opLengths q
  , opDispositions = opDispositions p ++ opDispositions q
  , opReasons = opReasons p ++ opReasons q
  }

-- | Plan one dual update: buffer the part into both sides. The auth
-- gate runs on the keyed cipher side; the digest side is unkeyed and
-- never gated. No crypto is planned.
planDualUpdate
  :: SessionOps -> SessionState -> BS.ByteString
  -> (SessionOps, SessionState, StepOutcome)
planDualUpdate ops st part = case dualOf ops of
  Nothing -> (ops, st, denyOutcome (mkDeny CKR_OPERATION_NOT_INITIALIZED
    "no dual operation is active"))
  Just du -> case duStaged du of
    Just _ -> (ops, st, denyOutcome (mkDeny CKR_OPERATION_NOT_INITIALIZED
      "dual is finalized; retry the staged outputs instead"))
    Nothing -> case gateDataCall st (duCipher du) of
      GateDeny d term ->
        (if term then freeDual ops else ops, st, denyOutcome d)
      GateOk st' cipher' ->
        case (appendBuffered (duDigest du) part, appendBuffered cipher' part) of
          (Right digest'', Right cipher'') ->
            let total = BS.length (bufferedOf digest'')
            in ( setDual (Just du
                         { duDigest = digest'', duCipher = cipher'' }) ops
               , st'
               , StepOutcome CKR_OK [] Nothing
                   ["dual buffered " ++ show (BS.length part)
                     ++ " bytes (" ++ show total ++ " total per side)"] [] Nothing
               )
          (Left d, _) -> (freeDual ops, st', denyOutcome d)
          (_, Left d) -> (freeDual ops, st', denyOutcome d)

-- | Plan a dual final: one digest effect over the digest buffer plus
-- one cipher effect over the cipher buffer (padded first for
-- encrypt). A ragged unpadded encrypt buffer denies but keeps the
-- dual, since further updates can still repair the alignment.
planDualFinal
  :: SessionOps -> SessionState -> (SessionOps, SessionState, StepOutcome)
planDualFinal ops st = case dualOf ops of
  Nothing -> (ops, st, denyOutcome (mkDeny CKR_OPERATION_NOT_INITIALIZED
    "no dual operation is active"))
  Just du -> case duStaged du of
    Just _ -> (ops, st, denyOutcome (mkDeny CKR_OPERATION_NOT_INITIALIZED
      "dual is finalized; retry the staged outputs instead"))
    Nothing -> case gateDataCall st (duCipher du) of
      GateDeny d term ->
        (if term then freeDual ops else ops, st, denyOutcome d)
      GateOk st' cipher' ->
        let du' = du { duCipher = cipher' }
            dCom = duDigest du'
            cCom = duCipher du'
        in case duDir du of
          DirEncrypt ->
            let spec = duCipherSpec du
            in if csPad spec
              then case pkcs7Pad (csBlock spec) (bufferedOf cCom) of
                Nothing ->
                  ( freeDual ops
                  , st'
                  , denyOutcome (mkDeny CKR_GENERAL_ERROR
                      "dual cipher shape escapes the PKCS#7 range")
                  )
                Just padded -> emitDual ops st' du' (bufferedOf dCom) padded
              else if BS.length (bufferedOf cCom) `mod` csBlock spec /= 0
                then ( setDual (Just du') ops
                     , st'
                     , denyOutcome (mkDeny CKR_DATA_LEN_RANGE
                         "unpadded dual encrypt needs block-aligned input")
                     )
                else emitDual ops st' du' (bufferedOf dCom) (bufferedOf cCom)
          DirDecrypt ->
            emitDual ops st' du' (bufferedOf dCom) (bufferedOf cCom)
  where
    emitDual o s du dIn cIn =
      ( setDual (Just du) o
      , s
      , StepOutcome CKR_OK
          [ FxDigest (commonMech (duDigest du)) dIn
          , FxCipher (duDir du) (commonMech (duCipher du)) (commonKey (duCipher du))
              (commonParams (duCipher du)) cIn
          ]
          Nothing
          ["dual final planned over "
            ++ show (BS.length dIn) ++ " digest bytes and "
            ++ show (BS.length cIn) ++ " cipher bytes"] [] Nothing
      )

-- | Finish one side's bytes through the output planner, always
-- retaining the staged output (a done side still needs its bytes for
-- retry accounting).
finishSide
  :: String -> BS.ByteString -> OutputIntent
  -> (StagedOutput, OutputPlan, Bool)
finishSide name bytes intent =
  let (st', plan) = planOneShot (OpLive (Consumption 0)) name bytes intent
  in (StagedOutput name bytes st', plan, opCode plan == CKR_OK)

-- | Finish a planned dual final: resolve both driver answers (the
-- cipher side strips padding exactly as for singles), then stage
-- both outputs through one merged plan. Both sides must stage
-- before the dual frees; any failure terminates the whole dual.
finishDual
  :: SessionOps -> String -> String -> CryptoResult -> CryptoResult
  -> OutputIntent -> OutputIntent -> (SessionOps, StepOutcome)
finishDual ops dName cName dRes cRes dIntent cIntent =
  case dualOf ops of
    Nothing -> (ops, denyOutcome (mkDeny CKR_OPERATION_NOT_INITIALIZED
      "no dual operation is active"))
    Just du -> case duStaged du of
      Just _ -> (ops, denyOutcome (mkDeny CKR_GENERAL_ERROR
        "dual outputs already staged; use retry"))
      Nothing -> case dRes of
        GotCryptoError err -> kill (interpretError (TyCrypto err))
          ("dual digest crypto failed: " ++ show err)
        GotValid _ -> kill CKR_GENERAL_ERROR
          "driver answered a dual digest with a verdict"
        GotResource _ -> kill CKR_GENERAL_ERROR
          "driver answered a dual digest with a resource"
        -- Unreachable via 'toCrypto'; loud on violation.
        GotUnit -> kill CKR_GENERAL_ERROR
          "driver answered a dual digest with a feed unit"
        GotBytes dBytes -> case cRes of
          GotCryptoError err -> kill (interpretError (TyCrypto err))
            ("dual cipher crypto failed: " ++ show err)
          GotValid _ -> kill CKR_GENERAL_ERROR
            "driver answered a dual cipher step with a verdict"
          GotResource _ -> kill CKR_GENERAL_ERROR
            "driver answered a dual cipher step with a resource"
          -- Unreachable via 'toCrypto'; loud on violation.
          GotUnit -> kill CKR_GENERAL_ERROR
            "driver answered a dual cipher step with a feed unit"
          GotBytes raw -> case cipherOut du raw of
            Left deny -> (freeDual ops, denyOutcome deny)
            Right cBytes ->
              let (dSt, dPlan, dDone) = finishSide dName dBytes dIntent
                  (cSt, cPlan, cDone) = finishSide cName cBytes cIntent
                  merged = mergePlans dPlan cPlan
              in if dDone && cDone
                then ( freeDual ops
                     , StepOutcome CKR_OK [] (Just merged) ["dual final complete"] [] Nothing)
                else ( setDual (Just du
                               { duStaged = Just (DualStaged dSt cSt dDone cDone) }) ops
                     , StepOutcome (opCode merged) [] (Just merged)
                         ["dual outputs staged; retry with the reported lengths"] [] Nothing)
  where
    kill code why = (freeDual ops, denyOutcome (mkDeny code why))
    cipherOut du raw = case duDir du of
      DirEncrypt -> Right raw
      DirDecrypt ->
        let spec = duCipherSpec du
        in if csPad spec
          then case pkcs7Unpad (csBlock spec) raw of
            Just plain -> Right plain
            Nothing -> Left (mkDeny CKR_ENCRYPTED_DATA_INVALID
              "dual decrypt padding check failed")
          else if BS.length raw `mod` csBlock spec == 0
            then Right raw
            else Left (mkDeny CKR_ENCRYPTED_DATA_LEN_RANGE
              "unpadded dual decrypt answer is not block-aligned")

-- | A quiet plan for an already-delivered dual side: no writes, the
-- length answer repeated, and a terminating disposition.
quietPlan :: StagedOutput -> OutputPlan
quietPlan s = OutputPlan
  { opCode = CKR_OK
  , opWrites = []
  , opLengths = [([stName s], fromIntegral (BS.length (stBytes s)))]
  , opDispositions = [ResultDisposition [stName s] CKR_OK OpTerminate]
  , opReasons = ["already delivered"]
  }

-- | Retry a staged dual final with fresh intents. Delivered sides
-- replay nothing; pending sides restage through the output planner.
-- The dual frees once both sides have staged.
retryDualFinal
  :: SessionOps -> OutputIntent -> OutputIntent -> (SessionOps, StepOutcome)
retryDualFinal ops dIntent cIntent = case dualOf ops of
  Nothing -> (ops, denyOutcome (mkDeny CKR_OPERATION_NOT_INITIALIZED
    "no dual operation is active"))
  Just du -> case duStaged du of
    Nothing -> (ops, denyOutcome (mkDeny CKR_OPERATION_NOT_INITIALIZED
      "dual holds no staged outputs"))
    Just staged ->
      let (dSt', dPlan, dDone) = retrySide (dsDigest staged)
            (dsDigestDone staged) dIntent
          (cSt', cPlan, cDone) = retrySide (dsCipher staged)
            (dsCipherDone staged) cIntent
          merged = mergePlans dPlan cPlan
      in if dDone && cDone
        then ( freeDual ops
             , StepOutcome CKR_OK [] (Just merged) ["dual retry complete"] [] Nothing)
        else ( setDual (Just du
                       { duStaged = Just (DualStaged dSt' cSt' dDone cDone) }) ops
             , StepOutcome (opCode merged) [] (Just merged)
                 ["dual retry still short; staged outputs retained"] [] Nothing)
  where
    retrySide s done intent
      | done = (s, quietPlan s, True)
      | otherwise =
          let (st', plan) = planOneShot (stState s) (stName s) (stBytes s) intent
          in (s { stState = st' }, plan, opCode plan == CKR_OK)
