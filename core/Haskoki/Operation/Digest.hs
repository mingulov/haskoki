{- | Digest operation lifecycle (pure).

Multipart sequencing over one digest slot through a backend stream:
the init allocates a backend context ('FxDigestInit'),
updates feed it ('FxDigestFeed') without buffering, and the final
consumes it ('FxDigestConsume') while the finisher releases it, so
every exit that drops a live stream drains it through 'pcReleases'.
One-shot is allowed only before any update. Per-result
disposition: success frees the slot, a short buffer keeps it for
'retryStaged', and any crypto failure or driver-protocol violation
terminates it.
-}
module Haskoki.Operation.Digest
  ( planDigestUpdate
  , planDigestOneShot
  , planDigestFinal
  , finishDigestInit
  , finishDigestFeed
  , finishDigest
  ) where

import qualified Data.ByteString as BS

import Haskoki.Model (SessionState)
import Haskoki.Operation
  ( CryptoEffect (..)
  , CryptoResult (..)
  , DigestStream (..)
  , SessionOps
  , SlotCommon
  , SlotKind (..)
  , StepOutcome (..)
  , appendBuffered
  , TypedError (..)
  , interpretError
  , denyOutcome
  , denyOutcomeR
  , mkDeny
  , gateDataCall
  , DataGate (..)
  , insertOp
  , lookupSingle
  , removeSingle
  , setStaged
  , stageBytes
  , stagedOf
  , streamOf
  , activeDigest
  , bufferedOf
  , commonMech
  , mkActiveDigest
  , setBuffered
  , setLive
  )
import Haskoki.Outcome (ResourceRelease (..))
import Haskoki.Request (OutputIntent)
import Haskoki.Types (ReturnCode (..))

-- | The release for a slot's live stream, if any.
streamRelease :: SlotCommon -> [ResourceRelease]
streamRelease sc = case streamOf sc of
  Just (DigestStream rid _) -> [ReleaseEngineResource rid]
  Nothing -> []

-- | Whether the slot's stream was fed already. A streamless slot
-- (restored legacy state) counts as unfed.
streamFed :: Maybe DigestStream -> Bool
streamFed Nothing = False
streamFed (Just ds) = dsFed ds

-- | Plan one digest update: feed the part to the backend stream.
-- The part is never buffered; the driver runs the feed effect.
planDigestUpdate
  :: SessionOps -> SessionState -> BS.ByteString
  -> (SessionOps, SessionState, StepOutcome)
planDigestUpdate ops st part = case lookupSingle ops SlotDigest of
  Nothing -> (ops, st, denyOutcome (mkDeny CKR_OPERATION_NOT_INITIALIZED
    "no digest operation is active"))
  Just active -> case activeDigest active of
    Just sc -> runUpdate ops st sc part
    _ -> (ops, st, denyOutcome (mkDeny CKR_GENERAL_ERROR
      "digest slot holds a foreign operation"))
  where
    runUpdate o s sc p = case stagedOf sc of
      Just _ -> (o, s, denyOutcome (mkDeny CKR_OPERATION_NOT_INITIALIZED
        "digest is finalized; retry the staged output instead"))
      Nothing -> case gateDataCall s sc of
        GateDeny d term ->
          (if term then removeSingle SlotDigest o else o, s, denyOutcome d)
        GateOk s' sc' -> case streamOf sc' of
          Nothing -> (removeSingle SlotDigest o, s', denyOutcome
            (mkDeny CKR_GENERAL_ERROR "digest stream is not allocated"))
          Just ds ->
            let sc'' = setLive (ds { dsFed = True }) sc'
            in ( insertOp (mkActiveDigest sc'') o
               , s'
               , StepOutcome CKR_OK
                   [FxDigestFeed (dsResource ds) p]
                   Nothing
                   ["fed " ++ show (BS.length p)
                     ++ " bytes to the digest stream"]
                   [] Nothing
               )

-- | Plan a digest one-shot over the full input. Allowed only before
-- any update; the bound still guards the single input even though
-- the bytes cross in the effect instead of the buffer.
planDigestOneShot
  :: SessionOps -> SessionState -> String -> BS.ByteString
  -> (SessionOps, SessionState, StepOutcome)
planDigestOneShot ops st _name input = case lookupSingle ops SlotDigest of
  Nothing -> (ops, st, denyOutcome (mkDeny CKR_OPERATION_NOT_INITIALIZED
    "no digest operation is active"))
  Just active -> case activeDigest active of
    Just sc -> runOneShot ops st sc input
    _ -> (ops, st, denyOutcome (mkDeny CKR_GENERAL_ERROR
      "digest slot holds a foreign operation"))
  where
    runOneShot o s sc bytes = case stagedOf sc of
      Just _ -> (o, s, denyOutcome (mkDeny CKR_OPERATION_NOT_INITIALIZED
        "digest is finalized; retry the staged output instead"))
      Nothing
        | streamFed (streamOf sc) || not (BS.null (bufferedOf sc)) ->
            (removeSingle SlotDigest o, s, denyOutcome (mkDeny CKR_OPERATION_ACTIVE
              "multipart input already fed; re-init to continue"))
        | otherwise -> case gateDataCall s sc of
            GateDeny d term ->
              (if term then removeSingle SlotDigest o else o, s, denyOutcome d)
            GateOk s' sc' -> case appendBuffered sc' bytes of
              Left d -> (removeSingle SlotDigest o, s', denyOutcome d)
              Right sc'' ->
                let sc0 = setBuffered BS.empty sc''
                in ( insertOp (mkActiveDigest sc0) o
                   , s'
                   , StepOutcome CKR_OK
                       [FxDigest (commonMech sc0) bytes]
                       Nothing
                       ["digest one-shot planned over "
                         ++ show (BS.length bytes) ++ " bytes"]
                       [] Nothing
                   )

-- | Plan a digest final: consume the backend stream. The finisher
-- stages the digest bytes and releases the context on every exit.
planDigestFinal
  :: SessionOps -> SessionState -> String
  -> (SessionOps, SessionState, StepOutcome)
planDigestFinal ops st _name = case lookupSingle ops SlotDigest of
  Nothing -> (ops, st, denyOutcome (mkDeny CKR_OPERATION_NOT_INITIALIZED
    "no digest operation is active"))
  Just active -> case activeDigest active of
    Just sc -> runFinal ops st sc
    _ -> (ops, st, denyOutcome (mkDeny CKR_GENERAL_ERROR
      "digest slot holds a foreign operation"))
  where
    runFinal o s sc = case stagedOf sc of
      Just _ -> (o, s, denyOutcome (mkDeny CKR_OPERATION_NOT_INITIALIZED
        "digest is finalized; retry the staged output instead"))
      Nothing -> case gateDataCall s sc of
        GateDeny d term ->
          (if term then removeSingle SlotDigest o else o, s, denyOutcome d)
        GateOk s' sc' -> case streamOf sc' of
          Nothing -> (removeSingle SlotDigest o, s', denyOutcome
            (mkDeny CKR_GENERAL_ERROR "digest stream is not allocated"))
          Just ds ->
            ( insertOp (mkActiveDigest sc') o
            , s'
            , StepOutcome CKR_OK
                [FxDigestConsume (dsResource ds)]
                Nothing
                ["digest final consumes the stream"]
                [] Nothing
            )

-- | Finish a digest-init allocation: record the stream on success,
-- terminate the slot on any failure. The allocation answered with
-- no resource, so a failure releases nothing.
finishDigestInit
  :: SessionOps -> SlotKind -> String -> CryptoResult -> OutputIntent
  -> (SessionOps, StepOutcome)
finishDigestInit ops kind _name result _intent
  | kind /= SlotDigest =
      (ops, denyOutcome (mkDeny CKR_ARGUMENTS_BAD "not a digest slot"))
  | otherwise = case lookupSingle ops SlotDigest of
      Nothing -> (ops, denyOutcome (mkDeny CKR_OPERATION_NOT_INITIALIZED
        "no digest operation is active"))
      Just active -> case activeDigest active of
        Just sc -> runFinish ops sc result
        _ -> (ops, denyOutcome (mkDeny CKR_GENERAL_ERROR
          "digest slot holds a foreign operation"))
  where
    runFinish o sc res = case res of
      GotResource rid -> case stagedOf sc of
        -- A staged slot is already concluded: the alloc answer is
        -- spurious (a second answer for one init — unreachable in
        -- real flows), so it is acknowledged without recording and
        -- the staged conclusion stands. Staged-first denies,
        -- occupancy, and retry then behave exactly as before; only
        -- the coexisting stream — unrepresentable now — is gone
        -- (save admits the staged slot instead of refusing it as
        -- live, and session close releases nothing for it).
        Just _ ->
          ( insertOp (mkActiveDigest sc) o
          , StepOutcome CKR_OK [] Nothing ["digest stream allocated"] [] Nothing
          )
        Nothing ->
          let sc' = setLive (DigestStream rid False) sc
          in ( insertOp (mkActiveDigest sc') o
             , StepOutcome CKR_OK [] Nothing ["digest stream allocated"] [] Nothing
             )
      GotCryptoError err ->
        ( removeSingle SlotDigest o
        , denyOutcome (mkDeny (interpretError (TyCrypto err))
            ("digest init failed: " ++ show err)))
      _ ->
        ( removeSingle SlotDigest o
        , denyOutcome (mkDeny CKR_GENERAL_ERROR
            "driver answered a digest init without a resource"))

-- | Finish a digest feed: the slot is unchanged on success; any
-- failure or protocol violation terminates it and releases the
-- stream.
finishDigestFeed
  :: SessionOps -> SlotKind -> String -> CryptoResult -> OutputIntent
  -> (SessionOps, StepOutcome)
finishDigestFeed ops kind _name result _intent
  | kind /= SlotDigest =
      (ops, denyOutcome (mkDeny CKR_ARGUMENTS_BAD "not a digest slot"))
  | otherwise = case lookupSingle ops SlotDigest of
      Nothing -> (ops, denyOutcome (mkDeny CKR_OPERATION_NOT_INITIALIZED
        "no digest operation is active"))
      Just active -> case activeDigest active of
        Just sc -> runFinish ops sc result
        _ -> (ops, denyOutcome (mkDeny CKR_GENERAL_ERROR
          "digest slot holds a foreign operation"))
  where
    runFinish o sc res = case res of
      GotBytes _ ->
        (o, StepOutcome CKR_OK [] Nothing ["digest feed complete"] [] Nothing)
      GotCryptoError err ->
        ( removeSingle SlotDigest o
        , denyOutcomeR (mkDeny (interpretError (TyCrypto err)) ("digest feed failed: " ++ show err))
            (streamRelease sc)
        )
      _ ->
        ( removeSingle SlotDigest o
        , denyOutcomeR (mkDeny CKR_GENERAL_ERROR "driver answered a digest feed off-shape")
            (streamRelease sc)
        )

-- | Finish a planned digest final or one-shot: stage the digest
-- bytes, or terminate the slot on any failure. A verdict- or
-- resource-shaped result is a driver protocol violation and
-- terminates as well. Every exit that drops a live stream releases
-- it; a short buffer keeps the slot with the stream cleared, so
-- the pure retry can never double-release.
finishDigest
  :: SessionOps -> SlotKind -> String -> CryptoResult -> OutputIntent
  -> (SessionOps, StepOutcome)
finishDigest ops kind name result intent
  | kind /= SlotDigest =
      (ops, denyOutcome (mkDeny CKR_ARGUMENTS_BAD "not a digest slot"))
  | otherwise = case lookupSingle ops SlotDigest of
      Nothing -> (ops, denyOutcome (mkDeny CKR_OPERATION_NOT_INITIALIZED
        "no digest operation is active"))
      Just active -> case activeDigest active of
        Just sc -> runFinish ops sc result
        _ -> (ops, denyOutcome (mkDeny CKR_GENERAL_ERROR
          "digest slot holds a foreign operation"))
  where
    runFinish o sc res = case stagedOf sc of
      Just _ -> (o, denyOutcome (mkDeny CKR_GENERAL_ERROR
        "digest already staged; use retry"))
      Nothing -> case res of
        GotBytes digest ->
          let (staged, plan, freed) = stageBytes name digest intent
              rel = streamRelease sc
          in if freed
            then (removeSingle SlotDigest o
                 , StepOutcome CKR_OK [] (Just plan) ["digest complete"] rel Nothing)
            else ( insertOp
                     (mkActiveDigest (setStaged staged sc)) o
                 , StepOutcome CKR_BUFFER_TOO_SMALL [] (Just plan)
                     ["digest staged; retry with the reported length"] rel Nothing)
        GotValid _ ->
          ( removeSingle SlotDigest o
          , denyOutcomeR (mkDeny CKR_GENERAL_ERROR "driver answered a digest with a verdict")
              (streamRelease sc)
          )
        GotResource _ ->
          ( removeSingle SlotDigest o
          , denyOutcomeR (mkDeny CKR_GENERAL_ERROR "driver answered a digest with a resource")
              (streamRelease sc)
          )
        -- Unreachable via 'toCrypto' (which never produces
        -- 'GotUnit'); loud failure if the driver protocol is ever
        -- violated.
        GotUnit ->
          ( removeSingle SlotDigest o
          , denyOutcomeR (mkDeny CKR_GENERAL_ERROR "driver answered a digest with a feed unit")
              (streamRelease sc)
          )
        GotCryptoError err ->
          ( removeSingle SlotDigest o
          , denyOutcomeR (mkDeny (interpretError (TyCrypto err)) ("digest crypto failed: " ++ show err))
              (streamRelease sc)
          )
