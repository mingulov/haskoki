{- | Checked call-work construction (pure).

A 'CallWork' is one executable call unit — the submitting session,
the guarding reservation, and the effect the runner executes —
validated as a triple before anything runs it. 'checkedCallWork'
is the only constructor: it validates step presence, step/session
identity, the function/slot family, and effect compatibility, in
that order, reporting the first failure as a typed 'WorkMismatch'.
'callPairCompatible' is the total Bool form for injected
boundaries (async submit, detach rejoin): stepped triples must
check fully, while legacy unstepped triples admit explicitly
('admitLegacyUnstepped') without ever sniffing the effect
content. Normal submission never content-fallbacks: a missing
step is a hard 'WorkUnstepped', never a guessed coherence.

This is a pure leaf over the domain types ('Haskoki.Outcome',
'Haskoki.Request', 'Haskoki.Operation.State',
'Haskoki.Operation.Effect', 'Haskoki.Model', 'Haskoki.Types').
It never imports the async runtime or any effect interpreter; the
boundaries that enforce it ('Haskoki.Runtime.Async',
'Haskoki.Runtime.Detached', the FFI submit legs) depend on it,
never the reverse.
-}
module Haskoki.CallWork
  ( CallWork
  , WorkMismatch (..)
  , checkedCallWork
  , callPairCompatible
  , admitLegacyUnstepped
  , callFunctionSlot
  , callFunctionEffect
  , callWorkSession
  , callWorkReservation
  , callWorkEffect
  ) where

import Data.Either (isRight)

import Haskoki.Model (SessionState (..))
import Haskoki.Operation.Effect (CryptoEffect (..))
import Haskoki.Operation.State (CipherDir (..), SlotKind (..))
import Haskoki.Outcome (CryptoStep (..), EffectRequest (..), Reservation (..))
import Haskoki.Request (FunctionId (..))
import Haskoki.Types (SessionId)

-- | Why a (session, reservation, effect) triple is not executable
-- call work. Check order (first failure reports): step presence,
-- then step/session identity, then the function/slot family, then
-- effect compatibility.
data WorkMismatch
  = -- | The reservation pins no step: nothing to validate the
    -- triple against. Normal submission refuses; injected
    -- boundaries admit legacy fixtures explicitly
    -- ('admitLegacyUnstepped').
    WorkUnstepped
  | -- | The step's session disagrees with the submitting session:
    -- @(want, got)@, the submitting session first.
    WorkSessionMismatch !SessionId !SessionId
  | -- | The pinned function/slot pair disagrees: either the
    -- function has no finishing leg or the slot is not the leg it
    -- runs over.
    WorkFunctionSlotMismatch !FunctionId !SlotKind
  | -- | The pinned function cannot consume the planned effect.
    WorkEffectMismatch !FunctionId !CryptoEffect
  deriving (Eq, Show)

-- | Checked call work: the constructor is private, so values only
-- ever come from 'checkedCallWork'. Read through the accessors
-- below; the record fields stay internal.
data CallWork = CallWork
  { cwSession :: !SessionId
  , cwReservation :: !Reservation
  , cwEffect :: !EffectRequest
  } deriving (Eq, Show)

-- | The submitting session behind checked call work.
callWorkSession :: CallWork -> SessionId
callWorkSession = cwSession

-- | The guarding reservation behind checked call work.
callWorkReservation :: CallWork -> Reservation
callWorkReservation = cwReservation

-- | The executable effect behind checked call work.
callWorkEffect :: CallWork -> EffectRequest
callWorkEffect = cwEffect

-- | The call-effect shape behind one planned effect: the classifier
-- 'callFunctionEffect' matches on. Key-management shapes share one
-- bucket: none ever pairs with a call step (key work finishes
-- through 'Haskoki.Operation.KeyManagement.finishWork', never a
-- call finisher).
data CallEffectShape
  = ShapeDigest
  | ShapeDigestInit
  | ShapeDigestFeed
  | ShapeDigestConsume
  | ShapeCipher !CipherDir
  | ShapeSign
  | ShapeVerify
  | ShapeSignRecover
  | ShapeVerifyRecover
  | ShapeMsgCipher !CipherDir
  | ShapeMsgSign
  | ShapeMsgVerify
  | ShapeKeyMgmt
  deriving (Eq, Show)

-- | Classify one planned effect. Exhaustive over 'CryptoEffect' (no
-- wildcard): a new constructor breaks the build here, forcing an
-- explicit call-coherence verdict.
effectShape :: CryptoEffect -> CallEffectShape
effectShape fx = case fx of
  FxDigest _ _ -> ShapeDigest
  FxDigestInit _ -> ShapeDigestInit
  FxDigestFeed _ _ -> ShapeDigestFeed
  FxDigestConsume _ -> ShapeDigestConsume
  FxCipher dir _ _ _ _ -> ShapeCipher dir
  FxSign _ _ _ _ -> ShapeSign
  FxVerify _ _ _ _ _ -> ShapeVerify
  FxSignRecover _ _ _ _ _ -> ShapeSignRecover
  FxVerifyRecover _ _ _ _ _ -> ShapeVerifyRecover
  FxMessageCipher dir _ _ _ _ _ -> ShapeMsgCipher dir
  FxMessageSign _ _ _ _ -> ShapeMsgSign
  FxMessageVerify _ _ _ _ _ -> ShapeMsgVerify
  FxGenerateKey _ _ _ -> ShapeKeyMgmt
  FxWrap _ _ _ _ -> ShapeKeyMgmt
  FxUnwrap _ _ _ _ -> ShapeKeyMgmt
  FxAuthWrap _ _ _ _ -> ShapeKeyMgmt
  FxAuthUnwrap _ _ _ _ -> ShapeKeyMgmt
  FxDerive _ _ _ _ _ _ -> ShapeKeyMgmt
  FxKemEncaps _ _ _ _ -> ShapeKeyMgmt
  FxKemDecaps _ _ _ _ -> ShapeKeyMgmt

-- | The slot a finishing function runs over, if it has a finishing
-- leg. Mirrors 'Haskoki.Transition.runFinisher' arm for arm: the
-- Just-set pin in @TransitionSpec@ fails if either table drifts.
-- Exhaustive over 'FunctionId' (no wildcard): a new function
-- breaks the build here, forcing an explicit slot verdict.
callFunctionSlot :: FunctionId -> Maybe SlotKind
callFunctionSlot fid = case fid of
  F_Digest -> Just SlotDigest
  F_DigestInit -> Just SlotDigest
  F_DigestUpdate -> Just SlotDigest
  F_DigestFinal -> Just SlotDigest
  F_Sign -> Just SlotSign
  F_SignFinal -> Just SlotSign
  F_SignRecover -> Just SlotSign
  F_Verify -> Just SlotVerify
  F_VerifyFinal -> Just SlotVerify
  F_VerifyRecover -> Just SlotVerify
  F_Encrypt -> Just SlotEncrypt
  F_EncryptUpdate -> Just SlotEncrypt
  F_EncryptFinal -> Just SlotEncrypt
  F_Decrypt -> Just SlotDecrypt
  F_DecryptUpdate -> Just SlotDecrypt
  F_DecryptFinal -> Just SlotDecrypt
  F_EncryptMessage -> Just SlotEncrypt
  F_DecryptMessage -> Just SlotDecrypt
  F_SignMessage -> Just SlotSign
  F_VerifyMessage -> Just SlotVerify
  F_EncryptMessageNext -> Just SlotEncrypt
  F_DecryptMessageNext -> Just SlotDecrypt
  F_SignMessageNext -> Just SlotSign
  F_VerifyMessageNext -> Just SlotVerify
  -- Functions without a finishing leg map to 'Nothing' (no
  -- wildcard): a new constructor breaks the build here, forcing
  -- an explicit arm choice, exactly as in 'runFinisher'.
  F_GetInfo -> Nothing
  F_GetSlotList -> Nothing
  F_GetSessionInfo -> Nothing
  F_OpenSession -> Nothing
  F_CloseSession -> Nothing
  F_Login -> Nothing
  F_Logout -> Nothing
  F_SignInit -> Nothing
  F_SignRecoverInit -> Nothing
  F_CreateObject -> Nothing
  F_DestroyObject -> Nothing
  F_CopyObject -> Nothing
  F_FindObjects -> Nothing
  F_GetAttributeValue -> Nothing
  F_SetAttributeValue -> Nothing
  F_SignUpdate -> Nothing
  F_VerifyInit -> Nothing
  F_VerifyRecoverInit -> Nothing
  F_VerifyUpdate -> Nothing
  F_EncryptInit -> Nothing
  F_DecryptInit -> Nothing
  F_MessageEncryptInit -> Nothing
  F_MessageDecryptInit -> Nothing
  F_MessageSignInit -> Nothing
  F_MessageVerifyInit -> Nothing
  F_EncryptMessageBegin -> Nothing
  F_DecryptMessageBegin -> Nothing
  F_SignMessageBegin -> Nothing
  F_VerifyMessageBegin -> Nothing
  F_MessageEncryptFinal -> Nothing
  F_MessageDecryptFinal -> Nothing
  F_MessageSignFinal -> Nothing
  F_MessageVerifyFinal -> Nothing
  F_SessionCancel -> Nothing
  F_InitToken -> Nothing
  F_InitPIN -> Nothing
  F_SetPIN -> Nothing

-- | Whether a finishing function accepts one planned effect: the
-- exact per-function shape sets the planners emit (the producing
-- planner per arm: 'Haskoki.Operation.Digest',
-- 'Haskoki.Operation.Signature', 'Haskoki.Operation.Cipher',
-- 'Haskoki.Operation.Message', and the decoded-init arm for
-- digest allocation). Cipher directions pin exactly (encrypt
-- legs take 'DirEncrypt' only, decrypt legs 'DirDecrypt'
-- only — 'withCipherSlot' guarantees the planner side);
-- key-management shapes pair with nothing. Exhaustive over
-- 'FunctionId' (no wildcard); effect coverage is forced
-- through 'effectShape'.
callFunctionEffect :: FunctionId -> CryptoEffect -> Bool
callFunctionEffect fid fx =
  let shape = effectShape fx
  in case fid of
    F_Digest -> shape == ShapeDigest
    F_DigestInit -> shape == ShapeDigestInit
    F_DigestUpdate -> shape == ShapeDigestFeed
    F_DigestFinal -> shape == ShapeDigest || shape == ShapeDigestConsume
    F_Sign -> shape == ShapeSign
    F_SignFinal -> shape == ShapeSign
    F_SignRecover -> shape == ShapeSignRecover
    F_Verify -> shape == ShapeVerify
    F_VerifyFinal -> shape == ShapeVerify
    F_VerifyRecover -> shape == ShapeVerifyRecover
    F_Encrypt -> shape == ShapeCipher DirEncrypt
    F_EncryptUpdate -> shape == ShapeCipher DirEncrypt
    F_EncryptFinal -> shape == ShapeCipher DirEncrypt
    F_Decrypt -> shape == ShapeCipher DirDecrypt
    F_DecryptUpdate -> shape == ShapeCipher DirDecrypt
    F_DecryptFinal -> shape == ShapeCipher DirDecrypt
    F_EncryptMessage -> shape == ShapeMsgCipher DirEncrypt
    F_DecryptMessage -> shape == ShapeMsgCipher DirDecrypt
    F_SignMessage -> shape == ShapeMsgSign
    F_VerifyMessage -> shape == ShapeMsgVerify
    F_EncryptMessageNext -> shape == ShapeMsgCipher DirEncrypt
    F_DecryptMessageNext -> shape == ShapeMsgCipher DirDecrypt
    F_SignMessageNext -> shape == ShapeMsgSign
    F_VerifyMessageNext -> shape == ShapeMsgVerify
    -- Functions without a finishing leg accept nothing (no
    -- wildcard): a new constructor breaks the build here,
    -- forcing an explicit arm choice.
    F_GetInfo -> False
    F_GetSlotList -> False
    F_GetSessionInfo -> False
    F_OpenSession -> False
    F_CloseSession -> False
    F_Login -> False
    F_Logout -> False
    F_SignInit -> False
    F_SignRecoverInit -> False
    F_CreateObject -> False
    F_DestroyObject -> False
    F_CopyObject -> False
    F_FindObjects -> False
    F_GetAttributeValue -> False
    F_SetAttributeValue -> False
    F_SignUpdate -> False
    F_VerifyInit -> False
    F_VerifyRecoverInit -> False
    F_VerifyUpdate -> False
    F_EncryptInit -> False
    F_DecryptInit -> False
    F_MessageEncryptInit -> False
    F_MessageDecryptInit -> False
    F_MessageSignInit -> False
    F_MessageVerifyInit -> False
    F_EncryptMessageBegin -> False
    F_DecryptMessageBegin -> False
    F_SignMessageBegin -> False
    F_VerifyMessageBegin -> False
    F_MessageEncryptFinal -> False
    F_MessageDecryptFinal -> False
    F_MessageSignFinal -> False
    F_MessageVerifyFinal -> False
    F_SessionCancel -> False
    F_InitToken -> False
    F_InitPIN -> False
    F_SetPIN -> False

-- | Check one (submitting session, reservation, effect) triple into
-- executable call work: the step must exist, its session must be
-- the submitting session, its function/slot pair must agree, and
-- the pinned function must accept the planned effect. The first
-- failure reports; see 'WorkMismatch' for the order.
checkedCallWork :: SessionId -> Reservation -> EffectRequest -> Either WorkMismatch CallWork
checkedCallWork sid res eff = case resStep res of
  Nothing -> Left WorkUnstepped
  Just step -> case eff of
    EffectCrypto fx
      | ssId (csSession step) /= sid ->
          Left (WorkSessionMismatch sid (ssId (csSession step)))
      | callFunctionSlot (csFunction step) /= Just (csKind step) ->
          Left (WorkFunctionSlotMismatch (csFunction step) (csKind step))
      | not (callFunctionEffect (csFunction step) fx) ->
          Left (WorkEffectMismatch (csFunction step) fx)
      | otherwise -> Right (CallWork sid res eff)

-- | Whether a (submitting session, reservation, effect) triple may
-- execute at an injected boundary (async submit, detach rejoin):
-- stepped triples must check fully; legacy unstepped triples
-- admit explicitly ('admitLegacyUnstepped') without sniffing the
-- effect. Total: every triple takes exactly one verdict, and no
-- verdict accepts by default.
callPairCompatible :: SessionId -> Reservation -> EffectRequest -> Bool
callPairCompatible sid res eff
  | admitLegacyUnstepped res = True
  | otherwise = isRight (checkedCallWork sid res eff)

-- | INTERNAL: the explicit legacy admission behind
-- 'callPairCompatible'. Unstepped reservations predate pinned
-- steps (hand-built fixtures); injected boundaries admit them
-- AS-IS — the effect family is never guessed from a missing
-- step, so there is no content fallback to drift. Normal
-- submission never calls this: planner-produced pairs always
-- carry steps, and a missing step there is 'WorkUnstepped'.
admitLegacyUnstepped :: Reservation -> Bool
admitLegacyUnstepped res = case resStep res of
  Nothing -> True
  Just _ -> False
