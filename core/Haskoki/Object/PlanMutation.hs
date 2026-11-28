{- | Object copy and set-attribute planning.
-}
{-# LANGUAGE OverloadedStrings #-}
module Haskoki.Object.PlanMutation
  ( deriveCopyAttrs
  , setAttributePolicy
  , copyPriority
  , copyExempt
  , copyIsNoop
  , planCopyObject
  , planSetAttributes
  ) where

import Data.List ( sortOn)
import Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map
import Haskoki.Attribute
  ( AttributeType (..)
  , AttributeValue (..)
  , historyAttrs
  , payloadSealed
  , sealedAttrs
  )
import Haskoki.Model
  ( Model (..)
  , ObjectState (..)
  , SessionState (..)
  )
import Haskoki.Outcome
  ( DeltaOp (..)
  , NativeOutput (..)
  , PlanResult (..)
  , PreparedCommit (..)
  , StateDelta (..)
  )
import Haskoki.Request ( OutputRegion (..))
import Haskoki.Session (SessionLogin ( LoginSO), admitCode, admitPrivate, admitWritable)
import Haskoki.Types
  ( ExternalHandle (..)
  , ObjectId (..)
  , ReturnCode (..)
  )
import Haskoki.Object.Handles
import Haskoki.Object.PlanCerts
import Haskoki.Object.PlanQuery
import Haskoki.Object.PlanReject
import Haskoki.Object.StorageAttrs
import Haskoki.Object.TemplateValidation

-- | Derive the stored attributes of a copy. Non-key copies keep
-- the merged map verbatim. Key copies additionally materialize the
-- absent protection flags from the source-effective view: the two
-- caller-settable flags where the merged map lacks them, and the
-- history/origin rows per the copy rule (a true->false EXTRACTABLE
-- flip forces NEVER_EXTRACTABLE false, since the key was
-- extractable once; the other rows inherit the source-effective
-- values). Public key copies carry no history rows (defensive: drops
-- any stored ALWAYS/NEVER a public source carries; class-changing
-- copies are refused, so private history cannot arrive here).
deriveCopyAttrs
  :: Map AttributeType AttributeValue -> Map AttributeType AttributeValue
  -> Map AttributeType AttributeValue
deriveCopyAttrs srcAttrs over
  | not (isKeyClass merged) = merged
  | isPublicKeyClass merged =
      fill [AttrSensitive, AttrExtractable, AttrLocal, AttrKeyGenMechanism]
        (Map.delete AttrAlwaysSensitive (Map.delete AttrNeverExtractable merged))
  | flipsDown =
      Map.insert AttrNeverExtractable (ValBool False)
        (fill [AttrSensitive, AttrExtractable, AttrAlwaysSensitive, AttrLocal, AttrKeyGenMechanism] merged)
  | otherwise =
      fill [AttrSensitive, AttrExtractable, AttrAlwaysSensitive, AttrNeverExtractable, AttrLocal, AttrKeyGenMechanism] merged
  where
    merged = Map.union over srcAttrs
    srcEff = effectiveAttrs srcAttrs
    flipsDown =
      Map.lookup AttrExtractable srcEff == Just (ValBool True)
        && Map.lookup AttrExtractable over == Just (ValBool False)
    fill ts m = foldr insertMissing m ts
    insertMissing t m
      | Map.member t m = m
      | otherwise = Map.insert t (srcEffOr t) m
    srcEffOr t = case Map.lookup t srcEff of
      Just v -> v
      Nothing
        | t == AttrKeyGenMechanism -> ValULong maxBound
        | otherwise -> ValBool False

-- | The shared per-attribute mutability policy behind
-- 'planSetAttributes' and 'planCopyObject': Nothing = mutable,
-- Just = refusal. Each ratchet compares against the effective value
-- (the reported view): writing what a read reports succeeds and only
-- a flip against the ratchet refuses. The 'CKA_MODIFIABLE=false'
-- guard above the ratchets is the exception: it compares against
-- the stored map, so on a non-modifiable object writing a defaulted
-- value the read reports (an absent label read back as @""@) still
-- refuses read-only. Non-key classes own no key flags and read
-- FALSE, so their enforcement is unchanged by construction. Copy
-- and set call this one function, so the two paths cannot drift on
-- any attribute.
setAttributePolicy
  :: Map AttributeType AttributeValue
  -> AttributeType -> AttributeValue -> Maybe (ReturnCode, String)
setAttributePolicy cur t v
  | not (flagOr modifiableDefault AttrModifiable cur)
  , Map.lookup t cur /= Just v = Just (CKR_ATTRIBUTE_READ_ONLY,
      "object is not modifiable (CKA_MODIFIABLE=false)")
  | t `elem` [AttrLabel, AttrApplication, AttrId] = Nothing
  | t `elem` [ AttrEncrypt, AttrDecrypt, AttrSign, AttrVerify
             , AttrSignRecover, AttrVerifyRecover
             , AttrWrap, AttrUnwrap, AttrDerive
             , AttrEncapsulate, AttrDecapsulate ] = Nothing
  | t == AttrToken = ratchet (flagOr tokenDefault AttrToken cur) True
      "CKA_TOKEN can only change false->true"
  | t == AttrExtractable = ratchet (effectiveExtractable cur) False
      "CKA_EXTRACTABLE can only change true->false"
  | t == AttrSensitive = ratchet (effectiveSensitive cur) True
      "CKA_SENSITIVE can only change false->true"
  | t == AttrCopyable = ratchet (flagOr copyableDefault AttrCopyable cur) False
      "CKA_COPYABLE can only change true->false"
  | t == AttrDestroyable = ratchet (flagOr destroyableDefault AttrDestroyable cur) False
      "CKA_DESTROYABLE can only change true->false"
  | t == AttrTrusted = Nothing
  | otherwise = Just (CKR_ATTRIBUTE_READ_ONLY,
      "attribute is not modifiable: " ++ show t)
  where
    ratchet c allowTrue msg = case v of
      ValBool n
        | c == n -> Nothing
        | n == allowTrue -> Nothing
      _ -> Just (CKR_ATTRIBUTE_READ_ONLY, msg)

-- | Copy-template check order. Seal (sensitive/extractable) precedes
-- certificate immutability, so a mixed template reports the seal;
-- class/key-type precede both. Within one priority the attribute
-- order decides.
copyPriority :: AttributeType -> Int
copyPriority t
  | t `elem` [AttrClass, AttrKeyType] = 0
  | t `elem` [AttrSensitive, AttrExtractable] = 1
  | t == AttrTrusted = 2
  | t `elem` certImmutable = 3
  | t `elem` historyAttrs = 4
  | otherwise = 5

-- | Attributes a copy template may set even on a non-modifiable
-- source (PKCS#11 3.2 C_CopyObject): the storage flags. TOKEN and
-- DESTROYABLE are freely settable on the copy in both directions;
-- COPYABLE keeps its true->false ratchet; PRIVATE keeps its
-- sealed-object guard; MODIFIABLE may only tighten (true->false).
copyExempt :: AttributeType -> Bool
copyExempt t = t `elem`
  [AttrToken, AttrPrivate, AttrModifiable, AttrDestroyable, AttrCopyable]

-- | Same-value no-op test for copy overrides: the stored bytes,
-- or the read-back view for @CKA_VALUE@ and @CKA_EC_PARAMS@ (the
-- 'readView' representation a read returns). One definition shared
-- by the refusal check and the no-op drop, so both paths agree on
-- what a no-op is.
copyIsNoop :: Map AttributeType AttributeValue -> Map AttributeType AttributeValue -> AttributeType -> AttributeValue -> Bool
copyIsNoop stored view t v = Map.lookup t stored == Just v
  || (t `elem` [AttrValue, AttrEcParams] && Map.lookup t view == Just v)

-- | Plan object copy: the source handle must resolve and be
-- visible to the calling session, the override template must be
-- contradiction-free, and the merged attributes must still carry a
-- class. The copy gets a fresh id and handle; the source is
-- untouched. Every override is validated through the shared
-- 'setAttributePolicy' against the source (same code as the set
-- path: 'CKR_ATTRIBUTE_READ_ONLY'); a no-op same-value override
-- still copies. A same-value override repeating the read-back value
-- (the 'readView' representation) is a no-op and is dropped before
-- the merge, so the stored bytes are preserved. Copy exemptions:
-- TOKEN, PRIVATE, MODIFIABLE, DESTROYABLE and COPYABLE may be set
-- even on a non-modifiable source (TOKEN and DESTROYABLE freely in
-- both directions; MODIFIABLE tightens only; COPYABLE to false
-- only; PRIVATE true->false on a sealed object refuses);
-- data-object CKA_VALUE overrides merge on modifiable sources only.
-- TRUSTED=true overrides need the SO login, and a merged
-- TRUSTED=true without the SO refuses (no silent inheritance).
-- Stored key copies materialize absent protection from the
-- source-effective view, with a true->false EXTRACTABLE flip
-- forcing NEVER_EXTRACTABLE false. Wrongly shaped overrides refuse
-- before any rule. An explicit @CKA_COPYABLE=false@ on the source
-- prohibits the copy ('CKR_ACTION_PROHIBITED').
planCopyObject
  :: Model -> SessionState -> ExternalHandle -> [(AttributeType, AttributeValue)]
  -> PlanResult
planCopyObject model st h tmpl = case resolveHandle model h of
  Nothing -> invalidHandle "unknown or destroyed source handle"
  Just src
    | not (objectVisible st src) ->
        invalidHandle "object not visible to session"
    | not (objectCopyable src) ->
        templateReject CKR_ACTION_PROHIBITED
          "source object is not copyable (CKA_COPYABLE=false)"
    | otherwise -> case checkDuplicates tmpl of
        Left t -> templateReject CKR_TEMPLATE_INCONSISTENT
          ("contradictory attribute: " ++ show t)
        Right overRaw -> case wrongShape (Map.toList overRaw) of
          Just t -> templateReject CKR_TEMPLATE_INCONSISTENT
            ("wrong shape for attribute: " ++ show t)
          Nothing
            | Map.lookup AttrTrusted overRaw == Just (ValBool True)
            , ssLogin st /= LoginSO ->
                templateReject CKR_ATTRIBUTE_READ_ONLY
                  "only the security officer may copy to TRUSTED=true"
            | Just (code, msg) <- copyRefusal (osAttrs src) overRaw ->
                templateReject code msg
            | mergedTrusted, ssLogin st /= LoginSO ->
                templateReject CKR_ATTRIBUTE_READ_ONLY
                  "copy would inherit TRUSTED=true without the security officer"
            | Just msg <- valueLenConflict (Map.union over (osAttrs src)) ->
                templateReject CKR_TEMPLATE_INCONSISTENT msg
            | Left deny <- admitPrivate (ssLogin st)
                (mergedIsPrivate (Map.union over (osAttrs src))) ->
                templateReject (admitCode deny)
                  "only the normal user may copy to private objects"
            | Left deny <- admitWritable (ssReadOnly st)
                (mergedIsToken (Map.union over (osAttrs src))) ->
                templateReject (admitCode deny)
                  "read-only session cannot copy to token objects"
            | otherwise ->
                let merged = deriveCopyAttrs (osAttrs src) over
                in if Map.member AttrClass merged
              then
                let oid = ObjectId (mNextObject model)
                    h2 = ExternalHandle (mNextHandle model)
                    owner
                      | mergedIsToken merged = Nothing
                      | otherwise = Just (ssId st)
                in Immediate PreparedCommit
                  { pcCode = CKR_OK
                  , pcDelta = StateDelta
                      [ DeltaCreateObjectFull oid merged owner (ssSlot st)
                      , DeltaBindHandle h2 oid
                      ]
                  , pcPersist = []
                  , pcOutputs = [NativeOutput (RegionHandle "object") (encodeHandle h2)]
                  , pcReleases = []
                  , pcReasons = ["copied object " ++ show (osId src) ++ " to " ++ show oid]
                  }
              else templateReject CKR_TEMPLATE_INCOMPLETE
                "merged template is missing the class"
            where
              srcAttrs0 = osAttrs src
              srcView = readView srcAttrs0
              over = Map.filterWithKey (\t v -> not (copyIsNoop srcAttrs0 srcView t v)) overRaw
              mergedTrusted =
                Map.lookup AttrTrusted (Map.union over srcAttrs0)
                  == Just (ValBool True)
              isCertSource =
                Map.lookup AttrClass (osAttrs src) == Just (ValULong ckoCertificate)
              isDataSource =
                Map.lookup AttrClass (osAttrs src) == Just (ValULong ckoData)
              -- First copy-template refusal in priority order, if any.
              -- TRUSTED on a certificate source stays refused even
              -- same-value (no SO exception); history attributes
              -- always refuse (token-assigned rows are never
              -- caller-carried, even same-value); a sealed
              -- component named on a sealed source refuses whatever
              -- the value, before the same-value no-op, so copy
              -- cannot confirm a guessed value or seed; same-value
              -- overrides are otherwise no-ops, comparing
              -- CKA_VALUE and CKA_EC_PARAMS against the read view
              -- as well as the stored bytes; data VALUE merges on
              -- modifiable sources only; exemptions bypass the
              -- modifiable gate; everything else goes through the
              -- shared policy with copy wording.
              copyRefusal srcAttrs overM = go ordered
                where
                  ordered = sortOn (\(t, _) -> (copyPriority t, fromEnum t))
                    (Map.toList overM)
                  srcViewLocal = readView srcAttrs
                  go [] = Nothing
                  go ((t, v) : rest)
                    | isCertSource, t == AttrTrusted =
                        Just (CKR_ATTRIBUTE_READ_ONLY,
                          "copy cannot override certificate field: " ++ show t)
                    | t `elem` historyAttrs = case setAttributePolicy srcAttrs t v of
                        Just (code, sharedMsg) ->
                          Just (code, copyMessage t v sharedMsg)
                        -- Unreachable: the shared policy refuses
                        -- history attributes unconditionally.
                        Nothing -> go rest
                    | t `elem` sealedAttrs
                    , payloadSealed (effectiveAttrs srcAttrs) =
                        Just (CKR_ATTRIBUTE_READ_ONLY,
                          "copy cannot name a sealed component: " ++ show t)
                    | copyIsNoop srcAttrs srcViewLocal t v = go rest
                    | t == AttrValue, isDataSource
                    , flagOr modifiableDefault AttrModifiable srcAttrs = go rest
                    | copyExempt t = case exemptRefusal t v of
                        Just refusal -> Just refusal
                        Nothing -> go rest
                    | otherwise = case setAttributePolicy srcAttrs t v of
                        Nothing -> go rest
                        Just (code, sharedMsg) ->
                          Just (code, copyMessage t v sharedMsg)
                  exemptRefusal t v
                    | t == AttrModifiable = modifiableCopyRefusal v
                    | t == AttrPrivate = privateRefusal v
                    | t == AttrToken = Nothing
                    | t == AttrDestroyable = Nothing
                    | otherwise =
                        setAttributePolicy modCur t v
                    where
                      modCur = Map.insert AttrModifiable (ValBool True) srcAttrs
                  modifiableCopyRefusal v = case v of
                    ValBool n
                      | flagOr modifiableDefault AttrModifiable srcAttrs == n -> Nothing
                      | n == False -> Nothing
                      | otherwise -> Just (CKR_ATTRIBUTE_READ_ONLY,
                          "copy cannot loosen MODIFIABLE false->true")
                    _ -> Just (CKR_ATTRIBUTE_READ_ONLY,
                      "copy cannot override immutable attribute: " ++ show AttrModifiable)
                  privateRefusal v = case v of
                    ValBool n
                      | flagOr privateDefault AttrPrivate srcAttrs == n -> Nothing
                      | n == False
                      , flagOr privateDefault AttrPrivate srcAttrs
                      , payloadSealed (effectiveAttrs srcAttrs) ->
                          Just (CKR_ATTRIBUTE_READ_ONLY,
                            "copy cannot make a sealed object public")
                      | otherwise -> Nothing
                    _ -> Just (CKR_ATTRIBUTE_READ_ONLY,
                      "copy cannot override immutable attribute: " ++ show AttrPrivate)
                  copyMessage t v sharedMsg
                    | not (flagOr modifiableDefault AttrModifiable srcAttrs) = sharedMsg
                    | t == AttrSensitive, v == ValBool False
                    , effectiveSensitive srcAttrs =
                        "copy cannot clear the sensitive flag"
                    | t == AttrExtractable, v == ValBool True
                    , not (effectiveExtractable srcAttrs) =
                        "copy cannot set extractable on an unextractable source"
                    | isCertSource, t `elem` certImmutable =
                        "copy cannot override certificate field: " ++ show t
                    | t `elem` historyAttrs =
                        "copy cannot override history attribute: " ++ show t
                    | otherwise =
                        "copy cannot override immutable attribute: " ++ show t

-- | Plan an attribute change: the handle must resolve and be
-- visible to the calling session, the template must be
-- contradiction-free with well-shaped values, and every entry must
-- be mutable on this object. Freely mutable: label, application,
-- id, and the operation usage flags. One-way ratchets (a flip
-- against the ratchet refuses 'CKR_ATTRIBUTE_READ_ONLY', a no-op
-- write succeeds): token false->true, extractable true->false,
-- sensitive false->true, copyable true->false, destroyable
-- true->false. Everything else (class, key type, value, value
-- length, mechanism policy, certificate and key-component
-- attributes) is unmodifiable and refuses
-- 'CKR_ATTRIBUTE_READ_ONLY'. The change is atomic: one combined
-- delta applies all entries or none. TRUSTED=true writes need the
-- SO login (refused before mutability as 'CKR_ATTRIBUTE_READ_ONLY');
-- TRUSTED=false writes pass for any session.
planSetAttributes
  :: Model -> SessionState -> ExternalHandle -> [(AttributeType, AttributeValue)]
  -> PlanResult
planSetAttributes model st h tmpl = case resolveHandle model h of
  Nothing -> invalidHandle "unknown or destroyed object handle"
  Just ost
    | not (objectVisible st ost) ->
        invalidHandle "object not visible to session"
    | Left deny <- admitPrivate (ssLogin st) (tmplWantsPrivate tmpl) ->
        templateReject (admitCode deny)
          "only the normal user may mark objects private"
    | Left deny <- admitWritable (ssReadOnly st)
        (objectToken ost || tmplWantsToken tmpl) ->
        templateReject (admitCode deny)
          "read-only session cannot modify token objects"
    | otherwise -> case checkDuplicates tmpl of
        Left t -> templateReject CKR_TEMPLATE_INCONSISTENT
          ("contradictory attribute: " ++ show t)
        Right over -> case wrongShape (Map.toList over) of
          Just t -> templateReject CKR_TEMPLATE_INCONSISTENT
            ("wrong shape for attribute: " ++ show t)
          Nothing
            | Map.lookup AttrTrusted over == Just (ValBool True)
            , ssLogin st /= LoginSO ->
                templateReject CKR_ATTRIBUTE_READ_ONLY
                  "only the security officer may set TRUSTED=true"
            | otherwise -> case firstRefusal (osAttrs ost) (Map.toList over) of
                Just (code, msg) -> templateReject code msg
                Nothing -> Immediate PreparedCommit
                  { pcCode = CKR_OK
                  , pcDelta = StateDelta [DeltaSetAttributes (osId ost) over]
                  , pcPersist = []
                  , pcOutputs = []
                  , pcReleases = []
                  , pcReasons = ["set " ++ show (Map.size over)
                      ++ " attributes on " ++ show (osId ost)]
                  }
  where
    firstRefusal _ [] = Nothing
    firstRefusal cur ((t, v) : rest) = case setAttributePolicy cur t v of
      Just refusal -> Just refusal
      Nothing -> firstRefusal cur rest
