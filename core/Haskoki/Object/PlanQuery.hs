{- | Object find and get-attribute planning.
-}
{-# LANGUAGE OverloadedStrings #-}
module Haskoki.Object.PlanQuery
  (planFindObjects
  , viewForFind
  , readView
  , planGetAttributes
  ) where

import Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map
import Data.Maybe (listToMaybe)
import Data.Set (Set)
import qualified Data.Set as Set
import Haskoki.Attribute
  (AttributeResult (..)
  , AttributeType (..)
  , AttributeValue (..)
  , PartialReads (..)
  , encodeValue
  , getAttributes
  , payloadSealed
  , sealedAttrs
  )
import Haskoki.Der (dhSpkiFields, dsaSpkiFields, ecParamsNameOfOid)
import Haskoki.Model
  (HandleBinding (..)
  , Model (..)
  , ObjectState (..)
  , SessionState (..)
  )
import Haskoki.Outcome
  (DeltaOp (..)
  , NativeOutput (..)
  , PlanResult (..)
  , PreparedCommit (..)
  , Rejection (..)
  , StateDelta (..)
  )
import Haskoki.Request (OutputIntent (..), OutputRegion (..))
import Haskoki.Types
  (ExternalHandle (..)
  , ObjectId (..)
  , ReturnCode (..)
  )
import Haskoki.Object.Handles
import Haskoki.Object.PlanReject
import Haskoki.Object.StorageAttrs
import Haskoki.Object.TemplateValidation
import Haskoki.Object.PlanCerts

-- | Plan a one-shot find: matches carry equality over the read-back
-- view ('readView': the same representation 'planGetAttributes'
-- returns, plus the common storage defaults a storage object
-- reports) in ascending object-id order, restricted to objects
-- visible to the calling session. An empty template matches every
-- visible object; a contradictory template is rejected, never
-- silently emptied. Matches without a current binding gain fresh
-- ones in the same combined delta (discovery mints bindings; it
-- never reuses a dead handle). Sealed components never match: a
-- template naming the value or any private component only matches
-- unsealed objects, so find cannot serve as a guess-oracle against
-- sealed material (sealed objects stay discoverable by their other
-- attributes). The read-back @y@ is minimal (no leading zeros), so
-- a find with a creation-time @y@ that had leading zero bytes still
-- misses. The view projections run only when the template names an
-- attribute they change.
planFindObjects
  :: Model -> SessionState -> [(AttributeType, AttributeValue)] -> PlanResult
planFindObjects model st tmpl = case checkDuplicates tmpl of
  Left t -> templateReject CKR_TEMPLATE_INCONSISTENT
    ("contradictory attribute: " ++ show t)
  Right q ->
    let matches =
          [ (oid, ost)
          | (oid, ost) <- Map.toAscList (mObjects model)
          , objectVisible st ost
          , matchAll q ost
          ]
        (binds, outs) = assign (mNextHandle model) matches
    in Immediate PreparedCommit
      { pcCode = CKR_OK
      , pcDelta = StateDelta binds
      , pcPersist = []
      , pcOutputs = outs
      , pcReleases = []
      , pcReasons = ["find matched " ++ show (length matches) ++ " objects"]
      }
  where
    matchAll :: Map AttributeType AttributeValue -> ObjectState -> Bool
    matchAll q ost = all hit (Map.toList q)
      where
        view = viewForFind (Map.keysSet q) (osAttrs ost)
        hit (t, _)
          | t `elem` sealedAttrs, payloadSealed view = False
        hit (t, v) = Map.lookup t view == Just v
    currentHandle :: ObjectId -> ObjectState -> Maybe ExternalHandle
    currentHandle oid ost = listToMaybe
      [ h
      | (h, b) <- Map.toAscList (mHandles model)
      , hbObject b == oid
      , hbGeneration b == osGeneration ost
      ]
    assign :: Int -> [(ObjectId, ObjectState)] -> ([DeltaOp], [NativeOutput])
    assign _ [] = ([], [])
    assign next ((oid, ost) : rest) = case currentHandle oid ost of
      Just h ->
        let (binds, outs) = assign next rest
        in (binds, NativeOutput (RegionHandle "object") (encodeHandle h) : outs)
      Nothing ->
        let h = ExternalHandle next
            (binds, outs) = assign (next + 1) rest
        in (DeltaBindHandle h oid : binds
           , NativeOutput (RegionHandle "object") (encodeHandle h) : outs
           )

-- | Public-component projection for reads: 'AttrValue' stores
-- the SPKI DER (the engine's material shape), but PKCS#11 reads
-- the DSA/DH public value @y@ through @CKA_VALUE@ — so a public
-- DSA/DH object whose value parses as an SPKI reads @y@ instead
-- of the DER. Anything else (private halves, secrets, opaque
-- synthetic values, unparseable DER) passes through untouched.
-- The projection runs as part of 'readView' before 'getAttributes'
-- and before find matching; the seal never applies to these public
-- objects, so @y@ always reads and always matches.
projectPublicValue :: Map AttributeType AttributeValue -> Map AttributeType AttributeValue
projectPublicValue attrs = case (classOf, keyTypeOf, Map.lookup AttrValue attrs) of
  (Just c, Just k, Just (ValBytes der))
    | c == ckoPublicKey && k == ckkDsa
    , Just (_, _, _, y) <- dsaSpkiFields der ->
        Map.insert AttrValue (ValBytes y) attrs
    | c == ckoPublicKey && (k == ckkDh || k == ckkX9_42Dh)
    , Just (_, _, _, y) <- dhSpkiFields der ->
        Map.insert AttrValue (ValBytes y) attrs
  _ -> attrs
  where
    classOf = case Map.lookup AttrClass attrs of
      Just (ValULong c) -> Just c
      _ -> Nothing
    keyTypeOf = case Map.lookup AttrKeyType attrs of
      Just (ValULong k) -> Just k
      _ -> Nothing

-- | Curve-name normalization for reads: 'AttrEcParams' stores either
-- the engine curve name (generated and C-ABI-created keys) or the
-- raw SPKI parameter OID (pub-from-priv derivations), but the FFI
-- template decoder maps the OID to the name before matching — so a
-- stored OID reads as its name instead. Anything else (stored
-- names, foreign OIDs, non-bytes shapes) passes through untouched.
-- The normalization runs as part of 'readView'; stored bytes are
-- unchanged, and the C ABI still emits the OID DER via
-- 'ecParamsToWire'.
normalizeEcParams :: Map AttributeType AttributeValue -> Map AttributeType AttributeValue
normalizeEcParams attrs = case Map.lookup AttrEcParams attrs of
  Just (ValBytes bs) -> case ecParamsNameOfOid bs of
    Just name -> Map.insert AttrEcParams (ValBytes name) attrs
    Nothing -> attrs
  _ -> attrs

-- | The single shared read/find view: the public-value projection
-- and the curve-name normalization run only for the named
-- attributes that they change (find skips an SPKI parse when the
-- template does not name @CKA_VALUE@), then the common storage
-- defaults. Both 'planGetAttributes' (via 'readView') and
-- 'planFindObjects' match over this representation, so a value a
-- read returns always finds.
viewForFind :: Set AttributeType -> Map AttributeType AttributeValue -> Map AttributeType AttributeValue
viewForFind names attrs = effectiveAttrs (norm (proj attrs))
  where
    proj
      | Set.member AttrValue names = projectPublicValue
      | otherwise = id
    norm
      | Set.member AttrEcParams names = normalizeEcParams
      | otherwise = id

-- | The full shared read/find view ('viewForFind' over both
-- projected attributes): the representation 'planGetAttributes'
-- returns.
readView :: Map AttributeType AttributeValue -> Map AttributeType AttributeValue
readView = viewForFind (Set.fromList [AttrValue, AttrEcParams])

-- | Plan an attribute read: the handle must resolve and be
-- visible to the calling session, then one mixed outcome. Every
-- readable value is delivered; withheld entries are recorded per
-- attribute. A fully readable read commits; any sensitive or
-- unavailable entry makes the whole outcome a rejection that STILL
-- carries the readable values (error plus required effects in one
-- outcome).
planGetAttributes
  :: Model -> SessionState -> ExternalHandle -> [AttributeType] -> PlanResult
planGetAttributes model st h wanted = case resolveHandle model h of
  Nothing -> invalidHandle "unknown or destroyed object handle"
  Just ost
    | not (objectVisible st ost) ->
        invalidHandle "object not visible to session"
    | otherwise ->
    let PartialReads code results =
          getAttributes (readView (osAttrs ost)) wanted
        outs =
          [ NativeOutput (RegionBytes (show t) IntentNull) (encodeValue v)
          | (t, ResOk v) <- results
          ]
        reasons = [show t ++ ": " ++ statusOf r | (t, r) <- results]
    in if code == CKR_OK
      then Immediate PreparedCommit
        { pcCode = CKR_OK
        , pcDelta = StateDelta []
        , pcPersist = []
        , pcOutputs = outs
        , pcReleases = []
        , pcReasons = reasons
        }
      else Reject Rejection
        { rejCode = code
        , rejOutputs = outs
        , rejDelta = StateDelta []
        , rejReleases = []
        , rejReasons = reasons
        , rejCause = Nothing
        }
  where
    statusOf :: AttributeResult -> String
    statusOf r = case r of
      ResOk _ -> "ok"
      ResSensitive -> "sensitive"
      ResUnavailable -> "unavailable"
