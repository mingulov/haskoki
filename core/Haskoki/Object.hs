{- | Object lifecycle planning and the external-handle map (pure).

Stable internal 'ObjectId's, caller-visible 'ExternalHandle's, and
generation-guarded bindings between them. Handles are never reused:
destroy stale-marks the binding (generation bump, binding retained)
and resolution faults deterministically forever after. Discovery
(find) mints fresh bindings for objects that lack a current one.

Request arguments ride the 'Request.reqInput' 'ByteString' via
tiny documented codecs ('encodeTemplate'/'parseTemplate',
'encodeWanted'/'parseWanted'); real decode lives in the FFI layer.
-}
{-# LANGUAGE OverloadedStrings #-}
module Haskoki.Object
  ( TemplateError (..)
  , validateTemplate
  , TemplateRule (..)
  , RuleDeny (..)
  , findRule
  , checkRules
  , encodeTemplate
  , parseTemplate
  , maxTemplateEntries
  , encodeWanted
  , parseWanted
  , encodeHandle
  , decodeHandle
  , resolveHandle
  , objectToken
  , objectPrivate
  , objectVisible
  , planCreateObject
  , planDestroyObject
  , planCopyObject
  , planFindObjects
  , planGetAttributes
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map
import Data.Maybe (isNothing, listToMaybe)
import Data.Text (Text)
import Data.Word (Word64, Word8)

import Haskoki.Attribute
  ( AttributeResult (..)
  , AttributeType (..)
  , AttributeValue (..)
  , PartialReads (..)
  , attributeTypeByName
  , decodeValue
  , encodeValue
  , getAttributes
  , payloadSealed
  , shapeMatches
  )
import Haskoki.Attribute.Generated
  (classNameById, generatedTemplateRules, mustClassId, mustKeyTypeId)
import Haskoki.Der
  (curveCoordLen, curveOidOfParams, ecPrivateDer, ecPublicDer,
   rsaPrivateDer, rsaPublicDer, unwrapEcPoint)
import Haskoki.Model
  ( HandleBinding (..)
  , Model (..)
  , ObjectState (..)
  , SessionState (..)
  )
import Haskoki.Outcome
  ( DeltaOp (..)
  , NativeOutput (..)
  , PlanResult (..)
  , PreparedCommit (..)
  , Rejection (..)
  , StateDelta (..)
  )
import Haskoki.Request (OutputIntent (..), OutputRegion (..))
import Haskoki.Session (SessionLogin (LoginPublic))
import Haskoki.Types
  ( ExternalHandle (..)
  , ObjectId (..)
  , ReturnCode (..)
  )

-- ---------------------------------------------------------------------------
-- Template validation
-- ---------------------------------------------------------------------------

-- | Why a template was rejected: two entries for one type with
-- different values, a value with the wrong shape for its type, or
-- a missing required class.
data TemplateError
  = TemplateContradiction !AttributeType
  | TemplateWrongType !AttributeType
  | TemplateIncomplete
  deriving (Eq, Show)

-- | Reject contradictory duplicates; repeated identical values merge
-- silently. The incoming template stays an ordered sequence until
-- this check runs so contradictions cannot hide in a map.
checkDuplicates
  :: [(AttributeType, AttributeValue)]
  -> Either AttributeType (Map AttributeType AttributeValue)
checkDuplicates = go Map.empty
  where
    go acc [] = Right acc
    go acc ((t, v) : rest) = case Map.lookup t acc of
      Nothing -> go (Map.insert t v acc) rest
      Just v'
        | v' == v -> go acc rest
        | otherwise -> Left t

-- | Validate a creation template: no contradictions, every value
-- carrying its type's shape, and the class present (the one
-- required attribute in this inventory; class-specific required
-- sets arrive with the generated inventory). Malformedness
-- outranks incompleteness: contradictions and wrong shapes refuse
-- before the class check runs.
validateTemplate
  :: [(AttributeType, AttributeValue)]
  -> Either TemplateError (Map AttributeType AttributeValue)
validateTemplate entries = case checkDuplicates entries of
  Left t -> Left (TemplateContradiction t)
  Right m -> case wrongShape (Map.toList m) of
    Just t -> Left (TemplateWrongType t)
    Nothing
      | Map.member AttrClass m -> Right m
      | otherwise -> Left TemplateIncomplete
  where
    wrongShape [] = Nothing
    wrongShape ((t, v) : rest)
      | shapeMatches t v = wrongShape rest
      | otherwise = Just t

-- ---------------------------------------------------------------------------
-- Template rules
-- ---------------------------------------------------------------------------

-- | One template rule: the class and key-type context plus the
-- required and forbidden @CKA_*@ names. Rules come from the generated
-- table ('generatedTemplateRules'); this type is the curated view.
data TemplateRule = TemplateRule
  { trClass :: !Text
  , trKeyType :: !(Maybe Text)
  , trRequired :: ![Text]
  , trForbidden :: ![Text]
  } deriving (Eq, Show)

-- | Why a template broke its rule: a required attribute is absent, or
-- a forbidden one is present. Names are the @CKA_*@ spellings from
-- the rule, so denials cite the rule exactly.
data RuleDeny
  = RuleMissingRequired !Text
  | RuleForbiddenPresent !Text
  deriving (Eq, Show)

-- | Find the rule for a @(class, key-type)@ context, if any. Contexts
-- without a rule carry no presence constraints beyond 'validateTemplate'.
findRule :: Text -> Text -> Maybe TemplateRule
findRule clsName keyName = listToMaybe
  [ TemplateRule c k req frb
  | (c, k, req, frb) <- generatedTemplateRules
  , c == clsName
  , k == Just keyName
  ]

-- | Enforce one rule against validated template attributes. Required
-- names that do not map into the 'AttributeType' inventory fail
-- closed (missing); forbidden names without a mapping cannot be
-- present in a model template, so they are vacuously satisfied.
checkRules :: TemplateRule -> Map AttributeType AttributeValue -> Either RuleDeny ()
checkRules rule attrs = do
  mapM_ require (trRequired rule)
  mapM_ forbid (trForbidden rule)
  where
    require :: Text -> Either RuleDeny ()
    require name = case attributeTypeByName name of
      Nothing -> Left (RuleMissingRequired name)
      Just t
        | Map.member t attrs -> Right ()
        | otherwise -> Left (RuleMissingRequired name)
    forbid :: Text -> Either RuleDeny ()
    forbid name = case attributeTypeByName name of
      Just t
        | Map.member t attrs -> Left (RuleForbiddenPresent name)
      _ -> Right ()

-- ---------------------------------------------------------------------------
-- Request-argument codecs (over reqInput)
-- ---------------------------------------------------------------------------

-- | Attribute-type tag: the 'Enum' order of 'AttributeType'.
attrTag :: AttributeType -> Word8
attrTag = fromIntegral . fromEnum

-- | Tag back to type; unknown tags fail.
tagAttr :: Word8 -> Maybe AttributeType
tagAttr w
  | w <= fromIntegral (fromEnum (maxBound :: AttributeType)) =
      Just (toEnum (fromIntegral w))
  | otherwise = Nothing

-- | Encode a template (order and duplicates preserved): each entry
-- is a tag byte, a 4-byte big-endian length, then the canonical
-- value bytes ('encodeValue').
encodeTemplate :: [(AttributeType, AttributeValue)] -> ByteString
encodeTemplate = BS.concat . map encodeEntry
  where
    encodeEntry :: (AttributeType, AttributeValue) -> ByteString
    encodeEntry (t, v) =
      let bs = encodeValue v
          len = BS.length bs
      in BS.pack
        [ attrTag t
        , fromIntegral (len `div` 16777216 `mod` 256)
        , fromIntegral (len `div` 65536 `mod` 256)
        , fromIntegral (len `div` 256 `mod` 256)
        , fromIntegral (len `mod` 256)
        ] <> bs

-- | Bound on entries per template (pinned single source of truth;
-- ConfigSpec pins the value through the FFI alias). The C packer
-- and the FFI frame decode enforce the same bound on native paths;
-- the core codec enforces it here so in-process planCall paths
-- (scenario, detached) cannot bypass it. @limits.attribute_entries@
-- does NOT drive this bound (reserved key, disclosed in the
-- capabilities report).
maxTemplateEntries :: Int
maxTemplateEntries = 64

-- | Decode a template; truncation, unknown tags, overruns,
-- cross-shape value bytes, and past-bound entry counts all fail.
-- Values decode against their owning type's shape, so a template
-- cannot smuggle a bool where a ULong belongs.
parseTemplate :: ByteString -> Maybe [(AttributeType, AttributeValue)]
parseTemplate = go 0
  where
    go :: Int -> ByteString -> Maybe [(AttributeType, AttributeValue)]
    go n bs
      | BS.null bs = Just []
      | n >= maxTemplateEntries = Nothing
      | BS.length bs < 5 = Nothing
      | otherwise = case BS.unpack (BS.take 5 bs) of
          [tag, b3, b2, b1, b0] ->
            let len = fromIntegral b3 * 16777216
                  + fromIntegral b2 * 65536
                  + fromIntegral b1 * 256
                  + fromIntegral b0
                rest = BS.drop 5 bs
            in if BS.length rest < len
              then Nothing
              else do
                t <- tagAttr tag
                let (valBs, more) = BS.splitAt len rest
                v <- decodeValue t valBs
                ((t, v) :) <$> go (n + 1) more
          _ -> Nothing

-- | Encode a wanted-attribute list as tag bytes.
encodeWanted :: [AttributeType] -> ByteString
encodeWanted = BS.pack . map attrTag

-- | Decode a wanted-attribute list; any unknown tag fails.
parseWanted :: ByteString -> Maybe [AttributeType]
parseWanted = mapM tagAttr . BS.unpack

-- ---------------------------------------------------------------------------
-- Handles and resolution
-- ---------------------------------------------------------------------------

-- | Canonical handle encoding: the handle number as an unsigned long.
encodeHandle :: ExternalHandle -> ByteString
encodeHandle (ExternalHandle n) = encodeValue (ValULong (fromIntegral n))

-- | Decode a handle; anything but 8-byte in-'Int'-range bytes
-- fails. The range guard is the platform-width check at the C
-- boundary: handles cross as 'Int'-backed words, while
-- the model representation stays full-width.
decodeHandle :: ByteString -> Maybe ExternalHandle
decodeHandle bs = case decodeValue AttrClass bs of
  Just (ValULong w)
    | w <= fromIntegral (maxBound :: Int) ->
        Just (ExternalHandle (fromIntegral w))
  _ -> Nothing

-- | Guarded resolution: the binding must exist, the object must
-- exist, and the binding generation must still match the object's.
-- Anything else is 'Nothing' (the caller maps it to
-- 'CKR_OBJECT_HANDLE_INVALID').
resolveHandle :: Model -> ExternalHandle -> Maybe ObjectState
resolveHandle m h = case Map.lookup h (mHandles m) of
  Nothing -> Nothing
  Just b -> case Map.lookup (hbObject b) (mObjects m) of
    Nothing -> Nothing
    Just ost
      | hbGeneration b == osGeneration ost -> Just ost
      | otherwise -> Nothing

-- | The object's token flag (absent or wrongly shaped = session object).
objectToken :: ObjectState -> Bool
objectToken ost = Map.lookup AttrToken (osAttrs ost) == Just (ValBool True)

-- | The object's private flag (absent or wrongly shaped = public).
objectPrivate :: ObjectState -> Bool
objectPrivate ost = Map.lookup AttrPrivate (osAttrs ost) == Just (ValBool True)

-- | Visibility per calling session: the object must live on the
-- session's slot, and private objects additionally need a
-- non-public login. Any authenticated login (user, SO,
-- context grant) sees same-slot private objects; finer roles arrive
-- with the operation tasks.
objectVisible :: SessionState -> ObjectState -> Bool
objectVisible st ost =
  ssSlot st == osSlot ost
    && (not (objectPrivate ost) || ssLogin st /= LoginPublic)

-- ---------------------------------------------------------------------------
-- Planning
-- ---------------------------------------------------------------------------

-- | Plan object creation: validate the template, derive key-import
-- material ('importMaterial'), then allocate the object id and handle
-- deterministically from the model counters. A failed template
-- leaves no partial object and no binding.
planCreateObject
  :: Model -> SessionState -> [(AttributeType, AttributeValue)] -> PlanResult
planCreateObject model st tmpl = case validateTemplate tmpl of
  Left (TemplateContradiction t) -> templateReject CKR_TEMPLATE_INCONSISTENT
    ("contradictory attribute: " ++ show t)
  Left (TemplateWrongType t) -> templateReject CKR_TEMPLATE_INCONSISTENT
    ("wrong shape for attribute: " ++ show t)
  Left TemplateIncomplete -> templateReject CKR_TEMPLATE_INCOMPLETE
    "template is missing the class"
  Right attrs
    | Just (ValULong c) <- Map.lookup AttrClass attrs
    , isNothing (classNameById c) ->
        templateReject CKR_TEMPLATE_INCONSISTENT
          ("unknown object class: " ++ show c)
    | otherwise -> case importMaterial attrs of
        Left (code, msg) -> templateReject code msg
        Right stored ->
          let oid = ObjectId (mNextObject model)
              h = ExternalHandle (mNextHandle model)
              owner
                | Map.lookup AttrToken stored == Just (ValBool True) = Nothing
                | otherwise = Just (ssId st)
          in Immediate PreparedCommit
            { pcCode = CKR_OK
            , pcDelta = StateDelta
                [ DeltaCreateObjectFull oid stored owner (ssSlot st)
                , DeltaBindHandle h oid
                ]
            , pcPersist = []
            , pcOutputs = [NativeOutput (RegionHandle "object") (encodeHandle h)]
            , pcReleases = []
            , pcReasons = ["created object " ++ show oid]
            }

ckoPrivateKey, ckoPublicKey, ckkRsa, ckkEc :: Word64
ckoPrivateKey = mustClassId "CKO_PRIVATE_KEY"
ckoPublicKey = mustClassId "CKO_PUBLIC_KEY"
ckkRsa = mustKeyTypeId "CKK_RSA"
ckkEc = mustKeyTypeId "CKK_EC"

-- | Key-import material: RSA/EC public/private templates carry
-- components, but the engine consumes PKCS#8/SPKI DER in 'AttrValue'
-- (the same shape key generation stores). For those four shapes,
-- require the complete component set ('CKR_TEMPLATE_INCOMPLETE'
-- when short), assemble the DER, and store it as the value
-- alongside the verbatim components. An explicit value next to
-- components contradicts (inconsistent), except the EC private
-- scalar, which arrives as the value and is consumed by the
-- assembly. Malformed parts refuse as inconsistent; foreign curves
-- refuse as 'CKR_CURVE_NOT_SUPPORTED'. Anything else stores
-- verbatim.
importMaterial
  :: Map AttributeType AttributeValue
  -> Either (ReturnCode, String) (Map AttributeType AttributeValue)
importMaterial attrs = case (classOf, keyTypeOf) of
  (Just c, Just k)
    | c == ckoPrivateKey && k == ckkRsa -> rsaPrivate
    | c == ckoPublicKey && k == ckkRsa -> rsaPublic
    | c == ckoPrivateKey && k == ckkEc -> ecPrivate
    | c == ckoPublicKey && k == ckkEc -> ecPublic
  _ -> Right attrs
  where
    classOf = case Map.lookup AttrClass attrs of
      Just (ValULong c) -> Just c
      _ -> Nothing
    keyTypeOf = case Map.lookup AttrKeyType attrs of
      Just (ValULong k) -> Just k
      _ -> Nothing
    need t = case Map.lookup t attrs of
      Just (ValBytes bs)
        | not (BS.null bs) -> Right bs
        | otherwise -> Left (CKR_TEMPLATE_INCONSISTENT,
            "empty component: " ++ show t)
      Just _ -> Left (CKR_TEMPLATE_INCONSISTENT,
        "wrong shape for component: " ++ show t)
      Nothing -> Left (CKR_TEMPLATE_INCOMPLETE,
        "missing component: " ++ show t)
    forbidValue
      | Map.member AttrValue attrs = Left (CKR_TEMPLATE_INCONSISTENT,
          "explicit value with key components")
      | otherwise = Right ()
    orReject rej = maybe (Left rej) Right
    rsaPrivate = do
      n <- need AttrModulus
      e <- need AttrPublicExponent
      d <- need AttrPrivateExponent
      p <- need AttrPrime1
      q <- need AttrPrime2
      dp <- need AttrExponent1
      dq <- need AttrExponent2
      qi <- need AttrCoefficient
      forbidValue
      pure (Map.insert AttrValue
        (ValBytes (rsaPrivateDer n e d p q dp dq qi)) attrs)
    rsaPublic = do
      n <- need AttrModulus
      e <- need AttrPublicExponent
      forbidValue
      pure (Map.insert AttrValue
        (ValBytes (rsaPublicDer n e)) attrs)
    ecPrivate = do
      params <- need AttrEcParams
      scalar <- need AttrValue
      (oid, coordLen) <- orReject
        (CKR_CURVE_NOT_SUPPORTED, "unsupported EC curve parameters")
        (resolveCurve params)
      scalar' <- orReject (CKR_TEMPLATE_INCONSISTENT,
          "EC scalar length does not match the curve")
        (checkScalar coordLen scalar)
      pure (Map.insert AttrValue
        (ValBytes (ecPrivateDer oid scalar')) attrs)
    ecPublic = do
      params <- need AttrEcParams
      point <- need AttrEcPoint
      (oid, coordLen) <- orReject
        (CKR_CURVE_NOT_SUPPORTED, "unsupported EC curve parameters")
        (resolveCurve params)
      raw <- orReject (CKR_TEMPLATE_INCONSISTENT,
          "EC_POINT is not a wrapped uncompressed point")
        (unwrapEcPoint coordLen point)
      forbidValue
      pure (Map.insert AttrValue
        (ValBytes (ecPublicDer oid raw)) attrs)
    resolveCurve params = do
      oid <- curveOidOfParams params
      n <- curveCoordLen oid
      pure (oid, n)
    checkScalar coordLen s
      | BS.null s = Nothing
      | BS.length s > coordLen = Nothing
      | otherwise = Just s

-- | Plan object destruction: the handle must resolve and the
-- object must be visible to the calling session, then one combined
-- delta removes the object and stale-marks its bindings.
planDestroyObject :: Model -> SessionState -> ExternalHandle -> PlanResult
planDestroyObject model st h = case resolveHandle model h of
  Nothing -> invalidHandle "unknown or destroyed object handle"
  Just ost
    | objectVisible st ost -> Immediate PreparedCommit
        { pcCode = CKR_OK
        , pcDelta = StateDelta [DeltaDestroyObject (osId ost)]
        , pcPersist = []
        , pcOutputs = []
        , pcReleases = []
        , pcReasons = ["destroyed object " ++ show (osId ost)]
        }
    | otherwise -> invalidHandle "object not visible to session"

-- | Plan object copy: the source handle must resolve and be
-- visible to the calling session, the override template must be
-- contradiction-free, and the merged attributes must still carry a
-- class. The copy gets a fresh id and handle; the source is
-- untouched. Seal ratchet: overrides that flip sensitive true->false
-- or extractable false->true are rejected ('CKR_TEMPLATE_INCONSISTENT');
-- sealed flags otherwise inherit, so a copy of a sealed object is
-- sealed too.
planCopyObject
  :: Model -> SessionState -> ExternalHandle -> [(AttributeType, AttributeValue)]
  -> PlanResult
planCopyObject model st h tmpl = case resolveHandle model h of
  Nothing -> invalidHandle "unknown or destroyed source handle"
  Just src ->
    if not (objectVisible st src)
      then invalidHandle "object not visible to session"
      else case checkDuplicates tmpl of
        Left t -> templateReject CKR_TEMPLATE_INCONSISTENT
          ("contradictory attribute: " ++ show t)
        Right over
          | Map.lookup AttrSensitive (osAttrs src) == Just (ValBool True)
          , Map.lookup AttrSensitive over == Just (ValBool False) ->
              templateReject CKR_TEMPLATE_INCONSISTENT
                "copy cannot clear the sensitive flag"
          | Map.lookup AttrExtractable (osAttrs src) == Just (ValBool False)
          , Map.lookup AttrExtractable over == Just (ValBool True) ->
              templateReject CKR_TEMPLATE_INCONSISTENT
                "copy cannot set extractable on an unextractable source"
          | otherwise ->
              let merged = Map.union over (osAttrs src)
              in if Map.member AttrClass merged
            then
              let oid = ObjectId (mNextObject model)
                  h2 = ExternalHandle (mNextHandle model)
                  owner
                    | Map.lookup AttrToken merged == Just (ValBool True) = Nothing
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

-- | Plan a one-shot find: matches carry equality over the stored
-- attributes in ascending object-id order, restricted to objects
-- visible to the calling session. An empty template matches every
-- visible object; a contradictory template is rejected, never
-- silently emptied. Matches without a current binding gain fresh
-- ones in the same combined delta (discovery mints bindings; it
-- never reuses a dead handle). Sealed payloads never match on
-- 'AttrValue': a template naming the value only matches unsealed
-- objects, so find cannot serve as a guess-oracle against a sealed
-- payload (sealed objects stay discoverable by their other
-- attributes).
planFindObjects
  :: Model -> SessionState -> [(AttributeType, AttributeValue)] -> PlanResult
planFindObjects model st tmpl = case checkDuplicates tmpl of
  Left t -> templateReject CKR_TEMPLATE_INCONSISTENT
    ("contradictory attribute: " ++ show t)
  Right q ->
    let matches =
          [ (oid, ost)
          | (oid, ost) <- Map.toAscList (mObjects model)
          , matchAll q ost
          , objectVisible st ost
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
        hit (AttrValue, _)
          | payloadSealed (osAttrs ost) = False
        hit (t, v) = Map.lookup t (osAttrs ost) == Just v
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
        in ( DeltaBindHandle h oid : binds
           , NativeOutput (RegionHandle "object") (encodeHandle h) : outs
           )

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
    let PartialReads code results = getAttributes (osAttrs ost) wanted
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
        }
  where
    statusOf :: AttributeResult -> String
    statusOf r = case r of
      ResOk _ -> "ok"
      ResSensitive -> "sensitive"
      ResUnavailable -> "unavailable"

-- | A template rejection: no outputs, no delta, no partial object.
templateReject :: ReturnCode -> String -> PlanResult
templateReject code why = Reject Rejection
  { rejCode = code
  , rejOutputs = []
  , rejDelta = StateDelta []
  , rejReleases = []
  , rejReasons = [why]
  }

-- | An unresolvable-handle rejection.
invalidHandle :: String -> PlanResult
invalidHandle why = Reject Rejection
  { rejCode = CKR_OBJECT_HANDLE_INVALID
  , rejOutputs = []
  , rejDelta = StateDelta []
  , rejReleases = []
  , rejReasons = [why]
  }
