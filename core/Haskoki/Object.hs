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
  , objectCopyable
  , objectDestroyable
  , objectVisible
  , planCreateObject
  , planDestroyObject
  , planCopyObject
  , planSetAttributes
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
  (curveCoordLen, curveOidOfParams, dhPrivateDer, dhPrivateDerQ, dhPublicDer, dhPublicDerQ, dhSpkiFields, dsaPrivateDer, dsaPublicDer, dsaSpkiFields,
   ecPrivateDer, ecPublicDer, eddsaPrivateDer, eddsaPublicDer,
   edwardsOidOfParams, edwardsWidthsOfParams, mldsaOidOfCkp,
   mldsaPrivateDer, mldsaPublicDer, mldsaWidthsOfOid,
   slhdsaOidOfCkp, slhdsaPrivateDer, slhdsaPublicDer,
   slhdsaWidthsOfOid,
   mlkemEkWellFormed, mlkemOidOfCkp,
   mlkemPrivateDer, mlkemPublicDer, mlkemWidthsOfOid,
   rsaPrivateDer, rsaPublicDer,
   unwrapEcPoint, unwrapEdwardsPoint)
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
import Haskoki.Session (SessionLogin (LoginPublic), admitCode, admitPrivate, admitWritable)
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

-- | Token-owner test over merged/stored attributes (absent or
-- wrongly shaped = session object). Single predicate behind the
-- owner derivation and the read-only writability checks.
mergedIsToken :: Map AttributeType AttributeValue -> Bool
mergedIsToken m = Map.lookup AttrToken m == Just (ValBool True)

-- | Token-owner test over a raw template list (first match wins;
-- duplicates are rejected downstream by template validation).
tmplWantsToken :: [(AttributeType, AttributeValue)] -> Bool
tmplWantsToken tmpl = lookup AttrToken tmpl == Just (ValBool True)

-- | Privacy test over merged/stored attributes (absent or wrongly
-- shaped = public).
mergedIsPrivate :: Map AttributeType AttributeValue -> Bool
mergedIsPrivate m = Map.lookup AttrPrivate m == Just (ValBool True)

-- | Privacy test over a raw template list (first match wins).
tmplWantsPrivate :: [(AttributeType, AttributeValue)] -> Bool
tmplWantsPrivate tmpl = lookup AttrPrivate tmpl == Just (ValBool True)

-- | Secret-key CKA_VALUE_LEN must match the value length. A huge
-- LEN over a short value is inconsistent (and must never become an
-- allocation); the copy path checks the merged template.
valueLenConflict :: Map AttributeType AttributeValue -> Maybe String
valueLenConflict m =
  case (Map.lookup AttrClass m, Map.lookup AttrValueLen m, Map.lookup AttrValue m) of
    (Just (ValULong c), Just (ValULong want), Just (ValBytes bs))
      | c == ckoSecretKey, want /= fromIntegral (BS.length bs) ->
          Just "CKA_VALUE_LEN does not match the value length"
    _ -> Nothing

-- | Whether the object may be copied (absent = copyable, per the
-- PKCS#11 default; only an explicit false prohibits).
objectCopyable :: ObjectState -> Bool
objectCopyable ost = Map.lookup AttrCopyable (osAttrs ost) /= Just (ValBool False)

-- | Whether the object may be destroyed (absent = destroyable;
-- only an explicit false prohibits).
objectDestroyable :: ObjectState -> Bool
objectDestroyable ost = Map.lookup AttrDestroyable (osAttrs ost) /= Just (ValBool False)

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
        Right stored
          | Left deny <- admitPrivate (ssLogin st) (mergedIsPrivate stored) ->
              templateReject (admitCode deny)
                "public session cannot create private objects"
          | Left deny <- admitWritable (ssReadOnly st) (mergedIsToken stored) ->
              templateReject (admitCode deny)
                "read-only session cannot create token objects"
          | otherwise ->
          let oid = ObjectId (mNextObject model)
              h = ExternalHandle (mNextHandle model)
              owner
                | mergedIsToken stored = Nothing
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

ckoPrivateKey, ckoPublicKey, ckoSecretKey, ckkRsa, ckkEc, ckkAes :: Word64
ckoPrivateKey = mustClassId "CKO_PRIVATE_KEY"
ckoPublicKey = mustClassId "CKO_PUBLIC_KEY"
ckoSecretKey = mustClassId "CKO_SECRET_KEY"
ckkRsa = mustKeyTypeId "CKK_RSA"
ckkEc = mustKeyTypeId "CKK_EC"
ckkDsa = mustKeyTypeId "CKK_DSA"
ckkDh = mustKeyTypeId "CKK_DH"
ckkX9_42Dh = mustKeyTypeId "CKK_X9_42_DH"
ckkEcEdwards = mustKeyTypeId "CKK_EC_EDWARDS"
ckkMlDsa = mustKeyTypeId "CKK_ML_DSA"
ckkSlhDsa = mustKeyTypeId "CKK_SLH_DSA"
ckkMlKem = mustKeyTypeId "CKK_ML_KEM"
ckkAes = mustKeyTypeId "CKK_AES"

-- | Key-import material: RSA/EC public/private templates carry
-- components, but the engine consumes PKCS#8/SPKI DER in 'AttrValue'
-- (the same shape key generation stores). For those shapes,
-- require the complete component set ('CKR_TEMPLATE_INCOMPLETE'
-- when short), assemble the DER, and store it as the value
-- alongside the verbatim components. An explicit value next to
-- components contradicts (inconsistent), except the EC private
-- scalar, which arrives as the value and is consumed by the
-- assembly. Malformed parts refuse as inconsistent; foreign curves
-- refuse as 'CKR_CURVE_NOT_SUPPORTED'. ML-DSA halves assemble
-- from the parameter set plus the raw key value (the public
-- value, the private expanded key); a seed-only private
-- template refuses — the pinned provider cannot expand a lone
-- seed. DH halves assemble from prime/base plus the raw value
-- (the public y, the private x); X9.42 additionally requires
-- the subprime while a PKCS#3 template carrying one refuses
-- inconsistent. SLH-DSA halves assemble the same way (the public
-- value, the private 4n secret). Secret keys require the
-- value, cohere it with an explicit value length, restrict AES to
-- its fixed lengths, and stamp a derived value length when the
-- caller omits it. Anything else stores verbatim.
importMaterial
  :: Map AttributeType AttributeValue
  -> Either (ReturnCode, String) (Map AttributeType AttributeValue)
importMaterial attrs = case (classOf, keyTypeOf) of
  (Just c, Just k)
    | c == ckoPrivateKey && k == ckkRsa -> rsaPrivate
    | c == ckoPublicKey && k == ckkRsa -> rsaPublic
    | c == ckoPrivateKey && k == ckkEc -> ecPrivate
    | c == ckoPublicKey && k == ckkEc -> ecPublic
    | c == ckoPrivateKey && k == ckkDsa -> dsaPrivate
    | c == ckoPublicKey && k == ckkDsa -> dsaPublic
    | c == ckoPrivateKey && (k == ckkDh || k == ckkX9_42Dh) -> dhPrivate k
    | c == ckoPublicKey && (k == ckkDh || k == ckkX9_42Dh) -> dhPublic k
    | c == ckoPrivateKey && k == ckkEcEdwards -> eddsaPrivate
    | c == ckoPublicKey && k == ckkEcEdwards -> eddsaPublic
    | c == ckoPrivateKey && k == ckkMlDsa -> mldsaPrivate
    | c == ckoPublicKey && k == ckkMlDsa -> mldsaPublic
    | c == ckoPrivateKey && k == ckkSlhDsa -> slhdsaPrivate
    | c == ckoPublicKey && k == ckkSlhDsa -> slhdsaPublic
    | c == ckoPrivateKey && k == ckkMlKem -> mlkemPrivate
    | c == ckoPublicKey && k == ckkMlKem -> mlkemPublic
    | c == ckoSecretKey -> secretKey k
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
    dsaPrivate = do
      p <- need AttrPrime
      q <- need AttrSubprime
      g <- need AttrBase
      x <- need AttrValue
      pure (Map.insert AttrValue
        (ValBytes (dsaPrivateDer p q g x)) attrs)
    dsaPublic = do
      p <- need AttrPrime
      q <- need AttrSubprime
      g <- need AttrBase
      y <- need AttrValue
      pure (Map.insert AttrValue
        (ValBytes (dsaPublicDer p q g y)) attrs)
    dhPrivate k = do
      p <- need AttrPrime
      g <- need AttrBase
      x <- need AttrValue
      assemble k p g x
    dhPublic k = do
      p <- need AttrPrime
      g <- need AttrBase
      y <- need AttrValue
      assemble k p g y
    assemble k p g v
      | k == ckkX9_42Dh = do
          q <- need AttrSubprime
          pure (Map.insert AttrValue
            (ValBytes (if isPriv then dhPrivateDerQ p g q v else dhPublicDerQ p g q v)) attrs)
      | Map.member AttrSubprime attrs =
          Left (CKR_TEMPLATE_INCONSISTENT, "PKCS#3 DH takes no subprime")
      | otherwise =
          Right (Map.insert AttrValue
            (ValBytes (if isPriv then dhPrivateDer p g v else dhPublicDer p g v)) attrs)
      where isPriv = classOf == Just ckoPrivateKey
    eddsaPrivate = do
      params <- need AttrEcParams
      seed <- need AttrValue
      (oid, seedW, _) <- orReject
        (CKR_CURVE_NOT_SUPPORTED, "unsupported Edwards curve parameters")
        (resolveEdwards params)
      seed' <- orReject (CKR_TEMPLATE_INCONSISTENT,
          "EdDSA seed length does not match the curve")
        (checkExact seedW seed)
      pure (Map.insert AttrValue
        (ValBytes (eddsaPrivateDer oid seed')) attrs)
    eddsaPublic = do
      params <- need AttrEcParams
      point <- need AttrEcPoint
      (oid, seedW, _) <- orReject
        (CKR_CURVE_NOT_SUPPORTED, "unsupported Edwards curve parameters")
        (resolveEdwards params)
      raw <- orReject (CKR_TEMPLATE_INCONSISTENT,
          "EC_POINT is not a raw or wrapped Edwards point")
        (unwrapEdwardsPoint seedW point)
      forbidValue
      pure (Map.insert AttrValue
        (ValBytes (eddsaPublicDer oid raw)) attrs)
    resolveEdwards params = do
      oid <- edwardsOidOfParams params
      (seedW, sigW) <- edwardsWidthsOfParams oid
      pure (oid, seedW, sigW)
    mldsaPrivate = do
      (oid, _, privW, _) <- needMldsaSet
      expanded <- case Map.lookup AttrValue attrs of
        Just (ValBytes bs)
          | not (BS.null bs) -> orReject (CKR_TEMPLATE_INCONSISTENT,
              "ML-DSA private value length does not match the parameter set")
              (checkExact privW bs)
          | otherwise -> Left (CKR_TEMPLATE_INCONSISTENT,
              "empty component: AttrValue")
        Just _ -> Left (CKR_TEMPLATE_INCONSISTENT,
          "wrong shape for component: AttrValue")
        Nothing
          | Map.member AttrSeed attrs -> Left (CKR_TEMPLATE_INCONSISTENT,
              "seed-only ML-DSA import is unsupported: supply CKA_VALUE (the expanded private key)")
          | otherwise -> Left (CKR_TEMPLATE_INCOMPLETE,
              "missing component: AttrValue")
      pure (Map.insert AttrValue
        (ValBytes (mldsaPrivateDer oid expanded)) attrs)
    mldsaPublic = do
      (oid, pubW, _, _) <- needMldsaSet
      raw <- need AttrValue
      raw' <- orReject (CKR_TEMPLATE_INCONSISTENT,
          "ML-DSA public value length does not match the parameter set")
        (checkExact pubW raw)
      pure (Map.insert AttrValue
        (ValBytes (mldsaPublicDer oid raw')) attrs)
    needMldsaSet = case Map.lookup AttrParameterSet attrs of
      Just (ValULong n) -> orReject (CKR_TEMPLATE_INCONSISTENT,
          "unknown ML-DSA parameter set: " ++ show n)
        (resolveMldsaSet n)
      Just _ -> Left (CKR_TEMPLATE_INCONSISTENT,
        "wrong shape for component: AttrParameterSet")
      Nothing -> Left (CKR_TEMPLATE_INCOMPLETE,
        "missing component: AttrParameterSet")
    resolveMldsaSet n = do
      oid <- mldsaOidOfCkp (fromIntegral n)
      (pubW, privW, sigW) <- mldsaWidthsOfOid oid
      pure (oid, pubW, privW, sigW)
    slhdsaPrivate = do
      (oid, _, privW, _) <- needSlhdsaSet
      raw <- case Map.lookup AttrValue attrs of
        Just (ValBytes bs)
          | not (BS.null bs) -> orReject (CKR_TEMPLATE_INCONSISTENT,
              "SLH-DSA private value length does not match the parameter set")
              (checkExact privW bs)
          | otherwise -> Left (CKR_TEMPLATE_INCONSISTENT,
              "empty component: AttrValue")
        Just _ -> Left (CKR_TEMPLATE_INCONSISTENT,
          "wrong shape for component: AttrValue")
        Nothing
          | Map.member AttrSeed attrs -> Left (CKR_TEMPLATE_INCONSISTENT,
              "seed-only SLH-DSA import is unsupported: supply CKA_VALUE (the 4n secret)")
          | otherwise -> Left (CKR_TEMPLATE_INCOMPLETE,
              "missing component: AttrValue")
      pure (Map.insert AttrValue
        (ValBytes (slhdsaPrivateDer oid raw)) attrs)
    slhdsaPublic = do
      (oid, pubW, _, _) <- needSlhdsaSet
      raw <- need AttrValue
      raw' <- orReject (CKR_TEMPLATE_INCONSISTENT,
          "SLH-DSA public value length does not match the parameter set")
        (checkExact pubW raw)
      pure (Map.insert AttrValue
        (ValBytes (slhdsaPublicDer oid raw')) attrs)
    needSlhdsaSet = case Map.lookup AttrParameterSet attrs of
      Just (ValULong n) -> orReject (CKR_TEMPLATE_INCONSISTENT,
          "unknown SLH-DSA parameter set: " ++ show n)
        (resolveSlhdsaSet n)
      Just _ -> Left (CKR_TEMPLATE_INCONSISTENT,
        "wrong shape for component: AttrParameterSet")
      Nothing -> Left (CKR_TEMPLATE_INCOMPLETE,
        "missing component: AttrParameterSet")
    resolveSlhdsaSet n = do
      oid <- slhdsaOidOfCkp (fromIntegral n)
      (pubW, privW, sigW) <- slhdsaWidthsOfOid oid
      pure (oid, pubW, privW, sigW)
    mlkemPrivate = do
      (oid, _, dkW, _, alg) <- needMlkemSet
      dk <- case Map.lookup AttrValue attrs of
        Just (ValBytes bs)
          | not (BS.null bs) -> orReject (CKR_TEMPLATE_INCONSISTENT,
              "ML-KEM private value length does not match the parameter set")
              (checkExact dkW bs)
          | otherwise -> Left (CKR_TEMPLATE_INCONSISTENT,
              "empty component: AttrValue")
        Just _ -> Left (CKR_TEMPLATE_INCONSISTENT,
          "wrong shape for component: AttrValue")
        Nothing -> Left (CKR_TEMPLATE_INCOMPLETE,
          "missing component: AttrValue")
      -- The provider accepts seed+dk (its own SEQ form) but
      -- refuses flat-dk PKCS#8, so dk-only import stores the
      -- raw dk verbatim (the backend loads it via fromdata)
      -- while seed+dk assembles the provider form.
      stored <- case Map.lookup AttrSeed attrs of
        Just (ValBytes seed)
          | BS.length seed == 64 ->
              pure (mlkemPrivateDer oid seed dk)
          | otherwise -> Left (CKR_TEMPLATE_INCONSISTENT,
              "ML-KEM seed length is not 64 bytes (d || z)")
        Just _ -> Left (CKR_TEMPLATE_INCONSISTENT,
          "wrong shape for component: AttrSeed")
        Nothing -> pure dk
      pure (Map.insert AttrKemAlg (ValULong (fromIntegral alg))
        (Map.insert AttrValue (ValBytes stored) attrs))
    mlkemPublic = do
      (oid, ekW, _, _, alg) <- needMlkemSet
      ek <- need AttrValue
      ek' <- orReject (CKR_TEMPLATE_INCONSISTENT,
          "ML-KEM public value length does not match the parameter set")
        (checkExact ekW ek)
      -- FIPS 203 §7.2 modulus check at import time: a
      -- non-canonical ek is a malformed CKA_VALUE
      -- (CKR_ATTRIBUTE_VALUE_INVALID, the spec-correct code),
      -- never a key the backend would touch.
      if mlkemEkWellFormed oid ek'
        then pure (Map.insert AttrKemAlg (ValULong (fromIntegral alg))
          (Map.insert AttrValue
            (ValBytes (mlkemPublicDer oid ek')) attrs))
        else Left (CKR_ATTRIBUTE_VALUE_INVALID,
          "ML-KEM public value is not a canonical encapsulation key")
    needMlkemSet = case Map.lookup AttrParameterSet attrs of
      Just (ValULong n) -> orReject (CKR_TEMPLATE_INCONSISTENT,
          "unknown ML-KEM parameter set: " ++ show n)
        (resolveMlkemSet n)
      Just _ -> Left (CKR_TEMPLATE_INCONSISTENT,
        "wrong shape for component: AttrParameterSet")
      Nothing -> Left (CKR_TEMPLATE_INCOMPLETE,
        "missing component: AttrParameterSet")
    resolveMlkemSet n = do
      oid <- mlkemOidOfCkp (fromIntegral n)
      (ekW, dkW, ctW) <- mlkemWidthsOfOid oid
      alg <- case (fromIntegral n :: Int) of
        1 -> Just 512
        2 -> Just 768
        3 -> Just 1024
        _ -> Nothing
      pure (oid, ekW, dkW, ctW, alg)
    checkExact w s
      | BS.length s == w = Just s
      | otherwise = Nothing
    resolveCurve params = do
      oid <- curveOidOfParams params
      n <- curveCoordLen oid
      pure (oid, n)
    checkScalar coordLen s
      | BS.null s = Nothing
      | BS.length s > coordLen = Nothing
      | otherwise = Just s
    secretKey k = do
      bytes <- needValue
      let n = fromIntegral (BS.length bytes) :: Word64
      case Map.lookup AttrValueLen attrs of
        Just (ValULong want)
          | want /= n -> Left (CKR_TEMPLATE_INCONSISTENT,
              "CKA_VALUE_LEN does not match the value length")
          | otherwise -> checkAes k n
        Just _ -> Left (CKR_TEMPLATE_INCONSISTENT,
          "wrong shape for attribute: AttrValueLen")
        Nothing
          | k == ckkAes && n `notElem` [16, 24, 32] ->
              Left (CKR_ATTRIBUTE_VALUE_INVALID,
                "AES key value must be 16, 24, or 32 bytes")
          | otherwise -> Right (Map.insert AttrValueLen (ValULong n) attrs)
    checkAes k n
      | k == ckkAes && n `notElem` [16, 24, 32] =
          Left (CKR_ATTRIBUTE_VALUE_INVALID,
            "AES key value must be 16, 24, or 32 bytes")
      | otherwise = Right attrs
    needValue = case Map.lookup AttrValue attrs of
      Just (ValBytes bs) -> Right bs
      Just _ -> Left (CKR_TEMPLATE_INCONSISTENT,
        "wrong shape for attribute: AttrValue")
      Nothing -> Left (CKR_TEMPLATE_INCOMPLETE,
        "missing component: AttrValue")

-- | Plan object destruction: the handle must resolve and the
-- object must be visible to the calling session, then one combined
-- delta removes the object and stale-marks its bindings. An
-- explicit @CKA_DESTROYABLE=false@ prohibits the destroy
-- ('CKR_ACTION_PROHIBITED').
planDestroyObject :: Model -> SessionState -> ExternalHandle -> PlanResult
planDestroyObject model st h = case resolveHandle model h of
  Nothing -> invalidHandle "unknown or destroyed object handle"
  Just ost
    | not (objectVisible st ost) ->
        invalidHandle "object not visible to session"
    | not (objectDestroyable ost) ->
        templateReject CKR_ACTION_PROHIBITED
          "object is not destroyable (CKA_DESTROYABLE=false)"
    | Left deny <- admitWritable (ssReadOnly st) (objectToken ost) ->
        templateReject (admitCode deny)
          "read-only session cannot destroy token objects"
    | otherwise -> Immediate PreparedCommit
        { pcCode = CKR_OK
        , pcDelta = StateDelta [DeltaDestroyObject (osId ost)]
        , pcPersist = []
        , pcOutputs = []
        , pcReleases = []
        , pcReasons = ["destroyed object " ++ show (osId ost)]
        }

-- | Plan object copy: the source handle must resolve and be
-- visible to the calling session, the override template must be
-- contradiction-free, and the merged attributes must still carry a
-- class. The copy gets a fresh id and handle; the source is
-- untouched. Seal ratchet: overrides that flip sensitive true->false
-- or extractable false->true are rejected ('CKR_TEMPLATE_INCONSISTENT');
-- sealed flags otherwise inherit, so a copy of a sealed object is
-- sealed too. An explicit @CKA_COPYABLE=false@ on the source
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
        Right over
          | Map.lookup AttrSensitive (osAttrs src) == Just (ValBool True)
          , Map.lookup AttrSensitive over == Just (ValBool False) ->
              templateReject CKR_TEMPLATE_INCONSISTENT
                "copy cannot clear the sensitive flag"
          | Map.lookup AttrExtractable (osAttrs src) == Just (ValBool False)
          , Map.lookup AttrExtractable over == Just (ValBool True) ->
              templateReject CKR_TEMPLATE_INCONSISTENT
                "copy cannot set extractable on an unextractable source"
          | Just msg <- valueLenConflict (Map.union over (osAttrs src)) ->
              templateReject CKR_TEMPLATE_INCONSISTENT msg
          | Left deny <- admitPrivate (ssLogin st)
              (mergedIsPrivate (Map.union over (osAttrs src))) ->
              templateReject (admitCode deny)
                "public session cannot copy to private objects"
          | Left deny <- admitWritable (ssReadOnly st)
              (mergedIsToken (Map.union over (osAttrs src))) ->
              templateReject (admitCode deny)
                "read-only session cannot copy to token objects"
          | otherwise ->
              let merged = Map.union over (osAttrs src)
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
-- delta applies all entries or none.
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
          "public session cannot mark objects private"
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
          Nothing -> case firstRefusal (osAttrs ost) (Map.toList over) of
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
    wrongShape [] = Nothing
    wrongShape ((t, v) : rest)
      | shapeMatches t v = wrongShape rest
      | otherwise = Just t
    firstRefusal _ [] = Nothing
    firstRefusal cur ((t, v) : rest) = case mutableAs cur t v of
      Just refusal -> Just refusal
      Nothing -> firstRefusal cur rest
    -- Nothing = mutable, Just = refusal. Absent flags read as
    -- false (the PKCS#11 defaults), so a no-op write to an absent
    -- flag succeeds while a ratchet flip refuses.
    mutableAs :: Map AttributeType AttributeValue
      -> AttributeType -> AttributeValue -> Maybe (ReturnCode, String)
    mutableAs cur t v
      | Map.lookup AttrModifiable cur == Just (ValBool False)
      , Map.lookup t cur /= Just v = Just (CKR_ATTRIBUTE_READ_ONLY,
          "object is not modifiable (CKA_MODIFIABLE=false)")
      | t `elem` [AttrLabel, AttrApplication, AttrId] = Nothing
      | t `elem` [ AttrEncrypt, AttrDecrypt, AttrSign, AttrVerify
                 , AttrSignRecover, AttrVerifyRecover
                 , AttrWrap, AttrUnwrap, AttrDerive
                 , AttrEncapsulate, AttrDecapsulate ] = Nothing
      | t == AttrToken = ratchet cur AttrToken True
          "CKA_TOKEN can only change false->true"
      | t == AttrExtractable = ratchet cur AttrExtractable False
          "CKA_EXTRACTABLE can only change true->false"
      | t == AttrSensitive = ratchet cur AttrSensitive True
          "CKA_SENSITIVE can only change false->true"
      | t == AttrCopyable = ratchet cur AttrCopyable False
          "CKA_COPYABLE can only change true->false"
      | t == AttrDestroyable = ratchet cur AttrDestroyable False
          "CKA_DESTROYABLE can only change true->false"
      | otherwise = Just (CKR_ATTRIBUTE_READ_ONLY,
          "attribute is not modifiable: " ++ show t)
      where
        ratchet curMap flag allowTrue msg = case (curVal, v) of
          (ValBool c, ValBool n)
            | c == n -> Nothing
            | n == allowTrue -> Nothing
            | otherwise -> Just (CKR_ATTRIBUTE_READ_ONLY, msg)
          _ -> Just (CKR_ATTRIBUTE_READ_ONLY, msg)
          where curVal = Map.findWithDefault (ValBool False) flag curMap

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
-- | Public-component projection for reads: 'AttrValue' stores
-- the SPKI DER (the engine's material shape), but PKCS#11 reads
-- the DSA/DH public value @y@ through @CKA_VALUE@ — so a public
-- DSA/DH object whose value parses as an SPKI reads @y@ instead
-- of the DER. Anything else (private halves, secrets, opaque
-- synthetic values, unparseable DER) passes through untouched;
-- sealing still applies to the projected read (the projection
-- runs before 'getAttributes', so a sealed flag redacts @y@
-- exactly like the stored value).
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

planGetAttributes
  :: Model -> SessionState -> ExternalHandle -> [AttributeType] -> PlanResult
planGetAttributes model st h wanted = case resolveHandle model h of
  Nothing -> invalidHandle "unknown or destroyed object handle"
  Just ost
    | not (objectVisible st ost) ->
        invalidHandle "object not visible to session"
    | otherwise ->
    let PartialReads code results = getAttributes (projectPublicValue (osAttrs ost)) wanted
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
