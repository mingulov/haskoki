{- | Object creation planning.
-}
{-# LANGUAGE OverloadedStrings #-}
module Haskoki.Object.PlanCreate
  ( planCreateObject
  ) where

import Data.Bits (countLeadingZeros)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.List (find)
import Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map
import Data.Maybe (isNothing)
import Data.Word (Word64)
import Haskoki.Attribute
  ( AttributeType (..)
  , AttributeValue (..)
  , historyAttrs
  , stampKeyDefaults
  )
import Haskoki.Attribute.Generated
  ( classNameById)
import Haskoki.Der
  ( curveCoordLen, curveOidOfParams, curveOrderOfOid, dhPrivateDer, dhPrivateDerQ, dhPublicDer, dhPublicDerQ, dsaPrivateDer, dsaPublicDer,
   ecPrivateDer, ecPublicDer, eddsaPrivateDer, eddsaPublicDer,
   edwardsOidOfParams, edwardsWidthsOfParams, mldsaOidOfCkp,
   montgomeryOidOfParams, montgomeryPrivateDer, montgomeryPublicDer,
   montgomeryWidthOfParams, unwrapMontgomeryPoint,
   mldsaPrivateDer, mldsaPublicDer, mldsaWidthsOfOid,
   slhdsaOidOfCkp, slhdsaPrivateDer, slhdsaPublicDer,
   slhdsaWidthsOfOid,
   mlkemEkWellFormed, mlkemOidOfCkp,
   mlkemPrivateDer, mlkemPublicDer, mlkemWidthsOfOid,
   rsaPrivateDer, rsaPublicDer,
   unwrapEcPoint, unwrapEdwardsPoint)
import Haskoki.Model
  ( Model (..)
  , SessionState (..)
  )
import Haskoki.Outcome
  ( DeltaOp (..)
  , NativeOutput (..)
  , PlanResult (..)
  , PreparedCommit (..)
  , StateDelta (..)
  )
import Haskoki.Request (OutputRegion (..))
import Haskoki.Session (SessionLogin (LoginSO), admitCode, admitPrivate, admitWritable)
import Haskoki.Types
  ( ExternalHandle (..)
  , ObjectId (..)
  , ReturnCode (..)
  )
import Haskoki.Object.Handles
import Haskoki.Object.PlanCerts
import Haskoki.Object.PlanReject
import Haskoki.Object.StorageAttrs
import Haskoki.Object.TemplateValidation

-- | Stamp one imported key: the caller-wins protection defaults
-- plus import history. Imported material was exposed outside the
-- token, so history and origin read false (secret and private
-- keys take false history rows; public keys take the origin pair
-- and own no history rows). Non-key classes pass through
-- unchanged. Runs after 'importMaterial', before admission.
stampCreatedKey :: Map AttributeType AttributeValue -> Map AttributeType AttributeValue
stampCreatedKey attrs = case Map.lookup AttrClass attrs of
  Just (ValULong c)
    | c == ckoPublicKey ->
        Map.insert AttrKeyGenMechanism (ValULong maxBound)
          (Map.insert AttrLocal (ValBool False) (stampKeyDefaults c attrs))
    | c == ckoPrivateKey || c == ckoSecretKey ->
        Map.insert AttrKeyGenMechanism (ValULong maxBound)
          (Map.insert AttrLocal (ValBool False)
            (Map.insert AttrNeverExtractable (ValBool False)
              (Map.insert AttrAlwaysSensitive (ValBool False) (stampKeyDefaults c attrs))))
  _ -> attrs

-- | Plan object creation: validate the template, derive key-import
-- material ('importMaterial'), stamp creation history on keys,
-- then allocate the object id and handle deterministically from
-- the model counters. A failed template leaves no partial object
-- and no binding.
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
    | Just t <- find (`elem` historyAttrs) (Map.keys attrs) ->
        templateReject CKR_TEMPLATE_INCONSISTENT
          ("history attribute not allowed in creation template: " ++ show t)
    | otherwise -> case checkCertificateDates attrs of
    Left e -> templateReject CKR_TEMPLATE_INCONSISTENT
      ("certificate date: " ++ show e)
    Right () -> case checkCertificateTemplate attrs of
      Left TemplateIncomplete -> templateReject CKR_TEMPLATE_INCOMPLETE
        "x509 certificate template requires certificate type, value and subject"
      Left e -> templateReject CKR_TEMPLATE_INCONSISTENT
        ("certificate template: " ++ show e)
      Right ()
        | Just (ValULong c) <- Map.lookup AttrClass attrs
        , isNothing (classNameById c) ->
            templateReject CKR_TEMPLATE_INCONSISTENT
              ("unknown object class: " ++ show c)
        | otherwise -> case importMaterial attrs of
            Left (code, msg) -> templateReject code msg
            Right stored0
              | Left deny <- admitPrivate (ssLogin st) (mergedIsPrivate stored) ->
                  templateReject (admitCode deny)
                    "only the normal user may create private objects"
              | Left deny <- admitWritable (ssReadOnly st) (mergedIsToken stored) ->
                  templateReject (admitCode deny)
                    "read-only session cannot create token objects"
              | Map.lookup AttrTrusted stored == Just (ValBool True)
              , ssLogin st /= LoginSO ->
                  templateReject CKR_ATTRIBUTE_READ_ONLY
                    "only the security officer may create TRUSTED=true objects"
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
              where
                stored = stampCreatedKey stored0


-- | Key-import material: RSA/EC public/private templates carry
-- components, but the engine consumes PKCS#8/SPKI DER in 'AttrValue'
-- (the same shape key generation stores). For those shapes,
-- require the complete component set ('CKR_TEMPLATE_INCOMPLETE'
-- when short), assemble the DER, and store it as the value
-- alongside the verbatim components. An RSA public import
-- additionally stamps the authoritative @CKA_MODULUS_BITS@ (the
-- true bit width of the modulus, overwriting any supplied size);
-- the private half carries no size, per PKCS#11 3.2 section 6.1.
-- An explicit value next to
-- components contradicts (inconsistent), except the EC private
-- scalar, which arrives as the value and is consumed by the
-- assembly. Malformed parts refuse as inconsistent; foreign curves
-- refuse as 'CKR_CURVE_NOT_SUPPORTED'. ML-DSA halves assemble
-- from the parameter set plus the raw key value (the public
-- value, the private expanded key); a seed-only private
-- template refuses -- haskoki requires the expanded value (the
-- provider documents seed expansion, but the template gate
-- rejects before the provider is reached). DH halves assemble
-- from prime/base plus the raw value
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
  ( Just c, Just k)
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
    | c == ckoPrivateKey && k == ckkEcMontgomery -> xdhPrivate
    | c == ckoPublicKey && k == ckkEcMontgomery -> xdhPublic
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
      pure (Map.insert AttrModulusBits (ValULong (fromIntegral (bitsOf n)))
        (Map.insert AttrValue
          (ValBytes (rsaPublicDer n e)) attrs))
    ecPrivate = do
      params <- need AttrEcParams
      scalar <- need AttrValue
      (oid, _, orderBytes) <- orReject
        (CKR_CURVE_NOT_SUPPORTED, "unsupported EC curve parameters")
        (resolveCurve params)
      scalar' <- orReject (CKR_TEMPLATE_INCONSISTENT,
          "EC scalar length does not match the curve")
        (checkScalar orderBytes scalar)
      pure (Map.insert AttrValue
        (ValBytes (ecPrivateDer oid scalar')) attrs)
    ecPublic = do
      params <- need AttrEcParams
      point <- need AttrEcPoint
      (oid, coordLen, _) <- orReject
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
    xdhPrivate = do
      params <- need AttrEcParams
      scalar <- need AttrValue
      (oid, w) <- orReject
        (CKR_CURVE_NOT_SUPPORTED, "unsupported Montgomery curve parameters")
        (resolveMontgomery params)
      scalar' <- orReject (CKR_TEMPLATE_INCONSISTENT,
          "XDH scalar length does not match the curve")
        (checkExact w scalar)
      pure (Map.insert AttrValue
        (ValBytes (montgomeryPrivateDer oid scalar')) attrs)
    xdhPublic = do
      params <- need AttrEcParams
      point <- need AttrEcPoint
      (oid, w) <- orReject
        (CKR_CURVE_NOT_SUPPORTED, "unsupported Montgomery curve parameters")
        (resolveMontgomery params)
      raw <- orReject (CKR_TEMPLATE_INCONSISTENT,
          "EC_POINT is not a raw or wrapped Montgomery point")
        (unwrapMontgomeryPoint w point)
      forbidValue
      pure (Map.insert AttrValue
        (ValBytes (montgomeryPublicDer oid raw)) attrs)
    resolveMontgomery params = do
      oid <- montgomeryOidOfParams params
      w <- montgomeryWidthOfParams oid
      pure (oid, w)
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
      alg <- (case (fromIntegral n :: Int) of
        1 -> Just 512
        2 -> Just 768
        3 -> Just 1024
        _ -> Nothing) :: Maybe Int
      pure (oid, ekW, dkW, ctW, alg)
    checkExact w s
      | BS.length s == w = Just s
      | otherwise = Nothing
    resolveCurve params = do
      oid <- curveOidOfParams params
      coordLen <- curveCoordLen oid
      orderBytes <- curveOrderOfOid oid
      pure (oid, coordLen, orderBytes)
    -- | Private scalars must satisfy 1 ≤ d < n (SEC1 §2.3.6,
    -- PKCS#11 §6.3.4): measures the integer (spec big-integer
    -- has no minimal-encoding rule, so zero-padded values load),
    -- all-zero (d=0) refuses, over-wide refuses, and full-width
    -- values compare lexicographically against the order (equal
    -- length big-endian). Shorter values are always below the
    -- order (fewer bytes than its minimal encoding). Returns the
    -- order-width normalization (left-pad with zeros), so padding
    -- can never blow past downstream size limits.
    checkScalar orderBytes s =
      let stripped = BS.dropWhile (== 0) s
          orderLen = BS.length orderBytes
      in if BS.null stripped || BS.length stripped > orderLen
         then Nothing
         else if BS.length stripped < orderLen
              then Just (BS.replicate (orderLen - BS.length stripped) 0 <> stripped)
              else if stripped < orderBytes
                   then Just stripped
                   else Nothing
    secretKey k
      | isAsymmetricKeyType k = Left (CKR_TEMPLATE_INCONSISTENT,
          "asymmetric key type on a secret object")
      | otherwise = do
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

-- | True bit width of unsigned big-endian bytes (leading zero
-- bits discounted, so short top octets measure honestly).
bitsOf :: ByteString -> Int
bitsOf bs = case BS.dropWhile (== 0) bs of
  stripped
    | BS.null stripped -> 0
    | otherwise -> BS.length stripped * 8 - countLeadingZeros (BS.head stripped)
