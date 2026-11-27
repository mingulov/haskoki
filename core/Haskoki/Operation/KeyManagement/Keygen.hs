{- | KeyManagement keygen planners: pair/single generation plus
the curve/set/exponent/domain readers behind them.

Imports the Types/Template/Codec/Codes/MechIds leaves only.
Re-exported via the shell.
-}
{-# LANGUAGE OverloadedStrings #-}
module Haskoki.Operation.KeyManagement.Keygen
  ( planGenerateKeyPair
  , planGenerateKey
  ) where

import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map
import Data.Word (Word64)
import Haskoki.Attribute
  ( AttributeType (..)
  , AttributeValue (..)
  )
import Haskoki.Der (curveTable, dhParamsDer, dhParamsDerQ, dsaParamsDer, edwardsTable, montgomeryTable)
import Haskoki.Model (Model (..), SessionState (..))
import Haskoki.Operation.Effect (CryptoEffect (..))
import Haskoki.Operation.KeyManagement.Codec
import Haskoki.Operation.KeyManagement.Codes
import Haskoki.Operation.KeyManagement.MechIds
import Haskoki.Operation.KeyManagement.Template
import Haskoki.Operation.KeyManagement.Types
import Haskoki.Recipe.Kdf (decodePbkd2Params, maxPbkd2Iters)
import Haskoki.Recipe.Pbe (PbeKind (..), PbeRecipe (pbeKind), pbeIvLen, pbeKeyLen, pbeParamsValid, pbeRecipeFor)
import Haskoki.Recipe.Otp (hotpKeygenMaxBytes, hotpKeygenMinBytes)
import Haskoki.Registry (MechanismId (..))
import Haskoki.Registry.Generated (ckm_ML_KEM_KEY_PAIR_GEN)
import Haskoki.Rules (Rules)
import Haskoki.Session (admitCode, admitObjects)
import Haskoki.Types (ReturnCode (..))


-- | Shared pair-template validation: both templates check against
-- their class and the mechanism's key type, then the
-- mechanism-specific arguments resolve (which may normalize the
-- attributes, e.g. the agreed KEM set). Returns the validated
-- pair for the caller to admit and wrap (admission runs
-- after validation).
withPair
  :: SessionState -> MechanismId -> Word64
  -> [(AttributeType, AttributeValue)] -> [(AttributeType, AttributeValue)]
  -> (Map AttributeType AttributeValue -> Map AttributeType AttributeValue
      -> Either KeyDeny (GenArgs, Map AttributeType AttributeValue, Map AttributeType AttributeValue))
  -> Either KeyDeny (PendingWork, CryptoEffect)
withPair st mech wantKey pubT privT argsOf =
  case checkKeyTemplate ckoPublicKey wantKey pubT of
    Left deny -> Left deny
    Right pubA -> case checkKeyTemplate ckoPrivateKey wantKey privT of
      Left deny -> Left deny
      Right privA -> case argsOf pubA privA of
        Left deny -> Left deny
        Right (args, pubA', privA') ->
          Right
            ( PwGeneratePair
                (pendingFromAttrs st (stampGenerated ckoPublicKey mech pubA'))
                (pendingFromAttrs st (stampGenerated ckoPrivateKey mech privA'))
            , FxGenerateKey mech BS.empty (encodeGenArgs args)
            )

-- | KEM keys never derive (no KEM derive operation exists):
-- an explicit @CKA_DERIVE=true@ refuses inconsistent, and
-- absent (or explicit-false) stamps false — the oracle's
-- derive-false leg reads the value back, and only an explicit
-- false passes (a missing attribute records a deviation).
-- Inspects the RAW template (equivalent to the defaulted map:
-- an explicit true survives defaulting; absent and false both
-- stamp false). (Not a forbidden rule: a stored false would
-- poison presence-based re-validation.)
kemNoDerive
  :: [(AttributeType, AttributeValue)] -> Map AttributeType AttributeValue
  -> Either KeyDeny (Map AttributeType AttributeValue)
kemNoDerive raw attrs
  | any (\(t, v) -> t == AttrDerive && v == ValBool True) raw =
      Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
        "KEM keys do not derive: CKA_DERIVE must not be true")
  | otherwise = Right (Map.insert AttrDerive (ValBool False) attrs)

-- | The ML-KEM parameter set for a pair: the spec keygen
-- input @AttrParameterSet@ (@CKP_ML_KEM_512\/768\/1024@ =
-- 1\/2\/3, the 'mldsaSetOf' precedent) wins when present; the
-- internal @AttrKemAlg@ tag (512\/768\/1024) serves callers
-- that already resolved it; absent everywhere defaults to 768.
-- The private template inherits when absent and must agree
-- when present; a template carrying both must agree with
-- itself.
kemAlgOf
  :: Map AttributeType AttributeValue -> Map AttributeType AttributeValue
  -> Either KeyDeny Int
kemAlgOf pubA privA = do
  pubSet <- resolveOne "public" pubA
  privSet <- resolveOne "private" privA
  case (pubSet, privSet) of
    (Just a, Just b)
      | a == b -> Right a
      | otherwise -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
          "keypair templates disagree on the KEM parameter set")
    (Just a, Nothing) -> Right a
    (Nothing, Just b) -> Right b
    (Nothing, Nothing) -> Right 768
  where
    resolveOne who attrs = case Map.lookup AttrParameterSet attrs of
      Just (ValULong ckp)
        | ckp `elem` [1, 2, 3] ->
            let alg = [512, 768, 1024] !! fromIntegral (ckp - 1)
            in case Map.lookup AttrKemAlg attrs of
              Nothing -> Right (Just alg)
              Just (ValULong alg')
                | fromIntegral alg' == alg -> Right (Just alg)
                | otherwise -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
                    (who ++ " template KEM set contradicts its parameter set"))
              Just _ -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
                (who ++ " KEM parameter set is malformed"))
        | otherwise -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
            ("unknown ML-KEM parameter set: " ++ show ckp))
      Just _ -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
        (who ++ " KEM parameter set is malformed"))
      Nothing -> case Map.lookup AttrKemAlg attrs of
        Nothing -> Right Nothing
        Just (ValULong alg)
          | alg `elem` [512, 768, 1024] -> Right (Just (fromIntegral alg))
          | otherwise -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
              ("unknown KEM parameter set: " ++ show alg))
        Just _ -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
          (who ++ " KEM parameter set is malformed"))

-- | The ML-DSA parameter-set id for a pair: the public
-- template's @AttrParameterSet@ (@CKP_ML_DSA_44\/65\/87@ =
-- 1\/2\/3, the spec keygen input), which the private template
-- inherits when absent and must agree with when present.
-- Absent everywhere defaults to 65 (the 'kemAlgOf' precedent:
-- the middle set, as KEM defaults 768).
mldsaSetOf
  :: Map AttributeType AttributeValue -> Map AttributeType AttributeValue
  -> Either KeyDeny Int
mldsaSetOf pubA privA = case Map.lookup AttrParameterSet pubA of
  Just (ValULong ckp)
    | ckp `elem` [1, 2, 3] -> case Map.lookup AttrParameterSet privA of
        Nothing -> Right (fromIntegral ckp)
        Just (ValULong ckp')
          | ckp' == ckp -> Right (fromIntegral ckp)
          | otherwise -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
              "keypair templates disagree on the ML-DSA parameter set")
        Just _ -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
          "private ML-DSA parameter set is malformed")
    | otherwise -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
        ("unknown ML-DSA parameter set: " ++ show ckp))
  Just _ -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
    "public ML-DSA parameter set is malformed")
  Nothing -> case Map.lookup AttrParameterSet privA of
    Nothing -> Right 2
    Just (ValULong ckp)
      | ckp `elem` [1, 2, 3] -> Right (fromIntegral ckp)
      | otherwise -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
          ("unknown ML-DSA parameter set: " ++ show ckp))
    Just _ -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
      "private ML-DSA parameter set is malformed")

-- | The SLH-DSA parameter-set id for a pair: the public
-- template's @AttrParameterSet@ (@CKP_SLH_DSA_*@ = 1..12, the
-- spec keygen input), which the private template inherits
-- when absent and must agree with when present. Absent
-- everywhere defaults to 1 (SLH-DSA-SHA2-128s, the first set
-- and the driver's unscannable-key default).
slhdsaSetOf
  :: Map AttributeType AttributeValue -> Map AttributeType AttributeValue
  -> Either KeyDeny Int
slhdsaSetOf pubA privA = case Map.lookup AttrParameterSet pubA of
  Just (ValULong ckp)
    | ckp `elem` [1 .. 12] -> case Map.lookup AttrParameterSet privA of
        Nothing -> Right (fromIntegral ckp)
        Just (ValULong ckp')
          | ckp' == ckp -> Right (fromIntegral ckp)
          | otherwise -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
              "keypair templates disagree on the SLH-DSA parameter set")
        Just _ -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
          "private SLH-DSA parameter set is malformed")
    | otherwise -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
        ("unknown SLH-DSA parameter set: " ++ show ckp))
  Just _ -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
    "public SLH-DSA parameter set is malformed")
  Nothing -> case Map.lookup AttrParameterSet privA of
    Nothing -> Right 1
    Just (ValULong ckp)
      | ckp `elem` [1 .. 12] -> Right (fromIntegral ckp)
      | otherwise -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
          ("unknown SLH-DSA parameter set: " ++ show ckp))
    Just _ -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
      "private SLH-DSA parameter set is malformed")

-- | The EC curve for a pair: @AttrEcParams@ is required in the
-- public template (PKCS#11 names the curve there), the private
-- template inherits it when absent and must agree when present.
-- Every 'Haskoki.Der.curveTable' row executes in the engine set —
-- deliberately maximal (weak sub-224-bit and binary curves ride
-- for oracle coverage, never as a deployment recommendation);
-- anything else is mechanism-invalid, never silently
-- substituted.
ecCurveOf
  :: Map AttributeType AttributeValue -> Map AttributeType AttributeValue
  -> Either KeyDeny ByteString
ecCurveOf pubA privA = case Map.lookup AttrEcParams pubA of
  Just (ValBytes curve)
    | curve `elem` [n | (n, _, _, _) <- curveTable] -> case Map.lookup AttrEcParams privA of
        Nothing -> Right curve
        Just (ValBytes curve')
          | curve' == curve -> Right curve
          | otherwise -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
              "keypair templates disagree on the curve")
        Just _ -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
          "private EC params are malformed")
    | otherwise -> Left (KeyDeny CKR_MECHANISM_INVALID
        ("unsupported curve: " ++ show curve))
  Just _ -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
    "public EC params are malformed")
  Nothing -> Left (KeyDeny CKR_TEMPLATE_INCOMPLETE
    "EC keypair templates must name the curve")

-- | The served Edwards curve for a pair: the public template's
-- @AttrEcParams@ (an 'edwardsTable' engine name — the wire codec
-- maps caller OIDs to names), which the private template inherits
-- when absent and must agree with when present. Unknown curves
-- (including Weierstrass names — a caller mixing
-- @CKM_EC_KEY_PAIR_GEN@ parameters into the Edwards mechanism)
-- refuse mechanism-invalid (the 'ecCurveOf' precedent).
edwardsCurveOf
  :: Map AttributeType AttributeValue -> Map AttributeType AttributeValue
  -> Either KeyDeny ByteString
edwardsCurveOf pubA privA = case Map.lookup AttrEcParams pubA of
  Just (ValBytes curve)
    | curve `elem` [n | (n, _, _, _) <- edwardsTable] -> case Map.lookup AttrEcParams privA of
        Nothing -> Right curve
        Just (ValBytes curve')
          | curve' == curve -> Right curve
          | otherwise -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
              "keypair templates disagree on the curve")
        Just _ -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
          "private EC params are malformed")
    | otherwise -> Left (KeyDeny CKR_MECHANISM_INVALID
        ("unsupported curve: " ++ show curve))
  Just _ -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
    "public EC params are malformed")
  Nothing -> Left (KeyDeny CKR_TEMPLATE_INCOMPLETE
    "Edwards keypair templates must name the curve")

-- | The served Montgomery curve for a pair: the public template's
-- @AttrEcParams@ (a 'montgomeryTable' engine name — the wire codec
-- maps caller OIDs to names), which the private template inherits
-- when absent and must agree with when present. Unknown curves
-- (including Weierstrass and Edwards names — a caller mixing
-- another mechanism's parameters into the Montgomery mechanism)
-- refuse mechanism-invalid (the 'ecCurveOf' precedent).
montgomeryCurveOf
  :: Map AttributeType AttributeValue -> Map AttributeType AttributeValue
  -> Either KeyDeny ByteString
montgomeryCurveOf pubA privA = case Map.lookup AttrEcParams pubA of
  Just (ValBytes curve)
    | curve `elem` [n | (n, _, _) <- montgomeryTable] -> case Map.lookup AttrEcParams privA of
        Nothing -> Right curve
        Just (ValBytes curve')
          | curve' == curve -> Right curve
          | otherwise -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
              "keypair templates disagree on the curve")
        Just _ -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
          "private EC params are malformed")
    | otherwise -> Left (KeyDeny CKR_MECHANISM_INVALID
        ("unsupported curve: " ++ show curve))
  Just _ -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
    "public EC params are malformed")
  Nothing -> Left (KeyDeny CKR_TEMPLATE_INCOMPLETE
    "Montgomery keypair templates must name the curve")

-- | The RSA public exponent for a pair: the public template's
-- @AttrPublicExponent@ when present (big-endian bytes, must decode
-- to an odd integer >= 3), else the 65537 default. A private
-- exponent must agree when present.
rsaExponentOf
  :: Map AttributeType AttributeValue -> Map AttributeType AttributeValue
  -> Either KeyDeny Integer
rsaExponentOf pubA privA = case Map.lookup AttrPublicExponent pubA of
  Just (ValBytes bs) -> case bytesToInteger bs of
    Just e
      | e >= 3 && odd e -> case Map.lookup AttrPublicExponent privA of
          Nothing -> Right e
          Just (ValBytes bs')
            | bytesToInteger bs' == Just e -> Right e
            | otherwise -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
                "keypair templates disagree on the public exponent")
          Just _ -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
            "private public exponent is malformed")
      | otherwise -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
          "public exponent must be odd and >= 3")
    Nothing -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
      "public exponent is malformed")
  Just _ -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
    "public exponent is malformed")
  Nothing -> case Map.lookup AttrPublicExponent privA of
    Nothing -> Right 65537
    Just (ValBytes bs) -> case bytesToInteger bs of
      Just e
        | e >= 3 && odd e -> Right e
        | otherwise -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
            "public exponent must be odd and >= 3")
      Nothing -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
        "public exponent is malformed")
    Just _ -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
      "public exponent is malformed")

-- | Big-endian bytes to an integer; empty input decodes to 0.
bytesToInteger :: ByteString -> Maybe Integer
bytesToInteger bs
  | BS.length bs > 8 = Nothing
  | otherwise = Just (BS.foldl' (\acc b -> acc * 256 + fromIntegral b) 0 bs)

-- | The RSA modulus size for a pair: @AttrModulusBits@ is required
-- in the public template, the private template inherits it when
-- absent and must agree when present.
rsaBitsOf
  :: Map AttributeType AttributeValue -> Map AttributeType AttributeValue
  -> Either KeyDeny Int
rsaBitsOf pubA privA = case Map.lookup AttrModulusBits pubA of
  Just (ValULong bits)
    | bits `elem` [2048, 3072, 4096] -> case Map.lookup AttrModulusBits privA of
        Nothing -> Right (fromIntegral bits)
        Just (ValULong bits')
          | bits' == bits -> Right (fromIntegral bits)
          | otherwise -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
              "keypair templates disagree on the modulus size")
        Just _ -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
          "private modulus bits are malformed")
    | otherwise -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
        ("modulus size out of range: " ++ show bits))
  Just _ -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
    "public modulus bits are malformed")
  Nothing -> Left (KeyDeny CKR_TEMPLATE_INCOMPLETE
    "RSA keypair templates must name the modulus size")

-- | The DSA domain parameters for a pair, framed as DER DSS-Parms
-- for the driver. @AttrPrime@\/@AttrSubprime@\/@AttrBase@ are
-- required in the public template (PKCS#11 names the domain there),
-- the private template inherits them when absent and must agree
-- when present. Present-but-unserved @AttrPrimeBits@\/
-- @AttrSubprimeBits@ refuse as inconsistent first (a template
-- whose only size hint is unserved contradicts the mechanism even
-- before the missing-parameters check runs, mirroring 'rsaBitsOf');
-- missing parameters are incomplete; malformed or empty parts are
-- inconsistent. Size bounds are generous ceilings (4096-bit p\/g,
-- 512-bit q) — the backend, not the planner, owns the served-pair
-- policy.
dsaDomainOf
  :: Map AttributeType AttributeValue -> Map AttributeType AttributeValue
  -> Either KeyDeny ByteString
dsaDomainOf pubA privA = do
  checkSizeBit AttrPrimeBits [1024, 2048, 3072] pubA
  checkSizeBit AttrPrimeBits [1024, 2048, 3072] privA
  checkSizeBit AttrSubprimeBits [160, 224, 256] pubA
  checkSizeBit AttrSubprimeBits [160, 224, 256] privA
  p <- component AttrPrime pubA privA
  q <- component AttrSubprime pubA privA
  g <- component AttrBase pubA privA
  pure (dsaParamsDer p q g)
  where
    checkSizeBit t served attrs = case Map.lookup t attrs of
      Nothing -> Right ()
      Just (ValULong n)
        | n `elem` served -> Right ()
        | otherwise -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
            ("DSA size out of range: " ++ show t ++ "=" ++ show n))
      Just _ -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
        ("DSA size attribute is malformed: " ++ show t))
    component t pub priv = case Map.lookup t pub of
      Just (ValBytes bs)
        | BS.null bs -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
            ("DSA domain parameter is empty: " ++ show t))
        | BS.length bs > bound t -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
            ("DSA domain parameter oversized: " ++ show t))
        | otherwise -> case Map.lookup t priv of
            Nothing -> Right bs
            Just (ValBytes bs')
              | bs' == bs -> Right bs
              | otherwise -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
                  "keypair templates disagree on DSA domain parameters")
            Just _ -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
              "private DSA domain parameter is malformed")
      Just _ -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
        ("DSA domain parameter is malformed: " ++ show t))
      Nothing -> Left (KeyDeny CKR_TEMPLATE_INCOMPLETE
        "DSA keypair templates must carry p, q and g")
    bound AttrSubprime = 64
    bound _ = 512

-- | DH domain parameters from keypair templates: @CKA_PRIME@ and
-- @CKA_BASE@ always, @CKA_SUBPRIME@ exactly for X9.42
-- (@wantQ@). Missing parameters are incomplete; malformed,
-- empty, oversized, disagreeing, or structurally impossible
-- parts are inconsistent, as is a subprime on a PKCS#3
-- template (PKCS#3 has no q). Size hints are checked before
-- the missing-parameters check runs (mirroring
-- 'dsaDomainOf'); the backend, not the planner, owns the
-- served-pair policy.
--
-- The structural floor (NIST SP 800-56A rev. 3 section
-- 5.5.1): the prime carries at least 512 significant bits
-- and the generator sits in @2..p-1@ (X9.42: the subprime
-- in @2..p-1@ too). Values compare leading-zero-blind, so
-- zero-padded degenerates refuse exactly like bare ones.
-- Deeper checks (primality, @q | p-1@, @g^q = 1@) stay with
-- the executing backend, which owns the crypto.
dhDomainOf
  :: Bool
  -> Map AttributeType AttributeValue -> Map AttributeType AttributeValue
  -> Either KeyDeny ByteString
dhDomainOf wantQ pubA privA = do
  checkSizeBit AttrPrimeBits [1024, 2048, 3072, 4096] pubA
  checkSizeBit AttrPrimeBits [1024, 2048, 3072, 4096] privA
  checkSizeBit AttrSubprimeBits [160, 224, 256] pubA
  checkSizeBit AttrSubprimeBits [160, 224, 256] privA
  p <- component AttrPrime pubA privA
  g <- component AttrBase pubA privA
  case dhStructural p g of
    Just msg -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT msg)
    Nothing -> pure ()
  case (wantQ, Map.lookup AttrSubprime pubA) of
    (True, _) -> do
      q <- component AttrSubprime pubA privA
      case dhSubprime p q of
        Just msg -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT msg)
        Nothing -> pure (dhParamsDerQ p g q)
    (False, Nothing) -> pure (dhParamsDer p g)
    (False, Just _) -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
      "PKCS#3 DH domain takes no subprime")
  where
    -- Significant bytes: leading zeros dropped (the empty
    -- encoding is value zero).
    sig :: ByteString -> ByteString
    sig = BS.dropWhile (== 0)
    -- Unsigned big-endian comparison, leading-zero-blind.
    ltBE :: ByteString -> ByteString -> Bool
    ltBE a b = case compare (BS.length a') (BS.length b') of
      LT -> True
      GT -> False
      EQ -> a' < b'
      where
        a' = sig a
        b' = sig b
    -- The (p, g) structural floor: 512 significant prime
    -- bits, @2 <= g < p@. 'Nothing' accepts.
    dhStructural :: ByteString -> ByteString -> Maybe String
    dhStructural p g
      | BS.length (sig p) < 64 =
          Just "DH prime under the 512-bit structural floor"
      | BS.null (sig g) || sig g == BS.singleton 1 || not (ltBE g p) =
          Just "DH generator outside 2 <= g < p"
      | otherwise = Nothing
    -- The X9.42 subprime range: @1 < q < p@. 'Nothing'
    -- accepts.
    dhSubprime :: ByteString -> ByteString -> Maybe String
    dhSubprime p q
      | BS.null (sig q) || sig q == BS.singleton 1 || not (ltBE q p) =
          Just "X9.42 subprime outside 1 < q < p"
      | otherwise = Nothing
    checkSizeBit t served attrs = case Map.lookup t attrs of
      Nothing -> Right ()
      Just (ValULong n)
        | n `elem` served -> Right ()
        | otherwise -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
            ("DH size out of range: " ++ show t ++ "=" ++ show n))
      Just _ -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
        ("DH size attribute is malformed: " ++ show t))
    component t pub priv = case Map.lookup t pub of
      Just (ValBytes bs)
        | BS.null bs -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
            ("DH domain parameter is empty: " ++ show t))
        | BS.length bs > bound t -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
            ("DH domain parameter oversized: " ++ show t))
        | otherwise -> case Map.lookup t priv of
            Nothing -> Right bs
            Just (ValBytes bs')
              | bs' == bs -> Right bs
              | otherwise -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
                  "keypair templates disagree on DH domain parameters")
            Just _ -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
              "private DH domain parameter is malformed")
      Just _ -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
        ("DH domain parameter is malformed: " ++ show t))
      Nothing -> Left (KeyDeny CKR_TEMPLATE_INCOMPLETE
        "DH keypair templates must carry the domain parameters")
    bound AttrSubprime = 64
    bound _ = 512

-- | Plan a TLS/SSL3 pre-master keygen: the 2-byte @CK_VERSION@
-- parameter is required and its bytes lead the 48-byte generic
-- secret. A missing length defaults to 48; the validated params
-- ride the effect so async replays reproduce the version.
planTlsPremaster
  :: SessionState -> MechanismId -> ByteString
  -> [(AttributeType, AttributeValue)]
  -> Either KeyDeny (PendingWork, CryptoEffect)
planTlsPremaster st mech params tmpl = case BS.unpack params of
  [major, minor] -> case checkKeyTemplate ckoSecretKey ckkGenericSecret tmpl of
    Left deny -> Left deny
    Right attrs -> case Map.lookup AttrValueLen attrs of
      Just (ValULong n)
        | n == 48 -> Right (effect attrs major minor)
        | otherwise -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
            ("pre-master length must be 48 bytes: " ++ show n))
      Just _ -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
        "pre-master value length is malformed")
      Nothing -> Right (effect attrs major minor)
  _ -> Left (KeyDeny CKR_MECHANISM_PARAM_INVALID
    "TLS/SSL3 pre-master needs a 2-byte CK_VERSION")
  where
    effect attrs major minor =
      ( PwGenerateKey (pendingFromAttrs st (stampGenerated ckoSecretKey mech attrs))
      , FxGenerateKey mech params (encodeGenArgs (GenTlsPremaster major minor))
      )

-- | Plan a WTLS pre-master keygen: the 1-byte version parameter
-- is required and leads a variable-length (20-255 byte) generic
-- secret. The validated params ride the effect for replays.
planWtlsPremaster
  :: SessionState -> MechanismId -> ByteString
  -> [(AttributeType, AttributeValue)]
  -> Either KeyDeny (PendingWork, CryptoEffect)
planWtlsPremaster st mech params tmpl = case BS.unpack params of
  [ver] -> case checkKeyTemplate ckoSecretKey ckkGenericSecret tmpl of
    Left deny -> Left deny
    Right attrs -> case Map.lookup AttrValueLen attrs of
      Just (ValULong n)
        | n >= 20 && n <= 255 -> Right (effect attrs ver (fromIntegral n))
        | otherwise -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
            ("WTLS pre-master length must be 20 to 255 bytes: " ++ show n))
      Just _ -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
        "WTLS pre-master value length is malformed")
      Nothing -> Left (KeyDeny CKR_TEMPLATE_INCOMPLETE
        "WTLS pre-master keygen needs CKA_VALUE_LEN")
  _ -> Left (KeyDeny CKR_MECHANISM_PARAM_INVALID
    "WTLS pre-master needs a 1-byte version")
  where
    effect attrs ver n =
      ( PwGenerateKey (pendingFromAttrs st (stampGenerated ckoSecretKey mech attrs))
      , FxGenerateKey mech params (encodeGenArgs (GenWtlsPremaster ver n))
      )

-- | Plan a PBKD2 keygen: the @pbkd2-params\/2@ frame (PRF code,
-- iterations, salt, inline password) is required and validated
-- before the template; the derived length is required and checked
-- against the target key type's domain (generic-secret: 1 to the
-- shared ceiling; AES: 16\/24\/32; DES3: 24; XTS: 32\/64 — the
-- unwrap coherence table). Unlisted target types refuse closed:
-- minting an unknown fixed-length type would poison the object
-- store. The validated frame rides the effect so async replays
-- reproduce the derived material bit-for-bit.
planPbkd2Gen
  :: SessionState -> MechanismId -> ByteString
  -> [(AttributeType, AttributeValue)]
  -> Either KeyDeny (PendingWork, CryptoEffect)
planPbkd2Gen st mech params tmpl = case decodePbkd2Params params of
  Nothing -> Left (KeyDeny CKR_MECHANISM_PARAM_INVALID
    "PBKD2 keygen needs a pbkd2-params/2 frame")
  Just (_, iters, _, _)
    | iters < 1 || iters > maxPbkd2Iters -> Left (KeyDeny CKR_MECHANISM_PARAM_INVALID
        ("PBKD2 iterations must be 1 to " ++ show maxPbkd2Iters ++ ": " ++ show iters))
    | otherwise -> case targetKey of
        Nothing -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
          ("PBKD2 target key type is not served: " ++ show targetRaw))
        Just wantKey -> case checkKeyTemplate ckoSecretKey wantKey tmpl of
          Left deny -> Left deny
          Right attrs -> case Map.lookup AttrValueLen attrs of
            Just (ValULong n)
              | pbkd2LenOk wantKey n -> Right (effect attrs (fromIntegral n))
              | otherwise -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
                  ("PBKD2 length " ++ show n ++ " is outside " ++ pbkd2LenDesc wantKey))
            Just _ -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
              "PBKD2 value length is malformed")
            Nothing -> Left (KeyDeny CKR_TEMPLATE_INCOMPLETE
              "PBKD2 keygen needs CKA_VALUE_LEN")
  where
    targetRaw = lookup AttrKeyType tmpl
    -- Absent defaults to generic-secret (the strict check stamps
    -- it); listed fixed types dispatch to their own strict check
    -- (class, generated rules, usage defaults); anything else —
    -- including malformed shapes — refuses closed.
    targetKey = case targetRaw of
      Nothing -> Just ckkGenericSecret
      Just (ValULong k)
        | k == ckkGenericSecret -> Just ckkGenericSecret
        | k == ckkAes -> Just ckkAes
        | k == ckkDes3 -> Just ckkDes3
        | k == ckkAesXts -> Just ckkAesXts
        | otherwise -> Nothing
      Just _ -> Nothing
    pbkd2LenOk wantKey n
      | wantKey == ckkAes = n `elem` [16, 24, 32]
      | wantKey == ckkDes3 = n == 24
      | wantKey == ckkAesXts = n `elem` [32, 64]
      | otherwise = n >= 1 && n <= fromIntegral pbkd2KeygenMaxBytes
    pbkd2LenDesc wantKey
      | wantKey == ckkAes = "the AES 16/24/32 domain"
      | wantKey == ckkDes3 = "the DES3 24-byte domain"
      | wantKey == ckkAesXts = "the XTS 32/64 domain"
      | otherwise = "1 to " ++ show pbkd2KeygenMaxBytes ++ " bytes"
    effect attrs n =
      ( PwGenerateKey (pendingFromAttrs st (stampGenerated ckoSecretKey mech attrs))
      , FxGenerateKey mech params (encodeGenArgs (GenPbkd2 n))
      )

-- | Plan a PBE keygen: the @pbe-params\/1@ frame (iterations,
-- password, salt) is required and validated before the
-- template; the key type and length are fixed per row (see
-- 'pbeKeyLen') with a DES3-keygen-style default when
-- @CKA_VALUE_LEN@ is absent. The validated frame rides the
-- effect so async replays reproduce the key and IV
-- bit-for-bit. The RC4 rows complete key-only (no IV).
planPbeGen
  :: SessionState -> MechanismId -> ByteString
  -> [(AttributeType, AttributeValue)]
  -> Either KeyDeny (PendingWork, CryptoEffect)
planPbeGen st mech params tmpl = case pbeRecipeFor mech of
  Nothing -> Left (KeyDeny CKR_MECHANISM_INVALID
    "PBE keygen needs a PBE mechanism")
  Just r
    | not (pbeParamsValid r params) -> Left (KeyDeny CKR_MECHANISM_PARAM_INVALID
        "PBE keygen needs a valid pbe-params/1 frame")
    | otherwise -> case checkKeyTemplate ckoSecretKey wantKey tmpl of
        Left deny -> Left deny
        Right attrs -> case Map.lookup AttrValueLen attrs of
          Just (ValULong n)
            | fromIntegral n == keyLen -> Right (effect attrs)
            | otherwise -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
                ("PBE length must be " ++ show keyLen ++ " bytes: " ++ show n))
          Just _ -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
            "PBE value length is malformed")
          Nothing -> Right (effect attrs)
    where
      wantKey = case pbeKind r of
        PbeDes3 -> ckkDes3
        PbeDes2 -> ckkDes2
        PbeSha1Cast128 -> ckkCast128
        PbeSha1Rc4_128 -> ckkRc4
        PbeSha1Rc4_40 -> ckkRc4
        PbeSha1Rc2_128 -> ckkRc2
        PbeSha1Rc2_40 -> ckkRc2
        PbeMd5Des -> ckkDes
        PbeMd5Cast -> ckkCast
        PbeMd5Cast3 -> ckkCast3
        PbeMd5Cast128 -> ckkCast128
      keyLen = pbeKeyLen (pbeKind r)
      effect attrs
        | pbeIvLen (pbeKind r) > 0 =
            ( PwGenerateKeyIv (pendingFromAttrs st (stampGenerated ckoSecretKey mech attrs)) keyLen
            , FxGenerateKey mech params (encodeGenArgs (GenPbe keyLen))
            )
        | otherwise =
            ( PwGenerateKey (pendingFromAttrs st (stampGenerated ckoSecretKey mech attrs))
            , FxGenerateKey mech params (encodeGenArgs (GenPbe keyLen))
            )

-- | Plan key-pair generation: both templates validate fully before
-- any effect plans, so a bad template yields zero objects. ML-KEM,
-- EC, RSA and DSA pair mechanisms (generated ids, resolved by
-- name). Admission gates last (parse-first, mirroring
-- 'Haskoki.Operation.Derive'): mechanism, templates, then the
-- bound check just before the effect.
planGenerateKeyPair
  :: Rules -> Model -> SessionState -> MechanismId
  -> [(AttributeType, AttributeValue)] -> [(AttributeType, AttributeValue)]
  -> KeyPlan
planGenerateKeyPair rules model st mech pubT privT =
  case validated of
    Left deny -> KeyDenied deny
    Right (pw, fx) ->
      case admitObjects rules (Map.size (mObjects model)) 2 of
        Left deny -> KeyDenied (KeyDeny (admitCode deny)
          ("admission denied: " ++ show deny))
        Right () -> KeyEffect pw fx
  where
    validated
      | mech == MechanismId (ckm_ML_KEM_KEY_PAIR_GEN) =
          withPair st mech ckkMlKem pubT privT $ \pubA privA -> do
            alg <- kemAlgOf pubA privA
            pubA' <- kemNoDerive pubT pubA
            privA' <- kemNoDerive privT privA
            let ckp = case alg of
                  512 -> 1 :: Int
                  768 -> 2
                  _ -> 3
                tag = Map.insert AttrKemAlg (ValULong (fromIntegral alg))
                  . Map.insert AttrParameterSet (ValULong (fromIntegral ckp))
            pure (GenMlKem alg, tag pubA', tag privA')
      | mech == ecKeyPairGenMech || mech == ecExtraBitsKeyPairGenMech =
          withPair st mech ckkEc pubT privT $ \pubA privA -> do
            curve <- ecCurveOf pubA privA
            pure (GenEc curve, pubA, privA)
      | mech == rsaKeyPairGenMech =
          withPair st mech ckkRsa pubT privT $ \pubA privA -> do
            bits <- rsaBitsOf pubA privA
            e <- rsaExponentOf pubA privA
            pure (GenRsa bits e, pubA, privA)
      | mech == dsaKeyPairGenMech =
          withPair st mech ckkDsa pubT privT $ \pubA privA -> do
            der <- dsaDomainOf pubA privA
            pure (GenDsaKeypair der, pubA, privA)
      | mech == dhKeyPairGenMech =
          withPair st mech ckkDh pubT privT $ \pubA privA -> do
            der <- dhDomainOf False pubA privA
            pure (GenDhKeypair der, pubA, privA)
      | mech == x9_42DhKeyPairGenMech =
          withPair st mech ckkX9_42Dh pubT privT $ \pubA privA -> do
            der <- dhDomainOf True pubA privA
            pure (GenDhKeypair der, pubA, privA)
      | mech == edwardsKeyPairGenMech =
          withPair st mech ckkEcEdwards pubT privT $ \pubA privA -> do
            curve <- edwardsCurveOf pubA privA
            pure (GenEdwardsKeypair curve, pubA, privA)
      | mech == montgomeryKeyPairGenMech =
          withPair st mech ckkEcMontgomery pubT privT $ \pubA privA -> do
            curve <- montgomeryCurveOf pubA privA
            pure (GenMontgomeryKeypair curve, pubA, privA)
      | mech == mldsaKeyPairGenMech =
          withPair st mech ckkMlDsa pubT privT $ \pubA privA -> do
            ckp <- mldsaSetOf pubA privA
            let tag = Map.insert AttrParameterSet (ValULong (fromIntegral ckp))
            pure (GenMlDsa ckp, tag pubA, tag privA)
      | mech == slhdsaKeyPairGenMech =
          withPair st mech ckkSlhDsa pubT privT $ \pubA privA -> do
            ckp <- slhdsaSetOf pubA privA
            let tag = Map.insert AttrParameterSet (ValULong (fromIntegral ckp))
            pure (GenSlhDsa ckp, tag pubA, tag privA)
      | otherwise =
          Left (KeyDeny CKR_MECHANISM_INVALID
            ("not a key-pair mechanism: " ++ show mech))

-- | Plan single-key generation: AES takes a 128\/192\/256-bit
-- length via @AttrValueLen@ (bytes); HOTP takes any length in the
-- recipe's 16-64 byte window; the sweep table serves the fixed,
-- discrete and ranged symmetric keygens; DSA and X9.42 DH
-- parameter generation take the @(L, N)@ size pair via
-- @AttrPrimeBits@ (required) and @AttrSubprimeBits@ (defaulted
-- for DSA, required for X9.42 DH) and complete one pending
-- domain-parameters object. The driver answer completes one
-- pending object. Admission gates last (parse-first): mechanism,
-- template, then the bound check just before the effect.
planGenerateKey
  :: Rules -> Model -> SessionState -> MechanismId -> ByteString
  -> [(AttributeType, AttributeValue)]
  -> KeyPlan
planGenerateKey rules model st mech params tmpl =
  case validated of
    Left deny -> KeyDenied deny
    Right (pw, fx) ->
      case admitObjects rules (Map.size (mObjects model)) 1 of
        Left deny -> KeyDenied (KeyDeny (admitCode deny)
          ("admission denied: " ++ show deny))
        Right () -> KeyEffect pw fx
  where
    validated
      -- Only the pre-master keygens (the client version),
      -- PBKD2 (the v2 frame), and PBE (the v1 frame) take
      -- mechanism parameters; every other keygen refuses
      -- params.
      | not (BS.null params)
      , mech /= tlsPremasterKeyGenMech
      , mech /= ssl3PremasterKeyGenMech
      , mech /= wtlsPremasterKeyGenMech
      , mech /= pbkd2KeyGenMech
      , mech /= pbeDes3KeyGenMech
      , mech /= pbeDes2KeyGenMech
      , mech /= pbeSha1Cast128KeyGenMech
      , mech /= pbeSha1Rc4_128KeyGenMech
      , mech /= pbeSha1Rc4_40KeyGenMech
      , mech /= pbeSha1Rc2_128KeyGenMech
      , mech /= pbeSha1Rc2_40KeyGenMech
      , mech /= pbeMd5DesKeyGenMech
      , mech /= pbeMd5CastKeyGenMech
      , mech /= pbeMd5Cast3KeyGenMech
      , mech /= pbeMd5Cast128KeyGenMech =
          Left (KeyDeny CKR_MECHANISM_PARAM_INVALID
            "keygen takes no mechanism params")
      | mech == tlsPremasterKeyGenMech = planTlsPremaster st mech params tmpl
      | mech == ssl3PremasterKeyGenMech = planTlsPremaster st mech params tmpl
      | mech == wtlsPremasterKeyGenMech = planWtlsPremaster st mech params tmpl
      | mech == pbkd2KeyGenMech = planPbkd2Gen st mech params tmpl
      | mech == pbeDes3KeyGenMech = planPbeGen st mech params tmpl
      | mech == pbeDes2KeyGenMech = planPbeGen st mech params tmpl
      | mech == pbeSha1Cast128KeyGenMech = planPbeGen st mech params tmpl
      | mech == pbeSha1Rc4_128KeyGenMech = planPbeGen st mech params tmpl
      | mech == pbeSha1Rc4_40KeyGenMech = planPbeGen st mech params tmpl
      | mech == pbeSha1Rc2_128KeyGenMech = planPbeGen st mech params tmpl
      | mech == pbeSha1Rc2_40KeyGenMech = planPbeGen st mech params tmpl
      | mech == pbeMd5DesKeyGenMech = planPbeGen st mech params tmpl
      | mech == pbeMd5CastKeyGenMech = planPbeGen st mech params tmpl
      | mech == pbeMd5Cast3KeyGenMech = planPbeGen st mech params tmpl
      | mech == pbeMd5Cast128KeyGenMech = planPbeGen st mech params tmpl
      | mech == dsaParameterGenMech =
          case checkKeyTemplate ckoDomainParameters ckkDsa tmpl of
          Left deny -> Left deny
          -- Domain parameters are not keys: no protection or
          -- history rows are stamped (pending carries over verbatim).
          Right attrs -> case dsaParamSizes attrs of
            Left deny -> Left deny
            Right (l, n) -> Right
              ( PwGenerateKey (pendingFromAttrs st attrs)
              , FxGenerateKey mech BS.empty (encodeGenArgs (GenDsaParams l n))
              )
      -- X9.42 DH parameter generation frames the same
      -- (L, N) pair as DSA (on the OpenSSL backend FIPS 186-2
      -- at 1024/160, 186-4 above; provider DHX unwired), so
      -- the driver runs
      -- the DSA paramgen entry point and the (P, Q, G) triple
      -- publishes on the OpenSSL backend as X9.42 DH domain
      -- parameters (synthetic passes opaque bytes through
      -- unstamped) -- the same
      -- FIPS 186 math, the same DER DSS-Parms framing the
      -- finisher stamps).
      | mech == x9_42DhParameterGenMech =
          case checkKeyTemplate ckoDomainParameters ckkX9_42Dh tmpl of
          Left deny -> Left deny
          -- Not keys: no protection or history rows are stamped.
          Right attrs -> case dhParamSizes attrs of
            Left deny -> Left deny
            Right (l, n) -> Right
              ( PwGenerateKey (pendingFromAttrs st attrs)
              , FxGenerateKey mech BS.empty (encodeGenArgs (GenDsaParams l n))
              )
      -- DH PKCS parameter generation frames the same (L, N)
      -- pair as X9.42 (on the OpenSSL backend 186-2 at 1024/160,
      -- 186-4 above; same driver entry point, same DER DSS-Parms
      -- framing). Both backends publish the typed PKCS#3 object;
      -- p/q/g stamping reads OpenSSL's DER, with q plus its width
      -- as haskoki-specific readback (v3.2 section 6.4.9 specifies
      -- p, g, and prime width; synthetic passes opaque bytes
      -- through unstamped) -- but the subprime size defaults from
      -- L (the oracle sends CKA_PRIME_BITS only and expects CKR_OK).
      | mech == dhPkcsParameterGenMech =
          case checkKeyTemplate ckoDomainParameters ckkDh tmpl of
          Left deny -> Left deny
          -- Not keys: no protection or history rows are stamped.
          Right attrs -> case dhPkcsParamSizes attrs of
            Left deny -> Left deny
            Right (l, n) -> Right
              ( PwGenerateKey (pendingFromAttrs st attrs)
              , FxGenerateKey mech BS.empty (encodeGenArgs (GenDsaParams l n))
              )
      | mech == aesKeyGenMech = case checkKeyTemplate ckoSecretKey ckkAes tmpl of
          Left deny -> Left deny
          Right attrs -> case Map.lookup AttrValueLen attrs of
            Just (ValULong n)
              | n `elem` [16, 24, 32] -> Right
                  ( PwGenerateKey (pendingFromAttrs st (stampGenerated ckoSecretKey mech attrs))
                  , FxGenerateKey mech BS.empty (encodeGenArgs (GenAes (fromIntegral n)))
                  )
              | otherwise -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
                  ("AES length must be 16, 24 or 32 bytes: " ++ show n))
            Just _ -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
              "AES value length is malformed")
            Nothing -> Left (KeyDeny CKR_TEMPLATE_INCOMPLETE
              "AES keygen needs CKA_VALUE_LEN")
      | mech == des3KeyGenMech = case checkKeyTemplate ckoSecretKey ckkDes3 tmpl of
          Left deny -> Left deny
          Right attrs -> case Map.lookup AttrValueLen attrs of
            Just (ValULong n)
              | n `elem` [16, 24] -> Right
                  ( PwGenerateKey (pendingFromAttrs st (stampGenerated ckoSecretKey mech attrs))
                  , FxGenerateKey mech BS.empty (encodeGenArgs (GenBytes (fromIntegral n)))
                  )
              | otherwise -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
                  ("DES3 length must be 16 or 24 bytes: " ++ show n))
            Just _ -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
              "DES3 value length is malformed")
            -- A missing length mints three-key (24 bytes): the
            -- mechanism's headline size (16 selects the two-key
            -- variant explicitly). Fixed-size keygen defaults where
            -- the size is natural; AES keeps its required length.
            Nothing -> Right
              ( PwGenerateKey (pendingFromAttrs st (stampGenerated ckoSecretKey mech attrs))
              , FxGenerateKey mech BS.empty (encodeGenArgs (GenBytes 24))
              )
      | mech == hotpKeyGenMech = case checkKeyTemplate ckoSecretKey ckkHotp tmpl of
          Left deny -> Left deny
          Right attrs -> case Map.lookup AttrValueLen attrs of
            Just (ValULong n)
              | n >= fromIntegral hotpKeygenMinBytes && n <= fromIntegral hotpKeygenMaxBytes -> Right
                  ( PwGenerateKey (pendingFromAttrs st (stampGenerated ckoSecretKey mech attrs))
                  , FxGenerateKey mech BS.empty (encodeGenArgs (GenBytes (fromIntegral n)))
                  )
              | otherwise -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
                  ("HOTP length must be " ++ show hotpKeygenMinBytes ++ " to "
                    ++ show hotpKeygenMaxBytes ++ " bytes: " ++ show n))
            Just _ -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
              "HOTP value length is malformed")
            Nothing -> Left (KeyDeny CKR_TEMPLATE_INCOMPLETE
              "HOTP keygen needs CKA_VALUE_LEN")
      -- BLAKE2B-512 HMAC keys mint at the digest width only: the
      -- per-width keygen split (160\/256\/384\/512) exists to fix
      -- the size, so any other length is inconsistent and a
      -- missing length is incomplete (the HOTP explicit-length
      -- precedent, not the DES3 default).
      -- Table-driven sweep (slice 11a): one arm serves every
      -- fixed, discrete and ranged symmetric keygen (HMAC keygens
      -- take a VALUE_LEN-sized key per the standard, so the old
      -- exact-64 BLAKE2B-512 arm moved into the table).
      | Just (label, kt, lens, parity) <- lookup mech keygenSweepSpecs =
          planSweepKeygen st mech label kt lens parity tmpl
      -- ChaCha20 keys mint at 256 bits only: the single-width
      -- keygen fixes the size, so any other length is
      -- inconsistent and a missing length is incomplete (the
      -- HOTP explicit-length precedent, not the DES3 default).
      | mech == chacha20KeyGenMech = case checkKeyTemplate ckoSecretKey ckkChacha20 tmpl of
          Left deny -> Left deny
          Right attrs -> case Map.lookup AttrValueLen attrs of
            Just (ValULong n)
              | n == 32 -> Right
                  ( PwGenerateKey (pendingFromAttrs st (stampGenerated ckoSecretKey mech attrs))
                  , FxGenerateKey mech BS.empty (encodeGenArgs (GenBytes 32))
                  )
              | otherwise -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
                  ("ChaCha20 length must be 32 bytes: " ++ show n))
            Just _ -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
              "ChaCha20 value length is malformed")
            Nothing -> Left (KeyDeny CKR_TEMPLATE_INCOMPLETE
              "ChaCha20 keygen needs CKA_VALUE_LEN")
      | mech == genericSecretKeyGenMech =
          case checkKeyTemplate ckoSecretKey ckkGenericSecret tmpl of
          Left deny -> Left deny
          Right attrs -> case Map.lookup AttrValueLen attrs of
            Just (ValULong n)
              | n >= fromIntegral genericSecretKeygenMinBytes && n <= fromIntegral genericSecretKeygenMaxBytes -> Right
                  ( PwGenerateKey (pendingFromAttrs st (stampGenerated ckoSecretKey mech attrs))
                  , FxGenerateKey mech BS.empty (encodeGenArgs (GenBytes (fromIntegral n)))
                  )
              | otherwise -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
                  ("generic-secret length must be " ++ show genericSecretKeygenMinBytes ++ " to "
                    ++ show genericSecretKeygenMaxBytes ++ " bytes: " ++ show n))
            Just _ -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
              "generic-secret value length is malformed")
            Nothing -> Left (KeyDeny CKR_TEMPLATE_INCOMPLETE
              "generic-secret keygen needs CKA_VALUE_LEN")
      | otherwise =
          Left (KeyDeny CKR_MECHANISM_INVALID
            ("not a key mechanism: " ++ show mech))

-- | The DSA @(L, N)@ size pair for parameter generation:
-- @AttrPrimeBits@ is required, @AttrSubprimeBits@ defaults per L
-- (@{1024: 160, 2048: 256, 3072: 256}@). Served pairs are the
-- (L, N) set the backends approve -- on the OpenSSL backend
-- (1024, 160) runs 186-2 and (2048, 224), (2048, 256),
-- (3072, 256) run 186-4 (synthetic emits opaque test bytes) --
-- anything else is inconsistent,
-- mirroring 'rsaBitsOf' (unserved keygen sizes refuse as
-- inconsistent, never silently substituted). Shared by DSA and
-- X9.42 DH parameter generation (the same FIPS 186 math); the
-- label names the mechanism in refusal strings. A missing
-- @CKA_SUBPRIME_BITS@ defaults per L for DSA (the headline
-- sizes) but is incomplete for X9.42 DH (the oracle requires
-- it: @test_parameter_gen_rejects_missing_subprime_bits@).
fips186ParamSizes
  :: String -> Bool -> Map AttributeType AttributeValue -> Either KeyDeny (Int, Int)
fips186ParamSizes label requireSub attrs = case Map.lookup AttrPrimeBits attrs of
  Just (ValULong l)
    | l == 1024 || l == 2048 || l == 3072 -> case Map.lookup AttrSubprimeBits attrs of
        Nothing
          | requireSub -> Left (KeyDeny CKR_TEMPLATE_INCOMPLETE
              (label ++ " parameter generation needs CKA_SUBPRIME_BITS"))
          | otherwise -> Right (fromIntegral l, dflt (fromIntegral l))
        Just (ValULong n)
          | (fromIntegral l, fromIntegral n) `elem` served ->
              Right (fromIntegral l, fromIntegral n)
          | otherwise -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
              (label ++ " (L, N) pair out of range: " ++ show (l, n)))
        Just _ -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
          (label ++ " subprime bits are malformed"))
    | otherwise -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
        (label ++ " prime size out of range: " ++ show l))
  Just _ -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
    (label ++ " prime bits are malformed"))
  Nothing -> Left (KeyDeny CKR_TEMPLATE_INCOMPLETE
    (label ++ " parameter generation needs CKA_PRIME_BITS"))
  where
    served :: [(Int, Int)]
    served = [(1024, 160), (2048, 224), (2048, 256), (3072, 256)]
    dflt :: Int -> Int
    dflt 1024 = 160
    dflt 2048 = 256
    dflt _ = 256

dsaParamSizes :: Map AttributeType AttributeValue -> Either KeyDeny (Int, Int)
dsaParamSizes = fips186ParamSizes "DSA" False

dhParamSizes :: Map AttributeType AttributeValue -> Either KeyDeny (Int, Int)
dhParamSizes = fips186ParamSizes "X9.42 DH" True

dhPkcsParamSizes :: Map AttributeType AttributeValue -> Either KeyDeny (Int, Int)
dhPkcsParamSizes = fips186ParamSizes "DH PKCS" False
