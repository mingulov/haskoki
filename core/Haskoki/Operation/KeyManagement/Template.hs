{- | KeyManagement template checks: strict template validation,
usage defaults, derivation domains, generation/unwrap stamping,
byte-op protection, and object-reading policy.

Imports the Types/Codes/MechIds/Codec leaves only. Re-exported
via the shell.
-}
{-# LANGUAGE OverloadedStrings #-}
module Haskoki.Operation.KeyManagement.Template
  ( ensureTemplateClass
  , checkKeyTemplate
  , checkKeyTemplateAny
  , defaultUsage
  , applyRules
  , DerivedDomain (..)
  , secretKeyDomain
  , derivedObjectDomain
  , checkDerivedTarget
  , sealedByteOpChildOk
  , checkDataTemplate
  , stampGenerated
  , stampUnwrapped
  , pendingFromAttrs
  , ByteOpsProtection (..)
  , byteOpsProtectionOf
  , resolveByteOpsProtection
  , policyFromObject
  , keyTypeCompatible
  , keyClassCompatible
  , mechAllowed
  , rejectOf
  , internal
  , keyBytesOf
  , keygenSweepSpecs
  , planSweepKeygen
  , lenOk
  , lenDesc
  ) where

import Data.Bits ((.|.), shiftL)
import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import Data.List (find)
import Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map
import qualified Data.Text as T
import Data.Word (Word64, Word8)
import Haskoki.Attribute
  ( AttributeType (..)
  , AttributeValue (..)
  , attributeTypeByName
  , historyAttrs
  , stampKeyDefaults
  )
import Haskoki.Attribute.Generated
  ( classNameById
  , keyTypeNameById
  )
import Haskoki.Model (ObjectState (..), SessionState (..))
import Haskoki.Object
  ( RuleDeny (..)
  , TemplateError (..)
  , TemplateRule (..)
  , checkRules
  , effectiveExtractable
  , effectiveSensitive
  , findRule
  , isAsymmetricKeyType
  , mergedIsToken
  , validateTemplate
  )
import Haskoki.Operation.Effect
  ( CryptoEffect (..)
  )
import Haskoki.Operation.KeyManagement.Codec
import Haskoki.Operation.KeyManagement.Codes
import Haskoki.Operation.KeyManagement.MechIds
import Haskoki.Operation.KeyManagement.Types
import Haskoki.Outcome
  ( PlanResult (..)
  , Rejection (..)
  , StateDelta (..)
  )
import Haskoki.Recipe.Otp (hotpKeygenMaxBytes, hotpKeygenMinBytes)
import Haskoki.Registry (MechanismId (..), Operation (..))
import Haskoki.Registry.KeyMatrix (matrixKeyTypes)
import Haskoki.Types (ReturnCode (..))


-- | Default a missing template class to the mechanism-implied class.
-- Keygen, keypair, derive, and unwrap templates need not repeat the
-- class the mechanism determines (standard practice: oracle fixtures
-- omit it); a present class must still match, and wrong shapes
-- still refuse before this default applies. The stored object
-- always carries the class either way.
ensureTemplateClass
  :: Word64 -> [(AttributeType, AttributeValue)]
  -> [(AttributeType, AttributeValue)]
ensureTemplateClass wantClass tmpl
  | any ((== AttrClass) . fst) tmpl = tmpl
  | otherwise = (AttrClass, ValULong wantClass) : tmpl

-- | Check one key template against its expected class and key type:
-- a history attribute refuses before any other check,
-- contradictions reject, a missing class defaults to the
-- mechanism-implied class, a class that is present but wrong is
-- inconsistent, then the template rule for the @(class, key-type)@
-- context enforces required/forbidden presence, and a missing key
-- type defaults to the mechanism's key.
checkKeyTemplate
  :: Word64 -> Word64 -> [(AttributeType, AttributeValue)]
  -> Either KeyDeny (Map AttributeType AttributeValue)
checkKeyTemplate wantClass wantKey tmpl
  | wantClass == ckoSecretKey && isAsymmetricKeyType wantKey =
      Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
        "asymmetric key type on a secret template")
  | Just (t, _) <- find ((`elem` historyAttrs) . fst) tmpl =
      Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
        ("history attribute not allowed in key template: " ++ show t))
  | otherwise =
  case validateTemplate (ensureTemplateClass wantClass tmpl) of
  Left (TemplateContradiction t) -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
    ("contradictory attribute: " ++ show t))
  Left (TemplateWrongType t) -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
    ("wrong shape for attribute: " ++ show t))
  Left TemplateIncomplete -> Left (KeyDeny CKR_TEMPLATE_INCOMPLETE
    "template is missing the class")
  Right attrs -> case Map.lookup AttrClass attrs of
    Just (ValULong c)
      | c /= wantClass -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
          ("template class " ++ show c ++ " is not " ++ show wantClass))
      | otherwise -> case applyRules wantClass wantKey attrs of
          Left deny -> Left deny
          Right () -> case Map.lookup AttrKeyType attrs of
            Nothing -> Right (defaultUsage wantClass wantKey
              (Map.insert AttrKeyType (ValULong wantKey) attrs))
            Just (ValULong k)
              | k == wantKey -> Right (defaultUsage wantClass wantKey attrs)
              | otherwise -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
                  ("template key type " ++ show k ++ " is not " ++ show wantKey))
            Just _ -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
              "template key type is malformed")
    _ -> Left (KeyDeny CKR_TEMPLATE_INCOMPLETE "template is missing the class")

-- | Check one key template against its expected class with any key
-- type: a history attribute refuses before any other check,
-- contradictions reject, a missing class defaults to the
-- mechanism-implied class, a class that is present but wrong is
-- inconsistent, an asymmetric key type on a secret class is
-- inconsistent, and a missing key type defaults to the caller's
-- default. Derivation templates use this (derived keys span key
-- types); generation and KEM use the strict 'checkKeyTemplate'.
checkKeyTemplateAny
  :: Word64 -> Word64 -> [(AttributeType, AttributeValue)]
  -> Either KeyDeny (Map AttributeType AttributeValue)
checkKeyTemplateAny wantClass defaultKey tmpl
  | Just (t, _) <- find ((`elem` historyAttrs) . fst) tmpl =
      Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
        ("history attribute not allowed in key template: " ++ show t))
  | otherwise =
  case validateTemplate (ensureTemplateClass wantClass tmpl) of
  Left (TemplateContradiction t) -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
    ("contradictory attribute: " ++ show t))
  Left (TemplateWrongType t) -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
    ("wrong shape for attribute: " ++ show t))
  Left TemplateIncomplete -> Left (KeyDeny CKR_TEMPLATE_INCOMPLETE
    "template is missing the class")
  Right attrs -> case Map.lookup AttrClass attrs of
    Just (ValULong c)
      | c /= wantClass -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
          ("template class " ++ show c ++ " is not " ++ show wantClass))
      | otherwise -> case Map.lookup AttrKeyType attrs of
          Nothing -> Right (Map.insert AttrKeyType (ValULong defaultKey) attrs)
          Just (ValULong k)
            | c == ckoSecretKey && isAsymmetricKeyType k ->
                Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
                  "asymmetric key type on a secret template")
            | otherwise -> Right attrs
          Just _ -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
            "template key type is malformed")
    _ -> Left (KeyDeny CKR_TEMPLATE_INCOMPLETE "template is missing the class")

-- | Generation-time usage defaults: absent operation flags
-- default TRUE on the strict key-template path (single/pair
-- generation and KEM outputs), so minimal templates mint usable
-- keys — except @CKA_DERIVE@, which defaults FALSE per the
-- PKCS#11 common key attributes table (derivation is opt-in);
-- explicit values — including FALSE — always win
-- (left-biased union). Defaults follow the object class: public
-- keys default the public operations (encrypt\/verify\/wrap\/
-- encapsulate), private and secret keys the full set (a private
-- key serves the public operations too); non-key classes get no
-- defaults. Flags the context's generated rule forbids stay
-- absent (a defaulted forbidden flag would poison re-validation:
-- detached rejoin replays stored templates through this same
-- check). This matches the oracle's minimal-template legs (which
-- generate with no usage flags and then operate) and the
-- SoftHSM/NSS generation behavior; explicit-false refusal tests
-- are unaffected. @CKA_ALWAYS_AUTHENTICATE@ is not a usage
-- permit and stays absent (false). Creation (@C_CreateObject@)
-- does not use this path and keeps absent-means-false.
defaultUsage :: Word64 -> Word64 -> Map AttributeType AttributeValue -> Map AttributeType AttributeValue
defaultUsage wantClass wantKey attrs = Map.union attrs defaults
  where
    defaults = Map.fromList (trueDefaults ++ deriveDefault)
    trueDefaults = [(t, ValBool True) | t <- usageFlags, t `notElem` forbidden]
    -- CKA_DERIVE defaults FALSE on every key class (the PKCS#11
    -- default): derivation is opt-in. Forbidden stays absent (a
    -- stored value, even false, would poison presence-based
    -- re-validation); non-key classes take no default.
    deriveDefault
      | keyClassWanted && AttrDerive `notElem` forbidden = [(AttrDerive, ValBool False)]
      | otherwise = []
    keyClassWanted =
      wantClass == ckoPublicKey || wantClass == ckoPrivateKey || wantClass == ckoSecretKey
    usageFlags
      | wantClass == ckoPublicKey =
          [AttrEncrypt, AttrVerify, AttrWrap, AttrEncapsulate]
      | wantClass == ckoPrivateKey || wantClass == ckoSecretKey =
          [ AttrEncrypt, AttrDecrypt, AttrSign, AttrVerify
          , AttrWrap, AttrUnwrap
          , AttrEncapsulate, AttrDecapsulate
          ]
      | otherwise = []
    forbidden = case (classNameById wantClass, keyTypeNameById wantKey) of
      (Just cn, Just kn) -> case findRule cn kn of
        Just rule -> [t | name <- trForbidden rule, Just t <- [attributeTypeByName name]]
        Nothing -> []
      _ -> []

-- | Enforce the generated template rule for a @(class, key-type)@
-- context selected by the planner (not by the template: the rule
-- applies even when the template omits the key type and it later
-- defaults). Contexts without a rule, or with unresolvable context
-- ids, carry no additional constraints. Missing-required denies
-- incomplete; forbidden-present denies inconsistent.
applyRules :: Word64 -> Word64 -> Map AttributeType AttributeValue -> Either KeyDeny ()
applyRules wantClass wantKey attrs =
  case (classNameById wantClass, keyTypeNameById wantKey) of
    (Just cn, Just kn) -> case findRule cn kn of
      Nothing -> Right ()
      Just rule -> case checkRules rule attrs of
        Right () -> Right ()
        Left (RuleMissingRequired n) -> Left (KeyDeny CKR_TEMPLATE_INCOMPLETE
          ("template rule " ++ T.unpack cn ++ "/" ++ T.unpack kn
            ++ " requires " ++ T.unpack n))
        Left (RuleForbiddenPresent n) -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
          ("template rule " ++ T.unpack cn ++ "/" ++ T.unpack kn
            ++ " forbids " ++ T.unpack n))
    _ -> Right ()

-- | The material-length domain of a derived object: any positive
-- length the mechanism yields, a discrete set of sizes, or an
-- inclusive byte range (PKCS#11 v3.2: a derive template may select
-- the key type, and a supplied length must fit that type).
data DerivedDomain
  = DomainAnyLength
  | DomainLengths ![Int]
  | DomainRange !Int !Int
  deriving (Eq, Show)

-- | The served secret-key destination types of a derivation and
-- their algorithm length domains (bytes). Variable-length types —
-- generic secrets, HKDF and the HMAC families — take any positive
-- length the mechanism yields (their keygen rows cap at the 255-byte
-- frame, which is a generation limit, not a key domain). AES is
-- 16\/24\/32 and DES3 24 (the unwrap and PBKD2-generation tables),
-- ChaCha20 32, HOTP the backend-enforced 16..64, RC4 1..256; every
-- other served symmetric type takes its algorithm size from the keygen sweep
-- ('keygenSweepSpecs': fixed, discrete or ranged). Unlisted types —
-- asymmetric (RSA, EC, DSA, DH, ML-KEM, ...), unserved legacy and
-- vendor numerics — have no secret-key domain ('Nothing') and refuse
-- closed.
secretKeyDomain :: Word64 -> Maybe DerivedDomain
secretKeyDomain kt
  | kt `elem` variableLength = Just DomainAnyLength
  | kt == ckkAes = Just (DomainLengths [16, 24, 32])
  | kt == ckkDes3 = Just (DomainLengths [24])
  | kt == ckkChacha20 = Just (DomainLengths [32])
  | kt == ckkHotp = Just (DomainRange hotpKeygenMinBytes hotpKeygenMaxBytes)
  -- RC4 keys are 1 to 256 bytes (the keygen row stops at its
  -- 255-byte frame).
  | kt == ckkRc4 = Just (DomainRange 1 256)
  | otherwise = case [lens | (_, (_, t, lens, _)) <- keygenSweepSpecs, t == kt] of
      KeygenFixed d : _ -> Just (DomainLengths [d])
      KeygenDiscrete ns : _ -> Just (DomainLengths ns)
      KeygenRange lo hi : _ -> Just (DomainRange lo hi)
      [] -> Nothing
  where
    variableLength =
      [ ckkGenericSecret, ckkHkdf
      , ckkSha1Hmac, ckkSha224Hmac, ckkSha256Hmac, ckkSha384Hmac
      , ckkSha512Hmac, ckkSha512_224Hmac, ckkSha512_256Hmac, ckkSha512THmac
      , ckkSha3_224Hmac, ckkSha3_256Hmac, ckkSha3_384Hmac, ckkSha3_512Hmac
      , ckkBlake2b160Hmac, ckkBlake2b256Hmac, ckkBlake2b384Hmac
      , ckkBlake2b512Hmac
      ]

-- | Resolve the destination domain of one derived object from its
-- validated attributes: data objects (HKDF-DATA) take any length; a
-- secret key takes its type's 'secretKeyDomain' (an absent type is
-- the generic default); an unserved or asymmetric key type, and any
-- other class, is a well-formed but incompatible template
-- (@CKR_TEMPLATE_INCONSISTENT@). A missing class stays incomplete
-- (the 'publishPending' rule).
derivedObjectDomain
  :: Map AttributeType AttributeValue -> Either KeyDeny DerivedDomain
derivedObjectDomain attrs = case Map.lookup AttrClass attrs of
  Just (ValULong c)
    | c == ckoData -> Right DomainAnyLength
    | c == ckoSecretKey -> case Map.lookup AttrKeyType attrs of
        Just (ValULong kt) -> case secretKeyDomain kt of
          Just d -> Right d
          Nothing -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
            ("derived key type " ++ show kt ++ " is not a served secret-key type"))
        -- An absent type is the derive default (generic secret);
        -- the planners stamp it, so only bare pending work omits it.
        Nothing -> Right DomainAnyLength
        Just _ -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
          "derived key type is malformed")
    | otherwise -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
        ("derived object class " ++ show c ++ " is not a secret key or data object"))
  _ -> Left (KeyDeny CKR_TEMPLATE_INCOMPLETE "derived object lacks a class")

-- | THE shared derive destination check: the object's resolved
-- type admits @n@ material bytes, and a declared @CKA_VALUE_LEN@
-- agrees with @n@. Planners call it on every
-- resolved template before any effect (requested length) and
-- 'finishWork' calls it on the final material before publication
-- (returned length), so neither a template nor a wrong-sized answer
-- can create an object outside its key domain. Refusals are
-- @CKR_TEMPLATE_INCONSISTENT@ (the established type\/length
-- convention; the unwrap coherence precedent).
checkDerivedTarget :: Map AttributeType AttributeValue -> Int -> Either KeyDeny ()
checkDerivedTarget attrs n = do
  d <- derivedObjectDomain attrs
  if not (admits d)
    then Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
      ("derived length " ++ show n ++ " is outside the "
        ++ show (Map.lookup AttrKeyType attrs) ++ " domain " ++ show d))
    else case Map.lookup AttrValueLen attrs of
      Just (ValULong m) | toInteger m /= toInteger n -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
        ("derived material length " ++ show n ++ " differs from CKA_VALUE_LEN "
          ++ show m))
      _ -> Right ()
  where
    admits DomainAnyLength = n >= 1
    admits (DomainLengths ns) = n `elem` ns
    admits (DomainRange lo hi) = n >= lo && n <= hi

-- | Child key types a sealed byte-op input may mint: generic
-- secrets, the HMAC families and vetted ciphers whose mechanisms
-- do not expose raw key bytes. Any other type — RC2, RC4,
-- Poly1305, DES2, DES3, DES, CAST, Salsa20 and the rest — refuses
-- closed with @CKR_TEMPLATE_INCONSISTENT@, since the child's own
-- mechanism would hand the sealed bytes back (a Poly1305 tag with
-- r = 0 is the sealed half; RC2 effective-bits stepping walks the
-- key; a known part of a DES3 key reduces the sealed bytes to
-- DES-strength search).
sealedByteOpChildOk :: Word64 -> Bool
sealedByteOpChildOk k = k `elem` sealedByteOpChildTypes
  where
    sealedByteOpChildTypes =
      [ ckkGenericSecret
      , ckkAes, ckkChacha20
      , ckkCamellia, ckkAria, ckkSeed
      , ckkSha1Hmac, ckkSha224Hmac, ckkSha256Hmac, ckkSha384Hmac
      , ckkSha512Hmac, ckkSha512_224Hmac, ckkSha512_256Hmac, ckkSha512THmac
      , ckkSha3_224Hmac, ckkSha3_256Hmac, ckkSha3_384Hmac, ckkSha3_512Hmac
      , ckkBlake2b160Hmac, ckkBlake2b256Hmac, ckkBlake2b384Hmac
      , ckkBlake2b512Hmac
      ]

-- | Check one data-object template for data-output derivations
-- (@CKM_HKDF_DATA@): a history attribute refuses before any other
-- check, contradictions and wrong shapes reject, a missing class
-- defaults to the mechanism-implied @CKO_DATA@, a class that is
-- present but wrong is a key-type contradiction (the operation
-- derives data objects, never keys), and a @CKA_KEY_TYPE@
-- attribute is inconsistent (data objects carry no key type).
checkDataTemplate
  :: Word64 -> [(AttributeType, AttributeValue)]
  -> Either KeyDeny (Map AttributeType AttributeValue)
checkDataTemplate wantData tmpl
  | Just (t, _) <- find ((`elem` historyAttrs) . fst) tmpl =
      Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
        ("history attribute not allowed in data template: " ++ show t))
  | otherwise =
  case validateTemplate (ensureTemplateClass wantData tmpl) of
  Left (TemplateContradiction t) -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
    ("contradictory attribute: " ++ show t))
  Left (TemplateWrongType t) -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
    ("wrong shape for attribute: " ++ show t))
  Left TemplateIncomplete -> Left (KeyDeny CKR_TEMPLATE_INCOMPLETE
    "template is missing the class")
  Right attrs -> case Map.lookup AttrClass attrs of
    Just (ValULong c)
      | c /= wantData -> Left (KeyDeny CKR_KEY_TYPE_INCONSISTENT
          ("template class " ++ show c ++ " is not a data object"))
      | Map.member AttrKeyType attrs -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
          "data template must not carry CKA_KEY_TYPE")
      | otherwise -> Right attrs
    _ -> Left (KeyDeny CKR_TEMPLATE_INCOMPLETE "template is missing the class")

-- | Stamp one freshly generated key: the caller-wins protection
-- defaults plus birth history. Secret and private keys take
-- ALWAYS_SENSITIVE at the birth sensitive mark,
-- NEVER_EXTRACTABLE at the negated birth extractable mark,
-- LOCAL true and the generating mechanism; public halves take the
-- origin pair and own no history rows. Explicit caller values
-- always win. Runs after validation, before 'pendingFromAttrs',
-- so pending objects carry the final flags. Non-key classes take
-- the protection defaults only (identity there).
stampGenerated :: Word64 -> MechanismId -> Map AttributeType AttributeValue -> Map AttributeType AttributeValue
stampGenerated cls mech attrs
  | cls == ckoPublicKey =
      Map.insert AttrKeyGenMechanism (ValULong (unMechanismId mech))
        (Map.insert AttrLocal (ValBool True) filled)
  | cls == ckoPrivateKey || cls == ckoSecretKey =
      Map.insert AttrKeyGenMechanism (ValULong (unMechanismId mech))
        (Map.insert AttrLocal (ValBool True)
          (Map.insert AttrNeverExtractable (ValBool (not ext))
            (Map.insert AttrAlwaysSensitive (ValBool sens) filled)))
  | otherwise = filled
  where
    filled = stampKeyDefaults cls attrs
    sens = Map.lookup AttrSensitive filled == Just (ValBool True)
    ext = Map.lookup AttrExtractable filled == Just (ValBool True)

-- | Stamp one unwrapped key: the caller-wins unwrap defaults
-- (non-sensitive, extractable) plus import history. Unwrapped
-- material was exposed outside the token, so history and origin
-- read false. Runs after validation, before 'pendingFromAttrs'.
-- Unwrap mints secret keys only (the template class gate).
stampUnwrapped :: Map AttributeType AttributeValue -> Map AttributeType AttributeValue
stampUnwrapped attrs =
  Map.insert AttrKeyGenMechanism (ValULong maxBound)
    (Map.insert AttrLocal (ValBool False)
      (Map.insert AttrNeverExtractable (ValBool False)
        (Map.insert AttrAlwaysSensitive (ValBool False) filled)))
  where
    filled = foldr insertMissing attrs [(AttrSensitive, False), (AttrExtractable, True)]
    insertMissing (t, v) acc
      | Map.member t acc = acc
      | otherwise = Map.insert t (ValBool v) acc

-- | Pending object from validated template attributes: the token
-- flag decides the lifetime owner, the calling session the home
-- slot. Generation size parameters (@AttrModulusBits@,
-- @AttrPrimeBits@, @AttrSubprimeBits@) are dropped: the finisher
-- re-stamps the authoritative size where the object carries one
-- (RSA public @CKA_MODULUS_BITS@, domain-parameter prime widths);
-- DSA/DH key halves carry no size, so nothing is re-stamped there.
-- Everything else carries over verbatim.
pendingFromAttrs :: SessionState -> Map AttributeType AttributeValue -> PendingObject
pendingFromAttrs st attrs = PendingObject
  { poAttrs = Map.delete AttrSubprimeBits (Map.delete AttrPrimeBits (Map.delete AttrModulusBits attrs))
  , poOwner =
      if mergedIsToken attrs
        then Nothing
        else Just (ssId st)
  , poSlot = ssSlot st
  }

-- | Required byte-operation child protection (PKCS #11 3.2
-- §6.43.3–§6.43.7): sensitivity is required when any input key is
-- sensitive; nonextractability is required when any input key is
-- unextractable. Source values decide through the effective view
-- (per-class defaults), matching the readback seal and the copy
-- guard.
data ByteOpsProtection = ByteOpsProtection
  { bopSensitive :: !Bool
  , bopUnextractable :: !Bool
  } deriving (Eq, Show)

-- | Combine validated byte-operation source protection: the base
-- key plus the auxiliary key where the mechanism takes one
-- (@CKM_CONCATENATE_BASE_AND_KEY@ only; the data/offset rows pass
-- 'Nothing'). Either input can require protection; neither input
-- can waive the other's.
byteOpsProtectionOf
  :: Map AttributeType AttributeValue
  -> Maybe (Map AttributeType AttributeValue)
  -> ByteOpsProtection
byteOpsProtectionOf base mAux = ByteOpsProtection
  { bopSensitive = effectiveSensitive base || maybe False effectiveSensitive mAux
  , bopUnextractable = not (effectiveExtractable base)
      || maybe False (not . effectiveExtractable) mAux
  }

-- | Resolve one validated byte-operation caller template against
-- the required source protection: a template that explicitly
-- downgrades (sensitive true->false or extractable false->true)
-- refuses 'CKR_TEMPLATE_INCONSISTENT' (the copy-guard precedent);
-- otherwise the required flags stamp onto the template (omitted
-- attributes inherit, matching values pass through) and the merged
-- map carries into the pending object. When nothing is required
-- the template stands unchanged here; the derive merge then fills
-- omitted rows from the sources (per §6.43). Scoped to the five
-- byte-operation mechanisms only: no other derivation family
-- consults this helper.
--
-- History attributes never stamp here: only the protection pair
-- inherits (history derives in the composed derive merge).
-- Templates carrying history refuse inconsistent at the template
-- check, and reads report the effective view.
resolveByteOpsProtection
  :: ByteOpsProtection -> Map AttributeType AttributeValue
  -> Either KeyDeny (Map AttributeType AttributeValue)
resolveByteOpsProtection req attrs
  | bopSensitive req
  , Map.lookup AttrSensitive attrs == Just (ValBool False) =
      Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
        "byte-op derive cannot clear the inherited sensitive flag")
  | bopUnextractable req
  , Map.lookup AttrExtractable attrs == Just (ValBool True) =
      Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
        "byte-op derive cannot set extractable on an inherited unextractable key")
  | otherwise = Right (stamp AttrExtractable (ValBool False) (bopUnextractable req)
      (stamp AttrSensitive (ValBool True) (bopSensitive req) attrs))
  where
    stamp t v True m = Map.insert t v m
    stamp _ _ False m = m

-- | Read the usage policy off a key object: the permitted operations
-- plus the always-authenticate mark. 'Nothing' when the object
-- carries no key attributes at all (a legacy object), in
-- which case callers fall back to the caller-derived 'KeyPolicy'.
-- Absent flags read as false, per the PKCS#11 defaults.
policyFromObject :: ObjectState -> Maybe ([Operation], Bool)
policyFromObject ost
  | not (any (`Map.member` osAttrs ost) keyAttrs) = Nothing
  | otherwise = Just (permits, flag AttrAlwaysAuthenticate)
  where
    keyAttrs =
      [ AttrKeyType
      , AttrEncrypt, AttrDecrypt, AttrSign, AttrVerify
      , AttrSignRecover, AttrVerifyRecover
      , AttrWrap, AttrUnwrap, AttrDerive
      , AttrEncapsulate, AttrDecapsulate
      , AttrAlwaysAuthenticate
      ]
    flag t = Map.lookup t (osAttrs ost) == Just (ValBool True)
    permits =
      [ op
      | (t, op) <-
          [ (AttrEncrypt, OpEncrypt)
          , (AttrDecrypt, OpDecrypt)
          , (AttrSign, OpSign)
          , (AttrVerify, OpVerify)
          , (AttrSignRecover, OpSignRecover)
          , (AttrVerifyRecover, OpVerifyRecover)
          , (AttrWrap, OpWrap)
          , (AttrUnwrap, OpUnwrap)
          , (AttrDerive, OpDerive)
          , (AttrEncapsulate, OpEncapsulate)
          , (AttrDecapsulate, OpDecapsulate)
          ]
      , flag t
      ]

-- | Key-type compatibility for one @(mechanism, operation, key)@:
-- the matrix ('Haskoki.Registry.KeyMatrix.matrixKeyTypes') permits
-- the key's @CKA_KEY_TYPE@, the pair sits outside the reviewed
-- matrix, or the key carries no key type at all (the legacy seam:
-- untyped objects skip the matrix, mirroring the 'policyFromObject'
-- fallback to the caller-derived policy). 'False' only when a
-- present type contradicts a reviewed row.
keyTypeCompatible :: MechanismId -> Operation -> ObjectState -> Bool
keyTypeCompatible mech op ost = case matrixKeyTypes mech op of
  Nothing -> True
  Just tys -> case Map.lookup AttrKeyType (osAttrs ost) of
    Just (ValULong k) -> k `elem` tys
    _ -> True

-- | Class/type coherence for one @(mechanism, operation, key)@ on a
-- reviewed matrix row: an asymmetric key type lives on a
-- public\/private object and a secret key type on a secret object
-- (a secret-class object for an asymmetric mechanism is
-- incoherent, and vice versa). Pairs outside the reviewed matrix,
-- objects without a key class, and objects without a key type
-- skip the check (the same legacy seam as 'keyTypeCompatible'):
-- 'False' only when a present class and a present type contradict
-- each other on a reviewed row.
keyClassCompatible :: MechanismId -> Operation -> ObjectState -> Bool
keyClassCompatible mech op ost = case matrixKeyTypes mech op of
  Nothing -> True
  Just _ -> case (Map.lookup AttrClass (osAttrs ost), Map.lookup AttrKeyType (osAttrs ost)) of
    (Just (ValULong c), Just (ValULong k))
      | c == ckoSecretKey -> not (isAsymmetricKeyType k)
      | c == ckoPublicKey || c == ckoPrivateKey -> isAsymmetricKeyType k
      | otherwise -> True
    _ -> True

-- | Allowed-mechanism compatibility for a @(mechanism, key)@: keys
-- without @CKA_ALLOWED_MECHANISMS@ serve every mechanism; keys
-- carrying it serve exactly the listed ids. The stored value is a
-- packed little-endian @CK_MECHANISM_TYPE@ array (the frame wire
-- order); a misaligned value or a wrong shape fails closed (serves
-- nothing), since a list the token cannot parse must not grant.
mechAllowed :: MechanismId -> ObjectState -> Bool
mechAllowed (MechanismId m) ost = case Map.lookup AttrAllowedMechanisms (osAttrs ost) of
  Nothing -> True
  Just (ValBytes bs)
    | BS.length bs `mod` 8 /= 0 -> False
    | otherwise -> m `elem` decodeIds bs
  Just _ -> False
  where
    decodeIds :: ByteString -> [Word64]
    decodeIds rest
      | BS.null rest = []
      | otherwise =
          let (h, t) = BS.splitAt 8 rest
          in foldr step 0 (BS.unpack h) : decodeIds t
    step :: Word8 -> Word64 -> Word64
    step b acc = acc `shiftL` 8 .|. fromIntegral b

-- | A key-management denial as a plan outcome: no outputs, no delta.
rejectOf :: KeyDeny -> PlanResult
rejectOf (KeyDeny code why) = Reject Rejection
  { rejCode = code
  , rejOutputs = []
  , rejDelta = StateDelta []
  , rejReleases = []
  , rejReasons = [why]
  , rejCause = Nothing
  }

-- | An internal malfunction: malformed driver answers and
-- publication-arity violations. Zero objects, always.
internal :: String -> PlanResult
internal why = Reject Rejection
  { rejCode = CKR_GENERAL_ERROR
  , rejOutputs = []
  , rejDelta = StateDelta []
  , rejReleases = []
  , rejReasons = ["internal: " ++ why]
  , rejCause = Nothing
  }

-- | Read stored key material back for the driver resolver. The seal
-- does not apply here: it governs the attribute read path, while
-- crypto use of sealed keys is legal.
keyBytesOf :: ObjectState -> Maybe ByteString
keyBytesOf ost = case Map.lookup AttrValue (osAttrs ost) of
  Just (ValBytes bs) -> Just bs
  _ -> Nothing

-- | One sweep row: label (for refusal detail), key type,
-- lengths, and whether the driver sets odd DES parity (FIPS
-- 46-3: DES, DES2, CDMF only).
keygenSweepSpecs :: [(MechanismId, (String, Word64, KeygenLens, Bool))]
keygenSweepSpecs =
  [ (desKeyGenMech, ("DES", ckkDes, KeygenFixed 8, True))
  , (des2KeyGenMech, ("DES2", ckkDes2, KeygenFixed 16, True))
  , (cdmfKeyGenMech, ("CDMF", ckkCdmf, KeygenFixed 8, True))
  , (ideaKeyGenMech, ("IDEA", ckkIdea, KeygenFixed 16, False))
  , (seedKeyGenMech, ("SEED", ckkSeed, KeygenFixed 16, False))
  , (skipjackKeyGenMech, ("SKIPJACK", ckkSkipjack, KeygenFixed 12, False))
  , (batonKeyGenMech, ("BATON", ckkBaton, KeygenFixed 40, False))
  , (juniperKeyGenMech, ("JUNIPER", ckkJuniper, KeygenFixed 40, False))
  , (gost28147KeyGenMech, ("GOST28147", ckkGost28147, KeygenFixed 32, False))
  , (salsa20KeyGenMech, ("SALSA20", ckkSalsa20, KeygenFixed 32, False))
  , (poly1305KeyGenMech, ("POLY1305", ckkPoly1305, KeygenFixed 32, False))
  , (ariaKeyGenMech, ("ARIA", ckkAria, KeygenDiscrete [16, 24, 32], False))
  , (camelliaKeyGenMech, ("CAMELLIA", ckkCamellia, KeygenDiscrete [16, 24, 32], False))
  , (twofishKeyGenMech, ("TWOFISH", ckkTwofish, KeygenDiscrete [16, 24, 32], False))
  , (aesXtsKeyGenMech, ("AES-XTS", ckkAesXts, KeygenDiscrete [32, 64], False))
  , (castKeyGenMech, ("CAST", ckkCast, KeygenRange 1 8, False))
  , (cast3KeyGenMech, ("CAST3", ckkCast3, KeygenRange 1 8, False))
  , (cast128KeyGenMech, ("CAST128", ckkCast128, KeygenRange 1 16, False))
  , (rc2KeyGenMech, ("RC2", ckkRc2, KeygenRange 1 128, False))
  , (rc4KeyGenMech, ("RC4", ckkRc4, KeygenRange 1 255, False))
  , (rc5KeyGenMech, ("RC5", ckkRc5, KeygenRange 1 255, False))
  , (blowfishKeyGenMech, ("BLOWFISH", ckkBlowfish, KeygenRange 4 56, False))
  , (hkdfKeyGenMech, ("HKDF", ckkHkdf, KeygenRange 1 255, False))
  , (sha1KeyGenMech, ("SHA-1-HMAC", ckkSha1Hmac, KeygenRange 1 255, False))
  , (sha224KeyGenMech, ("SHA224-HMAC", ckkSha224Hmac, KeygenRange 1 255, False))
  , (sha256KeyGenMech, ("SHA256-HMAC", ckkSha256Hmac, KeygenRange 1 255, False))
  , (sha384KeyGenMech, ("SHA384-HMAC", ckkSha384Hmac, KeygenRange 1 255, False))
  , (sha512KeyGenMech, ("SHA512-HMAC", ckkSha512Hmac, KeygenRange 1 255, False))
  , (sha512_224KeyGenMech, ("SHA512/224-HMAC", ckkSha512_224Hmac, KeygenRange 1 255, False))
  , (sha512_256KeyGenMech, ("SHA512/256-HMAC", ckkSha512_256Hmac, KeygenRange 1 255, False))
  , (sha512TKeyGenMech, ("SHA512/t-HMAC", ckkSha512THmac, KeygenRange 1 255, False))
  , (sha3_224KeyGenMech, ("SHA3-224-HMAC", ckkSha3_224Hmac, KeygenRange 1 255, False))
  , (sha3_256KeyGenMech, ("SHA3-256-HMAC", ckkSha3_256Hmac, KeygenRange 1 255, False))
  , (sha3_384KeyGenMech, ("SHA3-384-HMAC", ckkSha3_384Hmac, KeygenRange 1 255, False))
  , (sha3_512KeyGenMech, ("SHA3-512-HMAC", ckkSha3_512Hmac, KeygenRange 1 255, False))
  , (blake2b160KeyGenMech, ("BLAKE2B-160-HMAC", ckkBlake2b160Hmac, KeygenRange 1 255, False))
  , (blake2b256KeyGenMech, ("BLAKE2B-256-HMAC", ckkBlake2b256Hmac, KeygenRange 1 255, False))
  , (blake2b384KeyGenMech, ("BLAKE2B-384-HMAC", ckkBlake2b384Hmac, KeygenRange 1 255, False))
  , (blake2b512KeyGenMech, ("BLAKE2B-512-HMAC", ckkBlake2b512Hmac, KeygenRange 1 255, False))
  ]

-- | Plan one table-driven keygen: the template check fixes the
-- class and key type, then the shape admits the length (fixed
-- sizes default when absent, anything else needs @CKA_VALUE_LEN@).
planSweepKeygen
  :: SessionState -> MechanismId -> String -> Word64 -> KeygenLens -> Bool
  -> [(AttributeType, AttributeValue)]
  -> Either KeyDeny (PendingWork, CryptoEffect)
planSweepKeygen st mech label kt lens parity tmpl =
  case checkKeyTemplate ckoSecretKey kt tmpl of
    Left deny -> Left deny
    Right attrs -> case Map.lookup AttrValueLen attrs of
      Just (ValULong n)
        | lenOk lens (fromIntegral n) ->
            Right (effect attrs (fromIntegral n))
        | otherwise -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
            (label ++ " length must be " ++ lenDesc lens ++ ": " ++ show n))
      Just _ -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
        (label ++ " value length is malformed"))
      Nothing -> case lens of
        KeygenFixed d -> Right (effect attrs d)
        _ -> Left (KeyDeny CKR_TEMPLATE_INCOMPLETE
          (label ++ " keygen needs CKA_VALUE_LEN"))
  where
    effect attrs n =
      ( PwGenerateKey (pendingFromAttrs st (stampGenerated ckoSecretKey mech attrs))
      , FxGenerateKey mech BS.empty (encodeGenArgs (args n))
      )
    args n
      | parity = GenParityBytes n
      | otherwise = GenBytes n

-- | Admit one sweep length (bytes) against its shape.
lenOk :: KeygenLens -> Int -> Bool
lenOk (KeygenFixed d) n = n == d
lenOk (KeygenDiscrete ns) n = n `elem` ns
lenOk (KeygenRange lo hi) n = n >= lo && n <= hi

-- | Refusal detail for one sweep shape.
lenDesc :: KeygenLens -> String
lenDesc (KeygenFixed d) = show d ++ " bytes"
lenDesc (KeygenDiscrete ns) = "one of " ++ show ns ++ " bytes"
lenDesc (KeygenRange lo hi) = show lo ++ " to " ++ show hi ++ " bytes"
