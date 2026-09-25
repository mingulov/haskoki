{- | Key-management planning: generation, wrap\/unwrap, derivation
and KEM finishers over one shared pending-object publication (pure).

Every planner here returns a 'KeyPlan': a denial, an immediate
'PlanResult' (length queries and short buffers, which create no
objects), or exactly one 'CryptoEffect' plus the 'PendingWork' its
answer completes. 'finishWork' runs the driver's answer against the
pending work and publishes through 'publishPending' — the ONE
atomic-publish mechanism every key, pair, unwrap, derive and
encapsulation funnels through. All templates validate before any id
or handle is allocated, and 'Haskoki.Transition.publishDelta' applies
the resulting delta atomically, so a failed call leaves zero objects.

Key material arrives in driver answers and is stored on the new
objects' 'AttrValue' ('storeMaterial'); 'keyBytesOf' reads it back
for the driver resolver. The seal ('payloadSealed') governs the
attribute READ path only: sealed keys stay usable for crypto, per
PKCS#11.

Template defaults follow PKCS#11: a missing class is incomplete, a
missing key type defaults to the mechanism's key, usage flags and
the extractable mark default to false (absent means false, and the
planners enforce strictly).

Class, key-type and mechanism ids resolve through the
generated tables ('Haskoki.Attribute.Generated',
'Haskoki.Registry.Generated') by name; no numeric ids are hand-typed
here. Strict template paths additionally enforce the generated
template rules ('Haskoki.Object.checkRules').
-}
{-# LANGUAGE OverloadedStrings #-}
module Haskoki.Operation.KeyManagement
  ( -- * Plan currency
    KeyDeny (..)
  , KeyPlan (..)
  , PendingObject (..)
  , PendingWork (..)
  , publishPending
  , finishWork
  , stampPairComponents
  , keyPairCompatible
    -- * Object reading
  , keyBytesOf
  , policyFromObject
  , keyTypeCompatible
  , mechAllowed
    -- * Class and key-type codes (spec\/vendor\/pkcs11.h)
  , ckoData
  , ckoSecretKey
  , ckoPublicKey
  , ckoPrivateKey
  , ckkRsa
  , ckkEc
  , ckkGenericSecret
  , ckkAes
  , ckkHotp
  , ckkMlKem
    -- * Mechanism ids (spec\/vendor\/pkcs11.h)
  , aesKeyGenMech
  , hotpKeyGenMech
  , genericSecretKeyGenMech
  , genericSecretKeygenMinBytes
  , genericSecretKeygenMaxBytes
  , ecKeyPairGenMech
  , rsaKeyPairGenMech
  , aesCbcMech
    -- * Shared template checks
  , checkKeyTemplate
  , checkKeyTemplateAny
  , pendingFromAttrs
    -- * Generation frames (planner \<-\> driver contract)
  , GenArgs (..)
  , encodeGenArgs
  , decodeGenArgs
  , encodeKeyPair
  , decodeKeyPair
  , encodeWrapParams
  , decodeWrapParams
    -- * Wrap padding (mirrors Haskoki.Operation.Cipher)
  , padPkcs7
  , unpadPkcs7
    -- * Planners
  , planGenerateKeyPair
  , planGenerateKey
  , planWrapKey
  , planUnwrapKey
  , planAuthWrapKey
  , planAuthUnwrapKey
  ) where

import Control.Monad (guard)
import Data.Bits ((.|.), shiftL)
import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map
import qualified Data.Text as T
import Data.Word (Word64, Word8)

import Haskoki.Attribute
  ( AttributeType (..)
  , AttributeValue (..)
  , encodeValue
  )
import Haskoki.Attribute.Generated
  ( classNameById
  , keyTypeNameById
  , mustClassId
  , mustKeyTypeId
  )
import Haskoki.Der (RsaCrt (..), parseRsaPrivate, parseRsaPublic)
import Haskoki.Model (Model (..), ObjectState (..), SessionState (..))
import Haskoki.Object
  ( RuleDeny (..)
  , TemplateError (..)
  , checkRules
  , findRule
  , objectVisible
  , resolveHandle
  , validateTemplate
  )
import Haskoki.Operation.Effect
  ( CryptoEffect (..)
  , CryptoResult (..)
  , TypedError (..)
  , interpretError
  )
import Haskoki.Outcome
  ( DeltaOp (..)
  , NativeOutput (..)
  , PlanResult (..)
  , PreparedCommit (..)
  , Rejection (..)
  , StateDelta (..)
  )
import Haskoki.Recipe.Otp (hotpKeygenMaxBytes, hotpKeygenMinBytes)
import Haskoki.Registry (MechanismId (..), Operation (..))
import Haskoki.Registry.KeyMatrix (matrixKeyTypes)
import Haskoki.Registry.Generated
  ( ckm_AES_CBC
  , ckm_AES_KEY_GEN
  , ckm_EC_KEY_PAIR_GEN
  , ckm_GENERIC_SECRET_KEY_GEN
  , ckm_HOTP_KEY_GEN
  , ckm_ML_KEM_KEY_PAIR_GEN
  , ckm_RSA_PKCS_KEY_PAIR_GEN
  )
import Haskoki.Request (OutputIntent (..), OutputRegion (..))
import Haskoki.Rules (Rules)
import Haskoki.Session (admitCode, admitObjects)
import Haskoki.Types
  ( ExternalHandle (..)
  , ObjectId (..)
  , ReturnCode (..)
  , SessionId
  , SlotId
  )

-- ---------------------------------------------------------------------------
-- Class and key-type codes
-- ---------------------------------------------------------------------------

-- | @CKO_DATA@ (generated id, resolved by name).
ckoData :: Word64
ckoData = mustClassId "CKO_DATA"

-- | @CKO_SECRET_KEY@ (generated id, resolved by name).
ckoSecretKey :: Word64
ckoSecretKey = mustClassId "CKO_SECRET_KEY"

-- | @CKO_PUBLIC_KEY@ (generated id, resolved by name).
ckoPublicKey :: Word64
ckoPublicKey = mustClassId "CKO_PUBLIC_KEY"

-- | @CKO_PRIVATE_KEY@ (generated id, resolved by name).
ckoPrivateKey :: Word64
ckoPrivateKey = mustClassId "CKO_PRIVATE_KEY"

-- | @CKK_RSA@ (generated id, resolved by name).
ckkRsa :: Word64
ckkRsa = mustKeyTypeId "CKK_RSA"

-- | @CKK_EC@ (generated id, resolved by name).
ckkEc :: Word64
ckkEc = mustKeyTypeId "CKK_EC"

-- | @CKK_GENERIC_SECRET@ (generated id, resolved by name).
ckkGenericSecret :: Word64
ckkGenericSecret = mustKeyTypeId "CKK_GENERIC_SECRET"

-- | @CKK_AES@ (generated id, resolved by name).
ckkAes :: Word64
ckkAes = mustKeyTypeId "CKK_AES"

-- | @CKK_HOTP@ (generated id, resolved by name).
ckkHotp :: Word64
ckkHotp = mustKeyTypeId "CKK_HOTP"

-- | @CKK_ML_KEM@ (generated id, resolved by name).
ckkMlKem :: Word64
ckkMlKem = mustKeyTypeId "CKK_ML_KEM"

-- ---------------------------------------------------------------------------
-- Mechanism ids
-- ---------------------------------------------------------------------------

-- | @CKM_AES_KEY_GEN@ (generated id, resolved by name).
aesKeyGenMech :: MechanismId
aesKeyGenMech = MechanismId (ckm_AES_KEY_GEN)

-- | @CKM_HOTP_KEY_GEN@ (generated id, resolved by name).
hotpKeyGenMech :: MechanismId
hotpKeyGenMech = MechanismId (ckm_HOTP_KEY_GEN)

-- | @CKM_GENERIC_SECRET_KEY_GEN@ (generated id, resolved by name).
genericSecretKeyGenMech :: MechanismId
genericSecretKeyGenMech = MechanismId (ckm_GENERIC_SECRET_KEY_GEN)

-- | Generic-secret keygen floor: a zero-length secret carries no key
-- material, so the planner refuses it as inconsistent.
genericSecretKeygenMinBytes :: Int
genericSecretKeygenMinBytes = 1

-- | Generic-secret keygen ceiling: the 'GenBytes' planner-driver frame
-- carries the length in one byte, so 255 is the representable
-- maximum. Revisit (wider frame) if a caller needs longer secrets.
genericSecretKeygenMaxBytes :: Int
genericSecretKeygenMaxBytes = 255

-- | @CKM_EC_KEY_PAIR_GEN@ (generated id, resolved by name).
ecKeyPairGenMech :: MechanismId
ecKeyPairGenMech = MechanismId (ckm_EC_KEY_PAIR_GEN)

-- | @CKM_RSA_PKCS_KEY_PAIR_GEN@ (generated id, resolved by name).
rsaKeyPairGenMech :: MechanismId
rsaKeyPairGenMech = MechanismId (ckm_RSA_PKCS_KEY_PAIR_GEN)

-- | @CKM_AES_CBC@ (the wrap mechanism: the planner pads, the
-- driver runs raw CBC; generated id, resolved by name).
aesCbcMech :: MechanismId
aesCbcMech = MechanismId (ckm_AES_CBC)

-- ---------------------------------------------------------------------------
-- Plan currency
-- ---------------------------------------------------------------------------

-- | Why a key-management call was denied.
data KeyDeny = KeyDeny
  { kdCode :: !ReturnCode
  , kdReason :: !String
  } deriving (Eq, Show)

-- | One key-management plan: a denial (no objects, no outputs), an
-- immediate outcome (length queries and short buffers, likewise
-- object-free), or exactly one effect plus the pending work its
-- answer completes.
data KeyPlan
  = KeyDenied !KeyDeny
  | KeyImmediate !PlanResult
  | KeyEffect !PendingWork !CryptoEffect
  deriving (Eq, Show)

-- | One object awaiting publication: its full attributes, its
-- lifetime owner ('Nothing' = token object) and its home slot.
data PendingObject = PendingObject
  { poAttrs :: !(Map AttributeType AttributeValue)
  , poOwner :: !(Maybe SessionId)
  , poSlot :: !SlotId
  } deriving (Eq, Show)

-- | The pending work one driver answer completes. Every variant
-- carries fully validated templates; 'finishWork' only adds the
-- driver-supplied material and publishes.
data PendingWork
  = PwGeneratePair
      { pwPub :: !PendingObject
      , pwPriv :: !PendingObject
      }
  | PwGenerateKey
      { pwKey :: !PendingObject
      }
  | PwEncaps
      { pwSecret :: !PendingObject
      , pwCtLen :: !Int
      , pwSsLen :: !Int
      }
  | PwDecaps
      { pwSecret :: !PendingObject
      }
  | PwBlobOut
      { pwRegion :: !String
      }
  | PwUnwrap
      { pwKey :: !PendingObject
      }
  | PwDerive
      { pwKeys :: ![PendingObject]
      , pwLens :: ![Int]
      }
  deriving (Eq, Show)

-- | Publish pending objects as one atomic delta: every object
-- validates before any id or handle is allocated, so a bad entry
-- fails the whole batch with zero allocation. Ids and handles
-- allocate deterministically from the model counters in list order.
publishPending
  :: Model -> SessionState -> [PendingObject] -> Either KeyDeny (StateDelta, [ExternalHandle])
publishPending model _st pos = do
  mapM_ validPending pos
  let oids = [ObjectId (mNextObject model + i) | i <- [0 .. length pos - 1]]
      hs = [ExternalHandle (mNextHandle model + i) | i <- [0 .. length pos - 1]]
      ops = concat
        [ [ DeltaCreateObjectFull oid (poAttrs po) (poOwner po) (poSlot po)
          , DeltaBindHandle h oid
          ]
        | (po, oid, h) <- zip3 pos oids hs
        ]
  pure (StateDelta ops, hs)
  where
    validPending :: PendingObject -> Either KeyDeny ()
    validPending po
      | Map.member AttrClass (poAttrs po) = Right ()
      | otherwise = Left (KeyDeny CKR_TEMPLATE_INCOMPLETE
          "pending object lacks a class")

-- | Whether a pending-work/effect pair is executable:
-- the validated constructor for executable key pairs. Each
-- 'PendingWork' shape accepts exactly the effects whose answers
-- its finisher can consume (see 'finishWork'); generation pairs
-- additionally check the framed 'GenArgs' (single-key vs
-- pair-key). Execution sites ('runKeyPlan', the async drive)
-- refuse incoherent pairs BEFORE running any effect; the
-- planners below produce only coherent pairs (the suite proves
-- it), and 'finishWork' keeps its answer-shape defenses as
-- defense in depth.
keyPairCompatible :: PendingWork -> CryptoEffect -> Bool
keyPairCompatible (PwGeneratePair _ _) (FxGenerateKey _ _ input) =
  case decodeGenArgs input of
    Just (GenEc _) -> True
    Just (GenRsa _ _) -> True
    Just (GenMlKem _) -> True
    _ -> False
keyPairCompatible (PwGenerateKey _) (FxGenerateKey _ _ input) =
  case decodeGenArgs input of
    Just (GenAes _) -> True
    Just (GenBytes _) -> True
    _ -> False
keyPairCompatible (PwBlobOut _) (FxWrap _ _ _ _) = True
keyPairCompatible (PwBlobOut _) (FxAuthWrap _ _ _ _) = True
keyPairCompatible (PwUnwrap _) (FxUnwrap _ _ _ _) = True
keyPairCompatible (PwUnwrap _) (FxAuthUnwrap _ _ _ _) = True
keyPairCompatible (PwEncaps _ _ _) (FxKemEncaps _ _ _ _) = True
keyPairCompatible (PwDecaps _) (FxKemDecaps _ _ _ _) = True
keyPairCompatible (PwDerive _ _) (FxDerive _ _ _ _ _) = True
keyPairCompatible _ _ = False

-- | Finish planned work against the driver's answer. On bytes the
-- material lands on the pending objects and the whole batch
-- publishes through 'publishPending' (all-or-nothing: a malformed
-- answer or a validation failure yields zero objects); on any
-- driver failure the mapped code rejects with an empty delta.
finishWork :: Model -> SessionState -> PendingWork -> CryptoResult -> PlanResult
finishWork model st pw res = case (pw, res) of
  (PwGeneratePair pub priv, GotBytes bs) -> case decodeKeyPair bs of
    Just (privM, Just pubM) ->
      case stampPairComponents pub priv pubM privM of
        Just (pub', priv') ->
          publish (storeMaterial pubM pub') (storeMaterial privM priv')
        Nothing -> internal "keypair answer material fails component decode"
    _ -> internal "keypair answer is not a framed private/public pair"
  (PwEncaps sec ctLen ssLen, GotBytes bs)
    | BS.length bs == ctLen + ssLen ->
        let (ct, ss) = BS.splitAt ctLen bs
        in publish1 (storeMaterial ss sec)
            [NativeOutput (RegionBytes "ciphertext" IntentNull) ct]
            ["encapsulated " ++ show ctLen ++ " ciphertext bytes"]
    | otherwise -> internal
        ("encaps answer length " ++ show (BS.length bs)
          ++ " mismatches " ++ show ctLen ++ "+" ++ show ssLen)
  (PwDecaps sec, GotBytes bs)
    | BS.length bs == 32 -> publish1 (storeMaterial bs sec) []
        ["decapsulated shared secret"]
    | otherwise -> internal
        ("decaps answer length " ++ show (BS.length bs) ++ " mismatches 32")
  (PwGenerateKey po, GotBytes bs) -> case decodeKeyPair bs of
    Just (mat, Nothing) -> publish1 (storeMaterial mat po) []
      ["generated key"]
    _ -> internal "single-key answer is not lone material"
  (PwBlobOut region, GotBytes bs) -> Immediate PreparedCommit
    { pcCode = CKR_OK
    , pcDelta = StateDelta []
    , pcPersist = []
    , pcOutputs = [NativeOutput (RegionBytes region IntentNull) bs]
    , pcReleases = []
    , pcReasons = ["wrapped blob ready"]
    }
  (PwUnwrap po, GotBytes bs) -> case unpadPkcs7 16 bs of
    Just mat -> publish1 (storeMaterial mat po) []
      ["unwrapped key"]
    Nothing -> Reject Rejection
      { rejCode = CKR_ENCRYPTED_DATA_INVALID
      , rejOutputs = []
      , rejDelta = StateDelta []
      , rejReleases = []
      , rejReasons = ["unwrap padding check failed"]
      }
  (PwDerive pos lens, GotBytes bs)
    | BS.length bs /= sum lens -> internal
        ("derive answer length " ++ show (BS.length bs)
          ++ " mismatches " ++ show (sum lens))
    | otherwise -> case publishPending model st
        [storeMaterial mat po | (po, mat) <- zip pos (splitLens lens bs)] of
        Left deny -> rejectOf deny
        Right (delta, hs) -> Immediate PreparedCommit
          { pcCode = CKR_OK
          , pcDelta = delta
          , pcPersist = []
          , pcOutputs =
              [ NativeOutput (RegionHandle "key")
                  (encodeValue (ValULong (fromIntegral (unExternalHandle h))))
              | h <- hs
              ]
          , pcReleases = []
          , pcReasons = ["derived " ++ show (length pos) ++ " keys"]
          }
  (_, GotValid _) -> internal "verdict answer to key management"
  (_, GotResource _) -> internal "resource answer to key management"
  -- A feed answer never reaches a key finisher; loud on
  -- violation (same failure class as the pre-change empty-bytes
  -- mis-shape, which failed its frame decode).
  (_, GotUnit) -> internal "unit answer to key management"
  (_, GotCryptoError e) -> Reject Rejection
    { rejCode = interpretError (TyCrypto e)
    , rejOutputs = []
    , rejDelta = StateDelta []
    , rejReleases = []
    , rejReasons = ["driver: " ++ show e]
    }
  where
    publish :: PendingObject -> PendingObject -> PlanResult
    publish pub priv = case publishPending model st [pub, priv] of
      Left deny -> rejectOf deny
      Right (delta, [pubH, privH]) -> Immediate PreparedCommit
        { pcCode = CKR_OK
        , pcDelta = delta
        , pcPersist = []
        , pcOutputs =
            [ NativeOutput (RegionHandle "public") (encodeValue (ValULong (fromIntegral (unExternalHandle pubH))))
            , NativeOutput (RegionHandle "private") (encodeValue (ValULong (fromIntegral (unExternalHandle privH))))
            ]
        , pcReleases = []
        , pcReasons = ["generated key pair"]
        }
      Right _ -> internal "pair publication arity"
    publish1 :: PendingObject -> [NativeOutput] -> [String] -> PlanResult
    publish1 po extraOutputs reasons = case publishPending model st [po] of
      Left deny -> rejectOf deny
      Right (delta, [h]) -> Immediate PreparedCommit
        { pcCode = CKR_OK
        , pcDelta = delta
        , pcPersist = []
        , pcOutputs = extraOutputs
            ++ [NativeOutput (RegionHandle "key") (encodeValue (ValULong (fromIntegral (unExternalHandle h))))]
        , pcReleases = []
        , pcReasons = reasons
        }
      Right _ -> internal "single publication arity"

-- | Store driver-supplied key material on a pending object.
storeMaterial :: ByteString -> PendingObject -> PendingObject
storeMaterial mat po = po { poAttrs = Map.insert AttrValue (ValBytes mat) (poAttrs po) }

-- | Stamp keygen components back onto a pending pair. Reads serve
-- stored attributes only (no decode-on-read path), so an RSA pair
-- must carry its CRT components: the public half gets the modulus
-- and exponent, the private half all eight PKCS#1 parts. The two
-- DER halves must agree on (n, e); any parse failure or mismatch
-- is 'Nothing' (the finisher rejects with zero objects). Other key
-- types pass through untouched.
stampPairComponents
  :: PendingObject -> PendingObject -> ByteString -> ByteString
  -> Maybe (PendingObject, PendingObject)
stampPairComponents pub priv pubM privM
  | Map.lookup AttrKeyType (poAttrs pub) /= Just (ValULong ckkRsa) =
      Just (pub, priv)
  | otherwise = do
      (n, e) <- parseRsaPublic pubM
      crt <- parseRsaPrivate privM
      guard (crtN crt == n && crtE crt == e)
      let pubA = Map.insert AttrModulus (ValBytes n)
            (Map.insert AttrPublicExponent (ValBytes e) (poAttrs pub))
          privA = Map.insert AttrModulus (ValBytes n)
            (Map.insert AttrPublicExponent (ValBytes e)
            (Map.insert AttrPrivateExponent (ValBytes (crtD crt))
            (Map.insert AttrPrime1 (ValBytes (crtP crt))
            (Map.insert AttrPrime2 (ValBytes (crtQ crt))
            (Map.insert AttrExponent1 (ValBytes (crtDp crt))
            (Map.insert AttrExponent2 (ValBytes (crtDq crt))
            (Map.insert AttrCoefficient (ValBytes (crtQinv crt))
              (poAttrs priv))))))))
      Just (pub { poAttrs = pubA }, priv { poAttrs = privA })

-- | Split concatenated derived material at the planned lengths.
splitLens :: [Int] -> ByteString -> [ByteString]
splitLens [] _ = []
splitLens (n : ns) bs =
  let (h, t) = BS.splitAt n bs
  in h : splitLens ns t

-- | Read stored key material back for the driver resolver. The seal
-- does not apply here: it governs the attribute read path, while
-- crypto use of sealed keys is legal.
keyBytesOf :: ObjectState -> Maybe ByteString
keyBytesOf ost = case Map.lookup AttrValue (osAttrs ost) of
  Just (ValBytes bs) -> Just bs
  _ -> Nothing

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
  }

-- ---------------------------------------------------------------------------
-- Shared template checks
-- ---------------------------------------------------------------------------

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
-- contradictions reject, a missing class defaults to the
-- mechanism-implied class, a class that is present but wrong is
-- inconsistent, then the template rule for the @(class, key-type)@
-- context enforces required/forbidden presence, and a missing key
-- type defaults to the mechanism's key.
checkKeyTemplate
  :: Word64 -> Word64 -> [(AttributeType, AttributeValue)]
  -> Either KeyDeny (Map AttributeType AttributeValue)
checkKeyTemplate wantClass wantKey tmpl =
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
            Nothing -> Right (Map.insert AttrKeyType (ValULong wantKey) attrs)
            Just (ValULong k)
              | k == wantKey -> Right attrs
              | otherwise -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
                  ("template key type " ++ show k ++ " is not " ++ show wantKey))
            Just _ -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
              "template key type is malformed")
    _ -> Left (KeyDeny CKR_TEMPLATE_INCOMPLETE "template is missing the class")

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

-- | Check one key template against its expected class with any key
-- type: contradictions reject, a missing class defaults to the
-- mechanism-implied class, a class that is present but wrong is
-- inconsistent, and a missing key type defaults to the caller's
-- default. Derivation templates use this (derived keys span key
-- types); generation and KEM use the strict 'checkKeyTemplate'.
checkKeyTemplateAny
  :: Word64 -> Word64 -> [(AttributeType, AttributeValue)]
  -> Either KeyDeny (Map AttributeType AttributeValue)
checkKeyTemplateAny wantClass defaultKey tmpl =
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
          Just (ValULong _) -> Right attrs
          Just _ -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
            "template key type is malformed")
    _ -> Left (KeyDeny CKR_TEMPLATE_INCOMPLETE "template is missing the class")

-- | Pending object from validated template attributes: the token
-- flag decides the lifetime owner, the calling session the home
-- slot. Generation parameters that are not stored key attributes
-- (@AttrModulusBits@) are dropped; everything else carries over
-- verbatim.
pendingFromAttrs :: SessionState -> Map AttributeType AttributeValue -> PendingObject
pendingFromAttrs st attrs = PendingObject
  { poAttrs = Map.delete AttrModulusBits attrs
  , poOwner =
      if Map.lookup AttrToken attrs == Just (ValBool True)
        then Nothing
        else Just (ssId st)
  , poSlot = ssSlot st
  }

-- ---------------------------------------------------------------------------
-- Generation frames (planner <-> driver contract)
-- ---------------------------------------------------------------------------

-- | Key-generation arguments framed for the driver: AES length in
-- bytes, EC curve name, RSA modulus bits plus public exponent, the
-- ML-KEM parameter set (512\/768\/1024), or an opaque secret length
-- in bytes (HOTP).
data GenArgs
  = GenAes !Int
  | GenEc !ByteString
  | GenRsa !Int !Integer
  | GenMlKem !Int
  | GenBytes !Int
  deriving (Eq, Show)

-- | Frame generation arguments: @tag:u8 ...@ with tag 0 AES
-- (@len:u8@), 1 EC (curve bytes), 2 RSA (@bits:u64be exp:u64be@),
-- 3 ML-KEM (@alg:u16be@), 4 opaque secret bytes (@len:u8@).
encodeGenArgs :: GenArgs -> ByteString
encodeGenArgs args = case args of
  GenAes n -> BS.singleton 0 <> BS.singleton (fromIntegral n)
  GenEc curve -> BS.singleton 1 <> curve
  GenRsa bits e -> BS.singleton 2 <> u64be (fromIntegral bits) <> u64be (fromIntegral e)
  GenMlKem alg -> BS.singleton 3 <> BS.pack
    [fromIntegral (alg `div` 256), fromIntegral (alg `mod` 256)]
  GenBytes n -> BS.singleton 4 <> BS.singleton (fromIntegral n)

-- | Parse framed generation arguments. Short frames, unknown tags
-- and trailing bytes all fail.
decodeGenArgs :: ByteString -> Maybe GenArgs
decodeGenArgs bs = case BS.uncons bs of
  Just (0, rest) -> case BS.unpack rest of
    [n] -> Just (GenAes (fromIntegral n))
    _ -> Nothing
  Just (1, curve)
    | not (BS.null curve) -> Just (GenEc curve)
    | otherwise -> Nothing
  Just (2, rest)
    | BS.length rest == 16 ->
        let (bBits, bExp) = BS.splitAt 8 rest
        in Just (GenRsa (fromInteger (foldBE bBits)) (foldBE bExp))
    | otherwise -> Nothing
  Just (3, rest) -> case BS.unpack rest of
    [hi, lo] -> Just (GenMlKem (fromIntegral hi * 256 + fromIntegral lo))
    _ -> Nothing
  Just (4, rest) -> case BS.unpack rest of
    [n] -> Just (GenBytes (fromIntegral n))
    _ -> Nothing
  _ -> Nothing

-- | 8-byte big-endian framing.
u64be :: Int -> ByteString
u64be n = BS.pack
  [ fromIntegral (n `div` 72057594037927936 `mod` 256)
  , fromIntegral (n `div` 281474976710656 `mod` 256)
  , fromIntegral (n `div` 1099511627776 `mod` 256)
  , fromIntegral (n `div` 4294967296 `mod` 256)
  , fromIntegral (n `div` 16777216 `mod` 256)
  , fromIntegral (n `div` 65536 `mod` 256)
  , fromIntegral (n `div` 256 `mod` 256)
  , fromIntegral (n `mod` 256)
  ]

-- | Big-endian fold computed in 'Integer' so large values never wrap.
foldBE :: ByteString -> Integer
foldBE = BS.foldl' (\acc b -> acc * 256 + fromIntegral b) 0

-- | Frame a keygen answer: @privLen:u32be priv pub?@. A single key
-- carries no public half; a pair always carries both.
encodeKeyPair :: ByteString -> Maybe ByteString -> ByteString
encodeKeyPair priv mPub =
  let n = BS.length priv
  in BS.pack
    [ fromIntegral (n `div` 16777216 `mod` 256)
    , fromIntegral (n `div` 65536 `mod` 256)
    , fromIntegral (n `div` 256 `mod` 256)
    , fromIntegral (n `mod` 256)
    ] <> priv <> maybe BS.empty id mPub

-- | Parse a framed keygen answer. A short length prefix, a length
-- overrun, or a length that lies all fail.
decodeKeyPair :: ByteString -> Maybe (ByteString, Maybe ByteString)
decodeKeyPair bs
  | BS.length bs < 4 = Nothing
  | otherwise =
      let (bLen, rest) = BS.splitAt 4 bs
          n = fromInteger (foldBE bLen)
      in if BS.length rest < n
        then Nothing
        else let (priv, pub) = BS.splitAt n rest
             in Just (priv, if BS.null pub then Nothing else Just pub)

-- | Frame authenticated-wrap parameters: @ivLen:u32be iv aad@.
encodeWrapParams :: ByteString -> ByteString -> ByteString
encodeWrapParams iv aad =
  let n = BS.length iv
  in BS.pack
    [ fromIntegral (n `div` 16777216 `mod` 256)
    , fromIntegral (n `div` 65536 `mod` 256)
    , fromIntegral (n `div` 256 `mod` 256)
    , fromIntegral (n `mod` 256)
    ] <> iv <> aad

-- | Parse framed authenticated-wrap parameters. A short prefix or
-- an overrun length fails.
decodeWrapParams :: ByteString -> Maybe (ByteString, ByteString)
decodeWrapParams bs
  | BS.length bs < 4 = Nothing
  | otherwise =
      let (bLen, rest) = BS.splitAt 4 bs
          n = fromInteger (foldBE bLen)
      in if BS.length rest < n
        then Nothing
        else Just (BS.splitAt n rest)

-- ---------------------------------------------------------------------------
-- Wrap padding
-- ---------------------------------------------------------------------------

-- | Pad one wrap payload with PKCS#7. This mirrors
-- 'Haskoki.Operation.Cipher.pkcs7Pad' exactly (duplicated because
-- that module plans cipher slots while this one must stay importable
-- from the init policy without a cycle); 'KeyManagementSpec'
-- cross-checks both on every sample.
padPkcs7 :: Int -> ByteString -> Maybe ByteString
padPkcs7 block bs
  | block < 1 || block > 255 = Nothing
  | otherwise = Just (bs <> BS.replicate n (fromIntegral n))
  where
    n = block - (BS.length bs `mod` block)

-- | Strip PKCS#7 padding, checking the framing strictly. Mirrors
-- 'Haskoki.Operation.Cipher.pkcs7Unpad' exactly (see 'padPkcs7').
unpadPkcs7 :: Int -> ByteString -> Maybe ByteString
unpadPkcs7 block bs = do
  guard (block >= 1 && block <= 255)
  let len = BS.length bs
  guard (len > 0 && len `mod` block == 0)
  let padByte = BS.index bs (len - 1)
      n = fromIntegral padByte
  guard (n >= 1 && n <= min block len)
  let (plain, pad) = BS.splitAt (len - n) bs
  guard (BS.all (== padByte) pad)
  pure plain

-- ---------------------------------------------------------------------------
-- Key-pair generation
-- ---------------------------------------------------------------------------

-- | Plan key-pair generation: both templates validate fully before
-- any effect plans, so a bad template yields zero objects. ML-KEM,
-- EC and RSA pair mechanisms (generated ids, resolved by name).
-- Admission gates last (parse-first, mirroring
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
            let tag = Map.insert AttrKemAlg (ValULong (fromIntegral alg))
            pure (GenMlKem alg, tag pubA, tag privA)
      | mech == ecKeyPairGenMech =
          withPair st mech ckkEc pubT privT $ \pubA privA -> do
            curve <- ecCurveOf pubA privA
            pure (GenEc curve, pubA, privA)
      | mech == rsaKeyPairGenMech =
          withPair st mech ckkRsa pubT privT $ \pubA privA -> do
            bits <- rsaBitsOf pubA privA
            e <- rsaExponentOf pubA privA
            pure (GenRsa bits e, pubA, privA)
      | otherwise =
          Left (KeyDeny CKR_MECHANISM_INVALID
            ("not a key-pair mechanism: " ++ show mech))

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
            ( PwGeneratePair (pendingFromAttrs st pubA') (pendingFromAttrs st privA')
            , FxGenerateKey mech BS.empty (encodeGenArgs args)
            )

-- | The ML-KEM parameter set for a pair: the public template's
-- @AttrKemAlg@ (default 768), which the private template inherits
-- when absent and must agree with when present.
kemAlgOf
  :: Map AttributeType AttributeValue -> Map AttributeType AttributeValue
  -> Either KeyDeny Int
kemAlgOf pubA privA = case Map.lookup AttrKemAlg pubA of
  Just (ValULong alg)
    | alg `elem` [512, 768, 1024] -> case Map.lookup AttrKemAlg privA of
        Nothing -> Right (fromIntegral alg)
        Just (ValULong alg')
          | alg' == alg -> Right (fromIntegral alg)
          | otherwise -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
              "keypair templates disagree on the KEM parameter set")
        Just _ -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
          "private KEM parameter set is malformed")
    | otherwise -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
        ("unknown KEM parameter set: " ++ show alg))
  Just _ -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
    "public KEM parameter set is malformed")
  Nothing -> case Map.lookup AttrKemAlg privA of
    Nothing -> Right 768
    Just (ValULong alg)
      | alg `elem` [512, 768, 1024] -> Right (fromIntegral alg)
      | otherwise -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
          ("unknown KEM parameter set: " ++ show alg))
    Just _ -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
      "private KEM parameter set is malformed")

-- | The EC curve for a pair: @AttrEcParams@ is required in the
-- public template (PKCS#11 names the curve there), the private
-- template inherits it when absent and must agree when present.
-- Only P-256 executes in the engine set; anything else is
-- mechanism-invalid, never silently substituted.
ecCurveOf
  :: Map AttributeType AttributeValue -> Map AttributeType AttributeValue
  -> Either KeyDeny ByteString
ecCurveOf pubA privA = case Map.lookup AttrEcParams pubA of
  Just (ValBytes curve)
    | curve == "P-256" -> case Map.lookup AttrEcParams privA of
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

-- ---------------------------------------------------------------------------
-- Single-key generation
-- ---------------------------------------------------------------------------

-- | Plan single-key generation: AES takes a 128\/192\/256-bit
-- length via @AttrValueLen@ (bytes); HOTP takes any length in the
-- recipe's 16-64 byte window. The driver answer completes one
-- pending secret object. Admission gates last (parse-first):
-- mechanism, template, then the bound check just before the effect.
planGenerateKey
  :: Rules -> Model -> SessionState -> MechanismId
  -> [(AttributeType, AttributeValue)]
  -> KeyPlan
planGenerateKey rules model st mech tmpl =
  case validated of
    Left deny -> KeyDenied deny
    Right (pw, fx) ->
      case admitObjects rules (Map.size (mObjects model)) 1 of
        Left deny -> KeyDenied (KeyDeny (admitCode deny)
          ("admission denied: " ++ show deny))
        Right () -> KeyEffect pw fx
  where
    validated
      | mech == aesKeyGenMech = case checkKeyTemplate ckoSecretKey ckkAes tmpl of
          Left deny -> Left deny
          Right attrs -> case Map.lookup AttrValueLen attrs of
            Just (ValULong n)
              | n `elem` [16, 24, 32] -> Right
                  ( PwGenerateKey (pendingFromAttrs st attrs)
                  , FxGenerateKey mech BS.empty (encodeGenArgs (GenAes (fromIntegral n)))
                  )
              | otherwise -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
                  ("AES length must be 16, 24 or 32 bytes: " ++ show n))
            Just _ -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
              "AES value length is malformed")
            Nothing -> Left (KeyDeny CKR_TEMPLATE_INCOMPLETE
              "AES keygen needs CKA_VALUE_LEN")
      | mech == hotpKeyGenMech = case checkKeyTemplate ckoSecretKey ckkHotp tmpl of
          Left deny -> Left deny
          Right attrs -> case Map.lookup AttrValueLen attrs of
            Just (ValULong n)
              | n >= fromIntegral hotpKeygenMinBytes && n <= fromIntegral hotpKeygenMaxBytes -> Right
                  ( PwGenerateKey (pendingFromAttrs st attrs)
                  , FxGenerateKey mech BS.empty (encodeGenArgs (GenBytes (fromIntegral n)))
                  )
              | otherwise -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
                  ("HOTP length must be " ++ show hotpKeygenMinBytes ++ " to "
                    ++ show hotpKeygenMaxBytes ++ " bytes: " ++ show n))
            Just _ -> Left (KeyDeny CKR_TEMPLATE_INCONSISTENT
              "HOTP value length is malformed")
            Nothing -> Left (KeyDeny CKR_TEMPLATE_INCOMPLETE
              "HOTP keygen needs CKA_VALUE_LEN")
      | mech == genericSecretKeyGenMech =
          case checkKeyTemplate ckoSecretKey ckkGenericSecret tmpl of
          Left deny -> Left deny
          Right attrs -> case Map.lookup AttrValueLen attrs of
            Just (ValULong n)
              | n >= fromIntegral genericSecretKeygenMinBytes && n <= fromIntegral genericSecretKeygenMaxBytes -> Right
                  ( PwGenerateKey (pendingFromAttrs st attrs)
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

-- ---------------------------------------------------------------------------
-- Wrap and unwrap
-- ---------------------------------------------------------------------------

-- | Resolve a wrapping key: the handle resolves to a visible object
-- carrying the required usage mark and stored material. Every
-- caller is an AES-CBC wrap/unwrap path, so the key must be an AES
-- secret key; anything else (EC/RSA halves, generic secrets) is a
-- key-type refusal, never a silent coercion of foreign material.
withWrappingKey
  :: Model -> SessionState -> AttributeType -> String -> ExternalHandle
  -> Either KeyDeny (ObjectId, ByteString)
withWrappingKey model st usage label h = case resolveHandle model h of
  Nothing -> Left (KeyDeny CKR_OBJECT_HANDLE_INVALID
    "unknown or destroyed wrapping-key handle")
  Just ost
    | not (objectVisible st ost) -> Left (KeyDeny CKR_OBJECT_HANDLE_INVALID
        "wrapping key not visible in this session")
    | Map.lookup usage (osAttrs ost) /= Just (ValBool True) ->
        Left (KeyDeny CKR_KEY_FUNCTION_NOT_PERMITTED
          ("wrapping key does not permit " ++ label))
    | Map.lookup AttrClass (osAttrs ost) /= Just (ValULong ckoSecretKey) ||
      Map.lookup AttrKeyType (osAttrs ost) /= Just (ValULong ckkAes) ->
        Left (KeyDeny (if usage == AttrWrap
                        then CKR_WRAPPING_KEY_TYPE_INCONSISTENT
                        else CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT)
          ("wrapping key is not an AES secret key: " ++ label))
    | otherwise -> case keyBytesOf ost of
        Just mat -> Right (osId ost, mat)
        Nothing -> Left (KeyDeny CKR_GENERAL_ERROR
          "wrapping key lacks material")

-- | Resolve a wrap target: the handle resolves to a visible
-- extractable object carrying stored material.
withWrapTarget
  :: Model -> SessionState -> ExternalHandle
  -> Either KeyDeny ByteString
withWrapTarget model st h = case resolveHandle model h of
  Nothing -> Left (KeyDeny CKR_OBJECT_HANDLE_INVALID
    "unknown or destroyed target handle")
  Just ost
    | not (objectVisible st ost) -> Left (KeyDeny CKR_OBJECT_HANDLE_INVALID
        "target not visible in this session")
    | Map.lookup AttrExtractable (osAttrs ost) /= Just (ValBool True) ->
        Left (KeyDeny CKR_KEY_UNEXTRACTABLE "target is not extractable")
    | otherwise -> case keyBytesOf ost of
        Just mat -> Right mat
        Nothing -> Left (KeyDeny CKR_KEY_NOT_WRAPPABLE
          "target carries no key material")

-- | Plan one wrap: the wrapping key needs the wrap mark, the target
-- must be extractable. Length queries and short buffers answer the
-- padded length and plan no crypto; a sufficient buffer plans one
-- wrap effect over the padded material.
planWrapKey
  :: Model -> SessionState -> MechanismId -> ByteString
  -> ExternalHandle -> ExternalHandle -> OutputIntent
  -> KeyPlan
planWrapKey model st mech iv wrapH targetH intent
  | mech /= aesCbcMech =
      KeyDenied (KeyDeny CKR_MECHANISM_INVALID
        ("not a wrap mechanism: " ++ show mech))
  | BS.length iv /= 16 =
      KeyDenied (KeyDeny CKR_ARGUMENTS_BAD "AES-CBC wrap needs a 16-byte IV")
  | otherwise = case withWrappingKey model st AttrWrap "wrapping" wrapH of
      Left deny -> KeyDenied deny
      Right (wrapOid, _) -> case withWrapTarget model st targetH of
        Left deny -> KeyDenied deny
        Right mat -> case padPkcs7 16 mat of
          Nothing -> KeyDenied (KeyDeny CKR_GENERAL_ERROR
            "wrap payload escapes the PKCS#7 range")
          Just padded ->
            let blobLen = BS.length padded
                lenOut = NativeOutput (RegionBytes "wrapped" intent)
                  (encodeValue (ValULong (fromIntegral blobLen)))
            in case intent of
              IntentNull -> KeyImmediate (Immediate PreparedCommit
                { pcCode = CKR_OK
                , pcDelta = StateDelta []
                , pcPersist = []
                , pcOutputs = [lenOut]
                , pcReleases = []
                , pcReasons = ["wrap length query"]
                })
              IntentBuffer cap
                | cap < fromIntegral blobLen -> KeyImmediate (Reject Rejection
                    { rejCode = CKR_BUFFER_TOO_SMALL
                    , rejOutputs = [lenOut]
                    , rejDelta = StateDelta []
                    , rejReleases = []
                    , rejReasons = ["short buffer"]
                    })
                | otherwise -> KeyEffect (PwBlobOut "wrapped")
                    (FxWrap mech (Just wrapOid) iv padded)

-- | Plan one unwrap: the wrapping key needs the unwrap mark, the
-- blob must be block-aligned, and the template must name the new
-- key's class and key type explicitly (the blob carries no header).
-- Admission gates last (parse-first): mechanism, IV, blob,
-- key, template, then the bound check just before the effect.
planUnwrapKey
  :: Rules -> Model -> SessionState -> MechanismId -> ByteString
  -> ExternalHandle -> ByteString -> [(AttributeType, AttributeValue)]
  -> KeyPlan
planUnwrapKey rules model st mech iv wrapH blob tmpl =
  case validated of
    Left deny -> KeyDenied deny
    Right (pw, fx) ->
      case admitObjects rules (Map.size (mObjects model)) 1 of
        Left deny -> KeyDenied (KeyDeny (admitCode deny)
          ("admission denied: " ++ show deny))
        Right () -> KeyEffect pw fx
  where
    validated
      | mech /= aesCbcMech =
          Left (KeyDeny CKR_MECHANISM_INVALID
            ("not a wrap mechanism: " ++ show mech))
      | BS.length iv /= 16 =
          Left (KeyDeny CKR_ARGUMENTS_BAD "AES-CBC unwrap needs a 16-byte IV")
      | BS.null blob || BS.length blob `mod` 16 /= 0 =
          Left (KeyDeny CKR_ARGUMENTS_BAD "wrapped blob is not block-aligned")
      | not (any ((== AttrKeyType) . fst) tmpl) =
          Left (KeyDeny CKR_TEMPLATE_INCOMPLETE
            "unwrap template must name the key type")
      | otherwise = case withWrappingKey model st AttrUnwrap "unwrapping" wrapH of
          Left deny -> Left deny
          Right (wrapOid, _) -> case checkKeyTemplateAny ckoSecretKey ckkGenericSecret tmpl of
            Left deny -> Left deny
            Right attrs -> Right
              ( PwUnwrap (pendingFromAttrs st attrs)
              , FxUnwrap mech (Just wrapOid) iv blob
              )

-- | Plan one authenticated wrap: like 'planWrapKey', but the blob
-- binds associated data under a 32-byte tag, so the answered length
-- is the padded length plus 32.
planAuthWrapKey
  :: Model -> SessionState -> MechanismId -> ByteString
  -> ExternalHandle -> ExternalHandle -> ByteString -> OutputIntent
  -> KeyPlan
planAuthWrapKey model st mech iv wrapH targetH aad intent
  | mech /= aesCbcMech =
      KeyDenied (KeyDeny CKR_MECHANISM_INVALID
        ("not a wrap mechanism: " ++ show mech))
  | BS.length iv /= 16 =
      KeyDenied (KeyDeny CKR_ARGUMENTS_BAD "AES-CBC wrap needs a 16-byte IV")
  | otherwise = case withWrappingKey model st AttrWrap "wrapping" wrapH of
      Left deny -> KeyDenied deny
      Right (wrapOid, _) -> case withWrapTarget model st targetH of
        Left deny -> KeyDenied deny
        Right mat -> case padPkcs7 16 mat of
          Nothing -> KeyDenied (KeyDeny CKR_GENERAL_ERROR
            "wrap payload escapes the PKCS#7 range")
          Just padded ->
            let blobLen = BS.length padded + 32
                lenOut = NativeOutput (RegionBytes "wrapped" intent)
                  (encodeValue (ValULong (fromIntegral blobLen)))
            in case intent of
              IntentNull -> KeyImmediate (Immediate PreparedCommit
                { pcCode = CKR_OK
                , pcDelta = StateDelta []
                , pcPersist = []
                , pcOutputs = [lenOut]
                , pcReleases = []
                , pcReasons = ["authenticated-wrap length query"]
                })
              IntentBuffer cap
                | cap < fromIntegral blobLen -> KeyImmediate (Reject Rejection
                    { rejCode = CKR_BUFFER_TOO_SMALL
                    , rejOutputs = [lenOut]
                    , rejDelta = StateDelta []
                    , rejReleases = []
                    , rejReasons = ["short buffer"]
                    })
                | otherwise -> KeyEffect (PwBlobOut "wrapped")
                    (FxAuthWrap mech (Just wrapOid) (encodeWrapParams iv aad) padded)

-- | Plan one authenticated unwrap: like 'planUnwrapKey', with the
-- associated data the tag is verified against. Admission gates
-- last (parse-first): mechanism, IV, blob, key, template,
-- then the bound check just before the effect.
planAuthUnwrapKey
  :: Rules -> Model -> SessionState -> MechanismId -> ByteString
  -> ExternalHandle -> ByteString -> ByteString -> [(AttributeType, AttributeValue)]
  -> KeyPlan
planAuthUnwrapKey rules model st mech iv wrapH blob aad tmpl =
  case validated of
    Left deny -> KeyDenied deny
    Right (pw, fx) ->
      case admitObjects rules (Map.size (mObjects model)) 1 of
        Left deny -> KeyDenied (KeyDeny (admitCode deny)
          ("admission denied: " ++ show deny))
        Right () -> KeyEffect pw fx
  where
    validated
      | mech /= aesCbcMech =
          Left (KeyDeny CKR_MECHANISM_INVALID
            ("not a wrap mechanism: " ++ show mech))
      | BS.length iv /= 16 =
          Left (KeyDeny CKR_ARGUMENTS_BAD "AES-CBC unwrap needs a 16-byte IV")
      | BS.length blob < 32 || (BS.length blob - 32) `mod` 16 /= 0 =
          Left (KeyDeny CKR_ARGUMENTS_BAD "authenticated blob has a bad length")
      | not (any ((== AttrKeyType) . fst) tmpl) =
          Left (KeyDeny CKR_TEMPLATE_INCOMPLETE
            "unwrap template must name the key type")
      | otherwise = case withWrappingKey model st AttrUnwrap "unwrapping" wrapH of
          Left deny -> Left deny
          Right (wrapOid, _) -> case checkKeyTemplateAny ckoSecretKey ckkGenericSecret tmpl of
            Left deny -> Left deny
            Right attrs -> Right
              ( PwUnwrap (pendingFromAttrs st attrs)
              , FxAuthUnwrap mech (Just wrapOid) (encodeWrapParams iv aad) blob
              )
