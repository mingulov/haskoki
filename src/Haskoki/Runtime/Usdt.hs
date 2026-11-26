{-# LANGUAGE CPP #-}
{-# LANGUAGE OverloadedStrings #-}
{- | USDT emission bridge: op ids, registry mapping, and probe calls.

Two providers: Latchset-compatible @crypto_auditing@ records (one per
delivered public-key operation) and the private @haskoki@ namespace
(operation outcomes, policy rejects, job lifecycle). All probe
arguments are scalars; key material, PINs, and message bodies never
cross this module (attribute lengths and metadata only, mirroring the
JSONL 'TraceSecret' discipline).

Op ids are process-wide unique 'UsdtOpId' values with a constant low
word (@0x48534B30@, never 0, -1, or a PID); the counter saturates
instead of wrapping. Emission always happens after final delivery,
outside STM, as the last step of the delivery path: a failure before
emission skips the record, never fabricates one.

Without @HSK_USDT@ (the cabal @usdt@ flag off) every emitter is a
no-op and no probe path exists.
-}
module Haskoki.Runtime.Usdt
  ( UsdtOpId (..)
  , newUsdtOpId
  , usdtSaturations
  , PkName (..)
  , pkNameCode
  , PkKeyFacts (..)
  , noPkFacts
  , PkRecord (..)
  , PkRoute (..)
  , routeOfFunc
  , slotKindOfFunc
  , resolvePk
  , isVerdictCode
  , isVerdictRv
  , UsdtStagedMeta (..)
  , fxMechOf
  , Disposition (..)
  , dispositionCode
  , OpMode (..)
  , opModeCode
  , PolicyReason (..)
  , policyReasonCode
  , JobPhase (..)
  , jobPhaseCode
  , functionCode
  , keyFactsOf
  , hashOfMechanism
  , paddingOfMechanism
  , usdtSlotStaged
  , usdtLiveMeta
  , policyReasonOf
  , policyReasonOfRv
  , UsdtRetainMap
  , retainStagedMeta
  , takeRetainedMeta
  , dropRetainedMeta
  , purgeRetainSession
  , emitPkRecord
  , emitOperationEnd
  , emitPolicyReject
  , emitJobState
  ) where

import Data.Bits (shiftL, (.&.), (.|.))
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map
import qualified Data.Text as T
import Data.Word (Word32, Word64)
#ifndef HSK_USDT
import Data.Unique (hashUnique, newUnique)
#endif

import Haskoki.Attribute (AttributeType (..), AttributeValue (..))
import Haskoki.Attribute.Generated (mustKeyTypeId)
import Haskoki.Der (curveNameOfOid, edwardsNameOfOid,
  montgomeryNameOfOid)
import Haskoki.Model (Model, ObjectState (..), SessionState (..),
  lookupObject, lookupSession)
import Haskoki.Operation.Effect (CryptoEffect (..))
import Haskoki.Operation.State (SlotKind (..), activeMessage, commonKey,
  commonMech, commonOf, lookupSingle, msCommon, stagedOf)
import Haskoki.Registry.Generated (generatedInventory)
import Haskoki.Registry.Types (MechanismId (..))
import Haskoki.Request (FunctionId (..))
import Haskoki.ReturnCode.Generated (ReturnCode (..), returnCodeToRV)
import Haskoki.Types (SessionId)

-- ---------------------------------------------------------------------------
-- Op ids
-- ---------------------------------------------------------------------------

-- | Process-wide USDT operation id. Low word is the constant tag
-- (never 0, -1, or a PID); high word is a 1-based counter.
newtype UsdtOpId = UsdtOpId { unUsdtOpId :: Word64 }
  deriving (Eq, Ord, Show)

usdtTag :: Word64
usdtTag = 0x48534B30

mkOpId :: Word32 -> UsdtOpId
mkOpId n = UsdtOpId ((fromIntegral n `shiftL` 32) .|. usdtTag)

-- | Allocate a fresh op id, or 'Nothing' once the counter saturates
-- (no wrap, no reuse; saturations are counted). The counter is
-- C-owned (no Haskell globals, per the FFI hygiene rule); without
-- HSK_USDT the RTS unique supply stands in (never emitted).
newUsdtOpId :: IO (Maybe UsdtOpId)
#ifdef HSK_USDT
newUsdtOpId = do
  n <- c_allocOp
  pure (if n == 0 then Nothing else Just (mkOpId n))
#else
newUsdtOpId = do
  h <- hashUnique <$> newUnique
  let n = fromIntegral h .&. 0xFFFFFFFF
  pure (if n == 0 then Nothing else Just (mkOpId n))
#endif

-- | How many allocations hit saturation (practically zero).
usdtSaturations :: IO Word64
#ifdef HSK_USDT
usdtSaturations = c_saturations
#else
usdtSaturations = pure 0
#endif

-- ---------------------------------------------------------------------------
-- Codes (must match cbits/usdt.h)
-- ---------------------------------------------------------------------------

data PkName
  = PkSign | PkVerify | PkEncrypt | PkDecrypt
  | PkEncapsulate | PkDecapsulate | PkGenerate | PkDerive
  deriving (Eq, Show)

pkNameCode :: PkName -> Word32
pkNameCode n = case n of
  PkSign -> 1; PkVerify -> 2; PkEncrypt -> 3; PkDecrypt -> 4
  PkEncapsulate -> 5; PkDecapsulate -> 6; PkGenerate -> 7; PkDerive -> 8

-- | Key facts for a pk record. Zero fields omit (algorithm 0 means
-- "not a pk key type", bits 0 omits).
data PkKeyFacts = PkKeyFacts
  { pkfAlg :: !Word32
  , pkfCurve :: !Word32
  , pkfGroup :: !Word32
  , pkfBits :: !Word64
  } deriving (Eq, Show)

noPkFacts :: PkKeyFacts
noPkFacts = PkKeyFacts 0 0 0 0

-- | One Latchset record: the context name plus present fields.
data PkRecord = PkRecord
  { prName :: !PkName
  , prFacts :: !PkKeyFacts
  , prHash :: !Word32
  , prPad :: !Word32
  } deriving (Eq, Show)

-- | Metadata retained across a staged recall: everything the
-- delivery emission needs, resolved while the key is alive.
data UsdtStagedMeta = UsdtStagedMeta
  { usmFunc :: !Word32
  , usmMech :: !Word64
  , usmPk :: !(Maybe PkRecord)
  } deriving (Eq, Show)

data Disposition
  = DispDelivered | DispFailedExec | DispFailedPublish
  | DispFailedWriteback | DispAbandoned
  deriving (Eq, Show)

dispositionCode :: Disposition -> Word32
dispositionCode d = case d of
  DispDelivered -> 1; DispFailedExec -> 2; DispFailedPublish -> 3
  DispFailedWriteback -> 4; DispAbandoned -> 5

data OpMode = ModeSync | ModeAsync
  deriving (Eq, Show)

opModeCode :: OpMode -> Word32
opModeCode ModeSync = 0
opModeCode ModeAsync = 1

data PolicyReason
  = ReasonAuth | ReasonUsage | ReasonReadonly | ReasonTemplate
  | ReasonState
  deriving (Eq, Show)

policyReasonCode :: PolicyReason -> Word32
policyReasonCode r = case r of
  ReasonAuth -> 1; ReasonUsage -> 2; ReasonReadonly -> 3
  ReasonTemplate -> 4; ReasonState -> 5

data JobPhase
  = PhaseAccepted | PhaseClaimed | PhaseReady | PhaseDelivered
  | PhaseFailed | PhaseCanceled
  deriving (Eq, Show)

jobPhaseCode :: JobPhase -> Word32
jobPhaseCode p = case p of
  PhaseAccepted -> 1; PhaseClaimed -> 2; PhaseReady -> 3
  PhaseDelivered -> 4; PhaseFailed -> 5; PhaseCanceled -> 6

-- | Stable function code: 'FunctionId' is append-only ('Request.hs'),
-- so 'fromEnum' is a frozen numbering.
functionCode :: FunctionId -> Word32
functionCode = fromIntegral . fromEnum

-- ---------------------------------------------------------------------------
-- Mapping (pinned by tests)
-- ---------------------------------------------------------------------------

mechNameOf :: MechanismId -> Maybe String
mechNameOf (MechanismId w) =
  lookup w [(n, T.unpack t) | (n, t, _) <- generatedInventory]

-- | Hash code from the canonical mechanism name. Exact rules,
-- ordered most-specific first; unknown hashes omit (0).
hashOfMechanism :: MechanismId -> Word32
hashOfMechanism mid = case mechNameOf mid of
  Nothing -> 0
  Just n
    | has "SHA3_224" n -> 7
    | has "SHA3_256" n -> 8
    | has "SHA3_384" n -> 9
    | has "SHA3_512" n -> 10
    | has "SHA512_224" n -> 3
    | has "SHA512_256" n -> 4
    | has "SHA224" n -> 3
    | has "SHA256" n -> 4
    | has "SHA384" n -> 5
    | has "SHA512" n -> 6
    | has "SHA1" n -> 2
    | has "MD5" n -> 1
    | otherwise -> 0
  where
    has s h = s `isInfixOf'` h

-- | Padding code from the canonical mechanism name.
paddingOfMechanism :: MechanismId -> Word32
paddingOfMechanism mid = case mechNameOf mid of
  Nothing -> 0
  Just n
    | "PSS" `isInfixOf'` n -> 1
    | "OAEP" `isInfixOf'` n -> 2
    | "RSA_PKCS" `isInfixOf'` n
      && not ("X_509" `isInfixOf'` n)
      && not ("X9_31" `isInfixOf'` n) -> 3
    | otherwise -> 0

isInfixOf' :: String -> String -> Bool
isInfixOf' needle hay = any (needle `isPrefixOf'`) (tails' hay)
  where
    isPrefixOf' [] _ = True
    isPrefixOf' _ [] = False
    isPrefixOf' (x : xs) (y : ys) = x == y && isPrefixOf' xs ys
    tails' [] = [[]]
    tails' s@(_ : xs) = s : tails' xs

attrULong :: Map AttributeType AttributeValue -> AttributeType
  -> Maybe Word64
attrULong attrs t = case Map.lookup t attrs of
  Just (ValULong w) -> Just w
  _ -> Nothing

attrBytesLen :: Map AttributeType AttributeValue -> AttributeType
  -> Maybe Int
attrBytesLen attrs t = case Map.lookup t attrs of
  -- Length only; the bytes themselves never leave the object.
  Just (ValBytes b) -> Just (BS.length b)
  _ -> Nothing

attrBytes :: Map AttributeType AttributeValue -> AttributeType
  -> Maybe ByteString
attrBytes attrs t = case Map.lookup t attrs of
  Just (ValBytes b) -> Just b
  _ -> Nothing

-- | Crypto routes that can yield a Latchset record. The route,
-- not the mechanism family, decides eligibility (an HMAC 'sign' is
-- private-only, an RSA 'sign' is not).
data PkRoute
  = RouteSign | RouteVerify | RouteEncrypt | RouteDecrypt
  | RouteGenerate | RouteDerive | RouteWrap | RouteUnwrap
  | RouteEncapsulate | RouteDecapsulate
  deriving (Eq, Show)

-- | The pk route of a calling function, or 'Nothing' for
-- functions that never yield Latchset records (inits, updates,
-- digests, management). Message legs map by family.
routeOfFunc :: FunctionId -> Maybe PkRoute
routeOfFunc f = case f of
  F_Sign -> Just RouteSign
  F_SignFinal -> Just RouteSign
  F_SignRecover -> Just RouteSign
  F_Verify -> Just RouteVerify
  F_VerifyFinal -> Just RouteVerify
  F_VerifyRecover -> Just RouteVerify
  F_Encrypt -> Just RouteEncrypt
  F_EncryptFinal -> Just RouteEncrypt
  F_Decrypt -> Just RouteDecrypt
  F_DecryptFinal -> Just RouteDecrypt
  F_GenerateKey -> Just RouteGenerate
  F_GenerateKeyPair -> Just RouteGenerate
  F_DeriveKey -> Just RouteDerive
  F_WrapKey -> Just RouteWrap
  F_UnwrapKey -> Just RouteUnwrap
  F_EncapsulateKey -> Just RouteEncapsulate
  F_DecapsulateKey -> Just RouteDecapsulate
  F_SignMessage -> Just RouteSign
  F_SignMessageNext -> Just RouteSign
  F_MessageSignFinal -> Just RouteSign
  F_VerifyMessage -> Just RouteVerify
  F_VerifyMessageNext -> Just RouteVerify
  F_MessageVerifyFinal -> Just RouteVerify
  F_EncryptMessage -> Just RouteEncrypt
  F_EncryptMessageNext -> Just RouteEncrypt
  F_MessageEncryptFinal -> Just RouteEncrypt
  F_DecryptMessage -> Just RouteDecrypt
  F_DecryptMessageNext -> Just RouteDecrypt
  F_MessageDecryptFinal -> Just RouteDecrypt
  _ -> Nothing

-- | The classic slot a function addresses, or 'Nothing' for
-- session-wide calls (cancel), dual updates (two slots; finals
-- report each peer separately), and non-crypto legs.
slotKindOfFunc :: FunctionId -> Maybe SlotKind
slotKindOfFunc f = case f of
  F_DigestInit -> Just SlotDigest
  F_Digest -> Just SlotDigest
  F_DigestUpdate -> Just SlotDigest
  F_DigestFinal -> Just SlotDigest
  F_SignInit -> Just SlotSign
  F_Sign -> Just SlotSign
  F_SignUpdate -> Just SlotSign
  F_SignFinal -> Just SlotSign
  F_SignRecoverInit -> Just SlotSign
  F_SignRecover -> Just SlotSign
  F_VerifyInit -> Just SlotVerify
  F_Verify -> Just SlotVerify
  F_VerifyUpdate -> Just SlotVerify
  F_VerifyFinal -> Just SlotVerify
  F_VerifyRecoverInit -> Just SlotVerify
  F_VerifyRecover -> Just SlotVerify
  F_EncryptInit -> Just SlotEncrypt
  F_Encrypt -> Just SlotEncrypt
  F_EncryptUpdate -> Just SlotEncrypt
  F_EncryptFinal -> Just SlotEncrypt
  F_DecryptInit -> Just SlotDecrypt
  F_Decrypt -> Just SlotDecrypt
  F_DecryptUpdate -> Just SlotDecrypt
  F_DecryptFinal -> Just SlotDecrypt
  F_MessageEncryptInit -> Just SlotEncrypt
  F_MessageDecryptInit -> Just SlotDecrypt
  F_MessageSignInit -> Just SlotSign
  F_MessageVerifyInit -> Just SlotVerify
  F_EncryptMessage -> Just SlotEncrypt
  F_DecryptMessage -> Just SlotDecrypt
  F_SignMessage -> Just SlotSign
  F_VerifyMessage -> Just SlotVerify
  F_EncryptMessageBegin -> Just SlotEncrypt
  F_DecryptMessageBegin -> Just SlotDecrypt
  F_SignMessageBegin -> Just SlotSign
  F_VerifyMessageBegin -> Just SlotVerify
  F_EncryptMessageNext -> Just SlotEncrypt
  F_DecryptMessageNext -> Just SlotDecrypt
  F_SignMessageNext -> Just SlotSign
  F_VerifyMessageNext -> Just SlotVerify
  F_MessageEncryptFinal -> Just SlotEncrypt
  F_MessageDecryptFinal -> Just SlotDecrypt
  F_MessageSignFinal -> Just SlotSign
  F_MessageVerifyFinal -> Just SlotVerify
  _ -> Nothing

-- | Resolve a pk record for a route, or 'Nothing' for private-only
-- traffic (MACs, symmetric ciphers, KDFs, composite wraps, domain
-- parameters, public-from-private extraction).
resolvePk :: PkRoute -> MechanismId -> PkKeyFacts -> Maybe PkRecord
resolvePk route mech facts = case route of
  RouteSign
    | pkfAlg facts `elem` [1, 2, 3, 6, 7, 9] -> pk PkSign
    | otherwise -> Nothing
  RouteVerify
    | pkfAlg facts `elem` [1, 2, 3, 6, 7, 9] -> pk PkVerify
    | otherwise -> Nothing
  RouteEncrypt
    | pkfAlg facts == 1 -> pk PkEncrypt
    | otherwise -> Nothing
  RouteDecrypt
    | pkfAlg facts == 1 -> pk PkDecrypt
    | otherwise -> Nothing
  RouteGenerate
    | pkfAlg facts /= 0 -> pk PkGenerate
    | otherwise -> Nothing
  RouteDerive
    | isAgreementMech mech
      && pkfAlg facts `elem` [2, 4, 5] -> pk PkDerive
    | otherwise -> Nothing
  RouteWrap
    | isDirectRsaWrap mech -> pk PkEncrypt
    | otherwise -> Nothing
  RouteUnwrap
    | isDirectRsaWrap mech -> pk PkDecrypt
    | otherwise -> Nothing
  RouteEncapsulate -> pk PkEncapsulate
  RouteDecapsulate -> pk PkDecapsulate
  where
    pk name = Just (PkRecord name facts (hashOfMechanism mech)
      (paddingOfMechanism mech))

isAgreementMech :: MechanismId -> Bool
isAgreementMech mid = case mechNameOf mid of
  Nothing -> False
  Just n -> or
    [ "ECDH" `isInfixOf'` n
    , "DH_PKCS_DERIVE" `isInfixOf'` n
    , "X9_42_DH" `isInfixOf'` n && "KEY_PAIR_GEN" `notInfixOf'` n
    ]
  where
    notInfixOf' a b = not (a `isInfixOf'` b)

isDirectRsaWrap :: MechanismId -> Bool
isDirectRsaWrap mid = case mechNameOf mid of
  Nothing -> False
  Just n -> "RSA" `isInfixOf'` n
    && not ("AES" `isInfixOf'` n)
    && not ("KEM" `isInfixOf'` n)

-- | Definitive negative-verdict codes: crypto ran and reported.
isVerdictCode :: ReturnCode -> Bool
isVerdictCode CKR_SIGNATURE_INVALID = True
isVerdictCode CKR_ENCRYPTED_DATA_INVALID = True
isVerdictCode _ = False

-- | 'isVerdictCode' by raw CKR number.
isVerdictRv :: Word32 -> Bool
isVerdictRv w = w == returnCodeToRV CKR_SIGNATURE_INVALID
  || w == returnCodeToRV CKR_ENCRYPTED_DATA_INVALID

-- | Key facts from object attributes. Symmetric and unknown key
-- types yield 'noPkFacts' (the caller treats algorithm 0 as
-- private-only). Bits are exact key sizes where the attributes
-- determine them; EC omits bits (the curve name carries the
-- strength; order byte-widths would misstate it); PQC records are
-- algorithm-only, following the OpenSSL KEM precedent.
keyFactsOf :: ObjectState -> PkKeyFacts
keyFactsOf st = case attrULong attrs AttrKeyType of
  Just k
    | k == mustKeyTypeId "CKK_RSA" -> rsaFacts
    | k == mustKeyTypeId "CKK_EC" -> ecFacts
    | k == mustKeyTypeId "CKK_DSA" -> dsaFacts
    | k == mustKeyTypeId "CKK_DH"
      || k == mustKeyTypeId "CKK_X9_42_DH" -> dhFacts
    | k == mustKeyTypeId "CKK_EC_EDWARDS" -> edwardsFacts
    | k == mustKeyTypeId "CKK_EC_MONTGOMERY" -> montgomeryFacts
    | k == mustKeyTypeId "CKK_ML_DSA" -> PkKeyFacts 7 0 0 0
    | k == mustKeyTypeId "CKK_ML_KEM" -> PkKeyFacts 8 0 0 0
    | k == mustKeyTypeId "CKK_SLH_DSA" -> PkKeyFacts 9 0 0 0
    | otherwise -> noPkFacts
  Nothing -> noPkFacts
  where
    attrs = osAttrs st
    rsaFacts = PkKeyFacts 1 0 0 bits
      where
        bits = case attrULong attrs AttrModulusBits of
          Just b -> b
          Nothing -> case attrBytesLen attrs AttrModulus of
            Just n -> fromIntegral n * 8
            Nothing -> 0
    ecFacts = case attrBytes attrs AttrEcParams >>= curveNameOfOid of
      Just "P-256" -> PkKeyFacts 2 1 0 0
      Just "P-384" -> PkKeyFacts 2 2 0 0
      Just "P-521" -> PkKeyFacts 2 3 0 0
      Just "secp256k1" -> PkKeyFacts 2 4 0 0
      -- Served exotic curves resolve to no registry code yet (the
      -- record still carries algorithm + mechanism).
      _ -> PkKeyFacts 2 0 0 0
    dsaFacts = PkKeyFacts 3 0 0 bits
      where
        bits = case attrULong attrs AttrSubprimeBits of
          Just b -> b
          Nothing -> case attrBytesLen attrs AttrSubprime of
            Just n -> fromIntegral n * 8
            Nothing -> 0
    dhFacts = PkKeyFacts 4 0 0 bits
      where
        bits = case attrBytesLen attrs AttrPrime of
          Just n -> fromIntegral n * 8
          Nothing -> 0
    edwardsFacts = case attrBytesLen attrs AttrValue of
      Just 32 -> PkKeyFacts 6 5 0 256
      Just 57 -> PkKeyFacts 6 7 0 456
      _ -> case attrBytes attrs AttrEcParams >>= edwardsNameOfOid of
        Just "Ed25519" -> PkKeyFacts 6 5 0 256
        Just "Ed448" -> PkKeyFacts 6 7 0 456
        _ -> PkKeyFacts 6 0 0 0
    montgomeryFacts = case attrBytesLen attrs AttrValue of
      Just 32 -> PkKeyFacts 5 6 0 256
      Just 56 -> PkKeyFacts 5 8 0 448
      _ -> case attrBytes attrs AttrEcParams >>= montgomeryNameOfOid of
        Just "X25519" -> PkKeyFacts 5 6 0 256
        Just "X448" -> PkKeyFacts 5 8 0 448
        _ -> PkKeyFacts 5 0 0 0

-- | The mechanism carried by an effect, when it carries one
-- (resource-keyed digest legs do not).
fxMechOf :: CryptoEffect -> Maybe MechanismId
fxMechOf fx = case fx of
  FxDigest { fxMech = m } -> Just m
  FxDigestInit { fxMech = m } -> Just m
  FxDigestFeed {} -> Nothing
  FxDigestConsume {} -> Nothing
  FxCipher { fxMech = m } -> Just m
  FxSign { fxMech = m } -> Just m
  FxVerify { fxMech = m } -> Just m
  FxSignRecover { fxMech = m } -> Just m
  FxVerifyRecover { fxMech = m } -> Just m
  FxMessageCipher { fxMech = m } -> Just m
  FxMessageSign { fxMech = m } -> Just m
  FxMessageVerify { fxMech = m } -> Just m
  FxGenerateKey { fxMech = m } -> Just m
  FxWrap { fxMech = m } -> Just m
  FxUnwrap { fxMech = m } -> Just m
  FxAuthWrap { fxMech = m } -> Just m
  FxAuthUnwrap { fxMech = m } -> Just m
  FxDerive { fxMech = m } -> Just m
  FxKemEncaps { fxMech = m } -> Just m
  FxKemDecaps { fxMech = m } -> Just m

-- ---------------------------------------------------------------------------
-- Live-slot resolution (pure; over a model snapshot)
-- ---------------------------------------------------------------------------

-- | Whether a slot holds staged bytes (classic or message inner).
usdtSlotStaged :: Model -> SessionId -> SlotKind -> Bool
usdtSlotStaged m sid kind = case lookupSession m sid of
  Nothing -> False
  Just st -> case lookupSingle (ssOps st) kind of
    Nothing -> False
    Just active -> stagedHere (commonOf active)
      || case activeMessage active of
        Nothing -> False
        Just msg -> stagedHere (msCommon msg)
  where
    stagedHere sc = case stagedOf sc of
      Nothing -> False
      Just _ -> True

-- | Delivery metadata for a live slot: mechanism plus key facts
-- resolved while the key exists. Yields 'Nothing' only when the
-- slot itself is gone; a missing key degrades to mechanism-only
-- (the pk record drops out, the private end keeps func/mech).
usdtLiveMeta :: Model -> SessionId -> SlotKind -> FunctionId
  -> Maybe UsdtStagedMeta
usdtLiveMeta m sid kind func = do
  st <- lookupSession m sid
  active <- lookupSingle (ssOps st) kind
  let sc = commonOf active
      mech = commonMech sc
      facts = case commonKey sc of
        Nothing -> noPkFacts
        Just oid -> case lookupObject m oid of
          Nothing -> noPkFacts
          Just os -> keyFactsOf os
      mrec = routeOfFunc func >>= \r -> resolvePk r mech facts
  pure (UsdtStagedMeta (functionCode func) (unMechanismId mech) mrec)

-- ---------------------------------------------------------------------------
-- Policy mapping
-- ---------------------------------------------------------------------------

-- | Admission-denial reason for a return code, or 'Nothing' when the
-- code is not policy (caller bugs, ranges, verdicts, environment).
-- Signature/encrypted-data verdicts are explicitly excluded: a
-- failed verification has its own record semantics.
-- | The single policy table: admission-denial codes and their
-- reason class. Signature/encrypted-data verdicts are deliberately
-- absent (failed verifications have their own record semantics),
-- as are ranges, caller bugs, and environment codes.
policyTable :: [(ReturnCode, PolicyReason)]
policyTable =
  [ (CKR_USER_NOT_LOGGED_IN, ReasonAuth)
  , (CKR_USER_ALREADY_LOGGED_IN, ReasonAuth)
  , (CKR_USER_ANOTHER_ALREADY_LOGGED_IN, ReasonAuth)
  , (CKR_PIN_INCORRECT, ReasonAuth)
  , (CKR_PIN_LOCKED, ReasonAuth)
  , (CKR_KEY_FUNCTION_NOT_PERMITTED, ReasonUsage)
  , (CKR_KEY_UNEXTRACTABLE, ReasonUsage)
  , (CKR_KEY_NOT_WRAPPABLE, ReasonUsage)
  , (CKR_KEY_TYPE_INCONSISTENT, ReasonUsage)
  , (CKR_WRAPPING_KEY_TYPE_INCONSISTENT, ReasonUsage)
  , (CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT, ReasonUsage)
  , (CKR_CURVE_NOT_SUPPORTED, ReasonUsage)
  , (CKR_ACTION_PROHIBITED, ReasonUsage)
  , (CKR_SESSION_READ_ONLY, ReasonReadonly)
  , (CKR_SESSION_READ_ONLY_EXISTS, ReasonReadonly)
  , (CKR_TEMPLATE_INCOMPLETE, ReasonTemplate)
  , (CKR_TEMPLATE_INCONSISTENT, ReasonTemplate)
  , (CKR_ATTRIBUTE_SENSITIVE, ReasonTemplate)
  , (CKR_ATTRIBUTE_TYPE_INVALID, ReasonTemplate)
  , (CKR_ATTRIBUTE_READ_ONLY, ReasonTemplate)
  , (CKR_ATTRIBUTE_VALUE_INVALID, ReasonTemplate)
  , (CKR_OPERATION_ACTIVE, ReasonState)
  , (CKR_OPERATION_NOT_INITIALIZED, ReasonState)
  ]

policyReasonOf :: ReturnCode -> Maybe PolicyReason
policyReasonOf code = lookup code policyTable

-- | 'policyReasonOf' by raw CKR number, for paths that only carry
-- the reported code. Numbers derive from 'returnCodeToRV' (the
-- single authority); no magic constants.
policyReasonOfRv :: Word32 -> Maybe PolicyReason
policyReasonOfRv rv =
  lookup rv [(returnCodeToRV c, r) | (c, r) <- policyTable]

-- ---------------------------------------------------------------------------
-- Staged-metadata retention (per instance, keyed by live slot)
-- ---------------------------------------------------------------------------

-- | Metadata retained between staging and recall delivery, resolved
-- while the key is alive. Entries die with their slot: delivery
-- takes, teardown purges, session close purges the session.
type UsdtRetainMap = Map (SessionId, SlotKind) UsdtStagedMeta

retainStagedMeta :: SessionId -> SlotKind -> UsdtStagedMeta
  -> UsdtRetainMap -> UsdtRetainMap
retainStagedMeta sid kind meta =
  Map.insert (sid, kind) meta

takeRetainedMeta :: SessionId -> SlotKind -> UsdtRetainMap
  -> (Maybe UsdtStagedMeta, UsdtRetainMap)
takeRetainedMeta sid kind m = case Map.lookup key m of
  Nothing -> (Nothing, m)
  Just meta -> (Just meta, Map.delete key m)
  where
    key = (sid, kind)

purgeRetainSession :: SessionId -> UsdtRetainMap -> UsdtRetainMap
purgeRetainSession sid =
  Map.filterWithKey (\(s, _) _ -> s /= sid)

dropRetainedMeta :: SessionId -> SlotKind -> UsdtRetainMap
  -> UsdtRetainMap
dropRetainedMeta sid kind = Map.delete (sid, kind)

-- ---------------------------------------------------------------------------
-- Emitters (no-op unless HSK_USDT)
-- ---------------------------------------------------------------------------

#ifdef HSK_USDT

foreign import ccall unsafe "usdt.h hsk_usdt_alloc_op"
  c_allocOp :: IO Word32

foreign import ccall unsafe "usdt.h hsk_usdt_saturations"
  c_saturations :: IO Word64

foreign import ccall unsafe "usdt.h hsk_usdt_pk_record"
  c_pkRecord :: Word64 -> Word32 -> Word32 -> Word32 -> Word32
    -> Word64 -> Word32 -> Word32 -> IO ()

foreign import ccall unsafe "usdt.h hsk_usdt_operation_end"
  c_operationEnd :: Word64 -> Word32 -> Word64 -> Word32 -> Word32
    -> Word32 -> Word32 -> IO ()

foreign import ccall unsafe "usdt.h hsk_usdt_policy_reject"
  c_policyReject :: Word64 -> Word32 -> Word32 -> Word64 -> Word32
    -> Word32 -> Word32 -> IO ()

foreign import ccall unsafe "usdt.h hsk_usdt_job_state"
  c_jobState :: Word32 -> Word64 -> Word64 -> Word32 -> Word32
    -> Word32 -> Word32 -> IO ()

#else

c_pkRecord :: Word64 -> Word32 -> Word32 -> Word32 -> Word32
  -> Word64 -> Word32 -> Word32 -> IO ()
c_pkRecord _ _ _ _ _ _ _ _ = pure ()

c_operationEnd :: Word64 -> Word32 -> Word64 -> Word32 -> Word32
  -> Word32 -> Word32 -> IO ()
c_operationEnd _ _ _ _ _ _ _ = pure ()

c_policyReject :: Word64 -> Word32 -> Word32 -> Word64 -> Word32
  -> Word32 -> Word32 -> IO ()
c_policyReject _ _ _ _ _ _ _ = pure ()

c_jobState :: Word32 -> Word64 -> Word64 -> Word32 -> Word32
  -> Word32 -> Word32 -> IO ()
c_jobState _ _ _ _ _ _ _ = pure ()

#endif

-- | Emit one Latchset record (new + release in the single call).
emitPkRecord :: UsdtOpId -> PkRecord -> IO ()
emitPkRecord (UsdtOpId op) rec =
  c_pkRecord op (pkNameCode (prName rec)) (pkfAlg f) (pkfCurve f)
    (pkfGroup f) (pkfBits f) (prHash rec) (prPad rec)
  where
    f = prFacts rec

-- | Emit one terminal private outcome.
emitOperationEnd :: UsdtOpId -> Word32 -> Word64 -> Bool -> Word32
  -> Disposition -> OpMode -> IO ()
emitOperationEnd (UsdtOpId op) func mech mechPresent ckr disp mode =
  c_operationEnd op func mech (fromBool mechPresent) ckr
    (dispositionCode disp) (opModeCode mode)

-- | Emit one admission denial (never terminal by itself; the
-- teardown path adds 'emitOperationEnd' when removal commits).
emitPolicyReject :: UsdtOpId -> Bool -> Word32 -> Word64 -> Bool
  -> PolicyReason -> Word32 -> IO ()
emitPolicyReject (UsdtOpId op) opValid func mech mechPresent reason ckr =
  c_policyReject op (fromBool opValid) func mech
    (fromBool mechPresent) (policyReasonCode reason) ckr

-- | Emit one committed async job transition.
emitJobState :: Word32 -> Word64 -> UsdtOpId -> Bool -> JobPhase
  -> Word32 -> Bool -> IO ()
emitJobState table job (UsdtOpId op) opValid phase ckr ckrValid =
  c_jobState table job op (fromBool opValid) (jobPhaseCode phase)
    ckr (fromBool ckrValid)

fromBool :: Bool -> Word32
fromBool False = 0
fromBool True = 1
