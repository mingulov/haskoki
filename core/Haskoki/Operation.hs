{- | Session operation slots and the classic-operation init policy (pure).

Per-session state ('SessionOps' and friends) lives in
'Haskoki.Operation.State' and is re-exported here, so the model can
host it without an import cycle.

Each session holds at most one active operation per 'SlotKind': a
digest/encrypt pair coexists, while a conflicting same-kind init is
rejected with 'CKR_OPERATION_ACTIVE'. Init consumes the
descriptor registry (source-backed operation routes), the engine
capability set, and the object rules (handle resolution plus
session visibility); key-usage permission and the
always-authenticate mark come from the key object wherever key
attributes exist ('policyFromObject'), with the caller-derived
'KeyPolicy' as the fallback for legacy objects (the remaining seam).

Crypto executes outside the pure core: planners emit 'CryptoEffect's
and drivers answer with 'CryptoResult's, so the model suites drive
the synthetic engine while the engine smoke suite answers the same
planned effects with the real engine backend. Final and one-shot bytes
are staged through the output planner ('planOneShot'): a short
buffer keeps the slot for 'retryStaged', any crypto failure or
verdict mismatch terminates it.

Context-specific authentication (the login machine) is consumed
only at its defined point: the first data call of an
always-authenticate slot ('gateDataCall'). A grant presented to a
non-pending slot fails without being consumed (premature); a pending
slot whose first data call arrives grantless terminates, so a later
grant finds nothing to spend on (late).
-}
module Haskoki.Operation
  ( -- * Slots and states (see Haskoki.Operation.State)
    module Haskoki.Operation.State
    -- * Effect currency (see Haskoki.Operation.Effect)
  , module Haskoki.Operation.Effect
    -- * Init policy
  , KeyPolicy (..)
  , InitArgs (..)
  , OpEnv (..)
  , InitOutcome (..)
  , initOperation
  , initDualOperation
  , initMessageOperation
    -- * Data-call planning shared machinery
    -- ('StepDeny', 'DenyDetail', 'TypedError' and the interpreter
    -- live in Haskoki.Operation.Effect and are re-exported above)
  , StepOutcome (..)
  , denyOutcome
  , denyOutcomeR
  , DataGate (..)
  , gateDataCall
  , stageBytes
  , retryStaged
  , isUnframedCipher
  , isCtsMech
  , isAesStreamMech
  , isAesWrapMech
  , isKwpMech
  , isOfbMech
  , isXtsMech
    -- * Buffer bound for the per-kind lifecycles
  , maxBuffered
  , appendBuffered
  ) where

import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import Data.Maybe (isJust)

import Haskoki.Model (Model, ObjectState (..), SessionState (..))
import Haskoki.Object (objectVisible, resolveHandle)
import Haskoki.Outcome (ResourceRelease)
import Haskoki.Operation.Effect
import Haskoki.Operation.KeyManagement (keyTypeCompatible, mechAllowed, policyFromObject)
import Haskoki.Operation.State
import Haskoki.Output
  ( OutputPlan (..)
  , planOneShot
  )
import Haskoki.Recipe.Ccm (ccmParamsValid, ccmRecipeFor)
import Haskoki.Recipe.Cipher (BlockCipherRecipe (crName), cipherParamsValid, cipherRecipeFor, ctsName, kwpNames, ofbName, streamNames, wrapNames, xtsName)
import Haskoki.Recipe.Cmac (cmacParamsValid, cmacRecipeFor)
import Haskoki.Recipe.Des3Mac (des3macParamsValid, des3macRecipeFor)
import Haskoki.Recipe.Digest (digestParamsValid)
import Haskoki.Recipe.Ecdsa (ecdsaParamsValid, ecdsaRecipeFor)
import Haskoki.Recipe.Dsa (dsaParamsValid, dsaRecipeFor)
import Haskoki.Recipe.Eddsa (eddsaParamsValid, eddsaRecipeFor)
import Haskoki.Recipe.Gcm (gcmParamsValid, gcmRecipeFor)
import Haskoki.Recipe.Chacha20 (chachaParamsValid, chachaRecipeFor)
import Haskoki.Recipe.Hmac (hmacParamsValid, hmacRecipeFor)
import Haskoki.Recipe.MlDsa (mldsaParamsValid, mldsaRecipeFor)
import Haskoki.Recipe.SlhDsa (slhdsaParamsValid, slhdsaRecipeFor)
import Haskoki.Recipe.Otp (hotpParamsValid, hotpRecipeFor)
import Haskoki.Recipe.RsaOaep (rsaOaepParamsValid, rsaOaepRecipeFor)
import Haskoki.Recipe.RsaPkcs1 (rsaPkcs1ParamsValid, rsaPkcs1RecipeFor)
import Haskoki.Recipe.RsaPss (rsaPssParamsValid, rsaPssRecipeFor)
import Haskoki.Registry
  ( EngineCapabilities
  , MechanismId
  , Operation (..)
  , Registry
  , lookupBehavior
  , routeOperation
  , descRoutes
  , supports
  )
import Haskoki.Request (OutputIntent (..))
import Haskoki.Session (SessionLogin (..))
import Haskoki.Types
  ( Consumption (..)
  , ExternalHandle
  , ObjectId
  , OpState (..)
  , ReturnCode (..)
  )

-- ---------------------------------------------------------------------------
-- Init policy
-- ---------------------------------------------------------------------------

-- | Caller-derived key policy for one init: the handle to resolve,
-- the operations this key may serve, and whether every use needs a
-- context-specific grant.
data KeyPolicy = KeyPolicy
  { kpHandle :: !ExternalHandle
  , kpPermits :: ![Operation]
  , kpAlwaysAuth :: !Bool
  } deriving (Eq, Show)

-- | Init arguments: operation, mechanism, opaque parameters, the key
-- policy for keyed ops, and the shape specs for cipher/recovery ops.
data InitArgs = InitArgs
  { iaOp :: !Operation
  , iaMech :: !MechanismId
  , iaParams :: !ByteString
  , iaKey :: !(Maybe KeyPolicy)
  , iaCipher :: !(Maybe CipherSpec)
  , iaRecover :: !(Maybe RecoverSpec)
  } deriving (Eq, Show)

-- | What init plans against: the descriptor registry, the engine
-- capability set, and the object model for handle resolution.
data OpEnv = OpEnv
  { oeRegistry :: !Registry
  , oeCaps :: !EngineCapabilities
  , oeModel :: !Model
  } deriving (Eq, Show)

-- | Init outcome: the return code plus diagnostic reasons. Init plans
-- no crypto, so there are no effects and no output plan. A rejection
-- carries the typed denial detail ('ioDeny'); success carries none.
data InitOutcome = InitOutcome
  { ioCode :: !ReturnCode
  , ioReasons :: ![String]
  , ioDeny :: !(Maybe DenyDetail)
  } deriving (Eq, Show)

-- | A validated init shape: plain, cipher, or recovery. Internal:
-- allocation only ever observes a shape that passed 'checkShape'.
data InitShape
  = ShapePlain
  | ShapeCipher !CipherSpec
  | ShapeRecover !RecoverSpec
  deriving (Eq, Show)

-- | Whether an operation is keyed. Only digest is unkeyed.
opKeyed :: Operation -> Bool
opKeyed OpDigest = False
opKeyed _ = True

-- | One validated init: the slot, the checked shape, the resolved
-- key object, and the auth marking. Internal: allocation only ever
-- observes validated inits.
data ValidInit = ValidInit
  { viKind :: !SlotKind
  , viShape :: !InitShape
  , viKey :: !(Maybe ObjectId)
  , viAuth :: !OpAuth
  } deriving (Eq, Show)

-- | Validate init arguments without allocating: operation-set
-- membership, source legality, engine capability, init shape, and
-- the key binding (resolution, visibility, usage permission, login
-- for always-authenticate keys). Shared by single and dual inits.
validateInit :: OpEnv -> SessionState -> InitArgs -> Either StepDeny ValidInit
validateInit env st args =
  case slotOf (iaOp args) of
    Nothing -> Left (mkDeny CKR_MECHANISM_INVALID "not a classic operation")
    Just kind -> case lookupBehavior (oeRegistry env) (iaMech args) of
      Nothing -> Left (mkDeny CKR_MECHANISM_INVALID "unknown mechanism")
      Just desc
        | iaOp args `notElem` map routeOperation (descRoutes desc) ->
            Left (mkDeny CKR_MECHANISM_INVALID
              "no source-backed route for this operation")
        | not (supports (oeCaps env) (iaMech args) (iaOp args)) ->
            Left (mkDeny CKR_MECHANISM_INVALID
              "engine lacks this (mechanism, operation)")
        | otherwise -> case checkShape args of
            Left deny -> Left deny
            Right shape -> case checkMechParams args of
              Left deny -> Left deny
              Right () -> case checkKeyBinding env st args of
                Left deny -> Left deny
                Right (mkey, auth) -> Right (ValidInit kind shape mkey auth)

-- | Cipher and recovery shapes are fixed at init; anything else
-- carrying a shape is malformed.
checkShape :: InitArgs -> Either StepDeny InitShape
checkShape args = case (cipherDirOf (iaOp args), iaCipher args) of
  (Just _, Nothing) ->
    Left (mkDeny CKR_ARGUMENTS_BAD "cipher operation requires a cipher spec")
  (Just _, Just spec)
    | csBlock spec < 1 || csBlock spec > 1024 ->
        Left (mkDeny CKR_ARGUMENTS_BAD "cipher block width out of range")
    | csPad spec && csBlock spec > 255 ->
        Left (mkDeny CKR_ARGUMENTS_BAD
          "padded cipher block escapes the PKCS#7 byte range")
    -- The planner's PKCS#7 framing must never cover an
    -- asymmetric operation (the block width is vestigial for RSA
    -- rows; the length bound lives in the backend).
    | csPad spec && isJust (rsaOaepRecipeFor (iaMech args)) ->
        Left (mkDeny CKR_ARGUMENTS_BAD
          "asymmetric cipher operation takes no padding spec")
    | csPad spec && isJust (gcmRecipeFor (iaMech args)) ->
        Left (mkDeny CKR_ARGUMENTS_BAD
          "AEAD cipher operation takes no padding spec")
    | csPad spec && isJust (ccmRecipeFor (iaMech args)) ->
        Left (mkDeny CKR_ARGUMENTS_BAD
          "AEAD cipher operation takes no padding spec")
    | csPad spec && isJust (chachaRecipeFor (iaMech args)) ->
        Left (mkDeny CKR_ARGUMENTS_BAD
          "ChaCha20 cipher operation takes no padding spec")
    | otherwise -> checkRecover args (ShapeCipher spec)
  (Nothing, Just _) ->
    Left (mkDeny CKR_ARGUMENTS_BAD "non-cipher operation takes no cipher spec")
  (Nothing, Nothing) -> checkRecover args ShapePlain

-- | Asymmetric cipher rows skip block framing: an OAEP input is
-- length-bounded by the backend (@k-2*hLen-2@), never block-aligned,
-- and answers stage raw. 'checkShape' already refuses padded specs
-- for these rows; the planners and finishers consult this so the
-- vestigial cipher width never gates bytes. (@CKM_RSA_PKCS@ joins
-- when it gets a cipher shape; today OAEP is the only asymmetric
-- row that can hold a cipher slot.)
isUnframedCipher :: MechanismId -> Bool
isUnframedCipher m = isJust (rsaOaepRecipeFor m) || isJust (gcmRecipeFor m) || isJust (ccmRecipeFor m) || isJust (chachaRecipeFor m)

-- | Ciphertext-stealing rows: @CKM_AES_CTS@ keeps the 16-byte shape
-- but replaces block alignment with a length floor (input must
-- cover >= 1 block; output length equals input length) and never
-- streams multipart updates (the steal pair intertwines the last
-- two blocks, so only the final sees the whole buffer). The
-- planners consult this alongside 'isUnframedCipher'.
isCtsMech :: MechanismId -> Bool
isCtsMech m = case cipherRecipeFor m of
  Just r -> crName r == ctsName
  Nothing -> False

-- | Length-preserving AES stream rows (@CKM_AES_CFB128@,
-- @CKM_AES_CFB8@, @CKM_AES_CFB1@, @CKM_AES_OFB@): any input length
-- round-trips length-preserved, including empty. The planners
-- accept unaligned input for these rows; chaining follows the
-- ciphertext tail like CBC (streamed answers are always >= 1
-- block, so the tail IS the next register), except OFB (see
-- 'isOfbMech').
isAesStreamMech :: MechanismId -> Bool
isAesStreamMech m = case cipherRecipeFor m of
  Just r -> crName r `elem` streamNames
  Nothing -> False

-- | OFB never streams multipart updates: its register evolves
-- through the block cipher, so the planner cannot derive the next
-- register from the answer tail — only the final (which sees the
-- whole buffer) runs the effect. CFB128/CFB8/CFB1 stream like CBC.
isOfbMech :: MechanismId -> Bool
isOfbMech m = case cipherRecipeFor m of
  Just r -> crName r == ofbName
  Nothing -> False

-- | AES key-wrap rows (@CKM_AES_KEY_WRAP@, @CKM_AES_KEY_WRAP_PAD@,
-- @CKM_AES_KEY_WRAP_KWP@): one-shot integrity over the whole
-- buffer, so multipart updates never stream (only the final runs
-- the effect) and output expands by the wrap framing. KW takes
-- multiple-of-8 input >= 16 bytes; KWP takes any length >= 1
-- (see 'isKwpMech').
isAesWrapMech :: MechanismId -> Bool
isAesWrapMech m = case cipherRecipeFor m of
  Just r -> crName r `elem` wrapNames
  Nothing -> False

-- | The KWP rows (@CKM_AES_KEY_WRAP_KWP@ plus the PAD alias the
-- oracle equates with KWP): RFC 5649 padding accepts any input
-- length >= 1, unlike KW's multiple-of-8 floor.
isKwpMech :: MechanismId -> Bool
isKwpMech m = case cipherRecipeFor m of
  Just r -> crName r `elem` kwpNames
  Nothing -> False

-- | The XTS row (@CKM_AES_XTS@): IEEE 1619 tweakable encryption
-- over data units of >= 16 bytes (any length above; stealing
-- covers ragged tails). Multipart updates never stream (only the
-- final runs the effect): within-call tweak evolution is GF
-- doubling per block, which the planner cannot advance from the
-- answer tail, so the whole unit buffers to the final like OFB.
isXtsMech :: MechanismId -> Bool
isXtsMech m = case cipherRecipeFor m of
  Just r -> crName r == xtsName
  Nothing -> False

-- | Mechanism-parameter check (recipe-backed mechanisms):
-- operations whose recipe constrains mechanism parameters enforce
-- here. Digest inits take empty parameters only
-- ('Haskoki.Recipe.Digest.digestParamsValid'); HMAC inits enforce
-- per-mechanism parameters (plain: empty only; GENERAL: in-range
-- tag length) via 'hmacRecipeFor'; cipher inits enforce
-- per-mechanism IV geometry (CBC: one block; ECB: empty only) via
-- 'cipherRecipeFor'; RSA v1.5 inits take empty parameters only via
-- 'rsaPkcs1RecipeFor'; RSA-PSS inits enforce the salted binding via
-- 'rsaPssRecipeFor'; RSA-OAEP inits enforce the labeled params via
-- 'rsaOaepRecipeFor'; ECDSA inits enforce the encoding selection
-- via 'ecdsaRecipeFor'; DSA inits enforce the encoding selection
-- via 'dsaRecipeFor'; CMAC inits enforce the plain/GENERAL
-- shape via 'cmacRecipeFor'; AEAD inits enforce the caller IV and
-- approved tag width via 'gcmRecipeFor'; CCM inits refuse
-- out-of-range nonces and tag widths with
-- 'CKR_MECHANISM_PARAM_INVALID' (OASIS §2.20.2 pins that code for
-- bad CCM parameters at init); later slices extend this
-- to KDF recipes.
-- Runs after shape checks (which govern specs) and before key
-- binding.
checkMechParams :: InitArgs -> Either StepDeny ()
checkMechParams args
  | iaOp args == OpDigest
  , not (digestParamsValid (iaParams args)) =
      Left (mkDeny CKR_ARGUMENTS_BAD
        "digest operation takes empty mechanism parameters")
  | Just r <- hmacRecipeFor (iaMech args)
  , not (hmacParamsValid r (iaParams args)) =
      Left (mkDeny CKR_ARGUMENTS_BAD
        "HMAC mechanism parameters rejected by the recipe")
  | Just r <- cipherRecipeFor (iaMech args)
  , not (cipherParamsValid r (iaParams args)) =
      Left (mkDeny CKR_ARGUMENTS_BAD
        "cipher mechanism parameters rejected by the recipe")
  | Just r <- rsaPkcs1RecipeFor (iaMech args)
  , not (rsaPkcs1ParamsValid r (iaParams args)) =
      Left (mkDeny CKR_ARGUMENTS_BAD
        "RSA mechanism parameters rejected by the recipe")
  | Just r <- rsaPssRecipeFor (iaMech args)
  , not (rsaPssParamsValid r (iaParams args)) =
      Left (mkDeny CKR_ARGUMENTS_BAD
        "RSA-PSS mechanism parameters rejected by the recipe")
  | Just r <- rsaOaepRecipeFor (iaMech args)
  , not (rsaOaepParamsValid r (iaParams args)) =
      Left (mkDeny CKR_ARGUMENTS_BAD
        "RSA-OAEP mechanism parameters rejected by the recipe")
  | Just r <- ecdsaRecipeFor (iaMech args)
  , not (ecdsaParamsValid r (iaParams args)) =
      Left (mkDeny CKR_ARGUMENTS_BAD
        "ECDSA mechanism parameters rejected by the recipe")
  | Just r <- dsaRecipeFor (iaMech args)
  , not (dsaParamsValid r (iaParams args)) =
      Left (mkDeny CKR_ARGUMENTS_BAD
        "DSA mechanism parameters rejected by the recipe")
  | isJust (eddsaRecipeFor (iaMech args))
  , BS.null (iaParams args) =
      Left (mkDeny CKR_MECHANISM_PARAM_INVALID
        "EdDSA requires explicit mechanism parameters")
  | Just r <- eddsaRecipeFor (iaMech args)
  , not (eddsaParamsValid r (iaParams args)) =
      Left (mkDeny CKR_ARGUMENTS_BAD
        "EdDSA mechanism parameters rejected by the recipe")
  | Just r <- mldsaRecipeFor (iaMech args)
  , not (mldsaParamsValid r (iaParams args)) =
      Left (mkDeny CKR_ARGUMENTS_BAD
        "ML-DSA mechanism parameters rejected by the recipe")
  | Just r <- slhdsaRecipeFor (iaMech args)
  , not (slhdsaParamsValid r (iaParams args)) =
      Left (mkDeny CKR_ARGUMENTS_BAD
        "SLH-DSA mechanism parameters rejected by the recipe")
  | Just r <- cmacRecipeFor (iaMech args)
  , not (cmacParamsValid r (iaParams args)) =
      Left (mkDeny CKR_ARGUMENTS_BAD
        "CMAC mechanism parameters rejected by the recipe")
  | Just r <- des3macRecipeFor (iaMech args)
  , not (des3macParamsValid r (iaParams args)) =
      Left (mkDeny CKR_ARGUMENTS_BAD
        "3DES-MAC mechanism parameters rejected by the recipe")
  | Just r <- hotpRecipeFor (iaMech args)
  , not (hotpParamsValid r (iaParams args)) =
      Left (mkDeny CKR_ARGUMENTS_BAD
        "HOTP mechanism parameters rejected by the recipe")
  | Just r <- gcmRecipeFor (iaMech args)
  , not (gcmParamsValid r (iaParams args)) =
      Left (mkDeny CKR_ARGUMENTS_BAD
        "GCM mechanism parameters rejected by the recipe")
  | Just r <- ccmRecipeFor (iaMech args)
  , not (ccmParamsValid r (iaParams args)) =
      Left (mkDeny CKR_MECHANISM_PARAM_INVALID
        "CCM mechanism parameters rejected by the recipe")
  | Just r <- chachaRecipeFor (iaMech args)
  , not (chachaParamsValid r (iaParams args)) =
      Left (mkDeny CKR_ARGUMENTS_BAD
        "ChaCha20 mechanism parameters rejected by the recipe")
  | otherwise = Right ()

-- | Recovery shape check, preserving whatever the cipher check
-- validated when no recovery shape is requested.
checkRecover :: InitArgs -> InitShape -> Either StepDeny InitShape
checkRecover args incoming = case (recoverRoleOf (iaOp args), iaRecover args) of
  (Just _, Nothing) ->
    Left (mkDeny CKR_ARGUMENTS_BAD "recovery operation requires a recover spec")
  (Just _, Just spec)
    | rsCapacity spec < 1 || rsTagLen spec < 1
        || rsTagLen spec > rsCapacity spec ->
        Left (mkDeny CKR_ARGUMENTS_BAD "recover spec out of range")
    | otherwise -> Right (ShapeRecover spec)
  (Nothing, Just _) ->
    Left (mkDeny CKR_ARGUMENTS_BAD "non-recovery operation takes no recover spec")
  (Nothing, Nothing) -> Right incoming

-- | Key-shape and key-binding checks: keyed ops need a key, unkeyed
-- ops take none, and a bound key must resolve, be visible, carry a
-- compatible key type, permit the operation, and (for
-- always-authenticate keys) sit under a user login. Success carries
-- the resolved object id and the auth marking. Usage permission and
-- the always-authenticate mark come from the key OBJECT
-- ('policyFromObject') wherever key attributes exist; legacy
-- objects without them still honor the caller-derived 'KeyPolicy'
-- (the remaining seam). The key-type check ('keyTypeCompatible')
-- runs before the usage check: a type contradiction is the deeper
-- mismatch, and the oracle's wrong-key-type fixtures carry usage
-- flags (they must surface @KEY_TYPE_INCONSISTENT@, not a usage
-- refusal). The allowed-mechanism check ('mechAllowed') sits
-- between them: a key that names its mechanisms refuses unlisted
-- ones with @KEY_FUNCTION_NOT_PERMITTED@.
checkKeyBinding
  :: OpEnv -> SessionState -> InitArgs -> Either StepDeny (Maybe ObjectId, OpAuth)
checkKeyBinding env st args = case (opKeyed (iaOp args), iaKey args) of
  (True, Nothing) -> Left (mkDeny CKR_ARGUMENTS_BAD "operation requires a key")
  (False, Just _) -> Left (mkDeny CKR_ARGUMENTS_BAD "operation takes no key")
  (False, Nothing) -> Right (Nothing, AuthNone)
  (True, Just kp) -> case resolveHandle (oeModel env) (kpHandle kp) of
    Nothing -> Left (mkDeny CKR_OBJECT_HANDLE_INVALID "unknown object handle")
    Just ost
      | not (objectVisible st ost) ->
          Left (mkDeny CKR_OBJECT_HANDLE_INVALID
            "object not visible in this session")
      | not (keyTypeCompatible (iaMech args) (iaOp args) ost) ->
          Left (mkDeny CKR_KEY_TYPE_INCONSISTENT
            "key type does not serve this mechanism")
      | not (mechAllowed (iaMech args) ost) ->
          Left (mkDeny CKR_KEY_FUNCTION_NOT_PERMITTED
            "mechanism is not in the key's allowed list")
      | otherwise ->
          let (permits, alwaysAuth) = case policyFromObject ost of
                Just (p, a) -> (p, a)
                Nothing -> (kpPermits kp, kpAlwaysAuth kp)
          in if iaOp args `notElem` permits
            then Left (mkDeny CKR_KEY_FUNCTION_NOT_PERMITTED
              "key does not permit this operation")
            else if alwaysAuth && ssLogin st `notElem` [LoginUser, LoginContextUser]
              then Left (mkDeny CKR_USER_NOT_LOGGED_IN
                "always-authenticate key needs a user login")
              else Right (Just (osId ost),
                if alwaysAuth then AuthPending else AuthNone)

-- | Allocate a single slot from validated init arguments.
allocateSingle
  :: SessionOps -> InitArgs -> ValidInit -> (SessionOps, InitOutcome)
allocateSingle ops args vi =
  let common = mkSlotCommon (iaMech args) (iaOp args) (viKey vi)
            (iaParams args) (viAuth vi)
      active = case viShape vi of
        ShapeCipher spec -> case cipherDirOf (iaOp args) of
          Just dir -> mkActiveCipher dir common spec
          Nothing -> mkActiveDigest common
        ShapeRecover spec -> case recoverRoleOf (iaOp args) of
          Just role -> mkActiveRecover role common spec
          Nothing -> mkActiveDigest common
        ShapePlain -> case viKind vi of
          SlotDigest -> mkActiveDigest common
          SlotSign -> mkActiveSign common
          SlotVerify -> mkActiveVerify common
          SlotEncrypt -> mkActiveCipher DirEncrypt common (CipherSpec 16 False)
          SlotDecrypt -> mkActiveCipher DirDecrypt common (CipherSpec 16 False)
  in ( insertOp active ops
     , InitOutcome CKR_OK ["initialized " ++ show (iaOp args)] Nothing
     )

-- | Initialize one classic operation. Check order (documented,
-- tested): operation-set membership, then the slot conflict (a doomed
-- call fails before touching keys), then the shared validation.
initOperation
  :: OpEnv -> SessionOps -> SessionState -> InitArgs -> (SessionOps, InitOutcome)
initOperation env ops st args =
  case slotOf (iaOp args) of
    Nothing -> reject CKR_MECHANISM_INVALID "not a classic operation"
    Just kind
      | kindOccupied ops kind ->
          reject CKR_OPERATION_ACTIVE "an operation is already active in this slot"
      | otherwise -> case validateInit env st args of
          Left deny -> rejectDeny deny
          Right vi -> allocateSingle ops args vi
  where
    reject :: ReturnCode -> String -> (SessionOps, InitOutcome)
    reject code why = rejectDeny (mkDeny code why)
    rejectDeny deny = (ops, InitOutcome (sdCode deny) [sdReason deny] (Just (sdDetail deny)))

-- | Initialize a dual digest+cipher operation: the digest side must
-- be a digest, the cipher side encrypt or decrypt. Both sides pass
-- the shared validation; the dual occupies both slots and conflicts
-- with any single or dual already there.
initDualOperation
  :: OpEnv -> SessionOps -> SessionState -> InitArgs -> InitArgs
  -> (SessionOps, InitOutcome)
initDualOperation env ops st dArgs cArgs =
  case cipherDirOf (iaOp cArgs) of
    Nothing -> reject CKR_ARGUMENTS_BAD
      "dual cipher side must be encrypt or decrypt"
    Just dir
      | iaOp dArgs /= OpDigest -> reject CKR_ARGUMENTS_BAD
          "dual digest side must be a digest"
      | hasDual ops -> reject CKR_OPERATION_ACTIVE
          "a dual operation is already active"
      | kindOccupied ops SlotDigest -> reject CKR_OPERATION_ACTIVE
          "digest slot is already active"
      | kindOccupied ops (dirKind dir) -> reject CKR_OPERATION_ACTIVE
          "cipher slot is already active"
      | otherwise -> case validateInit env st dArgs of
          Left deny -> rejectDeny deny
          Right vd -> case validateInit env st cArgs of
            Left deny -> rejectDeny deny
            Right vc -> case viShape vc of
              ShapeCipher spec -> allocate dir vd vc spec
              _ -> reject CKR_GENERAL_ERROR "dual cipher shape mismatch"
  where
    reject :: ReturnCode -> String -> (SessionOps, InitOutcome)
    reject code why = rejectDeny (mkDeny code why)
    rejectDeny deny = (ops, InitOutcome (sdCode deny) [sdReason deny] (Just (sdDetail deny)))
    allocate dir vd vc spec =
      let dCommon = mkSlotCommon (iaMech dArgs) (iaOp dArgs) (viKey vd)
            (iaParams dArgs) (viAuth vd)
          cCommon = mkSlotCommon (iaMech cArgs) (iaOp cArgs) (viKey vc)
            (iaParams cArgs) (viAuth vc)
          du = DualState dCommon cCommon dir spec Nothing
      in ( setDual (Just du) ops
         , InitOutcome CKR_OK ["initialized dual digest+" ++ show (iaOp cArgs)] Nothing
         )

-- | Initialize one outer message context. Check order: the args op
-- must name the family's classic counterpart (a mismatched bundle
-- is malformed), then the slot conflict (a doomed call fails before
-- touching keys), then the shared validation against the classic
-- counterpart ('msgFamilyOp'). The context records the message
-- operation tag and starts idle with zero delivered messages.
initMessageOperation
  :: MsgFamily -> OpEnv -> SessionOps -> SessionState -> InitArgs
  -> (SessionOps, InitOutcome)
initMessageOperation fam env ops st args
  | iaOp args /= msgFamilyOp fam =
      reject CKR_ARGUMENTS_BAD "init args op mismatches the message family"
  | kindOccupied ops kind =
      reject CKR_OPERATION_ACTIVE "an operation is already active in this slot"
  | otherwise = case validateInit env st args of
      Left deny -> rejectDeny deny
      Right vi -> allocateMessage ops args fam vi
  where
    kind = msgFamilyKind fam
    reject :: ReturnCode -> String -> (SessionOps, InitOutcome)
    reject code why = rejectDeny (mkDeny code why)
    rejectDeny deny = (ops, InitOutcome (sdCode deny) [sdReason deny] (Just (sdDetail deny)))
    allocateMessage o a f vi =
      let common = mkSlotCommon (iaMech a) (msgOperation f) (viKey vi)
            (iaParams a) (viAuth vi)
          spec = case viShape vi of
            ShapeCipher cs -> Just cs
            _ -> Nothing
          ms = MsgState f common MsgIdle spec 0
      in ( insertOp (mkActiveMessage ms) o
         , InitOutcome CKR_OK ["initialized message " ++ show f] Nothing
         )

-- ---------------------------------------------------------------------------
-- Data-call planning shared machinery
-- ---------------------------------------------------------------------------

-- | One step's outcome: the return code, the crypto the driver must
-- run (empty once bytes are ready or the step was denied), the output
-- plan once bytes are staged, backend resources the commit must
-- release, diagnostic reasons, and the typed denial detail for
-- denied steps ('Nothing' otherwise).
data StepOutcome = StepOutcome
  { soCode :: !ReturnCode
  , soEffects :: ![CryptoEffect]
  , soPlan :: !(Maybe OutputPlan)
  , soReasons :: ![String]
  , soReleases :: ![ResourceRelease]
  , soDeny :: !(Maybe DenyDetail)
  } deriving (Eq, Show)

-- | A denied step: no effects, no output plan, no releases. Carries
-- the typed denial detail to the edge.
denyOutcome :: StepDeny -> StepOutcome
denyOutcome d =
  StepOutcome (interpretError (TyDeny d)) [] Nothing [sdReason d] [] (Just (sdDetail d))

-- | A denied step that also releases backend resources (crypto
-- failures on streaming slots): the denial detail plus the releases
-- the commit must drain.
denyOutcomeR :: StepDeny -> [ResourceRelease] -> StepOutcome
denyOutcomeR d rel = (denyOutcome d) { soReleases = rel }

-- | The context-auth gate verdict: proceed (possibly with the grant
-- consumed), or deny with whether the slot must terminate. Only a
-- grantless first data call on a pending slot terminates; a premature
-- grant use denies without consuming or terminating.
data DataGate
  = GateOk !SessionState !SlotCommon
  | GateDeny !StepDeny !Bool
  deriving (Eq, Show)

-- | Gate one data call on a slot's auth state against the session
-- login. Consumption happens here and nowhere else: the first data
-- call of a pending slot spends a held context grant and returns the
-- session to a plain user login.
gateDataCall :: SessionState -> SlotCommon -> DataGate
gateDataCall st sc = case commonAuth sc of
  AuthPending
    | ssLogin st == LoginContextUser ->
        GateOk (st { ssLogin = LoginUser }) (setCommonAuth AuthSatisfied sc)
    | otherwise ->
        GateDeny (mkDeny CKR_USER_NOT_LOGGED_IN
          "context-specific login required before first use") True
  _ | ssLogin st == LoginContextUser ->
        GateDeny (mkDeny CKR_USER_NOT_LOGGED_IN
          "context grant is not spendable on this operation") False
    | otherwise -> GateOk st sc

-- | Stage final bytes through the output planner: success frees the
-- slot (no staged output is retained), a short buffer retains the
-- full bytes with their planner liveness for 'retryStaged'. A size
-- query ('IntentNull') always stages — even an empty output, which
-- would otherwise "fit" and free the slot before the recall.
stageBytes
  :: String -> ByteString -> OutputIntent
  -> (Maybe StagedOutput, OutputPlan, Bool)
stageBytes name out intent =
  let (st', plan) = planOneShot (OpLive (Consumption 0)) name out intent
  in case (intent, opCode plan) of
    (IntentNull, _) -> (Just (StagedOutput name out st'), plan, False)
    (_, CKR_OK) -> (Nothing, plan, True)
    _ -> (Just (StagedOutput name out st'), plan, False)

-- | Retry a staged final output with a fresh intent. Success frees
-- the slot; a still-short buffer keeps the full staged bytes again;
-- a re-query ('IntentNull') re-reports the staged length and keeps
-- the slot. Unstaged, unknown, or kind-mismatched slots deny
-- without mutation.
retryStaged :: SessionOps -> SlotKind -> OutputIntent -> (SessionOps, StepOutcome)
retryStaged ops kind intent = case lookupSingle ops kind of
  Nothing -> (ops, denyOutcome (mkDeny CKR_OPERATION_NOT_INITIALIZED
    "no operation is active in this slot"))
  Just active | isJust (activeMessage active) ->
    (ops, denyOutcome (mkDeny CKR_ARGUMENTS_BAD
      "message output needs the message retry; the classic retry would free the outer context"))
  Just active ->
    let sc = commonOf active
    in case stagedOf sc of
      Nothing -> (ops, denyOutcome (mkDeny CKR_OPERATION_NOT_INITIALIZED
        "slot holds no staged output"))
      Just staged ->
        let (st', plan) = planOneShot (stState staged)
              (stName staged) (stBytes staged) intent
        in case (intent, opCode plan) of
          -- A re-query re-reports the staged length and keeps the
          -- slot; only a fitting buffer completes the retry.
          (IntentNull, _) ->
            let sc' = setStaged (Just (staged { stState = st' })) sc
            in ( insertOp (setCommon active sc') ops
               , StepOutcome CKR_BUFFER_TOO_SMALL [] (Just plan)
                   ["re-query re-reports the staged length"] [] Nothing
               )
          (_, CKR_OK) ->
            ( removeSingle kind ops
            , StepOutcome CKR_OK [] (Just plan) ["retry complete"] [] Nothing
            )
          _ ->
            let sc' = setStaged (Just (staged { stState = st' })) sc
            in ( insertOp (setCommon active sc') ops
               , StepOutcome (opCode plan) [] (Just plan)
                   ["retry still short; staged output retained"] [] Nothing
               )

-- | Bound on multipart accumulation per slot: the output planner's
-- single-output bound, so a staged slot can always stage what it
-- buffered. Message inner buffers share this bound.
maxBuffered :: Int
maxBuffered = 16 * 1024 * 1024

-- | Append bytes to a slot's multipart accumulation, rejecting input
-- past the buffer bound. Callers terminate the slot on denial.
appendBuffered :: SlotCommon -> ByteString -> Either StepDeny SlotCommon
appendBuffered sc part =
  let buf = bufferedOf sc <> part
  in if BS.length buf > maxBuffered
    then Left (mkDeny CKR_ARGUMENTS_BAD "multipart input exceeds the buffer bound")
    else Right (setBuffered buf sc)