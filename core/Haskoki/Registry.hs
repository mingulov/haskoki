{- | Descriptor registry: inventory/behavior/engine/catalog separation.

Header constants establish mechanism identity; they do not specify
legal operations or behavior. This registry keeps four projections
apart:

* official inventory: every baseline identifier and alias, including
  catalog-only and historical entries;
* behavior registry: only descriptors with a parameter codec and a
  source-backed operation policy;
* engine capabilities: executable @(mechanism, operation)@ pairs, owned
  by each backend but typed here so the pure core can intersect them;
* active token catalog: the configured projection exposed to consumers.

A catalog-only entry stays in the coverage denominator but never
becomes executable. Descriptors are only populated with concrete
reviewed rules; the header inventory is never mass-marked supported.

This module is pure core: no IO, no FFI, no engine imports.
-}
{-# LANGUAGE OverloadedStrings #-}
module Haskoki.Registry
  ( -- * Identifiers and vocabularies
    module Haskoki.Registry.Types
  , Family (..)
  , familyName
  , Operation (..)
  , operationName
  , KeySizeUnit (..)
  , keyUnitName
    -- * Descriptors
  , SourceRef (..)
  , RoutePolicy (..)
  , Descriptor (..)
  , RegistryError (..)
    -- * Registry
  , Registry
  , InventoryEntry (..)
  , EngineCapabilities
  , mkCapabilities
  , supports
  , MechanismStatus (..)
  , emptyRegistry
  , addInventory
  , registerDescriptor
  , promoteInventory
  , setCatalog
  , lookupBehavior
  , lookupByName
  , behaviorRoutes
  , mechanismList
  , behaviorIds
  , inventoryIds
  , describeStatus
  , isExecutable
    -- * Curated population and dump
  , curatedRegistry
  , renderMechId
  , dumpRegistry
  ) where

import Control.Monad (foldM)
import Data.Char (toUpper)
import Data.List (sort, sortOn)
import Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map
import Data.Set (Set)
import qualified Data.Set as Set
import Data.Text (Text)
import qualified Data.Text as T
import Data.Word (Word64)
import Numeric (showHex)

import Haskoki.Recipe.Cipher
  ( BlockCipherRecipe (..)
  , cipherCodecFor
  , cipherRecipes
  )
import Haskoki.Recipe.Cmac
  ( CmacRecipe (..)
  , cmacCodecFor
  , cmacRecipes
  )
import Haskoki.Recipe.Digest (digestCodec)
import Haskoki.Recipe.Ecdh
  ( EcdhRecipe (..)
  , ecdhCodecFor
  , ecdhRecipes
  )
import Haskoki.Recipe.Ecdsa
  ( EcdsaRecipe (..)
  , ecdsaCodecFor
  , ecdsaRecipes
  )
import Haskoki.Recipe.Gcm
  ( GcmRecipe (..)
  , gcmCodecFor
  , gcmRecipes
  )
import Haskoki.Recipe.Hmac (HmacRecipe (..), hmacCodecFor, hmacRecipes)
import Haskoki.Recipe.Kdf
  ( KdfRecipe (..)
  , kdfCodecFor
  , kdfRecipes
  )
import Haskoki.Recipe.Otp
  ( OtpRecipe (..)
  , hotpCodecFor
  , hotpRecipes
  )
import Haskoki.Recipe.RsaOaep
  ( RsaOaepRecipe (..)
  , rsaOaepCodecFor
  , rsaOaepRecipes
  )
import Haskoki.Recipe.RsaPkcs1
  ( RsaPkcs1Recipe (..)
  , rsaPkcs1CodecFor
  , rsaPkcs1Recipes
  )
import Haskoki.Recipe.RsaPss
  ( RsaPssRecipe (..)
  , rsaPssCodecFor
  , rsaPssRecipes
  )
import Haskoki.Registry.Generated (generatedInventory, mustGeneratedId)
import Haskoki.Registry.Types
import Haskoki.Types (Pkcs11Version (..))

-- | Behavioral family. Family dispatch never overrides a mechanism's
-- own permitted operations. Recipes extend the original set with the
-- name-shape families from @scripts/generate-mechanisms.py@: family is
-- a catalog grouping hint for recipe planning, never a behavior claim.
data Family
  = FamilyDigest
  | FamilyMac
  | FamilyCipher
  | FamilyAead
  | FamilyRsa
  | FamilyEc
  | FamilyDsa
  | FamilyKeyGen
  | FamilyKeyPair
  | FamilyDerive
  | FamilyWrap
  | FamilyKem
  | FamilyOtp
  | FamilyStateful
  | FamilyPqc
  | FamilySpecial
  deriving (Eq, Ord, Show, Enum, Bounded)

-- | Canonical family label, shared with @spec/mechanisms.json@.
familyName :: Family -> Text
familyName f = case f of
  FamilyDigest -> "digest"
  FamilyMac -> "mac"
  FamilyCipher -> "cipher"
  FamilyAead -> "aead"
  FamilyRsa -> "rsa"
  FamilyEc -> "ec"
  FamilyDsa -> "dsa"
  FamilyKeyGen -> "keygen"
  FamilyKeyPair -> "keypair"
  FamilyDerive -> "derive"
  FamilyWrap -> "wrap"
  FamilyKem -> "kem"
  FamilyOtp -> "otp"
  FamilyStateful -> "stateful"
  FamilyPqc -> "pqc"
  FamilySpecial -> "special"

-- | PKCS#11 operations a route may permit. Labels match the
-- @spec/mechanisms.json@ route vocabulary.
data Operation
  = OpDigest
  | OpSign
  | OpVerify
  | OpSignRecover
  | OpVerifyRecover
  | OpEncrypt
  | OpDecrypt
  | OpGenerateKey
  | OpGenerateKeyPair
  | OpDerive
  | OpWrap
  | OpUnwrap
  | OpEncapsulate
  | OpDecapsulate
  | OpMessageEncrypt
  | OpMessageDecrypt
  | OpMessageSign
  | OpMessageVerify
  | OpAuthWrap
  | OpAuthUnwrap
  deriving (Eq, Ord, Show, Enum, Bounded)

-- | Canonical operation label.
operationName :: Operation -> Text
operationName op = case op of
  OpDigest -> "digest"
  OpSign -> "sign"
  OpVerify -> "verify"
  OpSignRecover -> "sign-recover"
  OpVerifyRecover -> "verify-recover"
  OpEncrypt -> "encrypt"
  OpDecrypt -> "decrypt"
  OpGenerateKey -> "generate-key"
  OpGenerateKeyPair -> "generate-key-pair"
  OpDerive -> "derive"
  OpWrap -> "wrap"
  OpUnwrap -> "unwrap"
  OpEncapsulate -> "encapsulate"
  OpDecapsulate -> "decapsulate"
  OpMessageEncrypt -> "message-encrypt"
  OpMessageDecrypt -> "message-decrypt"
  OpMessageSign -> "message-sign"
  OpMessageVerify -> "message-verify"
  OpAuthWrap -> "authenticated-wrap"
  OpAuthUnwrap -> "authenticated-unwrap"

-- | Key-size unit for mechanism info. Units are mechanism-specific;
-- there is no universal default.
data KeySizeUnit
  = KeyBits
  | KeyBytes
  | NotApplicable
  | MechanismSpecific
  deriving (Eq, Ord, Show, Enum, Bounded)

-- | Canonical unit label, shared with @spec/mechanisms.json@.
keyUnitName :: KeySizeUnit -> Text
keyUnitName u = case u of
  KeyBits -> "bits"
  KeyBytes -> "bytes"
  NotApplicable -> "not-applicable"
  MechanismSpecific -> "mechanism-specific"

-- | A source backing a route: a byte-locked source id from
-- @spec/sources.lock.json@ plus the exact section or definition.
data SourceRef = SourceRef
  { srcId :: !Text
  , srcSection :: !Text
  } deriving (Eq, Show)

-- | One permitted operation with its source backing and acceptance
-- evidence. A route without source refs is not source-backed and is
-- rejected at registration.
data RoutePolicy = RoutePolicy
  { routeOperation :: !Operation
  , routeSources :: ![SourceRef]
  , routeAcceptance :: ![Text]
  } deriving (Eq, Show)

-- | A mechanism descriptor. The codec is 'Maybe' so that registration
-- can reject descriptors with no codec ('MissingCodec') instead of
-- trusting partial rows.
data Descriptor = Descriptor
  { descId :: !MechanismId
  , descCanonical :: !MechanismName
  , descAliases :: ![MechanismName]
  , descBaseline :: ![Pkcs11Version]
  , descFamily :: !Family
  , descCodec :: !(Maybe ParameterCodec)
  , descRoutes :: ![RoutePolicy]
  , descKeyUnit :: !KeySizeUnit
  , descMinKey :: !Word64
  , descMaxKey :: !Word64
  } deriving (Eq, Show)

-- | Registration failures. Every case keeps the row out of the
-- behavior registry; nothing is silently widened.
data RegistryError
  = MissingCodec !MechanismName
  | MissingPolicy !MechanismName !Text
  | DuplicateMechanism !MechanismId
  | AliasConflict !MechanismName !MechanismId !MechanismId
  | UnknownCatalogMember !MechanismId
  | PromoteMismatch !MechanismId !MechanismName !MechanismName
  deriving (Eq, Show)

-- | Official-inventory row: identity and aliases only, no behavior.
data InventoryEntry = InventoryEntry
  { invCanonical :: !MechanismName
  , invAliases :: ![MechanismName]
  } deriving (Eq, Show)

-- | Executable @(mechanism, operation)@ pairs of one backend.
newtype EngineCapabilities = EngineCapabilities
  { unEngineCapabilities :: Set (MechanismId, Operation) }
  deriving (Eq, Show)

-- | Build capabilities from a pair list.
mkCapabilities :: [(MechanismId, Operation)] -> EngineCapabilities
mkCapabilities = EngineCapabilities . Set.fromList

-- | Test one executable pair.
supports :: EngineCapabilities -> MechanismId -> Operation -> Bool
supports (EngineCapabilities s) mid op = Set.member (mid, op) s

-- | Registry holding the inventory, behavior, and catalog projections.
data Registry = Registry
  { regInventory :: !(Map MechanismId InventoryEntry)
  , regBehavior :: !(Map MechanismId Descriptor)
  , regCatalog :: !(Set MechanismId)
  } deriving (Eq, Show)

-- | Executability status of one mechanism id.
data MechanismStatus
  = StatusUnknown
  | StatusCatalogOnly
  | StatusSupported
  deriving (Eq, Show)

-- | Empty registry: no inventory, no behavior, no catalog.
emptyRegistry :: Registry
emptyRegistry = Registry Map.empty Map.empty Set.empty

-- | Canonical-plus-alias name index over the inventory.
nameIndex :: Registry -> Map MechanismName MechanismId
nameIndex reg = Map.fromList $
  [(invCanonical e, i) | (i, e) <- Map.toList (regInventory reg)]
  ++ [(a, i) | (i, e) <- Map.toList (regInventory reg), a <- invAliases e]

-- | Check name claims against the current index.
checkNames :: Registry -> MechanismId -> MechanismName -> [MechanismName]
           -> Either RegistryError ()
checkNames reg mid canon aliases =
  case [ (n, owner) | n <- canon : aliases
                   , Just owner <- [Map.lookup n (nameIndex reg)]
                   , owner /= mid ] of
    [] -> Right ()
    ((n, owner) : _) -> Left (AliasConflict n owner mid)

-- | Add an inventory-only row (catalog-only / historical). No codec or
-- policy is attached, so the row can never become executable.
addInventory :: Registry -> MechanismId -> MechanismName -> [MechanismName]
             -> Either RegistryError Registry
addInventory reg mid canon aliases
  | Map.member mid (regInventory reg) = Left (DuplicateMechanism mid)
  | otherwise = do
      checkNames reg mid canon aliases
      let entry = InventoryEntry canon aliases
      Right reg { regInventory = Map.insert mid entry (regInventory reg) }

-- | Register a behavior descriptor. Rejects rows with no codec, with
-- no routes, or with any route lacking source refs, plus duplicate
-- ids and alias conflicts.
registerDescriptor :: Registry -> Descriptor -> Either RegistryError Registry
registerDescriptor reg d = do
  case descCodec d of
    Nothing -> Left (MissingCodec (descCanonical d))
    Just _ -> Right ()
  case descRoutes d of
    [] -> Left (MissingPolicy (descCanonical d) "no operation routes")
    routes -> case [ r | r <- routes, null (routeSources r) ] of
      [] -> Right ()
      (r : _) -> Left (MissingPolicy (descCanonical d)
        ("operation " <> operationName (routeOperation r) <> " has no source refs"))
  if Map.member (descId d) (regInventory reg)
    then Left (DuplicateMechanism (descId d))
    else Right ()
  checkNames reg (descId d) (descCanonical d) (descAliases d)
  let entry = InventoryEntry (descCanonical d) (descAliases d)
  Right reg
    { regInventory = Map.insert (descId d) entry (regInventory reg)
    , regBehavior = Map.insert (descId d) d (regBehavior reg)
    }

-- | Promote a catalog-only inventory row to a behavior descriptor.
-- The id must already be in the inventory WITHOUT behavior, and the
-- descriptor's canonical name must match the inventory row exactly;
-- anything else is rejected (no silent renames, no double behavior,
-- no promotion of unknown ids). This is the catalog-to-behavior
-- path: identity comes from the generated inventory, behavior from
-- the reviewed descriptor.
promoteInventory :: Registry -> Descriptor -> Either RegistryError Registry
promoteInventory reg d = do
  case descCodec d of
    Nothing -> Left (MissingCodec (descCanonical d))
    Just _ -> Right ()
  case descRoutes d of
    [] -> Left (MissingPolicy (descCanonical d) "no operation routes")
    routes -> case [ r | r <- routes, null (routeSources r) ] of
      [] -> Right ()
      (r : _) -> Left (MissingPolicy (descCanonical d)
        ("operation " <> operationName (routeOperation r) <> " has no source refs"))
  case Map.lookup (descId d) (regInventory reg) of
    Nothing -> Left (UnknownCatalogMember (descId d))
    Just inv
      | Map.member (descId d) (regBehavior reg) ->
          Left (DuplicateMechanism (descId d))
      | invCanonical inv /= descCanonical d ->
          Left (PromoteMismatch (descId d) (invCanonical inv) (descCanonical d))
      | otherwise -> do
          checkNames reg (descId d) (descCanonical d) (descAliases d)
          let entry = InventoryEntry (descCanonical d) (descAliases d)
          Right reg
            { regInventory = Map.insert (descId d) entry (regInventory reg)
            , regBehavior = Map.insert (descId d) d (regBehavior reg)
            }

-- | Replace the catalog projection. Every member must already be in
-- the inventory.
setCatalog :: Registry -> [MechanismId] -> Either RegistryError Registry
setCatalog reg mids =
  case [ m | m <- mids, not (Map.member m (regInventory reg)) ] of
    (m : _) -> Left (UnknownCatalogMember m)
    [] -> Right reg { regCatalog = Set.fromList mids }

-- | Behavior lookup: 'Nothing' for unknown and catalog-only ids.
lookupBehavior :: Registry -> MechanismId -> Maybe Descriptor
lookupBehavior reg mid = Map.lookup mid (regBehavior reg)

-- | Resolve a canonical or alias name to its behavior descriptor.
lookupByName :: Registry -> MechanismName -> Maybe Descriptor
lookupByName reg name =
  Map.lookup name (nameIndex reg) >>= Map.lookup `flip` regBehavior reg

-- | Every behavior-backed @(mechanism, operation)@ pair, ascending by
-- id. Backends derive their capabilities from this so that only
-- reviewed descriptors execute.
behaviorRoutes :: Registry -> [(MechanismId, Operation)]
behaviorRoutes reg =
  [(i, routeOperation r) | (i, d) <- Map.toAscList (regBehavior reg), r <- descRoutes d]

-- | Catalog projection as a deduplicated ascending id list. Aliases
-- never appear here: alias names share their numeric id.
mechanismList :: Registry -> [MechanismId]
mechanismList = Set.toAscList . regCatalog

-- | Behavior ids, ascending.
behaviorIds :: Registry -> [MechanismId]
behaviorIds = Map.keys . regBehavior

-- | Inventory ids, ascending.
inventoryIds :: Registry -> [MechanismId]
inventoryIds = Map.keys . regInventory

-- | Status of one id: supported needs behavior; catalog membership
-- without behavior is catalog-only.
describeStatus :: Registry -> MechanismId -> MechanismStatus
describeStatus reg mid
  | Map.member mid (regBehavior reg) = StatusSupported
  | Set.member mid (regCatalog reg) = StatusCatalogOnly
  | otherwise = StatusUnknown

-- | Executability: behavior present, catalog-listed, operation
-- permitted by the descriptor routes, and supported by the engine.
isExecutable :: Registry -> EngineCapabilities -> MechanismId -> Operation -> Bool
isExecutable reg caps mid op =
  case Map.lookup mid (regBehavior reg) of
    Nothing -> False
    Just d ->
      Set.member mid (regCatalog reg)
      && any ((== op) . routeOperation) (descRoutes d)
      && supports caps mid op

-- ---------------------------------------------------------------------------
-- Curated population
-- ---------------------------------------------------------------------------

-- | All four baseline interfaces.
allBaselines :: [Pkcs11Version]
allBaselines = [Pkcs11_2_40, Pkcs11_3_0, Pkcs11_3_1, Pkcs11_3_2]

-- | Identity ref: the single locked header, naming the exact @CKM_*@
-- definition in the byte-locked artifact.
idSources :: MechanismName -> [SourceRef]
idSources ck =
  [ SourceRef "S-PD-32" ("pkcs11.h:" <> ck) ]

-- | One source-backed synthetic route (A37: same fixture/seed/schedule
-- gives equivalent normalized outputs).
synthRoute :: Operation -> MechanismName -> RoutePolicy
synthRoute op ck = RoutePolicy op (idSources ck) ["A37"]

noParams :: ParameterCodec
noParams = ParameterCodec "no-params" 1

dSHA256 :: Descriptor
dSHA256 = Descriptor
  { descId = MechanismId 0x250
  , descCanonical = "CKM_SHA256"
  , descAliases = []
  , descBaseline = allBaselines
  , descFamily = FamilyDigest
  , descCodec = Just digestCodec
  -- The verified multipart (A16) and real-KAT (A39) cases
  -- join synthetic A37 (the codec value is unchanged: no-params/1).
  , descRoutes = [mechRoute OpDigest "CKM_SHA256" ["A16", "A37", "A39"]]
  , descKeyUnit = NotApplicable
  , descMinKey = 0
  , descMaxKey = 0
  }

-- | One digest behavior descriptor: codec and shape from the digest
-- recipe, acceptance from the verified group cases (multipart A16,
-- synthetic A37, real-KAT A39). Baselines follow the header span
-- (SHA-3 arrived in 3.0; the rest are 2.40).
digestDesc :: MechanismName -> [Pkcs11Version] -> Descriptor
digestDesc name baseline = promotedDesc name baseline FamilyDigest
  digestCodec [mechRoute OpDigest name ["A16", "A37", "A39"]]
  NotApplicable 0 0

dSHA224, dSHA384, dSHA512, dSHA512_224, dSHA512_256 :: Descriptor
dSHA224 = digestDesc "CKM_SHA224" allBaselines
dSHA384 = digestDesc "CKM_SHA384" allBaselines
dSHA512 = digestDesc "CKM_SHA512" allBaselines
dSHA512_224 = digestDesc "CKM_SHA512_224" allBaselines
dSHA512_256 = digestDesc "CKM_SHA512_256" allBaselines

dSHA3_224, dSHA3_256, dSHA3_384, dSHA3_512 :: Descriptor
dSHA3_224 = digestDesc "CKM_SHA3_224" [Pkcs11_3_0, Pkcs11_3_1, Pkcs11_3_2]
dSHA3_256 = digestDesc "CKM_SHA3_256" [Pkcs11_3_0, Pkcs11_3_1, Pkcs11_3_2]
dSHA3_384 = digestDesc "CKM_SHA3_384" [Pkcs11_3_0, Pkcs11_3_1, Pkcs11_3_2]
dSHA3_512 = digestDesc "CKM_SHA3_512" [Pkcs11_3_0, Pkcs11_3_1, Pkcs11_3_2]

dSHA1, dMD5, dRIPEMD160 :: Descriptor
dSHA1 = digestDesc "CKM_SHA_1" allBaselines
dMD5 = digestDesc "CKM_MD5" allBaselines
dRIPEMD160 = digestDesc "CKM_RIPEMD160" allBaselines

-- | Baseline span for an HMAC recipe name (SHA-3 arrived in 3.0;
-- the rest, GENERAL rows included, are 2.40).
hmacBaselines :: MechanismName -> [Pkcs11Version]
hmacBaselines name
  | "CKM_SHA3_" `T.isPrefixOf` name = [Pkcs11_3_0, Pkcs11_3_1, Pkcs11_3_2]
  | otherwise = allBaselines

-- | The HMAC behavior group, derived from the recipe table:
-- one descriptor per recipe row, codec from 'hmacCodecFor', sign and
-- verify routes citing synthetic A37 and real-KAT A39 (no A16: the
-- backends offer one-shot MAC only, no multipart MAC entry). This
-- replaces the hand-written HMAC-SHA-256 descriptor (same id,
-- completed routes); the other 25 rows are new promotions.
hmacDescs :: [Descriptor]
hmacDescs =
  [ promotedDesc (hrName r) (hmacBaselines (hrName r)) FamilyMac
      (hmacCodecFor r)
      [ mechRoute OpSign (hrName r) ["A37", "A39"]
      , mechRoute OpVerify (hrName r) ["A37", "A39"]
      ]
      MechanismSpecific 0 0
  | r <- hmacRecipes
  ]

-- | Baseline span for an RSA v1.5 recipe name (SHA-3 arrived in
-- 3.0; the rest, the raw row included, are 2.40).
rsaPkcs1Baselines :: MechanismName -> [Pkcs11Version]
rsaPkcs1Baselines name
  | "CKM_SHA3_" `T.isPrefixOf` name = [Pkcs11_3_0, Pkcs11_3_1, Pkcs11_3_2]
  | otherwise = allBaselines

-- | The RSA v1.5 behavior group, derived from the recipe table:
-- one descriptor per recipe row, codec from 'rsaPkcs1CodecFor',
-- sign and verify routes citing synthetic A37 and real-KAT A39 (no
-- A16: the backends offer one-shot sign only, no multipart sign
-- entry). Key bounds are the de-facto vendor range 512..4096 bits.
rsaPkcs1Descs :: [Descriptor]
rsaPkcs1Descs =
  [ promotedDesc (rrName r) (rsaPkcs1Baselines (rrName r)) FamilyRsa
      (rsaPkcs1CodecFor r)
      [ mechRoute OpSign (rrName r) ["A37", "A39"]
      , mechRoute OpVerify (rrName r) ["A37", "A39"]
      ]
      KeyBits 512 4096
  | r <- rsaPkcs1Recipes
  ]

-- | The RSA-PSS behavior group, derived from the recipe table:
-- one descriptor per recipe row, codec from 'rsaPssCodecFor',
-- sign and verify routes citing synthetic A37 and real-KAT A39 (no
-- A16: the backends offer one-shot sign only). Key bounds are the
-- de-facto vendor range 512..4096 bits.
rsaPssDescs :: [Descriptor]
rsaPssDescs =
  [ promotedDesc (rpName r) (rsaPkcs1Baselines (rpName r)) FamilyRsa
      (rsaPssCodecFor r)
      [ mechRoute OpSign (rpName r) ["A37", "A39"]
      , mechRoute OpVerify (rpName r) ["A37", "A39"]
      ]
      KeyBits 512 4096
  | r <- rsaPssRecipes
  ]

-- | The RSA-OAEP behavior descriptor, derived from the recipe table:
-- encrypt and decrypt routes citing the verified
-- multipart (A16: the planner buffers updates and emits one
-- asymmetric effect at final), synthetic (A37), and real-KAT (A39)
-- cases. No wrap/unwrap routes: the wrap planner is AES-CBC
-- only (named gap, see the JSON note).
rsaOaepDescs :: [Descriptor]
rsaOaepDescs =
  [ promotedDesc (roName r) allBaselines FamilyRsa
      (rsaOaepCodecFor r)
      [ mechRoute OpEncrypt (roName r) ["A16", "A37", "A39"]
      , mechRoute OpDecrypt (roName r) ["A16", "A37", "A39"]
      ]
      KeyBits 512 4096
  | r <- rsaOaepRecipes
  ]

-- | Baseline span for an ECDSA recipe name (SHA-3 arrived in
-- 3.0; the rest, the raw row included, are 2.40).
ecdsaBaselines :: MechanismName -> [Pkcs11Version]
ecdsaBaselines name
  | "CKM_ECDSA_SHA3_" `T.isPrefixOf` name = [Pkcs11_3_0, Pkcs11_3_1, Pkcs11_3_2]
  | otherwise = allBaselines

-- | The ECDSA behavior group, derived from the recipe table:
-- one descriptor per recipe row, codec from 'ecdsaCodecFor',
-- sign and verify routes citing synthetic A37 and real-KAT A39 (no
-- A16: the backends offer one-shot sign only). Key bounds are the
-- curve range 256..521 bits.
ecdsaDescs :: [Descriptor]
ecdsaDescs =
  [ promotedDesc (reName r) (ecdsaBaselines (reName r)) FamilyEc
      (ecdsaCodecFor r)
      [ mechRoute OpSign (reName r) ["A37", "A39"]
      , mechRoute OpVerify (reName r) ["A37", "A39"]
      ]
      KeyBits 256 521
  | r <- ecdsaRecipes
  ]

-- | The CMAC behavior group, derived from the recipe table:
-- one descriptor per recipe row, codec from 'cmacCodecFor',
-- sign and verify routes citing synthetic A37 and real-KAT A39 (no
-- A16: the driver offers one-shot MAC only).
cmacDescs :: [Descriptor]
cmacDescs =
  [ promotedDesc (rcName r) allBaselines FamilyMac
      (cmacCodecFor r)
      [ mechRoute OpSign (rcName r) ["A37", "A39"]
      , mechRoute OpVerify (rcName r) ["A37", "A39"]
      ]
      MechanismSpecific 0 0
  | r <- cmacRecipes
  ]

-- | The KDF behavior group, derived from the recipe table:
-- one descriptor per recipe row, codec from 'kdfCodecFor',
-- the derive route citing the planner case (A20), the synthetic
-- construction (A37), and the real vectors (A39). All rows predate
-- 2.40; key bounds are mechanism-specific (widths follow the
-- digest or the planned length).
kdfDescs :: [Descriptor]
kdfDescs =
  [ promotedDesc (rkName r) allBaselines FamilyDerive
      (kdfCodecFor r)
      [ mechRoute OpDerive (rkName r) ["A20", "A37", "A39"]
      ]
      MechanismSpecific 0 0
  | r <- kdfRecipes
  ]

-- | The OTP behavior group, derived from the recipe table:
-- one descriptor per recipe row, codec from 'hotpCodecFor',
-- the sign and verify routes citing the synthetic construction
-- (A37) and the real KATs (A39). Key bounds are
-- mechanism-specific (any non-empty HMAC key codes; keygen mints
-- 16-64 bytes).
otpDescs :: [Descriptor]
otpDescs =
  [ promotedDesc (otpName r) allBaselines FamilyOtp
      (hotpCodecFor r)
      [ mechRoute OpSign (otpName r) ["A37", "A39"]
      , mechRoute OpVerify (otpName r) ["A37", "A39"]
      ]
      MechanismSpecific 0 0
  | r <- hotpRecipes
  ]

-- | The ECDH behavior group, derived from the recipe table:
-- one descriptor per recipe row, codec from 'ecdhCodecFor',
-- the derive route citing the planner case (A20), the synthetic
-- construction (A37), and the real KATs (A39). Both rows predate
-- 2.40; key bounds are mechanism-specific (the secret width follows
-- the base curve).
ecdhDescs :: [Descriptor]
ecdhDescs =
  [ promotedDesc (rhName r) allBaselines FamilyDerive
      (ecdhCodecFor r)
      [ mechRoute OpDerive (rhName r) ["A20", "A37", "A39"]
      ]
      MechanismSpecific 0 0
  | r <- ecdhRecipes
  ]

dAESKeyGen :: Descriptor
dAESKeyGen = Descriptor
  { descId = MechanismId 0x1080
  , descCanonical = "CKM_AES_KEY_GEN"
  , descAliases = []
  , descBaseline = allBaselines
  , descFamily = FamilyKeyGen
  -- Mechanism parameters are NULL; the length arrives via the
  -- CKA_VALUE_LEN template attribute, not via pParameter.
  , descCodec = Just noParams
  , descRoutes = [synthRoute OpGenerateKey "CKM_AES_KEY_GEN"]
  , descKeyUnit = KeyBits
  , descMinKey = 128
  , descMaxKey = 256
  }

-- | @CKM_HOTP_KEY_GEN@: mechanism parameters are NULL;
-- the length arrives via the @CKA_VALUE_LEN@ template attribute
-- (16-64 bytes), not via pParameter. Synthetic-only (the AES
-- keygen precedent).
dHotpKeyGen :: Descriptor
dHotpKeyGen = promotedDesc "CKM_HOTP_KEY_GEN" allBaselines FamilyKeyGen
  noParams [synthRoute OpGenerateKey "CKM_HOTP_KEY_GEN"]
  KeyBits 128 512

-- | @CKM_GENERIC_SECRET_KEY_GEN@: mechanism parameters are NULL;
-- the length arrives via the @CKA_VALUE_LEN@ template attribute
-- (1-255 bytes: the floor refuses empty secrets, the ceiling is
-- the one-byte 'GenBytes' planner-driver frame).
dGenericSecretKeyGen :: Descriptor
dGenericSecretKeyGen = promotedDesc "CKM_GENERIC_SECRET_KEY_GEN" allBaselines FamilyKeyGen
  noParams [synthRoute OpGenerateKey "CKM_GENERIC_SECRET_KEY_GEN"]
  KeyBits 8 2040

-- | The block-cipher behavior group, derived from the recipe table:
-- one descriptor per recipe row, codec from
-- 'cipherCodecFor', encrypt and decrypt routes citing the verified
-- multipart (A16), synthetic (A37), and real-KAT (A39) cases. This
-- replaces the hand-written AES-CBC descriptor (same id,
-- completed routes); the other 8 rows are new promotions. AES-CBC
-- keeps its tested wrap/unwrap/authenticated routes (same
-- 16-byte-IV parameter shape); key bounds follow the recipe's key
-- set (DES3 16..24, the AES family 16..32).
cipherDescs :: [Descriptor]
cipherDescs =
  [ promotedDesc (crName r) allBaselines FamilyCipher
      (cipherCodecFor r)
      ( [ mechRoute OpEncrypt (crName r) ["A16", "A37", "A39"]
        , mechRoute OpDecrypt (crName r) ["A16", "A37", "A39"]
        ] ++ wrapRoutes (crName r)
      )
      KeyBytes (fromIntegral (minimum (crKeyLens r)))
      (fromIntegral (maximum (crKeyLens r)))
  | r <- cipherRecipes
  ]
  where
    wrapRoutes name
      | name == "CKM_AES_CBC" =
          [ mechRoute OpWrap "CKM_AES_CBC" ["A20", "A37", "A39"]
          , mechRoute OpUnwrap "CKM_AES_CBC" ["A20", "A37", "A39"]
          , mechRoute OpAuthWrap "CKM_AES_CBC" ["A23", "A37"]
          , mechRoute OpAuthUnwrap "CKM_AES_CBC" ["A23", "A37"]
          ]
      | otherwise = []

-- | Aliases for one inventoried id, resolved through the generated
-- table (header-derived, never hand-typed). Unknown ids (test-local)
-- carry no aliases.
generatedAliases :: MechanismId -> [MechanismName]
generatedAliases (MechanismId w) =
  [ a | (w', _, als) <- generatedInventory, w' == w, a <- als ]

-- | One source-backed route over the identity ref.
mechRoute :: Operation -> MechanismName -> [Text] -> RoutePolicy
mechRoute op ck cases = RoutePolicy op (idSources ck) cases

-- | Promote one inventoried mechanism to a behavior descriptor: id
-- and aliases resolve through the generated table (never hand-typed);
-- baseline span, family, codec, routes and key bounds are the
-- reviewed promotion content.
promotedDesc :: MechanismName -> [Pkcs11Version] -> Family -> ParameterCodec
             -> [RoutePolicy] -> KeySizeUnit -> Word64 -> Word64 -> Descriptor
promotedDesc name baseline fam codec routes unit lo hi =
  let mid = MechanismId (mustGeneratedId name)
  in Descriptor
    { descId = mid
    , descCanonical = name
    , descAliases = generatedAliases mid
    , descBaseline = baseline
    , descFamily = fam
    , descCodec = Just codec
    , descRoutes = routes
    , descKeyUnit = unit
    , descMinKey = lo
    , descMaxKey = hi
    }

dECKeyPairGen :: Descriptor
dECKeyPairGen = promotedDesc "CKM_EC_KEY_PAIR_GEN" allBaselines FamilyKeyPair
  noParams [mechRoute OpGenerateKeyPair "CKM_EC_KEY_PAIR_GEN" ["A20", "A37"]]
  KeyBits 0 0

dRsaPkcsKeyPairGen :: Descriptor
dRsaPkcsKeyPairGen = promotedDesc "CKM_RSA_PKCS_KEY_PAIR_GEN" allBaselines FamilyKeyPair
  noParams [mechRoute OpGenerateKeyPair "CKM_RSA_PKCS_KEY_PAIR_GEN" ["A20", "A37"]]
  KeyBits 0 0

dMlKemKeyPairGen :: Descriptor
dMlKemKeyPairGen = promotedDesc "CKM_ML_KEM_KEY_PAIR_GEN" [Pkcs11_3_2] FamilyKeyPair
  noParams [mechRoute OpGenerateKeyPair "CKM_ML_KEM_KEY_PAIR_GEN" ["A20", "A37"]]
  KeyBits 0 0

dHkdfDerive :: Descriptor
dHkdfDerive = promotedDesc "CKM_HKDF_DERIVE"
  [Pkcs11_3_0, Pkcs11_3_1, Pkcs11_3_2] FamilyDerive
  (ParameterCodec "hkdf-expand-params" 1)
  [mechRoute OpDerive "CKM_HKDF_DERIVE" ["A20", "A37", "A39"]]
  MechanismSpecific 0 0

dMlKem :: Descriptor
dMlKem = promotedDesc "CKM_ML_KEM" [Pkcs11_3_2] FamilyKem
  noParams
  [ mechRoute OpEncapsulate "CKM_ML_KEM" ["A22", "A37"]
  , mechRoute OpDecapsulate "CKM_ML_KEM" ["A22", "A37"]
  ]
  MechanismSpecific 0 0

-- | AEAD behavior descriptors: one per GCM recipe row, with the
-- recipe codec, encrypt/decrypt routes, and AES key bounds
-- (16..32 bytes).
aeadDescs :: [Descriptor]
aeadDescs =
  [ promotedDesc (gcmName r) allBaselines FamilyAead
      (gcmCodecFor r)
      [ mechRoute OpEncrypt (gcmName r) ["A16", "A37", "A39"]
      , mechRoute OpDecrypt (gcmName r) ["A16", "A37", "A39"]
      ]
      KeyBytes 16 32
  | r <- gcmRecipes
  ]

-- | The curated population: 109 reviewed behavior descriptors
-- with concrete rules, plus the full header inventory (464
-- canonical rows covering all 480 header CKM names) folded in from
-- the generated table. Catalog-only rows (355: everything but the
-- 109 behavior ids) stay in the coverage denominator but never
-- become executable. The catalog covers the full inventory.
curatedRegistry :: Registry
curatedRegistry =
  case build of
    Right r -> r
    Left err -> error ("curatedRegistry: " ++ show err)
  where
    behaviorDescs :: [Descriptor]
    behaviorDescs =
      ( [ dSHA256, dAESKeyGen, dHotpKeyGen, dGenericSecretKeyGen
        , dECKeyPairGen, dRsaPkcsKeyPairGen, dMlKemKeyPairGen, dHkdfDerive, dMlKem
        , dSHA224, dSHA384, dSHA512, dSHA512_224, dSHA512_256
        , dSHA3_224, dSHA3_256, dSHA3_384, dSHA3_512
        , dSHA1, dMD5, dRIPEMD160
        ] ++ hmacDescs ++ cipherDescs ++ aeadDescs ++ rsaPkcs1Descs
          ++ rsaPssDescs ++ rsaOaepDescs ++ ecdsaDescs ++ ecdhDescs
          ++ cmacDescs ++ kdfDescs ++ otpDescs
      )
    behaviorIds0 :: [Word64]
    behaviorIds0 = map (unMechanismId . descId) behaviorDescs
    addGenerated :: Registry -> (Word64, Text, [Text])
                 -> Either RegistryError Registry
    addGenerated reg (w, name, aliases)
      | w `elem` behaviorIds0 = Right reg
      | otherwise = addInventory reg (MechanismId w) name aliases
    build :: Either RegistryError Registry
    build = do
      r0 <- Right emptyRegistry
      r1 <- foldM registerDescriptor r0 behaviorDescs
      r2 <- foldM addGenerated r1 generatedInventory
      setCatalog r2 [MechanismId w | (w, _, _) <- generatedInventory]

-- ---------------------------------------------------------------------------
-- Canonical dump (consistency projection for spec/mechanisms.json)
-- ---------------------------------------------------------------------------

-- | Render @0x00000250@-style ids (lowercase prefix, 8 uppercase hex).
renderMechId :: MechanismId -> Text
renderMechId (MechanismId w) =
  T.pack ("0x" ++ map toUpper (padLeft 8 '0' (showHex w "")))
  where
    padLeft :: Int -> Char -> String -> String
    padLeft n c s = replicate (n - length s) c ++ s

renderCodec :: ParameterCodec -> Text
renderCodec c = codecName c <> "/" <> T.pack (show (codecVersion c))

renderRoute :: RoutePolicy -> Text
renderRoute r =
  operationName (routeOperation r) <> ":" <> T.intercalate "," (sort (routeAcceptance r))

dumpMech :: Descriptor -> Text
dumpMech d = T.intercalate "|"
  [ "mech"
  , renderMechId (descId d)
  , descCanonical d
  , T.intercalate "," (sort (descAliases d))
  , familyName (descFamily d)
  , maybe "none/0" renderCodec (descCodec d)
  , keyUnitName (descKeyUnit d) <> ":" <> T.pack (show (descMinKey d))
      <> "-" <> T.pack (show (descMaxKey d))
  , T.intercalate ";" (map renderRoute (sortOn (operationName . routeOperation) (descRoutes d)))
  ]

dumpInv :: MechanismId -> InventoryEntry -> Text
dumpInv mid e = T.intercalate "|"
  [ "inv"
  , renderMechId mid
  , invCanonical e
  , T.intercalate "," (sort (invAliases e))
  , "catalog-only"
  ]

-- | Canonical projection of the registry, line-oriented so that
-- @scripts/check-mechanisms.py@ can render the same text from
-- @spec/mechanisms.json@ without a Haskell JSON dependency.
dumpRegistry :: Registry -> Text
dumpRegistry reg = T.unlines $
  ["schema 1"]
  ++ [ dumpMech d | (_, d) <- Map.toAscList (regBehavior reg) ]
  ++ [ dumpInv i e | (i, e) <- Map.toAscList (regInventory reg)
                  , not (Map.member i (regBehavior reg)) ]
  ++ ["catalog|" <> T.intercalate "," (map renderMechId (mechanismList reg))]
