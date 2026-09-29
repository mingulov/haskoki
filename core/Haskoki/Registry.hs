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
import Haskoki.Recipe.CbcMac
  ( CbcMacRecipe (..)
  , cbcmacCodecFor
  , cbcmacRecipes
  )
import Haskoki.Recipe.Des3Mac
  ( Des3MacRecipe (..)
  , des3macCodecFor
  , des3macRecipes
  )
import Haskoki.Recipe.Gmac
  ( GmacRecipe (..)
  , gmacCodecFor
  , gmacRecipes
  )
import Haskoki.Recipe.XcbcMac
  ( XcbcRecipe (..)
  , xcbcCodecFor
  , xcbcRecipes
  )
import Haskoki.Recipe.Digest (digestCodec)
import Haskoki.Recipe.Dh
  ( DhRecipe (..)
  , dhCodecFor
  , dhRecipes
  )
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
import Haskoki.Recipe.Dsa
  ( DsaRecipe (..)
  , dsaCodecFor
  , dsaRecipes
  )
import Haskoki.Recipe.Eddsa
  ( EddsaRecipe (..)
  , eddsaCodecFor
  , eddsaRecipes
  )
import Haskoki.Recipe.Ccm
  ( CcmRecipe (..)
  , ccmCodecFor
  , ccmRecipes
  )
import Haskoki.Recipe.Chacha20
  ( Chacha20Recipe (..)
  , chachaCodecFor
  , chachaRecipes
  )
import Haskoki.Recipe.Gcm
  ( GcmRecipe (..)
  , gcmCodecFor
  , gcmRecipes
  )
import Haskoki.Recipe.Hmac (HmacRecipe (..), hmacCodecFor, hmacRecipes)
import Haskoki.Recipe.MlDsa
  ( MldsaRecipe (..)
  , mldsaCodecFor
  , mldsaRecipes
  )
import Haskoki.Recipe.SlhDsa
  ( SlhdsaRecipe (..)
  , slhdsaCodecFor
  , slhdsaRecipes
  )
import Haskoki.Recipe.EncryptData
  ( EncryptDataRecipe (..)
  , encryptDataCodecFor
  , encryptDataRecipes
  )
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
import Haskoki.Recipe.Sp800108
  ( Sp800Recipe (..)
  , sp800CodecFor
  , sp800Recipes
  )
import Haskoki.Recipe.ByteOps
  ( ByteOpsRecipe (..)
  , byteOpsCodecFor
  , byteOpsRecipes
  )
import Haskoki.Recipe.TlsKdf
  ( TlsKdfRecipe (..)
  , tlsKdfCodecFor
  , tlsKdfRecipes
  )
import Haskoki.Recipe.TlsKeyMat
  ( TlsKeyMatRecipe (..)
  , tlsKeyMatCodecFor
  , tlsKeyMatRecipes
  )
import Haskoki.Recipe.Pbe
  ( PbeRecipe (..)
  , pbeCodecFor
  , pbeKeyLen
  , pbeRecipes
  )
import Haskoki.Recipe.Ssl3
  ( Ssl3Kind (..)
  , Ssl3Recipe (..)
  , ssl3CodecFor
  , ssl3Recipes
  )
import Haskoki.Recipe.Ike
  ( IkeRecipe (..)
  , ikeCodecFor
  , ikeRecipes
  )
import Haskoki.Recipe.TlsPrf
  ( TlsPrfRecipe (..)
  , tlsPrfCodecFor
  , tlsPrfRecipes
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
import Haskoki.Recipe.RsaX509
  ( RsaX509Recipe (..)
  , rsaX509CodecFor
  , rsaX509Recipes
  )
import Haskoki.Recipe.RsaX931
  ( RsaX931Recipe (..)
  , rsaX931CodecFor
  , rsaX931Recipes
  )
import Haskoki.Recipe.Poly1305
  ( Poly1305Recipe (..)
  , poly1305CodecFor
  , poly1305Recipes
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

dBLAKE2B_512 :: Descriptor
dBLAKE2B_512 = digestDesc "CKM_BLAKE2B_512" [Pkcs11_3_0, Pkcs11_3_1, Pkcs11_3_2]

dBLAKE2B_160, dBLAKE2B_256, dBLAKE2B_384 :: Descriptor
dBLAKE2B_160 = digestDesc "CKM_BLAKE2B_160" [Pkcs11_3_0, Pkcs11_3_1, Pkcs11_3_2]
dBLAKE2B_256 = digestDesc "CKM_BLAKE2B_256" [Pkcs11_3_0, Pkcs11_3_1, Pkcs11_3_2]
dBLAKE2B_384 = digestDesc "CKM_BLAKE2B_384" [Pkcs11_3_0, Pkcs11_3_1, Pkcs11_3_2]

-- | Baseline span for an HMAC recipe name (SHA-3 and BLAKE2B
-- arrived in 3.0; the rest, GENERAL rows included, are 2.40).
hmacBaselines :: MechanismName -> [Pkcs11Version]
hmacBaselines name
  | "CKM_SHA3_" `T.isPrefixOf` name = [Pkcs11_3_0, Pkcs11_3_1, Pkcs11_3_2]
  | "CKM_BLAKE2B_" `T.isPrefixOf` name = [Pkcs11_3_0, Pkcs11_3_1, Pkcs11_3_2]
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
-- entry). The raw row additionally serves wrap/unwrap (block-type-2
-- cipher; the digest rows are signature-only). Key bounds are the
-- de-facto vendor range 512..4096 bits.
rsaPkcs1Descs :: [Descriptor]
rsaPkcs1Descs =
  [ promotedDesc (rrName r) (rsaPkcs1Baselines (rrName r)) FamilyRsa
      (rsaPkcs1CodecFor r)
      ( [ mechRoute OpSign (rrName r) ["A37", "A39"]
        , mechRoute OpVerify (rrName r) ["A37", "A39"]
        ] ++ wrapRoutes (rrName r)
      )
      KeyBits 512 4096
  | r <- rsaPkcs1Recipes
  ]
  where
    wrapRoutes name
      | name == "CKM_RSA_PKCS" =
          [ mechRoute OpWrap "CKM_RSA_PKCS" ["A20", "A37", "A39"]
          , mechRoute OpUnwrap "CKM_RSA_PKCS" ["A20", "A37", "A39"]
          ]
      | otherwise = []

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
-- cases, plus wrap/unwrap routes citing the key-management (A20),
-- synthetic (A37), and real-KAT (A39) cases.
rsaOaepDescs :: [Descriptor]
rsaOaepDescs =
  [ promotedDesc (roName r) allBaselines FamilyRsa
      (rsaOaepCodecFor r)
      [ mechRoute OpEncrypt (roName r) ["A16", "A37", "A39"]
      , mechRoute OpDecrypt (roName r) ["A16", "A37", "A39"]
      , mechRoute OpWrap (roName r) ["A20", "A37", "A39"]
      , mechRoute OpUnwrap (roName r) ["A20", "A37", "A39"]
      ]
      KeyBits 512 4096
  | r <- rsaOaepRecipes
  ]

-- | The RSA-X.509 behavior descriptor, derived from the recipe table:
-- sign and verify routes citing synthetic A37 and real-KAT A39 (no
-- A16: the backends offer one-shot sign only), encrypt and decrypt
-- routes citing the verified multipart (A16: the planner buffers
-- updates and emits one asymmetric effect at final), synthetic
-- (A37), and real-KAT (A39) cases, plus wrap/unwrap routes citing
-- the key-management (A20), synthetic (A37), and real-KAT (A39)
-- cases. Key bounds are the de-facto vendor range 512..4096 bits.
rsaX509Descs :: [Descriptor]
rsaX509Descs =
  [ promotedDesc (rxName r) allBaselines FamilyRsa
      (rsaX509CodecFor r)
      [ mechRoute OpSign (rxName r) ["A37", "A39"]
      , mechRoute OpVerify (rxName r) ["A37", "A39"]
      , mechRoute OpEncrypt (rxName r) ["A16", "A37", "A39"]
      , mechRoute OpDecrypt (rxName r) ["A16", "A37", "A39"]
      , mechRoute OpWrap (rxName r) ["A20", "A37", "A39"]
      , mechRoute OpUnwrap (rxName r) ["A20", "A37", "A39"]
      ]
      KeyBits 512 4096
  | r <- rsaX509Recipes
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

-- | Baseline span for a DSA recipe name (SHA-3 arrived in
-- 3.0; the rest, the raw row included, are 2.40 and older).
dsaBaselines :: MechanismName -> [Pkcs11Version]
dsaBaselines name
  | "CKM_DSA_SHA3_" `T.isPrefixOf` name = [Pkcs11_3_0, Pkcs11_3_1, Pkcs11_3_2]
  | otherwise = allBaselines

-- | The DSA behavior group, derived from the recipe table:
-- one descriptor per recipe row, codec from 'dsaCodecFor',
-- sign and verify routes citing synthetic A37 and real-KAT A39 (no
-- A16: the backends offer one-shot sign only). Key bounds are the
-- served prime range 1024..3072 bits.
dsaDescs :: [Descriptor]
dsaDescs =
  [ promotedDesc (rdName r) (dsaBaselines (rdName r)) FamilyDsa
      (dsaCodecFor r)
      [ mechRoute OpSign (rdName r) ["A37", "A39"]
      , mechRoute OpVerify (rdName r) ["A37", "A39"]
      ]
      KeyBits 1024 3072
  | r <- dsaRecipes
  ]

-- | Baseline span for the EdDSA recipe (@CKM_EDDSA@ arrived in
-- 3.0).
eddsaBaselines :: MechanismName -> [Pkcs11Version]
eddsaBaselines _ = [Pkcs11_3_0, Pkcs11_3_1, Pkcs11_3_2]

-- | The EdDSA behavior group, derived from the recipe table:
-- one descriptor per recipe row, codec from 'eddsaCodecFor',
-- sign and verify routes citing synthetic A37 and real-KAT A39 (no
-- A16: the backends offer one-shot sign only). Key bounds are the
-- served seed range 256..456 bits (Ed25519..Ed448).
eddsaDescs :: [Descriptor]
eddsaDescs =
  [ promotedDesc (redName r) (eddsaBaselines (redName r)) FamilyEc
      (eddsaCodecFor r)
      [ mechRoute OpSign (redName r) ["A37", "A39"]
      , mechRoute OpVerify (redName r) ["A37", "A39"]
      ]
      KeyBits 256 456
  | r <- eddsaRecipes
  ]

-- | Baseline span for the ML-DSA recipe (@CKM_ML_DSA@ arrived in
-- 3.2).
mldsaBaselines :: MechanismName -> [Pkcs11Version]
mldsaBaselines _ = [Pkcs11_3_2]

-- | The ML-DSA behavior group, derived from the recipe table:
-- one descriptor per recipe row, codec from 'mldsaCodecFor',
-- sign and verify routes citing synthetic A37 and real-KAT A39 (no
-- A16: the backends offer one-shot sign only). Key bounds are the
-- served public-key range 1312..2592 bytes (FIPS 204 widths for
-- ML-DSA-44..87, the OASIS mechanism-info unit).
mldsaDescs :: [Descriptor]
mldsaDescs =
  [ promotedDesc (rmlName r) (mldsaBaselines (rmlName r)) FamilyPqc
      (mldsaCodecFor r)
      [ mechRoute OpSign (rmlName r) ["A37", "A39"]
      , mechRoute OpVerify (rmlName r) ["A37", "A39"]
      ]
      KeyBytes 1312 2592
  | r <- mldsaRecipes
  ]

-- | Baseline span for the SLH-DSA recipe (@CKM_SLH_DSA@ arrived in
-- 3.2).
slhdsaBaselines :: MechanismName -> [Pkcs11Version]
slhdsaBaselines _ = [Pkcs11_3_2]

-- | The SLH-DSA behavior group, derived from the recipe table:
-- one descriptor per recipe row, codec from 'slhdsaCodecFor',
-- sign and verify routes citing synthetic A37 and real-KAT A39 (no
-- A16: the backends offer one-shot sign only). Key bounds are the
-- served public-key range 32..64 bytes (FIPS 205 widths for
-- SLH-DSA-SHA2/SHAKE-128..256, the OASIS mechanism-info unit).
slhdsaDescs :: [Descriptor]
slhdsaDescs =
  [ promotedDesc (rslName r) (slhdsaBaselines (rslName r)) FamilyPqc
      (slhdsaCodecFor r)
      [ mechRoute OpSign (rslName r) ["A37", "A39"]
      , mechRoute OpVerify (rslName r) ["A37", "A39"]
      ]
      KeyBytes 32 64
  | r <- slhdsaRecipes
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

-- | The 3DES-MAC behavior group, derived from the recipe table:
-- one descriptor per recipe row, codec from 'des3macCodecFor',
-- sign and verify routes citing synthetic A37 and real-KAT A39 (no
-- A16: the driver offers one-shot MAC only).
des3macDescs :: [Descriptor]
des3macDescs =
  [ promotedDesc (rdmName r) allBaselines FamilyMac
      (des3macCodecFor r)
      [ mechRoute OpSign (rdmName r) ["A37", "A39"]
      , mechRoute OpVerify (rdmName r) ["A37", "A39"]
      ]
      MechanismSpecific 0 0
  | r <- des3macRecipes
  ]

-- | The CBC-MAC behavior group, derived from the recipe table:
-- one descriptor per recipe row, codec from 'cbcmacCodecFor',
-- sign and verify routes citing synthetic A37 and real-KAT A39 (no
-- A16: the driver offers one-shot MAC only).
cbcmacDescs :: [Descriptor]
cbcmacDescs =
  [ promotedDesc (cbmName r) allBaselines FamilyMac
      (cbcmacCodecFor r)
      [ mechRoute OpSign (cbmName r) ["A37", "A39"]
      , mechRoute OpVerify (cbmName r) ["A37", "A39"]
      ]
      MechanismSpecific 0 0
  | r <- cbcmacRecipes
  ]

-- | The XCBC-MAC behavior group, derived from the recipe table:
-- one descriptor per recipe row, codec from 'xcbcCodecFor',
-- sign and verify routes citing synthetic A37 and real-KAT A39 (no
-- A16: the driver offers one-shot MAC only).
xcbcDescs :: [Descriptor]
xcbcDescs =
  [ promotedDesc (xcbName r) allBaselines FamilyMac
      (xcbcCodecFor r)
      [ mechRoute OpSign (xcbName r) ["A37", "A39"]
      , mechRoute OpVerify (xcbName r) ["A37", "A39"]
      ]
      MechanismSpecific 0 0
  | r <- xcbcRecipes
  ]

-- | The GMAC behavior group, derived from the recipe table:
-- one descriptor per recipe row, codec from 'gmacCodecFor',
-- sign and verify routes citing synthetic A37 and real-KAT A39 (no
-- A16: the driver offers one-shot MAC only).
gmacDescs :: [Descriptor]
gmacDescs =
  [ promotedDesc (gmName r) allBaselines FamilyMac
      (gmacCodecFor r)
      [ mechRoute OpSign (gmName r) ["A37", "A39"]
      , mechRoute OpVerify (gmName r) ["A37", "A39"]
      ]
      MechanismSpecific 0 0
  | r <- gmacRecipes
  ]

-- | The KDF behavior group, derived from the recipe table:
-- one descriptor per recipe row, codec from 'kdfCodecFor',
-- the derive route citing the planner case (A20), the synthetic
-- construction (A37), and the real vectors (A39). PBKD2 carries
-- a second, generate-key route over the same frame (the
-- password rides inline instead of the base key). The SHA rows
-- predate 2.40; the BLAKE2B and SHAKE rows arrived in 3.0. Key
-- bounds are mechanism-specific (widths follow the digest or the
-- planned length).
kdfBaselines :: MechanismName -> [Pkcs11Version]
kdfBaselines name
  | "CKM_BLAKE2B_" `T.isPrefixOf` name = [Pkcs11_3_0, Pkcs11_3_1, Pkcs11_3_2]
  | "CKM_SHAKE_" `T.isPrefixOf` name = [Pkcs11_3_0, Pkcs11_3_1, Pkcs11_3_2]
  | otherwise = allBaselines

kdfDescs :: [Descriptor]
kdfDescs =
  [ promotedDesc (rkName r) (kdfBaselines (rkName r)) FamilyDerive
      (kdfCodecFor r)
      (mechRoute OpDerive (rkName r) ["A20", "A37", "A39"]
        : [ mechRoute OpGenerateKey (rkName r) ["A20", "A37", "A39"]
          | rkPbkd2 r
          ])
      MechanismSpecific 0 0
  | r <- kdfRecipes
  ]

-- | The TLS-PRF behavior group, derived from the recipe table:
-- one descriptor per recipe row, codec from 'tlsPrfCodecFor',
-- the derive route citing the planner case (A20), the synthetic
-- construction (A37), and the real vectors (A39). The single row
-- predates 2.40; key bounds are mechanism-specific (the planned
-- length, capped by the TLS-PRF ceiling).
tlsPrfDescs :: [Descriptor]
tlsPrfDescs =
  [ promotedDesc (rtName r) allBaselines FamilyDerive
      (tlsPrfCodecFor r)
      [ mechRoute OpDerive (rtName r) ["A20", "A37", "A39"]
      ]
      MechanismSpecific 0 0
  | r <- tlsPrfRecipes
  ]

-- | The SP 800-108 behavior group, derived from the recipe table:
-- one descriptor per recipe row, codec from 'sp800CodecFor',
-- the derive route citing the planner case (A20), the synthetic
-- construction (A37), and the real vectors (A39). The three rows
-- arrived in v3.0; key bounds are mechanism-specific (the planned
-- length, capped by the SP 800-108 ceiling with the L-fit
-- check).
sp800Descs :: [Descriptor]
sp800Descs =
  [ promotedDesc (rsName r) [Pkcs11_3_0, Pkcs11_3_1, Pkcs11_3_2] FamilyDerive
      (sp800CodecFor r)
      [ mechRoute OpDerive (rsName r) ["A20", "A37", "A39"]
      ]
      MechanismSpecific 0 0
  | r <- sp800Recipes
  ]

-- | Baseline span for a TLS-KDF recipe name: the TLS 1.0 and
-- 1.2 master rows (0x375\/0x377\/0x3d9\/0x3e0\/0x3e2) are 2.40
-- (the 1.0 rows older still); the extended-master rows
-- (0x56\/0x57, RFC 7627 postdates v2.40) and the generic
-- @CKM_TLS_KDF@ row (0x3e5, the TLS-1.3-era free row) arrived
-- in 3.0.
tlsKdfBaselines :: MechanismName -> [Pkcs11Version]
tlsKdfBaselines name
  | name == "CKM_TLS_KDF" = [Pkcs11_3_0, Pkcs11_3_1, Pkcs11_3_2]
  | "CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE" `T.isPrefixOf` name = [Pkcs11_3_0, Pkcs11_3_1, Pkcs11_3_2]
  | otherwise = allBaselines

-- | The TLS-KDF behavior group, derived from the recipe table:
-- one descriptor per recipe row, codec from 'tlsKdfCodecFor',
-- the derive route citing the planner case (A20), the synthetic
-- construction (A37), and the real vectors (A39). Key bounds
-- are mechanism-specific (the planned length, capped by the
-- TLS-KDF ceiling).
tlsKdfDescs :: [Descriptor]
tlsKdfDescs =
  [ promotedDesc (tkName r) (tlsKdfBaselines (tkName r)) FamilyDerive
      (tlsKdfCodecFor r)
      [ mechRoute OpDerive (tkName r) ["A20", "A37", "A39"]
      ]
      MechanismSpecific 0 0
  | r <- tlsKdfRecipes
  ]

-- | The IKE behavior group, derived from the recipe table: one
-- descriptor per recipe row, codec from 'ikeCodecFor', the
-- derive route citing the planner case (A20), the synthetic
-- construction (A37), and the real vectors (A39). The four rows
-- arrived in v3.0; key bounds are mechanism-specific (the
-- planned length, capped by the per-kind ceiling).
ikeDescs :: [Descriptor]
ikeDescs =
  [ promotedDesc (ikName r) [Pkcs11_3_0, Pkcs11_3_1, Pkcs11_3_2] FamilyDerive
      (ikeCodecFor r)
      [ mechRoute OpDerive (ikName r) ["A20", "A37", "A39"]
      ]
      MechanismSpecific 0 0
  | r <- ikeRecipes
  ]

-- | The byte-op behavior group, derived from the recipe table:
-- one descriptor per recipe row, codec from 'byteOpsCodecFor',
-- the derive route citing the planner case (A20), the
-- synthetic separation (A37), and the real vectors (A39).
-- The five rows are v2-era; key bounds are
-- mechanism-specific (the planned length, capped by the
-- natural width).
byteOpsDescs :: [Descriptor]
byteOpsDescs =
  [ promotedDesc (boName r) allBaselines FamilyDerive
      (byteOpsCodecFor r)
      [ mechRoute OpDerive (boName r) ["A20", "A37", "A39"]
      ]
      MechanismSpecific 0 0
  | r <- byteOpsRecipes
  ]

-- | Baselines for the key-material rows: the TLS 1.0 row is
-- v2-era; the TLS 1.2 rows arrived in v3.0.
tlsKeyMatBaselines :: MechanismName -> [Pkcs11Version]
tlsKeyMatBaselines name
  | name == "CKM_TLS_KEY_AND_MAC_DERIVE" = allBaselines
  | otherwise = [Pkcs11_3_0, Pkcs11_3_1, Pkcs11_3_2]

-- | The key-material behavior group, derived from the recipe
-- table: one descriptor per recipe row, codec from
-- 'tlsKeyMatCodecFor', the derive route citing the planner
-- case (A20), the synthetic separation (A37), and the real
-- vectors (A39). Key bounds are mechanism-specific (the
-- planned block, split per params).
tlsKeyMatDescs :: [Descriptor]
tlsKeyMatDescs =
  [ promotedDesc (tkmName r) (tlsKeyMatBaselines (tkmName r)) FamilyDerive
      (tlsKeyMatCodecFor r)
      [ mechRoute OpDerive (tkmName r) ["A20", "A37", "A39"]
      ]
      MechanismSpecific 0 0
  | r <- tlsKeyMatRecipes
  ]

-- | The PBE behavior group, derived from the recipe table: one
-- descriptor per recipe row, codec from 'pbeCodecFor', the
-- generate-key route citing the planner case (A20), the
-- synthetic construction (A37), and the real vectors (A39).
-- Both rows predate 2.40; key bounds are the fixed widths in
-- bits (DES2: 128, DES3: 192).
pbeDescs :: [Descriptor]
pbeDescs =
  [ promotedDesc (pbeName r) allBaselines FamilyKeyGen
      (pbeCodecFor r)
      [ mechRoute OpGenerateKey (pbeName r) ["A20", "A37", "A39"]
      ]
      KeyBits (fromIntegral bits) (fromIntegral bits)
  | r <- pbeRecipes
  , let bits = 8 * pbeKeyLen (pbeKind r)
  ]

-- | The SSL3 behavior group, derived from the recipe table:
-- one descriptor per recipe row, codec from 'ssl3CodecFor'.
-- The three derive rows cite the planner case (A20), the
-- synthetic construction (A37), and the real vectors (A39);
-- the two MAC rows cite sign and verify routes (A37, A39 —
-- no A16: one-shot MAC only). All five rows predate 2.40;
-- key bounds are mechanism-specific.
ssl3Descs :: [Descriptor]
ssl3Descs =
  [ promotedDesc (ssl3Name r) allBaselines (ssl3Family r)
      (ssl3CodecFor r)
      (ssl3Routes r)
      MechanismSpecific 0 0
  | r <- ssl3Recipes
  ]
  where
    ssl3Family r = case ssl3Kind r of
      Ssl3Md5Mac -> FamilyMac
      Ssl3Sha1Mac -> FamilyMac
      _ -> FamilyDerive
    ssl3Routes r = case ssl3Kind r of
      Ssl3Md5Mac -> macRoutes (ssl3Name r)
      Ssl3Sha1Mac -> macRoutes (ssl3Name r)
      _ -> [mechRoute OpDerive (ssl3Name r) ["A20", "A37", "A39"]]
    macRoutes name =
      [ mechRoute OpSign name ["A37", "A39"]
      , mechRoute OpVerify name ["A37", "A39"]
      ]

-- | The RSA-X9.31 behavior group, derived from the recipe table:
-- one descriptor per recipe row, codec from 'rsaX931CodecFor',
-- sign and verify routes citing synthetic A37 and real-KAT A39 (no
-- A16: the backends offer one-shot sign only). Both rows predate
-- 2.40; key bounds are the de-facto vendor range 512..4096 bits.
rsaX931Descs :: [Descriptor]
rsaX931Descs =
  [ promotedDesc (rx931Name r) allBaselines FamilyRsa
      (rsaX931CodecFor r)
      [ mechRoute OpSign (rx931Name r) ["A37", "A39"]
      , mechRoute OpVerify (rx931Name r) ["A37", "A39"]
      ]
      KeyBits 512 4096
  | r <- rsaX931Recipes
  ]

-- | The Poly1305 behavior descriptor, derived from the recipe
-- table: sign and verify routes citing synthetic A37 and real-KAT
-- A39 (no A16: one-shot MAC only). The row arrived in 3.0; key
-- bounds are mechanism-specific (the 32-byte one-time key).
poly1305Descs :: [Descriptor]
poly1305Descs =
  [ promotedDesc (polyName r) [Pkcs11_3_0, Pkcs11_3_1, Pkcs11_3_2] FamilyMac
      (poly1305CodecFor r)
      [ mechRoute OpSign (polyName r) ["A37", "A39"]
      , mechRoute OpVerify (polyName r) ["A37", "A39"]
      ]
      MechanismSpecific 0 0
  | r <- poly1305Recipes
  ]

-- | The encrypt-data behavior group, derived from the recipe table:
-- one descriptor per recipe row, codec from
-- 'encryptDataCodecFor', the derive route citing the planner case
-- (A20), the synthetic construction (A37), and the real vectors
-- (A39). All eight rows predate 2.40; key bounds are
-- mechanism-specific (widths follow the planned length, capped by
-- the encrypted data width).
encryptDataDescs :: [Descriptor]
encryptDataDescs =
  [ promotedDesc (erName r) allBaselines FamilyDerive
      (encryptDataCodecFor r)
      [ mechRoute OpDerive (erName r) ["A20", "A37", "A39"]
      ]
      MechanismSpecific 0 0
  | r <- encryptDataRecipes
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

dhDescs :: [Descriptor]
dhDescs =
  [ promotedDesc (dhName r) allBaselines FamilyDerive
      (dhCodecFor r)
      [ mechRoute OpDerive (dhName r) ["A20", "A37", "A39"]
      ]
      MechanismSpecific 0 0
  | r <- dhRecipes
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

-- | @CKM_DES3_KEY_GEN@: mechanism parameters are NULL;
-- the length arrives via the @CKA_VALUE_LEN@ template attribute
-- (16/24 bytes, two-key/three-key), not via pParameter.
dDES3KeyGen :: Descriptor
dDES3KeyGen = promotedDesc "CKM_DES3_KEY_GEN" allBaselines FamilyKeyGen
  noParams [synthRoute OpGenerateKey "CKM_DES3_KEY_GEN"]
  KeyBits 128 192

-- | @CKM_BLAKE2B_512_KEY_GEN@: mechanism parameters are NULL;
-- the length arrives via the @CKA_VALUE_LEN@ template attribute
-- (1-255 bytes: HMAC keygens take a VALUE_LEN-sized key per the
-- standard, not the digest width). Arrived in 3.0.
dBlake2b512KeyGen :: Descriptor
dBlake2b512KeyGen = promotedDesc "CKM_BLAKE2B_512_KEY_GEN"
  [Pkcs11_3_0, Pkcs11_3_1, Pkcs11_3_2] FamilyKeyGen
  noParams [synthRoute OpGenerateKey "CKM_BLAKE2B_512_KEY_GEN"]
  KeyBits 8 2040

-- | @CKM_CHACHA20_KEY_GEN@: mechanism parameters are NULL; the
-- length arrives via the @CKA_VALUE_LEN@ template attribute
-- (exactly 32 bytes / 256 bits). Arrived in 3.0.
dChacha20KeyGen :: Descriptor
dChacha20KeyGen = promotedDesc "CKM_CHACHA20_KEY_GEN"
  [Pkcs11_3_0, Pkcs11_3_1, Pkcs11_3_2] FamilyKeyGen
  noParams [synthRoute OpGenerateKey "CKM_CHACHA20_KEY_GEN"]
  KeyBits 256 256

-- | @CKM_GENERIC_SECRET_KEY_GEN@: mechanism parameters are NULL;
-- the length arrives via the @CKA_VALUE_LEN@ template attribute
-- (1-255 bytes: the floor refuses empty secrets, the ceiling is
-- the one-byte 'GenBytes' planner-driver frame).
dGenericSecretKeyGen :: Descriptor
dGenericSecretKeyGen = promotedDesc "CKM_GENERIC_SECRET_KEY_GEN" allBaselines FamilyKeyGen
  noParams [synthRoute OpGenerateKey "CKM_GENERIC_SECRET_KEY_GEN"]
  KeyBits 8 2040

-- | The keygen sweep (slice 11a): one descriptor per reviewed
-- fixed, discrete and ranged symmetric keygen. Mechanism
-- parameters are NULL throughout; the length arrives via
-- @CKA_VALUE_LEN@ (fixed sizes default when absent). Bounds are
-- bits, mirroring the planner table.
keygenSweepDescs :: [Descriptor]
keygenSweepDescs = map mkSweep keygenSweepRows
  where
    mkSweep (name, baseline, lo, hi) = promotedDesc name baseline FamilyKeyGen
      noParams [synthRoute OpGenerateKey name]
      KeyBits lo hi
    v3 = [Pkcs11_3_0, Pkcs11_3_1, Pkcs11_3_2]
    keygenSweepRows =
      [ ("CKM_DES_KEY_GEN", allBaselines, 64, 64)
      , ("CKM_DES2_KEY_GEN", allBaselines, 128, 128)
      , ("CKM_CDMF_KEY_GEN", allBaselines, 64, 64)
      , ("CKM_IDEA_KEY_GEN", allBaselines, 128, 128)
      , ("CKM_SEED_KEY_GEN", allBaselines, 128, 128)
      , ("CKM_SKIPJACK_KEY_GEN", allBaselines, 96, 96)
      , ("CKM_BATON_KEY_GEN", allBaselines, 320, 320)
      , ("CKM_JUNIPER_KEY_GEN", allBaselines, 320, 320)
      , ("CKM_GOST28147_KEY_GEN", allBaselines, 256, 256)
      , ("CKM_SALSA20_KEY_GEN", v3, 256, 256)
      , ("CKM_POLY1305_KEY_GEN", v3, 256, 256)
      , ("CKM_ARIA_KEY_GEN", allBaselines, 128, 256)
      , ("CKM_CAMELLIA_KEY_GEN", allBaselines, 128, 256)
      , ("CKM_TWOFISH_KEY_GEN", allBaselines, 128, 256)
      , ("CKM_AES_XTS_KEY_GEN", allBaselines, 256, 512)
      , ("CKM_CAST_KEY_GEN", allBaselines, 8, 64)
      , ("CKM_CAST3_KEY_GEN", allBaselines, 8, 64)
      , ("CKM_CAST128_KEY_GEN", allBaselines, 8, 128)
      , ("CKM_RC2_KEY_GEN", allBaselines, 8, 1024)
      , ("CKM_RC4_KEY_GEN", allBaselines, 8, 2040)
      , ("CKM_RC5_KEY_GEN", allBaselines, 8, 2040)
      , ("CKM_BLOWFISH_KEY_GEN", allBaselines, 32, 448)
      , ("CKM_HKDF_KEY_GEN", v3, 8, 2040)
      , ("CKM_SHA_1_KEY_GEN", v3, 8, 2040)
      , ("CKM_SHA224_KEY_GEN", v3, 8, 2040)
      , ("CKM_SHA256_KEY_GEN", v3, 8, 2040)
      , ("CKM_SHA384_KEY_GEN", v3, 8, 2040)
      , ("CKM_SHA512_KEY_GEN", v3, 8, 2040)
      , ("CKM_SHA512_224_KEY_GEN", v3, 8, 2040)
      , ("CKM_SHA512_256_KEY_GEN", v3, 8, 2040)
      , ("CKM_SHA512_T_KEY_GEN", v3, 8, 2040)
      , ("CKM_SHA3_224_KEY_GEN", v3, 8, 2040)
      , ("CKM_SHA3_256_KEY_GEN", v3, 8, 2040)
      , ("CKM_SHA3_384_KEY_GEN", v3, 8, 2040)
      , ("CKM_SHA3_512_KEY_GEN", v3, 8, 2040)
      , ("CKM_BLAKE2B_160_KEY_GEN", v3, 8, 2040)
      , ("CKM_BLAKE2B_256_KEY_GEN", v3, 8, 2040)
      , ("CKM_BLAKE2B_384_KEY_GEN", v3, 8, 2040)
      ]

-- | The pre-master keygens (slice 11a, phase 2): unlike the
-- sweep, these take mechanism parameters (the client version:
-- @CK_VERSION@ for TLS/SSL3, one @CK_BYTE@ for WTLS), and the
-- version bytes lead the generic secret.
premasterDescs :: [Descriptor]
premasterDescs =
  [ (promotedDesc "CKM_TLS_PRE_MASTER_KEY_GEN" allBaselines FamilyKeyGen
      (ParameterCodec "ck-version" 1) [synthRoute OpGenerateKey "CKM_TLS_PRE_MASTER_KEY_GEN"]
      KeyBits 384 384)
  , (promotedDesc "CKM_SSL3_PRE_MASTER_KEY_GEN" allBaselines FamilyKeyGen
      (ParameterCodec "ck-version" 1) [synthRoute OpGenerateKey "CKM_SSL3_PRE_MASTER_KEY_GEN"]
      KeyBits 384 384)
  , (promotedDesc "CKM_WTLS_PRE_MASTER_KEY_GEN" allBaselines FamilyKeyGen
      (ParameterCodec "ck-byte" 1) [synthRoute OpGenerateKey "CKM_WTLS_PRE_MASTER_KEY_GEN"]
      KeyBits 160 2040)
  ]

-- | The block-cipher behavior group, derived from the recipe table:
-- one descriptor per recipe row, codec from
-- 'cipherCodecFor', encrypt and decrypt routes citing the verified
-- multipart (A16), synthetic (A37), and real-KAT (A39) cases. This
-- replaces the hand-written AES-CBC descriptor (same id,
-- completed routes). AES-CBC keeps its tested
-- wrap/unwrap/authenticated routes (same 16-byte-IV parameter
-- shape); key bounds follow the recipe's key set (DES3 16..24,
-- the AES/ARIA/Camellia families 16..32).
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
      -- The AES key-wrap rows serve the object path (plain
      -- wrap/unwrap only: the authenticated construction is
      -- CBC-specific) alongside raw encrypt/decrypt.
      | name `elem` wrapNames =
          [ mechRoute OpWrap name ["A20", "A37", "A39"]
          , mechRoute OpUnwrap name ["A20", "A37", "A39"]
          ]
      | otherwise = []
    wrapNames =
      [ "CKM_AES_KEY_WRAP"
      , "CKM_AES_KEY_WRAP_PAD"
      , "CKM_AES_KEY_WRAP_KWP"
      , "CKM_AES_KEY_WRAP_PKCS7"
      ]

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

dECExtraBitsKeyPairGen :: Descriptor
dECExtraBitsKeyPairGen = promotedDesc "CKM_EC_KEY_PAIR_GEN_W_EXTRA_BITS"
  [Pkcs11_3_0, Pkcs11_3_1, Pkcs11_3_2] FamilyKeyPair
  noParams [mechRoute OpGenerateKeyPair "CKM_EC_KEY_PAIR_GEN_W_EXTRA_BITS" ["A20", "A37"]]
  KeyBits 0 0

dRsaPkcsKeyPairGen :: Descriptor
dRsaPkcsKeyPairGen = promotedDesc "CKM_RSA_PKCS_KEY_PAIR_GEN" allBaselines FamilyKeyPair
  noParams [mechRoute OpGenerateKeyPair "CKM_RSA_PKCS_KEY_PAIR_GEN" ["A20", "A37"]]
  KeyBits 0 0

dMlKemKeyPairGen :: Descriptor
dMlKemKeyPairGen = promotedDesc "CKM_ML_KEM_KEY_PAIR_GEN" [Pkcs11_3_2] FamilyKeyPair
  noParams [mechRoute OpGenerateKeyPair "CKM_ML_KEM_KEY_PAIR_GEN" ["A20", "A37"]]
  KeyBytes 800 1568

dDsaKeyPairGen :: Descriptor
dDsaKeyPairGen = promotedDesc "CKM_DSA_KEY_PAIR_GEN" allBaselines FamilyKeyPair
  noParams [mechRoute OpGenerateKeyPair "CKM_DSA_KEY_PAIR_GEN" ["A20", "A37"]]
  KeyBits 1024 3072

dDhKeyPairGen :: Descriptor
dDhKeyPairGen = promotedDesc "CKM_DH_PKCS_KEY_PAIR_GEN" allBaselines FamilyKeyPair
  noParams [mechRoute OpGenerateKeyPair "CKM_DH_PKCS_KEY_PAIR_GEN" ["A20", "A37"]]
  KeyBits 1024 4096

dX9_42DhKeyPairGen :: Descriptor
dX9_42DhKeyPairGen = promotedDesc "CKM_X9_42_DH_KEY_PAIR_GEN" allBaselines FamilyKeyPair
  noParams [mechRoute OpGenerateKeyPair "CKM_X9_42_DH_KEY_PAIR_GEN" ["A20", "A37"]]
  KeyBits 1024 4096

dEdwardsKeyPairGen :: Descriptor
dEdwardsKeyPairGen = promotedDesc "CKM_EC_EDWARDS_KEY_PAIR_GEN" [Pkcs11_3_0, Pkcs11_3_1, Pkcs11_3_2] FamilyKeyPair
  noParams [mechRoute OpGenerateKeyPair "CKM_EC_EDWARDS_KEY_PAIR_GEN" ["A20", "A37"]]
  KeyBits 256 456

dMontgomeryKeyPairGen :: Descriptor
dMontgomeryKeyPairGen = promotedDesc "CKM_EC_MONTGOMERY_KEY_PAIR_GEN" [Pkcs11_3_0, Pkcs11_3_1, Pkcs11_3_2] FamilyKeyPair
  noParams [mechRoute OpGenerateKeyPair "CKM_EC_MONTGOMERY_KEY_PAIR_GEN" ["A20", "A37"]]
  KeyBits 256 448

dMlDsaKeyPairGen :: Descriptor
dMlDsaKeyPairGen = promotedDesc "CKM_ML_DSA_KEY_PAIR_GEN" [Pkcs11_3_2] FamilyKeyPair
  noParams [mechRoute OpGenerateKeyPair "CKM_ML_DSA_KEY_PAIR_GEN" ["A20", "A37"]]
  KeyBytes 1312 2592

dSlhDsaKeyPairGen :: Descriptor
dSlhDsaKeyPairGen = promotedDesc "CKM_SLH_DSA_KEY_PAIR_GEN" [Pkcs11_3_2] FamilyKeyPair
  noParams [mechRoute OpGenerateKeyPair "CKM_SLH_DSA_KEY_PAIR_GEN" ["A20", "A37"]]
  KeyBytes 32 64

dDsaParameterGen :: Descriptor
dDsaParameterGen = promotedDesc "CKM_DSA_PARAMETER_GEN" allBaselines FamilyKeyGen
  noParams [synthRoute OpGenerateKey "CKM_DSA_PARAMETER_GEN"]
  KeyBits 1024 3072

dX9_42DhParameterGen :: Descriptor
dX9_42DhParameterGen = promotedDesc "CKM_X9_42_DH_PARAMETER_GEN" allBaselines FamilyKeyGen
  noParams [synthRoute OpGenerateKey "CKM_X9_42_DH_PARAMETER_GEN"]
  KeyBits 1024 3072

dDhPkcsParameterGen :: Descriptor
dDhPkcsParameterGen = promotedDesc "CKM_DH_PKCS_PARAMETER_GEN" allBaselines FamilyKeyGen
  noParams [synthRoute OpGenerateKey "CKM_DH_PKCS_PARAMETER_GEN"]
  KeyBits 1024 3072

dHkdfDerive :: Descriptor
dHkdfDerive = promotedDesc "CKM_HKDF_DERIVE"
  [Pkcs11_3_0, Pkcs11_3_1, Pkcs11_3_2] FamilyDerive
  (ParameterCodec "hkdf-params" 3)
  [mechRoute OpDerive "CKM_HKDF_DERIVE" ["A20", "A37", "A39"]]
  MechanismSpecific 0 0

dHkdfData :: Descriptor
dHkdfData = promotedDesc "CKM_HKDF_DATA"
  [Pkcs11_3_0, Pkcs11_3_1, Pkcs11_3_2] FamilyDerive
  (ParameterCodec "hkdf-params" 3)
  [mechRoute OpDerive "CKM_HKDF_DATA" ["A20", "A37", "A39"]]
  MechanismSpecific 0 0

dMlKem :: Descriptor
dMlKem = promotedDesc "CKM_ML_KEM" [Pkcs11_3_2] FamilyKem
  noParams
  [ mechRoute OpEncapsulate "CKM_ML_KEM" ["A22", "A37"]
  , mechRoute OpDecapsulate "CKM_ML_KEM" ["A22", "A37"]
  ]
  KeyBytes 800 1568

-- | AEAD behavior descriptors: one per GCM/CCM recipe row, with
-- the recipe codec, encrypt/decrypt routes, and AES key bounds
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
  ++
  [ promotedDesc (ccmName r) allBaselines FamilyAead
      (ccmCodecFor r)
      [ mechRoute OpEncrypt (ccmName r) ["A16", "A37", "A39"]
      , mechRoute OpDecrypt (ccmName r) ["A16", "A37", "A39"]
      ]
      KeyBytes 16 32
  | r <- ccmRecipes
  ]
  ++
  [ promotedDesc (chachaName r) [Pkcs11_3_0, Pkcs11_3_1, Pkcs11_3_2] FamilyAead
      (chachaCodecFor r)
      [ mechRoute OpEncrypt (chachaName r) ["A16", "A37", "A39"]
      , mechRoute OpDecrypt (chachaName r) ["A16", "A37", "A39"]
      ]
      KeyBytes 32 32
  | r <- chachaRecipes, chachaName r == "CKM_CHACHA20_POLY1305"
  ]

-- | The raw ChaCha20 stream row (256-bit keys only).
chachaStreamDescs :: [Descriptor]
chachaStreamDescs =
  [ promotedDesc (chachaName r) [Pkcs11_3_0, Pkcs11_3_1, Pkcs11_3_2] FamilyCipher
      (chachaCodecFor r)
      [ mechRoute OpEncrypt (chachaName r) ["A16", "A37", "A39"]
      , mechRoute OpDecrypt (chachaName r) ["A16", "A37", "A39"]
      ]
      KeyBytes 32 32
  | r <- chachaRecipes, chachaName r == "CKM_CHACHA20"
  ]

-- | The curated population: 295 reviewed behavior descriptors
-- with concrete rules, plus the full header inventory (464
-- canonical rows covering all 480 header CKM names) folded in from
-- the generated table. Catalog-only rows (169: everything but the
-- 295 behavior ids) stay in the coverage denominator but never
-- become executable. The catalog covers the full inventory.
curatedRegistry :: Registry
curatedRegistry =
  case build of
    Right r -> r
    Left err -> error ("curatedRegistry: " ++ show err)
  where
    behaviorDescs :: [Descriptor]
    behaviorDescs =
      ( [ dSHA256, dAESKeyGen, dDES3KeyGen, dHotpKeyGen, dGenericSecretKeyGen, dBlake2b512KeyGen, dChacha20KeyGen
        , dECKeyPairGen, dECExtraBitsKeyPairGen, dRsaPkcsKeyPairGen, dMlKemKeyPairGen, dDsaKeyPairGen, dDsaParameterGen, dDhKeyPairGen, dDhPkcsParameterGen, dX9_42DhKeyPairGen, dX9_42DhParameterGen, dEdwardsKeyPairGen, dMontgomeryKeyPairGen, dMlDsaKeyPairGen, dSlhDsaKeyPairGen, dHkdfDerive, dHkdfData, dMlKem
        , dSHA224, dSHA384, dSHA512, dSHA512_224, dSHA512_256
        , dSHA3_224, dSHA3_256, dSHA3_384, dSHA3_512
        , dSHA1, dMD5, dRIPEMD160, dBLAKE2B_512
        , dBLAKE2B_160, dBLAKE2B_256, dBLAKE2B_384
        ] ++ hmacDescs ++ cipherDescs ++ aeadDescs ++ chachaStreamDescs ++ keygenSweepDescs ++ premasterDescs ++ rsaPkcs1Descs
          ++ rsaPssDescs ++ rsaOaepDescs ++ rsaX509Descs ++ ecdsaDescs ++ dsaDescs ++ eddsaDescs ++ mldsaDescs ++ slhdsaDescs ++ ecdhDescs ++ dhDescs
          ++ cmacDescs ++ des3macDescs ++ cbcmacDescs ++ xcbcDescs ++ gmacDescs ++ kdfDescs ++ tlsPrfDescs ++ sp800Descs ++ tlsKdfDescs ++ ikeDescs ++ byteOpsDescs ++ tlsKeyMatDescs ++ pbeDescs ++ ssl3Descs ++ otpDescs ++ encryptDataDescs ++ rsaX931Descs ++ poly1305Descs
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
