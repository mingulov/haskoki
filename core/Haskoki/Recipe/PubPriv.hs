{- | Pub-from-priv recipe: the single-row shape-group recipe.

One header mechanism — @CKM_PUB_KEY_FROM_PRIV_KEY@ (0x403A) —
derives a public key object from a private base key over
C_DeriveKey with no parameters (@no-params\/1@), ignoring
CKA_DERIVE (the only derive row allowed to). Served base
types: RSA, EC Weierstrass (only when the private half embeds
its public point — scalar-only imports refuse, since y-recovery
is Fp math), EC Montgomery (agreement against the base point),
EC Edwards. DSA\/DH refuse (no provider path); ML-DSA\/SLH-DSA\/
ML-KEM refuse (the provider keymgmt has no priv-import path at
all — fromdata rc=-2 in 4.0.2).

This module owns the row table, the codec, the base type gate,
and the attribute map. The map covers modeled attributes only:
CKA_LOCAL, CKA_TRUSTED, the dates, CKA_GEN_MECHANISM and
CKA_WRAP_TEMPLATE have no 'AttributeType' here, so reflections
(ENCRYPT<-DECRYPT, VERIFY<-SIGN, VERIFY_RECOVER<-SIGN_RECOVER,
WRAP<-UNWRAP, ENCAPSULATE<-DECAPSULATE), copies (DERIVE\/ID\/
SUBJECT\/PUBLIC_KEY_INFO\/ALLOWED_MECHANISMS), forced-false
(TOKEN\/PRIVATE), forced-true (MODIFIABLE\/COPYABLE\/DESTROYABLE)
and forced-empty (LABEL) are the whole table. Missing base
booleans stay missing (reads default false); the caller
template wins over map defaults at the planner. Pure core only.

Consumers:

* 'Haskoki.Registry' builds the row's behavior descriptor from
  'pubPrivCodecFor' (never a re-typed codec literal);
* 'Haskoki.Operation.Derive.planDerive' accepts the frame via
  'pubPrivRecipeFor' + 'pubPrivParamsValid', gates the base via
  'pubPrivBaseKeyOk', and defaults the pending object through
  'pubPrivMapAttrs';
* the driver routes the effect to the pub-extract entry;
  RecipePubPrivSpec pins this table.
-}
{-# LANGUAGE OverloadedStrings #-}
module Haskoki.Recipe.PubPriv
  ( PubPrivRecipe (..)
  , pubPrivRecipes
  , pubPrivRecipeFor
  , pubPrivCodecFor
  , pubPrivParamsValid
  , pubPrivBaseKeyOk
  , pubPrivBaseMatOk
  , pubPrivMapAttrs
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map
import Data.Word (Word64)

import Haskoki.Attribute (AttributeType (..), AttributeValue (..))
import Haskoki.Attribute.Generated (mustKeyTypeId)
import Haskoki.Der (ecPkcs8HasPub, ecSec1HasPub)
import Haskoki.Registry.Generated (mustGeneratedId)
import Haskoki.Registry.Types (MechanismId (..), MechanismName, ParameterCodec (..))

-- | One pub-from-priv recipe: the mechanism name (single row).
data PubPrivRecipe = PubPrivRecipe
  { pprName :: !MechanismName
  } deriving (Eq, Show)

-- | The row takes no parameters.
pubPrivCodecFor :: PubPrivRecipe -> ParameterCodec
pubPrivCodecFor _ = ParameterCodec "no-params" 1

-- | The one covered mechanism.
pubPrivRecipes :: [PubPrivRecipe]
pubPrivRecipes =
  [ PubPrivRecipe "CKM_PUB_KEY_FROM_PRIV_KEY"
  ]

-- | Resolve a mechanism id to its recipe, if covered.
pubPrivRecipeFor :: MechanismId -> Maybe PubPrivRecipe
pubPrivRecipeFor mid =
  case [ r | r <- pubPrivRecipes
           , MechanismId (mustGeneratedId (pprName r)) == mid ] of
    (r : _) -> Just r
    [] -> Nothing

-- | Empty parameters only.
pubPrivParamsValid :: PubPrivRecipe -> ByteString -> Bool
pubPrivParamsValid _ params = BS.null params

-- | Served base key types: RSA, EC Weierstrass, EC Montgomery,
-- EC Edwards. Everything else (DSA\/DH\/PQC\/secret\/opaque)
-- refuses at the planner.
pubPrivBaseKeyOk :: Word64 -> Bool
pubPrivBaseKeyOk kty =
  kty == mustKeyTypeId "CKK_RSA"
    || kty == mustKeyTypeId "CKK_EC"
    || kty == mustKeyTypeId "CKK_EC_MONTGOMERY"
    || kty == mustKeyTypeId "CKK_EC_EDWARDS"

-- | Material gate over a type-admitted base: EC halves must embed
-- their public point (either stored framing — raw SEC1 from
-- keygen or PKCS#8 from imports — with @[1]@; scalar-only
-- halves refuse, since y-recovery is Fp math); every other
-- served family passes (shape is the backend's to enforce,
-- per the ECDH unscannable-sides precedent).
pubPrivBaseMatOk :: Word64 -> ByteString -> Bool
pubPrivBaseMatOk kty mat
  | kty == mustKeyTypeId "CKK_EC" = ecPkcs8HasPub mat || ecSec1HasPub mat
  | otherwise = True

-- | Reflection pairs (derived <- base).
reflections :: [(AttributeType, AttributeType)]
reflections =
  [ (AttrEncrypt, AttrDecrypt)
  , (AttrVerify, AttrSign)
  , (AttrVerifyRecover, AttrSignRecover)
  , (AttrWrap, AttrUnwrap)
  , (AttrEncapsulate, AttrDecapsulate)
  ]

-- | Copied attributes (same name both sides).
copies :: [AttributeType]
copies =
  [ AttrDerive
  , AttrId
  , AttrSubject
  , AttrPublicKeyInfo
  , AttrAllowedMechanisms
  ]

-- | The attribute map: reflections and copies follow the base
-- (missing stays missing), TOKEN\/PRIVATE force false,
-- MODIFIABLE\/COPYABLE\/DESTROYABLE force true, LABEL forces
-- empty. Unmodeled table cells (LOCAL, TRUSTED, dates,
-- GEN_MECHANISM, WRAP_TEMPLATE) are out of scope by
-- construction — see the module header.
pubPrivMapAttrs
  :: Map AttributeType AttributeValue
  -> Map AttributeType AttributeValue
pubPrivMapAttrs base =
  Map.fromList forced <> Map.fromList reflected <> Map.fromList copied
  where
    reflected =
      [ (dst, v)
      | (dst, src) <- reflections
      , Just v <- [Map.lookup src base]
      ]
    copied =
      [ (a, v)
      | a <- copies
      , Just v <- [Map.lookup a base]
      ]
    forced =
      [ (AttrToken, ValBool False)
      , (AttrPrivate, ValBool False)
      , (AttrModifiable, ValBool True)
      , (AttrCopyable, ValBool True)
      , (AttrDestroyable, ValBool True)
      , (AttrLabel, ValBytes "")
      ]
