{- | Init key-type matrix: reviewed mechanism\/operation key
compatibility.

'matrixKeyTypes' answers which @CKK_*@ key types may serve one
@(mechanism, operation)@ pair. 'Just' lists the permitted types;
'Nothing' means the pair is outside the reviewed matrix and keeps
the legacy behavior (usage-flags permission only). Rows derive
from the reviewed recipe tables, so a new recipe row is covered
automatically and a mechanism with no recipe row stays
unconstrained rather than silently misclassified.

Coverage (classic Init path only): HMAC sign\/verify wants
@CKK_GENERIC_SECRET@ or the row's per-digest @CKK_*_HMAC@ type
(digest-precise: a SHA-512 HMAC key does not serve SHA-256 HMAC);
RSA v1.5\/PSS sign\/verify and RSA-OAEP
encrypt\/decrypt want @CKK_RSA@; ECDSA sign\/verify wants @CKK_EC@;
block-cipher encrypt\/decrypt wants the recipe row's key type;
CMAC sign\/verify wants @CKK_AES@ (@CKK_DES3@ for the DES3 rows);
3DES-MAC sign\/verify wants @CKK_DES3@;
HOTP sign\/verify wants @CKK_HOTP@.
Derive, wrap\/unwrap, KEM, and message-family framing have their
own planners and gates and are not matrix rows; digest is unkeyed.
-}
{-# LANGUAGE OverloadedStrings #-}
module Haskoki.Registry.KeyMatrix
  ( matrixKeyTypes
  ) where

import Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map
import Data.Word (Word64)

import Haskoki.Attribute.Generated (mustKeyTypeId)
import Haskoki.Recipe.Ccm (CcmRecipe (..), ccmRecipes)
import Haskoki.Recipe.Chacha20 (Chacha20Recipe (..), chachaRecipes)
import Haskoki.Recipe.Cipher (BlockCipherRecipe (..), cipherRecipes)
import Haskoki.Recipe.Cmac (CmacRecipe (..), cmacRecipes)
import Haskoki.Recipe.Des3Mac (Des3MacRecipe (..), des3macRecipes)
import Haskoki.Recipe.Ecdsa (EcdsaRecipe (..), ecdsaRecipes)
import Haskoki.Recipe.Gcm (GcmRecipe (..), gcmRecipes)
import Haskoki.Recipe.Hmac (HmacRecipe (..), hmacRecipes)
import Haskoki.Recipe.Otp (OtpRecipe (..), hotpRecipes)
import Haskoki.Recipe.RsaOaep (RsaOaepRecipe (..), rsaOaepRecipes)
import Haskoki.Recipe.RsaPkcs1 (RsaPkcs1Recipe (..), rsaPkcs1Recipes)
import Haskoki.Recipe.RsaPss (RsaPssRecipe (..), rsaPssRecipes)
import Haskoki.Registry (Operation (..))
import Haskoki.Registry.Generated (mustGeneratedId)
import Haskoki.Registry.Types (MechanismId (..))

-- | Permitted @CKK_*@ key types for one @(mechanism, operation)@
-- pair, or 'Nothing' when the pair is outside the reviewed matrix.
matrixKeyTypes :: MechanismId -> Operation -> Maybe [Word64]
matrixKeyTypes mid op = Map.lookup (mid, op) matrixTable

-- | The reviewed table, derived from the recipe rows. One entry per
-- (recipe row, covered operation); pairs outside the table look up
-- to 'Nothing'.
matrixTable :: Map (MechanismId, Operation) [Word64]
matrixTable = Map.fromList (concat
  [ [ ((midOf (hrName r), o), [ckkGeneric, mustKeyTypeId (hrKeyType r)])
    | r <- hmacRecipes, o <- [OpSign, OpVerify] ]
  , [ ((midOf (rrName r), o), [ckkRsa]) | r <- rsaPkcs1Recipes, o <- [OpSign, OpVerify] ]
  , [ ((midOf (rpName r), o), [ckkRsa]) | r <- rsaPssRecipes, o <- [OpSign, OpVerify] ]
  , [ ((midOf (roName r), o), [ckkRsa]) | r <- rsaOaepRecipes, o <- [OpEncrypt, OpDecrypt] ]
  , [ ((midOf (reName r), o), [ckkEc]) | r <- ecdsaRecipes, o <- [OpSign, OpVerify] ]
  , [ ((midOf (crName r), o), [mustKeyTypeId (crKeyType r)])
    | r <- cipherRecipes, o <- [OpEncrypt, OpDecrypt] ]
  , [ ((midOf (gcmName r), o), [ckkAes])
    | r <- gcmRecipes, o <- [OpEncrypt, OpDecrypt] ]
  , [ ((midOf (ccmName r), o), [ckkAes])
    | r <- ccmRecipes, o <- [OpEncrypt, OpDecrypt] ]
  , [ ((midOf (chachaName r), o), [ckkChacha20])
    | r <- chachaRecipes, o <- [OpEncrypt, OpDecrypt] ]
  , [ ((midOf (rcName r), o), [if rcDes3 r then ckkDes3 else ckkAes])
    | r <- cmacRecipes, o <- [OpSign, OpVerify] ]
  , [ ((midOf (rdmName r), o), [ckkDes3])
    | r <- des3macRecipes, o <- [OpSign, OpVerify] ]
  , [ ((midOf (otpName r), o), [mustKeyTypeId (otpKeyType r)])
    | r <- hotpRecipes, o <- [OpSign, OpVerify] ]
  ])
  where
    midOf name = MechanismId (mustGeneratedId name)
    ckkGeneric = mustKeyTypeId "CKK_GENERIC_SECRET"
    ckkRsa = mustKeyTypeId "CKK_RSA"
    ckkEc = mustKeyTypeId "CKK_EC"
    ckkAes = mustKeyTypeId "CKK_AES"
    ckkDes3 = mustKeyTypeId "CKK_DES3"
    ckkChacha20 = mustKeyTypeId "CKK_CHACHA20"
