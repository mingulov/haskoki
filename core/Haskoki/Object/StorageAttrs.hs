{- | Object common storage-object attributes.
-}
{-# LANGUAGE OverloadedStrings #-}
module Haskoki.Object.StorageAttrs
  ( flagOr
  , isStorageObject
  , isKeyClass
  , isPublicKeyClass
  , keyDefaults
  , effectiveAttrs
  , objectToken
  , objectPrivate
  , mergedIsToken
  , tmplWantsToken
  , mergedIsPrivate
  , tmplWantsPrivate
  , valueLenConflict
  , objectCopyable
  , objectDestroyable
  , objectVisible
  , tokenDefault
  , privateDefault
  , modifiableDefault
  , copyableDefault
  , destroyableDefault
  , effectiveSensitive
  , effectiveExtractable
  ) where

import qualified Data.ByteString as BS
import Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map
import Data.Word (Word64)
import Haskoki.Attribute
  ( AttributeType (..)
  , AttributeValue (..)
  )
import Haskoki.Attribute.Generated
  ( mustClassId)
import Haskoki.Model
  ( ObjectState (..)
  , SessionState (..)
  )
import Haskoki.Session (SessionLogin (LoginContextUser, LoginUser))
import Haskoki.Object.PlanCerts

-- | The value the provider enforces for each common storage flag an
-- object's stored attributes lack: an absent TOKEN is a session
-- object, an absent PRIVATE is public, and an absent MODIFIABLE,
-- COPYABLE or DESTROYABLE prohibits nothing. This is the one source
-- for both sides: the enforcement predicates below read these
-- values through 'flagOr', and so does the read/find view
-- ('effectiveAttrs'), so a reported default cannot drift from the
-- enforced one.
tokenDefault, privateDefault, modifiableDefault, copyableDefault, destroyableDefault :: Bool
tokenDefault = False
privateDefault = False
modifiableDefault = True
copyableDefault = True
destroyableDefault = True

-- | The common storage flags paired with their enforced defaults.
storageFlagDefaults :: [(AttributeType, Bool)]
storageFlagDefaults =
  [ (AttrToken, tokenDefault)
  , (AttrPrivate, privateDefault)
  , (AttrModifiable, modifiableDefault)
  , (AttrCopyable, copyableDefault)
  , (AttrDestroyable, destroyableDefault)
  ]

-- | A flag's effective value: the stored boolean, else the given
-- enforced default (absent or wrongly shaped = default).
flagOr :: Bool -> AttributeType -> Map AttributeType AttributeValue -> Bool
flagOr dflt t m = case Map.lookup t m of
  Just (ValBool b) -> b
  _ -> dflt

-- | The same over a raw template list (first match wins; duplicates
-- are rejected downstream by template validation).
tmplFlagOr :: Bool -> AttributeType -> [(AttributeType, AttributeValue)] -> Bool
tmplFlagOr dflt t tmpl = case lookup t tmpl of
  Just (ValBool b) -> b
  _ -> dflt

-- | Classes outside the PKCS#11 storage-object hierarchy: hardware
-- feature, mechanism, profile and validation objects own none of the
-- common storage attributes.
nonStorageClasses :: [Word64]
nonStorageClasses =
  map mustClassId ["CKO_HW_FEATURE", "CKO_MECHANISM", "CKO_PROFILE", "CKO_VALIDATION"]

-- | Whether stored attributes describe a storage object: any class
-- the provider admits except 'nonStorageClasses' (data,
-- certificates, the key classes, domain parameters, trust and
-- vendor-defined objects). A map without a class is not one.
isStorageObject :: Map AttributeType AttributeValue -> Bool
isStorageObject attrs = case Map.lookup AttrClass attrs of
  Just (ValULong c) -> c `notElem` nonStorageClasses
  _ -> False

-- | Whether stored attributes describe a key object: the secret,
-- private and public key classes. A map without a class is not one.
isKeyClass :: Map AttributeType AttributeValue -> Bool
isKeyClass attrs = case Map.lookup AttrClass attrs of
  Just (ValULong c) -> c == ckoSecretKey || c == ckoPrivateKey || c == ckoPublicKey
  _ -> False

-- | Whether stored attributes describe a public key object. A map
-- without a class is not one.
isPublicKeyClass :: Map AttributeType AttributeValue -> Bool
isPublicKeyClass attrs = case Map.lookup AttrClass attrs of
  Just (ValULong c) -> c == ckoPublicKey
  _ -> False

-- | The reported key attributes a private or secret key object
-- lacks: non-sensitive, unextractable, not derivable, with the
-- weakest history/origin claim (no false never-extracted
-- assurance for legacy rows). Key-generation mechanism reads
-- @CK_UNAVAILABLE_INFORMATION@: it carries a valid value only when
-- @CKA_LOCAL@ is true. @CKA_DERIVE@ is a common key attribute
-- with a CK_FALSE default (PKCS#11 Table 26), so every key
-- reports it.
keyDefaults :: [(AttributeType, AttributeValue)]
keyDefaults =
  [ (AttrSensitive, ValBool False)
  , (AttrExtractable, ValBool False)
  , (AttrAlwaysSensitive, ValBool False)
  , (AttrNeverExtractable, ValBool False)
  , (AttrLocal, ValBool False)
  , (AttrDerive, ValBool False)
  -- maxBound is CK_UNAVAILABLE_INFORMATION: KGM is valid only when
  -- LOCAL is TRUE (PKCS#11 Table 26).
  , (AttrKeyGenMechanism, ValULong maxBound)
  ]

-- | The reported key attributes a public key object lacks:
-- non-sensitive, extractable and not derivable, plus the origin
-- pair. Public keys own no ALWAYS_SENSITIVE\/NEVER_EXTRACTABLE
-- (Table 27), so reads of those report unknown. Public material
-- is always readable (the seal never applies to public keys), so
-- the defaults tell the truth. @CKA_DERIVE@ is a common key
-- attribute with a CK_FALSE default (PKCS#11 Table 26), so every
-- key reports it. Caller-supplied values are stored and
-- reported, but never seal.
publicKeyDefaults :: [(AttributeType, AttributeValue)]
publicKeyDefaults =
  [ (AttrSensitive, ValBool False)
  , (AttrExtractable, ValBool True)
  , (AttrLocal, ValBool False)
  , (AttrDerive, ValBool False)
  -- maxBound is CK_UNAVAILABLE_INFORMATION: KGM is valid only when
  -- LOCAL is TRUE (PKCS#11 Table 26).
  , (AttrKeyGenMechanism, ValULong maxBound)
  ]

-- | The attribute view that reads and finds see. A storage object
-- owns every common storage attribute, so each one its stored map
-- lacks is filled in: the flags with the enforced defaults above,
-- @CKA_LABEL@ with the PKCS#11 empty default. Key objects
-- additionally own the key attributes and gain 'keyDefaults' for
-- the ones they lack; public keys gain 'publicKeyDefaults'
-- instead. Stored values always win. The view is computed per call
-- and never stored, so stored records and their durable bytes are
-- unchanged. @CKA_UNIQUE_ID@ is not modeled and stays unreported.
-- Non-storage objects pass through unchanged.
effectiveAttrs :: Map AttributeType AttributeValue -> Map AttributeType AttributeValue
effectiveAttrs attrs
  | isPublicKeyClass attrs =
      Map.union attrs (Map.union storageDefaults publicKeyDefaultMap)
  | isKeyClass attrs = Map.union attrs (Map.union storageDefaults keyDefaultMap)
  | isStorageObject attrs = Map.union attrs storageDefaults
  | otherwise = attrs
  where
    storageDefaults = Map.fromList
      ((AttrLabel, ValBytes BS.empty)
        : [(t, ValBool d) | (t, d) <- storageFlagDefaults])
    keyDefaultMap = Map.fromList keyDefaults
    publicKeyDefaultMap = Map.fromList publicKeyDefaults

-- | Effective protection flags for enforcement: the stored value,
-- else the class default from 'effectiveAttrs' (public keys report
-- EXTRACTABLE=TRUE, all other keys FALSE). Non-key classes own no
-- flags and read FALSE (fail-closed). Every enforcement predicate
-- reads these, never a literal default, so a reported default
-- cannot drift from the enforced one.
effectiveSensitive, effectiveExtractable :: Map AttributeType AttributeValue -> Bool
effectiveSensitive attrs = case Map.lookup AttrSensitive (effectiveAttrs attrs) of
  Just (ValBool b) -> b
  _ -> False
effectiveExtractable attrs = case Map.lookup AttrExtractable (effectiveAttrs attrs) of
  Just (ValBool b) -> b
  _ -> False

-- | The object's token flag (absent or wrongly shaped = session object).
objectToken :: ObjectState -> Bool
objectToken = mergedIsToken . osAttrs

-- | The object's private flag (absent or wrongly shaped = public).
objectPrivate :: ObjectState -> Bool
objectPrivate = mergedIsPrivate . osAttrs

-- | Token-owner test over merged/stored attributes (absent or
-- wrongly shaped = session object). Single predicate behind the
-- owner derivation and the read-only writability checks.
mergedIsToken :: Map AttributeType AttributeValue -> Bool
mergedIsToken = flagOr tokenDefault AttrToken

-- | Token-owner test over a raw template list (first match wins;
-- duplicates are rejected downstream by template validation).
tmplWantsToken :: [(AttributeType, AttributeValue)] -> Bool
tmplWantsToken = tmplFlagOr tokenDefault AttrToken

-- | Privacy test over merged/stored attributes (absent or wrongly
-- shaped = public).
mergedIsPrivate :: Map AttributeType AttributeValue -> Bool
mergedIsPrivate = flagOr privateDefault AttrPrivate

-- | Privacy test over a raw template list (first match wins).
tmplWantsPrivate :: [(AttributeType, AttributeValue)] -> Bool
tmplWantsPrivate = tmplFlagOr privateDefault AttrPrivate

-- | Secret-key CKA_VALUE_LEN must match the value length. A huge
-- LEN over a short value is inconsistent (and must never become an
-- allocation); the copy path checks the merged template.
valueLenConflict :: Map AttributeType AttributeValue -> Maybe String
valueLenConflict m =
  case (Map.lookup AttrClass m, Map.lookup AttrValueLen m, Map.lookup AttrValue m) of
    (Just (ValULong c), Just (ValULong want), Just (ValBytes bs))
      | c == ckoSecretKey, want /= fromIntegral (BS.length bs) ->
          Just "CKA_VALUE_LEN does not match the value length"
    _ -> Nothing

-- | Whether the object may be copied (absent = copyable, per the
-- PKCS#11 default; only an explicit false prohibits).
objectCopyable :: ObjectState -> Bool
objectCopyable = flagOr copyableDefault AttrCopyable . osAttrs

-- | Whether the object may be destroyed (absent = destroyable;
-- only an explicit false prohibits).
objectDestroyable :: ObjectState -> Bool
objectDestroyable = flagOr destroyableDefault AttrDestroyable . osAttrs

-- | Visibility per calling session: the object must live on the
-- session's slot, and private objects are additionally visible
-- only under a user login (plain or context grant). The SO sees
-- same-slot public objects only: SO sessions must neither see nor
-- use user @CKA_PRIVATE=true@ objects (PKCS#11 role separation).
objectVisible :: SessionState -> ObjectState -> Bool
objectVisible st ost =
  ssSlot st == osSlot ost
    && (not (objectPrivate ost) || ssLogin st `elem` [LoginUser, LoginContextUser])
