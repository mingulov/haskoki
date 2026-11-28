{- | Object certificate and key-type support.
-}
{-# LANGUAGE OverloadedStrings #-}
module Haskoki.Object.PlanCerts
  ( ckkEcMontgomery
  , isAsymmetricKeyType
  , ckoCertificate
  , ckoData
  , checkCertificateTemplate
  , checkCertificateDates
  , certImmutable
  , ckoPrivateKey
  , ckoPublicKey
  , ckoSecretKey
  , ckkRsa
  , ckkEc
  , ckkAes
  , ckkDsa
  , ckkDh
  , ckkX9_42Dh
  , ckkEcEdwards
  , ckkMlDsa
  , ckkSlhDsa
  , ckkMlKem
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
  ( mustClassId, mustKeyTypeId)
import Haskoki.Object.TemplateValidation

ckoPrivateKey, ckoPublicKey, ckoSecretKey, ckkRsa, ckkEc, ckkAes, ckkDsa, ckkDh, ckkX9_42Dh, ckkEcEdwards, ckkMlDsa, ckkSlhDsa, ckkMlKem, ckkKea, ckkGostr3410, ckkHss, ckkXmss, ckkXmssMt :: Word64
ckoPrivateKey = mustClassId "CKO_PRIVATE_KEY"
ckoPublicKey = mustClassId "CKO_PUBLIC_KEY"
ckoSecretKey = mustClassId "CKO_SECRET_KEY"
ckkRsa = mustKeyTypeId "CKK_RSA"
ckkEc = mustKeyTypeId "CKK_EC"
ckkDsa = mustKeyTypeId "CKK_DSA"
ckkDh = mustKeyTypeId "CKK_DH"
ckkX9_42Dh = mustKeyTypeId "CKK_X9_42_DH"
ckkEcEdwards = mustKeyTypeId "CKK_EC_EDWARDS"
ckkEcMontgomery :: Word64
ckkEcMontgomery = mustKeyTypeId "CKK_EC_MONTGOMERY"
ckkMlDsa = mustKeyTypeId "CKK_ML_DSA"
ckkSlhDsa = mustKeyTypeId "CKK_SLH_DSA"
ckkMlKem = mustKeyTypeId "CKK_ML_KEM"
ckkAes = mustKeyTypeId "CKK_AES"
ckkKea = mustKeyTypeId "CKK_KEA"
ckkGostr3410 = mustKeyTypeId "CKK_GOSTR3410"
ckkHss = mustKeyTypeId "CKK_HSS"
ckkXmss = mustKeyTypeId "CKK_XMSS"
ckkXmssMt = mustKeyTypeId "CKK_XMSSMT"

-- | Key types that belong to asymmetric (public\/private) objects:
-- the signature, agreement and KEM types of the pinned header.
-- A secret-class object carrying one of these is incoherent and
-- refuses at creation, unwrap, derive and generate time.
isAsymmetricKeyType :: Word64 -> Bool
isAsymmetricKeyType k = k `elem`
  [ ckkRsa, ckkDsa, ckkDh, ckkEc, ckkX9_42Dh, ckkKea
  , ckkGostr3410, ckkEcEdwards, ckkEcMontgomery
  , ckkHss, ckkXmss, ckkXmssMt, ckkMlKem, ckkMlDsa, ckkSlhDsa
  ]

ckoCertificate :: Word64
ckoCertificate = mustClassId "CKO_CERTIFICATE"

ckoData :: Word64
ckoData = mustClassId "CKO_DATA"

-- | CKC_X_509 per the pinned header (spec/vendor/pkcs11.h:300);
-- there is no model inventory of certificate types.
ckcX509 :: Word64
ckcX509 = 0

-- | X.509 creation requirements over an already shape-validated
-- template: the type itself must be present; X.509 additionally
-- requires VALUE and SUBJECT (presence only: empty-DER-Name
-- SUBJECT is accepted for SAN-only certificates). Non-X.509
-- subtype values keep the generic CLASS+TYPE-only path. Only
-- TemplateIncomplete is ever produced here; shapes were pinned
-- by validateTemplate before this runs.
checkCertificateTemplate
  :: Map AttributeType AttributeValue -> Either TemplateError ()
checkCertificateTemplate attrs = case Map.lookup AttrClass attrs of
  Just (ValULong c)
    | c == ckoCertificate -> case Map.lookup AttrCertificateType attrs of
        Nothing -> Left TemplateIncomplete
        Just (ValULong t)
          | t == ckcX509 ->
              if Map.member AttrValue attrs && Map.member AttrSubject attrs
                then Right ()
                else Left TemplateIncomplete
          | otherwise -> Right ()
        _ -> Right ()
  _ -> Right ()

-- | Certificate date format over an already shape-validated
-- template: present START_DATE/END_DATE values must be exactly 8
-- ASCII-digit bytes (the YYYYMMDD layout; month/day semantics are
-- NOT validated and no validity period is enforced). Violations are
-- 'TemplateWrongType' (inconsistent); absence is fine. The create
-- path runs this before 'checkCertificateTemplate' so malformedness
-- precedes incompleteness.
checkCertificateDates
  :: Map AttributeType AttributeValue -> Either TemplateError ()
checkCertificateDates attrs = do
  checkOne AttrStartDate
  checkOne AttrEndDate
  where
    checkOne t = case Map.lookup t attrs of
      Nothing -> Right ()
      Just (ValBytes bs)
        | BS.length bs == 8 && BS.all isDigit bs -> Right ()
        | otherwise -> Left (TemplateWrongType t)
      Just _ -> Left (TemplateWrongType t)
    isDigit w = w >= 0x30 && w <= 0x39

-- | Certificate attributes a copy template may never override: the
-- identity fields plus the trust, category, and date attributes.
-- The copy guard scopes this set to certificate sources only.
certImmutable :: [AttributeType]
certImmutable =
  [ AttrClass, AttrCertificateType, AttrValue, AttrSubject, AttrIssuer, AttrSerialNumber
  , AttrPublicKeyInfo, AttrHashOfSubjectPublicKey, AttrHashOfIssuerPublicKey
  , AttrTrusted, AttrCertificateCategory, AttrStartDate, AttrEndDate
  ]
