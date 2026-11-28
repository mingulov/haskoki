{- | Minimal DER codec for key assembly and keygen stamping.

'planCreateObject' stores asymmetric keys the same way key generation
does: @AttrValue@ carries PKCS#8 (private) or SubjectPublicKeyInfo
(public) DER, while the PKCS#11 components stay stored verbatim for
reads. The writers assemble that DER purely from components — the
only runtime input the backend needs beyond the components is the
curve OID, resolved by 'curveOidOfParams'. The readers run the
other way at keygen finish time: the backend returns DER halves,
and 'finishWork' stamps the components back onto the new objects
so reads serve them without a decode-on-read path.

Scope is deliberately narrow: RSA PKCS#1/SPKI/PKCS#8, SEC1 EC
keys on the 22 covered curves ('curveTable'), DSA DSS-Parms /
SPKI / PKCS#8, Edwards SPKI / PKCS#8 on the 2 served curves
('edwardsTable'), Montgomery SPKI / PKCS#8 on the 2 served
curves ('montgomeryTable'), ML-DSA SPKI / flat-expanded PKCS#8
on the 3 served levels ('mldsaTable'), and ML-KEM SPKI /
provider-form PKCS#8 on the 3 served sets ('mlkemTable').
Anything else refuses at the call site
('CKR_CURVE_NOT_SUPPORTED' for foreign curves,
'CKR_TEMPLATE_INCONSISTENT' for malformed parts) instead of
encoding half-understood structures.
-}
{-# LANGUAGE OverloadedStrings #-}
module Haskoki.Der
  ( rsaPrivateDer
  , rsaPublicDer
  , rsaSpkiFields
  , ecPrivateDer
  , ecPublicDer
  , dsaParamsDer
  , dsaPrivateDer
  , dsaPublicDer
  , parseDsaParams
  , dsaSpkiFields
  , dsaPkcs8Fields
  , dhParamsDer
  , dhParamsDerQ
  , dhPrivateDer
  , dhPublicDer
  , dhPrivateDerQ
  , dhPublicDerQ
  , parseDhParams
  , dhSpkiFields
  , dhPkcs8Fields
  , eddsaPrivateDer
  , eddsaPublicDer
  , eddsaSpkiFields
  , eddsaPkcs8Fields
  , mldsaTable
  , mldsaPublicDer
  , mldsaPrivateDer
  , mldsaSpkiFields
  , mldsaPkcs8Fields
  , mldsaOidOfParams
  , mldsaNameOfOid
  , mldsaWidthsOfOid
  , mldsaCkpOfOid
  , mldsaOidOfCkp
  , mlkemTable
  , mlkemPublicDer
  , mlkemPrivateDer
  , mlkemSpkiFields
  , mlkemPkcs8Fields
  , mlkemOidOfParams
  , mlkemNameOfOid
  , mlkemWidthsOfOid
  , mlkemCkpOfOid
  , mlkemOidOfCkp
  , mlkemEkWellFormed
  , slhdsaTable
  , slhdsaPublicDer
  , slhdsaPrivateDer
  , slhdsaSpkiFields
  , slhdsaPkcs8Fields
  , slhdsaOidOfParams
  , slhdsaNameOfOid
  , slhdsaWidthsOfOid
  , slhdsaCkpOfOid
  , slhdsaOidOfCkp
  , unwrapEcPoint
  , unwrapEdwardsPoint
  , unwrapMontgomeryPoint
  , curveOidOfParams
  , curveCoordLen
  , curveOrderLen
  , curveOrderOfOid
  , curveNameOfOid
  , curveTable
  , edwardsTable
  , edwardsOidOfParams
  , edwardsNameOfOid
  , edwardsWidthsOfParams
  , montgomeryTable
  , montgomeryOidOfParams
  , montgomeryNameOfOid
  , ecParamsNameOfOid
  , montgomeryWidthOfParams
  , montgomeryPrivateDer
  , montgomeryPublicDer
  , montgomerySpkiFields
  , montgomeryPkcs8Fields
  , coveredCurveNames
  , edwardsCurveNames
  , montgomeryCurveNames
  , integerToBE
  , RsaCrt (..)
  , parseRsaPrivate
  , parseRsaPublic
  , spkiPoint
  , ecSpkiFields
  , ecPkcs8HasPub
  , ecSec1HasPub
  , derOctet
  ) where


import Haskoki.Der.Primitives
import Haskoki.Der.Classical
import Haskoki.Der.Pqc
