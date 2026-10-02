{- | Certificate template contract tests (T-C01).

X.509 creation requires certificate type, value, and subject
(presence only: an empty-DER-Name subject is accepted for
SAN-only certificates). Non-X.509 subtype values keep the
generic CLASS+TYPE-only path. Only TemplateIncomplete is
produced by the gate; malformedness outranks incompleteness.

T-C03 adds the trust/category/date attribute cases: the SO-only
TRUSTED=true boundary on create/copy/set, category/date roundtrips
with search, the 8-ASCII-digit date format ahead of presence, the
scoped certificate copy-immutable set, and setter/copy precedence.
-}
{-# LANGUAGE OverloadedStrings #-}
module CertificateSpec (spec) where

import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BC8
import qualified Data.Map.Strict as Map
import Data.Word (Word64)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertEqual, assertFailure, testCase)

import Haskoki.Attribute
  ( AttributeType (..)
  , AttributeValue (..)
  , maxAttributeBytes
  )
import Haskoki.Attribute.Generated (mustClassId)
import Haskoki.Model
  ( Model (..)
  , ObjectState (..)
  , SessionState (..)
  , addToken
  , emptyModel
  )
import Haskoki.Object
  ( decodeHandle
  , encodeTemplate
  , encodeWanted
  , planCopyObject
  , planCreateObject
  , planSetAttributes
  , resolveHandle
  )
import Haskoki.Operation (emptySessionOps)
import Haskoki.Outcome
  ( NativeOutput (..)
  , PlanResult (..)
  , PreparedCommit (..)
  , Rejection (..)
  )
import Haskoki.Request (FunctionId (..), Request (..))
import Haskoki.Rules (defaultRules)
import Haskoki.Session (SessionLogin (..))
import Haskoki.Transition (planCall, publishDelta)
import Haskoki.Types
  ( ExternalHandle (..)
  , Generation (..)
  , Pkcs11Version (..)
  , ReturnCode (..)
  , Revision (..)
  , SessionId (..)
  , SlotId (..)
  )

spec :: TestTree
spec = testGroup "Certificates"
  [ testGroup "T-C01"
    [ testCase "caseCertRequiresTypeValueSubject" caseCertRequiresTypeValueSubject
    , testCase "caseCertEmptySubjectAccepted" caseCertEmptySubjectAccepted
    , testCase "caseCertNonX509Generic" caseCertNonX509Generic
    , testCase "caseCertPrecedenceTyped" caseCertPrecedenceTyped
    , testCase "caseCertPrecedenceCodec" caseCertPrecedenceCodec
    , testCase "caseCertNoPartial" caseCertNoPartial
    ]
  , testGroup "T-C03"
    [ testCase "caseTrustedBoundary" caseTrustedBoundary
    , testCase "caseCategoryRoundtrip" caseCategoryRoundtrip
    , testCase "caseDateRoundtrip" caseDateRoundtrip
    , testCase "caseDateFormat" caseDateFormat
    , testCase "caseCertImmutableMatrix" caseCertImmutableMatrix
    , testCase "caseCopyScopeRegression" caseCopyScopeRegression
    , testCase "caseCopyPrecedence" caseCopyPrecedence
    , testCase "caseTrustedAtomicity" caseTrustedAtomicity
    , testCase "caseSetterPrecedence" caseSetterPrecedence
    , testCase "caseNewAttrShapes" caseNewAttrShapes
    ]
  , testGroup "T-C04"
    [ testCase "caseSuppliedOpaque" caseSuppliedOpaque
    , testCase "caseNoCoherenceGate" caseNoCoherenceGate
    ]
  ]

certClass :: Word64
certClass = mustClassId "CKO_CERTIFICATE"

-- | CKC_X_509 per the pinned header (spec/vendor/pkcs11.h:300);
-- there is no model inventory of certificate types.
ckcX509 :: Word64
ckcX509 = 0

testSession :: SessionState
testSession = SessionState
  { ssId = SessionId 1
  , ssSlot = SlotId 7
  , ssRevision = Revision 1
  , ssGeneration = Generation 1
  , ssReadOnly = False
  , ssLogin = LoginPublic
  , ssOps = emptySessionOps
  }

clsCert, typX509, valDer, subjCn :: (AttributeType, AttributeValue)
clsCert = (AttrClass, ValULong certClass)
typX509 = (AttrCertificateType, ValULong ckcX509)
valDer = (AttrValue, ValBytes "der")
subjCn = (AttrSubject, ValBytes "cn")

certAttrs :: [(AttributeType, AttributeValue)]
certAttrs = [clsCert, typX509, valDer, subjCn]

-- | Each of TYPE, VALUE, SUBJECT missing in turn refuses
-- INCOMPLETE; the full template commits.
caseCertRequiresTypeValueSubject :: IO ()
caseCertRequiresTypeValueSubject = do
  (sid, m0) <- openSession seeded
  (codeT, _) <- runReject m0 (createReq sid [clsCert, valDer, subjCn])
  assertEqual "missing TYPE" CKR_TEMPLATE_INCOMPLETE codeT
  (codeV, _) <- runReject m0 (createReq sid [clsCert, typX509, subjCn])
  assertEqual "missing VALUE" CKR_TEMPLATE_INCOMPLETE codeV
  (codeS, _) <- runReject m0 (createReq sid [clsCert, typX509, valDer])
  assertEqual "missing SUBJECT" CKR_TEMPLATE_INCOMPLETE codeS
  (pc, _) <- runCommit m0 (createReq sid certAttrs)
  assertEqual "full template" CKR_OK (pcCode pc)

-- | A zero-length SUBJECT is accepted (SAN-only certificates)
-- and stored verbatim.
caseCertEmptySubjectAccepted :: IO ()
caseCertEmptySubjectAccepted = do
  (sid, m0) <- openSession seeded
  let tmpl =
        [ (AttrClass, ValULong certClass)
        , (AttrCertificateType, ValULong ckcX509)
        , (AttrValue, ValBytes "der")
        , (AttrSubject, ValBytes "")
        ]
  (pc, m1) <- runCommit m0 (createReq sid tmpl)
  assertEqual "empty subject commits" CKR_OK (pcCode pc)
  h <- commitHandle pc
  case resolveHandle m1 h of
    Nothing -> assertFailure "created handle does not resolve"
    Just ost -> assertEqual "subject stored verbatim"
      (Just (ValBytes "")) (Map.lookup AttrSubject (osAttrs ost))

-- | Non-X.509 subtype values keep the generic CLASS+TYPE-only
-- path: VALUE/SUBJECT omitted still commits.
caseCertNonX509Generic :: IO ()
caseCertNonX509Generic = mapM_ check [1, 2]
  where
    check :: Word64 -> IO ()
    check t = do
      (sid, m0) <- openSession seeded
      (pc, _) <- runCommit m0 (createReq sid
        [ (AttrClass, ValULong certClass)
        , (AttrCertificateType, ValULong t)
        ])
      assertEqual ("non-x509 type " ++ show t) CKR_OK (pcCode pc)

-- | At the typed seam a contradictory duplicate plus a missing
-- SUBJECT refuses INCONSISTENT, and a wrong-shape VALUE plus a
-- missing SUBJECT refuses INCONSISTENT: malformedness outranks
-- incompleteness.
caseCertPrecedenceTyped :: IO ()
caseCertPrecedenceTyped = do
  let missingSubject =
        [ clsCert, typX509, valDer
        , (AttrLabel, ValBytes "a"), (AttrLabel, ValBytes "b")
        ]
  case planCreateObject emptyModel testSession missingSubject of
    Reject rej -> assertEqual "contradiction outranks omission"
      CKR_TEMPLATE_INCONSISTENT (rejCode rej)
    Immediate _ -> assertFailure "contradiction committed"
    Execute _ _ -> assertFailure "contradiction reserved execution"
  let wrongShape =
        [ (AttrClass, ValULong certClass)
        , (AttrCertificateType, ValULong ckcX509)
        , (AttrValue, ValULong 7)
        ]
  case planCreateObject emptyModel testSession wrongShape of
    Reject rej -> assertEqual "wrong shape outranks omission"
      CKR_TEMPLATE_INCONSISTENT (rejCode rej)
    Immediate _ -> assertFailure "wrong shape committed"
    Execute _ _ -> assertFailure "wrong shape reserved execution"

-- | At the codec seam truncated/malformed template bytes refuse
-- ARGUMENTS_BAD, never reaching the certificate gate.
caseCertPrecedenceCodec :: IO ()
caseCertPrecedenceCodec = do
  (sid, m0) <- openSession seeded
  let short = (createReq sid []) { reqInput = BS.pack [1, 2, 3] }
  (codeShort, _) <- runReject m0 short
  assertEqual "short bytes" CKR_ARGUMENTS_BAD codeShort
  let unknownTag = (createReq sid []) { reqInput = BS.pack [255, 0, 0, 0, 0] }
  (codeTag, _) <- runReject m0 unknownTag
  assertEqual "unknown tag" CKR_ARGUMENTS_BAD codeTag
  let chopped = (createReq sid [])
        { reqInput = BS.init (encodeTemplate certAttrs) }
  (codeChop, _) <- runReject m0 chopped
  assertEqual "truncated encoding" CKR_ARGUMENTS_BAD codeChop

-- | Each refused create leaves object and handle counts unchanged.
caseCertNoPartial :: IO ()
caseCertNoPartial = do
  (sid, m0) <- openSession seeded
  let refused =
        [ [clsCert, valDer, subjCn]
        , [clsCert, typX509, subjCn]
        , [clsCert, typX509, valDer]
        ]
      counts m = (Map.size (mObjects m), Map.size (mHandles m))
      before = counts m0
  let go m [] = pure m
      go m (tmpl : rest) = do
        (code, m') <- runReject m (createReq sid tmpl)
        assertEqual "refusal code" CKR_TEMPLATE_INCOMPLETE code
        assertEqual "no partial state" before (counts m')
        go m' rest
  _ <- go m0 refused
  pure ()

-- ---------------------------------------------------------------------------
-- T-C03 cases
-- ---------------------------------------------------------------------------

trustedTrue, trustedFalse :: (AttributeType, AttributeValue)
trustedTrue = (AttrTrusted, ValBool True)
trustedFalse = (AttrTrusted, ValBool False)

dataClass, secretClass :: Word64
dataClass = mustClassId "CKO_DATA"
secretClass = mustClassId "CKO_SECRET_KEY"

-- | The SO-only TRUSTED=true boundary on create, set, and copy for
-- all four login shapes; TRUSTED=false stores and reads back for any
-- session; exact-value find matches the SO-created TRUSTED=true
-- objects. Copy refusals speak the copy-path vocabulary
-- (INCONSISTENT); create/set refusals speak READ_ONLY.
caseTrustedBoundary :: IO ()
caseTrustedBoundary = do
  -- Public session: create+set true refuse READ_ONLY.
  (sidP, mP0) <- openSession seeded
  (codePC, mP1) <- runReject mP0 (createReq sidP (certAttrs ++ [trustedTrue]))
  assertEqual "public create trusted=true" CKR_ATTRIBUTE_READ_ONLY codePC
  (pcPP, mP2) <- runCommit mP1 (createReq sidP certAttrs)
  hP <- commitHandle pcPP
  (codePS, _) <- runReject mP2 (setReq sidP hP [trustedTrue])
  assertEqual "public set trusted=true" CKR_ATTRIBUTE_READ_ONLY codePS
  -- Authenticated user: the same refusals.
  (sidU, mU0) <- openSession seeded
  mU1 <- loginAs mU0 sidU
  (codeUC, mU2) <- runReject mU1 (createReq sidU (certAttrs ++ [trustedTrue]))
  assertEqual "user create trusted=true" CKR_ATTRIBUTE_READ_ONLY codeUC
  (pcUP, mU3) <- runCommit mU2 (createReq sidU certAttrs)
  hU <- commitHandle pcUP
  (codeUS, _) <- runReject mU3 (setReq sidU hU [trustedTrue])
  assertEqual "user set trusted=true" CKR_ATTRIBUTE_READ_ONLY codeUS
  -- Context grant: direct planner calls (no model route mints the
  -- grant without an active operation).
  let granted = testSession { ssLogin = LoginContextUser }
  case planCreateObject emptyModel granted (certAttrs ++ [trustedTrue]) of
    Reject rej -> assertEqual "context create trusted=true"
      CKR_ATTRIBUTE_READ_ONLY (rejCode rej)
    Immediate _ -> assertFailure "context trusted=true create committed"
    Execute _ _ -> assertFailure "context trusted=true create reserved execution"
  case planCreateObject emptyModel testSession certAttrs of
    Immediate pcC -> case publishDelta emptyModel (pcDelta pcC) of
      Left fault -> assertFailure ("context setup fault: " ++ show fault)
      Right mC -> do
        hC <- commitHandle pcC
        case planSetAttributes mC granted hC [trustedTrue] of
          Reject rej -> assertEqual "context set trusted=true"
            CKR_ATTRIBUTE_READ_ONLY (rejCode rej)
          Immediate _ -> assertFailure "context trusted=true set committed"
          Execute _ _ -> assertFailure "context trusted=true set reserved execution"
        case planCopyObject mC granted hC [trustedTrue] of
          Reject rej -> assertEqual "context copy trusted=true"
            CKR_TEMPLATE_INCONSISTENT (rejCode rej)
          Immediate _ -> assertFailure "context trusted=true copy committed"
          Execute _ _ -> assertFailure "context trusted=true copy reserved execution"
    Reject rej -> assertFailure ("context setup rejected: " ++ show (rejCode rej))
    Execute _ _ -> assertFailure "context setup reserved execution"
  -- SO: create+set true commit and read back true.
  (sidS, mS0) <- openSession seeded
  mS1 <- loginAsSO mS0 sidS
  (pcST, mS2) <- runCommit mS1 (createReq sidS (certAttrs ++ [trustedTrue]))
  hST <- commitHandle pcST
  case resolveHandle mS2 hST of
    Nothing -> assertFailure "SO trusted create handle lost"
    Just ost -> assertEqual "SO trusted=true stored"
      (Just (ValBool True)) (Map.lookup AttrTrusted (osAttrs ost))
  (pcSP, mS3) <- runCommit mS2 (createReq sidS certAttrs)
  hSP <- commitHandle pcSP
  (pcSS, mS4) <- runCommit mS3 (setReq sidS hSP [trustedTrue])
  assertEqual "SO set trusted=true" CKR_OK (pcCode pcSS)
  case resolveHandle mS4 hSP of
    Nothing -> assertFailure "SO trusted set handle lost"
    Just ost -> assertEqual "SO trusted=true set stored"
      (Just (ValBool True)) (Map.lookup AttrTrusted (osAttrs ost))
  -- TRUSTED=true find by exact value matches the SO-created objects.
  (pcSF, _) <- runCommit mS4 (findReq sidS [trustedTrue])
  foundT <- findHandles pcSF
  assertEqual "trusted=true find matches" [hST, hSP] foundT
  (pcSNF, _) <- runCommit mS4 (findReq sidS [trustedFalse])
  foundF <- findHandles pcSNF
  assertEqual "trusted=false find matches nothing yet" [] foundF
  -- The SO copy rule is unscoped: TRUSTED=true copy-override needs
  -- SO on every class, so DATA sources pin the rule without the
  -- certificate immutable set.
  (sidD, mD0) <- openSession seeded
  (pcD, mD1) <- runCommit mD0
    (createReq sidD [(AttrClass, ValULong dataClass), (AttrLabel, ValBytes "d")])
  hD <- commitHandle pcD
  (codeDC, mD2) <- runReject mD1 (copyReq sidD hD [trustedTrue])
  assertEqual "public data copy trusted=true" CKR_TEMPLATE_INCONSISTENT codeDC
  mD3 <- loginAsSO mD2 sidD
  (pcDSC, mD4) <- runCommit mD3 (copyReq sidD hD [trustedTrue])
  hDSC <- commitHandle pcDSC
  case resolveHandle mD4 hDSC of
    Nothing -> assertFailure "SO data copy handle lost"
    Just ost -> assertEqual "SO data copy trusted=true stored"
      (Just (ValBool True)) (Map.lookup AttrTrusted (osAttrs ost))
  -- TRUSTED=false copies merge off-class for any session.
  (pcDF, mD5) <- runCommit mD4 (copyReq sidD hD [trustedFalse])
  hDF <- commitHandle pcDF
  case resolveHandle mD5 hDF of
    Nothing -> assertFailure "false data copy handle lost"
    Just ost -> assertEqual "false data copy stored"
      (Just (ValBool False)) (Map.lookup AttrTrusted (osAttrs ost))
  -- TRUSTED=false writes are the documented exception to every
  -- refusal above: every login shape stores and reads back false.
  (pcPF, mP3) <- runCommit mP2 (createReq sidP (certAttrs ++ [trustedFalse]))
  hPF <- commitHandle pcPF
  case resolveHandle mP3 hPF of
    Nothing -> assertFailure "public false create handle lost"
    Just ost -> assertEqual "public false stored"
      (Just (ValBool False)) (Map.lookup AttrTrusted (osAttrs ost))
  (pcPSF, mP4) <- runCommit mP3 (setReq sidP hP [trustedFalse])
  assertEqual "public false set" CKR_OK (pcCode pcPSF)
  case resolveHandle mP4 hP of
    Nothing -> assertFailure "public false set handle lost"
    Just ost -> assertEqual "public false set stored"
      (Just (ValBool False)) (Map.lookup AttrTrusted (osAttrs ost))
  (pcUF, mU4) <- runCommit mU3 (createReq sidU (certAttrs ++ [trustedFalse]))
  hUF <- commitHandle pcUF
  case resolveHandle mU4 hUF of
    Nothing -> assertFailure "user false create handle lost"
    Just ost -> assertEqual "user false stored"
      (Just (ValBool False)) (Map.lookup AttrTrusted (osAttrs ost))
  (pcUSF, mU5) <- runCommit mU4 (setReq sidU hU [trustedFalse])
  assertEqual "user false set" CKR_OK (pcCode pcUSF)
  case resolveHandle mU5 hU of
    Nothing -> assertFailure "user false set handle lost"
    Just ost -> assertEqual "user false set stored"
      (Just (ValBool False)) (Map.lookup AttrTrusted (osAttrs ost))
  (pcSOF, mS5) <- runCommit mS4 (createReq sidS (certAttrs ++ [trustedFalse]))
  hSOF <- commitHandle pcSOF
  case resolveHandle mS5 hSOF of
    Nothing -> assertFailure "SO false create handle lost"
    Just ost -> assertEqual "SO false stored"
      (Just (ValBool False)) (Map.lookup AttrTrusted (osAttrs ost))
  case planCreateObject emptyModel granted (certAttrs ++ [trustedFalse]) of
    Immediate pcG -> case publishDelta emptyModel (pcDelta pcG) of
      Left fault -> assertFailure ("context false setup fault: " ++ show fault)
      Right mG -> do
        hG <- commitHandle pcG
        case resolveHandle mG hG of
          Nothing -> assertFailure "context false create handle lost"
          Just ost -> assertEqual "context false stored"
            (Just (ValBool False)) (Map.lookup AttrTrusted (osAttrs ost))
        case planSetAttributes mG granted hG [trustedFalse] of
          Immediate pcGS -> case publishDelta mG (pcDelta pcGS) of
            Left fault -> assertFailure ("context false set fault: " ++ show fault)
            Right mGS -> case resolveHandle mGS hG of
              Nothing -> assertFailure "context false set handle lost"
              Just ost -> assertEqual "context false set stored"
                (Just (ValBool False)) (Map.lookup AttrTrusted (osAttrs ost))
          Reject rej -> assertFailure
            ("context false set refused: " ++ show (rejCode rej))
          Execute _ _ -> assertFailure "context false set reserved execution"
    Reject rej -> assertFailure
      ("context false create refused: " ++ show (rejCode rej))
    Execute _ _ -> assertFailure "context false create reserved execution"
  -- USER DATA-source copy: off-class, so only the SO rule can refuse
  -- (the certificate immutable set cannot mask it); the SO message is
  -- pinned.
  (sidDU, mDU0) <- openSession seeded
  mDU1 <- loginAs mDU0 sidDU
  (pcDU, mDU2) <- runCommit mDU1
    (createReq sidDU [(AttrClass, ValULong dataClass), (AttrLabel, ValBytes "du")])
  hDU <- commitHandle pcDU
  (rejDU, _) <- runRejectFull mDU2 (copyReq sidDU hDU [trustedTrue])
  assertEqual "user data copy trusted=true"
    CKR_TEMPLATE_INCONSISTENT (rejCode rejDU)
  assertEqual "user data copy SO message"
    ["only the security officer may copy to TRUSTED=true"] (rejReasons rejDU)
  -- Context DATA-source copy: same off-class SO pin via direct
  -- planner calls.
  case planCreateObject emptyModel testSession
      [(AttrClass, ValULong dataClass), (AttrLabel, ValBytes "ctx-data")] of
    Immediate pcGD -> case publishDelta emptyModel (pcDelta pcGD) of
      Left fault -> assertFailure ("context data setup fault: " ++ show fault)
      Right mGD -> do
        hGD <- commitHandle pcGD
        case planCopyObject mGD granted hGD [trustedTrue] of
          Reject rej -> do
            assertEqual "context data copy trusted=true"
              CKR_TEMPLATE_INCONSISTENT (rejCode rej)
            assertEqual "context data copy SO message"
              ["only the security officer may copy to TRUSTED=true"] (rejReasons rej)
          Immediate _ -> assertFailure "context data trusted=true copy committed"
          Execute _ _ -> assertFailure "context data trusted=true copy reserved execution"
    Reject rej -> assertFailure
      ("context data setup rejected: " ++ show (rejCode rej))
    Execute _ _ -> assertFailure "context data setup reserved execution"

-- | Category is opaque: 0 and maxBound store, search, and read back;
-- set and copy-override refuse.
caseCategoryRoundtrip :: IO ()
caseCategoryRoundtrip = do
  (sid, m0) <- openSession seeded
  (pc0, m1) <- runCommit m0
    (createReq sid (certAttrs ++ [(AttrCertificateCategory, ValULong 0)]))
  h0 <- commitHandle pc0
  case resolveHandle m1 h0 of
    Nothing -> assertFailure "category-0 handle lost"
    Just ost -> assertEqual "category 0 stored"
      (Just (ValULong 0)) (Map.lookup AttrCertificateCategory (osAttrs ost))
  (pcM, m2) <- runCommit m1
    (createReq sid (certAttrs ++ [(AttrCertificateCategory, ValULong maxBound)]))
  hM <- commitHandle pcM
  case resolveHandle m2 hM of
    Nothing -> assertFailure "category-max handle lost"
    Just ost -> assertEqual "category maxBound stored"
      (Just (ValULong maxBound)) (Map.lookup AttrCertificateCategory (osAttrs ost))
  (pcF0, _) <- runCommit m2
    (findReq sid [(AttrCertificateCategory, ValULong 0)])
  found0 <- findHandles pcF0
  assertEqual "category 0 find" [h0] found0
  (pcFM, _) <- runCommit m2
    (findReq sid [(AttrCertificateCategory, ValULong maxBound)])
  foundM <- findHandles pcFM
  assertEqual "category maxBound find" [hM] foundM
  (codeS, _) <- runReject m2
    (setReq sid h0 [(AttrCertificateCategory, ValULong 7)])
  assertEqual "category set refused" CKR_ATTRIBUTE_READ_ONLY codeS
  (codeC, m3) <- runReject m2
    (copyReq sid h0 [(AttrCertificateCategory, ValULong 7)])
  assertEqual "category copy-override refused" CKR_TEMPLATE_INCONSISTENT codeC
  assertEqual "no copy created"
    (Map.size (mObjects m2)) (Map.size (mObjects m3))

-- | Dates store, search, and read back; set refuses (read-only, so no
-- setter format check exists).
caseDateRoundtrip :: IO ()
caseDateRoundtrip = do
  (sid, m0) <- openSession seeded
  let start = (AttrStartDate, ValBytes "20240131")
      end = (AttrEndDate, ValBytes "20250131")
  (pc, m1) <- runCommit m0 (createReq sid (certAttrs ++ [start, end]))
  h <- commitHandle pc
  case resolveHandle m1 h of
    Nothing -> assertFailure "dated handle lost"
    Just ost -> do
      assertEqual "start date stored"
        (Just (ValBytes "20240131")) (Map.lookup AttrStartDate (osAttrs ost))
      assertEqual "end date stored"
        (Just (ValBytes "20250131")) (Map.lookup AttrEndDate (osAttrs ost))
  (pcF, _) <- runCommit m1 (findReq sid [start])
  found <- findHandles pcF
  assertEqual "start-date find" [h] found
  (codeS, _) <- runReject m1 (setReq sid h [start])
  assertEqual "start-date set refused" CKR_ATTRIBUTE_READ_ONLY codeS
  (codeE, _) <- runReject m1 (setReq sid h [end])
  assertEqual "end-date set refused" CKR_ATTRIBUTE_READ_ONLY codeE

-- | Present dates must be exactly 8 ASCII-digit bytes; violations
-- refuse INCONSISTENT at create, before the presence gate (a missing
-- SUBJECT plus a malformed date reports the date). Month/day
-- semantics are not validated.
caseDateFormat :: IO ()
caseDateFormat = do
  (sid, m0) <- openSession seeded
  let bad =
        [ ("7-byte start", (AttrStartDate, ValBytes "2024013"))
        , ("9-byte start", (AttrStartDate, ValBytes "202401311"))
        , ("non-digit start", (AttrStartDate, ValBytes "20240X31"))
        , ("7-byte end", (AttrEndDate, ValBytes "2025013"))
        , ("non-digit end", (AttrEndDate, ValBytes "2025-01-3"))
        ]
      check (label, entry) = do
        (code, _) <- runReject m0 (createReq sid (certAttrs ++ [entry]))
        assertEqual label CKR_TEMPLATE_INCONSISTENT code
  mapM_ check bad
  (codeP, _) <- runReject m0
    (createReq sid [clsCert, typX509, valDer, (AttrStartDate, ValBytes "short")])
  assertEqual "malformed date precedes missing subject"
    CKR_TEMPLATE_INCONSISTENT codeP
  (pcM, _) <- runCommit m0
    (createReq sid (certAttrs ++ [(AttrStartDate, ValBytes "20241331")]))
  assertEqual "month 13 accepted" CKR_OK (pcCode pcM)

fullCert :: [(AttributeType, AttributeValue)]
fullCert = certAttrs
  ++ [ (AttrLabel, ValBytes "matrix")
     , (AttrIssuer, ValBytes "i")
     , (AttrSerialNumber, ValBytes "s")
     , (AttrPublicKeyInfo, ValBytes "p")
     , (AttrHashOfSubjectPublicKey, ValBytes "h1")
     , (AttrHashOfIssuerPublicKey, ValBytes "h2")
     , (AttrCertificateCategory, ValULong 1)
     , (AttrStartDate, ValBytes "20240131")
     , (AttrEndDate, ValBytes "20250131")
     ]

-- | Copy/set of every certificate-immutable member refuses — CLASS
-- override on cert sources included — except TRUSTED=false set
-- (allowed all logins) and SO TRUSTED=true set (allowed).
-- LABEL/APPLICATION/ID overrides stay allowed on both paths.
caseCertImmutableMatrix :: IO ()
caseCertImmutableMatrix = do
  (sid, m0) <- openSession seeded
  (pc, m1) <- runCommit m0 (createReq sid fullCert)
  h <- commitHandle pc
  let overrides =
        [ (AttrClass, ValULong dataClass)
        , (AttrCertificateType, ValULong 1)
        , (AttrValue, ValBytes "other")
        , (AttrSubject, ValBytes "other-subject")
        , (AttrIssuer, ValBytes "other-issuer")
        , (AttrSerialNumber, ValBytes "other-serial")
        , (AttrPublicKeyInfo, ValBytes "other-pki")
        , (AttrHashOfSubjectPublicKey, ValBytes "other-h1")
        , (AttrHashOfIssuerPublicKey, ValBytes "other-h2")
        , trustedFalse
        , (AttrCertificateCategory, ValULong 9)
        , (AttrStartDate, ValBytes "20250101")
        , (AttrEndDate, ValBytes "20260101")
        ]
      checkCopy entry = do
        (code, m') <- runReject m1 (copyReq sid h [entry])
        assertEqual ("copy refused: " ++ show (fst entry))
          CKR_TEMPLATE_INCONSISTENT code
        assertEqual ("no copy created: " ++ show (fst entry))
          (Map.size (mObjects m1)) (Map.size (mObjects m'))
      checkSet entry = do
        (code, _) <- runReject m1 (setReq sid h [entry])
        assertEqual ("set refused: " ++ show (fst entry))
          CKR_ATTRIBUTE_READ_ONLY code
  mapM_ checkCopy overrides
  mapM_ checkSet (filter ((/= AttrTrusted) . fst) overrides)
  -- A malformed date set still refuses READ_ONLY: the setter has no
  -- format check (refusal precedes format).
  (codeBadSet, _) <- runReject m1
    (setReq sid h [(AttrStartDate, ValBytes "short")])
  assertEqual "malformed date set" CKR_ATTRIBUTE_READ_ONLY codeBadSet
  -- TRUSTED=false set is the documented exception (allowed all
  -- logins; other shapes are covered by the boundary case).
  (pcTF, m2) <- runCommit m1 (setReq sid h [trustedFalse])
  assertEqual "trusted=false set" CKR_OK (pcCode pcTF)
  case resolveHandle m2 h of
    Nothing -> assertFailure "false-set handle lost"
    Just ost -> assertEqual "trusted=false set stored"
      (Just (ValBool False)) (Map.lookup AttrTrusted (osAttrs ost))
  -- SO TRUSTED=true set is allowed; SO copy TRUSTED=true still
  -- refuses INCONSISTENT (the immutable set has no SO exception).
  (sidS, mS0) <- openSession seeded
  mS1 <- loginAsSO mS0 sidS
  (pcS, mS2) <- runCommit mS1 (createReq sidS fullCert)
  hS <- commitHandle pcS
  (pcST, mS3) <- runCommit mS2 (setReq sidS hS [trustedTrue])
  assertEqual "SO trusted=true set" CKR_OK (pcCode pcST)
  case resolveHandle mS3 hS of
    Nothing -> assertFailure "SO trusted-set handle lost"
    Just ost -> assertEqual "SO trusted=true set stored"
      (Just (ValBool True)) (Map.lookup AttrTrusted (osAttrs ost))
  (codeSC, _) <- runReject mS3 (copyReq sidS hS [trustedTrue])
  assertEqual "SO trusted=true copy refused" CKR_TEMPLATE_INCONSISTENT codeSC
  -- LABEL/APPLICATION/ID overrides stay allowed on both paths.
  (pcCL, m3) <- runCommit m2
    (copyReq sid h [(AttrLabel, ValBytes "copy-label")])
  assertEqual "label copy-override" CKR_OK (pcCode pcCL)
  hCL <- commitHandle pcCL
  case resolveHandle m3 hCL of
    Nothing -> assertFailure "label-copy handle lost"
    Just ost -> assertEqual "label copy-override stored"
      (Just (ValBytes "copy-label")) (Map.lookup AttrLabel (osAttrs ost))
  (pcCA, m4) <- runCommit m3
    (copyReq sid h [(AttrApplication, ValBytes "copy-app")])
  assertEqual "application copy-override" CKR_OK (pcCode pcCA)
  (pcCI, m5) <- runCommit m4 (copyReq sid h [(AttrId, ValBytes "copy-id")])
  assertEqual "id copy-override" CKR_OK (pcCode pcCI)
  (pcSL, m6) <- runCommit m5 (setReq sid h [(AttrLabel, ValBytes "set-label")])
  assertEqual "label set" CKR_OK (pcCode pcSL)
  (pcSA, m7) <- runCommit m6
    (setReq sid h [(AttrApplication, ValBytes "set-app")])
  assertEqual "application set" CKR_OK (pcCode pcSA)
  (pcSI, _) <- runCommit m7 (setReq sid h [(AttrId, ValBytes "set-id")])
  assertEqual "id set" CKR_OK (pcCode pcSI)

-- | The certificate copy guard never fires off-class: non-certificate
-- VALUE-override copies still merge, and non-certificate
-- CLASS-override copies keep their existing merge behavior.
caseCopyScopeRegression :: IO ()
caseCopyScopeRegression = do
  (sid, m0) <- openSession seeded
  (pc, m1) <- runCommit m0
    (createReq sid
      [ (AttrClass, ValULong dataClass)
      , (AttrLabel, ValBytes "src")
      , (AttrValue, ValBytes "v1")
      ])
  h <- commitHandle pc
  (pcC, m2) <- runCommit m1 (copyReq sid h [(AttrValue, ValBytes "v2")])
  assertEqual "value-override copy" CKR_OK (pcCode pcC)
  h2 <- commitHandle pcC
  case resolveHandle m2 h2 of
    Nothing -> assertFailure "value-copy handle lost"
    Just ost -> do
      assertEqual "value merged"
        (Just (ValBytes "v2")) (Map.lookup AttrValue (osAttrs ost))
      assertEqual "label inherited"
        (Just (ValBytes "src")) (Map.lookup AttrLabel (osAttrs ost))
  (pcC2, m3) <- runCommit m2
    (copyReq sid h [(AttrClass, ValULong secretClass)])
  assertEqual "class-override copy keeps merging" CKR_OK (pcCode pcC2)
  h3 <- commitHandle pcC2
  case resolveHandle m3 h3 of
    Nothing -> assertFailure "class-copy handle lost"
    Just ost -> assertEqual "class merged"
      (Just (ValULong secretClass)) (Map.lookup AttrClass (osAttrs ost))

-- | Copy-template precedence: contradictory duplicates refuse;
-- wrong-shape overrides refuse INCONSISTENT before the seal and
-- immutable rules (pinned by message); well-shaped
-- certificate-immutable overrides carry the certificate message.
caseCopyPrecedence :: IO ()
caseCopyPrecedence = do
  (sid, m0) <- openSession seeded
  (pc, m1) <- runCommit m0
    (createReq sid [(AttrClass, ValULong dataClass), (AttrLabel, ValBytes "a")])
  h <- commitHandle pc
  (codeD, _) <- runReject m1
    (copyReq sid h [(AttrLabel, ValBytes "x"), (AttrLabel, ValBytes "y")])
  assertEqual "contradictory duplicates" CKR_TEMPLATE_INCONSISTENT codeD
  (pcS, m2) <- runCommit m1
    (createReq sid
      [ (AttrClass, ValULong dataClass)
      , (AttrSensitive, ValBool True)
      , (AttrValue, ValBytes "s")
      ])
  hS <- commitHandle pcS
  -- Wrong-shape overrides cannot survive the codec seam (values
  -- decode against their owning type's shape), so the shape-order
  -- pins call the planner directly at the typed seam.
  st2 <- sessionOf m2 sid "shape-before-seal session lost"
  case planCopyObject m2 st2 hS
      [(AttrSensitive, ValBool False), (AttrLabel, ValULong 9)] of
    Reject rej -> do
      assertEqual "shape-before-seal code"
        CKR_TEMPLATE_INCONSISTENT (rejCode rej)
      assertEqual "shape before seal"
        ["wrong shape for attribute: AttrLabel"] (rejReasons rej)
    Immediate _ -> assertFailure "wrong-shape copy committed"
    Execute _ _ -> assertFailure "wrong-shape copy reserved execution"
  (pcC, m3) <- runCommit m2 (createReq sid certAttrs)
  hC <- commitHandle pcC
  st3 <- sessionOf m3 sid "shape-before-immutable session lost"
  case planCopyObject m3 st3 hC [(AttrValue, ValBytes "x"), (AttrLabel, ValULong 9)] of
    Reject rej -> do
      assertEqual "shape-before-immutable code"
        CKR_TEMPLATE_INCONSISTENT (rejCode rej)
      assertEqual "shape before immutable"
        ["wrong shape for attribute: AttrLabel"] (rejReasons rej)
    Immediate _ -> assertFailure "wrong-shape copy committed"
    Execute _ _ -> assertFailure "wrong-shape copy reserved execution"
  (rejImm, _) <- runRejectFull m3 (copyReq sid hC [(AttrValue, ValBytes "x")])
  assertEqual "immutable code" CKR_TEMPLATE_INCONSISTENT (rejCode rejImm)
  assertEqual "certificate message"
    ["copy cannot override certificate field: AttrValue"] (rejReasons rejImm)
  -- Mixed-fault precedence: a sensitive certificate copied with
  -- SENSITIVE=false plus a VALUE override reports the seal message,
  -- not the certificate message (seals precede immutability).
  (pcSens, m4) <- runCommit m3
    (createReq sid (certAttrs ++ [(AttrSensitive, ValBool True)]))
  hSens <- commitHandle pcSens
  (rejMix, _) <- runRejectFull m4
    (copyReq sid hSens [(AttrSensitive, ValBool False), (AttrValue, ValBytes "x")])
  assertEqual "mixed-fault code" CKR_TEMPLATE_INCONSISTENT (rejCode rejMix)
  assertEqual "seal before immutable"
    ["copy cannot clear the sensitive flag"] (rejReasons rejMix)

-- | TRUSTED refusals are atomic: a refused mixed USER setter leaves
-- label and TRUSTED intact, and a refused create writes nothing.
caseTrustedAtomicity :: IO ()
caseTrustedAtomicity = do
  (sid, m0) <- openSession seeded
  m1 <- loginAs m0 sid
  (pc, m2) <- runCommit m1
    (createReq sid (certAttrs ++ [(AttrLabel, ValBytes "atom")]))
  h <- commitHandle pc
  (codeS, m3) <- runReject m2
    (setReq sid h [(AttrLabel, ValBytes "moved"), trustedTrue])
  assertEqual "mixed set refused" CKR_ATTRIBUTE_READ_ONLY codeS
  case resolveHandle m3 h of
    Nothing -> assertFailure "atomicity handle lost"
    Just ost -> do
      assertEqual "label intact"
        (Just (ValBytes "atom")) (Map.lookup AttrLabel (osAttrs ost))
      assertEqual "trusted intact"
        Nothing (Map.lookup AttrTrusted (osAttrs ost))
  let counts m = (Map.size (mObjects m), Map.size (mHandles m))
      before = counts m3
  (codeC, m4) <- runReject m3
    (createReq sid (certAttrs ++ [(AttrLabel, ValBytes "doomed"), trustedTrue]))
  assertEqual "refused create" CKR_ATTRIBUTE_READ_ONLY codeC
  assertEqual "no partial state" before (counts m4)

-- | Malformedness precedes the TRUSTED setter gate: contradictory
-- TRUSTED duplicates (either order) and a wrong-shape sibling
-- refuse INCONSISTENT, never READ_ONLY.
caseSetterPrecedence :: IO ()
caseSetterPrecedence = do
  (sid, m0) <- openSession seeded
  m1 <- loginAs m0 sid
  (pc, m2) <- runCommit m1 (createReq sid certAttrs)
  h <- commitHandle pc
  (codeTF, _) <- runReject m2 (setReq sid h [trustedTrue, trustedFalse])
  assertEqual "true-then-false duplicates" CKR_TEMPLATE_INCONSISTENT codeTF
  (codeFT, _) <- runReject m2 (setReq sid h [trustedFalse, trustedTrue])
  assertEqual "false-then-true duplicates" CKR_TEMPLATE_INCONSISTENT codeFT
  -- A wrong-shape sibling cannot survive the codec seam, so this pin
  -- calls the planner directly at the typed seam.
  st <- sessionOf m2 sid "setter-precedence session lost"
  case planSetAttributes m2 st h [trustedTrue, (AttrLabel, ValULong 3)] of
    Reject rej -> assertEqual "wrong-shape sibling"
      CKR_TEMPLATE_INCONSISTENT (rejCode rej)
    Immediate _ -> assertFailure "wrong-shape set committed"
    Execute _ _ -> assertFailure "wrong-shape set reserved execution"

-- | The new attributes carry their shapes: wrong-shape
-- TRUSTED/CATEGORY refuse INCONSISTENT at the typed seam, and
-- overlong date bytes refuse ARGUMENTS_BAD at the codec seam.
caseNewAttrShapes :: IO ()
caseNewAttrShapes = do
  case planCreateObject emptyModel testSession
      [clsCert, (AttrTrusted, ValULong 1)] of
    Reject rej -> assertEqual "trusted wrong shape"
      CKR_TEMPLATE_INCONSISTENT (rejCode rej)
    Immediate _ -> assertFailure "wrong-shape trusted committed"
    Execute _ _ -> assertFailure "wrong-shape trusted reserved execution"
  case planCreateObject emptyModel testSession
      [clsCert, (AttrCertificateCategory, ValBool True)] of
    Reject rej -> assertEqual "category wrong shape"
      CKR_TEMPLATE_INCONSISTENT (rejCode rej)
    Immediate _ -> assertFailure "wrong-shape category committed"
    Execute _ _ -> assertFailure "wrong-shape category reserved execution"
  (sid, m0) <- openSession seeded
  let huge = (AttrStartDate, ValBytes (BS.replicate (maxAttributeBytes + 1) 0))
  (codeH, _) <- runReject m0 (createReq sid (certAttrs ++ [huge]))
  assertEqual "overlong date" CKR_ARGUMENTS_BAD codeH

-- ---------------------------------------------------------------------------
-- T-C04 cases
-- ---------------------------------------------------------------------------

-- | Supplied metadata is opaque: garbage non-DER VALUE plus arbitrary
-- SUBJECT/ISSUER/SERIAL/SPKI/both-hashes commits; every field reads
-- back exactly; find by each supplied field matches.
caseSuppliedOpaque :: IO ()
caseSuppliedOpaque = do
  (sid, m0) <- openSession seeded
  let garbageBytes = BS.pack [0xFF, 0x00, 0xFE, 0x47, 0x41, 0x52, 0x42, 0x41, 0x47, 0x45]
      valGarbage = (AttrValue, ValBytes garbageBytes)
      subjSup = (AttrSubject, ValBytes "supplied-subject-opaque")
      issSup = (AttrIssuer, ValBytes "supplied-issuer-opaque")
      serSup = (AttrSerialNumber, ValBytes "supplied-serial-opaque")
      spkiSup = (AttrPublicKeyInfo, ValBytes "supplied-spki-opaque")
      hSubjSup = (AttrHashOfSubjectPublicKey, ValBytes "supplied-hash-subject")
      hIssSup = (AttrHashOfIssuerPublicKey, ValBytes "supplied-hash-issuer")
      tmpl = [clsCert, typX509, valGarbage, subjSup, issSup, serSup, spkiSup, hSubjSup, hIssSup]
  (pc, m1) <- runCommit m0 (createReq sid tmpl)
  assertEqual "garbage VALUE commits" CKR_OK (pcCode pc)
  h <- commitHandle pc
  case resolveHandle m1 h of
    Nothing -> assertFailure "opaque handle lost"
    Just ost -> do
      assertEqual "VALUE stored verbatim"
        (Just (ValBytes garbageBytes)) (Map.lookup AttrValue (osAttrs ost))
      assertEqual "SUBJECT stored verbatim"
        (Just (ValBytes "supplied-subject-opaque")) (Map.lookup AttrSubject (osAttrs ost))
      assertEqual "ISSUER stored verbatim"
        (Just (ValBytes "supplied-issuer-opaque")) (Map.lookup AttrIssuer (osAttrs ost))
      assertEqual "SERIAL stored verbatim"
        (Just (ValBytes "supplied-serial-opaque")) (Map.lookup AttrSerialNumber (osAttrs ost))
      assertEqual "SPKI stored verbatim"
        (Just (ValBytes "supplied-spki-opaque")) (Map.lookup AttrPublicKeyInfo (osAttrs ost))
      assertEqual "hash-subject stored verbatim"
        (Just (ValBytes "supplied-hash-subject")) (Map.lookup AttrHashOfSubjectPublicKey (osAttrs ost))
      assertEqual "hash-issuer stored verbatim"
        (Just (ValBytes "supplied-hash-issuer")) (Map.lookup AttrHashOfIssuerPublicKey (osAttrs ost))
  let checkFind entry = do
        (pcF, _) <- runCommit m1 (findReq sid [entry])
        found <- findHandles pcF
        assertEqual ("find matches: " ++ show (fst entry)) [h] found
  mapM_ checkFind [valGarbage, subjSup, issSup, serSup, spkiSup, hSubjSup, hIssSup]

-- | No coherence gate: SUBJECT/ISSUER/SERIAL contradicting each other
-- and VALUE still commits; only missing required fields refuse.
caseNoCoherenceGate :: IO ()
caseNoCoherenceGate = do
  (sid, m0) <- openSession seeded
  let valC = (AttrValue, ValBytes "value-says-alice")
      subjC = (AttrSubject, ValBytes "CN=bob-contradicts-value")
      issC = (AttrIssuer, ValBytes "CN=carol-contradicts-both")
      serC = (AttrSerialNumber, ValBytes "serial-999-contradicts-all")
      tmpl = [clsCert, typX509, valC, subjC, issC, serC]
  (pc, _) <- runCommit m0 (createReq sid tmpl)
  assertEqual "contradictory metadata commits" CKR_OK (pcCode pc)
  (codeT, _) <- runReject m0 (createReq sid [clsCert, valC, subjC, issC, serC])
  assertEqual "missing TYPE" CKR_TEMPLATE_INCOMPLETE codeT
  (codeV, _) <- runReject m0 (createReq sid [clsCert, typX509, subjC, issC, serC])
  assertEqual "missing VALUE" CKR_TEMPLATE_INCOMPLETE codeV
  (codeS, _) <- runReject m0 (createReq sid [clsCert, typX509, valC, issC, serC])
  assertEqual "missing SUBJECT" CKR_TEMPLATE_INCOMPLETE codeS

-- ---------------------------------------------------------------------------
-- Fixture block copied verbatim from tests/model/ObjectSpec.hs:218-320
-- (ObjectSpec exports only spec, so the helpers are copied, not imported).
-- ---------------------------------------------------------------------------

slot0 :: SlotId
slot0 = SlotId 0

seeded :: Model
seeded = addToken emptyModel slot0

mkRequest :: FunctionId -> Maybe SessionId -> Request
mkRequest fun mSid = Request
  { reqVersion = Pkcs11_3_2
  , reqFunction = fun
  , reqSession = mSid
  , reqHandle = Nothing
  , reqInput = mempty
  , reqRegions = []
  }

openSession :: Model -> IO (SessionId, Model)
openSession = openSessionOn slot0

openSessionOn :: SlotId -> Model -> IO (SessionId, Model)
openSessionOn (SlotId n) model = do
  let req = (mkRequest F_OpenSession Nothing)
        { reqInput = BC8.pack ("slot=" ++ show n ++ ",rw") }
  case planCall defaultRules model req of
    Immediate pc -> case publishDelta model (pcDelta pc) of
      Left fault -> assertFailure ("open delta fault: " ++ show fault)
      Right m' ->
        let sid = SessionId (mNextSession model)
        in pure (sid, m')
    other -> assertFailure ("open failed: " ++ show other)

createReq :: SessionId -> [(AttributeType, AttributeValue)] -> Request
createReq sid tmpl =
  (mkRequest F_CreateObject (Just sid)) { reqInput = encodeTemplate tmpl }

destroyReq :: SessionId -> ExternalHandle -> Request
destroyReq sid h =
  (mkRequest F_DestroyObject (Just sid)) { reqHandle = Just h }

copyReq :: SessionId -> ExternalHandle -> [(AttributeType, AttributeValue)] -> Request
copyReq sid h tmpl =
  (mkRequest F_CopyObject (Just sid))
    { reqHandle = Just h, reqInput = encodeTemplate tmpl }

findReq :: SessionId -> [(AttributeType, AttributeValue)] -> Request
findReq sid tmpl =
  (mkRequest F_FindObjects (Just sid)) { reqInput = encodeTemplate tmpl }

getReq :: SessionId -> ExternalHandle -> [AttributeType] -> Request
getReq sid h wanted =
  (mkRequest F_GetAttributeValue (Just sid))
    { reqHandle = Just h, reqInput = encodeWanted wanted }

setReq :: SessionId -> ExternalHandle -> [(AttributeType, AttributeValue)] -> Request
setReq sid h tmpl =
  (mkRequest F_SetAttributeValue (Just sid))
    { reqHandle = Just h, reqInput = encodeTemplate tmpl }

loginReq :: SessionId -> Request
loginReq sid = (mkRequest F_Login (Just sid)) { reqInput = "user:ok" }

logoutReq :: SessionId -> Request
logoutReq sid = mkRequest F_Logout (Just sid)

closeReq :: SessionId -> Request
closeReq sid = mkRequest F_CloseSession (Just sid)

loginAs :: Model -> SessionId -> IO Model
loginAs model sid = snd <$> runCommit model (loginReq sid)

-- | Plan and publish an Immediate commit; fail otherwise.
runCommit :: Model -> Request -> IO (PreparedCommit, Model)
runCommit model req =
  case planCall defaultRules model req of
    Immediate pc -> case publishDelta model (pcDelta pc) of
      Left fault -> assertFailure ("delta fault: " ++ show fault)
      Right m' -> pure (pc, m')
    Reject rej -> assertFailure ("expected commit, rejected: " ++ show (rejCode rej))
    Execute _ _ -> assertFailure "expected commit, got Execute"

-- | Plan a rejection; publish its delta and return code + model.
runReject :: Model -> Request -> IO (ReturnCode, Model)
runReject model req = do
  (rej, m') <- runRejectFull model req
  pure (rejCode rej, m')

-- | Plan a rejection; publish its delta and return the full outcome.
runRejectFull :: Model -> Request -> IO (Rejection, Model)
runRejectFull model req =
  case planCall defaultRules model req of
    Reject rej -> case publishDelta model (rejDelta rej) of
      Left fault -> assertFailure ("rejection delta fault: " ++ show fault)
      Right m' -> pure (rej, m')
    Immediate pc -> assertFailure ("expected reject, committed: " ++ show (pcCode pc))
    Execute _ _ -> assertFailure "expected reject, got Execute"

-- | The single handle carried by a create/copy commit's outputs.
commitHandle :: PreparedCommit -> IO ExternalHandle
commitHandle pc = case pcOutputs pc of
  [NativeOutput _ bs] -> case decodeHandle bs of
    Just h -> pure h
    Nothing -> assertFailure "handle output undecodable"
  outs -> assertFailure ("expected one handle output, got: " ++ show outs)

-- ---------------------------------------------------------------------------
-- T-C03 helpers (not part of the verbatim fixture block above)
-- ---------------------------------------------------------------------------

soLoginReq :: SessionId -> Request
soLoginReq sid = (mkRequest F_Login (Just sid)) { reqInput = "so:ok" }

loginAsSO :: Model -> SessionId -> IO Model
loginAsSO model sid = snd <$> runCommit model (soLoginReq sid)

-- | Every handle carried by a find commit's outputs, in order.
findHandles :: PreparedCommit -> IO [ExternalHandle]
findHandles pc = mapM outHandle (pcOutputs pc)
  where
    outHandle (NativeOutput _ bs) = case decodeHandle bs of
      Just h -> pure h
      Nothing -> assertFailure "find handle output undecodable"

-- | The live session state for direct typed-seam planner calls.
sessionOf :: Model -> SessionId -> String -> IO SessionState
sessionOf m sid label = case Map.lookup sid (mSessions m) of
  Just st -> pure st
  Nothing -> assertFailure label
