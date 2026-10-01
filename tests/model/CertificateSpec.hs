{- | Certificate template contract tests (T-C01).

X.509 creation requires certificate type, value, and subject
(presence only: an empty-DER-Name subject is accepted for
SAN-only certificates). Non-X.509 subtype values keep the
generic CLASS+TYPE-only path. Only TemplateIncomplete is
produced by the gate; malformedness outranks incompleteness.
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
  , planCreateObject
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
spec = testGroup "Certificates/T-C01"
  [ testCase "caseCertRequiresTypeValueSubject" caseCertRequiresTypeValueSubject
  , testCase "caseCertEmptySubjectAccepted" caseCertEmptySubjectAccepted
  , testCase "caseCertNonX509Generic" caseCertNonX509Generic
  , testCase "caseCertPrecedenceTyped" caseCertPrecedenceTyped
  , testCase "caseCertPrecedenceCodec" caseCertPrecedenceCodec
  , testCase "caseCertNoPartial" caseCertNoPartial
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
