{- | Object and attribute model tests.

Part 1: mixed attribute read — one outcome carries readable values
plus per-attribute failures under a failing overall code.
Part 2: attribute codecs with bounds.
Part 3: object lifecycle — create validation, destroy flows, copy,
find, and the generation-guarded external-handle map.
Part 4: redaction across adversarial flag mixes and the partial
get-attributes outcome (error plus effects, closing a parked item).
Part 5: token-vs-session visibility per login state, logout
invalidation without resurrection, creator-close destruction.
-}
{-# LANGUAGE OverloadedStrings #-}
module ObjectSpec (spec) where

import qualified Data.Map.Strict as Map
import Data.List (isInfixOf)
import Data.Word (Word32, Word64)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertEqual, assertFailure, testCase)

import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import qualified Data.ByteString.Char8 as BC8
import Test.Tasty.HUnit (assertBool)

import Haskoki.Attribute
  ( AttributeResult (..)
  , AttributeType (..)
  , AttributeValue (..)
  , PartialReads (..)
  , decodeValue
  , encodeValue
  , getAttributes
  , maxAttributeBytes
  )
import Haskoki.Attribute.Generated (mustClassId, mustKeyTypeId)
import Haskoki.Model
  ( HandleBinding (..)
  , Model (..)
  , ObjectState (..)
  , SessionState (..)
  , addToken
  , emptyModel
  , lookupHandle
  , lookupObject
  , lookupSession
  )
import Haskoki.Object
  ( decodeHandle
  , encodeTemplate
  , encodeWanted
  , objectVisible
  , parseTemplate
  , resolveHandle
  )
import Haskoki.Operation (CryptoEffect (..), SlotKind (..), activeSlots)
import Haskoki.Operation.Codec (encodeCancelInput, encodeInitInput, encodeVerifyInput)
import Haskoki.Outcome
  ( BackendFailure (..)
  , DeltaOp (..)
  , EffectRequest (..)
  , EngineResult (..)
  , NativeOutput (..)
  , PlanResult (..)
  , PreparedCommit (..)
  , Rejection (..)
  , Reservation (..)
  , StateDelta (..)
  )
import Haskoki.Registry (MechanismId (..), Operation (..))
import Haskoki.Request (FunctionId (..), OutputIntent (..), OutputRegion (..), Request (..))
import Haskoki.Rules (defaultRules)
import Haskoki.Session (SessionLogin (..))
import Haskoki.Transition (finishEffect, planCall, publishDelta)
import Haskoki.Types
  ( EngineResourceId (..)
  , ExternalHandle (..)
  , Generation (..)
  , ObjectId (..)
  , Pkcs11Version (..)
  , ReturnCode (..)
  , SessionId (..)
  , SlotId (..)
  )

spec :: TestTree
spec = testGroup "objects and attributes"
  [ testCase "mixed read: value plus failures in one outcome" caseMixedRead
  , testCase "codec roundtrip per value shape" caseCodecRoundtrip
  , testCase "codec rejects wrong shapes and overlong input" caseCodecBounds
  , testCase "codec pins unsigned ULong totality" caseCodecNegativeULong
  , testCase "create: success stores template" caseCreateSuccess
  , testCase "create: contradictory duplicates fail without an object" caseCreateContradiction
  , testCase "create: missing class fails without an object" caseCreateIncomplete
  , testCase "create: repeated identical value is not contradictory" caseCreateDuplicateSame
  , testCase "destroy: handle dies once, reuse faults" caseDestroyFlow
  , testCase "generated: bumped binding faults while object lives" caseGenerationGuard
  , testCase "copy: inherits source, overrides template" caseCopyFlow
  , testCase "copy: unsealing overrides rejected, sealed copies stay sealed" caseCopySealRatchet
  , testCase "copy: absent EXTRACTABLE cannot be copied to true" caseCopyExtractableAbsent
  , testCase "create/copy: history attributes in templates refused" caseCreateRefusesHistory
  , testCase "copy: legacy copies materialize the absent flags" caseCopyMaterializesAbsent
  , testCase "copy: tightening keeps never-extractable false" caseCopyTightenKeepsNeverFalse
  , testCase "copy: sensitizing keeps always-sensitive false" caseCopySensitizeKeepsAlwaysFalse
  , testCase "copy: refused copies change nothing" caseRefusedCopyChangesNothing
  , testCase "copy: class/type overrides refused (rsa-private, sensitive)" caseCopyImmutableRsaSensitive
  , testCase "copy: class/type overrides refused (rsa-private, unextractable)" caseCopyImmutableRsaUnextractable
  , testCase "copy: class/type overrides refused (rsa-private, legacy)" caseCopyImmutableRsaLegacy
  , testCase "copy: class/type overrides refused (aes-secret, sensitive)" caseCopyImmutableAesSensitive
  , testCase "copy: class/type overrides refused (aes-secret, unextractable)" caseCopyImmutableAesUnextractable
  , testCase "copy: class/type overrides refused (aes-secret, legacy)" caseCopyImmutableAesLegacy
  , testCase "copy: same-value class/type override still copies" caseCopyNoopClassAndType
  , testCase "copy: value override on sensitive secret refused" caseCopyValueOverrideRefused
  , testCase "copy: RSA component overrides refused" caseCopyRsaComponentRefused
  , testCase "copy: EC component override refused" caseCopyEcComponentRefused
  , testCase "copy: PQC component override refused" caseCopyPqcComponentRefused
  , testCase "copy: EC params relabel refused" caseCopyEcParamsRelabelRefused
  , testCase "copy: TRUSTED forged override refused read-only" caseCopyTrustedForgedRefused
  , testCase "copy: TRUSTED inherited copy refused for non-SO" caseCopyTrustedInheritedRefused
  , testCase "copy: ALWAYS_AUTHENTICATE drop refused" caseCopyAlwaysAuthenticateDropRefused
  , testCase "copy: ALLOWED_MECHANISMS widening refused" caseCopyAllowedMechanismsWidenRefused
  , testCase "copy: DECRYPT added on non-modifiable refused" caseCopyDecryptAddedRefused
  , testCase "copy: non-exempt change on non-modifiable refused" caseCopyNonModifiableRefused
  , testCase "copy: widening ALLOWED_MECHANISMS refused" caseCopyAllowedWidenRefused
  , testCase "copy: exemptions still work on non-modifiable" caseCopyExemptionsStillWork
  , testCase "copy: MODIFIABLE loosen refused, DECRYPT never set" caseCopyModifiableLoosenTwoStepBlocked
  , testCase "copy: token to session succeeds" caseCopyTokenTrueToFalseWorks
  , testCase "copy: DESTROYABLE false to true succeeds" caseCopyDestroyableFalseToTrueWorks
  , testCase "copy: data VALUE on non-modifiable refused" caseCopyDataValueNonModRefused
  , testCase "copy: sealed PRIVATE true to false refused" caseCopySealedPrivateToPublicRefused
  , testCase "copy: MODIFIABLE tighten still works" caseCopyModifiableTightenStillWorks
  , testCase "copy: tightening still works" caseCopyTighteningStillWorks
  , testCase "copy: same-value overrides still work" caseCopySameValueStillWorks
  , testCase "copy: inconsistent NEVER forced false on tighten" caseCopyInconsistentNeverForcedFalse
  , testCase "key defaults: legacy key value seals" caseKeyEffectiveSeal
  , testCase "key defaults: find matches the effective protection" caseKeyEffectiveFind
  , testCase "key defaults: protection ratchets on legacy keys" caseKeyEffectiveRatchets
  , testCase "key defaults: data objects unchanged" caseDataUnchanged
  , testCase "key defaults: public keys stay readable" casePublicKeysStayReadable
  , testCase "key defaults: sealed private components never match" caseRsaPrivateFindWithholds
  , testCase "key defaults: public enforcement follows reported" casePublicEnforcementFollowsReported
  , testCase "key defaults: sealed value find stands alone" caseSealedValueFindStandsAlone
  , testCase "find: template match returns handles" caseFindFlow
  , testCase "find: sealed payloads never match a value guess" caseFindSealedNoOracle
  , testCase "find: contradictory template rejected, nothing bound" caseFindContradiction
  , testCase "routes: malformed object calls are CKR_ARGUMENTS_BAD" caseBadArgs
  , testCase "logout: token-owned private handles die too" caseLogoutTokenPrivate
  , testCase "generated: destroyed handles never resolve or reappear" caseHandleGuard
  , testCase "redaction: adversarial flag mixes never leak" caseRedactionMixes
  , testCase "get-attributes: partial outcome is error plus effects" casePartialOutcome
  , testCase "get-attributes: all readable commits" caseReadAllOk
  , testCase "set-attributes: label change and token promotion" caseSetAttrFlow
  , testCase "set-attributes: ratchets and atomicity" caseSetAttrRatchets
  , testCase "copy: COPYABLE=false prohibits" caseCopyableGate
  , testCase "destroy: DESTROYABLE=false prohibits" caseDestroyableGate
  , testCase "set-attributes: COPYABLE/DESTROYABLE ratchet true->false only" caseCopyDestroyRatchets
  , testCase "create: secret VALUE/VALUE_LEN coherence" caseSecretImportCoherence
  , testCase "create: certificate stores verbatim" caseCertCreate
  , testCase "visibility: private objects follow login state" caseVisibilityLogin
  , testCase "visibility: SO sessions cannot see user private objects" caseVisibilitySOIsolation
  , testCase "logout: private-key operations retire across login transitions" caseLogoutRetiresPrivateOps
  , testCase "logout: destroyed-key staged output retires across logout" caseLogoutRetiresDestroyedKeyStagedOps
  , testCase "isolation: sessions only touch their own slot objects" caseSlotIsolation
  , testCase "logout: private handles die without resurrection" caseLogoutNoResurrection
  , testCase "logout: destruction is scoped to the token" caseLogoutDestructionMatrix
  , testCase "create/copy: SO cannot mint private objects" caseSOCreationAdmission
  , testCase "context grant binds to one key and session" caseContextGrantBinding
  , testCase "context grant survives short buffers and size queries" caseContextGrantSurvivesShortBuffer
  , testCase "cancel of unrelated selection keeps the grant" caseContextCancelKeepsUnrelatedGrant
  , testCase "context lockout performs logout" caseContextLockoutLogsOut
  , testCase "close: creator-close destroys session objects" caseCreatorClose
  , testCase "codec: 65-entry template refused" caseTemplateEntryBound
  , testCase "create: 65-entry template refused loudly" caseCreateEntryBound
  , testCase "storage defaults: absent attributes read the enforced value" caseStorageDefaultsRead
  , testCase "storage defaults: find matches the reported value" caseStorageDefaultsFind
  , testCase "storage defaults: reported values are the enforced ones" caseStorageDefaultsEnforced
  , testCase "storage defaults: never written into the stored map" caseStorageDefaultsNotStored
  , testCase "storage defaults: explicit values win" caseStorageDefaultsExplicitWins
  , testCase "storage defaults: non-storage classes stay unavailable" caseStorageDefaultsNonStorage
  , testCase "storage defaults: failure precedence unchanged" caseStorageDefaultsPrecedence
  , testGroup "role matrix"
    [ testCase "create/copy/set/destroy across role, mode, visibility, lifetime" caseRoleMatrix
    , testCase "public read/write sessions mutate ordinary public token objects" casePublicRwPositive
    , testCase "trusted objects admit only the security officer" caseTrustedSoOnly
    , testCase "find visibility follows login state" caseVisibilityFindCounts
    ]
  ]

-- | A sensitive, unextractable object read for a readable label, its
-- withheld payload, and an absent type: the label value must arrive
-- alongside the failures in ONE outcome with a failing overall code.
caseMixedRead :: IO ()
caseMixedRead = do
  let attrs = Map.fromList
        [ (AttrLabel, ValBytes "greeting")
        , (AttrSensitive, ValBool True)
        , (AttrExtractable, ValBool False)
        , (AttrValue, ValBytes "s3cret")
        ]
      got = getAttributes attrs [AttrLabel, AttrValue, AttrApplication]
  assertEqual "overall code" CKR_ATTRIBUTE_SENSITIVE (prCode got)
  assertEqual "per-attribute results"
    [ (AttrLabel, ResOk (ValBytes "greeting"))
    , (AttrValue, ResSensitive)
    , (AttrApplication, ResUnavailable)
    ]
    (prResults got)

-- | Every value shape survives an encode/decode roundtrip through its
-- owning attribute type.
caseCodecRoundtrip :: IO ()
caseCodecRoundtrip = do
  mapM_ check
    [ (AttrSensitive, ValBool True)
    , (AttrSensitive, ValBool False)
    , (AttrClass, ValULong 0)
    , (AttrClass, ValULong 42)
    , (AttrLabel, ValBytes "greeting")
    , (AttrLabel, ValBytes "")
    ]
  where
    check :: (AttributeType, AttributeValue) -> IO ()
    check (t, v) =
      assertEqual ("roundtrip " ++ show t ++ " " ++ show v)
        (Just v) (decodeValue t (encodeValue v))

-- | Decoding rejects cross-shape bytes (bool where a ULong belongs and
-- vice versa), malformed scalars, and byte arrays past the bound.
caseCodecBounds :: IO ()
caseCodecBounds = do
  assertEqual "bool byte is not a ULong" Nothing
    (decodeValue AttrClass (encodeValue (ValBool True)))
  assertEqual "ULong bytes are not a bool" Nothing
    (decodeValue AttrSensitive (encodeValue (ValULong 1)))
  assertEqual "two bytes are not a bool" Nothing
    (decodeValue AttrSensitive (BS.pack [0, 1]))
  assertEqual "short bytes are not a ULong" Nothing
    (decodeValue AttrClass (BS.pack [1, 2, 3]))
  let huge = BC8.pack (replicate (maxAttributeBytes + 1) 'x')
  assertEqual "overlong bytes rejected" Nothing
    (decodeValue AttrLabel huge)
  assertBool "bound is positive" (maxAttributeBytes > 0)

-- | 'ValULong' is unsigned: the codec is total over the
-- 'Word64' domain. The old wrap-then-reject contract for negatives
-- retired with the 'Int' payload: all-ones bytes are the
-- first-class value 'maxBound', and the old 'Int'-range edges
-- round-trip with the same wire bytes.
caseCodecNegativeULong :: IO ()
caseCodecNegativeULong = do
  assertEqual "maxBound roundtrips" (Just (ValULong maxBound))
    (decodeValue AttrClass (encodeValue (ValULong maxBound)))
  assertEqual "old Int maxBound roundtrips"
    (Just (ValULong (fromIntegral (maxBound :: Int))))
    (decodeValue AttrClass
      (encodeValue (ValULong (fromIntegral (maxBound :: Int)))))
  assertEqual "zero roundtrips" (Just (ValULong 0))
    (decodeValue AttrClass (encodeValue (ValULong 0)))

-- ---------------------------------------------------------------------------
-- Part 3 harness: sessions plus object call helpers
-- ---------------------------------------------------------------------------

-- | The in-process template codec enforces the same 64-entry bound
-- the C packer and FFI frame decode enforce on native paths
-- (previously the 65-entry template decoded here).
caseTemplateEntryBound :: IO ()
caseTemplateEntryBound = do
  let big = replicate 65 (AttrLabel, ValBytes "pad")
      fit = replicate 64 (AttrLabel, ValBytes "pad")
  assertEqual "65 entries refused" Nothing
    (parseTemplate (encodeTemplate big))
  case parseTemplate (encodeTemplate fit) of
    Just tmpl -> assertEqual "64 entries admitted" 64 (length tmpl)
    Nothing -> assertFailure "64-entry template refused"

-- | A 65-entry create template — otherwise valid (class present,
-- padding repeats one identical value, which is not contradictory)
-- — is refused loudly in-process (previously admitted).
caseCreateEntryBound :: IO ()
caseCreateEntryBound = do
  (sid, m) <- openSession seeded
  let big = (AttrClass, ValULong 0)
        : replicate 64 (AttrLabel, ValBytes "pad")
  assertEqual "65 entries built" 65 (length big)
  case planCall defaultRules m (createReq sid big) of
    Reject rej -> assertEqual "refusal code" CKR_ARGUMENTS_BAD (rejCode rej)
    Immediate pc -> assertFailure
      ("65-entry create committed: " ++ show (pcCode pc))
    Execute _ _ -> assertFailure "65-entry create executed"

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
openSessionOn slot model = openSessionMode slot False model

openSessionMode :: SlotId -> Bool -> Model -> IO (SessionId, Model)
openSessionMode (SlotId n) readOnly model = do
  let req = (mkRequest F_OpenSession Nothing)
        { reqInput = BC8.pack ("slot=" ++ show n ++ (if readOnly then ",ro" else ",rw")) }
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

loginAsSo :: Model -> SessionId -> IO Model
loginAsSo model sid = snd <$> runCommit model (soLoginReq sid)

isToken :: Bool -> (AttributeType, AttributeValue)
isToken b = (AttrToken, ValBool b)

isPrivate :: Bool -> (AttributeType, AttributeValue)
isPrivate b = (AttrPrivate, ValBool b)

data MatrixRole = MPublic | MUser | MSO deriving (Eq, Show)
data CellOp = OpCreate | OpCopy | OpSet | OpDestroy deriving (Eq, Show)

data Cell = Cell
  { cellName :: String
  , cellRole :: MatrixRole
  , cellRO :: Bool
  , cellPriv :: Bool
  , cellTok :: Bool
  , cellOp :: CellOp
  , cellWant :: Either ReturnCode ()
  }

loginFor :: MatrixRole -> Model -> SessionId -> IO Model
loginFor MPublic m _ = pure m
loginFor MSO m sid = loginAsSo m sid
-- Unreachable: runCell short-circuits MUser to `pure m5` (it reuses the setup
-- login); a second login would deny and a logout would kill private handles.
loginFor MUser _ _ = error "loginFor MUser unreachable"

-- One table cell. Order matters: setup logs in as user and creates the
-- target. User-role cells REUSE that login (a second login would deny, and
-- a logout would kill private handles); public/SO cells log out first so
-- the test login is the only one (token login is token-global).
runCell :: Cell -> IO ()
runCell c = do
  (sid, m1) <- openSessionMode slot0 (cellRO c) seeded
  (setup, m2) <- openSessionMode slot0 False m1
  m3 <- loginAs m2 setup
  let tmpl = [classData, label "cell", isToken (cellTok c), isPrivate (cellPriv c)]
      srcTmpl = [classData, label "src", isToken False, isPrivate False]
  (h, m4) <- case cellOp c of
    OpCreate -> pure (ExternalHandle 0, m3)
    OpCopy -> do
      (pc, m') <- runCommit m3 (createReq setup srcTmpl)
      h' <- commitHandle pc
      pure (h', m')
    _ -> do
      (pc, m') <- runCommit m3 (createReq setup tmpl)
      h' <- commitHandle pc
      pure (h', m')
  m5 <- if cellRole c == MUser then pure m4 else snd <$> runCommit m4 (logoutReq setup)
  m6 <- case cellRole c of
    MUser -> pure m5
    r -> loginFor r m5 sid
  let req = case cellOp c of
        OpCreate -> createReq sid tmpl
        OpCopy -> copyReq sid h [label "copy", isToken (cellTok c), isPrivate (cellPriv c)]
        OpSet -> setReq sid h [label "set"]
        OpDestroy -> destroyReq sid h
  case cellWant c of
    Right () -> do
      (pc, _) <- runCommit m6 req
      assertEqual (cellName c) CKR_OK (pcCode pc)
    Left want -> do
      (code, m') <- runReject m6 req
      assertEqual (cellName c) want code
      -- A refused set proves nothing by itself: read the label back
      -- to show the refusal changed nothing (cell 29 is the only
      -- set-refusal cell).
      if cellOp c == OpSet
        then do
          (pcG, _) <- runCommit m' (getReq sid h [AttrLabel])
          assertEqual (cellName c ++ ": refused set changes nothing")
            [encodeValue (ValBytes "cell")] [outBytes o | o <- pcOutputs pcG]
        else pure ()

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

-- | Plan an Execute step; fail otherwise. Returns the reservation and
-- effect for 'finishEffect'.
runExecute :: Model -> Request -> IO (Reservation, EffectRequest)
runExecute model req =
  case planCall defaultRules model req of
    Execute res eff -> pure (res, eff)
    Reject rej -> assertFailure ("expected execute, rejected: " ++ show (rejCode rej))
    Immediate pc -> assertFailure ("expected execute, committed: " ++ show (pcCode pc))

-- | One crypto data call with a single byte output region.
dataReq :: FunctionId -> SessionId -> String -> ByteString -> Int -> Request
dataReq fid sid name blob cap =
  (mkRequest fid (Just sid))
    { reqInput = blob
    , reqRegions = [RegionBytes name (IntentBuffer (fromIntegral cap))]
    }

-- | The single handle carried by a create/copy commit's outputs.
commitHandle :: PreparedCommit -> IO ExternalHandle
commitHandle pc = case pcOutputs pc of
  [NativeOutput _ bs] -> case decodeHandle bs of
    Just h -> pure h
    Nothing -> assertFailure "handle output undecodable"
  outs -> assertFailure ("expected one handle output, got: " ++ show outs)

-- | Every handle carried by a find commit's outputs, in order.
findHandles :: PreparedCommit -> IO [ExternalHandle]
findHandles pc = mapM outHandle (pcOutputs pc)
  where
    outHandle (NativeOutput _ bs) = case decodeHandle bs of
      Just h -> pure h
      Nothing -> assertFailure "find handle output undecodable"

classData :: (AttributeType, AttributeValue)
classData = (AttrClass, ValULong 0)

label :: ByteString -> (AttributeType, AttributeValue)
label s = (AttrLabel, ValBytes s)

-- ---------------------------------------------------------------------------
-- Part 3 cases
-- ---------------------------------------------------------------------------

caseCreateSuccess :: IO ()
caseCreateSuccess = do
  (sid, m1) <- openSession seeded
  let tmpl = [classData, label "a"]
  (pc, m2) <- runCommit m1 (createReq sid tmpl)
  assertEqual "code" CKR_OK (pcCode pc)
  h <- commitHandle pc
  case resolveHandle m2 h of
    Nothing -> assertFailure "created handle does not resolve"
    Just ost -> do
      assertEqual "stored attrs" (Map.fromList tmpl) (osAttrs ost)
      assertEqual "session-owned" (Just sid) (osOwner ost)
      assertEqual "slot" slot0 (osSlot ost)

caseCreateContradiction :: IO ()
caseCreateContradiction = do
  (sid, m1) <- openSession seeded
  let tmpl = [classData, label "a", label "b"]
  (code, m2) <- runReject m1 (createReq sid tmpl)
  assertEqual "code" CKR_TEMPLATE_INCONSISTENT code
  assertEqual "no partial object" 0 (Map.size (mObjects m2))
  assertEqual "no binding" 0 (Map.size (mHandles m2))

caseCreateIncomplete :: IO ()
caseCreateIncomplete = do
  (sid, m1) <- openSession seeded
  (code, m2) <- runReject m1 (createReq sid [label "a"])
  assertEqual "code" CKR_TEMPLATE_INCOMPLETE code
  assertEqual "no partial object" 0 (Map.size (mObjects m2))

caseCreateDuplicateSame :: IO ()
caseCreateDuplicateSame = do
  (sid, m1) <- openSession seeded
  let tmpl = [classData, label "a", label "a"]
  (pc, m2) <- runCommit m1 (createReq sid tmpl)
  assertEqual "code" CKR_OK (pcCode pc)
  h <- commitHandle pc
  case resolveHandle m2 h of
    Nothing -> assertFailure "created handle does not resolve"
    Just ost ->
      assertEqual "deduped attrs"
        (Map.fromList [classData, label "a"]) (osAttrs ost)

caseDestroyFlow :: IO ()
caseDestroyFlow = do
  (sid, m1) <- openSession seeded
  (pc, m2) <- runCommit m1 (createReq sid [classData, label "gone"])
  h <- commitHandle pc
  (pcD, m3) <- runCommit m2 (destroyReq sid h)
  assertEqual "destroy code" CKR_OK (pcCode pcD)
  assertEqual "object gone" Nothing (resolveHandle m3 h)
  case lookupHandle m3 h of
    Nothing -> assertFailure "binding must be retained stale, not deleted"
    Just b -> assertBool "generation bumped on destroy" (hbGeneration b /= Generation 1)
  (code, m4) <- runReject m3 (destroyReq sid h)
  assertEqual "reuse faults" CKR_OBJECT_HANDLE_INVALID code
  assertEqual "still no object" Nothing (resolveHandle m4 h)

-- | Direct generation-guard unit test: a live binding plus a
-- 'DeltaBumpHandle' faults 'resolveHandle' while the object itself
-- stays alive and untouched.
caseGenerationGuard :: IO ()
caseGenerationGuard = do
  (sid, m1) <- openSession seeded
  (pc, m2) <- runCommit m1 (createReq sid [classData, label "bumped"])
  h <- commitHandle pc
  ost0 <- case resolveHandle m2 h of
    Nothing -> assertFailure "setup handle lost"
    Just ost -> pure ost
  m3 <- case publishDelta m2 (StateDelta [DeltaBumpHandle h]) of
    Left fault -> assertFailure ("bump fault: " ++ show fault)
    Right m' -> pure m'
  assertEqual "bumped binding no longer resolves" Nothing (resolveHandle m3 h)
  case lookupObject m3 (osId ost0) of
    Nothing -> assertFailure "object must survive the bump"
    Just ost1 -> assertEqual "object itself untouched" (osAttrs ost0) (osAttrs ost1)

caseCopyFlow :: IO ()
caseCopyFlow = do
  (sid, m1) <- openSession seeded
  (pc, m2) <- runCommit m1 (createReq sid [classData, label "orig"])
  h <- commitHandle pc
  (pcC, m3) <- runCommit m2 (copyReq sid h [label "copy"])
  assertEqual "copy code" CKR_OK (pcCode pcC)
  h2 <- commitHandle pcC
  assertBool "fresh handle" (h2 /= h)
  case (resolveHandle m3 h, resolveHandle m3 h2) of
    (Just src, Just dst) -> do
      assertEqual "source kept" (Just (ValBytes "orig"))
        (Map.lookup AttrLabel (osAttrs src))
      assertEqual "class inherited" (Just (ValULong 0))
        (Map.lookup AttrClass (osAttrs dst))
      assertEqual "label overridden" (Just (ValBytes "copy"))
        (Map.lookup AttrLabel (osAttrs dst))
    _ -> assertFailure "source and copy must both resolve"
  let nBefore = Map.size (mObjects m3)
  (code, m4) <- runReject m3 (copyReq sid h [label "x", label "y"])
  assertEqual "contradictory copy" CKR_TEMPLATE_INCONSISTENT code
  assertEqual "no copy created" nBefore (Map.size (mObjects m4))

-- | Seal ratchet on copy: overrides that flip sensitive true->false
-- or extractable false->true are rejected (no copy created), and a
-- plain copy of a sealed object stays sealed (its payload still
-- redacts on read).
caseCopySealRatchet :: IO ()
caseCopySealRatchet = do
  (sid, m1) <- openSession seeded
  (pc, m2) <- runCommit m1
    (createReq sid
      [ classData
      , (AttrSensitive, ValBool True)
      , (AttrExtractable, ValBool False)
      , (AttrValue, ValBytes "s3cret")
      ])
  h <- commitHandle pc
  let nBefore = Map.size (mObjects m2)
  (code, m3) <- runReject m2
    (copyReq sid h [(AttrSensitive, ValBool False), (AttrExtractable, ValBool True)])
  assertEqual "unsealing copy rejected" CKR_ATTRIBUTE_READ_ONLY code
  assertEqual "no unsealed copy created" nBefore (Map.size (mObjects m3))
  (codeS, m4) <- runReject m3
    (copyReq sid h [(AttrSensitive, ValBool False)])
  assertEqual "sensitive-only unseal rejected" CKR_ATTRIBUTE_READ_ONLY codeS
  (codeE, m5) <- runReject m4
    (copyReq sid h [(AttrExtractable, ValBool True)])
  assertEqual "extractable-only unseal rejected" CKR_ATTRIBUTE_READ_ONLY codeE
  assertEqual "still no copy created" nBefore (Map.size (mObjects m5))
  (pcC, m6) <- runCommit m5 (copyReq sid h [])
  h2 <- commitHandle pcC
  assertBool "sealed copy is a fresh handle" (h2 /= h)
  (rej, _) <- runRejectFull m6 (getReq sid h2 [AttrValue])
  assertEqual "copy of sealed still redacts" CKR_ATTRIBUTE_SENSITIVE (rejCode rej)
  assertEqual "no payload bytes escape" [] (rejOutputs rej)

-- | A key without CKA_EXTRACTABLE is not wrappable, and a copy may
-- not make it so: a copy template that sets EXTRACTABLE=true is
-- refused unless the source is explicitly extractable. Tightening
-- (EXTRACTABLE=false) and plain copies still pass.
caseCopyExtractableAbsent :: IO ()
caseCopyExtractableAbsent = do
  (sid, m0) <- openSession seeded
  let sealedKey = secretAes (BS.replicate 16 9) ++ [(AttrSensitive, ValBool True)]
  (pc, m1) <- runCommit m0 (createReq sid sealedKey)
  h <- commitHandle pc
  let nBefore = Map.size (mObjects m1)
  (code, m2) <- runReject m1 (copyReq sid h [(AttrExtractable, ValBool True)])
  assertEqual "absent EXTRACTABLE cannot be copied to true"
    CKR_ATTRIBUTE_READ_ONLY code
  assertEqual "no extractable copy created" nBefore (Map.size (mObjects m2))
  (pcF, m3) <- runCommit m2 (copyReq sid h [(AttrExtractable, ValBool False)])
  assertEqual "copy may tighten to EXTRACTABLE=false" CKR_OK (pcCode pcF)
  (pcP, m4) <- runCommit m3 (copyReq sid h [])
  assertEqual "plain copy still allowed" CKR_OK (pcCode pcP)
  (pcE, m5) <- runCommit m4
    (createReq sid (secretAes (BS.replicate 16 3) ++ [(AttrExtractable, ValBool True)]))
  he <- commitHandle pcE
  (pcT, _) <- runCommit m5 (copyReq sid he [(AttrExtractable, ValBool True)])
  assertEqual "explicitly extractable source copies as extractable" CKR_OK (pcCode pcT)

-- | Caller templates may not carry history attributes: creation
-- refuses inconsistent, and a copy override naming one refuses
-- read-only (the set path's code). Both leave the count unchanged.
caseCreateRefusesHistory :: IO ()
caseCreateRefusesHistory = do
  (sid, m0) <- openSession seeded
  let nBefore = Map.size (mObjects m0)
  (code, m1) <- runReject m0
    (createReq sid (secretAes (BS.replicate 16 7) ++ [(AttrLocal, ValBool True)]))
  assertEqual "history create refused" CKR_TEMPLATE_INCONSISTENT code
  assertEqual "no history object created" nBefore (Map.size (mObjects m1))
  (pc, m2) <- runCommit m1 (createReq sid (secretAes (BS.replicate 16 3)))
  h <- commitHandle pc
  let nBeforeCopy = Map.size (mObjects m2)
  (codeC, m3) <- runReject m2 (copyReq sid h [(AttrNeverExtractable, ValBool False)])
  assertEqual "history copy override refused" CKR_ATTRIBUTE_READ_ONLY codeC
  assertEqual "no history copy created" nBeforeCopy (Map.size (mObjects m3))

-- | Copying a legacy key materializes the absent protection flags:
-- the copy stores the source-effective values for all six key
-- attributes, so the absent population only shrinks.
caseCopyMaterializesAbsent :: IO ()
caseCopyMaterializesAbsent = do
  (sid, m0) <- openSession seeded
  (pc, m1) <- runCommit m0 (createReq sid (secretAes (BS.replicate 16 7)))
  h <- commitHandle pc
  (pcC, m2) <- runCommit m1 (copyReq sid h [])
  h2 <- commitHandle pcC
  dst <- case resolveHandle m2 h2 of
    Nothing -> assertFailure "materialized copy resolves"
    Just ost -> pure (osAttrs ost)
  mapM_ (\(t, v) -> assertEqual ("materialized " ++ show t)
    (Just v) (Map.lookup t dst))
    [ (AttrSensitive, ValBool False)
    , (AttrExtractable, ValBool False)
    , (AttrAlwaysSensitive, ValBool False)
    , (AttrNeverExtractable, ValBool False)
    , (AttrLocal, ValBool False)
    , (AttrKeyGenMechanism, ValULong maxBound)
    ]

-- | A copy that tightens EXTRACTABLE true->false stores the flip
-- with NEVER_EXTRACTABLE false: the key was extractable once, so
-- no false never-extracted assurance survives the tightening.
caseCopyTightenKeepsNeverFalse :: IO ()
caseCopyTightenKeepsNeverFalse = do
  (sid, m0) <- openSession seeded
  (pc, m1) <- runCommit m0
    (createReq sid (secretAes (BS.replicate 16 7) ++ [(AttrExtractable, ValBool True)]))
  h <- commitHandle pc
  (pc1, m2) <- runCommit m1 (copyReq sid h [])
  h1 <- commitHandle pc1
  mid <- case resolveHandle m2 h1 of
    Nothing -> assertFailure "intermediate copy resolves"
    Just ost -> pure (osAttrs ost)
  assertEqual "intermediate keeps true" (Just (ValBool True))
    (Map.lookup AttrExtractable mid)
  assertEqual "intermediate never-extractable" (Just (ValBool False))
    (Map.lookup AttrNeverExtractable mid)
  (pc2, m3) <- runCommit m2 (copyReq sid h1 [(AttrExtractable, ValBool False)])
  h2 <- commitHandle pc2
  dst <- case resolveHandle m3 h2 of
    Nothing -> assertFailure "tightened copy resolves"
    Just ost -> pure (osAttrs ost)
  assertEqual "tightened extractable" (Just (ValBool False))
    (Map.lookup AttrExtractable dst)
  assertEqual "tightened never-extractable" (Just (ValBool False))
    (Map.lookup AttrNeverExtractable dst)

-- | A copy that sensitizes keeps ALWAYS_SENSITIVE false: the copy
-- inherits the source history, and the materialized source was
-- born open.
caseCopySensitizeKeepsAlwaysFalse :: IO ()
caseCopySensitizeKeepsAlwaysFalse = do
  (sid, m0) <- openSession seeded
  (pc, m1) <- runCommit m0 (createReq sid (secretAes (BS.replicate 16 7)))
  h <- commitHandle pc
  (pc1, m2) <- runCommit m1 (copyReq sid h [])
  h1 <- commitHandle pc1
  mid <- case resolveHandle m2 h1 of
    Nothing -> assertFailure "intermediate copy resolves"
    Just ost -> pure (osAttrs ost)
  assertEqual "intermediate always-sensitive" (Just (ValBool False))
    (Map.lookup AttrAlwaysSensitive mid)
  (pc2, m3) <- runCommit m2 (copyReq sid h1 [(AttrSensitive, ValBool True)])
  h2 <- commitHandle pc2
  dst <- case resolveHandle m3 h2 of
    Nothing -> assertFailure "sensitized copy resolves"
    Just ost -> pure (osAttrs ost)
  assertEqual "sensitized sensitive" (Just (ValBool True))
    (Map.lookup AttrSensitive dst)
  assertEqual "sensitized always-sensitive" (Just (ValBool False))
    (Map.lookup AttrAlwaysSensitive dst)

-- | A refused copy changes nothing: the rejection carries an empty
-- delta, the source map is identical afterwards, and the object
-- count is unchanged.
caseRefusedCopyChangesNothing :: IO ()
caseRefusedCopyChangesNothing = do
  (sid, m0) <- openSession seeded
  let tmpl = secretAes (BS.replicate 16 9) ++ [(AttrSensitive, ValBool True)]
  (pc, m1) <- runCommit m0 (createReq sid tmpl)
  h <- commitHandle pc
  srcBefore <- case resolveHandle m1 h of
    Nothing -> assertFailure "source resolves before the refused copy"
    Just ost -> pure (osAttrs ost)
  let nBefore = Map.size (mObjects m1)
  (rej, m2) <- runRejectFull m1 (copyReq sid h [(AttrExtractable, ValBool True)])
  assertEqual "unsealing copy refused" CKR_ATTRIBUTE_READ_ONLY (rejCode rej)
  assertEqual "empty delta" (StateDelta []) (rejDelta rej)
  assertEqual "no copy created" nBefore (Map.size (mObjects m2))
  srcAfter <- case resolveHandle m2 h of
    Nothing -> assertFailure "source resolves after the refused copy"
    Just ost -> pure (osAttrs ost)
  assertEqual "source map unchanged" srcBefore srcAfter

-- | One immutable-override refusal leg: copying the source with the
-- given class or key-type override is refused read-only (the set
-- path's code for these immutable attributes), with no handle
-- emitted, an empty delta, and the store unchanged.
copyImmutableRefused
  :: String -> [(AttributeType, AttributeValue)]
  -> (AttributeType, AttributeValue) -> IO ()
copyImmutableRefused name src over = do
  (sid, m0) <- openSession seeded
  (pc, m1) <- runCommit m0 (createReq sid src)
  h <- commitHandle pc
  let nObjs = Map.size (mObjects m1)
      nHandles = Map.size (mHandles m1)
  (rej, m2) <- runRejectFull m1 (copyReq sid h [over])
  assertEqual ("refused: " ++ name) CKR_ATTRIBUTE_READ_ONLY (rejCode rej)
  assertEqual ("no handle emitted: " ++ name) [] (rejOutputs rej)
  assertEqual ("empty delta: " ++ name) (StateDelta []) (rejDelta rej)
  assertEqual ("object count unchanged: " ++ name) nObjs (Map.size (mObjects m2))
  assertEqual ("handle count unchanged: " ++ name) nHandles (Map.size (mHandles m2))

-- | The three immutable overrides for one source: a public-key
-- class, a data class, and a changed key type.
copyImmutableMatrix :: String -> [(AttributeType, AttributeValue)] -> Word64 -> IO ()
copyImmutableMatrix name src changedType = mapM_
  (\(ovName, over) -> copyImmutableRefused (name ++ "+" ++ ovName) src over)
  [ ("class-public", (AttrClass, ValULong (mustClassId "CKO_PUBLIC_KEY")))
  , ("class-data", (AttrClass, ValULong (mustClassId "CKO_DATA")))
  , ("changed-type", (AttrKeyType, ValULong changedType))
  ]

-- | A sealed RSA private key (stored sensitive) copied with a
-- changed class or key type is refused read-only.
caseCopyImmutableRsaSensitive :: IO ()
caseCopyImmutableRsaSensitive =
  copyImmutableMatrix "rsa-private/sensitive"
    (privateRsaLegacy ++ [(AttrSensitive, ValBool True), (AttrExtractable, ValBool True)])
    (mustKeyTypeId "CKK_EC")

-- | A sealed RSA private key (stored unextractable) copied with a
-- changed class or key type is refused read-only.
caseCopyImmutableRsaUnextractable :: IO ()
caseCopyImmutableRsaUnextractable =
  copyImmutableMatrix "rsa-private/unextractable"
    (privateRsaLegacy ++ [(AttrSensitive, ValBool False), (AttrExtractable, ValBool False)])
    (mustKeyTypeId "CKK_EC")

-- | A flag-less RSA private key (sealed by the defaults) copied
-- with a changed class or key type is refused read-only.
caseCopyImmutableRsaLegacy :: IO ()
caseCopyImmutableRsaLegacy =
  copyImmutableMatrix "rsa-private/legacy"
    privateRsaLegacy
    (mustKeyTypeId "CKK_EC")

-- | A sealed AES key (stored sensitive) copied with a changed class
-- or key type is refused read-only.
caseCopyImmutableAesSensitive :: IO ()
caseCopyImmutableAesSensitive =
  copyImmutableMatrix "aes-secret/sensitive"
    (secretAes (BS.replicate 16 7) ++ [(AttrSensitive, ValBool True), (AttrExtractable, ValBool True)])
    (mustKeyTypeId "CKK_GENERIC_SECRET")

-- | A sealed AES key (stored unextractable) copied with a changed
-- class or key type is refused read-only.
caseCopyImmutableAesUnextractable :: IO ()
caseCopyImmutableAesUnextractable =
  copyImmutableMatrix "aes-secret/unextractable"
    (secretAes (BS.replicate 16 7) ++ [(AttrSensitive, ValBool False), (AttrExtractable, ValBool False)])
    (mustKeyTypeId "CKK_GENERIC_SECRET")

-- | A flag-less AES key (sealed by the defaults) copied with a
-- changed class or key type is refused read-only.
caseCopyImmutableAesLegacy :: IO ()
caseCopyImmutableAesLegacy =
  copyImmutableMatrix "aes-secret/legacy"
    (secretAes (BS.replicate 16 7))
    (mustKeyTypeId "CKK_GENERIC_SECRET")

-- | A no-op same-value class and key-type override still copies:
-- only a changed value is refused. Both sources keep their class
-- on the copy.
caseCopyNoopClassAndType :: IO ()
caseCopyNoopClassAndType = mapM_ noopLeg
  [ ("rsa-private", privateRsaLegacy, "CKO_PRIVATE_KEY", "CKK_RSA")
  , ("aes-secret", secretAes (BS.replicate 16 7), "CKO_SECRET_KEY", "CKK_AES")
  ]
  where
    noopLeg (name, src, cls, kty) = do
      (sid, m0) <- openSession seeded
      (pc, m1) <- runCommit m0 (createReq sid src)
      h <- commitHandle pc
      (pcC, m2) <- runCommit m1 (copyReq sid h
        [ (AttrClass, ValULong (mustClassId cls))
        , (AttrKeyType, ValULong (mustKeyTypeId kty))
        ])
      assertEqual ("no-op override copies: " ++ name) CKR_OK (pcCode pcC)
      h2 <- commitHandle pcC
      assertBool ("no-op copy is a fresh handle: " ++ name) (h2 /= h)
      case (resolveHandle m2 h, resolveHandle m2 h2) of
        (Just srcOst, Just dstOst) ->
          assertEqual ("no-op copy keeps the class: " ++ name)
            (Map.lookup AttrClass (osAttrs srcOst))
            (Map.lookup AttrClass (osAttrs dstOst))
        _ -> assertFailure ("no-op copy handles lost: " ++ name)

-- | One copy-policy refusal leg: the copy is refused read-only (the
-- set path's code), with no handle emitted, an empty delta, and the
-- store unchanged.
copyPolicyRefused
  :: String -> [(AttributeType, AttributeValue)]
  -> [(AttributeType, AttributeValue)] -> IO ()
copyPolicyRefused name src over = do
  (sid, m0) <- openSession seeded
  (pc, m1) <- runCommit m0 (createReq sid src)
  h <- commitHandle pc
  let nObjs = Map.size (mObjects m1)
      nHandles = Map.size (mHandles m1)
  (rej, m2) <- runRejectFull m1 (copyReq sid h over)
  assertEqual ("refused: " ++ name) CKR_ATTRIBUTE_READ_ONLY (rejCode rej)
  assertEqual ("no handle emitted: " ++ name) [] (rejOutputs rej)
  assertEqual ("empty delta: " ++ name) (StateDelta []) (rejDelta rej)
  assertEqual ("object count unchanged: " ++ name) nObjs (Map.size (mObjects m2))
  assertEqual ("handle count unchanged: " ++ name) nHandles (Map.size (mHandles m2))

-- | P-256 and P-384 EC_PARAMS DER blobs (the wire OIDs).
ecParamsP256b, ecParamsP384b :: ByteString
ecParamsP256b = BS.pack [0x06,0x08,0x2A,0x86,0x48,0xCE,0x3D,0x03,0x01,0x07]
ecParamsP384b = BS.pack [0x06,0x05,0x2B,0x81,0x04,0x00,0x22]

-- | A minimal EC private-key template: class, key type, P-256 params,
-- a 32-byte scalar, and the session mark.
ecPrivLegacy :: [(AttributeType, AttributeValue)]
ecPrivLegacy =
  [ (AttrClass, ValULong (mustClassId "CKO_PRIVATE_KEY"))
  , (AttrKeyType, ValULong (mustKeyTypeId "CKK_EC"))
  , (AttrToken, ValBool False)
  , (AttrEcParams, ValBytes ecParamsP256b)
  , (AttrValue, ValBytes (BS.replicate 32 0x07))
  ]

-- | Publish a bare storage row plus its handle, bypassing creation
-- validation (for sources the public API cannot build: PQC fixtures
-- without driver vectors, inconsistent history rows).
publishBare
  :: Model -> SessionId -> [(AttributeType, AttributeValue)]
  -> IO (ExternalHandle, Model)
publishBare m sid attrs = do
  let oid = ObjectId (mNextObject m)
      h = ExternalHandle (mNextHandle m)
      delta = StateDelta
        [ DeltaCreateObjectFull oid (Map.fromList attrs) (Just sid) slot0
        , DeltaBindHandle h oid
        ]
  case publishDelta m delta of
    Left fault -> assertFailure ("bare publish fault: " ++ show fault)
    Right m' -> pure (h, m')

-- | A bare ML-DSA private row: class, key type, value, seed,
-- parameter set, and the session mark. No import validation runs.
mldsaBare :: [(AttributeType, AttributeValue)]
mldsaBare =
  [ (AttrClass, ValULong (mustClassId "CKO_PRIVATE_KEY"))
  , (AttrKeyType, ValULong (mustKeyTypeId "CKK_ML_DSA"))
  , (AttrToken, ValBool False)
  , (AttrValue, ValBytes (BS.replicate 64 0x11))
  , (AttrSeed, ValBytes (BS.replicate 32 0x22))
  , (AttrParameterSet, ValULong 44)
  , (AttrSensitive, ValBool True)
  , (AttrExtractable, ValBool False)
  ]

-- | A sensitive AES key copied with a changed CKA_VALUE (same length,
-- so no length conflict) is refused read-only.
caseCopyValueOverrideRefused :: IO ()
caseCopyValueOverrideRefused =
  copyPolicyRefused "aes-sensitive/value"
    (secretAes (BS.replicate 16 7)
      ++ [(AttrSensitive, ValBool True), (AttrExtractable, ValBool True)])
    [(AttrValue, ValBytes (BS.replicate 16 9))]

-- | An RSA private key copied with a changed private exponent or a
-- changed modulus is refused read-only.
caseCopyRsaComponentRefused :: IO ()
caseCopyRsaComponentRefused = do
  copyPolicyRefused "rsa-private/privexp"
    (privateRsaLegacy ++ [(AttrSensitive, ValBool True)])
    [(AttrPrivateExponent, ValBytes "forged-privexp")]
  copyPolicyRefused "rsa-private/modulus"
    (privateRsaLegacy ++ [(AttrSensitive, ValBool True)])
    [(AttrModulus, ValBytes "forged-modulus")]

-- | An EC private key copied with a changed CKA_VALUE is refused
-- read-only.
caseCopyEcComponentRefused :: IO ()
caseCopyEcComponentRefused =
  copyPolicyRefused "ec-private/value"
    (ecPrivLegacy ++ [(AttrSensitive, ValBool True)])
    [(AttrValue, ValBytes (BS.replicate 32 0x09))]

-- | A PQC private key copied with a changed CKA_SEED is refused
-- read-only.
caseCopyPqcComponentRefused :: IO ()
caseCopyPqcComponentRefused = do
  (sid, m0) <- openSession seeded
  (h, m1) <- publishBare m0 sid mldsaBare
  let nObjs = Map.size (mObjects m1)
      nHandles = Map.size (mHandles m1)
  (rej, m2) <- runRejectFull m1
    (copyReq sid h [(AttrSeed, ValBytes (BS.replicate 32 0x33))])
  assertEqual "refused: mldsa/seed" CKR_ATTRIBUTE_READ_ONLY (rejCode rej)
  assertEqual "no handle emitted: mldsa/seed" [] (rejOutputs rej)
  assertEqual "empty delta: mldsa/seed" (StateDelta []) (rejDelta rej)
  assertEqual "object count unchanged: mldsa/seed" nObjs (Map.size (mObjects m2))
  assertEqual "handle count unchanged: mldsa/seed" nHandles (Map.size (mHandles m2))

-- | An EC private key copied with relabelled EC_PARAMS (P-256 to
-- P-384) is refused read-only.
caseCopyEcParamsRelabelRefused :: IO ()
caseCopyEcParamsRelabelRefused =
  copyPolicyRefused "ec-private/params"
    (ecPrivLegacy ++ [(AttrSensitive, ValBool True)])
    [(AttrEcParams, ValBytes ecParamsP384b)]

-- | A key copied with a forged TRUSTED=true by a non-SO user is
-- refused with the set path's read-only code.
caseCopyTrustedForgedRefused :: IO ()
caseCopyTrustedForgedRefused = do
  (sid, m0) <- openSession seeded
  m1 <- loginAs m0 sid
  (pc, m2) <- runCommit m1 (createReq sid (secretAes (BS.replicate 16 7)))
  h <- commitHandle pc
  let nObjs = Map.size (mObjects m2)
      nHandles = Map.size (mHandles m2)
  (rej, m3) <- runRejectFull m2
    (copyReq sid h [(AttrTrusted, ValBool True)])
  assertEqual "refused: trusted-forged" CKR_ATTRIBUTE_READ_ONLY (rejCode rej)
  assertEqual "no handle emitted: trusted-forged" [] (rejOutputs rej)
  assertEqual "empty delta: trusted-forged" (StateDelta []) (rejDelta rej)
  assertEqual "object count unchanged: trusted-forged" nObjs (Map.size (mObjects m3))
  assertEqual "handle count unchanged: trusted-forged" nHandles (Map.size (mHandles m3))

-- | A TRUSTED source copied with an empty template by a non-SO user
-- is refused read-only: the copy would otherwise inherit TRUSTED.
caseCopyTrustedInheritedRefused :: IO ()
caseCopyTrustedInheritedRefused = do
  (sid, m0) <- openSession seeded
  mSO <- snd <$> runCommit m0 (soLoginReq sid)
  (pc, m1) <- runCommit mSO
    (createReq sid [classData, label "trusted-src", (AttrTrusted, ValBool True)])
  h <- commitHandle pc
  let mU = m1
        { mSessions = Map.adjust (\st -> st { ssLogin = LoginUser }) sid (mSessions m1) }
      nObjs = Map.size (mObjects mU)
      nHandles = Map.size (mHandles mU)
  (rej, m2) <- runRejectFull mU (copyReq sid h [])
  assertEqual "refused: trusted-inherited" CKR_ATTRIBUTE_READ_ONLY (rejCode rej)
  assertEqual "no handle emitted: trusted-inherited" [] (rejOutputs rej)
  assertEqual "empty delta: trusted-inherited" (StateDelta []) (rejDelta rej)
  assertEqual "object count unchanged: trusted-inherited" nObjs (Map.size (mObjects m2))
  assertEqual "handle count unchanged: trusted-inherited" nHandles (Map.size (mHandles m2))

-- | A signing key with ALWAYS_AUTHENTICATE=TRUE copied with FALSE is
-- refused read-only.
caseCopyAlwaysAuthenticateDropRefused :: IO ()
caseCopyAlwaysAuthenticateDropRefused =
  copyPolicyRefused "rsa-private/always-auth"
    (privateRsaLegacy
      ++ [(AttrAlwaysAuthenticate, ValBool True), (AttrSign, ValBool True)])
    [(AttrAlwaysAuthenticate, ValBool False)]

-- | A key whose ALLOWED_MECHANISMS lists one mechanism, copied with a
-- widened two-mechanism list, is refused read-only.
caseCopyAllowedMechanismsWidenRefused :: IO ()
caseCopyAllowedMechanismsWidenRefused =
  copyPolicyRefused "aes/allowed-widen"
    (secretAes (BS.replicate 16 7)
      ++ [(AttrAllowedMechanisms, ValBytes (BS.pack [1,2,3,4,5,6,7,8]))])
    [(AttrAllowedMechanisms, ValBytes (BS.pack [1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16]))]

-- | On a MODIFIABLE=false source, adding DECRYPT=TRUE by copy is
-- refused read-only, and the set path refuses it too.
caseCopyDecryptAddedRefused :: IO ()
caseCopyDecryptAddedRefused = do
  let src = secretAes (BS.replicate 16 7)
        ++ [(AttrModifiable, ValBool False), (AttrDecrypt, ValBool False)]
  copyPolicyRefused "aes-nonmod/decrypt" src [(AttrDecrypt, ValBool True)]
  (sid, m0) <- openSession seeded
  (pc, m1) <- runCommit m0 (createReq sid src)
  h <- commitHandle pc
  (code, _) <- runReject m1 (setReq sid h [(AttrDecrypt, ValBool True)])
  assertEqual "set decrypt on non-modifiable" CKR_ATTRIBUTE_READ_ONLY code

-- | On a MODIFIABLE=false source, a non-exempt label change by copy
-- is refused read-only, and the set path refuses it too.
caseCopyNonModifiableRefused :: IO ()
caseCopyNonModifiableRefused = do
  let src = secretAes (BS.replicate 16 7)
        ++ [(AttrModifiable, ValBool False), label "a"]
  copyPolicyRefused "aes-nonmod/label" src [label "b"]
  (sid, m0) <- openSession seeded
  (pc, m1) <- runCommit m0 (createReq sid src)
  h <- commitHandle pc
  (code, _) <- runReject m1 (setReq sid h [label "b"])
  assertEqual "set label on non-modifiable" CKR_ATTRIBUTE_READ_ONLY code

-- | Widening ALLOWED_MECHANISMS by copy is refused read-only: a
-- wrapping key (WRAP-only, DECRYPT denied, mechanisms pinned to
-- wrap) copied with a widened mechanism list plus DECRYPT is
-- refused, so no widened copy exists. This pins the widening
-- refusal only; other DECRYPT paths follow the shared policy.
caseCopyAllowedWidenRefused :: IO ()
caseCopyAllowedWidenRefused = do
  (sid, m0) <- openSession seeded
  let wrapKey = secretAes (BS.replicate 16 0xA1)
        ++ [ (AttrWrap, ValBool True)
           , (AttrDecrypt, ValBool False)
           , (AttrAllowedMechanisms, ValBytes (BS.pack [1,2,3,4,5,6,7,8]))
           , label "wrap-key"
           ]
      target = secretAes (BS.replicate 16 0xC3)
        ++ [ (AttrSensitive, ValBool True)
           , (AttrExtractable, ValBool True)
           , label "wrap-target"
           ]
  (pcW, m1) <- runCommit m0 (createReq sid wrapKey)
  hw <- commitHandle pcW
  (pcT, m2) <- runCommit m1 (createReq sid target)
  _ <- commitHandle pcT
  let nObjs = Map.size (mObjects m2)
      nHandles = Map.size (mHandles m2)
  (rej, m3) <- runRejectFull m2 (copyReq sid hw
    [ (AttrAllowedMechanisms, ValBytes (BS.pack [9,10,11,12,13,14,15,16]))
    , (AttrDecrypt, ValBool True)
    , label "evil-copy"
    ])
  assertEqual "chain copy refused" CKR_ATTRIBUTE_READ_ONLY (rejCode rej)
  assertEqual "chain no handle" [] (rejOutputs rej)
  assertEqual "chain empty delta" (StateDelta []) (rejDelta rej)
  assertEqual "chain object count" nObjs (Map.size (mObjects m3))
  assertEqual "chain handle count" nHandles (Map.size (mHandles m3))
  (pcF, _) <- runCommit m3 (findReq sid [label "evil-copy"])
  evil <- findHandles pcF
  assertEqual "no evil copy exists" [] evil

-- | Copy exemptions on a non-modifiable source: TOKEN, PRIVATE,
-- DESTROYABLE and COPYABLE-to-false still copy. MODIFIABLE may
-- only tighten on copy: false to true is refused read-only.
caseCopyExemptionsStillWork :: IO ()
caseCopyExemptionsStillWork = do
  (sid, m0) <- openSession seeded
  m1 <- loginAs m0 sid
  let src = [classData, label "nonmod-src", (AttrModifiable, ValBool False)]
  (pc, m2) <- runCommit m1 (createReq sid src)
  h <- commitHandle pc
  let okLeg name over check = do
        (pcC, m3) <- runCommit m2 (copyReq sid h over)
        assertEqual ("exemption copies: " ++ name) CKR_OK (pcCode pcC)
        h2 <- commitHandle pcC
        assertBool ("exemption fresh handle: " ++ name) (h2 /= h)
        ost <- mustResolve m3 h2
        check ost
  okLeg "token" [(AttrToken, ValBool True)] $ \ost ->
    assertEqual "token stored" (Just (ValBool True)) (Map.lookup AttrToken (osAttrs ost))
  okLeg "private" [(AttrPrivate, ValBool True)] $ \ost ->
    assertEqual "private stored" (Just (ValBool True)) (Map.lookup AttrPrivate (osAttrs ost))
  okLeg "destroyable" [(AttrDestroyable, ValBool False)] $ \ost ->
    assertEqual "destroyable stored" (Just (ValBool False)) (Map.lookup AttrDestroyable (osAttrs ost))
  okLeg "copyable" [(AttrCopyable, ValBool False)] $ \ost ->
    assertEqual "copyable stored" (Just (ValBool False)) (Map.lookup AttrCopyable (osAttrs ost))
  let nObjs = Map.size (mObjects m2)
      nHandles = Map.size (mHandles m2)
  (rej, m3) <- runRejectFull m2 (copyReq sid h [(AttrModifiable, ValBool True)])
  assertEqual "modifiable loosen refused" CKR_ATTRIBUTE_READ_ONLY (rejCode rej)
  assertEqual "modifiable loosen no handle" [] (rejOutputs rej)
  assertEqual "modifiable loosen empty delta" (StateDelta []) (rejDelta rej)
  assertEqual "modifiable loosen objects" nObjs (Map.size (mObjects m3))
  assertEqual "modifiable loosen handles" nHandles (Map.size (mHandles m3))

-- | Two-step MODIFIABLE bypass blocked: a non-modifiable wrapping
-- key copied with MODIFIABLE=TRUE is refused read-only, so no
-- loosened copy exists on which DECRYPT could then be set. Before
-- the fix the copy succeeded and DECRYPT set on the copy.
caseCopyModifiableLoosenTwoStepBlocked :: IO ()
caseCopyModifiableLoosenTwoStepBlocked = do
  (sid, m0) <- openSession seeded
  let src = secretAes (BS.replicate 16 0xA1)
        ++ [ (AttrModifiable, ValBool False)
           , (AttrWrap, ValBool True)
           , (AttrDecrypt, ValBool False)
           , label "wrap-nonmod"
           ]
  (pc, m1) <- runCommit m0 (createReq sid src)
  h <- commitHandle pc
  let nObjs = Map.size (mObjects m1)
      nHandles = Map.size (mHandles m1)
  case planCall defaultRules m1
    (copyReq sid h [(AttrModifiable, ValBool True)]) of
    Reject rej -> do
      m2 <- case publishDelta m1 (rejDelta rej) of
        Left fault -> assertFailure ("rejection delta fault: " ++ show fault)
        Right m' -> pure m'
      assertEqual "loosen copy refused" CKR_ATTRIBUTE_READ_ONLY (rejCode rej)
      assertEqual "loosen no handle" [] (rejOutputs rej)
      assertEqual "loosen empty delta" (StateDelta []) (rejDelta rej)
      assertEqual "loosen objects" nObjs (Map.size (mObjects m2))
      assertEqual "loosen handles" nHandles (Map.size (mHandles m2))
      (pcF, _) <- runCommit m2 (findReq sid [(AttrModifiable, ValBool True)])
      evil <- findHandles pcF
      assertEqual "no loosened copy exists" [] evil
      (pcL, _) <- runCommit m2 (findReq sid [label "wrap-nonmod"])
      only <- findHandles pcL
      assertEqual "only the source remains" [h] only
      (code, _) <- runReject m2 (setReq sid h [(AttrDecrypt, ValBool True)])
      assertEqual "source DECRYPT still refused" CKR_ATTRIBUTE_READ_ONLY code
    Immediate pcC -> do
      mC <- case publishDelta m1 (pcDelta pcC) of
        Left fault -> assertFailure ("copy delta fault: " ++ show fault)
        Right m' -> pure m'
      h2 <- commitHandle pcC
      (pcS, _) <- runCommit mC (setReq sid h2 [(AttrDecrypt, ValBool True)])
      assertEqual "exploit: DECRYPT sets on loosened copy" CKR_OK (pcCode pcS)
      assertFailure "bypass: MODIFIABLE false->true copy allowed DECRYPT to be set"
    Execute _ _ -> assertFailure "expected immediate or reject for copy"

-- | A token key copied with TOKEN=FALSE succeeds as a session
-- object; the source stays a token object.
caseCopyTokenTrueToFalseWorks :: IO ()
caseCopyTokenTrueToFalseWorks = do
  (sid, m0) <- openSession seeded
  m1 <- loginAs m0 sid
  let src = filter ((/= AttrToken) . fst) (secretAes (BS.replicate 16 7))
        ++ [(AttrToken, ValBool True), label "tok-src"]
  (pc, m2) <- runCommit m1 (createReq sid src)
  h <- commitHandle pc
  (pcC, m3) <- runCommit m2
    (copyReq sid h [(AttrToken, ValBool False), label "sess-copy"])
  assertEqual "token to session copies" CKR_OK (pcCode pcC)
  h2 <- commitHandle pcC
  assertBool "fresh handle" (h2 /= h)
  dst <- mustResolve m3 h2
  assertEqual "copy is session"
    (Just (ValBool False)) (Map.lookup AttrToken (osAttrs dst))
  assertEqual "copy session-owned" (Just sid) (osOwner dst)
  srcOst <- mustResolve m3 h
  assertEqual "source still token"
    (Just (ValBool True)) (Map.lookup AttrToken (osAttrs srcOst))
  assertEqual "source token-owned" Nothing (osOwner srcOst)

-- | DESTROYABLE false to true on copy succeeds; the source is
-- unaffected.
caseCopyDestroyableFalseToTrueWorks :: IO ()
caseCopyDestroyableFalseToTrueWorks = do
  (sid, m0) <- openSession seeded
  let src = [classData, label "nodes-src", (AttrDestroyable, ValBool False)]
  (pc, m1) <- runCommit m0 (createReq sid src)
  h <- commitHandle pc
  (pcC, m2) <- runCommit m1 (copyReq sid h [(AttrDestroyable, ValBool True)])
  assertEqual "destroyable loosen copies" CKR_OK (pcCode pcC)
  h2 <- commitHandle pcC
  dst <- mustResolve m2 h2
  assertEqual "copy destroyable"
    (Just (ValBool True)) (Map.lookup AttrDestroyable (osAttrs dst))
  srcOst <- mustResolve m2 h
  assertEqual "source still not destroyable"
    (Just (ValBool False)) (Map.lookup AttrDestroyable (osAttrs srcOst))

-- | A MODIFIABLE=false data object copied with a new CKA_VALUE is
-- refused read-only: the data VALUE merge does not bypass the gate.
caseCopyDataValueNonModRefused :: IO ()
caseCopyDataValueNonModRefused =
  copyPolicyRefused "data-nonmod/value"
    [classData, label "d", (AttrModifiable, ValBool False), (AttrValue, ValBytes "old")]
    [(AttrValue, ValBytes "new")]

-- | A sealed private key copied with PRIVATE=FALSE is refused
-- read-only: a sealed object cannot be made public by copy.
caseCopySealedPrivateToPublicRefused :: IO ()
caseCopySealedPrivateToPublicRefused = do
  (sid, m0) <- openSession seeded
  m1 <- loginAs m0 sid
  let src = secretAes (BS.replicate 16 7)
        ++ [ (AttrSensitive, ValBool True)
           , (AttrExtractable, ValBool True)
           , (AttrPrivate, ValBool True)
           , label "sealed-priv"
           ]
  (pc, m2) <- runCommit m1 (createReq sid src)
  h <- commitHandle pc
  let nObjs = Map.size (mObjects m2)
      nHandles = Map.size (mHandles m2)
  (rej, m3) <- runRejectFull m2 (copyReq sid h [(AttrPrivate, ValBool False)])
  assertEqual "sealed private refused" CKR_ATTRIBUTE_READ_ONLY (rejCode rej)
  assertEqual "sealed private no handle" [] (rejOutputs rej)
  assertEqual "sealed private empty delta" (StateDelta []) (rejDelta rej)
  assertEqual "sealed private objects" nObjs (Map.size (mObjects m3))
  assertEqual "sealed private handles" nHandles (Map.size (mHandles m3))

-- | MODIFIABLE tightening on copy still works: true to false, and
-- same-value false, both copy.
caseCopyModifiableTightenStillWorks :: IO ()
caseCopyModifiableTightenStillWorks = do
  (sid, m0) <- openSession seeded
  let src = [classData, label "mod-src", (AttrModifiable, ValBool True)]
  (pc, m1) <- runCommit m0 (createReq sid src)
  h <- commitHandle pc
  (pcC, m2) <- runCommit m1 (copyReq sid h [(AttrModifiable, ValBool False)])
  assertEqual "modifiable tighten copies" CKR_OK (pcCode pcC)
  h2 <- commitHandle pcC
  dst <- mustResolve m2 h2
  assertEqual "tightened stored"
    (Just (ValBool False)) (Map.lookup AttrModifiable (osAttrs dst))
  (sidB, mB0) <- openSession seeded
  let srcB = [classData, label "nonmod-same", (AttrModifiable, ValBool False)]
  (pcB, mB1) <- runCommit mB0 (createReq sidB srcB)
  hB <- commitHandle pcB
  (pcBC, _) <- runCommit mB1 (copyReq sidB hB [(AttrModifiable, ValBool False)])
  assertEqual "modifiable same-value copies" CKR_OK (pcCode pcBC)

-- | One-way tightening by copy still works: SENSITIVE false-to-true
-- and EXTRACTABLE true-to-false.
caseCopyTighteningStillWorks :: IO ()
caseCopyTighteningStillWorks = do
  (sid, m0) <- openSession seeded
  (pcS, m1) <- runCommit m0
    (createReq sid (secretAes (BS.replicate 16 7) ++ [(AttrSensitive, ValBool False)]))
  hs <- commitHandle pcS
  (pcC1, m2) <- runCommit m1 (copyReq sid hs [(AttrSensitive, ValBool True)])
  assertEqual "sensitive tightens" CKR_OK (pcCode pcC1)
  (pcE, m3) <- runCommit m2
    (createReq sid (secretAes (BS.replicate 16 3) ++ [(AttrExtractable, ValBool True)]))
  he <- commitHandle pcE
  (pcC2, _) <- runCommit m3 (copyReq sid he [(AttrExtractable, ValBool False)])
  assertEqual "extractable tightens" CKR_OK (pcCode pcC2)

-- | Same-value overrides still copy: VALUE, MODULUS, EC_PARAMS and
-- SEED echoing the stored bytes are no-ops.
caseCopySameValueStillWorks :: IO ()
caseCopySameValueStillWorks = do
  (sid, m0) <- openSession seeded
  let v = BS.replicate 16 7
  (pcV, m1) <- runCommit m0 (createReq sid (secretAes v))
  hv <- commitHandle pcV
  (pcC1, _) <- runCommit m1 (copyReq sid hv [(AttrValue, ValBytes v)])
  assertEqual "same value copies" CKR_OK (pcCode pcC1)
  (pcR, m2) <- runCommit m1 (createReq sid privateRsaLegacy)
  hr <- commitHandle pcR
  (pcC2, _) <- runCommit m2
    (copyReq sid hr [(AttrModulus, ValBytes "legacy-modulus")])
  assertEqual "same modulus copies" CKR_OK (pcCode pcC2)
  (pcE, m3) <- runCommit m2 (createReq sid ecPrivLegacy)
  he <- commitHandle pcE
  ostE <- mustResolve m3 he
  case Map.lookup AttrEcParams (osAttrs ostE) of
    Nothing -> assertFailure "ec params stored"
    Just pv -> do
      (pcC3, _) <- runCommit m3 (copyReq sid he [(AttrEcParams, pv)])
      assertEqual "same params copy" CKR_OK (pcCode pcC3)
  (hP, m4) <- publishBare m3 sid mldsaBare
  (pcC4, _) <- runCommit m4
    (copyReq sid hP [(AttrSeed, ValBytes (BS.replicate 32 0x22))])
  assertEqual "same seed copies" CKR_OK (pcCode pcC4)

-- | The flip-forcing arm fires on an inconsistent stored row: a
-- source claiming EXTRACTABLE=TRUE with NEVER_EXTRACTABLE=TRUE,
-- copied with EXTRACTABLE=FALSE, stores NEVER=FALSE on the copy.
caseCopyInconsistentNeverForcedFalse :: IO ()
caseCopyInconsistentNeverForcedFalse = do
  (sid, m0) <- openSession seeded
  let badRow = secretAes (BS.replicate 16 7)
        ++ [ (AttrExtractable, ValBool True)
           , (AttrNeverExtractable, ValBool True)
           ]
  (h, m1) <- publishBare m0 sid badRow
  (pcC, m2) <- runCommit m1 (copyReq sid h [(AttrExtractable, ValBool False)])
  assertEqual "inconsistent tighten copies" CKR_OK (pcCode pcC)
  h2 <- commitHandle pcC
  dst <- mustResolve m2 h2
  assertEqual "forced never-extractable"
    (Just (ValBool False)) (Map.lookup AttrNeverExtractable (osAttrs dst))
  assertEqual "tightened extractable"
    (Just (ValBool False)) (Map.lookup AttrExtractable (osAttrs dst))

-- | A legacy key (no protection flags stored) seals: its absent
-- EXTRACTABLE reads as unextractable, so the value redacts.
caseKeyEffectiveSeal :: IO ()
caseKeyEffectiveSeal = do
  (sid, m0) <- openSession seeded
  (pc, m1) <- runCommit m0 (createReq sid (secretAes (BS.replicate 16 7)))
  h <- commitHandle pc
  (rej, _) <- runRejectFull m1 (getReq sid h [AttrValue])
  assertEqual "legacy key value seals" CKR_ATTRIBUTE_SENSITIVE (rejCode rej)
  assertEqual "no payload bytes escape" [] (rejOutputs rej)

-- | Find matches a legacy key by its effective protection: the
-- reported EXTRACTABLE=false hits, true misses, and the sealed
-- payload never matches a value guess.
caseKeyEffectiveFind :: IO ()
caseKeyEffectiveFind = do
  (sid, m0) <- openSession seeded
  let keyBytes = BS.replicate 16 7
  (pc, m1) <- runCommit m0 (createReq sid (secretAes keyBytes))
  h <- commitHandle pc
  (pcF, _) <- runCommit m1 (findReq sid [(AttrExtractable, ValBool False)])
  hits <- findHandles pcF
  assertEqual "effective false matches" [h] hits
  (pcT, _) <- runCommit m1 (findReq sid [(AttrExtractable, ValBool True)])
  misses <- findHandles pcT
  assertEqual "effective true misses" [] misses
  (pcV, _) <- runCommit m1 (findReq sid [(AttrValue, ValBytes keyBytes)])
  oracle <- findHandles pcV
  assertEqual "sealed value never matches" [] oracle

-- | Set ratchets on a legacy key follow the reported values:
-- EXTRACTABLE cannot flip up from its reported false, writing the
-- reported SENSITIVE=false is a no-op, and the four stamped
-- attributes refuse as immutable.
caseKeyEffectiveRatchets :: IO ()
caseKeyEffectiveRatchets = do
  (sid, m0) <- openSession seeded
  (pc, m1) <- runCommit m0 (createReq sid (secretAes (BS.replicate 16 7)))
  h <- commitHandle pc
  (codeE, _) <- runReject m1 (setReq sid h [(AttrExtractable, ValBool True)])
  assertEqual "extractable cannot flip up" CKR_ATTRIBUTE_READ_ONLY codeE
  (pcS, _) <- runCommit m1 (setReq sid h [(AttrSensitive, ValBool False)])
  assertEqual "reported no-op writes" CKR_OK (pcCode pcS)
  -- Direction pin: false->true succeeds, then true->false refuses.
  -- A swapped ratchet would refuse the first and allow the second.
  (pcT, mT) <- runCommit m1 (setReq sid h [(AttrSensitive, ValBool True)])
  assertEqual "sensitive flips up" CKR_OK (pcCode pcT)
  (codeD, _) <- runReject mT (setReq sid h [(AttrSensitive, ValBool False)])
  assertEqual "sensitive cannot flip down" CKR_ATTRIBUTE_READ_ONLY codeD
  mapM_ (\(t, v) -> do
    (code, _) <- runReject m1 (setReq sid h [(t, v)])
    assertEqual ("stamped attribute is immutable: " ++ show t)
      CKR_ATTRIBUTE_READ_ONLY code)
    [ (AttrAlwaysSensitive, ValBool False)
    , (AttrNeverExtractable, ValBool False)
    , (AttrLocal, ValBool False)
    , (AttrKeyGenMechanism, ValULong maxBound)
    ]

-- | Non-key classes are untouched by the key view: a data object
-- with no flags still reads its value, still reports SENSITIVE
-- unavailable, never matches a protection default in find, and
-- still matches its reported label default.
caseDataUnchanged :: IO ()
caseDataUnchanged = do
  (sid, m0) <- openSession seeded
  (pc, m1) <- runCommit m0
    (createReq sid [classData, (AttrValue, ValBytes "payload")])
  h <- commitHandle pc
  (pcG, _) <- runCommit m1 (getReq sid h [AttrValue])
  assertEqual "data value reads" CKR_OK (pcCode pcG)
  (codeS, _) <- runReject m1 (getReq sid h [AttrSensitive])
  assertEqual "data sensitive unavailable" CKR_ATTRIBUTE_TYPE_INVALID codeS
  (pcF, _) <- runCommit m1 (findReq sid [(AttrSensitive, ValBool False)])
  misses <- findHandles pcF
  assertEqual "data misses protection default" [] misses
  (pcL, _) <- runCommit m1 (findReq sid [(AttrLabel, ValBytes "")])
  hits <- findHandles pcL
  assertEqual "data label default still matches" [h] hits

-- | Public key material never seals: a legacy public row (no
-- protection flags stored) reads its value and reports the public
-- defaults, and a public row carrying explicit sealing flags still
-- reads its value while reporting the stored marks.
casePublicKeysStayReadable :: IO ()
casePublicKeysStayReadable = do
  (sid, m0) <- openSession seeded
  (pc, m1) <- runCommit m0 (createReq sid publicRsa)
  h <- commitHandle pc
  (pcV, _) <- runCommit m1 (getReq sid h [AttrValue])
  assertEqual "legacy public value reads" CKR_OK (pcCode pcV)
  (pcE, _) <- runCommit m1 (getReq sid h [AttrSensitive, AttrExtractable])
  assertEqual "legacy public reports the public defaults"
    [encodeValue (ValBool False), encodeValue (ValBool True)]
    [outBytes o | o <- pcOutputs pcE]
  (pcF, _) <- runCommit m1 (findReq sid [(AttrExtractable, ValBool True)])
  found <- findHandles pcF
  assertEqual "legacy public matches reported true" [h] found
  (pcS, m2) <- runCommit m1 (createReq sid
    (publicRsa ++ [(AttrSensitive, ValBool True), (AttrExtractable, ValBool False)]))
  hs <- commitHandle pcS
  (pcSV, _) <- runCommit m2 (getReq sid hs [AttrValue])
  assertEqual "flagged public value reads" CKR_OK (pcCode pcSV)
  (pcSE, _) <- runCommit m2 (getReq sid hs [AttrSensitive, AttrExtractable])
  assertEqual "flagged public reports stored marks"
    [encodeValue (ValBool True), encodeValue (ValBool False)]
    [outBytes o | o <- pcOutputs pcSE]
  -- History attributes are private/secret-only: a public read of
  -- either one is an unknown type, and a public key never matches
  -- a history default in find.
  (codeA, _) <- runReject m1 (getReq sid h [AttrAlwaysSensitive])
  assertEqual "public always-sensitive unknown" CKR_ATTRIBUTE_TYPE_INVALID codeA
  (codeN, _) <- runReject m1 (getReq sid h [AttrNeverExtractable])
  assertEqual "public never-extractable unknown" CKR_ATTRIBUTE_TYPE_INVALID codeN
  (pcHA, _) <- runCommit m1 (findReq sid [(AttrAlwaysSensitive, ValBool False)])
  histA <- findHandles pcHA
  assertEqual "public misses always-sensitive default" [] histA
  (pcHN, _) <- runCommit m1 (findReq sid [(AttrNeverExtractable, ValBool False)])
  histN <- findHandles pcHN
  assertEqual "public misses never-extractable default" [] histN

-- | A sealed RSA private key withholds every private component in
-- find, not only the value: a guessed private exponent, prime,
-- exponent or coefficient never matches, while the public modulus
-- still does. The read path already seals these; find must agree.
caseRsaPrivateFindWithholds :: IO ()
caseRsaPrivateFindWithholds = do
  (sid, m0) <- openSession seeded
  (pc, m1) <- runCommit m0 (createReq sid privateRsaLegacy)
  h <- commitHandle pc
  (rej, _) <- runRejectFull m1 (getReq sid h [AttrPrivateExponent])
  assertEqual "legacy private exponent seals" CKR_ATTRIBUTE_SENSITIVE (rejCode rej)
  (rejP2, _) <- runRejectFull m1 (getReq sid h [AttrPrime2])
  assertEqual "legacy prime2 seals" CKR_ATTRIBUTE_SENSITIVE (rejCode rejP2)
  (rejE1, _) <- runRejectFull m1 (getReq sid h [AttrExponent1])
  assertEqual "legacy exponent1 seals" CKR_ATTRIBUTE_SENSITIVE (rejCode rejE1)
  (rejE2, _) <- runRejectFull m1 (getReq sid h [AttrExponent2])
  assertEqual "legacy exponent2 seals" CKR_ATTRIBUTE_SENSITIVE (rejCode rejE2)
  (pcG, _) <- runCommit m1
    (findReq sid [(AttrPrivateExponent, ValBytes "legacy-privexp-guess")])
  oracle <- findHandles pcG
  assertEqual "sealed private exponent never matches" [] oracle
  (pcP, _) <- runCommit m1 (findReq sid [(AttrPrime1, ValBytes "legacy-prime1")])
  oracleP <- findHandles pcP
  assertEqual "sealed prime never matches" [] oracleP
  (pcP2, _) <- runCommit m1 (findReq sid [(AttrPrime2, ValBytes "legacy-prime2")])
  oracleP2 <- findHandles pcP2
  assertEqual "sealed prime2 never matches" [] oracleP2
  (pcE1, _) <- runCommit m1 (findReq sid [(AttrExponent1, ValBytes "legacy-exp1")])
  oracleE1 <- findHandles pcE1
  assertEqual "sealed exponent1 never matches" [] oracleE1
  (pcE2, _) <- runCommit m1 (findReq sid [(AttrExponent2, ValBytes "legacy-exp2")])
  oracleE2 <- findHandles pcE2
  assertEqual "sealed exponent2 never matches" [] oracleE2
  (pcC, _) <- runCommit m1
    (findReq sid [(AttrCoefficient, ValBytes "legacy-coeff")])
  oracleC <- findHandles pcC
  assertEqual "sealed coefficient never matches" [] oracleC
  (pcM, _) <- runCommit m1 (findReq sid [(AttrModulus, ValBytes "legacy-modulus")])
  modHits <- findHandles pcM
  assertEqual "public modulus still matches" [h] modHits

-- | Public enforcement follows the reported extractable-true: on a
-- flag-less public key, writing the reported value is a no-op and
-- copying to it is allowed. A literal absent-means-false default
-- would refuse both.
casePublicEnforcementFollowsReported :: IO ()
casePublicEnforcementFollowsReported = do
  (sid, m0) <- openSession seeded
  (pc, m1) <- runCommit m0 (createReq sid publicRsa)
  h <- commitHandle pc
  (pcS, m2) <- runCommit m1 (setReq sid h [(AttrExtractable, ValBool True)])
  assertEqual "public set of reported true" CKR_OK (pcCode pcS)
  (pcC, _) <- runCommit m2 (copyReq sid h [(AttrExtractable, ValBool True)])
  assertEqual "public copy to reported true" CKR_OK (pcCode pcC)

-- | The sealed-value find guard as a standalone pin: a legacy key
-- never matches a value guess. Kept separate so the assertion runs
-- even when earlier legs in the grouped case change.
caseSealedValueFindStandsAlone :: IO ()
caseSealedValueFindStandsAlone = do
  (sid, m0) <- openSession seeded
  let keyBytes = BS.replicate 16 7
  (pc, m1) <- runCommit m0 (createReq sid (secretAes keyBytes))
  _ <- commitHandle pc
  (pcV, _) <- runCommit m1 (findReq sid [(AttrValue, ValBytes keyBytes)])
  oracle <- findHandles pcV
  assertEqual "sealed value never matches" [] oracle

caseFindFlow :: IO ()
caseFindFlow = do
  (sid, m1) <- openSession seeded
  (pcA, m2) <- runCommit m1 (createReq sid [classData, label "a"])
  ha <- commitHandle pcA
  (pcB, m3) <- runCommit m2 (createReq sid [classData, label "b"])
  hb <- commitHandle pcB
  (pcF, _) <- runCommit m3 (findReq sid [label "a"])
  found <- findHandles pcF
  assertEqual "template match" [ha] found
  (pcAll, _) <- runCommit m3 (findReq sid [])
  foundAll <- findHandles pcAll
  assertEqual "empty template finds all" [ha, hb] foundAll
  (pcNone, _) <- runCommit m3 (findReq sid [label "zzz"])
  foundNone <- findHandles pcNone
  assertEqual "no match is successful emptiness" [] foundNone

-- | No find guess-oracle on sealed payloads: a template naming
-- 'AttrValue' matches unsealed objects only. The sealed object is
-- still discoverable by its label, and a wrong guess matches
-- nothing at all.
caseFindSealedNoOracle :: IO ()
caseFindSealedNoOracle = do
  (sid, m1) <- openSession seeded
  (pcS, m2) <- runCommit m1
    (createReq sid
      [ classData
      , label "sealed"
      , (AttrSensitive, ValBool True)
      , (AttrValue, ValBytes "s3cret")
      ])
  hs <- commitHandle pcS
  (pcU, m3) <- runCommit m2
    (createReq sid [classData, label "open", (AttrValue, ValBytes "s3cret")])
  hu <- commitHandle pcU
  (pcGuess, _) <- runCommit m3 (findReq sid [(AttrValue, ValBytes "s3cret")])
  guess <- findHandles pcGuess
  assertEqual "value guess matches the unsealed object only" [hu] guess
  (pcWrong, _) <- runCommit m3 (findReq sid [(AttrValue, ValBytes "nope")])
  wrong <- findHandles pcWrong
  assertEqual "wrong guess matches nothing" [] wrong
  (pcLab, _) <- runCommit m3 (findReq sid [label "sealed"])
  byLabel <- findHandles pcLab
  assertEqual "sealed object still found by label" [hs] byLabel

-- | A contradictory find template is rejected, never silently
-- emptied, and mints no bindings.
caseFindContradiction :: IO ()
caseFindContradiction = do
  (sid, m1) <- openSession seeded
  (code, m2) <- runReject m1 (findReq sid [label "x", label "y"])
  assertEqual "code" CKR_TEMPLATE_INCONSISTENT code
  assertEqual "no bindings minted" 0 (Map.size (mHandles m2))

-- | Malformed object calls on every route reject with
-- 'CKR_ARGUMENTS_BAD': missing handles and undecodable bodies.
caseBadArgs :: IO ()
caseBadArgs = do
  (sid, m1) <- openSession seeded
  (codeD, _) <- runReject m1 (mkRequest F_DestroyObject (Just sid))
  assertEqual "destroy without handle" CKR_ARGUMENTS_BAD codeD
  (codeG, _) <- runReject m1 (mkRequest F_GetAttributeValue (Just sid))
  assertEqual "get without handle" CKR_ARGUMENTS_BAD codeG
  (codeC, _) <- runReject m1 (mkRequest F_CopyObject (Just sid))
  assertEqual "copy without handle" CKR_ARGUMENTS_BAD codeC
  let truncated = (createReq sid []) { reqInput = BS.pack [1, 2, 3] }
  (codeT, _) <- runReject m1 truncated
  assertEqual "truncated create template" CKR_ARGUMENTS_BAD codeT
  let badFind = (findReq sid []) { reqInput = BS.pack [1, 2, 3] }
  (codeF, _) <- runReject m1 badFind
  assertEqual "truncated find template" CKR_ARGUMENTS_BAD codeF
  let badWanted = (getReq sid (ExternalHandle 1) []) { reqInput = BS.singleton 255 }
  (codeW, _) <- runReject m1 badWanted
  assertEqual "unknown wanted tag" CKR_ARGUMENTS_BAD codeW

-- ---------------------------------------------------------------------------
-- Handle-guard generated sequence (LCG harness style)
-- ---------------------------------------------------------------------------

data HOp = HCreate !Int | HDestroy !Int
  deriving (Eq, Show)

-- | Next LCG value (Numerical Recipes constants).
lcgNext :: Word64 -> Word64
lcgNext s = s * 6364136223846793005 + 1442695040888963407

genHOp :: Word64 -> (HOp, Word64)
genHOp s0 =
  let s1 = lcgNext s0
      s2 = lcgNext s1
      n = fromIntegral (s2 `mod` 5) :: Int
  in case s1 `mod` 3 of
    2 -> (HDestroy n, s2)
    _ -> (HCreate n, s2)

genHSeq :: Word64 -> Int -> [HOp]
genHSeq seed n = go seed n []
  where
    go :: Word64 -> Int -> [HOp] -> [HOp]
    go _ 0 acc = reverse acc
    go s k acc = let (op, s') = genHOp s in go s' (k - 1) (op : acc)

hCorpus :: [(Word64, Int)]
hCorpus = [(seed, len) | seed <- [1 .. 40], len <- [1, 5, 12]]

caseHandleGuard :: IO ()
caseHandleGuard = mapM_ check hCorpus
  where
    check :: (Word64, Int) -> IO ()
    check (seed, len) = do
      (sid, m0) <- openSession seeded
      let ops = genHSeq seed len
          tag = " seed=" ++ show seed ++ " len=" ++ show len
      (created, destroyed, mFinal) <- runHOps sid m0 ops [] []
      assertEqual ("handles distinct" ++ tag) (length created)
        (length (Map.fromList [(h, ()) | h <- created] :: Map.Map ExternalHandle ()))
      mapM_ (assertDead tag mFinal) destroyed
      mapM_ (assertLive tag mFinal destroyed) created

runHOps :: SessionId -> Model -> [HOp] -> [ExternalHandle] -> [ExternalHandle]
         -> IO ([ExternalHandle], [ExternalHandle], Model)
runHOps _ m [] created destroyed = pure (created, destroyed, m)
runHOps sid m (op : rest) created destroyed = case op of
  HCreate n -> do
    (pc, m') <- runCommit m (createReq sid [classData, label (BC8.pack (show n))])
    h <- commitHandle pc
    assertBool "fresh handle never reappears" (h `notElem` (created ++ destroyed))
    mapM_ (assertDead "mid-run" m') destroyed
    runHOps sid m' rest (created ++ [h]) destroyed
  HDestroy _k | null created ->
    runHOps sid m rest created destroyed
  HDestroy k -> do
    let h = created !! (k `mod` length created)
    if h `elem` destroyed
      then do
        (code, m') <- runReject m (destroyReq sid h)
        assertEqual "double destroy faults" CKR_OBJECT_HANDLE_INVALID code
        runHOps sid m' rest created destroyed
      else do
        (_, m') <- runCommit m (destroyReq sid h)
        assertDead "after destroy" m' h
        runHOps sid m' rest created (destroyed ++ [h])

assertDead :: String -> Model -> ExternalHandle -> IO ()
assertDead tag m h =
  assertEqual ("destroyed handle faults" ++ tag) Nothing (resolveHandle m h)

assertLive :: String -> Model -> [ExternalHandle] -> ExternalHandle -> IO ()
assertLive tag m destroyed h
  | h `elem` destroyed = pure ()
  | otherwise = case resolveHandle m h of
      Just _ -> pure ()
      Nothing -> assertFailure ("live handle lost" ++ tag ++ ": " ++ show h)

-- ---------------------------------------------------------------------------
-- Part 4 cases: redaction and the partial outcome
-- ---------------------------------------------------------------------------

secretVal :: AttributeValue
secretVal = ValBytes "s3cret"

labelTag :: AttributeValue
labelTag = ValBytes "tag"

-- | Every combination of the sealing flags: either flag alone seals
-- the payload; only (false, true) and (absent, absent) read it back.
flagMixes :: [(Maybe Bool, Maybe Bool, Bool)]
flagMixes =
  [ (Just True, Just True, True)
  , (Just True, Just False, True)
  , (Just False, Just True, False)
  , (Just False, Just False, True)
  , (Nothing, Just False, True)
  , (Just True, Nothing, True)
  , (Just False, Nothing, False)
  , (Nothing, Just True, False)
  , (Nothing, Nothing, False)
  ]

caseRedactionMixes :: IO ()
caseRedactionMixes = do
  (sid, m0) <- openSession seeded
  mapM_ (checkMix sid m0) flagMixes
  -- Direct-map garbage flags follow the documented exact-match rule
  -- (unreachable via routes: the template codec rejects cross-shape
  -- bytes, so stored flags are always well-shaped booleans).
  let garbage = Map.fromList
        [ (AttrSensitive, ValBytes "yes")
        , (AttrValue, secretVal)
        ]
      got = getAttributes garbage [AttrValue]
  assertEqual "garbage flag code" CKR_OK (prCode got)
  assertEqual "garbage flag reads back" [(AttrValue, ResOk secretVal)] (prResults got)
  where
    checkMix :: SessionId -> Model -> (Maybe Bool, Maybe Bool, Bool) -> IO ()
    checkMix sid m0 (mSens, mExt, sealed) = do
      let tag = " sens=" ++ show mSens ++ " ext=" ++ show mExt
          tmpl = [classData, (AttrLabel, labelTag)]
            ++ [(AttrSensitive, ValBool b) | Just b <- [mSens]]
            ++ [(AttrExtractable, ValBool b) | Just b <- [mExt]]
            ++ [(AttrValue, secretVal)]
      (pc, m1) <- runCommit m0 (createReq sid tmpl)
      h <- commitHandle pc
      let secretBs = encodeValue secretVal
          leaked outs reasons =
            any (secretBs `BS.isInfixOf`) outs || "s3cret" `isInfixOf` unwords reasons
      if sealed
        then do
          (rej, _) <- runRejectFull m1 (getReq sid h [AttrLabel, AttrValue])
          assertEqual ("code" ++ tag) CKR_ATTRIBUTE_SENSITIVE (rejCode rej)
          let outs = [outBytes o | o <- rejOutputs rej]
          assertEqual ("only the label escapes" ++ tag) [encodeValue labelTag] outs
          assertBool ("secret leaks" ++ tag)
            (not (leaked outs (rejReasons rej)))
        else do
          (pcG, _) <- runCommit m1 (getReq sid h [AttrLabel, AttrValue])
          assertEqual ("code" ++ tag) CKR_OK (pcCode pcG)
          let outs = [outBytes o | o <- pcOutputs pcG]
          assertEqual ("both values" ++ tag)
            [encodeValue labelTag, secretBs] outs

-- | Parked item, closed with a production path: one 'planCall'
-- yields an error code TOGETHER WITH the readable partial outputs
-- (plus the per-attribute reasons and a publishable delta) in a
-- single outcome — nothing hand-constructed.
casePartialOutcome :: IO ()
casePartialOutcome = do
  (sid, m1) <- openSession seeded
  (pc, m2) <- runCommit m1
    (createReq sid
      [ classData
      , (AttrLabel, ValBytes "greeting")
      , (AttrSensitive, ValBool True)
      , (AttrExtractable, ValBool False)
      , (AttrValue, ValBytes "s3cret")
      ])
  h <- commitHandle pc
  let objsBefore = mObjects m2
      handlesBefore = mHandles m2
  case planCall defaultRules m2 (getReq sid h [AttrLabel, AttrValue, AttrApplication]) of
    Reject rej -> do
      assertEqual "overall code" CKR_ATTRIBUTE_SENSITIVE (rejCode rej)
      assertEqual "readable value rides along"
        [encodeValue (ValBytes "greeting")] [outBytes o | o <- rejOutputs rej]
      assertEqual "per-attribute reasons"
        [ "AttrLabel: ok"
        , "AttrValue: sensitive"
        , "AttrApplication: unavailable"
        ]
        (rejReasons rej)
      case publishDelta m2 (rejDelta rej) of
        Left fault -> assertFailure ("rejection delta must publish: " ++ show fault)
        Right m3 -> do
          assertEqual "reads do not mutate objects" objsBefore (mObjects m3)
          assertEqual "reads do not mutate handles" handlesBefore (mHandles m3)
    other -> assertFailure ("expected a partial-outcome rejection, got: " ++ show other)

caseReadAllOk :: IO ()
caseReadAllOk = do
  (sid, m1) <- openSession seeded
  (pc, m2) <- runCommit m1
    (createReq sid [classData, label "x", (AttrApplication, ValBytes "app")])
  h <- commitHandle pc
  (pcG, _) <- runCommit m2 (getReq sid h [AttrLabel, AttrApplication])
  assertEqual "code" CKR_OK (pcCode pcG)
  assertEqual "wanted order"
    [encodeValue (ValBytes "x"), encodeValue (ValBytes "app")]
    [outBytes o | o <- pcOutputs pcG]
  (pcE, _) <- runCommit m2 (getReq sid h [])
  assertEqual "empty read" CKR_OK (pcCode pcE)
  assertEqual "no outputs" [] (pcOutputs pcE)

-- ---------------------------------------------------------------------------
-- Part 5 cases: visibility, logout invalidation, creator-close
-- ---------------------------------------------------------------------------

privateFlag :: (AttributeType, AttributeValue)
privateFlag = (AttrPrivate, ValBool True)

tokenFlagTmpl :: (AttributeType, AttributeValue)
tokenFlagTmpl = (AttrToken, ValBool True)

caseVisibilityLogin :: IO ()
caseVisibilityLogin = do
  -- The pure rule first: public is always visible, private needs a
  -- user login (plain or context grant; SO does not qualify).
  (a0, m0) <- openSession seeded
  -- Public sessions cannot mint private objects in the first place.
  (codeP, _) <- runReject m0 (createReq a0 [classData, label "priv", privateFlag])
  assertEqual "public cannot create private" CKR_USER_NOT_LOGGED_IN codeP
  -- Log in, then create: visibility follows the login state.
  m0login <- loginAs m0 a0
  (pcP, m1) <- runCommit m0login (createReq a0 [classData, label "priv", privateFlag])
  hp <- commitHandle pcP
  (pcU, m2) <- runCommit m1 (createReq a0 [classData, label "pub"])
  hu <- commitHandle pcU
  st0 <- case lookupSession m2 a0 of
    Nothing -> assertFailure "setup session lost"
    Just st -> pure st
  let vis h login = case resolveHandle m2 h of
        Nothing -> assertFailure "setup handle lost"
        Just ost -> pure (objectVisible (st0 { ssLogin = login }) ost)
  assertBool "public visible to public" =<< vis hu LoginPublic
  assertBool "private hidden from public" . not =<< vis hp LoginPublic
  assertBool "private visible to user" =<< vis hp LoginUser
  -- End to end through the routes: read while logged in, logout, read.
  (pcG, _) <- runCommit m2 (getReq a0 hp [AttrLabel])
  assertEqual "user reads private" CKR_OK (pcCode pcG)
  (pcF, mf) <- runCommit m2 (findReq a0 [])
  foundUser <- findHandles pcF
  assertBool "find includes private while logged in" (hp `elem` foundUser)
  m4 <- snd <$> runCommit mf (logoutReq a0)
  (code, m5) <- runReject m4 (getReq a0 hp [AttrLabel])
  assertEqual "public cannot read private" CKR_OBJECT_HANDLE_INVALID code
  (pcF2, _) <- runCommit m5 (findReq a0 [])
  foundPublic <- findHandles pcF2
  assertBool "find excludes private while public" (hp `notElem` foundPublic)
  assertBool "find keeps public while public" (hu `elem` foundPublic)
  (pcG2, _) <- runCommit m5 (getReq a0 hu [AttrLabel])
  assertEqual "public reads public" CKR_OK (pcCode pcG2)

-- | SO/user private-object isolation (F-1): an SO session must not
-- see or use user @CKA_PRIVATE=true@ objects, while user, context,
-- and public visibility keep their established shapes. The planner
-- legs flip the session login to SO in-model with the binding live:
-- a real logout would kill the binding, which would fault for the
-- wrong reason. The final legs run the real login transitions
-- end to end (logout -> SO -> logout -> user).
caseVisibilitySOIsolation :: IO ()
caseVisibilitySOIsolation = do
  (a0, m0) <- openSession seeded
  m0login <- loginAs m0 a0
  let secretClass = ValULong (mustClassId "CKO_SECRET_KEY")
      genericSecret = ValULong (mustKeyTypeId "CKK_GENERIC_SECRET")
  (pcK, m1) <- runCommit m0login (createReq a0
    [ (AttrClass, secretClass)
    , (AttrKeyType, genericSecret)
    , (AttrValue, ValBytes "0123456789abcdef0123456789abcdef")
    , (AttrToken, ValBool True)
    , (AttrPrivate, ValBool True)
    , (AttrSign, ValBool True)
    , label "so-key"
    ])
  hk <- commitHandle pcK
  (pcU, m2) <- runCommit m1 (createReq a0 [classData, label "pub"])
  hu <- commitHandle pcU
  st0 <- case lookupSession m2 a0 of
    Nothing -> assertFailure "setup session lost"
    Just st -> pure st
  ostK <- case resolveHandle m2 hk of
    Nothing -> assertFailure "setup key lost"
    Just ost -> pure ost
  ostU <- case resolveHandle m2 hu of
    Nothing -> assertFailure "setup public object lost"
    Just ost -> pure ost
  -- The pure rule: SO joins public in hiding private objects; user,
  -- context, and SO-over-public keep their established shapes.
  assertBool "private hidden from SO" $
    not (objectVisible (st0 { ssLogin = LoginSO }) ostK)
  assertBool "private visible to user" $
    objectVisible (st0 { ssLogin = LoginUser }) ostK
  assertBool "private visible to context grant" $
    objectVisible (st0 { ssLogin = LoginContextUser }) ostK
  assertBool "private hidden from public" $
    not (objectVisible (st0 { ssLogin = LoginPublic }) ostK)
  assertBool "public visible to SO" $
    objectVisible (st0 { ssLogin = LoginSO }) ostU
  -- Find/read/use refuse with the binding live under an SO login.
  let mSO = m2
        { mSessions = Map.adjust (\st -> st { ssLogin = LoginSO }) a0 (mSessions m2) }
      sReq sid h = (mkRequest F_SignInit (Just sid))
        { reqHandle = Just h
        , reqInput = encodeInitInput (MechanismId 0x251) [OpSign] False BS.empty
        }
  (pcF, _) <- runCommit mSO (findReq a0 [])
  foundSO <- findHandles pcF
  assertBool "SO find excludes private key" (hk `notElem` foundSO)
  assertBool "SO find keeps public object" (hu `elem` foundSO)
  (codeG, _) <- runReject mSO (getReq a0 hk [AttrLabel])
  assertEqual "SO read faults" CKR_OBJECT_HANDLE_INVALID codeG
  (codeD, _) <- runReject mSO (destroyReq a0 hk)
  assertEqual "SO destroy faults" CKR_OBJECT_HANDLE_INVALID codeD
  (codeC, _) <- runReject mSO (copyReq a0 hk [label "smuggled"])
  assertEqual "SO copy faults" CKR_OBJECT_HANDLE_INVALID codeC
  (codeS, _) <- runReject mSO (setReq a0 hk [label "relabeled"])
  assertEqual "SO set-attributes faults" CKR_OBJECT_HANDLE_INVALID codeS
  (codeI, _) <- runReject mSO (sReq a0 hk)
  -- A key handle the session cannot see refuses at init like an unknown
  -- key handle: CKR_KEY_HANDLE_INVALID (PKCS#11 v3.1 section 5.1.6;
  -- C_SignInit 5.13.1 lists it, not CKR_OBJECT_HANDLE_INVALID).
  assertEqual "SO sign-init refused" CKR_KEY_HANDLE_INVALID codeI
  -- The user still uses the key at the same seam.
  (pcUI, _) <- runCommit m2 (sReq a0 hk)
  assertEqual "user sign-init commits" CKR_OK (pcCode pcUI)
  -- Login transitions end to end: logout -> SO hides the token key
  -- (public object stays), logout -> user reveals it under a fresh
  -- handle (logout killed the old binding, not the object).
  m4 <- snd <$> runCommit m2 (logoutReq a0)
  mSO2 <- snd <$> runCommit m4 (soLoginReq a0)
  (pcF2, _) <- runCommit mSO2 (findReq a0 [])
  foundSO2 <- findHandles pcF2
  assertEqual "SO find after transition sees public only" [hu] foundSO2
  m5 <- snd <$> runCommit mSO2 (logoutReq a0)
  m6 <- loginAs m5 a0
  (pcF3, m7) <- runCommit m6 (findReq a0 [])
  foundU2 <- findHandles pcF3
  assertEqual "user re-find reveals both objects" 2 (length foundU2)
  -- Final-triage F-1(b): length-only is blind to wrong-member sets.
  -- The key's old binding died at logout (fresh handle by design —
  -- asserting hk membership here is wrong); pin the documented shape:
  -- public handle stable, exactly one fresh non-hk handle, and the
  -- fresh handle resolves to a live object (not a phantom). The
  -- resolution runs against the POST-find state: find commits the
  -- fresh binding via DeltaBindHandle, so pre-find m6 cannot see it.
  assertBool "user re-find keeps public object" (hu `elem` foundU2)
  assertBool "key rebinding is fresh (old binding died)" (hk `notElem` foundU2)
  case filter (/= hu) foundU2 of
    [freshH] -> case resolveHandle m7 freshH of
      Nothing -> assertFailure "re-found key handle is dangling"
      -- Codex-final minor: identity, not just liveness — a fresh
      -- alias to the public object must not pass this pin.
      Just ost -> assertEqual "re-found handle resolves to the key object"
        (osId ostK) (osId ost)
    _ -> assertFailure "user re-find must add exactly one fresh handle"

soLoginReq :: SessionId -> Request
soLoginReq sid = (mkRequest F_Login (Just sid)) { reqInput = "so:ok" }

ctxLoginReq :: SessionId -> Request
ctxLoginReq sid = (mkRequest F_Login (Just sid)) { reqInput = "context:ok" }

ctxLoginBadReq :: SessionId -> Request
ctxLoginBadReq sid = (mkRequest F_Login (Just sid)) { reqInput = "context:bad" }

cancelReq :: SessionId -> Word32 -> Request
cancelReq sid flags =
  (mkRequest F_SessionCancel (Just sid)) { reqInput = encodeCancelInput flags }

-- | The observed login of a live session.
loginOf :: Model -> SessionId -> IO SessionLogin
loginOf m sid = case lookupSession m sid of
  Nothing -> assertFailure "session lost"
  Just st -> pure (ssLogin st)

-- | Resolve a setup handle or fail the case.
mustResolve :: Model -> ExternalHandle -> IO ObjectState
mustResolve m h = case resolveHandle m h of
  Nothing -> assertFailure "setup handle lost"
  Just ost -> pure ost

-- | Object/handle allocation counters: a refused creation must move none.
countersOf :: Model -> (Int, Int, Int, Int)
countersOf m =
  (Map.size (mObjects m), Map.size (mHandles m), mNextObject m, mNextHandle m)

-- | A private token HMAC key with the always-authenticate mark: the
-- eligible shape for context grants.
authKeyTmpl :: ByteString -> [(AttributeType, AttributeValue)]
authKeyTmpl lbl =
  [ (AttrClass, ValULong (mustClassId "CKO_SECRET_KEY"))
  , (AttrKeyType, ValULong (mustKeyTypeId "CKK_GENERIC_SECRET"))
  , (AttrValue, ValBytes "0123456789abcdef0123456789abcdef")
  , (AttrToken, ValBool True)
  , (AttrPrivate, ValBool True)
  , (AttrSign, ValBool True)
  , (AttrVerify, ValBool True)
  , (AttrAlwaysAuthenticate, ValBool True)
  , label lbl
  ]

signInitReq :: SessionId -> ExternalHandle -> Request
signInitReq sid h = (mkRequest F_SignInit (Just sid))
  { reqHandle = Just h
  , reqInput = encodeInitInput (MechanismId 0x251) [OpSign] False BS.empty
  }

verifyInitReq :: SessionId -> ExternalHandle -> Request
verifyInitReq sid h = (mkRequest F_VerifyInit (Just sid))
  { reqHandle = Just h
  , reqInput = encodeInitInput (MechanismId 0x251) [OpVerify] False BS.empty
  }

-- | Finish a sign one-shot with a 32-byte stub signature, publishing
-- the resulting commit. Short caps stage (BUFFER_TOO_SMALL);
-- fitting caps complete (OK).
runSignFinish :: Model -> SessionId -> String -> ByteString -> Int -> IO (PreparedCommit, Model)
runSignFinish m sid name input cap = do
  (res, _) <- runExecute m (dataReq F_Sign sid name input cap)
  case finishEffect defaultRules m res (EngineOkBytes (BS.replicate 32 0xEE)) of
    Left rej -> assertFailure ("sign finish rejected: " ++ show (rejCode rej))
    Right pc -> case publishDelta m (pcDelta pc) of
      Left fault -> assertFailure ("sign finish fault: " ++ show fault)
      Right m' -> pure (pc, m')

-- | F-1 follow-up (cached-operation bypass): logout retires every
-- cached operation bound to a private key — on every same-slot
-- session, staged outputs included — so neither a public session
-- nor a later SO login can drive init-before-logout key use. The
-- unkeyed digest survives both transitions: retirement is
-- selective, not a session wipe.
caseLogoutRetiresPrivateOps :: IO ()
caseLogoutRetiresPrivateOps = do
  (a0, m0) <- openSession seeded
  m0login <- loginAs m0 a0
  let secretClass = ValULong (mustClassId "CKO_SECRET_KEY")
      genericSecret = ValULong (mustKeyTypeId "CKK_GENERIC_SECRET")
      aesType = ValULong (mustKeyTypeId "CKK_AES")
      hmacMech = MechanismId 0x251
      sha256Mech = MechanismId 0x250
      aesCbcMech = MechanismId 0x1082
      iv = BS.replicate 16 0
      initReq fid h blob = (mkRequest fid (Just a0))
        { reqHandle = Just h, reqInput = blob }
  (pcK, m1) <- runCommit m0login (createReq a0
    [ (AttrClass, secretClass)
    , (AttrKeyType, genericSecret)
    , (AttrValue, ValBytes "0123456789abcdef0123456789abcdef")
    , (AttrToken, ValBool True)
    , (AttrPrivate, ValBool True)
    , (AttrSign, ValBool True)
    , (AttrVerify, ValBool True)
    , label "f1-op-hmac"
    ])
  hk <- commitHandle pcK
  (pcE, m2) <- runCommit m1 (createReq a0
    [ (AttrClass, secretClass)
    , (AttrKeyType, aesType)
    , (AttrValue, ValBytes "0123456789abcdef")
    , (AttrToken, ValBool True)
    , (AttrPrivate, ValBool True)
    , (AttrEncrypt, ValBool True)
    , (AttrDecrypt, ValBool True)
    , label "f1-op-aes"
    ])
  he <- commitHandle pcE
  -- All four keyed classic slots go active under the user login.
  (_, mS) <- runCommit m2 (initReq F_SignInit hk
    (encodeInitInput hmacMech [OpSign] False BS.empty))
  (_, mV) <- runCommit mS (initReq F_VerifyInit hk
    (encodeInitInput hmacMech [OpVerify] False BS.empty))
  (_, mE) <- runCommit mV (initReq F_EncryptInit he
    (encodeInitInput aesCbcMech [OpEncrypt] False iv))
  (_, mD) <- runCommit mE (initReq F_DecryptInit he
    (encodeInitInput aesCbcMech [OpDecrypt] False iv))
  -- Plus an unkeyed digest (stream alloc finished with a fake id).
  (resDI, effDI) <- runExecute mD ((mkRequest F_DigestInit (Just a0))
    { reqInput = encodeInitInput sha256Mech [OpDigest] False BS.empty })
  m3 <- case effDI of
    EffectCrypto (FxDigestInit _) ->
      case finishEffect defaultRules mD resDI
             (EngineOkResource (EngineResourceId 11)) of
        Left rej ->
          assertFailure ("digest init finish rejected: " ++ show (rejCode rej))
        Right pc -> case publishDelta mD (pcDelta pc) of
          Left fault -> assertFailure ("digest init fault: " ++ show fault)
          Right m' -> pure m'
    _ -> assertFailure ("expected FxDigestInit, got: " ++ show effDI)
  -- A second same-slot session stages a signature under the user login.
  (b0, mB0) <- openSession m3
  stb <- case lookupSession mB0 b0 of
    Nothing -> assertFailure "second session lost"
    Just st -> pure st
  assertEqual "second session observes the user login" LoginUser (ssLogin stb)
  (_, mB1) <- runCommit mB0 ((mkRequest F_SignInit (Just b0))
    { reqHandle = Just hk
    , reqInput = encodeInitInput hmacMech [OpSign] False BS.empty
    })
  (resShort, _) <- runExecute mB1 (dataReq F_Sign b0 "signature" "f1-bytes" 8)
  mB2 <- case finishEffect defaultRules mB1 resShort
               (EngineOkBytes (BS.replicate 32 0xEE)) of
    Left rej ->
      assertFailure ("short sign finish rejected: " ++ show (rejCode rej))
    Right pc -> do
      assertEqual "short buffer stages" CKR_BUFFER_TOO_SMALL (pcCode pc)
      case publishDelta mB1 (pcDelta pc) of
        Left fault -> assertFailure ("short sign fault: " ++ show fault)
        Right m' -> pure m'
  -- Logout retires the private-key slots on both sessions; the
  -- unkeyed digest stays (so no stream is released).
  (pcL, m4) <- runCommit mB2 (logoutReq a0)
  assertEqual "logout releases nothing" [] (pcReleases pcL)
  sta <- case lookupSession m4 a0 of
    Nothing -> assertFailure "session lost across logout"
    Just st -> pure st
  assertEqual "only the digest survives on A" [SlotDigest] (activeSlots (ssOps sta))
  stb2 <- case lookupSession m4 b0 of
    Nothing -> assertFailure "second session lost across logout"
    Just st -> pure st
  assertEqual "staged sign retires on B" [] (activeSlots (ssOps stb2))
  -- Public use after logout: every keyed slot refuses.
  let signReq sid = dataReq F_Sign sid "signature" "f1-bytes" 64
      verifyReq sid = dataReq F_Verify sid "verify"
        (encodeVerifyInput "f1-bytes" (BS.replicate 32 0)) 64
      encReq sid = dataReq F_Encrypt sid "ciphertext" (BS.replicate 16 1) 64
      decReq sid = dataReq F_Decrypt sid "plaintext" (BS.replicate 16 2) 64
  (codePS, m5) <- runReject m4 (signReq a0)
  assertEqual "public sign after logout refuses"
    CKR_OPERATION_NOT_INITIALIZED codePS
  (codePV, m6) <- runReject m5 (verifyReq a0)
  assertEqual "public verify after logout refuses"
    CKR_OPERATION_NOT_INITIALIZED codePV
  (codePE, m7) <- runReject m6 (encReq a0)
  assertEqual "public encrypt after logout refuses"
    CKR_OPERATION_NOT_INITIALIZED codePE
  (codePD, m8) <- runReject m7 (decReq a0)
  assertEqual "public decrypt after logout refuses"
    CKR_OPERATION_NOT_INITIALIZED codePD
  -- The finding's exact path: SO login, then the cached sign refuses.
  mSO <- snd <$> runCommit m8 (soLoginReq a0)
  (codeSO, m9) <- runReject mSO (signReq a0)
  assertEqual "SO sign after logout refuses"
    CKR_OPERATION_NOT_INITIALIZED codeSO
  -- The staged signature retired with its slot: the retry refuses
  -- instead of delivering user-login bytes to the SO session.
  (codeR, m10) <- runReject m9 (dataReq F_Sign b0 "signature" BS.empty 64)
  assertEqual "SO staged-sign retry refuses"
    CKR_OPERATION_NOT_INITIALIZED codeR
  -- The unkeyed digest sailed through logout and the SO login: it
  -- still feeds, and still feeds after a user re-login.
  (_, effU1) <- runExecute m10
    ((mkRequest F_DigestUpdate (Just a0)) { reqInput = "hello" })
  case effU1 of
    EffectCrypto (FxDigestFeed _ fed) ->
      assertEqual "first feed intact" "hello" fed
    _ -> assertFailure ("expected FxDigestFeed, got: " ++ show effU1)
  m11 <- snd <$> runCommit m10 (logoutReq a0)
  m12 <- loginAs m11 a0
  (_, effU2) <- runExecute m12
    ((mkRequest F_DigestUpdate (Just a0)) { reqInput = "world" })
  case effU2 of
    EffectCrypto (FxDigestFeed _ fed) ->
      assertEqual "second feed intact" "world" fed
    _ -> assertFailure ("expected FxDigestFeed, got: " ++ show effU2)

-- | F-1 round 2 (staged-recall residual): a private-key decrypt
-- staged through a length query keeps its bytes in the slot when the
-- key is destroyed ('DeltaDestroyObject' leaves 'ssOps' intact), so
-- a logout retirement that skips keys which no longer resolve
-- strands the staged plaintext for a later SO login to recall
-- ('retryStaged' delivers staged bytes without key resolution).
-- Logout must retire keyed operations whose key no longer resolves.
caseLogoutRetiresDestroyedKeyStagedOps :: IO ()
caseLogoutRetiresDestroyedKeyStagedOps = do
  (a0, m0) <- openSession seeded
  m0login <- loginAs m0 a0
  let secretClass = ValULong (mustClassId "CKO_SECRET_KEY")
      aesType = ValULong (mustKeyTypeId "CKK_AES")
      aesCbcMech = MechanismId 0x1082
      iv = BS.replicate 16 0
      plain = "user-plaintext!!"
  assertEqual "fixture is one CBC block" 16 (BS.length plain)
  (pcK, m1) <- runCommit m0login (createReq a0
    [ (AttrClass, secretClass)
    , (AttrKeyType, aesType)
    , (AttrValue, ValBytes "0123456789abcdef")
    , (AttrToken, ValBool True)
    , (AttrPrivate, ValBool True)
    , (AttrDecrypt, ValBool True)
    , label "f1-op-aes-destroy"
    ])
  hk <- commitHandle pcK
  (_, m2) <- runCommit m1 ((mkRequest F_DecryptInit (Just a0))
    { reqHandle = Just hk
    , reqInput = encodeInitInput aesCbcMech [OpDecrypt] False iv
    })
  -- A length query stages the decrypted block without delivering it.
  let query = (mkRequest F_Decrypt (Just a0))
        { reqInput = BS.replicate 16 0x2A
        , reqRegions = [RegionBytes "plaintext" IntentNull]
        }
  (resQ, _) <- runExecute m2 query
  m3 <- case finishEffect defaultRules m2 resQ (EngineOkBytes plain) of
    Left rej ->
      assertFailure ("query finish rejected: " ++ show (rejCode rej))
    Right pc -> do
      assertEqual "query stages" CKR_BUFFER_TOO_SMALL (pcCode pc)
      case publishDelta m2 (pcDelta pc) of
        Left fault -> assertFailure ("query fault: " ++ show fault)
        Right m' -> pure m'
  -- Destroying the key leaves the staged slot intact (pre-existing
  -- shape: destroy touches objects/handles, not 'ssOps').
  (_, m4) <- runCommit m3 (destroyReq a0 hk)
  case resolveHandle m4 hk of
    Nothing -> pure ()
    Just _ -> assertFailure "destroyed key still resolves"
  -- Logout must retire the stranded staged slot even though its key
  -- no longer resolves; the SO login then recalls nothing.
  m5 <- snd <$> runCommit m4 (logoutReq a0)
  mSO <- snd <$> runCommit m5 (soLoginReq a0)
  case planCall defaultRules mSO (dataReq F_Decrypt a0 "plaintext" BS.empty 64) of
    Immediate pc
      | pcCode pc == CKR_OK ->
          assertFailure ("SO recalls destroyed-key staged plaintext: "
            ++ show [outBytes o | o <- pcOutputs pc])
      | otherwise ->
          assertFailure ("SO recall committed with: " ++ show (pcCode pc))
    Reject rej ->
      assertEqual "SO staged recall after destroy+logout refuses"
        CKR_OPERATION_NOT_INITIALIZED (rejCode rej)
    Execute _ _ ->
      assertFailure "SO recall executed instead of refusing"
  sta <- case lookupSession m5 a0 of
    Nothing -> assertFailure "session lost across logout"
    Just st -> pure st
  assertEqual "destroyed-key staged op retires at logout"
    [] (activeSlots (ssOps sta))

-- | Slot isolation: a session only sees objects on its own slot, on
-- every object gate (get, find, destroy, copy). Same-slot access
-- keeps working.
caseSlotIsolation :: IO ()
caseSlotIsolation = do
  let slot1 = SlotId 1
      twoSlot = addToken seeded slot1
  (a, m1) <- openSessionOn slot0 twoSlot
  (b, m2) <- openSessionOn slot1 m1
  (pcA, m3) <- runCommit m2 (createReq a [classData, label "on-a"])
  ha <- commitHandle pcA
  (pcB, m4) <- runCommit m3 (createReq b [classData, label "on-b"])
  hb <- commitHandle pcB
  (pcOwn, _) <- runCommit m4 (getReq a ha [AttrLabel])
  assertEqual "same-slot read works" CKR_OK (pcCode pcOwn)
  (codeX, m5) <- runReject m4 (getReq b ha [AttrLabel])
  assertEqual "cross-slot read faults" CKR_OBJECT_HANDLE_INVALID codeX
  (codeY, m6) <- runReject m5 (getReq a hb [AttrLabel])
  assertEqual "cross-slot read faults the other way" CKR_OBJECT_HANDLE_INVALID codeY
  (pcFA, _) <- runCommit m6 (findReq a [])
  assertEqual "find sees own slot only" [ha] =<< findHandles pcFA
  (pcFB, _) <- runCommit m6 (findReq b [])
  assertEqual "find sees own slot only, other side" [hb] =<< findHandles pcFB
  (codeD, m7) <- runReject m6 (destroyReq b ha)
  assertEqual "cross-slot destroy faults" CKR_OBJECT_HANDLE_INVALID codeD
  (codeC, _) <- runReject m7 (copyReq b ha [label "smuggled"])
  assertEqual "cross-slot copy faults" CKR_OBJECT_HANDLE_INVALID codeC

-- | Logout destroys private session objects (OASIS PKCS#11 3.2
-- §5.6.10): the delta carries the destruction, the old handle dies,
-- and re-login finds nothing — the object is gone, not hidden. The
-- public session object is untouched throughout.
caseLogoutNoResurrection :: IO ()
caseLogoutNoResurrection = do
  (a, m0) <- openSession seeded
  m1 <- loginAs m0 a
  (pcP, m2) <- runCommit m1 (createReq a [classData, label "priv", privateFlag])
  hp <- commitHandle pcP
  (pcU, m3) <- runCommit m2 (createReq a [classData, label "pub"])
  hu <- commitHandle pcU
  ostP <- mustResolve m3 hp
  (pcL, m4) <- runCommit m3 (logoutReq a)
  let StateDelta lops = pcDelta pcL
  assertEqual "logout destroys the private session object"
    [osId ostP] [oid | DeltaDestroyObject oid <- lops]
  (code, m5) <- runReject m4 (getReq a hp [AttrLabel])
  assertEqual "logout kills the private handle" CKR_OBJECT_HANDLE_INVALID code
  (pcG, _) <- runCommit m5 (getReq a hu [AttrLabel])
  assertEqual "public handle survives logout" CKR_OK (pcCode pcG)
  m6 <- loginAs m5 a
  (code2, m7) <- runReject m6 (getReq a hp [AttrLabel])
  assertEqual "no resurrection after re-login" CKR_OBJECT_HANDLE_INVALID code2
  (pcF, mF) <- runCommit m7 (findReq a [label "priv"])
  found <- findHandles pcF
  assertEqual "destroyed object is not rediscovered" [] found
  assertEqual "only the public object remains" 1 (Map.size (mObjects mF))
  (pcG3, _) <- runCommit mF (getReq a hu [AttrLabel])
  assertEqual "public handle still the same one" CKR_OK (pcCode pcG3)

-- | Token-owned private objects take the opposite logout path from
-- session-owned ones: the handle dies at logout, stays dead across
-- re-login, and only a fresh discovery handle reads again. The
-- token object itself survives (logout destroys private session
-- objects only — the control for the destruction above).
caseLogoutTokenPrivate :: IO ()
caseLogoutTokenPrivate = do
  (a, m0) <- openSession seeded
  m1 <- loginAs m0 a
  (pcP, m2) <- runCommit m1
    (createReq a [classData, label "tokpriv", tokenFlagTmpl, privateFlag])
  hp <- commitHandle pcP
  m3 <- snd <$> runCommit m2 (logoutReq a)
  (code, m4) <- runReject m3 (getReq a hp [AttrLabel])
  assertEqual "logout kills the token-private handle" CKR_OBJECT_HANDLE_INVALID code
  m5 <- loginAs m4 a
  (code2, m6) <- runReject m5 (getReq a hp [AttrLabel])
  assertEqual "no resurrection after re-login" CKR_OBJECT_HANDLE_INVALID code2
  (pcF, mF) <- runCommit m6 (findReq a [label "tokpriv"])
  found <- findHandles pcF
  case found of
    [hp2] -> do
      assertBool "discovery mints a fresh handle" (hp2 /= hp)
      (pcG2, _) <- runCommit mF (getReq a hp2 [AttrLabel])
      assertEqual "fresh handle reads" CKR_OK (pcCode pcG2)
    _ -> assertFailure ("expected exactly the re-discovered handle, got: " ++ show found)

-- | Logout destruction is scoped: every private session object on
-- the token dies — including ones created by a second same-slot
-- session — while public session objects, every token object, and
-- every other token survive untouched.
caseLogoutDestructionMatrix :: IO ()
caseLogoutDestructionMatrix = do
  let slot1 = SlotId 1
      twoSlot = addToken seeded slot1
  (a, m1) <- openSessionOn slot0 twoSlot
  (b, m2) <- openSessionOn slot0 m1
  (c, m3) <- openSessionOn slot1 m2
  m4 <- loginAs m3 a
  m5 <- loginAs m4 c
  (pcPS, m6) <- runCommit m5 (createReq a [classData, label "priv-sess-a", privateFlag])
  hPS <- commitHandle pcPS
  (pcUS, m7) <- runCommit m6 (createReq a [classData, label "pub-sess-a"])
  hUS <- commitHandle pcUS
  (pcPT, m8) <- runCommit m7
    (createReq a [classData, label "priv-tok", tokenFlagTmpl, privateFlag])
  hPT <- commitHandle pcPT
  (pcUT, m9) <- runCommit m8 (createReq a [classData, label "pub-tok", tokenFlagTmpl])
  hUT <- commitHandle pcUT
  (pcPSB, m10) <- runCommit m9 (createReq b [classData, label "priv-sess-b", privateFlag])
  hPSB <- commitHandle pcPSB
  (pcPSC, m11) <- runCommit m10 (createReq c [classData, label "priv-sess-c", privateFlag])
  hPSC <- commitHandle pcPSC
  ostPT <- mustResolve m11 hPT
  -- Logout through B still clears the whole of slot 0.
  m12 <- snd <$> runCommit m11 (logoutReq b)
  assertEqual "A public" LoginPublic =<< loginOf m12 a
  assertEqual "B public" LoginPublic =<< loginOf m12 b
  assertEqual "other token stays logged in" LoginUser =<< loginOf m12 c
  assertEqual "slot-0 private session object destroyed" Nothing (resolveHandle m12 hPS)
  assertEqual "second-session private object destroyed" Nothing (resolveHandle m12 hPSB)
  assertBool "public session object survives" (hUS `resolvesIn` m12)
  assertBool "public token object survives" (hUT `resolvesIn` m12)
  assertEqual "private token handle dead" Nothing (resolveHandle m12 hPT)
  assertBool "private token object survives" (lookupObject m12 (osId ostPT) /= Nothing)
  assertBool "other-token private object survives" (hPSC `resolvesIn` m12)
  -- After re-login the destroyed objects stay gone while the token
  -- object re-discovers under a fresh handle.
  m13 <- loginAs m12 a
  (pcFA, m14) <- runCommit m13 (findReq a [label "priv-sess-a"])
  assertEqual "no rediscovery on A" [] =<< findHandles pcFA
  (pcFB, _) <- runCommit m14 (findReq b [label "priv-sess-b"])
  assertEqual "no rediscovery on B" [] =<< findHandles pcFB
  (pcFT, m15) <- runCommit m14 (findReq a [label "priv-tok"])
  foundT <- findHandles pcFT
  case foundT of
    [fresh] -> do
      assertBool "token rediscovery mints fresh" (fresh /= hPT)
      ostFresh <- mustResolve m15 fresh
      assertEqual "rediscovery names the token object" (osId ostPT) (osId ostFresh)
    _ -> assertFailure ("expected the token rediscovery, got: " ++ show foundT)
  (pcFU, _) <- runCommit m15 (findReq a [label "pub-sess-a"])
  assertEqual "public handle stable" [hUS] =<< findHandles pcFU
  (pcFC, _) <- runCommit m15 (findReq c [label "priv-sess-c"])
  assertEqual "other-token handle stable" [hPSC] =<< findHandles pcFC
  where
    resolvesIn h m = resolveHandle m h /= Nothing

-- | SO creation admission (OASIS PKCS#11 3.2 §5.7.1-5.7.2): the SO
-- administers public objects (TRUSTED=true included) but cannot
-- mint private ones — create and copy both refuse with
-- CKR_USER_NOT_LOGGED_IN and allocate nothing. Template errors
-- still precede admission, and admission still precedes the
-- session mode.
caseSOCreationAdmission :: IO ()
caseSOCreationAdmission = do
  (a, m0) <- openSession seeded
  mSO <- snd <$> runCommit m0 (soLoginReq a)
  let before = countersOf mSO
  -- Private create refuses under SO, session and token alike.
  (codePS, m1) <- runReject mSO (createReq a [classData, label "so-priv", privateFlag])
  assertEqual "SO private session refused" CKR_USER_NOT_LOGGED_IN codePS
  (codePT, m2) <- runReject m1
    (createReq a [classData, label "so-priv-tok", tokenFlagTmpl, privateFlag])
  assertEqual "SO private token refused" CKR_USER_NOT_LOGGED_IN codePT
  assertEqual "refusals allocate nothing" before (countersOf m2)
  -- Public administration still admits, TRUSTED=true included.
  (pcU, m3) <- runCommit m2 (createReq a [classData, label "so-pub"])
  hU <- commitHandle pcU
  (pcT, m4) <- runCommit m3
    (createReq a [classData, label "so-trusted", (AttrTrusted, ValBool True)])
  hT <- commitHandle pcT
  ostT <- mustResolve m4 hT
  assertEqual "SO trusted stored"
    (Just (ValBool True)) (Map.lookup AttrTrusted (osAttrs ostT))
  -- Copy to private refuses; copy to public admits.
  (codeC, m5) <- runReject m4 (copyReq a hU [label "so-copy", privateFlag])
  assertEqual "SO copy to private refused" CKR_USER_NOT_LOGGED_IN codeC
  assertEqual "copy refusal allocates nothing" (countersOf m4) (countersOf m5)
  (_, m6) <- runCommit m5 (copyReq a hU [label "so-copy-pub"])
  -- Template errors precede admission even for SO private shapes.
  (codeTI, m7) <- runReject m6 (createReq a [classData, label "x", label "y", privateFlag])
  assertEqual "contradiction precedes admission" CKR_TEMPLATE_INCONSISTENT codeTI
  (codeTC, _) <- runReject m7 (createReq a [label "noclass", privateFlag])
  assertEqual "incompleteness precedes admission" CKR_TEMPLATE_INCOMPLETE codeTC
  -- Admission precedes the session mode: an SO login on a
  -- read-only session (unreachable live — the SO/RO exclusion
  -- forbids it — so flipped in-model purely to pin the planner
  -- order) still reports the role, not the mode.
  let mRO = m7
        { mSessions = Map.adjust (\st -> st { ssReadOnly = True }) a (mSessions m7) }
  (codeRM, _) <- runReject mRO
    (createReq a [classData, label "so-ro", tokenFlagTmpl, privateFlag])
  assertEqual "role precedes mode" CKR_USER_NOT_LOGGED_IN codeRM
  -- And the mode check is still live for the user on a read-only
  -- session asking for a private token object.
  mP <- snd <$> runCommit m7 (logoutReq a)
  mU0 <- loginAs mP a
  (roU, mU1) <- openSessionMode slot0 True mU0
  (codeRU, _) <- runReject mU1
    (createReq roU [classData, label "u-ro", tokenFlagTmpl, privateFlag])
  assertEqual "user RO token refused by mode" CKR_SESSION_READ_ONLY codeRU

-- | Context-grant binding (G27): a grant issues only for the single
-- eligible active marked operation (binding by uniqueness), spends
-- on the first data use, and never authorizes a later operation or
-- another session. Two keys and two sessions across success,
-- failure, and cancellation, plus the simultaneous-pending pair.
caseContextGrantBinding :: IO ()
caseContextGrantBinding = do
  (a, m0) <- openSession seeded
  (b, m1) <- openSession m0
  m2 <- loginAs m1 a
  (pcA, m3) <- runCommit m2 (createReq a (authKeyTmpl "key-a"))
  hA <- commitHandle pcA
  (pcB, m4) <- runCommit m3 (createReq a (authKeyTmpl "key-b"))
  hB <- commitHandle pcB
  -- An idle session takes no grant even with a sibling pending, and
  -- a plain active operation does not qualify either.
  (_, m5) <- runCommit m4 (signInitReq a hA)
  (codeIdle, m6) <- runReject m5 (ctxLoginReq b)
  assertEqual "idle session takes no grant" CKR_OPERATION_NOT_INITIALIZED codeIdle
  (resDI, effDI) <- runExecute m6 ((mkRequest F_DigestInit (Just b))
    { reqInput = encodeInitInput (MechanismId 0x250) [OpDigest] False BS.empty })
  m7 <- case effDI of
    EffectCrypto (FxDigestInit _) ->
      case finishEffect defaultRules m6 resDI (EngineOkResource (EngineResourceId 11)) of
        Left rej -> assertFailure ("digest init finish rejected: " ++ show (rejCode rej))
        Right pc -> case publishDelta m6 (pcDelta pc) of
          Left fault -> assertFailure ("digest init fault: " ++ show fault)
          Right m' -> pure m'
    _ -> assertFailure ("expected FxDigestInit, got: " ++ show effDI)
  (codeDigest, m8) <- runReject m7 (ctxLoginReq b)
  assertEqual "plain digest takes no grant" CKR_OPERATION_NOT_INITIALIZED codeDigest
  -- The pending marked key grants — on its session only.
  m9 <- snd <$> runCommit m8 (ctxLoginReq a)
  assertEqual "grant lands on A" LoginContextUser =<< loginOf m9 a
  assertEqual "B stays plain user" LoginUser =<< loginOf m9 b
  -- First data use spends the grant and succeeds.
  (pcS1, m10) <- runSignFinish m9 a "signature" "g27-bytes" 64
  assertEqual "granted sign ok" CKR_OK (pcCode pcS1)
  assertEqual "grant consumed" LoginUser =<< loginOf m10 a
  -- The next operation needs a fresh grant: grantless use denies and
  -- terminates, so a late grant finds nothing.
  (_, m11) <- runCommit m10 (signInitReq a hB)
  (codeNext, m12) <- runReject m11 (dataReq F_Sign a "signature" "g27-bytes" 64)
  assertEqual "next key without fresh grant" CKR_USER_NOT_LOGGED_IN codeNext
  stA12 <- case lookupSession m12 a of
    Nothing -> assertFailure "session lost"
    Just st -> pure st
  assertEqual "grantless slot terminated" [] (activeSlots (ssOps stA12))
  -- A fresh grant for the next key succeeds.
  (_, m13) <- runCommit m12 (signInitReq a hB)
  m14 <- snd <$> runCommit m13 (ctxLoginReq a)
  (pcS2, m15) <- runSignFinish m14 a "signature" "g27-bytes" 64
  assertEqual "fresh-grant sign ok" CKR_OK (pcCode pcS2)
  -- Cancellation before first use kills the grant: the replacement
  -- operation cannot spend it.
  (_, m16) <- runCommit m15 (signInitReq a hA)
  m17 <- snd <$> runCommit m16 (ctxLoginReq a)
  assertEqual "grant lands again" LoginContextUser =<< loginOf m17 a
  m18 <- snd <$> runCommit m17 (cancelReq a 0)
  assertEqual "cancel kills the grant" LoginUser =<< loginOf m18 a
  (_, m19) <- runCommit m18 (signInitReq a hB)
  (codeCancel, m20) <- runReject m19 (dataReq F_Sign a "signature" "g27-bytes" 64)
  assertEqual "replacement needs a fresh grant" CKR_USER_NOT_LOGGED_IN codeCancel
  -- A terminating crypto failure ends the spent operation; the next
  -- one still needs its own grant.
  (_, m21) <- runCommit m20 (signInitReq a hA)
  m22 <- snd <$> runCommit m21 (ctxLoginReq a)
  (resF, _) <- runExecute m22 (dataReq F_Sign a "signature" "g27-bytes" 64)
  m23 <- case finishEffect defaultRules m22 resF
      (EngineFail (BackendBadParam "sign" "boom")) of
    Left rej -> do
      assertEqual "crypto failure code" CKR_GENERAL_ERROR (rejCode rej)
      case publishDelta m22 (rejDelta rej) of
        Left fault -> assertFailure ("failure fault: " ++ show fault)
        Right m' -> pure m'
    Right pc -> assertFailure ("failure committed: " ++ show (pcCode pc))
  (_, m24) <- runCommit m23 (signInitReq a hB)
  (codeFail, m25) <- runReject m24 (dataReq F_Sign a "signature" "g27-bytes" 64)
  assertEqual "post-failure needs a fresh grant" CKR_USER_NOT_LOGGED_IN codeFail
  -- A grant never crosses sessions: B's pending key cannot spend A's.
  (_, m26) <- runCommit m25 (signInitReq a hA)
  m27 <- snd <$> runCommit m26 (ctxLoginReq a)
  m28 <- snd <$> runCommit m27 (cancelReq b 0)
  (_, m29) <- runCommit m28 (signInitReq b hB)
  (codeX, m30) <- runReject m29 (dataReq F_Sign b "signature" "g27-bytes" 64)
  assertEqual "sibling grant does not cross" CKR_USER_NOT_LOGGED_IN codeX
  assertEqual "A still holds its grant" LoginContextUser =<< loginOf m30 a
  -- B's own grant spends on B while A keeps its own.
  (_, m31) <- runCommit m30 (signInitReq b hB)
  m32 <- snd <$> runCommit m31 (ctxLoginReq b)
  (pcS3, m33) <- runSignFinish m32 b "signature" "g27-bytes" 64
  assertEqual "sibling fresh-grant sign ok" CKR_OK (pcCode pcS3)
  assertEqual "A grant untouched" LoginContextUser =<< loginOf m33 a
  (pcS4, m34) <- runSignFinish m33 a "signature" "g27-bytes" 64
  assertEqual "original grant still spends" CKR_OK (pcCode pcS4)
  -- Two simultaneously pending operations take no grant: the grant
  -- binds by uniqueness. Reducing to one grants again.
  (_, m35) <- runCommit m34 (signInitReq a hA)
  (_, m36) <- runCommit m35 (verifyInitReq a hB)
  (codePair, m37) <- runReject m36 (ctxLoginReq a)
  assertEqual "simultaneous pending takes no grant" CKR_OPERATION_NOT_INITIALIZED codePair
  m38 <- snd <$> runCommit m37 (cancelReq a 0x6000)
  m39 <- snd <$> runCommit m38 (ctxLoginReq a)
  (pcS5, m40) <- runSignFinish m39 a "signature" "g27-pair" 64
  assertEqual "reduced grant spends" CKR_OK (pcCode pcS5)
  -- A second pending init while a grant is outstanding refuses, so
  -- no later operation can steal the bound grant; a plain init
  -- still admits and the bound grant still spends.
  (_, m41) <- runCommit m40 (signInitReq a hA)
  m42 <- snd <$> runCommit m41 (ctxLoginReq a)
  (codeSteal, m43) <- runReject m42 (verifyInitReq a hB)
  assertEqual "second pending init refused" CKR_OPERATION_ACTIVE codeSteal
  _ <- runExecute m43 ((mkRequest F_DigestInit (Just a))
    { reqInput = encodeInitInput (MechanismId 0x250) [OpDigest] False BS.empty })
  (pcS6, _) <- runSignFinish m43 a "signature" "g27-steal" 64
  assertEqual "bound grant still spends" CKR_OK (pcCode pcS6)

-- | A spent grant stays spent across nonterminal outputs: short
-- buffers and size queries stage and retry without re-login.
caseContextGrantSurvivesShortBuffer :: IO ()
caseContextGrantSurvivesShortBuffer = do
  (a, m0) <- openSession seeded
  m1 <- loginAs m0 a
  (pcK, m2) <- runCommit m1 (createReq a (authKeyTmpl "key-s"))
  hK <- commitHandle pcK
  (_, m3) <- runCommit m2 (signInitReq a hK)
  m4 <- snd <$> runCommit m3 (ctxLoginReq a)
  -- A short buffer stages; the retry delivers with no fresh grant.
  (pcShort, m5) <- runSignFinish m4 a "signature" "g27-short" 8
  assertEqual "short buffer stages" CKR_BUFFER_TOO_SMALL (pcCode pcShort)
  assertEqual "still plain user" LoginUser =<< loginOf m5 a
  (pcRetry, m6) <- runCommit m5 (dataReq F_Sign a "signature" BS.empty 64)
  assertEqual "retry delivers" CKR_OK (pcCode pcRetry)
  -- A size query stages; the recall delivers with no fresh grant.
  (_, m7) <- runCommit m6 (signInitReq a hK)
  m8 <- snd <$> runCommit m7 (ctxLoginReq a)
  (resQ, _) <- runExecute m8 ((mkRequest F_Sign (Just a))
    { reqInput = "g27-query"
    , reqRegions = [RegionBytes "signature" IntentNull]
    })
  m9 <- case finishEffect defaultRules m8 resQ (EngineOkBytes (BS.replicate 32 0xEE)) of
    Left rej -> assertFailure ("query finish rejected: " ++ show (rejCode rej))
    Right pc -> do
      assertEqual "query stages" CKR_BUFFER_TOO_SMALL (pcCode pc)
      case publishDelta m8 (pcDelta pc) of
        Left fault -> assertFailure ("query fault: " ++ show fault)
        Right m' -> pure m'
  (pcRecall, _) <- runCommit m9 (dataReq F_Sign a "signature" BS.empty 64)
  assertEqual "recall delivers" CKR_OK (pcCode pcRecall)

-- | Cancelling an unrelated selection leaves the grant alone: only
-- the granted operation's own end invalidates it.
caseContextCancelKeepsUnrelatedGrant :: IO ()
caseContextCancelKeepsUnrelatedGrant = do
  (a, m0) <- openSession seeded
  m1 <- loginAs m0 a
  (pcK, m2) <- runCommit m1 (createReq a (authKeyTmpl "key-c"))
  hK <- commitHandle pcK
  (_, m3) <- runCommit m2 (signInitReq a hK)
  m4 <- snd <$> runCommit m3 (ctxLoginReq a)
  -- Cancelling an idle selection is a no-op: the grant survives and
  -- still spends.
  m5 <- snd <$> runCommit m4 (cancelReq a 0x400)
  assertEqual "idle cancel keeps the grant" LoginContextUser =<< loginOf m5 a
  (pcS, _) <- runSignFinish m5 a "signature" "g27-sel" 64
  assertEqual "grant still spends" CKR_OK (pcCode pcS)

-- | Context-PIN lockout performs the full logout transition: the
-- token goes public on every session, private session objects die,
-- private handles stale, and private-key operations retire — while
-- the user role stays locked and the SO role stays independent.
caseContextLockoutLogsOut :: IO ()
caseContextLockoutLogsOut = do
  (a, m0) <- openSession seeded
  (b, m1) <- openSession m0
  m2 <- loginAs m1 a
  (pcK, m3) <- runCommit m2 (createReq a (authKeyTmpl "key-l"))
  hK <- commitHandle pcK
  (pcS, m4) <- runCommit m3 (createReq a [classData, label "lock-priv", privateFlag])
  hS <- commitHandle pcS
  (_, m5) <- runCommit m4 (signInitReq a hK)
  (_, m6) <- runCommit m5 (signInitReq b hK)
  ostK <- mustResolve m6 hK
  -- The first misses refuse without logging out.
  (code1, m7) <- runReject m6 (ctxLoginBadReq a)
  assertEqual "first context miss" CKR_PIN_INCORRECT code1
  assertEqual "still user on A" LoginUser =<< loginOf m7 a
  assertEqual "still user on B" LoginUser =<< loginOf m7 b
  (code2, m8) <- runReject m7 (ctxLoginBadReq a)
  assertEqual "second context miss" CKR_PIN_INCORRECT code2
  -- The locking miss logs the token out.
  (code3, m9) <- runReject m8 (ctxLoginBadReq a)
  assertEqual "third context miss locks" CKR_PIN_LOCKED code3
  assertEqual "A public" LoginPublic =<< loginOf m9 a
  assertEqual "B public" LoginPublic =<< loginOf m9 b
  assertEqual "private session object destroyed" Nothing (resolveHandle m9 hS)
  assertEqual "private key handle dead" Nothing (resolveHandle m9 hK)
  assertBool "private token key survives" (lookupObject m9 (osId ostK) /= Nothing)
  stA9 <- case lookupSession m9 a of
    Nothing -> assertFailure "session lost"
    Just st -> pure st
  assertEqual "A ops retired" [] (activeSlots (ssOps stA9))
  stB9 <- case lookupSession m9 b of
    Nothing -> assertFailure "session lost"
    Just st -> pure st
  assertEqual "B ops retired" [] (activeSlots (ssOps stB9))
  -- The user role is locked (PIN_LOCKED, not ALREADY_LOGGED_IN —
  -- the token is public), while SO login still works.
  (codeU, m10) <- runReject m9 (loginReq a)
  assertEqual "locked user stays locked" CKR_PIN_LOCKED codeU
  mSO <- snd <$> runCommit m10 (soLoginReq a)
  assertEqual "SO independent" LoginSO =<< loginOf mSO a

caseCreatorClose :: IO ()
caseCreatorClose = do
  (a, m0) <- openSession seeded
  (b, m1) <- openSession m0
  (pcS, m2) <- runCommit m1 (createReq a [classData, label "sess"])
  hs <- commitHandle pcS
  (pcT, m3) <- runCommit m2 (createReq a [classData, label "tok", tokenFlagTmpl])
  ht <- commitHandle pcT
  case (resolveHandle m3 hs, resolveHandle m3 ht) of
    (Just sos, Just too) -> do
      assertEqual "session-owned" (Just a) (osOwner sos)
      assertEqual "token-owned" Nothing (osOwner too)
    _ -> assertFailure "setup handles lost"
  -- Cross-session use before the close: B reads both.
  (pcB1, _) <- runCommit m3 (getReq b hs [AttrLabel])
  assertEqual "B reads session object" CKR_OK (pcCode pcB1)
  (pcB2, _) <- runCommit m3 (getReq b ht [AttrLabel])
  assertEqual "B reads token object" CKR_OK (pcCode pcB2)
  (pcF, _) <- runCommit m3 (findReq b [])
  assertEqual "B finds both" [hs, ht] =<< findHandles pcF
  -- Closing the creator destroys its session objects only.
  m4 <- snd <$> runCommit m3 (closeReq a)
  (code, m5) <- runReject m4 (getReq b hs [AttrLabel])
  assertEqual "session object died with creator" CKR_OBJECT_HANDLE_INVALID code
  (pcB3, _) <- runCommit m5 (getReq b ht [AttrLabel])
  assertEqual "token object survives creator close" CKR_OK (pcCode pcB3)
  (pcF2, _) <- runCommit m5 (findReq b [])
  assertEqual "only the token object remains" [ht] =<< findHandles pcF2

secretAes :: ByteString -> [(AttributeType, AttributeValue)]
secretAes keyBytes =
  [ (AttrClass, ValULong (mustClassId "CKO_SECRET_KEY"))
  , (AttrKeyType, ValULong (mustKeyTypeId "CKK_AES"))
  , (AttrValue, ValBytes keyBytes)
  , (AttrToken, ValBool False)
  ]

-- | A minimal RSA public-key template: class, key type, the two
-- import components and the session mark. No protection flags.
publicRsa :: [(AttributeType, AttributeValue)]
publicRsa =
  [ (AttrClass, ValULong (mustClassId "CKO_PUBLIC_KEY"))
  , (AttrKeyType, ValULong (mustKeyTypeId "CKK_RSA"))
  , (AttrModulus, ValBytes (BS.pack [0xDE, 0xAD, 0xBE, 0xEF]))
  , (AttrPublicExponent, ValBytes (BS.pack [1, 0, 1]))
  , (AttrToken, ValBool False)
  ]

-- | A minimal RSA private-key template without protection flags:
-- class, key type, the eight import components and the session
-- mark. The import assembles the value; the absent flags seal it.
privateRsaLegacy :: [(AttributeType, AttributeValue)]
privateRsaLegacy =
  [ (AttrClass, ValULong (mustClassId "CKO_PRIVATE_KEY"))
  , (AttrKeyType, ValULong (mustKeyTypeId "CKK_RSA"))
  , (AttrModulus, ValBytes "legacy-modulus")
  , (AttrPublicExponent, ValBytes "legacy-pubexp")
  , (AttrPrivateExponent, ValBytes "legacy-privexp-guess")
  , (AttrPrime1, ValBytes "legacy-prime1")
  , (AttrPrime2, ValBytes "legacy-prime2")
  , (AttrExponent1, ValBytes "legacy-exp1")
  , (AttrExponent2, ValBytes "legacy-exp2")
  , (AttrCoefficient, ValBytes "legacy-coeff")
  , (AttrToken, ValBool False)
  ]

caseSetAttrFlow :: IO ()
caseSetAttrFlow = do
  (sid, m0) <- openSession seeded
  (pc, m1) <- runCommit m0 (createReq sid [classData, label "old"])
  h <- commitHandle pc
  -- Label change commits and stores.
  (_, m2) <- runCommit m1 (setReq sid h [label "new"])
  case resolveHandle m2 h of
    Nothing -> assertFailure "handle lost after setattr"
    Just ost -> assertEqual "label changed"
      (Just (ValBytes "new")) (Map.lookup AttrLabel (osAttrs ost))
  -- Token promotion commits, reads back, and moves ownership.
  (_, m3) <- runCommit m2 (setReq sid h [(AttrToken, ValBool True)])
  case resolveHandle m3 h of
    Nothing -> assertFailure "handle lost after promotion"
    Just ost -> do
      assertEqual "token reads back" (Just (ValBool True))
        (Map.lookup AttrToken (osAttrs ost))
      assertEqual "token-owned" Nothing (osOwner ost)
  -- Demotion refuses and changes nothing.
  (code, m4) <- runReject m3 (setReq sid h [(AttrToken, ValBool False)])
  assertEqual "demote code" CKR_ATTRIBUTE_READ_ONLY code
  case resolveHandle m4 h of
    Nothing -> assertFailure "handle lost after refused demote"
    Just ost -> assertEqual "still token" (Just (ValBool True))
      (Map.lookup AttrToken (osAttrs ost))

caseSetAttrRatchets :: IO ()
caseSetAttrRatchets = do
  (sid, m0) <- openSession seeded
  (pc, m1) <- runCommit m0
    (createReq sid [classData, label "k", (AttrExtractable, ValBool True)])
  h <- commitHandle pc
  -- Extractable true->false ok, false->true refused.
  (_, m2) <- runCommit m1
    (setReq sid h [(AttrExtractable, ValBool False)])
  (codeE, _) <- runReject m2
    (setReq sid h [(AttrExtractable, ValBool True)])
  assertEqual "extractable escalation" CKR_ATTRIBUTE_READ_ONLY codeE
  -- Sensitive false->true ok, true->false refused.
  (_, m4) <- runCommit m2
    (setReq sid h [(AttrSensitive, ValBool True)])
  (codeS, _) <- runReject m4
    (setReq sid h [(AttrSensitive, ValBool False)])
  assertEqual "sensitive downgrade" CKR_ATTRIBUTE_READ_ONLY codeS
  -- Class and value never mutable.
  (codeC, _) <- runReject m4 (setReq sid h [classData])
  assertEqual "class immutable" CKR_ATTRIBUTE_READ_ONLY codeC
  (codeV, _) <- runReject m4
    (setReq sid h [(AttrValue, ValBytes "x")])
  assertEqual "value immutable" CKR_ATTRIBUTE_READ_ONLY codeV
  -- Mixed valid+invalid is atomic: nothing changes.
  (codeM, m5) <- runReject m4
    (setReq sid h [label "changed", classData])
  assertEqual "mixed code" CKR_ATTRIBUTE_READ_ONLY codeM
  case resolveHandle m5 h of
    Nothing -> assertFailure "handle lost after mixed refuse"
    Just ost -> assertEqual "label kept" (Just (ValBytes "k"))
      (Map.lookup AttrLabel (osAttrs ost))

caseCopyableGate :: IO ()
caseCopyableGate = do
  (sid, m0) <- openSession seeded
  (pc, m1) <- runCommit m0
    (createReq sid [classData, label "nc", (AttrCopyable, ValBool False)])
  h <- commitHandle pc
  (code, _) <- runReject m1 (copyReq sid h [label "copy"])
  assertEqual "non-copyable copy" CKR_ACTION_PROHIBITED code
  (pc2, m2) <- runCommit m1
    (createReq sid [classData, label "c", (AttrCopyable, ValBool True)])
  h2 <- commitHandle pc2
  (pcC, _) <- runCommit m2 (copyReq sid h2 [])
  assertEqual "copyable copy" CKR_OK (pcCode pcC)

caseDestroyableGate :: IO ()
caseDestroyableGate = do
  (sid, m0) <- openSession seeded
  (pc, m1) <- runCommit m0
    (createReq sid [classData, label "nd", (AttrDestroyable, ValBool False)])
  h <- commitHandle pc
  (code, m2) <- runReject m1 (destroyReq sid h)
  assertEqual "non-destroyable destroy" CKR_ACTION_PROHIBITED code
  case resolveHandle m2 h of
    Nothing -> assertFailure "refused destroy killed the object"
    Just _ -> pure ()
  (pc2, m3) <- runCommit m2
    (createReq sid [classData, label "d", (AttrDestroyable, ValBool True)])
  h2 <- commitHandle pc2
  (pcD, _) <- runCommit m3 (destroyReq sid h2)
  assertEqual "destroyable destroy" CKR_OK (pcCode pcD)

-- | COPYABLE and DESTROYABLE only ratchet true->false. From an
-- absent flag (read as true): setting false commits, setting true
-- again is refused, and the gated action is then prohibited. From an
-- explicit false: setting true is refused.
caseCopyDestroyRatchets :: IO ()
caseCopyDestroyRatchets = mapM_ one
  [ (AttrCopyable, \sid h -> copyReq sid h [])
  , (AttrDestroyable, destroyReq)
  ]
  where
    one (flag, act) = do
      (sid, m0) <- openSession seeded
      (pc, m1) <- runCommit m0 (createReq sid [classData, label "ratchet"])
      h <- commitHandle pc
      (pcOff, m2) <- runCommit m1 (setReq sid h [(flag, ValBool False)])
      assertEqual (show flag ++ " absent -> false") CKR_OK (pcCode pcOff)
      (codeOn, m3) <- runReject m2 (setReq sid h [(flag, ValBool True)])
      assertEqual (show flag ++ " false -> true refused")
        CKR_ATTRIBUTE_READ_ONLY codeOn
      (codeAct, _) <- runReject m3 (act sid h)
      assertEqual (show flag ++ " action prohibited") CKR_ACTION_PROHIBITED codeAct
      (pcX, m4) <- runCommit m0
        (createReq sid [classData, label "explicit", (flag, ValBool False)])
      hx <- commitHandle pcX
      (codeX, _) <- runReject m4 (setReq sid hx [(flag, ValBool True)])
      assertEqual (show flag ++ " explicit false -> true refused")
        CKR_ATTRIBUTE_READ_ONLY codeX

caseSecretImportCoherence :: IO ()
caseSecretImportCoherence = do
  (sid, m0) <- openSession seeded
  let key16 = BC8.pack (replicate 16 'k')
  -- Matching VALUE_LEN imports.
  (pcOk, m1) <- runCommit m0
    (createReq sid (secretAes key16 ++ [(AttrValueLen, ValULong 16)]))
  assertEqual "matching import" CKR_OK (pcCode pcOk)
  -- Mismatched VALUE_LEN refuses.
  (codeM, _) <- runReject m1
    (createReq sid (secretAes key16 ++ [(AttrValueLen, ValULong 17)]))
  assertEqual "mismatch code" CKR_TEMPLATE_INCONSISTENT codeM
  -- Absurd VALUE_LEN refuses.
  (codeA, _) <- runReject m1
    (createReq sid (secretAes key16 ++ [(AttrValueLen, ValULong maxBound)]))
  assertEqual "absurd code" CKR_TEMPLATE_INCONSISTENT codeA
  -- Short AES value refuses.
  (codeS, _) <- runReject m1
    (createReq sid (secretAes (BC8.pack (replicate 15 'k'))))
  assertEqual "short AES code" CKR_ATTRIBUTE_VALUE_INVALID codeS
  -- Omitted VALUE_LEN stamps the derived length.
  (pcS, m2) <- runCommit m1 (createReq sid (secretAes key16))
  h <- commitHandle pcS
  case resolveHandle m2 h of
    Nothing -> assertFailure "imported handle lost"
    Just ost -> assertEqual "stamped length" (Just (ValULong 16))
      (Map.lookup AttrValueLen (osAttrs ost))

caseCertCreate :: IO ()
caseCertCreate = do
  (sid, m0) <- openSession seeded
  let tmpl =
        [ (AttrClass, ValULong (mustClassId "CKO_CERTIFICATE"))
        , (AttrCertificateType, ValULong 0)
        , (AttrValue, ValBytes "der")
        , (AttrSubject, ValBytes "cn")
        , (AttrId, ValBytes "id")
        , (AttrToken, ValBool False)
        , (AttrPublicKeyInfo, ValBytes "spki")
        ]
  (pc, m1) <- runCommit m0 (createReq sid tmpl)
  assertEqual "cert import" CKR_OK (pcCode pc)
  h <- commitHandle pc
  case resolveHandle m1 h of
    Nothing -> assertFailure "cert handle lost"
    Just ost -> assertEqual "cert stored verbatim"
      (Map.fromList tmpl) (osAttrs ost)

-- ---------------------------------------------------------------------------
-- Common storage-object attributes: absent means the enforced default
-- ---------------------------------------------------------------------------

-- | The value each common storage-object attribute must report when
-- the creating template omitted it. Written out here, independently
-- of the provider's own table, from what the provider enforces:
-- absent TOKEN is a session object, absent PRIVATE is public, and
-- absent MODIFIABLE, COPYABLE and DESTROYABLE refuse nothing.
-- LABEL is the PKCS#11 empty default.
expectedDefaults :: [(AttributeType, AttributeValue)]
expectedDefaults =
  [ (AttrToken, ValBool False)
  , (AttrPrivate, ValBool False)
  , (AttrModifiable, ValBool True)
  , (AttrCopyable, ValBool True)
  , (AttrDestroyable, ValBool True)
  , (AttrLabel, ValBytes "")
  ]

-- | A value that differs from the expected default, per attribute.
otherThan :: AttributeValue -> AttributeValue
otherThan v = case v of
  ValBool b -> ValBool (not b)
  ValBytes _ -> ValBytes "not-empty"
  ValULong n -> ValULong (n + 1)

-- | Search tag shared by the objects the default cases create: an
-- APPLICATION value, so no case needs the label it inspects.
dfltTag :: ByteString -> (AttributeType, AttributeValue)
dfltTag s = (AttrApplication, ValBytes s)

-- | Storage-class templates that omit every common storage attribute.
storageTemplates :: [(String, [(AttributeType, AttributeValue)])]
storageTemplates =
  [ ("data", [classData, dfltTag "dflt-data"])
  , ("certificate",
      [ (AttrClass, ValULong (mustClassId "CKO_CERTIFICATE"))
      , (AttrCertificateType, ValULong 0)
      , (AttrValue, ValBytes "der")
      , (AttrSubject, ValBytes "cn")
      , dfltTag "dflt-cert"
      ])
  , ("secret key",
      [ (AttrClass, ValULong (mustClassId "CKO_SECRET_KEY"))
      , (AttrKeyType, ValULong (mustKeyTypeId "CKK_AES"))
      , (AttrValue, ValBytes (BS.replicate 16 7))
      , dfltTag "dflt-secret"
      ])
  ]

-- | Per class and per attribute: a read of the absent attribute
-- returns CKR_OK with the enforced default, alone and in one read.
caseStorageDefaultsRead :: IO ()
caseStorageDefaultsRead = mapM_ one storageTemplates
  where
    one (cls, tmpl) = do
      (sid, m0) <- openSession seeded
      (pc, m1) <- runCommit m0 (createReq sid tmpl)
      h <- commitHandle pc
      mapM_ (readOne cls sid m1 h) expectedDefaults
      (pcAll, _) <- runCommit m1 (getReq sid h (map fst expectedDefaults))
      assertEqual (cls ++ ": all defaults in one read")
        [encodeValue v | (_, v) <- expectedDefaults]
        [outBytes o | o <- pcOutputs pcAll]
    readOne cls sid m h (t, v) = case planCall defaultRules m (getReq sid h [t]) of
      Immediate pcG -> do
        assertEqual (cls ++ " " ++ show t ++ ": code") CKR_OK (pcCode pcG)
        assertEqual (cls ++ " " ++ show t ++ ": value")
          [encodeValue v] [outBytes o | o <- pcOutputs pcG]
      Reject rej -> assertFailure
        (cls ++ " " ++ show t ++ ": absent attribute must read its default, got "
          ++ show (rejCode rej))
      Execute _ _ -> assertFailure "read must not execute"

-- | Per class and per attribute: a find naming the reported default
-- matches the object, and a find naming any other value does not.
caseStorageDefaultsFind :: IO ()
caseStorageDefaultsFind = mapM_ one storageTemplates
  where
    one (cls, tmpl) = do
      (sid, m0) <- openSession seeded
      (pc, m1) <- runCommit m0 (createReq sid tmpl)
      h <- commitHandle pc
      let tag = [e | e@(AttrApplication, _) <- tmpl]
      mapM_ (findOne cls sid m1 h tag) expectedDefaults
    findOne cls sid m h tag (t, v) = do
      (pcHit, _) <- runCommit m (findReq sid (tag ++ [(t, v)]))
      hits <- findHandles pcHit
      assertEqual (cls ++ " " ++ show t ++ ": default matches") [h] hits
      (pcMiss, _) <- runCommit m (findReq sid (tag ++ [(t, otherThan v)]))
      misses <- findHandles pcMiss
      assertEqual (cls ++ " " ++ show t ++ ": other value misses") [] misses

-- | What is reported is what is enforced: the object read as
-- PRIVATE=false is visible to a public session, TOKEN=false is
-- session-owned, MODIFIABLE=true accepts a label change,
-- COPYABLE=true copies, DESTROYABLE=true destroys, and writing a
-- reported default back is a no-op write that succeeds.
caseStorageDefaultsEnforced :: IO ()
caseStorageDefaultsEnforced = do
  (sid, m0) <- openSession seeded
  (pc, m1) <- runCommit m0 (createReq sid [classData, dfltTag "enforced"])
  h <- commitHandle pc
  ost <- mustResolve m1 h
  st <- case lookupSession m1 sid of
    Just s -> pure s
    Nothing -> assertFailure "session lost"
  assertBool "public session sees the PRIVATE=false object" (objectVisible st ost)
  assertEqual "TOKEN=false object is session-owned" (Just sid) (osOwner ost)
  (pcFind, _) <- runCommit m1 (findReq sid [dfltTag "enforced"])
  found <- findHandles pcFind
  assertEqual "logged-out find sees it" [h] found
  (_, mSet) <- runCommit m1 (setReq sid h [label "changed"])
  _ <- mustResolve mSet h
  (pcCopy, _) <- runCommit m1 (copyReq sid h [])
  assertEqual "COPYABLE=true copies" CKR_OK (pcCode pcCopy)
  (pcDestroy, _) <- runCommit m1 (destroyReq sid h)
  assertEqual "DESTROYABLE=true destroys" CKR_OK (pcCode pcDestroy)
  -- Writing back a reported default is a no-op write that succeeds
  -- for every settable common attribute. PRIVATE and MODIFIABLE are
  -- not settable after creation, for any value.
  mapM_ (\(t, v) ->
          let code = case planCall defaultRules m1 (setReq sid h [(t, v)]) of
                Immediate pcW -> pcCode pcW
                Reject rej -> rejCode rej
                Execute _ _ -> CKR_GENERAL_ERROR
          in assertEqual ("write back " ++ show t) CKR_OK code)
    [ e | e@(t, _) <- expectedDefaults
        , t `elem` [AttrToken, AttrCopyable, AttrDestroyable, AttrLabel] ]
  mapM_ (\(t, v) -> do
          (code, _) <- runReject m1 (setReq sid h [(t, v)])
          assertEqual ("not settable " ++ show t) CKR_ATTRIBUTE_READ_ONLY code)
    [ e | e@(t, _) <- expectedDefaults, t `elem` [AttrPrivate, AttrModifiable] ]

-- | Reporting and matching read effective values; they never write
-- them. The stored map stays exactly the creation template after
-- create, read, find, and copy, so durable bytes do not change.
caseStorageDefaultsNotStored :: IO ()
caseStorageDefaultsNotStored = do
  (sid, m0) <- openSession seeded
  let tmpl = [classData, dfltTag "not-stored"]
  (pc, m1) <- runCommit m0 (createReq sid tmpl)
  h <- commitHandle pc
  (_, m2) <- runCommit m1 (getReq sid h (map fst expectedDefaults))
  (_, m3) <- runCommit m2 (findReq sid (dfltTag "not-stored" : expectedDefaults))
  (pcC, m4) <- runCommit m3 (copyReq sid h [])
  hc <- commitHandle pcC
  ost <- mustResolve m4 h
  assertEqual "stored map is the template" (Map.fromList tmpl) (osAttrs ost)
  cpy <- mustResolve m4 hc
  assertEqual "copy stores the source map" (Map.fromList tmpl) (osAttrs cpy)

-- | Explicitly stored values win over the defaults, on read and find.
caseStorageDefaultsExplicitWins :: IO ()
caseStorageDefaultsExplicitWins = do
  (sid, m0) <- openSession seeded
  m1 <- loginAs m0 sid
  let explicit =
        [ (AttrPrivate, ValBool True)
        , (AttrModifiable, ValBool False)
        , (AttrCopyable, ValBool False)
        , (AttrDestroyable, ValBool False)
        , (AttrLabel, ValBytes "explicit")
        ]
  (pc, m2) <- runCommit m1 (createReq sid (classData : dfltTag "explicit" : explicit))
  h <- commitHandle pc
  (pcG, _) <- runCommit m2 (getReq sid h (map fst explicit))
  assertEqual "explicit values read back"
    [encodeValue v | (_, v) <- explicit] [outBytes o | o <- pcOutputs pcG]
  mapM_ (\(t, v) -> do
          (pcF, _) <- runCommit m2 (findReq sid [dfltTag "explicit", (t, otherThan v)])
          hits <- findHandles pcF
          assertEqual ("default does not match explicit " ++ show t) [] hits)
    explicit

-- | Only storage objects own the common storage attributes: a
-- hardware feature or mechanism object created without them still
-- reports them unavailable and never matches a default in find.
caseStorageDefaultsNonStorage :: IO ()
caseStorageDefaultsNonStorage = mapM_ one
  [ ("CKO_HW_FEATURE", mustClassId "CKO_HW_FEATURE")
  , ("CKO_MECHANISM", mustClassId "CKO_MECHANISM")
  ]
  where
    one (name, cls) = do
      (sid, m0) <- openSession seeded
      let tag = dfltTag (BC8.pack name)
      (pc, m1) <- runCommit m0
        (createReq sid [(AttrClass, ValULong cls), tag])
      h <- commitHandle pc
      mapM_ (\(t, v) -> do
              (code, _) <- runReject m1 (getReq sid h [t])
              assertEqual (name ++ " " ++ show t ++ " unavailable")
                CKR_ATTRIBUTE_TYPE_INVALID code
              (pcF, _) <- runCommit m1 (findReq sid [tag, (t, v)])
              hits <- findHandles pcF
              assertEqual (name ++ " " ++ show t ++ " no default match") [] hits)
        expectedDefaults

-- | Failure precedence is unchanged for attributes that really are
-- unavailable: sensitive still dominates, an attribute a data object
-- does not own (CKA_KEY_TYPE) still fails the read, and the defaulted attribute rides
-- along as a readable value in the same outcome.
caseStorageDefaultsPrecedence :: IO ()
caseStorageDefaultsPrecedence = do
  (sid, m0) <- openSession seeded
  (pc, m1) <- runCommit m0
    (createReq sid
      [ classData
      , (AttrSensitive, ValBool True)
      , (AttrValue, ValBytes "s3cret")
      ])
  h <- commitHandle pc
  (rej, _) <- runRejectFull m1 (getReq sid h [AttrValue, AttrPrivate, AttrKeyType])
  assertEqual "sensitive dominates" CKR_ATTRIBUTE_SENSITIVE (rejCode rej)
  assertEqual "default rides along" [encodeValue (ValBool False)]
    [outBytes o | o <- rejOutputs rej]
  assertEqual "per-attribute reasons"
    ["AttrValue: sensitive", "AttrPrivate: ok", "AttrKeyType: unavailable"]
    (rejReasons rej)
  (rej2, _) <- runRejectFull m1 (getReq sid h [AttrPrivate, AttrKeyType])
  assertEqual "unavailable still fails" CKR_ATTRIBUTE_TYPE_INVALID (rejCode rej2)
  assertEqual "default still delivered" [encodeValue (ValBool False)]
    [outBytes o | o <- rejOutputs rej2]

-- ---------------------------------------------------------------------------
-- Role matrix: role x session mode x visibility x lifetime for
-- create/copy/set/destroy, with the exact refusal codes.
-- ---------------------------------------------------------------------------
--
-- Expected codes (each table cell runs on a fresh model; the setup
-- session creates the target, then the test login — if any — is the
-- only one, since token login is token-global):
--
--   create: public mints public only (private answers
--     CKR_USER_NOT_LOGGED_IN); the user mints everything; SO
--     administers public objects only (private answers
--     CKR_USER_NOT_LOGGED_IN, like public); token targets on a
--     read-only session answer CKR_SESSION_READ_ONLY; the role
--     check precedes the mode check, so public-RO private shapes
--     answer CKR_USER_NOT_LOGGED_IN. Public read/write sessions
--     mutating ordinary public token objects is the retained
--     baseline (OASIS PKCS#11 3.2 sections 5.7.1-5.7.3, usage
--     guide 2.6.3-2.6.4): no universal login check exists, and
--     the positive control below pins create/copy/set/destroy
--     all committing there.
--   copy/set/destroy: sampled — one cell per (role, mode,
--     visibility, lifetime) refusal class — since copy/set/destroy
--     share the create admission gates plus visibility.
--   trusted: only SO mints or marks TRUSTED=true; admission
--     outranks the trusted check (public-RO set of TRUSTED=true
--     on a public token target answers CKR_SESSION_READ_ONLY).
--   find: public and SO find-all see exactly the public handle;
--     logout kills private bindings, so a remembered private
--     handle answers CKR_OBJECT_HANDLE_INVALID afterwards.
--   login exclusion: SO login while any read-only session is
--     open answers CKR_SESSION_READ_ONLY_EXISTS.
--
-- Read-only-token has no cell: the token-level write-protect flag
-- is unoffered (it exists only in the vendored headers), so there
-- is no provider behavior to pin — recorded here, never as a pass.

roleCells :: [Cell]
roleCells =
  [ Cell "01 public/RW create pub+sess" MPublic False False False OpCreate (Right ())
  , Cell "02 public/RW create pub+tok" MPublic False False True OpCreate (Right ())
  , Cell "03 public/RW create priv+sess" MPublic False True False OpCreate (Left CKR_USER_NOT_LOGGED_IN)
  , Cell "04 public/RW create priv+tok" MPublic False True True OpCreate (Left CKR_USER_NOT_LOGGED_IN)
  , Cell "05 public/RO create pub+sess" MPublic True False False OpCreate (Right ())
  , Cell "06 public/RO create pub+tok" MPublic True False True OpCreate (Left CKR_SESSION_READ_ONLY)
  , Cell "07 public/RO create priv+sess" MPublic True True False OpCreate (Left CKR_USER_NOT_LOGGED_IN)
  , Cell "08 public/RO create priv+tok" MPublic True True True OpCreate (Left CKR_USER_NOT_LOGGED_IN)
  , Cell "09 user/RW create pub+sess" MUser False False False OpCreate (Right ())
  , Cell "10 user/RW create pub+tok" MUser False False True OpCreate (Right ())
  , Cell "11 user/RW create priv+sess" MUser False True False OpCreate (Right ())
  , Cell "12 user/RW create priv+tok" MUser False True True OpCreate (Right ())
  , Cell "13 user/RO create pub+sess" MUser True False False OpCreate (Right ())
  , Cell "14 user/RO create pub+tok" MUser True False True OpCreate (Left CKR_SESSION_READ_ONLY)
  , Cell "15 user/RO create priv+sess" MUser True True False OpCreate (Right ())
  , Cell "16 user/RO create priv+tok" MUser True True True OpCreate (Left CKR_SESSION_READ_ONLY)
  , Cell "17 SO/RW create pub+sess" MSO False False False OpCreate (Right ())
  , Cell "18 SO/RW create pub+tok" MSO False False True OpCreate (Right ())
  , Cell "19 SO/RW create priv+sess" MSO False True False OpCreate (Left CKR_USER_NOT_LOGGED_IN)
  , Cell "20 SO/RW create priv+tok" MSO False True True OpCreate (Left CKR_USER_NOT_LOGGED_IN)
  , Cell "22 public/RW copy to pub+tok" MPublic False False True OpCopy (Right ())
  , Cell "23 user/RW copy to pub+tok" MUser False False True OpCopy (Right ())
  , Cell "24 SO/RW copy to pub+tok" MSO False False True OpCopy (Right ())
  , Cell "25 public/RO copy to pub+tok" MPublic True False True OpCopy (Left CKR_SESSION_READ_ONLY)
  , Cell "26 public/RW copy to priv+sess" MPublic False True False OpCopy (Left CKR_USER_NOT_LOGGED_IN)
  , Cell "27 user/RW copy to priv+sess" MUser False True False OpCopy (Right ())
  , Cell "28 public/RW set on pub+tok" MPublic False False True OpSet (Right ())
  , Cell "29 public/RO set on pub+tok" MPublic True False True OpSet (Left CKR_SESSION_READ_ONLY)
  , Cell "30 user/RW set on pub+tok" MUser False False True OpSet (Right ())
  , Cell "31 user/RW set on priv+sess" MUser False True False OpSet (Right ())
  , Cell "34 public/RW destroy pub+tok" MPublic False False True OpDestroy (Right ())
  , Cell "35 public/RO destroy pub+tok" MPublic True False True OpDestroy (Left CKR_SESSION_READ_ONLY)
  , Cell "36 user/RW destroy pub+sess" MUser False False False OpDestroy (Right ())
  , Cell "37 user/RO destroy pub+sess" MUser True False False OpDestroy (Right ())
  , Cell "43 SO/RW set on pub+tok" MSO False False True OpSet (Right ())
  , Cell "44 SO/RW destroy pub+tok" MSO False False True OpDestroy (Right ())
  ]

caseRoleMatrix :: IO ()
caseRoleMatrix = do
  mapM_ runCell roleCells
  -- Cell 21: SO login is refused while any read-only session is
  -- open (the caseSoRoConflict precedent).
  (_ro, m1) <- openSessionMode slot0 True seeded
  (rw, m2) <- openSessionMode slot0 False m1
  (code, _) <- runReject m2 (soLoginReq rw)
  assertEqual "cell 21 SO login refused while RO open" CKR_SESSION_READ_ONLY_EXISTS code

-- | The permitted-public-RW-mutation positive control: cells 2/22/28/34
-- on ONE public read/write session, with a label readback after each
-- mutation (the readback after destroy is the refusal itself: the
-- handle no longer resolves).
casePublicRwPositive :: IO ()
casePublicRwPositive = do
  (sid, m0) <- openSessionMode slot0 False seeded
  (pcC, m1) <- runCommit m0
    (createReq sid [classData, label "pub-tok", isToken True, isPrivate False])
  assertEqual "public RW create pub+tok" CKR_OK (pcCode pcC)
  hTok <- commitHandle pcC
  (pcG1, _) <- runCommit m1 (getReq sid hTok [AttrLabel])
  assertEqual "create label reads back"
    [encodeValue (ValBytes "pub-tok")] [outBytes o | o <- pcOutputs pcG1]
  (pcS, m2) <- runCommit m1
    (createReq sid [classData, label "src", isToken False, isPrivate False])
  hSrc <- commitHandle pcS
  (pcCp, m3) <- runCommit m2
    (copyReq sid hSrc [label "copy-tok", isToken True, isPrivate False])
  assertEqual "public RW copy to pub+tok" CKR_OK (pcCode pcCp)
  hCopy <- commitHandle pcCp
  (pcG2, _) <- runCommit m3 (getReq sid hCopy [AttrLabel])
  assertEqual "copy label reads back"
    [encodeValue (ValBytes "copy-tok")] [outBytes o | o <- pcOutputs pcG2]
  (pcSet, m4) <- runCommit m3 (setReq sid hTok [label "set-tok"])
  assertEqual "public RW set on pub+tok" CKR_OK (pcCode pcSet)
  (pcG3, _) <- runCommit m4 (getReq sid hTok [AttrLabel])
  assertEqual "set label reads back"
    [encodeValue (ValBytes "set-tok")] [outBytes o | o <- pcOutputs pcG3]
  (pcD, m5) <- runCommit m4 (destroyReq sid hTok)
  assertEqual "public RW destroy pub+tok" CKR_OK (pcCode pcD)
  (codeG, _) <- runReject m5 (getReq sid hTok [AttrLabel])
  assertEqual "destroyed handle reads back invalid" CKR_OBJECT_HANDLE_INVALID codeG

-- | Trusted objects admit only the security officer: user create/set
-- of TRUSTED=true refuse, SO create/set commit, and admission
-- outranks the trusted check (a public read-only set of
-- TRUSTED=true on a public token target reports the mode). The
-- cells use a secret-key class, where TRUSTED is defined (it is
-- not defined for data objects).
caseTrustedSoOnly :: IO ()
caseTrustedSoOnly = do
  let secretClass = (AttrClass, ValULong (mustClassId "CKO_SECRET_KEY"))
      secretType = (AttrKeyType, ValULong (mustKeyTypeId "CKK_GENERIC_SECRET"))
      secretBytes = (AttrValue, ValBytes "0123456789abcdef0123456789abcdef")
  (sid, m0) <- openSessionMode slot0 False seeded
  mU <- loginAs m0 sid
  (codeC, m1) <- runReject mU
    (createReq sid [secretClass, secretType, secretBytes, label "t-user", isToken True, isPrivate False, (AttrTrusted, ValBool True)])
  assertEqual "user create TRUSTED refused" CKR_ATTRIBUTE_READ_ONLY codeC
  mP1 <- snd <$> runCommit m1 (logoutReq sid)
  mSO <- loginAsSo mP1 sid
  (pcT, m2) <- runCommit mSO
    (createReq sid [secretClass, secretType, secretBytes, label "t-so", isToken True, isPrivate False, (AttrTrusted, ValBool True)])
  assertEqual "SO create TRUSTED commits" CKR_OK (pcCode pcT)
  hT <- commitHandle pcT
  ostT <- mustResolve m2 hT
  assertEqual "SO trusted stored"
    (Just (ValBool True)) (Map.lookup AttrTrusted (osAttrs ostT))
  (pcP, m3) <- runCommit m2
    (createReq sid [secretClass, secretType, secretBytes, label "plain", isToken True, isPrivate False])
  hP <- commitHandle pcP
  mP2 <- snd <$> runCommit m3 (logoutReq sid)
  mU2 <- loginAs mP2 sid
  (codeS, m4) <- runReject mU2 (setReq sid hP [(AttrTrusted, ValBool True)])
  assertEqual "user set TRUSTED refused" CKR_ATTRIBUTE_READ_ONLY codeS
  mP3 <- snd <$> runCommit m4 (logoutReq sid)
  mSO2 <- loginAsSo mP3 sid
  (pcS, m5) <- runCommit mSO2 (setReq sid hP [(AttrTrusted, ValBool True)])
  assertEqual "SO set TRUSTED commits" CKR_OK (pcCode pcS)
  mP4 <- snd <$> runCommit m5 (logoutReq sid)
  (ro, m6) <- openSessionMode slot0 True mP4
  (codeP, _) <- runReject m6 (setReq ro hP [(AttrTrusted, ValBool True)])
  assertEqual "RO set TRUSTED reports mode first" CKR_SESSION_READ_ONLY codeP

-- | Find visibility follows the login state: with one public and one
-- private token object present, public and SO find-all return
-- exactly the public handle; after logout the remembered private
-- handle refuses — logout kills private bindings, so stale and
-- invisible agree on CKR_OBJECT_HANDLE_INVALID.
caseVisibilityFindCounts :: IO ()
caseVisibilityFindCounts = do
  (sid, m0) <- openSessionMode slot0 False seeded
  mU <- loginAs m0 sid
  (pcU, m1) <- runCommit mU
    (createReq sid [classData, label "vis-pub", isToken True, isPrivate False])
  hu <- commitHandle pcU
  (pcK, m2) <- runCommit m1
    (createReq sid [classData, label "vis-priv", isToken True, isPrivate True])
  hk <- commitHandle pcK
  mP <- snd <$> runCommit m2 (logoutReq sid)
  (pcF1, _) <- runCommit mP (findReq sid [])
  foundP <- findHandles pcF1
  assertEqual "public find sees public only" [hu] foundP
  mSO <- loginAsSo mP sid
  (pcF2, _) <- runCommit mSO (findReq sid [])
  foundSO <- findHandles pcF2
  assertEqual "SO find sees public only" [hu] foundSO
  mP2 <- snd <$> runCommit mSO (logoutReq sid)
  (codeD, _) <- runReject mP2 (destroyReq sid hk)
  assertEqual "remembered private handle invalid after logout" CKR_OBJECT_HANDLE_INVALID codeD
