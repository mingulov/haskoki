-- REGISTRATION: haskoki-logout-oracle-tests
{- | Independent logout/object-lifetime policy oracle plus one
mechanism-variant known-answer check.

The oracle re-derives the logout rule from the OASIS contract text
(PKCS#11 3.2 @5.6.10@: logout destroys the private session objects
on the slot; token objects and public session objects survive; the
cached operations bound to a private key on the slot retire while
unkeyed and public-key operations survive) in its own miniature
model ('OracleObject', 'oracleSurvivesLogout', 'oracleRetiresOp').
It drives the real planners ('planCall', 'publishDelta') as the
system under test, then observes the outcome through raw record
fields, 'Data.Map.Strict' lookups, and the abstract-state
projectors ('lookupSingle', 'commonOf', 'commonKey',
'activeSlots') only. It never calls the rule's implementation
helpers ('Haskoki.Object.objectPrivate',
'Haskoki.Object.objectToken', 'Haskoki.Object.objectVisible',
'Haskoki.Object.resolveHandle', 'retirePrivateKeyOps', or the
logout planner itself), so a weakened rule fails here rather than
being re-described. Key privacy for the retirement prediction
comes from the oracle's own setup records, never from the
implementation's classifiers.

Request construction ('encodeTemplate', the 'Request' record)
is shared harness plumbing, not the rule: the independence
boundary is the prediction plus the observation, both written
by hand from the standard.

The mechanism-variant known-answer group pins one variant,
CKM_AES_GCM (@0x1087@), end to end: the exact init-frame bytes,
the decoded triple, and the cipher shape. Every expected value
below is hand-derived from the OASIS mechanism number and the
documented frame layout (@mech:u64 permits:u16 flags:u8
params:bytes@, the parameter tail an opaque 13-byte fixture);
none was printed from the implementation. A CKM_AES_CBC control
vector pins one long-settled meaning so any codec drift fails
loudly. No codec source was touched for this module; the existing
codec law suite still passes unchanged.
-}
{-# LANGUAGE OverloadedStrings #-}
module Main (main) where

import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import Data.List (sort, sortOn)
import qualified Data.Map.Strict as Map
import Data.Maybe (isJust)
import Test.Tasty (defaultMain, testGroup)
import Test.Tasty.HUnit (assertBool, assertEqual, assertFailure, testCase)

import Haskoki.Attribute (AttributeType (..), AttributeValue (..))
import Haskoki.Attribute.Generated (mustClassId, mustKeyTypeId)
import Haskoki.Model
  ( HandleBinding (..)
  , Model (..)
  , ObjectState (..)
  , SessionState (..)
  , addToken
  , emptyModel
  )
import Haskoki.Object (encodeTemplate)
import Haskoki.Operation
  ( SlotKind (..)
  , activeSlots
  , commonKey
  , commonOf
  , lookupSingle
  )
import Haskoki.Operation.Codec (cipherShapeFor, decodeInitInput, encodeInitInput)
import Haskoki.Operation.State (CipherSpec (..), SessionOps)
import Haskoki.Outcome
  ( EffectRequest
  , EngineResult (..)
  , PlanResult (..)
  , PreparedCommit (..)
  , Rejection (..)
  , Reservation
  )
import Haskoki.Registry (MechanismId (..), Operation (..))
import Haskoki.Request (FunctionId (..), Request (..))
import Haskoki.Rules (defaultRules)
import Haskoki.Session (SessionLogin (..), TokenAuth (..))
import Haskoki.Transition (finishEffect, planCall, publishDelta)
import Haskoki.Types
  ( EngineResourceId (..)
  , ExternalHandle
  , ObjectId
  , Pkcs11Version (..)
  , ReturnCode (..)
  , SessionId (..)
  , SlotId (..)
  )

main :: IO ()
main = defaultMain $ testGroup "logout oracle and variant KAT"
  [ testGroup "logout policy oracle"
      [ testCase "matrix: logout destroys exactly private session objects" caseMatrix
      , testCase "retirement: private-key operations retire, the rest survive" caseRetirement
      , testCase "refusal: logout while public changes nothing" caseRefusedWhenPublic
      , testCase "walkthrough: refusal then success without resurrection" caseWalkthrough
      , testCase "rediscovery: fresh handle for survivors, none for the destroyed" caseRediscovery
      ]
  , testGroup "mechanism variant KAT"
      [ testCase "GCM init frame decodes to the pinned triple" caseGcmDecode
      , testCase "GCM init frame encodes to the pinned bytes" caseGcmEncode
      , testCase "GCM cipher shape is the unit stream width" caseGcmShape
      , testCase "CBC control vector is stable" caseCbcControl
      , testCase "reserved bits and truncation refuse" caseFrameRefusals
      ]
  ]

-- ---------------------------------------------------------------------------
-- The independent oracle: its own model of the rule
-- ---------------------------------------------------------------------------

-- | The oracle's own record of one setup object: what the oracle
-- asked for, in its own words. Deliberately not 'ObjectState'.
data OracleObject = OracleObject
  { ooLabel :: !ByteString
  , ooPrivate :: !Bool
  , ooToken :: !Bool
  , ooSlot :: !SlotId
  } deriving (Eq, Show)

-- | The oracle's prediction, re-derived from the contract text: a
-- slot logout destroys exactly the private session objects seated
-- on that slot. Anything on another slot, anything public, and
-- anything token-owned survives.
oracleSurvivesLogout :: SlotId -> OracleObject -> Bool
oracleSurvivesLogout logoutSlot oo =
  ooSlot oo /= logoutSlot || ooToken oo || not (ooPrivate oo)

-- | The oracle's handle prediction: handles bound to a private
-- object on the logout slot go stale (destroyed objects lose the
-- object; surviving token objects are re-discoverable only under
-- a fresh handle). Every other handle stays fresh.
oracleHandleStale :: SlotId -> OracleObject -> Bool
oracleHandleStale logoutSlot oo =
  ooSlot oo == logoutSlot && ooPrivate oo

-- | The oracle's retirement prediction, re-derived from the
-- contract text: on the logout slot, a cached operation retires
-- exactly when its key resolves to an object the oracle recorded
-- as private, or to no live object at all (fail closed).
-- Unkeyed operations and every operation on another slot survive.
-- The privacy table is the oracle's own setup facts.
oracleRetiresOp :: SlotId -> [(ObjectId, Bool)] -> Model -> SlotId -> Maybe ObjectId -> Bool
oracleRetiresOp logoutSlot privOf model opSlot mKey
  | opSlot /= logoutSlot = False
  | otherwise = case mKey of
      Nothing -> False
      Just oid -> case lookup oid privOf of
        Just priv -> priv
        Nothing -> Map.notMember oid (mObjects model)

-- ---------------------------------------------------------------------------
-- Raw-map observers (no implementation predicates)
-- ---------------------------------------------------------------------------

-- | Locate an object by its label through a raw attribute-map scan.
findOidByLabel :: Model -> ByteString -> Maybe ObjectId
findOidByLabel m lbl =
  Map.foldrWithKey
    (\oid ost acc -> case acc of
      Just found -> Just found
      Nothing ->
        if Map.lookup AttrLabel (osAttrs ost) == Just (ValBytes lbl)
          then Just oid
          else Nothing
    )
    Nothing
    (mObjects m)

-- | Every handle binding naming an object, in handle order.
bindingsFor :: Model -> ObjectId -> [(ExternalHandle, HandleBinding)]
bindingsFor m oid =
  sortOn fst
    [ (h, b)
    | (h, b) <- Map.toList (mHandles m)
    , hbObject b == oid
    ]

-- | Binding freshness by direct generation comparison: 'Nothing'
-- when the binding or its object is gone, 'Just' whether the
-- generations still match.
bindingFreshIn :: Model -> ExternalHandle -> Maybe Bool
bindingFreshIn m h = do
  b <- Map.lookup h (mHandles m)
  ost <- Map.lookup (hbObject b) (mObjects m)
  pure (hbGeneration b == osGeneration ost)

sessionLoginOf :: Model -> SessionId -> Maybe SessionLogin
sessionLoginOf m sid = ssLogin <$> Map.lookup sid (mSessions m)

tokenLoggedIn :: Model -> SlotId -> Maybe Bool
tokenLoggedIn m slot = isJust . taLogin <$> Map.lookup slot (mTokenAuth m)

-- ---------------------------------------------------------------------------
-- Harness: drive the public planner path
-- ---------------------------------------------------------------------------

slot0 :: SlotId
slot0 = SlotId 0

slot1 :: SlotId
slot1 = SlotId 1

seeded :: Model
seeded = addToken (addToken emptyModel slot0) slot1

mkRequest :: FunctionId -> Maybe SessionId -> Request
mkRequest fun mSid = Request
  { reqVersion = Pkcs11_3_2
  , reqFunction = fun
  , reqSession = mSid
  , reqHandle = Nothing
  , reqInput = mempty
  , reqRegions = []
  }

openSessionOn :: SlotId -> Model -> IO (SessionId, Model)
openSessionOn (SlotId n) model = do
  let req = (mkRequest F_OpenSession Nothing)
        { reqInput = "slot=" <> slotNum <> ",rw" }
      slotNum = case n of
        0 -> "0"
        1 -> "1"
        _ -> "9"
  case planCall defaultRules model req of
    Immediate pc -> case publishDelta model (pcDelta pc) of
      Left fault -> assertFailure ("open delta fault: " ++ show fault)
      Right m' -> pure (SessionId (mNextSession model), m')
    other -> assertFailure ("open failed: " ++ show other)

loginAs :: Model -> SessionId -> IO Model
loginAs model sid = snd <$> runCommit model (loginReq sid)

loginReq :: SessionId -> Request
loginReq sid = (mkRequest F_Login (Just sid)) { reqInput = "user:ok" }

logoutReq :: SessionId -> Request
logoutReq sid = mkRequest F_Logout (Just sid)

createReq :: SessionId -> [(AttributeType, AttributeValue)] -> Request
createReq sid tmpl =
  (mkRequest F_CreateObject (Just sid)) { reqInput = encodeTemplate tmpl }

findReq :: SessionId -> [(AttributeType, AttributeValue)] -> Request
findReq sid tmpl =
  (mkRequest F_FindObjects (Just sid)) { reqInput = encodeTemplate tmpl }

runCommit :: Model -> Request -> IO (PreparedCommit, Model)
runCommit model req =
  case planCall defaultRules model req of
    Immediate pc -> case publishDelta model (pcDelta pc) of
      Left fault -> assertFailure ("delta fault: " ++ show fault)
      Right m' -> pure (pc, m')
    Reject rej -> assertFailure ("expected commit, rejected: " ++ show (rejCode rej))
    Execute _ _ -> assertFailure "expected commit, got Execute"

runExecute :: Model -> Request -> IO (Reservation, EffectRequest)
runExecute model req =
  case planCall defaultRules model req of
    Execute res eff -> pure (res, eff)
    other -> assertFailure ("expected Execute, got: " ++ show other)

initReq :: FunctionId -> SessionId -> ExternalHandle -> MechanismId -> [Operation] -> Request
initReq fid sid h mech permits =
  (mkRequest fid (Just sid))
    { reqHandle = Just h
    , reqInput = encodeInitInput mech permits False BS.empty
    }

-- | Open an unkeyed digest stream, finishing the allocation effect
-- with a stub resource id the way the white-box suites do: the
-- stream, not the backend, is what this oracle observes.
digestInit :: Model -> SessionId -> IO Model
digestInit model sid = do
  let req = (mkRequest F_DigestInit (Just sid))
        { reqInput = encodeInitInput (MechanismId 0x250) [OpDigest] False BS.empty }
  (res, _) <- runExecute model req
  case finishEffect defaultRules model res (EngineOkResource (EngineResourceId 11)) of
    Left rej -> assertFailure ("digest init finish rejected: " ++ show (rejCode rej))
    Right pc -> case publishDelta model (pcDelta pc) of
      Left fault -> assertFailure ("digest init fault: " ++ show fault)
      Right m' -> pure m'

classData :: (AttributeType, AttributeValue)
classData = (AttrClass, ValULong 0)

label :: ByteString -> (AttributeType, AttributeValue)
label s = (AttrLabel, ValBytes s)

privateFlag :: (AttributeType, AttributeValue)
privateFlag = (AttrPrivate, ValBool True)

tokenFlag :: (AttributeType, AttributeValue)
tokenFlag = (AttrToken, ValBool True)

mustOid :: Model -> ByteString -> IO ObjectId
mustOid m lbl = case findOidByLabel m lbl of
  Nothing -> assertFailure ("setup object lost: " ++ show lbl)
  Just oid -> pure oid

mustSession :: Model -> SessionId -> IO SessionState
mustSession m sid = case Map.lookup sid (mSessions m) of
  Nothing -> assertFailure ("setup session lost: " ++ show sid)
  Just st -> pure st

mustHandle :: Model -> ObjectId -> IO ExternalHandle
mustHandle m oid = case map fst (bindingsFor m oid) of
  (h : _) -> pure h
  [] -> assertFailure ("no handle bound for: " ++ show oid)

secretKeyTmpl :: ByteString -> Bool -> Bool -> [(AttributeType, AttributeValue)]
secretKeyTmpl lbl isPrivate canVerify =
  [ (AttrClass, ValULong (mustClassId "CKO_SECRET_KEY"))
  , (AttrKeyType, ValULong (mustKeyTypeId "CKK_GENERIC_SECRET"))
  , (AttrValue, ValBytes "0123456789abcdef0123456789abcdef")
  , (AttrSign, ValBool True)
  , (AttrVerify, ValBool canVerify)
  , label lbl
  ]
    ++ [(AttrPrivate, ValBool True) | isPrivate]

-- | The shared scenario: sessions A and B on slot 0, C on slot 1;
-- A and C logged in; the full private/public by session/token
-- matrix on A plus one private session object each on B and C.
setupMatrix :: IO (Model, SessionId, SessionId, SessionId, [OracleObject])
setupMatrix = do
  (a, m1) <- openSessionOn slot0 seeded
  (b, m2) <- openSessionOn slot0 m1
  (c, m3) <- openSessionOn slot1 m2
  m4 <- loginAs m3 a
  m5 <- loginAs m4 c
  let mk :: OracleObject -> SessionId -> Model -> IO Model
      mk oo sid m = snd <$> runCommit m (createReq sid (tmpl oo))
      oos =
        [ OracleObject "priv-sess-a" True False slot0
        , OracleObject "pub-sess-a" False False slot0
        , OracleObject "priv-tok" True True slot0
        , OracleObject "pub-tok" False True slot0
        , OracleObject "priv-sess-b" True False slot0
        , OracleObject "priv-sess-c" True False slot1
        ]
      tmpl oo =
        [classData, label (ooLabel oo)]
          ++ [privateFlag | ooPrivate oo]
          ++ [tokenFlag | ooToken oo]
      owner oo
        | ooLabel oo == "priv-sess-b" = b
        | ooLabel oo == "priv-sess-c" = c
        | otherwise = a
  m6 <- foldr (\oo rest -> rest >>= mk oo (owner oo)) (pure m5) (reverse oos)
  pure (m6, a, b, c, oos)

-- ---------------------------------------------------------------------------
-- Oracle cases
-- ---------------------------------------------------------------------------

-- | Every recorded object is present exactly when the oracle says
-- it survives; survivors keep their full records; sessions and
-- token auth match the oracle's slot-scoped prediction down to the
-- record; handles stale exactly where predicted and are otherwise
-- untouched.
caseMatrix :: IO ()
caseMatrix = do
  (m0, a, b, c, oos) <- setupMatrix
  -- Setup anchor: every object is bound under at least one fresh handle.
  preHandles <- mapM (anchorFresh m0) oos
  stA0 <- mustSession m0 a
  stB0 <- mustSession m0 b
  stC0 <- mustSession m0 c
  (pc, m1) <- runCommit m0 (logoutReq b)
  assertEqual "logout code" CKR_OK (pcCode pc)
  mapM_ (checkSurvival m0 m1) oos
  -- Touched sessions differ from their setup records in the login
  -- alone (the login delta carries no revision bump); the
  -- other-slot session is byte-identical.
  stA1 <- mustSession m1 a
  stB1 <- mustSession m1 b
  assertEqual "A back to public, nothing else"
    (stA0 { ssLogin = LoginPublic }) stA1
  assertEqual "B back to public, nothing else"
    (stB0 { ssLogin = LoginPublic }) stB1
  assertEqual "C fully untouched" stC0 =<< mustSession m1 c
  assertEqual "C stays logged in" (Just LoginUser) (sessionLoginOf m1 c)
  assertEqual "slot 0 logged out" (Just False) (tokenLoggedIn m1 slot0)
  assertEqual "slot 1 stays logged in" (Just True) (tokenLoggedIn m1 slot1)
  assertEqual "slot 1 auth fully untouched"
    (Map.lookup slot1 (mTokenAuth m0))
    (Map.lookup slot1 (mTokenAuth m1))
  mapM_ (checkHandles m0 m1) (zip oos preHandles)
  where
    anchorFresh :: Model -> OracleObject -> IO [ExternalHandle]
    anchorFresh m oo = do
      oid <- mustOid m (ooLabel oo)
      let hs = map fst (bindingsFor m oid)
      assertBool ("setup binds " ++ show (ooLabel oo)) (not (null hs))
      mapM_ (anchorOne m) hs
      pure hs
    anchorOne :: Model -> ExternalHandle -> IO ()
    anchorOne m h =
      assertEqual ("setup binding fresh: " ++ show h) (Just True) (bindingFreshIn m h)
    checkSurvival :: Model -> Model -> OracleObject -> IO ()
    checkSurvival m0 m1 oo = do
      assertEqual ("survival: " ++ show (ooLabel oo))
        (oracleSurvivesLogout slot0 oo)
        (isJust (findOidByLabel m1 (ooLabel oo)))
      -- Survivors keep their full object records.
      case (findOidByLabel m0 (ooLabel oo), findOidByLabel m1 (ooLabel oo)) of
        (Just oid0, Just oid1) -> do
          assertEqual ("stable id: " ++ show (ooLabel oo)) oid0 oid1
          assertEqual ("untouched record: " ++ show (ooLabel oo))
            (Map.lookup oid0 (mObjects m0))
            (Map.lookup oid1 (mObjects m1))
        _ -> pure ()
    checkHandles :: Model -> Model -> (OracleObject, [ExternalHandle]) -> IO ()
    checkHandles m0 m1 (oo, hs)
      | oracleSurvivesLogout slot0 oo = mapM_ (checkOne m0 m1 oo) hs
      | otherwise = do
          -- Destroyed bindings are retained stale, never deleted.
          mapM_ (checkRetained m1) hs
          mapM_ (checkDangling m1) hs
    checkOne :: Model -> Model -> OracleObject -> ExternalHandle -> IO ()
    checkOne m0 m1 oo h = do
      assertEqual ("handle freshness: " ++ show h)
        (Just (not (oracleHandleStale slot0 oo)))
        (bindingFreshIn m1 h)
      -- Bindings the oracle predicts fresh are byte-identical.
      if oracleHandleStale slot0 oo
        then pure ()
        else assertEqual ("untouched binding: " ++ show h)
          (Map.lookup h (mHandles m0))
          (Map.lookup h (mHandles m1))
    checkRetained :: Model -> ExternalHandle -> IO ()
    checkRetained m h =
      assertBool ("destroyed binding retained: " ++ show h)
        (Map.member h (mHandles m))
    checkDangling :: Model -> ExternalHandle -> IO ()
    checkDangling m h =
      assertEqual ("destroyed binding dangling: " ++ show h)
        Nothing
        (bindingFreshIn m h)

-- | Cached operations bound to a private key on the logout slot
-- retire; the unkeyed digest, the public-key verify, and the
-- other-slot sign survive with identical records. The retirement
-- prediction is the oracle's own ('oracleRetiresOp' over the
-- oracle's privacy facts); observation reads the abstract slots
-- through the projectors.
caseRetirement :: IO ()
caseRetirement = do
  (a, m1) <- openSessionOn slot0 seeded
  (c, m2) <- openSessionOn slot1 m1
  m3 <- loginAs m2 a
  m4 <- loginAs m3 c
  (_, m5) <- runCommit m4 (createReq a (secretKeyTmpl "op-priv" True False))
  (_, m6) <- runCommit m5 (createReq a (secretKeyTmpl "op-pub" False True))
  (_, m7) <- runCommit m6 (createReq c (secretKeyTmpl "op-c" True False))
  oidP <- mustOid m7 "op-priv"
  oidU <- mustOid m7 "op-pub"
  oidC <- mustOid m7 "op-c"
  let privOf = [(oidP, True), (oidU, False), (oidC, True)]
  hP <- mustHandle m7 oidP
  hU <- mustHandle m7 oidU
  hC <- mustHandle m7 oidC
  (_, m8) <- runCommit m7 (initReq F_SignInit a hP (MechanismId 0x251) [OpSign])
  (_, m9) <- runCommit m8 (initReq F_VerifyInit a hU (MechanismId 0x251) [OpVerify])
  m10 <- digestInit m9 a
  (_, m11) <- runCommit m10 (initReq F_SignInit c hC (MechanismId 0x251) [OpSign])
  stA0 <- mustSession m11 a
  stC0 <- mustSession m11 c
  let opsA0 = ssOps stA0
      opsC0 = ssOps stC0
  assertEqual "A holds sign, verify, digest"
    [SlotDigest, SlotSign, SlotVerify] (activeSlots opsA0)
  assertEqual "C holds sign" [SlotSign] (activeSlots opsC0)
  (pc, m12) <- runCommit m11 (logoutReq a)
  assertEqual "logout code" CKR_OK (pcCode pc)
  stA1 <- mustSession m12 a
  stC1 <- mustSession m12 c
  let opsA1 = ssOps stA1
      opsC1 = ssOps stC1
      keyOf kind = case lookupSingle opsA0 kind of
        Nothing -> Nothing
        Just active -> commonKey (commonOf active)
      retired kind = oracleRetiresOp slot0 privOf m12 slot0 (keyOf kind)
      expectedA = [kind | kind <- activeSlots opsA0, not (retired kind)]
  assertEqual "A keeps exactly the predicted survivors"
    expectedA (activeSlots opsA1)
  assertEqual "oracle retires the private sign" True (retired SlotSign)
  assertEqual "oracle keeps the public verify" False (retired SlotVerify)
  assertEqual "oracle keeps the unkeyed digest" False (retired SlotDigest)
  mapM_ (checkSurvivor opsA0 opsA1) expectedA
  assertEqual "other-slot ops fully untouched" opsC0 opsC1
  assertEqual "A non-ops fields untouched"
    (ssId stA0, ssSlot stA0, ssGeneration stA0, ssReadOnly stA0)
    (ssId stA1, ssSlot stA1, ssGeneration stA1, ssReadOnly stA1)
  assertEqual "A back to public" LoginPublic (ssLogin stA1)
  where
    checkSurvivor :: SessionOps -> SessionOps -> SlotKind -> IO ()
    checkSurvivor before after kind =
      assertEqual ("surviving op identical: " ++ show kind)
        (lookupSingle before kind)
        (lookupSingle after kind)

-- | Logging out a public token refuses with
-- 'CKR_USER_NOT_LOGGED_IN' and changes nothing at all — against a
-- populated public state, so any stray write has somewhere to land.
caseRefusedWhenPublic :: IO ()
caseRefusedWhenPublic = do
  (sid, m0) <- openSessionOn slot0 seeded
  (_, m1) <- runCommit m0 (createReq sid [classData, label "public-state"])
  m2 <- digestInit m1 sid
  case planCall defaultRules m2 (logoutReq sid) of
    Reject rej -> do
      assertEqual "refusal code" CKR_USER_NOT_LOGGED_IN (rejCode rej)
      assertEqual "no outputs on refusal" [] (rejOutputs rej)
      case publishDelta m2 (rejDelta rej) of
        Left fault -> assertFailure ("refusal delta fault: " ++ show fault)
        Right m3 -> assertEqual "model unchanged by refused logout" m2 m3
    Immediate pc -> assertFailure ("public logout committed: " ++ show (pcCode pc))
    Execute _ _ -> assertFailure "public logout executed"

-- | One linear walkthrough of the failing case first: the refusal,
-- then the success, then proof the destroyed object never comes back.
caseWalkthrough :: IO ()
caseWalkthrough = do
  (sid, m0) <- openSessionOn slot0 seeded
  -- Step 1: logout while public is refused and mutates nothing.
  m1 <- case planCall defaultRules m0 (logoutReq sid) of
    Reject rej -> do
      assertEqual "step 1: refusal code" CKR_USER_NOT_LOGGED_IN (rejCode rej)
      case publishDelta m0 (rejDelta rej) of
        Left fault -> assertFailure ("step 1: fault: " ++ show fault)
        Right m -> m <$ assertEqual "step 1: model unchanged" m0 m
    other -> assertFailure ("step 1: expected refusal, got: " ++ show other)
  -- Step 2: login is admitted.
  (pcLogin, m2) <- runCommit m1 (loginReq sid)
  assertEqual "step 2: login code" CKR_OK (pcCode pcLogin)
  -- Step 3: a private session object is created and bound.
  (pcCreate, m3) <- runCommit m2
    (createReq sid [classData, label "walk", privateFlag])
  assertEqual "step 3: create code" CKR_OK (pcCode pcCreate)
  oid <- mustOid m3 "walk"
  let preBindings = bindingsFor m3 oid
  assertBool "step 3: object bound" (not (null preBindings))
  -- Step 4: logout commits.
  (pcLogout, m4) <- runCommit m3 (logoutReq sid)
  assertEqual "step 4: logout code" CKR_OK (pcCode pcLogout)
  -- Step 5: exactly the oracle's prediction holds.
  let oo = OracleObject "walk" True False slot0
  assertEqual "step 5: oracle says destroyed" False (oracleSurvivesLogout slot0 oo)
  assertEqual "step 5: object gone" Nothing (findOidByLabel m4 "walk")
  assertEqual "step 5: session public" (Just LoginPublic) (sessionLoginOf m4 sid)
  assertEqual "step 5: token logged out" (Just False) (tokenLoggedIn m4 slot0)
  -- Step 6: after re-login the object stays gone and no find
  -- rebinds it: every binding still naming the destroyed id is one
  -- of the retained stale ones.
  m5 <- loginAs m4 sid
  assertEqual "step 6: still gone" Nothing (findOidByLabel m5 "walk")
  (_, m6) <- runCommit m5 (findReq sid [label "walk"])
  assertEqual "step 6: gone after find" Nothing (findOidByLabel m6 "walk")
  let postBindings = sort
        [ h
        | (h, b) <- Map.toList (mHandles m6)
        , hbObject b == oid
        ]
  assertEqual "step 6: no new bindings" (sort (map fst preBindings)) postBindings
  mapM_ (checkStale m6) postBindings
  where
    checkStale :: Model -> ExternalHandle -> IO ()
    checkStale m h =
      assertEqual ("walkthrough: binding stale: " ++ show h) Nothing (bindingFreshIn m h)

-- | After logout and re-login, the surviving private token object
-- re-discovers under a fresh handle, the public handle is stable,
-- and destroyed objects gain no bindings.
caseRediscovery :: IO ()
caseRediscovery = do
  (m0, a, _, _, _) <- setupMatrix
  sessOid <- mustOid m0 "priv-sess-a"
  let sessBefore = sort (map fst (bindingsFor m0 sessOid))
  assertBool "setup binds the session object" (not (null sessBefore))
  (pcLogout, m1) <- runCommit m0 (logoutReq a)
  assertEqual "logout code" CKR_OK (pcCode pcLogout)
  m2 <- loginAs m1 a
  tokOid <- mustOid m2 "priv-tok"
  pubOid <- mustOid m2 "pub-sess-a"
  let tokBefore = sort (map fst (bindingsFor m1 tokOid))
      pubBefore = sort (map fst (bindingsFor m1 pubOid))
  (_, m3) <- runCommit m2 (findReq a [label "priv-tok"])
  let tokAfter = sort (map fst (bindingsFor m3 tokOid))
      fresh = filter (`notElem` tokBefore) tokAfter
  assertEqual "token re-discovers exactly one fresh handle" 1 (length fresh)
  mapM_ (checkFresh m3) fresh
  (_, m4) <- runCommit m3 (findReq a [label "pub-sess-a"])
  let pubAfter = sort (map fst (bindingsFor m4 pubOid))
  assertEqual "public handle stable" pubBefore pubAfter
  (_, m5) <- runCommit m4 (findReq a [label "priv-sess-a"])
  assertEqual "destroyed object stays gone" Nothing (findOidByLabel m5 "priv-sess-a")
  let sessAfter = sort
        [ h
        | (h, b) <- Map.toList (mHandles m5)
        , hbObject b == sessOid
        ]
  assertEqual "destroyed object gains no bindings" sessBefore sessAfter
  where
    checkFresh :: Model -> ExternalHandle -> IO ()
    checkFresh m h =
      assertEqual ("rediscovered binding fresh: " ++ show h) (Just True) (bindingFreshIn m h)

-- ---------------------------------------------------------------------------
-- Mechanism-variant known-answer checks
-- ---------------------------------------------------------------------------

-- | The pinned variant: CKM_AES_GCM (@0x1087@, OASIS PKCS#11 3.2
-- @2.14@), an authenticated stream mode. Permits encrypt+decrypt
-- (bits 2,3), the always-authenticate mark set, and an opaque
-- 13-byte parameter tail: the frame pins the outer init layout,
-- not inner GCM parameter structure.
gcmMech :: MechanismId
gcmMech = MechanismId 0x1087

gcmParams :: ByteString
gcmParams = "iv-bytes-0123"

-- | Hand-derived frame: @mech:u64 permits:u16 flags:u8
-- params:bytes@ with big-endian integers. Written from the
-- documented layout, never printed from the implementation.
gcmFrame :: ByteString
gcmFrame =
  BS.pack [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x87, 0x00, 0x0C, 0x01]
    <> gcmParams

-- | The stability control: CKM_AES_CBC (@0x1082@), encrypt-only,
-- no always-authenticate mark, a 16-byte IV.
cbcFrame :: ByteString
cbcFrame =
  BS.pack [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x82, 0x00, 0x04, 0x00]
    <> "0123456789abcdef"

caseGcmDecode :: IO ()
caseGcmDecode =
  assertEqual "GCM frame decodes to the pinned triple"
    (Just (gcmMech, [OpEncrypt, OpDecrypt], True, gcmParams))
    (decodeInitInput gcmFrame)

caseGcmEncode :: IO ()
caseGcmEncode =
  assertEqual "GCM triple encodes to the pinned bytes"
    gcmFrame
    (encodeInitInput gcmMech [OpEncrypt, OpDecrypt] True gcmParams)

caseGcmShape :: IO ()
caseGcmShape =
  assertEqual "GCM shape is the unit stream width"
    (Just (CipherSpec 1 False))
    (cipherShapeFor gcmMech)

caseCbcControl :: IO ()
caseCbcControl = do
  assertEqual "CBC frame decodes"
    (Just (MechanismId 0x1082, [OpEncrypt], False, "0123456789abcdef"))
    (decodeInitInput cbcFrame)
  assertEqual "CBC triple encodes"
    cbcFrame
    (encodeInitInput (MechanismId 0x1082) [OpEncrypt] False "0123456789abcdef")
  assertEqual "CBC shape is the unpadded block"
    (Just (CipherSpec 16 False))
    (cipherShapeFor (MechanismId 0x1082))

caseFrameRefusals :: IO ()
caseFrameRefusals = do
  let reservedBit =
        BS.pack [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x87, 0x40, 0x0C, 0x01]
          <> gcmParams
      reservedFlag =
        BS.pack [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x87, 0x00, 0x0C, 0x03]
          <> gcmParams
  assertEqual "reserved permit bit refuses" Nothing (decodeInitInput reservedBit)
  assertEqual "reserved flag bit refuses" Nothing (decodeInitInput reservedFlag)
  assertEqual "truncated frame refuses" Nothing (decodeInitInput (BS.take 10 gcmFrame))
