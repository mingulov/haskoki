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
import Data.Word (Word64)
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
import Haskoki.Outcome
  ( DeltaOp (..)
  , NativeOutput (..)
  , PlanResult (..)
  , PreparedCommit (..)
  , Rejection (..)
  , StateDelta (..)
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
  , testCase "find: template match returns handles" caseFindFlow
  , testCase "find: sealed payloads never match a value guess" caseFindSealedNoOracle
  , testCase "find: contradictory template rejected, nothing bound" caseFindContradiction
  , testCase "routes: malformed object calls are CKR_ARGUMENTS_BAD" caseBadArgs
  , testCase "logout: token-owned private handles die too" caseLogoutTokenPrivate
  , testCase "generated: destroyed handles never resolve or reappear" caseHandleGuard
  , testCase "redaction: adversarial flag mixes never leak" caseRedactionMixes
  , testCase "get-attributes: partial outcome is error plus effects" casePartialOutcome
  , testCase "get-attributes: all readable commits" caseReadAllOk
  , testCase "visibility: private objects follow login state" caseVisibilityLogin
  , testCase "isolation: sessions only touch their own slot objects" caseSlotIsolation
  , testCase "logout: private handles die without resurrection" caseLogoutNoResurrection
  , testCase "close: creator-close destroys session objects" caseCreatorClose
  , testCase "codec: 65-entry template refused" caseTemplateEntryBound
  , testCase "create: 65-entry template refused loudly" caseCreateEntryBound
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
  assertEqual "unsealing copy rejected" CKR_TEMPLATE_INCONSISTENT code
  assertEqual "no unsealed copy created" nBefore (Map.size (mObjects m3))
  (codeS, m4) <- runReject m3
    (copyReq sid h [(AttrSensitive, ValBool False)])
  assertEqual "sensitive-only unseal rejected" CKR_TEMPLATE_INCONSISTENT codeS
  (codeE, m5) <- runReject m4
    (copyReq sid h [(AttrExtractable, ValBool True)])
  assertEqual "extractable-only unseal rejected" CKR_TEMPLATE_INCONSISTENT codeE
  assertEqual "still no copy created" nBefore (Map.size (mObjects m5))
  (pcC, m6) <- runCommit m5 (copyReq sid h [])
  h2 <- commitHandle pcC
  assertBool "sealed copy is a fresh handle" (h2 /= h)
  (rej, _) <- runRejectFull m6 (getReq sid h2 [AttrValue])
  assertEqual "copy of sealed still redacts" CKR_ATTRIBUTE_SENSITIVE (rejCode rej)
  assertEqual "no payload bytes escape" [] (rejOutputs rej)

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
  -- non-public login.
  (a0, m0) <- openSession seeded
  (pcP, m1) <- runCommit m0 (createReq a0 [classData, label "priv", privateFlag])
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
  -- End to end through the routes: login, read, logout, read.
  m3 <- loginAs m2 a0
  (pcG, _) <- runCommit m3 (getReq a0 hp [AttrLabel])
  assertEqual "user reads private" CKR_OK (pcCode pcG)
  (pcF, mf) <- runCommit m3 (findReq a0 [])
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

caseLogoutNoResurrection :: IO ()
caseLogoutNoResurrection = do
  (a, m0) <- openSession seeded
  m1 <- loginAs m0 a
  (pcP, m2) <- runCommit m1 (createReq a [classData, label "priv", privateFlag])
  hp <- commitHandle pcP
  (pcU, m3) <- runCommit m2 (createReq a [classData, label "pub"])
  hu <- commitHandle pcU
  m4 <- snd <$> runCommit m3 (logoutReq a)
  (code, m5) <- runReject m4 (getReq a hp [AttrLabel])
  assertEqual "logout kills the private handle" CKR_OBJECT_HANDLE_INVALID code
  (pcG, _) <- runCommit m5 (getReq a hu [AttrLabel])
  assertEqual "public handle survives logout" CKR_OK (pcCode pcG)
  m6 <- loginAs m5 a
  (code2, m7) <- runReject m6 (getReq a hp [AttrLabel])
  assertEqual "no resurrection after re-login" CKR_OBJECT_HANDLE_INVALID code2
  (pcF, mF) <- runCommit m7 (findReq a [label "priv"])
  found <- findHandles pcF
  case found of
    [hp2] -> do
      assertBool "discovery mints a fresh handle" (hp2 /= hp)
      (pcG2, _) <- runCommit mF (getReq a hp2 [AttrLabel])
      assertEqual "fresh handle reads" CKR_OK (pcCode pcG2)
    _ -> assertFailure ("expected exactly the re-discovered handle, got: " ++ show found)
  (pcG3, _) <- runCommit mF (getReq a hu [AttrLabel])
  assertEqual "public handle still the same one" CKR_OK (pcCode pcG3)

-- | Token-owned private objects take the same logout path as
-- session-owned ones: the handle dies at logout, stays dead across
-- re-login, and only a fresh discovery handle reads again. The
-- token object itself survives (logout kills handles, not objects).
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
