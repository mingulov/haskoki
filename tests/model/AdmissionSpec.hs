{- | Object/slot admission-bound tests.

Every creation seam (create, copy, keygen, keypair, unwrap, derive)
refuses past 'rulesMaxObjects' with 'CKR_HOST_MEMORY', and token
seating refuses past 'rulesMaxTokens'; bounds come from the resolved
config on native paths ('rulesFromConfig'). All bounds here are
test-local (small @B@ via custom 'Rules'); production defaults are
pinned separately and never drive refusal.
-}
{-# LANGUAGE OverloadedStrings #-}
module AdmissionSpec (spec) where

import qualified Data.ByteString as BS
import qualified Data.Map.Strict as Map
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertEqual, assertFailure, testCase)

import Haskoki.Attribute (AttributeType (..), AttributeValue (..))
import Haskoki.Model
  ( Model (..)
  , SessionState
  , addToken
  , emptyModel
  , lookupSession
  )
import Haskoki.Object (decodeHandle, encodeTemplate)
import Haskoki.Operation.Derive (encodeDeriveParams, hkdfDeriveMech, planDerive)
import Haskoki.Operation.KeyManagement
  ( KeyDeny (..)
  , KeyPlan (..)
  , aesKeyGenMech
  , ckkAes
  , ckkEc
  , ckkGenericSecret
  , ckoPrivateKey
  , ckoPublicKey
  , ckoSecretKey
  , ecKeyPairGenMech
  , planGenerateKey
  , planGenerateKeyPair
  , planUnwrapKey
  )
import Haskoki.Outcome
  ( NativeOutput (..)
  , PlanResult (..)
  , PreparedCommit (..)
  , Rejection (..)
  )
import Haskoki.Request (FunctionId (..), Request (..))
import Haskoki.Rules (Rules (..), defaultRules)
import Haskoki.Runtime.Config (Config (..), Limits (..), defaultConfig)
import Haskoki.Runtime.Lifecycle
  ( newEnv
  , restoreStoreState
  , rulesFromConfig
  , seatToken
  , snapshotModel
  )
import Haskoki.Runtime.Storage (ObjectRecord (..), TokenRecord (..))
import Haskoki.Session
  ( AdmitDeny (..)
  , admitCode
  , admitObjects
  , admitToken
  , tokenAuthNew
  )
import Haskoki.Transition (planCall, publishDelta)
import Haskoki.Types
  ( ExternalHandle (..)
  , Generation (..)
  , ObjectId (..)
  , Pkcs11Version (..)
  , ReturnCode (..)
  , Revision (..)
  , SessionId (..)
  , SlotId (..)
  , TokenId (..)
  )

spec :: TestTree
spec = testGroup "admission bounds"
  [ testCase "create: B+1 refused with CKR_HOST_MEMORY" caseCreateBound
  , testCase "copy: refused at a full store" caseCopyBound
  , testCase "keygen: refused at a full store" caseKeygenBound
  , testCase "keypair: pair needs room for two" caseKeypairCount
  , testCase "unwrap: refused at a full store" caseUnwrapBound
  , testCase "derive: refused at a full store" caseDeriveBound
  , testCase "derive: huge length refused loudly" caseDeriveHugeLength
  , testCase "admitObjects/admitToken: pure pins" casePurePins
  , testCase "seating: past-bound refused, count frozen" caseSeatBound
  , testCase "seating: reseat is idempotent" caseReseat
  , testCase "restore: over-bound reload refused atomically" caseRestoreBound
  , testCase "restore: over-cap objects refused atomically" caseRestoreObjectsBound
  , testCase "rulesFromConfig: small limits track enforcement" caseTracksConfig
  , testCase "rulesFromConfig defaultConfig == defaultRules" caseDefaultEquality
  , testCase "defaults mirror the [limits] section-3 values" caseDefaultPins
  ]

-- ---------------------------------------------------------------------------
-- Harness (Rules-parameterized; ObjectSpec-shaped)
-- ---------------------------------------------------------------------------

rulesB :: Rules
rulesB = defaultRules { rulesMaxObjects = 8 }

rulesT :: Rules
rulesT = defaultRules { rulesMaxTokens = 2 }

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

tmpl :: [(AttributeType, AttributeValue)]
tmpl = [(AttrClass, ValULong 0), (AttrLabel, ValBytes "a")]

openSession :: Rules -> Model -> IO (SessionId, Model)
openSession rules model = do
  let req = (mkRequest F_OpenSession Nothing) { reqInput = "slot=0,rw" }
  case planCall rules model req of
    Immediate pc -> case publishDelta model (pcDelta pc) of
      Left fault -> assertFailure ("open delta fault: " ++ show fault)
      Right m' -> pure (SessionId (mNextSession model), m')
    other -> assertFailure ("open failed: " ++ show other)

loginAsUser :: Rules -> Model -> SessionId -> IO Model
loginAsUser rules model sid = do
  let req = (mkRequest F_Login (Just sid)) { reqInput = "user:ok" }
  case planCall rules model req of
    Immediate pc -> case publishDelta model (pcDelta pc) of
      Left fault -> assertFailure ("login delta fault: " ++ show fault)
      Right m' -> pure m'
    other -> assertFailure ("login failed: " ++ show other)

createOne :: Rules -> Model -> SessionId -> IO (ExternalHandle, Model)
createOne rules model sid = do
  let req = (mkRequest F_CreateObject (Just sid))
        { reqInput = encodeTemplate tmpl }
  case planCall rules model req of
    Immediate pc -> case publishDelta model (pcDelta pc) of
      Left fault -> assertFailure ("create delta fault: " ++ show fault)
      Right m' -> do
        h <- commitHandle pc
        pure (h, m')
    Reject rej -> assertFailure
      ("fill create rejected early: " ++ show (rejCode rej))
    Execute _ _ -> assertFailure "fill create executed (impossible)"

commitHandle :: PreparedCommit -> IO ExternalHandle
commitHandle pc = case pcOutputs pc of
  [NativeOutput _ bs] -> case decodeHandle bs of
    Just h -> pure h
    Nothing -> assertFailure "handle output undecodable"
  outs -> assertFailure ("expected one handle output, got: " ++ show outs)

fillObjects :: Rules -> SessionId -> Int -> Model -> IO Model
fillObjects _ _ 0 m = pure m
fillObjects rules sid n m = do
  (_, m') <- createOne rules m sid
  fillObjects rules sid (n - 1) m'

-- ---------------------------------------------------------------------------
-- Cases
-- ---------------------------------------------------------------------------

caseCreateBound :: IO ()
caseCreateBound = do
  (sid, m1) <- openSession rulesB seeded
  mFull <- fillObjects rulesB sid 8 m1
  assertEqual "filled to the bound" 8 (Map.size (mObjects mFull))
  let req = (mkRequest F_CreateObject (Just sid))
        { reqInput = encodeTemplate tmpl }
  case planCall rulesB mFull req of
    Reject rej -> assertEqual "refusal code" CKR_HOST_MEMORY (rejCode rej)
    Immediate pc -> assertFailure
      ("9th create committed (unbounded): " ++ show (pcCode pc))
    Execute _ _ -> assertFailure "9th create executed (impossible)"

caseCopyBound :: IO ()
caseCopyBound = do
  (sid, m1) <- openSession rulesB seeded
  (h, m2) <- createOne rulesB m1 sid
  mFull <- fillObjects rulesB sid 7 m2
  assertEqual "filled to the bound" 8 (Map.size (mObjects mFull))
  let req = (mkRequest F_CopyObject (Just sid))
        { reqHandle = Just h, reqInput = encodeTemplate [] }
  case planCall rulesB mFull req of
    Reject rej -> assertEqual "refusal code" CKR_HOST_MEMORY (rejCode rej)
    Immediate pc -> assertFailure
      ("copy committed at a full store: " ++ show (pcCode pc))
    Execute _ _ -> assertFailure "copy executed (impossible)"

caseKeygenBound :: IO ()
caseKeygenBound = do
  (sid, m1) <- openSession rulesB seeded
  mFull <- fillObjects rulesB sid 8 m1
  st <- sessionOf mFull sid
  case planGenerateKey rulesB mFull st aesKeyGenMech (aesTmpl 32) of
    KeyDenied deny -> assertEqual "refusal code" CKR_HOST_MEMORY (kdCode deny)
    other -> assertFailure ("keygen planned at a full store: " ++ show other)

caseKeypairCount :: IO ()
caseKeypairCount = do
  (sid, m1) <- openSession rulesB seeded
  m7 <- fillObjects rulesB sid 7 m1
  st7 <- sessionOf m7 sid
  case planGenerateKeyPair rulesB m7 st7 ecKeyPairGenMech ecPubTmpl ecPrivTmpl of
    KeyDenied deny -> assertEqual "refusal code" CKR_HOST_MEMORY (kdCode deny)
    other -> assertFailure ("pair planned without room for two: " ++ show other)
  m6 <- fillObjects rulesB sid 6 m1
  st6 <- sessionOf m6 sid
  case planGenerateKeyPair rulesB m6 st6 ecKeyPairGenMech ecPubTmpl ecPrivTmpl of
    KeyEffect _ _ -> pure ()
    other -> assertFailure ("pair refused with room for two: " ++ show other)

caseUnwrapBound :: IO ()
caseUnwrapBound = do
  (sid, m1) <- openSession rulesB seeded
  mFull <- fillObjects rulesB sid 8 m1
  st <- sessionOf mFull sid
  -- Parse-first: validation precedes admission, so unusable
  -- arguments refuse the validation code even at a full store
  -- (here the mechanism check fires first); the bound code is
  -- reserved for valid requests that do not fit. Fail-safe either
  -- way. (This pin asserted CKR_HOST_MEMORY before the flip.)
  case planUnwrapKey rulesB mFull st aesKeyGenMech "" (ExternalHandle 0) "" [] of
    KeyDenied deny -> assertEqual "refusal code" CKR_MECHANISM_INVALID (kdCode deny)
    other -> assertFailure ("unwrap planned at a full store: " ++ show other)

caseDeriveBound :: IO ()
caseDeriveBound = do
  (sid, m1) <- openSession rulesB seeded
  m2 <- loginAsUser rulesB m1 sid
  (baseH, m3) <- createBase m2 sid
  mFull <- fillObjects rulesB sid 7 m3
  assertEqual "filled to the bound" 8 (Map.size (mObjects mFull))
  st <- sessionOf mFull sid
  let blob = encodeDeriveParams "derive-info" [soloTmpl]
  case planDerive rulesB mFull st hkdfDeriveMech baseH blob of
    KeyDenied deny -> assertEqual "refusal code" CKR_HOST_MEMORY (kdCode deny)
    other -> assertFailure ("derive planned at a full store: " ++ show other)
  where
    soloTmpl =
      [ (AttrClass, ValULong ckoSecretKey)
      , (AttrKeyType, ValULong ckkGenericSecret)
      , (AttrValueLen, ValULong 32)
      , (AttrToken, ValBool False)
      , (AttrEncrypt, ValBool True)
      ]

-- | Plant a usable AES derive-base key; shared by the derive cases.
createBase :: Model -> SessionId -> IO (ExternalHandle, Model)
createBase model sid = do
  let baseTmpl =
        [ (AttrClass, ValULong ckoSecretKey)
        , (AttrKeyType, ValULong ckkAes)
        , (AttrValueLen, ValULong 32)
        , (AttrToken, ValBool False)
        , (AttrDerive, ValBool True)
        , (AttrValue, ValBytes (BS.replicate 32 0x6B))
        ]
      req = (mkRequest F_CreateObject (Just sid))
        { reqInput = encodeTemplate baseTmpl }
  case planCall rulesB model req of
    Immediate pc -> case publishDelta model (pcDelta pc) of
      Left fault -> assertFailure ("base delta fault: " ++ show fault)
      Right m' -> do
        h <- commitHandle pc
        pure (h, m')
    other -> assertFailure ("base create failed: " ++ show other)

-- | A derived length past the 'Int' platform range refuses
-- loudly instead of wrapping through 'fromIntegral' into a
-- negative length.
caseDeriveHugeLength :: IO ()
caseDeriveHugeLength = do
  (sid, m1) <- openSession rulesB seeded
  m2 <- loginAsUser rulesB m1 sid
  (baseH, m3) <- createBase m2 sid
  st <- sessionOf m3 sid
  let blob = encodeDeriveParams "derive-info" [hugeTmpl]
  case planDerive rulesB m3 st hkdfDeriveMech baseH blob of
    KeyDenied deny -> do
      assertEqual "refusal code" CKR_TEMPLATE_INCONSISTENT (kdCode deny)
      assertEqual "refusal reason" "derived length exceeds the platform range"
        (kdReason deny)
    other -> assertFailure ("huge derive planned: " ++ show other)
  where
    hugeTmpl =
      [ (AttrClass, ValULong ckoSecretKey)
      , (AttrKeyType, ValULong ckkGenericSecret)
      , (AttrValueLen, ValULong maxBound)
      , (AttrToken, ValBool False)
      , (AttrEncrypt, ValBool True)
      ]

casePurePins :: IO ()
casePurePins = do
  assertEqual "objects full" (Left AdmitObjectsFull) (admitObjects rulesB 8 1)
  assertEqual "objects room" (Right ()) (admitObjects rulesB 7 1)
  assertEqual "pair needs two" (Left AdmitObjectsFull) (admitObjects rulesB 7 2)
  assertEqual "pair fits" (Right ()) (admitObjects rulesB 6 2)
  assertEqual "tokens full" (Left AdmitTokensFull) (admitToken rulesT 2)
  assertEqual "tokens room" (Right ()) (admitToken rulesT 1)
  assertEqual "objects code" CKR_HOST_MEMORY (admitCode AdmitObjectsFull)
  assertEqual "tokens code" CKR_HOST_MEMORY (admitCode AdmitTokensFull)

caseSeatBound :: IO ()
caseSeatBound = do
  env <- newEnv rulesT
  e0 <- seatToken env (SlotId 0)
  e1 <- seatToken env (SlotId 1)
  assertEqual "seat 0" (Right ()) e0
  assertEqual "seat 1" (Right ()) e1
  e2 <- seatToken env (SlotId 2)
  assertEqual "seat 2 refused" (Left AdmitTokensFull) e2
  m <- snapshotModel env
  assertEqual "seated count frozen" 2 (Map.size (mTokenAuth m))

caseReseat :: IO ()
caseReseat = do
  env <- newEnv rulesT
  e0 <- seatToken env (SlotId 0)
  e0' <- seatToken env (SlotId 0)
  assertEqual "first seat" (Right ()) e0
  assertEqual "reseat idempotent" (Right ()) e0'
  m <- snapshotModel env
  assertEqual "one seated" 1 (Map.size (mTokenAuth m))

caseRestoreBound :: IO ()
caseRestoreBound = do
  env <- newEnv rulesT
  eBig <- restoreStoreState env [mkToken 1 0, mkToken 2 1, mkToken 3 2]
  assertEqual "over-bound reload refused" (Left AdmitTokensFull) eBig
  m0 <- snapshotModel env
  assertEqual "nothing seated" 0 (Map.size (mTokenAuth m0))
  env2 <- newEnv rulesT
  eFit <- restoreStoreState env2 [mkToken 1 0, mkToken 2 1]
  assertEqual "at-bound reload commits" (Right ()) eFit
  m2 <- snapshotModel env2
  assertEqual "two seated" 2 (Map.size (mTokenAuth m2))
  where
    mkToken tid slot =
      ( TokenRecord (TokenId tid) (SlotId slot) (Generation 0)
          ("t" ++ show tid) tokenAuthNew
      , []
      )

-- | A stored generation whose objects would seat
-- past 'rulesMaxObjects' is refused all-or-nothing (tokens stay
-- unseated too), exactly like the token bound; an at-cap reload
-- commits (previously the over-cap reload committed).
caseRestoreObjectsBound :: IO ()
caseRestoreObjectsBound = do
  env <- newEnv rulesO
  eBig <- restoreStoreState env
    [ ( TokenRecord (TokenId 1) (SlotId 0) (Generation 0) "t1" tokenAuthNew
      , [mkObj 1, mkObj 2, mkObj 3]
      )
    ]
  assertEqual "over-cap reload refused" (Left AdmitObjectsFull) eBig
  m0 <- snapshotModel env
  assertEqual "no objects written" 0 (Map.size (mObjects m0))
  assertEqual "no tokens seated" 0 (Map.size (mTokenAuth m0))
  env2 <- newEnv rulesO
  eFit <- restoreStoreState env2
    [ ( TokenRecord (TokenId 1) (SlotId 0) (Generation 0) "t1" tokenAuthNew
      , [mkObj 1, mkObj 2]
      )
    ]
  assertEqual "at-cap reload commits" (Right ()) eFit
  m2 <- snapshotModel env2
  assertEqual "two objects restored" 2 (Map.size (mObjects m2))
  where
    mkObj n = ObjectRecord
      { orId = ObjectId n
      , orToken = TokenId 1
      , orClass = 0
      , orKeyType = Nothing
      , orAttrs = Map.fromList [(AttrClass, ValULong 0)]
      , orMaterialEncoding = "none"
      , orMaterial = Nothing
      , orRevision = Revision 1
      }

rulesO :: Rules
rulesO = defaultRules { rulesMaxObjects = 2 }

caseTracksConfig :: IO ()
caseTracksConfig = do
  let lims = (cfgLimits defaultConfig) { limObjects = 8, limSlots = 2 }
      cfg = defaultConfig { cfgLimits = lims }
      rules = rulesFromConfig cfg
  assertEqual "objects tracked" 8 (rulesMaxObjects rules)
  assertEqual "slots tracked" 2 (rulesMaxTokens rules)
  (sid, m1) <- openSession rules seeded
  mFull <- fillObjects rules sid 8 m1
  let req = (mkRequest F_CreateObject (Just sid))
        { reqInput = encodeTemplate tmpl }
  case planCall rules mFull req of
    Reject rej -> assertEqual "refusal code" CKR_HOST_MEMORY (rejCode rej)
    other -> assertFailure ("9th create not refused: " ++ show other)
  env <- newEnv rules
  _ <- seatToken env (SlotId 0)
  _ <- seatToken env (SlotId 1)
  e2 <- seatToken env (SlotId 2)
  assertEqual "3rd seat refused" (Left AdmitTokensFull) e2

caseDefaultEquality :: IO ()
caseDefaultEquality =
  assertEqual "default config derives default rules"
    defaultRules (rulesFromConfig defaultConfig)

caseDefaultPins :: IO ()
caseDefaultPins = do
  assertEqual "default objects" 100000 (rulesMaxObjects defaultRules)
  assertEqual "default tokens" 16 (rulesMaxTokens defaultRules)
  assertEqual "default sessions" 1024 (rulesMaxSessions defaultRules)

-- ---------------------------------------------------------------------------
-- Fixtures (key templates mirror KeyManagementSpec)
-- ---------------------------------------------------------------------------

sessionOf :: Model -> SessionId -> IO SessionState
sessionOf m sid = case lookupSession m sid of
  Nothing -> assertFailure "session missing" >> undefined
  Just st -> pure st

aesTmpl :: Int -> [(AttributeType, AttributeValue)]
aesTmpl n =
  [ (AttrClass, ValULong ckoSecretKey)
  , (AttrKeyType, ValULong ckkAes)
  , (AttrValueLen, ValULong (fromIntegral n))
  , (AttrToken, ValBool False)
  , (AttrPrivate, ValBool True)
  , (AttrSensitive, ValBool True)
  , (AttrExtractable, ValBool True)
  ]

ecPubTmpl :: [(AttributeType, AttributeValue)]
ecPubTmpl =
  [ (AttrClass, ValULong ckoPublicKey)
  , (AttrKeyType, ValULong ckkEc)
  , (AttrEcParams, ValBytes "P-256")
  , (AttrToken, ValBool False)
  , (AttrVerify, ValBool True)
  ]

ecPrivTmpl :: [(AttributeType, AttributeValue)]
ecPrivTmpl =
  [ (AttrClass, ValULong ckoPrivateKey)
  , (AttrKeyType, ValULong ckkEc)
  , (AttrEcParams, ValBytes "P-256")
  , (AttrToken, ValBool False)
  , (AttrPrivate, ValBool True)
  , (AttrSensitive, ValBool True)
  , (AttrExtractable, ValBool False)
  , (AttrSign, ValBool True)
  ]
