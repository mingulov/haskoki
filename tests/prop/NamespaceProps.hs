{- | Namespace laws: session ops never create\/destroy objects
and object ops never touch sessions — the TransitionSpec
caseNamespaces precedent generalized to all lengths 0..12 plus
constant (all-duplicates) sequences. Every side publishes on the
seeded 'seedBase' (sessions 1..3 open, objects\/handles 9..10
present, slots 0..1 seated) so success-path side effects are
observable, and the OTHER namespaces are asserted UNCHANGED vs
the base — never merely empty (the empty-model shape
faulted every non-empty session side before any assertion ran).
-}
module NamespaceProps (spec, seedBase) where

import qualified Data.Map.Strict as Map
import Data.Word (Word64)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertBool, assertEqual, assertFailure, testCase)

import Gen
  ( constructorHits
  , ctorName
  , freshSeeds
  , genSeq
  , genSeqFull14
  , hitSummary
  , lcgNext
  , propSeedOverride
  )
import Haskoki.Attribute (AttributeType (..), AttributeValue (..))
import Haskoki.Model (Model (..), ObjectState (..), addToken, emptyModel)
import Haskoki.Operation (emptySessionOps)
import Haskoki.Outcome (DeltaOp (..), StateDelta (..))
import Haskoki.Session
  ( ActiveLogin (..)
  , SessionLogin (..)
  , TokenAuth (..)
  )
import Haskoki.Transition (publishDelta)
import Haskoki.Types
  ( ExternalHandle (..)
  , Generation (..)
  , ObjectId (..)
  , SessionId (..)
  , SlotId (..)
  )

spec :: Int -> TestTree
spec count =
  testGroup
    "namespace laws"
    [ testCase "namespaces stay separate" (caseNamespaces count)
    , testCase "namespaces over constant seqs" caseConstNamespaces
    , testCase "full namespace partition" (caseFull count)
    , testCase "unbind preserves session and token namespaces" caseUnbind
    , testCase "attribute updates stay in the object namespace"
        caseAttrNamespace
    , testCase "attribute namespace sensitivity" caseAttrSensitivity
    , testCase "every constructor witnesses success"
        caseConstructorWitnesses
    , testCase "full corpus hits every constructor"
        (caseCorpusHits count)
    ]

-- | Two-way split for the original session/object corpora.
-- Deliberately exhaustive with no catch-all: a new constructor
-- fails compilation here (fatal-omissions) instead of inheriting
-- a side silently.
isSessionOp :: DeltaOp -> Bool
isSessionOp op = case op of
  DeltaTouchSession _ -> True
  DeltaCloseSession _ -> True
  DeltaBumpGeneration _ _ -> True
  DeltaCreateObject _ -> False
  DeltaDestroyObject _ -> False
  DeltaCreateObjectFull _ _ _ _ -> False
  DeltaSetAttributes _ _ -> False
  DeltaBindHandle _ _ -> False
  DeltaBumpHandle _ -> False
  DeltaUnbindHandle _ -> False
  DeltaOpenSession _ _ _ -> True
  DeltaSetSessionLogin _ _ -> True
  DeltaSetTokenAuth _ _ -> True
  DeltaSetSessionOps _ _ -> True

checkSeparation :: [DeltaOp] -> IO ()
checkSeparation ops = do
  let sessionOnly = [op | op <- ops, isSessionOp op]
      objectOnly = [op | op <- ops, not (isSessionOp op)]
  case publishDelta seedBase (StateDelta sessionOnly) of
    Left _ -> pure ()
    Right m -> do
      assertEqual "session ops leave objects unchanged"
        (mObjects seedBase) (mObjects m)
      assertEqual "session ops leave handles unchanged"
        (mHandles seedBase) (mHandles m)
      assertEqual "session ops leave token-auth unchanged"
        (mTokenAuth seedBase) (mTokenAuth m)
  case publishDelta seedBase (StateDelta objectOnly) of
    Left _ -> pure ()
    Right m -> do
      assertEqual "object ops leave sessions unchanged"
        (mSessions seedBase) (mSessions m)
      assertEqual "object ops leave token-auth unchanged"
        (mTokenAuth seedBase) (mTokenAuth m)

caseNamespaces :: Int -> IO ()
caseNamespaces count = do
  seedOv <- propSeedOverride
  mapM_ check [(seed, len) | seed <- freshSeeds seedOv count, len <- [0 .. 12]]
  where
    check :: (Word64, Int) -> IO ()
    check (seed, len) = checkSeparation (genSeq seed len)

constOps :: [DeltaOp]
constOps =
  [ DeltaTouchSession (SessionId 1)
  , DeltaCloseSession (SessionId 1)
  , DeltaBumpGeneration (SessionId 1) (Generation 2)
  , DeltaCreateObject (ObjectId 1)
  , DeltaDestroyObject (ObjectId 1)
  , DeltaUnbindHandle (ExternalHandle 9)
  , DeltaSetAttributes (ObjectId 9)
      (Map.singleton AttrClass (ValULong 3))
  ]

caseConstNamespaces :: IO ()
caseConstNamespaces =
  mapM_ check [(op, len) | op <- constOps, len <- [0 .. 12]]
  where
    check :: (DeltaOp, Int) -> IO ()
    check (op, len) = checkSeparation (replicate len op)

-- ---------------------------------------------------------------------------
-- Full 14-constructor partition
-- ---------------------------------------------------------------------------

-- | Namespace class: object ops touch objects/handles only, session
-- ops touch sessions only, token ops touch token-auth only
-- (verified against every applyOp branch in Transition.hs).
-- Deliberately exhaustive with no catch-all: a new constructor
-- fails compilation here (fatal-omissions) instead of inheriting
-- a class silently.
data OpClass = OCObject | OCSession | OCToken
  deriving (Eq, Show)

opClass :: DeltaOp -> OpClass
opClass op = case op of
  DeltaTouchSession _ -> OCSession
  DeltaCloseSession _ -> OCSession
  DeltaBumpGeneration _ _ -> OCSession
  DeltaCreateObject _ -> OCObject
  DeltaDestroyObject _ -> OCObject
  DeltaCreateObjectFull _ _ _ _ -> OCObject
  DeltaSetAttributes _ _ -> OCObject
  DeltaBindHandle _ _ -> OCObject
  DeltaBumpHandle _ -> OCObject
  DeltaUnbindHandle _ -> OCObject
  DeltaOpenSession _ _ _ -> OCSession
  DeltaSetSessionLogin _ _ -> OCSession
  DeltaSetTokenAuth _ _ -> OCToken
  DeltaSetSessionOps _ _ -> OCSession

-- | One full delta op drawn from the generator state over small id
-- spaces (covers the original 12 constructors; traces frozen —
-- the full 14-constructor corpus lives in Gen.genSeqFull14).
genOpFull :: Word64 -> (DeltaOp, Word64)
genOpFull s0 =
  let s1 = lcgNext s0
      s2 = lcgNext s1
      s3 = lcgNext s2
      pick = fromIntegral (s1 `mod` 12) :: Int
      sid = SessionId (1 + fromIntegral (s2 `mod` 3))
      sid2 = SessionId (1 + fromIntegral ((s2 `div` 3) `mod` 3))
      oid = ObjectId (1 + fromIntegral ((s2 `div` 9) `mod` 5))
      hdl = ExternalHandle (1 + fromIntegral ((s2 `div` 45) `mod` 5))
      slotV = SlotId (fromIntegral ((s2 `div` 225) `mod` 2))
      genV = Generation (1 + fromIntegral ((s2 `div` 450) `mod` 4))
      readOnly = s3 `mod` 2 == 1
      attrs =
        if s3 `div` 2 `mod` 2 == 0
          then Map.empty
          else Map.singleton AttrClass (ValULong (fromIntegral (s3 `mod` 7)))
      owner =
        if s3 `div` 4 `mod` 2 == 0
          then Nothing
          else Just sid2
      loginV = case s3 `div` 8 `mod` 3 of
        0 -> LoginPublic
        1 -> LoginUser
        _ -> LoginSO
      authV =
        TokenAuth
          (if s3 `div` 24 `mod` 2 == 0 then Nothing else Just AuthUser)
          (if s3 `div` 48 `mod` 2 == 0 then Nothing else Just "test-user")
          (fromIntegral (s3 `div` 96 `mod` 5))
          (fromIntegral (s3 `div` 480 `mod` 4))
          (fromIntegral (s3 `div` 1920 `mod` 4))
          (s3 `div` 7680 `mod` 2 == 1)
          (s3 `div` 15360 `mod` 2 == 1)
  in case pick of
    0 -> (DeltaTouchSession sid, s3)
    1 -> (DeltaCloseSession sid, s3)
    2 -> (DeltaBumpGeneration sid genV, s3)
    3 -> (DeltaCreateObject oid, s3)
    4 -> (DeltaDestroyObject oid, s3)
    5 -> (DeltaCreateObjectFull oid attrs owner slotV, s3)
    6 -> (DeltaBindHandle hdl oid, s3)
    7 -> (DeltaBumpHandle hdl, s3)
    8 -> (DeltaOpenSession sid slotV readOnly, s3)
    9 -> (DeltaSetSessionLogin sid loginV, s3)
    10 -> (DeltaSetTokenAuth slotV authV, s3)
    _ -> (DeltaSetSessionOps sid emptySessionOps, s3)

-- | A deterministic full op sequence of the requested length.
genSeqFull :: Word64 -> Int -> [DeltaOp]
genSeqFull seed n = go seed n []
  where
    go :: Word64 -> Int -> [DeltaOp] -> [DeltaOp]
    go _ 0 acc = reverse acc
    go s k acc = let (op, s') = genOpFull s in go s' (k - 1) (op : acc)

-- | Model seating slot 0, so token ops can succeed (on the empty
-- model they fault on the unknown slot and the law would be
-- vacuous).
tokenModel :: Model
tokenModel = addToken emptyModel (SlotId 0)

-- | The seeded base every namespace side publishes on:
-- slots 0..1 seated, sessions 1..3 pre-opened via OpenSession on
-- slot 0, objects\/handles 9..10 present. Generator ids live in
-- 1..5 (sessions 1..3), so the seeded objects\/handles sit outside
-- the generated range: creates can still succeed while the base
-- already holds observable other-namespace state. A seed failure
-- is a loud construction error, never a silent pass.
seedBase :: Model
seedBase = case publishDelta seated (StateDelta seedOps) of
  Left fault -> error ("seedBase construction failed: " ++ show fault)
  Right m -> m
  where
    seated = addToken tokenModel (SlotId 1)
    seedOps =
      [ DeltaOpenSession (SessionId 1) (SlotId 0) False
      , DeltaOpenSession (SessionId 2) (SlotId 0) False
      , DeltaOpenSession (SessionId 3) (SlotId 0) False
      , DeltaCreateObjectFull (ObjectId 9) Map.empty Nothing (SlotId 0)
      , DeltaCreateObjectFull (ObjectId 10) Map.empty Nothing (SlotId 0)
      , DeltaBindHandle (ExternalHandle 9) (ObjectId 9)
      , DeltaBindHandle (ExternalHandle 10) (ObjectId 10)
      ]

-- | Representative token auth: a logged-in user, distinct from a
-- fresh token in every field the witnesses compare.
tokenAuth0 :: TokenAuth
tokenAuth0 = TokenAuth (Just AuthUser) (Just "test-user") 1 0 0 False False

-- | One representative per full constructor (attribute updates
-- target a seeded object so the success path executes).
constOpsFull :: [DeltaOp]
constOpsFull =
  [ DeltaTouchSession (SessionId 1)
  , DeltaCloseSession (SessionId 1)
  , DeltaBumpGeneration (SessionId 1) (Generation 2)
  , DeltaCreateObject (ObjectId 1)
  , DeltaDestroyObject (ObjectId 1)
  , DeltaCreateObjectFull (ObjectId 1) Map.empty Nothing (SlotId 0)
  , DeltaSetAttributes (ObjectId 9)
      (Map.singleton AttrClass (ValULong 3))
  , DeltaBindHandle (ExternalHandle 1) (ObjectId 1)
  , DeltaBumpHandle (ExternalHandle 1)
  , DeltaUnbindHandle (ExternalHandle 9)
  , DeltaOpenSession (SessionId 1) (SlotId 0) False
  , DeltaSetSessionLogin (SessionId 1) LoginUser
  , DeltaSetTokenAuth (SlotId 0) tokenAuth0
  , DeltaSetSessionOps (SessionId 1) emptySessionOps
  ]

-- | The three separations on the seeded base: object-only leaves
-- sessions+token-auth UNCHANGED; session-only leaves
-- objects+handles+token-auth UNCHANGED; token-only leaves
-- sessions+objects+handles UNCHANGED. A failing side passes
-- (fault atomicity is the delta law's domain) — but
-- on the seeded base every class has succeeding sides, so the
-- assertions execute (no vacuous arms).
checkPartition :: [DeltaOp] -> IO ()
checkPartition ops = do
  let objectOnly = [op | op <- ops, opClass op == OCObject]
      sessionOnly = [op | op <- ops, opClass op == OCSession]
      tokenOnly = [op | op <- ops, opClass op == OCToken]
  case publishDelta seedBase (StateDelta objectOnly) of
    Left _ -> pure ()
    Right m -> do
      assertEqual "object ops leave sessions unchanged"
        (mSessions seedBase) (mSessions m)
      assertEqual "object ops leave token-auth unchanged"
        (mTokenAuth seedBase) (mTokenAuth m)
  case publishDelta seedBase (StateDelta sessionOnly) of
    Left _ -> pure ()
    Right m -> do
      assertEqual "session ops leave objects unchanged"
        (mObjects seedBase) (mObjects m)
      assertEqual "session ops leave handles unchanged"
        (mHandles seedBase) (mHandles m)
      assertEqual "session ops leave token-auth unchanged"
        (mTokenAuth seedBase) (mTokenAuth m)
  case publishDelta seedBase (StateDelta tokenOnly) of
    Left _ -> pure ()
    Right m -> do
      assertEqual "token ops leave sessions unchanged"
        (mSessions seedBase) (mSessions m)
      assertEqual "token ops leave objects unchanged"
        (mObjects seedBase) (mObjects m)
      assertEqual "token ops leave handles unchanged"
        (mHandles seedBase) (mHandles m)

caseFull :: Int -> IO ()
caseFull count = do
  seedOv <- propSeedOverride
  let seeds = freshSeeds seedOv count
  mapM_ checkGen [(seed, len) | seed <- seeds, len <- [0 .. 12]]
  mapM_ checkConst [(op, len) | op <- constOpsFull, len <- [0 .. 12]]
  where
    checkGen :: (Word64, Int) -> IO ()
    checkGen (seed, len) = checkPartition (genSeqFull seed len)
    checkConst :: (DeltaOp, Int) -> IO ()
    checkConst (op, len) = checkPartition (replicate len op)

-- Keep the original LCG and all of its seeds/traces intact. These named
-- success/failure traces add permanent retirement without diluting that corpus.
caseUnbind :: IO ()
caseUnbind = mapM_ check
  [ [DeltaUnbindHandle (ExternalHandle 9)]
  , [DeltaUnbindHandle (ExternalHandle 9), DeltaUnbindHandle (ExternalHandle 9)]
  , [DeltaUnbindHandle (ExternalHandle 9), DeltaBindHandle (ExternalHandle 11) (ObjectId 9)]
  , [DeltaUnbindHandle (ExternalHandle 9), DeltaDestroyObject (ObjectId 404)]
  ]
  where
    check ops = do
      checkSeparation ops
      checkPartition ops
      case publishDelta seedBase (StateDelta ops) of
        Left _ -> pure ()
        Right m -> do
          assertEqual "old binding deleted" Nothing (Map.lookup (ExternalHandle 9) (mHandles m))
          assertEqual "parked objects retained" (mObjects seedBase) (mObjects m)

-- ---------------------------------------------------------------------------
-- Attribute namespace + constructor witnesses + corpus hits
-- ---------------------------------------------------------------------------

-- | Attribute updates against populated objects: a nonempty change
-- lands in the object map while the session, handle, and token-auth
-- namespaces stay identical. Covers empty-to-nonempty,
-- overwrite-merge (overlay wins, siblings kept), and token
-- promotion deterministically, plus generated overlays retargeted
-- at a seeded object.
caseAttrNamespace :: IO ()
caseAttrNamespace = do
  checkOverlay "empty-to-nonempty" seedBase (ObjectId 9)
    (Map.singleton AttrClass (ValULong 3))
    (Map.singleton AttrClass (ValULong 3))
  -- Overwrite-merge starts from an object that already holds two
  -- attributes; the overlay wins its key and keeps the sibling.
  case publishDelta seedBase (StateDelta
         [DeltaCreateObjectFull oidWitness
            (Map.fromList [(AttrClass, ValULong 1),
                           (AttrToken, ValBool False)])
            Nothing (SlotId 0)]) of
    Left fault ->
      assertFailure ("overwrite setup faulted: " ++ show fault)
    Right seeded ->
      checkOverlay "overwrite-merge" seeded oidWitness
        (Map.singleton AttrClass (ValULong 2))
        (Map.fromList [(AttrClass, ValULong 2),
                       (AttrToken, ValBool False)])
  -- Token promotion moves ownership off the session while staying
  -- object-local.
  case publishDelta seedBase (StateDelta
         [DeltaCreateObjectFull oidWitness2 Map.empty
            (Just (SessionId 1)) (SlotId 0)]) of
    Left fault ->
      assertFailure ("promotion setup faulted: " ++ show fault)
    Right seeded ->
      case publishDelta seeded (StateDelta
             [DeltaSetAttributes oidWitness2
                (Map.singleton AttrToken (ValBool True))]) of
        Left fault ->
          assertFailure ("promotion faulted: " ++ show fault)
        Right m -> do
          assertEqual "promotion keeps sessions"
            (mSessions seeded) (mSessions m)
          assertEqual "promotion keeps handles"
            (mHandles seeded) (mHandles m)
          assertEqual "promotion keeps token-auth"
            (mTokenAuth seeded) (mTokenAuth m)
          case Map.lookup oidWitness2 (mObjects m) of
            Nothing -> assertFailure "promotion: object vanished"
            Just ost -> do
              assertEqual "promotion moves owner off session"
                Nothing (osOwner ost)
              assertEqual "promotion sets token flag"
                (Map.singleton AttrToken (ValBool True)) (osAttrs ost)
  -- Generated overlays, retargeted at a seeded object so every one
  -- applies on the success path.
  seedOvAttr <- propSeedOverride
  let overlays =
        [ over
        | seed <- freshSeeds seedOvAttr 25
        , DeltaSetAttributes _ over <- genSeqFull14 seed 12
        ]
  assertBool "generator emits attribute updates" (not (null overlays))
  assertBool "generated overlays are nonempty"
    (all (not . Map.null) overlays)
  mapM_ (checkGenOverlay (ObjectId 9)) overlays
  where
    oidWitness = ObjectId 11
    oidWitness2 = ObjectId 12
    checkOverlay
      :: String
      -> Model
      -> ObjectId
      -> Map.Map AttributeType AttributeValue
      -> Map.Map AttributeType AttributeValue
      -> IO ()
    checkOverlay label base oid over want = do
      assertBool (label ++ ": overlay nonempty") (not (Map.null over))
      case publishDelta base (StateDelta [DeltaSetAttributes oid over]) of
        Left fault ->
          assertFailure (label ++ " faulted: " ++ show fault)
        Right m -> do
          assertEqual (label ++ ": sessions unchanged")
            (mSessions base) (mSessions m)
          assertEqual (label ++ ": handles unchanged")
            (mHandles base) (mHandles m)
          assertEqual (label ++ ": token-auth unchanged")
            (mTokenAuth base) (mTokenAuth m)
          case Map.lookup oid (mObjects m) of
            Nothing -> assertFailure (label ++ ": object vanished")
            Just ost ->
              assertEqual (label ++ ": attrs merged") want (osAttrs ost)
    checkGenOverlay :: ObjectId -> Map.Map AttributeType AttributeValue -> IO ()
    checkGenOverlay oid over =
      let baseAttrs = maybe Map.empty osAttrs
            (Map.lookup oid (mObjects seedBase))
      in checkOverlay "generated overlay" seedBase oid over
           (Map.union over baseAttrs)

-- | Sensitivity control for the attribute namespace law: the pure
-- update leaves sessions IDENTICAL, while the same update plus a
-- genuine session mutation leaves them DIFFERENT. If the second
-- assertion ever failed, the namespace comparison would be blind
-- to session writes.
caseAttrSensitivity :: IO ()
caseAttrSensitivity = do
  let over = Map.singleton AttrClass (ValULong 3)
      oid = ObjectId 9
  case publishDelta seedBase (StateDelta [DeltaSetAttributes oid over]) of
    Left fault ->
      assertFailure ("pure update faulted: " ++ show fault)
    Right m ->
      assertEqual "pure update keeps sessions"
        (mSessions seedBase) (mSessions m)
  case publishDelta seedBase (StateDelta
         [DeltaSetAttributes oid over,
          DeltaCloseSession (SessionId 2)]) of
    Left fault ->
      assertFailure ("mutating update faulted: " ++ show fault)
    Right m ->
      assertBool "session mutation visible"
        (mSessions seedBase /= mSessions m)

-- | One succeeding op per constructor on the seeded base: every
-- witness MUST publish Right with its intended effect, so failed
-- operations and vacuous Left skips cannot satisfy coverage.
caseConstructorWitnesses :: IO ()
caseConstructorWitnesses = mapM_ check witnesses
  where
    witnesses :: [(String, DeltaOp, Model -> IO ())]
    witnesses =
      [ ("touch", DeltaTouchSession (SessionId 1), \m ->
            assertEqual "touch keeps sessions"
              (mSessions seedBase) (mSessions m))
      , ("close", DeltaCloseSession (SessionId 3), \m ->
            assertEqual "close drops session" True
              (not (Map.member (SessionId 3) (mSessions m))))
      , ("bump-generation",
          DeltaBumpGeneration (SessionId 1) (Generation 9), \m ->
            assertBool "bump changes sessions"
              (mSessions seedBase /= mSessions m))
      , ("create", DeltaCreateObject (ObjectId 1), \m ->
            assertEqual "create inserts" True
              (Map.member (ObjectId 1) (mObjects m)))
      , ("destroy", DeltaDestroyObject (ObjectId 10), \m ->
            assertEqual "destroy removes" True
              (not (Map.member (ObjectId 10) (mObjects m))))
      , ("create-full",
          DeltaCreateObjectFull (ObjectId 2) Map.empty Nothing (SlotId 0),
          \m -> assertEqual "create-full inserts" True
              (Map.member (ObjectId 2) (mObjects m)))
      , ("set-attributes",
          DeltaSetAttributes (ObjectId 9)
            (Map.singleton AttrClass (ValULong 3)),
          \m -> case Map.lookup (ObjectId 9) (mObjects m) of
              Nothing -> assertFailure "set-attributes: object vanished"
              Just ost -> assertEqual "set-attributes merges"
                (Map.singleton AttrClass (ValULong 3)) (osAttrs ost))
      , ("bind", DeltaBindHandle (ExternalHandle 11) (ObjectId 9), \m ->
            assertEqual "bind inserts" True
              (Map.member (ExternalHandle 11) (mHandles m)))
      , ("unbind", DeltaUnbindHandle (ExternalHandle 9), \m ->
            assertEqual "unbind deletes" True
              (not (Map.member (ExternalHandle 9) (mHandles m))))
      , ("bump-handle", DeltaBumpHandle (ExternalHandle 10), \m ->
            assertBool "bump changes handles"
              (mHandles seedBase /= mHandles m))
      , ("open-session",
          DeltaOpenSession (SessionId 4) (SlotId 1) False, \m ->
            assertEqual "open inserts session" True
              (Map.member (SessionId 4) (mSessions m)))
      , ("set-session-login",
          DeltaSetSessionLogin (SessionId 1) LoginUser, \m ->
            assertBool "login changes sessions"
              (mSessions seedBase /= mSessions m))
      , ("set-token-auth", DeltaSetTokenAuth (SlotId 1) tokenAuth0, \m ->
            assertBool "auth changes token-auth"
              (mTokenAuth seedBase /= mTokenAuth m))
      , ("set-session-ops",
          DeltaSetSessionOps (SessionId 1) emptySessionOps, \m ->
            assertBool "ops change sessions"
              (mSessions seedBase /= mSessions m))
      ]
    check :: (String, DeltaOp, Model -> IO ()) -> IO ()
    check (label, op, effect) =
      case publishDelta seedBase (StateDelta [op]) of
        Left fault ->
          assertFailure ("witness " ++ label ++ " faulted: " ++ show fault)
        Right m -> effect m

-- | Hit obligations over the full generated corpus: every
-- constructor appears at least once, so raising case counts can
-- never substitute for constructor coverage. The corpus size is
-- fixed (PROP_SEED shifts it, never shrinks it) so tiny case
-- counts cannot starve an arm.
caseCorpusHits :: Int -> IO ()
caseCorpusHits _count = do
  seedOv <- propSeedOverride
  let seeds = freshSeeds seedOv 50
      corpus =
        [ op
        | seed <- seeds
        , len <- [0 .. 12]
        , op <- genSeqFull14 seed len
        ]
      hits = constructorHits corpus
  putStrLn ("namespace corpus: " ++ hitSummary hits)
  mapM_ (checkHit hits) [ctorName op | op <- constOpsFull]
  where
    checkHit hits name =
      assertBool ("corpus hits " ++ name)
        (Map.findWithDefault 0 name hits >= 1)
