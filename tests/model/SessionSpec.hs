{- | Session/auth lifecycle model tests: the login matrix.

Every case drives 'planCall' and 'publishDelta' (rejection deltas
included: denied PIN attempts persist their counters exactly like
the runtime publishes them).
-}
{-# LANGUAGE OverloadedStrings #-}
module SessionSpec (spec) where

import qualified Data.Map.Strict as Map
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertEqual, assertFailure, testCase)

import Haskoki.Model
  ( Model (..)
  , SessionState (ssLogin)
  , addToken
  , emptyModel
  , lookupSession
  , lookupTokenAuth
  )
import Haskoki.Outcome
  ( PlanResult (..)
  , PreparedCommit (..)
  , Rejection (..)
  )
import Haskoki.Request (FunctionId (..), Request (..))
import Haskoki.Rules (Rules (..), defaultRules)
import Haskoki.Session
  ( ActiveLogin (..)
  , SessionLogin (..)
  , TokenAuth (..)
  )
import Haskoki.Transition (planCall, publishDelta)
import Haskoki.Types
  ( Pkcs11Version (..)
  , ReturnCode (..)
  , SessionId (..)
  , SlotId (..)
  )

spec :: TestTree
spec = testGroup "session lifecycle"
  [ testCase "login through A is visible through B" caseLoginVisible
  , testCase "last session close logs out" caseLastCloseLogout
  , testCase "SO and read-only sessions exclude each other" caseSoRoConflict
  , testCase "context login needs user login and active op" caseContextGrant
  , testCase "named-user login records the principal" caseNamedUser
  , testCase "PIN lockout is deterministic (default 3)" casePinLockout
  , testCase "PIN threshold comes from rules" casePinThreshold
  , testCase "success resets the attempt counter" caseCounterReset
  , testCase "double and cross-role login denied" caseAlreadyAnother
  , testCase "logout clears token and sessions" caseLogout
  , testCase "admission: token, bound, args" caseAdmission
  , testCase "session-close ordering (A30 analogue)" caseCloseOrdering
  ]

-- ---------------------------------------------------------------------------
-- Harness
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

openReq :: SlotId -> Bool -> Request
openReq (SlotId n) readOnly =
  (mkRequest F_OpenSession Nothing)
    { reqInput = "slot=" <> slotNum <> (if readOnly then ",ro" else ",rw")
    }
  where
    slotNum = case n of
      0 -> "0"
      1 -> "1"
      _ -> "9"

loginReq :: SessionId -> String -> Request
loginReq sid args =
  (mkRequest F_Login (Just sid)) { reqInput = loginBytes args }
  where
    loginBytes s = case s of
      "user-ok" -> "user:ok"
      "user-bad" -> "user:bad"
      "so-ok" -> "so:ok"
      "so-bad" -> "so:bad"
      "ctx-ok" -> "context:ok"
      "ctx-bad" -> "context:bad"
      ('u' : 's' : 'e' : 'r' : ':' : rest) -> "user:" <> userBytes rest
      _ -> "bogus"
    userBytes r = case r of
      "alice-ok" -> "alice:ok"
      _ -> "bob:ok"

-- | Plan and publish an Immediate commit; fail otherwise.
runCommit :: Rules -> Model -> Request -> IO Model
runCommit rules model req =
  case planCall rules model req of
    Immediate pc -> case publishDelta model (pcDelta pc) of
      Left fault -> assertFailure ("delta fault: " ++ show fault)
      Right m' -> pure m'
    Reject rej -> assertFailure ("expected commit, rejected: " ++ show (rejCode rej))
    Execute _ _ -> assertFailure "expected commit, got Execute"

-- | Plan a rejection; publish its delta (counter persistence) and
-- return the code plus the updated model.
runReject :: Rules -> Model -> Request -> IO (ReturnCode, Model)
runReject rules model req =
  case planCall rules model req of
    Reject rej -> case publishDelta model (rejDelta rej) of
      Left fault -> assertFailure ("rejection delta fault: " ++ show fault)
      Right m' -> pure (rejCode rej, m')
    Immediate pc -> assertFailure ("expected reject, committed: " ++ show (pcCode pc))
    Execute _ _ -> assertFailure "expected reject, got Execute"

openSession :: Rules -> Model -> SlotId -> Bool -> IO (SessionId, Model)
openSession rules model slot readOnly = do
  m' <- runCommit rules model (openReq slot readOnly)
  let sid = SessionId (mNextSession model)
  case lookupSession m' sid of
    Nothing -> assertFailure "opened session missing from model"
    Just _ -> pure (sid, m')

loginAs :: Rules -> Model -> SessionId -> String -> IO Model
loginAs rules model sid args = runCommit rules model (loginReq sid args)

closeSession :: Rules -> Model -> SessionId -> IO Model
closeSession rules model sid =
  runCommit rules model (mkRequest F_CloseSession (Just sid))

authOf :: Model -> SlotId -> TokenAuth
authOf model slot = case lookupTokenAuth model slot of
  Nothing -> error "token missing"
  Just a -> a

loginOf :: Model -> SessionId -> SessionLogin
loginOf model sid = case lookupSession model sid of
  Nothing -> error "session missing"
  Just st -> ssLogin st

-- ---------------------------------------------------------------------------
-- Cases
-- ---------------------------------------------------------------------------

caseLoginVisible :: IO ()
caseLoginVisible = do
  (a, m1) <- openSession defaultRules seeded slot0 False
  (b, m2) <- openSession defaultRules m1 slot0 False
  m3 <- loginAs defaultRules m2 a "user-ok"
  assertEqual "token login" (Just AuthUser) (taLogin (authOf m3 slot0))
  assertEqual "A sees user" LoginUser (loginOf m3 a)
  assertEqual "B sees user" LoginUser (loginOf m3 b)
  assertEqual "epoch bumped once" 1 (taAuthEpoch (authOf m3 slot0))
  -- A session opened after login observes the token login too.
  (c, m4) <- openSession defaultRules m3 slot0 False
  assertEqual "late open sees user" LoginUser (loginOf m4 c)

caseLastCloseLogout :: IO ()
caseLastCloseLogout = do
  (a, m1) <- openSession defaultRules seeded slot0 False
  (b, m2) <- openSession defaultRules m1 slot0 False
  m3 <- loginAs defaultRules m2 a "user-ok"
  m4 <- closeSession defaultRules m3 a
  assertEqual "still logged in" (Just AuthUser) (taLogin (authOf m4 slot0))
  assertEqual "B still user" LoginUser (loginOf m4 b)
  m5 <- closeSession defaultRules m4 b
  assertEqual "token public" Nothing (taLogin (authOf m5 slot0))
  assertEqual "epoch bumped on logout" 2 (taAuthEpoch (authOf m5 slot0))
  assertEqual "no sessions left" 0 (Map.size (mSessions m5))

caseSoRoConflict :: IO ()
caseSoRoConflict = do
  (ro, m1) <- openSession defaultRules seeded slot0 True
  (rw, m2) <- openSession defaultRules m1 slot0 False
  -- SO login with a read-only session open is denied; token unchanged.
  (code, m3) <- runReject defaultRules m2 (loginReq rw "so-ok")
  assertEqual "SO blocked by RO" CKR_SESSION_READ_ONLY_EXISTS code
  assertEqual "token still public" Nothing (taLogin (authOf m3 slot0))
  -- Closing the RO session unblocks SO login.
  m4 <- closeSession defaultRules m3 ro
  m5 <- loginAs defaultRules m4 rw "so-ok"
  assertEqual "SO logged in" (Just AuthSO) (taLogin (authOf m5 slot0))
  assertEqual "RW sees SO" LoginSO (loginOf m5 rw)
  -- The exclusion runs the other way too: no RO opens under SO.
  (code2, _) <- runReject defaultRules m5 (openReq slot0 True)
  assertEqual "RO blocked under SO" CKR_SESSION_READ_ONLY_EXISTS code2
  -- But a second RW session is fine, and it observes the SO login.
  (rw2, m6) <- openSession defaultRules m5 slot0 False
  assertEqual "new RW observes SO" LoginSO (loginOf m6 rw2)

caseContextGrant :: IO ()
caseContextGrant = do
  (a, m1) <- openSession defaultRules seeded slot0 False
  (b, m2) <- openSession defaultRules m1 slot0 False
  -- Context login on a public token is denied.
  (code, _) <- runReject defaultRules m2 (loginReq b "ctx-ok")
  assertEqual "context needs user login" CKR_USER_NOT_LOGGED_IN code
  m3 <- loginAs defaultRules m2 a "user-ok"
  -- Without an active operation there is nothing to re-authenticate:
  -- state conflicts decide before PIN evaluation, so even the right
  -- PIN refuses with OPERATION_NOT_INITIALIZED (the grant shape with
  -- an active op is pinned at the C adapter instead).
  (codeOp, m4) <- runReject defaultRules m3 (loginReq b "ctx-ok")
  assertEqual "context needs active op" CKR_OPERATION_NOT_INITIALIZED codeOp
  (codeBad, m5) <- runReject defaultRules m4 (loginReq b "ctx-bad")
  assertEqual "no-op refuses before PIN check" CKR_OPERATION_NOT_INITIALIZED codeBad
  assertEqual "no attempt consumed" 0 (taUserAttempts (authOf m5 slot0))
  assertEqual "B observes user login without grant" LoginUser (loginOf m5 b)

caseNamedUser :: IO ()
caseNamedUser = do
  (a, m1) <- openSession defaultRules seeded slot0 False
  m2 <- loginAs defaultRules m1 a "user:alice-ok"
  assertEqual "principal recorded" (Just "alice") (taPrincipal (authOf m2 slot0))
  m3 <- runCommit defaultRules m2 (mkRequest F_Logout (Just a))
  assertEqual "principal cleared" Nothing (taPrincipal (authOf m3 slot0))

casePinLockout :: IO ()
casePinLockout = do
  (a, m1) <- openSession defaultRules seeded slot0 False
  (c1, m2) <- runReject defaultRules m1 (loginReq a "user-bad")
  assertEqual "first failure" CKR_PIN_INCORRECT c1
  (c2, m3) <- runReject defaultRules m2 (loginReq a "user-bad")
  assertEqual "second failure" CKR_PIN_INCORRECT c2
  assertEqual "two attempts" 2 (taUserAttempts (authOf m3 slot0))
  (c3, m4) <- runReject defaultRules m3 (loginReq a "user-bad")
  assertEqual "third failure locks" CKR_PIN_LOCKED c3
  assertEqual "locked flag" True (taUserLocked (authOf m4 slot0))
  -- Lockout is sticky: even the right PIN stays locked.
  (c4, m5) <- runReject defaultRules m4 (loginReq a "user-ok")
  assertEqual "correct PIN still locked" CKR_PIN_LOCKED c4
  assertEqual "token never logged in" Nothing (taLogin (authOf m5 slot0))
  -- The SO role is independent: SO login still works.
  m6 <- loginAs defaultRules m5 a "so-ok"
  assertEqual "SO unaffected" (Just AuthSO) (taLogin (authOf m6 slot0))

casePinThreshold :: IO ()
casePinThreshold = do
  let rules1 = defaultRules { rulesMaxPinAttempts = 1 }
      rules5 = defaultRules { rulesMaxPinAttempts = 5 }
  (a, m1) <- openSession rules1 seeded slot0 False
  (c1, _) <- runReject rules1 m1 (loginReq a "user-bad")
  assertEqual "threshold 1 locks at once" CKR_PIN_LOCKED c1
  (b, m2) <- openSession rules5 seeded slot0 False
  m3 <- foldl (\acc _ -> acc >>= \m -> snd <$> runReject rules5 m (loginReq b "user-bad"))
    (pure m2) [1 .. 4 :: Int]
  assertEqual "four failures below 5" 4 (taUserAttempts (authOf m3 slot0))
  assertEqual "not locked yet" False (taUserLocked (authOf m3 slot0))
  (c5, m4) <- runReject rules5 m3 (loginReq b "user-bad")
  assertEqual "fifth failure locks" CKR_PIN_LOCKED c5
  assertEqual "locked" True (taUserLocked (authOf m4 slot0))

caseCounterReset :: IO ()
caseCounterReset = do
  (a, m1) <- openSession defaultRules seeded slot0 False
  (_, m2) <- runReject defaultRules m1 (loginReq a "user-bad")
  (_, m3) <- runReject defaultRules m2 (loginReq a "user-bad")
  m4 <- loginAs defaultRules m3 a "user-ok"
  assertEqual "counter reset" 0 (taUserAttempts (authOf m4 slot0))
  m5 <- runCommit defaultRules m4 (mkRequest F_Logout (Just a))
  (_, m6) <- runReject defaultRules m5 (loginReq a "user-bad")
  assertEqual "fresh counter" 1 (taUserAttempts (authOf m6 slot0))

caseAlreadyAnother :: IO ()
caseAlreadyAnother = do
  (a, m1) <- openSession defaultRules seeded slot0 False
  m2 <- loginAs defaultRules m1 a "user-ok"
  (c1, _) <- runReject defaultRules m2 (loginReq a "user-ok")
  assertEqual "double user login" CKR_USER_ALREADY_LOGGED_IN c1
  (c2, m3) <- runReject defaultRules m2 (loginReq a "so-ok")
  assertEqual "SO over user" CKR_USER_ANOTHER_ALREADY_LOGGED_IN c2
  assertEqual "user still logged in" (Just AuthUser) (taLogin (authOf m3 slot0))
  m4 <- runCommit defaultRules m3 (mkRequest F_Logout (Just a))
  m5 <- loginAs defaultRules m4 a "so-ok"
  (c3, _) <- runReject defaultRules m5 (loginReq a "user-ok")
  assertEqual "user over SO" CKR_USER_ANOTHER_ALREADY_LOGGED_IN c3

caseLogout :: IO ()
caseLogout = do
  (a, m1) <- openSession defaultRules seeded slot0 False
  (b, m2) <- openSession defaultRules m1 slot0 False
  (c0, _) <- runReject defaultRules m2 (mkRequest F_Logout (Just a))
  assertEqual "logout while public" CKR_USER_NOT_LOGGED_IN c0
  m3 <- loginAs defaultRules m2 a "user-ok"
  m4 <- runCommit defaultRules m3 (mkRequest F_Logout (Just b))
  assertEqual "token public" Nothing (taLogin (authOf m4 slot0))
  assertEqual "A public" LoginPublic (loginOf m4 a)
  assertEqual "B public" LoginPublic (loginOf m4 b)
  assertEqual "epoch 2" 2 (taAuthEpoch (authOf m4 slot0))
  -- Login again bumps the epoch again: 1 login + 1 logout + 1 login = 3.
  m5 <- loginAs defaultRules m4 b "so-ok"
  assertEqual "epoch 3" 3 (taAuthEpoch (authOf m5 slot0))

caseAdmission :: IO ()
caseAdmission = do
  -- No token seated on slot 1.
  (c1, _) <- runReject defaultRules seeded (openReq (SlotId 1) False)
  assertEqual "absent token" CKR_TOKEN_NOT_PRESENT c1
  -- Session bound enforced.
  let rules1 = defaultRules { rulesMaxSessions = 1 }
  (_, m1) <- openSession rules1 seeded slot0 False
  (c2, _) <- runReject rules1 m1 (openReq slot0 False)
  assertEqual "sessions full" CKR_SESSION_COUNT c2
  -- Malformed arguments rejected.
  (c3, _) <- runReject defaultRules seeded
    ((mkRequest F_OpenSession Nothing) { reqInput = "nonsense" })
  assertEqual "bad open args" CKR_ARGUMENTS_BAD c3
  (a, m2) <- openSession defaultRules seeded slot0 False
  (c4, _) <- runReject defaultRules m2
    ((mkRequest F_Login (Just a)) { reqInput = "user" })
  assertEqual "bad login args" CKR_ARGUMENTS_BAD c4

caseCloseOrdering :: IO ()
caseCloseOrdering = do
  -- A30 analogue: N sessions, login in the middle, close in a
  -- scrambled order; only the final close logs out.
  (a, m1) <- openSession defaultRules seeded slot0 False
  (b, m2) <- openSession defaultRules m1 slot0 False
  (c, m3) <- openSession defaultRules m2 slot0 False
  m4 <- loginAs defaultRules m3 b "user-ok"
  m5 <- closeSession defaultRules m4 c
  assertEqual "close 1 of 3 stays in" (Just AuthUser) (taLogin (authOf m5 slot0))
  m6 <- closeSession defaultRules m5 a
  assertEqual "close 2 of 3 stays in" (Just AuthUser) (taLogin (authOf m6 slot0))
  assertEqual "login epoch still 1" 1 (taAuthEpoch (authOf m6 slot0))
  m7 <- closeSession defaultRules m6 b
  assertEqual "final close logs out" Nothing (taLogin (authOf m7 slot0))
  assertEqual "logout epoch 2" 2 (taAuthEpoch (authOf m7 slot0))
  assertEqual "all closed" 0 (Map.size (mSessions m7))
