{- | One checked rule, end to end: logout/object lifetime.

A user call becomes a 'Request' ADT, the planner answers Reject,
Immediate, or Execute, effects finish through 'finishEffect',
commits are decided as 'PreparedCommit' values and land through
'publishDelta' (in-memory publication; the runtime performs
'pcPersist' for durability, which this program does not do), and
the printed facts at the end are read back from the model. The
rule being taught:

logout on a slot destroys every private session object on that
slot, stale-marks the handles bound to private objects there,
retires the private-key operations, and clears the login; public
session objects and token objects survive, and other slots are
untouched.

Every stage prints what happened; any violated expectation ends
the program with a nonzero exit, so @cabal run exe:logout-journey@
is itself the check. The sign step uses clearly marked simulated
engine bytes: the real backend is out of scope for this example,
which teaches the pipeline shape around one policy rule.
-}
{-# LANGUAGE OverloadedStrings #-}
module Main (main) where

import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import qualified Data.Map.Strict as Map
import Data.Maybe (isJust, isNothing)
import System.Exit (die)
import System.IO (hPutStrLn, stderr)

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
import Haskoki.Operation (SlotKind (..), activeSlots)
import Haskoki.Operation.Codec (encodeInitInput)
import Haskoki.Outcome
  ( EffectRequest
  , EngineResult (..)
  , PlanResult (..)
  , PreparedCommit (..)
  , Rejection (..)
  , Reservation
  , StateDelta
  )
import Haskoki.Registry (MechanismId (..), Operation (..))
import Haskoki.Request
  ( FunctionId (..)
  , OutputIntent (..)
  , OutputRegion (..)
  , Request (..)
  )
import Haskoki.Rules (defaultRules)
import Haskoki.Session (SessionLogin (..), TokenAuth (..))
import Haskoki.Transition (finishEffect, planCall, publishDelta)
import Haskoki.Types
  ( ExternalHandle
  , ObjectId
  , Pkcs11Version (..)
  , ReturnCode (..)
  , SessionId (..)
  , SlotId (..)
  )

main :: IO ()
main = do
  stage "0: seat a token and open a session"
  let m0 = addToken emptyModel slot0
  (sid, m1) <- openSession m0
  putLog ("session: " ++ show sid)
  check "exactly one session" (Map.size (mSessions m1) == 1)

  stage "1: refusal — logout while public changes nothing"
  m2 <- case planCall defaultRules m1 (logoutReq sid) of
    Reject rej -> do
      putLog ("planner said: Reject " ++ show (rejCode rej))
      check "refusal code" (rejCode rej == CKR_USER_NOT_LOGGED_IN)
      publish ("refusal delta: " ++ show (rejDelta rej)) m1 (rejDelta rej)
    other -> die ("expected a refusal, got: " ++ show other)
  check "model unchanged by the refusal" (m1 == m2)

  stage "2: login commits and publishes"
  (pcLogin, m3) <- planAndPublish m2 (loginReq sid)
  check "login code" (pcCode pcLogin == CKR_OK)
  putLog ("token auth: " ++ show (Map.lookup slot0 (mTokenAuth m3)))

  stage "3: create one object per lifetime corner"
  (_, m4) <- planAndPublish m3 (createReq sid keyTmpl)
  (_, m5) <- planAndPublish m4
    (createReq sid [classData, label "journey-public", tokenFlag])
  (_, m6) <- planAndPublish m5
    (createReq sid [classData, label "journey-scratch"])
  keyOid <- mustFind m6 "journey-key"
  pubOid <- mustFind m6 "journey-public"
  scrOid <- mustFind m6 "journey-scratch"
  putLog ("private session key: " ++ show keyOid)
  putLog ("public token object: " ++ show pubOid)
  putLog ("public session object: " ++ show scrOid)
  check "three objects live" (Map.size (mObjects m6) == 3)

  stage "4: effect — sign through the session key"
  keyHandle <- mustHandle m6 keyOid
  (_, m7) <- planAndPublish m6 (signInitReq sid keyHandle)
  putLog "sign initialized (Immediate commit)"
  (res, eff) <- planExecute m7 (dataReq F_Sign sid "sig" "hello pkcs11" 64)
  putLog ("reservation: " ++ show res)
  putLog ("effect request: " ++ show eff)
  m8 <- case finishEffect defaultRules m7 res simSignature of
    Left rej -> die ("finish rejected: " ++ show (rejCode rej))
    Right pc -> do
      putLog "finish accepted the simulated engine bytes"
      putLog ("commit code: " ++ show (pcCode pc))
      publish "signature commit" m7 (pcDelta pc)

  stage "4b: a second sign stays live at logout"
  (_, m9) <- planAndPublish m8 (signInitReq sid keyHandle)
  putLog "second sign initialized and left running"

  stage "5: logout commits the rule"
  pcLogout <- case planCall defaultRules m9 (logoutReq sid) of
    Immediate pc -> do
      putLog ("planner said: Immediate " ++ show (pcCode pc))
      putLog ("delta ops: " ++ show (pcDelta pc))
      pure pc
    other -> die ("expected Immediate, got: " ++ show other)
  m10 <- publish "logout commit" m9 (pcDelta pcLogout)

  stage "6: publication — read the rule back from the model"
  check "private session key destroyed" (isNothing (findByLabel m10 "journey-key"))
  check "public token object survives" (isJust (findByLabel m10 "journey-public"))
  check "public session object survives" (isJust (findByLabel m10 "journey-scratch"))
  check "session back to public" (sessionLoginOf m10 sid == Just LoginPublic)
  check "token logged out" (tokenLoggedIn m10 slot0 == Just False)
  stFinal <- mustSession m10 sid
  putLog ("live operation slots after logout: " ++ show (activeSlots (ssOps stFinal)))
  check "private-key sign retired" (SlotSign `notElem` activeSlots (ssOps stFinal))
  putLog "RULE HOLDS: logout destroyed exactly the private session objects"

-- ---------------------------------------------------------------------------
-- Harness
-- ---------------------------------------------------------------------------

slot0 :: SlotId
slot0 = SlotId 0

stage :: String -> IO ()
stage s = putStrLn ("--- " ++ s)

putLog :: String -> IO ()
putLog s = putStrLn ("    " ++ s)

check :: String -> Bool -> IO ()
check what True = putStrLn ("    ok: " ++ what)
check what False = do
  hPutStrLn stderr ("VIOLATION: " ++ what)
  die ("example failed at: " ++ what)

mkRequest :: FunctionId -> Maybe SessionId -> Request
mkRequest fun mSid = Request
  { reqVersion = Pkcs11_3_2
  , reqFunction = fun
  , reqSession = mSid
  , reqHandle = Nothing
  , reqInput = mempty
  , reqRegions = []
  }

openReq :: SlotId -> Request
openReq (SlotId n) =
  (mkRequest F_OpenSession Nothing) { reqInput = "slot=" <> digit <> ",rw" }
  where
    digit = case n of
      0 -> "0"
      _ -> "9"

loginReq :: SessionId -> Request
loginReq sid = (mkRequest F_Login (Just sid)) { reqInput = "user:ok" }

logoutReq :: SessionId -> Request
logoutReq sid = mkRequest F_Logout (Just sid)

createReq :: SessionId -> [(AttributeType, AttributeValue)] -> Request
createReq sid tmpl =
  (mkRequest F_CreateObject (Just sid)) { reqInput = encodeTemplate tmpl }

signInitReq :: SessionId -> ExternalHandle -> Request
signInitReq sid h = (mkRequest F_SignInit (Just sid))
  { reqHandle = Just h
  , reqInput = encodeInitInput (MechanismId 0x251) [OpSign] False BS.empty
  }

dataReq :: FunctionId -> SessionId -> String -> ByteString -> Int -> Request
dataReq fid sid name blob cap =
  (mkRequest fid (Just sid))
    { reqInput = blob
    , reqRegions = [RegionBytes name (IntentBuffer (fromIntegral cap))]
    }

classData :: (AttributeType, AttributeValue)
classData = (AttrClass, ValULong 0)

label :: ByteString -> (AttributeType, AttributeValue)
label s = (AttrLabel, ValBytes s)

tokenFlag :: (AttributeType, AttributeValue)
tokenFlag = (AttrToken, ValBool True)

-- | A private session HMAC key: no 'AttrToken' entry, so the object
-- is session-owned and the logout rule will destroy it.
keyTmpl :: [(AttributeType, AttributeValue)]
keyTmpl =
  [ (AttrClass, ValULong (mustClassId "CKO_SECRET_KEY"))
  , (AttrKeyType, ValULong (mustKeyTypeId "CKK_GENERIC_SECRET"))
  , (AttrValue, ValBytes "0123456789abcdef0123456789abcdef")
  , (AttrPrivate, ValBool True)
  , (AttrSign, ValBool True)
  , label "journey-key"
  ]

-- | Simulated engine bytes standing in for the real backend, which
-- is out of scope here: a 32-byte stub signature. Labeled at every
-- use so no reader mistakes it for backend evidence.
simSignature :: EngineResult
simSignature = EngineOkBytes (BS.replicate 32 0xEE)

openSession :: Model -> IO (SessionId, Model)
openSession model = do
  (pc, m') <- planAndPublish model (openReq slot0)
  putLog ("open code: " ++ show (pcCode pc))
  pure (SessionId (mNextSession model), m')

planAndPublish :: Model -> Request -> IO (PreparedCommit, Model)
planAndPublish model req =
  case planCall defaultRules model req of
    Immediate pc -> do
      putLog ("planner said: Immediate " ++ show (pcCode pc))
      m' <- publish "commit" model (pcDelta pc)
      pure (pc, m')
    Reject rej -> die ("expected a commit, refused: " ++ show (rejCode rej))
    Execute _ _ -> die "expected a commit, got Execute"

planExecute :: Model -> Request -> IO (Reservation, EffectRequest)
planExecute model req =
  case planCall defaultRules model req of
    Execute res eff -> do
      putLog "planner said: Execute (an effect leaves the model gate)"
      pure (res, eff)
    other -> die ("expected Execute, got: " ++ show other)

publish :: String -> Model -> StateDelta -> IO Model
publish what model delta =
  case publishDelta model delta of
    Left fault -> die ("publication fault (" ++ what ++ "): " ++ show fault)
    Right m' -> m' <$ putLog ("published: " ++ what)

findByLabel :: Model -> ByteString -> Maybe ObjectId
findByLabel m lbl =
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

mustFind :: Model -> ByteString -> IO ObjectId
mustFind m lbl = case findByLabel m lbl of
  Nothing -> die ("setup object lost: " ++ show lbl)
  Just oid -> pure oid

mustHandle :: Model -> ObjectId -> IO ExternalHandle
mustHandle m oid = case
  [ h | (h, b) <- Map.toList (mHandles m), hbObject b == oid ] of
  (h : _) -> pure h
  [] -> die ("no handle bound for: " ++ show oid)

mustSession :: Model -> SessionId -> IO SessionState
mustSession m sid = case Map.lookup sid (mSessions m) of
  Nothing -> die ("session lost: " ++ show sid)
  Just st -> pure st

sessionLoginOf :: Model -> SessionId -> Maybe SessionLogin
sessionLoginOf m sid = ssLogin <$> Map.lookup sid (mSessions m)

tokenLoggedIn :: Model -> SlotId -> Maybe Bool
tokenLoggedIn m slot = isJust . taLogin <$> Map.lookup slot (mTokenAuth m)
