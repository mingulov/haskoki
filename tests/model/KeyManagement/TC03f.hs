{- | KeyManagement T-C03f cases.
-}
{-# LANGUAGE OverloadedStrings #-}
module KeyManagement.TC03f
  ( trustedPending
  , trustedObject
  , plainObject
  , expectTrustedRefused
  , expectAdmitted
  , loginSo
  , caseKeygenTrustedUserRefused
  , caseKeypairTrustedUserRefused
  , caseDeriveUnwrapTrustedUserRefused
  , caseKeygenTrustedAllowedPaths
  , trustedSecret
  , plainSecret
  , expectFinishRefused
  , caseFinishTrustedUserRefused
  , caseFinishTrustedSoSucceeds
  , caseFinishUntrustedUserSucceeds
  ) where

import qualified Data.ByteString as BS
import qualified Data.Map.Strict as Map
import Test.Tasty.HUnit ( assertEqual, assertFailure)
import Haskoki.Attribute
  ( AttributeType (..)
  , AttributeValue (..)
  )
import Haskoki.Model
  ( Model (..)
  , SessionState
  )
import Haskoki.Operation.Effect ( CryptoResult (..))
import Haskoki.Operation.KeyManagement
  ( KeyDeny (..)
  , PendingObject (..)
  , PendingWork (..)
  , admitPending
  , ckoSecretKey
  , encodeKeyPair
  , finishWork
  )
import Haskoki.Outcome
  ( DeltaOp (..)
  , PlanResult (..)
  , Rejection (..)
  , StateDelta (..)
  )
import Haskoki.Session (SessionLogin (..))
import Haskoki.Transition (publishDelta)
import Haskoki.Types
  ( ReturnCode (..)
  )
import KeyManagement.Fixtures

-- ---------------------------------------------------------------------------
-- T-C03f cases: the SO-only TRUSTED gate covers the operation paths
-- ---------------------------------------------------------------------------

-- | One pending session object carrying exactly the given attributes.
trustedPending :: [(AttributeType, AttributeValue)] -> PendingObject
trustedPending attrs = PendingObject
  { poAttrs = Map.fromList attrs
  , poOwner = Just sid1
  , poSlot = slot0
  }

trustedObject :: PendingObject
trustedObject = trustedPending [(AttrTrusted, ValBool True)]

plainObject :: PendingObject
plainObject = trustedPending []

expectTrustedRefused :: String -> SessionState -> PendingWork -> IO ()
expectTrustedRefused label st pw = case admitPending st pw of
  Left deny -> assertEqual (label ++ " code") CKR_ATTRIBUTE_READ_ONLY (kdCode deny)
  Right () -> assertFailure (label ++ " admitted TRUSTED=true")

expectAdmitted :: String -> SessionState -> PendingWork -> IO ()
expectAdmitted label st pw = case admitPending st pw of
  Left deny -> assertFailure (label ++ " refused: " ++ show deny)
  Right () -> pure ()

loginSo :: Model -> IO Model
loginSo m =
  expectRight (publishDelta m (StateDelta [DeltaSetSessionLogin sid1 LoginSO]))

caseKeygenTrustedUserRefused :: IO ()
caseKeygenTrustedUserRefused = do
  m <- seedModel >>= loginUser
  st <- getSession m
  expectTrustedRefused "USER keygen" st (PwGenerateKey trustedObject)
  expectTrustedRefused "USER keygen+iv" st (PwGenerateKeyIv trustedObject 16)
  mPub <- seedModel
  stPub <- getSession mPub
  expectTrustedRefused "public keygen" stPub (PwGenerateKey trustedObject)

caseKeypairTrustedUserRefused :: IO ()
caseKeypairTrustedUserRefused = do
  m <- seedModel >>= loginUser
  st <- getSession m
  expectTrustedRefused "USER keypair trusted-priv" st
    (PwGeneratePair plainObject trustedObject)
  expectTrustedRefused "USER keypair trusted-pub" st
    (PwGeneratePair trustedObject plainObject)

caseDeriveUnwrapTrustedUserRefused :: IO ()
caseDeriveUnwrapTrustedUserRefused = do
  m <- seedModel >>= loginUser
  st <- getSession m
  expectTrustedRefused "USER derive" st (PwDerive [trustedObject] [32])
  expectTrustedRefused "USER unwrap" st (PwUnwrap trustedObject)
  expectTrustedRefused "USER encaps" st (PwEncaps trustedObject 32 32)

caseKeygenTrustedAllowedPaths :: IO ()
caseKeygenTrustedAllowedPaths = do
  m <- seedModel >>= loginSo
  stSo <- getSession m
  expectAdmitted "SO keygen" stSo (PwGenerateKey trustedObject)
  expectAdmitted "SO keypair" stSo (PwGeneratePair trustedObject trustedObject)
  expectAdmitted "SO derive" stSo (PwDerive [trustedObject] [32])
  mUser <- seedModel >>= loginUser
  stUser <- getSession mUser
  expectAdmitted "USER untrusted keygen" stUser (PwGenerateKey plainObject)
  expectAdmitted "USER trusted=false keygen" stUser
    (PwGenerateKey (trustedPending [(AttrTrusted, ValBool False)]))

-- ---------------------------------------------------------------------------
-- T-C03f round 2: the completion-time gate in 'finishWork' (async
-- completions and detached replays publish here, past the
-- submit-time 'admitPending' check). Replay-shaped inputs drive
-- 'finishWork' directly with canned driver answers.
-- ---------------------------------------------------------------------------

-- | A class-carrying pending secret object (publishable pre-fix,
-- so the refusal pin is a genuine failure without the gate).
trustedSecret :: PendingObject
trustedSecret = trustedPending
  [ (AttrClass, ValULong ckoSecretKey)
  , (AttrTrusted, ValBool True)
  ]

plainSecret :: PendingObject
plainSecret = trustedPending [(AttrClass, ValULong ckoSecretKey)]

expectFinishRefused
  :: String -> Model -> SessionState -> PendingWork -> CryptoResult -> IO ()
expectFinishRefused label m st pw res = case finishWork m st pw res of
  Reject r -> do
    assertEqual (label ++ " code") CKR_ATTRIBUTE_READ_ONLY (rejCode r)
    let StateDelta ops = rejDelta r
        created = length [() | DeltaCreateObjectFull {} <- ops]
    assertEqual (label ++ " publishes nothing") 0 created
    assertEqual (label ++ " empty delta") (StateDelta []) (rejDelta r)
  other ->
    assertFailure (label ++ " not refused: " ++ show other)

caseFinishTrustedUserRefused :: IO ()
caseFinishTrustedUserRefused = do
  m <- seedModel >>= loginUser
  st <- getSession m
  let mat = BS.replicate 16 0x5a
  expectFinishRefused "USER finish keygen" m st
    (PwGenerateKey trustedSecret) (GotBytes (encodeKeyPair mat Nothing))
  expectFinishRefused "USER finish keypair" m st
    (PwGeneratePair trustedSecret trustedSecret)
    (GotBytes (encodeKeyPair mat (Just mat)))
  expectFinishRefused "USER finish derive" m st
    (PwDerive [trustedSecret] [16]) (GotBytes mat)

caseFinishTrustedSoSucceeds :: IO ()
caseFinishTrustedSoSucceeds = do
  m <- seedModel >>= loginSo
  st <- getSession m
  let mat = BS.replicate 16 0x5a
  _ <- finishCommit m st (PwGenerateKey trustedSecret)
    (GotBytes (encodeKeyPair mat Nothing)) 1
  _ <- finishCommit m st (PwGeneratePair trustedSecret trustedSecret)
    (GotBytes (encodeKeyPair mat (Just mat))) 2
  _ <- finishCommit m st (PwDerive [trustedSecret] [16]) (GotBytes mat) 1
  pure ()

caseFinishUntrustedUserSucceeds :: IO ()
caseFinishUntrustedUserSucceeds = do
  m <- seedModel >>= loginUser
  st <- getSession m
  let mat = BS.replicate 16 0x5a
  _ <- finishCommit m st (PwGenerateKey plainSecret)
    (GotBytes (encodeKeyPair mat Nothing)) 1
  _ <- finishCommit m st (PwGeneratePair plainSecret plainSecret)
    (GotBytes (encodeKeyPair mat (Just mat))) 2
  _ <- finishCommit m st (PwDerive [plainSecret] [16]) (GotBytes mat) 1
  pure ()
