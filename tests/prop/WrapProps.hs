{- | Wrap-gate laws: the AES-CBC wrap/unwrap planners refuse any
wrapping key that is not an AES secret key — over the whole
key-type domain — and admit exactly AES. Keys are planted raw
(no keygen round-trip), so every 'Word64' exercises the planner;
a seed fault fails loudly rather than filtering inputs.
-}
{-# LANGUAGE OverloadedStrings #-}
module WrapProps (spec) where

import qualified Data.ByteString as BS
import qualified Data.Map.Strict as Map
import Data.Word (Word64)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.QuickCheck
  ( Gen
  , Property
  , arbitrary
  , counterexample
  , forAll
  , property
  , suchThat
  , (.&&.)
  , (===)
  )

import Gen (propWith)
import Haskoki.Attribute (AttributeType (..), AttributeValue (..))
import Haskoki.Model
  ( Model
  , SessionState
  , addToken
  , emptyModel
  , lookupSession
  )
import Haskoki.Operation.KeyManagement
  ( KeyDeny (..)
  , KeyPlan (..)
  , aesCbcMech
  , ckkAes
  , ckoSecretKey
  , planUnwrapKey
  , planWrapKey
  )
import Haskoki.Outcome (DeltaOp (..), StateDelta (..))
import Haskoki.Request (OutputIntent (..))
import Haskoki.Rules (defaultRules)
import Haskoki.Session (SessionLogin (..))
import Haskoki.Transition (publishDelta)
import Haskoki.Types
  ( ExternalHandle (..)
  , ObjectId (..)
  , ReturnCode (..)
  , SessionId (..)
  , SlotId (..)
  )

spec :: Maybe Int -> Int -> TestTree
spec seedOv count = testGroup "wrap key-type gate laws"
  [ propWith seedOv "wrap admits exactly AES" 701 count pWrapGate
  , propWith seedOv "unwrap admits exactly AES" 702 count pUnwrapGate
  ]

slot0 :: SlotId
slot0 = SlotId 0

sid1 :: SessionId
sid1 = SessionId 1

iv16 :: BS.ByteString
iv16 = "0123456789abcdef"

applyDelta :: Model -> StateDelta -> Model
applyDelta m d = case publishDelta m d of
  Left fault -> error ("gate seed fault: " ++ show fault)
  Right m' -> m'

-- | A model with one logged-in session, one wrap-candidate key of
-- the given type id (secret class, wrap/unwrap marks, material),
-- and one AES-128 extractable target.
plantForGate :: Word64 -> (Model, SessionState, ExternalHandle, ExternalHandle)
plantForGate kt =
  let m0 = addToken emptyModel slot0
      m1 = applyDelta m0 (StateDelta [DeltaOpenSession sid1 slot0 False])
      m2 = applyDelta m1 (StateDelta [DeltaSetSessionLogin sid1 LoginUser])
      wattrs = Map.fromList
        [ (AttrClass, ValULong ckoSecretKey)
        , (AttrKeyType, ValULong kt)
        , (AttrToken, ValBool False)
        , (AttrPrivate, ValBool False)
        , (AttrWrap, ValBool True)
        , (AttrUnwrap, ValBool True)
        , (AttrExtractable, ValBool True)
        , (AttrValue, ValBytes (BS.replicate 32 0x42))
        ]
      m3 = applyDelta m2 (StateDelta
        [ DeltaCreateObjectFull (ObjectId 1) wattrs (Just sid1) slot0
        , DeltaBindHandle (ExternalHandle 11) (ObjectId 1)
        ])
      tattrs = Map.fromList
        [ (AttrClass, ValULong ckoSecretKey)
        , (AttrKeyType, ValULong ckkAes)
        , (AttrToken, ValBool False)
        , (AttrPrivate, ValBool False)
        , (AttrExtractable, ValBool True)
        , (AttrValue, ValBytes (BS.replicate 16 0x74))
        ]
      m4 = applyDelta m3 (StateDelta
        [ DeltaCreateObjectFull (ObjectId 2) tattrs (Just sid1) slot0
        , DeltaBindHandle (ExternalHandle 12) (ObjectId 2)
        ])
  in case lookupSession m4 sid1 of
    Nothing -> error "gate seed fault: session missing"
    Just st -> (m4, st, ExternalHandle 11, ExternalHandle 12)

-- | Non-AES key-type ids: the generator never yields AES, so the
-- fuzzed branch cannot silently collapse onto the positive case
-- (a bare 'arbitrary' would hit AES with probability 2^-64 and
-- the admission branch would run zero times).
nonAesKeyType :: Gen Word64
nonAesKeyType = arbitrary `suchThat` (/= ckkAes)

pWrapGate :: Property
pWrapGate =
  let (mA, stA, wrapHA, targetHA) = plantForGate ckkAes
      positive = case planWrapKey mA stA aesCbcMech iv16 wrapHA targetHA (IntentBuffer 64) of
        KeyEffect _ _ -> property True
        other -> counterexample ("AES must plan, got: " ++ show other) False
      negative = forAll nonAesKeyType $ \kt ->
        let (m, st, wrapH, targetH) = plantForGate kt
        in case planWrapKey m st aesCbcMech iv16 wrapH targetH (IntentBuffer 64) of
          KeyDenied (KeyDeny code _) -> code === CKR_WRAPPING_KEY_TYPE_INCONSISTENT
          other -> counterexample ("must deny, got: " ++ show other) False
  in positive .&&. negative

pUnwrapGate :: Property
pUnwrapGate =
  let tmpl =
        [ (AttrClass, ValULong ckoSecretKey)
        , (AttrKeyType, ValULong ckkAes)
        , (AttrToken, ValBool False)
        ]
      (mA, stA, wrapHA, _targetHA) = plantForGate ckkAes
      positive = case planUnwrapKey defaultRules mA stA aesCbcMech iv16 wrapHA (BS.replicate 32 0) tmpl of
        KeyEffect _ _ -> property True
        other -> counterexample ("AES must plan, got: " ++ show other) False
      negative = forAll nonAesKeyType $ \kt ->
        let (m, st, wrapH, _targetH) = plantForGate kt
        in case planUnwrapKey defaultRules m st aesCbcMech iv16 wrapH (BS.replicate 32 0) tmpl of
          KeyDenied (KeyDeny code _) -> code === CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT
          other -> counterexample ("must deny, got: " ++ show other) False
  in positive .&&. negative
