{- | Multi-session store proofs.

Two sessions share one store handle with interleaved commits (no lost
updates); revision conflicts surface as the typed
'StoreRevisionConflict' error, never silent overwrites. Both backends
run the same cases.
-}
{-# LANGUAGE OverloadedStrings #-}
module MultiSessionSpec (spec) where

import qualified Data.Map.Strict as Map
import Data.ByteString (ByteString)
import Data.List (isInfixOf)
import System.Directory (removeDirectoryRecursive)
import System.FilePath ((</>))
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertBool, assertEqual, assertFailure, testCase)

import Control.Exception (bracket)

import Haskoki.Attribute (AttributeType (..), AttributeValue (..))
import Haskoki.Model
  ( addToken
  , emptyModel
  , lookupObject
  , lookupSession
  )
import Haskoki.Outcome (DeltaOp (..), StateDelta (..))
import Haskoki.Runtime.Storage
  ( CommitResult (..)
  , FaultInjector
  , ObjectPut (..)
  , ObjectRecord (..)
  , Store (..)
  , StoreDelta (..)
  , StoreError (..)
  , StoreLimits
  , TokenRecord (..)
  , defaultLimits
  , emptyDelta
  , noFaults
  , objectToRecord
  , reserveRestoredIds
  )
import Haskoki.Runtime.Storage.Memory (newMemoryWorld, openMemoryStoreWith)
import Haskoki.Runtime.Storage.SQLite (openSQLiteStoreWith)
import Haskoki.Transition (publishDelta)
import Haskoki.Types
  ( ObjectId (..)
  , Revision (..)
  , SessionId (..)
  , SlotId (..)
  )
import StoreSpec (expectCreated, expectJust, expectRight, makeTempDir, seedStore)

-- | Open a store on the case identity with the given limits and faults.
type OpenWith = StoreLimits -> FaultInjector -> IO (Either StoreError Store)

spec :: TestTree
spec = testGroup "Multi-session store"
  [ testGroup "memory"
      [ testCase "interleaved commits lose no updates" $
          withMemoryIdentity testInterleaved
      , testCase "revision conflict is typed, never a silent overwrite" $
          withMemoryIdentity testConflict
      ]
  , testGroup "sqlite"
      [ testCase "interleaved commits lose no updates" $
          withSQLiteIdentity testInterleaved
      , testCase "revision conflict is typed, never a silent overwrite" $
          withSQLiteIdentity testConflict
      ]
  , testCase "commit tests observe death deterministically (no busy-spin)" caseNoBusySpin
  ]

-- | Fresh memory identity per case.
withMemoryIdentity :: (OpenWith -> IO ()) -> IO ()
withMemoryIdentity use = do
  world <- newMemoryWorld
  use (\lim inj -> openMemoryStoreWith world lim inj)

-- | Fresh SQLite file identity per case, cleaned up afterwards.
withSQLiteIdentity :: (OpenWith -> IO ()) -> IO ()
withSQLiteIdentity use =
  bracket (makeTempDir "haskoki-multisession-test") removeDirectoryRecursive $ \dir ->
    use (\lim inj -> openSQLiteStoreWith (dir </> "store.db") lim inj)

-- | Two sessions plan through one store handle with interleaved
-- commits: plan A via session 1, plan B via session 2, commit A,
-- commit B. Both land; nothing is lost.
testInterleaved :: OpenWith -> IO ()
testInterleaved openWith = do
  eStore <- openWith defaultLimits noFaults
  store <- either (assertFailure . show) pure eStore
  (tok, recs) <- seedStore store
  let slot = SlotId 0
      tid = trId tok
  mSeated <- expectRight "seat+open-two" (publishDelta (addToken emptyModel slot)
    (StateDelta [ DeltaOpenSession (SessionId 1) slot False
                , DeltaOpenSession (SessionId 2) slot False
                ]))
  let mReserved = reserveRestoredIds (map orId recs) mSeated
  st1 <- expectJust "session 1" (lookupSession mReserved (SessionId 1))
  _st2 <- expectJust "session 2" (lookupSession mReserved (SessionId 2))
  (mA, _, oidA) <- expectCreated mReserved st1 (tmplFor "interleave-a")
  st2AfterA <- expectJust "session 2 survives A" (lookupSession mA (SessionId 2))
  (mB, _, oidB) <- expectCreated mA st2AfterA (tmplFor "interleave-b")
  assertBool "distinct objects" (oidA /= oidB)
  ostA <- expectJust "object A" (lookupObject mB oidA)
  ostB <- expectJust "object B" (lookupObject mB oidB)
  rA <- storeCommit store emptyDelta
    { sdPutObjects = [ObjectPut Nothing (objectToRecord tid ostA)] }
  assertEqual "commit A" Committed rA
  rB <- storeCommit store emptyDelta
    { sdPutObjects = [ObjectPut Nothing (objectToRecord tid ostB)] }
  assertEqual "commit B" Committed rB
  eLoaded <- storeLoadTokens store
  loaded <- either (assertFailure . show) pure eLoaded
  assertEqual "no lost updates" 4 (countObjects loaded)
  assertBool "A durable" (objectPresent oidA loaded)
  assertBool "B durable" (objectPresent oidB loaded)
  storeClose store

-- | Guarded writes against stale or missing revisions refuse with the
-- typed 'StoreRevisionConflict' error and land nothing; the
-- correctly-guarded write commits.
testConflict :: OpenWith -> IO ()
testConflict openWith = do
  eStore <- openWith defaultLimits noFaults
  store <- either (assertFailure . show) pure eStore
  (_, recs) <- seedStore store
  victim <- case recs of
    (r : _) -> pure r
    [] -> assertFailure "seed produced no objects"
  let badRev = Revision (unRevision (orRevision victim) + 1000)
      overwrite = victim
        { orAttrs = Map.insert AttrLabel (ValBytes "sneaky") (orAttrs victim) }
  refused <- storeCommit store emptyDelta
    { sdPutObjects = [ObjectPut (Just badRev) overwrite] }
  case refused of
    NotCommitted (StoreRevisionConflict _) -> pure ()
    other -> assertFailure ("expected StoreRevisionConflict, got: " ++ show other)
  -- A guarded write to a missing object conflicts too (never an
  -- upsert through the guard).
  ghost <- storeCommit store emptyDelta
    { sdPutObjects =
        [ObjectPut (Just (Revision 1)) (victim { orId = ObjectId 9999 })] }
  case ghost of
    NotCommitted (StoreRevisionConflict _) -> pure ()
    other -> assertFailure ("expected missing-object conflict, got: " ++ show other)
  -- No silent overwrite: the durable record is still the original.
  eLoaded <- storeLoadTokens store
  loaded <- either (assertFailure . show) pure eLoaded
  case [o | (_, os) <- loaded, o <- os, orId o == orId victim] of
    [o] -> assertEqual "original content intact" (orAttrs victim) (orAttrs o)
    _ -> assertFailure "victim missing or duplicated after refused commits"
  -- The correctly-guarded write commits.
  ok <- storeCommit store emptyDelta
    { sdPutObjects = [ObjectPut (Just (orRevision victim)) overwrite] }
  assertEqual "guarded write commits" Committed ok
  storeClose store

-- | The async-mask commit case must observe thread death through a
-- deterministic death signal, never the old 'waitDeath' busy-spin
-- (whose @timeout 10000 (pure ())@ waits nothing: @pure ()@
-- resolves instantly, so the spin can miss under load).
caseNoBusySpin :: IO ()
caseNoBusySpin = do
  body <- readFile "tests/storage/CommitSpec.hs"
  let hits =
        [n | (n, ln) <- zip [1 :: Int ..] (lines body), "timeout 10000" `isInfixOf` ln]
  case hits of
    [] -> pure ()
    _ -> assertFailure ("CommitSpec still busy-spins on lines: " ++ show hits)

-- | Token-object template with a distinct label.
tmplFor :: ByteString -> [(AttributeType, AttributeValue)]
tmplFor label =
  [ (AttrClass, ValULong 3)
  , (AttrToken, ValBool True)
  , (AttrLabel, ValBytes label)
  , (AttrValue, ValBytes "interleave-bytes")
  ]

-- | Count stored objects across tokens.
countObjects :: [(TokenRecord, [ObjectRecord])] -> Int
countObjects = sum . map (length . snd)

-- | Whether an object id is present in loaded state.
objectPresent :: ObjectId -> [(TokenRecord, [ObjectRecord])] -> Bool
objectPresent oid = any (any ((== oid) . orId) . snd)
