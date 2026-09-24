{- | Validated slot insertion pins.

'SlotKind' derivation ('slotOfActive'), total kind-derived
insertion ('insertOp'), and validating insertion ('insertChecked'):
the raw 'insertSingle' that installed any operation under any
kind is gone, replaced by the validating API.

'caseNoRawInsertion' is the removal pin: it scans @core/@,
@src/@, @ffi/@, @tests/@ (and @app/@ when present) for any
remaining 'insertSingle' token and fails with file:line
evidence.
-}
module SlotInsertSpec (spec) where

import Control.Monad (forM)
import qualified Data.ByteString as BS
import Data.List (isInfixOf)
import System.Directory (doesDirectoryExist, listDirectory)
import System.FilePath ((</>), takeExtension)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertEqual, assertFailure, testCase)

import Haskoki.Operation
  ( ActiveOp
  , CipherDir (..)
  , CipherSpec (..)
  , MsgFamily (..)
  , MsgInner (..)
  , MsgState (..)
  , OpAuth (..)
  , RecoverRole (..)
  , RecoverSpec (..)
  , SessionOps
  , SlotCommon
  , SlotKind (..)
  , SlotMismatch (..)
  , emptySessionOps
  , insertChecked
  , insertOp
  , lookupSingle
  , mkActiveCipher
  , mkActiveDigest
  , mkActiveMessage
  , mkActiveRecover
  , mkActiveSign
  , mkActiveVerify
  , mkSlotCommon
  , slotOfActive
  )
import Haskoki.Registry (MechanismId (..), Operation (..))

spec :: TestTree
spec = testGroup "Validated slot insertion"
  [ testGroup "slotOfActive pins"
    [ testCase "digest" $
        assertEqual "digest kind" SlotDigest
          (slotOfActive (mkActiveDigest sampleCommon))
    , testCase "sign" $
        assertEqual "sign kind" SlotSign
          (slotOfActive (mkActiveSign sampleCommon))
    , testCase "verify" $
        assertEqual "verify kind" SlotVerify
          (slotOfActive (mkActiveVerify sampleCommon))
    , testCase "recover sign" $
        assertEqual "recover-sign kind" SlotSign
          (slotOfActive
            (mkActiveRecover RoleSignRecover sampleCommon sampleRecover))
    , testCase "recover verify" $
        assertEqual "recover-verify kind" SlotVerify
          (slotOfActive
            (mkActiveRecover RoleVerifyRecover sampleCommon sampleRecover))
    , testCase "cipher encrypt" $
        assertEqual "cipher-encrypt kind" SlotEncrypt
          (slotOfActive
            (mkActiveCipher DirEncrypt sampleCommon sampleCipher))
    , testCase "cipher decrypt" $
        assertEqual "cipher-decrypt kind" SlotDecrypt
          (slotOfActive
            (mkActiveCipher DirDecrypt sampleCommon sampleCipher))
    , testCase "message encrypt" $
        assertEqual "message-encrypt kind" SlotEncrypt
          (slotOfActive (mkActiveMessage (sampleMessage MsgEncrypt)))
    , testCase "message decrypt" $
        assertEqual "message-decrypt kind" SlotDecrypt
          (slotOfActive (mkActiveMessage (sampleMessage MsgDecrypt)))
    , testCase "message sign" $
        assertEqual "message-sign kind" SlotSign
          (slotOfActive (mkActiveMessage (sampleMessage MsgSign)))
    , testCase "message verify" $
        assertEqual "message-verify kind" SlotVerify
          (slotOfActive (mkActiveMessage (sampleMessage MsgVerify)))
    ]
  , testGroup "insertChecked accepts matching pairs"
    [ testCase "digest at digest" $
        checkAccept SlotDigest (mkActiveDigest sampleCommon)
    , testCase "cipher decrypt at decrypt" $
        checkAccept SlotDecrypt
          (mkActiveCipher DirDecrypt sampleCommon sampleCipher)
    , testCase "message sign at sign" $
        checkAccept SlotSign
          (mkActiveMessage (sampleMessage MsgSign))
    , testCase "recover verify at verify" $
        checkAccept SlotVerify
          (mkActiveRecover RoleVerifyRecover sampleCommon sampleRecover)
    ]
  , testGroup "insertChecked rejects mismatched pairs"
    [ testCase "digest at sign" $
        checkReject SlotSign (mkActiveDigest sampleCommon)
    , testCase "sign at digest" $
        checkReject SlotDigest (mkActiveSign sampleCommon)
    , testCase "cipher encrypt at decrypt" $
        checkReject SlotDecrypt
          (mkActiveCipher DirEncrypt sampleCommon sampleCipher)
    , testCase "recover sign at verify" $
        checkReject SlotVerify
          (mkActiveRecover RoleSignRecover sampleCommon sampleRecover)
    , testCase "message encrypt at sign" $
        checkReject SlotSign
          (mkActiveMessage (sampleMessage MsgEncrypt))
    , testCase "verify at encrypt" $
        checkReject SlotEncrypt (mkActiveVerify sampleCommon)
    ]
  , testGroup "insertOp derives the kind"
    [ testCase "digest lands in digest only" $
        checkDerived (mkActiveDigest sampleCommon) SlotDigest
    , testCase "cipher decrypt lands in decrypt only" $
        checkDerived
          (mkActiveCipher DirDecrypt sampleCommon sampleCipher) SlotDecrypt
    , testCase "message verify lands in verify only" $
        checkDerived
          (mkActiveMessage (sampleMessage MsgVerify)) SlotVerify
    ]
  , testCase "raw insertSingle is gone" caseNoRawInsertion
  ]

-- | A matching kind/operation pair inserts and reads back.
checkAccept :: SlotKind -> ActiveOp -> IO ()
checkAccept kind active = case insertChecked kind active emptySessionOps of
  Left mm -> assertFailure ("matching pair rejected: " ++ show mm)
  Right ops -> assertEqual "reads back" (Just active) (lookupSingle ops kind)

-- | A mismatched kind/operation pair is rejected at construction,
-- naming the claimed slot and the operation's true slot.
checkReject :: SlotKind -> ActiveOp -> IO ()
checkReject kind active =
  assertEqual "mismatch rejected"
    (Left (SlotMismatch kind (slotOfActive active)) :: Either SlotMismatch SessionOps)
    (insertChecked kind active emptySessionOps)

-- | 'insertOp' installs the operation under its derived kind and
-- nowhere else.
checkDerived :: ActiveOp -> SlotKind -> IO ()
checkDerived active kind = do
  let ops = insertOp active emptySessionOps
  assertEqual "derived slot holds it" (Just active) (lookupSingle ops kind)
  mapM_ (checkEmpty ops)
    (filter (/= kind) [minBound .. maxBound])
  where
    checkEmpty :: SessionOps -> SlotKind -> IO ()
    checkEmpty ops other =
      assertEqual ("slot empty: " ++ show other) Nothing (lookupSingle ops other)

-- | A sample shared slot state (streamless, unstaged, unbuffered).
sampleCommon :: SlotCommon
sampleCommon = mkSlotCommon (MechanismId 0x250) OpDigest Nothing BS.empty AuthNone

-- | A sample cipher shape.
sampleCipher :: CipherSpec
sampleCipher = CipherSpec 16 False

-- | A sample recovery shape.
sampleRecover :: RecoverSpec
sampleRecover = RecoverSpec 128 16

-- | A sample outer message context over the sample common state.
sampleMessage :: MsgFamily -> MsgState
sampleMessage fam = MsgState fam sampleCommon MsgIdle Nothing 0

-- | The raw forging operation must be gone from every Haskell
-- source file (this probe exempts its own file, auditable here).
caseNoRawInsertion :: IO ()
caseNoRawInsertion = do
  files <- filter (/= "tests/model/SlotInsertSpec.hs")
    . concat <$> mapM walkHs ["core", "src", "ffi", "tests", "app"]
  hits <- fmap concat $ forM files $ \fp -> do
    body <- readFile fp
    pure
      [ (fp, n)
      | (n, ln) <- zip [1 :: Int ..] (lines body)
      , "insertSingle" `isInfixOf` ln
      ]
  case hits of
    [] -> pure ()
    _ -> assertFailure ("raw insertSingle uses: " ++ show hits)

-- | All @.hs@ files under a root (@[]@ when the root is absent).
walkHs :: FilePath -> IO [FilePath]
walkHs root = do
  ok <- doesDirectoryExist root
  if not ok then pure [] else go root
  where
    go dir = do
      ents <- listDirectory dir
      fmap concat $ forM ents $ \e -> do
        let p = dir </> e
        isDir <- doesDirectoryExist p
        if isDir then go p else pure [p | takeExtension p == ".hs"]
