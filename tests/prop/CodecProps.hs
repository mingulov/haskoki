{- | Codec laws: every Codec.hs pair roundtrips over generated
payloads, reserved bits and truncated frames reject, and the
message family gates accept exactly their own tags.
-}
{-# LANGUAGE OverloadedStrings #-}
module CodecProps (spec) where

import Data.Bits (bit, testBit, (.|.))
import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import Data.List (nub, sort)
import Data.Maybe (isJust, isNothing)
import Data.Word (Word16, Word64)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertBool, assertEqual, testCase)
import Test.Tasty.QuickCheck
  ( Gen
  , Property
  , arbitrary
  , forAll
  , sublistOf
  , (.&&.)
  )

import Gen (lcgBytes, lcgNext, permitOps, propWith, qcBytes)
import Haskoki.FFI.Decode (maxInputBytes)
import Haskoki.Operation.Codec
  ( decodeInitInput
  , decodeMsgBegin
  , decodeMsgNext
  , decodeMsgOneShot
  , decodeVerifyInput
  , encodeInitInput
  , encodeMsgBegin
  , encodeMsgNext
  , encodeMsgOneShot
  , encodeVerifyInput
  )
import Haskoki.Operation.Message (MsgBegin (..), MsgNext (..), MsgOneShot (..))
import Haskoki.Operation.State (MsgFamily (..))
import Haskoki.Registry (MechanismId (..), Operation (..))

spec :: Maybe Int -> Int -> TestTree
spec seedOv count =
  testGroup
    "codec laws"
    [ propWith seedOv "init roundtrip" 101 count pInitRoundtrip
    , propWith seedOv "verify roundtrip" 102 count pVerifyRoundtrip
    , propWith seedOv "begin roundtrip" 103 count pBeginRoundtrip
    , propWith seedOv "next roundtrip cipher" 104 count pNextCipher
    , propWith seedOv "next roundtrip sign" 105 count pNextSign
    , propWith seedOv "next roundtrip verify" 106 count pNextVerify
    , propWith seedOv "oneshot roundtrip cipher" 107 count pOneCipher
    , propWith seedOv "oneshot roundtrip sign" 108 count pOneSign
    , propWith seedOv "oneshot roundtrip verify" 109 count pOneVerify
    , testCase "init reserved bits reject" (caseInitReserved count)
    , testCase "verify truncation law" (caseVerifyTrunc count)
    , testCase "next family gate table" caseNextGate
    , testCase "oneshot family gate table" caseOneGate
    , testCase "edge roundtrips incl max" caseEdges
    ]

-- | Canonical init arguments: sorted unique permits (valid by
-- construction, matching decode's canonical order).
genInitArgs :: Gen (MechanismId, [Operation], Bool, ByteString)
genInitArgs = do
  w <- arbitrary
  permits <- sort . nub <$> sublistOf permitOps
  auth <- arbitrary
  params <- qcBytes 256
  pure (MechanismId w, permits, auth, params)

pInitRoundtrip :: Property
pInitRoundtrip = forAll genInitArgs $ \(mech, permits, auth, params) ->
  decodeInitInput (encodeInitInput mech permits auth params)
    == Just (mech, permits, auth, params)

pVerifyRoundtrip :: Property
pVerifyRoundtrip = forAll (qcBytes 128) $ \dat ->
  forAll (qcBytes 128) $ \sig ->
    decodeVerifyInput (encodeVerifyInput dat sig) == Just (dat, sig)

pBeginRoundtrip :: Property
pBeginRoundtrip = forAll (qcBytes 64) $ \params ->
  forAll (qcBytes 128) $ \aad ->
    let begin = MsgBegin params aad
    in decodeMsgBegin (encodeMsgBegin begin) == Just begin

pNextCipher :: Property
pNextCipher = forAll genNextCipher $ \next ->
  let blob = encodeMsgNext next
  in decodeMsgNext MsgEncrypt blob == Just next
       .&&. decodeMsgNext MsgDecrypt blob == Just next
  where
    genNextCipher :: Gen MsgNext
    genNextCipher =
      MsgNextCipher <$> qcBytes 64 <*> qcBytes 128 <*> arbitrary

pNextSign :: Property
pNextSign = forAll genNextSign $ \next ->
  decodeMsgNext MsgSign (encodeMsgNext next) == Just next
  where
    genNextSign :: Gen MsgNext
    genNextSign =
      MsgNextSign <$> qcBytes 64 <*> qcBytes 128 <*> arbitrary

pNextVerify :: Property
pNextVerify = forAll genNextVerify $ \next ->
  decodeMsgNext MsgVerify (encodeMsgNext next) == Just next
  where
    genNextVerify :: Gen MsgNext
    genNextVerify = do
      params <- qcBytes 64
      part <- qcBytes 128
      useWitness <- arbitrary
      witness <-
        if useWitness
          then Just <$> qcBytes 64
          else pure Nothing
      pure (MsgNextVerify params part witness)

pOneCipher :: Property
pOneCipher = forAll genOneCipher $ \one ->
  let blob = encodeMsgOneShot one
  in decodeMsgOneShot MsgEncrypt blob == Just one
       .&&. decodeMsgOneShot MsgDecrypt blob == Just one
  where
    genOneCipher :: Gen MsgOneShot
    genOneCipher =
      MsgOneShotCipher <$> qcBytes 64 <*> qcBytes 64 <*> qcBytes 128

pOneSign :: Property
pOneSign = forAll genOneSign $ \one ->
  decodeMsgOneShot MsgSign (encodeMsgOneShot one) == Just one
  where
    genOneSign :: Gen MsgOneShot
    genOneSign = MsgOneShotSign <$> qcBytes 64 <*> qcBytes 128

pOneVerify :: Property
pOneVerify = forAll genOneVerify $ \one ->
  decodeMsgOneShot MsgVerify (encodeMsgOneShot one) == Just one
  where
    genOneVerify :: Gen MsgOneShot
    genOneVerify =
      MsgOneShotVerify <$> qcBytes 64 <*> qcBytes 128 <*> qcBytes 64

-- ---------------------------------------------------------------------------
-- Reserved bits: every reserved permit bit (6-15) and flag bit (1-7)
-- rejects on every generated blob; the unmodified blob decodes.
-- ---------------------------------------------------------------------------

-- | (byte index, bit index) of the 17 reserved bits: permits u16
-- big-endian at bytes 8-9, flags at byte 10.
reservedBits :: [(Int, Int)]
reservedBits =
  [(9, 6), (9, 7)]
    ++ [(8, b) | b <- [0 .. 7]]
    ++ [(10, b) | b <- [1 .. 7]]

-- | Total bit setter (valid blobs always carry the 11-byte header).
setBitAt :: Int -> Int -> ByteString -> ByteString
setBitAt byteIx bitIx bs =
  let (pre, rest) = BS.splitAt byteIx bs
  in case BS.uncons rest of
    Nothing -> bs
    Just (b, post) -> pre <> BS.singleton (b .|. bit bitIx) <> post

validParts :: Word64 -> (MechanismId, [Operation], Bool, ByteString)
validParts seed =
  ( MechanismId seed
  , sort [op | (op, n) <- zip permitOps [0 ..], testBit w16 n]
  , seed `mod` 2 == 1
  , lcgBytes (lcgNext seed) (fromIntegral (seed `mod` 65))
  )
  where
    w16 :: Word16
    w16 = fromIntegral seed

caseInitReserved :: Int -> IO ()
caseInitReserved count = mapM_ checkSeed [1 .. fromIntegral count]
  where
    checkSeed :: Word64 -> IO ()
    checkSeed seed = do
      let (mech, permits, auth, params) = validParts seed
          blob = encodeInitInput mech permits auth params
      assertEqual ("valid blob seed=" ++ show seed)
        (Just (mech, permits, auth, params))
        (decodeInitInput blob)
      mapM_ (checkBit blob seed) reservedBits
    checkBit :: ByteString -> Word64 -> (Int, Int) -> IO ()
    checkBit blob seed (byteIx, bitIx) =
      assertEqual
        ("reserved bit seed=" ++ show seed ++ " byte=" ++ show byteIx
          ++ " bit=" ++ show bitIx)
        Nothing
        (decodeInitInput (setBitAt byteIx bitIx blob))

-- ---------------------------------------------------------------------------
-- Verify truncation: cuts inside the header/data region reject; cuts
-- inside the trailing witness decode to the shortened witness.
-- ---------------------------------------------------------------------------

caseVerifyTrunc :: Int -> IO ()
caseVerifyTrunc count = mapM_ checkPair (edgePairs ++ genPairs)
  where
    genPairs :: [(ByteString, ByteString)]
    genPairs =
      [ ( lcgBytes s (fromIntegral (s `mod` 41))
        , lcgBytes (lcgNext s) (fromIntegral ((s `div` 41) `mod` 41))
        )
      | s <- [1 .. fromIntegral count]
      ]
    edgePairs :: [(ByteString, ByteString)]
    edgePairs =
      [(BS.empty, BS.empty), (BS.empty, "s"), ("d", BS.empty), ("d", "s")]
    checkPair :: (ByteString, ByteString) -> IO ()
    checkPair (dat, sig) = do
      let blob = encodeVerifyInput dat sig
          hlen = 4 + BS.length dat
          total = BS.length blob
      mapM_ (checkCut dat sig blob hlen) [0 .. total]
    checkCut :: ByteString -> ByteString -> ByteString -> Int -> Int -> IO ()
    checkCut dat sig blob hlen k =
      let want =
            if k < hlen
              then Nothing
              else Just (dat, BS.take (k - hlen) sig)
      in assertEqual ("trunc k=" ++ show k) want
            (decodeVerifyInput (BS.take k blob))

-- ---------------------------------------------------------------------------
-- Family gates: each tag decodes under exactly its own families.
-- ---------------------------------------------------------------------------

allFams :: [MsgFamily]
allFams = [MsgEncrypt, MsgDecrypt, MsgSign, MsgVerify]

checkGate
  :: (MsgFamily -> ByteString -> Maybe a)
  -> ByteString
  -> [MsgFamily]
  -> MsgFamily
  -> IO ()
checkGate decode blob wantFams fam =
  if fam `elem` wantFams
    then assertBool ("accept " ++ show fam) (isJust (decode fam blob))
    else assertBool ("reject " ++ show fam) (isNothing (decode fam blob))

caseNextGate :: IO ()
caseNextGate = do
  let cipherBlob = encodeMsgNext (MsgNextCipher "p" "x" True)
      signBlob = encodeMsgNext (MsgNextSign "p" "x" False)
      verifyBlob0 = encodeMsgNext (MsgNextVerify "p" "x" Nothing)
      verifyBlob1 = encodeMsgNext (MsgNextVerify "p" "x" (Just "w"))
  mapM_ (checkGate decodeMsgNext cipherBlob [MsgEncrypt, MsgDecrypt]) allFams
  mapM_ (checkGate decodeMsgNext signBlob [MsgSign]) allFams
  mapM_ (checkGate decodeMsgNext verifyBlob0 [MsgVerify]) allFams
  mapM_ (checkGate decodeMsgNext verifyBlob1 [MsgVerify]) allFams

caseOneGate :: IO ()
caseOneGate = do
  let cipherBlob = encodeMsgOneShot (MsgOneShotCipher "p" "a" "x")
      signBlob = encodeMsgOneShot (MsgOneShotSign "p" "x")
      verifyBlob = encodeMsgOneShot (MsgOneShotVerify "p" "x" "w")
  mapM_ (checkGate decodeMsgOneShot cipherBlob [MsgEncrypt, MsgDecrypt]) allFams
  mapM_ (checkGate decodeMsgOneShot signBlob [MsgSign]) allFams
  mapM_ (checkGate decodeMsgOneShot verifyBlob [MsgVerify]) allFams

-- ---------------------------------------------------------------------------
-- Edges: empty/single/max payloads; non-canonical permits canonicalize.
-- ---------------------------------------------------------------------------

maxParams :: ByteString
maxParams = BS.replicate (fromIntegral maxInputBytes) 0xAB

checkInit
  :: MechanismId -> [Operation] -> Bool -> ByteString -> IO ()
checkInit mech permits auth params =
  assertEqual "init edge"
    (Just (mech, sort (nub permits), auth, params))
    (decodeInitInput (encodeInitInput mech permits auth params))

caseEdges :: IO ()
caseEdges = do
  checkInit (MechanismId 0) [] False BS.empty
  checkInit (MechanismId maxBound) permitOps True BS.empty
  checkInit (MechanismId 7) [OpSign, OpSign] False (BS.singleton 0)
  checkInit (MechanismId 9) permitOps True maxParams
  assertEqual "begin empty"
    (Just (MsgBegin BS.empty BS.empty))
    (decodeMsgBegin (encodeMsgBegin (MsgBegin BS.empty BS.empty)))
  assertEqual "begin max params"
    (Just (MsgBegin maxParams BS.empty))
    (decodeMsgBegin (encodeMsgBegin (MsgBegin maxParams BS.empty)))
  assertEqual "begin max aad"
    (Just (MsgBegin BS.empty maxParams))
    (decodeMsgBegin (encodeMsgBegin (MsgBegin BS.empty maxParams)))
  let nextEmpty = MsgNextCipher BS.empty BS.empty True
  assertEqual "next empty" (Just nextEmpty)
    (decodeMsgNext MsgEncrypt (encodeMsgNext nextEmpty))
  let nextNoWit = MsgNextVerify BS.empty BS.empty Nothing
  assertEqual "next no witness" (Just nextNoWit)
    (decodeMsgNext MsgVerify (encodeMsgNext nextNoWit))
  let nextEmptyWit = MsgNextVerify BS.empty BS.empty (Just BS.empty)
  assertEqual "next empty witness" (Just nextEmptyWit)
    (decodeMsgNext MsgVerify (encodeMsgNext nextEmptyWit))
  let oneEmpty = MsgOneShotCipher BS.empty BS.empty BS.empty
  assertEqual "oneshot empty" (Just oneEmpty)
    (decodeMsgOneShot MsgDecrypt (encodeMsgOneShot oneEmpty))
  let oneEmptyWit = MsgOneShotVerify BS.empty BS.empty BS.empty
  assertEqual "oneshot empty witness" (Just oneEmptyWit)
    (decodeMsgOneShot MsgVerify (encodeMsgOneShot oneEmptyWit))
