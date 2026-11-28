{- | KeyManagement Part 1: KEM keygen, encaps and generated reads.
-}
{-# LANGUAGE OverloadedStrings #-}
module KeyManagement.Part1
  ( caseKemKeygen
  , caseGeneratedPublicReads
  , caseKemLengthQuery
  , caseKemEncaps
  , caseKemEncapsShort
  ) where

import qualified Data.ByteString as BS
import qualified Data.Map.Strict as Map
import Test.Tasty.HUnit (assertBool, assertEqual, assertFailure)
import Haskoki.Attribute
  ( AttributeType (..)
  , AttributeValue (..)
  , decodeValue
  , encodeValue
  )
import Haskoki.Model
  ( Model (..)
  , ObjectState (..)
  )
import Haskoki.Object (planGetAttributes, resolveHandle)
import Haskoki.Operation.Kem
  ( KemAlg (..)
  , kemCtLen
  , mlKemKeyPairGenMech
  , mlKemMech
  , planKemEncaps
  )
import Haskoki.Operation.KeyManagement
  ( KeyPlan (..)
  , ckkGenericSecret
  , ckkMlKem
  , ckoPrivateKey
  , ckoPublicKey
  , ckoSecretKey
  , dhKeyPairGenMech
  , dsaKeyPairGenMech
  , ecKeyPairGenMech
  , mldsaKeyPairGenMech
  , keyBytesOf
  , planGenerateKeyPair
  , rsaKeyPairGenMech
  )
import Haskoki.Outcome
  ( NativeOutput (..)
  , PlanResult (..)
  , PreparedCommit (..)
  , Rejection (..)
  , StateDelta (..)
  )
import Haskoki.Request (OutputIntent (..), OutputRegion (..))
import Haskoki.Rules (defaultRules)
import Haskoki.Transition (publishDelta)
import Haskoki.Types
  ( ReturnCode (..)
  )
import KeyManagement.Fixtures
import KeyManagement.Part2Fixtures
import KeyManagement.Premaster

-- ---------------------------------------------------------------------------
-- Part 1
-- ---------------------------------------------------------------------------

caseKemKeygen :: IO ()
caseKemKeygen = withSynth $ \answer -> do
  m0 <- seedModel
  st <- getSession m0
  (m1, pubH, privH) <- genKemPair answer m0 st
  assertBool "handles differ" (pubH /= privH)
  Just pub <- pure (resolveHandle m1 pubH)
  Just priv <- pure (resolveHandle m1 privH)
  assertEqual "pub class" (Just (ValULong ckoPublicKey)) (Map.lookup AttrClass (osAttrs pub))
  assertEqual "priv class" (Just (ValULong ckoPrivateKey)) (Map.lookup AttrClass (osAttrs priv))
  assertEqual "pub keytype" (Just (ValULong ckkMlKem)) (Map.lookup AttrKeyType (osAttrs pub))
  assertEqual "priv kem alg" (Just (ValULong 768)) (Map.lookup AttrKemAlg (osAttrs priv))
  assertEqual "pub usage" (Just (ValBool True)) (Map.lookup AttrEncapsulate (osAttrs pub))
  assertEqual "priv usage" (Just (ValBool True)) (Map.lookup AttrDecapsulate (osAttrs priv))
  case (keyBytesOf pub, keyBytesOf priv) of
    (Just p, Just q) -> do
      assertBool "pub material nonempty" (not (BS.null p))
      assertBool "priv material nonempty" (not (BS.null q))
      assertBool "halves differ" (p /= q)
    _ -> assertFailure "keypair halves lack stored material"

-- | Generated public halves read back under minimal templates: no
-- protection flags are minted or needed. Each leg pins its public
-- template carries none, then reads the public value straight off
-- the finished pair. The RSA leg also reads the stamped modulus
-- (the synthetic EC halves are opaque, so no point is stamped
-- there).
caseGeneratedPublicReads :: IO ()
caseGeneratedPublicReads = withSynth $ \answer -> do
  m0 <- seedModel
  st <- getSession m0
  (m1, kemH) <- mint answer m0 st "ML-KEM" mlKemKeyPairGenMech kemPubTmpl kemPrivTmpl
  (m2, mldsaH) <- mint answer m1 st "ML-DSA" mldsaKeyPairGenMech mldsaPubTmpl mldsaPrivTmpl
  (m3, dhH) <- mint answer m2 st "DH" dhKeyPairGenMech dhPubTmpl dhPrivTmpl
  (m4, dsaH) <- mint answer m3 st "DSA" dsaKeyPairGenMech dsaPubTmpl dsaPrivTmpl
  (m5, ecH) <- mint answer m4 st "EC" ecKeyPairGenMech ecPubTmpl ecPrivTmpl
  (m6, rsaH) <- mint answer m5 st "RSA" rsaKeyPairGenMech rsaPubTmpl rsaPrivTmpl
  mapM_ (readValue m6 st)
    [ ("ML-KEM", kemH), ("ML-DSA", mldsaH), ("DH", dhH)
    , ("DSA", dsaH), ("EC", ecH), ("RSA", rsaH)
    ]
  Just rsaPub <- pure (resolveHandle m6 rsaH)
  case Map.lookup AttrModulus (osAttrs rsaPub) of
    Just (ValBytes n) -> do
      got <- readAttr m6 st "RSA modulus" rsaH AttrModulus
      assertEqual "RSA modulus" (Just (ValBytes n)) got
    other -> assertFailure ("RSA public lacks modulus: " ++ show other)
  where
    mint answer m st tag mech pubT privT = do
      assertBool (tag ++ ": public template carries no protection flags")
        (all (\(t, _) -> t /= AttrSensitive && t /= AttrExtractable) pubT)
      case planGenerateKeyPair defaultRules m st mech pubT privT of
        KeyEffect pw fx -> do
          res <- answer m fx
          c <- finishCommit m st pw res 2
          pubH <- handleOf (pcOutputs c !! 0)
          m' <- expectRight (publishDelta m (pcDelta c))
          pure (m', pubH)
        other -> assertFailure (tag ++ ": pair plan is not an effect: " ++ show other)
          >> undefined
    readValue m st (tag, h) = do
      Just ost <- pure (resolveHandle m h)
      Just mat <- pure (keyBytesOf ost)
      got <- readAttr m st (tag ++ " public value") h AttrValue
      assertEqual (tag ++ " public value") (Just (ValBytes mat)) got
    readAttr m st tag h t = case planGetAttributes m st h [t] of
      Immediate c -> case pcOutputs c of
        [o] -> pure (decodeValue t (outBytes o))
        _ -> assertFailure (tag ++ ": read outputs arity") >> undefined
      Reject rej -> assertFailure (tag ++ ": read rejected: " ++ show (rejCode rej))
        >> undefined
      Execute _ _ -> assertFailure (tag ++ ": read must not execute") >> undefined

caseKemLengthQuery :: IO ()
caseKemLengthQuery = withSynth $ \answer -> do
  m0 <- seedModel
  st <- getSession m0
  (m1, pubH, _) <- genKemPair answer m0 st
  let before = Map.size (mObjects m1)
  case planKemEncaps m1 st mlKemMech pubH KemMl768 secretTmpl IntentNull of
    KeyImmediate (Immediate c) -> do
      assertEqual "query code" CKR_OK (pcCode c)
      assertEqual "query publishes nothing" (StateDelta []) (pcDelta c)
      assertEqual "query answers the ct length"
        [NativeOutput (RegionBytes "ciphertext" IntentNull)
          (encodeValue (ValULong (fromIntegral (kemCtLen KemMl768))))]
        (pcOutputs c)
      m2 <- expectRight (publishDelta m1 (pcDelta c))
      assertEqual "no key created" before (Map.size (mObjects m2))
    other -> assertFailure ("length query is not an Immediate commit: " ++ show other)

caseKemEncaps :: IO ()
caseKemEncaps = withSynth $ \answer -> do
  m0 <- seedModel
  st <- getSession m0
  (m1, pubH, _) <- genKemPair answer m0 st
  let before = Map.size (mObjects m1)
      ctLen = kemCtLen KemMl768
      intent = IntentBuffer (fromIntegral ctLen)
  (ct1, h) <- case planKemEncaps m1 st mlKemMech pubH KemMl768 secretTmpl intent of
    KeyEffect pw fx -> do
      res <- answer m1 fx
      c <- finishCommit m1 st pw res 1
      let outs = pcOutputs c
      assertEqual "ciphertext plus exactly one handle" 2 (length outs)
      ct <- case outs !! 0 of
        NativeOutput (RegionBytes "ciphertext" _) bs -> pure bs
        o -> assertFailure ("first output is not the ciphertext: " ++ show o) >> undefined
      assertEqual "ciphertext length" ctLen (BS.length ct)
      hh <- handleOf (outs !! 1)
      m2 <- expectRight (publishDelta m1 (pcDelta c))
      assertEqual "exactly one object published" (before + 1) (Map.size (mObjects m2))
      Just ost <- pure (resolveHandle m2 hh)
      assertEqual "secret class" (Just (ValULong ckoSecretKey)) (Map.lookup AttrClass (osAttrs ost))
      assertEqual "secret keytype" (Just (ValULong ckkGenericSecret)) (Map.lookup AttrKeyType (osAttrs ost))
      assertEqual "secret usage" (Just (ValBool True)) (Map.lookup AttrEncrypt (osAttrs ost))
      case keyBytesOf ost of
        Just ss -> assertEqual "shared secret length" 32 (BS.length ss)
        Nothing -> assertFailure "secret object lacks stored material"
      pure (ct, hh)
    other -> assertFailure ("encaps plan is not an effect: " ++ show other) >> undefined
  -- Deterministic test engine: the same key encapsulates the same bytes.
  case planKemEncaps m1 st mlKemMech pubH KemMl768 secretTmpl intent of
    KeyEffect pw fx -> do
      res <- answer m1 fx
      c <- finishCommit m1 st pw res 1
      case pcOutputs c of
        (NativeOutput (RegionBytes "ciphertext" _) ct2 : _) ->
          assertEqual "synthetic encaps is seed-deterministic" ct1 ct2
        _ -> assertFailure "no ciphertext output"
    other -> assertFailure ("encaps plan is not an effect: " ++ show other) >> undefined
  _ <- pure h
  pure ()

caseKemEncapsShort :: IO ()
caseKemEncapsShort = withSynth $ \answer -> do
  m0 <- seedModel
  st <- getSession m0
  (m1, pubH, _) <- genKemPair answer m0 st
  let before = Map.size (mObjects m1)
      ctLen = kemCtLen KemMl768
  case planKemEncaps m1 st mlKemMech pubH KemMl768 secretTmpl (IntentBuffer 100) of
    KeyImmediate (Reject r) -> do
      assertEqual "short code" CKR_BUFFER_TOO_SMALL (rejCode r)
      assertEqual "short publishes nothing" (StateDelta []) (rejDelta r)
      assertEqual "short answers the ct length"
        [NativeOutput (RegionBytes "ciphertext" (IntentBuffer 100))
          (encodeValue (ValULong (fromIntegral ctLen)))]
        (rejOutputs r)
      m2 <- expectRight (publishDelta m1 (rejDelta r))
      assertEqual "no key created" before (Map.size (mObjects m2))
    other -> assertFailure ("short encaps is not a length rejection: " ++ show other)
