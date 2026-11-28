{- | KeyManagement keygen sweep (slice 11a).
-}
{-# LANGUAGE OverloadedStrings #-}
module KeyManagement.KeygenSweep
  ( SweepLens
  , keygenSweepTable
  , sweepLengths
  , caseKeygenSweep
  , genSweepKey
  , sweepTmpl
  ) where

import Data.Bits (popCount)
import qualified Data.ByteString as BS
import qualified Data.Map.Strict as Map
import Data.Word (Word64, Word8)
import Test.Tasty.HUnit (assertBool, assertEqual, assertFailure)
import Haskoki.Attribute
  ( AttributeType (..)
  , AttributeValue (..)
  )
import Haskoki.Model
  ( Model (..)
  , ObjectState (..)
  , SessionState
  )
import Haskoki.Object (resolveHandle)
import Haskoki.Operation.Effect (CryptoEffect (..), CryptoResult (..))
import Haskoki.Operation.KeyManagement
  ( KeyDeny (..)
  , KeyPlan (..)
  , ckkAes
  , ckkAesXts
  , ckkDes
  , ckkDes2
  , ckkCdmf
  , ckkCast
  , ckkCast3
  , ckkCast128
  , ckkRc2
  , ckkRc4
  , ckkRc5
  , ckkIdea
  , ckkSkipjack
  , ckkBaton
  , ckkJuniper
  , ckkBlowfish
  , ckkTwofish
  , ckkGost28147
  , ckkSeed
  , ckkAria
  , ckkCamellia
  , ckkSalsa20
  , ckkPoly1305
  , ckkHkdf
  , ckkSha1Hmac
  , ckkSha224Hmac
  , ckkSha256Hmac
  , ckkSha384Hmac
  , ckkSha512Hmac
  , ckkSha512_224Hmac
  , ckkSha512_256Hmac
  , ckkSha512THmac
  , ckkSha3_224Hmac
  , ckkSha3_256Hmac
  , ckkSha3_384Hmac
  , ckkSha3_512Hmac
  , ckkBlake2b160Hmac
  , ckkBlake2b256Hmac
  , ckkBlake2b384Hmac
  , ckoSecretKey
  , keyBytesOf
  , planGenerateKey
  , desKeyGenMech
  , des2KeyGenMech
  , cdmfKeyGenMech
  , castKeyGenMech
  , cast3KeyGenMech
  , cast128KeyGenMech
  , rc2KeyGenMech
  , rc4KeyGenMech
  , rc5KeyGenMech
  , ideaKeyGenMech
  , skipjackKeyGenMech
  , batonKeyGenMech
  , juniperKeyGenMech
  , blowfishKeyGenMech
  , twofishKeyGenMech
  , gost28147KeyGenMech
  , seedKeyGenMech
  , ariaKeyGenMech
  , camelliaKeyGenMech
  , salsa20KeyGenMech
  , poly1305KeyGenMech
  , aesXtsKeyGenMech
  , hkdfKeyGenMech
  , sha1KeyGenMech
  , sha224KeyGenMech
  , sha256KeyGenMech
  , sha384KeyGenMech
  , sha512KeyGenMech
  , sha512_224KeyGenMech
  , sha512_256KeyGenMech
  , sha512TKeyGenMech
  , sha3_224KeyGenMech
  , sha3_256KeyGenMech
  , sha3_384KeyGenMech
  , sha3_512KeyGenMech
  , blake2b160KeyGenMech
  , blake2b256KeyGenMech
  , blake2b384KeyGenMech
  )
import Haskoki.Outcome
  ( PreparedCommit (..)
  )
import Haskoki.Registry (MechanismId (..))
import Haskoki.Rules (defaultRules)
import Haskoki.Transition (publishDelta)
import Haskoki.Types
  ( ExternalHandle (..)
  , ReturnCode (..)
  )
import KeyManagement.Fixtures

-- ---------------------------------------------------------------------------
-- Keygen sweep (slice 11a)
-- ---------------------------------------------------------------------------

-- | Sweep length shapes: fixed sizes mint the headline length when
-- @CKA_VALUE_LEN@ is absent; discrete and ranged shapes require it.
data SweepLens
  = SweepFixed Int
  | SweepDiscrete [Int]
  | SweepRange Int Int
  deriving (Eq, Show)

-- | (label, mechanism, key type, lengths, DES-parity?).
keygenSweepTable :: [(String, MechanismId, Word64, SweepLens, Bool)]
keygenSweepTable =
  [ ("DES", desKeyGenMech, ckkDes, SweepFixed 8, True)
  , ("DES2", des2KeyGenMech, ckkDes2, SweepFixed 16, True)
  , ("CDMF", cdmfKeyGenMech, ckkCdmf, SweepFixed 8, True)
  , ("IDEA", ideaKeyGenMech, ckkIdea, SweepFixed 16, False)
  , ("SEED", seedKeyGenMech, ckkSeed, SweepFixed 16, False)
  , ("SKIPJACK", skipjackKeyGenMech, ckkSkipjack, SweepFixed 12, False)
  , ("BATON", batonKeyGenMech, ckkBaton, SweepFixed 40, False)
  , ("JUNIPER", juniperKeyGenMech, ckkJuniper, SweepFixed 40, False)
  , ("GOST28147", gost28147KeyGenMech, ckkGost28147, SweepFixed 32, False)
  , ("SALSA20", salsa20KeyGenMech, ckkSalsa20, SweepFixed 32, False)
  , ("POLY1305", poly1305KeyGenMech, ckkPoly1305, SweepFixed 32, False)
  , ("ARIA", ariaKeyGenMech, ckkAria, SweepDiscrete [16, 24, 32], False)
  , ("CAMELLIA", camelliaKeyGenMech, ckkCamellia, SweepDiscrete [16, 24, 32], False)
  , ("TWOFISH", twofishKeyGenMech, ckkTwofish, SweepDiscrete [16, 24, 32], False)
  , ("AES-XTS", aesXtsKeyGenMech, ckkAesXts, SweepDiscrete [32, 64], False)
  , ("CAST", castKeyGenMech, ckkCast, SweepRange 1 8, False)
  , ("CAST3", cast3KeyGenMech, ckkCast3, SweepRange 1 8, False)
  , ("CAST128", cast128KeyGenMech, ckkCast128, SweepRange 1 16, False)
  , ("RC2", rc2KeyGenMech, ckkRc2, SweepRange 1 128, False)
  , ("RC4", rc4KeyGenMech, ckkRc4, SweepRange 1 255, False)
  , ("RC5", rc5KeyGenMech, ckkRc5, SweepRange 1 255, False)
  , ("BLOWFISH", blowfishKeyGenMech, ckkBlowfish, SweepRange 4 56, False)
  , ("HKDF", hkdfKeyGenMech, ckkHkdf, SweepRange 1 255, False)
  , ("SHA-1-HMAC", sha1KeyGenMech, ckkSha1Hmac, SweepRange 1 255, False)
  , ("SHA224-HMAC", sha224KeyGenMech, ckkSha224Hmac, SweepRange 1 255, False)
  , ("SHA256-HMAC", sha256KeyGenMech, ckkSha256Hmac, SweepRange 1 255, False)
  , ("SHA384-HMAC", sha384KeyGenMech, ckkSha384Hmac, SweepRange 1 255, False)
  , ("SHA512-HMAC", sha512KeyGenMech, ckkSha512Hmac, SweepRange 1 255, False)
  , ("SHA512/224-HMAC", sha512_224KeyGenMech, ckkSha512_224Hmac, SweepRange 1 255, False)
  , ("SHA512/256-HMAC", sha512_256KeyGenMech, ckkSha512_256Hmac, SweepRange 1 255, False)
  , ("SHA512/t-HMAC", sha512TKeyGenMech, ckkSha512THmac, SweepRange 1 255, False)
  , ("SHA3-224-HMAC", sha3_224KeyGenMech, ckkSha3_224Hmac, SweepRange 1 255, False)
  , ("SHA3-256-HMAC", sha3_256KeyGenMech, ckkSha3_256Hmac, SweepRange 1 255, False)
  , ("SHA3-384-HMAC", sha3_384KeyGenMech, ckkSha3_384Hmac, SweepRange 1 255, False)
  , ("SHA3-512-HMAC", sha3_512KeyGenMech, ckkSha3_512Hmac, SweepRange 1 255, False)
  , ("BLAKE2B-160-HMAC", blake2b160KeyGenMech, ckkBlake2b160Hmac, SweepRange 1 255, False)
  , ("BLAKE2B-256-HMAC", blake2b256KeyGenMech, ckkBlake2b256Hmac, SweepRange 1 255, False)
  , ("BLAKE2B-384-HMAC", blake2b384KeyGenMech, ckkBlake2b384Hmac, SweepRange 1 255, False)
  ]

-- | Good lengths, bad lengths, and the missing-length default (fixed
-- sizes only) for one sweep shape.
sweepLengths :: SweepLens -> ([Int], [Int], Maybe Int)
sweepLengths (SweepFixed n) =
  ([n], [x | x <- [n - 1, n + 1], x >= 0], Just n)
sweepLengths (SweepDiscrete ns) =
  (ns, filter (`notElem` ns) [0, 1, 8, 20, 48, 65], Nothing)
sweepLengths (SweepRange lo hi) =
  ([lo, (lo + hi) `div` 2, hi], [0] ++ [x | x <- [lo - 1, hi + 1], x > 0], Nothing)

caseKeygenSweep :: IO ()
caseKeygenSweep = withSynth $ \answer -> do
  m0 <- seedModel
  st <- getSession m0
  go answer st m0 keygenSweepTable
  where
    go _ _ _m [] = pure ()
    go answer st m (row : rows) = do
      m' <- runSweepRow answer st m row
      go answer st m' rows

runSweepRow
  :: (Model -> CryptoEffect -> IO CryptoResult)
  -> SessionState -> Model
  -> (String, MechanismId, Word64, SweepLens, Bool)
  -> IO Model
runSweepRow answer st m (label, mech, kt, lens, parity) = do
  let (good, bad, defLen) = sweepLengths lens
  case good of
    [] -> assertFailure (label ++ " sweep has no good length") >> pure m
    (g0 : _) -> do
      m1 <- mintGood m good
      mapM_ (refuseBad m1) bad
      m2 <- missingLen m1 g0 defLen
      case planGenerateKey defaultRules m2 st mech BS.empty (sweepTmpl ckkAes g0) of
        KeyDenied deny -> assertEqual (label ++ " wrong type code")
          CKR_TEMPLATE_INCONSISTENT (kdCode deny)
        other -> assertFailure (label ++ " wrong key type must refuse: " ++ show other)
      pure m2
  where
    mintGood m' [] = pure m'
    mintGood m' (n : ns) = do
      (m'', h) <- genSweepKey answer m' st mech (sweepTmpl kt n)
      Just ost <- pure (resolveHandle m'' h)
      assertEqual (label ++ " class")
        (Just (ValULong ckoSecretKey)) (Map.lookup AttrClass (osAttrs ost))
      assertEqual (label ++ " type")
        (Just (ValULong kt)) (Map.lookup AttrKeyType (osAttrs ost))
      case keyBytesOf ost of
        Just mat -> do
          assertEqual (label ++ " material length") n (BS.length mat)
          if parity
            then assertBool (label ++ " odd parity") (BS.all oddParity mat)
            else pure ()
        Nothing -> assertFailure (label ++ " generated key lacks material")
      mintGood m'' ns
    refuseBad m' n = case planGenerateKey defaultRules m' st mech BS.empty (sweepTmpl kt n) of
      KeyDenied deny -> assertEqual (label ++ " bad length code " ++ show n)
        CKR_TEMPLATE_INCONSISTENT (kdCode deny)
      other -> assertFailure (label ++ " length " ++ show n ++ " must refuse: " ++ show other)
    missingLen m' n (Just d) = do
      (m'', h) <- genSweepKey answer m' st mech (dropValueLen (sweepTmpl kt n))
      Just ost <- pure (resolveHandle m'' h)
      case keyBytesOf ost of
        Just mat -> assertEqual (label ++ " default material") d (BS.length mat)
        Nothing -> assertFailure (label ++ " generated key lacks material")
      pure m''
    missingLen m' n Nothing =
      case planGenerateKey defaultRules m' st mech BS.empty (dropValueLen (sweepTmpl kt n)) of
        KeyDenied deny -> do
          assertEqual (label ++ " missing length code")
            CKR_TEMPLATE_INCOMPLETE (kdCode deny)
          pure m'
        other -> assertFailure (label ++ " missing length must refuse: " ++ show other)
    dropValueLen tmpl = [a | a@(t, _) <- tmpl, t /= AttrValueLen]

-- | Odd DES parity: every key byte carries an odd number of 1 bits.
oddParity :: Word8 -> Bool
oddParity b = odd (popCount b)

-- | Generate one sweep key through the planner + synthetic backend.
genSweepKey :: (Model -> CryptoEffect -> IO CryptoResult)
  -> Model -> SessionState -> MechanismId
  -> [(AttributeType, AttributeValue)]
  -> IO (Model, ExternalHandle)
genSweepKey answer m st mech tmpl = case planGenerateKey defaultRules m st mech BS.empty tmpl of
  KeyEffect pw fx -> do
    res <- answer m fx
    c <- finishCommit m st pw res 1
    h <- handleOf (pcOutputs c !! 0)
    m' <- expectRight (publishDelta m (pcDelta c))
    pure (m', h)
  other -> assertFailure ("keygen plan is not an effect: " ++ show other) >> undefined

sweepTmpl :: Word64 -> Int -> [(AttributeType, AttributeValue)]
sweepTmpl kt n =
  [ (AttrClass, ValULong ckoSecretKey)
  , (AttrKeyType, ValULong kt)
  , (AttrValueLen, ValULong (fromIntegral n))
  , (AttrToken, ValBool False)
  , (AttrSign, ValBool True)
  ]
