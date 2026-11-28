{- | KeyManagement part 2 fixtures.
-}
{-# LANGUAGE OverloadedStrings #-}
module KeyManagement.Part2Fixtures
  ( iv16
  , genAesKey
  , aesTmpl
  , genDes3Key
  , des3Tmpl
  , wrapKeyTmpl
  , ecPubTmpl
  , ecPrivTmpl
  , rsaPubTmpl
  , rsaPrivTmpl
  , dsaP
  , dsaQ
  , dsaG
  , dsaPubTmpl
  , dsaPrivTmpl
  , dsaParamsTmpl
  , x942ParamsTmpl
  , dhPkcsParamsTmpl
  , dhP
  , dhG
  , dhQ
  , dhPubTmpl
  , dhPrivTmpl
  , dhX942PubTmpl
  , dhX942PrivTmpl
  , dhRealP
  , ed19OidBytes
  , ed48OidBytes
  , edPoint19
  , edSeed19
  , edPubTmpl
  , edPrivTmpl
  , x19OidBytes
  , x48OidBytes
  , xPoint19
  , xScalar19
  , xdPubTmpl
  , xdPrivTmpl
  ) where

import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import Data.Word (Word64)
import Test.Tasty.HUnit (assertFailure)
import Haskoki.Attribute
  ( AttributeType (..)
  , AttributeValue (..)
  )
import Haskoki.Model
  ( Model (..)
  , SessionState
  )
import Haskoki.Operation.Effect (CryptoEffect (..), CryptoResult (..))
import Haskoki.Operation.KeyManagement
  ( KeyPlan (..)
  , aesKeyGenMech
  , ckkAes
  , ckkDes3
  , ckkDh
  , ckkDsa
  , ckkEc
  , ckkEcEdwards
  , ckkEcMontgomery
  , ckkRsa
  , ckkX9_42Dh
  , ckoDomainParameters
  , ckoPrivateKey
  , ckoPublicKey
  , ckoSecretKey
  , des3KeyGenMech
  , planGenerateKey
  )
import Haskoki.Outcome
  ( PreparedCommit (..)
  )
import Haskoki.Rules (defaultRules)
import Haskoki.Transition (publishDelta)
import Haskoki.Types
  ( ExternalHandle (..)
  )
import KeyManagement.Fixtures

-- ---------------------------------------------------------------------------
-- Part 2 fixtures
-- ---------------------------------------------------------------------------

iv16 :: ByteString
iv16 = "0123456789abcdef"

-- | Generate one AES key through the planner + synthetic backend.
genAesKey :: (Model -> CryptoEffect -> IO CryptoResult)
  -> Model -> SessionState -> [(AttributeType, AttributeValue)]
  -> IO (Model, ExternalHandle)
genAesKey answer m st tmpl = case planGenerateKey defaultRules m st aesKeyGenMech BS.empty tmpl of
  KeyEffect pw fx -> do
    res <- answer m fx
    c <- finishCommit m st pw res 1
    h <- handleOf (pcOutputs c !! 0)
    m' <- expectRight (publishDelta m (pcDelta c))
    pure (m', h)
  other -> assertFailure ("keygen plan is not an effect: " ++ show other) >> undefined

aesTmpl :: Int -> [(AttributeType, AttributeValue)]
aesTmpl n =
  [ (AttrClass, ValULong ckoSecretKey)
  , (AttrKeyType, ValULong ckkAes)
  , (AttrValueLen, ValULong (fromIntegral n))
  , (AttrToken, ValBool False)
  , (AttrPrivate, ValBool True)
  , (AttrSensitive, ValBool True)
  , (AttrExtractable, ValBool True)
  , (AttrEncrypt, ValBool True)
  , (AttrDecrypt, ValBool True)
  ]

-- | Generate one 3DES key through the planner + synthetic backend.
genDes3Key :: (Model -> CryptoEffect -> IO CryptoResult)
  -> Model -> SessionState -> [(AttributeType, AttributeValue)]
  -> IO (Model, ExternalHandle)
genDes3Key answer m st tmpl = case planGenerateKey defaultRules m st des3KeyGenMech BS.empty tmpl of
  KeyEffect pw fx -> do
    res <- answer m fx
    c <- finishCommit m st pw res 1
    h <- handleOf (pcOutputs c !! 0)
    m' <- expectRight (publishDelta m (pcDelta c))
    pure (m', h)
  other -> assertFailure ("keygen plan is not an effect: " ++ show other) >> undefined

des3Tmpl :: Int -> [(AttributeType, AttributeValue)]
des3Tmpl n =
  [ (AttrClass, ValULong ckoSecretKey)
  , (AttrKeyType, ValULong ckkDes3)
  , (AttrValueLen, ValULong (fromIntegral n))
  , (AttrToken, ValBool False)
  , (AttrPrivate, ValBool True)
  , (AttrSensitive, ValBool True)
  , (AttrExtractable, ValBool True)
  , (AttrSign, ValBool True)
  , (AttrVerify, ValBool True)
  ]

wrapKeyTmpl :: [(AttributeType, AttributeValue)]
wrapKeyTmpl =
  [ (AttrClass, ValULong ckoSecretKey)
  , (AttrKeyType, ValULong ckkAes)
  , (AttrValueLen, ValULong 32)
  , (AttrToken, ValBool False)
  , (AttrPrivate, ValBool True)
  , (AttrExtractable, ValBool False)
  , (AttrWrap, ValBool True)
  , (AttrUnwrap, ValBool True)
  ]

ecPubTmpl :: [(AttributeType, AttributeValue)]
ecPubTmpl =
  [ (AttrClass, ValULong ckoPublicKey)
  , (AttrKeyType, ValULong ckkEc)
  , (AttrEcParams, ValBytes "P-256")
  , (AttrToken, ValBool False)
  , (AttrVerify, ValBool True)
  ]

ecPrivTmpl :: [(AttributeType, AttributeValue)]
ecPrivTmpl =
  [ (AttrClass, ValULong ckoPrivateKey)
  , (AttrKeyType, ValULong ckkEc)
  , (AttrEcParams, ValBytes "P-256")
  , (AttrToken, ValBool False)
  , (AttrPrivate, ValBool True)
  , (AttrSensitive, ValBool True)
  , (AttrExtractable, ValBool False)
  , (AttrSign, ValBool True)
  ]

rsaPubTmpl :: [(AttributeType, AttributeValue)]
rsaPubTmpl =
  [ (AttrClass, ValULong ckoPublicKey)
  , (AttrKeyType, ValULong ckkRsa)
  , (AttrModulusBits, ValULong 2048)
  , (AttrToken, ValBool False)
  ]

rsaPrivTmpl :: [(AttributeType, AttributeValue)]
rsaPrivTmpl =
  [ (AttrClass, ValULong ckoPrivateKey)
  , (AttrKeyType, ValULong ckkRsa)
  , (AttrModulusBits, ValULong 2048)
  , (AttrToken, ValBool False)
  , (AttrPrivate, ValBool True)
  , (AttrSensitive, ValBool True)
  , (AttrExtractable, ValBool False)
  ]

-- Toy DSA domain values (shaped, not prime: planners check
-- presence and shape, never primality).
dsaP :: ByteString
dsaP = BS.pack (0x80 : replicate 127 1)

dsaQ :: ByteString
dsaQ = BS.pack (0x80 : replicate 19 2)

dsaG :: ByteString
dsaG = BS.pack (0x40 : replicate 127 3)

dsaPubTmpl :: [(AttributeType, AttributeValue)]
dsaPubTmpl =
  [ (AttrClass, ValULong ckoPublicKey)
  , (AttrKeyType, ValULong ckkDsa)
  , (AttrPrime, ValBytes dsaP)
  , (AttrSubprime, ValBytes dsaQ)
  , (AttrBase, ValBytes dsaG)
  , (AttrToken, ValBool False)
  , (AttrVerify, ValBool True)
  ]

dsaPrivTmpl :: [(AttributeType, AttributeValue)]
dsaPrivTmpl =
  [ (AttrClass, ValULong ckoPrivateKey)
  , (AttrKeyType, ValULong ckkDsa)
  , (AttrToken, ValBool False)
  , (AttrPrivate, ValBool True)
  , (AttrSensitive, ValBool True)
  , (AttrExtractable, ValBool False)
  , (AttrSign, ValBool True)
  ]

dsaParamsTmpl :: Word64 -> [(AttributeType, AttributeValue)]
dsaParamsTmpl l =
  [ (AttrClass, ValULong ckoDomainParameters)
  , (AttrKeyType, ValULong ckkDsa)
  , (AttrPrimeBits, ValULong l)
  , (AttrToken, ValBool False)
  ]

x942ParamsTmpl :: Word64 -> Word64 -> [(AttributeType, AttributeValue)]
x942ParamsTmpl l n =
  [ (AttrClass, ValULong ckoDomainParameters)
  , (AttrKeyType, ValULong ckkX9_42Dh)
  , (AttrPrimeBits, ValULong l)
  , (AttrSubprimeBits, ValULong n)
  , (AttrToken, ValBool False)
  ]

dhPkcsParamsTmpl :: Word64 -> Word64 -> [(AttributeType, AttributeValue)]
dhPkcsParamsTmpl l n =
  [ (AttrClass, ValULong ckoDomainParameters)
  , (AttrKeyType, ValULong ckkDh)
  , (AttrPrimeBits, ValULong l)
  , (AttrSubprimeBits, ValULong n)
  , (AttrToken, ValBool False)
  ]

-- Toy DH values (shaped: planners check presence and shape;
-- the real test below mints on the RFC 3526 prime).
dhP :: ByteString
dhP = BS.pack (0x80 : replicate 255 1)

dhG :: ByteString
dhG = BS.singleton 2

dhQ :: ByteString
dhQ = BS.pack (0x80 : replicate 31 4)

dhPubTmpl :: [(AttributeType, AttributeValue)]
dhPubTmpl =
  [ (AttrClass, ValULong ckoPublicKey)
  , (AttrKeyType, ValULong ckkDh)
  , (AttrPrime, ValBytes dhP)
  , (AttrBase, ValBytes dhG)
  , (AttrToken, ValBool False)
  , (AttrDerive, ValBool True)
  ]

dhPrivTmpl :: [(AttributeType, AttributeValue)]
dhPrivTmpl =
  [ (AttrClass, ValULong ckoPrivateKey)
  , (AttrKeyType, ValULong ckkDh)
  , (AttrToken, ValBool False)
  , (AttrPrivate, ValBool True)
  , (AttrSensitive, ValBool True)
  , (AttrExtractable, ValBool False)
  , (AttrDerive, ValBool True)
  ]

dhX942PubTmpl :: [(AttributeType, AttributeValue)]
dhX942PubTmpl =
  [ (AttrClass, ValULong ckoPublicKey)
  , (AttrKeyType, ValULong ckkX9_42Dh)
  , (AttrPrime, ValBytes dhP)
  , (AttrBase, ValBytes dhG)
  , (AttrSubprime, ValBytes dhQ)
  , (AttrToken, ValBool False)
  , (AttrDerive, ValBool True)
  ]

dhX942PrivTmpl :: [(AttributeType, AttributeValue)]
dhX942PrivTmpl =
  [ (AttrClass, ValULong ckoPrivateKey)
  , (AttrKeyType, ValULong ckkX9_42Dh)
  , (AttrToken, ValBool False)
  , (AttrPrivate, ValBool True)
  , (AttrSensitive, ValBool True)
  , (AttrExtractable, ValBool False)
  , (AttrDerive, ValBool True)
  ]

-- | The RFC 3526 2048-bit MODP prime (real keygen domain).
dhRealP :: ByteString
dhRealP = hex $ concat
  [ "ffffffffffffffffadf85458a2bb4a9aafdc5620273d3cf1d8b9c583ce2d3695a9"
  , "e13641146433fbcc939dce249b3ef97d2fe363630c75d8f681b202aec4617ad3"
  , "df1ed5d5fd65612433f51f5f066ed0856365553ded1af3b557135e7f57c93598"
  , "4f0c70e0e68b77e2a689daf3efe8721df158a136ade73530acca4f483a797abc"
  , "0ab182b324fb61d108a94bb2c8e3fbb96adab760d7f4681d4f42a3de394df4ae"
  , "56ede76372bb190b07a7c8ee0a6d709e02fce1cdf7e2ecc03404cd28342f6191"
  , "72fe9ce98583ff8e4f1232eef28183c3fe3b1b4c6fad733bb5fcbc2ec22005c5"
  , "8ef1837d1683b2c6f34a26c1b2effa886b423861285c97ffffffffffffffff"
  ]

-- Toy Edwards values (shaped: planners check presence and shape;
-- stamping parses real DER assembled from these parts).
ed19OidBytes :: ByteString
ed19OidBytes = hex "06032b6570"

ed48OidBytes :: ByteString
ed48OidBytes = hex "06032b6571"

edPoint19 :: ByteString
edPoint19 = BS.pack (0x58 : replicate 31 0x42)

edSeed19 :: ByteString
edSeed19 = BS.pack (0x11 : replicate 31 0x24)

edPubTmpl :: [(AttributeType, AttributeValue)]
edPubTmpl =
  [ (AttrClass, ValULong ckoPublicKey)
  , (AttrKeyType, ValULong ckkEcEdwards)
  , (AttrEcParams, ValBytes "Ed25519")
  , (AttrToken, ValBool False)
  , (AttrVerify, ValBool True)
  ]

edPrivTmpl :: [(AttributeType, AttributeValue)]
edPrivTmpl =
  [ (AttrClass, ValULong ckoPrivateKey)
  , (AttrKeyType, ValULong ckkEcEdwards)
  , (AttrToken, ValBool False)
  , (AttrPrivate, ValBool True)
  , (AttrSensitive, ValBool True)
  , (AttrExtractable, ValBool False)
  , (AttrSign, ValBool True)
  ]

-- Toy Montgomery values (shaped: planners check presence and
-- shape; stamping parses real DER assembled from these parts).
x19OidBytes :: ByteString
x19OidBytes = hex "06032b656e"

x48OidBytes :: ByteString
x48OidBytes = hex "06032b656f"

xPoint19 :: ByteString
xPoint19 = BS.pack (0x68 : replicate 31 0x42)

xScalar19 :: ByteString
xScalar19 = BS.pack (0x10 : replicate 31 0x24)

xdPubTmpl :: [(AttributeType, AttributeValue)]
xdPubTmpl =
  [ (AttrClass, ValULong ckoPublicKey)
  , (AttrKeyType, ValULong ckkEcMontgomery)
  , (AttrEcParams, ValBytes "X25519")
  , (AttrToken, ValBool False)
  , (AttrDerive, ValBool True)
  ]

xdPrivTmpl :: [(AttributeType, AttributeValue)]
xdPrivTmpl =
  [ (AttrClass, ValULong ckoPrivateKey)
  , (AttrKeyType, ValULong ckkEcMontgomery)
  , (AttrToken, ValBool False)
  , (AttrPrivate, ValBool True)
  , (AttrSensitive, ValBool True)
  , (AttrExtractable, ValBool False)
  , (AttrDerive, ValBool True)
  ]
