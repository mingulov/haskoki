{- | Driver wrap dispatch and composition wrap/unwrap.
-}
{-# LANGUAGE OverloadedStrings #-}
module Haskoki.Engine.Driver.Wrap
  ( isRsaPkcsWrapMech
  , isAesKwWrapMech
  , runEcdhCompWrap
  , runEcdhCompUnwrap
  , runRsaCompWrap
  , runRsaCompUnwrap
  ) where
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BC8
import Data.ByteString (ByteString)
import qualified Data.Text as T

import Haskoki.Engine.Backend
  ( BackendEnv
  , CryptoBackend (..)
  , EcSpec (..)
  , EngineResult (..)
  , KeyGenSpec (..)
  , KeyMaterial (..)
  , OaepParams (..)
  , RsaCipherParams (..)
  )
import Haskoki.Engine.Driver.Cipher (runCipher)
import Haskoki.Engine.Driver.Common (compSpec, keyBytesOf, rsaDigest)
import Haskoki.Engine.Driver.Result (toCryptoError)
import Haskoki.Operation.Effect (CryptoError (..), CryptoResult (..))
import Haskoki.Operation.State (CipherDir (..))
import Haskoki.Operation.KeyManagement
  ( aesKwMech
  , aesKwPadMech
  , aesKwp7Mech
  , aesKwpMech
  , rsaPkcsMech
  )
import Haskoki.Recipe.WrapComp
  ( WrapCompDomain (..)
  , WrapCompEcdhRecipe
  , wrapCompAesBytes
  , wrapCompAgreePeer
  , wrapCompDomain
  , wrapCompPubPeer
  , wrapCompSplitBlob
  , wrapCompTransportLen
  , wrapCompTransportPrefix
  )
import Haskoki.Recipe.WrapCompRsa
  ( WrapCompRsaRecipe
  , wrapCompRsaAesBytes
  , wrapCompRsaFrameHead
  , wrapCompRsaModulusBytes
  , wrapCompRsaOaep
  , wrapCompRsaSplitBlob
  , wrapCompRsaUnframeHead
  )
import Haskoki.Registry (MechanismId (..))


-- | The raw RSA v1.5 row: the only v1.5 mechanism that wraps
-- (the digest rows are signature-only).
isRsaPkcsWrapMech :: MechanismId -> Bool
isRsaPkcsWrapMech mech = mech == rsaPkcsMech

-- | The AES key-wrap rows (KW plus the two KWP names, plus
-- KW-PKCS7 whose planner pads first): the planner frames the
-- payload (raw, or PKCS#7-padded for PKCS7) and 'runCipher'
-- executes the wrap backend spec selected by 'cipherCtor'.
isAesKwWrapMech :: MechanismId -> Bool
isAesKwWrapMech mech =
  mech == aesKwMech || mech == aesKwPadMech || mech == aesKwpMech || mech == aesKwp7Mech

-- | ECDH-composition wrap: ephemeral transport keygen on
-- the wrapping (recipient PUBLIC) key's domain, ECDH
-- agreement of the transport private half against the
-- wrapping public half, the FIRST agreement bytes as the AES
-- KEK (NOT the derive truncation, which drops leading bytes),
-- KWP seal of the target, blob = transport-pub || kwp-blob.
-- Served primitives only (generateKey, ecdhDerive, the KWP
-- cipher entry); the ephemeral key never persists. Opaque
-- doubles transport on a fixed P-256 request (synthetic pairs
-- are curve-independent opaque halves, so the row's curve
-- family is immaterial there); real keys always scan.
runEcdhCompWrap :: CryptoBackend b => BackendEnv b -> WrapCompEcdhRecipe -> KeyMaterial -> ByteString -> ByteString -> IO CryptoResult
runEcdhCompWrap env r wrapKey params target = case keyBytesOf wrapKey of
  Nothing -> pure (GotCryptoError (CryptoBadKey "driver"
    "composition wrapping key has no bytes"))
  Just wrapB -> case wrapCompAesBytes params of
    Nothing -> pure (GotCryptoError (CryptoFailed
      "driver: malformed wrap-composition parameters"))
    Just aesBytes ->
      let dom = wrapCompDomain wrapB
      in case wrapCompPubPeer dom wrapB of
        Nothing -> pure (GotCryptoError (CryptoFailed
          "driver: wrapping public peer rejected"))
        Just recipPub -> do
          g <- generateKey env (transportGen dom)
          case g of
            EngineFail err -> pure (GotCryptoError (toCryptoError err))
            EngineOk (KeyDer tpriv, Just (KeyDer tpub)) ->
              case ( wrapCompTransportPrefix r dom tpub
                   , wrapCompTransportLen r dom ) of
                (Just prefix, Just preLen)
                  | BS.length prefix == preLen -> do
                      s <- ecdhDerive env (compSpec r) (KeyDer tpriv) (KeyDer recipPub)
                      case s of
                        EngineFail err -> pure (GotCryptoError (toCryptoError err))
                        EngineOk secret
                          | BS.length secret < aesBytes -> pure (GotCryptoError (CryptoFailed
                              "driver: agreement secret shorter than the KEK"))
                          | otherwise -> do
                              sealed <- runCipher env DirEncrypt aesKwpMech
                                (KeyBytes (BS.take aesBytes secret)) BS.empty target
                              case sealed of
                                GotBytes ct -> pure (GotBytes (prefix <> ct))
                                other -> pure other
                _ -> pure (GotCryptoError (CryptoFailed
                  "driver: transport framing failed"))
            _ -> pure (GotCryptoError (CryptoFailed
              "driver: transport keygen shape rejected"))
  where
    transportGen DomainOpaque = GenEC (EcSpec "P-256" "DER")
    transportGen (DomainWeierstrass name _) =
      GenEC (EcSpec (T.unpack name) "DER")
    transportGen (DomainMontgomery name _) =
      GenXDHKeypair (BC8.pack (T.unpack name))

-- | ECDH-composition unwrap: split the transport prefix,
-- re-derive the KEK against it, KWP-open the tail. KWP-open
-- failures propagate as authentication faults (fail closed,
-- never wrong plaintext).
runEcdhCompUnwrap :: CryptoBackend b => BackendEnv b -> WrapCompEcdhRecipe -> KeyMaterial -> ByteString -> ByteString -> IO CryptoResult
runEcdhCompUnwrap env r unwrapKey params blob = case keyBytesOf unwrapKey of
  Nothing -> pure (GotCryptoError (CryptoBadKey "driver"
    "composition unwrapping key has no bytes"))
  Just wrapB -> case wrapCompAesBytes params of
    Nothing -> pure (GotCryptoError (CryptoFailed
      "driver: malformed wrap-composition parameters"))
    Just aesBytes ->
      let dom = wrapCompDomain wrapB
      in case wrapCompSplitBlob r dom blob of
        Nothing -> pure (GotCryptoError (CryptoFailed
          "driver: composition blob framing rejected"))
        Just (prefix, kwpBlob) ->
          case wrapCompAgreePeer r dom prefix of
            Nothing -> pure (GotCryptoError (CryptoFailed
              "driver: composition transport peer rejected"))
            Just peer -> do
              s <- ecdhDerive env (compSpec r) unwrapKey (KeyDer peer)
              case s of
                EngineFail err -> pure (GotCryptoError (toCryptoError err))
                EngineOk secret
                  | BS.length secret < aesBytes -> pure (GotCryptoError (CryptoFailed
                      "driver: agreement secret shorter than the KEK"))
                  | otherwise ->
                      runCipher env DirDecrypt aesKwpMech
                        (KeyBytes (BS.take aesBytes secret)) BS.empty kwpBlob

-- | RSA-composition wrap: mint a random temp KEK at the
-- requested strength, OAEP-seal it under the recipient
-- PUBLIC key, KWP-seal the target under the KEK, answer the
-- modulus-wide OAEP head plus the KWP tail. Served
-- primitives only (generateKey, pkeyEncrypt, the KWP cipher
-- entry); the KEK never persists. Tag-sized synthetic seals
-- frame modulus-wide through the recipe (exact-k real seals
-- pass through).
runRsaCompWrap :: CryptoBackend b => BackendEnv b -> WrapCompRsaRecipe -> KeyMaterial -> ByteString -> ByteString -> IO CryptoResult
runRsaCompWrap env _ wrapKey params target = case keyBytesOf wrapKey of
  Nothing -> pure (GotCryptoError (CryptoBadKey "driver"
    "composition wrapping key has no bytes"))
  Just wrapB ->
    case (wrapCompRsaModulusBytes wrapB, wrapCompRsaAesBytes params, wrapCompRsaOaep params) of
      (Just k, Just aesBytes, Just (d, m, label)) -> case (rsaDigest d, rsaDigest m) of
        (Just dh, Just mh) -> do
          g <- generateKey env (GenSym "AES" aesBytes)
          case g of
            EngineOk (KeyBytes kek, _)
              | BS.length kek == aesBytes -> do
                  s <- pkeyEncrypt env (RsaOaep (OaepParams dh mh label)) wrapKey kek
                  case s of
                    EngineFail err -> pure (GotCryptoError (toCryptoError err))
                    EngineOk raw -> case wrapCompRsaFrameHead k (aesBytes + 16) raw of
                      Nothing -> pure (GotCryptoError (CryptoFailed
                        "driver: OAEP head escapes the modulus width"))
                      Just framed -> do
                        sealed <- runCipher env DirEncrypt aesKwpMech
                          (KeyBytes kek) BS.empty target
                        case sealed of
                          GotBytes ct -> pure (GotBytes (framed <> ct))
                          other -> pure other
            EngineOk _ -> pure (GotCryptoError (CryptoFailed
              "driver: temp KEK keygen shape rejected"))
            EngineFail err -> pure (GotCryptoError (toCryptoError err))
        _ -> pure (GotCryptoError (CryptoFailed
          "driver: OAEP digest stems rejected"))
      _ -> pure (GotCryptoError (CryptoFailed
        "driver: malformed wrap-composition parameters"))

-- | RSA-composition unwrap: split the modulus-wide head,
-- OAEP-open the KEK with the PRIVATE key (length-tripwired),
-- KWP-open the tail. Open failures propagate as
-- authentication faults (fail closed, never wrong
-- plaintext).
runRsaCompUnwrap :: CryptoBackend b => BackendEnv b -> WrapCompRsaRecipe -> KeyMaterial -> ByteString -> ByteString -> IO CryptoResult
runRsaCompUnwrap env _ unwrapKey params blob = case keyBytesOf unwrapKey of
  Nothing -> pure (GotCryptoError (CryptoBadKey "driver"
    "composition unwrapping key has no bytes"))
  Just wrapB ->
    case (wrapCompRsaModulusBytes wrapB, wrapCompRsaAesBytes params, wrapCompRsaOaep params) of
      (Just k, Just aesBytes, Just (d, m, label)) ->
        case wrapCompRsaSplitBlob k blob of
          Nothing -> pure (GotCryptoError (CryptoFailed
            "driver: composition blob framing rejected"))
          Just (framed, kwpBlob) -> case (rsaDigest d, rsaDigest m) of
            (Just dh, Just mh) -> do
              let inner = wrapCompRsaUnframeHead k (aesBytes + 16) framed
              o <- pkeyDecrypt env (RsaOaep (OaepParams dh mh label)) unwrapKey inner
              case o of
                EngineFail err -> pure (GotCryptoError (toCryptoError err))
                EngineOk kek
                  | BS.length kek == aesBytes ->
                      runCipher env DirDecrypt aesKwpMech
                        (KeyBytes kek) BS.empty kwpBlob
                  | otherwise -> pure (GotCryptoError (CryptoFailed
                      "driver: opened KEK escapes the requested strength"))
            _ -> pure (GotCryptoError (CryptoFailed
              "driver: OAEP digest stems rejected"))
      _ -> pure (GotCryptoError (CryptoFailed
        "driver: malformed wrap-composition parameters"))
