{- | Driver answer adapters: backend results onto 'CryptoResult',
backend/crypto errors onto each other and the core taxonomy, and
the release drain.

Leaf module: imports only the backend, the effect vocabulary, and
'Haskoki.Outcome'. Imported by 'Haskoki.Engine.Driver' and every
family; re-exported names keep the 'Haskoki.Engine.Driver' export
list byte-identical.
-}
{-# LANGUAGE OverloadedStrings #-}
module Haskoki.Engine.Driver.Result
  ( toBytes
  , toResource
  , toUnit
  , toVerifyBool
  , toVerifyUnit
  , toKemPair
  , toCryptoError
  , toCoreFailure
  , fromCoreFailure
  , cryptoToCore
  , encodeResult
  , drainReleases
  ) where

import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import qualified Haskoki.Outcome as O

import Haskoki.Engine.Backend
  ( BackendEnv
  , BackendError (..)
  , CryptoBackend (..)
  , EngineResult (..)
  )
import Haskoki.Operation.Effect (CryptoError (..), CryptoResult (..))
import Haskoki.Types (EngineResourceId)

-- | Bytes-shaped answers: backend failures map onto the typed
-- crypto errors.
toBytes :: EngineResult ByteString -> CryptoResult
toBytes (EngineOk b) = GotBytes b
toBytes (EngineFail err) = GotCryptoError (toCryptoError err)

-- | Allocation answers: the resource id crosses to the finisher,
-- which records it on the slot.
toResource :: EngineResult EngineResourceId -> CryptoResult
toResource (EngineOk rid) = GotResource rid
toResource (EngineFail err) = GotCryptoError (toCryptoError err)

-- | Feed answers: success carries no bytes, and the unit shape is
-- preserved as 'GotUnit' — distinct from empty bytes —
-- through the driver helpers until 'encodeResult'.
toUnit :: EngineResult () -> CryptoResult
toUnit (EngineOk ()) = GotUnit
toUnit (EngineFail err) = GotCryptoError (toCryptoError err)

-- | Verify-shaped answers: an authentication failure is a verdict,
-- never a malfunction; any other backend failure keeps its
-- category through 'toCryptoError' (categories survive
-- every adapter). Mismatch stays 'False'; most preserved
-- categories still interpret to 'CKR_GENERAL_ERROR', except
-- 'BackendSigLenRange', which interprets to
-- 'CKR_SIGNATURE_LEN_RANGE', and 'BackendUnsupported', which is
-- unreachable here — the mechanism was validated at plan time;
-- should it ever arrive, classifying beats collapsing.
toVerifyBool :: EngineResult Bool -> CryptoResult
toVerifyBool (EngineOk v) = GotValid v
toVerifyBool (EngineFail (BackendAuthFailed _)) = GotValid False
toVerifyBool (EngineFail err) = GotCryptoError (toCryptoError err)

toVerifyUnit :: EngineResult () -> CryptoResult
toVerifyUnit (EngineOk ()) = GotValid True
toVerifyUnit (EngineFail (BackendAuthFailed _)) = GotValid False
toVerifyUnit (EngineFail err) = GotCryptoError (toCryptoError err)

-- | Encapsulation answers: @ciphertext || secret@ for the finisher
-- to split at the mechanism's ciphertext length.
toKemPair :: EngineResult (ByteString, ByteString) -> CryptoResult
toKemPair (EngineOk (ct, ss)) = GotBytes (ct <> ss)
toKemPair (EngineFail err) = GotCryptoError (toCryptoError err)

-- | Backend failures onto crypto errors: total and
-- category-preserving. Each backend error maps to its mirror
-- crypto error with fields intact; a bytes-shaped authentication
-- failure stays 'CryptoAuthFailed'. Every case keeps the code its
-- collapse produced.
toCryptoError :: BackendError -> CryptoError
toCryptoError err = case err of
  BackendUnsupported o w -> CryptoUnsupported o w
  BackendBadParam o w -> CryptoBadParam o w
  BackendBadKey o w -> CryptoBadKey o w
  BackendMechParamInvalid o w -> CryptoMechParamInvalid o w
  BackendAuthFailed o -> CryptoAuthFailed o
  BackendSigLenRange o -> CryptoSigLenRange o
  BackendInvalidState o w -> CryptoInvalidState o w
  BackendNative o c w -> CryptoNative o c w
  BackendResourceGone o r -> CryptoResourceGone o r

-- | Backend errors onto core failures: the exact
-- constructor-for-constructor mirror. Total both ways with
-- 'fromCoreFailure' (see the round-trip pins).
toCoreFailure :: BackendError -> O.BackendFailure
toCoreFailure err = case err of
  BackendUnsupported o w -> O.BackendUnsupported o w
  BackendBadParam o w -> O.BackendBadParam o w
  BackendBadKey o w -> O.BackendBadKey o w
  BackendMechParamInvalid o w -> O.BackendMechParamInvalid o w
  BackendAuthFailed o -> O.BackendAuthFailed o
  BackendSigLenRange o -> O.BackendSigLenRange o
  BackendInvalidState o w -> O.BackendInvalidState o w
  BackendNative o c w -> O.BackendNative o c w
  BackendResourceGone o r -> O.BackendResourceGone o r

-- | Core failures back onto backend errors: the exact inverse of
-- 'toCoreFailure' over all nine constructors.
fromCoreFailure :: O.BackendFailure -> BackendError
fromCoreFailure f = case f of
  O.BackendUnsupported o w -> BackendUnsupported o w
  O.BackendBadParam o w -> BackendBadParam o w
  O.BackendBadKey o w -> BackendBadKey o w
  O.BackendMechParamInvalid o w -> BackendMechParamInvalid o w
  O.BackendAuthFailed o -> BackendAuthFailed o
  O.BackendSigLenRange o -> BackendSigLenRange o
  O.BackendInvalidState o w -> BackendInvalidState o w
  O.BackendNative o c w -> BackendNative o c w
  O.BackendResourceGone o r -> BackendResourceGone o r

-- | Crypto failures back onto core failures: the exact
-- inverse of 'toCryptoError' on the nine shared categories. The
-- unclassified 'CryptoFailed' bucket has no backend counterpart and
-- lands on a native failure (pinned one-way mapping, code unchanged).
cryptoToCore :: CryptoError -> O.BackendFailure
cryptoToCore err = case err of
  CryptoUnsupported o w -> O.BackendUnsupported o w
  CryptoBadParam o w -> O.BackendBadParam o w
  CryptoBadKey o w -> O.BackendBadKey o w
  CryptoMechParamInvalid o w -> O.BackendMechParamInvalid o w
  CryptoAuthFailed o -> O.BackendAuthFailed o
  CryptoSigLenRange o -> O.BackendSigLenRange o
  CryptoInvalidState o w -> O.BackendInvalidState o w
  CryptoNative o c w -> O.BackendNative o c w
  CryptoResourceGone o r -> O.BackendResourceGone o r
  CryptoFailed s -> O.BackendNative "driver" (-1) s

-- | Adapt a crypto answer onto the 'finishEffect' contract. Verdicts
-- keep their shape ('O.EngineOkValid'); failures keep their
-- taxonomy one-to-one through 'cryptoToCore', so an
-- authentication failure arrives typed instead of collapsing onto
-- native. This is the ONLY collapse point — the unit feed
-- shape ('GotUnit') lands here as empty bytes, byte-identical to
-- the pre-change collapse.
encodeResult :: CryptoResult -> O.EngineResult
encodeResult (GotBytes b) = O.EngineOkBytes b
encodeResult (GotValid v) = O.EngineOkValid v
encodeResult (GotResource rid) = O.EngineOkResource rid
encodeResult GotUnit = O.EngineOkBytes BS.empty
encodeResult (GotCryptoError err) = O.EngineFail (cryptoToCore err)

-- | Drain committed releases through the backend: every
-- 'O.ReleaseEngineResource' runs 'releaseResource', so a commit
-- that frees a multipart context cannot leak it. The fold over an
-- empty list is a no-op for the release-free commits.
drainReleases :: CryptoBackend b => BackendEnv b -> [O.ResourceRelease] -> IO ()
drainReleases be = mapM_ drain
  where
    drain (O.ReleaseEngineResource rid) = releaseResource be rid
