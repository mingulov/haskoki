{- | Driver HOTP dispatch and execution.
-}
{-# LANGUAGE OverloadedStrings #-}
module Haskoki.Engine.Driver.Hotp
  ( hotpParamsFor
  , isHotpMech
  , runHotpSign
  , runHotpVerify
  ) where
import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import Data.Maybe (isJust)
import Data.Word (Word64)

import Haskoki.Engine.Backend
  ( BackendEnv
  , CryptoBackend (..)
  , DigestAlg (..)
  , EngineResult (..)
  , KeyMaterial (..)
  , MacSpec (..)
  )
import Haskoki.Engine.Driver.Common (driverCtEq)
import Haskoki.Engine.Driver.Result (toCryptoError)
import Haskoki.Operation.Effect (CryptoError (..), CryptoResult (..))
import Haskoki.Recipe.Otp
  ( decodeHotpParams
  , encodeHotpCounter
  , hotpRecipeFor
  , hotpTruncate
  )
import Haskoki.Registry (MechanismId (..))


-- | HOTP dispatch: a covered mechanism with valid @hotp-params\/1@
-- parameters to (counter, digits) (pinned against
-- 'Haskoki.Recipe.Otp' by RecipeOtpSpec). 'Nothing' means uncovered
-- (non-HOTP mechanism) or malformed parameters.
hotpParamsFor :: MechanismId -> ByteString -> Maybe (Word64, Int)
hotpParamsFor mech params = do
  _ <- hotpRecipeFor mech
  decodeHotpParams params

-- | An HOTP mechanism regardless of parameter validity (drives the
-- parameter-refusal branch: malformed HOTP params are
-- 'CryptoFailed', never 'CryptoUnsupported').
isHotpMech :: MechanismId -> Bool
isHotpMech mech = isJust (hotpRecipeFor mech)

-- | HOTP sign effects: HMAC-SHA1 over the counter, then RFC
-- 4226 dynamic truncation to ASCII digits. The input is always
-- empty (HOTP signs the counter only); anything else is a
-- 'CryptoFailed' parameter refusal, never silently signed.
runHotpSign :: CryptoBackend b => BackendEnv b -> MechanismId -> ByteString -> KeyMaterial -> ByteString -> IO CryptoResult
runHotpSign env mech params key input = case key of
  KeyBytes _ -> case hotpParamsFor mech params of
    Just (counter, digits)
      | BS.null input -> do
          r <- macSign env (MacHMAC D_SHA1 Nothing) key (encodeHotpCounter counter)
          pure $ case r of
            EngineFail err -> GotCryptoError (toCryptoError err)
            EngineOk mac -> case hotpTruncate mac digits of
              Just code -> GotBytes code
              Nothing -> shortMac
      | otherwise -> pure (GotCryptoError (CryptoFailed
          "driver: HOTP signs the counter only: input must be empty"))
    _ -> pure (GotCryptoError (CryptoFailed
        "driver: HOTP takes hotp-params/1 (counter, 6-8 digits)"))
  _ -> pure (GotCryptoError (CryptoBadKey "driver"
    "HOTP needs raw symmetric key bytes"))

-- | HOTP verify effects: recompute, truncate, constant-time
-- compare. A mismatch is the 'False' verdict, never a
-- malfunction.
runHotpVerify :: CryptoBackend b => BackendEnv b -> MechanismId -> ByteString -> KeyMaterial -> ByteString -> ByteString -> IO CryptoResult
runHotpVerify env mech params key input want = case key of
  KeyBytes _ -> case hotpParamsFor mech params of
    Just (counter, digits)
      | BS.null input -> do
          r <- macSign env (MacHMAC D_SHA1 Nothing) key (encodeHotpCounter counter)
          pure $ case r of
            EngineFail err -> GotCryptoError (toCryptoError err)
            EngineOk mac -> case hotpTruncate mac digits of
              Just code
                | driverCtEq code want -> GotValid True
                | otherwise -> GotValid False
              Nothing -> shortMac
      | otherwise -> pure (GotCryptoError (CryptoFailed
          "driver: HOTP signs the counter only: input must be empty"))
    _ -> pure (GotCryptoError (CryptoFailed
        "driver: HOTP takes hotp-params/1 (counter, 6-8 digits)"))
  _ -> pure (GotCryptoError (CryptoBadKey "driver"
    "HOTP needs raw symmetric key bytes"))

-- | A backend MAC shorter than HMAC-SHA1's 20 bytes breaks the
-- backend contract; the truncation cannot run. Both shipped
-- backends return full-width MACs, so this arm is defensive.
shortMac :: CryptoResult
shortMac = GotCryptoError (CryptoFailed
  "driver: HOTP backend MAC too short to truncate")
