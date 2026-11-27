{- | Driver SP 800-108 dispatch and execution.
-}
{-# LANGUAGE OverloadedStrings #-}
module Haskoki.Engine.Driver.Sp800
  ( Sp800Exec (..)
  , sp800ParamsFor
  , isSp800Mech
  , runSp800
  ) where
import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import Control.Monad (guard)

import Haskoki.Engine.Backend
  ( BackendEnv
  , BackendError (..)
  , CryptoBackend (..)
  , DigestAlg (..)
  , digestOutLen
  , EngineResult (..)
  , KeyMaterial (..)
  , MacSpec (..)
  )
import Haskoki.Engine.Driver.Common (rsaDigest)
import Haskoki.Engine.Driver.Result (toCryptoError)
import Haskoki.Operation.Effect (CryptoError (..), CryptoResult (..))
import Haskoki.Recipe.Kdf (kdfCodeDigest)
import Haskoki.Recipe.Sp800108
  ( Sp800Mode (..)
  , Sp800Params (..)
  , Sp800Recipe (..)
  , decodeSp800Params
  , maxSp800Total
  , sp800ParamsValid
  , sp800RecipeFor
  )
import Haskoki.Registry (MechanismId (..))


-- | SP 800-108 execution tuple: the mode, the HMAC digest plus
-- its width, the counter and length widths, the IV, and the
-- flattened fixed input.
data Sp800Exec = Sp800Exec
  { seMode :: !Sp800Mode
  , seAlg :: !DigestAlg
  , seHashLen :: !Int
  , seCounterBits :: !Int
  , seLengthBits :: !Int
  , seIv :: !ByteString
  , seFixed :: !ByteString
  } deriving (Eq, Show)

-- | SP 800-108 dispatch: the covered (mechanism, params) pair to
-- its execution tuple (pinned by RecipeSp800108Spec).
-- 'Nothing' means uncovered (non-SP-800-108 mechanism) or
-- malformed parameters.
sp800ParamsFor :: MechanismId -> ByteString -> Maybe Sp800Exec
sp800ParamsFor mech params = do
  r <- sp800RecipeFor mech
  guard (sp800ParamsValid r params)
  p <- decodeSp800Params params
  stem <- kdfCodeDigest (fromIntegral (spPrf p))
  alg <- rsaDigest stem
  hashLen <- digestOutLen alg
  pure (Sp800Exec (rsMode r) alg hashLen
    (spCounterBits p) (spLengthBits p) (spIv p) (spFixed p))

-- | An SP 800-108 mechanism (drives the parameter-refusal
-- branches).
isSp800Mech :: MechanismId -> Bool
isSp800Mech mech = case sp800RecipeFor mech of
  Just _ -> True
  Nothing -> False

-- | SP 800-108 effects: the mode expansion over the HMAC
-- route, truncated to the planned length (capped by
-- 'maxSp800Total' with the L-fit check — the planner caps
-- honestly, so off-range fires only for hand-built
-- effects). A non-bytes key is 'CryptoBadKey'.
runSp800 :: CryptoBackend b => BackendEnv b -> Sp800Exec -> KeyMaterial -> Int -> IO CryptoResult
runSp800 env ex key outLen = case key of
  KeyBytes kb
    | outLen >= 1 && outLen <= maxSp800Total
    , toInteger outLen * 8 < 2 ^ seLengthBits ex
    , seMode ex /= Sp800Counter
      || toInteger ((outLen + seHashLen ex - 1) `div` seHashLen ex)
         <= 2 ^ seCounterBits ex - 1 -> do
        r <- sp800Expand env ex kb outLen
        pure $ case r of
          EngineFail err -> GotCryptoError (toCryptoError err)
          EngineOk d -> GotBytes (BS.take outLen d)
    | otherwise -> pure (GotCryptoError (CryptoFailed
        "driver: SP800-108 length out of range or widths do not fit"))
  _ -> pure (GotCryptoError (CryptoBadKey "driver"
    "key derivation needs raw secret bytes"))

-- | SP 800-108 expansion (NIST SP 800-108 §5.1\/5.2\/5.3)
-- over the HMAC route: counter @K(i) = PRF(KI, [i]_r ||
-- fixed || [L]_l)@, feedback @K(i) = PRF(KI, K(i-1) ||
-- fixed || [L]_l)@ with @K(0) = IV@, double-pipeline @A(i)
-- = PRF(KI, A(i-1))@, @K(i) = PRF(KI, A(i) || fixed ||
-- [L]_l)@ with @A(0) = fixed || [L]_l@. L is the derived
-- bit-length by construction; counter mode refuses past
-- @2^r - 1@ iterations (never wraps).
sp800Expand :: CryptoBackend b => BackendEnv b -> Sp800Exec -> ByteString -> Int -> IO (EngineResult ByteString)
sp800Expand env ex kb outLen
  | seMode ex == Sp800Counter
  , toInteger n > 2 ^ seCounterBits ex - 1 = pure (EngineFail (BackendBadParam "sp800Expand"
      "iteration count exceeds the counter width"))
  | otherwise = case seMode ex of
      Sp800Counter -> goCounter 1 []
      Sp800Feedback -> goFeedback n (seIv ex) []
      Sp800DoublePipeline -> goPipeline n suffix []
  where
    spec = MacHMAC (seAlg ex) Nothing
    key = KeyBytes kb
    h = seHashLen ex
    n = (outLen + h - 1) `div` h
    suffix = seFixed ex <> encodeW (seLengthBits ex `div` 8) (outLen * 8)
    rBytes = seCounterBits ex `div` 8
    encodeW w v = BS.pack [fromIntegral ((v `div` 256 ^ i) `mod` 256) | i <- [w - 1, w - 2 .. 0]]
    goCounter i acc
      | i > n = pure (EngineOk (BS.take outLen (BS.concat (reverse acc))))
      | otherwise = do
          t <- macSign env spec key (encodeW rBytes i <> suffix)
          case t of
            EngineFail err -> pure (EngineFail err)
            EngineOk blk -> goCounter (i + 1) (blk : acc)
    goFeedback 0 _ acc = pure (EngineOk (BS.take outLen (BS.concat (reverse acc))))
    goFeedback k prev acc = do
      t <- macSign env spec key (prev <> suffix)
      case t of
        EngineFail err -> pure (EngineFail err)
        EngineOk blk -> goFeedback (k - 1) blk (blk : acc)
    goPipeline 0 _ acc = pure (EngineOk (BS.take outLen (BS.concat (reverse acc))))
    goPipeline k aPrev acc = do
      aNext <- macSign env spec key aPrev
      case aNext of
        EngineFail err -> pure (EngineFail err)
        EngineOk a -> do
          p <- macSign env spec key (a <> suffix)
          case p of
            EngineFail err -> pure (EngineFail err)
            EngineOk blk -> goPipeline (k - 1) a (blk : acc)
