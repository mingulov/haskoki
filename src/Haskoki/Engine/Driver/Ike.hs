{- | Driver IKE dispatch and execution.
-}
{-# LANGUAGE OverloadedStrings #-}
module Haskoki.Engine.Driver.Ike
  ( IkeExec (..)
  , ikeParamsFor
  , isIkeMech
  , ikeNeedsAux
  , runIke
  ) where
import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import Control.Monad (guard)
import Data.Word (Word8)

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
import Haskoki.Recipe.Ike
  ( IkeKind (..)
  , IkeRecipe (..)
  , decodeIkeParams
  , ikeParamsValid
  , ikeRecipeFor
  , maxIkeOutput
  )
import Haskoki.Recipe.Kdf (kdfCodeDigest)
import Haskoki.Registry (MechanismId (..))


-- | One IKE execution: the kind, the PRF digest, and the
-- frame inputs (the aux keygxy material resolves separately
-- through 'fxKey2'; the runner interprets flags, key number,
-- and blobs per kind).
data IkeExec = IkeExec
  { ieKind :: !IkeKind
  , ieAlg :: !DigestAlg
  , ieFlags :: !Word8
  , ieKeyNum :: !Word8
  , ieBlob1 :: !ByteString
  , ieBlob2 :: !ByteString
  } deriving (Eq, Show)

-- | IKE dispatch: the covered (mechanism, params) pair to
-- its execution tuple (pinned by RecipeIkeSpec).
-- 'Nothing' means uncovered (non-IKE mechanism), malformed
-- parameters, or the reserved unmapped-PRF code (the planner
-- denies that one; the driver never sees it).
ikeParamsFor :: MechanismId -> ByteString -> Maybe IkeExec
ikeParamsFor mech params = do
  r <- ikeRecipeFor mech
  guard (ikeParamsValid r params)
  (prf, flags, keynum, _aux, b1, b2) <- decodeIkeParams params
  guard (prf /= 0)
  stem <- kdfCodeDigest (fromIntegral prf)
  alg <- rsaDigest stem
  pure (IkeExec (ikKind r) alg flags keynum b1 b2)

-- | An IKE mechanism (drives the parameter-refusal
-- branches).
isIkeMech :: MechanismId -> Bool
isIkeMech mech = case ikeRecipeFor mech of
  Just _ -> True
  Nothing -> False

-- | The IKE rows needing an aux key: IKEv1-PRF takes the
-- keygxy input (the planner resolves it onto 'fxKey2'); the
-- extended row takes it optionally, the others never.
ikeNeedsAux :: IkeExec -> Bool
ikeNeedsAux ex = ieKind ex == Ike1Prf

-- | IKE effects over the HMAC route: prf+ iteration,
-- the single-shot PRF in either role order, the IKEv1
-- single shot over the aux keygxy input, and the
-- counter-less extended iteration (truncating the base
-- when neither aux nor extra is present — the oracle
-- reference rule). Off-range lengths are 'CryptoFailed';
-- non-bytes keys are 'CryptoBadKey'.
runIke :: CryptoBackend b => BackendEnv b -> IkeExec -> KeyMaterial -> Maybe KeyMaterial -> Int -> IO CryptoResult
runIke env ex key mAux outLen = case key of
  KeyBytes kb -> case auxOf mAux of
    Left err -> pure (GotCryptoError err)
    Right auxB -> case ieKind ex of
      Ike2PrfPlus
        | outLen >= 1
        , Just h <- digestOutLen (ieAlg ex)
        , (outLen + h - 1) `div` h <= 255 -> do
            r <- ikePrfPlusExpand env (ieAlg ex) kb (ieBlob1 ex) outLen
            pure $ case r of
              EngineFail err -> GotCryptoError (toCryptoError err)
              EngineOk d -> GotBytes (BS.take outLen d)
        | otherwise -> pure (GotCryptoError (CryptoFailed
            "driver: IKE prf+ length out of range"))
      IkePrf
        | outLen >= 1, Just h <- digestOutLen (ieAlg ex), outLen <= h -> do
            let (kk, msg) = if ieFlags ex == 1
                  then (ieBlob1 ex <> ieBlob2 ex, kb)
                  else (kb, ieBlob1 ex <> ieBlob2 ex)
            r <- macSign env (MacHMAC (ieAlg ex) Nothing) (KeyBytes kk) msg
            pure $ case r of
              EngineFail err -> GotCryptoError (toCryptoError err)
              EngineOk d -> GotBytes (BS.take outLen d)
        | otherwise -> pure (GotCryptoError (CryptoFailed
            "driver: IKE PRF length out of range"))
      Ike1Prf -> case auxB of
        -- Unreachable post-dispatch (IKEv1-PRF needs aux);
        -- typed, never a crash.
        Nothing -> pure (GotCryptoError (CryptoBadKey "driver"
          "IKEv1-PRF derive binds no keygxy key"))
        Just gx
          | outLen >= 1, Just h <- digestOutLen (ieAlg ex), outLen <= h -> do
              let msg = gx <> ieBlob1 ex <> ieBlob2 ex <> BS.singleton (ieKeyNum ex)
              r <- macSign env (MacHMAC (ieAlg ex) Nothing) (KeyBytes kb) msg
              pure $ case r of
                EngineFail err -> GotCryptoError (toCryptoError err)
                EngineOk d -> GotBytes (BS.take outLen d)
          | otherwise -> pure (GotCryptoError (CryptoFailed
              "driver: IKEv1-PRF length out of range"))
      Ike1Extended
        | outLen >= 1 && outLen <= maxIkeOutput
        , extTruncOk auxB (ieBlob1 ex) (BS.length kb) outLen -> do
            r <- ikeExtExpand env (ieAlg ex) kb auxB (ieBlob1 ex) outLen
            pure $ case r of
              EngineFail err -> GotCryptoError (toCryptoError err)
              EngineOk d -> GotBytes (BS.take outLen d)
        | otherwise -> pure (GotCryptoError (CryptoFailed
            "driver: IKE extended length out of range"))
  _ -> pure (GotCryptoError (CryptoBadKey "driver"
    "key derivation needs raw secret bytes"))
  where
    auxOf Nothing
      | ikeNeedsAux ex = Left (CryptoBadKey "driver" "IKE derive binds no aux key")
      | otherwise = Right Nothing
    auxOf (Just (KeyBytes ab)) = Right (Just ab)
    auxOf (Just _) = Left (CryptoBadKey "driver" "IKE aux key is not byte material")
    -- | The truncation rule admits the request: without aux
    -- input the output must fit the base.
    extTruncOk Nothing extra kbLen wantLen = not (BS.null extra) || wantLen <= kbLen
    extTruncOk (Just _) _ _ _ = True

-- | IKEv2 prf+ (RFC 4306 §2.8): @T(i) = PRF(K, T(i-1) |
-- seed | i)@ with @T(0)@ empty, the counter a single byte
-- (never wraps: past 255 blocks refuses).
ikePrfPlusExpand :: CryptoBackend b => BackendEnv b -> DigestAlg -> ByteString -> ByteString -> Int -> IO (EngineResult ByteString)
ikePrfPlusExpand env alg kb seed outLen = case digestOutLen alg of
  Nothing -> pure (EngineFail (BackendBadParam "ikePrfPlusExpand"
    "IKE prf+ needs a fixed-width HMAC"))
  Just h
    | outLen < 1 -> pure (EngineFail (BackendBadParam "ikePrfPlusExpand"
        "IKE prf+ length out of range"))
    | n > 255 -> pure (EngineFail (BackendBadParam "ikePrfPlusExpand"
        "IKE prf+ length exceeds the counter capacity"))
    | otherwise -> go 1 BS.empty []
    where
      n = (outLen + h - 1) `div` h
      spec = MacHMAC alg Nothing
      key = KeyBytes kb
      go i prev acc
        | i > n = pure (EngineOk (BS.take outLen (BS.concat (reverse acc))))
        | otherwise = do
            t <- macSign env spec key (prev <> seed <> BS.singleton (fromIntegral i))
            case t of
              EngineFail err -> pure (EngineFail err)
              EngineOk blk -> go (i + 1) blk (blk : acc)

-- | IKEv1 extended expansion: @T(i) = PRF(K, T(i-1) |
-- keygxy | extra)@ with the first message the bare seed
-- (@\\x00@ when both inputs are empty); with neither
-- input and a short output, the base truncates (the
-- oracle reference rule).
ikeExtExpand :: CryptoBackend b => BackendEnv b -> DigestAlg -> ByteString -> Maybe ByteString -> ByteString -> Int -> IO (EngineResult ByteString)
ikeExtExpand env alg kb mGx extra outLen
  | outLen < 1 = pure (EngineFail (BackendBadParam "ikeExtExpand"
      "IKE extended length out of range"))
  | otherwise = case (mGx, BS.null extra) of
      (Nothing, True)
        | outLen <= BS.length kb -> pure (EngineOk (BS.take outLen kb))
        | otherwise -> pure (EngineFail (BackendBadParam "ikeExtExpand"
            "IKE extended truncation exceeds the base length"))
      _ -> case digestOutLen alg of
        Nothing -> pure (EngineFail (BackendBadParam "ikeExtExpand"
          "IKE extended needs a fixed-width HMAC"))
        Just h ->
          let seed = maybe BS.empty id mGx <> extra
              first = if BS.null seed then BS.singleton 0 else seed
              n = (outLen + h - 1) `div` h
              spec = MacHMAC alg Nothing
              key = KeyBytes kb
              go 0 _ acc = pure (EngineOk (BS.take outLen (BS.concat (reverse acc))))
              go k prev acc = do
                let msg = if k == n then first else prev <> seed
                t <- macSign env spec key msg
                case t of
                  EngineFail err -> pure (EngineFail err)
                  EngineOk blk -> go (k - 1) blk (blk : acc)
          in go n first []
