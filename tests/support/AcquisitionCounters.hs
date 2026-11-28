-- | Acquisition balance counters shared by the model and engine FFI
-- suites (opens, closes, pointer allocs and frees, registrations
-- and retirements). Closes, frees and retirements count only once
-- they return. Previously duplicated in FfiAsyncSpec and
-- FfiAcquireSpec with keep-in-sync comments; the copies were
-- identical modulo import qualification.
module AcquisitionCounters
  ( AcqCounts (..)
  , zeroCounts
  , countingAcquisitionOver
  ) where

import Data.IORef (IORef, atomicModifyIORef', newIORef, readIORef)

import Haskoki.Engine.Backend (EngineResult (..))
import Haskoki.FFI.Async (AsyncAcquisition (..), newResidueOwner)

data AcqCounts = AcqCounts
  { acStoreOpens :: !Int
  , acStoreCloses :: !Int
  , acBackendOpens :: !Int
  , acBackendCloses :: !Int
  , acCtxAllocs :: !Int
  , acCtxFrees :: !Int
  , acBoxAllocs :: !Int
  , acBoxFrees :: !Int
  , acRegistrations :: !Int
  , acRetirements :: !Int
  }
  deriving (Show)

zeroCounts :: AcqCounts
zeroCounts = AcqCounts 0 0 0 0 0 0 0 0 0 0

-- | Counting wrapper over the given steps, with a private residue
-- owner (parallel cases never share one).
countingAcquisitionOver
  :: AsyncAcquisition -> IO (AsyncAcquisition, IO AcqCounts)
countingAcquisitionOver base = do
  ref <- newIORef zeroCounts
  owner <- newResidueOwner
  let bump f = atomicModifyIORef' ref (\c -> (f c, ()))
      acq = base
        { aaOpenStore = \p -> do
            r <- aaOpenStore base p
            case r of
              Right _ -> bump (\c -> c { acStoreOpens = acStoreOpens c + 1 })
              Left _ -> pure ()
            pure r
        , aaCloseStore = \st -> do
            aaCloseStore base st
            bump (\c -> c { acStoreCloses = acStoreCloses c + 1 })
        , aaOpenBackend = do
            r <- aaOpenBackend base
            case r of
              EngineOk _ -> bump (\c -> c { acBackendOpens = acBackendOpens c + 1 })
              EngineFail _ -> pure ()
            pure r
        , aaCloseBackend = \be -> do
            aaCloseBackend base be
            bump (\c -> c { acBackendCloses = acBackendCloses c + 1 })
        , aaNewCtxPtr = \ctx -> do
            sp <- aaNewCtxPtr base ctx
            bump (\c -> c { acCtxAllocs = acCtxAllocs c + 1 })
            pure sp
        , aaFreeCtxPtr = \sp -> do
            aaFreeCtxPtr base sp
            bump (\c -> c { acCtxFrees = acCtxFrees c + 1 })
        , aaRegisterCtx = \sp table -> do
            aaRegisterCtx base sp table
            bump (\c -> c { acRegistrations = acRegistrations c + 1 })
        , aaRetireCtx = \sp -> do
            aaRetireCtx base sp
            bump (\c -> c { acRetirements = acRetirements c + 1 })
        , aaNewBoxPtr = \b -> do
            sp <- aaNewBoxPtr base b
            bump (\c -> c { acBoxAllocs = acBoxAllocs c + 1 })
            pure sp
        , aaFreeBoxPtr = \sp -> do
            aaFreeBoxPtr base sp
            bump (\c -> c { acBoxFrees = acBoxFrees c + 1 })
        , aaResidue = owner
        }
  pure (acq, readIORef ref)
