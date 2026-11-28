{- | Detached limits.
-}
module Haskoki.Runtime.Storage.Limits
  ( StoreLimits
  , defaultLimits
  , limMaxObjects
  , limMaxTotalBytes
  , limMaxRecordBytes
  , limMaxJobs
  ) where


-- ---------------------------------------------------------------------------
-- Limits
-- ---------------------------------------------------------------------------

-- | Pre-commit bounds (enforced; the opener has always
-- carried them, so its shape is stable).
data StoreLimits = StoreLimits
  { limMaxObjects :: !Int
  , limMaxTotalBytes :: !Int
  , limMaxRecordBytes :: !Int
  , limMaxJobs :: !Int
  } deriving (Eq, Show)

-- | Demonstration bounds: 4096 objects, 16 MiB total, 256 KiB per
-- record, 256 detached jobs.
defaultLimits :: StoreLimits
defaultLimits = StoreLimits
  { limMaxObjects = 4096
  , limMaxTotalBytes = 16777216
  , limMaxRecordBytes = 262144
  , limMaxJobs = 256
  }
