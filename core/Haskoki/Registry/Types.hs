{- | Shared mechanism vocabulary types.

'MechanismId', 'MechanismName' and 'ParameterCodec' live here --
below both 'Haskoki.Registry' and the 'Haskoki.Recipe.*' shape-group
recipes -- so recipes can own their group's canonical codec without
an import cycle (recipes need the codec TYPE; the registry consumes
recipe codecs). 'Haskoki.Registry' re-exports this module, so all
existing imports keep working.
-}
module Haskoki.Registry.Types
  ( MechanismId (..)
  , MechanismName
  , ParameterCodec (..)
  ) where

import Data.Text (Text)
import Data.Word (Word32, Word64)

-- | Numeric mechanism identifier (@CKM_*@ value).
newtype MechanismId = MechanismId { unMechanismId :: Word64 }
  deriving (Eq, Ord, Show)

-- | Canonical or alias mechanism name (@CKM_*@ symbol).
type MechanismName = Text

-- | Named, versioned parameter codec for a mechanism's @pParameter@.
data ParameterCodec = ParameterCodec
  { codecName :: !Text
  , codecVersion :: !Word32
  } deriving (Eq, Show)
