{- | PKCS#11 facade stub.

Placeholder for the public entry surface. The real provider exposes the
versioned C function tables through a small generated facade (@cbits@ +
@ffi\/@); Haskell callers go through the pure request\/outcome
contracts (@planCall@, @finishEffect@, @publishDelta@).

Every function here is currently unimplemented and returns
'CKR_GENERAL_ERROR'. An untested stub never counts as behavior.
-}
module Haskoki.PKCS11
  ( initialize
  , finalize
  , getInfo
  , getSlotList
  ) where

import Haskoki.Types (Outcome (..), ReturnCode (..), SlotId)

-- | Initialize the provider. Stub: always 'CKR_GENERAL_ERROR'.
initialize :: IO (Outcome ())
initialize = pure (OutcomeErr CKR_GENERAL_ERROR)

-- | End a provider interval. Note: finalization must never tear down the
-- GHC runtime (@hs_exit@); see @03-abi-and-runtime.md@. Stub.
finalize :: IO (Outcome ())
finalize = pure (OutcomeErr CKR_GENERAL_ERROR)

-- | Provider metadata. Stub.
getInfo :: IO (Outcome String)
getInfo = pure (OutcomeErr CKR_GENERAL_ERROR)

-- | List visible slots. Stub.
getSlotList :: IO (Outcome [SlotId])
getSlotList = pure (OutcomeErr CKR_GENERAL_ERROR)
