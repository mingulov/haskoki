{- | Top-level entry point for the @haskoki@ soft token.

This scaffold re-exports the public surface. See the design package
(@ws\/docs\/incoming\/haskell-pkcs11-design@, read-only) for the full
architecture: a pure internal core, an effectful runtime, and a small
generated C facade.

The working identifier used by the design documents is @hsp11@\/
@libhsp11.so@; the public package ships as @haskoki@.
-}
module Haskoki
  ( -- * Core types
    module Haskoki.Types
    -- * PKCS#11 facade
  , module Haskoki.PKCS11
  ) where

import Haskoki.PKCS11
import Haskoki.Types
