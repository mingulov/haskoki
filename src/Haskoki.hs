{- | Top-level entry point for the @haskoki@ soft token.

This scaffold re-exports the public surface. See
@docs\/demo-walkthrough.md@ (operator path) and
@docs\/operations-notes.md@ (decisions) for the architecture: a pure
internal core, an effectful runtime, and a small generated C facade.

The @hsp11@ strings in design-bundle-derived example files are
inherited verbatim (see @tests\/ops\/fixtures\/PROVENANCE.md@);
the package ships as @haskoki@.
-}
module Haskoki
  ( -- * Core types
    module Haskoki.Types
    -- * PKCS#11 facade
  , module Haskoki.PKCS11
  ) where

import Haskoki.PKCS11
import Haskoki.Types
