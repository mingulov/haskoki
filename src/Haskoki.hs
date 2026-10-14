{- | Top-level entry point for the @haskoki@ soft token.

This scaffold re-exports the public surface. See
@docs\/demo-walkthrough.md@ (operator path) and
@docs\/operations-notes.md@ (decisions) for the architecture: a pure
internal core, an effectful runtime, and a small generated C facade.

The @hsp11@ strings in design-bundle-derived example files are
inherited verbatim (see @tests\/ops\/fixtures\/PROVENANCE.md@);
the package ships as @haskoki@.

The @Haskoki.PKCS11@ names re-exported below are a deprecated
compatibility scaffold (each answers @CKR_GENERAL_ERROR@); the
serving path is the versioned C function tables, and the Haskell
path is the pure request\/outcome contracts. See @Haskoki.PKCS11@.
-}
module Haskoki
  ( -- * Core types
    module Haskoki.Types
    -- * PKCS#11 facade
  , module Haskoki.PKCS11
  ) where

import Haskoki.PKCS11
import Haskoki.Types
