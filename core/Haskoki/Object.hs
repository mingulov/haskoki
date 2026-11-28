{- | Object lifecycle planning and the external-handle map (pure).

Stable internal 'ObjectId's, caller-visible 'ExternalHandle's, and
generation-guarded bindings between them. Handles are never reused:
destroy stale-marks the binding (generation bump, binding retained)
and resolution faults deterministically forever after. Discovery
(find) mints fresh bindings for objects that lack a current one.

Request arguments ride the 'Request.reqInput' 'ByteString' via
tiny documented codecs ('encodeTemplate'/'parseTemplate',
'encodeWanted'/'parseWanted'); real decode lives in the FFI layer.
-}
module Haskoki.Object
  ( TemplateError (..)
  , validateTemplate
  , TemplateRule (..)
  , RuleDeny (..)
  , findRule
  , checkRules
  , encodeTemplate
  , parseTemplate
  , maxTemplateEntries
  , encodeWanted
  , parseWanted
  , encodeHandle
  , decodeHandle
  , resolveHandle
  , isStorageObject
  , isKeyClass
  , keyDefaults
  , effectiveAttrs
  , effectiveSensitive
  , effectiveExtractable
  , flagOr
  , objectToken
  , objectPrivate
  , mergedIsToken
  , mergedIsPrivate
  , objectCopyable
  , objectDestroyable
  , objectVisible
  , planCreateObject
  , planDestroyObject
  , planCopyObject
  , planSetAttributes
  , planFindObjects
  , planGetAttributes
  , readView
  , viewForFind
  , isAsymmetricKeyType
  ) where


import Haskoki.Object.TemplateValidation
import Haskoki.Object.TemplateRules
import Haskoki.Object.Codecs
import Haskoki.Object.Handles
import Haskoki.Object.StorageAttrs
import Haskoki.Object.PlanCerts
import Haskoki.Object.PlanCreate
import Haskoki.Object.PlanDestroy
import Haskoki.Object.PlanMutation
import Haskoki.Object.PlanQuery
