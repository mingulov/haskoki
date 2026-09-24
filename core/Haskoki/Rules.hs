{- | Static planning rules input.

'Rules' carries the policy knobs 'planCall' and 'finishEffect' consult:
session admission, PIN lockout, and the mechanism registry plus
the engine capability set the operation planners intersect. Hosts
with a real backend replace 'rulesCaps' with the intersection of
the curated behavior routes and their backend's reported
capabilities; 'defaultRules' trusts the full curated registry.
-}
module Haskoki.Rules
  ( Rules (..)
  , defaultRules
  ) where

import Haskoki.Registry
  ( EngineCapabilities
  , Registry
  , behaviorRoutes
  , curatedRegistry
  , mkCapabilities
  )

-- | Planning policy: session admission bound, object/token admission
-- bounds, PIN lockout threshold, mechanism registry, and engine
-- capabilities. Every addition keeps 'defaultRules' total.
data Rules = Rules
  { rulesMaxSessions :: !Int
  , rulesMaxObjects :: !Int
  , rulesMaxTokens :: !Int
  , rulesMaxPinAttempts :: !Int
  , rulesRegistry :: !Registry
  , rulesCaps :: !EngineCapabilities
  } deriving (Eq, Show)

-- | Default rules used by tests and by hosts without configuration.
-- PIN lockout threshold defaults to 3 consecutive failures; the
-- registry is curated and every behavior-backed pair is executable.
-- The admission bounds mirror the @[limits]@ §3 defaults
-- (@objects=100000@, @slots=16@, @sessions=1024@): native instances
-- take their bounds from the resolved config instead
-- ('Haskoki.Runtime.Lifecycle.rulesFromConfig'), and equality on the
-- default config is pinned by the admission spec, so these values
-- only govern hosts without configuration.
defaultRules :: Rules
defaultRules = Rules
  { rulesMaxSessions = 1024
  , rulesMaxObjects = 100000
  , rulesMaxTokens = 16
  , rulesMaxPinAttempts = 3
  , rulesRegistry = curatedRegistry
  , rulesCaps = mkCapabilities (behaviorRoutes curatedRegistry)
  }
