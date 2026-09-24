{- | The engine suite's process-wide @HASKOKI_CONFIG@ lock.

Root cause of the config-env flake: tasty runs the engine suite's
cases in parallel threads of ONE process, and @HASKOKI_CONFIG@ is
process-wide state. @FfiAcquireSpec.withConfigEnv@ publishes a
garbage path while @DetachedEngineSpec.caseFfiDetachRejoin@ (and
every other env-sensitive open below) resolves the same variable
through production @resolveOnce@ — a garbage read resolves @Left _@,
the open reports NULL, and "ctx2 opens" fails.

The rule: every test that mutates @HASKOKI_CONFIG@ (@withConfigEnv@)
and every test that opens through an env-reading production entry
(@haskokiAsyncOpen@, @haskokiAsyncOpenOn@, @haskokiCryptoOpen@;
@haskokiStdOpen@/@haskokiInstanceOpen@ have no call sites in this suite)
runs the sensitive section under @withEnvLock@. @Main@ creates one
lock per suite binary and threads it through the four specs that
need it — there is deliberately no top-level lock value (the
hygiene gate forbids that shape tree-wide). Sections are short (one
open or one dirty window), never nest, and @bracket@ releases on
async exceptions, so a killed holder cannot wedge the suite.
-}
module EnvLock (withEnvLock) where

import Control.Concurrent.MVar (MVar, withMVar)

-- | Run an env-sensitive section serialized against all other
-- env-sensitive sections in this process. Never nest: the MVar is
-- not reentrant.
withEnvLock :: MVar () -> IO a -> IO a
withEnvLock lock action = withMVar lock (\_ -> action)
