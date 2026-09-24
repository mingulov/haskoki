{- | FFI acquisition hygiene probes, behavioral half.

NULL pins for config-injected failures (bad SQLite path, refused
seating, oversize catalog), plus a non-poisoning pin (a failed
open never breaks the next open).

The async-window probe ('caseStdAsyncSlow'): async exceptions
delivered mid-open are rethrown from the inner opens (sync
failures stay NULL-identical; the @foreign export@ boundary keeps
its catch-all so no Haskell exception crosses into C), so the
mid-open kill aborts the open.

Probe shape (deliberately NOT a kill spray): the victim signals
@entered@ from inside a seconds-long open (a large memory catalog:
50k seatings, no files, no environment reads), main fires ONE
@killThread@ (the victim is provably alive and far from exit, so
the synchronous throw is always delivered mid-open and always
returns), then joins on @outcome@. Both joins carry a 10s
'System.Timeout' backstop ('assertFailure' on expiry) per the
no-wedge rule. Prior attempts wedged here with a masked-driver
kill spray: the first kill lands before the victim installs its
report handler, the victim dies silently, and the join blocks
forever (64\/64 kills returned,
@iters=0@, @outcome=Nothing@). The entered-rendezvous makes that
impossible: no kill precedes handler installation.

The structural half (hook-injected leak probes over the bracket
acquisition, plus the crypto-guard unwind probe) lives in the
engine suite (@FfiAcquireSpec@). Crypto cases live there (not
here) because this suite's @ConfigSpec@
mutates @HASKOKI_CONFIG@ process-wide and tasty runs cases in
parallel; the engine suite has no environment writers, so its
crypto probes are race-free.
-}
module FfiAsyncSpec (spec) where

import Control.Concurrent
  ( forkIO
  , killThread
  , newEmptyMVar
  , putMVar
  , takeMVar
  )
import Control.Exception (SomeException, try)
import Foreign.Ptr (nullPtr)
import Foreign.StablePtr (StablePtr, castStablePtrToPtr)
import System.Timeout (timeout)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertBool, assertFailure, testCase)

import Haskoki.FFI.Standard (StdInstance, haskokiStdClose, openStdInstance)
import Haskoki.Runtime.Config
  ( Config (..)
  , Limits (..)
  , StorageCfg (..)
  , StorageKind (..)
  , TokensCfg (..)
  , defaultConfig
  )

spec :: TestTree
spec = testGroup "FFI acquisition"
  [ testCase "std open succeeds then closes" caseStdSuccess
  , testCase "std open bad sqlite path is NULL" caseStdBadSqlite
  , testCase "std open zero slots is NULL" caseStdZeroSlots
  , testCase "std open oversize catalog is NULL" caseStdOversize
  , testCase "std failed open does not poison the next" caseStdNonPoison
  , testCase "std async kill aborts the open (none swallowed)" caseStdAsyncSlow
  ]

isNull :: StablePtr a -> Bool
isNull sp = castStablePtrToPtr sp == nullPtr

-- ---------------------------------------------------------------------------
-- Config-injected failures (pins: always NULL)
-- ---------------------------------------------------------------------------

badSqliteCfg :: Config
badSqliteCfg = defaultConfig
  { cfgStorage = (cfgStorage defaultConfig)
      { scKind = StorageSQLite
      , scPath = Just "/nonexistent-dir-xyz/store.db"
      }
  }

zeroSlotCfg :: Config
zeroSlotCfg = defaultConfig
  { cfgLimits = (cfgLimits defaultConfig) { limSlots = 0 } }

oversizeCatalogCfg :: Config
oversizeCatalogCfg = defaultConfig
  { cfgLimits = (cfgLimits defaultConfig) { limSlots = 2 }
  , cfgTokens = (cfgTokens defaultConfig)
      { tcEntries =
          [ ("tok-a", "0000", "1111")
          , ("tok-b", "0000", "2222")
          , ("tok-c", "0000", "3333")
          ]
      }
  }

caseStdSuccess :: IO ()
caseStdSuccess = do
  sp <- openStdInstance defaultConfig
  assertBool "memory open succeeds" (not (isNull sp))
  haskokiStdClose sp

caseStdBadSqlite :: IO ()
caseStdBadSqlite = do
  sp <- openStdInstance badSqliteCfg
  assertBool "bad sqlite path is NULL" (isNull sp)

caseStdZeroSlots :: IO ()
caseStdZeroSlots = do
  sp <- openStdInstance zeroSlotCfg
  assertBool "zero-slot seating refusal is NULL" (isNull sp)

caseStdOversize :: IO ()
caseStdOversize = do
  sp <- openStdInstance oversizeCatalogCfg
  assertBool "oversize catalog refusal is NULL" (isNull sp)

caseStdNonPoison :: IO ()
caseStdNonPoison = do
  bad <- openStdInstance badSqliteCfg
  assertBool "bad open is NULL" (isNull bad)
  good <- openStdInstance defaultConfig
  assertBool "next open succeeds" (not (isNull good))
  haskokiStdClose good

-- ---------------------------------------------------------------------------
-- Async injection (the kill aborts the open; previously it was
-- swallowed and the open completed)
-- ---------------------------------------------------------------------------

-- | A slow-but-successful open: 50k catalog seatings on the memory
-- backend (no files, no environment reads). The seating loop runs
-- ~100ms+, so a kill fired right after @entered@ is delivered
-- mid-open with a 100x+ margin — deterministically, without hooks.
-- The slot bound admits the whole catalog (seating must SUCCEED;
-- a refusal would fail fast and evaporate the slow window).
bigCatalogCfg :: Config
bigCatalogCfg = defaultConfig
  { cfgLimits = (cfgLimits defaultConfig) { limSlots = bigCatalogSeats + 8 }
  , cfgTokens = (cfgTokens defaultConfig)
      { tcEntries =
          [ ("tok-" ++ show i, "0000", "1111") | i <- [1 .. bigCatalogSeats] ]
      }
  }

bigCatalogSeats :: Int
bigCatalogSeats = 50000

caseStdAsyncSlow :: IO ()
caseStdAsyncSlow = do
  entered <- newEmptyMVar
  outcome <- newEmptyMVar
  victimTid <- forkIO $ do
    r <- try $ do
      putMVar entered ()
      openStdInstance bigCatalogCfg
    putMVar outcome (r :: Either SomeException (StablePtr StdInstance))
  mEntered <- timeout 10000000 (takeMVar entered)
  case mEntered of
    Nothing -> assertFailure "wedge detected: victim never entered the open"
    Just () -> pure ()
  -- Single kill: the victim is alive inside a ~100ms+ open, so this
  -- is delivered mid-open and returns (no spray, no exit race).
  killThread victimTid
  mOut <- timeout 10000000 (takeMVar outcome)
  case mOut of
    Nothing -> assertFailure "wedge detected: open never reported after kill"
    Just (Left _) -> pure ()
    Just (Right sp) -> do
      if isNull sp then pure () else haskokiStdClose sp
      assertFailure "async swallowed: kill mid-open did not abort the open"
