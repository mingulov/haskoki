{- | FFI hygiene structural pins.

'caseNoUnsafePerformIO': provider liveness is C-owned surface
state (the former Haskell global 'gProviderLive' built on
'unsafePerformIO' is gone with its import). Tree-wide walk over
@src/@, @ffi/@, @tests/@ (and @app/@ when present): any
'unsafePerformIO' line that is not a legitimate
'unsafeUseAsCString' use fails with file:line evidence.

Behavior pins live in C (@tests/c/loader.c@, case @T00D@
plus the routed @A03@ cycles): the direct symbols are C ABI with
no Haskell callers, so Haskell cannot pin their behavior — the
loader asserts the full return-code matrix and the proof diffs
the two logs byte-identically.
-}
module FfiHygieneSpec (spec) where

import Control.Monad (forM)
import Data.List (isInfixOf)
import System.Directory (doesDirectoryExist, listDirectory)
import System.FilePath ((</>), takeExtension)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertFailure, testCase)

spec :: TestTree
spec = testGroup "FFI hygiene"
  [ testCase "no unsafePerformIO globals" caseNoUnsafePerformIO
  ]

caseNoUnsafePerformIO :: IO ()
caseNoUnsafePerformIO = do
  -- This probe names 'unsafePerformIO' throughout, so it exempts its
  -- own file (the exemption is this line, auditable here).
  files <- filter (/= "tests/model/FfiHygieneSpec.hs")
    . concat <$> mapM walkHs ["src", "ffi", "tests", "app"]
  hits <- fmap concat $ forM files $ \fp -> do
    body <- readFile fp
    pure
      [ (fp, n)
      | (n, ln) <- zip [1 :: Int ..] (lines body)
      , "unsafePerformIO" `isInfixOf` ln
      , not ("unsafeUseAsCString" `isInfixOf` ln)
      ]
  case hits of
    [] -> pure ()
    _ -> assertFailure ("unsafePerformIO uses: " ++ show hits)

-- | All @.hs@ files under a root (@[]@ when the root is absent).
walkHs :: FilePath -> IO [FilePath]
walkHs root = do
  ok <- doesDirectoryExist root
  if not ok then pure [] else go root
  where
    go dir = do
      ents <- listDirectory dir
      fmap concat $ forM ents $ \e -> do
        let p = dir </> e
        isDir <- doesDirectoryExist p
        if isDir then go p else pure [p | takeExtension p == ".hs"]
