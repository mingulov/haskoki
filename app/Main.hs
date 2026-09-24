{- | @haskoki-ctl@ executable: thin wrapper over 'Haskoki.Ctl'.
-}
module Main (main) where

import System.Environment (getArgs)
import System.Exit (ExitCode (..), exitWith)
import System.IO (hPutStr, stderr)

import Haskoki.Ctl (CtlExit (..), runCtl)

main :: IO ()
main = do
  args <- getArgs
  CtlExit code out err <- runCtl args
  putStr out
  hPutStr stderr err
  exitWith (if code == 0 then ExitSuccess else ExitFailure code)
