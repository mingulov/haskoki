module Main (main) where

-- Same facade import as probe-main, but resolved through the
-- haskoki-internal sublibrary: proves the named library is not
-- publicly dependable out of tree either.
import Haskoki.PKCS11 (finalize, getInfo, getSlotList, initialize)

main :: IO ()
main = do
  _ <- initialize
  _ <- getInfo
  _ <- getSlotList
  _ <- finalize
  putStrLn "facade reachable (this build must fail post-decision)"
