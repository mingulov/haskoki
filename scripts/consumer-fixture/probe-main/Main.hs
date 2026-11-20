module Main (main) where

-- A new consumer's first import. Pre-exposure-decision this
-- resolves to four always-failing stubs; post-decision this
-- module must not compile (facade unexposed).
import Haskoki.PKCS11 (finalize, getInfo, getSlotList, initialize)

main :: IO ()
main = do
  _ <- initialize
  _ <- getInfo
  _ <- getSlotList
  _ <- finalize
  putStrLn "facade reachable (this build must fail post-decision)"
