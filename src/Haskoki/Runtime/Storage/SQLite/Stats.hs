{- | SQLite store statistics counters.

Leaf module: three atomic counters over 'StoreStats'.
-}
{-# LANGUAGE OverloadedStrings #-}
module Haskoki.Runtime.Storage.SQLite.Stats
  ( bumpCommits
  , bumpVerifyReloads
  , bumpQuarantines
  ) where

import Data.IORef (IORef, atomicModifyIORef')

import Haskoki.Runtime.Storage (StoreStats (..))

bumpCommits :: IORef StoreStats -> IO ()
bumpCommits v = atomicModifyIORef' v (\s -> (s { ssCommits = ssCommits s + 1 }, ()))

bumpVerifyReloads :: IORef StoreStats -> IO ()
bumpVerifyReloads v = atomicModifyIORef' v (\s -> (s { ssVerifyReloads = ssVerifyReloads s + 1 }, ()))

bumpQuarantines :: IORef StoreStats -> Int -> IO ()
bumpQuarantines v n = atomicModifyIORef' v (\s -> (s { ssQuarantines = ssQuarantines s + n }, ()))
