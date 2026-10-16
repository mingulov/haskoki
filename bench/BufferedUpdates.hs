{-# LANGUAGE BangPatterns #-}
-- | Cost of buffered multipart accumulation through the production
-- bound check and append (Haskoki.Operation.appendBuffered).
--
-- Measurement, not a gate. Each payload/chunk case runs in its own OS
-- process with a 60 s in-process cap; the parent adds a 90 s hard cap.
--
-- > buffered-updates --case PAYLOAD CHUNK   one case, JSON and ROW lines
-- > buffered-updates --all OUT.json         nine cases, JSON file, table
-- > buffered-updates --self-test            controls for the harness
module Main (main) where

import Control.Exception (evaluate)
import Data.Bits (shiftR, xor)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.IORef (IORef, newIORef, readIORef, writeIORef)
import Data.List (isInfixOf, isPrefixOf)
import Text.Read (readMaybe)
import Data.Version (showVersion)
import Data.Word (Word32, Word64)
import GHC.Clock (getMonotonicTimeNSec)
import GHC.Stats (RTSStats (..), getRTSStats, getRTSStatsEnabled)
import Haskoki.Operation (appendBuffered)
import Haskoki.Operation.State
  (OpAuth (AuthNone), SlotCommon, bufferedOf, mkSlotCommon)
import Haskoki.Registry (MechanismId (..), Operation (OpDigest))
import Numeric (showFFloat, showHex)
import System.Environment (getArgs, getExecutablePath)
import System.Exit (ExitCode (..), exitWith)
import System.Info (fullCompilerVersion)
import System.IO (hPutStrLn, stderr)
import System.Process (readProcessWithExitCode)
import System.Timeout (timeout)

data CaseResult = CaseResult
  { crStatus :: String
  , crJson   :: String
  , crRow    :: String
  }

capUs :: Int
capUs = 60 * 1000000

hardCapUs :: Int
hardCapUs = 90 * 1000000

fnv1a64 :: ByteString -> Word64
fnv1a64 =
  BS.foldl' (\h b -> (h `xor` fromIntegral b) * 0x100000001b3)
            0xcbf29ce484222325

mkPayload :: Int -> ByteString
mkPayload n = fst (BS.unfoldrN n step (0x2545F491 :: Word32))
  where
    step s =
      let s' = s * 1664525 + 1013904223
      in Just (fromIntegral (s' `shiftR` 24), s')

-- The measured path: per update, copy the chunk in (as the FFI copy-in
-- does), then accumulate through the production bound check + append.
accumulate :: IORef Int -> ByteString -> Int -> Bool -> IO (Int, Word64)
accumulate progress payload chunk dropLast = go sc0 0 0
  where
    sc0 :: SlotCommon
    sc0 = mkSlotCommon (MechanismId 0x250) OpDigest Nothing BS.empty AuthNone
    total = BS.length payload
    stop = if dropLast then total - chunk else total
    go :: SlotCommon -> Int -> Int -> IO (Int, Word64)
    go !sc !off !n
      | off >= stop =
          let buf = bufferedOf sc
          in evaluate (BS.length buf, fnv1a64 buf)
      | otherwise =
          case appendBuffered sc (BS.copy (BS.take chunk (BS.drop off payload))) of
            Left _ -> ioError (userError "bound denial inside the 16 MiB bound")
            Right sc' -> do
              _ <- evaluate (BS.length (bufferedOf sc'))
              writeIORef progress (n + 1)
              go sc' (off + chunk) (n + 1)

updatesTotal :: Int -> Int -> Int
updatesTotal p c = (p + c - 1) `div` c

hex64 :: Word64 -> String
hex64 w = "fnv1a64:" ++ showHex w ""

jsonStr :: String -> String
jsonStr s = "\"" ++ s ++ "\""

mib :: Int -> String
mib b = showFFloat (Just 2) (fromIntegral b / 1048576 :: Double) ""

secs :: Word64 -> String
secs ns = showFFloat (Just 2) (fromIntegral ns / 1e9 :: Double) ""

jsonRecord
  :: Int -> Int -> Maybe Int -> String -> Word64 -> Word64
  -> Maybe Word64 -> Maybe Word64 -> Maybe Word64 -> Maybe Word64 -> Maybe Word64
  -> String -> String -> String
jsonRecord p c done status elapsed cap alloc maxLive maxMem gcsN csum expected result =
  "{" ++ concatMap id (commaSep
    [ "\"payload\":" ++ show p
    , "\"chunk\":" ++ show c
    , "\"updates_total\":" ++ show (updatesTotal p c)
    , "\"updates_completed\":" ++ maybe "null" show done
    , "\"status\":" ++ jsonStr status
    , "\"elapsed_ns\":" ++ show elapsed
    , "\"cap_ns\":" ++ show cap
    , "\"allocated_bytes\":" ++ numOrNull alloc
    , "\"max_live_bytes\":" ++ numOrNull maxLive
    , "\"max_mem_in_use_bytes\":" ++ numOrNull maxMem
    , "\"gcs\":" ++ numOrNull gcsN
    , "\"checksum\":" ++ maybe "null" (jsonStr . hex64) csum
    , "\"expected_checksum\":" ++ jsonStr expected
    , "\"result\":" ++ jsonStr result
    ]) ++ "}"
  where
    numOrNull = maybe "null" show
    commaSep [] = []
    commaSep (x : xs) = x : map (',' :) xs

rowText
  :: Int -> Int -> String -> Word64 -> Maybe Int -> Maybe Word64 -> Maybe Word64
  -> String -> String
rowText p c status elapsed done alloc maxMem result =
  "| " ++ show (p `div` 1048576) ++ " MiB | " ++ show c ++ " B | " ++ status
    ++ " | " ++ secs elapsed ++ " | "
    ++ maybe "n/a" show done ++ "/" ++ show (updatesTotal p c)
    ++ " | " ++ maybe "n/a" (mib . fromIntegral) alloc
    ++ " | " ++ maybe "n/a" (mib . fromIntegral) maxMem
    ++ " | " ++ result ++ " |"

runCase :: Int -> Int -> Int -> Bool -> IO CaseResult
runCase cap payloadLen chunk dropLast = do
  enabled <- getRTSStatsEnabled
  if not enabled
    then do
      hPutStrLn stderr "RTS stats disabled"
      exitWith (ExitFailure 2)
    else do
      let payload = mkPayload payloadLen
          expected = fnv1a64 payload
      _ <- evaluate (BS.length payload)
      _ <- evaluate expected
      progress <- newIORef (0 :: Int)
      s0 <- getRTSStats
      t0 <- getMonotonicTimeNSec
      r <- timeout cap (accumulate progress payload chunk dropLast)
      t1 <- getMonotonicTimeNSec
      s1 <- getRTSStats
      done <- readIORef progress
      let elapsed = t1 - t0
          alloc = allocated_bytes s1 - allocated_bytes s0
          gcsN = fromIntegral (gcs s1 - gcs s0) :: Word64
          maxLive = max_live_bytes s1
          maxMem = max_mem_in_use_bytes s1
          (status, csum, result) = case r of
            Just (len, cs)
              | len == payloadLen && cs == expected -> ("ok", Just cs, "match")
              | otherwise -> ("mismatch", Just cs, "mismatch")
            Nothing -> ("censored", Nothing, "censored")
          capNs = fromIntegral cap * 1000 :: Word64
          json = jsonRecord payloadLen chunk (Just done) status elapsed capNs
                   (Just alloc) (Just maxLive) (Just maxMem) (Just gcsN)
                   csum (hex64 expected) result
          row = rowText payloadLen chunk status elapsed (Just done)
                  (Just alloc) (Just maxMem) result
      pure (CaseResult status json row)

caseMain :: Int -> Int -> IO ()
caseMain p c = do
  CaseResult _ j row <- runCase capUs p c False
  putStrLn ("JSON " ++ j)
  putStrLn ("ROW " ++ row)

printable :: String -> String
printable = filter (\ch -> ch >= ' ' && ch <= '~' && ch /= '"' && ch /= '\\')

-- Status field of a child JSON line (the harness writes it unescaped).
statusOf :: String -> String
statusOf = go
  where
    key = "\"status\":\""
    go [] = "error"
    go s@(_ : rest)
      | key `isPrefixOf` s = takeWhile (/= '"') (drop (length key) s)
      | otherwise = go rest

hardCensored :: Int -> Int -> CaseResult
hardCensored p c =
  let ns = fromIntegral hardCapUs * 1000 :: Word64
      json = jsonRecord p c Nothing "censored-hard" ns ns Nothing Nothing Nothing
               Nothing Nothing "unknown" "censored"
      row = rowText p c "censored-hard" ns Nothing Nothing Nothing "censored"
  in CaseResult "censored-hard" json row

-- Same field set as every other record; unknown values are null, and the
-- failure detail (with the child exit code) is carried in "result".
errorCase :: Int -> Int -> String -> CaseResult
errorCase p c msg =
  let ns = 0 :: Word64
      json = jsonRecord p c Nothing "error" ns (fromIntegral capUs * 1000) Nothing
               Nothing Nothing Nothing Nothing "unknown"
               ("error: " ++ printable msg)
      row = rowText p c "error" ns Nothing Nothing Nothing "error"
  in CaseResult "error" json row

childCaseWith :: Int -> FilePath -> [String] -> (Int, Int) -> IO CaseResult
childCaseWith cap exe argv (p, c) = do
  r <- timeout cap
         (readProcessWithExitCode exe argv "")
  pure $ case r of
    Nothing -> hardCensored p c
    Just (code, out, err) ->
      let ls = lines out
          js = [drop 5 l | l <- ls, "JSON " `isPrefixOf` l]
          rs = [drop 4 l | l <- ls, "ROW " `isPrefixOf` l]
      in case (code, js, rs) of
           (ExitSuccess, [j], [row]) -> CaseResult (statusOf j) j row
           _ -> errorCase p c ("exit " ++ exitText code ++ ": " ++ take 400 err)

childCase :: FilePath -> (Int, Int) -> IO CaseResult
childCase exe (p, c) =
  childCaseWith hardCapUs exe ["--case", show p, show c] (p, c)

exitText :: ExitCode -> String
exitText ExitSuccess = "0"
exitText (ExitFailure n) = show n

allMain :: FilePath -> IO ()
allMain out = do
  exe <- getExecutablePath
  let cells = [(p, c) | p <- [1048576, 4194304, 16777216], c <- [1, 1024, 65536]]
  results <- mapM (childCase exe) cells
  let doc = "{\"schema\":\"haskoki-buffered-updates/1\""
        ++ ",\"path\":\"Haskoki.Operation.appendBuffered\""
        ++ ",\"ghc\":" ++ jsonStr (showVersion fullCompilerVersion)
        ++ ",\"rts\":\"-T -N1\",\"cap_s\":60,\"hard_cap_s\":90,\"cases\":["
        ++ joinWith "," (map crJson results) ++ "]}\n"
  writeFile out doc
  putStrLn "| payload | chunk | status | elapsed s | updates | alloc MiB | max mem MiB | result |"
  putStrLn "|---|---|---|---|---|---|---|---|"
  mapM_ (putStrLn . crRow) results
  let bad = [() | r <- results, crStatus r `elem` ["error", "mismatch"]]
  exitWith (if null bad then ExitSuccess else ExitFailure 1)
  where
    joinWith _ [] = ""
    joinWith sep (x : xs) = x ++ concatMap (sep ++) xs

selfTest :: IO ()
selfTest = do
  mapM_ (\c -> check 65536 c "ok" =<< runCase capUs 65536 c False) [1, 1024, 65536]
  check 1048576 1 "censored" =<< runCase 1000 1048576 1 False
  check 65536 1024 "mismatch" =<< runCase capUs 65536 1024 True
  let hc = hardCensored 1048576 1
  check 1048576 1 "censored-hard" hc
  ok <- runCase capUs 65536 1024 False
  ec <- childCase "/bin/false" (65536, 1024)
  check 65536 1024 "error" ec
  failIf "error record lacks the exit code" (not ("exit 1" `isInfixOf` crJson ec))
  failIf "error record field set differs" (keysOf (crJson ec) /= keysOf (crJson ok))
  failIf "hard-censored record field set differs" (keysOf (crJson hc) /= keysOf (crJson ok))
  -- The parent-side hard cap through the real timeout path: a child that
  -- outlives a 100 ms cap must produce the censored-hard record. The
  -- abandoned sleep exits on its own after 5 s.
  hcTimeout <- childCaseWith 100000 "/bin/sleep" ["5"] (65536, 1024)
  check 65536 1024 "censored-hard" hcTimeout
  failIf "timeout hard-cap record field set differs"
    (keysOf (crJson hcTimeout) /= keysOf (crJson ok))
  failIf "usage parse accepts a zero chunk" (parseArgs ["--case", "65536", "0"] /= Nothing)
  failIf "usage parse rejects a valid case"
    (parseArgs ["--case", "65536", "1"] /= Just (OneCase (CaseArgs 65536 1)))
  putStrLn "self-test: ok"
  where
    failIf msg bad = if bad then putStrLn ("self-test: " ++ msg) >> exitWith (ExitFailure 1) else pure ()
    -- Top-level key names of a flat one-line JSON object.
    keysOf :: String -> [String]
    keysOf = go . drop 1
      where
        go [] = []
        go ('"' : r) =
          let (k, r') = break (== '"') r
          in if take 2 (drop 1 r') == ":" then k : go (skipValue (drop 3 r')) else go (drop 1 r')
        go (_ : r) = go r
        -- skip a value up to the next top-level comma (values here are flat)
        skipValue ('"' : r) = skipStr r
        skipValue r = dropWhile (\ch -> ch /= ',' && ch /= '}') r
        skipStr ('"' : r) = r
        skipStr (_ : r) = skipStr r
        skipStr [] = []
    check p c want r
      | crStatus r == want = pure ()
      | otherwise = do
          putStrLn ("self-test: case " ++ show (p :: Int) ++ "/" ++ show (c :: Int)
                    ++ " status " ++ crStatus r ++ ", want " ++ want)
          exitWith (ExitFailure 1)

data Command = SelfTest | AllCases FilePath | OneCase CaseArgs
  deriving Eq

data CaseArgs = CaseArgs Int Int
  deriving Eq

-- Malformed argv or a non-positive payload/chunk is a usage error.
parseArgs :: [String] -> Maybe Command
parseArgs ["--self-test"] = Just SelfTest
parseArgs ["--all", out] = Just (AllCases out)
parseArgs ["--case", p, c] = do
  pn <- readMaybe p
  cn <- readMaybe c
  if pn > 0 && cn > 0 then Just (OneCase (CaseArgs pn cn)) else Nothing
parseArgs _ = Nothing

main :: IO ()
main = do
  args <- getArgs
  case parseArgs args of
    Just SelfTest -> selfTest
    Just (AllCases out) -> allMain out
    Just (OneCase (CaseArgs p c)) -> caseMain p c
    Nothing -> do
      hPutStrLn stderr "usage: buffered-updates --case PAYLOAD CHUNK | --all OUT.json | --self-test"
      exitWith (ExitFailure 2)
