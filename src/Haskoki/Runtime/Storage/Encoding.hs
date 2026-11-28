{- | Detached canonical encoding.
-}
module Haskoki.Runtime.Storage.Encoding
  ( recordFormatVersion
  , Json (..)
  , renderJson
  , renderString
  , parseJson
  , lookupField
  , asString
  , asBool
  , asObject
  , docTopKeys
  ) where

import Data.Bits ( shiftR, (.&.))
import Data.Char (chr, isHexDigit, ord)
import Data.List ( sortOn)
import Haskoki.Runtime.Storage.FixedHex

-- ---------------------------------------------------------------------------
-- Canonical encoding
-- ---------------------------------------------------------------------------

-- | The record format version. Every document carries it; anything
-- else is rejected on decode.
recordFormatVersion :: Int
recordFormatVersion = 1

-- | Lowest-level JSON value subset used by stored documents.
data Json
  = JObject ![(String, Json)]
  | JString !String
  | JBool !Bool
  | JNumber !Integer
  | JNull
  deriving (Eq, Show)

-- | Render canonical JSON: object keys ascending, minimal escapes,
-- no whitespace. Decoding ('parseJson') accepts exactly this shape
-- plus insignificant whitespace.
renderJson :: Json -> String
renderJson v = case v of
  JObject kvs -> "{" ++ join "," [renderString k ++ ":" ++ renderJson j | (k, j) <- sortOn fst kvs] ++ "}"
  JString s -> renderString s
  JBool True -> "true"
  JBool False -> "false"
  JNumber n -> show n
  JNull -> "null"
  where
    join :: String -> [String] -> String
    join _ [] = ""
    join _ [x] = x
    join sep (x : xs) = x ++ sep ++ join sep xs

-- | Render a JSON string with minimal escapes.
renderString :: String -> String
renderString s = '"' : concatMap esc s ++ "\""
  where
    esc :: Char -> String
    esc '"' = "\\\""
    esc '\\' = "\\\\"
    esc '\b' = "\\b"
    esc '\f' = "\\f"
    esc '\n' = "\\n"
    esc '\r' = "\\r"
    esc '\t' = "\\t"
    esc c
      | ord c < 0x20 = "\\u" ++ hex4 (ord c)
      | otherwise = [c]
    hex4 :: Int -> String
    hex4 n =
      [ hexDigit ((n `shiftR` 12) .&. 0xF)
      , hexDigit ((n `shiftR` 8) .&. 0xF)
      , hexDigit ((n `shiftR` 4) .&. 0xF)
      , hexDigit (n .&. 0xF)
      ]

-- | Strict subset parser: objects, strings (with @\\u@ escapes),
-- true\/false\/null, and non-negative integers. Rejects trailing
-- input, unknown escapes, and malformed numbers.
parseJson :: String -> Maybe Json
parseJson s = case parseValue (skipWs s) of
  Just (v, rest)
    | all isWs rest -> Just v
  _ -> Nothing
  where
    isWs c = c == ' ' || c == '\t' || c == '\n' || c == '\r'
    skipWs = dropWhile isWs
    parseValue :: String -> Maybe (Json, String)
    parseValue [] = Nothing
    parseValue (c : cs) = case c of
      '{' -> parseObject (skipWs cs)
      '"' -> parseStringBody cs
      't' -> parseLit "true" (JBool True) (c : cs)
      'f' -> parseLit "false" (JBool False) (c : cs)
      'n' -> parseLit "null" JNull (c : cs)
      _
        | c >= '0' && c <= '9' -> parseNumber (c : cs)
        | otherwise -> Nothing
    parseLit :: String -> Json -> String -> Maybe (Json, String)
    parseLit lit v s0 =
      let (pre, rest) = splitAt (length lit) s0
      in if pre == lit then Just (v, rest) else Nothing
    parseNumber :: String -> Maybe (Json, String)
    parseNumber s0 =
      let (digits, rest) = span (\c -> c >= '0' && c <= '9') s0
      in if null digits then Nothing else Just (JNumber (read digits), rest)
    parseObject :: String -> Maybe (Json, String)
    parseObject ('}' : rest) = Just (JObject [], rest)
    parseObject s0 = do
      ('"' : kcs) <- Just s0
      (JString k, afterK) <- parseStringBody kcs
      (':' : vcs) <- Just (skipWs afterK)
      (v, afterV) <- parseValue (skipWs vcs)
      parseMore [(k, v)] (skipWs afterV)
      where
        parseMore :: [(String, Json)] -> String -> Maybe (Json, String)
        parseMore acc (',' : rest) = do
          ('"' : kcs) <- Just (skipWs rest)
          (JString k, afterK) <- parseStringBody kcs
          (':' : vcs) <- Just (skipWs afterK)
          (v, afterV) <- parseValue (skipWs vcs)
          parseMore (acc ++ [(k, v)]) (skipWs afterV)
        parseMore acc ('}' : rest) = Just (JObject acc, rest)
        parseMore _ _ = Nothing
    -- | Parse the body of a string (after the opening quote).
    parseStringBody :: String -> Maybe (Json, String)
    parseStringBody = go []
      where
        go :: String -> String -> Maybe (Json, String)
        go _ [] = Nothing
        go acc ('"' : rest) = Just (JString (reverse acc), rest)
        go acc ('\\' : e : rest) = case e of
          '"' -> go ('"' : acc) rest
          '\\' -> go ('\\' : acc) rest
          '/' -> go ('/' : acc) rest
          'b' -> go ('\b' : acc) rest
          'f' -> go ('\f' : acc) rest
          'n' -> go ('\n' : acc) rest
          'r' -> go ('\r' : acc) rest
          't' -> go ('\t' : acc) rest
          'u' -> case rest of
            [a, b, c, d] -> hexChar a b c d >>= \n -> go (chr n : acc) []
            (a : b : c : d : more) -> hexChar a b c d >>= \n ->
              if n >= 0xD800 && n <= 0xDBFF
                then case more of
                  ('\\' : 'u' : a2 : b2 : c2 : d2 : more2) ->
                    hexChar a2 b2 c2 d2 >>= \m ->
                      if m >= 0xDC00 && m <= 0xDFFF
                        then go (chr (0x10000 + (n - 0xD800) * 0x400 + (m - 0xDC00)) : acc) more2
                        else Nothing
                  _ -> Nothing
                else go (chr n : acc) more
            _ -> Nothing
          _ -> Nothing
        go acc (c : rest) = go (c : acc) rest
        hexChar :: Char -> Char -> Char -> Char -> Maybe Int
        hexChar a b c d
          | all isHexDigit [a, b, c, d] =
              Just (hexVal a * 4096 + hexVal b * 256 + hexVal c * 16 + hexVal d)
          | otherwise = Nothing

-- | Field accessors over a decoded object body.
lookupField :: String -> [(String, Json)] -> Maybe Json
lookupField k kvs = lookup k kvs

asString :: Json -> Maybe String
asString (JString s) = Just s
asString _ = Nothing

asBool :: Json -> Maybe Bool
asBool (JBool b) = Just b
asBool _ = Nothing

asObject :: Json -> Maybe [(String, Json)]
asObject (JObject kvs) = Just kvs
asObject _ = Nothing

-- | The sorted top-level keys of a canonical document ('[]' when
-- the bytes do not parse). The storage suite pins exact key sets.
docTopKeys :: String -> [String]
docTopKeys s = case parseJson s of
  Just (JObject kvs) -> map fst kvs
  _ -> []
