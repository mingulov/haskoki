{- | Config-parse properties.

Totality + determinism over hostile documents, plus universal
rejection of unknown keys. The parser is total by construction
(Either/Maybe, -Werror on incomplete patterns); these laws pin
that against future drift. Kept-over Task 12 acceptance (the
fuzz harness itself stays deferred).
-}
module ConfigProps (spec) where

import Control.Exception (SomeException, evaluate, try)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.QuickCheck
  ( Gen
  , Property
  , arbitrary
  , elements
  , forAll
  , ioProperty
  , listOf
  , oneof
  , suchThat
  , (==>)
  )

import Gen (propWith)
import Haskoki.Runtime.Config
  ( ConfigError (..)
  , configKeyCatalog
  , parseConfig
  )

spec :: Maybe Int -> Int -> TestTree
spec seedOv count = testGroup "config parse laws"
  [ propWith seedOv "parse total" 306 count pParseTotal
  , propWith seedOv "parse deterministic" 307 count pParseDeterministic
  , propWith seedOv "unknown keys refuse" 308 count pUnknownRefuse
  ]

-- | Small printable atoms (no structural characters).
genAtom :: Gen String
genAtom = listOf (elements (['a' .. 'z'] ++ ['0' .. '9'] ++ "_.-"))

-- | Values across the supported subset plus hostile shapes.
genValue :: Gen String
genValue = oneof
  [ elements ["true", "false"]
  , show <$> (arbitrary :: Gen Integer)
  , (\n -> "-" ++ show (abs n)) <$> (arbitrary :: Gen Integer)
  , pure "\"\"",
    (\s -> "\"" ++ s ++ "\"") <$> listOf (elements "ab01 _-")
  , pure "\"unterminated"
  , pure "\"bad\\qescape\""
  , pure "\"tab\\there\""
  , pure "[]"
  , (\s -> "[" ++ s ++ "]") <$> listOf (elements "ab\", ")
  , pure "[\"ragged\", 4]"
  , pure "bareword"
  , pure ""
  ]

-- | One document line: headers, assignments, comments, blanks,
-- and malformed shapes (all must parse-or-refuse, never crash).
genLine :: Gen String
genLine = oneof
  [ (\s -> "[" ++ s ++ "]") <$> oneof [genAtom, pure "", pure "a[b", pure " a "]
  , elements ["[", "]", "[]", "[a", "a]", "="]
  , (\k v -> k ++ " = " ++ v) <$> genAtom <*> genValue
  , (\k -> k ++ " =") <$> genAtom
  , (\v -> "= " ++ v) <$> genValue
  , (\c -> "#" ++ c) <$> listOf (elements "ab #01_-")
  , elements ["", " ", "   "]
  , listOf arbitrary
  ]

genDoc :: Gen String
genDoc = unlines <$> listOf genLine

-- | Full evaluation must never throw: any document parses or
-- refuses. The assertion IS the absence of an exception.
pParseTotal :: Property
pParseTotal = forAll genDoc $ \doc -> ioProperty $ do
  r <- try (evaluate (length (show (parseConfig doc))))
    :: IO (Either SomeException Int)
  pure (case r of
    Left _ -> False
    Right n -> n >= 0)

-- | Parsing is pure: the same document parses identically twice.
-- Guards against future impurity (timestamps/PIDs in messages,
-- unordered traversal, global state). The second input is
-- reverse-reversed (identical string, distinct thunk) so GHC's
-- common-subexpression elimination cannot compute once and
-- compare against itself — an impure-counter mutant was verified
-- to fail this property (see the TDD record).
pParseDeterministic :: Property
pParseDeterministic = forAll genDoc $ \doc ->
  parseConfig doc == parseConfig (reverse (reverse doc))

-- | Any well-formed assignment outside the catalog refuses with
-- CfgUnknownKey (the documented unknown-key contract).
pUnknownRefuse :: Property
pUnknownRefuse = forAll genPair $ \(sec, key) ->
  (sec, key) `notElem` map fst configKeyCatalog ==>
    let doc = "schema_version = 1\n"
          ++ (if null sec then "" else "[" ++ sec ++ "]\n")
          ++ key ++ " = true\n"
    in case parseConfig doc of
      Left (CfgUnknownKey _) -> True
      _ -> False
  where
    genPair :: Gen (String, String)
    genPair = do
      sec <- oneof [pure "", genAtom, elements knownSections]
      key <- genAtom `suchThat` (not . null)
      pure (sec, key)
    knownSections =
      [ "storage", "engine", "async", "scenario.async", "trace"
      , "control", "fixtures", "limits", "sim", "tokens"
      ]
