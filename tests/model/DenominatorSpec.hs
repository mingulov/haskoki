{- | Denominator tests.

The complete source-defined baseline: every header-defined mechanism,
attribute, object class, key type, and function must be present in the
generated catalogs. Counts are pinned to unique @#define@s in the
byte-locked @spec/vendor/@ headers, measured with @LC_ALL=C@ (byte
collation):

* 480 @CKM_*@ names: 464 canonical entries + 16 aliases
  (16 same-value respellings: CAST5\/CAST128 x8, ECDSA\/EC
  key-pair-gen x1, DSA typo x1, SHA3\/SHAKE x6; the header carries
  no alias-style defines) in @spec/mechanisms.json@
* 160 @CKA_*@ names: 158 canonical + 2 aliases (SUB_PRIME_BITS,
  ECDSA_PARAMS) in @spec/attributes.json@. NOTE: an earlier count said
  159, but that count was measured under a UTF-8 locale whose
  @sort -u@ collapses @CKA_SUB_PRIME_BITS@ with @CKA_SUBPRIME_BITS@
  (underscore-insensitive collation). Byte collation gives 160
  distinct header names, and all 160 are catalogued (reproduce
  with @LC_ALL=C@ byte collation). Template rules add 6 quoted
  required-refs and the HOTP rule 2 more, so the quoted total
  is 168.
* 13 @CKO_*@ classes (no aliases) in @spec/attributes.json@, plus 4
  rule class refs (quoted total 17).
* 69 @CKK_*@ names: 67 canonical + 2 aliases (ECDSA\/EC, CAST5\/CAST128)
  in @spec/attributes.json@, plus 4 rule key-type refs (quoted
  total 73).
* 104 @C_*@ functions in @spec/function-contracts.json@

The generator keeps quoted @CKX_*@ sequences out of every field
except @canonical_name@\/@aliases@ (and @\"name\"@ for functions), so
counting those occurrences pins the catalogued-name population.
Byte-exactness of numeric IDs against the headers, generator
idempotency, and the soundness of this counting method are enforced
by @scripts/check-denominators.py@ (host gate); these tests pin the
cardinalities from inside the Haskell suites so a truncated
regeneration fails loudly here too.
-}
{-# LANGUAGE OverloadedStrings #-}
module DenominatorSpec (spec) where

import qualified Data.Text as T
import qualified Data.Text.IO as TIO
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertEqual, testCase)

spec :: TestTree
spec = testGroup "Denominators"
  [ testCase "mechanisms.json holds 464+16 CKM names" caseMechanisms
  , testCase "attributes.json holds 158+2+8/13+4/67+2+4 refs" caseAttributes
  , testCase "function-contracts.json holds 104 functions" caseFunctions
  ]

countTag :: T.Text -> T.Text -> Int
countTag tag content = length (T.breakOnAll tag content)

caseMechanisms :: IO ()
caseMechanisms = do
  content <- TIO.readFile "spec/mechanisms.json"
  assertEqual "CKM canonical entries" 464
    (countTag "\"canonical_name\": \"CKM_" content)
  assertEqual "CKM total catalogued names" 480
    (countTag "\"CKM_" content)

caseAttributes :: IO ()
caseAttributes = do
  -- Totals include template-rule references (8 CKA
  -- required refs, 4 CKO class refs, 4 CKK key-type refs); canonical
  -- counts pin the header populations exactly.
  content <- TIO.readFile "spec/attributes.json"
  assertEqual "CKA canonical entries" 158
    (countTag "\"canonical_name\": \"CKA_" content)
  assertEqual "CKA total quoted names" 168
    (countTag "\"CKA_" content)
  assertEqual "CKO canonical entries" 13
    (countTag "\"canonical_name\": \"CKO_" content)
  assertEqual "CKO total quoted names" 17
    (countTag "\"CKO_" content)
  assertEqual "CKK canonical entries" 67
    (countTag "\"canonical_name\": \"CKK_" content)
  assertEqual "CKK total quoted names" 73
    (countTag "\"CKK_" content)

caseFunctions :: IO ()
caseFunctions = do
  content <- TIO.readFile "spec/function-contracts.json"
  assertEqual "C_* function entries" 104
    (countTag "\"name\": \"C_" content)
