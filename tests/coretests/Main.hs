{- | Core-subset runner: the model specs that import pure-core
modules only, compiled against @haskoki-core@ WITHOUT the runtime/FFI
libraries. This suite's @build-depends@ names @haskoki:haskoki-core@
and external data/test libraries only — any 'Haskoki.Runtime' or
'Haskoki.FFI' import here fails to compile, which structurally
enforces the closure. Spec sources are shared with
@haskoki-model-tests@ (each suite builds its own objects); the
qualifying set is re-verified by import scan, not by this file.
-}
module Main (main) where

import Test.Tasty (TestTree, defaultMain, testGroup)

import qualified ByteFormatSpec
import qualified DenominatorSpec
import qualified ErrorDetailSpec
import qualified ErrorInterpSpec
import qualified FfiHygieneSpec
import qualified MechanismExhaustivenessSpec
import qualified ObjectSpec
import qualified OperationSpec
import qualified RegistrySpec
import qualified SessionSpec
import qualified SlotInsertSpec
import qualified SlotPhaseSpec
import qualified SnapshotSpec
import qualified TemplateRulesSpec
import qualified TransitionSpec
import qualified ULongSpec

spec :: TestTree
spec = testGroup "core subset (no runtime/FFI)"
  [ ByteFormatSpec.spec
  , DenominatorSpec.spec
  , ErrorDetailSpec.spec
  , ErrorInterpSpec.spec
  , FfiHygieneSpec.spec
  , MechanismExhaustivenessSpec.spec
  , ObjectSpec.spec
  , OperationSpec.spec
  , RegistrySpec.spec
  , SessionSpec.spec
  , SlotInsertSpec.spec
  , SlotPhaseSpec.spec
  , SnapshotSpec.spec
  , TemplateRulesSpec.spec
  , TransitionSpec.spec
  , ULongSpec.spec
  ]

main :: IO ()
main = defaultMain spec
