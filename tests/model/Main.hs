module Main (main) where

import Test.Tasty (defaultMain, testGroup)

import qualified AdmissionSpec
import qualified AsyncSpec
import qualified ByteFormatSpec
import qualified BytesSpec
import qualified ConfigHonestySpec
import qualified ConfigSpec
import qualified ControlSpec
import qualified CtlSpec
import qualified DecodedRequestSpec
import qualified DenominatorSpec
import qualified DetachedSpec
import qualified ErrorDetailSpec
import qualified ErrorInterpSpec
import qualified ErrorPinSpec
import qualified ErrorUnifySpec
import qualified EventsSpec
import qualified FfiAsyncSpec
import qualified FfiHygieneSpec
import qualified JobStepSpec
import qualified LeaseScopeSpec
import qualified KeyManagementSpec
import qualified LifecycleSpec
import qualified MechanismExhaustivenessSpec
import qualified MessageSpec
import qualified MultiSessionSpec
import qualified MultiTokenSpec
import qualified ObjectSpec
import qualified OperationSpec
import qualified OwnershipSpec
import qualified OutputSpec
import qualified RecipeCipherSpec
import qualified RecipeCmacSpec
import qualified RecipeDigestSpec
import qualified RecipeEcdhSpec
import qualified RecipeEcdsaSpec
import qualified RecipeHmacSpec
import qualified RecipeKdfSpec
import qualified RecipeOaepSpec
import qualified RecipeOtpSpec
import qualified RecipePssSpec
import qualified RecipeRsaSpec
import qualified RegistrySpec
import qualified RoutingSpec
import qualified SecretsSpec
import qualified SessionSpec
import qualified SimBridgeSpec
import qualified SimStressSpec
import qualified SlotInsertSpec
import qualified SlotPhaseSpec
import qualified SnapshotSpec
import qualified StandardSurfaceSpec
import qualified TemplateRulesSpec
import qualified TraceSpec
import qualified TransitionSpec
import qualified ULongSpec

main :: IO ()
main = defaultMain $ testGroup "haskoki model + lifecycle"
  [ TransitionSpec.spec
  , SessionSpec.spec
  , LifecycleSpec.spec
  , MessageSpec.spec
  , MultiSessionSpec.spec
  , MultiTokenSpec.spec
  , ObjectSpec.spec
  , OperationSpec.spec
  , OwnershipSpec.spec
  , OutputSpec.spec
  , RecipeCipherSpec.spec
  , RecipeCmacSpec.spec
  , RecipeDigestSpec.spec
  , RecipeEcdhSpec.spec
  , RecipeEcdsaSpec.spec
  , RecipeHmacSpec.spec
  , RecipeKdfSpec.spec
  , RecipeOaepSpec.spec
  , RecipeOtpSpec.spec
  , RecipePssSpec.spec
  , RecipeRsaSpec.spec
  , RegistrySpec.spec
  , MechanismExhaustivenessSpec.spec
  , RoutingSpec.spec
  , KeyManagementSpec.spec
  , SimBridgeSpec.spec
  , SimStressSpec.spec
  , SlotInsertSpec.spec
  , SlotPhaseSpec.spec
  , SnapshotSpec.spec
  , StandardSurfaceSpec.spec
  , TemplateRulesSpec.spec
  , AsyncSpec.spec
  , ByteFormatSpec.spec
  , BytesSpec.spec
  , DetachedSpec.spec
  , ErrorDetailSpec.spec
  , ErrorInterpSpec.spec
  , ErrorPinSpec.spec
  , ErrorUnifySpec.spec
  , ConfigHonestySpec.spec
  , ConfigSpec.spec
  , EventsSpec.spec
  , FfiAsyncSpec.spec
  , FfiHygieneSpec.spec
  , JobStepSpec.spec
  , LeaseScopeSpec.spec
  , TraceSpec.spec
  , ControlSpec.spec
  , CtlSpec.spec
  , DenominatorSpec.spec
  , DecodedRequestSpec.spec
  , AdmissionSpec.spec
  , ULongSpec.spec
  , SecretsSpec.spec
  ]
