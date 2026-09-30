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
import qualified KeyImportSpec
import qualified KeyManagementSpec
import qualified LifecycleSpec
import qualified MechanismExhaustivenessSpec
import qualified MessageSpec
import qualified MultiSessionSpec
import qualified MultiTokenSpec
import qualified NotificationsSpec
import qualified ObjectSpec
import qualified OperationSpec
import qualified OwnershipSpec
import qualified OutputSpec
import qualified RecipeByteOpsSpec
import qualified RecipeCbcMacSpec
import qualified RecipeCcmSpec
import qualified RecipeChacha20Spec
import qualified RecipeCipherSpec
import qualified RecipeCmacSpec
import qualified RecipeDes3MacSpec
import qualified RecipeDhSpec
import qualified RecipeDigestSpec
import qualified RecipeDsaSpec
import qualified RecipeEcdhSpec
import qualified RecipeEcdsaSpec
import qualified RecipeEddsaSpec
import qualified RecipeEncryptDataSpec
import qualified RecipeGcmSpec
import qualified RecipeGmacSpec
import qualified RecipeHmacSpec
import qualified RecipeIkeSpec
import qualified RecipeKdfSpec
import qualified RecipeMlDsaSpec
import qualified RecipeOaepSpec
import qualified RecipeOtpSpec
import qualified RecipePbeSpec
import qualified RecipePoly1305Spec
import qualified RecipePssSpec
import qualified RecipeRsaSpec
import qualified RecipeRsaX931Spec
import qualified RecipeSlhDsaSpec
import qualified RecipeSp800108Spec
import qualified RecipeSsl3Spec
import qualified RecipeTlsKdfSpec
import qualified RecipeTlsKeyMatSpec
import qualified RecipePubPrivSpec
import qualified RecipeTlsPrfSpec
import qualified RecipeX509Spec
import qualified RecipeXcbcMacSpec
import qualified RecipeWrapCompRsaSpec
import qualified RecipeWrapCompSpec
import qualified RegistrySpec
import qualified RoutingSpec
import qualified SecretsSpec
import qualified SessionCancelSpec
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
  , SessionCancelSpec.spec
  , SessionSpec.spec
  , LifecycleSpec.spec
  , MessageSpec.spec
  , MultiSessionSpec.spec
  , MultiTokenSpec.spec
  , NotificationsSpec.spec
  , ObjectSpec.spec
  , OperationSpec.spec
  , OwnershipSpec.spec
  , OutputSpec.spec
  , RecipeByteOpsSpec.spec
  , RecipeCbcMacSpec.spec
  , RecipeCcmSpec.spec
  , RecipeChacha20Spec.spec
  , RecipeCipherSpec.spec
  , RecipeCmacSpec.spec
  , RecipeDes3MacSpec.spec
  , RecipeDhSpec.spec
  , RecipeDigestSpec.spec
  , RecipeDsaSpec.spec
  , RecipeEcdhSpec.spec
  , RecipeEcdsaSpec.spec
  , RecipeEddsaSpec.spec
  , RecipeEncryptDataSpec.spec
  , RecipeGcmSpec.spec
  , RecipeGmacSpec.spec
  , RecipeHmacSpec.spec
  , RecipeIkeSpec.spec
  , RecipeKdfSpec.spec
  , RecipeMlDsaSpec.spec
  , RecipeOaepSpec.spec
  , RecipeOtpSpec.spec
  , RecipePbeSpec.spec
  , RecipePoly1305Spec.spec
  , RecipePssSpec.spec
  , RecipeRsaSpec.spec
  , RecipeRsaX931Spec.spec
  , RecipeSlhDsaSpec.spec
  , RecipeSsl3Spec.spec
  , RecipeSp800108Spec.spec
  , RecipeTlsKdfSpec.spec
  , RecipeTlsKeyMatSpec.spec
  , RecipePubPrivSpec.spec
  , RecipeTlsPrfSpec.spec
  , RecipeX509Spec.spec
  , RecipeXcbcMacSpec.spec
  , RecipeWrapCompRsaSpec.spec
  , RecipeWrapCompSpec.spec
  , RegistrySpec.spec
  , MechanismExhaustivenessSpec.spec
  , RoutingSpec.spec
  , KeyImportSpec.spec
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
