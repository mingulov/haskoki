{- | Message operation tests.

Two messages processed under one initialized outer
context; each message ended correctly; the outer context finalized
after. Part A covers the encrypt vertical end to end (init, begin,
next, end-next, one-shot, finish, short-buffer retry, outer final).
-}
{-# LANGUAGE OverloadedStrings #-}
module MessageSpec (spec) where

import qualified Data.ByteString as BS
import Data.Bits (xor)
import Data.ByteString (ByteString)
import qualified Data.Map.Strict as Map
import Data.Word (Word64, Word8)
import Foreign.Marshal.Alloc (allocaBytes)
import Foreign.Marshal.Array (peekArray, pokeArray)
import Foreign.Ptr (Ptr, nullPtr)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertBool, assertEqual, assertFailure, testCase)

import Haskoki.Attribute (AttributeType (..), AttributeValue (..))
import Haskoki.Model
  ( HandleBinding (..)
  , Model (..)
  , ObjectState (..)
  , SessionState (..)
  , emptyModel
  )
import Haskoki.Operation
  ( CipherDir (..)
  , CipherSpec (..)
  , CryptoEffect (..)
  , CryptoError (..)
  , CryptoResult (..)
  , InitArgs (..)
  , InitOutcome (..)
  , KeyPolicy (..)
  , MsgFamily (..)
  , MsgInner (..)
  , MsgState (..)
  , OpAuth (..)
  , OpEnv (..)
  , SlotKind (..)
  , StepOutcome (..)
  , activeSlots
  , emptySessionOps
  , initMessageOperation
  , initOperation
  , maxBuffered
  , retryStaged
  , slotAuth
  )
import Haskoki.FFI.Decode (maxInputBytes)
import Haskoki.FFI.Encode (BoundBuffer (..), EncodeReport (..), encodeWrites)
import Haskoki.FFI.MessageParams
  ( MsgParamError (..)
  , MsgParams (..)
  , decodeMessageParams
  , planNonceWriteback
  , planTagWriteback
  , splitTag
  )
import Haskoki.Operation.Cipher (finishCipher, planCipherOneShot, planCipherUpdate)
import Haskoki.Output (OutputPlan (..), TypedWrite (..), WritePayload (..))
import Haskoki.Operation.Message
  ( MsgBegin (..)
  , MsgNext (..)
  , MsgOneShot (..)
  , finalizeMessage
  , finishMessage
  , lookupMessage
  , messageBuffered
  , planMessageBegin
  , planMessageNext
  , planMessageOneShot
  , retryMessageStaged
  )
import Haskoki.Registry
  ( MechanismId (..)
  , Operation (..)
  , curatedRegistry
  , mkCapabilities
  )
import Haskoki.Request (OutputIntent (..))
import Haskoki.Session (SessionLogin (..))
import Haskoki.Types
  ( ExternalHandle (..)
  , Generation (..)
  , ObjectId (..)
  , ReturnCode (..)
  , Revision (..)
  , SessionId (..)
  , SlotId (..)
  )

spec :: TestTree
spec = testGroup "message operations"
  [ testCase "two messages under one outer context, then outer final" caseTwoMessages
  , testCase "message init conflicts and arg shape" caseMessageInitConflicts
  , testCase "invalid ordering rejected without mutation" caseMessageOrdering
  , testCase "message error keeps the outer context" caseMessageErrorKeepsOuter
  , testCase "oversize part aborts the message only" caseMessageOverflow
  , testCase "unpadded lengths keep or skip the message" caseMessageLengths
  , testCase "auth gate consumes at first begin" caseMessageAuth
  , testCase "aad bound into cipher effects, refused for sign" caseMessageAad
  , testCase "classic and message calls do not mix" caseClassicMessageMixing
  , testCase "decrypt vertical with pad checks" caseDecryptVertical
  , testCase "sign vertical: multipart equals one-shot" caseSignVertical
  , testCase "verify vertical: verdicts end the message" caseVerifyVertical
  , testCase "family and codec mismatch rejected" caseFamilyCodecMismatch
  , testCase "message params decode with family aad rule" caseMessageParamsDecode
  , testCase "nonce writeback through nested regions" caseNonceWriteback
  , testCase "tag split and writeback" caseTagSplitWriteback
  , testCase "toy aead binds nonce aad and tag" caseToyAeadEndToEnd
  ]

-- ---------------------------------------------------------------------------
-- Fixtures
-- ---------------------------------------------------------------------------

aesCbcMech :: MechanismId
aesCbcMech = MechanismId 0x1082

sha256Mech :: MechanismId
sha256Mech = MechanismId 0x250

hmacMech :: MechanismId
hmacMech = MechanismId 0x251

testSlot :: SlotId
testSlot = SlotId 7

testSession :: SessionState
testSession = SessionState
  { ssId = SessionId 1
  , ssSlot = testSlot
  , ssRevision = Revision 1
  , ssGeneration = Generation 1
  , ssReadOnly = False
  , ssLogin = LoginPublic
  , ssOps = emptySessionOps
  }

modelWithKey :: Model
modelWithKey =
  let ost = ObjectState
        { osId = ObjectId 9
        , osRevision = Revision 1
        , osGeneration = Generation 1
        , osAttrs = Map.fromList
            [ (AttrClass, ValULong 4)
            , (AttrPrivate, ValBool False)
            ]
        , osOwner = Nothing
        , osSlot = testSlot
        }
  in emptyModel
    { mObjects = Map.singleton (ObjectId 9) ost
    , mHandles = Map.singleton (ExternalHandle 3)
        (HandleBinding (ObjectId 9) (Generation 1))
    }

testEnv :: OpEnv
testEnv = OpEnv
  { oeRegistry = curatedRegistry
  , oeCaps = mkCapabilities
      [ (sha256Mech, OpDigest)
      , (hmacMech, OpSign)
      , (hmacMech, OpVerify)
      , (aesCbcMech, OpEncrypt)
      , (aesCbcMech, OpDecrypt)
      ]
  , oeModel = modelWithKey
  }

aesKey :: KeyPolicy
aesKey = KeyPolicy
  { kpHandle = ExternalHandle 3
  , kpPermits = [OpEncrypt, OpDecrypt]
  , kpAlwaysAuth = False
  }

encryptArgs :: InitArgs
encryptArgs = InitArgs
  { iaOp = OpEncrypt
  , iaMech = aesCbcMech
  , iaParams = BS.replicate 16 0
  , iaKey = Just aesKey
  , iaCipher = Just (CipherSpec 16 True)
  , iaRecover = Nothing
  }

-- | Toy cipher executor: byte reversal (an involution, so encrypt
-- and decrypt roundtrip through the same driver).
toyCipher :: ByteString -> ByteString
toyCipher = BS.reverse

runMessageEffect :: CryptoEffect -> CryptoResult
runMessageEffect fx = case fx of
  FxMessageCipher _ _ _ _ _ input -> GotBytes (toyCipher input)
  _ -> GotBytes BS.empty

-- | Toy tag executor: byte reversal stands in for the MAC.
toyTag :: ByteString -> ByteString
toyTag = BS.reverse

runMessageSignEffect :: CryptoEffect -> CryptoResult
runMessageSignEffect fx = case fx of
  FxMessageSign _ _ _ input -> GotBytes (toyTag input)
  _ -> GotBytes BS.empty

runMessageVerifyEffect :: CryptoEffect -> CryptoResult
runMessageVerifyEffect fx = case fx of
  FxMessageVerify _ _ _ input sig -> GotValid (toyTag input == sig)
  _ -> GotValid False

decryptArgs :: InitArgs
decryptArgs = InitArgs
  { iaOp = OpDecrypt
  , iaMech = aesCbcMech
  , iaParams = BS.replicate 16 0
  , iaKey = Just aesKey
  , iaCipher = Just (CipherSpec 16 True)
  , iaRecover = Nothing
  }

signKey :: KeyPolicy
signKey = aesKey { kpPermits = [OpSign, OpVerify] }

signArgs :: InitArgs
signArgs = InitArgs OpSign hmacMech BS.empty (Just signKey) Nothing Nothing

verifyArgs :: InitArgs
verifyArgs = InitArgs OpVerify hmacMech BS.empty (Just signKey) Nothing Nothing

-- ---------------------------------------------------------------------------
-- Part A: two messages, one outer context, outer final
-- ---------------------------------------------------------------------------

caseTwoMessages :: IO ()
caseTwoMessages = do
  let (ops0, initOut) =
        initMessageOperation MsgEncrypt testEnv emptySessionOps testSession encryptArgs
  assertEqual "message init ok" CKR_OK (ioCode initOut)
  assertEqual "message init takes the encrypt slot" [SlotEncrypt] (activeSlots ops0)
  -- Message 1, multipart: begin, next, end-next, finish.
  let begin1 = MsgBegin { mbParams = BS.replicate 16 1, mbAad = BS.empty }
      (ops1, st1, b1) = planMessageBegin ops0 testSession MsgEncrypt begin1
  assertEqual "begin ok" CKR_OK (soCode b1)
  assertEqual "begin plans no crypto" [] (soEffects b1)
  let (ops2, st2, n1) = planMessageNext ops1 st1 MsgEncrypt
        (MsgNextCipher BS.empty "hello, " False)
  assertEqual "next ok" CKR_OK (soCode n1)
  assertEqual "intermediate next plans no crypto" [] (soEffects n1)
  let (ops3, st3, nEnd) = planMessageNext ops2 st2 MsgEncrypt
        (MsgNextCipher BS.empty "world" True)
  assertEqual "end-next ok" CKR_OK (soCode nEnd)
  ct1 <- case soEffects nEnd of
    [FxMessageCipher dir _ _ _ aad input] -> do
      assertEqual "end-next direction" DirEncrypt dir
      assertEqual "end-next binds empty aad" BS.empty aad
      -- Padded "hello, world" (12 bytes) to one 16-byte block.
      assertEqual "end-next input is padded concat" 16 (BS.length input)
      let (ops4, fin1) = finishMessage MsgEncrypt ops3 SlotEncrypt "ct1"
            (runMessageEffect (FxMessageCipher dir aesCbcMech Nothing BS.empty aad input))
            (IntentBuffer 64)
      assertEqual "message-1 finish ok" CKR_OK (soCode fin1)
      -- The message ended but the OUTER context survives for message 2.
      assertEqual "outer slot survives message end" [SlotEncrypt] (activeSlots ops4)
      assertEqual "one delivery counted" (Just 1) (deliveredCount (lookupMessage ops4 SlotEncrypt))
      pure ops4
    other -> assertFailure ("expected one message-cipher effect, got " ++ show other)
  -- Message 2, one-shot with a short first buffer, then retry.
  let one = MsgOneShotCipher
        { moParams = BS.replicate 16 2, moAad = BS.empty, moInput = "second" }
      (ops5, _, o1) = planMessageOneShot ct1 st3 MsgEncrypt "ct2" one
  assertEqual "one-shot plans ok" CKR_OK (soCode o1)
  ops6 <- case soEffects o1 of
    [fx@(FxMessageCipher _ _ _ _ _ _)] -> do
      let (opsS, short) = finishMessage MsgEncrypt ops5 SlotEncrypt "ct2"
            (runMessageEffect fx) (IntentBuffer 2)
      assertEqual "short buffer" CKR_BUFFER_TOO_SMALL (soCode short)
      assertEqual "short keeps the outer slot" [SlotEncrypt] (activeSlots opsS)
      let (opsR, retry) = retryMessageStaged MsgEncrypt opsS SlotEncrypt (IntentBuffer 64)
      assertEqual "retry ok" CKR_OK (soCode retry)
      assertEqual "retry keeps the outer slot" [SlotEncrypt] (activeSlots opsR)
      assertEqual "two deliveries counted" (Just 2) (deliveredCount (lookupMessage opsR SlotEncrypt))
      pure opsR
    other -> assertFailure ("expected one one-shot effect, got " ++ show other)
  -- Outer final frees the slot.
  let (ops7, final) = finalizeMessage MsgEncrypt ops6
  assertEqual "outer final ok" CKR_OK (soCode final)
  assertEqual "outer final frees the slot" [] (activeSlots ops7)
  assertEqual "message gone with the slot" Nothing (lookupMessage ops7 SlotEncrypt)

-- ---------------------------------------------------------------------------
-- Init conflicts and argument shape
-- ---------------------------------------------------------------------------

digestArgs :: InitArgs
digestArgs = InitArgs
  { iaOp = OpDigest
  , iaMech = sha256Mech
  , iaParams = BS.empty
  , iaKey = Nothing
  , iaCipher = Nothing
  , iaRecover = Nothing
  }

caseMessageInitConflicts :: IO ()
caseMessageInitConflicts = do
  let (ops0, i0) =
        initMessageOperation MsgEncrypt testEnv emptySessionOps testSession encryptArgs
  assertEqual "message init ok" CKR_OK (ioCode i0)
  -- A second message init in the same slot conflicts; the first survives.
  let (ops1, i1) =
        initMessageOperation MsgEncrypt testEnv ops0 testSession encryptArgs
  assertEqual "second message init conflicts" CKR_OPERATION_ACTIVE (ioCode i1)
  assertEqual "conflict keeps the first" [SlotEncrypt] (activeSlots ops1)
  -- A classic init in a message-held slot conflicts too.
  let (_, ic) = initOperation testEnv ops1 testSession encryptArgs
  assertEqual "classic init on message slot" CKR_OPERATION_ACTIVE (ioCode ic)
  -- And a message init on a classic-held slot.
  let (opsC, _) = initOperation testEnv emptySessionOps testSession encryptArgs
      (_, im) = initMessageOperation MsgEncrypt testEnv opsC testSession encryptArgs
  assertEqual "message init on classic slot" CKR_OPERATION_ACTIVE (ioCode im)
  -- A message/digest pair coexists like the classic pair.
  let (ops2, i2) = initOperation testEnv ops1 testSession digestArgs
  assertEqual "digest init beside message" CKR_OK (ioCode i2)
  assertEqual "pair coexists" [SlotDigest, SlotEncrypt] (activeSlots ops2)
  -- Args naming the wrong op are malformed, before any state check.
  let (_, iw) = initMessageOperation MsgEncrypt testEnv emptySessionOps testSession
        (encryptArgs { iaOp = OpDecrypt })
  assertEqual "args op must match family" CKR_ARGUMENTS_BAD (ioCode iw)
  -- Shared key policy still applies: keyed op without a key.
  let (_, ik) = initMessageOperation MsgEncrypt testEnv emptySessionOps testSession
        (encryptArgs { iaKey = Nothing })
  assertEqual "key required" CKR_ARGUMENTS_BAD (ioCode ik)

-- ---------------------------------------------------------------------------
-- Invalid ordering: rejected without mutation
-- ---------------------------------------------------------------------------

caseMessageOrdering :: IO ()
caseMessageOrdering = do
  let (ops0, _) =
        initMessageOperation MsgEncrypt testEnv emptySessionOps testSession encryptArgs
  -- Next before begin.
  let (_, _, nb) = planMessageNext ops0 testSession MsgEncrypt
        (MsgNextCipher BS.empty "part" False)
  assertEqual "next before begin" CKR_OPERATION_NOT_INITIALIZED (soCode nb)
  assertEqual "rejected next plans nothing" [] (soEffects nb)
  -- Begin twice: the first message is preserved.
  let beginA = MsgBegin { mbParams = BS.replicate 16 1, mbAad = BS.empty }
      (ops1, st1, b1) = planMessageBegin ops0 testSession MsgEncrypt beginA
  assertEqual "begin ok" CKR_OK (soCode b1)
  let (ops1b, _, b2) = planMessageBegin ops1 st1 MsgEncrypt beginA
  assertEqual "begin twice" CKR_OPERATION_ACTIVE (soCode b2)
  assertEqual "begin-twice keeps the first idle" (Just 0) (messageBuffered ops1b SlotEncrypt)
  let (ops2, st2, n1) = planMessageNext ops1b st1 MsgEncrypt
        (MsgNextCipher BS.empty "hi" False)
  assertEqual "first message still feeds" CKR_OK (soCode n1)
  assertEqual "buffered" (Just 2) (messageBuffered ops2 SlotEncrypt)
  -- One-shot in the middle of a multipart message.
  let (_, _, mid) = planMessageOneShot ops2 st2 MsgEncrypt "ct"
        (MsgOneShotCipher BS.empty BS.empty "whole")
  assertEqual "one-shot mid-message" CKR_OPERATION_ACTIVE (soCode mid)
  -- Finalize with an open message: rejected, message and context survive.
  let (ops2b, finOpen) = finalizeMessage MsgEncrypt ops2
  assertEqual "finalize with open message" CKR_OPERATION_ACTIVE (soCode finOpen)
  assertEqual "context survives" [SlotEncrypt] (activeSlots ops2b)
  assertEqual "message survives" (Just 2) (messageBuffered ops2b SlotEncrypt)
  -- End and deliver the message, then finalize cleanly.
  let (ops3, _, nEnd) = planMessageNext ops2b st2 MsgEncrypt
        (MsgNextCipher BS.empty BS.empty True)
  assertEqual "end ok" CKR_OK (soCode nEnd)
  ops4 <- case soEffects nEnd of
    [fx] -> do
      let (o, fin) = finishMessage MsgEncrypt ops3 SlotEncrypt "ct"
            (runMessageEffect fx) (IntentBuffer 64)
      assertEqual "finish ok" CKR_OK (soCode fin)
      pure o
    other -> assertFailure ("expected one end effect, got " ++ show other)
  -- Staged output also blocks the outer final.
  let (ops5, _, o1) = planMessageOneShot ops4 st2 MsgEncrypt "ct2"
        (MsgOneShotCipher BS.empty BS.empty "second")
  ops6 <- case soEffects o1 of
    [fx] -> do
      let (o, short) = finishMessage MsgEncrypt ops5 SlotEncrypt "ct2"
            (runMessageEffect fx) (IntentBuffer 1)
      assertEqual "short buffer" CKR_BUFFER_TOO_SMALL (soCode short)
      pure o
    other -> assertFailure ("expected one one-shot effect, got " ++ show other)
  let (ops6b, finStaged) = finalizeMessage MsgEncrypt ops6
  assertEqual "finalize with staged output" CKR_OPERATION_ACTIVE (soCode finStaged)
  let (ops7, retry) = retryMessageStaged MsgEncrypt ops6b SlotEncrypt (IntentBuffer 64)
  assertEqual "retry ok" CKR_OK (soCode retry)
  let (ops8, finDone) = finalizeMessage MsgEncrypt ops7
  assertEqual "outer final ok" CKR_OK (soCode finDone)
  assertEqual "outer final frees" [] (activeSlots ops8)
  -- Finalize with nothing initialized.
  let (_, finNone) = finalizeMessage MsgEncrypt ops8
  assertEqual "finalize uninitialized" CKR_OPERATION_NOT_INITIALIZED (soCode finNone)
  -- Finish with no message output pending.
  let (ops9, _) =
        initMessageOperation MsgEncrypt testEnv emptySessionOps testSession encryptArgs
      (_, finIdle) = finishMessage MsgEncrypt ops9 SlotEncrypt "ct"
        (GotBytes "junk") (IntentBuffer 64)
  assertEqual "finish while idle" CKR_OPERATION_NOT_INITIALIZED (soCode finIdle)
  -- Wrong slot kind for the family.
  let (_, finKind) = finishMessage MsgEncrypt ops9 SlotDecrypt "ct"
        (GotBytes "junk") (IntentBuffer 64)
  assertEqual "finish kind mismatch" CKR_ARGUMENTS_BAD (soCode finKind)
  -- A retry with nothing staged.
  let (_, retryNone) = retryMessageStaged MsgEncrypt ops9 SlotEncrypt (IntentBuffer 64)
  assertEqual "retry unstaged" CKR_OPERATION_NOT_INITIALIZED (soCode retryNone)

-- ---------------------------------------------------------------------------
-- Acceptance 4: a message error terminates the message, not the slot
-- ---------------------------------------------------------------------------

deliveredCount :: Maybe MsgState -> Maybe Int
deliveredCount = fmap msMessages

innerOf :: Maybe MsgState -> Maybe MsgInner
innerOf = fmap msInner

caseMessageErrorKeepsOuter :: IO ()
caseMessageErrorKeepsOuter = do
  let (ops0, _) =
        initMessageOperation MsgEncrypt testEnv emptySessionOps testSession encryptArgs
      beginA = MsgBegin { mbParams = BS.empty, mbAad = BS.empty }
      (ops1, st1, _) = planMessageBegin ops0 testSession MsgEncrypt beginA
      (ops2, _, nEnd) = planMessageNext ops1 st1 MsgEncrypt
        (MsgNextCipher BS.empty "doomed" True)
  assertEqual "end plans" 1 (length (soEffects nEnd))
  -- The same driver failure that frees a classic slot only ends the message.
  let (ops3, failed) = finishMessage MsgEncrypt ops2 SlotEncrypt "ct"
        (GotCryptoError (CryptoFailed "boom")) (IntentBuffer 64)
  assertEqual "message crypto failure code" CKR_GENERAL_ERROR (soCode failed)
  assertEqual "outer slot survives the message error" [SlotEncrypt] (activeSlots ops3)
  assertEqual "message idled" (Just MsgIdle) (innerOf (lookupMessage ops3 SlotEncrypt))
  assertEqual "failures do not count" (Just 0) (deliveredCount (lookupMessage ops3 SlotEncrypt))
  -- No re-init needed: the next message begins on the surviving context.
  let (ops4, st4, b2) = planMessageBegin ops3 st1 MsgEncrypt beginA
  assertEqual "begin after message error" CKR_OK (soCode b2)
  let (ops5, _, nEnd2) = planMessageNext ops4 st4 MsgEncrypt
        (MsgNextCipher BS.empty "recovered" True)
  ops6 <- case soEffects nEnd2 of
    [fx] -> do
      let (o, fin) = finishMessage MsgEncrypt ops5 SlotEncrypt "ct2"
            (runMessageEffect fx) (IntentBuffer 64)
      assertEqual "recovery message ok" CKR_OK (soCode fin)
      assertEqual "one delivery counted" (Just 1) (deliveredCount (lookupMessage o SlotEncrypt))
      pure o
    other -> assertFailure ("expected one effect, got " ++ show other)
  -- A verdict-shaped answer is a driver-protocol violation: same disposition.
  let (ops8, _, o2) = planMessageOneShot ops6 st4 MsgEncrypt "ct3"
        (MsgOneShotCipher BS.empty BS.empty "mismatch")
  case soEffects o2 of
    [fx] -> do
      let (o, bad) = finishMessage MsgEncrypt ops8 SlotEncrypt "ct3"
            (runMessageEffect fx `asVerdict` GotValid True) (IntentBuffer 64)
      assertEqual "verdict on bytes family" CKR_GENERAL_ERROR (soCode bad)
      assertEqual "slot survives violation" [SlotEncrypt] (activeSlots o)
    other -> assertFailure ("expected one effect, got " ++ show other)
  -- Classic contrast: the identical driver failure frees a classic slot.
  let (opsC0, _) = initOperation testEnv emptySessionOps testSession encryptArgs
      (opsC1, _, c1) = planCipherOneShot opsC0 testSession SlotEncrypt "ct" "classic"
  assertEqual "classic one-shot plans" 1 (length (soEffects c1))
  let (opsC2, cFailed) = finishCipher opsC1 SlotEncrypt "ct"
        (GotCryptoError (CryptoFailed "boom")) (IntentBuffer 64)
  assertEqual "classic failure code" CKR_GENERAL_ERROR (soCode cFailed)
  assertEqual "classic failure frees the slot" [] (activeSlots opsC2)
  where
    asVerdict :: CryptoResult -> CryptoResult -> CryptoResult
    asVerdict _ v = v

-- ---------------------------------------------------------------------------
-- Oversize input aborts the message only
-- ---------------------------------------------------------------------------

caseMessageOverflow :: IO ()
caseMessageOverflow = do
  let (ops0, _) =
        initMessageOperation MsgEncrypt testEnv emptySessionOps testSession encryptArgs
      beginA = MsgBegin { mbParams = BS.empty, mbAad = BS.empty }
      (ops1, st1, _) = planMessageBegin ops0 testSession MsgEncrypt beginA
      huge = BS.replicate (maxBuffered + 1) 0
      (ops2, _, over) = planMessageNext ops1 st1 MsgEncrypt
        (MsgNextCipher BS.empty huge False)
  assertEqual "oversize part" CKR_ARGUMENTS_BAD (soCode over)
  assertEqual "outer survives overflow" [SlotEncrypt] (activeSlots ops2)
  assertEqual "message aborted" (Just MsgIdle) (innerOf (lookupMessage ops2 SlotEncrypt))
  let (_, _, b2) = planMessageBegin ops2 st1 MsgEncrypt beginA
  assertEqual "begin after overflow" CKR_OK (soCode b2)

-- ---------------------------------------------------------------------------
-- Unpadded lengths: repairable end denies keep the message open
-- ---------------------------------------------------------------------------

unpaddedArgs :: InitArgs
unpaddedArgs = encryptArgs { iaCipher = Just (CipherSpec 8 False) }

caseMessageLengths :: IO ()
caseMessageLengths = do
  let (ops0, i0) =
        initMessageOperation MsgEncrypt testEnv emptySessionOps testSession unpaddedArgs
  assertEqual "unpadded message init" CKR_OK (ioCode i0)
  let beginA = MsgBegin { mbParams = BS.empty, mbAad = BS.empty }
      (ops1, st1, _) = planMessageBegin ops0 testSession MsgEncrypt beginA
      (ops2, st2, _) = planMessageNext ops1 st1 MsgEncrypt
        (MsgNextCipher BS.empty "abc" False)
      -- 5 bytes against an 8-byte block: denied, message stays open.
      (ops3, st3, ragged) = planMessageNext ops2 st2 MsgEncrypt
        (MsgNextCipher BS.empty "de" True)
  assertEqual "ragged end" CKR_DATA_LEN_RANGE (soCode ragged)
  assertEqual "ragged end plans nothing" [] (soEffects ragged)
  assertEqual "message stays open" (Just 5) (messageBuffered ops3 SlotEncrypt)
  -- Further parts repair the alignment and the message completes.
  let (_ops4, _, nEnd) = planMessageNext ops3 st3 MsgEncrypt
        (MsgNextCipher BS.empty "fgh" True)
  assertEqual "repaired end ok" CKR_OK (soCode nEnd)
  case soEffects nEnd of
    [FxMessageCipher _ _ _ _ _ input] ->
      assertEqual "aligned effect input" 8 (BS.length input)
    other -> assertFailure ("expected one effect, got " ++ show other)
  -- A ragged one-shot denies on an idle context: no message opens.
  let (ops5, _) =
        initMessageOperation MsgEncrypt testEnv emptySessionOps testSession unpaddedArgs
      (ops6, st6, raggedOne) = planMessageOneShot ops5 testSession MsgEncrypt "ct"
        (MsgOneShotCipher BS.empty BS.empty "short")
  assertEqual "ragged one-shot" CKR_DATA_LEN_RANGE (soCode raggedOne)
  assertEqual "no message opened" (Just 0) (messageBuffered ops6 SlotEncrypt)
  let (_, _, bAfter) = planMessageBegin ops6 st6 MsgEncrypt beginA
  assertEqual "begin after ragged one-shot" CKR_OK (soCode bAfter)

-- ---------------------------------------------------------------------------
-- Auth gate: consumed at the first begin
-- ---------------------------------------------------------------------------

caseMessageAuth :: IO ()
caseMessageAuth = do
  let logged = testSession { ssLogin = LoginUser }
      granted = testSession { ssLogin = LoginContextUser }
      authKey = aesKey { kpAlwaysAuth = True }
      authArgs = encryptArgs { iaKey = Just authKey }
      beginA = MsgBegin { mbParams = BS.empty, mbAad = BS.empty }
  -- Always-auth init under a user login marks the slot pending.
  let (ops0, i0) = initMessageOperation MsgEncrypt testEnv emptySessionOps logged authArgs
  assertEqual "auth init ok" CKR_OK (ioCode i0)
  assertEqual "slot pending" (Just AuthPending) (slotAuth ops0 SlotEncrypt)
  -- Grantless first begin terminates the whole outer context.
  let (ops1, _, late) = planMessageBegin ops0 logged MsgEncrypt beginA
  assertEqual "grantless begin" CKR_USER_NOT_LOGGED_IN (soCode late)
  assertEqual "grantless begin kills the slot" [] (activeSlots ops1)
  -- With the grant, the first begin consumes it.
  let (ops2, _) = initMessageOperation MsgEncrypt testEnv emptySessionOps logged authArgs
      (ops3, st3, first) = planMessageBegin ops2 granted MsgEncrypt beginA
  assertEqual "granted begin ok" CKR_OK (soCode first)
  assertEqual "grant consumed" LoginUser (ssLogin st3)
  assertEqual "slot satisfied" (Just AuthSatisfied) (slotAuth ops3 SlotEncrypt)
  let (_, _, n1) = planMessageNext ops3 st3 MsgEncrypt
        (MsgNextCipher BS.empty "part" False)
  assertEqual "next under plain login" CKR_OK (soCode n1)
  -- Premature grant on a plain slot: denied, nothing consumed or freed.
  let (ops4, _) =
        initMessageOperation MsgEncrypt testEnv emptySessionOps testSession encryptArgs
      (ops5, st5, early) = planMessageBegin ops4 granted MsgEncrypt beginA
  assertEqual "premature grant" CKR_USER_NOT_LOGGED_IN (soCode early)
  assertEqual "plain slot survives" [SlotEncrypt] (activeSlots ops5)
  assertEqual "grant unconsumed" LoginContextUser (ssLogin st5)

-- ---------------------------------------------------------------------------
-- AAD binding and per-call parameter override
-- ---------------------------------------------------------------------------

caseMessageAad :: IO ()
caseMessageAad = do
  let (ops0, _) =
        initMessageOperation MsgEncrypt testEnv emptySessionOps testSession encryptArgs
      beginA = MsgBegin { mbParams = BS.replicate 16 9, mbAad = "aad-tag" }
      (ops1, st1, _) = planMessageBegin ops0 testSession MsgEncrypt beginA
      -- Empty next-params keep the begin params; nonempty replace them.
      (ops2, st2, _) = planMessageNext ops1 st1 MsgEncrypt
        (MsgNextCipher BS.empty "half-" False)
      (ops3, _, nEnd) = planMessageNext ops2 st2 MsgEncrypt
        (MsgNextCipher (BS.replicate 16 7) "-message" True)
  case soEffects nEnd of
    [FxMessageCipher _ _ _ params aad input] -> do
      assertEqual "latest params win" (BS.replicate 16 7) params
      assertEqual "aad bound into the effect" "aad-tag" aad
      assertEqual "padded input" 16 (BS.length input)
    other -> assertFailure ("expected one effect, got " ++ show other)
  -- Empty params on the end-next keep the begin params: finish the
  -- first message, then begin a fresh one.
  (ops4, st4) <- case soEffects nEnd of
    [fx] -> do
      let (o, fin) = finishMessage MsgEncrypt ops3 SlotEncrypt "ct"
            (runMessageEffect fx) (IntentBuffer 64)
      assertEqual "first aad message ok" CKR_OK (soCode fin)
      let (ob, sb, b2) = planMessageBegin o st2 MsgEncrypt beginA
      assertEqual "second begin ok" CKR_OK (soCode b2)
      pure (ob, sb)
    other -> assertFailure ("expected one effect, got " ++ show other)
  let (_ops5, _, nEnd2) = planMessageNext ops4 st4 MsgEncrypt
        (MsgNextCipher BS.empty "0123456789abcdef" True)
  case soEffects nEnd2 of
    [FxMessageCipher _ _ _ params aad _] -> do
      assertEqual "empty keeps begin params" (BS.replicate 16 9) params
      assertEqual "aad still bound" "aad-tag" aad
    other -> assertFailure ("expected one effect, got " ++ show other)
  -- Sign/verify families have no AAD channel.
  let (opsS, iS) = initMessageOperation MsgSign testEnv emptySessionOps testSession signArgs
  assertEqual "sign message init" CKR_OK (ioCode iS)
  let (_, _, badAad) = planMessageBegin opsS testSession MsgSign
        (MsgBegin BS.empty "nope")
  assertEqual "sign rejects aad" CKR_ARGUMENTS_BAD (soCode badAad)
  let (_, _, beginOk) = planMessageBegin opsS testSession MsgSign
        (MsgBegin BS.empty BS.empty)
  assertEqual "sign begin without aad" CKR_OK (soCode beginOk)

-- ---------------------------------------------------------------------------
-- Classic and message calls do not mix
-- ---------------------------------------------------------------------------

caseClassicMessageMixing :: IO ()
caseClassicMessageMixing = do
  let (opsM, _) =
        initMessageOperation MsgEncrypt testEnv emptySessionOps testSession encryptArgs
      -- Classic update on a message slot: foreign operation.
      (_, _, upd) = planCipherUpdate opsM testSession SlotEncrypt "part" Nothing
  assertEqual "classic update on message slot" CKR_GENERAL_ERROR (soCode upd)
  -- Message begin on a classic slot: message process uninitialized.
  let (opsC, _) = initOperation testEnv emptySessionOps testSession encryptArgs
      (_, _, bMsg) = planMessageBegin opsC testSession MsgEncrypt
        (MsgBegin BS.empty BS.empty)
  assertEqual "message begin on classic slot" CKR_OPERATION_NOT_INITIALIZED (soCode bMsg)
  -- The classic retry refuses a staged message output and keeps it intact.
  let (ops2, _, o1) = planMessageOneShot opsM testSession MsgEncrypt "ct"
        (MsgOneShotCipher BS.empty BS.empty "staged")
  case soEffects o1 of
    [fx] -> do
      let (ops3, short) = finishMessage MsgEncrypt ops2 SlotEncrypt "ct"
            (runMessageEffect fx) (IntentBuffer 1)
      assertEqual "short buffer" CKR_BUFFER_TOO_SMALL (soCode short)
      let (ops4, classic) = retryStaged ops3 SlotEncrypt (IntentBuffer 64)
      assertEqual "classic retry refused" CKR_ARGUMENTS_BAD (soCode classic)
      let (ops5, retry) = retryMessageStaged MsgEncrypt ops4 SlotEncrypt (IntentBuffer 64)
      assertEqual "message retry still ok" CKR_OK (soCode retry)
      assertEqual "slot kept" [SlotEncrypt] (activeSlots ops5)
    other -> assertFailure ("expected one effect, got " ++ show other)

-- ---------------------------------------------------------------------------
-- Part B: decrypt vertical with pad checks
-- ---------------------------------------------------------------------------

-- | The staged payload bytes of a finished message step, if the
-- outcome carries exactly one byte write.
stagedPayload :: StepOutcome -> Maybe ByteString
stagedPayload out = case soPlan out of
  Just plan -> case opWrites plan of
    [TypedWrite _ _ (PayloadBytes bs)] -> Just bs
    _ -> Nothing
  Nothing -> Nothing

caseDecryptVertical :: IO ()
caseDecryptVertical = do
  -- Encrypt/decrypt contexts coexist in sibling slots: roundtrip.
  let (opsE, _) =
        initMessageOperation MsgEncrypt testEnv emptySessionOps testSession encryptArgs
      (opsED, iD) =
        initMessageOperation MsgDecrypt testEnv opsE testSession decryptArgs
  assertEqual "decrypt init ok" CKR_OK (ioCode iD)
  assertEqual "siblings coexist" [SlotEncrypt, SlotDecrypt] (activeSlots opsED)
  let (ops1, _, oE) = planMessageOneShot opsED testSession MsgEncrypt "ct"
        (MsgOneShotCipher BS.empty BS.empty "secret-msg")
  ct <- case soEffects oE of
    [fx] -> do
      let (o, fin) = finishMessage MsgEncrypt ops1 SlotEncrypt "ct"
            (runMessageEffect fx) (IntentBuffer 64)
      assertEqual "encrypt ok" CKR_OK (soCode fin)
      case stagedPayload fin of
        Just bytes -> pure (bytes, o)
        Nothing -> assertFailure "encrypt staged no bytes"
    other -> assertFailure ("expected one effect, got " ++ show other)
  let (ctBytes, ops2) = ct
      (ops3, _, oD) = planMessageOneShot ops2 testSession MsgDecrypt "pt"
        (MsgOneShotCipher BS.empty BS.empty ctBytes)
  assertEqual "decrypt one-shot plans" 1 (length (soEffects oD))
  ops4 <- case soEffects oD of
    [fx@(FxMessageCipher dir _ _ _ _ input)] -> do
      assertEqual "decrypt direction" DirDecrypt dir
      assertEqual "decrypt effect input is raw" ctBytes input
      let (o, fin) = finishMessage MsgDecrypt ops3 SlotDecrypt "pt"
            (runMessageEffect fx) (IntentBuffer 64)
      assertEqual "decrypt ok" CKR_OK (soCode fin)
      assertEqual "roundtrip plaintext" (Just "secret-msg") (stagedPayload fin)
      assertEqual "decrypt keeps its slot" [SlotEncrypt, SlotDecrypt] (activeSlots o)
      pure o
    other -> assertFailure ("expected one effect, got " ++ show other)
  -- Multipart decrypt equals the one-shot.
  let beginA = MsgBegin { mbParams = BS.empty, mbAad = BS.empty }
      (ops5, st5, _) = planMessageBegin ops4 testSession MsgDecrypt beginA
      (ops6, st6, _) = planMessageNext ops5 st5 MsgDecrypt
        (MsgNextCipher BS.empty (BS.take 8 ctBytes) False)
      (ops7, _, nEnd) = planMessageNext ops6 st6 MsgDecrypt
        (MsgNextCipher BS.empty (BS.drop 8 ctBytes) True)
  case soEffects nEnd of
    [FxMessageCipher _ _ _ _ _ input] ->
      assertEqual "multipart input is the concatenation" ctBytes input
    other -> assertFailure ("expected one effect, got " ++ show other)
  -- Corrupt padding terminates the message, never the outer context.
  ops8 <- case soEffects nEnd of
    [_] -> do
      let (o, bad) = finishMessage MsgDecrypt ops7 SlotDecrypt "pt"
            (GotBytes "junk!!") (IntentBuffer 64)
      assertEqual "bad pad code" CKR_ENCRYPTED_DATA_INVALID (soCode bad)
      assertEqual "slot survives bad pad" [SlotEncrypt, SlotDecrypt] (activeSlots o)
      assertEqual "message idled" (Just MsgIdle) (innerOf (lookupMessage o SlotDecrypt))
      pure o
    other -> assertFailure ("expected one effect, got " ++ show other)
  -- A ragged unpadded driver answer is likewise message-terminal.
  let (opsU, stU, _) = planMessageBegin ops8 testSession MsgDecrypt beginA
      (opsV, _, nEndU) = planMessageNext opsU stU MsgDecrypt
        (MsgNextCipher BS.empty ctBytes True)
  assertEqual "end plans" 1 (length (soEffects nEndU))
  let (opsW, ragged) = finishMessage MsgDecrypt opsV SlotDecrypt "pt"
        (GotBytes "short!") (IntentBuffer 64)
  -- "short!" is 6 bytes: not block-aligned, and no valid pad framing.
  assertEqual "ragged answer code" CKR_ENCRYPTED_DATA_INVALID (soCode ragged)
  assertEqual "slot survives" [SlotEncrypt, SlotDecrypt] (activeSlots opsW)
  -- Unpadded decrypt: aligned answers stage, ragged answers fail
  -- with the length code while the context survives.
  let (opsP, _) = initMessageOperation MsgDecrypt testEnv emptySessionOps testSession
        (decryptArgs { iaCipher = Just (CipherSpec 8 False) })
      (opsQ, _, oP) = planMessageOneShot opsP testSession MsgDecrypt "pt"
        (MsgOneShotCipher BS.empty BS.empty "12345678")
  assertEqual "unpadded decrypt plans" 1 (length (soEffects oP))
  case soEffects oP of
    [fx] -> do
      let (o, fin) = finishMessage MsgDecrypt opsQ SlotDecrypt "pt"
            (runMessageEffect fx) (IntentBuffer 64)
      assertEqual "aligned ok" CKR_OK (soCode fin)
      assertEqual "aligned staged" (Just "87654321") (stagedPayload fin)
      let (o2, _, oP2) = planMessageOneShot o testSession MsgDecrypt "pt"
            (MsgOneShotCipher BS.empty BS.empty "12345678")
      case soEffects oP2 of
        [_] -> do
          let (o3, rag) = finishMessage MsgDecrypt o2 SlotDecrypt "pt"
                (GotBytes "short") (IntentBuffer 64)
          assertEqual "ragged code" CKR_ENCRYPTED_DATA_LEN_RANGE (soCode rag)
          assertEqual "slot kept" [SlotDecrypt] (activeSlots o3)
        other -> assertFailure ("expected one effect, got " ++ show other)
    other -> assertFailure ("expected one effect, got " ++ show other)

-- ---------------------------------------------------------------------------
-- Part B: sign vertical, multipart equals one-shot
-- ---------------------------------------------------------------------------

caseSignVertical :: IO ()
caseSignVertical = do
  let (ops0, i0) =
        initMessageOperation MsgSign testEnv emptySessionOps testSession signArgs
  assertEqual "sign init ok" CKR_OK (ioCode i0)
  let beginA = MsgBegin { mbParams = BS.empty, mbAad = BS.empty }
      (ops1, st1, _) = planMessageBegin ops0 testSession MsgSign beginA
      (ops2, st2, n1) = planMessageNext ops1 st1 MsgSign
        (MsgNextSign BS.empty "hello, " False)
  assertEqual "sign next ok" CKR_OK (soCode n1)
  assertEqual "intermediate sign next plans nothing" [] (soEffects n1)
  let (ops3, _, nEnd) = planMessageNext ops2 st2 MsgSign
        (MsgNextSign BS.empty "world" True)
  assertEqual "sign end ok" CKR_OK (soCode nEnd)
  (sig, ops4) <- case soEffects nEnd of
    [fx@(FxMessageSign _ _ _ input)] -> do
      assertEqual "sign input is the concatenation" "hello, world" input
      let (o, fin) = finishMessage MsgSign ops3 SlotSign "sig"
            (runMessageSignEffect fx) (IntentBuffer 64)
      assertEqual "sign finish ok" CKR_OK (soCode fin)
      assertEqual "sign keeps the slot" [SlotSign] (activeSlots o)
      case stagedPayload fin of
        Just bytes -> pure (bytes, o)
        Nothing -> assertFailure "sign staged no bytes"
    other -> assertFailure ("expected one effect, got " ++ show other)
  -- The one-shot over the same input produces the same tag.
  let (ops5, _, o1) = planMessageOneShot ops4 st2 MsgSign "sig2"
        (MsgOneShotSign BS.empty "hello, world")
  case soEffects o1 of
    [fx] -> do
      let (o, fin) = finishMessage MsgSign ops5 SlotSign "sig2"
            (runMessageSignEffect fx) (IntentBuffer 2)
      assertEqual "short sign buffer" CKR_BUFFER_TOO_SMALL (soCode fin)
      let (o2, retry) = retryMessageStaged MsgSign o SlotSign (IntentBuffer 64)
      assertEqual "sign retry ok" CKR_OK (soCode retry)
      assertEqual "one-shot equals multipart" (Just sig) (stagedPayload retry)
      assertEqual "two deliveries" (Just 2) (deliveredCount (lookupMessage o2 SlotSign))
    other -> assertFailure ("expected one effect, got " ++ show other)
  -- A cipher one-shot under sign is refused as a codec mismatch
  -- (malformed call, before any state check).
  let (_, _, o2) = planMessageOneShot ops4 st2 MsgSign "sig3"
        (MsgOneShotCipher BS.empty BS.empty "x")
  assertEqual "wrong codec refused" CKR_ARGUMENTS_BAD (soCode o2)

-- ---------------------------------------------------------------------------
-- Part B: verify vertical, verdicts end the message
-- ---------------------------------------------------------------------------

caseVerifyVertical :: IO ()
caseVerifyVertical = do
  let (ops0, i0) =
        initMessageOperation MsgVerify testEnv emptySessionOps testSession verifyArgs
  assertEqual "verify init ok" CKR_OK (ioCode i0)
  let witness = toyTag "attested"
  -- Valid one-shot: CKR_OK with a terminating plan, slot kept.
  let (ops1, _, o1) = planMessageOneShot ops0 testSession MsgVerify "vrf"
        (MsgOneShotVerify BS.empty "attested" witness)
  assertEqual "verify one-shot plans" 1 (length (soEffects o1))
  ops2 <- case soEffects o1 of
    [fx@(FxMessageVerify _ _ _ input sig)] -> do
      assertEqual "verify input" "attested" input
      assertEqual "verify witness" witness sig
      let (o, fin) = finishMessage MsgVerify ops1 SlotVerify "vrf"
            (runMessageVerifyEffect fx) (IntentBuffer 64)
      assertEqual "valid witness" CKR_OK (soCode fin)
      assertEqual "verdict keeps the slot" [SlotVerify] (activeSlots o)
      assertEqual "verdict counted" (Just 1) (deliveredCount (lookupMessage o SlotVerify))
      pure o
    other -> assertFailure ("expected one effect, got " ++ show other)
  -- Invalid one-shot: SIGNATURE_INVALID, slot kept, message counted.
  let (ops3, st3, _) = planMessageBegin ops2 testSession MsgVerify
        (MsgBegin BS.empty BS.empty)
      (ops4, _, nEnd) = planMessageNext ops3 st3 MsgVerify
        (MsgNextVerify BS.empty "attested" (Just "bogus"))
  assertEqual "verify end plans" 1 (length (soEffects nEnd))
  ops5 <- case soEffects nEnd of
    [fx] -> do
      let (o, fin) = finishMessage MsgVerify ops4 SlotVerify "vrf"
            (runMessageVerifyEffect fx) (IntentBuffer 64)
      assertEqual "mismatch code" CKR_SIGNATURE_INVALID (soCode fin)
      assertEqual "slot survives mismatch" [SlotVerify] (activeSlots o)
      assertEqual "mismatch counted" (Just 2) (deliveredCount (lookupMessage o SlotVerify))
      pure o
    other -> assertFailure ("expected one effect, got " ++ show other)
  -- Multipart feeding with the witness on the last part.
  let (ops6, st6, _) = planMessageBegin ops5 st3 MsgVerify
        (MsgBegin BS.empty BS.empty)
      (ops7, st7, c1) = planMessageNext ops6 st6 MsgVerify
        (MsgNextVerify BS.empty "att" Nothing)
  assertEqual "continue ok" CKR_OK (soCode c1)
  assertEqual "continue plans nothing" [] (soEffects c1)
  let (_ops8, _, cEnd) = planMessageNext ops7 st7 MsgVerify
        (MsgNextVerify BS.empty "ested" (Just witness))
  case soEffects cEnd of
    [FxMessageVerify _ _ _ input sig] -> do
      assertEqual "multipart input" "attested" input
      assertEqual "multipart witness" witness sig
    other -> assertFailure ("expected one effect, got " ++ show other)
  -- An empty witness is invalid without an effect; the message ends.
  let (ops9, st9, _) = planMessageBegin ops5 st3 MsgVerify
        (MsgBegin BS.empty BS.empty)
      (ops10, _, cEmpty) = planMessageNext ops9 st9 MsgVerify
        (MsgNextVerify BS.empty "attested" (Just BS.empty))
  assertEqual "empty witness invalid" CKR_SIGNATURE_INVALID (soCode cEmpty)
  assertEqual "empty plans no effect" [] (soEffects cEmpty)
  assertEqual "message ended" (Just MsgIdle) (innerOf (lookupMessage ops10 SlotVerify))
  assertEqual "slot kept" [SlotVerify] (activeSlots ops10)
  -- Bytes where a verdict belongs: protocol violation, slot kept.
  let (ops12, _, o3) = planMessageOneShot ops10 st9 MsgVerify "vrf"
        (MsgOneShotVerify BS.empty "attested" witness)
  case soEffects o3 of
    [_] -> do
      let (o, bad) = finishMessage MsgVerify ops12 SlotVerify "vrf"
            (GotBytes "junk") (IntentBuffer 64)
      assertEqual "bytes on verify" CKR_GENERAL_ERROR (soCode bad)
      assertEqual "slot survives" [SlotVerify] (activeSlots o)
    other -> assertFailure ("expected one effect, got " ++ show other)

-- ---------------------------------------------------------------------------
-- Part B: family and codec mismatch
-- ---------------------------------------------------------------------------

caseFamilyCodecMismatch :: IO ()
caseFamilyCodecMismatch = do
  let (opsE, _) =
        initMessageOperation MsgEncrypt testEnv emptySessionOps testSession encryptArgs
      (_, _, m1) = planMessageNext opsE testSession MsgEncrypt
        (MsgNextSign BS.empty "x" False)
  assertEqual "sign codec under encrypt" CKR_ARGUMENTS_BAD (soCode m1)
  let (opsS, _) =
        initMessageOperation MsgSign testEnv emptySessionOps testSession signArgs
      (_, _, m2) = planMessageNext opsS testSession MsgSign
        (MsgNextCipher BS.empty "x" False)
  assertEqual "cipher codec under sign" CKR_ARGUMENTS_BAD (soCode m2)
  let (_, _, m3) = planMessageOneShot opsS testSession MsgSign "s"
        (MsgOneShotVerify BS.empty "x" "w")
  assertEqual "verify one-shot under sign" CKR_ARGUMENTS_BAD (soCode m3)

-- ---------------------------------------------------------------------------
-- Part C: message parameter decode with the family AAD rule
-- ---------------------------------------------------------------------------

-- | Fill a fresh buffer with the given bytes and hand its pointer on.
withInputBytes :: [Word8] -> (Ptr Word8 -> Word64 -> IO a) -> IO a
withInputBytes bytes k =
  allocaBytes (length bytes) $ \ptr -> do
    pokeArray ptr bytes
    k ptr (fromIntegral (length bytes))

caseMessageParamsDecode :: IO ()
caseMessageParamsDecode = do
  -- Cipher families decode params and AAD into owned bytes.
  withInputBytes [1 .. 12] $ \pPtr pLen ->
    withInputBytes [21, 22, 23] $ \aPtr aLen -> do
      decoded <- decodeMessageParams MsgEncrypt pPtr pLen aPtr aLen
      case decoded of
        Right mp -> do
          assertEqual "params copied" (BS.pack [1 .. 12]) (mpParams mp)
          assertEqual "aad copied" (BS.pack [21, 22, 23]) (mpAad mp)
        Left err -> assertFailure ("expected params, got " ++ show err)
  -- Null with zero length decodes to empty on both halves.
  decodedNull <- decodeMessageParams MsgDecrypt nullPtr 0 nullPtr 0
  case decodedNull of
    Right mp -> do
      assertEqual "null params empty" BS.empty (mpParams mp)
      assertEqual "null aad empty" BS.empty (mpAad mp)
    Left err -> assertFailure ("expected empty, got " ++ show err)
  -- Null with a nonzero length rejects before any dereference.
  badNull <- decodeMessageParams MsgEncrypt nullPtr 4 nullPtr 0
  assertEqual "null with length" (Left (MsgParamBadPointer 4)) badNull
  -- Past-bound lengths reject even from null.
  tooLarge <- decodeMessageParams MsgEncrypt nullPtr (maxInputBytes + 1) nullPtr 0
  assertEqual "oversize rejects" (Left (MsgParamTooLarge (maxInputBytes + 1))) tooLarge
  -- Sign/verify families have no AAD channel: nonzero AAD rejects.
  withInputBytes [9] $ \pPtr pLen ->
    withInputBytes [8] $ \aPtr aLen -> do
      rejected <- decodeMessageParams MsgSign pPtr pLen aPtr aLen
      assertEqual "sign aad rejected" (Left MsgParamAadRejected) rejected
      ok <- decodeMessageParams MsgSign pPtr pLen nullPtr 0
      case ok of
        Right mp -> assertEqual "sign params kept" (BS.pack [9]) (mpParams mp)
        Left err -> assertFailure ("expected params, got " ++ show err)

-- ---------------------------------------------------------------------------
-- Part C: nonce writeback through nested regions
-- ---------------------------------------------------------------------------

caseNonceWriteback :: IO ()
caseNonceWriteback = do
  let nonce = BS.pack [1 .. 12]
      plan = planNonceWriteback "msgparams" 12 nonce (IntentBuffer 12)
  assertEqual "nonce plan ok" CKR_OK (opCode plan)
  -- The write lands at its nested path; a trailing canary survives.
  allocaBytes 13 $ \ptr -> do
    pokeArray ptr (replicate 13 (0 :: Word8))
    let bufs = [BoundBuffer ["msgparams", "nonce"] ptr 12]
    reports <- encodeWrites bufs (opWrites plan)
    case reports of
      [r] -> do
        assertEqual "write ok" CKR_OK (erCode r)
        assertEqual "twelve written" 12 (erWritten r)
      other -> assertFailure ("expected one report, got " ++ show other)
    landed <- peekArray 13 ptr
    assertEqual "nonce bytes land" ([1 .. 12] ++ [0]) landed
  -- A wrong-length nonce rejects with no writes.
  let bad = planNonceWriteback "msgparams" 12 (BS.pack [1, 2]) (IntentBuffer 12)
  assertEqual "wrong length" CKR_ARGUMENTS_BAD (opCode bad)
  assertEqual "no writes planned" [] (opWrites bad)
  -- A short caller buffer reports short with the required length.
  let short = planNonceWriteback "msgparams" 12 nonce (IntentBuffer 4)
  assertEqual "short buffer" CKR_BUFFER_TOO_SMALL (opCode short)
  assertEqual "required length" [(["msgparams", "nonce"], 12)] (opLengths short)
  assertEqual "no short writes" [] (opWrites short)

-- ---------------------------------------------------------------------------
-- Part C: tag split and writeback
-- ---------------------------------------------------------------------------

caseTagSplitWriteback :: IO ()
caseTagSplitWriteback = do
  let blob = BS.pack [1 .. 20] <> BS.pack [101 .. 116]
  case splitTag 16 blob of
    Right (ct, tag) -> do
      assertEqual "ciphertext head" (BS.pack [1 .. 20]) ct
      assertEqual "tag tail" (BS.pack [101 .. 116]) tag
    Left err -> assertFailure ("expected split, got " ++ show err)
  assertEqual "short blob" (Left MsgParamShortTag) (splitTag 16 (BS.pack [1, 2]))
  -- The tag writes back through its nested region like the nonce.
  let tag = BS.pack [101 .. 116]
      plan = planTagWriteback "msgparams" 16 tag (IntentBuffer 16)
  assertEqual "tag plan ok" CKR_OK (opCode plan)
  allocaBytes 16 $ \ptr -> do
    let bufs = [BoundBuffer ["msgparams", "tag"] ptr 16]
    reports <- encodeWrites bufs (opWrites plan)
    case reports of
      [r] -> assertEqual "tag write ok" CKR_OK (erCode r)
      other -> assertFailure ("expected one report, got " ++ show other)
    landed <- peekArray 16 ptr
    assertEqual "tag bytes land" [101 .. 116] landed

-- ---------------------------------------------------------------------------
-- Part C: toy AEAD binds nonce, AAD, and tag end to end
-- ---------------------------------------------------------------------------

tagLen :: Int
tagLen = 16

-- | Toy AEAD tag over (nonce, AAD, ciphertext): every blob byte
-- folds into one of 16 lanes, so a change anywhere in the triple
-- moves the tag.
toyAeadTag :: ByteString -> ByteString -> ByteString -> ByteString
toyAeadTag nonce aad ct = BS.pack [lane i | i <- [0 .. tagLen - 1]]
  where
    blob = "AEADv1" <> nonce <> BS.singleton 0 <> aad <> BS.singleton 1 <> ct
    lane i = BS.foldl' xor (fromIntegral (i * 31 + BS.length blob)) (strided i)
    strided i = BS.pack [b | (j, b) <- zip [0 ..] (BS.unpack blob), j `mod` tagLen == i]

toyAeadEncrypt :: ByteString -> ByteString -> ByteString -> ByteString
toyAeadEncrypt nonce aad input =
  let ct = BS.reverse input in ct <> toyAeadTag nonce aad ct

toyAeadDecrypt :: ByteString -> ByteString -> ByteString -> Either String ByteString
toyAeadDecrypt nonce aad blob
  | BS.length blob < tagLen = Left "blob shorter than the tag"
  | tag /= toyAeadTag nonce aad ct = Left "tag mismatch"
  | otherwise = Right (BS.reverse ct)
  where
    (ct, tag) = BS.splitAt (BS.length blob - tagLen) blob

runToyAeadEncrypt :: CryptoEffect -> CryptoResult
runToyAeadEncrypt fx = case fx of
  FxMessageCipher _ _ _ params aad input ->
    GotBytes (toyAeadEncrypt params aad input)
  _ -> GotCryptoError (CryptoFailed "unexpected effect")

runToyAeadDecrypt :: CryptoEffect -> CryptoResult
runToyAeadDecrypt fx = case fx of
  FxMessageCipher _ _ _ params aad input ->
    either (GotCryptoError . CryptoFailed) GotBytes (toyAeadDecrypt params aad input)
  _ -> GotCryptoError (CryptoFailed "unexpected effect")

caseToyAeadEndToEnd :: IO ()
caseToyAeadEndToEnd = do
  let nonce = BS.pack [1 .. 12]
      aad = "header-bytes"
      (opsE, _) =
        initMessageOperation MsgEncrypt testEnv emptySessionOps testSession encryptArgs
      (opsED, _) =
        initMessageOperation MsgDecrypt testEnv opsE testSession decryptArgs
      (ops1, _, oE) = planMessageOneShot opsED testSession MsgEncrypt "ct"
        (MsgOneShotCipher nonce aad "payload-data")
  blob <- case soEffects oE of
    [fx@(FxMessageCipher _ _ _ params boundAad input)] -> do
      assertEqual "nonce bound" nonce params
      assertEqual "aad bound" aad boundAad
      assertEqual "input bound padded" ("payload-data" <> BS.replicate 4 4) input
      let (o, fin) = finishMessage MsgEncrypt ops1 SlotEncrypt "ct"
            (runToyAeadEncrypt fx) (IntentBuffer 64)
      assertEqual "aead encrypt ok" CKR_OK (soCode fin)
      case stagedPayload fin of
        Just bytes -> pure (bytes, o)
        Nothing -> assertFailure "encrypt staged no bytes"
    other -> assertFailure ("expected one effect, got " ++ show other)
  let (blobBytes, ops2) = blob
  -- "payload-data" pads to one 16-byte block; the blob appends the tag.
  assertEqual "blob holds ct plus tag" (16 + tagLen) (BS.length blobBytes)
  -- The tag splits off the tail and the head decrypts with the same
  -- nonce and AAD.
  (ctBytes, tagBytes) <- case splitTag (fromIntegral tagLen) blobBytes of
    Right parts -> pure parts
    Left err -> assertFailure ("expected split, got " ++ show err)
  let (ops3, _, oD) = planMessageOneShot ops2 testSession MsgDecrypt "pt"
        (MsgOneShotCipher nonce aad blobBytes)
  ops4 <- case soEffects oD of
    [fx] -> do
      let (o, fin) = finishMessage MsgDecrypt ops3 SlotDecrypt "pt"
            (runToyAeadDecrypt fx) (IntentBuffer 64)
      assertEqual "aead decrypt ok" CKR_OK (soCode fin)
      assertEqual "roundtrip" (Just "payload-data") (stagedPayload fin)
      pure o
    other -> assertFailure ("expected one effect, got " ++ show other)
  -- A tampered tag fails authentication; the context survives.
  let tampered = ctBytes <> BS.pack (map (+ 1) (BS.unpack tagBytes))
      (ops5, _, oT) = planMessageOneShot ops4 testSession MsgDecrypt "pt"
        (MsgOneShotCipher nonce aad tampered)
  ops6 <- case soEffects oT of
    [fx] -> do
      let (o, bad) = finishMessage MsgDecrypt ops5 SlotDecrypt "pt"
            (runToyAeadDecrypt fx) (IntentBuffer 64)
      assertEqual "tag mismatch code" CKR_GENERAL_ERROR (soCode bad)
      assertEqual "context survives" [SlotEncrypt, SlotDecrypt] (activeSlots o)
      pure o
    other -> assertFailure ("expected one effect, got " ++ show other)
  -- Changed AAD authenticates nothing: the tag no longer verifies.
  let (ops7, _, oA) = planMessageOneShot ops6 testSession MsgDecrypt "pt"
        (MsgOneShotCipher nonce "forged-header" blobBytes)
  case soEffects oA of
    [fx] -> do
      let (o, bad) = finishMessage MsgDecrypt ops7 SlotDecrypt "pt"
            (runToyAeadDecrypt fx) (IntentBuffer 64)
      assertEqual "aad mismatch code" CKR_GENERAL_ERROR (soCode bad)
      assertEqual "context survives aad" [SlotEncrypt, SlotDecrypt] (activeSlots o)
      assertBool "tag differs under changed aad"
        (toyAeadTag nonce aad ctBytes /= toyAeadTag nonce "forged-header" ctBytes)
      assertBool "tag differs under changed nonce"
        (toyAeadTag nonce aad ctBytes /= toyAeadTag (BS.pack [9 .. 20]) aad ctBytes)
    other -> assertFailure ("expected one effect, got " ++ show other)
