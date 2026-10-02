{- | Normalized call requests for the pure core.

A 'Request' carries the selected API version, a function identifier,
normalized (decoded, bounded, address-free) arguments, and an
'OutputIntent' describing every output region. Nothing here references
caller memory.
-}
module Haskoki.Request
  ( FunctionId (..)
  , OutputIntent (..)
  , OutputRegion (..)
  , Request (..)
  , DecodedRequest (..)
  , InitFunction (..)
  , initFunctionId
  , initOperation
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Word (Word64)

import Haskoki.Attribute (AttributeType, AttributeValue)
import Haskoki.Operation.State (RecoverSpec)
import Haskoki.Registry (MechanismId, Operation (..))
import Haskoki.Types (ExternalHandle, Pkcs11Version, SessionId, redactShown)

-- | Function identifiers the core planner can route. The original
-- skeleton covers session/object/auth plus digest/sign, extended by
-- the operation layer (classic encrypt/decrypt/verify, multipart
-- steps, and the v3 message families). Keep constructors stable once
-- published (the output planner and the FFI trampolines key off
-- them): new entries append, never reorder.
data FunctionId
  = F_GetInfo
  | F_GetSlotList
  | F_GetSessionInfo
  | F_OpenSession
  | F_CloseSession
  | F_Login
  | F_Logout
  | F_DigestInit
  | F_Digest
  | F_SignInit
  | F_Sign
  | F_CreateObject
  | F_DestroyObject
  | F_CopyObject
  | F_FindObjects
  | F_GetAttributeValue
  | F_SetAttributeValue
  | F_DigestUpdate
  | F_DigestFinal
  | F_SignUpdate
  | F_SignFinal
  | F_VerifyInit
  | F_Verify
  | F_VerifyUpdate
  | F_VerifyFinal
  | F_EncryptInit
  | F_Encrypt
  | F_EncryptUpdate
  | F_EncryptFinal
  | F_DecryptInit
  | F_Decrypt
  | F_DecryptUpdate
  | F_DecryptFinal
  | F_MessageEncryptInit
  | F_MessageDecryptInit
  | F_MessageSignInit
  | F_MessageVerifyInit
  | F_EncryptMessage
  | F_DecryptMessage
  | F_SignMessage
  | F_VerifyMessage
  | F_EncryptMessageBegin
  | F_DecryptMessageBegin
  | F_SignMessageBegin
  | F_VerifyMessageBegin
  | F_EncryptMessageNext
  | F_DecryptMessageNext
  | F_SignMessageNext
  | F_VerifyMessageNext
  | F_MessageEncryptFinal
  | F_MessageDecryptFinal
  | F_MessageSignFinal
  | F_MessageVerifyFinal
  | F_SessionCancel
  | F_SignRecoverInit
  | F_SignRecover
  | F_VerifyRecoverInit
  | F_VerifyRecover
  deriving (Eq, Ord, Show, Enum, Bounded)

-- | How the caller provided (or omitted) an output buffer. Null (absent)
-- and present-with-zero-capacity are observably different calls and must
-- never be conflated.
data OutputIntent
  = -- | No buffer supplied: size query where the source allows one.
    IntentNull
  | -- | Buffer supplied with the given capacity in bytes.
    IntentBuffer { intentCapacity :: !Word64 }
  deriving (Eq, Show)

-- | One described output region: scalar, handle, byte-vector, or nested.
data OutputRegion
  = RegionScalar { regionName :: !String }
  | RegionHandle { regionName :: !String }
  | RegionBytes { regionName :: !String, regionIntent :: !OutputIntent }
  | RegionNested { regionName :: !String, regionFields :: ![OutputRegion] }
  deriving (Eq, Show)

-- | A normalized call request: version + function + decoded arguments +
-- output-region descriptors. All variable-length inputs are strict owned
-- bytes with caller-independent bounds already checked at decode time.
data Request = Request
  { reqVersion :: !Pkcs11Version
  , reqFunction :: !FunctionId
  , reqSession :: !(Maybe SessionId)
  , reqHandle :: !(Maybe ExternalHandle)
  , reqInput :: !ByteString
  , reqRegions :: ![OutputRegion]
  } deriving (Eq)

-- | 'Show' redacts template-carrying inputs: create, copy,
-- and find requests carry encoded templates that may embed key
-- material, so their 'reqInput' renders its kind and length only
-- ('redactShown'). Operation-data inputs render normally:
-- secrets are distinguished from ordinary data, not blanket
-- hidden. Explicit inspection pattern-matches the exported
-- record (never 'Show').
instance Show Request where
  show r = "Request {reqVersion = " ++ show (reqVersion r)
    ++ ", reqFunction = " ++ show (reqFunction r)
    ++ ", reqSession = " ++ show (reqSession r)
    ++ ", reqHandle = " ++ show (reqHandle r)
    ++ ", reqInput = " ++ showInput (reqFunction r) (reqInput r)
    ++ ", reqRegions = " ++ show (reqRegions r) ++ "}"
    where
      showInput fun bs
        | fun `elem` [F_CreateObject, F_CopyObject, F_FindObjects] =
            redactShown "template" (BS.length bs)
        | otherwise = show bs

-- | A decoded request: one constructor per migrated call
-- shape, each carrying exactly its domain payload — already
-- validated at the representation boundary (FFI frame, wire codec).
-- A function/payload mismatch is unrepresentable: there is no
-- @(FunctionId, ByteString)@ pair to misalign, so the planner
-- ('Haskoki.Transition.planDecoded') never re-parses 'reqInput'.
-- Unmigrated call shapes stay on 'Request'; 'planCall' decodes the
-- migrated shapes once for byte-carrying callers and dispatches to
-- 'planDecoded'.
data DecodedRequest
  = -- | Create one object in a session from a decoded template.
    DRCreateObject
      { drSession :: !SessionId
      , drTemplate :: ![(AttributeType, AttributeValue)]
      }
  | -- | Copy one object under a decoded modifier template.
    DRCopyObject
      { drSession :: !SessionId
      , drHandle :: !ExternalHandle
      , drTemplate :: ![(AttributeType, AttributeValue)]
      }
  | -- | Find the objects matching a decoded template.
    DRFindObjects
      { drSession :: !SessionId
      , drTemplate :: ![(AttributeType, AttributeValue)]
      }
  | -- | Read decoded wanted attributes off one object.
    DRGetAttributeValue
      { drSession :: !SessionId
      , drHandle :: !ExternalHandle
      , drWanted :: ![AttributeType]
      }
  | -- | Set decoded attributes on one object, atomically.
    DRSetAttributeValue
      { drSession :: !SessionId
      , drHandle :: !ExternalHandle
      , drTemplate :: ![(AttributeType, AttributeValue)]
      }
  | -- | Initialize a classic operation from decoded init
      -- arguments (no init frame to re-parse).
    DRInit
      { drSession :: !SessionId
      , drInitFunction :: !InitFunction
      , drInitKey :: !(Maybe ExternalHandle)
      , drInitMech :: !MechanismId
      , drInitPermits :: ![Operation]
      , drInitAuth :: !Bool
      , drInitParams :: !ByteString
      }
  | -- | Initialize a recovery operation from decoded init
      -- arguments plus the caller-fixed recover shape (the
      -- modulus-width capacity, read off the key by the
      -- producer — no init frame to re-parse). Positional:
      -- the fields mirror 'DRInit' with the recover shape
      -- appended.
    DRInitRecover
      !SessionId
      !InitFunction
      !(Maybe ExternalHandle)
      !MechanismId
      ![Operation]
      !Bool
      !ByteString
      !RecoverSpec
  deriving (Eq)

-- | 'Show' redacts decoded templates (following the 'Request'
-- redaction precedent): create, copy, and find shapes carry decoded
-- templates
-- that may embed key material, so their 'drTemplate' renders its
-- kind and entry count only ('redactShown'). Wanted attribute
-- types and init parameters render normally: types name no values,
-- and init params are ordinary operation data, not secrets.
-- Explicit inspection pattern-matches the exported constructors
-- (never 'Show').
instance Show DecodedRequest where
  show (DRCreateObject sid tmpl) =
    "DRCreateObject {drSession = " ++ show sid
      ++ ", drTemplate = " ++ redactShown "template" (length tmpl) ++ "}"
  show (DRCopyObject sid h tmpl) =
    "DRCopyObject {drSession = " ++ show sid
      ++ ", drHandle = " ++ show h
      ++ ", drTemplate = " ++ redactShown "template" (length tmpl) ++ "}"
  show (DRFindObjects sid tmpl) =
    "DRFindObjects {drSession = " ++ show sid
      ++ ", drTemplate = " ++ redactShown "template" (length tmpl) ++ "}"
  show (DRGetAttributeValue sid h wanted) =
    "DRGetAttributeValue {drSession = " ++ show sid
      ++ ", drHandle = " ++ show h
      ++ ", drWanted = " ++ show wanted ++ "}"
  show (DRSetAttributeValue sid h tmpl) =
    "DRSetAttributeValue {drSession = " ++ show sid
      ++ ", drHandle = " ++ show h
      ++ ", drTemplate = " ++ redactShown "template" (length tmpl) ++ "}"
  show (DRInit sid fun key mech permits auth params) =
    "DRInit {drSession = " ++ show sid
      ++ ", drInitFunction = " ++ show fun
      ++ ", drInitKey = " ++ show key
      ++ ", drInitMech = " ++ show mech
      ++ ", drInitPermits = " ++ show permits
      ++ ", drInitAuth = " ++ show auth
      ++ ", drInitParams = " ++ show params ++ "}"
  show (DRInitRecover sid fun key mech permits auth params spec) =
    "DRInitRecover {drSession = " ++ show sid
      ++ ", drInitFunction = " ++ show fun
      ++ ", drInitKey = " ++ show key
      ++ ", drInitMech = " ++ show mech
      ++ ", drInitPermits = " ++ show permits
      ++ ", drInitAuth = " ++ show auth
      ++ ", drInitParams = " ++ show params
      ++ ", drInitRecover = " ++ show spec ++ "}"

-- | The classic init shapes: digest plus the four keyed
-- inits plus the two recovery inits. The planner function id
-- and the registry operation both derive from this one tag
-- ('initFunctionId', 'initOperation'), so an init/function
-- mismatch is unrepresentable. Message inits stay
-- on 'Request' (no FFI producer).
data InitFunction
  = InitDigest
  | InitSign
  | InitVerify
  | InitEncrypt
  | InitDecrypt
  | InitSignRecover
  | InitVerifyRecover
  deriving (Eq, Ord, Show, Enum, Bounded)

-- | The planner function id behind an init shape.
initFunctionId :: InitFunction -> FunctionId
initFunctionId f = case f of
  InitDigest -> F_DigestInit
  InitSign -> F_SignInit
  InitVerify -> F_VerifyInit
  InitEncrypt -> F_EncryptInit
  InitDecrypt -> F_DecryptInit
  InitSignRecover -> F_SignRecoverInit
  InitVerifyRecover -> F_VerifyRecoverInit

-- | The registry operation behind an init shape.
initOperation :: InitFunction -> Operation
initOperation f = case f of
  InitDigest -> OpDigest
  InitSign -> OpSign
  InitVerify -> OpVerify
  InitEncrypt -> OpEncrypt
  InitDecrypt -> OpDecrypt
  InitSignRecover -> OpSignRecover
  InitVerifyRecover -> OpVerifyRecover
