{- | Detached records.
-}
module Haskoki.Runtime.Storage.Records
  ( TokenRecord (..)
  , CredentialRecord (..)
  , ObjectRecord (..)
  , ObjectPut (..)
  , JobBody (..)
  , JobRecord (..)
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Map.Strict (Map)
import Data.Word (Word64)
import Haskoki.Attribute (AttributeType (..), AttributeValue (..))
import Haskoki.Runtime.Attach (JobExecState (..))
import Haskoki.Session
  ( TokenAuth (..)
  )
import Haskoki.Types
  ( Generation (..)
  , ObjectId (..)
  , ReturnCode (..)
  , Revision (..)
  , SlotId (..)
  , TokenId (..)
  , redactShown
  )

-- ---------------------------------------------------------------------------
-- Records
-- ---------------------------------------------------------------------------

-- | One persisted token: stable identity, slot assignment,
-- generation, label, and the DURABLE authentication half (retry
-- counters and lock flags). The transient half (active login,
-- principal, epoch) is scrubbed at the commit boundary and never
-- encoded, so reopening never restores an authenticated session.
data TokenRecord = TokenRecord
  { trId :: !TokenId
  , trSlot :: !SlotId
  , trGeneration :: !Generation
  , trLabel :: !String
  , trAuth :: !TokenAuth
  } deriving (Eq, Show)

-- | One persisted token credential: the provisioned SO PIN
-- (always present once the row exists) and the provisioned user
-- PIN ('Nothing' = uninitialized: no user login can succeed
-- until the SO sets one). At most one row per token. A stored
-- token gets its row when it is seeded (the catalog PINs, in the
-- seed transaction), and from then on the row is its only
-- credential: config PIN edits never replace it, and a stored
-- token without a row serves no login (a legacy store).
-- The row is owned by its token like objects and jobs: dropping
-- the token removes it. A token reset keeps it (the durable
-- credential always wins), unlike the reset token's objects and
-- jobs.
data CredentialRecord = CredentialRecord
  { crToken :: !TokenId
  , crSoPin :: !ByteString
  , crUserPin :: !(Maybe ByteString)
  } deriving (Eq)

-- | 'Show' redacts both PINs: each renders its kind and length
-- only ('redactShown'); the home token renders normally.
-- Explicit inspection pattern-matches the exported record
-- (never 'Show').
instance Show CredentialRecord where
  show c = "CredentialRecord {crToken = " ++ show (crToken c)
    ++ ", crSoPin = " ++ redactShown "pin" (BS.length (crSoPin c))
    ++ ", crUserPin = " ++ showPin (crUserPin c) ++ "}"
    where
      showPin Nothing = "Nothing"
      showPin (Just bs) = "Just " ++ redactShown "pin" (BS.length bs)

-- | One persisted token object: stable logical id, home token,
-- class\/key-type keys, the canonical attribute document, typed
-- key-material encoding, and revision. Session objects are never
-- stored; external handles are never stored (they are minted by the
-- live model on reload).
data ObjectRecord = ObjectRecord
  { orId :: !ObjectId
  , orToken :: !TokenId
  , orClass :: !Word64
  , orKeyType :: !(Maybe Word64)
  , orAttrs :: !(Map AttributeType AttributeValue)
  , orMaterialEncoding :: !String
  , orMaterial :: !(Maybe ByteString)
  , orRevision :: !Revision
  } deriving (Eq)

-- | 'Show' redacts the material blob: 'orMaterial' renders
-- its kind and length only ('redactShown'); the attribute map
-- renders through the redacted 'AttributeValue' instance. All
-- other fields render normally. Explicit inspection
-- pattern-matches the exported record (never 'Show').
instance Show ObjectRecord where
  show o = "ObjectRecord {orId = " ++ show (orId o)
    ++ ", orToken = " ++ show (orToken o)
    ++ ", orClass = " ++ show (orClass o)
    ++ ", orKeyType = " ++ show (orKeyType o)
    ++ ", orAttrs = " ++ show (orAttrs o)
    ++ ", orMaterialEncoding = " ++ show (orMaterialEncoding o)
    ++ ", orMaterial = " ++ showMat (orMaterial o)
    ++ ", orRevision = " ++ show (orRevision o) ++ "}"
    where
      showMat Nothing = "Nothing"
      showMat (Just bs) = "Just " ++ redactShown "key" (BS.length bs)

-- | One object write: the expected current revision ('Nothing' =
-- the object must not exist yet) plus the replacement record.
data ObjectPut = ObjectPut
  { opExpected :: !(Maybe Revision)
  , opRecord :: !ObjectRecord
  } deriving (Eq, Show)

-- | The durable job body: either a deterministic pending recipe
-- (a named recipe plus owned parameter bytes, replayable after
-- restart) or a fully prepared owned result (a verdict plus owned
-- result bytes, deliverable without any live context). Real opaque
-- native contexts are never serialized here: an unsaveable job is
-- an explicit outcome at the lifecycle layer, not a memory image
-- described as resumable state.
data JobBody
  = JobPending { jbRecipe :: !String, jbParams :: !ByteString }
  | JobResult { jbCode :: !ReturnCode, jbBytes :: !ByteString }
  deriving (Eq)

-- | 'Show' redacts job bytes: recipe parameters may embed
-- templates and prepared results may embed a ready-but-unfinished
-- keygen answer, so both byte fields render their kind and length
-- only ('redactShown'). Recipe names and return codes render
-- normally. Explicit inspection pattern-matches the exported
-- constructors (never 'Show').
instance Show JobBody where
  show (JobPending name params) =
    "JobPending {jbRecipe = " ++ show name
      ++ ", jbParams = " ++ redactShown "params" (BS.length params) ++ "}"
  show (JobResult code bs) =
    "JobResult {jbCode = " ++ show code
      ++ ", jbBytes = " ++ redactShown "result" (BS.length bs) ++ "}"

-- | One persisted detached job: a stable module\/store-wide
-- persistent id (never a recycled row number), the home token and
-- the token generation the id is valid under (reset kills old
-- ids), the function name, the execution state, and the body.
data JobRecord = JobRecord
  { jrPersistentId :: !Word64
  , jrToken :: !TokenId
  , jrTokenGeneration :: !Generation
  , jrFunction :: !String
  , jrState :: !JobExecState
  , jrBody :: !JobBody
  } deriving (Eq, Show)
