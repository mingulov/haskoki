{- | Pure exact-output planner: bounded region bindings, typed native
write sets, and per-result operation dispositions.

The planner consumes normalized requests ('OutputRegion' intents from
"Haskoki.Request") and per-region outcomes, and produces explicit
write sets: what to write, where (nested paths), which lengths to
report, and what happens to each operation afterwards. It never
touches caller memory; the FFI encode side ("Haskoki.FFI.Encode")
applies these plans to bounded buffers.

Part 1: one-shot consumption ('planOneShot'): size queries and
short-buffer retries never consume the input and never write; only
the exact call consumes (once) and terminates the operation.

Part 2: bounded region bindings ('bindRegions'), scalar\/handle\/
byte\/nested region plans ('planOutputs'), and checked length
conversion ('checkedULong', 'checkedTotal') with overflow rejection.

Part 3: batched multi-leg transactions ('planBatch') with partial
reads and per-result operation dispositions: a failed leg releases
only its own engine resource while sibling legs continue, and
retryable short buffers always keep their resource.

Part 4: the generated-IV vertical slice ('planGeneratedIV'):
mechanism-length-checked nested writeback into params buffers.
-}
module Haskoki.Output
  ( OutputPlan (..)
  , TypedWrite (..)
  , WritePayload (..)
  , typedWriteBytes
  , OpDisposition (..)
  , ResultDisposition (..)
  , planOneShot
  , maxOutputBytes
  , LengthError (..)
  , checkedULong
  , checkedTotal
  , DataSource (..)
  , RegionOutcome (..)
  , Binding (..)
  , BindError (..)
  , bindRegions
  , planOutputs
  , LegResult (..)
  , planBatch
  , planGeneratedIV
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Word (Word64)

import Haskoki.Attribute (AttributeValue (..), encodeValue)
import Haskoki.Object (encodeHandle)
import Haskoki.Request (OutputIntent (..), OutputRegion (..))
import Haskoki.Types
  ( BindingId (..)
  , Consumption (..)
  , EngineResourceId
  , ExternalHandle
  , OpState (..)
  , ReturnCode (..)
  )

-- | The explicit plan for one call's outputs: the overall code, the
-- typed writes to apply, the required lengths to report per leaf
-- path (size answers survive short buffers), one disposition per
-- result, and diagnostic reasons.
data OutputPlan = OutputPlan
  { opCode :: !ReturnCode
  , opWrites :: ![TypedWrite]
  , opLengths :: ![([String], Word64)]
  , opDispositions :: ![ResultDisposition]
  , opReasons :: ![String]
  } deriving (Eq, Show)

-- | One permitted typed write: the nested path it targets, the
-- region it was planned from, and the typed payload. Length
-- conversions and capacity checks happen before this value exists.
data TypedWrite = TypedWrite
  { twPath :: ![String]
  , twRegion :: !OutputRegion
  , twPayload :: !WritePayload
  } deriving (Eq, Show)

-- | Encode a typed write's payload to native bytes: raw bytes as-is,
-- handles via the canonical 'encodeHandle', ULongs via 8-byte
-- big-endian over the whole 'Word64' domain (total, never
-- wrapping). 'Nothing' is retained for future unencodable payload
-- kinds only; every current payload encodes.
typedWriteBytes :: TypedWrite -> Maybe ByteString
typedWriteBytes w = case twPayload w of
  PayloadBytes bs -> Just bs
  PayloadULong v -> Just (encodeValue (ValULong v))
  PayloadHandle h -> Just (encodeHandle h)

-- | A typed payload: raw bytes, an unsigned long, or an external
-- handle value.
data WritePayload
  = PayloadBytes !ByteString
  | PayloadULong !Word64
  | PayloadHandle !ExternalHandle
  deriving (Eq, Show)

-- | What happens to an operation (or its engine resource) after one
-- result: keep it for retries, terminate it with no resource, or
-- release exactly one engine resource id. Per-result dispositions
-- replace generic cleanup: a failed leg releases only its own
-- resource while sibling legs continue.
data OpDisposition
  = OpKeep
  | OpTerminate
  | OpRelease !EngineResourceId
  deriving (Eq, Show)

-- | One result's disposition: the leaf path, that result's own code,
-- and the operation disposition.
data ResultDisposition = ResultDisposition
  { rdPath :: ![String]
  , rdCode :: !ReturnCode
  , rdDisposition :: !OpDisposition
  } deriving (Eq, Show)

-- | Plan one call of a one-shot byte operation (the sign-final
-- slice): @name@ is the region, @out@ the full required output.
--
-- * 'IntentNull' (size query): report the required length, write
--   nothing, keep the op, consume nothing.
-- * Short buffer: @CKR_BUFFER_TOO_SMALL@, still report the required
--   length, write nothing, keep the op for retry, consume nothing.
-- * Sufficient buffer: write the payload, consume exactly once,
--   terminate the op.
-- * 'OpDead': @CKR_GENERAL_ERROR@, nothing written, nothing consumed.
planOneShot
  :: OpState -> String -> ByteString -> OutputIntent -> (OpState, OutputPlan)
planOneShot OpDead name _ _ =
  ( OpDead
  , OutputPlan
      { opCode = CKR_GENERAL_ERROR
      , opWrites = []
      , opLengths = []
      , opDispositions = [ResultDisposition [name] CKR_GENERAL_ERROR OpTerminate]
      , opReasons = ["operation already terminated"]
      }
  )
planOneShot (OpLive (Consumption n)) name out intent =
  let required :: Word64
      required = fromIntegral (BS.length out)
      region = RegionBytes name intent
      disp code d = [ResultDisposition [name] code d]
  in case intent of
    IntentNull ->
      ( OpLive (Consumption n)
      , OutputPlan
          { opCode = CKR_OK
          , opWrites = []
          , opLengths = [([name], required)]
          , opDispositions = disp CKR_OK OpKeep
          , opReasons = ["size query"]
          }
      )
    IntentBuffer cap
      | cap < required ->
          ( OpLive (Consumption n)
          , OutputPlan
              { opCode = CKR_BUFFER_TOO_SMALL
              , opWrites = []
              , opLengths = [([name], required)]
              , opDispositions = disp CKR_BUFFER_TOO_SMALL OpKeep
              , opReasons = ["short buffer: retry with the reported length"]
              }
          )
      | otherwise ->
          ( OpLive (Consumption (n + 1))
          , OutputPlan
              { opCode = CKR_OK
              , opWrites = [TypedWrite [name] region (PayloadBytes out)]
              , opLengths = [([name], required)]
              , opDispositions = disp CKR_OK OpTerminate
              , opReasons = ["exact write; input consumed"]
              }
          )

-- ---------------------------------------------------------------------------
-- Part 2: bounds, bindings, and region plans
-- ---------------------------------------------------------------------------

-- | Bound on any single planned output (16 MiB). Sources past this
-- bound reject with 'CKR_ARGUMENTS_BAD'; the bound also caps every
-- byte leaf's binding.
maxOutputBytes :: Word64
maxOutputBytes = 16 * 1024 * 1024

-- | A rejected length conversion: negative, or past the 64-bit
-- native bound.
data LengthError
  = LengthNegative !Integer
  | LengthTooLarge !Integer
  deriving (Eq, Show)

-- | Checked conversion from an unbounded computed length to a native
-- 64-bit length. Model lengths are computed in 'Integer' precisely
-- so this check can reject negatives and overflow instead of
-- wrapping them.
checkedULong :: Integer -> Either LengthError Word64
checkedULong n
  | n < 0 = Left (LengthNegative n)
  | n > toInteger (maxBound :: Word64) = Left (LengthTooLarge n)
  | otherwise = Right (fromIntegral n)

-- | Checked total of native lengths: summed in 'Integer', then
-- converted, so wrap-around can never hide an oversized total.
checkedTotal :: [Word64] -> Either LengthError Word64
checkedTotal = checkedULong . sum . map toInteger

-- | A normalized per-region outcome source: owned bytes, an unsigned
-- long, an external handle, or nested field sources keyed by field
-- name.
data DataSource
  = SourceBytes !ByteString
  | SourceULong !Word64
  | SourceHandle !ExternalHandle
  | SourceNested ![(String, DataSource)]
  deriving (Eq, Show)

-- | One region paired with its outcome: either a per-region failure
-- code or the source to plan from.
data RegionOutcome = RegionOutcome
  { roRegion :: !OutputRegion
  , roResult :: !(Either ReturnCode DataSource)
  } deriving (Eq, Show)

-- | One bound leaf binding: the assigned id, the nested path, the
-- region it was bound from, and the most source bytes this leaf
-- will ever accept (8 for scalars\/handles, 'maxOutputBytes' for
-- byte leaves).
data Binding = Binding
  { bindId :: !BindingId
  , bindPath :: ![String]
  , bindRegion :: !OutputRegion
  , bindBound :: !Word64
  } deriving (Eq, Show)

-- | Binding failure: two leaves share one path, so the encoder
-- could not tell their write targets apart.
newtype BindError = BindDuplicate [String]
  deriving (Eq, Show)

-- | Bind regions to bound leaves: nested regions flatten to their
-- leaves with extended paths, ids are assigned 0.. in traversal
-- order, and colliding leaf paths are rejected (first collision in
-- traversal order wins).
bindRegions :: [OutputRegion] -> Either BindError [Binding]
bindRegions regions = assign 0 [] (concatMap (leafOf []) regions)
  where
    assign
      :: Int -> [[String]] -> [([String], OutputRegion, Word64)]
      -> Either BindError [Binding]
    assign _ _ [] = Right []
    assign n seen ((path, region, bound) : rest)
      | path `elem` seen = Left (BindDuplicate path)
      | otherwise =
          (Binding (BindingId n) path region bound :)
            <$> assign (n + 1) (path : seen) rest

-- | The bound leaves of one region under a path prefix.
leafOf :: [String] -> OutputRegion -> [([String], OutputRegion, Word64)]
leafOf prefix region = case region of
  RegionScalar name -> [(prefix ++ [name], region, 8)]
  RegionHandle name -> [(prefix ++ [name], region, 8)]
  RegionBytes name _ -> [(prefix ++ [name], region, maxOutputBytes)]
  RegionNested name fields -> concatMap (leafOf (prefix ++ [name])) fields

-- | One planned leg (internal): its own code plus the writes,
-- reported lengths, dispositions, and reasons it contributes.
data LegPlan = LegPlan
  { lpCode :: !ReturnCode
  , lpWrites :: ![TypedWrite]
  , lpLengths :: ![([String], Word64)]
  , lpDisps :: ![ResultDisposition]
  , lpReasons :: ![String]
  }

-- | Plan a batch of region outcomes: 'planBatch' with no engine
-- resource behind any leg.
planOutputs :: [RegionOutcome] -> OutputPlan
planOutputs = planBatch . map toLeg
  where
    toLeg (RegionOutcome region result) = LegResult region result Nothing

-- | One transaction leg: a region, its outcome, and the engine
-- resource behind it, if any. Only terminally failed legs release
-- their resource; 'CKR_OK' and retryable 'CKR_BUFFER_TOO_SMALL'
-- legs always keep it.
data LegResult = LegResult
  { legRegion :: !OutputRegion
  , legOutcome :: !(Either ReturnCode DataSource)
  , legResource :: !(Maybe EngineResourceId)
  } deriving (Eq, Show)

-- | Plan a multi-leg transaction. Successful legs contribute their
-- writes (partial reads: successes are delivered under a failing
-- overall code); failed legs contribute no writes but keep their
-- own disposition and code. The overall code is the first leg
-- failure in order, else 'CKR_OK'. Regions that fail to bind
-- (colliding leaf paths) reject the whole batch with
-- 'CKR_ARGUMENTS_BAD'.
planBatch :: [LegResult] -> OutputPlan
planBatch legs = case bindRegions (map legRegion legs) of
  Left (BindDuplicate path) -> OutputPlan
    { opCode = CKR_ARGUMENTS_BAD
    , opWrites = []
    , opLengths = []
    , opDispositions = []
    , opReasons = ["duplicate output path: " ++ show path]
    }
  Right _ -> combineLegs (map planTransactionLeg legs)
  where
    combineLegs :: [LegPlan] -> OutputPlan
    combineLegs plans = OutputPlan
      { opCode = case [lpCode l | l <- plans, lpCode l /= CKR_OK] of
          [] -> CKR_OK
          (c : _) -> c
      , opWrites = concatMap lpWrites plans
      , opLengths = concatMap lpLengths plans
      , opDispositions = concatMap lpDisps plans
      , opReasons = concatMap lpReasons plans
      }
    planTransactionLeg :: LegResult -> LegPlan
    planTransactionLeg leg' =
      disposeLeg (legResource leg')
        (planLeg (RegionOutcome (legRegion leg') (legOutcome leg')))

-- | Attach a leg's engine-resource disposition: a terminally failed
-- leg releases its resource on its first failed result; successful
-- and retryable-short legs keep it. Exactly one result per leg
-- carries the release, so the runtime frees each named resource
-- once while sibling legs continue.
disposeLeg :: Maybe EngineResourceId -> LegPlan -> LegPlan
disposeLeg mRes leg'
  | lpCode leg' == CKR_OK = leg'
  | lpCode leg' == CKR_BUFFER_TOO_SMALL = leg'
  | otherwise = case mRes of
      Nothing -> leg'
      Just rid -> leg' { lpDisps = releaseFirst rid (lpDisps leg') }
  where
    releaseFirst :: EngineResourceId -> [ResultDisposition] -> [ResultDisposition]
    releaseFirst _ [] = []
    releaseFirst rid (d : ds)
      | rdCode d /= CKR_OK = d { rdDisposition = OpRelease rid } : ds
      | otherwise = d : releaseFirst rid ds

-- ---------------------------------------------------------------------------
-- Part 4: generated-IV nested writeback
-- ---------------------------------------------------------------------------

-- | Plan a generated-IV writeback into a nested mechanism-params
-- buffer: @mech@ names the params struct, @wanted@ is the
-- mechanism's exact IV length, @iv@ the generated bytes. A
-- wrong-length IV rejects with 'CKR_ARGUMENTS_BAD' before any
-- planning; otherwise the IV plans as a nested @iv@ field under
-- @mech@ (size-query\/short\/exact per the caller's intent).
planGeneratedIV :: String -> Word64 -> ByteString -> OutputIntent -> OutputPlan
planGeneratedIV mech wanted iv intent
  | fromIntegral (BS.length iv) /= wanted = OutputPlan
      { opCode = CKR_ARGUMENTS_BAD
      , opWrites = []
      , opLengths = []
      , opDispositions =
          [ResultDisposition [mech, "iv"] CKR_ARGUMENTS_BAD OpKeep]
      , opReasons =
          ["iv length " ++ show (BS.length iv)
            ++ " mismatches mechanism length " ++ show wanted]
      }
  | otherwise = planOutputs
      [ RegionOutcome
          (RegionNested mech [RegionBytes "iv" intent])
          (Right (SourceNested [("iv", SourceBytes iv)]))
      ]

-- | Plan one region outcome: a failed source plans no writes under
-- its own code; a live source must match its region's kind.
planLeg :: RegionOutcome -> LegPlan
planLeg (RegionOutcome region result) = case result of
  Left code -> LegPlan
    { lpCode = code
    , lpWrites = []
    , lpLengths = []
    , lpDisps = [ResultDisposition [regionName region] code OpKeep]
    , lpReasons = ["source failed: " ++ show code]
    }
  Right src -> matchRegion [] region src

-- | Match one live source against its region under a path prefix.
matchRegion :: [String] -> OutputRegion -> DataSource -> LegPlan
matchRegion prefix region src = case (region, src) of
  (RegionScalar name, SourceULong v) ->
    let path = prefix ++ [name]
    in ok path [TypedWrite path region (PayloadULong v)] [(path, 8)]
  (RegionHandle name, SourceHandle h) ->
    let path = prefix ++ [name]
    in ok path [TypedWrite path region (PayloadHandle h)] [(path, 8)]
  (RegionBytes name intent, SourceBytes bs) ->
    let path = prefix ++ [name]
        required = fromIntegral (BS.length bs) :: Word64
    in if required > maxOutputBytes
      then bad path "byte source past the output bound"
      else case intent of
        IntentNull -> LegPlan
          { lpCode = CKR_OK
          , lpWrites = []
          , lpLengths = [(path, required)]
          , lpDisps = [ResultDisposition path CKR_OK OpKeep]
          , lpReasons = ["size query"]
          }
        IntentBuffer cap
          | cap < required -> LegPlan
              { lpCode = CKR_BUFFER_TOO_SMALL
              , lpWrites = []
              , lpLengths = [(path, required)]
              , lpDisps = [ResultDisposition path CKR_BUFFER_TOO_SMALL OpKeep]
              , lpReasons = ["short buffer"]
              }
          | otherwise -> ok path [TypedWrite path region (PayloadBytes bs)]
              [(path, required)]
  (RegionNested name fields, SourceNested pairs) ->
    let legs = map (planField (prefix ++ [name]) pairs) fields
    in LegPlan
      { lpCode = case [lpCode l | l <- legs, lpCode l /= CKR_OK] of
          [] -> CKR_OK
          (c : _) -> c
      , lpWrites = concatMap lpWrites legs
      , lpLengths = concatMap lpLengths legs
      , lpDisps = concatMap lpDisps legs
      , lpReasons = concatMap lpReasons legs
      }
  _ -> bad (prefix ++ [regionName region])
    ("region/source kind mismatch: " ++ show region)
  where
    ok path writes lengths = LegPlan
      { lpCode = CKR_OK
      , lpWrites = writes
      , lpLengths = lengths
      , lpDisps = [ResultDisposition path CKR_OK OpKeep]
      , lpReasons = []
      }
    bad path why = LegPlan
      { lpCode = CKR_ARGUMENTS_BAD
      , lpWrites = []
      , lpLengths = []
      , lpDisps = [ResultDisposition path CKR_ARGUMENTS_BAD OpKeep]
      , lpReasons = [why]
      }
    planField parent pairs field = case lookup (regionName field) pairs of
      Nothing -> bad (parent ++ [regionName field]) "nested field missing from source"
      Just src' -> matchRegion parent field src'
