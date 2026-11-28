{- | Haskoki.Operation.Derive.Stamping: protection-flag stamping for derived keys.
-}
module Haskoki.Operation.Derive.Stamping
  ( stampDerived
  ) where


import qualified Data.Map.Strict as Map

import Haskoki.Attribute (AttributeType (..), AttributeValue (..))
import Haskoki.Object (effectiveExtractable, effectiveSensitive)

-- | Stamp one derived SECRET key: omitted protection flags
-- inherit the source-effective values (the base key, plus the aux
-- key where the mechanism takes one), and history derives from
-- the child flags and the source history: always-sensitive is the
-- child sensitive mark AND the sources' always rows;
-- never-extractable is the child unextractable mark AND the
-- sources' never rows; local is false and the mechanism id reads
-- unavailable. Explicit caller values always win. Sources read
-- through the effective view (a source without stored history
-- reads false). Data outputs stamp nothing; the public row stamps
-- its own forced set.
stampDerived
  :: Map.Map AttributeType AttributeValue
  -> Maybe (Map.Map AttributeType AttributeValue)
  -> Map.Map AttributeType AttributeValue
  -> Map.Map AttributeType AttributeValue
stampDerived base mAux attrs =
  Map.insert AttrKeyGenMechanism (ValULong maxBound)
    (Map.insert AttrLocal (ValBool False)
      (Map.insert AttrNeverExtractable (ValBool never)
        (Map.insert AttrAlwaysSensitive (ValBool always) filled)))
  where
    sensSrc = effectiveSensitive base || maybe False effectiveSensitive mAux
    extSrc = effectiveExtractable base && maybe True effectiveExtractable mAux
    alwaysSrc = histTrue AttrAlwaysSensitive base
      && maybe True (histTrue AttrAlwaysSensitive) mAux
    neverSrc = histTrue AttrNeverExtractable base
      && maybe True (histTrue AttrNeverExtractable) mAux
    filled = foldr insertMissing attrs [(AttrSensitive, sensSrc), (AttrExtractable, extSrc)]
    sens = Map.lookup AttrSensitive filled == Just (ValBool True)
    ext = Map.lookup AttrExtractable filled == Just (ValBool True)
    always = sens && alwaysSrc
    never = not ext && neverSrc
    insertMissing (t, v) acc
      | Map.member t acc = acc
      | otherwise = Map.insert t (ValBool v) acc
    -- Stored-true-or-false reads the same as the effective view
    -- for key objects (absent history defaults false); every
    -- derive source is a key.
    histTrue t m = Map.lookup t m == Just (ValBool True)
