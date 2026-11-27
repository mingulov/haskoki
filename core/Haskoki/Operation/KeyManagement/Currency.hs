{- | KeyManagement plan currency: pending-work admission, the
finishers that publish driver answers, and material storage.

Imports the Types/Codes/Codec leaves and Template. Re-exported
via the shell.
-}
{-# LANGUAGE OverloadedStrings #-}
module Haskoki.Operation.KeyManagement.Currency
  ( workFunction
  , pendingWantsTrusted
  , admitPending
  , pendingObjects
  , publishPending
  , keyPairCompatible
  , finishWork
  , storeMaterial
  , derivedNeedsParity
  , storeDerivedMaterial
  , stampPairComponents
  , stampParamsObject
  , paramsReason
  , bitsOf
  , splitLens
  ) where

import Control.Monad (guard)
import Data.Bits (countLeadingZeros)
import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import qualified Data.Map.Strict as Map
import Data.Word (Word64)
import Haskoki.Attribute
  ( AttributeType (..)
  , AttributeValue (..)
  , encodeValue
  )
import Haskoki.Der (RsaCrt (..), derOctet, dhPkcs8Fields, dhSpkiFields, dsaPkcs8Fields, dsaSpkiFields, ecSpkiFields, eddsaPkcs8Fields, eddsaSpkiFields, edwardsNameOfOid, mldsaPkcs8Fields, mldsaSpkiFields, mlkemPkcs8Fields, mlkemSpkiFields, montgomeryNameOfOid, montgomeryPkcs8Fields, montgomerySpkiFields, parseDsaParams, parseRsaPrivate, parseRsaPublic, slhdsaPkcs8Fields, slhdsaSpkiFields, spkiPoint)
import Haskoki.Model (Model (..), SessionState (..))
import Haskoki.Object (mergedIsPrivate)
import Haskoki.Operation.Effect
  ( CryptoEffect (..)
  , CryptoResult (..)
  , TypedError (..)
  , interpretError
  , keptCause
  )
import Haskoki.Operation.KeyManagement.Codec
import Haskoki.Operation.KeyManagement.Codes
import Haskoki.Operation.KeyManagement.Template
import Haskoki.Operation.KeyManagement.Types
import Haskoki.Outcome
  ( DeltaOp (..)
  , NativeOutput (..)
  , PlanResult (..)
  , PreparedCommit (..)
  , Rejection (..)
  , StateDelta (..)
  )
import Haskoki.Recipe.Pbe (pbeDesParity)
import Haskoki.Recipe.RsaX509 (x509Tail)
import Haskoki.Request (FunctionId (..), OutputIntent (..), OutputRegion (..))
import Haskoki.Session (SessionLogin (LoginSO), admitCode, admitPrivate, admitWritable)
import Haskoki.Types
  ( ExternalHandle (..)
  , ObjectId (..)
  , ReturnCode (..)
  )


-- | The C function a unit of key work belongs to (error
-- attribution for finishers). Total: every constructor maps.
-- PwBlobOut covers both wrap planners ('planWrapKey' and
-- 'planAuthWrapKey'): authenticated wrap is a C_WrapKey shape,
-- not a distinct C entry. Likewise PwUnwrap covers
-- 'planUnwrapKey' and 'planAuthUnwrapKey' under C_UnwrapKey.
workFunction :: PendingWork -> FunctionId
workFunction work = case work of
  PwGeneratePair {} -> F_GenerateKeyPair
  PwGenerateKey {} -> F_GenerateKey
  PwGenerateKeyIv {} -> F_GenerateKey
  PwEncaps {} -> F_EncapsulateKey
  PwDecaps {} -> F_DecapsulateKey
  PwBlobOut {} -> F_WrapKey
  PwUnwrap {} -> F_UnwrapKey
  PwUnwrapRaw {} -> F_UnwrapKey
  PwUnwrapPad8 {} -> F_UnwrapKey
  PwUnwrapTail {} -> F_UnwrapKey
  PwDerive {} -> F_DeriveKey
  PwDeriveIv {} -> F_DeriveKey
  PwDerivePub {} -> F_DeriveKey

-- | Whether any pending object requests @CKA_TRUSTED=true@. Shared
-- by the submit-time gate ('admitPending') and the completion-time
-- gate ('finishWork'): only the security officer may create or
-- complete such objects (both refuse non-SO sessions with
-- 'CKR_ATTRIBUTE_READ_ONLY' and an empty delta).
pendingWantsTrusted :: PendingWork -> Bool
pendingWantsTrusted pw = any isTrusted (pendingObjects pw)
  where
    isTrusted po =
      Map.lookup AttrTrusted (poAttrs po) == Just (ValBool True)

-- | Writability over the objects a key plan will create: read-only
-- sessions admit session objects and deny token objects
-- (PKCS #11 Base v3.0 §5.7.1-5.7.3, via 'admitWritable').
-- Length queries and wrap paths create nothing and always admit.
admitPending :: SessionState -> PendingWork -> Either KeyDeny ()
admitPending st pw =
  case admitPrivate (ssLogin st) wantsPrivate of
    Left deny -> Left (KeyDeny (admitCode deny)
      "only the normal user may create private objects")
    Right () -> case admitWritable (ssReadOnly st) wantsToken of
      Left deny -> Left (KeyDeny (admitCode deny)
        "read-only session cannot create token objects")
      Right ()
        | wantsTrusted
        , ssLogin st /= LoginSO -> Left (KeyDeny CKR_ATTRIBUTE_READ_ONLY
            "only the security officer may create TRUSTED=true objects")
        | otherwise -> Right ()
  where
    pos = pendingObjects pw
    wantsToken = any isToken pos
    isToken po = case poOwner po of
      Nothing -> True
      Just _ -> False
    wantsPrivate = any isPrivate pos
    isPrivate po = mergedIsPrivate (poAttrs po)
    wantsTrusted = pendingWantsTrusted pw

-- | Objects a pending work item will create (queries and pure
-- bytes-out work create none).
pendingObjects :: PendingWork -> [PendingObject]
pendingObjects pw = case pw of
  PwGeneratePair pub priv -> [pub, priv]
  PwGenerateKey k -> [k]
  PwGenerateKeyIv k _ -> [k]
  PwEncaps s _ _ -> [s]
  PwDecaps s -> [s]
  PwBlobOut _ -> []
  PwUnwrap k -> [k]
  PwUnwrapRaw k -> [k]
  PwUnwrapPad8 k -> [k]
  PwUnwrapTail k _ _ -> [k]
  PwDerive pos _ -> pos
  PwDeriveIv pos _ _ -> pos
  PwDerivePub po _ -> [po]

-- | Publish pending objects as one atomic delta: every object
-- validates before any id or handle is allocated, so a bad entry
-- fails the whole batch with zero allocation. Ids and handles
-- allocate deterministically from the model counters in list order.
publishPending
  :: Model -> SessionState -> [PendingObject] -> Either KeyDeny (StateDelta, [ExternalHandle])
publishPending model _st pos = do
  mapM_ validPending pos
  let oids = [ObjectId (mNextObject model + i) | i <- [0 .. length pos - 1]]
      hs = [ExternalHandle (mNextHandle model + i) | i <- [0 .. length pos - 1]]
      ops = concat
        [ [ DeltaCreateObjectFull oid (poAttrs po) (poOwner po) (poSlot po)
          , DeltaBindHandle h oid
          ]
        | (po, oid, h) <- zip3 pos oids hs
        ]
  pure (StateDelta ops, hs)
  where
    validPending :: PendingObject -> Either KeyDeny ()
    validPending po
      | Map.member AttrClass (poAttrs po) = Right ()
      | otherwise = Left (KeyDeny CKR_TEMPLATE_INCOMPLETE
          "pending object lacks a class")

-- | Whether a pending-work/effect pair is executable:
-- the validated constructor for executable key pairs. Each
-- 'PendingWork' shape accepts exactly the effects whose answers
-- its finisher can consume (see 'finishWork'); generation pairs
-- additionally check the framed 'GenArgs' (single-key vs
-- pair-key). Execution sites ('runKeyPlan', the async drive)
-- refuse incoherent pairs BEFORE running any effect; the
-- planners below produce only coherent pairs (the suite proves
-- it), and 'finishWork' keeps its answer-shape defenses as
-- defense in depth.
keyPairCompatible :: PendingWork -> CryptoEffect -> Bool
keyPairCompatible (PwGeneratePair _ _) (FxGenerateKey _ _ input) =
  case decodeGenArgs input of
    Just (GenEc _) -> True
    Just (GenRsa _ _) -> True
    Just (GenMlKem _) -> True
    Just (GenDsaKeypair _) -> True
    Just (GenDhKeypair _) -> True
    Just (GenEdwardsKeypair _) -> True
    Just (GenMontgomeryKeypair _) -> True
    Just (GenMlDsa _) -> True
    Just (GenSlhDsa _) -> True
    _ -> False
keyPairCompatible (PwGenerateKey _) (FxGenerateKey _ _ input) =
  case decodeGenArgs input of
    Just (GenAes _) -> True
    Just (GenBytes _) -> True
    Just (GenParityBytes _) -> True
    Just (GenTlsPremaster _ _) -> True
    Just (GenWtlsPremaster _ _) -> True
    Just (GenPbkd2 _) -> True
    Just (GenDsaParams _ _) -> True
    Just (GenPbe _) -> True
    _ -> False
keyPairCompatible (PwGenerateKeyIv _ _) (FxGenerateKey _ _ input) =
  case decodeGenArgs input of
    Just (GenPbe _) -> True
    _ -> False
keyPairCompatible (PwBlobOut _) (FxWrap _ _ _ _) = True
keyPairCompatible (PwBlobOut _) (FxAuthWrap _ _ _ _) = True
keyPairCompatible (PwUnwrap _) (FxUnwrap _ _ _ _) = True
keyPairCompatible (PwUnwrap _) (FxAuthUnwrap _ _ _ _) = True
keyPairCompatible (PwUnwrapRaw _) (FxUnwrap _ _ _ _) = True
keyPairCompatible (PwUnwrapPad8 _) (FxUnwrap _ _ _ _) = True
keyPairCompatible (PwUnwrapTail _ _ _) (FxUnwrap _ _ _ _) = True
keyPairCompatible (PwEncaps _ _ _) (FxKemEncaps _ _ _ _) = True
keyPairCompatible (PwDecaps _) (FxKemDecaps _ _ _ _) = True
keyPairCompatible (PwDerive _ _) (FxDerive _ _ _ _ _ _) = True
keyPairCompatible (PwDeriveIv _ _ _) (FxDerive _ _ _ _ _ _) = True
keyPairCompatible (PwDerivePub _ _) (FxDerive _ _ _ _ _ _) = True
keyPairCompatible _ _ = False

-- | Finish planned work against the driver's answer. On bytes the
-- material lands on the pending objects and the whole batch
-- publishes through 'publishPending' (all-or-nothing: a malformed
-- answer or a validation failure yields zero objects); on any
-- driver failure the mapped code rejects with an empty delta.
finishWork :: Model -> SessionState -> PendingWork -> CryptoResult -> PlanResult
finishWork model st pw res
  -- Completion-time SO-only TRUSTED gate (T-C03f round 2): the
  -- submit-time check in 'admitPending' covers sync dispatch, but
  -- async completions and detached replays publish through this
  -- finisher — refuse before any shape dispatch, with an empty
  -- delta (no partial publication).
  | pendingWantsTrusted pw
  , ssLogin st /= LoginSO = rejectOf (KeyDeny CKR_ATTRIBUTE_READ_ONLY
      "only the security officer may complete TRUSTED=true objects")
  | otherwise = case (pw, res) of
  (PwGeneratePair pub priv, GotBytes bs) -> case decodeKeyPair bs of
    Just (privM, Just pubM) ->
      case stampPairComponents pub priv pubM privM of
        Just (pub', priv') ->
          publish (storeMaterial pubM pub') (storeMaterial privM priv')
        Nothing -> internal "keypair answer material fails component decode"
    _ -> internal "keypair answer is not a framed private/public pair"
  (PwEncaps sec ctLen ssLen, GotBytes bs)
    | BS.length bs == ctLen + ssLen ->
        let (ct, ss) = BS.splitAt ctLen bs
        in publish1 (storeMaterial ss sec)
            [NativeOutput (RegionBytes "ciphertext" IntentNull) ct]
            ["encapsulated " ++ show ctLen ++ " ciphertext bytes"]
    | otherwise -> internal
        ("encaps answer length " ++ show (BS.length bs)
          ++ " mismatches " ++ show ctLen ++ "+" ++ show ssLen)
  (PwDecaps sec, GotBytes bs)
    | BS.length bs == 32 -> publish1 (storeMaterial bs sec) []
        ["decapsulated shared secret"]
    | otherwise -> internal
        ("decaps answer length " ++ show (BS.length bs) ++ " mismatches 32")
  (PwGenerateKey po, GotBytes bs) -> case decodeKeyPair bs of
    Just (mat, Nothing) -> case stampParamsObject po mat of
      Just po' -> publish1 (storeMaterial mat po') []
        [paramsReason po']
      Nothing -> internal "params answer material fails component decode"
    _ -> internal "single-key answer is not lone material"
  -- PBE answers frame the key/IV pair: the key publishes as
  -- the object, the IV rides a byte output for the FFI
  -- write-back.
  (PwGenerateKeyIv po keyLen, GotBytes bs) -> case decodeKeyPair bs of
    Just (mat, Just iv)
      | BS.length mat == keyLen && BS.length iv == 8 -> case stampParamsObject po mat of
          Just po' -> publish1 (storeMaterial mat po')
            [NativeOutput (RegionBytes "iv" IntentNull) iv]
            ["pbe key plus iv"]
          Nothing -> internal "pbe answer material fails component decode"
      | otherwise -> internal
          ("pbe answer lengths " ++ show (BS.length mat) ++ "+"
            ++ show (BS.length iv) ++ " mismatch " ++ show keyLen ++ "+8")
    _ -> internal "pbe answer is not a key/iv pair"
  (PwBlobOut region, GotBytes bs) -> Immediate PreparedCommit
    { pcCode = CKR_OK
    , pcDelta = StateDelta []
    , pcPersist = []
    , pcOutputs = [NativeOutput (RegionBytes region IntentNull) bs]
    , pcReleases = []
    , pcReasons = ["wrapped blob ready"]
    }
  (PwUnwrap po, GotBytes bs) -> case unpadPkcs7 16 bs of
    Just mat -> publishUnwrap mat po
    Nothing -> Reject Rejection
      { rejCode = CKR_ENCRYPTED_DATA_INVALID
      , rejOutputs = []
      , rejDelta = StateDelta []
      , rejReleases = []
      , rejReasons = ["unwrap padding check failed"]
      , rejCause = Nothing
      }
  -- RSA unwrap answers raw key material (the asymmetric padding
  -- is consumed by the backend): no PKCS#7 framing to strip.
  (PwUnwrapRaw po, GotBytes bs) ->
    publishUnwrap bs po
  -- KW-PKCS7 answers the padded image: strip the 8-quantum
  -- framing (a corrupt pad is ENCRYPTED_DATA_INVALID, like the
  -- CBC path, and publishes nothing).
  (PwUnwrapPad8 po, GotBytes bs) -> case unpadPkcs7 8 bs of
    Just mat -> publishUnwrap mat po
    Nothing -> Reject Rejection
      { rejCode = CKR_ENCRYPTED_DATA_INVALID
      , rejOutputs = []
      , rejDelta = StateDelta []
      , rejReleases = []
      , rejReasons = ["unwrap padding check failed"]
      , rejCause = Nothing
      }
  -- X.509 unwrap answers a full k-block; the key is the trailing
  -- value_len bytes (the length the unwrap template named).
  (PwUnwrapTail po k n, GotBytes bs) -> case x509Tail k n bs of
    Just mat -> publishUnwrap mat po
    Nothing -> internal
      ("x509 answer length " ++ show (BS.length bs)
        ++ " mismatches width " ++ show k)
  (PwDerive pos lens, GotBytes bs)
    | BS.length bs /= sum lens -> internal
        ("derive answer length " ++ show (BS.length bs)
          ++ " mismatches " ++ show (sum lens))
    | length pos /= length lens -> internal "derive pending arity mismatch"
    -- Key domain: the final material must fit each resolved type before
    -- publication (no invalid typed object from incoherent work).
    | Left deny <- mapM_ (\(po, mat) -> checkDerivedTarget (poAttrs po) (BS.length mat))
        (zip pos (splitLens lens bs)) -> rejectOf deny
    | otherwise -> case publishPending model st
        [storeDerivedMaterial mat po | (po, mat) <- zip pos (splitLens lens bs)] of
        Left deny -> rejectOf deny
        Right (delta, hs) -> Immediate PreparedCommit
          { pcCode = CKR_OK
          , pcDelta = delta
          , pcPersist = []
          , pcOutputs =
              [ NativeOutput (RegionHandle "key")
                  (encodeValue (ValULong (fromIntegral (unExternalHandle h))))
              | h <- hs
              ]
          , pcReleases = []
          , pcReasons = ["derived " ++ show (length pos) ++ " keys"]
          }
  -- Key-material answers append the two IVs after the key
  -- bytes (TLS key-block order): keys publish as objects,
  -- IVs ride byte outputs for the FFI write-back. Empty IVs
  -- (a zero size) emit no output.
  (PwDeriveIv pos lens (ivCLen, ivSLen), GotBytes bs)
    | BS.length bs /= sum lens + ivCLen + ivSLen -> internal
        ("keymat answer length " ++ show (BS.length bs)
          ++ " mismatches " ++ show (sum lens + ivCLen + ivSLen))
    | length pos /= length lens -> internal "keymat pending arity mismatch"
    -- Key domain: key outputs (IVs are bytes, never objects) must fit
    -- their resolved types before publication.
    | Left deny <- mapM_ (\(po, mat) -> checkDerivedTarget (poAttrs po) (BS.length mat))
        (zip pos (splitLens lens keyBs)) -> rejectOf deny
    | otherwise -> case publishPending model st
        [storeDerivedMaterial mat po | (po, mat) <- zip pos (splitLens lens keyBs)] of
        Left deny -> rejectOf deny
        Right (delta, hs) -> Immediate PreparedCommit
          { pcCode = CKR_OK
          , pcDelta = delta
          , pcPersist = []
          , pcOutputs =
              [ NativeOutput (RegionHandle "key")
                  (encodeValue (ValULong (fromIntegral (unExternalHandle h))))
              | h <- hs
              ] ++ ivOut "iv-client" ivC ++ ivOut "iv-server" ivS
          , pcReleases = []
          , pcReasons = ["derived " ++ show (length pos) ++ " keys + ivs"]
          }
    where
      (keyBs, ivBs) = BS.splitAt (sum lens) bs
      (ivC, ivS) = BS.splitAt ivCLen ivBs
      ivOut _ out | BS.null out = []
      ivOut region out = [NativeOutput (RegionBytes region IntentNull) out]
  -- Pub-from-priv answers the DER SPKI of the derived public
  -- key: stamp the type's components (the keygen stamping
  -- shapes) and publish the single object. Unparseable halves
  -- (synthetic opaque doubles) pass through unstamped rather
  -- than rejecting, mirroring the EC/Edwards/Montgomery keygen
  -- arms — reads serve stored attributes only.
  (PwDerivePub po kty, GotBytes bs) ->
    publish1 (storeMaterial bs (stampPub kty po bs)) [] ["derived public key"]
  (_, GotValid _) -> internal "verdict answer to key management"
  (_, GotResource _) -> internal "resource answer to key management"
  -- A feed answer never reaches a key finisher; loud on
  -- violation (same failure class as the pre-change empty-bytes
  -- mis-shape, which failed its frame decode).
  (_, GotUnit) -> internal "unit answer to key management"
  (w, ans@(GotCryptoError e)) ->
    let code = interpretError (workFunction w) (TyCrypto e)
    in Reject Rejection
      { rejCode = code
      , rejOutputs = []
      , rejDelta = StateDelta []
      , rejReleases = []
      , rejReasons = ["driver: " ++ show e]
      , rejCause = keptCause (workFunction w) ans code
      }
  where
    publish :: PendingObject -> PendingObject -> PlanResult
    publish pub priv = case publishPending model st [pub, priv] of
      Left deny -> rejectOf deny
      Right (delta, [pubH, privH]) -> Immediate PreparedCommit
        { pcCode = CKR_OK
        , pcDelta = delta
        , pcPersist = []
        , pcOutputs =
            [ NativeOutput (RegionHandle "public") (encodeValue (ValULong (fromIntegral (unExternalHandle pubH))))
            , NativeOutput (RegionHandle "private") (encodeValue (ValULong (fromIntegral (unExternalHandle privH))))
            ]
        , pcReleases = []
        , pcReasons = ["generated key pair"]
        }
      Right _ -> internal "pair publication arity"
    publish1 :: PendingObject -> [NativeOutput] -> [String] -> PlanResult
    publish1 po extraOutputs reasons = case publishPending model st [po] of
      Left deny -> rejectOf deny
      Right (delta, [h]) -> Immediate PreparedCommit
        { pcCode = CKR_OK
        , pcDelta = delta
        , pcPersist = []
        , pcOutputs = extraOutputs
            ++ [NativeOutput (RegionHandle "key") (encodeValue (ValULong (fromIntegral (unExternalHandle h))))]
        , pcReleases = []
        , pcReasons = reasons
        }
      Right _ -> internal "single publication arity"
    -- Publish unwrapped material after the type/length coherence
    -- check: the answered bytes must suit the template key type
    -- (AES: 16/24/32; DES3: 24; XTS: 32/64; anything else: any
    -- length). A mismatch is key-type confusion (Tookan section
    -- 3.2) and refuses with CKR_TEMPLATE_INCONSISTENT, publishing
    -- nothing.
    -- Stamp SPKI components onto a derived public object (the
    -- keygen component shapes, single-sided: the private half
    -- stays with the caller). Unparseable input passes through
    -- unstamped (synthetic opaque doubles).
    stampPub :: Word64 -> PendingObject -> ByteString -> PendingObject
    stampPub k po bs
      | k == ckkRsa = case parseRsaPublic bs of
          Just (n, e) -> po { poAttrs = Map.insert AttrModulusBits (ValULong (fromIntegral (bitsOf n)))
            (Map.insert AttrModulus (ValBytes n)
            (Map.insert AttrPublicExponent (ValBytes e) (poAttrs po))) }
          Nothing -> po
      | k == ckkEc = case ecSpkiFields bs of
          Just (params, pt) | BS.take 1 pt == BS.singleton 0x04 ->
            po { poAttrs = Map.insert AttrEcPoint (ValBytes (derOctet pt))
              (Map.insert AttrEcParams (ValBytes params) (poAttrs po)) }
          _ -> po
      | k == ckkEcEdwards = case eddsaSpkiFields bs of
          Just (_, pt) ->
            po { poAttrs = Map.insert AttrEcPoint (ValBytes pt) (poAttrs po) }
          Nothing -> po
      | k == ckkEcMontgomery = case montgomerySpkiFields bs of
          Just (_, pt) ->
            po { poAttrs = Map.insert AttrEcPoint (ValBytes pt) (poAttrs po) }
          Nothing -> po
      | otherwise = po
    publishUnwrap :: ByteString -> PendingObject -> PlanResult
    publishUnwrap mat po
      | typeLenOk = publish1 (storeMaterial mat po) [] ["unwrapped key"]
      | otherwise = Reject Rejection
          { rejCode = CKR_TEMPLATE_INCONSISTENT
          , rejOutputs = []
          , rejDelta = StateDelta []
          , rejReleases = []
          , rejReasons = ["unwrapped material length "
              ++ show (BS.length mat) ++ " mismatches key type "
              ++ show (Map.lookup AttrKeyType (poAttrs po))]
          , rejCause = Nothing
          }
      where
        typeLenOk = case Map.lookup AttrKeyType (poAttrs po) of
          Just (ValULong k)
            | k == ckkAes -> BS.length mat `elem` [16, 24, 32]
            | k == ckkDes3 -> BS.length mat == 24
            | k == ckkAesXts -> BS.length mat `elem` [32, 64]
          _ -> True

-- | Store driver-supplied key material on a pending object.
storeMaterial :: ByteString -> PendingObject -> PendingObject
storeMaterial mat po = po { poAttrs = Map.insert AttrValue (ValBytes mat) (poAttrs po) }

-- | DES-family targets take FIPS 46-3 odd-parity adjustment on
-- derived material: PKCS#11 makes the token responsible for the
-- parity bits of generated DES/DES2/DES3/CDMF key bytes, on every
-- derive mechanism, not just PBE. Every other type passes through.
derivedNeedsParity :: Map.Map AttributeType AttributeValue -> Bool
derivedNeedsParity attrs = case Map.lookup AttrKeyType attrs of
  Just (ValULong k) ->
    k == ckkDes || k == ckkDes2 || k == ckkDes3 || k == ckkCdmf
  _ -> False

-- | Store derived key material, parity-adjusting DES-family
-- targets (shared helper with the PBE finish).
storeDerivedMaterial :: ByteString -> PendingObject -> PendingObject
storeDerivedMaterial mat po
  | derivedNeedsParity (poAttrs po) = storeMaterial (pbeDesParity mat) po
  | otherwise = storeMaterial mat po

-- | Stamp keygen components back onto a pending pair. Reads serve
-- stored attributes only (no decode-on-read path), so an RSA pair
-- must carry its CRT components: the public half gets the modulus,
-- the exponent and the authoritative @CKA_MODULUS_BITS@ (the true
-- bit width of the modulus; the private half carries no size, per
-- PKCS#11 3.2 section 6.1), the private half all eight PKCS#1
-- parts. The two
-- DER halves must agree on (n, e); any parse failure or mismatch
-- is 'Nothing' (the finisher rejects with zero objects). A DSA
-- pair stamps @CKA_PRIME@\/@CKA_SUBPRIME@\/@CKA_BASE@ onto both
-- halves, parsed authoritatively from the SPKI\/PKCS#8 halves
-- (which must agree on (p, q, g)); @AttrValue@ keeps the DER
-- halves ('storeMaterial' runs after stamping, as for RSA\/EC).
-- Opaque halves (synthetic test doubles, not DER) pass through
-- unstamped rather than rejecting, mirroring the EC arm. An EC
-- pair stamps @CKA_EC_POINT@ (the DER OCTET STRING of the
-- uncompressed SPKI point) on the public half and copies the
-- public half's @CKA_EC_PARAMS@ onto a private half whose
-- template lacks it (the value is template-derived, so the copy
-- holds even for opaque halves); opaque halves pass through
-- without @CKA_EC_POINT@ rather than rejecting. Halves that
-- disagree on the curve never reach the stamp: the planner
-- ('ecCurveOf') refuses them before generation, and equal values
-- pass through.
-- An Edwards pair stamps the raw @CKA_EC_POINT@ on the public
-- half and the agreed engine curve name as @CKA_EC_PARAMS@ on
-- the private half (whose template lacks it); disagreeing or
-- opaque halves pass through unstamped.
-- A Montgomery pair stamps the same way (the raw u-coordinate
-- point, the agreed curve name).
-- An ML-DSA pair stamps the @CKA_SEED@ on the private half
-- (parsed from the PKCS#8 half, whose seed the planner
-- cannot know; the set rides both halves from the planner
-- planner tag, and @AttrValue@ keeps the DER halves via
-- 'storeMaterial' as for every asymmetric family — reads serve
-- DER as @CKA_VALUE@, the codebase-wide convention);
-- disagreeing or opaque halves pass through unstamped. An
-- ML-KEM pair stamps the @CKA_SEED@ on the private half the
-- same way (parsed from the provider-form PKCS#8 half);
-- disagreeing or opaque halves pass through unstamped. Other
-- key types pass through untouched.
stampPairComponents
  :: PendingObject -> PendingObject -> ByteString -> ByteString
  -> Maybe (PendingObject, PendingObject)
stampPairComponents pub priv pubM privM
  | Map.lookup AttrKeyType (poAttrs pub) == Just (ValULong ckkDsa) =
      case (dsaSpkiFields pubM, dsaPkcs8Fields privM) of
        (Just (p, q, g, _), Just (p', q', g', _))
          | p' == p && q' == q && g' == g ->
              let stamp a = Map.insert AttrPrime (ValBytes p)
                    (Map.insert AttrSubprime (ValBytes q)
                    (Map.insert AttrBase (ValBytes g) a))
              in Just (pub { poAttrs = stamp (poAttrs pub) }
                     , priv { poAttrs = stamp (poAttrs priv) })
        _ -> Just (pub, priv)
  | Map.lookup AttrKeyType (poAttrs pub) == Just (ValULong ckkDh)
    || Map.lookup AttrKeyType (poAttrs pub) == Just (ValULong ckkX9_42Dh) =
      case (dhSpkiFields pubM, dhPkcs8Fields privM) of
        (Just (p, g, q, _), Just (p', g', q', _))
          | p' == p && g' == g && q' == q ->
              let stamp a = Map.insert AttrPrime (ValBytes p)
                    (Map.insert AttrBase (ValBytes g)
                    (maybe id (\qb -> Map.insert AttrSubprime (ValBytes qb)) q a))
              in Just (pub { poAttrs = stamp (poAttrs pub) }
                     , priv { poAttrs = stamp (poAttrs priv) })
        _ -> Just (pub, priv)
  | Map.lookup AttrKeyType (poAttrs pub) == Just (ValULong ckkMlDsa) =
      case (mldsaSpkiFields pubM, mldsaPkcs8Fields privM) of
        (Just (pubOid, _), Just (privOid, seed, _))
          | pubOid == privOid ->
              let privA = Map.insert AttrSeed (ValBytes seed) (poAttrs priv)
              in Just (pub, priv { poAttrs = privA })
        _ -> Just (pub, priv)
  | Map.lookup AttrKeyType (poAttrs pub) == Just (ValULong ckkSlhDsa) =
      case (slhdsaSpkiFields pubM, slhdsaPkcs8Fields privM) of
        (Just (pubOid, _), Just (privOid, raw))
          | pubOid == privOid ->
              let n = BS.length raw `div` 4
                  privA = Map.insert AttrSeed (ValBytes (BS.take n raw)) (poAttrs priv)
              in Just (pub, priv { poAttrs = privA })
        _ -> Just (pub, priv)
  | Map.lookup AttrKeyType (poAttrs pub) == Just (ValULong ckkMlKem) =
      case (mlkemSpkiFields pubM, mlkemPkcs8Fields privM) of
        (Just (pubOid, _), Just (privOid, seed, _))
          | pubOid == privOid ->
              let privA = Map.insert AttrSeed (ValBytes seed) (poAttrs priv)
              in Just (pub, priv { poAttrs = privA })
        _ -> Just (pub, priv)
  | Map.lookup AttrKeyType (poAttrs pub) == Just (ValULong ckkEcEdwards) =
      case (eddsaSpkiFields pubM, eddsaPkcs8Fields privM) of
        (Just (pubOid, pubPoint), Just (privOid, _seed))
          | pubOid == privOid
          , Just curve <- edwardsNameOfOid pubOid ->
              let pubA = Map.insert AttrEcPoint (ValBytes pubPoint) (poAttrs pub)
                  privA = Map.insert AttrEcParams (ValBytes curve) (poAttrs priv)
              in Just (pub { poAttrs = pubA }, priv { poAttrs = privA })
        _ -> Just (pub, priv)
  | Map.lookup AttrKeyType (poAttrs pub) == Just (ValULong ckkEcMontgomery) =
      case (montgomerySpkiFields pubM, montgomeryPkcs8Fields privM) of
        (Just (pubOid, pubPoint), Just (privOid, _scalar))
          | pubOid == privOid
          , Just curve <- montgomeryNameOfOid pubOid ->
              let pubA = Map.insert AttrEcPoint (ValBytes pubPoint) (poAttrs pub)
                  privA = Map.insert AttrEcParams (ValBytes curve) (poAttrs priv)
              in Just (pub { poAttrs = pubA }, priv { poAttrs = privA })
        _ -> Just (pub, priv)
  | Map.lookup AttrKeyType (poAttrs pub) == Just (ValULong ckkEc) =
      let pub' = case spkiPoint pubM of
            Just pt | BS.take 1 pt == BS.singleton 0x04 ->
              pub { poAttrs = Map.insert AttrEcPoint (ValBytes (derOctet pt)) (poAttrs pub) }
            _ -> pub
          priv' = case Map.lookup AttrEcParams (poAttrs pub) of
            Just p | Map.notMember AttrEcParams (poAttrs priv) ->
              priv { poAttrs = Map.insert AttrEcParams p (poAttrs priv) }
            _ -> priv
      in Just (pub', priv')
  | Map.lookup AttrKeyType (poAttrs pub) /= Just (ValULong ckkRsa) =
      Just (pub, priv)
  | otherwise = do
      (n, e) <- parseRsaPublic pubM
      crt <- parseRsaPrivate privM
      guard (crtN crt == n && crtE crt == e)
      let pubA = Map.insert AttrModulusBits (ValULong (fromIntegral (bitsOf n)))
            (Map.insert AttrModulus (ValBytes n)
            (Map.insert AttrPublicExponent (ValBytes e) (poAttrs pub)))
          privA = Map.insert AttrModulus (ValBytes n)
            (Map.insert AttrPublicExponent (ValBytes e)
            (Map.insert AttrPrivateExponent (ValBytes (crtD crt))
            (Map.insert AttrPrime1 (ValBytes (crtP crt))
            (Map.insert AttrPrime2 (ValBytes (crtQ crt))
            (Map.insert AttrExponent1 (ValBytes (crtDp crt))
            (Map.insert AttrExponent2 (ValBytes (crtDq crt))
            (Map.insert AttrCoefficient (ValBytes (crtQinv crt))
              (poAttrs priv))))))))
      Just (pub { poAttrs = pubA }, priv { poAttrs = privA })

-- | Stamp domain-parameter components back onto a pending
-- single object. A @CKO_DOMAIN_PARAMETERS@ pending object carries
-- DER DSS-Parms material; reads serve stored attributes only, so
-- the finisher parses the material and stamps @CKA_PRIME@\/
-- @CKA_SUBPRIME@\/@CKA_BASE@ plus the true bit widths as
-- @CKA_PRIME_BITS@\/@CKA_SUBPRIME_BITS@. Opaque material
-- (synthetic test doubles, not DER) passes through unstamped
-- rather than rejecting, mirroring the EC pair arm. Other
-- classes pass through untouched.
stampParamsObject :: PendingObject -> ByteString -> Maybe PendingObject
stampParamsObject po mat
  | Map.lookup AttrClass (poAttrs po) /= Just (ValULong ckoDomainParameters) =
      Just po
  | otherwise = case parseDsaParams mat of
      Just (p, q, g)
        | not (BS.null p) && not (BS.null q) && not (BS.null g) ->
            let stamped = Map.insert AttrPrime (ValBytes p)
                  (Map.insert AttrSubprime (ValBytes q)
                  (Map.insert AttrBase (ValBytes g)
                  (Map.insert AttrPrimeBits (ValULong (fromIntegral (bitsOf p)))
                  (Map.insert AttrSubprimeBits (ValULong (fromIntegral (bitsOf q)))
                    (poAttrs po)))))
            in Just (po { poAttrs = stamped })
      _ -> Just po

-- | The committed reason for a finished single-key job: domain
-- parameters name themselves, everything else is a key.
paramsReason :: PendingObject -> String
paramsReason po
  | Map.lookup AttrClass (poAttrs po) == Just (ValULong ckoDomainParameters) =
      "generated domain parameters"
  | otherwise = "generated key"

-- | True bit width of unsigned big-endian bytes (leading zero
-- bits discounted, so short top octets measure honestly).
bitsOf :: ByteString -> Int
bitsOf bs = case BS.dropWhile (== 0) bs of
  stripped
    | BS.null stripped -> 0
    | otherwise -> BS.length stripped * 8 - countLeadingZeros (BS.head stripped)

-- | Split concatenated derived material at the planned lengths.
splitLens :: [Int] -> ByteString -> [ByteString]
splitLens [] _ = []
splitLens (n : ns) bs =
  let (h, t) = BS.splitAt n bs
  in h : splitLens ns t
