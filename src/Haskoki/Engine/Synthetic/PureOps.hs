{- | Haskoki.Engine.Synthetic.PureOps: pure deterministic test constructions (MAC/sign/agree/seal/keygen).
-}
{-# LANGUAGE OverloadedStrings #-}
module Haskoki.Engine.Synthetic.PureOps
  ( classAeadSeal
  , classAeadOpen
  , sigEncoding
  , dsaFloor
  , x931Floor
  , genCurveOk
  , genSymBytes
  , genPair
  , synthDsaParams
  , signIdentity
  , rsaModulusOf
  , pairIdOf
  , genKemPair
  , genRsaPair
  , kemHalfOf
  , kemCt
  , kemSs
  , kemAlgByte
  , kemByteAlg
  , kemCtLenOf
  , keyFamily
  , ctEq
  , classMac
  , classSign
  , classSignFor
  , ecdhAgreeInputs
  , classEcdh
  , classDh
  , classOaepSeal
  , classOaepOpen
  , oaepParamFrame
  , oaepStreamFrame
  , oaepTagFrame
  , classPkcs1Seal
  , classPkcs1Open
  , pkcs1StreamFrame
  , pkcs1TagFrame
  , classX509Seal
  , classX509Open
  , x509StreamFrame
  , classCipher
  , classCipherFor
  , synthWrapSeal
  , synthWrapOpen
  , wrapTagKey
  , classStream
  , classXof
  , classDigest
  ) where


import Control.Monad (guard)
import Data.Bits ((.|.), xor)
import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import qualified Data.ByteString.Char8 as BC8
import Data.Maybe (fromMaybe)
import Data.Word (Word8, Word64)

import Haskoki.Engine.Backend
  ( AeadSpec (..)
  , CipherSpec (..)
  , DigestAlg (..)
  , digestMacStem
  , digestOutLen
  , EcdhSpec (..)
  , DhSpec (..)
  , EcSpec (..)
  , KeyMaterial (..)
  , KeyRef (..)
  , MacSpec (..)
  , OaepParams (..)
  , PqcKemAlg (..)
  , rsaSigCap
  , SigSpec (..)
  )
import Haskoki.Engine.Synthetic.Framing
import Haskoki.Der
  ( RsaCrt (..)
  , curveTable
  , integerToBE
  , parseRsaPrivate
  , parseRsaPublic
  , rsaPrivateDer
  , rsaPublicDer
  )
import Haskoki.Recipe.RsaX509 (x509PadBlock)


-- | Seal under the synthetic AEAD: PRF keystream XOR plus a tag
-- over (key, nonce, aad, body). Deterministic; NOT real GCM.
classAeadSeal :: ByteString -> AeadSpec -> ByteString -> ByteString -> ByteString -> (ByteString, ByteString)
classAeadSeal kb spec iv aad input = (body, tag)
  where
    body = BS.packZipWith xor
      (prfBytes (frame ["haskoki-synth/aead-ct/v1", kb, iv]) (BS.length input))
      input
    tag = prfBytes
      (frame ["haskoki-synth/aead-tag/v1", kb, iv, aad, body])
      (aeadTagLen spec)

-- | Open a synthetic AEAD envelope: the tag must match exactly
-- (constant-time) or the whole open is 'Nothing'.
classAeadOpen :: ByteString -> AeadSpec -> ByteString -> ByteString -> ByteString -> ByteString -> Maybe ByteString
classAeadOpen kb spec iv aad body tag
  | not (ctEq tag want) = Nothing
  | otherwise = Just (BS.packZipWith xor
      (prfBytes (frame ["haskoki-synth/aead-ct/v1", kb, iv]) (BS.length body))
      body)
  where
    want = prfBytes
      (frame ["haskoki-synth/aead-tag/v1", kb, iv, aad, body])
      (aeadTagLen spec)

-- | Signature encoding tag carried into the construction (the guard
-- admits DER and RAW only; anything else never reaches here).
sigEncoding :: SigSpec -> ByteString
sigEncoding (SigECDSA ec _)
  | ecEncoding ec == "RAW" = "RAW"
  | otherwise = "DER"
sigEncoding (SigDSA enc _)
  | enc == "RAW" = "RAW"
  | otherwise = "DER"
sigEncoding _ = "DER"

-- | DSA raw floor: the raw row signs caller digests of at least
-- 20 bytes (PKCS#11); prehash rows hash arbitrary input (empty
-- included). Mirrors the planner check and the real shim floor.
dsaFloor :: SigSpec -> ByteString -> Maybe String
dsaFloor (SigDSA _ Nothing) msg
  | BS.length msg < 20 = Just "DSA raw digest shorter than 20 bytes"
dsaFloor _ _ = Nothing

-- | X9.31 floor: raw inputs must hit the hash-id length set
-- (20\/32\/48\/64 bytes); digested inputs must name one of the
-- same four digests (the real backend's provider rule, mirrored
-- so both engines refuse identically).
x931Floor :: SigSpec -> ByteString -> Maybe String
x931Floor (SigRSA_X931 Nothing) msg
  | BS.length msg `elem` [20, 32, 48, 64] = Nothing
  | otherwise = Just "X9.31 raw digest outside the 20/32/48/64-byte hash-id set"
x931Floor (SigRSA_X931 (Just alg)) _
  | alg `elem` [D_SHA1, D_SHA256, D_SHA384, D_SHA512] = Nothing
  | otherwise = Just "X9.31 digest outside the SHA-1/256/384/512 hash-id set"
x931Floor _ _ = Nothing

-- | Synthetic keygen admits every covered curve: pairs are opaque
-- tagged bytes (see 'genPair'), so no per-curve material applies.
genCurveOk :: String -> Bool
genCurveOk c = BC8.pack c `elem` [n | (n, _, _, _) <- curveTable]

-- | Symmetric key bytes from the backend seed and the generation
-- counter: the same seed plus the same call sequence replays. The
-- algorithm label domain-separates the streams, so e.g. HOTP keys
-- never collide with AES keys at equal lengths.
genSymBytes :: Word64 -> Word64 -> ByteString -> Int -> ByteString
genSymBytes seed ctr alg n =
  streamKeyBytes seed (OpNumber ctr)
    (frame ["haskoki-synth/class-keygen/v1", alg, word32BE n]) n

-- | A tagged P-256 pair: both halves share one pair identity, each
-- carrying its own role byte and material. Layout per half:
-- @"HKS1" || pairId(32) || role(1) || mat(32)@; role 0 is private.
genPair :: Word64 -> Word64 -> (KeyMaterial, Maybe KeyMaterial)
genPair seed ctr = (KeyDer priv, Just (KeyDer pub))
  where
    pairId = prfBytes
      (frame ["haskoki-synth/class-pair/v1", word64BE seed, word64BE ctr]) 32
    privM = streamKeyBytes seed (OpNumber ctr)
      (frame ["haskoki-synth/class-pair-priv/v1"]) 32
    pubM = streamKeyBytes seed (OpNumber ctr)
      (frame ["haskoki-synth/class-pair-pub/v1"]) 32
    priv = "HKS1" <> pairId <> BS.singleton 0 <> privM
    pub = "HKS1" <> pairId <> BS.singleton 1 <> pubM

-- | Opaque DSA domain parameters: length-framed PRF bytes under
-- a DSA-params domain (an opaque test double, not DER — stamping
-- passes synthetic halves through unstamped, like EC). The length
-- frames the (L, N) pair: p || q || g widths.
synthDsaParams :: Word64 -> Word64 -> Int -> Int -> ByteString
synthDsaParams seed ctr p q =
  genSymBytes seed ctr "DSA-params" (p `div` 8 + (q + 7) `div` 8 + p `div` 8)

-- | The signing identity: pair halves sign under the shared pair
-- identity, RSA DER halves under their shared modulus, raw keys
-- under their own bytes. The modulus rule lets generated RSA
-- pairs roundtrip sign/verify (both halves carry n) while every
-- distinct key still owns a distinct identity.
signIdentity :: ByteString -> ByteString
signIdentity kb = case pairIdOf kb of
  Just pid -> pid
  Nothing -> case rsaModulusOf kb of
    Just n -> n
    Nothing -> kb

-- | The RSA modulus when the bytes are an RSA SPKI or PKCS#8
-- half (either side of a generated or planted pair).
rsaModulusOf :: ByteString -> Maybe ByteString
rsaModulusOf kb = case parseRsaPublic kb of
  Just (n, _) -> Just n
  Nothing -> crtN <$> parseRsaPrivate kb

-- | Parse a generated pair half back to its pair identity (strict:
-- exact 69 bytes, magic, role 0 or 1).
pairIdOf :: ByteString -> Maybe ByteString
pairIdOf bs = do
  guard (BS.length bs == 69)
  let (magic, r1) = BS.splitAt 4 bs
  guard (magic == "HKS1")
  let (pid, r2) = BS.splitAt 32 r1
  (role, _) <- BS.uncons r2
  guard (role == 0 || role == 1)
  Just pid

-- | A tagged ML-KEM pair: like 'genPair' but under the @HKS2@ magic
-- with a parameter-set byte, so KEM halves never parse as EC halves
-- and vice versa. Layout per half: @"HKS2" || alg(1) || pairId(32)
-- || role(1) || mat(32)@; role 0 is private.
genKemPair :: Word64 -> Word64 -> PqcKemAlg -> (KeyMaterial, Maybe KeyMaterial)
genKemPair seed ctr alg = (KeyDer priv, Just (KeyDer pub))
  where
    tag = BS.singleton (kemAlgByte alg)
    pairId = prfBytes
      (frame ["haskoki-synth/kem-pair/v1", word64BE seed, word64BE ctr, tag]) 32
    privM = streamKeyBytes seed (OpNumber ctr)
      (frame ["haskoki-synth/kem-pair-priv/v1", tag]) 32
    pubM = streamKeyBytes seed (OpNumber ctr)
      (frame ["haskoki-synth/kem-pair-pub/v1", tag]) 32
    priv = "HKS2" <> tag <> pairId <> BS.singleton 0 <> privM
    pub = "HKS2" <> tag <> pairId <> BS.singleton 1 <> pubM

-- | A deterministic test RSA pair: well-formed PKCS#8/SPKI DER
-- around PRF-drawn components (NOT real RSA math; the fixed
-- construction is what makes model tests replay). Both halves
-- share the modulus, so 'signIdentity' unites them for
-- sign/verify roundtrips exactly like the @HKS1@ pair identity
-- does for EC. The exponent is the requested one in minimal
-- big-endian form; primes and CRT parts are top-bit-set PRF
-- bytes at the standard widths.
genRsaPair :: Word64 -> Word64 -> Int -> Integer -> (KeyMaterial, Maybe KeyMaterial)
genRsaPair seed ctr bits e = (KeyDer priv, Just (KeyDer pub))
  where
    nLen = bits `div` 8
    halfLen = bits `div` 16
    base = frame ["haskoki-synth/rsa-pair/v1", word64BE seed, word64BE ctr,
      word64BE (fromIntegral bits), integerToBE e]
    comp label len = topBit (prfBytes (base <> label) len)
    n = comp "n" nLen
    eBs = integerToBE e
    d = comp "d" nLen
    p = comp "p" halfLen
    q = comp "q" halfLen
    dp = comp "dp" halfLen
    dq = comp "dq" halfLen
    qi = comp "qinv" halfLen
    priv = rsaPrivateDer n eBs d p q dp dq qi
    pub = rsaPublicDer n eBs
    topBit bs = case BS.uncons bs of
      Just (b, rest) -> BS.cons (b .|. 0x80) rest
      Nothing -> bs

-- | Parse a KEM half back to its parameter set, pair identity and
-- role (strict: exact 70 bytes, @HKS2@ magic, known set, role 0/1).
kemHalfOf :: ByteString -> Maybe (PqcKemAlg, ByteString, Word8)
kemHalfOf bs = do
  guard (BS.length bs == 70)
  let (magic, r1) = BS.splitAt 4 bs
  guard (magic == "HKS2")
  (tag, r2) <- BS.uncons r1
  alg <- kemByteAlg tag
  let (pid, r3) = BS.splitAt 32 r2
  (role, _) <- BS.uncons r3
  guard (role == 0 || role == 1)
  Just (alg, pid, role)

-- | The deterministic test ciphertext: standard length for the set,
-- derived from the backend seed and the pair identity (NOT real
-- ML-KEM; the fixed construction is what makes model tests replay).
kemCt :: Word64 -> PqcKemAlg -> ByteString -> ByteString
kemCt seed alg pid = prfBytes
  (frame [ "haskoki-synth/kem-ct/v1", word64BE seed
        , BS.singleton (kemAlgByte alg), pid ])
  (kemCtLenOf alg)

-- | The deterministic test shared secret: 32 bytes from the backend
-- seed and the pair identity, shared by both halves.
kemSs :: Word64 -> ByteString -> ByteString
kemSs seed pid = prfBytes
  (frame ["haskoki-synth/kem-ss/v1", word64BE seed, pid]) 32

-- | KEM parameter-set tags: the byte after the @HKS2@ magic.
kemAlgByte :: PqcKemAlg -> Word8
kemAlgByte alg = case alg of
  ML_KEM_512 -> 0
  ML_KEM_768 -> 1
  ML_KEM_1024 -> 2

-- | Tag byte back to its set.
kemByteAlg :: Word8 -> Maybe PqcKemAlg
kemByteAlg tag = case tag of
  0 -> Just ML_KEM_512
  1 -> Just ML_KEM_768
  2 -> Just ML_KEM_1024
  _ -> Nothing

-- | Standard ciphertext lengths per set.
kemCtLenOf :: PqcKemAlg -> Int
kemCtLenOf alg = case alg of
  ML_KEM_512 -> 768
  ML_KEM_768 -> 1088
  ML_KEM_1024 -> 1568

keyFamily :: KeyMaterial -> String
keyFamily (KeyBytes _) = "SYM"
keyFamily (KeyDer _) = "DER"
keyFamily (KeyRefMaterial (KeyRef _ fam)) = fam

-- | Constant-time equality (lengths plus a full xor fold).
ctEq :: ByteString -> ByteString -> Bool
ctEq a b =
  BS.length a == BS.length b
    && foldl' (\acc (x, y) -> acc .|. (x `xor` y)) 0 (BS.zip a b) == 0

-- | Class-interface MAC: domain-separated expansion over the
-- owned key bytes and the input, at the spec's algorithm width with
-- the requested truncation sliced off the full tag. SHA-256 keeps
-- its historical bytes (same domain tag, same 32-byte width); the
-- empty fallbacks are unreachable (the guard refuses XOFs and
-- non-HMAC families first).
classMac :: MacSpec -> ByteString -> ByteString -> ByteString
classMac (MacHMAC alg trunc) kb input =
  case (digestMacStem alg, digestOutLen alg) of
    (Just stem, Just w) ->
      BS.take (fromMaybe w trunc) (prfBytes
        (frame ["haskoki-synth/class-mac/v1", kb, BC8.pack ("HMAC-" ++ stem), input])
        w)
    _ -> BS.empty
classMac MacPoly1305 kb input =
  prfBytes (frame ["haskoki-synth/class-mac/v1", kb, "POLY1305", input]) 16
classMac _ _ _ = BS.empty

-- | Class-interface signature: 64-byte domain-separated expansion
-- over the signing identity, the encoding tag, and the input. Raw
-- keys sign under their object identity; generated pair halves sign
-- under the shared pair identity, so a pair verifies across.
classSign :: ByteString -> ByteString -> ByteString -> ByteString
classSign enc identity input = prfBytes
  (frame ["haskoki-synth/class-sig/v1", identity, enc, input])
  synthSigLength

-- | Spec-keyed signature: the original ECDSA row (P-256, either
-- encoding, SHA-256) keeps the encoding tag byte-for-byte
-- (existing pins hold); every other ECDSA spec tags with its full
-- parameters (curve, encoding, and digest, raw included); DSA
-- specs tag with their full parameters (encoding and digest, raw
-- included); EdDSA and ML-DSA specs tag with their full
-- parameters (level, context, and hedge included); RSA rows tag
-- with their capability name (PSS tags with its full parameters,
-- salt included) — so curves, digests, encodings, levels,
-- contexts, and families never share a test signature over one
-- identity. (X9.31 tags with its full parameters like PSS.)
classSignFor :: SigSpec -> ByteString -> ByteString -> ByteString
classSignFor spec@(SigECDSA (EcSpec "P-256" _) (Just D_SHA256)) identity input =
  classSign (sigEncoding spec) identity input
classSignFor spec@(SigECDSA _ _) identity input =
  classSign (BC8.pack (show spec)) identity input
classSignFor spec@(SigDSA _ _) identity input =
  classSign (BC8.pack (show spec)) identity input
classSignFor spec@(SigEdDSA _ _) identity input =
  classSign (BC8.pack (show spec)) identity input
classSignFor spec@(SigMLDSA _ _ _ _) identity input =
  classSign (BC8.pack (show spec)) identity input
classSignFor spec@(SigSLHDSA _ _ _) identity input =
  classSign (BC8.pack (show spec)) identity input
classSignFor spec@(SigRSA_PSS _) identity input =
  classSign (BC8.pack (show spec)) identity input
classSignFor spec@(SigRSA_X931 _) identity input =
  classSign (BC8.pack (show spec)) identity input
classSignFor spec identity input =
  classSign (BC8.pack (fromMaybe (show spec) (rsaSigCap spec))) identity input

-- | Synthetic ECDH agreement inputs. Generated opaque halves
-- agree commutatively: either half of pair A against either half
-- of pair B lands on the ordered pair identity, so composition
-- wrap (transport-priv x recipient-pub) and composition unwrap
-- (recipient-priv x transport-pub) agree like real DH.
-- Everything else keeps the (base identity, peer bytes) framing.
ecdhAgreeInputs :: ByteString -> ByteString -> (ByteString, ByteString)
ecdhAgreeInputs base peer = case (pairIdOf base, pairIdOf peer) of
  (Just a, Just b) -> (min a b, max a b)
  _ -> (signIdentity base, peer)

-- | Synthetic ECDH agreement: the domain-framed PRF over the spec,
-- the base identity, and the peer bytes at the max width. The
-- cofactor bit is part of the domain (unlike the real h=1 curves,
-- where cofactor multiplication is a no-op).
classEcdh :: EcdhSpec -> ByteString -> ByteString -> ByteString
classEcdh spec base peer = prfBytes
  (frame ["haskoki-synth/class-ecdh/v1", BC8.pack (show spec), base, peer])
  synthEcdhWidth

-- | Synthetic DH agreement: the domain-framed PRF over the spec,
-- the base identity, and the peer bytes at the max width.
classDh :: DhSpec -> ByteString -> ByteString -> ByteString
classDh spec base peer = prfBytes
  (frame ["haskoki-synth/class-dh/v1", BC8.pack (show spec), base, peer])
  synthDhWidth

-- | Synthetic OAEP seal: deterministic, reversible, param-bound.
-- The body is a keystream XOR over (identity, params, input); the
-- 16-byte tag authenticates (identity, params, body), so a wrong
-- label, hash, MGF, or key fails the open with a verdict-shaped
-- 'Nothing'.
classOaepSeal :: ByteString -> OaepParams -> ByteString -> ByteString
classOaepSeal identity params input =
  body <> prfBytes (frame (oaepTagFrame identity params body)) 16
  where
    body = BS.packZipWith xor
      (prfBytes (frame (oaepStreamFrame identity params)) (BS.length input))
      input

-- | Open a synthetic OAEP envelope: recompute the tag (mismatch is
-- 'Nothing'), then XOR back. Short inputs are 'Nothing', never a
-- crash.
classOaepOpen :: ByteString -> OaepParams -> ByteString -> Maybe ByteString
classOaepOpen identity params sealed
  | BS.length sealed < 16 = Nothing
  | not (ctEq tag (prfBytes (frame (oaepTagFrame identity params body)) 16)) =
      Nothing
  | otherwise = Just (BS.packZipWith xor
      (prfBytes (frame (oaepStreamFrame identity params)) (BS.length body))
      body)
  where
    (body, tag) = BS.splitAt (BS.length sealed - 16) sealed

-- | OAEP parameter framing shared by the stream and the tag.
oaepParamFrame :: OaepParams -> [ByteString]
oaepParamFrame params =
  [ BC8.pack (show (oaepHash params))
  , BC8.pack (show (oaepMgf params))
  , oaepLabel params
  ]

oaepStreamFrame :: ByteString -> OaepParams -> [ByteString]
oaepStreamFrame identity params =
  "haskoki-synth/class-oaep-stream/v1" : identity : oaepParamFrame params

oaepTagFrame :: ByteString -> OaepParams -> ByteString -> [ByteString]
oaepTagFrame identity params body =
  "haskoki-synth/class-oaep-tag/v1" : identity : oaepParamFrame params ++ [body]

-- | Synthetic PKCS#1 v1.5 seal: the OAEP construction with its own
-- domain tags, so v1.5 and OAEP envelopes never cross-open. No
-- parameter framing (v1.5 carries none); the tag still binds
-- (identity, body), so a wrong key fails the open.
classPkcs1Seal :: ByteString -> ByteString -> ByteString
classPkcs1Seal identity input =
  body <> prfBytes (frame (pkcs1TagFrame identity body)) 16
  where
    body = BS.packZipWith xor
      (prfBytes (frame (pkcs1StreamFrame identity)) (BS.length input))
      input

-- | Open a synthetic v1.5 envelope: recompute the tag (mismatch is
-- 'Nothing'), then XOR back. Short inputs are 'Nothing', never a
-- crash.
classPkcs1Open :: ByteString -> ByteString -> Maybe ByteString
classPkcs1Open identity sealed
  | BS.length sealed < 16 = Nothing
  | not (ctEq tag (prfBytes (frame (pkcs1TagFrame identity body)) 16)) =
      Nothing
  | otherwise = Just (BS.packZipWith xor
      (prfBytes (frame (pkcs1StreamFrame identity)) (BS.length body))
      body)
  where
    (body, tag) = BS.splitAt (BS.length sealed - 16) sealed

pkcs1StreamFrame :: ByteString -> [ByteString]
pkcs1StreamFrame identity =
  ["haskoki-synth/class-pkcs1-stream/v1", identity]

pkcs1TagFrame :: ByteString -> ByteString -> [ByteString]
pkcs1TagFrame identity body =
  ["haskoki-synth/class-pkcs1-tag/v1", identity, body]

-- | Synthetic X.509 seal: the input left-pads to the modulus width
-- and XORs with the modulus-keyed stream. No tag (raw RSA has no
-- integrity, so opens never fail on content). 'Nothing' on empty
-- or over-wide input, never a crash.
classX509Seal :: ByteString -> ByteString -> Maybe ByteString
classX509Seal modulus input = do
  padded <- x509PadBlock (BS.length modulus) input
  pure (BS.packZipWith xor
    (prfBytes (frame (x509StreamFrame modulus)) (BS.length padded))
    padded)

-- | Open a synthetic X.509 block: XOR back. Non-modulus-wide
-- inputs are 'Nothing', never a crash.
classX509Open :: ByteString -> ByteString -> Maybe ByteString
classX509Open modulus sealed
  | BS.length sealed /= BS.length modulus = Nothing
  | otherwise = Just (BS.packZipWith xor
      (prfBytes (frame (x509StreamFrame modulus)) (BS.length sealed))
      sealed)

x509StreamFrame :: ByteString -> [ByteString]
x509StreamFrame modulus =
  ["haskoki-synth/class-x509-stream/v1", modulus]

-- | Class-interface cipher: length-preserving reversible stream
-- construction (keystream XOR over the owned key bytes and iv).
-- Empty input gives empty output; no padding is ever implied.
classCipher :: ByteString -> ByteString -> ByteString -> ByteString
classCipher kb iv input =
  BS.packZipWith xor (classStream kb iv (BS.length input)) input

-- | Spec-keyed cipher: the stream is domain-separated by the
-- backend spec, so two algorithms sharing a key and IV never emit
-- the same test ciphertext. AES-256-CBC keeps its legacy bytes
-- byte-for-byte (existing golden pins hold); every other spec tags
-- the key frame with its constructor name.
classCipherFor :: CipherSpec -> ByteString -> ByteString -> ByteString -> ByteString
classCipherFor C_AES256_CBC kb iv input = classCipher kb iv input
classCipherFor spec kb iv input =
  classCipher (BC8.pack (show spec) <> kb) iv input

-- | Synthetic wrap seal (test construction, NOT RFC 3394/5649):
-- the input is zero-padded to a multiple of 8, XORed with the
-- spec-keyed stream, and prefixed with an 8-byte keyed tag
-- (@\"HSKW\" <> u32be(length)@ XOR the wrap-tag stream). The IV
-- (empty for the fixed-AIV rows) mixes into the tag key and the
-- body stream, so alternate-IV seals differ deterministically.
-- Output expands exactly like the real thing (KW: inlen + 8; KWP:
-- ceil8(inlen) + 8) so shape-level parity holds.
synthWrapSeal :: CipherSpec -> ByteString -> ByteString -> ByteString -> ByteString
synthWrapSeal spec kb iv input =
  let n = BS.length input
      pad = (8 - n `mod` 8) `mod` 8
      body = classCipherFor spec kb iv (input <> BS.replicate pad 0)
      tag = BS.packZipWith xor
        (classStream (wrapTagKey spec kb <> iv) BS.empty 8)
        ("HSKW" <> word32BE n)
  in tag <> body

-- | Synthetic wrap open: verifies the keyed tag (magic plus
-- canonical zero padding) and returns the original bytes.
-- 'Nothing' (reported as AuthFailed) covers wrong keys,
-- corruption, truncation, and non-canonical padding.
synthWrapOpen :: CipherSpec -> ByteString -> ByteString -> ByteString -> Maybe ByteString
synthWrapOpen spec kb iv ct = do
  let (tag, body) = BS.splitAt 8 ct
  guard (BS.length tag == 8 && BS.length body >= 8 && BS.length body `mod` 8 == 0)
  let clear = BS.packZipWith xor
        (classStream (wrapTagKey spec kb <> iv) BS.empty 8) tag
  guard (BS.take 4 clear == "HSKW")
  let n = unword32BE (BS.drop 4 clear)
  guard (n <= BS.length body)
  let padded = classCipherFor spec kb iv body
      (pt, rest) = BS.splitAt n padded
  guard (BS.length rest == (8 - n `mod` 8) `mod` 8)
  guard (BS.all (== 0) rest)
  pure pt

-- | Domain separation for the wrap tag stream.
wrapTagKey :: CipherSpec -> ByteString -> ByteString
wrapTagKey spec kb = BC8.pack (show spec) <> kb <> "wrap-tag"

classStream :: ByteString -> ByteString -> Int -> ByteString
classStream kb iv n = prfBytes
  (frame ["haskoki-synth/class-stream/v1", kb, iv])
  n

-- | Class-interface digest: domain-separated expansion over the
-- algorithm tag and the input. The seed plays no part (as with the
-- retired record digest, only key generation is seed-keyed). Output
-- width follows 'synthDigestLengthFor'; SHA-256 output is
-- byte-identical to the original construction.
-- | Synthetic XOF output: the same labeled PRF stream as
-- 'classDigest' under a distinct domain, at the requested
-- length (non-positive lengths yield empty; callers range-check).
classXof :: DigestAlg -> ByteString -> Int -> ByteString
classXof alg input n = prfBytes
  (frame ["haskoki-synth/class-xof/v1", encodeAlg alg, input]) n
  where
    encodeAlg :: DigestAlg -> ByteString
    encodeAlg D_SHAKE128 = "SHAKE128"
    encodeAlg D_SHAKE256 = "SHAKE256"
    encodeAlg other = "NOT-XOF:" <> BS.pack (map (fromIntegral . fromEnum) (show other))

classDigest :: DigestAlg -> ByteString -> ByteString
classDigest alg input = prfBytes
  (frame ["haskoki-synth/class-digest/v1", encodeAlg alg, input])
  (synthDigestLengthFor alg)
  where
    encodeAlg :: DigestAlg -> ByteString
    encodeAlg D_MD5 = "MD5"
    encodeAlg D_SHA1 = "SHA1"
    encodeAlg D_SHA224 = "SHA224"
    encodeAlg D_SHA256 = "SHA256"
    encodeAlg D_SHA384 = "SHA384"
    encodeAlg D_SHA512 = "SHA512"
    encodeAlg D_SHA512_224 = "SHA512-224"
    encodeAlg D_SHA512_256 = "SHA512-256"
    encodeAlg D_SHA3_224 = "SHA3-224"
    encodeAlg D_SHA3_256 = "SHA3-256"
    encodeAlg D_SHA3_384 = "SHA3-384"
    encodeAlg D_SHA3_512 = "SHA3-512"
    encodeAlg D_RIPEMD160 = "RIPEMD160"
    encodeAlg D_SHAKE128 = "SHAKE128"
    encodeAlg D_SHAKE256 = "SHAKE256"
    encodeAlg D_BLAKE2B512 = "BLAKE2B-512"
    encodeAlg D_BLAKE2B160 = "BLAKE2B-160"
    encodeAlg D_BLAKE2B256 = "BLAKE2B-256"
    encodeAlg D_BLAKE2B384 = "BLAKE2B-384"
