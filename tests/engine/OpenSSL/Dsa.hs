{- | OpenSSL DSA and EdDSA cases.
-}
{-# LANGUAGE OverloadedStrings #-}
module OpenSSL.Dsa
  ( caseDsa
  , caseDsaKeygen
  , caseEddsa
  , caseRealEddsaKeygen
  ) where

import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import Test.Tasty.HUnit (assertBool, assertEqual, assertFailure)
import Haskoki.Engine.Backend
  ( CryptoBackend (..)
  , DigestAlg (..)
  , EcSpec (..)
  , KeyGenSpec (..)
  , KeyMaterial (..)
  , SigSpec (..)
  )
import OpenSSL.Fixtures

-- | DSA fixtures: CLI-generated (2048,224) keypair (pinned
-- @openssl dsaparam/gendsa@, PKCS#8 private half) plus a CLI
-- SHA-256 signature over 'dsaCliMsg' (cross-implementation KAT),
-- and the wycheproof (2048,256) group-0 SPKI with tc59 (valid)
-- and tc1 (invalid: r+q) P1363 vectors from
-- @dsa_2048_256_sha256_p1363_test.json@.
dsaCliPub :: ByteString
dsaCliPub = hex $ concat
  ["308203423082023506072a8648ce380401308202280282010100887ba402e537402944fc0b99930fe8dc2cf648f063ca5c40e7d8679f3c58"
  , "4d93125abf9d8e21daba7f1b64c8ed6e11ace9bb78ad66d71c71cdc2f3c0ea4341c174006c80f5833311dfd6dd7e902dc806ce1e470e9dfa"
  , "4fb7581b744b9412c42948d9f5c98cd2a9b3dabb058a6eb9d4adaa11ebf79cc665acaea98729ff6bab6172db75ef22dc55a440f0f89c4a0d"
  , "018756eb9077b6bad92500238caefe7bb42080a3f071340b8cf8c4ec8128dbad5352fec210030d649a172802d2f92763c02d051c97114d01"
  , "562cc82c8a40d5de28cab2e311a3e6842eaf990d3cb26096ed7a495b81e82472f770b0201a8aea0c27ecf5f6e711f2356f8f262d71cf4c6f"
  , "91fb021d00f9db1760fb0a352f4fed24e43fb2905f7156d7d425fb3a392468cc4102820100122cdd506b17ee6999e5874f3426a4540ba2be"
  , "d03c654b69149cad7cac01bbc0124f3881ea856b420eb5ec1d9d4a77b6c364d00161d711a32bc8edcc900233dce8814a56758f6e7caba971"
  , "e135b82d9b37a77e01cae0f7f38249578fec4f78dfaf64f372dd3bbd64ca8448199b30fbf44551f2a13b48c2e9a890cb715d87ea7a8060cc"
  , "8eb36afaa5b9cc89f7947b6345d482bff613b12cadf1cfa006b5694a6bb501ae76c9e759667a53f635757a5db97f50acf4447962b18ac91c"
  , "e966ed96cf0d6b52c9d5eeb049c634917cd450b24627ec12f2d8818f179b4df221d999e75e6835147abf4b0b68956b4db9d85fab096bdf9a"
  , "fac381c367ed0f1143f0ea87c303820105000282010060b8ba1b907936a778f3eb7027a6a6fdecc1ee0ae417fcec01aefbedb60e48bb4999"
  , "e10d49efcb2db0ada5c429212c8b52f59ecf71982c619a573b42ad63a94dcce71166ee4a9575a0c9188311194f7207f5fb91ff89ac8b11a0"
  , "b2119f6a0b67da8c5e073f0ad05da9c36a7b1bb7d731b91960d65e361c5e5d2d001d46586b54bbc40a3fa1d1a80db188b5b8deea97ac53e1"
  , "76972607ecf8c4dd96a3ed2d7d2817b32ac62c3899470ae8e30412eef07098ab75be9269570d3dfb4bc9db68df75398aee11f2218bcf7dca"
  , "414048a25ac59f8df695e435d0fb0e4a327063fc86bada9db51cc7b1f176f35ce11a985ae2e5a7b2e61bb55af290866fe2099f1050a9"
  ]

dsaCliPriv :: ByteString
dsaCliPriv = hex $ concat
  ["3082025b0201003082023506072a8648ce380401308202280282010100887ba402e537402944fc0b99930fe8dc2cf648f063ca5c40e7d867"
  , "9f3c584d93125abf9d8e21daba7f1b64c8ed6e11ace9bb78ad66d71c71cdc2f3c0ea4341c174006c80f5833311dfd6dd7e902dc806ce1e47"
  , "0e9dfa4fb7581b744b9412c42948d9f5c98cd2a9b3dabb058a6eb9d4adaa11ebf79cc665acaea98729ff6bab6172db75ef22dc55a440f0f8"
  , "9c4a0d018756eb9077b6bad92500238caefe7bb42080a3f071340b8cf8c4ec8128dbad5352fec210030d649a172802d2f92763c02d051c97"
  , "114d01562cc82c8a40d5de28cab2e311a3e6842eaf990d3cb26096ed7a495b81e82472f770b0201a8aea0c27ecf5f6e711f2356f8f262d71"
  , "cf4c6f91fb021d00f9db1760fb0a352f4fed24e43fb2905f7156d7d425fb3a392468cc4102820100122cdd506b17ee6999e5874f3426a454"
  , "0ba2bed03c654b69149cad7cac01bbc0124f3881ea856b420eb5ec1d9d4a77b6c364d00161d711a32bc8edcc900233dce8814a56758f6e7c"
  , "aba971e135b82d9b37a77e01cae0f7f38249578fec4f78dfaf64f372dd3bbd64ca8448199b30fbf44551f2a13b48c2e9a890cb715d87ea7a"
  , "8060cc8eb36afaa5b9cc89f7947b6345d482bff613b12cadf1cfa006b5694a6bb501ae76c9e759667a53f635757a5db97f50acf4447962b1"
  , "8ac91ce966ed96cf0d6b52c9d5eeb049c634917cd450b24627ec12f2d8818f179b4df221d999e75e6835147abf4b0b68956b4db9d85fab09"
  , "6bdf9afac381c367ed0f1143f0ea87c3041d021b17d4566d451940d21d58ac3059302cb8dabcdf2a80adaf36f21bd0"
  ]

dsaCliMsg :: ByteString
dsaCliMsg = hex "4453412066697874757265206d657373616765"

dsaCliSigDer :: ByteString
dsaCliSigDer = hex "303d021c2cf49ba16d76c738ce1d586bc5d5c24d24b5278f66167cd432b72e75021d009d247ced58ddc6591799508425029b03f145a3a9dff66d77ef68c2ce"

-- | EdDSA fixtures: Wycheproof ed25519 vectors (TEST 1 tcId 80,
-- group0 tc1 valid + tc10 invalid) copied from
-- @testvectors_v1/ed25519_test.json@ (SPKI-wrapped here for the
-- backend's KeyDer shape); a CLI cross-implementation KAT (pinned
-- @openssl pkeyutl@ over the KeyImportSpec Ed25519 key); and a
-- pinned-CLI Ed448 keypair for roundtrips.
edWyT1Pub :: ByteString
edWyT1Pub = hex $ concat
  ["302a300506032b6570032100d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
  ]

edWyT1Msg :: ByteString
edWyT1Msg = hex ""

edWyT1Sig :: ByteString
edWyT1Sig = hex $ concat
  ["e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46b"
  ,"d25bf5f0595bbe24655141438e7a100b"
  ]

edWyG0Pub :: ByteString
edWyG0Pub = hex $ concat
  ["302a300506032b65700321007d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa"
  ]

edWyG0Msg :: ByteString
edWyG0Msg = hex ""

edWyG0Sig :: ByteString
edWyG0Sig = hex $ concat
  ["d4fbdb52bfa726b44d1786a8c0d171c3e62ca83c9e5bbe63de0bb2483f8fd6cc1429ab72cafc41ab56af02ff8fcc43b9"
  ,"9bfe4c7ae940f60f38ebaa9d311c4007"
  ]

edWyBadMsg :: ByteString
edWyBadMsg = hex "3f"

edWyBadSig :: ByteString
edWyBadSig = hex $ concat
  ["000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
  ,"00000000000000000000000000000000"
  ]

edCliPriv :: ByteString
edCliPriv = hex $ concat
  ["302e020100300506032b657004220420e48c12f6fd3bd16c24e972eab3910d1053a23f9db0113d10d0835223f638dd05"
  ]

edCliPub :: ByteString
edCliPub = hex $ concat
  ["302a300506032b6570032100e3066819aa9f7d91c3c4ebad5584adeef588d8a1cbf2a09a8081d41cc5183402"
  ]

edCliMsg :: ByteString
edCliMsg = "eddsa cli kat message"

edCliSig :: ByteString
edCliSig = hex $ concat
  ["6b88ff1978856a802dd75dc694a6435d3df4da2909d43a00e5ec3718a7cce79cdeafacceabe5a05eb676f8315e9ca793"
  ,"0a9b1d6497562a3d650cb07cc20ce30e"
  ]

ed48Priv :: ByteString
ed48Priv = hex $ concat
  ["3047020100300506032b6571043b04398217a8d0ea3724199e10d866da9b2f582ce7c9a8aa37ad7763df96d48c210c1c"
  ,"3ef3fe87ad7ce40306f70747dfee39a799cd1a0ecb1481f9e1"
  ]

ed48Pub :: ByteString
ed48Pub = hex $ concat
  ["3043300506032b6571033a0086328bf04c3d241a0f05968cee630c68cdd2e2378a2f63e01ec215a661c7f83dddfddc78"
  ,"8c1102a2529c68b8d3c0155ec9e263561e2545d280"
  ]

dsaWyPub :: ByteString
dsaWyPub = hex $ concat
  ["308203463082023906072a8648ce3804013082022c0282010100faa45850a6f185cff01790524f60c6867461578fcb013cf340fe495b43b4"
  , "6acc759c0d2f61bfaef901f510274298876f3048f41d13697ccb77fb540ed0b3fbc7a60a3c97297310fa929d90837eeb6ed0ee82a36c5f4c"
  , "9dc4e2ea07d20f27675c48152abdf6f6dba66cfd8f58aed85d77ae8bb367b1348a5f46099d511507ad6575bbf8ec6ba48baa620cdcf1bd2e"
  , "c7aaafeae6d98d235921203af64814163cdd11424968f5ab77fad662306eea7ee69792f2b5d39d658ab9d927f368e68363ac18178e304096"
  , "33c4d488fb1fb92d22bca9214a4dfb720f28f4511f9be42e53e7f907d2d41f92bac9ca5e87580082390bbd0c229b2dc7e899aed654f7df06"
  , "2cf9022100fefbe4917b5ea7dbb3d5c62dc15bf430d8464813d2431819fe556832c3889d2f0282010038971fbfad52d9e8a84a2c17ed90cc"
  , "ff311648100e962c3269be255cab1471507ba40f457f5fb7990f6591b72b146e65213c619275b9b58d7597f41b42c55535592301e35b3a46"
  , "9dd5b204d70ccdd3cd477f65bd0f52eae53578fee143a43ae68b725c3c324fc91a84ecb7489dc67346ad11f3a0afdea009ce53201fa12207"
  , "aea5b4461ab0ffaa801beab94f648797aa1192be18345b270435ccb4678ce663c7bf35f7a7a3c98fc4907bd12701230469a18e3ae6327aca"
  , "d29dac259bc5f5e912e64fe7ad0364af74ecace858cbf7a36a1dac9f9ddc7665fb7c639019971cc2691e2b586666691914b4f3785ef0d1a8"
  , "3f34a8130ed29724ce443493fceee25aa7038201050002820100669300e7128ef31a126fb015c525596a21bbd43082f8ca6d6f7a9974e482"
  , "5085d1a50092956cd02016206c572d43eb90146f384454ac7f185f85af8855efcd3b9116c14e4ff859e07b2dad84f91fe23d7c09945368db"
  , "0ab30fff942741fcfa40f39ea82596370149bf168b79ef3067ba883ee3af6025465a79e96de11bd2f7f6eda740398ef4347ee4551b857128"
  , "1272f5cb83b0356f37e3ed5a19b084dff5156a3c78f8fdc3ccb5b3db431aa08a280c4a9da780aa4eeca8fb74ed7135b1370121c15328f17e"
  , "0504ea2e2c68e2e53268f875f17ce3cabd34e77866711c68c711a8ea4fa136a685cd07f5fff584d6c813cf3bffd0d705795998562b9235e6"
  , "1430"
  ]

dsaWyMsg :: ByteString
dsaWyMsg = hex "313233343030"

dsaWySig :: ByteString
dsaWySig = hex "3be2ad698f533f614e3a51d78516e1351c3290f3804f5a9f71e91957c3cddbe2be73fbe8557f552300c7419f25c44e7f0f9fd1e46bd4f3425e1618d320fd5ae6"

dsaWyBadSig :: ByteString
dsaWyBadSig = hex "01aace8c171d789060b16c9f594c85ae5c412aeea77ddf626fd7e20a7da13b0edc005bf17d17a8d9172cab83df9e56cccce8f282e35bbdbe99eadf8bc20ae9722c6f"

-- | DSA sign/verify: wycheproof KAT (tc59 valid verifies, tc1
-- r+q overlong refused by length), CLI cross-implementation DER KAT,
-- roundtrips over all 9 digests x RAW/DER plus the raw row, the
-- raw 20-byte floor, and typed key refusals.
caseDsa :: IO ()
caseDsa = withBackend $ \env -> do
  let wyRaw = SigDSA "RAW" (Just D_SHA256)
      cliPub = KeyDer dsaCliPub
      cliPriv = KeyDer dsaCliPriv
      wyPub = KeyDer dsaWyPub
      tamper bs = BS.init bs <> BS.singleton (BS.last bs + 1)
  -- Wycheproof KAT: tc59 (valid) verifies; tc1 (r+q) is 66
  -- bytes, not the 64 the q256 row requires, so length rejects it
  -- before the value check (right-length bad sigs still mismatch,
  -- pinned by the tampered leg below).
  expectOk "wycheproof tc59 valid" =<< verify env wyRaw wyPub dsaWyMsg dsaWySig
  expectSigLenRange "wycheproof tc1 invalid" =<< verify env wyRaw wyPub dsaWyMsg dsaWyBadSig
  expectAuthFailed "wycheproof tampered" =<< verify env wyRaw wyPub dsaWyMsg (tamper dsaWySig)
  -- Range still enforces at the right length: r above the group
  -- order (all-ones, wider than any 256-bit q) mismatches.
  expectAuthFailed "wycheproof r above q mismatches" =<<
    verify env wyRaw wyPub dsaWyMsg (BS.replicate 32 0xFF <> BS.drop 32 dsaWySig)
  -- CLI cross-implementation KAT (DER signature over dsaCliMsg).
  let cliDer = SigDSA "DER" (Just D_SHA256)
  expectOk "cli DER verifies" =<< verify env cliDer cliPub dsaCliMsg dsaCliSigDer
  expectAuthFailed "cli DER tampered" =<<
    verify env cliDer cliPub dsaCliMsg (tamper dsaCliSigDer)
  -- Roundtrips: every recipe digest x both encodings signs and
  -- verifies its own output (q=224: raw sigs are exactly 56 bytes).
  mapM_ (roundtrip env cliPriv cliPub tamper)
    [ D_SHA1, D_SHA224, D_SHA256, D_SHA384, D_SHA512
    , D_SHA3_224, D_SHA3_256, D_SHA3_384, D_SHA3_512
    ]
  -- Raw row: a 20-byte digest roundtrips; 7 bytes refuse typed.
  let raw = SigDSA "RAW" Nothing
      rawDer = SigDSA "DER" Nothing
      dgst20 = BS.replicate 20 0xA5
  sigRaw <- expectOk "raw sign" =<< sign env raw cliPriv dgst20
  assertEqual "raw sig is r||s" 56 (BS.length sigRaw)
  expectOk "raw verify" =<< verify env raw cliPub dgst20 sigRaw
  sigRawDer <- expectOk "raw DER sign" =<< sign env rawDer cliPriv dgst20
  assertBool "raw DER parses" (BS.take 1 sigRawDer == "\x30")
  expectOk "raw DER verify" =<< verify env rawDer cliPub dgst20 sigRawDer
  expectBadParam "raw short sign refuses" =<< sign env raw cliPriv (BS.replicate 7 0)
  expectBadParam "raw short verify refuses" =<< verify env raw cliPub (BS.replicate 7 0) sigRaw
  -- Wrong-length raw signatures refuse by length, never verify.
  expectSigLenRange "truncated raw refused by length" =<<
    verify env wyRaw wyPub dsaWyMsg (BS.init dsaWySig)
  expectSigLenRange "overlong raw refused by length" =<<
    verify env wyRaw wyPub dsaWyMsg (dsaWySig <> "\x00")
  -- Garbage keys refuse typed.
  expectBadKey "garbage sign refused" =<< sign env wyRaw (KeyDer "bogus") dsaWyMsg
  expectBadKey "garbage verify refused" =<< verify env wyRaw (KeyDer "bogus") dsaWyMsg dsaWySig
  where
    roundtrip env priv pub tamper alg = do
      let raw = SigDSA "RAW" (Just alg)
          der = SigDSA "DER" (Just alg)
          label = show alg
      sigR <- expectOk ("sign RAW " ++ label) =<< sign env raw priv dsaCliMsg
      assertEqual ("raw width " ++ label) 56 (BS.length sigR)
      expectOk ("verify RAW " ++ label) =<< verify env raw pub dsaCliMsg sigR
      sigD <- expectOk ("sign DER " ++ label) =<< sign env der priv dsaCliMsg
      expectOk ("verify DER " ++ label) =<< verify env der pub dsaCliMsg sigD
      expectAuthFailed ("tampered " ++ label) =<< verify env raw pub dsaCliMsg (tamper sigR)

-- | DSA generation: paramgen mints parseable (L,N) params, keygen
-- mints a usable pair from them, and garbage params refuse typed.
caseDsaKeygen :: IO ()
caseDsaKeygen = withBackend $ \env -> do
  (paramsM, Nothing) <- expectOk "paramgen 2048/256" =<<
    generateKey env (GenDSAParams 2048 256)
  paramsDer <- case paramsM of
    KeyDer der -> pure der
    other -> assertFailure ("paramgen answer is not DER: " ++ show other)
  (priv, Just pub) <- expectOk "keygen from params" =<<
    generateKey env (GenDSAKeypair paramsDer)
  let dsaSpec = SigDSA "RAW" (Just D_SHA256)
  sig <- expectOk "genkey sign" =<< sign env dsaSpec priv dsaCliMsg
  assertEqual "genkey raw width q256" 64 (BS.length sig)
  expectOk "genkey verify" =<< verify env dsaSpec pub dsaCliMsg sig
  expectBadKey "garbage params refused" =<<
    generateKey env (GenDSAKeypair "bogus")

-- | EdDSA: Wycheproof KATs (TEST 1 tcId 80 + group0 tc1 verify,
-- group0 tc10 invalid mismatches), a CLI cross-implementation KAT,
-- and roundtrips on both curves (fixed widths, determinism, empty
-- messages, typed key-shape refusals, cross-curve refusal).
caseEddsa :: IO ()
caseEddsa = withBackend $ \env -> do
  let ed19 = SigEdDSA (EcSpec "Ed25519" "RAW") ""
      ed48 = SigEdDSA (EcSpec "Ed448" "RAW") ""
      tamper bs = BS.init bs <> BS.singleton (BS.last bs + 1)
  -- Wycheproof KATs: TEST 1 + group0 tc1 verify; tc10 invalid
  -- and tampered vectors mismatch.
  expectOk "wycheproof TEST 1" =<<
    verify env ed19 (KeyDer edWyT1Pub) edWyT1Msg edWyT1Sig
  expectOk "wycheproof group0 tc1" =<<
    verify env ed19 (KeyDer edWyG0Pub) edWyG0Msg edWyG0Sig
  expectAuthFailed "wycheproof group0 tc10 invalid" =<<
    verify env ed19 (KeyDer edWyG0Pub) edWyBadMsg edWyBadSig
  expectAuthFailed "wycheproof TEST 1 tampered" =<<
    verify env ed19 (KeyDer edWyT1Pub) edWyT1Msg (tamper edWyT1Sig)
  -- CLI cross-implementation KAT (pkeyutl signature over edCliMsg).
  expectOk "cli verifies" =<<
    verify env ed19 (KeyDer edCliPub) edCliMsg edCliSig
  expectAuthFailed "cli tampered" =<<
    verify env ed19 (KeyDer edCliPub) edCliMsg (tamper edCliSig)
  -- Roundtrips: Ed25519 sigs are exactly 64 bytes, Ed448 114;
  -- signing is deterministic; empty messages serve.
  sig19 <- expectOk "sign Ed25519" =<<
    sign env ed19 (KeyDer edCliPriv) edCliMsg
  assertEqual "Ed25519 width" 64 (BS.length sig19)
  expectOk "verify Ed25519" =<<
    verify env ed19 (KeyDer edCliPub) edCliMsg sig19
  sig19b <- expectOk "resign Ed25519" =<<
    sign env ed19 (KeyDer edCliPriv) edCliMsg
  assertEqual "Ed25519 deterministic" sig19 sig19b
  expectAuthFailed "Ed25519 tampered" =<<
    verify env ed19 (KeyDer edCliPub) edCliMsg (tamper sig19)
  sigE <- expectOk "sign empty" =<<
    sign env ed19 (KeyDer edCliPriv) BS.empty
  expectOk "verify empty" =<<
    verify env ed19 (KeyDer edCliPub) BS.empty sigE
  sig48 <- expectOk "sign Ed448" =<<
    sign env ed48 (KeyDer ed48Priv) edCliMsg
  assertEqual "Ed448 width" 114 (BS.length sig48)
  expectOk "verify Ed448" =<<
    verify env ed48 (KeyDer ed48Pub) edCliMsg sig48
  expectAuthFailed "Ed448 tampered" =<<
    verify env ed48 (KeyDer ed48Pub) edCliMsg (tamper sig48)
  -- Wrong-length signatures refuse by length, never verify.
  expectSigLenRange "truncated refused by length" =<<
    verify env ed19 (KeyDer edCliPub) edCliMsg (BS.init sig19)
  expectSigLenRange "overlong refused by length" =<<
    verify env ed19 (KeyDer edCliPub) edCliMsg (sig19 <> "\x00")
  -- Garbage keys refuse typed.
  expectBadKey "garbage sign refused" =<<
    sign env ed19 (KeyDer "bogus") edCliMsg
  expectBadKey "garbage verify refused" =<<
    verify env ed19 (KeyDer "bogus") edCliMsg sig19
  -- Cross-curve execution refuses typed (the label is a hint;
  -- the shim checks the key's actual algorithm).
  expectBadKey "Ed448 key under Ed25519 refused" =<<
    sign env ed19 (KeyDer ed48Priv) edCliMsg
  expectBadKey "Ed25519 key under Ed448 refused" =<<
    sign env ed48 (KeyDer edCliPriv) edCliMsg
  -- Non-pure specs (context) stay unsupported.
  expectUnsupported "context unsupported" =<<
    sign env (SigEdDSA (EcSpec "Ed25519" "RAW") "CTX") (KeyDer edCliPriv) edCliMsg

-- | EdDSA generation: keygen mints usable pairs on both curves,
-- and unknown curves refuse typed.
caseRealEddsaKeygen :: IO ()
caseRealEddsaKeygen = withBackend $ \env -> do
  (priv19, Just pub19) <- expectOk "keygen Ed25519" =<<
    generateKey env (GenEdDSAKeypair "Ed25519")
  let spec19 = SigEdDSA (EcSpec "Ed25519" "RAW") ""
  sig19 <- expectOk "genkey sign Ed25519" =<< sign env spec19 priv19 edCliMsg
  assertEqual "genkey Ed25519 width" 64 (BS.length sig19)
  expectOk "genkey verify Ed25519" =<< verify env spec19 pub19 edCliMsg sig19
  (priv48, Just pub48) <- expectOk "keygen Ed448" =<<
    generateKey env (GenEdDSAKeypair "Ed448")
  let spec48 = SigEdDSA (EcSpec "Ed448" "RAW") ""
  sig48 <- expectOk "genkey sign Ed448" =<< sign env spec48 priv48 edCliMsg
  assertEqual "genkey Ed448 width" 114 (BS.length sig48)
  expectOk "genkey verify Ed448" =<< verify env spec48 pub48 edCliMsg sig48
  expectUnsupported "unknown curve refused" =<<
    generateKey env (GenEdDSAKeypair "P-256")
