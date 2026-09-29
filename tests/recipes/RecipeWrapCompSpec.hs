{- | Wrap-composition ECDH recipe tests.

The ECDH half of the wrap-composition group: 3 header mechanisms
sharing @wrapcomp-ecdh-params\/1@ (@kdf:u64be sharedLen:u64be
shared aesBits:u64be@, no peer field — the transport keypair is
ephemeral). Only @CKD_NULL@ (code 0) with @ulAESKeyBits@ in
128\/192\/256 is served; shared data is accepted and ignored
(the ECDH1 rule).

'Haskoki.Recipe.WrapComp' owns the codec, validation, key-type
gates, domain scan, transport framing, and blob split; these
tests pin the recipe. Consumers (planner arms, driver arms,
engines) pin their own layers against this table.
-}
{-# LANGUAGE OverloadedStrings #-}
module RecipeWrapCompSpec (spec) where

import qualified Data.ByteString as BS
import Data.Char (digitToInt, isHexDigit)
import Data.Text (Text)
import qualified Data.Text as T
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertBool, assertEqual, assertFailure, testCase)

import Haskoki.Attribute.Generated (mustKeyTypeId)
import Haskoki.Recipe.WrapComp
  ( WrapCompDomain (..)
  , WrapCompEcdhRecipe (..)
  , decodeWrapCompEcdhParams
  , encodeWrapCompEcdhParams
  , opaqueTransportLen
  , wrapCompAesBytes
  , wrapCompAgreePeer
  , wrapCompDomain
  , wrapCompEcdhKeyOk
  , wrapCompEcdhParamsValid
  , wrapCompEcdhRecipeFor
  , wrapCompEcdhRecipes
  , wrapCompSplitBlob
  , wrapCompTransportLen
  , wrapCompTransportPrefix
  )
import Haskoki.Registry (MechanismId (..))
import Haskoki.Registry.Generated
  ( mustGeneratedId
  )

spec :: TestTree
spec = testGroup "wrap-composition ECDH recipe"
  [ testCase "params codec roundtrips, faults refuse" caseParams
  , testCase "recipe table: 3 rows, gates, cofactor flags" caseTable
  , testCase "domain scan: DER curves resolve, garbage is opaque" caseDomain
  , testCase "transport lengths: framing matrix" caseTransportLen
  , testCase "transport prefix: SPKI framing per row" casePrefix
  , testCase "blob split: fixed, octet-parse, opaque, refusals" caseSplit
  ]

expectJust :: String -> Maybe a -> IO a
expectJust label = maybe (assertFailure ("expected Just: " ++ label)) pure

hex :: String -> BS.ByteString
hex s = BS.pack (go (filter isHexDigit s))
  where
    go [] = []
    go (a : b : rest) = fromIntegral (digitToInt a * 16 + digitToInt b) : go rest
    go [_] = error "hex: odd digit count"

-- Weierstrass fixtures (RecipeEcdhSpec vectors, copied verbatim).
p256Priv, p256Pub, p384Pub, p521Pub :: BS.ByteString
p256Priv = hex "308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b0201010420e9032e4f06ee6b5397252cfb48e73a8d3f7717d4024dd4cc5b98bbf041c11bb3a14403420004a348bab88ded75858acef31e9afa0ef8680ad8ec1196227b10083a630f029ecfc5503e37b76e2538f9ec2ceb6aa766cc7948071e6c39b9a93f0c54d5f7b12086"
p256Pub = hex "3059301306072a8648ce3d020106082a8648ce3d03010703420004a348bab88ded75858acef31e9afa0ef8680ad8ec1196227b10083a630f029ecfc5503e37b76e2538f9ec2ceb6aa766cc7948071e6c39b9a93f0c54d5f7b12086"
p384Pub = hex "3076301006072a8648ce3d020106052b8104002203620004467ab2e9c927f143e9f6151006e492da4d11c9e079e339f6086dfd988bd0cac51e25adf31d504a7c730a94c1c4b3bb880cffcceaf56ebc0c1a42e04051e8d11e409440f6a4924c1cfea44e8858601cd2a041d7340fe670712e91ca3ec5389a0c"
p521Pub = hex "30819b301006072a8648ce3d020106052b810400230381860004019eed1a84c846d69d26a869d864b0d1bf557cc7320ce1d8018f22f3b963f6b4c136b38d44c8cb2e21218e96f93aa82459dfb186d80fe06db19cc3c49989e1da9c1701a6889745283941b46bb94ab6f59ad10786191c910aa0183b702b25cd18de9afa5731805cab4f7e3309226b19e397fbaed8b54a03e2e9e1e79ec3862f0ca47a1fc9"

-- Montgomery fixtures (KeyImportSpec goldens, copied verbatim).
x19P8, x48P8, x19Spki :: BS.ByteString
x19P8 = hex "302e020100300506032b656e04220420107c0296168df7ef1da8bf471f5ac2d793788e84eb8b34d86a2605b2424d0847"
x48P8 = hex "3046020100300506032b656f043a0438f0b746caef9d715d94ecf3cc83b6b5caf0140402ff06b3043a56f2904b1594350ce4b7523116d8422a97365bb37c3f11f746e4765e71efad"
x19Spki = hex "302a300506032b656e032100684cd5fbe3473e3cb8dc7263ec9f0a837d770e5c9e2db619c8e9b0294b0e991d"

-- Opaque synthetic-shaped double: "HKS1" || pairId(32) || role(1) || mat(32).
opaquePub :: BS.ByteString
opaquePub = "HKS1" <> BS.replicate 32 0xA5 <> BS.singleton 1 <> BS.replicate 32 0x5A

recipeOf :: Text -> WrapCompEcdhRecipe
recipeOf name =
  case wrapCompEcdhRecipeFor (MechanismId (mustGeneratedId name)) of
    Just r -> r
    Nothing -> error ("test recipe missing: " ++ T.unpack name)

plainR, cofR, xR :: WrapCompEcdhRecipe
plainR = recipeOf "CKM_ECDH_AES_KEY_WRAP"
cofR = recipeOf "CKM_ECDH_COF_AES_KEY_WRAP"
xR = recipeOf "CKM_ECDH_X_AES_KEY_WRAP"

caseParams :: IO ()
caseParams = do
  let good = encodeWrapCompEcdhParams 0 BS.empty 128
  assertEqual "roundtrip" (Just (0, BS.empty, 128)) (decodeWrapCompEcdhParams good)
  assertBool "null kdf + 128 valid" (wrapCompEcdhParamsValid plainR good)
  mapM_ (\b ->
    assertBool ("strength valid: " ++ show b)
      (wrapCompEcdhParamsValid plainR (encodeWrapCompEcdhParams 0 BS.empty b))
    ) [128, 192, 256]
  assertEqual "aes bytes 128" (Just 16) (wrapCompAesBytes good)
  assertEqual "aes bytes 256" (Just 32)
    (wrapCompAesBytes (encodeWrapCompEcdhParams 0 BS.empty 256))
  assertBool "shared data ignored, still valid"
    (wrapCompEcdhParamsValid plainR (encodeWrapCompEcdhParams 0 "shared" 192))
  assertBool "rows share validation"
    (wrapCompEcdhParamsValid cofR good && wrapCompEcdhParamsValid xR good)
  -- Every nonzero KDF selector is refused.
  mapM_ (\k ->
    assertBool ("kdf refused: " ++ show k)
      (not (wrapCompEcdhParamsValid plainR (encodeWrapCompEcdhParams k BS.empty 128))
        && wrapCompAesBytes (encodeWrapCompEcdhParams k BS.empty 128) == Nothing)
    ) [1, 2, 3, 9]
  -- Off-set strengths are refused.
  mapM_ (\b ->
    assertBool ("strength refused: " ++ show b)
      (not (wrapCompEcdhParamsValid plainR (encodeWrapCompEcdhParams 0 BS.empty b)))
    ) [0, 64, 100, 257, 512]
  -- Framing faults refuse.
  assertBool "truncated refuses"
    (decodeWrapCompEcdhParams (BS.take 20 good) == Nothing)
  let over = encodeWrapCompEcdhParams 0 BS.empty 128
  assertBool "trailing byte refuses"
    (decodeWrapCompEcdhParams (over <> BS.pack [0]) == Nothing)

caseTable :: IO ()
caseTable = do
  assertEqual "3 rows" 3 (length wrapCompEcdhRecipes)
  assertBool "plain id" (wrapCompEcdhRecipeFor (MechanismId 0x1053) == Just plainR)
  assertBool "cof id" (wrapCompEcdhRecipeFor (MechanismId 0x4039) == Just cofR)
  assertBool "x id" (wrapCompEcdhRecipeFor (MechanismId 0x4038) == Just xR)
  assertBool "unknown id" (wrapCompEcdhRecipeFor (MechanismId 0xDEAD) == Nothing)
  assertEqual "cofactor flags" [False, True, False] (map wceCofactor wrapCompEcdhRecipes)
  let ckkEc = mustKeyTypeId "CKK_EC"
      ckkMont = mustKeyTypeId "CKK_EC_MONTGOMERY"
      ckkRsa = mustKeyTypeId "CKK_RSA"
  assertBool "plain takes EC" (wrapCompEcdhKeyOk plainR ckkEc)
  assertBool "plain takes Montgomery" (wrapCompEcdhKeyOk plainR ckkMont)
  assertBool "plain refuses RSA" (not (wrapCompEcdhKeyOk plainR ckkRsa))
  assertBool "cof takes EC" (wrapCompEcdhKeyOk cofR ckkEc)
  assertBool "cof refuses Montgomery" (not (wrapCompEcdhKeyOk cofR ckkMont))
  assertBool "x takes Montgomery" (wrapCompEcdhKeyOk xR ckkMont)
  assertBool "x refuses EC" (not (wrapCompEcdhKeyOk xR ckkEc))

caseDomain :: IO ()
caseDomain = do
  case wrapCompDomain p256Priv of
    DomainWeierstrass _ 32 -> pure ()
    d -> error ("P-256 priv domain: " ++ show d)
  case wrapCompDomain p256Pub of
    DomainWeierstrass _ 32 -> pure ()
    d -> error ("P-256 pub domain: " ++ show d)
  case wrapCompDomain p384Pub of
    DomainWeierstrass _ 48 -> pure ()
    d -> error ("P-384 pub domain: " ++ show d)
  case wrapCompDomain p521Pub of
    DomainWeierstrass _ 66 -> pure ()
    d -> error ("P-521 pub domain: " ++ show d)
  case wrapCompDomain x19P8 of
    DomainMontgomery _ 32 -> pure ()
    d -> error ("X25519 domain: " ++ show d)
  case wrapCompDomain x48P8 of
    DomainMontgomery _ 56 -> pure ()
    d -> error ("X448 domain: " ++ show d)
  assertEqual "garbage is opaque" DomainOpaque (wrapCompDomain "not-a-key")
  assertEqual "empty is opaque" DomainOpaque (wrapCompDomain BS.empty)
  assertEqual "opaque double is opaque" DomainOpaque (wrapCompDomain opaquePub)

caseTransportLen :: IO ()
caseTransportLen = do
  let domP256 = wrapCompDomain p256Pub
      domP384 = wrapCompDomain p384Pub
      domP521 = wrapCompDomain p521Pub
      domX19 = wrapCompDomain x19P8
      domX48 = wrapCompDomain x48P8
  -- Plain: bare points and raw coordinates.
  assertEqual "plain P-256" (Just 65) (wrapCompTransportLen plainR domP256)
  assertEqual "plain P-384" (Just 97) (wrapCompTransportLen plainR domP384)
  assertEqual "plain P-521" (Just 133) (wrapCompTransportLen plainR domP521)
  assertEqual "plain X25519" (Just 32) (wrapCompTransportLen plainR domX19)
  assertEqual "plain X448" (Just 56) (wrapCompTransportLen plainR domX48)
  -- Cofactor: OCTET STRING images (short form at P-256, long form at P-521).
  assertEqual "cof P-256" (Just 67) (wrapCompTransportLen cofR domP256)
  assertEqual "cof P-521" (Just 136) (wrapCompTransportLen cofR domP521)
  assertEqual "cof refuses Montgomery" Nothing (wrapCompTransportLen cofR domX19)
  -- X: Montgomery raw coordinates only.
  assertEqual "x X25519" (Just 32) (wrapCompTransportLen xR domX19)
  assertEqual "x X448" (Just 56) (wrapCompTransportLen xR domX48)
  assertEqual "x refuses Weierstrass" Nothing (wrapCompTransportLen xR domP256)
  -- Opaque doubles: the 69-byte half on every row.
  assertEqual "opaque const" 69 opaqueTransportLen
  mapM_ (\r ->
    assertEqual ("opaque " ++ T.unpack (wceName r)) (Just 69)
      (wrapCompTransportLen r DomainOpaque)
    ) wrapCompEcdhRecipes

casePrefix :: IO ()
casePrefix = do
  let domP256 = wrapCompDomain p256Pub
      domX19 = wrapCompDomain x19P8
  -- Plain Weierstrass: the bare point out of the SPKI.
  case wrapCompTransportPrefix plainR domP256 p256Pub of
    Just pt -> do
      assertEqual "bare point length" 65 (BS.length pt)
      assertEqual "uncompressed tag" 0x04 (BS.index pt 0)
      assertEqual "point tail" (BS.drop (BS.length p256Pub - 65) p256Pub) pt
    Nothing -> error "plain prefix failed"
  -- Cofactor: the OCTET STRING image of the same point.
  case wrapCompTransportPrefix cofR domP256 p256Pub of
    Just img -> do
      assertEqual "octet image length" 67 (BS.length img)
      assertEqual "octet header" (BS.pack [0x04, 0x41]) (BS.take 2 img)
    Nothing -> error "cof prefix failed"
  -- Montgomery: the raw u-coordinate out of the SPKI.
  case wrapCompTransportPrefix xR domX19 x19Spki of
    Just u -> assertEqual "raw u" (BS.drop (BS.length x19Spki - 32) x19Spki) u
    Nothing -> error "x prefix failed"
  assertEqual "plain frames Montgomery too"
    (wrapCompTransportPrefix plainR domX19 x19Spki)
    (wrapCompTransportPrefix xR domX19 x19Spki)
  -- Opaque doubles pass through verbatim, length-tripwired.
  assertEqual "opaque passthrough" (Just opaquePub)
    (wrapCompTransportPrefix plainR DomainOpaque opaquePub)
  assertEqual "opaque short refused" Nothing
    (wrapCompTransportPrefix plainR DomainOpaque (BS.take 68 opaquePub))
  -- Garbage framing refuses.
  assertEqual "garbage SPKI refused" Nothing
    (wrapCompTransportPrefix plainR domP256 "not-an-spki")
  assertEqual "row/domain contradiction refused" Nothing
    (wrapCompTransportPrefix cofR domX19 x19Spki)

caseSplit :: IO ()
caseSplit = do
  let domP256 = wrapCompDomain p256Pub
      domP521 = wrapCompDomain p521Pub
      domX19 = wrapCompDomain x19P8
      kwp = BS.replicate 24 0xCC
  -- Fixed splits invert framing.
  pre <- expectJust "plain prefix" (wrapCompTransportPrefix plainR domP256 p256Pub)
  assertEqual "plain split" (Just (pre, kwp))
    (wrapCompSplitBlob plainR domP256 (pre <> kwp))
  u <- expectJust "x prefix" (wrapCompTransportPrefix xR domX19 x19Spki)
  assertEqual "x split" (Just (u, kwp))
    (wrapCompSplitBlob xR domX19 (u <> kwp))
  assertEqual "opaque split" (Just (opaquePub, kwp))
    (wrapCompSplitBlob plainR DomainOpaque (opaquePub <> kwp))
  -- Cofactor parses the OCTET prefix (short and long forms).
  img <- expectJust "cof prefix" (wrapCompTransportPrefix cofR domP256 p256Pub)
  case wrapCompSplitBlob cofR domP256 (img <> kwp) of
    Just (got, rest) -> do
      assertEqual "cof image" img got
      assertEqual "cof kwp" kwp rest
    Nothing -> error "cof split failed"
  img521 <- expectJust "cof P-521 prefix" (wrapCompTransportPrefix cofR domP521 p521Pub)
  assertEqual "cof P-521 image length" 136 (BS.length img521)
  case wrapCompSplitBlob cofR domP521 (img521 <> kwp) of
    Just (got, rest) -> do
      assertEqual "cof P-521 image" img521 got
      assertEqual "cof P-521 kwp" kwp rest
    Nothing -> error "cof P-521 split failed"
  -- Refusals: short blobs, length lies, non-points.
  assertEqual "short blob refused" Nothing
    (wrapCompSplitBlob plainR domP256 (BS.take 70 (pre <> kwp)))
  assertEqual "ragged KWP tail refused" Nothing
    (wrapCompSplitBlob plainR domP256 (pre <> BS.replicate 20 0xCC))
  assertEqual "length lie refused" Nothing
    (wrapCompSplitBlob cofR domP256 (BS.pack [0x04, 0x41] <> BS.replicate 10 0 <> kwp))
  assertEqual "non-point octet refused" Nothing
    (wrapCompSplitBlob cofR domP256 (BS.pack [0x04, 0x41] <> BS.replicate 65 0x02 <> kwp))
  assertEqual "contradiction refused" Nothing
    (wrapCompSplitBlob xR domP256 (pre <> kwp))
  -- Agreement peers: the inner point out of cofactor images, the
  -- prefix itself everywhere else.
  assertEqual "cof peer is the inner point" (Just pre)
    (wrapCompAgreePeer cofR domP256 img)
  assertEqual "plain peer is the prefix" (Just pre)
    (wrapCompAgreePeer plainR domP256 pre)
  assertEqual "x peer is the prefix" (Just u)
    (wrapCompAgreePeer xR domX19 u)
  assertEqual "opaque peer is the prefix" (Just opaquePub)
    (wrapCompAgreePeer plainR DomainOpaque opaquePub)
  assertEqual "cof garbage refused" Nothing
    (wrapCompAgreePeer cofR domP256 "not-an-image")
