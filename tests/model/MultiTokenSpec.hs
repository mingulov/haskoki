{- | Multi-token serving suite (seating/enumeration/sessions/info,
auth/object isolation).

Drives the real 'Haskoki.FFI.Standard' exports in-process over two
harnesses: manually seated instances (slot-0-only gaps fail here)
and catalog-driven opens (the fixture through the
'openStdInstance' seam). The multi-token fixture uses memory
storage; the SQLite round-trip case overrides the store path to a
dedicated temp file (never the default store).
-}
module MultiTokenSpec (spec) where

import Control.Exception (bracket)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BC8
import Data.Char (chr, ord)
import Data.IORef (newIORef)
import Data.List (isInfixOf, nub)
import qualified Data.Map.Strict as Map
import Data.Word (Word64, Word8)
import Foreign.C.Types (CULong (..))
import Foreign.Marshal.Alloc (alloca)
import Foreign.Marshal.Array (advancePtr, allocaArray, peekArray)
import Foreign.Ptr (Ptr, castPtr, nullPtr)
import Foreign.StablePtr (StablePtr, castStablePtrToPtr, newStablePtr)
import Foreign.Storable (peek, poke)
import System.Directory (getTemporaryDirectory, removeFile)
import System.FilePath ((</>))
import System.IO.Error (tryIOError)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertBool, assertEqual, testCase)

import Haskoki.Ctl (CtlExit (..), runCtl)
import Haskoki.Engine.Backend
  ( BackendEnv
  , CryptoBackend (..)
  , EngineResult (..)
  )
import Haskoki.Engine.OpenSSL4 (OpenSSL4)
import Haskoki.FFI.Notify (invokeNativeNotify)
import Haskoki.FFI.Standard
  ( StdInstance (..)
  , haskokiStdClose
  , haskokiStdCloseAllSessions
  , haskokiStdCloseSession
  , haskokiStdCreateObject
  , haskokiStdDestroyObject
  , haskokiStdFind
  , haskokiStdFindFinal
  , haskokiStdFindInit
  , haskokiStdGetOneAttr
  , haskokiStdGetSessionInfo
  , haskokiStdGetSlotList
  , haskokiStdInitToken
  , haskokiStdLogin
  , haskokiStdLogout
  , haskokiStdOpenSession
  , haskokiStdSlotPresent
  , haskokiStdTokenLabel
  , haskokiStdTokenLive
  , haskokiStdTokenSerial
  , homeTokenId
  , homeTokenLabel
  , openStdInstance
  , tokenIdForSlot
  )
import Haskoki.Model (Model (..))
import Haskoki.Rules (defaultRules)
import Haskoki.Runtime.SlotEvents (SlotDefinition (..), newSlotEvents)
import Haskoki.Runtime.Async (newAsyncTable)
import Haskoki.Runtime.Config
  ( Config (..)
  , Limits (..)
  , StorageCfg (..)
  , StorageKind (..)
  , TokensCfg (..)
  , defaultConfig
  , loadConfigFile
  , parseConfig
  )
import Haskoki.Runtime.Lifecycle
  ( defaultInitArgs
  , initialize
  , newEnv
  , restoreStoreState
  , seatToken
  , snapshotModel
  )
import Haskoki.Runtime.Storage (TokenRecord (..))
import Haskoki.Session (TokenAuth (..), tokenAuthNew)
import Haskoki.Types (Generation (..), Outcome (..), SlotId (..), TokenId (..))

spec :: TestTree
spec = testGroup "Multi-token"
  [ testCase "three seated slots enumerate three" caseEnumerateThree
  , testCase "slot 2 opens a session" caseOpenSessionSlot2
  , testCase "slot 1 token is live (info seam)" caseTokenLiveSlot1
  , testCase "token-present filtering follows seating" casePresentFiltering
  , testCase "bad slot refused (guard)" caseBadSlot
  , testCase "catalog seats three (fixture open)" caseCatalogSeatsThree
  , testCase "per-slot labels served padded" caseCatalogLabels
  , testCase "sessions open per slot" caseCatalogSessions
  , testCase "close-all is slot-scoped" caseCloseAllPerSlot
  , testCase "beyond-catalog slots refused" caseCatalogBadSlot
  , testCase "default config serves home only" caseDefaultByteIdentical
  , testCase "over-bound catalog refuses the open" caseSeatBoundRefuses
  , testCase "sqlite store round-trips three tokens" caseSqliteRoundTrip
  , testCase "store reload restores three tokens" caseRestoreThree
  , testCase "per-slot token ids unique" caseTokenIdsUnique
  , testCase "memory serials follow pinned token ids" caseMemorySerialPinned
  , testCase "cross-slot login independence" caseLoginIndependent
  , testCase "cross-slot object invisibility" caseObjectsIsolated
  , testCase "user PINs route per slot" casePerSlotPins
  , testCase "SO PINs route per slot" caseSoPerSlot
  , testCase "shrunk catalog over a reused store is refused" caseCatalogShrinkRefused
  , testCase "reinit with a wrong SO PIN refuses and preserves" caseReinitWrongPinRefused
  , testCase "reinit with the SO PIN resets its own token" caseReinitCorrectPinResets
  , testCase "reinit with sessions open refuses" caseReinitSessionsRefuse
  , testCase "locked SO recovers through authorized reinit" caseReinitLockedSoRecovery
  ]

fixturePath :: FilePath
fixturePath = "tests/ops/fixtures/multi-token.toml"

-- | Open a live instance with exactly the given slots seated (fresh
-- Env, provider init, per-slot 'seatToken', live OpenSSL4 backend,
-- empty find cursors, no store). Catalog lookups fall back to the
-- home entry (no catalog data): manual instances test slot
-- mechanics, catalog-driven opens test catalog data.
openManualInstance :: [SlotId] -> IO (StablePtr StdInstance)
openManualInstance slots = do
  env <- newEnv defaultRules
  ini <- initialize env defaultInitArgs
  case ini of
    OutcomeErr code -> fail ("manual init failed: " ++ show code)
    OutcomeOk () -> pure ()
  mapM_ (seatOne env) slots
  eBe <- openBackend "provider=default" :: IO (EngineResult (BackendEnv OpenSSL4))
  be <- case eBe of
    EngineFail err -> fail ("manual backend open failed: " ++ show err)
    EngineOk b -> pure b
  cursors <- newIORef Map.empty
  table <- newAsyncTable 8
  views <- newIORef Map.empty
  bindings <- newIORef Map.empty
  notify <- newIORef Map.empty
  hub <- newSlotEvents (max 1 (length slots)) [SlotDefinition slot False | slot <- slots]
    >>= either (fail . show) pure
  serving <- newIORef Map.empty
  dirty <- newIORef []
  newStablePtr (StdInstance env be cursors Nothing Map.empty Map.empty
    serving dirty hub (pure ()) (closeBackend be) table Nothing views bindings
    notify invokeNativeNotify Nothing)
  where
    seatOne env slot = do
      eSeat <- seatToken env slot
      case eSeat of
        Left deny -> fail ("manual seat failed: " ++ show deny)
        Right () -> pure ()

-- | Bracket a manually seated instance (closed via the real close).
withManualInstance :: [SlotId] -> (StablePtr StdInstance -> IO a) -> IO a
withManualInstance slots = bracket (openManualInstance slots) haskokiStdClose

-- | Load the multi-token fixture (fails the test on any error).
loadFixtureConfig :: IO Config
loadFixtureConfig = do
  eCfg <- loadConfigFile fixturePath
  case eCfg of
    Left err -> fail ("multi-token fixture must parse: " ++ show err)
    Right cfg -> pure cfg

-- | Bracket a catalog-driven open of the given config.
withConfigInstance :: Config -> (StablePtr StdInstance -> IO a) -> IO a
withConfigInstance cfg = bracket (openStdInstance cfg) haskokiStdClose

-- | Bracket a catalog-driven open of the fixture.
withCatalogInstance :: (StablePtr StdInstance -> IO a) -> IO a
withCatalogInstance action = do
  cfg <- loadFixtureConfig
  withConfigInstance cfg action

-- | Open one read/write session on the given slot (fails unless OK).
openSession :: StablePtr StdInstance -> CULong -> IO CULong
openSession inst slot =
  alloca $ \(phSession :: Ptr CULong) -> do
    poke phSession (CULong 0)
    rv <- haskokiStdOpenSession inst slot (CULong 0) phSession
    assertEqual "open rv" (CULong 0) rv
    peek phSession

-- | Read one slot's 32 label bytes (fails unless OK).
readLabel :: StablePtr StdInstance -> CULong -> IO [Word8]
readLabel inst slot =
  allocaArray 32 $ \(buf :: Ptr Word8) -> do
    rv <- haskokiStdTokenLabel inst slot buf
    assertEqual "label rv" (CULong 0) rv
    peekArray 32 buf

-- | Blank-pad a label the way the C record expects (32 bytes).
padded :: String -> [Word8]
padded s = take 32 (map (fromIntegral . ord) s ++ repeat 0x20)

-- | Log in on a session with the given CKU_* role word (0 SO, 1
-- user) and PIN bytes.
loginAs :: StablePtr StdInstance -> CULong -> CULong -> String -> IO CULong
loginAs inst h userType pinStr =
  BS.useAsCStringLen (BC8.pack pinStr) $ \(cstr, len) ->
    haskokiStdLogin inst h userType (castPtr cstr) (fromIntegral len)

-- | Read one session's provider-local login code (0 public, 1
-- user, 2 SO, 3 context grant; fails unless the info call is OK).
sessionLoginOf :: StablePtr StdInstance -> CULong -> IO CULong
sessionLoginOf inst h =
  alloca $ \(pSlot :: Ptr CULong) ->
  alloca $ \(pRO :: Ptr CULong) ->
  alloca $ \(pLogin :: Ptr CULong) ->
  alloca $ \(pDevErr :: Ptr CULong) -> do
    rv <- haskokiStdGetSessionInfo inst h pSlot pRO pLogin pDevErr
    assertEqual "session-info rv" (CULong 0) rv
    peek pLogin

-- | Little-endian u64 (template-frame integer order).
le64 :: Word64 -> BS.ByteString
le64 w = BS.pack
  [fromIntegral ((w `div` (256 ^ s)) `mod` 256) | s <- [0 .. 7 :: Int]]

-- | Pack a template frame: count + (type, len, value) records.
buildFrame :: [(Word64, BS.ByteString)] -> BS.ByteString
buildFrame attrs =
  le64 (fromIntegral (length attrs))
    <> mconcat [le64 t <> le64 (fromIntegral (BS.length v)) <> v | (t, v) <- attrs]

-- | Create one object on a session (fails unless OK; returns the
-- handle).
createObject :: StablePtr StdInstance -> CULong -> BS.ByteString -> IO CULong
createObject inst h frame =
  BS.useAsCStringLen frame $ \(cstr, len) ->
    alloca $ \(phObject :: Ptr CULong) -> do
      poke phObject (CULong 0)
      rv <- haskokiStdCreateObject inst h (castPtr cstr) (fromIntegral len) phObject
      assertEqual "create rv" (CULong 0) rv
      peek phObject

-- | Find every visible object on a session (empty template; fails
-- unless every leg is OK).
findAll :: StablePtr StdInstance -> CULong -> IO [CULong]
findAll inst h =
  BS.useAsCStringLen (le64 0) $ \(cstr, len) -> do
    rvInit <- haskokiStdFindInit inst h (castPtr cstr) (fromIntegral len)
    assertEqual "find-init rv" (CULong 0) rvInit
    allocaArray 8 $ \(pHandles :: Ptr CULong) ->
      alloca $ \(pCount :: Ptr CULong) -> do
        poke pCount (CULong 0)
        rvFind <- haskokiStdFind inst h 8 pHandles pCount
        assertEqual "find rv" (CULong 0) rvFind
        CULong n <- peek pCount
        hits <- peekArray (fromIntegral n) pHandles
        rvFinal <- haskokiStdFindFinal inst h
        assertEqual "find-final rv" (CULong 0) rvFinal
        pure hits

-- | Read one attribute's bytes (code + bytes; bytes empty unless OK).
getAttrBytes
  :: StablePtr StdInstance -> CULong -> CULong -> Word64 -> IO (CULong, BS.ByteString)
getAttrBytes inst h obj cka =
  allocaArray 64 $ \(buf :: Ptr Word8) ->
    alloca $ \(pLen :: Ptr CULong) -> do
      poke pLen (CULong 64)
      rv <- haskokiStdGetOneAttr inst h obj (CULong cka) buf pLen
      if rv == CULong 0
        then do
          CULong n <- peek pLen
          bytes <- BS.packCStringLen (castPtr buf, fromIntegral n)
          pure (rv, bytes)
        else pure (rv, BS.empty)

-- | Three seated slots enumerate as [0,1,2] (count query +
-- fill legs).
caseEnumerateThree :: IO ()
caseEnumerateThree =
  withManualInstance [SlotId 0, SlotId 1, SlotId 2] $ \inst ->
    alloca $ \(pCount :: Ptr CULong) -> do
      poke pCount (CULong 0)
      rvQuery <- haskokiStdGetSlotList inst 0 nullPtr pCount
      CULong nQuery <- peek pCount
      assertEqual "count-query rv" (CULong 0) rvQuery
      assertEqual "three slots" 3 nQuery
      poke pCount (CULong 3)
      allocaArray 3 $ \(pList :: Ptr CULong) -> do
        rvFill <- haskokiStdGetSlotList inst 0 pList pCount
        CULong nFill <- peek pCount
        ids <- peekArray 3 pList
        assertEqual "fill rv" (CULong 0) rvFill
        assertEqual "fill count" 3 nFill
        assertEqual "slot ids" [CULong 0, CULong 1, CULong 2] ids

-- | A session opens on slot 2. Before multi-token seating, the
-- slot/=0 check refused with SLOT_ID_INVALID (0x03).
caseOpenSessionSlot2 :: IO ()
caseOpenSessionSlot2 =
  withManualInstance [SlotId 0, SlotId 1, SlotId 2] $ \inst ->
    alloca $ \(phSession :: Ptr CULong) -> do
      poke phSession (CULong 0)
      rv <- haskokiStdOpenSession inst (CULong 2) (CULong 0) phSession
      CULong h <- peek phSession
      assertEqual "slot-2 open rv" (CULong 0) rv
      assertEqual "slot-2 handle valid" True (h /= 0)

-- | The slot-1 token liveness seam answers CKR_OK (the
-- GetTokenInfo body consults it per slot).
caseTokenLiveSlot1 :: IO ()
caseTokenLiveSlot1 =
  withManualInstance [SlotId 0, SlotId 1, SlotId 2] $ \inst ->
    allocaArray 6 $ \(buf :: Ptr CULong) -> do
      rv <- haskokiStdTokenLive inst (CULong 1)
        (buf `advancePtr` 0) (buf `advancePtr` 1) (buf `advancePtr` 2)
        (buf `advancePtr` 3) (buf `advancePtr` 4) (buf `advancePtr` 5)
      assertEqual "slot-1 token-live rv" (CULong 0) rv

-- | Token-present filtering follows seating (two seated of
-- three possible slots report 2, both with and without the
-- token-present flag — every seated slot holds a token).
casePresentFiltering :: IO ()
casePresentFiltering =
  withManualInstance [SlotId 0, SlotId 1] $ \inst ->
    alloca $ \(pCount :: Ptr CULong) -> do
      poke pCount (CULong 0)
      rvPresent <- haskokiStdGetSlotList inst 1 nullPtr pCount
      CULong nPresent <- peek pCount
      assertEqual "present-query rv" (CULong 0) rvPresent
      assertEqual "two present slots" 2 nPresent
      poke pCount (CULong 0)
      rvAll <- haskokiStdGetSlotList inst 0 nullPtr pCount
      CULong nAll <- peek pCount
      assertEqual "all-query rv" (CULong 0) rvAll
      assertEqual "two slots" 2 nAll
      -- The token-present filter is vacuous by
      -- design — the filled present-list equals the filled
      -- all-list, not just the counts.
      allocaArray 2 $ \(pList :: Ptr CULong) -> do
        poke pCount (CULong 2)
        rvFillPresent <- haskokiStdGetSlotList inst 1 pList pCount
        presentIds <- peekArray 2 pList
        poke pCount (CULong 2)
        rvFillAll <- haskokiStdGetSlotList inst 0 pList pCount
        allIds <- peekArray 2 pList
        assertEqual "present fill rv" (CULong 0) rvFillPresent
        assertEqual "all fill rv" (CULong 0) rvFillAll
        assertEqual "present list equals all list" allIds presentIds

-- | GUARD: unseated slots
-- refuse with SLOT_ID_INVALID (0x03) on every slot-taking seam.
caseBadSlot :: IO ()
caseBadSlot =
  withManualInstance [SlotId 0, SlotId 1] $ \inst ->
    alloca $ \(phSession :: Ptr CULong) -> do
      poke phSession (CULong 0)
      rvOpen <- haskokiStdOpenSession inst (CULong 99) (CULong 0) phSession
      assertEqual "bad-slot open refused" (CULong 0x03) rvOpen
      allocaArray 6 $ \(buf :: Ptr CULong) -> do
        rvLive <- haskokiStdTokenLive inst (CULong 99)
          (buf `advancePtr` 0) (buf `advancePtr` 1) (buf `advancePtr` 2)
          (buf `advancePtr` 3) (buf `advancePtr` 4) (buf `advancePtr` 5)
        assertEqual "bad-slot token-live refused" (CULong 0x03) rvLive

-- | The fixture open seats all three catalog slots
-- (count query + fill + token-present legs).
caseCatalogSeatsThree :: IO ()
caseCatalogSeatsThree =
  withCatalogInstance $ \inst ->
    alloca $ \(pCount :: Ptr CULong) -> do
      poke pCount (CULong 0)
      rvQuery <- haskokiStdGetSlotList inst 0 nullPtr pCount
      CULong nQuery <- peek pCount
      assertEqual "count-query rv" (CULong 0) rvQuery
      assertEqual "three slots" 3 nQuery
      poke pCount (CULong 3)
      allocaArray 3 $ \(pList :: Ptr CULong) -> do
        rvFill <- haskokiStdGetSlotList inst 0 pList pCount
        CULong nFill <- peek pCount
        ids <- peekArray 3 pList
        assertEqual "fill rv" (CULong 0) rvFill
        assertEqual "fill count" 3 nFill
        assertEqual "slot ids" [CULong 0, CULong 1, CULong 2] ids
      poke pCount (CULong 0)
      rvPresent <- haskokiStdGetSlotList inst 1 nullPtr pCount
      CULong nPresent <- peek pCount
      assertEqual "present-query rv" (CULong 0) rvPresent
      assertEqual "three present slots" 3 nPresent

-- | Each catalog slot serves its own label, blank-padded
-- to the 32-byte CK_TOKEN_INFO field.
caseCatalogLabels :: IO ()
caseCatalogLabels =
  withCatalogInstance $ \inst -> do
    l0 <- readLabel inst (CULong 0)
    l1 <- readLabel inst (CULong 1)
    l2 <- readLabel inst (CULong 2)
    assertEqual "slot-0 label" (padded "haskoki-demo") l0
    assertEqual "slot-1 label" (padded "haskoki-ops") l1
    assertEqual "slot-2 label" (padded "haskoki-audit") l2

-- | Sessions open on every catalog slot with distinct
-- handles.
caseCatalogSessions :: IO ()
caseCatalogSessions =
  withCatalogInstance $ \inst -> do
    h0 <- openSession inst (CULong 0)
    h1 <- openSession inst (CULong 1)
    h2 <- openSession inst (CULong 2)
    assertEqual "three distinct handles" 3 (length (nub [h0, h1, h2]))

-- | Close-all closes exactly its slot's sessions (slot-0
-- session survives close-all(1); the slot-1 handle dies with
-- SESSION_HANDLE_INVALID, 0xB3).
caseCloseAllPerSlot :: IO ()
caseCloseAllPerSlot =
  withCatalogInstance $ \inst -> do
    h0 <- openSession inst (CULong 0)
    h1 <- openSession inst (CULong 1)
    rvClose <- haskokiStdCloseAllSessions inst (CULong 1)
    assertEqual "close-all rv" (CULong 0) rvClose
    rv0 <- haskokiStdCloseSession inst h0
    assertEqual "slot-0 session survives" (CULong 0) rv0
    rv1 <- haskokiStdCloseSession inst h1
    assertEqual "slot-1 session died" (CULong 0xB3) rv1

-- | Slots past the catalog refuse on every slot-taking
-- seam (open, close-all, label, present).
caseCatalogBadSlot :: IO ()
caseCatalogBadSlot =
  withCatalogInstance $ \inst -> do
    alloca $ \(phSession :: Ptr CULong) -> do
      poke phSession (CULong 0)
      rvOpen <- haskokiStdOpenSession inst (CULong 3) (CULong 0) phSession
      assertEqual "slot-3 open refused" (CULong 0x03) rvOpen
    rvClose <- haskokiStdCloseAllSessions inst (CULong 3)
    assertEqual "slot-3 close-all refused" (CULong 0x03) rvClose
    allocaArray 32 $ \(buf :: Ptr Word8) -> do
      rvLabel <- haskokiStdTokenLabel inst (CULong 3) buf
      assertEqual "slot-3 label refused" (CULong 0x03) rvLabel
    rvPresent <- haskokiStdSlotPresent inst (CULong 3)
    assertEqual "slot-3 absent" (CULong 0x03) rvPresent
    rvPresent0 <- haskokiStdSlotPresent inst (CULong 0)
    assertEqual "slot-0 present" (CULong 0) rvPresent0

-- | Default-config stability: without [tokens] the open
-- serves exactly the home token (count 1, demo label, slot 1
-- refused everywhere).
caseDefaultByteIdentical :: IO ()
caseDefaultByteIdentical =
  withConfigInstance defaultConfig $ \inst ->
    alloca $ \(pCount :: Ptr CULong) -> do
      poke pCount (CULong 0)
      rvQuery <- haskokiStdGetSlotList inst 0 nullPtr pCount
      CULong nQuery <- peek pCount
      assertEqual "count-query rv" (CULong 0) rvQuery
      assertEqual "one slot" 1 nQuery
      poke pCount (CULong 1)
      allocaArray 1 $ \(pList :: Ptr CULong) -> do
        rvFill <- haskokiStdGetSlotList inst 0 pList pCount
        ids <- peekArray 1 pList
        assertEqual "fill rv" (CULong 0) rvFill
        assertEqual "slot id" [CULong 0] ids
      l0 <- readLabel inst (CULong 0)
      assertEqual "home label" (padded homeTokenLabel) l0
      alloca $ \(phSession :: Ptr CULong) -> do
        poke phSession (CULong 0)
        rvOpen <- haskokiStdOpenSession inst (CULong 1) (CULong 0) phSession
        assertEqual "slot-1 open refused" (CULong 0x03) rvOpen
      rvPresent <- haskokiStdSlotPresent inst (CULong 1)
      assertEqual "slot-1 absent" (CULong 0x03) rvPresent

-- | A catalog larger than the seating bound refuses the
-- whole open loudly (NULL) instead of truncating.
caseSeatBoundRefuses :: IO ()
caseSeatBoundRefuses = do
  cfg <- loadFixtureConfig
  let squeezed = cfg { cfgLimits = (cfgLimits cfg) { limSlots = 1 } }
  inst <- openStdInstance squeezed
  assertBool "over-bound catalog refuses the open"
    (castStablePtrToPtr inst == nullPtr)

-- | The SQLite path commits one row per catalog token on
-- first open and serves all three again after reopen (dedicated
-- temp store path, never the default store).
caseSqliteRoundTrip :: IO ()
caseSqliteRoundTrip = do
  base <- getTemporaryDirectory
  let dbPath = base </> "haskoki-multitoken.sqlite"
  _ <- tryIOError (removeFile dbPath)
  _ <- tryIOError (removeFile (dbPath ++ ".lock"))
  cfg <- loadFixtureConfig
  let sqliteCfg = cfg
        { cfgStorage = StorageCfg StorageSQLite (Just dbPath) 5000 True }
  withConfigInstance sqliteCfg $ \inst ->
    alloca $ \(pCount :: Ptr CULong) -> do
      poke pCount (CULong 0)
      rvQuery <- haskokiStdGetSlotList inst 0 nullPtr pCount
      CULong nQuery <- peek pCount
      assertEqual "first-open rv" (CULong 0) rvQuery
      assertEqual "first-open three slots" 3 nQuery
  rInspect <- runCtl ["store", "inspect", "--path", dbPath]
  assertEqual "inspect exit" 0 (ceCode rInspect)
  assertBool "three token rows" ("tokens: 3" `isInfixOf` ceOut rInspect)
  withConfigInstance sqliteCfg $ \inst -> do
    alloca $ \(pCount :: Ptr CULong) -> do
      poke pCount (CULong 0)
      rvQuery <- haskokiStdGetSlotList inst 0 nullPtr pCount
      CULong nQuery <- peek pCount
      assertEqual "reopen rv" (CULong 0) rvQuery
      assertEqual "reopen three slots" 3 nQuery
    l1 <- readLabel inst (CULong 1)
    assertEqual "reopen slot-1 label" (padded "haskoki-ops") l1
  _ <- tryIOError (removeFile dbPath)
  _ <- tryIOError (removeFile (dbPath ++ ".lock"))
  pure ()

-- | A 3-token store reopened under a home-only
-- config must NOT serve the stale extra slots with home-fallback
-- labels/PINs — prune or refuse loudly. This task refuses: the
-- reopen fails (the served count is captured in the failure
-- message as the defect evidence).
caseCatalogShrinkRefused :: IO ()
caseCatalogShrinkRefused = do
  base <- getTemporaryDirectory
  let dbPath = base </> "haskoki-catalog-shrink.sqlite"
  _ <- tryIOError (removeFile dbPath)
  _ <- tryIOError (removeFile (dbPath ++ ".lock"))
  cfg <- loadFixtureConfig
  let sqliteCfg = cfg
        { cfgStorage = StorageCfg StorageSQLite (Just dbPath) 5000 True }
  withConfigInstance sqliteCfg $ \inst ->
    alloca $ \(pCount :: Ptr CULong) -> do
      poke pCount (CULong 0)
      rvQuery <- haskokiStdGetSlotList inst 0 nullPtr pCount
      CULong nQuery <- peek pCount
      assertEqual "first-open rv" (CULong 0) rvQuery
      assertEqual "first-open three slots" 3 nQuery
  let homeCfg = sqliteCfg
        { cfgTokens = (cfgTokens sqliteCfg) { tcEntries = [] } }
  inst2 <- openStdInstance homeCfg
  let refused = castStablePtrToPtr inst2 == nullPtr
  if refused
    then do
      _ <- tryIOError (removeFile dbPath)
      _ <- tryIOError (removeFile (dbPath ++ ".lock"))
      pure ()
    else do
      nStale <- alloca $ \(pCount :: Ptr CULong) -> do
        poke pCount (CULong 0)
        _ <- haskokiStdGetSlotList inst2 0 nullPtr pCount
        CULong n <- peek pCount
        pure n
      haskokiStdClose inst2
      _ <- tryIOError (removeFile dbPath)
      _ <- tryIOError (removeFile (dbPath ++ ".lock"))
      assertBool ("shrunk-catalog reopen served stale slots: " ++ show nStale)
        False

-- | The existing reload path ('restoreStoreState', extended
-- not forked) restores three token auths with per-slot state.
caseRestoreThree :: IO ()
caseRestoreThree = do
  env <- newEnv defaultRules
  let rec n label attempts =
        ( TokenRecord (TokenId n) (SlotId (n - 1)) (Generation 0) label
            tokenAuthNew { taUserAttempts = attempts }
        , []
        )
  eRestored <- restoreStoreState env
    [ rec 1 "haskoki-demo" 0
    , rec 2 "haskoki-ops" 1
    , rec 3 "haskoki-audit" 2
    ]
  case eRestored of
    Left deny -> fail ("reload refused: " ++ show deny)
    Right () -> pure ()
  m <- snapshotModel env
  assertEqual "three auths" 3 (Map.size (mTokenAuth m))
  case Map.lookup (SlotId 1) (mTokenAuth m) of
    Nothing -> fail "slot-1 auth missing after reload"
    Just auth -> assertEqual "slot-1 attempts kept" 1 (taUserAttempts auth)

-- | Per-slot store ids are unique across the catalog range
-- and slot 0 keeps the home id.
caseTokenIdsUnique :: IO ()
caseTokenIdsUnique = do
  let ids = [tokenIdForSlot (SlotId n) | n <- [0 .. 15]]
  assertEqual "sixteen unique ids" 16 (length (nub ids))
  assertEqual "slot 0 keeps home id" homeTokenId (tokenIdForSlot (SlotId 0))

-- | Memory instances read the serial from the pinned identity
-- catalog too (identity-derived serial ruling): the fixture with
-- @token_ids = ["1", "26", "3"]@ reports TokenId 26 on slot 1 as
-- @000000000000001a@ (a positional reading gives
-- @0000000000000002@), and the other slots follow their pins.
caseMemorySerialPinned :: IO ()
caseMemorySerialPinned = do
  body <- readFile fixturePath
  cfg <- case parseConfig (body ++ "token_ids = [\"1\", \"26\", \"3\"]\n") of
    Left err -> fail ("pinned memory fixture must parse: " ++ show err)
    Right c -> pure c
  assertEqual "fixture stays memory-backed" StorageMemory (scKind (cfgStorage cfg))
  withConfigInstance cfg $ \inst -> do
    readSerial inst (CULong 0) >>= assertEqual "slot-0 serial" "0000000000000001"
    readSerial inst (CULong 1) >>= assertEqual "slot-1 serial" "000000000000001a"
    readSerial inst (CULong 2) >>= assertEqual "slot-2 serial" "0000000000000003"

-- | Read one slot's 16-byte serial (fails unless the call is OK).
readSerial :: StablePtr StdInstance -> CULong -> IO String
readSerial inst slot =
  allocaArray 16 $ \(buf :: Ptr Word8) -> do
    rv <- haskokiStdTokenSerial inst slot buf
    assertEqual "serial rv" (CULong 0) rv
    map (chr . fromIntegral) <$> peekArray 16 buf

-- | Login state is per token (slot) — logging in on slot 1
-- leaves slot 2 public and vice versa, and logout is likewise
-- slot-scoped. Proven slot-aware with the global PIN first
-- (honest guard); the same shape holds with per-slot
-- catalog PINs now that PINs route per slot.
caseLoginIndependent :: IO ()
caseLoginIndependent =
  withCatalogInstance $ \inst -> do
    s1 <- openSession inst (CULong 1)
    s2 <- openSession inst (CULong 2)
    rvLogin1 <- loginAs inst s1 1 "2345"
    assertEqual "slot-1 login ok" (CULong 0) rvLogin1
    l1 <- sessionLoginOf inst s1
    l2 <- sessionLoginOf inst s2
    assertEqual "slot-1 session user" (CULong 1) l1
    assertEqual "slot-2 session still public" (CULong 0) l2
    rvLogout1 <- haskokiStdLogout inst s1
    assertEqual "slot-1 logout ok" (CULong 0) rvLogout1
    l1b <- sessionLoginOf inst s1
    l2b <- sessionLoginOf inst s2
    assertEqual "slot-1 session public again" (CULong 0) l1b
    assertEqual "slot-2 session undisturbed" (CULong 0) l2b
    rvLogin2 <- loginAs inst s2 1 "3456"
    assertEqual "slot-2 login ok" (CULong 0) rvLogin2
    l1c <- sessionLoginOf inst s1
    l2c <- sessionLoginOf inst s2
    assertEqual "slot-1 still public" (CULong 0) l1c
    assertEqual "slot-2 session user" (CULong 1) l2c

-- | Objects are per-token — an object created in a slot-1
-- session is invisible from slot 2 (find yields zero with CKR_OK;
-- get-one-attr and destroy refuse with OBJECT_HANDLE_INVALID,
-- 0x82) while staying readable on slot 1: the
-- session→slot→token chain already carries through (honest guard).
caseObjectsIsolated :: IO ()
caseObjectsIsolated =
  withCatalogInstance $ \inst -> do
    s1 <- openSession inst (CULong 1)
    s2 <- openSession inst (CULong 2)
    let frame = buildFrame
          [ (0x00, le64 0) -- CKA_CLASS = CKO_DATA
          , (0x01, BS.singleton 0) -- CKA_TOKEN = false
          , (0x02, BS.singleton 0) -- CKA_PRIVATE = false
          , (0x03, BC8.pack "slot1-only") -- CKA_LABEL
          ]
    priv <- createObject inst s1 frame
    hits2 <- findAll inst s2
    assertEqual "slot-2 find yields zero" [] hits2
    (rvGet2, _) <- getAttrBytes inst s2 priv 0x03
    assertEqual "slot-2 get refused" (CULong 0x82) rvGet2
    rvDestroy2 <- haskokiStdDestroyObject inst s2 priv
    assertEqual "slot-2 destroy refused" (CULong 0x82) rvDestroy2
    (rvGet1, bytes1) <- getAttrBytes inst s1 priv 0x03
    assertEqual "slot-1 get ok" (CULong 0) rvGet1
    assertEqual "slot-1 label reads" (BC8.pack "slot1-only") bytes1
    rvDestroy1 <- haskokiStdDestroyObject inst s1 priv
    assertEqual "slot-1 destroy ok" (CULong 0) rvDestroy1

-- | User PINs route per slot — the slot-1 catalog PIN
-- logs slot 1 in, while slot-0 and cross-slot PINs refuse with
-- PIN_INCORRECT (0xA0); failed before per-slot routing (global
-- PIN compare).
casePerSlotPins :: IO ()
casePerSlotPins =
  withCatalogInstance $ \inst -> do
    s1 <- openSession inst (CULong 1)
    rvOk <- loginAs inst s1 1 "2345"
    assertEqual "slot-1 user PIN accepted" (CULong 0) rvOk
    l1 <- sessionLoginOf inst s1
    assertEqual "slot-1 logged in" (CULong 1) l1
    rvLogout <- haskokiStdLogout inst s1
    assertEqual "slot-1 logout ok" (CULong 0) rvLogout
    rvWrong <- loginAs inst s1 1 "1234"
    assertEqual "slot-0 PIN refused on slot 1" (CULong 0xA0) rvWrong
    s2 <- openSession inst (CULong 2)
    rvCross <- loginAs inst s2 1 "2345"
    assertEqual "slot-1 PIN refused on slot 2" (CULong 0xA0) rvCross

-- | SO PINs route per slot — the slot-1 catalog SO PIN
-- logs slot 1 in as SO, while the slot-0 SO PIN refuses with
-- PIN_INCORRECT (0xA0); failed before per-slot routing (global
-- PIN compare).
caseSoPerSlot :: IO ()
caseSoPerSlot =
  withCatalogInstance $ \inst -> do
    s1 <- openSession inst (CULong 1)
    rvSo <- loginAs inst s1 0 "6789"
    assertEqual "slot-1 SO PIN accepted" (CULong 0) rvSo
    l1 <- sessionLoginOf inst s1
    assertEqual "slot-1 SO login observed" (CULong 2) l1
    rvLogout <- haskokiStdLogout inst s1
    assertEqual "slot-1 logout ok" (CULong 0) rvLogout
    rvWrongSo <- loginAs inst s1 0 "5678"
    assertEqual "slot-0 SO PIN refused on slot 1" (CULong 0xA0) rvWrongSo

-- | Call InitToken on a slot with a Haskell-string SO PIN and
-- label (the label pads to the fixed 32 C bytes here, as the
-- C caller would).
callInitToken :: StablePtr StdInstance -> CULong -> String -> String -> IO CULong
callInitToken inst slot pinStr labelStr =
  BS.useAsCStringLen (BC8.pack pinStr) $ \(cPin, lenPin) ->
    BS.useAsCStringLen (BC8.pack (take 32 (labelStr ++ repeat ' '))) $ \(cLabel, _) ->
      haskokiStdInitToken inst slot (castPtr cPin) (fromIntegral lenPin) (castPtr cLabel)

-- | A persistent public data object frame (survives session
-- close, so a reinit either destroys it or it stays).
persistentFrame :: String -> BS.ByteString
persistentFrame label = buildFrame
  [ (0x00, le64 0) -- CKA_CLASS = CKO_DATA
  , (0x01, BS.singleton 1) -- CKA_TOKEN = true
  , (0x02, BS.singleton 0) -- CKA_PRIVATE = false
  , (0x03, BC8.pack label) -- CKA_LABEL
  ]

-- | A reinit carrying a wrong SO PIN refuses with
-- PIN_INCORRECT (0xA0) and preserves everything: the token
-- object survives, both PINs still serve, and the refusal
-- consumes no SO attempt (two wrong SO logins afterwards
-- still answer PIN_INCORRECT rather than locking on the
-- second, and the catalog SO PIN then serves).
caseReinitWrongPinRefused :: IO ()
caseReinitWrongPinRefused =
  withCatalogInstance $ \inst -> do
    s0 <- openSession inst (CULong 0)
    rvLogin <- loginAs inst s0 1 "1234"
    assertEqual "user login" (CULong 0) rvLogin
    _victim <- createObject inst s0 (persistentFrame "slot0-kept")
    rvLogout <- haskokiStdLogout inst s0
    assertEqual "logout" (CULong 0) rvLogout
    rvClose <- haskokiStdCloseSession inst s0
    assertEqual "session closes" (CULong 0) rvClose
    rvBad <- callInitToken inst (CULong 0) "wrong-pin" "haskoki-demo"
    assertEqual "wrong SO PIN refused" (CULong 0xA0) rvBad
    r0 <- openSession inst (CULong 0)
    hits <- findAll inst r0
    assertEqual "token object survives" 1 (length hits)
    rvStrike1 <- loginAs inst r0 0 "bad-so-0001"
    assertEqual "first wrong SO login" (CULong 0xA0) rvStrike1
    rvStrike2 <- loginAs inst r0 0 "bad-so-0002"
    assertEqual "second wrong SO login" (CULong 0xA0) rvStrike2
    rvSo <- loginAs inst r0 0 "5678"
    assertEqual "SO PIN serves" (CULong 0) rvSo
    rvLogout2 <- haskokiStdLogout inst r0
    assertEqual "SO logout" (CULong 0) rvLogout2
    rvUser <- loginAs inst r0 1 "1234"
    assertEqual "user PIN serves" (CULong 0) rvUser
    rvLogout3 <- haskokiStdLogout inst r0
    assertEqual "user logout" (CULong 0) rvLogout3
    rvClose2 <- haskokiStdCloseSession inst r0
    assertEqual "session closes" (CULong 0) rvClose2

-- | A reinit carrying the token's SO PIN succeeds: its own
-- token object is destroyed, the sibling token object
-- survives, the user PIN becomes uninitialized (user login
-- answers USER_PIN_NOT_INITIALIZED, 0x102), and the SO PIN
-- serves on.
caseReinitCorrectPinResets :: IO ()
caseReinitCorrectPinResets =
  withCatalogInstance $ \inst -> do
    s0 <- openSession inst (CULong 0)
    rvLogin0 <- loginAs inst s0 1 "1234"
    assertEqual "slot-0 login" (CULong 0) rvLogin0
    _victim <- createObject inst s0 (persistentFrame "slot0-victim")
    rvLogout0 <- haskokiStdLogout inst s0
    assertEqual "slot-0 logout" (CULong 0) rvLogout0
    rvClose0 <- haskokiStdCloseSession inst s0
    assertEqual "slot-0 closes" (CULong 0) rvClose0
    s1 <- openSession inst (CULong 1)
    rvLogin1 <- loginAs inst s1 1 "2345"
    assertEqual "slot-1 login" (CULong 0) rvLogin1
    _kept <- createObject inst s1 (persistentFrame "slot1-kept")
    rvLogout1 <- haskokiStdLogout inst s1
    assertEqual "slot-1 logout" (CULong 0) rvLogout1
    rvClose1 <- haskokiStdCloseSession inst s1
    assertEqual "slot-1 closes" (CULong 0) rvClose1
    rvOk <- callInitToken inst (CULong 0) "5678" "haskoki-demo"
    assertEqual "authorized reinit succeeds" (CULong 0) rvOk
    r0 <- openSession inst (CULong 0)
    hits0 <- findAll inst r0
    assertEqual "own object destroyed" [] hits0
    rvUser <- loginAs inst r0 1 "1234"
    assertEqual "user PIN uninitialized" (CULong 0x102) rvUser
    rvSo <- loginAs inst r0 0 "5678"
    assertEqual "SO PIN serves" (CULong 0) rvSo
    rvLogout <- haskokiStdLogout inst r0
    assertEqual "SO logout" (CULong 0) rvLogout
    rvClose <- haskokiStdCloseSession inst r0
    assertEqual "slot-0 closes" (CULong 0) rvClose
    r1 <- openSession inst (CULong 1)
    hits1 <- findAll inst r1
    assertEqual "sibling object survives" 1 (length hits1)
    rvCloseSib <- haskokiStdCloseSession inst r1
    assertEqual "slot-1 closes" (CULong 0) rvCloseSib

-- | A reinit with sessions open refuses with SESSION_EXISTS
-- (0xB6) either way: the sessions-empty precondition holds
-- ahead of the SO-PIN check, so an open session refuses with
-- the token's PIN as well as with a wrong one.
caseReinitSessionsRefuse :: IO ()
caseReinitSessionsRefuse =
  withCatalogInstance $ \inst -> do
    s0 <- openSession inst (CULong 0)
    rvRight <- callInitToken inst (CULong 0) "5678" "haskoki-demo"
    assertEqual "open session refuses, token PIN" (CULong 0xB6) rvRight
    rvWrong <- callInitToken inst (CULong 0) "wrong-pin" "haskoki-demo"
    assertEqual "open session refuses, wrong PIN" (CULong 0xB6) rvWrong
    rvClose <- haskokiStdCloseSession inst s0
    assertEqual "session closes" (CULong 0) rvClose

-- | A locked SO recovers through an authorized reinit, on a
-- SQLite store with a reopen between the reset and the
-- proof: three wrong SO logins lock the role (0xA4), a
-- wrong-PIN reinit refuses with PIN_INCORRECT (0xA0) and the
-- lock stays (even the token SO PIN answers locked), then
-- the authorized reinit succeeds, and after the reopen the
-- SO PIN serves while the user PIN reports uninitialized
-- (0x102). Dedicated temp store path, never the default
-- store.
caseReinitLockedSoRecovery :: IO ()
caseReinitLockedSoRecovery = do
  base <- getTemporaryDirectory
  let dbPath = base </> "haskoki-reinit-locked.sqlite"
  _ <- tryIOError (removeFile dbPath)
  _ <- tryIOError (removeFile (dbPath ++ ".lock"))
  cfg <- loadFixtureConfig
  let sqliteCfg = cfg
        { cfgStorage = StorageCfg StorageSQLite (Just dbPath) 5000 True }
  withConfigInstance sqliteCfg $ \inst -> do
    s0 <- openSession inst (CULong 0)
    rvStrike1 <- loginAs inst s0 0 "bad-so-0001"
    assertEqual "SO strike one" (CULong 0xA0) rvStrike1
    rvStrike2 <- loginAs inst s0 0 "bad-so-0002"
    assertEqual "SO strike two" (CULong 0xA0) rvStrike2
    rvStrike3 <- loginAs inst s0 0 "bad-so-0003"
    assertEqual "SO strike three locks" (CULong 0xA4) rvStrike3
    rvClose <- haskokiStdCloseSession inst s0
    assertEqual "session closes" (CULong 0) rvClose
    rvBad <- callInitToken inst (CULong 0) "wrong-pin" "haskoki-demo"
    assertEqual "wrong SO PIN refused" (CULong 0xA0) rvBad
    r0 <- openSession inst (CULong 0)
    rvLocked <- loginAs inst r0 0 "5678"
    assertEqual "SO stays locked" (CULong 0xA4) rvLocked
    rvClose2 <- haskokiStdCloseSession inst r0
    assertEqual "session closes" (CULong 0) rvClose2
    rvOk <- callInitToken inst (CULong 0) "5678" "haskoki-demo"
    assertEqual "authorized reinit succeeds" (CULong 0) rvOk
  withConfigInstance sqliteCfg $ \inst -> do
    r0 <- openSession inst (CULong 0)
    rvSo <- loginAs inst r0 0 "5678"
    assertEqual "SO serves after reopen" (CULong 0) rvSo
    rvLogout <- haskokiStdLogout inst r0
    assertEqual "SO logout" (CULong 0) rvLogout
    rvUser <- loginAs inst r0 1 "1234"
    assertEqual "user PIN uninitialized" (CULong 0x102) rvUser
    rvClose <- haskokiStdCloseSession inst r0
    assertEqual "session closes" (CULong 0) rvClose
  _ <- tryIOError (removeFile dbPath)
  _ <- tryIOError (removeFile (dbPath ++ ".lock"))
  pure ()
