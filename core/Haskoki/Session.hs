{- | Session/token/authentication lifecycle model (pure).

Login state is per token (slot); sessions observe it. 'TokenAuth'
carries the active login, the authentication epoch (bumped on every
login/logout transition so dependent reservations can key off it),
per-role PIN-attempt counters with deterministic lockout, and the
optional named-user principal.

Check order inside 'loginAttempt' (documented, tested): state
conflicts (already/another logged in, SO/RO exclusion,
context-requires-user-login) are decided BEFORE PIN evaluation, so a
call that cannot succeed never consumes an attempt. A locked role
denies everything for that role, including conflict-shaped calls.
-}
{-# LANGUAGE OverloadedStrings #-}
module Haskoki.Session
  ( -- * Login state
    SessionLogin (..)
  , ActiveLogin (..)
  , LoginKind (..)
  , PinCheck (..)
  , TokenAuth (..)
  , tokenAuthNew
    -- * Login attempts
  , LoginDeny (..)
  , denyCode
  , LoginOutcome (..)
  , loginAttempt
  , logoutToken
  , closeSessionAuth
    -- * Session admission
  , AdmitDeny (..)
  , admitCode
  , admitSession
  , admitObjects
  , admitToken
  , admitWritable
    -- * Request-argument codecs
  , parseOpenArgs
  , parseLoginArgs
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BC8

import Haskoki.Rules (Rules (..))
import Haskoki.Types (ReturnCode (..), SlotId (..))

-- | What one session observes: public, logged in as user or SO, or
-- holding a one-session context-specific grant.
data SessionLogin
  = LoginPublic
  | LoginUser
  | LoginSO
  | LoginContextUser
  deriving (Eq, Show)

-- | Token-level active login. A context-specific grant never changes
-- this; it touches exactly one session.
data ActiveLogin
  = AuthUser
  | AuthSO
  deriving (Eq, Show)

-- | Which role a login call targets. 'LoginAsContext' re-authenticates
-- the user for a single session while the token stays user-logged-in.
data LoginKind
  = LoginAsUser
  | LoginAsSO
  | LoginAsContext
  deriving (Eq, Show)

-- | Modeled PIN verdict. Real PIN verification is a runtime/engine
-- concern (later tasks); the core counts attempts deterministically
-- off this verdict.
data PinCheck
  = PinCorrect
  | PinIncorrect
  deriving (Eq, Show)

-- | Per-token authentication state.
data TokenAuth = TokenAuth
  { taLogin :: !(Maybe ActiveLogin)
  , taPrincipal :: !(Maybe String)
  , taAuthEpoch :: !Int
  , taUserAttempts :: !Int
  , taSoAttempts :: !Int
  , taUserLocked :: !Bool
  , taSoLocked :: !Bool
  } deriving (Eq, Show)

-- | Fresh token: public, epoch zero, counters zero, nothing locked.
tokenAuthNew :: TokenAuth
tokenAuthNew = TokenAuth
  { taLogin = Nothing
  , taPrincipal = Nothing
  , taAuthEpoch = 0
  , taUserAttempts = 0
  , taSoAttempts = 0
  , taUserLocked = False
  , taSoLocked = False
  }

-- | Why a login attempt was denied. 'DenyPinIncorrect' carries the
-- attempts remaining before lockout.
data LoginDeny
  = DenyAlreadyLoggedIn
  | DenyAnotherLoggedIn
  | DenyPinIncorrect { denyRemaining :: !Int }
  | DenyPinLocked
  | DenyReadOnlyExists
  | DenyUserNotLoggedIn
  deriving (Eq, Show)

-- | Source-defined return code for each denial.
denyCode :: LoginDeny -> ReturnCode
denyCode d = case d of
  DenyAlreadyLoggedIn -> CKR_USER_ALREADY_LOGGED_IN
  DenyAnotherLoggedIn -> CKR_USER_ANOTHER_ALREADY_LOGGED_IN
  DenyPinIncorrect _ -> CKR_PIN_INCORRECT
  DenyPinLocked -> CKR_PIN_LOCKED
  DenyReadOnlyExists -> CKR_SESSION_READ_ONLY_EXISTS
  DenyUserNotLoggedIn -> CKR_USER_NOT_LOGGED_IN

-- | A login attempt always yields the token state to persist (failed
-- attempts move counters) plus either the denial or the granted
-- session login.
data LoginOutcome
  = LoginDenied !LoginDeny !TokenAuth
  | LoginGranted !TokenAuth !SessionLogin
  deriving (Eq, Show)

-- | Attempt a login. State conflicts are decided before PIN
-- evaluation; a locked role denies before anything else for that
-- role. Counters reset on success and lock deterministically at
-- 'rulesMaxPinAttempts' failures (default 3).
loginAttempt
  :: Rules
  -> TokenAuth
  -> Bool -- ^ a read-only session is open on this slot
  -> LoginKind
  -> Maybe String -- ^ named-user principal ('Nothing' = default)
  -> PinCheck
  -> LoginOutcome
loginAttempt rules auth roExists kind mName pin =
  let limit = max 1 (rulesMaxPinAttempts rules)
      locked = case kind of
        LoginAsUser -> taUserLocked auth
        LoginAsContext -> taUserLocked auth
        LoginAsSO -> taSoLocked auth
  in if locked
    then LoginDenied DenyPinLocked auth
    else case checkConflict auth roExists kind of
      Just deny -> LoginDenied deny auth
      Nothing -> case pin of
        PinIncorrect -> LoginDenied (bump limit) (bumpAuth limit)
        PinCorrect -> LoginGranted (grantAuth kind mName) (grantLogin kind)
  where
    -- State conflicts first: a doomed call consumes no attempts.
    checkConflict :: TokenAuth -> Bool -> LoginKind -> Maybe LoginDeny
    checkConflict a ro k = case k of
      LoginAsUser -> case taLogin a of
        Just AuthSO -> Just DenyAnotherLoggedIn
        Just AuthUser -> Just DenyAlreadyLoggedIn
        Nothing -> Nothing
      LoginAsSO -> case taLogin a of
        Just AuthUser -> Just DenyAnotherLoggedIn
        Just AuthSO -> Just DenyAlreadyLoggedIn
        Nothing
          | ro -> Just DenyReadOnlyExists
          | otherwise -> Nothing
      LoginAsContext -> case taLogin a of
        Just AuthUser -> Nothing
        Just AuthSO -> Just DenyAnotherLoggedIn
        Nothing -> Just DenyUserNotLoggedIn
    -- Failed attempt: bump the role counter, lock at the limit.
    bump :: Int -> LoginDeny
    bump limit =
      let n' = attemptsOf kind auth + 1
      in if n' >= limit then DenyPinLocked else DenyPinIncorrect (limit - n')
    bumpAuth :: Int -> TokenAuth
    bumpAuth limit = case kind of
      LoginAsSO ->
        let n' = taSoAttempts auth + 1
        in auth { taSoAttempts = n', taSoLocked = n' >= limit }
      _ ->
        let n' = taUserAttempts auth + 1
        in auth { taUserAttempts = n', taUserLocked = n' >= limit }
    grantAuth :: LoginKind -> Maybe String -> TokenAuth
    grantAuth k name = case k of
      LoginAsUser -> auth
        { taLogin = Just AuthUser
        , taPrincipal = name
        , taAuthEpoch = taAuthEpoch auth + 1
        , taUserAttempts = 0
        }
      LoginAsSO -> auth
        { taLogin = Just AuthSO
        , taPrincipal = Nothing
        , taAuthEpoch = taAuthEpoch auth + 1
        , taSoAttempts = 0
        }
      LoginAsContext -> auth { taUserAttempts = 0 }
    grantLogin :: LoginKind -> SessionLogin
    grantLogin k = case k of
      LoginAsUser -> LoginUser
      LoginAsSO -> LoginSO
      LoginAsContext -> LoginContextUser

-- | Attempts consumed so far for the role behind a login kind.
attemptsOf :: LoginKind -> TokenAuth -> Int
attemptsOf kind auth = case kind of
  LoginAsSO -> taSoAttempts auth
  _ -> taUserAttempts auth

-- | Log the token out. Returns the updated auth plus whether a login
-- was actually cleared. Epoch bumps only on a real transition.
logoutToken :: TokenAuth -> (TokenAuth, Bool)
logoutToken auth = case taLogin auth of
  Nothing -> (auth, False)
  Just _ ->
    ( auth { taLogin = Nothing
           , taPrincipal = Nothing
           , taAuthEpoch = taAuthEpoch auth + 1
           }
    , True
    )

-- | Last-session-close logout rule: when the final session on a slot
-- closes (remaining count zero), any active login is cleared and the
-- epoch bumps. Otherwise the auth state is unchanged.
closeSessionAuth :: TokenAuth -> Int -> TokenAuth
closeSessionAuth auth remaining
  | remaining <= 0 = fst (logoutToken auth)
  | otherwise = auth

-- | Why admission was denied (sessions, objects, or token seating).
data AdmitDeny
  = AdmitTokenAbsent
  | AdmitSessionsFull
  | AdmitReadOnlyWhileSO
  | AdmitObjectsFull
  | AdmitTokensFull
  | AdmitReadOnly
  deriving (Eq, Show)

-- | Source-defined return code for each admission denial. Exhaustion
-- denials report @CKR_HOST_MEMORY@: the PKCS#11-conventional refusal
-- when the host cannot house another session, object, or token
-- (sessions keep their narrower @CKR_SESSION_COUNT@).
admitCode :: AdmitDeny -> ReturnCode
admitCode d = case d of
  AdmitTokenAbsent -> CKR_TOKEN_NOT_PRESENT
  AdmitSessionsFull -> CKR_SESSION_COUNT
  AdmitReadOnlyWhileSO -> CKR_SESSION_READ_ONLY_EXISTS
  AdmitObjectsFull -> CKR_HOST_MEMORY
  AdmitTokensFull -> CKR_HOST_MEMORY
  AdmitReadOnly -> CKR_SESSION_READ_ONLY

-- | Admit a session open: the slot must hold a token, the session
-- bound must not be exhausted, and a read-only session must not open
-- while the SO is logged in (SO/RO exclusion, both directions).
admitSession :: Rules -> Maybe TokenAuth -> Int -> Bool -> Either AdmitDeny ()
admitSession rules mAuth openCount readOnly =
  case mAuth of
    Nothing -> Left AdmitTokenAbsent
    Just auth
      | openCount >= rulesMaxSessions rules -> Left AdmitSessionsFull
      | readOnly && taLogin auth == Just AuthSO -> Left AdmitReadOnlyWhileSO
      | otherwise -> Right ()

-- | Admit the creation of @newCount@ objects against the object
-- bound: @openCount@ live objects plus the newcomers must fit. Pair
-- generation admits with @newCount = 2@; every other creation seam
-- admits with 1.
admitObjects :: Rules -> Int -> Int -> Either AdmitDeny ()
admitObjects rules openCount newCount
  | openCount + newCount > rulesMaxObjects rules = Left AdmitObjectsFull
  | otherwise = Right ()

-- | Admit seating one more token against the slot bound:
-- @seatedCount@ already-seated tokens must leave room.
admitToken :: Rules -> Int -> Either AdmitDeny ()
admitToken rules seatedCount
  | seatedCount >= rulesMaxTokens rules = Left AdmitTokensFull
  | otherwise = Right ()

-- | Admit a mutation against the session's read-only flag and the
-- target object's owner: the ONE pure writability decision.
-- Read/write sessions admit everything; read-only sessions admit
-- session objects and deny token objects with 'AdmitReadOnly'
-- (OASIS PKCS#11 Base v3.0 §5.7.1-5.7.3: "only session objects
-- can be created/destroyed during a read-only session"). Every
-- creation path (create, copy, generate, keypair, unwrap, derive,
-- encapsulate, decapsulate) and every mutation of an existing
-- object (set-attributes, destroy) enforces this where the owner
-- is decided: the object planners decide inline, and the key-plan
-- runner decides over the pending work ('admitPending') before
-- any effect runs. Reads,
-- pure crypto, wrap (no object created), session lifecycle, and
-- random generation are ungated (no object mutation). The
-- unenforced public-object login rule is a separate follow-up.
admitWritable :: Bool -> Bool -> Either AdmitDeny ()
admitWritable readOnly isToken
  | readOnly && isToken = Left AdmitReadOnly
  | otherwise = Right ()

-- | Decode OpenSession arguments: @slot=\<nat\>,rw@ or @slot=\<nat\>,ro@.
parseOpenArgs :: ByteString -> Maybe (SlotId, Bool)
parseOpenArgs bs = do
  rest <- BS.stripPrefix "slot=" bs
  let (numBs, flagBs) = BC8.break (== ',') rest
  n <- parseNat numBs
  flag <- case BC8.unpack flagBs of
    ",rw" -> Just False
    ",ro" -> Just True
    _ -> Nothing
  pure (SlotId n, flag)

-- | Decode Login arguments: @user[:name]:ok|bad@, @so:ok|bad@,
-- @context:ok|bad@.
parseLoginArgs :: ByteString -> Maybe (LoginKind, Maybe String, PinCheck)
parseLoginArgs bs = case BC8.split ':' bs of
  [who, pin] -> do
    kind <- kindOf who
    check <- pinOf pin
    pure (kind, Nothing, check)
  [who, name, pin]
    | who == BC8.pack "user" && not (BS.null name) -> do
        check <- pinOf pin
        pure (LoginAsUser, Just (BC8.unpack name), check)
    | otherwise -> Nothing
  _ -> Nothing
  where
    kindOf :: ByteString -> Maybe LoginKind
    kindOf who
      | who == BC8.pack "user" = Just LoginAsUser
      | who == BC8.pack "so" = Just LoginAsSO
      | who == BC8.pack "context" = Just LoginAsContext
      | otherwise = Nothing
    pinOf :: ByteString -> Maybe PinCheck
    pinOf pin
      | pin == BC8.pack "ok" = Just PinCorrect
      | pin == BC8.pack "bad" = Just PinIncorrect
      | otherwise = Nothing

-- | Parse a non-negative decimal integer; rejects empty and
-- non-digit input.
parseNat :: ByteString -> Maybe Int
parseNat bs
  | BS.null bs = Nothing
  | BC8.all (`elem` ['0' .. '9']) bs =
      case BC8.readInt bs of
        Just (n, rest) | BS.null rest -> Just n
        _ -> Nothing
  | otherwise = Nothing
