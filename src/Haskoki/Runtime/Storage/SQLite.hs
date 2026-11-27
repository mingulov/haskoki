{- | SQLite store backend: one local file, single writer.

On 'openSQLiteStore' the backend takes single-writer ownership via
an O_EXCL sidecar lock file (@\<db\>.lock@) carrying the owner's
pid: the kernel flock is the authority — a stale lock with no
holder (the same pid, a live pid, an unknowable pid, an
unparsable pid, an empty file, or a dead pid from a crashed run)
is taken over without touching any data, and a held lock refuses
explicitly with 'StoreSecondWriter'. SQLite-level locking alone
would not keep two provider caches coherent, so the file lock —
not the database — is the ownership arbiter.

Ownership is fail-closed and kernel-backed: a truly unreadable
lock, and an unknowable @\/proc@ verdict with the kernel lock
held, refuse with 'StoreSecondWriter' rather than risk a state
fork, and every owner holds an exclusive non-blocking @flock(2)@
on a held-open lock fd for the lock's lifetime, so a live owner
still refuses takeovers. Exclusion is
anchored to the database identity as well as the sidecar (a second
held-open @flock(2)@, on the database file itself), so deleting
the lock path cannot fork a live owner via a replacement lock;
release unlinks only the owned lock inode.

An empty database initializes transactionally from the schema in
@spec\/storage-schema.sql@ (five tables, indexes, meta rows); an
existing database is verified (tables present, @schema_version@
exactly @3@). Versions 1 and 2 refuse as migration-required and are
never migrated by an open: the open writes nothing, and only the
explicit @haskoki-ctl store migrate@ moves a store to version 3. A foreign or
garbage file is rejected with a diagnosis and left byte-identical.

SQLite configuration (design 08, section 6): foreign keys on, a
bounded 5s busy timeout, rollback-journal mode, extra durable
(EXTRA) synchronization, so a commit followed closely by a power
loss stays committed. WAL is not used; no unsafe journal\/sync
mode is ever selected. Every commit runs as one @BEGIN IMMEDIATE@
transaction, so multi-object deltas are all-or-nothing.

Full-width unsigned quantities travel as 8-byte big-endian blobs
or fixed hex text; only the bounded @revision@ counter uses an
INTEGER column (guarded by @CHECK (revision > 0)@), and every
read-back range-checks before narrowing to 'Int'.

Close serializes with use: the close runs under the same
connection guard as every operation, so it waits for in-flight
uses instead of closing the handle beneath them; later uses of
the closed handle fail closed. A close that cannot complete (an
injected close fault, or a SQLite close error) retains the
handle, the lock, and both kernel guards, refuses new
operations, reports the failure by throwing, and a later close
retries for real.
-}
module Haskoki.Runtime.Storage.SQLite
  ( openSQLiteStore
  , openSQLiteStoreWith
  , openSQLiteStoreWithHooks
  , SQLiteTestHooks (..)
  , noSQLiteTestHooks
  , sqliteSchemaVersion
  , livenessFromProbes
  , PidLiveness (..)
  , ProcProbe (..)
  , pidIsDead
  , waitForGoFile
  , waitForPoll
  , pauseForFreshCreate
  , FileIdentity (..)
  , StoreSnapshot (..)
  , resolveStorePath
  , resolveStorePathTracked
  , resolveStoreSpelling
  , resolveStoreSpellingTracked
  , withStoreSpelling
  , requireRegularStore
  , readStoreSnapshot
  , readStoreSnapshotAllowCold
  , OwnerState (..)
  , probeOwner
  , guardFlags
  , readFileCloexec
  , OwnedStoreFile
  , ownedPath
  , ownedDbMatches
  , withOwnedStoreFile
  , withOwnedStoreFileKeep
  , clearColdJournalOwned
  , SQLiteMigration (..)
  , MigrationHooks (..)
  , noMigrationHooks
  , MigrateTxnError (..)
  , migrateOwned
  ) where

import Haskoki.Runtime.Storage.SQLite.Init
import Haskoki.Runtime.Storage.SQLite.Migrate
import Haskoki.Runtime.Storage.SQLite.Open
import Haskoki.Runtime.Storage.SQLite.Ownership
import Haskoki.Runtime.Storage.SQLite.Snapshot
import Haskoki.Runtime.Storage.SQLite.Types
