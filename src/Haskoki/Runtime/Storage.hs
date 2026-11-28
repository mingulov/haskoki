{- | Narrow persistent-store contract.

The process-level store owns token metadata, credentials, token
objects, and detached-job records. Sessions and active
operations stay transient. Memory and SQLite backends implement the
same 'Store' record; the @haskoki-storage-tests@ suite runs the
identical contract cases against both.

Canonical record encoding (design 08, section 3):

* Every stored document is versioned JSON with @format_version = 1@.
  Unknown format versions are rejected, never decoded speculatively.
* Bytes ride as base64 strings; full-width unsigned quantities
  (ids, classes, enums, revisions) ride as fixed 16-hex-character
  strings, never bare JSON numbers and never blindly cast through
  the SQLite signed-integer domain.
* The only bare JSON number in any document is @format_version@;
  the only JSON booleans are semantic flags. Object keys sort
  ascending, so rendering is byte-canonical for a given value.
* Documents carry logical state only: no handle, pointer, callback
  address, @EVP_*@ context, or struct image may appear (pinned by
  fixture scans in the storage suite).

The contract layers capabilities: open\/load\/commit\/close\/inspect,
the commit protocol (fault injection, quarantine, reload),
adversarial validation, detached-job records, and token reset.

Each open 'Store' handle owns one detached-job claim authority
('storeClaims'); a reopened handle starts empty, so closing a store
while detached attachments are live is a documented boundary (see
docs\/operations-notes.md).
-}
module Haskoki.Runtime.Storage
  ( -- * Limits
    StoreLimits (..)
  , defaultLimits
    -- * Records
  , TokenRecord (..)
  , CredentialRecord (..)
  , ObjectRecord (..)
  , ObjectPut (..)
  , JobRecord (..)
  , JobExecState (..)
  , JobBody (..)
    -- * Deltas and results
  , StoreDelta (..)
  , emptyDelta
  , StoreDeltaClass (..)
  , deltaClasses
  , scrubTokenAuth
  , scrubDeltaAuth
  , CommitResult (..)
  , StoreError (..)
    -- * Commit protocol
  , FaultPoint (..)
  , FaultInjector (..)
  , noFaults
  , scriptedFaults
  , withMaskHook
  , withResultHook
  , StoreStats (..)
  , zeroStats
  , PublicationAdvice (..)
  , decidePublication
  , Reconcile (..)
  , reconcileReload
  , reconcileJobsReload
  , reconcileCredentialsReload
  , jobIdCounterKey
  , nextJobReservation
  , coverDeletedJobIds
    -- * Pre-commit validation
  , LoadedState (..)
  , checkLimits
  , checkExpectedRevisions
  , checkTokenRefs
  , checkSlotUnique
  , knownMaterialEncodings
    -- * Durable token identity
  , DesiredToken (..)
  , IdentityRefusal (..)
  , ReconcilePlan (..)
  , reconcileIdentities
  , renderIdentityRefusal
  , tokensWithoutCredentials
  , SlotMoveRefusal (..)
  , planSlotMoves
  , renderSlotMoveRefusal
    -- * Store contract
  , Store (..)
  , ClaimAuthority
  , claimCensus
  , markCensus
  , StoredDoc (..)
  , HandleState (..)
  , storeClosed
    -- * Model projection
  , objectToRecord
  , reserveRestoredIds
    -- * Canonical encoding
  , recordFormatVersion
  , encodeTokenRecord
  , decodeTokenRecord
  , encodeCredentialRecord
  , decodeCredentialRecord
  , encodeObjectRecord
  , decodeObjectRecord
  , encodeAttrsDoc
  , decodeAttrsDoc
  , encodeJobRecord
  , decodeJobRecord
  , execStateName
  , nameExecState
  , encodeReturnCode
  , decodeReturnCode
  , docTopKeys
  , encodeBase64
  , decodeBase64
  , encodeHex16
  , decodeHex16
  , encodeHexWord64
  , decodeHexWord64
  ) where

import Haskoki.Runtime.Attach (ClaimAuthority, JobExecState (..), claimCensus, markCensus)
import Haskoki.Runtime.Storage.Limits
import Haskoki.Runtime.Storage.Records
import Haskoki.Runtime.Storage.Deltas
import Haskoki.Runtime.Storage.Commit
import Haskoki.Runtime.Storage.Contract
import Haskoki.Runtime.Storage.Precommit
import Haskoki.Runtime.Storage.TokenIdentity
import Haskoki.Runtime.Storage.Projection
import Haskoki.Runtime.Storage.Encoding
import Haskoki.Runtime.Storage.Base64
import Haskoki.Runtime.Storage.FixedHex
import Haskoki.Runtime.Storage.TokenDocs
import Haskoki.Runtime.Storage.CredDocs
import Haskoki.Runtime.Storage.ObjectDocs
import Haskoki.Runtime.Storage.Word64Hex
import Haskoki.Runtime.Storage.JobDocs
