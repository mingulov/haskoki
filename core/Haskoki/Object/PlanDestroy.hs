{- | Object destruction planning.
-}
{-# LANGUAGE OverloadedStrings #-}
module Haskoki.Object.PlanDestroy
  ( planDestroyObject
  ) where

import Haskoki.Model
  ( Model (..)
  , ObjectState (..)
  , SessionState (..)
  )
import Haskoki.Outcome
  ( DeltaOp (..)
  , PlanResult (..)
  , PreparedCommit (..)
  , StateDelta (..)
  )
import Haskoki.Session (admitCode, admitWritable)
import Haskoki.Types
  ( ExternalHandle (..)
  , ReturnCode (..)
  )
import Haskoki.Object.Handles
import Haskoki.Object.PlanReject
import Haskoki.Object.StorageAttrs

-- | Plan object destruction: the handle must resolve and the
-- object must be visible to the calling session, then one combined
-- delta removes the object and stale-marks its bindings. An
-- explicit @CKA_DESTROYABLE=false@ prohibits the destroy
-- ('CKR_ACTION_PROHIBITED').
planDestroyObject :: Model -> SessionState -> ExternalHandle -> PlanResult
planDestroyObject model st h = case resolveHandle model h of
  Nothing -> invalidHandle "unknown or destroyed object handle"
  Just ost
    | not (objectVisible st ost) ->
        invalidHandle "object not visible to session"
    | not (objectDestroyable ost) ->
        templateReject CKR_ACTION_PROHIBITED
          "object is not destroyable (CKA_DESTROYABLE=false)"
    | Left deny <- admitWritable (ssReadOnly st) (objectToken ost) ->
        templateReject (admitCode deny)
          "read-only session cannot destroy token objects"
    | otherwise -> Immediate PreparedCommit
        { pcCode = CKR_OK
        , pcDelta = StateDelta [DeltaDestroyObject (osId ost)]
        , pcPersist = []
        , pcOutputs = []
        , pcReleases = []
        , pcReasons = ["destroyed object " ++ show (osId ost)]
        }
