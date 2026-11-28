-- | Shared logged-out test session fixture.
--
-- Thirty-six specs built the same 'SessionState' by hand; the only
-- variation across all of them is the slot ('SlotId 7' everywhere
-- except 'SessionCancelSpec', which uses slot 0). One definition
-- keeps them from drifting apart again.
module TestSession
  ( testSession
  , testSessionOn
  ) where

import Haskoki.Model (SessionState (..))
import Haskoki.Operation (emptySessionOps)
import Haskoki.Session (SessionLogin (..))
import Haskoki.Types
  ( Generation (..)
  , Revision (..)
  , SessionId (..)
  , SlotId (..)
  )

-- | The canonical logged-out test session: session 1 on slot 7,
-- revision 1, public login, no operations.
testSession :: SessionState
testSession = testSessionOn (SlotId 7)

-- | 'testSession' on the given slot.
testSessionOn :: SlotId -> SessionState
testSessionOn slot = SessionState
  { ssId = SessionId 1
  , ssSlot = slot
  , ssRevision = Revision 1
  , ssGeneration = Generation 1
  , ssReadOnly = False
  , ssLogin = LoginPublic
  , ssOps = emptySessionOps
  }
