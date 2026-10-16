-- | Storm-scale hang-detection budget for the model suite.
--
-- One shared deadline for every join and no-wedge guard in this
-- suite ('runWorkers', 'guarded', 'joinBounded'): 300 seconds of
-- wall clock. Partial machine stalls (a swapped-out lock holder
-- convoying every worker) legitimately exceed 60 seconds while
-- every worker still progresses, so the deadline bounds hang
-- detection, never the work itself, which completes in seconds
-- when the machine runs. A join or probe body that never finishes
-- still fails loudly, naming the straggler or probe.
module StormBudget (stormScaleBudget) where

-- | Storm-scale budget in microseconds: 300 seconds.
stormScaleBudget :: Int
stormScaleBudget = 300000000
