# Planning seed (vendored)

`functions.csv` is the 104-row function planning seed, copied verbatim
from the design bundle (`ws/docs/incoming/haskell-pkcs11-design/spec/
inventory/functions.csv`, outside this package) so generation and
validation stay hermetic: three scripts read it
(`generate-abi.py`, `generate-function-contracts.py`,
`validate-spec.py`), and CI checks out this repo alone.

Bytes are pinned: `spec/abi-reconciliation.json`
`planning_seed_sha256` must match this file (`validate-spec.py`
rule A41 fails otherwise). Do not edit in place; re-copy from the
bundle and re-run `generate-abi.py`.
