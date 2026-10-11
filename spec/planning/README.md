# Function inventory

[functions.csv](functions.csv) is the checked-in 104-row input for ABI and
function-contract generation. It originated in the project's initial design
and is maintained here.

Its checksum is recorded as `planning_seed_sha256` in
[abi-reconciliation.json](../abi-reconciliation.json). When the inventory
changes, update the generated ABI/contracts and reconciliation together;
[validate-spec.py](../../scripts/validate-spec.py) checks the checksum and
row count. Generation uses only files in this repository.
