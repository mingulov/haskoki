# p11scope side illustration (host observer, unprivileged workload)

What PKCS#11 calls a Haskoki checker workload makes, observed from the
Linux host with [p11scope](https://github.com/mingulov/p11scope). The
Haskoki image stays an ordinary unprivileged container; kernel/process
observation privileges belong to the observer only. p11scope is NOT
part of the Haskoki image and NOT a release dependency.

## Warnings (read before citing the table below)

- `evidence.completeness = PARTIAL`. 496 slots stayed
  semantics-unverified/count-only; only the 9 rows below carry names.
- Attach-slot exhaustion (tool capacity, this capture's concrete
  refusal): `libhaskoki.so` was refused attach — "module needs
  104 more of the 512 attach slots; 496 are in use — refusing to
  attach a prefix".
- Discovery gaps (tool limitation, ties to Haskoki's table design):
  in the saved artifact, 1 subject reports `unsupported
  function-table version; the scanner does not walk this layout`
  for the observed module and 20 subjects report `discovery
  unavailable`. The mechanisms table is EMPTY (`[]` in this
  capture: unattributed, not zero activity).
- Tracking gaps: 40 pid/descendant gaps
  (`evidence.pid_descendant_gaps`).
- Latencies in the artifact are log2-bucket approximations and are
  NOT full round-trip proxy measurements (this lane is direct
  anyway; no proxy was involved).
- eBPF trace latency ≠ proxy round-trip. Never cite these numbers
  as end-to-end timings.
- Provider identity is hash-pinned at attach
  (`sha256 5bad965f…` for the observed `libhaskoki.so`) with
  in-place-change detection (`evidence.provider_changed`).

## How to reproduce

Observer: `p11scope-observer:preview` (`p11scope profile --help` is the
pinned flag doc). Step 0 is `doctor` (privileged observer: exit 0,
zero FAILs; unprivileged: exit 1 with 3 FAILs — BPF map creation
refused):

```sh
docker run --rm --network none --privileged --entrypoint /usr/local/bin/p11scope \
  p11scope-observer:preview doctor
# verdict: capture available; run capture not eligible (none)
```

```sh
# 1. Long workload: full checker lane, detached (runs ~17 min — the
#    canonical direct/full wall clock in release-results timeout
#    guidance — giving
#    ample attach time; PID1 is a shell wrapper, so select the
#    container CGROUP, not PID1):
CID=$(docker run -d --rm --network none -v "$PWD/out:/out" \
  haskoki-demo:0.3.0.0 check --mode direct --profile full)
# 2. Observe 60 s by cgroup-v2 path (absolute cgroupfs form; the
#    observer needs --cgroupns=host + the host cgroupfs mount).
#    NAMED container (no --rm): -o must be a container-local trusted
#    path, so the file is copied out before removal:
docker run --name p11obs --network none --privileged --cgroupns=host --pid=host \
  -v /sys/fs/cgroup:/sys/fs/cgroup \
  --entrypoint /usr/local/bin/p11scope p11scope-observer:preview profile \
  --cgroup /sys/fs/cgroup/system.slice/docker-$CID.scope \
  --duration 60 -o /root/cap.json
docker cp p11obs:/root/cap.json ./cap.json
docker rm p11obs
# 3. Stop the workload (still running; the full lane takes ~17 min otherwise):
docker stop $CID
```

## Snapshot (60 s of `check --mode direct --profile full`, 2026-10-06)

36 attributed calls across 9 functions (return codes observed):

| Function | Calls | Errors | Return codes |
|---|---|---|---|
| C_GetSlotList | 8 | 0 | 8 × `0x0` |
| C_CloseSession | 5 | 0 | 5 × `0x0` |
| C_Finalize | 4 | 0 | 4 × `0x0` |
| C_OpenSession | 4 | 0 | 4 × `0x0` |
| C_Login | 4 | 0 | 4 × `0x0` |
| C_Initialize | 3 | 0 | 3 × `0x0` |
| C_CreateObject | 3 | 3 | 3 × `0xd0` |
| C_GetInterface | 3 | 0 | 3 × `0x0` |
| C_Logout | 2 | 0 | 2 × `0x0` |

Full artifact (316 KB JSON, schema `p11scope/observed-profile/v3`) is
not shipped here; re-run the commands above to reproduce it.
