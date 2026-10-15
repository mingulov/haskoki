# Buffered multipart update cost

Measurement of how the buffered accumulation behaves for nine payload and chunk
combinations, and the resulting decision on bounded chunks. Source:
`bench/BufferedUpdates.hs` (benchmark `buffered-updates`),
raw records in [buffered-updates.json](buffered-updates.json).

## Environment

Every number below belongs to this one run and this one host.

- host: 12 logical CPUs (`nproc` 12), AMD Ryzen AI 9 HX PRO 370 w/ Radeon 890M
- load before the run: `17:13:29 up 7:20, load average: 3.36, 3.15, 3.84`
- load after the run: `17:15:48 up 7:23, load average: 1.90, 2.63, 3.55`
- GHC 9.10.3, runtime options `-T -N1` (single capability), one OS process per case
- source commit 4cad819f17a483bde994e2c124a9a914ce256a9e (the benchmark was
  built and run at this commit)
- the run held the shared build lock, so no other build on the machine ran
  during it; other non-build processes were not excluded, which the load
  averages above record
- one run per cell, no repetition

## Table

| payload | chunk | status | elapsed s | updates | allocated MiB | max live MiB | max mem in use MiB | GCs | result |
|---|---|---|---|---|---|---|---|---|---|
| 1 MiB | 1 B | ok | 12.66 | 1048576/1048576 | 524724.98 | 1.02 | 24.00 | 120288 | match |
| 1 MiB | 1024 B | ok | 0.02 | 1024/1024 | 511.97 | 1.17 | 25.00 | 117 | match |
| 1 MiB | 65536 B | ok | 0.01 | 16/16 | 8.45 | 0.00 | 15.00 | 2 | match |
| 4 MiB | 1 B | censored | 60.06 | 2282444/4194304 | 2485056.20 | 4.02 | 26.00 | 533340 | censored |
| 4 MiB | 1024 B | ok | 0.33 | 4096/4096 | 8199.63 | 4.14 | 33.00 | 1454 | match |
| 4 MiB | 65536 B | ok | 0.01 | 64/64 | 133.97 | 4.95 | 25.00 | 25 | match |
| 16 MiB | 1 B | censored | 60.02 | 2273074/16777216 | 2464698.41 | 16.02 | 38.00 | 528655 | censored |
| 16 MiB | 1024 B | ok | 5.51 | 16384/16384 | 131102.50 | 16.14 | 80.00 | 13742 | match |
| 16 MiB | 65536 B | ok | 0.12 | 256/256 | 2072.04 | 16.95 | 75.00 | 217 | match |

## Reading the table

- `censored` means the 60 s in-process cap was reached before all updates
  completed; `updates` then shows how many finished. A `censored-hard` record
  (the 90 s parent cap) did not occur in this run.
- Each case runs in its own process, so allocation and residency figures are
  per process. `allocated MiB` is the bytes allocated during the timed region.
- `max live MiB` is updated by the RTS only at a major collection, so it can
  understate the true peak between collections. `max mem in use MiB` is the
  memory the RTS obtained from the OS.
- `result` compares an FNV-1a 64-bit checksum of the accumulated buffer with
  the checksum of the input payload (`match`), or reports `censored`.
- The 4 MiB and 16 MiB payloads with 1 B chunks were censored at 60 s; their
  allocation and residency figures describe the partial run only.

## Decision

Rule (fixed before the run): bounded chunks are justified if any 1 KiB or
64 KiB cell is censored or takes more than 5 s, or the 1 MiB / 1 B cell is
censored. Otherwise the current representation is retained.

Applying the rule to the numbers:

- 1 KiB and 64 KiB cells: none censored. The 16 MiB / 1 KiB cell took 5.51 s,
  which is above the 5 s threshold. All other 1 KiB and 64 KiB cells took
  0.33 s or less.
- 1 MiB / 1 B cell: status `ok` (12.66 s), not censored.

**Decision: justified: separate follow-up.** The rule fires on a single cell,
16 MiB / 1 KiB, by a margin of 0.51 s from one unrepeated run; the figure
is a record of this run on this host, not an estimate of typical cost. The
representation change is not part of this work package, because it touches
the slot accessors, the snapshot codec and every final. The follow-up issue
text is drafted in the SDD workspace and no issue is opened.

## Scope and limits

- One path is measured: `appendBuffered`, the accumulation shared by
  non-streamable cipher, signature, message and digest-in-dual flows. Each
  update copies the chunk in (as the FFI copy-in does) and then appends
  through the production bound check.
- Not measured: the list copy in `FFI/Decode.hs`, and the per-call FFI cost of
  native digest updates.
- Single host, `-N1`, one run per cell. This document makes no throughput
  claim.
- Bounds are checked before any copy: `validateOperationIn` checks lengths
  before appending, and that ordering is retained.
- Record schema: every record, including `error` records, carries the same
  field set; values unknown for a failed or hard-censored case are `null`
  (`expected_checksum` is the string `unknown` when the parent could not read
  it). For an `error` record, `result` holds `error:` followed by the child
  exit code and the first part of its standard error.
