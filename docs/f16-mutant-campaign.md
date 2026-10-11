# A small mutation check

During October 2026 release preparation, eight deliberate changes tested
whether selected checks could detect regressions. All eight were detected.
This was a bounded manual sensitivity check, not exhaustive mutation coverage.

| Deliberate change | Check that detected it |
| --- | --- |
| Let an SO session see user-private objects | [ObjectSpec](../tests/model/ObjectSpec.hs): SO visibility refusal |
| Allow SQLite lock takeover when owner liveness is unknown | [StoreSpec](../tests/storage/StoreSpec.hs): masked/unreadable owner cases |
| Disable terminal-job retention eviction | [AsyncSpec](../tests/model/AsyncSpec.hs): count and byte retention bounds |
| Advertise unsupported AES-GCM message flags | [MessageFlagBatterySpec](../tests/model/MessageFlagBatterySpec.hs): route/flag correspondence |
| Disconnect PBKD2 from native derivation | [consumer_derive_f10.c](../tests/c/consumer_derive_f10.c): PBKD2 derive calls |
| Misspell a mechanism evidence case ID | [check-test-evidence.py](../scripts/check-test-evidence.py): unresolved evidence |
| Disable the status-flip test's mutation | [MechanismExhaustivenessSpec](../tests/model/MechanismExhaustivenessSpec.hs): status-mutation control |
| Replace an immutable GitHub Action pin with a tag | [check-actions-pinned.py](../scripts/check-actions-pinned.py): mutable-pin refusal |

To repeat a sensitivity check, use a disposable source worktree, establish
a passing baseline, make one change, and run the named check. The check
must fail for that change and pass again after restoration. Native and
Haskell checks require the [developer environment](toolchain.md); the two
Python gates can run without a compiler.

The normal [release workflow](publishing.md) tests the unchanged source.
The eight historical detections do not qualify a later revision by themselves.
