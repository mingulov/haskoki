#!/usr/bin/env python3
"""Generate the function-contract catalog from the ABI inventory.

Reads:
  spec/abi-inventory.json         generated function order per layout
  spec/planning/functions.csv     104-row planning seed (acceptance
                                  cases), vendored for hermetic generation

Writes (deterministic bytes, no timestamps):
  spec/function-contracts.json    all 104 3.2-layout functions classified
                                  as planned-with-behavior (entry + behavior
                                  tests) vs unsupported-with-reason (exact
                                  gap) vs not-applicable (justified)

STDLIB ONLY. Run on HOST python3 from anywhere:
  python3 scripts/generate-function-contracts.py

Contract criterion:
  * planned-with-behavior: a caller-visible entry exists (a planCall
    FunctionId, a real C-table handler, or a haskoki_* foreign export
    exercised by tests) AND behavior tests execute it. Evidence names
    the executed suites; the generator verifies every cited spec file
    exists (the semantic link is curated and reviewable in PLANNED).
  * unsupported-with-reason: the reason names the EXACT gap, including
    "behavior tested at the operation layer but unwired" (citing the
    tested behavior without claiming entry reachability).
  * not-applicable: justified in the reason (legacy-only entries).

Never a behavior claim without tests: no "planned" row without evidence.
"""

import csv
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SPEC = REPO / "spec"
ABI_PATH = SPEC / "abi-inventory.json"
CSV_PATH = SPEC / "planning" / "functions.csv"
OUT_PATH = SPEC / "function-contracts.json"

# name -> (entry, [(suite, spec_file_relative_to_repo)]).
# Suite labels match the cabal test-suite / script harness that runs
# the cited file.
PLANNED = {
    # planCall FunctionId entries: lifecycle/session/object discovery.
    "C_GetInfo": ("planCall:F_GetInfo",
                  [("haskoki-model-tests", "tests/model/RoutingSpec.hs")]),
    "C_GetSlotList": ("planCall:F_GetSlotList",
                      [("haskoki-model-tests", "tests/model/RoutingSpec.hs")]),
    "C_OpenSession": ("planCall:F_OpenSession",
                      [("haskoki-model-tests", "tests/model/SessionSpec.hs")]),
    "C_CloseSession": ("planCall:F_CloseSession",
                       [("haskoki-model-tests", "tests/model/SessionSpec.hs")]),
    "C_Login": ("planCall:F_Login",
                [("haskoki-model-tests", "tests/model/SessionSpec.hs")]),
    "C_Logout": ("planCall:F_Logout",
                 [("haskoki-model-tests", "tests/model/SessionSpec.hs")]),
    "C_CreateObject": ("planCall:F_CreateObject",
                       [("haskoki-model-tests", "tests/model/ObjectSpec.hs")]),
    "C_CopyObject": ("planCall:F_CopyObject",
                     [("haskoki-model-tests", "tests/model/ObjectSpec.hs")]),
    "C_DestroyObject": ("planCall:F_DestroyObject",
                        [("haskoki-model-tests", "tests/model/ObjectSpec.hs")]),
    "C_FindObjects": ("planCall:F_FindObjects",
                      [("haskoki-model-tests", "tests/model/ObjectSpec.hs")]),
    "C_GetAttributeValue": ("planCall:F_GetAttributeValue",
                            [("haskoki-model-tests", "tests/model/ObjectSpec.hs")]),
    "C_SetAttributeValue": ("planCall:F_SetAttributeValue",
                            [("haskoki-model-tests", "tests/model/ObjectSpec.hs"),
                             ("test-consumers.sh", "tests/c/consumer_template_attrs.c")]),
    # planCall entries: classic crypt (digest/sign/verify/cipher).
    "C_DigestInit": ("planCall:F_DigestInit",
                     [("haskoki-model-tests", "tests/model/RoutingSpec.hs"),
                      ("haskoki-engine-tests", "tests/engine/SyntheticSpec.hs"),
                      ("test-crypto-routed.sh", "tests/c/crypto_routed.c")]),
    "C_Digest": ("planCall:F_Digest",
                 [("haskoki-model-tests", "tests/model/RoutingSpec.hs"),
                  ("haskoki-engine-tests", "tests/engine/SyntheticSpec.hs"),
                  ("test-crypto-routed.sh", "tests/c/crypto_routed.c")]),
    "C_DigestUpdate": ("planCall:F_DigestUpdate",
                       [("haskoki-model-tests", "tests/model/OperationSpec.hs"),
                        ("haskoki-engine-tests", "tests/engine/SyntheticSpec.hs")]),
    "C_DigestFinal": ("planCall:F_DigestFinal",
                      [("haskoki-model-tests", "tests/model/OperationSpec.hs"),
                       ("haskoki-engine-tests", "tests/engine/SyntheticSpec.hs")]),
    "C_DigestKey": ("haskoki_std_digest_key:F_DigestUpdate",
                    [("test-consumers.sh", "tests/c/consumer_roundtrip.c")]),
    "C_SignInit": ("planCall:F_SignInit",
                   [("haskoki-model-tests", "tests/model/RoutingSpec.hs"),
                    ("haskoki-model-tests", "tests/model/OperationSpec.hs")]),
    "C_Sign": ("planCall:F_Sign",
               [("haskoki-model-tests", "tests/model/RoutingSpec.hs"),
                ("haskoki-model-tests", "tests/model/OperationSpec.hs"),
                ("haskoki-engine-tests", "tests/engine/SyntheticSpec.hs")]),
    "C_SignUpdate": ("planCall:F_SignUpdate",
                     [("haskoki-model-tests", "tests/model/OperationSpec.hs")]),
    "C_SignFinal": ("planCall:F_SignFinal",
                    [("haskoki-model-tests", "tests/model/OperationSpec.hs")]),
    "C_VerifyInit": ("planCall:F_VerifyInit",
                     [("haskoki-model-tests", "tests/model/OperationSpec.hs")]),
    "C_Verify": ("planCall:F_Verify",
                 [("haskoki-model-tests", "tests/model/OperationSpec.hs"),
                  ("haskoki-engine-tests", "tests/engine/SyntheticSpec.hs")]),
    "C_VerifyUpdate": ("planCall:F_VerifyUpdate",
                       [("haskoki-model-tests", "tests/model/OperationSpec.hs")]),
    "C_VerifyFinal": ("planCall:F_VerifyFinal",
                      [("haskoki-model-tests", "tests/model/OperationSpec.hs")]),
    "C_EncryptInit": ("planCall:F_EncryptInit",
                      [("haskoki-model-tests", "tests/model/OperationSpec.hs")]),
    "C_Encrypt": ("planCall:F_Encrypt",
                  [("haskoki-model-tests", "tests/model/OperationSpec.hs"),
                   ("haskoki-engine-tests", "tests/engine/SyntheticSpec.hs")]),
    "C_EncryptUpdate": ("planCall:F_EncryptUpdate",
                        [("haskoki-model-tests", "tests/model/OperationSpec.hs")]),
    "C_EncryptFinal": ("planCall:F_EncryptFinal",
                       [("haskoki-model-tests", "tests/model/OperationSpec.hs")]),
    "C_DecryptInit": ("planCall:F_DecryptInit",
                      [("haskoki-model-tests", "tests/model/OperationSpec.hs")]),
    "C_Decrypt": ("planCall:F_Decrypt",
                  [("haskoki-model-tests", "tests/model/OperationSpec.hs"),
                   ("haskoki-engine-tests", "tests/engine/SyntheticSpec.hs")]),
    "C_DecryptUpdate": ("planCall:F_DecryptUpdate",
                        [("haskoki-model-tests", "tests/model/OperationSpec.hs")]),
    "C_DecryptFinal": ("planCall:F_DecryptFinal",
                       [("haskoki-model-tests", "tests/model/OperationSpec.hs")]),
    # Dual-function entries: one haskoki_std_dual_* foreign export
    # framing into both reused planCall FunctionIds (the
    # C_DigestKey precedent), executed by tests/c/dual_routed.c.
    "C_DigestEncryptUpdate": ("haskoki_std_dual_digest_encrypt:F_DigestUpdate+F_EncryptUpdate",
                              [("mechanisms/task-m02", "tests/c/dual_routed.c")]),
    "C_DecryptDigestUpdate": ("haskoki_std_dual_decrypt_digest:F_DecryptUpdate+F_DigestUpdate",
                              [("mechanisms/task-m02", "tests/c/dual_routed.c")]),
    "C_SignEncryptUpdate": ("haskoki_std_dual_sign_encrypt:F_SignUpdate+F_EncryptUpdate",
                            [("mechanisms/task-m02", "tests/c/dual_routed.c")]),
    "C_DecryptVerifyUpdate": ("haskoki_std_dual_decrypt_verify:F_DecryptUpdate+F_VerifyUpdate",
                              [("mechanisms/task-m02", "tests/c/dual_routed.c")]),
    # planCall entries: v3 message families (all 20).
    "C_MessageEncryptInit": ("planCall:F_MessageEncryptInit",
                             [("haskoki-model-tests", "tests/model/MessageSpec.hs"),
                              ("test-consumers.sh", "tests/c/message_routed.c")]),
    "C_MessageDecryptInit": ("planCall:F_MessageDecryptInit",
                             [("haskoki-model-tests", "tests/model/MessageSpec.hs"),
                              ("test-consumers.sh", "tests/c/message_routed.c")]),
    "C_MessageSignInit": ("planCall:F_MessageSignInit",
                          [("haskoki-model-tests", "tests/model/MessageSpec.hs"),
                              ("test-consumers.sh", "tests/c/message_routed.c")]),
    "C_MessageVerifyInit": ("planCall:F_MessageVerifyInit",
                            [("haskoki-model-tests", "tests/model/MessageSpec.hs"),
                              ("test-consumers.sh", "tests/c/message_routed.c")]),
    "C_EncryptMessage": ("planCall:F_EncryptMessage",
                         [("haskoki-model-tests", "tests/model/MessageSpec.hs"),
                              ("test-consumers.sh", "tests/c/message_routed.c")]),
    "C_DecryptMessage": ("planCall:F_DecryptMessage",
                         [("haskoki-model-tests", "tests/model/MessageSpec.hs"),
                              ("test-consumers.sh", "tests/c/message_routed.c")]),
    "C_SignMessage": ("planCall:F_SignMessage",
                      [("haskoki-model-tests", "tests/model/MessageSpec.hs"),
                              ("test-consumers.sh", "tests/c/message_routed.c")]),
    "C_VerifyMessage": ("planCall:F_VerifyMessage",
                        [("haskoki-model-tests", "tests/model/MessageSpec.hs"),
                              ("test-consumers.sh", "tests/c/message_routed.c")]),
    "C_EncryptMessageBegin": ("planCall:F_EncryptMessageBegin",
                              [("haskoki-model-tests", "tests/model/MessageSpec.hs"),
                              ("test-consumers.sh", "tests/c/message_routed.c")]),
    "C_DecryptMessageBegin": ("planCall:F_DecryptMessageBegin",
                              [("haskoki-model-tests", "tests/model/MessageSpec.hs"),
                              ("test-consumers.sh", "tests/c/message_routed.c")]),
    "C_SignMessageBegin": ("planCall:F_SignMessageBegin",
                           [("haskoki-model-tests", "tests/model/MessageSpec.hs"),
                              ("test-consumers.sh", "tests/c/message_routed.c")]),
    "C_VerifyMessageBegin": ("planCall:F_VerifyMessageBegin",
                             [("haskoki-model-tests", "tests/model/MessageSpec.hs"),
                              ("test-consumers.sh", "tests/c/message_routed.c")]),
    "C_EncryptMessageNext": ("planCall:F_EncryptMessageNext",
                             [("haskoki-model-tests", "tests/model/MessageSpec.hs"),
                              ("test-consumers.sh", "tests/c/message_routed.c")]),
    "C_DecryptMessageNext": ("planCall:F_DecryptMessageNext",
                             [("haskoki-model-tests", "tests/model/MessageSpec.hs"),
                              ("test-consumers.sh", "tests/c/message_routed.c")]),
    "C_SignMessageNext": ("planCall:F_SignMessageNext",
                          [("haskoki-model-tests", "tests/model/MessageSpec.hs"),
                              ("test-consumers.sh", "tests/c/message_routed.c")]),
    "C_VerifyMessageNext": ("planCall:F_VerifyMessageNext",
                            [("haskoki-model-tests", "tests/model/MessageSpec.hs"),
                              ("test-consumers.sh", "tests/c/message_routed.c")]),
    "C_MessageEncryptFinal": ("planCall:F_MessageEncryptFinal",
                              [("haskoki-model-tests", "tests/model/MessageSpec.hs"),
                              ("test-consumers.sh", "tests/c/message_routed.c")]),
    "C_MessageDecryptFinal": ("planCall:F_MessageDecryptFinal",
                              [("haskoki-model-tests", "tests/model/MessageSpec.hs"),
                              ("test-consumers.sh", "tests/c/message_routed.c")]),
    "C_MessageSignFinal": ("planCall:F_MessageSignFinal",
                           [("haskoki-model-tests", "tests/model/MessageSpec.hs"),
                              ("test-consumers.sh", "tests/c/message_routed.c")]),
    "C_MessageVerifyFinal": ("planCall:F_MessageVerifyFinal",
                             [("haskoki-model-tests", "tests/model/MessageSpec.hs"),
                              ("test-consumers.sh", "tests/c/message_routed.c")]),
    # Real C-table handlers / foreign exports exercised by tests.
    "C_Initialize": ("c-table:on_Initialize",
                     [("haskoki-model-tests", "tests/model/LifecycleSpec.hs"),
                      ("test-loader.sh", "tests/c/loader.c")]),
    "C_Finalize": ("c-table:on_Finalize",
                   [("haskoki-model-tests", "tests/model/LifecycleSpec.hs"),
                    ("test-loader.sh", "tests/c/loader.c")]),
    "C_GetFunctionList": ("c-table:discovery",
                          [("test-loader.sh", "tests/c/loader.c")]),
    "C_GetMechanismList": ("c-table:on_GetMechanismList",
                           [("test-loader.sh", "tests/c/loader.c")]),
    "C_GetMechanismInfo": ("c-table:on_GetMechanismInfo",
                           [("test-loader.sh", "tests/c/loader.c")]),
    "C_WaitForSlotEvent": ("haskoki-export:haskoki_wait_for_slot_event",
                           # Retained private FIFO/callback proofs, not public
                           # coalescing, presence or native CK_NOTIFY evidence.
                           [("haskoki-model-tests", "tests/model/EventsSpec.hs"),
                            ("test-control-events.sh", "tests/c/control_events.c")]),
    # These route through the standard surface with behavior tests
    # executing them (the stale "no behavior test" reasons are gone).
    "C_GetSlotInfo": ("c-table:std_GetSlotInfo",
                      [("haskoki-model-tests", "tests/model/MultiTokenSpec.hs"),
                       ("test-consumers.sh", "tests/c/consumer_discovery.c"),
                       ("test-consumers.sh", "tests/c/consumer_multitoken.c")]),
    "C_GetTokenInfo": ("c-table:std_GetTokenInfo",
                       [("haskoki-model-tests", "tests/model/MultiTokenSpec.hs"),
                        ("test-consumers.sh", "tests/c/consumer_discovery.c"),
                        ("test-consumers.sh", "tests/c/consumer_multitoken.c")]),
    "C_GetSessionInfo": ("haskoki-export:haskoki_std_get_session_info",
                         [("haskoki-model-tests", "tests/model/MultiTokenSpec.hs"),
                          ("test-consumers.sh", "tests/c/consumer_discovery.c")]),
    "C_GetInterfaceList": ("c-global:C_GetInterfaceList",
                           [("test-c-abi.sh", "tests/c/layout_320.c")]),
    "C_GetInterface": ("c-global:C_GetInterface",
                       [("test-c-abi.sh", "tests/c/layout_320.c")]),
    "C_SessionCancel": ("planCall:F_SessionCancel",
                        [("haskoki-model-tests", "tests/model/SessionCancelSpec.hs"),
                         ("test-consumers.sh", "tests/c/consumer_session_cancel.c")]),
    "C_WrapKey": ("c-table:std_WrapKey",
                [("haskoki-model-tests", "tests/model/KeyManagementSpec.hs"),
                 ("test-consumers.sh", "tests/c/consumer_roundtrip.c")]),
    "C_UnwrapKey": ("c-table:std_UnwrapKey",
                  [("haskoki-model-tests", "tests/model/KeyManagementSpec.hs"),
                   ("test-consumers.sh", "tests/c/consumer_roundtrip.c")]),
    "C_AsyncComplete": ("haskoki-export:haskoki_hs_async_complete",
                        [("haskoki-engine-tests", "tests/engine/AsyncEngineSpec.hs"),
                         ("haskoki-engine-tests", "tests/engine/DetachedEngineSpec.hs"),
                         ("test-consumers.sh", "tests/c/async_routed.c"),
                         ("haskoki-model-tests", "tests/model/StandardSurfaceSpec.hs")]),
    "C_AsyncGetID": ("haskoki-export:haskoki_hs_async_get_id",
                     [("haskoki-engine-tests", "tests/engine/DetachedEngineSpec.hs"),
                      ("test-consumers.sh", "tests/c/async_routed.c"),
                      ("haskoki-model-tests", "tests/model/StandardSurfaceSpec.hs"),
                      ("haskoki-engine-tests", "tests/engine/AsyncEngineSpec.hs")]),
    "C_AsyncJoin": ("haskoki-export:haskoki_hs_async_join",
                    [("haskoki-engine-tests", "tests/engine/DetachedEngineSpec.hs"),
                     ("test-consumers.sh", "tests/c/async_routed.c"),
                     ("haskoki-model-tests", "tests/model/StandardSurfaceSpec.hs"),
                     ("haskoki-engine-tests", "tests/engine/AsyncEngineSpec.hs")]),
}

# Public notifications evidence from the executed serving suites and native
# consumers. Append without replacing earlier planner/private references or
# changing classifications, entries, ordinals, layouts or CSV acceptance.
NOTIFICATIONS_EVIDENCE = {
    "C_WaitForSlotEvent": [
        ("test-consumers.sh", "tests/c/notifications_routed.c"),
        ("test-consumers.sh", "tests/c/consumer_notifications_poll.c"),
        ("haskoki-model-tests", "tests/model/NotificationsSpec.hs")],
    "C_GetSlotList": [
        ("test-consumers.sh", "tests/c/notifications_routed.c"),
        ("haskoki-model-tests", "tests/model/NotificationsSpec.hs")],
    "C_GetSlotInfo": [
        ("test-consumers.sh", "tests/c/notifications_routed.c"),
        ("haskoki-model-tests", "tests/model/NotificationsSpec.hs")],
    "C_GetTokenInfo": [
        ("test-consumers.sh", "tests/c/notifications_routed.c"),
        ("haskoki-model-tests", "tests/model/NotificationsSpec.hs")],
    "C_OpenSession": [
        ("test-consumers.sh", "tests/c/notifications_routed.c"),
        ("haskoki-engine-tests", "tests/engine/NotificationsEngineSpec.hs")],
    "C_Digest": [
        ("test-consumers.sh", "tests/c/notifications_routed.c"),
        ("haskoki-engine-tests", "tests/engine/NotificationsEngineSpec.hs")],
    "C_Finalize": [
        ("test-consumers.sh", "tests/c/notifications_routed.c"),
        ("haskoki-model-tests", "tests/model/NotificationsSpec.hs"),
        ("haskoki-engine-tests", "tests/engine/NotificationsEngineSpec.hs")],
}
for name, additions in NOTIFICATIONS_EVIDENCE.items():
    entry, earlier = PLANNED[name]
    PLANNED[name] = (entry, list(dict.fromkeys(earlier + additions)))

# Public certificate evidence from the executed serving suites and the
# native consumer. Append without replacing earlier planner references
# or changing classifications, entries, ordinals, layouts or CSV
# acceptance. T-C10 owns exactly these tuples.
CERTIFICATES_EVIDENCE = {
    "C_CreateObject": [
        ("test-consumers.sh", "tests/c/consumer_certificates.c"),
        ("haskoki-model-tests", "tests/model/CertificateSpec.hs"),
        ("haskoki-engine-tests", "tests/engine/CertificateEngineSpec.hs")],
    "C_CopyObject": [
        ("test-consumers.sh", "tests/c/consumer_certificates.c")],
    "C_DestroyObject": [
        ("test-consumers.sh", "tests/c/consumer_certificates.c")],
    "C_GetAttributeValue": [
        ("test-consumers.sh", "tests/c/consumer_certificates.c")],
    "C_SetAttributeValue": [
        ("test-consumers.sh", "tests/c/consumer_certificates.c")],
    "C_FindObjects": [
        ("test-consumers.sh", "tests/c/consumer_certificates.c")],
}
for name, additions in CERTIFICATES_EVIDENCE.items():
    entry, earlier = PLANNED[name]
    PLANNED[name] = (entry, list(dict.fromkeys(earlier + additions)))

# Row-to-policy references: function name -> list of doc anchors.
# Emitted ONLY on rows present in this map (the six object rows).
POLICY_REFS = {
    "C_CreateObject": ["docs/certificate-objects.md#supplied-values-metadata-position"],
    "C_CopyObject": ["docs/certificate-objects.md#supplied-values-metadata-position"],
    "C_DestroyObject": ["docs/certificate-objects.md#supplied-values-metadata-position"],
    "C_GetAttributeValue": ["docs/certificate-objects.md#supplied-values-metadata-position"],
    "C_SetAttributeValue": ["docs/certificate-objects.md#supplied-values-metadata-position"],
    "C_FindObjects": ["docs/certificate-objects.md#supplied-values-metadata-position"],
}

# name -> exact-gap reason (no behavior claim without tests).
UNWIRed_OP = ("operation-layer behavior tested but no planCall FunctionId "
              "and no C-table route")
UNSUPPORTED = {
    # C_GetSessionInfo/C_GetSlotInfo/C_GetTokenInfo live in PLANNED
    # (standard-surface routes + executed behavior tests).
    "C_InitToken": ("no C_InitToken planning; token setup exists only as "
                    "the Ctl scenario fixture.load step"),
    "C_InitPIN": "no PIN planning in the model; ABI layout only",
    "C_SetPIN": "no PIN planning in the model; ABI layout only",
    "C_LoginUser": ("no C_LoginUser entry; role-login planning covers "
                    "C_Login only"),
    "C_CloseAllSessions": "no close-all planning (single-session close only)",
    "C_GetOperationState": ("no C_GetOperationState framing; engine snapshot "
                            "machinery is tested but unwired to this entry"),
    "C_SetOperationState": ("no C_SetOperationState framing; engine snapshot "
                            "machinery is tested but unwired to this entry"),
    "C_GetObjectSize": "no model planning; ABI layout only",
    "C_FindObjectsInit": "one-shot find only; no cursor state (planner scope: pure-engine one-shot model; the public FFI cursor lives above this layer)",
    "C_FindObjectsFinal": "one-shot find only; no cursor state (planner scope: pure-engine one-shot model; the public FFI cursor lives above this layer)",
    "C_SignRecoverInit": UNWIRed_OP + " (OperationSpec recover cases)",
    "C_SignRecover": UNWIRed_OP + " (OperationSpec recover cases)",
    "C_VerifyRecoverInit": UNWIRed_OP + " (OperationSpec recover cases)",
    "C_VerifyRecover": UNWIRed_OP + " (OperationSpec recover cases)",
    # Dual rows live in PLANNED (wired + executed).
    "C_GenerateKey": UNWIRed_OP + " (KeyManagementSpec keygen cases)",
    "C_GenerateKeyPair": UNWIRed_OP + " (KeyManagementSpec keypair + KEM cases)",
    "C_DeriveKey": UNWIRed_OP + " (KeyManagementSpec derive cases)",
    "C_SeedRandom": "no model planning; ABI layout only",
    "C_GenerateRandom": "no model planning; ABI layout only",
    "C_EncapsulateKey": UNWIRed_OP + " (KeyManagementSpec KEM encaps cases, SyntheticSpec KEM)",
    "C_DecapsulateKey": UNWIRed_OP + " (KeyManagementSpec KEM cases, SyntheticSpec KEM)",
    "C_VerifySignatureInit": "no validation-object verify planning",
    "C_VerifySignature": "no validation-object verify planning",
    "C_VerifySignatureUpdate": "no validation-object verify planning",
    "C_VerifySignatureFinal": "no validation-object verify planning",
    "C_GetSessionValidationFlags": "no validation-flags planning",
    "C_WrapKeyAuthenticated": UNWIRed_OP + " (KeyManagementSpec authenticated-wrapping cases)",
    "C_UnwrapKeyAuthenticated": UNWIRed_OP + " (KeyManagementSpec authenticated-unwrapping cases)",
}

NOT_APPLICABLE = {
    "C_GetFunctionStatus": ("legacy parallel-management entry; specified "
                            "CKR_FUNCTION_NOT_SUPPORTED outside legacy mode, "
                            "which haskoki never enters"),
    "C_CancelFunction": ("legacy parallel-management entry; specified "
                         "CKR_FUNCTION_NOT_SUPPORTED outside legacy mode, "
                         "which haskoki never enters"),
}


def fail(msg):
    print(f"generate-function-contracts: FAIL: {msg}", file=sys.stderr)
    sys.exit(1)


def main():
    try:
        abi = json.loads(ABI_PATH.read_text())
    except Exception as e:  # noqa: BLE001 - reported, not hidden
        fail(f"cannot parse {ABI_PATH}: {e}")
    if not CSV_PATH.exists():
        fail(f"planning seed missing: {CSV_PATH}")
    seed = {}
    with open(CSV_PATH, newline="") as f:
        for row in csv.DictReader(f):
            seed[row["function"]] = row
    ifaces = abi.get("interfaces", {})
    try:
        f32 = ifaces["3.2"]["functions"]
    except KeyError:
        fail("abi-inventory.json has no 3.2 layout")
    if len(f32) != 104:
        fail(f"3.2 layout has {len(f32)} functions, want 104")
    if set(seed) != {f["name"] for f in f32}:
        fail("planning-seed function set != 3.2 layout set")
    # Per-function layout membership from the generated inventory.
    layouts_of = {f["name"]: [] for f in f32}
    for iface in ("2.40", "3.0", "3.1", "3.2"):
        for f in ifaces[iface]["functions"]:
            layouts_of.setdefault(f["name"], []).append(iface)
    # Classification must cover every function exactly once.
    classified = set(PLANNED) | set(UNSUPPORTED) | set(NOT_APPLICABLE)
    names32 = {f["name"] for f in f32}
    if classified != names32:
        fail(f"classification gap/extra: "
             f"missing={sorted(names32 - classified)} "
             f"extra={sorted(classified - names32)}")
    if set(PLANNED) & set(UNSUPPORTED) or set(PLANNED) & set(NOT_APPLICABLE) \
            or set(UNSUPPORTED) & set(NOT_APPLICABLE):
        fail("function classified twice")
    # Every evidence citation must name a real file (the semantic link
    # is curated; existence is machine-checked).
    for name, (_entry, ev) in PLANNED.items():
        if not ev:
            fail(f"{name}: planned without evidence")
        for suite, rel in ev:
            if not (REPO / rel).exists():
                fail(f"{name}: evidence file missing: {rel} (suite {suite})")
    functions = []
    for f in f32:
        name = f["name"]
        row = seed[name]
        acc = [a for a in row["acceptance_cases"].split(";") if a]
        base = {
            "name": name,
            "ordinal_3_2": f["ordinal_1_based"],
            "layouts": layouts_of[name],
            "first_layout": row["first_layout"],
            "csv_acceptance": acc,
        }
        if name in PLANNED:
            entry, ev = PLANNED[name]
            base["contract"] = "planned-with-behavior"
            base["entry"] = entry
            base["reason"] = None
            base["test_evidence"] = [
                {"suite": suite, "spec": rel} for suite, rel in ev
            ]
            if name in POLICY_REFS:
                base["policy_refs"] = list(POLICY_REFS[name])
        elif name in UNSUPPORTED:
            base["contract"] = "unsupported-with-reason"
            base["entry"] = "none"
            base["reason"] = UNSUPPORTED[name]
            base["test_evidence"] = []
        else:
            base["contract"] = "not-applicable"
            base["entry"] = "none"
            base["reason"] = NOT_APPLICABLE[name]
            base["test_evidence"] = []
        functions.append({k: base[k] for k in sorted(base)})
    doc = {
        "scope": "planner/in-process reachability, NOT C-table routing",
        "functions": functions,
        "schema_version": 1,
        "status": "generated-source-of-truth",
        "provenance": ("104 3.2-layout functions from "
                       "spec/abi-inventory.json with planning-seed "
                       "acceptance cases; classification reviewed "
                       "against the contract criterion (entry + executed "
                       "behavior tests). Re-runs preserve no rows: "
                       "classification edits land in this generator's "
                       "PLANNED/UNSUPPORTED/NOT_APPLICABLE tables."),
    }
    OUT_PATH.write_text(json.dumps(doc, indent=2) + "\n")
    n_planned = len(PLANNED)
    print(f"generate-function-contracts: 104 functions "
          f"({n_planned} planned, {len(UNSUPPORTED)} unsupported, "
          f"{len(NOT_APPLICABLE)} not-applicable)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
