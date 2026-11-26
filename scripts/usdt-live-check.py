#!/usr/bin/env python3
"""USDT live-capture analyzer: assert typed records per phase.

Reads a GDB capture produced by tests/gdb/usdt_cap.txt over
tests/c/usdt_live.c and fails loudly on any deviation from the
pinned record shapes (see the per-phase asserts below).
Correlation is by op id within the run (counter order is
run-local: silent failures consume ids, so ids are never
hardcoded, only correlated).

Global invariants: NEW/REL pairing, NEW/END terminal pairing,
REJ op_valid iff a same-op END exists, orphan parents, the 'HSK0'
op tag, reason/disposition/phase ranges (failed-exec never
emitted), and exact per-phase event counts (no silent extra or
missing line anywhere).

Func codes derive from core/Haskoki/Request.hs declaration order
(the same fromEnum functionCode uses), so a reorder fails here
instead of silently repinning. CKR/mechanism numbers are stable
external PKCS#11 constants, pinned literally.

STDLIB ONLY. Usage:
  python3 scripts/usdt-live-check.py <capture-file>
"""
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
REQ = REPO / "core" / "Haskoki" / "Request.hs"

# Stable external PKCS#11 constants (decimal as printed by the recipe).
CKR_OK = 0
CKR_FUNCTION_CANCELED = 80
CKR_KEY_HANDLE_INVALID = 96
CKR_KEY_TYPE_INCONSISTENT = 99
CKR_KEY_FUNCTION_NOT_PERMITTED = 104
CKR_KEY_UNEXTRACTABLE = 106
CKR_OPERATION_NOT_INITIALIZED = 145
CKR_PIN_INCORRECT = 160
CKR_SIGNATURE_INVALID = 192

# Mechanism ids (integers; the recipe prints hex).
M_RSA_KEYGEN = 0x0
M_OAEP = 0x9
M_PSS = 0xD
M_ML_KEM_KEYGEN = 0xF
M_ML_KEM = 0x17
M_DH_KEYGEN = 0x20
M_DH_DERIVE = 0x21
M_SHA256_RSA = 0x40
M_XOR = 0x364
M_SHA256 = 0x250
M_HMAC_SHA256 = 0x251
M_EC_KEYGEN = 0x1040
M_ECDSA_SHA256 = 0x1044
M_EDDSA_KEYGEN = 0x1055
M_EDDSA = 0x1057
M_AES_KEYGEN = 0x1080
M_AES_CBC = 0x1082
M_AES_CBC_PAD = 0x1085

PHASE_ORDER = [
    "init", "wrong-pin", "login", "keygen", "sign",
    "verify-ok", "verify-bad", "verify-empty", "verify-null",
    "sign-shortbuf", "shortbuf-verify", "init-denied",
    "digestkey-denied", "digestkey-staged-denied", "msg-sign",
    "msg-verify-next", "msg-encrypt-next", "msg-abandon",
    "msg-init-denied", "msg-query-modes", "msg-query-staged",
    "msg-recall-nonfinal",
    "sign-pss", "verify-pss",
    "sign-abandon", "relogin", "setup-hmac",
    "sign-abandon-nullguard", "sign-abandon-oversize", "digest",
    "digest-abandon-key", "derive", "derive-dh", "wrap", "unwrap",
    "wrap-oaep", "unwrap-oaep", "wrap-query-denied",
    "encaps-query-denied", "eddsa", "kem-keygen",
    "encaps", "decaps", "logout-staged", "logout-fires",
    "logout-clean", "logout-ec-verify", "teardown", "async-deliver",
    "async-cancel",
    "async-xthread", "async-xthread-handoff", "async-detach",
    "async-rejoin", "done",
]

# Exact per-phase event counts (new, rel, end, rej, job): no silent
# extra or missing line anywhere in the capture.
COUNTS = {
    "init": (0, 0, 0, 0, 0),
    "wrong-pin": (0, 0, 1, 1, 0),
    "login": (0, 0, 1, 0, 0),
    "keygen": (1, 1, 1, 0, 0),
    "sign": (1, 1, 1, 0, 0),
    "verify-ok": (1, 1, 1, 0, 0),
    "verify-bad": (1, 1, 1, 0, 0),
    "verify-empty": (1, 1, 1, 0, 0),
    "verify-null": (0, 0, 0, 0, 0),
    "sign-shortbuf": (1, 1, 1, 0, 0),
    "shortbuf-verify": (1, 1, 1, 0, 0),
    "init-denied": (0, 0, 1, 1, 0),
    "digestkey-denied": (0, 0, 0, 1, 0),
    "digestkey-staged-denied": (0, 0, 1, 1, 0),
    "msg-sign": (1, 1, 1, 0, 0),
    "msg-verify-next": (2, 2, 2, 0, 0),
    "msg-encrypt-next": (0, 0, 2, 0, 0),
    "msg-abandon": (0, 0, 2, 0, 0),
    "msg-init-denied": (0, 0, 1, 1, 0),
    "msg-query-modes": (0, 0, 2, 2, 0),
    "msg-query-staged": (0, 0, 2, 0, 0),
    "msg-recall-nonfinal": (0, 0, 3, 0, 0),
    "sign-pss": (1, 1, 1, 0, 0),
    "verify-pss": (1, 1, 1, 0, 0),
    "sign-abandon": (0, 0, 1, 0, 0),
    "relogin": (0, 0, 1, 0, 0),
    "setup-hmac": (0, 0, 1, 0, 0),
    "sign-abandon-nullguard": (0, 0, 1, 0, 0),
    "sign-abandon-oversize": (0, 0, 1, 0, 0),
    "digest": (0, 0, 1, 0, 0),
    "digest-abandon-key": (0, 0, 1, 0, 0),
    "derive": (0, 0, 2, 0, 0),
    "derive-dh": (4, 4, 4, 0, 0),
    "wrap": (0, 0, 3, 0, 0),
    "unwrap": (0, 0, 3, 0, 0),
    "wrap-oaep": (2, 2, 3, 0, 0),
    "unwrap-oaep": (1, 1, 1, 0, 0),
    "wrap-query-denied": (0, 0, 3, 1, 0),
    "encaps-query-denied": (1, 1, 2, 1, 0),
    "eddsa": (3, 3, 3, 0, 0),
    "kem-keygen": (1, 1, 1, 0, 0),
    "encaps": (1, 1, 1, 0, 0),
    "decaps": (1, 1, 1, 0, 0),
    "logout-staged": (0, 0, 1, 0, 0),
    "logout-fires": (0, 0, 1, 0, 0),
    "logout-clean": (2, 2, 2, 0, 0),
    "logout-ec-verify": (1, 1, 1, 0, 0),
    "teardown": (0, 0, 0, 0, 0),
    "async-deliver": (0, 0, 1, 0, 4),
    "async-cancel": (0, 0, 1, 0, 2),
    "async-xthread": (0, 0, 0, 0, 1),
    "async-xthread-handoff": (0, 0, 1, 0, 3),
    "async-detach": (0, 0, 1, 0, 2),
    "async-rejoin": (0, 0, 1, 0, 4),
    "done": (0, 0, 0, 0, 0),
}

TAG = 0x48534B30  # 'HSK0'


def func_codes():
    """fromEnum order of FunctionId from source (fail closed)."""
    text = REQ.read_text()
    start = text.find("data FunctionId")
    if start < 0:
        raise ValueError("data FunctionId not found")
    end = text.find("deriving", start)
    seg = text[start:end if end > start else len(text)]
    first = re.search(r"=\s+(F_\w+)", seg)
    if not first:
        raise ValueError("FunctionId first ctor not found")
    ctors = [first.group(1)] + re.findall(r"\|\s+(F_\w+)", seg)
    return {c: i for i, c in enumerate(ctors)}


def parse(path):
    """Parse the capture into phases + grouped ops."""
    phases = []
    cur = None
    for raw in Path(path).read_text().splitlines():
        if raw.startswith("PHASE:"):
            cur = {"name": raw[6:], "new": [], "rel": [], "end": [],
                   "rej": [], "job": []}
            phases.append(cur)
            continue
        if cur is None:
            continue
        m = re.match(r"^NEW ctx=([0-9a-f]+) parent=(-?\d+) n=(\d+)$", raw)
        if m:
            cur["new"].append({"ctx": m.group(1),
                               "parent": int(m.group(2)),
                               "n": int(m.group(3)), "elems": []})
            continue
        m = re.match(r"^  ([A-Za-z_:.-]+) = (str:\S+|word:\d+|blob\(len \d+\))$",
                     raw)
        if m and cur["new"]:
            cur["new"][-1]["elems"].append((m.group(1), m.group(2)))
            continue
        m = re.match(r"^REL ctx=([0-9a-f]+)$", raw)
        if m:
            cur["rel"].append(m.group(1))
            continue
        m = re.match(r"^END op=([0-9a-f]+) func=(\d+) mech=([0-9a-f]+) "
                     r"mp=(\d+) ckr=(\d+) disp=(\d+) mode=(\d+)$", raw)
        if m:
            cur["end"].append({"op": m.group(1), "func": int(m.group(2)),
                               "mech": int(m.group(3), 16),
                               "mp": int(m.group(4)),
                               "ckr": int(m.group(5)),
                               "disp": int(m.group(6)),
                               "mode": int(m.group(7))})
            continue
        m = re.match(r"^REJ op=([0-9a-f]+) ov=(\d+) func=(\d+) "
                     r"mech=([0-9a-f]+) mp=(\d+) reason=(\d+) ckr=(\d+)$",
                     raw)
        if m:
            cur["rej"].append({"op": m.group(1), "ov": int(m.group(2)),
                               "func": int(m.group(3)),
                               "mech": int(m.group(4), 16),
                               "mp": int(m.group(5)),
                               "reason": int(m.group(6)),
                               "ckr": int(m.group(7))})
            continue
        m = re.match(r"^JOB tab=(\d+) job=(\d+) op=([0-9a-f]+) ov=(\d+) "
                     r"phase=(\d+) ckr=(\d+) cv=(\d+)$", raw)
        if m:
            cur["job"].append({"tab": int(m.group(1)),
                               "job": int(m.group(2)), "op": m.group(3),
                               "ov": int(m.group(4)),
                               "phase": int(m.group(5)),
                               "ckr": int(m.group(6)),
                               "cv": int(m.group(7))})
            continue
    return phases


def elems_dict(new):
    return dict(new["elems"])


class Checker:
    def __init__(self, phases, func):
        self.phases = phases
        self.by_name = {p["name"]: p for p in phases}
        self.func = func
        self.fails = []

    def fail(self, msg):
        self.fails.append(msg)

    def phase(self, name):
        p = self.by_name.get(name)
        if p is None:
            self.fail("missing phase: %s" % name)
            return {"name": name, "new": [], "rel": [], "end": [],
                    "rej": [], "job": []}
        return p

    def check_order(self):
        got = [p["name"] for p in self.phases]
        if got != PHASE_ORDER:
            self.fail("phase order drift:\n got: %s\nwant: %s"
                      % (got, PHASE_ORDER))

    def check_counts(self):
        for p in self.phases:
            want = COUNTS.get(p["name"])
            if want is None:
                self.fail("no count pin for phase: %s" % p["name"])
                continue
            got = (len(p["new"]), len(p["rel"]), len(p["end"]),
                   len(p["rej"]), len(p["job"]))
            if got != want:
                self.fail("%s: counts %s, want %s"
                          % (p["name"], got, want))

    def check_global(self):
        news = [n for p in self.phases for n in p["new"]]
        rels = [r for p in self.phases for r in p["rel"]]
        ends = [e for p in self.phases for e in p["end"]]
        rejs = [r for p in self.phases for r in p["rej"]]
        jobs = [j for p in self.phases for j in p["job"]]
        for n in news:
            if n["parent"] != -1:
                self.fail("NEW %s: parent %d, want orphan -1"
                          % (n["ctx"], n["parent"]))
            if int(n["ctx"], 16) & 0xFFFFFFFF != TAG:
                self.fail("NEW %s: bad op tag" % n["ctx"])
            if len(n["elems"]) != n["n"]:
                self.fail("NEW %s: printed %d elems, n=%d"
                          % (n["ctx"], len(n["elems"]), n["n"]))
            if rels.count(n["ctx"]) != 1:
                self.fail("NEW %s: REL count %d, want 1"
                          % (n["ctx"], rels.count(n["ctx"])))
            if sum(1 for e in ends if e["op"] == n["ctx"]) != 1:
                self.fail("NEW %s: END count != 1" % n["ctx"])
        for r in rels:
            if sum(1 for n in news if n["ctx"] == r) != 1:
                self.fail("REL %s without exactly one NEW" % r)
        for e in ends:
            if int(e["op"], 16) & 0xFFFFFFFF != TAG:
                self.fail("END %s: bad op tag" % e["op"])
            if e["disp"] == 2:
                self.fail("END %s: reserved DispFailedExec emitted"
                          % e["op"])
            if e["disp"] not in (1, 3, 4, 5, 6):
                self.fail("END %s: bad disp %d" % (e["op"], e["disp"]))
        ops = [e["op"] for e in ends]
        if len(ops) != len(set(ops)):
            self.fail("END op ids not unique: %d ends, %d distinct"
                      % (len(ops), len(set(ops))))
        for r in rejs:
            if r["reason"] not in (1, 2, 3, 4, 5):
                self.fail("REJ %s: bad reason %d" % (r["op"], r["reason"]))
            # op_valid holds iff a same-op END exists for this call.
            has_end = any(e["op"] == r["op"] for e in ends)
            if bool(r["ov"]) != has_end:
                self.fail("REJ %s: ov=%d but same-op END present=%s"
                          % (r["op"], r["ov"], has_end))
        for j in jobs:
            # ckrValid holds only on Failed: every other phase
            # carries ckr=0/cv=0 by construction (usdtJobPhase).
            if bool(j["cv"]) != (j["phase"] == 5):
                self.fail("JOB %s: cv=%d on phase %d"
                          % (j["op"], j["cv"], j["phase"]))
            if j["cv"] and j["ckr"] == 0:
                self.fail("JOB %s: cv=1 with ckr=0" % j["op"])
            if j["phase"] not in (1, 2, 3, 4, 5, 6, 7):
                self.fail("JOB %s: bad phase %d" % (j["op"], j["phase"]))
            if j["ov"] != 1:
                self.fail("JOB %s: ov=%d, want 1" % (j["op"], j["ov"]))

    def expect_new(self, ph, name, fields):
        """One NEW with exact element set in phase ph; returns ctx."""
        news = [n for n in ph["new"]
                if elems_dict(n).get("name") == "str:" + name]
        if len(news) != 1:
            self.fail("%s: %d %s records, want 1"
                      % (ph["name"], len(news), name))
            return None
        got = elems_dict(news[0])
        if got != fields:
            self.fail("%s: %s fields %s, want %s"
                      % (ph["name"], name, got, fields))
        return news[0]["ctx"]

    def expect_end(self, ph, op, func, mech, mp, ckr, disp, mode):
        ends = [e for e in ph["end"]
                if op is None or e["op"] == op]
        if op is not None and len(ends) != 1:
            self.fail("%s: %d ENDs for op %s, want 1"
                      % (ph["name"], len(ends), op))
            return
        want = {"func": func, "mech": mech, "mp": mp, "ckr": ckr,
                "disp": disp, "mode": mode}
        for e in ends:
            got = {k: e[k] for k in want}
            if got != want:
                self.fail("%s: END %s fields %s, want %s"
                          % (ph["name"], e["op"], got, want))

    def expect_rej(self, ph, func, mech, mp, reason, ckr, ov, idx=0,
                     nrej=1):
        if len(ph["rej"]) != nrej:
            self.fail("%s: %d REJs, want %d"
                      % (ph["name"], len(ph["rej"]), nrej))
            return None
        r = ph["rej"][idx]
        want = {"func": func, "mech": mech, "mp": mp, "reason": reason,
                "ckr": ckr, "ov": ov}
        got = {k: r[k] for k in want}
        if got != want:
            self.fail("%s: REJ fields %s, want %s"
                      % (ph["name"], got, want))
        return r["op"]

    def run(self):
        f = self.func
        self.check_order()
        self.check_counts()
        self.check_global()
        # Legs index per-phase records positionally; running them
        # after a count/order failure crashes instead of reporting.
        if self.fails:
            return

        ph = self.phase("wrong-pin")
        op = self.expect_rej(ph, f["F_Login"], 0, 0, 1,
                             CKR_PIN_INCORRECT, 1)
        self.expect_end(ph, op, f["F_Login"], 0, 0,
                        CKR_PIN_INCORRECT, 3, 0)

        for name in ("login", "relogin"):
            ph = self.phase(name)
            self.expect_end(ph, None, f["F_Login"], 0, 0, CKR_OK, 1, 0)

        ph = self.phase("setup-hmac")
        self.expect_end(ph, None, f["F_CreateObject"], 0, 0,
                        CKR_OK, 1, 0)

        rsa2048 = {"name": "str:pk::generate", "pk::algorithm": "str:RSA",
                   "pk::bits": "word:2048"}
        ph = self.phase("keygen")
        ctx = self.expect_new(ph, "pk::generate", rsa2048)
        self.expect_end(ph, ctx, f["F_GenerateKeyPair"], M_RSA_KEYGEN, 1,
                        CKR_OK, 1, 0)

        v15 = {"name": "str:pk::sign", "pk::algorithm": "str:RSA",
               "pk::bits": "word:2048", "pk::hash": "str:SHA256",
               "pk::rsa_padding": "str:pkcs1-v1.5"}
        ph = self.phase("sign")
        ctx = self.expect_new(ph, "pk::sign", v15)
        self.expect_end(ph, ctx, f["F_Sign"], M_SHA256_RSA, 1, CKR_OK, 1, 0)

        for name in ("verify-ok", "verify-bad", "verify-empty"):
            ph = self.phase(name)
            rec = dict(v15)
            rec["name"] = "str:pk::verify"
            ctx = self.expect_new(ph, "pk::verify", rec)
            ckr = CKR_OK if name == "verify-ok" else CKR_SIGNATURE_INVALID
            self.expect_end(ph, ctx, f["F_Verify"], M_SHA256_RSA, 1,
                            ckr, 1, 0)

        ph = self.phase("sign-shortbuf")
        ctx = self.expect_new(ph, "pk::sign", v15)
        self.expect_end(ph, ctx, f["F_Sign"], M_SHA256_RSA, 1,
                        CKR_OK, 1, 0)

        ph = self.phase("shortbuf-verify")
        rec = dict(v15)
        rec["name"] = "str:pk::verify"
        ctx = self.expect_new(ph, "pk::verify", rec)
        self.expect_end(ph, ctx, f["F_Verify"], M_SHA256_RSA, 1,
                        CKR_OK, 1, 0)

        ph = self.phase("init-denied")
        self.expect_end(ph, ph["end"][0]["op"], f["F_GenerateKey"],
                        M_AES_KEYGEN, 1, CKR_OK, 1, 0)
        # Requested-mech reporting: ECDSA init refused on an AES key.
        self.expect_rej(ph, f["F_SignInit"], M_ECDSA_SHA256, 1, 2,
                        CKR_KEY_TYPE_INCONSISTENT, 0)

        ph = self.phase("digestkey-denied")
        self.expect_rej(ph, f["F_DigestUpdate"], M_SHA256, 1, 2,
                        CKR_KEY_TYPE_INCONSISTENT, 0)

        ph = self.phase("digestkey-staged-denied")
        # Retention wears the staging call's identity: the bytes were
        # staged by a one-shot C_Digest short query, so both halves
        # of the pair report F_Digest, not the failed call's default.
        op = self.expect_rej(ph, f["F_Digest"], M_SHA256, 1, 2,
                             CKR_KEY_TYPE_INCONSISTENT, 1)
        self.expect_end(ph, op, f["F_Digest"], M_SHA256, 1,
                        CKR_OPERATION_NOT_INITIALIZED, 5, 0)

        ph = self.phase("msg-sign")
        ctx = self.expect_new(ph, "pk::sign", v15)
        self.expect_end(ph, ctx, f["F_SignMessage"], M_SHA256_RSA, 1,
                        CKR_OK, 1, 0)

        ph = self.phase("msg-verify-next")
        ctx = self.expect_new(ph, "pk::sign", v15)
        self.expect_end(ph, ctx, f["F_SignMessage"], M_SHA256_RSA, 1,
                        CKR_OK, 1, 0)
        rec = dict(v15)
        rec["name"] = "str:pk::verify"
        ctx = self.expect_new(ph, "pk::verify", rec)
        self.expect_end(ph, ctx, f["F_VerifyMessageNext"], M_SHA256_RSA,
                        1, CKR_OK, 1, 0)

        ph = self.phase("msg-encrypt-next")
        self.expect_end(ph, ph["end"][0]["op"], f["F_GenerateKey"],
                        M_AES_KEYGEN, 1, CKR_OK, 1, 0)
        self.expect_end(ph, ph["end"][1]["op"], f["F_EncryptMessageNext"],
                        M_AES_CBC, 1, CKR_OK, 1, 0)

        ph = self.phase("msg-abandon")
        self.expect_end(ph, ph["end"][0]["op"], f["F_GenerateKey"],
                        M_AES_KEYGEN, 1, CKR_OK, 1, 0)
        self.expect_end(ph, ph["end"][1]["op"], f["F_EncryptMessageNext"],
                        M_AES_CBC, 1, CKR_OPERATION_NOT_INITIALIZED, 5, 0)

        ph = self.phase("msg-init-denied")
        self.expect_end(ph, ph["end"][0]["op"], f["F_GenerateKey"],
                        M_AES_KEYGEN, 1, CKR_OK, 1, 0)
        # Requested-mech reporting on the message path: an ECDSA
        # message-sign init refused on an AES key.
        self.expect_rej(ph, f["F_MessageSignInit"], M_ECDSA_SHA256, 1,
                        2, CKR_KEY_TYPE_INCONSISTENT, 0)

        ph = self.phase("msg-query-modes")
        self.expect_end(ph, ph["end"][0]["op"], f["F_GenerateKey"],
                        M_AES_KEYGEN, 1, CKR_OK, 1, 0)
        # Query finality: the same NOT_INITIALIZED failure stays
        # end-less for a non-final query but reports a failed end
        # for a final one (ov tracks the same-op end).
        self.expect_rej(ph, f["F_EncryptMessageNext"], M_AES_CBC, 1,
                        5, CKR_OPERATION_NOT_INITIALIZED, 0,
                        idx=0, nrej=2)
        op = self.expect_rej(ph, f["F_EncryptMessageNext"], M_AES_CBC,
                             1, 5, CKR_OPERATION_NOT_INITIALIZED, 1,
                             idx=1, nrej=2)
        self.expect_end(ph, op, f["F_EncryptMessageNext"], M_AES_CBC,
                        1, CKR_OPERATION_NOT_INITIALIZED, 3, 0)

        ph = self.phase("msg-query-staged")
        self.expect_end(ph, ph["end"][0]["op"], f["F_GenerateKey"],
                        M_AES_KEYGEN, 1, CKR_OK, 1, 0)
        # The NULL query reports its length silently; closing the
        # session abandons the staged slot exactly once, via the
        # flush (no reject: the close itself succeeded).
        self.expect_end(ph, ph["end"][1]["op"], f["F_EncryptMessageNext"],
                        M_AES_CBC, 1, CKR_OPERATION_NOT_INITIALIZED, 5, 0)

        ph = self.phase("msg-recall-nonfinal")
        self.expect_end(ph, ph["end"][0]["op"], f["F_GenerateKey"],
                        M_AES_KEYGEN, 1, CKR_OK, 1, 0)
        # N1: the non-final recall delivers the staged final bytes
        # with a delivered end (staged state promotes it past the
        # caller's end=0); the re-init plus one-shot pins a clean
        # F_EncryptMessage identity.
        self.expect_end(ph, ph["end"][1]["op"], f["F_EncryptMessageNext"],
                        M_AES_CBC, 1, CKR_OK, 1, 0)
        self.expect_end(ph, ph["end"][2]["op"], f["F_EncryptMessage"],
                        M_AES_CBC, 1, CKR_OK, 1, 0)

        pss = {"name": "str:pk::sign", "pk::algorithm": "str:RSA",
               "pk::bits": "word:2048", "pk::hash": "str:SHA384",
               "pk::rsa_padding": "str:pss"}
        ph = self.phase("sign-pss")
        ctx = self.expect_new(ph, "pk::sign", pss)
        self.expect_end(ph, ctx, f["F_Sign"], M_PSS, 1, CKR_OK, 1, 0)
        ph = self.phase("verify-pss")
        rec = dict(pss)
        rec["name"] = "str:pk::verify"
        ctx = self.expect_new(ph, "pk::verify", rec)
        self.expect_end(ph, ctx, f["F_Verify"], M_PSS, 1, CKR_OK, 1, 0)

        ph = self.phase("sign-abandon")
        self.expect_end(ph, None, f["F_Sign"], M_SHA256_RSA, 1,
                        CKR_OPERATION_NOT_INITIALIZED, 5, 0)

        for name in ("sign-abandon-nullguard", "sign-abandon-oversize"):
            ph = self.phase(name)
            self.expect_end(ph, None, f["F_Sign"], M_HMAC_SHA256, 1,
                            CKR_OPERATION_NOT_INITIALIZED, 5, 0)

        ph = self.phase("digest")
        self.expect_end(ph, None, f["F_Digest"], M_SHA256, 1,
                        CKR_OK, 1, 0)

        ph = self.phase("digest-abandon-key")
        self.expect_end(ph, None, f["F_Digest"], M_SHA256, 1,
                        CKR_OPERATION_NOT_INITIALIZED, 5, 0)

        ph = self.phase("derive")
        self.expect_end(ph, ph["end"][0]["op"], f["F_CreateObject"],
                        0, 0, CKR_OK, 1, 0)
        self.expect_end(ph, ph["end"][1]["op"], f["F_DeriveKey"],
                        M_XOR, 1, CKR_OK, 1, 0)

        ph = self.phase("derive-dh")
        dhgen = {"name": "str:pk::generate",
                 "pk::algorithm": "str:DH", "pk::bits": "word:2048"}
        dhder = {"name": "str:pk::derive",
                 "pk::algorithm": "str:DH", "pk::bits": "word:2048"}
        gens = [n for n in ph["new"] if elems_dict(n) == dhgen]
        ders = [n for n in ph["new"] if elems_dict(n) == dhder]
        if len(gens) != 2 or len(ders) != 2:
            self.fail("derive-dh: want 2 DH-generate + 2 DH-derive "
                      "records (DH/2048, no hash/pad/group)")
        for e in ph["end"]:
            if e["func"] == f["F_DeriveKey"]:
                self.expect_end(ph, e["op"], f["F_DeriveKey"],
                                M_DH_DERIVE, 1, CKR_OK, 1, 0)
            else:
                self.expect_end(ph, e["op"], f["F_GenerateKeyPair"],
                                M_DH_KEYGEN, 1, CKR_OK, 1, 0)

        ph = self.phase("wrap")
        for e in ph["end"][:2]:
            self.expect_end(ph, e["op"], f["F_GenerateKey"],
                            M_AES_KEYGEN, 1, CKR_OK, 1, 0)
        self.expect_end(ph, ph["end"][2]["op"], f["F_WrapKey"],
                        M_AES_CBC, 1, CKR_OK, 1, 0)

        ph = self.phase("unwrap")
        self.expect_end(ph, ph["end"][0]["op"], f["F_UnwrapKey"],
                        M_AES_CBC, 1, CKR_OK, 1, 0)
        self.expect_end(ph, ph["end"][1]["op"], f["F_Encrypt"],
                        M_AES_CBC_PAD, 1, CKR_OK, 1, 0)
        self.expect_end(ph, ph["end"][2]["op"], f["F_Decrypt"],
                        M_AES_CBC_PAD, 1, CKR_OK, 1, 0)

        oaep_enc = {"name": "str:pk::encrypt",
                    "pk::algorithm": "str:RSA", "pk::bits": "word:2048",
                    "pk::hash": "str:SHA256",
                    "pk::rsa_padding": "str:oaep"}
        ph = self.phase("wrap-oaep")
        self.expect_end(ph, ph["end"][0]["op"], f["F_GenerateKeyPair"],
                        M_RSA_KEYGEN, 1, CKR_OK, 1, 0)
        self.expect_end(ph, ph["end"][1]["op"], f["F_GenerateKey"],
                        M_AES_KEYGEN, 1, CKR_OK, 1, 0)
        ctx = self.expect_new(ph, "pk::encrypt", oaep_enc)
        self.expect_end(ph, ctx, f["F_WrapKey"], M_OAEP, 1, CKR_OK, 1, 0)
        ph = self.phase("unwrap-oaep")
        rec = dict(oaep_enc)
        rec["name"] = "str:pk::decrypt"
        ctx = self.expect_new(ph, "pk::decrypt", rec)
        self.expect_end(ph, ctx, f["F_UnwrapKey"], M_OAEP, 1, CKR_OK, 1, 0)

        ph = self.phase("wrap-query-denied")
        self.expect_end(ph, ph["end"][0]["op"], f["F_GenerateKey"],
                        M_AES_KEYGEN, 1, CKR_OK, 1, 0)
        self.expect_end(ph, ph["end"][1]["op"], f["F_GenerateKey"],
                        M_AES_KEYGEN, 1, CKR_OK, 1, 0)
        op = self.expect_rej(ph, f["F_WrapKey"], M_AES_CBC, 1, 2,
                             CKR_KEY_UNEXTRACTABLE, 1)
        self.expect_end(ph, op, f["F_WrapKey"], M_AES_CBC, 1,
                        CKR_KEY_UNEXTRACTABLE, 3, 0)

        kemgen = {"name": "str:pk::generate",
                  "pk::algorithm": "str:ML-KEM"}
        ph = self.phase("encaps-query-denied")
        ctx = self.expect_new(ph, "pk::generate", kemgen)
        self.expect_end(ph, ctx, f["F_GenerateKeyPair"], M_ML_KEM_KEYGEN,
                        1, CKR_OK, 1, 0)
        op = self.expect_rej(ph, f["F_EncapsulateKey"], M_ML_KEM, 1, 2,
                             CKR_KEY_FUNCTION_NOT_PERMITTED, 1)
        self.expect_end(ph, op, f["F_EncapsulateKey"], M_ML_KEM, 1,
                        CKR_KEY_FUNCTION_NOT_PERMITTED, 3, 0)

        ph = self.phase("eddsa")
        edgen = {"name": "str:pk::generate",
                 "pk::algorithm": "str:EDDSA",
                 "pk::curve": "str:ed25519", "pk::bits": "word:256"}
        ctx = self.expect_new(ph, "pk::generate", edgen)
        self.expect_end(ph, ctx, f["F_GenerateKeyPair"], M_EDDSA_KEYGEN,
                        1, CKR_OK, 1, 0)
        edsign = {"name": "str:pk::sign", "pk::algorithm": "str:EDDSA",
                  "pk::curve": "str:ed25519", "pk::bits": "word:256"}
        ctx = self.expect_new(ph, "pk::sign", edsign)
        self.expect_end(ph, ctx, f["F_Sign"], M_EDDSA, 1, CKR_OK, 1, 0)
        edver = {"name": "str:pk::verify", "pk::algorithm": "str:EDDSA",
                 "pk::curve": "str:ed25519", "pk::bits": "word:256"}
        ctx = self.expect_new(ph, "pk::verify", edver)
        self.expect_end(ph, ctx, f["F_Verify"], M_EDDSA, 1, CKR_OK, 1, 0)

        kemgen = {"name": "str:pk::generate",
                  "pk::algorithm": "str:ML-KEM"}
        ph = self.phase("kem-keygen")
        ctx = self.expect_new(ph, "pk::generate", kemgen)
        self.expect_end(ph, ctx, f["F_GenerateKeyPair"], M_ML_KEM_KEYGEN,
                        1, CKR_OK, 1, 0)
        ph = self.phase("encaps")
        rec = dict(kemgen)
        rec["name"] = "str:pk::encapsulate"
        ctx = self.expect_new(ph, "pk::encapsulate", rec)
        self.expect_end(ph, ctx, f["F_EncapsulateKey"], M_ML_KEM, 1,
                        CKR_OK, 1, 0)
        ph = self.phase("decaps")
        rec = dict(kemgen)
        rec["name"] = "str:pk::decapsulate"
        ctx = self.expect_new(ph, "pk::decapsulate", rec)
        self.expect_end(ph, ctx, f["F_DecapsulateKey"], M_ML_KEM, 1,
                        CKR_OK, 1, 0)

        ph = self.phase("logout-staged")
        self.expect_end(ph, None, f["F_CreateObject"], 0, 0,
                        CKR_OK, 1, 0)

        ph = self.phase("logout-fires")
        self.expect_end(ph, None, f["F_Sign"], M_HMAC_SHA256, 1,
                        CKR_OPERATION_NOT_INITIALIZED, 5, 0)

        ph = self.phase("logout-clean")
        ecgen = {"name": "str:pk::generate",
                 "pk::algorithm": "str:EC", "pk::curve": "str:secp256r1"}
        ctx = self.expect_new(ph, "pk::generate", ecgen)
        self.expect_end(ph, ctx, f["F_GenerateKeyPair"], M_EC_KEYGEN, 1,
                        CKR_OK, 1, 0)
        ecdsa = {"name": "str:pk::sign", "pk::algorithm": "str:EC",
                 "pk::curve": "str:secp256r1", "pk::hash": "str:SHA256"}
        ctx = self.expect_new(ph, "pk::sign", ecdsa)
        self.expect_end(ph, ctx, f["F_Sign"], M_ECDSA_SHA256, 1,
                        CKR_OK, 1, 0)

        ph = self.phase("logout-ec-verify")
        # The curve survives the stored-form round trip: resolvers
        # read the engine's stored name, not DER (regression leg).
        ecver = {"name": "str:pk::verify", "pk::algorithm": "str:EC",
                 "pk::curve": "str:secp256r1", "pk::hash": "str:SHA256"}
        ctx = self.expect_new(ph, "pk::verify", ecver)
        self.expect_end(ph, ctx, f["F_Verify"], M_ECDSA_SHA256, 1,
                        CKR_OK, 1, 0)

        self.check_async("async-deliver", [1, 2, 3, 4], CKR_OK, 1)
        self.check_async("async-cancel", [1, 6], CKR_FUNCTION_CANCELED, 5)

        # Cross-thread: accepted on main, claimed/ready/delivered on
        # the worker, all under one job id.
        a = self.phase("async-xthread")
        b = self.phase("async-xthread-handoff")
        ja = [j for j in a["job"]]
        jb = [j for j in b["job"]]
        if [j["phase"] for j in ja] != [1]:
            self.fail("async-xthread: want [accepted], got %s" % ja)
        if [j["phase"] for j in jb] != [2, 3, 4]:
            self.fail("async-xthread-handoff: want [claimed, ready, "
                      "delivered], got %s" % jb)
        ids = {(j["tab"], j["job"], j["op"]) for j in ja + jb}
        if len(ids) != 1:
            self.fail("async-xthread: job identity splits: %s" % ids)
        e = b["end"][0]
        if (e["op"], e["func"], e["disp"], e["mode"]) != \
                (next(iter(ids))[2], f["F_Digest"], 1, 1):
            self.fail("async-xthread-handoff: END %s" % e)

        # Detach hands off (handoff pair under the source op);
        # rejoin is a fresh op (Accepted, Ready on claim win).
        a = self.phase("async-detach")
        if [j["phase"] for j in a["job"]] != [1, 7]:
            self.fail("async-detach: want [accepted, handoff], got %s"
                      % a["job"])
        else:
            ids_a = {(j["tab"], j["job"], j["op"]) for j in a["job"]}
            if len(ids_a) != 1:
                self.fail("async-detach: job identity splits")
            else:
                e = a["end"][0]
                if (e["op"], e["func"], e["mech"], e["mp"], e["ckr"],
                        e["disp"], e["mode"]) != \
                        (next(iter(ids_a))[2], f["F_Digest"], M_SHA256,
                         1, CKR_OK, 6, 1):
                    self.fail("async-detach: END %s" % e)
        b = self.phase("async-rejoin")
        if [j["phase"] for j in b["job"]] != [1, 2, 3, 4]:
            self.fail("async-rejoin: want [accepted, claimed, ready, "
                      "delivered], got %s" % b["job"])
        else:
            ids_b = {(j["tab"], j["job"], j["op"]) for j in b["job"]}
            if len(ids_b) != 1:
                self.fail("async-rejoin: job identity splits")
            else:
                ops_a = {j["op"] for j in a["job"]}
                ops_b = {j["op"] for j in b["job"]}
                if ops_a == ops_b:
                    self.fail("async-rejoin: op id not fresh")
                e = b["end"][0]
                if (e["op"], e["func"], e["disp"], e["mode"]) != \
                        (next(iter(ids_b))[2], f["F_Digest"], 1, 1):
                    self.fail("async-rejoin: END %s" % e)

    def check_async(self, name, phases, ckr, disp):
        ph = self.phase(name)
        jobs = ph["job"]
        if [j["phase"] for j in jobs] != phases:
            self.fail("%s: phases %s, want %s"
                      % (name, [j["phase"] for j in jobs], phases))
            return
        ids = {(j["tab"], j["job"], j["op"]) for j in jobs}
        if len(ids) != 1:
            self.fail("%s: job identity splits: %s" % (name, ids))
            return
        e = ph["end"][0]
        op = next(iter(ids))[2]
        want = {"op": op, "func": self.func["F_Digest"],
                "mech": M_SHA256, "mp": 1, "ckr": ckr, "disp": disp,
                "mode": 1}
        got = {k: e[k] for k in want}
        if got != want:
            self.fail("%s: END %s, want %s" % (name, got, want))


def main(argv):
    if len(argv) != 2:
        print("usage: usdt-live-check.py <capture-file>")
        return 2
    try:
        func = func_codes()
    except (OSError, ValueError) as exc:
        print("usdt-live-check: FAIL: %s" % exc)
        return 1
    try:
        phases = parse(argv[1])
    except OSError as exc:
        print("usdt-live-check: FAIL: cannot read %s: %s" % (argv[1], exc))
        return 1
    checker = Checker(phases, func)
    checker.run()
    if checker.fails:
        print("usdt-live-check: FAIL (%d):" % len(checker.fails))
        for msg in checker.fails:
            print("  - %s" % msg)
        return 1
    n_ops = len({e["op"] for p in phases for e in p["end"]})
    n_new = sum(len(p["new"]) for p in phases)
    print("usdt-live-check: OK (%d phases, %d ops, %d pk records)"
          % (len(phases), n_ops, n_new))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
