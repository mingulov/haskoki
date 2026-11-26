#!/usr/bin/env python3
"""USDT live-capture analyzer: assert typed records per phase.

Reads a GDB capture produced by tests/gdb/usdt_cap.txt over
tests/c/usdt_live.c and fails loudly on any deviation from the
pinned record shapes (see the EXPECTS table). Correlation is by op
id within the run (counter order is run-local: phantom allocations
from silent failures consume ids, so ids are never hardcoded).

Global invariants: NEW/REL pairing, NEW/END terminal pairing,
REJ/END pairing, orphan parents, the 'HSK0' op tag, reason/
disposition ranges, and the reserved DispFailedExec never emitted.
Per-phase asserts pin exact fields, counts, and silence legs.

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
CKR_ARGS_BAD = 7
CKR_FUNCTION_CANCELED = 80
CKR_KEY_HANDLE_INVALID = 96
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
M_AES_KEYGEN = 0x1080
M_AES_CBC = 0x1082
M_AES_CBC_PAD = 0x1085

PHASE_ORDER = [
    "init", "wrong-pin", "login", "keygen", "sign",
    "verify-ok", "verify-bad", "verify-empty", "verify-null",
    "sign-shortbuf", "sign-pss", "verify-pss", "sign-abandon",
    "relogin", "setup-hmac", "sign-abandon-nullguard",
    "sign-abandon-oversize", "digest", "digest-abandon-key",
    "derive", "derive-dh", "wrap", "unwrap", "wrap-oaep",
    "unwrap-oaep", "kem-keygen", "encaps", "decaps", "teardown",
    "async-deliver", "async-cancel", "async-xthread",
    "async-xthread-handoff", "done",
]

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

    def check_global(self):
        news = [n for p in self.phases for n in p["new"]]
        rels = [r for p in self.phases for r in p["rel"]]
        ends = [e for p in self.phases for e in p["end"]]
        rejs = [r for p in self.phases for r in p["rej"]]
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
            if e["disp"] not in (1, 3, 4, 5):
                self.fail("END %s: bad disp %d" % (e["op"], e["disp"]))
        for r in rejs:
            if r["reason"] not in (1, 2, 3, 4, 5):
                self.fail("REJ %s: bad reason %d" % (r["op"], r["reason"]))
            if sum(1 for e in ends if e["op"] == r["op"]) != 1:
                self.fail("REJ %s: END count != 1" % r["op"])

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

    def expect_silent(self, name):
        ph = self.phase(name)
        total = sum(len(ph[k]) for k in ("new", "rel", "end", "rej", "job"))
        if total != 0:
            self.fail("%s: %d probe lines, want silence" % (name, total))

    def run(self):
        f = self.func
        self.check_order()
        self.check_global()

        self.expect_silent("init")

        ph = self.phase("wrong-pin")
        if len(ph["rej"]) != 1 or len(ph["end"]) != 1 or ph["new"]:
            self.fail("wrong-pin: want 1 REJ + 1 END, no NEW")
        else:
            r = ph["rej"][0]
            if (r["func"], r["reason"], r["ckr"]) != \
                    (f["F_Login"], 1, CKR_PIN_INCORRECT):
                self.fail("wrong-pin: REJ %s" % r)
            self.expect_end(ph, r["op"], f["F_Login"], 0, 0,
                            CKR_PIN_INCORRECT, 3, 0)

        for name in ("login", "relogin"):
            ph = self.phase(name)
            if len(ph["end"]) != 1 or ph["rej"] or ph["new"]:
                self.fail("%s: want bare END only" % name)
            else:
                self.expect_end(ph, None, f["F_Login"], 0, 0, CKR_OK, 1, 0)

        ph = self.phase("setup-hmac")
        if len(ph["end"]) != 1 or ph["new"]:
            self.fail("setup-hmac: want 1 CreateObject END, no NEW")
        else:
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

        for name, func in (("verify-ok", "F_Verify"),
                           ("verify-bad", "F_Verify"),
                           ("verify-empty", "F_Verify")):
            ph = self.phase(name)
            rec = dict(v15)
            rec["name"] = "str:pk::verify"
            ctx = self.expect_new(ph, "pk::verify", rec)
            ckr = CKR_OK if name == "verify-ok" else CKR_SIGNATURE_INVALID
            self.expect_end(ph, ctx, f[func], M_SHA256_RSA, 1, ckr, 1, 0)

        self.expect_silent("verify-null")

        ph = self.phase("sign-shortbuf")
        if len(ph["new"]) != 1:
            self.fail("sign-shortbuf: %d NEWs, want exactly 1"
                      % len(ph["new"]))
        else:
            ctx = self.expect_new(ph, "pk::sign", v15)
            self.expect_end(ph, ctx, f["F_Sign"], M_SHA256_RSA, 1,
                            CKR_OK, 1, 0)

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
        if len(ph["end"]) != 1 or ph["new"]:
            self.fail("sign-abandon: want 1 abandoned END, no NEW")
        else:
            self.expect_end(ph, None, f["F_Sign"], M_SHA256_RSA, 1,
                            CKR_OPERATION_NOT_INITIALIZED, 5, 0)

        for name in ("sign-abandon-nullguard", "sign-abandon-oversize"):
            ph = self.phase(name)
            if len(ph["end"]) != 1 or ph["new"]:
                self.fail("%s: want 1 abandoned END, no NEW" % name)
            else:
                self.expect_end(ph, None, f["F_Sign"], M_HMAC_SHA256, 1,
                                CKR_OPERATION_NOT_INITIALIZED, 5, 0)

        ph = self.phase("digest")
        if len(ph["end"]) != 1 or ph["new"]:
            self.fail("digest: want private END only, no NEW")
        else:
            self.expect_end(ph, None, f["F_Digest"], M_SHA256, 1,
                            CKR_OK, 1, 0)

        ph = self.phase("digest-abandon-key")
        if len(ph["end"]) != 1 or ph["new"] or ph["rej"]:
            self.fail("digest-abandon-key: want 1 abandoned END "
                      "(non-policy, no REJ)")
        else:
            self.expect_end(ph, None, f["F_Digest"], M_SHA256, 1,
                            CKR_OPERATION_NOT_INITIALIZED, 5, 0)

        ph = self.phase("derive")
        if ph["new"] or len(ph["end"]) != 2:
            self.fail("derive: want 0 NEW + 2 ENDs (create, derive)")
        else:
            self.expect_end(ph, ph["end"][0]["op"], f["F_CreateObject"],
                            0, 0, CKR_OK, 1, 0)
            self.expect_end(ph, ph["end"][1]["op"], f["F_DeriveKey"],
                            M_XOR, 1, CKR_OK, 1, 0)

        ph = self.phase("derive-dh")
        if len(ph["new"]) != 4:
            self.fail("derive-dh: %d NEWs, want 4" % len(ph["new"]))
        else:
            dhgen = {"name": "str:pk::generate",
                     "pk::algorithm": "str:DH", "pk::bits": "word:2048"}
            dhder = {"name": "str:pk::derive",
                     "pk::algorithm": "str:DH", "pk::bits": "word:2048"}
            gens = [n for n in ph["new"] if elems_dict(n) == dhgen]
            ders = [n for n in ph["new"] if elems_dict(n) == dhder]
            if len(gens) != 2 or len(ders) != 2:
                self.fail("derive-dh: want 2 DH-generate + 2 DH-derive "
                          "records (DH/2048, no hash/pad/group)")
        ends = [e for e in ph["end"] if e["func"] == f["F_DeriveKey"]]
        if len(ends) != 2:
            self.fail("derive-dh: %d derive ENDs, want 2" % len(ends))
        for e in ends:
            if (e["func"], e["mech"], e["disp"]) != \
                    (f["F_DeriveKey"], M_DH_DERIVE, 1):
                self.fail("derive-dh: END %s" % e)

        ph = self.phase("wrap")
        if ph["new"] or len(ph["end"]) != 3:
            self.fail("wrap: want 0 NEW + 3 ENDs")
        else:
            for e in ph["end"][:2]:
                self.expect_end(ph, e["op"], f["F_GenerateKey"],
                                M_AES_KEYGEN, 1, CKR_OK, 1, 0)
            self.expect_end(ph, ph["end"][2]["op"], f["F_WrapKey"],
                            M_AES_CBC, 1, CKR_OK, 1, 0)

        ph = self.phase("unwrap")
        if ph["new"] or len(ph["end"]) != 3:
            self.fail("unwrap: want 0 NEW + 3 ENDs")
        else:
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
        ctx = self.expect_new(ph, "pk::encrypt", oaep_enc)
        self.expect_end(ph, ctx, f["F_WrapKey"], M_OAEP, 1, CKR_OK, 1, 0)
        ph = self.phase("unwrap-oaep")
        rec = dict(oaep_enc)
        rec["name"] = "str:pk::decrypt"
        ctx = self.expect_new(ph, "pk::decrypt", rec)
        self.expect_end(ph, ctx, f["F_UnwrapKey"], M_OAEP, 1, CKR_OK, 1, 0)

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

        self.expect_silent("teardown")
        self.expect_silent("done")

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
        if len(b["end"]) != 1:
            self.fail("async-xthread-handoff: want 1 END")
        else:
            e = b["end"][0]
            if (e["op"], e["func"], e["disp"], e["mode"]) != \
                    (next(iter(ids))[2], f["F_Digest"], 1, 1):
                self.fail("async-xthread-handoff: END %s" % e)

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
        if len(ph["end"]) != 1:
            self.fail("%s: want 1 END" % name)
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