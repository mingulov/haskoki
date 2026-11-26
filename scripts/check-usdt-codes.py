#!/usr/bin/env python3
"""USDT code consistency: Haskell codes in Haskoki.Runtime.Usdt must
match cbits/usdt.h defines and string tables exactly.

STDLIB ONLY. Run: python3 scripts/check-usdt-codes.py [--self-test]

Compares:
  - HSK_PK_* / HSK_ALG_* / HSK_CURVE_* / HSK_GROUP_* / HSK_HASH_* /
    HSK_PAD_* numeric defines against the Haskell pkNameCode and the
    PkKeyFacts-producing sites is indirect; this gate pins the C
    defines present and the Haskell code functions' literal outputs
    by executing the documented pairs (parsed, not executed).
  - the C string tables (algorithm/curve/group/hash/padding spellings)
    against the frozen spelling list below.

Fails closed on unparsable files.
"""
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
H = REPO / "cbits" / "usdt.h"
C = REPO / "cbits" / "usdt.c"
HS = REPO / "src" / "Haskoki" / "Runtime" / "Usdt.hs"

# C define -> Haskell code function and expected value.
# (hsfunc, [(cdefine, value)])
CODE_GROUPS = [
    ("pkNameCode",
     [("HSK_PK_SIGN", 1), ("HSK_PK_VERIFY", 2), ("HSK_PK_ENCRYPT", 3),
      ("HSK_PK_DECRYPT", 4), ("HSK_PK_ENCAPSULATE", 5),
      ("HSK_PK_DECAPSULATE", 6), ("HSK_PK_GENERATE", 7),
      ("HSK_PK_DERIVE", 8)]),
    ("dispositionCode",
     [("DispDelivered", 1), ("DispFailedExec", 2),
      ("DispFailedPublish", 3), ("DispFailedWriteback", 4),
      ("DispAbandoned", 5), ("DispHandedOff", 6)]),
    ("opModeCode", [("ModeSync", 0), ("ModeAsync", 1)]),
    ("policyReasonCode",
     [("ReasonAuth", 1), ("ReasonUsage", 2), ("ReasonReadonly", 3),
      ("ReasonTemplate", 4), ("ReasonState", 5)]),
    ("jobPhaseCode",
     [("PhaseAccepted", 1), ("PhaseClaimed", 2), ("PhaseReady", 3),
      ("PhaseDelivered", 4), ("PhaseFailed", 5), ("PhaseCanceled", 6),
      ("PhaseHandoff", 7)]),
]

# C table -> [(define, spelling)]
STRING_TABLES = {
    "hsk_algs": [
        ("HSK_ALG_RSA", "RSA"), ("HSK_ALG_EC", "EC"),
        ("HSK_ALG_DSA", "DSA"), ("HSK_ALG_DH", "DH"),
        ("HSK_ALG_XDH", "XDH"), ("HSK_ALG_EDDSA", "EDDSA"),
        ("HSK_ALG_ML_DSA", "ML-DSA"), ("HSK_ALG_ML_KEM", "ML-KEM"),
        ("HSK_ALG_SLH_DSA", "SLH-DSA")],
    "hsk_curves": [
        ("HSK_CURVE_SECP256R1", "secp256r1"),
        ("HSK_CURVE_SECP384R1", "secp384r1"),
        ("HSK_CURVE_SECP521R1", "secp521r1"),
        ("HSK_CURVE_SECP256K1", "secp256k1"),
        ("HSK_CURVE_ED25519", "ed25519"),
        ("HSK_CURVE_X25519", "x25519"),
        ("HSK_CURVE_ED448", "ed448"),
        ("HSK_CURVE_X448", "x448")],
    "hsk_groups": [
        ("HSK_GROUP_MODP2048", "modp2048"),
        ("HSK_GROUP_MODP3072", "modp3072"),
        ("HSK_GROUP_MODP4096", "modp4096"),
        ("HSK_GROUP_MODP6144", "modp6144"),
        ("HSK_GROUP_MODP8192", "modp8192")],
    "hsk_hashes": [
        ("HSK_HASH_MD5", "MD5"), ("HSK_HASH_SHA1", "SHA1"),
        ("HSK_HASH_SHA224", "SHA224"), ("HSK_HASH_SHA256", "SHA256"),
        ("HSK_HASH_SHA384", "SHA384"), ("HSK_HASH_SHA512", "SHA512"),
        ("HSK_HASH_SHA3_224", "SHA3-224"),
        ("HSK_HASH_SHA3_256", "SHA3-256"),
        ("HSK_HASH_SHA3_384", "SHA3-384"),
        ("HSK_HASH_SHA3_512", "SHA3-512")],
    "hsk_pads": [
        ("HSK_PAD_PSS", "pss"), ("HSK_PAD_OAEP", "oaep"),
        ("HSK_PAD_PKCS1_V1_5", "pkcs1-v1.5")],
}


def fail(msg):
    print(f"FAIL: usdt-codes: {msg}")
    return 1


def parse_defines(text):
    return {m.group(1): int(m.group(2))
            for m in re.finditer(r"#define\s+(HSK_\w+)\s+(\d+)", text)}


def parse_hs_codes(text, func):
    m = re.search(rf"^{re.escape(func)}.*?\n(.*?)(?:\n\s*\n|\Z)",
                  text, re.M | re.S)
    if not m:
        return None
    block = m.group(1)
    out = {name: int(val) for name, val
           in re.findall(r"(\w+)\s*->\s*(\d+)", block)}
    out.update({name: int(val) for name, val in
                re.findall(rf"{re.escape(func)}\s+(\w+)\s*=\s*(\d+)",
                           func + "\n" + block)})
    return out


def hs_name_for_define(define):
    # HSK_PK_SIGN -> PkSign.
    parts = define.split("_")[1:]
    return "".join(p[:1] + p[1:].lower() for p in parts)


def check():
    errs = []
    try:
        h = H.read_text()
        c = C.read_text()
        hs = HS.read_text()
    except OSError as exc:
        return [f"cannot read inputs: {exc}"]
    defines = parse_defines(h)
    if not defines:
        return ["no HSK_* defines parsed from cbits/usdt.h"]

    # pkNameCode rows must match HSK_PK_* defines by value.
    pk = parse_hs_codes(hs, "pkNameCode")
    if not pk:
        errs.append("cannot parse pkNameCode")
    else:
        for define, want in CODE_GROUPS[0][1]:
            if defines.get(define) != want:
                errs.append(f"C {define}={defines.get(define)}, want {want}")
            if pk.get(hs_name_for_define(define)) != want:
                errs.append(f"hs pkNameCode {define} mismatch")

    # Other code functions pin literals (parsed presence + values).
    for func, rows in CODE_GROUPS[1:]:
        got = parse_hs_codes(hs, func)
        if not got:
            errs.append(f"cannot parse {func}")
            continue
        for name, want in rows:
            if got.get(name) != want:
                errs.append(f"hs {func} {name}={got.get(name)}, "
                            f"want {want}")

    # String tables: every expected (define, spelling) present, and
    # no table row references an undefined HSK_* code.
    for table, rows in STRING_TABLES.items():
        for define, spelling in rows:
            if defines.get(define) is None:
                errs.append(f"C {define} undefined (table {table})")
            pat = (r"\[" + re.escape(define) + r"\]\s*=\s*\""
                   + re.escape(spelling) + r"\"")
            if not re.search(pat, c):
                errs.append(f"C table {table} lacks {define}="
                            f'"{spelling}"')

    # Haskell key-fact codes used in keyFactsOf must be defined C codes.
    # (Spot check: every HSK_ALG/CURVE/GROUP/HASH/PAD define from 1..N
    # has no gaps, so Haskell literals cannot silently miss one.)
    for prefix in ("HSK_ALG_", "HSK_CURVE_", "HSK_GROUP_", "HSK_HASH_",
                   "HSK_PAD_", "HSK_PK_"):
        vals = sorted(v for k, v in defines.items()
                      if k.startswith(prefix) and "NONE" not in k
                      and v != 0)
        if vals != list(range(1, len(vals) + 1)):
            errs.append(f"C {prefix}* has gaps: {vals}")
    return errs


def self_test():
    global C
    errs = check()
    if errs:
        for e in errs:
            print(f"FAIL: usdt-codes self-test: {e}")
        return 1
    # Negative: tampered spelling must fail.
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        bad = Path(td) / "usdt.c"
        bad.write_text(C.read_text().replace('"ML-KEM"', '"MLKEM"'))
        real, C = C, bad
        try:
            tampered = check()
        finally:
            C = real
    if not tampered:
        print("FAIL: usdt-codes self-test: tamper not detected")
        return 1
    print("usdt-codes self-test: OK")
    return 0


def main(argv):
    if "--self-test" in argv:
        return self_test()
    errs = check()
    if errs:
        for e in errs:
            print(f"FAIL: usdt-codes: {e}")
        return 1
    print("usdt-codes: OK (Haskell codes match cbits/usdt.h)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
