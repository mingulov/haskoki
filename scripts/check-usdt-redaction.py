#!/usr/bin/env python3
"""USDT redaction gate: no secret bytes may cross the probe interface.

Fails (exit 1) when any rule fails. The USDT emission path carries
enums and metadata only; this gate pins that property at every layer
of the boundary, failing closed on unparsable files:

1. Haskell FFI imports (`foreign import ccall ... "usdt.h hsk_*" in
   src/Haskoki/Runtime/Usdt.hs): every argument must be Word32/Word64
   and every result IO ()/IO Word32/IO Word64 — no Ptr, CString,
   ByteString, or other payload-capable type.
2. C prototypes (`hsk_usdt_*` in cbits/usdt.h): every parameter must
   be uint32_t/uint64_t (or void) — no pointers at all.
3. C shim body (cbits/usdt.c): no copying primitives (memcpy, strcpy
   family, memmove, sprintf family, strlen, strdup) — the shim never
   moves caller data, it only indexes static tables by enum code.
4. Record assembly (cbits/usdt.c `data[n].value =` sites): every RHS
   must be a static-table reference (`hsk_<table>[<code>]`) or a
   by-value scalar cast (`(const void *)(uintptr_t)<scalar>`); every
   `data[n].key =` RHS must be a string literal. Anything else fails.
5. Behavioral battery: tests/model/UsdtMapSpec.hs must carry the
   `secret content independence` group with the distinctive fixture
   secrets (content-independence is asserted at runtime there).

STDLIB ONLY. Run on HOST python3 from anywhere:
  python3 scripts/check-usdt-redaction.py [--self-test]
"""
import argparse
import re
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
HS = REPO / "src" / "Haskoki" / "Runtime" / "Usdt.hs"
H = REPO / "cbits" / "usdt.h"
C = REPO / "cbits" / "usdt.c"
SPEC = REPO / "tests" / "model" / "UsdtMapSpec.hs"

HS_SCALARS = {"Word32", "Word64"}
HS_RESULTS = {"IO ()", "IO Word32", "IO Word64"}
C_SCALARS = {"uint32_t", "uint64_t"}

FORBIDDEN_CALLS = [
    "memcpy", "strcpy", "strncpy", "strcat", "strncat", "memmove",
    "sprintf", "snprintf", "strlen", "strdup",
]

VALUE_TABLE_RE = re.compile(r"^hsk_[a-z_]+\[[A-Za-z_][A-Za-z0-9_]*\]$")
VALUE_SCALAR_RE = re.compile(
    r"^\(const void \*\)\(uintptr_t\)[A-Za-z_][A-Za-z0-9_]*$")
KEY_LITERAL_RE = re.compile(r'^"[A-Za-z_:.-]+"$')

failures = []


def fail(msg):
    failures.append(msg)


def check_hs_imports(text):
    """Rule 1: every usdt.h foreign import is scalar-only."""
    lines = text.splitlines()
    found = 0
    i = 0
    while i < len(lines):
        m = re.match(
            r'foreign import ccall unsafe "usdt\.h (hsk_\w+)"\s*$',
            lines[i].strip())
        if not m:
            i += 1
            continue
        found += 1
        name = m.group(1)
        i += 1
        if i >= len(lines) or "::" not in lines[i]:
            fail("hs-import %s: missing type signature" % name)
            continue
        sig = lines[i].split("::", 1)[1]
        i += 1
        while i < len(lines) and lines[i].startswith((" ", "\t")) \
                and lines[i].strip() and not lines[i].strip().startswith(
                    ("foreign ", "{-#", "--")):
            # A continuation line ends the signature only when the
            # accumulated text no longer ends with an arrow.
            sig += " " + lines[i].strip()
            if not sig.rstrip().endswith("->"):
                i += 1
                break
            i += 1
        parts = [p.strip() for p in sig.split("->")]
        if len(parts) < 1:
            fail("hs-import %s: unparsable signature" % name)
            continue
        result, args = parts[-1], parts[:-1]
        if result not in HS_RESULTS:
            fail("hs-import %s: non-scalar result %r" % (name, result))
        for arg in args:
            if arg not in HS_SCALARS:
                fail("hs-import %s: non-scalar arg %r" % (name, arg))
    if found == 0:
        fail("hs-imports: no usdt.h foreign imports found")
    return found


def check_c_prototypes(text):
    """Rule 2: every hsk_usdt_* prototype is scalar-only."""
    found = 0
    for m in re.finditer(r"\bhsk_usdt_(\w+)\s*\((.*?)\);", text, re.S):
        name = "hsk_usdt_" + m.group(1)
        # Skip the DTRACE-free #else branch (no prototypes there) by
        # construction: prototypes only exist under HSK_USDT.
        found += 1
        params = [p.strip() for p in m.group(2).split(",")]
        if params == ["void"]:
            continue
        for param in params:
            pm = re.match(r"^(\w+)\s+\w+$", param)
            if pm is None or pm.group(1) not in C_SCALARS:
                fail("c-proto %s: non-scalar param %r" % (name, param))
    if found == 0:
        fail("c-protos: no hsk_usdt_* prototypes found")
    return found


def check_c_body(text):
    """Rules 3-4: no copying primitives; table/scalar values only."""
    for word in FORBIDDEN_CALLS:
        if re.search(r"\b%s\b" % word, text):
            fail("c-body: forbidden copying primitive %s present" % word)
    values = keys = 0
    for lineno, line in enumerate(text.splitlines(), 1):
        vm = re.match(r"\s*data\[n\]\.value\s*=\s*(.+);", line)
        if vm:
            values += 1
            rhs = vm.group(1).strip()
            if not (VALUE_TABLE_RE.match(rhs)
                    or VALUE_SCALAR_RE.match(rhs)):
                fail("c-body:%d: non-table value RHS %r" % (lineno, rhs))
        km = re.match(r"\s*data\[n\]\.key\s*=\s*(.+);", line)
        if km:
            keys += 1
            rhs = km.group(1).strip()
            if not KEY_LITERAL_RE.match(rhs):
                fail("c-body:%d: non-literal key RHS %r" % (lineno, rhs))
    if values == 0:
        fail("c-body: no data[n].value sites found")
    if keys == 0:
        fail("c-body: no data[n].key sites found")
    return values, keys


def check_battery(text):
    """Rule 5: the fixture-secret battery exists in the spec."""
    if 'testGroup "secret content independence"' not in text:
        fail("battery: 'secret content independence' group missing")
    for fixture in ("secretModA", "secretModB", "secretKeyA", "secretKeyB"):
        if fixture not in text:
            fail("battery: fixture %s missing" % fixture)


def check(hs_path=HS, h_path=H, c_path=C, spec_path=SPEC):
    global failures
    failures = []
    try:
        hs_text = Path(hs_path).read_text()
        h_text = Path(h_path).read_text()
        c_text = Path(c_path).read_text()
        spec_text = Path(spec_path).read_text()
    except OSError as exc:
        return ["cannot read inputs: %s" % exc]
    check_hs_imports(hs_text)
    check_c_prototypes(h_text)
    check_c_body(c_text)
    check_battery(spec_text)
    return list(failures)


CLEAN_HS = (
    'foreign import ccall unsafe "usdt.h hsk_usdt_alloc_op"\n'
    '  c_allocOp :: IO Word32\n'
    'foreign import ccall unsafe "usdt.h hsk_usdt_pk_record"\n'
    '  c_pkRecord :: Word64 -> Word32 -> Word32 -> Word32 -> Word32\n'
    '    -> Word64 -> Word32 -> Word32 -> IO ()\n'
)
CLEAN_H = (
    'uint32_t hsk_usdt_alloc_op(void);\n'
    'void hsk_usdt_pk_record(uint64_t op, uint32_t name, uint32_t alg,\n'
    '    uint32_t curve, uint32_t group, uint64_t bits, uint32_t hash,\n'
    '    uint32_t padding);\n'
)
CLEAN_C = (
    '    data[n].key = "name";\n'
    '    data[n].value = hsk_pk_names[name];\n'
    '    data[n].value_size = (unsigned long)-1;\n'
    '    data[n].key = "pk::bits";\n'
    '    data[n].value = (const void *)(uintptr_t)bits;\n'
    '    data[n].value_size = (unsigned long)-2;\n'
)
CLEAN_SPEC = 'redactPins = testGroup "secret content independence"\nsecretModA\nsecretModB\nsecretKeyA\nsecretKeyB\n'


def self_test():
    cases = [
        ("clean passes",
         CLEAN_HS, CLEAN_H, CLEAN_C, CLEAN_SPEC, 0, []),
        ("hs pointer arg fails",
         CLEAN_HS.replace("-> Word64 -> Word32 -> Word32 -> IO ()",
                          "-> Word64 -> Ptr Word8 -> Word32 -> IO ()"),
         CLEAN_H, CLEAN_C, CLEAN_SPEC, 1, ["non-scalar arg"]),
        ("hs cstring result fails",
         CLEAN_HS.replace("c_allocOp :: IO Word32",
                          "c_allocOp :: IO CString"),
         CLEAN_H, CLEAN_C, CLEAN_SPEC, 1, ["non-scalar result"]),
        ("c pointer param fails",
         CLEAN_HS,
         CLEAN_H.replace("uint32_t padding", "const char *padding"),
         CLEAN_C, CLEAN_SPEC, 1, ["non-scalar param"]),
        ("c strcpy fails",
         CLEAN_HS, CLEAN_H,
         CLEAN_C + '    strcpy(buf, name);\n', CLEAN_SPEC, 1, ["strcpy"]),
        ("c caller-pointer value fails",
         CLEAN_HS, CLEAN_H,
         CLEAN_C.replace("hsk_pk_names[name]", "caller_buf"),
         CLEAN_SPEC, 1, ["non-table value"]),
        ("c non-literal key fails",
         CLEAN_HS, CLEAN_H,
         CLEAN_C.replace('"pk::bits"', "key_ptr"), CLEAN_SPEC, 1,
         ["non-literal key"]),
        ("missing battery fails",
         CLEAN_HS, CLEAN_H, CLEAN_C, "-- no battery here\n", 1,
         ["group missing"]),
        ("missing fixture fails",
         CLEAN_HS, CLEAN_H, CLEAN_C,
         CLEAN_SPEC.replace("secretKeyB\n", ""), 1, ["secretKeyB"]),
    ]
    failed = 0
    with tempfile.TemporaryDirectory() as tmp:
        for label, hs, h, c, spec, want_n, want_words in cases:
            root = Path(tmp)
            (root / "U.hs").write_text(hs)
            (root / "u.h").write_text(h)
            (root / "u.c").write_text(c)
            (root / "S.hs").write_text(spec)
            got = check(root / "U.hs", root / "u.h", root / "u.c",
                        root / "S.hs")
            detail = " ".join(got)
            ok = (len(got) == want_n or (want_n == 1 and len(got) >= 1)) \
                and all(w in detail for w in want_words)
            print("%s: self-test %s" % ("ok" if ok else "FAIL", label))
            if not ok:
                print("  got: %s" % detail)
                failed += 1
    print("usdt-redaction: self-test %s" % ("ok" if not failed else "FAIL"))
    return 1 if failed else 0


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args(argv)
    if args.self_test:
        return self_test()
    found = check()
    if found:
        print("usdt-redaction: FAIL:")
        for msg in found:
            print("  %s" % msg)
        return 1
    print("usdt-redaction: OK (ffi scalar-only, shim table-only, "
          "fixture battery present)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
