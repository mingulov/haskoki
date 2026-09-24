#!/usr/bin/env python3
"""OpenSSL surface conformance check: enforce the provider-only boundary.

Fails (exit 1) when:

* src/Haskoki/Engine/Backend.hs imports Foreign.*, declares foreign
  imports, or enables ForeignFunctionInterface (pure types only);
* cbits/ossl4_ctx.{h,c} or ffi/Haskoki/FFI/OpenSSL4/Raw.hs reference a
  banned low-level symbol: ENGINE_*, *_meth_* constructors, RSA_sign,
  AES_encrypt, EC_KEY_*, OPENSSL_cleanup, OPENSSL_atexit, or the old
  EVP_DigestSign/VerifyInit ENGINE forms;
* the shim references a pkcs11 provider string/header (prose mentions
  in comments are allowed; quoted literals and includes are not).

Prose mentions of banned names in C comments are tolerated (the ban is
about code references), except inside Raw.hs, which must stay minimal.
"""
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
BACKEND = REPO / "src/Haskoki/Engine/Backend.hs"
RAW = REPO / "ffi/Haskoki/FFI/OpenSSL4/Raw.hs"
SHIM = [REPO / "cbits/ossl4_ctx.h", REPO / "cbits/ossl4_ctx.c"]

# Banned code references (regexes over comment-stripped C / raw Haskell).
BANNED_CODE = [
    r"\bENGINE_[A-Za-z_]+",
    r"\bEVP_(?:CIPHER|MD|PKEY|PKEY_asn1)_meth_[A-Za-z_]+",
    r"\bRSA_sign\b",
    r"\bAES_encrypt\b",
    r"\bEC_KEY_[A-Za-z_]+",
    r"(?<![A-Za-z_])OPENSSL_cleanup\s*\(",
    r"&\s*OPENSSL_cleanup\b",
    r"(?<![A-Za-z_])OPENSSL_atexit\s*\(",
    r"&\s*OPENSSL_atexit\b",
    r"\bOPENSSL_init_crypto\s*\(",
    r"\bOpenSSL_add_all_[A-Za-z_]+\s*\(",
    r"\bERR_free_strings\s*\(",
    r"\bEVP_cleanup\s*\(",
]

BANNED_RE = [re.compile(p) for p in BANNED_CODE]

BACKEND_BANNED = [
    r"^import\s+(?:qualified\s+)?Foreign\b",
    r"^foreign\s+import\b",
    r"\{-#\s*LANGUAGE[^\-]*\bForeignFunctionInterface\b",
]
BACKEND_RE = [re.compile(p) for p in BACKEND_BANNED]

PKCS11_LITERAL = re.compile(r'"[^"\n]*pkcs11[^"\n]*"|pkcs11\.h', re.IGNORECASE)


def strip_c_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.DOTALL)
    text = re.sub(r"//[^\n]*", " ", text)
    return text


def check_backend() -> list:
    failures = []
    src = BACKEND.read_text().splitlines()
    for lineno, line in enumerate(src, start=1):
        stripped = line.strip()
        for rx in BACKEND_RE:
            if rx.search(stripped):
                failures.append(f"{BACKEND.relative_to(REPO)}:{lineno}: {stripped}")
    return failures


def check_code_refs(path: Path, strip_comments: bool) -> list:
    failures = []
    text = path.read_text()
    code = strip_c_comments(text) if strip_comments else text
    for lineno, line in enumerate(code.splitlines(), start=1):
        for rx in BANNED_RE:
            if rx.search(line):
                failures.append(
                    f"{path.relative_to(REPO)}:{lineno}: banned ref {rx.pattern!r}: {line.strip()}"
                )
    return failures


def check_pkcs11() -> list:
    failures = []
    for path in SHIM:
        for lineno, line in enumerate(path.read_text().splitlines(), start=1):
            if PKCS11_LITERAL.search(line):
                failures.append(
                    f"{path.relative_to(REPO)}:{lineno}: pkcs11 provider string: {line.strip()}"
                )
    return failures


def main() -> int:
    missing = [str(p) for p in [BACKEND, RAW, *SHIM] if not p.exists()]
    if missing:
        print(f"ossl4-surface: missing files: {', '.join(missing)}", file=sys.stderr)
        return 1
    failures = check_backend()
    failures += check_pkcs11()
    for path in SHIM:
        failures += check_code_refs(path, strip_comments=True)
    failures += check_code_refs(RAW, strip_comments=False)
    if failures:
        print("ossl4-surface: BANNED references found:", file=sys.stderr)
        for f in failures:
            print(f"  {f}", file=sys.stderr)
        return 1
    print("ossl4-surface: OK (Backend pure; shim+Raw provider-only)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
