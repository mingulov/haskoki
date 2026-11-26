#!/usr/bin/env python3
"""USDT probe manifest gate: the shipped module carries exactly the
frozen probe set, with exact arities, machine-word arguments, and no
semaphores.

STDLIB ONLY. Run:
  python3 scripts/check-usdt-probes.py --so PATH/TO/libhaskoki.so
  python3 scripts/check-usdt-probes.py --so PATH --expect-off
  python3 scripts/check-usdt-probes.py --self-test

Manifest (frozen by the 0.6.1 USDT plan; change only with a plan
amendment): provider crypto_auditing carries new_context_with_data/4
and release_context/1 and nothing else; provider haskoki carries
operation_end/7, policy_reject/7 and job_state/7 and nothing else.
Every argument must be an 8-byte word; every semaphore must be 0
(plain probes). --expect-off requires zero notes for either
provider. Fails closed: missing readelf/cc, unreadable file,
non-ELF input, or a missing fixture toolchain all fail.
"""
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
USDT_H = REPO / "cbits" / "usdt.h"
DOCKER_IMAGE = "ubuntu:26.04"
DOCKER_TIMEOUT = 600

# provider -> {probe: argc}
MANIFEST = {
    "crypto_auditing": {
        "new_context_with_data": 4,
        "release_context": 1,
    },
    "haskoki": {
        "operation_end": 7,
        "policy_reject": 7,
        "job_state": 7,
    },
}

PROVIDERS = frozenset(MANIFEST)


def fail(msg):
    print(f"FAIL: usdt-probes: {msg}")
    return 1


def parse_notes(text):
    """Parse readelf -nW output into [(provider, name, argc, sem, widths)]."""
    notes = []
    cur = {}
    for line in text.splitlines():
        m = re.search(r"Provider:\s*(\S+)", line)
        if m:
            if cur:
                notes.append(cur)
            cur = {"provider": m.group(1)}
            continue
        m = re.search(r"Name:\s*(\S+)", line)
        if m and cur and "name" not in cur:
            cur["name"] = m.group(1)
            continue
        m = re.search(r"Semaphore:\s*(\S+)", line)
        if m and cur:
            cur["sem"] = m.group(1)
            continue
        m = re.search(r"Arguments:(.*)$", line)
        if m and cur:
            args = m.group(1).split()
            cur["argc"] = len(args)
            cur["widths"] = [a.split("@")[0] for a in args if "@" in a]
            continue
    if cur:
        notes.append(cur)
    return [(n.get("provider"), n.get("name"), n.get("argc"),
             n.get("sem"), n.get("widths", [])) for n in notes]


def readelf_notes(path):
    exe = shutil.which("readelf")
    if exe is None:
        return None, "readelf not found"
    try:
        r = subprocess.run([exe, "-nW", str(path)],
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           text=True, timeout=120)
    except (OSError, subprocess.SubprocessError) as exc:
        return None, f"readelf failed: {exc}"
    if r.returncode != 0:
        return None, f"readelf failed: {r.stdout.strip()[:200]}"
    if "NT_STAPSDT" not in r.stdout and ".note.stapsdt" not in r.stdout:
        return [], None
    return parse_notes(r.stdout), None


def check_manifest(notes):
    """Exact-set manifest check. Returns list of failure strings."""
    errs = []
    want = {(p, n): c for p, m in MANIFEST.items() for n, c in m.items()}
    seen = {}
    for provider, name, argc, sem, widths in notes:
        if provider not in PROVIDERS:
            continue
        if (provider, name) not in want:
            errs.append(f"unexpected probe {provider}:{name} "
                        f"(manifest is exact)")
            continue
        seen[(provider, name)] = seen.get((provider, name), 0) + 1
        if argc != want[(provider, name)]:
            errs.append(f"{provider}:{name} has {argc} args, "
                        f"want {want[(provider, name)]}")
        # Widths render "8" (unsigned word) or "-8" (signed word,
        # from (long) casts); both are machine words.
        if any(w.lstrip("-") != "8" for w in widths):
            errs.append(f"{provider}:{name} has non-word args: {widths}")
        if sem is not None and sem not in ("0x0000000000000000", "0x0", "0"):
            errs.append(f"{provider}:{name} has semaphore {sem} "
                        f"(want plain probes)")
    for key in sorted(want):
        if key not in seen:
            errs.append(f"missing probe {key[0]}:{key[1]}")
    return errs


def check_off(notes):
    return [f"unexpected probe {p}:{n} in an off build"
            for p, n, _, _, _ in notes if p in PROVIDERS]


def cmd_check(args):
    if not args.so:
        return fail("--so PATH is required")
    p = Path(args.so)
    if not p.is_file():
        return fail(f"not a file: {p}")
    notes, err = readelf_notes(p)
    if err is not None:
        return fail(err)
    errs = check_off(notes) if args.expect_off else check_manifest(notes)
    if errs:
        for e in errs:
            print(f"FAIL: usdt-probes: {e}")
        return 1
    mode = "off (no probes)" if args.expect_off else "exact manifest"
    print(f"usdt-probes: OK ({p.name}: {mode})")
    return 0


POSITIVE_C = r"""
#include "cbits/usdt.h"
void usdt_selftest_fire(unsigned long ctx) {
    HSK_AUDIT_RECORD(ctx, "pk::sign");
    HSK_USDT_RELEASE(ctx);
    HSK_HASKOKI_OPERATION_END(ctx, 1, 2, 1, 0, 1, 0);
    HSK_HASKOKI_POLICY_REJECT(ctx, 1, 1, 2, 1, 3, 4);
    HSK_HASKOKI_JOB_STATE(5, 6, ctx, 1, 7, 8, 1);
}
"""

NEGATIVE_C = "int usdt_selftest_anchor;\n"

TAMPER_C = r"""
#include <sys/sdt.h>
void usdt_selftest_fire(unsigned long ctx) {
    DTRACE_PROBE3(haskoki, operation_end, ctx, 1, 2);
}
"""


def have_host_sdt():
    for cand in ("/usr/include/sys/sdt.h",
                 "/usr/include/x86_64-linux-gnu/sys/sdt.h"):
        if Path(cand).is_file():
            return True
    return False


def cc_shared(workdir, src_text, out_name, extra=()):
    src = workdir / "probe.c"
    src.write_text(src_text)
    out = workdir / out_name
    if shutil.which("cc") is None:
        return None, "host cc not found"
    r = subprocess.run(["cc", "-shared", "-fPIC", "-I", str(REPO),
                        *extra, "-o", str(out), str(src)],
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                       text=True, timeout=300)
    if r.returncode != 0:
        return None, f"cc failed: {r.stdout.strip()[:300]}"
    return out, None


def cc_shared_docker(workdir, src_text, out_name, extra=()):
    if shutil.which("docker") is None:
        return None, "need cc+sdt.h on host or docker"
    src = workdir / "probe.c"
    src.write_text(src_text)
    if USDT_H.is_file():
        hdr = workdir / "cbits"
        hdr.mkdir(exist_ok=True)
        (hdr / "usdt.h").write_text(USDT_H.read_text())
    flags = " ".join(extra)
    r = subprocess.run(
        ["docker", "run", "--rm", "--network", "host",
         "-v", f"{workdir}:/w", DOCKER_IMAGE, "sh", "-ec",
         "apt-get update -qq 2>/dev/null; "
         "apt-get install -y -qq --no-install-recommends "
         "systemtap-sdt-dev gcc libc6-dev >/dev/null 2>&1; "
         f"gcc -shared -fPIC -I /w {flags} -o /w/{out_name} /w/probe.c"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        timeout=DOCKER_TIMEOUT)
    if r.returncode != 0:
        return None, f"docker cc failed: {r.stdout.strip()[:300]}"
    return workdir / out_name, None


def build_fixture(workdir, src_text, out_name, needs_sdt, extra=()):
    if not needs_sdt:
        return cc_shared(workdir, src_text, out_name, extra)
    if have_host_sdt():
        return cc_shared(workdir, src_text, out_name, extra)
    return cc_shared_docker(workdir, src_text, out_name, extra)


def self_test():
    failures = []

    def check(name, cond, detail=""):
        print(f"{'ok' if cond else 'FAIL'}: self-test: {name}"
              + (f": {detail}" if detail and not cond else ""))
        if not cond:
            failures.append(name)

    # Parser unit leg (no toolchain needed).
    sample = """\
  stapsdt              0x00000046\tNT_STAPSDT (SystemTap probe descriptors)\t    Provider: haskoki
    Name: operation_end
    Location: 0x000000000000110d, Base: 0x0000000000002000, Semaphore: 0x0000000000000000
    Arguments: 8@-8(%rbp) 8@-16(%rbp) 8@-24(%rbp) 8@-32(%rbp) 8@-40(%rbp) 8@-48(%rbp) 8@-56(%rbp)
"""
    parsed = parse_notes(sample)
    check("parser reads provider/name/argc/sem/widths",
          parsed == [("haskoki", "operation_end", 7,
                      "0x0000000000000000", ["8"] * 7)],
          repr(parsed))

    with tempfile.TemporaryDirectory(prefix="usdt-gate-") as td:
        work = Path(td)
        # Positive leg: the real header must produce the manifest.
        if not USDT_H.is_file():
            check("positive fixture builds from cbits/usdt.h", False,
                  "cbits/usdt.h missing")
        else:
            so, err = build_fixture(work, POSITIVE_C, "pos.so", True,
                                    ("-DHSK_USDT",))
            check("positive fixture builds from cbits/usdt.h", so is not None,
                  err or "")
            if so is not None:
                notes, err = readelf_notes(so)
                if err is not None:
                    check("positive manifest found", False, err)
                else:
                    errs = check_manifest(notes)
                    check("positive manifest found", not errs,
                          "; ".join(errs))
            off, err = build_fixture(work, POSITIVE_C, "pos-off.so", False)
            check("off-branch fixture builds without sdt.h", off is not None,
                  err or "")
            if off is not None:
                notes, err = readelf_notes(off)
                if err is not None:
                    check("off branch carries no probes", False, err)
                else:
                    check("off branch carries no probes",
                          not check_off(notes))
        # Negative leg: plain TU carries no probes.
        so, err = build_fixture(work, NEGATIVE_C, "neg.so", False)
        check("negative fixture builds", so is not None, err or "")
        if so is not None:
            notes, err = readelf_notes(so)
            if err is not None:
                check("negative off check passes", False, err)
            else:
                check("negative off check passes", not check_off(notes))
        # Tamper leg: wrong arity must fail the manifest.
        so, err = build_fixture(work, TAMPER_C, "tamper.so", True)
        check("tamper fixture builds", so is not None, err or "")
        if so is not None:
            notes, err = readelf_notes(so)
            if err is not None:
                check("tamper arity rejected", False, err)
            else:
                check("tamper arity rejected",
                      bool(check_manifest(notes)))

    if failures:
        print(f"usdt-probes self-test: FAIL ({len(failures)} legs)")
        return 1
    print("usdt-probes self-test: OK")
    return 0


def main(argv):
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--so", default=None)
    ap.add_argument("--expect-off", action="store_true")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args(argv)
    if args.self_test:
        return self_test()
    return cmd_check(args)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
