#!/usr/bin/env python3
"""Remote-only bounded diagnostics. Collect every result; failures stay failures."""
import hashlib
import json
import os
from pathlib import Path
import secrets
import signal
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "product-review-results"
OUT.mkdir(exist_ok=True)
RESULTS = []
PROBE_ENV = os.environ.copy()
PROBE_ENV.pop("HASKOKI_CONFIG", None)
PROBE_ENV.pop("HASKOKI_TRACE", None)
FOLLOWUP = sys.argv[1:] == ["--followup"]
if sys.argv[1:] not in ([], ["--followup"]):
    raise SystemExit("usage: run-source-checks.py [--followup]")


def record(name, command, *, timeout=240, env=None, classification="regression"):
    effective = dict(PROBE_ENV)
    if env:
        effective.update({k: str(v) for k, v in env.items()})
    scratch = OUT / (name + "-scratch")
    scratch.mkdir(exist_ok=True)
    effective["TMPDIR"] = str(scratch)
    started = time.monotonic()
    result = {"name": name, "command": command, "timeout_seconds": timeout,
              "classification": classification, "env_overrides": env or {},
              "log": name + ".log"}
    with (OUT / result["log"]).open("w") as log:
        log.write(json.dumps(result) + "\n")
        log.flush()
        try:
            proc = subprocess.Popen(command, cwd=ROOT, env=effective, stdout=log,
                                    stderr=subprocess.STDOUT, start_new_session=True)
            try:
                result["exit_code"] = proc.wait(timeout=timeout)
                result["status"] = "pass" if proc.returncode == 0 else "fail"
            except subprocess.TimeoutExpired:
                os.killpg(proc.pid, signal.SIGTERM)
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    os.killpg(proc.pid, signal.SIGKILL)
                    proc.wait()
                result.update(exit_code=proc.returncode, status="timeout")
        except OSError as exc:
            log.write("SETUP_ERROR " + repr(exc) + "\n")
            result.update(exit_code=None, status="setup_error")
    result["elapsed_seconds"] = round(time.monotonic() - started, 3)
    RESULTS.append(result)
    (OUT / "results.json").write_text(json.dumps(RESULTS, indent=2) + "\n")
    print(json.dumps(result), flush=True)
    if result["status"] != "pass":
        print((OUT / result["log"]).read_text(errors="replace")[-16000:], flush=True)
    return result["status"] == "pass"


def configuration(name, *, sqlite=False, extra=""):
    location = OUT / (name + ".toml")
    storage = 'kind = "memory"\n'
    if sqlite:
        storage = 'kind = "sqlite"\npath = ' + json.dumps(str(OUT / (name + ".db"))) + "\n"
    location.write_text('schema_version = 1\nprofile = "demo-maximal"\n\n'
                        '[storage]\n' + storage + '\n[engine]\nkind = "openssl"\n'
                        'allow_synthetic_fallback = false\nprivate_library_context = true\n'
                        '\n[trace]\nenabled = false\n' + extra)
    return {"HASKOKI_CONFIG": str(location)}


record("versions", ["bash", "-c", "set -euo pipefail\nprintf 'GITHUB_SHA=%s\\n' \"$GITHUB_SHA\"\nghc --version\ncabal --version\ncc --version\n/opt/openssl-4.0.2/bin/openssl version"], timeout=30, classification="provenance")
modules = sorted((ROOT / "dist-newstyle").rglob("libhaskoki*.so"))
if len(modules) != 1:
    record("module-discovery", ["python3", "-c", "raise SystemExit('SETUP_ERROR expected exactly one shared module')"], classification="setup")
    if FOLLOWUP:
        failures = [r["name"] for r in RESULTS if r["status"] != "pass"]
        print("SUMMARY " + json.dumps({"cases": len(RESULTS), "failures": failures}), flush=True)
        sys.exit(1)
else:
    module = str(modules[0])
    (OUT / "module.json").write_text(json.dumps({"path": module, "sha256": hashlib.sha256(modules[0].read_bytes()).hexdigest()}, indent=2) + "\n")
    native = str(OUT / "native_product_probe")
    if record("compile-native", ["cc", "-std=c11", "-O2", "-g", "-Wall", "-Wextra", "-Werror", "-Ispec/vendor", "tests/review/native_product_probe.c", "-o", native, "-ldl", "-lpthread"], classification="setup"):
        if FOLLOWUP:
            record("native-context-binding", [native, module, "context-binding"],
                   env=configuration("native-context-binding"), classification="diagnostic")
            limits = configuration("limits-two", extra='\n[limits]\nsessions = 2\n')
            record("native-session-limit", [native, module, "session-limit"],
                   env=limits, classification="diagnostic")
        else:
            for mode in ["dh-collision", "derive-protection", "private-logout", "private-so", "digest-os", "digest-app", "lifecycle", "token-info", "pin-lockout-reopen"]:
                record("native-" + mode, [native, module, mode], env=configuration("native-" + mode, sqlite=mode == "pin-lockout-reopen"), classification="diagnostic")
            limits = configuration("limits-two-pin-one", extra='\n[limits]\nsessions = 2\n\n[tokens]\nlabels = ["haskoki-demo"]\nso_pins = ["s"]\nuser_pins = ["u"]\n')
            limits.update(HSK_REVIEW_USER_PIN="u", HSK_REVIEW_SO_PIN="s")
            record("native-configured-limits", [native, module, "token-info"], env=limits, classification="diagnostic-observation")
            record("opensc-configured-pin-one", ["pkcs11-tool", "--module", module, "--login", "--pin", "u", "--list-objects"], env=limits, classification="diagnostic-observation")
    if FOLLOWUP:
        failures = [r["name"] for r in RESULTS if r["status"] != "pass"]
        print("SUMMARY " + json.dumps({"cases": len(RESULTS), "failures": failures}), flush=True)
        sys.exit(1 if failures else 0)
    waiter = str(OUT / "finalize_wait_race_probe")
    if record("compile-finalize-wait", ["cc", "-std=c11", "-O2", "-g", "-Wall", "-Wextra", "-Werror", "-Ispec/vendor", "tests/c/finalize_wait_race_probe.c", "-o", waiter, "-ldl", "-lpthread"], classification="setup"):
        record("finalize-wait-100", [waiter, module], env={"HASKOKI_FINALIZE_WAIT_CYCLES": "100"}, classification="supplementary-stress")

    independent = configuration("independent-clients", sqlite=True)
    independent["GNUTLS_PIN"] = "1234"
    record("gnutls-discovery", ["p11tool", "--provider", module, "--batch", "--list-tokens"], env=independent, classification="independent-client")
    if record("opensc-create-ec", ["pkcs11-tool", "--module", module, "--login", "--pin", "1234", "--keypairgen", "--key-type", "EC:prime256v1", "--label", "review-ec", "--id", "0101", "--usage-sign"], env=independent, classification="independent-client"):
        record("gnutls-list-key", ["p11tool", "--provider", module, "--batch", "--login", "--list-all", "pkcs11:token=haskoki-demo"], env=independent, classification="independent-client")
        record("gnutls-test-sign", ["p11tool", "--provider", module, "--batch", "--login", "--test-sign", "--hash", "SHA256", "pkcs11:token=haskoki-demo;object=review-ec;type=private"], env=independent, classification="independent-client")

    java_dir = OUT / "java"
    java_dir.mkdir(exist_ok=True)
    java_config = OUT / "sunpkcs11.cfg"
    java_config.write_text("name = HaskokiReview\nlibrary = " + module + "\n" + '''slot = 0
destroyTokenAfterLogout = true
attributes(generate, CKO_PUBLIC_KEY, CKK_EC) = {
  CKA_TOKEN = false
  CKA_PRIVATE = false
  CKA_VERIFY = true
}
attributes(generate, CKO_PRIVATE_KEY, CKK_EC) = {
  CKA_TOKEN = false
  CKA_PRIVATE = true
  CKA_SENSITIVE = true
  CKA_EXTRACTABLE = false
  CKA_SIGN = true
}
''')
    if record("compile-java", ["javac", "--release", "17", "-d", str(java_dir), "tests/review/JavaTokenProbe.java"], classification="setup"):
        record("java-independent-ec", ["java", "--add-modules", "jdk.crypto.cryptoki,jdk.crypto.ec", "-cp", str(java_dir), "JavaTokenProbe", str(java_config)], env=configuration("java-independent-ec"), classification="independent-client")

record("runtime-store-probes", ["cabal", "test", "haskoki-review-probes", "--test-show-details=direct"], timeout=180, classification="diagnostic")
seed = secrets.randbelow(2**31 - 1)
for suite in ["haskoki-core-tests", "haskoki-tests", "haskoki-storage-tests",
              "haskoki-prop-tests", "haskoki-model-tests", "haskoki-engine-tests"]:
    record(suite, ["cabal", "test", suite, "--test-show-details=direct"], timeout=600,
           env={"PROP_SEED": str(seed), "PROP_CASES": "1000"})

for driver in ["test-crypto-routed.sh", "test-sim-threaded.sh", "test-finalize-race.sh",
               "test-async-attached.sh", "test-async-detached.sh", "test-control-events.sh",
               "test-lifecycle.sh", "test-consumers.sh", "test-c-mutexes.sh",
               "test-ossl4-bounds.sh"]:
    record(driver[:-3], ["sh", "scripts/" + driver], timeout=360)
record("sim-threaded-8", ["sh", "scripts/test-sim-threaded.sh"], timeout=360,
       env={"HASKOKI_SIM_N": "8", "HASKOKI_SIM_M": "100"})


failures = [r["name"] for r in RESULTS if r["status"] != "pass"]
print("SUMMARY " + json.dumps({"cases": len(RESULTS), "failures": failures}), flush=True)
sys.exit(1 if failures else 0)
