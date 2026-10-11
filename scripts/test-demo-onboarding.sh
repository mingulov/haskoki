#!/bin/sh
# Run the beginner paths against an existing image. No builds, host toolchain,
# network access in the containers, host credentials, or real keys required.
# The first run catches missing /out; hands-on catches missing tools/config and
# lost keys between clients; remoting catches a client that never reaches Haskoki.
set -u
image=${1:?usage: test-demo-onboarding.sh IMAGE [OUTPUT-DIR]}
out=${2:-$(mktemp -d)}
mkdir -p "$out" || exit 1
failures=0
check() {
  name=$1; shift
  if "$@" > "$out/$name.log" 2>&1; then
    echo "PASS: onboarding $name"
  else
    echo "FAIL: onboarding $name"
    cat "$out/$name.log"
    failures=$((failures + 1))
  fi
}

first_run() {
  docker run --rm --network none --user 19876:19876 "$image" > "$out/first-run.txt" 2>&1 &&
    grep -q 'demo-ok: 8/8 verifications hold' "$out/first-run.txt" || {
      cat "$out/first-run.txt"; return 1;
    }
}

hands_on() {
  docker run --rm --network none --user 19876:19876 "$image" shell sh -ec '
    haskoki-ctl --version
    pkcs11-check version
    pkcs11-tool --module "$HASKOKI_MODULE" --list-slots
    pkcs11-tool --module "$HASKOKI_MODULE" --login --pin 1234 \
      --keypairgen --key-type EC:prime256v1 --label my-key --usage-sign
    printf "hello from Haskoki" > message.txt
    pkcs11-tool --module "$HASKOKI_MODULE" --login --pin 1234 \
      --sign --mechanism ECDSA-SHA256 --label my-key --type privkey \
      --input-file message.txt --output-file signature.bin
    test "$(wc -c < signature.bin)" -eq 64
    pkcs11-tool --module "$HASKOKI_MODULE" --login --pin 1234 \
      --verify --mechanism ECDSA-SHA256 --label my-key --type pubkey \
      --input-file message.txt --signature-file signature.bin
    printf "a different message" > changed.txt
    if pkcs11-tool --module "$HASKOKI_MODULE" --login --pin 1234 \
      --verify --mechanism ECDSA-SHA256 --label my-key --type pubkey \
      --input-file changed.txt --signature-file signature.bin; then
      echo "Changed message incorrectly verified" >&2; exit 1
    fi
    printf abc > abc.txt
    pkcs11-tool --module "$HASKOKI_MODULE" --hash --mechanism SHA256 \
      --input-file abc.txt --output-file digest.bin
    test "$(od -An -tx1 digest.bin | tr -d " \n")" = \
      ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
  '
}

p11_kit() {
  docker run --rm --network none --user 19876:19876 "$image" p11-kit-demo \
    > "$out/p11-kit.txt" 2>&1 &&
    grep -q 'p11-kit-demo-ok:' "$out/p11-kit.txt" || {
      cat "$out/p11-kit.txt"; return 1;
    }
}

proxy() {
  docker run --rm --network none --user 19876:19876 "$image" proxy-demo \
    > "$out/proxy.txt" 2>&1 &&
    grep -q 'proxy-example-ok: 5/5 steps hold' "$out/proxy.txt" || {
      cat "$out/proxy.txt"; return 1;
    }
}

check first-run first_run
check hands-on hands_on
check p11-kit p11_kit
check proxy proxy
test "$failures" -eq 0
