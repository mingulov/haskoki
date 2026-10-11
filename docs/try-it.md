# Try Haskoki

These instructions target the v0.3.1.0 candidate described in the
[README](../README.md#try-it-with-docker). You need Docker running on the
tested Linux amd64 platform. No Haskell setup or hardware token is needed.

## Run the demo and keep its output

The README's one-command demo is disposable. To keep reports and example
files, use a writable directory on your machine (Linux shell):

```sh
HASKOKI_IMAGE=ghcr.io/mingulov/haskoki-demo:v0.3.1.0
mkdir -p out
docker run --rm --network none --user "$(id -u):$(id -g)" \
  -v "$PWD/out:/out" "$HASKOKI_IMAGE" demo
```

Expect `demo-ok: 8/8 verifications hold`. Open `out/demo-*/report.json` for
the result; the same directory contains the messages, signatures, and logs.
Each run creates fresh keys and a new directory. The demo PINs are public
fixtures: user `1234`, security officer `5678`.

A **signature** lets a public key check that a message was signed with the
matching private key. It does not hide the message. **Encryption** hides
its contents; decryption recovers them. A **digest** is a fixed-size
fingerprint of the input. The demo exercises all three.

## Try pkcs11-tool yourself

Open a prepared shell. It creates a fresh token store, sets the module and
configuration paths, and puts the included tools on `PATH`:

```sh
HASKOKI_IMAGE=ghcr.io/mingulov/haskoki-demo:v0.3.1.0
mkdir -p out
docker run --rm -it --network none --user "$(id -u):$(id -g)" \
  -v "$PWD/out:/out" "$HASKOKI_IMAGE" shell
```

Paste these commands **inside that shell**, in order. `--module` chooses
Haskoki; `--login --pin 1234` unlocks the disposable demo token.

```sh
# See the token, then create one EC key pair for signing.
pkcs11-tool --module "$HASKOKI_MODULE" --list-slots
pkcs11-tool --module "$HASKOKI_MODULE" --login --pin 1234 \
  --keypairgen --key-type EC:prime256v1 --label my-key --usage-sign

# Sign a message with the private key.
printf 'hello from Haskoki' > message.txt
pkcs11-tool --module "$HASKOKI_MODULE" --login --pin 1234 \
  --sign --mechanism ECDSA-SHA256 --label my-key --type privkey \
  --input-file message.txt --output-file signature.bin

# Check the signature with the public key.
pkcs11-tool --module "$HASKOKI_MODULE" --login --pin 1234 \
  --verify --mechanism ECDSA-SHA256 --label my-key --type pubkey \
  --input-file message.txt --signature-file signature.bin
```

Expect `Signature is valid`. Change the message and repeat the verification:
it must fail. That is the useful part of a signature. To inspect your keys,
run `pkcs11-tool --module "$HASKOKI_MODULE" --login --pin 1234 --list-objects`.
Type `exit` when finished.

Each shell starts a fresh store. With the mount above, its files remain in
`out/session-*/`; without a mount they disappear with the container. To
reuse one saved token, pass its printed configuration path on the next run:

```sh
# Replace XXXXXXXX with the session directory you want to reuse.
docker run --rm -it --network none --user "$(id -u):$(id -g)" \
  -v "$PWD/out:/out" -e HASKOKI_CONFIG=/out/session-XXXXXXXX/backend.toml \
  "$HASKOKI_IMAGE" shell
```

The store contains disposable private keys in plaintext. Stop its clients
before reusing it. Keep one key pair in this introductory exercise: some
OpenSC operations select the first matching key. Start a new shell for a
fresh experiment.

## Check the token

Back in your **host terminal**, run the bundled external checker:

```sh
docker run --rm --network none "$HASKOKI_IMAGE" check --mode direct --profile smoke
```

Expect `check-ok: zero findings`; allow a few minutes. The pinned
`pkcs11-check` 0.2.3 smoke profile collects 743 cases, including skipped and
expected-failure cases. It is not 743 passing tests or a certification.
Add the output mount from the first command to retain its detailed reports.

## Try another process

These are two independent, optional routes to the same token:

```sh
docker run --rm --network none "$HASKOKI_IMAGE" proxy-demo
docker run --rm --network none "$HASKOKI_IMAGE" p11-kit-demo
```

| Route | What happens | Success marker |
| --- | --- | --- |
| pkcs11-proxy-ng | Its client shim talks to its daemon over loopback; the example compares five operations with direct loading. | `proxy-example-ok: 5/5 steps hold` |
| p11-kit | `pkcs11-tool` loads `p11-kit-client.so`, which talks over a local Unix socket to a process loading Haskoki. | `p11-kit-demo-ok: 7/7 checks hold` |

The p11-kit example performs key generation, signing, verification, and a
known digest check. It also rejects a changed message and checks that the
token disappears and digesting fails after the server stops. It needs no
pkcs11-proxy-ng service.
The [small script](../examples/release/p11-kit-example) shows the server and
client commands; [upstream remoting documentation](https://p11-glue.github.io/p11-glue/p11-kit/manual/remoting.html)
explains forwarding. This demo checks those basic operations only, not the
full PKCS#11 3.x remoting surface.

Both examples stay inside one container with no published port. The proxy
uses unauthenticated plaintext loopback; the p11-kit example uses a private
local socket. Neither recipe configures a remote production service.

## Image contents and size

The image carries the Haskoki module and control tool, GHC runtime,
OpenSSL libraries, OpenSC `pkcs11-tool`, Python with `pkcs11-check` 0.2.3,
`pkcs11-proxy-ng` v0.2.2, p11-kit server/client, and the example scripts.
Compilers and build caches belong to the separate developer image.
p11scope is an optional host-side observer, not an image dependency.

For scale, the published **v0.3.0.0** image is **112.45 MiB compressed**
(sum of registry layers) and **341.97 MiB unpacked** (`docker inspect .Size`
in its [GitHub build](https://github.com/mingulov/haskoki/actions/runs/37961585654/job/113928599520)).
Those are different measurements, not extra amounts to add together. An
[October 11 v0.3.1.0 candidate build](https://github.com/mingulov/haskoki/actions/runs/38125091547/job/114430294809)
measured **346.66 MiB unpacked**, about 4.68 MiB (1.4%) more with this patch.
Each build records its size in the GitHub `demo-image-build` job. Actual disk
use also depends on shared Docker layers and retained reports.

Everything needed above is included. Larger vector-test collections are
optional downloads; see [results](release-results.md#vector-data-runs-6).
For provenance, the release manifest records the image digest. Locally:

```sh
docker image inspect "$HASKOKI_IMAGE" --format '{{.Size}} bytes; {{json .RepoDigests}}'
```

## When something fails

- **Image unavailable:** check that the selected version is published on
  [GitHub Releases](https://github.com/mingulov/haskoki/releases). A source
  branch preparing a release does not create its GHCR tag.
- **Docker unavailable:** start Docker and check `docker version`. A registry
  download needs network access; `--network none` isolates the running demo.
- **Wrong architecture:** this image is Linux amd64. Docker Desktop or ARM
  emulation may provide that environment, but those paths are unqualified.
- **Output permission denied:** create `out` yourself and use the UID/GID
  arguments shown above. A read-only mount cannot hold reports.
- **Attribute warnings:** OpenSC may report `CKR_ATTRIBUTE_TYPE_INVALID`
  while inspecting `LOCAL`, `DERIVE`, `VERIFY_RECOVER`, or
  `ALWAYS_AUTHENTICATE`. These are current attribute-reporting limitations;
  key generation and signature verification must still succeed.
- **A command reports findings:** exit 1 means a check failed; exit 2 means
  invalid arguments or setup trouble. Keep the report and logs. A shell
  command returns that tool's own exit code.

The optional `check --mode direct --profile full`, proxy full profile, and
`compare` take much longer and intentionally exit 1 for documented findings.
Read [the results](release-results.md) before using them. The short demo
and smoke checks should exit 0. Share logs when reporting a problem, but
omit token databases, keys, and credentials.
