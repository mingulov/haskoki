# Try Haskoki

Start with the [README build steps](../README.md#quick-start-container-no-haskell-build).
They build a local image from the source and stage the bundle required
by `docker/Dockerfile.demo`. A bare demo-image build from a fresh clone
is missing that input. Once an image is published and anonymously
verified, the release notes will provide the pull command.

The examples below run from the checkout with a writable `out/`
directory. They use your UID so reports stay yours. Docker is the only
host-side runtime dependency.

## A small demo

```sh
mkdir -p out
docker run --rm --network none --user "$(id -u):$(id -g)" \
  -v "$PWD/out:/out" haskoki-demo:0.3.0.0 demo
```

Watch for successful slot discovery, an EC signature verification,
the SHA-256 digest, and an RSA-OAEP round trip. The final line is:

```text
demo-ok: 8/8 verifications hold; report: /out/demo-<run>/report.json
```

The host copy is `out/demo-<run>/report.json`, alongside the step logs.
Key, signature, and ciphertext bytes vary between runs. The digest and
the success conditions do not. Each invocation uses fresh stores and
public demo PINs; no real credentials are needed.

## Check through an external consumer

```sh
docker run --rm --network none --user "$(id -u):$(id -g)" \
  -v "$PWD/out:/out" haskoki-demo:0.3.0.0 \
  check --mode direct --profile smoke
```

The image contains [pkcs11-check](https://github.com/mingulov/pkcs11-check)
0.2.3 as a separate program. It loads the compiled module, checks its
environment, then runs the selected tests. Expect `check-ok: zero findings`
and a report under `out/check-direct-smoke-*/`. Allow a few minutes.

The smoke profile collects 743 tests, including skips and expected
failures. It is a quick check of discovery, slots, digests, and profiles,
not an independent audit or a standards certificate.

## Move the provider into a separate process

```sh
docker run --rm --network none --user "$(id -u):$(id -g)" \
  -v "$PWD/out:/out" --entrypoint /bin/sh haskoki-demo:0.3.0.0 \
  /opt/haskoki/examples/release/proxy-example
```

Expect `proxy-example-ok: 5/5 steps hold direct-vs-proxied`. It compares
slot discovery, EC key generation, signing, verification, and a digest:

```text
direct: client -> Haskoki module -> OpenSSL
proxy:  client -> proxy shim -> loopback -> proxy daemon -> Haskoki
```

[pkcs11-proxy-ng](https://github.com/mingulov/pkcs11-proxy-ng) v0.2.2
provides the shim and daemon. In this example both run in one container;
the daemon uses unauthenticated plaintext loopback. No port is published.
It demonstrates process placement, not a network deployment or transport
protection. Look under `out/proxy-example-*/` for the report and daemon log.

For the same checker smoke profile through the proxy, change
`--mode direct` to `--mode proxy` in the previous command.

## Longer checks and exit codes

`check --profile full` runs the larger offline selection. It currently
collected 10993 tests in the latest recorded CI run and reports 22 known findings in each mode, with
skips and expected failures counted separately. Expect exit 1. The
[results page](release-results.md) gives the exact counters and limits.
Allow tens of minutes; this is optional for a short demonstration.

`compare` runs both full modes and compares their outcomes. Raw differences
are expected; the image includes a classifier for 83 recorded exclusions
and 22 shared findings. Use the [full walkthrough](demo-walkthrough.md#11-container-image-proxy-example--compare-classifier)
if you need that investigation. Neither offline profile downloads vector
corpora; vector runs have their own [recipe](release-results.md#vector-data-runs-6).

| Exit | Meaning |
| --- | --- |
| 0 | The selected demo/check succeeded, with no findings or unexpected differences. |
| 1 | A verification failed, findings were reported, or comparison found differences. Read the report. |
| 2 | Invalid arguments or a setup problem, such as an unwritable output directory. |

Run `docker run --rm haskoki-demo:0.3.0.0 check --help` for options.
Re-running creates another report directory. Keep only reports you need;
the output directories also contain disposable demo stores.

## If something fails

- Image missing: finish the README's local build, including bundle staging.
  A GHCR tag in draft release notes does not establish availability.
- Output permission error: create `out/` yourself, mount it read-write,
  and use the UID/GID arguments above. A read-only mount cannot accept logs.
- Module fails to load on a native host: check [supported hosts](../SUPPORTED-HOSTS.md)
  and extract the whole bundle, including its runtime libraries.
- Checker findings: distinguish exit 1 from a broken run (exit 2); compare
  the report with the documented profile and tool versions.

For optional host-side observation, see the small
[p11scope note](p11scope-trace.md). It is not a demo dependency.
