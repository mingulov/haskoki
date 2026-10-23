# Firefox with a Haskoki client certificate

This example puts a real Firefox desktop in a disposable container. Firefox
loads a pinned native p11-kit client; a second container runs Haskoki's p11-kit
server with its stock OpenSC spy recording calls to Haskoki. A local nginx
HTTPS site requires the token's client certificate. The EC P-256 private key is
generated in Haskoki and is never imported into Firefox's internal key store.

The companion builds p11-kit client **0.26.2** from the official release, with
source SHA-256
`09fd9f44da4813a3141e73d5e7cf7008e5660d0405f13d56c15e1da9dcecf828`, to match the
server inside the pinned Haskoki image. Debian's installed p11-kit 0.25.5 tools
remain available, but their client module is not used: its older encoding of
parameterless mechanisms is incompatible with this server. The standalone
client and upstream `COPYING` are under `/opt/haskoki-p11-kit/` in the companion
image. No Haskoki core changes are required.

## Run the desktop

Use Linux amd64, Docker, Python 3.8 or newer, and a checkout of this repository. Initial
setup downloads the token image and builds a Debian trixie companion image
with Firefox ESR, NSS tools, the matching p11-kit client, nginx, Xvfb and noVNC. Package
versions and both Docker image identities are saved for each run. No host
browser, Haskell tools, NSS installation or host CA changes are needed.

Run from the repository root, choosing an output directory that does not exist:

```sh
mkdir -p out
python3 examples/firefox/demo.py start --out 'out/Firefox käyttäjä' --port 6080
```

The parent directory must already exist. The launcher creates the output
directory with mode 0700. It prints
a URL such as `http://127.0.0.1:6080/vnc.html?autoconnect=1&resize=scale`, the demo
PIN **1234**, and the exact stop command. Open that URL in your host browser.
Inside the desktop, Firefox visits `https://localhost:8443/`. This HTTPS port
exists inside the browser container; only the noVNC desktop port is published
to the host, bound to 127.0.0.1.

Enter PIN 1234 when Firefox asks to authenticate to `haskoki-demo`. Select
`Haskoki Firefox demo` when asked for a client certificate. Manual mode uses
Firefox's **Ask Every Time** certificate preference. The accepted page reports `verify=SUCCESS`, `subject=CN=Haskoki Firefox demo`, the peer's
SHA-1 certificate fingerprint, and the negotiated TLS version. The fingerprint
is SHA-1 because that is nginx's `$ssl_client_fingerprint` format; the full
client certificate SHA-256 fingerprint is separately saved in the artifacts.

Firefox may cache the PIN, selected certificate and TLS sessions. The **Remember this decision**
setting can suppress the chooser during a session or for longer. Opening a new tab is not a fresh
handshake test. Use a new run/profile to repeat the first-use prompts.

Inspect the token through Firefox Settings → Privacy & Security → Certificates
→ **Security Devices**: expand **Haskoki demo** and select `haskoki-demo`.
**View Certificates** → **Your Certificates** shows `Haskoki Firefox demo`.
The key's public half and matching leaf certificate are also retained as
`client-public.der`, `client.der` and `client.pem`; `spki-match.txt` records their
identical public-key hashes. Client certificate subject/issuer/serial metadata
come from real certificate DER when OpenSC imports it into Haskoki.

Stop with the printed command, or:

```sh
python3 examples/firefox/demo.py stop --out 'out/Firefox käyttäjä'
```

Stop validates both container ownership labels and the `/out` mount before
removing containers by immutable Docker ID. It saves container logs and keeps the output directory.
It never stops unrelated containers. Repeating stop is allowed. Startup or
test failure also attempts this owned cleanup.

## Run the real-browser acceptance test

Use a fresh output path. If an interactive desktop is using port 6080, choose a
different loopback desktop port:

```sh
python3 examples/firefox/demo.py test --out 'out/Firefox testi' --port 6081
```

This launches actual Firefox with its local Marionette protocol enabled. The
small client uses Python's standard library; no geckodriver or Selenium is
installed. It checks module identity, rejects PIN 0000 through the real Firefox
PIN dialog and requires `CKR_PIN_INCORRECT` in the spy log, then accepts PIN
1234. It identifies the exact token certificate by SHA-256 fingerprint and
`USER_CERT` type, requires NSS's internal store to contain no private keys,
and navigates to nginx with client authentication.

Success requires the expected verified peer subject and fingerprint plus a
successful nonempty token `C_Sign` or multipart `C_SignFinal` call. The test then closes Firefox, stops the token
container, creates another fresh Firefox profile/process and visits the same
site. That control must show nginx's specific missing-client-certificate 400
response and a corresponding `NONE` entry in the server access log. An
arbitrary navigation failure does not pass. `report.json` has `passed: true`
only after all these checks; any failure exits the launcher nonzero. Tests stop
their owned containers automatically and retain evidence.

To qualify a different locally built token image, pass its exact reference explicitly:

```sh
python3 examples/firefox/demo.py test --out 'out/Firefox candidate' --port 6081 \
  --token-image YOUR_EXACT_CANDIDATE_IMAGE
```

The override is recorded in `state.json`, `token-image.json` and `report.json`.
It does not turn candidate results into qualification of the published digest.
The default token image is pinned to
`ghcr.io/mingulov/haskoki-demo@sha256:2e0b73aacce0357fd8292608f1ac45cd8b81b6e3cf14c4dadba877c1fc801406`.

## Artifacts and tested boundary

The run directory contains the Haskoki SQLite store under `session-*`, its
backend configuration, per-run CA/server keys and certificates, client
certificate and public key, `module.sha256`, `server-spy.sha256`,
`spki-match.txt`, `p11-kit-client.txt` (source and actual client hash), installed package
versions, image inspection records, NSS inventories, service/browser logs,
`pkcs11-spy.log`, and the fresh Firefox profile(s). Tests also retain
`report.json`, authenticated and native manager screenshots on success, and a desktop screenshot
on browser failure when available. `state.json` names the owned containers and
records the requested image. The spy contains the public fixture PIN and
signing inputs; use only disposable data. The demo store is not encrypted at
rest. Nothing changes host trust or a personal Firefox profile.

On 2026-10-23 the companion image used Firefox ESR `153.5.1esr-1~deb13u1`, NSS
`3.110-1+deb13u4`, the source-built p11-kit client `0.26.2`, nginx
`1.26.3-3+deb13u10`, and Debian OpenSC tools `0.26.1-2`. The stock token image
provided p11-kit server `0.26.2-2` and OpenSC spy `0.27.0~rc1-1`. The actual built
client SHA-256 was
`aaa9f29d8c95010803d06e2e78b18c4710bf744fde624fc4f2fd5f3a10ab3c2f`; the unchanged
published Haskoki module SHA-256 was
`d386a9743d40b48ecb96fa5ff616e1a48fba432c01c6e68bc5ccad3967f3768b`.
The real Firefox test passed wrong-PIN rejection, correct-PIN login, exact token
certificate identity, TLS 1.3 client authentication, a successful 64-byte
`C_SignFinal` in the server-side spy, visible Security Devices/Your Certificates
rows, and a fresh Firefox process/profile receiving nginx 400 with `NONE` after
the token stopped. NSS internal private-key inventories were empty before and
after authentication. Manual PIN entry and certificate selection also reached
the accepted page; loopback noVNC HTTP, WebSocket and RFB checks passed. The
focused Python checks passed 13 tests, and the existing demo-shard harness
passed 18 tests.

Qualification applies to the recorded image/module/client bytes and versions.
Other operating systems, architectures, host Firefox packages and browser
versions are unqualified. The companion source build does not qualify an
arbitrary distribution p11-kit client or an arbitrary candidate Haskoki image.
