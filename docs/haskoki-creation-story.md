# How Haskoki was created

Haskoki began as an experiment in making PKCS#11 development easier to
organize and test. PKCS#11 is the interface applications use to work with
keys on smart cards, hardware security modules, and software tokens. A
token needs to do the cryptography, remember who is logged in, decide
which keys a session may see, and handle callers that stop halfway through.

The idea was to describe those rules in Haskell, test the model on its
own, and then exercise the compiled module with ordinary client tools.
The aim was broad, explicit coverage of behavior, with mistakes easier
to find during development. The [coverage record](coverage.md) shows what
was actually tested.

## Starting small, then widening

The [changelog](../CHANGELOG.md) records the first scaffold on September
20, 2026: a shared library a C application could load, the right
function-table layouts, and a small SHA-256 example. Getting that boundary
right gave the rest of the work somewhere to land. The public repository
started with [an import on September 24](https://github.com/mingulov/haskoki/commit/2cd3f37).

Sessions, objects, key generation, signing, and encryption followed in
small steps. More ciphers, curves, and post-quantum algorithms widened the
crypto support; a coverage sweep reached 316 behavior-tested mechanisms
in a catalog of 464. Later work covered async jobs, notifications,
certificates, interrupted calls, and native resource lifetimes. The
[timeline](haskoki-creation-story-timeline.md) follows these stages.

Haskell helped separate decisions from effects. The model decides whether
a session may sign and what state should follow; the runtime asks OpenSSL
to perform the signature. Those decisions can be tested without a native
client. Distinct types also help keep handles and requests apart. The
[design note](haskell-design.md) shows the code; concurrency and native
resource handling still needed their own tests.

## The checker and the process boundary

[pkcs11-check](https://github.com/mingulov/pkcs11-check) exercised the module
from outside its own suites. Client calls exposed mistakes in templates,
errors, and advertised capabilities. An incorrectly advertised AES-GCM
message capability was withdrawn, for example. Release hardening reduced
the full demo-checker finding set from 27 to 22, and later work moved it
to 21; the remaining findings are [documented](release-results.md).

Direct loading also brought the whole GHC runtime and its shared
libraries into a third-party application's process: a substantial
footprint, with threading and lifetime behavior the client had to live
with. [pkcs11-proxy-ng](https://github.com/mingulov/pkcs11-proxy-ng) lets its
daemon load that stack while the application loads a PKCS#11 shim.
Reusing this transport avoided creating a custom client/daemon gRPC
system unrelated to the original token work.

Direct and proxied tests then helped find differences across that
boundary. The demo pins the tested v0.2.2 proxy and records exclusions
for calls it cannot forward. v0.3.1.0 also offers a basic p11-kit route
over a local socket; [Try Haskoki](try-it.md#try-another-process) explains both.

A side note: [p11scope](https://github.com/mingulov/p11scope) can observe
PKCS#11 calls on Linux. The [observer note](p11scope-trace.md) explains
that view. It is optional and runs separately from the demo image.

## Making it useful to someone else

Muse Code, Codex, and Claude agents helped implement and review the
project. Model tests, properties, C clients, and external checks exercised
different parts of it. Packaging became part of the work too: a relocatable
native bundle, a source archive built outside the checkout, and a Docker
image with the runtime and client tools included. The first tagged release,
[v0.3.0.0](https://github.com/mingulov/haskoki/releases/tag/v0.3.0.0),
was published on October 9 but never announced.

v0.3.1.0 followed on October 12 with shorter onboarding, a prepared
shell, and hands-on client examples. v0.4.0.0 followed on October 15
with the token provisioning lifecycle, stricter request checks, and
refreshed guides. v0.5.0.0 followed on October 19 as the first public release:
new private and secret keys default to unextractable, storage moves to
schema 3 with a migrate-once upgrade, and a 61-leg client portfolio
exercises the release.

Recorded calls through October 18, 2026, account for about **19.88
billion input-plus-output tokens**; **97.7% of input was cached**, mostly
repeated context reads. That is model usage, not generated-code volume,
a bill, or personal working hours. The [usage account](haskoki-creation-story-costing.md)
gives the model breakdown and the later phases.

To see the result, [try the Docker demo](../README.md#try-it-with-docker)
with disposable keys. Haskoki remains a demonstrator with unencrypted
storage and documented limits.
