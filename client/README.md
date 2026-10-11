# Haskell test client

This package loads a PKCS#11 module with `dlopen`, resolves its function
list, and exercises the C ABI from Haskell. It is a test client, excluded
from the release bundles.

From the repository root, `scripts/test-client.sh` builds and exercises the
client against Haskoki in the [developer environment](../docs/toolchain.md).
The script also runs as part of the full native gate driver.

## Commands

```text
haskoki-client <module.so> slots
haskoki-client <module.so> mechs [slot]
haskoki-client <module.so> digest <file>
haskoki-client <module.so> rand [n]
haskoki-client <module.so> hmac        # RFC 4231 test case 1
haskoki-client <module.so> aes         # AES-CBC-PAD round trip
haskoki-client <module.so> ec          # ECDSA P-256 sign/verify
haskoki-client <module.so> kdf         # SHA256-KDF derive
haskoki-client <module.so> roundtrip   # aes + hmac + ec + kdf
```

Token refusals produce a nonzero exit and a `CK_RV` name on stderr.

## Source and header

[Raw.hsc](src/Haskoki/Client/Raw.hsc) derives constants and struct layouts
with hsc2hs. [Client.hs](src/Haskoki/Client.hs) manages sessions, login,
templates, and crypto calls; [Main.hs](app/Main.hs) implements the CLI.

The public-domain [vendored header](vendor/pkcs11.h) is a byte-identical copy
of the root [PKCS#11 header](../spec/vendor/pkcs11.h), included so this
package's source archive is self-contained. Keep both copies synchronized
when the pinned header changes.
