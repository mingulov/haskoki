# haskoki-client (test-only)

In-repo Haskell PKCS#11 client driver for the Haskoki token. It
`dlopen`s a module, resolves `C_GetFunctionList`, and drives the C ABI
through the resolved function list — a genuine foreign client proving
the advertised surface is usable outside the C consumers.

Test jig, not a shipped SDK: `scripts/make-release.sh` does not pack
this package. All struct offsets and constants come from the single
verbatim `spec/vendor/pkcs11.h` via hsc2hs.

## Layout

- `src/Haskoki/Client/Raw.hsc` — raw bindings: `dlopen`, function-list
  resolution, `foreign import ccall "dynamic"` wrappers, info-struct
  readers.
- `src/Haskoki/Client.hs` — small bracketed layer: sessions, login,
  templates, single-moves crypto, random.
- `app/Main.hs` — `haskoki-client` CLI.

## CLI

```
haskoki-client <module.so> slots
haskoki-client <module.so> mechs [slot]
haskoki-client <module.so> digest <file>
haskoki-client <module.so> rand [n]
haskoki-client <module.so> hmac        # RFC 4231 test case 1
haskoki-client <module.so> aes         # AES-CBC-PAD roundtrip
haskoki-client <module.so> ec          # ECDSA P-256 sign/verify
haskoki-client <module.so> kdf         # SHA256-KDF derive
haskoki-client <module.so> roundtrip   # aes + hmac + ec + kdf
```

Exit nonzero with the `CK_RV` name on stderr on any token refusal.
`scripts/test-client.sh` runs the CLI against the freshly built
`libhaskoki.so` and is part of `scripts/run-gates.sh`.
