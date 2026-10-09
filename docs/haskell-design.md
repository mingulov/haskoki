# What Haskell contributes

Haskell makes the PKCS#11 rules visible as data and functions. The core
models sessions, objects, permissions, operation states, and output
decisions using owned values and distinct types. Planning a call and
finishing its result are separate from running native crypto:

```text
decoded call -> pure plan -> crypto effect -> pure finish -> publish
```

[`Transition.hs`](../core/Haskoki/Transition.hs) describes the planning
and finishing steps. [`CryptoEffect`](../core/Haskoki/Operation/Effect.hs)
records the requested work, and the
[engine driver](../src/Haskoki/Engine/Driver.hs) interprets it. The same
backend interface supports controlled synthetic tests and real OpenSSL
operations. The public C demo uses OpenSSL.

## Benefits in this codebase

- The private `haskoki-core` [Cabal component](../haskoki.cabal) depends
  on data libraries. Runtime, storage, and native bindings sit outside it.
  This keeps protocol tests usable without loading a native consumer.
- Distinct [handle types](../core/Haskoki/Types.hs) prevent mixing session,
  object, and resource IDs accidentally. [Output requests](../core/Haskoki/Request.hs)
  distinguish a size query from a supplied buffer.
- [Attribute values](../core/Haskoki/Attribute.hs) use `ByteString` for
  binary data and distinguish readable, sensitive, and unavailable values.
  [Byte-preservation tests](../tests/model/BytesSpec.hs) exercise that choice.
- The compiler rejects selected omissions, including incomplete patterns
  and missing record fields. [Delta properties](../tests/prop/DeltaProps.hs)
  and [streaming properties](../tests/prop/StreamProps.hs) then check behavior
  that types alone do not describe.

The separation also helps with failures. Async execution must finish or
repair a claimed job if its runner throws or is interrupted; the
[ownership tests](../tests/model/OwnershipSpec.hs) inject both cases.
Native digest contexts are borrowed under a registry lock while used;
their lifetime is a runtime responsibility, not a consequence of purity.

## Costs and limits

Loading the module also loads the GHC runtime. The release bundles its
runtime dependencies and keeps the runtime alive for the process lifetime.
The [host contract](../SUPPORTED-HOSTS.md) covers threading, loading, and
finalization. Async coordination uses STM and IO, and the FFI contains
substantial validation, admission, persistence, and delivery logic.

Some requests still carry generic byte payloads, and effect/result
compatibility still needs runtime checks. Native digest state cannot be
serialized into an operation snapshot. The
[core-boundary checker](../scripts/check-core-boundary.py) is a textual
guard, not a proof of purity or totality.

Haskell helps explain and maintain protocol behavior. It does not prove
PKCS#11 conformance, eliminate timing leaks, or make C and OpenSSL memory-safe.
That boundary still needs native tests and careful ownership.
See the [evidence levels](trust-ladder.md) and [current results](release-results.md).
