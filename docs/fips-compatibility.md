# FIPS status

Haskoki has **no implemented or validated FIPS mode**. The demo uses its
pinned OpenSSL 4.0.2 build with the default and legacy providers, loaded by
`openBackend` in [OpenSSL4.hs](../src/Haskoki/Engine/OpenSSL4.hs).
Known-answer vectors check output bytes; they do not establish validation.

A future FIPS-provider integration would need a separately selected provider
and library context, explicit algorithm/property selection, startup checks
that refuse an unavailable provider, and qualification of the actual build
and operating environment. A mechanism allowlist alone would not provide
those properties.

For that work, start with OpenSSL's
[FIPS module documentation](https://docs.openssl.org/4.0/man7/fips_module/)
and the applicable module's
[NIST validation record](https://csrc.nist.gov/projects/cryptographic-module-validation-program/validated-modules/search).
Follow that module's Security Policy rather than assuming Haskoki's current
OpenSSL pin or Docker environment is covered.

The [dependency inventory](dependency-inventory.md) distinguishes Haskoki's
crypto build from OpenSSL copies used by client tools. There is no FIPS
configuration switch to enable in the current demo.
