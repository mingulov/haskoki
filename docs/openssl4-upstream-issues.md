# OpenSSL 4.0.2 limitations

Haskoki uses the pinned OpenSSL 4.0.2 build described in
[toolchain.lock](../toolchain.lock). These are implementation constraints
and downstream choices, not a list of filed upstream bugs.

## DSA parameter generation

Haskoki sets both p and q sizes explicitly rather than relying on the
provider's q-size default. The defaults are 1024/160, 2048/256, and
3072/256 bits; 2048/224 is honored when requested. See the DSA parameter
handling in [ossl4_ctx.c](../cbits/ossl4_ctx.c).

The seed-dependent `CKM_DSA_PROBABILISTIC_PARAMETER_GEN`,
`CKM_DSA_SHAWE_TAYLOR_PARAMETER_GEN`, and `CKM_DSA_FIPS_G_GEN` routes remain
unavailable in this backend. The [mechanism inventory](coverage.md)
records their reasons. This does not imply all DSA generation is unavailable.

## Other boundary choices

- The DSA raw-sign route enforces Haskoki's digest-length contract rather
  than relying on provider acceptance.
- AES-XTS accepts its defined key widths; there is no AES-192-XTS route.
- Equal XTS key halves are refused by the crypto provider.

Source and mechanism tests define these contracts. Passing crypto vectors
does not make Haskoki a FIPS-validated module; see the
[FIPS status](fips-compatibility.md).
