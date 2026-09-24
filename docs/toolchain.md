# Toolchain

Compilers, environments, and the reproducibility story. Versions are
frozen in [`toolchain.lock`](../toolchain.lock) and
[`cabal.project.freeze`](../cabal.project.freeze).

## Supported compilers

| Compiler | Status | Install |
|---|---|---|
| GHC 9.10.3 | default | OS package (`apt install ghc cabal-install` on Ubuntu 26.04) or ghcup vanilla |
| GHC 10.0.1-alpha1 (snapshot 10.0.0.20260917) | alternative | ghcup `prereleases` channel (see below) |

`haskoki.cabal` (`tested-with`), `cabal.project(.freeze)`, and
`Dockerfile` track the default compiler. The alternative lives in
`cabal.project.ghc10alpha(.freeze)` and `Dockerfile.ghc10alpha`.

Minimum is GHC 9.10: the build treats `-Wincomplete-record-selectors`
(introduced in 9.10) as a fatal omission class, so older compilers
reject `haskoki.cabal`.

## Docker (default environment)

```sh
cd haskoki
docker build -t haskoki-dev:ghc-9.10.3 .
docker run --rm -v "$PWD:/work" -w /work haskoki-dev:ghc-9.10.3 cabal test all
```

The image carries Ubuntu 26.04, GHC 9.10.3 + cabal-install from apt,
the pinned OpenSSL prefix (next section), and prebuilt project deps
with the test suite baked passing, so a fresh machine needs only
Docker. Transfer it with `docker save` / `docker load` (see the
`Dockerfile` header). Scripts that drive the image honor
`HASKOKI_IMAGE` (default `haskoki-dev:ghc-9.10.3`).

## Native setup (Ubuntu 26.04)

```sh
sudo apt install ghc cabal-install build-essential libgmp-dev
cabal update
cabal test all
```

This needs the OpenSSL prefix below. When the prefix uses the
`lib64` + shared-object layout instead of the expected `lib/`
static-only layout (see below), point the build at a staged prefix:

```sh
mkdir -p /tmp/ossl4-stage/lib
ln -s /opt/openssl-4.0.2/lib64/libcrypto.a /tmp/ossl4-stage/lib/libcrypto.a
ln -s /opt/openssl-4.0.2/include /tmp/ossl4-stage/include
printf 'extra-lib-dirs: /tmp/ossl4-stage/lib\nextra-include-dirs: /tmp/ossl4-stage/include\n' \
  > cabal.project.local   # git-ignored; never commit
cabal test all
```

## The OpenSSL prefix

`haskoki.cabal` links `libcrypto` from `/opt/openssl-4.0.2` with no
env substitution (the `.cabal` format has none), include dir
`/opt/openssl-4.0.2/include` and lib dir `/opt/openssl-4.0.2/lib`.
The expected layout is static-only (`libcrypto.a`, no shared
objects): the release gate refuses any dynamic libcrypto in the
module closure, and a shared `libcrypto.so` next to the archive
would link dynamically by default.

Build the prefix from source with the flags in
`toolchain.lock` (`[openssl]`), summarized:

```sh
perl ./Configure --prefix=/opt/openssl-4.0.2 \
  --openssldir=/opt/openssl-4.0.2/ssl --libdir=lib \
  no-docs no-tests threads no-shared no-pinshared linux-x86_64
make -j"$(nproc)" && make install_sw
```

Verify the tarball SHA-256 and the `OpenSSL 4.0.2 25 Aug 2026`
version string (exact values in `toolchain.lock`).

## Reproducibility

- `cabal.project.freeze` pins every package version plus the Hackage
  `index-state`; `cabal.project` only relaxes bounds
  (`allow-newer: all`) for re-resolution.
- Re-freeze with `cabal freeze`, then run the full suite before
  committing the result.
- `toolchain.lock` records the image, compiler, boot libraries,
  Hackage pins, OpenSSL build, and loader-proof facts. The release
  builder checksums it into every artifact (`toolchain-record.txt`).

## Alternative toolchain (GHC 10 alpha)

```sh
ghcup -s prereleases install ghc 10.0.0.20260917 --set
ghcup install cabal 3.18.1.0 --set
cabal build --project-file=cabal.project.ghc10alpha
```

or build `Dockerfile.ghc10alpha` (tag
`haskoki-dev:ghc-10.0.0.20260917`), which renames the alpha project
files into place before the baked test run.

## Troubleshooting

- `Missing (or bad) C library: crypto` at configure: the OpenSSL
  prefix is missing or mislaid — see "The OpenSSL prefix".
- `expected exactly one libhaskoki*.so` from `scripts/make-release.sh`:
  the script wants a tree built by exactly one compiler; build the
  release in the Docker image or a clean tree.
- `GHC drift: image wants 9.10.x` from `docker build`: the base
  image's OS GHC moved past 9.10; re-freeze for the new compiler
  before rebuilding.
