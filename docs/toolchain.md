# Toolchain

Compilers, environments, and the reproducibility story. Versions are
frozen in [`toolchain.lock`](../toolchain.lock) and
[`cabal.project.freeze`](../cabal.project.freeze).

## Supported compilers

| Compiler | Status | Install |
|---|---|---|
| GHC 9.10.3 | supported | OS package (`apt install ghc cabal-install` on Ubuntu 26.04) or ghcup vanilla |

`haskoki.cabal` (`tested-with`), `cabal.project(.freeze)`, and
`Dockerfile` track the one supported compiler.

Minimum is GHC 9.10: the build treats `-Wincomplete-record-selectors`
(introduced in 9.10) as a fatal omission class, so older compilers
reject `haskoki.cabal`.

## Docker (default environment)

```sh
cd haskoki
HASKOKI_BUILD_USER=ubuntu
if [ "$(id -u)" != 1000 ]; then HASKOKI_BUILD_USER=haskoki-builder; fi
docker build --build-arg USERNAME="$HASKOKI_BUILD_USER" \
  --build-arg UID="$(id -u)" --build-arg GID="$(id -g)" \
  -t haskoki-dev:ghc-9.10.3 .
docker run --rm -v "$PWD:/work" -w /work haskoki-dev:ghc-9.10.3 cabal test all
```

The image carries Ubuntu 26.04, GHC 9.10.3 + cabal-install from apt,
the pinned OpenSSL prefix (next section), and prebuilt project deps
with the test suite baked passing, so a fresh machine needs only
Docker. Transfer it with `docker save` / `docker load` (see the
`Dockerfile` header). Scripts that drive the image honor
`HASKOKI_IMAGE` (default `haskoki-dev:ghc-9.10.3`).

Run these commands as a non-root host user. Matching the builder UID/GID
lets it write the bind-mounted checkout. On a non-1000 UID, the different
username is required too: the base image already has an `ubuntu` user,
and changing only the numeric build arguments does not change that user.

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

## OpenSSL provenance + maintenance contract

The project links one pinned libcrypto and ships no
system-libcrypto fallback (option C: keep the static link). Exact
pin values live in `toolchain.lock` (`[openssl]`); the values below
are restated from that lock for the release record.

- Source tarball:
  `https://github.com/openssl/openssl/releases/download/openssl-4.0.2/openssl-4.0.2.tar.gz`
- Tarball sha256:
  `736b467530f916737b7031310ccb21d8218c6229e61e8e160cd1d3458cd543a8`
  (checked on download by the `openssl-build` Docker stage before
  unpacking).
- Configure flags: `--prefix=/opt/openssl-4.0.2
  --openssldir=/opt/openssl-4.0.2/ssl --libdir=lib no-docs no-tests
  threads no-shared no-pinshared linux-x86_64` (see `Dockerfile`).
- Linked bytes: `libcrypto.a` from that build, statically linked
  into `lib/libhaskoki.so` (`haskoki.cabal` names the exact archive
  in both link stanzas); the pinned `legacy.so` provider module
  ships next to it (`lib/ossl-modules/legacy.so`, plus
  `lib/libcrypto.so.4` only on module-build layouts — see
  `scripts/make-release.sh`).
- License text: `licenses/openssl-LICENSE.txt` is byte-identical to
  the tarball's `LICENSE.txt` (compared at vendoring time; sha256
  `7d5450cb2d142651b8afa315b5f238efc805dad827d91ba367d8516bc9d49e7a`);
  every bundle carries it plus the generated `licenses/NOTICES.md`,
  the GHC distribution grant (`licenses/GHC-copyright`), and each
  Hackage-sourced lib's own `licenses/<pkg>-LICENSE`.

Validation scope (what ran and what did not):

- Upstream OpenSSL test suite: NOT run (`no-tests` in the
  configure flags; `make install_sw` only). No `make test` result
  is claimed for the pinned build.
- Tarball integrity: sha256 checked on download (Docker stage).
- Version identity: the engine refuses any libcrypto whose version
  string is not the pinned one
  (`src/Haskoki/Engine/OpenSSL4.hs`); the pinned CLI reports
  `OpenSSL 4.0.2 25 Aug 2026`.
- Crypto sanity: the engine proof vector `sha256("abc") =
  ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad`
  (exact value in the lock) plus the release smoke (real digest +
  legacy-cipher KAT) on every install test.

Advisory monitoring + rebuild ownership:

- Whoever cuts a release watches the OpenSSL 4.0.x security
  advisories (openssl-announce) from pin date to release date and
  records the check in the release evidence. (Owner to confirm the
  standing owner + cadence; until then the release manager owns it.)
- Any OpenSSL change — version bump, flag change, or rebuild from
  a different tarball — re-qualifies ALL binaries (full gates +
  drivers + install legs) under a NEW release identity (new
  version). Bytes are never swapped silently under a published
  version.

Provider-origin rule: shipped provider modules must resolve
inside the artifact, never host `/opt` (absent on install
hosts). Enforcement: `scripts/make-release.sh` fails the build
when `ldd` shows any `/opt` binding on the shipped provider files
(PROVIDER-ORIGIN check), and `scripts/test-release-install.sh`
re-checks inside-artifact bindings on a bare image in both legs.

## Pinned source-build recipe

Rebuilds the library, module, operator tool, and full test suite
from the `haskoki-<ver>.tar.gz` source archive (the verified sdist
shipped as a release asset). Two paths: the Docker builder (pinned
compiler + prefix, preferred) and a native host (same compiler +
a hand-built prefix). `cabal install haskoki` is NOT claimed to
work without the system prerequisites below.

### Path 1: Docker builder (preferred)

Prereqs: Docker + the builder image (`haskoki-dev:ghc-9.10.3`,
which carries GHC 9.10.3, cabal-install, the pinned
`/opt/openssl-4.0.2` prefix, and the frozen-plan inputs).

```sh
tar xzf haskoki-0.3.0.0.tar.gz
cd haskoki-0.3.0.0
printf 'packages: .\nallow-newer: all\n' > cabal.project
docker run --rm --network host -v "$PWD:/src" -w /src \
  haskoki-dev:ghc-9.10.3 sh -c 'cabal build all --enable-tests && cabal test all'
```

The unpacked tree carries `cabal.project.freeze`, which `cabal`
reads next to the created `cabal.project`; no Hackage re-resolution
happens (offline-safe once the image's package index is present).

Expected outputs: `cabal build all` exits 0; `cabal test all`
passes every suite (core 260/260, tests 2/2, storage 58/58,
engine 368/368, prop 58/58, model 1279/1279 — the locked counts;
see the verification log for the observed run).

### Path 2: native host (Ubuntu 26.04)

Prereqs: `sudo apt install ghc cabal-install build-essential
libgmp-dev` (GHC 9.10.3) plus the prefix below.

Prefix setup (how to obtain `/opt/openssl-4.0.2`):

```sh
curl -fsSLO https://github.com/openssl/openssl/releases/download/openssl-4.0.2/openssl-4.0.2.tar.gz
echo "736b467530f916737b7031310ccb21d8218c6229e61e8e160cd1d3458cd543a8  openssl-4.0.2.tar.gz" | sha256sum -c -
tar xzf openssl-4.0.2.tar.gz
cd openssl-4.0.2
perl ./Configure --prefix=/opt/openssl-4.0.2 \
  --openssldir=/opt/openssl-4.0.2/ssl --libdir=lib \
  no-docs no-tests threads no-shared no-pinshared linux-x86_64
make -j"$(nproc)"
sudo make install_sw
/opt/openssl-4.0.2/bin/openssl version
```

The last line must print `OpenSSL 4.0.2 25 Aug 2026`. Then, from
the unpacked source archive (same `cabal.project` line as path 1):

```sh
tar xzf haskoki-0.3.0.0.tar.gz
cd haskoki-0.3.0.0
printf 'packages: .\nallow-newer: all\n' > cabal.project
cabal update
cabal build all --enable-tests
cabal test all
```

Expected outputs: same suite counts as path 1.

### Hackage candidate (deferred)

Mechanics prepared, upload NOT performed (owner decision
pending): `cabal sdist` produces the candidate tarball, and the
candidate procedure is `cabal upload --candidate
dist-newstyle/sdist/haskoki-<ver>.tar.gz`. No upload was run for
this release.

## Troubleshooting

- `Missing (or bad) C library: crypto` at configure: the OpenSSL
  prefix is missing or mislaid — see "The OpenSSL prefix".
- `expected exactly one libhaskoki*.so` from `scripts/make-release.sh`:
  the script wants a tree built by exactly one compiler; build the
  release in the Docker image or a clean tree.
- `GHC drift: image wants 9.10.x` from `docker build`: the base
  image's OS GHC moved past 9.10; re-freeze for the new compiler
  before rebuilding.
