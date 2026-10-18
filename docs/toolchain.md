# Building and testing Haskoki

The easiest development route is GitHub: open a pull request and CI builds
and tests the native bundle, source archive, and demo image. You can also
run **CI and Release** manually with **mode=build** on your branch. The
[publishing guide](publishing.md) explains the tested-image download and
separate release action. No local compiler build is needed for either route.

For using the demo, start with the [README](../README.md). The runtime demo
image and the larger developer image below have different purposes.

## Pinned environment

[toolchain.lock](../toolchain.lock) and
[cabal.project.freeze](../cabal.project.freeze) record GHC 9.10.3, OpenSSL
4.0.2, package versions, and the Hackage index state. The Cabal file uses
GHC 9.10 warning classes; older compilers are not supported.

The OpenSSL prefix must be `/opt/openssl-4.0.2`, with headers under `include`
and the static archive under `lib/libcrypto.a`. A shared library beside the
archive can change the link result; the release builder checks the module
closure. Bundled provider modules must resolve inside the artifact.

## Optional local Docker build

From a repository checkout, run as a non-root host user. This needs several
GB of disk space and network access to prepare the builder:

```sh
HASKOKI_BUILD_USER=ubuntu
if [ "$(id -u)" != 1000 ]; then HASKOKI_BUILD_USER=haskoki-builder; fi
docker build --build-arg USERNAME="$HASKOKI_BUILD_USER" \
  --build-arg UID="$(id -u)" --build-arg GID="$(id -g)" \
  -t haskoki-dev:ghc-9.10.3 .
docker run --rm -v "$PWD:/work" -w /work \
  haskoki-dev:ghc-9.10.3 \
  sh -c 'cabal build all --enable-tests && cabal test all'
```

The builder supplies Ubuntu 26.04, the compiler, Cabal, pinned OpenSSL, and
project dependencies. A non-1000 UID also needs the different username:
the base already contains `ubuntu`. Scripts that launch the builder honor
`HASKOKI_IMAGE`, defaulting to `haskoki-dev:ghc-9.10.3`.
Build before testing so Cabal registers the main library before running the
separate core test package.

## Optional native build on Ubuntu 26.04

Install GHC 9.10.3, Cabal, and build prerequisites, then prepare OpenSSL:

```sh
sudo apt-get install ghc cabal-install build-essential libgmp-dev
curl -fsSLO https://github.com/openssl/openssl/releases/download/openssl-4.0.2/openssl-4.0.2.tar.gz
echo '736b467530f916737b7031310ccb21d8218c6229e61e8e160cd1d3458cd543a8  openssl-4.0.2.tar.gz' | sha256sum -c -
tar -xzf openssl-4.0.2.tar.gz
(
  cd openssl-4.0.2
  perl ./Configure --prefix=/opt/openssl-4.0.2 \
    --openssldir=/opt/openssl-4.0.2/ssl --libdir=lib \
    no-docs no-tests threads no-shared no-pinshared linux-x86_64
  make -j"$(nproc)"
  sudo make install_sw
  /opt/openssl-4.0.2/bin/openssl version
)
```

The version must be `OpenSSL 4.0.2 25 Aug 2026`. The upstream OpenSSL test
suite is not run by this recipe (`no-tests`); Haskoki's engine and native
smoke checks exercise the resulting crypto build.

From the repository root:

```sh
cabal update
cabal build all --enable-tests
cabal test all
```

Use a clean prefix with the layout above. If an existing installation has
`lib64` or shared libraries, rebuild it with the pinned layout or supply an
isolated static prefix through a git-ignored `cabal.project.local`.

## Building a released source archive

Download `haskoki-<version>.tar.gz` from
[GitHub Releases](https://github.com/mingulov/haskoki/releases), with its
manifest and checksums. The archive contains the main package and seven test
suites; the separate test client ships its own source archive (below).
With the native prerequisites above, or a prepared developer image:

```sh
HASKOKI_VERSION=0.4.0.0  # latest published release
tar -xzf "haskoki-$HASKOKI_VERSION.tar.gz"
cd "haskoki-$HASKOKI_VERSION"
printf 'packages: .\nallow-newer: all\n' > cabal.project
cabal update
cabal build all --enable-tests
cabal test all
```

For the Docker route, replace the last three commands with:

```sh
docker run --rm -v "$PWD:/src" -w /src haskoki-dev:ghc-9.10.3 \
  sh -c 'cabal update && cabal build all --enable-tests && cabal test all'
```

The archive's freeze pins dependency resolution. GitHub's bundle job checks
source archives outside the checkout before release.

## Building the client source archive

The test client is not in the main archive. From the repository root, build
its own source archive (plain `cabal sdist` packages only the main package):

```sh
cabal sdist haskoki-client
```

Unpack `dist-newstyle/sdist/haskoki-client-<version>.tar.gz` outside the
checkout. The client archive carries no freeze file, so update the package
index before building:

```sh
HASKOKI_CLIENT_VERSION=$(grep -m1 '^version:' client/haskoki-client.cabal | awk '{print $2}')
tar -xzf "dist-newstyle/sdist/haskoki-client-$HASKOKI_CLIENT_VERSION.tar.gz" -C /tmp/sdist-client
cd "/tmp/sdist-client/haskoki-client-$HASKOKI_CLIENT_VERSION"
printf 'packages: .\nallow-newer: all\n' > cabal.project
cabal update
cabal build all --enable-tests
cabal test all
```

For the Docker route, replace the last three commands with:

```sh
docker run --rm -v "$PWD:/src" -w /src haskoki-dev:ghc-9.10.3 \
  sh -c 'cabal update && cabal build all --enable-tests && cabal test all'
```

## Packaging and maintenance

[scripts/make-release.sh](../scripts/make-release.sh) stages the native
bundle; [package-release.sh](../scripts/package-release.sh) creates its
archive; [test-release-install.sh](../scripts/test-release-install.sh)
requires that packaged archive and tests installation on bare images.
[run-gates.sh](../scripts/run-gates.sh) is the full contributor driver.
These commands build or launch containers; use GitHub when local resources
are limited.

Changing OpenSSL, compiler, or frozen dependencies requires rebuilding and
qualifying the artifacts under a new release identity. Release files include
toolchain records and component notices; see the [dependency inventory](dependency-inventory.md).

If Cabal reports a missing C library `crypto`, check the OpenSSL prefix. If
the release builder finds multiple `libhaskoki*.so` files, use a clean tree
with one compiler. Update the freeze and run the required checks before
committing a toolchain change.
