# haskoki toolchain image (default: GHC 9.10.3 from OS packages).
#
# Reproducible build/test environment, transferable to any Docker host:
# Ubuntu 26.04, GHC 9.10.3 + cabal-install from apt, pinned OpenSSL
# 4.0.2 libcrypto, project deps prebuilt.
#
#   Build (from this directory):  docker build -t haskoki-dev:ghc-9.10.3 .
#   Shell with repo mounted:      docker run --rm -it -v "$PWD:/work" -w /work haskoki-dev:ghc-9.10.3
#   Transfer to another machine:  docker save haskoki-dev:ghc-9.10.3 | zstd > haskoki-dev.tar.zst
#                                 (elsewhere) docker load < haskoki-dev.tar.zst
#
# Pinned versions live in toolchain.lock and in `tested-with`
# (haskoki.cabal); see docs/toolchain.md.
# 26.04 base already ships user ubuntu (1000:1000); defaults reuse it so
# bind-mounted files keep host ownership. For other ids pass e.g.
# --build-arg USERNAME=dev --build-arg UID=2000 --build-arg GID=2000.
ARG USERNAME=ubuntu
ARG UID=1000
ARG GID=1000
# Pinned libcrypto for the OpenSSL4 backend (see toolchain.lock
# [openssl]; haskoki.cabal hardcodes OPENSSL_PREFIX below because the
# .cabal format has no env substitution).
ARG OPENSSL_VERSION=4.0.2
ARG OPENSSL_SHA256=736b467530f916737b7031310ccb21d8218c6229e61e8e160cd1d3458cd543a8
ARG OPENSSL_PREFIX=/opt/openssl-4.0.2

# Pinned OpenSSL 4.0.2 (libcrypto for the OpenSSL4 backend).
FROM ubuntu:26.04 AS openssl-build
ARG OPENSSL_VERSION OPENSSL_SHA256 OPENSSL_PREFIX
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential perl ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /tmp/ossl-build
RUN curl -fsSLO "https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz" \
 && echo "${OPENSSL_SHA256}  openssl-${OPENSSL_VERSION}.tar.gz" | sha256sum -c - \
 && tar xzf "openssl-${OPENSSL_VERSION}.tar.gz" \
 && cd "openssl-${OPENSSL_VERSION}" \
 && perl ./Configure --prefix="${OPENSSL_PREFIX}" --openssldir="${OPENSSL_PREFIX}/ssl" \
      --libdir=lib no-docs no-tests threads no-shared no-pinshared linux-x86_64 \
 && make -j"$(nproc)" \
 && make install_sw \
 && rm -rf /tmp/ossl-build/openssl-${OPENSSL_VERSION} \
 && "${OPENSSL_PREFIX}/bin/openssl" version

FROM ubuntu:26.04

ARG USERNAME
ARG UID
ARG GID

ENV DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8

# System deps: OS Haskell toolchain + C toolchain for cbits/direct-sqlite.
# The frozen build plan (cabal.project.freeze) pins base-4.20.x, so the
# image refuses an archive drift past GHC 9.10 with a loud error.
RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential ghc cabal-install libgmp-dev git \
    && rm -rf /var/lib/apt/lists/* \
    && ghc --numeric-version && cabal --numeric-version \
    && if ! ghc --numeric-version | grep -q '^9\.10\.'; then \
         echo "GHC drift: image wants 9.10.x (see docs/toolchain.md)" >&2; \
         exit 1; \
       fi

# Non-root dev user (create only when the base image lacks it).
RUN if ! getent passwd "$USERNAME" >/dev/null; then \
      getent group "$GID" || groupadd -g "$GID" "$USERNAME"; \
      useradd -m -u "$UID" -g "$GID" -s /bin/bash "$USERNAME"; \
    fi
USER $USERNAME
ENV HOME=/home/$USERNAME
WORKDIR /home/$USERNAME

# Pinned libcrypto prefix for the OpenSSL4 backend build.
COPY --from=openssl-build /opt/openssl-4.0.2 /opt/openssl-4.0.2
ENV OPENSSL4_PREFIX=/opt/openssl-4.0.2

# Project layer: copy the package, fetch Hackage index, build + test so the
# image carries compiled deps and works offline on the next machine.
WORKDIR /work
COPY --chown=$UID:$GID haskoki.cabal cabal.project cabal.project.freeze Setup.hs ./
COPY --chown=$UID:$GID toolchain.lock toolchain.lock
COPY --chown=$UID:$GID README.md CHANGELOG.md LICENSE ./
COPY --chown=$UID:$GID licenses/ licenses/
COPY --chown=$UID:$GID src/ src/
COPY --chown=$UID:$GID core/ core/
COPY --chown=$UID:$GID ffi/ ffi/
COPY --chown=$UID:$GID cbits/ cbits/
COPY --chown=$UID:$GID test/ test/
COPY --chown=$UID:$GID tests/ tests/
COPY --chown=$UID:$GID spec/ spec/
COPY --chown=$UID:$GID scripts/ scripts/
COPY --chown=$UID:$GID app/ app/
COPY --chown=$UID:$GID tools/ tools/
COPY --chown=$UID:$GID docs/ docs/
COPY --chown=$UID:$GID client/ client/
# Build before testing: a fresh `cabal test all` can run haskoki-core-tests
# before the sibling main library unit registers (Cabal-9341); the
# explicit build first is the same workaround scripts/run-gates.sh uses.
RUN cabal update && cabal build all --enable-tests && cabal test all

CMD ["/bin/bash"]
