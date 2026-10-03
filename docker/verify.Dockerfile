# haskoki verification toolchain image (dual GHC + SMT/sanitizer/lint stack).
#
# Companion to the pinned build image (Dockerfile, GHC 9.10.3): the repo
# KEEPS building on 9.10.3; this image carries the verification-only
# toolchain from add_testing.md. Dual compiler by necessity, not taste:
# Liquid Haskell rides GHC 9.14.1 (single-GHC policy) while Stan
# (base<4.22) and Weeder (9.10-series HIE) must build under GHC 9.10.3.
# Heavyweight C provers (SAW/Crux) are a later layer, added only when a
# slice needs LLVM-level C proofs.
#
#   Build (from repo root):  docker build --network host -f docker/verify.Dockerfile -t haskoki-verify:ghc-9.14.1 .
#                            (host network: this environment's docker bridge DNS is broken)
#   Verify with repo mounted: docker run --rm --network host -v "$PWD:/work" -w /work haskoki-verify:ghc-9.14.1 \
#                               ghc -fplugin=LiquidHaskell src/Some/Module.hs
#
# Pinned versions are ARGs below; the final step prints every resolved
# version, and the hs-tools stage ends with a real Liquid Haskell smoke
# proof (a failed refinement fails the build).
ARG USERNAME=ubuntu
ARG UID=1000
ARG GID=1000
ARG GHC_MAIN=9.14.1
ARG GHC_REPO=9.10.3
ARG CABAL_VERSION=3.16.1.0
ARG Z3_VERSION=5.1.0
ARG Z3_SHA256=f47be8d27d3230e823bf1eeede2fe0abaca55bb78d0b59974370e6689a92284a
ARG CLANG_VERSION=1:21.1.8-6ubuntu1
ARG VALGRIND_VERSION=1:3.26.0-0ubuntu1
ARG HLINT_VERSION=3.10-2build1
ARG STAN_VERSION=0.2.1.0
ARG WEEDER_VERSION=2.11.0
ARG LH_VERSION=0.9.14.1.1

FROM ubuntu:26.04 AS ghcup-base
ARG USERNAME UID GID GHC_MAIN GHC_REPO CABAL_VERSION
ENV DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    BOOTSTRAP_HASKELL_NONINTERACTIVE=1 \
    BOOTSTRAP_HASKELL_MINIMAL=1 \
    GHCUP_INSTALL_BASE_PREFIX=/opt/ghcup
RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential curl ca-certificates libgmp-dev libnuma-dev \
      libffi-dev zlib1g-dev pkg-config git unzip \
    && rm -rf /var/lib/apt/lists/*
RUN curl --proto '=https' --tlsv1.2 -fsSL https://get-ghcup.haskell.org | bash
ENV PATH=/opt/ghcup/.ghcup/bin:$PATH
RUN ghcup install ghc "${GHC_MAIN}" --set \
    && ghcup install ghc "${GHC_REPO}" \
    && ghcup install cabal "${CABAL_VERSION}" --set
RUN ghc --numeric-version && ghc-9.10.3 --numeric-version \
    && cabal --numeric-version
# Non-root dev user (create only when the base image lacks it).
RUN if ! getent passwd "$USERNAME" >/dev/null; then \
      getent group "$GID" || groupadd -g "$GID" "$USERNAME"; \
      useradd -m -u "$UID" -g "$GID" -s /bin/bash "$USERNAME"; \
    fi

# Native verification tools: Clang 21 (ASan/UBSan/TSan/libFuzzer),
# Valgrind, HLint, Z3 (GitHub binary: apt z3=4.13.3 is below the 4.15.1
# floor Liquid Haskell requires).
FROM ghcup-base AS native-tools
ARG CLANG_VERSION VALGRIND_VERSION HLINT_VERSION Z3_VERSION Z3_SHA256
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      clang-21="${CLANG_VERSION}" libclang-rt-21-dev llvm-21 \
      libfuzzer-21-dev="${CLANG_VERSION}" \
      valgrind="${VALGRIND_VERSION}" hlint="${HLINT_VERSION}" \
    && rm -rf /var/lib/apt/lists/* \
    && clang-21 --version | head -1 && valgrind --version
RUN curl -fsSL -o /tmp/z3.zip "https://github.com/Z3Prover/z3/releases/download/z3-${Z3_VERSION}/z3-${Z3_VERSION}-x64-glibc-2.39.zip" \
    && echo "${Z3_SHA256}  /tmp/z3.zip" | sha256sum -c - \
    && unzip -q /tmp/z3.zip -d /opt && rm /tmp/z3.zip \
    && ln -s "/opt/z3-${Z3_VERSION}-x64-glibc-2.39" /opt/z3 \
    && /opt/z3/bin/z3 --version
ENV PATH=/opt/z3/bin:$PATH

# Haskell verification tools as the dev user (cabal store lands in the
# user's HOME so mounted-repo runs reuse it): Stan + Weeder under the
# repo-series compiler, Liquid Haskell under 9.14.1, then an LH smoke
# proof that fails the build unless refinement checking works end to end.
FROM native-tools AS hs-tools
ARG USERNAME UID GHC_MAIN GHC_REPO STAN_VERSION WEEDER_VERSION LH_VERSION
USER $USERNAME
ENV HOME=/home/$USERNAME \
    PATH=/home/$USERNAME/.local/bin:/opt/z3/bin:/opt/ghcup/.ghcup/bin:$PATH
RUN cabal update \
    && cabal install --with-compiler="ghc-${GHC_REPO}" \
         --installdir=/home/$USERNAME/.local/bin \
         "stan-${STAN_VERSION}" "weeder-${WEEDER_VERSION}" \
    && cabal install --with-compiler="ghc-${GHC_MAIN}" \
         --installdir=/home/$USERNAME/.local/bin \
         "liquidhaskell-${LH_VERSION}"
RUN stan --version && weeder --version
# LH smoke as a throwaway cabal project: bare ghc cannot see the
# cabal-installed plugin (store package db), but a project with
# liquidhaskell in build-depends resolves it — the same shape real
# module verification will use.
RUN mkdir -p /tmp/lhsmoke && cd /tmp/lhsmoke \
    && printf 'cabal-version: 3.0\nname: lhsmoke\nversion: 0.1.0.0\nbuild-type: Simple\n\nexecutable lhsmoke\n  main-is: Main.hs\n  build-depends: base, liquidhaskell\n  ghc-options: -fplugin=LiquidHaskell\n  default-language: Haskell2010\n' > lhsmoke.cabal \
    && printf '{-@ double :: Nat -> Nat @-}\ndouble :: Int -> Int\ndouble x = 2 * x\nmain :: IO ()\nmain = print (double 21)\n' > Main.hs \
    && cabal build exe:lhsmoke \
    && PLUGIN_OK=$(cabal exec -- ghc -fplugin=LiquidHaskell Main.hs -fno-code 2>&1 | grep -c "LIQUID: SAFE" || true) \
    && echo "LH smoke SAFE markers: $PLUGIN_OK" && test "$PLUGIN_OK" -ge 1

FROM hs-tools
ARG USERNAME
USER $USERNAME
ENV HOME=/home/$USERNAME
WORKDIR /work
RUN echo "=== haskoki-verify resolved versions ===" \
    && ghc --numeric-version && ghc-9.10.3 --numeric-version \
    && cabal --numeric-version \
    && clang-21 --version | head -1 && z3 --version && valgrind --version \
    && hlint --version && stan --version && weeder --version

CMD ["/bin/bash"]
