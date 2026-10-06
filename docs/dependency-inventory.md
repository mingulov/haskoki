# Dependency/license inventory — demo image `haskoki-demo:0.3.0.0`

What the release image actually contains, per layer, with the
notice location for each component. Measured on the R8
candidate build unless noted. This document states facts and
points at texts; it makes no claim of legal compatibility
between any two licenses.

Haskoki itself: Apache-2.0 (`LICENSE`, `haskoki.cabal`
`license: Apache-2.0`, image label
`org.opencontainers.image.licenses="Apache-2.0"`). That label
names the project's license, not the whole image.

## Bundle tree (`/opt/haskoki/dist-release/haskoki-0.3.0.0/`)

Primary record: `licenses/NOTICES.md` inside the tree
(generated per build by `scripts/make-release.sh`) with full
texts beside it. Contents:

- Haskoki (`licenses/Haskoki-LICENSE`, copied from repo
  `LICENSE`): Apache-2.0.
- OpenSSL 4.0.2 libcrypto (`licenses/OpenSSL-LICENSE.txt`,
  copied from repo `licenses/openssl-LICENSE.txt`; tarball
  sha256 pinned in `toolchain.lock`): Apache-2.0, statically
  linked into `lib/libhaskoki.so`, plus the pinned provider
  files.
- GHC runtime closure (`lib/libHS*.so`, 24 libs):
  `licenses/GHC-copyright` (copied from the builder's
  `/usr/share/doc/ghc/copyright`, Ubuntu ghc 9.10.3). The
  grant states BSD-3-Clause for `Files: *`; per-file upstream
  texts beyond that grant are NOT separately shipped (their
  home is the GHC source tree, tag `ghc-9.10.3-release`).
- Hackage libs (`libHSdirect-sqlite-…`): each package's own
  license file shipped (`licenses/direct-sqlite-LICENSE`);
  the frozen plan is checksummed in `toolchain-record.txt`.
- Pinned PKCS#11 header (`smoke/include/pkcs11.h`): public
  domain (stated in the header itself).
- `bin/haskoki-ctl`: Haskell closure statically linked.
  Static attribution, component by component (dynamic
  NEEDED lists prove nothing here — they show system libs
  only): GHC libraries under the distribution grant above;
  `direct-sqlite` bindings under the MIT grant shipped as
  `licenses/direct-sqlite-LICENSE` (Copyright 2012 Irene
  Knapp; note the upstream `.cabal` declares BSD3 — the
  shipped file's text governs this artifact); and the SQLite
  amalgamation the bindings embed (275 `sqlite3_*` static
  symbols via `nm`, version string `3.45.0` — public domain,
  see Embedded components). Dynamically linked only against
  system libc/libm/libgmp/libffi/libnuma (verified
  `objdump` NEEDED, no `libHS*` entries). Those system libs
  are NOT shipped in the bundle; see OS packages below.
- `toolchain-record.txt`: compiler, git SHA/branch, freeze
  hashes, engine builds, per-artifact sha256.

## Proxy (`/opt/haskoki/proxy/`)

`pkcs11-proxy-ng` v0.2.0 (tag `v0.2.0`), built from source in
the image. Dual MIT/Apache-2.0; full texts ship as
`LICENSE-MIT` + `LICENSE-APACHE` beside the binaries (asserted
present by the Dockerfile runtime self-test). Source:
`https://github.com/mingulov/pkcs11-proxy-ng` at tag `v0.2.0`;
daemon/shim hashes in `docs/release-results/environment.json`.

## Checker venv (`/opt/p11c/`, Python 3.14.4)

34 distributions; license identifiers below come from
each `METADATA` (`License-Expression`, else `License:`,
else the `License :: OSI Approved` classifier). Most are
SPDX expressions; two rows keep their raw legacy metadata
text and are marked `(legacy text)` rather than normalized.
License texts ship inside the `*.dist-info` dirs per wheel
metadata (verified: `pkcs11-check` carries `licenses/`).

| Distribution | License |
|---|---|
| annotated_doc 0.0.5 | MIT |
| annotated_types 0.8.0 | MIT |
| asn1crypto 1.5.1 | MIT |
| cffi 2.1.1 | MIT-0 |
| cryptography 50.0.2 | Apache-2.0 OR BSD-3-Clause |
| execnet 2.1.2 | MIT |
| hypothesis 6.168.4 | MPL-2.0 |
| iniconfig 2.3.0 | MIT |
| markdown_it_py 4.2.0 | MIT (classifier) |
| mdurl 0.1.2 | MIT (classifier) |
| packaging 26.3 | Apache-2.0 OR BSD-2-Clause |
| pip 25.1.1 | MIT |
| pkcs11_check 0.2.3 | MIT OR Apache-2.0 |
| pluggy 1.6.0 | MIT |
| psutil 7.2.2 | BSD-3-Clause |
| py_cpuinfo2 10.1.1 | MIT |
| pycparser 3.0 | BSD-3-Clause |
| pydantic 2.13.5 | MIT |
| pydantic_core 2.46.5 | MIT |
| pydantic_settings 2.15.0 | MIT |
| pygments 2.21.0 | BSD-2-Clause |
| pytest 9.1.1 | MIT |
| pytest_benchmark 5.3.0 | BSD-2-Clause |
| pytest_reportlog 1.0.0 | MIT |
| pytest_timeout 2.4.0 | MIT |
| pytest_xdist 3.8.0 | MIT |
| python_dotenv 1.2.4 | BSD-3-Clause |
| rich 15.0.0 | MIT |
| shellingham 1.5.4 | ISC License (legacy text) |
| sortedcontainers 2.4.0 | Apache 2.0 (legacy text) |
| tomli 2.4.1 | MIT |
| typer 0.27.2 | MIT |
| typing_extensions 4.16.0 | PSF-2.0 |
| typing_inspection 0.4.4 | MIT |

Upstream for each distribution:
`https://pypi.org/project/<dist>/<version>/` (exact
project-page URL pattern; verified 2026-10-06:
`cryptography/50.0.2` and `pytest/9.1.1` both → 200).
Reproduce the set with `pip download` against
`/opt/p11c/freeze.txt`, written at image build time.

## OS packages and base image

Base: `ubuntu:26.04` @
`sha256:513c074113a871b51a8d16ab445c88779d6452d937a164fb5cc479f32668a41d`
(digest resolved at candidate build time; 87 `ii` packages).
The Dockerfile runtime stage installs `libgmp10 libffi8
libnuma1 opensc python3 ca-certificates`; `libgmp10` is
already in the base (no-op). Result: 110 installed, 23 added,
0 removed (method: `dpkg -l` name diff, `LC_ALL=C`, base
image vs candidate).

Every package's copyright file ships in-image at
`/usr/share/doc/<pkg>/copyright` (all 110 verified present).
The License column quotes the file's first `Files` stanza
(`Files: *` unless noted); `(prose)` = old-format file read
by hand. Upstream per package: the `Source` column names the
source package; `https://packages.ubuntu.com/search?keywords=<src>`
resolves each one (pattern verified 2026-10-06,
`keywords=libgmp10` → 200; suite `resolute`).

`libgmp10`'s in-image grant is `GPL-2+ or LGPL-3+`
(`Files: *`): it is consumed only as a dynamic OS package —
`libgmp.so.10` appears in the `objdump -p` NEEDED lists of
both `bin/haskoki-ctl` (with `libm/libc/libffi/libnuma`, no
`libHS*`) and `lib/libhaskoki.so` — never statically linked
into a shipped binary.

| Package | Version | Arch | Source | Layer | License (in-image copyright) |
|---|---|---|---|---|---|
| apt | 3.2.0 | amd64 | apt | base | GPL-2+ |
| base-files | 14ubuntu6.2 | amd64 | base-files | base | GPL-2+ |
| base-passwd | 3.6.8 | amd64 | base-passwd | base | GPL-2 |
| bash | 5.3-2ubuntu1 | amd64 | bash | base | GPL-3+ |
| bsdutils | 1:2.41.3-3ubuntu2.2 | amd64 | util-linux | base | GPL-2+ |
| ca-certificates | 20260601~26.04.1 | all | ca-certificates | added | MPL-2.0 (cert data) + GPL-2+ (packaging) |
| coreutils | 9.5-1ubuntu2+0.0.0~ubuntu25 | all | coreutils-from | base | GPL-3 |
| coreutils-from-uutils | 0.0.0~ubuntu25 | all | coreutils-from | base | GPL-3 |
| dash | 0.5.12-12ubuntu3 | amd64 | dash | base | BSD-3-Clause |
| debconf | 1.5.92 | all | debconf | base | BSD-2-clause |
| debianutils | 5.23.2build1 | amd64 | debianutils | base | GPL-2+ |
| diffutils | 1:3.12-1ubuntu0.1 | amd64 | diffutils | base | GPL-3+ |
| dpkg | 1.23.7ubuntu1 | amd64 | dpkg | base | GPL-2+ |
| e2fsprogs | 1.47.2-3ubuntu4 | amd64 | e2fsprogs | base | GPL-2 |
| findutils | 4.10.0-3build2 | amd64 | findutils | base | GFDL-NIV-1.3+ or GFDL-NIV-1.3+ as written (also GPL-3+ stanzas) |
| gcc-16-base | 16-20260322-1ubuntu1 | amd64 | gcc-16 | base | GPL-3+ w/ GCC Runtime Exception 3.1 (prose) |
| gnu-coreutils | 9.7-3ubuntu2.1 | amd64 | coreutils | base | GPL-3+ |
| gpgv | 2.4.8-4ubuntu3 | amd64 | gnupg2 | base | GPL-3+ |
| grep | 3.12-1 | amd64 | grep | base | GPL-3+ (multi-line Files list) |
| gzip | 1.14-1~exp2ubuntu1.1 | amd64 | gzip | base | GPL-3+ |
| hostname | 3.25build1 | amd64 | hostname | base | GPL-2 |
| init-system-helpers | 1.69 | all | init-system-helpers | base | BSD-3-clause |
| libacl1 | 2.3.2-2 | amd64 | acl | base | GPL-2+ (multi-line Files list) |
| libapt-pkg7.0 | 3.2.0 | amd64 | apt | base | GPL-2+ |
| libatomic1 | 16-20260322-1ubuntu1 | amd64 | gcc-16 | added | GPL-3+ w/ GCC Runtime Exception 3.1 (prose) |
| libattr1 | 1:2.5.2-4ubuntu0.1 | amd64 | attr | base | GPL-2+ (multi-line Files list) |
| libaudit-common | 1:4.1.2-1build1 | all | audit | base | GPL-2 |
| libaudit1 | 1:4.1.2-1build1 | amd64 | audit | base | GPL-2 |
| libblkid1 | 2.41.3-3ubuntu2.2 | amd64 | util-linux | base | GPL-2+ |
| libbsd0 | 0.12.2-2build2 | amd64 | libbsd | base | BSD-3-clause (multi-line Files list) |
| libbz2-1.0 | 1.0.8-6ubuntu0.1 | amd64 | bzip2 | base | BSD-variant |
| libc-bin | 2.43-2ubuntu2.3 | amd64 | glibc | base | LGPL-2.1+ |
| libc-gconv-modules-extra | 2.43-2ubuntu2.3 | amd64 | glibc | base | LGPL-2.1+ |
| libc6 | 2.43-2ubuntu2.3 | amd64 | glibc | base | LGPL-2.1+ |
| libcap-ng0 | 0.8.5-4build5 | amd64 | libcap-ng | base | LGPL-2.1+ |
| libcom-err2 | 1.47.2-3ubuntu4 | amd64 | e2fsprogs | base | GPL-2 |
| libcrypt1 | 1:4.5.1-1 | amd64 | libxcrypt | base | mixed BSD-3-clause / public-domain, per-file (prose) |
| libdb5.3t64 | 5.3.28+dfsg2-10ubuntu1 | amd64 | db5.3 | base | Sleepycat and BSD-3-clause |
| libdebconfclient0 | 0.280ubuntu1 | amd64 | cdebconf | base | BSD-2-Clause |
| libeac3 | 1.1.2+ds+git20220117+453c3d6b03a0-1.1build3 | amd64 | openpace | added | GPL-3+ |
| libexpat1 | 2.7.4-1ubuntu0.2 | amd64 | expat | added | MIT |
| libext2fs2t64 | 1.47.2-3ubuntu4 | amd64 | e2fsprogs | base | GPL-2 |
| libffi8 | 3.5.2-4 | amd64 | libffi | added | Expat |
| libgcc-s1 | 16-20260322-1ubuntu1 | amd64 | gcc-16 | base | GPL-3+ w/ GCC Runtime Exception 3.1 (prose) |
| libgcrypt20 | 1.12.0-2ubuntu1.1 | amd64 | libgcrypt20 | base | LGPLv2.1+ (library) |
| libglib2.0-0t64 | 2.88.0-1ubuntu0.1 | amd64 | glib2.0 | added | LGPL-2.1+ |
| libgmp10 | 2:6.3.0+dfsg-5ubuntu2 | amd64 | gmp | base | GPL-2+ or LGPL-3+ |
| libgpg-error0 | 1.58-2 | amd64 | libgpg-error | base | LGPL-2.1+ |
| liblz4-1 | 1.10.0-8 | amd64 | lz4 | base | GPL-2+ |
| liblzma5 | 5.8.3-1 | amd64 | xz-utils | base | 0BSD |
| libmd0 | 1.1.0-2build4 | amd64 | libmd | base | BSD-3-clause (multi-line Files list) |
| libmount1 | 2.41.3-3ubuntu2.2 | amd64 | util-linux | base | GPL-2+ |
| libncursesw6 | 6.6+20251231-1 | amd64 | ncurses | base | MIT/X11 |
| libnuma1 | 2.0.19-1build1 | amd64 | numactl | added | LGPL-2.1 for libnuma (prose) |
| libpam-modules | 1.7.0-5ubuntu3.2 | amd64 | pam | base | BSD-3-clause or GPL |
| libpam-modules-bin | 1.7.0-5ubuntu3.2 | amd64 | pam | base | BSD-3-clause or GPL |
| libpam-runtime | 1.7.0-5ubuntu3.2 | all | pam | base | BSD-3-clause or GPL |
| libpam0g | 1.7.0-5ubuntu3.2 | amd64 | pam | base | BSD-3-clause or GPL |
| libpcre2-8-0 | 10.46-1build1 | amd64 | pcre2 | base | BSD-3-clause-Cambridge with BINARY LIBRARY-LIKE PACKAGES exception |
| libproc2-0 | 2:4.0.4-9ubuntu1 | amd64 | procps | base | LGPL-2.1+ |
| libpython3-stdlib | 3.14.3-0ubuntu2 | amd64 | python3-defaults | added | PSF (prose) |
| libpython3.14-minimal | 3.14.4-1ubuntu0.2 | amd64 | python3.14 | added | PSF (prose block) |
| libpython3.14-stdlib | 3.14.4-1ubuntu0.2 | amd64 | python3.14 | added | PSF (prose block) |
| libreadline8t64 | 8.3-4 | amd64 | readline | added | GPL-3+ |
| libseccomp2 | 2.6.0-2ubuntu5 | amd64 | libseccomp | base | LGPL-2.1 |
| libselinux1 | 3.9-4build1 | amd64 | libselinux | base | public-domain |
| libsemanage-common | 3.9-1build1 | all | libsemanage | base | LGPL-2.1+ |
| libsemanage2 | 3.9-1build1 | amd64 | libsemanage | base | LGPL-2.1+ |
| libsepol2 | 3.9-2 | amd64 | libsepol | base | LGPL-2.1+ |
| libsmartcols1 | 2.41.3-3ubuntu2.2 | amd64 | util-linux | base | GPL-2+ |
| libsqlite3-0 | 3.46.1-9ubuntu0.3 | amd64 | sqlite3 | added | public-domain |
| libss2 | 1.47.2-3ubuntu4 | amd64 | e2fsprogs | base | GPL-2 |
| libssl3t64 | 3.5.5-1ubuntu3.7 | amd64 | openssl | base | Apache-2.0 |
| libstdc++6 | 16-20260322-1ubuntu1 | amd64 | gcc-16 | base | GPL-3+ w/ GCC Runtime Exception 3.1 (prose) |
| libsystemd0 | 259.5-0ubuntu3.4 | amd64 | systemd | base | LGPL-2.1+ |
| libtinfo6 | 6.6+20251231-1 | amd64 | ncurses | base | MIT/X11 |
| libudev1 | 259.5-0ubuntu3.4 | amd64 | systemd | base | LGPL-2.1+ |
| libuuid1 | 2.41.3-3ubuntu2.2 | amd64 | util-linux | base | GPL-2+ |
| libxxhash0 | 0.8.3-2build1 | amd64 | xxhash | base | BSD-2-clause |
| libzstd1 | 1.5.7+dfsg-3 | amd64 | libzstd | base | BSD-3-clause or GPL-2 |
| login | 1:4.16.0-2+really2.41.3-3ubuntu2.2 | amd64 | util-linux | base | GPL-2+ |
| login.defs | 1:4.17.4-2ubuntu3 | all | shadow | base | BSD-3-clause |
| logsave | 1.47.2-3ubuntu4 | amd64 | e2fsprogs | base | GPL-2 |
| mawk | 1.3.4.20260129-1 | amd64 | mawk | base | GPL-2.0-only |
| media-types | 14.0.0build1 | all | media-types | added | ad-hoc |
| mount | 2.41.3-3ubuntu2.2 | amd64 | util-linux | base | GPL-2+ |
| ncurses-base | 6.6+20251231-1 | all | ncurses | base | MIT/X11 |
| ncurses-bin | 6.6+20251231-1 | amd64 | ncurses | base | MIT/X11 |
| netbase | 6.5build1 | all | netbase | added | GPL-2 |
| opensc | 0.27.0~rc1-1 | amd64 | opensc | added | LGPL-2.1+ |
| opensc-pkcs11 | 0.27.0~rc1-1 | amd64 | opensc | added | LGPL-2.1+ |
| openssl | 3.5.5-1ubuntu3.7 | amd64 | openssl | added | Apache-2.0 |
| openssl-provider-legacy | 3.5.5-1ubuntu3.7 | amd64 | openssl | base | Apache-2.0 |
| passwd | 1:4.17.4-2ubuntu3 | amd64 | shadow | base | BSD-3-clause |
| perl-base | 5.40.1-7ubuntu0.1 | amd64 | perl | base | GPL-1+ or Artistic |
| procps | 2:4.0.4-9ubuntu1 | amd64 | procps | base | LGPL-2.1+ |
| python3 | 3.14.3-0ubuntu2 | amd64 | python3-defaults | added | PSF (prose) |
| python3-minimal | 3.14.3-0ubuntu2 | amd64 | python3-defaults | added | PSF (prose) |
| python3.14 | 3.14.4-1ubuntu0.2 | amd64 | python3.14 | added | PSF (prose block) |
| python3.14-minimal | 3.14.4-1ubuntu0.2 | amd64 | python3.14 | added | PSF (prose block) |
| readline-common | 8.3-4 | all | readline | added | GPL-3+ |
| rust-coreutils | 0.8.0-0ubuntu3 | amd64 | rust-coreutils | base | MIT |
| sed | 4.9-2ubuntu1 | amd64 | sed | base | GPL-3+ |
| sensible-utils | 0.0.26build1 | all | sensible-utils | base | GPL-2+ |
| sysvinit-utils | 3.15-5ubuntu1 | amd64 | sysvinit | base | GPL-2.0+ |
| tar | 1.35+dfsg-4ubuntu0.4 | amd64 | tar | base | GPL-3+ |
| tzdata | 2026c-0ubuntu0.26.04.1 | all | tzdata | added | public-domain |
| ubuntu-keyring | 2023.11.28.1build1 | all | ubuntu-keyring | base | GPL (keys carry no copyright; prose) |
| util-linux | 2.41.3-3ubuntu2.2 | amd64 | util-linux | base | GPL-2+ |
| zlib1g | 1:1.3.dfsg+really1.3.1-1ubuntu3.1 | amd64 | zlib | base | Zlib |

## Embedded components (code inside shipped files)

Two shipped binaries embed third-party code that has no
separate package entry; both are disclosed here, not just in
a scanner list:

- `libHSdirect-sqlite-…so` embeds the SQLite amalgamation:
  272 `sqlite3_*` dynamic symbols and version string
  `3.45.0` (measured `nm -D` + `strings`). SQLite's own
  dedication is public domain
  (`https://www.sqlite.org/copyright.html`, verified 200
  2026-10-06); the Haskell bindings around it are covered by
  `licenses/direct-sqlite-LICENSE` (shipped; upstream
  `direct-sqlite-2.3.29`, Hackage `license: BSD3`).
- `cryptography 50.0.2` (`_rust.abi3.so`) embeds OpenSSL
  4.0.3 (measured `strings`: `OpenSSL 4.0.3 29 Sep 2026`;
  0 `OPENSSL_*` dynamic symbols and NEEDED of only
  `libgcc_s/libc` — fully static).
  This is the wheel's own static build — do NOT confuse it
  with Haskoki's pinned OpenSSL 4.0.2 (Bundle section) or
  the OS `libssl3t64` 3.5.5 (table above). Three distinct
  OpenSSL builds ship in this image; each is version-pinned
  where its owner pins it.

## Shipped examples and fixtures

`examples/release/` (proxy-example, compare-classify, frozen
sets): project files, Apache-2.0. No third-party dataset is
embedded: vector corpora ship unfetched and download at user
request only (`fetch-data`).

## Blockers

None found: every shipped component above carries its notice
in-image or a pointer to its exact source. The two historical
NOTICES.md open items are resolved in the Bundle section
(GHC grant scope stated; `haskoki-ctl` linkage measured).
