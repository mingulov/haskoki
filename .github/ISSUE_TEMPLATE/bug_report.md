---
name: Bug report
about: Report a Haskoki defect with a reproducible record
labels: bug
---

> Do NOT paste PINs, private keys, real token databases, or any secrets.
> Scrub `report.json`/logs before attaching: keep versions, the command,
> exit code, and the failing step; drop key material and PINs.

## Version / digest

- Haskoki version (`haskoki-ctl --version`, or image tag):
- Image digest if containerized (`docker inspect --format '{{.Id}} {{.RepoDigests}}' <image:tag>`, e.g. `… haskoki-demo:0.3.0.0`):
- Proxy pair if proxied (`pkcs11-proxy-ng --version` + shim/daemon hashes):

## Command

Exact command line(s), run from which directory, and the config/module
path used (e.g. `HASKOKI_CONFIG=…`, `--module …`).

```sh
# paste here
```

## Environment

- Host OS + kernel (`uname -a`), glibc (`ldd --version`):
- Docker or native; container tag or toolchain image:
- Storage: `memory` (default, transient) or `sqlite` (path?) — state/reset rules: `docs/demo-walkthrough.md` §6:

## Observed vs expected

What happened (exit code + failing step/output):

What you expected instead:

## Cleaned report

Attach the scrubbed `report.json` / run-dir excerpt (see the warning
above). Steps to reproduce from a fresh state directory help most.
