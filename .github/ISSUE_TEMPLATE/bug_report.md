---
name: Bug report
about: Report a Haskoki defect with a reproducible example
labels: bug
---

Do not include PINs, private keys, token databases, or other secrets.
Clean reports and logs before attaching them.

## Version and environment

- Haskoki version (`haskoki-ctl --version`, or image tag):
- Image tag and digest, if using Docker (`docker image inspect <image> --format '{{.Id}} {{json .RepoDigests}}'`):
- Proxy or p11-kit version, if using remoting:
- Host OS, kernel, and architecture (`uname -a`):
- Docker or native; glibc version for a native bundle (`ldd --version`):
- Storage (`memory` or `sqlite`) and whether it is a fresh store:

## Reproduction

Exact commands, starting directory, and module/configuration paths:

```sh
# Paste here.
```

Steps to reproduce with disposable keys and a fresh state directory:

## Expected and actual result

What you expected:

What happened, including the exit code and failing output:

## Reports

If available, attach cleaned `report.json` and relevant logs. Keep versions,
commands, exit codes, and failing steps; remove credentials and key material.
