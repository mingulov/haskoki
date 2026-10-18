# Observing PKCS#11 calls with p11scope

[p11scope](https://github.com/mingulov/p11scope) can observe PKCS#11 calls
on a Linux host. It is useful for seeing which calls a client makes while
Haskoki handles a workload. It runs separately and is not required by the
Haskoki demo image.

Start with p11scope's setup instructions and `doctor` command. Capture
requires its Linux/eBPF prerequisites and observer privileges; the Haskoki
workload can remain an ordinary unprivileged container. Select the workload's
actual process or cgroup, including descendants, using the installed
version's `profile --help`.

A full checker run provides a longer observation window than the short
demo. Keep its reports in a host directory:

```sh
# HASKOKI_IMAGE is selected in Try Haskoki.
mkdir -p out
docker run --rm --network none --user "$(id -u):$(id -g)" \
  -v "$PWD/out:/out" "$HASKOKI_IMAGE" \
  check --mode direct --profile full
```

That profile intentionally exits 1 for documented findings; see
[release results](release-results.md). Start the observer from another
terminal while it runs.

Read the capture's completeness, discovery gaps, attach refusals, and
unattributed counts before drawing conclusions. An empty mechanism table
need not mean no crypto happened. Provider-call latency also does not
measure a complete proxy round trip. These limits belong in any shared
trace result, together with the observer and workload versions.
