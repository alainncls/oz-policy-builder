# Disposable build workers

The container package in [SELF-HOSTING.md](SELF-HOSTING.md) runs the API and compiler in
one container and is intended for a single operator with trusted clients. CPU and memory
limits on that container are not a boundary between requests.

The separate worker mode runs the API as an unprivileged Linux host process. The API sends
one bounded generated-file job to a fixed, operator-installed launcher. The reference
launcher creates one rootless Podman container for that job and removes it before returning
an artifact. The API never mounts a Docker socket or starts a privileged nested runtime.

This mode requires Linux, rootless Podman with `--timeout` support, subordinate user/group
IDs, and delegated cgroup v2 CPU, memory and PID controllers. A platform without these
controls must fail its acceptance checks before receiving untrusted jobs. The package does
not provision a provider, publish an image, create a DNS record, or configure a public endpoint.

## Configure a Linux host

Use a dedicated service account with a normal home directory, rootless Podman at
`/usr/bin/podman`, Python 3.11 or later, subordinate UID/GID ranges, and a running systemd
user manager. Follow your distribution's supported rootless setup; do not disable host security
controls or add privileged containers to compensate for missing delegation.

Build the image from an immutable reviewed revision using [SELF-HOSTING.md](SELF-HOSTING.md),
then load it into the service account's rootless image store. Verify its origin and record its
immutable image ID or registry digest. The launcher uses `--pull never`; credentials and registry
networking are not needed during a job. Build the host binary for the host operating system with
`cargo build --locked --release -p ozpb-mcp-server -p ozpb-cli`. A binary copied from an image may
require a newer host libc; compiling the host binary avoids that assumption.

Install these reviewed files using your normal host configuration system. Install the API binary
and the launcher from the same revision: each rejects the other's output from a different one,
and every build would then retain its slot.

| Source | Host destination | Ownership and mode |
| --- | --- | --- |
| `target/release/ozpb-mcp-server` | `/usr/local/bin/ozpb-mcp-server` | root, 0555 |
| `deployment/entrypoint.sh` | `/usr/local/libexec/ozpb-api` | root, 0555 |
| `deployment/worker-launcher.py` | `/usr/local/libexec/ozpb-worker-launcher` | root, 0555 |
| Edited `deployment/build-worker.example.json` | `/etc/ozpb/build-worker.json` | root, 0644 |
| Edited `deployment/http.example.env` | `/etc/ozpb/http.env` | root, 0644 |
| `deployment/ozpb-api.service` | service account's `.config/systemd/user/ozpb-api.service` | service account, 0600 |

Every parent of the launcher must be protected from writes by other users. Symlinks are
refused in the launcher and every ancestor; configure its canonical absolute path. The worker JSON
contains only operator resource ceilings and the immutable image identity. Its `jobs` and
`timeout_seconds` ceilings must cover the API's `OZPB_BUILD_JOBS` and
`OZPB_BUILD_TIMEOUT_SECS`. The runtime adds 35 seconds for bounded toolchain probes; the
launcher and API each allow additional bounded startup and cleanup time. The example uses
one concurrent job, two CPUs, 4 GiB memory including tmpfs, 256 PIDs, and 3 GiB private tmpfs.
Adjust these explicit limits to the host and test that a cold build completes.

Put `bearer-token`, `registry-roots.json`, `registry.signed.json`, and `rpc-sources.json` under
`/etc/ozpb/http`, readable only by the administrator and dedicated API account. Use the token
format and signed-trust/RPC configuration described in SELF-HOSTING. The entrypoint reads
credentials from files immediately before executing the API; no token appears in argv, the
service unit, the image, or the launcher environment. TLS private keys belong to the separate
proxy. The API listens on `127.0.0.1:8080`; colocate a TLS proxy and retain the supplied
host/origin/path checks. No access logs are enabled by the supplied user unit.

Under the service account, run `systemctl --user daemon-reload` and
`systemctl --user start ozpb-api.service` after the acceptance checks below pass. The user unit
delegates cgroups to rootless Podman. Its host process needs the distribution's normal rootless
UID mapping helpers; no-new-privileges and capability removal are enforced inside each worker
container. The Compose service remains the separate single-operator mode.

For a CLI invocation, set `OZPB_BUILD_WORKER_LAUNCHER` to the same protected executable or
use `--build-worker-launcher`. Invalid, missing, relative, symlinked or writable launcher paths
fail configuration; they never fall back to host compilation.

## Trust and lifecycle

The operator trusts the host kernel, container runtime, launcher, configuration and immutable
worker image. The launcher is executable code with that operator's privileges: install it and
its configuration with restrictive permissions, and do not permit callers to choose either.
Keep unrelated workloads and credentials out of the service account.

Each job has a private PID/IPC/network namespace and bounded writable tmpfs. Compiler
dependencies are read-only image content. Source, target cache and output disappear with
the container; no writable target cache is shared between jobs. The compiler has no network
egress, host mounts, bearer token, RPC configuration or registry signing material. The tmpfs
permits execution because Cargo build scripts execute native programs inside the container.
The fresh container's tmpfs mount is root-owned with sticky mode `1777`, following the
[Podman 4.9 tmpfs interface](https://github.com/containers/podman/blob/v4.9.3/docs/source/markdown/options/tmpfs.md).
That release rejects explicit `uid`/`gid` mount options. The single worker principal remains
UID/GID `10001`; its source directory, Cargo home and target directory are mode `0700`
under umask `0077`. Each container has its own mount, so this does not expose one job's
files to another job or the API. Linux acceptance observes the actual Rust build directory's
ownership and mode while compiling, as well as fresh-cache isolation.

Podman's [runtime timeout](https://docs.podman.io/en/v5.7.0/markdown/podman-run.1.html#timeout-seconds)
is enforced by conmon, independently of the API and launcher processes. Namespace teardown
also ends processes that created a new session with `setsid`; killing a host process group
alone does not establish this boundary.

Only the trusted launcher writes the outer result frame, after checking that the job's
container no longer exists. Worker stdout is bounded input to that frame, never a cleanup
assertion. The API independently checks the response framing, job identity, Wasm digest,
toolchain metadata and configured dependency pins before producing a BuildManifest.

If the launcher dies, exceeds its deadline or produces an invalid frame, cleanup is uncertain.
The API retains the job's capacity slot and returns a fixed, redacted error. Inspect and remove
any remaining containers under the dedicated service account, then restart the API to restore
capacity. A normal compilation failure releases capacity only after confirmed removal.

When a client cancels the request, the API waits, within the launch's own deadline, for the
launcher to report that its SIGTERM handler is installed, then sends it SIGTERM and waits up to 45
seconds. The launcher stops the running job, removes its container and writes the usual frame
with a null result; a stop requested before launch runs nothing. That confirmation releases the
slot. A launcher that does not confirm in time is handled as one that died: its slot stays
retained until the operator has cleaned up.

## Launcher contract for another provider

The API starts the configured executable with no arguments, a private file on stdin, bounded
stdout capture, and a minimal host environment. The input is JSON with schema
`build-worker-job/v1`, `crate_name`, `files` (an array of `{path, body}`), `timeout_seconds`, and
`jobs`. Time and parallelism originate in operator configuration, and the launcher must check
them against its own ceilings. The six paths are exactly `Cargo.toml`, `Cargo.lock`,
`rust-toolchain.toml`, `rustfmt.toml`, `src/lib.rs`, and `src/contract.rs`, with no duplicates.
Combined UTF-8 source is at most 2 MiB and encoded input is at most 16 MiB. The launcher's
stdout begins with the line `ready`, written once it handles SIGTERM and before it reads its
input; output without that line releases no capacity. SIGTERM means the request was cancelled:
stop the job, prove its removal and frame a null result. Once removal is confirmed, ignore it.

The worker's bounded JSON result has schema `build-worker-result/v1` and `artifact`, either
null for a failed build or an object containing `wasm_base64`, `wasm_hash`, and `toolchain`.
Toolchain contains `rustc_version`, `stellar_cli_version`, and `builder`. The worker cannot
claim cleanup. After independently proving the disposable job has ended and its writable
state is gone, the launcher writes a separate object with schema `contained-build-result/v1`,
`job_hash` (SHA-256 of the exact stdin bytes), `containment` equal to `removed`, and `result`
containing the validated worker result or null, after its `ready` line. Both stdout layers are
capped at 4 MiB; Wasm is capped at 2 MiB. No diagnostic strings are part of either protocol.

A different provider adapter must retain the same independent runtime deadline, disposable
filesystem/process lifecycle, resource limits, no-egress/no-secrets boundary, and teardown
proof. Provider commands, image selection, credentials and resource paths remain fixed
operator configuration; none can be selected by job input. Run the equivalent adversarial
acceptance suite on that provider before treating its teardown assertion as trustworthy.

## Acceptance on the chosen host

Before accepting client traffic, run the containment checks on the actual runtime and kernel:

```sh
python3 scripts/test-worker-launcher.py
systemd-run --user --scope -p Delegate=yes \
  python3 scripts/test-worker-containment.py --image sha256:YOUR_REVIEWED_IMAGE_ID
```

The second command requires the image already loaded into the dedicated account. It builds
a small synthetic adversarial image locally, without publishing or pulling anything, and removes
that test image when finished. It refuses an account with existing worker jobs so its lifecycle
checks cannot mistake another workload for its own. It checks:

- Real generated Wasm builds and reproduces with network access disabled.
- A host secret canary cannot be read and an external connection cannot be opened.
- An escaped background process ends at the runtime deadline, even after the launcher is killed.
- A following job sees neither the preceding job's files nor its writable compilation cache.
- Requests with extra paths, excessive source, invalid framing or excessive output fail closed.
- Exact CPU quota, memory/swap, PID and tmpfs ceilings are visible in the job's kernel controls.
- Adversarial forks and tmpfs writes stop at small configured limits. CPU saturation and memory
  exhaustion are not load-tested by this suite.

TLS, bearer authentication, RPC allowlists, signed registry roots, request quotas and body limits
remain API responsibilities. Retain the checks in `scripts/check-hosted-endpoint.py` when placing
the host service behind your TLS proxy. Disable access logs and do not retain request bodies,
generated source, compiler output or worker responses in operational logs.
