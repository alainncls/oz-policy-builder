#!/usr/bin/python3 -I
"""One rootless, disposable build. Only this launcher can assert container removal.

Install at a fixed protected path; configuration is /etc/ozpb/build-worker.json.
No request value becomes a command, runtime option, host mount or image selection.
"""

import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import sys
import tempfile
import time
import uuid

PODMAN = "/usr/bin/podman"
CONFIG = Path("/etc/ozpb/build-worker.json")
MAX_JOB = 16 * 1024 * 1024
MAX_OUTPUT = 4 * 1024 * 1024
FILES = {"Cargo.toml", "Cargo.lock", "rust-toolchain.toml", "rustfmt.toml", "src/lib.rs", "src/contract.rs"}


class Refused(Exception):
    """A fixed, redacted launcher failure."""


# A cancelled request reaches the launcher as SIGTERM from the API. The handler only records
# it. The job's run checks that record before it starts the runtime client and on every poll,
# and stops there, where its client is killed and its container is then removed and that removal
# framed with no result. Nothing else is interrupted: raising from the handler at an arbitrary
# line could skip killing the client, run the removal before the container exists, or lose a
# confirmation already made, and the API would then free capacity a job still holds or strand it.
STOP = {"requested": False}
# Written first, once the handler is installed. The API signals no earlier, because a SIGTERM
# before the handler exists kills the launcher with nothing confirmed.
READY = b"ready\n"


def stop_requested(signum, frame):
    STOP["requested"] = True


def install_stop_handler():
    signal.signal(signal.SIGTERM, stop_requested)


def integer(value, low, high):
    if type(value) is not int or not low <= value <= high:
        raise Refused()
    return value


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise Refused()
        result[key] = value
    return result


def decode(data):
    return json.loads(data, object_pairs_hook=unique_object)


def load_config(path=CONFIG):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid not in (0, os.getuid()) or info.st_mode & 0o022:
        raise Refused()
    with path.open("rb") as source:
        raw = source.read(8193)
    if len(raw) > 8192:
        raise Refused()
    config = decode(raw)
    if set(config) != {"image", "timeout_seconds", "cpus", "memory_mib", "pids", "tmpfs_mib", "jobs"}:
        raise Refused()
    # Locally loaded image ID or fully qualified digest; tags and implicit pulls are forbidden.
    if not isinstance(config["image"], str) or not re.fullmatch(
        r"(?:sha256:|[a-z0-9.-]+(?::[0-9]+)?/[a-z0-9._/-]+@sha256:)[0-9a-f]{64}", config["image"]
    ):
        raise Refused()
    for name, low, high in [("timeout_seconds", 1, 3600), ("cpus", 1, 16),
                            ("memory_mib", 256, 16384), ("pids", 16, 512),
                            ("tmpfs_mib", 64, 8192), ("jobs", 1, 16)]:
        integer(config[name], low, high)
    if config["jobs"] > config["cpus"] or config["tmpfs_mib"] > config["memory_mib"]:
        raise Refused()
    return config


def validate_job(raw, config):
    if len(raw) > MAX_JOB:
        raise Refused()
    job = decode(raw)
    if set(job) != {"schema", "crate_name", "files", "timeout_seconds", "jobs"}:
        raise Refused()
    if job["schema"] != "build-worker-job/v1" or not isinstance(job["crate_name"], str):
        raise Refused()
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", job["crate_name"]):
        raise Refused()
    integer(job["timeout_seconds"], 1, config["timeout_seconds"])
    integer(job["jobs"], 1, config["jobs"])
    if not isinstance(job["files"], list) or len(job["files"]) != len(FILES):
        raise Refused()
    names, total = set(), 0
    for item in job["files"]:
        if not isinstance(item, dict) or set(item) != {"path", "body"}:
            raise Refused()
        path, body = item["path"], item["body"]
        if not isinstance(path, str) or path not in FILES or path in names or not isinstance(body, str):
            raise Refused()
        names.add(path)
        total += len(body.encode("utf-8"))
    if names != FILES or total > 2 * 1024 * 1024:
        raise Refused()
    return job


def bounded(command, timeout, limit, source=None, stoppable=False):
    """Capture bounded stdout and discard stderr; terminate only the local client on failure.

    This is not the container boundary. Conmon's separate deadline survives client death.
    A `stoppable` run also ends when a stop is requested, before it starts or while it runs.
    """
    if stoppable and STOP["requested"]:
        raise Refused()
    process = subprocess.Popen(command, stdin=source or subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.DEVNULL, start_new_session=True, close_fds=True)
    deadline, result = time.monotonic() + timeout, bytearray()
    try:
        with selectors.DefaultSelector() as poll:
            poll.register(process.stdout, selectors.EVENT_READ)
            while poll.get_map():
                if stoppable and STOP["requested"]:
                    raise Refused()
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise Refused()
                for key, _ in poll.select(min(remaining, 0.1)):
                    chunk = os.read(key.fileobj.fileno(), min(65536, limit + 1 - len(result)))
                    if not chunk:
                        poll.unregister(key.fileobj)
                    else:
                        result.extend(chunk)
                        if len(result) > limit:
                            raise Refused()
            status = process.wait(timeout=max(0.01, deadline - time.monotonic()))
        return status, bytes(result)
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
        process.stdout.close()


def command(config, name, job):
    return [PODMAN, "run", "--rm", "--name", name, "--label", "org.ozpb.worker=true",
            "--pull", "never", "--timeout", str(job["timeout_seconds"] + 35),
            "--network", "none", "--no-hosts", "--http-proxy=false",
            "--pid", "private", "--ipc", "private", "--uts", "private", "--cgroupns", "private",
            "--userns", "nomap", "--user", "10001:10001", "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges", "--read-only", "--read-only-tmpfs=false",
            "--systemd=false", "--image-volume", "ignore", "--log-driver", "none",
            "--cpus", str(config["cpus"]), "--memory", str(config["memory_mib"]) + "m",
            "--memory-swap", str(config["memory_mib"]) + "m", "--pids-limit", str(config["pids"]),
            "--ulimit", "nofile=1024:1024", "--umask", "0077", "--shm-size", "8m",
            "--tmpfs", "/tmp/ozpb:rw,exec,nosuid,nodev,mode=1777,size=" + str(config["tmpfs_mib"]) + "m",
            "--unsetenv-all", "--env", "PATH=/usr/local/cargo/bin:/usr/local/bin:/usr/bin:/bin",
            "--env", "RUSTUP_HOME=/usr/local/rustup", "--env", "RUSTUP_AUTO_INSTALL=0",
            "--env", "CARGO_NET_OFFLINE=true", "--env", "CARGO_HOME=/tmp/ozpb/cargo",
            "--env", "TMPDIR=/tmp/ozpb", "--env", "OZPB_BUILD_CACHE_DIR=/tmp/ozpb/target",
            "--entrypoint", "/opt/ozpb/entrypoint.sh", "--interactive", config["image"],
            "/usr/local/bin/ozpb-build-worker"]


def preflight():
    if sys.platform != "linux" or os.geteuid() == 0:
        raise Refused()
    status, raw = bounded([PODMAN, "info", "--format", "json"], 10, 1024 * 1024)
    host = decode(raw).get("host", {})
    if status != 0 or not host.get("security", {}).get("rootless") or host.get("cgroupVersion") != "v2":
        raise Refused()
    if not {"cpu", "memory", "pids"}.issubset(set(host.get("cgroupControllers", []))):
        raise Refused()


def removed(name):
    # Removal forcibly terminates the complete container, including new-session descendants.
    bounded([PODMAN, "rm", "--force", "--time", "0", name], 15, 4096)
    status, _ = bounded([PODMAN, "container", "exists", name], 10, 4096)
    return status == 1  # 0 exists; 125 is a storage error, never successful cleanup.


def worker_result(raw):
    """Validate shape before framing; never let worker text become launcher control fields."""
    result = decode(raw)
    if not isinstance(result, dict) or set(result) != {"schema", "artifact"} or result["schema"] != "build-worker-result/v1":
        raise Refused()
    artifact = result["artifact"]
    if artifact is not None:
        if not isinstance(artifact, dict) or set(artifact) != {"wasm_base64", "wasm_hash", "toolchain"}:
            raise Refused()
        if not isinstance(artifact["wasm_base64"], str) or len(artifact["wasm_base64"]) > 2800000 \
                or not artifact["wasm_base64"].isascii():
            raise Refused()
        if not isinstance(artifact["wasm_hash"], str) or not re.fullmatch("[0-9a-f]{64}", artifact["wasm_hash"]):
            raise Refused()
        tools = artifact["toolchain"]
        if not isinstance(tools, dict) or set(tools) != {"rustc_version", "stellar_cli_version", "builder"}:
            raise Refused()
        if not all(isinstance(value, str) and len(value) <= 256 for value in tools.values()):
            raise Refused()
        try:
            if any(len(value.encode("utf-8")) > 256 for value in tools.values()):
                raise Refused()
        except UnicodeError:
            raise Refused() from None
    return result


def launch(raw, config):
    def frame(result):
        return {"schema": "contained-build-result/v1", "job_hash": hashlib.sha256(raw).hexdigest(),
                "containment": "removed", "result": result}

    # Nothing has launched yet: a configuration/input refusal cannot leave a container.
    try:
        job = validate_job(raw, config)
        preflight()
    except (Refused, ValueError, TypeError, KeyError, OSError, subprocess.SubprocessError):
        return frame(None)
    if STOP["requested"]:
        return frame(None)
    name = "ozpb-job-" + uuid.uuid4().hex
    result = None
    # A file descriptor avoids a blocked writer and is never mounted into the container.
    with tempfile.TemporaryFile() as source:
        source.write(raw)
        source.seek(0)
        try:
            status, output = bounded(command(config, name, job), job["timeout_seconds"] + 45,
                                     MAX_OUTPUT, source, stoppable=True)
            if status == 0:
                result = worker_result(output)
        except (Refused, ValueError, TypeError, OSError, subprocess.SubprocessError, RecursionError):
            result = None
        finally:
            if not removed(name):
                raise Refused()
    return frame(result)


def main():
    try:
        if len(sys.argv) != 1:
            raise Refused()
        install_stop_handler()
        sys.stdout.buffer.write(READY)
        sys.stdout.buffer.flush()
        raw = sys.stdin.buffer.read(MAX_JOB + 1)
        frame = launch(raw, load_config())
        # Removal is confirmed and nothing is left to stop. Interpreter shutdown restores
        # SIGTERM's default action after flushing this frame, and a late stop would then kill a
        # launcher whose confirmation the API has to discard.
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        encoded = json.dumps(frame, separators=(",", ":")).encode()
        if len(encoded) > MAX_OUTPUT:
            # Cleanup was already confirmed. Retain that fact even when framing
            # overhead or JSON escaping pushes the result over its wire budget.
            frame["result"] = None
            encoded = json.dumps(frame, separators=(",", ":")).encode()
        sys.stdout.buffer.write(encoded)
        return 0
    except (Refused, ValueError, TypeError, KeyError, OSError, subprocess.SubprocessError, RecursionError):
        print("disposable worker unavailable; verify cleanup before restarting capacity", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
