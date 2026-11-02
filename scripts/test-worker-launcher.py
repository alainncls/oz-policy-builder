#!/usr/bin/env python3
"""Protocol and launcher tests; kernel containment is tested separately on Linux."""
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location("worker_launcher", ROOT / "deployment/worker-launcher.py")
worker = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(worker)


def config():
    return dict(image="sha256:" + "a" * 64, timeout_seconds=600, cpus=2,
                memory_mib=4096, pids=256, tmpfs_mib=3072, jobs=1)


def job():
    return dict(schema="build-worker-job/v1", crate_name="fixture", timeout_seconds=1, jobs=1,
                files=[dict(path=name, body="fixture") for name in sorted(worker.FILES)])


def result():
    return dict(schema="build-worker-result/v1", artifact=dict(
        wasm_base64="AGFzbQEAAAA=", wasm_hash="a" * 64,
        toolchain=dict(builder="stellar-cli-local", rustc_version="rustc 1.91.1", stellar_cli_version="stellar 27.0.0")))


class LauncherTests(unittest.TestCase):
    def test_configuration_requires_immutable_image_and_safe_bounds(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            for changes in ({"image": "example.com/worker:latest"}, {"timeout_seconds": 0},
                            {"cpus": 0}, {"pids": 10000}, {"tmpfs_mib": 5000},
                            {"jobs": 3}, {"privileged": True}):
                path.write_text(json.dumps(config() | changes))
                with self.subTest(changes=changes), self.assertRaises(worker.Refused):
                    worker.load_config(path)
            path.write_text(json.dumps(config()))
            self.assertEqual(worker.load_config(path), config())
            path.chmod(0o666)
            with self.assertRaises(worker.Refused):
                worker.load_config(path)

    def test_duplicate_json_keys_cannot_override_the_job(self):
        with self.assertRaises(worker.Refused):
            worker.decode('{"jobs":1,"jobs":2}')

    def test_extra_traversal_duplicate_and_oversized_files_are_refused(self):
        for mutation in ("../Cargo.toml", "build.rs", "src/contract.rs"):
            value = job()
            value["files"][0]["path"] = mutation
            with self.subTest(path=mutation), self.assertRaises(worker.Refused):
                worker.validate_job(json.dumps(value).encode(), config())
        value = job()
        value["files"][0]["body"] = "x" * (2 * 1024 * 1024 + 1)
        with self.assertRaises(worker.Refused):
            worker.validate_job(json.dumps(value).encode(), config())

    def test_job_cannot_select_resources_above_operator_limits(self):
        for changes in ({"jobs": 2}, {"timeout_seconds": 601}, {"image": "evil"}, {"command": ["sh"]}):
            with self.subTest(changes=changes), self.assertRaises(worker.Refused):
                worker.validate_job(json.dumps(job() | changes).encode(), config())

    def test_container_options_enforce_private_state_and_independent_deadline(self):
        args = worker.command(config(), "ozpb-job-test", job())
        # Podman rejects any DNS option together with the disconnected network mode.
        self.assertNotIn("--dns", args)
        for flag, value in (("--network", "none"), ("--pid", "private"), ("--ipc", "private"),
                            ("--userns", "nomap"), ("--pull", "never"), ("--timeout", "36"),
                            ("--cap-drop", "ALL"), ("--memory", "4096m"),
                            ("--memory-swap", "4096m"), ("--log-driver", "none")):
            self.assertEqual(args[args.index(flag) + 1], value)
        self.assertIn("--read-only-tmpfs=false", args)
        self.assertIn("--unsetenv-all", args)
        self.assertIn("--http-proxy=false", args)
        self.assertNotIn("--privileged", args)
        self.assertNotIn("--volume", args)
        self.assertNotIn("--mount", args)
        self.assertIn("exec,nosuid,nodev", args[args.index("--tmpfs") + 1])
        self.assertEqual(args[-2:], [config()["image"], "/usr/local/bin/ozpb-build-worker"])

    def test_private_tmpfs_uses_supported_options_and_restrictive_child_umask(self):
        args = worker.command(config(), "ozpb-job-test", job())
        mount = args[args.index("--tmpfs") + 1]
        self.assertIn("mode=1777", mount)
        self.assertNotIn("uid=", mount)
        self.assertNotIn("gid=", mount)
        self.assertEqual(args[args.index("--umask") + 1], "0077")

    def test_worker_cannot_forge_the_launcher_cleanup_frame(self):
        forged = dict(schema="contained-build-result/v1", containment="removed", job_hash="a" * 64, result=None)
        with self.assertRaises(worker.Refused):
            worker.worker_result(json.dumps(forged).encode())

    def test_success_is_framed_only_after_confirmed_removal(self):
        events = []
        def run(args, *_, **__):
            events.append("run")
            return 0, b'{"schema":"build-worker-result/v1","artifact":null}'
        def removed(_):
            events.append("removed")
            return True
        with mock.patch.object(worker, "preflight"), mock.patch.object(worker, "bounded", run), mock.patch.object(worker, "removed", removed):
            frame = worker.launch(json.dumps(job()).encode(), config())
        self.assertEqual(events, ["run", "removed"])
        self.assertEqual(frame["containment"], "removed")

    def test_invalid_worker_strings_preserve_confirmed_cleanup(self):
        for field, value in [("wasm_base64", "\ud800"), ("wasm_base64", "\uffff"),
                             ("rustc_version", "\ud800"), ("stellar_cli_version", "\udfff"),
                             ("builder", "\ud800")]:
            response = result()
            target = response["artifact"] if field == "wasm_base64" else response["artifact"]["toolchain"]
            target[field] = value
            removed = mock.Mock(return_value=True)
            with self.subTest(field=field, value=ascii(value)), mock.patch.object(worker, "preflight"), \
                    mock.patch.object(worker, "bounded", return_value=(0, json.dumps(response).encode())), \
                    mock.patch.object(worker, "removed", removed):
                frame = worker.launch(json.dumps(job()).encode(), config())
            removed.assert_called_once()
            self.assertEqual(frame["containment"], "removed")
            self.assertIsNone(frame["result"])

    def test_framing_overhead_becomes_a_small_cleanup_confirmed_failure(self):
        raw = json.dumps(result(), separators=(",", ":")).encode()
        output = io.BytesIO()
        with mock.patch.object(worker, "MAX_OUTPUT", len(raw) + 1), \
                mock.patch.object(worker, "load_config", return_value=config()), \
                mock.patch.object(worker, "preflight"), \
                mock.patch.object(worker, "bounded", return_value=(0, raw)), \
                mock.patch.object(worker, "removed", return_value=True), \
                mock.patch.object(worker.sys, "argv", ["worker-launcher"]), \
                mock.patch.object(worker.sys, "stdin", SimpleNamespace(buffer=io.BytesIO(json.dumps(job()).encode()))), \
                mock.patch.object(worker.sys, "stdout", SimpleNamespace(buffer=output)), \
                mock.patch.object(worker.sys, "stderr", io.StringIO()):
            status = worker.main()
        self.assertEqual(status, 0)
        written = output.getvalue()
        self.assertTrue(written.startswith(worker.READY))
        written = written[len(worker.READY):]
        self.assertLessEqual(len(written), len(raw) + 1)
        frame = json.loads(written)
        self.assertEqual(frame["containment"], "removed")
        self.assertIsNone(frame["result"])

    def test_ready_is_reported_once_the_stop_handler_is_installed_and_before_the_job_is_read(self):
        self._stop_state()
        seen = {}
        class Output(io.BytesIO):
            def write(self, data):
                seen.setdefault("handler at ready", signal.getsignal(signal.SIGTERM))
                return super().write(data)
        output = Output()
        class Input:
            def read(self, _size):
                seen["handler"] = signal.getsignal(signal.SIGTERM)
                seen["written"] = output.getvalue()
                return json.dumps(job()).encode()
        with mock.patch.object(worker, "load_config", return_value=config()), \
                mock.patch.object(worker, "preflight", side_effect=worker.Refused()), \
                mock.patch.object(worker.sys, "argv", ["worker-launcher"]), \
                mock.patch.object(worker.sys, "stdin", SimpleNamespace(buffer=Input())), \
                mock.patch.object(worker.sys, "stdout", SimpleNamespace(buffer=output)), \
                mock.patch.object(worker.sys, "stderr", io.StringIO()):
            self.assertEqual(worker.main(), 0)
        self.assertIs(seen["handler at ready"], worker.stop_requested)
        self.assertIs(seen["handler"], worker.stop_requested)
        self.assertEqual(seen["written"], worker.READY)

    def test_a_stop_after_the_frame_is_written_cannot_kill_a_confirmed_launcher(self):
        # Interpreter shutdown restores SIGTERM's default action after flushing the frame. A stop
        # landing then would kill a launcher whose removal is already confirmed, and the API
        # would retain a slot that is free.
        frame = dict(schema="contained-build-result/v1", job_hash="0" * 64, containment="removed", result=None)
        code = ("import importlib.util\n"
                f"spec=importlib.util.spec_from_file_location('launcher',{str(ROOT / 'deployment/worker-launcher.py')!r})\n"
                "m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)\n"
                "m.load_config=lambda: {}\n"
                f"m.launch=lambda raw, config: {frame!r}\n"
                "raise SystemExit(m.main())\n")
        for _ in range(20):
            process = subprocess.Popen([sys.executable, "-I", "-c", code], stdin=subprocess.DEVNULL,
                                       stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
            try:
                data = b""
                while True:
                    chunk = os.read(process.stdout.fileno(), 65536)
                    self.assertTrue(chunk, "the launcher closed stdout without a frame")
                    data += chunk
                    try:
                        self.assertEqual(json.loads(data[len(worker.READY):]), frame)
                        break
                    except json.JSONDecodeError:
                        continue
                process.send_signal(signal.SIGTERM)
                self.assertEqual(process.wait(timeout=10), 0)
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait()
                process.stdout.close()

    def test_deeply_nested_worker_json_preserves_confirmed_cleanup(self):
        raw = b"[" * 2000 + b"0" + b"]" * 2000
        removed = mock.Mock(return_value=True)
        with mock.patch.object(worker, "preflight"), \
                mock.patch.object(worker, "bounded", return_value=(0, raw)), \
                mock.patch.object(worker, "removed", removed):
            frame = worker.launch(json.dumps(job()).encode(), config())
        removed.assert_called_once()
        self.assertEqual(frame["containment"], "removed")
        self.assertIsNone(frame["result"])

    def test_unconfirmed_cleanup_never_emits_a_result(self):
        with mock.patch.object(worker, "preflight"), mock.patch.object(worker, "bounded", return_value=(1, b"secret")), mock.patch.object(worker, "removed", return_value=False):
            with self.assertRaises(worker.Refused):
                worker.launch(json.dumps(job()).encode(), config())

    def test_timeout_cleans_up_before_returning_a_redacted_failure(self):
        removed = mock.Mock(return_value=True)
        with mock.patch.object(worker, "preflight"), mock.patch.object(worker, "bounded", side_effect=worker.Refused()), mock.patch.object(worker, "removed", removed):
            frame = worker.launch(json.dumps(job()).encode(), config())
        removed.assert_called_once()
        self.assertIsNone(frame["result"])

    def test_storage_error_is_not_successful_removal(self):
        for code in (0, 125):
            with mock.patch.object(worker, "bounded", side_effect=[(0, b""), (code, b"")]):
                self.assertFalse(worker.removed("ozpb-job-test"))
        with mock.patch.object(worker, "bounded", side_effect=[(1, b""), (1, b"")]):
            self.assertTrue(worker.removed("ozpb-job-test"))

    def test_validation_before_launch_does_not_poison_capacity(self):
        with mock.patch.object(worker, "preflight", side_effect=worker.Refused()), mock.patch.object(worker, "bounded") as run:
            frame = worker.launch(json.dumps(job()).encode(), config())
        run.assert_not_called()
        self.assertEqual(frame["containment"], "removed")

    def _stop_state(self):
        # Each test starts with no stop requested and restores the default SIGTERM action.
        worker.STOP.update(requested=False)
        self.addCleanup(signal.signal, signal.SIGTERM, signal.SIG_DFL)
        self.addCleanup(worker.STOP.update, requested=False)

    def _child(self, directory):
        """A stand-in for the runtime client: records its pid, then runs for 30 s."""
        pidfile = Path(directory) / "client.pid"
        code = (f"import os,time\nopen({str(pidfile)!r}+'.tmp','w').write(str(os.getpid()))\n"
                f"os.replace({str(pidfile)!r}+'.tmp',{str(pidfile)!r})\ntime.sleep(30)")
        return [sys.executable, "-c", code], pidfile

    @staticmethod
    def _alive(pid):
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        return True

    def test_sigterm_during_the_job_kills_its_client_then_removes_it_and_frames_no_result(self):
        self._stop_state()
        worker.install_stop_handler()
        removed = mock.Mock(return_value=True)
        with tempfile.TemporaryDirectory() as directory:
            client, pidfile = self._child(directory)
            def stop_once_running():
                while not pidfile.exists():
                    time.sleep(0.02)
                os.kill(os.getpid(), signal.SIGTERM)
            threading.Thread(target=stop_once_running, daemon=True).start()
            started = time.monotonic()
            with mock.patch.object(worker, "preflight"), mock.patch.object(worker, "command", return_value=client), \
                    mock.patch.object(worker, "removed", removed):
                frame = worker.launch(json.dumps(job()).encode(), config())
            self.assertLess(time.monotonic() - started, 10)
            pid = int(pidfile.read_text())
            self.assertFalse(self._alive(pid), "the runtime client survived the stop")
        removed.assert_called_once()
        self.assertEqual(frame["containment"], "removed")
        self.assertIsNone(frame["result"])

    def test_a_stop_requested_before_launch_runs_nothing(self):
        self._stop_state()
        worker.stop_requested(signal.SIGTERM, None)
        with mock.patch.object(worker, "preflight"), mock.patch.object(worker, "bounded") as run, \
                mock.patch.object(worker, "removed") as removed:
            frame = worker.launch(json.dumps(job()).encode(), config())
        run.assert_not_called()
        removed.assert_not_called()
        self.assertEqual(frame["containment"], "removed")
        self.assertIsNone(frame["result"])

    def test_a_stop_after_the_check_still_never_starts_the_client(self):
        # SIGTERM between launch's early check and the client start (while the job file is
        # written) is honoured by the run itself, before it starts anything.
        self._stop_state()
        removed = mock.Mock(return_value=True)
        with tempfile.TemporaryDirectory() as directory:
            client, pidfile = self._child(directory)
            def command(*_):
                worker.stop_requested(signal.SIGTERM, None)
                return client
            with mock.patch.object(worker, "preflight"), mock.patch.object(worker, "command", command), \
                    mock.patch.object(worker, "removed", removed):
                frame = worker.launch(json.dumps(job()).encode(), config())
            time.sleep(0.3)
            self.assertFalse(pidfile.exists(), "the client was started after the stop")
        removed.assert_called_once()
        self.assertIsNone(frame["result"])

    def test_sigterm_during_removal_or_failure_handling_interrupts_nothing(self):
        self._stop_state()
        worker.install_stop_handler()
        def removed(_):
            os.kill(os.getpid(), signal.SIGTERM)
            time.sleep(0.2)  # a raising handler would surface here
            return True
        def run(*_args, **_kwargs):
            os.kill(os.getpid(), signal.SIGTERM)
            time.sleep(0.2)
            raise worker.Refused()  # the job failed; its handling must still frame removal
        with mock.patch.object(worker, "preflight"), mock.patch.object(worker, "bounded", run), \
                mock.patch.object(worker, "removed", removed):
            frame = worker.launch(json.dumps(job()).encode(), config())
        self.assertEqual(frame["containment"], "removed")
        self.assertIsNone(frame["result"])
        self.assertTrue(worker.STOP["requested"])

    def test_an_unrequested_stoppable_run_is_unaffected(self):
        self._stop_state()
        self.assertEqual(worker.bounded([sys.executable, "-c", "print('ok')"], 5, 1024, stoppable=True),
                         (0, b"ok\n"))

    def test_output_capture_is_actually_bounded(self):
        with self.assertRaises(worker.Refused):
            worker.bounded([sys.executable, "-c", "import sys;sys.stdout.write('x'*8192)"], 2, 1024)
        self.assertEqual(worker.bounded([sys.executable, "-c", "print('ok')"], 2, 1024), (0, b"ok\n"))


if __name__ == "__main__":
    unittest.main()
