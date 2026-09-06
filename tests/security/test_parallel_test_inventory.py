"""Exercise complete execution, failures and measurement in disposable suites."""

import contextlib
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from .support import load_script, REPO_ROOT

MODULE = load_script("ci/run_python_tests.py")
RUNNER = REPO_ROOT / "scripts/ci/run_python_tests.py"


class ParallelInventoryTests(unittest.TestCase):
    def fixture(self, root, body):
        (root / "test_sample.py").write_text("import unittest\nclass Sample(unittest.TestCase):\n" + body)

    def invoke(self, root, *extra, env=None):
        return subprocess.run([sys.executable, "-B", str(RUNNER), "--start", str(root),
                               "--workers", "2", *extra], capture_output=True, text=True,
                              env=env, timeout=60)

    def test_discovery_preserves_the_real_complete_inventory(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.fixture(root, " def test_first(self): pass\n def test_second(self): pass\n")
            with mock.patch.object(sys, "path", sys.path.copy()), mock.patch.dict(sys.modules):
                ids = MODULE.discover(root)
            self.assertEqual(ids, ["test_sample.Sample.test_first", "test_sample.Sample.test_second"])

    def test_discovery_rejects_loader_errors_empty_and_duplicate_cases(self):
        case = unittest.FunctionTestCase(lambda: None)
        for errors, cases in ((["fixture import error"], [case]), ([], []), ([], [case, case])):
            loader = mock.Mock(errors=errors)
            loader.discover.return_value = unittest.TestSuite(cases)
            with mock.patch.object(MODULE.unittest, "TestLoader", return_value=loader), self.assertRaises(ValueError):
                MODULE.discover(Path("unused-fixture"))

    def test_partitions_preserve_every_test_and_refuse_invalid_inputs(self):
        ids = ["a", "b", "c", "d", "e"]
        self.assertEqual(MODULE.partition(ids, 2), [["a", "c", "e"], ["b", "d"]])
        for data, workers in (([], 2), (["a", "a"], 2), (ids, 0), (ids, 5)):
            with self.subTest(data=data, workers=workers), self.assertRaises(ValueError):
                MODULE.partition(data, workers)

    def test_worker_receipt_requires_exact_execution_and_success(self):
        good = dict.fromkeys(MODULE.COUNTS, 0)
        good.update(executed=["a", "b"], tests_run=2, successful=True, skipped=1)
        MODULE.validate_result(["a", "b"], good)
        with self.assertRaises(ValueError):
            MODULE.validate_result(["a", "b"], {**good, "foreign": 0})
        changes = [("executed", ["a"]), ("executed", ["b", "a"]),
                   ("executed", ["a", "a"]), ("executed", ["a", "foreign"]),
                   ("tests_run", 1), ("skipped", True), ("skipped", -1),
                   ("skipped", 3), ("successful", False), ("successful", 1),
                   ("failures", 1), ("errors", 1), ("unexpected_successes", 1)]
        for key, value in changes:
            changed = {**good, key: value}
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                MODULE.validate_result(["a", "b"], changed)
        for key in good:
            changed = copy.deepcopy(good)
            del changed[key]
            with self.subTest(missing=key), self.assertRaises(ValueError):
                MODULE.validate_result(["a", "b"], changed)

    def test_worker_loader_errors_prevent_test_execution(self):
        executed = []
        case = unittest.FunctionTestCase(lambda: executed.append(True))
        loader = mock.Mock(errors=["fixture import error"])
        loader.loadTestsFromNames.return_value = unittest.TestSuite([case])
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(sys, "path", sys.path.copy()):
            config = dict(start=temporary, ids=[case.id()], verbosity=0,
                          result=str(Path(temporary) / "result.json"))
            with mock.patch.object(MODULE.unittest, "TestLoader", return_value=loader), self.assertRaises(ValueError):
                MODULE.worker(config)
            self.assertEqual(executed, [])

    def test_nonzero_process_exit_overrides_successful_test_result(self):
        process = mock.Mock()
        process.wait.return_value = 7
        process.poll.return_value = 7

        def start(config, directory, index, covered):
            record = dict.fromkeys(MODULE.COUNTS, 0)
            record.update(executed=config["ids"], tests_run=1, successful=True)
            Path(config["result"]).write_text(json.dumps(record))
            log = directory / "fixture.log"
            log.write_text("")
            return process, log.open("wb"), log

        with mock.patch.object(MODULE, "discover", return_value=["fixture"]), mock.patch.object(MODULE, "start_worker", side_effect=start), contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(ValueError):
                MODULE.run(Path("unused-fixture"), 1)

    def test_invalid_timeout_refuses_before_discovery(self):
        for timeout in (0, -1, 1201):
            with self.subTest(timeout=timeout), mock.patch.object(MODULE, "discover") as discover:
                with self.assertRaises(ValueError):
                    MODULE.run(Path("unused-fixture"), 1, timeout=timeout)
                discover.assert_not_called()

    def test_real_workers_report_pass_skip_and_expected_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.fixture(root, " def test_pass(self): self.assertTrue(True)\n"
                         " @unittest.skip('fixture')\n def test_skip(self): pass\n"
                         " @unittest.expectedFailure\n def test_expected(self): self.fail('fixture')\n")
            result = self.invoke(root)
            self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
            receipt = json.loads(result.stdout.splitlines()[-1])
            self.assertEqual((receipt["discovered"], receipt["tests_run"], receipt["workers"],
                              receipt["skipped"], receipt["expected_failures"]), (3, 3, 2, 1, 1))

    def test_empty_import_error_failure_error_and_unexpected_success_fail(self):
        cases = ("", "raise RuntimeError('import fixture')\n", " def test_fail(self): self.fail('fixture')\n",
                 " def test_error(self): raise RuntimeError('fixture')\n",
                 " @unittest.expectedFailure\n def test_unexpected(self): pass\n")
        for body in cases:
            with self.subTest(body=body), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                if body.startswith("raise"):
                    (root / "test_sample.py").write_text(body)
                elif body:
                    self.fixture(root, body)
                result = self.invoke(root)
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertNotIn('"test_inventory": "PASS"', result.stdout)

    def test_missing_result_and_timeout_never_authorize_success(self):
        for body, timeout in ((" def test_exit(self): __import__('os')._exit(0)\n", 10),
                              (" def test_wait(self): __import__('time').sleep(30)\n", 0.05)):
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                self.fixture(root, body)
                # Discovery is mocked only to avoid cross-fixture module caching;
                # the child loader, test, process timeout and missing receipt are real.
                with mock.patch.object(MODULE, "discover", return_value=["test_sample.Sample." + ("test_exit" if timeout == 10 else "test_wait")]), contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                    with self.assertRaises(ValueError):
                        MODULE.run(root, 1, timeout=timeout)

    @unittest.skipUnless(os.name == "posix", "process groups require POSIX")
    def test_stop_worker_terminates_a_live_session_and_ordinary_child(self):
        source = "import subprocess, sys, time; subprocess.Popen([sys.executable, '-B', '-c', 'import time; time.sleep(30)']); print('ready', flush=True); time.sleep(30)"
        process = subprocess.Popen([sys.executable, "-B", "-c", source], start_new_session=True, stdout=subprocess.PIPE)
        try:
            self.assertTrue(select.select([process.stdout], [], [], 5)[0], "fixture did not start")
            self.assertEqual(process.stdout.readline(), b"ready\n")
            MODULE.stop_worker(process)
            self.assertLess(process.returncode, 0)
            self.assertTrue(select.select([process.stdout], [], [], 2)[0], "ordinary child retained the output pipe")
            self.assertEqual(process.stdout.read(), b"")
        finally:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
            process.stdout.close()

    @unittest.skipUnless(importlib.util.find_spec("coverage"), "requires the pinned coverage environment")
    def test_coverage_includes_worker_and_test_subprocess_execution(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "fixture_target.py").write_text("def parent():\n return 1\n\ndef child():\n return 2\n\nif __name__ == '__main__':\n child()\n")
            self.fixture(root, " def test_parent(self): self.assertEqual(__import__('fixture_target').parent(), 1)\n"
                         " def test_child(self):\n  import subprocess, sys, fixture_target\n  subprocess.run([sys.executable, '-B', fixture_target.__file__], check=True)\n")
            config = root / "coveragerc"
            config.write_text("[run]\nparallel = True\npatch = subprocess\nsource = " + str(root) + "\n")
            env = {**os.environ, "COVERAGE_FILE": str(root / "data"), "COVERAGE_RCFILE": str(config)}
            result = self.invoke(root, "--coverage", env=env)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            for args in (("combine",), ("json", "-o", str(root / "report.json"))):
                result = subprocess.run([sys.executable, "-B", "-m", "coverage", *args], env=env, capture_output=True, text=True, timeout=30)
                self.assertEqual(result.returncode, 0, result.stderr)
            files = json.loads((root / "report.json").read_text())["files"]
            target = next(record for path, record in files.items() if path.endswith("fixture_target.py"))
            self.assertTrue({2, 5}.issubset(target["executed_lines"]), target)
