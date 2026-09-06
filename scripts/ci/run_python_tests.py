#!/usr/bin/env python3
"""Run every discovered unittest once in bounded, isolated processes."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import tempfile
import time
import unittest

COUNTS = ("tests_run", "failures", "errors", "skipped", "expected_failures", "unexpected_successes")


def test_ids(suite):
    """Preserve unittest's discovery order while flattening its suites."""
    for test in suite:
        if isinstance(test, unittest.TestSuite):
            yield from test_ids(test)
        else:
            yield test.id()


def discover(start):
    loader = unittest.TestLoader()
    ids = list(test_ids(loader.discover(str(start), pattern="test_*.py")))
    if loader.errors:
        print("\n".join(loader.errors), file=sys.stderr)
    if loader.errors or not ids or len(ids) != len(set(ids)):
        raise ValueError("discovery is empty, duplicated or contains import errors")
    return ids


def partition(ids, workers):
    if not 1 <= workers <= 4:
        raise ValueError("worker count must be between one and four")
    groups = [ids[index::workers] for index in range(min(workers, len(ids)))]
    flattened = [item for group in groups for item in group]
    if not groups or sorted(flattened) != sorted(ids) or len(flattened) != len(set(flattened)):
        raise ValueError("partition does not contain every test exactly once")
    return groups


def validate_result(expected, record):
    """A zero process exit is insufficient without an exact execution census."""
    if set(record) != {*COUNTS, "executed", "successful"}:
        raise ValueError("worker result is incomplete or foreign")
    if record["executed"] != expected or record["tests_run"] != len(expected):
        raise ValueError("worker did not execute its exact assigned tests")
    if any(type(record[key]) is not int or record[key] < 0 for key in COUNTS):
        raise ValueError("worker counts are malformed")
    if record["skipped"] + record["expected_failures"] > record["tests_run"]:
        raise ValueError("worker outcome counts exceed its execution census")
    if record["successful"] is not True or any(record[key] for key in ("failures", "errors", "unexpected_successes")):
        raise ValueError("worker reported unsuccessful tests")


def worker(config):
    sys.path.insert(0, config["start"])
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromNames(config["ids"])
    if loader.errors or list(test_ids(suite)) != config["ids"]:
        raise ValueError("worker could not load its exact assigned tests")

    class RecordingResult(unittest.TextTestResult):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.executed = []

        def startTest(self, test):
            self.executed.append(test.id())
            super().startTest(test)

    result = unittest.TextTestRunner(verbosity=config["verbosity"], resultclass=RecordingResult).run(suite)
    record = {"executed": result.executed, "successful": result.wasSuccessful(),
              "tests_run": result.testsRun, "failures": len(result.failures),
              "errors": len(result.errors), "skipped": len(result.skipped),
              "expected_failures": len(result.expectedFailures),
              "unexpected_successes": len(result.unexpectedSuccesses)}
    Path(config["result"]).write_text(json.dumps(record), encoding="utf-8")
    return 0 if result.wasSuccessful() else 1


def start_worker(config, directory, index, covered):
    config_path = directory / f"worker-{index}.json"
    log_path = directory / f"worker-{index}.log"
    config_path.write_text(json.dumps(config), encoding="utf-8")
    command = [sys.executable, "-B", str(Path(__file__).resolve()), "--supervise", str(config_path)]
    if covered:
        command += ["--coverage"]
    output = log_path.open("wb")
    try:
        process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=output, stderr=subprocess.STDOUT, start_new_session=True)
    except BaseException:
        output.close()
        raise
    return process, output, log_path


def supervise(config_path, covered):
    """Keep a live session owner until the parent disposes of test children."""
    config = json.loads(config_path.read_text(encoding="utf-8"))
    command = [sys.executable, "-B"]
    if covered:
        command += ["-m", "coverage", "run"]
    command += [str(Path(__file__).resolve()), "--worker", str(config_path)]
    child = subprocess.Popen(command, stdin=subprocess.DEVNULL)
    while child.poll() is None:
        if os.name == "posix":
            if select.select([sys.stdin.buffer], [], [], 0.05)[0]:
                os.killpg(os.getpgrp(), signal.SIGKILL)
        else:
            time.sleep(0.05)
    code = child.returncode
    destination = Path(config["exit_status"])
    pending = destination.with_suffix(".pending")
    pending.write_text(json.dumps(code), encoding="utf-8")
    pending.replace(destination)
    # Coverage has saved and the test process has exited. Keeping this leader
    # alive avoids PID reuse and Darwin's unsignalable zombie-only groups.
    sys.stdin.buffer.read(1)
    if os.name == "posix":
        os.killpg(os.getpgrp(), signal.SIGKILL)
    return code


def wait_worker(process, timeout, exit_status):
    """Wait for the actual test-process exit; never reap the session owner."""
    deadline = time.monotonic() + timeout
    while True:
        if os.name == "posix":
            exited = os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is not None
        else:
            exited = process.poll() is not None
        if exited:
            raise ValueError("worker supervisor exited before cleanup")
        if exit_status.is_file():
            code = json.loads(exit_status.read_text(encoding="utf-8"))
            if type(code) is not int or not -127 <= code <= 255:
                raise ValueError("worker process exit is malformed")
            return code
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise subprocess.TimeoutExpired(process.args, timeout)
        time.sleep(min(0.01, remaining))


def stop_worker(process):
    # The supervisor remains alive until group cleanup, retaining its PID.
    if process.returncode is not None:
        return
    try:
        if os.name == "posix":
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        else:
            process.kill()
    finally:
        if process.stdin is not None:
            process.stdin.close()
        process.wait(timeout=5)


def run(start, workers, covered=False, timeout=1200, verbosity=1):
    if not 0 < timeout <= 1200:
        raise ValueError("worker timeout must be positive and at most twenty minutes")
    started = time.monotonic()
    ids = discover(start)
    groups = partition(ids, workers)
    totals = dict.fromkeys(COUNTS, 0)
    failed = False
    with tempfile.TemporaryDirectory(prefix="platform-unittest-") as scratch:
        directory = Path(scratch)
        tasks = []
        try:
            for index, group in enumerate(groups):
                config = {"start": str(start), "ids": group, "verbosity": verbosity,
                          "result": str(directory / f"result-{index}.json"),
                          "exit_status": str(directory / f"exit-{index}.json")}
                tasks.append((group, config, *start_worker(config, directory, index, covered)))
            for group, config, process, output, log_path in tasks:
                try:
                    code = wait_worker(process, max(0, started + timeout - time.monotonic()), Path(config["exit_status"]))
                    sys.stdout.write(log_path.read_text(encoding="utf-8", errors="replace"))
                    record = json.loads(Path(config["result"]).read_text(encoding="utf-8"))
                    validate_result(group, record)
                    if code != 0:
                        raise ValueError("worker exit contradicts its result")
                    for key in COUNTS:
                        totals[key] += record[key]
                except Exception as error:
                    print(f"WORKER_FAILED: {type(error).__name__}: {error}", file=sys.stderr)
                    failed = True
        finally:
            for _, _, process, output, _ in tasks:
                try:
                    stop_worker(process)
                except (OSError, subprocess.TimeoutExpired) as error:
                    print(f"WORKER_CLEANUP_FAILED: {error}", file=sys.stderr)
                    failed = True
                finally:
                    output.close()
    if failed or totals["tests_run"] != len(ids):
        raise ValueError("complete discovered test inventory did not pass")
    print(json.dumps({"test_inventory": "PASS", "discovered": len(ids), "workers": len(groups),
                      "elapsed_seconds": round(time.monotonic() - started, 3), **totals}, sort_keys=True))
    return 0


def main():
    # Match `python -m unittest`: existing suites also import tests as a
    # package rooted at the working directory, independently of discovery.
    sys.path.insert(0, str(Path.cwd()))

    def interrupted(signum, frame):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, interrupted)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--start", type=Path, default=Path("tests"))
    parser.add_argument("--workers", type=int, default=min(4, os.cpu_count() or 1))
    parser.add_argument("--coverage", action="store_true")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--worker", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--supervise", type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    try:
        if args.worker is not None:
            return worker(json.loads(args.worker.read_text(encoding="utf-8")))
        if args.supervise is not None:
            return supervise(args.supervise, args.coverage)
        return run(args.start.resolve(), args.workers, args.coverage, verbosity=2 if args.verbose else 1)
    except (OSError, ValueError) as error:
        print(f"TEST_INVENTORY_FAILED: {error}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
