"""Test hang guards only; the child is controlled Python, never a target."""
import os
from pathlib import Path
import runpy
import subprocess
import sys
import time
import unittest
from unittest.mock import patch

HELPER = Path(__file__).with_name("subprocess_timeout.py")
# Validate the run's environment during discovery, before any child starts.
subprocess_timeout = runpy.run_path(str(HELPER))["subprocess_timeout"]


class SubprocessTimeoutTests(unittest.TestCase):
    def guard(self, scale=None):
        with patch.dict(os.environ):
            os.environ.pop("AUTO_RE_TEST_TIMEOUT_SCALE", None)
            if scale is not None:
                os.environ["AUTO_RE_TEST_TIMEOUT_SCALE"] = scale
            return runpy.run_path(str(HELPER))["subprocess_timeout"]

    def test_default_is_exactly_fifteen_seconds(self):
        self.assertEqual(self.guard()(), 15)

    def test_valid_fractional_and_boundary_scales(self):
        for scale in ("1", "1.5", "4", "20"):
            with self.subTest(scale=scale):
                self.assertEqual(self.guard(scale)(), 15 * float(scale))

    def test_other_existing_base_guards_are_preserved_and_scaled(self):
        for seconds in (5, 10, 30, 60):
            with self.subTest(seconds=seconds):
                self.assertEqual(self.guard()(seconds), seconds)
                self.assertEqual(self.guard("4")(seconds), 4 * seconds)

    def test_invalid_scales_fail_on_load(self):
        for scale in ("", "invalid", "NaN", "inf", "-inf", "0", "-1", "0.99", "20.01", "1e999"):
            with self.subTest(scale=scale), self.assertRaisesRegex(
                    ValueError, "AUTO_RE_TEST_TIMEOUT_SCALE.*finite.*1.*20"):
                self.guard(scale)

    def test_sleeping_child_still_times_out_at_the_scaled_bound(self):
        timeout = self.guard("2")(0.1)
        start = time.monotonic()
        with self.assertRaises(subprocess.TimeoutExpired) as caught:
            subprocess.run([sys.executable, "-B", "-c", "import time; time.sleep(60)"],
                           capture_output=True, timeout=timeout)
        elapsed = time.monotonic() - start
        self.assertEqual(caught.exception.timeout, 0.2)
        self.assertGreaterEqual(elapsed, timeout)
        # Allow scheduling/kill/reap overhead; this is not a performance test.
        self.assertLess(elapsed, timeout + 5)


if __name__ == "__main__":
    unittest.main()
