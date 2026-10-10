"""Opt-in scaling for offline test hang guards, never production timeouts."""
import math
import os

try:
    _SCALE = float(os.environ.get("AUTO_RE_TEST_TIMEOUT_SCALE", "1"))
except ValueError as error:
    raise ValueError("AUTO_RE_TEST_TIMEOUT_SCALE must be finite and between 1 and 20") from error
if not math.isfinite(_SCALE) or not 1 <= _SCALE <= 20:
    raise ValueError("AUTO_RE_TEST_TIMEOUT_SCALE must be finite and between 1 and 20")


def subprocess_timeout(seconds=15):
    return seconds * _SCALE
