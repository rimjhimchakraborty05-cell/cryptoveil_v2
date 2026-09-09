"""
test_entropy.py — 8 unit tests for agent/sensors/entropy_watcher.py

Run directly:
    python tests/test_entropy.py
"""
from __future__ import annotations

import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from agent.sensors.entropy_watcher import EntropyWatcher, shannon_entropy  # noqa: E402


class _FakeBroker:
    """Minimal stand-in for EventBroker.publish_threadsafe — records events."""

    def __init__(self):
        self.published = []

    def publish_threadsafe(self, event):
        self.published.append(event)


class TestShannonEntropy(unittest.TestCase):
    # 1
    def test_empty_bytes_has_zero_entropy(self):
        self.assertEqual(shannon_entropy(b""), 0.0)

    # 2
    def test_single_repeated_byte_has_zero_entropy(self):
        self.assertEqual(shannon_entropy(b"\x41" * 1000), 0.0)

    # 3
    def test_two_symbol_alternation_has_entropy_one(self):
        data = (b"\x00\x01") * 500
        self.assertAlmostEqual(shannon_entropy(data), 1.0, places=6)

    # 4
    def test_uniform_256_symbol_distribution_has_entropy_eight(self):
        data = bytes(range(256)) * 100  # every byte value equally often
        self.assertAlmostEqual(shannon_entropy(data), 8.0, places=6)

    # 5
    def test_english_text_has_low_to_moderate_entropy(self):
        text = (b"the quick brown fox jumps over the lazy dog " * 20)
        self.assertLess(shannon_entropy(text), 4.5)

    # 6
    def test_random_bytes_have_high_entropy(self):
        data = os.urandom(4096)
        self.assertGreaterEqual(shannon_entropy(data), 7.0)


class TestEntropyWatcherBurstDetection(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="cv_entropy_test_")
        self.broker = _FakeBroker()
        self.watcher = EntropyWatcher(
            broker=self.broker,
            watch_paths=[self.tmpdir],
            entropy_threshold=7.0,
            burst_window_seconds=60.0,
            burst_count_threshold=5,
        )

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _write_random_file(self, name: str) -> str:
        path = os.path.join(self.tmpdir, name)
        with open(path, "wb") as f:
            f.write(os.urandom(2048))
        return path

    # 7
    def test_single_high_entropy_write_does_not_trigger_burst(self):
        path = self._write_random_file("f0.bin")
        self.watcher.handle(path, "created")
        self.assertEqual(len(self.broker.published), 1)
        self.assertFalse(self.broker.published[0].burst_triggered)

    # 8
    def test_repeated_high_entropy_writes_trigger_burst(self):
        for i in range(6):  # exceeds burst_count_threshold=5
            path = self._write_random_file(f"f{i}.bin")
            self.watcher.handle(path, "created")
        self.assertTrue(any(ev.burst_triggered for ev in self.broker.published))
        last = self.broker.published[-1]
        self.assertEqual(last.severity.value, "critical")


if __name__ == "__main__":
    unittest.main(verbosity=2)
