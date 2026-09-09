"""
test_browser_profiles.py — Unit tests for multi-browser profile discovery sensor and endpoints.
"""
from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from agent.sensors.browser_profiles import BrowserProfileScanner  # noqa: E402
from agent.bus.events import BrowserTelemetryEvent  # noqa: E402


class TestBrowserProfiles(unittest.TestCase):
    def test_scanner_returns_list(self):
        profiles = BrowserProfileScanner.get_all_profiles()
        self.assertIsInstance(profiles, list)
        for p in profiles:
            self.assertIn("browser", p)
            self.assertIn("profile_dir", p)
            self.assertIn("display_name", p)
            self.assertIn("email", p)

    def test_browser_telemetry_event_has_email_fields(self):
        ev = BrowserTelemetryEvent(
            event_kind="site_visit",
            hostname="example.com",
            trust_score=85,
            user_email="testuser@gmail.com",
            browser_name="Google Chrome",
        )
        self.assertEqual(ev.user_email, "testuser@gmail.com")
        self.assertEqual(ev.browser_name, "Google Chrome")
        self.assertEqual(ev.topic, "browser.telemetry")


if __name__ == "__main__":
    unittest.main()
