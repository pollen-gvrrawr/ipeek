"""Unit tests for gui_app.py.

The report formatting is tested without a window. The window tests open a
real (hidden) Tkinter window and are skipped if no display is available.
Run with:   python -m unittest discover -s tests -v
"""
import os
import sys
import tkinter as tk
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import gui_app  # noqa: E402
import ip_info_app as core  # noqa: E402

DETAILS = {"ip": "8.8.8.8", "isp": "GOOGLE", "asn": "AS15169", "country": "United States",
           "country_code": "US", "region": "California", "city": "Mountain View",
           "postal": None, "latitude": 37.42, "longitude": -122.08,
           "timezone": "America/Los_Angeles", "utc_offset": "-0700", "source": "ipapi.co"}


def public_report():
    return {"analysis": core.analyze_ip("8.8.8.8"), "details": dict(DETAILS)}


class ReportRowsTests(unittest.TestCase):
    def test_public_ipv4_rows(self):
        rows = gui_app.report_rows(public_report())
        labels = {label: value for kind, label, value in rows if kind == "row"}
        self.assertEqual(rows[0], ("title", "IPv4 address: 8.8.8.8", ""))
        self.assertEqual(labels["Class"], "A")
        self.assertEqual(labels["ASN"], "AS15169")
        self.assertIsNone(labels["Postal code"])          # shown as N/A in the window

    def test_ipv6_rows_show_expanded_form(self):
        report = {"analysis": core.analyze_ip("2001:db8::1"),
                  "details": {"ip": "2001:db8::1", "error": "not public"}}
        rows = gui_app.report_rows(report)
        labels = {label: value for kind, label, value in rows if kind == "row"}
        self.assertEqual(labels["Expanded"], "2001:0db8:0000:0000:0000:0000:0000:0001")
        self.assertEqual(rows[-1][0], "error")

    def test_map_url(self):
        self.assertEqual(gui_app.map_url([public_report()]),
                         "https://www.google.com/maps?q=37.42,-122.08")
        self.assertIsNone(gui_app.map_url([]))


class WindowTests(unittest.TestCase):
    def setUp(self):
        try:
            self.app = gui_app.IPeekApp(autoload=False)
        except tk.TclError:
            self.skipTest("no display available")
        self.app.withdraw()

    def tearDown(self):
        self.app.destroy()

    def pane_text(self, pane):
        return pane.text.get("1.0", "end")

    def test_show_my_ips_fills_tiles_and_report(self):
        results = {"generated": "2026-11-03T10:00:00", "public_ipv4": "8.8.8.8",
                   "public_ipv6": None, "reports": [public_report()]}
        self.app.show_my_ips(results)
        self.assertEqual(self.app.v4_value.cget("text"), "8.8.8.8")
        self.assertIn("not available", self.app.v6_value.cget("text"))
        self.assertIn("Mountain View", self.pane_text(self.app.mine_pane))
        self.assertIsNotNone(self.app.mine_pane.url)        # "Open map" is enabled

    def test_invalid_address_is_not_looked_up(self):
        with mock.patch.object(core, "build_report") as build:
            self.app.lookup("999.1.1.1")
        build.assert_not_called()
        self.assertIn("not a valid", self.pane_text(self.app.lookup_pane))

    def test_lookup_runs_core_and_shows_result(self):
        with mock.patch.object(core, "build_report", return_value=public_report()):
            self.app.lookup("8.8.8.8")
            done, result, error = self.app._results.get(timeout=5)
        done(result, error)
        self.assertIn("GOOGLE", self.pane_text(self.app.lookup_pane))
        self.assertIsNotNone(self.app.lookup_pane.data)


if __name__ == "__main__":
    unittest.main()
