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

    def test_batch_tab_loads_file_and_shows_results(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "ips.txt")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("8.8.8.8\n192.168.1.10\n8.8.8.8\n")
            self.app.load_batch_file(path)
        self.assertEqual(self.app.batch_entries, [("8.8.8.8", 2), ("192.168.1.10", 1)])
        self.assertIn("2 unique", self.app.batch_info.cget("text"))

        def fake(ip):
            details = dict(DETAILS) if ip == "8.8.8.8" else {"ip": ip, "error": "not public"}
            return {"analysis": core.analyze_ip(ip), "details": details}
        with mock.patch.object(core, "build_report", side_effect=fake):
            self.app.run_batch()
            while True:                       # progress updates first, then the result
                done, result, error = self.app._results.get(timeout=5)
                done(result, error)
                if done == self.app.show_batch:
                    break
        text = self.pane_text(self.app.batch_pane)
        # one vertical report per address, in file order, like the Look up tab
        self.assertLess(text.index("IPv4 address: 8.8.8.8"),
                        text.index("IPv4 address: 192.168.1.10"))
        self.assertEqual(text.count("Address analysis"), 2)
        for label in ("Binary", "Reverse DNS name", "ISP / Organization", "Postal code",
                      "Timezone", "Times seen in file"):
            self.assertIn(label, text)
        self.assertIn("GOOGLE", text)
        self.assertIn("Could not get online details: not public", text)
        self.assertEqual(len(self.app.batch_pane.data["reports"]), 2)   # Save all (JSON)
        self.assertIn("1 public", self.app.batch_info.cget("text"))

        # Table view has the same results, one row per address
        columns = [c for c, _, _ in gui_app.BATCH_COLUMNS]
        rows = [dict(zip(columns, self.app.batch_table.item(i, "values")))
                for i in self.app.batch_table.get_children()]
        self.assertEqual((rows[0]["ip"], rows[0]["count"], rows[0]["isp"]),
                         ("8.8.8.8", "2", "GOOGLE"))
        self.assertEqual(rows[0]["postal"], "N/A")             # empty, like the report
        self.assertIn("not public", rows[1]["note"])

    def _run_fake_batch(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "ips.txt")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("8.8.8.8\n192.168.1.10\n8.8.4.4\n")
            self.app.load_batch_file(path)

        def fake(ip):
            public = not ip.startswith("192.")
            details = dict(DETAILS, ip=ip) if public else {"ip": ip, "error": "not public"}
            return {"analysis": core.analyze_ip(ip), "details": details}
        with mock.patch.object(core, "build_report", side_effect=fake):
            self.app.run_batch()
            while True:
                done, result, error = self.app._results.get(timeout=5)
                done(result, error)
                if done == self.app.show_batch:
                    break

    def test_find_highlights_every_match_and_steps_through_them(self):
        self._run_fake_batch()
        text = self.app.batch_pane.text
        self.app.find_var.set("google")                 # case-insensitive
        self.assertEqual(len(self.app.find_matches), 2)  # 8.8.8.8 and 8.8.4.4
        self.assertEqual(self.app.find_count.cget("text"), "1 of 2")
        self.assertEqual(len(text.tag_ranges("match")), 4)        # 2 ranges, start+end each
        first = text.index("current.first")
        self.app.find_step(1)
        self.assertEqual(self.app.find_count.cget("text"), "2 of 2")
        self.assertNotEqual(text.index("current.first"), first)
        self.app.find_step(1)                           # wraps around to the first
        self.assertEqual(self.app.find_count.cget("text"), "1 of 2")
        self.app.find_step(-1)                          # and backwards to the last
        self.assertEqual(self.app.find_count.cget("text"), "2 of 2")

    def test_find_no_results_and_clear(self):
        self._run_fake_batch()
        self.app.find_var.set("cloudflare")
        self.assertEqual(self.app.find_count.cget("text"), "No results")
        self.app.find_var.set("")
        self.assertEqual(self.app.find_count.cget("text"), "")
        self.assertEqual(self.app.batch_pane.text.tag_ranges("match"), ())

    def test_find_in_table_view_marks_matching_rows(self):
        self._run_fake_batch()
        self.app.batch_view.set("table")
        self.app.set_batch_view()
        self.app.find_var.set("192.168")
        table = self.app.batch_table
        self.assertEqual(len(self.app.find_matches), 1)
        self.assertIn("match", table.item(self.app.find_matches[0], "tags"))
        self.assertEqual(table.selection(), (self.app.find_matches[0],))
        self.assertEqual(table.item(table.selection()[0], "values")[0], "192.168.1.10")

    def test_view_toggle_switches_between_reports_and_table(self):
        self.app.update_idletasks()
        self.assertEqual(self.app.batch_view.get(), "reports")      # default
        self.assertTrue(self.app.batch_pane.winfo_manager())
        self.assertFalse(self.app.batch_table_frame.winfo_manager())
        self.app.batch_view.set("table")
        self.app.set_batch_view()
        self.assertFalse(self.app.batch_pane.winfo_manager())
        self.assertTrue(self.app.batch_table_frame.winfo_manager())


class BatchReportRowsTests(unittest.TestCase):
    def test_failed_public_lookup_is_flagged_in_table(self):
        row = dict.fromkeys(gui_app.batch_lookup.CSV_COLUMNS, "")
        row.update(ip="1.1.1.1", count=1, scope="Public (globally routable)",
                   error="ipapi.co: RateLimited")
        values, failed = gui_app.batch_table_values(row)
        self.assertTrue(failed)
        self.assertEqual(values[-1], "ipapi.co: RateLimited")

    def test_table_formats_like_the_report(self):
        report = {"analysis": core.analyze_ip("2001:4860:4860::8888"),
                  "details": dict(DETAILS, ip="2001:4860:4860::8888")}
        row = gui_app.batch_lookup.result_row("2001:4860:4860::8888", 1, report)
        values, _ = gui_app.batch_table_values(row)
        cells = dict(zip([h for _, h, _ in gui_app.BATCH_COLUMNS], values))
        self.assertEqual(cells["Expanded"], "2001:4860:4860:0000:0000:0000:0000:8888")
        self.assertEqual(cells["Country"], "United States (US)")
        self.assertEqual(cells["Timezone"], "America/Los_Angeles (UTC-0700)")

    def test_same_rows_as_single_report_plus_times_seen(self):
        report = public_report()
        row = gui_app.batch_lookup.result_row("8.8.8.8", 3, report)
        rows = gui_app.batch_report_rows(row, report)
        self.assertEqual(rows[0], ("title", "IPv4 address: 8.8.8.8", ""))
        self.assertEqual(rows[1], ("row", "Times seen in file", 3))
        self.assertEqual(rows[2:], gui_app.report_rows(report)[1:])

    def test_crashed_lookup_shows_error(self):
        row = gui_app.batch_lookup.result_row("1.1.1.1", 1, error="boom")
        rows = gui_app.batch_report_rows(row)
        self.assertEqual(rows[-1], ("error", "", "Lookup failed: boom"))


if __name__ == "__main__":
    unittest.main()
