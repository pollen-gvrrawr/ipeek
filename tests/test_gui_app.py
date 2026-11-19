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
        self.app.batch_find.var.set("google")                 # case-insensitive
        self.assertEqual(len(self.app.batch_find.matches), 2)  # 8.8.8.8 and 8.8.4.4
        self.assertEqual(self.app.batch_find.count.cget("text"), "1 of 2")
        self.assertEqual(len(text.tag_ranges("match")), 4)        # 2 ranges, start+end each
        first = text.index("current.first")
        self.app.batch_find.step(1)
        self.assertEqual(self.app.batch_find.count.cget("text"), "2 of 2")
        self.assertNotEqual(text.index("current.first"), first)
        self.app.batch_find.step(1)                           # wraps around to the first
        self.assertEqual(self.app.batch_find.count.cget("text"), "1 of 2")
        self.app.batch_find.step(-1)                          # and backwards to the last
        self.assertEqual(self.app.batch_find.count.cget("text"), "2 of 2")

    def test_find_no_results_and_clear(self):
        self._run_fake_batch()
        self.app.batch_find.var.set("cloudflare")
        self.assertEqual(self.app.batch_find.count.cget("text"), "No results")
        self.app.batch_find.var.set("")
        self.assertEqual(self.app.batch_find.count.cget("text"), "")
        self.assertEqual(self.app.batch_pane.text.tag_ranges("match"), ())

    def test_find_in_table_view_marks_matching_rows(self):
        self._run_fake_batch()
        self.app.batch_view.set("table")
        self.app.set_batch_view()
        self.app.batch_find.var.set("192.168")
        table = self.app.batch_table
        self.assertEqual(len(self.app.batch_find.matches), 1)
        self.assertIn("match", table.item(self.app.batch_find.matches[0], "tags"))
        self.assertEqual(table.selection(), (self.app.batch_find.matches[0],))
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

    def test_batch_whois_mode_shows_owner_in_both_views(self):
        self.app.batch_mode.set("whois")
        self.app.set_batch_mode()
        result = {"ip": "8.8.8.8", "ptr_name": "8.8.8.8.in-addr.arpa",
                  "dns": {"hostname": "dns.google", "aliases": [], "forward_confirmed": True,
                          "error": None},
                  "whois": {"owner": "Google LLC", "network_name": "GOGL",
                            "range": "8.8.8.0 - 8.8.8.255", "cidr": "8.8.8.0/24",
                            "type": "DIRECT ALLOCATION", "country": None,
                            "abuse_email": "network-abuse@google.com",
                            "registered": "2023-12-28", "last_changed": "2023-12-28",
                            "registry": "ARIN (North America)", "source": "https://rdap"}}
        private = {"ip": "192.168.1.1", "ptr_name": "1.1.168.192.in-addr.arpa",
                   "dns": {"hostname": None, "aliases": [], "forward_confirmed": None,
                           "error": "no PTR record"},
                   "whois_error": "not a public address, so it has no public WHOIS record"}
        self.app.batch_entries, self.app.batch_path = [("8.8.8.8", 2), ("192.168.1.1", 1)], "x.txt"
        with mock.patch.object(gui_app.reverse_whois, "lookup",
                               side_effect=lambda ip, cache=None: result if ip == "8.8.8.8"
                               else private):
            self.app.run_batch()
            while True:
                done, value, error = self.app._results.get(timeout=5)
                done(value, error)
                if done == self.app.show_batch:
                    break
        text = self.pane_text(self.app.batch_pane)
        self.assertIn("Reverse DNS / WHOIS: 8.8.8.8", text)
        self.assertIn("Times seen in file", text)
        self.assertIn("Google LLC", text)
        columns = [c for c, _, _ in gui_app.WHOIS_BATCH_COLUMNS]
        rows = [dict(zip(columns, self.app.batch_table.item(i, "values")))
                for i in self.app.batch_table.get_children()]
        self.assertEqual((rows[0]["hostname"], rows[0]["owner"]), ("dns.google", "Google LLC"))
        self.assertEqual(rows[1]["hostname"], "no PTR record")
        self.assertIn("not public", rows[1]["note"])
        self.assertIn("1 with a network owner", self.app.batch_info.cget("text"))
        self.assertEqual(self.app.batch_result_mode, "whois")

    def test_switching_batch_mode_clears_old_results(self):
        self._run_fake_batch()                          # IP-details results on screen
        self.assertTrue(self.app.batch_table.get_children())
        self.app.batch_mode.set("whois")
        self.app.set_batch_mode()
        self.assertEqual(self.app.batch_table.get_children(), ())
        self.assertEqual(self.app.batch_rows, [])
        self.assertIn("disabled", self.app.batch_export_btn.state())
        self.assertEqual(self.app.batch_table["columns"][3], "hostname")   # after From hostname

    def test_batch_both_mode_with_hostnames(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "mixed.txt")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("8.8.8.8\ndns.google\nnope.invalid\n")
            self.app.load_batch_file(path)
            self.assertEqual(self.app.batch_entries, [("8.8.8.8", 1)])   # names off
            self.app.batch_hostnames.set(True)
            self.app._batch_hostnames_changed()                          # re-reads the file
        self.assertIn("1 unique IP address(es) and 2 hostname(s) found",
                      self.app.batch_info.cget("text"))
        self.app.batch_mode.set("both")
        self.app.set_batch_mode()

        def report(ip):
            return {"analysis": core.analyze_ip(ip), "details": dict(DETAILS, ip=ip)}

        def whois(ip, cache=None):
            return {"ip": ip, "ptr_name": "x.arpa",
                    "dns": {"hostname": "dns.google", "aliases": [], "forward_confirmed": True,
                            "error": None},
                    "whois": {"owner": "Google LLC", "network_name": "GOGL",
                              "range": "8.8.8.0 - 8.8.8.255", "cidr": "8.8.8.0/24",
                              "type": "DIRECT ALLOCATION", "country": None,
                              "abuse_email": "network-abuse@google.com",
                              "registered": "2023-12-28", "last_changed": "2023-12-28",
                              "registry": "ARIN (North America)", "source": "https://rdap"}}

        def resolver(name):
            if name == "dns.google":
                return ["8.8.8.8", "8.8.4.4"]
            raise OSError("the name does not exist or has no address")
        with mock.patch.object(core, "build_report", side_effect=report), \
                mock.patch.object(gui_app.reverse_whois, "lookup", side_effect=whois), \
                mock.patch.object(gui_app.batch_lookup, "resolve_hostname", side_effect=resolver), \
                mock.patch.object(gui_app.batch_lookup.socket, "getaddrinfo",   # no real DNS
                                  side_effect=AssertionError("real DNS lookup in a test")):
            self.app.run_batch()
            while True:
                done, value, error = self.app._results.get(timeout=5)
                done(value, error)
                if done == self.app.show_batch:
                    break
        text = self.pane_text(self.app.batch_pane)
        for expected in ("ISP / Organization", "GOOGLE", "Reverse DNS (hostname)", "Google LLC",
                         "From hostname in file"):
            self.assertIn(expected, text)
        self.assertEqual(text.count("Address analysis"), 2)            # 8.8.8.8 and 8.8.4.4
        columns = [c for c, _, _ in gui_app.BOTH_BATCH_COLUMNS]
        rows = [dict(zip(columns, self.app.batch_table.item(i, "values")))
                for i in self.app.batch_table.get_children()]
        self.assertEqual((rows[0]["ip"], rows[0]["count"], rows[0]["from_hostname"]),
                         ("8.8.8.8", "2", "dns.google"))
        self.assertEqual((rows[0]["isp"], rows[0]["owner"]), ("GOOGLE", "Google LLC"))
        self.assertIn("Could not resolve 1 hostname(s): nope.invalid",
                      self.app.batch_info.cget("text"))
        self.assertEqual(self.app.batch_result_mode, "both")

    def _temporary_history(self):
        import tempfile
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        for name, value in (("ENABLED", True),
                            ("PATH", os.path.join(tmp.name, "history.jsonl"))):
            patcher = mock.patch.object(gui_app.history, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_my_ips_shows_public_ip_change(self):
        self._temporary_history()
        first = {"generated": "2026-11-19T10:00:00", "public_ipv4": "1.1.1.1",
                 "public_ipv6": None, "reports": []}
        self.app.show_my_ips(first)
        self.assertIn("First check", self.app.ip_change.cget("text"))
        self.app.show_my_ips(dict(first, public_ipv4="2.2.2.2"))
        self.assertIn("Public IPv4 changed: 1.1.1.1 -> 2.2.2.2", self.app.ip_change.cget("text"))

    def test_history_tab_lists_lookups_and_changes(self):
        self._temporary_history()
        for ip in ("1.1.1.1", "2.2.2.2"):
            gui_app.history.record_my_ips({"public_ipv4": ip, "public_ipv6": None,
                                           "reports": []})
        gui_app.history.record("lookup", "8.8.8.8", "Public, Google LLC, US")
        self.app.tabs.select(self.app.history_tab)
        self.app.update()                                 # fires <<NotebookTabChanged>>
        rows = [self.app.history_table.item(i, "values")
                for i in self.app.history_table.get_children()]
        self.assertEqual(rows[0][2], "8.8.8.8")           # newest first
        self.assertEqual(len(rows), 3)
        self.assertIn("1 public IP change(s) in 2 check(s)",
                      self.app.history_info.cget("text"))
        self.app.history_view.set("changes")
        self.app.refresh_history()
        rows = [self.app.history_table.item(i, "values")
                for i in self.app.history_table.get_children()]
        self.assertEqual(rows, [rows[0]])
        self.assertEqual(rows[0][1:3], ("Public IPv4 changed", "2.2.2.2"))

    def _fill_history(self):
        self._temporary_history()
        for ip in ("1.1.1.1", "2.2.2.2"):
            gui_app.history.record_my_ips({"public_ipv4": ip, "public_ipv6": None,
                                           "reports": []})
        gui_app.history.record("lookup", "8.8.8.8", "Public, Google LLC, US",
                               {"isp": "Google LLC", "country": "US"})
        gui_app.history.record("whois", "1.1.1.1", "one.one.one.one, APNIC",
                               {"hostname": "one.one.one.one", "owner": "APNIC"})
        self.app.refresh_history()

    def test_history_reports_view(self):
        self._fill_history()
        self.assertEqual(self.app.history_layout.get(), "table")       # default
        self.app.history_layout.set("reports")
        self.app.set_history_layout()
        self.app.update_idletasks()
        self.assertTrue(self.app.history_pane.winfo_manager())
        self.assertFalse(self.app.history_table_frame.winfo_manager())
        text = self.pane_text(self.app.history_pane)
        self.assertLess(text.index("Reverse DNS / WHOIS"), text.index("IP lookup"))  # newest 1st
        for expected in ("ISP / Organization", "Google LLC", "Owner", "APNIC",
                         "Public IPv4 changed: 1.1.1.1 -> 2.2.2.2"):
            self.assertIn(expected, text)
        self.assertEqual(len(self.app.history_pane.data), 4)            # Save history (JSON)

    def test_history_find_in_both_views(self):
        self._fill_history()
        bar = self.app.history_find
        bar.var.set("1.1.1.1")                       # table: matching rows
        # both my_ip checks (the 2nd says "changed: 1.1.1.1 -> 2.2.2.2") + the WHOIS lookup
        self.assertEqual(len(bar.matches), 3)
        self.assertEqual(bar.count.cget("text"), "1 of 3")
        self.assertEqual(self.app.history_table.selection(), (bar.matches[0],))
        self.app.history_layout.set("reports")       # reports: every match in the text
        self.app.set_history_layout()
        self.assertGreaterEqual(len(bar.matches), 3)
        self.assertTrue(self.app.history_pane.text.tag_ranges("current"))
        bar.step(-1)
        self.assertEqual(bar.count.cget("text"), f"{len(bar.matches)} of {len(bar.matches)}")
        bar.var.set("")
        self.assertEqual(self.app.history_pane.text.tag_ranges("match"), ())

    def test_history_shows_the_addresses_of_a_batch(self):
        self._temporary_history()
        rows = [{"ip": "8.8.8.8", "count": 2, "scope": "Public (globally routable)",
                 "isp": "Google LLC", "country_code": "US", "error": ""},
                {"ip": "192.168.1.1", "count": 1, "scope": "Private (not routable)",
                 "isp": "", "country_code": "", "error": "not a public address"}]
        gui_app.history.record_batch("ips.txt", "ip", 2, "2 unique address(es)", rows)
        self.app.refresh_history()
        table = self.app.history_table
        values = [table.item(i, "values") for i in table.get_children()]
        self.assertEqual(values[0][1:3], ("Batch lookup", "ips.txt"))
        self.assertEqual(values[1][1:], ("   ↳ address in batch", "8.8.8.8",
                                         "Public, Google LLC, US (seen 2x)"))
        self.assertEqual(values[2][2], "192.168.1.1")
        self.app.history_find.var.set("192.168.1.1")   # find which batch an IP was in
        self.assertEqual(table.item(table.selection()[0], "values")[2], "192.168.1.1")

        self.app.history_layout.set("reports")
        self.app.set_history_layout()
        text = self.pane_text(self.app.history_pane)
        self.assertIn("Addresses in this batch (2)", text)
        self.assertIn("Public, Google LLC, US (seen 2x)", text)

    def test_history_changes_view_in_reports(self):
        self._fill_history()
        self.app.history_view.set("changes")
        self.app.history_layout.set("reports")
        self.app.set_history_layout()
        self.app.refresh_history()
        text = self.pane_text(self.app.history_pane)
        self.assertIn("Public IPv4 changed", text)
        self.assertIn("Old address", text)
        self.assertNotIn("IP lookup", text)

    def test_ctrl_f_focuses_the_open_tabs_find_bar(self):
        self.app.tabs.select(self.app.history_tab)
        self.assertEqual(self.app._focus_find(), "break")
        self.app.tabs.select(self.app.batch_tab)
        self.assertEqual(self.app._focus_find(), "break")
        self.app.tabs.select(0)
        self.assertIsNone(self.app._focus_find())

    def test_clear_history_asks_first(self):
        self._temporary_history()
        gui_app.history.record("lookup", "8.8.8.8", "x")
        with mock.patch.object(gui_app.messagebox, "askyesno", return_value=False):
            self.app.clear_history()
        self.assertEqual(len(gui_app.history.load()), 1)
        with mock.patch.object(gui_app.messagebox, "askyesno", return_value=True):
            self.app.clear_history()
        self.assertEqual(gui_app.history.load(), [])

    def test_whois_tab_shows_hostname_and_owner(self):
        result = {"ip": "8.8.8.8", "ptr_name": "8.8.8.8.in-addr.arpa",
                  "dns": {"hostname": "dns.google", "aliases": [], "forward_confirmed": True,
                          "error": None},
                  "whois": {"owner": "Google LLC", "network_name": "GOGL",
                            "range": "8.8.8.0 - 8.8.8.255", "cidr": "8.8.8.0/24",
                            "type": "DIRECT ALLOCATION", "country": None,
                            "abuse_email": "network-abuse@google.com",
                            "registered": "2023-12-28", "last_changed": "2023-12-28",
                            "registry": "ARIN (North America)", "source": "https://rdap"}}
        with mock.patch.object(gui_app.reverse_whois, "lookup", return_value=result):
            self.app.whois_lookup("8.8.8.8")
            done, value, error = self.app._results.get(timeout=5)
        done(value, error)
        text = self.pane_text(self.app.whois_pane)
        for expected in ("dns.google", "Google LLC", "8.8.8.0/24", "network-abuse@google.com"):
            self.assertIn(expected, text)
        self.assertIn("N/A", text)                       # country is empty for ARIN
        self.assertEqual(self.app.whois_pane.data, result)

    def test_whois_tab_rejects_invalid_address(self):
        with mock.patch.object(gui_app.reverse_whois, "lookup") as lookup:
            self.app.whois_lookup("hello")
        lookup.assert_not_called()
        self.assertIn("not a valid", self.pane_text(self.app.whois_pane))


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
