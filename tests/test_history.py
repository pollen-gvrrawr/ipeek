"""Unit tests for history.py and the history CLI options.

Every test uses its own temporary history file, so the real one in the
user's app-data folder is never read or written.
Run with:   python -m unittest discover -s tests -v
"""
import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import history  # noqa: E402
import ip_info_app as app  # noqa: E402


def my_results(ipv4, ipv6=None, isp="ComClark"):
    details = {"isp": isp} if isp else {"error": "x"}
    return {"generated": "2026-11-19T10:00:00", "public_ipv4": ipv4, "public_ipv6": ipv6,
            "reports": [{"analysis": {}, "details": details}]}


class HistoryTestCase(unittest.TestCase):
    """Turns history on with a temporary file for each test."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.path = os.path.join(tmp.name, "IPeek", "history.jsonl")
        for name, value in (("ENABLED", True), ("PATH", self.path)):
            patcher = mock.patch.object(history, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)


class StorageTests(HistoryTestCase):
    def test_off_by_default_writes_nothing(self):
        with mock.patch.object(history, "ENABLED", False):
            self.assertIsNone(history.record("lookup", "8.8.8.8", "x"))
            self.assertIsNone(history.record_my_ips(my_results("1.2.3.4")))
        self.assertFalse(os.path.exists(self.path))

    def test_record_and_load_creates_folder(self):
        history.record("lookup", "8.8.8.8", "Public, Google LLC, US")
        history.record("whois", "1.1.1.1", "one.one.one.one, APNIC")
        self.assertEqual([e["target"] for e in history.load()], ["8.8.8.8", "1.1.1.1"])
        self.assertEqual(len(history.load("whois")), 1)

    def test_keeps_only_newest_entries(self):
        with mock.patch.object(history, "MAX_ENTRIES", 3):
            for n in range(5):
                history.record("lookup", f"10.0.0.{n}", "x")
        self.assertEqual([e["target"] for e in history.load()],
                         ["10.0.0.2", "10.0.0.3", "10.0.0.4"])

    def test_damaged_lines_and_bom_are_tolerated(self):
        os.makedirs(os.path.dirname(self.path))
        with open(self.path, "w", encoding="utf-8-sig") as fh:      # Notepad-style BOM
            fh.write(json.dumps({"kind": "lookup", "target": "a"}) + "\n{broken\n")
            fh.write(json.dumps({"kind": "lookup", "target": "b"}) + "\n")
        self.assertEqual([e["target"] for e in history.load()], ["a", "b"])

    def test_missing_file_and_clear(self):
        self.assertEqual(history.load(), [])
        self.assertFalse(history.clear())
        history.record("lookup", "8.8.8.8", "x")
        self.assertTrue(history.clear())
        self.assertEqual(history.load(), [])

    def test_unwritable_file_does_not_stop_a_lookup(self):
        with mock.patch("builtins.open", side_effect=PermissionError("denied")):
            self.assertIsNone(history.record("lookup", "8.8.8.8", "x"))

    def test_default_path_per_system(self):
        with mock.patch.object(history, "PATH", None), \
                mock.patch.object(history.platform, "system", return_value="Windows"), \
                mock.patch.dict(os.environ, {"APPDATA": r"C:\Users\x\AppData\Roaming"}):
            self.assertTrue(history.history_path().endswith(os.path.join("IPeek",
                                                                         "history.jsonl")))
        with mock.patch.object(history.platform, "system", return_value="Linux"), \
                mock.patch.dict(os.environ, {"XDG_DATA_HOME": "/data"}):
            self.assertEqual(history.default_path(),
                             os.path.join("/data", "ipeek", "history.jsonl"))


class ChangeDetectionTests(HistoryTestCase):
    def test_compare(self):
        self.assertEqual(history.compare({"ipv4": "1.1.1.1"}, {"ipv4": "1.1.1.1"}), [])
        changed = history.compare({"ipv4": "1.1.1.1", "ipv6": None},
                                  {"ipv4": "2.2.2.2", "ipv6": "2001:db8::1"})
        self.assertEqual([c["version"] for c in changed], ["IPv4", "IPv6"])
        self.assertEqual(changed[0]["text"], "Public IPv4 changed: 1.1.1.1 -> 2.2.2.2")
        self.assertIn("now available", changed[1]["text"])
        gone = history.compare({"ipv6": "2001:db8::1"}, {"ipv6": None})
        self.assertIn("no longer detected", gone[0]["text"])

    def test_first_then_unchanged_then_changed(self):
        first = history.record_my_ips(my_results("136.158.61.201"))
        self.assertIsNone(first["previous"])
        self.assertIn("First check", history.status_text(first))

        same = history.record_my_ips(my_results("136.158.61.201"))
        self.assertEqual(same["changes"], [])
        self.assertIn("Unchanged since your last check", history.status_text(same))

        moved = history.record_my_ips(my_results("136.158.99.7"))
        self.assertEqual(moved["changes"][0]["old"], "136.158.61.201")
        self.assertIn("Changed since your last check", history.status_text(moved))
        self.assertEqual(history.load()[-1]["data"]["isp"], "ComClark")

    def test_ip_changes_timeline(self):
        for ip in ("1.1.1.1", "1.1.1.1", "2.2.2.2", "2.2.2.2", "3.3.3.3"):
            history.record_my_ips(my_results(ip))
        history.record("lookup", "8.8.8.8", "x")        # other lookups are ignored
        changes = history.ip_changes()
        self.assertEqual([(c["old"], c["new"]) for c in changes],
                         [("1.1.1.1", "2.2.2.2"), ("2.2.2.2", "3.3.3.3")])
        self.assertIn("since", changes[0])

    def test_status_text_off(self):
        self.assertIsNone(history.status_text(None))


class OtherLookupTests(HistoryTestCase):
    def test_lookup_whois_and_batch_results(self):
        history.record_lookup({"analysis": app.analyze_ip("8.8.8.8"),
                               "details": {"isp": "Google LLC", "country_code": "US"}})
        history.record_whois({"ip": "192.168.1.1", "dns": {"hostname": None},
                              "whois_error": "not a public address"})
        history.record_batch(os.path.join("samples", "ips.txt"), "whois", 10, "10 unique")
        lookup, whois, batch = history.load()
        self.assertEqual(lookup["result"], "Public, Google LLC, US")
        self.assertEqual(whois["result"], "no hostname, not a public address")
        self.assertEqual((batch["kind"], batch["target"], batch["data"]["addresses"]),
                         ("batch_whois", "ips.txt", 10))
        self.assertEqual(history.entry_row(batch)[1], "Batch reverse DNS / WHOIS")


def ip_row(ip, count=1, scope="Public (globally routable)", isp="Google LLC", cc="US",
           error=""):
    return {"ip": ip, "count": count, "scope": scope, "isp": isp, "country_code": cc,
            "error": error}


class BatchAddressTests(HistoryTestCase):
    def test_batch_keeps_each_address_and_its_result(self):
        rows = [ip_row("8.8.8.8", 2),
                ip_row("192.168.1.1", scope="Private (not routable on the Internet)", isp="",
                       cc="", error="not a public address"),
                ip_row("1.1.1.1", isp="", cc="", error="ipapi.co: RateLimited"),
                {"ip": "9.9.9.9", "count": 1, "scope": "", "error": "boom"}]
        history.record_batch("ips.txt", "ip", 4, "4 unique", rows)
        self.assertEqual(history.batch_ips(history.load()[-1]), [
            ("8.8.8.8", 2, "Public, Google LLC, US"),
            ("192.168.1.1", 1, "Private"),
            ("1.1.1.1", 1, "Public, ipapi.co: RateLimited"),
            ("9.9.9.9", 1, "lookup failed: boom")])

    def test_whois_batch_results(self):
        rows = [{"ip": "8.8.8.8", "count": 1, "hostname": "dns.google", "owner": "Google LLC",
                 "whois_error": ""},
                {"ip": "10.0.0.5", "count": 1, "hostname": "", "owner": "",
                 "whois_error": "not a public address"}]
        history.record_batch("log.csv", "whois", 2, "2 unique", rows)
        self.assertEqual([r for _, _, r in history.batch_ips(history.load()[-1])],
                         ["dns.google, Google LLC", "no hostname, not public"])

    def test_both_batch_and_hostnames(self):
        row = dict(ip_row("8.8.8.8", 3), hostname="dns.google", owner="Google LLC",
                   whois_error="", from_hostname="dns.google")
        history.record_batch("hosts.txt", "both", 1, "1 unique", [row])
        entry = history.load()[-1]
        self.assertEqual(entry["kind"], "batch_both")
        self.assertEqual(history.entry_row(entry)[1], "Batch IP details + WHOIS")
        self.assertEqual(history.batch_ips(entry)[0][2],
                         "Public, Google LLC, US; dns.google, Google LLC (from dns.google)")

    def test_large_batch_is_capped(self):
        rows = [ip_row(f"10.0.{n // 256}.{n % 256}") for n in range(7)]
        with mock.patch.object(history, "MAX_BATCH_IPS", 5):
            history.record_batch("big.txt", "ip", 7, "7 unique", rows)
        entry = history.load()[-1]
        self.assertEqual(len(history.batch_ips(entry)), 5)
        self.assertEqual(entry["data"]["ips_omitted"], 2)

    def test_other_kinds_have_no_addresses(self):
        history.record("lookup", "8.8.8.8", "x")
        self.assertEqual(history.batch_ips(history.load()[-1]), [])


class CliTests(HistoryTestCase):
    def run_cli(self, *args):
        # the fake my_results() reports are empty, so don't print them
        with redirect_stdout(io.StringIO()) as out, mock.patch.object(app, "print_report"):
            app.main(["--no-color", *args])
        return out.getvalue()

    def test_me_shows_change(self):
        history.record_my_ips(my_results("136.158.61.201"))
        with mock.patch.object(app, "get_my_report", return_value=my_results("136.158.99.7")):
            text = self.run_cli("--me")
        self.assertIn("Public IPv4 changed: 136.158.61.201 -> 136.158.99.7", text)

    def test_me_json_includes_changes(self):
        history.record_my_ips(my_results("1.1.1.1"))
        with mock.patch.object(app, "get_my_report", return_value=my_results("2.2.2.2")):
            data = json.loads(self.run_cli("--me", "--json"))
        self.assertEqual(data["ip_changes"][0]["new"], "2.2.2.2")

    def test_no_history_flag(self):
        with mock.patch.object(app, "get_my_report", return_value=my_results("1.1.1.1")):
            self.run_cli("--me", "--no-history")
        self.assertEqual(history.load(), [])

    def test_lookups_are_logged(self):
        with mock.patch.object(app, "build_report", return_value={
                "analysis": app.analyze_ip("8.8.8.8"), "details": {"isp": "Google LLC"}}), \
                mock.patch.object(app, "print_report"):
            self.run_cli("--ip", "8.8.8.8")
        self.assertEqual(history.load()[-1]["target"], "8.8.8.8")

    def test_batch_run_lists_its_addresses_in_history(self):
        src = os.path.join(os.path.dirname(self.path), "ips.txt")
        os.makedirs(os.path.dirname(src), exist_ok=True)
        with open(src, "w", encoding="utf-8") as fh:
            fh.write("8.8.8.8\n8.8.8.8\n192.168.1.1\n")
        fake = {"analysis": app.analyze_ip("8.8.8.8"),
                "details": {"isp": "Google LLC", "country_code": "US"}}
        private = {"analysis": app.analyze_ip("192.168.1.1"),
                   "details": {"error": "not a public address"}}
        with mock.patch.object(app, "build_report",
                               side_effect=lambda ip: fake if ip == "8.8.8.8" else private):
            self.run_cli("--batch", src, "--brief")
        text = self.run_cli("--history")
        self.assertIn("Batch lookup", text)
        self.assertIn("- 8.8.8.8", text)
        self.assertIn("Public, Google LLC, US (seen 2x)", text)
        self.assertIn("- 192.168.1.1", text)

    def test_history_list_ip_changes_and_clear(self):
        for ip in ("1.1.1.1", "2.2.2.2"):
            history.record_my_ips(my_results(ip))
        text = self.run_cli("--history")
        self.assertIn("LOOKUP HISTORY (last 2)", text)
        self.assertIn("first check", text)
        self.assertIn("Public IPv4 changed: 1.1.1.1 -> 2.2.2.2", self.run_cli("--ip-changes"))
        self.assertEqual(len(json.loads(self.run_cli("--history", "1", "--json"))), 1)
        self.assertIn("deleted", self.run_cli("--clear-history"))
        self.assertIn("No lookups recorded yet", self.run_cli("--history"))
        self.assertIn("No changes recorded", self.run_cli("--ip-changes"))


if __name__ == "__main__":
    unittest.main()
