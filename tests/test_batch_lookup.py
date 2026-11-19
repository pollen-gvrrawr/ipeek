"""Unit tests for batch_lookup.py and the --batch CLI option.

No internet needed: the lookup is mocked.  Run with:
    python -m unittest discover -s tests -v
"""
import csv
import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import batch_lookup  # noqa: E402
import ip_info_app as app  # noqa: E402

GOOGLE = {"ip": "8.8.8.8", "isp": "GOOGLE", "asn": "AS15169", "country": "United States",
          "country_code": "US", "region": "California", "city": "Mountain View",
          "postal": None, "latitude": 37.42, "longitude": -122.08,
          "timezone": "America/Los_Angeles", "utc_offset": "-0700", "source": "ipapi.co"}


def fake_build_report(ip):
    """Offline stand-in for app.build_report: real analysis, sample details."""
    analysis = app.analyze_ip(ip)
    if not analysis["scope"].startswith("Public"):
        details = {"ip": ip, "error": "not a public address, so it has no ISP/location data"}
    elif ip == "1.1.1.1":
        details = {"ip": ip, "error": "ipapi.co: RateLimited; ipwho.is: limit reached"}
    else:
        details = dict(GOOGLE, ip=ip)
    return {"analysis": analysis, "details": details}


class ExtractTests(unittest.TestCase):
    def test_one_ip_per_line(self):
        entries, skipped = batch_lookup.extract_ips(["8.8.8.8", "2001:4860:4860::8888", ""])
        self.assertEqual(entries, [("8.8.8.8", 1), ("2001:4860:4860::8888", 1)])
        self.assertEqual(skipped, [])

    def test_firewall_csv_any_column_with_header_and_ports(self):
        lines = ["time,action,src,dst",
                 "10:00,DENY,203.0.113.5:443,192.168.1.10",
                 "10:01,DENY,203.0.113.5,192.168.1.10",
                 "10:02,ALLOW,no address here,TCP"]
        entries, skipped = batch_lookup.extract_ips(lines)
        self.assertEqual(entries, [("203.0.113.5", 2), ("192.168.1.10", 2)])
        self.assertEqual(skipped, [(4, "10:02,ALLOW,no address here,TCP")])

    def test_duplicates_are_normalised(self):
        entries, _ = batch_lookup.extract_ips(["2001:DB8::1", "2001:0db8:0:0:0:0:0:1"])
        self.assertEqual(entries, [("2001:db8::1", 2)])

    def test_comments_and_invalid_lines(self):
        entries, skipped = batch_lookup.extract_ips(["# my list", "8.8.8.8", "999.1.1.1"])
        self.assertEqual(entries, [("8.8.8.8", 1)])
        self.assertEqual(skipped, [(3, "999.1.1.1")])


class RunBatchTests(unittest.TestCase):
    def test_rows_progress_and_summary(self):
        seen = []
        entries = [("8.8.8.8", 3), ("192.168.1.10", 1), ("1.1.1.1", 1)]
        rows = batch_lookup.run_batch(entries, fake_build_report,
                                      lambda done, total, ip: seen.append((done, total)))
        self.assertEqual(seen, [(1, 3), (2, 3), (3, 3)])
        self.assertEqual((rows[0]["isp"], rows[0]["count"], rows[0]["class"]), ("GOOGLE", 3, "A"))
        self.assertIn("RateLimited", rows[2]["error"])
        self.assertEqual(batch_lookup.summarize(rows),
                         {"total": 3, "public": 2, "not_public": 1, "failed": 1})

    def test_one_crash_does_not_stop_the_batch(self):
        def flaky(ip):
            if ip == "8.8.4.4":
                raise RuntimeError("boom")
            return fake_build_report(ip)
        rows = batch_lookup.run_batch([("8.8.4.4", 1), ("8.8.8.8", 1)], flaky)
        self.assertEqual(rows[0]["error"], "boom")
        self.assertEqual(rows[1]["isp"], "GOOGLE")

    def test_default_output_path(self):
        self.assertEqual(batch_lookup.default_output_path(os.path.join("logs", "fw.txt")),
                         os.path.join("logs", "fw_results.csv"))


class FileAndCliTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.src = os.path.join(self.tmp.name, "firewall.csv")
        with open(self.src, "w", encoding="utf-8") as fh:
            fh.write("src,dst\n8.8.8.8,192.168.1.10\n8.8.8.8,fe80::1\nbad,row\n")

    def test_cli_writes_csv(self):
        out = os.path.join(self.tmp.name, "out.csv")
        with mock.patch.object(app, "build_report", side_effect=fake_build_report), \
                redirect_stdout(io.StringIO()) as printed:
            app.main(["--batch", self.src, "--out", out, "--no-color"])
        with open(out, encoding="utf-8-sig", newline="") as fh:
            rows = list(csv.DictReader(fh))
        self.assertEqual(list(rows[0]), list(batch_lookup.CSV_COLUMNS))
        self.assertEqual([r["ip"] for r in rows], ["8.8.8.8", "192.168.1.10", "fe80::1"])
        self.assertEqual((rows[0]["count"], rows[0]["asn"]), ("2", "AS15169"))
        self.assertEqual(rows[0]["reverse_dns"], "8.8.8.8.in-addr.arpa")
        self.assertEqual(rows[0]["binary"], "00001000.00001000.00001000.00001000")
        self.assertEqual(rows[2]["expanded"], "fe80:0000:0000:0000:0000:0000:0000:0001")
        self.assertEqual((rows[0]["utc_offset"], rows[0]["postal"]), ("-0700", ""))
        self.assertIn("Skipped 1 line(s)", printed.getvalue())

    def test_cli_prints_full_report_for_every_ip(self):
        out = os.path.join(self.tmp.name, "out.csv")
        with mock.patch.object(app, "build_report", side_effect=fake_build_report),                 redirect_stdout(io.StringIO()) as printed:
            app.main(["--batch", self.src, "--out", out, "--no-color"])
        text = printed.getvalue()
        for label in ("Binary", "Reverse DNS name", "Expanded", "ISP / Organization",
                      "Postal code", "Timezone", "Times seen in file", "SUMMARY"):
            self.assertIn(label, text)
        self.assertEqual(text.count("Address analysis"), 3)       # one report per IP

    def test_cli_brief_prints_only_summary(self):
        out = os.path.join(self.tmp.name, "out.csv")
        with mock.patch.object(app, "build_report", side_effect=fake_build_report),                 redirect_stdout(io.StringIO()) as printed:
            app.main(["--batch", self.src, "--out", out, "--brief", "--no-color"])
        self.assertNotIn("Address analysis", printed.getvalue())
        self.assertIn("3 unique address(es)", printed.getvalue())

    def run_find(self, *extra):
        out = os.path.join(self.tmp.name, "out.csv")
        with mock.patch.object(app, "build_report", side_effect=fake_build_report), \
                redirect_stdout(io.StringIO()) as printed:
            app.main(["--batch", self.src, "--out", out, "--no-color", *extra])
        return printed.getvalue()

    def test_find_highlights_and_counts_matches(self):
        text = self.run_find("--find", "mountain view")          # case-insensitive
        self.assertIn("[Mountain View]", text)                    # brackets when no colour
        self.assertIn('Find "mountain view": 1 match(es) in 1 address(es) (8.8.8.8)', text)

    def test_find_with_brief_still_counts_matches_in_full_reports(self):
        text = self.run_find("--find", "in-addr.arpa", "--brief")
        self.assertNotIn("Address analysis", text)
        self.assertIn("2 match(es) in 2 address(es)", text)       # the two IPv4 addresses

    def test_find_skips_the_map_link(self):
        text = self.run_find("--find", "google")
        self.assertIn("[GOOGLE]", text)
        self.assertIn("https://www.google.com/maps", text)        # map row not highlighted
        self.assertIn('Find "google": 1 match(es) in 1 address(es) (8.8.8.8)', text)

    def test_find_no_matches(self):
        self.assertIn('Find "cloudflare": no matches', self.run_find("--find", "cloudflare"))

    def test_find_in_json(self):
        data = json.loads(self.run_find("--find", "AS15169", "--json"))
        self.assertEqual(data["find"], {"text": "AS15169", "matches": {"8.8.8.8": 1}})

    def test_cli_default_output_and_json(self):
        with mock.patch.object(app, "build_report", side_effect=fake_build_report), \
                redirect_stdout(io.StringIO()) as printed:
            app.main(["--batch", self.src, "--json"])
        data = json.loads(printed.getvalue())
        self.assertEqual(data["output"], os.path.join(self.tmp.name, "firewall_results.csv"))
        self.assertTrue(os.path.exists(data["output"]))
        self.assertEqual(data["skipped_lines"], [4])

    def test_cli_missing_file_does_not_crash(self):
        with redirect_stdout(io.StringIO()) as printed:
            result = app.show_batch(os.path.join(self.tmp.name, "nope.txt"))
        self.assertIsNone(result)
        self.assertIn("Could not read", printed.getvalue())


class HighlightTests(unittest.TestCase):
    def test_keeps_surrounding_colour(self):
        red, end = "\x1b[91m", "\x1b[0m"
        with mock.patch.object(app.Color, "HIGHLIGHT", "<H>"), \
                mock.patch.object(app.Color, "END", end):
            text, count = app.highlight(f"{red}Google LLC and google{end}", "GOOGLE")
        self.assertEqual(count, 2)
        # after each match the red colour is switched back on
        self.assertEqual(text, f"{red}<H>Google{end}{red} LLC and <H>google{end}{red}{end}")

    def test_does_not_match_inside_colour_codes(self):
        _, count = app.highlight("\x1b[91mred\x1b[0m", "91")
        self.assertEqual(count, 0)

    def test_empty_query(self):
        self.assertEqual(app.highlight("abc", ""), ("abc", 0))


def fake_whois(ip, cache=None):
    """Offline stand-in for reverse_whois.lookup."""
    if not app.analyze_ip(ip)["scope"].startswith("Public"):
        return {"ip": ip, "ptr_name": "x.arpa",
                "dns": {"hostname": None, "aliases": [], "forward_confirmed": None,
                        "error": "no PTR record"},
                "whois_error": "not a public address, so it has no public WHOIS record"}
    return {"ip": ip, "ptr_name": "x.arpa",
            "dns": {"hostname": "dns.google", "aliases": [], "forward_confirmed": True,
                    "error": None},
            "whois": {"owner": "Google LLC", "network_name": "GOGL", "range": "8.8.8.0 - 8.8.8.255",
                      "cidr": "8.8.8.0/24", "type": "DIRECT ALLOCATION", "country": None,
                      "abuse_email": "network-abuse@google.com", "registered": "2023-12-28",
                      "last_changed": "2023-12-28", "registry": "ARIN (North America)",
                      "source": "https://rdap.arin.net/registry/ip/8.8.8.8"}}


def fake_resolver(name):
    table = {"dns.google": ["8.8.8.8", "8.8.4.4"], "one.one.one.one": ["1.1.1.1"]}
    if name not in table:
        raise OSError("the name does not exist or has no address")
    return table[name]


class HostnameTests(unittest.TestCase):
    def test_hostnames_are_read_only_when_asked(self):
        lines = ["host,ip", "dns.google,8.8.8.8", "HELO One.One.One.One.", "10:00 2026-11-19"]
        self.assertEqual(batch_lookup.extract_ips(lines)[0], [("8.8.8.8", 1)])
        entries, skipped = batch_lookup.extract_ips(lines, hostnames=True)
        self.assertEqual(entries, [("dns.google", 1), ("8.8.8.8", 1), ("one.one.one.one", 1)])
        self.assertEqual(skipped, [(4, "10:00 2026-11-19")])     # times/dates aren't names

    def test_not_hostnames(self):
        for text in ("TCP", "v1.2", "10.0.0", "2026-11-19", "-bad-.com", "a..b.com"):
            with self.subTest(text=text):
                self.assertIsNone(batch_lookup._parse_hostname(text))

    def test_resolve_merges_counts_and_reports_failures(self):
        entries = [("8.8.8.8", 1), ("dns.google", 2), ("nope.invalid", 1), ("10.0.0.5", 1)]
        resolved, unresolved = batch_lookup.resolve_entries(entries, fake_resolver)
        self.assertEqual(resolved, [("8.8.8.8", 3, ("dns.google",)),
                                    ("8.8.4.4", 2, ("dns.google",)),
                                    ("10.0.0.5", 1, ())])
        self.assertEqual(unresolved, [("nope.invalid",
                                       "the name does not exist or has no address")])

    def test_run_batch_fills_from_hostname(self):
        rows = batch_lookup.run_batch([("8.8.8.8", 3, ("dns.google",)), ("10.0.0.5", 1, ())],
                                      fake_build_report)
        self.assertEqual([r["from_hostname"] for r in rows], ["dns.google", ""])

    def test_resolve_hostname_failure(self):
        with mock.patch.object(batch_lookup.socket, "getaddrinfo",
                               side_effect=batch_lookup.socket.gaierror(11001)), \
                self.assertRaisesRegex(OSError, "does not exist"):
            batch_lookup.resolve_hostname("nope.invalid")


class BothModeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.src = os.path.join(self.tmp.name, "mixed.csv")
        with open(self.src, "w", encoding="utf-8") as fh:
            fh.write("purpose,value\nip details,8.8.8.8\nreverse dns,dns.google\n"
                     "bad,nope.invalid\nprivate,192.168.1.1\n")

    def test_both_row_keeps_both_countries(self):
        row = batch_lookup.both_row("8.8.8.8", 1, {"report": fake_build_report("8.8.8.8"),
                                                   "whois": fake_whois("8.8.8.8")})
        self.assertEqual(list(row), list(batch_lookup.BOTH_COLUMNS))
        self.assertEqual((row["isp"], row["country"]), ("GOOGLE", "United States"))
        self.assertEqual((row["owner"], row["hostname"]), ("Google LLC", "dns.google"))
        self.assertEqual(row["whois_source"], "https://rdap.arin.net/registry/ip/8.8.8.8")
        self.assertEqual(row["source"], "ipapi.co")

    def run_cli(self, *args):
        with mock.patch.object(app, "build_report", side_effect=fake_build_report), \
                mock.patch.object(app.reverse_whois, "lookup", side_effect=fake_whois), \
                mock.patch.object(batch_lookup, "resolve_hostname", side_effect=fake_resolver), \
                mock.patch.object(batch_lookup.socket, "getaddrinfo",       # no real DNS
                                  side_effect=AssertionError("real DNS lookup in a test")), \
                redirect_stdout(io.StringIO()) as out:
            app.main(["--no-color", *args])
        return out.getvalue()

    def test_cli_batch_both_with_hostnames(self):
        text = self.run_cli("--batch-both", self.src, "--resolve-hostnames")
        self.assertIn("BATCH IP DETAILS + REVERSE DNS / WHOIS", text)
        self.assertIn("ISP / Organization", text)          # IP-details report ...
        self.assertIn("Reverse DNS (hostname)", text)      # ... and the WHOIS sections
        self.assertIn("From hostname in file : dns.google", text)
        self.assertIn("(from dns.google)", text)
        self.assertIn("Could not resolve 1 hostname(s): nope.invalid", text)
        with open(os.path.join(self.tmp.name, "mixed_both.csv"), encoding="utf-8-sig") as fh:
            rows = list(csv.DictReader(fh))
        self.assertEqual([r["ip"] for r in rows], ["8.8.8.8", "8.8.4.4", "192.168.1.1"])
        self.assertEqual((rows[0]["count"], rows[0]["from_hostname"]), ("2", "dns.google"))
        self.assertEqual((rows[0]["isp"], rows[0]["owner"]), ("GOOGLE", "Google LLC"))

    def test_without_resolve_hostnames_names_are_skipped(self):
        text = self.run_cli("--batch-whois", self.src, "--brief")
        self.assertIn("2 unique address(es)", text)
        self.assertIn("Skipped 2 line(s) with no IP address", text)
        self.assertNotIn("Could not resolve", text)

    def test_json_lists_unresolved_hostnames(self):
        data = json.loads(self.run_cli("--batch", self.src, "--resolve-hostnames", "--json",
                                       "--out", os.path.join(self.tmp.name, "o.csv")))
        self.assertEqual(data["mode"], "ip")
        self.assertEqual(list(data["unresolved_hostnames"]), ["nope.invalid"])
        self.assertTrue(data["summary"].startswith("3 unique address(es)"))


if __name__ == "__main__":
    unittest.main()
