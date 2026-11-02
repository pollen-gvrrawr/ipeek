"""Unit tests for ip_info_app.py.

All network calls are replaced with unittest.mock, so the tests run offline.
Run from the project root with:  python -m unittest discover -v
"""

import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import ip_info_app as app  # noqa: E402


# --- Sample API responses ----------------------------------------------------

IPAPI_OK = {
    "ip": "8.8.8.8", "org": "GOOGLE", "asn": "AS15169",
    "country_name": "United States", "country_code": "US",
    "region": "California", "city": "Mountain View", "postal": "94043",
    "latitude": 37.42301, "longitude": -122.083352,
    "timezone": "America/Los_Angeles",
}

IPWHOIS_OK = {
    "ip": "8.8.8.8", "success": True, "country": "United States",
    "country_code": "US", "region": "California", "city": "Mountain View",
    "postal": "94039", "latitude": 37.3860517, "longitude": -122.0838511,
    "connection": {"asn": 15169, "org": "Google LLC", "isp": "Google LLC"},
    "timezone": {"id": "America/Los_Angeles"},
}


def fake_response(payload=None, status=200):
    """Build a mock requests.Response returning payload with the given status."""
    response = mock.Mock()
    response.json.return_value = payload
    if status >= 400:
        response.raise_for_status.side_effect = requests.HTTPError(f"{status} error")
    else:
        response.raise_for_status.return_value = None
    return response


def router(routes):
    """Return a fake requests.get that answers by URL prefix.

    routes maps a URL prefix to a response or an exception instance. Any URL
    not listed raises ConnectionError, like being offline.
    """
    def fake_get(url, **kwargs):
        """Return or raise the configured result for url."""
        for prefix, result in routes.items():
            if url.startswith(prefix):
                if isinstance(result, Exception):
                    raise result
                return result
        raise requests.ConnectionError(f"offline: {url}")
    return fake_get


def run_main(argv):
    """Run app.main(argv) and return (exit_code, stdout, stderr)."""
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = app.main(argv)
    return code, out.getvalue(), err.getvalue()


# --- Analysis layer -------------------------------------------------------------

class TestAnalysis(unittest.TestCase):
    """Offline analysis with the ipaddress module."""

    def test_public_ipv4(self):
        """A public IPv4 gets version, class, binary and reverse DNS."""
        result = app.analyse_ip("8.8.8.8")
        self.assertEqual(result["version"], 4)
        self.assertEqual(result["scope"], "Public")
        self.assertTrue(result["is_public"])
        self.assertEqual(result["ipv4_class"], "A")
        self.assertEqual(result["binary"], "00001000.00001000.00001000.00001000")
        self.assertEqual(result["reverse_dns"], "8.8.8.8.in-addr.arpa")

    def test_ipv4_classes(self):
        """Each first-octet range maps to the right class."""
        cases = {"10.0.0.1": "A", "172.16.0.1": "B", "192.168.1.1": "C",
                 "224.0.0.1": "D (multicast)", "250.0.0.1": "E (experimental)"}
        for address, expected in cases.items():
            with self.subTest(address=address):
                self.assertEqual(app.analyse_ip(address)["ipv4_class"], expected)

    def test_scopes(self):
        """Special ranges are labelled and never treated as public."""
        cases = {"192.168.1.10": "Private", "127.0.0.1": "Loopback",
                 "169.254.1.1": "Link-local", "224.0.0.1": "Multicast",
                 "0.0.0.0": "Unspecified", "fe80::1": "Link-local",
                 "::1": "Loopback", "fd00::1": "Private"}
        for address, expected in cases.items():
            with self.subTest(address=address):
                result = app.analyse_ip(address)
                self.assertEqual(result["scope"], expected)
                self.assertFalse(result["is_public"])

    def test_ipv6_forms(self):
        """IPv6 gets compressed and expanded forms instead of class/binary."""
        result = app.analyse_ip("2001:4860:4860:0000:0000:0000:0000:8888")
        self.assertEqual(result["version"], 6)
        self.assertEqual(result["compressed"], "2001:4860:4860::8888")
        self.assertEqual(result["expanded"], "2001:4860:4860:0000:0000:0000:0000:8888")
        self.assertNotIn("ipv4_class", result)
        self.assertTrue(result["reverse_dns"].endswith(".ip6.arpa"))

    def test_input_cleanup(self):
        """Whitespace and IPv6 brackets are accepted."""
        self.assertEqual(app.analyse_ip("  1.1.1.1 \n")["address"], "1.1.1.1")
        self.assertEqual(app.analyse_ip("[::1]")["address"], "::1")

    def test_invalid_input(self):
        """Invalid addresses return None instead of raising."""
        for bad in ["", "abc", "256.1.1.1", "1.2.3", "2001:::1", None]:
            with self.subTest(bad=bad):
                self.assertIsNone(app.analyse_ip(bad))


# --- API layer -------------------------------------------------------------------

class TestApi(unittest.TestCase):
    """Network calls, fallback and normalisation (all mocked)."""

    @mock.patch("ip_info_app.requests.get")
    def test_fetch_json_handles_errors(self, get):
        """Network errors, HTTP errors and bad JSON all give None."""
        bad_json = fake_response()
        bad_json.json.side_effect = ValueError("not json")
        for outcome in [requests.ConnectionError(), requests.Timeout(),
                        fake_response({}, 429), bad_json, fake_response([1, 2])]:
            with self.subTest(outcome=outcome):
                get.side_effect = router({"https://x": outcome})
                self.assertIsNone(app.fetch_json("https://x"))

    @mock.patch("ip_info_app.requests.get")
    def test_public_ipv4(self, get):
        """The ipify IPv4 address is returned and the timeout is used."""
        get.return_value = fake_response({"ip": "203.0.113.5"})
        self.assertEqual(app.get_public_ipv4(), "203.0.113.5")
        get.assert_called_once_with(app.IPV4_URL, headers=app.HEADERS, timeout=app.TIMEOUT)

    @mock.patch("ip_info_app.requests.get")
    def test_public_ipv6_unavailable(self, get):
        """No IPv6 connectivity gives None, not an exception."""
        get.side_effect = requests.ConnectionError("no route")
        self.assertIsNone(app.get_public_ipv6())

    @mock.patch("ip_info_app.requests.get")
    def test_public_ip_wrong_version_rejected(self, get):
        """An IPv4 answer from the IPv6 endpoint is rejected."""
        get.return_value = fake_response({"ip": "203.0.113.5"})
        self.assertIsNone(app.get_public_ipv6())

    @mock.patch("ip_info_app.requests.get")
    def test_details_from_ipapi(self, get):
        """ipapi.co is used first and normalised to the standard keys."""
        get.side_effect = router({"https://ipapi.co": fake_response(IPAPI_OK)})
        details = app.get_ip_details("8.8.8.8")
        self.assertEqual(details["source"], "ipapi.co")
        self.assertEqual(details["isp"], "GOOGLE")
        self.assertEqual(details["asn"], "AS15169")
        self.assertEqual(details["country"], "United States")
        self.assertEqual(details["timezone"], "America/Los_Angeles")
        self.assertEqual(details["maps_link"],
                         "https://www.google.com/maps?q=37.42301,-122.083352")

    @mock.patch("ip_info_app.requests.get")
    def test_fallback_to_ipwhois_on_api_error(self, get):
        """An ipapi.co error body falls back to ipwho.is."""
        get.side_effect = router({
            "https://ipapi.co": fake_response({"error": True, "reason": "RateLimited"}),
            "https://ipwho.is": fake_response(IPWHOIS_OK),
        })
        details = app.get_ip_details("8.8.8.8")
        self.assertEqual(details["source"], "ipwho.is")
        self.assertEqual(details["asn"], "AS15169")
        self.assertEqual(details["isp"], "Google LLC")
        self.assertEqual(details["timezone"], "America/Los_Angeles")

    @mock.patch("ip_info_app.requests.get")
    def test_fallback_on_network_error(self, get):
        """An ipapi.co timeout falls back to ipwho.is."""
        get.side_effect = router({
            "https://ipapi.co": requests.Timeout(),
            "https://ipwho.is": fake_response(IPWHOIS_OK),
        })
        self.assertEqual(app.get_ip_details("8.8.8.8")["source"], "ipwho.is")

    @mock.patch("ip_info_app.requests.get")
    def test_both_providers_fail(self, get):
        """If both providers fail the result is None."""
        get.side_effect = router({
            "https://ipapi.co": fake_response({}, 500),
            "https://ipwho.is": fake_response({"success": False, "message": "Invalid IP"}),
        })
        self.assertIsNone(app.get_ip_details("8.8.8.8"))

    def test_normalised_keys_match(self):
        """Both providers produce exactly the same keys."""
        self.assertEqual(set(app.normalise_ipapi(IPAPI_OK)),
                         set(app.normalise_ipwhois(IPWHOIS_OK)))

    def test_maps_link_missing_coordinates(self):
        """No maps link is built without coordinates."""
        self.assertIsNone(app.build_maps_link(None, 1.0))


# --- CLI layer -------------------------------------------------------------------

class TestCli(unittest.TestCase):
    """Report building, command-line options and the menu."""

    @mock.patch("ip_info_app.requests.get")
    def test_private_address_skips_api(self, get):
        """Private addresses never trigger a network call."""
        report = app.build_report("192.168.1.10")
        get.assert_not_called()
        self.assertIsNone(report["details"])
        self.assertIn("skipped", report["note"])

    @mock.patch("ip_info_app.requests.get")
    def test_ip_json_output(self, get):
        """--ip --json prints valid JSON containing analysis and details."""
        get.side_effect = router({"https://ipapi.co": fake_response(IPAPI_OK)})
        code, out, _ = run_main(["--ip", "8.8.8.8", "--json"])
        self.assertEqual(code, 0)
        data = json.loads(out)
        self.assertEqual(data["analysis"]["ipv4_class"], "A")
        self.assertEqual(data["details"]["city"], "Mountain View")

    @mock.patch("ip_info_app.requests.get")
    def test_ip_text_output_when_offline(self, get):
        """With no network, --ip still shows the analysis and a note."""
        get.side_effect = requests.ConnectionError()
        code, out, _ = run_main(["--ip", "1.1.1.1"])
        self.assertEqual(code, 0)
        self.assertIn("00000001.00000001.00000001.00000001", out)
        self.assertIn("lookup failed", out)

    def test_invalid_ip_exit_code(self):
        """An invalid --ip value exits with code 2 and an error message."""
        code, _, err = run_main(["--ip", "999.1.1.1"])
        self.assertEqual(code, 2)
        self.assertIn("not a valid", err)

    @mock.patch("ip_info_app.requests.get")
    def test_me_without_ipv6(self, get):
        """--me shows the IPv4 report and the 'No public IPv6' message."""
        get.side_effect = router({
            "https://api.ipify.org": fake_response({"ip": "8.8.8.8"}),
            "https://ipapi.co": fake_response(IPAPI_OK),
        })
        code, out, _ = run_main(["--me"])
        self.assertEqual(code, 0)
        self.assertIn("No public IPv6 available", out)
        self.assertIn("Mountain View", out)

    @mock.patch("ip_info_app.requests.get")
    def test_me_fully_offline(self, get):
        """--me with no network exits 1 without crashing."""
        get.side_effect = requests.ConnectionError()
        code, out, _ = run_main(["--me"])
        self.assertEqual(code, 1)
        self.assertIn("Could not determine public IPv4", out)

    def test_save_writes_json_file(self):
        """--save writes the report to a JSON file."""
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "report.json")
            code, _, err = run_main(["--ip", "10.0.0.1", "--save", path])
            self.assertEqual(code, 0)
            self.assertIn("Saved", err)
            with open(path, encoding="utf-8") as handle:
                self.assertEqual(json.load(handle)["analysis"]["scope"], "Private")

    def test_save_to_bad_path(self):
        """An unwritable --save path reports an error and exits 1."""
        bad = os.path.join(tempfile.gettempdir(), "no-such-dir-xyz", "r.json")
        code, _, err = run_main(["--ip", "10.0.0.1", "--save", bad])
        self.assertEqual(code, 1)
        self.assertIn("could not save", err)

    def test_me_and_ip_are_exclusive(self):
        """--me and --ip cannot be combined."""
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            app.parse_args(["--me", "--ip", "8.8.8.8"])

    @mock.patch("builtins.input", side_effect=["3", "10.0.0.1", "9", "4", "", "0"])
    @mock.patch("ip_info_app.save_json", return_value=True)
    def test_menu_flow(self, save, _input):
        """Menu: offline analysis, invalid option, save with default name, exit."""
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = app.main([])
        self.assertEqual(code, 0)
        self.assertIn("Address analysis: 10.0.0.1", out.getvalue())
        self.assertIn("please choose", err.getvalue())
        save.assert_called_once()
        self.assertEqual(save.call_args.args[1], "ip_report.json")

    @mock.patch("builtins.input", side_effect=["2", "not-an-ip", "4", EOFError()])
    def test_menu_invalid_address_and_eof(self, _input):
        """Menu rejects bad addresses, refuses empty saves and exits on EOF."""
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = app.run_menu()
        self.assertEqual(code, 0)
        self.assertIn("not a valid", err.getvalue())
        self.assertIn("nothing to save", err.getvalue())


if __name__ == "__main__":
    unittest.main()
