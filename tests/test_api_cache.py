"""Unit tests for api_cache.py (caching and API-key support) and how
ip_info_app.py uses it.

Every test uses its own temporary cache and config files and a clean set of
IPEEK_* environment variables, so the real files in the user's app-data
folder are never read or written, and the APIs are mocked (no internet).
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

import requests

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import api_cache  # noqa: E402
import ip_info_app as app  # noqa: E402
from test_ip_info_app import IPAPI_SAMPLE, IPWHOIS_SAMPLE, fake_response  # noqa: E402

IPSTACK_SAMPLE = {
    "ip": "8.8.8.8", "type": "ipv4", "country_code": "US", "country_name": "United States",
    "region_name": "California", "city": "Mountain View", "zip": "94043",
    "latitude": 37.42, "longitude": -122.08,
    "time_zone": {"id": "America/Los_Angeles", "gmt_offset": -25200},
    "connection": {"asn": 15169, "isp": "Google LLC"}, "currency": {"code": "USD"},
}


class CacheTestCase(unittest.TestCase):
    """Turns the cache on with temporary files and no API keys for each test."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        patches = [mock.patch.object(api_cache, "ENABLED", True),
                   mock.patch.object(api_cache, "READ", True),
                   mock.patch.object(api_cache, "PATH", os.path.join(self.tmp.name, "cache.json")),
                   mock.patch.object(api_cache, "CONFIG_PATH",
                                     os.path.join(self.tmp.name, "config.json")),
                   mock.patch.dict(os.environ, {}, clear=False)]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        for name in api_cache.KEY_ENV.values():
            os.environ.pop(name, None)

    def write_config(self, **settings):
        with open(api_cache.CONFIG_PATH, "w", encoding="utf-8") as fh:
            json.dump(settings, fh)


class CacheTests(CacheTestCase):
    def test_put_then_get(self):
        api_cache.put("8.8.8.8", {"ip": "8.8.8.8", "source": "ipapi.co"}, now=1000)
        d = api_cache.get("8.8.8.8", now=1000 + 3600)
        self.assertEqual(d["source"], "ipapi.co")
        self.assertTrue(d["cached"])
        self.assertIn("cached_at", d)

    def test_expired_entry_is_ignored(self):
        api_cache.put("8.8.8.8", {"ip": "8.8.8.8"}, now=1000)
        self.assertIsNone(api_cache.get("8.8.8.8", now=1000 + 25 * 3600))

    def test_cache_hours_from_config(self):
        self.write_config(cache_hours=1)
        api_cache.put("8.8.8.8", {"ip": "8.8.8.8"}, now=1000)
        self.assertIsNone(api_cache.get("8.8.8.8", now=1000 + 2 * 3600))

    def test_cache_hours_zero_turns_it_off(self):
        self.write_config(cache_hours=0)
        api_cache.put("8.8.8.8", {"ip": "8.8.8.8"})
        self.assertFalse(os.path.exists(api_cache.PATH))

    def test_errors_are_not_cached(self):
        api_cache.put("8.8.8.8", {"ip": "8.8.8.8", "error": "offline"})
        self.assertIsNone(api_cache.get("8.8.8.8"))

    def test_off_by_default_in_tests(self):
        with mock.patch.object(api_cache, "ENABLED", False):
            api_cache.put("8.8.8.8", {"ip": "8.8.8.8"})
            self.assertIsNone(api_cache.get("8.8.8.8"))
        self.assertFalse(os.path.exists(api_cache.PATH))

    def test_damaged_cache_file_is_ignored(self):
        with open(api_cache.PATH, "w", encoding="utf-8") as fh:
            fh.write("{not json")
        self.assertIsNone(api_cache.get("8.8.8.8"))
        api_cache.put("8.8.8.8", {"ip": "8.8.8.8"})      # rebuilt
        self.assertIsNotNone(api_cache.get("8.8.8.8"))

    def test_keeps_only_newest_entries(self):
        with mock.patch.object(api_cache, "MAX_ENTRIES", 2):
            for n in range(3):
                api_cache.put(f"8.8.8.{n}", {"ip": f"8.8.8.{n}"})
        self.assertIsNone(api_cache.get("8.8.8.0"))
        self.assertIsNotNone(api_cache.get("8.8.8.2"))

    def test_clear(self):
        api_cache.put("8.8.8.8", {"ip": "8.8.8.8"})
        self.assertTrue(api_cache.clear())
        self.assertFalse(api_cache.clear())


class ApiKeyTests(CacheTestCase):
    def test_no_keys(self):
        self.assertIsNone(api_cache.api_key("ipapi_key"))
        self.assertEqual([n for n, _ in app.providers()], ["ipapi.co", "ipwho.is"])

    def test_key_from_config(self):
        self.write_config(ipstack_key="  abc123  ")
        self.assertEqual(api_cache.api_key("ipstack_key"), "abc123")
        self.assertEqual([n for n, _ in app.providers()], ["ipapi.co", "ipstack", "ipwho.is"])

    def test_environment_wins_over_config(self):
        self.write_config(ipapi_key="from-config")
        os.environ["IPEEK_IPAPI_KEY"] = "from-env"
        self.assertEqual(api_cache.api_key("ipapi_key"), "from-env")

    def test_redact_hides_keys(self):
        os.environ["IPEEK_IPAPI_KEY"] = "SECRET42"
        text = api_cache.redact("401 for url: https://ipapi.co/8.8.8.8/json/?key=SECRET42")
        self.assertNotIn("SECRET42", text)
        self.assertIn("key=***", text)


class LookupWithCacheTests(CacheTestCase):
    @mock.patch("ip_info_app.requests.get")
    def test_second_lookup_uses_the_cache(self, get):
        get.return_value = fake_response(IPAPI_SAMPLE)
        first = app.get_ip_details("8.8.8.8")
        second = app.get_ip_details("8.8.8.8")
        self.assertEqual(get.call_count, 1)                 # only one API request
        self.assertNotIn("cached", first)
        self.assertTrue(second["cached"])
        self.assertEqual(second["isp"], "GOOGLE")
        self.assertIn("cached", app.source_text(second))

    @mock.patch("ip_info_app.requests.get")
    def test_no_cache_asks_the_api_again(self, get):
        get.return_value = fake_response(IPAPI_SAMPLE)
        app.get_ip_details("8.8.8.8")
        with mock.patch.object(api_cache, "READ", False):
            self.assertNotIn("cached", app.get_ip_details("8.8.8.8"))
        self.assertEqual(get.call_count, 2)

    @mock.patch("ip_info_app.requests.get")
    def test_failed_lookup_is_retried(self, get):
        get.side_effect = requests.ConnectionError("offline")
        self.assertIn("error", app.get_ip_details("8.8.8.8"))
        get.side_effect = None
        get.return_value = fake_response(IPAPI_SAMPLE)
        self.assertEqual(app.get_ip_details("8.8.8.8")["source"], "ipapi.co")

    @mock.patch("ip_info_app.requests.get")
    def test_ipapi_key_is_sent(self, get):
        os.environ["IPEEK_IPAPI_KEY"] = "PAID1"
        get.return_value = fake_response(IPAPI_SAMPLE)
        app.get_ip_details("8.8.8.8")
        self.assertEqual(get.call_args.kwargs["params"], {"key": "PAID1"})

    @mock.patch("ip_info_app.requests.get")
    def test_ipstack_used_when_ipapi_fails(self, get):
        os.environ["IPEEK_IPSTACK_KEY"] = "STACK1"
        get.side_effect = [fake_response({"error": True, "reason": "RateLimited"}),
                           fake_response(IPSTACK_SAMPLE)]
        d = app.get_ip_details("8.8.8.8")
        self.assertEqual((d["source"], d["asn"], d["utc_offset"], d["version"], d["postal"]),
                         ("ipstack", "AS15169", "-0700", "IPv4", "94043"))
        self.assertEqual(get.call_args.kwargs["params"], {"access_key": "STACK1"})

    @mock.patch("ip_info_app.requests.get")
    def test_ipstack_error_falls_back_to_ipwhois(self, get):
        os.environ["IPEEK_IPSTACK_KEY"] = "STACK1"
        get.side_effect = [requests.ConnectionError("down"),
                           fake_response({"success": False,
                                          "error": {"code": 101, "info": "Invalid key"}}),
                           fake_response(IPWHOIS_SAMPLE)]
        self.assertEqual(app.get_ip_details("8.8.8.8")["source"], "ipwho.is")

    @mock.patch("ip_info_app.requests.get")
    def test_error_message_never_shows_the_key(self, get):
        os.environ["IPEEK_IPAPI_KEY"] = "SECRET42"
        get.side_effect = requests.HTTPError(
            "403 Client Error for url: https://ipapi.co/8.8.8.8/json/?key=SECRET42")
        d = app.get_ip_details("8.8.8.8")
        self.assertNotIn("SECRET42", d["error"])

    def test_cache_info_and_clear_cache_flags(self):
        self.write_config(ipapi_key="K")
        api_cache.put("8.8.8.8", {"ip": "8.8.8.8"})
        out = io.StringIO()
        with redirect_stdout(out):
            app.main(["--cache-info", "--json"])
        info = json.loads(out.getvalue())
        self.assertEqual((info["cached_addresses"], info["api_keys"]), (1, ["ipapi.co"]))
        self.assertNotIn('"K"', out.getvalue())             # the key itself isn't shown
        with redirect_stdout(io.StringIO()):
            app.main(["--clear-cache"])
        self.assertFalse(os.path.exists(api_cache.PATH))


if __name__ == "__main__":
    unittest.main()
