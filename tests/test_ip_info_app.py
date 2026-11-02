"""Unit tests for ip_info_app.py.

The REST APIs are mocked, so these tests run offline and give the same result
every time.  Run with:   python -m unittest discover -s tests -v
"""
import os
import sys
import unittest
from unittest import mock

import requests

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import ip_info_app as app  # noqa: E402

IPAPI_SAMPLE = {
    "ip": "8.8.8.8", "version": "IPv4", "city": "Mountain View",
    "region": "California", "country_name": "United States", "country_code": "US",
    "postal": "94043", "latitude": 37.42, "longitude": -122.08,
    "timezone": "America/Los_Angeles", "utc_offset": "-0700",
    "asn": "AS15169", "org": "GOOGLE", "currency": "USD",
}
IPWHOIS_SAMPLE = {
    "ip": "8.8.8.8", "success": True, "type": "IPv4", "city": "Mountain View",
    "region": "California", "country": "United States", "country_code": "US",
    "latitude": 37.42, "longitude": -122.08,
    "connection": {"asn": 15169, "isp": "Google LLC"},
    "timezone": {"id": "America/Los_Angeles", "utc": "-07:00"},
}


def fake_response(payload, status=200):
    resp = mock.Mock()
    resp.json.return_value = payload
    resp.status_code = status
    resp.raise_for_status.side_effect = (
        None if status < 400 else requests.HTTPError(f"HTTP {status}"))
    return resp


class AnalysisTests(unittest.TestCase):
    def test_public_ipv4(self):
        info = app.analyze_ip("8.8.8.8")
        self.assertEqual(info["version"], "IPv4")
        self.assertEqual(info["scope"], "Public (globally routable)")
        self.assertEqual(info["class"], "A")
        self.assertEqual(info["binary"], "00001000.00001000.00001000.00001000")

    def test_private_ipv4(self):
        self.assertTrue(app.analyze_ip("192.168.1.10")["scope"].startswith("Private"))

    def test_ipv6_compressed_and_expanded(self):
        info = app.analyze_ip("2001:4860:4860::8888")
        self.assertEqual(info["version"], "IPv6")
        self.assertEqual(info["exploded"], "2001:4860:4860:0000:0000:0000:0000:8888")
        self.assertEqual(info["compressed"], "2001:4860:4860::8888")

    def test_link_local_ipv6(self):
        self.assertEqual(app.analyze_ip("fe80::1")["scope"], "Link-local")

    def test_invalid_address(self):
        with self.assertRaises(ValueError):
            app.analyze_ip("999.1.1.1")


class ApiTests(unittest.TestCase):
    @mock.patch("ip_info_app.requests.get")
    def test_get_public_ips(self, get):
        get.side_effect = [fake_response({"ip": "203.0.113.5"}),
                           requests.ConnectionError("no IPv6")]
        self.assertEqual(app.get_public_ips(), {"ipv4": "203.0.113.5", "ipv6": None})

    @mock.patch("ip_info_app.requests.get")
    def test_details_from_ipapi(self, get):
        get.return_value = fake_response(IPAPI_SAMPLE)
        d = app.get_ip_details("8.8.8.8")
        self.assertEqual((d["asn"], d["isp"], d["country_code"], d["source"]),
                         ("AS15169", "GOOGLE", "US", "ipapi.co"))

    @mock.patch("ip_info_app.requests.get")
    def test_falls_back_to_ipwhois_when_rate_limited(self, get):
        get.side_effect = [fake_response({"error": True, "reason": "RateLimited"}),
                           fake_response(IPWHOIS_SAMPLE)]
        d = app.get_ip_details("8.8.8.8")
        self.assertEqual((d["source"], d["asn"], d["isp"]),
                         ("ipwho.is", "AS15169", "Google LLC"))

    @mock.patch("ip_info_app.requests.get")
    def test_both_apis_fail(self, get):
        get.side_effect = requests.ConnectionError("offline")
        self.assertIn("error", app.get_ip_details("8.8.8.8"))


class DisplayTests(unittest.TestCase):
    @mock.patch("ip_info_app.requests.get")
    def test_lookup_invalid_ip_does_not_crash(self, get):
        self.assertIsNone(app.show_lookup("not-an-ip"))
        get.assert_not_called()


if __name__ == "__main__":
    unittest.main()
