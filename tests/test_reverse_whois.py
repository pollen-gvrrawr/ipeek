"""Unit tests for reverse_whois.py and the --whois CLI option.

No internet needed: DNS and the RDAP server are mocked with sample data.
Run with:   python -m unittest discover -s tests -v
"""
import io
import json
import os
import socket
import sys
import unittest
from contextlib import redirect_stdout
from unittest import mock

import requests

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import ip_info_app as app  # noqa: E402
import reverse_whois as rw  # noqa: E402


def vcard(fn, kind="org", email=None):
    items = [["version", {}, "text", "4.0"], ["fn", {}, "text", fn], ["kind", {}, "text", kind]]
    if email:
        items.append(["email", {}, "text", email])
    return ["vcard", items]


# Shape of a real ARIN answer (abuse contact nested inside the registrant)
ARIN = {
    "handle": "NET-8-8-8-0-2", "name": "GOGL", "type": "DIRECT ALLOCATION",
    "startAddress": "8.8.8.0", "endAddress": "8.8.8.255", "port43": "whois.arin.net",
    "cidr0_cidrs": [{"v4prefix": "8.8.8.0", "length": 24}],
    "events": [{"eventAction": "registration", "eventDate": "2023-12-28T17:24:33-05:00"},
               {"eventAction": "last changed", "eventDate": "2023-12-28T17:24:56-05:00"}],
    "entities": [{"handle": "GOGL", "roles": ["registrant"], "vcardArray": vcard("Google LLC"),
                  "entities": [{"handle": "ABUSE5250-ARIN", "roles": ["abuse"],
                                "vcardArray": vcard("Abuse", "group",
                                                    "network-abuse@google.com")}]}],
}

# Shape of a real RIPE answer (maintainer listed as a registrant too, people nested)
RIPE = {
    "handle": "193.0.0.0 - 193.0.7.255", "name": "RIPE-NCC", "type": "ASSIGNED PA",
    "startAddress": "193.0.0.0", "endAddress": "193.0.7.255", "country": "NL",
    "port43": "whois.ripe.net", "cidr0_cidrs": [{"v4prefix": "193.0.0.0", "length": 21}],
    "entities": [
        {"handle": "RIPE-NCC-MNT", "roles": ["registrant"],
         "vcardArray": vcard("RIPE-NCC-MNT", "individual")},
        {"handle": "ORG-RIEN1-RIPE", "roles": ["registrant"], "vcardArray": vcard("RIPE NCC")},
        {"handle": "OPS4-RIPE", "roles": ["abuse"],
         "vcardArray": vcard("RIPE NCC Operations", "group", "abuse@ripe.net"),
         "entities": [{"handle": "XY1-RIPE", "roles": ["technical"],
                       "vcardArray": vcard("A Person", "individual")}]},
    ],
}


def fake_response(status=200, data=None, url="https://rdap.arin.net/registry/ip/8.8.8.8"):
    response = mock.Mock(status_code=status, url=url)
    response.json.return_value = data or {}
    response.raise_for_status.side_effect = (
        requests.HTTPError(f"{status} error") if status >= 400 else None)
    return response


class ParseRdapTests(unittest.TestCase):
    def test_arin(self):
        w = rw.parse_rdap(ARIN)
        self.assertEqual(w["owner"], "Google LLC")
        self.assertEqual(w["abuse_email"], "network-abuse@google.com")
        self.assertEqual(w["range"], "8.8.8.0 - 8.8.8.255")
        self.assertEqual(w["cidr"], "8.8.8.0/24")
        self.assertEqual((w["registered"], w["last_changed"]), ("2023-12-28", "2023-12-28"))
        self.assertEqual(w["registry"], "ARIN (North America)")

    def test_ripe_prefers_organisation_and_hides_people(self):
        w = rw.parse_rdap(RIPE)
        self.assertEqual(w["owner"], "RIPE NCC")                  # not the maintainer
        self.assertEqual(w["abuse_email"], "abuse@ripe.net")
        self.assertEqual(w["country"], "NL")
        self.assertNotIn("A Person", json.dumps(w))               # no personal names

    def test_missing_fields_do_not_crash(self):
        w = rw.parse_rdap({})
        self.assertIsNone(w["owner"])
        self.assertIsNone(w["range"])
        self.assertIsNone(w["cidr"])


class WhoisTests(unittest.TestCase):
    def test_success_keeps_registry_url(self):
        with mock.patch.object(rw.requests, "get", return_value=fake_response(data=ARIN)):
            w = rw.whois("8.8.8.8")
        self.assertEqual(w["source"], "https://rdap.arin.net/registry/ip/8.8.8.8")

    def test_not_found_and_rate_limit(self):
        for status, text in ((404, "no WHOIS record"), (429, "rate-limiting")):
            with self.subTest(status=status), \
                    mock.patch.object(rw.requests, "get", return_value=fake_response(status)), \
                    self.assertRaisesRegex(ValueError, text):
                rw.whois("8.8.8.8")


class ReverseDnsTests(unittest.TestCase):
    def test_hostname_forward_confirmed(self):
        with mock.patch.object(rw.socket, "gethostbyaddr",
                               return_value=("dns.google", [], ["8.8.8.8"])), \
                mock.patch.object(rw.socket, "getaddrinfo",
                                  return_value=[(2, 1, 6, "", ("8.8.8.8", 0))]):
            dns = rw.reverse_dns("8.8.8.8")
        self.assertEqual(dns["hostname"], "dns.google")
        self.assertTrue(dns["forward_confirmed"])

    def test_hostname_not_forward_confirmed(self):
        with mock.patch.object(rw.socket, "gethostbyaddr",
                               return_value=("mail.example.com", [], ["203.0.113.9"])), \
                mock.patch.object(rw.socket, "getaddrinfo",
                                  return_value=[(2, 1, 6, "", ("198.51.100.1", 0))]):
            self.assertFalse(rw.reverse_dns("203.0.113.9")["forward_confirmed"])

    def test_ipv6_cannot_be_checked_without_ipv6(self):
        with mock.patch.object(rw.socket, "getaddrinfo", side_effect=socket.gaierror(11004)):
            self.assertIsNone(rw.forward_confirms("dns.google", "2001:4860:4860::8888"))
            self.assertFalse(rw.forward_confirms("dns.google", "8.8.8.8"))

    def test_no_ptr_record(self):
        with mock.patch.object(rw.socket, "gethostbyaddr", side_effect=socket.herror(1)):
            dns = rw.reverse_dns("192.0.2.1")
        self.assertIsNone(dns["hostname"])
        self.assertIn("no PTR record", dns["error"])


def fake_dns(ip):
    return {"hostname": "dns.google", "aliases": [], "forward_confirmed": True, "error": None}


class LookupTests(unittest.TestCase):
    def test_public_address(self):
        with mock.patch.object(rw, "reverse_dns", side_effect=fake_dns), \
                mock.patch.object(rw.requests, "get", return_value=fake_response(data=ARIN)):
            result = rw.lookup(" 8.8.8.8 ")
        rows = {label: value for kind, label, value in rw.lookup_rows(result) if kind == "row"}
        self.assertEqual(rows["Hostname"], "dns.google")
        self.assertEqual(rows["PTR name"], "8.8.8.8.in-addr.arpa")
        self.assertEqual(rows["Owner"], "Google LLC")
        self.assertIn("yes", rows["Forward-confirmed"])

    def test_private_address_skips_whois(self):
        with mock.patch.object(rw, "reverse_dns", side_effect=fake_dns), \
                mock.patch.object(rw.requests, "get") as get:
            result = rw.lookup("192.168.1.1")
        get.assert_not_called()
        self.assertIn("not a public address", result["whois_error"])
        self.assertEqual(rw.lookup_rows(result)[-1][0], "error")

    def test_offline(self):
        with mock.patch.object(rw, "reverse_dns", side_effect=fake_dns), \
                mock.patch.object(rw.requests, "get", side_effect=requests.ConnectionError()):
            self.assertIn("could not reach", rw.lookup("8.8.8.8")["whois_error"])

    def test_invalid_address(self):
        with self.assertRaises(ValueError):
            rw.lookup("999.1.1.1")


class CliTests(unittest.TestCase):
    def run_cli(self, *args):
        with mock.patch.object(rw, "reverse_dns", side_effect=fake_dns), \
                mock.patch.object(rw.requests, "get", return_value=fake_response(data=ARIN)), \
                redirect_stdout(io.StringIO()) as out:
            app.main(["--no-color", *args])
        return out.getvalue()

    def test_whois_flag(self):
        text = self.run_cli("--whois", "8.8.8.8")
        for expected in ("REVERSE DNS / WHOIS: 8.8.8.8", "dns.google", "Google LLC",
                         "network-abuse@google.com", "8.8.8.0/24"):
            self.assertIn(expected, text)

    def test_whois_json(self):
        data = json.loads(self.run_cli("--whois", "8.8.8.8", "--json"))
        self.assertEqual(data["whois"]["owner"], "Google LLC")
        self.assertEqual(data["dns"]["hostname"], "dns.google")

    def test_invalid_input_does_not_crash(self):
        self.assertIn("not a valid", self.run_cli("--whois", "not-an-ip"))


if __name__ == "__main__":
    unittest.main()
