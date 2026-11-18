"""Unit tests for subnet_calc.py (backlog item B02).

No internet needed.  Run with:   python -m unittest discover -s tests -v
"""
import io
import os
import sys
import unittest
from contextlib import redirect_stdout

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import ip_info_app as app  # noqa: E402
import subnet_calc  # noqa: E402


class SubnetIPv4Tests(unittest.TestCase):
    def test_slash_26(self):
        info = subnet_calc.calculate_subnet("192.168.1.0/26")
        self.assertEqual(info["subnet_mask"], "255.255.255.192")
        self.assertEqual(info["wildcard_mask"], "0.0.0.63")
        self.assertEqual(info["broadcast_address"], "192.168.1.63")
        self.assertEqual((info["first_host"], info["last_host"]),
                         ("192.168.1.1", "192.168.1.62"))
        self.assertEqual((info["usable_hosts"], info["total_addresses"]), (62, 64))

    def test_host_address_gives_its_network(self):
        info = subnet_calc.calculate_subnet("192.168.1.77/26")
        self.assertEqual(info["network"], "192.168.1.64/26")
        self.assertEqual(info["host_given"], "192.168.1.77")

    def test_address_and_mask_form(self):
        info = subnet_calc.calculate_subnet("10.0.0.0 255.255.255.0")
        self.assertEqual((info["network"], info["usable_hosts"]), ("10.0.0.0/24", 254))

    def test_slash_31_and_32(self):
        self.assertEqual(subnet_calc.calculate_subnet("10.0.0.0/31")["usable_hosts"], 2)
        self.assertEqual(subnet_calc.calculate_subnet("10.0.0.5/32")["usable_hosts"], 1)


class SubnetIPv6Tests(unittest.TestCase):
    def test_slash_64(self):
        info = subnet_calc.calculate_subnet("2001:db8:abcd:12::/64")
        self.assertEqual(info["version"], "IPv6")
        self.assertEqual(info["total_addresses"], 2 ** 64)
        self.assertEqual(info["last_host"], "2001:db8:abcd:12:ffff:ffff:ffff:ffff")
        self.assertNotIn("broadcast_address", info)


class SubnetInputTests(unittest.TestCase):
    def test_missing_prefix(self):
        with self.assertRaises(ValueError):
            subnet_calc.calculate_subnet("192.168.1.0")

    def test_invalid_network(self):
        for bad in ("192.168.1.0/33", "300.1.1.0/24", "hello/24"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                subnet_calc.calculate_subnet(bad)

    def test_cli_invalid_input_does_not_crash(self):
        with redirect_stdout(io.StringIO()) as out:
            self.assertIsNone(app.show_subnet("not-a-network"))
        self.assertIn("not a valid network", out.getvalue())


if __name__ == "__main__":
    unittest.main()
