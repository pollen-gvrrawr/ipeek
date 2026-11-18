"""Unit tests for local_network.py (backlog item B01).

The parsers are checked with sample command output from Windows, Linux and
macOS, and the system calls are mocked, so the results are the same on any
computer.  Run with:   python -m unittest discover -s tests -v
"""
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import local_network as ln  # noqa: E402

IPCONFIG_SAMPLE = """
Windows IP Configuration

   Host Name . . . . . . . . . . . . : TECH-PC

Ethernet adapter VirtualBox Host-Only:

   Description . . . . . . . . . . . : VirtualBox Host-Only Ethernet Adapter
   IPv4 Address. . . . . . . . . . . : 192.168.56.1(Preferred)
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . :

Wireless LAN adapter Wi-Fi:

   Description . . . . . . . . . . . : Intel(R) Wi-Fi 6 AX201
   Link-local IPv6 Address . . . . . : fe80::1c2d:3e4f:5a6b:7c8d%12(Preferred)
   IPv4 Address. . . . . . . . . . . : 192.168.1.23(Preferred)
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : fe80::1%12
                                       192.168.1.1
   DNS Servers . . . . . . . . . . . : 192.168.1.1
                                       8.8.8.8
"""

IP_ADDR_SAMPLE = """\
1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever preferred_lft forever
2: eth0    inet 10.0.2.15/24 brd 10.0.2.255 scope global dynamic eth0\\       valid_lft 86000sec
"""

IFCONFIG_SAMPLE = """\
lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384
\tinet 127.0.0.1 netmask 0xff000000
en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\tinet 192.168.0.42 netmask 0xfffffc00 broadcast 192.168.3.255
"""


class WindowsParserTests(unittest.TestCase):
    def test_picks_the_adapter_with_our_ip(self):
        info = ln.parse_ipconfig(IPCONFIG_SAMPLE, "192.168.1.23")
        self.assertEqual(info["interface"], "Wi-Fi")
        self.assertEqual(info["subnet_mask"], "255.255.255.0")
        self.assertEqual(info["dns_servers"], ["192.168.1.1", "8.8.8.8"])

    def test_prefers_ipv4_gateway_over_ipv6_link_local(self):
        self.assertEqual(ln.parse_ipconfig(IPCONFIG_SAMPLE, "192.168.1.23")["gateway"],
                         "192.168.1.1")

    def test_unknown_ip_returns_empty(self):
        self.assertEqual(ln.parse_ipconfig(IPCONFIG_SAMPLE, "10.9.9.9"), {})


class LinuxAndMacParserTests(unittest.TestCase):
    def test_linux_ip_addr(self):
        self.assertEqual(ln.parse_ip_addr(IP_ADDR_SAMPLE, "10.0.2.15"),
                         {"interface": "eth0", "prefix_length": 24})

    def test_linux_default_route(self):
        self.assertEqual(ln.parse_ip_route("default via 10.0.2.2 dev eth0 proto dhcp"),
                         "10.0.2.2")
        self.assertIsNone(ln.parse_ip_route(""))

    def test_mac_ifconfig_hex_netmask(self):
        self.assertEqual(ln.parse_ifconfig(IFCONFIG_SAMPLE, "192.168.0.42"),
                         {"interface": "en0", "subnet_mask": "255.255.252.0"})

    def test_mac_route_get(self):
        self.assertEqual(ln.parse_route_get("   route to: default\n    gateway: 192.168.0.1\n"),
                         "192.168.0.1")

    def test_resolv_conf(self):
        text = "# generated\nnameserver 1.1.1.1\nsearch home\nnameserver 2606:4700::1111\n"
        self.assertEqual(ln.parse_resolv_conf(text), ["1.1.1.1", "2606:4700::1111"])


class GetLocalNetworkTests(unittest.TestCase):
    @mock.patch("local_network.run_command", return_value=IPCONFIG_SAMPLE)
    @mock.patch("local_network.get_local_ip",
                side_effect=lambda version=4: "192.168.1.23" if version == 4 else None)
    def test_windows_full_report(self, _ip, _run):
        info = ln.get_local_network(system="Windows")
        self.assertEqual((info["private_ipv4"], info["gateway"], info["network"],
                          info["prefix_length"]),
                         ("192.168.1.23", "192.168.1.1", "192.168.1.0/24", 24))

    def test_mask_from_prefix_length(self):
        info = ln.add_network_details({"private_ipv4": "10.0.2.15", "prefix_length": 24})
        self.assertEqual((info["subnet_mask"], info["network"]),
                         ("255.255.255.0", "10.0.2.0/24"))

    @mock.patch("local_network.get_local_ip", return_value=None)
    def test_no_network_does_not_crash(self, _ip):
        self.assertIn("error", ln.get_local_network(system="Windows"))


if __name__ == "__main__":
    unittest.main()
