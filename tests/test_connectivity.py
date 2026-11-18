"""Unit tests for connectivity.py (backlog item B05).

No real packets are sent: the parsers are checked with sample ping and
traceroute output, and the system calls are mocked.
Run with:   python -m unittest discover -s tests -v
"""
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import connectivity as cn  # noqa: E402

WINDOWS_PING_OK = """
Pinging 8.8.8.8 with 32 bytes of data:
Reply from 8.8.8.8: bytes=32 time=8ms TTL=115
Reply from 8.8.8.8: bytes=32 time=9ms TTL=115

Ping statistics for 8.8.8.8:
    Packets: Sent = 2, Received = 2, Lost = 0 (0% loss),
Approximate round trip times in milli-seconds:
    Minimum = 8ms, Maximum = 9ms, Average = 8ms
"""
WINDOWS_PING_UNREACHABLE = """
Pinging 192.168.1.250 with 32 bytes of data:
Reply from 192.168.1.23: Destination host unreachable.

Ping statistics for 192.168.1.250:
    Packets: Sent = 1, Received = 1, Lost = 0 (0% loss),
"""
LINUX_PING = """
PING 8.8.8.8 (8.8.8.8) 56(84) bytes of data.
64 bytes from 8.8.8.8: icmp_seq=1 ttl=115 time=8.01 ms

--- 8.8.8.8 ping statistics ---
4 packets transmitted, 3 received, 25% packet loss, time 3004ms
rtt min/avg/max/mdev = 8.010/8.120/8.230/0.110 ms
"""
WINDOWS_TRACERT = """
Tracing route to 8.8.8.8 over a maximum of 15 hops

  1     2 ms     3 ms     2 ms  192.168.100.1
  2     *        *        *     Request timed out.
  3    <1 ms     7 ms     6 ms  161.49.10.10
  4    10 ms     7 ms     8 ms  8.8.8.8

Trace complete.
"""
LINUX_TRACEROUTE = """traceroute to 8.8.8.8 (8.8.8.8), 15 hops max, 60 byte packets
 1  10.0.2.2  0.512 ms  0.433 ms  0.401 ms
 2  * * *
"""


class ValidationTests(unittest.TestCase):
    def test_accepts_ips_and_hostnames(self):
        for host in ("8.8.8.8", "2001:4860:4860::8888", "dns.google", "localhost"):
            with self.subTest(host=host):
                self.assertEqual(cn.validate_host(host), host)

    def test_rejects_options_and_shell_text(self):
        for bad in ("-n 999", "8.8.8.8 & del *", "host;reboot", ""):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                cn.validate_host(bad)


class CommandTests(unittest.TestCase):
    def test_ping_commands_per_os(self):
        self.assertEqual(cn.build_ping_command("8.8.8.8", 2, system="Windows"),
                         ["ping", "-n", "2", "-w", "2000", "8.8.8.8"])
        self.assertEqual(cn.build_ping_command("::1", 2, ipv6=True, system="Linux"),
                         ["ping", "-c", "2", "-W", "2", "-6", "::1"])
        self.assertEqual(cn.build_ping_command("::1", 2, ipv6=True, system="Darwin")[0], "ping6")

    def test_traceroute_commands_per_os(self):
        self.assertEqual(cn.build_traceroute_command("8.8.8.8", 15, system="Windows")[0], "tracert")
        self.assertEqual(cn.build_traceroute_command("8.8.8.8", 15, system="Linux")[0], "traceroute")


class ParserTests(unittest.TestCase):
    def test_windows_ping(self):
        r = cn.parse_ping(WINDOWS_PING_OK)
        self.assertEqual((r["sent"], r["received"], r["loss_percent"], r["avg_ms"], r["reachable"]),
                         (2, 2, 0.0, 8.0, True))

    def test_windows_unreachable_is_not_reachable(self):
        self.assertFalse(cn.parse_ping(WINDOWS_PING_UNREACHABLE)["reachable"])

    def test_linux_ping(self):
        r = cn.parse_ping(LINUX_PING)
        self.assertEqual((r["sent"], r["received"], r["loss_percent"], r["avg_ms"]),
                         (4, 3, 25.0, 8.12))

    def test_windows_tracert(self):
        hops = cn.parse_traceroute(WINDOWS_TRACERT)
        self.assertEqual([h["address"] for h in hops],
                         ["192.168.100.1", None, "161.49.10.10", "8.8.8.8"])
        self.assertEqual(hops[2]["ms"], 1.0)                 # "<1 ms"

    def test_linux_traceroute(self):
        hops = cn.parse_traceroute(LINUX_TRACEROUTE)
        self.assertEqual([(h["hop"], h["address"]) for h in hops], [(1, "10.0.2.2"), (2, None)])


class FeatureTests(unittest.TestCase):
    @mock.patch("connectivity.run", return_value=("", "the 'traceroute' command is not installed"))
    def test_missing_command_is_reported(self, _run):
        result = cn.traceroute("8.8.8.8")
        self.assertIn("not installed", result["error"])
        self.assertFalse(result["reached"])

    @mock.patch("connectivity.ping", return_value={"reachable": False, "avg_ms": None})
    @mock.patch("connectivity.socket.getaddrinfo", side_effect=OSError)
    @mock.patch("connectivity.local_network.get_local_ip", return_value=None)
    def test_ipv6_not_ready(self, _ip, _dns, _ping):
        r = cn.ipv6_readiness(lambda: None)
        self.assertEqual((r["passed"], r["total"]), (0, 4))
        self.assertTrue(r["verdict"].startswith("Not ready"))

    @mock.patch("connectivity.ping", return_value={"reachable": True, "avg_ms": 12.0})
    @mock.patch("connectivity.socket.getaddrinfo",
                return_value=[(None, None, None, "", ("2607:f8b0::200e", 443, 0, 0))])
    @mock.patch("connectivity.local_network.get_local_ip", return_value="2001:4860:1::5")
    def test_ipv6_ready(self, _ip, _dns, _ping):
        r = cn.ipv6_readiness(lambda: "2001:4860:1::5")
        self.assertEqual(r["passed"], 4)
        self.assertTrue(r["verdict"].startswith("Ready"))


if __name__ == "__main__":
    unittest.main()
