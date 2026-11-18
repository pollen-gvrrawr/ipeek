"""
IPeek connectivity tests (backlog item B05)
===========================================

Ping and traceroute to a chosen host, plus an IPv6 readiness check that shows
whether IPv6 really works end to end, not just whether an address exists.

How it works
------------
    * ping and traceroute use the operating system's own commands (ping and
      tracert on Windows; ping and traceroute on Linux/macOS), run with
      subprocess and NO shell. The host is validated first, so text such as
      "-n 999" or "8.8.8.8 & del" can never reach the command line.
    * build_*_command() and parse_*() only work with lists and text, so the
      unit tests can check them on any system without sending real packets.

Used by the CLI in ip_info_app.py (--ping, --trace, --ipv6-check and menu
options 6-8).
"""

import ipaddress
import platform
import re
import socket
import subprocess

import local_network

PING_COUNT = 4
MAX_HOPS = 15
IPV6_TEST_HOST = "ipv6.google.com"           # has only an IPv6 (AAAA) address
IPV6_TEST_ADDRESS = "2001:4860:4860::8888"   # Google Public DNS over IPv6

HOSTNAME = re.compile(r"(?=.{1,253}$)[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
                      r"(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\.?")


def validate_host(host):
    """Return the host if it is an IP address or a hostname, else raise ValueError."""
    host = host.strip()
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        pass
    if HOSTNAME.fullmatch(host):
        return host
    raise ValueError(f"'{host}' is not a valid IP address or hostname")


# ---------------------------------------------------------------------------
# Building and running the commands
# ---------------------------------------------------------------------------
def build_ping_command(host, count=PING_COUNT, ipv6=False, system=None):
    system = system or platform.system()
    if system == "Windows":
        return ["ping", "-n", str(count), "-w", "2000"] + (["-6"] if ipv6 else []) + [host]
    if system == "Darwin":
        return ["ping6" if ipv6 else "ping", "-c", str(count), host]
    return ["ping", "-c", str(count), "-W", "2"] + (["-6"] if ipv6 else []) + [host]


def build_traceroute_command(host, max_hops=MAX_HOPS, ipv6=False, system=None):
    system = system or platform.system()
    if system == "Windows":
        return (["tracert", "-d", "-h", str(max_hops), "-w", "1000"]
                + (["-6"] if ipv6 else []) + [host])
    if system == "Darwin":
        return ["traceroute6" if ipv6 else "traceroute", "-n", "-m", str(max_hops), host]
    return (["traceroute", "-n", "-m", str(max_hops), "-w", "2"]
            + (["-6"] if ipv6 else []) + [host])


def run(cmd, timeout):
    """Run cmd without a shell. Returns (output, error message or None)."""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, errors="replace",
                                timeout=timeout)
        return result.stdout + result.stderr, None
    except FileNotFoundError:
        hint = " (on Linux: sudo apt install traceroute)" if "traceroute" in cmd[0] else ""
        return "", f"the '{cmd[0]}' command is not installed{hint}"
    except subprocess.TimeoutExpired:
        return "", f"'{cmd[0]}' took longer than {timeout} seconds"


# ---------------------------------------------------------------------------
# Parsers (text in, dict out)
# ---------------------------------------------------------------------------
def parse_ping(output):
    """Read packet counts, loss and average time from ping output (any OS)."""
    result = {"sent": None, "received": None, "loss_percent": None, "avg_ms": None}
    win = re.search(r"Sent = (\d+), Received = (\d+)", output)
    unix = re.search(r"(\d+) packets transmitted, (\d+) (?:packets )?received", output)
    counts = win or unix
    if counts:
        result["sent"], result["received"] = int(counts.group(1)), int(counts.group(2))
    loss = re.search(r"(\d+(?:\.\d+)?)% (?:packet )?loss", output)
    if loss:
        result["loss_percent"] = float(loss.group(1))
    avg = (re.search(r"Average = (\d+)ms", output)                     # Windows
           or re.search(r"= [\d.]+/([\d.]+)/", output))                 # Linux/macOS
    if avg:
        result["avg_ms"] = float(avg.group(1))
    # Windows counts "Destination host unreachable" as a reply but gives no
    # round-trip time, so a host is only reachable if there is an average time.
    result["reachable"] = result["avg_ms"] is not None
    return result


def parse_traceroute(output):
    """Return a list of hops: {'hop': n, 'address': str or None, 'ms': float or None}."""
    hops = []
    for line in output.splitlines():
        match = re.match(r"\s*(\d+)\s+(.*)", line)
        if not match:
            continue
        address = None
        for token in match.group(2).replace("(", " ").replace(")", " ").split():
            try:
                address = str(ipaddress.ip_address(token))
                break
            except ValueError:
                continue
        time = re.search(r"<?(\d+(?:\.\d+)?)\s*ms", match.group(2))
        hops.append({"hop": int(match.group(1)), "address": address,
                     "ms": float(time.group(1)) if time else None})
    return hops


# ---------------------------------------------------------------------------
# Features
# ---------------------------------------------------------------------------
def ping(host, count=PING_COUNT, ipv6=False):
    host = validate_host(host)
    output, error = run(build_ping_command(host, count, ipv6), timeout=count * 3 + 5)
    result = {"host": host, **parse_ping(output)}
    if error:
        result["error"] = error
    return result


def traceroute(host, max_hops=MAX_HOPS, ipv6=False):
    host = validate_host(host)
    output, error = run(build_traceroute_command(host, max_hops, ipv6),
                        timeout=max_hops * 4 + 10)
    hops = parse_traceroute(output)
    result = {"host": host, "hops": hops,
              "reached": bool(hops) and hops[-1]["address"] is not None}
    if error:
        result["error"] = error
    return result


def ipv6_readiness(public_ipv6_lookup=None):
    """Check IPv6 step by step and give an overall verdict.

    public_ipv6_lookup is a function that returns this computer's public IPv6
    (ip_info_app passes its ipify lookup), so this module needs no API code.
    """
    checks = []

    local = local_network.get_local_ip(6)
    has_global = bool(local) and ipaddress.ip_address(local).is_global
    checks.append({"name": "Global IPv6 address on this computer", "passed": has_global,
                   "detail": local or "none (only link-local or no IPv6)"})

    try:
        aaaa = socket.getaddrinfo(IPV6_TEST_HOST, 443, socket.AF_INET6)[0][4][0]
        checks.append({"name": f"DNS returns an IPv6 address for {IPV6_TEST_HOST}",
                       "passed": True, "detail": aaaa})
    except OSError:
        checks.append({"name": f"DNS returns an IPv6 address for {IPV6_TEST_HOST}",
                       "passed": False, "detail": "no AAAA answer"})

    reply = ping(IPV6_TEST_ADDRESS, count=2, ipv6=True)
    checks.append({"name": f"Ping {IPV6_TEST_ADDRESS} over IPv6", "passed": reply["reachable"],
                   "detail": f"{reply['avg_ms']:.0f} ms average" if reply["reachable"]
                   else reply.get("error", "no reply")})

    if public_ipv6_lookup:
        public = public_ipv6_lookup()
        checks.append({"name": "Websites see a public IPv6 address", "passed": bool(public),
                       "detail": public or "not detected"})

    passed = sum(c["passed"] for c in checks)
    if passed == len(checks):
        verdict = "Ready: IPv6 works end to end"
    elif has_global:
        verdict = "Partly ready: this computer has IPv6, but traffic does not get through"
    else:
        verdict = "Not ready: this network does not provide IPv6"
    return {"checks": checks, "passed": passed, "total": len(checks), "verdict": verdict}
