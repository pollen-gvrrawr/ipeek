"""
IPeek local network information (backlog item B01)
==================================================

Shows the LOCAL side of the connection, next to the public IP: this
computer's private IPv4 address, subnet mask, network, default gateway and
DNS servers. Technicians usually need both sides when troubleshooting.

How it works
------------
    * The private IP comes from the socket module: "connecting" a UDP socket
      makes the operating system pick the interface it would use to reach the
      internet. UDP has no handshake, so no packet is actually sent.
    * The mask, gateway and DNS servers come from the operating system's own
      tools (ipconfig on Windows; ip and /etc/resolv.conf on Linux; ifconfig,
      route and /etc/resolv.conf on macOS).
    * The parse_*() functions only read text, so the unit tests can check them
      with sample output from each operating system.

Used by the CLI in ip_info_app.py (--local and menu option 5).
"""

import ipaddress
import platform
import re
import socket
import subprocess

PROBE_V4 = "8.8.8.8"                 # any public address works; nothing is sent
PROBE_V6 = "2001:4860:4860::8888"
COMMAND_TIMEOUT = 10                 # seconds


# ---------------------------------------------------------------------------
# Reading from the operating system
# ---------------------------------------------------------------------------
def get_local_ip(version=4):
    """Return the address this computer uses to reach the internet, or None."""
    family, probe = (socket.AF_INET, PROBE_V4) if version == 4 else (socket.AF_INET6, PROBE_V6)
    try:
        with socket.socket(family, socket.SOCK_DGRAM) as sock:
            sock.connect((probe, 53))
            return sock.getsockname()[0].split("%")[0]
    except OSError:                   # no network, or no IPv6 route
        return None


def run_command(cmd):
    """Run a system command and return its output, or "" if it fails."""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, errors="replace",
                                timeout=COMMAND_TIMEOUT)
        return result.stdout
    except (OSError, subprocess.SubprocessError):
        return ""


def read_file(path):
    try:
        with open(path, encoding="utf-8") as fh:
            return fh.read()
    except OSError:
        return ""


# ---------------------------------------------------------------------------
# Parsers (text in, dict out: no system calls, so they are easy to test)
# ---------------------------------------------------------------------------
def _clean(value):
    """'fe80::1%11(Preferred)' -> 'fe80::1'"""
    return value.split("(")[0].split("%")[0].strip()


def _is_ipv4(text):
    try:
        return ipaddress.ip_address(text).version == 4
    except ValueError:
        return False


def parse_ipconfig(text, ip):
    """Find the adapter that has address ip in 'ipconfig /all' output.

    Returns {interface, description, subnet_mask, gateway, dns_servers}, or {}
    if no adapter has that address.
    """
    adapters, name, fields, last = [], None, {}, None
    for line in text.splitlines():
        if line and not line[0].isspace() and line.rstrip().endswith(":"):
            adapters.append((name, fields))                  # new adapter starts
            name, fields, last = line.rstrip()[:-1], {}, None
        elif " : " in line:
            label, value = line.split(" : ", 1)
            last = label.replace(".", "").strip()
            fields[last] = [_clean(value)] if value.strip() else []
        elif line.strip() and last:                          # continuation line
            fields[last].append(_clean(line))
    adapters.append((name, fields))

    for name, fields in adapters:
        addresses = fields.get("IPv4 Address", []) + fields.get("IP Address", [])
        if ip in addresses:
            gateways = fields.get("Default Gateway", [])
            ipv4_gateways = [g for g in gateways if _is_ipv4(g)]
            return {
                "interface": name.split(" adapter ")[-1],
                "description": (fields.get("Description") or [None])[0],
                "subnet_mask": (fields.get("Subnet Mask") or [None])[0],
                "gateway": (ipv4_gateways or gateways or [None])[0],
                "dns_servers": fields.get("DNS Servers", []),
            }
    return {}


def parse_ip_addr(text, ip):
    """Linux 'ip -o -4 addr show' -> {interface, prefix_length} for address ip."""
    for line in text.splitlines():
        match = re.match(r"\d+:\s+(\S+)\s+inet\s+([\d.]+)/(\d+)", line)
        if match and match.group(2) == ip:
            return {"interface": match.group(1), "prefix_length": int(match.group(3))}
    return {}


def parse_ip_route(text):
    """Linux 'ip route show default' -> gateway address or None."""
    match = re.search(r"default via (\S+)", text)
    return match.group(1) if match else None


def parse_ifconfig(text, ip):
    """macOS 'ifconfig' -> {interface, subnet_mask} for address ip."""
    interface = None
    for line in text.splitlines():
        if line and not line[0].isspace():
            interface = line.split(":")[0]
        match = re.search(r"inet ([\d.]+) netmask (0x[0-9a-fA-F]+)", line)
        if match and match.group(1) == ip:
            mask = str(ipaddress.IPv4Address(int(match.group(2), 16)))
            return {"interface": interface, "subnet_mask": mask}
    return {}


def parse_route_get(text):
    """macOS 'route -n get default' -> gateway address or None."""
    match = re.search(r"gateway:\s*(\S+)", text)
    return match.group(1) if match else None


def parse_resolv_conf(text):
    """/etc/resolv.conf -> list of DNS server addresses."""
    return [line.split()[1] for line in text.splitlines()
            if line.strip().startswith("nameserver") and len(line.split()) > 1]


# ---------------------------------------------------------------------------
# Putting it together
# ---------------------------------------------------------------------------
def get_local_network(system=None):
    """Return a dict describing this computer's local network connection."""
    system = system or platform.system()
    ipv4 = get_local_ip(4)
    info = {"private_ipv4": ipv4, "local_ipv6": get_local_ip(6), "interface": None,
            "description": None, "subnet_mask": None, "prefix_length": None,
            "network": None, "gateway": None, "dns_servers": []}
    if not ipv4:
        info["error"] = "no active network connection found"
        return info

    if system == "Windows":
        info.update(parse_ipconfig(run_command(["ipconfig", "/all"]), ipv4))
    elif system == "Darwin":
        info.update(parse_ifconfig(run_command(["ifconfig"]), ipv4))
        info["gateway"] = parse_route_get(run_command(["route", "-n", "get", "default"]))
        info["dns_servers"] = parse_resolv_conf(read_file("/etc/resolv.conf"))
    else:                                                    # Linux
        info.update(parse_ip_addr(run_command(["ip", "-o", "-4", "addr", "show"]), ipv4))
        info["gateway"] = parse_ip_route(run_command(["ip", "route", "show", "default"]))
        info["dns_servers"] = parse_resolv_conf(read_file("/etc/resolv.conf"))

    return add_network_details(info)


def add_network_details(info):
    """Fill in the mask/prefix and network address from whichever one is known."""
    mask = info.get("subnet_mask") or info.get("prefix_length")
    if info.get("private_ipv4") and mask:
        iface = ipaddress.ip_interface(f"{info['private_ipv4']}/{mask}")
        info["subnet_mask"] = str(iface.netmask)
        info["prefix_length"] = iface.network.prefixlen
        info["network"] = str(iface.network)
    return info


def local_rows(info):
    """Turn a get_local_network() dict into (label, value) rows for display."""
    return [("Interface", info.get("interface")),
            ("Adapter", info.get("description")),
            ("Private IPv4", info.get("private_ipv4")),
            ("Subnet mask", info.get("subnet_mask") and
             f"{info['subnet_mask']} (/{info['prefix_length']})"),
            ("Network", info.get("network")),
            ("Default gateway", info.get("gateway")),
            ("DNS servers", ", ".join(info.get("dns_servers") or [])),
            ("Local IPv6", info.get("local_ipv6"))]
