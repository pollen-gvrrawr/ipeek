#!/usr/bin/env python3
"""
ip_info_app.py - IPv4/IPv6 Address Application
DEVASC Project Activity 3 (Option 2)

Shows a computer's public IPv4/IPv6 addresses, looks up ISP and location
details for any public IP, and analyses any address offline (version, scope,
class, binary form, compressed/expanded IPv6, reverse DNS name).

The file is split into five layers so each team member can own one part:
    1. CONFIG   - URLs, timeouts, constants
    2. API      - all network calls and response normalisation
    3. ANALYSIS - offline address analysis with the ipaddress module
    4. DISPLAY  - coloured terminal output, JSON output and saving
    5. CLI      - argparse options, interactive menu, program entry point

Usage:
    python ip_info_app.py                  # interactive menu
    python ip_info_app.py --me             # this computer's public IPs
    python ip_info_app.py --ip 8.8.8.8     # look up one address
    python ip_info_app.py --ip 8.8.8.8 --json --save report.json
"""

import argparse
import ipaddress
import json
import sys

import requests

try:
    from colorama import Fore, Style, just_fix_windows_console
except ImportError:  # colours are optional: the app still works without colorama

    class _NoColour:
        """Stand-in for colorama's Fore/Style that returns empty strings."""

        def __getattr__(self, name):
            """Return an empty string for any colour attribute."""
            return ""

    Fore = Style = _NoColour()

    def just_fix_windows_console():
        """No-op replacement used when colorama is not installed."""


# =============================================================================
# LAYER 1: CONFIG
# URLs, timeouts and other constants. Change values here, not in the code below.
# =============================================================================

APP_NAME = "IPv4/IPv6 Address Application"

IPV4_URL = "https://api.ipify.org?format=json"
IPV6_URL = "https://api6.ipify.org?format=json"
IPAPI_URL = "https://ipapi.co/{ip}/json/"      # primary details provider
IPWHOIS_URL = "https://ipwho.is/{ip}"          # fallback details provider
MAPS_URL = "https://www.google.com/maps?q={lat},{lon}"

TIMEOUT = 5  # seconds per HTTP request
HEADERS = {"User-Agent": "ip-info-app/1.0 (DEVASC project)"}

IPV6_UNAVAILABLE = "No public IPv6 available"
IPV4_UNAVAILABLE = "Could not determine public IPv4 (check your connection)"


# =============================================================================
# LAYER 2: API
# Every network call lives here. Functions return None instead of raising, so
# a network problem can never crash the app.
# =============================================================================

def fetch_json(url):
    """GET a URL and return the JSON body as a dict, or None on any error.

    Covers connection errors, timeouts, HTTP error codes (e.g. 429 rate
    limits), invalid JSON and JSON that is not an object.
    """
    try:
        response = requests.get(url, headers=HEADERS, timeout=TIMEOUT)
        response.raise_for_status()
        data = response.json()
    except (requests.RequestException, ValueError):
        return None
    return data if isinstance(data, dict) else None


def get_public_ip(url, version):
    """Ask an ipify endpoint for our public IP and check it is the right version.

    Returns the address as a string, or None if the request failed or the
    service returned something that is not a valid IPv<version> address.
    """
    data = fetch_json(url)
    if not data:
        return None
    try:
        ip = ipaddress.ip_address(str(data.get("ip", "")).strip())
    except ValueError:
        return None
    return str(ip) if ip.version == version else None


def get_public_ipv4():
    """Return this computer's public IPv4 address, or None if unavailable."""
    return get_public_ip(IPV4_URL, 4)


def get_public_ipv6():
    """Return this computer's public IPv6 address, or None if unavailable."""
    return get_public_ip(IPV6_URL, 6)


def build_maps_link(latitude, longitude):
    """Return a Google Maps link for the coordinates, or None if either is missing."""
    if latitude is None or longitude is None:
        return None
    return MAPS_URL.format(lat=latitude, lon=longitude)


def normalise_ipapi(data):
    """Convert an ipapi.co response into the app's standard details dict."""
    return {
        "ip": data.get("ip"),
        "isp": data.get("org"),
        "asn": data.get("asn"),
        "country": data.get("country_name"),
        "country_code": data.get("country_code"),
        "region": data.get("region"),
        "city": data.get("city"),
        "postal": data.get("postal"),
        "latitude": data.get("latitude"),
        "longitude": data.get("longitude"),
        "timezone": data.get("timezone"),
        "source": "ipapi.co",
    }


def normalise_ipwhois(data):
    """Convert an ipwho.is response into the app's standard details dict."""
    connection = data.get("connection") or {}
    timezone = data.get("timezone")
    asn = connection.get("asn")
    return {
        "ip": data.get("ip"),
        "isp": connection.get("isp") or connection.get("org"),
        "asn": f"AS{asn}" if asn else None,
        "country": data.get("country"),
        "country_code": data.get("country_code"),
        "region": data.get("region"),
        "city": data.get("city"),
        "postal": data.get("postal"),
        "latitude": data.get("latitude"),
        "longitude": data.get("longitude"),
        "timezone": timezone.get("id") if isinstance(timezone, dict) else timezone,
        "source": "ipwho.is",
    }


def lookup_ipapi(ip):
    """Look up an IP on ipapi.co. Returns normalised details or None on failure."""
    data = fetch_json(IPAPI_URL.format(ip=ip))
    if not data or data.get("error"):
        return None
    return normalise_ipapi(data)


def lookup_ipwhois(ip):
    """Look up an IP on ipwho.is. Returns normalised details or None on failure."""
    data = fetch_json(IPWHOIS_URL.format(ip=ip))
    if not data or data.get("success") is False:
        return None
    return normalise_ipwhois(data)


def get_ip_details(ip):
    """Get ISP/location details for an IP, trying ipapi.co then ipwho.is.

    Returns the normalised dict with a "maps_link" key added, or None if
    both providers fail.
    """
    details = lookup_ipapi(ip) or lookup_ipwhois(ip)
    if details:
        details["maps_link"] = build_maps_link(details["latitude"], details["longitude"])
    return details


# =============================================================================
# LAYER 3: ANALYSIS
# Offline analysis using only the standard ipaddress module. No network here.
# =============================================================================

def parse_ip(text):
    """Parse user input into an ipaddress object, or return None if invalid.

    Surrounding whitespace and IPv6 brackets (e.g. "[::1]") are accepted.
    """
    if not isinstance(text, str):
        return None
    cleaned = text.strip().strip("[]")
    try:
        return ipaddress.ip_address(cleaned)
    except ValueError:
        return None


def get_scope(ip):
    """Return a human-readable scope label such as "Public" or "Private"."""
    if ip.is_unspecified:
        return "Unspecified"
    if ip.is_loopback:
        return "Loopback"
    if ip.is_link_local:
        return "Link-local"
    if ip.is_multicast:
        return "Multicast"
    if ip.is_private:
        return "Private"
    if ip.is_global:
        return "Public"
    return "Reserved/special-purpose"


def get_ipv4_class(ip):
    """Return the classful network class (A-E) of an IPv4 address."""
    first_octet = ip.packed[0]
    if first_octet < 128:
        return "A"
    if first_octet < 192:
        return "B"
    if first_octet < 224:
        return "C"
    if first_octet < 240:
        return "D (multicast)"
    return "E (experimental)"


def get_ipv4_binary(ip):
    """Return an IPv4 address in dotted binary, e.g. 00001000.00001000...."""
    return ".".join(f"{octet:08b}" for octet in ip.packed)


def analyse_ip(text):
    """Analyse an address offline and return a dict of facts, or None if invalid.

    Always includes address, version, scope, is_public and reverse_dns.
    IPv4 adds ipv4_class and binary; IPv6 adds compressed and expanded.
    """
    ip = parse_ip(text)
    if ip is None:
        return None
    scope = get_scope(ip)
    result = {
        "address": str(ip),
        "version": ip.version,
        "scope": scope,
        "is_public": scope == "Public",
        "reverse_dns": ip.reverse_pointer,
    }
    if ip.version == 4:
        result["ipv4_class"] = get_ipv4_class(ip)
        result["binary"] = get_ipv4_binary(ip)
    else:
        result["compressed"] = ip.compressed
        result["expanded"] = ip.exploded
    return result


# =============================================================================
# LAYER 4: DISPLAY
# Coloured, aligned terminal output, plus JSON printing and saving.
# =============================================================================

LABEL_WIDTH = 14

ANALYSIS_FIELDS = [
    ("address", "Address"),
    ("version", "Version"),
    ("scope", "Scope"),
    ("ipv4_class", "IPv4 class"),
    ("binary", "Binary"),
    ("compressed", "Compressed"),
    ("expanded", "Expanded"),
    ("reverse_dns", "Reverse DNS"),
]

DETAIL_FIELDS = [
    ("isp", "ISP/Org"),
    ("asn", "ASN"),
    ("country", "Country"),
    ("country_code", "Country code"),
    ("region", "Region"),
    ("city", "City"),
    ("postal", "Postal code"),
    ("latitude", "Latitude"),
    ("longitude", "Longitude"),
    ("timezone", "Timezone"),
    ("maps_link", "Google Maps"),
    ("source", "Data source"),
]


def print_heading(title):
    """Print a bright section heading underlined with '='."""
    print()
    print(Style.BRIGHT + Fore.CYAN + title + Style.RESET_ALL)
    print(Fore.CYAN + "=" * len(title) + Style.RESET_ALL)


def print_field(label, value):
    """Print one aligned "label: value" line; empty values show as '-'."""
    shown = "-" if value in (None, "") else str(value)
    print(f"  {Fore.GREEN}{label:<{LABEL_WIDTH}}{Style.RESET_ALL}: {shown}")


def print_note(message):
    """Print an informational warning in yellow."""
    print(f"  {Fore.YELLOW}{message}{Style.RESET_ALL}")


def print_error(message):
    """Print an error message in red to stderr (keeps --json stdout clean)."""
    print(f"{Fore.RED}Error: {message}{Style.RESET_ALL}", file=sys.stderr)


def print_success(message):
    """Print a success message in green to stderr (keeps --json stdout clean)."""
    print(f"{Fore.GREEN}{message}{Style.RESET_ALL}", file=sys.stderr)


def print_report(report):
    """Print a single-address report: offline analysis then online details."""
    analysis = report["analysis"]
    print_heading(f"Address analysis: {analysis['address']}")
    for key, label in ANALYSIS_FIELDS:
        if key in analysis:
            print_field(label, analysis[key])

    if report.get("details"):
        print_heading("ISP and location")
        for key, label in DETAIL_FIELDS:
            print_field(label, report["details"].get(key))
    if report.get("note"):
        print_note(report["note"])


def print_my_report(result):
    """Print this computer's public IPv4/IPv6 summary and a report for each."""
    print_heading("This computer's public addresses")
    print_field("Public IPv4", result["public_ipv4"] or IPV4_UNAVAILABLE)
    print_field("Public IPv6", result["public_ipv6"] or IPV6_UNAVAILABLE)
    for report in result["reports"]:
        print_report(report)


def to_json(data):
    """Return data as an indented JSON string."""
    return json.dumps(data, indent=2, ensure_ascii=False)


def save_json(data, path):
    """Write data to a JSON file. Returns True on success, False on failure."""
    try:
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(to_json(data) + "\n")
    except OSError as exc:
        print_error(f"could not save to {path}: {exc}")
        return False
    print_success(f"Saved results to {path}")
    return True


# =============================================================================
# LAYER 5: CLI
# Builds reports from the API and analysis layers, parses arguments and runs
# the interactive menu.
# =============================================================================

def build_report(text, online=True):
    """Build the full report for one address, or return None if it is invalid.

    Private and other non-public addresses are analysed offline only, without
    calling the APIs. Set online=False to skip the APIs for any address.
    """
    analysis = analyse_ip(text)
    if analysis is None:
        return None
    report = {"analysis": analysis, "details": None, "note": None}
    if not analysis["is_public"]:
        report["note"] = f"{analysis['scope']} address: online lookup skipped."
    elif not online:
        report["note"] = "Offline analysis only: online lookup skipped."
    else:
        report["details"] = get_ip_details(analysis["address"])
        if report["details"] is None:
            report["note"] = "Location lookup failed (ipapi.co and ipwho.is unavailable)."
    return report


def build_my_report():
    """Find this computer's public IPv4/IPv6 and build a report for each one."""
    ipv4 = get_public_ipv4()
    ipv6 = get_public_ipv6()
    return {
        "public_ipv4": ipv4,
        "public_ipv6": ipv6,
        "reports": [build_report(ip) for ip in (ipv4, ipv6) if ip],
    }


def parse_args(argv=None):
    """Parse command-line arguments. With no arguments the menu is used."""
    parser = argparse.ArgumentParser(
        description=f"{APP_NAME} - DEVASC Project Activity 3 (Option 2)",
    )
    target = parser.add_mutually_exclusive_group()
    target.add_argument("--me", action="store_true",
                        help="show this computer's public IPv4/IPv6 details")
    target.add_argument("--ip", metavar="ADDR",
                        help="analyse and look up a specific IPv4/IPv6 address")
    parser.add_argument("--json", action="store_true",
                        help="print results as JSON instead of coloured text")
    parser.add_argument("--save", metavar="FILE",
                        help="save results to a JSON file")
    return parser.parse_args(argv)


def prompt(text):
    """Read a line of user input, returning None on Ctrl+C or end of input."""
    try:
        return input(text).strip().lstrip("﻿")  # BOM from piped input
    except (EOFError, KeyboardInterrupt):
        print()
        return None


def run_menu():
    """Run the interactive menu until the user exits. Returns an exit code."""
    last_result = None
    while True:
        print_heading(APP_NAME)
        print("  1) Show my public IPv4/IPv6 details")
        print("  2) Look up an IP address")
        print("  3) Analyse an IP address offline (no API calls)")
        print("  4) Save last result to a JSON file")
        print("  0) Exit")
        choice = prompt("Select an option: ")

        if choice is None or choice in ("0", "q", "quit", "exit"):
            print("Goodbye.")
            return 0
        if choice == "1":
            last_result = build_my_report()
            print_my_report(last_result)
        elif choice in ("2", "3"):
            address = prompt("Enter an IPv4 or IPv6 address: ")
            if address is None:
                continue
            report = build_report(address, online=(choice == "2"))
            if report is None:
                print_error(f"'{address}' is not a valid IPv4 or IPv6 address.")
            else:
                last_result = report
                print_report(report)
        elif choice == "4":
            if last_result is None:
                print_error("nothing to save yet - run options 1-3 first.")
                continue
            path = prompt("File name [ip_report.json]: ")
            if path is not None:
                save_json(last_result, path or "ip_report.json")
        else:
            print_error("please choose 0, 1, 2, 3 or 4.")


def main(argv=None):
    """Program entry point. Returns a process exit code (0 ok, 1 network, 2 input)."""
    just_fix_windows_console()
    args = parse_args(argv)

    if not (args.me or args.ip or args.json or args.save):
        return run_menu()

    if args.ip is not None:
        result = build_report(args.ip)
        if result is None:
            print_error(f"'{args.ip}' is not a valid IPv4 or IPv6 address.")
            return 2
    else:  # --me, or --json/--save on their own
        result = build_my_report()

    if args.json:
        print(to_json(result))
    elif args.ip is not None:
        print_report(result)
    else:
        print_my_report(result)

    if args.save and not save_json(result, args.save):
        return 1
    if args.ip is None and not result["reports"]:
        return 1  # no public address could be found at all
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print()
        sys.exit(130)
