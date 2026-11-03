"""
IPeek: IPv4/IPv6 Address Application  (DEVASC Project Activity 3 - Option 2)
============================================================================

A command-line prototype for network technicians that shows the computer's
current PUBLIC IP addressing information, using free REST APIs:

    * ipify  (https://www.ipify.org)  - returns the public IPv4 / IPv6 address
    * ipapi.co (https://ipapi.co)     - returns details for an IP address:
                                        geolocation, ISP/organization, ASN,
                                        country code, timezone, etc.
    * ipwho.is (https://ipwho.is)     - backup details API, used automatically
                                        when ipapi.co fails or is rate-limited

On top of the API data, the app uses Python's built-in ``ipaddress`` module to
analyse each address (version, scope, compressed/expanded IPv6, reverse DNS
pointer name, binary form of IPv4).

How to run
----------
    pip install -r requirements.txt
    python ip_info_app.py                 # interactive menu
    python ip_info_app.py --me            # show my public IPv4 + IPv6 and exit
    python ip_info_app.py --ip 8.8.8.8    # look up any IPv4/IPv6 address
    python ip_info_app.py --me --json     # print raw JSON (for scripts)
    python ip_info_app.py --me --save report.json   # save results to a file

Code layout (for teams continuing this project)
-----------------------------------------------
    1. CONFIG            - API URLs and timeouts (change APIs here)
    2. API LAYER         - functions that call the REST APIs and return dicts
    3. ANALYSIS LAYER    - offline analysis with the ipaddress module
    4. DISPLAY LAYER     - functions that format and print the results
    5. CLI / MENU        - argument parsing and the interactive menu

Each layer only talks to the one below it, so a new feature (e.g. a GUI or a
new API) can be added by replacing one layer without touching the others.
"""

import argparse
import ipaddress
import json
import os
import sys
from datetime import datetime

import requests
from colorama import Fore, Style, just_fix_windows_console

# ---------------------------------------------------------------------------
# 1. CONFIG
# ---------------------------------------------------------------------------
IPV4_URL = "https://api.ipify.org?format=json"    # IPv4 only
IPV6_URL = "https://api6.ipify.org?format=json"   # IPv6 only (fails if no IPv6)
IPAPI_URL = "https://ipapi.co/{ip}/json/"          # primary details API
IPWHOIS_URL = "https://ipwho.is/{ip}"              # backup details API
TIMEOUT = 5                                        # seconds per request
APP_VERSION = "1.0.0"


# ---------------------------------------------------------------------------
# Terminal colours (colorama). Disabled automatically when output is
# redirected or when the user passes --no-color.
# ---------------------------------------------------------------------------
class Color:
    HEADER = Fore.LIGHTMAGENTA_EX
    BLUE = Fore.LIGHTBLUE_EX
    CYAN = Fore.LIGHTCYAN_EX
    GREEN = Fore.LIGHTGREEN_EX
    YELLOW = Fore.LIGHTYELLOW_EX
    RED = Fore.LIGHTRED_EX
    BOLD = Style.BRIGHT
    END = Style.RESET_ALL

    @classmethod
    def disable(cls):
        for name in ("HEADER", "BLUE", "CYAN", "GREEN", "YELLOW", "RED", "BOLD", "END"):
            setattr(cls, name, "")


just_fix_windows_console()  # enables colour codes in the Windows console


# ---------------------------------------------------------------------------
# 2. API LAYER
# ---------------------------------------------------------------------------
def get_public_ip(url):
    """Call an ipify endpoint and return the IP string, or None on failure.

    ipify answers with JSON like {"ip": "203.0.113.5"}. The IPv6 endpoint
    cannot be reached at all when the network has no IPv6, so a connection
    error simply means "no public IPv6" rather than a crash.
    """
    try:
        response = requests.get(url, timeout=TIMEOUT)
        response.raise_for_status()
        return response.json().get("ip")
    except (requests.RequestException, ValueError):
        return None


def get_public_ips():
    """Return {'ipv4': str|None, 'ipv6': str|None} for this computer."""
    return {"ipv4": get_public_ip(IPV4_URL), "ipv6": get_public_ip(IPV6_URL)}


def _from_ipapi(ip):
    """Query ipapi.co and normalise the answer. Raises on error/rate-limit."""
    response = requests.get(IPAPI_URL.format(ip=ip), timeout=TIMEOUT,
                            headers={"User-Agent": "ipeek/" + APP_VERSION})
    response.raise_for_status()
    data = response.json()
    if data.get("error"):                      # e.g. "RateLimited", "Reserved IP"
        raise ValueError(data.get("reason", "ipapi.co error"))
    return {
        "ip": data.get("ip", ip),
        "version": data.get("version"),
        "city": data.get("city"),
        "region": data.get("region"),
        "country": data.get("country_name"),
        "country_code": data.get("country_code"),
        "postal": data.get("postal"),
        "latitude": data.get("latitude"),
        "longitude": data.get("longitude"),
        "timezone": data.get("timezone"),
        "utc_offset": data.get("utc_offset"),
        "isp": data.get("org"),
        "asn": data.get("asn"),
        "currency": data.get("currency"),
        "source": "ipapi.co",
    }


def _from_ipwhois(ip):
    """Query ipwho.is (backup) and normalise to the same keys as ipapi.co."""
    response = requests.get(IPWHOIS_URL.format(ip=ip), timeout=TIMEOUT)
    response.raise_for_status()
    data = response.json()
    if not data.get("success", False):
        raise ValueError(data.get("message", "ipwho.is error"))
    conn = data.get("connection", {}) or {}
    tz = data.get("timezone", {}) or {}
    asn = conn.get("asn")
    return {
        "ip": data.get("ip", ip),
        "version": data.get("type"),
        "city": data.get("city"),
        "region": data.get("region"),
        "country": data.get("country"),
        "country_code": data.get("country_code"),
        "postal": data.get("postal"),
        "latitude": data.get("latitude"),
        "longitude": data.get("longitude"),
        "timezone": tz.get("id"),
        "utc_offset": tz.get("utc"),
        "isp": conn.get("isp") or conn.get("org"),
        "asn": f"AS{asn}" if asn else None,
        "currency": None,
        "source": "ipwho.is",
    }


def get_ip_details(ip):
    """Return details for an IP address as a dict.

    Tries ipapi.co first, then ipwho.is. If both fail, returns a dict with an
    'error' key so the caller can still show the offline analysis.
    """
    errors = []
    for name, provider in (("ipapi.co", _from_ipapi), ("ipwho.is", _from_ipwhois)):
        try:
            return provider(ip)
        except (requests.RequestException, ValueError) as exc:
            reason = "connection failed" if isinstance(exc, requests.ConnectionError) else exc
            errors.append(f"{name}: {reason}")
    return {"ip": ip, "error": "; ".join(errors)}


# ---------------------------------------------------------------------------
# 3. ANALYSIS LAYER  (no internet needed)
# ---------------------------------------------------------------------------
def analyze_ip(ip):
    """Describe an address with the standard-library ipaddress module.

    Raises ValueError if the text is not a valid IPv4/IPv6 address.
    """
    addr = ipaddress.ip_address(ip.strip())
    info = {
        "address": str(addr),
        "version": f"IPv{addr.version}",
        "scope": _scope(addr),
        "reverse_pointer": addr.reverse_pointer,
    }
    if addr.version == 4:
        info["binary"] = ".".join(f"{int(o):08b}" for o in str(addr).split("."))
        info["class"] = _ipv4_class(addr)
    else:
        info["compressed"] = addr.compressed
        info["exploded"] = addr.exploded
        if addr.ipv4_mapped:
            info["ipv4_mapped"] = str(addr.ipv4_mapped)
    return info


def _scope(addr):
    """Return a human-readable scope for the address."""
    if addr.is_loopback:
        return "Loopback"
    if addr.is_link_local:
        return "Link-local"
    if addr.is_multicast:
        return "Multicast"
    if addr.is_private:
        return "Private (not routable on the Internet)"
    if addr.is_reserved or addr.is_unspecified:
        return "Reserved"
    return "Public (globally routable)"


def _ipv4_class(addr):
    """Classful network class (A-E) - still asked about in networking courses."""
    first = int(str(addr).split(".")[0])
    if first < 128:
        return "A"
    if first < 192:
        return "B"
    if first < 224:
        return "C"
    if first < 240:
        return "D (multicast)"
    return "E (experimental)"


def build_report(ip):
    """Combine API details and offline analysis for one IP into one dict.

    Private/loopback/link-local addresses have no ISP or location, so the
    online lookup is skipped for them (saves API calls).
    """
    analysis = analyze_ip(ip)
    if ipaddress.ip_address(analysis["address"]).is_global:
        details = get_ip_details(analysis["address"])
    else:
        details = {"ip": analysis["address"],
                   "error": "not a public address, so it has no ISP/location data"}
    return {"analysis": analysis, "details": details}


# ---------------------------------------------------------------------------
# 4. DISPLAY LAYER
# ---------------------------------------------------------------------------
LINE = "=" * 60


def print_header(title):
    print(f"\n{Color.BOLD}{Color.HEADER}{LINE}\n {title}\n{LINE}{Color.END}")


def print_row(label, value):
    """Print one aligned 'Label : value' row; empty values show as N/A."""
    shown = value if value not in (None, "") else f"{Color.YELLOW}N/A{Color.END}"
    print(f"  {Color.CYAN}{label:<22}{Color.END}: {shown}")


def print_report(report):
    """Pretty-print a report produced by build_report()."""
    a, d = report["analysis"], report["details"]
    print_header(f"{a['version']} ADDRESS: {a['address']}")

    print(f"{Color.BOLD} Address analysis{Color.END}")
    print_row("Version", a["version"])
    print_row("Scope", a["scope"])
    if a["version"] == "IPv4":
        print_row("Class", a["class"])
        print_row("Binary", a["binary"])
    else:
        print_row("Compressed", a["compressed"])
        print_row("Expanded", a["exploded"])
        if "ipv4_mapped" in a:
            print_row("IPv4-mapped", a["ipv4_mapped"])
    print_row("Reverse DNS name", a["reverse_pointer"])

    print(f"\n{Color.BOLD} Provider & location{Color.END}")
    if "error" in d:
        print(f"  {Color.RED}Could not get online details: {d['error']}{Color.END}")
        return
    print_row("ISP / Organization", d.get("isp"))
    print_row("ASN", d.get("asn"))
    print_row("Country", f"{d.get('country')} ({d.get('country_code')})")
    print_row("Region / City", f"{d.get('region')} / {d.get('city')}")
    print_row("Postal code", d.get("postal"))
    if d.get("latitude") is not None:
        print_row("Coordinates", f"{d['latitude']}, {d['longitude']}")
        print_row("Map", f"https://www.google.com/maps?q={d['latitude']},{d['longitude']}")
    print_row("Timezone", f"{d.get('timezone')} (UTC{d.get('utc_offset') or ''})")
    print(f"  {Color.BLUE}(data source: {d.get('source')}){Color.END}")


def show_my_ips(as_json=False, save_path=None):
    """Feature: look up and display this computer's public IPv4 and IPv6."""
    ips = get_public_ips()
    results = {"generated": datetime.now().isoformat(timespec="seconds"),
               "public_ipv4": ips["ipv4"], "public_ipv6": ips["ipv6"],
               "reports": []}
    for ip in (ips["ipv4"], ips["ipv6"]):
        if ip:
            results["reports"].append(build_report(ip))

    if as_json:
        print(json.dumps(results, indent=2))
    else:
        print_header("MY PUBLIC IP ADDRESSES")
        print_row("Public IPv4", ips["ipv4"] or f"{Color.RED}not detected{Color.END}")
        print_row("Public IPv6", ips["ipv6"] or
                  f"{Color.YELLOW}not available (network has no IPv6){Color.END}")
        for report in results["reports"]:
            print_report(report)
    if save_path:
        save_results(results, save_path)
    return results


def show_lookup(ip, as_json=False, save_path=None):
    """Feature: look up any IPv4/IPv6 address the technician types in."""
    try:
        report = build_report(ip)
    except ValueError:
        print(f"{Color.RED}'{ip}' is not a valid IPv4 or IPv6 address.{Color.END}")
        return None
    if as_json:
        print(json.dumps(report, indent=2))
    else:
        print_report(report)
    if save_path:
        save_results(report, save_path)
    return report


def save_results(data, path):
    """Feature: save results to a .json or .txt file for ticket records."""
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
    print(f"\n{Color.GREEN}Saved to {os.path.abspath(path)}{Color.END}")


# ---------------------------------------------------------------------------
# 5. CLI / MENU
# ---------------------------------------------------------------------------
MENU = """
{b}IPeek v{v}: IPv4/IPv6 Address Application{e}
  1) Show my public IPv4 and IPv6 information
  2) Look up another IP address
  3) Save my public IP report to a file
  q) Quit
"""


def interactive_menu():
    """Menu loop, similar in style to the DEVASC MapQuest lab (type q to quit)."""
    while True:
        print(MENU.format(b=Color.BOLD, v=APP_VERSION, e=Color.END))
        choice = input("Choose an option: ").strip().lower()
        if choice in ("q", "quit"):
            print("Goodbye!")
            break
        if choice == "1":
            show_my_ips()
        elif choice == "2":
            ip = input("Enter an IPv4 or IPv6 address: ").strip()
            show_lookup(ip)
        elif choice == "3":
            name = input("File name [ip_report.json]: ").strip() or "ip_report.json"
            show_my_ips(save_path=name)
        else:
            print(f"{Color.YELLOW}Please choose 1, 2, 3 or q.{Color.END}")


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Show public IPv4/IPv6 addressing information for network technicians.")
    parser.add_argument("--me", action="store_true", help="show my public IPv4/IPv6 and exit")
    parser.add_argument("--ip", help="look up a specific IPv4 or IPv6 address and exit")
    parser.add_argument("--json", action="store_true", help="output raw JSON")
    parser.add_argument("--save", metavar="FILE", help="save the results to FILE (JSON)")
    parser.add_argument("--no-color", action="store_true", help="disable coloured output")
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    if args.no_color or args.json or not sys.stdout.isatty():
        Color.disable()
    if args.ip:
        show_lookup(args.ip, as_json=args.json, save_path=args.save)
    elif args.me:
        show_my_ips(as_json=args.json, save_path=args.save)
    else:
        interactive_menu()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nGoodbye!")
