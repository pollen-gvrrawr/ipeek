"""
IPeek: IPv4/IPv6 Address Application  (DEVASC Project Activity 3 - Option 2)
============================================================================

A prototype for network technicians that shows the computer's current PUBLIC
IP addressing information, using free REST APIs. This file is the core app and
the command-line interface; gui_app.py is a Tkinter desktop window that reuses
the same functions. The REST APIs used are:

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
    python ip_info_app.py --subnet 192.168.1.0/26   # subnet calculator
    python ip_info_app.py --local                   # private IP, mask, gateway, DNS
    python ip_info_app.py --ping 8.8.8.8            # ping a host
    python ip_info_app.py --trace 8.8.8.8           # traceroute to a host
    python ip_info_app.py --ipv6-check              # does IPv6 work end to end?
    python ip_info_app.py --batch ips.txt           # look up a file of IPs, export CSV
    python ip_info_app.py --batch ips.txt --brief   # same, but print only the summary
    python ip_info_app.py --batch ips.txt --find google   # highlight every match
    python ip_info_app.py --whois 8.8.8.8           # hostname + network owner
    python ip_info_app.py --batch-whois ips.txt     # the same for every IP in a file
    python ip_info_app.py --batch-both ips.txt      # IP details + reverse DNS / WHOIS
    python ip_info_app.py --batch ips.txt --resolve-hostnames   # also read hostnames
    python ip_info_app.py --history                 # past lookups (newest last)
    python ip_info_app.py --ip-changes              # every change of my public IP

Code layout (for teams continuing this project)
-----------------------------------------------
    1. CONFIG            - API URLs and timeouts (change APIs here)
    2. API LAYER         - functions that call the REST APIs and return dicts
    3. ANALYSIS LAYER    - offline analysis with the ipaddress module
    4. DISPLAY LAYER     - functions that format and print the results
    5. CLI / MENU        - argument parsing and the interactive menu

Each layer only talks to the one below it, so a new feature (e.g. a GUI or a
new API) can be added by replacing one layer without touching the others.
gui_app.py does exactly that: it replaces layers 4-5 with a Tkinter window and
calls layers 2-3 unchanged.
"""

import argparse
import ipaddress
import json
import os
import sys
from datetime import datetime

import io
import re
from contextlib import redirect_stdout

import requests
from colorama import Back, Fore, Style, just_fix_windows_console

import batch_lookup
import connectivity
import history
import local_network
import reverse_whois
import subnet_calc

# ---------------------------------------------------------------------------
# 1. CONFIG
# ---------------------------------------------------------------------------
IPV4_URL = "https://api.ipify.org?format=json"    # IPv4 only
IPV6_URL = "https://api6.ipify.org?format=json"   # IPv6 only (fails if no IPv6)
IPAPI_URL = "https://ipapi.co/{ip}/json/"          # primary details API
IPWHOIS_URL = "https://ipwho.is/{ip}"              # backup details API
TIMEOUT = 5                                        # seconds per request
APP_VERSION = "2.0.0"


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
    HIGHLIGHT = Back.YELLOW + Fore.BLACK   # --find matches
    END = Style.RESET_ALL

    @classmethod
    def disable(cls):
        for name in ("HEADER", "BLUE", "CYAN", "GREEN", "YELLOW", "RED", "BOLD",
                     "HIGHLIGHT", "END"):
            setattr(cls, name, "")


_ANSI = re.compile(r"(\x1b\[[0-9;]*m)")


def highlight(text, query):
    """Highlight every case-insensitive match of query in text.

    Returns (text, number_of_matches). Colour codes already in the text are
    skipped, and the colour that was active before a match is restored after
    it. When colours are off (--no-color, or output saved to a file), matches
    are shown in [brackets] instead.
    """
    if not query:
        return text, 0
    pattern = re.compile(re.escape(query), re.IGNORECASE)
    on, off = (Color.HIGHLIGHT, Color.END) if Color.HIGHLIGHT else ("[", "]")
    out, active, count = [], "", 0
    for i, piece in enumerate(_ANSI.split(text)):
        if i % 2:                                  # a colour code, keep it as is
            out.append(piece)
            active = "" if piece == Style.RESET_ALL else active + piece
            continue
        out.append(pattern.sub(lambda m: on + m.group(0) + off + active, piece))
        count += len(pattern.findall(piece))
    return "".join(out), count


def _capture(func, *args):
    """Run a print function and return what it printed as a string."""
    with redirect_stdout(io.StringIO()) as buffer:
        func(*args)
    return buffer.getvalue()


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


def get_my_report():
    """Find this computer's public IPv4/IPv6 and build a report for each.

    Used by both the CLI (show_my_ips) and the desktop GUI (gui_app.py).
    """
    ips = get_public_ips()
    results = {"generated": datetime.now().isoformat(timespec="seconds"),
               "public_ipv4": ips["ipv4"], "public_ipv6": ips["ipv6"],
               "reports": []}
    for ip in (ips["ipv4"], ips["ipv6"]):
        if ip:
            results["reports"].append(build_report(ip))
    return results


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
    results = get_my_report()
    status = history.record_my_ips(results)          # None when history is off

    if as_json:
        shown = dict(results, ip_changes=status["changes"]) if status else results
        print(json.dumps(shown, indent=2))
    else:
        print_header("MY PUBLIC IP ADDRESSES")
        print_row("Public IPv4", results["public_ipv4"] or f"{Color.RED}not detected{Color.END}")
        print_row("Public IPv6", results["public_ipv6"] or
                  f"{Color.YELLOW}not available (network has no IPv6){Color.END}")
        if status:
            colour = Color.YELLOW + Color.BOLD if status["changes"] else Color.GREEN
            print(f"  {colour}{history.status_text(status)}{Color.END}")
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
    history.record_lookup(report)
    if as_json:
        print(json.dumps(report, indent=2))
    else:
        print_report(report)
    if save_path:
        save_results(report, save_path)
    return report


def show_subnet(text, as_json=False, save_path=None):
    """Feature: subnet calculator for an IPv4 or IPv6 network in CIDR notation."""
    try:
        info = subnet_calc.calculate_subnet(text)
    except ValueError as exc:
        print(f"{Color.RED}'{text}' is not a valid network: {exc}{Color.END}")
        return None
    if as_json:
        print(json.dumps(info, indent=2))
    else:
        print_header(f"SUBNET CALCULATOR: {info['network']}")
        for label, value in subnet_calc.subnet_rows(info):
            print_row(label, value)
    if save_path:
        save_results(info, save_path)
    return info


def show_local_network(as_json=False, save_path=None):
    """Feature: this computer's private IP, subnet mask, gateway and DNS servers."""
    info = local_network.get_local_network()
    if as_json:
        print(json.dumps(info, indent=2))
    else:
        print_header("MY LOCAL NETWORK")
        if "error" in info:
            print(f"  {Color.RED}{info['error']}{Color.END}")
        else:
            for label, value in local_network.local_rows(info):
                print_row(label, value)
    if save_path:
        save_results(info, save_path)
    return info


def _run_check(work, text):
    """Run a connectivity test; print a friendly message for a bad host name."""
    try:
        return work(text)
    except ValueError as exc:
        print(f"{Color.RED}{exc}.{Color.END}")
        return None


def _finish(data, as_json, save_path, show):
    """Print data as JSON or with show(data), then save it if asked."""
    if as_json:
        print(json.dumps(data, indent=2))
    else:
        show(data)
    if save_path:
        save_results(data, save_path)
    return data


def show_ping(host, as_json=False, save_path=None):
    """Feature: ping a host and show whether it answers and how fast."""
    result = _run_check(connectivity.ping, host)
    if result is None:
        return None

    def show(r):
        print_header(f"PING {r['host']}")
        if "error" in r:
            print(f"  {Color.RED}{r['error']}{Color.END}")
            return
        ok = f"{Color.GREEN}Yes{Color.END}" if r["reachable"] else f"{Color.RED}No{Color.END}"
        print_row("Reachable", ok)
        print_row("Sent / received", f"{r['sent']} / {r['received']}")
        print_row("Packet loss", None if r["loss_percent"] is None else f"{r['loss_percent']:g}%")
        print_row("Average time", None if r["avg_ms"] is None else f"{r['avg_ms']:g} ms")
    return _finish(result, as_json, save_path, show)


def show_traceroute(host, as_json=False, save_path=None):
    """Feature: list the routers (hops) between this computer and a host."""
    if not as_json:
        print(f"{Color.BLUE}Tracing the route to {host}. This can take up to a minute...{Color.END}")
    result = _run_check(connectivity.traceroute, host)
    if result is None:
        return None

    def show(r):
        print_header(f"TRACEROUTE {r['host']}")
        if "error" in r:
            print(f"  {Color.RED}{r['error']}{Color.END}")
        for hop in r["hops"]:
            where = hop["address"] or f"{Color.YELLOW}* no reply{Color.END}"
            time = f"  ({hop['ms']:g} ms)" if hop["ms"] is not None else ""
            print_row(f"Hop {hop['hop']}", f"{where}{time}")
    return _finish(result, as_json, save_path, show)


def show_ipv6_check(as_json=False, save_path=None):
    """Feature: IPv6 readiness check, step by step."""
    result = connectivity.ipv6_readiness(lambda: get_public_ip(IPV6_URL))

    def show(r):
        print_header("IPv6 READINESS CHECK")
        for check in r["checks"]:
            mark = f"{Color.GREEN}PASS{Color.END}" if check["passed"] else f"{Color.RED}FAIL{Color.END}"
            print(f"  [{mark}] {check['name']}: {check['detail']}")
        colour = Color.GREEN if r["passed"] == r["total"] else Color.YELLOW
        print(f"\n  {Color.BOLD}{colour}{r['verdict']} ({r['passed']}/{r['total']} checks){Color.END}")
    return _finish(result, as_json, save_path, show)


# What changes between the three kinds of batch lookup
BATCH_TITLES = {"ip": "BATCH LOOKUP", "whois": "BATCH REVERSE DNS / WHOIS",
                "both": "BATCH IP DETAILS + REVERSE DNS / WHOIS"}
BATCH_SUFFIX = {"ip": "_results", "whois": "_whois", "both": "_both"}


def batch_summary(rows, mode):
    """The one-line summary of a batch, for any mode."""
    parts = []
    if mode in ("ip", "both"):
        s = batch_lookup.summarize(rows)
        parts.append(f"{s['public']} public, {s['not_public']} not public, "
                     f"{s['failed']} failed lookup(s)")
    if mode in ("whois", "both"):
        s = batch_lookup.summarize_whois(rows)
        parts.append(f"{s['hostnames']} with a hostname, {s['owners']} with a network owner"
                     + ("" if mode == "both" else f", {s['not_public']} not public")
                     + f", {s['failed']} failed WHOIS lookup(s)")
    return f"{len(rows)} unique address(es): " + "; ".join(parts)


def show_batch(path, out_path=None, as_json=False, brief=False, find=None, mode="ip",
               hostnames=False):
    """Feature: look up every IP in a .txt/.csv file and export the results to CSV.

    mode "ip" runs the IP-details report (the same rows as --ip) for every
    address, "whois" the reverse DNS / WHOIS lookup (the same rows as
    --whois), and "both" runs the two. hostnames=True also reads hostnames
    from the file and looks up their IP addresses. Prints the full result for
    every address, then a one-line-per-address summary table. brief=True
    prints only the summary, which is easier to read for long files; the CSV
    always has every field. find highlights every match of that text and
    counts the matches.
    """
    try:
        entries, skipped = batch_lookup.read_ip_file(path, hostnames)
    except OSError as exc:
        print(f"{Color.RED}Could not read '{path}': {exc.strerror or exc}{Color.END}")
        return None
    if not entries:
        what = "IP addresses or hostnames" if hostnames else "IP addresses"
        print(f"{Color.YELLOW}No {what} found in '{path}'.{Color.END}")
        return None
    names = [t for t, _ in entries if batch_lookup.is_hostname(t)]
    if names and not as_json:
        print(f"  Resolving {len(names)} hostname(s)...", flush=True)
    entries, unresolved = batch_lookup.resolve_entries(entries)

    def progress(done, total, ip):
        if not as_json:
            print(f"\r  Looking up {done}/{total}: {ip:<40}", end="", flush=True)

    reports = {}
    cache = reverse_whois.WhoisCache()           # one WHOIS query per network
    if mode == "whois":
        run = lambda ip: reverse_whois.lookup(ip, cache)  # noqa: E731
        to_row, columns = batch_lookup.whois_row, batch_lookup.WHOIS_COLUMNS
    elif mode == "both":
        run = lambda ip: {"report": build_report(ip),  # noqa: E731
                          "whois": reverse_whois.lookup(ip, cache)}
        to_row, columns = batch_lookup.both_row, batch_lookup.BOTH_COLUMNS
    else:
        run, to_row, columns = build_report, batch_lookup.result_row, batch_lookup.CSV_COLUMNS

    def show_one(result):
        if mode == "whois":
            print_rows(reverse_whois.lookup_rows(result))
        elif mode == "both":
            print_report(result["report"])
            print_rows(reverse_whois.lookup_rows(result["whois"])[1:])   # no 2nd title
        else:
            print_report(result)

    def lookup(ip):                       # keep each full result for printing
        reports[ip] = run(ip)
        return reports[ip]

    if not as_json:
        print_header(f"{BATCH_TITLES[mode]}: {os.path.basename(path)}")
    rows = batch_lookup.run_batch(entries, lookup, progress, to_row=to_row)
    out_path = out_path or batch_lookup.default_output_path(path, BATCH_SUFFIX[mode])
    batch_lookup.write_csv(rows, out_path, columns)

    def print_address(r):
        if r["ip"] in reports:
            show_one(reports[r["ip"]])
        else:                             # the lookup crashed, so there is no report
            print_header(f"ADDRESS: {r['ip']}")
            print(f"  {Color.RED}Lookup failed: {r.get('error') or r.get('whois_error')}"
                  f"{Color.END}")
        print_row("Times seen in file", r["count"])
        if r["from_hostname"]:
            print_row("From hostname in file", r["from_hostname"])

    # Each address's report is built as text first, so --find can highlight
    # and count matches in it (the count works with --brief too).
    def find_in(block):
        """highlight() each line, except the Map link: every public IP's map URL
        contains "google.com", which would make a search for "google" match them all."""
        out, total = [], 0
        for line in block.splitlines(keepends=True):
            if _ANSI.sub("", line).strip().startswith("Map "):
                out.append(line)
                continue
            line, found = highlight(line, find)
            out.append(line)
            total += found
        return "".join(out), total

    blocks, matches = [], {}
    for r in rows:
        block, found = find_in(_capture(print_address, r))
        blocks.append(block)
        if found:
            matches[r["ip"]] = found
    summary = batch_summary(rows, mode)
    history.record_batch(path, mode, len(rows), summary, rows)

    if as_json:
        data = {"input": path, "output": out_path, "mode": mode, "summary": summary,
                "results": rows, "skipped_lines": [n for n, _ in skipped]}
        if hostnames:
            data["unresolved_hostnames"] = dict(unresolved)
        if find:
            data["find"] = {"text": find, "matches": matches}
        print(json.dumps(data, indent=2))
        return rows

    print("\r" + " " * 60 + "\r", end="")
    if not brief:
        print("".join(blocks), end="")
        print_header(f"SUMMARY: {os.path.basename(path)}")
    if mode == "whois":
        print(f"  {Color.CYAN}{'IP address':<40}{'Hostname':<32}Owner / note{Color.END}")
    elif mode == "both":
        print(f"  {Color.CYAN}{'IP address':<40}{'Scope':<12}{'Hostname':<32}"
              f"Owner / ISP / note{Color.END}")
    else:
        print(f"  {Color.CYAN}{'IP address':<40}{'Scope':<12}{'Country':<9}ISP / note{Color.END}")
    for r in rows:
        if mode == "whois":
            failed = r["whois_error"] and not batch_lookup.whois_not_public(r)
            note = r["owner"] or (f"{Color.RED}{r['whois_error']}{Color.END}" if failed
                                  else "not public")
            line = f"  {r['ip']:<40}{(r['hostname'] or '-')[:30]:<32}{note}"
        elif mode == "both":
            scope = r["scope"].split(" ")[0] or "?"
            note = r["owner"] or r["isp"] or (
                f"{Color.RED}{r['error'] or r['whois_error']}{Color.END}"
                if scope in ("Public", "?") else "not public")
            line = f"  {r['ip']:<40}{scope:<12}{(r['hostname'] or '-')[:30]:<32}{note}"
        else:
            scope = r["scope"].split(" ")[0] or "?"
            note = r["isp"] or (f"{Color.RED}{r['error']}{Color.END}" if r["error"]
                                and scope in ("Public", "?") else "")
            line = f"  {r['ip']:<40}{scope:<12}{r['country_code'] or '-':<9}{note}"
        if r["from_hostname"]:
            line += f"  (from {r['from_hostname']})"
        print(highlight(line, find)[0])
    print(f"\n  {summary}")
    if skipped:
        lines = ", ".join(str(n) for n, _ in skipped[:10]) + (" ..." if len(skipped) > 10 else "")
        what = "IP address or hostname" if hostnames else "IP address"
        print(f"  {Color.YELLOW}Skipped {len(skipped)} line(s) with no {what}: "
              f"line {lines}{Color.END}")
    if unresolved:
        listed = ", ".join(n for n, _ in unresolved[:10]) + (" ..." if len(unresolved) > 10
                                                              else "")
        print(f"  {Color.YELLOW}Could not resolve {len(unresolved)} hostname(s): "
              f"{listed}{Color.END}")
    if find:
        if matches:
            ips = ", ".join(list(matches)[:10]) + (" ..." if len(matches) > 10 else "")
            print(f"  {Color.HIGHLIGHT}Find \"{find}\"{Color.END}: "
                  f"{sum(matches.values())} match(es) in {len(matches)} address(es) ({ips})")
        else:
            print(f"  {Color.YELLOW}Find \"{find}\": no matches{Color.END}")
    print(f"\n{Color.GREEN}Results saved to {os.path.abspath(out_path)}{Color.END}")
    return rows


def print_rows(rows):
    """Print (kind, label, value) rows, e.g. from reverse_whois.lookup_rows()."""
    for kind, label, value in rows:
        if kind == "title":
            print_header(label.upper())
        elif kind == "head":
            print(f"\n{Color.BOLD} {label}{Color.END}")
        elif kind == "row":
            print_row(label, value)
        elif kind == "error":
            print(f"  {Color.RED}{value}{Color.END}")
        else:
            print(f"  {Color.BLUE}({value}){Color.END}")


def show_whois(text, as_json=False, save_path=None):
    """Feature: reverse DNS (hostname) and WHOIS (network owner) for an IP."""
    try:
        result = reverse_whois.lookup(text)
    except ValueError:
        print(f"{Color.RED}'{text}' is not a valid IPv4 or IPv6 address.{Color.END}")
        return None
    history.record_whois(result)
    return _finish(result, as_json, save_path,
                   lambda r: print_rows(reverse_whois.lookup_rows(r)))


def show_history(limit=20, changes_only=False, as_json=False):
    """Feature: past lookups, or every change of this computer's public IP."""
    if changes_only:
        changes = history.ip_changes()
        if as_json:
            print(json.dumps(changes, indent=2))
            return changes
        print_header("PUBLIC IP CHANGES")
        if not changes:
            checks = len(history.load("my_ip"))
            print(f"  No changes recorded ({checks} check(s) of your public IP so far). "
                  "Run --me now and then to track it.")
        for c in changes:
            print(f"  {c['time'].replace('T', ' ')}  {Color.YELLOW}{c['text']}{Color.END}"
                  f"  (previous check {c['since'].replace('T', ' ')})")
        return changes

    entries = history.load()[-limit:] if limit else history.load()
    if as_json:
        print(json.dumps(entries, indent=2))
        return entries
    print_header(f"LOOKUP HISTORY (last {len(entries)})")
    if not entries:
        print("  No lookups recorded yet.")
    for entry in entries:
        when, kind, target, result = history.entry_row(entry)
        colour = Color.YELLOW if entry.get("data", {}).get("changes") else ""
        print(f"  {when}  {Color.CYAN}{kind:<26}{Color.END}{target:<30} "
              f"{colour}{result}{Color.END if colour else ''}")
        for ip, count, ip_result in history.batch_ips(entry):    # addresses in a batch
            seen = f" (seen {count}x)" if count > 1 else ""
            print(f"  {'':<21}{'':<26}- {ip:<28} {ip_result}{seen}")
        omitted = entry.get("data", {}).get("ips_omitted")
        if omitted:
            print(f"  {'':<21}{'':<26}  ... and {omitted} more (see the exported CSV)")
    print(f"\n  {Color.BLUE}(history file: {history.history_path()}){Color.END}")
    return entries


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
  4) Subnet calculator (IPv4/IPv6)
  5) Show my local network (private IP, gateway, DNS)
  6) Ping a host
  7) Traceroute to a host
  8) IPv6 readiness check
  9) Batch lookup from a .txt/.csv file (export to CSV)
 10) Reverse DNS / WHOIS lookup (hostname, network owner)
 11) Batch reverse DNS / WHOIS from a .txt/.csv file (export to CSV)
 12) Batch IP details + reverse DNS / WHOIS from a .txt/.csv file
 13) Lookup history and public IP changes
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
        elif choice == "4":
            text = input("Enter a network, e.g. 192.168.1.0/26 or 2001:db8::/64: ").strip()
            show_subnet(text)
        elif choice == "5":
            show_local_network()
        elif choice in ("6", "7"):
            host = input("Enter an IP address or hostname [8.8.8.8]: ").strip() or "8.8.8.8"
            (show_ping if choice == "6" else show_traceroute)(host)
        elif choice == "8":
            show_ipv6_check()
        elif choice in ("9", "11", "12"):
            mode = {"9": "ip", "11": "whois", "12": "both"}[choice]
            path = input("File with IP addresses (.txt or .csv): ").strip().strip('"')
            if path:
                default = batch_lookup.default_output_path(path, BATCH_SUFFIX[mode])
                out = input(f"Save results as [{default}]: ").strip().strip('"') or default
                hosts = input("Also look up hostnames in the file? [y/N]: ").strip().lower()
                show_batch(path, out_path=out, mode=mode, hostnames=hosts in ("y", "yes"))
        elif choice == "10":
            ip = input("Enter an IPv4 or IPv6 address [8.8.8.8]: ").strip() or "8.8.8.8"
            show_whois(ip)
        elif choice == "13":
            show_history()
            show_history(changes_only=True)
        else:
            print(f"{Color.YELLOW}Please choose 1-13 or q.{Color.END}")


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Show public IPv4/IPv6 addressing information for network technicians.")
    parser.add_argument("--me", action="store_true", help="show my public IPv4/IPv6 and exit")
    parser.add_argument("--ip", help="look up a specific IPv4 or IPv6 address and exit")
    parser.add_argument("--subnet", metavar="CIDR",
                        help="subnet calculator, e.g. 192.168.1.0/26 or 2001:db8::/64")
    parser.add_argument("--local", action="store_true",
                        help="show my private IP, subnet mask, gateway and DNS servers")
    parser.add_argument("--ping", metavar="HOST", help="ping an IP address or hostname")
    parser.add_argument("--trace", metavar="HOST", help="traceroute to an IP address or hostname")
    parser.add_argument("--ipv6-check", action="store_true",
                        help="check whether IPv6 works end to end")
    parser.add_argument("--batch", metavar="FILE",
                        help="look up every IP in a .txt/.csv file and export the results to CSV")
    parser.add_argument("--batch-whois", metavar="FILE",
                        help="reverse DNS / WHOIS for every IP in a .txt/.csv file, export to CSV")
    parser.add_argument("--batch-both", metavar="FILE",
                        help="IP details AND reverse DNS / WHOIS for every IP in a .txt/.csv "
                             "file, export to CSV")
    parser.add_argument("--resolve-hostnames", action="store_true",
                        help="with a batch option, also read hostnames (e.g. dns.google) "
                             "from the file and look up their IP addresses")
    parser.add_argument("--out", metavar="FILE",
                        help="CSV file for batch results (default: <FILE>_results.csv, "
                             "_whois.csv or _both.csv)")
    parser.add_argument("--brief", action="store_true",
                        help="with a batch option, print only the summary table")
    parser.add_argument("--find", metavar="TEXT",
                        help="with a batch option, highlight every match of TEXT "
                             "and count the matches")
    parser.add_argument("--whois", metavar="IP",
                        help="reverse DNS (hostname) and WHOIS (network owner) for an IP")
    parser.add_argument("--json", action="store_true", help="output raw JSON")
    parser.add_argument("--save", metavar="FILE", help="save the results to FILE (JSON)")
    parser.add_argument("--history", nargs="?", const=20, type=int, metavar="N",
                        help="show the last N lookups (default 20, 0 for all)")
    parser.add_argument("--ip-changes", action="store_true",
                        help="show every change of this computer's public IP")
    parser.add_argument("--clear-history", action="store_true",
                        help="delete the lookup history")
    parser.add_argument("--no-history", action="store_true",
                        help="don't record this run in the lookup history")
    parser.add_argument("--no-color", action="store_true", help="disable coloured output")
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    if args.no_color or args.json or not sys.stdout.isatty():
        Color.disable()
    batch = [(args.batch, "ip"), (args.batch_whois, "whois"), (args.batch_both, "both")]
    batch_file, batch_mode = next(((f, m) for f, m in batch if f), (None, None))
    if args.no_history:
        history.ENABLED = False
    if args.clear_history:
        removed = history.clear()
        print("Lookup history deleted." if removed else "There was no lookup history.")
    elif args.history is not None:
        show_history(args.history, as_json=args.json)
    elif args.ip_changes:
        show_history(changes_only=True, as_json=args.json)
    elif batch_file:
        show_batch(batch_file, out_path=args.out, as_json=args.json, brief=args.brief,
                   find=args.find, mode=batch_mode, hostnames=args.resolve_hostnames)
    elif args.subnet:
        show_subnet(args.subnet, as_json=args.json, save_path=args.save)
    elif args.local:
        show_local_network(as_json=args.json, save_path=args.save)
    elif args.ping:
        show_ping(args.ping, as_json=args.json, save_path=args.save)
    elif args.trace:
        show_traceroute(args.trace, as_json=args.json, save_path=args.save)
    elif args.whois:
        show_whois(args.whois, as_json=args.json, save_path=args.save)
    elif args.ipv6_check:
        show_ipv6_check(as_json=args.json, save_path=args.save)
    elif args.ip:
        show_lookup(args.ip, as_json=args.json, save_path=args.save)
    elif args.me:
        show_my_ips(as_json=args.json, save_path=args.save)
    else:
        interactive_menu()


if __name__ == "__main__":
    history.ENABLED = True          # only when run as a program, never in the tests
    try:
        main()
    except KeyboardInterrupt:
        print("\nGoodbye!")
