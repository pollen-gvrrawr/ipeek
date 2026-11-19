"""
IPeek batch lookup (backlog item: Batch lookup)
===============================================

Reads a list of IP addresses from a .txt or .csv file, looks each one up and
exports the results to a CSV file. Useful when checking the addresses in a
firewall export or a log file.

Input rules (so firewall and log exports work without cleaning them first):
    * Every cell of every line is checked, so an IP can be in any column.
    * Cells are split on commas, semicolons, tabs and spaces.
    * An IPv4 address with a port, such as 203.0.113.5:443, counts as the IP.
    * Each address is looked up once. The "count" column says how many times
      it appeared in the file.
    * Lines that start with # are comments. A line with no IP address is
      listed as skipped, except the first line (usually a header).
    * Optionally (--resolve-hostnames, or the GUI checkbox) hostnames such as
      dns.google are read too: each is resolved to its IP addresses, which are
      looked up like the others, and the "from_hostname" column says which
      name they came from. Names that don't resolve are reported. It is off by
      default because logs are full of dotted names (e.g. "HELO
      mail.example.org") that aren't meant to be looked up.

It runs one of three lookups for every address:
    * IP details (ip_info_app.build_report): --batch, menu option 9
    * Reverse DNS / WHOIS (reverse_whois.lookup): --batch-whois, menu option 11
    * Both of them: --batch-both, menu option 12
All three are also in the "Batch lookup" tab in gui_app.py. The lookups are
passed in as functions, so this module does not import ip_info_app and the
tests can run without internet.
"""

import csv
import ipaddress
import os
import re
import socket
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout

# Columns of the exported CSV, in the same order as the single-IP report:
# address analysis first, then provider & location. compressed/expanded/
# ipv4_mapped are only filled for IPv6, class/binary only for IPv4.
ANALYSIS_COLUMNS = ("version", "scope", "class", "binary", "compressed", "expanded",
                    "ipv4_mapped", "reverse_dns")
DETAIL_COLUMNS = ("isp", "asn", "country", "country_code", "region", "city", "postal",
                  "latitude", "longitude", "timezone", "utc_offset", "source")
CSV_COLUMNS = (("ip", "count", "from_hostname") + ANALYSIS_COLUMNS + DETAIL_COLUMNS
               + ("error",))

# analysis key in analyze_ip() for each analysis column, where the name differs
_ANALYSIS_KEYS = {"expanded": "exploded", "reverse_dns": "reverse_pointer"}

_SPLIT = re.compile(r"[,;\s]+")
# a DNS name with at least one dot and a letters-only top-level label
_HOSTNAME = re.compile(r"(?=.{4,253}$)(?:(?!-)[a-z0-9-]{1,63}(?<!-)\.)+[a-z]{2,63}")
DNS_TIMEOUT = 5          # seconds to resolve one hostname


def _parse_ip(token):
    """Return the address in token as a normalised string, or None."""
    token = token.strip().strip("\"'[]()")
    if token.count(":") == 1 and "." in token:          # 203.0.113.5:443
        token = token.split(":")[0]
    try:
        return str(ipaddress.ip_address(token))
    except ValueError:
        return None


def _parse_hostname(token):
    """Return token as a lower-case hostname, or None if it doesn't look like one."""
    name = token.strip().strip("\"'[]()").rstrip(".").lower()
    return name if _HOSTNAME.fullmatch(name) else None


def is_hostname(target):
    """True if an entry from extract_ips() is a hostname rather than an IP."""
    return _parse_ip(target) is None


def extract_ips(lines, hostnames=False):
    """Find the IP addresses (and, if hostnames=True, the hostnames) in text lines.

    Returns (entries, skipped):
        entries - list of (ip or hostname, count) in the order first seen
        skipped - list of (line_number, line_text) for lines with nothing to look up
    """
    counts = {}
    skipped = []
    for number, line in enumerate(lines, start=1):
        text = line.strip()
        if not text or text.startswith("#"):
            continue
        found = []
        for token in _SPLIT.split(text):
            ip = _parse_ip(token)
            name = None if ip or not hostnames else _parse_hostname(token)
            if ip or name:
                found.append(ip or name)
        if not found:
            if number > 1:                               # line 1 is usually a header
                skipped.append((number, text))
            continue
        for ip in found:
            counts[ip] = counts.get(ip, 0) + 1
    return list(counts.items()), skipped


def read_ip_file(path, hostnames=False):
    """Read a .txt or .csv file and return extract_ips() for its lines."""
    with open(path, encoding="utf-8-sig", errors="replace") as fh:
        return extract_ips(fh, hostnames)


def resolve_hostname(name):
    """The IP addresses of a hostname (A and AAAA records), in the order DNS gives them.

    Raises OSError if it can't be resolved within DNS_TIMEOUT seconds.
    """
    pool = ThreadPoolExecutor(max_workers=1)
    try:
        infos = pool.submit(socket.getaddrinfo, name, None).result(timeout=DNS_TIMEOUT)
    except FutureTimeout:
        raise OSError(f"DNS did not answer within {DNS_TIMEOUT} s") from None
    except socket.gaierror:
        raise OSError("the name does not exist or has no address") from None
    finally:
        pool.shutdown(wait=False)
    ips = []
    for info in infos:
        ip = str(ipaddress.ip_address(info[4][0].split("%")[0]))
        if ip not in ips:
            ips.append(ip)
    return ips


def resolve_entries(entries, resolver=resolve_hostname):
    """Replace the hostnames in extract_ips() entries by their IP addresses.

    Returns (resolved, unresolved):
        resolved   - list of (ip, count, names): names is a tuple of the
                     hostnames in the file that resolved to this IP (empty if
                     the IP itself was in the file). An IP that is both in the
                     file and behind a hostname is looked up once.
        unresolved - list of (hostname, reason)
    """
    merged, unresolved = {}, []
    for target, count in entries:
        if not is_hostname(target):
            ips, name = [target], None
        else:
            try:
                ips, name = resolver(target), target
            except OSError as exc:
                unresolved.append((target, str(exc)))
                continue
        for ip in ips:
            seen, names = merged.get(ip, (0, ()))
            if name and name not in names:
                names += (name,)
            merged[ip] = (seen + count, names)
    return [(ip, count, names) for ip, (count, names) in merged.items()], unresolved


def result_row(ip, count, report=None, error=None):
    """Flatten one build_report() result into a dict with CSV_COLUMNS keys."""
    row = dict.fromkeys(CSV_COLUMNS, "")
    row.update(ip=ip, count=count)
    if report is None:
        row["error"] = error or "lookup failed"
        return row
    a, d = report["analysis"], report["details"]
    for column in ANALYSIS_COLUMNS:
        row[column] = a.get(_ANALYSIS_KEYS.get(column, column), "")
    for key in DETAIL_COLUMNS + ("error",):
        value = d.get(key)
        row[key] = "" if value is None else value
    return row


# ---------------------------------------------------------------------------
# Batch reverse DNS / WHOIS (results of reverse_whois.lookup)
# ---------------------------------------------------------------------------
WHOIS_FIELDS = ("owner", "network_name", "range", "cidr", "type", "country", "abuse_email",
                "registered", "last_changed", "registry", "source")
WHOIS_COLUMNS = (("ip", "count", "from_hostname", "ptr_name", "hostname", "other_names",
                  "forward_confirmed", "dns_error") + WHOIS_FIELDS + ("whois_error",))
_CONFIRMED = {True: "yes", False: "no", None: "could not check"}


def whois_row(ip, count, result=None, error=None):
    """Flatten one reverse_whois.lookup() result into a dict with WHOIS_COLUMNS keys."""
    row = dict.fromkeys(WHOIS_COLUMNS, "")
    row.update(ip=ip, count=count)
    if result is None:
        row["whois_error"] = error or "lookup failed"
        return row
    dns = result["dns"]
    row.update(ptr_name=result["ptr_name"], hostname=dns["hostname"] or "",
               other_names=", ".join(dns["aliases"]), dns_error=dns["error"] or "",
               forward_confirmed=_CONFIRMED[dns["forward_confirmed"]] if dns["hostname"] else "")
    whois = result.get("whois")
    if whois is None:
        row["whois_error"] = result.get("whois_error", "")
        return row
    for key in WHOIS_FIELDS:
        row[key] = "" if whois.get(key) is None else whois[key]
    return row


def whois_not_public(row):
    """True for addresses that have no public WHOIS record (private, loopback...)."""
    return row["whois_error"].startswith("not a public address")


def summarize_whois(rows):
    """Count addresses for the batch WHOIS summary line.

    hostnames  - addresses with a reverse DNS hostname
    owners     - public addresses whose network owner was found
    not_public - private, loopback, etc. (no public WHOIS record)
    failed     - public addresses whose WHOIS lookup failed
    """
    return {"total": len(rows),
            "hostnames": sum(1 for r in rows if r["hostname"]),
            "owners": sum(1 for r in rows if r["owner"]),
            "not_public": sum(1 for r in rows if whois_not_public(r)),
            "failed": sum(1 for r in rows if r["whois_error"] and not whois_not_public(r))}


# ---------------------------------------------------------------------------
# Both lookups for every address (IP details + reverse DNS / WHOIS)
# ---------------------------------------------------------------------------
# WHOIS columns whose names are already used by the IP-details columns
_BOTH_RENAMED = {"country": "whois_country", "source": "whois_source"}
BOTH_COLUMNS = CSV_COLUMNS + tuple(_BOTH_RENAMED.get(c, c) for c in WHOIS_COLUMNS
                                   if c not in ("ip", "count", "from_hostname"))


def both_row(ip, count, result=None, error=None):
    """Flatten {"report": build_report(), "whois": reverse_whois.lookup()} into
    one dict with BOTH_COLUMNS keys (WHOIS country/source become whois_country
    and whois_source, so they don't overwrite the IP-details ones)."""
    result = result or {}
    row = result_row(ip, count, result.get("report"), error)
    for key, value in whois_row(ip, count, result.get("whois"), error).items():
        if key not in ("ip", "count", "from_hostname"):
            row[_BOTH_RENAMED.get(key, key)] = value
    return row


# ---------------------------------------------------------------------------
# Running a batch and saving it
# ---------------------------------------------------------------------------
def run_batch(entries, lookup, progress=None, to_row=result_row):
    """Look up every entry and return a list of result rows.

    entries are (ip, count) or (ip, count, names) from resolve_entries().
    lookup(ip) returns one result: a build_report() dict by default, a
    reverse_whois.lookup() dict with to_row=whois_row, or both with
    to_row=both_row. progress(done, total, ip), if given, is called after
    each address. One failed lookup does not stop the batch: its row gets an
    error instead.
    """
    rows = []
    total = len(entries)
    for done, (ip, count, *names) in enumerate(entries, start=1):
        try:
            row = to_row(ip, count, lookup(ip))
        except Exception as exc:                         # keep going with the rest
            row = to_row(ip, count, error=str(exc))
        if names and names[0]:
            row["from_hostname"] = ", ".join(names[0])
        rows.append(row)
        if progress:
            progress(done, total, ip)
    return rows


def write_csv(rows, path, columns=CSV_COLUMNS):
    """Write result rows to a CSV file. utf-8-sig so Excel shows accents correctly."""
    with open(path, "w", newline="", encoding="utf-8-sig") as fh:
        writer = csv.DictWriter(fh, fieldnames=columns)
        writer.writeheader()
        writer.writerows(rows)


def summarize(rows):
    """Count addresses for the summary line.

    public     - public addresses (online details were requested)
    not_public - private, loopback, link-local, etc. (no online lookup)
    failed     - public addresses whose online lookup failed
    """
    counts = {"total": len(rows), "public": 0, "not_public": 0, "failed": 0}
    for r in rows:
        if not r["scope"]:                               # the lookup itself crashed
            counts["failed"] += 1
        elif r["scope"].startswith("Public"):
            counts["public"] += 1
            counts["failed"] += bool(r["error"])
        else:
            counts["not_public"] += 1
    return counts


def default_output_path(input_path, suffix="_results"):
    """reports/firewall.txt -> reports/firewall_results.csv (or _whois / _both)"""
    return os.path.splitext(input_path)[0] + suffix + ".csv"
