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

Used by the CLI in ip_info_app.py (--batch and menu option 9) and by the
"Batch lookup" tab in gui_app.py. The lookup itself is passed in as a
function (normally ip_info_app.build_report), so this module does not import
ip_info_app and the tests can run without internet.
"""

import csv
import ipaddress
import os
import re

# Columns of the exported CSV, in the same order as the single-IP report:
# address analysis first, then provider & location. compressed/expanded/
# ipv4_mapped are only filled for IPv6, class/binary only for IPv4.
ANALYSIS_COLUMNS = ("version", "scope", "class", "binary", "compressed", "expanded",
                    "ipv4_mapped", "reverse_dns")
DETAIL_COLUMNS = ("isp", "asn", "country", "country_code", "region", "city", "postal",
                  "latitude", "longitude", "timezone", "utc_offset", "source")
CSV_COLUMNS = ("ip", "count") + ANALYSIS_COLUMNS + DETAIL_COLUMNS + ("error",)

# analysis key in analyze_ip() for each analysis column, where the name differs
_ANALYSIS_KEYS = {"expanded": "exploded", "reverse_dns": "reverse_pointer"}

_SPLIT = re.compile(r"[,;\s]+")


def _parse_ip(token):
    """Return the address in token as a normalised string, or None."""
    token = token.strip().strip("\"'[]()")
    if token.count(":") == 1 and "." in token:          # 203.0.113.5:443
        token = token.split(":")[0]
    try:
        return str(ipaddress.ip_address(token))
    except ValueError:
        return None


def extract_ips(lines):
    """Find the IP addresses in an iterable of text lines.

    Returns (entries, skipped):
        entries - list of (ip, count) in the order first seen
        skipped - list of (line_number, line_text) for lines with no IP
    """
    counts = {}
    skipped = []
    for number, line in enumerate(lines, start=1):
        text = line.strip()
        if not text or text.startswith("#"):
            continue
        found = [ip for ip in map(_parse_ip, _SPLIT.split(text)) if ip]
        if not found:
            if number > 1:                               # line 1 is usually a header
                skipped.append((number, text))
            continue
        for ip in found:
            counts[ip] = counts.get(ip, 0) + 1
    return list(counts.items()), skipped


def read_ip_file(path):
    """Read a .txt or .csv file and return extract_ips() for its lines."""
    with open(path, encoding="utf-8-sig", errors="replace") as fh:
        return extract_ips(fh)


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


def run_batch(entries, lookup, progress=None):
    """Look up every (ip, count) entry and return a list of result rows.

    lookup(ip) must return a build_report() dict. progress(done, total, ip),
    if given, is called after each address. One failed lookup does not stop
    the batch: its row gets an error instead.
    """
    rows = []
    total = len(entries)
    for done, (ip, count) in enumerate(entries, start=1):
        try:
            rows.append(result_row(ip, count, lookup(ip)))
        except Exception as exc:                         # keep going with the rest
            rows.append(result_row(ip, count, error=str(exc)))
        if progress:
            progress(done, total, ip)
    return rows


def write_csv(rows, path):
    """Write result rows to a CSV file. utf-8-sig so Excel shows accents correctly."""
    with open(path, "w", newline="", encoding="utf-8-sig") as fh:
        writer = csv.DictWriter(fh, fieldnames=CSV_COLUMNS)
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


def default_output_path(input_path):
    """reports/firewall.txt -> reports/firewall_results.csv"""
    return os.path.splitext(input_path)[0] + "_results.csv"
