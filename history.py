"""
IPeek lookup history (backlog item: History)
===========================================

Keeps a log of past lookups and detects when this computer's public IP
address changes, which helps track the dynamic IPs that many ISPs hand out.

What is logged
--------------
    * my_ip        - "my public IPs" checks (IPv4, IPv6, ISP)
    * lookup       - single IP lookups (scope, ISP, country)
    * whois        - reverse DNS / WHOIS lookups (hostname, owner)
    * batch        - batch lookups (file, summary, and each address with its
                     short result, so you can see which batch an IP was in)
    * batch_whois  - batch reverse DNS / WHOIS lookups
    * batch_both   - batches that ran both lookups

Every my_ip check is compared with the previous one, so a change of public
IPv4 or IPv6 address is reported straight away, and ip_changes() lists every
change over time.

Where it is stored
------------------
One JSON object per line (JSON Lines) in the user's app-data folder, not in
the project folder, so it works the same for the .exe and is never committed:
    Windows: %APPDATA%\\IPeek\\history.jsonl
    macOS:   ~/Library/Application Support/IPeek/history.jsonl
    Linux:   ~/.local/share/ipeek/history.jsonl
Only the newest MAX_ENTRIES entries are kept.

Logging is OFF until an app turns it on (ENABLED = True). ip_info_app.py and
gui_app.py do that only when they are started as programs, so importing them
in the unit tests never writes to a real history file.
"""

import json
import os
import platform
from datetime import datetime

ENABLED = False          # set to True by the CLI/GUI when started as programs
PATH = None              # None = default_path(); tests set a temporary file
MAX_ENTRIES = 1000
MAX_BATCH_IPS = 500      # addresses kept per batch entry

KIND_LABELS = {"my_ip": "My public IPs", "lookup": "IP lookup", "whois": "Reverse DNS / WHOIS",
               "batch": "Batch lookup", "batch_whois": "Batch reverse DNS / WHOIS",
               "batch_both": "Batch IP details + WHOIS"}


def default_path():
    """The history file in this user's app-data folder (see the module docstring)."""
    system = platform.system()
    if system == "Windows":
        base = os.path.join(os.environ.get("APPDATA") or os.path.expanduser("~"), "IPeek")
    elif system == "Darwin":
        base = os.path.expanduser("~/Library/Application Support/IPeek")
    else:
        base = os.path.join(os.environ.get("XDG_DATA_HOME")
                            or os.path.expanduser("~/.local/share"), "ipeek")
    return os.path.join(base, "history.jsonl")


def history_path():
    return PATH or default_path()


# ---------------------------------------------------------------------------
# Reading and writing
# ---------------------------------------------------------------------------
def load(kind=None):
    """All entries, oldest first (optionally only one kind). Bad lines are skipped."""
    entries = []
    try:
        # utf-8-sig: still reads the first line if an editor such as Notepad
        # saved the file with a byte-order mark
        with open(history_path(), encoding="utf-8-sig") as fh:
            for line in fh:
                try:
                    entry = json.loads(line)
                except ValueError:
                    continue                    # a damaged line doesn't lose the rest
                if isinstance(entry, dict) and (kind is None or entry.get("kind") == kind):
                    entries.append(entry)
    except FileNotFoundError:
        pass
    return entries


def record(kind, target, result, data=None):
    """Append one entry to the history and return it (or None if logging is off).

    target is what was looked up (an IP or a file name), result a short text
    for the history list, data any extra values worth keeping.
    """
    if not ENABLED:
        return None
    entry = {"time": datetime.now().isoformat(timespec="seconds"), "kind": kind,
             "target": target, "result": result, "data": data or {}}
    path = history_path()
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry) + "\n")
        _trim(path)
    except OSError:
        return None                             # history must never stop a lookup
    return entry


def _trim(path):
    """Keep only the newest MAX_ENTRIES lines."""
    with open(path, encoding="utf-8") as fh:
        lines = fh.readlines()
    if len(lines) > MAX_ENTRIES:
        with open(path, "w", encoding="utf-8") as fh:
            fh.writelines(lines[-MAX_ENTRIES:])


def clear():
    """Delete the history file. Returns True if there was one."""
    try:
        os.remove(history_path())
        return True
    except FileNotFoundError:
        return False


# ---------------------------------------------------------------------------
# Public IP change detection
# ---------------------------------------------------------------------------
def compare(old, new):
    """Differences between two my_ip data dicts, as a list of change dicts.

    Each change: {"version": "IPv4"/"IPv6", "old": ..., "new": ..., "text": ...}.
    A missing address (None) is a change too, e.g. IPv6 appearing or going away.
    """
    changes = []
    for version, key in (("IPv4", "ipv4"), ("IPv6", "ipv6")):
        before, after = old.get(key), new.get(key)
        if before == after:
            continue
        if before and after:
            text = f"Public {version} changed: {before} -> {after}"
        elif after:
            text = f"Public {version} is now available: {after}"
        else:
            text = f"Public {version} is no longer detected (was {before})"
        changes.append({"version": version, "old": before, "new": after, "text": text})
    return changes


def record_my_ips(results):
    """Log a get_my_report() result and compare it with the previous check.

    Returns {"previous": the previous my_ip entry or None, "changes": [...]},
    or None when logging is off.
    """
    if not ENABLED:
        return None
    earlier = load("my_ip")
    previous = earlier[-1] if earlier else None
    data = {"ipv4": results.get("public_ipv4"), "ipv6": results.get("public_ipv6")}
    isp = next((r["details"].get("isp") for r in results.get("reports", [])
                if r["details"].get("isp")), None)
    if isp:
        data["isp"] = isp
    changes = compare(previous["data"], data) if previous else []
    result = "; ".join(c["text"] for c in changes) or (
        "unchanged" if previous else "first check")
    target = " / ".join(ip for ip in (data["ipv4"], data["ipv6"]) if ip) or "not detected"
    record("my_ip", target, result, dict(data, changes=changes))
    return {"previous": previous, "changes": changes}


def status_text(status):
    """One line about the public IP compared with the last check, or None."""
    if status is None:
        return None
    previous = status["previous"]
    if previous is None:
        return "First check recorded. Future checks will tell you if your public IP changes."
    when = previous["time"].replace("T", " ")
    if status["changes"]:
        return f"Changed since your last check ({when}): " + "; ".join(
            c["text"] for c in status["changes"])
    return f"Unchanged since your last check ({when})."


def ip_changes():
    """Every public IP change in the history, oldest first.

    Each item: {"time", "version", "old", "new", "text", "since"} where since
    is the time of the check before the change.
    """
    changes, previous = [], None
    for entry in load("my_ip"):
        if previous is not None:
            for change in compare(previous["data"], entry["data"]):
                changes.append(dict(change, time=entry["time"], since=previous["time"]))
        previous = entry
    return changes


# ---------------------------------------------------------------------------
# Short results for the other lookups
# ---------------------------------------------------------------------------
def record_lookup(report):
    """Log a build_report() result."""
    a, d = report["analysis"], report["details"]
    parts = [a["scope"].split(" (")[0]]
    if d.get("isp"):
        parts.append(d["isp"])
    if d.get("country_code"):
        parts.append(d["country_code"])
    return record("lookup", a["address"], ", ".join(parts),
                  {"isp": d.get("isp"), "country": d.get("country_code")})


def record_whois(result):
    """Log a reverse_whois.lookup() result."""
    hostname = result["dns"]["hostname"]
    owner = (result.get("whois") or {}).get("owner")
    text = f"{hostname or 'no hostname'}, {owner or result.get('whois_error', 'no owner')}"
    return record("whois", result["ip"], text, {"hostname": hostname, "owner": owner})


def _whois_result(row):
    error = row.get("whois_error") or ""
    if error.startswith("not a public address"):
        error = "not public"
    owner = row.get("owner") or error or "no owner"
    return f"{row.get('hostname') or 'no hostname'}, {owner}"


def _ip_result(row):
    scope = (row.get("scope") or "").split(" (")[0]
    if not scope:                                   # the lookup itself failed
        return f"lookup failed: {row.get('error', '')}"
    parts = [scope] + [row[k] for k in ("isp", "country_code") if row.get(k)]
    if row.get("error") and scope == "Public":
        parts.append(row["error"])
    return ", ".join(parts)


def batch_ip_result(row, mode):
    """Short result for one address of a batch (a batch_lookup result row),
    plus the hostname it came from when the file's hostnames were resolved."""
    if mode == "whois":
        text = _whois_result(row)
    elif mode == "both":
        text = f"{_ip_result(row)}; {_whois_result(row)}"
    else:
        text = _ip_result(row)
    if row.get("from_hostname"):
        text += f" (from {row['from_hostname']})"
    return text


BATCH_KINDS = {"ip": "batch", "whois": "batch_whois", "both": "batch_both"}


def record_batch(path, mode, count, summary, rows=None):
    """Log a batch run (mode "ip", "whois" or "both") with a short result for each address.

    At most MAX_BATCH_IPS addresses are kept per batch so a huge file can't
    bloat the history; the rest are counted in "ips_omitted" (the exported CSV
    still has them all).
    """
    data = {"file": os.path.abspath(path), "addresses": count}
    if rows:
        data["ips"] = [{"ip": r["ip"], "count": r.get("count", 1),
                        "result": batch_ip_result(r, mode)} for r in rows[:MAX_BATCH_IPS]]
        if len(rows) > MAX_BATCH_IPS:
            data["ips_omitted"] = len(rows) - MAX_BATCH_IPS
    return record(BATCH_KINDS.get(mode, "batch"), os.path.basename(path), summary, data)


def batch_ips(entry):
    """[(ip, count, result), ...] stored with a batch entry (empty for other kinds)."""
    return [(i.get("ip", ""), i.get("count", 1), i.get("result", ""))
            for i in entry.get("data", {}).get("ips", [])]


def entry_row(entry):
    """(time, kind label, target, result) for showing one entry in a list."""
    return (entry.get("time", "").replace("T", " "),
            KIND_LABELS.get(entry.get("kind"), entry.get("kind", "?")),
            entry.get("target", ""), entry.get("result", ""))
