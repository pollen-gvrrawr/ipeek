"""
IPeek desktop GUI (Tkinter)
===========================

A window version of IPeek for technicians who prefer buttons to commands.
It does not have its own networking or analysis code: every lookup goes
through the same functions as the command-line app in ip_info_app.py
(get_my_report, build_report), so both versions always give the same answers
and the unit tests cover both.

How to run
----------
    pip install -r requirements.txt
    python gui_app.py

Tkinter is part of the standard Python installer on Windows and macOS, so
nothing extra is needed for the window itself.

Code layout
-----------
    * report_rows() / map_url()  - turn a report dict into rows to show
                                   (no Tkinter, so they are easy to test)
    * batch_report_rows()        - one batch result -> report rows (Reports view)
    * batch_table_values()       - one batch result -> table cells (Table view)
    * whois_report_rows() / whois_table_values() - the same for a batch
                                   reverse DNS / WHOIS, and both_report_rows() /
                                   both_table_values() for both lookups
                                   (BATCH_MODES picks which)
    * whois tab                  - reverse_whois.lookup_rows() in a ResultPane
    * history_entry_rows() / history_change_rows() - History tab, Reports view
    * FindBar                    - Google Docs-style find bar (Batch lookup and
                                   History tabs)
    * IPeekApp                   - the window: header, five tabs, status bar
    * lookups run in a background thread so the window never freezes while
      waiting for an API; results come back through a queue.
"""

import queue
import threading
import tkinter as tk
import webbrowser
from tkinter import filedialog, messagebox, ttk

import batch_lookup
import history
import ip_info_app as core
import reverse_whois

# ---------------------------------------------------------------------------
# Look and feel (same palette as the IPeek slides)
# ---------------------------------------------------------------------------
BG = "#F0D9E4"        # Mountain Heather
SURFACE = "#FFF8FB"
BORDER = "#C1ADAC"    # Decanting
TEXT = "#16131F"      # Back in Black
DARK = "#4A3F4B"      # Funkie Friday
MUTED = "#806C79"     # Moonscape
OK = "#2F6B4A"
WARN = "#8A5A12"
ERR = "#9B2335"
MATCH = "#FBE3A1"     # find bar: every match
CURRENT = "#F2B544"   # find bar: the match you are on
FONT = "Segoe UI"
MONO = "Consolas"

EXAMPLES = ("8.8.8.8", "2001:4860:4860::8888", "192.168.1.10", "fe80::1")


# ---------------------------------------------------------------------------
# Report formatting (no Tkinter here)
# ---------------------------------------------------------------------------
def report_rows(report):
    """Turn a build_report() dict into a list of (kind, label, value) rows.

    kind is 'title' (the address), 'head' (section title), 'row' (label +
    value), 'error' or 'note'.
    The rows follow the same order as print_report() in the CLI.
    """
    a, d = report["analysis"], report["details"]
    rows = [("title", f"{a['version']} address: {a['address']}", ""),
            ("head", "Address analysis", ""),
            ("row", "Version", a["version"]),
            ("row", "Scope", a["scope"])]
    if a["version"] == "IPv4":
        rows += [("row", "Class", a["class"]), ("row", "Binary", a["binary"])]
    else:
        rows += [("row", "Compressed", a["compressed"]), ("row", "Expanded", a["exploded"])]
        if "ipv4_mapped" in a:
            rows.append(("row", "IPv4-mapped", a["ipv4_mapped"]))
    rows.append(("row", "Reverse DNS name", a["reverse_pointer"]))

    rows.append(("head", "Provider & location", ""))
    if "error" in d:
        rows.append(("error", "", f"Could not get online details: {d['error']}"))
        return rows
    rows += [("row", "ISP / Organization", d.get("isp")),
             ("row", "ASN", d.get("asn")),
             ("row", "Country", f"{d.get('country')} ({d.get('country_code')})"),
             ("row", "Region / City", f"{d.get('region')} / {d.get('city')}"),
             ("row", "Postal code", d.get("postal"))]
    if d.get("latitude") is not None:
        rows.append(("row", "Coordinates", f"{d['latitude']}, {d['longitude']}"))
    rows += [("row", "Timezone", f"{d.get('timezone')} (UTC{d.get('utc_offset') or ''})"),
             ("note", "", f"data source: {d.get('source')}")]
    return rows


def map_url(reports):
    """Google Maps link for the first report that has coordinates, else None."""
    for report in reports:
        d = report["details"]
        if d.get("latitude") is not None:
            return f"https://www.google.com/maps?q={d['latitude']},{d['longitude']}"
    return None


def _batch_extra_rows(row):
    """Rows shown under each address's title in a batch: how often it was in
    the file, and the hostname(s) it came from (with Resolve hostnames)."""
    rows = [("row", "Times seen in file", row["count"])]
    if row.get("from_hostname"):
        rows.append(("row", "From hostname in file", row["from_hostname"]))
    return rows


def batch_report_rows(row, report=None):
    """Rows for one address in the Batch lookup tab.

    The same vertical layout as the single-IP report (report_rows), with
    "Times seen in file" (and "From hostname in file") under the title. row
    is a batch_lookup result row; report is the full build_report() dict, or
    None if the lookup crashed.
    """
    if report is None:
        return ([("title", f"Address: {row['ip']}", "")] + _batch_extra_rows(row)
                + [("error", "", f"Lookup failed: {row['error']}")])
    rows = report_rows(report)
    rows[1:1] = _batch_extra_rows(row)
    return rows


# Table view of the batch tab: (column id, heading, width), same rows and
# order as the single-IP report.
BATCH_COLUMNS = (
    ("ip", "IP address", 210), ("count", "Seen", 50), ("from_hostname", "From hostname", 160),
    # Address analysis
    ("version", "Version", 65), ("scope", "Scope", 250), ("class", "Class", 55),
    ("binary", "Binary", 300), ("compressed", "Compressed", 210),
    ("expanded", "Expanded", 330), ("ipv4_mapped", "IPv4-mapped", 110),
    ("reverse_dns", "Reverse DNS name", 330),
    # Provider & location
    ("isp", "ISP / Organization", 200), ("asn", "ASN", 80),
    ("country", "Country", 170), ("region_city", "Region / City", 220),
    ("postal", "Postal code", 90), ("coordinates", "Coordinates", 170),
    ("timezone", "Timezone", 230), ("source", "Data source", 90),
    ("note", "Note", 330),
)
_ONLINE = ("isp", "asn", "country", "region_city", "postal", "coordinates", "timezone")


def batch_table_values(row):
    """Turn one batch_lookup result row into the cells of the batch table.

    Values are formatted like the single-IP report (e.g. "United States (US)",
    "California / Mountain View"). Online fields the provider left empty show
    N/A, as in the report. Returns (values, failed); failed is True when a
    public address could not be looked up online, so the window can colour it.
    """
    cells, failed = _ip_cells(row)
    return tuple(cells[c] for c, _, _ in BATCH_COLUMNS), failed


def _ip_cells(row):
    """The IP-details cells of a batch row, formatted for the table; (cells, failed)."""
    scope = row["scope"] or "?"
    failed = bool(row["error"]) and (scope.startswith("Public") or scope == "?")
    looked_up = not row["error"]

    def pair(first, second, fmt):
        return fmt.format(first, second) if first or second else ""

    cells = dict(row)
    cells.update(
        country=pair(row["country"], row["country_code"], "{} ({})"),
        region_city=pair(row["region"], row["city"], "{} / {}"),
        coordinates=pair(row["latitude"], row["longitude"], "{}, {}"),
        timezone=pair(row["timezone"], row["utc_offset"], "{} (UTC{})"),
        note=row["error"] if failed else ("" if looked_up else "no online lookup (not public)"),
    )
    if looked_up:
        for column in _ONLINE:
            cells[column] = cells[column] or "N/A"
    return cells, failed


def whois_report_rows(row, result=None):
    """Rows for one address in a batch reverse DNS / WHOIS: the same layout as
    the Reverse DNS / WHOIS tab, with "Times seen in file" under the title."""
    if result is None:
        return ([("title", f"Address: {row['ip']}", "")] + _batch_extra_rows(row)
                + [("error", "", f"Lookup failed: {row['whois_error']}")])
    rows = reverse_whois.lookup_rows(result)
    rows[1:1] = _batch_extra_rows(row)
    return rows


def both_report_rows(row, result=None):
    """Rows for one address in a batch of both lookups: the IP-details report,
    then the reverse DNS / WHOIS sections (without a second title)."""
    if result is None:
        return ([("title", f"Address: {row['ip']}", "")] + _batch_extra_rows(row)
                + [("error", "", f"Lookup failed: {row['error'] or row['whois_error']}")])
    return batch_report_rows(row, result["report"]) + reverse_whois.lookup_rows(
        result["whois"])[1:]


WHOIS_BATCH_COLUMNS = (
    ("ip", "IP address", 210), ("count", "Seen", 50), ("from_hostname", "From hostname", 160),
    # Reverse DNS
    ("hostname", "Hostname", 230), ("forward_confirmed", "Forward-confirmed", 125),
    ("ptr_name", "PTR name", 300),
    # WHOIS
    ("owner", "Owner", 240), ("network_name", "Network name", 150),
    ("range", "IP range", 280), ("cidr", "CIDR", 150), ("type", "Allocation type", 150),
    ("country", "Country", 70), ("abuse_email", "Abuse contact", 230),
    ("registered", "Registered", 95), ("last_changed", "Last changed", 95),
    ("registry", "Registry", 260), ("note", "Note", 330),
)


def whois_table_values(row):
    """Cells of the batch table for one reverse DNS / WHOIS row; returns (values, failed)."""
    cells, failed = _whois_cells(row)
    return tuple(cells[c] for c, _, _ in WHOIS_BATCH_COLUMNS), failed


def _whois_cells(row):
    """The reverse DNS / WHOIS cells of a batch row; (cells, failed)."""
    not_public = batch_lookup.whois_not_public(row)
    failed = bool(row["whois_error"]) and not not_public
    cells = dict(row)
    cells["hostname"] = row["hostname"] or "no PTR record"
    cells["note"] = (row["whois_error"] if failed
                     else "no public WHOIS record (not public)" if not_public else "")
    return cells, failed


# Both lookups: IP-details columns, then the reverse DNS / WHOIS ones
BOTH_BATCH_COLUMNS = (
    BATCH_COLUMNS[:-1]
    + tuple(c for c in WHOIS_BATCH_COLUMNS[3:-1] if c[0] != "country")
    + (("whois_country", "WHOIS country", 100), ("note", "Note", 330)))


def both_table_values(row):
    """Cells of the batch table for one row of both lookups; returns (values, failed)."""
    cells, ip_failed = _ip_cells(row)
    whois_cells, whois_failed = _whois_cells(row)
    for column, _, _ in WHOIS_BATCH_COLUMNS[3:-1]:
        if column != "country":
            cells[column] = whois_cells[column]
    notes = [n for n in (cells["note"], whois_cells["note"]) if n]
    cells["note"] = "; ".join(dict.fromkeys(notes))          # no repeated notes
    return tuple(cells[c] for c, _, _ in BOTH_BATCH_COLUMNS), ip_failed or whois_failed


def _ip_summary(rows):
    s = batch_lookup.summarize(rows)
    return (f"{s['total']} address(es): {s['public']} public, {s['not_public']} not public, "
            f"{s['failed']} failed lookup(s)."), s["failed"]


def _whois_summary(rows):
    s = batch_lookup.summarize_whois(rows)
    return (f"{s['total']} address(es): {s['hostnames']} with a hostname, {s['owners']} with a "
            f"network owner, {s['not_public']} not public, {s['failed']} failed WHOIS "
            f"lookup(s)."), s["failed"]


def _both_summary(rows):
    ip_text, ip_failed = _ip_summary(rows)
    s = batch_lookup.summarize_whois(rows)
    return (ip_text[:-1] + f"; {s['hostnames']} with a hostname, {s['owners']} with a network "
            f"owner, {s['failed']} failed WHOIS lookup(s)."), ip_failed + s["failed"]


# What changes between the three kinds of batch lookup in the Batch lookup tab
BATCH_MODES = {
    "ip": {"columns": BATCH_COLUMNS, "values": batch_table_values,
           "report_rows": batch_report_rows, "to_row": batch_lookup.result_row,
           "csv_columns": batch_lookup.CSV_COLUMNS, "suffix": "_results",
           "summary": _ip_summary},
    "whois": {"columns": WHOIS_BATCH_COLUMNS, "values": whois_table_values,
              "report_rows": whois_report_rows, "to_row": batch_lookup.whois_row,
              "csv_columns": batch_lookup.WHOIS_COLUMNS, "suffix": "_whois",
              "summary": _whois_summary},
    "both": {"columns": BOTH_BATCH_COLUMNS, "values": both_table_values,
             "report_rows": both_report_rows, "to_row": batch_lookup.both_row,
             "csv_columns": batch_lookup.BOTH_COLUMNS, "suffix": "_both",
             "summary": _both_summary},
}


# ---------------------------------------------------------------------------
# The window
# ---------------------------------------------------------------------------
class ResultPane(ttk.Frame):
    """A read-only text area that shows reports, plus Save and Map buttons."""

    def __init__(self, parent, app):
        super().__init__(parent, style="Card.TFrame", padding=10)
        self.app = app
        self.data = None          # what "Save report" writes
        self.url = None           # what "Open map" opens

        self.text = tk.Text(self, wrap="word", height=18, relief="flat", bd=0,
                            bg=SURFACE, fg=TEXT, font=(FONT, 10), padx=6, pady=6,
                            tabs=("170p",), cursor="arrow")
        scroll = ttk.Scrollbar(self, command=self.text.yview)
        self.text.configure(yscrollcommand=scroll.set, state="disabled")
        self.text.tag_configure("title", font=(FONT, 12, "bold"), foreground=TEXT,
                                spacing1=10, spacing3=4)
        self.text.tag_configure("head", font=(FONT, 10, "bold"), foreground=DARK,
                                spacing1=8, spacing3=2)
        self.text.tag_configure("label", foreground=MUTED)
        self.text.tag_configure("value", font=(MONO, 10), lmargin2="170p", wrap="char")
        self.text.tag_configure("na", foreground=WARN)
        self.text.tag_configure("error", foreground=ERR)
        self.text.tag_configure("note", foreground=MUTED, font=(FONT, 9, "italic"))

        buttons = ttk.Frame(self, style="Card.TFrame")
        self.save_btn = ttk.Button(buttons, text="Save report (JSON)",
                                   command=self.save, state="disabled")
        self.map_btn = ttk.Button(buttons, text="Open map",
                                  command=self.open_map, state="disabled")
        self.save_btn.pack(side="left")
        self.map_btn.pack(side="left", padx=(8, 0))

        buttons.pack(side="bottom", fill="x", pady=(8, 0))
        scroll.pack(side="right", fill="y")
        self.text.pack(side="left", fill="both", expand=True)

    def clear(self, message=""):
        self.data, self.url = None, None
        self.save_btn.state(["disabled"])
        self.map_btn.state(["disabled"])
        self.text.configure(state="normal")
        self.text.delete("1.0", "end")
        if message:
            self.text.insert("end", message, "note")
        self.text.configure(state="disabled")

    def show_rows(self, rows, data=None):
        """Show ready-made (kind, label, value) rows, e.g. from batch_report_rows()."""
        self.clear()
        self.text.configure(state="normal")
        for kind, label, value in rows:
            self._insert(kind, label, value)
        self.text.configure(state="disabled")
        self.data = data
        if data is not None:
            self.save_btn.state(["!disabled"])

    def show(self, reports, data, error=None):
        """Show a list of reports. data is the dict that Save will write."""
        self.clear()
        self.text.configure(state="normal")
        if error:
            self.text.insert("end", error + "\n", "error")
        for report in reports:
            for kind, label, value in report_rows(report):
                self._insert(kind, label, value)
        self.text.configure(state="disabled")
        self.data, self.url = data, map_url(reports)
        if data is not None:
            self.save_btn.state(["!disabled"])
        if self.url:
            self.map_btn.state(["!disabled"])

    def _insert(self, kind, label, value):
        t = self.text
        if kind in ("title", "head"):
            t.insert("end", label + "\n", kind)
        elif kind == "row":
            t.insert("end", f"  {label}\t", "label")
            if value in (None, ""):
                t.insert("end", "N/A\n", "na")
            else:
                t.insert("end", f"{value}\n", "value")
        else:
            t.insert("end", f"  {value}\n", kind)

    def save(self):
        path = filedialog.asksaveasfilename(
            parent=self, title="Save IPeek report", defaultextension=".json",
            initialfile="ip_report.json", filetypes=[("JSON file", "*.json")])
        if path:
            core.save_results(self.data, path)
            self.app.set_status(f"Saved to {path}")

    def open_map(self):
        if self.url:
            webbrowser.open(self.url)


# Extra values shown in the History tab's Reports view, per kind of lookup
_HISTORY_DETAILS = {"my_ip": (("ipv4", "Public IPv4"), ("ipv6", "Public IPv6"), ("isp", "ISP")),
                    "lookup": (("isp", "ISP / Organization"), ("country", "Country")),
                    "whois": (("hostname", "Hostname"), ("owner", "Owner")),
                    "batch": (("file", "File"), ("addresses", "Addresses")),
                    "batch_whois": (("file", "File"), ("addresses", "Addresses")),
                    "batch_both": (("file", "File"), ("addresses", "Addresses"))}


def history_entry_rows(entry):
    """Report rows for one history entry (History tab, Reports view)."""
    when, kind, target, result = history.entry_row(entry)
    data = entry.get("data", {})
    rows = [("title", f"{when}  ·  {kind}", ""),
            ("row", "Address / file", target),
            ("row", "Result", result)]
    for key, label in _HISTORY_DETAILS.get(entry.get("kind"), ()):
        if key in data:
            rows.append(("row", label, data[key]))
    for change in data.get("changes", []):
        rows.append(("error", "", change["text"]))
    ips = history.batch_ips(entry)
    if ips:                                         # the addresses of a batch lookup
        rows.append(("head", f"Addresses in this batch ({len(ips)})", ""))
        for ip, count, result in ips:
            rows.append(("row", ip, result + (f" (seen {count}x)" if count > 1 else "")))
        if data.get("ips_omitted"):
            rows.append(("note", "", f"and {data['ips_omitted']} more (see the exported CSV)"))
    return rows


def history_change_rows(change):
    """Report rows for one public IP change (History tab, Reports view)."""
    return [("title", f"{change['time'].replace('T', ' ')}  ·  Public {change['version']} "
                      "changed", ""),
            ("row", "Old address", change["old"]),
            ("row", "New address", change["new"]),
            ("row", "Previous check", change["since"].replace("T", " ")),
            ("error", "", change["text"])]


class FindBar(ttk.Frame):
    """Google Docs-style find bar for a tab with a Reports and a Table view.

    Highlights every case-insensitive match in the view that is showing (the
    Reports text, or whole rows in the Table), marks the current one, and
    goes through them with the ▲/▼ buttons, Enter / Shift+Enter or the arrow
    keys. Esc or ✕ clears it. view_var holds "reports" or "table".
    """

    def __init__(self, parent, text, table, view_var):
        super().__init__(parent)
        self.text, self.table, self.view = text, table, view_var
        self.matches, self.index = [], -1
        text.tag_configure("match", background=MATCH)
        text.tag_configure("current", background=CURRENT)
        text.tag_raise("current")
        table.tag_configure("match", background=MATCH)

        ttk.Label(self, text="Find:", foreground=MUTED).pack(side="left", padx=(0, 6))
        self.var = tk.StringVar()
        self.var.trace_add("write", lambda *_: self.search())
        self.entry = ttk.Entry(self, textvariable=self.var, width=24)
        self.entry.pack(side="left")
        for key, step in (("<Return>", 1), ("<Down>", 1), ("<Shift-Return>", -1), ("<Up>", -1)):
            self.entry.bind(key, lambda _e, step=step: self.step(step))
        self.entry.bind("<Escape>", lambda _e: self.var.set(""))
        self.count = ttk.Label(self, text="", foreground=MUTED, width=10, anchor="center")
        self.count.pack(side="left", padx=4)
        for label, step in (("▲", -1), ("▼", 1)):
            ttk.Button(self, text=label, width=3,
                       command=lambda step=step: self.step(step)).pack(side="left")
        ttk.Button(self, text="✕", width=3,
                   command=lambda: self.var.set("")).pack(side="left", padx=(4, 0))

    def focus(self):
        self.entry.focus_set()
        self.entry.select_range(0, "end")

    def search(self):
        """Highlight every match of the find box in the view that is showing."""
        text, table = self.text, self.table
        text.tag_remove("match", "1.0", "end")
        text.tag_remove("current", "1.0", "end")
        for item in table.get_children():
            table.item(item, tags=[t for t in table.item(item, "tags") if t != "match"])
        table.selection_remove(table.selection())
        self.matches, self.index = [], -1

        query = self.var.get().strip()
        if not query:
            self.count.configure(text="", foreground=MUTED)
            return
        if self.view.get() == "reports":
            start, length = "1.0", tk.IntVar()
            while True:
                pos = text.search(query, start, "end", nocase=True, count=length)
                if not pos or not length.get():
                    break
                end = f"{pos}+{length.get()}c"
                text.tag_add("match", pos, end)
                self.matches.append((pos, end))
                start = end
        else:
            needle = query.lower()
            for item in table.get_children():
                if any(needle in str(v).lower() for v in table.item(item, "values")):
                    table.item(item, tags=list(table.item(item, "tags")) + ["match"])
                    self.matches.append(item)
        self.index = 0 if self.matches else -1
        self._show()

    def step(self, step):
        """Go to the next (step=1) or previous (step=-1) match, wrapping around."""
        if self.matches:
            self.index = (self.index + step) % len(self.matches)
            self._show()
        return "break"

    def _show(self):
        total = len(self.matches)
        if not total:
            self.count.configure(text="No results", foreground=ERR)
            return
        self.count.configure(text=f"{self.index + 1} of {total}", foreground=MUTED)
        match = self.matches[self.index]
        if self.view.get() == "reports":
            self.text.tag_remove("current", "1.0", "end")
            self.text.tag_add("current", *match)
            self.text.see(match[0])
        else:
            self.table.selection_set(match)
            self.table.see(match)


class IPeekApp(tk.Tk):
    """Main window: header, 'My public IPs', 'Look up', 'Batch lookup',
    'Reverse DNS / WHOIS' and 'History' tabs, status bar."""

    def __init__(self, autoload=True):
        super().__init__()
        self.title(f"IPeek v{core.APP_VERSION}: IPv4/IPv6 Address Application")
        self.geometry("780x660")
        self.minsize(620, 520)
        self.configure(bg=BG)
        self._results = queue.Queue()
        self._style()
        self._build()
        self.after(100, self._poll)
        if autoload:
            self.refresh_my_ips()

    # ----- layout ---------------------------------------------------------
    def _style(self):
        s = ttk.Style(self)
        s.theme_use("clam")
        s.configure(".", background=BG, foreground=TEXT, font=(FONT, 10))
        s.configure("Card.TFrame", background=SURFACE)
        s.configure("Header.TFrame", background=TEXT)
        s.configure("Title.TLabel", background=TEXT, foreground=BG, font=(FONT, 22, "bold"))
        s.configure("Sub.TLabel", background=TEXT, foreground=BORDER, font=(FONT, 10))
        s.configure("TileName.TLabel", background=SURFACE, foreground=MUTED, font=(FONT, 9))
        s.configure("TileValue.TLabel", background=SURFACE, foreground=TEXT, font=(MONO, 11, "bold"))
        s.configure("Status.TLabel", background=DARK, foreground=BG, padding=(10, 4))
        s.configure("TNotebook", background=BG, borderwidth=0, tabmargins=(12, 8, 12, 0))
        s.configure("TNotebook.Tab", background=BORDER, foreground=TEXT, padding=(14, 6))
        s.map("TNotebook.Tab", background=[("selected", SURFACE)])
        s.configure("TButton", background=SURFACE, bordercolor=BORDER, padding=(10, 4))
        s.map("TButton", background=[("active", BG), ("disabled", SURFACE)],
              foreground=[("disabled", BORDER)])
        s.configure("Primary.TButton", background=TEXT, foreground=BG)
        s.map("Primary.TButton", background=[("active", DARK)])
        s.configure("TEntry", fieldbackground=SURFACE, bordercolor=BORDER, padding=6)
        s.configure("Treeview", background=SURFACE, fieldbackground=SURFACE, foreground=TEXT,
                    bordercolor=BORDER, rowheight=24, font=(MONO, 10))
        s.map("Treeview", background=[("selected", BG)], foreground=[("selected", TEXT)])
        s.configure("Treeview.Heading", background=BORDER, foreground=TEXT,
                    font=(FONT, 9, "bold"), relief="flat")
        s.configure("Toolbutton", background=SURFACE, bordercolor=BORDER, padding=(12, 3))
        s.map("Toolbutton", background=[("selected", TEXT), ("active", BG)],
              foreground=[("selected", BG)])
        s.configure("TProgressbar", background=DARK, troughcolor=SURFACE, bordercolor=BORDER)

    def _build(self):
        header = ttk.Frame(self, style="Header.TFrame", padding=(20, 14))
        ttk.Label(header, text="IPeek", style="Title.TLabel").pack(anchor="w")
        ttk.Label(header, style="Sub.TLabel",
                  text="Check your public IPv4 and IPv6 addresses, or look up any IP "
                       "to see its provider, location and address type.").pack(anchor="w")
        header.pack(fill="x")

        self.status = ttk.Label(self, text="Ready", style="Status.TLabel", anchor="w")
        self.status.pack(side="bottom", fill="x")

        tabs = ttk.Notebook(self)
        tabs.pack(fill="both", expand=True, padx=12, pady=(4, 12))
        tabs.add(self._build_mine(tabs), text="My public IPs")
        tabs.add(self._build_lookup(tabs), text="Look up an IP")
        tabs.add(self._build_batch(tabs), text="Batch lookup")
        tabs.add(self._build_whois(tabs), text="Reverse DNS / WHOIS")
        self.history_tab = self._build_history(tabs)
        tabs.add(self.history_tab, text="History")
        tabs.bind("<<NotebookTabChanged>>", self._tab_changed)
        self.bind("<Control-f>", self._focus_find)
        self.tabs = tabs

    def _build_mine(self, parent):
        tab = ttk.Frame(parent, padding=12)
        tiles = ttk.Frame(tab)
        tiles.pack(fill="x")
        self.v4_value = self._tile(tiles, "Public IPv4", 0)
        self.v6_value = self._tile(tiles, "Public IPv6", 1)
        tiles.columnconfigure((0, 1), weight=1)
        # public IP compared with the last check (filled when history is on)
        self.ip_change = ttk.Label(tab, text="", foreground=MUTED, wraplength=720,
                                   justify="left")
        self.ip_change.pack(fill="x", pady=(8, 0))

        bar = ttk.Frame(tab)
        self.refresh_btn = ttk.Button(bar, text="Refresh", style="Primary.TButton",
                                      command=self.refresh_my_ips)
        self.refresh_btn.pack(side="left")
        bar.pack(fill="x", pady=10)

        self.mine_pane = ResultPane(tab, self)
        self.mine_pane.pack(fill="both", expand=True)
        return tab

    def _tile(self, parent, name, column):
        tile = ttk.Frame(parent, style="Card.TFrame", padding=12)
        tile.grid(row=0, column=column, sticky="nsew", padx=(0, 8) if column == 0 else (8, 0))
        ttk.Label(tile, text=name, style="TileName.TLabel").pack(anchor="w")
        value = ttk.Label(tile, text="...", style="TileValue.TLabel", wraplength=340)
        value.pack(anchor="w")
        return value

    def _build_lookup(self, parent):
        tab = ttk.Frame(parent, padding=12)
        row = ttk.Frame(tab)
        self.entry = ttk.Entry(row, font=(MONO, 11))
        self.entry.pack(side="left", fill="x", expand=True)
        self.entry.bind("<Return>", lambda _e: self.lookup())
        self.lookup_btn = ttk.Button(row, text="Look up", style="Primary.TButton",
                                     command=self.lookup)
        self.lookup_btn.pack(side="left", padx=(8, 0))
        row.pack(fill="x")

        examples = ttk.Frame(tab)
        ttk.Label(examples, text="Try:", foreground=MUTED).pack(side="left")
        for ip in EXAMPLES:
            ttk.Button(examples, text=ip, command=lambda ip=ip: self.lookup(ip)).pack(
                side="left", padx=(6, 0))
        examples.pack(fill="x", pady=10)

        self.lookup_pane = ResultPane(tab, self)
        self.lookup_pane.clear("Type an IPv4 or IPv6 address above and press Look up.")
        self.lookup_pane.pack(fill="both", expand=True)
        return tab

    def _build_batch(self, parent):
        tab = ttk.Frame(parent, padding=12)
        self.batch_entries, self.batch_rows, self.batch_path = [], [], None

        row = ttk.Frame(tab)
        ttk.Button(row, text="Choose file...", command=self.choose_batch_file).pack(side="left")
        self.batch_run_btn = ttk.Button(row, text="Run lookup", style="Primary.TButton",
                                        command=self.run_batch, state="disabled")
        self.batch_run_btn.pack(side="left", padx=(8, 0))
        # Look up: IP details (as in the Look up tab), Reverse DNS / WHOIS, or both
        ttk.Label(row, text="Look up:", foreground=MUTED).pack(side="left", padx=(16, 6))
        self.batch_mode = tk.StringVar(value="ip")
        self.batch_result_mode = "ip"         # the mode of the results on screen
        self.batch_mode_btns = [
            ttk.Radiobutton(row, text=text, value=value, variable=self.batch_mode,
                            style="Toolbutton", command=self.set_batch_mode)
            for value, text in (("ip", "IP details"), ("whois", "Reverse DNS / WHOIS"),
                                ("both", "Both"))]
        for button in self.batch_mode_btns:
            button.pack(side="left")
        self.batch_export_btn = ttk.Button(row, text="Export CSV", command=self.export_batch,
                                           state="disabled")
        self.batch_export_btn.pack(side="right")
        row.pack(fill="x")

        # Optional: also read hostnames (dns.google...) and look up their IPs
        self.batch_hostnames = tk.BooleanVar(value=False)
        self.batch_hostnames_box = ttk.Checkbutton(
            tab, text="Resolve hostnames in the file (e.g. dns.google) and look up their IPs",
            variable=self.batch_hostnames, command=self._batch_hostnames_changed)
        self.batch_hostnames_box.pack(anchor="w", pady=(8, 0))

        self.batch_info = ttk.Label(tab, foreground=MUTED, wraplength=700, justify="left",
                                    text="Choose a .txt or .csv file with IP addresses, for "
                                         "example a firewall export or a log file. IPs can be "
                                         "in any column.")
        self.batch_info.pack(fill="x", pady=(10, 4))
        self.batch_progress = ttk.Progressbar(tab, mode="determinate")
        self.batch_progress.pack(fill="x", pady=(0, 8))

        # View toggle: Reports (one vertical report per IP) or Table (one row per IP)
        toggle = ttk.Frame(tab)
        ttk.Label(toggle, text="View:", foreground=MUTED).pack(side="left", padx=(0, 6))
        self.batch_view = tk.StringVar(value="reports")
        for value, text in (("reports", "Reports"), ("table", "Table")):
            ttk.Radiobutton(toggle, text=text, value=value, variable=self.batch_view,
                            style="Toolbutton", command=self.set_batch_view).pack(side="left")
        toggle.pack(fill="x", pady=(0, 8))

        body = ttk.Frame(tab)
        body.pack(fill="both", expand=True)

        self.batch_pane = ResultPane(body, self)
        self.batch_pane.map_btn.pack_forget()      # one map link doesn't fit many IPs
        self.batch_pane.save_btn.configure(text="Save all reports (JSON)")
        self.batch_pane.clear("The report for each address will appear here, one after "
                              "another, like in the Look up tab.")

        self.batch_table_frame = ttk.Frame(body, style="Card.TFrame")
        self.batch_table = ttk.Treeview(self.batch_table_frame, show="headings")
        self._configure_batch_table()
        self.batch_table.tag_configure("failed", foreground=ERR)
        # Find bar (like Google Docs): highlights every match, ▲/▼ go through them
        self.batch_find = FindBar(toggle, self.batch_pane.text, self.batch_table,
                                  self.batch_view)
        self.batch_find.pack(side="right")
        yscroll = ttk.Scrollbar(self.batch_table_frame, command=self.batch_table.yview)
        xscroll = ttk.Scrollbar(self.batch_table_frame, orient="horizontal",
                                command=self.batch_table.xview)
        self.batch_table.configure(yscrollcommand=yscroll.set, xscrollcommand=xscroll.set)
        self.batch_table.grid(row=0, column=0, sticky="nsew")
        yscroll.grid(row=0, column=1, sticky="ns")
        xscroll.grid(row=1, column=0, sticky="ew")
        self.batch_table_frame.rowconfigure(0, weight=1)
        self.batch_table_frame.columnconfigure(0, weight=1)
        self.set_batch_view()
        self.batch_tab = tab
        return tab

    def _build_whois(self, parent):
        tab = ttk.Frame(parent, padding=12)
        row = ttk.Frame(tab)
        self.whois_entry = ttk.Entry(row, font=(MONO, 11))
        self.whois_entry.pack(side="left", fill="x", expand=True)
        self.whois_entry.bind("<Return>", lambda _e: self.whois_lookup())
        self.whois_btn = ttk.Button(row, text="Look up owner", style="Primary.TButton",
                                    command=self.whois_lookup)
        self.whois_btn.pack(side="left", padx=(8, 0))
        row.pack(fill="x")

        examples = ttk.Frame(tab)
        ttk.Label(examples, text="Try:", foreground=MUTED).pack(side="left")
        for ip in ("8.8.8.8", "1.1.1.1", "193.0.6.139", "2001:4860:4860::8888"):
            ttk.Button(examples, text=ip, command=lambda ip=ip: self.whois_lookup(ip)).pack(
                side="left", padx=(6, 0))
        examples.pack(fill="x", pady=10)

        self.whois_pane = ResultPane(tab, self)
        self.whois_pane.map_btn.pack_forget()      # WHOIS has no coordinates
        self.whois_pane.clear("Type an IP address to find its hostname (reverse DNS) and "
                              "who owns its network (WHOIS).")
        self.whois_pane.pack(fill="both", expand=True)
        return tab

    def _build_history(self, parent):
        tab = ttk.Frame(parent, padding=12)
        row = ttk.Frame(tab)
        ttk.Label(row, text="Show:", foreground=MUTED).pack(side="left", padx=(0, 6))
        self.history_view = tk.StringVar(value="all")
        for value, text in (("all", "All lookups"), ("changes", "Public IP changes")):
            ttk.Radiobutton(row, text=text, value=value, variable=self.history_view,
                            style="Toolbutton", command=self.refresh_history).pack(side="left")
        ttk.Button(row, text="Refresh", command=self.refresh_history).pack(side="left",
                                                                           padx=(12, 0))
        ttk.Button(row, text="Clear history", command=self.clear_history).pack(side="right")
        row.pack(fill="x")

        self.history_info = ttk.Label(tab, foreground=MUTED, wraplength=720, justify="left")
        self.history_info.pack(fill="x", pady=(10, 8))

        # View toggle: Table (one row per lookup) or Reports (one block per lookup)
        toggle = ttk.Frame(tab)
        ttk.Label(toggle, text="View:", foreground=MUTED).pack(side="left", padx=(0, 6))
        self.history_layout = tk.StringVar(value="table")
        for value, text in (("table", "Table"), ("reports", "Reports")):
            ttk.Radiobutton(toggle, text=text, value=value, variable=self.history_layout,
                            style="Toolbutton", command=self.set_history_layout).pack(side="left")
        toggle.pack(fill="x", pady=(0, 8))
        body = ttk.Frame(tab)
        body.pack(fill="both", expand=True)

        self.history_pane = ResultPane(body, self)
        self.history_pane.map_btn.pack_forget()
        self.history_pane.save_btn.configure(text="Save history (JSON)")

        frame = ttk.Frame(body, style="Card.TFrame")
        self.history_table = ttk.Treeview(frame, show="headings",
                                          columns=("time", "kind", "target", "result"))
        for column, heading, width in (("time", "Time", 150), ("kind", "Lookup", 190),
                                       ("target", "Address / file", 250),
                                       ("result", "Result", 520)):
            self.history_table.heading(column, text=heading, anchor="w")
            self.history_table.column(column, width=width, minwidth=60, anchor="w",
                                      stretch=column == "result")
        self.history_table.tag_configure("change", foreground=WARN)
        self.history_table.tag_configure("batch_ip", foreground=MUTED)
        yscroll = ttk.Scrollbar(frame, command=self.history_table.yview)
        xscroll = ttk.Scrollbar(frame, orient="horizontal", command=self.history_table.xview)
        self.history_table.configure(yscrollcommand=yscroll.set, xscrollcommand=xscroll.set)
        self.history_table.grid(row=0, column=0, sticky="nsew")
        yscroll.grid(row=0, column=1, sticky="ns")
        xscroll.grid(row=1, column=0, sticky="ew")
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)
        self.history_table_frame = frame
        self.history_find = FindBar(toggle, self.history_pane.text, self.history_table,
                                    self.history_layout)
        self.history_find.pack(side="right")
        self.set_history_layout()
        return tab

    # ----- actions --------------------------------------------------------
    def _tab_changed(self, _event=None):
        if self.tabs.select() == str(self.history_tab):
            self.refresh_history()

    def set_history_layout(self):
        """Show the History tab's Table or Reports view."""
        table = self.history_layout.get() == "table"
        (self.history_pane if table else self.history_table_frame).pack_forget()
        (self.history_table_frame if table else self.history_pane).pack(fill="both", expand=True)
        self.history_find.search()            # search the view that is now showing

    def refresh_history(self):
        """Fill the History tab (both views), newest first."""
        table = self.history_table
        table.delete(*table.get_children())
        checks = history.load("my_ip")
        changes = history.ip_changes()
        lines = []
        if self.history_view.get() == "changes":
            shown = list(reversed(changes))
            for c in shown:
                table.insert("", "end", tags=("change",), values=(
                    c["time"].replace("T", " "), f"Public {c['version']} changed",
                    c["new"] or "-",
                    f"{c['text']} (previous check {c['since'].replace('T', ' ')})"))
                lines += history_change_rows(c)
            empty = "No public IP changes recorded yet."
        else:
            shown = list(reversed(history.load()))
            for entry in shown:
                tags = ("change",) if entry.get("data", {}).get("changes") else ()
                table.insert("", "end", values=history.entry_row(entry), tags=tags)
                for ip, count, result in history.batch_ips(entry):   # addresses in a batch
                    seen = f" (seen {count}x)" if count > 1 else ""
                    table.insert("", "end", tags=("batch_ip",),
                                 values=("", "   ↳ address in batch", ip, result + seen))
                lines += history_entry_rows(entry)
        if shown:
            self.history_pane.show_rows(lines, data=shown)
        else:
            self.history_pane.clear(empty if self.history_view.get() == "changes"
                                    else "No lookups recorded yet.")
        self.history_find.search()            # re-apply a search typed earlier
        self.history_info.configure(
            text=f"{len(changes)} public IP change(s) in {len(checks)} check(s) of your "
                 f"public IP. The history is saved in {history.history_path()}")

    def clear_history(self):
        if messagebox.askyesno("Clear history", "Delete the whole lookup history?",
                               parent=self):
            history.clear()
            self.refresh_history()
            self.set_status("Lookup history deleted")

    def set_status(self, text):
        self.status.configure(text=text)

    def refresh_my_ips(self):
        self.refresh_btn.state(["disabled"])
        self.v4_value.configure(text="...", foreground=TEXT)
        self.v6_value.configure(text="...", foreground=TEXT)
        self.mine_pane.clear("Contacting ipify and ipapi.co...")
        self.set_status("Looking up your public IP addresses...")
        self._run(core.get_my_report, self.show_my_ips)

    def show_my_ips(self, results, error=None):
        self.refresh_btn.state(["!disabled"])
        if error:
            self.mine_pane.show([], None, error=f"Lookup failed: {error}")
            self.set_status("Lookup failed")
            return
        v4, v6 = results["public_ipv4"], results["public_ipv6"]
        self.v4_value.configure(text=v4 or "not detected", foreground=TEXT if v4 else ERR)
        self.v6_value.configure(text=v6 or "not available (network has no IPv6)",
                                foreground=TEXT if v6 else WARN)
        note = None if v4 or v6 else ("Could not reach ipify. Check your internet "
                                      "connection, then press Refresh.")
        self.mine_pane.show(results["reports"], results, error=note)
        self.set_status(f"Updated {results['generated'].replace('T', ' ')}")
        status = history.record_my_ips(results)     # None when history is off
        text = history.status_text(status)
        if status and status["changes"]:
            self.ip_change.configure(text="⚠ " + text, foreground=WARN, font=(FONT, 10, "bold"))
        else:
            self.ip_change.configure(text=text or "", foreground=OK, font=(FONT, 10))

    def lookup(self, ip=None):
        if ip is not None:
            self.entry.delete(0, "end")
            self.entry.insert(0, ip)
        text = self.entry.get().strip()
        if not text:
            return
        try:
            core.analyze_ip(text)           # validate before going online
        except ValueError:
            self.lookup_pane.show([], None,
                                  error=f"'{text}' is not a valid IPv4 or IPv6 address.")
            self.set_status("Invalid address")
            return
        self.lookup_btn.state(["disabled"])
        self.lookup_pane.clear(f"Looking up {text}...")
        self.set_status(f"Looking up {text}...")
        self._run(lambda: core.build_report(text), self.show_lookup)

    def show_lookup(self, report, error=None):
        self.lookup_btn.state(["!disabled"])
        if error:
            self.lookup_pane.show([], None, error=f"Lookup failed: {error}")
            self.set_status("Lookup failed")
            return
        self.lookup_pane.show([report], report)
        history.record_lookup(report)
        self.set_status(f"Looked up {report['analysis']['address']}")

    def set_batch_view(self):
        """Show the Reports or the Table view, as chosen with the View toggle."""
        reports = self.batch_view.get() == "reports"
        (self.batch_table_frame if reports else self.batch_pane).pack_forget()
        (self.batch_pane if reports else self.batch_table_frame).pack(fill="both", expand=True)
        self.batch_find.search()                    # search the view that is now showing

    # ----- find bars -------------------------------------------------------
    def _focus_find(self, _event=None):
        """Ctrl+F jumps to the find box of the Batch lookup or History tab."""
        bars = {str(self.batch_tab): self.batch_find, str(self.history_tab): self.history_find}
        bar = bars.get(self.tabs.select())
        if bar is None:
            return None
        bar.focus()
        return "break"

    def _configure_batch_table(self):
        """Set the table's columns for the chosen Look up mode."""
        columns = BATCH_MODES[self.batch_mode.get()]["columns"]
        self.batch_table.delete(*self.batch_table.get_children())
        self.batch_table.configure(columns=[c for c, _, _ in columns])
        for column, heading, width in columns:
            self.batch_table.heading(column, text=heading, anchor="w")
            self.batch_table.column(column, width=width, minwidth=40, anchor="w", stretch=False)

    def set_batch_mode(self):
        """Switch between IP details and Reverse DNS / WHOIS; old results are cleared."""
        self._configure_batch_table()
        self.batch_rows = []
        self.batch_result_mode = self.batch_mode.get()
        self.batch_progress.configure(value=0)
        self.batch_export_btn.state(["disabled"])
        what = {"ip": "IP details", "whois": "hostname and network owner",
                "both": "IP details, hostname and network owner"}[self.batch_result_mode]
        self.batch_pane.clear(f"Press Run lookup to look up the {what} of every address "
                              "in the file." if self.batch_entries else
                              "The report for each address will appear here, one after "
                              "another.")
        self.batch_find.search()

    def choose_batch_file(self):
        path = filedialog.askopenfilename(
            parent=self, title="Choose a file with IP addresses",
            filetypes=[("IP lists", "*.txt *.csv *.log"), ("All files", "*.*")])
        if path:
            self.load_batch_file(path)

    def _batch_hostnames_changed(self):
        """Re-read the loaded file, with or without its hostnames."""
        if self.batch_path:
            self.load_batch_file(self.batch_path)

    def load_batch_file(self, path):
        """Read the file (fast, offline) and show how many addresses it has."""
        hostnames = self.batch_hostnames.get()
        try:
            entries, skipped = batch_lookup.read_ip_file(path, hostnames)
        except OSError as exc:
            self.batch_info.configure(text=f"Could not read the file: {exc}", foreground=ERR)
            return
        self.batch_path, self.batch_entries = path, entries
        self.batch_pane.clear("Press Run lookup to look up every address in the file.")
        self.batch_table.delete(*self.batch_table.get_children())
        self.batch_find.search()
        self.batch_progress.configure(value=0)
        self.batch_export_btn.state(["disabled"])
        name = path.replace("\\", "/").split("/")[-1]
        what = "IP addresses or hostnames" if hostnames else "IP addresses"
        if not entries:
            self.batch_run_btn.state(["disabled"])
            self.batch_info.configure(text=f"No {what} found in {name}.", foreground=WARN)
            return
        names = sum(1 for t, _ in entries if batch_lookup.is_hostname(t))
        text = f"{name}: {len(entries) - names} unique IP address(es)"
        text += f" and {names} hostname(s) found." if hostnames else " found."
        if skipped:
            text += f" Skipped {len(skipped)} line(s) with no {what[:-2]}."
        self.batch_info.configure(text=text + " Press Run lookup to start.", foreground=MUTED)
        self.batch_run_btn.state(["!disabled"])

    def run_batch(self):
        if not self.batch_entries:
            return
        self.batch_run_btn.state(["disabled"])
        self.batch_export_btn.state(["disabled"])
        for button in self.batch_mode_btns + [self.batch_hostnames_box]:
            button.state(["disabled"])
        self.batch_pane.clear(f"Looking up {len(self.batch_entries)} address(es)...")
        self.batch_table.delete(*self.batch_table.get_children())
        self.batch_find.search()
        self.batch_progress.configure(maximum=len(self.batch_entries), value=0)
        entries = list(self.batch_entries)

        def progress(done, total, ip):        # runs in the worker thread
            self._results.put((self._batch_progress, (done, total, ip), None))

        mode = self.batch_mode.get()
        cache = reverse_whois.WhoisCache()        # one WHOIS query per network
        if mode == "whois":
            run = lambda ip: reverse_whois.lookup(ip, cache)  # noqa: E731
        elif mode == "both":
            run = lambda ip: {"report": core.build_report(ip),  # noqa: E731
                              "whois": reverse_whois.lookup(ip, cache)}
        else:
            run = core.build_report

        def work():
            reports = {}
            # hostnames -> IPs (DNS can be slow, so this runs in the worker thread too)
            resolved, unresolved = batch_lookup.resolve_entries(entries)

            def lookup(ip):                   # keep each full report for display
                reports[ip] = run(ip)
                return reports[ip]
            rows = batch_lookup.run_batch(resolved, lookup, progress,
                                          to_row=BATCH_MODES[mode]["to_row"])
            return mode, rows, reports, unresolved

        self._run(work, self.show_batch)

    def _batch_progress(self, step, _error=None):
        done, total, ip = step
        self.batch_progress.configure(maximum=total, value=done)   # hostnames add IPs
        self.set_status(f"Batch lookup {done}/{total}: {ip}")

    def show_batch(self, result, error=None):
        self.batch_run_btn.state(["!disabled"])
        for button in self.batch_mode_btns + [self.batch_hostnames_box]:
            button.state(["!disabled"])
        if error:
            self.batch_info.configure(text=f"Batch lookup failed: {error}", foreground=ERR)
            self.set_status("Batch lookup failed")
            return
        mode, rows, reports, unresolved = result
        self.batch_rows, self.batch_result_mode = rows, mode
        m = BATCH_MODES[mode]
        lines = []
        for row in rows:
            lines += m["report_rows"](row, reports.get(row["ip"]))
            values, failed = m["values"](row)
            self.batch_table.insert("", "end", values=values, tags=("failed",) if failed else ())
        self.batch_pane.show_rows(lines, data={"input": self.batch_path,
                                               "reports": list(reports.values())})
        summary, failed_count = m["summary"](rows)
        if unresolved:
            listed = ", ".join(n for n, _ in unresolved[:5]) + (" ..." if len(unresolved) > 5
                                                                 else "")
            summary += f" Could not resolve {len(unresolved)} hostname(s): {listed}."
        history.record_batch(self.batch_path or "", mode, len(rows), summary, rows)
        self.batch_info.configure(text=summary + " Press Export CSV to save the results.",
                                  foreground=ERR if failed_count or unresolved else MUTED)
        self.batch_export_btn.state(["!disabled"])
        self.set_status("Batch lookup finished")
        self.batch_find.search()                    # re-apply a search typed earlier

    def export_batch(self):
        m = BATCH_MODES[self.batch_result_mode]
        default = batch_lookup.default_output_path(self.batch_path or "ip_list.txt", m["suffix"])
        path = filedialog.asksaveasfilename(
            parent=self, title="Export batch results", defaultextension=".csv",
            initialfile=default.replace("\\", "/").split("/")[-1],
            filetypes=[("CSV file", "*.csv")])
        if path:
            batch_lookup.write_csv(self.batch_rows, path, m["csv_columns"])
            self.set_status(f"Exported {len(self.batch_rows)} row(s) to {path}")

    def whois_lookup(self, ip=None):
        if ip is not None:
            self.whois_entry.delete(0, "end")
            self.whois_entry.insert(0, ip)
        text = self.whois_entry.get().strip()
        if not text:
            return
        try:
            core.analyze_ip(text)           # validate before going online
        except ValueError:
            self.whois_pane.show([], None,
                                 error=f"'{text}' is not a valid IPv4 or IPv6 address.")
            self.set_status("Invalid address")
            return
        self.whois_btn.state(["disabled"])
        self.whois_pane.clear(f"Looking up the hostname and network owner of {text}...")
        self.set_status(f"Reverse DNS / WHOIS lookup for {text}...")
        self._run(lambda: reverse_whois.lookup(text), self.show_whois)

    def show_whois(self, result, error=None):
        self.whois_btn.state(["!disabled"])
        if error:
            self.whois_pane.show([], None, error=f"Lookup failed: {error}")
            self.set_status("Lookup failed")
            return
        self.whois_pane.show_rows(reverse_whois.lookup_rows(result), data=result)
        history.record_whois(result)
        self.set_status(f"Reverse DNS / WHOIS for {result['ip']} done")

    # ----- background work ------------------------------------------------
    def _run(self, work, done):
        """Run work() in a thread, then call done(result, error) on the UI thread."""
        def target():
            try:
                self._results.put((done, work(), None))
            except Exception as exc:          # show any failure instead of crashing
                self._results.put((done, None, str(exc)))
        threading.Thread(target=target, daemon=True).start()

    def _poll(self):
        try:
            while True:
                done, result, error = self._results.get_nowait()
                done(result, error)
        except queue.Empty:
            pass
        self.after(100, self._poll)


def main():
    history.ENABLED = True          # only when run as a program, never in the tests
    IPeekApp().mainloop()


if __name__ == "__main__":
    main()
