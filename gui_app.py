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
    * IPeekApp                   - the window: header, two tabs, status bar
    * lookups run in a background thread so the window never freezes while
      waiting for an API; results come back through a queue.
"""

import queue
import threading
import tkinter as tk
import webbrowser
from tkinter import filedialog, ttk

import ip_info_app as core

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


class IPeekApp(tk.Tk):
    """Main window: header, 'My public IPs' tab, 'Look up' tab, status bar."""

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
        self.tabs = tabs

    def _build_mine(self, parent):
        tab = ttk.Frame(parent, padding=12)
        tiles = ttk.Frame(tab)
        tiles.pack(fill="x")
        self.v4_value = self._tile(tiles, "Public IPv4", 0)
        self.v6_value = self._tile(tiles, "Public IPv6", 1)
        tiles.columnconfigure((0, 1), weight=1)

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

    # ----- actions --------------------------------------------------------
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
        self.set_status(f"Looked up {report['analysis']['address']}")

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
    IPeekApp().mainloop()


if __name__ == "__main__":
    main()
