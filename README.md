# IPeek: IPv4/IPv6 Address Application

[![tests](https://github.com/pollen-gvrrawr/ipeek/actions/workflows/tests.yml/badge.svg)](https://github.com/pollen-gvrrawr/ipeek/actions/workflows/tests.yml)
[![release](https://github.com/pollen-gvrrawr/ipeek/actions/workflows/release.yml/badge.svg)](https://github.com/pollen-gvrrawr/ipeek/actions/workflows/release.yml)

DEVASC Project Activity 3, Option 2. IPeek is a Python prototype for network technicians, with a command-line app and a desktop window (Tkinter) that share the same code. It shows a computer's current **public IPv4 and IPv6 addresses** and the details behind them: ISP, ASN, country code, geolocation and timezone. It also analyses any address you type in.

## Features

| # | Feature | Where in the code |
|---|---------|-------------------|
| 1 | Detects the public IPv4 **and** IPv6 address. If the network has no IPv6, it says so instead of crashing. | `get_public_ips()` |
| 2 | ISP/organization, **ASN**, country and **country code**, region/city, postal code, coordinates, timezone | `get_ip_details()` |
| 3 | Backup API: if ipapi.co is rate-limited, it switches to ipwho.is automatically | `_from_ipapi()`, `_from_ipwhois()` |
| 4 | Offline address analysis: scope (public/private/link-local/loopback), IPv4 class and binary, IPv6 compressed/expanded form, reverse DNS name | `analyze_ip()` |
| 5 | Look up **any** IPv4/IPv6 address, with input validation | `show_lookup()` |
| 6 | Formatted, coloured output and a Google Maps link to the location | display layer |
| 7 | JSON output (`--json`) and save to file (`--save`) for tickets and scripts | `save_results()` |
| 8 | Interactive menu, or command-line flags for quick use | `interactive_menu()`, `main()` |
| 9 | Desktop GUI with the same features: tabs, Refresh and Look up buttons, Save report and Open map | `gui_app.py` |
| 10 | Subnet calculator for IPv4 and IPv6: mask, wildcard, broadcast, first/last usable host and host count | `subnet_calc.py` |
| 11 | Local network info: private IPv4, subnet mask, network, default gateway and DNS servers (Windows, Linux, macOS) | `local_network.py` |
| 12 | Connectivity tests: ping and traceroute to any host, and an IPv6 readiness check that shows whether IPv6 works end to end | `connectivity.py` |
| 13 | Standalone Windows `.exe` files for the CLI and the GUI, so technicians can run IPeek without installing Python | `.github/workflows/release.yml` |
| 14 | Batch lookup: reads the IPs from a .txt/.csv file (firewall exports, logs; IPs can be in any column) and exports every field of the single-IP report to CSV, in the CLI and the GUI | `batch_lookup.py` |
| 15 | Reverse DNS / WHOIS: the real hostname of an IP (PTR lookup, with a forward-confirmation check) and who owns its network (owner, IP range/CIDR, abuse contact, registry), for one IP or every IP in a .txt/.csv file (exported to CSV), in the CLI and the GUI | `reverse_whois.py` |
| 16 | Batch extras: run **both** lookups (IP details + reverse DNS / WHOIS) for every IP in one go, and optionally read **hostnames** from the file (each is resolved to its IP addresses, which are then looked up; names that don't resolve are reported), in the CLI and the GUI | `batch_lookup.py` |
| 17 | Lookup history: every lookup is logged on this computer, and each check of your public IP is compared with the last one, so a change of IP from the ISP is reported straight away. `--history`, `--ip-changes` and a History tab in the GUI | `history.py` |

## APIs used

| API | Purpose | Key needed? |
|-----|---------|-------------|
| [ipify](https://www.ipify.org): `api.ipify.org`, `api6.ipify.org` | Public IPv4 / IPv6 | No |
| [ipapi.co](https://ipapi.co/api/) | IP details (primary) | No (free tier: about 1,000 requests/day) |
| [ipwho.is](https://ipwho.is) | IP details (backup) | No |
| [RDAP](https://about.rdap.org) via `rdap.org` | WHOIS: network owner, range and abuse contact. rdap.org redirects to the right registry (ARIN, RIPE NCC, APNIC, LACNIC, AFRINIC) | No |

## Download (Windows, no Python needed)

Get the latest `ipeek.exe` (command line) and `ipeek-gui.exe` (desktop window) from the [Releases page](https://github.com/pollen-gvrrawr/ipeek/releases/latest). The files are not code-signed, so Windows SmartScreen may show "Windows protected your PC" the first time: click **More info**, then **Run anyway**.

```bash
ipeek.exe --me
ipeek.exe --ip 8.8.8.8
ipeek-gui.exe
```

## Install and run

```bash
git clone https://github.com/pollen-gvrrawr/ipeek
cd ipeek
pip install -r requirements.txt

python ip_info_app.py                 # interactive menu
python ip_info_app.py --me            # my public IPv4 + IPv6
python ip_info_app.py --ip 8.8.8.8    # look up any address
python ip_info_app.py --ip 2001:4860:4860::8888
python ip_info_app.py --me --json     # raw JSON
python ip_info_app.py --me --save report.json
python ip_info_app.py --subnet 192.168.1.0/26        # subnet calculator
python ip_info_app.py --subnet 2001:db8:abcd:12::/64
python ip_info_app.py --local                        # private IP, mask, gateway, DNS
python ip_info_app.py --ping 8.8.8.8                 # ping a host
python ip_info_app.py --trace 8.8.8.8                # traceroute to a host
python ip_info_app.py --ipv6-check                   # does IPv6 work end to end?
python ip_info_app.py --batch samples/ips.txt                    # batch lookup -> samples/ips_results.csv
python ip_info_app.py --batch samples/firewall_log.csv           # -> samples/firewall_log_results.csv
python ip_info_app.py --batch samples/ips.txt --brief            # summary table only (CSV still has every field)
python ip_info_app.py --batch samples/ips.txt --find google      # highlight every match and count them
python ip_info_app.py --batch samples/ips.txt --out report.csv   # choose the CSV file name
python ip_info_app.py --batch samples/firewall_log.csv --json    # raw JSON
python ip_info_app.py --batch samples/ips.txt --find google
python ip_info_app.py --batch samples/firewall_log.csv --find private
python ip_info_app.py --batch samples/ips.txt --find AS15169 --brief   # summary only, still counts matches
python ip_info_app.py --batch samples/ips.txt --find cloudflare --json # matches per IP in the JSON
python ip_info_app.py --whois 8.8.8.8                # hostname (reverse DNS) + network owner (WHOIS)
python ip_info_app.py --whois 2001:4860:4860::8888 --json
python ip_info_app.py --batch-whois samples/whois_ips.txt       # every IP in a file -> samples/whois_ips_whois.csv
python ip_info_app.py --batch-whois samples/whois_log.csv --brief --find google
python ip_info_app.py --batch-both samples/whois_ips.txt        # IP details + reverse DNS / WHOIS -> samples/whois_ips_both.csv
python ip_info_app.py --batch-both samples/hostnames.txt --resolve-hostnames   # hostnames too
python ip_info_app.py --batch samples/hostnames.txt --resolve-hostnames --brief
python ip_info_app.py --batch-whois samples/hostnames.txt --resolve-hostnames --json
python ip_info_app.py --history                     # the last 20 lookups (--history 50, or 0 for all)
python ip_info_app.py --ip-changes                  # every change of your public IP
python ip_info_app.py --me --no-history             # a check that isn't recorded
python ip_info_app.py --clear-history               # delete the history


python gui_app.py                     # desktop window
```

The [`samples/`](samples/) folder has two files for trying the batch lookup:

* [`samples/ips.txt`](samples/ips.txt): one address per line. It has public IPv4 and IPv6 DNS servers, private, loopback and link-local addresses, a duplicate (counted twice) and two invalid lines (reported as skipped).
* [`samples/firewall_log.csv`](samples/firewall_log.csv): a firewall-style export with a header row and the IPs in the `src_ip` and `dst_ip` columns, including one with a port (`8.8.8.8:53`).

* [`samples/whois_ips.txt`](samples/whois_ips.txt): for `--batch-whois`. One address from each regional registry (ARIN, RIPE NCC, APNIC, LACNIC/NIC.br, AFRINIC), two addresses in the same network (the second reuses the first WHOIS answer), IPv6, a public address with no hostname, hostnames that don't point back to their IP, private addresses, a duplicate and an invalid line.
* [`samples/whois_log.csv`](samples/whois_log.csv): a mail/SSH/DNS server log for `--batch-whois`, with the IPs in the `client_ip` and `server_ip` columns.
* [`samples/hostnames.txt`](samples/hostnames.txt): hostnames and IP addresses together, for `--resolve-hostnames`. A hostname that resolves to an IP that is also in the file (looked up once, counted twice), a private address and a name that doesn't exist.

In the GUI, open the **Batch lookup** tab, click **Choose file...** and pick one of these files (choose **Reverse DNS / WHOIS** under **Look up** for the two WHOIS samples). Each run of a sample file makes about 6 real API calls, so repeated runs count towards ipapi.co's daily limit.

Run the tests. They work offline because the APIs are mocked:

```bash
python -m unittest discover -s tests -v
```

## Desktop GUI

[`gui_app.py`](gui_app.py) opens IPeek in a window. It has five tabs:

* **My public IPs** shows your public IPv4 and IPv6 at the top, then the full report for each. **Refresh** looks them up again.
* **Look up an IP** takes any IPv4 or IPv6 address, with example buttons for public, private and link-local addresses.
* **Batch lookup** opens a .txt or .csv file, looks up every IP in it with a progress bar and can **Export CSV**. A **Look up** switch chooses **IP details** (the same as the Look up tab), **Reverse DNS / WHOIS** (the same as the Reverse DNS / WHOIS tab) or **Both**. Tick **Resolve hostnames in the file** to also read hostnames such as `dns.google`: each is resolved to its IP addresses, which are looked up and shown with the hostname they came from. A **View** toggle switches between **Reports** (one vertical report per IP, like the Look up tab) and **Table** (one row per IP, all fields). The **Find** box highlights every match in either view; use ▲/▼ (or Enter / Shift+Enter) to go through them, Esc to clear, and Ctrl+F to jump to it.
* **Reverse DNS / WHOIS** shows an address's hostname and who owns its network, and can **Save report (JSON)**.
* **History** lists past lookups (newest first) or only the **Public IP changes**, and can **Clear history**. A batch lookup is listed with every address it checked and the result for each (up to 500 per batch; the exported CSV has them all), so you can search the history for an IP and see which batch it was in. Like the Batch lookup tab, it has a **View** toggle between **Table** (one row per lookup) and **Reports** (one block per lookup with its details), and a **Find** box that highlights every match (▲/▼ or Enter / Shift+Enter to go through them, Ctrl+F to jump to it). The **My public IPs** tab also says whether your public IP has changed since the last check.

The first two tabs can **Save report (JSON)** and **Open map** in your browser. The GUI has no networking or analysis code of its own. It calls `get_my_report()` and `build_report()` from `ip_info_app.py`, so the CLI and the GUI always give the same answers. Lookups run in a background thread, so the window doesn't freeze while it waits for an API.

Tkinter comes with the standard Python installer on Windows and macOS. On Linux, install it with `sudo apt install python3-tk`.

## Code structure (for teams continuing the project)

`ip_info_app.py` is split into five layers. Each layer only calls the one below it:

1. **CONFIG**: API URLs and timeout. To change provider, edit this section.
2. **API layer**: calls the REST APIs and returns *normalised* dicts. Every provider returns the same keys, so adding a new provider means writing one `_from_xxx()` function and adding it to the list in `get_ip_details()`.
3. **Analysis layer**: offline facts from Python's `ipaddress` module.
4. **Display layer**: formatting and printing only.
5. **CLI / menu**: `argparse` flags and the interactive menu.

`gui_app.py` replaces layers 4 and 5 with a Tkinter window and reuses layers 1 to 3 unchanged. To add another interface, follow the same pattern.

New Project Activity 4 features each live in their own module, so team members can work on them in parallel without editing the same code. `ip_info_app.py` only adds a flag and a menu option for each:

* `subnet_calc.py`: subnet calculator (offline, `ipaddress` module).
* `local_network.py`: local network info. It reads the operating system's own tools (`ipconfig`, `ip`, `ifconfig`); the parsers are tested with sample output from each system.
* `connectivity.py`: ping, traceroute and the IPv6 readiness check. It runs the system's `ping`/`tracert`/`traceroute` without a shell, and checks the host name first so it can't be used to inject commands.
* `batch_lookup.py`: batch lookup. It finds the IPs in every column of a .txt/.csv file (ports such as `203.0.113.5:443` are removed, duplicates are looked up once and counted), runs `build_report()` for each, and writes the results to CSV. Private addresses skip the API, which saves the free-tier limit; a large file of public IPs can still use up ipapi.co's daily requests, and then ipwho.is takes over. It can run IP details, reverse DNS / WHOIS, or both for every address (`both_row()` merges the two, renaming the WHOIS `country`/`source` columns to `whois_country`/`whois_source`). With `--resolve-hostnames`, `resolve_entries()` turns hostnames into their IP addresses first; it is off by default because logs are full of dotted names (such as `HELO mail.example.org`) that aren't meant to be looked up.
* `reverse_whois.py`: reverse DNS and WHOIS. The hostname comes from a real PTR lookup through the computer's DNS resolver, then a forward-confirmation check resolves the hostname back to see whether it points to the same IP (a mismatch is a common sign of a misconfigured or spoofed mail server). The network owner comes from RDAP, the JSON version of WHOIS. Private addresses skip RDAP because they have no public record. Only the owner organisation and abuse e-mail are shown, not personal contact names. For batch lookups (`--batch-whois` and the GUI), addresses in a network that was already looked up reuse that WHOIS answer, so a long file only sends one registry query per network and stays under the registries' rate limits.
* `history.py`: lookup history. Each lookup is saved as one line of JSON in the user's app-data folder (Windows: `%APPDATA%\IPeek\history.jsonl`; macOS: `~/Library/Application Support/IPeek/`; Linux: `~/.local/share/ipeek/`), so it works the same for the `.exe` and is never committed. Only the newest 1,000 entries are kept. Logging is only switched on when the CLI or GUI is started as a program, so the unit tests never write to a real history file.

## Team workflow

* `main` holds the reviewed, working version of the app.
* Each member works on a branch named `feature/<name>-<task>`. They open a **pull request**, another member reviews it, and it is merged into `main`.
* Future work is listed in [BACKLOG.md](BACKLOG.md).

## CI/CD pipeline (GitHub Actions)

| Workflow | Runs when | What it does |
|----------|-----------|--------------|
| **CI**: [`tests.yml`](.github/workflows/tests.yml) | Every push to any branch, and every pull request into `main` | Runs every unit test on Windows and Linux |
| **CD**: [`release.yml`](.github/workflows/release.yml) | A version tag such as `v2.0.0` is pushed (or it is started by hand from the Actions tab) | Runs the unit tests again. Only if they pass, it builds `ipeek.exe` and `ipeek-gui.exe` with PyInstaller, smoke-tests the CLI `.exe`, and publishes both files on a GitHub Release |

`main` is protected by a ruleset: changes go in through a pull request, and the pull request can only be merged when both CI test jobs pass and the branch is up to date. Nobody can bypass the rule, so a change that breaks a test never reaches `main`, and a release is only built from code that passed every test.

To publish a new release:

1. Raise `APP_VERSION` in `ip_info_app.py` (for example to `2.1.0`) through a pull request, and merge it.
2. Tag the merged commit and push the tag:

   ```bash
   git checkout main
   git pull
   git tag v2.1.0
   git push origin v2.1.0
   ```

3. Watch the **release** workflow in the Actions tab. When it finishes, the `.exe` files are on the Releases page. The workflow stops if the tag doesn't match `APP_VERSION`.

## Team

* Samantha Guevarra
* Sofiagail Lustre
* Gwyneth Fajardo
