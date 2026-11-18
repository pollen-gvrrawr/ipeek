# IPeek: IPv4/IPv6 Address Application

[![tests](https://github.com/pollen-gvrrawr/ipeek/actions/workflows/tests.yml/badge.svg)](https://github.com/pollen-gvrrawr/ipeek/actions/workflows/tests.yml)

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

## APIs used

| API | Purpose | Key needed? |
|-----|---------|-------------|
| [ipify](https://www.ipify.org): `api.ipify.org`, `api6.ipify.org` | Public IPv4 / IPv6 | No |
| [ipapi.co](https://ipapi.co/api/) | IP details (primary) | No (free tier: about 1,000 requests/day) |
| [ipwho.is](https://ipwho.is) | IP details (backup) | No |

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

python gui_app.py                     # desktop window
```

Run the tests. They work offline because the APIs are mocked:

```bash
python -m unittest discover -s tests -v
```

## Desktop GUI

[`gui_app.py`](gui_app.py) opens IPeek in a window. It has two tabs:

* **My public IPs** shows your public IPv4 and IPv6 at the top, then the full report for each. **Refresh** looks them up again.
* **Look up an IP** takes any IPv4 or IPv6 address, with example buttons for public, private and link-local addresses.

Both tabs can **Save report (JSON)** and **Open map** in your browser. The GUI has no networking or analysis code of its own. It calls `get_my_report()` and `build_report()` from `ip_info_app.py`, so the CLI and the GUI always give the same answers. Lookups run in a background thread, so the window doesn't freeze while it waits for an API.

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

## Team workflow

* `main` holds the reviewed, working version of the app.
* Each member works on a branch named `feature/<name>-<task>`. They open a **pull request**, another member reviews it, and it is merged into `main`.
* **CI pipeline (GitHub Actions):** [`.github/workflows/tests.yml`](.github/workflows/tests.yml) runs every unit test on Windows and Linux on each push and pull request. `main` is protected: a pull request can only be merged when both test jobs pass.
* Future work is listed in [BACKLOG.md](BACKLOG.md).

## Team

* Samantha Guevarra
* Sofiagail Lustre
* Gwyneth Fajardo
