# IPv4/IPv6 Address Application

DEVASC Project Activity 3, Option 2. This is a Python command-line prototype for network technicians. It shows a computer's current **public IPv4 and IPv6 addresses** and the details behind them: ISP, ASN, country code, geolocation and timezone. It also analyses any address you type in.

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

## APIs used

| API | Purpose | Key needed? |
|-----|---------|-------------|
| [ipify](https://www.ipify.org): `api.ipify.org`, `api6.ipify.org` | Public IPv4 / IPv6 | No |
| [ipapi.co](https://ipapi.co/api/) | IP details (primary) | No (free tier: about 1,000 requests/day) |
| [ipwho.is](https://ipwho.is) | IP details (backup) | No |

## Install and run

```bash
git clone https://github.com/pollen-gvrrawr/ipv4-ipv6-address-app
cd ipv4-ipv6-address-app
pip install -r requirements.txt

python ip_info_app.py                 # interactive menu
python ip_info_app.py --me            # my public IPv4 + IPv6
python ip_info_app.py --ip 8.8.8.8    # look up any address
python ip_info_app.py --ip 2001:4860:4860::8888
python ip_info_app.py --me --json     # raw JSON
python ip_info_app.py --me --save report.json
```

Run the tests. They work offline because the APIs are mocked:

```bash
python -m unittest discover -s tests -v
```

## Web version (GitHub Pages)

[`docs/index.html`](docs/index.html) is a browser version of the app: one HTML file with no build step and no dependencies. It has the same features as the Python app: your public IPv4/IPv6, details with the ipwho.is fallback, offline address analysis, lookup of any address, a map link, and JSON download. GitHub Pages can only serve static files and can't run Python, so the page calls the same APIs from the browser with JavaScript. Its code uses the same five layers as `ip_info_app.py`.

To try it locally, open `docs/index.html` in a browser. Add `?ip=8.8.8.8` to the URL to look up an address straight away.

To publish it:

1. The repository must be **public**. GitHub Pages on a private repo needs a paid plan.
2. Go to **Settings → Pages → Build and deployment**. Set *Source* to **Deploy from a branch**, *Branch* to **main** and *folder* to **/docs**, then click **Save**.
3. After about a minute the site is live at `https://pollen-gvrrawr.github.io/ipv4-ipv6-address-app/`.

## Code structure (for teams continuing the project)

`ip_info_app.py` is split into five layers. Each layer only calls the one below it:

1. **CONFIG**: API URLs and timeout. To change provider, edit this section.
2. **API layer**: calls the REST APIs and returns *normalised* dicts. Every provider returns the same keys, so adding a new provider means writing one `_from_xxx()` function and adding it to the list in `get_ip_details()`.
3. **Analysis layer**: offline facts from Python's `ipaddress` module.
4. **Display layer**: formatting and printing only.
5. **CLI / menu**: `argparse` flags and the interactive menu.

## Team workflow

* `main` holds the reviewed, working version of the app.
* Each member works on a branch named `feature/<name>-<task>`. They open a **pull request**, another member reviews it, and it is merged into `main`.
* Future work is listed in [BACKLOG.md](BACKLOG.md).

## Team

* Samantha Guevarra
* Sofiagail Lustre
* Gwyneth Fajardo
