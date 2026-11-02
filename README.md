# IPv4/IPv6 Address Application

DEVASC Project Activity 3 (Option 2): a Python prototype that shows a computer's public IPv4/IPv6 addressing information for network technicians.

Team: Samantha Guevarra, Sofia Gail Lustre, Gwyneth Odrajaf

## Features

- **Public addresses**: finds this computer's public IPv4 and IPv6. If there is no IPv6 connectivity, it shows "No public IPv6 available" instead of an error.
- **ISP and location lookup** for any public IP: ISP/organisation, ASN, country, region, city, postal code, coordinates, timezone and a Google Maps link.
- **Automatic fallback**: if ipapi.co fails or is rate-limited, the app uses ipwho.is. Results from both services use the same field names.
- **Offline analysis** with Python's `ipaddress` module:
  - version (4 or 6) and scope (Public, Private, Loopback, Link-local, Multicast, ...)
  - IPv4 class (A–E) and dotted binary form
  - IPv6 compressed and expanded forms
  - reverse DNS name (`in-addr.arpa` / `ip6.arpa`)
- **No API calls for private addresses**: private, loopback and other non-public addresses are analysed locally only.
- **Two ways to use it**: an interactive menu, or command-line options for scripting.
- **JSON output and saving** with `--json` and `--save`.
- **Robust**: invalid input is validated, and network errors, timeouts and API errors never crash the app.

## APIs used

| API | URL | Purpose |
|---|---|---|
| ipify (IPv4) | `https://api.ipify.org?format=json` | Public IPv4 address |
| ipify (IPv6) | `https://api6.ipify.org?format=json` | Public IPv6 address |
| ipapi.co | `https://ipapi.co/<ip>/json/` | IP details (primary) |
| ipwho.is | `https://ipwho.is/<ip>` | IP details (fallback) |

None of these APIs needs an API key. ipapi.co's free tier has a daily request limit. When the limit is reached, the app falls back to ipwho.is automatically.

## Installation

Requires Python 3.8 or newer.

```bash
git clone <repo-url>
cd ipv4-ipv6-address-app
python -m venv venv
venv\Scripts\activate          # Windows
# source venv/bin/activate     # macOS/Linux
pip install -r requirements.txt
```

## Running

```bash
python ip_info_app.py                          # interactive menu
python ip_info_app.py --me                     # this computer's public IPv4/IPv6
python ip_info_app.py --ip 8.8.8.8             # look up an IPv4 address
python ip_info_app.py --ip 2001:4860:4860::8888
python ip_info_app.py --ip 192.168.1.10        # private: offline analysis only
python ip_info_app.py --me --json              # JSON output
python ip_info_app.py --ip 1.1.1.1 --save report.json
python ip_info_app.py --help
```

Menu options:

```
1) Show my public IPv4/IPv6 details
2) Look up an IP address
3) Analyse an IP address offline (no API calls)
4) Save last result to a JSON file
0) Exit
```

Exit codes: `0` success, `1` network failure (no public IP found) or save error, `2` invalid address.

## Tests

The tests use `unittest` and `unittest.mock`. They replace every network call, so they run offline and finish in under a second.

```bash
python -m unittest discover -v
```

They cover the offline analysis, the ipapi.co → ipwho.is fallback, normalisation of both providers' responses, network errors, the IPv6-unavailable case, the CLI options, saving to a file and the interactive menu.

## Code structure

```
ip_info_app.py            # the application, split into 5 layers
tests/test_ip_info_app.py # offline unit tests
requirements.txt          # requests, colorama
BACKLOG.md                # prioritised future enhancements
```

`ip_info_app.py` is divided into five sections, each marked with a `LAYER n` banner comment:

| Layer | Responsibility | Key functions |
|---|---|---|
| 1. Config | API URLs, timeout, constants | `IPV4_URL`, `IPAPI_URL`, `TIMEOUT` |
| 2. API | All network calls; returns `None` instead of raising | `fetch_json`, `get_public_ipv4/6`, `get_ip_details`, `normalise_ipapi/ipwhois` |
| 3. Analysis | Offline analysis with `ipaddress` | `parse_ip`, `get_scope`, `get_ipv4_class`, `analyse_ip` |
| 4. Display | Coloured, aligned output (colorama), JSON, saving | `print_report`, `print_my_report`, `to_json`, `save_json` |
| 5. CLI | Report building, argparse, menu, `main()` | `build_report`, `parse_args`, `run_menu`, `main` |

Data flows in one direction: **CLI → API + Analysis → Display**. Only the API layer talks to the network, and only the Display layer formats output.

## Team workflow

Each member owns one part of the code and works on their own branch:

| Part | Layers | Branch | Tests |
|---|---|---|---|
| Member 1 | 1. Config + 2. API | `feature/api` | `TestApi` |
| Member 2 | 3. Analysis | `feature/analysis` | `TestAnalysis` |
| Member 3 | 4. Display + 5. CLI | `feature/display-cli` | `TestCli` |

Workflow:

1. Update `main` before starting: `git checkout main && git pull`
2. Create your branch: `git checkout -b feature/<part>`
3. Edit **only your own layer's section** of `ip_info_app.py` (and its test class). Because the sections don't overlap, Git can merge the branches without conflicts.
4. Run `python -m unittest discover -v` before every commit. All tests must pass.
5. Commit in small steps with clear messages, e.g. `api: add ipwho.is fallback`.
6. Push and open a pull request into `main`. Another team member reviews it before merging.
7. If you need to change a function signature another layer uses, agree on it with that layer's owner first.
