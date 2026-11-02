# Backlog

Future enhancements in priority order. Owner = the layer/branch that would do the work (see the README's team workflow).

## High priority

| # | Enhancement | Owner | Notes |
|---|---|---|---|
| 1 | Show the local (LAN) IPv4/IPv6 addresses next to the public ones | API / Analysis | Use `socket` to find the outbound interface address, then show it as Private/Public |
| 2 | Real reverse DNS (PTR) lookup | Analysis | Today we show the `in-addr.arpa` name only. Add an optional `socket.gethostbyaddr()` call with a timeout |
| 3 | `--no-color` flag and automatic plain output when stdout isn't a terminal | Display | Keeps redirected text output free of ANSI codes |
| 4 | Retry with backoff for failed requests | API | One retry for timeouts before falling back |
| 5 | Subnet/CIDR input (e.g. `192.168.1.0/24`) | Analysis | Network, broadcast, mask, wildcard, host range, host count |

## Medium priority

| # | Enhancement | Owner | Notes |
|---|---|---|---|
| 6 | Look up several addresses at once (`--ip` repeated or `--file ips.txt`) | CLI | Output a table, or a JSON list |
| 7 | CSV export (`--save report.csv`) | Display | Choose the format from the file extension |
| 8 | Cache API results for a few minutes | API | Avoids ipapi.co rate limits during demos |
| 9 | Optional API keys from environment variables | Config | ipapi.co paid tier, ipinfo.io as a third provider |
| 10 | Show which special-purpose range a reserved address belongs to | Analysis | e.g. CGNAT 100.64.0.0/10, documentation 192.0.2.0/24 |

## Low priority

| # | Enhancement | Owner | Notes |
|---|---|---|---|
| 11 | Split `ip_info_app.py` into a package (`config.py`, `api.py`, ...) | All | Do this once the layers have stabilised |
| 12 | GitHub Actions CI that runs the unit tests on every pull request | All | |
| 13 | Simple web UI (Flask) using the same API/analysis layers | Display / CLI | |
| 14 | IPv6 address-type details (EUI-64, 6to4, Teredo, IPv4-mapped) | Analysis | `ipaddress` has `sixtofour`, `teredo`, `ipv4_mapped` |
| 15 | Docker image | All | |
