# Backlog: future enhancements (for Project Activity 4)

Items are in priority order (P1 is highest).

| Priority | Item | Why |
|----------|------|-----|
| P1 | **Local network info**: show the private IP, subnet mask, default gateway and DNS servers next to the public IP | Technicians usually need public and private addressing together |
| P1 | **Subnet calculator**: enter `192.168.1.0/26` and get the network/broadcast address, usable host range and host count (IPv4 and IPv6) | A frequent technician task, and it reuses the `ipaddress` module |
| Done | ~~**Graphical interface**~~: web UI in `docs/index.html`, hosted on GitHub Pages | Easier for non-CLI users |
| P2 | **Batch lookup**: read a list of IPs from a .txt/.csv file and export the results to CSV | Useful when checking firewall or log entries |
| P2 | **Reverse DNS / WHOIS lookup** (hostname of an IP, network owner) | Fuller troubleshooting picture |
| P3 | **Connectivity tests**: ping and traceroute to a chosen IP, with an IPv6 readiness check | Shows whether IPv6 really works end-to-end |
| P3 | **History**: keep a log of past lookups and detect when the public IP changes | Helps track dynamic IP changes from an ISP |
| P3 | **Caching and API-key support** (ipapi.co paid key, ipstack) | Avoids free-tier rate limits |
| P3 | Package as a standalone `.exe` with PyInstaller | Technicians can run it without installing Python |
