"""
IPeek reverse DNS / WHOIS lookup (backlog item: Reverse DNS / WHOIS lookup)
==========================================================================

For one IP address it answers two troubleshooting questions:

    * What is its hostname?  A real reverse DNS (PTR) lookup through the
      computer's DNS resolver, plus a forward-confirmation check: does the
      hostname resolve back to the same IP? (A mismatch is common for spoofed
      or badly configured mail servers.) The main report only shows the PTR
      *name* (e.g. 8.8.8.8.in-addr.arpa); this module actually queries it.
    * Who owns the network?  WHOIS data through RDAP, the JSON successor of
      WHOIS run by the regional internet registries (ARIN, RIPE NCC, APNIC,
      LACNIC, AFRINIC). rdap.org redirects each query to the right registry,
      so no API key or extra package is needed. It shows the network name,
      IP range (CIDR), owner organisation, abuse contact and dates.

Private, loopback and other non-public addresses have no public WHOIS record,
so only the reverse DNS lookup runs for them (a local DNS server may still
know their hostname).

Used by the CLI in ip_info_app.py (--whois and menu option 10) and by the
"Reverse DNS / WHOIS" tab in gui_app.py. Personal contact names in the RDAP
data are not shown, only the owner organisation and its abuse e-mail.
"""

import ipaddress
import socket
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout

import requests

RDAP_URL = "https://rdap.org/ip/{ip}"
RDAP_TIMEOUT = 10          # seconds; rdap.org redirects to the registry
DNS_TIMEOUT = 5            # seconds for each DNS lookup
USER_AGENT = "ipeek-rdap"

REGISTRIES = {"whois.arin.net": "ARIN (North America)",
              "whois.ripe.net": "RIPE NCC (Europe, Middle East, Central Asia)",
              "whois.apnic.net": "APNIC (Asia-Pacific)",
              "whois.lacnic.net": "LACNIC (Latin America, Caribbean)",
              "whois.afrinic.net": "AFRINIC (Africa)",
              "whois.registro.br": "NIC.br (Brazil, part of LACNIC)"}


# ---------------------------------------------------------------------------
# Reverse DNS
# ---------------------------------------------------------------------------
def _with_timeout(func, *args, timeout=DNS_TIMEOUT):
    """Run a blocking socket call, giving up after timeout seconds.

    socket.gethostbyaddr() has no timeout of its own, so it runs in a worker
    thread; if it is too slow the result is abandoned.
    """
    pool = ThreadPoolExecutor(max_workers=1)
    try:
        return pool.submit(func, *args).result(timeout=timeout)
    finally:
        pool.shutdown(wait=False)


def reverse_dns(ip):
    """PTR lookup for ip, with forward confirmation.

    Returns a dict: hostname (or None), aliases, forward_confirmed
    (True/False, or None if there is no hostname or it could not be checked)
    and error (or None).
    """
    result = {"hostname": None, "aliases": [], "forward_confirmed": None, "error": None}
    try:
        hostname, aliases, _ = _with_timeout(socket.gethostbyaddr, ip)
    except socket.herror:
        result["error"] = "no PTR record: this address has no hostname"
        return result
    except FutureTimeout:
        result["error"] = f"DNS did not answer within {DNS_TIMEOUT} s"
        return result
    except OSError as exc:
        result["error"] = f"DNS lookup failed: {exc}"
        return result
    result["hostname"], result["aliases"] = hostname, list(aliases)
    result["forward_confirmed"] = forward_confirms(hostname, ip)
    return result


def forward_confirms(hostname, ip):
    """Does hostname resolve back to ip (forward-confirmed reverse DNS)?

    Returns True or False, or None when it cannot be checked: on a network
    without IPv6, Windows will not look up IPv6 (AAAA) addresses at all, so
    an IPv6 address can't be confirmed there.
    """
    wanted = ipaddress.ip_address(ip)
    family = socket.AF_INET6 if wanted.version == 6 else socket.AF_INET
    try:
        infos = _with_timeout(socket.getaddrinfo, hostname, None, family)
    except socket.gaierror:
        return None if wanted.version == 6 else False
    except (OSError, FutureTimeout):
        return None
    for info in infos:
        try:
            if ipaddress.ip_address(info[4][0].split("%")[0]) == wanted:
                return True
        except ValueError:
            continue
    return False


# ---------------------------------------------------------------------------
# WHOIS (RDAP)
# ---------------------------------------------------------------------------
def _vcard(entity, field):
    """Values of one vCard field (e.g. 'fn', 'email', 'kind') of an RDAP entity."""
    vcard = (entity.get("vcardArray") or [None, []])[1]
    return [item[3] for item in vcard if len(item) > 3 and item[0] == field]


def _walk(entities):
    """Every entity, top level first, then the ones nested inside them."""
    queue = list(entities or [])
    while queue:
        entity = queue.pop(0)
        yield entity
        queue.extend(entity.get("entities") or [])


def parse_rdap(data):
    """Turn an RDAP IP-network response into a flat dict for display."""
    entities = list(_walk(data.get("entities")))
    registrants = [e for e in entities if "registrant" in e.get("roles", [])]
    # prefer an organisation over a maintainer/individual record
    owner = next((e for e in registrants if "org" in _vcard(e, "kind")),
                 registrants[0] if registrants else None)
    abuse = next((e for e in entities if "abuse" in e.get("roles", []) and _vcard(e, "email")),
                 None)
    events = {e.get("eventAction"): (e.get("eventDate") or "")[:10]
              for e in data.get("events", [])}
    cidrs = [f"{c.get('v4prefix') or c.get('v6prefix')}/{c['length']}"
             for c in data.get("cidr0_cidrs", []) if "length" in c]
    start, end = data.get("startAddress"), data.get("endAddress")
    port43 = data.get("port43") or ""
    return {
        "network_name": data.get("name"),
        "handle": data.get("handle"),
        "range": f"{start} - {end}" if start and end else None,
        "cidr": ", ".join(cidrs) or None,
        "type": data.get("type"),
        "owner": _vcard(owner, "fn")[0] if owner and _vcard(owner, "fn") else None,
        "owner_handle": owner.get("handle") if owner else None,
        "country": data.get("country"),
        "abuse_email": _vcard(abuse, "email")[0] if abuse else None,
        "registered": events.get("registration"),
        "last_changed": events.get("last changed"),
        "registry": REGISTRIES.get(port43, port43 or None),
    }


def whois(ip):
    """RDAP lookup for a public ip. Returns parse_rdap() dict plus 'source'.

    Raises requests.RequestException or ValueError on failure.
    """
    response = requests.get(RDAP_URL.format(ip=ip), timeout=RDAP_TIMEOUT,
                            headers={"Accept": "application/rdap+json",
                                     "User-Agent": USER_AGENT})
    if response.status_code == 404:
        raise ValueError("no WHOIS record found for this address")
    if response.status_code == 429:
        raise ValueError("the registry is rate-limiting requests; try again in a minute")
    response.raise_for_status()
    info = parse_rdap(response.json())
    info["source"] = response.url            # the registry rdap.org redirected to
    return info


class WhoisCache:
    """Remembers WHOIS answers by IP range, for batch lookups.

    One RDAP answer covers a whole network (e.g. 8.8.8.0 - 8.8.8.255), so
    other addresses in that range reuse it instead of asking the registry
    again. That keeps a long batch fast and under the registries' rate limits.
    """

    def __init__(self):
        self._ranges = []                    # (first address, last address, info)

    def get(self, ip):
        addr = ipaddress.ip_address(ip)
        for first, last, info in self._ranges:
            if first.version == addr.version and first <= addr <= last:
                return dict(info)
        return None

    def add(self, info):
        try:
            first, last = (ipaddress.ip_address(p) for p in info["range"].split(" - "))
        except (AttributeError, ValueError):     # no usable range in the answer
            return
        self._ranges.append((first, last, dict(info)))


# ---------------------------------------------------------------------------
# Both together
# ---------------------------------------------------------------------------
def lookup(text, cache=None):
    """Reverse DNS + WHOIS for an IPv4/IPv6 address. Raises ValueError if invalid.

    cache, a WhoisCache, is used by batch lookups to reuse WHOIS answers for
    addresses in a network that was already looked up.
    """
    addr = ipaddress.ip_address(text.strip())
    ip = str(addr)
    result = {"ip": ip, "ptr_name": addr.reverse_pointer, "dns": reverse_dns(ip)}
    if not addr.is_global:
        result["whois_error"] = "not a public address, so it has no public WHOIS record"
        return result
    cached = cache.get(ip) if cache is not None else None
    if cached is not None:
        result["whois"] = cached
        return result
    try:
        result["whois"] = whois(ip)
        if cache is not None:
            cache.add(result["whois"])
    except requests.ConnectionError:
        result["whois_error"] = "could not reach rdap.org (check the internet connection)"
    except requests.Timeout:
        result["whois_error"] = f"the registry did not answer within {RDAP_TIMEOUT} s"
    except (requests.RequestException, ValueError) as exc:
        result["whois_error"] = str(exc)
    return result


FORWARD_TEXT = {
    True: "yes, the hostname resolves back to this IP",
    False: "no, the hostname does not resolve back to this IP",
    None: "could not check from this network (for IPv6: the network has no IPv6)",
}


def lookup_rows(result):
    """Turn a lookup() dict into (kind, label, value) rows.

    kind is 'title', 'head', 'row', 'error' or 'note', the same row kinds the
    GUI's report pane and the CLI already use.
    """
    dns = result["dns"]
    rows = [("title", f"Reverse DNS / WHOIS: {result['ip']}", ""),
            ("head", "Reverse DNS (hostname)", ""),
            ("row", "PTR name", result["ptr_name"])]
    if dns["hostname"]:
        rows.append(("row", "Hostname", dns["hostname"]))
        if dns["aliases"]:
            rows.append(("row", "Other names", ", ".join(dns["aliases"])))
        rows.append(("row", "Forward-confirmed", FORWARD_TEXT[dns["forward_confirmed"]]))
    else:
        rows.append(("error", "", dns["error"]))

    rows.append(("head", "WHOIS (network owner)", ""))
    if "whois" not in result:
        rows.append(("error", "", result["whois_error"]))
        return rows
    w = result["whois"]
    rows += [("row", "Owner", w["owner"]),
             ("row", "Network name", w["network_name"]),
             ("row", "IP range", w["range"]),
             ("row", "CIDR", w["cidr"]),
             ("row", "Allocation type", w["type"]),
             ("row", "Country", w["country"]),
             ("row", "Abuse contact", w["abuse_email"]),
             ("row", "Registered", w["registered"]),
             ("row", "Last changed", w["last_changed"]),
             ("row", "Registry", w["registry"]),
             ("note", "", f"data source: {w['source']}")]
    return rows
