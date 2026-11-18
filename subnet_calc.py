"""
IPeek subnet calculator (backlog item B02)
==========================================

Works out the details of an IPv4 or IPv6 network from CIDR notation, for
example 192.168.1.0/26 or 2001:db8:abcd:12::/64. It only uses Python's
built-in ipaddress module, so it needs no internet.

Used by the CLI in ip_info_app.py (--subnet and menu option 4).
"""

import ipaddress


def calculate_subnet(text):
    """Return a dict describing the network written in text.

    Accepts "192.168.1.0/26", "192.168.1.0 255.255.255.192" (address and
    mask) or "2001:db8::/64". A host address with a prefix, such as
    192.168.1.77/26, is allowed: the result describes the network it is in.
    Raises ValueError if the text is not a valid network.
    """
    cleaned = "/".join(text.split())          # "addr mask" -> "addr/mask"
    if "/" not in cleaned:
        raise ValueError("add a prefix length, for example 192.168.1.0/24")
    net = ipaddress.ip_network(cleaned, strict=False)
    given = ipaddress.ip_address(cleaned.split("/")[0])

    info = {
        "input": text.strip(),
        "version": f"IPv{net.version}",
        "network": str(net),
        "network_address": str(net.network_address),
        "prefix_length": net.prefixlen,
        "total_addresses": net.num_addresses,
    }
    if given != net.network_address:
        info["host_given"] = str(given)

    if net.version == 4:
        info["subnet_mask"] = str(net.netmask)
        info["wildcard_mask"] = str(net.hostmask)
        info["broadcast_address"] = str(net.broadcast_address)
        if net.prefixlen <= 30:
            # The network and broadcast addresses cannot be given to hosts.
            info["usable_hosts"] = net.num_addresses - 2
            info["first_host"] = str(net.network_address + 1)
            info["last_host"] = str(net.broadcast_address - 1)
        else:
            # /31 point-to-point links (RFC 3021) use both addresses; /32 is one host.
            info["usable_hosts"] = net.num_addresses
            info["first_host"] = str(net.network_address)
            info["last_host"] = str(net.broadcast_address)
    else:
        # IPv6 has no broadcast address, so every address in the range is usable.
        info["usable_hosts"] = net.num_addresses
        info["first_host"] = str(net.network_address)
        info["last_host"] = str(net.broadcast_address)
        info["expanded_network"] = net.network_address.exploded
    return info


def subnet_rows(info):
    """Turn a calculate_subnet() dict into (label, value) rows for display."""
    rows = [("Network", info["network"]), ("Version", info["version"])]
    if "host_given" in info:
        rows.append(("Address you entered", info["host_given"]))
    if info["version"] == "IPv4":
        rows += [("Subnet mask", info["subnet_mask"]),
                 ("Wildcard mask", info["wildcard_mask"]),
                 ("Broadcast address", info["broadcast_address"])]
    else:
        rows.append(("Expanded network", info["expanded_network"]))
    rows += [("First usable", info["first_host"]),
             ("Last usable", info["last_host"]),
             ("Usable hosts", f"{info['usable_hosts']:,}"),
             ("Total addresses", f"{info['total_addresses']:,}")]
    return rows
