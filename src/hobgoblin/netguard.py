"""Decide whether the proxy may open a connection to an IP address.

The proxy resolves names itself, checks *every* returned address, then
connects to a checked address. That closes the DNS-rebinding gap where a
name resolves to a public address at check time and to 169.254.169.254 at
connect time.
"""

from __future__ import annotations

import ipaddress
from typing import Iterable

IPAddr = ipaddress.IPv4Address | ipaddress.IPv6Address
IPNet = ipaddress.IPv4Network | ipaddress.IPv6Network

# Ranges that is_global does not cover, or that tunnel to other address spaces.
_EXTRA_BLOCKED: tuple[IPNet, ...] = tuple(
    ipaddress.ip_network(n)
    for n in (
        "100.64.0.0/10",  # CGNAT (is_global is already False; explicit for clarity)
        "64:ff9b::/96",  # NAT64 well-known prefix: can reach private IPv4
        "64:ff9b:1::/48",  # local-use NAT64
        "2002::/16",  # 6to4: embeds an arbitrary IPv4
        "2001::/32",  # Teredo
        "224.0.0.0/4",  # multicast
        "ff00::/8",
    )
)


def parse_cidrs(values: Iterable[str]) -> tuple[IPNet, ...]:
    return tuple(ipaddress.ip_network(v.strip(), strict=False) for v in values if v.strip())


def _canonical(ip: IPAddr) -> IPAddr:
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    return ip


def check_ip(
    ip: str | IPAddr,
    allow_cidrs: Iterable[IPNet] = (),
    deny_cidrs: Iterable[IPNet] = (),
) -> tuple[bool, str]:
    """Return (allowed, reason). Order: explicit deny > explicit allow >
    built-in blocks (non-global, NAT64/6to4/Teredo, multicast)."""
    try:
        addr = _canonical(ipaddress.ip_address(ip) if isinstance(ip, str) else ip)
    except ValueError:
        return False, f"not an IP address: {ip!r}"

    for net in deny_cidrs:
        if addr.version == net.version and addr in net:
            return False, f"{addr} is in denied range {net}"
    for net in allow_cidrs:
        if addr.version == net.version and addr in net:
            return True, f"{addr} is in allowed range {net}"
    for net in _EXTRA_BLOCKED:
        if addr.version == net.version and addr in net:
            return False, f"{addr} is in blocked range {net}"
    if not addr.is_global:
        return False, f"{addr} is not a public address"
    return True, "public address"


def check_all(
    ips: Iterable[str],
    allow_cidrs: Iterable[IPNet] = (),
    deny_cidrs: Iterable[IPNet] = (),
) -> tuple[str | None, str]:
    """All addresses must pass; a mixed answer is treated as an attack.
    Returns (first allowed ip, reason) or (None, reason)."""
    allow_cidrs, deny_cidrs = tuple(allow_cidrs), tuple(deny_cidrs)
    ips = list(dict.fromkeys(ips))
    if not ips:
        return None, "name did not resolve"
    for ip in ips:
        ok, why = check_ip(ip, allow_cidrs, deny_cidrs)
        if not ok:
            return None, why
    return ips[0], "all resolved addresses allowed"
