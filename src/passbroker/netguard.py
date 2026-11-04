"""Which addresses the broker's browser may never reach: this PC, LANs, tailnets."""

from __future__ import annotations

import ipaddress

BLOCKED_SUFFIXES = (".local", ".localhost", ".internal", ".lan", ".home.arpa", ".ts.net", ".beta.tailscale.net")


def _private(ip: str) -> bool:
    addr = ipaddress.ip_address(ip.split("%")[0])
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    cgnat = isinstance(addr, ipaddress.IPv4Address) and addr in ipaddress.ip_network("100.64.0.0/10")
    return addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast or addr.is_reserved or addr.is_unspecified or cgnat
