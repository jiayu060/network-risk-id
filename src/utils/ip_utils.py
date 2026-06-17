"""IP address utilities: validation, subnet matching, private/ public detection."""

import ipaddress
from typing import Optional

# RFC 1918 / RFC 6598 / RFC 6890 private ranges
_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),   # CGNAT
    ipaddress.ip_network("169.254.0.0/16"),  # link-local
    ipaddress.ip_network("127.0.0.0/8"),     # loopback
    ipaddress.ip_network("0.0.0.0/8"),       # current network
    ipaddress.ip_network("224.0.0.0/4"),     # multicast
    ipaddress.ip_network("240.0.0.0/4"),     # reserved
]


def is_valid_ip(ip_str: str) -> bool:
    """Check if string is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False


def is_private_ip(ip_str: str) -> bool:
    """Check if IP is in a private/reserved range."""
    try:
        ip = ipaddress.ip_address(ip_str)
        for net in _PRIVATE_NETWORKS:
            if ip in net:
                return True
        return False
    except ValueError:
        return False


def is_internal_ip(ip_str: str) -> bool:
    """Alias for is_private_ip. Handles CIDR notation."""
    if "/" in ip_str:
        try:
            net = ipaddress.ip_network(ip_str, strict=False)
            return is_private_ip(str(net.network_address))
        except ValueError:
            return False
    return is_private_ip(ip_str)


def is_public_ip(ip_str: str) -> bool:
    """Check if IP is a public routable address."""
    return is_valid_ip(ip_str) and not is_private_ip(ip_str)


def ip_in_subnet(ip_str: str, subnet_cidr: str) -> bool:
    """Check if an IP belongs to a given subnet (CIDR notation)."""
    try:
        ip = ipaddress.ip_address(ip_str)
        net = ipaddress.ip_network(subnet_cidr, strict=False)
        return ip in net
    except ValueError:
        return False


def normalize_ip(ip_str: str) -> Optional[str]:
    """Normalize an IP string to its canonical form, or None if invalid."""
    try:
        return str(ipaddress.ip_address(ip_str))
    except ValueError:
        return None


def extract_ips_from_text(text: str) -> list[str]:
    """Extract all valid IPv4 addresses from arbitrary text."""
    import re
    ipv4_re = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    candidates = ipv4_re.findall(text)
    return [c for c in candidates if is_valid_ip(c)]
