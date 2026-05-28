import socket
import re
from typing import Optional


def format_packet_summary(src: str, dst: str, protocol: str, length: int, action: str) -> str:
    action_tag = f"[{action.upper()}]"
    return f"{action_tag:<9} {protocol:<6} {src:<20} -> {dst:<20} len={length}"


def resolve_hostname(ip: str) -> Optional[str]:
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror):
        return None


def is_valid_ip(address: str) -> bool:
    pattern = re.compile(
        r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
    )
    return bool(pattern.match(address))


def is_valid_cidr(cidr: str) -> bool:
    try:
        ip, prefix = cidr.split("/")
        return is_valid_ip(ip) and 0 <= int(prefix) <= 32
    except (ValueError, AttributeError):
        return False


def ip_in_cidr(ip: str, cidr: str) -> bool:
    try:
        import ipaddress
        return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False


def load_config(path: str) -> list:
    entries = []
    try:
        with open(path, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    entries.append(line)
    except FileNotFoundError:
        pass
    return entries


def protocol_number_to_name(proto: int) -> str:
    mapping = {
        1: "ICMP",
        6: "TCP",
        17: "UDP",
        41: "IPv6",
        58: "ICMPv6",
    }
    return mapping.get(proto, str(proto))
