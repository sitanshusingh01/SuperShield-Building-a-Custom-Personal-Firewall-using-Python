from dataclasses import dataclass, field
from typing import List, Optional
from .utils import is_valid_ip, is_valid_cidr, ip_in_cidr, load_config


@dataclass
class Rule:
    action: str
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    protocol: Optional[str] = None
    port: Optional[int] = None
    description: str = ""

    def matches(self, src: str, dst: str, protocol: str, port: Optional[int] = None) -> bool:
        if self.src_ip:
            if "/" in self.src_ip:
                if not ip_in_cidr(src, self.src_ip):
                    return False
            elif src != self.src_ip:
                return False

        if self.dst_ip:
            if "/" in self.dst_ip:
                if not ip_in_cidr(dst, self.dst_ip):
                    return False
            elif dst != self.dst_ip:
                return False

        if self.protocol and self.protocol.upper() != protocol.upper():
            return False

        if self.port is not None and port != self.port:
            return False

        return True


class FirewallRules:
    def __init__(self, blocked_ips_path: str = "config/blocked_ips.txt"):
        self._rules: List[Rule] = []
        self._blocked_ips: set = set()
        self._blocked_ip_path = blocked_ips_path
        self._load_blocked_ips()

    def _load_blocked_ips(self):
        entries = load_config(self._blocked_ip_path)
        for entry in entries:
            if is_valid_ip(entry) or is_valid_cidr(entry):
                self._blocked_ips.add(entry)

    def add_rule(self, rule: Rule):
        self._rules.append(rule)

    def block_ip(self, ip: str) -> bool:
        if is_valid_ip(ip) or is_valid_cidr(ip):
            self._blocked_ips.add(ip)
            self._persist_blocked_ips()
            return True
        return False

    def unblock_ip(self, ip: str) -> bool:
        if ip in self._blocked_ips:
            self._blocked_ips.discard(ip)
            self._persist_blocked_ips()
            return True
        return False

    def _persist_blocked_ips(self):
        try:
            with open(self._blocked_ip_path, "w") as f:
                f.write("# SuperShield blocked IPs / CIDRs\n")
                for ip in sorted(self._blocked_ips):
                    f.write(ip + "\n")
        except OSError:
            pass

    def evaluate(self, src: str, dst: str, protocol: str, port: Optional[int] = None) -> str:
        for ip in self._blocked_ips:
            if "/" in ip:
                if ip_in_cidr(src, ip):
                    return "BLOCK"
            elif src == ip:
                return "BLOCK"

        for rule in self._rules:
            if rule.matches(src, dst, protocol, port):
                return rule.action.upper()

        return "ALLOW"

    def list_blocked_ips(self) -> List[str]:
        return sorted(self._blocked_ips)

    def list_rules(self) -> List[Rule]:
        return list(self._rules)

    def clear_rules(self):
        self._rules.clear()

    def load_rules_from_list(self, rules: List[dict]):
        for r in rules:
            self._rules.append(
                Rule(
                    action=r.get("action", "ALLOW"),
                    src_ip=r.get("src_ip"),
                    dst_ip=r.get("dst_ip"),
                    protocol=r.get("protocol"),
                    port=r.get("port"),
                    description=r.get("description", ""),
                )
            )
