import os
import platform
import ctypes
from typing import List

HOSTS_PATH_WINDOWS = r"C:\Windows\System32\drivers\etc\hosts"
HOSTS_PATH_UNIX = "/etc/hosts"
REDIRECT_IP = "127.0.0.1"


def _get_hosts_path() -> str:
    if platform.system() == "Windows":
        return HOSTS_PATH_WINDOWS
    return HOSTS_PATH_UNIX


def _is_admin() -> bool:
    try:
        if platform.system() == "Windows":
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        return os.geteuid() == 0
    except AttributeError:
        return False


class Blocker:
    def __init__(self, hosts_path: str = None):
        self.hosts_path = hosts_path or _get_hosts_path()
        self._marker_start = "# SuperShield BEGIN"
        self._marker_end = "# SuperShield END"

    def _read_hosts(self) -> str:
        try:
            with open(self.hosts_path, "r") as f:
                return f.read()
        except (PermissionError, FileNotFoundError) as e:
            raise RuntimeError(f"Cannot read hosts file: {e}")

    def _write_hosts(self, content: str):
        try:
            with open(self.hosts_path, "w") as f:
                f.write(content)
        except PermissionError:
            raise RuntimeError(
                "Permission denied. Run SuperShield with administrator/root privileges to modify the hosts file."
            )

    def _extract_managed_section(self, content: str) -> List[str]:
        lines = []
        inside = False
        for line in content.splitlines():
            if line.strip() == self._marker_start:
                inside = True
                continue
            if line.strip() == self._marker_end:
                inside = False
                continue
            if inside:
                lines.append(line)
        return lines

    def _remove_managed_section(self, content: str) -> str:
        result = []
        inside = False
        for line in content.splitlines(keepends=True):
            if line.strip() == self._marker_start:
                inside = True
                continue
            if line.strip() == self._marker_end:
                inside = False
                continue
            if not inside:
                result.append(line)
        return "".join(result)

    def block_website(self, domain: str) -> bool:
        if not _is_admin():
            raise RuntimeError("Root/Administrator privileges are required to modify the hosts file.")
        content = self._read_hosts()
        managed = self._extract_managed_section(content)
        entry = f"{REDIRECT_IP} {domain}"
        www_entry = f"{REDIRECT_IP} www.{domain}"
        if entry in managed:
            return False

        managed.append(entry)
        if www_entry not in managed:
            managed.append(www_entry)

        base = self._remove_managed_section(content).rstrip("\n")
        new_content = (
            base + "\n\n"
            + self._marker_start + "\n"
            + "\n".join(managed) + "\n"
            + self._marker_end + "\n"
        )
        self._write_hosts(new_content)
        return True

    def unblock_website(self, domain: str) -> bool:
        if not _is_admin():
            raise RuntimeError("Root/Administrator privileges are required to modify the hosts file.")
        content = self._read_hosts()
        managed = self._extract_managed_section(content)
        entry = f"{REDIRECT_IP} {domain}"
        www_entry = f"{REDIRECT_IP} www.{domain}"
        original_len = len(managed)
        managed = [l for l in managed if l not in (entry, www_entry)]
        if len(managed) == original_len:
            return False

        base = self._remove_managed_section(content).rstrip("\n")
        if managed:
            new_content = (
                base + "\n\n"
                + self._marker_start + "\n"
                + "\n".join(managed) + "\n"
                + self._marker_end + "\n"
            )
        else:
            new_content = base + "\n"
        self._write_hosts(new_content)
        return True

    def list_blocked_websites(self) -> List[str]:
        try:
            content = self._read_hosts()
        except RuntimeError:
            return []
        managed = self._extract_managed_section(content)
        domains = []
        for line in managed:
            parts = line.split()
            if len(parts) == 2 and parts[0] == REDIRECT_IP:
                domain = parts[1]
                if not domain.startswith("www."):
                    domains.append(domain)
        return domains

    def unblock_all(self):
        if not _is_admin():
            raise RuntimeError("Root/Administrator privileges are required to modify the hosts file.")
        content = self._read_hosts()
        base = self._remove_managed_section(content).rstrip("\n")
        self._write_hosts(base + "\n")
