import logging
import os
from datetime import datetime

LOG_PATH = os.path.join(os.path.dirname(__file__), "..", "logs", "firewall.log")


class FirewallLogger:
    def __init__(self, log_path: str = LOG_PATH):
        self.log_path = os.path.abspath(log_path)
        os.makedirs(os.path.dirname(self.log_path), exist_ok=True)

        self._logger = logging.getLogger("supershield")
        self._logger.setLevel(logging.DEBUG)

        if not self._logger.handlers:
            file_handler = logging.FileHandler(self.log_path)
            file_handler.setLevel(logging.DEBUG)
            fmt = logging.Formatter(
                "%(asctime)s | %(levelname)-8s | %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            )
            file_handler.setFormatter(fmt)
            self._logger.addHandler(file_handler)

    def log_packet(self, src: str, dst: str, protocol: str, action: str, extra: str = ""):
        msg = f"SRC={src:<18} DST={dst:<18} PROTO={protocol:<6} ACTION={action}"
        if extra:
            msg += f" | {extra}"
        if action.upper() == "ALLOW":
            self._logger.info(msg)
        else:
            self._logger.warning(msg)

    def log_event(self, message: str):
        self._logger.info(f"[EVENT] {message}")

    def log_error(self, message: str):
        self._logger.error(f"[ERROR] {message}")

    def log_startup(self):
        self._logger.info("=" * 70)
        self._logger.info(f"SuperShield Firewall started at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        self._logger.info("=" * 70)

    def log_shutdown(self, stats: dict):
        self._logger.info("-" * 70)
        self._logger.info(
            f"Session ended | Total={stats.get('total', 0)} "
            f"Allowed={stats.get('allowed', 0)} "
            f"Blocked={stats.get('blocked', 0)}"
        )
        self._logger.info("=" * 70)

    @property
    def path(self) -> str:
        return self.log_path
