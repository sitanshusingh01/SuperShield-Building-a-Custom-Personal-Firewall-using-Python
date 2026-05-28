import threading
import time
from collections import deque, defaultdict
from dataclasses import dataclass, field
from typing import Deque, Dict, Optional


@dataclass
class PacketRecord:
    src: str
    dst: str
    protocol: str
    length: int
    action: str
    port: Optional[int] = None
    timestamp: float = field(default_factory=time.time)


class Monitor:
    def __init__(self, history_size: int = 200):
        self._lock = threading.Lock()
        self._history: Deque[PacketRecord] = deque(maxlen=history_size)
        self._stats: Dict[str, int] = defaultdict(int)
        self._start_time = time.time()

    def record(
        self,
        src: str,
        dst: str,
        protocol: str,
        length: int,
        action: str,
        port: Optional[int] = None,
    ):
        record = PacketRecord(src, dst, protocol, length, action, port)
        with self._lock:
            self._history.append(record)
            self._stats["total"] += 1
            if action.upper() == "ALLOW":
                self._stats["allowed"] += 1
            else:
                self._stats["blocked"] += 1
            self._stats[f"proto_{protocol}"] += 1

    def get_stats(self) -> dict:
        with self._lock:
            return {
                "total": self._stats["total"],
                "allowed": self._stats["allowed"],
                "blocked": self._stats["blocked"],
                "uptime_seconds": int(time.time() - self._start_time),
                "proto_breakdown": {
                    k.replace("proto_", ""): v
                    for k, v in self._stats.items()
                    if k.startswith("proto_")
                },
            }

    def get_recent(self, n: int = 20) -> list:
        with self._lock:
            return list(self._history)[-n:]

    def get_top_sources(self, n: int = 5) -> list:
        counter: Dict[str, int] = defaultdict(int)
        with self._lock:
            for r in self._history:
                counter[r.src] += 1
        return sorted(counter.items(), key=lambda x: x[1], reverse=True)[:n]

    def get_top_blocked(self, n: int = 5) -> list:
        counter: Dict[str, int] = defaultdict(int)
        with self._lock:
            for r in self._history:
                if r.action.upper() == "BLOCK":
                    counter[r.src] += 1
        return sorted(counter.items(), key=lambda x: x[1], reverse=True)[:n]

    def reset(self):
        with self._lock:
            self._history.clear()
            self._stats.clear()
            self._start_time = time.time()

    def uptime_str(self) -> str:
        elapsed = int(time.time() - self._start_time)
        h, rem = divmod(elapsed, 3600)
        m, s = divmod(rem, 60)
        return f"{h:02d}:{m:02d}:{s:02d}"
