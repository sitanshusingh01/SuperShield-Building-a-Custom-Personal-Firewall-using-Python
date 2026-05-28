import threading
from typing import Callable, Optional

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, get_if_list
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

from .utils import protocol_number_to_name


class PacketSniffer:
    def __init__(
        self,
        iface: Optional[str] = None,
        packet_callback: Optional[Callable] = None,
        filter_expr: str = "ip",
    ):
        self.iface = iface
        self.packet_callback = packet_callback
        self.filter_expr = filter_expr
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def _process_packet(self, packet):
        if self._stop_event.is_set():
            return

        if not SCAPY_AVAILABLE:
            return

        if IP not in packet:
            return

        src = packet[IP].src
        dst = packet[IP].dst
        proto_num = packet[IP].proto
        protocol = protocol_number_to_name(proto_num)
        length = len(packet)
        port = None

        if TCP in packet:
            port = packet[TCP].dport
        elif UDP in packet:
            port = packet[UDP].dport

        summary = packet.summary()

        if self.packet_callback:
            self.packet_callback(
                src=src,
                dst=dst,
                protocol=protocol,
                length=length,
                port=port,
                summary=summary,
            )

    def start(self):
        if not SCAPY_AVAILABLE:
            raise RuntimeError(
                "Scapy is not installed. Install it with: pip install scapy"
            )

        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run, daemon=True, name="PacketSniffer"
        )
        self._thread.start()

    def _run(self):
        sniff(
            iface=self.iface,
            filter=self.filter_expr,
            prn=self._process_packet,
            store=False,
            stop_filter=lambda _: self._stop_event.is_set(),
        )

    def stop(self):
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3)

    @staticmethod
    def list_interfaces() -> list:
        if not SCAPY_AVAILABLE:
            return []
        return get_if_list()

    @property
    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()
