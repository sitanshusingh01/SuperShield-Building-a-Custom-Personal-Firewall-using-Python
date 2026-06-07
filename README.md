# SuperShield — Custom Personal Firewall
A Python based personal firewall prototype that demonstrates real time packet monitoring, IP blocking, website filtering, rule-based traffic control, and a live terminal dashboard. Built as a college capstone project to explore network security concepts using open-source tools

---

## Features

- **Live Packet Sniffing** — Captures network packets in real time using Scapy and displays source IP, destination IP, protocol, and packet length
- **IP Blocking** — Maintains a persistent blocklist of IPs and CIDRs; blocked packets are denied and logged immediately
- **Rule Engine** — Modular, extensible rule system supporting per-protocol, per-port, and per-IP filtering
- **Website Blocking** — Redirects domains to localhost via the OS hosts file (requires admin/root)
- **Traffic Logging** — Structured log file with timestamps, source/destination, protocol, and action taken
- **Terminal Dashboard** — Refreshing live view of packet activity, statistics, and top blocked sources
- **Statistics Tracking** — Running totals of packets inspected, allowed, and blocked, broken down by protocol
- **CLI Interface** — Full command-line interface for managing rules, IPs, and websites without editing config files directly

---

## Tech Stack

| Component        | Library / Tool          |
|------------------|-------------------------|
| Packet capture   | Scapy 2.5+              |
| Process info     | psutil                  |
| Logging          | Python `logging` module |
| CLI              | Python `argparse`       |
| Concurrency      | Python `threading`      |
| Config parsing   | Built-in file I/O       |
| Language         | Python 3.9+             |

---

## Project Structure

```
SuperShield/
│
├── main.py                   # Entry point and CLI command definitions
│
├── firewall/
│   ├── __init__.py
│   ├── packet_sniffer.py     # Scapy-based packet capture thread
│   ├── firewall_rules.py     # Rule engine and IP blocklist management
│   ├── logger.py             # Structured file logging
│   ├── blocker.py            # Hosts-file-based website blocker
│   ├── monitor.py            # In-memory statistics and packet history
│   └── utils.py              # IP validation, protocol mapping, helpers
│
├── logs/
│   └── firewall.log          # Generated log output (sample included)
│
├── config/
│   └── blocked_ips.txt       # Persistent IP/CIDR blocklist
│
├── screenshots/              # Demo screenshots (add your own)
│
├── requirements.txt
├── README.md
├── LICENSE
└── .gitignore
```

---

## Installation

### Prerequisites

- Python 3.9 or higher
- pip
- Administrator or root access (required for packet capture and hosts file changes)

### Steps

```bash
# 1. Clone the repository
git clone https://github.com/yourusername/supershield.git
cd supershield

# 2. (Recommended) Create a virtual environment
python -m venv venv
source venv/bin/activate        # On Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# On Linux/macOS you may also need libpcap:
# sudo apt-get install libpcap-dev   (Debian/Ubuntu)
# brew install libpcap               (macOS)
```

---

## Usage

All commands require elevated privileges for live packet capture and hosts file modification.

### Start packet sniffing (verbose mode)

```bash
sudo python main.py sniff --verbose
```

### Start with live terminal dashboard

```bash
sudo python main.py sniff --dashboard
```

### Specify a network interface and BPF filter

```bash
sudo python main.py sniff --iface eth0 --filter "tcp port 80"
```

### Load custom JSON rules file

```bash
sudo python main.py sniff --rules config/rules.json
```

### Manage blocked IPs

```bash
# Block a single IP
python main.py block 203.0.113.50

# Block a CIDR range
python main.py block 10.0.0.0/8

# Unblock an IP
python main.py unblock 203.0.113.50

# List all blocked IPs
python main.py list-blocked
```

### Manage blocked websites (requires root/admin)

```bash
sudo python main.py block-site facebook.com
sudo python main.py block-site youtube.com
sudo python main.py unblock-site facebook.com
sudo python main.py list-sites
```

### List available network interfaces

```bash
python main.py interfaces
```

---

## Custom Rules File (JSON)

Create a `config/rules.json` file to define advanced filtering rules:

```json
[
  {
    "action": "BLOCK",
    "protocol": "ICMP",
    "description": "Block all ICMP ping traffic"
  },
  {
    "action": "BLOCK",
    "dst_ip": "192.168.1.1",
    "port": 23,
    "protocol": "TCP",
    "description": "Block Telnet to gateway"
  },
  {
    "action": "ALLOW",
    "src_ip": "192.168.1.100",
    "description": "Always allow trusted workstation"
  }
]
```

Rules are evaluated top-to-bottom. The first matching rule wins. If no rule matches, the packet is allowed by default.

---

## Log Format

Logs are written to `logs/firewall.log`:

```
2025-04-10 09:00:03 | INFO     | SRC=192.168.1.5       DST=8.8.8.8          PROTO=UDP    ACTION=ALLOW
2025-04-10 09:00:07 | WARNING  | SRC=192.0.2.1         DST=192.168.1.1      PROTO=TCP    ACTION=BLOCK
```

---

## Dashboard Preview

```
=================================================================
  SuperShield — Personal Firewall Monitor
=================================================================
  Uptime : 00:02:34   Log : firewall.log
=================================================================
  Total Packets : 142        Allowed : 119        Blocked : 23
=================================================================
  Protocols : ICMP=8   TCP=97   UDP=37
=================================================================
  Blocked IPs  (3) : 192.0.2.1, 192.0.2.2, 198.51.100.0/24
=================================================================
  Recent Packets:
    [ALLOW]   TCP    192.168.1.5          -> 140.82.121.4         len=74
    [BLOCK]   TCP    192.0.2.1            -> 192.168.1.1          len=60
    [ALLOW]   UDP    192.168.1.8          -> 8.8.8.8              len=83
=================================================================
```

---

## Screenshots

> Add screenshots of your terminal session here after a demo run.

| Dashboard | Blocked Packet Log |
|-----------|-------------------|
| *(screenshot)* | *(screenshot)* |

---

## How It Works

1. **Packet Capture** — `PacketSniffer` launches a background thread using Scapy's `sniff()`. Each captured packet is passed to a callback.
2. **Rule Evaluation** — The callback calls `FirewallRules.evaluate()`, which checks the source IP against the persistent blocklist and then against any custom rules in order.
3. **Logging** — Every packet decision is written to the log file via `FirewallLogger` using Python's standard `logging` module.
4. **Statistics** — `Monitor` keeps a rolling in-memory history and running totals, displayed by the dashboard refresh loop.
5. **Website Blocking** — `Blocker` rewrites the system hosts file to redirect domains to 127.0.0.1, making them unreachable from any browser on the machine.

---

## Future Scope

- GUI dashboard using tkinter or a web-based interface
- Export logs to CSV / JSON for offline analysis
- Suspicious traffic heuristics (port scan detection, flood detection)
- Notification alerts for high-priority block events
- Integration with threat intelligence IP feeds
- Per-application traffic filtering using process IDs from psutil

---

## Important Notes

- Packet sniffing and hosts file modification require **root/Administrator privileges**.
- This project is a **prototype** for educational purposes. It does not replace a production firewall.
- On Windows, Npcap must be installed for Scapy to capture packets: https://npcap.com

---

## Contributors

- Your Name — Core development
- Team Member 2 — Logging and rule engine
- Team Member 3 — Testing and documentation

---

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
