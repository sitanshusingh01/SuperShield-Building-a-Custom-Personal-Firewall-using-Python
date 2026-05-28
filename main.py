#!/usr/bin/env python3

import argparse
import os
import sys
import time
import signal
import threading
import json

from firewall.firewall_rules import FirewallRules, Rule
from firewall.packet_sniffer import PacketSniffer, SCAPY_AVAILABLE
from firewall.logger import FirewallLogger
from firewall.blocker import Blocker
from firewall.monitor import Monitor
from firewall.utils import format_packet_summary

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
BLOCKED_IPS_PATH = os.path.join(BASE_DIR, "config", "blocked_ips.txt")
LOG_PATH = os.path.join(BASE_DIR, "logs", "firewall.log")

_shutdown = threading.Event()


def handle_signal(signum, frame):
    print("\n[!] Shutdown signal received. Stopping SuperShield...")
    _shutdown.set()


def build_packet_handler(rules: FirewallRules, logger: FirewallLogger, monitor: Monitor, verbose: bool):
    def on_packet(src, dst, protocol, length, port, summary):
        action = rules.evaluate(src, dst, protocol, port)
        monitor.record(src, dst, protocol, length, action, port)
        logger.log_packet(src, dst, protocol, action)

        if verbose or action == "BLOCK":
            line = format_packet_summary(src, dst, protocol, length, action)
            print(line)

    return on_packet


def print_dashboard(monitor: Monitor, logger: FirewallLogger, rules: FirewallRules):
    os.system("cls" if os.name == "nt" else "clear")
    stats = monitor.get_stats()
    uptime = monitor.uptime_str()

    separator = "=" * 65

    print(separator)
    print("  SuperShield — Personal Firewall Monitor")
    print(separator)
    print(f"  Uptime : {uptime}   Log : {os.path.basename(logger.path)}")
    print(separator)
    print(f"  Total Packets : {stats['total']:<10} "
          f"Allowed : {stats['allowed']:<10} "
          f"Blocked : {stats['blocked']}")
    print(separator)

    breakdown = stats.get("proto_breakdown", {})
    if breakdown:
        proto_str = "  Protocols : " + "  ".join(
            f"{k}={v}" for k, v in sorted(breakdown.items())
        )
        print(proto_str)
        print(separator)

    blocked_ips = rules.list_blocked_ips()
    print(f"  Blocked IPs  ({len(blocked_ips)}) : {', '.join(blocked_ips[:6]) or 'none'}")
    print(separator)

    print("  Recent Packets:")
    recent = monitor.get_recent(15)
    if not recent:
        print("    Waiting for traffic...")
    else:
        for r in reversed(recent):
            line = format_packet_summary(r.src, r.dst, r.protocol, r.length, r.action)
            print(f"    {line}")

    print(separator)

    top_blocked = monitor.get_top_blocked(3)
    if top_blocked:
        print("  Top Blocked Sources:")
        for ip, count in top_blocked:
            print(f"    {ip:<20} {count} packets blocked")
        print(separator)

    print("  [Ctrl+C to stop]")


def run_dashboard_loop(monitor: Monitor, logger: FirewallLogger, rules: FirewallRules, interval: float = 1.5):
    while not _shutdown.is_set():
        print_dashboard(monitor, logger, rules)
        time.sleep(interval)


def cmd_block_ip(args):
    rules = FirewallRules(blocked_ips_path=BLOCKED_IPS_PATH)
    if rules.block_ip(args.ip):
        print(f"[+] {args.ip} added to blocklist.")
    else:
        print(f"[-] Invalid IP address: {args.ip}")


def cmd_unblock_ip(args):
    rules = FirewallRules(blocked_ips_path=BLOCKED_IPS_PATH)
    if rules.unblock_ip(args.ip):
        print(f"[+] {args.ip} removed from blocklist.")
    else:
        print(f"[-] {args.ip} was not in the blocklist.")


def cmd_list_blocked(args):
    rules = FirewallRules(blocked_ips_path=BLOCKED_IPS_PATH)
    ips = rules.list_blocked_ips()
    if ips:
        print("Blocked IPs:")
        for ip in ips:
            print(f"  {ip}")
    else:
        print("No IPs are currently blocked.")


def cmd_block_site(args):
    blocker = Blocker()
    try:
        if blocker.block_website(args.domain):
            print(f"[+] {args.domain} has been blocked.")
        else:
            print(f"[-] {args.domain} is already blocked.")
    except RuntimeError as e:
        print(f"[!] {e}")


def cmd_unblock_site(args):
    blocker = Blocker()
    try:
        if blocker.unblock_website(args.domain):
            print(f"[+] {args.domain} has been unblocked.")
        else:
            print(f"[-] {args.domain} was not in the blocklist.")
    except RuntimeError as e:
        print(f"[!] {e}")


def cmd_list_sites(args):
    blocker = Blocker()
    sites = blocker.list_blocked_websites()
    if sites:
        print("Blocked websites:")
        for s in sites:
            print(f"  {s}")
    else:
        print("No websites are currently blocked.")


def cmd_stats(args):
    print("[!] Stats are only available during an active sniffing session.")
    print("    Run 'python main.py sniff' to start monitoring.")


def cmd_sniff(args):
    if not SCAPY_AVAILABLE:
        print("[!] Scapy is not installed. Run: pip install scapy")
        sys.exit(1)

    if os.name != "nt" and os.geteuid() != 0:
        print("[!] Packet sniffing requires root privileges.")
        print("    Try: sudo python main.py sniff")
        sys.exit(1)

    logger = FirewallLogger(log_path=LOG_PATH)
    rules = FirewallRules(blocked_ips_path=BLOCKED_IPS_PATH)
    monitor = Monitor()

    if args.rules:
        try:
            with open(args.rules, "r") as f:
                custom_rules = json.load(f)
            rules.load_rules_from_list(custom_rules)
            print(f"[+] Loaded {len(custom_rules)} custom rules from {args.rules}")
        except (FileNotFoundError, json.JSONDecodeError) as e:
            print(f"[!] Could not load rules file: {e}")

    logger.log_startup()

    handler = build_packet_handler(rules, logger, monitor, verbose=args.verbose)
    sniffer = PacketSniffer(
        iface=args.iface or None,
        packet_callback=handler,
        filter_expr=args.filter,
    )

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    print(f"[*] Starting SuperShield on interface: {args.iface or 'default'}")
    print(f"[*] Filter : {args.filter}")
    print(f"[*] Log    : {logger.path}")
    print(f"[*] Blocked IPs loaded: {len(rules.list_blocked_ips())}")

    sniffer.start()

    if args.dashboard:
        dash_thread = threading.Thread(
            target=run_dashboard_loop,
            args=(monitor, logger, rules),
            daemon=True,
        )
        dash_thread.start()
    else:
        print("[*] Sniffing packets... Press Ctrl+C to stop.\n")

    _shutdown.wait()
    sniffer.stop()

    final_stats = monitor.get_stats()
    logger.log_shutdown(final_stats)

    print("\n[*] SuperShield stopped.")
    print(f"    Total  : {final_stats['total']}")
    print(f"    Allowed: {final_stats['allowed']}")
    print(f"    Blocked: {final_stats['blocked']}")
    print(f"    Log    : {logger.path}")


def main():
    parser = argparse.ArgumentParser(
        prog="supershield",
        description="SuperShield — Custom Personal Firewall",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    sniff_parser = subparsers.add_parser("sniff", help="Start packet sniffing and firewall enforcement")
    sniff_parser.add_argument("--iface", "-i", default=None, help="Network interface (default: auto)")
    sniff_parser.add_argument("--filter", "-f", default="ip", help="BPF filter expression (default: ip)")
    sniff_parser.add_argument("--verbose", "-v", action="store_true", help="Print every packet")
    sniff_parser.add_argument("--dashboard", "-d", action="store_true", help="Show live dashboard")
    sniff_parser.add_argument("--rules", "-r", default=None, help="Path to JSON rules file")
    sniff_parser.set_defaults(func=cmd_sniff)

    block_parser = subparsers.add_parser("block", help="Block an IP address")
    block_parser.add_argument("ip", help="IP address or CIDR to block (e.g., 192.168.1.10 or 10.0.0.0/8)")
    block_parser.set_defaults(func=cmd_block_ip)

    unblock_parser = subparsers.add_parser("unblock", help="Unblock an IP address")
    unblock_parser.add_argument("ip", help="IP address or CIDR to unblock")
    unblock_parser.set_defaults(func=cmd_unblock_ip)

    subparsers.add_parser("list-blocked", help="List all blocked IPs").set_defaults(func=cmd_list_blocked)

    site_block = subparsers.add_parser("block-site", help="Block a website via hosts file")
    site_block.add_argument("domain", help="Domain to block (e.g., facebook.com)")
    site_block.set_defaults(func=cmd_block_site)

    site_unblock = subparsers.add_parser("unblock-site", help="Unblock a website")
    site_unblock.add_argument("domain", help="Domain to unblock")
    site_unblock.set_defaults(func=cmd_unblock_site)

    subparsers.add_parser("list-sites", help="List blocked websites").set_defaults(func=cmd_list_sites)
    subparsers.add_parser("stats", help="Show session statistics").set_defaults(func=cmd_stats)

    iface_parser = subparsers.add_parser("interfaces", help="List available network interfaces")
    iface_parser.set_defaults(func=lambda _: print("\n".join(PacketSniffer.list_interfaces()) or "None found"))

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
