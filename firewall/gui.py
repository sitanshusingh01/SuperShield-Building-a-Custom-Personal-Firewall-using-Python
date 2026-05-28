import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading
import time
import queue
import os
import sys

from .firewall_rules import FirewallRules, Rule
from .packet_sniffer import PacketSniffer, SCAPY_AVAILABLE
from .logger import FirewallLogger
from .monitor import Monitor
from .utils import format_packet_summary, is_valid_ip, is_valid_cidr

BASE_DIR = os.path.join(os.path.dirname(__file__), "..")
BLOCKED_IPS_PATH = os.path.join(BASE_DIR, "config", "blocked_ips.txt")
LOG_PATH = os.path.join(BASE_DIR, "logs", "firewall.log")

COLOR_BG = "#1e1e2e"
COLOR_PANEL = "#2a2a3e"
COLOR_ACCENT = "#7c3aed"
COLOR_GREEN = "#22c55e"
COLOR_RED = "#ef4444"
COLOR_YELLOW = "#f59e0b"
COLOR_TEXT = "#e2e8f0"
COLOR_MUTED = "#94a3b8"
COLOR_BORDER = "#3f3f5f"


class SuperShieldGUI:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("SuperShield — Personal Firewall")
        self.root.geometry("1050x700")
        self.root.minsize(900, 600)
        self.root.configure(bg=COLOR_BG)

        self._packet_queue: queue.Queue = queue.Queue(maxsize=500)
        self._running = False
        self._sniffer: PacketSniffer = None

        self.rules = FirewallRules(blocked_ips_path=BLOCKED_IPS_PATH)
        self.logger = FirewallLogger(log_path=LOG_PATH)
        self.monitor = Monitor()

        self._build_styles()
        self._build_header()
        self._build_main()
        self._build_statusbar()

        self._poll_queue()
        self._refresh_stats()

    def _build_styles(self):
        style = ttk.Style()
        style.theme_use("clam")

        style.configure("TNotebook", background=COLOR_BG, borderwidth=0)
        style.configure("TNotebook.Tab",
                        background=COLOR_PANEL,
                        foreground=COLOR_MUTED,
                        padding=[14, 6],
                        font=("Segoe UI", 10))
        style.map("TNotebook.Tab",
                  background=[("selected", COLOR_ACCENT)],
                  foreground=[("selected", "white")])

        style.configure("Treeview",
                        background=COLOR_PANEL,
                        fieldbackground=COLOR_PANEL,
                        foreground=COLOR_TEXT,
                        rowheight=24,
                        font=("Consolas", 9))
        style.configure("Treeview.Heading",
                        background=COLOR_BORDER,
                        foreground=COLOR_TEXT,
                        font=("Segoe UI", 9, "bold"))
        style.map("Treeview", background=[("selected", COLOR_ACCENT)])

        style.configure("TScrollbar", background=COLOR_PANEL, troughcolor=COLOR_BG)

    def _build_header(self):
        header = tk.Frame(self.root, bg=COLOR_ACCENT, height=52)
        header.pack(fill="x", side="top")
        header.pack_propagate(False)

        tk.Label(header, text="🛡  SuperShield",
                 font=("Segoe UI", 16, "bold"),
                 bg=COLOR_ACCENT, fg="white").pack(side="left", padx=18, pady=10)

        right = tk.Frame(header, bg=COLOR_ACCENT)
        right.pack(side="right", padx=18, pady=8)

        self._start_btn = tk.Button(
            right, text="  ▶  Start",
            font=("Segoe UI", 10, "bold"),
            bg=COLOR_GREEN, fg="white", relief="flat",
            padx=14, pady=4, cursor="hand2",
            command=self._start_sniffing)
        self._start_btn.pack(side="left", padx=4)

        self._stop_btn = tk.Button(
            right, text="  ■  Stop",
            font=("Segoe UI", 10, "bold"),
            bg=COLOR_RED, fg="white", relief="flat",
            padx=14, pady=4, cursor="hand2",
            state="disabled",
            command=self._stop_sniffing)
        self._stop_btn.pack(side="left", padx=4)

    def _build_main(self):
        container = tk.Frame(self.root, bg=COLOR_BG)
        container.pack(fill="both", expand=True, padx=12, pady=8)

        left = tk.Frame(container, bg=COLOR_BG, width=220)
        left.pack(side="left", fill="y", padx=(0, 8))
        left.pack_propagate(False)
        self._build_stats_panel(left)
        self._build_blocklist_control(left)

        right = tk.Frame(container, bg=COLOR_BG)
        right.pack(side="left", fill="both", expand=True)
        self._build_tabs(right)

    def _stat_box(self, parent, label, var, color):
        box = tk.Frame(parent, bg=COLOR_PANEL, pady=10)
        box.pack(fill="x", pady=4)
        tk.Label(box, text=label,
                 font=("Segoe UI", 9),
                 bg=COLOR_PANEL, fg=COLOR_MUTED).pack()
        tk.Label(box, textvariable=var,
                 font=("Consolas", 22, "bold"),
                 bg=COLOR_PANEL, fg=color).pack()

    def _build_stats_panel(self, parent):
        tk.Label(parent, text="STATISTICS",
                 font=("Segoe UI", 9, "bold"),
                 bg=COLOR_BG, fg=COLOR_MUTED).pack(anchor="w", pady=(4, 2))

        self._var_total = tk.StringVar(value="0")
        self._var_allowed = tk.StringVar(value="0")
        self._var_blocked = tk.StringVar(value="0")
        self._var_uptime = tk.StringVar(value="00:00:00")

        self._stat_box(parent, "Total Packets", self._var_total, COLOR_TEXT)
        self._stat_box(parent, "Allowed", self._var_allowed, COLOR_GREEN)
        self._stat_box(parent, "Blocked", self._var_blocked, COLOR_RED)

        uptime_box = tk.Frame(parent, bg=COLOR_PANEL, pady=8)
        uptime_box.pack(fill="x", pady=4)
        tk.Label(uptime_box, text="Uptime",
                 font=("Segoe UI", 9),
                 bg=COLOR_PANEL, fg=COLOR_MUTED).pack()
        tk.Label(uptime_box, textvariable=self._var_uptime,
                 font=("Consolas", 13, "bold"),
                 bg=COLOR_PANEL, fg=COLOR_YELLOW).pack()

        self._var_status = tk.StringVar(value="● Idle")
        status_lbl = tk.Label(parent, textvariable=self._var_status,
                              font=("Segoe UI", 10, "bold"),
                              bg=COLOR_BG, fg=COLOR_MUTED)
        status_lbl.pack(pady=(10, 0))
        self._status_label = status_lbl

    def _build_blocklist_control(self, parent):
        tk.Label(parent, text="BLOCK IP / CIDR",
                 font=("Segoe UI", 9, "bold"),
                 bg=COLOR_BG, fg=COLOR_MUTED).pack(anchor="w", pady=(16, 2))

        entry_frame = tk.Frame(parent, bg=COLOR_PANEL, pady=6, padx=6)
        entry_frame.pack(fill="x")

        self._ip_entry = tk.Entry(entry_frame,
                                  font=("Consolas", 10),
                                  bg="#1a1a2e", fg=COLOR_TEXT,
                                  insertbackground=COLOR_TEXT,
                                  relief="flat", bd=4)
        self._ip_entry.pack(fill="x", pady=(0, 4))
        self._ip_entry.insert(0, "e.g. 192.168.1.5")
        self._ip_entry.bind("<FocusIn>", lambda e: self._clear_placeholder())
        self._ip_entry.bind("<Return>", lambda e: self._do_block_ip())

        btn_row = tk.Frame(entry_frame, bg=COLOR_PANEL)
        btn_row.pack(fill="x")
        tk.Button(btn_row, text="Block", font=("Segoe UI", 9, "bold"),
                  bg=COLOR_RED, fg="white", relief="flat",
                  cursor="hand2", command=self._do_block_ip).pack(side="left", expand=True, fill="x", padx=(0, 2))
        tk.Button(btn_row, text="Unblock", font=("Segoe UI", 9, "bold"),
                  bg=COLOR_PANEL, fg=COLOR_TEXT, relief="flat",
                  cursor="hand2", command=self._do_unblock_ip).pack(side="left", expand=True, fill="x")

    def _clear_placeholder(self):
        if self._ip_entry.get() == "e.g. 192.168.1.5":
            self._ip_entry.delete(0, "end")

    def _build_tabs(self, parent):
        nb = ttk.Notebook(parent)
        nb.pack(fill="both", expand=True)

        self._build_packets_tab(nb)
        self._build_blocked_tab(nb)
        self._build_log_tab(nb)

    def _build_packets_tab(self, nb):
        frame = tk.Frame(nb, bg=COLOR_BG)
        nb.add(frame, text="  Live Traffic  ")

        cols = ("time", "action", "protocol", "src", "dst", "len")
        self._tree = ttk.Treeview(frame, columns=cols, show="headings", height=25)

        widths = {"time": 80, "action": 72, "protocol": 70, "src": 155, "dst": 155, "len": 58}
        labels = {"time": "Time", "action": "Action", "protocol": "Proto",
                  "src": "Source IP", "dst": "Destination IP", "len": "Len"}
        for col in cols:
            self._tree.heading(col, text=labels[col])
            self._tree.column(col, width=widths[col], anchor="center" if col in ("action", "protocol", "len") else "w")

        self._tree.tag_configure("ALLOW", foreground=COLOR_GREEN)
        self._tree.tag_configure("BLOCK", foreground=COLOR_RED)

        vsb = ttk.Scrollbar(frame, orient="vertical", command=self._tree.yview)
        self._tree.configure(yscrollcommand=vsb.set)

        self._tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")

        self._auto_scroll = tk.BooleanVar(value=True)
        ctrl = tk.Frame(frame, bg=COLOR_BG)
        ctrl.pack(fill="x", pady=4, padx=4)
        tk.Checkbutton(ctrl, text="Auto-scroll",
                       variable=self._auto_scroll,
                       bg=COLOR_BG, fg=COLOR_MUTED,
                       selectcolor=COLOR_PANEL,
                       activebackground=COLOR_BG).pack(side="left")
        tk.Button(ctrl, text="Clear", font=("Segoe UI", 9),
                  bg=COLOR_PANEL, fg=COLOR_TEXT, relief="flat",
                  command=lambda: self._tree.delete(*self._tree.get_children())).pack(side="right")

    def _build_blocked_tab(self, nb):
        frame = tk.Frame(nb, bg=COLOR_BG)
        nb.add(frame, text="  Blocked IPs  ")

        cols = ("ip",)
        self._blocked_tree = ttk.Treeview(frame, columns=cols, show="headings", height=25)
        self._blocked_tree.heading("ip", text="Blocked IP / CIDR")
        self._blocked_tree.column("ip", width=300)

        vsb = ttk.Scrollbar(frame, orient="vertical", command=self._blocked_tree.yview)
        self._blocked_tree.configure(yscrollcommand=vsb.set)
        self._blocked_tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")

        self._refresh_blocked_list()

    def _build_log_tab(self, nb):
        frame = tk.Frame(nb, bg=COLOR_BG)
        nb.add(frame, text="  Log File  ")

        self._log_text = scrolledtext.ScrolledText(
            frame,
            font=("Consolas", 9),
            bg="#111120", fg=COLOR_TEXT,
            insertbackground=COLOR_TEXT,
            state="disabled",
            wrap="none")
        self._log_text.pack(fill="both", expand=True)

        ctrl = tk.Frame(frame, bg=COLOR_BG)
        ctrl.pack(fill="x", pady=4, padx=4)
        tk.Button(ctrl, text="Refresh Log", font=("Segoe UI", 9),
                  bg=COLOR_PANEL, fg=COLOR_TEXT, relief="flat",
                  command=self._load_log_file).pack(side="left")
        tk.Label(ctrl, text=f"  {LOG_PATH}",
                 font=("Segoe UI", 8),
                 bg=COLOR_BG, fg=COLOR_MUTED).pack(side="left")

        self._load_log_file()

    def _build_statusbar(self):
        bar = tk.Frame(self.root, bg=COLOR_BORDER, height=24)
        bar.pack(fill="x", side="bottom")
        bar.pack_propagate(False)
        self._statusbar_var = tk.StringVar(value="Ready — SuperShield v1.0")
        tk.Label(bar, textvariable=self._statusbar_var,
                 font=("Segoe UI", 8),
                 bg=COLOR_BORDER, fg=COLOR_MUTED).pack(side="left", padx=8)

    def _start_sniffing(self):
        if not SCAPY_AVAILABLE:
            messagebox.showerror("Missing Dependency",
                                 "Scapy is not installed.\n\nRun: pip install scapy")
            return

        if os.name != "nt" and os.geteuid() != 0:
            messagebox.showwarning("Privileges Required",
                                   "Packet sniffing requires root/administrator privileges.\n"
                                   "Restart SuperShield with: sudo python main.py gui")
            return

        self._running = True
        self.monitor.reset()
        self.logger.log_startup()

        handler = self._make_handler()
        self._sniffer = PacketSniffer(packet_callback=handler)
        self._sniffer.start()

        self._start_btn.config(state="disabled")
        self._stop_btn.config(state="normal")
        self._var_status.set("● Running")
        self._status_label.config(fg=COLOR_GREEN)
        self._statusbar_var.set("Sniffing packets... Press Stop to halt.")

    def _stop_sniffing(self):
        self._running = False
        if self._sniffer:
            self._sniffer.stop()
            self._sniffer = None

        stats = self.monitor.get_stats()
        self.logger.log_shutdown(stats)

        self._start_btn.config(state="normal")
        self._stop_btn.config(state="disabled")
        self._var_status.set("● Idle")
        self._status_label.config(fg=COLOR_MUTED)
        self._statusbar_var.set(
            f"Stopped — Total: {stats['total']}  Allowed: {stats['allowed']}  Blocked: {stats['blocked']}")
        self._load_log_file()

    def _make_handler(self):
        def on_packet(src, dst, protocol, length, port, summary):
            action = self.rules.evaluate(src, dst, protocol, port)
            self.monitor.record(src, dst, protocol, length, action, port)
            self.logger.log_packet(src, dst, protocol, action)
            ts = time.strftime("%H:%M:%S")
            self._packet_queue.put_nowait((ts, action, protocol, src, dst, length))
        return on_packet

    def _poll_queue(self):
        try:
            while True:
                ts, action, protocol, src, dst, length = self._packet_queue.get_nowait()
                tag = "ALLOW" if action == "ALLOW" else "BLOCK"
                self._tree.insert("", "end",
                                  values=(ts, action, protocol, src, dst, length),
                                  tags=(tag,))
                if self._auto_scroll.get():
                    children = self._tree.get_children()
                    if children:
                        self._tree.see(children[-1])
                if len(self._tree.get_children()) > 1000:
                    self._tree.delete(self._tree.get_children()[0])
        except queue.Empty:
            pass
        self.root.after(80, self._poll_queue)

    def _refresh_stats(self):
        stats = self.monitor.get_stats()
        self._var_total.set(str(stats["total"]))
        self._var_allowed.set(str(stats["allowed"]))
        self._var_blocked.set(str(stats["blocked"]))
        self._var_uptime.set(self.monitor.uptime_str())
        self.root.after(1000, self._refresh_stats)

    def _refresh_blocked_list(self):
        self._blocked_tree.delete(*self._blocked_tree.get_children())
        for ip in self.rules.list_blocked_ips():
            self._blocked_tree.insert("", "end", values=(ip,))

    def _do_block_ip(self):
        ip = self._ip_entry.get().strip()
        if not ip or ip == "e.g. 192.168.1.5":
            return
        if self.rules.block_ip(ip):
            self._refresh_blocked_list()
            self._statusbar_var.set(f"Blocked: {ip}")
            self._ip_entry.delete(0, "end")
        else:
            messagebox.showerror("Invalid Input", f"'{ip}' is not a valid IP address or CIDR range.")

    def _do_unblock_ip(self):
        ip = self._ip_entry.get().strip()
        if not ip or ip == "e.g. 192.168.1.5":
            selected = self._blocked_tree.selection()
            if selected:
                ip = self._blocked_tree.item(selected[0])["values"][0]
            else:
                return
        if self.rules.unblock_ip(ip):
            self._refresh_blocked_list()
            self._statusbar_var.set(f"Unblocked: {ip}")
            self._ip_entry.delete(0, "end")
        else:
            messagebox.showinfo("Not Found", f"{ip} is not in the blocklist.")

    def _load_log_file(self):
        self._log_text.config(state="normal")
        self._log_text.delete("1.0", "end")
        try:
            with open(LOG_PATH, "r") as f:
                content = f.read()
            self._log_text.insert("end", content)
            self._log_text.see("end")
        except FileNotFoundError:
            self._log_text.insert("end", "(No log file found yet — start sniffing to generate logs)")
        self._log_text.config(state="disabled")


def launch():
    root = tk.Tk()
    app = SuperShieldGUI(root)
    root.mainloop()
