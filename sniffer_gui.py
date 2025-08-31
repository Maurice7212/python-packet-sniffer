import tkinter as tk
from tkinter import ttk, scrolledtext
from scapy.all import AsyncSniffer, IP, TCP, UDP, ICMP, get_if_list, get_working_ifaces
import time, queue
from collections import Counter
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure


class VisualPacketSniffer:
    def __init__(self, root):
        self.root = root
        self.root.title("🚀 Advanced Visual Packet Sniffer")
        self.root.geometry("1100x750")
        self.is_sniffing = False
        self.packets = []
        self.stats = Counter()
        self.top_ips = Counter()
        self.packet_queue = queue.Queue()
        self.sniffer = None

        # Interfaces (only active ones)
        self.interfaces = [iface.name for iface in get_working_ifaces()]
        if not self.interfaces:  # fallback if none detected
            self.interfaces = get_if_list()

        self.iface_var = tk.StringVar(value=self.get_default_interface())

        # GUI Frames
        control_frame = ttk.Frame(root)
        control_frame.pack(anchor='nw', padx=10, pady=5)

        # Interface selector
        ttk.Label(control_frame, text="Interface:").grid(row=0, column=0, padx=5)
        self.iface_menu = ttk.Combobox(control_frame, textvariable=self.iface_var,
                                       values=self.interfaces, width=50)
        self.iface_menu.grid(row=0, column=1, padx=5)

        # Protocol filter
        self.protocol_var = tk.StringVar(value="ALL")
        ttk.Label(control_frame, text="Protocol Filter:").grid(row=0, column=2, padx=5)
        ttk.Combobox(control_frame, textvariable=self.protocol_var,
                     values=["ALL", "TCP", "UDP", "ICMP"], width=10).grid(row=0, column=3, padx=5)

        # Buttons
        ttk.Button(control_frame, text="Start", command=self.start_sniffing).grid(row=0, column=4, padx=5)
        ttk.Button(control_frame, text="Stop", command=self.stop_sniffing).grid(row=0, column=5, padx=5)
        ttk.Button(control_frame, text="Clear", command=self.clear_display).grid(row=0, column=6, padx=5)

        # Packet display
        self.packet_display = scrolledtext.ScrolledText(root, width=130, height=20)
        self.packet_display.pack(padx=10, pady=5)

        # Stats label
        self.stats_label = ttk.Label(root, text="Packet Stats: TCP=0 | UDP=0 | ICMP=0 | Others=0")
        self.stats_label.pack(anchor='nw', padx=10, pady=2)

        # Matplotlib figure for live graphs
        self.fig = Figure(figsize=(11, 3), dpi=100)
        self.ax_proto = self.fig.add_subplot(121)
        self.ax_ip = self.fig.add_subplot(122)
        self.canvas = FigureCanvasTkAgg(self.fig, master=root)
        self.canvas.get_tk_widget().pack(padx=10, pady=5)
        self.fig.tight_layout()

        # Periodic UI updater
        self.update_ui()

    def get_default_interface(self):
        """Prefer Wi-Fi or Ethernet, else first active iface"""
        for iface in self.interfaces:
            if "Wi-Fi" in iface or "Wireless" in iface or "Ethernet" in iface:
                return iface
        return self.interfaces[0] if self.interfaces else None

    def start_sniffing(self):
        if not self.is_sniffing:
            self.is_sniffing = True
            self.iface = self.iface_var.get()
            self.sniffer = AsyncSniffer(iface=self.iface,
                                        prn=self.process_packet,
                                        store=False,
                                        promisc=True)  # promiscuous mode
            self.sniffer.start()
            self.packet_display.insert(tk.END, f"[*] Sniffer started on {self.iface}\n")

    def stop_sniffing(self):
        if self.is_sniffing:
            self.is_sniffing = False
            if self.sniffer:
                self.sniffer.stop()
            self.packet_display.insert(tk.END, "[*] Sniffer stopped.\n")

    def clear_display(self):
        self.packet_display.delete(1.0, tk.END)
        self.stats = Counter()
        self.top_ips = Counter()
        self.packets.clear()
        self.update_stats()
        self.redraw_graphs()

    def process_packet(self, pkt):
        info = self.parse_packet(pkt)
        if info:
            self.packet_queue.put(info)

    def parse_packet(self, pkt):
        proto = "OTHER"
        dport = 0
        if IP in pkt:
            ip = pkt[IP]
            src, dst = ip.src, ip.dst
            self.top_ips[src] += 1

            if TCP in pkt:
                proto = "TCP"
                dport = pkt[TCP].dport
            elif UDP in pkt:
                proto = "UDP"
                dport = pkt[UDP].dport
            elif ICMP in pkt:
                proto = "ICMP"

            # Apply filter
            if self.protocol_var.get() != "ALL" and proto != self.protocol_var.get():
                return None

            self.stats[proto] += 1
            ts = time.strftime("%H:%M:%S")
            summary = f"[{ts}] {proto} | {src}->{dst} | Port:{dport}"
            if proto == "TCP" and dport in [22, 23, 3389]:
                summary += " [!] Suspicious"
            return summary
        else:
            self.stats["OTHER"] += 1
        return None

    def update_stats(self):
        self.stats_label.config(
            text=f"Packet Stats: TCP={self.stats.get('TCP', 0)} | UDP={self.stats.get('UDP', 0)} | "
                 f"ICMP={self.stats.get('ICMP', 0)} | Others={self.stats.get('OTHER', 0)}"
        )

    def redraw_graphs(self):
        self.ax_proto.clear()
        self.ax_ip.clear()

        # Protocol Pie
        labels = ['TCP', 'UDP', 'ICMP', 'Others']
        sizes = [self.stats.get('TCP', 0),
                 self.stats.get('UDP', 0),
                 self.stats.get('ICMP', 0),
                 self.stats.get('OTHER', 0)]

        if sum(sizes) > 0:
            self.ax_proto.pie(sizes, labels=labels, autopct='%1.1f%%')
        else:
            self.ax_proto.text(0.5, 0.5, "No Data Yet", ha='center', va='center')

        self.ax_proto.set_title("Protocol Distribution")

        # Top talkers Bar
        top_ips = dict(self.top_ips.most_common(5))
        if top_ips:
            self.ax_ip.bar(top_ips.keys(), top_ips.values(), color='orange')
        else:
            self.ax_ip.text(0.5, 0.5, "No IPs Yet", ha='center', va='center')

        self.ax_ip.set_title("Top 5 Talkers")
        self.canvas.draw()

    def update_ui(self):
        # Flush packet queue safely in main thread
        while not self.packet_queue.empty():
            info = self.packet_queue.get()
            self.packets.append(info)
            self.packet_display.insert(tk.END, info + "\n")
            self.packet_display.see(tk.END)

        self.update_stats()
        self.redraw_graphs()
        self.root.after(1000, self.update_ui)  # run every 1s


if __name__ == "__main__":
    root = tk.Tk()
    app = VisualPacketSniffer(root)
    root.mainloop()
