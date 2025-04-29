import argparse
from scapy.all import sniff, IP, TCP, UDP, ICMP, wrpcap
from datetime import datetime
import curses
import threading
from collections import defaultdict, Counter
import time
import csv

# ---- Global Stats Storage ----
stats = {
    'total': 0,
    'TCP': 0,
    'UDP': 0,
    'ICMP': 0,
    'SYN': 0,
    'sources': Counter()
}

# ---- Port Scan Detection ----
scan_tracker = defaultdict(lambda: {
    "ports": set(),
    "last_seen": time.time(),
})
SCAN_PORT_THRESHOLD = 10    # Flag if more than 10 unique ports
SCAN_TIMEOUT = 10           # Reset port set after 10 seconds

# ---- Packet Storage for Export ----
packets_to_save = []
csv_rows = []

# ---- Decode TCP Flags ----
def decode_tcp_flags(flags_num):
    flags = []
    if flags_num & 0x01: flags.append("FIN")
    if flags_num & 0x02: flags.append("SYN")
    if flags_num & 0x04: flags.append("RST")
    if flags_num & 0x08: flags.append("PSH")
    if flags_num & 0x10: flags.append("ACK")
    if flags_num & 0x20: flags.append("URG")
    if flags_num & 0x40: flags.append("ECE")
    if flags_num & 0x80: flags.append("CWR")
    return ",".join(flags) if flags else "NONE"

# ---- Packet Handler ----
def packet_handler(packet):
    stats['total'] += 1

    if IP in packet:
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        proto = ip_layer.proto
        proto_str = {1: "ICMP", 6: "TCP", 17: "UDP"}.get(proto, str(proto))

        stats['sources'][src_ip] += 1
        now = time.time()

        row = {
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'protocol': proto_str,
            'sport': '',
            'dport': '',
            'flags': ''
        }

        if TCP in packet:
            stats['TCP'] += 1
            dport = packet[TCP].dport
            sport = packet[TCP].sport
            flags = packet[TCP].flags
            row.update({
                'sport': sport,
                'dport': dport,
                'flags': decode_tcp_flags(flags)
            })

            # Count SYN packets
            if flags & 0x02:
                stats['SYN'] += 1

            # Track ports for scan detection
            if now - scan_tracker[src_ip]["last_seen"] > SCAN_TIMEOUT:
                scan_tracker[src_ip]["ports"] = set()
            scan_tracker[src_ip]["ports"].add(dport)
            scan_tracker[src_ip]["last_seen"] = now

        elif UDP in packet:
            stats['UDP'] += 1
            row.update({
                'sport': packet[UDP].sport,
                'dport': packet[UDP].dport
            })

        elif ICMP in packet:
            stats['ICMP'] += 1

        # Save packet if needed
        if args.csv:
            csv_rows.append(row)

        if args.pcap:
            packets_to_save.append(packet)

# ---- Sniffing Thread ----
def start_sniffing(interface):
    sniff(iface=interface, prn=packet_handler, store=False)

# ---- Curses UI Dashboard ----
def dashboard(stdscr):
    curses.curs_set(0)
    stdscr.nodelay(True)

    while True:
        stdscr.erase()
        height, width = stdscr.getmaxyx()

        try:
            stdscr.addstr(0, 2, "📡 NetWatch Live Packet Stats", curses.A_BOLD | curses.A_UNDERLINE)
            stdscr.addstr(2, 2, f"Total Packets: {stats['total']}")
            stdscr.addstr(3, 2, f"TCP Packets:   {stats['TCP']}")
            stdscr.addstr(4, 2, f"UDP Packets:   {stats['UDP']}")
            stdscr.addstr(5, 2, f"ICMP Packets:  {stats['ICMP']}")
            stdscr.addstr(6, 2, f"SYN Packets:   {stats['SYN']}")

            stdscr.addstr(8, 2, "Top 5 Source IPs:")
            for i, (ip, count) in enumerate(stats['sources'].most_common(5), start=9):
                if i < height - 1:
                    stdscr.addstr(i, 4, f"{ip} - {count} packets")

            stdscr.addstr(15, 2, "⚠️ Potential Port Scanners:")
            suspicious = [ip for ip, data in scan_tracker.items()
                          if len(data["ports"]) > SCAN_PORT_THRESHOLD]

            if suspicious:
                for idx, ip in enumerate(suspicious[:5], start=16):
                    if idx < height - 1:
                        port_count = len(scan_tracker[ip]["ports"])
                        stdscr.addstr(idx, 4, f"{ip} → {port_count} unique ports")
            else:
                if height > 17:
                    stdscr.addstr(16, 4, "None detected.")

            if height > 22:
                stdscr.addstr(height - 1, 2, "Press Ctrl+C to exit.")
            else:
                stdscr.addstr(height - 1, 2, "(Resize terminal for more info)")

            stdscr.refresh()
            curses.napms(500)

        except curses.error:
            pass  # Handle small window gracefully

# ---- Main Entry ----
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NetWatch Dashboard Sniffer")
    parser.add_argument('-i', '--interface', type=str, required=True, help='Network interface to sniff on')
    parser.add_argument('--csv', type=str, help='Path to save packet metadata as CSV')
    parser.add_argument('--pcap', type=str, help='Path to save full packets as PCAP')
    parser.add_argument('--count', type=int, default=0, help='Number of packets to capture (0 = infinite)')
    args = parser.parse_args()

    print(f"[*] Sniffing on interface: {args.interface}")
    if args.csv:
        print(f"[*] CSV output will be saved to: {args.csv}")
    if args.pcap:
        print(f"[*] PCAP output will be saved to: {args.pcap}")

    # Start background packet sniffer thread
    sniffer_thread = threading.Thread(target=lambda: sniff(
        iface=args.interface,
        prn=packet_handler,
        store=False,
        count=args.count
    ), daemon=True)
    sniffer_thread.start()

    # Start terminal dashboard
    try:
        curses.wrapper(dashboard)
    except KeyboardInterrupt:
        print("\n[!] Exiting NetWatch Dashboard...")

    # Save output
    if args.csv and csv_rows:
        with open(args.csv, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=['timestamp', 'src_ip', 'dst_ip', 'protocol', 'sport', 'dport', 'flags'])
            writer.writeheader()
            writer.writerows(csv_rows)
        print(f"[+] CSV saved to {args.csv}")

    if args.pcap and packets_to_save:
        wrpcap(args.pcap, packets_to_save)
        print(f"[+] PCAP saved to {args.pcap}")
