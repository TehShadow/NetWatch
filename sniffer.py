import argparse
from scapy.all import sniff, IP, TCP, UDP, ICMP, wrpcap
from datetime import datetime
import csv

# Containers for saving captured data
packets = []
csv_rows = []

# ---- Decode TCP Flags ----
def decode_tcp_flags(flags_num):
    flags = []
    if flags_num & 0x01:
        flags.append("FIN")
    if flags_num & 0x02:
        flags.append("SYN")
    if flags_num & 0x04:
        flags.append("RST")
    if flags_num & 0x08:
        flags.append("PSH")
    if flags_num & 0x10:
        flags.append("ACK")
    if flags_num & 0x20:
        flags.append("URG")
    if flags_num & 0x40:
        flags.append("ECE")
    if flags_num & 0x80:
        flags.append("CWR")
    return ",".join(flags) if flags else "NONE"

# ---- Handle Each Packet ----
def packet_handler(packet):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if IP in packet:
        ip_layer = packet[IP]
        proto = ip_layer.proto
        proto_str = {1: "ICMP", 6: "TCP", 17: "UDP"}.get(proto, str(proto))

        row = {
            'timestamp': timestamp,
            'src_ip': ip_layer.src,
            'dst_ip': ip_layer.dst,
            'protocol': proto_str,
            'sport': '',
            'dport': '',
            'flags': ''
        }

        if TCP in packet:
            tcp = packet[TCP]
            flags_human = decode_tcp_flags(tcp.flags)
            row.update({
                'sport': tcp.sport,
                'dport': tcp.dport,
                'flags': flags_human
            })

        elif UDP in packet:
            udp = packet[UDP]
            row.update({
                'sport': udp.sport,
                'dport': udp.dport
            })

        elif ICMP in packet:
            row.update({
                'protocol': 'ICMP'
            })

        # Print to console
        print(f"[{timestamp}] {row['src_ip']} -> {row['dst_ip']} | {row['protocol']}", end='')
        if row['sport'] or row['dport']:
            print(f" | Sport: {row['sport']} -> Dport: {row['dport']}", end='')
        if row['flags']:
            print(f" | Flags: {row['flags']}", end='')
        print()

        # Save data if needed
        if args.csv:
            csv_rows.append(row)

        if args.pcap:
            packets.append(packet)

# ---- Argument Parsing ----
parser = argparse.ArgumentParser(description="NetWatch Packet Sniffer")
parser.add_argument('-i', '--interface', type=str, required=True, help='Network interface to sniff on (e.g., eth0, wlan0)')
parser.add_argument('--csv', type=str, help='Path to save captured packet info as CSV')
parser.add_argument('--pcap', type=str, help='Path to save packets in PCAP format')
parser.add_argument('--count', type=int, default=0, help='Number of packets to capture (0 = infinite)')

args = parser.parse_args()

# ---- Sniffing Start ----
print(f"[*] Starting packet sniffing on {args.interface}...")
if args.csv:
    print(f"[*] CSV output will be saved to {args.csv}")
if args.pcap:
    print(f"[*] PCAP output will be saved to {args.pcap}")

try:
    sniff(iface=args.interface, prn=packet_handler, store=False, count=args.count)
except KeyboardInterrupt:
    print("\n[!] Capture stopped by user.")

# ---- Saving Output ----
if args.csv:
    with open(args.csv, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=['timestamp', 'src_ip', 'dst_ip', 'protocol', 'sport', 'dport', 'flags'])
        writer.writeheader()
        writer.writerows(csv_rows)
    print(f"[+] CSV saved to {args.csv}")

if args.pcap:
    wrpcap(args.pcap, packets)
    print(f"[+] PCAP saved to {args.pcap}")
