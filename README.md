📡 NetWatch: Terminal-Based Network Packet Monitor
NetWatch is a lightweight, real-time network packet analyzer and terminal dashboard built with Python and Scapy. It captures packets on a specified network interface, visualizes live traffic stats using curses, and optionally exports metadata to CSV or raw packets to PCAP.

🛠 Features
Live dashboard for total, TCP, UDP, ICMP, and SYN packet stats

* Top talkers (most active source IPs)

* Basic port scan detection (SYN scans)

* Packet capture export:

🧾 CSV: Packet metadata

🧪 PCAP: Full packet payloads

Works on Linux (requires root for interface sniffing)

