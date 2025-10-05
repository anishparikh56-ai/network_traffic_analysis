from scapy.all import TCP, IP, sniff

SYN_THRESHOLD = 20  # Number of SYN packets threshold
TIME_WINDOW = 30  # Time window in seconds

def print_packet(packet):
    if packet.haslayer(TCP) and packet.getlayer(TCP).flags == "S":
        print(packet.summary())


def detect_tcp_scan(packets):
    pkt_count = {}
    for packet in packets:
        if packet.haslayer(TCP) and packet.getlayer(TCP).flags == "S":
            if packet[IP].src in pkt_count:
                pkt_count[packet[IP].src] += 1
            else:
                pkt_count[packet[IP].src] = 1

    for ip_src, pkt_count in pkt_count.items():
        if pkt_count > SYN_THRESHOLD:
            print(f"TCP scan detected from source {ip_src}. TCP packets count: {pkt_count}")

# Sniff packets and apply detection function within the specified time window
packets = sniff(filter="tcp", timeout=TIME_WINDOW, prn=print_packet)
detect_tcp_scan(packets)
