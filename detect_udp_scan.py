from scapy.all import UDP, IP, sniff

UDP_THRESHOLD = 10
TIME_WINDOW = 20

def print_packet(packet):
    if packet.haslayer(UDP):
        print(packet.summary())


def detect_udp_scan(packets):
    pkt_count = {}
    for pkt in packets:
        if UDP in pkt and len(pkt[UDP].payload) == 0:
            if pkt[IP].src in pkt_count:
                pkt_count[pkt[IP].src] += 1
            else:
                pkt_count[pkt[IP].src] = 1
    
    for ip_src, pkt_count in pkt_count.items():
        if pkt_count > UDP_THRESHOLD:
            print(f"UDP scan detected from {ip_src}. UDP Packets Count: {pkt_count}")

# Sniff network traffic and apply the detection function to each packet
packets = sniff(filter="udp", prn=print_packet, timeout=TIME_WINDOW)
detect_udp_scan(packets)