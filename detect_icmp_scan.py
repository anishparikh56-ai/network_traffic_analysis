from scapy.all import ICMP, IP, sniff

def detect_icmp_scan(packet):
    if packet.haslayer(ICMP):
        if packet[ICMP].type == 8:  # ICMP Echo Request (ping)
            print("ICMP scan detected from", packet[IP].src)

sniff(filter="icmp", prn=detect_icmp_scan)
