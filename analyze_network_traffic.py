from scapy.all import TCP, IP, IPv6, ICMP, UDP, DNS, DNSQR, sniff
import argparse

icmp_type_map = {
    0: "Echo Reply",
    3: "Destination Unreachable",
    8: "Echo Request",
    11: "Time Exceeded",
}


def analyze_icmp_traffic(packet):
    source_ip = packet[IP].src
    destination_ip = packet[IP].dst
    icmp_type = icmp_type_map.get(packet[ICMP].type, "Unknown")

    print()
    print(f"ICMP Type: {icmp_type}")
    print(f"Source IP: {source_ip}")
    print(f"Destination IP: {destination_ip}")


def analyze_dns_traffic(packet):
    # DNS request (qr=0)
    if packet[DNS].qr == 0:
        print(f"DNS request for domain: {packet[DNSQR].qname.decode()}")

    # DNS response (qr=1)
    if packet[DNS].qr == 1:
        if getattr(packet[DNS], 'an'):
            for answer in packet[DNS].an:
                if answer.type == 1:
                    print(f"DNS Response IP: {answer.rdata}")
                    print()
        else:
            print("No DNS Response!\n")

def packet_capture(packet):
    # Analyze the captured packet here
    if packet.haslayer(TCP):
        return

    if packet.haslayer(DNS):
        analyze_dns_traffic(packet)
    
    if packet.haslayer(ICMP):
        analyze_icmp_traffic(packet)



parser = argparse.ArgumentParser()
parser.add_argument('-i', '--ifname', help='Interface name', required=True)

## e.g "icmp", "port 53"
parser.add_argument('-f', '--filter', help='Filter Traffic', required=True)
args = parser.parse_args()


# Start capturing packets
sniff(prn=packet_capture, iface=args.ifname, filter=args.filter)

