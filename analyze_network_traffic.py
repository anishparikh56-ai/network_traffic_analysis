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

    print(f"Source IP: {source_ip}")
    print(f"Destination IP: {destination_ip}")
    print(f"ICMP Type: {icmp_type}")


def analyze_dns_traffic(packet):
    if packet.haslayer(DNS):
        # DNS request (qr=0)
        if packet[DNS].qr == 0:
            print("DNS Request captured:")
            print(f"Domain: {packet[DNSQR].qname.decode()}")

        # DNS response (qr=1)
        elif packet[DNS].qr == 1:
            print("DNS Response captured:")
            print(f"Domain: {packet[DNSQR].qname.decode()}")
            for answer in packet[DNS]:
                # print(answer.fieldtype)
                if answer.fieldtype == 1:  # A record
                    print(f"IP: {answer.rdata}")


def packet_capture(packet):
    # Analyze the captured packet here
    if packet.haslayer(TCP) or packet.haslayer(UDP):
        return

    print("###### Packet Analysis Begins ######\n")
    if packet.haslayer(DNS):
        analyze_dns_traffic(packet)
    
    if packet.haslayer(ICMP):
        analyze_icmp_traffic(packet)

    print()
    print("###### Packet Analysis Ends ######\n")


parser = argparse.ArgumentParser()
parser.add_argument('-i', '--ifname', help='Interface name', required=True)
args = parser.parse_args()


# Start capturing packets
sniff(prn=packet_capture, iface=args.ifname)

