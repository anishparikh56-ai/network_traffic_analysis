from scapy.all import IP, ICMP, sr1
import socket
import argparse

parser = argparse.ArgumentParser()
parser.add_argument('-i', '--ifname', help='Interface name', required=True)
args = parser.parse_args()

def send_icmp_packet(destination_ip, interface=args.ifname, num_of_packets=4):
    icmp_packet = IP(dst=destination_ip)/ICMP()
    
    for _ in range(num_of_packets):
        sr1(icmp_packet, timeout=1, verbose=False, iface=interface)

def resolve_domain(domain):
    try:
        ip_address = socket.gethostbyname(domain)
        print(f"The IP address of {domain} is: {ip_address}")
    except socket.gaierror:
        print(f"Unable to resolve IP address for {domain}")

    return ip_address

# Send ICMP packet
send_icmp_packet(resolve_domain("msn.com"))