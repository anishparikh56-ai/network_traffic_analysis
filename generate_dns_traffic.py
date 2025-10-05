from scapy.all import IP, UDP, DNS, DNSQR, send

# DNS request parameters
dns_server = "8.8.8.8"
dns_port = 53
domain = "msn.com"

# Create DNS request packet
dns_request = IP(dst=dns_server) / UDP(dport=dns_port) / DNS(rd=1, qd=DNSQR(qname=domain))

# Send DNS request packet
send(dns_request, verbose=False)
