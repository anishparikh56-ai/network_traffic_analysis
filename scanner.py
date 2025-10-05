from scapy.all import TCP, UDP, IP, ICMP, sr, sr1
import argparse

top_ports = [
    21,    # FTP
    22,    # SSH
    23,    # Telnet
    25,    # SMTP
    53,    # DNS
    80,    # HTTP
    110,   # POP3
    115,   # SFTP
    119,   # NNTP
    123,   # NTP
    135,   # RPC
    137,   # NetBIOS
    139,   # NetBIOS
    143,   # IMAP
    161,   # SNMP
    179,   # BGP
    194,   # IRC
    220,   # IMAP3
    389,   # LDAP
    443,   # HTTPS
    445,   # SMB
    465,   # SMTPS
    514,   # Syslog
    515,   # LPD
    587,   # SMTP (Submission)
    993,   # IMAPS
    995,   # POP3S
    1080,  # SOCKS
    1433,  # MSSQL
    1521,  # Oracle DB
    1723,  # PPTP
    1812,  # RADIUS
    2049,  # NFS
    2082,  # cPanel
    2083,  # cPanel (SSL)
    2222,  # DirectAdmin
    3306,  # MySQL
    3389,  # RDP
    3690,  # SVN
    4333,  # mSQL
    4500,  # IPSec
    5432,  # PostgreSQL
    5900,  # VNC
    5984,  # CouchDB
    6379,  # Redis
    6667,  # IRC
    6697,  # IRC (SSL)
    8000,  # HTTP (Alternative)
    8080,  # HTTP Proxy
    8443,  # HTTPS (Alternative)
    8888,  # HTTP (Alternative)
    9000,  # HTTP (Alternative)
    9418,  # Git
    9999,  # Application Port
    10000, # Webmin
    11211, # Memcached
    27017, # MongoDB
    27018, # MongoDB
    27019, # MongoDB
    28017, # MongoDB (HTTP)
    37777, # Dahua DVR
    50000, # SAP
    50070, # Hadoop
    50075, # Hadoop
    50090, # Hadoop
    54321, # MongoDB
    60000, # Deep Discovery Inspector
    62078, # iPhone Sync
    8081,  # HTTP Proxy
    8088,  # Hadoop
    8090,  # HTTP (Alternative)
    9001,  # HTTP (Alternative)
    9090,  # HTTP (Alternative)
    27015, # Steam
    27016, # Steam
    27017, # Steam
    27018, # Steam
    27019, # Steam
    27020, # Steam
    32768, # MySQL
    49152, # Oracle DB
    49153, # Oracle DB
    49154, # Oracle DB
    49155, # Oracle DB
    49156, # Oracle DB
    49157  # Oracle DB
]


def scan_target(packet):
    # Send the packet and receive response
    return sr(packet, timeout=2, verbose=0)


# TCP SYN/FIN Ping Scan to detect live hosts
def perform_tcp_scan(target, flags):
    packet = IP(dst=target) / TCP(dport=80, flags=flags)
    ans, _ = scan_target(packet)

    if ans:
        print(f"Host {target} is up.")
    else:
        print(f"Host {target} is down.")


# UDP Ping Scan to detect live hosts
def perform_udp_scan(target):
    packet = IP(dst=target) / UDP(dport=53)
    ans, _ = scan_target(packet)

    for snd, rcv in ans:
        # print("Packet Sent: ", snd)
        # print("Packet Received: ", rcv)
        ip = rcv[IP]
        if ip.haslayer(ICMP):
            if ip[ICMP].type == 3:
                print(f"UDP Scan -> Host is active: {rcv[IP].src}")


# ICMP Ping Scan to detect live hosts
def perform_icmp_scan(target):
    packet = IP(dst=target) / ICMP()
    ans, _ = scan_target(packet)

    for snd, rcv in ans:
        # print("Packet Sent: ", snd)
        # print("Packet Received: ", rcv)
        ip = rcv[IP]
        if ip[ICMP].type == 0 and ip[ICMP].code == 0:
            print(f"ICMP Scan -> Host is active: {rcv[IP].src}")


# Perform TCP Port Scan
def perform_tcp_port_scan(target, port):
    packet = IP(dst=target) / TCP(dport=port, flags='S')
    response = sr1(packet, timeout=2, verbose=0)
    if response:
        if response.haslayer(TCP) and response.getlayer(TCP).flags == "SA":
            print(f"Port {port} is open.")
        else:
            print(f"Port {port} is closed.")
    else:
        print(f"Port {port} is filtered.")


# Perform UDP Port Scan
def perform_udp_port_scan(target, port):
    packet = IP(dst=target) / UDP(dport=port)
    response = sr1(packet, timeout=1, verbose=0)
    if response and response.haslayer(UDP):
            print(f"Port {port} is open.")
    else:
        print(f"Port {port} is closed or filtered.")


class SplitArgs(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        setattr(namespace, self.dest, values.split(','))


parser = argparse.ArgumentParser()
parser.add_argument('-t', '--target', dest='target', help='Target IP/Network CIDR', required=True)
parser.add_argument('--top-ports', dest='top_ports', action='store_true', help='Scan only top ports')
parser.add_argument('--all-ports', dest='all_ports', action='store_true', help='Scan all ports')
parser.add_argument('-p', dest='ports', action=SplitArgs)
parser.add_argument('-f', '--flags', default='S', help='Specify TCP Flag')
parser.add_argument('--scan-type', dest='scan_type', help='Specify Scan Type: PS/PU/PE - TCP Syn/UDP/ICMP Discovery, sS/sU - TCP/UDP Port Scan')
args = parser.parse_args()

if args.top_ports:
    ports_to_scan = top_ports
elif args.all_ports:
    ports_to_scan = range(1, 65535 + 1)
elif args.ports:
    ports_to_scan = args.ports
else:
    ports_to_scan = top_ports

if args.scan_type == 'PS':
    perform_tcp_scan(args.target, args.flags)
elif args.scan_type == 'PU':
    perform_udp_scan(args.target)
elif args.scan_type == 'PE':
    perform_icmp_scan(args.target)
elif args.scan_type == 'sS':
    for port in ports_to_scan:
        perform_tcp_port_scan(args.target, int(port))
elif args.scan_type == 'sU':
    for port in ports_to_scan:
        perform_udp_port_scan(args.target, int(port))