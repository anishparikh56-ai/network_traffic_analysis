from scapy.all import TCP, IP, sr1
import argparse

parser = argparse.ArgumentParser()
parser.add_argument('-t', '--dest_ip', help='Target IP', required=True)
args = parser.parse_args()


ip = IP(dst=args.dest_ip)

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

def tcp_syn_ping_scan(target_ip, target_port):
    # Create TCP SYN packet for each port
    tcp = TCP(dport=port, flags="S")

    # Construct the packet
    packet = ip / tcp

    # Send the packet and receive response
    response = sr1(packet, timeout=2, verbose=0)

    # Check if response received
    if response:
        if response.haslayer(TCP) and response.getlayer(TCP).flags == "SA":
            print(f"Port {port} is open.")
        else:
            print(f"Port {port} is closed.")
    else:
        print(f"Port {port} is filtered.")


# Perform TCP SYN Ping Scan against a range of ports on a target host
for port in top_ports:
    tcp_syn_ping_scan(args.dest_ip, port)