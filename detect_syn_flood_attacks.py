from scapy.all import TCP, sniff

SYN_THRESHOLD = 80  # Number of SYN packets threshold
TIME_WINDOW = 20  # Time window in seconds


def print_packet(packet):
    if packet.haslayer(TCP) and packet.getlayer(TCP).flags == "S":
        print(packet.summary())


def detect_syn_flood(packets):
    syn_count = sum(1 for packet in packets if packet.haslayer(TCP) and packet.getlayer(TCP).flags == "S")
    if syn_count >= SYN_THRESHOLD:
        print("Possible SYN flood attack detected. SYN packets count: {}".format(syn_count))

# Sniff packets and apply detection function within the specified time window
packets = sniff(filter="tcp", timeout=TIME_WINDOW, prn=print_packet)
detect_syn_flood(packets)
