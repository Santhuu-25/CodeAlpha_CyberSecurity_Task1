from scapy.all import sniff, IP, TCP, UDP, ICMP


def packet_callback(packet):

    if IP not in packet:
        return

    source_ip = packet[IP].src
    destination_ip = packet[IP].dst

    protocol = "Other"
    source_port = "-"
    destination_port = "-"

    if TCP in packet:
        protocol = "TCP"
        source_port = packet[TCP].sport
        destination_port = packet[TCP].dport

    elif UDP in packet:
        protocol = "UDP"
        source_port = packet[UDP].sport
        destination_port = packet[UDP].dport

    elif ICMP in packet:
        protocol = "ICMP"

    payload_size = len(bytes(packet[IP].payload))

    print("----------------------------------------")
    print("Source IP        :", source_ip)
    print("Destination IP   :", destination_ip)
    print("Protocol         :", protocol)
    print("Source Port      :", source_port)
    print("Destination Port :", destination_port)
    print("Payload Size     :", payload_size, "bytes")


print("========================================")
print("       CODEALPHA NETWORK SNIFFER")
print("========================================")
print("Capturing authorized lab traffic...")
print("Press CTRL+C to stop.")
print()

sniff(prn=packet_callback, store=False)
