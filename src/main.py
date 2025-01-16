from scapy.all import sniff, IP, TCP, UDP, ICMP
from tabulate import tabulate

captured_packets = []  # To store packet details for tabulated output

def packet_callback(packet):
    if IP in packet:
        ip_layer = packet[IP]
        protocol = "Unknown"
        src_port = None
        dst_port = None

        if TCP in packet:
            protocol = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif UDP in packet:
            protocol = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        elif ICMP in packet:
            protocol = "ICMP"

        # Add packet details to the list
        captured_packets.append([
            ip_layer.src,
            ip_layer.dst,
            protocol,
            src_port if src_port else "-",
            dst_port if dst_port else "-"
        ])

if __name__ == "__main__":
    # Ask user for filters
    ip_filter = input("Enter an IP to filter (leave blank for none): ").strip()
    protocol_filter = input("Enter a protocol to filter (TCP/UDP/ICMP, leave blank for none): ").strip().upper()
    port_filter = input("Enter a port to filter (leave blank for none): ").strip()

    def custom_filter(packet):
        if IP in packet:
            ip_match = not ip_filter or packet[IP].src == ip_filter or packet[IP].dst == ip_filter
            protocol_match = not protocol_filter or protocol_filter in packet.summary()
            
            # Check port filtering
            port_match = True
            if port_filter:
                if TCP in packet or UDP in packet:
                    src_port = packet[TCP].sport if TCP in packet else packet[UDP].sport
                    dst_port = packet[TCP].dport if TCP in packet else packet[UDP].dport
                    port_match = int(port_filter) in (src_port, dst_port)

            return ip_match and protocol_match and port_match
        return False

    print("Starting filtered packet capture...")
    sniff(prn=packet_callback, lfilter=custom_filter, count=10)  # Capture 10 packets with filtering
    print("Filtered packet capture complete!")

    # Display captured packets in a table
    headers = ["Source IP", "Destination IP", "Protocol", "Source Port", "Destination Port"]
    print(tabulate(captured_packets, headers=headers, tablefmt="grid"))
