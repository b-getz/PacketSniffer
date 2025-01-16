from scapy.all import sniff, IP, TCP, UDP, ICMP
from tabulate import tabulate

captured_packets = []  # To store packet details
suspicious_packets = []  # To store suspicious packet details

def is_suspicious(packet):
    """Check if a packet is suspicious based on certain criteria."""
    if IP in packet:
        ip_layer = packet[IP]

        # Check for reserved IP ranges (e.g., loopback or link-local)
        reserved_ips = ["127.", "169.254."]
        if any(ip_layer.src.startswith(prefix) or ip_layer.dst.startswith(prefix) for prefix in reserved_ips):
            return True

        # Check for uncommon ports
        uncommon_ports = [8081, 12345, 31337]
        if TCP in packet or UDP in packet:
            src_port = packet[TCP].sport if TCP in packet else packet[UDP].sport
            dst_port = packet[TCP].dport if TCP in packet else packet[UDP].dport
            if src_port in uncommon_ports or dst_port in uncommon_ports:
                return True

        # Check for malformed packets (e.g., missing IP fields)
        if not ip_layer.src or not ip_layer.dst:
            return True

        # Check for unusual TCP flags
        if TCP in packet:
            tcp_layer = packet[TCP]
            flag_combinations = [
                tcp_layer.flags & 0x29 == 0x29,  # SYN+FIN
                tcp_layer.flags & 0x14 == 0x14,  # URG+PSH
            ]
            if any(flag_combinations):
                return True

        # Check for irregular payload sizes
        if len(packet) > 1500:  # Arbitrary threshold for large packets
            return True

        # Check for uncommon protocols
        if not (TCP in packet or UDP in packet or ICMP in packet):
            return True

    return False

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

        # Use filters
        if apply_filter(ip_layer.src, ip_layer.dst, protocol, src_port, dst_port):
            captured_packets.append([
                ip_layer.src,
                ip_layer.dst,
                protocol,
                src_port if src_port else "-",
                dst_port if dst_port else "-"
            ])

            # Check for suspicious packets
            if is_suspicious(packet):
                suspicious_packets.append([
                    ip_layer.src,
                    ip_layer.dst,
                    protocol,
                    src_port if src_port else "-",
                    dst_port if dst_port else "-"
                ])

def apply_filter(src_ip, dst_ip, protocol, src_port, dst_port):
    """Check if a packet matches the user-defined filters."""
    ip_match = not ip_filter or ip_filter in [src_ip, dst_ip]
    protocol_match = not protocol_filter or protocol_filter == protocol
    port_match = not port_filter or port_filter in [src_port, dst_port]
    return ip_match and protocol_match and port_match

if __name__ == "__main__":
    # Prompt user for filters
    ip_filter = input("Enter an IP to filter (leave blank for none): ").strip()
    protocol_filter = input("Enter a protocol to filter (TCP/UDP/ICMP, leave blank for none): ").strip().upper()
    port_filter = input("Enter a port to filter (leave blank for none): ").strip()
    port_filter = int(port_filter) if port_filter else None

    print("Starting packet capture...")
    sniff(prn=packet_callback, count=20)  # Capture 20 packets
    print("Packet capture complete!")

    # Show captured packets
    headers = ["Source IP", "Destination IP", "Protocol", "Source Port", "Destination Port"]
    print("\nAll Captured Packets:")
    print(tabulate(captured_packets, headers=headers, tablefmt="grid"))

    # Show suspicious packets
    if suspicious_packets:
        print("\nSuspicious Packets Detected:")
        print(tabulate(suspicious_packets, headers=headers, tablefmt="grid"))
    else:
        print("\nNo suspicious packets detected.")
