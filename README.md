# Packet Sniffer
A packet sniffer and analyzer built using Python, Scapy, and other Python-supported libraries. This tool was created to capture, filter, and analyze network traffic in real-time, providing insights into network activity for educational purposes and gaining a deeper understanding of networking and security concepts.

# Features
- **Packet Capture**: Captures live network traffic, showing details such as source IP, destination IP, protocol, and port numbers.
- **Filtering**: Allows IP, protocol (TCP/UDP/ICMP), and port number filtering.
- **Suspicious Packet Detection**: Flags packets with reserved IPs, uncommon ports, malformed headers, unusual TCP flags, or irregular payload sizes.
- **Formatted Output**: Shows captured and suspicious packets in a tabulated format for clear and professional output.

# Setup Instructions
1. Clone the repository:
   ```bash
   git clone https://github.com/b-getz/PacketSniffer.git
   cd PacketSniffer
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
3. Run the tool:
   ```bash
   python src/main.py

# Usage
1. Run the tool and follow the prompts to:
   - Filter packets according to IP, protocol, or port (all optional)
   - Capture and view up to 20 packets (customizable within the code)
2. Review the output for both normal and suspicious network traffic

# Disclaimer
This tool is intended for **educational purposes** and should **ONLY** be used on owned networks. Unauthorized use of this tool on networks could result in violations of local laws and regulations.

# Future Enhancements
1. Add real-time traffic summaries, such as protocol distribution and packet statistics
2. Implement exporting results to .csv or .txt
3. Enhance suspicious packet detection (w/ machine learning?)
