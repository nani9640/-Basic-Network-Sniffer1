# -Basic-Network-Sniffer1



 pip install scapy
 sudo python3 network_sniffer.py
 python network_sniffer.py


from scapy.all import sniff, IP, TCP, UDP, ICMP
import datetime

def packet_callback(packet):
    # Check if the packet has an IP layer
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto
        
        # Get the current timestamp
        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        # Print basic packet information
        print(f"{timestamp} - Packet: {packet.summary()}")
        print(f"Source IP: {ip_src}, Destination IP: {ip_dst}, Protocol: {protocol}")

        # Check for TCP, UDP, and ICMP packets
        if TCP in packet:
            print("TCP Packet:")
            print(f"Source Port: {packet[TCP].sport}, Destination Port: {packet[TCP].dport}")
        elif UDP in packet:
            print("UDP Packet:")
            print(f"Source Port: {packet[UDP].sport}, Destination Port: {packet[UDP].dport}")
        elif ICMP in packet:
            print("ICMP Packet")

        print("\n")

# Start sniffing packets
def start_sniffer(interface=None):
    print("Starting the sniffer...")
    sniff(iface=interface, prn=packet_callback, store=0)

if __name__ == "__main__":
    # You can specify an interface (like 'eth0', 'wlan0', etc.) or leave it as None to capture on all interfaces.
    start_sniffer(interface=None)

 pip install scapy
 sudo python3 network_sniffer.py
 python network_sniffer.py
