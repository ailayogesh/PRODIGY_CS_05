from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP
import datetime

def packet_callback(packet):
    # Check if the packet has an IP layer
    if IP in packet:
        # Extract source and destination IP addresses
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto  # Protocol number
        
        # Determine protocol name
        if protocol == 6:
            protocol_name = "TCP"
        elif protocol == 17:
            protocol_name = "UDP"
        elif protocol == 1:
            protocol_name = "ICMP"
        else:
            protocol_name = f"Other ({protocol})"
        
        print(f"\n[Time: {datetime.datetime.now()}]")
        print(f"Source IP: {src_ip}")
        print(f"Destination IP: {dst_ip}")
        print(f"Protocol: {protocol_name}")

        # Print payload if it's TCP/UDP
        if protocol_name in ["TCP", "UDP"]:
            try:
                payload = bytes(packet[protocol_name].payload).decode("utf-8", errors="ignore")
                print(f"Payload:\n{payload}")
            except Exception as e:
                print("Payload: Unable to decode")

# Start sniffing on the network interface
# Replace 'eth0' with your network interface name
print("Starting packet sniffer. Press Ctrl+C to stop.")
sniff(iface="Wi-Fi", filter="ip", prn=packet_callback, store=0)
