from scapy.layers.inet import IP
from scapy.all import sniff
import packet_filter

def packet_print(packet):
    # Print packet information
    print("Packet captured. Executing packet_print function...")
    print(f"Protocol: {packet['IP'].proto} --> Source IP: {packet['IP'].src} --> Destination IP: {packet['IP'].dst}")

def packet_callback(packet):
    # Append all sniffed packets to all_packets list
    all_packets.append(packet)

while True:
    # Start sniffing packets
    all_packets = []
    captured_packets = sniff(prn=packet_callback, store=0, timeout=10)

    # Filter IP packets
    ip_packets = [packet for packet in all_packets if IP in packet]

    # Ask user for filtering criteria
    print("Enter filtering criteria:")
    src_ip = input("Enter source IP address (leave blank to ignore): ")
    dst_ip = input("Enter destination IP address (leave blank to ignore): ")
    protocol_input = input("Enter protocol (1 for ICMP, 6 for TCP, 17 for UDP) (leave blank to ignore): ")
    src_port = input("Enter source port (leave blank to ignore): ")
    dst_port = input("Enter destination port (leave blank to ignore): ")

    # Convert protocol to integer if it's not blank
    protocol = int(protocol_input) if protocol_input else None

    print("Filtering criteria received:")
    print(f"Source IP: {src_ip}")
    print(f"Destination IP: {dst_ip}")
    print(f"Protocol: {protocol}")
    print(f"Source port: {src_port}")
    print(f"Destination port: {dst_port}")

    # Filter packets based on criteria
    filtered_packets = packet_filter.filter_packets(ip_packets, src_ip=src_ip, dst_ip=dst_ip, protocol=protocol, src_port=src_port, dst_port=dst_port)

    # Print filtered packets
    for packet in filtered_packets:
        packet_print(packet)

    # Ask the user if they want to repeat the process
    repeat = input("Do you want to capture and filter packets again? (yes/no): ").lower()
    if repeat != "yes":
        break  # Exit the loop if the user doesn't want to repeat