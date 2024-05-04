from scapy.layers.inet import IP

def filter_packets(packet_list, src_ip=None, dst_ip=None, protocol=None, src_port=None, dst_port=None):
    filtered_packets = packet_list
    
    # Apply filtering criteria
    if src_ip:
        filtered_packets = [packet for packet in filtered_packets if IP in packet and packet[IP].src == src_ip]
    
    if dst_ip:
        filtered_packets = [packet for packet in filtered_packets if IP in packet and packet[IP].dst == dst_ip]
    
    if protocol is not None:
        filtered_packets = [packet for packet in filtered_packets if IP in packet and packet[IP].proto == int(protocol)]
    
    if src_port:
        filtered_packets = [packet for packet in filtered_packets if packet.haslayer('TCP') and packet['TCP'].sport == int(src_port)]
    
    if dst_port:
        filtered_packets = [packet for packet in filtered_packets if packet.haslayer('TCP') and packet['TCP'].dport == int(dst_port)]
    
    return filtered_packets
