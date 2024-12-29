import subprocess
import time
import os
from scapy.all import rdpcap 


def process_pcap(file_path):
    packets = rdpcap(file_path)
    parameters = []

    for packet in packets:
        src_ip, dst_ip, protocol, length, src_port, dst_port, timestamp = extract_parameters(packet)
        parameters.append([src_ip, dst_ip, protocol, length, src_port, dst_port, timestamp])

    return parameters

# Function to extract parameters from a PCAP file
def extract_parameters(packet):
    # Extract parameters from the packet
    if 'ARP' in packet:
        src_ip = packet['ARP'].psrc
        dst_ip = packet['ARP'].pdst
        protocol = packet['ARP'].ptype
    else:
        src_ip = packet['IP'].src if 'IP' in packet else '0.0.0.0'
        dst_ip = packet['IP'].dst if 'IP' in packet else '0.0.0.0'
        protocol = packet['IP'].proto if 'IP' in packet else 0
        
    src_port, dst_port = extract_ports(packet)
    length = len(packet)
    timestamp = packet.time
    return src_ip, dst_ip, protocol, length, src_port, dst_port, timestamp

def extract_ports(packet):
    if 'TCP' in packet:
        src_port = packet['TCP'].sport
        dst_port = packet['TCP'].dport
        return src_port, dst_port
    elif 'UDP' in packet:
        src_port = packet['UDP'].sport
        dst_port = packet['UDP'].dport
        return src_port, dst_port
    else:
        return 0, 0

def synthesize_features(parameters):

    total_length = 0  # Total length of all packets
    total_packets = len(parameters)  # Total number of packets

    unique_src_ports = set()  # Set to store unique source ports
    unique_dst_ports = set()  # Set to store unique destination ports
    flow_start_time = {}  # Dictionary to store the start time of each flow
    flow_duration = {}  # Dictionary to store the duration of each flow
    flow_bytes = {}  # Dictionary to store the total bytes of each flow
    flow_packets = {}  # Dictionary to store the total packets of each flow
    flow_bytes_per_sec_list = []  # List to store flow bytes/s for each flow
    flow_packets_per_sec_list = []  # List to store flow packets/s for each flow

    for param in parameters:
        # Extracting individual parameters from the parameter tuple
        src_ip, dst_ip, protocol, length, src_port, dst_port, timestamp = param
        
        total_length += length

        if src_port != 0:
            unique_src_ports.add(src_port)
        if dst_port != 0:
            unique_dst_ports.add(dst_port)
        
        # Define flow key based on source and destination IP and ports
        flow_key = (src_ip, dst_ip, src_port, dst_port, protocol)
        
        if flow_key not in flow_start_time:
            flow_start_time[flow_key] = timestamp
            flow_bytes[flow_key] = length
            flow_packets[flow_key] = 1
        else:
            flow_duration[flow_key] = timestamp - flow_start_time[flow_key]
            flow_bytes[flow_key] += length
            flow_packets[flow_key] += 1
    
    flow_features = []
    for flow_key, duration in flow_duration.items():
        flow_bytes_per_sec = flow_bytes[flow_key] / duration if duration else 0
        flow_packets_per_sec = flow_packets[flow_key] / duration if duration else 0
        flow_bytes_per_sec_list.append(flow_bytes_per_sec)
        flow_packets_per_sec_list.append(flow_packets_per_sec)
        flow_features.append((duration, flow_bytes_per_sec, flow_packets_per_sec))

    highest_fbps = round(float(max(flow_bytes_per_sec_list)),2) if flow_bytes_per_sec_list else 0
    highest_fpps = round(float(max(flow_packets_per_sec_list)),2) if flow_packets_per_sec_list else 0
    avg_fbps = round(sum(float(x) for x in flow_bytes_per_sec_list) / len(flow_bytes_per_sec_list),2) if flow_bytes_per_sec_list else 0
    avg_fpps = round(sum(float(x) for x in flow_packets_per_sec_list) / len(flow_packets_per_sec_list),2) if flow_packets_per_sec_list else 0
    length_packet_ratio = round(total_length / total_packets,2)
    total_unique_src_ports = len(unique_src_ports)
    total_unique_dst_ports = len(unique_dst_ports)

    features =[]
    features.append(highest_fbps)
    features.append(highest_fpps)
    features.append(avg_fbps)
    features.append(avg_fpps)
    features.append(length_packet_ratio)
    features.append(total_unique_src_ports)
    features.append(total_unique_dst_ports)

    return features

def capture_packets(output_dir, capture_duration):
    try:
        os.makedirs(output_dir, exist_ok=True)
        
        while True:
            timestamp = time.strftime("%d-%m-%Y--%H-%M-%S")
            filename = f"capture_{timestamp}.pcap"
            output_file = os.path.join(output_dir, filename)
            print(f"Capturing packets for {capture_duration} seconds. Output file: {output_file}")

            # Run tshark to capture packets for the given duration
            subprocess.run(["tshark", "-i", "wlp2s0", "-w", output_file, "-a", f"duration:{capture_duration}"], check=True)

            parameters = process_pcap(output_file)
            features = synthesize_features(parameters)

            with open(f"{output_dir}/summary-{filename}.txt","a") as file:
                file.write(f"Summary of {filename}:\n")
                file.write(f"highest flow byte per second = {features[0]}\n")
                file.write(f"highest flow packet per second = {features[1]}\n")
                file.write(f"average flow byte per second = {features[2]}\n")
                file.write(f"average flow packet per second = {features[3]}\n")
                file.write(f"length packet ratio = {features[4]}\n")
                file.write(f"total unique source ports = {features[5]}\n")
                file.write(f"total unique destination ports = {features[6]}\n")
            print("Capture complete.")

    except KeyboardInterrupt:
        print("\nPacket capture stopped by user.")

if __name__ == "__main__":
    output_directory = "flow"
    capture_duration_seconds = 600  # Set the capture duration in seconds
    capture_packets(output_directory, capture_duration_seconds)
