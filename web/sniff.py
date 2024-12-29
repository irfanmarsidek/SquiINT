from scapy.all import sniff
import threading
import time
from datetime import datetime

data = []
protocol_data = {'TCP': [], 'UDP': [], 'MDNS': [], 'ARP': []}
packet_lengths = []

# Dictionary to store packet lengths per second for each protocol
protocol_packet_lengths = {'TCP': 0, 'UDP': 0, 'MDNS': 0, 'ARP': 0}
total_length = 0

def process_packet(packet):
    """Callback function to process each packet"""
    global protocol_packet_lengths, total_length
    length = len(packet)
    packet_lengths.append(length)
    total_length += length

    # Identify protocol and add length to corresponding protocol
    if packet.haslayer('TCP'):
        protocol_packet_lengths['TCP'] += length
    elif packet.haslayer('UDP'):
        if packet['UDP'].sport == 5353 or packet['UDP'].dport == 5353:
            protocol_packet_lengths['MDNS'] += length
            protocol_packet_lengths['UDP'] += length
        else:
            protocol_packet_lengths['UDP'] += length
    elif packet.haslayer('ARP'):
        protocol_packet_lengths['ARP'] += length

def capture_packets():
    """Capture packets using scapy"""
    sniff(prn=process_packet)

def total_packet_lengths():
    global total_length
    """Calculate total packet lengths per 10 seconds"""
    while True:
        time.sleep(1)
        if packet_lengths:
            total_length = sum(packet_lengths)
            packet_lengths.clear()

def generate_data():
    global data, total_length
    """Generate data for the main graph"""
    while True:
        if len(data) >= 20:
            data.pop(0)
        current_time = datetime.now().timestamp() * 1000  # Convert to milliseconds
        data.append({'time': current_time, 'value': total_length})
        total_length = 0  # Reset total_length after adding to data
        time.sleep(1)  # generate data every 10 seconds

def generate_protocol_data():
    global protocol_data
    """Generate data for the protocol-specific graph"""
    while True:
        current_time = datetime.now().timestamp() * 1000  # Convert to milliseconds
        for protocol in protocol_packet_lengths:
            if len(protocol_data[protocol]) >= 20:
                protocol_data[protocol].pop(0)
            protocol_data[protocol].append({'time': current_time, 'value': protocol_packet_lengths[protocol]})
            protocol_packet_lengths[protocol] = 0  # Reset after appending
        time.sleep(1)  # generate data every 10 seconds
        
if __name__ == "__main__":

    # Start packet capture in a separate thread
    threading.Thread(target=capture_packets).start()

    # Start calculating total packet lengths in a separate thread
    threading.Thread(target=total_packet_lengths).start()

    # Start generating data for the main graph in a separate thread
    threading.Thread(target=generate_data).start()

    # Start generating data for the protocol-specific graph in a separate thread
    threading.Thread(target=generate_protocol_data).start()