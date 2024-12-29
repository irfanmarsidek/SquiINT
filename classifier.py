from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime
from collections import defaultdict
import pandas as pd
import joblib
from tensorflow.keras.models import load_model # type: ignore
import pickle

# Load the trained model and scaler
model = load_model("granular-cnn-model.h5")
scaler = joblib.load("scaler.pkl")
encoder = joblib.load("encoder.joblib")

# Load class mapping
with open('class_mapping.pkl', 'rb') as f:
    class_mapping = pickle.load(f)

index_to_class = {v: k for k, v in class_mapping.items()}

# Dictionary to store connection data based on IP pairs
connections = defaultdict(lambda: {
    "duration": 0,
    "protocol_type": "",
    "service": "",
    "src_bytes": 0,
    "dst_bytes": 0,
    "flag": "",
    "count": 0,
    "srv_count": 0,
    "land": 0,
    "serror_count": 0,
    "serror_rate": 0.0,
    "srv_serror_rate": 0.0,
    "rerror_count": 0,
    "rerror_rate": 0.0,
    "srv_rerror_rate": 0.0,
    "same_srv_rate": 0.0,
    "diff_srv_rate": 0.0,
    "srv_diff_host_rate": 0.0,
    "dst_host_count": 0,
    "dst_host_srv_count": 0,
    "dst_host_same_srv_rate": 0.0,
    "dst_host_diff_srv_rate": 0.0,
    "dst_host_same_src_port_rate": 0.0,
    "dst_host_srv_diff_host_rate": 0.0,
    "dst_host_serror_rate": 0.0,
    "dst_host_srv_serror_rate": 0.0,
    "dst_host_rerror_rate": 0.0,
    "dst_host_srv_rerror_rate": 0.0
})

# TCP service map
tcp_service_map = {
    20: "ftp_data",
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    37: "time",
    53: "domain_u",
    67: "dhcp",
    79: "finger",
    80: "http",
    110: "pop_3",
    111: "sunrpc",
    113: "auth",
    119: "nntp",
    135: "netbios_ns",
    137: "netbios_dgm",
    139: "netbios_ssn",
    143: "imap4",
    161: "snmp",
    443: "http_443",
    515: "printer",
    993: "imap4_ssl",
    995: "pop_3_ssl",
    1080: "socks",
    1433: "sql_net",
    3306: "mysql",
    5432: "postgresql",
    8001: "http_8001",
    2784: "http_2784",
}

# UDP service map
udp_service_map = {
    53: "domain_u",
    67: "dhcp",
    68: "dhcp_client",
    69: "tftp_u",
    123: "ntp_u",
    137: "netbios_ns",
    138: "netbios_dgm",
    161: "snmp",
    162: "snmp_trap",
    514: "syslog",
    520: "rip",
    33434: "traceroute",
}

# ICMP service map
icmp_service_map = {
    (0, 0): "echo_reply",
    (3, 0): "network_unreachable",
    (3, 1): "host_unreachable",
    (3, 3): "port_unreachable",
    (5, 0): "redirect",
    (8, 0): "echo_request",
    (11, 0): "ttl_exceeded",
}

# Function to get the service based on the protocol and port
def get_service(packet):
    if TCP in packet:
        port = packet[TCP].dport
        return tcp_service_map.get(port, "other")
    elif UDP in packet:
        port = packet[UDP].dport
        return udp_service_map.get(port, "other")
    elif ICMP in packet:
        icmp_type = packet[ICMP].type
        icmp_code = packet[ICMP].code
        return icmp_service_map.get((icmp_type, icmp_code), "other")
    return "other"

# Function to update destination host-related features
def update_dst_host_features(connection_key, connection):
    """
    Update destination host-related features for the given connection.
    """
    dst_ip = connection_key[1]
    dst_protocol = connection_key[2]

    # Find all connections to the same destination IP and protocol
    related_connections = [
        conn for (src, dst, proto), conn in connections.items()
        if dst == dst_ip and proto == dst_protocol
    ]

    total_connections = len(related_connections)
    same_srv_count = sum(1 for conn in related_connections if conn["service"] == connection["service"])
    diff_srv_count = total_connections - same_srv_count

    same_src_port_count = sum(1 for conn in related_connections if conn["src_bytes"] == connection["src_bytes"])
    srv_diff_host_count = total_connections - same_src_port_count

    serror_count = sum(1 for conn in related_connections if conn["flag"] in ["S0", "RSTR"])
    srv_serror_count = sum(1 for conn in related_connections if conn["flag"] == "S0")
    rerror_count = sum(1 for conn in related_connections if conn["flag"] in ["REJ", "RSTO"])
    srv_rerror_count = sum(1 for conn in related_connections if conn["flag"] == "REJ")

    # Update the destination host features
    connection["dst_host_count"] = total_connections
    connection["dst_host_srv_count"] = same_srv_count
    connection["dst_host_same_srv_rate"] = same_srv_count / total_connections if total_connections > 0 else 0.0
    connection["dst_host_diff_srv_rate"] = diff_srv_count / total_connections if total_connections > 0 else 0.0
    connection["dst_host_same_src_port_rate"] = same_src_port_count / total_connections if total_connections > 0 else 0.0
    connection["dst_host_srv_diff_host_rate"] = srv_diff_host_count / total_connections if total_connections > 0 else 0.0
    connection["dst_host_serror_rate"] = serror_count / total_connections if total_connections > 0 else 0.0
    connection["dst_host_srv_serror_rate"] = srv_serror_count / total_connections if total_connections > 0 else 0.0
    connection["dst_host_rerror_rate"] = rerror_count / total_connections if total_connections > 0 else 0.0
    connection["dst_host_srv_rerror_rate"] = srv_rerror_count / total_connections if total_connections > 0 else 0.0

# Packet callback function
def packet_callback(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol_type = packet[IP].proto
        connection_key = (src_ip, dst_ip, protocol_type)

        # Initialize or update connection information
        connection = connections[connection_key]
        current_time = datetime.now()

        # Set protocol type (TCP/UDP/ICMP)
        connection['protocol_type'] = (
            'tcp' if protocol_type == 6 else
            'udp' if protocol_type == 17 else
            'icmp' if protocol_type == 1 else 'other'
        )
        connection['land'] = 1 if src_ip == dst_ip else 0

        # Update duration
        if 'last_seen' in connection:
            duration = (current_time - connection['last_seen']).total_seconds()
            connection['duration'] += duration
        connection['last_seen'] = current_time

        # Update service and flags
        connection['service'] = get_service(packet)

        # Update additional statistics
        if connection['count'] > 1:
            connection['same_srv_rate'] = connection['srv_count'] / connection['count']
            connection['diff_srv_rate'] = 1 - connection['same_srv_rate']

        # Update destination host-related features
        update_dst_host_features(connection_key, connection)

# Save connection data
def save_connection_data():
    data = []
    for (src_ip, dst_ip, protocol), features in connections.items():
        row = {key: features[key] for key in features}
        row.update({"src_ip": src_ip, "dst_ip": dst_ip, "protocol_type": protocol})
        data.append(row)

    # Save to CSV
    df = pd.DataFrame(data)
    df.to_csv("nsl_kdd_features.csv", index=False)
    print("Data saved to nsl_kdd_features.csv")

# Start sniffing
try:
    print("Starting packet capture. Press Ctrl+C to stop.")
    sniff(iface="wlp2s0", prn=packet_callback, store=0)
except KeyboardInterrupt:
    print("\nStopping packet capture.")
    save_connection_data()