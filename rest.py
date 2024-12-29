from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime
from collections import defaultdict
import pandas as pd
import joblib  # For loading the model
from sklearn.preprocessing import StandardScaler  # Assume scaler was used during training
from tensorflow.keras.models import load_model # type: ignore
import pickle

# Load the trained model and scaler
model = load_model("granular-cnn-model.h5")
scaler = joblib.load("scaler.pkl")
encoder = joblib.load("encoder.joblib")

# Class dictionary 
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
    # "wrong_fragment": 0, ---
    # "urgent": 0, ---
    # "hot": 0, 
    # "num_failed_logins": 0, 
    # "logged_in": 0, -back, satan
    # "num_compromised": 0,
    # "root_shell": 0,
    # "su_attempted": 0,
    # "num_root": 0,
    # "num_file_creations": 0,
    # "num_shells": 0,
    # "num_access_files": 0,
    # "num_outbound_cmds": 0,
    # "is_host_login": 0,
    # "is_guest_login": 0,
    "count": 0,
    "srv_count": 0,
    "serror_count": 0, # not feature
    "serror_rate": 0.0,
    "srv_serror_rate": 0.0,
    "rerror_count": 0, # not feature
    "rerror_rate": 0.0,
    "srv_rerror_rate": 0.0,
    "same_srv_rate": 0.0,
    "diff_srv_rate": 0.0,
    "srv_diff_host_rate": 0.0,
    "src_host_ips": [], # not feature
    "dst_host_ips": [], # not feature
    "dst_host_services": [], # not feature
    "src_host_count": 0, # not feature
    "dst_host_count": 0,
    "dst_host_srv_count": 0,
    "dst_host_same_srv_rate": 0.0,
    "dst_host_diff_srv_rate": 0.0,
    "dst_host_same_src_port_rate": 0.0,
    "dst_host_srv_diff_host_rate": 0.0,
    "dst_host_serror_rate": 0.0,
    # "dst_host_srv_serror_rate": 0.0,
    # "dst_host_rerror_rate": 0.0,
    # "dst_host_srv_rerror_rate": 0.0
})

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

udp_service_map = {
    53: "domain_u",
    67: "dhcp",  # Server-side DHCP
    68: "dhcp_client",  # Client-side DHCP
    69: "tftp_u",
    123: "ntp_u",  # Network Time Protocol
    137: "netbios_ns",
    138: "netbios_dgm",
    161: "snmp",
    162: "snmp_trap",
    514: "syslog",
    520: "rip",  # Routing Information Protocol
    33434: "traceroute",
}

icmp_service_map = {
    (0, 0): "echo_reply",       # Type 0: Echo Reply
    (3, 0): "network_unreachable",  # Type 3, Code 0: Destination Unreachable (Network)
    (3, 1): "host_unreachable",     # Type 3, Code 1: Destination Unreachable (Host)
    (3, 3): "port_unreachable",     # Type 3, Code 3: Destination Unreachable (Port)
    (5, 0): "redirect",             # Type 5: Redirect Message
    (8, 0): "echo_request",         # Type 8: Echo Request
    (11, 0): "ttl_exceeded",        # Type 11: Time Exceeded (TTL expired)
}

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

def map_tcp_flags(flags, has_payload=False, is_ack_received=False):

        # NSL-KDD flag mapping based on TCP flags
        if flags == "S":  # SYN
            return "S0"  # Connection attempt seen, no reply
        elif flags == "SA":  # SYN, ACK
            return "SF"  # Normal connection
        elif flags == "R":  # RST
            return "RSTR"  # Reset by the initiator
        elif flags == "RA":  # RST, ACK
            return "RSTO"  # Reset by the responder
        elif flags == "F":  # FIN
            return "SH"  # SYN and FIN only
        elif flags == "FA":  # FIN, ACK
            return "SF"  # Normal connection
        elif flags == "R" and not is_ack_received:  # Reset without ACK
            return "RSTOS0"  # Reset for SYN but no reply
        elif flags == "A" and not has_payload:  # ACK with no data
            return "S2"  # Established connection with no data
        elif flags == "PA" and has_payload:  # Partial connection
            return "S3"  # Partial connection
        elif flags == "R" and has_payload:  # RST after some payload
            return "REJ"  # Rejected connection
        else:
            return "OTH"  # Other or unknown pattern

def map_udp_flags(response_received):
    if response_received:
        return "SF"  # Normal connection with data transfer
    else:
        return  # No reply or other pattern

def map_icmp_flags(icmp_type, icmp_code):
    if (icmp_type, icmp_code) == (8, 0):  # Echo request
        return "S0"  # Echo request sent, no reply
    elif (icmp_type, icmp_code) == (0, 0):  # Echo reply
        return "SF"  # Normal ICMP reply
    elif icmp_type == 3:  # Destination unreachable
        return "REJ"  # Connection rejected
    elif icmp_type == 11:  # Time exceeded
        return "RSTO"  # TTL expired, equivalent to reset
    else:
        return "OTH"  # Other or unknown pattern

def get_flag(packet):
    if TCP in packet:
        payload_check = True if len(packet[TCP].payload) > 0 else False
        ack_check = True if packet[TCP].flags & 0x10 else False
        flags = packet[TCP].flags
        return map_tcp_flags(flags,payload_check,ack_check)
    elif UDP in packet:
        return "SF"
        # response_received = hasattr(packet, 'response') and packet.response  # Check if a response exists
        # return map_udp_flags(response_received)
    elif ICMP in packet:
        icmp_type = packet[ICMP].type
        icmp_code = packet[ICMP].code
        return map_icmp_flags(icmp_type, icmp_code)
    else:
        return "OTH"  # Default for unsupported protocols

def map_class(df):
    class_mapping = {label: idx for idx, label in enumerate(df['class'].unique())}

def packet_callback(packet):
    """ Callback function to process each packet captured by Scapy. """
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol_type = packet[IP].proto  # 6 for TCP, 17 for UDP
        connection_key = (src_ip, dst_ip, protocol_type)
        
        # Initialize or update connection information
        connection = connections[connection_key]
        current_time = datetime.now()
        
        # Set protocol type (tcp/udp)
        connection['protocol_type'] = (
            'tcp' if protocol_type == 6 else 
            'udp' if protocol_type == 17 else
            'icmp' if protocol_type == 1 else 
            'other' 
        )
        
        # Check if the source and destination IPs are the same
        connection['land'] = 1 if src_ip == dst_ip else 0

        # Update duration by calculating time difference
        if 'last_seen' in connection:
            duration = (current_time - connection['last_seen']).total_seconds()
            connection['duration'] += duration
        connection['last_seen'] = current_time  # Update last seen time
        
        # Service and flag mapping
        connection['service'] = get_service(packet)
        # print(f"{packet.flags} || {connection['protocol_type']}")
        connection['flag'] = get_flag(packet)

        # Update count of unique connections
        connection['count'] += 1

        # Serror and rerror rate
        if TCP in packet:
            if connection['flag'] == 'RSTR':  # RST flag
                connection['rerror_count'] += 1
                connection['rerror_rate'] = connection['rerror_count']/connection['count']
            if connection['flag'] == 'S0' and 'A' not in connection['flag']:  # S error if SYN without ACK
                connection['serror_count'] += 1
                connection['serror_rate'] = connection['serror_count']/connection['count']
        
        # Count bytes transferred
        if src_ip == packet[IP].src:
            connection['src_bytes'] += len(packet)
        else:
            connection['dst_bytes'] += len(packet)

        if connection['service'] != "":
            connection['srv_count'] += 1

        connection['srv_serror_rate'] = connection['serror_count']/connection['srv_count']

        # Placeholder for statistical features
        # Assume recent connections between same IPs for rate calculations
        if connection['count'] > 1:
            connection['same_srv_rate'] = connection['srv_count'] / connection['count']
            connection['diff_srv_rate'] = 1 - connection['same_srv_rate']
            connection['srv_diff_host_rate'] = (
                1 - connection['srv_count'] / connection['count']
            )

        # # Directly calculate and update dst_host metrics
        # connection.setdefault('dst_host_ips', set())
        # connection.setdefault('dst_host_services', set())

        # Update metrics
        connection['src_host_ips'].append(src_ip)
        connection['dst_host_ips'].append(dst_ip)  # Track unique source and dest IPs
        connection['dst_host_services'].append(connection['service'])  # Track unique services
        connection['dst_host_count'] = len(connection['dst_host_ips'])
        connection['src_host_count'] = len(connection['src_host_ips'])
        connection['dst_host_srv_count'] = len(connection['dst_host_services'])

        if connection['dst_host_count'] > 0:
            connection['dst_host_same_srv_rate'] = connection['dst_host_srv_count'] / connection['dst_host_count']
            connection['dst_host_diff_srv_rate'] = 1 - connection['dst_host_same_srv_rate']

        connection['dst_host_same_src_port_rate'] = connection['dst_host_same_srv_rate']
        connection['dst_host_srv_diff_host_rate'] = connection['src_host_count'] / connection['dst_host_srv_count']
        
        connection['dst_host_serror_rate'] = connection['serror_count'] / connection['dst_host_count']

        # Display the connection (optional, for debugging)
        # print(f"Connection from {src_ip} to {dst_ip} ({protocol_type}): {connection}")

        # Transform the connection data for classification
        classify_connection(connection_key, connection)

def transform_features(connection):
    """Preprocess connection data to match model input format."""
    row = {
        "duration": connection["duration"],
        "protocol_type": connection["protocol_type"],
        "service": connection["service"],
        "src_bytes": connection["src_bytes"],
        "dst_bytes": connection["dst_bytes"],
        "flag": connection["flag"],
        "count": connection["count"],
        "srv_count": connection["srv_count"],
        "land": connection["land"],
        "serror_rate": connection["serror_rate"],
        "rerror_rate": connection["rerror_rate"],
        "same_srv_rate": connection["same_srv_rate"],
        "diff_srv_rate": connection["diff_srv_rate"],
        "dst_host_count": connection["dst_host_count"],
        "dst_host_srv_count": connection["dst_host_srv_count"],
        "dst_host_same_srv_rate": connection["dst_host_same_srv_rate"],
        "dst_host_diff_srv_rate": connection["dst_host_diff_srv_rate"],
        "dst_host_same_src_port_rate": connection["dst_host_same_src_port_rate"],
        "dst_host_srv_diff_host_rate": connection["dst_host_srv_diff_host_rate"],
        "dst_host_serror_rate": connection["dst_host_serror_rate"],
    }
    df = pd.DataFrame([row])
    
    # Use the fitted encoder to transform categorical features
    encoded_features = encoder.transform(df[['protocol_type', 'service', 'flag']])
    encoded_df = pd.DataFrame(encoded_features, columns=encoder.get_feature_names_out(['protocol_type', 'service', 'flag']))

    # Drop original categorical columns and concatenate encoded columns
    df = df.drop(columns=['protocol_type', 'service', 'flag']).reset_index(drop=True)
    df = pd.concat([df, encoded_df], axis=1)
    
    # Ensure column alignment with training data by adding any missing columns with 0
    for col in scaler.feature_names_in_:
        if col not in df.columns:
            df[col] = 0
    df = df[scaler.feature_names_in_]  # Reorder to match scaler's training data
    
    # Scale the features using the trained scaler
    features = scaler.transform(df)
    return features, row

def classify_connection(connection_key, connection):
    """Classify each connection into one of the classes using the loaded class mapping."""
    # Transform the connection features into the format required by the model
    features,row = transform_features(connection)
    
    # Model prediction
    prediction = model.predict(features)  # Granular class probabilities

    # Interpretation of the prediction
    class_index = prediction.argmax()  # Get the index of the highest probability
    label = index_to_class[class_index]  # Decode the class label from the mapping
    
    # Extract connection details
    src_ip, dst_ip, protocol_type = connection_key
    
    print(f"Connection from {src_ip} to {dst_ip} ({protocol_type}): {label}")
    print(f"/nData :{row}")

    with open("logs.txt","a") as file:
            file.write(f"Connection from {src_ip} to {dst_ip} ({connection['protocol_type']})({connection['service']})({connection['flag']}): {label}\n")
            file.write(f"{row}\n")

    if label != "normal":
        with open("alert.txt","a") as file:
            file.write(f"Connection from {src_ip} to {dst_ip} ({connection['protocol_type']})({connection['service']})({connection['flag']}): {label}\n")
            file.write(f"{row}\n")

    if src_ip == "10.167.3.160":
        with open("test.txt","a") as file:
            file.write(f"Connection from {src_ip} to {dst_ip} ({connection['protocol_type']})({connection['service']})({connection['flag']}): {label}\n")
            file.write(f"{connection}\n")
    # Return the classified connection details
    return {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "protocol_type": protocol_type,
        "label": label,
        # "confidence": prediction[class_index]  # Probability of the predicted class
    }


# Start sniffing
try:
    print("Starting packet capture. Press Ctrl+C to stop.")
    sniff(iface="wlp2s0", prn=packet_callback, store=0)
except KeyboardInterrupt:
    print("\nStopping packet capture.")
