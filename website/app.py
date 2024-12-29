from flask import Flask, render_template, jsonify
import sniff
import threading
import netifaces as ni
import subprocess
import webbrowser
from collections import defaultdict
from datetime import datetime

app = Flask(__name__)

# Connection tracking data structure
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
    "serror_rate": 0.0,
    "rerror_rate": 0.0,
    "same_srv_rate": 0.0,
    "diff_srv_rate": 0.0,
    "srv_diff_host_rate": 0.0,
})

# Simulate connection tracking (you can replace this with your packet sniffing logic)
def capture_connections():
    from scapy.all import sniff, IP, TCP, UDP, ICMP

    def packet_callback(packet):
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol = "TCP" if TCP in packet else "UDP" if UDP in packet else "ICMP" if ICMP in packet else "OTHER"
            connection_key = (src_ip, dst_ip, protocol)

            # Update connection details
            connection = connections[connection_key]
            connection["protocol_type"] = protocol
            connection["src_bytes"] += len(packet) if src_ip == packet[IP].src else 0
            connection["dst_bytes"] += len(packet) if dst_ip == packet[IP].dst else 0
            connection["count"] += 1
            connection["last_seen"] = datetime.now()

    sniff(prn=packet_callback, store=0)

# Flask routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/protocol_data')
def get_protocol_data():
    return jsonify(sniff.protocol_data)

@app.route('/connections')
def get_connections():
    """Serve connection data for visualization."""
    return jsonify([{
        "src_ip": src,
        "dst_ip": dst,
        "protocol": conn["protocol_type"],
        "src_bytes": conn["src_bytes"],
        "dst_bytes": conn["dst_bytes"],
        "count": conn["count"]
    } for (src, dst, _), conn in connections.items()])

@app.route('/nodes')
def nodes():
    return render_template('nodes.html')

def callWeb(ip):
    webbrowser.open("http://{}:5000".format(ip))

if __name__ == '__main__':
    ip = ni.ifaddresses("wlp2s0")[ni.AF_INET][0]['addr']
    print("Hosting at IP address: " + ip)

    # Open the web application in a browser
    threading.Thread(target=callWeb, args=(ip,)).start()

    # Start packet capture in a separate thread
    threading.Thread(target=capture_connections).start()

    # Start existing sniff logic in separate threads
    threading.Thread(target=sniff.capture_packets).start()
    threading.Thread(target=sniff.total_packet_lengths).start()
    threading.Thread(target=sniff.generate_data).start()
    threading.Thread(target=sniff.generate_protocol_data).start()

    app.run(debug=True, host=ip)
