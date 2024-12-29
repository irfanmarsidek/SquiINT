from flask import Flask, render_template, jsonify
import sniff
import threading
import netifaces as ni
import subprocess
import webbrowser

app = Flask(__name__)

def callWeb(ip):
    webbrowser.open("http://{}:5000".format(ip))

@app.route('/')
def index():
    return render_template('home/index2.html')

@app.route('/data')
def get_data():
    return jsonify(sniff.data)

@app.route('/protocol_data')
def get_protocol_data():
    return jsonify(sniff.protocol_data)

if __name__ == '__main__':

    ip = ni.ifaddresses("wlp2s0")[ni.AF_INET][0]['addr']
    print("hosting at IP address : "+ip)

    # Start packet capture in a separate thread
    threading.Thread(target=sniff.capture_packets).start()

    # Start calculating total packet lengths in a separate thread
    threading.Thread(target=sniff.total_packet_lengths).start()

    # Start generating data for the main graph in a separate thread
    threading.Thread(target=sniff.generate_data).start()

    # Start generating data for the protocol-specific graph in a separate thread
    threading.Thread(target=sniff.generate_protocol_data).start()

    app.run(debug=True, host=ip)
