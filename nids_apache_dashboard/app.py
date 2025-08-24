

from flask import Flask, render_template, jsonify
import os
import threading
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../nids prot-2/src')))
from nids import NetworkIDS

app = Flask(__name__)
# Global variable to hold the NIDS instance and thread
nids_instance = None
nids_thread = None

# Show only alerts from the log file
@app.route('/alerts')
def show_alerts():
    log_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '../nids prot-2/logs/intrusion_detection.log'))
    if os.path.exists(log_path):
        with open(log_path, 'r') as f:
            logs = f.readlines()
        alerts = [line for line in logs if 'ALERT' in line]
        return jsonify({'alerts': ''.join(alerts) if alerts else 'No alerts found.'})
    else:
        return jsonify({'alerts': 'No alerts found.'})

# Global variable to hold the NIDS instance and thread
nids_instance = None
nids_thread = None

@app.route('/run_detection')
def run_detection():
    global nids_instance, nids_thread
    if nids_thread and nids_thread.is_alive():
        return jsonify({'result': 'Detection is already running.'})
    def run_nids():
        # Only use files/data from the project folder
        nids_instance = NetworkIDS(cli_mode=True)
        nids_instance.run()
    nids_thread = threading.Thread(target=run_nids, daemon=True)
    nids_thread.start()
    return jsonify({'result': 'Detection started!'})

@app.route('/stop_detection')
def stop_detection():
    global nids_instance
    if nids_instance:
        nids_instance.stop()
        return jsonify({'status': 'Detection stopped!'})
    else:
        return jsonify({'status': 'Detection was not running.'})


# Show all log messages (including alerts)
@app.route('/logs')
def show_logs():
    log_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '../nids prot-2/logs/intrusion_detection.log'))
    if os.path.exists(log_path):
        with open(log_path, 'r') as f:
            logs = f.readlines()
        # Optionally, filter for lines containing 'ALERT' if you want only alerts
        # alerts = [line for line in logs if 'ALERT' in line]
        # return jsonify({'logs': ''.join(alerts)})
        return jsonify({'logs': ''.join(logs)})
    else:
        return jsonify({'logs': 'No logs found.'})

@app.route('/')
def index():
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)